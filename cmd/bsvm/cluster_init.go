// Cluster bootstrap for the spec-16 3-node devnet. This command deploys
// the rollup covenant to BSV (one transaction, once, for the whole
// cluster) and writes a single shard.json that every node in the
// cluster uses. It is designed to run as a one-shot docker-compose
// service BEFORE the nodes boot, writing to a shared Docker volume so
// every node sees the same genesis covenant txid.
//
// The file is intentionally self-contained: it owns its own bootstrap
// wallet, funds it on regtest, compiles the FRI covenant, deploys it,
// and writes shard.json. It does NOT touch the per-node fee wallets
// (those live in each node's own data dir and are handled by
// wireBSVBroadcast on first run).
//
// Idempotent: if the target shard.json already exists and points at a
// live BSV transaction, the command is a no-op. This lets operators
// re-run `docker compose up` safely.
package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/holiman/uint256"
	cli "github.com/urfave/cli/v2"

	"github.com/icellan/bsvm/internal/db"
	"github.com/icellan/bsvm/pkg/block"
	"github.com/icellan/bsvm/pkg/bsvclient"
	"github.com/icellan/bsvm/pkg/covenant"
	"github.com/icellan/bsvm/pkg/shard"
	"github.com/icellan/bsvm/pkg/types"
	"github.com/icellan/bsvm/pkg/vm"

	gocompiler "github.com/icellan/runar/compilers/go/compiler"
	runar "github.com/icellan/runar/packages/runar-go"
)

// clusterInitLockFile is the name of the exclusive-create lock file
// used to serialize concurrent invocations of `bsvm init-cluster`.
// Rare in practice (docker-compose brings up bsvm-init exactly once),
// but guards against the case where an operator races two manual
// invocations against the same shared volume.
const clusterInitLockFile = ".init-lock"

// deployReceiptFile is an operator-facing JSON artefact summarising
// the deploy. Not consumed by any node at runtime — it exists purely
// so operators inspecting the shared volume can see deploy metadata
// without parsing shard.json.
const deployReceiptFile = "deploy_receipt.json"

// bootstrapWalletFile is the filename for the one-shot BSV wallet that
// funds the covenant deploy. Named distinctly from the per-node
// fee_wallet.wif so operators can tell them apart at a glance.
const bootstrapWalletFile = "bootstrap_wallet.wif"

// clusterGenesisAllocFile holds the genesis allocation (address →
// balance+nonce+code+storage) computed by init-cluster. Nodes joining
// the cluster read this file when initializing their local DB so every
// node lands on the same genesis state root as the one the deployed
// covenant binds.
const clusterGenesisAllocFile = "genesis_alloc.json"

// deployFundBTC is the amount (in whole BSV) the bootstrap wallet asks
// the regtest node to send it before deploying. 5 BSV is vastly more
// than a single deploy tx needs (typical deploy ~100k sats) but leaves
// plenty of headroom for re-tries without re-funding.
const deployFundBTC float64 = 5.0

// deployUtxoPollBudget is the total time budget for polling
// listunspent after fund+mine. Matches devnet_funding.go's utxoPollBudget.
const deployUtxoPollBudget = 30 * time.Second

// deployUtxoPollInterval is the retry interval while waiting for the
// funded UTXO to surface.
const deployUtxoPollInterval = 1 * time.Second

// deployReceipt is the shape of deploy_receipt.json. The fields are
// exactly what an operator wants to see in one place: when, what txid,
// which address paid, which vout carries the covenant.
type deployReceipt struct {
	DeployedAt       string `json:"deployedAt"`
	TxID             string `json:"txid"`
	Vout             uint32 `json:"vout"`
	Satoshis         uint64 `json:"sats"`
	BootstrapAddress string `json:"bootstrapAddress"`
	ChainID          int64  `json:"chainId"`
	VerificationMode string `json:"verificationMode"`
	GenesisStateRoot string `json:"genesisStateRoot"`
}

// cmdInitCluster deploys the rollup covenant to BSV and writes a
// single shard.json that every node in the cluster uses. Intended to
// run once, before any node boots, in a shared /shared/cluster volume.
//
// Idempotent: if --datadir/shard.json already exists and its
// GenesisCovenantTxID points to an existing BSV transaction, returns
// success. A coarse file lock at <datadir>/.init-lock serialises
// concurrent invocations.
//
// Required flags / env:
//
//	--datadir          shared volume path (default /shared/cluster)
//	--bsv-rpc          BSV node URL (or env BSVM_BSV_RPC)
//	--bsv-network      regtest|testnet|mainnet (default regtest)
//	--prove-mode       execute|prove (maps to fri/groth16-wa)
//	--chain-id         EVM chain id (default 31337)
//	--prefund-accounts hardhat|none
func cmdInitCluster(ctx *cli.Context) error {
	dataDir := ctx.String("datadir")
	bsvRPC := strings.TrimSpace(ctx.String("bsv-rpc"))
	if bsvRPC == "" {
		bsvRPC = strings.TrimSpace(os.Getenv("BSVM_BSV_RPC"))
	}
	if bsvRPC == "" {
		return fmt.Errorf("init-cluster: --bsv-rpc (or BSVM_BSV_RPC) is required")
	}
	bsvNet := ctx.String("bsv-network")
	if bsvNet == "" {
		bsvNet = "regtest"
	}
	proveMode := ctx.String("prove-mode")
	if proveMode == "" {
		proveMode = "execute"
	}
	chainID := ctx.Int64("chain-id")
	if chainID == 0 {
		chainID = 31337
	}
	prefund := ctx.String("prefund-accounts")
	if prefund == "" {
		prefund = "hardhat"
	}

	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return fmt.Errorf("init-cluster: ensure datadir: %w", err)
	}

	// Acquire a coarse lock to serialize concurrent invocations.
	// O_EXCL + retry-with-sleep is enough here — bsvm-init runs at
	// most once per `docker compose up` and operators do not normally
	// race manual invocations. The lock file is cleaned up on success.
	lockPath := filepath.Join(dataDir, clusterInitLockFile)
	lockFile, err := acquireInitLock(lockPath)
	if err != nil {
		return fmt.Errorf("init-cluster: acquire lock: %w", err)
	}
	defer func() {
		_ = lockFile.Close()
		_ = os.Remove(lockPath)
	}()

	slog.Info("init-cluster: starting",
		"datadir", dataDir,
		"bsvNet", bsvNet,
		"proveMode", proveMode,
		"chainID", chainID,
		"prefund", prefund)

	// 1. Build the BSV RPC provider.
	provider, err := bsvclient.NewRPCProvider(bsvRPC, bsvNet)
	if err != nil {
		return fmt.Errorf("init-cluster: provider: %w", err)
	}

	// 2. Idempotency check: if shard.json already exists AND its
	// covenant txid is present on BSV, nothing more to do.
	shardPath := filepath.Join(dataDir, "shard.json")
	if existing, err := shard.LoadConfig(shardPath); err == nil {
		if existing.GenesisCovenantTxID != "" {
			trimmed := strings.TrimPrefix(existing.GenesisCovenantTxID, "0x")
			if _, txErr := provider.GetRawTransactionVerbose(trimmed); txErr == nil {
				slog.Info("init-cluster: cluster already initialized, no-op",
					"txid", trimmed, "shard", shardPath)
				return nil
			} else {
				slog.Warn("init-cluster: existing shard.json references missing tx; will re-deploy",
					"txid", trimmed, "err", txErr)
			}
		}
	}

	// 3. Governance config (single_key, devnet key).
	govConfig := covenant.GovernanceConfig{Mode: covenant.GovernanceSingleKey}
	pub, err := shard.DevnetGovernanceKey()
	if err != nil {
		return fmt.Errorf("init-cluster: devnet gov key: %w", err)
	}
	govConfig.Keys = [][]byte{pub}
	govKeys := []string{hex.EncodeToString(pub)}

	// 4. Determine verification mode from prove mode.
	var verifyMode covenant.VerificationMode
	var verifyModeStr string
	switch proveMode {
	case "execute":
		verifyMode = covenant.VerifyFRI
		verifyModeStr = "fri"
	case "prove":
		// Mode 3 (Groth16-WA) requires a VK path — out of scope for the
		// cluster-bootstrap, which targets execute (FRI) devnet runs.
		return fmt.Errorf("init-cluster: prove-mode %q not yet supported (only execute/FRI)", proveMode)
	default:
		return fmt.Errorf("init-cluster: invalid prove-mode %q (want execute or prove)", proveMode)
	}

	// 5. Build the genesis alloc.
	genesisAlloc := map[types.Address]block.GenesisAccount{}
	switch prefund {
	case "", "none":
		// No prefund.
	case "hardhat":
		perAccount := new(uint256.Int).SetUint64(1000)
		perAccount.Mul(perAccount, new(uint256.Int).Exp(
			uint256.NewInt(10), uint256.NewInt(18),
		))
		for addr, acc := range shard.HardhatPrefundAlloc(perAccount) {
			genesisAlloc[addr] = acc
		}
	default:
		return fmt.Errorf("init-cluster: invalid prefund-accounts %q", prefund)
	}

	// 6. Compute the genesis state root in a throwaway in-memory DB so
	// the covenant's initial stateRoot readonly property matches what
	// nodes will produce when they initialize their local DB with the
	// same alloc.
	tmpDB := db.NewMemoryDB()
	genesisHeader, err := block.InitGenesis(tmpDB, &block.Genesis{
		Config:    vm.DefaultL2Config(chainID),
		Timestamp: 0,
		GasLimit:  block.DefaultGasLimit,
		Alloc:     genesisAlloc,
	})
	if err != nil {
		return fmt.Errorf("init-cluster: InitGenesis (temp): %w", err)
	}
	tmpDB.Close()
	slog.Info("init-cluster: genesis state root computed",
		"stateRoot", genesisHeader.StateRoot.Hex())

	// 7. Compile the FRI covenant. The SP1 VK is zeros for FRI — the
	// Mode 1 contract does not consult it on-chain.
	sp1VK := make([]byte, 32)
	contractSrc := findContractPath("rollup_fri.runar.go")
	constructorArgs, err := covenant.BuildFRIConstructorArgsExported(sp1VK, uint64(chainID), govConfig)
	if err != nil {
		return fmt.Errorf("init-cluster: FRI constructor args: %w", err)
	}
	gocompArtifact, err := gocompiler.CompileFromSource(contractSrc, gocompiler.CompileOptions{
		ConstructorArgs: constructorArgs,
	})
	if err != nil {
		return fmt.Errorf("init-cluster: compile FRI covenant (src=%s): %w", contractSrc, err)
	}
	sdkArtifact, err := goCompilerToSDKArtifact(gocompArtifact)
	if err != nil {
		return fmt.Errorf("init-cluster: artifact conversion: %w", err)
	}
	slog.Info("init-cluster: FRI covenant compiled",
		"scriptBytes", len(gocompArtifact.Script)/2,
		"constructorParams", len(gocompArtifact.ABI.Constructor.Params))

	// 8. Load or create the one-shot bootstrap wallet.
	bootstrapKey, err := loadOrCreateBootstrapWalletKey(dataDir)
	if err != nil {
		return fmt.Errorf("init-cluster: bootstrap wallet key: %w", err)
	}
	bootstrapAddr, err := FeeWalletBSVAddress(bootstrapKey, bsvNet)
	if err != nil {
		return fmt.Errorf("init-cluster: bootstrap wallet address: %w", err)
	}
	slog.Info("init-cluster: bootstrap wallet ready", "address", bootstrapAddr)

	// 9. Build the Rúnar signer. Use ExternalSigner so the DEPLOY path's
	// provider.GetUtxos(address) call gets the REGTEST address, not the
	// mainnet LocalSigner default. Without this, listunspent returns
	// nothing even when the address is funded.
	localSigner, err := runar.NewLocalSigner(hex.EncodeToString(bootstrapKey.Serialize()))
	if err != nil {
		return fmt.Errorf("init-cluster: local signer: %w", err)
	}
	pubKeyHex, _ := localSigner.GetPublicKey()
	signer := runar.NewExternalSigner(
		pubKeyHex,
		bootstrapAddr,
		func(txHex string, inputIndex int, subscript string, satoshis int64, sigHashType *int) (string, error) {
			return localSigner.Sign(txHex, inputIndex, subscript, satoshis, sigHashType)
		},
	)

	// 10. Fund the bootstrap wallet (regtest only). Uses the same
	// importaddress+sendtoaddress+generatetoaddress+poll pattern as
	// BootstrapFeeWallet in devnet_funding.go.
	if bsvNet == "regtest" {
		if err := fundBootstrapWallet(ctx.Context, provider, bootstrapAddr); err != nil {
			return fmt.Errorf("init-cluster: fund bootstrap wallet: %w", err)
		}
	} else {
		slog.Warn("init-cluster: non-regtest network — skipping auto-fund (operator must pre-fund)",
			"network", bsvNet, "address", bootstrapAddr)
	}

	// 11. Deploy the covenant. DefaultCovenantSats (10000) matches the
	// production covenant UTXO amount the manager expects. We inspect
	// the artifact's runtime constructor ABI to decide how many args
	// to pass: `gocompiler.CompileFromSource` with ConstructorArgs
	// bakes readonly fields into the script at compile time, leaving
	// only the mutable state fields in the runtime ABI.
	runarArgs := buildFRIRuntimeArgs(sdkArtifact, sp1VK, chainID, govConfig, genesisHeader.StateRoot)
	runarContract := runar.NewRunarContract(sdkArtifact, runarArgs)
	deployTxIDRaw, _, err := runarContract.Deploy(provider, signer, runar.DeployOptions{
		Satoshis: int64(covenant.DefaultCovenantSats),
	})
	if err != nil {
		return fmt.Errorf("init-cluster: deploy: %w", err)
	}
	deployTxID := strings.TrimPrefix(deployTxIDRaw, "0x")
	slog.Info("init-cluster: covenant deployed", "txid", deployTxID)

	// 12. Mine one block so the deploy confirms. Best-effort on
	// regtest; non-fatal elsewhere.
	if bsvNet == "regtest" {
		if _, err := provider.Call("generatetoaddress", 1, bootstrapAddr); err != nil {
			slog.Warn("init-cluster: generatetoaddress after deploy failed", "err", err)
		}
	}

	// 13. Confirm the deploy is visible via getrawtransaction.
	if _, err := provider.GetRawTransactionVerbose(deployTxID); err != nil {
		return fmt.Errorf("init-cluster: deploy tx not retrievable via getrawtransaction: %w", err)
	}

	// 14. Identify the vout carrying the covenant output. The SDK's
	// Deploy always places the covenant at output index 0; we re-verify
	// against the chain so the resulting shard.json is authoritative.
	deployVout := uint32(0)
	if cu := runarContract.GetCurrentUtxo(); cu != nil {
		if cu.OutputIndex < 0 {
			return fmt.Errorf("init-cluster: deployed utxo has negative OutputIndex %d", cu.OutputIndex)
		}
		deployVout = uint32(cu.OutputIndex)
	}

	// 15. Assemble and write shard.json.
	cfg := &shard.ShardConfig{
		ChainID:             chainID,
		ShardID:             deployTxID,
		GenesisCovenantTxID: deployTxID,
		GenesisCovenantVout: deployVout,
		CovenantSats:        covenant.DefaultCovenantSats,
		SP1VerifyingKey:     hex.EncodeToString(sp1VK),
		GovernanceMode:      govConfig.Mode.String(),
		GovernanceKeys:      govKeys,
		GovernanceThreshold: govConfig.Threshold,
		VerificationMode:    verifyModeStr,
		GenesisStateRoot:    genesisHeader.StateRoot.Hex(),
		HashFunction:        "keccak256",
		DataDir:             dataDir,
	}
	_ = verifyMode // explicitly unused locally; the string form lands in shard.json

	if err := cfg.Save(shardPath); err != nil {
		return fmt.Errorf("init-cluster: save shard.json: %w", err)
	}

	// 16. Persist the genesis alloc so each node can initialize its
	// local DB with the matching state root.
	if err := writeGenesisAlloc(filepath.Join(dataDir, clusterGenesisAllocFile), genesisAlloc); err != nil {
		return fmt.Errorf("init-cluster: save genesis alloc: %w", err)
	}

	// 17. Save the compiled ANF for audit (same convention as
	// InitShard). Non-fatal on failure — the shard runs fine without it.
	if gocompArtifact.ANF != nil {
		anfJSON, jerr := json.Marshal(gocompArtifact.ANF)
		if jerr == nil {
			_ = os.WriteFile(filepath.Join(dataDir, "covenant.anf.json"), anfJSON, 0o644)
		}
	}

	// 18. Write the operator-facing deploy receipt.
	receipt := deployReceipt{
		DeployedAt:       time.Now().UTC().Format(time.RFC3339),
		TxID:             deployTxID,
		Vout:             deployVout,
		Satoshis:         covenant.DefaultCovenantSats,
		BootstrapAddress: bootstrapAddr,
		ChainID:          chainID,
		VerificationMode: verifyModeStr,
		GenesisStateRoot: genesisHeader.StateRoot.Hex(),
	}
	receiptBytes, _ := json.MarshalIndent(receipt, "", "  ")
	if err := os.WriteFile(filepath.Join(dataDir, deployReceiptFile), receiptBytes, 0o644); err != nil {
		slog.Warn("init-cluster: writing deploy_receipt.json failed (non-fatal)", "err", err)
	}

	slog.Info("init-cluster: DONE",
		"txid", deployTxID,
		"vout", deployVout,
		"sats", covenant.DefaultCovenantSats,
		"stateRoot", genesisHeader.StateRoot.Hex(),
		"shardConfig", shardPath)
	return nil
}

// acquireInitLock tries up to 60 seconds to create an exclusive-create
// lock file at the given path. If an existing file is found we assume
// another invocation is in flight and wait for it to finish. On
// success the returned *os.File must be closed by the caller; the
// caller also owns removing the file on exit.
func acquireInitLock(path string) (*os.File, error) {
	const maxWait = 60 * time.Second
	const pollDelay = 500 * time.Millisecond
	deadline := time.Now().Add(maxWait)
	for {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err == nil {
			return f, nil
		}
		if !os.IsExist(err) {
			return nil, err
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("lock %s held for >%s", path, maxWait)
		}
		time.Sleep(pollDelay)
	}
}

// buildFRIRuntimeArgs returns the positional args the Rúnar SDK
// expects at deploy time for the FRI rollup contract. The argument
// shape depends on how the artifact was compiled:
//
//   - If the artifact's constructor ABI has 3 params, readonly fields
//     were baked into the script at compile time (the path
//     gocompiler.CompileFromSource with ConstructorArgs takes) and we
//     pass only the 3 mutable-state fields.
//   - If the artifact's constructor ABI has 10 params, nothing was
//     baked and we pass all 3 mutable + 7 readonly positional values.
//
// The latter path keeps this helper compatible with any future
// workflow that compiles without the constructor-args map. The
// compile-time bake path is what init-cluster uses today.
func buildFRIRuntimeArgs(artifact *runar.RunarArtifact, sp1VK []byte, chainID int64, gov covenant.GovernanceConfig, stateRoot types.Hash) []interface{} {
	mutable := mutableFRIArgs(stateRoot)
	abiParams := len(artifact.ABI.Constructor.Params)
	if abiParams == 3 {
		return mutable
	}
	// Fallback — emit all ten positional args for the un-baked path.
	readonly := readonlyFRIArgs(sp1VK, chainID, gov)
	return append(mutable, readonly...)
}

// mutableFRIArgs returns the 3 mutable-state positional args: stateRoot,
// blockNumber (0), frozen (0).
func mutableFRIArgs(stateRoot types.Hash) []interface{} {
	stateRootHex := strings.TrimPrefix(stateRoot.Hex(), "0x")
	return []interface{}{
		stateRootHex, // stateRoot
		int64(0),     // blockNumber
		int64(0),     // frozen
	}
}

// readonlyFRIArgs returns the 7 readonly positional args. Only used on
// the un-baked compile path (retained for forward compatibility with
// any future workflow that omits CompileOptions.ConstructorArgs).
func readonlyFRIArgs(sp1VK []byte, chainID int64, gov covenant.GovernanceConfig) []interface{} {
	emptyKey := strings.Repeat("00", 33)
	key1, key2, key3 := emptyKey, emptyKey, emptyKey
	if len(gov.Keys) >= 1 {
		key1 = hex.EncodeToString(gov.Keys[0])
	}
	if len(gov.Keys) >= 2 {
		key2 = hex.EncodeToString(gov.Keys[1])
	}
	if len(gov.Keys) >= 3 {
		key3 = hex.EncodeToString(gov.Keys[2])
	}

	vkHash := sha256Hex(sp1VK)
	modeInt := int64(gov.Mode)
	threshold := int64(gov.Threshold)
	if gov.Mode == covenant.GovernanceSingleKey && threshold == 0 {
		threshold = 1
	}

	return []interface{}{
		vkHash,    // sP1VerifyingKeyHash
		chainID,   // chainId
		modeInt,   // governanceMode
		threshold, // governanceThreshold
		key1,      // governanceKey
		key2,      // governanceKey2
		key3,      // governanceKey3
	}
}

// sha256Hex returns the hex-encoded sha256 of the input.
func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// loadOrCreateBootstrapWalletKey ensures a one-shot BSV deploy key exists
// at <dir>/bootstrap_wallet.wif. On first call the key is generated
// randomly and persisted with mode 0600; subsequent calls load it.
// Distinct from the per-node fee_wallet.wif handled by fee_wallet_key.go.
func loadOrCreateBootstrapWalletKey(dir string) (*ec.PrivateKey, error) {
	if dir == "" {
		return nil, fmt.Errorf("bootstrap wallet directory must not be empty")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("creating bootstrap wallet dir: %w", err)
	}
	path := filepath.Join(dir, bootstrapWalletFile)
	raw, err := os.ReadFile(path)
	if err == nil {
		priv, perr := ec.PrivateKeyFromHex(strings.TrimSpace(string(raw)))
		if perr != nil {
			return nil, fmt.Errorf("parsing %s: %w", path, perr)
		}
		return priv, nil
	}
	if !os.IsNotExist(err) {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return nil, fmt.Errorf("generating bootstrap key: %w", err)
	}
	hexKey := hex.EncodeToString(buf)
	priv, err := ec.PrivateKeyFromHex(hexKey)
	if err != nil {
		return nil, fmt.Errorf("loading generated bootstrap key: %w", err)
	}
	if err := os.WriteFile(path, []byte(hexKey), 0o600); err != nil {
		return nil, fmt.Errorf("persisting bootstrap key: %w", err)
	}
	return priv, nil
}

// fundBootstrapWallet funds the bootstrap wallet on regtest by importing
// the address, sending 5 BSV to it, mining one block, and polling
// listunspent until at least one UTXO is visible.
func fundBootstrapWallet(ctx context.Context, provider *bsvclient.RPCProvider, address string) error {
	if _, err := provider.Call("importaddress", address, "", false); err != nil {
		msg := strings.ToLower(err.Error())
		if !strings.Contains(msg, "already") {
			return fmt.Errorf("importaddress: %w", err)
		}
	}
	if _, err := provider.Call("sendtoaddress", address, deployFundBTC); err != nil {
		return fmt.Errorf("sendtoaddress: %w", err)
	}
	if _, err := provider.Call("generatetoaddress", 1, address); err != nil {
		return fmt.Errorf("generatetoaddress: %w", err)
	}

	pollCtx, cancel := context.WithTimeout(ctx, deployUtxoPollBudget)
	defer cancel()
	ticker := time.NewTicker(deployUtxoPollInterval)
	defer ticker.Stop()
	// One quick probe before falling into the ticker.
	if utxos, err := provider.GetUtxos(address); err == nil && len(utxos) > 0 {
		slog.Info("init-cluster: bootstrap UTXO surfaced", "count", len(utxos))
		return nil
	}
	for {
		select {
		case <-pollCtx.Done():
			return fmt.Errorf("timed out waiting for bootstrap UTXO at %s", address)
		case <-ticker.C:
			utxos, err := provider.GetUtxos(address)
			if err == nil && len(utxos) > 0 {
				slog.Info("init-cluster: bootstrap UTXO surfaced", "count", len(utxos))
				return nil
			}
		}
	}
}

// writeGenesisAlloc serializes the genesis alloc map to JSON at the
// given path. The encoding uses lowercase hex addresses for human
// readability.
func writeGenesisAlloc(path string, alloc map[types.Address]block.GenesisAccount) error {
	serialised := make(map[string]block.GenesisAccount, len(alloc))
	for addr, acc := range alloc {
		serialised[strings.ToLower(addr.Hex())] = acc
	}
	buf, err := json.MarshalIndent(serialised, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal alloc: %w", err)
	}
	if err := os.WriteFile(path, buf, 0o644); err != nil {
		return fmt.Errorf("write alloc file: %w", err)
	}
	return nil
}
