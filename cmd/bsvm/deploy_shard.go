// Deploy-shard subcommand: the "one transaction" entrypoint for
// bootstrapping a BSVM shard. Compiles the rollup covenant, produces
// the genesis manifest, and broadcasts a single BSV transaction whose
// vout 0 is the covenant UTXO and whose vout 1 is the OP_RETURN
// manifest envelope. The txid is then the only input a node needs to
// run the shard (`bsvm run --genesis-txid <txid>`).
//
// The single-tx design keeps node bootstrap trivial: read one tx,
// parse both outputs, cross-validate, start. It also keeps the
// spec-12 "BSV is the consensus layer" property honest — nothing the
// nodes need lives off-chain.
//
// This command replaces the older `bsvm init-cluster` workflow which
// wrote a shared shard.json to a Docker volume. init-cluster remains
// in place for backward compatibility but is considered deprecated.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	sdkscript "github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
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

// deployShardLockFile serialises concurrent invocations against the
// same --datadir.
const deployShardLockFile = ".deploy-lock"

// deployShardGenesisTxIDFile is the filename `bsvm deploy-shard`
// writes the resulting txid into, so downstream tooling (docker
// compose, shell scripts) can read it back without parsing logs.
const deployShardGenesisTxIDFile = "genesis.txid"

// deployShardGenesisTxFile is the filename `bsvm deploy-shard` writes
// the raw genesis transaction hex into. Follower nodes that don't
// have their own BSV RPC access can mount this file (or receive it
// via P2P) and boot the shard without ever talking to BSV. Since
// txid = double_sha256(rawTx) reversed, the raw tx is self-
// certifying — a node that hashes the file and compares to the
// expected txid gets tamper-evidence for free.
const deployShardGenesisTxFile = "genesis.tx"

// deployShardBootstrapWalletFile is the on-disk location of the
// one-shot BSV deploy key. Named distinctly from the per-node
// fee_wallet.wif so operators can tell them apart at a glance.
const deployShardBootstrapWalletFile = "bootstrap_wallet.wif"

// cmdDeployShard implements the `bsvm deploy-shard` subcommand.
// Flags (mirror init-cluster so existing wrappers keep working):
//
//	--datadir          where to write genesis.txid / covenant.anf.json
//	--bsv-rpc          BSV JSON-RPC endpoint (or BSVM_BSV_RPC)
//	--bsv-network      regtest|testnet|mainnet (default regtest)
//	--prove-mode       execute|prove (execute → FRI, prove → g16-wa)
//	--verification     fri|groth16|groth16-wa|devkey (override)
//	--governance       none|single_key|multisig (default single_key)
//	--chain-id         EVM chain id (default 31337)
//	--gas-limit        genesis block gas limit (default 30000000)
//	--prefund-accounts hardhat|none
//	--alloc-file       optional JSON file with an address→balance map
func cmdDeployShard(ctx *cli.Context) error {
	dataDir := ctx.String("datadir")
	bsvRPC := strings.TrimSpace(ctx.String("bsv-rpc"))
	if bsvRPC == "" {
		bsvRPC = strings.TrimSpace(os.Getenv("BSVM_BSV_RPC"))
	}
	if bsvRPC == "" {
		return fmt.Errorf("deploy-shard: --bsv-rpc (or BSVM_BSV_RPC) is required")
	}
	bsvNet := ctx.String("bsv-network")
	if bsvNet == "" {
		bsvNet = "regtest"
	}
	proveMode := ctx.String("prove-mode")
	if proveMode == "" {
		proveMode = "execute"
	}
	verification := ctx.String("verification")
	governance := ctx.String("governance")
	chainID := ctx.Int64("chain-id")
	if chainID == 0 {
		chainID = 31337
	}
	gasLimit := ctx.Uint64("gas-limit")
	if gasLimit == 0 {
		gasLimit = block.DefaultGasLimit
	}
	prefund := ctx.String("prefund-accounts")
	if prefund == "" {
		prefund = "hardhat"
	}

	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return fmt.Errorf("deploy-shard: ensure datadir: %w", err)
	}

	// Coarse lock so parallel invocations serialise.
	lockPath := filepath.Join(dataDir, deployShardLockFile)
	lockFile, err := acquireInitLock(lockPath)
	if err != nil {
		return fmt.Errorf("deploy-shard: acquire lock: %w", err)
	}
	defer func() {
		_ = lockFile.Close()
		_ = os.Remove(lockPath)
	}()

	// Idempotency: if a genesis.txid already exists AND the referenced
	// covenant tx is live on BSV, no-op so `docker compose up` restarts
	// without re-deploying. A missing or unresolved txid means we
	// proceed with a fresh deploy.
	txidPath := filepath.Join(dataDir, deployShardGenesisTxIDFile)
	if raw, readErr := os.ReadFile(txidPath); readErr == nil {
		existing := strings.TrimSpace(strings.TrimPrefix(string(raw), "0x"))
		if existing != "" {
			p, provErr := bsvclient.NewRPCProvider(bsvRPC, bsvNet)
			if provErr == nil {
				_, txErr := p.GetRawTransactionVerbose(existing)
				if txErr == nil {
					slog.Info("deploy-shard: existing genesis.txid references live tx, no-op",
						"txid", existing)
					fmt.Println(existing)
					return nil
				}
				slog.Warn("deploy-shard: existing genesis.txid references missing tx; re-deploying",
					"txid", existing, "err", txErr)
			}
		}
	}

	// Resolve verification mode.
	verifyMode, verifyModeStr, err := resolveVerificationMode(proveMode, verification)
	if err != nil {
		return fmt.Errorf("deploy-shard: %w", err)
	}

	// Governance: default single_key with the devnet governance key.
	govMode := governance
	if govMode == "" {
		govMode = "single_key"
	}
	govConfig, err := resolveGovernanceConfig(govMode)
	if err != nil {
		return fmt.Errorf("deploy-shard: %w", err)
	}

	// Genesis alloc.
	alloc, err := resolveGenesisAlloc(prefund, ctx.String("alloc-file"))
	if err != nil {
		return fmt.Errorf("deploy-shard: %w", err)
	}

	slog.Info("deploy-shard: starting",
		"datadir", dataDir,
		"bsvNet", bsvNet,
		"chainID", chainID,
		"verification", verifyModeStr,
		"governance", govMode,
		"allocAccounts", len(alloc))

	// Compute the genesis state root in a throwaway DB so we can bake
	// it into the covenant's initial stateRoot readonly property.
	tmpDB := db.NewMemoryDB()
	genesisHeader, err := block.InitGenesis(tmpDB, &block.Genesis{
		Config:    vm.DefaultL2Config(chainID),
		Timestamp: 0,
		GasLimit:  gasLimit,
		Alloc:     alloc,
	})
	if err != nil {
		return fmt.Errorf("deploy-shard: InitGenesis (temp): %w", err)
	}
	tmpDB.Close()
	slog.Info("deploy-shard: genesis state root computed",
		"stateRoot", genesisHeader.StateRoot.Hex())

	// SP1 VK: zeros for FRI / DevKey (neither consults it on-chain).
	// Mainnet-eligible modes (Groth16, Groth16-WA) aren't routed here
	// in this phase — see phase 3c gaps. resolveVerificationMode
	// rejects them above for now.
	sp1VK := make([]byte, 32)

	// Compile the covenant. Go through covenant.PrepareGenesis so
	// every mainnet guardrail (Mode 1 FRI rejection, VK pinning)
	// stays enforced; the deploy-shard command never bypasses them.
	genesisResult, err := covenant.PrepareGenesis(&covenant.GenesisConfig{
		ChainID:          uint64(chainID),
		SP1VerifyingKey:  sp1VK,
		InitialStateRoot: genesisHeader.StateRoot,
		Governance:       govConfig,
		Verification:     verifyMode,
		CovenantSats:     covenant.DefaultCovenantSats,
	})
	if err != nil {
		return fmt.Errorf("deploy-shard: prepare covenant: %w", err)
	}
	slog.Info("deploy-shard: covenant compiled",
		"scriptBytes", len(genesisResult.Covenant.LockingScript))

	// BSV provider + bootstrap wallet.
	provider, err := bsvclient.NewRPCProvider(bsvRPC, bsvNet)
	if err != nil {
		return fmt.Errorf("deploy-shard: provider: %w", err)
	}
	bootstrapKey, err := loadOrCreateDeployBootstrapKey(dataDir)
	if err != nil {
		return fmt.Errorf("deploy-shard: bootstrap key: %w", err)
	}
	bootstrapAddr, err := FeeWalletBSVAddress(bootstrapKey, bsvNet)
	if err != nil {
		return fmt.Errorf("deploy-shard: bootstrap address: %w", err)
	}
	slog.Info("deploy-shard: bootstrap wallet ready", "address", bootstrapAddr)

	if bsvNet == "regtest" {
		if err := fundBootstrapWallet(ctx.Context, provider, bootstrapAddr); err != nil {
			return fmt.Errorf("deploy-shard: fund bootstrap wallet: %w", err)
		}
	} else {
		slog.Warn("deploy-shard: non-regtest — operator must pre-fund the bootstrap wallet",
			"address", bootstrapAddr)
	}

	// Build the genesis manifest.
	manifest := &shard.GenesisManifest{
		Version:          shard.GenesisManifestVersion,
		ChainID:          chainID,
		GasLimit:         gasLimit,
		VerificationMode: verifyModeStr,
		SP1VerifyingKey:  hex.EncodeToString(sp1VK),
		Governance:       shard.GovernanceFromConfig(govConfig),
		Alloc:            shard.AllocFromMap(alloc),
		CovenantSats:     covenant.DefaultCovenantSats,
		Timestamp:        time.Now().Unix(),
	}
	manifestBytes, err := shard.EncodeManifest(manifest)
	if err != nil {
		return fmt.Errorf("deploy-shard: encode manifest: %w", err)
	}

	// Build the runtime locking script (code + state).
	sdkArtifact, err := recompileBakedArtifactForDeploy(verifyMode, sp1VK, uint64(chainID), govConfig)
	if err != nil {
		return fmt.Errorf("deploy-shard: recompile covenant artifact: %w", err)
	}
	stateRootHex := strings.TrimPrefix(genesisHeader.StateRoot.Hex(), "0x")
	contract := runar.NewRunarContract(sdkArtifact, []interface{}{
		stateRootHex,
		int64(0), // blockNumber
		int64(0), // frozen
	})
	lockingScriptHex := contract.GetLockingScript()

	// Deploy tx: vout 0 = covenant, vout 1 = OP_RETURN manifest,
	// vout 2 (optional) = change.
	txid, covenantVout, rawTxHex, err := broadcastGenesisTx(
		ctx.Context,
		provider,
		bootstrapKey,
		bootstrapAddr,
		lockingScriptHex,
		int64(covenant.DefaultCovenantSats),
		manifestBytes,
	)
	if err != nil {
		return fmt.Errorf("deploy-shard: broadcast: %w", err)
	}
	slog.Info("deploy-shard: genesis broadcast", "txid", txid, "vout", covenantVout, "raw_bytes", len(rawTxHex)/2)

	// Mine one confirmation on regtest.
	if bsvNet == "regtest" {
		if _, err := provider.Call("generatetoaddress", 1, bootstrapAddr); err != nil {
			slog.Warn("deploy-shard: generatetoaddress after broadcast failed (non-fatal)", "err", err)
		}
	}

	// Verify the tx is retrievable.
	if _, err := provider.GetRawTransactionVerbose(txid); err != nil {
		return fmt.Errorf("deploy-shard: genesis tx not retrievable: %w", err)
	}

	// Write the genesis txid to disk for downstream scripts.
	if err := os.WriteFile(txidPath, []byte(txid+"\n"), 0o644); err != nil {
		return fmt.Errorf("deploy-shard: write genesis.txid: %w", err)
	}

	// Write the raw tx hex so follower nodes (no BSV RPC) can derive
	// the shard offline. The file is self-certifying: any reader that
	// hashes the bytes and reverses the result must match genesis.txid.
	rawTxPath := filepath.Join(dataDir, deployShardGenesisTxFile)
	if err := os.WriteFile(rawTxPath, []byte(rawTxHex+"\n"), 0o644); err != nil {
		return fmt.Errorf("deploy-shard: write genesis.tx: %w", err)
	}

	// Save covenant.anf.json for audit (matches InitShard convention).
	if genesisResult.ANF != nil {
		if err := os.WriteFile(filepath.Join(dataDir, "covenant.anf.json"), genesisResult.ANF, 0o644); err != nil {
			slog.Warn("deploy-shard: writing covenant.anf.json failed (non-fatal)", "err", err)
		}
	}

	// stdout line so shell scripts can capture the txid without
	// parsing structured logs.
	fmt.Println(txid)

	slog.Info("deploy-shard: DONE",
		"txid", txid,
		"vout", covenantVout,
		"sats", covenant.DefaultCovenantSats,
		"stateRoot", genesisHeader.StateRoot.Hex(),
		"manifest_bytes", len(manifestBytes))
	return nil
}

// resolveVerificationMode picks the covenant verification mode from
// the --prove-mode and --verification flags. Explicit --verification
// always wins; otherwise prove-mode maps execute→fri, prove→g16-wa.
func resolveVerificationMode(proveMode, verification string) (covenant.VerificationMode, string, error) {
	v := verification
	if v == "" {
		switch proveMode {
		case "execute", "":
			v = "fri"
		case "prove":
			return 0, "", fmt.Errorf("prove-mode=prove (Groth16-WA) not yet wired in deploy-shard; use --verification=fri for now")
		case "mock":
			v = "devkey"
		default:
			return 0, "", fmt.Errorf("invalid --prove-mode %q", proveMode)
		}
	}
	switch v {
	case "fri":
		return covenant.VerifyFRI, "fri", nil
	case "devkey":
		return covenant.VerifyDevKey, "devkey", nil
	case "groth16":
		return 0, "", fmt.Errorf("--verification=groth16 not yet wired in deploy-shard (requires VK fixture)")
	case "groth16-wa":
		// Mode 3 (Groth16-WA) is mainnet-eligible but unreachable from
		// the mock / execute prover paths: the rollup covenant's
		// publicInput[1] == reducePublicValuesToScalarWA(publicValues)
		// binding requires a fresh SP1 Groth16 proof per batch, and
		// the only fixtures shipping with this repo (tests/sp1/,
		// pkg/overlay/testdata/) are the fixed Gate 0b sample whose
		// public inputs cannot satisfy the binding for a per-batch
		// publicValues blob. Deploy-shard therefore refuses Mode 3
		// until a real SP1 prover is wired (GPU, minutes per proof).
		// Use --verification=fri for the trust-minimized devnet path.
		return 0, "", fmt.Errorf("--verification=groth16-wa requires a real SP1 prover that produces a fresh " +
			"Groth16 proof per batch; the mock prover reuses the Gate 0b fixture whose publicInputs cannot " +
			"bind to per-batch publicValues. Use --verification=fri for devnet until a GPU-backed prover is wired")
	default:
		return 0, "", fmt.Errorf("invalid --verification %q", v)
	}
}

// resolveGovernanceConfig returns the governance config for the given
// mode string. For single_key the devnet governance key is used; for
// multisig the caller must extend this (future work — not needed for
// deploy-shard's devnet role today).
func resolveGovernanceConfig(mode string) (covenant.GovernanceConfig, error) {
	switch mode {
	case "none":
		return covenant.GovernanceConfig{Mode: covenant.GovernanceNone}, nil
	case "single_key":
		pub, err := shard.DevnetGovernanceKey()
		if err != nil {
			return covenant.GovernanceConfig{}, fmt.Errorf("devnet gov key: %w", err)
		}
		return covenant.GovernanceConfig{
			Mode: covenant.GovernanceSingleKey,
			Keys: [][]byte{pub},
		}, nil
	case "multisig":
		return covenant.GovernanceConfig{}, fmt.Errorf("--governance multisig not yet wired in deploy-shard")
	default:
		return covenant.GovernanceConfig{}, fmt.Errorf("invalid --governance %q", mode)
	}
}

// resolveGenesisAlloc returns the initial account allocations for the
// deploy. prefund drives the well-known helpers (hardhat / none);
// allocFile, when non-empty, is a JSON file mapping hex addresses to
// balances (decimal strings) that overrides / extends the prefund set.
func resolveGenesisAlloc(prefund, allocFile string) (map[types.Address]block.GenesisAccount, error) {
	out := map[types.Address]block.GenesisAccount{}
	switch prefund {
	case "", "none":
	case "hardhat":
		perAccount := new(uint256.Int).SetUint64(1000)
		perAccount.Mul(perAccount, new(uint256.Int).Exp(
			uint256.NewInt(10), uint256.NewInt(18),
		))
		for addr, acc := range shard.HardhatPrefundAlloc(perAccount) {
			out[addr] = acc
		}
	default:
		return nil, fmt.Errorf("invalid --prefund-accounts %q", prefund)
	}
	if allocFile != "" {
		raw, err := os.ReadFile(allocFile)
		if err != nil {
			return nil, fmt.Errorf("read alloc-file %s: %w", allocFile, err)
		}
		var extra map[string]string
		if err := json.Unmarshal(raw, &extra); err != nil {
			return nil, fmt.Errorf("parse alloc-file %s: %w", allocFile, err)
		}
		for addrStr, balStr := range extra {
			addr := types.HexToAddress(strings.TrimPrefix(addrStr, "0x"))
			bal := new(uint256.Int)
			if err := bal.SetFromDecimal(balStr); err != nil {
				return nil, fmt.Errorf("alloc %s balance %q: %w", addrStr, balStr, err)
			}
			out[addr] = block.GenesisAccount{Balance: bal}
		}
	}
	return out, nil
}

// broadcastGenesisTx builds and broadcasts a single BSV transaction
// containing:
//
//	vout 0 → covenant locking script with `satoshis` sats
//	vout 1 → OP_FALSE OP_RETURN OP_PUSHDATA4 <manifest>
//	vout 2 → P2PKH change to the bootstrap wallet (if non-zero)
//
// Returns the txid, the covenant vout (always 0 for this path), and
// the raw tx hex (as serialised and signed). The raw tx is emitted
// alongside the txid so the deploy helper can persist it — follower
// nodes hash the bytes to recover the genesis txid with no trust
// assumption on who handed them the file.
// The tx is signed with bootstrapKey and broadcast via the provider.
func broadcastGenesisTx(
	ctx context.Context,
	provider *bsvclient.RPCProvider,
	bootstrapKey *ec.PrivateKey,
	bootstrapAddr string,
	lockingScriptHex string,
	covenantSats int64,
	manifestBytes []byte,
) (string, uint32, string, error) {
	utxos, err := provider.GetUtxos(bootstrapAddr)
	if err != nil {
		return "", 0, "", fmt.Errorf("listunspent: %w", err)
	}
	if len(utxos) == 0 {
		return "", 0, "", fmt.Errorf("no UTXOs at %s", bootstrapAddr)
	}

	// Fee estimate: the SDK's helper assumes single covenant output +
	// P2PKH change. Our manifest output adds ~manifestBytes + 5 bytes
	// of envelope. Bump the locking-script byte length argument by the
	// manifest size so the fee covers it; this is an over-estimate
	// (P2PKH change is included in EstimateDeployFee's output cost
	// but the manifest output is tiny) but deploy tx fees are cheap.
	feeRate, err := provider.GetFeeRate()
	if err != nil {
		return "", 0, "", fmt.Errorf("GetFeeRate: %w", err)
	}
	lockingScriptBytes := len(lockingScriptHex) / 2
	opReturnBytes := len(manifestBytes) + 5 // OP_FALSE OP_RETURN OP_PUSHDATA4 <len4>
	selected := runar.SelectUtxos(utxos, covenantSats, lockingScriptBytes+opReturnBytes, feeRate)

	totalInput := int64(0)
	for _, u := range selected {
		totalInput += u.Satoshis
	}
	// A rough fee bump to cover the manifest output. 1 sat/KB * ~1 KB
	// extra script data is negligible but we add a buffer so we never
	// under-pay on testnet / mainnet.
	fee := runar.EstimateDeployFee(len(selected), lockingScriptBytes+opReturnBytes, feeRate)
	change := totalInput - covenantSats - fee
	if change < 0 {
		return "", 0, "", fmt.Errorf("insufficient funds: need %d sats, have %d", covenantSats+fee, totalInput)
	}

	tx := transaction.NewTransaction()
	for _, u := range selected {
		if err := tx.AddInputFrom(u.Txid, uint32(u.OutputIndex), u.Script, uint64(u.Satoshis), nil); err != nil {
			return "", 0, "", fmt.Errorf("add input %s:%d: %w", u.Txid, u.OutputIndex, err)
		}
	}

	// vout 0: covenant
	covenantLS, err := sdkscript.NewFromHex(lockingScriptHex)
	if err != nil {
		return "", 0, "", fmt.Errorf("covenant locking script: %w", err)
	}
	tx.AddOutput(&transaction.TransactionOutput{
		Satoshis:      uint64(covenantSats),
		LockingScript: covenantLS,
	})

	// vout 1: OP_RETURN manifest (OP_FALSE OP_RETURN OP_PUSHDATA4 <len4> <payload>)
	opReturnHex := buildOpReturnScriptHex(manifestBytes)
	opReturnLS, err := sdkscript.NewFromHex(opReturnHex)
	if err != nil {
		return "", 0, "", fmt.Errorf("manifest OP_RETURN script: %w", err)
	}
	tx.AddOutput(&transaction.TransactionOutput{
		Satoshis:      0,
		LockingScript: opReturnLS,
	})

	// vout 2: change
	if change > 0 {
		changeLS, err := sdkscript.NewFromHex(runar.BuildP2PKHScript(bootstrapAddr))
		if err != nil {
			return "", 0, "", fmt.Errorf("change script: %w", err)
		}
		tx.AddOutput(&transaction.TransactionOutput{
			Satoshis:      uint64(change),
			LockingScript: changeLS,
		})
	}

	// Sign every input with the bootstrap key.
	pubKeyHex := hex.EncodeToString(bootstrapKey.PubKey().Compressed())
	signer, err := runar.NewLocalSigner(hex.EncodeToString(bootstrapKey.Serialize()))
	if err != nil {
		return "", 0, "", fmt.Errorf("local signer: %w", err)
	}
	for i, u := range selected {
		sig, sigErr := signer.Sign(tx.Hex(), i, u.Script, u.Satoshis, nil)
		if sigErr != nil {
			return "", 0, "", fmt.Errorf("sign input %d: %w", i, sigErr)
		}
		unlockHex := runar.EncodePushData(sig) + runar.EncodePushData(pubKeyHex)
		unlock, ulErr := sdkscript.NewFromHex(unlockHex)
		if ulErr != nil {
			return "", 0, "", fmt.Errorf("unlock script %d: %w", i, ulErr)
		}
		tx.Inputs[i].UnlockingScript = unlock
	}

	// Honour context cancellation just before the RPC call — the
	// provider API doesn't support it natively.
	if err := ctx.Err(); err != nil {
		return "", 0, "", err
	}
	// Capture the raw tx hex AFTER signing but BEFORE broadcast so
	// the file we hand to followers matches the bytes BSV will see.
	rawTxHex := tx.Hex()
	txid, err := provider.Broadcast(tx)
	if err != nil {
		return "", 0, "", fmt.Errorf("broadcast: %w", err)
	}
	return txid, 0, rawTxHex, nil
}

// buildOpReturnScriptHex wraps a data payload in
// OP_FALSE OP_RETURN OP_PUSHDATA4 <len-le4> <payload>. OP_PUSHDATA4
// is used so any payload size up to 4 GiB works; for the ~KB manifest
// a smaller pushdata would suffice, but the constant-size prefix keeps
// the decoder predictable.
func buildOpReturnScriptHex(payload []byte) string {
	buf := make([]byte, 0, 2+5+len(payload))
	buf = append(buf, 0x00, 0x6a) // OP_FALSE OP_RETURN
	buf = append(buf, 0x4e)       // OP_PUSHDATA4
	buf = append(buf, byte(len(payload)), byte(len(payload)>>8), byte(len(payload)>>16), byte(len(payload)>>24))
	buf = append(buf, payload...)
	return hex.EncodeToString(buf)
}

// loadOrCreateDeployBootstrapKey is the deploy-shard copy of the
// cluster_init bootstrap-key helper. Kept distinct so the two
// subcommands don't share state paths.
func loadOrCreateDeployBootstrapKey(dir string) (*ec.PrivateKey, error) {
	if dir == "" {
		return nil, fmt.Errorf("bootstrap wallet directory must not be empty")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, deployShardBootstrapWalletFile)
	raw, err := os.ReadFile(path)
	if err == nil {
		priv, perr := ec.PrivateKeyFromHex(strings.TrimSpace(string(raw)))
		if perr != nil {
			return nil, fmt.Errorf("parse %s: %w", path, perr)
		}
		return priv, nil
	}
	if !os.IsNotExist(err) {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return nil, err
	}
	hexKey := hex.EncodeToString(buf)
	priv, err := ec.PrivateKeyFromHex(hexKey)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, []byte(hexKey), 0o600); err != nil {
		return nil, err
	}
	return priv, nil
}

// recompileBakedArtifactForDeploy reproduces the gocompiler artifact
// deploy-shard hands to runar.NewRunarContract. Mirrors the helper
// in pkg/shard/derive_helpers.go but kept local to cmd/bsvm so the
// deploy and derive paths stay independently testable.
func recompileBakedArtifactForDeploy(mode covenant.VerificationMode, sp1VK []byte, chainID uint64, gov covenant.GovernanceConfig) (*runar.RunarArtifact, error) {
	var (
		srcName string
		args    map[string]interface{}
		err     error
	)
	switch mode {
	case covenant.VerifyFRI:
		srcName = "rollup_fri.runar.go"
		args, err = covenant.BuildFRIConstructorArgsExported(sp1VK, chainID, gov)
	case covenant.VerifyDevKey:
		srcName = "rollup_devkey.runar.go"
		args, err = covenant.BuildFRIConstructorArgsExported(sp1VK, chainID, gov)
	default:
		return nil, fmt.Errorf("recompile not implemented for mode %s", mode.String())
	}
	if err != nil {
		return nil, err
	}
	src := findContractPath(srcName)
	compiled, err := gocompiler.CompileFromSource(src, gocompiler.CompileOptions{
		ConstructorArgs: args,
	})
	if err != nil {
		return nil, fmt.Errorf("compile %s: %w", srcName, err)
	}
	blob, err := json.Marshal(compiled)
	if err != nil {
		return nil, err
	}
	var sdk runar.RunarArtifact
	if err := json.Unmarshal(blob, &sdk); err != nil {
		return nil, err
	}
	return &sdk, nil
}
