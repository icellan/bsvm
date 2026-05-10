// Spec-16 BSV covenant-broadcast wiring for the bsvm binary. The helper
// in this file assembles the full advance-broadcast stack (fee wallet,
// JSON-RPC provider, Rúnar signer, deployed-contract binding,
// RunarBroadcastClient) and attaches it to the overlay's covenant
// manager so ProcessBatch actually submits advance transactions to BSV
// when the shard runs in devnet mock, execute, or prove mode.
package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	sdkhash "github.com/bsv-blockchain/go-sdk/primitives/hash"
	"github.com/icellan/bsvm/internal/db"
	"github.com/icellan/bsvm/pkg/arc"
	"github.com/icellan/bsvm/pkg/bsv"
	"github.com/icellan/bsvm/pkg/covenant"
	"github.com/icellan/bsvm/pkg/metrics"
	"github.com/icellan/bsvm/pkg/overlay"
	"github.com/icellan/bsvm/pkg/shard"

	gocompiler "github.com/icellan/runar/compilers/go/compiler"
	runar "github.com/icellan/runar/packages/runar-go"
)

// bsvHash160 computes RIPEMD160(SHA256(data)) — Bitcoin's standard
// pubkey hash function. Used at boot time to derive the fee wallet's
// expected P2PKH locking script from its compressed public key, then
// published via FeeWallet.SetExpectedScriptPubKey for the BEEF
// fee-wallet-funding consumer to match against.
func bsvHash160(data []byte) []byte {
	return sdkhash.Hash160(data)
}

// bsvWireOpts gathers every input wireBSVBroadcast needs. Keeps the
// main.go call site tidy and makes unit-testing (a future task) easier.
//
// Exactly one of ShardCfg / DerivedBoot must be non-nil. The legacy
// shard.json-driven boot produces ShardCfg; the Phase 8 genesis-txid
// boot produces DerivedBoot. Provider may be supplied pre-built when
// the caller already instantiated one (Phase 8 path) to avoid a
// second RPCProvider construction.
type bsvWireOpts struct {
	NodeCfg     *NodeConfig
	ShardCfg    *shard.ShardConfig
	DerivedBoot *bootResult
	ChainID     int64
	ProveMode   string
	DataDir     string
	DB          db.Database
	OverlayNode *overlay.OverlayNode
	CovenantMgr *covenant.CovenantManager
	// Provider is the BSV-node JSON-RPC client. May be a single-
	// endpoint *bsvclient.RPCProvider or the W6-11 failover wrapper
	// *bsvclient.MultiRPCProvider — both satisfy BSVProviderClient and
	// every consumer downstream is interface-typed accordingly.
	Provider BSVProviderClient
	// Counters is the daemon's shared metrics surface. Threaded into
	// the ARC client construction so ARCBroadcastAttempts /
	// ARCBroadcastFailed counters fire on every broadcast. Pass nil
	// only in tests; production code uses overlayNode.Counters().
	Counters *metrics.Counters
}

// bsvBroadcastResult captures the post-wiring artefacts callers may
// need to drive other subsystems (currently: the bridge.Withdrawer
// claim-tx loop, which signs with the same fee-wallet key the
// covenant-advance path uses). All fields are non-nil on success.
type bsvBroadcastResult struct {
	// FeeSigner is the runar.LocalSigner over the fee-wallet
	// PrivateKey. Suitable for SignInput-style protocols (the wallet
	// consolidation, withdrawal claims, etc.).
	FeeSigner *runar.LocalSigner
	// FeeAddress is the canonical P2PKH address derived from the fee
	// key for the active BSV network.
	FeeAddress string
	// Provider is the BSV-node JSON-RPC client the broadcast stack
	// uses. Returned so downstream wiring re-uses the same instance
	// rather than spawning a second connection pool.
	Provider BSVProviderClient
	// FeeWallet is the prover's BSV UTXO float. Exposed so the
	// bridge.Withdrawer can fund per-claim miner fees from it (spec
	// 07 Input 1 / Output 2). Same wallet the covenant-advance path
	// spends from — they share UTXOs.
	FeeWallet *overlay.FeeWallet
	// ARC is the production ARC broadcaster wired from the operator's
	// [bsv].arc_url / [bsv].arc_endpoint config. Nil when no ARC
	// endpoints are configured — downstream consumers (NetworkClient,
	// the BEEF callback handler, bridge claim retries) treat nil as
	// "ARC role disabled" and surface ErrProviderDisabled. Built with
	// metrics already attached so ARCBroadcastAttempts /
	// ARCBroadcastFailed{class} counters fire automatically.
	ARC arc.ARCClient
}

// wireBSVBroadcast builds the full covenant-advance broadcast stack —
// fee wallet, BSV JSON-RPC provider, Rúnar signer, deployed-contract
// binding, RunarBroadcastClient — and attaches it to the overlay's
// covenant manager. It also starts the confirmation watcher goroutine.
//
// On success it returns a result struct exposing the fee signer,
// address, and provider so downstream wiring (the bridge.Withdrawer
// loop in particular) can re-use them without re-deriving the key.
func wireBSVBroadcast(ctx context.Context, opts bsvWireOpts) (*bsvBroadcastResult, error) {
	rollupInputs, err := rollupSourceInputsFromOpts(opts)
	if err != nil {
		return nil, fmt.Errorf("rollup source inputs: %w", err)
	}
	bsvNet := opts.NodeCfg.BSV.Network
	if bsvNet == "" {
		bsvNet = "regtest"
	}

	// 1. Persist/load the fee-wallet key.
	feeKey, err := LoadOrCreateFeeWalletKey(opts.DataDir)
	if err != nil {
		return nil, fmt.Errorf("fee-wallet key: %w", err)
	}
	broadcastKey := feeKey
	broadcastKeyHex := hex.EncodeToString(feeKey.Serialize())
	broadcastSignerRole := "fee-wallet"
	if rollupInputs.Verification == covenant.VerifyDevKey {
		govKeyHex := shard.DevnetGovernancePrivateKey()
		govKey, govErr := ec.PrivateKeyFromHex(govKeyHex)
		if govErr != nil {
			return nil, fmt.Errorf("devkey broadcast signer: %w", govErr)
		}
		broadcastKey = govKey
		broadcastKeyHex = govKeyHex
		broadcastSignerRole = "devnet-governance"
	}
	feeAddr, err := FeeWalletBSVAddress(broadcastKey, bsvNet)
	if err != nil {
		return nil, fmt.Errorf("fee-wallet address: %w", err)
	}
	slog.Info("fee-wallet key loaded", "address", feeAddr, "signer_role", broadcastSignerRole)

	// 2. FeeWallet backed by the shared LevelDB.
	feeWallet := overlay.NewFeeWallet(opts.DB)
	if err := feeWallet.LoadFromDB(); err != nil {
		return nil, fmt.Errorf("fee-wallet load from DB: %w", err)
	}
	// Publish the wallet's expected P2PKH locking script so the BEEF
	// fee-wallet-funding consumer can match outputs against it (see
	// cmd/bsvm/beef_wiring.go::makeFeeWalletConsumer). The wallet's
	// address is the standard P2PKH derived from feeKey via go-sdk;
	// we hash160 the compressed pubkey and wrap with the canonical
	// OP_DUP OP_HASH160 <pkh20> OP_EQUALVERIFY OP_CHECKSIG envelope.
	pubKeyBytes := broadcastKey.PubKey().Compressed()
	pkh := bsvHash160(pubKeyBytes)
	feeWallet.SetExpectedScriptPubKey(bsv.BuildP2PKH(pkh))
	slog.Info("fee-wallet initialized",
		"balance_sats", feeWallet.Balance(),
		"expected_script_published", true)

	// 3. Attach to overlay.
	opts.OverlayNode.SetFeeWallet(feeWallet)

	// 4. BSV JSON-RPC provider. Re-use the caller's provider if one
	// was supplied (Phase 8 path), otherwise build a fresh one.
	provider := opts.Provider
	if provider == nil {
		p, provErr := BuildBSVProvider(opts.NodeCfg.BSV)
		if provErr != nil {
			return nil, fmt.Errorf("BSV RPC provider: %w", provErr)
		}
		if p == nil {
			return nil, fmt.Errorf("BSV RPC provider: no node_url(s) configured")
		}
		provider = p
	}
	slog.Info("BSV RPC provider ready",
		"endpoints", opts.NodeCfg.BSV.EffectiveNodeURLs(),
		"network", bsvNet)

	// 4b. ARC broadcast client. Built here (rather than at the cmdRun
	// scope) so wireBSVBroadcast is the single shared bootstrap point
	// for every BSV-side broadcast surface. Round-9 UU added the
	// metrics counters but never built a production ARC client; this
	// closes that gap. nil is a valid result — operators who haven't
	// configured ARC see "arc client: not configured" in the logs and
	// downstream callers (NetworkClient.Broadcast, the BEEF callback
	// handler) surface ErrProviderDisabled at call time.
	arcClient, err := BuildARCClient(opts.NodeCfg.BSV, opts.Counters)
	if err != nil {
		return nil, fmt.Errorf("arc client: %w", err)
	}
	if arcClient != nil {
		if mc, ok := arcClient.(*arc.MultiClient); ok {
			eps := mc.Endpoints()
			urls := make([]string, 0, len(eps))
			for _, e := range eps {
				urls = append(urls, e.URL)
			}
			slog.Info("arc client ready",
				"endpoints", urls,
				"strategy", string(mc.Strategy()))
		} else {
			slog.Info("arc client ready", "type", "single")
		}
	} else {
		slog.Info("arc client: not configured (no [bsv].arc_url or [bsv].arc_endpoint set)")
	}

	// 5. Rúnar signer from the fee-wallet key. Wrap LocalSigner in
	// ExternalSigner so PrepareCall's GetUtxos(address) queries the
	// REGTEST address we imported — LocalSigner.GetAddress() hardcodes
	// mainnet, which would cause listunspent to reject the address.
	localSigner, err := runar.NewLocalSigner(broadcastKeyHex)
	if err != nil {
		return nil, fmt.Errorf("runar signer: %w", err)
	}
	signerPubKey, _ := localSigner.GetPublicKey()
	signer := runar.NewExternalSigner(
		signerPubKey,
		feeAddr,
		func(txHex string, inputIndex int, subscript string, satoshis int64, sigHashType *int) (string, error) {
			return localSigner.Sign(txHex, inputIndex, subscript, satoshis, sigHashType)
		},
	)

	// 6. Re-derive the deployed contract via FromTxId.
	contractSrc, constructorArgs, err := selectRollupSourceForBoot(opts)
	if err != nil {
		return nil, fmt.Errorf("selecting rollup source: %w", err)
	}

	gocompArtifact, err := gocompiler.CompileFromSource(contractSrc, gocompiler.CompileOptions{
		ConstructorArgs: constructorArgs,
	})
	if err != nil {
		return nil, fmt.Errorf("recompiling rollup contract: %w", err)
	}

	sdkArtifact, err := goCompilerToSDKArtifact(gocompArtifact)
	if err != nil {
		return nil, fmt.Errorf("converting compiler artifact to SDK artifact: %w", err)
	}

	// Strip 0x prefix — bitcoind's getrawtransaction rejects it.
	genesisTxIDHex, genesisVout, err := genesisOutpointFromOpts(opts)
	if err != nil {
		return nil, fmt.Errorf("genesis outpoint: %w", err)
	}
	contract, err := runar.FromTxId(sdkArtifact, genesisTxIDHex, int(genesisVout), provider)
	if err != nil {
		return nil, fmt.Errorf("loading deployed contract: %w", err)
	}
	slog.Info("covenant contract bound", "txid", genesisTxIDHex, "vout", genesisVout)

	// 7. RunarBroadcastClient. The RPC provider satisfies both
	// runar.Provider and covenant.ConfirmationSource, so a single
	// instance drives both broadcast and confirmation tracking.
	broadcastProofMode := covenant.ProofModeFRI
	if rollupInputs.Verification == covenant.VerifyDevKey {
		broadcastProofMode = covenant.ProofModeDevKey
	}
	broadcastClient, err := covenant.NewRunarBroadcastClient(covenant.RunarBroadcastClientOpts{
		Contract:      contract,
		Provider:      provider,
		Signer:        signer,
		Confirmations: provider,
		// BlockHeaders is the legacy-node fallback (see
		// pkg/covenant/tx_status_reader.go). Same provider satisfies
		// it via the GetBlockHeader method we added in bsv_provider.go.
		BlockHeaders: provider,
		ChainID:      opts.ChainID,
		Mode:         broadcastProofMode,
	})
	if err != nil {
		return nil, fmt.Errorf("broadcast client: %w", err)
	}
	opts.CovenantMgr.SetBroadcastClient(broadcastClient)
	slog.Info("broadcast client attached")

	// 8. Confirmation watcher.
	opts.OverlayNode.StartConfirmationWatcher(broadcastClient, 10*time.Second)
	slog.Info("confirmation watcher started", "poll_interval", "10s")

	// 9. Devnet fee-wallet bootstrap. Regtest only; a no-op on
	// testnet/mainnet. The BootstrapFeeWallet call is idempotent — if
	// the wallet already holds MinBalanceSats, it returns immediately.
	if opts.NodeCfg.BSV.Network == "regtest" {
		ingested, err := BootstrapFeeWallet(ctx, BootstrapOpts{
			Provider:  provider,
			FeeWallet: feeWallet,
			Address:   feeAddr,
			Network:   opts.NodeCfg.BSV.Network,
		})
		if err != nil {
			slog.Warn("fee-wallet bootstrap failed; node will operate with whatever balance it has",
				"error", err, "balance_sats", feeWallet.Balance())
		} else if ingested > 0 {
			slog.Info("fee-wallet bootstrap completed",
				"ingested_utxos", ingested, "balance_sats", feeWallet.Balance())
		} else {
			slog.Info("fee-wallet already funded; skipping bootstrap",
				"balance_sats", feeWallet.Balance())
		}
	}

	// 10. Fee-wallet UTXO reconciler. Periodically re-syncs the wallet
	// with listunspent so spent UTXOs are purged and change outputs
	// from covenant-advance broadcasts are ingested. Without this the
	// FeeWallet eventually hands out stale inputs and broadcasts fail
	// at mempool with "missing or spent input".
	opts.OverlayNode.StartFeeWalletReconciler(provider, feeAddr, 30*time.Second)
	slog.Info("fee-wallet reconciler started", "poll_interval", "30s")

	return &bsvBroadcastResult{
		FeeSigner:  localSigner,
		FeeAddress: feeAddr,
		Provider:   provider,
		FeeWallet:  feeWallet,
		ARC:        arcClient,
	}, nil
}

// rollupSourceInputs is the minimal set of fields both the legacy
// shard.json and the Phase 8 derived-from-txid boot paths produce.
// selectRollupSourceForBoot collapses either path onto this struct
// so the switch on verification mode only lives in one place.
type rollupSourceInputs struct {
	Verification covenant.VerificationMode
	ChainID      int64
	Governance   covenant.GovernanceConfig
	SP1VK        []byte
}

// selectRollupSourceForBoot picks the contract source file and
// constructor args map matching the boot's verification mode.
//
// Exactly one of opts.ShardCfg / opts.DerivedBoot must be non-nil;
// this helper dispatches between them.
func selectRollupSourceForBoot(opts bsvWireOpts) (string, map[string]interface{}, error) {
	inputs, err := rollupSourceInputsFromOpts(opts)
	if err != nil {
		return "", nil, err
	}
	return selectRollupSourceInputs(inputs)
}

// rollupSourceInputsFromOpts collapses the bsvWireOpts into the
// inputs struct. Returns an error when neither ShardCfg nor
// DerivedBoot is set (caller programming error).
func rollupSourceInputsFromOpts(opts bsvWireOpts) (rollupSourceInputs, error) {
	if opts.DerivedBoot != nil {
		return rollupSourceInputs{
			Verification: opts.DerivedBoot.Verification,
			ChainID:      opts.ChainID,
			Governance:   opts.DerivedBoot.Governance,
			SP1VK:        padOrZero(opts.DerivedBoot.SP1VerifyingKey, 32),
		}, nil
	}
	if opts.ShardCfg != nil {
		gov, err := opts.ShardCfg.GovernanceConfig()
		if err != nil {
			return rollupSourceInputs{}, fmt.Errorf("governance config: %w", err)
		}
		verif, err := parseVerificationModeString(opts.ShardCfg.VerificationMode)
		if err != nil {
			return rollupSourceInputs{}, err
		}
		vk := []byte{}
		if opts.ShardCfg.SP1VerifyingKey != "" {
			if decoded, decErr := hex.DecodeString(opts.ShardCfg.SP1VerifyingKey); decErr == nil {
				vk = decoded
			}
		}
		return rollupSourceInputs{
			Verification: verif,
			ChainID:      opts.ChainID,
			Governance:   gov,
			SP1VK:        padOrZero(vk, 32),
		}, nil
	}
	return rollupSourceInputs{}, fmt.Errorf("bsvWireOpts: exactly one of ShardCfg / DerivedBoot must be set")
}

// selectRollupSourceInputs is the pure, mode-dispatching core.
func selectRollupSourceInputs(in rollupSourceInputs) (string, map[string]interface{}, error) {
	switch in.Verification {
	case covenant.VerifyFRI:
		path := findContractPath("rollup_fri.runar.go")
		args, err := covenant.BuildFRIConstructorArgsExported(in.SP1VK, uint64(in.ChainID), in.Governance)
		if err != nil {
			return "", nil, err
		}
		return path, args, nil
	case covenant.VerifyDevKey:
		path := findContractPath("rollup_devkey.runar.go")
		args, err := covenant.BuildFRIConstructorArgsExported(in.SP1VK, uint64(in.ChainID), in.Governance)
		if err != nil {
			return "", nil, err
		}
		return path, args, nil
	case covenant.VerifyGroth16WA:
		// Groth16-WA requires a per-batch SP1 Groth16 proof whose
		// publicInput[1] equals reducePublicValuesToScalarWA(publicValues)
		// for the on-chain pairing check to accept the advance. The
		// mock prover (pkg/prover/host.go::proveMock) reuses the fixed
		// Gate 0b fixture proof for every batch, so its publicInput[1]
		// is locked to the fixture's value and cannot match a per-batch
		// publicValues blob carrying live state roots + batch hash.
		// Wiring Mode 3 for the devnet therefore also requires either
		// a real SP1 prover (GPU, minutes per proof) or a prover that
		// regenerates the Groth16 witness per batch. Until one exists,
		// the only mainnet-eligible path through this code is
		// unreachable with the mock prover.
		return "", nil, fmt.Errorf("groth16-wa broadcast requires a real SP1 prover to regenerate proofs per batch " +
			"(mock prover reuses a fixed Gate 0b fixture that cannot satisfy the on-chain publicInput[1] == " +
			"reducePublicValuesToScalarWA(publicValues) binding); use --verification=fri for devnet execute/prove")
	case covenant.VerifyGroth16:
		return "", nil, fmt.Errorf("generic groth16 broadcast not yet wired")
	default:
		return "", nil, fmt.Errorf("unsupported verification mode for broadcast: %s", in.Verification.String())
	}
}

// padOrZero returns b if it has at least `size` bytes, otherwise a
// zero-filled slice of length `size`. Used for SP1 VK placeholders
// on modes that don't enforce the VK on-chain (FRI / DevKey).
func padOrZero(b []byte, size int) []byte {
	if len(b) >= size {
		return b
	}
	return make([]byte, size)
}

// genesisOutpointFromOpts returns the genesis covenant txid (hex,
// no 0x prefix) and vout from whichever of ShardCfg / DerivedBoot
// is set.
func genesisOutpointFromOpts(opts bsvWireOpts) (string, uint32, error) {
	if opts.DerivedBoot != nil {
		// DerivedBoot.GenesisCovenantTxID stores chainhash little-endian
		// bytes; BSVString() reverses to the big-endian display form
		// that BSV RPC (runar.FromTxId / getrawtransaction) expects.
		return opts.DerivedBoot.GenesisCovenantTxID.BSVString(), opts.DerivedBoot.GenesisCovenantVout, nil
	}
	if opts.ShardCfg != nil {
		return strings.TrimPrefix(opts.ShardCfg.GenesisCovenantTxID, "0x"), opts.ShardCfg.GenesisCovenantVout, nil
	}
	return "", 0, fmt.Errorf("bsvWireOpts: exactly one of ShardCfg / DerivedBoot must be set")
}

// findContractPath locates a Rúnar contract source file by name. Matches
// the logic in pkg/covenant/compile.go:findContractSourceNamed: first try
// a path relative to this Go source file (dev workflow), then fall back
// to pkg/covenant/contracts/<name> relative to pwd (Docker: WORKDIR=/app,
// contracts copied to /app/pkg/covenant/contracts/).
func findContractPath(name string) string {
	_, thisFile, _, ok := runtime.Caller(0)
	if ok {
		// cmd/bsvm/bsv_wiring.go → ../../pkg/covenant/contracts/<name>
		dir := filepath.Dir(thisFile)
		candidate := filepath.Join(dir, "..", "..", "pkg", "covenant", "contracts", name)
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}
	return filepath.Join("pkg", "covenant", "contracts", name)
}

// goCompilerToSDKArtifact converts a *gocompiler.Artifact into a
// *runar.RunarArtifact via JSON round-trip. Both structs share the
// same JSON tags (the SDK artifact schema is the canonical shape; the
// compiler package mirrors it), so serializing and parsing bridges
// the two types cleanly without manual field-copying.
//
// The round-trip intentionally drops the compiler-only IR-debug and
// source-map fields which have no SDK counterpart.
func goCompilerToSDKArtifact(a *gocompiler.Artifact) (*runar.RunarArtifact, error) {
	j, err := json.Marshal(a)
	if err != nil {
		return nil, fmt.Errorf("marshal compiler artifact: %w", err)
	}
	var sdk runar.RunarArtifact
	if err := json.Unmarshal(j, &sdk); err != nil {
		return nil, fmt.Errorf("unmarshal as SDK artifact: %w", err)
	}
	return &sdk, nil
}
