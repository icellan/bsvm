// Spec-16 BSV covenant-broadcast wiring for the bsvm binary. The helper
// in this file assembles the full advance-broadcast stack (fee wallet,
// JSON-RPC provider, Rúnar signer, deployed-contract binding,
// RunarBroadcastClient) and attaches it to the overlay's covenant
// manager so ProcessBatch actually submits advance transactions to BSV
// when the shard runs in prove-mode execute or prove.
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

	"github.com/icellan/bsvm/internal/db"
	"github.com/icellan/bsvm/pkg/bsvclient"
	"github.com/icellan/bsvm/pkg/covenant"
	"github.com/icellan/bsvm/pkg/overlay"
	"github.com/icellan/bsvm/pkg/shard"

	gocompiler "github.com/icellan/runar/compilers/go/compiler"
	runar "github.com/icellan/runar/packages/runar-go"
)

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
	Provider    *bsvclient.RPCProvider
}

// wireBSVBroadcast builds the full covenant-advance broadcast stack —
// fee wallet, BSV JSON-RPC provider, Rúnar signer, deployed-contract
// binding, RunarBroadcastClient — and attaches it to the overlay's
// covenant manager. It also starts the confirmation watcher goroutine.
func wireBSVBroadcast(ctx context.Context, opts bsvWireOpts) error {
	// 1. Persist/load the fee-wallet key.
	feeKey, err := LoadOrCreateFeeWalletKey(opts.DataDir)
	if err != nil {
		return fmt.Errorf("fee-wallet key: %w", err)
	}
	feeAddr, err := FeeWalletBSVAddress(feeKey, opts.NodeCfg.BSV.Network)
	if err != nil {
		return fmt.Errorf("fee-wallet address: %w", err)
	}
	slog.Info("fee-wallet key loaded", "address", feeAddr)

	// 2. FeeWallet backed by the shared LevelDB.
	feeWallet := overlay.NewFeeWallet(opts.DB)
	if err := feeWallet.LoadFromDB(); err != nil {
		return fmt.Errorf("fee-wallet load from DB: %w", err)
	}
	slog.Info("fee-wallet initialized", "balance_sats", feeWallet.Balance())

	// 3. Attach to overlay.
	opts.OverlayNode.SetFeeWallet(feeWallet)

	// 4. BSV JSON-RPC provider. Re-use the caller's provider if one
	// was supplied (Phase 8 path), otherwise build a fresh one.
	bsvNet := opts.NodeCfg.BSV.Network
	if bsvNet == "" {
		bsvNet = "regtest"
	}
	provider := opts.Provider
	if provider == nil {
		p, provErr := bsvclient.NewRPCProvider(opts.NodeCfg.BSV.NodeURL, bsvNet)
		if provErr != nil {
			return fmt.Errorf("BSV RPC provider: %w", provErr)
		}
		provider = p
	}
	slog.Info("BSV RPC provider ready", "url", opts.NodeCfg.BSV.NodeURL, "network", bsvNet)

	// 5. Rúnar signer from the fee-wallet key. Wrap LocalSigner in
	// ExternalSigner so PrepareCall's GetUtxos(address) queries the
	// REGTEST address we imported — LocalSigner.GetAddress() hardcodes
	// mainnet, which would cause listunspent to reject the address.
	feeKeyHex := hex.EncodeToString(feeKey.Serialize())
	localSigner, err := runar.NewLocalSigner(feeKeyHex)
	if err != nil {
		return fmt.Errorf("runar signer: %w", err)
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
		return fmt.Errorf("selecting rollup source: %w", err)
	}

	gocompArtifact, err := gocompiler.CompileFromSource(contractSrc, gocompiler.CompileOptions{
		ConstructorArgs: constructorArgs,
	})
	if err != nil {
		return fmt.Errorf("recompiling rollup contract: %w", err)
	}

	sdkArtifact, err := goCompilerToSDKArtifact(gocompArtifact)
	if err != nil {
		return fmt.Errorf("converting compiler artifact to SDK artifact: %w", err)
	}

	// Strip 0x prefix — bitcoind's getrawtransaction rejects it.
	genesisTxIDHex, genesisVout, err := genesisOutpointFromOpts(opts)
	if err != nil {
		return fmt.Errorf("genesis outpoint: %w", err)
	}
	contract, err := runar.FromTxId(sdkArtifact, genesisTxIDHex, int(genesisVout), provider)
	if err != nil {
		return fmt.Errorf("loading deployed contract: %w", err)
	}
	slog.Info("covenant contract bound", "txid", genesisTxIDHex, "vout", genesisVout)

	// 7. RunarBroadcastClient. The RPC provider satisfies both
	// runar.Provider and covenant.ConfirmationSource, so a single
	// instance drives both broadcast and confirmation tracking.
	broadcastClient, err := covenant.NewRunarBroadcastClient(covenant.RunarBroadcastClientOpts{
		Contract:      contract,
		Provider:      provider,
		Signer:        signer,
		Confirmations: provider,
		ChainID:       opts.ChainID,
		Mode:          covenant.ProofModeFRI,
	})
	if err != nil {
		return fmt.Errorf("broadcast client: %w", err)
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

	return nil
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
		return "", nil, fmt.Errorf("devkey covenant has no broadcast path in Phase 3c; use execute (FRI) or prove (Groth16-WA)")
	case covenant.VerifyGroth16WA:
		return "", nil, fmt.Errorf("groth16-wa broadcast not yet wired in Phase 3c")
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
		txidHex := strings.TrimPrefix(opts.DerivedBoot.GenesisCovenantTxID.Hex(), "0x")
		return txidHex, opts.DerivedBoot.GenesisCovenantVout, nil
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
