// Daemon-side bridge.Withdrawer wiring. Constructs the production
// WithdrawalScanner (over the daemon's *block.ChainDB), the BSV
// broadcaster + signer adapters, and starts
// ProcessFinalizedWithdrawalsLoop in a goroutine that lives until ctx
// is cancelled.
//
// Backwards compat: if any required dependency is missing the helper
// logs a clear WARN and returns a no-op start function so the daemon
// still boots. The two real "you must wire this for production"
// dependencies are:
//
//   - bridgeMonitor    — the L1 covenant must be deployed (see
//     [bridge].bridge_script_hex). Without it there's nothing to claim
//     against.
//   - feeKey           — the fee-wallet PrivateKey is needed to sign
//     bridge-input claims. The key is loaded inside wireBSVBroadcast,
//     so this helper is only meaningful when the broadcast stack is
//     also wired (prove-mode execute / prove with a BSV RPC endpoint).
//
// The CovenantAdvanceFinder seam is currently a stub that returns
// ErrAdvanceLookupUnimplemented for every request — until the daemon
// persists AnchorRecords linking L2 blocks to BSV advance txs (a
// separate piece of work, tracked in spec 07 Phase 3 follow-ups), the
// Withdrawer cannot construct a claim. Wiring it now ensures the loop
// starts cleanly and surfaces a clear "deferred" log so operators
// understand why no claims are firing yet.
package main

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/bsv-blockchain/go-sdk/transaction"

	"github.com/icellan/bsvm/pkg/block"
	"github.com/icellan/bsvm/pkg/bridge"
	"github.com/icellan/bsvm/pkg/overlay"
	"github.com/icellan/bsvm/pkg/types"

	runar "github.com/icellan/runar/packages/runar-go"
)

// withdrawalWireOpts gathers the dependencies WireWithdrawer needs.
// All fields are optional — the helper logs WARN and skips the loop
// when any required piece is missing. See package doc for which fields
// are "required".
type withdrawalWireOpts struct {
	// OverlayNode is the local L2 node. Used as the FinalizedTipProvider
	// (the scanner only emits withdrawals whose batch is past BSV
	// finality).
	OverlayNode *overlay.OverlayNode
	// ChainDB is the L2 chain database the scanner walks.
	ChainDB *block.ChainDB
	// BridgeMonitor exposes the L1 bridge covenant configuration. May
	// be nil (operator hasn't deployed an L1 bridge for this shard yet)
	// — wiring is skipped with a WARN.
	BridgeMonitor *bridge.BridgeMonitor
	// BridgeScript is the L1 bridge covenant locking script bytes.
	// Required when BridgeMonitor is set; the monitor stores the same
	// bytes internally but the field is unexported so we thread it
	// through here from the BuildBridgeMonitor call site.
	BridgeScript []byte
	// Provider is the BSV-node JSON-RPC client used to broadcast claim
	// transactions. May be nil on followers / mock-mode setups.
	Provider BSVProviderClient
	// FeeAddress is the canonical P2PKH address of the fee-wallet key.
	// Used to log the signer identity.
	FeeAddress string
	// FeeSigner is a runar.LocalSigner over the fee-wallet PrivateKey.
	// May be nil — the loop falls back to broadcasting unsigned claims
	// (only useful for hermetic tests; production claims will be
	// rejected by the bridge covenant if unsigned).
	FeeSigner *runar.LocalSigner
	// FeeWallet exposes the prover's BSV UTXO float. When set, the
	// Withdrawer takes the spec-07 claim-tx shape — Input 1 funds the
	// miner fee from a wallet UTXO (signed by the same FeeSigner key),
	// Output 2 returns claimer change. nil leaves the legacy
	// single-input path active (fee absorbed from the bridge change).
	FeeWallet *overlay.FeeWallet
	// PollInterval is how often ProcessFinalizedWithdrawals runs.
	// Defaults to 30s when zero.
	PollInterval time.Duration
	// ClaimFeeSatPerByte overrides the WithdrawalConfig default
	// (1 sat/byte). Zero leaves the default in place. Operators set
	// this from [bridge].claim_fee_sat_per_byte.
	ClaimFeeSatPerByte int64
}

// startWithdrawerFunc is returned by WireWithdrawer. The caller invokes
// it once with a long-lived context to start the background loop;
// cancelling the context stops the loop. Returns nil when wiring was
// skipped due to a missing dependency — calling it then is a safe
// no-op so callers don't need a nil check.
type startWithdrawerFunc func(ctx context.Context)

// WireWithdrawer constructs the production bridge.Withdrawer wired to
// the daemon's ChainDB / OverlayNode / BSV provider, and returns a
// start function that launches ProcessFinalizedWithdrawalsLoop in a
// goroutine. The returned function is always non-nil and safe to call
// even when wiring was skipped.
//
// Wiring decisions logged at INFO/WARN:
//   - INFO "withdrawal processor started" when the loop begins.
//   - WARN "withdrawal processor disabled: <reason>" when a required
//     dependency is missing.
//
// Per-claim lifecycle events ("claim broadcast: txid=…", "claim
// confirmed: txid=…") are logged inside the Withdrawer itself.
func WireWithdrawer(opts withdrawalWireOpts) startWithdrawerFunc {
	noop := func(context.Context) {}

	// Hard prerequisites: without these the loop literally cannot run.
	if opts.OverlayNode == nil {
		slog.Warn("withdrawal processor disabled: overlay node not constructed")
		return noop
	}
	if opts.ChainDB == nil {
		slog.Warn("withdrawal processor disabled: chain DB not constructed")
		return noop
	}
	if opts.BridgeMonitor == nil {
		slog.Warn("withdrawal processor disabled: bridge monitor not wired ([bridge].bridge_script_hex empty)")
		return noop
	}
	if opts.Provider == nil {
		slog.Warn("withdrawal processor disabled: no BSV RPC provider (mock mode or follower role)")
		return noop
	}
	if opts.FeeSigner == nil {
		slog.Warn("withdrawal processor disabled: no fee-wallet signer (BSV broadcast wiring not active)")
		return noop
	}

	chainAdapter := &chainDBReaderAdapter{db: opts.ChainDB}
	scanner := bridge.NewChainDBWithdrawalScanner(chainAdapter, opts.OverlayNode)

	if len(opts.BridgeScript) == 0 {
		slog.Warn("withdrawal processor disabled: bridge covenant script not configured")
		return noop
	}
	// Live bridge UTXO snapshot is owned by the BridgeMonitor (set at
	// daemon boot from operator config + advance/deposit deltas applied
	// in-flight). The Withdrawer mutates the snapshot after each claim
	// (UpdateAfterWithdrawal); for now we hand it the monitor's pointer
	// directly so post-claim mutations are observable via
	// CurrentBridgeUTXO. When the monitor has no snapshot yet (operator
	// hasn't seeded the L1 bridge state) we fall through to a zero-
	// balance stub so the loop runs idle until the snapshot is set.
	bridgeUTXO := opts.BridgeMonitor.CurrentBridgeUTXO()
	if bridgeUTXO == nil {
		slog.Info("withdrawal processor: no live bridge UTXO from monitor, starting with zero-balance stub",
			"hint", "call BridgeMonitor.SetBridgeUTXO from boot wiring once L1 bridge UTXO is known")
		bridgeUTXO = &bridge.BridgeUTXO{
			TxID:             types.Hash{},
			Vout:             0,
			Balance:          0,
			LastClaimedNonce: 0,
			Script:           append([]byte(nil), opts.BridgeScript...),
		}
	} else {
		// Ensure the script field is populated even if the monitor's
		// snapshot was seeded without one (the operator might have only
		// supplied (txid, vout, balance) at boot).
		if len(bridgeUTXO.Script) == 0 {
			bridgeUTXO.Script = append([]byte(nil), opts.BridgeScript...)
		}
	}

	finder := bridge.NewChainDBAdvanceFinder(
		chainAdapter,
		&bsvTxFetcherAdapter{provider: opts.Provider},
	)
	broadcaster := &arcBroadcaster{provider: opts.Provider}
	signer := &localSignerAdapter{
		signer:  opts.FeeSigner,
		address: opts.FeeAddress,
	}

	cfg := bridge.DefaultWithdrawalConfig()
	if opts.ClaimFeeSatPerByte > 0 {
		cfg.ClaimFeeSatPerByte = opts.ClaimFeeSatPerByte
	}
	w := bridge.NewWithdrawer(broadcaster, bridgeUTXO, scanner, finder, cfg).
		WithSigner(signer).
		WithBridgeUTXOTracker(opts.BridgeMonitor, opts.BridgeMonitor)

	// Spec 07 fee-funding UTXO. Production wiring uses the same
	// FeeWallet that funds covenant advances — its PrivateKey is the
	// FeeSigner above, so a single signer covers both inputs of the
	// claim tx (bridge unlock + P2PKH unlock for the fee UTXO). When
	// the FeeWallet is not wired the loop falls back to the legacy
	// single-input path so existing deployments keep working.
	if opts.FeeWallet != nil {
		w = w.WithFeeUTXOProvider(&feeWalletUTXOProvider{wallet: opts.FeeWallet})
	} else {
		slog.Info("withdrawal processor: fee wallet not wired, using legacy single-input claim tx (fee absorbed from bridge change)")
	}

	pollInterval := opts.PollInterval
	if pollInterval <= 0 {
		pollInterval = 30 * time.Second
	}

	return func(ctx context.Context) {
		slog.Info("withdrawal processor started",
			"poll_interval", pollInterval,
			"bridge_balance_sats", bridgeUTXO.Balance,
			"last_claimed_nonce", bridgeUTXO.LastClaimedNonce,
		)
		go func() {
			w.ProcessFinalizedWithdrawalsLoop(ctx, pollInterval)
			slog.Info("withdrawal processor stopped")
		}()
	}
}

// chainDBReaderAdapter adapts *block.ChainDB to bridge.ChainReader.
// pkg/bridge cannot import pkg/block (the dependency runs the other
// way), so the adapter lives here in cmd/bsvm where both sides are in
// scope.
type chainDBReaderAdapter struct {
	db *block.ChainDB
}

// HeaderByNumber returns the canonical L2 header at the given block
// number, projected onto the bridge.ChainHeader subset.
func (a *chainDBReaderAdapter) HeaderByNumber(number uint64) *bridge.ChainHeader {
	h := a.db.ReadHeaderByNumber(number)
	if h == nil {
		return nil
	}
	return &bridge.ChainHeader{Number: number, Hash: h.Hash()}
}

// ReceiptsByBlock returns the stored receipts for the given block.
func (a *chainDBReaderAdapter) ReceiptsByBlock(hash types.Hash, number uint64) []*types.Receipt {
	return a.db.ReadReceipts(hash, number)
}

// ReadAnchor implements bridge.AnchorReader. Returns hasRecord=false
// when no AnchorRecord has been written yet for blockNum so the
// finder can surface bridge.ErrAdvanceNotYetAnchored to the Withdrawer.
func (a *chainDBReaderAdapter) ReadAnchor(blockNum uint64) (types.Hash, bool, bool) {
	rec := a.db.ReadAnchorRecord(blockNum)
	if rec == nil {
		return types.Hash{}, false, false
	}
	return rec.BSVTxID, rec.Confirmed, true
}

// arcBroadcaster wraps a BSVProviderClient as a bridge.BSVBroadcaster.
// Production deployments using ARC supply a provider that round-trips
// sendrawtransaction through ARC; for regtest deployments the daemon's
// JSON-RPC provider is the broadcaster.
type arcBroadcaster struct {
	provider BSVProviderClient
}

// Broadcast submits the raw tx via the provider's Broadcast method.
// The provider expects a *transaction.Transaction; we parse the raw
// bytes through the BSV SDK so the on-the-wire shape stays canonical.
func (a *arcBroadcaster) Broadcast(rawTx []byte) (types.Hash, error) {
	tx, err := transaction.NewTransactionFromBytes(rawTx)
	if err != nil {
		return types.Hash{}, fmt.Errorf("parse raw withdrawal claim tx: %w", err)
	}
	txidHex, err := a.provider.Broadcast(tx)
	if err != nil {
		return types.Hash{}, fmt.Errorf("withdrawal claim broadcast: %w", err)
	}
	out := types.HexToHash("0x" + txidHex)
	slog.Info("withdrawal claim broadcast", "txid", out.BSVString())
	return out, nil
}

// localSignerAdapter wraps a runar.LocalSigner so it satisfies
// bridge.BSVSigner. The signing protocol in pkg/bridge mirrors
// pkg/covenant.PrivateKey: serialise the unsigned skeleton, sign one
// input at a time with knowledge of the prevout's locking script and
// satoshi amount, splice the returned unlock hex back in.
type localSignerAdapter struct {
	signer  *runar.LocalSigner
	address string
}

// SignInput delegates to runar.LocalSigner.Sign. sigHashType=nil lets
// the runar signer pick its default (SIGHASH_ALL|FORKID) which matches
// what BSV nodes expect for spendable claim txs.
func (a *localSignerAdapter) SignInput(rawTxHex string, inputIndex int, prevScriptHex string, prevSatoshis uint64) (string, error) {
	if a.signer == nil {
		return "", errors.New("nil signer")
	}
	// runar.LocalSigner.Sign takes satoshis as int64; widening is safe
	// because the bridge covenant balance fits comfortably in int64
	// (BSV's 21M coin cap is ~2.1e15 satoshis << math.MaxInt64).
	return a.signer.Sign(rawTxHex, inputIndex, prevScriptHex, int64(prevSatoshis), nil)
}

// feeWalletUTXOProvider adapts *overlay.FeeWallet to
// bridge.FeeUTXOProvider so the Withdrawer can fund per-claim miner
// fees from the prover's BSV UTXO float (spec 07 Input 1 / Output 2).
//
// The adapter selects the smallest single UTXO that covers
// minSatoshis using the wallet's largest-first SelectUTXOs API.
// For now we accept multi-UTXO selection only when no single UTXO
// suffices — the claim-tx builder currently handles a single fee
// input, so we surface a clear error if the wallet's best candidate
// is undersized. A multi-input fee UTXO path is a follow-up
// (TODO(NN-followup)).
type feeWalletUTXOProvider struct {
	wallet *overlay.FeeWallet
}

// ProvideClaimFeeUTXO returns the smallest single FeeWallet UTXO
// covering minSatoshis. Errors out when the wallet is empty or every
// available UTXO is undersized — both surfaces are loud-but-recoverable
// because the Withdrawer logs + defers to the next pass on error.
func (p *feeWalletUTXOProvider) ProvideClaimFeeUTXO(minSatoshis uint64) (*bridge.FeeUTXO, error) {
	if p == nil || p.wallet == nil {
		return nil, errors.New("fee wallet: not configured")
	}
	selected, _, err := p.wallet.SelectUTXOs(minSatoshis)
	if err != nil {
		return nil, fmt.Errorf("fee wallet: %w", err)
	}
	if len(selected) == 0 {
		return nil, errors.New("fee wallet: empty selection")
	}
	if len(selected) > 1 {
		// Multi-input fee funding requires the claim-tx builder to
		// accept a slice of fee UTXOs. Until that lands the
		// largest-first selection still gives us a working path
		// when at least ONE wallet UTXO covers the budget — log
		// loudly so operators see we're picking only the first.
		slog.Warn("fee wallet: multi-utxo selection not yet supported in claim tx, using largest only",
			"selected_count", len(selected),
			"budget_sats", minSatoshis,
			"first_utxo_sats", selected[0].Satoshis,
		)
	}
	u := selected[0]
	if u.Satoshis < minSatoshis {
		return nil, fmt.Errorf("fee wallet: largest utxo %d < min %d (multi-input fee funding is TODO(NN-followup))",
			u.Satoshis, minSatoshis)
	}
	return &bridge.FeeUTXO{
		TxID:          u.TxID,
		Vout:          u.Vout,
		Satoshis:      u.Satoshis,
		LockingScript: append([]byte(nil), u.ScriptPubKey...),
	}, nil
}

// bsvTxFetcherAdapter satisfies bridge.BSVTxFetcher by translating the
// runar.TransactionData returned from the BSV-node provider into the
// minimal *bridge.BSVTransaction shape the claim builder consumes
// (Outputs only). The provider is the same MultiRPCProvider that
// covenant advances broadcast through, so any failover policy applied
// there is inherited transparently.
type bsvTxFetcherAdapter struct {
	provider BSVProviderClient
}

// FetchBSVTx looks up txid via runar.Provider.GetTransaction and maps
// each TxOutput onto bridge.BSVOutput. The provider returns hex-encoded
// scripts (matching the verbose getrawtransaction shape); we decode to
// raw bytes here so the bridge package never has to do it.
func (a *bsvTxFetcherAdapter) FetchBSVTx(txid types.Hash) (*bridge.BSVTransaction, error) {
	if a.provider == nil {
		return nil, errors.New("bsv provider not configured")
	}
	td, err := a.provider.GetTransaction(txid.BSVString())
	if err != nil {
		return nil, fmt.Errorf("provider.GetTransaction: %w", err)
	}
	if td == nil {
		return nil, errors.New("provider returned nil tx")
	}
	outs := make([]bridge.BSVOutput, 0, len(td.Outputs))
	for i, o := range td.Outputs {
		script, decErr := hex.DecodeString(o.Script)
		if decErr != nil {
			return nil, fmt.Errorf("decode output %d script: %w", i, decErr)
		}
		val := uint64(0)
		if o.Satoshis > 0 {
			val = uint64(o.Satoshis)
		}
		outs = append(outs, bridge.BSVOutput{Script: script, Value: val})
	}
	return &bridge.BSVTransaction{
		TxID:    txid,
		Outputs: outs,
	}, nil
}
