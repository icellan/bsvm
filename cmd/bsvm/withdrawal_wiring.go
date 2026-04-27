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
	// PollInterval is how often ProcessFinalizedWithdrawals runs.
	// Defaults to 30s when zero.
	PollInterval time.Duration
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
	// Placeholder UTXO. The real bridge-UTXO tracker (monitor-driven)
	// is a separate piece of work; wiring the Withdrawer with this
	// stub keeps the loop running so production deployments observe
	// "no claimable balance" rather than "no withdrawer at all".
	bridgeUTXO := &bridge.BridgeUTXO{
		TxID:             types.Hash{},
		Vout:             0,
		Balance:          0,
		LastClaimedNonce: 0,
		Script:           append([]byte(nil), opts.BridgeScript...),
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
	w := bridge.NewWithdrawer(broadcaster, bridgeUTXO, scanner, finder, cfg).
		WithSigner(signer)

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
