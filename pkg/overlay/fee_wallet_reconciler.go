// Phase 5: fee-wallet UTXO reconciler. The production broadcast path
// spends fee-wallet UTXOs inside covenant-advance transactions but has
// no in-process hook to tell the wallet "this UTXO is gone, the change
// output now lives at vout N". Without reconciliation the FeeWallet's
// in-memory (and DB-persisted) set drifts from the BSV node's
// listunspent view after every broadcast and subsequent advances fail
// at mempool with "missing or spent input".
//
// This file wires a background goroutine that periodically calls the
// node's listunspent for the fee-wallet address and performs a
// three-way merge:
//
//   - UTXOs in the wallet but NOT in listunspent → spent → RemoveUTXO
//   - UTXOs in listunspent but NOT in the wallet → new → AddUTXO
//   - UTXOs in both → no-op
//
// The merge runs under the FeeWallet's own mutex (each Add/Remove
// takes the lock), not a single wide critical section — the broadcast
// path can still select UTXOs between individual wallet mutations
// performed by the reconciler. See the race analysis in the report
// attached to the phase-5 commit.
package overlay

import (
	"context"
	"encoding/hex"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/icellan/bsvm/pkg/types"

	runar "github.com/icellan/runar/packages/runar-go"
)

// defaultReconcileInterval is the default polling period for the
// reconciliation loop. 30s is short enough to keep stale UTXOs out of
// the selection pool and long enough that it doesn't hammer the node
// between advances, which themselves take much longer than the poll
// interval on BSV's 10-minute block cadence.
const defaultReconcileInterval = 30 * time.Second

// UtxoSource is the subset of runar.Provider that the reconciler needs.
// Keeping this narrow decouples the reconciler from the full
// runar.Provider surface and from pkg/bsvclient, which also lets tests
// plug in a stub without pulling in the JSON-RPC transport.
type UtxoSource interface {
	GetUtxos(address string) ([]runar.UTXO, error)
}

// FeeWalletReconciler periodically polls a BSV node's listunspent for
// the fee-wallet address and reconciles the result against the
// FeeWallet's DB-backed set: new UTXOs are added, spent ones are
// removed. It runs in its own goroutine with a configurable poll
// interval (default 30s) once Start has been called.
//
// Lifecycle model matches ConfirmationWatcher: Start is idempotent,
// Stop is idempotent and blocks until the goroutine has returned.
type FeeWalletReconciler struct {
	feeWallet *FeeWallet
	source    UtxoSource
	address   string
	interval  time.Duration

	mu      sync.Mutex
	started bool
	stopCh  chan struct{}
	doneCh  chan struct{}
}

// NewFeeWalletReconciler returns a ready-to-start reconciler. Pass a
// non-positive interval to fall back to the 30s default.
func NewFeeWalletReconciler(fw *FeeWallet, src UtxoSource, addr string, interval time.Duration) *FeeWalletReconciler {
	if interval <= 0 {
		interval = defaultReconcileInterval
	}
	return &FeeWalletReconciler{
		feeWallet: fw,
		source:    src,
		address:   addr,
		interval:  interval,
		stopCh:    make(chan struct{}),
		doneCh:    make(chan struct{}),
	}
}

// Start launches the reconciliation goroutine. Calling Start twice
// without an intervening Stop is a no-op (idempotent). The passed
// context is used to cancel the goroutine in addition to Stop; either
// trigger returns the goroutine cleanly.
func (r *FeeWalletReconciler) Start(ctx context.Context) {
	r.mu.Lock()
	if r.started {
		r.mu.Unlock()
		return
	}
	r.started = true
	r.mu.Unlock()
	go r.run(ctx)
}

// Stop signals the goroutine to exit and blocks until it does, or
// until the passed context expires. Safe to call multiple times; the
// second and subsequent calls are non-blocking no-ops because the
// goroutine has already exited on the first call.
func (r *FeeWalletReconciler) Stop(ctx context.Context) {
	r.mu.Lock()
	if !r.started {
		r.mu.Unlock()
		return
	}
	select {
	case <-r.stopCh:
		// Already stopping — fall through and wait on doneCh.
	default:
		close(r.stopCh)
	}
	r.mu.Unlock()

	if ctx == nil {
		<-r.doneCh
		return
	}
	select {
	case <-r.doneCh:
	case <-ctx.Done():
	}
}

// run is the main polling loop. It performs one reconciliation pass
// per interval tick until stopCh closes or ctx cancels.
func (r *FeeWalletReconciler) run(ctx context.Context) {
	defer close(r.doneCh)
	timer := time.NewTimer(r.interval)
	defer timer.Stop()
	for {
		select {
		case <-r.stopCh:
			return
		case <-ctx.Done():
			return
		case <-timer.C:
			added, removed, err := r.ReconcileOnce()
			if err != nil {
				slog.Warn("fee-wallet reconcile failed",
					"address", r.address, "err", err)
			} else if added > 0 || removed > 0 {
				slog.Info("fee-wallet reconciled",
					"address", r.address,
					"added", added, "removed", removed,
					"balance_sats", r.feeWallet.Balance(),
					"utxo_count", r.feeWallet.UTXOCount())
			}
			timer.Reset(r.interval)
		}
	}
}

// ReconcileOnce runs a single reconciliation pass synchronously and
// returns the number of UTXOs added and removed. Intended for tests
// and one-shot maintenance operations. On source error the method
// returns (0, 0, err) without mutating the wallet.
func (r *FeeWalletReconciler) ReconcileOnce() (added, removed int, err error) {
	if r.feeWallet == nil {
		return 0, 0, fmt.Errorf("reconciler: fee wallet is nil")
	}
	if r.source == nil {
		return 0, 0, fmt.Errorf("reconciler: source is nil")
	}

	current, err := r.source.GetUtxos(r.address)
	if err != nil {
		return 0, 0, fmt.Errorf("reconciler: listunspent: %w", err)
	}

	// Build the network-seen set keyed by the same hex(txid):vout form
	// the wallet uses internally.
	networkSet := make(map[string]runar.UTXO, len(current))
	for _, u := range current {
		if u.OutputIndex < 0 {
			slog.Warn("reconciler: skipping utxo with negative output index",
				"txid", u.Txid, "vout", u.OutputIndex)
			continue
		}
		if u.Satoshis < 0 {
			slog.Warn("reconciler: skipping utxo with negative satoshis",
				"txid", u.Txid, "vout", u.OutputIndex, "satoshis", u.Satoshis)
			continue
		}
		// u.Txid is a BSV txid (big-endian display form from
		// listunspent). Reverse into chainhash little-endian bytes so
		// the key matches AddUTXO / RemoveUTXO callers who construct
		// TxIDs via the same BSVHashFromHex helper.
		key := utxoKey(types.BSVHashFromHex(u.Txid), uint32(u.OutputIndex))
		networkSet[key] = u
	}

	// Snapshot the wallet's current view. UTXOs returns a copy (see
	// fee_wallet.go) so we can safely hold references to the entries
	// while calling Remove/Add which reacquire the lock.
	walletSnapshot := r.feeWallet.UTXOs()
	walletSet := make(map[string]struct{}, len(walletSnapshot))
	for _, w := range walletSnapshot {
		walletSet[utxoKey(w.TxID, w.Vout)] = struct{}{}
	}

	// Remove wallet UTXOs not in network.
	for _, w := range walletSnapshot {
		key := utxoKey(w.TxID, w.Vout)
		if _, seen := networkSet[key]; seen {
			continue
		}
		if removeErr := r.feeWallet.RemoveUTXO(w.TxID, w.Vout); removeErr != nil {
			// RemoveUTXO only errors when the DB delete fails. Log and
			// continue — the next reconciliation pass will retry the
			// removal. Skipping lets the rest of the pass still ingest
			// new change outputs so broadcast can make progress.
			slog.Warn("reconciler: RemoveUTXO failed, will retry next tick",
				"txid", w.TxID.BSVString(), "vout", w.Vout, "err", removeErr)
			continue
		}
		removed++
	}

	// Add network UTXOs not already in wallet.
	for key, u := range networkSet {
		if _, have := walletSet[key]; have {
			continue
		}
		scriptBytes, decErr := hex.DecodeString(u.Script)
		if decErr != nil {
			slog.Warn("reconciler: skipping utxo with un-decodable script",
				"txid", u.Txid, "vout", u.OutputIndex, "err", decErr)
			continue
		}
		feeUTXO := &FeeUTXO{
			// u.Txid is a BSV txid (big-endian display form) — reverse
			// into chainhash little-endian bytes for in-memory storage.
			TxID:         types.BSVHashFromHex(u.Txid),
			Vout:         uint32(u.OutputIndex),
			Satoshis:     uint64(u.Satoshis),
			ScriptPubKey: scriptBytes,
			// listunspent always returns spendable outputs. Mark them
			// confirmed to match how devnet_funding.go ingests the
			// bootstrap UTXO — the Confirmed flag gates spending, not
			// broadcast.
			Confirmed: true,
		}
		if addErr := r.feeWallet.AddUTXO(feeUTXO); addErr != nil {
			slog.Warn("reconciler: AddUTXO failed, will retry next tick",
				"txid", u.Txid, "vout", u.OutputIndex, "err", addErr)
			continue
		}
		added++
	}

	return added, removed, nil
}
