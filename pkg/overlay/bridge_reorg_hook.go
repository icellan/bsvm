package overlay

import (
	"errors"
	"fmt"
	"log/slog"
	"sync/atomic"
)

// reorgPauseReason is the human-readable string passed to BatcherPause
// when HaltAndRollbackForReorg trips. RPC clients receive it as the
// suffix of the ErrBatcherPaused / "shard frozen" error so operators
// can distinguish a reorg halt from other freeze causes.
const reorgPauseReason = "bsv reorg, awaiting replay"

// reorgHaltsTotal counts the number of times HaltAndRollbackForReorg
// has tripped this process. Exposed via ReorgHaltsTotal() so the admin
// panel / metrics surface can read it without taking the node mutex.
var reorgHaltsTotal atomic.Uint64

// ReorgHaltsTotal returns the cumulative number of bridge-reorg halts
// observed since process start. Process-global rather than per-node so
// the counter survives ad-hoc OverlayNode reconstruction in tests; the
// admin panel always reads the latest count regardless of which node
// instance is current.
func ReorgHaltsTotal() uint64 {
	return reorgHaltsTotal.Load()
}

// HaltAndRollbackForReorg is the L2-side rollback hook fired by the
// BridgeMonitor when a chaintracks reorg event causes
// RetractDepositsAbove to drop deposits the monitor previously credited.
//
// The bsvCommonAncestorHeight argument is the BSV block height at the
// reorg's common ancestor — deposits strictly above that height have
// been dropped from the monitor's bookkeeping. The hook responds by:
//
//  1. Pausing the batcher with the structured "bsv reorg, awaiting
//     replay" reason. RPC clients receive a "shard frozen" error
//     (ErrBatcherPaused) until an operator clears it, mirroring the
//     governance-freeze and circuit-breaker UX.
//  2. Rolling back the L2 execution tip to the finalized tip — the
//     last L2 block known to be backed by 6+ BSV confirmations and
//     therefore beyond any reorg chaintracks could legitimately
//     report. This conservatively un-credits any wBSV mints from the
//     retracted deposits without requiring per-block deposit-horizon
//     bookkeeping.
//  3. Logging the halt + rollback for operator visibility and
//     incrementing the process-global ReorgHaltsTotal counter for the
//     admin panel.
//
// The hook returns nil on success. Errors propagated from
// OverlayNode.Rollback are surfaced so the caller (typically the
// BridgeMonitor's RetractDepositsAbove) can log them and continue —
// the monitor's own bookkeeping rollback has already happened by the
// time this runs, so a Rollback failure does not cause double work,
// only operator-noticeable divergence.
//
// Concurrency: the method takes the OverlayNode mutex internally via
// Rollback. Callers must NOT hold n.mu when calling it.
func (n *OverlayNode) HaltAndRollbackForReorg(bsvCommonAncestorHeight uint64) error {
	if n == nil {
		return errors.New("overlay: HaltAndRollbackForReorg called on nil node")
	}

	// Snapshot the current tips for logging before any state mutation.
	executionTip := n.ExecutionTip()
	finalizedTip := n.FinalizedTip()

	slog.Warn("bsv reorg detected, halting L2 advance and rolling back",
		"bsvCommonAncestor", bsvCommonAncestorHeight,
		"executionTip", executionTip,
		"finalizedTip", finalizedTip,
	)

	// Pause the batcher first — even if the rollback below errors out
	// we want the shard to stop accepting new transactions until
	// operator review. We call the underlying Batcher.Pause(reason)
	// directly so the structured "bsv reorg, awaiting replay" string
	// reaches RPC clients via ErrBatcherPaused; the reason-less
	// BatcherPause wrapper would lose the diagnostic.
	if n.batcher != nil {
		n.batcher.Pause(reorgPauseReason)
	}

	reorgHaltsTotal.Add(1)

	// Rollback to the finalized tip. If the execution tip is already
	// at or below the finalized tip, Rollback is a no-op and returns
	// nil — which is exactly what we want. Note: Rollback rejects
	// rolling forward, but rolling back to a higher block than current
	// is impossible by construction (finalizedTip <= executionTip is
	// invariant elsewhere; we double-check defensively).
	if finalizedTip > executionTip {
		// Defensive: if invariants ever flip we don't want a panic
		// inside Rollback. Cap the rollback target at the current tip.
		finalizedTip = executionTip
	}

	if err := n.Rollback(finalizedTip); err != nil {
		slog.Error("rollback to finalized tip failed during reorg halt",
			"target", finalizedTip,
			"error", err,
		)
		return fmt.Errorf("rollback to finalized tip %d: %w", finalizedTip, err)
	}

	slog.Info("L2 halted and rolled back for bsv reorg",
		"newExecutionTip", n.ExecutionTip(),
		"bsvCommonAncestor", bsvCommonAncestorHeight,
	)

	return nil
}

// IsReorgHalted reports whether the batcher is currently paused with
// the reorg-halt reason. Useful for admin/metrics surfaces that want
// to distinguish a reorg halt from other freeze causes (governance,
// circuit breaker).
func (n *OverlayNode) IsReorgHalted() bool {
	if n == nil || n.batcher == nil {
		return false
	}
	if !n.batcher.IsPaused() {
		return false
	}
	return n.batcher.PauseReason() == reorgPauseReason
}

// ResetReorgHalt clears a reorg-halt pause. It is a thin wrapper over
// BatcherResume that only acts when the batcher is actually paused for
// a reorg — calling it during a governance freeze or circuit-breaker
// trip is a no-op so admin tooling cannot accidentally clear the wrong
// halt cause.
func (n *OverlayNode) ResetReorgHalt() bool {
	if !n.IsReorgHalted() {
		return false
	}
	n.BatcherResume()
	slog.Info("reorg halt cleared, batcher resumed")
	return true
}
