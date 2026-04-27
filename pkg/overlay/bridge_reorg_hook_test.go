package overlay

import (
	"testing"

	"github.com/holiman/uint256"

	"github.com/icellan/bsvm/pkg/types"
)

// TestHaltAndRollbackForReorg_PausesBatcher verifies the hook pauses
// the batcher with the structured reorg reason and the IsReorgHalted
// accessor correctly identifies the cause.
func TestHaltAndRollbackForReorg_PausesBatcher(t *testing.T) {
	ts := newTestSetup(t)
	defer ts.node.Stop()

	// Sanity: batcher starts unpaused.
	if ts.node.BatcherIsPaused() {
		t.Fatal("batcher should start unpaused")
	}
	if ts.node.IsReorgHalted() {
		t.Fatal("IsReorgHalted should be false before halt")
	}

	if err := ts.node.HaltAndRollbackForReorg(42); err != nil {
		t.Fatalf("HaltAndRollbackForReorg: %v", err)
	}

	if !ts.node.BatcherIsPaused() {
		t.Fatal("batcher should be paused after halt")
	}
	if !ts.node.IsReorgHalted() {
		t.Fatal("IsReorgHalted should be true after halt")
	}

	if got := ts.node.Batcher().PauseReason(); got != reorgPauseReason {
		t.Fatalf("PauseReason = %q, want %q", got, reorgPauseReason)
	}
}

// TestHaltAndRollbackForReorg_RollsBackToFinalizedTip drives the node
// forward, sets a finalized tip below the execution tip, then halts.
// Execution tip must drop to the finalized tip.
func TestHaltAndRollbackForReorg_RollsBackToFinalizedTip(t *testing.T) {
	ts := newTestSetup(t)
	defer ts.node.Stop()

	recipient := types.HexToAddress("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	transferAmount := uint256.NewInt(10_000_000_000_000)

	// Process 3 blocks.
	for i := uint64(0); i < 3; i++ {
		tx := ts.signTx(t, i, recipient, transferAmount, nil)
		if _, err := ts.node.ProcessBatch([]*types.Transaction{tx}); err != nil {
			t.Fatalf("ProcessBatch %d: %v", i+1, err)
		}
	}

	if got := ts.node.ExecutionTip(); got != 3 {
		t.Fatalf("execution tip = %d, want 3", got)
	}

	// Mark block 1 as finalized.
	ts.node.SetFinalizedTip(1)

	if err := ts.node.HaltAndRollbackForReorg(99); err != nil {
		t.Fatalf("HaltAndRollbackForReorg: %v", err)
	}

	if got := ts.node.ExecutionTip(); got != 1 {
		t.Fatalf("after halt: execution tip = %d, want 1 (finalized tip)", got)
	}
	if !ts.node.IsReorgHalted() {
		t.Fatal("IsReorgHalted should be true after halt")
	}
}

// TestHaltAndRollbackForReorg_NoOpWhenAtFinalized verifies that calling
// the hook when execution tip == finalized tip pauses the batcher but
// does not error or drive Rollback into an invalid state.
func TestHaltAndRollbackForReorg_NoOpWhenAtFinalized(t *testing.T) {
	ts := newTestSetup(t)
	defer ts.node.Stop()

	// Execution tip starts at 0; finalized tip stays at 0. Halt should
	// pause but Rollback to 0 from 0 is a no-op.
	if err := ts.node.HaltAndRollbackForReorg(0); err != nil {
		t.Fatalf("HaltAndRollbackForReorg: %v", err)
	}

	if got := ts.node.ExecutionTip(); got != 0 {
		t.Fatalf("execution tip = %d, want 0", got)
	}
	if !ts.node.BatcherIsPaused() {
		t.Fatal("batcher should be paused")
	}
}

// TestResetReorgHalt_ResumesOnlyForReorgCause verifies ResetReorgHalt
// resumes the batcher when paused for a reorg, but is a no-op when the
// pause is from another cause.
func TestResetReorgHalt_ResumesOnlyForReorgCause(t *testing.T) {
	ts := newTestSetup(t)
	defer ts.node.Stop()

	// Halt for reorg, then reset.
	if err := ts.node.HaltAndRollbackForReorg(10); err != nil {
		t.Fatalf("HaltAndRollbackForReorg: %v", err)
	}
	if !ts.node.IsReorgHalted() {
		t.Fatal("expected reorg halted")
	}
	if !ts.node.ResetReorgHalt() {
		t.Fatal("ResetReorgHalt should report success")
	}
	if ts.node.BatcherIsPaused() {
		t.Fatal("batcher should be resumed after ResetReorgHalt")
	}

	// Pause for an unrelated reason — ResetReorgHalt must NOT clear it.
	ts.node.Batcher().Pause("governance freeze")
	if !ts.node.BatcherIsPaused() {
		t.Fatal("expected batcher paused for governance freeze")
	}
	if ts.node.IsReorgHalted() {
		t.Fatal("IsReorgHalted should be false for non-reorg cause")
	}
	if ts.node.ResetReorgHalt() {
		t.Fatal("ResetReorgHalt should be no-op for non-reorg cause")
	}
	if !ts.node.BatcherIsPaused() {
		t.Fatal("batcher should still be paused (non-reorg cause)")
	}
}

// TestReorgHaltsTotal_Increments verifies the process-global counter
// advances on each halt.
func TestReorgHaltsTotal_Increments(t *testing.T) {
	ts := newTestSetup(t)
	defer ts.node.Stop()

	before := ReorgHaltsTotal()
	if err := ts.node.HaltAndRollbackForReorg(1); err != nil {
		t.Fatalf("halt: %v", err)
	}
	if err := ts.node.HaltAndRollbackForReorg(2); err != nil {
		t.Fatalf("halt: %v", err)
	}
	after := ReorgHaltsTotal()
	if after-before != 2 {
		t.Fatalf("ReorgHaltsTotal delta = %d, want 2", after-before)
	}
}

// TestHaltAndRollbackForReorg_NilNode guards the defensive nil-receiver
// branch.
func TestHaltAndRollbackForReorg_NilNode(t *testing.T) {
	var n *OverlayNode
	if err := n.HaltAndRollbackForReorg(0); err == nil {
		t.Fatal("nil node should return error")
	}
}
