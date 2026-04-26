package overlay

import (
	"strings"
	"testing"
	"time"

	"github.com/holiman/uint256"

	"github.com/icellan/bsvm/pkg/covenant"
	"github.com/icellan/bsvm/pkg/types"
)

// TestGovernanceFreezeWatcher_PausesBatcher exercises the end-to-end
// wiring described in spec 11: when the covenant transitions to
// Frozen, the freeze watcher pushes the new state through the
// GovernanceMonitor, which pauses the batcher. New tx submissions
// must then fail with an error that errors.Is against
// ErrBatcherPaused so the JSON-RPC layer can map it to "shard frozen".
func TestGovernanceFreezeWatcher_PausesBatcher(t *testing.T) {
	ts := newTestSetup(t)
	defer ts.node.Stop()

	ClearGovernanceMonitor(ts.node)

	// Start the watcher with a tight tick so the test doesn't sleep
	// for a full default interval (1s).
	w := EnableGovernanceFreezeWatcher(ts.node, 50*time.Millisecond)
	if w == nil {
		t.Fatal("EnableGovernanceFreezeWatcher returned nil for a fully-wired node")
	}
	defer w.Stop()

	// Sanity: the batcher accepts a tx while the shard is active.
	recipient := types.HexToAddress("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	tx0 := ts.signTx(t, 0, recipient, uint256.NewInt(1000), nil)
	if err := ts.node.Batcher().Add(tx0); err != nil {
		t.Fatalf("pre-freeze submission failed: %v", err)
	}

	// Simulate the covenant landing a freeze advance on BSV. Spec 12
	// encodes the freeze as Frozen=1 in the covenant state; we reuse
	// CovenantManager.ApplyAdvance to flip the flag the same way the
	// production broadcast path would.
	cm := ts.node.CovenantManager()
	cur := cm.CurrentState()
	frozen := covenant.CovenantState{
		StateRoot:   cur.StateRoot,
		BlockNumber: cur.BlockNumber + 1,
		Frozen:      1,
	}
	if err := cm.ApplyAdvance(types.Hash{1, 2, 3}, frozen); err != nil {
		t.Fatalf("ApplyAdvance(frozen) failed: %v", err)
	}

	// Force the watcher to sync without waiting for the next tick.
	w.SyncOnce()

	if !ts.node.Batcher().IsPaused() {
		t.Fatal("batcher should be paused after governance freeze")
	}
	if got := ts.node.GovernanceMonitor().State(); got != GovernanceFrozen {
		t.Fatalf("monitor state = %v, want frozen", got)
	}

	// New transactions must be rejected with an error that
	// IsBatcherPausedErr / errors.Is(ErrBatcherPaused) recognises.
	tx1 := ts.signTx(t, 1, recipient, uint256.NewInt(1000), nil)
	err := ts.node.Batcher().Add(tx1)
	if err == nil {
		t.Fatal("expected an error when submitting to a frozen batcher")
	}
	if !IsBatcherPausedErr(err) {
		t.Fatalf("error %q does not match ErrBatcherPaused / paused-batcher signature", err.Error())
	}
	// Defence-in-depth: the message itself should mention the pause
	// so operators reading logs can debug the rejection.
	if !strings.Contains(err.Error(), "paused") && !strings.Contains(err.Error(), "frozen") {
		t.Fatalf("error message %q lacks paused/frozen keyword", err.Error())
	}

	// Unfreeze: covenant transitions back to active. The watcher must
	// resume the batcher and the monitor must report active again.
	active := covenant.CovenantState{
		StateRoot:   frozen.StateRoot,
		BlockNumber: frozen.BlockNumber + 1,
		Frozen:      0,
	}
	if err := cm.ApplyAdvance(types.Hash{4, 5, 6}, active); err != nil {
		t.Fatalf("ApplyAdvance(active) failed: %v", err)
	}
	w.SyncOnce()

	if ts.node.Batcher().IsPaused() {
		t.Fatal("batcher should be resumed after governance unfreeze")
	}
	if got := ts.node.GovernanceMonitor().State(); got != GovernanceActive {
		t.Fatalf("monitor state = %v, want active", got)
	}

	tx2 := ts.signTx(t, 1, recipient, uint256.NewInt(1000), nil)
	if err := ts.node.Batcher().Add(tx2); err != nil {
		t.Fatalf("post-unfreeze submission failed: %v", err)
	}
}

// TestGovernanceFreezeWatcher_StartsPausedWhenAlreadyFrozen covers the
// node-restart path: a node that comes up with a covenant already in
// the Frozen state must report the pause immediately, before any tx
// is submitted, so the explorer never advertises a writable shard
// that isn't.
func TestGovernanceFreezeWatcher_StartsPausedWhenAlreadyFrozen(t *testing.T) {
	ts := newTestSetup(t)
	defer ts.node.Stop()

	ClearGovernanceMonitor(ts.node)

	// Pre-freeze the covenant before the watcher starts.
	cm := ts.node.CovenantManager()
	cur := cm.CurrentState()
	frozen := covenant.CovenantState{
		StateRoot:   cur.StateRoot,
		BlockNumber: cur.BlockNumber + 1,
		Frozen:      1,
	}
	if err := cm.ApplyAdvance(types.Hash{7, 7, 7}, frozen); err != nil {
		t.Fatalf("ApplyAdvance(frozen) failed: %v", err)
	}

	w := EnableGovernanceFreezeWatcher(ts.node, 50*time.Millisecond)
	if w == nil {
		t.Fatal("EnableGovernanceFreezeWatcher returned nil")
	}
	defer w.Stop()

	if !ts.node.Batcher().IsPaused() {
		t.Fatal("batcher should be paused on startup with frozen covenant")
	}

	recipient := types.HexToAddress("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	tx := ts.signTx(t, 0, recipient, uint256.NewInt(1000), nil)
	err := ts.node.Batcher().Add(tx)
	if err == nil {
		t.Fatal("expected paused error on tx submission to a node that started frozen")
	}
	if !IsBatcherPausedErr(err) {
		t.Fatalf("err = %v, want IsBatcherPausedErr", err)
	}
}
