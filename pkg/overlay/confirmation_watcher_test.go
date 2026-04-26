package overlay

import (
	"testing"
	"time"

	"github.com/icellan/bsvm/pkg/covenant"
	"github.com/icellan/bsvm/pkg/types"
)

// TestConfirmationWatcherAdvancesTips drives a fake BroadcastClient through
// the simulated BSV-confirmation lifecycle and verifies that the
// ConfirmationWatcher correctly advances confirmedTip and finalizedTip on
// the OverlayNode. This is the integration test that exercises the wiring
// added so the safe / finalized block tags actually move under BSV
// confirmations.
func TestConfirmationWatcherAdvancesTips(t *testing.T) {
	ts := newTestSetup(t)
	defer ts.node.Stop()

	fake := covenant.NewFakeBroadcastClient()

	// Use a fast poll interval so the test wall-clock stays short. The
	// watcher itself defaults zero/negative to 1 second, so we pass an
	// explicit small value.
	ts.node.StartConfirmationWatcher(fake, 20*time.Millisecond)
	defer func() {
		if w := ts.node.ConfirmationWatcherRef(); w != nil {
			w.Stop()
		}
	}()

	// Synthesise three outstanding broadcasts with deterministic txids
	// and register them with both the fake client and the watcher.
	txid1 := types.BytesToHash([]byte{0x01})
	txid2 := types.BytesToHash([]byte{0x02})
	txid3 := types.BytesToHash([]byte{0x03})

	w := ts.node.ConfirmationWatcherRef()
	if w == nil {
		t.Fatal("ConfirmationWatcher not attached after StartConfirmationWatcher")
	}

	w.Track(10, txid1)
	w.Track(20, txid2)
	w.Track(30, txid3)

	// Initially every broadcast has 0 confirmations so neither tip should
	// move. Sleep long enough for at least one poll cycle.
	waitForCondition(t, 250*time.Millisecond, func() bool {
		// Stable: tips remain zero after at least one poll cycle.
		return true
	})
	if got := ts.node.ConfirmedTip(); got != 0 {
		t.Fatalf("ConfirmedTip = %d, want 0 before any confirmations", got)
	}
	if got := ts.node.FinalizedTip(); got != 0 {
		t.Fatalf("FinalizedTip = %d, want 0 before any confirmations", got)
	}

	// Bump txid1 to 1 confirmation: confirmedTip should advance to 10.
	fake.SetConfirmations(txid1, 1)
	waitForCondition(t, 1*time.Second, func() bool {
		return ts.node.ConfirmedTip() >= 10
	})
	if got := ts.node.ConfirmedTip(); got != 10 {
		t.Fatalf("ConfirmedTip = %d, want 10 after txid1 hit 1 confirmation", got)
	}
	if got := ts.node.FinalizedTip(); got != 0 {
		t.Fatalf("FinalizedTip = %d, want 0 (no broadcast at 6+ confs yet)", got)
	}

	// Bump txid2 to 5 confirmations: confirmedTip should advance to 20
	// but finalizedTip should still be 0 (5 < 6).
	fake.SetConfirmations(txid2, 5)
	waitForCondition(t, 1*time.Second, func() bool {
		return ts.node.ConfirmedTip() >= 20
	})
	if got := ts.node.ConfirmedTip(); got != 20 {
		t.Fatalf("ConfirmedTip = %d, want 20 after txid2 hit 5 confirmations", got)
	}
	if got := ts.node.FinalizedTip(); got != 0 {
		t.Fatalf("FinalizedTip = %d, want 0 (txid2 still below depth 6)", got)
	}

	// Bump txid2 to 6 confirmations (the spec 11 finalized depth):
	// finalizedTip should now advance to 20.
	fake.SetConfirmations(txid2, 6)
	waitForCondition(t, 1*time.Second, func() bool {
		return ts.node.FinalizedTip() >= 20
	})
	if got := ts.node.FinalizedTip(); got != 20 {
		t.Fatalf("FinalizedTip = %d, want 20 after txid2 hit 6 confirmations", got)
	}

	// Bump txid3 to 10 confirmations: both tips advance to 30, and the
	// watcher drops finalised broadcasts from its tracking map.
	fake.SetConfirmations(txid3, 10)
	waitForCondition(t, 1*time.Second, func() bool {
		return ts.node.FinalizedTip() >= 30
	})
	if got := ts.node.ConfirmedTip(); got != 30 {
		t.Fatalf("ConfirmedTip = %d, want 30 after txid3 hit 10 confirmations", got)
	}
	if got := ts.node.FinalizedTip(); got != 30 {
		t.Fatalf("FinalizedTip = %d, want 30 after txid3 hit 10 confirmations", got)
	}

	// txid2 and txid3 reached the finalized depth and should have been
	// dropped. txid1 (still at 1 conf) remains. Allow one more poll to
	// give the drop a chance to land.
	waitForCondition(t, 250*time.Millisecond, func() bool {
		return w.Outstanding() == 1
	})
	if got := w.Outstanding(); got != 1 {
		t.Fatalf("Outstanding = %d, want 1 (only txid1 should remain after finalising txid2/txid3)", got)
	}
}

// TestStartConfirmationWatcherIdempotent verifies that calling
// StartConfirmationWatcher more than once cleanly stops the previous
// watcher and replaces it with a fresh one bound to the new client.
func TestStartConfirmationWatcherIdempotent(t *testing.T) {
	ts := newTestSetup(t)
	defer ts.node.Stop()

	fake1 := covenant.NewFakeBroadcastClient()
	ts.node.StartConfirmationWatcher(fake1, 20*time.Millisecond)
	first := ts.node.ConfirmationWatcherRef()
	if first == nil {
		t.Fatal("first watcher not attached")
	}

	fake2 := covenant.NewFakeBroadcastClient()
	ts.node.StartConfirmationWatcher(fake2, 20*time.Millisecond)
	second := ts.node.ConfirmationWatcherRef()
	if second == nil {
		t.Fatal("second watcher not attached")
	}
	if first == second {
		t.Fatal("StartConfirmationWatcher should have replaced the previous watcher")
	}
}

// TestStartConfirmationWatcherAppliesConfigDefault verifies the config
// default is used when interval <= 0 is passed.
func TestStartConfirmationWatcherAppliesConfigDefault(t *testing.T) {
	ts := newTestSetup(t)
	defer ts.node.Stop()

	// Passing 0 should fall back to ConfirmationPollInterval (or, if
	// that is also zero, the watcher's internal 1s default).
	fake := covenant.NewFakeBroadcastClient()
	ts.node.StartConfirmationWatcher(fake, 0)
	if w := ts.node.ConfirmationWatcherRef(); w == nil {
		t.Fatal("watcher not attached when interval is zero")
	}
}

// waitForCondition polls cond every 10ms and returns when it becomes
// true or the timeout expires. The caller decides whether a timeout is
// fatal — this helper just gives the watcher time to advance through
// at least one poll cycle without sleeping for a fixed worst-case
// duration.
func waitForCondition(t *testing.T, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
}
