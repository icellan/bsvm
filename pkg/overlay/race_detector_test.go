package overlay

import (
	"sync"
	"testing"
	"time"

	"github.com/icellan/bsvm/pkg/types"
)

// TestRaceDetector_SetPendingAdvance verifies that SetPendingAdvance records
// the pending advance transaction ID.
func TestRaceDetector_SetPendingAdvance(t *testing.T) {
	rd := NewRaceDetector(nil)

	txid := types.HexToHash("0xabcdef")
	rd.SetPendingAdvance(txid)

	rd.mu.Lock()
	defer rd.mu.Unlock()

	if rd.pendingAdvance == nil {
		t.Fatal("expected pending advance to be set")
	}
	if *rd.pendingAdvance != txid {
		t.Errorf("expected pending advance %s, got %s", txid.Hex(), rd.pendingAdvance.Hex())
	}
}

// TestRaceDetector_HandleAdvance_Win verifies that handling our own advance
// calls the onRaceWon callback and resets the loss counter.
func TestRaceDetector_HandleAdvance_Win(t *testing.T) {
	rd := NewRaceDetector(nil)

	// Set up some losses first.
	rd.mu.Lock()
	rd.consecutiveLosses = 3
	rd.mu.Unlock()

	var mu sync.Mutex
	wonCalled := false
	var wonEvent *CovenantAdvanceEvent

	rd.OnRaceWon(func(event *CovenantAdvanceEvent) {
		mu.Lock()
		defer mu.Unlock()
		wonCalled = true
		wonEvent = event
	})

	event := &CovenantAdvanceEvent{
		BSVTxID:       types.HexToHash("0x1111"),
		L2BlockNum:    5,
		PostStateRoot: types.HexToHash("0x2222"),
		IsOurs:        true,
	}

	err := rd.HandleCovenantAdvance(event)
	if err != nil {
		t.Fatalf("HandleCovenantAdvance returned error: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()

	if !wonCalled {
		t.Fatal("expected onRaceWon callback to be called")
	}
	if wonEvent.BSVTxID != event.BSVTxID {
		t.Errorf("expected BSVTxID %s, got %s", event.BSVTxID.Hex(), wonEvent.BSVTxID.Hex())
	}

	// Loss counter should be reset.
	if rd.ConsecutiveLosses() != 0 {
		t.Errorf("expected 0 consecutive losses after win, got %d", rd.ConsecutiveLosses())
	}
}

// TestRaceDetector_HandleAdvance_Loss verifies that handling another node's
// advance calls the onRaceLost callback and increments losses.
func TestRaceDetector_HandleAdvance_Loss(t *testing.T) {
	rd := NewRaceDetector(nil)

	var mu sync.Mutex
	lostCalled := false
	var lostEvent *CovenantAdvanceEvent

	rd.OnRaceLost(func(event *CovenantAdvanceEvent) {
		mu.Lock()
		defer mu.Unlock()
		lostCalled = true
		lostEvent = event
	})

	event := &CovenantAdvanceEvent{
		BSVTxID:       types.HexToHash("0x3333"),
		L2BlockNum:    5,
		PostStateRoot: types.HexToHash("0x4444"),
		BatchData:     []byte("winner-batch"),
		IsOurs:        false,
	}

	err := rd.HandleCovenantAdvance(event)
	if err != nil {
		t.Fatalf("HandleCovenantAdvance returned error: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()

	if !lostCalled {
		t.Fatal("expected onRaceLost callback to be called")
	}
	if lostEvent.BSVTxID != event.BSVTxID {
		t.Errorf("expected BSVTxID %s, got %s", event.BSVTxID.Hex(), lostEvent.BSVTxID.Hex())
	}

	// Loss counter should be incremented.
	if rd.ConsecutiveLosses() != 1 {
		t.Errorf("expected 1 consecutive loss, got %d", rd.ConsecutiveLosses())
	}
}

// TestRaceDetector_BackoffDuration verifies that backoff increases
// exponentially with consecutive losses.
func TestRaceDetector_BackoffDuration(t *testing.T) {
	rd := NewRaceDetector(nil)

	// Zero losses => 50-200ms first-attempt jitter (spec 11).
	if d := rd.BackoffDuration(); d < 50*time.Millisecond || d >= 200*time.Millisecond {
		t.Errorf("expected 50-200ms first-attempt jitter at 0 losses, got %v", d)
	}

	// 1 loss => ~250ms (base=125ms * 2^1 = 250ms, ±jitter)
	rd.mu.Lock()
	rd.consecutiveLosses = 1
	rd.mu.Unlock()

	d1 := rd.BackoffDuration()
	if d1 < 150*time.Millisecond || d1 > 350*time.Millisecond {
		t.Errorf("expected backoff ~250ms at 1 loss, got %v", d1)
	}

	// 2 losses => ~500ms (base=125ms * 2^2 = 500ms, ±jitter)
	rd.mu.Lock()
	rd.consecutiveLosses = 2
	rd.mu.Unlock()

	d2 := rd.BackoffDuration()
	if d2 < 400*time.Millisecond || d2 > 600*time.Millisecond {
		t.Errorf("expected backoff ~500ms at 2 losses, got %v", d2)
	}

	// 3 losses => ~1s (base=125ms * 2^3 = 1000ms, ±jitter)
	rd.mu.Lock()
	rd.consecutiveLosses = 3
	rd.mu.Unlock()

	d3 := rd.BackoffDuration()
	if d3 < 900*time.Millisecond || d3 > 1100*time.Millisecond {
		t.Errorf("expected backoff ~1s at 3 losses, got %v", d3)
	}

	// Verify monotonically increasing (on average).
	if d2 <= d1 {
		t.Errorf("expected d2 > d1, got d1=%v, d2=%v", d1, d2)
	}
	if d3 <= d2 {
		t.Errorf("expected d3 > d2, got d2=%v, d3=%v", d2, d3)
	}
}

// TestRaceDetector_BackoffDuration_MaxCap verifies that backoff is capped
// at maxBackoff (30s) regardless of how many losses occur.
func TestRaceDetector_BackoffDuration_MaxCap(t *testing.T) {
	rd := NewRaceDetector(nil)

	// Set many losses to push backoff past the max.
	rd.mu.Lock()
	rd.consecutiveLosses = 100
	rd.mu.Unlock()

	d := rd.BackoffDuration()
	if d > 30*time.Second {
		t.Errorf("backoff should be capped at 30s, got %v", d)
	}
	// Should be close to 30s.
	if d < 29*time.Second {
		t.Errorf("expected backoff near 30s at high losses, got %v", d)
	}
}

// TestRaceDetector_ShouldEnterFollowerMode verifies the follower mode
// threshold (default: 5 consecutive losses).
func TestRaceDetector_ShouldEnterFollowerMode(t *testing.T) {
	rd := NewRaceDetector(nil)

	// 4 losses: should not enter follower mode.
	rd.mu.Lock()
	rd.consecutiveLosses = 4
	rd.mu.Unlock()

	if rd.ShouldEnterFollowerMode() {
		t.Fatal("should not enter follower mode at 4 losses")
	}

	// 5 losses: should enter follower mode.
	rd.mu.Lock()
	rd.consecutiveLosses = 5
	rd.mu.Unlock()

	if !rd.ShouldEnterFollowerMode() {
		t.Fatal("should enter follower mode at 5 losses")
	}

	// 6 losses: should still be in follower mode.
	rd.mu.Lock()
	rd.consecutiveLosses = 6
	rd.mu.Unlock()

	if !rd.ShouldEnterFollowerMode() {
		t.Fatal("should still be in follower mode at 6 losses")
	}
}

// TestRaceDetector_ResetLossCounter verifies that resetting the loss
// counter sets it back to zero.
func TestRaceDetector_ResetLossCounter(t *testing.T) {
	rd := NewRaceDetector(nil)

	// Accumulate some losses.
	rd.mu.Lock()
	rd.consecutiveLosses = 7
	rd.mu.Unlock()

	if rd.ConsecutiveLosses() != 7 {
		t.Fatalf("expected 7 losses, got %d", rd.ConsecutiveLosses())
	}

	rd.ResetLossCounter()

	if rd.ConsecutiveLosses() != 0 {
		t.Errorf("expected 0 losses after reset, got %d", rd.ConsecutiveLosses())
	}

	if rd.ShouldEnterFollowerMode() {
		t.Error("should not be in follower mode after reset")
	}
}

// TestRaceDetector_ConsecutiveWinsAfterLosses verifies that a win resets
// the consecutive loss counter, breaking the follower-mode path.
func TestRaceDetector_ConsecutiveWinsAfterLosses(t *testing.T) {
	rd := NewRaceDetector(nil)

	// Simulate 4 losses.
	for i := 0; i < 4; i++ {
		event := &CovenantAdvanceEvent{
			BSVTxID:    types.HexToHash("0xdead"),
			L2BlockNum: uint64(i + 1),
			IsOurs:     false,
		}
		rd.HandleCovenantAdvance(event)
	}

	if rd.ConsecutiveLosses() != 4 {
		t.Fatalf("expected 4 losses, got %d", rd.ConsecutiveLosses())
	}

	// Now win one.
	winEvent := &CovenantAdvanceEvent{
		BSVTxID:    types.HexToHash("0xbeef"),
		L2BlockNum: 5,
		IsOurs:     true,
	}
	rd.HandleCovenantAdvance(winEvent)

	if rd.ConsecutiveLosses() != 0 {
		t.Errorf("expected 0 losses after win, got %d", rd.ConsecutiveLosses())
	}

	if rd.ShouldEnterFollowerMode() {
		t.Error("should not be in follower mode after a win")
	}

	// Lose 2 more -- should still be below threshold.
	for i := 0; i < 2; i++ {
		event := &CovenantAdvanceEvent{
			BSVTxID:    types.HexToHash("0xfeed"),
			L2BlockNum: uint64(6 + i),
			IsOurs:     false,
		}
		rd.HandleCovenantAdvance(event)
	}

	if rd.ConsecutiveLosses() != 2 {
		t.Errorf("expected 2 losses, got %d", rd.ConsecutiveLosses())
	}
	if rd.ShouldEnterFollowerMode() {
		t.Error("should not be in follower mode with only 2 losses")
	}
}
