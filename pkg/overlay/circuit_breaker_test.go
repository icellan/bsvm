package overlay

import (
	"sync"
	"testing"

	"github.com/icellan/bsvm/pkg/types"
)

// TestCircuitBreakerSuccess verifies that RecordSuccess resets the
// consecutive failure counter.
func TestCircuitBreakerSuccess(t *testing.T) {
	cb := NewCircuitBreaker(nil)

	goRoot := types.HexToHash("0xaaaa")
	sp1Root := types.HexToHash("0xbbbb")

	// Record 2 failures (below the threshold of 3).
	cb.RecordDisagreement(1, goRoot, sp1Root)
	cb.RecordDisagreement(2, goRoot, sp1Root)

	if cb.ConsecutiveFailures() != 2 {
		t.Fatalf("expected 2 consecutive failures, got %d", cb.ConsecutiveFailures())
	}

	// Record success -- should reset the counter.
	cb.RecordSuccess()

	if cb.ConsecutiveFailures() != 0 {
		t.Fatalf("expected 0 consecutive failures after success, got %d", cb.ConsecutiveFailures())
	}

	if cb.IsTripped() {
		t.Fatal("circuit breaker should not be tripped after success")
	}
}

// TestCircuitBreakerTrip verifies that 3 consecutive disagreements
// trips the breaker.
func TestCircuitBreakerTrip(t *testing.T) {
	cb := NewCircuitBreaker(nil)

	goRoot := types.HexToHash("0xaaaa")
	sp1Root := types.HexToHash("0xbbbb")

	// First two disagreements should not trip the breaker.
	tripped := cb.RecordDisagreement(1, goRoot, sp1Root)
	if tripped {
		t.Fatal("should not be tripped after 1 disagreement")
	}

	tripped = cb.RecordDisagreement(2, goRoot, sp1Root)
	if tripped {
		t.Fatal("should not be tripped after 2 disagreements")
	}

	// Third disagreement should trip the breaker.
	tripped = cb.RecordDisagreement(3, goRoot, sp1Root)
	if !tripped {
		t.Fatal("should be tripped after 3 disagreements")
	}

	if !cb.IsTripped() {
		t.Fatal("IsTripped should return true")
	}

	// Additional disagreements should still report tripped.
	tripped = cb.RecordDisagreement(4, goRoot, sp1Root)
	if !tripped {
		t.Fatal("should still be tripped after 4 disagreements")
	}
}

// TestCircuitBreakerReset verifies that manual reset clears the
// tripped state and failure counter.
func TestCircuitBreakerReset(t *testing.T) {
	cb := NewCircuitBreaker(nil)

	goRoot := types.HexToHash("0xaaaa")
	sp1Root := types.HexToHash("0xbbbb")

	// Trip the breaker.
	cb.RecordDisagreement(1, goRoot, sp1Root)
	cb.RecordDisagreement(2, goRoot, sp1Root)
	cb.RecordDisagreement(3, goRoot, sp1Root)

	if !cb.IsTripped() {
		t.Fatal("should be tripped before reset")
	}

	// Reset.
	cb.Reset()

	if cb.IsTripped() {
		t.Fatal("should not be tripped after reset")
	}

	if cb.ConsecutiveFailures() != 0 {
		t.Fatalf("expected 0 consecutive failures after reset, got %d", cb.ConsecutiveFailures())
	}

	// After reset, it should take another 3 failures to trip again.
	cb.RecordDisagreement(4, goRoot, sp1Root)
	cb.RecordDisagreement(5, goRoot, sp1Root)
	if cb.IsTripped() {
		t.Fatal("should not be tripped after only 2 failures post-reset")
	}

	cb.RecordDisagreement(6, goRoot, sp1Root)
	if !cb.IsTripped() {
		t.Fatal("should be tripped after 3 failures post-reset")
	}
}

// TestCircuitBreakerIntermittent verifies that a success between
// failures resets the counter, preventing tripping.
func TestCircuitBreakerIntermittent(t *testing.T) {
	cb := NewCircuitBreaker(nil)

	goRoot := types.HexToHash("0xaaaa")
	sp1Root := types.HexToHash("0xbbbb")

	// Fail, fail, succeed, fail, fail -- should NOT trip.
	cb.RecordDisagreement(1, goRoot, sp1Root)
	cb.RecordDisagreement(2, goRoot, sp1Root)
	cb.RecordSuccess()
	cb.RecordDisagreement(3, goRoot, sp1Root)
	cb.RecordDisagreement(4, goRoot, sp1Root)

	if cb.IsTripped() {
		t.Fatal("should not be tripped with intermittent successes")
	}

	if cb.ConsecutiveFailures() != 2 {
		t.Fatalf("expected 2 consecutive failures, got %d", cb.ConsecutiveFailures())
	}

	// One more failure should trip it (3 consecutive).
	cb.RecordDisagreement(5, goRoot, sp1Root)
	if !cb.IsTripped() {
		t.Fatal("should be tripped after 3 consecutive failures")
	}
}

// TestCircuitBreakerCallback verifies that the onTrip callback fires
// with the correct block number and state roots when the breaker trips.
func TestCircuitBreakerCallback(t *testing.T) {
	var mu sync.Mutex
	var calledBlock uint64
	var calledGoRoot, calledSP1Root types.Hash
	callCount := 0

	cb := NewCircuitBreaker(func(blockNum uint64, goRoot, sp1Root types.Hash) {
		mu.Lock()
		defer mu.Unlock()
		callCount++
		calledBlock = blockNum
		calledGoRoot = goRoot
		calledSP1Root = sp1Root
	})

	goRoot := types.HexToHash("0x1111")
	sp1Root := types.HexToHash("0x2222")

	// First two should not fire the callback.
	cb.RecordDisagreement(10, goRoot, sp1Root)
	cb.RecordDisagreement(11, goRoot, sp1Root)

	mu.Lock()
	if callCount != 0 {
		t.Fatalf("callback should not have fired yet, got %d calls", callCount)
	}
	mu.Unlock()

	// Third should fire the callback.
	cb.RecordDisagreement(12, goRoot, sp1Root)

	mu.Lock()
	if callCount != 1 {
		t.Fatalf("callback should have fired once, got %d calls", callCount)
	}
	if calledBlock != 12 {
		t.Fatalf("expected block 12 in callback, got %d", calledBlock)
	}
	if calledGoRoot != goRoot {
		t.Fatalf("expected goRoot %s in callback, got %s", goRoot.Hex(), calledGoRoot.Hex())
	}
	if calledSP1Root != sp1Root {
		t.Fatalf("expected sp1Root %s in callback, got %s", sp1Root.Hex(), calledSP1Root.Hex())
	}
	mu.Unlock()

	// Fourth disagreement should not fire the callback again (already tripped).
	cb.RecordDisagreement(13, goRoot, sp1Root)

	mu.Lock()
	if callCount != 1 {
		t.Fatalf("callback should have fired only once, got %d calls", callCount)
	}
	mu.Unlock()
}

// TestCircuitBreakerDefaults verifies the default configuration values.
func TestCircuitBreakerDefaults(t *testing.T) {
	cb := NewCircuitBreaker(nil)

	if cb.MaxRetries() != 2 {
		t.Fatalf("expected maxRetries 2, got %d", cb.MaxRetries())
	}

	if cb.RetryBackoff().Seconds() != 5 {
		t.Fatalf("expected retryBackoff 5s, got %v", cb.RetryBackoff())
	}

	if cb.ConsecutiveFailures() != 0 {
		t.Fatalf("expected 0 initial consecutive failures, got %d", cb.ConsecutiveFailures())
	}

	if cb.IsTripped() {
		t.Fatal("should not be tripped initially")
	}
}
