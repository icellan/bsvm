package overlay

import (
	"log/slog"
	"sync"
	"time"

	"github.com/icellan/bsvm/pkg/types"
)

// CircuitBreaker monitors for persistent EVM disagreements between the
// Go EVM and SP1 revm. If consecutive blocks disagree on state roots,
// the node pauses batch processing and enters follower-only mode.
//
// Per spec 09: 2 retries per block (3 total attempts), 5s backoff between
// retries, and 3 consecutive disagreeing blocks trip the breaker.
type CircuitBreaker struct {
	maxRetries           int           // per block, default 2 (3 total attempts)
	retryBackoff         time.Duration // default 5s
	consecutiveThreshold int           // blocks before tripping, default 3

	consecutiveFailures int
	tripped             bool
	mu                  sync.Mutex

	onTrip func(blockNum uint64, goRoot, sp1Root types.Hash) // alert callback
}

// NewCircuitBreaker creates a circuit breaker with the default configuration
// (2 retries, 5s backoff, 3 consecutive failures to trip). The onTrip
// callback is invoked when the breaker trips; it receives the block number
// and the two disagreeing state roots. If onTrip is nil, a slog warning
// is emitted instead.
func NewCircuitBreaker(onTrip func(uint64, types.Hash, types.Hash)) *CircuitBreaker {
	return &CircuitBreaker{
		maxRetries:           2,
		retryBackoff:         5 * time.Second,
		consecutiveThreshold: 3,
		onTrip:               onTrip,
	}
}

// RecordSuccess resets the consecutive failure counter. It should be called
// after a block where the Go EVM and SP1 state roots agree.
func (cb *CircuitBreaker) RecordSuccess() {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.consecutiveFailures = 0
}

// RecordDisagreement records a state root mismatch for the given block.
// It increments the consecutive failure counter and trips the breaker if
// the threshold is reached. Returns true if the circuit breaker has
// tripped (node should enter follower mode).
func (cb *CircuitBreaker) RecordDisagreement(blockNum uint64, goRoot, sp1Root types.Hash) bool {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.consecutiveFailures++

	slog.Warn("EVM state root disagreement",
		"block", blockNum,
		"goRoot", goRoot.Hex(),
		"sp1Root", sp1Root.Hex(),
		"consecutiveFailures", cb.consecutiveFailures,
		"threshold", cb.consecutiveThreshold,
	)

	if cb.consecutiveFailures >= cb.consecutiveThreshold && !cb.tripped {
		cb.tripped = true

		slog.Error("circuit breaker tripped: entering follower mode",
			"block", blockNum,
			"consecutiveFailures", cb.consecutiveFailures,
		)

		if cb.onTrip != nil {
			cb.onTrip(blockNum, goRoot, sp1Root)
		}
	}

	return cb.tripped
}

// IsTripped returns whether the circuit breaker is currently tripped.
// When tripped, the node should not produce new batches and should
// operate in follower-only mode.
func (cb *CircuitBreaker) IsTripped() bool {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	return cb.tripped
}

// Reset manually clears the circuit breaker, allowing batch processing
// to resume. This is intended to be called by an operator via the
// `bsvm admin reset-circuit-breaker` command after the disagreement
// root cause has been investigated and resolved.
func (cb *CircuitBreaker) Reset() {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.tripped = false
	cb.consecutiveFailures = 0

	slog.Info("circuit breaker reset: resuming batch processing")
}

// MaxRetries returns the maximum number of retries per block before
// recording a disagreement. The total attempts per block is
// MaxRetries + 1.
func (cb *CircuitBreaker) MaxRetries() int {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	return cb.maxRetries
}

// RetryBackoff returns the duration to wait between retry attempts.
func (cb *CircuitBreaker) RetryBackoff() time.Duration {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	return cb.retryBackoff
}

// ConsecutiveFailures returns the current consecutive failure count.
func (cb *CircuitBreaker) ConsecutiveFailures() int {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	return cb.consecutiveFailures
}
