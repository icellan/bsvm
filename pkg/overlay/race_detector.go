package overlay

import (
	"log/slog"
	"math/rand"
	"sync"
	"time"

	"github.com/icellan/bsvm/pkg/types"
)

// RaceOutcome represents the result of a covenant advance race.
type RaceOutcome int

const (
	// RaceWon means our covenant advance was accepted by the BSV network.
	RaceWon RaceOutcome = iota
	// RaceLost means another node's covenant advance was accepted first.
	RaceLost
	// RacePending means the race outcome is not yet determined.
	RacePending
)

// CovenantAdvanceEvent represents a covenant advance detected on the BSV network.
// This could be our own advance or another node's advance.
type CovenantAdvanceEvent struct {
	// BSVTxID is the BSV transaction ID of the covenant advance.
	BSVTxID types.Hash
	// L2BlockNum is the L2 block number committed by this advance.
	L2BlockNum uint64
	// PostStateRoot is the post-state root from the advance.
	PostStateRoot types.Hash
	// BatchData is the batch data from the OP_RETURN output.
	BatchData []byte
	// IsOurs is true if this advance was broadcast by this node.
	IsOurs bool
}

// RaceDetector monitors the BSV network for covenant advance transactions
// and determines whether this node won or lost a race.
type RaceDetector struct {
	mu sync.Mutex

	node *OverlayNode

	// Current state
	pendingAdvance    *types.Hash // Our pending advance tx, nil if none
	consecutiveLosses int         // Track consecutive losses for backoff

	// Configuration
	maxConsecutiveLosses int           // Enter follower mode after this many losses (default: 5)
	baseBackoff          time.Duration // Base backoff time (default: 2s)
	maxBackoff           time.Duration // Maximum backoff time (default: 30s)

	// Callbacks
	onRaceLost func(event *CovenantAdvanceEvent) // Called when we lose a race
	onRaceWon  func(event *CovenantAdvanceEvent) // Called when we win a race
}

// NewRaceDetector creates a new race detector for the given overlay node.
func NewRaceDetector(node *OverlayNode) *RaceDetector {
	return &RaceDetector{
		node:                 node,
		maxConsecutiveLosses: 5,
		baseBackoff:          125 * time.Millisecond, // 50-200ms initial jitter range
		maxBackoff:           30 * time.Second,
	}
}

// SetPendingAdvance records that we have broadcast a covenant advance transaction.
func (rd *RaceDetector) SetPendingAdvance(txid types.Hash) {
	rd.mu.Lock()
	defer rd.mu.Unlock()
	rd.pendingAdvance = &txid
}

// HandleCovenantAdvance processes a covenant advance event from the BSV network.
// If the advance is not ours, we've lost the race and need to replay the winner's batch.
func (rd *RaceDetector) HandleCovenantAdvance(event *CovenantAdvanceEvent) error {
	rd.mu.Lock()

	if event.IsOurs {
		// We won the race.
		rd.consecutiveLosses = 0
		rd.pendingAdvance = nil

		slog.Info("race won: our covenant advance accepted",
			"bsvTxID", event.BSVTxID.Hex(),
			"l2Block", event.L2BlockNum,
		)

		callback := rd.onRaceWon
		rd.mu.Unlock()

		if callback != nil {
			callback(event)
		}
		return nil
	}

	// We lost the race.
	rd.consecutiveLosses++
	rd.pendingAdvance = nil
	losses := rd.consecutiveLosses
	backoff := rd.backoffDuration()

	slog.Warn("race lost: another node's covenant advance accepted",
		"bsvTxID", event.BSVTxID.Hex(),
		"l2Block", event.L2BlockNum,
		"consecutiveLosses", losses,
		"nextBackoff", backoff,
	)

	callback := rd.onRaceLost
	rd.mu.Unlock()

	if callback != nil {
		callback(event)
	}
	return nil
}

// BackoffDuration returns how long to wait before attempting another advance,
// using exponential backoff with jitter based on consecutive losses.
func (rd *RaceDetector) BackoffDuration() time.Duration {
	rd.mu.Lock()
	defer rd.mu.Unlock()
	return rd.backoffDuration()
}

// backoffDuration computes the backoff without locking. Must be called with
// rd.mu held.
func (rd *RaceDetector) backoffDuration() time.Duration {
	if rd.consecutiveLosses == 0 {
		return 0
	}

	// Exponential backoff: baseBackoff * 2^consecutiveLosses
	backoff := rd.baseBackoff
	for i := 0; i < rd.consecutiveLosses; i++ {
		backoff *= 2
		if backoff > rd.maxBackoff {
			backoff = rd.maxBackoff
			break
		}
	}

	// Add jitter: ±25% of base backoff
	jitterRange := float64(rd.baseBackoff) * 0.5 // total range is 50% of base
	jitter := time.Duration(rand.Float64()*jitterRange - jitterRange/2)
	backoff += jitter

	// Clamp to maxBackoff
	if backoff > rd.maxBackoff {
		backoff = rd.maxBackoff
	}
	if backoff < 0 {
		backoff = rd.baseBackoff
	}

	return backoff
}

// ShouldEnterFollowerMode returns true if too many consecutive losses suggest
// this node should stop trying to advance and just follow.
func (rd *RaceDetector) ShouldEnterFollowerMode() bool {
	rd.mu.Lock()
	defer rd.mu.Unlock()
	return rd.consecutiveLosses >= rd.maxConsecutiveLosses
}

// ResetLossCounter resets the consecutive loss counter (called when we win).
func (rd *RaceDetector) ResetLossCounter() {
	rd.mu.Lock()
	defer rd.mu.Unlock()
	rd.consecutiveLosses = 0
}

// ConsecutiveLosses returns the current consecutive loss count.
func (rd *RaceDetector) ConsecutiveLosses() int {
	rd.mu.Lock()
	defer rd.mu.Unlock()
	return rd.consecutiveLosses
}

// OnRaceLost sets the callback for race loss events.
func (rd *RaceDetector) OnRaceLost(fn func(*CovenantAdvanceEvent)) {
	rd.mu.Lock()
	defer rd.mu.Unlock()
	rd.onRaceLost = fn
}

// OnRaceWon sets the callback for race win events.
func (rd *RaceDetector) OnRaceWon(fn func(*CovenantAdvanceEvent)) {
	rd.mu.Lock()
	defer rd.mu.Unlock()
	rd.onRaceWon = fn
}
