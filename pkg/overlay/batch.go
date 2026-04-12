package overlay

import (
	"fmt"
	"sync"
	"time"

	"github.com/icellan/bsvm/pkg/types"
)

// maxRecentHashes is the maximum number of recent transaction hashes
// to track for deduplication.
const maxRecentHashes = 10_000

// Batcher accumulates incoming EVM transactions and flushes them as
// batches to ProcessBatch. It enforces deduplication and respects both
// size limits and time-based flush delays.
//
// The batcher does NOT run a timer that produces empty blocks. It only
// flushes when there are pending transactions AND either the batch is
// full or the flush delay has expired.
type Batcher struct {
	node         *OverlayNode
	pending      []*types.Transaction
	mu           sync.Mutex
	maxBatchSize int
	flushDelay   time.Duration
	recentHashes map[types.Hash]struct{}

	// flushTimer fires after flushDelay to flush a non-empty pending
	// list. It is nil when there are no pending transactions.
	flushTimer *time.Timer
	stopped    bool
	paused     bool // governance freeze pauses batch processing
}

// NewBatcher creates a new batcher for the given overlay node. The
// maxBatchSize and flushDelay parameters control when batches are
// flushed. If maxBatchSize <= 0, it defaults to 128. If flushDelay
// <= 0, it defaults to 2 seconds.
func NewBatcher(node *OverlayNode, maxBatchSize int, flushDelay time.Duration) *Batcher {
	if maxBatchSize <= 0 {
		maxBatchSize = 128
	}
	if flushDelay <= 0 {
		flushDelay = 2 * time.Second
	}
	return &Batcher{
		node:         node,
		maxBatchSize: maxBatchSize,
		flushDelay:   flushDelay,
		recentHashes: make(map[types.Hash]struct{}),
	}
}

// Add adds a transaction to the pending batch. It deduplicates against
// recently seen transaction hashes and returns an error if the
// transaction was already seen. If the pending batch reaches
// maxBatchSize, it triggers an immediate flush.
func (b *Batcher) Add(tx *types.Transaction) error {
	b.mu.Lock()

	if b.stopped {
		b.mu.Unlock()
		return fmt.Errorf("batcher is stopped")
	}

	if b.paused {
		b.mu.Unlock()
		return fmt.Errorf("batcher is paused (governance freeze)")
	}

	txHash := tx.Hash()

	// Deduplication: reject transactions already seen recently.
	if _, exists := b.recentHashes[txHash]; exists {
		b.mu.Unlock()
		return fmt.Errorf("duplicate transaction %s", txHash.Hex())
	}

	// Check speculative depth limit.
	if b.node.txCache.SpeculativeDepth() >= b.node.config.MaxSpeculativeDepth {
		b.mu.Unlock()
		return fmt.Errorf("speculative depth limit reached (%d), try again later",
			b.node.config.MaxSpeculativeDepth)
	}

	// Track the hash for deduplication.
	b.recentHashes[txHash] = struct{}{}
	b.pruneRecentHashes()

	b.pending = append(b.pending, tx)

	// If batch is full, flush immediately.
	if len(b.pending) >= b.maxBatchSize {
		b.stopFlushTimer()
		txs := b.pending
		b.pending = nil
		b.mu.Unlock()
		_, err := b.node.ProcessBatch(txs)
		return err
	}

	// Start the flush timer if this is the first pending tx.
	if len(b.pending) == 1 {
		b.startFlushTimer()
	}

	b.mu.Unlock()
	return nil
}

// Flush flushes all pending transactions as a batch to ProcessBatch.
// Does nothing if there are no pending transactions.
func (b *Batcher) Flush() error {
	b.mu.Lock()

	if len(b.pending) == 0 {
		b.mu.Unlock()
		return nil
	}

	// Stop any pending flush timer.
	b.stopFlushTimer()

	// Take ownership of the pending transactions.
	txs := b.pending
	b.pending = nil
	b.mu.Unlock()

	// Call ProcessBatch outside any batcher lock.
	_, err := b.node.ProcessBatch(txs)
	return err
}

// PendingCount returns the number of transactions waiting to be batched.
func (b *Batcher) PendingCount() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.pending)
}

// Pause pauses the batcher for governance freeze. New transactions are
// rejected while paused, but existing pending transactions are retained.
func (b *Batcher) Pause() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.paused = true
	b.stopFlushTimer()
}

// Resume unpauses the batcher after a governance unfreeze. If there are
// pending transactions, the flush timer is restarted.
func (b *Batcher) Resume() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.paused = false
	if len(b.pending) > 0 {
		b.startFlushTimer()
	}
}

// IsPaused returns whether the batcher is currently paused.
func (b *Batcher) IsPaused() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.paused
}

// Stop stops the batcher and cancels any pending flush timer.
func (b *Batcher) Stop() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.stopped = true
	b.stopFlushTimer()
}

// startFlushTimer starts the flush delay timer. Must be called with
// b.mu held.
func (b *Batcher) startFlushTimer() {
	b.stopFlushTimer()
	b.flushTimer = time.AfterFunc(b.flushDelay, func() {
		// Use the public Flush method which handles locking correctly.
		_ = b.Flush()
	})
}

// stopFlushTimer stops and clears the flush timer. Must be called with
// b.mu held.
func (b *Batcher) stopFlushTimer() {
	if b.flushTimer != nil {
		b.flushTimer.Stop()
		b.flushTimer = nil
	}
}

// pruneRecentHashes trims the recentHashes map when it exceeds the
// maximum size. It removes approximately half the entries. Must be
// called with b.mu held.
func (b *Batcher) pruneRecentHashes() {
	if len(b.recentHashes) <= maxRecentHashes {
		return
	}
	// Remove approximately half the entries. Since map iteration order
	// is random in Go, this effectively removes a random subset.
	count := 0
	target := len(b.recentHashes) / 2
	for h := range b.recentHashes {
		if count >= target {
			break
		}
		delete(b.recentHashes, h)
		count++
	}
}
