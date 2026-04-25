package overlay

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/icellan/bsvm/pkg/metrics"
	"github.com/icellan/bsvm/pkg/tracing"
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
//
// Observability:
//   - Prometheus metrics via pkg/metrics (queue depth gauge + counters
//     for accepted / rejected / flushed).
//   - OpenTelemetry spans on Flush (where the batch is actually handed
//     off to ProcessBatch).
type Batcher struct {
	node         *OverlayNode
	pending      []*types.Transaction
	mu           sync.Mutex
	maxBatchSize int
	flushDelay   time.Duration
	recentHashes map[types.Hash]struct{}
	tracer       trace.Tracer

	// flushTimer fires after flushDelay to flush a non-empty pending
	// list. It is nil when there are no pending transactions.
	flushTimer *time.Timer
	stopped    bool
	paused     bool // governance freeze pauses batch processing

	// ---- Atomic counters (drive both Prometheus and Stats()) ----
	acceptedTotal   atomic.Uint64
	duplicatesTotal atomic.Uint64
	pausedRejected  atomic.Uint64
	depthRejected   atomic.Uint64
	flushesTotal    atomic.Uint64
	flushedTxsTotal atomic.Uint64

	// ---- Prometheus instruments (nil when registry is absent) ----
	promPending          prometheus.Gauge
	promAcceptedTotal    prometheus.Counter
	promDuplicatesTotal  prometheus.Counter
	promPausedRejected   prometheus.Counter
	promDepthRejected    prometheus.Counter
	promFlushesTotal     prometheus.Counter
	promFlushedTxsTotal  prometheus.Counter
	promFlushLatencySecs prometheus.Observer
}

// BatcherStats is a point-in-time snapshot of batcher activity used by
// the RPC layer.
type BatcherStats struct {
	Pending        int
	Paused         bool
	MaxBatchSize   int
	FlushDelayMs   int64
	Accepted       uint64
	Duplicates     uint64
	PausedRejected uint64
	DepthRejected  uint64
	Flushes        uint64
	FlushedTxs     uint64
}

// NewBatcher creates a new batcher for the given overlay node. The
// maxBatchSize and flushDelay parameters control when batches are
// flushed. If maxBatchSize <= 0, it defaults to 128. If flushDelay
// <= 0, it defaults to 2 seconds.
//
// Metrics / tracing are disabled (no-op) when called this way. Use
// NewBatcherWithObservability to wire Prometheus.
func NewBatcher(node *OverlayNode, maxBatchSize int, flushDelay time.Duration) *Batcher {
	return NewBatcherWithObservability(node, maxBatchSize, flushDelay, nil)
}

// NewBatcherWithObservability constructs a Batcher and registers its
// Prometheus collectors against the supplied registry. When registry is
// nil, no Prometheus collectors are created (tests and zero-config
// runs). Tracing always uses the global OTel provider.
func NewBatcherWithObservability(
	node *OverlayNode,
	maxBatchSize int,
	flushDelay time.Duration,
	registry *metrics.Registry,
) *Batcher {
	if maxBatchSize <= 0 {
		maxBatchSize = 128
	}
	if flushDelay <= 0 {
		flushDelay = 2 * time.Second
	}
	b := &Batcher{
		node:         node,
		maxBatchSize: maxBatchSize,
		flushDelay:   flushDelay,
		recentHashes: make(map[types.Hash]struct{}),
		tracer:       tracing.Tracer("bsvm/batcher"),
	}
	if registry != nil {
		b.promPending = registry.Gauge(
			"bsvm_batcher_pending",
			"Transactions accumulated in the current pending batch.",
		)
		b.promAcceptedTotal = registry.Counter(
			"bsvm_batcher_accepted_total",
			"Cumulative count of transactions accepted into a pending batch.",
		)
		b.promDuplicatesTotal = registry.Counter(
			"bsvm_batcher_duplicates_total",
			"Cumulative count of transactions rejected as duplicates.",
		)
		b.promPausedRejected = registry.Counter(
			"bsvm_batcher_rejected_paused_total",
			"Cumulative count of transactions rejected because the batcher is paused (governance freeze).",
		)
		b.promDepthRejected = registry.Counter(
			"bsvm_batcher_rejected_depth_total",
			"Cumulative count of transactions rejected because the speculative depth limit was reached.",
		)
		b.promFlushesTotal = registry.Counter(
			"bsvm_batcher_flushes_total",
			"Cumulative count of batch flushes (size-triggered or timer-triggered).",
		)
		b.promFlushedTxsTotal = registry.Counter(
			"bsvm_batcher_flushed_transactions_total",
			"Cumulative count of transactions that have been passed to ProcessBatch.",
		)
		b.promFlushLatencySecs = registry.Histogram(
			"bsvm_batcher_flush_duration_seconds",
			"Wall-clock time ProcessBatch takes to accept a flushed batch.",
			prometheus.DefBuckets,
		)
	}
	return b
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
		b.pausedRejected.Add(1)
		if b.promPausedRejected != nil {
			b.promPausedRejected.Inc()
		}
		b.mu.Unlock()
		return fmt.Errorf("batcher is paused (governance freeze)")
	}

	txHash := tx.Hash()

	// Deduplication: reject transactions already seen recently.
	if _, exists := b.recentHashes[txHash]; exists {
		b.duplicatesTotal.Add(1)
		if b.promDuplicatesTotal != nil {
			b.promDuplicatesTotal.Inc()
		}
		b.mu.Unlock()
		return fmt.Errorf("duplicate transaction %s", txHash.Hex())
	}

	// Check speculative depth limit.
	if b.node.txCache.SpeculativeDepth() >= b.node.config.MaxSpeculativeDepth {
		b.depthRejected.Add(1)
		if b.promDepthRejected != nil {
			b.promDepthRejected.Inc()
		}
		b.mu.Unlock()
		return fmt.Errorf("speculative depth limit reached (%d), try again later",
			b.node.config.MaxSpeculativeDepth)
	}

	// Track the hash for deduplication.
	b.recentHashes[txHash] = struct{}{}
	b.pruneRecentHashes()

	b.pending = append(b.pending, tx)
	b.acceptedTotal.Add(1)
	if b.promAcceptedTotal != nil {
		b.promAcceptedTotal.Inc()
	}
	if b.promPending != nil {
		b.promPending.Set(float64(len(b.pending)))
	}

	// If batch is full, flush immediately.
	if len(b.pending) >= b.maxBatchSize {
		b.stopFlushTimer()
		txs := b.pending
		b.pending = nil
		if b.promPending != nil {
			b.promPending.Set(0)
		}
		b.mu.Unlock()
		return b.processFlushed(context.Background(), "size", txs)
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
	if b.promPending != nil {
		b.promPending.Set(0)
	}
	b.mu.Unlock()

	return b.processFlushed(context.Background(), "timer", txs)
}

// processFlushed hands a batch of transactions to ProcessBatch with
// tracing and metric observation wrapped around the call. The trigger
// argument identifies what caused the flush ("size" or "timer") and
// becomes a span attribute.
func (b *Batcher) processFlushed(ctx context.Context, trigger string, txs []*types.Transaction) error {
	ctx, span := b.tracer.Start(ctx, "batcher.Flush",
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithAttributes(
			attribute.String("batcher.trigger", trigger),
			attribute.Int("batcher.batch_size", len(txs)),
		),
	)
	_ = ctx // ProcessBatch does not yet take a context; carry the span
	// anchor via the global provider.

	start := time.Now()
	_, err := b.node.ProcessBatch(txs)
	elapsed := time.Since(start)

	b.flushesTotal.Add(1)
	b.flushedTxsTotal.Add(uint64(len(txs)))
	if b.promFlushesTotal != nil {
		b.promFlushesTotal.Inc()
	}
	if b.promFlushedTxsTotal != nil {
		b.promFlushedTxsTotal.Add(float64(len(txs)))
	}
	if b.promFlushLatencySecs != nil {
		b.promFlushLatencySecs.Observe(elapsed.Seconds())
	}

	if err != nil {
		span.SetStatus(codes.Error, "process batch failed")
		span.RecordError(err)
	} else {
		span.SetStatus(codes.Ok, "")
		span.SetAttributes(attribute.Int64("batcher.flush_ms", elapsed.Milliseconds()))
	}
	span.End()

	return err
}

// PendingCount returns the number of transactions waiting to be batched.
func (b *Batcher) PendingCount() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.pending)
}

// Stats returns a point-in-time snapshot of batcher counters, suitable
// for the RPC layer. Read-only; does not take the batcher lock for
// counter fields (atomics), so safe under contention.
func (b *Batcher) Stats() BatcherStats {
	b.mu.Lock()
	pending := len(b.pending)
	paused := b.paused
	b.mu.Unlock()
	return BatcherStats{
		Pending:        pending,
		Paused:         paused,
		MaxBatchSize:   b.maxBatchSize,
		FlushDelayMs:   b.flushDelay.Milliseconds(),
		Accepted:       b.acceptedTotal.Load(),
		Duplicates:     b.duplicatesTotal.Load(),
		PausedRejected: b.pausedRejected.Load(),
		DepthRejected:  b.depthRejected.Load(),
		Flushes:        b.flushesTotal.Load(),
		FlushedTxs:     b.flushedTxsTotal.Load(),
	}
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
