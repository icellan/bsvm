package prover

import (
	"context"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/icellan/bsvm/pkg/metrics"
	"github.com/icellan/bsvm/pkg/tracing"
)

// ParallelProver coordinates parallel proof generation for multiple batches.
// It manages a pool of worker goroutines that invoke SP1Prover.Prove(),
// using a semaphore channel to limit concurrency to the configured number
// of workers.
//
// Observability:
//   - Prometheus metrics exposed via pkg/metrics (scraped at /metrics).
//   - OpenTelemetry spans emitted for each ProveBatch call, using the
//     global TracerProvider configured by pkg/tracing.
//   - Cached atomic snapshots feed the Metrics() method used by RPC
//     handlers; counters stay consistent between the scrape endpoint
//     and the JSON response.
type ParallelProver struct {
	prover  *SP1Prover
	workers int
	sem     chan struct{}
	tracer  trace.Tracer

	// ---- Cached atomic counters (drive both Prometheus and RPC snapshots) ----
	queueWaiting atomic.Int64 // goroutines blocked awaiting a worker slot
	inFlight     atomic.Int64
	started      atomic.Uint64
	succeeded    atomic.Uint64
	failed       atomic.Uint64
	totalProveMs atomic.Uint64 // cumulative across succeeded proofs

	// ---- Prometheus instruments (nil when registry is absent) ----
	promStartedTotal   prometheus.Counter
	promSucceededTotal prometheus.Counter
	promFailedTotal    prometheus.Counter
	promInFlight       prometheus.Gauge
	promQueueDepth     prometheus.Gauge
	promWorkers        prometheus.Gauge
	promDurationSecs   prometheus.Observer
}

// Metrics is a point-in-time snapshot of prover activity used by
// `bsv_provingStatus` and the admin RPC. Counters are cumulative since
// the node started; operators reading them over time can derive rates.
type Metrics struct {
	// Mode is the prover backend ("local", "network", "mock").
	Mode string
	// Workers is the maximum number of concurrent provers.
	Workers int
	// InFlight is the current number of proofs being generated.
	InFlight int
	// QueueDepth is the number of callers blocked waiting for a worker.
	QueueDepth int
	// ProofsStarted is the cumulative count of ProveBatch submissions.
	ProofsStarted uint64
	// ProofsSucceeded is the cumulative count of successful proofs.
	ProofsSucceeded uint64
	// ProofsFailed is the cumulative count of failed proofs.
	ProofsFailed uint64
	// AvgProveTimeMs is the mean wall-clock proof time over successful
	// proofs, in milliseconds. Zero if no successes yet.
	AvgProveTimeMs uint64
}

// ProveResult holds the outcome of an asynchronous proving operation.
type ProveResult struct {
	// Output contains the proof and public values on success.
	Output *ProveOutput
	// Err contains any error that occurred during proving.
	Err error
}

// NewParallelProver creates a new ParallelProver that will run up to
// the specified number of proving operations concurrently. The workers
// parameter must be at least 1.
//
// Metrics / tracing are disabled (no-op) when called this way — use
// NewParallelProverWithObservability to wire Prometheus + OTel.
func NewParallelProver(prover *SP1Prover, workers int) *ParallelProver {
	return NewParallelProverWithObservability(prover, workers, nil)
}

// NewParallelProverWithObservability creates a ParallelProver and
// registers Prometheus metrics against the supplied registry. When
// registry is nil, Prometheus collectors are skipped (useful for tests
// and the zero-config single-binary case). Tracing always uses the
// global OTel TracerProvider set by pkg/tracing.Setup.
func NewParallelProverWithObservability(
	prover *SP1Prover,
	workers int,
	registry *metrics.Registry,
) *ParallelProver {
	if workers < 1 {
		workers = 1
	}
	pp := &ParallelProver{
		prover:  prover,
		workers: workers,
		sem:     make(chan struct{}, workers),
		tracer:  tracing.Tracer("bsvm/prover"),
	}
	if registry != nil {
		pp.promStartedTotal = registry.Counter(
			"bsvm_prover_proofs_started_total",
			"Cumulative count of ProveBatch submissions.",
		)
		pp.promSucceededTotal = registry.Counter(
			"bsvm_prover_proofs_succeeded_total",
			"Cumulative count of proofs that returned successfully.",
		)
		pp.promFailedTotal = registry.Counter(
			"bsvm_prover_proofs_failed_total",
			"Cumulative count of proofs that returned with an error.",
		)
		pp.promInFlight = registry.Gauge(
			"bsvm_prover_in_flight",
			"Proofs currently being generated.",
		)
		pp.promQueueDepth = registry.Gauge(
			"bsvm_prover_queue_depth",
			"Callers blocked waiting for a free worker.",
		)
		pp.promWorkers = registry.Gauge(
			"bsvm_prover_workers",
			"Maximum concurrent provers.",
		)
		pp.promWorkers.Set(float64(workers))
		// 100ms .. 16m covers mock (sub-second) through CPU prove
		// (5-60s) and GPU prove (60s-16m) without wasting buckets.
		buckets := []float64{0.1, 0.25, 0.5, 1, 2, 5, 10, 30, 60, 120, 300, 600, 960}
		pp.promDurationSecs = registry.Histogram(
			"bsvm_prover_prove_duration_seconds",
			"Wall-clock time for each successful prove, in seconds.",
			buckets,
		)
	}
	return pp
}

// ProveBatch submits a batch for proving and returns a channel that will
// receive exactly one ProveResult when the operation completes. The
// proving operation runs in a separate goroutine, limited by the worker
// semaphore. If the context is cancelled before a worker slot becomes
// available, the result channel receives a context error.
func (pp *ParallelProver) ProveBatch(ctx context.Context, input *ProveInput) <-chan ProveResult {
	ch := make(chan ProveResult, 1)

	ctx, span := pp.tracer.Start(ctx, "prover.ProveBatch",
		trace.WithSpanKind(trace.SpanKindInternal),
	)
	pp.started.Add(1)
	if pp.promStartedTotal != nil {
		pp.promStartedTotal.Inc()
	}
	pp.queueWaiting.Add(1)
	if pp.promQueueDepth != nil {
		pp.promQueueDepth.Inc()
	}

	go func() {
		defer close(ch)

		// Acquire a worker slot.
		select {
		case pp.sem <- struct{}{}:
			// Got a slot; release it when done.
			defer func() { <-pp.sem }()
		case <-ctx.Done():
			pp.queueWaiting.Add(-1)
			if pp.promQueueDepth != nil {
				pp.promQueueDepth.Dec()
			}
			pp.failed.Add(1)
			if pp.promFailedTotal != nil {
				pp.promFailedTotal.Inc()
			}
			span.SetStatus(codes.Error, "context cancelled waiting for worker")
			span.RecordError(ctx.Err())
			span.End()
			ch <- ProveResult{Err: fmt.Errorf("context cancelled waiting for worker: %w", ctx.Err())}
			return
		}

		pp.queueWaiting.Add(-1)
		if pp.promQueueDepth != nil {
			pp.promQueueDepth.Dec()
		}
		pp.inFlight.Add(1)
		if pp.promInFlight != nil {
			pp.promInFlight.Inc()
		}

		// Check context again after acquiring the slot.
		if ctx.Err() != nil {
			pp.inFlight.Add(-1)
			if pp.promInFlight != nil {
				pp.promInFlight.Dec()
			}
			pp.failed.Add(1)
			if pp.promFailedTotal != nil {
				pp.promFailedTotal.Inc()
			}
			span.SetStatus(codes.Error, "context cancelled before proving")
			span.RecordError(ctx.Err())
			span.End()
			ch <- ProveResult{Err: fmt.Errorf("context cancelled before proving: %w", ctx.Err())}
			return
		}

		start := time.Now()
		output, err := pp.prover.Prove(ctx, input)
		elapsed := time.Since(start)

		pp.inFlight.Add(-1)
		if pp.promInFlight != nil {
			pp.promInFlight.Dec()
		}

		if err != nil {
			pp.failed.Add(1)
			if pp.promFailedTotal != nil {
				pp.promFailedTotal.Inc()
			}
			span.SetStatus(codes.Error, "prove failed")
			span.RecordError(err)
		} else {
			pp.succeeded.Add(1)
			pp.totalProveMs.Add(uint64(elapsed.Milliseconds()))
			if pp.promSucceededTotal != nil {
				pp.promSucceededTotal.Inc()
			}
			if pp.promDurationSecs != nil {
				pp.promDurationSecs.Observe(elapsed.Seconds())
			}
			span.SetAttributes(attribute.Int64("prove.duration_ms", elapsed.Milliseconds()))
		}
		span.End()

		ch <- ProveResult{Output: output, Err: err}
	}()

	return ch
}

// ProveAndWait proves a batch synchronously, blocking until the proof is
// complete or the context is cancelled. This is a convenience wrapper
// around ProveBatch for cases where the caller does not need asynchronous
// operation.
func (pp *ParallelProver) ProveAndWait(ctx context.Context, input *ProveInput) (*ProveOutput, error) {
	ch := pp.ProveBatch(ctx, input)
	result := <-ch
	return result.Output, result.Err
}

// Metrics returns a point-in-time snapshot of prover activity. Safe to
// call concurrently from any goroutine.
func (pp *ParallelProver) Metrics() Metrics {
	succeeded := pp.succeeded.Load()
	var avgMs uint64
	if succeeded > 0 {
		avgMs = pp.totalProveMs.Load() / succeeded
	}
	mode := "unknown"
	if pp.prover != nil {
		mode = pp.prover.Mode().String()
	}
	return Metrics{
		Mode:            mode,
		Workers:         pp.workers,
		InFlight:        int(pp.inFlight.Load()),
		QueueDepth:      int(pp.queueWaiting.Load()),
		ProofsStarted:   pp.started.Load(),
		ProofsSucceeded: succeeded,
		ProofsFailed:    pp.failed.Load(),
		AvgProveTimeMs:  avgMs,
	}
}
