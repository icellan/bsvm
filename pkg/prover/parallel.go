package prover

import (
	"context"
	"fmt"
)

// ParallelProver coordinates parallel proof generation for multiple batches.
// It manages a pool of worker goroutines that invoke SP1Prover.Prove(),
// using a semaphore channel to limit concurrency to the configured number
// of workers.
type ParallelProver struct {
	prover  *SP1Prover
	workers int
	sem     chan struct{}
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
func NewParallelProver(prover *SP1Prover, workers int) *ParallelProver {
	if workers < 1 {
		workers = 1
	}
	return &ParallelProver{
		prover:  prover,
		workers: workers,
		sem:     make(chan struct{}, workers),
	}
}

// ProveBatch submits a batch for proving and returns a channel that will
// receive exactly one ProveResult when the operation completes. The
// proving operation runs in a separate goroutine, limited by the worker
// semaphore. If the context is cancelled before a worker slot becomes
// available, the result channel receives a context error.
func (pp *ParallelProver) ProveBatch(ctx context.Context, input *ProveInput) <-chan ProveResult {
	ch := make(chan ProveResult, 1)

	go func() {
		defer close(ch)

		// Acquire a worker slot.
		select {
		case pp.sem <- struct{}{}:
			// Got a slot; release it when done.
			defer func() { <-pp.sem }()
		case <-ctx.Done():
			ch <- ProveResult{Err: fmt.Errorf("context cancelled waiting for worker: %w", ctx.Err())}
			return
		}

		// Check context again after acquiring the slot.
		if ctx.Err() != nil {
			ch <- ProveResult{Err: fmt.Errorf("context cancelled before proving: %w", ctx.Err())}
			return
		}

		output, err := pp.prover.Prove(ctx, input)
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
