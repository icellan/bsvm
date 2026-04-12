package prover

import (
	"context"
	"sync"
)

// PipelinedProver overlaps batch N+1 execution with batch N proving. While
// the prover generates a STARK proof for one batch, the next batch can be
// enqueued. When the current proof completes, the next input is immediately
// sent to the prover with zero idle time.
//
// This implements the single-node internal pipelining described in spec 11:
// while the GPU proves batch N, the CPU executes incoming transactions and
// accumulates batch N+1.
type PipelinedProver struct {
	base *SP1Prover

	mu       sync.Mutex
	inflight bool              // true when the prover is currently proving
	pending  *pipelineRequest  // next request waiting for the prover to become free
}

// pipelineRequest is an enqueued prove request with its result channel.
type pipelineRequest struct {
	ctx   context.Context
	input *ProveInput
	ch    chan ProveResult
}

// NewPipelinedProver creates a new PipelinedProver wrapping the given base
// prover. Prove requests are serialised: at most one proof runs at a time,
// with the next request queued and started immediately on completion.
func NewPipelinedProver(base *SP1Prover) *PipelinedProver {
	return &PipelinedProver{
		base: base,
	}
}

// Prove enqueues a prove request and returns a channel that will receive
// exactly one ProveResult when the proof is complete. If a proof is
// currently in progress, the new request replaces any previously pending
// request (only the latest pending batch matters). If the prover is idle,
// proving starts immediately.
func (p *PipelinedProver) Prove(ctx context.Context, input *ProveInput) <-chan ProveResult {
	ch := make(chan ProveResult, 1)
	req := &pipelineRequest{
		ctx:   ctx,
		input: input,
		ch:    ch,
	}

	p.mu.Lock()
	if p.inflight {
		// Prover is busy: replace any pending request with this one.
		// If there was a previous pending request, signal it was superseded.
		if p.pending != nil {
			p.pending.ch <- ProveResult{
				Err: context.Canceled,
			}
		}
		p.pending = req
		p.mu.Unlock()
		return ch
	}

	// Prover is idle: start immediately.
	p.inflight = true
	p.mu.Unlock()
	go p.run(req)
	return ch
}

// run executes a prove request and then drains the pending queue.
func (p *PipelinedProver) run(req *pipelineRequest) {
	for req != nil {
		output, err := p.base.Prove(req.ctx, req.input)
		req.ch <- ProveResult{Output: output, Err: err}

		// Check for pending work.
		p.mu.Lock()
		next := p.pending
		p.pending = nil
		if next == nil {
			p.inflight = false
			p.mu.Unlock()
			return
		}
		p.mu.Unlock()

		req = next
	}
}
