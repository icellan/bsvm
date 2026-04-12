package prover

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/icellan/bsvm/pkg/types"
)

func TestPipelinedProver_SingleRequest(t *testing.T) {
	base := NewSP1Prover(DefaultConfig())
	pp := NewPipelinedProver(base)

	input := &ProveInput{
		PreStateRoot: types.Hash{0x01},
		Transactions: [][]byte{{0xAA}},
	}

	ch := pp.Prove(context.Background(), input)
	result := <-ch

	if result.Err != nil {
		t.Fatalf("expected no error, got: %v", result.Err)
	}
	if result.Output == nil {
		t.Fatal("expected non-nil output")
	}
	if len(result.Output.Proof) == 0 {
		t.Error("expected non-empty proof bytes")
	}
}

func TestPipelinedProver_PipelinedRequests(t *testing.T) {
	base := NewSP1Prover(DefaultConfig())
	pp := NewPipelinedProver(base)

	// Submit two requests while the prover is busy.
	input1 := &ProveInput{
		PreStateRoot: types.Hash{0x01},
		Transactions: [][]byte{{0xAA}},
	}
	input2 := &ProveInput{
		PreStateRoot: types.Hash{0x02},
		Transactions: [][]byte{{0xBB}},
	}

	ch1 := pp.Prove(context.Background(), input1)
	ch2 := pp.Prove(context.Background(), input2)

	// Both should eventually complete.
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		result := <-ch1
		// First request either completes normally or is superseded.
		_ = result
	}()

	go func() {
		defer wg.Done()
		result := <-ch2
		// The second request may be the one that actually runs or may
		// be superseded if a third came in. In this test it should run.
		_ = result
	}()

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Success
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for pipelined prove results")
	}
}

func TestPipelinedProver_PendingSuperseded(t *testing.T) {
	base := NewSP1Prover(DefaultConfig())
	pp := NewPipelinedProver(base)

	// Start a prove that will run.
	input1 := &ProveInput{
		PreStateRoot: types.Hash{0x01},
		Transactions: [][]byte{{0xAA}},
	}
	ch1 := pp.Prove(context.Background(), input1)

	// Submit two more while the first is (likely) still running.
	// The first pending should be superseded by the second.
	input2 := &ProveInput{
		PreStateRoot: types.Hash{0x02},
		Transactions: [][]byte{{0xBB}},
	}
	input3 := &ProveInput{
		PreStateRoot: types.Hash{0x03},
		Transactions: [][]byte{{0xCC}},
	}

	ch2 := pp.Prove(context.Background(), input2)
	ch3 := pp.Prove(context.Background(), input3)

	// Collect all results.
	r1 := <-ch1
	r2 := <-ch2
	r3 := <-ch3

	// ch1 should succeed (it was the actively running proof).
	if r1.Err != nil {
		t.Errorf("first request should succeed, got: %v", r1.Err)
	}

	// ch2 should have been cancelled (superseded by ch3).
	if r2.Err == nil {
		t.Error("second request should have been superseded (cancelled)")
	}

	// ch3 should succeed (it replaced ch2 as pending and then ran).
	if r3.Err != nil {
		t.Errorf("third request should succeed, got: %v", r3.Err)
	}
}
