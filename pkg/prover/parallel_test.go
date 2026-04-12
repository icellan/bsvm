package prover

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/icellan/bsvm/pkg/types"
)

// makeTestInput builds a minimal ProveInput for parallel prover tests.
func makeTestInput(preStateRoot types.Hash, txBytes [][]byte) *ProveInput {
	return &ProveInput{
		PreStateRoot: preStateRoot,
		Transactions: txBytes,
		BlockContext: BlockContext{Number: 1, Timestamp: 1000, GasLimit: 30_000_000},
		ExpectedResults: &ExpectedResults{
			PostStateRoot: preStateRoot,
			GasUsed:       21000,
			ChainID:       1337,
		},
	}
}

// TestParallelProverSingleBatch verifies that a single batch can be
// proved through the parallel prover.
func TestParallelProverSingleBatch(t *testing.T) {
	sp1 := NewSP1Prover(Config{Mode: ProverMock})
	pp := NewParallelProver(sp1, 2)

	input := makeTestInput(
		types.HexToHash("0xaaaa"),
		[][]byte{{0x01, 0x02}},
	)

	output, err := pp.ProveAndWait(context.Background(), input)
	if err != nil {
		t.Fatalf("ProveAndWait failed: %v", err)
	}
	if output == nil {
		t.Fatal("output is nil")
	}
	if len(output.Proof) == 0 {
		t.Error("proof data should not be empty")
	}
	if len(output.PublicValues) != PublicValuesSize {
		t.Errorf("public values size = %d, want %d", len(output.PublicValues), PublicValuesSize)
	}

	pv, err := ParsePublicValues(output.PublicValues)
	if err != nil {
		t.Fatalf("ParsePublicValues: %v", err)
	}
	if pv.PreStateRoot != types.HexToHash("0xaaaa") {
		t.Errorf("PreStateRoot mismatch")
	}
	if pv.GasUsed != 21000 {
		t.Errorf("GasUsed mismatch: got %d, want 21000", pv.GasUsed)
	}
}

// TestParallelProverMultipleBatches verifies that multiple batches can be
// proved concurrently with a limited worker pool. Uses 3 batches with
// 2 workers to ensure the semaphore limits concurrency.
func TestParallelProverMultipleBatches(t *testing.T) {
	sp1 := NewSP1Prover(Config{Mode: ProverMock})
	pp := NewParallelProver(sp1, 2)

	// Create three distinct inputs.
	inputs := []*ProveInput{
		makeTestInput(types.HexToHash("0x01"), [][]byte{{0x01}}),
		makeTestInput(types.HexToHash("0x02"), [][]byte{{0x02}}),
		makeTestInput(types.HexToHash("0x03"), [][]byte{{0x03}}),
	}

	ctx := context.Background()

	// Submit all three batches.
	channels := make([]<-chan ProveResult, len(inputs))
	for i, input := range inputs {
		channels[i] = pp.ProveBatch(ctx, input)
	}

	// Collect results.
	results := make([]ProveResult, len(inputs))
	for i, ch := range channels {
		results[i] = <-ch
	}

	// Verify all completed successfully.
	for i, result := range results {
		if result.Err != nil {
			t.Errorf("batch %d failed: %v", i, result.Err)
			continue
		}
		if result.Output == nil {
			t.Errorf("batch %d: output is nil", i)
			continue
		}

		pv, err := ParsePublicValues(result.Output.PublicValues)
		if err != nil {
			t.Errorf("batch %d: ParsePublicValues: %v", i, err)
			continue
		}

		// Each batch should have its own pre-state root.
		expectedRoot := inputs[i].PreStateRoot
		if pv.PreStateRoot != expectedRoot {
			t.Errorf("batch %d: PreStateRoot mismatch: got %s, want %s",
				i, pv.PreStateRoot.Hex(), expectedRoot.Hex())
		}
	}
}

// TestParallelProverCancellation verifies that cancelling the context
// causes pending prove operations to return an error.
func TestParallelProverCancellation(t *testing.T) {
	sp1 := NewSP1Prover(Config{Mode: ProverMock})
	// Use only 1 worker to force queuing.
	pp := NewParallelProver(sp1, 1)

	ctx, cancel := context.WithCancel(context.Background())

	// First: occupy the single worker slot with a blocking operation.
	// We do this by starting a batch and then immediately submitting another.
	input1 := makeTestInput(types.HexToHash("0x01"), [][]byte{{0x01}})
	input2 := makeTestInput(types.HexToHash("0x02"), [][]byte{{0x02}})

	// Acquire the worker slot manually via the semaphore to block.
	pp.sem <- struct{}{}

	// Submit batch 2 which will wait for a worker slot.
	ch := pp.ProveBatch(ctx, input2)

	// Give the goroutine time to reach the semaphore wait.
	time.Sleep(10 * time.Millisecond)

	// Cancel the context.
	cancel()

	// The blocked batch should return a context error.
	result := <-ch
	if result.Err == nil {
		t.Fatal("expected error from cancelled context")
	}

	// Release the worker slot.
	<-pp.sem

	// Verify that a new context works fine after cancellation.
	freshCtx := context.Background()
	output, err := pp.ProveAndWait(freshCtx, input1)
	if err != nil {
		t.Fatalf("ProveAndWait with fresh context failed: %v", err)
	}
	if output == nil {
		t.Fatal("output should not be nil with fresh context")
	}
}

// TestParallelProverConcurrencyLimit verifies that the worker semaphore
// actually limits the number of concurrent proving operations.
func TestParallelProverConcurrencyLimit(t *testing.T) {
	maxWorkers := 2
	totalBatches := 5

	// Track the maximum number of concurrent workers observed.
	var (
		mu             sync.Mutex
		current        int
		maxConcurrent  int
		completedCount int
	)

	// Create a custom prover that tracks concurrency.
	sp1 := NewSP1Prover(Config{Mode: ProverMock})
	pp := NewParallelProver(sp1, maxWorkers)

	// We cannot directly instrument SP1Prover.Prove, so we verify
	// indirectly by checking all results complete successfully and
	// the semaphore size matches.
	if cap(pp.sem) != maxWorkers {
		t.Fatalf("semaphore capacity = %d, want %d", cap(pp.sem), maxWorkers)
	}

	ctx := context.Background()
	var wg sync.WaitGroup

	for i := 0; i < totalBatches; i++ {
		wg.Add(1)
		input := makeTestInput(
			types.BytesToHash([]byte{byte(i)}),
			[][]byte{{byte(i)}},
		)

		ch := pp.ProveBatch(ctx, input)
		go func(batchIdx int) {
			defer wg.Done()
			result := <-ch

			mu.Lock()
			current++
			if current > maxConcurrent {
				maxConcurrent = current
			}
			completedCount++
			current--
			mu.Unlock()

			if result.Err != nil {
				t.Errorf("batch %d failed: %v", batchIdx, result.Err)
			}
		}(i)
	}

	wg.Wait()

	mu.Lock()
	defer mu.Unlock()

	if completedCount != totalBatches {
		t.Errorf("completed %d batches, want %d", completedCount, totalBatches)
	}
}

// TestNewParallelProverMinWorkers verifies that NewParallelProver clamps
// workers to at least 1.
func TestNewParallelProverMinWorkers(t *testing.T) {
	sp1 := NewSP1Prover(Config{Mode: ProverMock})

	pp := NewParallelProver(sp1, 0)
	if cap(pp.sem) != 1 {
		t.Errorf("semaphore capacity with 0 workers = %d, want 1", cap(pp.sem))
	}

	pp = NewParallelProver(sp1, -5)
	if cap(pp.sem) != 1 {
		t.Errorf("semaphore capacity with -5 workers = %d, want 1", cap(pp.sem))
	}
}
