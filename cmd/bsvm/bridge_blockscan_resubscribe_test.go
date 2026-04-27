package main

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/icellan/bsvm/pkg/bridge"
)

// fakeSubscriber is a hand-rolled blockScannerSubscriber the
// reconnect-loop tests drive directly. Each Subscribe call pulls the
// next channel off `episodes` (FIFO); when the slice is exhausted any
// further call returns errSubscribeExhausted so a stuck test fails
// loudly rather than blocking.
//
// The fake is intentionally NOT a chaintracks client — it lives at the
// blockScannerSubscriber seam so we can exercise the reconnect logic
// without coupling to the chaintracks ReorgEvent shape.
type fakeSubscriber struct {
	mu sync.Mutex

	// episodes drives Subscribe. Each entry is either a channel (the
	// subscribe call returns that channel and a nil error) or, when the
	// matching errors[i] is non-nil, the subscribe returns the error
	// instead and the channel slot is ignored.
	episodes []chan uint64
	errors   []error

	subscribeCalls int32
	getBlockCalls  int32

	// blocks maps height → tx slice. Missing entries return nil + nil.
	blocks map[uint64][]*bridge.BSVTransaction
}

var errSubscribeExhausted = errors.New("fakeSubscriber: episodes exhausted")

func (f *fakeSubscriber) SubscribeNewBlocks(_ context.Context) (<-chan uint64, error) {
	atomic.AddInt32(&f.subscribeCalls, 1)
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.episodes) == 0 {
		return nil, errSubscribeExhausted
	}
	ch := f.episodes[0]
	err := f.errors[0]
	f.episodes = f.episodes[1:]
	f.errors = f.errors[1:]
	if err != nil {
		return nil, err
	}
	return ch, nil
}

func (f *fakeSubscriber) GetBlockTransactions(height uint64) ([]*bridge.BSVTransaction, error) {
	atomic.AddInt32(&f.getBlockCalls, 1)
	f.mu.Lock()
	defer f.mu.Unlock()
	if txs, ok := f.blocks[height]; ok {
		return txs, nil
	}
	return nil, nil
}

// recordingProcessor implements blockScannerProcessor. ProcessBlock
// just records the height seen so the test can assert ordering.
type recordingProcessor struct {
	mu     sync.Mutex
	heights []uint64
}

func (r *recordingProcessor) ProcessBlock(height uint64, _ []*bridge.BSVTransaction) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.heights = append(r.heights, height)
}

func (r *recordingProcessor) snapshot() []uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]uint64, len(r.heights))
	copy(out, r.heights)
	return out
}

// withTinyBackoff swaps the package backoff knobs for nanosecond-scale
// values so the reconnect tests run in milliseconds. Restored via the
// returned closer.
func withTinyBackoff(t *testing.T) {
	t.Helper()
	prevInitial := scannerBackoffInitial
	prevMax := scannerBackoffMax
	prevWarn := scannerWarnAfter
	scannerBackoffInitial = time.Millisecond
	scannerBackoffMax = 5 * time.Millisecond
	scannerWarnAfter = 1
	t.Cleanup(func() {
		scannerBackoffInitial = prevInitial
		scannerBackoffMax = prevMax
		scannerWarnAfter = prevWarn
	})
}

// waitFor polls cond until it returns true or the deadline passes.
// Returns true on success; false on timeout. Callers should fail the
// test on a false return.
func waitFor(d time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(time.Millisecond)
	}
	return cond()
}

// TestBridgeScannerReconnectsAfterChannelClose verifies that when the
// chaintracks-side channel closes, the supervisor loop re-subscribes
// and continues processing further events.
func TestBridgeScannerReconnectsAfterChannelClose(t *testing.T) {
	withTinyBackoff(t)

	first := make(chan uint64, 4)
	second := make(chan uint64, 4)
	fake := &fakeSubscriber{
		episodes: []chan uint64{first, second},
		errors:   []error{nil, nil},
		blocks:   map[uint64][]*bridge.BSVTransaction{},
	}
	proc := &recordingProcessor{}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Synchronous first subscribe (mirrors what startBridgeBlockScanner
	// does for the public API).
	initial, err := fake.SubscribeNewBlocks(ctx)
	if err != nil {
		t.Fatalf("first subscribe: %v", err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		runBridgeScannerWithReconnect(ctx, fake, proc, initial, slog.Default())
	}()

	// Push three heights on the first connection, then close.
	first <- 100
	first <- 101
	first <- 102
	close(first)

	if !waitFor(time.Second, func() bool { return len(proc.snapshot()) == 3 }) {
		t.Fatalf("first epoch: expected 3 heights, got %v", proc.snapshot())
	}

	// Push three more on the post-reconnect channel. The supervisor
	// should already have re-subscribed (subscribeCalls >= 2).
	if !waitFor(time.Second, func() bool { return atomic.LoadInt32(&fake.subscribeCalls) >= 2 }) {
		t.Fatalf("expected re-subscribe; subscribeCalls = %d", atomic.LoadInt32(&fake.subscribeCalls))
	}
	second <- 200
	second <- 201
	second <- 202

	if !waitFor(time.Second, func() bool { return len(proc.snapshot()) == 6 }) {
		t.Fatalf("second epoch: expected 6 heights total, got %v", proc.snapshot())
	}

	cancel()
	<-done

	got := proc.snapshot()
	want := []uint64{100, 101, 102, 200, 201, 202}
	if len(got) != len(want) {
		t.Fatalf("heights = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("heights[%d] = %d, want %d", i, got[i], want[i])
		}
	}
}

// TestBridgeScannerExpBackoffOnSubscribeError verifies that when
// SubscribeNewBlocks errors repeatedly the supervisor retries with
// backoff and eventually recovers when the fake stops erroring.
func TestBridgeScannerExpBackoffOnSubscribeError(t *testing.T) {
	withTinyBackoff(t)

	live := make(chan uint64, 1)
	fake := &fakeSubscriber{
		// Two error attempts, then a healthy channel. The supervisor
		// must keep retrying through both errors.
		episodes: []chan uint64{nil, nil, live},
		errors:   []error{errors.New("boom-1"), errors.New("boom-2"), nil},
		blocks:   map[uint64][]*bridge.BSVTransaction{},
	}
	proc := &recordingProcessor{}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// First subscribe: error. Mirror the boot path: when the synchronous
	// initial subscribe fails the daemon would surface it. For the
	// supervisor-loop test we drive runBridgeScannerWithReconnect
	// directly with a closed pre-channel so the loop falls into the
	// re-subscribe branch immediately.
	closedCh := make(chan uint64)
	close(closedCh)

	done := make(chan struct{})
	go func() {
		defer close(done)
		runBridgeScannerWithReconnect(ctx, fake, proc, closedCh, slog.Default())
	}()

	// Now feed a height through the eventually-healthy channel.
	live <- 999

	if !waitFor(2*time.Second, func() bool { return len(proc.snapshot()) == 1 }) {
		t.Fatalf("expected eventual recovery, got heights=%v subscribeCalls=%d",
			proc.snapshot(), atomic.LoadInt32(&fake.subscribeCalls))
	}
	if got := atomic.LoadInt32(&fake.subscribeCalls); got < 3 {
		t.Fatalf("expected at least 3 subscribe attempts (2 errored + 1 ok), got %d", got)
	}

	cancel()
	<-done
}

// TestBridgeScannerCleanExitOnContextCancel verifies that cancelling
// the context during the backoff sleep unwinds cleanly without further
// subscribe attempts.
func TestBridgeScannerCleanExitOnContextCancel(t *testing.T) {
	// Use a longer-than-normal backoff so the cancel definitely lands
	// while the supervisor is mid-sleep.
	prevInitial := scannerBackoffInitial
	prevMax := scannerBackoffMax
	scannerBackoffInitial = 500 * time.Millisecond
	scannerBackoffMax = 500 * time.Millisecond
	t.Cleanup(func() {
		scannerBackoffInitial = prevInitial
		scannerBackoffMax = prevMax
	})

	// Single failing episode then exhaustion — supervisor will retry
	// indefinitely if not for the cancel.
	fake := &fakeSubscriber{
		episodes: []chan uint64{nil},
		errors:   []error{errors.New("init-fail")},
		blocks:   map[uint64][]*bridge.BSVTransaction{},
	}
	proc := &recordingProcessor{}

	ctx, cancel := context.WithCancel(context.Background())
	closedCh := make(chan uint64)
	close(closedCh)

	done := make(chan struct{})
	go func() {
		defer close(done)
		runBridgeScannerWithReconnect(ctx, fake, proc, closedCh, slog.Default())
	}()

	// Let the supervisor enter its first backoff sleep.
	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case <-done:
		// Expected: clean exit during backoff.
	case <-time.After(time.Second):
		t.Fatal("supervisor did not exit on context cancel")
	}
}

// TestBridgeScannerResumeCursorSkipsAlreadyProcessed verifies that
// after a reconnect, heights ≤ the resume cursor are skipped (no
// GetBlockTransactions, no ProcessBlock).
func TestBridgeScannerResumeCursorSkipsAlreadyProcessed(t *testing.T) {
	withTinyBackoff(t)

	first := make(chan uint64, 2)
	second := make(chan uint64, 4)
	fake := &fakeSubscriber{
		episodes: []chan uint64{first, second},
		errors:   []error{nil, nil},
		blocks:   map[uint64][]*bridge.BSVTransaction{},
	}
	proc := &recordingProcessor{}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	initial, err := fake.SubscribeNewBlocks(ctx)
	if err != nil {
		t.Fatalf("first subscribe: %v", err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		runBridgeScannerWithReconnect(ctx, fake, proc, initial, slog.Default())
	}()

	// First epoch processes 50, 51.
	first <- 50
	first <- 51
	if !waitFor(time.Second, func() bool { return len(proc.snapshot()) == 2 }) {
		t.Fatalf("first epoch: %v", proc.snapshot())
	}
	getBlocksAfterFirst := atomic.LoadInt32(&fake.getBlockCalls)
	close(first)

	if !waitFor(time.Second, func() bool { return atomic.LoadInt32(&fake.subscribeCalls) >= 2 }) {
		t.Fatalf("expected re-subscribe after channel close")
	}

	// Second epoch replays 50, 51 (already-seen), then 52 (new). Only
	// 52 should be processed.
	second <- 50
	second <- 51
	second <- 52

	if !waitFor(time.Second, func() bool { return len(proc.snapshot()) == 3 }) {
		t.Fatalf("second epoch: expected 3 total processed (50,51,52), got %v", proc.snapshot())
	}

	cancel()
	<-done

	got := proc.snapshot()
	want := []uint64{50, 51, 52}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("processed heights = %v, want %v", got, want)
		}
	}
	// Replayed heights must NOT have triggered GetBlockTransactions —
	// the resume cursor short-circuits before the fetch.
	finalGetBlocks := atomic.LoadInt32(&fake.getBlockCalls)
	if delta := finalGetBlocks - getBlocksAfterFirst; delta != 1 {
		t.Fatalf("expected exactly 1 new GetBlockTransactions in second epoch (height 52), got %d (calls jumped from %d to %d)",
			delta, getBlocksAfterFirst, finalGetBlocks)
	}
}
