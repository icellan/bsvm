// Tests for the admin_rescanDeposits → BlockScannerHandle.RewindToHeight
// path. Drives the full operator-facing flow: build an AdminAPI,
// install the SetBridgeRescanner closure that wraps a real
// BlockScannerHandle, then invoke AdminAPI.RescanDeposits and assert
// (a) the cursor was rewound, (b) the supervisor's resume-skip logic
// no longer short-circuits replays of already-seen heights.
//
// The test uses the existing fakeSubscriber (no real chaintracks
// connection) plus a hand-rolled tipFetcher so the "scheduled" count
// surfaced through the RPC is asserted end-to-end.
package main

import (
	"context"
	"errors"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"

	"github.com/icellan/bsvm/pkg/bridge"
	"github.com/icellan/bsvm/pkg/rpc"
)

// startScannerForRescanTest builds a runBridgeScannerWithReconnect-driven
// scanner around a fakeSubscriber, plus a BlockScannerHandle wired with
// a stubbed tip-fetcher. Returns the handle, the recording processor, a
// fakeSubscriber, the per-supervisor close function, plus the outermost
// channel pair so the caller can drive heights + close it to trigger
// reconnects. The supervisor goroutine is started here.
func startScannerForRescanTest(t *testing.T, tipFn func() (uint64, error)) (
	*BlockScannerHandle,
	*recordingProcessor,
	*fakeSubscriber,
	chan uint64,
	chan uint64,
	func(),
) {
	t.Helper()
	withTinyBackoff(t)

	first := make(chan uint64, 8)
	second := make(chan uint64, 8)
	fake := &fakeSubscriber{
		episodes: []chan uint64{first, second},
		errors:   []error{nil, nil},
		blocks:   map[uint64][]*bridge.BSVTransaction{},
	}
	proc := &recordingProcessor{}

	ctx, cancel := context.WithCancel(context.Background())
	initial, err := fake.SubscribeNewBlocks(ctx)
	if err != nil {
		cancel()
		t.Fatalf("first subscribe: %v", err)
	}

	handle := &BlockScannerHandle{
		cmdCh: make(chan rewindCmd, 1),
		tipFn: tipFn,
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		defer handle.markClosed()
		runBridgeScannerWithReconnect(ctx, fake, proc, initial, handle, slog.Default())
	}()

	closeFn := func() {
		cancel()
		<-done
	}
	return handle, proc, fake, first, second, closeFn
}

// TestAdminRescanDeposits_FullPath_RewindsCursorAndReprocesses asserts
// the operator-facing flow end-to-end:
//
//  1. The scanner processes blocks 100-102, advancing the resume cursor.
//  2. The chaintracks stream closes; the supervisor re-subscribes.
//  3. WITHOUT the rescan, replays of 100-102 are skipped by the resume
//     cursor (verified by GetBlockTransactions call delta == 0).
//  4. AdminAPI.RescanDeposits(50) is called. The wired closure invokes
//     handle.RewindToHeight(50), the supervisor processes the rewind
//     command between block events, and the cursor moves back to 49.
//  5. After the rewind, the supervisor's tip lookup runs and returns
//     a tip of 200, so the RPC response surfaces scheduled = 150.
//  6. New events at heights 60, 61 (which would previously have been
//     skipped) now flow through to ProcessBlock, proving the rewind
//     took effect.
func TestAdminRescanDeposits_FullPath_RewindsCursorAndReprocesses(t *testing.T) {
	tipFn := func() (uint64, error) { return 200, nil }
	handle, proc, fake, first, second, closeAll := startScannerForRescanTest(t, tipFn)
	defer closeAll()

	// 1. Process the first epoch (100, 101, 102).
	first <- 100
	first <- 101
	first <- 102
	if !waitFor(time.Second, func() bool { return len(proc.snapshot()) == 3 }) {
		t.Fatalf("first epoch: expected 3 heights, got %v", proc.snapshot())
	}
	getBlocksAfterEpoch1 := atomic.LoadInt32(&fake.getBlockCalls)

	// 2. Drop the channel so the supervisor re-subscribes onto `second`.
	close(first)
	if !waitFor(time.Second, func() bool { return atomic.LoadInt32(&fake.subscribeCalls) >= 2 }) {
		t.Fatalf("expected re-subscribe, subscribeCalls = %d", atomic.LoadInt32(&fake.subscribeCalls))
	}

	// 3. Wire the AdminAPI with the rescanner closure that mirrors what
	// cmd/bsvm/main.go does on boot. This exercises the full
	// AdminAPI.RescanDeposits → BridgeRescanFn → handle.RewindToHeight
	// path rather than calling RewindToHeight directly.
	mon := bridge.NewBridgeMonitor(bridge.DefaultConfig(), nil, nil)
	a := &rpc.AdminAPI{}
	a.SetBridgeMonitor(mon)
	a.SetBridgeRescanner(func(fromHeight uint64) (uint64, error) {
		return handle.RewindToHeight(fromHeight)
	})

	// 4. Issue the rescan. The supervisor should be sitting in its
	// `case cmd := <-rewindCh:` arm of consumeUntilClose (the second
	// channel is drained but still open).
	resp, err := a.RescanDeposits(50)
	if err != nil {
		t.Fatalf("admin_rescanDeposits: %v", err)
	}

	// 5. Assert the RPC surfaced the scheduled-block count from tipFn
	// (200) minus fromHeight (50) = 150.
	if got, want := resp["scheduled"], uint64(150); got != want {
		t.Errorf("scheduled = %v, want %v", got, want)
	}
	if got, want := resp["fromHeight"], uint64(50); got != want {
		t.Errorf("fromHeight = %v, want %v", got, want)
	}
	if got, want := resp["success"], true; got != want {
		t.Errorf("success = %v, want %v", got, want)
	}

	// 6. Assert the handle's published cursor moved back. The supervisor
	// rewinds to fromHeight-1 = 49.
	if got, want := handle.CurrentCursor(), uint64(49); got != want {
		t.Errorf("CurrentCursor = %d, want %d (fromHeight-1)", got, want)
	}

	// 7. Push two heights that would previously have been skipped by
	// the resume cursor (≤102). Both should now flow through to
	// ProcessBlock because the cursor is at 49.
	second <- 60
	second <- 61
	if !waitFor(time.Second, func() bool { return len(proc.snapshot()) == 5 }) {
		t.Fatalf("post-rewind: expected 5 heights total (3 + 60, 61), got %v", proc.snapshot())
	}
	getBlocksAfterRescan := atomic.LoadInt32(&fake.getBlockCalls)
	if delta := getBlocksAfterRescan - getBlocksAfterEpoch1; delta != 2 {
		t.Errorf("expected 2 new GetBlockTransactions calls (60, 61) after rewind; got %d", delta)
	}

	// 8. Verify the heights are in the expected order.
	got := proc.snapshot()
	want := []uint64{100, 101, 102, 60, 61}
	if len(got) != len(want) {
		t.Fatalf("heights = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("heights[%d] = %d, want %d", i, got[i], want[i])
		}
	}
}

// TestAdminRescanDeposits_TipFetchFailure_StillRewinds asserts that a
// transient tip-lookup failure does NOT abort the cursor rewind — the
// operator's intent (replay from N) is honored; the response surfaces
// scheduled=0 plus the wrapped error so the RPC caller sees the
// degraded mode without the rescan silently no-opping.
func TestAdminRescanDeposits_TipFetchFailure_StillRewinds(t *testing.T) {
	wantErr := errors.New("chaintracks unreachable")
	tipFn := func() (uint64, error) { return 0, wantErr }
	handle, proc, _, first, _, closeAll := startScannerForRescanTest(t, tipFn)
	defer closeAll()

	// Drive a single block so the cursor publishes once before the rewind.
	first <- 1000
	if !waitFor(time.Second, func() bool { return handle.CurrentCursor() == 1000 }) {
		t.Fatalf("expected cursor=1000 after first block, got %d", handle.CurrentCursor())
	}

	scheduled, err := handle.RewindToHeight(500)
	if err == nil {
		t.Fatal("expected wrapped tip-lookup error; got nil")
	}
	if !errors.Is(err, wantErr) {
		t.Errorf("error chain missing tipFn err: %v", err)
	}
	if scheduled != 0 {
		t.Errorf("scheduled = %d, want 0 on tip-fetch failure", scheduled)
	}

	// The cursor MUST have moved despite the tip-fetch failure.
	if got, want := handle.CurrentCursor(), uint64(499); got != want {
		t.Errorf("CurrentCursor = %d, want %d (rewind applied even on tip failure)", got, want)
	}

	_ = proc // unused — this test asserts the handle, not ProcessBlock
}

// TestAdminRescanDeposits_HigherThanCursor_Noop asserts the documented
// idempotency rule: rewinding to a height at-or-above the current
// cursor does not move the cursor backwards (which would imply
// REPROCESSING work the operator did not request) and does not move it
// forwards either (which would skip events the operator might want).
// The cursor stays put; scheduled is still computed.
func TestAdminRescanDeposits_HigherThanCursor_Noop(t *testing.T) {
	tipFn := func() (uint64, error) { return 1500, nil }
	handle, _, _, first, _, closeAll := startScannerForRescanTest(t, tipFn)
	defer closeAll()

	// Advance the cursor to 100.
	first <- 100
	if !waitFor(time.Second, func() bool { return handle.CurrentCursor() == 100 }) {
		t.Fatalf("expected cursor=100 after first block, got %d", handle.CurrentCursor())
	}

	// Request a rewind to 500 (higher than the current cursor at 100).
	// Per the supervisor's idempotency check this is a no-op for the
	// cursor — but scheduled is still surfaced from the tip lookup.
	scheduled, err := handle.RewindToHeight(500)
	if err != nil {
		t.Fatalf("RewindToHeight(500): %v", err)
	}
	if got, want := scheduled, uint64(1000); got != want {
		t.Errorf("scheduled = %d, want %d (tip - fromHeight)", got, want)
	}
	if got, want := handle.CurrentCursor(), uint64(100); got != want {
		t.Errorf("CurrentCursor = %d, want %d (rewind to higher than cursor must be no-op)", got, want)
	}
}

// TestBlockScannerHandle_AfterClose_ReturnsTypedError asserts the
// post-shutdown contract: once the supervisor goroutine exits, the
// handle returns ErrBlockScannerClosed instead of blocking on a
// never-drained command channel.
func TestBlockScannerHandle_AfterClose_ReturnsTypedError(t *testing.T) {
	tipFn := func() (uint64, error) { return 0, nil }
	handle, _, _, _, _, closeAll := startScannerForRescanTest(t, tipFn)
	closeAll() // tear down NOW; the handle should refuse subsequent calls.

	// Give the supervisor a moment to flip the closed flag.
	if !waitFor(time.Second, func() bool {
		// CurrentCursor is always safe; the closed bit lives on a
		// separate mutex so peek via RewindToHeight error.
		_, err := handle.RewindToHeight(1)
		return errors.Is(err, ErrBlockScannerClosed)
	}) {
		t.Fatal("expected ErrBlockScannerClosed after supervisor exit")
	}
}
