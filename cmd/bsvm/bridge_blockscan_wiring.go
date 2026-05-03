// Daemon-side wiring that drives the bridge.BridgeMonitor's deposit-
// detection methods (ProcessBlock / RetractDepositsAbove) from a
// chaintracks-backed adapter (see cmd/bsvm/bridge_bsv_client.go). The
// scanner replaces the per-package run loop the monitor used to host;
// the monitor itself is now purely a state-keeper. The BEEF deposit
// path remains the primary deposit channel; this scanner backs it up
// for deposits that land directly on-chain (BSV tx with bridge-script
// output, no BEEF envelope).
//
// startBridgeBlockScanner returns a Close function the caller defers
// so the scanner goroutine + the chaintracks WS subscription unwind
// cleanly on daemon shutdown. Returns (nil, nil) when the scanner is
// not applicable for the current daemon configuration (no monitor, no
// chaintracks anchor); the daemon stays bootable in that case and the
// BEEF path keeps running in isolation.
//
// Reconnect semantics
// -------------------
// The chaintracks RemoteClient already exponentially-backs-off the
// underlying WebSocket reconnection (see pkg/chaintracks/stream.go).
// However the per-call channel returned by SubscribeReorgs CAN close
// on hard upstream failures (e.g. when chaintracks itself shuts down
// or the in-process hub aborts a slow consumer). When that happens the
// bridge scanner used to exit silently and required a daemon restart
// to recover.
//
// This wave wraps the inner consume-loop in an outer reconnect loop
// with the following behaviour:
//
//   - On channel close OR subscribe error, the outer loop sleeps for
//     an exponential-backoff interval (1s start, 60s cap, ±25% jitter)
//     and re-subscribes. Each reconnect attempt logs at INFO; after
//     three consecutive failures the level is promoted to WARN so
//     operator dashboards surface the persistent outage.
//   - A resume cursor (lastScannedHeight + lastScannedHash) is tracked
//     across reconnects. Heights at-or-below the cursor are skipped on
//     resume — the BridgeMonitor's deposit dedup keys are idempotent,
//     so re-processing wouldn't be a correctness problem, but skipping
//     avoids needless RPC fan-out work for deposits already persisted.
//   - Cancellation: ctx.Done is honoured during BOTH the consume-loop
//     read AND the backoff sleep, so a daemon shutdown mid-reconnect
//     unwinds cleanly without an extra round-trip.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand"
	"sync"
	"time"

	"github.com/icellan/bsvm/pkg/bridge"
	"github.com/icellan/bsvm/pkg/chaintracks"
	"github.com/icellan/bsvm/pkg/whatsonchain"
)

// blockScannerCloseFunc is returned from startBridgeBlockScanner so
// callers can defer-close the scanner without importing context here.
type blockScannerCloseFunc func() error

// BlockScannerHandle is the operator-facing control surface for the
// bridge block-scanner goroutine. The goroutine remains the sole owner
// of the resume cursor; the handle's methods enqueue typed commands
// the goroutine reads in its select loop. This keeps the cursor under
// a single goroutine's mutation while letting the RPC dispatcher
// (admin_rescanDeposits) safely request a rewind from any goroutine.
//
// Concurrency contract:
//   - RewindToHeight blocks until the supervisor goroutine acknowledges
//     the rewind on a reply channel. It is safe to call from any
//     goroutine (including the RPC dispatcher) while the supervisor is
//     mid-scan; the supervisor processes the command between block
//     events.
//   - CurrentCursor reads the latest cursor snapshot the supervisor
//     has published. The value is cached under a mutex to keep the
//     read path lock-free of the command channel — long-running scans
//     do not block UI polling.
//   - Both methods are no-ops (returning a typed error / zero) once the
//     supervisor goroutine has exited. This matches the daemon's
//     shutdown semantics: the handle becomes inert after the cmd-side
//     close function runs.
type BlockScannerHandle struct {
	// cmdCh is the typed command channel the supervisor goroutine
	// consumes in its select loop. Buffered to 1 so a single in-flight
	// rewind from the RPC layer does not block the caller waiting for
	// the goroutine to be between block events; further callers serialise
	// on the channel send.
	cmdCh chan rewindCmd

	// cursorMu protects publishedCursor. The supervisor writes after
	// each successful ProcessBlock (or after a rewind apply); readers
	// (admin RPC, tests) take the read lock. A plain Mutex is fine —
	// the publish rate (≤1/block) and read rate (UI polling) are both
	// modest.
	cursorMu        sync.Mutex
	publishedCursor uint64
	publishedSet    bool

	// tipFn returns the current BSV chain tip height. Used to compute
	// the "scheduled" count surfaced to the RPC. Nil-tolerant: when
	// the tip lookup fails the handle still applies the rewind but
	// reports scheduled=0 with a warning logged by the supervisor.
	tipFn func() (uint64, error)

	// closed is set to true by the supervisor's defer once it returns.
	// Subsequent RewindToHeight calls fail fast with a typed error
	// rather than blocking on a never-drained command channel.
	closedMu sync.Mutex
	closed   bool
}

// rewindCmd is the typed command sent on BlockScannerHandle.cmdCh. The
// supervisor goroutine reads it, mutates its private cursor state, and
// posts the (scheduled, err) tuple back on replyCh.
type rewindCmd struct {
	height  uint64
	replyCh chan rewindReply
}

// rewindReply is the supervisor's acknowledgement of a rewindCmd.
type rewindReply struct {
	scheduled uint64
	err       error
}

// ErrBlockScannerClosed is returned by BlockScannerHandle.RewindToHeight
// when the supervisor goroutine has exited (daemon shutdown). The
// handle becomes inert after this point; callers should not retry.
var ErrBlockScannerClosed = errors.New("bridge block scanner: handle closed (daemon shutting down)")

// RewindToHeight resets the supervisor's resume cursor to height-1 so
// the next event from chaintracks (or a directly-injected replay) at
// or above height is processed rather than skipped by the resume-cursor
// dedup. The call blocks until the supervisor acknowledges; returns
// the count of blocks scheduled to scan (current_tip - height) plus
// any error from the tip lookup. A tip-fetch failure does NOT abort
// the rewind — the cursor change still applies; the count is reported
// as 0 with the underlying error wrapped in the response so the
// operator sees the degraded mode in the RPC reply.
//
// Idempotent: rewinding to a height the cursor is already at-or-below
// is a no-op (no extra processing scheduled, no error).
//
// Safe to call concurrently with the supervisor's normal block
// processing — the command channel serialises mutations.
func (h *BlockScannerHandle) RewindToHeight(height uint64) (uint64, error) {
	if h == nil {
		return 0, ErrBlockScannerClosed
	}
	h.closedMu.Lock()
	closed := h.closed
	h.closedMu.Unlock()
	if closed {
		return 0, ErrBlockScannerClosed
	}
	reply := make(chan rewindReply, 1)
	// cmdCh is buffered to 1; concurrent callers serialise on the send.
	// The supervisor goroutine drains the channel between block events,
	// during reconnect backoff sleeps, and around subscribe attempts —
	// so a long-blocked send only happens if the supervisor itself is
	// blocked (which the daemon-shutdown ctx cancellation will unwind).
	h.cmdCh <- rewindCmd{height: height, replyCh: reply}
	r := <-reply
	return r.scheduled, r.err
}

// CurrentCursor returns the latest resume-cursor height the supervisor
// has published, or 0 when no block has been processed yet. Safe to
// call from any goroutine.
func (h *BlockScannerHandle) CurrentCursor() uint64 {
	if h == nil {
		return 0
	}
	h.cursorMu.Lock()
	defer h.cursorMu.Unlock()
	return h.publishedCursor
}

// publishCursor is the supervisor-internal helper that mirrors the
// goroutine's private cursor state into the handle's published cache.
// Called after every successful ProcessBlock and after every applied
// rewind so CurrentCursor stays fresh for the RPC.
func (h *BlockScannerHandle) publishCursor(height uint64, set bool) {
	if h == nil {
		return
	}
	h.cursorMu.Lock()
	h.publishedCursor = height
	h.publishedSet = set
	h.cursorMu.Unlock()
}

// markClosed flips the handle into its post-shutdown state. Called
// from the supervisor's defer in startBridgeBlockScanner.
func (h *BlockScannerHandle) markClosed() {
	if h == nil {
		return
	}
	h.closedMu.Lock()
	h.closed = true
	h.closedMu.Unlock()
}

// Reconnect-loop tuning. Exposed as package vars (not constants) so the
// auto-resubscribe tests can dial the backoff floor down to nanoseconds
// without sleeping for real wall-clock seconds inside `go test`.
var (
	scannerBackoffInitial = 1 * time.Second
	scannerBackoffMax     = 60 * time.Second
	scannerWarnAfter      = 3 // promote reconnect logs to WARN after this many consecutive failures
)

// bridgeBSVProviderForScan narrows the cmd-side BSVProviderClient
// down to the bridgeRPCClient surface the adapter needs (Call only).
// Returns nil when the input is nil so the scanner can proceed in
// chaintracks-only mode without faking an RPC client.
func bridgeBSVProviderForScan(p BSVProviderClient) bridgeRPCClient {
	if p == nil {
		return nil
	}
	return p
}

// startBridgeBlockScanner wires the bridge.BridgeMonitor's
// ProcessBlock / RetractDepositsAbove methods against a bridgeBSVClient
// composed from chaintracks + WoC + the optional BSV-node JSON-RPC
// failover provider. The scanner runs in its own goroutine and exits
// when ctx is cancelled. Channel closures / subscribe errors trigger an
// exponential-backoff reconnect rather than a permanent exit (see file
// doc-comment).
//
// Behaviour:
//
//   - Returns (nil, nil) when monitor is nil (no [bridge].
//     bridge_script_hex configured) — the daemon does not need a
//     scanner there.
//   - Returns (nil, nil) when chaintracks is nil (no SPV anchor) — we
//     refuse to scan without one because deposit confirmations are
//     unverifiable.
//   - Returns the close function on success. The function blocks
//     until the scanner goroutine has returned.
//
// Errors come from the BSV client construction; they're operator-
// fixable so we surface them rather than warn-and-continue.
func startBridgeBlockScanner(
	ctx context.Context,
	monitor *bridge.BridgeMonitor,
	chaintracksClient chaintracks.ChaintracksClient,
	wocClient whatsonchain.WhatsOnChainClient,
	rpcClient bridgeRPCClient,
	logger *slog.Logger,
	wocBlockTxFanoutMaxOverride int,
) (blockScannerCloseFunc, *BlockScannerHandle, error) {
	if monitor == nil {
		// No bridge configured for this shard — nothing to scan.
		return nil, nil, nil
	}
	if chaintracksClient == nil {
		logger.Warn("bridge block scanner: chaintracks not configured, scanner disabled (BEEF path remains active)")
		return nil, nil, nil
	}

	adapter, err := newBridgeBSVClientWithFanout(
		chaintracksClient, wocClient, rpcClient, monitor, logger, wocBlockTxFanoutMaxOverride,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("bridge block scanner: %w", err)
	}

	scanCtx, cancel := context.WithCancel(ctx)

	// Subscribe synchronously before returning so callers (and tests)
	// can rely on the chaintracks subscriber slot being registered by
	// the time startBridgeBlockScanner exits. A failure here is
	// operator-visible and we surface it rather than silently retrying
	// from inside the goroutine — the daemon's startup path treats this
	// as a hard error. Subsequent (post-restart) channel closures are
	// handled by the reconnect loop inside the goroutine.
	initialCh, err := adapter.SubscribeNewBlocks(scanCtx)
	if err != nil {
		cancel()
		return nil, nil, fmt.Errorf("bridge block scanner: subscribe: %w", err)
	}

	handle := &BlockScannerHandle{
		cmdCh: make(chan rewindCmd, 1),
		tipFn: adapter.GetBlockHeight,
	}

	var done sync.WaitGroup
	done.Add(1)
	go func() {
		defer done.Done()
		defer handle.markClosed()
		logger.Info("bridge block scanner started",
			"rpc_configured", rpcClient != nil,
			"woc_configured", wocClient != nil,
		)
		runBridgeScannerWithReconnect(scanCtx, adapter, monitor, initialCh, handle, logger)
	}()

	closeFn := func() error {
		cancel()
		done.Wait()
		return nil
	}
	return closeFn, handle, nil
}

// blockScannerSubscriber is the subset of *bridgeBSVClient the
// reconnect loop drives. Defined as an interface so the unit tests
// can inject a fake that orchestrates SubscribeNewBlocks failures /
// channel closures without standing up a real chaintracks client.
type blockScannerSubscriber interface {
	SubscribeNewBlocks(ctx context.Context) (<-chan uint64, error)
	GetBlockTransactions(height uint64) ([]*bridge.BSVTransaction, error)
}

// blockScannerProcessor is the subset of *bridge.BridgeMonitor the
// loop drives. Mirrors the surface so tests can use a recording fake.
type blockScannerProcessor interface {
	ProcessBlock(height uint64, txs []*bridge.BSVTransaction)
}

// runBridgeScannerWithReconnect is the supervisor loop. It owns
// (a) the resume cursor across re-subscriptions, (b) the exponential-
// backoff schedule, (c) the WARN-promotion bookkeeping, and (d) the
// rewind-command channel from the operator-facing BlockScannerHandle.
// The initialCh argument is the (already-open) channel from the
// synchronous first subscribe; the loop drains it first, then
// re-subscribes on close. The handle argument may be nil (legacy
// callers / tests) — the rewind command path is skipped when so.
// Returns only when ctx is cancelled.
func runBridgeScannerWithReconnect(
	ctx context.Context,
	adapter blockScannerSubscriber,
	monitor blockScannerProcessor,
	initialCh <-chan uint64,
	handle *BlockScannerHandle,
	logger *slog.Logger,
) {
	var (
		resumeHeight    uint64 // 0 means "no cursor yet"
		resumeSet       bool
		consecutiveFail int
		backoff         = scannerBackoffInitial
	)

	// applyRewind mutates the supervisor-private cursor state in
	// response to a rewindCmd from the handle. Returns the (scheduled,
	// err) tuple the handle's reply channel surfaces back to the RPC
	// caller. Idempotent: rewinding to a height the cursor is already
	// below is a no-op.
	applyRewind := func(cmd rewindCmd) rewindReply {
		// Compute the "scheduled" count (current_tip - height) using
		// the handle's tipFn. A tip-fetch failure does not abort the
		// rewind — we still apply the cursor change so the operator's
		// requested replay happens; we only degrade the count to zero
		// and surface the error.
		var (
			scheduled uint64
			tipErr    error
		)
		if handle != nil && handle.tipFn != nil {
			tip, err := handle.tipFn()
			if err != nil {
				tipErr = fmt.Errorf("tip lookup failed (rewind still applied): %w", err)
				logger.Warn("bridge block scanner: rewind tip lookup failed",
					"err", err, "from_height", cmd.height,
				)
			} else if tip > cmd.height {
				scheduled = tip - cmd.height
			}
		}

		// Apply the cursor rewind. We rewind to height-1 so the next
		// chaintracks event at-or-above height is processed. height==0
		// means "scan from genesis": clear the resume cursor.
		if cmd.height == 0 {
			resumeHeight = 0
			resumeSet = false
		} else if !resumeSet || cmd.height-1 < resumeHeight {
			resumeHeight = cmd.height - 1
			resumeSet = true
		}
		// else: cmd.height is at-or-below the current cursor; the
		// requested replay is already implied by the cursor's current
		// position. No-op.

		handle.publishCursor(resumeHeight, resumeSet)
		logger.Info("bridge block scanner: cursor rewound",
			"from_height", cmd.height,
			"new_resume_height", resumeHeight,
			"resume_set", resumeSet,
			"scheduled", scheduled,
		)
		return rewindReply{scheduled: scheduled, err: tipErr}
	}

	// drainRewinds processes any pending rewindCmds without blocking.
	// Called between subscribe attempts and during backoff sleeps so
	// the operator's RPC call is never starved by a long reconnect
	// storm.
	drainRewinds := func() {
		if handle == nil {
			return
		}
		for {
			select {
			case cmd := <-handle.cmdCh:
				cmd.replyCh <- applyRewind(cmd)
			default:
				return
			}
		}
	}

	blockCh := initialCh
	for {
		if ctx.Err() != nil {
			return
		}
		drainRewinds()
		if blockCh == nil {
			ch, err := adapter.SubscribeNewBlocks(ctx)
			if err != nil {
				consecutiveFail++
				level := slog.LevelInfo
				if consecutiveFail > scannerWarnAfter {
					level = slog.LevelWarn
				}
				logger.Log(ctx, level, "bridge block scanner: subscribe failed, retrying",
					"err", err,
					"consecutive_failures", consecutiveFail,
					"backoff", backoff,
					"resume_height", resumeHeight,
				)
				if !sleepWithCancelOrRewind(ctx, jitterBackoff(backoff), handle, applyRewind) {
					return
				}
				backoff = nextBackoff(backoff)
				continue
			}
			blockCh = ch
		}

		// Drain until either the channel closes or ctx is cancelled.
		// The first successful event resets backoff/failure counters
		// (handled inside consumeUntilClose).
		closed := consumeUntilClose(ctx, blockCh, adapter, monitor, &resumeHeight, &resumeSet, &consecutiveFail, &backoff, handle, applyRewind, logger)
		blockCh = nil // force re-subscribe on next iteration
		if !closed {
			// ctx cancelled inside the loop — exit cleanly.
			return
		}

		// Channel closed. Schedule reconnect.
		consecutiveFail++
		level := slog.LevelInfo
		if consecutiveFail > scannerWarnAfter {
			level = slog.LevelWarn
		}
		logger.Log(ctx, level, "bridge block scanner: chaintracks stream closed, reconnecting",
			"consecutive_failures", consecutiveFail,
			"backoff", backoff,
			"resume_height", resumeHeight,
			"resume_set", resumeSet,
		)
		if !sleepWithCancelOrRewind(ctx, jitterBackoff(backoff), handle, applyRewind) {
			return
		}
		backoff = nextBackoff(backoff)
	}
}

// consumeUntilClose drains blockCh until either ctx is cancelled or
// the channel is closed. Returns true iff the channel closed
// (signalling "reconnect"); false iff ctx was cancelled (signalling
// "exit cleanly"). The resume cursor is updated for every height that
// is processed; resets of consecutiveFail/backoff happen on the FIRST
// successful event of the new connection.
func consumeUntilClose(
	ctx context.Context,
	blockCh <-chan uint64,
	adapter blockScannerSubscriber,
	monitor blockScannerProcessor,
	resumeHeight *uint64,
	resumeSet *bool,
	consecutiveFail *int,
	backoff *time.Duration,
	handle *BlockScannerHandle,
	applyRewind func(rewindCmd) rewindReply,
	logger *slog.Logger,
) bool {
	// rewindCh is the handle's command channel, or nil when no handle
	// is wired. A nil channel in a select{} blocks forever, which is
	// exactly the legacy two-case behaviour.
	var rewindCh <-chan rewindCmd
	if handle != nil {
		rewindCh = handle.cmdCh
	}
	for {
		select {
		case <-ctx.Done():
			return false
		case cmd := <-rewindCh:
			// Apply the rewind in-line — applyRewind closes over the
			// supervisor's resume cursor pointers, so the mutation is
			// visible to the next block-channel read in this loop.
			cmd.replyCh <- applyRewind(cmd)
			continue
		case height, ok := <-blockCh:
			if !ok {
				return true
			}
			// First post-resubscribe event — reset the failure counter
			// and backoff. We do this BEFORE the resume-cursor skip
			// check so that a stream which only emits already-seen
			// heights still counts as "alive".
			if *consecutiveFail > 0 {
				logger.Info("bridge block scanner: stream healthy, resetting backoff",
					"height", height,
					"prior_failures", *consecutiveFail,
				)
			}
			*consecutiveFail = 0
			*backoff = scannerBackoffInitial

			if *resumeSet && height <= *resumeHeight {
				// Already processed this height in a previous epoch.
				// Idempotent dedup makes re-processing safe but a no-op
				// keeps the scanner cheap on long reconnect storms.
				logger.Debug("bridge block scanner: skipping height ≤ resume cursor",
					"height", height,
					"resume_height", *resumeHeight,
				)
				continue
			}

			txs, err := adapter.GetBlockTransactions(height)
			if err != nil {
				if errors.Is(err, ErrBlockFetchUnsupported) {
					// Surface once per startup, then squelch: the
					// scanner is effectively a no-op without RPC,
					// but the chaintracks subscription is cheap
					// enough to keep open for reorg notifications.
					logger.Debug("bridge block scanner: getblock unsupported, skipping height", "height", height)
					// Advance the cursor anyway — we don't want to
					// re-attempt this height on every reconnect.
					*resumeHeight = height
					*resumeSet = true
					handle.publishCursor(*resumeHeight, *resumeSet)
					continue
				}
				logger.Warn("bridge block scanner: GetBlockTransactions failed", "height", height, "err", err)
				continue
			}
			monitor.ProcessBlock(height, txs)
			*resumeHeight = height
			*resumeSet = true
			handle.publishCursor(*resumeHeight, *resumeSet)
		}
	}
}

// jitterBackoff applies ±25% multiplicative jitter to d. A jittered
// backoff prevents synchronised reconnect storms when many consumers
// share a single chaintracks deployment that just bounced.
func jitterBackoff(d time.Duration) time.Duration {
	if d <= 0 {
		return d
	}
	// rand.Int63n(d/2) ∈ [0, d/2); offset = -d/4 + rand*d/2 ∈ [-d/4, d/4).
	jitter := time.Duration(rand.Int63n(int64(d/2+1))) - d/4
	out := d + jitter
	if out < 0 {
		out = 0
	}
	return out
}

// nextBackoff doubles d, capped at scannerBackoffMax.
func nextBackoff(d time.Duration) time.Duration {
	next := d * 2
	if next > scannerBackoffMax {
		next = scannerBackoffMax
	}
	return next
}

// sleepWithCancel sleeps for d, returning false if ctx is cancelled
// during the wait. Returns true on full elapse.
//
// Retained as a thin wrapper around sleepWithCancelOrRewind so existing
// call sites and tests that don't drive the rewind handle stay
// unchanged.
func sleepWithCancel(ctx context.Context, d time.Duration) bool {
	return sleepWithCancelOrRewind(ctx, d, nil, nil)
}

// sleepWithCancelOrRewind sleeps for d, returning false if ctx is
// cancelled during the wait. Returns true on full elapse. If a handle
// is supplied, rewindCmds delivered during the sleep are processed
// in-line via applyRewind so the operator's RPC call doesn't block
// behind a long backoff. Each processed rewind does NOT extend the
// sleep — the timer keeps ticking — which matches the legacy "sleep
// for d, then re-attempt" semantics.
func sleepWithCancelOrRewind(
	ctx context.Context,
	d time.Duration,
	handle *BlockScannerHandle,
	applyRewind func(rewindCmd) rewindReply,
) bool {
	if d <= 0 {
		return ctx.Err() == nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	var rewindCh <-chan rewindCmd
	if handle != nil && applyRewind != nil {
		rewindCh = handle.cmdCh
	}
	for {
		select {
		case <-ctx.Done():
			return false
		case <-t.C:
			return true
		case cmd := <-rewindCh:
			cmd.replyCh <- applyRewind(cmd)
			// Loop and continue waiting on the timer / ctx.
		}
	}
}
