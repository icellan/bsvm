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
) (blockScannerCloseFunc, error) {
	if monitor == nil {
		// No bridge configured for this shard — nothing to scan.
		return nil, nil
	}
	if chaintracksClient == nil {
		logger.Warn("bridge block scanner: chaintracks not configured, scanner disabled (BEEF path remains active)")
		return nil, nil
	}

	adapter, err := newBridgeBSVClient(chaintracksClient, wocClient, rpcClient, monitor, logger)
	if err != nil {
		return nil, fmt.Errorf("bridge block scanner: %w", err)
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
		return nil, fmt.Errorf("bridge block scanner: subscribe: %w", err)
	}

	var done sync.WaitGroup
	done.Add(1)
	go func() {
		defer done.Done()
		logger.Info("bridge block scanner started",
			"rpc_configured", rpcClient != nil,
			"woc_configured", wocClient != nil,
		)
		runBridgeScannerWithReconnect(scanCtx, adapter, monitor, initialCh, logger)
	}()

	closeFn := func() error {
		cancel()
		done.Wait()
		return nil
	}
	return closeFn, nil
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
// backoff schedule, and (c) the WARN-promotion bookkeeping. The
// initialCh argument is the (already-open) channel from the synchronous
// first subscribe; the loop drains it first, then re-subscribes on
// close. Returns only when ctx is cancelled.
func runBridgeScannerWithReconnect(
	ctx context.Context,
	adapter blockScannerSubscriber,
	monitor blockScannerProcessor,
	initialCh <-chan uint64,
	logger *slog.Logger,
) {
	var (
		resumeHeight    uint64 // 0 means "no cursor yet"
		resumeSet       bool
		consecutiveFail int
		backoff         = scannerBackoffInitial
	)

	blockCh := initialCh
	for {
		if ctx.Err() != nil {
			return
		}
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
				if !sleepWithCancel(ctx, jitterBackoff(backoff)) {
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
		closed := consumeUntilClose(ctx, blockCh, adapter, monitor, &resumeHeight, &resumeSet, &consecutiveFail, &backoff, logger)
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
		if !sleepWithCancel(ctx, jitterBackoff(backoff)) {
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
	logger *slog.Logger,
) bool {
	for {
		select {
		case <-ctx.Done():
			return false
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
					continue
				}
				logger.Warn("bridge block scanner: GetBlockTransactions failed", "height", height, "err", err)
				continue
			}
			monitor.ProcessBlock(height, txs)
			*resumeHeight = height
			*resumeSet = true
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
func sleepWithCancel(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return ctx.Err() == nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
