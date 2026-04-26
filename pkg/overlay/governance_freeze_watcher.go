package overlay

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/icellan/bsvm/pkg/covenant"
)

// defaultFreezeWatchInterval is the default poll cadence for the
// governance freeze watcher. Freeze events land on BSV through normal
// confirmation latency, so a low-frequency poll is fine — fast enough
// that the batcher rejects new transactions within a few seconds of the
// freeze tx being recognised, slow enough that idle nodes don't burn
// CPU spinning on a never-changing flag.
const defaultFreezeWatchInterval = 1 * time.Second

// GovernanceFreezeWatcher polls the covenant manager's current state
// and forwards Frozen-flag transitions to the overlay's
// GovernanceMonitor so the batcher pauses/unpauses in lock step with
// the on-chain governance status.
//
// This is a polling shim rather than an event subscription because
// pkg/covenant does not yet expose a state-change callback API. The
// poll loop is cheap (a single in-memory field read per tick) and is
// the only way to reflect a freeze that lands while no advance is in
// flight. Once CovenantManager grows a subscribe-style hook we can
// retire the goroutine and react synchronously.
type GovernanceFreezeWatcher struct {
	node     *OverlayNode
	covMgr   *covenant.CovenantManager
	monitor  *GovernanceMonitor
	interval time.Duration

	mu      sync.Mutex
	cancel  context.CancelFunc
	running bool
	doneCh  chan struct{}
}

// NewGovernanceFreezeWatcher constructs a watcher bound to the given
// overlay node and its covenant manager. interval ≤ 0 falls back to
// the package default (1 s).
func NewGovernanceFreezeWatcher(node *OverlayNode, interval time.Duration) *GovernanceFreezeWatcher {
	if interval <= 0 {
		interval = defaultFreezeWatchInterval
	}
	return &GovernanceFreezeWatcher{
		node:     node,
		covMgr:   node.CovenantManager(),
		monitor:  node.GovernanceMonitor(),
		interval: interval,
	}
}

// Start kicks off the poll loop in a goroutine and immediately syncs
// the monitor against the current covenant state so a node started
// while frozen comes up paused. Calling Start more than once is a
// no-op for the second call (the first watcher keeps running).
func (w *GovernanceFreezeWatcher) Start() {
	w.mu.Lock()
	if w.running {
		w.mu.Unlock()
		return
	}
	w.running = true
	ctx, cancel := context.WithCancel(context.Background())
	w.cancel = cancel
	w.doneCh = make(chan struct{})
	w.mu.Unlock()

	// Reflect the current state synchronously before the goroutine
	// spins up; this makes the post-Start assertion deterministic for
	// tests and avoids a race where Add() runs before the first tick.
	w.syncOnce()

	go w.run(ctx)
}

// Stop signals the poll loop to exit and blocks until the goroutine
// has returned. Safe to call when the watcher was never started.
func (w *GovernanceFreezeWatcher) Stop() {
	w.mu.Lock()
	if !w.running {
		w.mu.Unlock()
		return
	}
	cancel := w.cancel
	doneCh := w.doneCh
	w.running = false
	w.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if doneCh != nil {
		<-doneCh
	}
}

// SyncOnce reads the covenant state once and forwards the result to
// the governance monitor. Exposed for tests so they can trigger the
// state-change handling without sleeping for a poll tick.
func (w *GovernanceFreezeWatcher) SyncOnce() {
	w.syncOnce()
}

func (w *GovernanceFreezeWatcher) syncOnce() {
	if w.covMgr == nil || w.monitor == nil {
		return
	}
	if w.covMgr.CurrentState().Frozen != 0 {
		// HandleGovernanceFreeze is idempotent (no-op when already
		// frozen) so re-issuing on each tick is safe.
		w.monitor.HandleGovernanceFreeze()
		return
	}
	// Active branch — only call Unfreeze when the monitor is currently
	// frozen so we don't spam the batcher with redundant Resume calls.
	if w.monitor.State() == GovernanceFrozen {
		w.monitor.HandleGovernanceUnfreeze()
	}
}

func (w *GovernanceFreezeWatcher) run(ctx context.Context) {
	defer close(w.doneCh)
	t := time.NewTicker(w.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			w.syncOnce()
		}
	}
}

// EnableGovernanceFreezeWatcher creates and starts a freeze watcher
// for the given node. Returns a handle so callers (cmd/bsvm, tests)
// can stop it on teardown. No-op when the node has no covenant
// manager wired (e.g. a follower without on-chain settlement) or no
// governance monitor (constructor without governance support).
//
// Wiring this is the entry point used by cmd/bsvm to give a frozen
// shard the same observable behaviour as a paused batcher: new
// transactions hit ErrBatcherPaused at the RPC seam and the explorer
// UI surfaces the pause through admin_getStatus.
func EnableGovernanceFreezeWatcher(node *OverlayNode, interval time.Duration) *GovernanceFreezeWatcher {
	if node == nil {
		return nil
	}
	if node.CovenantManager() == nil {
		slog.Debug("governance freeze watcher disabled: no covenant manager attached")
		return nil
	}
	if node.GovernanceMonitor() == nil {
		slog.Debug("governance freeze watcher disabled: no governance monitor attached")
		return nil
	}
	w := NewGovernanceFreezeWatcher(node, interval)
	w.Start()
	return w
}
