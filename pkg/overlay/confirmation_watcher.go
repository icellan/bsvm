package overlay

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/icellan/bsvm/pkg/covenant"
	"github.com/icellan/bsvm/pkg/types"
)

// finalizedDepth is the number of BSV confirmations required for an
// L2 block to be considered finalized. Matches the spec 11 threshold.
const finalizedDepth uint32 = 6

// ConfirmationWatcher periodically polls the broadcast client for
// confirmation counts on outstanding broadcast advances and bumps
// confirmedTip and finalizedTip on the overlay node accordingly.
type ConfirmationWatcher struct {
	node     *OverlayNode
	client   covenant.BroadcastClient
	interval time.Duration
	stopCh   chan struct{}
	doneCh   chan struct{}
	started  bool

	mu          sync.Mutex
	outstanding map[uint64]*pendingBroadcast
}

type pendingBroadcast struct {
	txid          types.Hash
	confirmations uint32
}

// NewConfirmationWatcher creates a ConfirmationWatcher bound to the given
// overlay node and broadcast client. Call Start to begin polling.
func NewConfirmationWatcher(node *OverlayNode, client covenant.BroadcastClient, interval time.Duration) *ConfirmationWatcher {
	if interval <= 0 {
		interval = time.Second
	}
	return &ConfirmationWatcher{
		node:        node,
		client:      client,
		interval:    interval,
		stopCh:      make(chan struct{}),
		doneCh:      make(chan struct{}),
		outstanding: make(map[uint64]*pendingBroadcast),
	}
}

// Track records a broadcast that should be polled for confirmations.
// Called from ProcessBatch after a successful BroadcastAdvance.
func (w *ConfirmationWatcher) Track(blockNum uint64, txid types.Hash) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.outstanding[blockNum] = &pendingBroadcast{txid: txid}
}

// Outstanding returns the number of broadcasts currently being tracked.
func (w *ConfirmationWatcher) Outstanding() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.outstanding)
}

// Start begins the polling loop in a goroutine. Calling Start twice is a
// no-op for the second call.
func (w *ConfirmationWatcher) Start() {
	w.mu.Lock()
	if w.started {
		w.mu.Unlock()
		return
	}
	w.started = true
	w.mu.Unlock()
	go w.run()
}

// Stop signals the watcher to exit and blocks until the goroutine has
// returned. Safe to call more than once; subsequent calls are no-ops.
func (w *ConfirmationWatcher) Stop() {
	w.mu.Lock()
	if !w.started {
		w.mu.Unlock()
		return
	}
	select {
	case <-w.stopCh:
		w.mu.Unlock()
		<-w.doneCh
		return
	default:
	}
	close(w.stopCh)
	w.mu.Unlock()
	<-w.doneCh
}

func (w *ConfirmationWatcher) run() {
	defer close(w.doneCh)
	timer := time.NewTimer(w.interval)
	defer timer.Stop()
	for {
		select {
		case <-w.stopCh:
			return
		case <-timer.C:
			w.poll()
			timer.Reset(w.interval)
		}
	}
}

// poll queries the broadcast client for every outstanding tx and bumps the
// overlay node's confirmed/finalized tips. Broadcasts that reach the
// finalized depth are dropped from the tracking map.
func (w *ConfirmationWatcher) poll() {
	w.mu.Lock()
	snapshot := make(map[uint64]*pendingBroadcast, len(w.outstanding))
	for blockNum, pending := range w.outstanding {
		snapshot[blockNum] = &pendingBroadcast{txid: pending.txid, confirmations: pending.confirmations}
	}
	w.mu.Unlock()

	if len(snapshot) == 0 {
		return
	}

	for blockNum, pending := range snapshot {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		confs, err := w.client.GetConfirmations(ctx, pending.txid)
		cancel()
		if err != nil {
			slog.Debug("confirmation query failed",
				"block", blockNum, "txid", pending.txid.BSVString(), "error", err)
			continue
		}
		snapshot[blockNum].confirmations = confs
	}

	var maxConfirmed, maxFinalized uint64
	toDrop := make([]uint64, 0)
	for blockNum, pending := range snapshot {
		if pending.confirmations >= 1 && blockNum > maxConfirmed {
			maxConfirmed = blockNum
		}
		if pending.confirmations >= finalizedDepth {
			if blockNum > maxFinalized {
				maxFinalized = blockNum
			}
			toDrop = append(toDrop, blockNum)
		}
	}

	w.mu.Lock()
	for blockNum, pending := range snapshot {
		if cur, ok := w.outstanding[blockNum]; ok {
			cur.confirmations = pending.confirmations
		}
	}
	for _, blockNum := range toDrop {
		delete(w.outstanding, blockNum)
	}
	w.mu.Unlock()

	if maxConfirmed > 0 && w.node.ConfirmedTip() < maxConfirmed {
		w.node.SetConfirmedTip(maxConfirmed)
	}
	if maxFinalized > 0 && w.node.FinalizedTip() < maxFinalized {
		w.node.SetFinalizedTip(maxFinalized)
	}
}
