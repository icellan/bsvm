package overlay

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/icellan/bsvm/pkg/block"
	"github.com/icellan/bsvm/pkg/covenant"
	"github.com/icellan/bsvm/pkg/types"
)

// finalizedDepth is the number of BSV confirmations required for an
// L2 block to be considered finalized. Matches the spec 11 threshold.
const finalizedDepth uint32 = 6

// pendingAnchorTimeout is how long the watcher will keep polling an
// outstanding anchor before logging a loud warning. The watcher does NOT
// drop the anchor on timeout (the operator may rebroadcast); it just
// surfaces the staleness so monitoring can fire. Defaults to 6 hours,
// matching the BSV "stuck mempool" rule of thumb where one operator
// intervention is plausibly cheaper than waiting longer.
const pendingAnchorTimeout = 6 * time.Hour

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
	// trackedAt is the wall-clock time the broadcast was registered.
	// Used purely for the stale-anchor warning; the watcher does not
	// drop pending entries on timeout (operator-controlled).
	trackedAt time.Time
	// staleLogged guards the once-per-anchor stale warning so a
	// long-pending tx doesn't spam logs every poll.
	staleLogged bool
	// anchorBackfilled is true once the watcher has written the
	// AnchorRecord with Confirmed=true. This is independent of the
	// finalizedDepth tracking-drop: the anchor flips Confirmed at the
	// first confirmation (>= 1), but the entry stays in the map until
	// finalizedDepth so SetFinalizedTip fires correctly.
	anchorBackfilled bool
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
	w.outstanding[blockNum] = &pendingBroadcast{txid: txid, trackedAt: time.Now()}
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

// pollResult is the per-anchor outcome of a single poll() pass. It
// carries the data the post-poll critical section needs to update the
// in-memory pending map AND back-fill the persisted AnchorRecord.
type pollResult struct {
	confirmations uint32
	blockHeight   uint64 // 0 when the BroadcastClient does not expose height
	err           error
}

// poll queries the broadcast client for every outstanding tx and bumps the
// overlay node's confirmed/finalized tips. Broadcasts that reach the
// finalized depth are dropped from the tracking map. AnchorRecord
// back-fill: once a tx has at least one confirmation, the watcher
// updates the persisted AnchorRecord with Confirmed=true and (when the
// client exposes TransactionStatusSource) the BSV block height.
func (w *ConfirmationWatcher) poll() {
	w.mu.Lock()
	snapshot := make(map[uint64]*pendingBroadcast, len(w.outstanding))
	for blockNum, pending := range w.outstanding {
		snapshot[blockNum] = &pendingBroadcast{
			txid:             pending.txid,
			confirmations:    pending.confirmations,
			trackedAt:        pending.trackedAt,
			staleLogged:      pending.staleLogged,
			anchorBackfilled: pending.anchorBackfilled,
		}
	}
	w.mu.Unlock()

	if len(snapshot) == 0 {
		return
	}

	statusSrc, hasStatusSrc := w.client.(covenant.TransactionStatusSource)

	results := make(map[uint64]pollResult, len(snapshot))
	for blockNum, pending := range snapshot {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		var (
			confs  uint32
			height uint64
			err    error
		)
		if hasStatusSrc {
			var st covenant.TxStatus
			st, err = statusSrc.GetTransactionStatus(ctx, pending.txid)
			confs = st.Confirmations
			height = st.BlockHeight
		} else {
			confs, err = w.client.GetConfirmations(ctx, pending.txid)
		}
		cancel()
		if err != nil {
			slog.Debug("confirmation query failed",
				"block", blockNum, "txid", pending.txid.BSVString(), "error", err)
			results[blockNum] = pollResult{err: err}
			continue
		}
		snapshot[blockNum].confirmations = confs
		results[blockNum] = pollResult{confirmations: confs, blockHeight: height}
	}

	var maxConfirmed, maxFinalized uint64
	toDrop := make([]uint64, 0)
	now := time.Now()
	for blockNum, pending := range snapshot {
		res := results[blockNum]
		// Anchor back-fill: a single confirmation is enough to set
		// Confirmed=true on the persisted record. We delay the write
		// until we see >= 1 confs to avoid pointless ChainDB churn on
		// every poll while the tx sits in the mempool.
		if res.err == nil && pending.confirmations >= 1 && !pending.anchorBackfilled {
			if w.backfillAnchor(blockNum, pending.txid, res.blockHeight) {
				snapshot[blockNum].anchorBackfilled = true
			}
		}
		if pending.confirmations >= 1 && blockNum > maxConfirmed {
			maxConfirmed = blockNum
		}
		if pending.confirmations >= finalizedDepth {
			if blockNum > maxFinalized {
				maxFinalized = blockNum
			}
			toDrop = append(toDrop, blockNum)
		}
		// Loud warning when an anchor sits unconfirmed past the timeout.
		// We log once per anchor — the operator gets a single signal,
		// not a flood. The entry is NOT dropped: rebroadcasting via the
		// existing CovenantManager replaces the txid; if the BSV node
		// eventually mines the original tx, the next poll resolves it.
		if pending.confirmations == 0 && !pending.staleLogged &&
			!pending.trackedAt.IsZero() && now.Sub(pending.trackedAt) >= pendingAnchorTimeout {
			slog.Error("anchor pending past timeout; manual rebroadcast may be required",
				"block", blockNum,
				"txid", pending.txid.BSVString(),
				"age", now.Sub(pending.trackedAt).String(),
			)
			snapshot[blockNum].staleLogged = true
		}
	}

	w.mu.Lock()
	for blockNum, pending := range snapshot {
		if cur, ok := w.outstanding[blockNum]; ok {
			cur.confirmations = pending.confirmations
			cur.staleLogged = pending.staleLogged
			cur.anchorBackfilled = pending.anchorBackfilled
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

// backfillAnchor rewrites the persisted AnchorRecord with Confirmed=true
// and (when known) the BSV block height. It is idempotent: if the
// record already holds the same values, the call is a no-op. Returns
// true on success so the caller can flip pending.anchorBackfilled and
// avoid repeating the write each poll.
func (w *ConfirmationWatcher) backfillAnchor(blockNum uint64, txid types.Hash, height uint64) bool {
	if w.node == nil {
		return false
	}
	chainDB := w.node.ChainDB()
	if chainDB == nil {
		return false
	}
	existing := chainDB.ReadAnchorRecord(blockNum)
	if existing == nil {
		// ProcessBatch writes the record on broadcast; a missing record
		// here means either an out-of-band write race or a watcher that
		// somehow tracked a tx whose anchor was never persisted. Don't
		// invent one — the bridge withdrawer's finder treats absent
		// records as ErrAdvanceNotYetAnchored, which is the safe answer.
		slog.Warn("confirmation watcher: anchor record missing for confirmed tx",
			"block", blockNum, "txid", txid.BSVString())
		return false
	}
	// Defensive: if the persisted txid disagrees with what we tracked,
	// log and keep our tracked txid. ProcessBatch is the authoritative
	// writer; this branch only fires if some other path mutated the
	// record between broadcast and confirmation.
	if existing.BSVTxID != (types.Hash{}) && existing.BSVTxID != txid {
		slog.Warn("confirmation watcher: anchor record txid mismatch",
			"block", blockNum,
			"persisted", existing.BSVTxID.BSVString(),
			"tracked", txid.BSVString(),
		)
	}
	if existing.Confirmed && existing.BSVBlockHeight == height {
		return true // already up to date
	}
	updated := &block.AnchorRecord{
		L2BlockNum:     blockNum,
		BSVTxID:        txid,
		BSVBlockHeight: height,
		Confirmed:      true,
	}
	if err := chainDB.WriteAnchorRecord(updated); err != nil {
		slog.Warn("confirmation watcher: anchor backfill failed",
			"block", blockNum, "txid", txid.BSVString(), "error", err)
		return false
	}
	slog.Debug("anchor record backfilled",
		"block", blockNum, "txid", txid.BSVString(), "bsvHeight", height)
	return true
}
