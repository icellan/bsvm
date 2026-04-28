package overlay

import (
	"testing"
	"time"

	"github.com/icellan/bsvm/pkg/block"
	"github.com/icellan/bsvm/pkg/covenant"
	"github.com/icellan/bsvm/pkg/types"
)

// TestConfirmationWatcherBackfillsAnchorRecord verifies the watcher
// rewrites the persisted AnchorRecord with Confirmed=true once the
// broadcast txid has at least one BSV confirmation, and back-fills the
// BSV block height from the TransactionStatusSource. This is the
// production-side behaviour the bridge withdrawer's
// ChainDBAdvanceFinder gates claim-broadcast on (spec 09).
func TestConfirmationWatcherBackfillsAnchorRecord(t *testing.T) {
	ts := newTestSetup(t)
	defer ts.node.Stop()

	fake := covenant.NewFakeBroadcastClient()

	// Pre-populate the chain DB with an AnchorRecord matching what
	// ProcessBatch would have written: txid set, Confirmed=false,
	// height=0. This stands in for the broadcast having happened just
	// before the watcher polled.
	const blockNum uint64 = 42
	txid := types.BytesToHash([]byte{0x42, 0x42, 0x42})

	pre := &block.AnchorRecord{
		L2BlockNum:     blockNum,
		BSVTxID:        txid,
		BSVBlockHeight: 0,
		Confirmed:      false,
	}
	if err := ts.chainDB.WriteAnchorRecord(pre); err != nil {
		t.Fatalf("seed anchor: %v", err)
	}
	// Register the txid with the fake but leave it at 0 confirmations.
	fake.SetConfirmations(txid, 0)
	fake.SetBlockHeight(txid, 0)

	ts.node.StartConfirmationWatcher(fake, 20*time.Millisecond)
	defer func() {
		if w := ts.node.ConfirmationWatcherRef(); w != nil {
			w.Stop()
		}
	}()
	w := ts.node.ConfirmationWatcherRef()
	w.Track(blockNum, txid)

	// Phase 1: 0 confirmations — the record stays Confirmed=false.
	waitForCondition(t, 250*time.Millisecond, func() bool { return true })
	if rec := ts.chainDB.ReadAnchorRecord(blockNum); rec == nil {
		t.Fatal("anchor record disappeared")
	} else if rec.Confirmed {
		t.Fatalf("anchor incorrectly marked confirmed at 0 confs: %+v", rec)
	} else if rec.BSVBlockHeight != 0 {
		t.Fatalf("anchor height = %d at 0 confs, want 0", rec.BSVBlockHeight)
	}

	// Phase 2: drive to 1 confirmation + a known block height. The
	// watcher should flip Confirmed=true and store the height.
	const minedHeight uint64 = 800_000
	fake.SetConfirmations(txid, 1)
	fake.SetBlockHeight(txid, minedHeight)
	waitForCondition(t, 1*time.Second, func() bool {
		rec := ts.chainDB.ReadAnchorRecord(blockNum)
		return rec != nil && rec.Confirmed && rec.BSVBlockHeight == minedHeight
	})
	rec := ts.chainDB.ReadAnchorRecord(blockNum)
	if rec == nil {
		t.Fatal("anchor record missing after backfill")
	}
	if !rec.Confirmed {
		t.Fatalf("anchor not flipped to Confirmed=true: %+v", rec)
	}
	if rec.BSVBlockHeight != minedHeight {
		t.Fatalf("anchor height = %d, want %d", rec.BSVBlockHeight, minedHeight)
	}
	if rec.BSVTxID != txid {
		t.Fatalf("anchor txid = %s, want %s", rec.BSVTxID.BSVString(), txid.BSVString())
	}
}

// TestConfirmationWatcherSkipsBackfillWithoutRecord exercises the
// "missing record" branch: the watcher logs a warning but does NOT
// invent an anchor record, because the bridge finder's safe answer for
// "no record" is ErrAdvanceNotYetAnchored.
func TestConfirmationWatcherSkipsBackfillWithoutRecord(t *testing.T) {
	ts := newTestSetup(t)
	defer ts.node.Stop()

	fake := covenant.NewFakeBroadcastClient()
	const blockNum uint64 = 99
	txid := types.BytesToHash([]byte{0x99})
	fake.SetConfirmations(txid, 1)
	fake.SetBlockHeight(txid, 12345)

	ts.node.StartConfirmationWatcher(fake, 20*time.Millisecond)
	defer func() {
		if w := ts.node.ConfirmationWatcherRef(); w != nil {
			w.Stop()
		}
	}()
	w := ts.node.ConfirmationWatcherRef()
	w.Track(blockNum, txid)

	// Wait long enough for at least one poll. Confirm no anchor was
	// invented.
	waitForCondition(t, 250*time.Millisecond, func() bool { return true })
	if rec := ts.chainDB.ReadAnchorRecord(blockNum); rec != nil {
		t.Fatalf("watcher invented anchor for missing record: %+v", rec)
	}
}

// TestConfirmationWatcherBackfillIdempotent verifies that the watcher
// only rewrites the AnchorRecord once even if poll() runs many times
// after backfilling. We measure this by re-writing a sentinel value
// and confirming the watcher does not clobber it.
func TestConfirmationWatcherBackfillIdempotent(t *testing.T) {
	ts := newTestSetup(t)
	defer ts.node.Stop()

	fake := covenant.NewFakeBroadcastClient()
	const blockNum uint64 = 7
	txid := types.BytesToHash([]byte{0x07})

	pre := &block.AnchorRecord{
		L2BlockNum: blockNum,
		BSVTxID:    txid,
		Confirmed:  false,
	}
	if err := ts.chainDB.WriteAnchorRecord(pre); err != nil {
		t.Fatalf("seed: %v", err)
	}
	fake.SetConfirmations(txid, 2)
	fake.SetBlockHeight(txid, 100)

	ts.node.StartConfirmationWatcher(fake, 20*time.Millisecond)
	defer func() {
		if w := ts.node.ConfirmationWatcherRef(); w != nil {
			w.Stop()
		}
	}()
	w := ts.node.ConfirmationWatcherRef()
	w.Track(blockNum, txid)

	// Wait for the first backfill.
	waitForCondition(t, 1*time.Second, func() bool {
		rec := ts.chainDB.ReadAnchorRecord(blockNum)
		return rec != nil && rec.Confirmed && rec.BSVBlockHeight == 100
	})

	// Now stamp a sentinel value into the record (as if an operator
	// touched it) and confirm later poll cycles do NOT keep clobbering
	// it back. Use a far-off height so any clobber would change it.
	const sentinelHeight uint64 = 999_999_999
	if err := ts.chainDB.WriteAnchorRecord(&block.AnchorRecord{
		L2BlockNum: blockNum, BSVTxID: txid,
		BSVBlockHeight: sentinelHeight, Confirmed: true,
	}); err != nil {
		t.Fatalf("sentinel write: %v", err)
	}

	// Run a few more polls.
	time.Sleep(120 * time.Millisecond)

	rec := ts.chainDB.ReadAnchorRecord(blockNum)
	if rec == nil {
		t.Fatal("record disappeared")
	}
	if rec.BSVBlockHeight != sentinelHeight {
		t.Fatalf("watcher clobbered sentinel: height=%d want %d", rec.BSVBlockHeight, sentinelHeight)
	}
}
