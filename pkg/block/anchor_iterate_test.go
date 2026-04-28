package block

import (
	"context"
	"errors"
	"testing"

	"github.com/icellan/bsvm/internal/db"
	"github.com/icellan/bsvm/pkg/types"
)

// TestChainDB_IterateAnchorRecords_Order asserts that the iterator
// surfaces every persisted anchor in ascending L2-block-number order.
// Encoding the block number big-endian under the "a" prefix is what
// gives us this property for free; the test pins it so a key-format
// regression breaks loudly.
func TestChainDB_IterateAnchorRecords_Order(t *testing.T) {
	chainDB := NewChainDB(db.NewMemoryDB())

	// Insert out of order on purpose so we can assert that iteration
	// re-orders to ascending.
	insertOrder := []uint64{42, 1, 7, 256, 100}
	for _, n := range insertOrder {
		rec := &AnchorRecord{
			L2BlockNum: n,
			BSVTxID:    types.HexToHash("0x01"),
		}
		if err := chainDB.WriteAnchorRecord(rec); err != nil {
			t.Fatalf("WriteAnchorRecord(%d): %v", n, err)
		}
	}

	var got []uint64
	err := chainDB.IterateAnchorRecords(context.Background(), func(r *AnchorRecord) bool {
		got = append(got, r.L2BlockNum)
		return true
	})
	if err != nil {
		t.Fatalf("IterateAnchorRecords: %v", err)
	}

	want := []uint64{1, 7, 42, 100, 256}
	if len(got) != len(want) {
		t.Fatalf("got %d records, want %d", len(got), len(want))
	}
	for i, n := range want {
		if got[i] != n {
			t.Fatalf("got[%d] = %d, want %d (full got=%v)", i, got[i], n, got)
		}
	}
}

// TestChainDB_IterateAnchorRecords_EarlyStop verifies the callback can
// halt iteration by returning false. The remaining records must NOT be
// surfaced.
func TestChainDB_IterateAnchorRecords_EarlyStop(t *testing.T) {
	chainDB := NewChainDB(db.NewMemoryDB())
	for _, n := range []uint64{1, 2, 3, 4, 5} {
		if err := chainDB.WriteAnchorRecord(&AnchorRecord{L2BlockNum: n}); err != nil {
			t.Fatalf("WriteAnchorRecord(%d): %v", n, err)
		}
	}

	var seen int
	err := chainDB.IterateAnchorRecords(context.Background(), func(r *AnchorRecord) bool {
		seen++
		return seen < 3 // stop after the third record
	})
	if err != nil {
		t.Fatalf("IterateAnchorRecords: %v", err)
	}
	if seen != 3 {
		t.Fatalf("seen = %d, want 3 (early-stop didn't halt)", seen)
	}
}

// TestChainDB_IterateAnchorRecords_CtxCancel verifies the iterator
// surfaces ctx.Err() when the caller cancels mid-walk.
func TestChainDB_IterateAnchorRecords_CtxCancel(t *testing.T) {
	chainDB := NewChainDB(db.NewMemoryDB())
	for _, n := range []uint64{1, 2, 3} {
		if err := chainDB.WriteAnchorRecord(&AnchorRecord{L2BlockNum: n}); err != nil {
			t.Fatalf("WriteAnchorRecord(%d): %v", n, err)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	err := chainDB.IterateAnchorRecords(ctx, func(r *AnchorRecord) bool {
		t.Fatalf("callback should not fire on a pre-cancelled context, got %v", r)
		return true
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}

// TestChainDB_IterateAnchorRecords_Empty verifies empty DB walks are
// non-error no-ops.
func TestChainDB_IterateAnchorRecords_Empty(t *testing.T) {
	chainDB := NewChainDB(db.NewMemoryDB())
	called := false
	err := chainDB.IterateAnchorRecords(context.Background(), func(r *AnchorRecord) bool {
		called = true
		return true
	})
	if err != nil {
		t.Fatalf("IterateAnchorRecords on empty DB: %v", err)
	}
	if called {
		t.Fatal("callback fired on empty DB")
	}
}
