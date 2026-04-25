package state

import (
	"testing"

	"github.com/icellan/bsvm/pkg/types"
)

// TestSnapshotNoDepthLimit verifies that the journal does NOT enforce a
// snapshot depth limit. Geth does not limit snapshot depth — the EVM
// call depth (1024) is the natural guard. Snapshots can legitimately
// exceed 1024 because the test runner, precompiles, and other callers
// also take snapshots outside the EVM call stack.
func TestSnapshotNoDepthLimit(t *testing.T) {
	j := newJournal()

	// Create 2000 snapshots — well past 1024. Must not panic.
	for i := 0; i < 2000; i++ {
		j.snapshot()
	}

	if len(j.validRevisions) != 2000 {
		t.Fatalf("expected 2000 valid revisions, got %d", len(j.validRevisions))
	}
}

func TestSnapshotRevertFreesDepth(t *testing.T) {
	j := newJournal()
	s := &StateDB{
		stateObjects: make(map[types.Address]*stateObject),
	}

	// Create 100 snapshots.
	var ids []int
	for i := 0; i < 100; i++ {
		ids = append(ids, j.snapshot())
	}

	// Revert to the 50th snapshot (id at index 49), removing snapshots 50-99.
	j.revertToSnapshot(ids[49], s)

	if len(j.validRevisions) != 49 {
		t.Fatalf("expected 49 valid revisions after revert, got %d", len(j.validRevisions))
	}

	// Create more snapshots after revert.
	for i := 0; i < 100; i++ {
		j.snapshot()
	}

	if len(j.validRevisions) != 149 {
		t.Fatalf("expected 149 valid revisions, got %d", len(j.validRevisions))
	}
}

func TestRevertInvalidSnapshotDoesNotCrash(t *testing.T) {
	j := newJournal()
	s := &StateDB{
		stateObjects: make(map[types.Address]*stateObject),
	}

	j.snapshot() // id 0
	j.snapshot() // id 1

	// Revert to a non-existent revision id — should log a warning, not crash.
	j.revertToSnapshot(999, s)

	if len(j.validRevisions) != 2 {
		t.Fatalf("expected 2 valid revisions, got %d", len(j.validRevisions))
	}
}

func TestRevertStaleSnapshotDoesNotCrash(t *testing.T) {
	j := newJournal()
	s := &StateDB{
		stateObjects: make(map[types.Address]*stateObject),
	}

	j.snapshot()        // id 0
	id1 := j.snapshot() // id 1
	id2 := j.snapshot() // id 2

	// Revert to snapshot 1 — removes snapshots at index 1 and beyond.
	j.revertToSnapshot(id1, s)

	// Now try reverting to snapshot 2 which is stale — should be a no-op.
	j.revertToSnapshot(id2, s)

	if len(j.validRevisions) != 1 {
		t.Fatalf("expected 1 valid revision after stale revert, got %d", len(j.validRevisions))
	}
}
