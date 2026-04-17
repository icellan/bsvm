package state

import (
	"testing"

	"github.com/icellan/bsvm/pkg/types"
)

// transientSDB is the intersection of the transient-storage APIs on the
// full StateDB and the MemoryStateDB.
type transientSDB interface {
	SetTransientState(addr types.Address, key, value types.Hash)
	GetTransientState(addr types.Address, key types.Hash) types.Hash
	Snapshot() int
	RevertToSnapshot(id int)
}

// TestTransientStorage_RevertToPreviousValue exercises EIP-1153 transient
// storage revert semantics on BOTH StateDB implementations:
//
//   - TSTORE value A
//   - Snapshot
//   - TSTORE value B
//   - Revert
//   - TLOAD must return A (not B, and not zero)
//
// The full StateDB implements this via transientStorageChange in the
// journal. MemoryStateDB's memorySnapshot does NOT include transient
// storage, so it currently fails this test. The MemoryStateDB sub-test
// is skipped with a TODO pending that fix.
func TestTransientStorage_RevertToPreviousValue(t *testing.T) {
	cases := []struct {
		name    string
		make    func(t *testing.T) transientSDB
		skipMsg string
	}{
		{
			name: "StateDB",
			make: func(t *testing.T) transientSDB {
				return newTestStateDB(t)
			},
		},
		{
			name: "MemoryStateDB",
			make: func(t *testing.T) transientSDB {
				return NewMemoryStateDB()
			},
		},
	}

	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			if c.skipMsg != "" {
				t.Skip(c.skipMsg)
			}
			sdb := c.make(t)
			addr := types.HexToAddress("0x0000000000000000000000000000000000001153")
			key := types.HexToHash("0xbeef")
			valueA := types.HexToHash("0xaa")
			valueB := types.HexToHash("0xbb")

			sdb.SetTransientState(addr, key, valueA)
			if got := sdb.GetTransientState(addr, key); got != valueA {
				t.Fatalf("%s: initial TLOAD mismatch, got %s want %s", c.name, got, valueA)
			}

			snap := sdb.Snapshot()
			sdb.SetTransientState(addr, key, valueB)
			if got := sdb.GetTransientState(addr, key); got != valueB {
				t.Fatalf("%s: TLOAD after second TSTORE mismatch, got %s want %s", c.name, got, valueB)
			}

			sdb.RevertToSnapshot(snap)
			if got := sdb.GetTransientState(addr, key); got != valueA {
				t.Fatalf("%s: TLOAD after revert must return prior value; got %s want %s", c.name, got, valueA)
			}
		})
	}
}

// TestTransientStorage_RevertToUnset checks that TSTORE followed by
// snapshot+revert correctly revert to the unset (zero) value.
func TestTransientStorage_RevertToUnset(t *testing.T) {
	cases := []struct {
		name    string
		make    func(t *testing.T) transientSDB
		skipMsg string
	}{
		{
			name: "StateDB",
			make: func(t *testing.T) transientSDB { return newTestStateDB(t) },
		},
		{
			name: "MemoryStateDB",
			make: func(t *testing.T) transientSDB {
				return NewMemoryStateDB()
			},
		},
	}

	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			if c.skipMsg != "" {
				t.Skip(c.skipMsg)
			}
			sdb := c.make(t)
			addr := types.HexToAddress("0x0000000000000000000000000000000000001154")
			key := types.HexToHash("0xcafe")
			val := types.HexToHash("0x42")

			snap := sdb.Snapshot()
			sdb.SetTransientState(addr, key, val)
			if got := sdb.GetTransientState(addr, key); got != val {
				t.Fatalf("%s: TLOAD after TSTORE mismatch, got %s want %s", c.name, got, val)
			}
			sdb.RevertToSnapshot(snap)
			if got := sdb.GetTransientState(addr, key); got != (types.Hash{}) {
				t.Fatalf("%s: TLOAD after revert must be zero, got %s", c.name, got)
			}
		})
	}
}
