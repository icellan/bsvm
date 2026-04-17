package state

import (
	"testing"

	"github.com/holiman/uint256"

	"github.com/icellan/bsvm/pkg/types"
	"github.com/icellan/bsvm/pkg/vm/tracing"
)

// EIP-6780 (Cancun): SELFDESTRUCT only deletes the account if the contract
// was created in the same transaction. Otherwise the balance is still
// swept to the beneficiary but the account is preserved.
//
// These tests are parameterised over BOTH implementations. The full StateDB
// implements EIP-6780 correctly via the newContract flag and
// Selfdestruct6780. MemoryStateDB has a divergent SelfDestruct that does
// not check the created flag; the assertions below document that
// divergence.

// sdbLike is the subset of StateDB operations the EIP-6780 tests exercise.
// Both *StateDB and *MemoryStateDB satisfy it.
type sdbLike interface {
	CreateAccount(addr types.Address)
	CreateContract(addr types.Address)
	AddBalance(addr types.Address, amount *uint256.Int, reason tracing.BalanceChangeReason) uint256.Int
	GetBalance(addr types.Address) *uint256.Int
	Snapshot() int
	RevertToSnapshot(id int)
	SelfDestruct(addr types.Address)
	Selfdestruct6780(addr types.Address)
	HasSelfDestructed(addr types.Address) bool
	Exist(addr types.Address) bool
}

// finaliseLike is implemented by both StateDB and MemoryStateDB. We use
// it to materialise the self-destruct deletion at tx boundary.
type finaliseLike interface {
	Finalise(deleteEmptyObjects bool)
}

func newFullStateDB(t *testing.T) sdbLike {
	t.Helper()
	return newTestStateDB(t)
}

func newMemStateDB(_ *testing.T) sdbLike {
	return NewMemoryStateDB()
}

type sdbFactory struct {
	name string
	make func(t *testing.T) sdbLike
}

func stateDBFactories() []sdbFactory {
	return []sdbFactory{
		{name: "StateDB", make: newFullStateDB},
		{name: "MemoryStateDB", make: newMemStateDB},
	}
}

// TestEIP6780_CreatedSameTx_IsDestroyed verifies that a contract created in
// the same tx and then SELFDESTRUCTed via Selfdestruct6780 is actually
// destroyed after Finalise.
func TestEIP6780_CreatedSameTx_IsDestroyed(t *testing.T) {
	for _, f := range stateDBFactories() {
		t.Run(f.name, func(t *testing.T) {
			sdb := f.make(t)
			addr := types.HexToAddress("0x0000000000000000000000000000000000006780")

			// Simulate CREATE: new account, mark as newly created contract,
			// fund it.
			sdb.CreateAccount(addr)
			sdb.CreateContract(addr)
			sdb.AddBalance(addr, uint256.NewInt(500), tracing.BalanceChangeUnspecified)

			// Fire EIP-6780 selfdestruct. Must actually destroy because
			// created-in-same-tx.
			sdb.Selfdestruct6780(addr)

			if !sdb.HasSelfDestructed(addr) {
				t.Fatalf("%s: expected selfDestructed flag after Selfdestruct6780 on same-tx contract", f.name)
			}
			if got := sdb.GetBalance(addr); !got.IsZero() {
				t.Fatalf("%s: balance must be zero after selfdestruct, got %s", f.name, got)
			}

			// After Finalise, the account should no longer exist.
			fin, ok := sdb.(finaliseLike)
			if !ok {
				t.Fatalf("%s: does not implement Finalise", f.name)
			}
			fin.Finalise(true)
			if sdb.Exist(addr) {
				t.Fatalf("%s: account must be deleted after Finalise", f.name)
			}
		})
	}
}

// TestEIP6780_PreExisting_IsPreservedOnSelfdestruct6780 verifies that a
// pre-existing contract (not created in the same tx) survives a
// Selfdestruct6780 call — balance is still swept, but the account stays.
//
// MemoryStateDB correctly implements Selfdestruct6780 (checks `created`)
// but `created` is ONLY set by CreateContract. In both implementations,
// Selfdestruct6780 on a pre-existing account must be a near no-op.
func TestEIP6780_PreExisting_IsPreservedOnSelfdestruct6780(t *testing.T) {
	for _, f := range stateDBFactories() {
		t.Run(f.name, func(t *testing.T) {
			sdb := f.make(t)
			addr := types.HexToAddress("0x00000000000000000000000000000000067800a1")

			// Fund and mark as committed (simulate pre-existing state).
			sdb.CreateAccount(addr)
			sdb.AddBalance(addr, uint256.NewInt(1000), tracing.BalanceChangeUnspecified)

			// Flush: Finalise moves this out of "just-created" scope.
			// For MemoryStateDB, we must also ensure `created` is not
			// set. The StateDB side never set newContract because
			// CreateContract was never called.
			if fin, ok := sdb.(finaliseLike); ok {
				fin.Finalise(false)
			}

			// Now call Selfdestruct6780: must NOT destroy.
			sdb.Selfdestruct6780(addr)

			if sdb.HasSelfDestructed(addr) {
				t.Fatalf("%s: Selfdestruct6780 must NOT mark pre-existing account", f.name)
			}
			if got := sdb.GetBalance(addr); got.Uint64() != 1000 {
				t.Fatalf("%s: balance on pre-existing account must be untouched by Selfdestruct6780, got %s", f.name, got)
			}
		})
	}
}

// TestEIP6780_PreExisting_LegacySelfDestruct verifies the geth-compatible
// "legacy" SelfDestruct path on a pre-existing (not-created-same-tx)
// account: the account's balance must be zeroed and the selfDestructed
// flag set. The account is preserved until Finalise though.
//
// The full StateDB performs the balance-zeroing inside SelfDestruct. The
// MemoryStateDB does the same; BUT MemoryStateDB does NOT guard
// Selfdestruct6780 on the created flag the way full StateDB does. This
// test documents the canonical legacy SelfDestruct behaviour on both.
func TestEIP6780_PreExisting_LegacySelfDestruct(t *testing.T) {
	for _, f := range stateDBFactories() {
		t.Run(f.name, func(t *testing.T) {
			sdb := f.make(t)
			addr := types.HexToAddress("0x00000000000000000000000000000000067800b2")
			sdb.CreateAccount(addr)
			sdb.AddBalance(addr, uint256.NewInt(777), tracing.BalanceChangeUnspecified)

			sdb.SelfDestruct(addr)
			if !sdb.HasSelfDestructed(addr) {
				t.Fatalf("%s: expected selfDestructed flag after legacy SelfDestruct", f.name)
			}
			if got := sdb.GetBalance(addr); !got.IsZero() {
				t.Fatalf("%s: balance must be zeroed by SelfDestruct, got %s", f.name, got)
			}
		})
	}
}

// TestEIP6780_CreateSnapshotDestroyRevertDestroy exercises the journal
// roundtrip: create a contract in the same tx, snapshot, selfDestruct,
// revert, then selfDestruct again. The EIP-6780 newContract flag MUST
// survive the snapshot/revert cycle so the second Selfdestruct6780 call
// still destroys the account.
//
// This is exactly the path that motivates the
// `createContractChange.dirtied()` review finding: if the journal drops
// the revert, the flag ends up false and the second call becomes a no-op.
func TestEIP6780_CreateSnapshotDestroyRevertDestroy(t *testing.T) {
	for _, f := range stateDBFactories() {
		t.Run(f.name, func(t *testing.T) {
			sdb := f.make(t)
			addr := types.HexToAddress("0x00000000000000000000000000000000067800c3")

			sdb.CreateAccount(addr)
			sdb.CreateContract(addr)
			sdb.AddBalance(addr, uint256.NewInt(9000), tracing.BalanceChangeUnspecified)

			snap := sdb.Snapshot()

			// First selfdestruct: succeeds because created-same-tx.
			sdb.Selfdestruct6780(addr)
			if !sdb.HasSelfDestructed(addr) {
				t.Fatalf("%s: first Selfdestruct6780 did not mark account", f.name)
			}

			// Revert the selfdestruct.
			sdb.RevertToSnapshot(snap)
			if sdb.HasSelfDestructed(addr) {
				t.Fatalf("%s: selfDestructed flag must be reverted by RevertToSnapshot", f.name)
			}
			if got := sdb.GetBalance(addr); got.Uint64() != 9000 {
				t.Fatalf("%s: balance must be restored after revert, got %s", f.name, got)
			}

			// Now selfdestruct again — the newContract flag must still be
			// true, so the second call must again destroy.
			sdb.Selfdestruct6780(addr)
			if !sdb.HasSelfDestructed(addr) {
				t.Fatalf("%s: second Selfdestruct6780 failed — newContract flag lost across revert", f.name)
			}
		})
	}
}

// TestEIP6780_MemoryStateDB_SelfDestructIgnoresCreatedFlag documents a
// known divergence: MemoryStateDB.SelfDestruct() does NOT enforce the
// EIP-6780 `created` guard (the guard lives on Selfdestruct6780 only).
// The full StateDB's SelfDestruct also does not enforce EIP-6780 — legacy
// SELFDESTRUCT is intentionally unconditional, EIP-6780 is a separate
// op. This test pins the behaviour so future changes are intentional.
func TestEIP6780_LegacySelfDestruct_UnconditionalOnBothImpls(t *testing.T) {
	for _, f := range stateDBFactories() {
		t.Run(f.name, func(t *testing.T) {
			sdb := f.make(t)
			addr := types.HexToAddress("0x00000000000000000000000000000000067800d4")

			// Pre-existing account, not created-this-tx.
			sdb.CreateAccount(addr)
			sdb.AddBalance(addr, uint256.NewInt(333), tracing.BalanceChangeUnspecified)
			if fin, ok := sdb.(finaliseLike); ok {
				fin.Finalise(false)
			}

			// Legacy SelfDestruct: unconditionally marks destructed.
			sdb.SelfDestruct(addr)
			if !sdb.HasSelfDestructed(addr) {
				t.Fatalf("%s: legacy SelfDestruct must unconditionally mark the account", f.name)
			}
		})
	}
}
