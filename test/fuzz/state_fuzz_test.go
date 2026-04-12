package fuzz

import (
	"testing"

	"github.com/holiman/uint256"

	"github.com/icellan/bsvm/internal/db"
	"github.com/icellan/bsvm/pkg/state"
	"github.com/icellan/bsvm/pkg/types"
	"github.com/icellan/bsvm/pkg/vm/tracing"
)

// FuzzStateDBOperations applies a random sequence of StateDB mutations
// and verifies that: (1) no panics occur, and (2) the same sequence of
// operations always produces the same state root (determinism).
func FuzzStateDBOperations(f *testing.F) {
	// Each seed is a byte slice interpreted as a sequence of commands.
	// Command byte format:
	//   bits 7-5: operation (0=CreateAccount, 1=AddBalance, 2=SetNonce,
	//             3=SetCode, 4=SetState, 5=Snapshot, 6=Revert, 7=noop)
	//   bits 4-0: parameter index (selects address/value/key from a
	//             small fixed set)
	f.Add([]byte{0x00, 0x20, 0x40, 0x60, 0x80})
	f.Add([]byte{0x00, 0x20, 0xa0, 0xc0, 0x20}) // create, add, snapshot, revert, add
	f.Add([]byte{0x01, 0x21, 0x41, 0x61, 0x81})
	f.Add([]byte{0x00, 0x20, 0x40, 0x60, 0x80, 0xa0, 0xc0, 0x00, 0x20})
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, ops []byte) {
		// Limit operation count to prevent excessive runtime.
		if len(ops) > 200 {
			ops = ops[:200]
		}

		// Run the sequence twice on fresh trie-backed StateDBs.
		// Both must produce the same state root.
		root1 := runStateOps(t, ops)
		root2 := runStateOps(t, ops)

		if root1 != root2 {
			t.Fatalf("non-deterministic state root: first %s, second %s", root1.Hex(), root2.Hex())
		}
	})
}

// runStateOps executes a sequence of operations on a fresh trie-backed
// StateDB and returns the intermediate root after all operations.
func runStateOps(t *testing.T, ops []byte) types.Hash {
	t.Helper()

	diskdb := db.NewMemoryDB()
	sdb, err := state.New(types.Hash{}, diskdb)
	if err != nil {
		t.Fatalf("failed to create StateDB: %v", err)
	}

	// Fixed set of addresses, values, and keys.
	addrs := [4]types.Address{
		types.HexToAddress("0x1111111111111111111111111111111111111111"),
		types.HexToAddress("0x2222222222222222222222222222222222222222"),
		types.HexToAddress("0x3333333333333333333333333333333333333333"),
		types.HexToAddress("0x4444444444444444444444444444444444444444"),
	}
	amounts := [4]*uint256.Int{
		uint256.NewInt(0),
		uint256.NewInt(1),
		uint256.NewInt(1000),
		uint256.NewInt(999999999),
	}
	keys := [4]types.Hash{
		types.HexToHash("0x01"),
		types.HexToHash("0x02"),
		types.HexToHash("0xff"),
		types.HexToHash("0xdeadbeef"),
	}
	values := [4]types.Hash{
		{},
		types.HexToHash("0x01"),
		types.HexToHash("0xabcdef"),
		types.HexToHash("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
	}

	var snapshots []int

	for _, op := range ops {
		opCode := op >> 5       // 3 bits: operation
		param := int(op & 0x1f) // 5 bits: parameter index

		addrIdx := param % 4
		valIdx := (param / 4) % 4

		switch opCode {
		case 0: // CreateAccount
			sdb.CreateAccount(addrs[addrIdx])

		case 1: // AddBalance
			sdb.AddBalance(addrs[addrIdx], amounts[valIdx], tracing.BalanceChangeUnspecified)

		case 2: // SetNonce
			sdb.SetNonce(addrs[addrIdx], uint64(valIdx*10), tracing.NonceChangeUnspecified)

		case 3: // SetCode
			code := make([]byte, valIdx*8)
			for i := range code {
				code[i] = byte(addrIdx*16 + i%16)
			}
			sdb.SetCode(addrs[addrIdx], code, tracing.CodeChangeUnspecified)

		case 4: // SetState
			sdb.SetState(addrs[addrIdx], keys[valIdx], values[addrIdx])

		case 5: // Snapshot
			snap := sdb.Snapshot()
			snapshots = append(snapshots, snap)

		case 6: // Revert
			if len(snapshots) > 0 {
				idx := param % len(snapshots)
				sdb.RevertToSnapshot(snapshots[idx])
				// Invalidate snapshots after the reverted one.
				snapshots = snapshots[:idx]
			}

		default:
			// noop
		}
	}

	return sdb.IntermediateRoot(true)
}
