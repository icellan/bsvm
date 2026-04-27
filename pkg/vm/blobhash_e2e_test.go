package vm

// End-to-end test for the EIP-4844 BLOBHASH opcode (0x49). The opcode
// must be present and active under the Cancun rule set, returning the
// indexed versioned hash from TxContext.BlobHashes (or zero when the
// index is out of range). This test pins both the active-under-Cancun
// fork-activation contract AND the round-trip from TxContext through
// the interpreter.

import (
	"math/big"
	"testing"

	"github.com/holiman/uint256"

	"github.com/icellan/bsvm/pkg/types"
	"github.com/icellan/bsvm/pkg/vm/tracing"
)

// blobhashCode is the runtime bytecode for a leaf contract that
// returns blobhash(0) at memory offset 0. Sequence:
//
//	PUSH1 0x00   (index 0)
//	BLOBHASH     (0x49)  pop index, push versioned_hash
//	PUSH1 0x00   (mem offset)
//	MSTORE       store hash at mem[0..32]
//	PUSH1 0x20   (length 32)
//	PUSH1 0x00   (offset 0)
//	RETURN
var blobhashCode = []byte{
	0x60, 0x00,
	0x49,
	0x60, 0x00,
	0x52,
	0x60, 0x20,
	0x60, 0x00,
	0xf3,
}

func newBlobHashTestEVM(t *testing.T, blobHashes []types.Hash) (*EVM, types.Address, types.Address) {
	t.Helper()

	statedb := &kzgTestStateDB{accounts: make(map[types.Address]*kzgTestAccount)}

	caller := types.HexToAddress("0x1000000000000000000000000000000000000001")
	statedb.CreateAccount(caller)
	statedb.AddBalance(caller, uint256.NewInt(1e18), tracing.BalanceChangeUnspecified)

	contract := types.HexToAddress("0x2000000000000000000000000000000000000002")
	statedb.CreateAccount(contract)
	statedb.SetCode(contract, blobhashCode, tracing.CodeChangeCreation)

	config := DefaultL2Config(1)
	blockCtx := BlockContext{
		CanTransfer: func(db StateDB, addr types.Address, amount *uint256.Int) bool {
			return db.GetBalance(addr).Cmp(amount) >= 0
		},
		Transfer:    func(db StateDB, sender, recipient types.Address, amount *uint256.Int) {},
		GetHash:     func(n uint64) types.Hash { return types.Hash{} },
		BlockNumber: big.NewInt(1),
		Time:        1000,
		Difficulty:  big.NewInt(0),
		BaseFee:     big.NewInt(0),
		BlobBaseFee: big.NewInt(1),
		GasLimit:    30_000_000,
	}
	evm := NewEVM(blockCtx, statedb, config, Config{})
	// BlobHashes lives on the per-tx context, NOT the block context,
	// so install it via the public TxContext field on the EVM. Same
	// shape as the txContext path the block executor uses.
	evm.TxContext.BlobHashes = blobHashes
	return evm, caller, contract
}

// TestBLOBHASHReturnsVersionedHash exercises the canonical case: the
// transaction carries one blob_versioned_hash, the contract calls
// blobhash(0), and the returned 32 bytes must equal that hash. This
// pins:
//
//  1. The Cancun jump table activates BLOBHASH (else the call traps
//     with invalid opcode).
//  2. The interpreter routes blobhash(idx) to TxContext.BlobHashes.
//  3. Versioned hashes survive the journey from tx → TxContext →
//     opBlobHash → memory → return data.
func TestBLOBHASHReturnsVersionedHash(t *testing.T) {
	want := types.HexToHash("0x010000000000000000000000000000000000000000000000000000000000abcd")
	evm, caller, contract := newBlobHashTestEVM(t, []types.Hash{want})

	ret, _, err := evm.Call(caller, contract, nil, 100_000, uint256.NewInt(0))
	if err != nil {
		t.Fatalf("Call to BLOBHASH leaf contract failed: %v", err)
	}
	if len(ret) != 32 {
		t.Fatalf("BLOBHASH returndata length = %d, want 32", len(ret))
	}
	got := types.BytesToHash(ret)
	if got != want {
		t.Fatalf("BLOBHASH(0) = %s, want %s", got.Hex(), want.Hex())
	}
}

// TestBLOBHASHOutOfRangeReturnsZero pins EIP-4844's "out of range
// returns zero" semantic: a tx with no blob hashes still allows
// BLOBHASH(0) to execute — it just returns 32 zero bytes. Contracts
// ported from L1 rely on this to avoid trapping when called on a
// non-blob tx.
func TestBLOBHASHOutOfRangeReturnsZero(t *testing.T) {
	evm, caller, contract := newBlobHashTestEVM(t, nil)

	ret, _, err := evm.Call(caller, contract, nil, 100_000, uint256.NewInt(0))
	if err != nil {
		t.Fatalf("Call to BLOBHASH leaf contract failed: %v", err)
	}
	if len(ret) != 32 {
		t.Fatalf("BLOBHASH returndata length = %d, want 32", len(ret))
	}
	for i, b := range ret {
		if b != 0 {
			t.Fatalf("BLOBHASH(0) on empty BlobHashes byte %d = 0x%02x, want 0x00", i, b)
		}
	}
}

// TestBLOBHASHIndexedReturnsCorrectHash confirms multi-blob indexing
// returns the right element. The opcode reads the index from the
// stack; the interpreter must apply it to TxContext.BlobHashes
// element-wise.
func TestBLOBHASHIndexedReturnsCorrectHash(t *testing.T) {
	hashes := []types.Hash{
		types.HexToHash("0x0100000000000000000000000000000000000000000000000000000000000001"),
		types.HexToHash("0x0100000000000000000000000000000000000000000000000000000000000002"),
		types.HexToHash("0x0100000000000000000000000000000000000000000000000000000000000003"),
	}

	// Bytecode that returns blobhash(2). PUSH1 0x02 BLOBHASH PUSH1 0x00
	// MSTORE PUSH1 0x20 PUSH1 0x00 RETURN
	code := []byte{
		0x60, 0x02,
		0x49,
		0x60, 0x00,
		0x52,
		0x60, 0x20,
		0x60, 0x00,
		0xf3,
	}

	statedb := &kzgTestStateDB{accounts: make(map[types.Address]*kzgTestAccount)}
	caller := types.HexToAddress("0x1000000000000000000000000000000000000001")
	statedb.CreateAccount(caller)
	statedb.AddBalance(caller, uint256.NewInt(1e18), tracing.BalanceChangeUnspecified)
	contract := types.HexToAddress("0x2000000000000000000000000000000000000002")
	statedb.CreateAccount(contract)
	statedb.SetCode(contract, code, tracing.CodeChangeCreation)

	config := DefaultL2Config(1)
	blockCtx := BlockContext{
		CanTransfer: func(db StateDB, addr types.Address, amount *uint256.Int) bool {
			return db.GetBalance(addr).Cmp(amount) >= 0
		},
		Transfer:    func(db StateDB, sender, recipient types.Address, amount *uint256.Int) {},
		GetHash:     func(n uint64) types.Hash { return types.Hash{} },
		BlockNumber: big.NewInt(1),
		Time:        1000,
		Difficulty:  big.NewInt(0),
		BaseFee:     big.NewInt(0),
		BlobBaseFee: big.NewInt(1),
		GasLimit:    30_000_000,
	}
	evm := NewEVM(blockCtx, statedb, config, Config{})
	evm.TxContext.BlobHashes = hashes

	ret, _, err := evm.Call(caller, contract, nil, 100_000, uint256.NewInt(0))
	if err != nil {
		t.Fatalf("Call to BLOBHASH(2) contract failed: %v", err)
	}
	got := types.BytesToHash(ret)
	if got != hashes[2] {
		t.Fatalf("BLOBHASH(2) = %s, want %s", got.Hex(), hashes[2].Hex())
	}
}
