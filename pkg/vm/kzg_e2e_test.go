package vm

import (
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"testing"

	"github.com/holiman/uint256"

	"github.com/icellan/bsvm/pkg/crypto"
	"github.com/icellan/bsvm/pkg/types"
	"github.com/icellan/bsvm/pkg/vm/tracing"
)

// TestKZGEndToEnd tests the full pipeline: create an EVM, deploy a contract
// that calls the point evaluation precompile (0x0a) via STATICCALL, and
// verify the return data matches the expected output.
func TestKZGEndToEnd(t *testing.T) {
	// Initialize KZG trusted setup.
	if err := InitKZGTrustedSetup(""); err != nil {
		t.Fatalf("InitKZGTrustedSetup: %v", err)
	}
	if !crypto.KZGReady() {
		t.Fatal("KZG should be ready")
	}

	// Load the test vector for real input.
	data, err := os.ReadFile("testdata/precompiles/pointEvaluation.json")
	if err != nil {
		t.Fatalf("failed to read test vectors: %v", err)
	}
	var vectors []precompileTestVector
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatalf("failed to parse: %v", err)
	}
	if len(vectors) == 0 {
		t.Fatal("no test vectors")
	}
	inputHex := vectors[0].Input
	inputBytes, _ := hex.DecodeString(inputHex)

	// Create an in-memory StateDB mock.
	statedb := &kzgTestStateDB{
		accounts: make(map[types.Address]*kzgTestAccount),
	}

	// Fund the caller.
	caller := types.HexToAddress("0x1000000000000000000000000000000000000001")
	statedb.CreateAccount(caller)
	statedb.AddBalance(caller, uint256.NewInt(1e18), tracing.BalanceChangeUnspecified)

	// Create EVM with Cancun rules (point evaluation active).
	config := DefaultL2Config(1)
	blockCtx := BlockContext{
		CanTransfer: func(db StateDB, addr types.Address, amount *uint256.Int) bool {
			return db.GetBalance(addr).Cmp(amount) >= 0
		},
		Transfer: func(db StateDB, sender, recipient types.Address, amount *uint256.Int) {
			db.SubBalance(sender, amount, tracing.BalanceChangeTransfer)
			db.AddBalance(recipient, amount, tracing.BalanceChangeTransfer)
		},
		GetHash:     func(n uint64) types.Hash { return types.Hash{} },
		BlockNumber: big.NewInt(1),
		Time:        1000,
		Difficulty:  big.NewInt(0),
		BaseFee:     big.NewInt(0),
		BlobBaseFee: big.NewInt(1),
		GasLimit:    30_000_000,
	}
	evm := NewEVM(blockCtx, statedb, config, Config{})

	// STATICCALL to precompile 0x0a with the KZG test vector input.
	precompileAddr := types.BytesToAddress([]byte{0x0a})
	gas := uint64(100_000)

	ret, remainingGas, err := evm.StaticCall(caller, precompileAddr, inputBytes, gas)
	if err != nil {
		t.Fatalf("StaticCall to point evaluation precompile failed: %v", err)
	}

	// Verify gas consumption: 50000 for the precompile.
	gasUsed := gas - remainingGas
	if gasUsed < 50000 {
		t.Fatalf("expected at least 50000 gas used, got %d", gasUsed)
	}

	// Verify the return data matches expected.
	expectedOutput, _ := hex.DecodeString(vectors[0].Expected)
	if len(ret) != len(expectedOutput) {
		t.Fatalf("return data length: got %d, want %d", len(ret), len(expectedOutput))
	}
	for i := range ret {
		if ret[i] != expectedOutput[i] {
			t.Fatalf("return data mismatch at byte %d:\n  got:  %x\n  want: %x", i, ret, expectedOutput)
		}
	}
}

// TestKZGEndToEndInvalidProof verifies that a corrupted KZG proof causes
// the precompile to revert (return error), not silently succeed.
func TestKZGEndToEndInvalidProof(t *testing.T) {
	if err := InitKZGTrustedSetup(""); err != nil {
		t.Fatalf("InitKZGTrustedSetup: %v", err)
	}

	data, err := os.ReadFile("testdata/precompiles/pointEvaluation.json")
	if err != nil {
		t.Fatalf("failed to read test vectors: %v", err)
	}
	var vectors []precompileTestVector
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatalf("failed to parse: %v", err)
	}
	inputBytes, _ := hex.DecodeString(vectors[0].Input)

	// Corrupt the proof (last 48 bytes).
	corrupted := make([]byte, len(inputBytes))
	copy(corrupted, inputBytes)
	corrupted[191] ^= 0xff

	statedb := &kzgTestStateDB{
		accounts: make(map[types.Address]*kzgTestAccount),
	}
	caller := types.HexToAddress("0x1000000000000000000000000000000000000001")
	statedb.CreateAccount(caller)
	statedb.AddBalance(caller, uint256.NewInt(1e18), tracing.BalanceChangeUnspecified)

	config := DefaultL2Config(1)
	blockCtx := BlockContext{
		CanTransfer: func(db StateDB, addr types.Address, amount *uint256.Int) bool {
			return db.GetBalance(addr).Cmp(amount) >= 0
		},
		Transfer: func(db StateDB, sender, recipient types.Address, amount *uint256.Int) {},
		GetHash:     func(n uint64) types.Hash { return types.Hash{} },
		BlockNumber: big.NewInt(1),
		Time:        1000,
		Difficulty:  big.NewInt(0),
		BaseFee:     big.NewInt(0),
		BlobBaseFee: big.NewInt(1),
		GasLimit:    30_000_000,
	}
	evm := NewEVM(blockCtx, statedb, config, Config{})

	precompileAddr := types.BytesToAddress([]byte{0x0a})
	ret, _, err := evm.StaticCall(caller, precompileAddr, corrupted, 100_000)

	// The precompile should fail — ret should be nil/empty and err non-nil.
	if err == nil && len(ret) > 0 {
		t.Fatal("expected precompile to fail with corrupted proof, but it succeeded")
	}
}

// kzgTestStateDB is a minimal StateDB implementation for KZG E2E tests.
// It only implements the methods needed for StaticCall to a precompile.
type kzgTestStateDB struct {
	accounts map[types.Address]*kzgTestAccount
	refund   uint64
}

type kzgTestAccount struct {
	balance *uint256.Int
	nonce   uint64
	code    []byte
}

func (s *kzgTestStateDB) CreateAccount(addr types.Address) {
	s.accounts[addr] = &kzgTestAccount{balance: new(uint256.Int)}
}
func (s *kzgTestStateDB) CreateContract(addr types.Address) {}
func (s *kzgTestStateDB) Exist(addr types.Address) bool {
	_, ok := s.accounts[addr]
	return ok
}
func (s *kzgTestStateDB) Empty(addr types.Address) bool {
	a, ok := s.accounts[addr]
	if !ok {
		return true
	}
	return a.nonce == 0 && a.balance.IsZero() && len(a.code) == 0
}
func (s *kzgTestStateDB) GetBalance(addr types.Address) *uint256.Int {
	if a, ok := s.accounts[addr]; ok {
		return a.balance
	}
	return new(uint256.Int)
}
func (s *kzgTestStateDB) AddBalance(addr types.Address, amount *uint256.Int, _ tracing.BalanceChangeReason) uint256.Int {
	prev := s.GetBalance(addr).Clone()
	if a, ok := s.accounts[addr]; ok {
		a.balance = new(uint256.Int).Add(a.balance, amount)
	}
	return *prev
}
func (s *kzgTestStateDB) SubBalance(addr types.Address, amount *uint256.Int, _ tracing.BalanceChangeReason) uint256.Int {
	prev := s.GetBalance(addr).Clone()
	if a, ok := s.accounts[addr]; ok {
		a.balance = new(uint256.Int).Sub(a.balance, amount)
	}
	return *prev
}
func (s *kzgTestStateDB) GetNonce(addr types.Address) uint64 {
	if a, ok := s.accounts[addr]; ok {
		return a.nonce
	}
	return 0
}
func (s *kzgTestStateDB) SetNonce(addr types.Address, n uint64, _ tracing.NonceChangeReason) {
	if a, ok := s.accounts[addr]; ok {
		a.nonce = n
	}
}
func (s *kzgTestStateDB) GetCode(addr types.Address) []byte {
	if a, ok := s.accounts[addr]; ok {
		return a.code
	}
	return nil
}
func (s *kzgTestStateDB) SetCode(addr types.Address, code []byte, _ tracing.CodeChangeReason) []byte {
	prev := s.GetCode(addr)
	if a, ok := s.accounts[addr]; ok {
		a.code = code
	}
	return prev
}
func (s *kzgTestStateDB) GetCodeHash(addr types.Address) types.Hash {
	code := s.GetCode(addr)
	if len(code) == 0 {
		return types.EmptyCodeHash
	}
	return types.BytesToHash(crypto.Keccak256(code))
}
func (s *kzgTestStateDB) GetCodeSize(addr types.Address) int              { return len(s.GetCode(addr)) }
func (s *kzgTestStateDB) GetState(types.Address, types.Hash) types.Hash   { return types.Hash{} }
func (s *kzgTestStateDB) GetCommittedState(types.Address, types.Hash) types.Hash {
	return types.Hash{}
}
func (s *kzgTestStateDB) SetState(types.Address, types.Hash, types.Hash) types.Hash {
	return types.Hash{}
}
func (s *kzgTestStateDB) GetStorageRoot(types.Address) types.Hash { return types.EmptyRootHash }
func (s *kzgTestStateDB) GetTransientState(types.Address, types.Hash) types.Hash {
	return types.Hash{}
}
func (s *kzgTestStateDB) SetTransientState(types.Address, types.Hash, types.Hash) {}
func (s *kzgTestStateDB) SelfDestruct(types.Address)                               {}
func (s *kzgTestStateDB) HasSelfDestructed(types.Address) bool                     { return false }
func (s *kzgTestStateDB) Selfdestruct6780(types.Address)                           {}
func (s *kzgTestStateDB) AddLog(*types.Log)                                        {}
func (s *kzgTestStateDB) AddRefund(gas uint64)                                     { s.refund += gas }
func (s *kzgTestStateDB) SubRefund(gas uint64)                                     { s.refund -= gas }
func (s *kzgTestStateDB) GetRefund() uint64                                        { return s.refund }
func (s *kzgTestStateDB) AddPreimage(types.Hash, []byte)                           {}
func (s *kzgTestStateDB) AddressInAccessList(types.Address) bool                   { return false }
func (s *kzgTestStateDB) SlotInAccessList(types.Address, types.Hash) (bool, bool)  { return false, false }
func (s *kzgTestStateDB) AddAddressToAccessList(types.Address)                     {}
func (s *kzgTestStateDB) AddSlotToAccessList(types.Address, types.Hash)            {}
func (s *kzgTestStateDB) Snapshot() int                                            { return 0 }
func (s *kzgTestStateDB) RevertToSnapshot(int)                                     {}
func (s *kzgTestStateDB) Prepare(Rules, types.Address, types.Address, *types.Address, []types.Address, types.AccessList) {
}
