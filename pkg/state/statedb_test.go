package state

import (
	"bytes"
	"testing"

	"github.com/holiman/uint256"

	"github.com/icellan/bsvm/internal/db"
	"github.com/icellan/bsvm/pkg/crypto"
	"github.com/icellan/bsvm/pkg/rlp"
	"github.com/icellan/bsvm/pkg/types"
	"github.com/icellan/bsvm/pkg/vm"
	"github.com/icellan/bsvm/pkg/vm/tracing"
)

// Compile-time interface checks.
var _ vm.StateDB = (*StateDB)(nil)
var _ vm.StateDB = (*MemoryStateDB)(nil)

func newTestStateDB(t *testing.T) *StateDB {
	t.Helper()
	diskdb := db.NewMemoryDB()
	sdb, err := New(types.Hash{}, diskdb)
	if err != nil {
		t.Fatalf("failed to create StateDB: %v", err)
	}
	return sdb
}

// TestAccountRLPRoundTrip verifies that Account RLP encoding/decoding is
// compatible with geth's format.
func TestAccountRLPRoundTrip(t *testing.T) {
	acct := Account{
		Nonce:    42,
		Balance:  uint256.NewInt(1000000),
		Root:     types.EmptyRootHash,
		CodeHash: types.EmptyCodeHash.Bytes(),
	}
	encoded, err := rlp.EncodeToBytes(&acct)
	if err != nil {
		t.Fatalf("encode failed: %v", err)
	}

	var decoded Account
	if err := rlp.DecodeBytes(encoded, &decoded); err != nil {
		t.Fatalf("decode failed: %v", err)
	}

	if decoded.Nonce != acct.Nonce {
		t.Errorf("nonce mismatch: got %d, want %d", decoded.Nonce, acct.Nonce)
	}
	if decoded.Balance.Cmp(acct.Balance) != 0 {
		t.Errorf("balance mismatch: got %s, want %s", decoded.Balance, acct.Balance)
	}
	if decoded.Root != acct.Root {
		t.Errorf("root mismatch: got %s, want %s", decoded.Root, acct.Root)
	}
	if !bytes.Equal(decoded.CodeHash, acct.CodeHash) {
		t.Errorf("codeHash mismatch: got %x, want %x", decoded.CodeHash, acct.CodeHash)
	}
}

// TestAccountRLPZeroBalance verifies that a zero-balance account encodes correctly.
func TestAccountRLPZeroBalance(t *testing.T) {
	acct := newAccount()
	encoded, err := rlp.EncodeToBytes(&acct)
	if err != nil {
		t.Fatalf("encode failed: %v", err)
	}

	var decoded Account
	if err := rlp.DecodeBytes(encoded, &decoded); err != nil {
		t.Fatalf("decode failed: %v", err)
	}

	if !decoded.Balance.IsZero() {
		t.Errorf("expected zero balance, got %s", decoded.Balance)
	}
}

// TestBasicAccountOperations tests creating accounts and modifying balance,
// nonce, and code.
func TestBasicAccountOperations(t *testing.T) {
	sdb := newTestStateDB(t)
	addr := types.HexToAddress("0x1234567890abcdef1234567890abcdef12345678")

	// Account should not exist yet.
	if sdb.Exist(addr) {
		t.Error("account should not exist before creation")
	}
	if !sdb.Empty(addr) {
		t.Error("non-existent account should be empty")
	}

	// Create account.
	sdb.CreateAccount(addr)
	if !sdb.Exist(addr) {
		t.Error("account should exist after creation")
	}
	if !sdb.Empty(addr) {
		t.Error("newly created account should be empty")
	}

	// Balance.
	if sdb.GetBalance(addr).Sign() != 0 {
		t.Error("initial balance should be zero")
	}
	prev := sdb.AddBalance(addr, uint256.NewInt(100), tracing.BalanceChangeUnspecified)
	if !prev.IsZero() {
		t.Errorf("expected previous balance 0, got %s", &prev)
	}
	if sdb.GetBalance(addr).Uint64() != 100 {
		t.Errorf("expected balance 100, got %s", sdb.GetBalance(addr))
	}
	prev = sdb.SubBalance(addr, uint256.NewInt(30), tracing.BalanceChangeUnspecified)
	if prev.Uint64() != 100 {
		t.Errorf("expected previous balance 100, got %s", &prev)
	}
	if sdb.GetBalance(addr).Uint64() != 70 {
		t.Errorf("expected balance 70, got %s", sdb.GetBalance(addr))
	}

	// Nonce.
	if sdb.GetNonce(addr) != 0 {
		t.Error("initial nonce should be zero")
	}
	sdb.SetNonce(addr, 5, tracing.NonceChangeTransaction)
	if sdb.GetNonce(addr) != 5 {
		t.Errorf("expected nonce 5, got %d", sdb.GetNonce(addr))
	}

	// Code.
	if sdb.GetCode(addr) != nil {
		t.Error("initial code should be nil")
	}
	if sdb.GetCodeHash(addr) != types.EmptyCodeHash {
		t.Error("initial code hash should be empty code hash")
	}
	code := []byte{0x60, 0x00, 0x60, 0x00, 0xfd} // PUSH1 0 PUSH1 0 REVERT
	prevCode := sdb.SetCode(addr, code, tracing.CodeChangeCreation)
	if prevCode != nil {
		t.Error("previous code should be nil")
	}
	if !bytes.Equal(sdb.GetCode(addr), code) {
		t.Error("code mismatch after SetCode")
	}
	expectedHash := types.BytesToHash(crypto.Keccak256(code))
	if sdb.GetCodeHash(addr) != expectedHash {
		t.Error("code hash mismatch after SetCode")
	}
	if sdb.GetCodeSize(addr) != len(code) {
		t.Errorf("expected code size %d, got %d", len(code), sdb.GetCodeSize(addr))
	}

	// Account should no longer be empty (has nonce and balance).
	if sdb.Empty(addr) {
		t.Error("account with balance and nonce should not be empty")
	}
}

// TestStorageReadWrite tests storage slot operations.
func TestStorageReadWrite(t *testing.T) {
	sdb := newTestStateDB(t)
	addr := types.HexToAddress("0xaaaa")
	sdb.CreateAccount(addr)

	key := types.HexToHash("0x01")
	val := types.HexToHash("0xff")

	// Initial state should be zero.
	if sdb.GetState(addr, key) != (types.Hash{}) {
		t.Error("initial storage should be zero")
	}

	// Set and read.
	prev := sdb.SetState(addr, key, val)
	if prev != (types.Hash{}) {
		t.Errorf("expected zero prev, got %s", prev)
	}
	if sdb.GetState(addr, key) != val {
		t.Error("storage value mismatch")
	}

	// GetCommittedState should still be zero (not committed yet).
	if sdb.GetCommittedState(addr, key) != (types.Hash{}) {
		t.Error("committed state should be zero before commit")
	}
}

// TestSnapshotAndRevert tests snapshot/revert with nested snapshots.
func TestSnapshotAndRevert(t *testing.T) {
	sdb := newTestStateDB(t)
	addr := types.HexToAddress("0xbbbb")

	// Depth 0: create account with balance 100.
	sdb.CreateAccount(addr)
	sdb.AddBalance(addr, uint256.NewInt(100), tracing.BalanceChangeUnspecified)
	snap0 := sdb.Snapshot()

	// Depth 1: add 50 more and set storage.
	sdb.AddBalance(addr, uint256.NewInt(50), tracing.BalanceChangeUnspecified)
	sdb.SetState(addr, types.HexToHash("0x01"), types.HexToHash("0xaa"))
	snap1 := sdb.Snapshot()

	// Depth 2: modify again.
	sdb.AddBalance(addr, uint256.NewInt(25), tracing.BalanceChangeUnspecified)
	sdb.SetNonce(addr, 10, tracing.NonceChangeTransaction)
	sdb.SetState(addr, types.HexToHash("0x02"), types.HexToHash("0xbb"))

	// Verify depth 2 state.
	if sdb.GetBalance(addr).Uint64() != 175 {
		t.Errorf("expected balance 175, got %s", sdb.GetBalance(addr))
	}
	if sdb.GetNonce(addr) != 10 {
		t.Errorf("expected nonce 10, got %d", sdb.GetNonce(addr))
	}

	// Revert to depth 1.
	sdb.RevertToSnapshot(snap1)
	if sdb.GetBalance(addr).Uint64() != 150 {
		t.Errorf("after revert to snap1: expected balance 150, got %s", sdb.GetBalance(addr))
	}
	if sdb.GetNonce(addr) != 0 {
		t.Errorf("after revert to snap1: expected nonce 0, got %d", sdb.GetNonce(addr))
	}
	if sdb.GetState(addr, types.HexToHash("0x01")) != types.HexToHash("0xaa") {
		t.Error("after revert to snap1: storage 0x01 should be preserved")
	}
	if sdb.GetState(addr, types.HexToHash("0x02")) != (types.Hash{}) {
		t.Error("after revert to snap1: storage 0x02 should be reverted")
	}

	// Revert to depth 0.
	sdb.RevertToSnapshot(snap0)
	if sdb.GetBalance(addr).Uint64() != 100 {
		t.Errorf("after revert to snap0: expected balance 100, got %s", sdb.GetBalance(addr))
	}
	if sdb.GetState(addr, types.HexToHash("0x01")) != (types.Hash{}) {
		t.Error("after revert to snap0: storage 0x01 should be reverted")
	}
}

// TestTransientStorage tests EIP-1153 transient storage operations.
func TestTransientStorage(t *testing.T) {
	sdb := newTestStateDB(t)
	addr := types.HexToAddress("0xcccc")
	key := types.HexToHash("0x01")
	val := types.HexToHash("0xdeadbeef")

	// Should be zero initially.
	if sdb.GetTransientState(addr, key) != (types.Hash{}) {
		t.Error("initial transient state should be zero")
	}

	// Set and get.
	sdb.SetTransientState(addr, key, val)
	if sdb.GetTransientState(addr, key) != val {
		t.Error("transient storage value mismatch")
	}

	// Transient storage should revert with snapshots.
	snap := sdb.Snapshot()
	sdb.SetTransientState(addr, key, types.HexToHash("0x999"))
	if sdb.GetTransientState(addr, key) != types.HexToHash("0x999") {
		t.Error("transient storage should be updated")
	}
	sdb.RevertToSnapshot(snap)
	if sdb.GetTransientState(addr, key) != val {
		t.Error("transient storage should revert to previous value")
	}
}

// TestAccessList tests EIP-2929 access list operations.
func TestAccessList(t *testing.T) {
	sdb := newTestStateDB(t)
	addr := types.HexToAddress("0xdddd")
	slot := types.HexToHash("0x01")

	// Initially cold.
	if sdb.AddressInAccessList(addr) {
		t.Error("address should not be in access list initially")
	}
	addrPresent, slotPresent := sdb.SlotInAccessList(addr, slot)
	if addrPresent || slotPresent {
		t.Error("neither address nor slot should be in access list initially")
	}

	// Add address.
	sdb.AddAddressToAccessList(addr)
	if !sdb.AddressInAccessList(addr) {
		t.Error("address should be in access list after adding")
	}
	addrPresent, slotPresent = sdb.SlotInAccessList(addr, slot)
	if !addrPresent {
		t.Error("address should be present")
	}
	if slotPresent {
		t.Error("slot should not be present yet")
	}

	// Add slot.
	sdb.AddSlotToAccessList(addr, slot)
	addrPresent, slotPresent = sdb.SlotInAccessList(addr, slot)
	if !addrPresent || !slotPresent {
		t.Error("both address and slot should be present")
	}

	// Revert should undo access list changes.
	snap := sdb.Snapshot()
	addr2 := types.HexToAddress("0xeeee")
	sdb.AddAddressToAccessList(addr2)
	if !sdb.AddressInAccessList(addr2) {
		t.Error("addr2 should be in access list")
	}
	sdb.RevertToSnapshot(snap)
	if sdb.AddressInAccessList(addr2) {
		t.Error("addr2 should not be in access list after revert")
	}
}

// TestSelfDestruct tests self-destruct and EIP-6780 behavior.
func TestSelfDestruct(t *testing.T) {
	sdb := newTestStateDB(t)
	addr := types.HexToAddress("0x1111")

	sdb.CreateAccount(addr)
	sdb.AddBalance(addr, uint256.NewInt(1000), tracing.BalanceChangeUnspecified)

	// SelfDestruct should zero the balance.
	sdb.SelfDestruct(addr)
	if !sdb.HasSelfDestructed(addr) {
		t.Error("account should be self-destructed")
	}
	if sdb.GetBalance(addr).Sign() != 0 {
		t.Error("balance should be zero after self-destruct")
	}

	// Revert should undo self-destruct.
	sdb2 := newTestStateDB(t)
	addr2 := types.HexToAddress("0x2222")
	sdb2.CreateAccount(addr2)
	sdb2.AddBalance(addr2, uint256.NewInt(500), tracing.BalanceChangeUnspecified)
	snap := sdb2.Snapshot()
	sdb2.SelfDestruct(addr2)
	if !sdb2.HasSelfDestructed(addr2) {
		t.Error("should be self-destructed")
	}
	sdb2.RevertToSnapshot(snap)
	if sdb2.HasSelfDestructed(addr2) {
		t.Error("should not be self-destructed after revert")
	}
	if sdb2.GetBalance(addr2).Uint64() != 500 {
		t.Errorf("balance should be restored to 500, got %s", sdb2.GetBalance(addr2))
	}
}

// TestSelfdestruct6780 tests EIP-6780 selfdestruct behavior.
func TestSelfdestruct6780(t *testing.T) {
	sdb := newTestStateDB(t)

	// Account NOT created in same tx.
	addr1 := types.HexToAddress("0x3333")
	sdb.CreateAccount(addr1)
	sdb.AddBalance(addr1, uint256.NewInt(100), tracing.BalanceChangeUnspecified)
	sdb.Selfdestruct6780(addr1)
	if sdb.HasSelfDestructed(addr1) {
		t.Error("should not self-destruct: not created in same tx")
	}

	// Account created in same tx.
	addr2 := types.HexToAddress("0x4444")
	sdb.CreateAccount(addr2)
	sdb.CreateContract(addr2)
	sdb.AddBalance(addr2, uint256.NewInt(200), tracing.BalanceChangeUnspecified)
	sdb.Selfdestruct6780(addr2)
	if !sdb.HasSelfDestructed(addr2) {
		t.Error("should self-destruct: created in same tx")
	}
}

// TestLogs tests log accumulation.
func TestLogs(t *testing.T) {
	sdb := newTestStateDB(t)
	txHash := types.HexToHash("0xabcd")
	sdb.SetTxContext(txHash, 0)

	log1 := &types.Log{
		Address: types.HexToAddress("0x1111"),
		Topics:  []types.Hash{types.HexToHash("0xaa")},
		Data:    []byte("hello"),
	}
	log2 := &types.Log{
		Address: types.HexToAddress("0x2222"),
		Topics:  []types.Hash{types.HexToHash("0xbb")},
		Data:    []byte("world"),
	}
	sdb.AddLog(log1)
	sdb.AddLog(log2)

	logs := sdb.GetLogs(txHash, 42, types.HexToHash("0xblock"))
	if len(logs) != 2 {
		t.Fatalf("expected 2 logs, got %d", len(logs))
	}
	if logs[0].Index != 0 || logs[1].Index != 1 {
		t.Error("log indices should be 0 and 1")
	}
	if logs[0].BlockNumber != 42 {
		t.Error("block number should be filled in")
	}

	// Log should be reverted on snapshot revert.
	snap := sdb.Snapshot()
	sdb.AddLog(&types.Log{
		Address: types.HexToAddress("0x3333"),
		Data:    []byte("reverted"),
	})
	if len(sdb.GetLogs(txHash, 0, types.Hash{})) != 3 {
		t.Error("expected 3 logs before revert")
	}
	sdb.RevertToSnapshot(snap)
	if len(sdb.GetLogs(txHash, 0, types.Hash{})) != 2 {
		t.Error("expected 2 logs after revert")
	}
}

// TestRefund tests the refund counter.
func TestRefund(t *testing.T) {
	sdb := newTestStateDB(t)

	sdb.AddRefund(100)
	if sdb.GetRefund() != 100 {
		t.Errorf("expected refund 100, got %d", sdb.GetRefund())
	}
	sdb.AddRefund(50)
	if sdb.GetRefund() != 150 {
		t.Errorf("expected refund 150, got %d", sdb.GetRefund())
	}
	sdb.SubRefund(30)
	if sdb.GetRefund() != 120 {
		t.Errorf("expected refund 120, got %d", sdb.GetRefund())
	}

	// SubRefund below zero must panic (matching geth behavior).
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected panic from SubRefund underflow, got none")
		}
	}()
	sdb.SubRefund(200)
}

// TestFinaliseAndIntermediateRoot tests finalisation and root computation.
func TestFinaliseAndIntermediateRoot(t *testing.T) {
	sdb := newTestStateDB(t)
	addr := types.HexToAddress("0xaaaa")

	sdb.CreateAccount(addr)
	sdb.AddBalance(addr, uint256.NewInt(100), tracing.BalanceChangeUnspecified)
	sdb.SetState(addr, types.HexToHash("0x01"), types.HexToHash("0xff"))

	root1 := sdb.IntermediateRoot(true)
	if root1 == (types.Hash{}) || root1 == types.EmptyRootHash {
		t.Error("intermediate root should not be empty after modifications")
	}

	// Calling IntermediateRoot again with same data should give same result.
	// We need to recreate since Finalise clears the journal.
	sdb2 := newTestStateDB(t)
	sdb2.CreateAccount(addr)
	sdb2.AddBalance(addr, uint256.NewInt(100), tracing.BalanceChangeUnspecified)
	sdb2.SetState(addr, types.HexToHash("0x01"), types.HexToHash("0xff"))
	root2 := sdb2.IntermediateRoot(true)

	if root1 != root2 {
		t.Errorf("deterministic root mismatch: %s vs %s", root1, root2)
	}
}

// TestCommitAndReopen tests committing state and reopening from the same root.
func TestCommitAndReopen(t *testing.T) {
	diskdb := db.NewMemoryDB()

	// Create and populate state.
	sdb, err := New(types.Hash{}, diskdb)
	if err != nil {
		t.Fatal(err)
	}
	addr := types.HexToAddress("0xaaaa")
	sdb.CreateAccount(addr)
	sdb.AddBalance(addr, uint256.NewInt(100), tracing.BalanceChangeUnspecified)
	sdb.SetNonce(addr, 7, tracing.NonceChangeTransaction)
	code := []byte{0x60, 0x00}
	sdb.SetCode(addr, code, tracing.CodeChangeCreation)
	sdb.SetState(addr, types.HexToHash("0x01"), types.HexToHash("0xff"))

	root, err := sdb.Commit(true)
	if err != nil {
		t.Fatalf("commit failed: %v", err)
	}
	if root == (types.Hash{}) {
		t.Error("committed root should not be zero")
	}

	// Reopen from the same root.
	sdb2, err := New(root, diskdb)
	if err != nil {
		t.Fatalf("reopen failed: %v", err)
	}

	if sdb2.GetBalance(addr).Uint64() != 100 {
		t.Errorf("reopened balance: expected 100, got %s", sdb2.GetBalance(addr))
	}
	if sdb2.GetNonce(addr) != 7 {
		t.Errorf("reopened nonce: expected 7, got %d", sdb2.GetNonce(addr))
	}
	if !bytes.Equal(sdb2.GetCode(addr), code) {
		t.Error("reopened code mismatch")
	}
	if sdb2.GetState(addr, types.HexToHash("0x01")) != types.HexToHash("0xff") {
		t.Error("reopened storage mismatch")
	}

	// Root should be deterministic.
	root2, err := sdb2.Commit(true)
	if err != nil {
		t.Fatalf("second commit failed: %v", err)
	}
	if root != root2 {
		t.Errorf("root should be deterministic: %s vs %s", root, root2)
	}
}

// TestNestedSnapshotRevert tests the critical nested snapshot flow described
// in the requirements.
func TestNestedSnapshotRevert(t *testing.T) {
	sdb := newTestStateDB(t)
	addr := types.HexToAddress("0x1234")

	// Create account.
	sdb.CreateAccount(addr)

	// Snapshot at depth 0.
	snap0 := sdb.Snapshot()

	// Modify state.
	sdb.AddBalance(addr, uint256.NewInt(100), tracing.BalanceChangeUnspecified)
	sdb.SetState(addr, types.HexToHash("0x01"), types.HexToHash("0xaa"))

	// Snapshot at depth 1.
	snap1 := sdb.Snapshot()

	// Modify state.
	sdb.AddBalance(addr, uint256.NewInt(200), tracing.BalanceChangeUnspecified)
	sdb.SetState(addr, types.HexToHash("0x02"), types.HexToHash("0xbb"))
	sdb.SetNonce(addr, 5, tracing.NonceChangeTransaction)

	// Verify current state.
	if sdb.GetBalance(addr).Uint64() != 300 {
		t.Errorf("expected balance 300, got %s", sdb.GetBalance(addr))
	}

	// Revert to depth 1: depth 1 changes reverted, depth 0 changes intact.
	sdb.RevertToSnapshot(snap1)
	if sdb.GetBalance(addr).Uint64() != 100 {
		t.Errorf("after revert snap1: expected balance 100, got %s", sdb.GetBalance(addr))
	}
	if sdb.GetState(addr, types.HexToHash("0x01")) != types.HexToHash("0xaa") {
		t.Error("after revert snap1: storage 0x01 should be preserved")
	}
	if sdb.GetState(addr, types.HexToHash("0x02")) != (types.Hash{}) {
		t.Error("after revert snap1: storage 0x02 should be reverted")
	}
	if sdb.GetNonce(addr) != 0 {
		t.Errorf("after revert snap1: expected nonce 0, got %d", sdb.GetNonce(addr))
	}

	// Revert to depth 0: all changes reverted.
	sdb.RevertToSnapshot(snap0)
	if sdb.GetBalance(addr).Uint64() != 0 {
		t.Errorf("after revert snap0: expected balance 0, got %s", sdb.GetBalance(addr))
	}
	if sdb.GetState(addr, types.HexToHash("0x01")) != (types.Hash{}) {
		t.Error("after revert snap0: storage 0x01 should be reverted")
	}
}

// TestPrepare tests the Prepare method for access list setup.
func TestPrepare(t *testing.T) {
	sdb := newTestStateDB(t)
	sender := types.HexToAddress("0xaaa1")
	coinbase := types.HexToAddress("0xaaa2")
	dest := types.HexToAddress("0xaaa3")
	precompile := types.HexToAddress("0x0001")

	rules := vm.Rules{
		IsBerlin:   true,
		IsShanghai: true,
	}

	sdb.Prepare(rules, sender, coinbase, &dest, []types.Address{precompile}, nil)

	// Sender, coinbase, dest, and precompile should be in access list.
	if !sdb.AddressInAccessList(sender) {
		t.Error("sender should be in access list")
	}
	if !sdb.AddressInAccessList(coinbase) {
		t.Error("coinbase should be in access list (Shanghai)")
	}
	if !sdb.AddressInAccessList(dest) {
		t.Error("dest should be in access list")
	}
	if !sdb.AddressInAccessList(precompile) {
		t.Error("precompile should be in access list")
	}
}

// TestPreimages tests preimage recording.
func TestPreimages(t *testing.T) {
	sdb := newTestStateDB(t)
	data := []byte("hello world")
	hash := types.BytesToHash(crypto.Keccak256(data))

	sdb.AddPreimage(hash, data)
	if _, ok := sdb.preimages[hash]; !ok {
		t.Error("preimage should be recorded")
	}
	if !bytes.Equal(sdb.preimages[hash], data) {
		t.Error("preimage data mismatch")
	}
}

// TestCopy tests deep copying a StateDB.
func TestCopy(t *testing.T) {
	sdb := newTestStateDB(t)
	addr := types.HexToAddress("0xaaaa")
	sdb.CreateAccount(addr)
	sdb.AddBalance(addr, uint256.NewInt(100), tracing.BalanceChangeUnspecified)

	cpy := sdb.Copy()

	// Modify original should not affect copy.
	sdb.AddBalance(addr, uint256.NewInt(50), tracing.BalanceChangeUnspecified)
	if cpy.GetBalance(addr).Uint64() != 100 {
		t.Errorf("copy balance should be 100, got %s", cpy.GetBalance(addr))
	}
	if sdb.GetBalance(addr).Uint64() != 150 {
		t.Errorf("original balance should be 150, got %s", sdb.GetBalance(addr))
	}
}

// TestCreateAccountOverwrite tests that CreateAccount silently overwrites
// an existing account (matching geth behavior). In geth, CreateAccount
// does NOT preserve balance — the EVM's Create function handles balance
// transfer separately.
func TestCreateAccountOverwrite(t *testing.T) {
	sdb := newTestStateDB(t)
	addr := types.HexToAddress("0x5555")

	sdb.CreateAccount(addr)
	sdb.AddBalance(addr, uint256.NewInt(999), tracing.BalanceChangeUnspecified)
	sdb.SetNonce(addr, 3, tracing.NonceChangeTransaction)
	code := []byte{0x01, 0x02}
	sdb.SetCode(addr, code, tracing.CodeChangeCreation)

	// Re-create: this silently overwrites with a fresh empty account.
	sdb.CreateAccount(addr)
	if sdb.GetBalance(addr).Uint64() != 0 {
		t.Errorf("expected balance 0 after re-create, got %s", sdb.GetBalance(addr))
	}
	if sdb.GetNonce(addr) != 0 {
		t.Errorf("expected nonce 0 after re-create, got %d", sdb.GetNonce(addr))
	}
	if sdb.GetCode(addr) != nil {
		t.Error("expected nil code after re-create")
	}
}

// TestEmptyAccountDeletion tests that empty accounts are deleted during
// finalisation when deleteEmptyObjects is true.
func TestEmptyAccountDeletion(t *testing.T) {
	sdb := newTestStateDB(t)
	addr := types.HexToAddress("0x6666")

	// Create an empty account.
	sdb.CreateAccount(addr)
	if !sdb.Exist(addr) {
		t.Error("account should exist after creation")
	}

	// The account is already tracked as dirty via journal.dirties
	// from the CreateAccount call above.

	// Finalise with deleteEmptyObjects = true.
	sdb.Finalise(true)
	if sdb.Exist(addr) {
		t.Error("empty account should be deleted after finalise")
	}
}

// TestSnapshotDepthLimit1024 verifies that 1024 snapshots can be created
// successfully.
func TestSnapshotDepthLimit1024(t *testing.T) {
	sdb := newTestStateDB(t)
	addr := types.HexToAddress("0xaaaa")
	sdb.CreateAccount(addr)

	ids := make([]int, 1024)
	for i := 0; i < 1024; i++ {
		ids[i] = sdb.Snapshot()
		sdb.AddBalance(addr, uint256.NewInt(1), tracing.BalanceChangeUnspecified)
	}

	// All 1024 snapshots should have distinct, increasing IDs.
	for i := 1; i < len(ids); i++ {
		if ids[i] <= ids[i-1] {
			t.Fatalf("snapshot IDs should be increasing: ids[%d]=%d, ids[%d]=%d", i-1, ids[i-1], i, ids[i])
		}
	}

	// Final balance should be 1024 (one unit added per snapshot).
	if sdb.GetBalance(addr).Uint64() != 1024 {
		t.Fatalf("expected balance 1024, got %s", sdb.GetBalance(addr))
	}
}

// TestSnapshotDepthBeyond1024 verifies that the 1025th snapshot panics
// because the journal enforces a maxSnapshotDepth of 1024.
func TestSnapshotDepthBeyond1024(t *testing.T) {
	sdb := newTestStateDB(t)
	addr := types.HexToAddress("0xbbbb")
	sdb.CreateAccount(addr)

	// Create exactly 1024 snapshots (the maximum).
	for i := 0; i < 1024; i++ {
		sdb.Snapshot()
		sdb.AddBalance(addr, uint256.NewInt(1), tracing.BalanceChangeUnspecified)
	}

	// The 1025th snapshot must panic.
	panicked := false
	func() {
		defer func() {
			if r := recover(); r != nil {
				panicked = true
			}
		}()
		sdb.Snapshot()
	}()

	if !panicked {
		t.Fatal("expected panic when exceeding snapshot depth limit of 1024")
	}
}

// TestSnapshotRevertAtMaxDepth verifies that revert still works correctly
// when we have reached the maximum snapshot depth.
func TestSnapshotRevertAtMaxDepth(t *testing.T) {
	sdb := newTestStateDB(t)
	addr := types.HexToAddress("0xcccc")
	sdb.CreateAccount(addr)

	// Take initial snapshot.
	snap0 := sdb.Snapshot()
	sdb.AddBalance(addr, uint256.NewInt(100), tracing.BalanceChangeUnspecified)

	// Fill up to depth 1024 (snap0 already used one slot, so 1023 more).
	for i := 1; i < 1024; i++ {
		sdb.Snapshot()
		sdb.AddBalance(addr, uint256.NewInt(1), tracing.BalanceChangeUnspecified)
	}

	// Balance should be 100 + 1023 = 1123.
	if sdb.GetBalance(addr).Uint64() != 1123 {
		t.Fatalf("expected balance 1123, got %s", sdb.GetBalance(addr))
	}

	// Revert all the way back to snap0.
	sdb.RevertToSnapshot(snap0)
	if sdb.GetBalance(addr).Uint64() != 0 {
		t.Fatalf("expected balance 0 after revert to snap0, got %s", sdb.GetBalance(addr))
	}
}

// TestMemoryStateDBBasicOperations tests the MemoryStateDB implementation.
func TestMemoryStateDBBasicOperations(t *testing.T) {
	m := NewMemoryStateDB()
	addr := types.HexToAddress("0xaaaa")

	// Create and check existence.
	if m.Exist(addr) {
		t.Error("should not exist yet")
	}
	m.CreateAccount(addr)
	if !m.Exist(addr) {
		t.Error("should exist after creation")
	}

	// Balance.
	prev := m.AddBalance(addr, uint256.NewInt(100), tracing.BalanceChangeUnspecified)
	if !prev.IsZero() {
		t.Error("prev should be zero")
	}
	if m.GetBalance(addr).Uint64() != 100 {
		t.Errorf("expected 100, got %s", m.GetBalance(addr))
	}

	// Nonce.
	m.SetNonce(addr, 5, tracing.NonceChangeTransaction)
	if m.GetNonce(addr) != 5 {
		t.Errorf("expected nonce 5, got %d", m.GetNonce(addr))
	}

	// Code.
	code := []byte{0x60, 0x00}
	m.SetCode(addr, code, tracing.CodeChangeCreation)
	if !bytes.Equal(m.GetCode(addr), code) {
		t.Error("code mismatch")
	}
	if m.GetCodeSize(addr) != 2 {
		t.Errorf("expected code size 2, got %d", m.GetCodeSize(addr))
	}

	// Storage.
	key := types.HexToHash("0x01")
	val := types.HexToHash("0xff")
	m.SetState(addr, key, val)
	if m.GetState(addr, key) != val {
		t.Error("storage mismatch")
	}

	// Snapshot/revert.
	snap := m.Snapshot()
	m.AddBalance(addr, uint256.NewInt(50), tracing.BalanceChangeUnspecified)
	m.SetState(addr, key, types.HexToHash("0x00"))
	m.RevertToSnapshot(snap)
	if m.GetBalance(addr).Uint64() != 100 {
		t.Errorf("expected balance 100 after revert, got %s", m.GetBalance(addr))
	}
	if m.GetState(addr, key) != val {
		t.Error("storage should be reverted")
	}
}

// TestMemoryStateDBSelfDestruct tests self-destruct in MemoryStateDB.
func TestMemoryStateDBSelfDestruct(t *testing.T) {
	m := NewMemoryStateDB()
	addr := types.HexToAddress("0x1111")
	m.CreateAccount(addr)
	m.AddBalance(addr, uint256.NewInt(500), tracing.BalanceChangeUnspecified)

	m.SelfDestruct(addr)
	if !m.HasSelfDestructed(addr) {
		t.Error("should be self-destructed")
	}
	if m.GetBalance(addr).Sign() != 0 {
		t.Error("balance should be zero")
	}
}

// TestMemoryStateDBSelfdestruct6780 tests EIP-6780 in MemoryStateDB.
func TestMemoryStateDBSelfdestruct6780(t *testing.T) {
	m := NewMemoryStateDB()
	addr := types.HexToAddress("0x2222")
	m.CreateAccount(addr)
	m.AddBalance(addr, uint256.NewInt(100), tracing.BalanceChangeUnspecified)

	// Not created in this tx.
	m.Selfdestruct6780(addr)
	if m.HasSelfDestructed(addr) {
		t.Error("should not self-destruct without CreateContract")
	}

	// Created in this tx.
	m.CreateContract(addr)
	m.Selfdestruct6780(addr)
	if !m.HasSelfDestructed(addr) {
		t.Error("should self-destruct after CreateContract")
	}
}

// TestMemoryStateDBTransientStorage tests transient storage in MemoryStateDB.
func TestMemoryStateDBTransientStorage(t *testing.T) {
	m := NewMemoryStateDB()
	addr := types.HexToAddress("0x3333")
	key := types.HexToHash("0x01")
	val := types.HexToHash("0xaa")

	if m.GetTransientState(addr, key) != (types.Hash{}) {
		t.Error("initial transient state should be zero")
	}
	m.SetTransientState(addr, key, val)
	if m.GetTransientState(addr, key) != val {
		t.Error("transient state mismatch")
	}
}

// TestMemoryStateDBAccessList tests access list in MemoryStateDB.
func TestMemoryStateDBAccessList(t *testing.T) {
	m := NewMemoryStateDB()
	addr := types.HexToAddress("0x4444")
	slot := types.HexToHash("0x01")

	if m.AddressInAccessList(addr) {
		t.Error("should not be in access list initially")
	}
	m.AddAddressToAccessList(addr)
	if !m.AddressInAccessList(addr) {
		t.Error("should be in access list after adding")
	}
	m.AddSlotToAccessList(addr, slot)
	addrOk, slotOk := m.SlotInAccessList(addr, slot)
	if !addrOk || !slotOk {
		t.Error("both should be present")
	}
}

// TestMemoryStateDBRefund tests refund counter in MemoryStateDB.
func TestMemoryStateDBRefund(t *testing.T) {
	m := NewMemoryStateDB()
	m.AddRefund(100)
	if m.GetRefund() != 100 {
		t.Errorf("expected 100, got %d", m.GetRefund())
	}
	m.SubRefund(30)
	if m.GetRefund() != 70 {
		t.Errorf("expected 70, got %d", m.GetRefund())
	}
}

// TestMemoryStateDBLogs tests log accumulation in MemoryStateDB.
func TestMemoryStateDBLogs(t *testing.T) {
	m := NewMemoryStateDB()
	m.AddLog(&types.Log{Address: types.HexToAddress("0x1111"), Data: []byte("a")})
	m.AddLog(&types.Log{Address: types.HexToAddress("0x2222"), Data: []byte("b")})

	snap := m.Snapshot()
	m.AddLog(&types.Log{Address: types.HexToAddress("0x3333"), Data: []byte("c")})
	m.RevertToSnapshot(snap)

	if len(m.logs) != 2 {
		t.Errorf("expected 2 logs after revert, got %d", len(m.logs))
	}
}

// TestSnapshot_DepthTracking verifies that creating multiple snapshots
// produces sequential, increasing IDs.
func TestSnapshot_DepthTracking(t *testing.T) {
	sdb := newTestStateDB(t)
	addr := types.HexToAddress("0xaaaa")
	sdb.CreateAccount(addr)

	const n = 10
	ids := make([]int, n)
	for i := 0; i < n; i++ {
		ids[i] = sdb.Snapshot()
		// Make a state change between snapshots so each revision has
		// a distinct journal index.
		sdb.AddBalance(addr, uint256.NewInt(1), tracing.BalanceChangeUnspecified)
	}

	for i := 1; i < n; i++ {
		if ids[i] <= ids[i-1] {
			t.Fatalf("snapshot IDs must be strictly increasing: ids[%d]=%d, ids[%d]=%d",
				i-1, ids[i-1], i, ids[i])
		}
	}
}

// TestSnapshot_RevertRestoresState verifies that reverting to a snapshot
// restores balance, nonce, and storage to their values at snapshot time.
func TestSnapshot_RevertRestoresState(t *testing.T) {
	sdb := newTestStateDB(t)
	addr := types.HexToAddress("0xbbbb")
	sdb.CreateAccount(addr)

	// Set initial state.
	sdb.AddBalance(addr, uint256.NewInt(100), tracing.BalanceChangeUnspecified)
	sdb.SetNonce(addr, 1, tracing.NonceChangeTransaction)
	sdb.SetState(addr, types.HexToHash("0x01"), types.HexToHash("0xaa"))

	snap := sdb.Snapshot()

	// Modify state after snapshot.
	sdb.AddBalance(addr, uint256.NewInt(200), tracing.BalanceChangeUnspecified)
	sdb.SetNonce(addr, 5, tracing.NonceChangeTransaction)
	sdb.SetState(addr, types.HexToHash("0x01"), types.HexToHash("0xff"))
	sdb.SetState(addr, types.HexToHash("0x02"), types.HexToHash("0xbb"))

	// Verify modified state.
	if sdb.GetBalance(addr).Uint64() != 300 {
		t.Fatalf("expected balance 300, got %s", sdb.GetBalance(addr))
	}

	// Revert and verify original state is restored.
	sdb.RevertToSnapshot(snap)

	if sdb.GetBalance(addr).Uint64() != 100 {
		t.Errorf("expected balance 100 after revert, got %s", sdb.GetBalance(addr))
	}
	if sdb.GetNonce(addr) != 1 {
		t.Errorf("expected nonce 1 after revert, got %d", sdb.GetNonce(addr))
	}
	if sdb.GetState(addr, types.HexToHash("0x01")) != types.HexToHash("0xaa") {
		t.Error("storage 0x01 should be restored to 0xaa after revert")
	}
	if sdb.GetState(addr, types.HexToHash("0x02")) != (types.Hash{}) {
		t.Error("storage 0x02 should be zero after revert")
	}
}

// TestSnapshot_NestedRevert verifies that reverting an inner snapshot
// preserves the outer snapshot's state, and the outer snapshot can
// still be reverted independently.
func TestSnapshot_NestedRevert(t *testing.T) {
	sdb := newTestStateDB(t)
	addr := types.HexToAddress("0xcccc")
	sdb.CreateAccount(addr)

	// Outer state.
	sdb.AddBalance(addr, uint256.NewInt(50), tracing.BalanceChangeUnspecified)
	sdb.SetState(addr, types.HexToHash("0x01"), types.HexToHash("0x11"))
	snapOuter := sdb.Snapshot()

	// Inner state.
	sdb.AddBalance(addr, uint256.NewInt(25), tracing.BalanceChangeUnspecified)
	sdb.SetState(addr, types.HexToHash("0x02"), types.HexToHash("0x22"))
	snapInner := sdb.Snapshot()

	// Deepest modifications.
	sdb.AddBalance(addr, uint256.NewInt(10), tracing.BalanceChangeUnspecified)
	sdb.SetState(addr, types.HexToHash("0x03"), types.HexToHash("0x33"))

	// Revert inner: deepest changes gone, inner and outer state intact.
	sdb.RevertToSnapshot(snapInner)
	if sdb.GetBalance(addr).Uint64() != 75 {
		t.Errorf("after inner revert: expected balance 75, got %s", sdb.GetBalance(addr))
	}
	if sdb.GetState(addr, types.HexToHash("0x02")) != types.HexToHash("0x22") {
		t.Error("after inner revert: storage 0x02 should be preserved")
	}
	if sdb.GetState(addr, types.HexToHash("0x03")) != (types.Hash{}) {
		t.Error("after inner revert: storage 0x03 should be reverted")
	}

	// Revert outer: inner changes also gone, only pre-outer state remains.
	sdb.RevertToSnapshot(snapOuter)
	if sdb.GetBalance(addr).Uint64() != 50 {
		t.Errorf("after outer revert: expected balance 50, got %s", sdb.GetBalance(addr))
	}
	if sdb.GetState(addr, types.HexToHash("0x01")) != types.HexToHash("0x11") {
		t.Error("after outer revert: storage 0x01 should be preserved")
	}
	if sdb.GetState(addr, types.HexToHash("0x02")) != (types.Hash{}) {
		t.Error("after outer revert: storage 0x02 should be reverted")
	}
}

// TestDeepSnapshotsNoLimit verifies that more than 1024 snapshots can be
// created without hitting an artificial depth limit. Geth imposes no
// snapshot depth limit — the EVM call depth (1024) is the guard at a
// different layer. Snapshots accumulate across all calls in a transaction.
func TestDeepSnapshotsNoLimit(t *testing.T) {
	sdb := NewMemoryStateDB()
	addr := types.HexToAddress("0xaaaa")
	sdb.CreateAccount(addr)

	const depth = 2048 // well above old 1024 limit
	snaps := make([]int, 0, depth)
	for i := 0; i < depth; i++ {
		id := sdb.Snapshot()
		snaps = append(snaps, id)
		sdb.SetNonce(addr, uint64(i+1), 0)
	}
	if got := sdb.GetNonce(addr); got != depth {
		t.Fatalf("nonce after %d snapshots: got %d, want %d", depth, got, depth)
	}

	// Revert to the halfway point.
	mid := depth / 2
	sdb.RevertToSnapshot(snaps[mid])
	if got := sdb.GetNonce(addr); got != uint64(mid) {
		t.Fatalf("nonce after revert to mid (%d): got %d, want %d", mid, got, mid)
	}

	// Revert to the very first snapshot.
	sdb.RevertToSnapshot(snaps[0])
	if got := sdb.GetNonce(addr); got != 0 {
		t.Fatalf("nonce after revert to 0: got %d, want 0", got)
	}
}

// TestSubRefundPanicsOnUnderflow verifies that SubRefund panics when
// the subtraction would underflow, matching geth behavior.
func TestSubRefundPanicsOnUnderflow(t *testing.T) {
	sdb := NewMemoryStateDB()
	sdb.AddRefund(100)

	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected panic from SubRefund underflow, got none")
		}
	}()
	sdb.SubRefund(101) // should panic
}

// TestDeterministicRoot verifies that the same operations produce the same
// root hash regardless of order.
func TestDeterministicRoot(t *testing.T) {
	create := func() types.Hash {
		diskdb := db.NewMemoryDB()
		sdb, err := New(types.Hash{}, diskdb)
		if err != nil {
			t.Fatal(err)
		}
		addr := types.HexToAddress("0xaaaa")
		sdb.CreateAccount(addr)
		sdb.AddBalance(addr, uint256.NewInt(100), tracing.BalanceChangeUnspecified)
		sdb.SetState(addr, types.HexToHash("0x01"), types.HexToHash("0xff"))
		root, err := sdb.Commit(true)
		if err != nil {
			t.Fatal(err)
		}
		return root
	}

	root1 := create()
	root2 := create()
	if root1 != root2 {
		t.Errorf("roots should be deterministic: %s vs %s", root1, root2)
	}
}
