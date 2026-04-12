package state

import (
	"bytes"
	"testing"

	"github.com/holiman/uint256"

	"github.com/icellan/bsvm/pkg/types"
	"github.com/icellan/bsvm/pkg/vm/tracing"
)

// TestMemoryStateDB_SetTxContext verifies that SetTxContext correctly sets
// the transaction hash and index, and that subsequently added logs pick
// up the context.
func TestMemoryStateDB_SetTxContext(t *testing.T) {
	m := NewMemoryStateDB()
	txHash := types.HexToHash("0xabcd")
	m.SetTxContext(txHash, 3)

	if m.TxIndex() != 3 {
		t.Errorf("expected tx index 3, got %d", m.TxIndex())
	}

	// Add a log and verify it picks up the tx context.
	m.AddLog(&types.Log{
		Address: types.HexToAddress("0x1111"),
		Data:    []byte("hello"),
	})

	logs := m.GetLogs(txHash, 0, types.Hash{})
	if len(logs) != 1 {
		t.Fatalf("expected 1 log, got %d", len(logs))
	}
	if logs[0].TxHash != txHash {
		t.Errorf("log tx hash mismatch: got %s, want %s", logs[0].TxHash.Hex(), txHash.Hex())
	}
	if logs[0].TxIndex != 3 {
		t.Errorf("log tx index mismatch: got %d, want 3", logs[0].TxIndex)
	}

	// Change tx context and add another log.
	txHash2 := types.HexToHash("0xef01")
	m.SetTxContext(txHash2, 4)
	m.AddLog(&types.Log{
		Address: types.HexToAddress("0x2222"),
		Data:    []byte("world"),
	})

	// First tx should still have 1 log.
	if len(m.GetLogs(txHash, 0, types.Hash{})) != 1 {
		t.Error("first tx should still have 1 log")
	}
	// Second tx should have 1 log.
	if len(m.GetLogs(txHash2, 0, types.Hash{})) != 1 {
		t.Error("second tx should have 1 log")
	}
}

// TestMemoryStateDB_GetLogs tests log filtering by tx hash and annotation
// with block number and block hash.
func TestMemoryStateDB_GetLogs(t *testing.T) {
	m := NewMemoryStateDB()

	tx1 := types.HexToHash("0x1111")
	tx2 := types.HexToHash("0x2222")

	// Add logs under tx1.
	m.SetTxContext(tx1, 0)
	m.AddLog(&types.Log{Address: types.HexToAddress("0xaa"), Data: []byte("a")})
	m.AddLog(&types.Log{Address: types.HexToAddress("0xbb"), Data: []byte("b")})

	// Add logs under tx2.
	m.SetTxContext(tx2, 1)
	m.AddLog(&types.Log{Address: types.HexToAddress("0xcc"), Data: []byte("c")})

	// Filter by tx1.
	blockHash := types.HexToHash("0xblock")
	logs := m.GetLogs(tx1, 42, blockHash)
	if len(logs) != 2 {
		t.Fatalf("expected 2 logs for tx1, got %d", len(logs))
	}
	for _, l := range logs {
		if l.BlockNumber != 42 {
			t.Errorf("expected block number 42, got %d", l.BlockNumber)
		}
		if l.BlockHash != blockHash {
			t.Errorf("expected block hash %s, got %s", blockHash.Hex(), l.BlockHash.Hex())
		}
	}

	// Filter by tx2.
	logs2 := m.GetLogs(tx2, 43, types.Hash{})
	if len(logs2) != 1 {
		t.Fatalf("expected 1 log for tx2, got %d", len(logs2))
	}
	if !bytes.Equal(logs2[0].Data, []byte("c")) {
		t.Error("wrong log data for tx2")
	}

	// Non-existent tx should return empty.
	logs3 := m.GetLogs(types.HexToHash("0x9999"), 0, types.Hash{})
	if len(logs3) != 0 {
		t.Errorf("expected 0 logs for unknown tx, got %d", len(logs3))
	}

	// Logs() should return all logs.
	allLogs := m.Logs()
	if len(allLogs) != 3 {
		t.Errorf("expected 3 total logs, got %d", len(allLogs))
	}
}

// TestMemoryStateDB_SetBalance tests direct balance setting.
func TestMemoryStateDB_SetBalance(t *testing.T) {
	m := NewMemoryStateDB()
	addr := types.HexToAddress("0xaaaa")

	// SetBalance on non-existent account should create it.
	m.SetBalance(addr, uint256.NewInt(500))
	if !m.Exist(addr) {
		t.Error("account should exist after SetBalance")
	}
	if m.GetBalance(addr).Uint64() != 500 {
		t.Errorf("expected balance 500, got %s", m.GetBalance(addr))
	}

	// Overwrite balance.
	m.SetBalance(addr, uint256.NewInt(0))
	if !m.GetBalance(addr).IsZero() {
		t.Errorf("expected balance 0, got %s", m.GetBalance(addr))
	}

	// Set to large value.
	large := new(uint256.Int).Mul(uint256.NewInt(1e18), uint256.NewInt(1e6))
	m.SetBalance(addr, large)
	if m.GetBalance(addr).Cmp(large) != 0 {
		t.Errorf("expected balance %s, got %s", large, m.GetBalance(addr))
	}
}

// TestMemoryStateDB_IntermediateRoot tests that IntermediateRoot produces
// deterministic hashes: same state gives the same root, different state
// gives a different root.
func TestMemoryStateDB_IntermediateRoot(t *testing.T) {
	// Helper to build identical state in a fresh MemoryStateDB.
	buildState := func() *MemoryStateDB {
		m := NewMemoryStateDB()
		addr1 := types.HexToAddress("0xaaaa")
		addr2 := types.HexToAddress("0xbbbb")
		m.CreateAccount(addr1)
		m.AddBalance(addr1, uint256.NewInt(100), tracing.BalanceChangeUnspecified)
		m.SetNonce(addr1, 5, tracing.NonceChangeTransaction)
		m.SetState(addr1, types.HexToHash("0x01"), types.HexToHash("0xff"))
		m.CreateAccount(addr2)
		m.AddBalance(addr2, uint256.NewInt(200), tracing.BalanceChangeUnspecified)
		return m
	}

	m1 := buildState()
	m2 := buildState()

	root1 := m1.IntermediateRoot(true)
	root2 := m2.IntermediateRoot(true)

	if root1 == (types.Hash{}) {
		t.Error("root should not be zero hash")
	}
	if root1 == types.EmptyRootHash {
		t.Error("root should not be empty root hash with non-empty state")
	}
	if root1 != root2 {
		t.Errorf("same state should produce same root: %s vs %s", root1.Hex(), root2.Hex())
	}

	// Different state should produce different root.
	m3 := buildState()
	m3.AddBalance(types.HexToAddress("0xaaaa"), uint256.NewInt(1), tracing.BalanceChangeUnspecified)
	root3 := m3.IntermediateRoot(true)
	if root3 == root1 {
		t.Error("different state should produce different root")
	}

	// Empty state should give empty root hash.
	m4 := NewMemoryStateDB()
	root4 := m4.IntermediateRoot(true)
	if root4 != types.EmptyRootHash {
		t.Errorf("empty state root should be EmptyRootHash, got %s", root4.Hex())
	}
}

// TestMemoryStateDB_Finalise tests that Finalise moves dirty storage to
// committed, removes self-destructed accounts, and optionally removes
// empty accounts.
func TestMemoryStateDB_Finalise(t *testing.T) {
	m := NewMemoryStateDB()
	addr := types.HexToAddress("0xaaaa")
	m.CreateAccount(addr)
	m.AddBalance(addr, uint256.NewInt(100), tracing.BalanceChangeUnspecified)

	key := types.HexToHash("0x01")
	val := types.HexToHash("0xff")
	m.SetState(addr, key, val)

	// Before Finalise, committed storage should be empty.
	if m.GetCommittedState(addr, key) != (types.Hash{}) {
		t.Error("committed state should be empty before Finalise")
	}

	m.Finalise(false)

	// After Finalise, committed storage should match dirty.
	if m.GetCommittedState(addr, key) != val {
		t.Errorf("committed state should be %s after Finalise, got %s",
			val.Hex(), m.GetCommittedState(addr, key).Hex())
	}

	// Self-destructed account should be removed.
	addr2 := types.HexToAddress("0xbbbb")
	m.CreateAccount(addr2)
	m.AddBalance(addr2, uint256.NewInt(50), tracing.BalanceChangeUnspecified)
	m.SelfDestruct(addr2)
	m.Finalise(false)
	if m.Exist(addr2) {
		t.Error("self-destructed account should be removed after Finalise")
	}

	// Empty account removal with deleteEmptyObjects=true.
	addr3 := types.HexToAddress("0xcccc")
	m.CreateAccount(addr3) // zero balance, zero nonce, empty code
	if !m.Exist(addr3) {
		t.Error("account should exist before Finalise")
	}
	m.Finalise(true)
	if m.Exist(addr3) {
		t.Error("empty account should be removed with deleteEmptyObjects=true")
	}

	// Non-empty account should NOT be removed with deleteEmptyObjects=true.
	addr4 := types.HexToAddress("0xdddd")
	m.CreateAccount(addr4)
	m.AddBalance(addr4, uint256.NewInt(1), tracing.BalanceChangeUnspecified)
	m.Finalise(true)
	if !m.Exist(addr4) {
		t.Error("non-empty account should not be removed")
	}
}

// TestMemoryStateDB_Commit tests that Commit returns a consistent root hash.
func TestMemoryStateDB_Commit(t *testing.T) {
	m := NewMemoryStateDB()
	addr := types.HexToAddress("0xaaaa")
	m.CreateAccount(addr)
	m.AddBalance(addr, uint256.NewInt(100), tracing.BalanceChangeUnspecified)
	m.SetState(addr, types.HexToHash("0x01"), types.HexToHash("0xff"))

	root1, err := m.Commit(true)
	if err != nil {
		t.Fatalf("Commit failed: %v", err)
	}
	if root1 == (types.Hash{}) {
		t.Error("committed root should not be zero hash")
	}

	// Calling Commit again on the same state should give the same root.
	// (Finalise is idempotent on already-finalised state.)
	root2, err := m.Commit(true)
	if err != nil {
		t.Fatalf("second Commit failed: %v", err)
	}
	if root1 != root2 {
		t.Errorf("Commit should be idempotent: %s vs %s", root1.Hex(), root2.Hex())
	}
}

// TestMemoryStateDB_Copy tests deep copying the MemoryStateDB. Modifications
// to the original after copying must not affect the copy.
func TestMemoryStateDB_Copy(t *testing.T) {
	m := NewMemoryStateDB()
	addr := types.HexToAddress("0xaaaa")
	m.CreateAccount(addr)
	m.AddBalance(addr, uint256.NewInt(100), tracing.BalanceChangeUnspecified)
	m.SetNonce(addr, 5, tracing.NonceChangeTransaction)
	m.SetCode(addr, []byte{0x60, 0x00}, tracing.CodeChangeCreation)
	m.SetState(addr, types.HexToHash("0x01"), types.HexToHash("0xff"))
	m.SetTransientState(addr, types.HexToHash("0x02"), types.HexToHash("0xaa"))
	m.AddAddressToAccessList(addr)
	m.AddPreimage(types.HexToHash("0xab"), []byte("preimage"))
	m.SetTxContext(types.HexToHash("0xdead"), 7)
	m.AddLog(&types.Log{Address: addr, Data: []byte("log data")})

	cp := m.Copy()

	// Verify copy has the same values.
	if cp.GetBalance(addr).Uint64() != 100 {
		t.Errorf("copy balance: expected 100, got %s", cp.GetBalance(addr))
	}
	if cp.GetNonce(addr) != 5 {
		t.Errorf("copy nonce: expected 5, got %d", cp.GetNonce(addr))
	}
	if !bytes.Equal(cp.GetCode(addr), []byte{0x60, 0x00}) {
		t.Error("copy code mismatch")
	}
	if cp.GetState(addr, types.HexToHash("0x01")) != types.HexToHash("0xff") {
		t.Error("copy storage mismatch")
	}
	if cp.TxIndex() != 7 {
		t.Errorf("copy tx index: expected 7, got %d", cp.TxIndex())
	}
	if len(cp.Logs()) != 1 {
		t.Errorf("copy logs: expected 1, got %d", len(cp.Logs()))
	}
	if _, ok := cp.Preimages()[types.HexToHash("0xab")]; !ok {
		t.Error("copy should have preimage")
	}

	// Modify original — copy should be unaffected.
	m.AddBalance(addr, uint256.NewInt(50), tracing.BalanceChangeUnspecified)
	m.SetNonce(addr, 10, tracing.NonceChangeTransaction)
	m.SetState(addr, types.HexToHash("0x01"), types.HexToHash("0x00"))
	m.AddLog(&types.Log{Address: addr, Data: []byte("extra")})

	if cp.GetBalance(addr).Uint64() != 100 {
		t.Errorf("copy balance should still be 100, got %s", cp.GetBalance(addr))
	}
	if cp.GetNonce(addr) != 5 {
		t.Errorf("copy nonce should still be 5, got %d", cp.GetNonce(addr))
	}
	if cp.GetState(addr, types.HexToHash("0x01")) != types.HexToHash("0xff") {
		t.Error("copy storage should be unchanged")
	}
	if len(cp.Logs()) != 1 {
		t.Errorf("copy should still have 1 log, got %d", len(cp.Logs()))
	}

	// Modify copy — original should be unaffected.
	cp.SubBalance(addr, uint256.NewInt(25), tracing.BalanceChangeUnspecified)
	if m.GetBalance(addr).Uint64() != 150 {
		t.Errorf("original balance should be 150, got %s", m.GetBalance(addr))
	}
}

// TestMemoryStateDB_GetProof verifies that GetProof and GetStorageProof
// return empty proofs without error.
func TestMemoryStateDB_GetProof(t *testing.T) {
	m := NewMemoryStateDB()
	addr := types.HexToAddress("0xaaaa")

	proof, err := m.GetProof(addr)
	if err != nil {
		t.Fatalf("GetProof failed: %v", err)
	}
	if proof == nil {
		t.Error("GetProof should return non-nil slice")
	}
	if len(proof) != 0 {
		t.Errorf("GetProof should return empty proof, got %d elements", len(proof))
	}

	storageProof, err := m.GetStorageProof(addr, types.HexToHash("0x01"))
	if err != nil {
		t.Fatalf("GetStorageProof failed: %v", err)
	}
	if storageProof == nil {
		t.Error("GetStorageProof should return non-nil slice")
	}
	if len(storageProof) != 0 {
		t.Errorf("GetStorageProof should return empty proof, got %d elements", len(storageProof))
	}
}

// TestMemoryStateDB_AccessRecording tests that StartAccessRecording and
// StopAccessRecording return a non-nil result and do not panic.
func TestMemoryStateDB_AccessRecording(t *testing.T) {
	m := NewMemoryStateDB()

	// Stop without start should return empty recording.
	rec := m.StopAccessRecording()
	if rec == nil {
		t.Fatal("StopAccessRecording should return non-nil result")
	}
	if rec.Accounts != nil && len(rec.Accounts) != 0 {
		t.Error("should have no accounts recorded")
	}
	if rec.Slots == nil {
		t.Error("Slots map should be non-nil")
	}

	// Start then stop.
	m.StartAccessRecording()
	rec2 := m.StopAccessRecording()
	if rec2 == nil {
		t.Fatal("StopAccessRecording after start should return non-nil result")
	}
	if rec2.Slots == nil {
		t.Error("Slots map should be non-nil after start/stop")
	}
}

// TestMemoryStateDB_DatabaseAndError tests the Database() and Error() stubs.
func TestMemoryStateDB_DatabaseAndError(t *testing.T) {
	m := NewMemoryStateDB()

	if m.Database() != nil {
		t.Error("Database() should return nil for MemoryStateDB")
	}
	if m.Error() != nil {
		t.Error("Error() should return nil for MemoryStateDB")
	}
}

// TestMemoryStateDB_Preimages tests Preimages() returns recorded preimages.
func TestMemoryStateDB_Preimages(t *testing.T) {
	m := NewMemoryStateDB()
	data := []byte("test preimage")
	hash := types.HexToHash("0xabab")

	m.AddPreimage(hash, data)

	preimages := m.Preimages()
	if len(preimages) != 1 {
		t.Fatalf("expected 1 preimage, got %d", len(preimages))
	}
	if !bytes.Equal(preimages[hash], data) {
		t.Error("preimage data mismatch")
	}
}
