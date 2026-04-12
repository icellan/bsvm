package state

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"testing"

	"github.com/holiman/uint256"

	"github.com/icellan/bsvm/internal/db"
	"github.com/icellan/bsvm/pkg/crypto"
	"github.com/icellan/bsvm/pkg/types"
	"github.com/icellan/bsvm/pkg/vm/tracing"
)

// newSnapshotTestStateDB creates a test StateDB with a MemoryDB.
func newSnapshotTestStateDB(t *testing.T) (*StateDB, db.Database) {
	t.Helper()
	diskdb := db.NewMemoryDB()
	sdb, err := New(types.Hash{}, diskdb)
	if err != nil {
		t.Fatalf("failed to create StateDB: %v", err)
	}
	return sdb, diskdb
}

// TestSnapshotEmptyState tests round-tripping an empty state snapshot.
func TestSnapshotEmptyState(t *testing.T) {
	sdb, _ := newSnapshotTestStateDB(t)

	var buf bytes.Buffer
	if err := sdb.CreateSnapshot(&buf); err != nil {
		t.Fatalf("CreateSnapshot failed: %v", err)
	}

	// Restore into a fresh database.
	restoreDB := db.NewMemoryDB()
	root, err := RestoreSnapshot(&buf, restoreDB)
	if err != nil {
		t.Fatalf("RestoreSnapshot failed: %v", err)
	}

	// Verify the restored root can be used to create a StateDB.
	restored, err := New(root, restoreDB)
	if err != nil {
		t.Fatalf("New from restored root failed: %v", err)
	}

	// The restored state should have the same root.
	restoredRoot := restored.IntermediateRoot(true)
	if restoredRoot != root {
		t.Errorf("root mismatch: got %s, want %s", restoredRoot.Hex(), root.Hex())
	}
}

// TestSnapshotSingleAccountNoCodeNoStorage tests a single account with no code or storage.
func TestSnapshotSingleAccountNoCodeNoStorage(t *testing.T) {
	sdb, _ := newSnapshotTestStateDB(t)

	addr := types.HexToAddress("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	sdb.CreateAccount(addr)
	sdb.AddBalance(addr, uint256.NewInt(42), tracing.BalanceChangeUnspecified)
	sdb.SetNonce(addr, 7, tracing.NonceChangeUnspecified)

	var buf bytes.Buffer
	if err := sdb.CreateSnapshot(&buf); err != nil {
		t.Fatalf("CreateSnapshot failed: %v", err)
	}

	restoreDB := db.NewMemoryDB()
	root, err := RestoreSnapshot(&buf, restoreDB)
	if err != nil {
		t.Fatalf("RestoreSnapshot failed: %v", err)
	}

	restored, err := New(root, restoreDB)
	if err != nil {
		t.Fatalf("New from restored root failed: %v", err)
	}

	if !restored.Exist(addr) {
		t.Fatal("restored account does not exist")
	}
	if got := restored.GetBalance(addr); got.Cmp(uint256.NewInt(42)) != 0 {
		t.Errorf("balance mismatch: got %s, want 42", got)
	}
	if got := restored.GetNonce(addr); got != 7 {
		t.Errorf("nonce mismatch: got %d, want 7", got)
	}
}

// TestSnapshotAccountWithCode tests an account with code but no storage.
func TestSnapshotAccountWithCode(t *testing.T) {
	sdb, _ := newSnapshotTestStateDB(t)

	addr := types.HexToAddress("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	sdb.CreateAccount(addr)
	code := []byte{0x60, 0x00, 0x60, 0x00, 0xFD} // PUSH 0, PUSH 0, REVERT
	sdb.SetCode(addr, code, tracing.CodeChangeUnspecified)
	sdb.AddBalance(addr, uint256.NewInt(1000), tracing.BalanceChangeUnspecified)

	var buf bytes.Buffer
	if err := sdb.CreateSnapshot(&buf); err != nil {
		t.Fatalf("CreateSnapshot failed: %v", err)
	}

	restoreDB := db.NewMemoryDB()
	root, err := RestoreSnapshot(&buf, restoreDB)
	if err != nil {
		t.Fatalf("RestoreSnapshot failed: %v", err)
	}

	restored, err := New(root, restoreDB)
	if err != nil {
		t.Fatalf("New from restored root failed: %v", err)
	}

	restoredCode := restored.GetCode(addr)
	if !bytes.Equal(restoredCode, code) {
		t.Errorf("code mismatch: got %x, want %x", restoredCode, code)
	}

	codeHash := restored.GetCodeHash(addr)
	expectedHash := types.BytesToHash(crypto.Keccak256(code))
	if codeHash != expectedHash {
		t.Errorf("code hash mismatch: got %s, want %s", codeHash.Hex(), expectedHash.Hex())
	}
}

// TestSnapshotAccountWithStorage tests an account with storage slots.
func TestSnapshotAccountWithStorage(t *testing.T) {
	sdb, _ := newSnapshotTestStateDB(t)

	addr := types.HexToAddress("0xcccccccccccccccccccccccccccccccccccccccc")
	sdb.CreateAccount(addr)
	sdb.AddBalance(addr, uint256.NewInt(500), tracing.BalanceChangeUnspecified)

	key1 := types.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000001")
	val1 := types.HexToHash("0x00000000000000000000000000000000000000000000000000000000000000ff")
	key2 := types.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000002")
	val2 := types.HexToHash("0x0000000000000000000000000000000000000000000000000000000000001234")

	sdb.SetState(addr, key1, val1)
	sdb.SetState(addr, key2, val2)

	var buf bytes.Buffer
	if err := sdb.CreateSnapshot(&buf); err != nil {
		t.Fatalf("CreateSnapshot failed: %v", err)
	}

	restoreDB := db.NewMemoryDB()
	root, err := RestoreSnapshot(&buf, restoreDB)
	if err != nil {
		t.Fatalf("RestoreSnapshot failed: %v", err)
	}

	restored, err := New(root, restoreDB)
	if err != nil {
		t.Fatalf("New from restored root failed: %v", err)
	}

	if got := restored.GetState(addr, key1); got != val1 {
		t.Errorf("storage slot 1 mismatch: got %s, want %s", got.Hex(), val1.Hex())
	}
	if got := restored.GetState(addr, key2); got != val2 {
		t.Errorf("storage slot 2 mismatch: got %s, want %s", got.Hex(), val2.Hex())
	}
}

// TestSnapshotMultipleAccounts tests snapshot with multiple accounts.
func TestSnapshotMultipleAccounts(t *testing.T) {
	sdb, _ := newSnapshotTestStateDB(t)

	addrs := []types.Address{
		types.HexToAddress("0x1111111111111111111111111111111111111111"),
		types.HexToAddress("0x2222222222222222222222222222222222222222"),
		types.HexToAddress("0x3333333333333333333333333333333333333333"),
	}

	for i, addr := range addrs {
		sdb.CreateAccount(addr)
		sdb.AddBalance(addr, uint256.NewInt(uint64((i+1)*100)), tracing.BalanceChangeUnspecified)
		sdb.SetNonce(addr, uint64(i+1), tracing.NonceChangeUnspecified)
	}

	// Add code to one account.
	code := []byte{0x60, 0x42, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xF3}
	sdb.SetCode(addrs[1], code, tracing.CodeChangeUnspecified)

	// Add storage to another.
	storageKey := types.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000005")
	storageVal := types.HexToHash("0x000000000000000000000000000000000000000000000000000000000000BEEF")
	sdb.SetState(addrs[2], storageKey, storageVal)

	var buf bytes.Buffer
	if err := sdb.CreateSnapshot(&buf); err != nil {
		t.Fatalf("CreateSnapshot failed: %v", err)
	}

	restoreDB := db.NewMemoryDB()
	root, err := RestoreSnapshot(&buf, restoreDB)
	if err != nil {
		t.Fatalf("RestoreSnapshot failed: %v", err)
	}

	restored, err := New(root, restoreDB)
	if err != nil {
		t.Fatalf("New from restored root failed: %v", err)
	}

	for i, addr := range addrs {
		if !restored.Exist(addr) {
			t.Errorf("account %d does not exist after restore", i)
			continue
		}
		expectedBalance := uint256.NewInt(uint64((i + 1) * 100))
		if got := restored.GetBalance(addr); got.Cmp(expectedBalance) != 0 {
			t.Errorf("account %d balance: got %s, want %s", i, got, expectedBalance)
		}
		if got := restored.GetNonce(addr); got != uint64(i+1) {
			t.Errorf("account %d nonce: got %d, want %d", i, got, i+1)
		}
	}

	// Check code.
	if got := restored.GetCode(addrs[1]); !bytes.Equal(got, code) {
		t.Errorf("code mismatch on account 1: got %x, want %x", got, code)
	}

	// Check storage.
	if got := restored.GetState(addrs[2], storageKey); got != storageVal {
		t.Errorf("storage mismatch on account 2: got %s, want %s", got.Hex(), storageVal.Hex())
	}
}

// TestSnapshotRootMatches verifies the restored state root matches the original.
func TestSnapshotRootMatches(t *testing.T) {
	sdb, _ := newSnapshotTestStateDB(t)

	addr := types.HexToAddress("0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")
	sdb.CreateAccount(addr)
	sdb.AddBalance(addr, uint256.NewInt(12345), tracing.BalanceChangeUnspecified)
	sdb.SetNonce(addr, 99, tracing.NonceChangeUnspecified)
	sdb.SetCode(addr, []byte{0x01, 0x02, 0x03}, tracing.CodeChangeUnspecified)
	sdb.SetState(addr, types.HexToHash("0x01"), types.HexToHash("0xAA"))

	// Commit to get the root.
	sdb.Finalise(true)
	originalRoot, err := sdb.Commit(true)
	if err != nil {
		t.Fatalf("Commit failed: %v", err)
	}

	// Re-open state to create snapshot (Commit invalidates the trie).
	sdb2, err := New(originalRoot, sdb.db.DiskDB())
	if err != nil {
		t.Fatalf("re-open state failed: %v", err)
	}

	var buf bytes.Buffer
	if err := sdb2.CreateSnapshot(&buf); err != nil {
		t.Fatalf("CreateSnapshot failed: %v", err)
	}

	restoreDB := db.NewMemoryDB()
	restoredRoot, err := RestoreSnapshot(&buf, restoreDB)
	if err != nil {
		t.Fatalf("RestoreSnapshot failed: %v", err)
	}

	if restoredRoot != originalRoot {
		t.Errorf("root mismatch: got %s, want %s", restoredRoot.Hex(), originalRoot.Hex())
	}
}

// TestSnapshotCorruptedChecksum verifies that a corrupted checksum is detected.
func TestSnapshotCorruptedChecksum(t *testing.T) {
	sdb, _ := newSnapshotTestStateDB(t)

	addr := types.HexToAddress("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	sdb.CreateAccount(addr)
	sdb.AddBalance(addr, uint256.NewInt(1), tracing.BalanceChangeUnspecified)

	var buf bytes.Buffer
	if err := sdb.CreateSnapshot(&buf); err != nil {
		t.Fatalf("CreateSnapshot failed: %v", err)
	}

	// Corrupt the last byte of the checksum.
	data := buf.Bytes()
	data[len(data)-1] ^= 0xFF

	restoreDB := db.NewMemoryDB()
	_, err := RestoreSnapshot(bytes.NewReader(data), restoreDB)
	if err == nil {
		t.Fatal("expected error for corrupted checksum, got nil")
	}
	if err.Error() != "snapshot checksum mismatch" {
		t.Errorf("unexpected error: %v", err)
	}
}

// TestSnapshotTruncated verifies that a truncated snapshot is detected.
func TestSnapshotTruncated(t *testing.T) {
	sdb, _ := newSnapshotTestStateDB(t)

	addr := types.HexToAddress("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	sdb.CreateAccount(addr)
	sdb.AddBalance(addr, uint256.NewInt(1), tracing.BalanceChangeUnspecified)

	var buf bytes.Buffer
	if err := sdb.CreateSnapshot(&buf); err != nil {
		t.Fatalf("CreateSnapshot failed: %v", err)
	}

	// Truncate the snapshot at various points.
	data := buf.Bytes()
	truncations := []int{0, 3, 10, len(data) / 2, len(data) - 1}
	for _, size := range truncations {
		restoreDB := db.NewMemoryDB()
		_, err := RestoreSnapshot(bytes.NewReader(data[:size]), restoreDB)
		if err == nil {
			t.Errorf("expected error for truncation at %d bytes, got nil", size)
		}
	}
}

// TestSnapshotWrongVersion verifies that a wrong version number is rejected.
func TestSnapshotWrongVersion(t *testing.T) {
	sdb, _ := newSnapshotTestStateDB(t)

	var buf bytes.Buffer
	if err := sdb.CreateSnapshot(&buf); err != nil {
		t.Fatalf("CreateSnapshot failed: %v", err)
	}

	data := buf.Bytes()

	// Change version byte (offset 4) to 99, then fix checksum.
	payload := make([]byte, len(data)-checksumSize)
	copy(payload, data[:len(data)-checksumSize])
	payload[4] = 99
	checksum := sha256.Sum256(payload)
	corrupted := append(payload, checksum[:]...)

	restoreDB := db.NewMemoryDB()
	_, err := RestoreSnapshot(bytes.NewReader(corrupted), restoreDB)
	if err == nil {
		t.Fatal("expected error for wrong version, got nil")
	}
	if err.Error() != "unsupported snapshot version 99" {
		t.Errorf("unexpected error: %v", err)
	}
}

// TestSnapshotWrongMagic verifies that wrong magic bytes are rejected.
func TestSnapshotWrongMagic(t *testing.T) {
	sdb, _ := newSnapshotTestStateDB(t)

	var buf bytes.Buffer
	if err := sdb.CreateSnapshot(&buf); err != nil {
		t.Fatalf("CreateSnapshot failed: %v", err)
	}

	data := buf.Bytes()

	// Change magic bytes, then fix checksum.
	payload := make([]byte, len(data)-checksumSize)
	copy(payload, data[:len(data)-checksumSize])
	payload[0] = 'X'
	checksum := sha256.Sum256(payload)
	corrupted := append(payload, checksum[:]...)

	restoreDB := db.NewMemoryDB()
	_, err := RestoreSnapshot(bytes.NewReader(corrupted), restoreDB)
	if err == nil {
		t.Fatal("expected error for wrong magic, got nil")
	}
	if err.Error() != "invalid snapshot magic" {
		t.Errorf("unexpected error: %v", err)
	}
}

// TestSnapshotDeterministic verifies that creating a snapshot twice
// from the same state produces identical output.
func TestSnapshotDeterministic(t *testing.T) {
	diskdb := db.NewMemoryDB()

	// Build state, commit.
	sdb, err := New(types.Hash{}, diskdb)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	addr := types.HexToAddress("0xdddddddddddddddddddddddddddddddddddddd")
	sdb.CreateAccount(addr)
	sdb.AddBalance(addr, uint256.NewInt(999), tracing.BalanceChangeUnspecified)
	sdb.SetState(addr, types.HexToHash("0x01"), types.HexToHash("0x02"))
	sdb.Finalise(true)
	root, err := sdb.Commit(true)
	if err != nil {
		t.Fatalf("Commit failed: %v", err)
	}

	// Create snapshot twice from the same committed state.
	var buf1, buf2 bytes.Buffer

	sdb1, err := New(root, diskdb)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	if err := sdb1.CreateSnapshot(&buf1); err != nil {
		t.Fatalf("CreateSnapshot 1 failed: %v", err)
	}

	sdb2, err := New(root, diskdb)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	if err := sdb2.CreateSnapshot(&buf2); err != nil {
		t.Fatalf("CreateSnapshot 2 failed: %v", err)
	}

	if !bytes.Equal(buf1.Bytes(), buf2.Bytes()) {
		t.Error("two snapshots of the same state are not identical")
	}
}

// TestSnapshotTrailingGarbage verifies that trailing garbage after valid
// entries but before the checksum is detected.
func TestSnapshotTrailingGarbage(t *testing.T) {
	sdb, _ := newSnapshotTestStateDB(t)

	var buf bytes.Buffer
	if err := sdb.CreateSnapshot(&buf); err != nil {
		t.Fatalf("CreateSnapshot failed: %v", err)
	}

	data := buf.Bytes()
	// Insert garbage between the payload and the checksum.
	payload := data[:len(data)-checksumSize]
	garbage := []byte{0xDE, 0xAD}
	newPayload := append(append([]byte{}, payload...), garbage...)
	checksum := sha256.Sum256(newPayload)
	corrupted := append(newPayload, checksum[:]...)

	restoreDB := db.NewMemoryDB()
	_, err := RestoreSnapshot(bytes.NewReader(corrupted), restoreDB)
	if err == nil {
		t.Fatal("expected error for trailing garbage, got nil")
	}
}

// TestSnapshotLargeBalance tests an account with a large uint256 balance.
func TestSnapshotLargeBalance(t *testing.T) {
	sdb, _ := newSnapshotTestStateDB(t)

	addr := types.HexToAddress("0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee")
	sdb.CreateAccount(addr)
	// Set a large balance: 2^200
	largeBalance := new(uint256.Int)
	largeBalance.SetBytes(types.HexToHash("0x0000000000000100000000000000000000000000000000000000000000000000").Bytes())
	sdb.AddBalance(addr, largeBalance, tracing.BalanceChangeUnspecified)

	var buf bytes.Buffer
	if err := sdb.CreateSnapshot(&buf); err != nil {
		t.Fatalf("CreateSnapshot failed: %v", err)
	}

	restoreDB := db.NewMemoryDB()
	root, err := RestoreSnapshot(&buf, restoreDB)
	if err != nil {
		t.Fatalf("RestoreSnapshot failed: %v", err)
	}

	restored, err := New(root, restoreDB)
	if err != nil {
		t.Fatalf("New from restored root failed: %v", err)
	}

	if got := restored.GetBalance(addr); got.Cmp(largeBalance) != 0 {
		t.Errorf("balance mismatch: got %s, want %s", got, largeBalance)
	}
}

// TestSnapshotSnapshotTooShort verifies that a snapshot that is too short
// (less than minimum header + checksum) returns an error.
func TestSnapshotSnapshotTooShort(t *testing.T) {
	// Minimum is 4 (magic) + 1 (version) + 32 (root) + 8 (count) + 32 (checksum) = 77 bytes.
	shortData := make([]byte, 76)
	restoreDB := db.NewMemoryDB()
	_, err := RestoreSnapshot(bytes.NewReader(shortData), restoreDB)
	if err == nil {
		t.Fatal("expected error for too-short snapshot, got nil")
	}
}

// TestSnapshotEmptyCountBadChecksum verifies that even with zero entries,
// a bad checksum is detected.
func TestSnapshotEmptyCountBadChecksum(t *testing.T) {
	// Build a valid header with 0 entries.
	var payload bytes.Buffer
	payload.Write(snapshotMagic[:])
	payload.WriteByte(snapshotVersion)
	payload.Write(types.EmptyRootHash[:])
	var countBuf [8]byte
	binary.BigEndian.PutUint64(countBuf[:], 0)
	payload.Write(countBuf[:])

	// Compute correct checksum then corrupt it.
	checksum := sha256.Sum256(payload.Bytes())
	checksum[0] ^= 0xFF
	data := append(payload.Bytes(), checksum[:]...)

	restoreDB := db.NewMemoryDB()
	_, err := RestoreSnapshot(bytes.NewReader(data), restoreDB)
	if err == nil {
		t.Fatal("expected error for bad checksum on empty snapshot, got nil")
	}
}
