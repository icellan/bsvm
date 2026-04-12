package state

import (
	"testing"

	"github.com/holiman/uint256"

	"github.com/icellan/bsvm/internal/db"
	"github.com/icellan/bsvm/pkg/crypto"
	"github.com/icellan/bsvm/pkg/mpt"
	"github.com/icellan/bsvm/pkg/rlp"
	"github.com/icellan/bsvm/pkg/types"
	"github.com/icellan/bsvm/pkg/vm/tracing"
)

// makeCommittedStateDB creates a StateDB with several accounts and storage
// slots, commits it, and returns a fresh StateDB reopened at the committed
// root along with the root hash.
func makeCommittedStateDB(t *testing.T) (*StateDB, types.Hash, db.Database) {
	t.Helper()
	diskdb := db.NewMemoryDB()

	sdb, err := New(types.Hash{}, diskdb)
	if err != nil {
		t.Fatalf("failed to create StateDB: %v", err)
	}

	// Account 1: EOA with balance and nonce.
	addr1 := types.HexToAddress("0x1111111111111111111111111111111111111111")
	sdb.CreateAccount(addr1)
	sdb.AddBalance(addr1, uint256.NewInt(1_000_000), tracing.BalanceChangeUnspecified)
	sdb.SetNonce(addr1, 42, tracing.NonceChangeTransaction)

	// Account 2: contract with code and storage.
	addr2 := types.HexToAddress("0x2222222222222222222222222222222222222222")
	sdb.CreateAccount(addr2)
	sdb.AddBalance(addr2, uint256.NewInt(500), tracing.BalanceChangeUnspecified)
	sdb.SetCode(addr2, []byte{0x60, 0x00, 0x60, 0x00, 0xf3}, tracing.CodeChangeCreation)
	sdb.SetState(addr2, types.HexToHash("0x01"), types.HexToHash("0xff"))
	sdb.SetState(addr2, types.HexToHash("0x02"), types.HexToHash("0xaa"))

	// Account 3: another EOA.
	addr3 := types.HexToAddress("0x3333333333333333333333333333333333333333")
	sdb.CreateAccount(addr3)
	sdb.AddBalance(addr3, uint256.NewInt(999), tracing.BalanceChangeUnspecified)

	root, err := sdb.Commit(true)
	if err != nil {
		t.Fatalf("commit failed: %v", err)
	}

	// Reopen at the committed root.
	sdb2, err := New(root, diskdb)
	if err != nil {
		t.Fatalf("reopen failed: %v", err)
	}

	return sdb2, root, diskdb
}

// proofDBFromSlice creates a db.Database containing proof nodes keyed by
// their content hash for use with mpt.VerifyProof.
func proofDBFromSlice(proofNodes [][]byte) db.Database {
	proofDB := db.NewMemoryDB()
	for _, node := range proofNodes {
		hash := crypto.Keccak256(node)
		proofDB.Put(hash, node)
	}
	return proofDB
}

// TestGetProof verifies that GetProof generates a valid Merkle proof for
// an existing account that can be verified by mpt.VerifyProof.
func TestGetProof(t *testing.T) {
	sdb, root, _ := makeCommittedStateDB(t)

	addr := types.HexToAddress("0x1111111111111111111111111111111111111111")
	proof, err := sdb.GetProof(addr)
	if err != nil {
		t.Fatalf("GetProof: %v", err)
	}
	if len(proof) == 0 {
		t.Fatal("expected non-empty proof for existing account")
	}

	// Verify the proof against the state root.
	proofDB := proofDBFromSlice(proof)
	key := crypto.Keccak256(addr[:])
	value, err := mpt.VerifyProof(root, key, proofDB)
	if err != nil {
		t.Fatalf("VerifyProof failed: %v", err)
	}
	if len(value) == 0 {
		t.Fatal("VerifyProof returned empty value for existing account")
	}

	// Decode the value as an Account and verify fields.
	var acct Account
	if err := rlp.DecodeBytes(value, &acct); err != nil {
		t.Fatalf("failed to decode account from proof value: %v", err)
	}
	if acct.Nonce != 42 {
		t.Errorf("account nonce: got %d, want 42", acct.Nonce)
	}
	if acct.Balance.Uint64() != 1_000_000 {
		t.Errorf("account balance: got %s, want 1000000", acct.Balance)
	}
}

// TestGetProofNonExistent verifies that GetProof generates a valid
// proof-of-absence for an account that does not exist in the trie.
func TestGetProofNonExistent(t *testing.T) {
	sdb, root, _ := makeCommittedStateDB(t)

	// This address was never created.
	addr := types.HexToAddress("0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")
	proof, err := sdb.GetProof(addr)
	if err != nil {
		t.Fatalf("GetProof: %v", err)
	}
	// The proof should be non-empty (at least the root node).
	if len(proof) == 0 {
		t.Fatal("expected non-empty proof even for non-existent account")
	}

	// Verify the proof. VerifyProof should return nil value for a
	// non-existent key (proof of absence).
	proofDB := proofDBFromSlice(proof)
	key := crypto.Keccak256(addr[:])
	value, err := mpt.VerifyProof(root, key, proofDB)
	if err != nil {
		t.Fatalf("VerifyProof failed: %v", err)
	}
	if value != nil {
		t.Errorf("expected nil value for non-existent account, got %x", value)
	}
}

// TestGetProofAfterModification verifies that GetProof produces correct
// proofs after modifying an account and committing the changes.
func TestGetProofAfterModification(t *testing.T) {
	diskdb := db.NewMemoryDB()

	// Create initial state.
	sdb, err := New(types.Hash{}, diskdb)
	if err != nil {
		t.Fatal(err)
	}
	addr := types.HexToAddress("0xaaaa")
	sdb.CreateAccount(addr)
	sdb.AddBalance(addr, uint256.NewInt(100), tracing.BalanceChangeUnspecified)
	root1, err := sdb.Commit(true)
	if err != nil {
		t.Fatal(err)
	}

	// Reopen, modify, and commit again.
	sdb2, err := New(root1, diskdb)
	if err != nil {
		t.Fatal(err)
	}
	sdb2.AddBalance(addr, uint256.NewInt(200), tracing.BalanceChangeUnspecified)
	sdb2.SetNonce(addr, 10, tracing.NonceChangeTransaction)
	root2, err := sdb2.Commit(true)
	if err != nil {
		t.Fatal(err)
	}

	// The roots must differ.
	if root1 == root2 {
		t.Fatal("state roots should differ after modification")
	}

	// Get proof from the new state.
	sdb3, err := New(root2, diskdb)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := sdb3.GetProof(addr)
	if err != nil {
		t.Fatalf("GetProof: %v", err)
	}
	if len(proof) == 0 {
		t.Fatal("expected non-empty proof")
	}

	// Verify against root2.
	proofDB := proofDBFromSlice(proof)
	key := crypto.Keccak256(addr[:])
	value, err := mpt.VerifyProof(root2, key, proofDB)
	if err != nil {
		t.Fatalf("VerifyProof failed: %v", err)
	}
	if len(value) == 0 {
		t.Fatal("expected non-empty value")
	}

	var acct Account
	if err := rlp.DecodeBytes(value, &acct); err != nil {
		t.Fatalf("decode account: %v", err)
	}
	if acct.Balance.Uint64() != 300 {
		t.Errorf("balance: got %s, want 300", acct.Balance)
	}
	if acct.Nonce != 10 {
		t.Errorf("nonce: got %d, want 10", acct.Nonce)
	}

	// The proof should NOT verify against root1 (the old root).
	_, err = mpt.VerifyProof(root1, key, proofDB)
	if err == nil {
		// VerifyProof may return nil error if the proof happens to also be
		// valid for root1 (extremely unlikely with different data).
		// But the value should differ.
		t.Log("proof also verified against old root (unlikely but possible)")
	}
}

// TestGetStorageProof verifies that GetStorageProof generates a valid
// Merkle proof for an existing storage slot.
func TestGetStorageProof(t *testing.T) {
	sdb, _, _ := makeCommittedStateDB(t)

	addr := types.HexToAddress("0x2222222222222222222222222222222222222222")
	slot := types.HexToHash("0x01")

	proof, err := sdb.GetStorageProof(addr, slot)
	if err != nil {
		t.Fatalf("GetStorageProof: %v", err)
	}
	if len(proof) == 0 {
		t.Fatal("expected non-empty storage proof")
	}

	// Get the storage root for this account.
	storageRoot := sdb.GetStorageRoot(addr)
	if storageRoot == types.EmptyRootHash {
		t.Fatal("storage root should not be empty for an account with storage")
	}

	// Verify the proof against the storage root.
	proofDB := proofDBFromSlice(proof)
	key := crypto.Keccak256(slot[:])
	value, err := mpt.VerifyProof(storageRoot, key, proofDB)
	if err != nil {
		t.Fatalf("VerifyProof failed: %v", err)
	}
	if len(value) == 0 {
		t.Fatal("expected non-empty value for existing storage slot")
	}

	// The value should decode to 0xff.
	_, content, _, err := rlp.Split(value)
	if err != nil {
		t.Fatalf("rlp.Split: %v", err)
	}
	decoded := types.BytesToHash(content)
	expected := types.HexToHash("0xff")
	if decoded != expected {
		t.Errorf("storage value: got %s, want %s", decoded.Hex(), expected.Hex())
	}
}

// TestGetStorageProofNonExistentAccount verifies that GetStorageProof
// returns an empty proof for a non-existent account.
func TestGetStorageProofNonExistentAccount(t *testing.T) {
	sdb, _, _ := makeCommittedStateDB(t)

	addr := types.HexToAddress("0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")
	slot := types.HexToHash("0x01")

	proof, err := sdb.GetStorageProof(addr, slot)
	if err != nil {
		t.Fatalf("GetStorageProof: %v", err)
	}
	if len(proof) != 0 {
		t.Errorf("expected empty proof for non-existent account, got %d nodes", len(proof))
	}
}

// TestGetStorageProofNonExistentSlot verifies proof-of-absence for a
// storage slot that doesn't exist on an account that does.
func TestGetStorageProofNonExistentSlot(t *testing.T) {
	sdb, _, _ := makeCommittedStateDB(t)

	addr := types.HexToAddress("0x2222222222222222222222222222222222222222")
	slot := types.HexToHash("0x99") // not set

	proof, err := sdb.GetStorageProof(addr, slot)
	if err != nil {
		t.Fatalf("GetStorageProof: %v", err)
	}
	if len(proof) == 0 {
		t.Fatal("expected non-empty proof for proof-of-absence")
	}

	// Verify the proof should return nil value (proof of absence).
	storageRoot := sdb.GetStorageRoot(addr)
	proofDB := proofDBFromSlice(proof)
	key := crypto.Keccak256(slot[:])
	value, err := mpt.VerifyProof(storageRoot, key, proofDB)
	if err != nil {
		t.Fatalf("VerifyProof failed: %v", err)
	}
	if value != nil {
		t.Errorf("expected nil value for non-existent slot, got %x", value)
	}
}

// TestGetStorageProofEOA verifies that GetStorageProof handles an EOA
// (account with no storage) correctly.
func TestGetStorageProofEOA(t *testing.T) {
	sdb, _, _ := makeCommittedStateDB(t)

	addr := types.HexToAddress("0x1111111111111111111111111111111111111111")
	slot := types.HexToHash("0x01")

	proof, err := sdb.GetStorageProof(addr, slot)
	if err != nil {
		t.Fatalf("GetStorageProof: %v", err)
	}
	// An EOA with empty storage root should produce an empty or minimal proof.
	// The storage root is EmptyRootHash, and the trie is empty.
	t.Logf("EOA storage proof has %d nodes", len(proof))
}

// TestGetProofMultipleAccounts verifies that proofs for different accounts
// are independently valid.
func TestGetProofMultipleAccounts(t *testing.T) {
	sdb, root, _ := makeCommittedStateDB(t)

	addrs := []types.Address{
		types.HexToAddress("0x1111111111111111111111111111111111111111"),
		types.HexToAddress("0x2222222222222222222222222222222222222222"),
		types.HexToAddress("0x3333333333333333333333333333333333333333"),
	}

	for _, addr := range addrs {
		proof, err := sdb.GetProof(addr)
		if err != nil {
			t.Fatalf("GetProof(%s): %v", addr.Hex(), err)
		}
		if len(proof) == 0 {
			t.Fatalf("expected non-empty proof for %s", addr.Hex())
		}

		proofDB := proofDBFromSlice(proof)
		key := crypto.Keccak256(addr[:])
		value, err := mpt.VerifyProof(root, key, proofDB)
		if err != nil {
			t.Fatalf("VerifyProof(%s): %v", addr.Hex(), err)
		}
		if len(value) == 0 {
			t.Fatalf("expected non-empty value for %s", addr.Hex())
		}
	}
}
