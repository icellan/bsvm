package prover

import (
	"testing"

	"github.com/holiman/uint256"

	"github.com/icellan/bsvm/internal/db"
	"github.com/icellan/bsvm/pkg/crypto"
	"github.com/icellan/bsvm/pkg/mpt"
	"github.com/icellan/bsvm/pkg/state"
	"github.com/icellan/bsvm/pkg/types"
	"github.com/icellan/bsvm/pkg/vm/tracing"
)

// makeCommittedState creates a StateDB with several accounts and storage,
// commits it, and returns a fresh StateDB reopened at the committed root.
func makeCommittedState(t *testing.T) (*state.StateDB, types.Hash) {
	t.Helper()
	diskdb := db.NewMemoryDB()

	sdb, err := state.New(types.Hash{}, diskdb)
	if err != nil {
		t.Fatalf("failed to create StateDB: %v", err)
	}

	// EOA account.
	addr1 := types.HexToAddress("0xaaaa")
	sdb.CreateAccount(addr1)
	sdb.AddBalance(addr1, uint256.NewInt(1_000_000), tracing.BalanceChangeUnspecified)
	sdb.SetNonce(addr1, 5, tracing.NonceChangeTransaction)

	// Contract account with storage.
	addr2 := types.HexToAddress("0xbbbb")
	sdb.CreateAccount(addr2)
	sdb.AddBalance(addr2, uint256.NewInt(500), tracing.BalanceChangeUnspecified)
	sdb.SetCode(addr2, []byte{0x60, 0x00, 0x60, 0x00, 0xf3}, tracing.CodeChangeCreation)
	sdb.SetState(addr2, types.HexToHash("0x01"), types.HexToHash("0xff"))
	sdb.SetState(addr2, types.HexToHash("0x02"), types.HexToHash("0xee"))

	// Another EOA.
	addr3 := types.HexToAddress("0xcccc")
	sdb.CreateAccount(addr3)
	sdb.AddBalance(addr3, uint256.NewInt(100), tracing.BalanceChangeUnspecified)

	root, err := sdb.Commit(true)
	if err != nil {
		t.Fatalf("commit failed: %v", err)
	}

	sdb2, err := state.New(root, diskdb)
	if err != nil {
		t.Fatalf("reopen failed: %v", err)
	}

	return sdb2, root
}

// proofDBFromNodes creates a db.Database from proof node slices for
// use with mpt.VerifyProof.
func proofDBFromNodes(proofNodes [][]byte) db.Database {
	proofDB := db.NewMemoryDB()
	for _, node := range proofNodes {
		hash := crypto.Keccak256(node)
		proofDB.Put(hash, node)
	}
	return proofDB
}

// TestStateExportWithRealProofs verifies that ExportStateForProving
// generates non-empty real proofs for all specified accounts and storage.
func TestStateExportWithRealProofs(t *testing.T) {
	sdb, _ := makeCommittedState(t)

	addr1 := types.HexToAddress("0xaaaa")
	addr2 := types.HexToAddress("0xbbbb")

	accessedAccounts := []types.Address{addr1, addr2}
	accessedSlots := map[types.Address][]types.Hash{
		addr2: {
			types.HexToHash("0x01"),
			types.HexToHash("0x02"),
		},
	}

	export, err := ExportStateForProving(sdb, accessedAccounts, accessedSlots)
	if err != nil {
		t.Fatalf("ExportStateForProving: %v", err)
	}

	if export == nil {
		t.Fatal("export is nil")
	}
	if export.PreStateRoot == (types.Hash{}) {
		t.Error("pre-state root should not be zero")
	}
	if len(export.Accounts) != 2 {
		t.Fatalf("expected 2 accounts, got %d", len(export.Accounts))
	}

	// Verify addr1 export.
	acct1 := export.Accounts[0]
	if acct1.Address != addr1 {
		t.Errorf("expected addr1, got %s", acct1.Address.Hex())
	}
	if acct1.Nonce != 5 {
		t.Errorf("addr1 nonce: got %d, want 5", acct1.Nonce)
	}
	if acct1.Balance.Uint64() != 1_000_000 {
		t.Errorf("addr1 balance: got %s, want 1000000", acct1.Balance)
	}
	if len(acct1.AccountProof) == 0 {
		t.Error("addr1 account proof should be non-empty")
	}

	// Verify addr2 export.
	acct2 := export.Accounts[1]
	if acct2.Address != addr2 {
		t.Errorf("expected addr2, got %s", acct2.Address.Hex())
	}
	if len(acct2.AccountProof) == 0 {
		t.Error("addr2 account proof should be non-empty")
	}
	if len(acct2.StorageSlots) != 2 {
		t.Fatalf("addr2 expected 2 storage slots, got %d", len(acct2.StorageSlots))
	}

	// Both storage slot proofs should be non-empty.
	for i, slot := range acct2.StorageSlots {
		if len(slot.Proof) == 0 {
			t.Errorf("addr2 storage slot %d proof should be non-empty", i)
		}
	}
}

// TestStateExportProofVerification verifies that each exported account
// proof can be verified against the state root using mpt.VerifyProof.
func TestStateExportProofVerification(t *testing.T) {
	sdb, _ := makeCommittedState(t)

	addr1 := types.HexToAddress("0xaaaa")
	addr2 := types.HexToAddress("0xbbbb")
	addr3 := types.HexToAddress("0xcccc")

	accessedAccounts := []types.Address{addr1, addr2, addr3}
	accessedSlots := map[types.Address][]types.Hash{
		addr2: {
			types.HexToHash("0x01"),
			types.HexToHash("0x02"),
		},
	}

	export, err := ExportStateForProving(sdb, accessedAccounts, accessedSlots)
	if err != nil {
		t.Fatalf("ExportStateForProving: %v", err)
	}

	// Verify each account proof against the state root.
	for _, acct := range export.Accounts {
		if len(acct.AccountProof) == 0 {
			t.Errorf("account %s has empty proof", acct.Address.Hex())
			continue
		}

		proofDB := proofDBFromNodes(acct.AccountProof)
		key := crypto.Keccak256(acct.Address[:])
		value, err := mpt.VerifyProof(export.PreStateRoot, key, proofDB)
		if err != nil {
			t.Errorf("VerifyProof(%s): %v", acct.Address.Hex(), err)
			continue
		}
		if len(value) == 0 {
			t.Errorf("VerifyProof(%s): expected non-empty value", acct.Address.Hex())
		}
	}

	// Verify storage proofs for addr2.
	addr2Export := export.Accounts[1]
	if addr2Export.Address != addr2 {
		t.Fatalf("expected addr2 at index 1, got %s", addr2Export.Address.Hex())
	}

	for _, slot := range addr2Export.StorageSlots {
		if len(slot.Proof) == 0 {
			t.Errorf("storage slot %s has empty proof", slot.Key.Hex())
			continue
		}

		proofDB := proofDBFromNodes(slot.Proof)
		key := crypto.Keccak256(slot.Key[:])
		value, err := mpt.VerifyProof(addr2Export.StorageRoot, key, proofDB)
		if err != nil {
			t.Errorf("VerifyProof(storage %s): %v", slot.Key.Hex(), err)
			continue
		}
		if len(value) == 0 {
			t.Errorf("VerifyProof(storage %s): expected non-empty value", slot.Key.Hex())
		}
	}
}

// TestStateExportNonExistentAccount verifies that exporting state for
// a non-existent account produces a valid proof-of-absence.
func TestStateExportNonExistentAccount(t *testing.T) {
	sdb, _ := makeCommittedState(t)

	// This address was never created.
	addr := types.HexToAddress("0xdeadbeef")

	accessedAccounts := []types.Address{addr}
	accessedSlots := map[types.Address][]types.Hash{}

	export, err := ExportStateForProving(sdb, accessedAccounts, accessedSlots)
	if err != nil {
		t.Fatalf("ExportStateForProving: %v", err)
	}

	if len(export.Accounts) != 1 {
		t.Fatalf("expected 1 account, got %d", len(export.Accounts))
	}

	acct := export.Accounts[0]
	// The proof should be non-empty (proves absence).
	if len(acct.AccountProof) == 0 {
		t.Error("expected non-empty proof for proof-of-absence")
	}

	// Verify the proof returns nil value.
	proofDB := proofDBFromNodes(acct.AccountProof)
	key := crypto.Keccak256(addr[:])
	value, err := mpt.VerifyProof(export.PreStateRoot, key, proofDB)
	if err != nil {
		t.Fatalf("VerifyProof: %v", err)
	}
	if value != nil {
		t.Errorf("expected nil value for non-existent account, got %x", value)
	}
}

// TestStateExportEmptyState verifies exporting from an empty state.
func TestStateExportEmptyState(t *testing.T) {
	diskdb := db.NewMemoryDB()
	sdb, err := state.New(types.Hash{}, diskdb)
	if err != nil {
		t.Fatal(err)
	}

	export, err := ExportStateForProving(sdb, nil, nil)
	if err != nil {
		t.Fatalf("ExportStateForProving: %v", err)
	}

	if export == nil {
		t.Fatal("export should not be nil")
	}
	if len(export.Accounts) != 0 {
		t.Errorf("expected 0 accounts, got %d", len(export.Accounts))
	}
}
