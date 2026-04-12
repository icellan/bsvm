package bridge

import (
	"testing"

	"github.com/icellan/bsvm/internal/db"
	"github.com/icellan/bsvm/pkg/types"
)

// ---------------------------------------------------------------------------
// TestDepositTree_AddAndHas
// ---------------------------------------------------------------------------

func TestDepositTree_AddAndHas(t *testing.T) {
	tree, err := NewDepositTree(db.NewMemoryDB(), types.EmptyRootHash)
	if err != nil {
		t.Fatalf("NewDepositTree: %v", err)
	}

	dep := NewDepositWithVout(
		types.HexToHash("0xaabb"),
		0,
		100,
		types.HexToAddress("0x1111111111111111111111111111111111111111"),
		50000,
	)
	dep.Confirmed = true

	// Before adding, the deposit should not exist.
	if tree.HasDeposit(dep.BSVTxID) {
		t.Error("deposit should not exist before adding")
	}

	// Add and verify.
	root := tree.AddDeposit(dep)
	if root == types.EmptyRootHash {
		t.Error("root should change after adding a deposit")
	}
	if root == (types.Hash{}) {
		t.Error("root should not be zero")
	}

	if !tree.HasDeposit(dep.BSVTxID) {
		t.Error("deposit should exist after adding")
	}
}

// ---------------------------------------------------------------------------
// TestDepositTree_GetDeposit
// ---------------------------------------------------------------------------

func TestDepositTree_GetDeposit(t *testing.T) {
	tree, err := NewDepositTree(db.NewMemoryDB(), types.EmptyRootHash)
	if err != nil {
		t.Fatalf("NewDepositTree: %v", err)
	}

	dep := NewDepositWithVout(
		types.HexToHash("0xccdd"),
		1,
		200,
		types.HexToAddress("0x2222222222222222222222222222222222222222"),
		75000,
	)
	dep.Confirmed = true
	tree.AddDeposit(dep)

	got := tree.GetDeposit(dep.BSVTxID)
	if got == nil {
		t.Fatal("GetDeposit returned nil")
	}
	if got.BSVTxID != dep.BSVTxID {
		t.Errorf("BSVTxID = %s, want %s", got.BSVTxID.Hex(), dep.BSVTxID.Hex())
	}
	if got.SatoshiAmount != dep.SatoshiAmount {
		t.Errorf("SatoshiAmount = %d, want %d", got.SatoshiAmount, dep.SatoshiAmount)
	}
	if got.L2Address != dep.L2Address {
		t.Errorf("L2Address = %s, want %s", got.L2Address.Hex(), dep.L2Address.Hex())
	}
	if got.BSVBlockHeight != dep.BSVBlockHeight {
		t.Errorf("BSVBlockHeight = %d, want %d", got.BSVBlockHeight, dep.BSVBlockHeight)
	}
}

// ---------------------------------------------------------------------------
// TestDepositTree_GetDeposit_NotFound
// ---------------------------------------------------------------------------

func TestDepositTree_GetDeposit_NotFound(t *testing.T) {
	tree, err := NewDepositTree(db.NewMemoryDB(), types.EmptyRootHash)
	if err != nil {
		t.Fatalf("NewDepositTree: %v", err)
	}

	got := tree.GetDeposit(types.HexToHash("0xdead"))
	if got != nil {
		t.Error("GetDeposit should return nil for nonexistent deposit")
	}
}

// ---------------------------------------------------------------------------
// TestDepositTree_DeterministicRoot
// ---------------------------------------------------------------------------

func TestDepositTree_DeterministicRoot(t *testing.T) {
	// Two trees with same deposits should produce the same root.
	deps := []*Deposit{
		NewDepositWithVout(types.HexToHash("0x01"), 0, 100,
			types.HexToAddress("0x1111111111111111111111111111111111111111"), 10000),
		NewDepositWithVout(types.HexToHash("0x02"), 0, 101,
			types.HexToAddress("0x2222222222222222222222222222222222222222"), 20000),
		NewDepositWithVout(types.HexToHash("0x03"), 0, 102,
			types.HexToAddress("0x3333333333333333333333333333333333333333"), 30000),
	}

	tree1, _ := NewDepositTree(db.NewMemoryDB(), types.EmptyRootHash)
	tree2, _ := NewDepositTree(db.NewMemoryDB(), types.EmptyRootHash)

	for _, dep := range deps {
		dep.Confirmed = true
		tree1.AddDeposit(dep)
		tree2.AddDeposit(dep)
	}

	if tree1.Hash() != tree2.Hash() {
		t.Errorf("same deposits should produce same root: %s != %s",
			tree1.Hash().Hex(), tree2.Hash().Hex())
	}
}

// ---------------------------------------------------------------------------
// TestDepositTree_Commit
// ---------------------------------------------------------------------------

func TestDepositTree_Commit(t *testing.T) {
	diskDB := db.NewMemoryDB()
	tree, err := NewDepositTree(diskDB, types.EmptyRootHash)
	if err != nil {
		t.Fatalf("NewDepositTree: %v", err)
	}

	dep := NewDepositWithVout(
		types.HexToHash("0xeeff"),
		0,
		300,
		types.HexToAddress("0x4444444444444444444444444444444444444444"),
		99999,
	)
	dep.Confirmed = true
	tree.AddDeposit(dep)

	root, err := tree.Commit()
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if root == (types.Hash{}) || root == types.EmptyRootHash {
		t.Error("committed root should be non-trivial")
	}

	// Reopen tree from the committed root.
	tree2, err := NewDepositTree(diskDB, root)
	if err != nil {
		t.Fatalf("NewDepositTree from committed root: %v", err)
	}

	if !tree2.HasDeposit(dep.BSVTxID) {
		t.Error("deposit should survive commit and reload")
	}

	got := tree2.GetDeposit(dep.BSVTxID)
	if got == nil {
		t.Fatal("GetDeposit after reload returned nil")
	}
	if got.SatoshiAmount != dep.SatoshiAmount {
		t.Errorf("amount after reload = %d, want %d", got.SatoshiAmount, dep.SatoshiAmount)
	}
}

// ---------------------------------------------------------------------------
// TestDepositTree_MultipleDeposits
// ---------------------------------------------------------------------------

func TestDepositTree_MultipleDeposits(t *testing.T) {
	tree, err := NewDepositTree(db.NewMemoryDB(), types.EmptyRootHash)
	if err != nil {
		t.Fatalf("NewDepositTree: %v", err)
	}

	const count = 50
	txids := make([]types.Hash, count)
	for i := 0; i < count; i++ {
		txid := types.Hash{}
		txid[0] = byte(i >> 8)
		txid[1] = byte(i & 0xff)
		txids[i] = txid

		dep := NewDepositWithVout(txid, 0, uint64(100+i),
			types.HexToAddress("0x5555555555555555555555555555555555555555"),
			uint64(10000+i*100))
		dep.Confirmed = true
		tree.AddDeposit(dep)
	}

	// Verify all deposits exist.
	for i, txid := range txids {
		if !tree.HasDeposit(txid) {
			t.Errorf("deposit %d should exist", i)
		}
	}

	// Verify a non-existent deposit does not exist.
	if tree.HasDeposit(types.HexToHash("0xdead")) {
		t.Error("non-existent deposit should not be found")
	}
}
