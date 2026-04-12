package covenant

import (
	"crypto/sha256"
	"testing"

	"github.com/icellan/bsvm/pkg/types"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// testTxID returns a deterministic transaction ID for a given seed.
func testTxID(seed byte) types.Hash {
	h := sha256.Sum256([]byte{seed, 0xAA, 0xBB})
	return types.BytesToHash(h[:])
}

// testBsvAddress returns a deterministic 20-byte BSV address for testing.
func testBsvAddress(seed byte) []byte {
	h := sha256.Sum256([]byte{seed, 0xCC, 0xDD})
	return h[:20]
}

// testMerkleProofData returns a deterministic Merkle proof (20 sibling hashes).
func testMerkleProofData() [][]byte {
	proof := make([][]byte, 20)
	for i := 0; i < 20; i++ {
		h := sha256.Sum256([]byte{byte(i), 0xEE})
		proof[i] = h[:]
	}
	return proof
}

// ---------------------------------------------------------------------------
// TestBridgeManager_BuildDepositData
// ---------------------------------------------------------------------------

func TestBridgeManager_BuildDepositData(t *testing.T) {
	genesisTxID := testTxID(1)
	stateCovenantTxID := testTxID(2)
	initialState := BridgeState{Balance: 100_000, WithdrawalNonce: 5}

	bm := NewBridgeManager(genesisTxID, 0, 100_000, initialState, stateCovenantTxID)

	data, err := bm.BuildDepositData(50_000)
	if err != nil {
		t.Fatalf("BuildDepositData failed: %v", err)
	}

	if data.PrevTxID != genesisTxID {
		t.Errorf("PrevTxID mismatch: got %x, want %x", data.PrevTxID, genesisTxID)
	}
	if data.PrevVout != 0 {
		t.Errorf("PrevVout mismatch: got %d, want 0", data.PrevVout)
	}
	if data.DepositSats != 50_000 {
		t.Errorf("DepositSats mismatch: got %d, want 50000", data.DepositSats)
	}
	if data.NewState.Balance != 150_000 {
		t.Errorf("new balance mismatch: got %d, want 150000", data.NewState.Balance)
	}
	if data.NewState.WithdrawalNonce != 5 {
		t.Errorf("nonce should not change: got %d, want 5", data.NewState.WithdrawalNonce)
	}
	if data.CovenantSats != 150_000 {
		t.Errorf("CovenantSats mismatch: got %d, want 150000", data.CovenantSats)
	}
}

// ---------------------------------------------------------------------------
// TestBridgeManager_BuildDepositData_ZeroAmount
// ---------------------------------------------------------------------------

func TestBridgeManager_BuildDepositData_ZeroAmount(t *testing.T) {
	bm := NewBridgeManager(testTxID(1), 0, 10_000, EmptyBridgeState(), testTxID(2))

	_, err := bm.BuildDepositData(0)
	if err == nil {
		t.Fatal("expected error for zero deposit, got nil")
	}
}

// ---------------------------------------------------------------------------
// TestBridgeManager_BuildWithdrawalData
// ---------------------------------------------------------------------------

func TestBridgeManager_BuildWithdrawalData(t *testing.T) {
	genesisTxID := testTxID(1)
	stateCovenantTxID := testTxID(2)
	initialState := BridgeState{Balance: 500_000, WithdrawalNonce: 10}

	bm := NewBridgeManager(genesisTxID, 0, 500_000, initialState, stateCovenantTxID)

	addr := testBsvAddress(1)
	root := types.BytesToHash(make([]byte, 32))
	proof := testMerkleProofData()

	data, err := bm.BuildWithdrawalData(addr, 100_000, root, proof, 7)
	if err != nil {
		t.Fatalf("BuildWithdrawalData failed: %v", err)
	}

	if data.PrevTxID != genesisTxID {
		t.Errorf("PrevTxID mismatch")
	}
	if data.PrevVout != 0 {
		t.Errorf("PrevVout mismatch: got %d, want 0", data.PrevVout)
	}
	if data.SatoshiAmount != 100_000 {
		t.Errorf("SatoshiAmount mismatch: got %d, want 100000", data.SatoshiAmount)
	}
	if data.Nonce != 10 {
		t.Errorf("Nonce mismatch: got %d, want 10", data.Nonce)
	}
	if data.WithdrawalRoot != root {
		t.Errorf("WithdrawalRoot mismatch")
	}
	if len(data.MerkleProof) != 20 {
		t.Errorf("MerkleProof length mismatch: got %d, want 20", len(data.MerkleProof))
	}
	if data.MerkleIndex != 7 {
		t.Errorf("MerkleIndex mismatch: got %d, want 7", data.MerkleIndex)
	}
	if data.NewState.Balance != 400_000 {
		t.Errorf("new balance mismatch: got %d, want 400000", data.NewState.Balance)
	}
	if data.NewState.WithdrawalNonce != 11 {
		t.Errorf("new nonce mismatch: got %d, want 11", data.NewState.WithdrawalNonce)
	}
	if data.CovenantSats != 400_000 {
		t.Errorf("CovenantSats mismatch: got %d, want 400000", data.CovenantSats)
	}
}

// ---------------------------------------------------------------------------
// TestBridgeManager_BuildWithdrawalData_InsufficientBalance
// ---------------------------------------------------------------------------

func TestBridgeManager_BuildWithdrawalData_InsufficientBalance(t *testing.T) {
	initialState := BridgeState{Balance: 1_000, WithdrawalNonce: 0}
	bm := NewBridgeManager(testTxID(1), 0, 1_000, initialState, testTxID(2))

	_, err := bm.BuildWithdrawalData(
		testBsvAddress(1),
		2_000, // more than balance
		types.Hash{},
		testMerkleProofData(),
		0,
	)
	if err == nil {
		t.Fatal("expected error for insufficient balance, got nil")
	}
}

// ---------------------------------------------------------------------------
// TestBridgeManager_BuildWithdrawalData_ZeroAmount
// ---------------------------------------------------------------------------

func TestBridgeManager_BuildWithdrawalData_ZeroAmount(t *testing.T) {
	initialState := BridgeState{Balance: 1_000, WithdrawalNonce: 0}
	bm := NewBridgeManager(testTxID(1), 0, 1_000, initialState, testTxID(2))

	_, err := bm.BuildWithdrawalData(
		testBsvAddress(1),
		0,
		types.Hash{},
		testMerkleProofData(),
		0,
	)
	if err == nil {
		t.Fatal("expected error for zero withdrawal amount, got nil")
	}
}

// ---------------------------------------------------------------------------
// TestBridgeManager_BuildWithdrawalData_InvalidAddress
// ---------------------------------------------------------------------------

func TestBridgeManager_BuildWithdrawalData_InvalidAddress(t *testing.T) {
	initialState := BridgeState{Balance: 10_000, WithdrawalNonce: 0}
	bm := NewBridgeManager(testTxID(1), 0, 10_000, initialState, testTxID(2))

	// 15 bytes instead of 20
	_, err := bm.BuildWithdrawalData(
		make([]byte, 15),
		1_000,
		types.Hash{},
		testMerkleProofData(),
		0,
	)
	if err == nil {
		t.Fatal("expected error for invalid address length, got nil")
	}
}

// ---------------------------------------------------------------------------
// TestBridgeManager_ApplyDeposit
// ---------------------------------------------------------------------------

func TestBridgeManager_ApplyDeposit(t *testing.T) {
	initialState := BridgeState{Balance: 100_000, WithdrawalNonce: 3}
	bm := NewBridgeManager(testTxID(1), 0, 100_000, initialState, testTxID(2))

	depositTxID := testTxID(10)
	bm.ApplyDeposit(depositTxID, 50_000)

	if bm.CurrentTxID() != depositTxID {
		t.Errorf("txid not updated")
	}
	if bm.CurrentVout() != 0 {
		t.Errorf("vout should be 0, got %d", bm.CurrentVout())
	}
	state := bm.CurrentState()
	if state.Balance != 150_000 {
		t.Errorf("balance mismatch: got %d, want 150000", state.Balance)
	}
	if state.WithdrawalNonce != 3 {
		t.Errorf("nonce should not change: got %d, want 3", state.WithdrawalNonce)
	}
}

// ---------------------------------------------------------------------------
// TestBridgeManager_ApplyWithdrawal
// ---------------------------------------------------------------------------

func TestBridgeManager_ApplyWithdrawal(t *testing.T) {
	initialState := BridgeState{Balance: 100_000, WithdrawalNonce: 5}
	bm := NewBridgeManager(testTxID(1), 0, 100_000, initialState, testTxID(2))

	withdrawTxID := testTxID(20)
	bm.ApplyWithdrawal(withdrawTxID, 30_000)

	if bm.CurrentTxID() != withdrawTxID {
		t.Errorf("txid not updated")
	}
	state := bm.CurrentState()
	if state.Balance != 70_000 {
		t.Errorf("balance mismatch: got %d, want 70000", state.Balance)
	}
	if state.WithdrawalNonce != 6 {
		t.Errorf("nonce mismatch: got %d, want 6", state.WithdrawalNonce)
	}
}

// ---------------------------------------------------------------------------
// TestBridgeManager_MultipleOperations
// ---------------------------------------------------------------------------

func TestBridgeManager_MultipleOperations(t *testing.T) {
	bm := NewBridgeManager(testTxID(1), 0, 0, EmptyBridgeState(), testTxID(2))

	// Deposit 100,000
	bm.ApplyDeposit(testTxID(10), 100_000)
	state := bm.CurrentState()
	if state.Balance != 100_000 {
		t.Fatalf("after deposit 1: balance %d, want 100000", state.Balance)
	}
	if state.WithdrawalNonce != 0 {
		t.Fatalf("after deposit 1: nonce %d, want 0", state.WithdrawalNonce)
	}

	// Deposit another 50,000
	bm.ApplyDeposit(testTxID(11), 50_000)
	state = bm.CurrentState()
	if state.Balance != 150_000 {
		t.Fatalf("after deposit 2: balance %d, want 150000", state.Balance)
	}

	// Withdraw 30,000
	bm.ApplyWithdrawal(testTxID(20), 30_000)
	state = bm.CurrentState()
	if state.Balance != 120_000 {
		t.Fatalf("after withdrawal 1: balance %d, want 120000", state.Balance)
	}
	if state.WithdrawalNonce != 1 {
		t.Fatalf("after withdrawal 1: nonce %d, want 1", state.WithdrawalNonce)
	}

	// Withdraw 20,000
	bm.ApplyWithdrawal(testTxID(21), 20_000)
	state = bm.CurrentState()
	if state.Balance != 100_000 {
		t.Fatalf("after withdrawal 2: balance %d, want 100000", state.Balance)
	}
	if state.WithdrawalNonce != 2 {
		t.Fatalf("after withdrawal 2: nonce %d, want 2", state.WithdrawalNonce)
	}

	// Deposit 10,000
	bm.ApplyDeposit(testTxID(12), 10_000)
	state = bm.CurrentState()
	if state.Balance != 110_000 {
		t.Fatalf("after deposit 3: balance %d, want 110000", state.Balance)
	}
	if state.WithdrawalNonce != 2 {
		t.Fatalf("after deposit 3: nonce %d, want 2", state.WithdrawalNonce)
	}

	// Verify BuildDepositData still works with current state
	data, err := bm.BuildDepositData(5_000)
	if err != nil {
		t.Fatalf("BuildDepositData failed: %v", err)
	}
	if data.NewState.Balance != 115_000 {
		t.Errorf("build deposit: new balance %d, want 115000", data.NewState.Balance)
	}

	// Verify BuildWithdrawalData still works with current state
	wdata, err := bm.BuildWithdrawalData(
		testBsvAddress(1),
		10_000,
		types.Hash{},
		testMerkleProofData(),
		0,
	)
	if err != nil {
		t.Fatalf("BuildWithdrawalData failed: %v", err)
	}
	if wdata.NewState.Balance != 100_000 {
		t.Errorf("build withdrawal: new balance %d, want 100000", wdata.NewState.Balance)
	}
	if wdata.Nonce != 2 {
		t.Errorf("build withdrawal: nonce %d, want 2", wdata.Nonce)
	}
	if wdata.NewState.WithdrawalNonce != 3 {
		t.Errorf("build withdrawal: new nonce %d, want 3", wdata.NewState.WithdrawalNonce)
	}
}
