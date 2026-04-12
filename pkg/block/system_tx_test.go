package block

import (
	"math/big"
	"testing"

	"github.com/holiman/uint256"
	"github.com/icellan/bsvm/internal/db"
	"github.com/icellan/bsvm/pkg/state"
	"github.com/icellan/bsvm/pkg/types"
)

// TestApplyDepositTx verifies that a deposit system transaction credits the
// recipient's balance and updates the bridge contract's totalDeposited slot.
func TestApplyDepositTx(t *testing.T) {
	database := db.NewMemoryDB()
	statedb, err := state.New(types.EmptyRootHash, database)
	if err != nil {
		t.Fatalf("failed to create state: %v", err)
	}

	header := &L2Header{
		Number:  big.NewInt(1),
		BaseFee: big.NewInt(0),
	}

	recipient := types.HexToAddress("0x1234567890123456789012345678901234567890")
	depositAmount := types.SatoshisToWei(50000) // 50000 satoshis

	depositTx := &types.DepositTransaction{
		SourceHash: types.HexToHash("0xdeadbeef"),
		From:       types.BridgeSystemAddress,
		To:         recipient,
		Value:      depositAmount,
		Gas:        0,
		IsSystemTx: true,
		Data:       nil,
	}

	receipt := ApplyDepositTx(statedb, header, depositTx)

	// Receipt should indicate success.
	if receipt.Status != types.ReceiptStatusSuccessful {
		t.Errorf("receipt status = %d, want %d", receipt.Status, types.ReceiptStatusSuccessful)
	}

	// Receipt type should be DepositTxType.
	if receipt.Type != types.DepositTxType {
		t.Errorf("receipt type = %d, want %d", receipt.Type, types.DepositTxType)
	}

	// No gas consumed.
	if receipt.GasUsed != 0 {
		t.Errorf("receipt GasUsed = %d, want 0", receipt.GasUsed)
	}

	if receipt.CumulativeGasUsed != 0 {
		t.Errorf("receipt CumulativeGasUsed = %d, want 0", receipt.CumulativeGasUsed)
	}

	// No logs.
	if len(receipt.Logs) != 0 {
		t.Errorf("receipt has %d logs, want 0", len(receipt.Logs))
	}

	// Check recipient balance was credited.
	balance := statedb.GetBalance(recipient)
	if balance.Cmp(depositAmount) != 0 {
		t.Errorf("recipient balance = %s, want %s", balance, depositAmount)
	}

	// Check totalDeposited was updated in bridge contract storage.
	totalDepositedHash := statedb.GetState(types.BridgeContractAddress, TotalDepositedStorageSlot)
	totalDeposited := new(uint256.Int).SetBytes(totalDepositedHash[:])
	if totalDeposited.Cmp(depositAmount) != 0 {
		t.Errorf("totalDeposited = %s, want %s", totalDeposited, depositAmount)
	}
}

// TestApplyDepositTxExistingAccount verifies that depositing to an account
// with an existing balance adds to it (does not replace it).
func TestApplyDepositTxExistingAccount(t *testing.T) {
	database := db.NewMemoryDB()
	statedb, err := state.New(types.EmptyRootHash, database)
	if err != nil {
		t.Fatalf("failed to create state: %v", err)
	}

	header := &L2Header{
		Number:  big.NewInt(1),
		BaseFee: big.NewInt(0),
	}

	recipient := types.HexToAddress("0x1234567890123456789012345678901234567890")

	// Set up existing balance.
	existingBalance := uint256.NewInt(1_000_000)
	statedb.CreateAccount(recipient)
	statedb.AddBalance(recipient, existingBalance, 0)

	depositAmount := types.SatoshisToWei(25000)

	depositTx := &types.DepositTransaction{
		SourceHash: types.HexToHash("0xaaaa"),
		From:       types.BridgeSystemAddress,
		To:         recipient,
		Value:      depositAmount,
		Gas:        0,
		IsSystemTx: true,
		Data:       nil,
	}

	receipt := ApplyDepositTx(statedb, header, depositTx)

	if receipt.Status != types.ReceiptStatusSuccessful {
		t.Fatalf("receipt status = %d, want success", receipt.Status)
	}

	// Balance should be existing + deposit.
	expectedBalance := new(uint256.Int).Add(existingBalance, depositAmount)
	gotBalance := statedb.GetBalance(recipient)
	if gotBalance.Cmp(expectedBalance) != 0 {
		t.Errorf("balance = %s, want %s", gotBalance, expectedBalance)
	}
}

// TestApplyDepositTxNewAccount verifies that depositing to a non-existent
// account creates it and credits the balance.
func TestApplyDepositTxNewAccount(t *testing.T) {
	database := db.NewMemoryDB()
	statedb, err := state.New(types.EmptyRootHash, database)
	if err != nil {
		t.Fatalf("failed to create state: %v", err)
	}

	header := &L2Header{
		Number:  big.NewInt(1),
		BaseFee: big.NewInt(0),
	}

	recipient := types.HexToAddress("0xabcdefabcdefabcdefabcdefabcdefabcdefabcd")

	// Verify account does not exist.
	if statedb.Exist(recipient) {
		t.Fatal("recipient should not exist before deposit")
	}

	depositAmount := types.SatoshisToWei(100000)

	depositTx := &types.DepositTransaction{
		SourceHash: types.HexToHash("0xbbbb"),
		From:       types.BridgeSystemAddress,
		To:         recipient,
		Value:      depositAmount,
		Gas:        0,
		IsSystemTx: true,
		Data:       nil,
	}

	receipt := ApplyDepositTx(statedb, header, depositTx)

	if receipt.Status != types.ReceiptStatusSuccessful {
		t.Fatalf("receipt status = %d, want success", receipt.Status)
	}

	// Account should now exist.
	if !statedb.Exist(recipient) {
		t.Fatal("recipient should exist after deposit")
	}

	// Balance should be the deposit amount.
	gotBalance := statedb.GetBalance(recipient)
	if gotBalance.Cmp(depositAmount) != 0 {
		t.Errorf("balance = %s, want %s", gotBalance, depositAmount)
	}
}

// TestApplyMultipleDeposits verifies that multiple deposits accumulate
// in both the recipient balance and totalDeposited.
func TestApplyMultipleDeposits(t *testing.T) {
	database := db.NewMemoryDB()
	statedb, err := state.New(types.EmptyRootHash, database)
	if err != nil {
		t.Fatalf("failed to create state: %v", err)
	}

	header := &L2Header{
		Number:  big.NewInt(1),
		BaseFee: big.NewInt(0),
	}

	recipient := types.HexToAddress("0x1111111111111111111111111111111111111111")

	amounts := []uint64{10000, 20000, 30000}
	var totalSatoshis uint64

	for i, sats := range amounts {
		depositTx := &types.DepositTransaction{
			SourceHash: types.HexToHash(types.Hash{byte(i + 1)}.Hex()),
			From:       types.BridgeSystemAddress,
			To:         recipient,
			Value:      types.SatoshisToWei(sats),
			Gas:        0,
			IsSystemTx: true,
			Data:       nil,
		}

		receipt := ApplyDepositTx(statedb, header, depositTx)
		if receipt.Status != types.ReceiptStatusSuccessful {
			t.Fatalf("deposit %d failed", i)
		}
		totalSatoshis += sats
	}

	// Check total balance.
	expectedBalance := types.SatoshisToWei(totalSatoshis)
	gotBalance := statedb.GetBalance(recipient)
	if gotBalance.Cmp(expectedBalance) != 0 {
		t.Errorf("total balance = %s, want %s", gotBalance, expectedBalance)
	}

	// Check totalDeposited.
	totalDepositedHash := statedb.GetState(types.BridgeContractAddress, TotalDepositedStorageSlot)
	totalDeposited := new(uint256.Int).SetBytes(totalDepositedHash[:])
	if totalDeposited.Cmp(expectedBalance) != 0 {
		t.Errorf("totalDeposited = %s, want %s", totalDeposited, expectedBalance)
	}
}

// TestApplyDepositTxWithIndex verifies the convenience wrapper.
func TestApplyDepositTxWithIndex(t *testing.T) {
	database := db.NewMemoryDB()
	statedb, err := state.New(types.EmptyRootHash, database)
	if err != nil {
		t.Fatalf("failed to create state: %v", err)
	}

	header := &L2Header{
		Number:  big.NewInt(5),
		BaseFee: big.NewInt(0),
	}

	recipient := types.HexToAddress("0x2222222222222222222222222222222222222222")
	depositTx := &types.DepositTransaction{
		SourceHash: types.HexToHash("0xcccc"),
		From:       types.BridgeSystemAddress,
		To:         recipient,
		Value:      types.SatoshisToWei(75000),
		Gas:        0,
		IsSystemTx: true,
		Data:       nil,
	}

	receipt := ApplyDepositTxWithIndex(statedb, header, depositTx, 3)

	if receipt.TransactionIndex != 3 {
		t.Errorf("TransactionIndex = %d, want 3", receipt.TransactionIndex)
	}

	if receipt.BlockNumber.Cmp(big.NewInt(5)) != 0 {
		t.Errorf("BlockNumber = %s, want 5", receipt.BlockNumber)
	}

	if receipt.Status != types.ReceiptStatusSuccessful {
		t.Errorf("receipt status = %d, want success", receipt.Status)
	}
}
