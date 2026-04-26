package block

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/holiman/uint256"
	"github.com/icellan/bsvm/internal/db"
	"github.com/icellan/bsvm/pkg/bridge"
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

// ---------------------------------------------------------------------------
// Withdrawal entry-point tests
// ---------------------------------------------------------------------------

// TestWithdrawSelector pins the 4-byte ABI selector for
// `withdraw(uint256,bytes20)`. This is the selector both Go and SP1 must
// honour so any drift here is caught at test time.
func TestWithdrawSelector(t *testing.T) {
	want := [4]byte{0xe7, 0x26, 0x89, 0xba}
	if WithdrawSelector != want {
		t.Errorf("WithdrawSelector = %x, want %x", WithdrawSelector, want)
	}
}

// TestEncodeDecodeWithdrawCalldata round-trips ABI calldata for a typical
// withdrawal request and checks that all three padding rules are enforced.
func TestEncodeDecodeWithdrawCalldata(t *testing.T) {
	addr := []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22, 0x33, 0x44,
		0x55, 0x66, 0x77, 0x88, 0x99, 0x00, 0xab, 0xcd, 0xef, 0x01}

	calldata, err := EncodeWithdrawCalldata(50_000_000, addr)
	if err != nil {
		t.Fatalf("EncodeWithdrawCalldata: %v", err)
	}
	if len(calldata) != 68 {
		t.Errorf("calldata length = %d, want 68", len(calldata))
	}
	if !bytes.Equal(calldata[:4], WithdrawSelector[:]) {
		t.Errorf("calldata selector = %x, want %x", calldata[:4], WithdrawSelector)
	}

	sats, gotAddr, err := DecodeWithdrawCalldata(calldata)
	if err != nil {
		t.Fatalf("DecodeWithdrawCalldata: %v", err)
	}
	if sats != 50_000_000 {
		t.Errorf("decoded satoshis = %d, want 50000000", sats)
	}
	if !bytes.Equal(gotAddr, addr) {
		t.Errorf("decoded address = %x, want %x", gotAddr, addr)
	}
}

func TestDecodeWithdrawCalldata_Errors(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{"too short", []byte{0xe7, 0x26, 0x89, 0xba}},
		{"wrong selector", append([]byte{0xff, 0x00, 0x00, 0x00}, make([]byte, 64)...)},
		{
			"amount > uint64 max",
			func() []byte {
				d := make([]byte, 68)
				copy(d[:4], WithdrawSelector[:])
				d[4] = 0x01 // first byte non-zero ⇒ does not fit in uint64
				return d
			}(),
		},
		{
			"non-zero bytes20 padding",
			func() []byte {
				d := make([]byte, 68)
				copy(d[:4], WithdrawSelector[:])
				d[28] = 0 // amount zero
				d[36+20] = 0xff // padding byte non-zero
				return d
			}(),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := DecodeWithdrawCalldata(tt.data)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
		})
	}
}

func TestIsWithdrawDispatch(t *testing.T) {
	other := types.HexToAddress("0x1111111111111111111111111111111111111111")
	bridgeAddr := types.BridgeContractAddress

	calldata, err := EncodeWithdrawCalldata(1000, make([]byte, 20))
	if err != nil {
		t.Fatalf("EncodeWithdrawCalldata: %v", err)
	}

	if !IsWithdrawDispatch(&bridgeAddr, calldata) {
		t.Error("expected bridge + withdraw selector to dispatch")
	}
	if IsWithdrawDispatch(&other, calldata) {
		t.Error("expected non-bridge target to NOT dispatch")
	}
	if IsWithdrawDispatch(nil, calldata) {
		t.Error("expected nil target (creation) to NOT dispatch")
	}
	if IsWithdrawDispatch(&bridgeAddr, calldata[:3]) {
		t.Error("expected calldata < 4 bytes to NOT dispatch")
	}
	wrongSel := make([]byte, 68)
	wrongSel[0] = 0xff
	if IsWithdrawDispatch(&bridgeAddr, wrongSel) {
		t.Error("expected wrong selector to NOT dispatch")
	}
}

// withdrawTestSetup creates a StateDB with the bridge predeploy installed,
// a non-zero totalDeposited so rate-limit math works, and the caller's
// balance pre-funded.
func withdrawTestSetup(t *testing.T, callerBal *uint256.Int, totalDeposited *uint256.Int) (*state.StateDB, types.Address) {
	t.Helper()
	database := db.NewMemoryDB()
	statedb, err := state.New(types.EmptyRootHash, database)
	if err != nil {
		t.Fatalf("state.New: %v", err)
	}
	bridge.DeployBridgePredeploy(statedb)

	// Seed totalDeposited so the rate-limit denominator is non-zero.
	var depHash types.Hash
	totalDeposited.WriteToSlice(depHash[:])
	statedb.SetState(types.BridgeContractAddress, bridge.TotalDepositedSlot, depHash)

	caller := types.HexToAddress("0xcafe000000000000000000000000000000000001")
	statedb.CreateAccount(caller)
	statedb.AddBalance(caller, callerBal, 0)
	return statedb, caller
}

func TestApplyWithdrawTx_Success(t *testing.T) {
	// totalDeposited = 100 BSV in wei so 10% / period = 10 BSV.
	totalDeposited := types.SatoshisToWei(10_000_000_000)
	callerBal := types.SatoshisToWei(2_000_000_000) // 20 BSV
	statedb, caller := withdrawTestSetup(t, callerBal, totalDeposited)

	addr := []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa,
		0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x01, 0x02, 0x03, 0x04}

	// Withdraw 1 BSV (well within rate limit).
	calldata, err := EncodeWithdrawCalldata(100_000_000, addr)
	if err != nil {
		t.Fatalf("EncodeWithdrawCalldata: %v", err)
	}

	header := &L2Header{Number: big.NewInt(42), BaseFee: big.NewInt(0)}
	statedb.SetTxContext(types.HexToHash("0xfeedbeef"), 0)
	log, err := ApplyWithdrawTx(statedb, header, caller, calldata)
	if err != nil {
		t.Fatalf("ApplyWithdrawTx: %v", err)
	}
	if log == nil {
		t.Fatal("expected non-nil log")
	}

	// Caller balance should be reduced by 1 BSV.
	wantCaller := new(uint256.Int).Sub(callerBal, types.SatoshisToWei(100_000_000))
	if statedb.GetBalance(caller).Cmp(wantCaller) != 0 {
		t.Errorf("caller balance = %s, want %s", statedb.GetBalance(caller), wantCaller)
	}

	// Burn address should hold the withdrawn amount.
	burn := types.HexToAddress("0x000000000000000000000000000000000000dEaD")
	if statedb.GetBalance(burn).Cmp(types.SatoshisToWei(100_000_000)) != 0 {
		t.Errorf("burn balance = %s, want %s", statedb.GetBalance(burn), types.SatoshisToWei(100_000_000))
	}

	// totalWithdrawn should reflect 1 BSV.
	totalWithdrawnHash := statedb.GetState(types.BridgeContractAddress, bridge.TotalWithdrawnSlot)
	totalWithdrawn := new(uint256.Int).SetBytes(totalWithdrawnHash[:])
	if totalWithdrawn.Cmp(types.SatoshisToWei(100_000_000)) != 0 {
		t.Errorf("totalWithdrawn = %s, want %s", totalWithdrawn, types.SatoshisToWei(100_000_000))
	}

	// Withdrawal nonce should now be 1.
	nonceHash := statedb.GetState(types.BridgeContractAddress, bridge.WithdrawalNonceSlot)
	nonceVal := new(uint256.Int).SetBytes(nonceHash[:])
	if !nonceVal.Eq(uint256.NewInt(1)) {
		t.Errorf("withdrawalNonce = %s, want 1", nonceVal)
	}

	// Log should target the bridge contract and carry the expected hash.
	if log.Address != types.BridgeContractAddress {
		t.Errorf("log.Address = %s, want bridge", log.Address.Hex())
	}
	if len(log.Topics) < 2 {
		t.Fatalf("log.Topics length = %d, want >= 2", len(log.Topics))
	}
	if len(log.Data) != 96 {
		t.Errorf("log.Data length = %d, want 96", len(log.Data))
	}
	gotHash := types.BytesToHash(log.Data[64:96])
	wantHash := bridge.WithdrawalHash(addr, 100_000_000, 0)
	if gotHash != wantHash {
		t.Errorf("log withdrawal hash = %s, want %s", gotHash.Hex(), wantHash.Hex())
	}
}

func TestApplyWithdrawTx_InsufficientBalance(t *testing.T) {
	totalDeposited := types.SatoshisToWei(10_000_000_000)
	// Caller has only 0.1 BSV but wants to withdraw 1 BSV.
	callerBal := types.SatoshisToWei(10_000_000)
	statedb, caller := withdrawTestSetup(t, callerBal, totalDeposited)

	calldata, _ := EncodeWithdrawCalldata(100_000_000, make([]byte, 20))
	header := &L2Header{Number: big.NewInt(1)}

	_, err := ApplyWithdrawTx(statedb, header, caller, calldata)
	if err == nil {
		t.Fatal("expected error for insufficient balance, got nil")
	}

	// Caller balance untouched.
	if statedb.GetBalance(caller).Cmp(callerBal) != 0 {
		t.Errorf("caller balance changed despite revert: got %s, want %s", statedb.GetBalance(caller), callerBal)
	}
}

func TestApplyWithdrawTx_RateLimitExceeded(t *testing.T) {
	// totalDeposited = 100 wei ⇒ max per period = 10 wei. Try to withdraw
	// 1 BSV worth of wei which is far more than the 10-wei cap.
	totalDeposited := uint256.NewInt(100)
	callerBal := types.SatoshisToWei(100_000_000) // user has plenty
	statedb, caller := withdrawTestSetup(t, callerBal, totalDeposited)

	calldata, _ := EncodeWithdrawCalldata(100_000_000, make([]byte, 20))
	header := &L2Header{Number: big.NewInt(1)}

	_, err := ApplyWithdrawTx(statedb, header, caller, calldata)
	if err == nil {
		t.Fatal("expected rate-limit error, got nil")
	}
}

func TestApplyWithdrawTx_MalformedCalldata(t *testing.T) {
	statedb, caller := withdrawTestSetup(t, types.SatoshisToWei(1e8),
		types.SatoshisToWei(1e10))

	header := &L2Header{Number: big.NewInt(1)}
	_, err := ApplyWithdrawTx(statedb, header, caller, []byte{0x01, 0x02})
	if err == nil {
		t.Fatal("expected error for short calldata")
	}
}

func TestApplyWithdrawTx_ZeroAmount(t *testing.T) {
	statedb, caller := withdrawTestSetup(t, types.SatoshisToWei(1e8),
		types.SatoshisToWei(1e10))

	calldata, _ := EncodeWithdrawCalldata(0, make([]byte, 20))
	header := &L2Header{Number: big.NewInt(1)}
	_, err := ApplyWithdrawTx(statedb, header, caller, calldata)
	if err == nil {
		t.Fatal("expected error for zero amount")
	}
}
