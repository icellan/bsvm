package bridge

import (
	"testing"

	"github.com/holiman/uint256"
	"github.com/icellan/bsvm/internal/db"
	"github.com/icellan/bsvm/pkg/state"
	"github.com/icellan/bsvm/pkg/types"
)

// newTestStateDB creates a fresh StateDB backed by an in-memory database
// for use in tests.
func newTestStateDB(t *testing.T) *state.StateDB {
	t.Helper()
	database := db.NewMemoryDB()
	statedb, err := state.New(types.EmptyRootHash, database)
	if err != nil {
		t.Fatalf("failed to create test state: %v", err)
	}
	return statedb
}

// setTotalDeposited is a test helper that writes a totalDeposited value
// into the bridge contract's storage.
func setTotalDeposited(statedb *state.StateDB, amount *uint256.Int) {
	addr := types.BridgeContractAddress
	if !statedb.Exist(addr) {
		statedb.CreateAccount(addr)
	}
	var hash types.Hash
	amount.WriteToSlice(hash[:])
	statedb.SetState(addr, TotalDepositedSlot, hash)
}

// --- Feature 1: Bridge Contract Predeploy ---

func TestDeployBridgePredeploy(t *testing.T) {
	statedb := newTestStateDB(t)
	DeployBridgePredeploy(statedb)

	addr := types.BridgeContractAddress

	// Account must exist.
	if !statedb.Exist(addr) {
		t.Fatal("bridge contract account does not exist after deploy")
	}

	// Account must have code.
	code := statedb.GetCode(addr)
	if len(code) == 0 {
		t.Fatal("bridge contract has no code after deploy")
	}

	// Code should match bridgeContractCode().
	expected := bridgeContractCode()
	if len(code) != len(expected) {
		t.Fatalf("code length mismatch: got %d, want %d", len(code), len(expected))
	}
	for i := range expected {
		if code[i] != expected[i] {
			t.Fatalf("code byte %d mismatch: got 0x%02x, want 0x%02x", i, code[i], expected[i])
		}
	}

	// Storage slots should be initialized to zero.
	totalDeposited := statedb.GetState(addr, TotalDepositedSlot)
	if totalDeposited != (types.Hash{}) {
		t.Errorf("totalDeposited not zero: %s", totalDeposited.Hex())
	}

	totalWithdrawn := statedb.GetState(addr, TotalWithdrawnSlot)
	if totalWithdrawn != (types.Hash{}) {
		t.Errorf("totalWithdrawn not zero: %s", totalWithdrawn.Hex())
	}

	nonce := statedb.GetState(addr, WithdrawalNonceSlot)
	if nonce != (types.Hash{}) {
		t.Errorf("withdrawalNonce not zero: %s", nonce.Hex())
	}
}

// --- Feature 2: Withdrawal Rate Limiting ---

func TestCheckWithdrawalRateLimit_NoDeposits(t *testing.T) {
	statedb := newTestStateDB(t)
	DeployBridgePredeploy(statedb)

	// With zero totalDeposited, any withdrawal should fail.
	amount := uint256.NewInt(1)
	err := CheckWithdrawalRateLimit(statedb, 0, amount)
	if err == nil {
		t.Fatal("expected rate limit error with zero deposits, got nil")
	}
}

func TestCheckWithdrawalRateLimit_WithinLimit(t *testing.T) {
	statedb := newTestStateDB(t)
	DeployBridgePredeploy(statedb)

	// Set totalDeposited to 100 ETH (in wei).
	deposited := new(uint256.Int).Mul(uint256.NewInt(100), uint256.NewInt(1e18))
	setTotalDeposited(statedb, deposited)

	// 10% of 100 ETH = 10 ETH. Withdraw 5 ETH (within limit).
	amount := new(uint256.Int).Mul(uint256.NewInt(5), uint256.NewInt(1e18))
	err := CheckWithdrawalRateLimit(statedb, 0, amount)
	if err != nil {
		t.Fatalf("expected withdrawal within limit to succeed: %v", err)
	}
}

func TestCheckWithdrawalRateLimit_AtLimit(t *testing.T) {
	statedb := newTestStateDB(t)
	DeployBridgePredeploy(statedb)

	// Set totalDeposited to 100 ETH.
	deposited := new(uint256.Int).Mul(uint256.NewInt(100), uint256.NewInt(1e18))
	setTotalDeposited(statedb, deposited)

	// Exactly 10% = 10 ETH should succeed.
	amount := new(uint256.Int).Mul(uint256.NewInt(10), uint256.NewInt(1e18))
	err := CheckWithdrawalRateLimit(statedb, 0, amount)
	if err != nil {
		t.Fatalf("expected withdrawal at exactly 10%% to succeed: %v", err)
	}
}

func TestCheckWithdrawalRateLimit_ExceedsLimit(t *testing.T) {
	statedb := newTestStateDB(t)
	DeployBridgePredeploy(statedb)

	// Set totalDeposited to 100 ETH.
	deposited := new(uint256.Int).Mul(uint256.NewInt(100), uint256.NewInt(1e18))
	setTotalDeposited(statedb, deposited)

	// 11% of 100 ETH = 11 ETH should fail.
	amount := new(uint256.Int).Mul(uint256.NewInt(11), uint256.NewInt(1e18))
	err := CheckWithdrawalRateLimit(statedb, 0, amount)
	if err == nil {
		t.Fatal("expected rate limit error for 11% withdrawal, got nil")
	}
}

func TestCheckWithdrawalRateLimit_MultiplePeriods(t *testing.T) {
	statedb := newTestStateDB(t)
	DeployBridgePredeploy(statedb)

	// Set totalDeposited to 1000 wei for simplicity.
	deposited := uint256.NewInt(1000)
	setTotalDeposited(statedb, deposited)

	// Period 0: withdraw 100 (10% of 1000 = 100, exactly at limit).
	amount := uint256.NewInt(100)
	blockInPeriod0 := uint64(0)
	err := CheckWithdrawalRateLimit(statedb, blockInPeriod0, amount)
	if err != nil {
		t.Fatalf("period 0 withdrawal should succeed: %v", err)
	}
	RecordWithdrawal(statedb, blockInPeriod0, amount, []byte{0x01}, 0)

	// Period 0: another withdrawal of 1 should fail (already at limit).
	err = CheckWithdrawalRateLimit(statedb, blockInPeriod0, uint256.NewInt(1))
	if err == nil {
		t.Fatal("period 0 second withdrawal should fail (limit reached)")
	}

	// Period 1: same amount should succeed (separate limit).
	blockInPeriod1 := uint64(BlocksPerPeriod)
	err = CheckWithdrawalRateLimit(statedb, blockInPeriod1, amount)
	if err != nil {
		t.Fatalf("period 1 withdrawal should succeed: %v", err)
	}
}

func TestCheckWithdrawalRateLimit_CumulativeInPeriod(t *testing.T) {
	statedb := newTestStateDB(t)
	DeployBridgePredeploy(statedb)

	// Set totalDeposited to 1000 wei.
	deposited := uint256.NewInt(1000)
	setTotalDeposited(statedb, deposited)
	// Max per period = 100 (10% of 1000).

	// First withdrawal: 60 wei.
	err := CheckWithdrawalRateLimit(statedb, 0, uint256.NewInt(60))
	if err != nil {
		t.Fatalf("first withdrawal (60) should succeed: %v", err)
	}
	RecordWithdrawal(statedb, 0, uint256.NewInt(60), []byte{0x01}, 0)

	// Second withdrawal: 40 wei (cumulative = 100, at limit).
	err = CheckWithdrawalRateLimit(statedb, 0, uint256.NewInt(40))
	if err != nil {
		t.Fatalf("second withdrawal (40, cumulative 100) should succeed: %v", err)
	}
	RecordWithdrawal(statedb, 0, uint256.NewInt(40), []byte{0x02}, 1)

	// Third withdrawal: 1 wei (cumulative = 101, exceeds limit).
	err = CheckWithdrawalRateLimit(statedb, 0, uint256.NewInt(1))
	if err == nil {
		t.Fatal("third withdrawal (1, cumulative 101) should fail")
	}
}

func TestRecordWithdrawal(t *testing.T) {
	statedb := newTestStateDB(t)
	DeployBridgePredeploy(statedb)

	// Set some initial totalDeposited so rate limits allow withdrawal.
	setTotalDeposited(statedb, uint256.NewInt(10000))

	addr := types.BridgeContractAddress
	amount := uint256.NewInt(500)
	bsvAddr := []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22, 0x33, 0x44,
		0x55, 0x66, 0x77, 0x88, 0x99, 0x00, 0xab, 0xcd, 0xef, 0x01}
	nonce := uint64(0)
	blockNumber := uint64(100)

	RecordWithdrawal(statedb, blockNumber, amount, bsvAddr, nonce)

	// Verify totalWithdrawn was updated.
	totalWithdrawnHash := statedb.GetState(addr, TotalWithdrawnSlot)
	totalWithdrawn := new(uint256.Int).SetBytes(totalWithdrawnHash[:])
	if totalWithdrawn.Cmp(amount) != 0 {
		t.Errorf("totalWithdrawn = %s, want %s", totalWithdrawn, amount)
	}

	// Verify periodWithdrawals was updated.
	period := blockNumber / BlocksPerPeriod
	periodSlot := computePeriodSlot(period)
	periodHash := statedb.GetState(addr, periodSlot)
	periodWithdrawals := new(uint256.Int).SetBytes(periodHash[:])
	if periodWithdrawals.Cmp(amount) != 0 {
		t.Errorf("periodWithdrawals = %s, want %s", periodWithdrawals, amount)
	}

	// Verify withdrawalNonce was incremented.
	nonceHash := statedb.GetState(addr, WithdrawalNonceSlot)
	nonceVal := new(uint256.Int).SetBytes(nonceHash[:])
	if !nonceVal.Eq(uint256.NewInt(1)) {
		t.Errorf("withdrawalNonce = %s, want 1", nonceVal)
	}

	// Verify the withdrawal hash was stored.
	satoshiAmount := types.WeiToSatoshis(amount)
	expectedHash := WithdrawalHash(bsvAddr, satoshiAmount, nonce)
	withdrawalSlot := computeWithdrawalSlot(nonce)
	storedHash := statedb.GetState(addr, withdrawalSlot)
	if storedHash != expectedHash {
		t.Errorf("stored withdrawal hash = %s, want %s", storedHash.Hex(), expectedHash.Hex())
	}

	// Record a second withdrawal and verify accumulation.
	amount2 := uint256.NewInt(300)
	RecordWithdrawal(statedb, blockNumber, amount2, bsvAddr, 1)

	totalWithdrawnHash = statedb.GetState(addr, TotalWithdrawnSlot)
	totalWithdrawn = new(uint256.Int).SetBytes(totalWithdrawnHash[:])
	expectedTotal := new(uint256.Int).Add(amount, amount2)
	if totalWithdrawn.Cmp(expectedTotal) != 0 {
		t.Errorf("totalWithdrawn after 2nd = %s, want %s", totalWithdrawn, expectedTotal)
	}

	nonceHash = statedb.GetState(addr, WithdrawalNonceSlot)
	nonceVal = new(uint256.Int).SetBytes(nonceHash[:])
	if !nonceVal.Eq(uint256.NewInt(2)) {
		t.Errorf("withdrawalNonce after 2nd = %s, want 2", nonceVal)
	}
}

func TestComputePeriodSlot(t *testing.T) {
	// Verify that different periods produce different slots.
	slot0 := computePeriodSlot(0)
	slot1 := computePeriodSlot(1)
	slot100 := computePeriodSlot(100)

	if slot0 == slot1 {
		t.Error("period 0 and period 1 should have different slots")
	}
	if slot0 == slot100 {
		t.Error("period 0 and period 100 should have different slots")
	}
	if slot1 == slot100 {
		t.Error("period 1 and period 100 should have different slots")
	}

	// Verify determinism: same period always gives same slot.
	slot0Again := computePeriodSlot(0)
	if slot0 != slot0Again {
		t.Error("computePeriodSlot is not deterministic")
	}

	// Verify the slot is non-zero (keccak256 output).
	if slot0 == (types.Hash{}) {
		t.Error("period slot 0 should not be zero hash")
	}
}

// --- Feature 3: Deposit Ordering ---

func TestSortDeposits_ByBlockHeight(t *testing.T) {
	d1 := NewDeposit(types.HexToHash("0xaa"), 300, types.Address{}, 1000)
	d2 := NewDeposit(types.HexToHash("0xbb"), 100, types.Address{}, 2000)
	d3 := NewDeposit(types.HexToHash("0xcc"), 200, types.Address{}, 3000)
	deposits := []*Deposit{d1, d2, d3}

	SortDeposits(deposits)

	if deposits[0].BSVBlockHeight != 100 {
		t.Errorf("first deposit height = %d, want 100", deposits[0].BSVBlockHeight)
	}
	if deposits[1].BSVBlockHeight != 200 {
		t.Errorf("second deposit height = %d, want 200", deposits[1].BSVBlockHeight)
	}
	if deposits[2].BSVBlockHeight != 300 {
		t.Errorf("third deposit height = %d, want 300", deposits[2].BSVBlockHeight)
	}
}

func TestSortDeposits_SameHeightByTxIndex(t *testing.T) {
	// Three deposits at the same height, different tx indices.
	d1 := NewDeposit(types.HexToHash("0xcc"), 100, types.Address{}, 1000)
	d1.TxIndex = 5
	d2 := NewDeposit(types.HexToHash("0xaa"), 100, types.Address{}, 2000)
	d2.TxIndex = 1
	d3 := NewDeposit(types.HexToHash("0xbb"), 100, types.Address{}, 3000)
	d3.TxIndex = 3
	deposits := []*Deposit{d1, d2, d3}

	SortDeposits(deposits)

	// Should be sorted by tx index ASC.
	if deposits[0].TxIndex != 1 {
		t.Errorf("first deposit TxIndex = %d, want 1", deposits[0].TxIndex)
	}
	if deposits[1].TxIndex != 3 {
		t.Errorf("second deposit TxIndex = %d, want 3", deposits[1].TxIndex)
	}
	if deposits[2].TxIndex != 5 {
		t.Errorf("third deposit TxIndex = %d, want 5", deposits[2].TxIndex)
	}
}

func TestSortDeposits_SameHeightAndTxIndex(t *testing.T) {
	txID := types.HexToHash("0xaa")

	d1 := NewDepositWithVout(txID, 2, 100, types.Address{}, 1000)
	d1.TxIndex = 0
	d2 := NewDepositWithVout(txID, 0, 100, types.Address{}, 2000)
	d2.TxIndex = 0
	d3 := NewDepositWithVout(txID, 1, 100, types.Address{}, 3000)
	d3.TxIndex = 0
	deposits := []*Deposit{d1, d2, d3}

	SortDeposits(deposits)

	if deposits[0].Vout != 0 {
		t.Errorf("first deposit vout = %d, want 0", deposits[0].Vout)
	}
	if deposits[1].Vout != 1 {
		t.Errorf("second deposit vout = %d, want 1", deposits[1].Vout)
	}
	if deposits[2].Vout != 2 {
		t.Errorf("third deposit vout = %d, want 2", deposits[2].Vout)
	}
}

func TestSortDeposits_Empty(t *testing.T) {
	var deposits []*Deposit
	// Should not panic.
	SortDeposits(deposits)
	if len(deposits) != 0 {
		t.Errorf("empty slice should remain empty, got len %d", len(deposits))
	}
}

func TestSortDeposits_Single(t *testing.T) {
	deposits := []*Deposit{
		NewDeposit(types.HexToHash("0xaa"), 100, types.Address{1}, 5000),
	}

	SortDeposits(deposits)

	if deposits[0].BSVBlockHeight != 100 {
		t.Errorf("single deposit height changed: got %d", deposits[0].BSVBlockHeight)
	}
	if deposits[0].SatoshiAmount != 5000 {
		t.Errorf("single deposit amount changed: got %d", deposits[0].SatoshiAmount)
	}
}

// --- Feature 4: L2 Withdraw Predeploy Selector ---

// TestL2WithdrawPredeployBytecode keeps the bytecode predicates the dispatch
// fast-path relies on. The actual selector matching lives in
// pkg/block.IsWithdrawDispatch (tested there); this test only guarantees
// the predeploy still ships with the success-stub code so the EVM does not
// revert before the fast-path can intercept the call.
func TestL2WithdrawPredeployBytecode(t *testing.T) {
	statedb := newTestStateDB(t)
	DeployBridgePredeploy(statedb)

	code := statedb.GetCode(types.BridgeContractAddress)
	if len(code) == 0 {
		t.Fatal("predeploy must ship with non-empty bytecode so EVM call succeeds before the fast-path dispatch")
	}
	// The stub bytecode is a deliberate constant — `0x60 01 60 00 52 60 20
	// 60 00 f3` (returns 32 bytes of 0x01). Pin the prefix so accidental
	// edits force a deliberate update of the dispatch fast-path tests.
	wantPrefix := []byte{0x60, 0x01, 0x60, 0x00, 0x52}
	for i, b := range wantPrefix {
		if code[i] != b {
			t.Fatalf("predeploy bytecode prefix mismatch at byte %d: got 0x%02x, want 0x%02x", i, code[i], b)
		}
	}
}
