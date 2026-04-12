package bridge

import (
	"fmt"

	"github.com/holiman/uint256"
	"github.com/icellan/bsvm/pkg/crypto"
	"github.com/icellan/bsvm/pkg/state"
	"github.com/icellan/bsvm/pkg/types"
	"github.com/icellan/bsvm/pkg/vm/tracing"
)

const (
	// BlocksPerPeriod is approximately 24 hours at ~10s/block.
	BlocksPerPeriod = 8640

	// MaxWithdrawalBPS is 10% expressed in basis points.
	MaxWithdrawalBPS = 1000

	// BurnAddress is the unrecoverable dead address for wBSV burns.
	BurnAddress = "0x000000000000000000000000000000000000dEaD"
)

// Storage slot constants for the bridge contract. These match the
// storage layout defined in pkg/block/system_tx.go.
var (
	// TotalDepositedSlot is slot 4: totalDeposited (uint256).
	TotalDepositedSlot = types.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000004")

	// TotalWithdrawnSlot is slot 5: totalWithdrawn (uint256).
	TotalWithdrawnSlot = types.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000005")

	// WithdrawalNonceSlot is slot 2: withdrawalNonce (uint256).
	WithdrawalNonceSlot = types.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000002")

	// PeriodWithdrawalsBaseSlot is slot 6: base for the periodWithdrawals
	// mapping. periodWithdrawals[period] is stored at
	// keccak256(abi.encode(period, 6)).
	PeriodWithdrawalsBaseSlot = types.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000006")
)

// DeployBridgePredeploy sets up the bridge contract in genesis state.
// It creates the account, sets the contract code, and initializes
// storage slots to zero.
func DeployBridgePredeploy(stateDB *state.StateDB) {
	addr := types.BridgeContractAddress

	// Create the account.
	stateDB.CreateAccount(addr)

	// Set minimal bridge contract code. This bytecode always returns
	// success (32 bytes of 0x01). The actual withdrawal enforcement
	// (rate limiting, burn, storage updates) is handled by the Go block
	// executor via RecordWithdrawal, mirroring how deposits are handled
	// via ApplyDepositTx in pkg/block/system_tx.go.
	code := bridgeContractCode()
	stateDB.SetCode(addr, code, tracing.CodeChangeCreation)

	// Initialize storage slots to zero.
	stateDB.SetState(addr, TotalDepositedSlot, types.Hash{})
	stateDB.SetState(addr, TotalWithdrawnSlot, types.Hash{})
	stateDB.SetState(addr, WithdrawalNonceSlot, types.Hash{})
}

// bridgeContractCode returns the EVM bytecode for the L2 bridge predeploy.
// This is a minimal contract that accepts any call and returns 32 bytes
// containing the value 1 (success). The real withdrawal logic (rate
// limiting, burn, event emission) is enforced at the Go block executor
// level, not in EVM bytecode.
//
// Bytecode:
//
//	PUSH1 0x01   (60 01)
//	PUSH1 0x00   (60 00)
//	MSTORE       (52)
//	PUSH1 0x20   (60 20)
//	PUSH1 0x00   (60 00)
//	RETURN       (f3)
func bridgeContractCode() []byte {
	return []byte{
		0x60, 0x01, // PUSH1 0x01
		0x60, 0x00, // PUSH1 0x00
		0x52,       // MSTORE
		0x60, 0x20, // PUSH1 0x20
		0x60, 0x00, // PUSH1 0x00
		0xf3, // RETURN
	}
}

// CheckWithdrawalRateLimit verifies that a withdrawal amount does not
// exceed the per-period rate limit. Each period (BlocksPerPeriod blocks,
// ~24h) allows withdrawals totalling at most MaxWithdrawalBPS/10000
// (10%) of totalDeposited.
//
// Returns nil if the withdrawal is within the rate limit, or an error
// describing the violation.
func CheckWithdrawalRateLimit(stateDB *state.StateDB, blockNumber uint64, amount *uint256.Int) error {
	addr := types.BridgeContractAddress

	// Read totalDeposited from storage.
	totalDepositedHash := stateDB.GetState(addr, TotalDepositedSlot)
	depositedInt := new(uint256.Int).SetBytes(totalDepositedHash[:])

	// If nothing has been deposited, no withdrawal is possible.
	if depositedInt.IsZero() {
		return fmt.Errorf("withdrawal rate limit exceeded: no deposits recorded")
	}

	// Max withdrawal per period = totalDeposited * MaxWithdrawalBPS / 10000.
	maxPerPeriod := new(uint256.Int).Mul(depositedInt, uint256.NewInt(MaxWithdrawalBPS))
	maxPerPeriod.Div(maxPerPeriod, uint256.NewInt(10000))

	// Determine the current period.
	period := blockNumber / BlocksPerPeriod

	// Read this period's cumulative withdrawals.
	periodSlot := computePeriodSlot(period)
	currentPeriodHash := stateDB.GetState(addr, periodSlot)
	withdrawnInt := new(uint256.Int).SetBytes(currentPeriodHash[:])

	// Check whether adding this withdrawal would exceed the limit.
	newTotal := new(uint256.Int).Add(withdrawnInt, amount)
	if newTotal.Cmp(maxPerPeriod) > 0 {
		return fmt.Errorf("withdrawal rate limit exceeded: period %d, used %s + %s > max %s",
			period, withdrawnInt, amount, maxPerPeriod)
	}

	return nil
}

// RecordWithdrawal updates the bridge contract's storage to reflect a
// completed withdrawal. It increments totalWithdrawn, updates the
// period's cumulative withdrawals, increments the withdrawal nonce,
// and stores the withdrawal hash.
func RecordWithdrawal(stateDB *state.StateDB, blockNumber uint64, amount *uint256.Int, bsvAddress []byte, nonce uint64) {
	addr := types.BridgeContractAddress

	// 1. Update totalWithdrawn (slot 5).
	totalWithdrawnHash := stateDB.GetState(addr, TotalWithdrawnSlot)
	totalWithdrawn := new(uint256.Int).SetBytes(totalWithdrawnHash[:])
	totalWithdrawn.Add(totalWithdrawn, amount)
	var newTotalWithdrawnHash types.Hash
	totalWithdrawn.WriteToSlice(newTotalWithdrawnHash[:])
	stateDB.SetState(addr, TotalWithdrawnSlot, newTotalWithdrawnHash)

	// 2. Update periodWithdrawals[period] (slot keccak256(period, 6)).
	period := blockNumber / BlocksPerPeriod
	periodSlot := computePeriodSlot(period)
	currentPeriodHash := stateDB.GetState(addr, periodSlot)
	periodWithdrawals := new(uint256.Int).SetBytes(currentPeriodHash[:])
	periodWithdrawals.Add(periodWithdrawals, amount)
	var newPeriodHash types.Hash
	periodWithdrawals.WriteToSlice(newPeriodHash[:])
	stateDB.SetState(addr, periodSlot, newPeriodHash)

	// 3. Increment withdrawalNonce (slot 2).
	nonceHash := stateDB.GetState(addr, WithdrawalNonceSlot)
	currentNonce := new(uint256.Int).SetBytes(nonceHash[:])
	currentNonce.Add(currentNonce, uint256.NewInt(1))
	var newNonceHash types.Hash
	currentNonce.WriteToSlice(newNonceHash[:])
	stateDB.SetState(addr, WithdrawalNonceSlot, newNonceHash)

	// 4. Store the withdrawal hash at a deterministic slot derived from
	//    the nonce. This allows on-chain verification of withdrawal data.
	satoshiAmount := types.WeiToSatoshis(amount)
	wHash := WithdrawalHash(bsvAddress, satoshiAmount, nonce)
	withdrawalSlot := computeWithdrawalSlot(nonce)
	stateDB.SetState(addr, withdrawalSlot, wHash)
}

// computePeriodSlot computes the storage slot for periodWithdrawals[period].
// Following Solidity's mapping storage layout: keccak256(abi.encode(key, slot)).
// Here key = uint256(period), slot = uint256(6).
func computePeriodSlot(period uint64) types.Hash {
	// Build 64-byte input: uint256(period) || uint256(6).
	var data [64]byte
	periodInt := uint256.NewInt(period)
	periodInt.WriteToSlice(data[0:32])
	data[63] = 6 // slot 6 as uint256

	hash := crypto.Keccak256(data[:])
	return types.BytesToHash(hash)
}

// computeWithdrawalSlot computes the storage slot for withdrawalHashes[nonce].
// Following Solidity's mapping storage layout: keccak256(abi.encode(key, slot)).
// Here key = uint256(nonce), slot = uint256(1) (the withdrawalHashes mapping).
func computeWithdrawalSlot(nonce uint64) types.Hash {
	var data [64]byte
	nonceInt := uint256.NewInt(nonce)
	nonceInt.WriteToSlice(data[0:32])
	data[63] = 1 // slot 1 as uint256 (withdrawalHashes mapping)

	hash := crypto.Keccak256(data[:])
	return types.BytesToHash(hash)
}
