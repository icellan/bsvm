package block

import (
	"math/big"

	"github.com/holiman/uint256"
	"github.com/icellan/bsvm/pkg/state"
	"github.com/icellan/bsvm/pkg/types"
	"github.com/icellan/bsvm/pkg/vm/tracing"
)

// TotalDepositedStorageSlot is the fixed storage slot for the
// totalDeposited variable in the L2Bridge predeploy contract.
// Solidity storage slot 4 (uint256). This is a compile-time constant
// derived from the bridge contract's storage layout.
//
// Storage layout:
//
//	slot 0: withdrawals mapping
//	slot 1: withdrawalHashes mapping
//	slot 2: withdrawalNonce
//	slot 3: (reserved)
//	slot 4: totalDeposited
//	slot 5: totalWithdrawn
//	slot 6: periodWithdrawals mapping
var TotalDepositedStorageSlot = types.Hash{
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 4,
}

// ApplyDepositTx applies a deposit system transaction by directly
// mutating the StateDB. This bypasses the EVM entirely -- no gas is
// bought, no gas is consumed, no gas is refunded, no Solidity code
// is executed.
//
// This follows the same pattern as Optimism's deposit transactions.
// The function always succeeds -- deposits cannot fail.
func ApplyDepositTx(statedb *state.StateDB, header *L2Header, tx *types.DepositTransaction) *types.Receipt {
	// 1. Ensure the recipient account exists.
	if !statedb.Exist(tx.To) {
		statedb.CreateAccount(tx.To)
	}

	// 2. Credit the deposit amount directly.
	statedb.AddBalance(tx.To, tx.Value, tracing.BalanceIncreaseDeposit)

	// 3. Update the bridge contract's totalDeposited counter via direct
	//    storage mutation.
	if !statedb.Exist(types.BridgeContractAddress) {
		statedb.CreateAccount(types.BridgeContractAddress)
	}
	currentTotal := statedb.GetState(types.BridgeContractAddress, TotalDepositedStorageSlot)
	newTotal := new(uint256.Int).Add(
		new(uint256.Int).SetBytes(currentTotal[:]),
		tx.Value,
	)
	var newTotalHash types.Hash
	newTotal.WriteToSlice(newTotalHash[:])
	statedb.SetState(types.BridgeContractAddress, TotalDepositedStorageSlot, newTotalHash)

	// 4. Create receipt (always successful).
	receipt := &types.Receipt{
		Type:              types.DepositTxType,
		Status:            types.ReceiptStatusSuccessful,
		CumulativeGasUsed: 0,
		TxHash:            tx.Hash(),
		GasUsed:           0,
		Logs:              nil,
		BlockNumber:       header.Number,
	}

	return receipt
}

// ApplyDepositTxWithIndex applies a deposit system transaction and sets
// the transaction context for log attribution. This is a convenience
// wrapper around ApplyDepositTx for use in block processing.
func ApplyDepositTxWithIndex(statedb *state.StateDB, header *L2Header, tx *types.DepositTransaction, txIndex int) *types.Receipt {
	statedb.SetTxContext(tx.Hash(), txIndex)
	receipt := ApplyDepositTx(statedb, header, tx)
	receipt.TransactionIndex = uint(txIndex)
	receipt.BlockNumber = new(big.Int).Set(header.Number)
	return receipt
}
