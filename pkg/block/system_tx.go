package block

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"

	"github.com/holiman/uint256"
	"github.com/icellan/bsvm/pkg/bridge"
	"github.com/icellan/bsvm/pkg/crypto"
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

// WithdrawSelector is the 4-byte ABI function selector for
// `withdraw(uint256,bytes20)`. Computed as the first 4 bytes of
// keccak256("withdraw(uint256,bytes20)") = 0xe72689ba.
var WithdrawSelector = [4]byte{0xe7, 0x26, 0x89, 0xba}

// withdrawalInitiatedTopic is the keccak256 of the canonical
// `WithdrawalInitiated(uint256,bytes20,uint256,bytes32)` event signature.
// Used as topic[0] of the synthetic log emitted by ApplyWithdrawTx so
// explorers and `eth_getLogs` consumers can filter for withdrawals.
var withdrawalInitiatedTopic = types.BytesToHash(crypto.Keccak256(
	[]byte("WithdrawalInitiated(uint256,bytes20,uint256,bytes32)"),
))

// burnAddress is the unrecoverable dead address that wBSV is burned to
// during a withdrawal. Matches the L2Bridge Solidity contract's
// BURN_ADDRESS (0x000...dEaD). The address has no private key so the
// balance is permanently irrecoverable on L2.
var burnAddress = types.HexToAddress("0x000000000000000000000000000000000000dEaD")

// IsWithdrawDispatch returns true when the message is a call to the
// L2Bridge predeploy whose calldata starts with the withdraw selector.
// The block executor uses this to short-circuit the EVM call and apply
// the withdrawal as a direct state mutation (mirroring how deposits are
// handled by ApplyDepositTx). The EVM bytecode at the predeploy address
// is a stub that always returns success — actual withdrawal enforcement
// (rate limit, balance burn, storage updates, event emission) lives in
// ApplyWithdrawTx so it cannot be re-entered or interfered with by
// other EVM code.
func IsWithdrawDispatch(to *types.Address, data []byte) bool {
	if to == nil {
		return false
	}
	if *to != types.BridgeContractAddress {
		return false
	}
	if len(data) < 4 {
		return false
	}
	return bytes.Equal(data[:4], WithdrawSelector[:])
}

// ApplyWithdrawTx applies an L2 withdrawal initiation. It is invoked
// by the state-transition fast path when a transaction targets the
// L2Bridge predeploy with the `withdraw(uint256,bytes20)` selector.
//
// Behaviour:
//  1. Decode (satoshiAmount, bsvAddress) from ABI calldata.
//  2. Convert satoshis to L2 wei via types.SatoshisToWei.
//  3. Reject if caller balance < L2 wei amount.
//  4. Reject if the per-period rate limit is exceeded.
//  5. Burn the wBSV: subtract from caller balance, credit the burn
//     address (matches the Solidity contract's BURN_ADDRESS path).
//  6. Read+increment the bridge's withdrawalNonce slot, then call
//     bridge.RecordWithdrawal to update totalWithdrawn,
//     periodWithdrawals[period], and the withdrawal hash slot.
//  7. Emit a synthetic WithdrawalInitiated log so frontends can index
//     the withdrawal via standard eth_getLogs.
//
// The function returns a non-nil error only for malformed calldata or
// failed pre-conditions (rate limit, balance). The caller is responsible
// for translating an error into a failed receipt.
func ApplyWithdrawTx(statedb *state.StateDB, header *L2Header, from types.Address, data []byte) (*types.Log, error) {
	satoshis, bsvAddr, err := DecodeWithdrawCalldata(data)
	if err != nil {
		return nil, err
	}
	if satoshis == 0 {
		return nil, errors.New("withdraw: amount must be positive")
	}

	weiAmount := types.SatoshisToWei(satoshis)

	balance := statedb.GetBalance(from)
	if balance.Cmp(weiAmount) < 0 {
		return nil, fmt.Errorf("withdraw: insufficient balance: have %s, want %s", balance, weiAmount)
	}

	blockNum := header.Number.Uint64()
	if err := bridge.CheckWithdrawalRateLimit(statedb, blockNum, weiAmount); err != nil {
		return nil, fmt.Errorf("withdraw: %w", err)
	}

	// Read the current nonce BEFORE RecordWithdrawal increments it so we
	// emit the log with the matching value.
	if !statedb.Exist(types.BridgeContractAddress) {
		statedb.CreateAccount(types.BridgeContractAddress)
	}
	nonceHash := statedb.GetState(types.BridgeContractAddress, bridge.WithdrawalNonceSlot)
	nonce := new(uint256.Int).SetBytes(nonceHash[:]).Uint64()

	// Burn the wBSV: subtract from caller, credit the unrecoverable
	// dead address. This mirrors the Solidity contract's transfer to
	// BURN_ADDRESS so totalSupply is preserved even though the wBSV is
	// effectively gone.
	statedb.SubBalance(from, weiAmount, tracing.BalanceDecreaseWithdrawal)
	if !statedb.Exist(burnAddress) {
		statedb.CreateAccount(burnAddress)
	}
	statedb.AddBalance(burnAddress, weiAmount, tracing.BalanceIncreaseWithdrawal)

	bridge.RecordWithdrawal(statedb, blockNum, weiAmount, bsvAddr, nonce)

	// Build the WithdrawalInitiated log. Topic 0 is the event signature;
	// topic 1 is the indexed sender (the L2 caller). Non-indexed params
	// (bsvAddress as 32-byte right-padded bytes20, amount, withdrawalHash)
	// are concatenated in the data field per the ABI spec.
	withdrawalHash := bridge.WithdrawalHash(bsvAddr, satoshis, nonce)
	logData := make([]byte, 0, 96)
	addrPadded := make([]byte, 32)
	copy(addrPadded[:20], bsvAddr) // bytes20 is right-padded with zeros
	logData = append(logData, addrPadded...)
	amountWord := make([]byte, 32)
	weiAmount.WriteToSlice(amountWord)
	logData = append(logData, amountWord...)
	logData = append(logData, withdrawalHash[:]...)

	senderTopic := types.Hash{}
	copy(senderTopic[12:], from[:])

	log := &types.Log{
		Address:     types.BridgeContractAddress,
		Topics:      []types.Hash{withdrawalInitiatedTopic, senderTopic},
		Data:        logData,
		BlockNumber: blockNum,
	}
	statedb.AddLog(log)

	return log, nil
}

// DecodeWithdrawCalldata decodes the ABI-encoded arguments for
// `withdraw(uint256 satoshis, bytes20 bsvAddressHash160)`. Calldata
// layout is: 4-byte selector + 32-byte uint256 + 32-byte bytes20
// (right-padded with zeros) = 68 bytes total.
//
// The satoshi amount must fit in uint64 (sufficient for any sane BSV
// amount); larger values are rejected. The address is returned as the
// raw 20-byte hash.
func DecodeWithdrawCalldata(data []byte) (satoshis uint64, bsvAddress []byte, err error) {
	if len(data) < 68 {
		return 0, nil, fmt.Errorf("withdraw: calldata too short: have %d, want at least 68", len(data))
	}
	if !bytes.Equal(data[:4], WithdrawSelector[:]) {
		return 0, nil, errors.New("withdraw: selector mismatch")
	}
	amountWord := data[4:36]
	addrWord := data[36:68]

	// uint256 satoshis: reject anything that doesn't fit in uint64.
	for i := 0; i < 24; i++ {
		if amountWord[i] != 0 {
			return 0, nil, errors.New("withdraw: amount exceeds uint64")
		}
	}
	satoshis = binary.BigEndian.Uint64(amountWord[24:32])

	// bytes20 is right-padded with zeros: bytes 0..19 hold the address,
	// bytes 20..31 must be zero per the ABI spec.
	for i := 20; i < 32; i++ {
		if addrWord[i] != 0 {
			return 0, nil, errors.New("withdraw: bytes20 has non-zero padding")
		}
	}
	bsvAddress = make([]byte, 20)
	copy(bsvAddress, addrWord[:20])
	return satoshis, bsvAddress, nil
}

// EncodeWithdrawCalldata returns the ABI-encoded calldata that the L2
// transaction must carry to invoke a withdrawal: selector + uint256
// satoshis + bytes20 (right-padded). Exposed so tests and clients
// (RPC, SDK) can build matching calldata without duplicating the layout.
func EncodeWithdrawCalldata(satoshis uint64, bsvAddress []byte) ([]byte, error) {
	if len(bsvAddress) != 20 {
		return nil, fmt.Errorf("withdraw: bsv address must be 20 bytes, got %d", len(bsvAddress))
	}
	out := make([]byte, 68)
	copy(out[:4], WithdrawSelector[:])
	binary.BigEndian.PutUint64(out[28:36], satoshis)
	copy(out[36:56], bsvAddress)
	return out, nil
}
