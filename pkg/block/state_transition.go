// Copyright 2014 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// Adapted from go-ethereum core/state_transition.go for the BSVM project.

package block

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/holiman/uint256"
	"github.com/icellan/bsvm/pkg/types"
	"github.com/icellan/bsvm/pkg/vm"
	"github.com/icellan/bsvm/pkg/vm/tracing"
)

var (
	// ErrNonceTooHigh is returned if the nonce of a transaction is higher
	// than the next expected nonce.
	ErrNonceTooHigh = errors.New("nonce too high")
	// ErrNonceTooLow is returned if the nonce of a transaction is lower
	// than the expected nonce.
	ErrNonceTooLow = errors.New("nonce too low")
	// ErrNonceMax is returned if the nonce of a transaction sender account
	// has maximum value of uint64.
	ErrNonceMax = errors.New("nonce has max value")
	// ErrInsufficientFundsForTransfer is returned if the sender does not
	// have enough funds to cover the value transfer.
	ErrInsufficientFundsForTransfer = errors.New("insufficient funds for transfer")
	// ErrInsufficientFunds is returned if the sender does not have enough
	// funds to cover gas costs.
	ErrInsufficientFunds = errors.New("insufficient funds for gas * price + value")
	// ErrGasLimitReached is returned if the gas pool has been exhausted.
	ErrGasLimitReached = errors.New("gas limit reached")
	// ErrIntrinsicGas is returned if the transaction gas is too low.
	ErrIntrinsicGas = errors.New("intrinsic gas too low")
	// ErrSenderNoEOA is returned if the sender of a transaction is not an
	// externally-owned account (EIP-3607).
	ErrSenderNoEOA = errors.New("sender not an eoa")
	// ErrFeeCapTooLow is returned if the transaction fee cap is less than
	// the base fee.
	ErrFeeCapTooLow = errors.New("max fee per gas less than block base fee")
	// ErrFeeCapVeryHigh is returned if the transaction fee cap is too high.
	ErrFeeCapVeryHigh = errors.New("max fee per gas higher than 2^256-1")
	// ErrTipVeryHigh is returned if the transaction tip is too high.
	ErrTipVeryHigh = errors.New("max priority fee per gas higher than 2^256-1")
	// ErrTipAboveFeeCap is returned if the transaction tip is above the fee cap.
	ErrTipAboveFeeCap = errors.New("max priority fee per gas higher than max fee per gas")
	// ErrMaxInitCodeSizeExceeded is returned if initcode exceeds the max size.
	ErrMaxInitCodeSizeExceeded = errors.New("max initcode size exceeded")
)

// Message represents an EVM message (transaction converted to execution format).
type Message struct {
	From       types.Address
	To         *types.Address
	Nonce      uint64
	Value      *uint256.Int
	GasLimit   uint64
	GasPrice   *big.Int
	GasFeeCap  *big.Int
	GasTipCap  *big.Int
	Data       []byte
	AccessList types.AccessList

	// BlobHashes and BlobGasFeeCap are EIP-4844 fields. We don't process
	// blob transactions on L2, but these are passed through to the EVM
	// context so opcodes like BLOBHASH work in tests.
	BlobHashes    []types.Hash
	BlobGasFeeCap *big.Int

	// When SkipNonceChecks is true, the message nonce is not checked against
	// the account nonce in state. Used for eth_call.
	SkipNonceChecks bool

	// When SkipFromEOACheck is true, the sender is not checked to be an EOA.
	SkipFromEOACheck bool
}

// TransactionToMessage converts a signed transaction to a Message by recovering
// the sender and extracting the transaction fields.
func TransactionToMessage(tx *types.Transaction, s types.Signer, baseFee *big.Int) (*Message, error) {
	from, err := types.Sender(s, tx)
	if err != nil {
		return nil, fmt.Errorf("could not recover sender: %w", err)
	}

	msg := &Message{
		From:             from,
		To:               tx.To(),
		Nonce:            tx.Nonce(),
		Value:            new(uint256.Int).Set(tx.Value()),
		GasLimit:         tx.Gas(),
		GasPrice:         new(big.Int).Set(tx.GasPrice()),
		GasFeeCap:        new(big.Int).Set(tx.GasFeeCap()),
		GasTipCap:        new(big.Int).Set(tx.GasTipCap()),
		Data:             tx.Data(),
		AccessList:       tx.AccessList(),
		SkipNonceChecks:  false,
		SkipFromEOACheck: false,
	}

	// If baseFee provided, set gasPrice to effectiveGasPrice.
	if baseFee != nil {
		msg.GasPrice = msg.GasPrice.Add(msg.GasTipCap, baseFee)
		if msg.GasPrice.Cmp(msg.GasFeeCap) > 0 {
			msg.GasPrice = new(big.Int).Set(msg.GasFeeCap)
		}
	}

	return msg, nil
}

// ExecutionResult contains the result of a state transition.
type ExecutionResult struct {
	UsedGas    uint64
	Err        error
	ReturnData []byte
}

// Failed returns whether the execution resulted in an error.
func (result *ExecutionResult) Failed() bool {
	return result.Err != nil
}

// Return returns the return data if execution succeeded, nil otherwise.
func (result *ExecutionResult) Return() []byte {
	if result.Err != nil {
		return nil
	}
	return result.ReturnData
}

// Revert returns the return data if the execution was explicitly reverted,
// nil otherwise.
func (result *ExecutionResult) Revert() []byte {
	if result.Err != vm.ErrExecutionReverted {
		return nil
	}
	return result.ReturnData
}

// NewEVMTxContext creates a new TxContext for the given message.
func NewEVMTxContext(msg *Message) vm.TxContext {
	return vm.TxContext{
		Origin:     msg.From,
		GasPrice:   msg.GasPrice,
		BlobHashes: msg.BlobHashes,
		BlobFeeCap: msg.BlobGasFeeCap,
	}
}

// stateTransition represents a state transition.
type stateTransition struct {
	gp           *GasPool
	msg          *Message
	gasRemaining uint64
	initialGas   uint64
	state        vm.StateDB
	evm          *vm.EVM
}

// newStateTransition initialises and returns a new state transition object.
func newStateTransition(evm *vm.EVM, msg *Message, gp *GasPool) *stateTransition {
	return &stateTransition{
		gp:    gp,
		evm:   evm,
		msg:   msg,
		state: evm.StateDB,
	}
}

// ApplyMessage computes the new state by applying the given message against
// the old state within the environment.
//
// ApplyMessage returns the execution result with the gas used (including gas
// refunds) and an error if it failed. An error always indicates a core error
// meaning that the message would always fail for that particular state and
// would never be accepted within a block.
func ApplyMessage(evm *vm.EVM, msg *Message, gp *GasPool) (*ExecutionResult, error) {
	evm.SetTxContext(NewEVMTxContext(msg))
	return newStateTransition(evm, msg, gp).execute()
}

// to returns the recipient of the message.
func (st *stateTransition) to() types.Address {
	if st.msg == nil || st.msg.To == nil {
		return types.Address{}
	}
	return *st.msg.To
}

// buyGas deducts the upfront gas cost from the sender's balance and
// reserves gas from the gas pool.
func (st *stateTransition) buyGas() error {
	mgval := new(big.Int).SetUint64(st.msg.GasLimit)
	mgval.Mul(mgval, st.msg.GasPrice)
	balanceCheck := new(big.Int).Set(mgval)
	if st.msg.GasFeeCap != nil {
		balanceCheck.SetUint64(st.msg.GasLimit)
		balanceCheck = balanceCheck.Mul(balanceCheck, st.msg.GasFeeCap)
	}
	balanceCheck.Add(balanceCheck, st.msg.Value.ToBig())

	balanceCheckU256, overflow := uint256.FromBig(balanceCheck)
	if overflow {
		return fmt.Errorf("%w: address %v required balance exceeds 256 bits", ErrInsufficientFunds, st.msg.From.Hex())
	}
	if have, want := st.state.GetBalance(st.msg.From), balanceCheckU256; have.Cmp(want) < 0 {
		return fmt.Errorf("%w: address %v have %v want %v", ErrInsufficientFunds, st.msg.From.Hex(), have, want)
	}
	if err := st.gp.SubGas(st.msg.GasLimit); err != nil {
		return err
	}

	if st.evm.Config.Tracer != nil && st.evm.Config.Tracer.OnGasChange != nil {
		st.evm.Config.Tracer.OnGasChange(0, st.msg.GasLimit, tracing.GasChangeTxInitialBalance)
	}
	st.gasRemaining = st.msg.GasLimit
	st.initialGas = st.msg.GasLimit

	mgvalU256, _ := uint256.FromBig(mgval)
	st.state.SubBalance(st.msg.From, mgvalU256, tracing.BalanceDecreaseGasBuy)
	return nil
}

// preCheck validates the nonce, checks sender is an EOA, verifies fee caps,
// and buys gas.
func (st *stateTransition) preCheck() error {
	msg := st.msg

	// Only check transactions that are not fake.
	if !msg.SkipNonceChecks {
		// Make sure this transaction's nonce is correct.
		stNonce := st.state.GetNonce(msg.From)
		if msgNonce := msg.Nonce; stNonce < msgNonce {
			return fmt.Errorf("%w: address %v, tx: %d state: %d", ErrNonceTooHigh,
				msg.From.Hex(), msgNonce, stNonce)
		} else if stNonce > msgNonce {
			return fmt.Errorf("%w: address %v, tx: %d state: %d", ErrNonceTooLow,
				msg.From.Hex(), msgNonce, stNonce)
		} else if stNonce+1 < stNonce {
			return fmt.Errorf("%w: address %v, nonce: %d", ErrNonceMax,
				msg.From.Hex(), stNonce)
		}
	}

	if !msg.SkipFromEOACheck {
		// EIP-3607: reject transactions from senders with deployed code.
		codeHash := st.state.GetCodeHash(msg.From)
		if codeHash != (types.Hash{}) && codeHash != types.EmptyCodeHash {
			return fmt.Errorf("%w: address %v, codehash: %s", ErrSenderNoEOA,
				msg.From.Hex(), codeHash.Hex())
		}
	}

	// Make sure that transaction gasFeeCap is greater than the baseFee (post london).
	if st.evm.ChainConfig().IsLondon(st.evm.Context.BlockNumber) {
		// Skip the checks if gas fields are zero and baseFee was explicitly disabled (eth_call).
		skipCheck := st.evm.Config.NoBaseFee && msg.GasFeeCap.BitLen() == 0 && msg.GasTipCap.BitLen() == 0
		if !skipCheck {
			if l := msg.GasFeeCap.BitLen(); l > 256 {
				return fmt.Errorf("%w: address %v, maxFeePerGas bit length: %d", ErrFeeCapVeryHigh,
					msg.From.Hex(), l)
			}
			if l := msg.GasTipCap.BitLen(); l > 256 {
				return fmt.Errorf("%w: address %v, maxPriorityFeePerGas bit length: %d", ErrTipVeryHigh,
					msg.From.Hex(), l)
			}
			if msg.GasFeeCap.Cmp(msg.GasTipCap) < 0 {
				return fmt.Errorf("%w: address %v, maxPriorityFeePerGas: %s, maxFeePerGas: %s", ErrTipAboveFeeCap,
					msg.From.Hex(), msg.GasTipCap, msg.GasFeeCap)
			}
			// This will panic if baseFee is nil, but basefee presence is verified
			// as part of header validation.
			if msg.GasFeeCap.Cmp(st.evm.Context.BaseFee) < 0 {
				return fmt.Errorf("%w: address %v, maxFeePerGas: %s, baseFee: %s", ErrFeeCapTooLow,
					msg.From.Hex(), msg.GasFeeCap, st.evm.Context.BaseFee)
			}
		}
	}

	return st.buyGas()
}

// execute will transition the state by applying the current message and
// returning the evm execution result with following fields.
//
//   - used gas: total gas used (including gas being refunded)
//   - returndata: the returned data from evm
//   - concrete execution error: various EVM errors which abort the execution,
//     e.g. ErrOutOfGas, ErrExecutionReverted
//
// However if any consensus issue encountered, return the error directly with
// nil evm execution result.
func (st *stateTransition) execute() (*ExecutionResult, error) {
	// First check this message satisfies all consensus rules before
	// applying the message.
	if err := st.preCheck(); err != nil {
		return nil, err
	}

	var (
		msg              = st.msg
		rules            = st.evm.ChainConfig().Rules(st.evm.Context.BlockNumber, st.evm.Context.Random != nil, st.evm.Context.Time)
		contractCreation = msg.To == nil
	)

	// Check clauses 4-5, subtract intrinsic gas if everything is correct.
	gas, err := vm.IntrinsicGas(msg.Data, msg.AccessList, contractCreation, rules.IsHomestead, rules.IsIstanbul, rules.IsShanghai)
	if err != nil {
		return nil, err
	}
	if st.gasRemaining < gas {
		return nil, fmt.Errorf("%w: have %d, want %d", ErrIntrinsicGas, st.gasRemaining, gas)
	}
	if t := st.evm.Config.Tracer; t != nil && t.OnGasChange != nil {
		t.OnGasChange(st.gasRemaining, st.gasRemaining-gas, tracing.GasChangeTxIntrinsicGas)
	}
	st.gasRemaining -= gas

	// Check clause 6: caller has enough balance to cover asset transfer.
	value := msg.Value
	if value == nil {
		value = new(uint256.Int)
	}
	if !value.IsZero() && !st.evm.Context.CanTransfer(st.state, msg.From, value) {
		return nil, fmt.Errorf("%w: address %v", ErrInsufficientFundsForTransfer, msg.From.Hex())
	}

	// Check whether the init code size has been exceeded.
	if rules.IsShanghai && contractCreation && len(msg.Data) > vm.MaxInitCodeSize {
		return nil, fmt.Errorf("%w: code size %v limit %v", ErrMaxInitCodeSizeExceeded, len(msg.Data), vm.MaxInitCodeSize)
	}

	// Execute the preparatory steps for state transition which includes:
	// - prepare accessList (post-berlin)
	// - reset transient storage (eip 1153)
	st.state.Prepare(rules, msg.From, st.evm.Context.Coinbase, msg.To, vm.ActivePrecompiles(rules), msg.AccessList)

	var (
		ret   []byte
		vmerr error // vm errors do not affect consensus and are therefore not assigned to err
	)
	if contractCreation {
		ret, _, st.gasRemaining, vmerr = st.evm.Create(msg.From, msg.Data, st.gasRemaining, value)
	} else {
		// Increment the nonce for the next transaction.
		st.state.SetNonce(msg.From, st.state.GetNonce(msg.From)+1, tracing.NonceChangeEoACall)

		// Execute the transaction's call.
		ret, st.gasRemaining, vmerr = st.evm.Call(msg.From, st.to(), msg.Data, st.gasRemaining, value)
	}

	// Compute refund counter, capped to a refund quotient.
	st.gasRemaining += st.calcRefund()

	// Return remaining gas to sender.
	st.returnGas()

	// Pay the effective tip to the coinbase.
	effectiveTip := msg.GasPrice
	if rules.IsLondon {
		effectiveTip = new(big.Int).Sub(msg.GasFeeCap, st.evm.Context.BaseFee)
		if effectiveTip.Cmp(msg.GasTipCap) > 0 {
			effectiveTip = msg.GasTipCap
		}
	}
	effectiveTipU256, _ := uint256.FromBig(effectiveTip)

	if st.evm.Config.NoBaseFee && msg.GasFeeCap.Sign() == 0 && msg.GasTipCap.Sign() == 0 {
		// Skip fee payment when NoBaseFee is set and the fee fields
		// are 0. This avoids a negative effectiveTip being applied to
		// the coinbase when simulating calls.
	} else {
		fee := new(uint256.Int).SetUint64(st.gasUsed())
		fee.Mul(fee, effectiveTipU256)
		st.state.AddBalance(st.evm.Context.Coinbase, fee, tracing.BalanceIncreaseRewardTransactionFee)
	}

	return &ExecutionResult{
		UsedGas:    st.gasUsed(),
		Err:        vmerr,
		ReturnData: ret,
	}, nil
}

// calcRefund computes the refund counter, capped to a refund quotient.
func (st *stateTransition) calcRefund() uint64 {
	var refund uint64
	if !st.evm.ChainConfig().IsLondon(st.evm.Context.BlockNumber) {
		// Before EIP-3529: refunds were capped to gasUsed / 2
		refund = st.gasUsed() / vm.RefundQuotient
	} else {
		// After EIP-3529: refunds are capped to gasUsed / 5
		refund = st.gasUsed() / vm.RefundQuotientEIP3529
	}
	if refund > st.state.GetRefund() {
		refund = st.state.GetRefund()
	}
	if st.evm.Config.Tracer != nil && st.evm.Config.Tracer.OnGasChange != nil && refund > 0 {
		st.evm.Config.Tracer.OnGasChange(st.gasRemaining, st.gasRemaining+refund, tracing.GasChangeTxRefunds)
	}
	return refund
}

// returnGas returns ETH for remaining gas, exchanged at the original rate.
func (st *stateTransition) returnGas() {
	remaining := uint256.NewInt(st.gasRemaining)
	remaining.Mul(remaining, uint256.MustFromBig(st.msg.GasPrice))
	st.state.AddBalance(st.msg.From, remaining, tracing.BalanceIncreaseGasReturn)

	if st.evm.Config.Tracer != nil && st.evm.Config.Tracer.OnGasChange != nil && st.gasRemaining > 0 {
		st.evm.Config.Tracer.OnGasChange(st.gasRemaining, 0, tracing.GasChangeTxLeftOverReturned)
	}

	// Also return remaining gas to the block gas counter so it is
	// available for the next transaction.
	st.gp.AddGas(st.gasRemaining)
}

// gasUsed returns the amount of gas used up by the state transition.
func (st *stateTransition) gasUsed() uint64 {
	return st.initialGas - st.gasRemaining
}
