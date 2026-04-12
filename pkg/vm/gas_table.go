// Copyright 2017 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package vm

import (
	"errors"
	"fmt"

	"github.com/icellan/bsvm/pkg/types"
)

// memoryGasCost calculates the quadratic gas for memory expansion. It does so
// only for the memory region that is expanded, not the total memory.
func memoryGasCost(mem *Memory, newMemSize uint64) (uint64, error) {
	if newMemSize == 0 {
		return 0, nil
	}
	if newMemSize > 0x1FFFFFFFE0 {
		return 0, ErrGasUintOverflow
	}
	newMemSizeWords := toWordSize(newMemSize)
	newMemSize = newMemSizeWords * 32

	if newMemSize > uint64(mem.Len()) {
		square := newMemSizeWords * newMemSizeWords
		linCoef := newMemSizeWords * MemoryGas
		quadCoef := square / QuadCoeffDiv
		newTotalFee := linCoef + quadCoef

		fee := newTotalFee - mem.lastGasCost
		mem.lastGasCost = newTotalFee

		return fee, nil
	}
	return 0, nil
}

func memoryCopierGas(stackpos int) gasFunc {
	return func(evm *EVM, contract *Contract, stack *Stack, mem *Memory, memorySize uint64) (uint64, error) {
		gas, err := memoryGasCost(mem, memorySize)
		if err != nil {
			return 0, err
		}
		words, overflow := stack.Back(stackpos).Uint64WithOverflow()
		if overflow {
			return 0, ErrGasUintOverflow
		}
		if words, overflow = SafeMul(toWordSize(words), CopyGas); overflow {
			return 0, ErrGasUintOverflow
		}
		if gas, overflow = SafeAdd(gas, words); overflow {
			return 0, ErrGasUintOverflow
		}
		return gas, nil
	}
}

var (
	gasCallDataCopy   = memoryCopierGas(2)
	gasCodeCopy       = memoryCopierGas(2)
	gasMcopy          = memoryCopierGas(2)
	gasExtCodeCopy    = memoryCopierGas(3)
	gasReturnDataCopy = memoryCopierGas(2)
)

func gasSStore(evm *EVM, contract *Contract, stack *Stack, mem *Memory, memorySize uint64) (uint64, error) {
	var (
		y, x    = stack.Back(1), stack.Back(0)
		current = evm.StateDB.GetState(contract.Address(), x.Bytes32())
	)
	if evm.chainRules.IsPetersburg || !evm.chainRules.IsConstantinople {
		switch {
		case current == (types.Hash{}) && y.Sign() != 0:
			return SstoreSetGas, nil
		case current != (types.Hash{}) && y.Sign() == 0:
			evm.StateDB.AddRefund(SstoreRefundGas)
			return SstoreClearGas, nil
		default:
			return SstoreResetGas, nil
		}
	}

	value := types.Hash(y.Bytes32())
	if current == value {
		return NetSstoreNoopGas, nil
	}
	original := evm.StateDB.GetCommittedState(contract.Address(), x.Bytes32())
	if original == current {
		if original == (types.Hash{}) {
			return NetSstoreInitGas, nil
		}
		if value == (types.Hash{}) {
			evm.StateDB.AddRefund(NetSstoreClearRefund)
		}
		return NetSstoreCleanGas, nil
	}
	if original != (types.Hash{}) {
		if current == (types.Hash{}) {
			evm.StateDB.SubRefund(NetSstoreClearRefund)
		} else if value == (types.Hash{}) {
			evm.StateDB.AddRefund(NetSstoreClearRefund)
		}
	}
	if original == value {
		if original == (types.Hash{}) {
			evm.StateDB.AddRefund(NetSstoreResetClearRefund)
		} else {
			evm.StateDB.AddRefund(NetSstoreResetRefund)
		}
	}
	return NetSstoreDirtyGas, nil
}

func gasSStoreEIP2200(evm *EVM, contract *Contract, stack *Stack, mem *Memory, memorySize uint64) (uint64, error) {
	if contract.Gas <= SstoreSentryGasEIP2200 {
		return 0, errors.New("not enough gas for reentrancy sentry")
	}
	var (
		y, x    = stack.Back(1), stack.Back(0)
		current = evm.StateDB.GetState(contract.Address(), x.Bytes32())
	)
	value := types.Hash(y.Bytes32())

	if current == value {
		return SloadGasEIP2200, nil
	}
	original := evm.StateDB.GetCommittedState(contract.Address(), x.Bytes32())
	if original == current {
		if original == (types.Hash{}) {
			return SstoreSetGasEIP2200, nil
		}
		if value == (types.Hash{}) {
			evm.StateDB.AddRefund(SstoreClearsScheduleRefundEIP2200)
		}
		return SstoreResetGasEIP2200, nil
	}
	if original != (types.Hash{}) {
		if current == (types.Hash{}) {
			evm.StateDB.SubRefund(SstoreClearsScheduleRefundEIP2200)
		} else if value == (types.Hash{}) {
			evm.StateDB.AddRefund(SstoreClearsScheduleRefundEIP2200)
		}
	}
	if original == value {
		if original == (types.Hash{}) {
			evm.StateDB.AddRefund(SstoreSetGasEIP2200 - SloadGasEIP2200)
		} else {
			evm.StateDB.AddRefund(SstoreResetGasEIP2200 - SloadGasEIP2200)
		}
	}
	return SloadGasEIP2200, nil
}

func makeGasLog(n uint64) gasFunc {
	return func(evm *EVM, contract *Contract, stack *Stack, mem *Memory, memorySize uint64) (uint64, error) {
		requestedSize, overflow := stack.Back(1).Uint64WithOverflow()
		if overflow {
			return 0, ErrGasUintOverflow
		}
		gas, err := memoryGasCost(mem, memorySize)
		if err != nil {
			return 0, err
		}
		if gas, overflow = SafeAdd(gas, LogGas); overflow {
			return 0, ErrGasUintOverflow
		}
		if gas, overflow = SafeAdd(gas, n*LogTopicGas); overflow {
			return 0, ErrGasUintOverflow
		}
		var memorySizeGas uint64
		if memorySizeGas, overflow = SafeMul(requestedSize, LogDataGas); overflow {
			return 0, ErrGasUintOverflow
		}
		if gas, overflow = SafeAdd(gas, memorySizeGas); overflow {
			return 0, ErrGasUintOverflow
		}
		return gas, nil
	}
}

func gasKeccak256(evm *EVM, contract *Contract, stack *Stack, mem *Memory, memorySize uint64) (uint64, error) {
	gas, err := memoryGasCost(mem, memorySize)
	if err != nil {
		return 0, err
	}
	wordGas, overflow := stack.Back(1).Uint64WithOverflow()
	if overflow {
		return 0, ErrGasUintOverflow
	}
	if wordGas, overflow = SafeMul(toWordSize(wordGas), Keccak256WordGas); overflow {
		return 0, ErrGasUintOverflow
	}
	if gas, overflow = SafeAdd(gas, wordGas); overflow {
		return 0, ErrGasUintOverflow
	}
	return gas, nil
}

func pureMemoryGascost(evm *EVM, contract *Contract, stack *Stack, mem *Memory, memorySize uint64) (uint64, error) {
	return memoryGasCost(mem, memorySize)
}

var (
	gasReturn  = pureMemoryGascost
	gasRevert  = pureMemoryGascost
	gasMLoad   = pureMemoryGascost
	gasMStore8 = pureMemoryGascost
	gasMStore  = pureMemoryGascost
	gasCreate  = pureMemoryGascost
)

func gasCreate2(evm *EVM, contract *Contract, stack *Stack, mem *Memory, memorySize uint64) (uint64, error) {
	gas, err := memoryGasCost(mem, memorySize)
	if err != nil {
		return 0, err
	}
	wordGas, overflow := stack.Back(2).Uint64WithOverflow()
	if overflow {
		return 0, ErrGasUintOverflow
	}
	if wordGas, overflow = SafeMul(toWordSize(wordGas), Keccak256WordGas); overflow {
		return 0, ErrGasUintOverflow
	}
	if gas, overflow = SafeAdd(gas, wordGas); overflow {
		return 0, ErrGasUintOverflow
	}
	return gas, nil
}

func gasCreateEip3860(evm *EVM, contract *Contract, stack *Stack, mem *Memory, memorySize uint64) (uint64, error) {
	gas, err := memoryGasCost(mem, memorySize)
	if err != nil {
		return 0, err
	}
	size, overflow := stack.Back(2).Uint64WithOverflow()
	if overflow {
		return 0, ErrGasUintOverflow
	}
	if size > uint64(MaxInitCodeSize) {
		return 0, fmt.Errorf("%w: size %d", ErrMaxInitCodeSizeExceeded, size)
	}
	moreGas := InitCodeWordGas * ((size + 31) / 32)
	if gas, overflow = SafeAdd(gas, moreGas); overflow {
		return 0, ErrGasUintOverflow
	}
	return gas, nil
}

func gasCreate2Eip3860(evm *EVM, contract *Contract, stack *Stack, mem *Memory, memorySize uint64) (uint64, error) {
	gas, err := memoryGasCost(mem, memorySize)
	if err != nil {
		return 0, err
	}
	size, overflow := stack.Back(2).Uint64WithOverflow()
	if overflow {
		return 0, ErrGasUintOverflow
	}
	if size > uint64(MaxInitCodeSize) {
		return 0, fmt.Errorf("%w: size %d", ErrMaxInitCodeSizeExceeded, size)
	}
	moreGas := (InitCodeWordGas + Keccak256WordGas) * ((size + 31) / 32)
	if gas, overflow = SafeAdd(gas, moreGas); overflow {
		return 0, ErrGasUintOverflow
	}
	return gas, nil
}

func gasExpFrontier(evm *EVM, contract *Contract, stack *Stack, mem *Memory, memorySize uint64) (uint64, error) {
	expByteLen := uint64((stack.data[stack.len()-2].BitLen() + 7) / 8)
	var (
		gas      = expByteLen * ExpByteFrontier
		overflow bool
	)
	if gas, overflow = SafeAdd(gas, ExpGas); overflow {
		return 0, ErrGasUintOverflow
	}
	return gas, nil
}

func gasExpEIP158(evm *EVM, contract *Contract, stack *Stack, mem *Memory, memorySize uint64) (uint64, error) {
	expByteLen := uint64((stack.data[stack.len()-2].BitLen() + 7) / 8)
	var (
		gas      = expByteLen * ExpByteEIP158
		overflow bool
	)
	if gas, overflow = SafeAdd(gas, ExpGas); overflow {
		return 0, ErrGasUintOverflow
	}
	return gas, nil
}

func gasCall(evm *EVM, contract *Contract, stack *Stack, mem *Memory, memorySize uint64) (uint64, error) {
	var (
		gas            uint64
		transfersValue = !stack.Back(2).IsZero()
		address        = types.Address(stack.Back(1).Bytes20())
	)
	if evm.chainRules.IsEIP158 {
		if transfersValue && evm.StateDB.Empty(address) {
			gas += CallNewAccountGas
		}
	} else if !evm.StateDB.Exist(address) {
		gas += CallNewAccountGas
	}
	if transfersValue {
		gas += CallValueTransferGas
	}
	memoryGas, err := memoryGasCost(mem, memorySize)
	if err != nil {
		return 0, err
	}
	var overflow bool
	if gas, overflow = SafeAdd(gas, memoryGas); overflow {
		return 0, ErrGasUintOverflow
	}
	evm.callGasTemp, err = callGas(evm.chainRules.IsEIP150, contract.Gas, gas, stack.Back(0))
	if err != nil {
		return 0, err
	}
	if gas, overflow = SafeAdd(gas, evm.callGasTemp); overflow {
		return 0, ErrGasUintOverflow
	}
	return gas, nil
}

func gasCallCode(evm *EVM, contract *Contract, stack *Stack, mem *Memory, memorySize uint64) (uint64, error) {
	memoryGas, err := memoryGasCost(mem, memorySize)
	if err != nil {
		return 0, err
	}
	var (
		gas      uint64
		overflow bool
	)
	if stack.Back(2).Sign() != 0 {
		gas += CallValueTransferGas
	}
	if gas, overflow = SafeAdd(gas, memoryGas); overflow {
		return 0, ErrGasUintOverflow
	}
	evm.callGasTemp, err = callGas(evm.chainRules.IsEIP150, contract.Gas, gas, stack.Back(0))
	if err != nil {
		return 0, err
	}
	if gas, overflow = SafeAdd(gas, evm.callGasTemp); overflow {
		return 0, ErrGasUintOverflow
	}
	return gas, nil
}

func gasDelegateCall(evm *EVM, contract *Contract, stack *Stack, mem *Memory, memorySize uint64) (uint64, error) {
	gas, err := memoryGasCost(mem, memorySize)
	if err != nil {
		return 0, err
	}
	evm.callGasTemp, err = callGas(evm.chainRules.IsEIP150, contract.Gas, gas, stack.Back(0))
	if err != nil {
		return 0, err
	}
	var overflow bool
	if gas, overflow = SafeAdd(gas, evm.callGasTemp); overflow {
		return 0, ErrGasUintOverflow
	}
	return gas, nil
}

func gasStaticCall(evm *EVM, contract *Contract, stack *Stack, mem *Memory, memorySize uint64) (uint64, error) {
	gas, err := memoryGasCost(mem, memorySize)
	if err != nil {
		return 0, err
	}
	evm.callGasTemp, err = callGas(evm.chainRules.IsEIP150, contract.Gas, gas, stack.Back(0))
	if err != nil {
		return 0, err
	}
	var overflow bool
	if gas, overflow = SafeAdd(gas, evm.callGasTemp); overflow {
		return 0, ErrGasUintOverflow
	}
	return gas, nil
}

func gasSelfdestruct(evm *EVM, contract *Contract, stack *Stack, mem *Memory, memorySize uint64) (uint64, error) {
	var gas uint64
	if evm.chainRules.IsEIP150 {
		gas = SelfdestructGasEIP150
		var address = types.Address(stack.Back(0).Bytes20())

		if evm.chainRules.IsEIP158 {
			if evm.StateDB.Empty(address) && evm.StateDB.GetBalance(contract.Address()).Sign() != 0 {
				gas += CreateBySelfdestructGas
			}
		} else if !evm.StateDB.Exist(address) {
			gas += CreateBySelfdestructGas
		}
	}

	if !evm.StateDB.HasSelfDestructed(contract.Address()) {
		evm.StateDB.AddRefund(SelfdestructRefundGas)
	}
	return gas, nil
}
