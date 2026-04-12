// Copyright 2020 The go-ethereum Authors
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

	"github.com/icellan/bsvm/pkg/types"
	"github.com/icellan/bsvm/pkg/vm/tracing"
)

func makeGasSStoreFunc(clearingRefund uint64) gasFunc {
	return func(evm *EVM, contract *Contract, stack *Stack, mem *Memory, memorySize uint64) (uint64, error) {
		// If we fail the minimum gas availability invariant, fail (0)
		if contract.Gas <= SstoreSentryGasEIP2200 {
			return 0, errors.New("not enough gas for reentrancy sentry")
		}
		// Gas sentry honoured, do the actual gas calculation based on the stored value
		var (
			y, x    = stack.Back(1), stack.peek()
			slot    = types.Hash(x.Bytes32())
			current = evm.StateDB.GetState(contract.Address(), slot)
			cost    = uint64(0)
		)
		// Check slot presence in the access list
		if _, slotPresent := evm.StateDB.SlotInAccessList(contract.Address(), slot); !slotPresent {
			cost = ColdSloadCostEIP2929
			// If the caller cannot afford the cost, this change will be rolled back
			evm.StateDB.AddSlotToAccessList(contract.Address(), slot)
		}
		value := types.Hash(y.Bytes32())

		if current == value { // noop (1)
			return cost + WarmStorageReadCostEIP2929, nil // SLOAD_GAS
		}
		original := evm.StateDB.GetCommittedState(contract.Address(), x.Bytes32())
		if original == current {
			if original == (types.Hash{}) { // create slot (2.1.1)
				return cost + SstoreSetGasEIP2200, nil
			}
			if value == (types.Hash{}) { // delete slot (2.1.2b)
				evm.StateDB.AddRefund(clearingRefund)
			}
			return cost + (SstoreResetGasEIP2200 - ColdSloadCostEIP2929), nil // write existing slot (2.1.2)
		}
		if original != (types.Hash{}) {
			if current == (types.Hash{}) { // recreate slot (2.2.1.1)
				evm.StateDB.SubRefund(clearingRefund)
			} else if value == (types.Hash{}) { // delete slot (2.2.1.2)
				evm.StateDB.AddRefund(clearingRefund)
			}
		}
		if original == value {
			if original == (types.Hash{}) { // reset to original inexistent slot (2.2.2.1)
				evm.StateDB.AddRefund(SstoreSetGasEIP2200 - WarmStorageReadCostEIP2929)
			} else { // reset to original existing slot (2.2.2.2)
				evm.StateDB.AddRefund((SstoreResetGasEIP2200 - ColdSloadCostEIP2929) - WarmStorageReadCostEIP2929)
			}
		}
		return cost + WarmStorageReadCostEIP2929, nil // dirty update (2.2)
	}
}

// gasSLoadEIP2929 calculates dynamic gas for SLOAD according to EIP-2929
func gasSLoadEIP2929(evm *EVM, contract *Contract, stack *Stack, mem *Memory, memorySize uint64) (uint64, error) {
	loc := stack.peek()
	slot := types.Hash(loc.Bytes32())
	// Check slot presence in the access list
	if _, slotPresent := evm.StateDB.SlotInAccessList(contract.Address(), slot); !slotPresent {
		evm.StateDB.AddSlotToAccessList(contract.Address(), slot)
		return ColdSloadCostEIP2929, nil
	}
	return WarmStorageReadCostEIP2929, nil
}

// gasExtCodeCopyEIP2929 implements extcodecopy according to EIP-2929
func gasExtCodeCopyEIP2929(evm *EVM, contract *Contract, stack *Stack, mem *Memory, memorySize uint64) (uint64, error) {
	gas, err := gasExtCodeCopy(evm, contract, stack, mem, memorySize)
	if err != nil {
		return 0, err
	}
	addr := types.Address(stack.peek().Bytes20())
	if !evm.StateDB.AddressInAccessList(addr) {
		evm.StateDB.AddAddressToAccessList(addr)
		var overflow bool
		if gas, overflow = SafeAdd(gas, ColdAccountAccessCostEIP2929-WarmStorageReadCostEIP2929); overflow {
			return 0, ErrGasUintOverflow
		}
		return gas, nil
	}
	return gas, nil
}

// gasEip2929AccountCheck checks whether the first stack item (as address) is present in the access list.
func gasEip2929AccountCheck(evm *EVM, contract *Contract, stack *Stack, mem *Memory, memorySize uint64) (uint64, error) {
	addr := types.Address(stack.peek().Bytes20())
	if !evm.StateDB.AddressInAccessList(addr) {
		evm.StateDB.AddAddressToAccessList(addr)
		return ColdAccountAccessCostEIP2929 - WarmStorageReadCostEIP2929, nil
	}
	return 0, nil
}

func makeCallVariantGasCallEIP2929(oldCalculator gasFunc, addressPosition int) gasFunc {
	return func(evm *EVM, contract *Contract, stack *Stack, mem *Memory, memorySize uint64) (uint64, error) {
		addr := types.Address(stack.Back(addressPosition).Bytes20())
		warmAccess := evm.StateDB.AddressInAccessList(addr)
		coldCost := ColdAccountAccessCostEIP2929 - WarmStorageReadCostEIP2929
		if !warmAccess {
			evm.StateDB.AddAddressToAccessList(addr)
			if !contract.UseGas(coldCost, evm.Config.Tracer, tracing.GasChangeCallStorageColdAccess) {
				return 0, ErrOutOfGas
			}
		}
		gas, err := oldCalculator(evm, contract, stack, mem, memorySize)
		if warmAccess || err != nil {
			return gas, err
		}
		contract.Gas += coldCost

		var overflow bool
		if gas, overflow = SafeAdd(gas, coldCost); overflow {
			return 0, ErrGasUintOverflow
		}
		return gas, nil
	}
}

var (
	gasCallEIP2929         = makeCallVariantGasCallEIP2929(gasCall, 1)
	gasDelegateCallEIP2929 = makeCallVariantGasCallEIP2929(gasDelegateCall, 1)
	gasStaticCallEIP2929   = makeCallVariantGasCallEIP2929(gasStaticCall, 1)
	gasCallCodeEIP2929     = makeCallVariantGasCallEIP2929(gasCallCode, 1)
	gasSelfdestructEIP2929 = makeSelfdestructGasFn(true)
	gasSelfdestructEIP3529 = makeSelfdestructGasFn(false)

	gasSStoreEIP2929 = makeGasSStoreFunc(SstoreClearsScheduleRefundEIP2200)
	gasSStoreEIP3529 = makeGasSStoreFunc(SstoreClearsScheduleRefundEIP3529)
)

func makeSelfdestructGasFn(refundsEnabled bool) gasFunc {
	gasFunc := func(evm *EVM, contract *Contract, stack *Stack, mem *Memory, memorySize uint64) (uint64, error) {
		var (
			gas     uint64
			address = types.Address(stack.peek().Bytes20())
		)
		if !evm.StateDB.AddressInAccessList(address) {
			evm.StateDB.AddAddressToAccessList(address)
			gas = ColdAccountAccessCostEIP2929
		}
		if evm.StateDB.Empty(address) && evm.StateDB.GetBalance(contract.Address()).Sign() != 0 {
			gas += CreateBySelfdestructGas
		}
		if refundsEnabled && !evm.StateDB.HasSelfDestructed(contract.Address()) {
			evm.StateDB.AddRefund(SelfdestructRefundGas)
		}
		return gas, nil
	}
	return gasFunc
}
