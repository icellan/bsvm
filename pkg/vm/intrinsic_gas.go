package vm

import (
	"fmt"

	"github.com/icellan/bsvm/pkg/types"
)

// IntrinsicGas computes the 'intrinsic gas' for a message with the given data.
func IntrinsicGas(data []byte, accessList types.AccessList, isContractCreation bool, isHomestead, isEIP2028, isEIP3860 bool) (uint64, error) {
	var gas uint64
	if isContractCreation && isHomestead {
		gas = TxGasContractCreation
	} else {
		gas = TxGas
	}
	// EIP-3860: reject initcode that exceeds the maximum size.
	if isContractCreation && isEIP3860 && len(data) > MaxInitCodeSize {
		return 0, fmt.Errorf("max initcode size exceeded: code size %d, limit %d", len(data), MaxInitCodeSize)
	}
	// Bump the required gas by the amount of transactional data
	if len(data) > 0 {
		// Zero and non-zero bytes are priced differently
		var nz uint64
		for _, byt := range data {
			if byt != 0 {
				nz++
			}
		}
		// Make sure we don't exceed uint64 for all data combinations
		nonZeroGas := TxDataNonZeroGasFrontier
		if isEIP2028 {
			nonZeroGas = TxDataNonZeroGasEIP2028
		}
		if (^uint64(0)-gas)/nonZeroGas < nz {
			return 0, ErrGasUintOverflow
		}
		gas += nz * nonZeroGas

		z := uint64(len(data)) - nz
		if (^uint64(0)-gas)/TxDataZeroGas < z {
			return 0, ErrGasUintOverflow
		}
		gas += z * TxDataZeroGas

		// EIP-3860: charge for initcode word gas
		if isContractCreation && isEIP3860 {
			lenWords := toWordSize(uint64(len(data)))
			if (^uint64(0)-gas)/InitCodeWordGas < lenWords {
				return 0, ErrGasUintOverflow
			}
			gas += lenWords * InitCodeWordGas
		}
	}
	if accessList != nil {
		gas += uint64(len(accessList)) * TxAccessListAddressGas
		gas += uint64(accessList.StorageKeys()) * TxAccessListStorageKeyGas
	}
	return gas, nil
}
