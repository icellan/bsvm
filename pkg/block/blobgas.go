// Copyright 2024 The go-ethereum Authors
// Adapted from go-ethereum consensus/misc/eip4844 for the BSVM project.

package block

import (
	"math/big"

	"github.com/icellan/bsvm/pkg/vm"
)

// EIP-4844 blob-gas schedule constants. These are the canonical Cancun values
// that geth and revm both use; the dual-EVM equivalence harness depends on
// them being byte-identical between the Go side (this file) and the SP1
// guest's revm.
const (
	// MinBlobGasPrice is the minimum blob_gas_price (= 1 wei). Used as the
	// `factor` argument to fake_exponential. Per EIP-4844:
	//
	//   blob_gas_price = fake_exponential(MIN_BLOB_GASPRICE, excess_blob_gas,
	//                                     BLOB_BASE_FEE_UPDATE_FRACTION)
	//
	// At excess_blob_gas == 0 the formula collapses to MinBlobGasPrice itself.
	MinBlobGasPrice uint64 = 1

	// BlobBaseFeeUpdateFraction controls how quickly blob_gas_price doubles
	// as excess_blob_gas grows. Per EIP-4844: 3338477. Each
	// BLOB_BASE_FEE_UPDATE_FRACTION units of excess gas roughly doubles the
	// blob_gas_price.
	BlobBaseFeeUpdateFraction uint64 = 3338477

	// TargetBlobGasPerBlock is the steady-state blob-gas budget per block
	// (= 3 blobs * BlobTxBlobGasPerBlob = 393216). Blocks that exceed it
	// increase ExcessBlobGas; blocks that fall short decrease it (saturating
	// at zero).
	TargetBlobGasPerBlock uint64 = 3 * 131072
)

// CalcExcessBlobGas computes the ExcessBlobGas for the block immediately
// after one with `parentExcessBlobGas` excess and `parentBlobGasUsed`
// blob-gas used. Per EIP-4844:
//
//	excess_blob_gas = max(parent.excess_blob_gas + parent.blob_gas_used
//	                      - TARGET_BLOB_GAS_PER_BLOCK, 0)
//
// The subtraction is saturating: under-target blocks drive ExcessBlobGas
// back toward zero rather than going negative.
func CalcExcessBlobGas(parentExcessBlobGas, parentBlobGasUsed uint64) uint64 {
	consumed := parentExcessBlobGas + parentBlobGasUsed
	if consumed < TargetBlobGasPerBlock {
		return 0
	}
	return consumed - TargetBlobGasPerBlock
}

// CalcBlobGasPrice returns the blob_gas_price for a block with the given
// `excessBlobGas`. Per EIP-4844:
//
//	blob_gas_price = fake_exponential(MIN_BLOB_GASPRICE, excess_blob_gas,
//	                                  BLOB_BASE_FEE_UPDATE_FRACTION)
//
// At excess_blob_gas == 0 the price is MinBlobGasPrice (= 1 wei). The
// returned *big.Int is always non-nil and >= 1.
func CalcBlobGasPrice(excessBlobGas uint64) *big.Int {
	return fakeExponential(
		new(big.Int).SetUint64(MinBlobGasPrice),
		new(big.Int).SetUint64(excessBlobGas),
		new(big.Int).SetUint64(BlobBaseFeeUpdateFraction),
	)
}

// fakeExponential approximates `factor * e ** (numerator / denominator)`
// using a Taylor series, per EIP-4844. The reference algorithm:
//
//	def fake_exponential(factor, numerator, denominator):
//	    i = 1
//	    output = 0
//	    numerator_accum = factor * denominator
//	    while numerator_accum > 0:
//	        output += numerator_accum
//	        numerator_accum = (numerator_accum * numerator) //
//	                          (denominator * i)
//	        i += 1
//	    return output // denominator
//
// The loop terminates because numerator_accum monotonically falls to zero
// once `i` exceeds `numerator/denominator` (the Taylor terms shrink). The
// arithmetic uses arbitrary-precision big.Int to match revm's i256 math —
// the equivalence harness compares the exact result.
//
// All inputs MUST be non-nil. denominator MUST be > 0; a zero denominator
// would divide by zero on the very first loop iteration. The returned
// *big.Int is a fresh allocation owned by the caller.
func fakeExponential(factor, numerator, denominator *big.Int) *big.Int {
	output := new(big.Int)
	numeratorAccum := new(big.Int).Mul(factor, denominator)
	one := big.NewInt(1)
	for i := big.NewInt(1); numeratorAccum.Sign() > 0; i.Add(i, one) {
		output.Add(output, numeratorAccum)
		// numerator_accum = (numerator_accum * numerator) // (denominator * i)
		numeratorAccum.Mul(numeratorAccum, numerator)
		div := new(big.Int).Mul(denominator, i)
		numeratorAccum.Quo(numeratorAccum, div)
	}
	return output.Quo(output, denominator)
}

// BlobGasUsedForTx returns the blob-gas charge for a single transaction:
//
//	blob_gas = len(BlobVersionedHashes) * BlobTxBlobGasPerBlob
//
// For non-blob transactions this is zero. Used by the block builder to
// accumulate header.BlobGasUsed across the batch.
func BlobGasUsedForTx(numBlobs int) uint64 {
	if numBlobs <= 0 {
		return 0
	}
	return uint64(numBlobs) * vm.BlobTxBlobGasPerBlob
}
