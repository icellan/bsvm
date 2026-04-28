package block

import (
	"math/big"
	"testing"
)

// TestFakeExponentialKnownValues pins the EIP-4844 fake_exponential
// approximation against the reference values from the spec.
func TestFakeExponentialKnownValues(t *testing.T) {
	tests := []struct {
		name        string
		factor      uint64
		numerator   uint64
		denominator uint64
		want        uint64
	}{
		// e^0 == 1, so factor * 1 == factor.
		{name: "zero numerator returns factor", factor: 1, numerator: 0, denominator: BlobBaseFeeUpdateFraction, want: 1},
		{name: "zero numerator factor=11", factor: 11, numerator: 0, denominator: BlobBaseFeeUpdateFraction, want: 11},
		// numerator == denominator yields factor * e ≈ factor * 2.7182...
		// Truncated to integer: factor=1 → floor(e) == 2.
		{name: "numerator == denominator factor=1", factor: 1, numerator: BlobBaseFeeUpdateFraction, denominator: BlobBaseFeeUpdateFraction, want: 2},
		// factor=10 ⇒ 10 * e ≈ 27.18 → 27.
		{name: "numerator == denominator factor=10", factor: 10, numerator: BlobBaseFeeUpdateFraction, denominator: BlobBaseFeeUpdateFraction, want: 27},
		// 2 * denominator ⇒ factor * e^2 ≈ factor * 7.389. factor=1 → 7.
		{name: "2x denominator factor=1", factor: 1, numerator: 2 * BlobBaseFeeUpdateFraction, denominator: BlobBaseFeeUpdateFraction, want: 7},
		// 5 * denominator ⇒ e^5 ≈ 148.41 → 148.
		{name: "5x denominator factor=1", factor: 1, numerator: 5 * BlobBaseFeeUpdateFraction, denominator: BlobBaseFeeUpdateFraction, want: 148},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := fakeExponential(
				new(big.Int).SetUint64(tc.factor),
				new(big.Int).SetUint64(tc.numerator),
				new(big.Int).SetUint64(tc.denominator),
			)
			if !got.IsUint64() {
				t.Fatalf("fakeExponential overflowed uint64: %s", got.String())
			}
			if got.Uint64() != tc.want {
				t.Fatalf("fakeExponential(%d, %d, %d) = %d, want %d",
					tc.factor, tc.numerator, tc.denominator, got.Uint64(), tc.want)
			}
		})
	}
}

// TestCalcBlobGasPriceMonotone pins the spec-level invariant that
// blob_gas_price is monotonically non-decreasing in excess_blob_gas, and
// that the floor is exactly MinBlobGasPrice (= 1 wei).
func TestCalcBlobGasPriceMonotone(t *testing.T) {
	prev := CalcBlobGasPrice(0)
	if prev.Uint64() != MinBlobGasPrice {
		t.Fatalf("CalcBlobGasPrice(0) = %s, want %d", prev, MinBlobGasPrice)
	}
	excess := []uint64{
		131_072, 262_144, 393_216, 524_288, // 1..4 blobs over target
		BlobBaseFeeUpdateFraction,
		2 * BlobBaseFeeUpdateFraction,
		10 * BlobBaseFeeUpdateFraction,
	}
	for _, e := range excess {
		got := CalcBlobGasPrice(e)
		if got.Cmp(prev) < 0 {
			t.Fatalf("CalcBlobGasPrice not monotone: e=%d → %s < prev %s", e, got, prev)
		}
		prev = got
	}
	// Sanity: the price at numerator == denominator should equal
	// floor(MIN_BLOB_GASPRICE * e) = 2 (matches the unit test above).
	if got := CalcBlobGasPrice(BlobBaseFeeUpdateFraction); got.Uint64() != 2 {
		t.Fatalf("CalcBlobGasPrice(%d) = %s, want 2 (= floor(e))",
			BlobBaseFeeUpdateFraction, got)
	}
}

// TestCalcExcessBlobGasSaturation pins the EIP-4844 invariant that
// CalcExcessBlobGas saturates at zero rather than going negative when
// the parent block was under-target.
func TestCalcExcessBlobGasSaturation(t *testing.T) {
	tests := []struct {
		name       string
		parentExc  uint64
		parentUsed uint64
		want       uint64
	}{
		{name: "both zero", parentExc: 0, parentUsed: 0, want: 0},
		{name: "parent under target", parentExc: 0, parentUsed: 131072, want: 0},
		{name: "parent at target", parentExc: 0, parentUsed: TargetBlobGasPerBlock, want: 0},
		{name: "parent over target by 1 blob", parentExc: 0, parentUsed: TargetBlobGasPerBlock + 131072, want: 131072},
		// excess + used = 786432, target subtraction → 393216
		{name: "carry forward excess", parentExc: 393216, parentUsed: 393216, want: 393216},
		// pure carry forward (no usage)
		{name: "decay below target", parentExc: 100000, parentUsed: 0, want: 0},
		// excess shrinks toward zero as used falls below target
		{name: "decay with some use", parentExc: 200_000, parentUsed: 100_000, want: 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := CalcExcessBlobGas(tc.parentExc, tc.parentUsed); got != tc.want {
				t.Fatalf("CalcExcessBlobGas(%d, %d) = %d, want %d",
					tc.parentExc, tc.parentUsed, got, tc.want)
			}
		})
	}
}

// TestExcessBlobGasChain walks a 3-block trajectory and verifies the
// chained ExcessBlobGas + blob_gas_price values match the EIP-4844
// schedule end-to-end.
func TestExcessBlobGasChain(t *testing.T) {
	// Block 0 (genesis): excess=0, blob_gas_price = 1.
	excess0, used0 := uint64(0), uint64(0)
	if got := CalcBlobGasPrice(excess0); got.Uint64() != 1 {
		t.Fatalf("block0 price = %s, want 1", got)
	}
	// Block 1: parent excess=0, parent used=0 ⇒ excess=0; this block
	// fills 6 blobs (786432 = 2 * target).
	excess1 := CalcExcessBlobGas(excess0, used0)
	used1 := uint64(6 * 131072) // 786432
	if excess1 != 0 {
		t.Fatalf("block1 excess = %d, want 0", excess1)
	}
	if got := CalcBlobGasPrice(excess1); got.Uint64() != 1 {
		t.Fatalf("block1 price = %s, want 1", got)
	}
	// Block 2: parent excess=0, parent used=786432 ⇒ excess = 786432 - 393216 = 393216.
	excess2 := CalcExcessBlobGas(excess1, used1)
	if excess2 != 393216 {
		t.Fatalf("block2 excess = %d, want 393216", excess2)
	}
	// Price at excess=393216 — Taylor-series approximation should yield
	// roughly 1 (rounded down from ≈1.124). Pin the exact integer value.
	gotPrice2 := CalcBlobGasPrice(excess2).Uint64()
	if gotPrice2 != 1 {
		t.Fatalf("block2 price = %d, want 1 (floor of fake_exponential(1, 393216, 3338477) ≈ 1.124)",
			gotPrice2)
	}
	// Block 3: parent excess=393216, parent used=0 ⇒ excess saturates to 0.
	excess3 := CalcExcessBlobGas(excess2, 0)
	if excess3 != 0 {
		t.Fatalf("block3 excess = %d, want 0 (under-target should saturate to zero)", excess3)
	}
	if got := CalcBlobGasPrice(excess3); got.Uint64() != 1 {
		t.Fatalf("block3 price = %s, want 1", got)
	}
}

// TestBlobGasUsedForTx pins the per-transaction blob-gas accumulation.
func TestBlobGasUsedForTx(t *testing.T) {
	if BlobGasUsedForTx(0) != 0 {
		t.Fatalf("BlobGasUsedForTx(0) != 0")
	}
	if BlobGasUsedForTx(-1) != 0 {
		t.Fatalf("BlobGasUsedForTx(-1) != 0")
	}
	if BlobGasUsedForTx(1) != 131072 {
		t.Fatalf("BlobGasUsedForTx(1) = %d, want 131072", BlobGasUsedForTx(1))
	}
	if BlobGasUsedForTx(6) != 786432 {
		t.Fatalf("BlobGasUsedForTx(6) = %d, want 786432", BlobGasUsedForTx(6))
	}
}
