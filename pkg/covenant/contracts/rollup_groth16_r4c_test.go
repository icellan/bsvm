package contracts

import (
	"math/big"
	"testing"

	runar "github.com/icellan/runar/packages/runar-go"
)

// R4c fidelity tests — pin that the Mode 2 contract's F01 / F08 / reducer
// assertions run over the real 254-bit BN254 scalar field under the Go
// mock, not truncated to int64.
//
// Before R4c:
//   - Bn254ScalarOrder / SP1ProgramVkHashScalar / Bn254ScalarMask were
//     runar.Bigint (int64) fields. A scalar that collided with the pinned
//     value in the low 64 bits but differed in the high bits would have
//     been accepted as equal under the Go mock, even though the compiled
//     Script correctly rejects it.
//   - `a < b` on runar.Bigint was int64 comparison, so setting the real
//     254-bit BN254 scalar order on the field meant nothing: every
//     candidate scalar would be int64-truncated before comparison.
//
// After R4c:
//   - The scalar-domain fields are runar.BigintBig (*big.Int).
//   - Comparisons use runar.BigintBigLess / runar.BigintBigEqual which
//     delegate to big.Int.Cmp and always compare the full integer value.
//   - The Go-mock matches the compiled-Script semantics on F01 and F08.
//
// These tests force the contract into a wide domain (real r, real
// 253-bit pinned scalar) and exercise the adversarial patterns that
// distinguish BigintBig semantics from int64 semantics.

// realBn254ScalarOrder is r = 21888242871839275222246405745257275088548364400416034343698204186575808495617,
// the actual BN254 scalar field order. Under the pre-R4c int64 harness,
// this value truncates to its low 64 bits (0x30644e72e131a029) — a
// meaningless number.
func realBn254ScalarOrder() *big.Int {
	r, _ := new(big.Int).SetString(
		"21888242871839275222246405745257275088548364400416034343698204186575808495617",
		10,
	)
	return r
}

// newGroth16RollupWide returns a Mode 2 contract configured with the real
// BN254 scalar order and a specified wide pinned vkey scalar. All other
// readonly fields reuse the default newGroth16Rollup values (generator-
// seeded IC points, single-key governance).
func newGroth16RollupWide(
	stateRoot string,
	pinnedVkeyScalar *big.Int,
	mask *big.Int,
) *Groth16RollupContract {
	c := newGroth16Rollup(stateRoot, 0, 0)
	c.Bn254ScalarOrder = realBn254ScalarOrder()
	c.SP1ProgramVkHashScalar = new(big.Int).Set(pinnedVkeyScalar)
	c.Bn254ScalarMask = new(big.Int).Set(mask)
	return c
}

// buildGroth16ArgsWide mirrors buildGroth16Args but computes g16Input1
// against the caller-supplied mask so the reducer binding holds under
// the real 2^253 modulus.
func buildGroth16ArgsWide(preStateRoot string, newBlockNumber int64, mask *big.Int) groth16AdvArgs {
	args := buildGroth16Args(preStateRoot, newBlockNumber)
	// Recompute g16Input1 against the supplied mask.
	pv := runar.ByteString(args.publicValues)
	hashBE := runar.Sha256(pv)
	hashLE := runar.ReverseBytes(hashBE)
	padded := runar.Cat(hashLE, runar.Num2Bin(0, 1))
	args.g16Input1 = runar.BigintBigMod(runar.Bin2NumBig(padded), mask)
	return args
}

// TestGroth16Rollup_R4c_AcceptsPinnedWide253BitVkeyScalar pins that a
// ~253-bit vkey scalar (the real output of SP1's sha256-then-reduce
// pipeline) survives the F01 vkey binding under the Go-mock. Under the
// pre-R4c int64 field, this value would have been silently truncated.
func TestGroth16Rollup_R4c_AcceptsPinnedWide253BitVkeyScalar(t *testing.T) {
	// A representative ~253-bit value: 2^252 + 0xDEADBEEF. Low 64 bits are
	// 0x00000000DEADBEEF, which cannot be mistaken for the high bits.
	wide := new(big.Int).Lsh(big.NewInt(1), 252)
	wide.Add(wide, big.NewInt(0xDEADBEEF))

	mask := new(big.Int).Lsh(big.NewInt(1), 253) // 2^253, real SP1 mask
	c := newGroth16RollupWide(zeros32(), wide, mask)

	args := buildGroth16ArgsWide(zeros32(), 1, mask)
	args.g16Input0 = new(big.Int).Set(wide)

	callGroth16Advance(c, args)

	if c.BlockNumber != 1 {
		t.Fatalf("expected block 1 after wide vkey-scalar advance, got %d", c.BlockNumber)
	}
}

// TestGroth16Rollup_R4c_RejectsHighBitCollisionOnVkeyScalar pins that a
// candidate g16Input0 matching the pinned scalar in the low 64 bits but
// differing in the high bits is REJECTED. This attack was indistinguishable
// under the pre-R4c int64 mock: 254-bit values truncate to int64, so any
// two scalars sharing the low 64 bits were "equal" to the Go comparator.
// Under BigintBigEqual the full 254-bit value is compared.
func TestGroth16Rollup_R4c_RejectsHighBitCollisionOnVkeyScalar(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected assertion failure on high-bit-collision g16Input0")
		}
	}()
	pinned := new(big.Int).Lsh(big.NewInt(1), 252)
	pinned.Add(pinned, big.NewInt(0xC0FFEE))

	// colliding = pinned XOR (1 << 200). Same low 64 bits, differs at bit
	// 200 — invisible to int64 compare, caught by big.Int.Cmp.
	colliding := new(big.Int).Xor(pinned, new(big.Int).Lsh(big.NewInt(1), 200))

	mask := new(big.Int).Lsh(big.NewInt(1), 253)
	c := newGroth16RollupWide(zeros32(), pinned, mask)

	args := buildGroth16ArgsWide(zeros32(), 1, mask)
	args.g16Input0 = colliding

	callGroth16Advance(c, args)
}

// TestGroth16Rollup_R4c_F08_RejectsExactlyR pins that a g16Input_i
// exactly equal to the real 254-bit r fails the F08 range check. Prior
// to R4c this test could only exercise the int64 stand-in (1<<40).
func TestGroth16Rollup_R4c_F08_RejectsExactlyR(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected assertion failure when g16Input0 == real BN254 r")
		}
	}()
	pinned := big.NewInt(0)
	mask := new(big.Int).Lsh(big.NewInt(1), 253)
	c := newGroth16RollupWide(zeros32(), pinned, mask)

	args := buildGroth16ArgsWide(zeros32(), 1, mask)
	args.g16Input0 = realBn254ScalarOrder()

	callGroth16Advance(c, args)
}

// TestGroth16Rollup_R4c_F08_AcceptsRMinusOne pins the upper boundary: the
// largest valid scalar is r - 1 and it must be accepted by the range
// check. This requires wide comparison — under int64 the truncated value
// of r - 1 would compare nonsensically against the truncated r.
func TestGroth16Rollup_R4c_F08_AcceptsRMinusOne(t *testing.T) {
	r := realBn254ScalarOrder()
	rMinus1 := new(big.Int).Sub(r, big.NewInt(1))

	// Pin the vkey scalar to rMinus1 so F01 holds against the same value
	// we'll inject for g16Input0. The reducer output needs to equal
	// g16Input1, which we recompute below against the mask.
	mask := new(big.Int).Lsh(big.NewInt(1), 253)
	c := newGroth16RollupWide(zeros32(), rMinus1, mask)

	args := buildGroth16ArgsWide(zeros32(), 1, mask)
	args.g16Input0 = new(big.Int).Set(rMinus1)
	// g16Input3 can be any value in [0, r); pick rMinus1 to exercise the
	// boundary on the unconstrained proofNonce slot too.
	args.g16Input3 = new(big.Int).Set(rMinus1)

	callGroth16Advance(c, args)

	if c.BlockNumber != 1 {
		t.Fatalf("expected block 1 after rMinus1 boundary advance, got %d", c.BlockNumber)
	}
}

// TestGroth16Rollup_R4c_ReducerMatchesWide253BitDomain pins that the
// Go-mock reducer (runar.BigintBigMod of Bin2NumBig(padded)) stays in
// the [0, 2^253) domain even when the input hash has the high bit set.
// Prior to R4c this path truncated at int64 and the reduction silently
// produced mock-only values that had no relationship to the real mask.
func TestGroth16Rollup_R4c_ReducerMatchesWide253BitDomain(t *testing.T) {
	// Craft a payload whose sha256 has bit 253 = 1 (i.e. overflows 2^253
	// before the mask). Any long incompressible string tends to; we just
	// pick a deterministic one and assert the reducer result is < 2^253.
	pv := runar.ByteString("r4c fidelity probe — high-bit sha256 coverage / 0xff" +
		"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff")
	mask := new(big.Int).Lsh(big.NewInt(1), 253)

	hashBE := runar.Sha256(pv)
	hashLE := runar.ReverseBytes(hashBE)
	padded := runar.Cat(hashLE, runar.Num2Bin(0, 1))
	reduced := runar.BigintBigMod(runar.Bin2NumBig(padded), mask)

	if reduced.Sign() < 0 {
		t.Fatalf("reducer produced negative value: %s", reduced.String())
	}
	if reduced.Cmp(mask) >= 0 {
		t.Fatalf("reducer output %s escaped the 2^253 mask", reduced.String())
	}

	// Sanity check: the raw Bin2NumBig output is >= 2^253 (i.e. the mask
	// actually fired). If it weren't, this test degenerates to a no-op.
	raw := runar.Bin2NumBig(padded)
	if raw.Cmp(mask) < 0 {
		t.Skipf("crafted payload didn't hit the 2^253 overflow (raw=%s); reducer fidelity unverified", raw.String())
	}
}
