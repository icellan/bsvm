package contracts

import (
	"testing"
)

// These tests exercise finding F08 on the Mode 2 generic Groth16 rollup
// contract: every BN254 scalar public input (g16Input0..g16Input4) must
// live in the canonical range [0, r) where r is the BN254 scalar field
// order. The covenant enforces the upper bound via
//
//	runar.Assert(g16Input_i < c.Bn254ScalarOrder)
//
// on both the AdvanceState path and every Upgrade* variant. The lower
// bound is not asserted in Script because Bitcoin Script numbers are
// sign-magnitude; a negative value would fail the MSM downstream anyway
// (and every SP1-produced scalar is non-negative by construction).
//
// Attack class: "differential-oracle hazard via unreduced scalar". EC
// scalar multiplication is periodic mod r, so a prover could submit a
// scalar s >= r that still pair-verifies on-chain, but SP1's Solidity
// and in-circuit reference verifiers ABI-reject such scalars before
// pairing. Without the range check the on-chain verifier would quietly
// diverge from the reference verifier during fuzzing / conformance
// testing — a correctness hazard, not a soundness break, but worth
// closing.
//
// The Go-mock harness sets testBn254ScalarOrder = 1<<40 so int64
// arithmetic stays well-defined. The real chain uses the full 254-bit
// r baked in by compile.go::buildGroth16ConstructorArgs.

// TestGroth16Rollup_F08_AcceptsInRangeInputs is the positive control.
// buildGroth16Args leaves every g16Input_i at zero, which trivially
// satisfies each < Bn254ScalarOrder assertion, and the advance must
// succeed.
func TestGroth16Rollup_F08_AcceptsInRangeInputs(t *testing.T) {
	c := newGroth16Rollup(zeros32(), 0, 0)
	args := buildGroth16Args(zeros32(), 1)
	callGroth16Advance(c, args)
	if c.BlockNumber != 1 {
		t.Fatalf("expected block 1 after advance, got %d", c.BlockNumber)
	}
}

// TestGroth16Rollup_F08_RejectsInput0AtOrder pins that a g16Input0
// exactly equal to r (the first value out of the [0, r) range) is
// rejected. This is the canonical boundary attack — a prover trying to
// submit an unreduced scalar whose low-order bits pair-verify.
func TestGroth16Rollup_F08_RejectsInput0AtOrder(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected assertion failure when g16Input0 == Bn254ScalarOrder")
		}
	}()
	c := newGroth16Rollup(zeros32(), 0, 0)
	args := buildGroth16Args(zeros32(), 1)
	args.g16Input0 = testBn254ScalarOrder
	callGroth16Advance(c, args)
}

// TestGroth16Rollup_F08_RejectsInput1AtOrder pins the same boundary for
// g16Input1 (SP1's committedValuesDigest slot).
func TestGroth16Rollup_F08_RejectsInput1AtOrder(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected assertion failure when g16Input1 == Bn254ScalarOrder")
		}
	}()
	c := newGroth16Rollup(zeros32(), 0, 0)
	args := buildGroth16Args(zeros32(), 1)
	args.g16Input1 = testBn254ScalarOrder
	callGroth16Advance(c, args)
}

// TestGroth16Rollup_F08_RejectsInput2AtOrder pins the same boundary for
// g16Input2 (SP1 exitCode slot).
func TestGroth16Rollup_F08_RejectsInput2AtOrder(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected assertion failure when g16Input2 == Bn254ScalarOrder")
		}
	}()
	c := newGroth16Rollup(zeros32(), 0, 0)
	args := buildGroth16Args(zeros32(), 1)
	args.g16Input2 = testBn254ScalarOrder
	callGroth16Advance(c, args)
}

// TestGroth16Rollup_F08_RejectsInput3AtOrder pins the same boundary for
// g16Input3 (SP1 proofNonce slot — otherwise unconstrained but still
// range-checked).
func TestGroth16Rollup_F08_RejectsInput3AtOrder(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected assertion failure when g16Input3 == Bn254ScalarOrder")
		}
	}()
	c := newGroth16Rollup(zeros32(), 0, 0)
	args := buildGroth16Args(zeros32(), 1)
	args.g16Input3 = testBn254ScalarOrder
	callGroth16Advance(c, args)
}

// TestGroth16Rollup_F08_RejectsInput4AtOrder pins the same boundary for
// g16Input4 (SP1 vkRoot slot).
func TestGroth16Rollup_F08_RejectsInput4AtOrder(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected assertion failure when g16Input4 == Bn254ScalarOrder")
		}
	}()
	c := newGroth16Rollup(zeros32(), 0, 0)
	args := buildGroth16Args(zeros32(), 1)
	args.g16Input4 = testBn254ScalarOrder
	callGroth16Advance(c, args)
}
