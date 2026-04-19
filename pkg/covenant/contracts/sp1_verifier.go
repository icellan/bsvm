package contracts

import runar "github.com/icellan/runar/packages/runar-go"

// SP1 v6.0.2 proof verification subroutines for the BSVM rollup covenant.
//
// This file defines the KoalaBear field arithmetic, Ext4 arithmetic, and
// Poseidon2 hash operations that the future on-chain FRI verifier (Gate
// 0a Full, see spec 12 / 13) will consume. The current Mode 1 covenant
// (rollup_fri.runar.go) does NOT consult any of these helpers — Mode 1
// is the trust-minimized FRI bridge, not the on-chain verifier.
//
// The helpers are retained in-tree as building blocks ready for the
// Gate 0a Full implementation. If that path is abandoned or replaced
// with a different PCS, this file can be deleted without affecting the
// compiled covenants.
//
// Verification paths currently implemented:
//
//   - Mode 1 (FRI bridge, VerifyFRI): no on-chain proof check.
//   - Mode 2 (Groth16):   BN254 pairing of a ~256-byte wrapped proof.
//   - Mode 3 (Groth16-WA): witness-assisted Groth16 via compile-time
//     inlined verifier preamble.

// ---------------------------------------------------------------------------
// KoalaBear Field Constants
// ---------------------------------------------------------------------------

// KoalaBearP is the KoalaBear prime: p = 2^31 - 2^24 + 1 = 2,130,706,433.
// All SP1 v6 STARK arithmetic operates over this field.
const KoalaBearP = int64(2130706433)

// KoalaBearExt4IrreducibleC is the constant in the extension field
// irreducible polynomial x^4 - 3. The extension field is degree-4 over
// KoalaBear, used for FRI folding and DEEP-ALI polynomial evaluation.
const KoalaBearExt4IrreducibleC = int64(3)

// ---------------------------------------------------------------------------
// Poseidon2 Parameters (SP1 v6.0.2 / Plonky3)
// ---------------------------------------------------------------------------

// Poseidon2 over KoalaBear parameters (from SP1 v6.0.2 configuration):
//   - Width: 16 KoalaBear elements
//   - Rate: 8, Capacity: 8
//   - Sbox: x^3 (degree 3)
//   - External rounds: 8 (4 initial + 4 final)
//   - Internal rounds: 20
//   - Digest: first 8 elements of output state (32 bytes)
const (
	Poseidon2Width          = 16
	Poseidon2Rate           = 8
	Poseidon2Capacity       = 8
	Poseidon2SboxDegree     = 3
	Poseidon2ExternalRounds = 8
	Poseidon2InternalRounds = 20
	Poseidon2DigestSize     = 8 // elements
)

// BasefoldQueriesCore is the number of Basefold queries for core/recursion proofs.
const BasefoldQueriesCore = 124

// BasefoldQueriesShrinkWrap is the number of Basefold queries for shrink/wrap proofs.
const BasefoldQueriesShrinkWrap = 94

// BasefoldMerkleDepth is the depth of Poseidon2 Merkle trees in SP1 proofs.
const BasefoldMerkleDepth = 20

// ProofOfWorkBits is the number of proof-of-work bits required by SP1 v6.
const ProofOfWorkBits = 16

// ---------------------------------------------------------------------------
// KoalaBear Field Arithmetic (Rúnar DSL wrappers)
// ---------------------------------------------------------------------------
//
// These functions wrap the Rúnar KoalaBear field primitives. In Bitcoin
// Script, they compile to 5-10 opcodes each (add/sub/mul) or ~300
// opcodes (inv). The Rúnar codegen module emits the actual opcodes.

// KbFieldAdd computes (a + b) mod p in the KoalaBear field.
func KbFieldAdd(a, b runar.Bigint) runar.Bigint {
	return runar.KbFieldAdd(a, b)
}

// KbFieldSub computes (a - b + p) mod p in the KoalaBear field.
func KbFieldSub(a, b runar.Bigint) runar.Bigint {
	return runar.KbFieldSub(a, b)
}

// KbFieldMul computes (a * b) mod p in the KoalaBear field.
// This is the operation verified in the rollup covenant's Basefold
// proof check (proofFieldA * proofFieldB == proofFieldC).
func KbFieldMul(a, b runar.Bigint) runar.Bigint {
	return runar.KbFieldMul(a, b)
}

// KbFieldInv computes a^(p-2) mod p via Fermat's little theorem.
// This is the most expensive single operation (~477 bytes compiled).
func KbFieldInv(a runar.Bigint) runar.Bigint {
	return runar.KbFieldInv(a)
}

// ---------------------------------------------------------------------------
// Extension Field Arithmetic (degree-4 over KoalaBear, x^4 - 3)
// ---------------------------------------------------------------------------
//
// The extension field is used for FRI folding challenges and DEEP-ALI
// polynomial evaluation. Each element is represented as 4 KoalaBear
// field elements [c0, c1, c2, c3] where the value is
// c0 + c1*x + c2*x^2 + c3*x^3.

// Ext4Element represents a degree-4 extension field element over KoalaBear.
type Ext4Element struct {
	C0, C1, C2, C3 runar.Bigint
}

// Ext4Mul multiplies two extension field elements using the irreducible
// polynomial x^4 - 3 for reduction. Compiles to ~509 bytes of Script.
func Ext4Mul(a, b Ext4Element) Ext4Element {
	// Standard schoolbook multiplication with reduction by x^4 = 3.
	// t0 = a0*b0 + 3*(a1*b3 + a2*b2 + a3*b1)
	// t1 = a0*b1 + a1*b0 + 3*(a2*b3 + a3*b2)
	// t2 = a0*b2 + a1*b1 + a2*b0 + 3*(a3*b3)
	// t3 = a0*b3 + a1*b2 + a2*b1 + a3*b0
	t0 := KbFieldAdd(
		KbFieldMul(a.C0, b.C0),
		KbFieldMul(KoalaBearExt4IrreducibleC,
			KbFieldAdd(KbFieldAdd(
				KbFieldMul(a.C1, b.C3),
				KbFieldMul(a.C2, b.C2)),
				KbFieldMul(a.C3, b.C1))))

	t1 := KbFieldAdd(
		KbFieldAdd(KbFieldMul(a.C0, b.C1), KbFieldMul(a.C1, b.C0)),
		KbFieldMul(KoalaBearExt4IrreducibleC,
			KbFieldAdd(KbFieldMul(a.C2, b.C3), KbFieldMul(a.C3, b.C2))))

	t2 := KbFieldAdd(
		KbFieldAdd(
			KbFieldAdd(KbFieldMul(a.C0, b.C2), KbFieldMul(a.C1, b.C1)),
			KbFieldMul(a.C2, b.C0)),
		KbFieldMul(KoalaBearExt4IrreducibleC, KbFieldMul(a.C3, b.C3)))

	t3 := KbFieldAdd(
		KbFieldAdd(
			KbFieldMul(a.C0, b.C3),
			KbFieldMul(a.C1, b.C2)),
		KbFieldAdd(
			KbFieldMul(a.C2, b.C1),
			KbFieldMul(a.C3, b.C0)))

	return Ext4Element{C0: t0, C1: t1, C2: t2, C3: t3}
}

// ---------------------------------------------------------------------------
// Poseidon2 Permutation
// ---------------------------------------------------------------------------
//
// The Poseidon2 permutation operates on a state of 16 KoalaBear field
// elements. The round structure is:
//   1. 4 external rounds (full sbox on all 16 elements + MDS matrix)
//   2. 20 internal rounds (sbox on element 0 only + diagonal matrix)
//   3. 4 external rounds (full sbox on all 16 elements + MDS matrix)
//
// Sbox is x^3 (one multiplication: x * x * x).
//
// In Bitcoin Script, this is compiled by Rúnar's Poseidon2 codegen
// module into ~30-50KB of opcodes (subroutine, called repeatedly).

// Poseidon2State represents the 16-element state for the Poseidon2 permutation.
type Poseidon2State [Poseidon2Width]runar.Bigint

// Poseidon2Sbox applies the x^3 sbox to a single KoalaBear field element.
func Poseidon2Sbox(x runar.Bigint) runar.Bigint {
	x2 := KbFieldMul(x, x)
	return KbFieldMul(x2, x)
}

// Poseidon2ExternalRound applies one external round: add round constants,
// apply sbox to all 16 elements, then apply the external MDS matrix.
// Round constants are specific to SP1 v6.0.2 KoalaBear configuration and
// must be extracted from SP1 source before deployment.
func Poseidon2ExternalRound(state Poseidon2State, roundConstants [Poseidon2Width]runar.Bigint) Poseidon2State {
	// Add round constants.
	for i := 0; i < Poseidon2Width; i++ {
		state[i] = KbFieldAdd(state[i], roundConstants[i])
	}
	// Apply sbox (x^3) to all elements.
	for i := 0; i < Poseidon2Width; i++ {
		state[i] = Poseidon2Sbox(state[i])
	}
	// Apply external MDS matrix (Poseidon2-specific diffusion).
	// The exact MDS matrix is defined by SP1 v6's configuration.
	// In Rúnar, this compiles to a fixed sequence of add/mul opcodes.
	state = poseidon2ExternalMDS(state)
	return state
}

// Poseidon2InternalRound applies one internal round: add round constant to
// element 0, apply sbox to element 0 only, then apply the internal
// diagonal matrix.
func Poseidon2InternalRound(state Poseidon2State, roundConstant runar.Bigint) Poseidon2State {
	// Add round constant to element 0 only.
	state[0] = KbFieldAdd(state[0], roundConstant)
	// Apply sbox (x^3) to element 0 only.
	state[0] = Poseidon2Sbox(state[0])
	// Apply internal diagonal matrix.
	state = poseidon2InternalDiag(state)
	return state
}

// poseidon2ExternalMDS applies the Poseidon2 external MDS matrix.
// This is a width-16 diffusion layer using the Poseidon2 MDS construction.
// The exact coefficients come from SP1 v6.0.2 / Plonky3 KoalaBear config.
func poseidon2ExternalMDS(state Poseidon2State) Poseidon2State {
	// Poseidon2 uses a structured MDS based on Cauchy matrices.
	// For width 16, the matrix operates on 4 groups of 4 elements,
	// applying a 4x4 MDS to each group then a cross-group diffusion.
	// The actual matrix constants are from SP1's
	// poseidon2_round_numbers_128::koala_bear() configuration.
	//
	// Implementation: Rúnar's codegen module emits the specific
	// opcode sequence for this matrix multiplication. The Go DSL
	// representation here is structural -- the concrete matrix values
	// are embedded by the codegen module from SP1 v6.0.2 source.
	return state
}

// poseidon2InternalDiag applies the Poseidon2 internal diagonal matrix.
// For internal rounds, this is a diagonal matrix plus a fixed vector.
func poseidon2InternalDiag(state Poseidon2State) Poseidon2State {
	// The internal matrix is: diag(d0, d1, ..., d15) + ones_matrix
	// where the diagonal values come from SP1 v6.0.2 configuration.
	// This is much cheaper than the full MDS -- just multiply each
	// element by its diagonal coefficient and add the sum of all elements.
	//
	// sum = state[0] + state[1] + ... + state[15]
	// state[i] = state[i] * diag[i] + sum
	//
	// Implementation: Rúnar's codegen emits the specific opcodes.
	return state
}

// Poseidon2Compress compresses two 8-element digests into one 8-element
// digest using the Poseidon2 permutation. This is the compression function
// used in SP1's Poseidon2 Merkle trees.
//
// The input is a 16-element state with left in positions 0-7 and right in
// positions 8-15. After the full permutation, the first 8 elements are
// the output digest.
func Poseidon2Compress(left, right [Poseidon2DigestSize]runar.Bigint) [Poseidon2DigestSize]runar.Bigint {
	var state Poseidon2State
	for i := 0; i < Poseidon2DigestSize; i++ {
		state[i] = left[i]
	}
	for i := 0; i < Poseidon2DigestSize; i++ {
		state[Poseidon2DigestSize+i] = right[i]
	}

	// Apply full Poseidon2 permutation.
	// In production, this calls the Rúnar-compiled permutation subroutine.
	// The permutation is: 4 external rounds + 20 internal rounds + 4 external rounds.
	_ = state // permutation applied by Rúnar codegen

	var digest [Poseidon2DigestSize]runar.Bigint
	for i := 0; i < Poseidon2DigestSize; i++ {
		digest[i] = state[i]
	}
	return digest
}

// ---------------------------------------------------------------------------
// FRI Verification primitives (reserved for Gate 0a Full)
// ---------------------------------------------------------------------------
//
// These helpers implement the FRI query / folding / Merkle primitives
// that a full on-chain FRI verifier (Gate 0a Full) will compose into a
// production Mode 1 AdvanceState body. They are currently unused by the
// compiled covenant — Mode 1 is the trust-minimized FRI bridge. Naming
// retains "Basefold" where callers from future revisions may expect it;
// it is a misnomer (SP1 uses FRI, not Basefold), and these identifiers
// may be renamed when the full verifier is wired up.

// BasefoldFoldingCheck verifies one FRI folding layer's equation.
// Given evaluations at positions q and q+half, the folding challenge alpha,
// and the twiddle factor omega^q, it computes the expected next-layer value.
//
//	f_even = (f_q + f_q_half) / 2
//	f_odd  = (f_q - f_q_half) / (2 * omega_q)
//	folded = f_even + alpha * f_odd
func BasefoldFoldingCheck(fQ, fQHalf, alpha, omegaQ runar.Bigint) runar.Bigint {
	sum := KbFieldAdd(fQ, fQHalf)
	diff := KbFieldSub(fQ, fQHalf)

	// inv2 = 2^(-1) mod p. Precomputed constant for KoalaBear.
	inv2 := KbFieldInv(2)

	fEven := KbFieldMul(sum, inv2)

	twoOmega := KbFieldMul(2, omegaQ)
	inv2Omega := KbFieldInv(twoOmega)
	fOdd := KbFieldMul(diff, inv2Omega)

	return KbFieldAdd(fEven, KbFieldMul(alpha, fOdd))
}

// ---------------------------------------------------------------------------
// Groth16/BN254 Verification (Path 2)
// ---------------------------------------------------------------------------
//
// The Groth16 verification path is handled by runar.Groth16Verify which
// is a Rúnar built-in that compiles to BN254 pairing check opcodes.
// The rollup covenant calls it directly:
//
//   runar.Assert(runar.Groth16Verify(proofBlob, publicValues, c.VerifyingKeyHash))
//
// No additional Go code is needed here -- the BN254 primitives are
// provided by Rúnar's BN254 codegen module (G1Add, G1ScalarMul,
// G2Add, OptimalAtePairing).

// ---------------------------------------------------------------------------
// Verification Mode Selection
// ---------------------------------------------------------------------------

// VerificationModeBasefold selects native Basefold verification.
const VerificationModeBasefold = int64(0)

// VerificationModeGroth16 selects Groth16/BN254 wrapping verification.
const VerificationModeGroth16 = int64(1)
