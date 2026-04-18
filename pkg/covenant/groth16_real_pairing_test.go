package covenant

import (
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	runar "github.com/icellan/runar/packages/runar-go"
	"github.com/icellan/runar/packages/runar-go/bn254witness"
)

// R4 / R5 — Go-level fidelity of Bn254MultiPairing4Big against the Mode 2
// sign convention, using the Gate 0 SP1 fixture.
//
// The Mode 2 contract's current on-chain pairing call uses the
// int64-typed Bn254MultiPairing4 mock (always returns true under Go
// test), and the DSL parser does not yet route Bn254MultiPairing4Big
// into compiled Script. So these tests do NOT call the contract — they
// drive the Big helper directly with gnark-derived values and verify:
//
//   - the fixture's (A, B, C, public_inputs, vk) tuple satisfies the
//     Groth16 equation under the bsv-evm Mode 2 arrangement
//
//       e(-A, B) · e(L, γ_stored) · e(C, δ_stored) · e(α, -β_stored_y) = 1
//
//     where β is stored pre-negated and runtime-negated, matching the
//     loader semantics in groth16_vk_loader.go.
//   - bit-flipping any coordinate breaks the equation.
//   - the helper returns the expected verdict for both honest and
//     tampered fixtures.
//
// Acts as Phase-5 differential conformance oracle (D1 Go vs D2 Script):
// if on-chain Script ever diverges from this, one side is wrong.

func realPairingFixtureDir(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Join(filepath.Dir(thisFile), "..", "..", "tests", "sp1")
}

// loadGate0Fixture reads the SP1 v6 Groth16 fixture shipped under
// tests/sp1/ and returns the parsed VK, proof and public inputs.
func loadGate0Fixture(t *testing.T) (vk bn254witness.VerifyingKey, proof bn254witness.Proof, publicInputs []*big.Int) {
	t.Helper()
	dir := realPairingFixtureDir(t)

	var err error
	vk, err = bn254witness.LoadSP1VKFromFile(filepath.Join(dir, "sp1_groth16_vk.json"))
	if err != nil {
		t.Fatalf("LoadSP1VKFromFile: %v", err)
	}

	rawHex, err := os.ReadFile(filepath.Join(dir, "groth16_raw_proof.hex"))
	if err != nil {
		t.Fatalf("read raw proof: %v", err)
	}
	proof, err = bn254witness.ParseSP1RawProof(strings.TrimSpace(string(rawHex)))
	if err != nil {
		t.Fatalf("ParseSP1RawProof: %v", err)
	}

	publicInputs, err = bn254witness.LoadSP1PublicInputs(filepath.Join(dir, "groth16_public_inputs.txt"))
	if err != nil {
		t.Fatalf("LoadSP1PublicInputs: %v", err)
	}
	if len(publicInputs) != Mode2PublicInputCount {
		t.Fatalf("expected %d public inputs, got %d", Mode2PublicInputCount, len(publicInputs))
	}
	return vk, proof, publicInputs
}

// computePreparedInputs performs the 5-term MSM off-chain using the
// ZeroInputWorkaround-adjusted VK (mirrors how the Mode 2 broadcast
// path will run in production).
func computePreparedInputs(t *testing.T, vk *Groth16VK, inputs []*big.Int) []byte {
	t.Helper()
	adjustedVK, adjustedInputs, err := ApplyZeroInputWorkaround(vk, inputs)
	if err != nil {
		t.Fatalf("ApplyZeroInputWorkaround: %v", err)
	}
	icSlots := [][]byte{adjustedVK.IC1, adjustedVK.IC2, adjustedVK.IC3, adjustedVK.IC4, adjustedVK.IC5}

	acc := append([]byte(nil), adjustedVK.IC0...)
	for i := 0; i < Mode2PublicInputCount; i++ {
		term := runar.Bn254G1ScalarMul(icSlots[i], adjustedInputs[i])
		acc = runar.Bn254G1Add(acc, term)
	}
	return acc
}

// negBetaG2Coords returns the Fp2 y-coordinates of β with the y-parts
// negated — mirroring the on-chain `Bn254FieldNegP(c.BetaG2Y0/Y1)` the
// Mode 2 contract applies at runtime so the stored β (already negated
// by the loader) cancels and the pairing consumes -β as SP1 expects.
func negBetaG2Coords(vk *Groth16VK) (y0Neg, y1Neg *big.Int) {
	y0 := new(big.Int).SetBytes(vk.BetaG2[2])
	y1 := new(big.Int).SetBytes(vk.BetaG2[3])
	return runar.Bn254FieldNeg(y0), runar.Bn254FieldNeg(y1)
}

// bytesBig converts a BN254 field byte slice to *big.Int (big-endian).
func bytesBig(b []byte) *big.Int {
	return new(big.Int).SetBytes(b)
}

// negAG1 returns -proof.A under the Mode 2 on-chain runtime pattern
// (Bn254G1NegateP(proofA)).
func negAG1(proof bn254witness.Proof) runar.Point {
	x := proof.A[0]
	y := proof.A[1]
	bytes := make([]byte, 64)
	copy(bytes[32-len(x.Bytes()):32], x.Bytes())
	copy(bytes[64-len(y.Bytes()):64], y.Bytes())
	return runar.Point(runar.Bn254G1Negate(bytes))
}

// cG1 returns proof.C packed as a runar.Point.
func cG1(proof bn254witness.Proof) runar.Point {
	x := proof.C[0]
	y := proof.C[1]
	bytes := make([]byte, 64)
	copy(bytes[32-len(x.Bytes()):32], x.Bytes())
	copy(bytes[64-len(y.Bytes()):64], y.Bytes())
	return runar.Point(bytes)
}

// alphaG1 packs vk.AlphaG1 into a runar.Point.
func alphaG1(vk *Groth16VK) runar.Point { return runar.Point(vk.AlphaG1) }

// TestBn254MultiPairing4Big_AcceptsGate0Fixture drives the runar real
// pairing against the Gate 0 fixture under Mode 2's on-chain sign
// convention and expects acceptance.
func TestBn254MultiPairing4Big_AcceptsGate0Fixture(t *testing.T) {
	rawVK, proof, publicInputs := loadGate0Fixture(t)

	bvk, err := Groth16VKFromBN254Witness(&rawVK)
	if err != nil {
		t.Fatalf("Groth16VKFromBN254Witness: %v", err)
	}

	preparedInputsBytes := computePreparedInputs(t, bvk, publicInputs)

	negBetaY0, negBetaY1 := negBetaG2Coords(bvk)

	ok := runar.Bn254MultiPairing4Big(
		negAG1(proof), proof.B[0], proof.B[1], proof.B[2], proof.B[3],
		runar.Point(preparedInputsBytes),
		bytesBig(bvk.GammaG2[0]), bytesBig(bvk.GammaG2[1]), bytesBig(bvk.GammaG2[2]), bytesBig(bvk.GammaG2[3]),
		cG1(proof),
		bytesBig(bvk.DeltaG2[0]), bytesBig(bvk.DeltaG2[1]), bytesBig(bvk.DeltaG2[2]), bytesBig(bvk.DeltaG2[3]),
		alphaG1(bvk),
		bytesBig(bvk.BetaG2[0]), bytesBig(bvk.BetaG2[1]), negBetaY0, negBetaY1,
	)
	if !ok {
		t.Fatal("real pairing rejected an honest Gate 0 proof under the Mode 2 sign convention")
	}
}

// TestBn254MultiPairing4Big_RejectsFlippedAY — mutating proof.A's
// y-coordinate by one field element must break the pairing.
func TestBn254MultiPairing4Big_RejectsFlippedAY(t *testing.T) {
	rawVK, proof, publicInputs := loadGate0Fixture(t)
	bvk, err := Groth16VKFromBN254Witness(&rawVK)
	if err != nil {
		t.Fatalf("Groth16VKFromBN254Witness: %v", err)
	}
	preparedInputsBytes := computePreparedInputs(t, bvk, publicInputs)
	negBetaY0, negBetaY1 := negBetaG2Coords(bvk)

	// Flip A_y off-curve by adding 1.
	mangled := proof
	mangled.A = [2]*big.Int{proof.A[0], new(big.Int).Add(proof.A[1], big.NewInt(1))}

	ok := runar.Bn254MultiPairing4Big(
		negAG1(mangled), mangled.B[0], mangled.B[1], mangled.B[2], mangled.B[3],
		runar.Point(preparedInputsBytes),
		bytesBig(bvk.GammaG2[0]), bytesBig(bvk.GammaG2[1]), bytesBig(bvk.GammaG2[2]), bytesBig(bvk.GammaG2[3]),
		cG1(mangled),
		bytesBig(bvk.DeltaG2[0]), bytesBig(bvk.DeltaG2[1]), bytesBig(bvk.DeltaG2[2]), bytesBig(bvk.DeltaG2[3]),
		alphaG1(bvk),
		bytesBig(bvk.BetaG2[0]), bytesBig(bvk.BetaG2[1]), negBetaY0, negBetaY1,
	)
	if ok {
		t.Fatal("expected pairing to REJECT a proof with flipped A.y")
	}
}

// TestBn254MultiPairing4Big_RejectsWrongPublicInput — flipping any
// public input must produce a different prepared_inputs and break the
// pairing.
func TestBn254MultiPairing4Big_RejectsWrongPublicInput(t *testing.T) {
	rawVK, proof, publicInputs := loadGate0Fixture(t)
	bvk, err := Groth16VKFromBN254Witness(&rawVK)
	if err != nil {
		t.Fatalf("Groth16VKFromBN254Witness: %v", err)
	}

	// Corrupt public input 0 (vkeyHash) by incrementing.
	mangled := make([]*big.Int, len(publicInputs))
	for i, pi := range publicInputs {
		mangled[i] = new(big.Int).Set(pi)
	}
	mangled[0].Add(mangled[0], big.NewInt(1))

	preparedInputsBytes := computePreparedInputs(t, bvk, mangled)
	negBetaY0, negBetaY1 := negBetaG2Coords(bvk)

	ok := runar.Bn254MultiPairing4Big(
		negAG1(proof), proof.B[0], proof.B[1], proof.B[2], proof.B[3],
		runar.Point(preparedInputsBytes),
		bytesBig(bvk.GammaG2[0]), bytesBig(bvk.GammaG2[1]), bytesBig(bvk.GammaG2[2]), bytesBig(bvk.GammaG2[3]),
		cG1(proof),
		bytesBig(bvk.DeltaG2[0]), bytesBig(bvk.DeltaG2[1]), bytesBig(bvk.DeltaG2[2]), bytesBig(bvk.DeltaG2[3]),
		alphaG1(bvk),
		bytesBig(bvk.BetaG2[0]), bytesBig(bvk.BetaG2[1]), negBetaY0, negBetaY1,
	)
	if ok {
		t.Fatal("expected pairing to REJECT a proof with wrong public_input[0]")
	}
}

// TestBn254MultiPairing4Big_RejectsForgedBetaY — leaving β.y un-negated
// at runtime (passing the stored pre-negated value verbatim instead of
// negating it again) must fail. This pins the loader-vs-contract
// sign-convention contract.
func TestBn254MultiPairing4Big_RejectsForgedBetaY(t *testing.T) {
	rawVK, proof, publicInputs := loadGate0Fixture(t)
	bvk, err := Groth16VKFromBN254Witness(&rawVK)
	if err != nil {
		t.Fatalf("Groth16VKFromBN254Witness: %v", err)
	}
	preparedInputsBytes := computePreparedInputs(t, bvk, publicInputs)

	// Intentionally DO NOT negate β.y — pass the stored (pre-negated)
	// value directly. The real pairing must reject.
	storedBetaY0 := bytesBig(bvk.BetaG2[2])
	storedBetaY1 := bytesBig(bvk.BetaG2[3])

	ok := runar.Bn254MultiPairing4Big(
		negAG1(proof), proof.B[0], proof.B[1], proof.B[2], proof.B[3],
		runar.Point(preparedInputsBytes),
		bytesBig(bvk.GammaG2[0]), bytesBig(bvk.GammaG2[1]), bytesBig(bvk.GammaG2[2]), bytesBig(bvk.GammaG2[3]),
		cG1(proof),
		bytesBig(bvk.DeltaG2[0]), bytesBig(bvk.DeltaG2[1]), bytesBig(bvk.DeltaG2[2]), bytesBig(bvk.DeltaG2[3]),
		alphaG1(bvk),
		bytesBig(bvk.BetaG2[0]), bytesBig(bvk.BetaG2[1]), storedBetaY0, storedBetaY1,
	)
	if ok {
		t.Fatal("expected pairing to REJECT a proof with un-negated β.y (loader sign-convention regression)")
	}
}

// TestReduceSP1ProgramVkHashScalar_Bigint254 pins that the F01 reducer
// produces the right 253-bit-masked scalar for a large input — exercises
// the full-width reduction path that Go-mock Bigint would truncate.
func TestReduceSP1ProgramVkHashScalar_Bigint254(t *testing.T) {
	// Construct a hypothetical SP1 vkey blob whose sha256 is unknown but
	// deterministic; verify the reduction yields a value < 2^253 and
	// recomputes deterministically.
	vkBytes := []byte("runar-r4-r5-fidelity-test-seed-42")
	s := ReduceSP1ProgramVkHashScalar(vkBytes)
	twoTo253 := new(big.Int).Lsh(big.NewInt(1), 253)
	if s.Cmp(twoTo253) >= 0 {
		t.Errorf("reduced scalar >= 2^253: %s", s)
	}
	if s.Sign() < 0 {
		t.Errorf("reduced scalar negative: %s", s)
	}
	again := ReduceSP1ProgramVkHashScalar(vkBytes)
	if s.Cmp(again) != 0 {
		t.Error("ReduceSP1ProgramVkHashScalar is non-deterministic")
	}
}

// TestReducePublicValuesToBn254Scalar_Bigint254 same invariant for the
// publicValues-digest reducer.
func TestReducePublicValuesToBn254Scalar_Bigint254(t *testing.T) {
	pv := make([]byte, 272)
	for i := range pv {
		pv[i] = byte(i)
	}
	s := ReducePublicValuesToBn254Scalar(pv)
	twoTo253 := new(big.Int).Lsh(big.NewInt(1), 253)
	if s.Cmp(twoTo253) >= 0 {
		t.Errorf("reduced pv scalar >= 2^253: %s", s)
	}
	if s.Sign() < 0 {
		t.Errorf("reduced pv scalar negative: %s", s)
	}
}
