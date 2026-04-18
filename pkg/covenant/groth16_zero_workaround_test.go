package covenant

import (
	"bytes"
	"math/big"
	"testing"

	runar "github.com/icellan/runar/packages/runar-go"
)

// identityG1 is the 64-byte encoding of the BN254 G1 identity point. The
// on-chain codegen's generic bn254G1AffineAdd / bn254G1ScalarMul cannot
// handle this value as an operand, so the zero-input workaround must
// ensure it never appears in an intermediate of the contract-side MSM.
var identityG1 = make([]byte, 64)

// referenceMSM recomputes IC0 + Σ xi·IC[i+1] using the same runar
// primitives the contract emits, treating zero scalars naturally via
// the off-chain Bn254G1Add identity handling. This is the algebraic
// value the workaround must preserve.
func referenceMSM(vk *Groth16VK, inputs []*big.Int) []byte {
	ic := [][]byte{vk.IC1, vk.IC2, vk.IC3, vk.IC4, vk.IC5}
	acc := append([]byte(nil), vk.IC0...)
	for i := 0; i < Mode2PublicInputCount; i++ {
		if inputs[i].Sign() == 0 {
			// off-chain: 0·P is the identity, which adds to acc as a no-op.
			continue
		}
		term := runar.Bn254G1ScalarMul(ic[i], inputs[i])
		acc = runar.Bn254G1Add(acc, term)
	}
	return acc
}

// TestApplyZeroInputWorkaround_NoIdentityIntermediates enumerates all 2^5
// zero patterns against the Gate 0 VK. For each pattern it runs the MSM
// exactly as the contract would after ApplyZeroInputWorkaround and asserts
// (a) every intermediate is non-identity, (b) the final accumulator equals
// the reference MSM on the original VK / inputs.
func TestApplyZeroInputWorkaround_NoIdentityIntermediates(t *testing.T) {
	vk, err := LoadSP1Groth16VK(gate0VKPath(t))
	if err != nil {
		t.Fatalf("LoadSP1Groth16VK: %v", err)
	}

	for mask := 0; mask < 1<<Mode2PublicInputCount; mask++ {
		inputs := make([]*big.Int, Mode2PublicInputCount)
		for i := 0; i < Mode2PublicInputCount; i++ {
			if mask&(1<<i) != 0 {
				inputs[i] = new(big.Int)
			} else {
				inputs[i] = big.NewInt(int64(7 + i))
			}
		}

		adjusted, adjInputs, err := ApplyZeroInputWorkaround(vk, inputs)
		if err != nil {
			t.Fatalf("mask=%05b ApplyZeroInputWorkaround: %v", mask, err)
		}

		if bytes.Equal(adjusted.IC0, identityG1) {
			t.Fatalf("mask=%05b adjusted IC0 is identity", mask)
		}

		icSlots := [][]byte{adjusted.IC1, adjusted.IC2, adjusted.IC3, adjusted.IC4, adjusted.IC5}
		acc := append([]byte(nil), adjusted.IC0...)
		for i := 0; i < Mode2PublicInputCount; i++ {
			term := runar.Bn254G1ScalarMul(icSlots[i], adjInputs[i])
			if bytes.Equal(term, identityG1) {
				t.Fatalf("mask=%05b term[%d] is identity (adjusted input was zero)", mask, i)
			}
			acc = runar.Bn254G1Add(acc, term)
			if bytes.Equal(acc, identityG1) {
				t.Fatalf("mask=%05b acc became identity after adding term[%d]", mask, i)
			}
		}

		want := referenceMSM(vk, inputs)
		if !bytes.Equal(acc, want) {
			t.Fatalf("mask=%05b final acc != reference MSM\n got: %x\nwant: %x", mask, acc, want)
		}
	}
}

// TestApplyZeroInputWorkaround_AllZerosProducesNonIdentity exercises the
// worst case: every public input is zero. The adjusted IC0 must not be
// identity and every MSM intermediate must stay non-identity.
func TestApplyZeroInputWorkaround_AllZerosProducesNonIdentity(t *testing.T) {
	vk, err := LoadSP1Groth16VK(gate0VKPath(t))
	if err != nil {
		t.Fatalf("LoadSP1Groth16VK: %v", err)
	}

	inputs := make([]*big.Int, Mode2PublicInputCount)
	for i := range inputs {
		inputs[i] = new(big.Int)
	}

	adjusted, adjInputs, err := ApplyZeroInputWorkaround(vk, inputs)
	if err != nil {
		t.Fatalf("ApplyZeroInputWorkaround: %v", err)
	}

	if bytes.Equal(adjusted.IC0, identityG1) {
		t.Fatal("adjusted IC0 is identity in all-zero case")
	}

	for i, x := range adjInputs {
		if x.Sign() == 0 {
			t.Fatalf("adjusted input %d is zero; workaround must substitute 1", i)
		}
	}

	icSlots := [][]byte{adjusted.IC1, adjusted.IC2, adjusted.IC3, adjusted.IC4, adjusted.IC5}
	acc := append([]byte(nil), adjusted.IC0...)
	for i := 0; i < Mode2PublicInputCount; i++ {
		term := runar.Bn254G1ScalarMul(icSlots[i], adjInputs[i])
		if bytes.Equal(term, identityG1) {
			t.Fatalf("term[%d] is identity", i)
		}
		acc = runar.Bn254G1Add(acc, term)
		if bytes.Equal(acc, identityG1) {
			t.Fatalf("acc became identity after term[%d]", i)
		}
	}

	want := referenceMSM(vk, inputs)
	if !bytes.Equal(acc, want) {
		t.Fatalf("all-zero final acc != reference\n got: %x\nwant: %x", acc, want)
	}
}

// TestApplyZeroInputWorkaround_DeepCopy verifies the helper returns a
// fresh *Groth16VK whose IC0 slice is independent of the caller's vk, so
// mutating one does not affect the other. Uses an all-nonzero input
// vector (no-op workaround) to isolate the copy behaviour.
func TestApplyZeroInputWorkaround_DeepCopy(t *testing.T) {
	vk, err := LoadSP1Groth16VK(gate0VKPath(t))
	if err != nil {
		t.Fatalf("LoadSP1Groth16VK: %v", err)
	}

	inputs := []*big.Int{
		big.NewInt(1), big.NewInt(2), big.NewInt(3), big.NewInt(4), big.NewInt(5),
	}

	adjusted, _, err := ApplyZeroInputWorkaround(vk, inputs)
	if err != nil {
		t.Fatalf("ApplyZeroInputWorkaround: %v", err)
	}

	if adjusted == vk {
		t.Fatal("adjusted is the same pointer as vk; want a deep copy")
	}
	if &adjusted.IC0 == &vk.IC0 {
		t.Fatal("adjusted.IC0 shares the same slice header as vk.IC0")
	}

	origFirst := vk.IC0[0]
	adjusted.IC0[0] ^= 0xff
	if vk.IC0[0] != origFirst {
		t.Fatalf("mutating adjusted.IC0 affected vk.IC0 (got %02x, want %02x)", vk.IC0[0], origFirst)
	}
}
