package covenant

import (
	"crypto/sha256"
	"fmt"
	"math/big"
	"os"

	runar "github.com/icellan/runar/packages/runar-go"
	"github.com/icellan/runar/packages/runar-go/bn254witness"
)

// PinnedSP1Groth16VKHashes is the allowlist of sha256 digests of SP1
// Groth16 vk.json files that mainnet shards may bake into the covenant
// locking script. Each entry corresponds to a specific SP1 release whose
// trusted-setup ceremony has been reviewed.
//
// Adding an entry here is security-significant: it authorises a ceremony
// transcript to serve as the Groth16 root of trust for every covenant
// pinned to this allowlist. Review the transcript and coordinator
// attestations before adding entries.
//
// The "gate0-fixture" entry below is the Gate 0b fixture shipped in
// tests/sp1/ and is ACCEPTED ONLY under VKTrustPolicyGate0Fixture. It
// MUST NOT be used on mainnet — it is not backed by a real ceremony.
var PinnedSP1Groth16VKHashes = map[string][32]byte{
	// tests/sp1/sp1_groth16_vk.json — Gate 0b fixture (NOT FOR MAINNET).
	// sha256: ba315d87303b212ac0c221881a34468013e6afc6b865e2abe3d68ad1c500c1d7
	"gate0-fixture": {
		0xba, 0x31, 0x5d, 0x87, 0x30, 0x3b, 0x21, 0x2a,
		0xc0, 0xc2, 0x21, 0x88, 0x1a, 0x34, 0x46, 0x80,
		0x13, 0xe6, 0xaf, 0xc6, 0xb8, 0x65, 0xe2, 0xab,
		0xe3, 0xd6, 0x8a, 0xd1, 0xc5, 0x00, 0xc1, 0xd7,
	},
}

// VKTrustPolicy controls how aggressively LoadSP1Groth16VKPinned verifies
// the VK's sha256 digest before parsing. Use VKTrustPolicyMainnet for
// real shard deployments; the other modes are for tests / regtest only.
type VKTrustPolicy int

const (
	// VKTrustPolicyMainnet requires the VK's sha256 to match a
	// PinnedSP1Groth16VKHashes entry whose name does NOT begin with
	// "gate0-" or "test-". The only policy safe for mainnet.
	VKTrustPolicyMainnet VKTrustPolicy = iota

	// VKTrustPolicyGate0Fixture allows the Gate 0b fixture. Use ONLY for
	// conformance tests and the regtest harness.
	VKTrustPolicyGate0Fixture

	// VKTrustPolicyAllowUnpinned disables the pinning check. Use ONLY for
	// Go-side unit tests constructing VKs on the fly. Never for a genesis
	// that will hold real funds.
	VKTrustPolicyAllowUnpinned
)

// String returns a human-readable name for the policy.
func (p VKTrustPolicy) String() string {
	switch p {
	case VKTrustPolicyMainnet:
		return "mainnet"
	case VKTrustPolicyGate0Fixture:
		return "gate0-fixture"
	case VKTrustPolicyAllowUnpinned:
		return "allow-unpinned"
	default:
		return fmt.Sprintf("unknown(%d)", int(p))
	}
}

// LoadSP1Groth16VKPinned reads an SP1-format Groth16 vk.json AND verifies
// its sha256 matches the given trust policy. Use this in any new code.
// The historical LoadSP1Groth16VK entry point is equivalent to
// LoadSP1Groth16VKPinned(path, VKTrustPolicyAllowUnpinned).
func LoadSP1Groth16VKPinned(vkJSONPath string, policy VKTrustPolicy) (*Groth16VK, error) {
	raw, err := os.ReadFile(vkJSONPath)
	if err != nil {
		return nil, fmt.Errorf("covenant: read vk.json %q: %w", vkJSONPath, err)
	}
	if err := checkPinnedVKHash(raw, policy); err != nil {
		return nil, fmt.Errorf("covenant: vk.json %q rejected by policy %s: %w",
			vkJSONPath, policy, err)
	}
	vk, err := bn254witness.LoadSP1VKFromFile(vkJSONPath)
	if err != nil {
		return nil, fmt.Errorf("covenant: LoadSP1Groth16VK: %w", err)
	}
	return Groth16VKFromBN254Witness(&vk)
}

// VerifyPinnedVKHash is a standalone helper for callers that want to
// confirm a file matches the pinned hash before passing it onwards
// (notably CompileGroth16WARollupPinned, which takes a path rather than
// pre-parsed VK bytes).
func VerifyPinnedVKHash(vkJSONPath string, policy VKTrustPolicy) error {
	raw, err := os.ReadFile(vkJSONPath)
	if err != nil {
		return fmt.Errorf("covenant: read vk.json %q: %w", vkJSONPath, err)
	}
	return checkPinnedVKHash(raw, policy)
}

// checkPinnedVKHash enforces F06: the VK bytes must match one of the
// allowed pinned hashes for the active policy.
func checkPinnedVKHash(raw []byte, policy VKTrustPolicy) error {
	actual := sha256.Sum256(raw)
	switch policy {
	case VKTrustPolicyAllowUnpinned:
		return nil
	case VKTrustPolicyGate0Fixture:
		expected, ok := PinnedSP1Groth16VKHashes["gate0-fixture"]
		if !ok {
			return fmt.Errorf("internal: gate0-fixture entry missing from PinnedSP1Groth16VKHashes")
		}
		if actual != expected {
			return fmt.Errorf("sha256 mismatch under gate0-fixture policy: got %x, want %x",
				actual, expected)
		}
		return nil
	case VKTrustPolicyMainnet:
		for name, pinned := range PinnedSP1Groth16VKHashes {
			if len(name) >= 5 && name[:5] == "gate0" {
				continue
			}
			if len(name) >= 5 && name[:5] == "test-" {
				continue
			}
			if actual == pinned {
				return nil
			}
		}
		return fmt.Errorf("sha256 %x is not in PinnedSP1Groth16VKHashes for mainnet policy (no real ceremony has been added yet)", actual)
	default:
		return fmt.Errorf("unknown VKTrustPolicy %d", int(policy))
	}
}

// Bn254ScalarMaskBitWidth is the exponent used to reduce SP1 public input
// scalars into the BN254 scalar field. SP1's Groth16 wrapper commits
// vkeyHash and committedValuesDigest as `sha256(x) & ((1<<253)-1)`; the
// covenant's reducePublicValuesToScalar applies the same mask. 2^253 < r
// (BN254 scalar order), so the mask result is always a valid scalar.
const Bn254ScalarMaskBitWidth = 253

// SP1Bn254ScalarMask returns the mask value 2^253.
func SP1Bn254ScalarMask() *big.Int {
	return new(big.Int).Lsh(big.NewInt(1), Bn254ScalarMaskBitWidth)
}

// ReduceSP1ProgramVkHashScalar computes the F01 reduction of
// sha256(sp1VerifyingKey) into the BN254 scalar field. This is the value
// the covenant pins as SP1ProgramVkHashScalar and asserts against
// g16Input0 on every advance.
func ReduceSP1ProgramVkHashScalar(sp1VerifyingKey []byte) *big.Int {
	if len(sp1VerifyingKey) == 0 {
		return new(big.Int)
	}
	h := sha256.Sum256(sp1VerifyingKey)
	hashInt := new(big.Int).SetBytes(h[:])
	mask := new(big.Int).Sub(SP1Bn254ScalarMask(), big.NewInt(1))
	return new(big.Int).And(hashInt, mask)
}

// ReducePublicValuesToBn254Scalar mirrors the covenant's on-chain
// reduction of sha256(publicValues) used for the g16Input1 binding.
// Callers precompute this off-chain before broadcasting an advance.
func ReducePublicValuesToBn254Scalar(publicValues []byte) *big.Int {
	h := sha256.Sum256(publicValues)
	hashInt := new(big.Int).SetBytes(h[:])
	mask := new(big.Int).Sub(SP1Bn254ScalarMask(), big.NewInt(1))
	return new(big.Int).And(hashInt, mask)
}

// Mode2PublicInputCount is the fixed number of BN254 public inputs in the
// SP1 circuit that the Mode 2 (generic Groth16) rollup contract's IC
// linearization expects. SP1 v6 uses 5 public inputs; this constant lets
// the loader and adjust helpers agree on the IC count without plumbing it
// through every call site.
const Mode2PublicInputCount = 5

// LoadSP1Groth16VK reads an SP1-format Groth16 verification key JSON file
// (same schema as tests/sp1/sp1_groth16_vk.json and the Gate 0b fixtures)
// and returns a decomposed *Groth16VK suitable for CompileGroth16Rollup.
//
// Sign-convention note — the bsv-evm Mode 2 contract at
// pkg/covenant/contracts/rollup_groth16.runar.go computes:
//
//	e(-A, B) * e(L, γ_stored) * e(C, δ_stored) * e(α, -β_stored_y) = 1
//
// where it negates proofA at runtime and negates the stored β y-coordinate
// at runtime (but uses γ, δ verbatim). For the Groth16 equation to hold
// term-by-term this requires:
//
//   - β stored PRE-NEGATED (runtime y-negation un-flips the sign)
//   - γ stored POSITIVE
//   - δ stored POSITIVE
//
// The SP1 vk.json format stores β, γ, δ all pre-negated (SP1 Solidity
// verifier convention). So this loader:
//
//   - Takes βNeg directly (matches what Mode 2 wants for β storage).
//   - Negates the y-coordinates of γNeg and δNeg to recover positive
//     γ and δ.
//
// AlphaG1 and IC[0..5] are G1 points stored positive in both conventions
// and copied verbatim.
func LoadSP1Groth16VK(vkJSONPath string) (*Groth16VK, error) {
	vk, err := bn254witness.LoadSP1VKFromFile(vkJSONPath)
	if err != nil {
		return nil, fmt.Errorf("covenant: LoadSP1Groth16VK: %w", err)
	}
	return Groth16VKFromBN254Witness(&vk)
}

// Groth16VKFromBN254Witness converts a Rúnar bn254witness.VerifyingKey into
// the covenant package's decomposed *Groth16VK with the Mode 2 sign
// convention applied (see LoadSP1Groth16VK doc comment).
//
// The returned *Groth16VK's BetaG2 field holds the SP1 βNeg verbatim, and
// its GammaG2 / DeltaG2 fields hold the SP1 γNeg / δNeg with y-coordinates
// re-negated back to positive form. G1 points are encoded as 64-byte
// uncompressed affine (x[32] || y[32]).
func Groth16VKFromBN254Witness(vk *bn254witness.VerifyingKey) (*Groth16VK, error) {
	if vk == nil {
		return nil, fmt.Errorf("covenant: nil bn254witness VerifyingKey")
	}
	if len(vk.IC) != 6 {
		return nil, fmt.Errorf("covenant: expected 6 IC points (SP1 has 5 public inputs), got %d", len(vk.IC))
	}

	g16 := &Groth16VK{
		AlphaG1: bn254EncodeG1(vk.AlphaG1[0], vk.AlphaG1[1]),
	}

	// β: contract stores β with negated y (pre-negated) and re-negates
	// at runtime. SP1's BetaNegG2 already has y negated, so we copy it
	// verbatim.
	for i := 0; i < 4; i++ {
		g16.BetaG2[i] = bn254EncodeFpBytes(vk.BetaNegG2[i])
	}

	// γ, δ: contract uses them verbatim in the pairing (no runtime
	// negation). SP1 stores them pre-negated, so we need positive values
	// — negate the y-coordinates (indices 2 and 3 of the Fp2 pair).
	for i := 0; i < 4; i++ {
		coord := vk.GammaNegG2[i]
		if i >= 2 {
			coord = runar.Bn254FieldNeg(coord)
		}
		g16.GammaG2[i] = bn254EncodeFpBytes(coord)
	}
	for i := 0; i < 4; i++ {
		coord := vk.DeltaNegG2[i]
		if i >= 2 {
			coord = runar.Bn254FieldNeg(coord)
		}
		g16.DeltaG2[i] = bn254EncodeFpBytes(coord)
	}

	// IC[0..5] are G1 points (positive) — direct copy.
	g16.IC0 = bn254EncodeG1(vk.IC[0][0], vk.IC[0][1])
	g16.IC1 = bn254EncodeG1(vk.IC[1][0], vk.IC[1][1])
	g16.IC2 = bn254EncodeG1(vk.IC[2][0], vk.IC[2][1])
	g16.IC3 = bn254EncodeG1(vk.IC[3][0], vk.IC[3][1])
	g16.IC4 = bn254EncodeG1(vk.IC[4][0], vk.IC[4][1])
	g16.IC5 = bn254EncodeG1(vk.IC[5][0], vk.IC[5][1])

	return g16, nil
}

// bn254EncodeG1 packs a BN254 G1 affine point into a 64-byte big-endian
// x || y byte slice, matching the runar.Point format expected by the
// Rúnar compiler's ByteString encoding for constructor-arg slots.
func bn254EncodeG1(x, y *big.Int) []byte {
	out := make([]byte, 64)
	copy(out[0:32], bn254EncodeFpBytes(x))
	copy(out[32:64], bn254EncodeFpBytes(y))
	return out
}

// bn254EncodeFpBytes left-zero-pads a BN254 Fp element to exactly 32 bytes
// big-endian. Nil values are treated as zero.
func bn254EncodeFpBytes(v *big.Int) []byte {
	out := make([]byte, 32)
	if v == nil {
		return out
	}
	b := v.Bytes()
	if len(b) > 32 {
		// Values larger than 32 bytes wouldn't be valid BN254 Fp elements;
		// truncate from the low end defensively.
		b = b[len(b)-32:]
	}
	copy(out[32-len(b):], b)
	return out
}

// Mode2AdjustedPublicInputs is the public-input vector the Mode 2 rollup
// contract must be invoked with after ApplyZeroInputWorkaround has adjusted
// the VK's IC0. Zero-valued inputs are replaced with 1 so the on-chain
// scalar multiplication / addition codegen (which does not special-case
// the BN254 identity point) never ends up adding an identity point to
// the accumulator.
type Mode2AdjustedPublicInputs [Mode2PublicInputCount]*big.Int

// ApplyZeroInputWorkaround produces a derived *Groth16VK and substituted
// public input vector that together satisfy the Groth16 equation even
// though Rúnar's generic Bn254G1AddP / Bn254G1ScalarMulP codegen cannot
// handle zero scalars or identity-point addends at runtime.
//
// Background — Rúnar limitation:
//
//	bn254G1AffineAdd (compilers/go/codegen/bn254.go) implements the
//	standard affine point-addition formula s = (qy - py)/(qx - px) with
//	no special case for either operand being the identity point (0, 0).
//	Similarly, EmitBN254G1ScalarMul promises correctness only for
//	k ∈ [1, r-1]; when the scalar is zero the subsequent Add against the
//	identity point divides by zero in Fp and the script fails. The
//	contract's on-chain MSM therefore blows up whenever any SP1 public
//	input is zero.
//
//	SP1 v6's 5-input Groth16 circuit routinely produces zero values for
//	the exitCode and vkRoot slots (indices 2 and 4 in the fixture), so
//	every real SP1 proof trips this limitation.
//
// Workaround:
//
//	Given public inputs (x0, x1, x2, x3, x4), compute the set Z of
//	indices where xi == 0. Replace the scalar at each zero index with 1
//	and subtract the corresponding IC[i+1] from IC[0]:
//
//	    IC0' := IC[0] - Σ_{i ∈ Z} IC[i+1]
//	    xi'  := 1  if i ∈ Z, else xi
//
//	The contract's on-chain MSM then computes:
//
//	    IC0' + Σ xi' · IC[i+1]
//	  = (IC[0] - Σ_{i∈Z} IC[i+1]) + Σ_{i∉Z} xi · IC[i+1] + Σ_{i∈Z} 1 · IC[i+1]
//	  = IC[0] + Σ_{i∉Z} xi · IC[i+1]
//	  = IC[0] + Σ xi · IC[i+1]  (since xi = 0 for i ∈ Z)
//
//	which is the correct prepared_inputs value the pairing expects. All
//	intermediate adds use non-identity points, so the codegen limitation
//	is side-stepped without any contract modification.
//
// The returned *Groth16VK is a deep copy with IC0 replaced; the original
// vk is left untouched. The adjusted public inputs must be passed to the
// contract's AdvanceState as g16Input0..g16Input4 — substituting them for
// the raw SP1 public inputs is the caller's responsibility.
//
// If inputs contains no zeros this helper returns a deep copy of the
// original vk and the original public inputs unchanged.
func ApplyZeroInputWorkaround(vk *Groth16VK, inputs []*big.Int) (*Groth16VK, Mode2AdjustedPublicInputs, error) {
	if vk == nil {
		return nil, Mode2AdjustedPublicInputs{}, fmt.Errorf("covenant: nil Groth16VK")
	}
	if len(inputs) != Mode2PublicInputCount {
		return nil, Mode2AdjustedPublicInputs{}, fmt.Errorf(
			"covenant: expected %d public inputs, got %d",
			Mode2PublicInputCount, len(inputs),
		)
	}

	// Deep-copy the VK so the caller's original stays untouched.
	adjusted := &Groth16VK{
		AlphaG1: append([]byte(nil), vk.AlphaG1...),
	}
	for i := 0; i < 4; i++ {
		adjusted.BetaG2[i] = append([]byte(nil), vk.BetaG2[i]...)
		adjusted.GammaG2[i] = append([]byte(nil), vk.GammaG2[i]...)
		adjusted.DeltaG2[i] = append([]byte(nil), vk.DeltaG2[i]...)
	}
	adjusted.IC0 = append([]byte(nil), vk.IC0...)
	adjusted.IC1 = append([]byte(nil), vk.IC1...)
	adjusted.IC2 = append([]byte(nil), vk.IC2...)
	adjusted.IC3 = append([]byte(nil), vk.IC3...)
	adjusted.IC4 = append([]byte(nil), vk.IC4...)
	adjusted.IC5 = append([]byte(nil), vk.IC5...)

	// Collect the IC[i+1] points for quick lookup by input index.
	icSlots := [][]byte{vk.IC1, vk.IC2, vk.IC3, vk.IC4, vk.IC5}

	// Accumulate the correction -Σ IC[i+1] for zero indices by running
	// it off-chain with the runar.Bn254G1* helpers (same primitives the
	// on-chain codegen implements, so output is bit-for-bit identical
	// for well-formed inputs). Post-R8 runar.Bn254G1Add and Bn254G1Negate
	// always return fresh allocations — no more identity-operand aliasing
	// bug that required the haveZero guard.
	correction := make([]byte, 64) // identity
	for i := 0; i < Mode2PublicInputCount; i++ {
		if inputs[i] == nil {
			return nil, Mode2AdjustedPublicInputs{}, fmt.Errorf("covenant: public input %d is nil", i)
		}
		if inputs[i].Sign() != 0 {
			continue
		}
		correction = runar.Bn254G1Add(correction, icSlots[i])
	}
	adjusted.IC0 = runar.Bn254G1Add(vk.IC0, runar.Bn254G1Negate(correction))

	// Replace zero inputs with 1 in the returned adjusted vector.
	var out Mode2AdjustedPublicInputs
	for i := 0; i < Mode2PublicInputCount; i++ {
		if inputs[i].Sign() == 0 {
			out[i] = big.NewInt(1)
		} else {
			out[i] = new(big.Int).Set(inputs[i])
		}
	}

	return adjusted, out, nil
}
