// Package proofmode defines the ProofMode enum identifying which on-chain
// verification path a given SP1 proof targets. Each mode corresponds to a
// distinct rollup covenant contract type and a distinct AdvanceProof shape
// on the BroadcastClient seam.
//
// ProofMode is its own package (rather than living in pkg/prover or
// pkg/covenant) to avoid a circular import between those two packages:
// pkg/covenant's AdvanceProof interface needs the enum, and pkg/prover's
// ProveOutput also needs the enum, but pkg/covenant and pkg/prover are
// otherwise independent.
package proofmode

// ProofMode identifies which on-chain verification math a proof is for.
type ProofMode uint8

const (
	// FRI is the trust-minimized SP1 FRI bridge mode. The covenant binds
	// state transitions (block+1, state roots, batch hash, chain id) but
	// does NOT verify the FRI proof on-chain. Off-chain nodes verify and
	// governance freeze is the only recourse against a malicious advance.
	// Corresponds to FRIRollupContract with a 5-arg advanceState method.
	// NOT mainnet-eligible — see rollup_fri.runar.go and spec 12. Gate 0a
	// Full will replace this with a fully on-chain FRI verifier.
	FRI ProofMode = 0

	// Groth16Generic is the BN254 multi-pairing verification path using
	// the generic Bn254G1AddP / Bn254G1ScalarMulP / Bn254MultiPairing4
	// primitives. Proof points are passed verbatim as runtime arguments.
	// Corresponds to Groth16RollupContract with a 16-arg advanceState
	// method.
	Groth16Generic ProofMode = 1

	// Groth16Witness is the witness-assisted Groth16 verification path.
	// The verifier is baked into the locking script at compile time via
	// CompileOptions.Groth16WAVKey, and the prover-supplied gradient /
	// final-exp / MSM witness bundle is passed via runar.CallOptions on
	// each spend. Corresponds to Groth16WARollupContract with a 5-arg
	// advanceState method. Smallest on-chain footprint (~688 KB vs
	// ~6 MB for Groth16Generic) — recommended production target.
	Groth16Witness ProofMode = 2
)

// String returns a human-readable name for the proof mode.
func (m ProofMode) String() string {
	switch m {
	case FRI:
		return "fri"
	case Groth16Generic:
		return "groth16-generic"
	case Groth16Witness:
		return "groth16-witness"
	default:
		return "unknown"
	}
}
