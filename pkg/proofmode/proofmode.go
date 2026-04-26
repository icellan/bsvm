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

import (
	"fmt"
	"strings"
)

// ProofMode identifies which on-chain verification math a proof is for.
type ProofMode uint8

const (
	// FRI is the trust-minimized SP1 STARK verification path (Mode 1).
	// The covenant invokes runar.VerifySP1FRI on every advance, replaying
	// the FRI argument against the pinned SP1VerifyingKeyHash (KoalaBear
	// field + Poseidon2 KoalaBear Merkle + colinearity + Fiat-Shamir
	// transcript). Corresponds to FRIRollupContract. Mode 1 (FRI), Mode 2
	// (Groth16), Mode 3 (Groth16WA) — all mainnet-eligible under VK pinning
	// policy F06 (post-Gate-0a-Full; see CLAUDE.md and spec 12).
	FRI ProofMode = 0

	// Groth16 is the BN254 multi-pairing verification path using
	// the generic Bn254G1AddP / Bn254G1ScalarMulP / Bn254MultiPairing4
	// primitives. Proof points are passed verbatim as runtime arguments.
	// Corresponds to Groth16RollupContract with a 16-arg advanceState
	// method.
	Groth16 ProofMode = 1

	// Groth16WA is the witness-assisted Groth16 verification path.
	// The verifier is baked into the locking script at compile time via
	// CompileOptions.Groth16WAVKey, and the prover-supplied gradient /
	// final-exp / MSM witness bundle is passed via runar.CallOptions on
	// each spend. Corresponds to Groth16WARollupContract with a 5-arg
	// advanceState method. Smallest on-chain footprint (~688 KB vs
	// ~6 MB for Groth16) — recommended production target.
	Groth16WA ProofMode = 2
)

// String returns a human-readable name for the proof mode.
func (m ProofMode) String() string {
	switch m {
	case FRI:
		return "fri"
	case Groth16:
		return "groth16"
	case Groth16WA:
		return "groth16-wa"
	default:
		return "unknown"
	}
}

// proofModeAliases maps every accepted spelling of a proof mode (current
// canonical names plus legacy "groth16-generic" / "groth16-witness" spellings
// for backward compat with config files in the wild) to its ProofMode value.
var proofModeAliases = map[string]ProofMode{
	"fri":             FRI,
	"groth16":         Groth16,
	"groth16-wa":      Groth16WA,
	"groth16-generic": Groth16,   // legacy alias for Groth16
	"groth16-witness": Groth16WA, // legacy alias for Groth16WA
}

// Parse converts a human-readable proof mode name into its ProofMode value.
// Comparison is case-insensitive and tolerant of surrounding whitespace.
// Both the canonical names ("fri", "groth16", "groth16-wa") and the legacy
// names ("groth16-generic", "groth16-witness") are accepted; the legacy
// names are aliases for backward compat with config files written before
// the Gate-0a-Full rename.
func Parse(s string) (ProofMode, error) {
	key := strings.ToLower(strings.TrimSpace(s))
	if m, ok := proofModeAliases[key]; ok {
		return m, nil
	}
	return 0, fmt.Errorf("proofmode: unknown mode %q", s)
}
