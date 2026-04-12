package covenant

import "fmt"

// VerificationMode determines how the covenant verifies SP1 proofs on-chain.
type VerificationMode int

const (
	// VerifyGroth16 uses SP1's Groth16/BN254 wrapping. The STARK proof is
	// wrapped into a ~256 byte Groth16 proof. The covenant verifies it via
	// a BN254 pairing check using Rúnar's witness-assisted Groth16 verifier
	// (~50-100 KB compiled script). This is the recommended mode for most
	// shards — smaller proof, faster on-chain verification, and the
	// witness-assisted technique minimizes script size.
	VerifyGroth16 VerificationMode = iota

	// VerifyBasefold verifies the SP1 STARK proof natively using KoalaBear
	// field arithmetic and Poseidon2 Merkle verification in Bitcoin Script.
	// No trusted setup required (fully transparent). Larger proof (~1.2 MB)
	// and larger script (1-5 MB estimated). Use when the BN254 trusted
	// setup is unacceptable for the shard's threat model.
	VerifyBasefold
)

// String returns a human-readable name for the verification mode.
func (m VerificationMode) String() string {
	switch m {
	case VerifyGroth16:
		return "groth16"
	case VerifyBasefold:
		return "basefold"
	default:
		return fmt.Sprintf("unknown(%d)", int(m))
	}
}

// GovernanceMode determines the shard's trust model.
type GovernanceMode int

const (
	// GovernanceNone means fully trustless. No freeze, no unfreeze, no upgrade.
	// The proof is the sole authority for state advances.
	GovernanceNone GovernanceMode = iota

	// GovernanceSingleKey means a single key can freeze/unfreeze/upgrade the shard.
	// The key cannot advance state — only a valid STARK proof can.
	GovernanceSingleKey

	// GovernanceMultiSig means an M-of-N multisig controls freeze/unfreeze/upgrade.
	// The keys cannot advance state — only a valid STARK proof can.
	GovernanceMultiSig
)

// String returns a human-readable name for the governance mode.
func (m GovernanceMode) String() string {
	switch m {
	case GovernanceNone:
		return "none"
	case GovernanceSingleKey:
		return "single_key"
	case GovernanceMultiSig:
		return "multisig"
	default:
		return fmt.Sprintf("unknown(%d)", int(m))
	}
}

// GovernanceConfig holds governance parameters set at genesis. These are
// embedded in the covenant script as compile-time properties and cannot
// be changed after genesis.
type GovernanceConfig struct {
	Mode      GovernanceMode
	Keys      [][]byte // Compressed public keys (33 bytes each)
	Threshold int      // M-of-N threshold (multisig only)
}

// Validate checks the governance config is consistent. It returns an error
// if the config violates any invariant for the selected mode.
func (g *GovernanceConfig) Validate() error {
	switch g.Mode {
	case GovernanceNone:
		if len(g.Keys) != 0 {
			return fmt.Errorf("governance mode none must have no keys, got %d", len(g.Keys))
		}
		if g.Threshold != 0 {
			return fmt.Errorf("governance mode none must have threshold 0, got %d", g.Threshold)
		}

	case GovernanceSingleKey:
		if len(g.Keys) != 1 {
			return fmt.Errorf("governance mode single_key requires exactly 1 key, got %d", len(g.Keys))
		}
		if err := validateCompressedPubKey(g.Keys[0]); err != nil {
			return fmt.Errorf("governance key invalid: %w", err)
		}
		if g.Threshold != 0 {
			return fmt.Errorf("governance mode single_key must have threshold 0, got %d", g.Threshold)
		}

	case GovernanceMultiSig:
		if len(g.Keys) < 2 {
			return fmt.Errorf("governance mode multisig requires at least 2 keys, got %d", len(g.Keys))
		}
		if g.Threshold < 1 {
			return fmt.Errorf("governance mode multisig threshold must be at least 1, got %d", g.Threshold)
		}
		if g.Threshold > len(g.Keys) {
			return fmt.Errorf("governance mode multisig threshold %d exceeds number of keys %d", g.Threshold, len(g.Keys))
		}
		for i, key := range g.Keys {
			if err := validateCompressedPubKey(key); err != nil {
				return fmt.Errorf("governance key %d invalid: %w", i, err)
			}
		}

	default:
		return fmt.Errorf("unknown governance mode %d", int(g.Mode))
	}
	return nil
}

// validateCompressedPubKey checks that a byte slice looks like a compressed
// secp256k1 public key (33 bytes, prefix 0x02 or 0x03).
func validateCompressedPubKey(key []byte) error {
	if len(key) != 33 {
		return fmt.Errorf("expected 33 bytes, got %d", len(key))
	}
	if key[0] != 0x02 && key[0] != 0x03 {
		return fmt.Errorf("expected prefix 0x02 or 0x03, got 0x%02x", key[0])
	}
	return nil
}
