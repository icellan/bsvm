package covenant

import (
	"fmt"

	"github.com/icellan/bsvm/pkg/types"
)

// DefaultCovenantSats is the fixed satoshi amount the covenant UTXO carries.
// It does not grow or shrink. The prover's incentive is purely L2 coinbase
// fees (wBSV), not BSV from the covenant. 10,000 satoshis is well above
// the standard BSV dust limit (546 sats).
const DefaultCovenantSats = uint64(10000)

// GenesisConfig holds parameters for creating a new shard's initial covenant.
type GenesisConfig struct {
	ChainID          uint64
	SP1VerifyingKey  []byte
	InitialStateRoot types.Hash
	Governance       GovernanceConfig
	Verification     VerificationMode // VerifyGroth16 (default), VerifyFRI, or VerifyGroth16WA
	Groth16VK        *Groth16VK       // Required when Verification == VerifyGroth16
	// Groth16WAVKPath is the absolute path to the SP1-format vk.json file
	// baked into the witness-assisted Groth16 preamble. Required when
	// Verification == VerifyGroth16WA.
	Groth16WAVKPath string
	// VKTrustPolicy controls the F06 pinning check applied by the Mode 3
	// WA compile path. VKTrustPolicyMainnet is required when Mainnet=true.
	// Tests use Gate0Fixture or AllowUnpinned.
	VKTrustPolicy VKTrustPolicy
	// Mainnet flags the shard as mainnet-bound. When true, PrepareGenesis
	// enforces VKTrustPolicy == VKTrustPolicyMainnet AND rejects
	// Verification == VerifyFRI (Mode 1 has no on-chain proof check and
	// is not mainnet-eligible until Gate 0a Full lands). Mode 2 and Mode 3
	// WA are mainnet-eligible under the pinning policy.
	Mainnet      bool
	CovenantSats uint64 // Default: DefaultCovenantSats (10000)
}

// GenesisResult holds the output of PrepareGenesis. It contains the compiled
// covenant, the initial state, and the locking script ready for embedding
// in the genesis BSV transaction.
type GenesisResult struct {
	Covenant      *CompiledCovenant
	InitialState  CovenantState
	LockingScript []byte
	ANF           []byte
}

// PrepareGenesis compiles the covenant and prepares the genesis state.
// The actual BSV transaction broadcast requires a BSV client (Milestone 5).
//
// The genesis state has:
//   - StateRoot set to the provided InitialStateRoot
//   - BlockNumber set to 0 (the first executable block is block 1)
//   - Frozen set to 0 (active)
//
// The covenant is compiled with the provided SP1 verifying key, chain ID,
// and governance configuration.
func PrepareGenesis(config *GenesisConfig) (*GenesisResult, error) {
	if config == nil {
		return nil, fmt.Errorf("genesis config must not be nil")
	}
	if config.ChainID == 0 {
		return nil, fmt.Errorf("chain ID must not be zero")
	}
	if len(config.SP1VerifyingKey) == 0 {
		return nil, fmt.Errorf("SP1 verifying key must not be empty")
	}

	sats := config.CovenantSats
	if sats == 0 {
		sats = DefaultCovenantSats
	}

	// F06 mainnet guardrail — the VK must be pinned via a reviewed
	// ceremony allowlist entry, not the gate0 fixture and not unpinned
	// random bytes. Applies to every mode that performs on-chain proof
	// verification (Mode 2 / Mode 3 WA).
	if config.Mainnet && config.VKTrustPolicy != VKTrustPolicyMainnet {
		return nil, fmt.Errorf("mainnet genesis requires VKTrustPolicy=Mainnet, got %s",
			config.VKTrustPolicy)
	}

	// Mode 1 mainnet guardrail — Mode 1 (VerifyFRI) is the trust-minimized
	// FRI bridge and does NOT verify the SP1 proof on-chain. A malicious
	// prover can advance to an invalid state; the only recourse is
	// governance freeze. It is not mainnet-eligible until Gate 0a Full
	// replaces it with a full on-chain FRI verifier. See spec 12.
	if config.Mainnet && config.Verification == VerifyFRI {
		return nil, fmt.Errorf(
			"mainnet genesis rejects VerifyFRI: Mode 1 is the trust-minimized FRI bridge " +
				"and has no on-chain proof check; use VerifyGroth16 or VerifyGroth16WA for mainnet")
	}

	var compiled *CompiledCovenant
	var err error
	switch config.Verification {
	case VerifyFRI:
		compiled, err = CompileFRIRollup(config.SP1VerifyingKey, config.ChainID, config.Governance)
	case VerifyGroth16:
		compiled, err = CompileGroth16Rollup(config.SP1VerifyingKey, config.ChainID, config.Governance, config.Groth16VK)
	case VerifyGroth16WA:
		compiled, err = CompileGroth16WARollupPinned(config.SP1VerifyingKey, config.ChainID, config.Governance, config.Groth16WAVKPath, config.VKTrustPolicy)
	default:
		return nil, fmt.Errorf("unknown verification mode %d", int(config.Verification))
	}
	if err != nil {
		return nil, fmt.Errorf("compiling covenant: %w", err)
	}

	initialState := CovenantState{
		StateRoot:   config.InitialStateRoot,
		BlockNumber: 0,
		Frozen:      0,
	}

	return &GenesisResult{
		Covenant:      compiled,
		InitialState:  initialState,
		LockingScript: compiled.LockingScript,
		ANF:           compiled.ANF,
	}, nil
}
