package covenant

import (
	"crypto/sha256"
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
	Verification     VerificationMode // VerifyGroth16 (default), VerifyBasefold, or VerifyGroth16WA
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
	// enforces VKTrustPolicy == VKTrustPolicyMainnet. Mode 3 WA is now a
	// full production target — the Rúnar R1b groth16PublicInput wiring
	// closes F01 at the contract layer, alongside the already-shipped
	// F02/F03 MSM-binding + G2 subgroup checks.
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
	// random bytes. The old Mode 3 mainnet block was lifted once R1b +
	// R2 landed upstream — all three verification modes are now
	// mainnet-eligible under the pinning policy.
	if config.Mainnet && config.VKTrustPolicy != VKTrustPolicyMainnet {
		return nil, fmt.Errorf("mainnet genesis requires VKTrustPolicy=Mainnet, got %s",
			config.VKTrustPolicy)
	}

	var compiled *CompiledCovenant
	var err error
	switch config.Verification {
	case VerifyBasefold:
		compiled, err = CompileBasefoldRollup(config.SP1VerifyingKey, config.ChainID, config.Governance)
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

// genesisOpReturnPrefix is the magic prefix for genesis OP_RETURN payloads.
// Format: "BSVM" + version byte (0x01).
var genesisOpReturnPrefix = []byte{0x42, 0x53, 0x56, 0x4d, 0x01} // "BSVM\x01"

// BuildGenesisTransaction constructs the BSV transaction that creates the
// genesis covenant UTXO. The fundingInput provides the BSV to fund the
// covenant output. The changeAddress receives leftover satoshis minus fee.
//
// Transaction structure:
//
//	Input 0:  Funding UTXO
//	Output 0: Covenant UTXO (locking script + covenant sats)
//	Output 1: OP_RETURN with genesis config (BSVM\x01 + initial state encoded)
//	Output 2: Change output
func (g *GenesisResult) BuildGenesisTransaction(
	fundingInput FeeInput,
	covenantSats uint64,
	changeAddress []byte,
) (*BSVTx, error) {
	if g == nil {
		return nil, fmt.Errorf("genesis result must not be nil")
	}
	if len(g.LockingScript) == 0 {
		return nil, fmt.Errorf("locking script must not be empty")
	}
	if fundingInput.Satoshis == 0 {
		return nil, fmt.Errorf("funding input must have satoshis")
	}
	if covenantSats == 0 {
		return nil, fmt.Errorf("covenant sats must not be zero")
	}
	if len(changeAddress) == 0 {
		return nil, fmt.Errorf("change address must not be empty")
	}

	// Build input: funding UTXO.
	inputs := []BSVInput{
		{
			PrevTxID: fundingInput.TxID,
			PrevVout: fundingInput.Vout,
			Script:   nil, // unsigned — caller signs later
			Sequence: 0xffffffff,
		},
	}

	// Build OP_RETURN payload: BSVM\x01 + initial state encoded (41 bytes).
	opReturnPayload := make([]byte, 0, len(genesisOpReturnPrefix)+covenantStateEncodedSize)
	opReturnPayload = append(opReturnPayload, genesisOpReturnPrefix...)
	opReturnPayload = append(opReturnPayload, g.InitialState.Encode()...)
	// Append ANF hash so verifiers can confirm the covenant logic.
	if len(g.ANF) > 0 {
		anfHash := sha256.Sum256(g.ANF)
		opReturnPayload = append(opReturnPayload, anfHash[:]...)
	}

	opReturnScript := buildOpReturnScript(opReturnPayload)

	// Build outputs.
	outputs := []BSVOutput{
		// Output 0: covenant UTXO.
		{
			Value:  covenantSats,
			Script: g.LockingScript,
		},
		// Output 1: OP_RETURN with genesis config.
		{
			Value:  0,
			Script: opReturnScript,
		},
		// Output 2: change output (placeholder).
		{
			Value:  0,
			Script: buildP2PKHScript(changeAddress),
		},
	}

	tx := &BSVTx{
		Version:  1,
		Inputs:   inputs,
		Outputs:  outputs,
		LockTime: 0,
	}

	// Estimate fee from serialized size (50 sat/KB).
	rawSize := uint64(len(tx.Serialize()))
	estimatedFee := (rawSize * defaultFeeRate) / 1000
	if estimatedFee == 0 {
		estimatedFee = 1 // minimum 1 satoshi fee
	}

	totalNeeded := covenantSats + estimatedFee
	if fundingInput.Satoshis < totalNeeded {
		return nil, fmt.Errorf("insufficient funding: have %d satoshis, need %d (covenant %d + fee %d)",
			fundingInput.Satoshis, totalNeeded, covenantSats, estimatedFee)
	}

	// Set change amount.
	changeAmount := fundingInput.Satoshis - covenantSats - estimatedFee
	tx.Outputs[2].Value = changeAmount

	return tx, nil
}
