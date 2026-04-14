package covenant

import (
	"fmt"

	"github.com/icellan/bsvm/pkg/types"
)

// FeeInput represents a BSV UTXO used to pay mining fees.
type FeeInput struct {
	TxID     types.Hash
	Vout     uint32
	Satoshis uint64
	Script   []byte // locking script
}

// AdvanceTransaction holds the constructed (unsigned) BSV transaction
// for a covenant advance.
type AdvanceTransaction struct {
	// RawTx is the serialized BSV transaction (unsigned).
	RawTx []byte
	// TxID is the transaction hash.
	TxID types.Hash
	// CovenantInputIndex is the index of the covenant UTXO input (always 0).
	CovenantInputIndex int
	// FeeInputIndices are the indices of fee UTXO inputs.
	FeeInputIndices []int
	// NewCovenantTxID is the txid of the new covenant output.
	NewCovenantTxID types.Hash
	// NewCovenantVout is the output index of the new covenant output.
	NewCovenantVout uint32
	// TotalFee is the mining fee paid in satoshis.
	TotalFee uint64
}

// defaultFeeRate is the fee rate in satoshis per kilobyte (50 sat/KB).
const defaultFeeRate = uint64(50)

// CovenantPersister is the interface for persisting covenant state.
// Implementations include ChainDB in pkg/block/.
type CovenantPersister interface {
	WriteCovenantState(state []byte) error
	WriteCovenantTxID(txid types.Hash) error
	ReadCovenantState() []byte
	ReadCovenantTxID() types.Hash
}

// CovenantManager tracks the covenant UTXO chain and builds advance transactions.
// It maintains the current state of the covenant (state root, block number,
// frozen flag) and the current UTXO location (txid, vout, satoshis).
//
// The manager does not broadcast transactions — actual BSV transaction
// construction and broadcast requires a BSV SDK (Milestone 5). It prepares
// the data needed to build covenant-advance transactions.
type CovenantManager struct {
	covenant        *CompiledCovenant
	genesisTxID     types.Hash
	currentTxID     types.Hash
	currentVout     uint32
	currentSats     uint64
	currentState    CovenantState
	chainID         uint64
	verification    VerificationMode
	governance      GovernanceConfig
	persister       CovenantPersister
	broadcastClient BroadcastClient
}

// AdvanceData holds everything needed to build a covenant-advance BSV transaction.
// The actual transaction construction requires a BSV SDK (Milestone 5).
type AdvanceData struct {
	PrevTxID     types.Hash
	PrevVout     uint32
	NewState     CovenantState
	BatchData    []byte
	Proof        []byte
	PublicValues []byte
	CovenantSats uint64
}

// NewCovenantManager creates a new covenant manager with the given compiled
// covenant and initial UTXO state. The genesisTxID and genesisVout identify
// the current covenant UTXO on the BSV blockchain.
func NewCovenantManager(
	covenant *CompiledCovenant,
	genesisTxID types.Hash,
	genesisVout uint32,
	sats uint64,
	initialState CovenantState,
	chainID uint64,
	verification VerificationMode,
) *CovenantManager {
	return &CovenantManager{
		covenant:     covenant,
		genesisTxID:  genesisTxID,
		currentTxID:  genesisTxID,
		verification: verification,
		currentVout:  genesisVout,
		currentSats:  sats,
		currentState: initialState,
		chainID:      chainID,
	}
}

// CurrentState returns the current covenant state.
func (cm *CovenantManager) CurrentState() CovenantState {
	return cm.currentState
}

// CurrentTxID returns the current covenant UTXO transaction ID.
func (cm *CovenantManager) CurrentTxID() types.Hash {
	return cm.currentTxID
}

// CurrentVout returns the current covenant UTXO output index.
func (cm *CovenantManager) CurrentVout() uint32 {
	return cm.currentVout
}

// VerificationMode returns the on-chain verification mode for this covenant.
func (cm *CovenantManager) VerificationMode() VerificationMode {
	return cm.verification
}

// GenesisTxID returns the genesis covenant UTXO transaction ID.
func (cm *CovenantManager) GenesisTxID() types.Hash {
	return cm.genesisTxID
}

// GovernanceConfig returns the governance configuration for this covenant.
func (cm *CovenantManager) GovernanceConfig() GovernanceConfig {
	return cm.governance
}

// SetGovernanceConfig sets the governance configuration on the manager.
// This is typically called after construction when the governance config
// is available from the genesis configuration.
func (cm *CovenantManager) SetGovernanceConfig(gov GovernanceConfig) {
	cm.governance = gov
}

// SetPersister sets the persistence backend for covenant state. When set,
// ApplyAdvance will persist state and txid after each advance.
func (cm *CovenantManager) SetPersister(p CovenantPersister) {
	cm.persister = p
}

// LoadPersistedState loads covenant state from the persister. Returns true if
// persisted state was found and loaded, false if no persisted state exists.
// This should be called on startup to restore state from a previous session.
func (cm *CovenantManager) LoadPersistedState(p CovenantPersister) bool {
	stateData := p.ReadCovenantState()
	if stateData == nil {
		return false
	}

	state, err := DecodeCovenantState(stateData)
	if err != nil {
		return false
	}

	txID := p.ReadCovenantTxID()

	cm.currentState = *state
	cm.currentTxID = txID
	cm.currentVout = 0
	cm.persister = p
	return true
}

// Covenant returns the compiled covenant associated with this manager.
func (cm *CovenantManager) Covenant() *CompiledCovenant {
	return cm.covenant
}

// BuildAdvanceData prepares the data needed to build a covenant-advance BSV
// transaction. It validates the new state and returns an AdvanceData struct
// containing all components needed for the transaction.
//
// The actual BSV transaction construction requires a BSV SDK (Milestone 5).
// This method validates:
//   - The shard is not frozen
//   - The block number increments by exactly 1
//   - The proof and public values are non-empty
//   - The batch data is non-empty
func (cm *CovenantManager) BuildAdvanceData(
	newState CovenantState,
	batchData []byte,
	proof []byte,
	publicValues []byte,
) (*AdvanceData, error) {
	if cm.currentState.Frozen != 0 {
		return nil, fmt.Errorf("covenant is frozen, cannot advance state")
	}
	if newState.BlockNumber != cm.currentState.BlockNumber+1 {
		return nil, fmt.Errorf("block number must increment by 1: current %d, proposed %d",
			cm.currentState.BlockNumber, newState.BlockNumber)
	}
	if len(proof) == 0 {
		return nil, fmt.Errorf("proof must not be empty")
	}
	if len(publicValues) == 0 {
		return nil, fmt.Errorf("public values must not be empty")
	}
	if len(batchData) == 0 {
		return nil, fmt.Errorf("batch data must not be empty")
	}

	return &AdvanceData{
		PrevTxID:     cm.currentTxID,
		PrevVout:     cm.currentVout,
		NewState:     newState,
		BatchData:    batchData,
		Proof:        proof,
		PublicValues: publicValues,
		CovenantSats: cm.currentSats,
	}, nil
}

// ApplyAdvance updates the manager's state after a successful covenant advance.
// This should be called after the BSV transaction has been broadcast and confirmed.
// The newTxID is the transaction ID of the advance transaction.
// If a persister is set, the state and txid are persisted to disk.
func (cm *CovenantManager) ApplyAdvance(newTxID types.Hash, newState CovenantState) error {
	cm.currentTxID = newTxID
	cm.currentVout = 0 // Covenant output is always at index 0
	cm.currentState = newState

	if cm.persister != nil {
		if err := cm.persister.WriteCovenantState(newState.Encode()); err != nil {
			return fmt.Errorf("persisting covenant state: %w", err)
		}
		if err := cm.persister.WriteCovenantTxID(newTxID); err != nil {
			return fmt.Errorf("persisting covenant txid: %w", err)
		}
	}
	return nil
}

// AdvanceState builds a BSV transaction that advances the covenant UTXO chain.
// The transaction spends the current covenant UTXO and creates:
//
//	Output 0: New covenant UTXO (same script, new state)
//	Output 1: OP_RETURN with batch data (BSVM\x02 format)
//	Output 2: Prover change output
//
// The method does NOT broadcast the transaction — that is the caller's
// responsibility (via BSV node RPC or ARC).
func (cm *CovenantManager) AdvanceState(
	newState CovenantState,
	batchData []byte,
	proof []byte,
	publicValues []byte,
	feeUTXOs []FeeInput,
	changeAddress []byte,
) (*AdvanceTransaction, error) {
	// Validate via BuildAdvanceData (checks frozen, block number, non-empty inputs).
	advData, err := cm.BuildAdvanceData(newState, batchData, proof, publicValues)
	if err != nil {
		return nil, err
	}

	if len(feeUTXOs) == 0 {
		return nil, fmt.Errorf("at least one fee UTXO is required")
	}
	if len(changeAddress) == 0 {
		return nil, fmt.Errorf("change address must not be empty")
	}

	// Build unlock script for the covenant input.
	unlockScript, err := BuildUnlockScript(advData)
	if err != nil {
		return nil, fmt.Errorf("building unlock script: %w", err)
	}

	// Build transaction inputs.
	inputs := make([]BSVInput, 0, 1+len(feeUTXOs))

	// Input 0: covenant UTXO.
	inputs = append(inputs, BSVInput{
		PrevTxID: cm.currentTxID,
		PrevVout: cm.currentVout,
		Script:   unlockScript,
		Sequence: 0xffffffff,
	})

	// Fee UTXO inputs.
	feeInputIndices := make([]int, len(feeUTXOs))
	var totalFeeInputSats uint64
	for i, feeUTXO := range feeUTXOs {
		inputs = append(inputs, BSVInput{
			PrevTxID: feeUTXO.TxID,
			PrevVout: feeUTXO.Vout,
			Script:   nil, // unsigned — caller signs later
			Sequence: 0xffffffff,
		})
		feeInputIndices[i] = i + 1
		totalFeeInputSats += feeUTXO.Satoshis
	}

	// Build transaction outputs.
	outputs := make([]BSVOutput, 0, 3)

	// Output 0: new covenant UTXO with same locking script and same satoshis.
	outputs = append(outputs, BSVOutput{
		Value:  cm.currentSats,
		Script: cm.covenant.LockingScript,
	})

	// Output 1: OP_RETURN with batch data.
	opReturnScript := buildOpReturnScript(batchData)
	outputs = append(outputs, BSVOutput{
		Value:  0,
		Script: opReturnScript,
	})

	// Output 2: change output (placeholder — we compute fee after sizing).
	changeScript := buildP2PKHScript(changeAddress)
	outputs = append(outputs, BSVOutput{
		Value:  0, // placeholder
		Script: changeScript,
	})

	// Build the transaction to estimate size.
	tx := &BSVTx{
		Version:  1,
		Inputs:   inputs,
		Outputs:  outputs,
		LockTime: 0,
	}

	// Estimate fee from serialized size.
	rawSize := uint64(len(tx.Serialize()))
	estimatedFee := (rawSize * defaultFeeRate) / 1000
	if estimatedFee == 0 {
		estimatedFee = 1 // minimum 1 satoshi fee
	}

	if totalFeeInputSats < estimatedFee {
		return nil, fmt.Errorf("insufficient fee inputs: have %d satoshis, need %d for estimated fee",
			totalFeeInputSats, estimatedFee)
	}

	// Set change amount.
	changeAmount := totalFeeInputSats - estimatedFee
	tx.Outputs[2].Value = changeAmount

	// Re-serialize with correct change amount.
	rawTx := tx.Serialize()
	txID := tx.TxID()

	return &AdvanceTransaction{
		RawTx:              rawTx,
		TxID:               txID,
		CovenantInputIndex: 0,
		FeeInputIndices:    feeInputIndices,
		NewCovenantTxID:    txID,
		NewCovenantVout:    0,
		TotalFee:           estimatedFee,
	}, nil
}

// buildP2PKHScript creates a standard P2PKH locking script for a 20-byte
// address hash: OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
func buildP2PKHScript(addrHash []byte) []byte {
	script := make([]byte, 0, 25)
	script = append(script, 0x76) // OP_DUP
	script = append(script, 0xa9) // OP_HASH160
	script = append(script, 0x14) // PUSH20
	script = append(script, addrHash...)
	script = append(script, 0x88) // OP_EQUALVERIFY
	script = append(script, 0xac) // OP_CHECKSIG
	return script
}
