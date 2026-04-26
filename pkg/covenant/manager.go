package covenant

import (
	"fmt"

	"github.com/icellan/bsvm/pkg/types"
)

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
	feeWallet       *FeeWallet
	stateChangeCB   func(prev, curr CovenantState)
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

// FeeWallet returns the fee wallet attached to this manager, or nil if
// none has been configured. The covenant manager does not use the fee
// wallet directly — it is held here so the overlay node and RPC layer
// can reach it through a single, stable handle without each layer
// owning its own pointer.
func (cm *CovenantManager) FeeWallet() *FeeWallet {
	return cm.feeWallet
}

// SetFeeWallet attaches (or replaces) the fee wallet. The wallet has no
// authority over the covenant — it only funds the BSV miner fee on
// covenant-advance transactions. Passing nil clears the wallet.
func (cm *CovenantManager) SetFeeWallet(fw *FeeWallet) {
	cm.feeWallet = fw
}

// SetStateChangeCallback registers a callback invoked after each
// successful ApplyAdvance with the previous and current covenant
// state. The overlay node uses this to detect Frozen-flag transitions
// and pause/unpause the batcher. Passing nil clears the callback.
//
// The callback runs synchronously inside ApplyAdvance and must not
// block the broadcast path. Callers that need to do non-trivial work
// should hand off to a goroutine.
func (cm *CovenantManager) SetStateChangeCallback(cb func(prev, curr CovenantState)) {
	cm.stateChangeCB = cb
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

// ValidateAdvanceData validates the data needed for a covenant advance.
func (cm *CovenantManager) ValidateAdvanceData(
	newState CovenantState,
	batchData []byte,
	proof []byte,
	publicValues []byte,
) error {
	if cm.currentState.Frozen != 0 {
		return fmt.Errorf("covenant is frozen, cannot advance state")
	}
	if newState.BlockNumber != cm.currentState.BlockNumber+1 {
		return fmt.Errorf("block number must increment by 1: current %d, proposed %d",
			cm.currentState.BlockNumber, newState.BlockNumber)
	}
	if len(proof) == 0 {
		return fmt.Errorf("proof must not be empty")
	}
	if len(publicValues) == 0 {
		return fmt.Errorf("public values must not be empty")
	}
	if len(batchData) == 0 {
		return fmt.Errorf("batch data must not be empty")
	}
	return nil
}

// ApplyAdvance updates the manager's state after a successful covenant advance.
// This should be called after the BSV transaction has been broadcast and confirmed.
// The newTxID is the transaction ID of the advance transaction.
// If a persister is set, the state and txid are persisted to disk.
//
// After persistence, any registered state-change callback is invoked
// with the previous and new state so observers (e.g. the overlay's
// governance monitor) can react to Frozen-flag transitions.
func (cm *CovenantManager) ApplyAdvance(newTxID types.Hash, newState CovenantState) error {
	prevState := cm.currentState
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
	if cm.stateChangeCB != nil {
		cm.stateChangeCB(prevState, newState)
	}
	return nil
}
