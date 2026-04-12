package covenant

import (
	"fmt"

	"github.com/icellan/bsvm/pkg/types"
)

// BridgeManager tracks the bridge covenant UTXO chain and manages
// deposit/withdrawal operations. It maintains the current state of the
// bridge (balance, withdrawal nonce) and the current UTXO location
// (txid, vout, satoshis).
//
// The manager does not broadcast transactions — actual BSV transaction
// construction and broadcast requires a BSV SDK (Milestone 5). It prepares
// the data needed to build bridge deposit and withdrawal transactions.
type BridgeManager struct {
	currentTxID       types.Hash
	currentVout       uint32
	currentSats       uint64
	currentState      BridgeState
	stateCovenantTxID types.Hash // Reference to main state covenant
}

// BridgeDepositData holds data needed to build a deposit BSV transaction.
type BridgeDepositData struct {
	PrevTxID     types.Hash
	PrevVout     uint32
	DepositSats  uint64
	NewState     BridgeState
	CovenantSats uint64
}

// BridgeWithdrawalData holds data needed to build a withdrawal BSV transaction.
type BridgeWithdrawalData struct {
	PrevTxID       types.Hash
	PrevVout       uint32
	BsvAddress     []byte
	SatoshiAmount  uint64
	Nonce          uint64
	WithdrawalRoot types.Hash
	MerkleProof    [][]byte
	MerkleIndex    uint64
	NewState       BridgeState
	CovenantSats   uint64
}

// NewBridgeManager creates a new bridge manager with the given initial state.
func NewBridgeManager(
	genesisTxID types.Hash,
	genesisVout uint32,
	sats uint64,
	initialState BridgeState,
	stateCovenantTxID types.Hash,
) *BridgeManager {
	return &BridgeManager{
		currentTxID:       genesisTxID,
		currentVout:       genesisVout,
		currentSats:       sats,
		currentState:      initialState,
		stateCovenantTxID: stateCovenantTxID,
	}
}

// CurrentState returns the current bridge state.
func (bm *BridgeManager) CurrentState() BridgeState {
	return bm.currentState
}

// CurrentTxID returns the current bridge covenant UTXO transaction ID.
func (bm *BridgeManager) CurrentTxID() types.Hash {
	return bm.currentTxID
}

// CurrentVout returns the current bridge covenant UTXO output index.
func (bm *BridgeManager) CurrentVout() uint32 {
	return bm.currentVout
}

// StateCovenantTxID returns the reference to the main state covenant.
func (bm *BridgeManager) StateCovenantTxID() types.Hash {
	return bm.stateCovenantTxID
}

// BuildDepositData prepares data for a deposit transaction. The deposit
// amount must be positive. The new state will have the balance increased
// by the deposit amount.
func (bm *BridgeManager) BuildDepositData(depositSatoshis uint64) (*BridgeDepositData, error) {
	if depositSatoshis == 0 {
		return nil, fmt.Errorf("deposit amount must be greater than zero")
	}

	newState := BridgeState{
		Balance:         bm.currentState.Balance + depositSatoshis,
		WithdrawalNonce: bm.currentState.WithdrawalNonce,
	}

	return &BridgeDepositData{
		PrevTxID:     bm.currentTxID,
		PrevVout:     bm.currentVout,
		DepositSats:  depositSatoshis,
		NewState:     newState,
		CovenantSats: bm.currentSats + depositSatoshis,
	}, nil
}

// BuildWithdrawalData prepares data for a withdrawal transaction. The
// withdrawal amount must be positive and not exceed the current balance.
// The withdrawal root and Merkle proof are used to verify the withdrawal
// on-chain against the state covenant's committed withdrawal root.
func (bm *BridgeManager) BuildWithdrawalData(
	bsvAddress []byte,
	satoshiAmount uint64,
	withdrawalRoot types.Hash,
	merkleProof [][]byte,
	merkleIndex uint64,
) (*BridgeWithdrawalData, error) {
	if satoshiAmount == 0 {
		return nil, fmt.Errorf("withdrawal amount must be greater than zero")
	}
	if satoshiAmount > bm.currentState.Balance {
		return nil, fmt.Errorf("insufficient balance: have %d, want %d", bm.currentState.Balance, satoshiAmount)
	}
	if len(bsvAddress) != 20 {
		return nil, fmt.Errorf("bsv address must be 20 bytes, got %d", len(bsvAddress))
	}
	if len(merkleProof) == 0 {
		return nil, fmt.Errorf("merkle proof must not be empty")
	}

	newState := BridgeState{
		Balance:         bm.currentState.Balance - satoshiAmount,
		WithdrawalNonce: bm.currentState.WithdrawalNonce + 1,
	}

	return &BridgeWithdrawalData{
		PrevTxID:       bm.currentTxID,
		PrevVout:       bm.currentVout,
		BsvAddress:     bsvAddress,
		SatoshiAmount:  satoshiAmount,
		Nonce:          bm.currentState.WithdrawalNonce,
		WithdrawalRoot: withdrawalRoot,
		MerkleProof:    merkleProof,
		MerkleIndex:    merkleIndex,
		NewState:       newState,
		CovenantSats:   bm.currentSats - satoshiAmount,
	}, nil
}

// ApplyDeposit updates bridge state after a deposit transaction is confirmed.
// The newTxID is the transaction ID of the deposit transaction.
func (bm *BridgeManager) ApplyDeposit(newTxID types.Hash, amount uint64) {
	bm.currentTxID = newTxID
	bm.currentVout = 0 // Bridge covenant output is always at index 0
	bm.currentState.Balance += amount
	bm.currentSats += amount
}

// ApplyWithdrawal updates bridge state after a withdrawal transaction is confirmed.
// The newTxID is the transaction ID of the withdrawal transaction.
func (bm *BridgeManager) ApplyWithdrawal(newTxID types.Hash, amount uint64) {
	bm.currentTxID = newTxID
	bm.currentVout = 0 // Bridge covenant output is always at index 0
	bm.currentState.Balance -= amount
	bm.currentState.WithdrawalNonce++
	bm.currentSats -= amount
}
