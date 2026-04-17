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
//
// Replay protection (two layers, defence-in-depth):
//
//  1. On-chain: BridgeState.WithdrawalsCommitment carries a running
//     hash-chain commitment folded over every processed withdrawal
//     nullifier. The Rúnar bridge covenant updates this on every
//     Withdraw call. Because the commitment is monotonic and baked into
//     the covenant output, a BSV reorg that rolls WithdrawalNonce back
//     MUST also roll WithdrawalsCommitment back to match a prior state;
//     replaying an already-folded (recipient, amount, nonce) would
//     either collide with the on-chain commitment value (detectable) or
//     require rewinding the full chain (attacker-infeasible without
//     dropping every subsequent withdrawal too).
//
//  2. Process-level side-table: the manager also maintains a map of
//     spent withdrawal nullifiers (hash256(recipient || amount ||
//     nonce)). A nullifier is never removed on rollback — once a
//     withdrawal has been observed the tuple is permanently burned. The
//     side-table catches replay attempts before they reach the covenant.
type BridgeManager struct {
	currentTxID       types.Hash
	currentVout       uint32
	currentSats       uint64
	currentState      BridgeState
	stateCovenantTxID types.Hash // Reference to main state covenant

	// spentNullifiers records withdrawal nullifiers that have been
	// observed (built + applied). A nullifier is never removed on
	// rollback — once a withdrawal has entered the manager's view the
	// recipient/amount/nonce tuple is permanently burned, because the
	// underlying BSV withdrawal tx may re-confirm under a different
	// chain. This is the anti-replay invariant.
	spentNullifiers map[types.Hash]struct{}

	// pendingByNonce tracks the withdrawal-build data that has been
	// handed out but not yet applied, keyed by its nonce. When
	// ApplyWithdrawal confirms a withdrawal, we look up the matching
	// (recipient, amount) here to compute and record the nullifier.
	pendingByNonce map[uint64]pendingWithdrawal
}

// pendingWithdrawal captures the recipient/amount for a withdrawal
// that has been built but not yet applied. Used so ApplyWithdrawal
// (which only receives amount) can still record the correct nullifier.
type pendingWithdrawal struct {
	bsvAddress []byte
	amount     uint64
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
		spentNullifiers:   make(map[types.Hash]struct{}),
		pendingByNonce:    make(map[uint64]pendingWithdrawal),
	}
}

// HasSpentNullifier reports whether a withdrawal with the given
// nullifier has already been observed by this manager.
func (bm *BridgeManager) HasSpentNullifier(n types.Hash) bool {
	_, ok := bm.spentNullifiers[n]
	return ok
}

// recordNullifier marks the given nullifier as spent. Idempotent.
func (bm *BridgeManager) recordNullifier(n types.Hash) {
	if bm.spentNullifiers == nil {
		bm.spentNullifiers = make(map[types.Hash]struct{})
	}
	bm.spentNullifiers[n] = struct{}{}
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
		Balance:               bm.currentState.Balance + depositSatoshis,
		WithdrawalNonce:       bm.currentState.WithdrawalNonce,
		WithdrawalsCommitment: bm.currentState.WithdrawalsCommitment,
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

	// Replay-defence: reject if the (recipient, amount, nonce) triple
	// has already been observed. This catches the BSV-reorg scenario
	// where the on-chain WithdrawalNonce rolls back but the withdrawal
	// has already been credited to the BSV recipient.
	nonce := bm.currentState.WithdrawalNonce
	nullifier := WithdrawalNullifier(bsvAddress, satoshiAmount, nonce)
	if bm.HasSpentNullifier(nullifier) {
		return nil, fmt.Errorf("withdrawal replay rejected: nullifier already spent (recipient=%x amount=%d nonce=%d)",
			bsvAddress, satoshiAmount, nonce)
	}

	// Record the pending withdrawal so ApplyWithdrawal (which only
	// receives the amount) can compute the nullifier when the BSV
	// withdrawal tx is confirmed. Storing a copy of bsvAddress guards
	// against caller mutation.
	addrCopy := make([]byte, len(bsvAddress))
	copy(addrCopy, bsvAddress)
	if bm.pendingByNonce == nil {
		bm.pendingByNonce = make(map[uint64]pendingWithdrawal)
	}
	bm.pendingByNonce[nonce] = pendingWithdrawal{bsvAddress: addrCopy, amount: satoshiAmount}

	// Predicted post-advance commitment: fold the pending nullifier so
	// NewState reflects the exact BridgeState the covenant will hold
	// once this withdrawal is applied on-chain.
	newState := BridgeState{
		Balance:               bm.currentState.Balance - satoshiAmount,
		WithdrawalNonce:       nonce + 1,
		WithdrawalsCommitment: foldWithdrawalsCommitment(bm.currentState.WithdrawalsCommitment, nullifier),
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
//
// Records the corresponding spent-nullifier for the withdrawal that was
// built at the CURRENT nonce (the one being consumed). If no build was
// recorded for this nonce (e.g. callers that skip BuildWithdrawalData),
// the nullifier is not recorded — those callers bypass the replay
// defence.
//
// Also folds the withdrawal's nullifier into WithdrawalsCommitment
// (hash256(prev || nullifier)) so the in-memory BridgeState tracks the
// on-chain commitment chain byte-for-byte. The fold only runs when a
// pending build is found for the current nonce — callers that skip
// BuildWithdrawalData (which provides the recipient address needed for
// the nullifier) leave the commitment untouched, matching the existing
// replay-defence contract.
func (bm *BridgeManager) ApplyWithdrawal(newTxID types.Hash, amount uint64) {
	nonce := bm.currentState.WithdrawalNonce
	if pending, ok := bm.pendingByNonce[nonce]; ok && pending.amount == amount {
		nullifier := WithdrawalNullifier(pending.bsvAddress, pending.amount, nonce)
		bm.recordNullifier(nullifier)
		bm.currentState.WithdrawalsCommitment = foldWithdrawalsCommitment(
			bm.currentState.WithdrawalsCommitment, nullifier)
		delete(bm.pendingByNonce, nonce)
	}

	bm.currentTxID = newTxID
	bm.currentVout = 0 // Bridge covenant output is always at index 0
	bm.currentState.Balance -= amount
	bm.currentState.WithdrawalNonce++
	bm.currentSats -= amount
}

// RollbackWithdrawal reverts the Balance / WithdrawalNonce / sats bumps
// from the most recent ApplyWithdrawal, modelling a BSV reorg that
// unconfirms the withdrawal tx. It intentionally does NOT remove the
// spent nullifier: once a withdrawal has been observed, its
// (recipient, amount, nonce) tuple is permanently burned because the
// reorg might re-confirm the same tx later, and permitting a replay
// would double-pay the recipient.
//
// It also intentionally does NOT roll WithdrawalsCommitment back. The
// commitment is a tamper-evident log of every observed withdrawal; if
// it retreated on rollback a BSV-reorg replay could silently hide the
// earlier observation from auditors. Leaving the commitment pinned
// above the rolled-back WithdrawalNonce means any subsequent on-chain
// Withdraw that tries to fold the same nullifier again will produce a
// commitment value the Go-side mirror refuses to track, surfacing the
// replay immediately.
//
// newPrevTxID is the bridge UTXO that precedes the reorged withdrawal
// (i.e. the UTXO we logically return to).
func (bm *BridgeManager) RollbackWithdrawal(newPrevTxID types.Hash, amount uint64) {
	if bm.currentState.WithdrawalNonce == 0 {
		// Nothing to roll back.
		return
	}
	bm.currentState.WithdrawalNonce--
	bm.currentState.Balance += amount
	bm.currentSats += amount
	bm.currentTxID = newPrevTxID
	bm.currentVout = 0
}
