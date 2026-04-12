package covenant

import (
	"crypto/sha256"
	"fmt"
	"testing"

	"github.com/icellan/bsvm/pkg/types"
)

// ---------------------------------------------------------------------------
// mockPersister
// ---------------------------------------------------------------------------

// mockPersister implements CovenantPersister for testing.
type mockPersister struct {
	state     []byte
	txID      types.Hash
	writeFail bool // if true, Write methods return an error
	stateCalls int
	txIDCalls  int
}

func (m *mockPersister) WriteCovenantState(state []byte) error {
	m.stateCalls++
	if m.writeFail {
		return fmt.Errorf("mock write state error")
	}
	m.state = make([]byte, len(state))
	copy(m.state, state)
	return nil
}

func (m *mockPersister) WriteCovenantTxID(txid types.Hash) error {
	m.txIDCalls++
	if m.writeFail {
		return fmt.Errorf("mock write txid error")
	}
	m.txID = txid
	return nil
}

func (m *mockPersister) ReadCovenantState() []byte {
	if m.state == nil {
		return nil
	}
	cp := make([]byte, len(m.state))
	copy(cp, m.state)
	return cp
}

func (m *mockPersister) ReadCovenantTxID() types.Hash {
	return m.txID
}

// ---------------------------------------------------------------------------
// TestApplyAdvance_Persists
// ---------------------------------------------------------------------------

// TestApplyAdvance_Persists verifies that ApplyAdvance persists both state
// and txid when a persister is set.
func TestApplyAdvance_Persists(t *testing.T) {
	cov := &CompiledCovenant{
		LockingScript: []byte{0x01},
		StateSize:     3,
		ScriptHash:    sha256.Sum256([]byte{0x01}),
	}
	initialState := CovenantState{
		StateRoot:   testStateRoot(0),
		BlockNumber: 0,
		Frozen:      0,
	}
	cm := NewCovenantManager(cov, types.Hash{}, 0, DefaultCovenantSats, initialState, 1, VerifyGroth16)

	p := &mockPersister{}
	cm.SetPersister(p)

	newState := CovenantState{
		StateRoot:   testStateRoot(1),
		BlockNumber: 1,
		Frozen:      0,
	}
	newTxID := types.BytesToHash([]byte{0xaa, 0xbb})

	err := cm.ApplyAdvance(newTxID, newState)
	if err != nil {
		t.Fatalf("ApplyAdvance failed: %v", err)
	}

	// Verify WriteCovenantState was called.
	if p.stateCalls != 1 {
		t.Errorf("WriteCovenantState called %d times, want 1", p.stateCalls)
	}

	// Verify WriteCovenantTxID was called.
	if p.txIDCalls != 1 {
		t.Errorf("WriteCovenantTxID called %d times, want 1", p.txIDCalls)
	}

	// Verify persisted state matches.
	decoded, err := DecodeCovenantState(p.state)
	if err != nil {
		t.Fatalf("decoding persisted state: %v", err)
	}
	if decoded.BlockNumber != 1 {
		t.Errorf("persisted block number = %d, want 1", decoded.BlockNumber)
	}
	if decoded.StateRoot != testStateRoot(1) {
		t.Error("persisted state root mismatch")
	}

	// Verify persisted txid matches.
	if p.txID != newTxID {
		t.Errorf("persisted txid = %x, want %x", p.txID, newTxID)
	}
}

// ---------------------------------------------------------------------------
// TestApplyAdvance_NoPersister
// ---------------------------------------------------------------------------

// TestApplyAdvance_NoPersister verifies that ApplyAdvance succeeds without
// error when no persister is set.
func TestApplyAdvance_NoPersister(t *testing.T) {
	cov := &CompiledCovenant{
		LockingScript: []byte{0x01},
		StateSize:     3,
	}
	initialState := CovenantState{
		StateRoot:   testStateRoot(0),
		BlockNumber: 0,
		Frozen:      0,
	}
	cm := NewCovenantManager(cov, types.Hash{}, 0, DefaultCovenantSats, initialState, 1, VerifyGroth16)

	// No persister set — should succeed without error.
	newState := CovenantState{
		StateRoot:   testStateRoot(1),
		BlockNumber: 1,
		Frozen:      0,
	}
	err := cm.ApplyAdvance(types.BytesToHash([]byte{0x01}), newState)
	if err != nil {
		t.Fatalf("ApplyAdvance without persister should succeed: %v", err)
	}

	// State should be updated in memory.
	if cm.CurrentState().BlockNumber != 1 {
		t.Errorf("block number = %d, want 1", cm.CurrentState().BlockNumber)
	}
}

// ---------------------------------------------------------------------------
// TestApplyAdvance_PersisterError
// ---------------------------------------------------------------------------

// TestApplyAdvance_PersisterError verifies that errors from the persister
// are propagated back from ApplyAdvance.
func TestApplyAdvance_PersisterError(t *testing.T) {
	cov := &CompiledCovenant{
		LockingScript: []byte{0x01},
		StateSize:     3,
	}
	initialState := CovenantState{
		StateRoot:   testStateRoot(0),
		BlockNumber: 0,
		Frozen:      0,
	}
	cm := NewCovenantManager(cov, types.Hash{}, 0, DefaultCovenantSats, initialState, 1, VerifyGroth16)

	p := &mockPersister{writeFail: true}
	cm.SetPersister(p)

	newState := CovenantState{
		StateRoot:   testStateRoot(1),
		BlockNumber: 1,
		Frozen:      0,
	}
	err := cm.ApplyAdvance(types.BytesToHash([]byte{0x01}), newState)
	if err == nil {
		t.Fatal("expected error when persister fails")
	}

	// Verify the error message contains useful context.
	if err.Error() != "persisting covenant state: mock write state error" {
		t.Errorf("unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// TestLoadPersistedState
// ---------------------------------------------------------------------------

// TestLoadPersistedState verifies that LoadPersistedState correctly loads
// state from a persister and updates the manager's internal state.
func TestLoadPersistedState(t *testing.T) {
	cov := &CompiledCovenant{
		LockingScript: []byte{0x01},
		StateSize:     3,
	}
	initialState := CovenantState{
		StateRoot:   testStateRoot(0),
		BlockNumber: 0,
		Frozen:      0,
	}
	cm := NewCovenantManager(cov, types.Hash{}, 0, DefaultCovenantSats, initialState, 1, VerifyGroth16)

	// Prepare persisted state.
	persistedState := CovenantState{
		StateRoot:          testStateRoot(42),
		BlockNumber:        42,
		Frozen:             0,
		AdvancesSinceInbox: 3,
	}
	persistedTxID := types.BytesToHash([]byte{0xde, 0xad, 0xbe, 0xef})

	p := &mockPersister{
		state: persistedState.Encode(),
		txID:  persistedTxID,
	}

	// Load persisted state.
	loaded := cm.LoadPersistedState(p)
	if !loaded {
		t.Fatal("LoadPersistedState should return true when state exists")
	}

	// Verify state was loaded.
	if cm.CurrentState().BlockNumber != 42 {
		t.Errorf("block number = %d, want 42", cm.CurrentState().BlockNumber)
	}
	if cm.CurrentState().StateRoot != testStateRoot(42) {
		t.Error("state root mismatch after load")
	}
	if cm.CurrentState().AdvancesSinceInbox != 3 {
		t.Errorf("advances since inbox = %d, want 3", cm.CurrentState().AdvancesSinceInbox)
	}
	if cm.CurrentTxID() != persistedTxID {
		t.Errorf("txid = %x, want %x", cm.CurrentTxID(), persistedTxID)
	}

	// Verify persister was set.
	// Advance and check persistence works.
	newState := CovenantState{
		StateRoot:   testStateRoot(43),
		BlockNumber: 43,
		Frozen:      0,
	}
	err := cm.ApplyAdvance(types.BytesToHash([]byte{0x01}), newState)
	if err != nil {
		t.Fatalf("ApplyAdvance after load failed: %v", err)
	}
	if p.stateCalls != 1 {
		t.Errorf("WriteCovenantState called %d times, want 1", p.stateCalls)
	}
}

// TestLoadPersistedState_Empty verifies that LoadPersistedState returns false
// when no state is persisted.
func TestLoadPersistedState_Empty(t *testing.T) {
	cov := &CompiledCovenant{
		LockingScript: []byte{0x01},
		StateSize:     3,
	}
	initialState := CovenantState{
		StateRoot:   testStateRoot(0),
		BlockNumber: 0,
		Frozen:      0,
	}
	cm := NewCovenantManager(cov, types.Hash{}, 0, DefaultCovenantSats, initialState, 1, VerifyGroth16)

	p := &mockPersister{} // no state

	loaded := cm.LoadPersistedState(p)
	if loaded {
		t.Fatal("LoadPersistedState should return false when no state exists")
	}

	// Original state should be preserved.
	if cm.CurrentState().BlockNumber != 0 {
		t.Errorf("block number should remain 0, got %d", cm.CurrentState().BlockNumber)
	}
}
