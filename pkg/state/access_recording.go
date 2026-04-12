package state

import (
	"sync"

	"github.com/icellan/bsvm/pkg/types"
)

// AccessRecording holds the cumulative set of all accounts and storage
// slots accessed during a batch execution. This is used by the prover
// to determine which state to export for the SP1 guest.
type AccessRecording struct {
	// Accounts lists all accounts that were accessed (read or written).
	Accounts []types.Address
	// Slots maps each account address to the storage slots accessed for
	// that account.
	Slots map[types.Address][]types.Hash
}

// accessRecorder tracks which accounts and storage slots are accessed
// during EVM execution. It is separate from the per-transaction EIP-2929
// access list: this recorder spans an entire batch and is used for prover
// state export.
type accessRecorder struct {
	mu       sync.Mutex
	accounts map[types.Address]struct{}
	slots    map[types.Address]map[types.Hash]struct{}
}

// newAccessRecorder creates a new access recorder.
func newAccessRecorder() *accessRecorder {
	return &accessRecorder{
		accounts: make(map[types.Address]struct{}),
		slots:    make(map[types.Address]map[types.Hash]struct{}),
	}
}

// recordAccount records that the given address was accessed.
func (r *accessRecorder) recordAccount(addr types.Address) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.accounts[addr] = struct{}{}
}

// recordSlot records that the given storage slot was accessed for the
// given address.
func (r *accessRecorder) recordSlot(addr types.Address, slot types.Hash) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.accounts[addr] = struct{}{}
	if r.slots[addr] == nil {
		r.slots[addr] = make(map[types.Hash]struct{})
	}
	r.slots[addr][slot] = struct{}{}
}

// result returns an AccessRecording containing all recorded accounts and
// storage slots.
func (r *accessRecorder) result() *AccessRecording {
	r.mu.Lock()
	defer r.mu.Unlock()

	rec := &AccessRecording{
		Slots: make(map[types.Address][]types.Hash),
	}
	for addr := range r.accounts {
		rec.Accounts = append(rec.Accounts, addr)
	}
	for addr, slots := range r.slots {
		for slot := range slots {
			rec.Slots[addr] = append(rec.Slots[addr], slot)
		}
	}
	return rec
}

// StartAccessRecording begins recording all account and storage slot
// accesses across multiple transactions. This is separate from the
// per-transaction EIP-2929 access list (which resets each tx). Call
// this before executing a batch of transactions.
func (s *StateDB) StartAccessRecording() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.accessRecorder = newAccessRecorder()
}

// StopAccessRecording stops recording and returns the cumulative set
// of all accounts and storage slots accessed since StartAccessRecording.
// This is used to determine which state to export for the SP1 guest.
func (s *StateDB) StopAccessRecording() *AccessRecording {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.accessRecorder == nil {
		return &AccessRecording{
			Slots: make(map[types.Address][]types.Hash),
		}
	}
	result := s.accessRecorder.result()
	s.accessRecorder = nil
	return result
}

// recordAccountAccess records an account access if recording is active.
func (s *StateDB) recordAccountAccess(addr types.Address) {
	if s.accessRecorder != nil {
		s.accessRecorder.recordAccount(addr)
	}
}

// recordSlotAccess records a storage slot access if recording is active.
func (s *StateDB) recordSlotAccess(addr types.Address, slot types.Hash) {
	if s.accessRecorder != nil {
		s.accessRecorder.recordSlot(addr, slot)
	}
}
