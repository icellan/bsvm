// Copyright 2016 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// Adapted from go-ethereum core/state/journal.go for the BSVM project.

package state

import (
	"log/slog"
	"maps"
	"slices"
	"sort"

	"github.com/holiman/uint256"

	"github.com/icellan/bsvm/pkg/crypto"
	"github.com/icellan/bsvm/pkg/types"
)

type revision struct {
	id           int
	journalIndex int
}

// journalEntry is a modification entry in the state change journal that can be
// reverted on demand.
type journalEntry interface {
	// revert undoes the changes introduced by this journal entry.
	revert(*StateDB)

	// dirtied returns the Ethereum address modified by this journal entry.
	dirtied() *types.Address

	// copy returns a deep-copied journal entry.
	copy() journalEntry
}

// journal contains the list of state modifications applied since the last state
// commit. These are tracked to be able to be reverted in the case of an execution
// exception or request for reversal.
type journal struct {
	entries []journalEntry        // Current changes tracked by the journal
	dirties map[types.Address]int // Dirty accounts and the number of changes

	validRevisions []revision
	nextRevisionID int
}

// newJournal creates a new initialized journal.
func newJournal() *journal {
	return &journal{
		dirties: make(map[types.Address]int),
	}
}

// reset clears the journal, after this operation the journal can be used anew.
// It is semantically similar to calling 'newJournal', but the underlying slices
// can be reused.
func (j *journal) reset() {
	j.entries = j.entries[:0]
	j.validRevisions = j.validRevisions[:0]
	clear(j.dirties)
	j.nextRevisionID = 0
}

// snapshot returns an identifier for the current revision of the state.
// No depth limit is imposed — geth does not limit snapshot depth, and
// the EVM call depth limit (1024) is the correct guard at a different
// layer. Snapshots accumulate across all calls in a transaction (not
// just nested ones), so the count can exceed the call depth limit.
func (j *journal) snapshot() int {
	id := j.nextRevisionID
	j.nextRevisionID++
	j.validRevisions = append(j.validRevisions, revision{id, j.length()})
	return id
}

// revertToSnapshot reverts all state changes made since the given revision.
// If the revision id is not found the call is silently ignored. This
// avoids crashing the node when a stale or invalid snapshot id is
// presented — the EVM interface does not permit returning an error
// from RevertToSnapshot.
func (j *journal) revertToSnapshot(revid int, s *StateDB) {
	// Find the snapshot in the stack of valid snapshots.
	idx := sort.Search(len(j.validRevisions), func(i int) bool {
		return j.validRevisions[i].id >= revid
	})
	if idx == len(j.validRevisions) || j.validRevisions[idx].id != revid {
		slog.Warn("revertToSnapshot called with unknown revision", "revid", revid)
		return
	}
	snapshot := j.validRevisions[idx].journalIndex

	// Replay the journal to undo changes and remove invalidated snapshots
	j.revert(s, snapshot)
	j.validRevisions = j.validRevisions[:idx]
}

// append inserts a new modification entry to the end of the change journal.
func (j *journal) append(entry journalEntry) {
	j.entries = append(j.entries, entry)
	if addr := entry.dirtied(); addr != nil {
		j.dirties[*addr]++
	}
}

// revert undoes a batch of journalled modifications along with any reverted
// dirty handling too.
func (j *journal) revert(statedb *StateDB, snapshot int) {
	for i := len(j.entries) - 1; i >= snapshot; i-- {
		// Undo the changes made by the operation
		j.entries[i].revert(statedb)

		// Drop any dirty tracking induced by the change
		if addr := j.entries[i].dirtied(); addr != nil {
			if j.dirties[*addr]--; j.dirties[*addr] == 0 {
				delete(j.dirties, *addr)
			}
		}
	}
	j.entries = j.entries[:snapshot]
}

// dirty explicitly sets an address to dirty, even if the change entries would
// otherwise suggest it as clean. This method is an ugly hack to handle the RIPEMD
// precompile consensus exception.
func (j *journal) dirty(addr types.Address) {
	j.dirties[addr]++
}

// length returns the current number of entries in the journal.
func (j *journal) length() int {
	return len(j.entries)
}

// copy returns a deep-copied journal.
func (j *journal) copy() *journal {
	entries := make([]journalEntry, 0, j.length())
	for i := 0; i < j.length(); i++ {
		entries = append(entries, j.entries[i].copy())
	}
	return &journal{
		entries:        entries,
		dirties:        maps.Clone(j.dirties),
		validRevisions: slices.Clone(j.validRevisions),
		nextRevisionID: j.nextRevisionID,
	}
}

// Helper methods matching geth's journal API.

func (j *journal) logChange(txHash types.Hash) {
	j.append(addLogChange{txhash: txHash})
}

func (j *journal) createObject(addr types.Address) {
	j.append(createObjectChange{account: addr})
}

func (j *journal) createContract(addr types.Address) {
	j.append(createContractChange{account: addr})
}

func (j *journal) destruct(addr types.Address) {
	j.append(selfDestructChange{account: addr})
}

func (j *journal) storageChange(addr types.Address, key, prev, origin types.Hash) {
	j.append(storageChangeEntry{
		account:   addr,
		key:       key,
		prevvalue: prev,
		origvalue: origin,
	})
}

func (j *journal) transientStateChange(addr types.Address, key, prev types.Hash) {
	j.append(transientStorageChange{
		account:  addr,
		key:      key,
		prevalue: prev,
	})
}

func (j *journal) refundChange(previous uint64) {
	j.append(refundChange{prev: previous})
}

func (j *journal) balanceChange(addr types.Address, previous *uint256.Int) {
	j.append(balanceChange{
		account: addr,
		prev:    previous.Clone(),
	})
}

func (j *journal) setCode(address types.Address, prevCode []byte) {
	j.append(codeChange{
		account:  address,
		prevCode: prevCode,
	})
}

func (j *journal) nonceChange(address types.Address, prev uint64) {
	j.append(nonceChange{
		account: address,
		prev:    prev,
	})
}

func (j *journal) touchChange(address types.Address) {
	j.append(touchChangeEntry{
		account: address,
	})
	if address == ripemd {
		// Explicitly put it in the dirty-cache, which is otherwise generated from
		// flattened journals.
		j.dirty(address)
	}
}

func (j *journal) accessListAddAccount(addr types.Address) {
	j.append(accessListAddAccountChange{address: addr})
}

func (j *journal) accessListAddSlot(addr types.Address, slot types.Hash) {
	j.append(accessListAddSlotChange{
		address: addr,
		slot:    slot,
	})
}

// ripemd is the address of the RIPEMD-160 precompile.
var ripemd = types.HexToAddress("0000000000000000000000000000000000000003")

type (
	// Changes to the account trie.
	createObjectChange struct {
		account types.Address
	}
	// createContractChange represents an account becoming a contract-account.
	// This event happens prior to executing initcode. The journal-event simply
	// manages the created-flag, in order to allow same-tx destruction.
	createContractChange struct {
		account types.Address
	}
	selfDestructChange struct {
		account types.Address
	}

	// Changes to individual accounts.
	balanceChange struct {
		account types.Address
		prev    *uint256.Int
	}
	nonceChange struct {
		account types.Address
		prev    uint64
	}
	storageChangeEntry struct {
		account   types.Address
		key       types.Hash
		prevvalue types.Hash
		origvalue types.Hash
	}
	codeChange struct {
		account  types.Address
		prevCode []byte
	}

	// Changes to other state values.
	refundChange struct {
		prev uint64
	}
	addLogChange struct {
		txhash types.Hash
	}
	touchChangeEntry struct {
		account types.Address
	}

	// Changes to the access list
	accessListAddAccountChange struct {
		address types.Address
	}
	accessListAddSlotChange struct {
		address types.Address
		slot    types.Hash
	}

	// Changes to transient storage
	transientStorageChange struct {
		account       types.Address
		key, prevalue types.Hash
	}
)

func (ch createObjectChange) revert(s *StateDB) {
	delete(s.stateObjects, ch.account)
}

func (ch createObjectChange) dirtied() *types.Address {
	return &ch.account
}

func (ch createObjectChange) copy() journalEntry {
	return createObjectChange{
		account: ch.account,
	}
}

func (ch createContractChange) revert(s *StateDB) {
	s.getStateObject(ch.account).newContract = false
}

func (ch createContractChange) dirtied() *types.Address {
	return nil
}

func (ch createContractChange) copy() journalEntry {
	return createContractChange{
		account: ch.account,
	}
}

func (ch selfDestructChange) revert(s *StateDB) {
	obj := s.getStateObject(ch.account)
	if obj != nil {
		obj.selfDestructed = false
	}
}

func (ch selfDestructChange) dirtied() *types.Address {
	return &ch.account
}

func (ch selfDestructChange) copy() journalEntry {
	return selfDestructChange{
		account: ch.account,
	}
}

func (ch touchChangeEntry) revert(s *StateDB) {
}

func (ch touchChangeEntry) dirtied() *types.Address {
	return &ch.account
}

func (ch touchChangeEntry) copy() journalEntry {
	return touchChangeEntry{
		account: ch.account,
	}
}

func (ch balanceChange) revert(s *StateDB) {
	s.getStateObject(ch.account).setBalance(ch.prev)
}

func (ch balanceChange) dirtied() *types.Address {
	return &ch.account
}

func (ch balanceChange) copy() journalEntry {
	return balanceChange{
		account: ch.account,
		prev:    new(uint256.Int).Set(ch.prev),
	}
}

func (ch nonceChange) revert(s *StateDB) {
	s.getStateObject(ch.account).setNonce(ch.prev)
}

func (ch nonceChange) dirtied() *types.Address {
	return &ch.account
}

func (ch nonceChange) copy() journalEntry {
	return nonceChange{
		account: ch.account,
		prev:    ch.prev,
	}
}

func (ch codeChange) revert(s *StateDB) {
	s.getStateObject(ch.account).setCode(types.BytesToHash(crypto.Keccak256(ch.prevCode)), ch.prevCode)
}

func (ch codeChange) dirtied() *types.Address {
	return &ch.account
}

func (ch codeChange) copy() journalEntry {
	return codeChange{
		account:  ch.account,
		prevCode: ch.prevCode,
	}
}

func (ch storageChangeEntry) revert(s *StateDB) {
	s.getStateObject(ch.account).setState(ch.key, ch.prevvalue, ch.origvalue)
}

func (ch storageChangeEntry) dirtied() *types.Address {
	return &ch.account
}

func (ch storageChangeEntry) copy() journalEntry {
	return storageChangeEntry{
		account:   ch.account,
		key:       ch.key,
		prevvalue: ch.prevvalue,
		origvalue: ch.origvalue,
	}
}

func (ch transientStorageChange) revert(s *StateDB) {
	s.setTransientState(ch.account, ch.key, ch.prevalue)
}

func (ch transientStorageChange) dirtied() *types.Address {
	return nil
}

func (ch transientStorageChange) copy() journalEntry {
	return transientStorageChange{
		account:  ch.account,
		key:      ch.key,
		prevalue: ch.prevalue,
	}
}

func (ch refundChange) revert(s *StateDB) {
	s.refund = ch.prev
}

func (ch refundChange) dirtied() *types.Address {
	return nil
}

func (ch refundChange) copy() journalEntry {
	return refundChange{
		prev: ch.prev,
	}
}

func (ch addLogChange) revert(s *StateDB) {
	logs := s.logs[ch.txhash]
	if len(logs) == 1 {
		delete(s.logs, ch.txhash)
	} else {
		s.logs[ch.txhash] = logs[:len(logs)-1]
	}
	s.logSize--
}

func (ch addLogChange) dirtied() *types.Address {
	return nil
}

func (ch addLogChange) copy() journalEntry {
	return addLogChange{
		txhash: ch.txhash,
	}
}

func (ch accessListAddAccountChange) revert(s *StateDB) {
	/*
		One important invariant here, is that whenever a (addr, slot) is added, if the
		addr is not already present, the add causes two journal entries:
		- one for the address,
		- one for the (address,slot)
		Therefore, when unrolling the change, we can always blindly delete the
		(addr) at this point, since no storage adds can remain when come upon
		a single (addr) change.
	*/
	s.accessList.DeleteAddress(ch.address)
}

func (ch accessListAddAccountChange) dirtied() *types.Address {
	return nil
}

func (ch accessListAddAccountChange) copy() journalEntry {
	return accessListAddAccountChange{
		address: ch.address,
	}
}

func (ch accessListAddSlotChange) revert(s *StateDB) {
	s.accessList.DeleteSlot(ch.address, ch.slot)
}

func (ch accessListAddSlotChange) dirtied() *types.Address {
	return nil
}

func (ch accessListAddSlotChange) copy() journalEntry {
	return accessListAddSlotChange{
		address: ch.address,
		slot:    ch.slot,
	}
}
