// Copyright 2014 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// Adapted from go-ethereum core/state/statedb.go for the BSVM project.

package state

import (
	"fmt"
	"maps"
	"sync"

	"github.com/holiman/uint256"

	"github.com/icellan/bsvm/internal/db"
	"github.com/icellan/bsvm/pkg/crypto"
	"github.com/icellan/bsvm/pkg/mpt"
	"github.com/icellan/bsvm/pkg/rlp"
	"github.com/icellan/bsvm/pkg/types"
	"github.com/icellan/bsvm/pkg/vm"
	"github.com/icellan/bsvm/pkg/vm/tracing"
)

// Ensure StateDB implements vm.StateDB at compile time.
var _ vm.StateDB = (*StateDB)(nil)

// StateDB structs within the ethereum protocol are used to store anything
// within the merkle trie. StateDBs take care of caching and storing
// nested states. It's the general query interface to retrieve:
//
//   - Contracts
//   - Accounts
//
// Once the state is committed, tries cached in stateDB (including account
// trie, storage tries) will no longer be functional. A new state instance
// must be created with new root and updated database for accessing post-
// commit states.
type StateDB struct {
	db   *mpt.Database
	trie *mpt.SecureTrie

	// originalRoot is the pre-state root, before any changes were made.
	// It will be updated when the Commit is called.
	originalRoot types.Hash

	// This map holds 'live' objects, which will get modified while
	// processing a state transition.
	stateObjects map[types.Address]*stateObject

	// This map holds 'deleted' objects. An object with the same address
	// might also occur in the 'stateObjects' map due to account
	// resurrection. The account value is tracked as the original value
	// before the transition. This map is populated at the transaction
	// boundaries.
	stateObjectsDestruct map[types.Address]*stateObject

	// DB error.
	// State objects are used by the consensus core and VM which are
	// unable to deal with database-level errors. Any error that occurs
	// during a database read is memoized here and will eventually be
	// returned by StateDB.Commit.
	dbErr error

	// The refund counter, also used by state transitioning.
	refund uint64

	// The tx context and all occurred logs in the scope of transaction.
	thash   types.Hash
	txIndex int
	logs    map[types.Hash][]*types.Log
	logSize uint

	// Preimages occurred seen by VM in the scope of block.
	preimages map[types.Hash][]byte

	// Per-transaction access list
	accessList *accessList

	// Transient storage
	transientStorage transientStorage

	// Journal of state modifications. This is the backbone of
	// Snapshot and RevertToSnapshot.
	journal *journal

	// accessRecorder tracks cumulative account and storage slot accesses
	// across a batch of transactions. It is non-nil only while recording
	// is active (between StartAccessRecording and StopAccessRecording).
	accessRecorder *accessRecorder

	mu sync.Mutex
}

// New creates a new StateDB rooted at the given state root. The database
// argument provides the underlying key-value storage.
func New(root types.Hash, database db.Database) (*StateDB, error) {
	trieDB := mpt.NewDatabase(database)
	tr, err := mpt.NewSecureTrie(root, trieDB)
	if err != nil {
		return nil, err
	}
	sdb := &StateDB{
		db:                   trieDB,
		trie:                 tr,
		originalRoot:         root,
		stateObjects:         make(map[types.Address]*stateObject),
		stateObjectsDestruct: make(map[types.Address]*stateObject),
		logs:                 make(map[types.Hash][]*types.Log),
		preimages:            make(map[types.Hash][]byte),
		journal:              newJournal(),
		accessList:           newAccessList(),
		transientStorage:     newTransientStorage(),
	}
	return sdb, nil
}

// setError remembers the first non-nil error it is called with.
func (s *StateDB) setError(err error) {
	if s.dbErr == nil {
		s.dbErr = err
	}
}

// Error returns the memorized database failure occurred earlier.
func (s *StateDB) Error() error {
	return s.dbErr
}

// SetTxContext sets the current transaction hash and index for log attribution.
func (s *StateDB) SetTxContext(txHash types.Hash, txIndex int) {
	s.thash = txHash
	s.txIndex = txIndex
}

// AddLog adds a log entry. The log is associated with the current transaction.
func (s *StateDB) AddLog(log *types.Log) {
	s.journal.logChange(s.thash)

	log.TxHash = s.thash
	log.TxIndex = uint(s.txIndex)
	log.Index = s.logSize
	s.logs[s.thash] = append(s.logs[s.thash], log)
	s.logSize++
}

// GetLogs returns the logs matching the specified transaction hash, and annotates
// them with the given blockNumber and blockHash.
func (s *StateDB) GetLogs(txHash types.Hash, blockNumber uint64, blockHash types.Hash) []*types.Log {
	logs := s.logs[txHash]
	for _, l := range logs {
		l.BlockNumber = blockNumber
		l.BlockHash = blockHash
	}
	return logs
}

// Logs returns all accumulated logs across all transactions.
func (s *StateDB) Logs() []*types.Log {
	var logs []*types.Log
	for _, lgs := range s.logs {
		logs = append(logs, lgs...)
	}
	return logs
}

// AddPreimage records a SHA3 preimage seen by the VM.
func (s *StateDB) AddPreimage(hash types.Hash, preimage []byte) {
	if _, ok := s.preimages[hash]; !ok {
		cp := make([]byte, len(preimage))
		copy(cp, preimage)
		s.preimages[hash] = cp
	}
}

// Preimages returns a list of SHA3 preimages that have been submitted.
func (s *StateDB) Preimages() map[types.Hash][]byte {
	return s.preimages
}

// AddRefund adds gas to the refund counter.
func (s *StateDB) AddRefund(gas uint64) {
	s.journal.refundChange(s.refund)
	s.refund += gas
}

// SubRefund subtracts gas from the refund counter. It panics if the
// subtraction would underflow, matching geth behavior — an underflow
// indicates a gas accounting logic error that must not be silenced.
func (s *StateDB) SubRefund(gas uint64) {
	s.journal.refundChange(s.refund)
	if gas > s.refund {
		panic(fmt.Sprintf("refund counter below zero (gas: %d > refund: %d)", gas, s.refund))
	}
	s.refund -= gas
}

// GetRefund returns the current value of the refund counter.
func (s *StateDB) GetRefund() uint64 {
	return s.refund
}

// Exist reports whether the given account address exists in the state.
// Notably this also returns true for self-destructed accounts.
func (s *StateDB) Exist(addr types.Address) bool {
	return s.getStateObject(addr) != nil
}

// Empty returns whether the state object is either non-existent
// or empty according to the EIP161 specification (balance = nonce = code = 0).
func (s *StateDB) Empty(addr types.Address) bool {
	so := s.getStateObject(addr)
	return so == nil || so.empty()
}

// GetBalance retrieves the balance from the given address or 0 if object not found.
func (s *StateDB) GetBalance(addr types.Address) *uint256.Int {
	stateObject := s.getStateObject(addr)
	if stateObject != nil {
		return stateObject.Balance()
	}
	return new(uint256.Int)
}

// GetNonce retrieves the nonce from the given address or 0 if object not found.
func (s *StateDB) GetNonce(addr types.Address) uint64 {
	stateObject := s.getStateObject(addr)
	if stateObject != nil {
		return stateObject.Nonce()
	}
	return 0
}

// GetStorageRoot retrieves the storage root from the given address or
// EmptyRootHash if the account does not exist or has no storage.
func (s *StateDB) GetStorageRoot(addr types.Address) types.Hash {
	stateObject := s.getStateObject(addr)
	if stateObject != nil {
		return stateObject.Root()
	}
	return types.EmptyRootHash
}

// TxIndex returns the current transaction index set by SetTxContext.
func (s *StateDB) TxIndex() int {
	return s.txIndex
}

// GetCode returns the code associated with the given account. Returns nil
// if the account does not exist or has no code.
func (s *StateDB) GetCode(addr types.Address) []byte {
	stateObject := s.getStateObject(addr)
	if stateObject != nil {
		return stateObject.Code()
	}
	return nil
}

// GetCodeSize returns the size of the code associated with the given account.
// Returns zero if the account does not exist or has no code.
func (s *StateDB) GetCodeSize(addr types.Address) int {
	stateObject := s.getStateObject(addr)
	if stateObject != nil {
		return len(stateObject.Code())
	}
	return 0
}

// GetCodeHash returns the code hash of the given account. Returns the empty
// hash if the account does not exist.
func (s *StateDB) GetCodeHash(addr types.Address) types.Hash {
	stateObject := s.getStateObject(addr)
	if stateObject != nil {
		return types.BytesToHash(stateObject.CodeHash())
	}
	return types.Hash{}
}

// GetState retrieves the value associated with the specific key.
func (s *StateDB) GetState(addr types.Address, hash types.Hash) types.Hash {
	s.recordSlotAccess(addr, hash)
	stateObject := s.getStateObject(addr)
	if stateObject != nil {
		return stateObject.GetState(hash)
	}
	return types.Hash{}
}

// GetCommittedState retrieves the value associated with the specific key
// without any mutations caused in the current execution.
func (s *StateDB) GetCommittedState(addr types.Address, hash types.Hash) types.Hash {
	stateObject := s.getStateObject(addr)
	if stateObject != nil {
		return stateObject.GetCommittedState(hash)
	}
	return types.Hash{}
}

// Database returns the underlying trie database.
func (s *StateDB) Database() *mpt.Database {
	return s.db
}

// HasSelfDestructed returns whether the given account has been marked for
// self-destruction.
func (s *StateDB) HasSelfDestructed(addr types.Address) bool {
	stateObject := s.getStateObject(addr)
	if stateObject != nil {
		return stateObject.selfDestructed
	}
	return false
}

/*
 * SETTERS
 */

// AddBalance adds amount to the account associated with addr.
func (s *StateDB) AddBalance(addr types.Address, amount *uint256.Int, reason tracing.BalanceChangeReason) uint256.Int {
	stateObject := s.getOrNewStateObject(addr)
	if stateObject == nil {
		return uint256.Int{}
	}
	return stateObject.AddBalance(amount)
}

// SubBalance subtracts amount from the account associated with addr.
func (s *StateDB) SubBalance(addr types.Address, amount *uint256.Int, reason tracing.BalanceChangeReason) uint256.Int {
	stateObject := s.getOrNewStateObject(addr)
	if stateObject == nil {
		return uint256.Int{}
	}
	if amount.IsZero() {
		return *(stateObject.Balance())
	}
	return stateObject.SetBalance(new(uint256.Int).Sub(stateObject.Balance(), amount))
}

// SetBalance sets the balance for the given address.
func (s *StateDB) SetBalance(addr types.Address, amount *uint256.Int) {
	stateObject := s.getOrNewStateObject(addr)
	if stateObject != nil {
		stateObject.SetBalance(amount)
	}
}

// SetNonce sets the nonce of the given account.
func (s *StateDB) SetNonce(addr types.Address, nonce uint64, reason tracing.NonceChangeReason) {
	stateObject := s.getOrNewStateObject(addr)
	if stateObject != nil {
		stateObject.SetNonce(nonce)
	}
}

// SetCode sets the code for the given account. Returns the previous code.
func (s *StateDB) SetCode(addr types.Address, code []byte, reason tracing.CodeChangeReason) []byte {
	stateObject := s.getOrNewStateObject(addr)
	if stateObject != nil {
		return stateObject.SetCode(types.BytesToHash(crypto.Keccak256(code)), code)
	}
	return nil
}

// SetState sets the value of a storage slot. Returns the previous value.
func (s *StateDB) SetState(addr types.Address, key, value types.Hash) types.Hash {
	s.recordSlotAccess(addr, key)
	if stateObject := s.getOrNewStateObject(addr); stateObject != nil {
		return stateObject.SetState(key, value)
	}
	return types.Hash{}
}

// SelfDestruct marks the given account as selfdestructed.
// This clears the account balance.
//
// The account's state object is still available until the state is committed,
// getStateObject will return a non-nil account after SelfDestruct.
func (s *StateDB) SelfDestruct(addr types.Address) {
	stateObject := s.getStateObject(addr)
	if stateObject == nil {
		return
	}
	// Regardless of whether it is already destructed or not, we do have to
	// journal the balance-change, if we set it to zero here.
	if !stateObject.Balance().IsZero() {
		stateObject.SetBalance(new(uint256.Int))
	}
	// If it is already marked as self-destructed, we do not need to add it
	// for journalling a second time.
	if !stateObject.selfDestructed {
		s.journal.destruct(addr)
		stateObject.markSelfdestructed()
	}
}

// Selfdestruct6780 implements EIP-6780: the account is only self-destructed
// if it was created in the same transaction.
func (s *StateDB) Selfdestruct6780(addr types.Address) {
	stateObject := s.getStateObject(addr)
	if stateObject == nil {
		return
	}
	if stateObject.newContract {
		s.SelfDestruct(addr)
	}
}

// SetTransientState sets transient storage for a given account. It
// adds the change to the journal so that it can be rolled back
// to its previous value if there is a revert.
func (s *StateDB) SetTransientState(addr types.Address, key, value types.Hash) {
	prev := s.GetTransientState(addr, key)
	if prev == value {
		return
	}
	s.journal.transientStateChange(addr, key, prev)
	s.setTransientState(addr, key, value)
}

// setTransientState is a lower level setter for transient storage. It
// is called during a revert to prevent modifications to the journal.
func (s *StateDB) setTransientState(addr types.Address, key, value types.Hash) {
	s.transientStorage.Set(addr, key, value)
}

// GetTransientState gets transient storage for a given account.
func (s *StateDB) GetTransientState(addr types.Address, key types.Hash) types.Hash {
	return s.transientStorage.Get(addr, key)
}

//
// Setting, updating & deleting state object methods.
//

// getStateObject retrieves a state object given by the address, returning nil if
// the object is not found or was deleted in this execution context.
func (s *StateDB) getStateObject(addr types.Address) *stateObject {
	// Record account access for prover state export.
	s.recordAccountAccess(addr)

	// Prefer live objects if any is available
	if obj := s.stateObjects[addr]; obj != nil {
		return obj
	}
	// Short circuit if the account is already destructed in this block.
	if _, ok := s.stateObjectsDestruct[addr]; ok {
		return nil
	}
	// Load from trie.
	enc, err := s.trie.Get(addr[:])
	if err != nil || len(enc) == 0 {
		return nil
	}
	var acct Account
	if err := rlp.DecodeBytes(enc, &acct); err != nil {
		return nil
	}
	// Insert into the live set
	obj := newObject(s, addr, acct)
	s.setStateObject(obj)
	return obj
}

func (s *StateDB) setStateObject(object *stateObject) {
	s.stateObjects[object.Address()] = object
}

// getOrNewStateObject retrieves a state object or create a new state object if nil.
func (s *StateDB) getOrNewStateObject(addr types.Address) *stateObject {
	obj := s.getStateObject(addr)
	if obj == nil {
		obj = s.createObject(addr)
	}
	return obj
}

// createObject creates a new state object. The assumption is held there is no
// existing account with the given address, otherwise it will be silently overwritten.
func (s *StateDB) createObject(addr types.Address) *stateObject {
	obj := newObject(s, addr, newAccount())
	s.journal.createObject(addr)
	s.setStateObject(obj)
	return obj
}

// CreateAccount explicitly creates a new state object, assuming that the
// account did not previously exist in the state. If the account already
// exists, this function will silently overwrite it which might lead to a
// consensus bug eventually.
func (s *StateDB) CreateAccount(addr types.Address) {
	s.createObject(addr)
}

// CreateContract is used whenever a contract is created. This may be preceded
// by CreateAccount, but that is not required if it already existed in the
// state due to funds sent beforehand.
// This operation sets the 'newContract'-flag, which is required in order to
// correctly handle EIP-6780 'delete-in-same-transaction' logic.
func (s *StateDB) CreateContract(addr types.Address) {
	obj := s.getStateObject(addr)
	if !obj.newContract {
		obj.newContract = true
		s.journal.createContract(addr)
	}
}

// Snapshot returns an identifier for the current revision of the state.
func (s *StateDB) Snapshot() int {
	return s.journal.snapshot()
}

// RevertToSnapshot reverts all state changes made since the given revision.
func (s *StateDB) RevertToSnapshot(revid int) {
	s.journal.revertToSnapshot(revid, s)
}

// Prepare handles the preparatory steps for executing a state transition.
// This method must be invoked before state transition.
//
// Berlin fork:
// - Add sender to access list (2929)
// - Add destination to access list (2929)
// - Add precompiles to access list (2929)
// - Add the contents of the optional tx access list (2930)
//
// Potential EIPs:
// - Reset access list (Berlin)
// - Add coinbase to access list (EIP-3651)
// - Reset transient storage (EIP-1153)
func (s *StateDB) Prepare(rules vm.Rules, sender, coinbase types.Address, dest *types.Address, precompiles []types.Address, txAccess types.AccessList) {
	if rules.IsBerlin {
		// Clear out any leftover from previous executions
		al := newAccessList()
		s.accessList = al

		al.AddAddress(sender)
		if dest != nil {
			al.AddAddress(*dest)
			// If it's a create-tx, the destination will be added inside evm.create
		}
		for _, addr := range precompiles {
			al.AddAddress(addr)
		}
		for _, el := range txAccess {
			al.AddAddress(el.Address)
			for _, key := range el.StorageKeys {
				al.AddSlot(el.Address, key)
			}
		}
		if rules.IsShanghai { // EIP-3651: warm coinbase
			al.AddAddress(coinbase)
		}
	}
	// Reset transient storage at the beginning of transaction execution
	s.transientStorage = newTransientStorage()
}

// AddAddressToAccessList adds the given address to the access list.
func (s *StateDB) AddAddressToAccessList(addr types.Address) {
	if s.accessList.AddAddress(addr) {
		s.journal.accessListAddAccount(addr)
	}
}

// AddSlotToAccessList adds the given (address, slot)-tuple to the access list.
func (s *StateDB) AddSlotToAccessList(addr types.Address, slot types.Hash) {
	addrMod, slotMod := s.accessList.AddSlot(addr, slot)
	if addrMod {
		// In practice, this should not happen, since there is no way to enter the
		// scope of 'address' without having the 'address' become already added
		// to the access list (via call-variant, create, etc).
		// Better safe than sorry, though
		s.journal.accessListAddAccount(addr)
	}
	if slotMod {
		s.journal.accessListAddSlot(addr, slot)
	}
}

// AddressInAccessList returns true if the given address is in the access list.
func (s *StateDB) AddressInAccessList(addr types.Address) bool {
	return s.accessList.ContainsAddress(addr)
}

// SlotInAccessList returns true if the given (address, slot)-tuple is in the access list.
func (s *StateDB) SlotInAccessList(addr types.Address, slot types.Hash) (bool, bool) {
	return s.accessList.Contains(addr, slot)
}

// AccessListEntries returns the current access list contents as a slice of
// AccessListEntry. This is used by eth_createAccessList to return the
// addresses and storage slots accessed during execution.
func (s *StateDB) AccessListEntries() []AccessListEntry {
	return s.accessList.Entries()
}

// Finalise finalises the state by removing the destructed objects and clears
// the journal as well as the refunds. Finalise, however, will not push any updates
// into the tries just yet. Only IntermediateRoot or Commit will do that.
func (s *StateDB) Finalise(deleteEmptyObjects bool) {
	for addr := range s.journal.dirties {
		obj, exist := s.stateObjects[addr]
		if !exist {
			// ripeMD is 'touched' at block 1714175, in tx 0x1237f737031e40bcde4a8b7e717b2d15e3ecadfe49bb1bbc71ee9deb09c6fcf2
			// That tx goes out of gas, and although the notion of 'touched' does not exist there, the
			// touch-event will still be recorded in the journal. Since ripeMD is a special snowflake,
			// it will persist in the journal even though the journal is reverted. In this special circumstance,
			// it may exist in `s.journal.dirties` but not in `s.stateObjects`.
			// Thus, we can safely ignore it here
			continue
		}
		if obj.selfDestructed || (deleteEmptyObjects && obj.empty()) {
			delete(s.stateObjects, obj.address)

			// We need to maintain account deletions explicitly (will remain
			// set indefinitely). Note only the first occurred self-destruct
			// event is tracked.
			if _, ok := s.stateObjectsDestruct[obj.address]; !ok {
				s.stateObjectsDestruct[obj.address] = obj
			}
		} else {
			obj.finalise()
		}
	}
	// Invalidate journal because reverting across transactions is not allowed.
	s.clearJournalAndRefund()
}

func (s *StateDB) clearJournalAndRefund() {
	s.journal.reset()
	s.refund = 0
}

// IntermediateRoot computes the current root hash of the state trie.
// It is called in between transactions to get the root hash that
// goes into transaction receipts.
func (s *StateDB) IntermediateRoot(deleteEmptyObjects bool) types.Hash {
	// Finalise all the dirty storage states and write them into the tries
	s.Finalise(deleteEmptyObjects)

	// Update all state objects in the trie.
	// Perform updates before deletions to avoid unnecessary trie node resolution.
	for _, obj := range s.stateObjects {
		// Update storage trie.
		if err := obj.updateStorageTrie(s.db); err != nil {
			s.setError(err)
			continue
		}
		// Update account in account trie.
		if err := obj.updateAccountTrie(s.trie); err != nil {
			s.setError(err)
			continue
		}
	}
	return s.trie.Hash()
}

// Commit finalises the state, commits all storage tries and the account trie,
// and flushes everything to disk. Returns the new state root hash.
func (s *StateDB) Commit(deleteEmptyObjects bool) (types.Hash, error) {
	// Short circuit in case any database failure occurred earlier.
	if s.dbErr != nil {
		return types.Hash{}, fmt.Errorf("commit aborted due to earlier error: %v", s.dbErr)
	}
	s.Finalise(deleteEmptyObjects)

	// Short circuit if any error occurs within the Finalise.
	if s.dbErr != nil {
		return types.Hash{}, fmt.Errorf("commit aborted due to database error: %v", s.dbErr)
	}

	// Commit all state objects.
	for addr, obj := range s.stateObjects {
		// Write code to disk if dirty.
		if obj.dirtyCode && len(obj.code) > 0 {
			codeHash := types.BytesToHash(obj.data.CodeHash)
			codeKey := codeDBKey(codeHash)
			if err := s.db.DiskDB().Put(codeKey, obj.code); err != nil {
				return types.Hash{}, err
			}
			obj.dirtyCode = false
		}

		// Commit the storage trie.
		if err := obj.commitStorageTrie(s.db); err != nil {
			return types.Hash{}, err
		}

		// Update the account in the account trie.
		data, err := rlp.EncodeToBytes(&obj.data)
		if err != nil {
			return types.Hash{}, err
		}
		if err := s.trie.Update(addr[:], data); err != nil {
			return types.Hash{}, err
		}
	}

	// Commit the account trie.
	root, nodes, err := s.trie.Commit(false)
	if err != nil {
		return types.Hash{}, err
	}
	// Write the trie node changes to the database.
	if nodes != nil {
		for _, n := range nodes.Nodes {
			if !n.IsDeleted() {
				s.db.InsertBlob(n.Hash, n.Blob)
			}
		}
	}

	// Flush the trie database to disk.
	if err := s.db.Commit(root); err != nil {
		return types.Hash{}, err
	}

	// Clear all internal flags and update state root.
	s.stateObjectsDestruct = make(map[types.Address]*stateObject)
	s.originalRoot = root
	return root, nil
}

// Merkle proof generation methods (GetProof, GetStorageProof) and their
// supporting types (proofList, errBatch) are in proof.go per Spec 02.

// Copy creates a deep, independent copy of the state.
// Snapshots of the copied state cannot be applied to the copy.
func (s *StateDB) Copy() *StateDB {
	state := &StateDB{
		db:                   s.db,
		trie:                 s.trie, // shares the trie (reads same committed data)
		originalRoot:         s.originalRoot,
		stateObjects:         make(map[types.Address]*stateObject, len(s.stateObjects)),
		stateObjectsDestruct: make(map[types.Address]*stateObject, len(s.stateObjectsDestruct)),
		dbErr:                s.dbErr,
		refund:               s.refund,
		thash:                s.thash,
		txIndex:              s.txIndex,
		logs:                 make(map[types.Hash][]*types.Log, len(s.logs)),
		logSize:              s.logSize,
		preimages:            maps.Clone(s.preimages),
		accessList:           s.accessList.Copy(),
		transientStorage:     s.transientStorage.Copy(),
		journal:              s.journal.copy(),
	}
	// Deep copy cached state objects.
	for addr, obj := range s.stateObjects {
		state.stateObjects[addr] = obj.deepCopy(state)
	}
	// Deep copy destructed state objects.
	for addr, obj := range s.stateObjectsDestruct {
		state.stateObjectsDestruct[addr] = obj.deepCopy(state)
	}
	// Deep copy the logs occurred in the scope of block
	for hash, logs := range s.logs {
		cpy := make([]*types.Log, len(logs))
		for i, l := range logs {
			cpy[i] = new(types.Log)
			*cpy[i] = *l
		}
		state.logs[hash] = cpy
	}
	return state
}
