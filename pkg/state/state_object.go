// Copyright 2014 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// Adapted from go-ethereum core/state/state_object.go for the BSVM project.

package state

import (
	"bytes"
	"maps"
	"slices"

	"github.com/holiman/uint256"

	"github.com/icellan/bsvm/pkg/crypto"
	"github.com/icellan/bsvm/pkg/mpt"
	"github.com/icellan/bsvm/pkg/rlp"
	"github.com/icellan/bsvm/pkg/types"
)

// Storage is a map of storage slot hashes to values.
type Storage map[types.Hash]types.Hash

// Copy returns a deep copy of the storage map.
func (s Storage) Copy() Storage {
	return maps.Clone(s)
}

// stateObject represents an Ethereum account which is being modified.
//
// The usage pattern is as follows:
// - First you need to obtain a state object.
// - Account values as well as storages can be accessed and modified through the object.
// - Finally, call commit to return the changes of storage trie and update account data.
type stateObject struct {
	db       *StateDB
	address  types.Address // address of ethereum account
	addrHash types.Hash    // hash of ethereum address of the account

	data Account // Account data with all mutations applied in the scope of block

	// Contract code.
	code      []byte
	dirtyCode bool // true if the code was updated

	// Storage caches.
	originStorage  Storage // Storage entries that have been accessed within the current block
	dirtyStorage   Storage // Storage entries that have been modified within the current transaction
	pendingStorage Storage // Storage entries that have been modified within the current block

	// Flag whether the account was marked as self-destructed. The self-destructed
	// account is still accessible in the scope of same transaction.
	selfDestructed bool

	// This is an EIP-6780 flag indicating whether the object is eligible for
	// self-destruct according to EIP-6780. The flag could be set either when
	// the contract is just created within the current transaction, or when the
	// object was previously existent and is being deployed as a contract within
	// the current transaction.
	newContract bool
}

// empty returns whether the account is considered empty.
func (s *stateObject) empty() bool {
	return s.data.Nonce == 0 && s.data.Balance.IsZero() && bytes.Equal(s.data.CodeHash, types.EmptyCodeHash.Bytes())
}

// newObject creates a state object.
func newObject(db *StateDB, address types.Address, data Account) *stateObject {
	if data.Balance == nil {
		data.Balance = new(uint256.Int)
	}
	if data.CodeHash == nil {
		data.CodeHash = types.EmptyCodeHash.Bytes()
	}
	if data.Root == (types.Hash{}) {
		data.Root = types.EmptyRootHash
	}
	return &stateObject{
		db:             db,
		address:        address,
		addrHash:       types.BytesToHash(crypto.Keccak256(address[:])),
		data:           data,
		originStorage:  make(Storage),
		dirtyStorage:   make(Storage),
		pendingStorage: make(Storage),
	}
}

func (s *stateObject) markSelfdestructed() {
	s.selfDestructed = true
}

func (s *stateObject) touch() {
	s.db.journal.touchChange(s.address)
}

// Address returns the address of the contract/account.
func (s *stateObject) Address() types.Address {
	return s.address
}

// GetState retrieves a value associated with the given storage key.
func (s *stateObject) GetState(key types.Hash) types.Hash {
	value, _ := s.getState(key)
	return value
}

// getState retrieves a value associated with the given storage key, along with
// its original value.
func (s *stateObject) getState(key types.Hash) (types.Hash, types.Hash) {
	origin := s.GetCommittedState(key)
	value, dirty := s.dirtyStorage[key]
	if dirty {
		return value, origin
	}
	return origin, origin
}

// GetCommittedState retrieves the value associated with the specific key
// without any mutations caused in the current execution.
func (s *stateObject) GetCommittedState(key types.Hash) types.Hash {
	// If we have a pending write or clean cached, return that
	if value, pending := s.pendingStorage[key]; pending {
		return value
	}
	if value, cached := s.originStorage[key]; cached {
		return value
	}
	// Load from storage trie.
	value := s.loadFromTrie(key)
	s.originStorage[key] = value
	return value
}

// loadFromTrie loads a storage slot value from the account's storage trie.
func (s *stateObject) loadFromTrie(key types.Hash) types.Hash {
	if s.data.Root == types.EmptyRootHash {
		return types.Hash{}
	}
	storageTrie, err := s.openStorageTrie()
	if err != nil {
		return types.Hash{}
	}
	enc, err := storageTrie.Get(key.Bytes())
	if err != nil || len(enc) == 0 {
		return types.Hash{}
	}
	// Storage values are RLP-encoded.
	_, content, _, err := rlp.Split(enc)
	if err != nil {
		return types.Hash{}
	}
	return types.BytesToHash(content)
}

// openStorageTrie opens the account's storage trie from the database.
func (s *stateObject) openStorageTrie() (*mpt.SecureTrie, error) {
	return mpt.NewSecureTrie(s.data.Root, s.db.db)
}

// SetState updates a value in account storage. It returns the previous value.
func (s *stateObject) SetState(key, value types.Hash) types.Hash {
	// If the new value is the same as old, don't set. Otherwise, track only the
	// dirty changes, supporting reverting all of it back to no change.
	prev, origin := s.getState(key)
	if prev == value {
		return prev
	}
	// New value is different, update and journal the change
	s.db.journal.storageChange(s.address, key, prev, origin)
	s.setState(key, value, origin)
	return prev
}

// setState updates a value in account dirty storage. The dirtiness will be
// removed if the value being set equals to the original value.
func (s *stateObject) setState(key types.Hash, value types.Hash, origin types.Hash) {
	// Storage slot is set back to its original value, undo the dirty marker
	if value == origin {
		delete(s.dirtyStorage, key)
		return
	}
	s.dirtyStorage[key] = value
}

// finalise moves all dirty storage slots into the pending area to be hashed or
// committed later. It is invoked at the end of every transaction.
func (s *stateObject) finalise() {
	for key, value := range s.dirtyStorage {
		s.pendingStorage[key] = value
	}
	if len(s.dirtyStorage) > 0 {
		s.dirtyStorage = make(Storage)
	}
	// Revoke the flag at the end of the transaction. It finalizes the status
	// of the newly-created object as it's no longer eligible for self-destruct
	// by EIP-6780. For non-newly-created objects, it's a no-op.
	s.newContract = false
}

// updateStorageTrie writes all pending storage changes to the storage trie.
func (s *stateObject) updateStorageTrie(trieDB *mpt.Database) error {
	if len(s.pendingStorage) == 0 {
		return nil
	}
	storageTrie, err := mpt.NewSecureTrie(s.data.Root, trieDB)
	if err != nil {
		return err
	}
	// Perform updates before deletions to avoid unnecessary trie node resolution.
	var deletions []types.Hash
	for key, value := range s.pendingStorage {
		// Skip noop changes
		if value == s.originStorage[key] {
			continue
		}
		if (value != types.Hash{}) {
			trimmed := bytes.TrimLeft(value.Bytes(), "\x00")
			enc, err := rlp.EncodeToBytes(trimmed)
			if err != nil {
				return err
			}
			if err := storageTrie.Update(key.Bytes(), enc); err != nil {
				return err
			}
		} else {
			deletions = append(deletions, key)
		}
	}
	for _, key := range deletions {
		if err := storageTrie.Delete(key.Bytes()); err != nil {
			return err
		}
	}
	// Update the account's storage root.
	s.data.Root = storageTrie.Hash()
	return nil
}

// commitStorageTrie commits the storage trie to the database.
func (s *stateObject) commitStorageTrie(trieDB *mpt.Database) error {
	if len(s.pendingStorage) == 0 {
		return nil
	}
	storageTrie, err := mpt.NewSecureTrie(s.data.Root, trieDB)
	if err != nil {
		return err
	}
	// Write pending changes.
	for key, value := range s.pendingStorage {
		// Skip noop changes
		if value == s.originStorage[key] {
			continue
		}
		if value == (types.Hash{}) {
			if err := storageTrie.Delete(key.Bytes()); err != nil {
				return err
			}
		} else {
			trimmed := bytes.TrimLeft(value.Bytes(), "\x00")
			enc, err := rlp.EncodeToBytes(trimmed)
			if err != nil {
				return err
			}
			if err := storageTrie.Update(key.Bytes(), enc); err != nil {
				return err
			}
		}
		// Overwrite the clean value of storage slots
		s.originStorage[key] = value
	}
	s.pendingStorage = make(Storage)

	root, nodes, err := storageTrie.Commit(false)
	if err != nil {
		return err
	}
	s.data.Root = root
	// Write the trie node changes to the database.
	if nodes != nil {
		for _, n := range nodes.Nodes {
			if !n.IsDeleted() {
				s.db.db.InsertBlob(n.Hash, n.Blob)
			}
		}
	}
	return nil
}

// updateAccountTrie writes the account data to the account trie.
func (s *stateObject) updateAccountTrie(trie *mpt.SecureTrie) error {
	data, err := rlp.EncodeToBytes(&s.data)
	if err != nil {
		return err
	}
	return trie.Update(s.address[:], data)
}

// AddBalance adds amount to s's balance. It is used to add funds to the
// destination account of a transfer. Returns the previous balance.
func (s *stateObject) AddBalance(amount *uint256.Int) uint256.Int {
	// EIP161: We must check emptiness for the objects such that the account
	// clearing (0,0,0 objects) can take effect.
	if amount.IsZero() {
		if s.empty() {
			s.touch()
		}
		return *(s.Balance())
	}
	return s.SetBalance(new(uint256.Int).Add(s.Balance(), amount))
}

// SetBalance sets the balance for the object, and returns the previous balance.
func (s *stateObject) SetBalance(amount *uint256.Int) uint256.Int {
	prev := *s.data.Balance
	s.db.journal.balanceChange(s.address, s.data.Balance)
	s.setBalance(amount)
	return prev
}

func (s *stateObject) setBalance(amount *uint256.Int) {
	s.data.Balance = amount
}

// SubBalance subtracts the given amount from the account balance and returns
// the previous balance as a value.
func (s *stateObject) SubBalance(amount *uint256.Int) uint256.Int {
	if amount.IsZero() {
		return *(s.Balance())
	}
	return s.SetBalance(new(uint256.Int).Sub(s.Balance(), amount))
}

// Nonce returns the account nonce.
func (s *stateObject) Nonce() uint64 {
	return s.data.Nonce
}

// SetNonce sets the account nonce with journal tracking.
func (s *stateObject) SetNonce(nonce uint64) {
	s.db.journal.nonceChange(s.address, s.data.Nonce)
	s.setNonce(nonce)
}

func (s *stateObject) setNonce(nonce uint64) {
	s.data.Nonce = nonce
}

// Code returns the contract code for this account. If the code has not been
// loaded yet, it is fetched from the database using the code hash.
func (s *stateObject) Code() []byte {
	if len(s.code) != 0 {
		return s.code
	}
	if bytes.Equal(s.data.CodeHash, types.EmptyCodeHash.Bytes()) {
		return nil
	}
	// Load code from database.
	codeKey := codeDBKey(types.BytesToHash(s.data.CodeHash))
	code, err := s.db.db.DiskDB().Get(codeKey)
	if err != nil {
		return nil
	}
	s.code = code
	return s.code
}

// SetCode sets the code and code hash for this account with journal tracking.
// Returns the previous code.
func (s *stateObject) SetCode(codeHash types.Hash, code []byte) []byte {
	prev := slices.Clone(s.code)
	s.db.journal.setCode(s.address, prev)
	s.setCode(codeHash, code)
	return prev
}

func (s *stateObject) setCode(codeHash types.Hash, code []byte) {
	s.code = code
	s.data.CodeHash = codeHash[:]
	s.dirtyCode = true
}

// CodeHash returns the code hash for this account.
func (s *stateObject) CodeHash() []byte {
	return s.data.CodeHash
}

// Balance returns the account balance.
func (s *stateObject) Balance() *uint256.Int {
	return s.data.Balance
}

// Root returns the storage root of the account.
func (s *stateObject) Root() types.Hash {
	return s.data.Root
}

// deepCopy creates a deep copy of the state object with a new parent db pointer.
func (s *stateObject) deepCopy(db *StateDB) *stateObject {
	obj := &stateObject{
		db:             db,
		address:        s.address,
		addrHash:       s.addrHash,
		data:           s.data,
		code:           s.code,
		originStorage:  s.originStorage.Copy(),
		pendingStorage: s.pendingStorage.Copy(),
		dirtyStorage:   s.dirtyStorage.Copy(),
		dirtyCode:      s.dirtyCode,
		selfDestructed: s.selfDestructed,
		newContract:    s.newContract,
	}
	// Deep copy balance.
	obj.data.Balance = new(uint256.Int).Set(s.data.Balance)
	// Deep copy code hash.
	obj.data.CodeHash = make([]byte, len(s.data.CodeHash))
	copy(obj.data.CodeHash, s.data.CodeHash)
	return obj
}

// codeDBKey returns the database key for storing contract code.
// The key is "c" + codeHash.
func codeDBKey(codeHash types.Hash) []byte {
	return append([]byte("c"), codeHash[:]...)
}
