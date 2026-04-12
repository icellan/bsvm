// Copyright 2015 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package mpt

import (
	"fmt"

	"github.com/icellan/bsvm/pkg/mpt/trienode"
	"github.com/icellan/bsvm/pkg/types"
)

// SecureTrie is the old name of StateTrie.
// Deprecated: use StateTrie.
type SecureTrie = StateTrie

// StateTrie wraps a trie with key hashing. In a stateTrie trie, all
// access operations hash the key using keccak256. This prevents
// calling code from creating long chains of nodes that
// increase the access time.
//
// Contrary to a regular trie, a StateTrie can only be created with
// New and must have an attached database. The database also stores
// the preimage of each key if preimage recording is enabled.
//
// StateTrie is not safe for concurrent use.
type StateTrie struct {
	trie             Trie
	db               NodeDatabase
	hashKeyBuf       [types.HashLength]byte
	secKeyCache      map[string][]byte
	secKeyCacheOwner *StateTrie // Pointer to self, replace the key cache on mismatch
}

// NewStateTrie creates a trie with an existing root node from a backing database.
//
// If root is the zero hash or the sha3 hash of an empty string, the
// trie is initially empty. Otherwise, New will panic if db is nil
// and returns MissingNodeError if the root node cannot be found.
func NewStateTrie(id *ID, db NodeDatabase) (*StateTrie, error) {
	if db == nil {
		return nil, fmt.Errorf("trie.NewStateTrie called without a database")
	}
	trie, err := New(id, db)
	if err != nil {
		return nil, err
	}
	tr := &StateTrie{trie: *trie, db: db}
	return tr, nil
}

// NewSecureTrie creates a new SecureTrie (StateTrie) from a root hash and database.
// This is a convenience function that matches the API previously used by pkg/state/.
func NewSecureTrie(root types.Hash, db NodeDatabase) (*SecureTrie, error) {
	id := TrieID(root)
	return NewStateTrie(id, db)
}

// MustGet returns the value for key stored in the trie.
// The value bytes must not be modified by the caller.
//
// This function will omit any encountered error but just
// print out an error message.
func (t *StateTrie) MustGet(key []byte) []byte {
	return t.trie.MustGet(t.hashKey(key))
}

// Get returns the value for key stored in the trie. The value bytes must
// not be modified by the caller.
//
// If the specified key is not in the trie, nil will be returned.
// If a trie node is not found in the database, a MissingNodeError is returned.
func (t *StateTrie) Get(key []byte) ([]byte, error) {
	return t.trie.Get(t.hashKey(key))
}

// GetNode attempts to retrieve a trie node by compact-encoded path. It is not
// possible to use keybyte-encoding as the path might contain odd nibbles.
// If the specified trie node is not in the trie, nil will be returned.
// If a trie node is not found in the database, a MissingNodeError is returned.
func (t *StateTrie) GetNode(path []byte) ([]byte, int, error) {
	return t.trie.GetNode(path)
}

// MustUpdate associates key with value in the trie. Subsequent calls to
// Get will return value. If value has length zero, any existing value
// is deleted from the trie and calls to Get will return nil.
//
// The value bytes must not be modified by the caller while they are
// stored in the trie.
//
// This function will omit any encountered error but just print out an
// error message.
func (t *StateTrie) MustUpdate(key, value []byte) {
	hk := t.hashKey(key)
	t.trie.MustUpdate(hk, value)
	t.getSecKeyCache()[string(hk)] = types.CopyBytes(key)
}

// Update associates key with value in the trie. Subsequent calls to
// Get will return value. If value has length zero, any existing value
// is deleted from the trie and calls to Get will return nil.
//
// The value bytes must not be modified by the caller while they are
// stored in the trie.
//
// If a node is not found in the database, a MissingNodeError is returned.
func (t *StateTrie) Update(key, value []byte) error {
	hk := t.hashKey(key)
	err := t.trie.Update(hk, value)
	if err != nil {
		return err
	}
	t.getSecKeyCache()[string(hk)] = types.CopyBytes(key)
	return nil
}

// MustDelete removes any existing value for key from the trie. This function
// will omit any encountered error but just print out an error message.
func (t *StateTrie) MustDelete(key []byte) {
	hk := t.hashKey(key)
	delete(t.getSecKeyCache(), string(hk))
	t.trie.MustDelete(hk)
}

// Delete removes any existing value for key from the trie.
//
// If a node is not found in the database, a MissingNodeError is returned.
func (t *StateTrie) Delete(key []byte) error {
	hk := t.hashKey(key)
	delete(t.getSecKeyCache(), string(hk))
	return t.trie.Delete(hk)
}

// GetKey returns the sha3 preimage of a hashed key that was
// previously used to store a value.
func (t *StateTrie) GetKey(shaKey []byte) []byte {
	if key, ok := t.getSecKeyCache()[string(shaKey)]; ok {
		return key
	}
	return nil
}

// Witness returns a set containing all trie nodes that have been accessed.
func (t *StateTrie) Witness() map[string]struct{} {
	return t.trie.Witness()
}

// Commit collects all dirty nodes in the trie and replaces them with the
// corresponding node hash. All collected nodes (including dirty leaves if
// collectLeaf is true) will be encapsulated into a nodeset for return.
// The returned nodeset can be nil if the trie is clean (nothing to commit).
// Once the trie is committed, it's not usable anymore. A new trie must
// be created with new root and updated trie database for following usage
func (t *StateTrie) Commit(collectLeaf bool) (types.Hash, *trienode.NodeSet, error) {
	// Clear the secure key cache on commit.
	if len(t.getSecKeyCache()) > 0 {
		t.secKeyCache = make(map[string][]byte)
	}
	// Commit the trie and return its modified nodeset.
	return t.trie.Commit(collectLeaf)
}

// Hash returns the root hash of StateTrie. It does not write to the
// database and can be used even if the trie doesn't have one.
func (t *StateTrie) Hash() types.Hash {
	return t.trie.Hash()
}

// Copy returns a copy of StateTrie. Returns an error if the trie contains
// corrupted nodes that cannot be copied.
func (t *StateTrie) Copy() (*StateTrie, error) {
	trieCopy, err := t.trie.Copy()
	if err != nil {
		return nil, err
	}
	return &StateTrie{
		trie:        *trieCopy,
		db:          t.db,
		secKeyCache: t.secKeyCache,
	}, nil
}

// NodeIterator returns an iterator that returns nodes of the underlying trie.
// Iteration starts at the key after the given start key.
func (t *StateTrie) NodeIterator(start []byte) (NodeIterator, error) {
	return t.trie.NodeIterator(start)
}

// MustNodeIterator is a wrapper of NodeIterator and will omit any encountered
// error but just print out an error message.
func (t *StateTrie) MustNodeIterator(start []byte) NodeIterator {
	return t.trie.MustNodeIterator(start)
}

// hashKey returns the hash of key as an ephemeral buffer.
// The caller must not hold onto the return value because it will become
// invalid on the next call to hashKey or secKey.
func (t *StateTrie) hashKey(key []byte) []byte {
	h := newHasher(false)
	h.sha.Reset()
	h.sha.Write(key)
	h.sha.Read(t.hashKeyBuf[:])
	returnHasherToPool(h)
	return t.hashKeyBuf[:]
}

// getSecKeyCache returns the current secure key cache, creating a new one if
// ownership changed (i.e. the current secure trie is a copy of another owning
// the actual cache).
func (t *StateTrie) getSecKeyCache() map[string][]byte {
	if t != t.secKeyCacheOwner {
		t.secKeyCacheOwner = t
		t.secKeyCache = make(map[string][]byte)
	}
	return t.secKeyCache
}
