// Package mpt database bridge.
//
// This file bridges the NodeDatabase interface expected by the extracted geth
// trie code with our internal/db.Database key-value store. Trie nodes are
// stored by hash (hash-based scheme). The owner and path parameters in
// NodeReader.Node are ignored; only the hash matters.

package mpt

import (
	"sync"

	"github.com/icellan/bsvm/internal/db"
	"github.com/icellan/bsvm/pkg/mpt/trienode"
	"github.com/icellan/bsvm/pkg/types"
)

// Database wraps a key-value store to implement NodeDatabase.
// Trie nodes are stored as hash -> blob. It also maintains a dirty
// cache of nodes that haven't been flushed to disk yet.
type Database struct {
	diskdb db.Database
	nodes  map[types.Hash][]byte // dirty cache
	lock   sync.Mutex
}

// Ensure Database implements NodeDatabase.
var _ NodeDatabase = (*Database)(nil)

// NewDatabase creates a new Database wrapping the given key-value store.
func NewDatabase(diskdb db.Database) *Database {
	return &Database{
		diskdb: diskdb,
		nodes:  make(map[types.Hash][]byte),
	}
}

// DiskDB returns the underlying key-value store.
func (db *Database) DiskDB() db.Database {
	return db.diskdb
}

// NodeReader returns a reader for the given state root. For hash-based
// storage, the state root is not used for routing; all nodes live in a
// single flat namespace keyed by hash.
func (db *Database) NodeReader(stateRoot types.Hash) (NodeReader, error) {
	return &databaseReader{db: db}, nil
}

// InsertBlob stores a node blob in the dirty cache, keyed by its hash.
func (db *Database) InsertBlob(hash types.Hash, blob []byte) {
	db.lock.Lock()
	defer db.lock.Unlock()
	cp := make([]byte, len(blob))
	copy(cp, blob)
	db.nodes[hash] = cp
}

// Node retrieves a node blob from the dirty cache or disk, by hash.
func (db *Database) Node(hash types.Hash) ([]byte, error) {
	db.lock.Lock()
	if blob, ok := db.nodes[hash]; ok {
		db.lock.Unlock()
		return blob, nil
	}
	db.lock.Unlock()
	return db.diskdb.Get(hash[:])
}

// Commit flushes all dirty nodes up to (and including) the given root
// to the underlying disk database. After Commit, the dirty cache
// corresponding to those nodes is cleared.
func (db *Database) Commit(root types.Hash) error {
	db.lock.Lock()
	defer db.lock.Unlock()

	batch := db.diskdb.NewBatch()
	for hash, blob := range db.nodes {
		if err := batch.Put(hash[:], blob); err != nil {
			return err
		}
	}
	if err := batch.Write(); err != nil {
		return err
	}
	db.nodes = make(map[types.Hash][]byte)
	return nil
}

// CommitNodeSet writes a trienode.NodeSet (returned by Trie.Commit) into the
// dirty cache so it can later be flushed via Commit.
func (db *Database) CommitNodeSet(nodes *trienode.NodeSet) {
	if nodes == nil {
		return
	}
	db.lock.Lock()
	defer db.lock.Unlock()
	for _, n := range nodes.Nodes {
		if n.IsDeleted() {
			continue
		}
		cp := make([]byte, len(n.Blob))
		copy(cp, n.Blob)
		db.nodes[n.Hash] = cp
	}
}

// databaseReader implements NodeReader by looking up nodes in the Database.
type databaseReader struct {
	db *Database
}

// Node retrieves a trie node by hash. The owner and path are ignored in
// hash-based storage.
func (r *databaseReader) Node(owner types.Hash, path []byte, hash types.Hash) ([]byte, error) {
	return r.db.Node(hash)
}
