// Copyright 2022 The go-ethereum Authors
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
	"github.com/icellan/bsvm/pkg/types"
)

// NodeDatabase is the interface for accessing trie nodes from storage.
// This is a simplified version of geth's triedb/database.NodeDatabase.
type NodeDatabase interface {
	// NodeReader returns a node reader associated with the specific state.
	NodeReader(stateRoot types.Hash) (NodeReader, error)
}

// NodeReader reads trie nodes.
type NodeReader interface {
	// Node retrieves the trie node blob with the provided trie identifier,
	// node path and the corresponding node hash.
	Node(owner types.Hash, path []byte, hash types.Hash) ([]byte, error)
}

// trieReader is a wrapper of the underlying node reader. It's not safe
// for concurrent usage.
type trieReader struct {
	owner  types.Hash
	reader NodeReader
	banned map[string]struct{} // Marker to prevent node from being accessed, for tests
}

// newTrieReader initializes the trie reader with the given node reader.
func newTrieReader(stateRoot, owner types.Hash, db NodeDatabase) (*trieReader, error) {
	if stateRoot == (types.Hash{}) || stateRoot == types.EmptyRootHash {
		return &trieReader{owner: owner}, nil
	}
	reader, err := db.NodeReader(stateRoot)
	if err != nil {
		return nil, &MissingNodeError{Owner: owner, NodeHash: stateRoot, err: err}
	}
	return &trieReader{owner: owner, reader: reader}, nil
}

// newEmptyReader initializes the pure in-memory reader. All read operations
// should be forbidden and returns the MissingNodeError.
func newEmptyReader() *trieReader {
	return &trieReader{}
}

// node retrieves the rlp-encoded trie node with the provided trie node
// information. An MissingNodeError will be returned in case the node is
// not found or any error is encountered.
//
// Don't modify the returned byte slice since it's not deep-copied and
// still be referenced by database.
func (r *trieReader) node(path []byte, hash types.Hash) ([]byte, error) {
	// Perform the logics in tests for preventing trie node access.
	if r.banned != nil {
		if _, ok := r.banned[string(path)]; ok {
			return nil, &MissingNodeError{Owner: r.owner, NodeHash: hash, Path: path}
		}
	}
	if r.reader == nil {
		return nil, &MissingNodeError{Owner: r.owner, NodeHash: hash, Path: path}
	}
	blob, err := r.reader.Node(r.owner, path, hash)
	if err != nil || len(blob) == 0 {
		return nil, &MissingNodeError{Owner: r.owner, NodeHash: hash, Path: path, err: err}
	}
	return blob, nil
}
