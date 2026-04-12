// Copyright 2022 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// Adapted from go-ethereum core/state/transient_storage.go for the BSVM project.

package state

import "github.com/icellan/bsvm/pkg/types"

// transientStorage is a representation of EIP-1153 "Transient Storage".
type transientStorage map[types.Address]Storage

// newTransientStorage creates a new instance of a transientStorage.
func newTransientStorage() transientStorage {
	return make(transientStorage)
}

// Set sets the transient-storage `value` for `key` at the given `addr`.
func (t transientStorage) Set(addr types.Address, key, value types.Hash) {
	if value == (types.Hash{}) { // this is a 'delete'
		if _, ok := t[addr]; ok {
			delete(t[addr], key)
			if len(t[addr]) == 0 {
				delete(t, addr)
			}
		}
	} else {
		if _, ok := t[addr]; !ok {
			t[addr] = make(Storage)
		}
		t[addr][key] = value
	}
}

// Get gets the transient storage for `key` at the given `addr`.
func (t transientStorage) Get(addr types.Address, key types.Hash) types.Hash {
	val, ok := t[addr]
	if !ok {
		return types.Hash{}
	}
	return val[key]
}

// Copy does a deep copy of the transientStorage.
func (t transientStorage) Copy() transientStorage {
	storage := make(transientStorage)
	for key, value := range t {
		storage[key] = value.Copy()
	}
	return storage
}
