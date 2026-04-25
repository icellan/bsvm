// Copyright 2014 The go-ethereum Authors
// Adapted for the BSVM project.
//
// proof.go — Merkle proof generation for account and storage proofs.
// Per Spec 02, this is a dedicated deliverable file for proof generation.

package state

import (
	"fmt"

	db "github.com/icellan/bsvm/internal/db"
	"github.com/icellan/bsvm/pkg/crypto"
	"github.com/icellan/bsvm/pkg/types"
)

// GetProof generates a Merkle proof for the given account in the state trie.
// The proof consists of the encoded trie nodes on the path from the root to
// the account. The proof can be verified using mpt.VerifyProof with the
// state root and the keccak256-hashed address as the key.
func (s *StateDB) GetProof(addr types.Address) ([][]byte, error) {
	// Ensure dirty state is flushed to the trie so the proof reflects
	// the latest in-memory modifications.
	s.IntermediateRoot(true)

	// Use a proofList to collect the encoded trie nodes.
	var proof proofList
	err := s.trie.Prove(crypto.Keccak256(addr[:]), &proof)
	if err != nil {
		return nil, err
	}
	return proof, nil
}

// GetStorageProof generates a Merkle proof for the given storage slot within
// the given account's storage trie. The proof can be verified using
// mpt.VerifyProof with the account's storage root and the keccak256-hashed
// storage key.
func (s *StateDB) GetStorageProof(addr types.Address, key types.Hash) ([][]byte, error) {
	// Ensure dirty state is flushed so the storage trie root is up to date.
	s.IntermediateRoot(true)

	stateObject := s.getStateObject(addr)
	if stateObject == nil {
		// Account does not exist; return a valid empty proof.
		return [][]byte{}, nil
	}
	storageTrie, err := stateObject.openStorageTrie()
	if err != nil {
		return nil, err
	}
	var proof proofList
	err = storageTrie.Prove(crypto.Keccak256(key[:]), &proof)
	if err != nil {
		return nil, err
	}
	return proof, nil
}

// proofList implements db.Database by collecting the Put'd values into an
// ordered slice of byte slices. This is used to collect Merkle proof nodes
// during trie proof generation.
type proofList [][]byte

// Put appends a proof node to the list. The key is the node hash and the
// value is the RLP-encoded trie node.
func (p *proofList) Put(key []byte, value []byte) error {
	cp := make([]byte, len(value))
	copy(cp, value)
	*p = append(*p, cp)
	return nil
}

// Get is not supported by proofList and always returns an error.
func (p *proofList) Get(key []byte) ([]byte, error) {
	return nil, fmt.Errorf("proofList does not support Get")
}

// Has is not supported by proofList and always returns false.
func (p *proofList) Has(key []byte) (bool, error) {
	return false, nil
}

// Delete is not supported by proofList and is a no-op.
func (p *proofList) Delete(key []byte) error {
	return nil
}

// NewBatch is not supported by proofList. It returns a no-op batch
// whose Write method returns an error.
func (p *proofList) NewBatch() db.Batch {
	return &errBatch{}
}

// errBatch is a Batch that always returns an error on Write.
type errBatch struct {
	size int
}

func (b *errBatch) Put(_ []byte, value []byte) error {
	b.size += len(value)
	return nil
}

func (b *errBatch) Delete(_ []byte) error { return nil }

func (b *errBatch) Write() error {
	return fmt.Errorf("proofList does not support batch writes")
}

func (b *errBatch) Reset()         { b.size = 0 }
func (b *errBatch) ValueSize() int { return b.size }

// Close is a no-op for proofList.
func (p *proofList) Close() error {
	return nil
}
