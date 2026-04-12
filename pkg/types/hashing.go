package types

import (
	"bytes"
)

// DerivableList is an interface for types that can produce an ordered list
// of RLP-encoded items for computing a trie root hash. The canonical
// implementation of DeriveSha using a Merkle Patricia Trie is in
// pkg/mpt/derive.go. This interface is defined here so that types like
// Receipts can implement it without importing pkg/mpt.
type DerivableList interface {
	Len() int
	EncodeIndex(int, *bytes.Buffer)
}
