package mpt

import (
	"bytes"

	"github.com/icellan/bsvm/pkg/rlp"
	"github.com/icellan/bsvm/pkg/types"
)

// DerivableList is an interface for types that can produce an ordered list
// of RLP-encoded items for computing a trie root hash.
type DerivableList interface {
	Len() int
	EncodeIndex(int, *bytes.Buffer)
}

// DeriveSha computes the root hash of a derivable list using a stack trie.
// This produces a Merkle Patricia Trie root that is bit-identical to what
// Ethereum produces for transaction roots, receipt roots, etc.
func DeriveSha(list DerivableList) types.Hash {
	if list.Len() == 0 {
		return types.EmptyRootHash
	}

	st := NewStackTrie(nil)
	var valueBuf bytes.Buffer

	for i := 0; i < list.Len(); i++ {
		// Key is the RLP encoding of the index.
		keyBytes, _ := rlp.EncodeToBytes(uint64(i))

		// Value is the item's RLP encoding.
		valueBuf.Reset()
		list.EncodeIndex(i, &valueBuf)

		st.Update(keyBytes, valueBuf.Bytes())
	}

	return st.Hash()
}
