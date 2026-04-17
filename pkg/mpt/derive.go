package mpt

import (
	"bytes"

	"github.com/icellan/bsvm/internal/db"
	"github.com/icellan/bsvm/pkg/rlp"
	"github.com/icellan/bsvm/pkg/types"
)

// DerivableList is an interface for types that can produce an ordered list
// of RLP-encoded items for computing a trie root hash.
type DerivableList interface {
	Len() int
	EncodeIndex(int, *bytes.Buffer)
}

// DeriveSha computes the root hash of a derivable list using a Merkle
// Patricia Trie keyed by rlp(index). This produces a root that is
// bit-identical to what Ethereum produces for transaction roots, receipt
// roots, etc.
//
// Note: we use a plain Trie (not a StackTrie) because StackTrie requires
// keys to be inserted in strictly ascending byte order, and rlp(index)
// keys are NOT monotonic in index order — for example rlp(0)=0x80 sorts
// after rlp(1..127)=0x01..0x7f. A plain Trie accepts keys in any order
// and produces the canonical Ethereum root.
func DeriveSha(list DerivableList) types.Hash {
	if list.Len() == 0 {
		return types.EmptyRootHash
	}

	tr := NewEmpty(NewDatabase(db.NewMemoryDB()))
	var valueBuf bytes.Buffer

	for i := 0; i < list.Len(); i++ {
		// Key is the RLP encoding of the index.
		keyBytes, _ := rlp.EncodeToBytes(uint64(i))

		// Value is the item's RLP encoding.
		valueBuf.Reset()
		list.EncodeIndex(i, &valueBuf)

		// Trie.Update never returns an error for a non-committed trie,
		// but we still check it to be defensive.
		if err := tr.Update(keyBytes, valueBuf.Bytes()); err != nil {
			// This can only happen if the trie has already been committed,
			// which is impossible here since we just created it.
			panic("mpt: DeriveSha Update on fresh trie: " + err.Error())
		}
	}

	return tr.Hash()
}
