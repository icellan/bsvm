package state

import (
	"io"
	"math/big"

	"github.com/holiman/uint256"

	"github.com/icellan/bsvm/pkg/rlp"
	"github.com/icellan/bsvm/pkg/types"
)

// Account represents an Ethereum account in the state trie.
// The fields are stored as an RLP-encoded list: [Nonce, Balance, Root, CodeHash].
type Account struct {
	Nonce    uint64
	Balance  *uint256.Int
	Root     types.Hash // storage trie root
	CodeHash []byte     // keccak256 of code
}

// rlpAccount is an intermediate struct used for RLP encoding and decoding.
// It converts Balance from uint256.Int to big.Int for geth-compatible encoding.
type rlpAccount struct {
	Nonce    uint64
	Balance  *big.Int
	Root     types.Hash
	CodeHash []byte
}

// newAccount creates a new empty account with default values.
func newAccount() Account {
	return Account{
		Balance:  new(uint256.Int),
		Root:     types.EmptyRootHash,
		CodeHash: types.EmptyCodeHash.Bytes(),
	}
}

// EncodeRLP implements rlp.Encoder for Account.
func (a *Account) EncodeRLP(w io.Writer) error {
	bal := new(big.Int)
	if a.Balance != nil {
		bal = a.Balance.ToBig()
	}
	ra := rlpAccount{
		Nonce:    a.Nonce,
		Balance:  bal,
		Root:     a.Root,
		CodeHash: a.CodeHash,
	}
	return rlp.Encode(w, &ra)
}

// DecodeRLP implements rlp.Decoder for Account.
func (a *Account) DecodeRLP(s *rlp.Stream) error {
	var ra rlpAccount
	if err := s.Decode(&ra); err != nil {
		return err
	}
	a.Nonce = ra.Nonce
	if ra.Balance != nil {
		var overflow bool
		a.Balance, overflow = uint256.FromBig(ra.Balance)
		if overflow {
			a.Balance = new(uint256.Int)
		}
	} else {
		a.Balance = new(uint256.Int)
	}
	a.Root = ra.Root
	a.CodeHash = ra.CodeHash
	return nil
}
