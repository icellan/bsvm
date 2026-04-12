package block

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"

	"github.com/icellan/bsvm/pkg/crypto"
	"github.com/icellan/bsvm/pkg/mpt"
	"github.com/icellan/bsvm/pkg/rlp"
	"github.com/icellan/bsvm/pkg/types"
)

// MaxExtraDataSize is the maximum allowed size of the Extra field in an
// L2Header. Per the BSVM spec, this is 32 bytes.
const MaxExtraDataSize = 32

// L2Header is the header of an L2 block. It contains metadata about the block
// including the state root, transaction root, and receipt root.
type L2Header struct {
	ParentHash  types.Hash    `json:"parentHash"`
	Coinbase    types.Address `json:"miner"`
	StateRoot   types.Hash    `json:"stateRoot"`
	TxHash      types.Hash    `json:"transactionsRoot"`
	ReceiptHash types.Hash    `json:"receiptsRoot"`
	LogsBloom   types.Bloom   `json:"logsBloom"`
	Number      *big.Int      `json:"number"`
	GasLimit    uint64        `json:"gasLimit"`
	GasUsed     uint64        `json:"gasUsed"`
	Timestamp   uint64        `json:"timestamp"`
	BaseFee     *big.Int      `json:"baseFeePerGas"`
	Extra       []byte        `json:"extraData"`
}

// Hash returns the keccak256 hash of the RLP-encoded header.
func (h *L2Header) Hash() types.Hash {
	data, _ := rlp.EncodeToBytes(h)
	return types.BytesToHash(crypto.Keccak256(data))
}

// ValidateHeader checks that the given L2Header satisfies structural
// constraints required by the BSVM spec:
//   - Extra data must not exceed MaxExtraDataSize (32 bytes)
//   - Number must not be nil
//   - GasUsed must not exceed GasLimit
func ValidateHeader(header *L2Header) error {
	if header.Number == nil {
		return errors.New("header number must not be nil")
	}
	if len(header.Extra) > MaxExtraDataSize {
		return fmt.Errorf("header extra data too long: %d > %d", len(header.Extra), MaxExtraDataSize)
	}
	if header.GasUsed > header.GasLimit {
		return fmt.Errorf("header gas used exceeds gas limit: %d > %d", header.GasUsed, header.GasLimit)
	}
	return nil
}

// L2Block is a complete L2 block containing a header, transactions, and
// receipts.
type L2Block struct {
	Header       *L2Header            `json:"header"`
	Transactions []*types.Transaction `json:"transactions"`
	Receipts     []*types.Receipt     `json:"receipts,omitempty"`

	// Cached values.
	hash types.Hash
	size uint64
}

// NewBlock creates a new L2 block from the given header, transactions, and receipts.
// The transaction and receipt roots are computed from the provided lists.
func NewBlock(header *L2Header, txs []*types.Transaction, receipts []*types.Receipt) *L2Block {
	b := &L2Block{Header: copyHeader(header)}

	if len(txs) == 0 {
		b.Header.TxHash = types.EmptyRootHash
	} else {
		b.Header.TxHash = mpt.DeriveSha(Transactions(txs))
		b.Transactions = make([]*types.Transaction, len(txs))
		copy(b.Transactions, txs)
	}

	if len(receipts) == 0 {
		b.Header.ReceiptHash = types.EmptyRootHash
	} else {
		b.Header.ReceiptHash = mpt.DeriveSha(types.Receipts(receipts))
		b.Header.LogsBloom = types.CreateBloom(receipts)
		b.Receipts = make([]*types.Receipt, len(receipts))
		copy(b.Receipts, receipts)
	}

	return b
}

// NewBlockWithHeader creates a block with the given header and no transactions.
func NewBlockWithHeader(header *L2Header) *L2Block {
	return &L2Block{Header: copyHeader(header)}
}

// Number returns the block number.
func (b *L2Block) Number() *big.Int {
	return new(big.Int).Set(b.Header.Number)
}

// NumberU64 returns the block number as a uint64.
func (b *L2Block) NumberU64() uint64 {
	return b.Header.Number.Uint64()
}

// Hash returns the keccak256 hash of the block's header.
func (b *L2Block) Hash() types.Hash {
	if b.hash == (types.Hash{}) {
		b.hash = b.Header.Hash()
	}
	return b.hash
}

// ParentHash returns the parent block's hash.
func (b *L2Block) ParentHash() types.Hash {
	return b.Header.ParentHash
}

// GasLimit returns the block's gas limit.
func (b *L2Block) GasLimit() uint64 {
	return b.Header.GasLimit
}

// GasUsed returns the total gas used in this block.
func (b *L2Block) GasUsed() uint64 {
	return b.Header.GasUsed
}

// Coinbase returns the coinbase address (block beneficiary).
func (b *L2Block) Coinbase() types.Address {
	return b.Header.Coinbase
}

// StateRoot returns the state root hash after this block.
func (b *L2Block) StateRoot() types.Hash {
	return b.Header.StateRoot
}

// Time returns the block timestamp.
func (b *L2Block) Time() uint64 {
	return b.Header.Timestamp
}

// BaseFee returns the block's base fee per gas.
func (b *L2Block) BaseFee() *big.Int {
	if b.Header.BaseFee == nil {
		return new(big.Int)
	}
	return new(big.Int).Set(b.Header.BaseFee)
}

// Transactions implements mpt.DerivableList for computing the transaction root.
type Transactions []*types.Transaction

// Len returns the number of transactions.
func (ts Transactions) Len() int {
	return len(ts)
}

// EncodeIndex encodes the i-th transaction into the provided buffer.
func (ts Transactions) EncodeIndex(i int, w *bytes.Buffer) {
	ts[i].EncodeRLP(w)
}

// copyHeader creates a deep copy of an L2Header.
func copyHeader(h *L2Header) *L2Header {
	cpy := *h
	if h.Number != nil {
		cpy.Number = new(big.Int).Set(h.Number)
	}
	if h.BaseFee != nil {
		cpy.BaseFee = new(big.Int).Set(h.BaseFee)
	}
	if h.Extra != nil {
		cpy.Extra = make([]byte, len(h.Extra))
		copy(cpy.Extra, h.Extra)
	}
	return &cpy
}
