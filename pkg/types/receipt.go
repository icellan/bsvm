package types

import (
	"bytes"
	"math/big"

	"github.com/icellan/bsvm/pkg/rlp"
)

const (
	// ReceiptStatusFailed indicates a transaction execution failure.
	ReceiptStatusFailed = uint64(0)
	// ReceiptStatusSuccessful indicates a successful transaction execution.
	ReceiptStatusSuccessful = uint64(1)
)

// Receipt represents the result of a transaction execution.
type Receipt struct {
	// Type is the EIP-2718 transaction type.
	Type uint8

	// PostState is the post-transaction state root (pre-Byzantium).
	PostState []byte

	// Status is the transaction execution status (post-Byzantium).
	Status uint64

	// CumulativeGasUsed is the total gas used in the block up to and
	// including this transaction.
	CumulativeGasUsed uint64

	// Bloom is the bloom filter for the logs in this receipt.
	Bloom Bloom

	// Logs contains the log entries emitted during execution.
	Logs []*Log

	// TxHash is the hash of the transaction.
	TxHash Hash

	// ContractAddress is the address of the newly created contract, if any.
	ContractAddress Address

	// GasUsed is the amount of gas used by this specific transaction.
	GasUsed uint64

	// BlockHash is the hash of the block containing this receipt.
	BlockHash Hash

	// BlockNumber is the number of the block containing this receipt.
	BlockNumber *big.Int

	// TransactionIndex is the index of the transaction in the block.
	TransactionIndex uint

	// EffectiveGasPrice is the actual gas price paid by the transaction.
	// Standard Ethereum tooling (ethers.js, Hardhat) requires this field.
	EffectiveGasPrice *big.Int

	// RolledBack indicates this receipt was invalidated by a cascade rollback.
	// When true, the transaction was in a speculative block that lost a
	// covenant advance race. The transaction may be re-included in a future
	// block but its effects (state changes, logs) from the original execution
	// are no longer valid.
	RolledBack bool

	// RolledBackAtBlock is the L2 block number at which the rollback occurred.
	// Zero if not rolled back.
	RolledBackAtBlock uint64
}

// receiptRLP is the RLP-serializable form of a receipt's consensus fields.
type receiptRLP struct {
	PostStateOrStatus []byte
	CumulativeGasUsed uint64
	Bloom             Bloom
	Logs              []*Log
}

// statusEncoding returns the byte encoding of the receipt status.
func (r *Receipt) statusEncoding() []byte {
	if len(r.PostState) > 0 {
		return r.PostState
	}
	if r.Status == ReceiptStatusSuccessful {
		return []byte{0x01}
	}
	return []byte{}
}

// Receipts is a slice of receipts.
type Receipts []*Receipt

// Len returns the number of receipts in the list.
func (rs Receipts) Len() int {
	return len(rs)
}

// EncodeIndex implements DerivableList for computing the receipt trie root.
// Legacy receipts: RLP([status_or_poststate, cumulativeGasUsed, bloom, logs]).
// Typed receipts: type_byte || RLP([...]).
func (rs Receipts) EncodeIndex(i int, w *bytes.Buffer) {
	r := rs[i]
	data := &receiptRLP{
		PostStateOrStatus: r.statusEncoding(),
		CumulativeGasUsed: r.CumulativeGasUsed,
		Bloom:             r.Bloom,
		Logs:              r.Logs,
	}
	switch r.Type {
	case LegacyTxType:
		rlp.Encode(w, data)
	default:
		w.WriteByte(r.Type)
		rlp.Encode(w, data)
	}
}
