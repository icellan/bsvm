package block

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/icellan/bsvm/pkg/types"
)

// BatchVersion is the current batch data format version.
const BatchVersion byte = 0x02

// BatchMagic is the 4-byte magic prefix for batch data.
var BatchMagic = [4]byte{'B', 'S', 'V', 'M'}

// MaxBatchDataSize is the maximum size of encoded batch data (4 MB).
const MaxBatchDataSize = 4 * 1024 * 1024

// batchHeaderSize is the fixed-size portion of the batch encoding:
// magic(4) + version(1) + timestamp(8) + coinbase(20) + parentHash(32) +
// bsvBlockHash(32) + depositHorizon(8) + txCount(4) = 109 bytes.
const batchHeaderSize = 4 + 1 + 8 + 20 + 32 + 32 + 8 + 4

// maxReasonableTxCount is a sanity limit on the number of transactions in a
// single batch to avoid allocating enormous slices when decoding corrupt data.
const maxReasonableTxCount = 1_000_000

// BatchData holds the canonical encoding of an L2 batch for embedding in
// a BSV covenant advance transaction's OP_RETURN output.
type BatchData struct {
	// Version is the format version (0x02).
	Version byte
	// Timestamp is the block timestamp (proposer sets, replayers use verbatim).
	Timestamp uint64
	// Coinbase is the block producer's address.
	Coinbase types.Address
	// ParentHash is the parent block hash (for ordering).
	ParentHash types.Hash
	// BSVBlockHash is the BSV block hash used for PREVRANDAO derivation.
	BSVBlockHash types.Hash
	// Transactions contains the RLP-encoded transactions.
	Transactions [][]byte
	// DepositHorizon is the BSV block height for deposit inclusion cutoff.
	DepositHorizon uint64
}

// EncodeBatchData encodes batch data with the BSVM\x02 envelope.
//
// Format:
//
//	BSVM(4) + version(1) + timestamp(8) + coinbase(20) + parentHash(32) +
//	bsvBlockHash(32) + depositHorizon(8) + txCount(4) + [txLen(4) + txData]...
//
// Returns an error if the encoded size exceeds MaxBatchDataSize.
func EncodeBatchData(batch *BatchData) ([]byte, error) {
	// Pre-compute total size to validate against MaxBatchDataSize and to
	// allocate the buffer in one shot.
	totalSize := batchHeaderSize
	for _, tx := range batch.Transactions {
		totalSize += 4 + len(tx) // txLen(4) + txData
	}

	if totalSize > MaxBatchDataSize {
		return nil, fmt.Errorf("batch data size %d exceeds maximum %d", totalSize, MaxBatchDataSize)
	}

	buf := make([]byte, totalSize)
	offset := 0

	// Magic bytes.
	copy(buf[offset:], BatchMagic[:])
	offset += 4

	// Version.
	buf[offset] = batch.Version
	offset++

	// Timestamp (big-endian uint64).
	binary.BigEndian.PutUint64(buf[offset:], batch.Timestamp)
	offset += 8

	// Coinbase (20 bytes).
	copy(buf[offset:], batch.Coinbase[:])
	offset += types.AddressLength

	// Parent hash (32 bytes).
	copy(buf[offset:], batch.ParentHash[:])
	offset += types.HashLength

	// BSV block hash (32 bytes).
	copy(buf[offset:], batch.BSVBlockHash[:])
	offset += types.HashLength

	// Deposit horizon (big-endian uint64).
	binary.BigEndian.PutUint64(buf[offset:], batch.DepositHorizon)
	offset += 8

	// Transaction count (big-endian uint32).
	binary.BigEndian.PutUint32(buf[offset:], uint32(len(batch.Transactions)))
	offset += 4

	// Transactions: each is txLen(4) + txData.
	for _, tx := range batch.Transactions {
		binary.BigEndian.PutUint32(buf[offset:], uint32(len(tx)))
		offset += 4
		copy(buf[offset:], tx)
		offset += len(tx)
	}

	return buf, nil
}

// DecodeBatchData decodes batch data from the BSVM\x02 envelope format.
// Returns an error if the magic bytes, version, or structure is invalid.
func DecodeBatchData(data []byte) (*BatchData, error) {
	if len(data) < batchHeaderSize {
		return nil, errors.New("batch data too short for header")
	}

	offset := 0

	// Validate magic bytes.
	if data[0] != BatchMagic[0] || data[1] != BatchMagic[1] ||
		data[2] != BatchMagic[2] || data[3] != BatchMagic[3] {
		return nil, fmt.Errorf("invalid batch magic: got %x, want %x", data[:4], BatchMagic[:])
	}
	offset += 4

	// Validate version.
	version := data[offset]
	if version != BatchVersion {
		return nil, fmt.Errorf("unsupported batch version: got %d, want %d", version, BatchVersion)
	}
	offset++

	// Timestamp.
	timestamp := binary.BigEndian.Uint64(data[offset:])
	offset += 8

	// Coinbase.
	var coinbase types.Address
	copy(coinbase[:], data[offset:offset+types.AddressLength])
	offset += types.AddressLength

	// Parent hash.
	var parentHash types.Hash
	copy(parentHash[:], data[offset:offset+types.HashLength])
	offset += types.HashLength

	// BSV block hash.
	var bsvBlockHash types.Hash
	copy(bsvBlockHash[:], data[offset:offset+types.HashLength])
	offset += types.HashLength

	// Deposit horizon.
	depositHorizon := binary.BigEndian.Uint64(data[offset:])
	offset += 8

	// Transaction count.
	txCount := binary.BigEndian.Uint32(data[offset:])
	offset += 4

	if txCount > maxReasonableTxCount {
		return nil, fmt.Errorf("unreasonable transaction count: %d", txCount)
	}

	// Parse transactions.
	transactions := make([][]byte, 0, txCount)
	for i := uint32(0); i < txCount; i++ {
		if offset+4 > len(data) {
			return nil, fmt.Errorf("batch data truncated at transaction %d length", i)
		}
		txLen := binary.BigEndian.Uint32(data[offset:])
		offset += 4

		if offset+int(txLen) > len(data) {
			return nil, fmt.Errorf("batch data truncated at transaction %d data: need %d bytes, have %d",
				i, txLen, len(data)-offset)
		}

		tx := make([]byte, txLen)
		copy(tx, data[offset:offset+int(txLen)])
		offset += int(txLen)
		transactions = append(transactions, tx)
	}

	return &BatchData{
		Version:        version,
		Timestamp:      timestamp,
		Coinbase:       coinbase,
		ParentHash:     parentHash,
		BSVBlockHash:   bsvBlockHash,
		Transactions:   transactions,
		DepositHorizon: depositHorizon,
	}, nil
}

// BatchDataHash returns the hash256 (double SHA-256) of the encoded batch data.
// This hash is committed in the SP1 public values for binding verification.
// hash256 matches Bitcoin's OP_HASH256: SHA256(SHA256(data)).
func BatchDataHash(encoded []byte) types.Hash {
	first := sha256.Sum256(encoded)
	second := sha256.Sum256(first[:])
	return types.BytesToHash(second[:])
}
