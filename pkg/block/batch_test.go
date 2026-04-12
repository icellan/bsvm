package block

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"testing"

	"github.com/icellan/bsvm/pkg/types"
)

// makeBatchData returns a BatchData with the given number of transactions,
// each txSize bytes long. If txSize is 0, default random 100-byte txs are
// used.
func makeBatchData(txCount int, txSize int) *BatchData {
	if txSize == 0 {
		txSize = 100
	}
	txs := make([][]byte, txCount)
	for i := range txs {
		tx := make([]byte, txSize)
		rand.Read(tx)
		txs[i] = tx
	}
	return &BatchData{
		Version:        BatchVersion,
		Timestamp:      1700000000,
		Coinbase:       types.HexToAddress("0x1234567890abcdef1234567890abcdef12345678"),
		ParentHash:     types.HexToHash("0xabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd"),
		BSVBlockHash:   types.HexToHash("0x1111111111111111111111111111111111111111111111111111111111111111"),
		Transactions:   txs,
		DepositHorizon: 850_000,
	}
}

func TestBatchData_EncodeDecode_RoundTrip(t *testing.T) {
	batch := makeBatchData(3, 64)

	encoded, err := EncodeBatchData(batch)
	if err != nil {
		t.Fatalf("EncodeBatchData: %v", err)
	}

	decoded, err := DecodeBatchData(encoded)
	if err != nil {
		t.Fatalf("DecodeBatchData: %v", err)
	}

	if decoded.Version != batch.Version {
		t.Errorf("version: got %d, want %d", decoded.Version, batch.Version)
	}
	if decoded.Timestamp != batch.Timestamp {
		t.Errorf("timestamp: got %d, want %d", decoded.Timestamp, batch.Timestamp)
	}
	if decoded.Coinbase != batch.Coinbase {
		t.Errorf("coinbase: got %s, want %s", decoded.Coinbase.Hex(), batch.Coinbase.Hex())
	}
	if decoded.ParentHash != batch.ParentHash {
		t.Errorf("parentHash: got %s, want %s", decoded.ParentHash.Hex(), batch.ParentHash.Hex())
	}
	if decoded.BSVBlockHash != batch.BSVBlockHash {
		t.Errorf("bsvBlockHash: got %s, want %s", decoded.BSVBlockHash.Hex(), batch.BSVBlockHash.Hex())
	}
	if decoded.DepositHorizon != batch.DepositHorizon {
		t.Errorf("depositHorizon: got %d, want %d", decoded.DepositHorizon, batch.DepositHorizon)
	}
	if len(decoded.Transactions) != len(batch.Transactions) {
		t.Fatalf("tx count: got %d, want %d", len(decoded.Transactions), len(batch.Transactions))
	}
	for i := range batch.Transactions {
		if !bytes.Equal(decoded.Transactions[i], batch.Transactions[i]) {
			t.Errorf("tx[%d] mismatch", i)
		}
	}
}

func TestBatchData_EncodeDecode_EmptyTransactions(t *testing.T) {
	batch := makeBatchData(0, 0)

	encoded, err := EncodeBatchData(batch)
	if err != nil {
		t.Fatalf("EncodeBatchData: %v", err)
	}

	// With 0 transactions the encoded size is exactly the header.
	if len(encoded) != batchHeaderSize {
		t.Errorf("encoded size: got %d, want %d", len(encoded), batchHeaderSize)
	}

	decoded, err := DecodeBatchData(encoded)
	if err != nil {
		t.Fatalf("DecodeBatchData: %v", err)
	}

	if len(decoded.Transactions) != 0 {
		t.Errorf("tx count: got %d, want 0", len(decoded.Transactions))
	}
}

func TestBatchData_EncodeDecode_MultipleTransactions(t *testing.T) {
	counts := []int{5, 50, 128}
	for _, count := range counts {
		t.Run("", func(t *testing.T) {
			batch := makeBatchData(count, 80)

			encoded, err := EncodeBatchData(batch)
			if err != nil {
				t.Fatalf("EncodeBatchData(%d txs): %v", count, err)
			}

			decoded, err := DecodeBatchData(encoded)
			if err != nil {
				t.Fatalf("DecodeBatchData(%d txs): %v", count, err)
			}

			if len(decoded.Transactions) != count {
				t.Fatalf("tx count: got %d, want %d", len(decoded.Transactions), count)
			}

			for i := range batch.Transactions {
				if !bytes.Equal(decoded.Transactions[i], batch.Transactions[i]) {
					t.Errorf("tx[%d] mismatch", i)
				}
			}
		})
	}
}

func TestBatchData_EncodeDecode_LargeTransaction(t *testing.T) {
	batch := makeBatchData(1, 100*1024) // 100 KB transaction.

	encoded, err := EncodeBatchData(batch)
	if err != nil {
		t.Fatalf("EncodeBatchData: %v", err)
	}

	decoded, err := DecodeBatchData(encoded)
	if err != nil {
		t.Fatalf("DecodeBatchData: %v", err)
	}

	if len(decoded.Transactions) != 1 {
		t.Fatalf("tx count: got %d, want 1", len(decoded.Transactions))
	}
	if !bytes.Equal(decoded.Transactions[0], batch.Transactions[0]) {
		t.Error("large transaction data mismatch")
	}
}

func TestBatchData_Decode_BadMagic(t *testing.T) {
	batch := makeBatchData(1, 32)
	encoded, err := EncodeBatchData(batch)
	if err != nil {
		t.Fatalf("EncodeBatchData: %v", err)
	}

	// Corrupt the magic bytes.
	encoded[0] = 'X'

	_, err = DecodeBatchData(encoded)
	if err == nil {
		t.Fatal("expected error for bad magic, got nil")
	}
}

func TestBatchData_Decode_BadVersion(t *testing.T) {
	batch := makeBatchData(1, 32)
	encoded, err := EncodeBatchData(batch)
	if err != nil {
		t.Fatalf("EncodeBatchData: %v", err)
	}

	// Set version to 0xFF.
	encoded[4] = 0xFF

	_, err = DecodeBatchData(encoded)
	if err == nil {
		t.Fatal("expected error for bad version, got nil")
	}
}

func TestBatchData_Decode_Truncated(t *testing.T) {
	batch := makeBatchData(3, 64)
	encoded, err := EncodeBatchData(batch)
	if err != nil {
		t.Fatalf("EncodeBatchData: %v", err)
	}

	// Truncate at various points within the encoded data.
	truncatePoints := []int{
		batchHeaderSize - 1, // mid-header
		batchHeaderSize + 2, // after header, mid first tx length
		batchHeaderSize + 6, // after first tx length, mid first tx data
		len(encoded) - 1,    // missing last byte of last tx
	}

	for _, point := range truncatePoints {
		if point >= len(encoded) || point <= 0 {
			continue
		}
		_, err := DecodeBatchData(encoded[:point])
		if err == nil {
			t.Errorf("expected error when truncating at byte %d, got nil", point)
		}
	}
}

func TestBatchData_Decode_TooShort(t *testing.T) {
	shortData := []byte("BSV") // Less than header size.

	_, err := DecodeBatchData(shortData)
	if err == nil {
		t.Fatal("expected error for too-short data, got nil")
	}
}

func TestBatchData_Hash_Deterministic(t *testing.T) {
	batch := makeBatchData(5, 50)
	encoded, err := EncodeBatchData(batch)
	if err != nil {
		t.Fatalf("EncodeBatchData: %v", err)
	}

	hash1 := BatchDataHash(encoded)
	hash2 := BatchDataHash(encoded)

	if hash1 != hash2 {
		t.Errorf("hash not deterministic: %s != %s", hash1.Hex(), hash2.Hex())
	}

	// Verify it is actually double SHA-256.
	first := sha256.Sum256(encoded)
	second := sha256.Sum256(first[:])
	expected := types.BytesToHash(second[:])
	if hash1 != expected {
		t.Errorf("hash mismatch: got %s, want %s", hash1.Hex(), expected.Hex())
	}
}

func TestBatchData_Hash_DifferentData(t *testing.T) {
	batch1 := makeBatchData(2, 50)
	batch2 := makeBatchData(2, 50)
	// Ensure they are actually different by changing the timestamp.
	batch2.Timestamp = batch1.Timestamp + 1

	encoded1, err := EncodeBatchData(batch1)
	if err != nil {
		t.Fatalf("EncodeBatchData batch1: %v", err)
	}
	encoded2, err := EncodeBatchData(batch2)
	if err != nil {
		t.Fatalf("EncodeBatchData batch2: %v", err)
	}

	hash1 := BatchDataHash(encoded1)
	hash2 := BatchDataHash(encoded2)

	if hash1 == hash2 {
		t.Error("different batch data produced the same hash")
	}
}

func TestBatchData_Encode_MaxSize(t *testing.T) {
	// Create a batch that exceeds MaxBatchDataSize.
	// MaxBatchDataSize is 4 MB. A single tx of ~4 MB plus overhead will
	// exceed the limit.
	largeTx := make([]byte, MaxBatchDataSize)
	rand.Read(largeTx)

	batch := &BatchData{
		Version:        BatchVersion,
		Timestamp:      1700000000,
		Coinbase:       types.Address{},
		ParentHash:     types.Hash{},
		Transactions:   [][]byte{largeTx},
		DepositHorizon: 0,
	}

	_, err := EncodeBatchData(batch)
	if err == nil {
		t.Fatal("expected error for oversized batch, got nil")
	}
}

func TestBatchData_Decode_CorruptedTxLen(t *testing.T) {
	batch := makeBatchData(2, 32)
	encoded, err := EncodeBatchData(batch)
	if err != nil {
		t.Fatalf("EncodeBatchData: %v", err)
	}

	// Corrupt the first transaction's length field to claim a huge size.
	// The tx length field starts at batchHeaderSize.
	encoded[batchHeaderSize] = 0xFF
	encoded[batchHeaderSize+1] = 0xFF
	encoded[batchHeaderSize+2] = 0xFF
	encoded[batchHeaderSize+3] = 0xFF

	_, err = DecodeBatchData(encoded)
	if err == nil {
		t.Fatal("expected error for corrupted tx length, got nil")
	}
}
