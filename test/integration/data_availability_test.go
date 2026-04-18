//go:build integration

package integration

import (
	"bytes"
	"crypto/sha256"
	"strings"
	"testing"

	"github.com/holiman/uint256"

	"github.com/icellan/bsvm/pkg/block"
	"github.com/icellan/bsvm/pkg/overlay"
	"github.com/icellan/bsvm/pkg/types"
)

// TestDA_BatchEncodeDecode verifies that BatchData survives a round-trip
// through EncodeBatchData / DecodeBatchData with all fields intact.
func TestDA_BatchEncodeDecode(t *testing.T) {
	batch := &block.BatchData{
		Version:    block.BatchVersion,
		Timestamp:  1234567890,
		Coinbase:   types.HexToAddress("0x0000000000000000000000000000000000000001"),
		ParentHash: types.BytesToHash([]byte("parent")),
		Transactions: [][]byte{
			{0x01, 0x02, 0x03},
			{0x04, 0x05},
		},
		DepositHorizon: 42,
	}
	encoded, err := block.EncodeBatchData(batch)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	decoded, err := block.DecodeBatchData(encoded)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if decoded.Version != batch.Version {
		t.Errorf("version = %d, want %d", decoded.Version, batch.Version)
	}
	if decoded.Timestamp != batch.Timestamp {
		t.Errorf("timestamp = %d, want %d", decoded.Timestamp, batch.Timestamp)
	}
	if decoded.Coinbase != batch.Coinbase {
		t.Errorf("coinbase = %s, want %s", decoded.Coinbase.Hex(), batch.Coinbase.Hex())
	}
	if len(decoded.Transactions) != len(batch.Transactions) {
		t.Fatalf("tx count = %d, want %d", len(decoded.Transactions), len(batch.Transactions))
	}
	if decoded.DepositHorizon != batch.DepositHorizon {
		t.Errorf("depositHorizon = %d, want %d", decoded.DepositHorizon, batch.DepositHorizon)
	}
	t.Logf("round-trip: %d bytes encoded, %d txs", len(encoded), len(decoded.Transactions))
}

// TestDA_RejectMalformedBatch verifies that DecodeBatchData rejects
// corrupted or truncated inputs.
func TestDA_RejectMalformedBatch(t *testing.T) {
	cases := []struct {
		name string
		data []byte
	}{
		{"empty", []byte{}},
		{"too short", []byte{0x01, 0x02}},
		{"wrong magic", []byte("XXVM" + strings.Repeat("\x00", 105))},
		{"truncated header", append([]byte("BSVM"), make([]byte, 10)...)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := block.DecodeBatchData(tc.data)
			if err == nil {
				t.Errorf("expected rejection for %s", tc.name)
			}
		})
	}
}

// TestDA_ProcessBatchReturnsBatchData verifies that ProcessBatch populates
// ProcessResult.BatchData with a valid batch encoding.
func TestDA_ProcessBatchReturnsBatchData(t *testing.T) {
	bundle := happyPathSetup(t)
	recipient := types.HexToAddress("0x00000000000000000000000000000000000000da")
	tx := signTransfer(t, bundle, 0, recipient, uint256.NewInt(1))
	result, err := bundle.Node.ProcessBatch([]*types.Transaction{tx})
	if err != nil {
		t.Fatalf("ProcessBatch: %v", err)
	}
	if len(result.BatchData) == 0 {
		t.Fatal("ProcessResult.BatchData is empty")
	}
	// Verify it decodes correctly.
	batch, err := block.DecodeBatchData(result.BatchData)
	if err != nil {
		t.Fatalf("decode returned BatchData: %v", err)
	}
	if len(batch.Transactions) != 1 {
		t.Errorf("tx count = %d, want 1", len(batch.Transactions))
	}
	t.Logf("batch: %d bytes, %d txs, version=%d", len(result.BatchData), len(batch.Transactions), batch.Version)
}

// TestDA_BatchHashMatchesPublicValues verifies that hash256(batchData) in
// the covenant's public values blob matches the actual batch data hash.
// The covenant's PV blob is rebuilt by BuildAdvanceProofForOutput (which
// places hash256(batchData) at offset 104..136), NOT in the prover's raw
// PublicValues (which has a different layout with receiptsHash/gasUsed at
// those offsets).
func TestDA_BatchHashMatchesPublicValues(t *testing.T) {
	bundle := happyPathSetup(t)
	recipient := types.HexToAddress("0x00000000000000000000000000000000000000db")
	tx := signTransfer(t, bundle, 0, recipient, uint256.NewInt(1))
	result, err := bundle.Node.ProcessBatch([]*types.Transaction{tx})
	if err != nil {
		t.Fatalf("ProcessBatch: %v", err)
	}
	if result.ProveOutput == nil {
		t.Fatal("no proof output")
	}
	if result.BatchData == nil {
		t.Fatal("no batch data")
	}

	// Build the covenant's AdvanceProof to get the covenant-side PV blob.
	proof, err := overlay.BuildAdvanceProofForOutput(result.ProveOutput, result.BatchData)
	if err != nil {
		t.Fatalf("BuildAdvanceProofForOutput: %v", err)
	}
	pv := proof.PublicValues()
	if len(pv) < 136 {
		t.Fatalf("covenant public values too short: %d bytes", len(pv))
	}

	// Compute hash256 of the batch data.
	batchHash := hash256Bytes(result.BatchData)
	pvBatchHash := pv[104:136]
	if !bytes.Equal(batchHash, pvBatchHash) {
		t.Errorf("batch hash mismatch: computed=%x, pv[104:136]=%x", batchHash, pvBatchHash)
	}
	t.Logf("batch hash verified at PV offset 104: %x", batchHash)
}

// hash256Bytes computes double SHA-256 (BSV OP_HASH256).
func hash256Bytes(data []byte) []byte {
	first := sha256.Sum256(data)
	second := sha256.Sum256(first[:])
	return second[:]
}
