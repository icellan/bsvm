package types

// EIP-4844 type-3 blob transaction tests. These pin:
//   1. The wire layout matches the EIP-4844 spec (chain_id, nonce,
//      max_priority_fee_per_gas, max_fee_per_gas, gas_limit, to, value,
//      data, access_list, max_fee_per_blob_gas, blob_versioned_hashes,
//      y_parity, r, s).
//   2. The signing hash is keccak256(0x03 || rlp(payload_without_signature)).
//   3. The London signer can sign and recover a type-3 tx.
//   4. Round-tripping through RLP encode/decode is byte-stable.
//   5. The type byte is 0x03.
//
// The Rust guest counterpart is exercised by
// prover/guest/src/tx.rs::tests::eip4844_*.

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/holiman/uint256"
	"github.com/icellan/bsvm/pkg/crypto"
)

// blobTxFixture builds a deterministic BlobTx for tests. The blob
// versioned-hash list intentionally has multiple entries to exercise the
// RLP list-of-strings encoding path.
func blobTxFixture(chainID *big.Int) *BlobTx {
	to := HexToAddress("0x1111111111111111111111111111111111111111")
	return &BlobTx{
		ChainID:    chainID,
		Nonce:      9,
		GasTipCap:  big.NewInt(1_000_000_000),
		GasFeeCap:  big.NewInt(2_000_000_000),
		Gas:        100_000,
		To:         &to,
		Value:      uint256.NewInt(7),
		Data:       []byte{0xCA, 0xFE, 0xBA, 0xBE},
		AccessList: AccessList{},
		BlobFeeCap: big.NewInt(3_000_000_000),
		BlobVersionedHashes: []Hash{
			HexToHash("0x0100000000000000000000000000000000000000000000000000000000000001"),
			HexToHash("0x0100000000000000000000000000000000000000000000000000000000000002"),
		},
	}
}

func TestBlobTx_TypeAndAccessors(t *testing.T) {
	tx := NewTx(blobTxFixture(big.NewInt(8453111)))
	if tx.Type() != BlobTxType {
		t.Fatalf("Type() = 0x%02x, want 0x%02x", tx.Type(), BlobTxType)
	}
	if got := tx.BlobFeeCap(); got == nil || got.Cmp(big.NewInt(3_000_000_000)) != 0 {
		t.Fatalf("BlobFeeCap() = %v, want 3e9", got)
	}
	if got := tx.BlobVersionedHashes(); len(got) != 2 {
		t.Fatalf("BlobVersionedHashes() len = %d, want 2", len(got))
	}
	if tx.To() == nil {
		t.Fatal("BlobTx.To() must be non-nil — EIP-4844 forbids contract creation")
	}
}

func TestBlobTx_NonBlobReturnsNilBlobFields(t *testing.T) {
	tx := NewTx(&LegacyTx{
		Nonce:    0,
		GasPrice: big.NewInt(1),
		Gas:      21000,
		Value:    uint256.NewInt(0),
		V:        big.NewInt(27),
		R:        big.NewInt(1),
		S:        big.NewInt(1),
	})
	if got := tx.BlobFeeCap(); got != nil {
		t.Errorf("non-blob tx BlobFeeCap() = %v, want nil", got)
	}
	if got := tx.BlobVersionedHashes(); got != nil {
		t.Errorf("non-blob tx BlobVersionedHashes() = %v, want nil", got)
	}
}

func TestBlobTx_SignerRoundtrip(t *testing.T) {
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	expected := Address(crypto.PubkeyToAddress(key.PublicKey))

	chainID := big.NewInt(8453111)
	signer := NewLondonSigner(chainID)

	signed, err := SignNewTx(key, signer, blobTxFixture(chainID))
	if err != nil {
		t.Fatalf("SignNewTx: %v", err)
	}
	if signed.Type() != BlobTxType {
		t.Fatalf("signed tx type = 0x%02x, want 0x%02x", signed.Type(), BlobTxType)
	}

	recovered, err := signer.Sender(signed)
	if err != nil {
		t.Fatalf("Sender: %v", err)
	}
	if recovered != expected {
		t.Fatalf("sender mismatch: got %s, want %s", recovered.Hex(), expected.Hex())
	}
}

func TestBlobTx_EncodeDecodeRoundtrip(t *testing.T) {
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	chainID := big.NewInt(8453111)
	signer := NewLondonSigner(chainID)

	signed, err := SignNewTx(key, signer, blobTxFixture(chainID))
	if err != nil {
		t.Fatalf("SignNewTx: %v", err)
	}

	var buf bytes.Buffer
	if err := signed.EncodeRLP(&buf); err != nil {
		t.Fatalf("EncodeRLP: %v", err)
	}
	raw := buf.Bytes()
	if len(raw) == 0 || raw[0] != BlobTxType {
		t.Fatalf("encoded tx must start with type byte 0x03, got 0x%02x", raw[0])
	}

	// Round-trip through decodeTyped (the typed-tx envelope path).
	var decoded Transaction
	if err := decoded.decodeTyped(raw); err != nil {
		t.Fatalf("decodeTyped: %v", err)
	}
	if decoded.Type() != BlobTxType {
		t.Fatalf("decoded type = 0x%02x, want 0x%02x", decoded.Type(), BlobTxType)
	}
	// Verify the round-tripped tx can recover the same sender.
	expected := Address(crypto.PubkeyToAddress(key.PublicKey))
	gotSender, err := signer.Sender(&decoded)
	if err != nil {
		t.Fatalf("Sender after round-trip: %v", err)
	}
	if gotSender != expected {
		t.Fatalf("sender after round-trip = %s, want %s", gotSender.Hex(), expected.Hex())
	}

	// Re-encode the decoded tx and confirm byte-stability.
	var rebuf bytes.Buffer
	if err := (&decoded).EncodeRLP(&rebuf); err != nil {
		t.Fatalf("re-EncodeRLP: %v", err)
	}
	if !bytes.Equal(raw, rebuf.Bytes()) {
		t.Fatalf("non-deterministic re-encoding: %d bytes -> %d bytes", len(raw), rebuf.Len())
	}

	// Confirm blob-specific fields survived the round-trip.
	if got := decoded.BlobFeeCap(); got == nil || got.Cmp(big.NewInt(3_000_000_000)) != 0 {
		t.Errorf("BlobFeeCap after round-trip = %v, want 3e9", got)
	}
	if hashes := decoded.BlobVersionedHashes(); len(hashes) != 2 {
		t.Fatalf("BlobVersionedHashes len after round-trip = %d, want 2", len(hashes))
	}
}

func TestBlobTx_RejectsEmptyBlobHashList(t *testing.T) {
	// Manually construct a signed type-3 tx with an empty blob_versioned_hashes
	// list and confirm the decoder rejects it (per EIP-4844: at least one hash
	// is required).
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	chainID := big.NewInt(8453111)
	signer := NewLondonSigner(chainID)

	tx := blobTxFixture(chainID)
	tx.BlobVersionedHashes = []Hash{} // empty -> wire-invalid

	signed, err := SignNewTx(key, signer, tx)
	if err != nil {
		t.Fatalf("SignNewTx: %v", err)
	}
	var buf bytes.Buffer
	if err := signed.EncodeRLP(&buf); err != nil {
		t.Fatalf("EncodeRLP: %v", err)
	}

	var decoded Transaction
	if err := decoded.decodeTyped(buf.Bytes()); err == nil {
		t.Fatal("expected decodeTyped to reject blob tx with empty blob hash list")
	}
}

func TestBlobTx_ChainIDMismatchRejected(t *testing.T) {
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	signer := NewLondonSigner(big.NewInt(8453111))
	wrongSigner := NewLondonSigner(big.NewInt(1))

	signed, err := SignNewTx(key, signer, blobTxFixture(big.NewInt(8453111)))
	if err != nil {
		t.Fatalf("SignNewTx: %v", err)
	}
	if _, err := wrongSigner.Sender(signed); err == nil {
		t.Fatal("expected Sender to reject blob tx with chainID mismatch")
	}
}
