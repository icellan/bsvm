package block

import (
	"math/big"
	"testing"

	"github.com/holiman/uint256"

	"github.com/icellan/bsvm/pkg/crypto"
	"github.com/icellan/bsvm/pkg/types"
)

// TestTransactionToMessage_BlobFieldsSurface pins the EIP-4844 contract
// the dual-EVM equivalence harness relies on: a type-3 BlobTx must
// surface BlobVersionedHashes and BlobFeeCap onto the Message, so that
// the Go EVM agrees with revm on blob-gas accounting and BLOBHASH
// semantics. Non-blob txs continue to leave both fields nil.
func TestTransactionToMessage_BlobFieldsSurface(t *testing.T) {
	const chainID int64 = 1337
	signer := types.NewLondonSigner(big.NewInt(chainID))

	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	t.Run("BlobTx surfaces hashes and blob fee cap", func(t *testing.T) {
		to := types.HexToAddress("0x4444444444444444444444444444444444444444")
		hash := types.HexToHash("0x010000000000000000000000000000000000000000000000000000000000abcd")
		blobFeeCap := big.NewInt(3_000_000_000)
		tx, err := types.SignNewTx(key, signer, &types.BlobTx{
			ChainID:             big.NewInt(chainID),
			Nonce:               0,
			GasTipCap:           big.NewInt(1_000_000_000),
			GasFeeCap:           big.NewInt(2_000_000_000),
			Gas:                 100_000,
			To:                  &to,
			Value:               uint256.NewInt(0),
			AccessList:          types.AccessList{},
			BlobFeeCap:          blobFeeCap,
			BlobVersionedHashes: []types.Hash{hash},
		})
		if err != nil {
			t.Fatalf("SignNewTx BlobTx: %v", err)
		}
		if tx.Type() != types.BlobTxType {
			t.Fatalf("expected BlobTxType (0x03), got 0x%02X", tx.Type())
		}

		msg, err := TransactionToMessage(tx, signer, big.NewInt(1))
		if err != nil {
			t.Fatalf("TransactionToMessage: %v", err)
		}

		if got := len(msg.BlobHashes); got != 1 {
			t.Fatalf("BlobHashes len = %d, want 1", got)
		}
		if msg.BlobHashes[0] != hash {
			t.Fatalf("BlobHashes[0] = %s, want %s", msg.BlobHashes[0].Hex(), hash.Hex())
		}
		if msg.BlobGasFeeCap == nil {
			t.Fatal("BlobGasFeeCap must not be nil for type-3 tx")
		}
		if msg.BlobGasFeeCap.Cmp(blobFeeCap) != 0 {
			t.Fatalf("BlobGasFeeCap = %s, want %s", msg.BlobGasFeeCap, blobFeeCap)
		}

		// Aliasing check: mutating the source slice / value must not affect
		// the Message — the converter copies both fields.
		hash[0] = 0xFF
		if msg.BlobHashes[0] == hash {
			t.Fatal("BlobHashes was not copied (aliased to source)")
		}
		blobFeeCap.SetInt64(0xDEADBEEF)
		if msg.BlobGasFeeCap.Int64() == 0xDEADBEEF {
			t.Fatal("BlobGasFeeCap was not copied (aliased to source)")
		}
	})

	t.Run("DynamicFeeTx leaves blob fields nil", func(t *testing.T) {
		to := types.HexToAddress("0x3333333333333333333333333333333333333333")
		tx, err := types.SignNewTx(key, signer, &types.DynamicFeeTx{
			ChainID:   big.NewInt(chainID),
			Nonce:     1,
			GasTipCap: big.NewInt(1),
			GasFeeCap: big.NewInt(1_000_000_000),
			Gas:       21_000,
			To:        &to,
			Value:     uint256.NewInt(1),
		})
		if err != nil {
			t.Fatalf("SignNewTx DynamicFeeTx: %v", err)
		}

		msg, err := TransactionToMessage(tx, signer, big.NewInt(1))
		if err != nil {
			t.Fatalf("TransactionToMessage: %v", err)
		}
		if msg.BlobHashes != nil {
			t.Fatalf("BlobHashes must be nil for non-blob tx, got %v", msg.BlobHashes)
		}
		if msg.BlobGasFeeCap != nil {
			t.Fatalf("BlobGasFeeCap must be nil for non-blob tx, got %s", msg.BlobGasFeeCap)
		}
	})

	t.Run("LegacyTx leaves blob fields nil", func(t *testing.T) {
		to := types.HexToAddress("0x1111111111111111111111111111111111111111")
		tx, err := types.SignNewTx(key, signer, &types.LegacyTx{
			Nonce:    2,
			GasPrice: big.NewInt(1_000_000_000),
			Gas:      21_000,
			To:       &to,
			Value:    uint256.NewInt(1),
		})
		if err != nil {
			t.Fatalf("SignNewTx LegacyTx: %v", err)
		}

		msg, err := TransactionToMessage(tx, signer, big.NewInt(1))
		if err != nil {
			t.Fatalf("TransactionToMessage: %v", err)
		}
		if msg.BlobHashes != nil {
			t.Fatalf("BlobHashes must be nil for legacy tx, got %v", msg.BlobHashes)
		}
		if msg.BlobGasFeeCap != nil {
			t.Fatalf("BlobGasFeeCap must be nil for legacy tx, got %s", msg.BlobGasFeeCap)
		}
	})
}
