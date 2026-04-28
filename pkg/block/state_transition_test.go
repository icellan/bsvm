package block

import (
	"errors"
	"math/big"
	"testing"

	"github.com/holiman/uint256"

	"github.com/icellan/bsvm/internal/db"
	"github.com/icellan/bsvm/pkg/crypto"
	"github.com/icellan/bsvm/pkg/state"
	"github.com/icellan/bsvm/pkg/types"
	"github.com/icellan/bsvm/pkg/vm"
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

// applyBlobTxFixture sets up a funded sender, a recipient, a header, and
// applies a single BlobTx with `nBlobs` versioned hashes plus
// `maxFeePerBlobGas`. Returns the sender address, the post-execution
// balance, the receipt, and any error from ApplyTransaction.
func applyBlobTxFixture(t *testing.T, nBlobs int, maxFeePerBlobGas uint64) (
	types.Address, *uint256.Int, *types.Receipt, error,
) {
	t.Helper()
	config := newTestChainConfig()
	database := db.NewMemoryDB()

	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	senderAddr := types.Address(crypto.PubkeyToAddress(key.PublicKey))
	recipientAddr := types.HexToAddress("0x1234567890abcdef1234567890abcdef12345678")

	// Fund sender with 1000 ether-equivalent (way more than needed).
	startBalanceBig := new(big.Int).Mul(big.NewInt(1000), new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil))
	startBalance, _ := uint256.FromBig(startBalanceBig)

	genesis := DefaultGenesis(testChainID)
	genesis.Alloc = map[types.Address]GenesisAccount{
		senderAddr: {Balance: startBalance},
	}
	genesisHeader, err := InitGenesis(database, genesis)
	if err != nil {
		t.Fatalf("InitGenesis: %v", err)
	}
	statedb, err := state.New(genesisHeader.StateRoot, database)
	if err != nil {
		t.Fatalf("state.New: %v", err)
	}

	header := &L2Header{
		ParentHash: genesisHeader.Hash(),
		Coinbase:   types.HexToAddress("0xcccccccccccccccccccccccccccccccccccccccc"),
		Number:     big.NewInt(1),
		GasLimit:   30_000_000,
		Timestamp:  1000,
		BaseFee:    new(big.Int),
	}

	blobHashes := make([]types.Hash, nBlobs)
	for i := range blobHashes {
		// EIP-4844 versioned hash: first byte = 0x01 (KZG version).
		blobHashes[i] = types.HexToHash("0x01" + "00000000000000000000000000000000000000000000000000000000000001")
		blobHashes[i][31] = byte(i + 1)
	}

	signer := types.LatestSignerForChainID(big.NewInt(testChainID))
	tx, err := types.SignNewTx(key, signer, &types.BlobTx{
		ChainID:             big.NewInt(testChainID),
		Nonce:               0,
		GasTipCap:           big.NewInt(1),
		GasFeeCap:           big.NewInt(1),
		Gas:                 21000,
		To:                  &recipientAddr,
		Value:               uint256.NewInt(0),
		BlobFeeCap:          new(big.Int).SetUint64(maxFeePerBlobGas),
		BlobVersionedHashes: blobHashes,
	})
	if err != nil {
		t.Fatalf("SignNewTx: %v", err)
	}

	gp := new(GasPool)
	gp.SetGas(header.GasLimit)
	var usedGas uint64
	coinbase := header.Coinbase
	receipt, err := ApplyTransaction(config, nil, &coinbase, gp, statedb, header, tx, &usedGas, vm.Config{}, nil)
	if err != nil {
		return senderAddr, statedb.GetBalance(senderAddr), nil, err
	}
	return senderAddr, statedb.GetBalance(senderAddr), receipt, nil
}

// TestApplyTransaction_BlobGasDebit_OneBlob verifies that a BlobTx with a
// single versioned hash debits exactly 131_072 wei from the sender on top
// of the execution-gas debit. This pins EIP-4844's upfront blob-fee burn
// behaviour and matches what revm computes for the same fixture.
func TestApplyTransaction_BlobGasDebit_OneBlob(t *testing.T) {
	// Baseline: a non-blob transfer with the same gas params.
	baselineSender, baselineBalance, _, err := applyTransferFixture(t)
	if err != nil {
		t.Fatalf("baseline transfer: %v", err)
	}
	_ = baselineSender

	blobSender, blobBalance, receipt, err := applyBlobTxFixture(t, 1, 1)
	if err != nil {
		t.Fatalf("BlobTx 1-hash: %v", err)
	}
	_ = blobSender
	if receipt.Status != types.ReceiptStatusSuccessful {
		t.Fatalf("BlobTx receipt status = %d, want %d",
			receipt.Status, types.ReceiptStatusSuccessful)
	}

	delta := new(uint256.Int).Sub(baselineBalance, blobBalance)
	expected := uint256.NewInt(vm.BlobTxBlobGasPerBlob) // 1 * 131072 * 1
	if delta.Cmp(expected) != 0 {
		t.Fatalf("BlobTx debited %s extra wei vs baseline, want %s (=0x%x)",
			delta, expected, vm.BlobTxBlobGasPerBlob)
	}
}

// TestApplyTransaction_BlobGasDebit_MultiBlob verifies the per-blob
// linear scaling of the upfront fee: N blobs => N*131_072 wei.
func TestApplyTransaction_BlobGasDebit_MultiBlob(t *testing.T) {
	baselineSender, baselineBalance, _, err := applyTransferFixture(t)
	if err != nil {
		t.Fatalf("baseline transfer: %v", err)
	}
	_ = baselineSender

	const nBlobs = 4
	_, blobBalance, _, err := applyBlobTxFixture(t, nBlobs, 1)
	if err != nil {
		t.Fatalf("BlobTx %d-hash: %v", nBlobs, err)
	}
	delta := new(uint256.Int).Sub(baselineBalance, blobBalance)
	expected := uint256.NewInt(uint64(nBlobs) * vm.BlobTxBlobGasPerBlob)
	if delta.Cmp(expected) != 0 {
		t.Fatalf("BlobTx %d-hash debited %s extra wei vs baseline, want %s",
			nBlobs, delta, expected)
	}
}

// TestApplyTransaction_BlobFeeCapTooLow rejects a BlobTx whose
// MaxFeePerBlobGas is below the prevailing blob_gas_price (here = 1).
// This mirrors revm's `BlobGasPriceGreaterThanMax` check.
func TestApplyTransaction_BlobFeeCapTooLow(t *testing.T) {
	_, _, _, err := applyBlobTxFixture(t, 1, 0)
	if err == nil {
		t.Fatal("expected ErrBlobFeeCapTooLow, got nil")
	}
	if !errors.Is(err, ErrBlobFeeCapTooLow) {
		t.Fatalf("expected ErrBlobFeeCapTooLow, got %v", err)
	}
}

// applyTransferFixture sets up the same sender/recipient/header as
// applyBlobTxFixture but submits a plain DynamicFeeTx instead. Used as
// the no-blob baseline for delta comparisons.
func applyTransferFixture(t *testing.T) (types.Address, *uint256.Int, *types.Receipt, error) {
	t.Helper()
	config := newTestChainConfig()
	database := db.NewMemoryDB()

	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	senderAddr := types.Address(crypto.PubkeyToAddress(key.PublicKey))
	recipientAddr := types.HexToAddress("0x1234567890abcdef1234567890abcdef12345678")

	startBalanceBig := new(big.Int).Mul(big.NewInt(1000), new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil))
	startBalance, _ := uint256.FromBig(startBalanceBig)
	genesis := DefaultGenesis(testChainID)
	genesis.Alloc = map[types.Address]GenesisAccount{
		senderAddr: {Balance: startBalance},
	}
	genesisHeader, err := InitGenesis(database, genesis)
	if err != nil {
		t.Fatalf("InitGenesis: %v", err)
	}
	statedb, err := state.New(genesisHeader.StateRoot, database)
	if err != nil {
		t.Fatalf("state.New: %v", err)
	}
	header := &L2Header{
		ParentHash: genesisHeader.Hash(),
		Coinbase:   types.HexToAddress("0xcccccccccccccccccccccccccccccccccccccccc"),
		Number:     big.NewInt(1),
		GasLimit:   30_000_000,
		Timestamp:  1000,
		BaseFee:    new(big.Int),
	}
	signer := types.LatestSignerForChainID(big.NewInt(testChainID))
	tx, err := types.SignNewTx(key, signer, &types.DynamicFeeTx{
		ChainID:   big.NewInt(testChainID),
		Nonce:     0,
		GasTipCap: big.NewInt(1),
		GasFeeCap: big.NewInt(1),
		Gas:       21000,
		To:        &recipientAddr,
		Value:     uint256.NewInt(0),
	})
	if err != nil {
		t.Fatalf("SignNewTx: %v", err)
	}
	gp := new(GasPool)
	gp.SetGas(header.GasLimit)
	var usedGas uint64
	coinbase := header.Coinbase
	receipt, err := ApplyTransaction(config, nil, &coinbase, gp, statedb, header, tx, &usedGas, vm.Config{}, nil)
	if err != nil {
		return senderAddr, statedb.GetBalance(senderAddr), nil, err
	}
	return senderAddr, statedb.GetBalance(senderAddr), receipt, nil
}
