//go:build integration

// Package integration tests: prover economics.
//
// These tests verify that the coinbase address (the L2 block producer)
// earns gas fees from transactions. With baseFee=0 on our L2,
// effectiveGasPrice = gasPrice, so fee = gasUsed * gasPrice.
package integration

import (
	"math/big"
	"testing"

	"github.com/holiman/uint256"

	"github.com/icellan/bsvm/pkg/types"
)

// TestProverEconomics_CoinbaseEarnsGasFees verifies that the coinbase
// address receives gas fees after processing a transfer.
func TestProverEconomics_CoinbaseEarnsGasFees(t *testing.T) {
	bundle := happyPathSetup(t)

	preState := bundle.Node.StateDB()
	preBal := preState.GetBalance(bundle.Coinbase)
	t.Logf("coinbase balance before: %s", preBal)

	recipient := types.HexToAddress("0x0000000000000000000000000000000000000aa1")
	gasPrice := big.NewInt(1_000_000_000)
	tx := types.MustSignNewTx(bundle.TxKey, bundle.Signer, &types.LegacyTx{
		Nonce:    0,
		GasPrice: gasPrice,
		Gas:      21000,
		To:       &recipient,
		Value:    uint256.NewInt(1_000),
	})

	result, err := bundle.Node.ProcessBatch([]*types.Transaction{tx})
	if err != nil {
		t.Fatalf("ProcessBatch: %v", err)
	}
	if result.Receipts[0].Status != 1 {
		t.Fatalf("receipt status = %d", result.Receipts[0].Status)
	}

	gasUsed := result.Receipts[0].GasUsed
	expectedFee := new(uint256.Int).Mul(
		uint256.NewInt(gasUsed),
		uint256.NewInt(uint64(gasPrice.Int64())),
	)
	expectedBal := new(uint256.Int).Add(preBal, expectedFee)

	sdb := stateAt(t, bundle, result.StateRoot)
	postBal := sdb.GetBalance(bundle.Coinbase)
	if postBal.Cmp(expectedBal) != 0 {
		t.Errorf("coinbase balance = %s, want %s (fee=%s)", postBal, expectedBal, expectedFee)
	}
	t.Logf("coinbase earned %s wei from %d gas", expectedFee, gasUsed)
}

// TestProverEconomics_MultipleTxsFeeAccumulation verifies that fees from
// multiple transactions in a batch accumulate on the coinbase.
func TestProverEconomics_MultipleTxsFeeAccumulation(t *testing.T) {
	bundle := happyPathSetup(t)

	preState := bundle.Node.StateDB()
	preBal := preState.GetBalance(bundle.Coinbase)

	const numTxs = 5
	gasPrice := big.NewInt(2_000_000_000)
	txs := make([]*types.Transaction, numTxs)
	for i := 0; i < numTxs; i++ {
		recipient := types.HexToAddress("0x0000000000000000000000000000000000000bb1")
		txs[i] = types.MustSignNewTx(bundle.TxKey, bundle.Signer, &types.LegacyTx{
			Nonce:    uint64(i),
			GasPrice: gasPrice,
			Gas:      21000,
			To:       &recipient,
			Value:    uint256.NewInt(1),
		})
	}

	result, err := bundle.Node.ProcessBatch(txs)
	if err != nil {
		t.Fatalf("ProcessBatch: %v", err)
	}

	var totalGas uint64
	for i, r := range result.Receipts {
		if r.Status != 1 {
			t.Errorf("receipt[%d] status = %d", i, r.Status)
		}
		totalGas += r.GasUsed
	}

	expectedFee := new(uint256.Int).Mul(
		uint256.NewInt(totalGas),
		uint256.NewInt(uint64(gasPrice.Int64())),
	)
	expectedBal := new(uint256.Int).Add(preBal, expectedFee)

	sdb := stateAt(t, bundle, result.StateRoot)
	postBal := sdb.GetBalance(bundle.Coinbase)
	if postBal.Cmp(expectedBal) != 0 {
		t.Errorf("coinbase balance = %s, want %s (totalGas=%d)", postBal, expectedBal, totalGas)
	}
	t.Logf("coinbase earned %s wei from %d txs (%d gas)", expectedFee, numTxs, totalGas)
}
