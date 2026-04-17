//go:build integration

// Package integration tests: end-to-end state integrity rejection suite.
//
// Each test runs a real EVM transfer through the overlay's ProcessBatch,
// extracts the contract call arguments that would have been broadcast to
// BSV, tampers one field, and verifies the on-chain covenant script rejects
// the tampered advance. This proves the full pipeline: EVM execution ->
// mock proving -> arg serialisation -> on-chain verification.
//
// Only Basefold mode is tested end-to-end here because it has the smallest
// locking script (~5.8 KB) and fastest deploy. Groth16 modes have per-mode
// rejection tests in rollup_groth16_test.go and rollup_groth16_wa_test.go.
package integration

import (
	"crypto/sha256"
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/holiman/uint256"

	"github.com/icellan/bsvm/pkg/covenant"
	"github.com/icellan/bsvm/pkg/regtestharness"
	"github.com/icellan/bsvm/pkg/types"

	runar "github.com/icellan/runar/packages/runar-go"
	"runar-integration/helpers"
)

// stateIntegritySetup deploys a fresh BasefoldRollupContract with the
// harness's deterministic genesis state root, builds a no-broadcast bundle,
// and returns handles for plan-and-tamper tests. Each test gets distinct
// seeds derived from t.Name() so tests are parallel-safe.
func stateIntegritySetup(t *testing.T) (
	contract *runar.RunarContract,
	provider runar.Provider,
	signer runar.Signer,
	bundle *regtestharness.Bundle,
) {
	t.Helper()
	txSeed, cbSeed := siSeedsFromName(t.Name())
	cfg := regtestharness.Config{
		ChainID:      chainID,
		TxKeySeed:    txSeed,
		CoinbaseSeed: cbSeed,
		ProofMode:    covenant.ProofModeBasefold,
	}
	root, err := regtestharness.ComputeGenesisStateRoot(cfg)
	if err != nil {
		t.Fatalf("ComputeGenesisStateRoot: %v", err)
	}
	rootHex := hex.EncodeToString(root[:])
	contract, provider, signer, _ = deployBasefoldRollupWithStateRoot(t, rootHex)
	if err := helpers.Mine(1); err != nil {
		t.Fatalf("mine deploy: %v", err)
	}
	cfg.Contract = contract
	cfg.Provider = provider
	cfg.Signer = signer
	cfg.NoBroadcast = true // KEY: don't broadcast, just extract args
	bundle, err = regtestharness.Build(cfg)
	if err != nil {
		t.Fatalf("regtestharness.Build: %v", err)
	}
	t.Cleanup(func() { bundle.Node.Stop() })
	return contract, provider, signer, bundle
}

// siSeedsFromName derives two bytes from sha256("si:" + testName) so each
// test gets distinct TxKey / Coinbase seeds.
func siSeedsFromName(name string) (byte, byte) {
	sum := sha256.Sum256([]byte("si:" + name))
	return sum[0], sum[17]
}

// planTransfer builds a single 1-wei transfer through the overlay's
// ProcessBatch and PlanAdvance pipeline, returning the valid contract call
// arguments that would have been broadcast to BSV.
func planTransfer(t *testing.T, bundle *regtestharness.Bundle) *regtestharness.PlannedAdvance {
	t.Helper()
	recipient := types.HexToAddress("0x00000000000000000000000000000000000000d1")
	tx := types.MustSignNewTx(bundle.TxKey, bundle.Signer, &types.LegacyTx{
		Nonce:    0,
		GasPrice: big.NewInt(1_000_000_000),
		Gas:      21000,
		To:       &recipient,
		Value:    uint256.NewInt(1),
	})
	plan, err := bundle.PlanAdvance([]*types.Transaction{tx})
	if err != nil {
		t.Fatalf("PlanAdvance: %v", err)
	}
	return plan
}

// cloneArgs returns a shallow copy of the contract call argument slice so
// that tamper mutations do not affect the original.
func cloneArgs(args []interface{}) []interface{} {
	out := make([]interface{}, len(args))
	copy(out, args)
	return out
}

// ---------------------------------------------------------------------------
// Rejection tests
// ---------------------------------------------------------------------------

// TestStateIntegrity_WrongPreStateRoot runs a real EVM transfer, extracts
// the valid contract call args, flips the leading byte of the pre-state root
// in the public values blob, and verifies the on-chain covenant rejects the
// tampered advance.
func TestStateIntegrity_WrongPreStateRoot(t *testing.T) {
	contract, provider, signer, bundle := stateIntegritySetup(t)
	plan := planTransfer(t, bundle)
	args := cloneArgs(plan.Args)

	pv := args[2].(string)
	args[2] = "ff" + pv[2:] // flip leading byte of PV[0:2] hex

	_, _, err := contract.Call("advanceState", args, provider, signer, nil)
	if err == nil {
		t.Fatal("expected rejection for wrong pre-state root")
	}
	t.Logf("correctly rejected: %v", err)
}

// TestStateIntegrity_WrongPostStateRoot runs a real EVM transfer, extracts
// the valid contract call args, flips a byte at offset 64 in the public
// values blob (the post-state root region), and verifies on-chain rejection.
func TestStateIntegrity_WrongPostStateRoot(t *testing.T) {
	contract, provider, signer, bundle := stateIntegritySetup(t)
	plan := planTransfer(t, bundle)
	args := cloneArgs(plan.Args)

	pv := args[2].(string)
	args[2] = pv[:64] + "ff" + pv[66:] // flip byte at PV hex offset 64

	_, _, err := contract.Call("advanceState", args, provider, signer, nil)
	if err == nil {
		t.Fatal("expected rejection for wrong post-state root")
	}
	t.Logf("correctly rejected: %v", err)
}

// TestStateIntegrity_SkippedBlockNumber runs a real EVM transfer, extracts
// the valid contract call args, changes the block number to 2 (skipping
// block 1), and verifies the covenant rejects the non-sequential advance.
func TestStateIntegrity_SkippedBlockNumber(t *testing.T) {
	contract, provider, signer, bundle := stateIntegritySetup(t)
	plan := planTransfer(t, bundle)
	args := cloneArgs(plan.Args)

	args[1] = int64(2) // skip block 1, jump to 2

	_, _, err := contract.Call("advanceState", args, provider, signer, nil)
	if err == nil {
		t.Fatal("expected rejection for skipped block number")
	}
	t.Logf("correctly rejected: %v", err)
}

// TestStateIntegrity_BadProofBlob runs a real EVM transfer, extracts the
// valid contract call args, replaces the proof blob with one generated from
// a different seed (so its hash no longer matches the public values), and
// verifies the covenant rejects the mismatched proof.
func TestStateIntegrity_BadProofBlob(t *testing.T) {
	contract, provider, signer, bundle := stateIntegritySetup(t)
	plan := planTransfer(t, bundle)
	args := cloneArgs(plan.Args)

	args[4] = hexGenProofBlob(99, proofBlobSize) // different seed -> different hash

	_, _, err := contract.Call("advanceState", args, provider, signer, nil)
	if err == nil {
		t.Fatal("expected rejection for tampered proof blob")
	}
	t.Logf("correctly rejected: %v", err)
}

// TestStateIntegrity_WrongChainID runs a real EVM transfer, extracts the
// valid contract call args, replaces the chain ID bytes at PV offset 136
// (hex offset 272) with a wrong chain ID (999), and verifies the covenant
// rejects the mismatch.
func TestStateIntegrity_WrongChainID(t *testing.T) {
	contract, provider, signer, bundle := stateIntegritySetup(t)
	plan := planTransfer(t, bundle)
	args := cloneArgs(plan.Args)

	pv := args[2].(string)
	wrongChainHex := fullPVNum2binHexLE(999, 8)
	args[2] = pv[:272] + wrongChainHex + pv[288:]

	_, _, err := contract.Call("advanceState", args, provider, signer, nil)
	if err == nil {
		t.Fatal("expected rejection for wrong chain ID")
	}
	t.Logf("correctly rejected: %v", err)
}

// TestStateIntegrity_BadBatchData runs a real EVM transfer, extracts the
// valid contract call args, replaces the batch data with a blob bound to
// different state roots (so its hash no longer matches the public values),
// and verifies the covenant rejects the mismatched batch data.
func TestStateIntegrity_BadBatchData(t *testing.T) {
	contract, provider, signer, bundle := stateIntegritySetup(t)
	plan := planTransfer(t, bundle)
	args := cloneArgs(plan.Args)

	args[3] = hexGenBatchData("ff"+hexZeros32()[2:], hexStateRoot(99), batchDataSize)

	_, _, err := contract.Call("advanceState", args, provider, signer, nil)
	if err == nil {
		t.Fatal("expected rejection for tampered batch data")
	}
	t.Logf("correctly rejected: %v", err)
}

// TestStateIntegrity_InvalidKoalaBearField runs a real EVM transfer,
// extracts the valid contract call args, sets proofC (args[7]) to an
// arbitrary value that is NOT the KoalaBear field product of proofA and
// proofB, and verifies the covenant rejects the invalid field check.
func TestStateIntegrity_InvalidKoalaBearField(t *testing.T) {
	contract, provider, signer, bundle := stateIntegritySetup(t)
	plan := planTransfer(t, bundle)
	args := cloneArgs(plan.Args)

	args[7] = int64(12345) // wrong product

	_, _, err := contract.Call("advanceState", args, provider, signer, nil)
	if err == nil {
		t.Fatal("expected rejection for invalid KoalaBear field product")
	}
	t.Logf("correctly rejected: %v", err)
}
