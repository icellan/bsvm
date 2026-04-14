//go:build integration

// Package integration tests: end-to-end happy-path suite.
//
// These tests are Phase 1 of the BSVM-INTEGRATION-TESTS-PROMPT.md attack-
// vector suite. They establish the pattern every subsequent phase will
// reuse: deterministic per-test seeds feed regtestharness.Build, each test
// deploys its own BasefoldRollupContract, drives bundle.Node.ProcessBatch,
// and asserts on tips, receipts, and state. No tampered-args negative
// tests, bridge tests, or multi-node tests appear here — those ship in
// Phase 2.
//
// All tests run on ProofModeBasefold because it has the smallest locking
// script and the fastest per-advance broadcast time; proof-mode
// parameterisation arrives in Phase 2 with the state-integrity rejection
// tests where mode coverage actually matters.
package integration

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/holiman/uint256"

	"github.com/icellan/bsvm/pkg/covenant"
	"github.com/icellan/bsvm/pkg/crypto"
	"github.com/icellan/bsvm/pkg/regtestharness"
	"github.com/icellan/bsvm/pkg/state"
	"github.com/icellan/bsvm/pkg/types"

	"runar-integration/helpers"
)

// storageContractCreationCode is the hand-written init+runtime bytecode for
// a 7-byte EVM contract that stores the first function argument into
// storage slot 0 and halts. Used by TestHappyPath_DeployAndSetStorage and
// TestHappyPath_DeployAndCallInSameBatch.
//
// Init bytecode (12 bytes): 6007600c60003960076000f3
//   PUSH1 0x07  — runtime length
//   PUSH1 0x0c  — runtime offset in this init code
//   PUSH1 0x00  — memory destination
//   CODECOPY    — copy runtime to memory[0:7]
//   PUSH1 0x07  — return size
//   PUSH1 0x00  — return offset
//   RETURN
//
// Runtime bytecode (7 bytes): 60043560005500
//   PUSH1 0x04  — calldata offset (skip 4-byte selector)
//   CALLDATALOAD — load 32 bytes from calldata[4:36] onto stack
//   PUSH1 0x00  — storage slot 0
//   SSTORE      — store top-of-stack value into slot 0
//   STOP
var storageContractCreationCode = mustHex("6007600c60003960076000f360043560005500")

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// encodeStorageSetCall encodes a call to the storage contract's implicit
// setter. The 4-byte prefix is the keccak256("set(uint256)") selector; the
// contract itself ignores it but real EVM tooling expects a selector.
func encodeStorageSetCall(v uint64) []byte {
	out := make([]byte, 36)
	// keccak256("set(uint256)")[:4] = 0x60fe47b1
	out[0] = 0x60
	out[1] = 0xfe
	out[2] = 0x47
	out[3] = 0xb1
	binary.BigEndian.PutUint64(out[36-8:], v)
	return out
}

// happyPathSetup deploys a fresh BasefoldRollupContract, builds a bundle
// against it, starts the confirmation watcher, and registers a t.Cleanup
// that stops the overlay node. Per-test seed derivation from t.Name()
// guarantees distinct funding wallets and distinct L2 coinbase keys so
// parallel-safe test isolation is automatic.
func happyPathSetup(t *testing.T) *regtestharness.Bundle {
	t.Helper()

	txSeed, cbSeed := seedsFromName(t.Name())

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

	contract, provider, signer, _ := deployBasefoldRollupWithStateRoot(t, rootHex)
	if err := helpers.Mine(1); err != nil {
		t.Fatalf("mine deploy: %v", err)
	}

	cfg.Contract = contract
	cfg.Provider = provider
	cfg.Signer = signer
	bundle, err := regtestharness.Build(cfg)
	if err != nil {
		t.Fatalf("regtestharness.Build: %v", err)
	}
	t.Cleanup(func() { bundle.Node.Stop() })

	bundle.Node.StartConfirmationWatcher(bundle.Client, 500*time.Millisecond)
	return bundle
}

// seedsFromName derives two bytes from sha256(testName) so each test gets
// distinct TxKey / Coinbase seeds without hardcoding a table.
func seedsFromName(name string) (byte, byte) {
	sum := sha256.Sum256([]byte(name))
	return sum[0], sum[17]
}

// signTransfer builds and signs a LegacyTx sending value wei from
// bundle.TxKey to to.
func signTransfer(t *testing.T, bundle *regtestharness.Bundle, nonce uint64, to types.Address, value *uint256.Int) *types.Transaction {
	t.Helper()
	return types.MustSignNewTx(bundle.TxKey, bundle.Signer, &types.LegacyTx{
		Nonce:    nonce,
		GasPrice: big.NewInt(1_000_000_000),
		Gas:      21000,
		To:       &to,
		Value:    value,
	})
}

// signCreate builds and signs a LegacyTx with To=nil and the supplied init
// code as Data. Used for contract deployments.
func signCreate(t *testing.T, bundle *regtestharness.Bundle, nonce uint64, code []byte) *types.Transaction {
	t.Helper()
	return types.MustSignNewTx(bundle.TxKey, bundle.Signer, &types.LegacyTx{
		Nonce:    nonce,
		GasPrice: big.NewInt(1_000_000_000),
		Gas:      200_000,
		To:       nil,
		Value:    uint256.NewInt(0),
		Data:     code,
	})
}

// signCall builds and signs a LegacyTx to an existing contract address.
func signCall(t *testing.T, bundle *regtestharness.Bundle, nonce uint64, to types.Address, data []byte) *types.Transaction {
	t.Helper()
	return types.MustSignNewTx(bundle.TxKey, bundle.Signer, &types.LegacyTx{
		Nonce:    nonce,
		GasPrice: big.NewInt(1_000_000_000),
		Gas:      100_000,
		To:       &to,
		Value:    uint256.NewInt(0),
		Data:     data,
	})
}

// stateAt returns a StateDB rooted at the given state root using the
// bundle's memory database. For reads only — do not Commit.
func stateAt(t *testing.T, bundle *regtestharness.Bundle, root types.Hash) *state.StateDB {
	t.Helper()
	sdb, err := state.New(root, bundle.Database)
	if err != nil {
		t.Fatalf("state.New(%s): %v", root.Hex(), err)
	}
	return sdb
}

// waitCond polls cond every 50 ms until it returns true or the timeout
// elapses.
func waitCond(t *testing.T, timeout time.Duration, desc string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !cond() {
		t.Fatalf("timed out waiting for %s", desc)
	}
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// TestHappyPath_SimpleTransfer sends one transfer from the genesis-funded
// wallet to a fresh recipient and verifies:
//   - ProcessBatch returns without error
//   - The receipt is successful (Status == 1, GasUsed == 21000)
//   - State at the new post-state root reflects the transferred value
//   - ExecutionTip, ProvenTip == 1; ConfirmedTip == 0 (not yet mined)
//   - After mining 1 BSV block, ConfirmedTip == 1
func TestHappyPath_SimpleTransfer(t *testing.T) {
	bundle := happyPathSetup(t)

	recipient := types.HexToAddress("0x00000000000000000000000000000000000000a1")
	transfer := uint256.NewInt(1_000_000) // 1e6 wei

	tx := signTransfer(t, bundle, 0, recipient, transfer)

	result, err := bundle.Node.ProcessBatch([]*types.Transaction{tx})
	if err != nil {
		t.Fatalf("ProcessBatch: %v", err)
	}

	if got := len(result.Receipts); got != 1 {
		t.Fatalf("receipts len = %d, want 1", got)
	}
	r := result.Receipts[0]
	if r.Status != 1 {
		t.Errorf("receipt status = %d, want 1 (success)", r.Status)
	}
	if r.GasUsed != 21000 {
		t.Errorf("receipt gasUsed = %d, want 21000", r.GasUsed)
	}

	// Recipient balance == transfer value.
	sdb := stateAt(t, bundle, result.StateRoot)
	if got := sdb.GetBalance(recipient); got.Cmp(transfer) != 0 {
		t.Errorf("recipient balance = %s, want %s", got, transfer)
	}

	// Sender balance dropped by (transfer + gas fee).
	expectedFee := new(uint256.Int).Mul(uint256.NewInt(21000), uint256.NewInt(1_000_000_000))
	expectedDrain := new(uint256.Int).Add(transfer, expectedFee)
	initialBalance := uint256.NewInt(1_000_000_000_000_000_000)
	expectedSender := new(uint256.Int).Sub(initialBalance, expectedDrain)
	if got := sdb.GetBalance(bundle.TxAddr); got.Cmp(expectedSender) != 0 {
		t.Errorf("sender balance = %s, want %s (drain = %s)", got, expectedSender, expectedDrain)
	}

	// Tips: execution and proven at 1; confirmed still 0.
	if got := bundle.Node.ExecutionTip(); got != 1 {
		t.Errorf("ExecutionTip = %d, want 1", got)
	}
	if got := bundle.Node.ProvenTip(); got != 1 {
		t.Errorf("ProvenTip = %d, want 1", got)
	}
	if got := bundle.Node.ConfirmedTip(); got != 0 {
		t.Errorf("ConfirmedTip pre-mining = %d, want 0", got)
	}

	// Mine 1 BSV block to confirm the advance.
	if err := helpers.Mine(1); err != nil {
		t.Fatalf("mine +1: %v", err)
	}
	waitCond(t, 60*time.Second, "ConfirmedTip>=1", func() bool {
		return bundle.Node.ConfirmedTip() >= 1
	})

	// Covenant UTXO advanced exactly once.
	txids := bundle.Client.TxIDs()
	if got := len(txids); got != 1 {
		t.Errorf("client.TxIDs len = %d, want 1", got)
	}
}

// TestHappyPath_MultipleTransfersInBatch submits 10 transfers in a single
// batch and verifies:
//   - All 10 receipts are successful
//   - Sum of receipt.GasUsed equals the block's total GasUsed
//   - Each of the 10 distinct recipients shows the correct balance
//   - The batch advances block number by exactly 1
func TestHappyPath_MultipleTransfersInBatch(t *testing.T) {
	bundle := happyPathSetup(t)

	const numTxs = 10
	transfer := uint256.NewInt(1_000)

	txs := make([]*types.Transaction, numTxs)
	recipients := make([]types.Address, numTxs)
	for i := 0; i < numTxs; i++ {
		recipients[i] = types.HexToAddress(
			fmt.Sprintf("0x00000000000000000000000000000000000000b%d", i),
		)
		txs[i] = signTransfer(t, bundle, uint64(i), recipients[i], transfer)
	}

	result, err := bundle.Node.ProcessBatch(txs)
	if err != nil {
		t.Fatalf("ProcessBatch: %v", err)
	}

	if got := len(result.Receipts); got != numTxs {
		t.Fatalf("receipts len = %d, want %d", got, numTxs)
	}

	// Every receipt succeeded; accumulate gas.
	var sumGas uint64
	for i, r := range result.Receipts {
		if r.Status != 1 {
			t.Errorf("receipt[%d] status = %d, want 1", i, r.Status)
		}
		sumGas += r.GasUsed
	}

	// Sum of per-tx gas equals block gas used.
	if got := result.Block.GasUsed(); got != sumGas {
		t.Errorf("block.GasUsed() = %d, want %d (sum of receipts)", got, sumGas)
	}

	// Every recipient's balance equals transfer.
	sdb := stateAt(t, bundle, result.StateRoot)
	for i, addr := range recipients {
		if got := sdb.GetBalance(addr); got.Cmp(transfer) != 0 {
			t.Errorf("recipient[%d] balance = %s, want %s", i, got, transfer)
		}
	}

	// Block number advanced by exactly 1.
	if got := result.Block.NumberU64(); got != 1 {
		t.Errorf("block number = %d, want 1", got)
	}
	if got := bundle.Node.ExecutionTip(); got != 1 {
		t.Errorf("ExecutionTip = %d, want 1", got)
	}

	// Single covenant advance for the entire 10-tx batch.
	if got := len(bundle.Client.TxIDs()); got != 1 {
		t.Errorf("client.TxIDs len = %d, want 1", got)
	}
}

// TestHappyPath_DeployAndSetStorage deploys the 19-byte storage contract,
// calls it with value 42, verifies slot 0 == 42, calls it again with
// value 99, verifies slot 0 == 99. Three covenant advances total.
func TestHappyPath_DeployAndSetStorage(t *testing.T) {
	bundle := happyPathSetup(t)

	// Batch 1: deploy.
	deployTx := signCreate(t, bundle, 0, storageContractCreationCode)
	r1, err := bundle.Node.ProcessBatch([]*types.Transaction{deployTx})
	if err != nil {
		t.Fatalf("deploy ProcessBatch: %v", err)
	}
	if got := r1.Receipts[0].Status; got != 1 {
		t.Fatalf("deploy receipt status = %d, want 1", got)
	}
	contractAddr := r1.Receipts[0].ContractAddress
	if contractAddr == (types.Address{}) {
		t.Fatal("deploy receipt has zero ContractAddress")
	}

	// Verify runtime code at deployed address.
	sdb := stateAt(t, bundle, r1.StateRoot)
	wantRuntime := mustHex("60043560005500")
	if got := sdb.GetCode(contractAddr); !bytes.Equal(got, wantRuntime) {
		t.Errorf("deployed runtime = %x, want %x", got, wantRuntime)
	}

	// Batch 2: set(42).
	setTx1 := signCall(t, bundle, 1, contractAddr, encodeStorageSetCall(42))
	r2, err := bundle.Node.ProcessBatch([]*types.Transaction{setTx1})
	if err != nil {
		t.Fatalf("set(42) ProcessBatch: %v", err)
	}
	if got := r2.Receipts[0].Status; got != 1 {
		t.Fatalf("set(42) receipt status = %d, want 1", got)
	}
	sdb = stateAt(t, bundle, r2.StateRoot)
	slot0 := sdb.GetState(contractAddr, types.Hash{})
	if got := new(big.Int).SetBytes(slot0[:]).Uint64(); got != 42 {
		t.Errorf("slot 0 after set(42) = %d, want 42", got)
	}

	// Batch 3: set(99).
	setTx2 := signCall(t, bundle, 2, contractAddr, encodeStorageSetCall(99))
	r3, err := bundle.Node.ProcessBatch([]*types.Transaction{setTx2})
	if err != nil {
		t.Fatalf("set(99) ProcessBatch: %v", err)
	}
	if got := r3.Receipts[0].Status; got != 1 {
		t.Fatalf("set(99) receipt status = %d, want 1", got)
	}
	sdb = stateAt(t, bundle, r3.StateRoot)
	slot0 = sdb.GetState(contractAddr, types.Hash{})
	if got := new(big.Int).SetBytes(slot0[:]).Uint64(); got != 99 {
		t.Errorf("slot 0 after set(99) = %d, want 99", got)
	}

	// Three covenant advances total.
	if got := len(bundle.Client.TxIDs()); got != 3 {
		t.Errorf("client.TxIDs len = %d, want 3", got)
	}
	if got := bundle.Node.ExecutionTip(); got != 3 {
		t.Errorf("ExecutionTip = %d, want 3", got)
	}
}

// TestHappyPath_DeployAndCallInSameBatch verifies that a contract can be
// deployed and called within the same batch. The deploy address is
// predicted via crypto.CreateAddress before the batch is submitted.
func TestHappyPath_DeployAndCallInSameBatch(t *testing.T) {
	bundle := happyPathSetup(t)

	// Predict the contract address created at nonce=0 from bundle.TxAddr.
	contractAddr := types.Address(crypto.CreateAddress(bundle.TxAddr, 0))

	deployTx := signCreate(t, bundle, 0, storageContractCreationCode)
	setTx := signCall(t, bundle, 1, contractAddr, encodeStorageSetCall(7))

	result, err := bundle.Node.ProcessBatch([]*types.Transaction{deployTx, setTx})
	if err != nil {
		t.Fatalf("ProcessBatch: %v", err)
	}

	if got := len(result.Receipts); got != 2 {
		t.Fatalf("receipts len = %d, want 2", got)
	}
	if got := result.Receipts[0].Status; got != 1 {
		t.Errorf("deploy receipt status = %d, want 1", got)
	}
	if got := result.Receipts[0].ContractAddress; got != contractAddr {
		t.Errorf("deploy ContractAddress = %s, want %s", got.Hex(), contractAddr.Hex())
	}
	if got := result.Receipts[1].Status; got != 1 {
		t.Errorf("set receipt status = %d, want 1", got)
	}

	sdb := stateAt(t, bundle, result.StateRoot)
	slot0 := sdb.GetState(contractAddr, types.Hash{})
	if got := new(big.Int).SetBytes(slot0[:]).Uint64(); got != 7 {
		t.Errorf("slot 0 after set(7) = %d, want 7", got)
	}

	// One batch, one covenant advance.
	if got := len(bundle.Client.TxIDs()); got != 1 {
		t.Errorf("client.TxIDs len = %d, want 1", got)
	}
	if got := bundle.Node.ExecutionTip(); got != 1 {
		t.Errorf("ExecutionTip = %d, want 1", got)
	}
}

// TestHappyPath_SpeculativeAdvancesToFinalized follows one transfer through
// the tip state machine:
//   - After ProcessBatch: ExecutionTip=1, ProvenTip=1, ConfirmedTip=0, FinalizedTip=0
//   - After 1 BSV block: ConfirmedTip=1 (advance tx confirmed)
//   - After 5 more BSV blocks (6 total): FinalizedTip=1
func TestHappyPath_SpeculativeAdvancesToFinalized(t *testing.T) {
	bundle := happyPathSetup(t)

	recipient := types.HexToAddress("0x00000000000000000000000000000000000000c1")
	tx := signTransfer(t, bundle, 0, recipient, uint256.NewInt(500))

	_, err := bundle.Node.ProcessBatch([]*types.Transaction{tx})
	if err != nil {
		t.Fatalf("ProcessBatch: %v", err)
	}

	// Immediately after ProcessBatch: executed + proven + broadcast, not yet confirmed.
	if got := bundle.Node.ExecutionTip(); got != 1 {
		t.Errorf("ExecutionTip pre-mine = %d, want 1", got)
	}
	if got := bundle.Node.ProvenTip(); got != 1 {
		t.Errorf("ProvenTip pre-mine = %d, want 1", got)
	}
	if got := bundle.Node.ConfirmedTip(); got != 0 {
		t.Errorf("ConfirmedTip pre-mine = %d, want 0", got)
	}
	if got := bundle.Node.FinalizedTip(); got != 0 {
		t.Errorf("FinalizedTip pre-mine = %d, want 0", got)
	}

	// Mine 1 BSV block — the advance tx confirms.
	if err := helpers.Mine(1); err != nil {
		t.Fatalf("mine +1: %v", err)
	}
	waitCond(t, 120*time.Second, "ConfirmedTip>=1", func() bool {
		return bundle.Node.ConfirmedTip() >= 1
	})
	// Still not finalized (need 6 confirmations total).
	if got := bundle.Node.FinalizedTip(); got != 0 {
		t.Errorf("FinalizedTip after 1 conf = %d, want 0", got)
	}

	// Mine 5 more BSV blocks — total 6 confirmations, advance finalizes.
	if err := helpers.Mine(5); err != nil {
		t.Fatalf("mine +5: %v", err)
	}
	waitCond(t, 120*time.Second, "FinalizedTip>=1", func() bool {
		return bundle.Node.FinalizedTip() >= 1
	})

	// Watcher drains once all advances are finalized.
	waitCond(t, 30*time.Second, "watcher drains outstanding", func() bool {
		return bundle.Node.ConfirmationWatcherRef().Outstanding() == 0
	})
}
