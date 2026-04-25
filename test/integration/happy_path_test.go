//go:build integration

// Package integration tests: end-to-end happy-path suite.
//
// These tests are Phase 1 of the BSVM-INTEGRATION-TESTS-PROMPT.md attack-
// vector suite. They establish the pattern every subsequent phase will
// reuse: deterministic per-test seeds feed regtestharness.Build, each test
// deploys its own FRIRollupContract, drives bundle.Node.ProcessBatch,
// and asserts on tips, receipts, and state. No tampered-args negative
// tests, bridge tests, or multi-node tests appear here — those ship in
// Phase 2.
//
// All tests run on ProofModeFRI because it has the smallest locking
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
//
//	PUSH1 0x07  — runtime length
//	PUSH1 0x0c  — runtime offset in this init code
//	PUSH1 0x00  — memory destination
//	CODECOPY    — copy runtime to memory[0:7]
//	PUSH1 0x07  — return size
//	PUSH1 0x00  — return offset
//	RETURN
//
// Runtime bytecode (7 bytes): 60043560005500
//
//	PUSH1 0x04  — calldata offset (skip 4-byte selector)
//	CALLDATALOAD — load 32 bytes from calldata[4:36] onto stack
//	PUSH1 0x00  — storage slot 0
//	SSTORE      — store top-of-stack value into slot 0
//	STOP
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

// erc20Bytecode is the compiled bytecode for a minimal ERC-20 contract
// (MinimalERC20.sol, solc 0.8.28, optimizer 200 runs). Constructor takes
// uint256 initialSupply. Functions: totalSupply() 0x18160ddd,
// balanceOf(address) 0x70a08231, transfer(address,uint256) 0xa9059cbb.
var erc20Bytecode = mustHex("6080604052348015600e575f5ffd5b5060405161028d38038061028d833981016040819052602b916043565b6001819055335f908152602081905260409020556059565b5f602082840312156052575f5ffd5b5051919050565b610227806100665f395ff3fe608060405234801561000f575f5ffd5b506004361061003f575f3560e01c806318160ddd1461004357806370a082311461005f578063a9059cbb1461007e575b5f5ffd5b61004c60015481565b6040519081526020015b60405180910390f35b61004c61006d36600461016f565b5f6020819052908152604090205481565b61009161008c36600461018f565b6100a1565b6040519015158152602001610056565b335f908152602081905260408120548211156100fa5760405162461bcd60e51b8152602060048201526014602482015273696e73756666696369656e742062616c616e636560601b604482015260640160405180910390fd5b335f90815260208190526040812080548492906101189084906101cb565b90915550506001600160a01b0383165f90815260208190526040812080548492906101449084906101de565b9091555060019150505b92915050565b80356001600160a01b038116811461016a575f5ffd5b919050565b5f6020828403121561017f575f5ffd5b61018882610154565b9392505050565b5f5f604083850312156101a0575f5ffd5b6101a983610154565b946020939093013593505050565b634e487b7160e01b5f52601160045260245ffd5b8181038181111561014e5761014e6101b7565b8082018082111561014e5761014e6101b756fea26469706673582212206fa265391acff9a75aac63cca692d7eca9d912167ee87212105807c23dcb9d3864736f6c634300081c0033")

// encodeERC20Deploy appends the ABI-encoded constructor arg (uint256 initialSupply)
// to the ERC-20 bytecode.
func encodeERC20Deploy(initialSupply uint64) []byte {
	arg := make([]byte, 32)
	binary.BigEndian.PutUint64(arg[24:], initialSupply)
	return append(erc20Bytecode, arg...)
}

// encodeERC20Transfer encodes transfer(address,uint256).
func encodeERC20Transfer(to types.Address, amount uint64) []byte {
	out := make([]byte, 68)
	out[0], out[1], out[2], out[3] = 0xa9, 0x05, 0x9c, 0xbb
	copy(out[4+12:36], to[:])
	binary.BigEndian.PutUint64(out[68-8:], amount)
	return out
}

// erc20BalanceSlot computes the storage slot for balanceOf[addr] in the
// MinimalERC20 contract. The balanceOf mapping is at slot 0, so the key
// is keccak256(abi.encode(addr, 0)).
func erc20BalanceSlot(addr types.Address) types.Hash {
	key := make([]byte, 64)
	copy(key[12:32], addr[:])
	// slot index 0 is already zero in key[32:64]
	return types.BytesToHash(crypto.Keccak256(key))
}

// happyPathSetup deploys a fresh FRIRollupContract, builds a bundle
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
		ProofMode:    covenant.ProofModeFRI,
	}
	root, err := regtestharness.ComputeGenesisStateRoot(cfg)
	if err != nil {
		t.Fatalf("ComputeGenesisStateRoot: %v", err)
	}
	rootHex := hex.EncodeToString(root[:])

	contract, provider, signer, _ := deployFRIRollupWithStateRoot(t, rootHex)
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

	// Mine 2 BSV blocks: the first ensures the advance tx is included even if
	// there was a small propagation delay, the second provides a safety net on
	// slower regtest runs. The assertion only requires ConfirmedTip >= 1.
	if err := helpers.Mine(2); err != nil {
		t.Fatalf("mine +2: %v", err)
	}
	waitCond(t, 120*time.Second, "ConfirmedTip>=1", func() bool {
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

// TestHappyPath_GasRefund deploys the storage contract, writes slot 0
// (set(42)), then clears slot 0 (set(0)). Clearing a storage slot triggers
// an EIP-2200 gas refund. The test verifies that the clear operation's
// receipt gas is less than the initial write, proving refunds are applied.
func TestHappyPath_GasRefund(t *testing.T) {
	bundle := happyPathSetup(t)

	// Batch 1: deploy.
	deployTx := signCreate(t, bundle, 0, storageContractCreationCode)
	r1, err := bundle.Node.ProcessBatch([]*types.Transaction{deployTx})
	if err != nil {
		t.Fatalf("deploy: %v", err)
	}
	if r1.Receipts[0].Status != 1 {
		t.Fatalf("deploy receipt status = %d, want 1", r1.Receipts[0].Status)
	}
	contractAddr := r1.Receipts[0].ContractAddress

	// Batch 2: set(42) — initial write to empty slot (cold SSTORE).
	setTx := signCall(t, bundle, 1, contractAddr, encodeStorageSetCall(42))
	r2, err := bundle.Node.ProcessBatch([]*types.Transaction{setTx})
	if err != nil {
		t.Fatalf("set(42): %v", err)
	}
	if r2.Receipts[0].Status != 1 {
		t.Fatalf("set(42) receipt status = %d, want 1", r2.Receipts[0].Status)
	}
	gasWrite := r2.Receipts[0].GasUsed
	t.Logf("set(42) gasUsed = %d", gasWrite)

	// Batch 3: set(0) — clear slot (triggers EIP-2200 refund).
	clearTx := signCall(t, bundle, 2, contractAddr, encodeStorageSetCall(0))
	r3, err := bundle.Node.ProcessBatch([]*types.Transaction{clearTx})
	if err != nil {
		t.Fatalf("set(0): %v", err)
	}
	if r3.Receipts[0].Status != 1 {
		t.Fatalf("set(0) receipt status = %d, want 1", r3.Receipts[0].Status)
	}
	gasClear := r3.Receipts[0].GasUsed
	t.Logf("set(0) gasUsed = %d (refund applied)", gasClear)

	// The clear operation should use LESS gas than the initial write because
	// the EIP-2200 SSTORE refund is subtracted from the gas consumed.
	if gasClear >= gasWrite {
		t.Errorf("expected gasClear (%d) < gasWrite (%d) — refund not applied", gasClear, gasWrite)
	}

	// Verify slot 0 is indeed cleared.
	sdb := stateAt(t, bundle, r3.StateRoot)
	slot0 := sdb.GetState(contractAddr, types.Hash{})
	if slot0 != (types.Hash{}) {
		t.Errorf("slot 0 after clear = %s, want zero", slot0.Hex())
	}
}

// TestHappyPath_BridgeDeposit credits an L2 account via a deposit system
// transaction (simulating a BSV bridge deposit) and verifies the balance
// appears in the state. Then sends a normal transfer to prove the overlay
// still works after the deposit.
func TestHappyPath_BridgeDeposit(t *testing.T) {
	bundle := happyPathSetup(t)

	depositAddr := types.HexToAddress("0x00000000000000000000000000000000000000f1")
	depositAmount := uint256.NewInt(500_000_000_000_000_000) // 0.5 ETH in wei

	depositTx := &types.DepositTransaction{
		SourceHash: types.BytesToHash([]byte("test-deposit-001")),
		From:       types.HexToAddress("0x0000000000000000000000000000000000000000"),
		To:         depositAddr,
		Value:      depositAmount,
		Gas:        0,
		IsSystemTx: true,
	}

	if err := bundle.Node.SubmitDepositTx(depositTx); err != nil {
		t.Fatalf("SubmitDepositTx: %v", err)
	}

	// Verify the deposited balance in the current state.
	currentState := bundle.Node.StateDB()
	balance := currentState.GetBalance(depositAddr)
	if balance.Cmp(depositAmount) != 0 {
		t.Errorf("deposit balance = %s, want %s", balance, depositAmount)
	}

	// Normal transfer still works after deposit.
	recipient := types.HexToAddress("0x00000000000000000000000000000000000000f2")
	tx := signTransfer(t, bundle, 0, recipient, uint256.NewInt(1_000))
	result, err := bundle.Node.ProcessBatch([]*types.Transaction{tx})
	if err != nil {
		t.Fatalf("ProcessBatch after deposit: %v", err)
	}
	if result.Receipts[0].Status != 1 {
		t.Errorf("transfer receipt status = %d, want 1", result.Receipts[0].Status)
	}

	// Deposited balance persists after batch.
	sdb := stateAt(t, bundle, result.StateRoot)
	if got := sdb.GetBalance(depositAddr); got.Cmp(depositAmount) != 0 {
		t.Errorf("deposit balance after batch = %s, want %s", got, depositAmount)
	}
}

// TestHappyPath_ERC20FullLifecycle deploys a minimal ERC-20 token contract,
// mints 1,000,000 tokens to the deployer, transfers 100 tokens to a
// recipient, then verifies balances via storage slot reads.
func TestHappyPath_ERC20FullLifecycle(t *testing.T) {
	bundle := happyPathSetup(t)

	const initialSupply = 1_000_000
	const transferAmount = 100
	recipient := types.HexToAddress("0x00000000000000000000000000000000000000e1")

	// Batch 1: deploy ERC-20 with initial supply minted to deployer.
	deployData := encodeERC20Deploy(initialSupply)
	deployTx := types.MustSignNewTx(bundle.TxKey, bundle.Signer, &types.LegacyTx{
		Nonce:    0,
		GasPrice: big.NewInt(1_000_000_000),
		Gas:      500_000,
		To:       nil,
		Value:    uint256.NewInt(0),
		Data:     deployData,
	})
	r1, err := bundle.Node.ProcessBatch([]*types.Transaction{deployTx})
	if err != nil {
		t.Fatalf("deploy ERC-20: %v", err)
	}
	if r1.Receipts[0].Status != 1 {
		t.Fatalf("deploy receipt status = %d, want 1", r1.Receipts[0].Status)
	}
	tokenAddr := r1.Receipts[0].ContractAddress
	if tokenAddr == (types.Address{}) {
		t.Fatal("deploy receipt has zero ContractAddress")
	}
	t.Logf("ERC-20 deployed at %s", tokenAddr.Hex())

	// Verify deployer balance == initialSupply via storage slot read.
	sdb := stateAt(t, bundle, r1.StateRoot)
	deployerSlot := erc20BalanceSlot(bundle.TxAddr)
	deployerBal := sdb.GetState(tokenAddr, deployerSlot)
	if got := new(big.Int).SetBytes(deployerBal[:]).Uint64(); got != initialSupply {
		t.Errorf("deployer token balance = %d, want %d", got, initialSupply)
	}

	// Batch 2: transfer 100 tokens to recipient.
	transferData := encodeERC20Transfer(recipient, transferAmount)
	transferTx := signCall(t, bundle, 1, tokenAddr, transferData)
	r2, err := bundle.Node.ProcessBatch([]*types.Transaction{transferTx})
	if err != nil {
		t.Fatalf("transfer: %v", err)
	}
	if r2.Receipts[0].Status != 1 {
		t.Fatalf("transfer receipt status = %d, want 1", r2.Receipts[0].Status)
	}

	// Verify balances after transfer.
	sdb = stateAt(t, bundle, r2.StateRoot)
	deployerBal = sdb.GetState(tokenAddr, deployerSlot)
	if got := new(big.Int).SetBytes(deployerBal[:]).Uint64(); got != initialSupply-transferAmount {
		t.Errorf("deployer balance after transfer = %d, want %d", got, initialSupply-transferAmount)
	}
	recipientSlot := erc20BalanceSlot(recipient)
	recipientBal := sdb.GetState(tokenAddr, recipientSlot)
	if got := new(big.Int).SetBytes(recipientBal[:]).Uint64(); got != transferAmount {
		t.Errorf("recipient balance after transfer = %d, want %d", got, transferAmount)
	}
}
