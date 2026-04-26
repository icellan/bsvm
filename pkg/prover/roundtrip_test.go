package prover

import (
	"bytes"
	"context"
	"math/big"
	"testing"

	"github.com/holiman/uint256"
	"github.com/icellan/bsvm/internal/db"
	"github.com/icellan/bsvm/pkg/block"
	"github.com/icellan/bsvm/pkg/crypto"
	"github.com/icellan/bsvm/pkg/mpt"
	"github.com/icellan/bsvm/pkg/state"
	"github.com/icellan/bsvm/pkg/types"
	"github.com/icellan/bsvm/pkg/vm"
)

const roundtripChainID = 1337

// testChainContext implements block.ChainContext for testing.
type testChainContext struct{}

// GetHeader returns nil; tests do not look up ancestor headers.
func (tc *testChainContext) GetHeader(_ types.Hash, _ uint64) *block.L2Header {
	return nil
}

// encodeTx RLP-encodes a transaction into bytes suitable for ProveInput.
func encodeTx(t *testing.T, tx *types.Transaction) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := tx.EncodeRLP(&buf); err != nil {
		t.Fatalf("failed to RLP-encode transaction: %v", err)
	}
	return buf.Bytes()
}

// TestRoundTripMockSimpleTransfer tests the complete Milestone 3 pipeline
// with a single ETH transfer using mock proving:
//  1. Create genesis state with a funded account
//  2. Create a signed transfer transaction
//  3. Execute the transaction with Go EVM (pkg/block)
//  4. Record accessed state with StartAccessRecording/StopAccessRecording
//  5. Export state with Merkle proofs (ExportStateForProving)
//  6. Build ProveInput from the state export + transaction
//  7. Call SP1Prover.Prove() in mock mode
//  8. Parse the PublicValues from the proof output
//  9. Verify all 10 PublicValues fields
func TestRoundTripMockSimpleTransfer(t *testing.T) {
	database := db.NewMemoryDB()
	chainConfig := vm.DefaultL2Config(roundtripChainID)

	// Generate a test key and derive sender address.
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	senderAddr := types.Address(crypto.PubkeyToAddress(key.PublicKey))
	recipientAddr := types.HexToAddress("0x1234567890abcdef1234567890abcdef12345678")
	coinbaseAddr := types.HexToAddress("0xcccccccccccccccccccccccccccccccccccccccc")

	// Step 1: Create genesis with a funded account (1000 ETH).
	genesis := block.DefaultGenesis(roundtripChainID)
	balance, _ := uint256.FromBig(new(big.Int).Mul(big.NewInt(1000), new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil)))
	genesis.Alloc = map[types.Address]block.GenesisAccount{
		senderAddr: {Balance: balance},
	}

	genesisHeader, err := block.InitGenesis(database, genesis)
	if err != nil {
		t.Fatalf("InitGenesis failed: %v", err)
	}

	// Record the pre-state root before execution.
	preStateRoot := genesisHeader.StateRoot

	// Open a pre-state database (at genesis root) for state export later.
	preStateDB, err := state.New(preStateRoot, database)
	if err != nil {
		t.Fatalf("failed to open pre-state: %v", err)
	}

	// Step 2: Create a signed transfer transaction (1 ETH).
	signer := types.NewLondonSigner(big.NewInt(roundtripChainID))
	tx, err := types.SignNewTx(key, signer, &types.DynamicFeeTx{
		ChainID:   big.NewInt(roundtripChainID),
		Nonce:     0,
		GasTipCap: big.NewInt(1),
		GasFeeCap: big.NewInt(1),
		Gas:       21000,
		To:        &recipientAddr,
		Value:     uint256.NewInt(1_000_000_000_000_000_000), // 1 ETH
	})
	if err != nil {
		t.Fatalf("failed to sign tx: %v", err)
	}

	// Step 3: Execute the transaction with Go EVM.
	// Open a new state for execution with access recording.
	execStateDB, err := state.New(preStateRoot, database)
	if err != nil {
		t.Fatalf("failed to open exec state: %v", err)
	}

	// Step 4: Start access recording before execution.
	execStateDB.StartAccessRecording()

	executor := block.NewBlockExecutor(chainConfig, vm.Config{})
	chainCtx := &testChainContext{}

	l2Block, receipts, err := executor.ProcessBatch(
		genesisHeader,
		coinbaseAddr,
		1000,
		[]*types.Transaction{tx},
		execStateDB,
		chainCtx,
	)
	if err != nil {
		t.Fatalf("ProcessBatch failed: %v", err)
	}

	if len(receipts) != 1 {
		t.Fatalf("expected 1 receipt, got %d", len(receipts))
	}
	if receipts[0].Status != types.ReceiptStatusSuccessful {
		t.Fatalf("expected successful receipt, got status %d", receipts[0].Status)
	}
	if receipts[0].GasUsed != 21000 {
		t.Fatalf("expected 21000 gas used, got %d", receipts[0].GasUsed)
	}

	// Record the Go EVM's computed post-state root.
	postStateRoot := l2Block.StateRoot()
	gasUsed := l2Block.GasUsed()

	// Compute the receipts hash (receipts trie root).
	receiptsHash := mpt.DeriveSha(types.Receipts(receipts))

	// Step 4 (cont): Stop access recording.
	recording := execStateDB.StopAccessRecording()

	// Step 5: Export pre-state with Merkle proofs for the accessed accounts.
	export, err := ExportStateForProving(preStateDB, recording.Accounts, recording.Slots)
	if err != nil {
		t.Fatalf("ExportStateForProving failed: %v", err)
	}

	stateExportJSON, err := SerializeExport(export)
	if err != nil {
		t.Fatalf("SerializeExport failed: %v", err)
	}

	// Verify the pre-state root in the export matches genesis.
	if export.PreStateRoot != preStateRoot {
		t.Fatalf("export pre-state root mismatch: got %s, want %s",
			export.PreStateRoot.Hex(), preStateRoot.Hex())
	}

	// Step 6: Build ProveInput.
	proveInput := &ProveInput{
		PreStateRoot: preStateRoot,
		StateExport:  stateExportJSON,
		Transactions: [][]byte{encodeTx(t, tx)},
		BlockContext: BlockContext{
			Number:    l2Block.NumberU64(),
			Timestamp: l2Block.Time(),
			Coinbase:  coinbaseAddr,
			GasLimit:  l2Block.GasLimit(),
			BaseFee:   0,
		},
		ExpectedResults: &ExpectedResults{
			PostStateRoot: postStateRoot,
			ReceiptsHash:  receiptsHash,
			GasUsed:       gasUsed,
			ChainID:       roundtripChainID,
		},
	}

	// Step 7: Prove with mock prover.
	prover := NewSP1Prover(Config{
		Mode:         ProverMock,
		SP1ProofMode: "compressed",
	})

	output, err := prover.Prove(context.Background(), proveInput)
	if err != nil {
		t.Fatalf("Prove (mock) failed: %v", err)
	}

	// Step 8: Parse the PublicValues.
	pv, err := ParsePublicValues(output.PublicValues)
	if err != nil {
		t.Fatalf("ParsePublicValues failed: %v", err)
	}

	// Step 9-12: Verify ALL 10 PublicValues fields.

	// 9. PreStateRoot matches genesis state root.
	if pv.PreStateRoot != preStateRoot {
		t.Errorf("PreStateRoot mismatch: got %s, want %s",
			pv.PreStateRoot.Hex(), preStateRoot.Hex())
	}

	// 10. PostStateRoot matches the Go EVM's computed post-state root.
	if pv.PostStateRoot != postStateRoot {
		t.Errorf("PostStateRoot mismatch: got %s, want %s",
			pv.PostStateRoot.Hex(), postStateRoot.Hex())
	}

	// Verify the post-state root actually changed from pre-state.
	if pv.PostStateRoot == pv.PreStateRoot {
		t.Error("PostStateRoot should differ from PreStateRoot after a transfer")
	}

	// ReceiptsHash matches the computed receipts trie root.
	if pv.ReceiptsHash != receiptsHash {
		t.Errorf("ReceiptsHash mismatch: got %s, want %s",
			pv.ReceiptsHash.Hex(), receiptsHash.Hex())
	}

	// 11. GasUsed matches the Go EVM's gas used.
	if pv.GasUsed != gasUsed {
		t.Errorf("GasUsed mismatch: got %d, want %d", pv.GasUsed, gasUsed)
	}
	if pv.GasUsed != 21000 {
		t.Errorf("GasUsed should be 21000 for simple transfer, got %d", pv.GasUsed)
	}

	// BatchDataHash is derived from the encoded transactions.
	expectedBatchHash := hashTransactions(proveInput.Transactions)
	if pv.BatchDataHash != expectedBatchHash {
		t.Errorf("BatchDataHash mismatch: got %s, want %s",
			pv.BatchDataHash.Hex(), expectedBatchHash.Hex())
	}
	if pv.BatchDataHash == (types.Hash{}) {
		t.Error("BatchDataHash should not be zero for non-empty transactions")
	}

	// 12. ChainID matches the configured chain ID.
	if pv.ChainID != roundtripChainID {
		t.Errorf("ChainID mismatch: got %d, want %d", pv.ChainID, roundtripChainID)
	}

	// WithdrawalRoot, InboxRootBefore, InboxRootAfter, MigrateScriptHash
	// are all zero in this simple test (no withdrawals or migrations).
	if pv.WithdrawalRoot != (types.Hash{}) {
		t.Errorf("WithdrawalRoot should be zero, got %s", pv.WithdrawalRoot.Hex())
	}
	if pv.InboxRootBefore != (types.Hash{}) {
		t.Errorf("InboxRootBefore should be zero, got %s", pv.InboxRootBefore.Hex())
	}
	if pv.InboxRootAfter != (types.Hash{}) {
		t.Errorf("InboxRootAfter should be zero, got %s", pv.InboxRootAfter.Hex())
	}
	if pv.MigrateScriptHash != (types.Hash{}) {
		t.Errorf("MigrateScriptHash should be zero, got %s", pv.MigrateScriptHash.Hex())
	}

	// Verify proof structure.
	if len(output.Proof) == 0 {
		t.Error("proof data should not be empty")
	}
	if output.VKHash == (types.Hash{}) {
		t.Error("VKHash should not be zero")
	}
	if len(output.PublicValues) != PublicValuesSize {
		t.Errorf("PublicValues size = %d, want %d", len(output.PublicValues), PublicValuesSize)
	}
}

// TestRoundTripMockContractDeployment tests the pipeline with a contract
// creation transaction.
func TestRoundTripMockContractDeployment(t *testing.T) {
	database := db.NewMemoryDB()
	chainConfig := vm.DefaultL2Config(roundtripChainID)

	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	senderAddr := types.Address(crypto.PubkeyToAddress(key.PublicKey))
	coinbaseAddr := types.HexToAddress("0xcccccccccccccccccccccccccccccccccccccccc")

	// Create genesis with a funded account.
	genesis := block.DefaultGenesis(roundtripChainID)
	balance, _ := uint256.FromBig(new(big.Int).Mul(big.NewInt(1000), new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil)))
	genesis.Alloc = map[types.Address]block.GenesisAccount{
		senderAddr: {Balance: balance},
	}

	genesisHeader, err := block.InitGenesis(database, genesis)
	if err != nil {
		t.Fatalf("InitGenesis failed: %v", err)
	}

	preStateRoot := genesisHeader.StateRoot

	// Open pre-state for export.
	preStateDB, err := state.New(preStateRoot, database)
	if err != nil {
		t.Fatalf("failed to open pre-state: %v", err)
	}

	// Simple contract: PUSH1 0x42 PUSH1 0x00 MSTORE PUSH1 0x20 PUSH1 0x00 RETURN
	// This stores 0x42 at memory[0] and returns 32 bytes of runtime code.
	contractCode := []byte{
		0x60, 0x42, // PUSH1 0x42
		0x60, 0x00, // PUSH1 0x00
		0x52,       // MSTORE
		0x60, 0x20, // PUSH1 0x20
		0x60, 0x00, // PUSH1 0x00
		0xf3, // RETURN
	}

	signer := types.NewLondonSigner(big.NewInt(roundtripChainID))
	tx, err := types.SignNewTx(key, signer, &types.DynamicFeeTx{
		ChainID:   big.NewInt(roundtripChainID),
		Nonce:     0,
		GasTipCap: big.NewInt(1),
		GasFeeCap: big.NewInt(1),
		Gas:       100000, // enough gas for contract creation
		To:        nil,    // nil To => contract creation
		Value:     uint256.NewInt(0),
		Data:      contractCode,
	})
	if err != nil {
		t.Fatalf("failed to sign tx: %v", err)
	}

	// Execute with access recording.
	execStateDB, err := state.New(preStateRoot, database)
	if err != nil {
		t.Fatalf("failed to open exec state: %v", err)
	}
	execStateDB.StartAccessRecording()

	executor := block.NewBlockExecutor(chainConfig, vm.Config{})
	chainCtx := &testChainContext{}

	l2Block, receipts, err := executor.ProcessBatch(
		genesisHeader, coinbaseAddr, 1000,
		[]*types.Transaction{tx}, execStateDB, chainCtx,
	)
	if err != nil {
		t.Fatalf("ProcessBatch failed: %v", err)
	}

	if len(receipts) != 1 {
		t.Fatalf("expected 1 receipt, got %d", len(receipts))
	}
	if receipts[0].Status != types.ReceiptStatusSuccessful {
		t.Fatalf("contract creation failed, status %d", receipts[0].Status)
	}

	// Verify contract was deployed.
	contractAddr := receipts[0].ContractAddress
	if contractAddr == (types.Address{}) {
		t.Fatal("contract address should be non-zero")
	}

	postStateRoot := l2Block.StateRoot()
	gasUsed := l2Block.GasUsed()
	receiptsHash := mpt.DeriveSha(types.Receipts(receipts))

	recording := execStateDB.StopAccessRecording()

	// Export pre-state.
	export, err := ExportStateForProving(preStateDB, recording.Accounts, recording.Slots)
	if err != nil {
		t.Fatalf("ExportStateForProving failed: %v", err)
	}

	stateExportJSON, err := SerializeExport(export)
	if err != nil {
		t.Fatalf("SerializeExport failed: %v", err)
	}

	// Build ProveInput and prove.
	proveInput := &ProveInput{
		PreStateRoot: preStateRoot,
		StateExport:  stateExportJSON,
		Transactions: [][]byte{encodeTx(t, tx)},
		BlockContext: BlockContext{
			Number:    l2Block.NumberU64(),
			Timestamp: l2Block.Time(),
			Coinbase:  coinbaseAddr,
			GasLimit:  l2Block.GasLimit(),
			BaseFee:   0,
		},
		ExpectedResults: &ExpectedResults{
			PostStateRoot: postStateRoot,
			ReceiptsHash:  receiptsHash,
			GasUsed:       gasUsed,
			ChainID:       roundtripChainID,
		},
	}

	prover := NewSP1Prover(Config{Mode: ProverMock})
	output, err := prover.Prove(context.Background(), proveInput)
	if err != nil {
		t.Fatalf("Prove (mock) failed: %v", err)
	}

	pv, err := ParsePublicValues(output.PublicValues)
	if err != nil {
		t.Fatalf("ParsePublicValues failed: %v", err)
	}

	// Verify public values.
	if pv.PreStateRoot != preStateRoot {
		t.Errorf("PreStateRoot mismatch")
	}
	if pv.PostStateRoot != postStateRoot {
		t.Errorf("PostStateRoot mismatch: got %s, want %s",
			pv.PostStateRoot.Hex(), postStateRoot.Hex())
	}
	if pv.PostStateRoot == pv.PreStateRoot {
		t.Error("PostStateRoot should differ from PreStateRoot after contract deploy")
	}
	if pv.ReceiptsHash != receiptsHash {
		t.Errorf("ReceiptsHash mismatch")
	}
	if pv.GasUsed != gasUsed {
		t.Errorf("GasUsed mismatch: got %d, want %d", pv.GasUsed, gasUsed)
	}
	if pv.GasUsed <= 21000 {
		t.Errorf("contract deployment should use more than 21000 gas, got %d", pv.GasUsed)
	}
	if pv.ChainID != roundtripChainID {
		t.Errorf("ChainID mismatch: got %d, want %d", pv.ChainID, roundtripChainID)
	}

	expectedBatchHash := hashTransactions(proveInput.Transactions)
	if pv.BatchDataHash != expectedBatchHash {
		t.Errorf("BatchDataHash mismatch")
	}
}

// TestRoundTripMockBatchMultipleTransfers tests the pipeline with a batch
// of three transfers executed together.
func TestRoundTripMockBatchMultipleTransfers(t *testing.T) {
	database := db.NewMemoryDB()
	chainConfig := vm.DefaultL2Config(roundtripChainID)

	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	senderAddr := types.Address(crypto.PubkeyToAddress(key.PublicKey))
	coinbaseAddr := types.HexToAddress("0xcccccccccccccccccccccccccccccccccccccccc")

	recipient1 := types.HexToAddress("0x1111111111111111111111111111111111111111")
	recipient2 := types.HexToAddress("0x2222222222222222222222222222222222222222")
	recipient3 := types.HexToAddress("0x3333333333333333333333333333333333333333")

	// Create genesis.
	genesis := block.DefaultGenesis(roundtripChainID)
	balance, _ := uint256.FromBig(new(big.Int).Mul(big.NewInt(1000), new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil)))
	genesis.Alloc = map[types.Address]block.GenesisAccount{
		senderAddr: {Balance: balance},
	}

	genesisHeader, err := block.InitGenesis(database, genesis)
	if err != nil {
		t.Fatalf("InitGenesis failed: %v", err)
	}

	preStateRoot := genesisHeader.StateRoot

	preStateDB, err := state.New(preStateRoot, database)
	if err != nil {
		t.Fatalf("failed to open pre-state: %v", err)
	}

	// Create three transfer transactions.
	signer := types.NewLondonSigner(big.NewInt(roundtripChainID))

	tx1, err := types.SignNewTx(key, signer, &types.DynamicFeeTx{
		ChainID:   big.NewInt(roundtripChainID),
		Nonce:     0,
		GasTipCap: big.NewInt(1),
		GasFeeCap: big.NewInt(1),
		Gas:       21000,
		To:        &recipient1,
		Value:     uint256.NewInt(100),
	})
	if err != nil {
		t.Fatalf("failed to sign tx1: %v", err)
	}

	tx2, err := types.SignNewTx(key, signer, &types.DynamicFeeTx{
		ChainID:   big.NewInt(roundtripChainID),
		Nonce:     1,
		GasTipCap: big.NewInt(1),
		GasFeeCap: big.NewInt(1),
		Gas:       21000,
		To:        &recipient2,
		Value:     uint256.NewInt(200),
	})
	if err != nil {
		t.Fatalf("failed to sign tx2: %v", err)
	}

	tx3, err := types.SignNewTx(key, signer, &types.DynamicFeeTx{
		ChainID:   big.NewInt(roundtripChainID),
		Nonce:     2,
		GasTipCap: big.NewInt(1),
		GasFeeCap: big.NewInt(1),
		Gas:       21000,
		To:        &recipient3,
		Value:     uint256.NewInt(300),
	})
	if err != nil {
		t.Fatalf("failed to sign tx3: %v", err)
	}

	txs := []*types.Transaction{tx1, tx2, tx3}

	// Execute with access recording.
	execStateDB, err := state.New(preStateRoot, database)
	if err != nil {
		t.Fatalf("failed to open exec state: %v", err)
	}
	execStateDB.StartAccessRecording()

	executor := block.NewBlockExecutor(chainConfig, vm.Config{})
	chainCtx := &testChainContext{}

	l2Block, receipts, err := executor.ProcessBatch(
		genesisHeader, coinbaseAddr, 1000, txs, execStateDB, chainCtx,
	)
	if err != nil {
		t.Fatalf("ProcessBatch failed: %v", err)
	}

	if len(receipts) != 3 {
		t.Fatalf("expected 3 receipts, got %d", len(receipts))
	}
	for i, r := range receipts {
		if r.Status != types.ReceiptStatusSuccessful {
			t.Fatalf("receipt %d not successful, status %d", i, r.Status)
		}
	}

	postStateRoot := l2Block.StateRoot()
	gasUsed := l2Block.GasUsed()
	receiptsHash := mpt.DeriveSha(types.Receipts(receipts))

	// Verify expected gas usage: 3 transfers * 21000 = 63000.
	if gasUsed != 63000 {
		t.Fatalf("expected 63000 gas used for 3 transfers, got %d", gasUsed)
	}

	recording := execStateDB.StopAccessRecording()

	// Export pre-state.
	export, err := ExportStateForProving(preStateDB, recording.Accounts, recording.Slots)
	if err != nil {
		t.Fatalf("ExportStateForProving failed: %v", err)
	}

	stateExportJSON, err := SerializeExport(export)
	if err != nil {
		t.Fatalf("SerializeExport failed: %v", err)
	}

	// Encode all transactions.
	encodedTxs := make([][]byte, len(txs))
	for i, tx := range txs {
		encodedTxs[i] = encodeTx(t, tx)
	}

	// Build ProveInput and prove.
	proveInput := &ProveInput{
		PreStateRoot: preStateRoot,
		StateExport:  stateExportJSON,
		Transactions: encodedTxs,
		BlockContext: BlockContext{
			Number:    l2Block.NumberU64(),
			Timestamp: l2Block.Time(),
			Coinbase:  coinbaseAddr,
			GasLimit:  l2Block.GasLimit(),
			BaseFee:   0,
		},
		ExpectedResults: &ExpectedResults{
			PostStateRoot: postStateRoot,
			ReceiptsHash:  receiptsHash,
			GasUsed:       gasUsed,
			ChainID:       roundtripChainID,
		},
	}

	prover := NewSP1Prover(Config{Mode: ProverMock})
	output, err := prover.Prove(context.Background(), proveInput)
	if err != nil {
		t.Fatalf("Prove (mock) failed: %v", err)
	}

	pv, err := ParsePublicValues(output.PublicValues)
	if err != nil {
		t.Fatalf("ParsePublicValues failed: %v", err)
	}

	// Verify all public values.
	if pv.PreStateRoot != preStateRoot {
		t.Errorf("PreStateRoot mismatch")
	}
	if pv.PostStateRoot != postStateRoot {
		t.Errorf("PostStateRoot mismatch: got %s, want %s",
			pv.PostStateRoot.Hex(), postStateRoot.Hex())
	}
	if pv.PostStateRoot == pv.PreStateRoot {
		t.Error("PostStateRoot should differ from PreStateRoot after transfers")
	}
	if pv.ReceiptsHash != receiptsHash {
		t.Errorf("ReceiptsHash mismatch")
	}
	if pv.GasUsed != 63000 {
		t.Errorf("GasUsed mismatch: got %d, want 63000", pv.GasUsed)
	}
	if pv.ChainID != roundtripChainID {
		t.Errorf("ChainID mismatch: got %d, want %d", pv.ChainID, roundtripChainID)
	}

	expectedBatchHash := hashTransactions(encodedTxs)
	if pv.BatchDataHash != expectedBatchHash {
		t.Errorf("BatchDataHash mismatch")
	}
	if pv.BatchDataHash == (types.Hash{}) {
		t.Error("BatchDataHash should not be zero for non-empty batch")
	}

	if pv.WithdrawalRoot != (types.Hash{}) {
		t.Errorf("WithdrawalRoot should be zero")
	}
	if pv.InboxRootBefore != (types.Hash{}) {
		t.Errorf("InboxRootBefore should be zero")
	}
	if pv.InboxRootAfter != (types.Hash{}) {
		t.Errorf("InboxRootAfter should be zero")
	}
	if pv.MigrateScriptHash != (types.Hash{}) {
		t.Errorf("MigrateScriptHash should be zero")
	}

	// Verify recipient balances via the execution state.
	r1Bal := execStateDB.GetBalance(recipient1)
	if r1Bal.Uint64() != 100 {
		t.Errorf("recipient1 balance: got %d, want 100", r1Bal.Uint64())
	}
	r2Bal := execStateDB.GetBalance(recipient2)
	if r2Bal.Uint64() != 200 {
		t.Errorf("recipient2 balance: got %d, want 200", r2Bal.Uint64())
	}
	r3Bal := execStateDB.GetBalance(recipient3)
	if r3Bal.Uint64() != 300 {
		t.Errorf("recipient3 balance: got %d, want 300", r3Bal.Uint64())
	}
}

// TestRoundTripMockTransferWithWithdrawals exercises the production-guest
// happy path the way the overlay node will: a single EOA→EOA transfer plus
// two L2→BSV withdrawals carried alongside in ProveInput. The mock prover
// stands in for SP1 so this runs in milliseconds, but the public-values
// blob is byte-identical to what the real guest would emit at every offset
// the covenant inspects:
//   - [0..32)    PreStateRoot  ← genesis StateRoot
//   - [32..64)   PostStateRoot ← Go EVM IntermediateRoot after the batch
//   - [64..96)   ReceiptsHash  ← MPT receipts trie root
//   - [96..104)  GasUsed       ← 21000 for one transfer
//   - [104..136) BatchDataHash ← hash256(tx-encoded-bytes)
//   - [136..144) ChainID       ← 1337
//   - [144..176) WithdrawalRoot ← bridge-side Merkle root over the two
//                                  fixture withdrawals (NOT zero)
//   - [272..280) BlockNumber   ← l2Block.NumberU64()
//
// This is the canonical 280-byte spec-12 layout (PublicValuesSize). The
// covenant binds postStateRoot at [32..64) and BlockNumber at [272..280)
// to advance the chain, so this test is the contract between the
// production guest and the rest of the system.
func TestRoundTripMockTransferWithWithdrawals(t *testing.T) {
	database := db.NewMemoryDB()
	chainConfig := vm.DefaultL2Config(roundtripChainID)

	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	senderAddr := types.Address(crypto.PubkeyToAddress(key.PublicKey))
	recipientAddr := types.HexToAddress("0xfeedfacefeedfacefeedfacefeedfacefeedface")
	coinbaseAddr := types.HexToAddress("0xcccccccccccccccccccccccccccccccccccccccc")

	// Genesis: fund the sender with 1000 ETH.
	genesis := block.DefaultGenesis(roundtripChainID)
	balance, _ := uint256.FromBig(new(big.Int).Mul(big.NewInt(1000), new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil)))
	genesis.Alloc = map[types.Address]block.GenesisAccount{
		senderAddr: {Balance: balance},
	}

	genesisHeader, err := block.InitGenesis(database, genesis)
	if err != nil {
		t.Fatalf("InitGenesis failed: %v", err)
	}
	preStateRoot := genesisHeader.StateRoot

	preStateDB, err := state.New(preStateRoot, database)
	if err != nil {
		t.Fatalf("failed to open pre-state: %v", err)
	}

	// Build a 1-ETH transfer.
	signer := types.NewLondonSigner(big.NewInt(roundtripChainID))
	tx, err := types.SignNewTx(key, signer, &types.DynamicFeeTx{
		ChainID:   big.NewInt(roundtripChainID),
		Nonce:     0,
		GasTipCap: big.NewInt(1),
		GasFeeCap: big.NewInt(1),
		Gas:       21000,
		To:        &recipientAddr,
		Value:     uint256.NewInt(1_000_000_000_000_000_000),
	})
	if err != nil {
		t.Fatalf("failed to sign tx: %v", err)
	}

	// Run the Go EVM with access recording so we can build a state export.
	execStateDB, err := state.New(preStateRoot, database)
	if err != nil {
		t.Fatalf("failed to open exec state: %v", err)
	}
	execStateDB.StartAccessRecording()

	executor := block.NewBlockExecutor(chainConfig, vm.Config{})
	chainCtx := &testChainContext{}

	l2Block, receipts, err := executor.ProcessBatch(
		genesisHeader, coinbaseAddr, 1000,
		[]*types.Transaction{tx}, execStateDB, chainCtx,
	)
	if err != nil {
		t.Fatalf("ProcessBatch failed: %v", err)
	}
	if len(receipts) != 1 || receipts[0].Status != types.ReceiptStatusSuccessful {
		t.Fatalf("unexpected receipt: %+v", receipts)
	}
	if receipts[0].GasUsed != 21000 {
		t.Fatalf("expected 21000 gas, got %d", receipts[0].GasUsed)
	}

	postStateRoot := l2Block.StateRoot()
	gasUsed := l2Block.GasUsed()
	receiptsHash := mpt.DeriveSha(types.Receipts(receipts))
	recording := execStateDB.StopAccessRecording()

	// Sanity: post-state must differ from pre-state for a non-trivial transfer.
	if postStateRoot == preStateRoot {
		t.Fatalf("postStateRoot == preStateRoot — Go EVM did not move state")
	}

	// Two L2 → BSV withdrawals. The bridge covenant verifies inclusion via
	// pkg/bridge.BuildWithdrawalMerkleTree, so the prover-side root MUST
	// match that algorithm bit-for-bit (see pkg/prover/withdrawal_root.go
	// and prover/guest/src/main.rs::build_withdrawal_merkle_root).
	withdrawals := []Withdrawal{
		{Recipient: types.HexToAddress("0x1111222233334444555566667777888899990000"), AmountSatoshis: 50_000, Nonce: 1},
		{Recipient: types.HexToAddress("0xffffeeeeddddccccbbbbaaaa999988887777aaaa"), AmountSatoshis: 175_000, Nonce: 2},
	}

	export, err := ExportStateForProving(preStateDB, recording.Accounts, recording.Slots)
	if err != nil {
		t.Fatalf("ExportStateForProving failed: %v", err)
	}
	stateExportJSON, err := SerializeExport(export)
	if err != nil {
		t.Fatalf("SerializeExport failed: %v", err)
	}

	proveInput := &ProveInput{
		PreStateRoot: preStateRoot,
		StateExport:  stateExportJSON,
		Transactions: [][]byte{encodeTx(t, tx)},
		BlockContext: BlockContext{
			Number:    l2Block.NumberU64(),
			Timestamp: l2Block.Time(),
			Coinbase:  coinbaseAddr,
			GasLimit:  l2Block.GasLimit(),
			BaseFee:   0,
		},
		Withdrawals: withdrawals,
		ExpectedResults: &ExpectedResults{
			PostStateRoot: postStateRoot,
			ReceiptsHash:  receiptsHash,
			GasUsed:       gasUsed,
			ChainID:       roundtripChainID,
		},
	}

	prover := NewSP1Prover(Config{Mode: ProverMock})
	output, err := prover.Prove(context.Background(), proveInput)
	if err != nil {
		t.Fatalf("Prove (mock) failed: %v", err)
	}
	if got, want := len(output.PublicValues), PublicValuesSize; got != want {
		t.Fatalf("public values length: got %d, want %d", got, want)
	}

	pv, err := ParsePublicValues(output.PublicValues)
	if err != nil {
		t.Fatalf("ParsePublicValues failed: %v", err)
	}

	// --- Canonical 280-byte layout assertions -------------------------------

	if pv.PreStateRoot != preStateRoot {
		t.Errorf("[0..32)  PreStateRoot:  got %s, want %s", pv.PreStateRoot.Hex(), preStateRoot.Hex())
	}
	if pv.PostStateRoot != postStateRoot {
		t.Errorf("[32..64) PostStateRoot: got %s, want %s", pv.PostStateRoot.Hex(), postStateRoot.Hex())
	}
	if pv.ReceiptsHash != receiptsHash {
		t.Errorf("[64..96) ReceiptsHash:  got %s, want %s", pv.ReceiptsHash.Hex(), receiptsHash.Hex())
	}
	if pv.GasUsed != 21000 {
		t.Errorf("[96..104) GasUsed: got %d, want 21000", pv.GasUsed)
	}
	if pv.BatchDataHash == (types.Hash{}) {
		t.Errorf("[104..136) BatchDataHash should not be zero for non-empty batch")
	}
	if pv.ChainID != roundtripChainID {
		t.Errorf("[136..144) ChainID: got %d, want %d", pv.ChainID, roundtripChainID)
	}
	expectedWithdrawalRoot := computeWithdrawalRoot(withdrawals)
	if pv.WithdrawalRoot != expectedWithdrawalRoot {
		t.Errorf("[144..176) WithdrawalRoot: got %s, want %s",
			pv.WithdrawalRoot.Hex(), expectedWithdrawalRoot.Hex())
	}
	if pv.WithdrawalRoot == (types.Hash{}) {
		t.Errorf("[144..176) WithdrawalRoot should be non-zero with %d withdrawals", len(withdrawals))
	}
	if pv.InboxRootBefore != (types.Hash{}) {
		t.Errorf("[176..208) InboxRootBefore should be zero (no inbox), got %s", pv.InboxRootBefore.Hex())
	}
	if pv.InboxRootAfter != (types.Hash{}) {
		t.Errorf("[208..240) InboxRootAfter should be zero (no inbox), got %s", pv.InboxRootAfter.Hex())
	}
	if pv.MigrateScriptHash != (types.Hash{}) {
		t.Errorf("[240..272) MigrateScriptHash should be zero (no migration), got %s", pv.MigrateScriptHash.Hex())
	}
	if pv.BlockNumber != l2Block.NumberU64() {
		t.Errorf("[272..280) BlockNumber: got %d, want %d", pv.BlockNumber, l2Block.NumberU64())
	}

	// Belt-and-braces: explicit byte-window comparison so a future encoder
	// drift can't sneak past the parsed-struct check above.
	if got := types.BytesToHash(output.PublicValues[32:64]); got != postStateRoot {
		t.Errorf("raw PV[32..64) PostStateRoot: got %s, want %s", got.Hex(), postStateRoot.Hex())
	}
	if got := types.BytesToHash(output.PublicValues[144:176]); got != expectedWithdrawalRoot {
		t.Errorf("raw PV[144..176) WithdrawalRoot: got %s, want %s", got.Hex(), expectedWithdrawalRoot.Hex())
	}

	// Surface the canonical hashes in -v output so the round-trip evidence
	// shows up in CI logs.
	t.Logf("preStateRoot:          %s", preStateRoot.Hex())
	t.Logf("postStateRoot (Go EVM): %s", postStateRoot.Hex())
	t.Logf("postStateRoot (PV):     %s", pv.PostStateRoot.Hex())
	t.Logf("withdrawalRoot:        %s", pv.WithdrawalRoot.Hex())
	t.Logf("batchDataHash:         %s", pv.BatchDataHash.Hex())
}
