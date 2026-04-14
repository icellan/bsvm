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
