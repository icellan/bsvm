package block

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/holiman/uint256"
	"github.com/icellan/bsvm/internal/db"
	"github.com/icellan/bsvm/pkg/crypto"
	"github.com/icellan/bsvm/pkg/state"
	"github.com/icellan/bsvm/pkg/types"
	"github.com/icellan/bsvm/pkg/vm"
	"github.com/icellan/bsvm/pkg/vm/tracing"
)

// testChainID is the chain ID used in tests.
const testChainID = 1337

// testChainContext implements ChainContext for testing.
type testChainContext struct {
	headers map[uint64]*L2Header
}

func (tc *testChainContext) GetHeader(hash types.Hash, number uint64) *L2Header {
	if tc.headers == nil {
		return nil
	}
	return tc.headers[number]
}

// newTestChainConfig returns a chain config with all forks enabled.
func newTestChainConfig() *vm.ChainConfig {
	return vm.DefaultL2Config(testChainID)
}

// newTestKey returns a deterministic private key for testing.
func newTestKey() (*struct {
	Key     interface{}
	Address types.Address
}, error) {
	// Use a well-known test private key (from geth tests).
	keyBytes := make([]byte, 32)
	keyBytes[31] = 1 // private key = 1
	key, err := crypto.ToECDSA(keyBytes)
	if err != nil {
		return nil, err
	}
	addr := crypto.PubkeyToAddress(key.PublicKey)
	return &struct {
		Key     interface{}
		Address types.Address
	}{Key: key, Address: types.Address(addr)}, nil
}

// --- Header tests ---

func TestL2HeaderHashDeterministic(t *testing.T) {
	h := &L2Header{
		ParentHash: types.HexToHash("0x01"),
		Number:     big.NewInt(1),
		GasLimit:   30_000_000,
		Timestamp:  1000,
		BaseFee:    new(big.Int),
	}

	hash1 := h.Hash()
	hash2 := h.Hash()

	if hash1 != hash2 {
		t.Fatalf("header hash not deterministic: %s != %s", hash1.Hex(), hash2.Hex())
	}

	if hash1 == (types.Hash{}) {
		t.Fatal("header hash is zero")
	}
}

func TestL2HeaderHashDiffers(t *testing.T) {
	h1 := &L2Header{
		Number:    big.NewInt(1),
		GasLimit:  30_000_000,
		Timestamp: 1000,
		BaseFee:   new(big.Int),
	}
	h2 := &L2Header{
		Number:    big.NewInt(2),
		GasLimit:  30_000_000,
		Timestamp: 1000,
		BaseFee:   new(big.Int),
	}

	if h1.Hash() == h2.Hash() {
		t.Fatal("different headers produced the same hash")
	}
}

// --- ValidateHeader tests ---

func TestValidateHeaderExtraValid(t *testing.T) {
	cases := []struct {
		name  string
		extra []byte
	}{
		{"nil extra", nil},
		{"empty extra", []byte{}},
		{"1 byte", []byte{0x01}},
		{"31 bytes", make([]byte, 31)},
		{"32 bytes (max)", make([]byte, 32)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := &L2Header{
				Number:   big.NewInt(1),
				GasLimit: 30_000_000,
				Extra:    tc.extra,
			}
			if err := ValidateHeader(h); err != nil {
				t.Fatalf("expected valid header, got error: %v", err)
			}
		})
	}
}

func TestValidateHeaderExtraInvalid(t *testing.T) {
	cases := []struct {
		name string
		size int
	}{
		{"33 bytes", 33},
		{"100 bytes", 100},
		{"256 bytes", 256},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := &L2Header{
				Number:   big.NewInt(1),
				GasLimit: 30_000_000,
				Extra:    make([]byte, tc.size),
			}
			err := ValidateHeader(h)
			if err == nil {
				t.Fatalf("expected error for extra data size %d, got nil", tc.size)
			}
		})
	}
}

func TestValidateHeaderNilNumber(t *testing.T) {
	h := &L2Header{
		Number:   nil,
		GasLimit: 30_000_000,
	}
	err := ValidateHeader(h)
	if err == nil {
		t.Fatal("expected error for nil Number, got nil")
	}
}

func TestValidateHeaderGasUsedExceedsLimit(t *testing.T) {
	h := &L2Header{
		Number:   big.NewInt(1),
		GasLimit: 1_000_000,
		GasUsed:  1_000_001,
	}
	err := ValidateHeader(h)
	if err == nil {
		t.Fatal("expected error when GasUsed > GasLimit, got nil")
	}
}

func TestValidateHeaderGasUsedEqualsLimit(t *testing.T) {
	h := &L2Header{
		Number:   big.NewInt(1),
		GasLimit: 1_000_000,
		GasUsed:  1_000_000,
	}
	if err := ValidateHeader(h); err != nil {
		t.Fatalf("expected valid header when GasUsed == GasLimit, got error: %v", err)
	}
}

// --- Block tests ---

func TestNewBlockCreation(t *testing.T) {
	header := &L2Header{
		Number:   big.NewInt(5),
		GasLimit: 30_000_000,
		BaseFee:  new(big.Int),
	}

	block := NewBlock(header, nil, nil)

	if block.NumberU64() != 5 {
		t.Fatalf("expected block number 5, got %d", block.NumberU64())
	}
	if block.GasLimit() != 30_000_000 {
		t.Fatalf("expected gas limit 30_000_000, got %d", block.GasLimit())
	}
	if len(block.Transactions) != 0 {
		t.Fatalf("expected 0 transactions, got %d", len(block.Transactions))
	}
	if block.Hash() == (types.Hash{}) {
		t.Fatal("block hash is zero")
	}
}

func TestNewBlockWithHeader(t *testing.T) {
	header := &L2Header{
		Number:   big.NewInt(10),
		GasLimit: 15_000_000,
		BaseFee:  new(big.Int),
	}
	block := NewBlockWithHeader(header)

	if block.NumberU64() != 10 {
		t.Fatalf("expected block number 10, got %d", block.NumberU64())
	}
	if block.GasLimit() != 15_000_000 {
		t.Fatalf("expected gas limit 15_000_000, got %d", block.GasLimit())
	}
}

func TestBlockAccessors(t *testing.T) {
	parent := types.HexToHash("0xdead")
	coinbase := types.HexToAddress("0xbeef")
	stateRoot := types.HexToHash("0xcafe")

	header := &L2Header{
		ParentHash: parent,
		Coinbase:   coinbase,
		StateRoot:  stateRoot,
		Number:     big.NewInt(42),
		GasLimit:   20_000_000,
		GasUsed:    5_000_000,
		Timestamp:  1700000000,
		BaseFee:    big.NewInt(100),
	}

	block := NewBlockWithHeader(header)

	if block.ParentHash() != parent {
		t.Fatalf("ParentHash mismatch")
	}
	if block.Coinbase() != coinbase {
		t.Fatalf("Coinbase mismatch")
	}
	if block.StateRoot() != stateRoot {
		t.Fatalf("StateRoot mismatch")
	}
	if block.Number().Int64() != 42 {
		t.Fatalf("Number mismatch")
	}
	if block.GasLimit() != 20_000_000 {
		t.Fatalf("GasLimit mismatch")
	}
	if block.GasUsed() != 5_000_000 {
		t.Fatalf("GasUsed mismatch")
	}
	if block.Time() != 1700000000 {
		t.Fatalf("Time mismatch")
	}
	if block.BaseFee().Int64() != 100 {
		t.Fatalf("BaseFee mismatch")
	}
}

// --- GasPool tests ---

func TestGasPoolAddSub(t *testing.T) {
	gp := new(GasPool)
	gp.AddGas(100)

	if gp.Gas() != 100 {
		t.Fatalf("expected 100, got %d", gp.Gas())
	}

	err := gp.SubGas(30)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gp.Gas() != 70 {
		t.Fatalf("expected 70, got %d", gp.Gas())
	}
}

func TestGasPoolUnderflow(t *testing.T) {
	gp := new(GasPool)
	gp.AddGas(50)

	err := gp.SubGas(100)
	if err == nil {
		t.Fatal("expected error for underflow")
	}
}

func TestGasPoolSetGas(t *testing.T) {
	gp := new(GasPool)
	gp.SetGas(999)
	if gp.Gas() != 999 {
		t.Fatalf("expected 999, got %d", gp.Gas())
	}
}

func TestGasPoolString(t *testing.T) {
	gp := new(GasPool)
	gp.SetGas(12345)
	if gp.String() != "12345" {
		t.Fatalf("expected '12345', got '%s'", gp.String())
	}
}

// --- Genesis tests ---

func TestInitGenesisCreatesProperBlock(t *testing.T) {
	database := db.NewMemoryDB()
	genesis := DefaultGenesis(testChainID)

	header, err := InitGenesis(database, genesis)
	if err != nil {
		t.Fatalf("InitGenesis failed: %v", err)
	}

	if header.Number.Int64() != 0 {
		t.Fatalf("expected genesis block number 0, got %d", header.Number.Int64())
	}
	if header.ParentHash != (types.Hash{}) {
		t.Fatal("genesis parent hash should be zero")
	}
	if header.GasLimit != DefaultGasLimit {
		t.Fatalf("expected gas limit %d, got %d", DefaultGasLimit, header.GasLimit)
	}

	// Verify it was written to the chain DB.
	chainDB := NewChainDB(database)
	headHash := chainDB.ReadHeadBlockHash()
	if headHash == (types.Hash{}) {
		t.Fatal("head block hash not written")
	}

	readBlock := chainDB.ReadBlock(headHash, 0)
	if readBlock == nil {
		t.Fatal("genesis block not found in chain DB")
	}
}

func TestGenesisStateRootDeterministic(t *testing.T) {
	genesis := DefaultGenesis(testChainID)
	genesis.Alloc = map[types.Address]GenesisAccount{
		types.HexToAddress("0x01"): {Balance: uint256.NewInt(1000)},
		types.HexToAddress("0x02"): {Balance: uint256.NewInt(2000)},
	}

	db1 := db.NewMemoryDB()
	header1, err := InitGenesis(db1, genesis)
	if err != nil {
		t.Fatalf("InitGenesis 1 failed: %v", err)
	}

	db2 := db.NewMemoryDB()
	header2, err := InitGenesis(db2, genesis)
	if err != nil {
		t.Fatalf("InitGenesis 2 failed: %v", err)
	}

	if header1.StateRoot != header2.StateRoot {
		t.Fatalf("genesis state root not deterministic: %s != %s", header1.StateRoot.Hex(), header2.StateRoot.Hex())
	}
}

func TestGenesisAllocationsApplied(t *testing.T) {
	database := db.NewMemoryDB()
	addr := types.HexToAddress("0xaaaa")
	balance := uint256.NewInt(1_000_000)

	genesis := DefaultGenesis(testChainID)
	genesis.Alloc = map[types.Address]GenesisAccount{
		addr: {Balance: balance, Nonce: 5},
	}

	header, err := InitGenesis(database, genesis)
	if err != nil {
		t.Fatalf("InitGenesis failed: %v", err)
	}

	// Verify the state root is not empty root.
	if header.StateRoot == types.EmptyRootHash {
		t.Fatal("genesis state root should not be empty when allocations exist")
	}

	// Verify the allocations by creating a state from the root.
	statedb, err := state.New(header.StateRoot, database)
	if err != nil {
		t.Fatalf("failed to open state: %v", err)
	}
	gotBalance := statedb.GetBalance(addr)
	if gotBalance.Cmp(balance) != 0 {
		t.Fatalf("expected balance %s, got %s", balance.String(), gotBalance.String())
	}
	gotNonce := statedb.GetNonce(addr)
	if gotNonce != 5 {
		t.Fatalf("expected nonce 5, got %d", gotNonce)
	}
}

// --- ChainDB tests ---

func TestChainDBHeaderRoundTrip(t *testing.T) {
	database := db.NewMemoryDB()
	chainDB := NewChainDB(database)

	header := &L2Header{
		ParentHash: types.HexToHash("0x01"),
		Number:     big.NewInt(10),
		GasLimit:   30_000_000,
		GasUsed:    1_000_000,
		Timestamp:  12345,
		BaseFee:    new(big.Int),
	}

	err := chainDB.WriteHeader(header)
	if err != nil {
		t.Fatalf("WriteHeader failed: %v", err)
	}

	hash := header.Hash()
	got := chainDB.ReadHeader(hash, 10)
	if got == nil {
		t.Fatal("ReadHeader returned nil")
	}
	if got.Hash() != hash {
		t.Fatalf("header hash mismatch: %s != %s", got.Hash().Hex(), hash.Hex())
	}
	if got.GasUsed != 1_000_000 {
		t.Fatalf("expected GasUsed 1_000_000, got %d", got.GasUsed)
	}
}

func TestChainDBBlockRoundTrip(t *testing.T) {
	database := db.NewMemoryDB()
	chainDB := NewChainDB(database)

	header := &L2Header{
		Number:   big.NewInt(1),
		GasLimit: 30_000_000,
		BaseFee:  new(big.Int),
	}

	block := NewBlock(header, nil, nil)
	err := chainDB.WriteBlock(block, nil)
	if err != nil {
		t.Fatalf("WriteBlock failed: %v", err)
	}

	hash := block.Hash()
	got := chainDB.ReadBlock(hash, 1)
	if got == nil {
		t.Fatal("ReadBlock returned nil")
	}
	if got.Hash() != hash {
		t.Fatalf("block hash mismatch")
	}
}

func TestChainDBCanonicalHash(t *testing.T) {
	database := db.NewMemoryDB()
	chainDB := NewChainDB(database)

	hash := types.HexToHash("0xabcdef")
	err := chainDB.WriteCanonicalHash(hash, 5)
	if err != nil {
		t.Fatalf("WriteCanonicalHash failed: %v", err)
	}

	got := chainDB.ReadCanonicalHash(5)
	if got != hash {
		t.Fatalf("canonical hash mismatch: %s != %s", got.Hex(), hash.Hex())
	}

	// Non-existent should return zero hash.
	missing := chainDB.ReadCanonicalHash(99)
	if missing != (types.Hash{}) {
		t.Fatalf("expected zero hash for missing canonical, got %s", missing.Hex())
	}
}

func TestChainDBTxLookup(t *testing.T) {
	database := db.NewMemoryDB()
	chainDB := NewChainDB(database)

	txHash := types.HexToHash("0xaaa")
	blockHash := types.HexToHash("0xbbb")

	err := chainDB.WriteTxLookup(txHash, blockHash, 10, 3)
	if err != nil {
		t.Fatalf("WriteTxLookup failed: %v", err)
	}

	entry, err := chainDB.ReadTxLookup(txHash)
	if err != nil {
		t.Fatalf("ReadTxLookup failed: %v", err)
	}
	if entry.BlockHash != blockHash {
		t.Fatalf("block hash mismatch")
	}
	if entry.BlockNumber != 10 {
		t.Fatalf("block number mismatch: %d", entry.BlockNumber)
	}
	if entry.Index != 3 {
		t.Fatalf("index mismatch: %d", entry.Index)
	}
}

func TestChainDBHeadBlockHash(t *testing.T) {
	database := db.NewMemoryDB()
	chainDB := NewChainDB(database)

	hash := types.HexToHash("0xfeed")
	err := chainDB.WriteHeadBlockHash(hash)
	if err != nil {
		t.Fatalf("WriteHeadBlockHash failed: %v", err)
	}

	got := chainDB.ReadHeadBlockHash()
	if got != hash {
		t.Fatalf("head block hash mismatch")
	}
}

// --- State transition tests ---

func TestSimpleValueTransfer(t *testing.T) {
	config := newTestChainConfig()
	database := db.NewMemoryDB()

	// Create genesis with a funded account.
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	senderAddr := types.Address(crypto.PubkeyToAddress(key.PublicKey))
	recipientAddr := types.HexToAddress("0x1234567890abcdef1234567890abcdef12345678")

	genesis := DefaultGenesis(testChainID)
	// 1000 ETH in wei.
	balance, _ := uint256.FromBig(new(big.Int).Mul(big.NewInt(1000), new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil)))
	genesis.Alloc = map[types.Address]GenesisAccount{
		senderAddr: {Balance: balance},
	}

	genesisHeader, err := InitGenesis(database, genesis)
	if err != nil {
		t.Fatalf("InitGenesis failed: %v", err)
	}

	// Open state at genesis root.
	statedb, err := state.New(genesisHeader.StateRoot, database)
	if err != nil {
		t.Fatalf("failed to open state: %v", err)
	}

	// Create a transfer transaction.
	transferValue := uint256.NewInt(1_000_000_000_000_000_000) // 1 ETH
	signer := types.NewLondonSigner(big.NewInt(testChainID))
	tx, err := types.SignNewTx(key, signer, &types.DynamicFeeTx{
		ChainID:   big.NewInt(testChainID),
		Nonce:     0,
		GasTipCap: big.NewInt(1),
		GasFeeCap: big.NewInt(1),
		Gas:       21000,
		To:        &recipientAddr,
		Value:     transferValue,
	})
	if err != nil {
		t.Fatalf("failed to sign tx: %v", err)
	}

	// Execute via ProcessBatch. Use a separate coinbase so tip doesn't go back to sender.
	coinbaseAddr := types.HexToAddress("0xcccccccccccccccccccccccccccccccccccccccc")
	executor := NewBlockExecutor(config, vm.Config{})
	chainCtx := &testChainContext{}

	block, receipts, err := executor.ProcessBatch(
		genesisHeader,
		coinbaseAddr,
		1000,
		[]*types.Transaction{tx},
		statedb,
		chainCtx,
	)
	if err != nil {
		t.Fatalf("ProcessBatch failed: %v", err)
	}

	// Verify results.
	if len(receipts) != 1 {
		t.Fatalf("expected 1 receipt, got %d", len(receipts))
	}
	if receipts[0].Status != types.ReceiptStatusSuccessful {
		t.Fatalf("expected successful receipt, got status %d", receipts[0].Status)
	}
	if receipts[0].GasUsed != 21000 {
		t.Fatalf("expected 21000 gas used, got %d", receipts[0].GasUsed)
	}

	// Verify recipient balance.
	recipientBal := statedb.GetBalance(recipientAddr)
	if recipientBal.Cmp(transferValue) != 0 {
		t.Fatalf("expected recipient balance %s, got %s", transferValue.String(), recipientBal.String())
	}

	// Verify sender balance decreased by value + gas.
	senderBal := statedb.GetBalance(senderAddr)
	expectedDeduction := new(big.Int).Add(transferValue.ToBig(), big.NewInt(21000)) // gas * gasPrice(1)
	expectedSenderBal := new(big.Int).Sub(balance.ToBig(), expectedDeduction)
	expectedSenderU256, _ := uint256.FromBig(expectedSenderBal)
	if senderBal.Cmp(expectedSenderU256) != 0 {
		t.Fatalf("expected sender balance %s, got %s", expectedSenderU256.String(), senderBal.String())
	}

	// Verify state root changed.
	if block.StateRoot() == genesisHeader.StateRoot {
		t.Fatal("state root should have changed after transfer")
	}

	// Verify block number.
	if block.NumberU64() != 1 {
		t.Fatalf("expected block number 1, got %d", block.NumberU64())
	}
}

func TestNonceValidation(t *testing.T) {
	config := newTestChainConfig()
	database := db.NewMemoryDB()

	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	senderAddr := types.Address(crypto.PubkeyToAddress(key.PublicKey))
	recipientAddr := types.HexToAddress("0x1111111111111111111111111111111111111111")

	genesis := DefaultGenesis(testChainID)
	balance, _ := uint256.FromBig(new(big.Int).Mul(big.NewInt(100), new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil)))
	genesis.Alloc = map[types.Address]GenesisAccount{
		senderAddr: {Balance: balance},
	}

	genesisHeader, err := InitGenesis(database, genesis)
	if err != nil {
		t.Fatalf("InitGenesis failed: %v", err)
	}

	statedb, err := state.New(genesisHeader.StateRoot, database)
	if err != nil {
		t.Fatalf("failed to open state: %v", err)
	}

	// Create a tx with nonce=5 when the state nonce is 0.
	signer := types.NewLondonSigner(big.NewInt(testChainID))
	tx, err := types.SignNewTx(key, signer, &types.DynamicFeeTx{
		ChainID:   big.NewInt(testChainID),
		Nonce:     5, // wrong nonce
		GasTipCap: big.NewInt(1),
		GasFeeCap: big.NewInt(1),
		Gas:       21000,
		To:        &recipientAddr,
		Value:     uint256.NewInt(1),
	})
	if err != nil {
		t.Fatalf("failed to sign tx: %v", err)
	}

	// ProcessBatch should skip the invalid tx.
	executor := NewBlockExecutor(config, vm.Config{})
	chainCtx := &testChainContext{}

	block, receipts, err := executor.ProcessBatch(
		genesisHeader,
		senderAddr,
		1000,
		[]*types.Transaction{tx},
		statedb,
		chainCtx,
	)
	if err != nil {
		t.Fatalf("ProcessBatch failed: %v", err)
	}

	// The tx should be skipped.
	if len(receipts) != 0 {
		t.Fatalf("expected 0 receipts (invalid nonce tx skipped), got %d", len(receipts))
	}
	if len(block.Transactions) != 0 {
		t.Fatalf("expected 0 transactions, got %d", len(block.Transactions))
	}
}

func TestInsufficientBalance(t *testing.T) {
	config := newTestChainConfig()
	database := db.NewMemoryDB()

	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	senderAddr := types.Address(crypto.PubkeyToAddress(key.PublicKey))
	recipientAddr := types.HexToAddress("0x2222222222222222222222222222222222222222")

	genesis := DefaultGenesis(testChainID)
	// Very small balance: only 1000 wei.
	genesis.Alloc = map[types.Address]GenesisAccount{
		senderAddr: {Balance: uint256.NewInt(1000)},
	}

	genesisHeader, err := InitGenesis(database, genesis)
	if err != nil {
		t.Fatalf("InitGenesis failed: %v", err)
	}

	statedb, err := state.New(genesisHeader.StateRoot, database)
	if err != nil {
		t.Fatalf("failed to open state: %v", err)
	}

	// Try to transfer more than the balance (including gas costs).
	signer := types.NewLondonSigner(big.NewInt(testChainID))
	tx, err := types.SignNewTx(key, signer, &types.DynamicFeeTx{
		ChainID:   big.NewInt(testChainID),
		Nonce:     0,
		GasTipCap: big.NewInt(1),
		GasFeeCap: big.NewInt(1),
		Gas:       21000,
		To:        &recipientAddr,
		Value:     uint256.NewInt(1_000_000), // way more than balance
	})
	if err != nil {
		t.Fatalf("failed to sign tx: %v", err)
	}

	executor := NewBlockExecutor(config, vm.Config{})
	chainCtx := &testChainContext{}

	_, receipts, err := executor.ProcessBatch(
		genesisHeader,
		senderAddr,
		1000,
		[]*types.Transaction{tx},
		statedb,
		chainCtx,
	)
	if err != nil {
		t.Fatalf("ProcessBatch failed: %v", err)
	}

	// The tx should be skipped due to insufficient funds.
	if len(receipts) != 0 {
		t.Fatalf("expected 0 receipts (insufficient balance tx skipped), got %d", len(receipts))
	}
}

// --- Block execution tests ---

func TestExecuteEmptyBlock(t *testing.T) {
	config := newTestChainConfig()
	database := db.NewMemoryDB()

	genesis := DefaultGenesis(testChainID)
	genesisHeader, err := InitGenesis(database, genesis)
	if err != nil {
		t.Fatalf("InitGenesis failed: %v", err)
	}

	statedb, err := state.New(genesisHeader.StateRoot, database)
	if err != nil {
		t.Fatalf("failed to open state: %v", err)
	}

	executor := NewBlockExecutor(config, vm.Config{})
	chainCtx := &testChainContext{}

	block, receipts, err := executor.ProcessBatch(
		genesisHeader,
		types.Address{},
		1000,
		nil,
		statedb,
		chainCtx,
	)
	if err != nil {
		t.Fatalf("ProcessBatch failed: %v", err)
	}

	if len(receipts) != 0 {
		t.Fatalf("expected 0 receipts, got %d", len(receipts))
	}
	if block.NumberU64() != 1 {
		t.Fatalf("expected block number 1, got %d", block.NumberU64())
	}
	if block.GasUsed() != 0 {
		t.Fatalf("expected 0 gas used, got %d", block.GasUsed())
	}
}

func TestExecuteBlockMultipleTransfers(t *testing.T) {
	config := newTestChainConfig()
	database := db.NewMemoryDB()

	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	senderAddr := types.Address(crypto.PubkeyToAddress(key.PublicKey))
	recipient1 := types.HexToAddress("0x1111111111111111111111111111111111111111")
	recipient2 := types.HexToAddress("0x2222222222222222222222222222222222222222")

	genesis := DefaultGenesis(testChainID)
	balance, _ := uint256.FromBig(new(big.Int).Mul(big.NewInt(1000), new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil)))
	genesis.Alloc = map[types.Address]GenesisAccount{
		senderAddr: {Balance: balance},
	}

	genesisHeader, err := InitGenesis(database, genesis)
	if err != nil {
		t.Fatalf("InitGenesis failed: %v", err)
	}

	statedb, err := state.New(genesisHeader.StateRoot, database)
	if err != nil {
		t.Fatalf("failed to open state: %v", err)
	}

	signer := types.NewLondonSigner(big.NewInt(testChainID))

	tx1, err := types.SignNewTx(key, signer, &types.DynamicFeeTx{
		ChainID:   big.NewInt(testChainID),
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
		ChainID:   big.NewInt(testChainID),
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

	executor := NewBlockExecutor(config, vm.Config{})
	chainCtx := &testChainContext{}

	block, receipts, err := executor.ProcessBatch(
		genesisHeader,
		senderAddr,
		1000,
		[]*types.Transaction{tx1, tx2},
		statedb,
		chainCtx,
	)
	if err != nil {
		t.Fatalf("ProcessBatch failed: %v", err)
	}

	if len(receipts) != 2 {
		t.Fatalf("expected 2 receipts, got %d", len(receipts))
	}
	for i, r := range receipts {
		if r.Status != types.ReceiptStatusSuccessful {
			t.Fatalf("receipt %d not successful", i)
		}
	}

	if block.GasUsed() != 42000 {
		t.Fatalf("expected 42000 gas used, got %d", block.GasUsed())
	}

	// Verify balances.
	r1Bal := statedb.GetBalance(recipient1)
	if r1Bal.Uint64() != 100 {
		t.Fatalf("expected recipient1 balance 100, got %d", r1Bal.Uint64())
	}
	r2Bal := statedb.GetBalance(recipient2)
	if r2Bal.Uint64() != 200 {
		t.Fatalf("expected recipient2 balance 200, got %d", r2Bal.Uint64())
	}
}

func TestGasPoolLimitsTotalGas(t *testing.T) {
	config := newTestChainConfig()
	database := db.NewMemoryDB()

	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	senderAddr := types.Address(crypto.PubkeyToAddress(key.PublicKey))
	recipientAddr := types.HexToAddress("0x1111111111111111111111111111111111111111")

	genesis := DefaultGenesis(testChainID)
	// Set gas limit very low.
	genesis.GasLimit = 25000
	balance, _ := uint256.FromBig(new(big.Int).Mul(big.NewInt(1000), new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil)))
	genesis.Alloc = map[types.Address]GenesisAccount{
		senderAddr: {Balance: balance},
	}

	genesisHeader, err := InitGenesis(database, genesis)
	if err != nil {
		t.Fatalf("InitGenesis failed: %v", err)
	}

	statedb, err := state.New(genesisHeader.StateRoot, database)
	if err != nil {
		t.Fatalf("failed to open state: %v", err)
	}

	signer := types.NewLondonSigner(big.NewInt(testChainID))

	// First tx uses 21000 gas.
	tx1, _ := types.SignNewTx(key, signer, &types.DynamicFeeTx{
		ChainID:   big.NewInt(testChainID),
		Nonce:     0,
		GasTipCap: big.NewInt(1),
		GasFeeCap: big.NewInt(1),
		Gas:       21000,
		To:        &recipientAddr,
		Value:     uint256.NewInt(1),
	})

	// Second tx also needs 21000 gas, but pool only has 25000 total.
	tx2, _ := types.SignNewTx(key, signer, &types.DynamicFeeTx{
		ChainID:   big.NewInt(testChainID),
		Nonce:     1,
		GasTipCap: big.NewInt(1),
		GasFeeCap: big.NewInt(1),
		Gas:       21000,
		To:        &recipientAddr,
		Value:     uint256.NewInt(1),
	})

	executor := NewBlockExecutor(config, vm.Config{})
	chainCtx := &testChainContext{}

	_, receipts, err := executor.ProcessBatch(
		genesisHeader,
		senderAddr,
		1000,
		[]*types.Transaction{tx1, tx2},
		statedb,
		chainCtx,
	)
	if err != nil {
		t.Fatalf("ProcessBatch failed: %v", err)
	}

	// Only the first tx should have been included (25000 < 21000 + 21000).
	if len(receipts) != 1 {
		t.Fatalf("expected 1 receipt (gas pool limit), got %d", len(receipts))
	}
}

// --- Integration test ---

func TestFullIntegration(t *testing.T) {
	config := newTestChainConfig()
	database := db.NewMemoryDB()

	// Generate sender key.
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	senderAddr := types.Address(crypto.PubkeyToAddress(key.PublicKey))
	recipientAddr := types.HexToAddress("0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")

	// 1. Init genesis with funded account.
	genesis := DefaultGenesis(testChainID)
	// 1000 ETH.
	oneETH := new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil)
	thousandETH := new(big.Int).Mul(big.NewInt(1000), oneETH)
	initialBalance, _ := uint256.FromBig(thousandETH)
	genesis.Alloc = map[types.Address]GenesisAccount{
		senderAddr: {Balance: initialBalance},
	}

	genesisHeader, err := InitGenesis(database, genesis)
	if err != nil {
		t.Fatalf("InitGenesis failed: %v", err)
	}

	// 2. Open state.
	statedb, err := state.New(genesisHeader.StateRoot, database)
	if err != nil {
		t.Fatalf("failed to open state: %v", err)
	}

	// 3. Create and sign a transfer tx.
	transferAmount := uint256.NewInt(5_000_000_000_000_000_000) // 5 ETH
	signer := types.NewLondonSigner(big.NewInt(testChainID))
	tx, err := types.SignNewTx(key, signer, &types.DynamicFeeTx{
		ChainID:   big.NewInt(testChainID),
		Nonce:     0,
		GasTipCap: big.NewInt(1_000_000_000), // 1 gwei
		GasFeeCap: big.NewInt(1_000_000_000), // 1 gwei
		Gas:       21000,
		To:        &recipientAddr,
		Value:     transferAmount,
	})
	if err != nil {
		t.Fatalf("failed to sign tx: %v", err)
	}

	// 4. ProcessBatch.
	executor := NewBlockExecutor(config, vm.Config{})
	coinbase := types.HexToAddress("0xcccccccccccccccccccccccccccccccccccccccc")
	chainCtx := &testChainContext{
		headers: map[uint64]*L2Header{
			0: genesisHeader,
		},
	}

	block, receipts, err := executor.ProcessBatch(
		genesisHeader,
		coinbase,
		2000,
		[]*types.Transaction{tx},
		statedb,
		chainCtx,
	)
	if err != nil {
		t.Fatalf("ProcessBatch failed: %v", err)
	}

	// 5. Verify receipt.
	if len(receipts) != 1 {
		t.Fatalf("expected 1 receipt, got %d", len(receipts))
	}
	receipt := receipts[0]
	if receipt.Status != types.ReceiptStatusSuccessful {
		t.Fatalf("expected successful receipt, got status %d", receipt.Status)
	}
	if receipt.GasUsed != 21000 {
		t.Fatalf("expected 21000 gas used, got %d", receipt.GasUsed)
	}

	// 6. Verify balances.
	recipientBal := statedb.GetBalance(recipientAddr)
	if recipientBal.Cmp(transferAmount) != 0 {
		t.Fatalf("recipient balance: expected %s, got %s", transferAmount.String(), recipientBal.String())
	}

	// Sender should have: initial - transfer - gasCost.
	gasCost := new(big.Int).Mul(big.NewInt(21000), big.NewInt(1_000_000_000))
	expectedSender := new(big.Int).Sub(thousandETH, transferAmount.ToBig())
	expectedSender.Sub(expectedSender, gasCost)
	expectedSenderU256, _ := uint256.FromBig(expectedSender)
	senderBal := statedb.GetBalance(senderAddr)
	if senderBal.Cmp(expectedSenderU256) != 0 {
		t.Fatalf("sender balance: expected %s, got %s", expectedSenderU256.String(), senderBal.String())
	}

	// Coinbase should have received the gas fee.
	coinbaseBal := statedb.GetBalance(coinbase)
	gasFeeU256, _ := uint256.FromBig(gasCost)
	if coinbaseBal.Cmp(gasFeeU256) != 0 {
		t.Fatalf("coinbase balance: expected %s, got %s", gasFeeU256.String(), coinbaseBal.String())
	}

	// 7. Verify state root changed.
	if block.StateRoot() == genesisHeader.StateRoot {
		t.Fatal("state root should have changed")
	}

	// 8. Verify block metadata.
	if block.NumberU64() != 1 {
		t.Fatalf("expected block number 1, got %d", block.NumberU64())
	}
	if block.ParentHash() != genesisHeader.Hash() {
		t.Fatal("parent hash mismatch")
	}
	if block.GasUsed() != 21000 {
		t.Fatalf("expected block gas used 21000, got %d", block.GasUsed())
	}

	// 9. Write block to ChainDB and read back.
	chainDB := NewChainDB(database)
	err = chainDB.WriteBlock(block, receipts)
	if err != nil {
		t.Fatalf("WriteBlock failed: %v", err)
	}

	readBlock := chainDB.ReadBlock(block.Hash(), block.NumberU64())
	if readBlock == nil {
		t.Fatal("failed to read block back from ChainDB")
	}
	if readBlock.Hash() != block.Hash() {
		t.Fatal("read block hash mismatch")
	}
	if readBlock.NumberU64() != block.NumberU64() {
		t.Fatal("read block number mismatch")
	}
	if readBlock.GasUsed() != block.GasUsed() {
		t.Fatal("read block gas used mismatch")
	}

	// 10. Verify tx lookup.
	entry, err := chainDB.ReadTxLookup(tx.Hash())
	if err != nil {
		t.Fatalf("ReadTxLookup failed: %v", err)
	}
	if entry.BlockHash != block.Hash() {
		t.Fatal("tx lookup block hash mismatch")
	}
	if entry.BlockNumber != 1 {
		t.Fatalf("tx lookup block number: expected 1, got %d", entry.BlockNumber)
	}
	if entry.Index != 0 {
		t.Fatalf("tx lookup index: expected 0, got %d", entry.Index)
	}
}

// --- ExecutionResult tests ---

func TestExecutionResultFailed(t *testing.T) {
	r := &ExecutionResult{Err: vm.ErrExecutionReverted, ReturnData: []byte{1, 2, 3}}
	if !r.Failed() {
		t.Fatal("expected Failed() to be true")
	}
	if r.Return() != nil {
		t.Fatal("expected Return() to be nil on failure")
	}
	revert := r.Revert()
	if len(revert) != 3 {
		t.Fatal("expected Revert() to return data")
	}
}

func TestExecutionResultSuccess(t *testing.T) {
	r := &ExecutionResult{Err: nil, ReturnData: []byte{4, 5, 6}}
	if r.Failed() {
		t.Fatal("expected Failed() to be false")
	}
	ret := r.Return()
	if len(ret) != 3 {
		t.Fatal("expected Return() to return data")
	}
	if r.Revert() != nil {
		t.Fatal("expected Revert() to be nil on success")
	}
}

// --- Contract creation test ---

func TestContractCreation(t *testing.T) {
	config := newTestChainConfig()
	database := db.NewMemoryDB()

	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	senderAddr := types.Address(crypto.PubkeyToAddress(key.PublicKey))

	genesis := DefaultGenesis(testChainID)
	balance, _ := uint256.FromBig(new(big.Int).Mul(big.NewInt(100), new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil)))
	genesis.Alloc = map[types.Address]GenesisAccount{
		senderAddr: {Balance: balance},
	}

	genesisHeader, err := InitGenesis(database, genesis)
	if err != nil {
		t.Fatalf("InitGenesis failed: %v", err)
	}

	statedb, err := state.New(genesisHeader.StateRoot, database)
	if err != nil {
		t.Fatalf("failed to open state: %v", err)
	}

	// Simple contract: PUSH1 0x42, PUSH1 0, MSTORE, PUSH1 32, PUSH1 0, RETURN
	// This stores 0x42 in memory and returns it.
	// bytecode: 0x60 0x42 0x60 0x00 0x52 0x60 0x20 0x60 0x00 0xf3
	initCode := []byte{0x60, 0x42, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xf3}

	signer := types.NewLondonSigner(big.NewInt(testChainID))
	tx, err := types.SignNewTx(key, signer, &types.DynamicFeeTx{
		ChainID:   big.NewInt(testChainID),
		Nonce:     0,
		GasTipCap: big.NewInt(1),
		GasFeeCap: big.NewInt(1),
		Gas:       100000,
		To:        nil, // contract creation
		Value:     uint256.NewInt(0),
		Data:      initCode,
	})
	if err != nil {
		t.Fatalf("failed to sign tx: %v", err)
	}

	executor := NewBlockExecutor(config, vm.Config{})
	chainCtx := &testChainContext{}

	_, receipts, err := executor.ProcessBatch(
		genesisHeader,
		senderAddr,
		1000,
		[]*types.Transaction{tx},
		statedb,
		chainCtx,
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
	if receipts[0].ContractAddress == (types.Address{}) {
		t.Fatal("contract address should not be zero")
	}

	// Verify the contract code was stored.
	contractCode := statedb.GetCode(receipts[0].ContractAddress)
	if len(contractCode) == 0 {
		t.Fatal("contract code not stored")
	}
}

// --- Transactions (DerivableList) tests ---

func TestTransactionsDerivableList(t *testing.T) {
	// Test that Transactions implements DerivableList correctly.
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	signer := types.NewLondonSigner(big.NewInt(testChainID))
	recipientAddr := types.HexToAddress("0x1111111111111111111111111111111111111111")

	tx1, _ := types.SignNewTx(key, signer, &types.DynamicFeeTx{
		ChainID:   big.NewInt(testChainID),
		Nonce:     0,
		GasTipCap: big.NewInt(1),
		GasFeeCap: big.NewInt(1),
		Gas:       21000,
		To:        &recipientAddr,
		Value:     uint256.NewInt(1),
	})

	txs := Transactions{tx1}
	if txs.Len() != 1 {
		t.Fatalf("expected Len() 1, got %d", txs.Len())
	}

	// EncodeIndex should not panic.
	var buf bytes.Buffer
	txs.EncodeIndex(0, &buf)
	if buf.Len() == 0 {
		t.Fatal("EncodeIndex produced empty output")
	}
}

// --- Failed tx still uses gas test ---

func TestFailedTxConsumesSenderGas(t *testing.T) {
	config := newTestChainConfig()
	database := db.NewMemoryDB()

	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	senderAddr := types.Address(crypto.PubkeyToAddress(key.PublicKey))

	genesis := DefaultGenesis(testChainID)
	balance, _ := uint256.FromBig(new(big.Int).Mul(big.NewInt(100), new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil)))
	genesis.Alloc = map[types.Address]GenesisAccount{
		senderAddr: {Balance: balance},
	}

	genesisHeader, err := InitGenesis(database, genesis)
	if err != nil {
		t.Fatalf("InitGenesis failed: %v", err)
	}

	statedb, err := state.New(genesisHeader.StateRoot, database)
	if err != nil {
		t.Fatalf("failed to open state: %v", err)
	}

	// Contract code that always reverts: PUSH1 0, PUSH1 0, REVERT
	// bytecode: 0x60 0x00 0x60 0x00 0xfd
	revertCode := []byte{0x60, 0x00, 0x60, 0x00, 0xfd}

	// First deploy the revert contract.
	signer := types.NewLondonSigner(big.NewInt(testChainID))

	// Deploy code that stores revert code: runtime code = 6000 6000 fd
	// Init code that returns runtime code:
	// PUSH5 revertCode PUSH1 0 MSTORE PUSH1 5 PUSH1 27 RETURN
	// Actually simpler: just use raw init code that returns the revert bytecode.
	// PUSH1 <len> PUSH1 <offset> PUSH1 0 CODECOPY PUSH1 <len> PUSH1 0 RETURN
	// Where offset = len(initcode). Let's use a simpler approach:
	// Runtime: 6000 6000 fd (always reverts)
	// Init: 60056010600039600560006000f3 -- doesn't matter, let's just call
	// a non-existent contract to get a "call" that fails.
	// Actually, the simplest way: send a CALL to a contract address that has
	// revert code.

	// Let's deploy the revert contract manually.
	contractAddr := types.HexToAddress("0x9999999999999999999999999999999999999999")
	statedb.CreateAccount(contractAddr)
	statedb.SetCode(contractAddr, revertCode, tracing.CodeChangeCreation)

	// Call the revert contract.
	tx, err := types.SignNewTx(key, signer, &types.DynamicFeeTx{
		ChainID:   big.NewInt(testChainID),
		Nonce:     0,
		GasTipCap: big.NewInt(1),
		GasFeeCap: big.NewInt(1),
		Gas:       100000,
		To:        &contractAddr,
		Value:     uint256.NewInt(0),
		Data:      nil,
	})
	if err != nil {
		t.Fatalf("failed to sign tx: %v", err)
	}

	executor := NewBlockExecutor(config, vm.Config{})
	chainCtx := &testChainContext{}

	_, receipts, err := executor.ProcessBatch(
		genesisHeader,
		senderAddr,
		1000,
		[]*types.Transaction{tx},
		statedb,
		chainCtx,
	)
	if err != nil {
		t.Fatalf("ProcessBatch failed: %v", err)
	}

	if len(receipts) != 1 {
		t.Fatalf("expected 1 receipt, got %d", len(receipts))
	}

	// The tx should be included but with failed status.
	if receipts[0].Status != types.ReceiptStatusFailed {
		t.Fatalf("expected failed status, got %d", receipts[0].Status)
	}

	// Gas should still have been consumed.
	if receipts[0].GasUsed == 0 {
		t.Fatal("failed tx should still consume gas")
	}
}

// --- copyHeader test ---

func TestCopyHeaderDeepCopy(t *testing.T) {
	h := &L2Header{
		Number:  big.NewInt(10),
		BaseFee: big.NewInt(100),
		Extra:   []byte{1, 2, 3},
	}

	cpy := copyHeader(h)

	// Modify the copy.
	cpy.Number.SetInt64(999)
	cpy.BaseFee.SetInt64(888)
	cpy.Extra[0] = 99

	// Original should be unchanged.
	if h.Number.Int64() != 10 {
		t.Fatal("original Number was modified")
	}
	if h.BaseFee.Int64() != 100 {
		t.Fatal("original BaseFee was modified")
	}
	if h.Extra[0] != 1 {
		t.Fatal("original Extra was modified")
	}
}

// --- AnchorRecord and covenant tracking tests ---

func TestChainDB_WriteReadAnchorRecord(t *testing.T) {
	database := db.NewMemoryDB()
	chainDB := NewChainDB(database)

	record := &AnchorRecord{
		L2BlockNum:     42,
		BSVTxID:        types.HexToHash("0xdeadbeef"),
		BSVBlockHeight: 800000,
		Confirmed:      true,
	}

	err := chainDB.WriteAnchorRecord(record)
	if err != nil {
		t.Fatalf("WriteAnchorRecord failed: %v", err)
	}

	got := chainDB.ReadAnchorRecord(42)
	if got == nil {
		t.Fatal("ReadAnchorRecord returned nil")
	}
	if got.L2BlockNum != record.L2BlockNum {
		t.Fatalf("L2BlockNum mismatch: got %d, want %d", got.L2BlockNum, record.L2BlockNum)
	}
	if got.BSVTxID != record.BSVTxID {
		t.Fatalf("BSVTxID mismatch: got %s, want %s", got.BSVTxID.Hex(), record.BSVTxID.Hex())
	}
	if got.BSVBlockHeight != record.BSVBlockHeight {
		t.Fatalf("BSVBlockHeight mismatch: got %d, want %d", got.BSVBlockHeight, record.BSVBlockHeight)
	}
	if got.Confirmed != record.Confirmed {
		t.Fatalf("Confirmed mismatch: got %v, want %v", got.Confirmed, record.Confirmed)
	}
}

func TestChainDB_ReadAnchorRecord_NotFound(t *testing.T) {
	database := db.NewMemoryDB()
	chainDB := NewChainDB(database)

	got := chainDB.ReadAnchorRecord(999)
	if got != nil {
		t.Fatalf("expected nil for non-existent anchor record, got %+v", got)
	}
}

func TestChainDB_WriteReadCovenantTxID(t *testing.T) {
	database := db.NewMemoryDB()
	chainDB := NewChainDB(database)

	txid := types.HexToHash("0xabcdef1234567890")

	err := chainDB.WriteCovenantTxID(txid)
	if err != nil {
		t.Fatalf("WriteCovenantTxID failed: %v", err)
	}

	got := chainDB.ReadCovenantTxID()
	if got != txid {
		t.Fatalf("covenant txid mismatch: got %s, want %s", got.Hex(), txid.Hex())
	}
}

func TestChainDB_ReadCovenantTxID_NotSet(t *testing.T) {
	database := db.NewMemoryDB()
	chainDB := NewChainDB(database)

	got := chainDB.ReadCovenantTxID()
	if got != (types.Hash{}) {
		t.Fatalf("expected zero hash for unset covenant txid, got %s", got.Hex())
	}
}

func TestChainDB_WriteReadCovenantState(t *testing.T) {
	database := db.NewMemoryDB()
	chainDB := NewChainDB(database)

	stateData := []byte("serialized covenant state data")

	err := chainDB.WriteCovenantState(stateData)
	if err != nil {
		t.Fatalf("WriteCovenantState failed: %v", err)
	}

	got := chainDB.ReadCovenantState()
	if !bytes.Equal(got, stateData) {
		t.Fatalf("covenant state mismatch: got %x, want %x", got, stateData)
	}
}

func TestChainDB_ReadCovenantState_NotSet(t *testing.T) {
	database := db.NewMemoryDB()
	chainDB := NewChainDB(database)

	got := chainDB.ReadCovenantState()
	if got != nil {
		t.Fatalf("expected nil for unset covenant state, got %x", got)
	}
}

func TestChainDB_MultipleAnchors(t *testing.T) {
	database := db.NewMemoryDB()
	chainDB := NewChainDB(database)

	records := []*AnchorRecord{
		{L2BlockNum: 1, BSVTxID: types.HexToHash("0x01"), BSVBlockHeight: 100, Confirmed: true},
		{L2BlockNum: 2, BSVTxID: types.HexToHash("0x02"), BSVBlockHeight: 101, Confirmed: true},
		{L2BlockNum: 3, BSVTxID: types.HexToHash("0x03"), BSVBlockHeight: 102, Confirmed: false},
	}

	for _, r := range records {
		if err := chainDB.WriteAnchorRecord(r); err != nil {
			t.Fatalf("WriteAnchorRecord(block %d) failed: %v", r.L2BlockNum, err)
		}
	}

	for _, want := range records {
		got := chainDB.ReadAnchorRecord(want.L2BlockNum)
		if got == nil {
			t.Fatalf("ReadAnchorRecord(%d) returned nil", want.L2BlockNum)
		}
		if got.L2BlockNum != want.L2BlockNum {
			t.Fatalf("L2BlockNum mismatch for block %d: got %d", want.L2BlockNum, got.L2BlockNum)
		}
		if got.BSVTxID != want.BSVTxID {
			t.Fatalf("BSVTxID mismatch for block %d", want.L2BlockNum)
		}
		if got.BSVBlockHeight != want.BSVBlockHeight {
			t.Fatalf("BSVBlockHeight mismatch for block %d: got %d, want %d", want.L2BlockNum, got.BSVBlockHeight, want.BSVBlockHeight)
		}
		if got.Confirmed != want.Confirmed {
			t.Fatalf("Confirmed mismatch for block %d: got %v, want %v", want.L2BlockNum, got.Confirmed, want.Confirmed)
		}
	}
}

// --- GetHash 256-block ancestor limit tests ---

func TestGetHash256BlockLimit(t *testing.T) {
	// Build a chain context with headers for blocks 0..300.
	headers := make(map[uint64]*L2Header)
	for i := uint64(0); i <= 300; i++ {
		headers[i] = &L2Header{
			Number:   big.NewInt(int64(i)),
			GasLimit: 30_000_000,
			BaseFee:  new(big.Int),
			// Each header has a unique parent hash so the hash is unique.
			ParentHash: types.BytesToHash(big.NewInt(int64(i)).Bytes()),
		}
	}
	chain := &testChainContext{headers: headers}

	t.Run("recent block N-1", func(t *testing.T) {
		header := headers[300]
		ctx := newBlockContext(header, chain, nil, nil)
		h := ctx.GetHash(299)
		if h == (types.Hash{}) {
			t.Fatal("expected non-zero hash for block N-1")
		}
		// Verify it matches the header's hash.
		expected := headers[299].Hash()
		if h != expected {
			t.Fatalf("hash mismatch for block 299: got %s, want %s", h.Hex(), expected.Hex())
		}
	})

	t.Run("boundary block N-256", func(t *testing.T) {
		header := headers[300]
		ctx := newBlockContext(header, chain, nil, nil)
		// Block 300 - 256 = 44, which is exactly at the boundary.
		h := ctx.GetHash(44)
		if h == (types.Hash{}) {
			t.Fatal("expected non-zero hash for block N-256 (boundary)")
		}
		expected := headers[44].Hash()
		if h != expected {
			t.Fatalf("hash mismatch for block 44: got %s, want %s", h.Hex(), expected.Hex())
		}
	})

	t.Run("too old block N-257", func(t *testing.T) {
		header := headers[300]
		ctx := newBlockContext(header, chain, nil, nil)
		// Block 300 - 257 = 43, which is too old.
		h := ctx.GetHash(43)
		if h != (types.Hash{}) {
			t.Fatalf("expected zero hash for block N-257, got %s", h.Hex())
		}
	})

	t.Run("current block N", func(t *testing.T) {
		header := headers[300]
		ctx := newBlockContext(header, chain, nil, nil)
		h := ctx.GetHash(300)
		if h != (types.Hash{}) {
			t.Fatalf("expected zero hash for current block, got %s", h.Hex())
		}
	})

	t.Run("block 0 returns empty for any lookup", func(t *testing.T) {
		header := headers[0]
		ctx := newBlockContext(header, chain, nil, nil)
		// Block 0 cannot look up anything (n >= currentBlockNum always true
		// because currentBlockNum is 0).
		h := ctx.GetHash(0)
		if h != (types.Hash{}) {
			t.Fatalf("expected zero hash at block 0, got %s", h.Hex())
		}
	})

	t.Run("nil chain returns empty", func(t *testing.T) {
		header := headers[300]
		ctx := newBlockContext(header, nil, nil, nil)
		h := ctx.GetHash(299)
		if h != (types.Hash{}) {
			t.Fatalf("expected zero hash with nil chain, got %s", h.Hex())
		}
	})
}

// --- DeriveRandom (PREVRANDAO) tests ---

func TestDeriveRandomDeterministic(t *testing.T) {
	bsvHash := types.HexToHash("0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")
	blockNum := uint64(42)

	result1 := DeriveRandom(bsvHash, blockNum)
	result2 := DeriveRandom(bsvHash, blockNum)

	if result1 != result2 {
		t.Fatalf("DeriveRandom not deterministic: %s != %s", result1.Hex(), result2.Hex())
	}
	if result1 == (types.Hash{}) {
		t.Fatal("DeriveRandom returned zero hash")
	}
}

func TestDeriveRandomDifferentInputs(t *testing.T) {
	bsvHash1 := types.HexToHash("0xaaaa")
	bsvHash2 := types.HexToHash("0xbbbb")
	blockNum := uint64(100)

	r1 := DeriveRandom(bsvHash1, blockNum)
	r2 := DeriveRandom(bsvHash2, blockNum)

	if r1 == r2 {
		t.Fatal("different BSV hashes should produce different PREVRANDAO values")
	}

	// Same hash, different block number.
	r3 := DeriveRandom(bsvHash1, 101)
	if r1 == r3 {
		t.Fatal("different block numbers should produce different PREVRANDAO values")
	}
}

func TestDeriveRandomIs32Bytes(t *testing.T) {
	bsvHash := types.HexToHash("0x1234")
	result := DeriveRandom(bsvHash, 0)

	// types.Hash is [32]byte, so len is always 32.
	if len(result) != 32 {
		t.Fatalf("expected 32-byte hash, got %d bytes", len(result))
	}
}

func TestChainDB_UpdateAnchor(t *testing.T) {
	database := db.NewMemoryDB()
	chainDB := NewChainDB(database)

	// Write initial unconfirmed anchor.
	record := &AnchorRecord{
		L2BlockNum:     10,
		BSVTxID:        types.HexToHash("0xfeed"),
		BSVBlockHeight: 0,
		Confirmed:      false,
	}

	err := chainDB.WriteAnchorRecord(record)
	if err != nil {
		t.Fatalf("WriteAnchorRecord failed: %v", err)
	}

	// Verify initial state.
	got := chainDB.ReadAnchorRecord(10)
	if got == nil {
		t.Fatal("ReadAnchorRecord returned nil")
	}
	if got.Confirmed {
		t.Fatal("expected Confirmed=false initially")
	}
	if got.BSVBlockHeight != 0 {
		t.Fatalf("expected BSVBlockHeight=0 initially, got %d", got.BSVBlockHeight)
	}

	// Update: mark as confirmed with a BSV block height.
	record.BSVBlockHeight = 800500
	record.Confirmed = true

	err = chainDB.WriteAnchorRecord(record)
	if err != nil {
		t.Fatalf("WriteAnchorRecord (update) failed: %v", err)
	}

	// Verify updated state.
	got = chainDB.ReadAnchorRecord(10)
	if got == nil {
		t.Fatal("ReadAnchorRecord returned nil after update")
	}
	if !got.Confirmed {
		t.Fatal("expected Confirmed=true after update")
	}
	if got.BSVBlockHeight != 800500 {
		t.Fatalf("expected BSVBlockHeight=800500 after update, got %d", got.BSVBlockHeight)
	}
	if got.BSVTxID != types.HexToHash("0xfeed") {
		t.Fatalf("BSVTxID changed unexpectedly after update")
	}
}

// --- MarkReceiptsRolledBack tests ---

func TestChainDB_MarkReceiptsRolledBack(t *testing.T) {
	database := db.NewMemoryDB()
	chainDB := NewChainDB(database)

	// Create 3 blocks with receipts.
	for blockNum := uint64(1); blockNum <= 3; blockNum++ {
		header := &L2Header{
			Number:   big.NewInt(int64(blockNum)),
			GasLimit: 30_000_000,
			BaseFee:  new(big.Int),
		}
		blk := NewBlock(header, nil, nil)
		receipts := []*types.Receipt{
			{
				Status:            types.ReceiptStatusSuccessful,
				CumulativeGasUsed: 21000 * blockNum,
				Logs:              []*types.Log{},
			},
		}
		if err := chainDB.WriteBlock(blk, receipts); err != nil {
			t.Fatalf("WriteBlock(%d) failed: %v", blockNum, err)
		}
	}

	// Mark blocks 2-3 as rolled back at block 1.
	if err := chainDB.MarkReceiptsRolledBack(2, 3, 1); err != nil {
		t.Fatalf("MarkReceiptsRolledBack failed: %v", err)
	}

	// Block 1 receipts should NOT be rolled back.
	hash1 := chainDB.ReadCanonicalHash(1)
	receipts1 := chainDB.ReadReceipts(hash1, 1)
	if receipts1 == nil {
		t.Fatal("block 1 receipts should exist")
	}
	if receipts1[0].RolledBack {
		t.Error("block 1 receipt should not be rolled back")
	}
	if receipts1[0].RolledBackAtBlock != 0 {
		t.Errorf("block 1 RolledBackAtBlock should be 0, got %d", receipts1[0].RolledBackAtBlock)
	}

	// Block 2 receipts should be rolled back.
	hash2 := chainDB.ReadCanonicalHash(2)
	receipts2 := chainDB.ReadReceipts(hash2, 2)
	if receipts2 == nil {
		t.Fatal("block 2 receipts should exist")
	}
	if !receipts2[0].RolledBack {
		t.Error("block 2 receipt should be rolled back")
	}
	if receipts2[0].RolledBackAtBlock != 1 {
		t.Errorf("block 2 RolledBackAtBlock should be 1, got %d", receipts2[0].RolledBackAtBlock)
	}

	// Block 3 receipts should be rolled back.
	hash3 := chainDB.ReadCanonicalHash(3)
	receipts3 := chainDB.ReadReceipts(hash3, 3)
	if receipts3 == nil {
		t.Fatal("block 3 receipts should exist")
	}
	if !receipts3[0].RolledBack {
		t.Error("block 3 receipt should be rolled back")
	}
	if receipts3[0].RolledBackAtBlock != 1 {
		t.Errorf("block 3 RolledBackAtBlock should be 1, got %d", receipts3[0].RolledBackAtBlock)
	}
}

func TestChainDB_MarkReceiptsRolledBack_EmptyRange(t *testing.T) {
	database := db.NewMemoryDB()
	chainDB := NewChainDB(database)

	// Marking an empty range (fromBlock > toBlock) should be a no-op.
	err := chainDB.MarkReceiptsRolledBack(5, 3, 2)
	if err != nil {
		t.Fatalf("MarkReceiptsRolledBack on empty range should not error, got: %v", err)
	}
}

func TestChainDB_MarkReceiptsRolledBack_MissingBlock(t *testing.T) {
	database := db.NewMemoryDB()
	chainDB := NewChainDB(database)

	// Create only block 1 (blocks 2 and 3 do not exist).
	header := &L2Header{
		Number:   big.NewInt(1),
		GasLimit: 30_000_000,
		BaseFee:  new(big.Int),
	}
	blk := NewBlock(header, nil, nil)
	receipts := []*types.Receipt{
		{
			Status:            types.ReceiptStatusSuccessful,
			CumulativeGasUsed: 21000,
			Logs:              []*types.Log{},
		},
	}
	if err := chainDB.WriteBlock(blk, receipts); err != nil {
		t.Fatalf("WriteBlock failed: %v", err)
	}

	// Marking range 1-3 should not error even though blocks 2-3 don't exist.
	err := chainDB.MarkReceiptsRolledBack(1, 3, 0)
	if err != nil {
		t.Fatalf("MarkReceiptsRolledBack with missing blocks should not error, got: %v", err)
	}

	// Block 1 receipts should be marked as rolled back.
	hash1 := chainDB.ReadCanonicalHash(1)
	receipts1 := chainDB.ReadReceipts(hash1, 1)
	if receipts1 == nil {
		t.Fatal("block 1 receipts should exist")
	}
	if !receipts1[0].RolledBack {
		t.Error("block 1 receipt should be rolled back")
	}
}

// --- SyncCheckpoint tests ---

func TestChainDB_WriteReadSyncCheckpoint(t *testing.T) {
	database := db.NewMemoryDB()
	chainDB := NewChainDB(database)

	txid := types.HexToHash("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	cp := &SyncCheckpoint{
		CovenantTxID: txid,
		L2BlockNum:   1000,
	}

	if err := chainDB.WriteSyncCheckpoint(cp); err != nil {
		t.Fatalf("WriteSyncCheckpoint failed: %v", err)
	}

	loaded := chainDB.ReadSyncCheckpoint()
	if loaded == nil {
		t.Fatal("ReadSyncCheckpoint returned nil after write")
	}
	if loaded.CovenantTxID != cp.CovenantTxID {
		t.Errorf("CovenantTxID: got %s, want %s", loaded.CovenantTxID.Hex(), cp.CovenantTxID.Hex())
	}
	if loaded.L2BlockNum != cp.L2BlockNum {
		t.Errorf("L2BlockNum: got %d, want %d", loaded.L2BlockNum, cp.L2BlockNum)
	}
}

func TestChainDB_ReadSyncCheckpoint_NotSet(t *testing.T) {
	database := db.NewMemoryDB()
	chainDB := NewChainDB(database)

	cp := chainDB.ReadSyncCheckpoint()
	if cp != nil {
		t.Errorf("expected nil checkpoint, got %+v", cp)
	}
}

// --- Genesis validation tests ---

func TestValidateGenesis_Valid(t *testing.T) {
	g := DefaultGenesis(testChainID)
	if err := ValidateGenesis(g); err != nil {
		t.Fatalf("ValidateGenesis failed on valid genesis: %v", err)
	}
}

func TestValidateGenesis_NilConfig(t *testing.T) {
	g := DefaultGenesis(testChainID)
	g.Config = nil
	if err := ValidateGenesis(g); err == nil {
		t.Fatal("expected error for nil config, got nil")
	}
}

func TestValidateGenesis_InvalidHashFunction(t *testing.T) {
	g := DefaultGenesis(testChainID)
	g.HashFunction = "sha256"
	if err := ValidateGenesis(g); err == nil {
		t.Fatal("expected error for unsupported hash function, got nil")
	}
}

func TestValidateGenesis_EmptyHashFunctionAllowed(t *testing.T) {
	g := DefaultGenesis(testChainID)
	g.HashFunction = ""
	if err := ValidateGenesis(g); err != nil {
		t.Fatalf("empty hash function should be allowed (defaults to keccak256): %v", err)
	}
}

func TestValidateGenesis_Keccak256Allowed(t *testing.T) {
	g := DefaultGenesis(testChainID)
	g.HashFunction = "keccak256"
	if err := ValidateGenesis(g); err != nil {
		t.Fatalf("keccak256 should be allowed: %v", err)
	}
}

func TestDefaultGenesis_HasAllFields(t *testing.T) {
	g := DefaultGenesis(testChainID)
	if g.HashFunction != "keccak256" {
		t.Errorf("HashFunction = %q, want %q", g.HashFunction, "keccak256")
	}
	if g.Config == nil {
		t.Fatal("Config should not be nil")
	}
	if g.Alloc == nil {
		t.Fatal("Alloc should not be nil")
	}
}

func TestInitGenesis_WithNewFields(t *testing.T) {
	database := db.NewMemoryDB()
	g := DefaultGenesis(testChainID)
	g.Coinbase = types.HexToAddress("0x1234567890123456789012345678901234567890")
	g.BridgeAddress = types.HexToAddress("0x4200000000000000000000000000000000000010")
	g.BSVAnchorTxID = types.HexToHash("0xaaaa")

	header, err := InitGenesis(database, g)
	if err != nil {
		t.Fatalf("InitGenesis failed: %v", err)
	}

	// Genesis header coinbase should always be zero address.
	if header.Coinbase != (types.Address{}) {
		t.Errorf("genesis coinbase should be zero address, got %s", header.Coinbase.Hex())
	}
}

func TestBlockExecutionResult(t *testing.T) {
	r := &BlockExecutionResult{
		StateRoot: types.HexToHash("0x1234"),
		Receipts:  []*types.Receipt{{Status: types.ReceiptStatusSuccessful}},
		Logs:      []*types.Log{{Address: types.HexToAddress("0x01")}},
		GasUsed:   21000,
	}
	if r.StateRoot == (types.Hash{}) {
		t.Error("StateRoot should not be zero")
	}
	if len(r.Receipts) != 1 {
		t.Errorf("Receipts length = %d, want 1", len(r.Receipts))
	}
	if len(r.Logs) != 1 {
		t.Errorf("Logs length = %d, want 1", len(r.Logs))
	}
	if r.GasUsed != 21000 {
		t.Errorf("GasUsed = %d, want 21000", r.GasUsed)
	}
}

func TestL2Block_ExportedFields(t *testing.T) {
	header := &L2Header{
		Number:   big.NewInt(1),
		GasLimit: 30_000_000,
		BaseFee:  new(big.Int),
	}
	receipts := []*types.Receipt{
		{Status: types.ReceiptStatusSuccessful, CumulativeGasUsed: 21000},
	}

	block := NewBlock(header, nil, receipts)
	if block.Header == nil {
		t.Fatal("Header field should be accessible")
	}
	if block.Transactions != nil && len(block.Transactions) != 0 {
		t.Errorf("Transactions should be empty, got %d", len(block.Transactions))
	}
	if len(block.Receipts) != 1 {
		t.Errorf("Receipts should have 1 receipt, got %d", len(block.Receipts))
	}
}

func TestMessageValueIsUint256(t *testing.T) {
	msg := &Message{
		Value: uint256.NewInt(42),
	}
	if msg.Value.Uint64() != 42 {
		t.Errorf("Message.Value = %d, want 42", msg.Value.Uint64())
	}
}
