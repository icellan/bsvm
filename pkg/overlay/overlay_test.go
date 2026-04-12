package overlay

import (
	"crypto/ecdsa"
	"math/big"
	"testing"
	"time"

	"github.com/holiman/uint256"

	"github.com/icellan/bsvm/internal/db"
	"github.com/icellan/bsvm/pkg/block"
	"github.com/icellan/bsvm/pkg/covenant"
	"github.com/icellan/bsvm/pkg/crypto"
	"github.com/icellan/bsvm/pkg/prover"
	"github.com/icellan/bsvm/pkg/state"
	"github.com/icellan/bsvm/pkg/types"
	"github.com/icellan/bsvm/pkg/vm"
	"github.com/icellan/bsvm/pkg/vm/tracing"
)

const testChainID = 1337

// testSetup holds all the components needed for overlay node tests.
type testSetup struct {
	node     *OverlayNode
	database db.Database
	chainDB  *block.ChainDB
	key      *ecdsa.PrivateKey
	addr     types.Address
	coinbase types.Address
	signer   types.Signer
	genesis  *block.L2Header
}

// newTestSetup creates a fully initialised overlay node for testing.
// It creates a genesis state with a funded test account.
func newTestSetup(t *testing.T) *testSetup {
	t.Helper()

	// Create a deterministic test key.
	keyBytes := make([]byte, 32)
	keyBytes[31] = 1
	key, err := crypto.ToECDSA(keyBytes)
	if err != nil {
		t.Fatalf("failed to create test key: %v", err)
	}
	addr := types.Address(crypto.PubkeyToAddress(key.PublicKey))

	// Create a coinbase key/address.
	cbKeyBytes := make([]byte, 32)
	cbKeyBytes[31] = 2
	cbKey, err := crypto.ToECDSA(cbKeyBytes)
	if err != nil {
		t.Fatalf("failed to create coinbase key: %v", err)
	}
	coinbase := types.Address(crypto.PubkeyToAddress(cbKey.PublicKey))

	// Create in-memory database.
	database := db.NewMemoryDB()

	// Initialise genesis with a funded account.
	genesis := &block.Genesis{
		Config:    vm.DefaultL2Config(testChainID),
		Timestamp: uint64(time.Now().Unix()),
		GasLimit:  30_000_000,
		Alloc: map[types.Address]block.GenesisAccount{
			addr: {
				Balance: uint256.NewInt(1_000_000_000_000_000_000), // 1 ETH
			},
		},
	}

	genesisHeader, err := block.InitGenesis(database, genesis)
	if err != nil {
		t.Fatalf("failed to init genesis: %v", err)
	}

	// Create the overlay config.
	config := DefaultOverlayConfig()
	config.ChainID = testChainID
	config.Coinbase = coinbase
	config.MaxBatchFlushDelay = 100 * time.Millisecond // faster for tests

	// Create a mock prover.
	sp1Prover := prover.NewSP1Prover(prover.DefaultConfig())

	// Create the covenant manager.
	compiledCovenant := &covenant.CompiledCovenant{}
	initialState := covenant.CovenantState{
		StateRoot:   genesisHeader.StateRoot,
		BlockNumber: 0,
	}
	covenantMgr := covenant.NewCovenantManager(
		compiledCovenant,
		types.Hash{},
		0,
		10000,
		initialState,
		testChainID,
		covenant.VerifyGroth16,
	)

	// Create the chain database.
	chainDB := block.NewChainDB(database)

	// Create the overlay node.
	node, err := NewOverlayNode(config, chainDB, database, covenantMgr, sp1Prover)
	if err != nil {
		t.Fatalf("failed to create overlay node: %v", err)
	}

	return &testSetup{
		node:     node,
		database: database,
		chainDB:  chainDB,
		key:      key,
		addr:     addr,
		coinbase: coinbase,
		signer:   types.LatestSignerForChainID(big.NewInt(testChainID)),
		genesis:  genesisHeader,
	}
}

// signTx creates and signs a legacy transfer transaction.
func (ts *testSetup) signTx(t *testing.T, nonce uint64, to types.Address, value *uint256.Int, gasPrice *big.Int) *types.Transaction {
	t.Helper()
	if gasPrice == nil {
		gasPrice = big.NewInt(1_000_000_000) // 1 gwei
	}
	tx := types.MustSignNewTx(ts.key, ts.signer, &types.LegacyTx{
		Nonce:    nonce,
		GasPrice: gasPrice,
		Gas:      21000,
		To:       &to,
		Value:    value,
	})
	return tx
}

// --- TestOverlayNodeCreation ---

func TestOverlayNodeCreation(t *testing.T) {
	ts := newTestSetup(t)
	defer ts.node.Stop()

	// Verify initial state.
	if ts.node.ExecutionTip() != 0 {
		t.Errorf("expected execution tip 0, got %d", ts.node.ExecutionTip())
	}
	if ts.node.ProvenTip() != 0 {
		t.Errorf("expected proven tip 0, got %d", ts.node.ProvenTip())
	}
	if ts.node.FinalizedTip() != 0 {
		t.Errorf("expected finalized tip 0, got %d", ts.node.FinalizedTip())
	}

	// Verify the batcher exists and has no pending.
	if ts.node.Batcher().PendingCount() != 0 {
		t.Errorf("expected 0 pending txs, got %d", ts.node.Batcher().PendingCount())
	}

	// Verify gas price oracle is configured.
	suggested := ts.node.GasPriceOracleRef().SuggestGasPrice()
	if suggested.Cmp(big.NewInt(1_000_000_000)) != 0 {
		t.Errorf("expected suggested gas price 1 gwei, got %s", suggested)
	}

	// Verify the state has the funded account.
	balance := ts.node.StateDB().GetBalance(ts.addr)
	expected := uint256.NewInt(1_000_000_000_000_000_000)
	if balance.Cmp(expected) != 0 {
		t.Errorf("expected balance %s, got %s", expected, balance)
	}
}

// --- TestSubmitTransaction ---

func TestSubmitTransaction(t *testing.T) {
	ts := newTestSetup(t)
	defer ts.node.Stop()

	// Create a valid transfer transaction.
	recipient := types.HexToAddress("0x1234567890abcdef1234567890abcdef12345678")
	tx := ts.signTx(t, 0, recipient, uint256.NewInt(1000), nil)

	// Submit the transaction.
	err := ts.node.SubmitTransaction(tx)
	if err != nil {
		t.Fatalf("failed to submit transaction: %v", err)
	}

	// Verify it's in the batcher.
	if ts.node.Batcher().PendingCount() != 1 {
		t.Errorf("expected 1 pending tx, got %d", ts.node.Batcher().PendingCount())
	}
}

// --- TestSubmitTransactionValidation ---

func TestSubmitTransactionValidation(t *testing.T) {
	ts := newTestSetup(t)
	defer ts.node.Stop()

	recipient := types.HexToAddress("0x1234567890abcdef1234567890abcdef12345678")

	t.Run("bad nonce", func(t *testing.T) {
		// Nonce too high (expected 0, sending with nonce 5).
		tx := ts.signTx(t, 5, recipient, uint256.NewInt(1000), nil)
		err := ts.node.SubmitTransaction(tx)
		if err == nil {
			t.Fatal("expected error for bad nonce")
		}
	})

	t.Run("insufficient balance", func(t *testing.T) {
		// Try to send more than the balance.
		bigValue := new(uint256.Int).Mul(
			uint256.NewInt(1_000_000_000_000_000_000),
			uint256.NewInt(1000),
		)
		tx := ts.signTx(t, 0, recipient, bigValue, nil)
		err := ts.node.SubmitTransaction(tx)
		if err == nil {
			t.Fatal("expected error for insufficient balance")
		}
	})

	t.Run("gas price too low", func(t *testing.T) {
		tx := ts.signTx(t, 0, recipient, uint256.NewInt(1000), big.NewInt(1)) // 1 wei
		err := ts.node.SubmitTransaction(tx)
		if err == nil {
			t.Fatal("expected error for low gas price")
		}
	})

	t.Run("gas limit exceeds block limit", func(t *testing.T) {
		// Create a tx with gas > block gas limit.
		tx := types.MustSignNewTx(ts.key, ts.signer, &types.LegacyTx{
			Nonce:    0,
			GasPrice: big.NewInt(1_000_000_000),
			Gas:      100_000_000, // exceeds 30M block gas limit
			To:       &recipient,
			Value:    uint256.NewInt(1000),
		})
		err := ts.node.SubmitTransaction(tx)
		if err == nil {
			t.Fatal("expected error for excessive gas limit")
		}
	})
}

// --- TestBatcherFlush ---

func TestBatcherFlush(t *testing.T) {
	ts := newTestSetup(t)
	defer ts.node.Stop()

	recipient := types.HexToAddress("0x1234567890abcdef1234567890abcdef12345678")
	tx := ts.signTx(t, 0, recipient, uint256.NewInt(1000), nil)

	// Add a transaction.
	err := ts.node.batcher.Add(tx)
	if err != nil {
		t.Fatalf("failed to add tx: %v", err)
	}

	if ts.node.batcher.PendingCount() != 1 {
		t.Fatalf("expected 1 pending, got %d", ts.node.batcher.PendingCount())
	}

	// Flush manually.
	err = ts.node.batcher.Flush()
	if err != nil {
		t.Fatalf("flush failed: %v", err)
	}

	// Verify the batch was processed: execution tip should advance.
	if ts.node.ExecutionTip() != 1 {
		t.Errorf("expected execution tip 1, got %d", ts.node.ExecutionTip())
	}

	// Pending should be empty.
	if ts.node.batcher.PendingCount() != 0 {
		t.Errorf("expected 0 pending after flush, got %d", ts.node.batcher.PendingCount())
	}
}

// --- TestBatcherMaxSize ---

func TestBatcherMaxSize(t *testing.T) {
	// Create a setup with a small max batch size.
	ts := newTestSetup(t)
	defer ts.node.Stop()

	// Override max batch size to 3 for testing.
	ts.node.batcher.maxBatchSize = 3

	recipient := types.HexToAddress("0x1234567890abcdef1234567890abcdef12345678")

	// Add 3 transactions (should auto-flush at 3).
	for i := uint64(0); i < 3; i++ {
		tx := ts.signTx(t, i, recipient, uint256.NewInt(1000), nil)
		err := ts.node.batcher.Add(tx)
		if err != nil {
			t.Fatalf("failed to add tx %d: %v", i, err)
		}
	}

	// The batch should have auto-flushed: execution tip should be 1.
	if ts.node.ExecutionTip() != 1 {
		t.Errorf("expected execution tip 1 after auto-flush, got %d", ts.node.ExecutionTip())
	}

	// No pending transactions should remain.
	if ts.node.batcher.PendingCount() != 0 {
		t.Errorf("expected 0 pending after auto-flush, got %d", ts.node.batcher.PendingCount())
	}
}

// --- TestBatcherDedup ---

func TestBatcherDedup(t *testing.T) {
	ts := newTestSetup(t)
	defer ts.node.Stop()

	recipient := types.HexToAddress("0x1234567890abcdef1234567890abcdef12345678")
	tx := ts.signTx(t, 0, recipient, uint256.NewInt(1000), nil)

	// Add the transaction once.
	err := ts.node.batcher.Add(tx)
	if err != nil {
		t.Fatalf("first add failed: %v", err)
	}

	// Add the same transaction again.
	err = ts.node.batcher.Add(tx)
	if err == nil {
		t.Fatal("expected error for duplicate transaction")
	}

	// Only one should be pending.
	if ts.node.batcher.PendingCount() != 1 {
		t.Errorf("expected 1 pending, got %d", ts.node.batcher.PendingCount())
	}
}

// --- TestProcessBatch ---

func TestProcessBatch(t *testing.T) {
	ts := newTestSetup(t)
	defer ts.node.Stop()

	recipient := types.HexToAddress("0x1234567890abcdef1234567890abcdef12345678")

	// Record initial state root.
	initialStateRoot := ts.genesis.StateRoot

	// Create and process a batch with a single transfer.
	tx := ts.signTx(t, 0, recipient, uint256.NewInt(1000), nil)
	result, err := ts.node.ProcessBatch([]*types.Transaction{tx})
	if err != nil {
		t.Fatalf("ProcessBatch failed: %v", err)
	}

	// Verify block was created.
	if result.Block == nil {
		t.Fatal("ProcessBatch returned nil block")
	}
	if result.Block.NumberU64() != 1 {
		t.Errorf("expected block 1, got %d", result.Block.NumberU64())
	}

	// Verify state root changed.
	if result.StateRoot == initialStateRoot {
		t.Error("state root should have changed after transfer")
	}

	// Verify receipts.
	if len(result.Receipts) != 1 {
		t.Fatalf("expected 1 receipt, got %d", len(result.Receipts))
	}
	if result.Receipts[0].Status != types.ReceiptStatusSuccessful {
		t.Error("expected successful receipt")
	}

	// Verify execution tip advanced.
	if ts.node.ExecutionTip() != 1 {
		t.Errorf("expected execution tip 1, got %d", ts.node.ExecutionTip())
	}

	// Verify the proof output exists (mock mode produces a proof).
	if result.ProveOutput == nil {
		t.Error("expected non-nil ProveOutput in mock mode")
	}

	// Verify the tx cache was updated.
	if ts.node.txCache.Len() != 1 {
		t.Errorf("expected 1 tx cache entry, got %d", ts.node.txCache.Len())
	}
}

// --- TestProcessBatchMultipleTxs ---

func TestProcessBatchMultipleTxs(t *testing.T) {
	ts := newTestSetup(t)
	defer ts.node.Stop()

	// Create 3 recipient addresses (avoid low addresses which are precompiles).
	r1 := types.HexToAddress("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	r2 := types.HexToAddress("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	r3 := types.HexToAddress("0xcccccccccccccccccccccccccccccccccccccccc")

	transferAmount := uint256.NewInt(100_000_000_000_000) // 0.0001 ETH

	txs := []*types.Transaction{
		ts.signTx(t, 0, r1, transferAmount, nil),
		ts.signTx(t, 1, r2, transferAmount, nil),
		ts.signTx(t, 2, r3, transferAmount, nil),
	}

	result, err := ts.node.ProcessBatch(txs)
	if err != nil {
		t.Fatalf("ProcessBatch failed: %v", err)
	}

	// All 3 receipts should be successful.
	if len(result.Receipts) != 3 {
		t.Fatalf("expected 3 receipts, got %d", len(result.Receipts))
	}
	for i, r := range result.Receipts {
		if r.Status != types.ReceiptStatusSuccessful {
			t.Errorf("receipt %d: expected success, got status %d", i, r.Status)
		}
	}

	// Verify recipient balances in the new state.
	// We need to read from the state after commit. Open state at new root.
	newState, err := state.New(result.StateRoot, ts.database)
	if err != nil {
		t.Fatalf("failed to open state at new root: %v", err)
	}

	for i, addr := range []types.Address{r1, r2, r3} {
		bal := newState.GetBalance(addr)
		if bal.Cmp(transferAmount) != 0 {
			t.Errorf("recipient %d balance: expected %s, got %s", i, transferAmount, bal)
		}
	}

	// Verify sender balance decreased.
	senderBal := newState.GetBalance(ts.addr)
	initialBalance := uint256.NewInt(1_000_000_000_000_000_000)
	if senderBal.Cmp(initialBalance) >= 0 {
		t.Error("sender balance should have decreased")
	}
}

// --- TestTxCache ---

func TestTxCache(t *testing.T) {
	cache := NewTxCache(ConfirmedState{
		StateRoot:  types.HexToHash("0xabc"),
		L2BlockNum: 0,
	})

	// Initially empty.
	if cache.Len() != 0 {
		t.Errorf("expected len 0, got %d", cache.Len())
	}

	// Tip should return confirmed state.
	root, num := cache.Tip()
	if num != 0 {
		t.Errorf("expected tip block 0, got %d", num)
	}
	if root != types.HexToHash("0xabc") {
		t.Errorf("expected tip root 0xabc, got %s", root.Hex())
	}

	// Append entries.
	cache.Append(&CachedTx{
		L2BlockNum: 1,
		StateRoot:  types.HexToHash("0x111"),
		BatchData:  []byte("batch1"),
	})
	cache.Append(&CachedTx{
		L2BlockNum: 2,
		StateRoot:  types.HexToHash("0x222"),
		BatchData:  []byte("batch2"),
	})
	cache.Append(&CachedTx{
		L2BlockNum: 3,
		StateRoot:  types.HexToHash("0x333"),
		BatchData:  []byte("batch3"),
	})

	if cache.Len() != 3 {
		t.Errorf("expected len 3, got %d", cache.Len())
	}

	// Tip should be block 3.
	root, num = cache.Tip()
	if num != 3 {
		t.Errorf("expected tip block 3, got %d", num)
	}
	if root != types.HexToHash("0x333") {
		t.Errorf("expected tip root 0x333, got %s", root.Hex())
	}

	// Confirm up to block 2.
	cache.Confirm(2)

	// Chain should have only block 3 left.
	if cache.Len() != 1 {
		t.Errorf("expected len 1, got %d", cache.Len())
	}

	// Confirmed tip should be block 2.
	confirmed := cache.ConfirmedTip()
	if confirmed.L2BlockNum != 2 {
		t.Errorf("expected confirmed block 2, got %d", confirmed.L2BlockNum)
	}
	if confirmed.StateRoot != types.HexToHash("0x222") {
		t.Errorf("expected confirmed root 0x222, got %s", confirmed.StateRoot.Hex())
	}

	// Tip should still be block 3 (unconfirmed).
	root, num = cache.Tip()
	if num != 3 {
		t.Errorf("expected tip block 3, got %d", num)
	}
}

// --- TestTxCacheSpeculativeDepth ---

func TestTxCacheSpeculativeDepth(t *testing.T) {
	cache := NewTxCache(ConfirmedState{
		StateRoot:  types.HexToHash("0x00"),
		L2BlockNum: 0,
	})

	// Initially zero.
	if depth := cache.SpeculativeDepth(); depth != 0 {
		t.Errorf("expected speculative depth 0, got %d", depth)
	}

	// Add 5 unconfirmed entries.
	for i := uint64(1); i <= 5; i++ {
		cache.Append(&CachedTx{
			L2BlockNum: i,
			StateRoot:  types.HexToHash("0x01"),
		})
	}

	if depth := cache.SpeculativeDepth(); depth != 5 {
		t.Errorf("expected speculative depth 5, got %d", depth)
	}

	// Confirm 2.
	cache.Confirm(2)
	if depth := cache.SpeculativeDepth(); depth != 3 {
		t.Errorf("expected speculative depth 3, got %d", depth)
	}

	// Mark block 3 as confirmed explicitly.
	entry := cache.GetByL2Block(3)
	if entry != nil {
		entry.Confirmed = true
	}
	if depth := cache.SpeculativeDepth(); depth != 2 {
		t.Errorf("expected speculative depth 2, got %d", depth)
	}
}

// --- TestGasPriceOracle ---

func TestGasPriceOracle(t *testing.T) {
	oracle := NewGasPriceOracle(big.NewInt(1_000_000_000)) // 1 gwei

	// SuggestGasPrice should return the minimum.
	suggested := oracle.SuggestGasPrice()
	if suggested.Cmp(big.NewInt(1_000_000_000)) != 0 {
		t.Errorf("expected 1 gwei, got %s", suggested)
	}

	// MinGasPrice should return the configured value.
	min := oracle.MinGasPrice()
	if min.Cmp(big.NewInt(1_000_000_000)) != 0 {
		t.Errorf("expected min gas price 1 gwei, got %s", min)
	}

	t.Run("valid gas price", func(t *testing.T) {
		tx := types.NewTx(&types.LegacyTx{
			GasPrice: big.NewInt(2_000_000_000), // 2 gwei
			Gas:      21000,
			Value:    uint256.NewInt(0),
		})
		if err := oracle.ValidateGasPrice(tx); err != nil {
			t.Errorf("expected valid gas price, got error: %v", err)
		}
	})

	t.Run("exactly minimum gas price", func(t *testing.T) {
		tx := types.NewTx(&types.LegacyTx{
			GasPrice: big.NewInt(1_000_000_000), // exactly 1 gwei
			Gas:      21000,
			Value:    uint256.NewInt(0),
		})
		if err := oracle.ValidateGasPrice(tx); err != nil {
			t.Errorf("expected valid gas price at minimum, got error: %v", err)
		}
	})

	t.Run("gas price too low", func(t *testing.T) {
		tx := types.NewTx(&types.LegacyTx{
			GasPrice: big.NewInt(100), // well below 1 gwei
			Gas:      21000,
			Value:    uint256.NewInt(0),
		})
		if err := oracle.ValidateGasPrice(tx); err == nil {
			t.Error("expected error for gas price below minimum")
		}
	})

	t.Run("nil gas price oracle default", func(t *testing.T) {
		defaultOracle := NewGasPriceOracle(nil)
		if defaultOracle.MinGasPrice().Cmp(big.NewInt(1_000_000_000)) != 0 {
			t.Errorf("expected default min gas price 1 gwei, got %s", defaultOracle.MinGasPrice())
		}
	})
}

// --- TestRollback ---

func TestRollback(t *testing.T) {
	ts := newTestSetup(t)
	defer ts.node.Stop()

	recipient := types.HexToAddress("0x1234567890abcdef1234567890abcdef12345678")
	transferAmount := uint256.NewInt(10_000_000_000_000) // 0.00001 ETH

	// Execute 3 blocks.
	var stateRoots [4]types.Hash // [0]=genesis, [1]=block1, [2]=block2, [3]=block3
	stateRoots[0] = ts.genesis.StateRoot

	for i := uint64(0); i < 3; i++ {
		tx := ts.signTx(t, i, recipient, transferAmount, nil)
		result, err := ts.node.ProcessBatch([]*types.Transaction{tx})
		if err != nil {
			t.Fatalf("ProcessBatch %d failed: %v", i+1, err)
		}
		stateRoots[i+1] = result.StateRoot
	}

	// Verify we're at block 3.
	if ts.node.ExecutionTip() != 3 {
		t.Fatalf("expected execution tip 3, got %d", ts.node.ExecutionTip())
	}

	// Rollback to block 1.
	err := ts.node.Rollback(1)
	if err != nil {
		t.Fatalf("Rollback failed: %v", err)
	}

	// Verify execution tip is now 1.
	if ts.node.ExecutionTip() != 1 {
		t.Errorf("expected execution tip 1 after rollback, got %d", ts.node.ExecutionTip())
	}

	// Verify the state root matches block 1's state root.
	currentRoot := ts.node.StateDB().IntermediateRoot(true) // always true: post-Spurious Dragon
	if currentRoot != stateRoots[1] {
		t.Errorf("expected state root %s after rollback, got %s",
			stateRoots[1].Hex(), currentRoot.Hex())
	}

	// Verify the tx cache was truncated.
	if ts.node.txCache.Len() != 1 {
		t.Errorf("expected 1 tx cache entry after rollback, got %d", ts.node.txCache.Len())
	}

	// Verify rollback to current block is a no-op.
	err = ts.node.Rollback(1)
	if err != nil {
		t.Errorf("rollback to current block should be no-op, got error: %v", err)
	}

	// Verify rollback forward fails.
	err = ts.node.Rollback(10)
	if err == nil {
		t.Error("expected error when rolling back forward")
	}
}

// --- TestDoubleSpendMonitorCreation ---

func TestDoubleSpendMonitorCreation(t *testing.T) {
	ts := newTestSetup(t)
	defer ts.node.Stop()

	monitor := ts.node.DSMonitor()
	if monitor == nil {
		t.Fatal("expected non-nil double-spend monitor")
	}

	// In single-node mode, CheckForConflict should always return nil.
	result, err := monitor.CheckForConflict(types.HexToHash("0xdeadbeef"))
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if result != nil {
		t.Error("expected nil result in single-node mode")
	}
}

// --- TestTxCacheTruncate ---

func TestTxCacheTruncate(t *testing.T) {
	cache := NewTxCache(ConfirmedState{
		StateRoot:  types.HexToHash("0x00"),
		L2BlockNum: 0,
	})

	for i := uint64(1); i <= 5; i++ {
		cache.Append(&CachedTx{
			L2BlockNum: i,
			StateRoot:  types.HexToHash("0x01"),
		})
	}

	if cache.Len() != 5 {
		t.Fatalf("expected len 5, got %d", cache.Len())
	}

	// Truncate after block 3: should remove blocks 4 and 5.
	cache.Truncate(3)

	if cache.Len() != 3 {
		t.Errorf("expected len 3 after truncate, got %d", cache.Len())
	}

	// Tip should be block 3.
	_, num := cache.Tip()
	if num != 3 {
		t.Errorf("expected tip block 3, got %d", num)
	}

	// Block 4 should not be found.
	if entry := cache.GetByL2Block(4); entry != nil {
		t.Error("expected block 4 to not be found after truncate")
	}

	// Truncate beyond all entries.
	cache.Truncate(10)
	if cache.Len() != 3 {
		t.Errorf("truncating beyond chain should be no-op, got len %d", cache.Len())
	}
}

// --- TestBatcherStop ---

func TestBatcherStop(t *testing.T) {
	ts := newTestSetup(t)

	// Stop the batcher.
	ts.node.batcher.Stop()

	// Adding a transaction should fail.
	recipient := types.HexToAddress("0x1234567890abcdef1234567890abcdef12345678")
	tx := ts.signTx(t, 0, recipient, uint256.NewInt(1000), nil)
	err := ts.node.batcher.Add(tx)
	if err == nil {
		t.Fatal("expected error after batcher stop")
	}
}

// --- TestProcessBatchEmpty ---

func TestProcessBatchEmpty(t *testing.T) {
	ts := newTestSetup(t)
	defer ts.node.Stop()

	// Processing an empty batch should error.
	_, err := ts.node.ProcessBatch(nil)
	if err == nil {
		t.Fatal("expected error for empty batch")
	}

	_, err = ts.node.ProcessBatch([]*types.Transaction{})
	if err == nil {
		t.Fatal("expected error for empty batch")
	}
}

// --- TestOverlayNodeEventFeed ---

func TestOverlayNodeEventFeed(t *testing.T) {
	ts := newTestSetup(t)
	defer ts.node.Stop()

	// Subscribe to new head events.
	ch := make(chan NewHeadEvent, 1)
	sub := ts.node.EventFeed().Subscribe(ch)
	defer sub.Unsubscribe()

	// Process a batch.
	recipient := types.HexToAddress("0x1234567890abcdef1234567890abcdef12345678")
	tx := ts.signTx(t, 0, recipient, uint256.NewInt(1000), nil)

	_, err := ts.node.ProcessBatch([]*types.Transaction{tx})
	if err != nil {
		t.Fatalf("ProcessBatch failed: %v", err)
	}

	// Check that an event was emitted.
	select {
	case event := <-ch:
		if event.Block == nil {
			t.Error("expected non-nil block in event")
		}
		if event.Block.NumberU64() != 1 {
			t.Errorf("expected block 1 in event, got %d", event.Block.NumberU64())
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for new head event")
	}
}

// --- TestMultipleBlocksSequential ---

func TestMultipleBlocksSequential(t *testing.T) {
	ts := newTestSetup(t)
	defer ts.node.Stop()

	recipient := types.HexToAddress("0x1234567890abcdef1234567890abcdef12345678")
	transferAmount := uint256.NewInt(1000)

	// Process 5 sequential blocks, each with 1 transaction.
	for i := uint64(0); i < 5; i++ {
		tx := ts.signTx(t, i, recipient, transferAmount, nil)
		result, err := ts.node.ProcessBatch([]*types.Transaction{tx})
		if err != nil {
			t.Fatalf("ProcessBatch %d failed: %v", i+1, err)
		}
		if result.Block.NumberU64() != i+1 {
			t.Errorf("expected block %d, got %d", i+1, result.Block.NumberU64())
		}
	}

	// Verify execution tip.
	if ts.node.ExecutionTip() != 5 {
		t.Errorf("expected execution tip 5, got %d", ts.node.ExecutionTip())
	}

	// Verify tx cache has 5 entries.
	if ts.node.txCache.Len() != 5 {
		t.Errorf("expected 5 tx cache entries, got %d", ts.node.txCache.Len())
	}

	// Verify block chain is linked.
	for i := uint64(1); i <= 5; i++ {
		header := ts.chainDB.ReadHeaderByNumber(i)
		if header == nil {
			t.Fatalf("header for block %d not found", i)
		}
		if i > 1 {
			parentHeader := ts.chainDB.ReadHeaderByNumber(i - 1)
			if parentHeader == nil {
				t.Fatalf("parent header for block %d not found", i)
			}
			if header.ParentHash != parentHeader.Hash() {
				t.Errorf("block %d parent hash mismatch", i)
			}
		}
	}
}

// --- TestConfigDefaults ---

func TestConfigDefaults(t *testing.T) {
	config := DefaultOverlayConfig()

	if config.BlockGasLimit != 30_000_000 {
		t.Errorf("expected block gas limit 30M, got %d", config.BlockGasLimit)
	}
	if config.MaxBatchSize != 128 {
		t.Errorf("expected max batch size 128, got %d", config.MaxBatchSize)
	}
	if config.MaxBatchFlushDelay != 2*time.Second {
		t.Errorf("expected flush delay 2s, got %v", config.MaxBatchFlushDelay)
	}
	if config.MinGasPrice.Cmp(big.NewInt(1_000_000_000)) != 0 {
		t.Errorf("expected min gas price 1 gwei, got %s", config.MinGasPrice)
	}
	if config.MaxSpeculativeDepth != 16 {
		t.Errorf("expected max speculative depth 16, got %d", config.MaxSpeculativeDepth)
	}
	if config.ChainID != 1 {
		t.Errorf("expected chain ID 1, got %d", config.ChainID)
	}
}

// --- TestProcessBatchInboxRoots ---

func TestProcessBatchInboxRoots(t *testing.T) {
	ts := newTestSetup(t)
	defer ts.node.Stop()

	// Verify the inbox monitor is initialized.
	if ts.node.InboxMonitor() == nil {
		t.Fatal("expected non-nil inbox monitor")
	}

	// Get the initial inbox hash (empty queue hash).
	initialHash := ts.node.InboxMonitor().QueueHash()
	if initialHash == (types.Hash{}) {
		t.Error("initial inbox hash should not be zero (it's hash256 of zeros)")
	}

	// Process a batch. The inbox roots in the prove input should be
	// populated from the InboxMonitor's QueueHash.
	recipient := types.HexToAddress("0x1234567890abcdef1234567890abcdef12345678")
	tx := ts.signTx(t, 0, recipient, uint256.NewInt(1000), nil)

	result, err := ts.node.ProcessBatch([]*types.Transaction{tx})
	if err != nil {
		t.Fatalf("ProcessBatch failed: %v", err)
	}

	// Verify batch was processed.
	if result.Block == nil {
		t.Fatal("expected non-nil block")
	}
	if result.Block.NumberU64() != 1 {
		t.Errorf("expected block 1, got %d", result.Block.NumberU64())
	}

	// Verify proof output exists (mock mode).
	if result.ProveOutput == nil {
		t.Fatal("expected non-nil ProveOutput in mock mode")
	}

	// Parse the public values and verify inbox roots are present.
	pv, err := prover.ParsePublicValues(result.ProveOutput.PublicValues)
	if err != nil {
		t.Fatalf("ParsePublicValues: %v", err)
	}

	// In this test, no inbox transactions were added, so both roots
	// should be the same (the initial empty queue hash).
	if pv.InboxRootBefore != initialHash {
		t.Errorf("InboxRootBefore mismatch: got %s, want %s",
			pv.InboxRootBefore.Hex(), initialHash.Hex())
	}
	if pv.InboxRootAfter != initialHash {
		t.Errorf("InboxRootAfter mismatch: got %s, want %s",
			pv.InboxRootAfter.Hex(), initialHash.Hex())
	}

	// Now add an inbox transaction and verify the hash changes.
	ts.node.InboxMonitor().AddInboxTransaction([]byte{0x01, 0x02, 0x03})
	newHash := ts.node.InboxMonitor().QueueHash()
	if newHash == initialHash {
		t.Error("inbox hash should change after adding a transaction")
	}
}

func TestBatcherPauseResume(t *testing.T) {
	ts := newTestSetup(t)
	defer ts.node.Stop()

	batcher := ts.node.Batcher()

	// Initially not paused.
	if batcher.IsPaused() {
		t.Error("batcher should not be paused initially")
	}

	// Pause.
	batcher.Pause()
	if !batcher.IsPaused() {
		t.Error("batcher should be paused after Pause()")
	}

	// Adding a transaction while paused should fail.
	recipient := types.HexToAddress("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	tx := ts.signTx(t, 0, recipient, uint256.NewInt(1000), nil)
	err := batcher.Add(tx)
	if err == nil {
		t.Error("expected error when adding tx to paused batcher")
	}

	// Resume.
	batcher.Resume()
	if batcher.IsPaused() {
		t.Error("batcher should not be paused after Resume()")
	}

	// Adding a transaction after resume should succeed.
	err = batcher.Add(tx)
	if err != nil {
		t.Errorf("unexpected error after resume: %v", err)
	}
}

func TestGovernanceMonitor(t *testing.T) {
	ts := newTestSetup(t)
	defer ts.node.Stop()

	gm := NewGovernanceMonitor(ts.node)

	// Initial state is active.
	if gm.State() != GovernanceActive {
		t.Errorf("initial state = %v, want active", gm.State())
	}

	// Freeze.
	gm.HandleGovernanceFreeze()
	if gm.State() != GovernanceFrozen {
		t.Errorf("state after freeze = %v, want frozen", gm.State())
	}
	// Batcher should be paused.
	if !ts.node.Batcher().IsPaused() {
		t.Error("batcher should be paused after governance freeze")
	}

	// Double freeze is a no-op.
	gm.HandleGovernanceFreeze()
	if gm.State() != GovernanceFrozen {
		t.Error("double freeze should remain frozen")
	}

	// Unfreeze.
	gm.HandleGovernanceUnfreeze()
	if gm.State() != GovernanceActive {
		t.Errorf("state after unfreeze = %v, want active", gm.State())
	}
	// Batcher should be resumed.
	if ts.node.Batcher().IsPaused() {
		t.Error("batcher should be resumed after governance unfreeze")
	}

	// Upgrade requires freeze first.
	gm.HandleGovernanceUpgrade([32]byte{1, 2, 3})
	if gm.State() != GovernanceActive {
		t.Error("upgrade should be rejected when not frozen")
	}

	// Freeze then upgrade.
	gm.HandleGovernanceFreeze()
	gm.HandleGovernanceUpgrade([32]byte{1, 2, 3})
	if gm.State() != GovernanceUpgrading {
		t.Errorf("state after freeze+upgrade = %v, want upgrading", gm.State())
	}
}

func TestOverlayConfig_NewFields(t *testing.T) {
	cfg := DefaultOverlayConfig()

	if cfg.TargetBatchSize != 128 {
		t.Errorf("TargetBatchSize = %d, want 128", cfg.TargetBatchSize)
	}
	if cfg.MinBatchSize != 1 {
		t.Errorf("MinBatchSize = %d, want 1", cfg.MinBatchSize)
	}
	if cfg.MinProfitableBatchGas != 0 {
		t.Errorf("MinProfitableBatchGas = %d, want 0", cfg.MinProfitableBatchGas)
	}
}

func TestConfirmedTip(t *testing.T) {
	ts := newTestSetup(t)
	defer ts.node.Stop()

	// Initially 0.
	if ts.node.ConfirmedTip() != 0 {
		t.Errorf("ConfirmedTip = %d, want 0", ts.node.ConfirmedTip())
	}

	// Set confirmed tip.
	ts.node.SetConfirmedTip(5)
	if ts.node.ConfirmedTip() != 5 {
		t.Errorf("ConfirmedTip = %d, want 5", ts.node.ConfirmedTip())
	}
}

// --- Ensure unused imports are used ---

// Verify tracing is used (it's needed for genesis balance allocation).
var _ = tracing.BalanceIncreaseDeposit
