package overlay

import (
	"math/big"
	"testing"
	"time"

	"github.com/holiman/uint256"

	"github.com/icellan/bsvm/internal/db"
	"github.com/icellan/bsvm/pkg/block"
	"github.com/icellan/bsvm/pkg/crypto"
	"github.com/icellan/bsvm/pkg/state"
	"github.com/icellan/bsvm/pkg/types"
	"github.com/icellan/bsvm/pkg/vm"
)

func TestExecutionVerifier_VerifyCovenantAdvance(t *testing.T) {
	// Set up genesis state with a funded account.
	keyBytes := make([]byte, 32)
	keyBytes[31] = 1
	key, err := crypto.ToECDSA(keyBytes)
	if err != nil {
		t.Fatalf("failed to create test key: %v", err)
	}
	addr := types.Address(crypto.PubkeyToAddress(key.PublicKey))
	coinbase := types.Address{0xCC}

	database := db.NewMemoryDB()
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

	chainDB := block.NewChainDB(database)
	chainConfig := vm.DefaultL2Config(testChainID)
	executor := block.NewBlockExecutor(chainConfig, vm.Config{})
	signer := types.LatestSignerForChainID(big.NewInt(testChainID))

	// Build a batch: one simple transfer.
	tx := types.MustSignNewTx(key, signer, &types.LegacyTx{
		Nonce:    0,
		GasPrice: big.NewInt(1_000_000_000),
		Gas:      21000,
		To:       &coinbase,
		Value:    uint256.NewInt(1000),
	})

	// Execute the batch to get the correct post-state root.
	statedb, err := state.New(genesisHeader.StateRoot, database)
	if err != nil {
		t.Fatalf("failed to open state: %v", err)
	}

	timestamp := uint64(time.Now().Unix())
	l2Block, _, err := executor.ProcessBatch(
		genesisHeader, coinbase, timestamp,
		[]*types.Transaction{tx}, statedb,
		&verifierChainContext{chainDB: chainDB},
	)
	if err != nil {
		t.Fatalf("batch execution failed: %v", err)
	}

	postStateRoot := l2Block.StateRoot()

	// Write the block so the parent lookup works during verification.
	if err := chainDB.WriteBlock(l2Block, nil); err != nil {
		t.Fatalf("failed to write block: %v", err)
	}

	// Encode the batch data.
	var rlpTxs [][]byte
	for _, btx := range l2Block.Transactions {
		w := &bytesWriter{}
		if err := btx.EncodeRLP(w); err != nil {
			t.Fatalf("failed to encode tx: %v", err)
		}
		rlpTxs = append(rlpTxs, w.Bytes())
	}

	batchData, err := block.EncodeBatchData(&block.BatchData{
		Version:      block.BatchVersion,
		Timestamp:    timestamp,
		Coinbase:     coinbase,
		ParentHash:   genesisHeader.Hash(),
		Transactions: rlpTxs,
	})
	if err != nil {
		t.Fatalf("failed to encode batch data: %v", err)
	}

	// Create the verifier.
	verifier := NewExecutionVerifier(executor, database, chainDB)

	// Test: correct state root should pass.
	advance := &CovenantAdvanceEvent{
		BSVTxID:       types.Hash{0x01},
		L2BlockNum:    1,
		PostStateRoot: postStateRoot,
		BatchData:     batchData,
		IsOurs:        false,
	}

	if err := verifier.VerifyCovenantAdvance(advance); err != nil {
		t.Errorf("expected verification to pass, got error: %v", err)
	}

	// Test: incorrect state root should fail.
	badAdvance := &CovenantAdvanceEvent{
		BSVTxID:       types.Hash{0x02},
		L2BlockNum:    1,
		PostStateRoot: types.Hash{0xFF}, // wrong
		BatchData:     batchData,
		IsOurs:        false,
	}

	if err := verifier.VerifyCovenantAdvance(badAdvance); err == nil {
		t.Error("expected verification to fail for incorrect state root")
	}

	// Test: nil advance should fail.
	if err := verifier.VerifyCovenantAdvance(nil); err == nil {
		t.Error("expected error for nil advance")
	}

	// Test: empty batch data should fail.
	emptyAdvance := &CovenantAdvanceEvent{
		BSVTxID:       types.Hash{0x03},
		L2BlockNum:    1,
		PostStateRoot: postStateRoot,
		BatchData:     nil,
	}
	if err := verifier.VerifyCovenantAdvance(emptyAdvance); err == nil {
		t.Error("expected error for empty batch data")
	}
}
