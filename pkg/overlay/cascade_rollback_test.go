package overlay

import (
	"math/big"
	"testing"
	"time"

	"github.com/holiman/uint256"

	"github.com/icellan/bsvm/pkg/block"
	"github.com/icellan/bsvm/pkg/rlp"
	"github.com/icellan/bsvm/pkg/state"
	"github.com/icellan/bsvm/pkg/types"
)

// TestOverlayNode_CascadeRollback performs a full cascade rollback test:
// process 3 blocks, then simulate losing a race at block 2 with a different
// winner batch. Verify state is rolled back and the winner's batch is replayed.
func TestOverlayNode_CascadeRollback(t *testing.T) {
	ts := newTestSetup(t)
	defer ts.node.Stop()

	recipient := types.HexToAddress("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	transferAmount := uint256.NewInt(10_000_000_000_000) // 0.00001 ETH

	// Process block 1.
	tx1 := ts.signTx(t, 0, recipient, transferAmount, nil)
	result1, err := ts.node.ProcessBatch([]*types.Transaction{tx1})
	if err != nil {
		t.Fatalf("ProcessBatch 1 failed: %v", err)
	}
	block1Root := result1.StateRoot

	// Process block 2 with our version.
	tx2 := ts.signTx(t, 1, recipient, transferAmount, nil)
	_, err = ts.node.ProcessBatch([]*types.Transaction{tx2})
	if err != nil {
		t.Fatalf("ProcessBatch 2 failed: %v", err)
	}

	// Process block 3.
	tx3 := ts.signTx(t, 2, recipient, transferAmount, nil)
	_, err = ts.node.ProcessBatch([]*types.Transaction{tx3})
	if err != nil {
		t.Fatalf("ProcessBatch 3 failed: %v", err)
	}

	if ts.node.ExecutionTip() != 3 {
		t.Fatalf("expected execution tip 3, got %d", ts.node.ExecutionTip())
	}

	// Now simulate losing a race at block 2. Another node's block 2
	// contained a different transaction (a transfer to a different recipient).
	// We need to build the winner's batch data.
	winnerRecipient := types.HexToAddress("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")

	// To create a valid winner batch, we need to re-execute from block 1
	// state using a different transaction. First, get block 1's header.
	block1Header := ts.chainDB.ReadHeaderByNumber(1)
	if block1Header == nil {
		t.Fatal("block 1 header not found")
	}

	// Create the winner's transaction: same sender, nonce 1, different recipient.
	winnerTx := ts.signTx(t, 1, winnerRecipient, transferAmount, nil)

	// RLP-encode the winner's transaction.
	var winnerTxRLP []byte
	{
		w := &bytesWriter{}
		if err := winnerTx.EncodeRLP(w); err != nil {
			t.Fatalf("failed to encode winner tx: %v", err)
		}
		winnerTxRLP = w.Bytes()
	}

	// Execute the winner's batch on a fresh state to get the expected
	// post-state root.
	winnerStateDB, err := state.New(block1Root, ts.database)
	if err != nil {
		t.Fatalf("failed to open state at block 1 root: %v", err)
	}

	winnerTimestamp := uint64(time.Now().Unix())
	winnerExecutor := ts.node.executor
	winnerBlock, _, err := winnerExecutor.ProcessBatch(
		block1Header,
		ts.coinbase,
		winnerTimestamp,
		[]*types.Transaction{winnerTx},
		winnerStateDB,
		ts.node,
	)
	if err != nil {
		t.Fatalf("winner batch execution failed: %v", err)
	}

	// Commit the winner state to get the root.
	winnerRoot, err := winnerStateDB.Commit(true)
	if err != nil {
		t.Fatalf("winner state commit failed: %v", err)
	}
	_ = winnerBlock

	// Build the winner's batch data.
	batchData := &block.BatchData{
		Version:    block.BatchVersion,
		Timestamp:  winnerTimestamp,
		Coinbase:   ts.coinbase,
		ParentHash: block1Header.Hash(),
		Transactions: [][]byte{
			winnerTxRLP,
		},
	}
	encodedBatch, err := block.EncodeBatchData(batchData)
	if err != nil {
		t.Fatalf("failed to encode winner batch data: %v", err)
	}

	// Create the CovenantAdvanceEvent.
	winnerEvent := &CovenantAdvanceEvent{
		BSVTxID:       types.HexToHash("0xdeadbeef"),
		L2BlockNum:    2,
		PostStateRoot: winnerRoot,
		BatchData:     encodedBatch,
		IsOurs:        false,
	}

	// Perform the cascade rollback.
	err = ts.node.CascadeRollback(winnerEvent)
	if err != nil {
		t.Fatalf("CascadeRollback failed: %v", err)
	}

	// Verify the execution tip is now 2 (winner's block).
	if ts.node.ExecutionTip() != 2 {
		t.Errorf("expected execution tip 2 after rollback, got %d", ts.node.ExecutionTip())
	}

	// Verify the state root matches the winner's root.
	currentRoot := ts.node.StateDB().IntermediateRoot(true) // always true: post-Spurious Dragon
	if currentRoot != winnerRoot {
		t.Errorf("expected state root %s after cascade rollback, got %s",
			winnerRoot.Hex(), currentRoot.Hex())
	}

	// Verify the winner's recipient received the transfer.
	winnerRecipientBalance := ts.node.StateDB().GetBalance(winnerRecipient)
	if winnerRecipientBalance.Cmp(transferAmount) != 0 {
		t.Errorf("expected winner recipient balance %s, got %s",
			transferAmount, winnerRecipientBalance)
	}
}

// TestOverlayNode_FollowerMode verifies that entering follower mode causes
// ProcessBatch to be rejected.
func TestOverlayNode_FollowerMode(t *testing.T) {
	ts := newTestSetup(t)
	defer ts.node.Stop()

	// Initially not in follower mode.
	if ts.node.IsFollower() {
		t.Fatal("node should not be in follower mode initially")
	}

	// Enter follower mode.
	ts.node.EnterFollowerMode()

	if !ts.node.IsFollower() {
		t.Fatal("node should be in follower mode")
	}

	// ProcessBatch should be rejected.
	recipient := types.HexToAddress("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	tx := ts.signTx(t, 0, recipient, uint256.NewInt(1000), nil)

	_, err := ts.node.ProcessBatch([]*types.Transaction{tx})
	if err == nil {
		t.Fatal("expected ProcessBatch to fail in follower mode")
	}
}

// TestOverlayNode_ExitFollowerMode verifies that exiting follower mode
// allows ProcessBatch to work again.
func TestOverlayNode_ExitFollowerMode(t *testing.T) {
	ts := newTestSetup(t)
	defer ts.node.Stop()

	// Enter follower mode.
	ts.node.EnterFollowerMode()

	if !ts.node.IsFollower() {
		t.Fatal("node should be in follower mode")
	}

	// Exit follower mode.
	ts.node.ExitFollowerMode()

	if ts.node.IsFollower() {
		t.Fatal("node should not be in follower mode after exit")
	}

	// ProcessBatch should work now.
	recipient := types.HexToAddress("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	tx := ts.signTx(t, 0, recipient, uint256.NewInt(1000), nil)

	result, err := ts.node.ProcessBatch([]*types.Transaction{tx})
	if err != nil {
		t.Fatalf("ProcessBatch failed after exiting follower mode: %v", err)
	}
	if result.Block.NumberU64() != 1 {
		t.Errorf("expected block 1, got %d", result.Block.NumberU64())
	}
}

// TestOverlayNode_ValidateForRequeue tests that validateForRequeue correctly
// checks nonce and balance.
func TestOverlayNode_ValidateForRequeue(t *testing.T) {
	ts := newTestSetup(t)
	defer ts.node.Stop()

	recipient := types.HexToAddress("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")

	t.Run("valid tx", func(t *testing.T) {
		// A tx with nonce 0 should be valid (matches current state nonce).
		tx := ts.signTx(t, 0, recipient, uint256.NewInt(1000), nil)
		if !ts.node.validateForRequeue(tx) {
			t.Error("expected tx with correct nonce to be valid for requeue")
		}
	})

	t.Run("wrong nonce", func(t *testing.T) {
		// A tx with nonce 5 should be invalid (state nonce is 0).
		tx := ts.signTx(t, 5, recipient, uint256.NewInt(1000), nil)
		if ts.node.validateForRequeue(tx) {
			t.Error("expected tx with wrong nonce to be invalid for requeue")
		}
	})

	t.Run("insufficient balance", func(t *testing.T) {
		// A tx that transfers more than the sender's balance.
		bigValue := new(uint256.Int).Mul(
			uint256.NewInt(1_000_000_000_000_000_000),
			uint256.NewInt(1000),
		)
		tx := ts.signTx(t, 0, recipient, bigValue, nil)
		if ts.node.validateForRequeue(tx) {
			t.Error("expected tx with insufficient balance to be invalid for requeue")
		}
	})
}

// TestOverlayNode_RequeueOrphanedTransactions verifies that orphaned
// transactions from rolled-back blocks are correctly re-queued when valid.
func TestOverlayNode_RequeueOrphanedTransactions(t *testing.T) {
	ts := newTestSetup(t)
	defer ts.node.Stop()

	recipient := types.HexToAddress("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	transferAmount := uint256.NewInt(10_000_000_000_000)

	// Process block 1 with tx at nonce 0.
	tx1 := ts.signTx(t, 0, recipient, transferAmount, nil)
	_, err := ts.node.ProcessBatch([]*types.Transaction{tx1})
	if err != nil {
		t.Fatalf("ProcessBatch 1 failed: %v", err)
	}

	// Process block 2 with tx at nonce 1.
	tx2 := ts.signTx(t, 1, recipient, transferAmount, nil)
	_, err = ts.node.ProcessBatch([]*types.Transaction{tx2})
	if err != nil {
		t.Fatalf("ProcessBatch 2 failed: %v", err)
	}

	if ts.node.ExecutionTip() != 2 {
		t.Fatalf("expected tip 2, got %d", ts.node.ExecutionTip())
	}

	// Collect orphaned transactions from block 2 (will include tx2).
	orphans := ts.node.collectOrphanedTxs(1, 2, nil)
	if len(orphans) != 1 {
		t.Fatalf("expected 1 orphan, got %d", len(orphans))
	}
	if orphans[0].Hash() != tx2.Hash() {
		t.Error("expected the orphan to be tx2")
	}

	// Now rollback to block 1.
	err = ts.node.Rollback(1)
	if err != nil {
		t.Fatalf("rollback failed: %v", err)
	}

	// After rollback, the sender's nonce is 1 (from the state after block 1),
	// and tx2 has nonce 1, so it should be valid for requeue.
	if !ts.node.validateForRequeue(tx2) {
		t.Error("expected tx2 to be valid for requeue after rollback to block 1")
	}

	// Re-queue the orphan via requeueOrphanedTransactions -- but the blocks
	// data is already gone (canonical hashes were cleared during rollback),
	// so we test validateForRequeue + batcher directly.
	err = ts.node.batcher.Add(tx2)
	if err != nil {
		t.Fatalf("failed to add orphan to batcher: %v", err)
	}

	if ts.node.batcher.PendingCount() != 1 {
		t.Errorf("expected 1 pending tx in batcher, got %d", ts.node.batcher.PendingCount())
	}
}

// TestOverlayNode_CollectOrphanedTxs_ExcludesWinnerTxs verifies that
// orphaned tx collection excludes transactions that are in the winner's batch.
func TestOverlayNode_CollectOrphanedTxs_ExcludesWinnerTxs(t *testing.T) {
	ts := newTestSetup(t)
	defer ts.node.Stop()

	r1 := types.HexToAddress("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	r2 := types.HexToAddress("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	transferAmount := uint256.NewInt(10_000_000_000_000)

	// Process block 1 with two transactions.
	tx1 := ts.signTx(t, 0, r1, transferAmount, nil)
	tx2 := ts.signTx(t, 1, r2, transferAmount, nil)
	_, err := ts.node.ProcessBatch([]*types.Transaction{tx1, tx2})
	if err != nil {
		t.Fatalf("ProcessBatch failed: %v", err)
	}

	// Collect orphans excluding tx1 (as if it's in the winner's batch).
	winnerTxHashes := map[types.Hash]bool{
		tx1.Hash(): true,
	}
	orphans := ts.node.collectOrphanedTxs(0, 1, winnerTxHashes)

	// Only tx2 should be orphaned.
	if len(orphans) != 1 {
		t.Fatalf("expected 1 orphan, got %d", len(orphans))
	}
	if orphans[0].Hash() != tx2.Hash() {
		t.Error("expected the orphan to be tx2")
	}
}

// TestOverlayNode_RaceDetectorIntegration verifies that the race detector
// is properly wired into the overlay node.
func TestOverlayNode_RaceDetectorIntegration(t *testing.T) {
	ts := newTestSetup(t)
	defer ts.node.Stop()

	rd := ts.node.RaceDetector()
	if rd == nil {
		t.Fatal("expected non-nil race detector")
	}

	// Verify initial state.
	if rd.ConsecutiveLosses() != 0 {
		t.Errorf("expected 0 initial losses, got %d", rd.ConsecutiveLosses())
	}
	if rd.ShouldEnterFollowerMode() {
		t.Error("should not be in follower mode initially")
	}

	// SetPendingAdvance should work.
	rd.SetPendingAdvance(types.HexToHash("0x5555"))
}

// TestOverlayNode_CascadeRollback_WinnerBatchDecoding verifies that a
// winner's batch data is correctly decoded and transactions are extracted.
func TestOverlayNode_CascadeRollback_WinnerBatchDecoding(t *testing.T) {
	ts := newTestSetup(t)
	defer ts.node.Stop()

	recipient := types.HexToAddress("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	transferAmount := uint256.NewInt(10_000_000_000_000)

	// Create a transaction and RLP-encode it.
	tx := ts.signTx(t, 0, recipient, transferAmount, nil)

	w := &bytesWriter{}
	if err := tx.EncodeRLP(w); err != nil {
		t.Fatalf("failed to encode tx: %v", err)
	}
	txRLP := w.Bytes()

	// Create batch data with this transaction.
	batchData := &block.BatchData{
		Version:      block.BatchVersion,
		Timestamp:    uint64(time.Now().Unix()),
		Coinbase:     ts.coinbase,
		ParentHash:   types.Hash{},
		Transactions: [][]byte{txRLP},
	}

	encoded, err := block.EncodeBatchData(batchData)
	if err != nil {
		t.Fatalf("failed to encode batch data: %v", err)
	}

	// Decode it back.
	decoded, err := block.DecodeBatchData(encoded)
	if err != nil {
		t.Fatalf("failed to decode batch data: %v", err)
	}

	if len(decoded.Transactions) != 1 {
		t.Fatalf("expected 1 transaction, got %d", len(decoded.Transactions))
	}

	// Decode the transaction from RLP.
	decodedTx := new(types.Transaction)
	if err := rlp.DecodeBytes(decoded.Transactions[0], decodedTx); err != nil {
		t.Fatalf("failed to decode transaction from batch: %v", err)
	}

	if decodedTx.Hash() != tx.Hash() {
		t.Errorf("decoded tx hash mismatch: expected %s, got %s",
			tx.Hash().Hex(), decodedTx.Hash().Hex())
	}
}

// Ensure test imports are used.
var _ = big.NewInt(0)
