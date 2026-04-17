package overlay

import (
	"fmt"
	"log/slog"
	"math/big"
	"time"

	"github.com/icellan/bsvm/pkg/block"
	"github.com/icellan/bsvm/pkg/rlp"
	"github.com/icellan/bsvm/pkg/state"
	"github.com/icellan/bsvm/pkg/types"
)

// CascadeRollback performs a full cascade rollback when this node loses a
// covenant advance race. It:
//  1. Rolls back to the last confirmed block (the block before the winner's)
//  2. Replays the winner's batch
//  3. Re-queues orphaned transactions that are still valid
//  4. Discards orphaned transactions that are now invalid
func (n *OverlayNode) CascadeRollback(winnerEvent *CovenantAdvanceEvent) error {
	// The fork point is the block before the winner's block. The winner's
	// block replaces our block at the same height.
	forkPoint := winnerEvent.L2BlockNum - 1

	// Collect orphaned transactions from the blocks we are about to roll back.
	oldTip := n.ExecutionTip()
	if winnerEvent.L2BlockNum > oldTip+1 {
		return fmt.Errorf("winner block %d is too far ahead of current tip %d",
			winnerEvent.L2BlockNum, oldTip)
	}

	slog.Info("starting cascade rollback",
		"forkPoint", forkPoint,
		"currentTip", oldTip,
		"winnerBlock", winnerEvent.L2BlockNum,
		"winnerStateRoot", winnerEvent.PostStateRoot.Hex(),
	)

	// Defence-in-depth (spec 11): re-execute the winner's batch against a
	// fresh state tree rooted at the parent and compare the resulting state
	// root to the advertised root BEFORE we touch the node's live state. If
	// the advance does not verify we refuse to accept it and feed the
	// disagreement into the circuit breaker.
	if !winnerEvent.IsOurs && n.executionVerifier != nil && len(winnerEvent.BatchData) > 0 {
		if verr := n.executionVerifier.VerifyCovenantAdvance(winnerEvent); verr != nil {
			slog.Error("refusing peer covenant advance: execution verification failed",
				"block", winnerEvent.L2BlockNum,
				"error", verr,
			)
			if n.circuitBreaker != nil {
				tripped := n.circuitBreaker.RecordDisagreement(
					winnerEvent.L2BlockNum,
					types.Hash{},
					winnerEvent.PostStateRoot,
				)
				if tripped {
					n.EnterFollowerMode()
				}
			}
			return fmt.Errorf("peer covenant advance failed verification: %w", verr)
		}
	}

	// Decode the winner's batch to learn which transactions are in it.
	winnerBatch, err := block.DecodeBatchData(winnerEvent.BatchData)
	if err != nil {
		return fmt.Errorf("failed to decode winner batch data: %w", err)
	}

	// Decode winner's transactions so we can identify them by hash.
	winnerTxHashes := make(map[types.Hash]bool)
	winnerTxs := make([]*types.Transaction, 0, len(winnerBatch.Transactions))
	for _, rlpTx := range winnerBatch.Transactions {
		tx := new(types.Transaction)
		if err := rlp.DecodeBytes(rlpTx, tx); err != nil {
			slog.Warn("failed to decode winner transaction", "error", err)
			continue
		}
		winnerTxHashes[tx.Hash()] = true
		winnerTxs = append(winnerTxs, tx)
	}

	// Collect orphaned transactions from blocks that will be rolled back
	// BEFORE rolling back (so we can still read them from ChainDB).
	orphanedTxs := n.collectOrphanedTxs(forkPoint, oldTip, winnerTxHashes)

	// Step 1: Rollback to the fork point.
	if err := n.Rollback(forkPoint); err != nil {
		return fmt.Errorf("rollback to fork point %d failed: %w", forkPoint, err)
	}

	// Step 2: Replay the winner's batch to rebuild state.
	winnerBlock, err := n.replayWinnerBatch(winnerBatch, winnerEvent.L2BlockNum, winnerTxs)
	if err != nil {
		return fmt.Errorf("replay of winner batch failed: %w", err)
	}

	// Verify the state root matches the winner's advertised post-state root.
	if winnerBlock.StateRoot() != winnerEvent.PostStateRoot {
		slog.Error("state root mismatch after replaying winner batch",
			"expected", winnerEvent.PostStateRoot.Hex(),
			"got", winnerBlock.StateRoot().Hex(),
		)
		// This is a critical consensus-level disagreement. Feed it into
		// the circuit breaker so repeated disagreements trip the node
		// into follower mode.
		if n.circuitBreaker != nil {
			tripped := n.circuitBreaker.RecordDisagreement(
				winnerEvent.L2BlockNum,
				winnerBlock.StateRoot(),
				winnerEvent.PostStateRoot,
			)
			if tripped {
				n.EnterFollowerMode()
			}
		}
		return fmt.Errorf("state root mismatch: expected %s, got %s",
			winnerEvent.PostStateRoot.Hex(), winnerBlock.StateRoot().Hex())
	}

	// Step 3: Validate and re-queue orphaned transactions.
	requeued := 0
	dropped := 0
	for _, tx := range orphanedTxs {
		if n.validateForRequeue(tx) {
			if err := n.batcher.Add(tx); err != nil {
				slog.Debug("failed to requeue orphan tx",
					"hash", tx.Hash().Hex(),
					"error", err,
				)
				dropped++
			} else {
				requeued++
			}
		} else {
			dropped++
		}
	}

	slog.Info("cascade rollback complete",
		"forkPoint", forkPoint,
		"winnerBlock", winnerEvent.L2BlockNum,
		"newTip", n.ExecutionTip(),
		"orphansCollected", len(orphanedTxs),
		"orphansRequeued", requeued,
		"orphansDropped", dropped,
	)

	return nil
}

// replayWinnerBatch re-executes the winner's transactions to rebuild state.
func (n *OverlayNode) replayWinnerBatch(batch *block.BatchData, _ uint64, txs []*types.Transaction) (*block.L2Block, error) {
	n.mu.Lock()
	defer n.mu.Unlock()

	if len(txs) == 0 {
		return nil, fmt.Errorf("winner batch has no valid transactions")
	}

	// Get the parent header (at the fork point, which is now our tip).
	parentHeader := n.chainDB.ReadHeaderByNumber(n.executionTip)
	if parentHeader == nil {
		return nil, fmt.Errorf("parent header not found for block %d", n.executionTip)
	}
	if parentHeader.Number == nil {
		parentHeader.Number = new(big.Int).SetUint64(n.executionTip)
	}
	if parentHeader.BaseFee == nil {
		parentHeader.BaseFee = new(big.Int)
	}

	// Execute the winner's batch using the batch timestamp and coinbase.
	l2Block, receipts, err := n.executor.ProcessBatch(
		parentHeader,
		batch.Coinbase,
		batch.Timestamp,
		txs,
		n.stateDB,
		n,
	)
	if err != nil {
		return nil, fmt.Errorf("winner batch execution failed: %w", err)
	}

	// Commit state.
	committedRoot, err := n.stateDB.Commit(true)
	if err != nil {
		return nil, fmt.Errorf("state commit after winner replay failed: %w", err)
	}

	// Write the winner's block to ChainDB.
	if err := n.chainDB.WriteBlock(l2Block, receipts); err != nil {
		return nil, fmt.Errorf("failed to write winner block to chaindb: %w", err)
	}

	// Re-open state at committed root.
	newStateDB, err := state.New(committedRoot, n.rawDB)
	if err != nil {
		return nil, fmt.Errorf("failed to re-open state at winner root %s: %w",
			committedRoot.Hex(), err)
	}
	n.stateDB = newStateDB

	// Update execution tip.
	n.executionTip = l2Block.NumberU64()

	// Update TxCache with the winner's entry.
	n.txCache.Append(&CachedTx{
		L2BlockNum:  l2Block.NumberU64(),
		StateRoot:   l2Block.StateRoot(),
		BatchData:   nil, // We don't need to store the winner's batch data
		ProveOutput: nil, // The winner proved this, not us
		BroadcastAt: time.Now(),
		Confirmed:   true, // The winner's block is confirmed on BSV
	})

	return l2Block, nil
}

// requeueOrphanedTransactions identifies transactions from rolled-back blocks
// that are still valid and re-submits them to the batcher. Returns the number
// of transactions successfully re-queued.
func (n *OverlayNode) requeueOrphanedTransactions(fromBlock, toBlock uint64) int {
	orphans := n.collectOrphanedTxs(fromBlock, toBlock, nil)

	requeued := 0
	for _, tx := range orphans {
		if n.validateForRequeue(tx) {
			if err := n.batcher.Add(tx); err == nil {
				requeued++
			}
		}
	}
	return requeued
}

// collectOrphanedTxs gathers all transactions from blocks in the range
// (fromBlock, toBlock] that are not in the winner's batch.
func (n *OverlayNode) collectOrphanedTxs(fromBlock, toBlock uint64, winnerTxHashes map[types.Hash]bool) []*types.Transaction {
	var orphans []*types.Transaction

	for blockNum := fromBlock + 1; blockNum <= toBlock; blockNum++ {
		hash := n.chainDB.ReadCanonicalHash(blockNum)
		if hash == (types.Hash{}) {
			continue
		}
		txs := n.chainDB.ReadBody(hash, blockNum)
		for _, tx := range txs {
			if winnerTxHashes != nil && winnerTxHashes[tx.Hash()] {
				// This transaction is in the winner's batch, skip it.
				continue
			}
			orphans = append(orphans, tx)
		}
	}

	return orphans
}

// validateForRequeue checks if a transaction is still valid for re-inclusion
// against the current state (after replay). Checks nonce and balance.
func (n *OverlayNode) validateForRequeue(tx *types.Transaction) bool {
	// Recover sender from signature.
	from, err := types.Sender(n.signer, tx)
	if err != nil {
		slog.Debug("failed to recover sender for orphan tx",
			"hash", tx.Hash().Hex(),
			"error", err,
		)
		return false
	}

	n.mu.Lock()
	stateNonce := n.stateDB.GetNonce(from)
	balance := n.stateDB.GetBalance(from)
	n.mu.Unlock()

	// Check nonce: must match current state nonce (not behind it).
	if tx.Nonce() != stateNonce {
		return false
	}

	// Check balance: sender needs gas * gasPrice + value.
	cost := new(big.Int).Mul(new(big.Int).SetUint64(tx.Gas()), tx.GasPrice())
	cost.Add(cost, tx.Value().ToBig())

	if balance.ToBig().Cmp(cost) < 0 {
		return false
	}

	return true
}

// EnterFollowerMode puts the node in follower-only mode. The node continues
// executing transactions and serving RPC but stops trying to advance the covenant.
func (n *OverlayNode) EnterFollowerMode() {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.followerMode = true
	slog.Info("entered follower mode: no longer attempting covenant advances")
}

// ExitFollowerMode returns the node to normal operation.
func (n *OverlayNode) ExitFollowerMode() {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.followerMode = false
	slog.Info("exited follower mode: resuming covenant advance attempts")
}

// IsFollower returns true if the node is in follower-only mode.
func (n *OverlayNode) IsFollower() bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.followerMode
}
