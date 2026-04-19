package overlay

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"math/big"
	"time"

	"github.com/icellan/bsvm/pkg/block"
	"github.com/icellan/bsvm/pkg/covenant"
	"github.com/icellan/bsvm/pkg/prover"
	"github.com/icellan/bsvm/pkg/rlp"
	"github.com/icellan/bsvm/pkg/state"
	"github.com/icellan/bsvm/pkg/types"
)

// mockProofMarker is the sentinel value written by the mock prover
// (pkg/prover/host.go). Production deployments refuse to wrap a proof
// with this marker into a covenant advance; see OverlayConfig.RequireRealProof.
var mockProofMarker = []byte("MOCK_SP1_PROOF")

// isMockProof reports whether the given proof bytes are the mock prover's
// placeholder sentinel.
func isMockProof(proof []byte) bool {
	return bytes.Equal(proof, mockProofMarker)
}

// ProcessResult holds the outcome of processing a batch of transactions.
type ProcessResult struct {
	// Block is the newly created L2 block.
	Block *block.L2Block
	// Receipts contains the transaction receipts.
	Receipts []*types.Receipt
	// StateRoot is the post-execution state root.
	StateRoot types.Hash
	// ProveOutput is the SP1 proof output, or nil if proving is
	// asynchronous and has not yet completed.
	ProveOutput *prover.ProveOutput
	// BatchData is the canonical batch encoding (from block.EncodeBatchData)
	// used by the prover and broadcast client. Exposed so callers like
	// PlanAdvance can rebuild the AdvanceProof without re-encoding.
	BatchData []byte
}

// ProcessBatch executes a batch of transactions through the Go EVM,
// generates an SP1 proof, and prepares data for covenant advance.
//
// Steps:
//  1. Get parent header from ChainDB
//  2. Start access recording on StateDB
//  3. Execute via block.BlockExecutor.ProcessBatch
//  4. Stop access recording to get accessed accounts/slots
//  5. Export state for proving
//  6. Submit to prover (synchronous for mock mode)
//  7. Write block and receipts to ChainDB
//  8. Update execution tip
//  9. Add to TxCache
//  10. Return result
func (n *OverlayNode) ProcessBatch(txs []*types.Transaction) (*ProcessResult, error) {
	n.mu.Lock()
	defer n.mu.Unlock()

	if len(txs) == 0 {
		return nil, fmt.Errorf("empty batch")
	}

	// Check follower mode: if in follower mode, refuse to process new batches.
	if n.followerMode {
		return nil, fmt.Errorf("node is in follower mode, not processing new batches")
	}

	// Check circuit breaker: if tripped, refuse to process new batches.
	if n.circuitBreaker != nil && n.circuitBreaker.IsTripped() {
		return nil, fmt.Errorf("circuit breaker tripped: node is in follower-only mode")
	}

	// 1. Get parent header from ChainDB.
	parentHeader := n.chainDB.ReadHeaderByNumber(n.executionTip)
	if parentHeader == nil {
		return nil, fmt.Errorf("parent header not found for block %d", n.executionTip)
	}
	// Ensure Number is non-nil (RLP may decode zero as nil for *big.Int).
	if parentHeader.Number == nil {
		parentHeader.Number = new(big.Int).SetUint64(n.executionTip)
	}
	if parentHeader.BaseFee == nil {
		parentHeader.BaseFee = new(big.Int)
	}

	// Record the pre-state root before execution.
	preStateRoot := parentHeader.StateRoot

	// 2. Start access recording on StateDB.
	n.stateDB.StartAccessRecording()

	// Capture inbox root BEFORE draining so we have the true
	// "before" state for the SP1 public values.
	var inboxRootBefore types.Hash
	if n.inboxMonitor != nil {
		inboxRootBefore = n.inboxMonitor.QueueHash()
	}

	// Check if forced inbox inclusion is required.
	if n.inboxMonitor != nil && n.inboxMonitor.MustDrainInbox() {
		inboxTxsRLP := n.inboxMonitor.DrainPending()
		// Decode and prepend inbox transactions to the batch.
		for _, rlpTx := range inboxTxsRLP {
			var inboxTx types.Transaction
			if err := rlp.DecodeBytes(rlpTx, &inboxTx); err != nil {
				slog.Warn("skipping invalid inbox transaction", "error", err)
				continue
			}
			txs = append([]*types.Transaction{&inboxTx}, txs...)
		}
	}

	// 3. Execute via block.BlockExecutor.ProcessBatch.
	// Derive the block timestamp deterministically from parent + interval.
	// Spec 11/12: every node (and the SP1 guest) must land on the same
	// block hash, so the timestamp cannot come from wall-clock time.
	interval := n.config.BlockInterval
	if interval == 0 {
		interval = 1
	}
	timestamp := parentHeader.Timestamp + interval
	l2Block, receipts, err := n.executor.ProcessBatch(
		parentHeader,
		n.config.Coinbase,
		timestamp,
		txs,
		n.stateDB,
		n,
	)
	if err != nil {
		n.stateDB.StopAccessRecording()
		return nil, fmt.Errorf("batch execution failed: %w", err)
	}

	// Compute post-state root.
	postStateRoot := l2Block.StateRoot()

	// 4. Stop access recording.
	accessRecording := n.stateDB.StopAccessRecording()

	// 5. Export state for proving using the PRE-state root. The prover
	// needs the state before execution, not after, so it can replay the
	// transactions and arrive at the post-state root independently.
	preStateDB, err := state.New(preStateRoot, n.rawDB)
	if err != nil {
		slog.Warn("failed to open pre-state for proving", "error", err)
	}
	var stateExport *prover.StateExport
	if preStateDB != nil {
		stateExport, err = prover.ExportStateForProving(
			preStateDB,
			accessRecording.Accounts,
			accessRecording.Slots,
		)
		if err != nil {
			slog.Warn("state export for proving failed", "error", err)
			// Non-fatal: we can still commit the block, proving will just
			// not work for this batch. In production this would be fatal.
		}
	}

	// Build the prove input.
	var rlpTxs [][]byte
	for _, tx := range l2Block.Transactions {
		var buf []byte
		b := new(bytesWriter)
		if err := tx.EncodeRLP(b); err == nil {
			buf = b.Bytes()
		}
		rlpTxs = append(rlpTxs, buf)
	}

	// Capture inbox root AFTER draining. inboxRootBefore was captured
	// before draining at the top of this function.
	var inboxRootAfter types.Hash
	if n.inboxMonitor != nil {
		inboxRootAfter = n.inboxMonitor.QueueHash()
	}

	proveInput := &prover.ProveInput{
		PreStateRoot:    preStateRoot,
		Transactions:    rlpTxs,
		InboxRootBefore: inboxRootBefore,
		InboxRootAfter:  inboxRootAfter,
		BlockContext: prover.BlockContext{
			Number:    l2Block.NumberU64(),
			Timestamp: l2Block.Time(),
			Coinbase:  n.config.Coinbase,
			GasLimit:  l2Block.GasLimit(),
			BaseFee:   0,
		},
		ExpectedResults: &prover.ExpectedResults{
			PostStateRoot: postStateRoot,
			ReceiptsHash:  l2Block.Header.ReceiptHash,
			GasUsed:       l2Block.GasUsed(),
			ChainID:       uint64(n.config.ChainID),
		},
	}

	if stateExport != nil {
		exportBytes, _ := json.Marshal(stateExport)
		proveInput.StateExport = exportBytes
	}

	// 6. Submit to prover (synchronous for mock/local modes).
	var proveOutput *prover.ProveOutput
	if n.parallelProver != nil {
		ctx := context.Background()
		output, proveErr := n.parallelProver.ProveAndWait(ctx, proveInput)
		if proveErr != nil {
			slog.Warn("proving failed", "block", l2Block.NumberU64(), "error", proveErr)
		} else {
			proveOutput = output
		}
	}

	// Build the canonical batch encoding now so it can be passed to both
	// the broadcast client and the TxCache entry. DepositHorizon comes
	// from the inbox monitor if one is configured.
	var depositHorizon uint64
	if n.inboxMonitor != nil {
		depositHorizon = uint64(n.inboxMonitor.AdvancesSinceDrain())
	}
	canonicalBatch := &block.BatchData{
		Version:        block.BatchVersion,
		Timestamp:      l2Block.Time(),
		Coinbase:       n.config.Coinbase,
		ParentHash:     parentHeader.Hash(),
		Transactions:   rlpTxs,
		DepositHorizon: depositHorizon,
	}
	encodedBatch, encodeErr := block.EncodeBatchData(canonicalBatch)
	if encodeErr != nil {
		slog.Warn("batch encoding failed", "error", encodeErr)
		encodedBatch = nil
		for _, rlpTx := range rlpTxs {
			encodedBatch = append(encodedBatch, rlpTx...)
		}
	}

	// Reject synthetic/mock proofs when the node is configured for
	// production. A mock proof carries the "MOCK_SP1_PROOF" marker and
	// must NEVER be wrapped into a covenant advance in a real deployment.
	if n.config.RequireRealProof && proveOutput != nil && isMockProof(proveOutput.Proof) {
		return nil, fmt.Errorf("production config: refusing to build covenant advance from mock SP1 proof")
	}

	// 6.5. Broadcast the advance to the BSV covenant if a proof was produced.
	// Failure here is non-fatal: the block still commits locally and the
	// race detector / next advance will reconcile.
	var broadcastResult *covenant.BroadcastResult
	if proveOutput != nil && n.covenantMgr != nil && n.covenantMgr.BroadcastClient() != nil {
		newCovState := n.covenantMgr.CurrentState()
		newCovState.BlockNumber = l2Block.NumberU64()
		newCovState.StateRoot = postStateRoot
		advanceProof, apErr := BuildAdvanceProofForOutput(proveOutput, encodedBatch)
		if apErr != nil {
			slog.Warn("advance proof construction failed", "block", l2Block.NumberU64(), "error", apErr)
		} else {
			result, bcErr := n.covenantMgr.BroadcastAdvance(
				context.Background(),
				newCovState,
				advanceProof,
			)
			if bcErr != nil {
				slog.Warn("covenant broadcast failed", "block", l2Block.NumberU64(), "error", bcErr)
			} else {
				broadcastResult = result
				if n.confirmationWatcher != nil {
					n.confirmationWatcher.Track(l2Block.NumberU64(), result.TxID)
				}
			}
		}
	}

	// 7. Commit state and write block + receipts to ChainDB.
	committedRoot, commitErr := n.stateDB.Commit(true)
	if commitErr != nil {
		return nil, fmt.Errorf("state commit failed: %w", commitErr)
	}

	if err := n.chainDB.WriteBlock(l2Block, receipts); err != nil {
		return nil, fmt.Errorf("failed to write block to chaindb: %w", err)
	}

	// Re-open the state at the new root so the next batch can operate
	// on a fresh trie (the old trie is invalidated by Commit).
	newStateDB, err := state.New(committedRoot, n.rawDB)
	if err != nil {
		return nil, fmt.Errorf("failed to re-open state at committed root %s: %w",
			committedRoot.Hex(), err)
	}
	n.stateDB = newStateDB

	// 8. Update execution tip.
	n.executionTip = l2Block.NumberU64()
	if proveOutput != nil {
		n.provenTip = l2Block.NumberU64()
	}

	// Record advance for inbox forced inclusion tracking.
	if n.inboxMonitor != nil {
		n.inboxMonitor.RecordAdvance()
	}

	// 9. Add to TxCache. encodedBatch was built before the broadcast step.
	cacheEntry := &CachedTx{
		L2BlockNum:  l2Block.NumberU64(),
		StateRoot:   postStateRoot,
		BatchData:   encodedBatch,
		ProveOutput: proveOutput,
		BroadcastAt: time.Now(),
	}
	if broadcastResult != nil {
		cacheEntry.BroadcastTxID = broadcastResult.TxID
		cacheEntry.BroadcastAt = broadcastResult.BroadcastAt
	}
	n.txCache.Append(cacheEntry)

	// Emit event for subscribers.
	if n.eventFeed != nil {
		n.eventFeed.Send(NewHeadEvent{Block: l2Block})
	}

	// 10. Announce the new block to P2P peers so they can sync.
	if n.blockAnnouncer != nil {
		var txHashes []types.Hash
		for _, tx := range l2Block.Transactions {
			txHashes = append(txHashes, tx.Hash())
		}
		if err := n.blockAnnouncer.BroadcastBlockAnnounce(
			parentHeader.Hash(),
			postStateRoot,
			l2Block.Header.TxHash,
			l2Block.NumberU64(),
			l2Block.GasUsed(),
			l2Block.Time(),
			txHashes,
		); err != nil {
			slog.Debug("block announcement broadcast failed", "block", l2Block.NumberU64(), "error", err)
		}
	}

	slog.Info("processed batch",
		"block", l2Block.NumberU64(),
		"txs", len(l2Block.Transactions),
		"gasUsed", l2Block.GasUsed(),
		"stateRoot", postStateRoot.Hex(),
	)

	return &ProcessResult{
		Block:       l2Block,
		Receipts:    receipts,
		StateRoot:   postStateRoot,
		ProveOutput: proveOutput,
		BatchData:   encodedBatch,
	}, nil
}

// NewHeadEvent is emitted when a new L2 block is processed.
type NewHeadEvent struct {
	// Block is the newly created L2 block.
	Block *block.L2Block
}

// bytesWriter is a simple writer that collects bytes for RLP encoding.
type bytesWriter struct {
	buf []byte
}

// Write implements io.Writer.
func (w *bytesWriter) Write(p []byte) (int, error) {
	w.buf = append(w.buf, p...)
	return len(p), nil
}

// Bytes returns the accumulated bytes.
func (w *bytesWriter) Bytes() []byte {
	return w.buf
}
