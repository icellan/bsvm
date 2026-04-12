package overlay

import (
	"fmt"
	"log/slog"

	"github.com/icellan/bsvm/pkg/state"
	"github.com/icellan/bsvm/pkg/types"
)

// Rollback reverts the overlay node's state to a specific block number.
// This is called when another node wins a covenant advance race and this
// node must discard its speculative state and replay the winner's batch.
//
// Rollback performs the following steps:
//  1. Validate the target block number is not ahead of the current tip
//  2. Read the target block's state root from ChainDB
//  3. Create a new StateDB from the target state root
//  4. Truncate the TxCache to remove invalidated entries
//  5. Update the execution tip
func (n *OverlayNode) Rollback(toBlock uint64) error {
	n.mu.Lock()
	defer n.mu.Unlock()

	if toBlock > n.executionTip {
		return fmt.Errorf("cannot rollback forward: current tip %d, target %d",
			n.executionTip, toBlock)
	}

	if toBlock == n.executionTip {
		// Already at the target block; nothing to do.
		return nil
	}

	slog.Info("rolling back",
		"from", n.executionTip,
		"to", toBlock,
	)

	// Read the target block's header to get the state root.
	targetHeader := n.chainDB.ReadHeaderByNumber(toBlock)
	if targetHeader == nil {
		return fmt.Errorf("target block header not found: block %d", toBlock)
	}

	// Create a new StateDB from the target state root.
	newStateDB, err := state.New(targetHeader.StateRoot, n.rawDB)
	if err != nil {
		return fmt.Errorf("failed to create state at block %d (root %s): %w",
			toBlock, targetHeader.StateRoot.Hex(), err)
	}

	// Mark rolled-back receipts.
	if err := n.chainDB.MarkReceiptsRolledBack(toBlock+1, n.executionTip, toBlock); err != nil {
		slog.Warn("failed to mark receipts as rolled back", "error", err)
	}

	// Rewrite the canonical chain pointers for rolled-back blocks.
	// We remove the canonical hash entries for blocks after the target
	// so that ChainDB no longer references them as canonical.
	for blockNum := toBlock + 1; blockNum <= n.executionTip; blockNum++ {
		// Write a zero hash to invalidate the canonical entry.
		if err := n.chainDB.WriteCanonicalHash(types.Hash{}, blockNum); err != nil {
			slog.Warn("failed to clear canonical hash",
				"block", blockNum,
				"error", err,
			)
		}
	}

	// Update head block hash to the target block.
	if err := n.chainDB.WriteHeadBlockHash(targetHeader.Hash()); err != nil {
		return fmt.Errorf("failed to update head block hash: %w", err)
	}

	// Truncate the TxCache.
	n.txCache.Truncate(toBlock)

	// Update the state and tip.
	n.stateDB = newStateDB
	n.executionTip = toBlock

	// If the proven tip is ahead of the new execution tip, adjust it.
	if n.provenTip > toBlock {
		n.provenTip = toBlock
	}

	// If the finalized tip is ahead of the new execution tip, adjust it.
	if n.finalizedTip > toBlock {
		n.finalizedTip = toBlock
	}

	slog.Info("rollback complete",
		"tip", n.executionTip,
		"stateRoot", targetHeader.StateRoot.Hex(),
	)

	return nil
}
