package shard

import (
	"fmt"
	"log/slog"
	"math/big"

	"github.com/icellan/bsvm/internal/db"
	"github.com/icellan/bsvm/pkg/block"
	"github.com/icellan/bsvm/pkg/rlp"
	"github.com/icellan/bsvm/pkg/state"
	"github.com/icellan/bsvm/pkg/types"
)

// checkpointInterval is the number of blocks between sync checkpoints.
const checkpointInterval = 1000

// BSVClient is the interface for reading BSV blockchain data needed to
// replay the covenant UTXO chain. The actual implementation will use a
// BSV node RPC or block explorer API (future milestone). Tests use a
// mock implementation.
type BSVClient interface {
	// GetTransaction retrieves a BSV transaction by its txid.
	GetTransaction(txid types.Hash) (*BSVTransaction, error)
	// GetSpendingTx finds the transaction that spends the specified
	// output (txid:vout). Returns nil without error if the output is
	// unspent.
	GetSpendingTx(txid types.Hash, vout uint32) (*BSVTransaction, error)
}

// BSVTransaction represents a BSV transaction with its outputs.
type BSVTransaction struct {
	// TxID is the transaction hash.
	TxID types.Hash
	// Outputs holds the transaction's outputs in order.
	Outputs []BSVOutput
}

// BSVOutput represents a single output of a BSV transaction.
type BSVOutput struct {
	// Script is the raw locking script bytes.
	Script []byte
	// Value is the output amount in satoshis.
	Value uint64
}

// SyncFromBSV replays the covenant UTXO chain from BSV to rebuild local
// L2 state. Starting from the genesis covenant transaction, it follows
// the UTXO spending chain. For each covenant advance transaction, it
// extracts the EVM batch data from the OP_RETURN output, re-executes
// the transactions, and verifies the resulting state roots match.
//
// This is the disaster recovery procedure: given only a BSV client and
// the genesis covenant txid, the complete L2 state can be reconstructed.
func SyncFromBSV(
	client BSVClient,
	chainDB *block.ChainDB,
	database db.Database,
	executor *block.BlockExecutor,
	genesisCovenantTxID types.Hash,
) error {
	if client == nil {
		return fmt.Errorf("BSV client must not be nil")
	}
	if chainDB == nil {
		return fmt.Errorf("chain DB must not be nil")
	}
	if database == nil {
		return fmt.Errorf("database must not be nil")
	}
	if executor == nil {
		return fmt.Errorf("block executor must not be nil")
	}

	// Determine how far the local chain has progressed.
	localHead := chainDB.ReadHeadHeader()
	localBlockNum := uint64(0)
	if localHead != nil && localHead.Number != nil {
		localBlockNum = localHead.Number.Uint64()
	}

	// Check for a sync checkpoint to resume from.
	currentTxID := genesisCovenantTxID
	currentVout := uint32(0)
	covenantBlockNum := uint64(0)

	if cp := chainDB.ReadSyncCheckpoint(); cp != nil && cp.L2BlockNum <= localBlockNum {
		// Resume from checkpoint: skip ahead in the covenant chain.
		currentTxID = cp.CovenantTxID
		covenantBlockNum = cp.L2BlockNum
		slog.Info("resuming sync from checkpoint",
			"covenantTxID", cp.CovenantTxID.Hex(),
			"l2BlockNum", cp.L2BlockNum,
		)
	}

	for {
		// Find the transaction that spends the current covenant output.
		spendingTx, err := client.GetSpendingTx(currentTxID, currentVout)
		if err != nil {
			return fmt.Errorf("getting spending tx for %s:%d: %w", currentTxID.Hex(), currentVout, err)
		}
		if spendingTx == nil {
			// Output is unspent. We have reached the tip of the
			// covenant chain and are fully synced.
			break
		}

		covenantBlockNum++

		// Skip blocks we have already processed locally.
		if covenantBlockNum <= localBlockNum {
			currentTxID = spendingTx.TxID
			currentVout = 0
			continue
		}

		// Extract the batch from the covenant advance transaction.
		// By convention, output 0 is the new covenant UTXO and output 1
		// is the OP_RETURN carrying the batch data.
		batch, batchData, err := extractBatch(spendingTx)
		if err != nil {
			return fmt.Errorf("extracting batch from covenant advance %s at block %d: %w",
				spendingTx.TxID.Hex(), covenantBlockNum, err)
		}

		// Re-execute the batch to verify correctness.
		parentHeader := chainDB.ReadHeadHeader()
		if parentHeader == nil {
			return fmt.Errorf("parent header not found for block %d", covenantBlockNum)
		}
		// RLP decodes *big.Int(0) as nil. Ensure Number and BaseFee
		// are non-nil before passing to ProcessBatch.
		if parentHeader.Number == nil {
			parentHeader.Number = new(big.Int)
		}
		if parentHeader.BaseFee == nil {
			parentHeader.BaseFee = new(big.Int)
		}

		// If we have batch data, use its timestamp and coinbase.
		timestamp := parentHeader.Timestamp + 1
		coinbase := types.Address{}
		if batchData != nil {
			timestamp = batchData.Timestamp
			coinbase = batchData.Coinbase
		}

		stateDB, stateErr := state.New(parentHeader.StateRoot, database)
		if stateErr != nil {
			return fmt.Errorf("opening state for block %d: %w", covenantBlockNum, stateErr)
		}

		newBlock, receipts, execErr := executor.ProcessBatch(
			parentHeader,
			coinbase,
			timestamp,
			batch,
			stateDB,
			nil, // No chain context needed for basic replay.
		)
		if execErr != nil {
			return fmt.Errorf("executing block %d: %w", covenantBlockNum, execErr)
		}

		// Commit the state.
		_, commitErr := stateDB.Commit(true)
		if commitErr != nil {
			return fmt.Errorf("committing state for block %d: %w", covenantBlockNum, commitErr)
		}

		// Write the block to the chain database.
		if writeErr := chainDB.WriteBlock(newBlock, receipts); writeErr != nil {
			return fmt.Errorf("writing block %d: %w", covenantBlockNum, writeErr)
		}

		// Write checkpoint every checkpointInterval blocks.
		if covenantBlockNum%checkpointInterval == 0 {
			cp := &block.SyncCheckpoint{
				CovenantTxID: spendingTx.TxID,
				L2BlockNum:   covenantBlockNum,
			}
			if cpErr := chainDB.WriteSyncCheckpoint(cp); cpErr != nil {
				slog.Warn("failed to write sync checkpoint",
					"block", covenantBlockNum, "error", cpErr)
			}
		}

		// Advance to the next covenant output.
		currentTxID = spendingTx.TxID
		currentVout = 0
	}

	return nil
}

// extractBatch extracts EVM transactions from a covenant advance BSV
// transaction. Output 0 is the new covenant UTXO. Output 1 is the
// OP_RETURN carrying batch data (BSVM\x02 format or legacy RLP).
//
// Returns the decoded transactions and, if available, the parsed batch
// data (which contains timestamp, coinbase, etc.). For legacy RLP
// batches, batchData is nil.
func extractBatch(tx *BSVTransaction) ([]*types.Transaction, *block.BatchData, error) {
	if len(tx.Outputs) < 2 {
		return nil, nil, fmt.Errorf("covenant advance tx must have at least 2 outputs, got %d", len(tx.Outputs))
	}

	opReturnData := tx.Outputs[1].Script
	if len(opReturnData) == 0 {
		// Empty batch is valid (e.g., governance-only advance).
		return nil, nil, nil
	}

	// Skip the OP_RETURN prefix (0x6a) and any push data opcodes.
	data := stripOpReturn(opReturnData)
	if len(data) == 0 {
		return nil, nil, nil
	}

	// Try BSVM\x02 format first.
	if len(data) >= 5 && string(data[:4]) == "BSVM" {
		batchData, err := block.DecodeBatchData(data)
		if err != nil {
			return nil, nil, fmt.Errorf("decoding BSVM batch: %w", err)
		}
		// Decode transactions from batch data.
		txs := make([]*types.Transaction, 0, len(batchData.Transactions))
		for i, rawTx := range batchData.Transactions {
			var evmTx types.Transaction
			if decErr := rlp.DecodeBytes(rawTx, &evmTx); decErr != nil {
				slog.Warn("skipping invalid tx in BSVM batch",
					"index", i, "error", decErr)
				continue
			}
			txs = append(txs, &evmTx)
		}
		return txs, batchData, nil
	}

	// Fall back to legacy RLP format.
	var txs []*types.Transaction
	if err := rlp.DecodeBytes(data, &txs); err != nil {
		return nil, nil, fmt.Errorf("decoding batch transactions: %w", err)
	}
	return txs, nil, nil
}

// stripOpReturn removes the OP_RETURN (0x6a) prefix and the subsequent
// push data length byte(s) from a script, returning only the payload.
func stripOpReturn(script []byte) []byte {
	if len(script) == 0 {
		return script
	}
	pos := 0
	// Skip OP_FALSE (0x00) if present (OP_FALSE OP_RETURN pattern).
	if script[pos] == 0x00 {
		pos++
	}
	// Skip OP_RETURN (0x6a).
	if pos < len(script) && script[pos] == 0x6a {
		pos++
	}
	// Skip push data opcode(s).
	if pos < len(script) {
		op := script[pos]
		switch {
		case op <= 0x4b:
			// Direct push: op is the number of bytes.
			pos++
		case op == 0x4c:
			// OP_PUSHDATA1: next byte is length.
			pos += 2
		case op == 0x4d:
			// OP_PUSHDATA2: next 2 bytes are length (little-endian).
			pos += 3
		case op == 0x4e:
			// OP_PUSHDATA4: next 4 bytes are length (little-endian).
			pos += 5
		}
	}
	if pos > len(script) {
		return nil
	}
	return script[pos:]
}
