package overlay

import (
	"fmt"
	"log/slog"
	"math/big"

	"github.com/icellan/bsvm/internal/db"
	"github.com/icellan/bsvm/pkg/block"
	"github.com/icellan/bsvm/pkg/rlp"
	"github.com/icellan/bsvm/pkg/state"
	"github.com/icellan/bsvm/pkg/types"
	"github.com/icellan/bsvm/pkg/vm"
)

// ExecutionVerifier re-executes batches from covenant advances and compares
// the resulting state root with the claimed state root. This is the
// defence-in-depth verification described in spec 11 and spec 12: all
// nodes independently verify every covenant advance by re-executing.
type ExecutionVerifier struct {
	executor *block.BlockExecutor
	rawDB    db.Database
	chainDB  *block.ChainDB
}

// NewExecutionVerifier creates a new ExecutionVerifier with the given
// block executor, raw database (for opening state at arbitrary roots),
// and chain database (for reading parent headers).
func NewExecutionVerifier(executor *block.BlockExecutor, rawDB db.Database, chainDB *block.ChainDB) *ExecutionVerifier {
	return &ExecutionVerifier{
		executor: executor,
		rawDB:    rawDB,
		chainDB:  chainDB,
	}
}

// VerifyCovenantAdvance re-executes the batch from a covenant advance and
// verifies the resulting state root matches the advance's claimed state
// root. Returns nil if the roots match, or an error describing the
// mismatch.
func (v *ExecutionVerifier) VerifyCovenantAdvance(advance *CovenantAdvanceEvent) error {
	if advance == nil {
		return fmt.Errorf("nil covenant advance event")
	}
	if len(advance.BatchData) == 0 {
		return fmt.Errorf("empty batch data in covenant advance for block %d", advance.L2BlockNum)
	}

	// Decode the batch data to get transactions and block parameters.
	batch, err := block.DecodeBatchData(advance.BatchData)
	if err != nil {
		return fmt.Errorf("failed to decode batch data: %w", err)
	}

	// Decode the RLP-encoded transactions.
	var txs []*types.Transaction
	for _, rlpTx := range batch.Transactions {
		tx := new(types.Transaction)
		if err := rlp.DecodeBytes(rlpTx, tx); err != nil {
			slog.Warn("skipping invalid transaction in verification",
				"error", err,
				"block", advance.L2BlockNum,
			)
			continue
		}
		txs = append(txs, tx)
	}

	// Read the parent header to get the pre-state root.
	parentNum := advance.L2BlockNum - 1
	parentHeader := v.chainDB.ReadHeaderByNumber(parentNum)
	if parentHeader == nil {
		return fmt.Errorf("parent header not found for block %d", parentNum)
	}
	if parentHeader.Number == nil {
		parentHeader.Number = new(big.Int).SetUint64(parentNum)
	}
	if parentHeader.BaseFee == nil {
		parentHeader.BaseFee = new(big.Int)
	}

	// Open a fresh state at the parent's state root.
	statedb, err := state.New(parentHeader.StateRoot, v.rawDB)
	if err != nil {
		return fmt.Errorf("failed to open state at root %s: %w",
			parentHeader.StateRoot.Hex(), err)
	}

	// Build a chain context that reads from our ChainDB.
	chainCtx := &verifierChainContext{chainDB: v.chainDB}

	// Re-execute the batch using the same parameters from the batch data.
	_, _, err = v.executor.ProcessBatch(
		parentHeader,
		batch.Coinbase,
		batch.Timestamp,
		txs,
		statedb,
		chainCtx,
	)
	if err != nil {
		return fmt.Errorf("batch re-execution failed at block %d: %w",
			advance.L2BlockNum, err)
	}

	// Compute the resulting state root.
	computedRoot := statedb.IntermediateRoot(true)

	// Compare with the claimed state root from the covenant advance.
	if computedRoot != advance.PostStateRoot {
		slog.Error("EXECUTION MISMATCH -- covenant advance has incorrect state root",
			"block", advance.L2BlockNum,
			"expected", advance.PostStateRoot.Hex(),
			"computed", computedRoot.Hex(),
			"bsvTx", advance.BSVTxID.Hex(),
		)
		return fmt.Errorf("execution mismatch at block %d: covenant=%s computed=%s",
			advance.L2BlockNum, advance.PostStateRoot.Hex(), computedRoot.Hex())
	}

	return nil
}

// verifierChainContext implements block.ChainContext for the verifier.
type verifierChainContext struct {
	chainDB *block.ChainDB
}

// GetHeader implements block.ChainContext.
func (c *verifierChainContext) GetHeader(hash types.Hash, number uint64) *block.L2Header {
	return c.chainDB.ReadHeader(hash, number)
}

// NewExecutionVerifierFromNode creates an ExecutionVerifier from an
// OverlayNode, using its existing executor, database, and chain DB.
func NewExecutionVerifierFromNode(node *OverlayNode) *ExecutionVerifier {
	chainConfig := vm.DefaultL2Config(node.config.ChainID)
	executor := block.NewBlockExecutor(chainConfig, vm.Config{})
	return NewExecutionVerifier(executor, node.rawDB, node.chainDB)
}
