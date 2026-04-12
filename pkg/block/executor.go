package block

import (
	"fmt"
	"math/big"

	"github.com/icellan/bsvm/pkg/state"
	"github.com/icellan/bsvm/pkg/types"
	"github.com/icellan/bsvm/pkg/vm"
)

// DefaultGasLimit is the default block gas limit for L2 blocks.
const DefaultGasLimit = 30_000_000

// BlockExecutionResult contains the result of executing a complete block.
type BlockExecutionResult struct {
	StateRoot types.Hash
	Receipts  []*types.Receipt
	Logs      []*types.Log
	GasUsed   uint64
}

// BlockExecutor executes blocks by applying transactions to the state.
type BlockExecutor struct {
	chainConfig *vm.ChainConfig
	vmConfig    vm.Config
}

// NewBlockExecutor creates a new block executor with the given chain and VM
// configuration.
func NewBlockExecutor(chainConfig *vm.ChainConfig, vmConfig vm.Config) *BlockExecutor {
	return &BlockExecutor{
		chainConfig: chainConfig,
		vmConfig:    vmConfig,
	}
}

// ExecuteBlock executes all transactions in a block against the provided
// state and returns a BlockExecutionResult containing the state root,
// receipts, logs, and total gas used. The state is modified in place.
func (e *BlockExecutor) ExecuteBlock(
	block *L2Block,
	statedb *state.StateDB,
	chainCtx ChainContext,
) (*BlockExecutionResult, error) {
	header := block.Header

	// Validate the header before execution.
	if err := ValidateHeader(header); err != nil {
		return nil, fmt.Errorf("invalid block header: %w", err)
	}

	coinbase := header.Coinbase

	gp := new(GasPool)
	gp.SetGas(header.GasLimit)

	var (
		receipts []*types.Receipt
		allLogs  []*types.Log
		usedGas  uint64
	)

	for i, tx := range block.Transactions {
		statedb.SetTxContext(tx.Hash(), i)

		receipt, err := ApplyTransaction(e.chainConfig, chainCtx, &coinbase, gp, statedb, header, tx, &usedGas, e.vmConfig, nil)
		if err != nil {
			return nil, fmt.Errorf("could not apply tx %d [%s]: %w", i, tx.Hash().Hex(), err)
		}
		receipt.TransactionIndex = uint(i)
		receipts = append(receipts, receipt)
		allLogs = append(allLogs, receipt.Logs...)
	}

	// Compute the post-execution state root.
	stateRoot := statedb.IntermediateRoot(true)

	return &BlockExecutionResult{
		StateRoot: stateRoot,
		Receipts:  receipts,
		Logs:      allLogs,
		GasUsed:   usedGas,
	}, nil
}

// ProcessBatch executes a batch of transactions and produces a new L2 block.
// This is the primary entry point for the overlay node to build blocks.
func (e *BlockExecutor) ProcessBatch(
	parentHeader *L2Header,
	coinbase types.Address,
	timestamp uint64,
	txs []*types.Transaction,
	statedb *state.StateDB,
	chainCtx ChainContext,
) (*L2Block, []*types.Receipt, error) {
	// Build the header for the new block.
	header := &L2Header{
		ParentHash: parentHeader.Hash(),
		Coinbase:   coinbase,
		Number:     new(big.Int).Add(parentHeader.Number, big.NewInt(1)),
		GasLimit:   parentHeader.GasLimit,
		Timestamp:  timestamp,
		BaseFee:    new(big.Int), // BaseFee is always 0 for this L2.
	}

	gp := new(GasPool)
	gp.SetGas(header.GasLimit)

	var (
		receipts    []*types.Receipt
		usedGas     uint64
		includedTxs []*types.Transaction
	)

	for i, tx := range txs {
		statedb.SetTxContext(tx.Hash(), i)

		receipt, err := ApplyTransaction(e.chainConfig, chainCtx, &coinbase, gp, statedb, header, tx, &usedGas, e.vmConfig, nil)
		if err != nil {
			// Skip transactions that fail validation (e.g. nonce too low,
			// insufficient funds for gas). This is normal in a competitive
			// multi-node model where some transactions may become invalid.
			continue
		}
		receipt.TransactionIndex = uint(len(includedTxs))
		includedTxs = append(includedTxs, tx)
		receipts = append(receipts, receipt)
	}

	header.GasUsed = usedGas

	// Validate the constructed header before proceeding.
	if err := ValidateHeader(header); err != nil {
		return nil, nil, fmt.Errorf("invalid block header: %w", err)
	}

	// Compute the state root.
	header.StateRoot = statedb.IntermediateRoot(true)

	// Build the block.
	block := NewBlock(header, includedTxs, receipts)

	return block, receipts, nil
}
