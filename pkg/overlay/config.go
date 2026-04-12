package overlay

import (
	"math/big"
	"time"

	"github.com/icellan/bsvm/pkg/types"
)

// OverlayConfig holds the configuration for an overlay node.
type OverlayConfig struct {
	// Coinbase is the L2 fee recipient address. This is the address that
	// receives gas fees from executed transactions.
	Coinbase types.Address

	// BlockGasLimit is the maximum gas allowed in a single L2 block.
	// Default: 30,000,000.
	BlockGasLimit uint64

	// MaxBatchSize is the maximum number of transactions per batch.
	// When the batcher accumulates this many transactions, it flushes
	// immediately. Default: 128.
	MaxBatchSize int

	// MaxBatchFlushDelay is the maximum time to wait before flushing a
	// non-empty batch. The timer only runs when there are pending
	// transactions. Default: 2s.
	MaxBatchFlushDelay time.Duration

	// MinGasPrice is the minimum gas price a transaction must have to
	// be accepted by the node. Default: 1 gwei (1e9 wei).
	MinGasPrice *big.Int

	// MaxSpeculativeDepth is the maximum number of unproven L2 blocks
	// the node will accumulate before pausing batch production. This
	// prevents the node from getting too far ahead of the prover.
	// Default: 16.
	MaxSpeculativeDepth int

	// ChainID is the L2 shard chain ID used for transaction signing
	// and replay protection.
	ChainID int64

	// TargetBatchSize is the preferred number of transactions per batch.
	// The batcher flushes when it reaches this count. Default: 128.
	TargetBatchSize int

	// MinBatchSize is the minimum number of transactions required before
	// a batch can be flushed by the timer. If there are fewer transactions
	// than this, the timer resets. Set to 0 to disable. Default: 1.
	MinBatchSize int

	// MinProfitableBatchGas is the minimum total gas across all
	// transactions in a batch before the prover considers it worth
	// proving. Batches below this threshold may be delayed. Default: 0
	// (prove everything).
	MinProfitableBatchGas uint64
}

// DefaultOverlayConfig returns an OverlayConfig with sensible defaults.
func DefaultOverlayConfig() OverlayConfig {
	return OverlayConfig{
		BlockGasLimit:         30_000_000,
		MaxBatchSize:          128,
		MaxBatchFlushDelay:    2 * time.Second,
		MinGasPrice:           big.NewInt(1_000_000_000), // 1 gwei
		MaxSpeculativeDepth:   16,
		ChainID:               1,
		TargetBatchSize:       128,
		MinBatchSize:          1,
		MinProfitableBatchGas: 0,
	}
}
