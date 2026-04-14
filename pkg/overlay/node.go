package overlay

import (
	"fmt"
	"log/slog"
	"math/big"
	"sync"
	"time"

	"github.com/icellan/bsvm/internal/db"
	"github.com/icellan/bsvm/pkg/block"
	"github.com/icellan/bsvm/pkg/covenant"
	"github.com/icellan/bsvm/pkg/event"
	"github.com/icellan/bsvm/pkg/prover"
	"github.com/icellan/bsvm/pkg/rlp"
	"github.com/icellan/bsvm/pkg/state"
	"github.com/icellan/bsvm/pkg/types"
	"github.com/icellan/bsvm/pkg/vm"
)

// OverlayNode is the main coordinator for the L2 overlay. It ties
// together EVM execution, state management, proving, and covenant
// tracking. In the single-node overlay (Milestone 5), it handles
// transaction submission, batch processing, and state management
// without BSV network connectivity.
type OverlayNode struct {
	config         OverlayConfig
	chainDB        *block.ChainDB
	stateDB        *state.StateDB
	rawDB          db.Database
	executor       *block.BlockExecutor
	prover         *prover.SP1Prover
	covenantMgr    *covenant.CovenantManager
	batcher        *Batcher
	txCache        *TxCache
	gasPriceOracle *GasPriceOracle
	parallelProver *prover.ParallelProver
	dsMonitor      *DoubleSpendMonitor
	circuitBreaker *CircuitBreaker
	raceDetector   *RaceDetector
	inboxMonitor   *InboxMonitor
	signer              types.Signer
	followerMode        bool
	confirmationWatcher *ConfirmationWatcher

	// Chain tips track the progress of the L2 chain.
	executionTip uint64 // latest executed L2 block
	provenTip    uint64 // latest proven block
	confirmedTip uint64 // latest block with 1-5 BSV confirmations
	finalizedTip uint64 // latest block with >= 6 BSV confirmations

	eventFeed *event.Feed

	mu sync.Mutex
}

// NewOverlayNode creates a new overlay node with the given components.
// It reads the current chain head from the ChainDB to initialise the
// execution tip. The state database is opened at the head state root.
func NewOverlayNode(
	config OverlayConfig,
	chainDB *block.ChainDB,
	database db.Database,
	covenantMgr *covenant.CovenantManager,
	sp1Prover *prover.SP1Prover,
) (*OverlayNode, error) {
	// Read the current head.
	headHeader := chainDB.ReadHeadHeader()
	if headHeader == nil {
		return nil, fmt.Errorf("no head header found in chain database")
	}
	// Ensure Number is non-nil (RLP may decode zero as nil for *big.Int).
	if headHeader.Number == nil {
		headHeader.Number = new(big.Int)
	}

	// Open state at the head root.
	stateDB, err := state.New(headHeader.StateRoot, database)
	if err != nil {
		return nil, fmt.Errorf("failed to open state at root %s: %w",
			headHeader.StateRoot.Hex(), err)
	}

	// Build the chain config.
	chainConfig := vm.DefaultL2Config(config.ChainID)

	// Create the block executor.
	executor := block.NewBlockExecutor(chainConfig, vm.Config{})

	// Create the parallel prover.
	var pp *prover.ParallelProver
	if sp1Prover != nil {
		pp = prover.NewParallelProver(sp1Prover, 1)
	}

	// Create the signer.
	signer := types.LatestSignerForChainID(big.NewInt(config.ChainID))

	// Initialise the node.
	node := &OverlayNode{
		config:         config,
		chainDB:        chainDB,
		stateDB:        stateDB,
		rawDB:          database,
		executor:       executor,
		prover:         sp1Prover,
		covenantMgr:    covenantMgr,
		gasPriceOracle: NewGasPriceOracle(config.MinGasPrice),
		parallelProver: pp,
		signer:         signer,
		executionTip:   headHeader.Number.Uint64(),
		eventFeed:      &event.Feed{},
		txCache: NewTxCache(ConfirmedState{
			StateRoot:  headHeader.StateRoot,
			L2BlockNum: headHeader.Number.Uint64(),
		}),
	}

	// Create the batcher.
	node.batcher = NewBatcher(node, config.MaxBatchSize, config.MaxBatchFlushDelay)

	// Create the double-spend monitor.
	node.dsMonitor = NewDoubleSpendMonitor(node)

	// Create the circuit breaker for EVM disagreement detection.
	node.circuitBreaker = NewCircuitBreaker(nil)

	// Create the inbox monitor for forced transaction inclusion.
	node.inboxMonitor = NewInboxMonitor()

	// Create the race detector for covenant advance race resolution.
	rd := NewRaceDetector(node)
	rd.OnRaceLost(func(event *CovenantAdvanceEvent) {
		if err := node.CascadeRollback(event); err != nil {
			slog.Error("cascade rollback failed", "error", err)
		}
		if rd.ShouldEnterFollowerMode() {
			node.EnterFollowerMode()
		}
	})
	rd.OnRaceWon(func(event *CovenantAdvanceEvent) {
		node.ExitFollowerMode()
	})
	node.raceDetector = rd

	return node, nil
}

// ExecutionTip returns the latest executed L2 block number.
func (n *OverlayNode) ExecutionTip() uint64 {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.executionTip
}

// ProvenTip returns the latest L2 block with a completed SP1 proof.
func (n *OverlayNode) ProvenTip() uint64 {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.provenTip
}

// ConfirmedTip returns the latest L2 block with 1-5 BSV confirmations.
func (n *OverlayNode) ConfirmedTip() uint64 {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.confirmedTip
}

// FinalizedTip returns the latest L2 block with >= 6 BSV confirmations.
func (n *OverlayNode) FinalizedTip() uint64 {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.finalizedTip
}

// SetConfirmedTip updates the confirmed tip. Called when a BSV transaction
// receives 1-5 confirmations.
func (n *OverlayNode) SetConfirmedTip(blockNum uint64) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.confirmedTip = blockNum
}

// SetFinalizedTip updates the finalized tip. Called when a BSV transaction
// receives at least 6 confirmations.
func (n *OverlayNode) SetFinalizedTip(blockNum uint64) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.finalizedTip = blockNum
}

// SubmitTransaction validates and adds a transaction to the batcher.
// It returns an error if validation fails or the batcher rejects the
// transaction (e.g., duplicate).
func (n *OverlayNode) SubmitTransaction(tx *types.Transaction) error {
	if err := n.ValidateTransaction(tx); err != nil {
		return fmt.Errorf("transaction validation failed: %w", err)
	}
	return n.batcher.Add(tx)
}

// ValidateTransaction checks whether a transaction is valid for
// inclusion in a batch. It verifies:
//   - Transaction signature (recovers sender)
//   - Nonce matches the sender's current nonce in state
//   - Sender has sufficient balance for gas * price + value
//   - Gas price meets the minimum gas price requirement
//   - Gas limit does not exceed block gas limit
func (n *OverlayNode) ValidateTransaction(tx *types.Transaction) error {
	// Validate gas price.
	if err := n.gasPriceOracle.ValidateGasPrice(tx); err != nil {
		return err
	}

	// Validate gas limit.
	if tx.Gas() > n.config.BlockGasLimit {
		return fmt.Errorf("transaction gas limit %d exceeds block gas limit %d",
			tx.Gas(), n.config.BlockGasLimit)
	}

	// Recover sender address (validates signature).
	from, err := types.Sender(n.signer, tx)
	if err != nil {
		return fmt.Errorf("invalid signature: %w", err)
	}

	// Check nonce.
	n.mu.Lock()
	stateNonce := n.stateDB.GetNonce(from)
	balance := n.stateDB.GetBalance(from)
	n.mu.Unlock()

	if tx.Nonce() != stateNonce {
		if tx.Nonce() < stateNonce {
			return fmt.Errorf("nonce too low: have %d, expected %d", tx.Nonce(), stateNonce)
		}
		return fmt.Errorf("nonce too high: have %d, expected %d", tx.Nonce(), stateNonce)
	}

	// Check balance: sender needs gas * gasPrice + value.
	cost := new(big.Int).Mul(new(big.Int).SetUint64(tx.Gas()), tx.GasPrice())
	cost.Add(cost, tx.Value().ToBig())

	if balance.ToBig().Cmp(cost) < 0 {
		return fmt.Errorf("insufficient funds: have %s, need %s", balance.ToBig(), cost)
	}

	return nil
}

// Batcher returns the node's transaction batcher.
func (n *OverlayNode) Batcher() *Batcher {
	return n.batcher
}

// TxCache returns the node's transaction cache.
func (n *OverlayNode) TxCacheRef() *TxCache {
	return n.txCache
}

// GasPriceOracle returns the node's gas price oracle.
func (n *OverlayNode) GasPriceOracleRef() *GasPriceOracle {
	return n.gasPriceOracle
}

// DSMonitor returns the node's double-spend monitor.
func (n *OverlayNode) DSMonitor() *DoubleSpendMonitor {
	return n.dsMonitor
}

// CircuitBreaker returns the node's circuit breaker for EVM disagreement
// detection.
func (n *OverlayNode) CircuitBreaker() *CircuitBreaker {
	return n.circuitBreaker
}

// RaceDetector returns the node's race detector for covenant advance race
// resolution.
func (n *OverlayNode) RaceDetector() *RaceDetector {
	return n.raceDetector
}

// InboxMonitor returns the node's inbox monitor for forced transaction
// inclusion tracking.
func (n *OverlayNode) InboxMonitor() *InboxMonitor {
	return n.inboxMonitor
}

// Config returns the node's configuration.
func (n *OverlayNode) Config() OverlayConfig {
	return n.config
}

// CovenantManager returns the node's covenant manager.
func (n *OverlayNode) CovenantManager() *covenant.CovenantManager {
	return n.covenantMgr
}

// EventFeed returns the node's event feed for subscribing to new heads.
func (n *OverlayNode) EventFeed() *event.Feed {
	return n.eventFeed
}

// StateDB returns the node's current state database. This is primarily
// used for testing and RPC queries.
func (n *OverlayNode) StateDB() *state.StateDB {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.stateDB
}

// ChainDB returns the node's chain database.
func (n *OverlayNode) ChainDB() *block.ChainDB {
	return n.chainDB
}

// GetHeader implements block.ChainContext for block hash lookups.
func (n *OverlayNode) GetHeader(hash types.Hash, number uint64) *block.L2Header {
	return n.chainDB.ReadHeader(hash, number)
}

// ReplayBatchData decodes batch data received from a peer and replays
// the transactions through the EVM. This is called during sync to
// bring the local state up to date with the network.
func (n *OverlayNode) ReplayBatchData(batchData []byte) error {
	batch, err := block.DecodeBatchData(batchData)
	if err != nil {
		return fmt.Errorf("failed to decode batch data: %w", err)
	}

	// Decode transactions from RLP.
	var txs []*types.Transaction
	for _, rlpTx := range batch.Transactions {
		tx := new(types.Transaction)
		if err := rlp.DecodeBytes(rlpTx, tx); err != nil {
			slog.Warn("skipping invalid transaction in batch replay", "error", err)
			continue
		}
		txs = append(txs, tx)
	}

	if len(txs) == 0 {
		return fmt.Errorf("no valid transactions in batch")
	}

	_, err = n.ProcessBatch(txs)
	return err
}

// StartConfirmationWatcher creates a ConfirmationWatcher bound to the given
// broadcast client and starts its polling loop in a background goroutine.
// Subsequent successful broadcasts in ProcessBatch will be tracked by this
// watcher. Calling StartConfirmationWatcher more than once replaces the
// previous watcher after stopping it.
func (n *OverlayNode) StartConfirmationWatcher(client covenant.BroadcastClient, interval time.Duration) {
	n.mu.Lock()
	old := n.confirmationWatcher
	n.mu.Unlock()
	if old != nil {
		old.Stop()
	}
	watcher := NewConfirmationWatcher(n, client, interval)
	n.mu.Lock()
	n.confirmationWatcher = watcher
	n.mu.Unlock()
	watcher.Start()
}

// ConfirmationWatcherRef returns the attached confirmation watcher, or nil.
func (n *OverlayNode) ConfirmationWatcherRef() *ConfirmationWatcher {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.confirmationWatcher
}

// Stop gracefully stops the overlay node and its components.
func (n *OverlayNode) Stop() {
	n.batcher.Stop()
	n.mu.Lock()
	watcher := n.confirmationWatcher
	n.mu.Unlock()
	if watcher != nil {
		watcher.Stop()
	}
}
