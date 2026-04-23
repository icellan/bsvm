package overlay

import (
	"context"
	"fmt"
	"log/slog"
	"math/big"
	"sync"
	"time"

	"github.com/icellan/bsvm/internal/db"
	"github.com/icellan/bsvm/pkg/block"
	"github.com/icellan/bsvm/pkg/covenant"
	"github.com/icellan/bsvm/pkg/event"
	"github.com/icellan/bsvm/pkg/metrics"
	"github.com/icellan/bsvm/pkg/prover"
	"github.com/icellan/bsvm/pkg/state"
	"github.com/icellan/bsvm/pkg/types"
	"github.com/icellan/bsvm/pkg/vm"
)

// BlockAnnouncer is implemented by the network gossip manager to broadcast
// new block announcements after ProcessBatch completes.
type BlockAnnouncer interface {
	BroadcastBlockAnnounce(parentHash types.Hash, stateRoot types.Hash, txRoot types.Hash, number uint64, gasUsed uint64, timestamp uint64, txHashes []types.Hash) error
}

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
	circuitBreaker    *CircuitBreaker
	raceDetector      *RaceDetector
	inboxMonitor      *InboxMonitor
	executionVerifier *ExecutionVerifier
	signer              types.Signer
	followerMode        bool
	confirmationWatcher *ConfirmationWatcher

	// Chain tips track the progress of the L2 chain.
	executionTip uint64 // latest executed L2 block
	provenTip    uint64 // latest proven block
	confirmedTip uint64 // latest block with 1-5 BSV confirmations
	finalizedTip uint64 // latest block with >= 6 BSV confirmations

	// blockAnnouncer broadcasts new block announcements to the P2P network.
	// Set via SetBlockAnnouncer after construction.
	blockAnnouncer BlockAnnouncer

	// feeWallet pays BSV mining fees on covenant-advance transactions.
	// Attached post-construction via SetFeeWallet; nil in follower/test
	// setups where the node never broadcasts to BSV.
	feeWallet *FeeWallet

	// feeWalletReconciler is an optional background goroutine that
	// periodically re-syncs the fee wallet's UTXO set with the BSV
	// node's listunspent view. Attached via StartFeeWalletReconciler
	// after SetFeeWallet; nil when the node never broadcasts.
	feeWalletReconciler *FeeWalletReconciler

	eventFeed *event.Feed

	mu sync.Mutex
}

// NewOverlayNode creates a new overlay node with the given components.
// It reads the current chain head from the ChainDB to initialise the
// execution tip. The state database is opened at the head state root.
//
// This constructor skips observability wiring. Production nodes should
// use NewOverlayNodeWithObservability so Prometheus and OpenTelemetry
// get the prover + batcher signals.
func NewOverlayNode(
	config OverlayConfig,
	chainDB *block.ChainDB,
	database db.Database,
	covenantMgr *covenant.CovenantManager,
	sp1Prover *prover.SP1Prover,
) (*OverlayNode, error) {
	return NewOverlayNodeWithObservability(config, chainDB, database, covenantMgr, sp1Prover, nil)
}

// NewOverlayNodeWithObservability creates an OverlayNode wiring its
// prover and batcher subsystems to the supplied Prometheus registry.
// When registry is nil, metrics are silently dropped (test-friendly).
func NewOverlayNodeWithObservability(
	config OverlayConfig,
	chainDB *block.ChainDB,
	database db.Database,
	covenantMgr *covenant.CovenantManager,
	sp1Prover *prover.SP1Prover,
	registry *metrics.Registry,
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
		pp = prover.NewParallelProverWithObservability(sp1Prover, 1, registry)
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
	node.batcher = NewBatcherWithObservability(node, config.MaxBatchSize, config.MaxBatchFlushDelay, registry)

	// Create the double-spend monitor.
	node.dsMonitor = NewDoubleSpendMonitor(node)

	// Create the circuit breaker for EVM disagreement detection.
	node.circuitBreaker = NewCircuitBreaker(nil)

	// Create the inbox monitor for forced transaction inclusion.
	node.inboxMonitor = NewInboxMonitor()

	// Wire up the execution verifier so every peer-driven covenant advance
	// is re-executed against our local state before we accept it. Spec 11
	// requires every node to independently verify covenant advances as a
	// defence-in-depth check alongside the STARK proof.
	node.executionVerifier = NewExecutionVerifierFromNode(node)

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

// ParallelProverRef returns the node's parallel prover coordinator.
// May be nil when the node was constructed without an SP1 prover
// (follower-only mode or unit tests).
func (n *OverlayNode) ParallelProverRef() *prover.ParallelProver {
	return n.parallelProver
}

// ---------------------------------------------------------------------------
// admin RPC accessors (spec 15)
// ---------------------------------------------------------------------------
//
// These tiny wrappers expose the minimum state the admin_* handlers
// need without letting rpc/ reach into unrelated batcher / prover /
// network internals. Each returns zero values when the relevant
// subsystem is nil (follower mode / tests).

// BatcherPause pauses the batcher.
func (n *OverlayNode) BatcherPause() {
	if n.batcher != nil {
		n.batcher.Pause()
	}
}

// BatcherResume unpauses the batcher.
func (n *OverlayNode) BatcherResume() {
	if n.batcher != nil {
		n.batcher.Resume()
	}
}

// BatcherIsPaused reports the batcher pause state.
func (n *OverlayNode) BatcherIsPaused() bool {
	if n.batcher == nil {
		return false
	}
	return n.batcher.IsPaused()
}

// BatcherPendingCount returns the current pending-transaction count.
func (n *OverlayNode) BatcherPendingCount() int {
	if n.batcher == nil {
		return 0
	}
	return n.batcher.PendingCount()
}

// BatcherForceFlush triggers an immediate flush of the pending batch.
func (n *OverlayNode) BatcherForceFlush() error {
	if n.batcher == nil {
		return nil
	}
	return n.batcher.Flush()
}

// PeerSummary returns a summary of peers connected to this node.
// Returns an empty slice when the peer manager is not attached yet —
// this is the current state for every node because the network /
// gossip layer stays independent of the overlay package.
//
// A real implementation lands alongside spec 15 wallet-side work once
// a PeerManager accessor is added.
func (n *OverlayNode) PeerSummary() []RPCPeerSummary {
	return []RPCPeerSummary{}
}

// RPCPeerSummary is the shape returned by PeerSummary. Duplicated
// here (not imported from pkg/rpc) to avoid a dependency cycle: rpc
// already depends on overlay.
type RPCPeerSummary struct {
	PeerID        string `json:"peerId"`
	Address       string `json:"address"`
	Role          string `json:"role"`
	LastHeartbeat int64  `json:"lastHeartbeat"`
	BlocksBehind  int64  `json:"blocksBehind"`
}

// RuntimeConfigView is the admin-panel-facing snapshot of settings
// the operator can read (and eventually write) at runtime.
type RuntimeConfigView struct {
	ChainID             int64  `json:"chainId"`
	MinGasPriceWei      string `json:"minGasPriceWei"`
	MaxBatchSize        int    `json:"maxBatchSize"`
	MaxBatchFlushMs     int64  `json:"maxBatchFlushMs"`
	MaxSpeculativeDepth int    `json:"maxSpeculativeDepth"`
	ProveMode           string `json:"proveMode"`
	RestartRequired     bool   `json:"restartRequired"`
}

// RuntimeConfig returns a read-only snapshot of the overlay's
// runtime-relevant settings. Every field is currently marked as
// requiring a restart to change — the plan scopes live reload to a
// follow-up pass that adds per-field mutexes.
func (n *OverlayNode) RuntimeConfig() RuntimeConfigView {
	minGas := "0"
	if n.config.MinGasPrice != nil {
		minGas = n.config.MinGasPrice.String()
	}
	return RuntimeConfigView{
		ChainID:             n.config.ChainID,
		MinGasPriceWei:      minGas,
		MaxBatchSize:        n.config.MaxBatchSize,
		MaxBatchFlushMs:     n.config.MaxBatchFlushDelay.Milliseconds(),
		MaxSpeculativeDepth: n.config.MaxSpeculativeDepth,
		ProveMode:           n.config.ProveMode,
		RestartRequired:     true,
	}
}

// ProveMode returns the spec-16 proving mode the overlay was started
// with. Used by the admin auth middleware to gate the dev-bypass
// header.
func (n *OverlayNode) ProveMode() string {
	return n.config.ProveMode
}

// ProverMetrics returns a flat tuple of the parallel prover counters.
// A flat tuple (rather than a struct) keeps the rpc package free of
// the prover import and matches the shape that AdminAPI consumes.
func (n *OverlayNode) ProverMetrics() (mode string, workers, inFlight, queueDepth int, proofsStarted, proofsSucceeded, proofsFailed, avgMs uint64) {
	if n.parallelProver == nil {
		return "disabled", 0, 0, 0, 0, 0, 0, 0
	}
	m := n.parallelProver.Metrics()
	return m.Mode, m.Workers, m.InFlight, m.QueueDepth,
		m.ProofsStarted, m.ProofsSucceeded, m.ProofsFailed, m.AvgProveTimeMs
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

// ExecutionVerifier returns the node's execution verifier. Every covenant
// advance arriving from a peer is re-executed via this verifier as a
// defence-in-depth consistency check alongside the STARK proof.
func (n *OverlayNode) ExecutionVerifier() *ExecutionVerifier {
	return n.executionVerifier
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
// the transactions through the EVM using the producer's coinbase and
// timestamp. This is called during sync to bring the local state up
// to date with the network.
//
// The producer's coinbase/timestamp — not the local node's config —
// are used, otherwise followers would compute different state roots
// than the producer for the same batch.
func (n *OverlayNode) ReplayBatchData(batchData []byte) error {
	batch, err := block.DecodeBatchData(batchData)
	if err != nil {
		return fmt.Errorf("failed to decode batch data: %w", err)
	}

	_, err = n.ReplayBatch(batch)
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

// SubmitDepositTx applies a deposit system transaction directly to the
// current state. Called by the bridge monitor when it detects a confirmed
// BSV deposit. The deposit bypasses the EVM — it is a direct balance
// credit to the recipient address.
func (n *OverlayNode) SubmitDepositTx(tx *types.DepositTransaction) error {
	n.mu.Lock()
	defer n.mu.Unlock()

	parentHeader := n.chainDB.ReadHeaderByNumber(n.executionTip)
	if parentHeader == nil {
		return fmt.Errorf("parent header not found for block %d", n.executionTip)
	}

	block.ApplyDepositTx(n.stateDB, parentHeader, tx)

	newRoot, err := n.stateDB.Commit(false)
	if err != nil {
		return fmt.Errorf("state commit after deposit: %w", err)
	}

	newStateDB, err := state.New(newRoot, n.rawDB)
	if err != nil {
		return fmt.Errorf("re-open state after deposit: %w", err)
	}
	n.stateDB = newStateDB

	slog.Info("applied deposit",
		"to", tx.To.Hex(),
		"value", tx.Value.String(),
		"sourceHash", tx.SourceHash.Hex(),
	)
	return nil
}

// SetBlockAnnouncer wires the gossip manager's block announcement
// broadcaster into the overlay. Called by cmd/bsvm after both the overlay
// and the gossip manager are constructed.
func (n *OverlayNode) SetBlockAnnouncer(a BlockAnnouncer) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.blockAnnouncer = a
}

// SetFeeWallet attaches a BSV fee wallet to the overlay node so the
// covenant broadcast path can pay for covenant-advance transactions.
// Safe to call once at startup after NewOverlayNode. Passing nil clears
// the attachment.
func (n *OverlayNode) SetFeeWallet(fw *FeeWallet) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.feeWallet = fw
}

// FeeWallet returns the attached fee wallet, or nil when none has been
// wired. Read by the reconciler and bsvAPI; callers must tolerate nil.
func (n *OverlayNode) FeeWallet() *FeeWallet {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.feeWallet
}

// StartFeeWalletReconciler kicks off a background goroutine that keeps
// the fee wallet in sync with the configured BSV node's listunspent
// view. Safe to call once after SetFeeWallet. No-op if the fee wallet
// is not attached. Calling it more than once stops the previous
// reconciler before starting a new one so an operator can switch the
// poll interval or the UtxoSource without restarting the node.
func (n *OverlayNode) StartFeeWalletReconciler(src UtxoSource, address string, interval time.Duration) {
	fw := n.FeeWallet()
	if fw == nil {
		return
	}
	n.mu.Lock()
	old := n.feeWalletReconciler
	n.mu.Unlock()
	if old != nil {
		stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		old.Stop(stopCtx)
		cancel()
	}

	recon := NewFeeWalletReconciler(fw, src, address, interval)
	// Pass a background context — the reconciler also responds to Stop
	// via its own stopCh, so the overlay's Stop() path can tear it down
	// cleanly without plumbing a node-wide context through NewOverlayNode.
	recon.Start(context.Background())
	n.mu.Lock()
	n.feeWalletReconciler = recon
	n.mu.Unlock()
}

// FeeWalletReconcilerRef returns the attached reconciler, or nil. Used
// by tests to inspect reconciler state without exposing the field.
func (n *OverlayNode) FeeWalletReconcilerRef() *FeeWalletReconciler {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.feeWalletReconciler
}

// Stop gracefully stops the overlay node and its components.
func (n *OverlayNode) Stop() {
	n.batcher.Stop()
	n.mu.Lock()
	watcher := n.confirmationWatcher
	reconciler := n.feeWalletReconciler
	n.mu.Unlock()
	if watcher != nil {
		watcher.Stop()
	}
	if reconciler != nil {
		// Bound the teardown at 5s so a wedged goroutine can't hang
		// Stop. The reconciler's poll loop only blocks on a single
		// HTTP round-trip which is capped by the provider's own
		// timeout, so this is defence-in-depth rather than the primary
		// bound.
		stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		reconciler.Stop(stopCtx)
		cancel()
	}
}
