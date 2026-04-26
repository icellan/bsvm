package overlay

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log/slog"
	"math/big"
	"time"

	"github.com/icellan/bsvm/pkg/block"
	"github.com/icellan/bsvm/pkg/covenant"
	"github.com/icellan/bsvm/pkg/crypto"
	"github.com/icellan/bsvm/pkg/prover"
	"github.com/icellan/bsvm/pkg/rlp"
	"github.com/icellan/bsvm/pkg/state"
	"github.com/icellan/bsvm/pkg/types"
)

// withdrawalInitiatedTopic mirrors pkg/block/system_tx.go's
// withdrawalInitiatedTopic. It is recomputed here (rather than exported
// from pkg/block) to keep overlay's dependency surface unchanged.
var withdrawalInitiatedTopic = types.BytesToHash(crypto.Keccak256(
	[]byte("WithdrawalInitiated(uint256,bytes20,uint256,bytes32)"),
))

// withdrawalNonceSlot mirrors pkg/bridge.WithdrawalNonceSlot (slot 2 in
// the L2Bridge predeploy storage layout). Inlined here to avoid pulling
// pkg/bridge into pkg/overlay's import graph.
var withdrawalNonceSlot = types.HexToHash(
	"0x0000000000000000000000000000000000000000000000000000000000000002",
)

// beUint64 reads an 8-byte big-endian uint64 from b. Returns 0 if b is
// not exactly 8 bytes long.
func beUint64(b []byte) uint64 {
	if len(b) != 8 {
		return 0
	}
	return binary.BigEndian.Uint64(b)
}

// extractWithdrawals scans the batch's receipts for the bridge predeploy's
// WithdrawalInitiated logs and returns the withdrawals in emission order.
//
// Log layout (see pkg/block/system_tx.go::ApplyWithdrawTx):
//
//	topic[0] = keccak256("WithdrawalInitiated(uint256,bytes20,uint256,bytes32)")
//	topic[1] = indexed sender (32-byte left-padded address)
//	data     = bsvAddr (32-byte right-padded bytes20)
//	         || weiAmount (uint256 BE)
//	         || withdrawalHash (32 bytes)
//
// The bridge stores the satoshi-denominated leaf at withdrawalHashes[nonce]
// in storage, computed as hash256(bsvAddr || satoshis_be || nonce_be). We
// reconstruct (recipient, satoshis, nonce) from the emission order: nonce
// is the index after RecordWithdrawal increments it (the i-th log in the
// batch carries the nonce as it appeared at emission time, i.e. the nonce
// recorded in topic ordering is monotonically increasing within the batch).
//
// Because the synthetic log doesn't include the nonce as a topic, we
// recover it from the on-chain bridge contract's withdrawalNonce slot:
// the slot is incremented once per withdrawal and the last N values
// before the post-state correspond to this batch's withdrawals. To stay
// pure-functional and avoid reading state here, we encode the nonce as
// the order-of-emission relative to the bridge's pre-batch nonce, which
// the caller supplies.
func extractWithdrawals(receipts []*types.Receipt, baseNonce uint64) []prover.Withdrawal {
	var out []prover.Withdrawal
	idx := uint64(0)
	for _, r := range receipts {
		if r == nil {
			continue
		}
		for _, log := range r.Logs {
			if log == nil || log.Address != types.BridgeContractAddress {
				continue
			}
			if len(log.Topics) == 0 || log.Topics[0] != withdrawalInitiatedTopic {
				continue
			}
			// Need at minimum: 32 (bsvAddr padded) + 32 (weiAmount) bytes.
			if len(log.Data) < 64 {
				slog.Warn("withdrawal log data too short", "len", len(log.Data))
				continue
			}
			var recipient types.Address
			copy(recipient[:], log.Data[0:20])

			// weiAmount is a uint256 BE; convert to satoshis the same way
			// ApplyWithdrawTx did so the leaf hash matches.
			weiBytes := log.Data[32:64]
			satoshis := weiBytesToSatoshis(weiBytes)

			out = append(out, prover.Withdrawal{
				Recipient:      recipient,
				AmountSatoshis: satoshis,
				Nonce:          baseNonce + idx,
			})
			idx++
		}
	}
	return out
}

// weiBytesToSatoshis interprets a 32-byte big-endian wei amount and
// converts it to satoshis (floor division by 10^10). Mirrors
// types.WeiToSatoshis but operates on raw bytes from a log, avoiding a
// uint256 allocation per log.
func weiBytesToSatoshis(b []byte) uint64 {
	if len(b) != 32 {
		return 0
	}
	// Anything in the top 24 bytes saturates uint64 sat space.
	for i := 0; i < 24; i++ {
		if b[i] != 0 {
			// A wei amount that needs more than 8 bytes will produce a
			// satoshi count larger than uint64. The bridge enforces a
			// per-period rate limit so this is unreachable in practice;
			// surface it via the satoshi truncation rules anyway.
			weiHi := binary.BigEndian.Uint64(b[16:24])
			weiLo := binary.BigEndian.Uint64(b[24:32])
			// Try a 128-bit / 10^10 division: if the high word is
			// non-zero, the satoshi count exceeds uint64.
			if weiHi == 0 {
				return weiLo / 10_000_000_000
			}
			return ^uint64(0) // saturate
		}
	}
	wei := binary.BigEndian.Uint64(b[24:32])
	return wei / 10_000_000_000
}

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
// This is the producer path: the node's configured coinbase is credited,
// and the block timestamp is derived deterministically from the parent
// header and the configured block interval. Any forced inbox
// transactions are drained and prepended to the batch.
//
// For replaying a peer-produced batch (sync path), use ReplayBatch
// instead so the producer's coinbase and timestamp are used verbatim.
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

	// Check if forced inbox inclusion is required. Producer-only: on the
	// replay path the batch already contains whatever the producer chose
	// to include.
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

	// Derive the block timestamp deterministically from parent + interval.
	// Spec 11/12: every node (and the SP1 guest) must land on the same
	// block hash, so the timestamp cannot come from wall-clock time.
	parentHeader := n.chainDB.ReadHeaderByNumber(n.executionTip)
	if parentHeader == nil {
		return nil, fmt.Errorf("parent header not found for block %d", n.executionTip)
	}
	interval := n.config.BlockInterval
	if interval == 0 {
		interval = 1
	}
	timestamp := parentHeader.Timestamp + interval

	return n.processBatchInternal(n.config.Coinbase, timestamp, txs)
}

// ReplayBatch re-executes a batch produced by a peer, reusing the
// producer's coinbase and timestamp verbatim. This is the sync path:
// the local node's config.Coinbase and local clock are ignored so that
// every node derives the same post-state root from the same batch
// bytes.
//
// The caller must hold no locks; this method acquires n.mu internally.
//
// Returns an error if the batch timestamp is not strictly greater than
// the parent header's timestamp (replays must advance time monotonically,
// matching the invariant ProcessBatch enforces on producers).
func (n *OverlayNode) ReplayBatch(batch *block.BatchData) (*ProcessResult, error) {
	n.mu.Lock()
	defer n.mu.Unlock()

	if batch == nil {
		return nil, fmt.Errorf("nil batch")
	}

	// Decode transactions from RLP.
	txs := make([]*types.Transaction, 0, len(batch.Transactions))
	for _, rlpTx := range batch.Transactions {
		tx := new(types.Transaction)
		if err := rlp.DecodeBytes(rlpTx, tx); err != nil {
			slog.Warn("skipping invalid transaction in batch replay", "error", err)
			continue
		}
		txs = append(txs, tx)
	}
	if len(txs) == 0 {
		return nil, fmt.Errorf("no valid transactions in replay batch")
	}

	// Validate the replay timestamp advances monotonically against our
	// current tip's parent header. Out-of-order replays are rejected so
	// a malformed gossip message can't corrupt the local chain.
	parentHeader := n.chainDB.ReadHeaderByNumber(n.executionTip)
	if parentHeader == nil {
		return nil, fmt.Errorf("parent header not found for block %d", n.executionTip)
	}
	if batch.Timestamp <= parentHeader.Timestamp {
		return nil, fmt.Errorf("replay batch timestamp %d not greater than parent timestamp %d",
			batch.Timestamp, parentHeader.Timestamp)
	}

	return n.processBatchInternal(batch.Coinbase, batch.Timestamp, txs)
}

// processBatchInternal is the shared execution core for ProcessBatch
// (producer) and ReplayBatch (follower sync). Caller MUST hold n.mu.
// The coinbase and timestamp parameters are applied verbatim — the
// caller is responsible for picking producer-path or replay-path values.
func (n *OverlayNode) processBatchInternal(
	coinbase types.Address,
	timestamp uint64,
	txs []*types.Transaction,
) (*ProcessResult, error) {
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

	// Capture inbox root BEFORE execution so we have the true "before"
	// state for the SP1 public values. On the producer path any forced
	// inbox drain has already happened in ProcessBatch before this call.
	var inboxRootBefore types.Hash
	if n.inboxMonitor != nil {
		inboxRootBefore = n.inboxMonitor.QueueHash()
	}

	// 3. Execute via block.BlockExecutor.ProcessBatch using the caller-
	// supplied coinbase and timestamp. For replays these come verbatim
	// from the producer's batch data; for producer runs they are the
	// node's configured coinbase and parent+interval timestamp.
	l2Block, receipts, err := n.executor.ProcessBatch(
		parentHeader,
		coinbase,
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

	// Capture inbox root AFTER execution. inboxRootBefore was captured
	// above before the executor ran.
	var inboxRootAfter types.Hash
	if n.inboxMonitor != nil {
		inboxRootAfter = n.inboxMonitor.QueueHash()
	}

	// Read the bridge's pre-batch withdrawalNonce so we can assign each
	// log emitted in this batch the correct nonce, then scrape the
	// receipts for WithdrawalInitiated events. The SP1 guest folds these
	// into the withdrawalRoot at PublicValues offset 144; the bridge
	// covenant proves individual withdrawals against that root.
	var preBatchWithdrawalNonce uint64
	if preStateDB != nil {
		nonceHash := preStateDB.GetState(types.BridgeContractAddress, withdrawalNonceSlot)
		preBatchWithdrawalNonce = beUint64(nonceHash[24:32])
	}
	withdrawals := extractWithdrawals(receipts, preBatchWithdrawalNonce)

	proveInput := &prover.ProveInput{
		PreStateRoot:    preStateRoot,
		Transactions:    rlpTxs,
		InboxRootBefore: inboxRootBefore,
		InboxRootAfter:  inboxRootAfter,
		Withdrawals:     withdrawals,
		BlockContext: prover.BlockContext{
			Number:    l2Block.NumberU64(),
			Timestamp: l2Block.Time(),
			Coinbase:  coinbase,
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
		Coinbase:       coinbase,
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
				// processBatchInternal is documented to be called with
				// n.mu held, so the field read is already serialised
				// against StartConfirmationWatcher; reaching for the
				// public ConfirmationWatcherRef accessor here would
				// re-enter n.mu and deadlock.
				if w := n.confirmationWatcher; w != nil {
					w.Track(l2Block.NumberU64(), result.TxID)
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
