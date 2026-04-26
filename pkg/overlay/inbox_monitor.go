package overlay

import (
	"crypto/sha256"
	"sync"

	"github.com/icellan/bsvm/pkg/types"
)

// MaxAdvancesWithoutInboxDrain is the maximum number of covenant advances
// allowed without draining pending inbox transactions. After this many
// advances, the next batch MUST include all pending inbox transactions.
const MaxAdvancesWithoutInboxDrain = 10

// InboxMonitor tracks the inbox covenant state and manages forced inclusion
// of inbox transactions. It watches for new inbox submissions on BSV and
// tracks how many advances have occurred since the last drain.
type InboxMonitor struct {
	mu sync.Mutex

	// Current inbox state.
	queueHash types.Hash
	txCount   uint64

	// Pending inbox transactions (in submission order).
	pendingTxs [][]byte // RLP-encoded transactions

	// Tracking for forced inclusion.
	advancesSinceLastDrain uint16
}

// NewInboxMonitor creates an InboxMonitor with an empty queue. The initial
// queue hash is hash256(zeroes(32)), matching the on-chain covenant genesis.
func NewInboxMonitor() *InboxMonitor {
	zeroes := make([]byte, 32)
	return &InboxMonitor{
		queueHash: hash256(zeroes),
	}
}

// AddInboxTransaction records a new transaction submitted to the inbox
// covenant on BSV. The txRLP is the raw RLP-encoded EVM transaction.
func (im *InboxMonitor) AddInboxTransaction(txRLP []byte) {
	im.mu.Lock()
	defer im.mu.Unlock()

	// Compute hash of the submitted transaction.
	txHash := hash256(txRLP)

	// Extend the hash chain: newRoot = hash256(oldRoot || txHash).
	combined := make([]byte, 0, types.HashLength+types.HashLength)
	combined = append(combined, im.queueHash[:]...)
	combined = append(combined, txHash[:]...)
	im.queueHash = hash256(combined)

	im.txCount++

	// Store a copy of the raw RLP.
	cp := make([]byte, len(txRLP))
	copy(cp, txRLP)
	im.pendingTxs = append(im.pendingTxs, cp)
}

// PendingCount returns the number of pending inbox transactions.
func (im *InboxMonitor) PendingCount() int {
	im.mu.Lock()
	defer im.mu.Unlock()
	return int(im.txCount)
}

// MustDrainInbox returns true if the next batch must include all pending
// inbox transactions (forced inclusion triggered). This is true when:
//   - At least MaxAdvancesWithoutInboxDrain advances have occurred since
//     the last drain, AND
//   - There are pending transactions in the inbox queue.
func (im *InboxMonitor) MustDrainInbox() bool {
	im.mu.Lock()
	defer im.mu.Unlock()
	return im.advancesSinceLastDrain >= MaxAdvancesWithoutInboxDrain && im.txCount > 0
}

// RecordAdvance increments the advance counter. Call after each covenant advance.
func (im *InboxMonitor) RecordAdvance() {
	im.mu.Lock()
	defer im.mu.Unlock()
	im.advancesSinceLastDrain++
}

// PendingTxsSnapshot returns a copy of the currently-queued inbox
// transactions WITHOUT mutating monitor state. Used by the prover witness
// builder to recompute the inbox chain root inside the SP1 guest (W4-3).
// Order matches submission order — identical to DrainPending output.
func (im *InboxMonitor) PendingTxsSnapshot() [][]byte {
	im.mu.Lock()
	defer im.mu.Unlock()
	out := make([][]byte, len(im.pendingTxs))
	for i, tx := range im.pendingTxs {
		cp := make([]byte, len(tx))
		copy(cp, tx)
		out[i] = cp
	}
	return out
}

// DrainPending returns all pending inbox transactions and resets the queue.
// Call when building a batch that includes inbox transactions.
func (im *InboxMonitor) DrainPending() [][]byte {
	im.mu.Lock()
	defer im.mu.Unlock()

	// Copy pending transactions.
	pending := make([][]byte, len(im.pendingTxs))
	copy(pending, im.pendingTxs)

	// Reset the queue to the empty state.
	zeroes := make([]byte, 32)
	im.queueHash = hash256(zeroes)
	im.txCount = 0
	im.advancesSinceLastDrain = 0
	im.pendingTxs = nil

	return pending
}

// AdvancesSinceDrain returns the number of advances since the last inbox drain.
func (im *InboxMonitor) AdvancesSinceDrain() uint16 {
	im.mu.Lock()
	defer im.mu.Unlock()
	return im.advancesSinceLastDrain
}

// QueueHash returns the current hash chain root.
func (im *InboxMonitor) QueueHash() types.Hash {
	im.mu.Lock()
	defer im.mu.Unlock()
	return im.queueHash
}

// hash256 computes double SHA-256 (BSV OP_HASH256).
func hash256(data []byte) types.Hash {
	first := sha256.Sum256(data)
	second := sha256.Sum256(first[:])
	return types.BytesToHash(second[:])
}
