package overlay

import (
	"fmt"
	"sync"

	"github.com/icellan/bsvm/pkg/types"
)

// ConflictResult describes a detected covenant UTXO conflict where
// another node has spent the covenant UTXO that this node expected
// to spend.
type ConflictResult struct {
	// CompetingTxID is the BSV transaction ID of the competing
	// covenant advance.
	CompetingTxID types.Hash
	// WinnerBatch is the encoded batch data from the winner's
	// OP_RETURN output.
	WinnerBatch []byte
	// L2BlockNum is the L2 block number the winner advanced to.
	L2BlockNum uint64
}

// BSVClient is an interface for querying the BSV network for double-spend
// detection. Implementations must provide the ability to look up spending
// transactions for a given UTXO.
type BSVClient interface {
	// GetSpendingTx returns the transaction that spent the given UTXO.
	// Returns nil if the UTXO is unspent. Returns an error on network failure.
	GetSpendingTx(txid types.Hash, vout uint32) (spendingTxID *types.Hash, batchData []byte, l2BlockNum uint64, err error)
}

// DoubleSpendMonitor detects when the covenant UTXO expected to be
// spent by this node was already spent by another node.
type DoubleSpendMonitor struct {
	node      *OverlayNode
	bsvClient BSVClient // nil until BSV connectivity is wired in
	mu        sync.Mutex
	// knownConflicts tracks UTXO conflicts already detected and handled,
	// keyed by the expected TxID, to avoid reprocessing the same conflict.
	knownConflicts map[types.Hash]struct{}
}

// NewDoubleSpendMonitor creates a new double-spend monitor for the
// given overlay node.
func NewDoubleSpendMonitor(node *OverlayNode) *DoubleSpendMonitor {
	return &DoubleSpendMonitor{
		node:           node,
		knownConflicts: make(map[types.Hash]struct{}),
	}
}

// SetBSVClient sets the BSV client used for on-chain lookups. When nil,
// CheckForConflict returns no conflict (single-node mode).
func (m *DoubleSpendMonitor) SetBSVClient(client BSVClient) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.bsvClient = client
}

// CheckForConflict checks if the covenant UTXO this node expected
// to spend was already spent by another node. When a BSV client is
// configured, it queries the BSV node for the spending transaction.
// If the spending tx differs from what we broadcast, it returns a
// ConflictResult with the winner's batch data.
func (m *DoubleSpendMonitor) CheckForConflict(expectedTxID types.Hash) (*ConflictResult, error) {
	m.mu.Lock()
	client := m.bsvClient
	m.mu.Unlock()

	if client == nil {
		// No BSV client connected -- single-node mode, no conflicts possible.
		return nil, nil
	}

	// Check if we already processed this conflict.
	m.mu.Lock()
	if _, known := m.knownConflicts[expectedTxID]; known {
		m.mu.Unlock()
		return nil, nil
	}
	m.mu.Unlock()

	// Query the BSV node for the spending transaction of the covenant UTXO.
	cm := m.node.CovenantManager()
	spendingTxID, batchData, l2BlockNum, err := client.GetSpendingTx(expectedTxID, cm.CurrentVout())
	if err != nil {
		return nil, fmt.Errorf("bsv client error: %w", err)
	}

	if spendingTxID == nil {
		// UTXO is unspent -- no conflict.
		return nil, nil
	}

	if *spendingTxID == expectedTxID {
		// We spent it ourselves -- no conflict.
		return nil, nil
	}

	// Conflict detected: another node spent the UTXO.
	m.mu.Lock()
	m.knownConflicts[expectedTxID] = struct{}{}
	m.mu.Unlock()

	return &ConflictResult{
		CompetingTxID: *spendingTxID,
		WinnerBatch:   batchData,
		L2BlockNum:    l2BlockNum,
	}, nil
}
