package overlay

import (
	"sync"
	"time"

	"github.com/icellan/bsvm/pkg/prover"
	"github.com/icellan/bsvm/pkg/types"
)

// CachedTx represents a single covenant advance that has been prepared
// (and possibly broadcast) but not yet confirmed on BSV. It tracks the
// L2 block, state root, batch data, and proof output for the advance.
type CachedTx struct {
	// L2BlockNum is the L2 block number this advance commits.
	L2BlockNum uint64
	// StateRoot is the post-execution state root for this block.
	StateRoot types.Hash
	// BatchData is the encoded batch data for the OP_RETURN output.
	BatchData []byte
	// ProveOutput is the SP1 proof output, or nil if proving is still
	// in progress.
	ProveOutput *prover.ProveOutput
	// BroadcastAt is the time this advance was broadcast to BSV.
	BroadcastAt time.Time
	// Confirmed is true when the corresponding BSV transaction has been
	// included in a BSV block.
	Confirmed bool
}

// ConfirmedState represents the last BSV-confirmed covenant state. When
// the unconfirmed chain is empty, the confirmed state IS the current
// covenant UTXO.
type ConfirmedState struct {
	// StateRoot is the state root at the confirmed block.
	StateRoot types.Hash
	// L2BlockNum is the L2 block number at the confirmed state.
	L2BlockNum uint64
}

// TxCache tracks the chain of unconfirmed covenant advances. It is the
// source of truth for the current state until BSV confirms them. The
// chain is ordered: index 0 is the oldest unconfirmed entry, and the
// last entry is the most recent.
type TxCache struct {
	mu           sync.RWMutex
	chain        []*CachedTx
	confirmedTip ConfirmedState
	byL2Block    map[uint64]*CachedTx
}

// NewTxCache creates a new transaction cache initialised with the given
// confirmed state.
func NewTxCache(confirmedState ConfirmedState) *TxCache {
	return &TxCache{
		confirmedTip: confirmedState,
		byL2Block:    make(map[uint64]*CachedTx),
	}
}

// Tip returns the current covenant state root and L2 block number.
// If there are unconfirmed entries, it returns the tip of the
// unconfirmed chain. Otherwise it returns the confirmed state.
func (c *TxCache) Tip() (types.Hash, uint64) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if len(c.chain) > 0 {
		tip := c.chain[len(c.chain)-1]
		return tip.StateRoot, tip.L2BlockNum
	}
	return c.confirmedTip.StateRoot, c.confirmedTip.L2BlockNum
}

// Append adds a newly prepared covenant advance to the unconfirmed chain.
func (c *TxCache) Append(entry *CachedTx) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.chain = append(c.chain, entry)
	c.byL2Block[entry.L2BlockNum] = entry
}

// Confirm marks all entries up to and including the given L2 block
// number as confirmed. Confirmed entries are removed from the
// unconfirmed chain and the confirmed tip is updated.
func (c *TxCache) Confirm(upToBlock uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()

	idx := -1
	for i, entry := range c.chain {
		if entry.L2BlockNum == upToBlock {
			idx = i
			break
		}
	}
	if idx < 0 {
		return
	}

	// Update confirmed tip.
	confirmed := c.chain[idx]
	c.confirmedTip = ConfirmedState{
		StateRoot:  confirmed.StateRoot,
		L2BlockNum: confirmed.L2BlockNum,
	}

	// Remove confirmed entries from the lookup map.
	for i := 0; i <= idx; i++ {
		delete(c.byL2Block, c.chain[i].L2BlockNum)
	}

	// Trim the chain.
	c.chain = c.chain[idx+1:]
}

// Len returns the total number of entries in the unconfirmed chain.
func (c *TxCache) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.chain)
}

// SpeculativeDepth returns the number of unconfirmed (speculative)
// entries in the cache. This is used to enforce MaxSpeculativeDepth.
func (c *TxCache) SpeculativeDepth() int {
	c.mu.RLock()
	defer c.mu.RUnlock()

	count := 0
	for _, entry := range c.chain {
		if !entry.Confirmed {
			count++
		}
	}
	return count
}

// ConfirmedTip returns the current confirmed state.
func (c *TxCache) ConfirmedTip() ConfirmedState {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.confirmedTip
}

// GetByL2Block returns the cached entry for the given L2 block number,
// or nil if not found in the unconfirmed chain.
func (c *TxCache) GetByL2Block(blockNum uint64) *CachedTx {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.byL2Block[blockNum]
}

// Truncate removes all entries from the unconfirmed chain that have an
// L2 block number greater than the given block number. This is used
// during rollback.
func (c *TxCache) Truncate(afterBlock uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()

	idx := -1
	for i, entry := range c.chain {
		if entry.L2BlockNum > afterBlock {
			idx = i
			break
		}
	}
	if idx < 0 {
		return
	}

	// Remove truncated entries from lookup.
	for i := idx; i < len(c.chain); i++ {
		delete(c.byL2Block, c.chain[i].L2BlockNum)
	}

	c.chain = c.chain[:idx]
}
