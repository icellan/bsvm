package covenant

import (
	"container/list"
	"context"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/icellan/bsvm/pkg/types"
)

// BlockHeaderSource looks up the BSV block header (specifically its
// height) for a given block hash. It's the optional fallback the
// TxStatusReader uses when the primary getrawtransaction response gives
// us a blockhash but no blockheight — older SV-Node builds (pre-
// Teranode) don't populate the blockheight field, so we have to make a
// follow-up getblockheader call to recover the height.
//
// pkg/bsvclient.RPCProvider and pkg/bsvclient.MultiRPCProvider both
// satisfy this via their GetBlockHeader method.
type BlockHeaderSource interface {
	// GetBlockHeader returns the verbose getblockheader response for
	// the given block hash. The response shape mirrors bitcoind's
	// getblockheader verbose=1 schema; only the "height" field is read
	// by TxStatusReader.
	GetBlockHeader(blockHash string) (map[string]interface{}, error)
}

// TxStatusReader is the standalone helper that turns a
// (ConfirmationSource, BlockHeaderSource) pair into a
// TransactionStatusSource. It is the same parsing logic
// RunarBroadcastClient.GetTransactionStatus uses internally; factoring
// it out lets non-broadcast call sites (the `bsvm anchor-backfill`
// CLI subcommand, future operator tooling) read tx status without
// needing to construct a full broadcast client.
//
// On the legacy-fallback path the reader caches blockhash→height
// mappings in a small bounded LRU so a burst of concurrent
// confirmations referencing the same recent BSV block only triggers
// one getblockheader RPC. The cache is process-local — callers
// constructing multiple readers do NOT share entries.
type TxStatusReader struct {
	confirmations ConfirmationSource
	headers       BlockHeaderSource

	mu    sync.Mutex
	cache *blockHeightCache
}

// blockHeightCacheCapacity is the maximum number of blockhash→height
// entries the LRU holds. 256 is enough for ~256 distinct recent BSV
// blocks (≥ 40 hours of work at 10-min block times) and bounds the
// memory at < 64 KiB even if every key is a 64-char hex string.
const blockHeightCacheCapacity = 256

// NewTxStatusReader constructs a TxStatusReader. confirmations is
// required; headers is optional — when nil, the reader skips the
// getblockheader fallback and a confirmed tx whose getrawtransaction
// response omits blockheight surfaces height=0 to the caller (same as
// the pre-fallback behaviour).
func NewTxStatusReader(confirmations ConfirmationSource, headers BlockHeaderSource) *TxStatusReader {
	return &TxStatusReader{
		confirmations: confirmations,
		headers:       headers,
		cache:         newBlockHeightCache(blockHeightCacheCapacity),
	}
}

// GetTransactionStatus implements TransactionStatusSource. It runs the
// fast getrawtransaction verbose=1 path first; only when the response
// reports a blockhash WITHOUT a blockheight (i.e. the tx is mined but
// the node didn't tell us the height) does it fall through to the
// getblockheader fallback. Modern nodes (Teranode, recent SV-Node) take
// the fast path on every call and never invoke getblockheader.
func (r *TxStatusReader) GetTransactionStatus(_ context.Context, txid types.Hash) (TxStatus, error) {
	if r.confirmations == nil {
		return TxStatus{}, fmt.Errorf("nil ConfirmationSource")
	}
	// getrawtransaction expects BSV's big-endian display form; txid is
	// stored in chainhash little-endian bytes so reverse via BSVString.
	txidHex := txid.BSVString()
	raw, err := r.confirmations.GetRawTransactionVerbose(txidHex)
	if err != nil {
		return TxStatus{}, fmt.Errorf("getrawtransaction %s: %w", txidHex, err)
	}

	confs := parseUint32Field(raw, "confirmations")
	height := parseUint64Field(raw, "blockheight")

	// Fast path: modern node returned a height directly. Done.
	if height > 0 {
		return TxStatus{Confirmations: confs, BlockHeight: height}, nil
	}

	// Fallback path: the tx is reportedly mined (blockhash non-empty)
	// but the node didn't include blockheight. Resolve via
	// getblockheader, with a small LRU cache so a burst of confirmed
	// txs in the same block only round-trips once.
	blockHash := stringField(raw, "blockhash")
	if blockHash == "" || r.headers == nil {
		// Either the tx is unmined (blockhash empty) or the caller
		// explicitly opted out of the fallback by passing a nil
		// BlockHeaderSource. Surface what we have.
		return TxStatus{Confirmations: confs, BlockHeight: 0}, nil
	}

	height, err = r.lookupHeight(blockHash)
	if err != nil {
		// A getblockheader failure here is non-fatal for the caller —
		// the daemon's confirmation watcher already tolerates
		// height=0. Surface confirmations alone with the wrapped
		// error so logs can attribute the missing height.
		return TxStatus{Confirmations: confs, BlockHeight: 0},
			fmt.Errorf("getblockheader %s: %w", blockHash, err)
	}
	return TxStatus{Confirmations: confs, BlockHeight: height}, nil
}

// lookupHeight returns the block height for the given block hash,
// consulting the in-memory LRU first and only issuing a getblockheader
// RPC on miss.
func (r *TxStatusReader) lookupHeight(blockHash string) (uint64, error) {
	r.mu.Lock()
	if h, ok := r.cache.get(blockHash); ok {
		r.mu.Unlock()
		return h, nil
	}
	r.mu.Unlock()

	// RPC outside the lock — many concurrent callers may race here on
	// a cold cache. Each pays a redundant RPC; the cache stops them
	// after the first successful response. Fine for the use case
	// (256-entry hot set on a single confirmed-block burst).
	hdr, err := r.headers.GetBlockHeader(blockHash)
	if err != nil {
		return 0, err
	}
	h := parseUint64Field(hdr, "height")
	if h == 0 {
		return 0, fmt.Errorf("getblockheader %s returned height=0", blockHash)
	}

	r.mu.Lock()
	r.cache.put(blockHash, h)
	r.mu.Unlock()
	return h, nil
}

// stringField reads a string from a getrawtransaction-style map.
// Missing or non-string values return the empty string.
func stringField(m map[string]interface{}, key string) string {
	v, ok := m[key]
	if !ok || v == nil {
		return ""
	}
	s, _ := v.(string)
	return s
}

// parseUint32Field reads a JSON number field and returns it as a
// uint32. Missing / non-numeric / negative values produce zero.
func parseUint32Field(m map[string]interface{}, key string) uint32 {
	v, ok := m[key]
	if !ok || v == nil {
		return 0
	}
	switch n := v.(type) {
	case float64:
		if n > 0 {
			return uint32(n)
		}
	case json.Number:
		if f, err := n.Float64(); err == nil && f > 0 {
			return uint32(f)
		}
	}
	return 0
}

// parseUint64Field reads a JSON number field and returns it as a
// uint64. Missing / non-numeric / non-positive values produce zero.
func parseUint64Field(m map[string]interface{}, key string) uint64 {
	v, ok := m[key]
	if !ok || v == nil {
		return 0
	}
	switch n := v.(type) {
	case float64:
		if n > 0 {
			return uint64(n)
		}
	case json.Number:
		if f, err := n.Float64(); err == nil && f > 0 {
			return uint64(f)
		}
	}
	return 0
}

// blockHeightCache is a tiny doubly-linked-list LRU keyed by block
// hash. Not exported — callers always go through TxStatusReader.
type blockHeightCache struct {
	cap   int
	items map[string]*list.Element
	order *list.List
}

type blockHeightEntry struct {
	hash   string
	height uint64
}

func newBlockHeightCache(capacity int) *blockHeightCache {
	if capacity <= 0 {
		capacity = blockHeightCacheCapacity
	}
	return &blockHeightCache{
		cap:   capacity,
		items: make(map[string]*list.Element, capacity),
		order: list.New(),
	}
}

func (c *blockHeightCache) get(hash string) (uint64, bool) {
	el, ok := c.items[hash]
	if !ok {
		return 0, false
	}
	c.order.MoveToFront(el)
	return el.Value.(*blockHeightEntry).height, true
}

func (c *blockHeightCache) put(hash string, height uint64) {
	if el, ok := c.items[hash]; ok {
		el.Value.(*blockHeightEntry).height = height
		c.order.MoveToFront(el)
		return
	}
	if c.order.Len() >= c.cap {
		oldest := c.order.Back()
		if oldest != nil {
			delete(c.items, oldest.Value.(*blockHeightEntry).hash)
			c.order.Remove(oldest)
		}
	}
	el := c.order.PushFront(&blockHeightEntry{hash: hash, height: height})
	c.items[hash] = el
}

// Len returns the number of cached entries — used by tests to assert
// eviction behaviour.
func (c *blockHeightCache) Len() int { return c.order.Len() }
