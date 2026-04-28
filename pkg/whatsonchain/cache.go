// cache.go: in-process caching wrapper around a WhatsOnChainClient.
//
// WhatsOnChain (WoC) is rate-limited per IP. The cache wrapper
// memoises content-addressed lookups so repeated requests for the
// same immutable artefact (a transaction, a sealed header, a Merkle
// proof) consume our WoC budget exactly once. Mutable lookups
// (chain tip, UTXO sets, fee estimates) are passed through unchanged.
//
// The wrapper layers two protections:
//
//  1. A bounded LRU cache per content-addressed method (size capped
//     at construction). Cache HIT short-circuits the upstream call.
//  2. A singleflight gate so N concurrent requests for the same key
//     coalesce to ONE upstream RTT, with each waiter receiving the
//     same result.
//
// Errors are NEVER cached: a transient WoC 5xx for txid X must not
// poison the wrapper into refusing to retry.
//
// The wrapper composes WhatsOnChainClient → WhatsOnChainClient so it
// drops cleanly into the existing NetworkClient wiring (see
// pkg/bsvclient/network.go).

package whatsonchain

import (
	"container/list"
	"context"
	"sync"

	"github.com/icellan/bsvm/pkg/metrics"
)

// CacheConfig configures a CachedClient. Each cache size is the
// maximum number of entries before LRU eviction. Zero or negative
// values disable that cache (calls pass through to upstream).
type CacheConfig struct {
	// TxCacheSize bounds the GetTx cache. Default 1000.
	TxCacheSize int
	// BlockTxIDsCacheSize bounds the GetBlockTxIDs cache. Default 64.
	// Each entry holds the full aggregated txid manifest for a block —
	// content-addressed and immutable, so caching is safe and skips
	// both the header roundtrip and (for paginated blocks) every page
	// fetch on repeat lookups.
	BlockTxIDsCacheSize int
	// BlockPageCacheSize bounds the per-page LRU used by the paginated
	// GetBlockTxIDs path. Each entry is a single page's flat slice of
	// big-endian hex txid strings; pages are content-addressed by their
	// URI so the cache is safe across blocks. Default 256.
	BlockPageCacheSize int
}

// DefaultCacheConfig returns the standard cache bounds.
func DefaultCacheConfig() CacheConfig {
	return CacheConfig{
		TxCacheSize:         1000,
		BlockTxIDsCacheSize: 64,
		BlockPageCacheSize:  256,
	}
}

// CachedClient wraps a WhatsOnChainClient with per-method LRU caches
// and singleflight de-duplication. The wrapper is safe for concurrent
// use.
type CachedClient struct {
	upstream WhatsOnChainClient

	txCache *lruCache
	txGroup *singleflightGroup

	blockTxIDsCache *lruCache
	blockTxIDsGroup *singleflightGroup

	blockPageCache *lruCache
	blockPageGroup *singleflightGroup

	// metrics is the daemon-wide Prometheus counter set. Always
	// non-nil after NewCachedClient; SetMetrics replaces it.
	metrics *metrics.Counters
}

// SetMetrics swaps the cache's Counters pointer. Pass the daemon's
// shared *metrics.Counters at boot to enable per-layer hit / miss
// counters; passing nil falls back to a fresh no-op registry so .Inc()
// stays safe.
func (c *CachedClient) SetMetrics(m *metrics.Counters) {
	if m == nil {
		c.metrics = metrics.DisabledCounters()
		return
	}
	c.metrics = m
}

// NewCachedClient wraps upstream with the cache configured by cfg.
// Passing the zero CacheConfig disables all caches and the wrapper
// becomes a transparent passthrough — useful for tests that want the
// wrapper interface without the caching behaviour.
func NewCachedClient(upstream WhatsOnChainClient, cfg CacheConfig) *CachedClient {
	c := &CachedClient{upstream: upstream, metrics: metrics.DisabledCounters()}
	if cfg.TxCacheSize > 0 {
		c.txCache = newLRU(cfg.TxCacheSize)
		c.txGroup = newSingleflightGroup()
	}
	if cfg.BlockTxIDsCacheSize > 0 {
		c.blockTxIDsCache = newLRU(cfg.BlockTxIDsCacheSize)
		c.blockTxIDsGroup = newSingleflightGroup()
	}
	if cfg.BlockPageCacheSize > 0 {
		c.blockPageCache = newLRU(cfg.BlockPageCacheSize)
		c.blockPageGroup = newSingleflightGroup()
	}
	return c
}

// GetTx returns the raw transaction bytes for txid. Cache HIT skips
// the WoC call entirely. Concurrent requests for the same txid
// collapse to a single upstream call. Errors are not cached.
func (c *CachedClient) GetTx(ctx context.Context, txid [32]byte) ([]byte, error) {
	if c.txCache == nil {
		return c.upstream.GetTx(ctx, txid)
	}
	key := string(txid[:])
	if v, ok := c.txCache.get(key); ok {
		c.metrics.IncWoCCacheHit("tx")
		// Defensive copy: callers may mutate the returned slice (e.g.
		// re-encode). The cache stores the canonical immutable bytes.
		raw := v.([]byte)
		out := make([]byte, len(raw))
		copy(out, raw)
		return out, nil
	}
	c.metrics.IncWoCCacheMiss("tx")
	v, err := c.txGroup.do(key, func() (any, error) {
		// Re-check the cache under the singleflight gate: another
		// caller may have populated it while we were queued.
		if cached, ok := c.txCache.get(key); ok {
			return cached, nil
		}
		raw, err := c.upstream.GetTx(ctx, txid)
		if err != nil {
			return nil, err
		}
		// Store an immutable copy.
		stored := make([]byte, len(raw))
		copy(stored, raw)
		c.txCache.put(key, stored)
		return stored, nil
	})
	if err != nil {
		return nil, err
	}
	raw := v.([]byte)
	out := make([]byte, len(raw))
	copy(out, raw)
	return out, nil
}

// GetUTXOs is intentionally NOT cached — UTXO sets are mutable.
// Calls pass straight through to upstream.
func (c *CachedClient) GetUTXOs(ctx context.Context, address string) ([]UTXO, error) {
	return c.upstream.GetUTXOs(ctx, address)
}

// GetBlockTxIDs returns the txid manifest for a block, with two layers
// of caching:
//
//  1. A block-level LRU keyed on block-hash. The block→txids list is
//     content-addressed (a sealed block's manifest never changes), so
//     a HIT skips both the header roundtrip and any paginated page
//     fetches the upstream would otherwise perform.
//  2. A per-page LRU keyed on the page URI, used only when the upstream
//     is a *Client (the canonical implementation). Pages are stable
//     content-addressed lookups in their own right; caching them
//     amortises the cost when the block-level cache misses (e.g. an
//     adjacent block in a hot scan range that shares no pages with
//     this one — the overhead is bounded by BlockPageCacheSize).
//
// Singleflight collapses concurrent requests for the same block into
// a single upstream call, mirroring the GetTx posture.
func (c *CachedClient) GetBlockTxIDs(ctx context.Context, blockHash [32]byte) ([][32]byte, error) {
	if c.blockTxIDsCache == nil {
		return c.upstream.GetBlockTxIDs(ctx, blockHash)
	}
	key := string(blockHash[:])
	if v, ok := c.blockTxIDsCache.get(key); ok {
		c.metrics.IncWoCCacheHit("block")
		return cloneTxIDs(v.([][32]byte)), nil
	}
	c.metrics.IncWoCCacheMiss("block")
	v, err := c.blockTxIDsGroup.do(key, func() (any, error) {
		// Re-check under the singleflight gate.
		if cached, ok := c.blockTxIDsCache.get(key); ok {
			return cached, nil
		}
		out, err := c.fetchBlockTxIDs(ctx, blockHash)
		if err != nil {
			return nil, err
		}
		// Store an immutable copy.
		stored := cloneTxIDs(out)
		c.blockTxIDsCache.put(key, stored)
		return stored, nil
	})
	if err != nil {
		return nil, err
	}
	return cloneTxIDs(v.([][32]byte)), nil
}

// fetchBlockTxIDs is the upstream-resolved fetch path used on a cache
// MISS. When the upstream is a *Client we drive its paginated path
// with a singleflight+LRU-backed page fetcher; otherwise we fall back
// to the upstream's GetBlockTxIDs (which is what stub clients in tests
// implement directly).
func (c *CachedClient) fetchBlockTxIDs(ctx context.Context, blockHash [32]byte) ([][32]byte, error) {
	if real, ok := c.upstream.(*Client); ok {
		return real.getBlockTxIDsWithPageFetcher(ctx, blockHash, c.cachedPageFetch)
	}
	return c.upstream.GetBlockTxIDs(ctx, blockHash)
}

// cachedPageFetch wraps a single paginated-page fetch with the page
// LRU + singleflight. Each page URI is a content-addressed lookup so
// hits are always safe to serve from cache.
func (c *CachedClient) cachedPageFetch(ctx context.Context, real *Client, pageURI string) ([]string, error) {
	if c.blockPageCache == nil {
		return fetchBlockPage(ctx, real, pageURI)
	}
	if v, ok := c.blockPageCache.get(pageURI); ok {
		c.metrics.IncWoCCacheHit("page")
		return cloneStrings(v.([]string)), nil
	}
	c.metrics.IncWoCCacheMiss("page")
	v, err := c.blockPageGroup.do(pageURI, func() (any, error) {
		if cached, ok := c.blockPageCache.get(pageURI); ok {
			return cached, nil
		}
		ids, err := fetchBlockPage(ctx, real, pageURI)
		if err != nil {
			return nil, err
		}
		stored := cloneStrings(ids)
		c.blockPageCache.put(pageURI, stored)
		return stored, nil
	})
	if err != nil {
		return nil, err
	}
	return cloneStrings(v.([]string)), nil
}

// cloneTxIDs returns an independent copy of in. The cache stores
// immutable canonical bytes; the wrapper hands callers their own copy
// so they can sort/append without corrupting the cached value.
func cloneTxIDs(in [][32]byte) [][32]byte {
	out := make([][32]byte, len(in))
	copy(out, in)
	return out
}

// cloneStrings returns an independent copy of in. Same rationale as
// cloneTxIDs.
func cloneStrings(in []string) []string {
	out := make([]string, len(in))
	copy(out, in)
	return out
}

// ChainInfo is intentionally NOT cached — the tip moves with each
// new block.
func (c *CachedClient) ChainInfo(ctx context.Context) (*ChainInfo, error) {
	return c.upstream.ChainInfo(ctx)
}

// Ping is intentionally NOT cached — it is a liveness probe.
func (c *CachedClient) Ping(ctx context.Context) error {
	return c.upstream.Ping(ctx)
}

// compile-time check that CachedClient satisfies WhatsOnChainClient.
var _ WhatsOnChainClient = (*CachedClient)(nil)

// ---------------------------------------------------------------------
// lruCache: bounded LRU keyed on string. Concurrency-safe.
// ---------------------------------------------------------------------

type lruEntry struct {
	key   string
	value any
}

type lruCache struct {
	mu       sync.Mutex
	capacity int
	ll       *list.List               // front = most recently used
	idx      map[string]*list.Element // key → list element pointing at lruEntry
}

func newLRU(capacity int) *lruCache {
	return &lruCache{
		capacity: capacity,
		ll:       list.New(),
		idx:      make(map[string]*list.Element, capacity),
	}
}

func (c *lruCache) get(key string) (any, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.idx[key]
	if !ok {
		return nil, false
	}
	c.ll.MoveToFront(el)
	return el.Value.(*lruEntry).value, true
}

func (c *lruCache) put(key string, value any) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.idx[key]; ok {
		el.Value.(*lruEntry).value = value
		c.ll.MoveToFront(el)
		return
	}
	el := c.ll.PushFront(&lruEntry{key: key, value: value})
	c.idx[key] = el
	if c.ll.Len() > c.capacity {
		oldest := c.ll.Back()
		if oldest != nil {
			c.ll.Remove(oldest)
			delete(c.idx, oldest.Value.(*lruEntry).key)
		}
	}
}

// len returns the current number of entries. Useful for tests.
func (c *lruCache) len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ll.Len()
}

// ---------------------------------------------------------------------
// singleflightGroup: minimal singleflight, modelled on
// golang.org/x/sync/singleflight but trimmed to the API we need.
// ---------------------------------------------------------------------

type singleflightCall struct {
	wg  sync.WaitGroup
	val any
	err error
}

type singleflightGroup struct {
	mu sync.Mutex
	m  map[string]*singleflightCall
}

func newSingleflightGroup() *singleflightGroup {
	return &singleflightGroup{m: make(map[string]*singleflightCall)}
}

// do runs fn for key, ensuring that concurrent callers for the same
// key share a single execution. The first caller runs fn; subsequent
// callers block until it returns and receive the same (val, err).
func (g *singleflightGroup) do(key string, fn func() (any, error)) (any, error) {
	g.mu.Lock()
	if c, ok := g.m[key]; ok {
		g.mu.Unlock()
		c.wg.Wait()
		return c.val, c.err
	}
	c := &singleflightCall{}
	c.wg.Add(1)
	g.m[key] = c
	g.mu.Unlock()

	c.val, c.err = fn()
	c.wg.Done()

	g.mu.Lock()
	delete(g.m, key)
	g.mu.Unlock()

	return c.val, c.err
}
