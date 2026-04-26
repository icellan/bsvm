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
)

// CacheConfig configures a CachedClient. Each cache size is the
// maximum number of entries before LRU eviction. Zero or negative
// values disable that cache (calls pass through to upstream).
type CacheConfig struct {
	// TxCacheSize bounds the GetTx cache. Default 1000.
	TxCacheSize int
}

// DefaultCacheConfig returns the standard cache bounds.
func DefaultCacheConfig() CacheConfig {
	return CacheConfig{TxCacheSize: 1000}
}

// CachedClient wraps a WhatsOnChainClient with per-method LRU caches
// and singleflight de-duplication. The wrapper is safe for concurrent
// use.
type CachedClient struct {
	upstream WhatsOnChainClient

	txCache *lruCache
	txGroup *singleflightGroup
}

// NewCachedClient wraps upstream with the cache configured by cfg.
// Passing the zero CacheConfig disables all caches and the wrapper
// becomes a transparent passthrough — useful for tests that want the
// wrapper interface without the caching behaviour.
func NewCachedClient(upstream WhatsOnChainClient, cfg CacheConfig) *CachedClient {
	c := &CachedClient{upstream: upstream}
	if cfg.TxCacheSize > 0 {
		c.txCache = newLRU(cfg.TxCacheSize)
		c.txGroup = newSingleflightGroup()
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
		// Defensive copy: callers may mutate the returned slice (e.g.
		// re-encode). The cache stores the canonical immutable bytes.
		raw := v.([]byte)
		out := make([]byte, len(raw))
		copy(out, raw)
		return out, nil
	}
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
