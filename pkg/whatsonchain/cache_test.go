package whatsonchain

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// stubClient is an in-process WhatsOnChainClient for the cache tests.
// It records the number of upstream calls per txid and lets each test
// configure deterministic responses.
type stubClient struct {
	mu       sync.Mutex
	calls    map[string]int
	tx       map[string][]byte
	err      error
	gate     chan struct{} // when non-nil, GetTx blocks until this is closed
	gateOnce sync.Once
}

func newStub() *stubClient {
	return &stubClient{
		calls: make(map[string]int),
		tx:    make(map[string][]byte),
	}
}

func (s *stubClient) GetTx(ctx context.Context, txid [32]byte) ([]byte, error) {
	if s.gate != nil {
		<-s.gate
	}
	s.mu.Lock()
	s.calls[string(txid[:])]++
	raw, ok := s.tx[string(txid[:])]
	err := s.err
	s.mu.Unlock()
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, ErrNotFound
	}
	out := make([]byte, len(raw))
	copy(out, raw)
	return out, nil
}

func (s *stubClient) GetUTXOs(ctx context.Context, address string) ([]UTXO, error) {
	return nil, nil
}
func (s *stubClient) ChainInfo(ctx context.Context) (*ChainInfo, error) { return nil, nil }
func (s *stubClient) GetBlockTxIDs(ctx context.Context, blockHash [32]byte) ([][32]byte, error) {
	return nil, nil
}
func (s *stubClient) Ping(ctx context.Context) error { return nil }

func (s *stubClient) callsFor(txid [32]byte) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls[string(txid[:])]
}

func (s *stubClient) setTx(txid [32]byte, raw []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tx[string(txid[:])] = raw
}

func (s *stubClient) setErr(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.err = err
}

func (s *stubClient) openGate() {
	s.gateOnce.Do(func() { close(s.gate) })
}

func TestCachedClient_HitReusesValue(t *testing.T) {
	stub := newStub()
	var txid [32]byte
	for i := range txid {
		txid[i] = 0xab
	}
	stub.setTx(txid, []byte{0x01, 0x02, 0x03})

	c := NewCachedClient(stub, DefaultCacheConfig())

	// First call: cache MISS — upstream called once.
	got, err := c.GetTx(context.Background(), txid)
	if err != nil {
		t.Fatalf("first GetTx: %v", err)
	}
	if string(got) != "\x01\x02\x03" {
		t.Fatalf("first GetTx returned %x", got)
	}

	// Second call: cache HIT — upstream NOT called again.
	got2, err := c.GetTx(context.Background(), txid)
	if err != nil {
		t.Fatalf("second GetTx: %v", err)
	}
	if string(got2) != "\x01\x02\x03" {
		t.Fatalf("second GetTx returned %x", got2)
	}
	if calls := stub.callsFor(txid); calls != 1 {
		t.Fatalf("expected exactly 1 upstream call, got %d", calls)
	}

	// Returned slices must be independent copies — mutating one must
	// not corrupt the cached value.
	got2[0] = 0xff
	got3, _ := c.GetTx(context.Background(), txid)
	if got3[0] != 0x01 {
		t.Fatalf("cache returned a shared slice; mutation leaked: %x", got3)
	}
}

func TestCachedClient_SingleflightCollapses(t *testing.T) {
	stub := newStub()
	stub.gate = make(chan struct{})
	var txid [32]byte
	for i := range txid {
		txid[i] = 0x42
	}
	stub.setTx(txid, []byte{0xde, 0xad, 0xbe, 0xef})

	c := NewCachedClient(stub, DefaultCacheConfig())

	const N = 10
	var wg sync.WaitGroup
	var failures atomic.Int32
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			raw, err := c.GetTx(context.Background(), txid)
			if err != nil || len(raw) != 4 {
				failures.Add(1)
			}
		}()
	}
	// Give the goroutines time to enter the singleflight gate.
	time.Sleep(50 * time.Millisecond)
	stub.openGate()
	wg.Wait()

	if failures.Load() != 0 {
		t.Fatalf("%d concurrent callers failed", failures.Load())
	}
	if calls := stub.callsFor(txid); calls != 1 {
		t.Fatalf("singleflight failed: expected 1 upstream call, got %d", calls)
	}
}

func TestCachedClient_ErrorsNotCached(t *testing.T) {
	stub := newStub()
	var txid [32]byte
	for i := range txid {
		txid[i] = 0x99
	}
	// First the upstream errors, then it succeeds — the wrapper must
	// not have cached the error from the first call.
	wantErr := errors.New("woc: 503")
	stub.setErr(wantErr)

	c := NewCachedClient(stub, DefaultCacheConfig())

	if _, err := c.GetTx(context.Background(), txid); !errors.Is(err, wantErr) {
		t.Fatalf("first call: expected wantErr, got %v", err)
	}

	// Recover upstream and seed a value.
	stub.setErr(nil)
	stub.setTx(txid, []byte{0x10})

	got, err := c.GetTx(context.Background(), txid)
	if err != nil {
		t.Fatalf("retry after recovery: %v", err)
	}
	if len(got) != 1 || got[0] != 0x10 {
		t.Fatalf("retry returned wrong bytes: %x", got)
	}
	// Upstream must have been called twice — once erroring, once
	// succeeding.
	if calls := stub.callsFor(txid); calls != 2 {
		t.Fatalf("expected exactly 2 upstream calls (error not cached), got %d", calls)
	}
}

func TestCachedClient_NotFoundNotCached(t *testing.T) {
	// ErrNotFound is a flavour of error and must not be cached either.
	stub := newStub()
	var txid [32]byte
	for i := range txid {
		txid[i] = 0x55
	}

	c := NewCachedClient(stub, DefaultCacheConfig())

	if _, err := c.GetTx(context.Background(), txid); !errors.Is(err, ErrNotFound) {
		t.Fatalf("first call: expected ErrNotFound, got %v", err)
	}
	stub.setTx(txid, []byte{0x77})
	got, err := c.GetTx(context.Background(), txid)
	if err != nil {
		t.Fatalf("second call: %v", err)
	}
	if len(got) != 1 || got[0] != 0x77 {
		t.Fatalf("second call returned wrong bytes: %x", got)
	}
}

func TestCachedClient_MutableMethodsPassthrough(t *testing.T) {
	// GetUTXOs / ChainInfo / Ping must not be cached. We only assert
	// the wrapper forwards them to the upstream — content correctness
	// is the upstream's concern.
	stub := newStub()
	c := NewCachedClient(stub, DefaultCacheConfig())
	if _, err := c.GetUTXOs(context.Background(), "1abc"); err != nil {
		t.Fatalf("GetUTXOs: %v", err)
	}
	if _, err := c.ChainInfo(context.Background()); err != nil {
		t.Fatalf("ChainInfo: %v", err)
	}
	if err := c.Ping(context.Background()); err != nil {
		t.Fatalf("Ping: %v", err)
	}
}

func TestCachedClient_DisabledCachePassesThrough(t *testing.T) {
	stub := newStub()
	var txid [32]byte
	for i := range txid {
		txid[i] = 0x01
	}
	stub.setTx(txid, []byte{0x42})

	c := NewCachedClient(stub, CacheConfig{TxCacheSize: 0})
	for i := 0; i < 3; i++ {
		if _, err := c.GetTx(context.Background(), txid); err != nil {
			t.Fatalf("iter %d: %v", i, err)
		}
	}
	if calls := stub.callsFor(txid); calls != 3 {
		t.Fatalf("disabled cache should pass through every call; got %d upstream calls", calls)
	}
}

// TestCachedClient_GetBlockTxIDs_CacheHIT exercises the block-level
// LRU. A first call drives the underlying *Client through the
// paginated header→pages flow; a second call for the same block hash
// must hit the cache and skip the upstream entirely (zero new HTTP
// calls).
func TestCachedClient_GetBlockTxIDs_CacheHIT(t *testing.T) {
	pages := [][]string{
		{makeTxIDHex(0), makeTxIDHex(1)},
		{makeTxIDHex(2), makeTxIDHex(3)},
	}

	var headerHits, pageHits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(r.URL.Path, "/page/") {
			pageHits.Add(1)
			for i := range pages {
				if strings.HasSuffix(r.URL.Path, fmt.Sprintf("/page/%d", i+1)) {
					_ = json.NewEncoder(w).Encode(pages[i])
					return
				}
			}
			http.NotFound(w, r)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/block/hash/") {
			headerHits.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"tx":    []string{},
				"pages": map[string]any{"uri": []string{"/block/hash/test/page/1", "/block/hash/test/page/2"}},
			})
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	upstream, err := NewClient(Config{URL: srv.URL, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	cached := NewCachedClient(upstream, DefaultCacheConfig())

	var blockHash [32]byte
	for i := range blockHash {
		blockHash[i] = 0x77
	}

	// First call: cache MISS, full header + 2 page fetches.
	got1, err := cached.GetBlockTxIDs(context.Background(), blockHash)
	if err != nil {
		t.Fatalf("first GetBlockTxIDs: %v", err)
	}
	if len(got1) != 4 {
		t.Fatalf("first call returned %d txids, want 4", len(got1))
	}
	if h := headerHits.Load(); h != 1 {
		t.Fatalf("first call: header hits = %d, want 1", h)
	}
	if p := pageHits.Load(); p != 2 {
		t.Fatalf("first call: page hits = %d, want 2", p)
	}

	// Second call: cache HIT. No new server hits.
	got2, err := cached.GetBlockTxIDs(context.Background(), blockHash)
	if err != nil {
		t.Fatalf("second GetBlockTxIDs: %v", err)
	}
	if len(got2) != len(got1) {
		t.Fatalf("second call returned %d txids, want %d", len(got2), len(got1))
	}
	if h := headerHits.Load(); h != 1 {
		t.Fatalf("cache MISS on second call: header hits = %d, want 1", h)
	}
	if p := pageHits.Load(); p != 2 {
		t.Fatalf("cache MISS on second call: page hits = %d, want 2", p)
	}

	// Mutating got2 must not corrupt the cached value.
	got2[0] = [32]byte{}
	got3, _ := cached.GetBlockTxIDs(context.Background(), blockHash)
	if got3[0] == ([32]byte{}) {
		t.Fatalf("cache returned a shared slice; mutation leaked")
	}
}

// TestCachedClient_GetBlockTxIDs_PageCacheReuse asserts that the
// per-page LRU short-circuits page refetches across distinct block
// lookups. We drive two block-hash requests whose headers reference
// the same page URI (a synthetic but deterministic scenario) and
// verify the page handler is only hit once.
func TestCachedClient_GetBlockTxIDs_PageCacheReuse(t *testing.T) {
	pageData := []string{makeTxIDHex(100), makeTxIDHex(101)}

	var pageHits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/shared-page") {
			pageHits.Add(1)
			_ = json.NewEncoder(w).Encode(pageData)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/block/hash/") {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"tx":    []string{},
				"pages": map[string]any{"uri": []string{"/shared-page"}},
			})
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	upstream, err := NewClient(Config{URL: srv.URL, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	cached := NewCachedClient(upstream, DefaultCacheConfig())

	var blockA, blockB [32]byte
	for i := range blockA {
		blockA[i] = 0x10
		blockB[i] = 0x20
	}

	if _, err := cached.GetBlockTxIDs(context.Background(), blockA); err != nil {
		t.Fatalf("blockA: %v", err)
	}
	if _, err := cached.GetBlockTxIDs(context.Background(), blockB); err != nil {
		t.Fatalf("blockB: %v", err)
	}
	if got := pageHits.Load(); got != 1 {
		t.Fatalf("expected 1 page fetch (page LRU should dedupe), got %d", got)
	}
}

// stubBlockClient extends stubClient-style recording to GetBlockTxIDs
// so we can verify cache HITs against arbitrary upstream interfaces
// (not just *Client). The cache must fall back to upstream.GetBlockTxIDs
// when the upstream is a stub, and still cache the aggregated result.
type stubBlockClient struct {
	mu     sync.Mutex
	calls  int
	result [][32]byte
	err    error
}

func (s *stubBlockClient) GetTx(_ context.Context, _ [32]byte) ([]byte, error) {
	return nil, ErrNotFound
}
func (s *stubBlockClient) GetUTXOs(_ context.Context, _ string) ([]UTXO, error) { return nil, nil }
func (s *stubBlockClient) ChainInfo(_ context.Context) (*ChainInfo, error)      { return nil, nil }
func (s *stubBlockClient) GetBlockTxIDs(_ context.Context, _ [32]byte) ([][32]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	if s.err != nil {
		return nil, s.err
	}
	out := make([][32]byte, len(s.result))
	copy(out, s.result)
	return out, nil
}
func (s *stubBlockClient) Ping(_ context.Context) error { return nil }

func (s *stubBlockClient) callCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

func TestCachedClient_GetBlockTxIDs_UpstreamFallbackCachesResult(t *testing.T) {
	stub := &stubBlockClient{
		result: [][32]byte{
			{0x01}, {0x02}, {0x03},
		},
	}
	cached := NewCachedClient(stub, DefaultCacheConfig())
	var blockHash [32]byte
	for i := range blockHash {
		blockHash[i] = 0x55
	}

	for i := 0; i < 4; i++ {
		got, err := cached.GetBlockTxIDs(context.Background(), blockHash)
		if err != nil {
			t.Fatalf("iter %d: %v", i, err)
		}
		if len(got) != 3 {
			t.Fatalf("iter %d returned %d ids", i, len(got))
		}
	}
	if stub.callCount() != 1 {
		t.Fatalf("expected 1 upstream call (block-level cache), got %d", stub.callCount())
	}
}

// fakePagedBlockClient is an in-process upstream that satisfies BOTH
// PaginatedBlockTxIDsFetcher AND PageFetcher. It exists so the
// CachedClient can wrap a non-*Client upstream and still exercise the
// per-page LRU+singleflight path. The header response is simulated
// inline (no HTTP); FetchPage hands out canned per-URI responses and
// counts the call so tests can verify singleflight + cache HIT.
type fakePagedBlockClient struct {
	mu        sync.Mutex
	pageCalls map[string]int
	pages     map[string][]string // pageURI → flat hex txid list
	// blockPages maps blockHash → []pageURI (the manifest the upstream
	// would return from its `/block/hash/<hash>` header endpoint).
	blockPages map[[32]byte][]string
}

func newFakePagedBlockClient() *fakePagedBlockClient {
	return &fakePagedBlockClient{
		pageCalls:  make(map[string]int),
		pages:      make(map[string][]string),
		blockPages: make(map[[32]byte][]string),
	}
}

func (f *fakePagedBlockClient) GetTx(_ context.Context, _ [32]byte) ([]byte, error) {
	return nil, ErrNotFound
}
func (f *fakePagedBlockClient) GetUTXOs(_ context.Context, _ string) ([]UTXO, error) {
	return nil, nil
}
func (f *fakePagedBlockClient) ChainInfo(_ context.Context) (*ChainInfo, error) { return nil, nil }
func (f *fakePagedBlockClient) Ping(_ context.Context) error                    { return nil }

// GetBlockTxIDs is called when the cache falls back to the upstream
// without page caching; we drive the same orchestration here for
// parity with GetBlockTxIDsWithPageFetcher.
func (f *fakePagedBlockClient) GetBlockTxIDs(ctx context.Context, blockHash [32]byte) ([][32]byte, error) {
	return f.GetBlockTxIDsWithPageFetcher(ctx, blockHash, f)
}

// GetBlockTxIDsWithPageFetcher orchestrates header+pages using the
// supplied PageFetcher (which the cache wraps in its LRU+singleflight
// gate). Implements PaginatedBlockTxIDsFetcher.
func (f *fakePagedBlockClient) GetBlockTxIDsWithPageFetcher(ctx context.Context, blockHash [32]byte, pf PageFetcher) ([][32]byte, error) {
	f.mu.Lock()
	uris := append([]string(nil), f.blockPages[blockHash]...)
	f.mu.Unlock()
	out := make([][32]byte, 0, 8)
	for _, uri := range uris {
		ids, err := pf.FetchPage(ctx, uri)
		if err != nil {
			return nil, err
		}
		decoded, err := decodeBlockTxIDs(ids, blockTxIDsAbsoluteMax)
		if err != nil {
			return nil, err
		}
		out = append(out, decoded...)
	}
	return out, nil
}

// FetchPage implements PageFetcher. Counts calls per URI so tests can
// assert dedupe.
func (f *fakePagedBlockClient) FetchPage(_ context.Context, pageURI string) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pageCalls[pageURI]++
	ids, ok := f.pages[pageURI]
	if !ok {
		return nil, ErrNotFound
	}
	out := make([]string, len(ids))
	copy(out, ids)
	return out, nil
}

func (f *fakePagedBlockClient) callsFor(uri string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.pageCalls[uri]
}

func (f *fakePagedBlockClient) seedPage(uri string, ids []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	cp := make([]string, len(ids))
	copy(cp, ids)
	f.pages[uri] = cp
}

func (f *fakePagedBlockClient) seedBlock(blockHash [32]byte, pageURIs []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	cp := make([]string, len(pageURIs))
	copy(cp, pageURIs)
	f.blockPages[blockHash] = cp
}

// TestCachedClient_PageFetcherInterface_StubGetsPageCache asserts that
// a non-*Client upstream that implements PageFetcher +
// PaginatedBlockTxIDsFetcher gets the per-page LRU wrapping for free.
// A second fetch of the same page URI (driven by an adjacent block
// whose manifest shares the URI) must hit the cache and never call
// FetchPage again.
func TestCachedClient_PageFetcherInterface_StubGetsPageCache(t *testing.T) {
	stub := newFakePagedBlockClient()
	const sharedURI = "/block/hash/test/page/shared"
	stub.seedPage(sharedURI, []string{makeTxIDHex(1), makeTxIDHex(2)})

	var blockA, blockB [32]byte
	for i := range blockA {
		blockA[i] = 0xa1
		blockB[i] = 0xb2
	}
	stub.seedBlock(blockA, []string{sharedURI})
	stub.seedBlock(blockB, []string{sharedURI})

	cached := NewCachedClient(stub, DefaultCacheConfig())

	// First block lookup populates the per-page LRU.
	got, err := cached.GetBlockTxIDs(context.Background(), blockA)
	if err != nil {
		t.Fatalf("GetBlockTxIDs(A): %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("blockA returned %d ids, want 2", len(got))
	}
	if calls := stub.callsFor(sharedURI); calls != 1 {
		t.Fatalf("after blockA: page calls = %d, want 1", calls)
	}

	// Second block lookup against a DIFFERENT block hash whose manifest
	// references the same page URI. Block-level cache misses (different
	// key); page-level cache must HIT and skip the upstream FetchPage.
	got2, err := cached.GetBlockTxIDs(context.Background(), blockB)
	if err != nil {
		t.Fatalf("GetBlockTxIDs(B): %v", err)
	}
	if len(got2) != 2 {
		t.Fatalf("blockB returned %d ids, want 2", len(got2))
	}
	if calls := stub.callsFor(sharedURI); calls != 1 {
		t.Fatalf("after blockB: page calls = %d, want 1 (page LRU should dedupe across blocks via PageFetcher interface)", calls)
	}
}

// TestCachedClient_PageFetcherInterface_NoFetcherFallback asserts that
// an upstream that doesn't implement PageFetcher /
// PaginatedBlockTxIDsFetcher still works — block-level caching kicks
// in via the upstream.GetBlockTxIDs passthrough, and the page LRU is
// simply not exercised. (No regression vs the previous *Client
// type-assertion path.)
func TestCachedClient_PageFetcherInterface_NoFetcherFallback(t *testing.T) {
	stub := &stubBlockClient{
		result: [][32]byte{{0x11}, {0x22}},
	}
	cached := NewCachedClient(stub, DefaultCacheConfig())

	var blockHash [32]byte
	for i := range blockHash {
		blockHash[i] = 0xcc
	}

	for i := 0; i < 3; i++ {
		got, err := cached.GetBlockTxIDs(context.Background(), blockHash)
		if err != nil {
			t.Fatalf("iter %d: %v", i, err)
		}
		if len(got) != 2 {
			t.Fatalf("iter %d returned %d ids", i, len(got))
		}
	}
	if stub.callCount() != 1 {
		t.Fatalf("expected 1 upstream call (block-level cache), got %d", stub.callCount())
	}
}

// TestCachedClient_PageFetcherInterface_ClientImplements is a
// compile-time-style guard: *Client must continue to satisfy
// PageFetcher AND PaginatedBlockTxIDsFetcher so the production wiring
// keeps the per-page LRU.
func TestCachedClient_PageFetcherInterface_ClientImplements(t *testing.T) {
	var _ PageFetcher = (*Client)(nil)
	var _ PaginatedBlockTxIDsFetcher = (*Client)(nil)
}

// TestNoopPageFetcher_ReturnsErrNotFound asserts the documented stub
// behaviour: NoopPageFetcher always returns ErrNotFound. Tests that
// wire it must keep the header path inline (no pages.uri).
func TestNoopPageFetcher_ReturnsErrNotFound(t *testing.T) {
	pf := NoopPageFetcher()
	_, err := pf.FetchPage(context.Background(), "/any")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("NoopPageFetcher.FetchPage = %v, want ErrNotFound", err)
	}
}

func TestLRU_EvictsOldest(t *testing.T) {
	lru := newLRU(2)
	lru.put("a", 1)
	lru.put("b", 2)
	if lru.len() != 2 {
		t.Fatalf("len after 2 puts = %d", lru.len())
	}
	if _, ok := lru.get("a"); !ok {
		t.Fatalf("a should still be present")
	}
	// Now "a" is most recently used; inserting "c" must evict "b".
	lru.put("c", 3)
	if _, ok := lru.get("b"); ok {
		t.Fatalf("b should have been evicted")
	}
	if v, ok := lru.get("a"); !ok || v.(int) != 1 {
		t.Fatalf("a missing after eviction: ok=%v v=%v", ok, v)
	}
	if v, ok := lru.get("c"); !ok || v.(int) != 3 {
		t.Fatalf("c missing: ok=%v v=%v", ok, v)
	}
}
