package whatsonchain

import (
	"context"
	"errors"
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
func (s *stubClient) Ping(ctx context.Context) error                    { return nil }

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
