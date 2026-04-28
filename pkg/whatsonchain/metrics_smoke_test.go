package whatsonchain

import (
	"context"
	"testing"

	"github.com/icellan/bsvm/pkg/metrics"
)

// TestCachedClient_MetricsTxLayer confirms GetTx hits / misses both
// fire on the tx layer counters when a fresh Counters is wired.
func TestCachedClient_MetricsTxLayer(t *testing.T) {
	stub := newStub()
	stub.tx[string(make([]byte, 32))] = []byte{0xde, 0xad, 0xbe, 0xef}
	c := NewCachedClient(stub, DefaultCacheConfig())
	counters := metrics.DisabledCounters()
	c.SetMetrics(counters)

	ctx := context.Background()
	var txid [32]byte

	// First call: miss.
	if _, err := c.GetTx(ctx, txid); err != nil {
		t.Fatalf("GetTx miss: %v", err)
	}
	if got := counters.CounterVecValue(counters.WoCCacheMissesTotal, "tx"); got != 1 {
		t.Errorf("WoCCacheMissesTotal{tx} want 1 got %v", got)
	}

	// Second call: hit.
	if _, err := c.GetTx(ctx, txid); err != nil {
		t.Fatalf("GetTx hit: %v", err)
	}
	if got := counters.CounterVecValue(counters.WoCCacheHitsTotal, "tx"); got != 1 {
		t.Errorf("WoCCacheHitsTotal{tx} want 1 got %v", got)
	}
}
