package arc

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/icellan/bsvm/pkg/metrics"
)

// TestClient_MetricsBroadcastAttempts confirms each Broadcast() call
// bumps ARCBroadcastAttemptsTotal by one, even when the request fails
// pre-response (transport error).
func TestClient_MetricsBroadcastAttempts(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Plain 502 with no terminal txStatus — IsTransient picks
		// 5xx; IsPermanent returns false because no terminal txStatus
		// is set and the Detail body doesn't carry a permanent-keyword.
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte(`{"extraInfo":"upstream timeout"}`))
	}))
	defer srv.Close()

	c, err := NewClient(Config{URL: srv.URL, Timeout: 2 * time.Second})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	counters := metrics.DisabledCounters()
	c.SetMetrics(counters)

	if _, err := c.Broadcast(context.Background(), []byte{0x01}); err == nil {
		t.Fatal("expected error from 502 response, got nil")
	}

	if got := metrics.CounterValue(counters.ARCBroadcastAttemptsTotal); got != 1 {
		t.Errorf("ARCBroadcastAttemptsTotal want 1 got %v", got)
	}
	// 502 with no terminal txStatus is transient.
	if got := counters.CounterVecValue(counters.ARCBroadcastFailedTotal, "transient"); got != 1 {
		t.Errorf("ARCBroadcastFailedTotal{transient} want 1 got %v", got)
	}
}

// TestClient_MetricsPermanentFailure confirms a REJECTED txStatus
// classifies as permanent.
func TestClient_MetricsPermanentFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"txStatus":"REJECTED","extraInfo":"bad-txns"}`))
	}))
	defer srv.Close()

	c, err := NewClient(Config{URL: srv.URL, Timeout: 2 * time.Second})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	counters := metrics.DisabledCounters()
	c.SetMetrics(counters)

	if _, err := c.Broadcast(context.Background(), []byte{0x01}); err == nil {
		t.Fatal("expected error from 400 REJECTED, got nil")
	}
	if got := counters.CounterVecValue(counters.ARCBroadcastFailedTotal, "permanent"); got != 1 {
		t.Errorf("ARCBroadcastFailedTotal{permanent} want 1 got %v", got)
	}
}
