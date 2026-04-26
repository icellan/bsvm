package rpc

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/icellan/bsvm/pkg/metrics"
)

// TestMetricsEndpoint verifies that when a metrics registry is
// attached the RPC server exposes a Prometheus scrape endpoint at
// `/metrics` that returns HTTP 200 with text containing the metric
// names registered against that registry.
//
// Spec 15 §"Metrics" requires a Prometheus scrape surface; this test
// pins it to the public mux so a future refactor cannot regress the
// wiring without being noticed.
func TestMetricsEndpoint(t *testing.T) {
	ts := newTestSetup(t)
	defer ts.node.Stop()

	// Register a handful of metrics so the scrape body is non-empty
	// and we have a stable string to assert on. These names mirror
	// the production `bsvm_fee_wallet_*` namespace so the assertion
	// also doubles as a smoke test that the canonical naming
	// convention round-trips through promhttp.
	registry := metrics.NewRegistry(metrics.Labels{
		NodeName: "test-node",
		ChainID:  "1337",
	})
	balance := registry.Gauge(
		"bsvm_fee_wallet_balance_satoshis",
		"Spendable BSV satoshis currently available in the fee wallet (test).",
	)
	balance.Set(42)

	ts.server.SetMetricsRegistry(registry)
	handler := ts.server.buildHTTPHandler()

	t.Run("returns 200 with metric body", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("status code = %d, want 200", w.Code)
		}
		body, err := io.ReadAll(w.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		text := string(body)
		if !strings.Contains(text, "bsvm_fee_wallet_balance_satoshis") {
			t.Fatalf("expected scrape body to mention bsvm_fee_wallet_balance_satoshis, got:\n%s", text)
		}
		// Sanity-check the const labels survive the scrape.
		if !strings.Contains(text, `node_name="test-node"`) {
			t.Fatalf("expected node_name label in scrape body, got:\n%s", text)
		}
		if !strings.Contains(text, `chain_id="1337"`) {
			t.Fatalf("expected chain_id label in scrape body, got:\n%s", text)
		}
	})
}

// TestMetricsEndpoint_NotMountedWithoutRegistry confirms that a node
// which never calls SetMetricsRegistry does NOT expose `/metrics`.
// Without a registry the request falls through to the JSON-RPC root
// handler, which rejects GET requests with 405. This pins the
// "metrics surface is opt-in" invariant from spec 15.
func TestMetricsEndpoint_NotMountedWithoutRegistry(t *testing.T) {
	ts := newTestSetup(t)
	defer ts.node.Stop()

	handler := ts.server.buildHTTPHandler()

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	// The exact status depends on the fallback handler (webui SPA or
	// JSON-RPC dispatcher) — the load-bearing guarantee is just that
	// it is NOT a 200 OpenMetrics scrape. Anything in the 4xx family
	// is fine.
	if w.Code == http.StatusOK {
		body, _ := io.ReadAll(w.Body)
		if strings.Contains(string(body), "# HELP") || strings.Contains(string(body), "# TYPE") {
			t.Fatalf("unexpected Prometheus scrape body served when no registry attached: %s", body)
		}
	}
}
