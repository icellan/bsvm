package metrics

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

func TestRegistry_LabelsAppliedToCounter(t *testing.T) {
	r := NewRegistry(Labels{NodeName: "node1", ChainID: "31337"})
	c := r.Counter("bsvm_test_counter", "help")
	c.Inc()
	c.Add(4)

	rec := httptest.NewRecorder()
	r.HTTPHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body := rec.Body.String()

	if !strings.Contains(body, `bsvm_test_counter{chain_id="31337",node_name="node1"} 5`) {
		t.Errorf("expected counter 5 with labels in scrape body, got:\n%s", body)
	}
}

func TestRegistry_CounterVecExtraLabels(t *testing.T) {
	r := NewRegistry(Labels{NodeName: "node2", ChainID: "31337"})
	vec := r.CounterVec("bsvm_test_status", "help", "status")

	vec.WithLabelValues("node2", "31337", "ok").Inc()
	vec.WithLabelValues("node2", "31337", "err").Add(2)

	rec := httptest.NewRecorder()
	r.HTTPHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body := rec.Body.String()

	if !strings.Contains(body, `bsvm_test_status{chain_id="31337",node_name="node2",status="ok"} 1`) {
		t.Errorf("expected ok=1 in body, got:\n%s", body)
	}
	if !strings.Contains(body, `bsvm_test_status{chain_id="31337",node_name="node2",status="err"} 2`) {
		t.Errorf("expected err=2 in body, got:\n%s", body)
	}
}

func TestRegistry_GaugeAndHistogram(t *testing.T) {
	r := NewRegistry(Labels{NodeName: "node1", ChainID: "31337"})
	g := r.Gauge("bsvm_test_gauge", "help")
	g.Set(42)

	h := r.Histogram("bsvm_test_hist", "help", []float64{0.1, 1, 10})
	h.Observe(0.5)
	h.Observe(5)

	rec := httptest.NewRecorder()
	r.HTTPHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body := rec.Body.String()

	if !strings.Contains(body, `bsvm_test_gauge{chain_id="31337",node_name="node1"} 42`) {
		t.Errorf("gauge missing in scrape: %s", body)
	}
	if !strings.Contains(body, `bsvm_test_hist_count{chain_id="31337",node_name="node1"} 2`) {
		t.Errorf("histogram count missing: %s", body)
	}
}

func TestRegistry_IsolatedBetweenInstances(t *testing.T) {
	// Two registries must have independent collector sets — otherwise
	// prometheus MustRegister would panic on the second call.
	r1 := NewRegistry(Labels{NodeName: "a", ChainID: "1"})
	r1.Counter("bsvm_isolation_check", "help")

	r2 := NewRegistry(Labels{NodeName: "b", ChainID: "2"})
	// Same metric name on a fresh registry must succeed.
	r2.Counter("bsvm_isolation_check", "help")
}

func TestRegistry_PromRegistryAccess(t *testing.T) {
	// PromRegistry should return the concrete *prometheus.Registry so
	// callers can register extra collectors (e.g. go runtime metrics).
	r := NewRegistry(Labels{NodeName: "a", ChainID: "1"})
	pr := r.PromRegistry()
	if pr == nil {
		t.Fatal("PromRegistry returned nil")
	}
	// Round-trip an extra collector to prove the pointer is live.
	c := prometheus.NewCounter(prometheus.CounterOpts{Name: "bsvm_external", Help: "help"})
	pr.MustRegister(c)
	c.Inc()

	rec := httptest.NewRecorder()
	r.HTTPHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body, _ := io.ReadAll(rec.Body)
	if !strings.Contains(string(body), "bsvm_external 1") {
		t.Errorf("external collector not scrapable: %s", body)
	}
}

func TestNoopRegistry_Usable(t *testing.T) {
	r := NoopRegistry()
	r.Counter("bsvm_noop_counter", "help").Inc()
	// Should not panic; scrape should succeed.
	rec := httptest.NewRecorder()
	r.HTTPHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("noop registry scrape failed: %d", rec.Code)
	}
}
