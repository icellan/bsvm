// Package metrics exposes Prometheus metrics for BSVM node subsystems.
//
// Design:
//
//   - One shared *prometheus.Registry per node process. All BSVM-owned
//     metrics are registered here; nothing touches the default Go
//     runtime registry. Operators who want Go-runtime metrics can layer
//     them on top via a second registry and merge at scrape time.
//   - Each subsystem (prover, batcher, covenant, bridge) exports its
//     metrics by constructing them via this package's factories and
//     storing them on its own struct. Keeps import graph tight
//     (prover does NOT depend on pkg/rpc, but does depend on
//     pkg/metrics).
//   - The same counters back both the Prometheus `/metrics` scrape and
//     the JSON RPC snapshots (`bsv_provingStatus`, `admin_*`). That way
//     a UI polling RPC and a Grafana dashboard scraping `/metrics` see
//     the same numbers, without double-bookkeeping.
//
// Labels: every metric carries `node_name` (from BSVM_NODE_NAME env, or
// the shard ID prefix as fallback) and `chain_id`. Operators running
// multiple shards on the same Grafana see per-shard series
// automatically.
package metrics

import (
	"net/http"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Labels carries the node identity attached to every metric. Populated
// once at node startup from the shard config + env; passed to every
// subsystem constructor.
type Labels struct {
	// NodeName is a human-readable name for the node (BSVM_NODE_NAME or
	// shard-unique ID). Used to distinguish provers on the same shard.
	NodeName string
	// ChainID is the L2 chain ID as a decimal string. Identifies the
	// shard the metric belongs to.
	ChainID string
}

// ToMap returns the labels as a prometheus.Labels map for curried
// metric construction.
func (l Labels) ToMap() prometheus.Labels {
	return prometheus.Labels{
		"node_name": l.NodeName,
		"chain_id":  l.ChainID,
	}
}

// constLabelNames is the fixed label set every BSVM metric carries.
var constLabelNames = []string{"node_name", "chain_id"}

// Registry is the BSVM-scoped Prometheus registry. All metrics produced
// by this package are registered here. Goroutines MUST read Registry()
// rather than capturing a package-global so tests can reset the
// registry between cases.
type Registry struct {
	reg    *prometheus.Registry
	labels Labels
	mu     sync.Mutex
}

// NewRegistry returns a fresh Registry scoped to the given labels. The
// BSVM node creates exactly one of these at startup and passes it to
// each subsystem.
func NewRegistry(labels Labels) *Registry {
	return &Registry{
		reg:    prometheus.NewRegistry(),
		labels: labels,
	}
}

// PromRegistry returns the underlying Prometheus registry. Exposed for
// callers that need to register non-BSVM collectors (e.g. a test
// fixture).
func (r *Registry) PromRegistry() *prometheus.Registry {
	return r.reg
}

// Labels returns the constant label values applied to every metric.
func (r *Registry) Labels() Labels {
	return r.labels
}

// HTTPHandler returns an http.Handler that serves the Prometheus
// scrape endpoint for this registry. Mount it on `/metrics`.
func (r *Registry) HTTPHandler() http.Handler {
	return promhttp.HandlerFor(r.reg, promhttp.HandlerOpts{
		EnableOpenMetrics: true,
		Registry:          r.reg,
	})
}

// CounterVec creates a new *prometheus.CounterVec with the BSVM const
// labels (node_name, chain_id) plus any extra label names, registered
// against this Registry. Panics on re-registration (match Prometheus
// convention — duplicate metric definitions are a programmer bug).
func (r *Registry) CounterVec(name, help string, extraLabels ...string) *prometheus.CounterVec {
	r.mu.Lock()
	defer r.mu.Unlock()
	labels := append([]string{}, constLabelNames...)
	labels = append(labels, extraLabels...)
	c := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: name,
		Help: help,
	}, labels)
	r.reg.MustRegister(c)
	return c
}

// Counter creates a new *prometheus.Counter bound to the BSVM const
// labels. Equivalent to CounterVec(name, help).WithLabelValues(...).
func (r *Registry) Counter(name, help string) prometheus.Counter {
	return r.CounterVec(name, help).WithLabelValues(r.labels.NodeName, r.labels.ChainID)
}

// GaugeVec creates a new *prometheus.GaugeVec with the BSVM const
// labels plus any extra label names.
func (r *Registry) GaugeVec(name, help string, extraLabels ...string) *prometheus.GaugeVec {
	r.mu.Lock()
	defer r.mu.Unlock()
	labels := append([]string{}, constLabelNames...)
	labels = append(labels, extraLabels...)
	g := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: name,
		Help: help,
	}, labels)
	r.reg.MustRegister(g)
	return g
}

// Gauge creates a new *prometheus.Gauge bound to the BSVM const labels.
func (r *Registry) Gauge(name, help string) prometheus.Gauge {
	return r.GaugeVec(name, help).WithLabelValues(r.labels.NodeName, r.labels.ChainID)
}

// HistogramVec creates a new *prometheus.HistogramVec with the BSVM
// const labels plus any extra label names. Buckets should be chosen
// per-subsystem (proving is seconds; tx routing is milliseconds).
func (r *Registry) HistogramVec(name, help string, buckets []float64, extraLabels ...string) *prometheus.HistogramVec {
	r.mu.Lock()
	defer r.mu.Unlock()
	labels := append([]string{}, constLabelNames...)
	labels = append(labels, extraLabels...)
	h := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    name,
		Help:    help,
		Buckets: buckets,
	}, labels)
	r.reg.MustRegister(h)
	return h
}

// Histogram creates a new *prometheus.Histogram bound to the BSVM const
// labels with the given buckets.
func (r *Registry) Histogram(name, help string, buckets []float64) prometheus.Observer {
	return r.HistogramVec(name, help, buckets).WithLabelValues(r.labels.NodeName, r.labels.ChainID)
}

// NoopRegistry returns a Registry backed by a fresh Prometheus registry
// that is never scraped. Useful in tests that instantiate subsystems
// without wanting to worry about duplicate metric registration when the
// same test file constructs multiple instances.
func NoopRegistry() *Registry {
	return NewRegistry(Labels{NodeName: "test", ChainID: "0"})
}
