package metrics

import (
	"strconv"

	"github.com/prometheus/client_golang/prometheus"
)

// NetworkMetrics groups the per-process metrics for the spec-17 BSV
// networking stack: ARC broadcast, chaintracks reorgs, BEEF gossip.
//
// Subsystems construct one NetworkMetrics per Registry at startup
// and pass the pointer wherever they record observations. All counters
// are pre-registered so callers never trigger registration races.
//
// Recorder methods (ObserveARCBroadcastLatency, RecordBEEFAccepted,
// etc.) take care of supplying the const-label values so callers do
// not have to remember the WithLabelValues argument order.
type NetworkMetrics struct {
	labels Labels

	arcBroadcastLatency  *prometheus.HistogramVec
	arcBroadcastFailures *prometheus.CounterVec
	chaintracksReorgs    prometheus.Counter
	chaintracksTipHeight prometheus.Gauge
	beefReceived         *prometheus.CounterVec
	beefRejected         *prometheus.CounterVec
}

// NewNetworkMetrics registers every metric in the spec-17 networking
// stack against r and returns a populated NetworkMetrics.
func NewNetworkMetrics(r *Registry) *NetworkMetrics {
	return &NetworkMetrics{
		labels: r.labels,
		arcBroadcastLatency: r.HistogramVec(
			"bsvevm_arc_broadcast_latency_seconds",
			"Latency of ARC broadcast calls in seconds, labelled by ARC endpoint.",
			[]float64{0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10, 30, 60},
			"endpoint",
		),
		arcBroadcastFailures: r.CounterVec(
			"bsvevm_arc_broadcast_failures_total",
			"Total ARC broadcast failures by endpoint.",
			"endpoint",
		),
		chaintracksReorgs: r.Counter(
			"bsvevm_chaintracks_reorg_total",
			"Total reorg events surfaced by the chaintracks client.",
		),
		chaintracksTipHeight: r.Gauge(
			"bsvevm_chaintracks_tip_height",
			"Current chaintracks best-chain tip height.",
		),
		beefReceived: r.CounterVec(
			"bsvevm_beef_envelope_received_total",
			"Total BEEF gossip envelopes received, by intent.",
			"intent",
		),
		beefRejected: r.CounterVec(
			"bsvevm_beef_envelope_rejected_total",
			"Total BEEF gossip envelopes rejected, by intent and reason.",
			"intent", "reason",
		),
	}
}

// ObserveARCBroadcastLatency records a single ARC broadcast latency
// in seconds against the named endpoint.
func (m *NetworkMetrics) ObserveARCBroadcastLatency(endpoint string, seconds float64) {
	m.arcBroadcastLatency.WithLabelValues(m.labels.NodeName, m.labels.ChainID, endpoint).Observe(seconds)
}

// IncARCBroadcastFailure increments the ARC broadcast failure counter
// for the named endpoint.
func (m *NetworkMetrics) IncARCBroadcastFailure(endpoint string) {
	m.arcBroadcastFailures.WithLabelValues(m.labels.NodeName, m.labels.ChainID, endpoint).Inc()
}

// IncChaintracksReorg bumps the reorg counter.
func (m *NetworkMetrics) IncChaintracksReorg() {
	m.chaintracksReorgs.Inc()
}

// SetChaintracksTipHeight publishes the current tip height.
func (m *NetworkMetrics) SetChaintracksTipHeight(h uint64) {
	m.chaintracksTipHeight.Set(float64(h))
}

// RecordBEEFAccepted bumps the per-intent receive counter.
func (m *NetworkMetrics) RecordBEEFAccepted(intent byte) {
	m.beefReceived.WithLabelValues(m.labels.NodeName, m.labels.ChainID, strconv.Itoa(int(intent))).Inc()
}

// RecordBEEFRejected bumps the per-intent / per-reason reject counter.
func (m *NetworkMetrics) RecordBEEFRejected(intent byte, reason string) {
	m.beefRejected.WithLabelValues(m.labels.NodeName, m.labels.ChainID, strconv.Itoa(int(intent)), reason).Inc()
}
