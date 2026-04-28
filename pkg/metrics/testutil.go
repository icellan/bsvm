package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

// CounterValue returns the current value of a prometheus.Counter for
// use in test assertions. Returns -1 when the metric cannot be sampled
// (only happens for zero-value test-helper inputs).
//
// This is exported solely for instrumentation smoke tests in the
// bridge / overlay / arc / chaintracks / whatsonchain / withdrawer
// packages — it lets each test confirm its instrumentation point is
// wired without depending on a /metrics scrape round-trip.
func CounterValue(c prometheus.Counter) float64 {
	if c == nil {
		return -1
	}
	var m dto.Metric
	if err := c.Write(&m); err != nil {
		return -1
	}
	if m.Counter == nil || m.Counter.Value == nil {
		return -1
	}
	return *m.Counter.Value
}

// HistogramSampleCount returns the number of observations recorded on
// a prometheus.Observer (Histogram). Useful as a test assertion that
// .Observe was called the expected number of times without binding to
// the bucket layout.
func HistogramSampleCount(o prometheus.Observer) uint64 {
	if o == nil {
		return 0
	}
	collector, ok := o.(prometheus.Metric)
	if !ok {
		return 0
	}
	var m dto.Metric
	if err := collector.Write(&m); err != nil {
		return 0
	}
	if m.Histogram == nil || m.Histogram.SampleCount == nil {
		return 0
	}
	return *m.Histogram.SampleCount
}

// GaugeValue returns the current value of a prometheus.Gauge for use
// in test assertions.
func GaugeValue(g prometheus.Gauge) float64 {
	if g == nil {
		return -1
	}
	var m dto.Metric
	if err := g.Write(&m); err != nil {
		return -1
	}
	if m.Gauge == nil || m.Gauge.Value == nil {
		return -1
	}
	return *m.Gauge.Value
}

// CounterVecValue returns the current value for a labelled counter
// inside a CounterVec, taking the registry's const-label values into
// account so callers don't have to remember the order. Returns -1 when
// the counter cannot be sampled.
func (c *Counters) CounterVecValue(vec *prometheus.CounterVec, labelValues ...string) float64 {
	if c == nil || vec == nil {
		return -1
	}
	all := append([]string{c.labels.NodeName, c.labels.ChainID}, labelValues...)
	return CounterValue(vec.WithLabelValues(all...))
}
