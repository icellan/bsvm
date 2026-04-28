package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
)

// Counters is the shared per-process set of subsystem counters,
// histograms, and gauges that operator dashboards consume. It groups
// every metric the BSVM daemon ships in a single struct so subsystems
// (bridge monitor, ARC client, withdrawer, prover host, chaintracks
// hub, WoC cache) can be handed one pointer and call .Inc() / .Observe()
// directly without nil-checks.
//
// Construct via NewCounters(reg). For tests / zero-config code paths
// that want subsystems usable without a live Prometheus registry, call
// DisabledCounters() — every collector is wired to a fresh internal
// throwaway registry so .Inc() / .Observe() are still safe but the
// metrics never reach a /metrics scrape.
//
// Unlike NetworkMetrics (which carries the spec-17 subset and exposes
// recorder methods that pre-fold const labels), Counters exposes the
// raw collectors directly. Subsystems that already have a stable
// label-resolution helper (e.g. the WoC cache layer name) call
// .WithLabelValues() inline through the helper methods below
// (IncARCBroadcastFailed / IncWoCCacheHit / etc.).
type Counters struct {
	// labels is the (node_name, chain_id) tuple stamped onto every
	// metric produced by the registry that built this Counters. The
	// per-vec helper methods consult it so callers don't need to
	// supply the const-label values themselves.
	labels Labels

	// BridgeDepositsTotal counts deposits that have been persisted to the
	// bridge monitor's DB. Only successful PersistDeposit calls contribute.
	BridgeDepositsTotal prometheus.Counter

	// BridgeWithdrawalsClaimedTotal counts withdrawal claims that
	// reached the BSV broadcast path successfully (post-classifier
	// retry, returning nil from the broadcaster).
	BridgeWithdrawalsClaimedTotal prometheus.Counter

	// BridgeRetractsTotal counts RetractDepositsAbove invocations on the
	// bridge monitor, fired when chaintracks observes a reorg.
	BridgeRetractsTotal prometheus.Counter

	// OverlayBatchesAdvancedTotal counts successful covenant-advance
	// broadcasts emitted from the overlay's process-batch path.
	OverlayBatchesAdvancedTotal prometheus.Counter

	// OverlayStateRootMismatchTotal counts dual-EVM cross-check
	// disagreements (Go EVM vs Rust EVM post-state). Should be 0 on a
	// healthy node — operator dashboards must alert on any non-zero
	// rate.
	OverlayStateRootMismatchTotal prometheus.Counter

	// ProverProofDurationSeconds observes wall-clock time SP1 proving
	// takes per batch. Buckets cover 1s..600s — typical local proving
	// runs land between 30s and 300s on commodity hardware.
	ProverProofDurationSeconds prometheus.Observer

	// ProverProofSizeBytes observes the size of the SP1 proof bytes
	// returned by the host bridge. Buckets cover 1 KiB..16 MiB — the
	// VerifyFRI preset is ~850 KB, Groth16 wrapped proofs are ~1-2 KB.
	ProverProofSizeBytes prometheus.Observer

	// ChaintracksReorgsTotal counts reorg events surfaced by the
	// chaintracks stream hub. Does not count linear extensions
	// (acceptNewBlock); only true reorgs (acceptReorg).
	ChaintracksReorgsTotal prometheus.Counter

	// ChaintracksReconnectsTotal counts WS reconnect attempts in the
	// stream supervisor loop. Always >= 1 for a long-running node.
	ChaintracksReconnectsTotal prometheus.Counter

	// ARCBroadcastAttemptsTotal counts every ARC client Broadcast call.
	ARCBroadcastAttemptsTotal prometheus.Counter

	// ARCBroadcastFailedTotal counts ARC broadcast failures by class
	// (transient vs permanent), classified via arc.AsBroadcastError.
	ARCBroadcastFailedTotal *prometheus.CounterVec

	// WoCCacheHitsTotal / WoCCacheMissesTotal track the in-process LRU
	// cache wrapping the WhatsOnChain client. Layer is the cache layer
	// name: "tx", "block", or "page".
	WoCCacheHitsTotal   *prometheus.CounterVec
	WoCCacheMissesTotal *prometheus.CounterVec

	// ClaimBroadcastTotal counts withdrawal claim broadcasts by result
	// (ok / transient_fail / permanent_fail).
	ClaimBroadcastTotal *prometheus.CounterVec

	// AnchorPendingTotal is a gauge of withdrawals deferred this pass
	// because the matching covenant advance hasn't yet been anchored
	// or confirmed. Updated by the Withdrawer at the start of every
	// pass; alerts fire when it stays high for too long (suggests
	// covenant broadcasts are stuck).
	AnchorPendingTotal prometheus.Gauge
}

// NewCounters registers every Counters collector against r and returns
// the populated struct. Callers MUST keep the returned pointer alive
// for the lifetime of the process — Counters owns the collectors.
//
// Metric names are composed from the registry's namespace (see
// [metrics].namespace in cmd/bsvm config) so a deployment that sets
// `namespace = "myshard"` exposes `myshard_bridge_deposits_total`
// instead of the default `bsvm_bridge_deposits_total`. The const
// labels (node_name, chain_id) and the help text are unaffected.
func NewCounters(r *Registry) *Counters {
	ns := r.Namespace()
	name := func(suffix string) string { return ns + "_" + suffix }
	return &Counters{
		labels: r.labels,
		BridgeDepositsTotal: r.Counter(
			name("bridge_deposits_total"),
			"Total deposits credited to the bridge monitor's DB.",
		),
		BridgeWithdrawalsClaimedTotal: r.Counter(
			name("bridge_withdrawals_claimed_total"),
			"Total withdrawal claims successfully broadcast to BSV.",
		),
		BridgeRetractsTotal: r.Counter(
			name("bridge_retracts_total"),
			"Total RetractDepositsAbove calls on the bridge monitor (reorg-driven).",
		),
		OverlayBatchesAdvancedTotal: r.Counter(
			name("overlay_batches_advanced_total"),
			"Total successful covenant-advance broadcasts emitted by the overlay.",
		),
		OverlayStateRootMismatchTotal: r.Counter(
			name("overlay_state_root_mismatch_total"),
			"Dual-EVM (Go vs revm-in-SP1) post-state disagreements. Must stay 0.",
		),
		ProverProofDurationSeconds: r.Histogram(
			name("prover_proof_duration_seconds"),
			"Wall-clock time the SP1 prover takes per batch.",
			[]float64{1, 2.5, 5, 10, 30, 60, 120, 300, 600},
		),
		ProverProofSizeBytes: r.Histogram(
			name("prover_proof_size_bytes"),
			"Size of SP1 proof bytes returned by the host bridge.",
			[]float64{1024, 4096, 16384, 65536, 262144, 1048576, 4194304, 16777216},
		),
		ChaintracksReorgsTotal: r.Counter(
			name("chaintracks_reorgs_total"),
			"Total reorg events emitted by the chaintracks stream hub.",
		),
		ChaintracksReconnectsTotal: r.Counter(
			name("chaintracks_reconnects_total"),
			"Total chaintracks WS reconnect attempts.",
		),
		ARCBroadcastAttemptsTotal: r.Counter(
			name("arc_broadcast_attempts_total"),
			"Total ARC client Broadcast() invocations.",
		),
		ARCBroadcastFailedTotal: r.CounterVec(
			name("arc_broadcast_failed_total"),
			"Total ARC broadcast failures classified as transient or permanent.",
			"class",
		),
		WoCCacheHitsTotal: r.CounterVec(
			name("woc_cache_hits_total"),
			"WhatsOnChain client in-process cache hits, by layer.",
			"layer",
		),
		WoCCacheMissesTotal: r.CounterVec(
			name("woc_cache_misses_total"),
			"WhatsOnChain client in-process cache misses, by layer.",
			"layer",
		),
		ClaimBroadcastTotal: r.CounterVec(
			name("claim_broadcast_total"),
			"Withdrawal claim broadcast outcomes by result class.",
			"result",
		),
		AnchorPendingTotal: r.Gauge(
			name("anchor_pending_total"),
			"Withdrawals deferred this pass because their covenant advance is not yet anchored/confirmed.",
		),
	}
}

// DisabledCounters returns a Counters wired to a throwaway registry —
// safe to call .Inc() / .Observe() on, but the values never reach a
// /metrics scrape. Use it as the default seed when subsystems don't
// have a registry yet (tests, embedded harnesses).
//
// Each call constructs a fresh registry: do NOT share a single
// DisabledCounters across tests that count assertions, since the two
// would observe each other's increments.
func DisabledCounters() *Counters {
	return NewCounters(NoopRegistry())
}

// IncARCBroadcastFailed bumps ARCBroadcastFailedTotal{class=...} by 1.
// Safe on a nil receiver.
func (c *Counters) IncARCBroadcastFailed(class string) {
	if c == nil || c.ARCBroadcastFailedTotal == nil {
		return
	}
	c.ARCBroadcastFailedTotal.WithLabelValues(c.labels.NodeName, c.labels.ChainID, class).Inc()
}

// IncWoCCacheHit / IncWoCCacheMiss bump the per-layer counters.
// Safe on a nil receiver.
func (c *Counters) IncWoCCacheHit(layer string) {
	if c == nil || c.WoCCacheHitsTotal == nil {
		return
	}
	c.WoCCacheHitsTotal.WithLabelValues(c.labels.NodeName, c.labels.ChainID, layer).Inc()
}

// IncWoCCacheMiss bumps WoCCacheMissesTotal{layer=...} by 1. Safe on a
// nil receiver.
func (c *Counters) IncWoCCacheMiss(layer string) {
	if c == nil || c.WoCCacheMissesTotal == nil {
		return
	}
	c.WoCCacheMissesTotal.WithLabelValues(c.labels.NodeName, c.labels.ChainID, layer).Inc()
}

// IncClaimBroadcast bumps ClaimBroadcastTotal{result=...} by 1.
// result is one of "ok", "transient_fail", "permanent_fail".
// Safe on a nil receiver.
func (c *Counters) IncClaimBroadcast(result string) {
	if c == nil || c.ClaimBroadcastTotal == nil {
		return
	}
	c.ClaimBroadcastTotal.WithLabelValues(c.labels.NodeName, c.labels.ChainID, result).Inc()
}
