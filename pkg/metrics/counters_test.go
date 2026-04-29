package metrics

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestCounters_RegisterAndScrape confirms NewCounters does not panic on
// repeated construction (each registry is independent) and that every
// expected metric name is present in a scrape after a single Inc()
// across all collectors.
func TestCounters_RegisterAndScrape(t *testing.T) {
	r := NewRegistry(Labels{NodeName: "n1", ChainID: "31337"})
	c := NewCounters(r)

	// Touch every collector once so it shows up in scrapes (scalar
	// counters/gauges register immediately, but vec counters only emit
	// per-label-set samples after the first WithLabelValues).
	c.BridgeDepositsTotal.Inc()
	c.BridgeWithdrawalsClaimedTotal.Inc()
	c.BridgeRetractsTotal.Inc()
	c.OverlayBatchesAdvancedTotal.Inc()
	c.OverlayStateRootMismatchTotal.Inc()
	c.ProverProofDurationSeconds.Observe(0.5)
	c.ProverProofSizeBytes.Observe(1024)
	c.ChaintracksReorgsTotal.Inc()
	c.ChaintracksReconnectsTotal.Inc()
	c.ARCBroadcastAttemptsTotal.Inc()
	c.IncARCBroadcastFailed("transient")
	c.IncARCBroadcastFailed("permanent")
	c.IncWoCCacheHit("tx")
	c.IncWoCCacheHit("block")
	c.IncWoCCacheHit("page")
	c.IncWoCCacheMiss("tx")
	c.IncClaimBroadcast("ok")
	c.IncClaimBroadcast("transient_fail")
	c.IncClaimBroadcast("permanent_fail")
	c.AnchorPendingTotal.Set(3)

	rec := httptest.NewRecorder()
	r.HTTPHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body := rec.Body.String()

	wantNames := []string{
		"bsvm_bridge_deposits_total",
		"bsvm_bridge_withdrawals_claimed_total",
		"bsvm_bridge_retracts_total",
		"bsvm_overlay_batches_advanced_total",
		"bsvm_overlay_state_root_mismatch_total",
		"bsvm_prover_proof_duration_seconds_count",
		"bsvm_prover_proof_size_bytes_count",
		"bsvm_chaintracks_reorgs_total",
		"bsvm_chaintracks_reconnects_total",
		"bsvm_arc_broadcast_attempts_total",
		`bsvm_arc_broadcast_failed_total{chain_id="31337",class="transient",node_name="n1"} 1`,
		`bsvm_arc_broadcast_failed_total{chain_id="31337",class="permanent",node_name="n1"} 1`,
		`bsvm_woc_cache_hits_total{chain_id="31337",layer="tx",node_name="n1"} 1`,
		`bsvm_woc_cache_hits_total{chain_id="31337",layer="block",node_name="n1"} 1`,
		`bsvm_woc_cache_hits_total{chain_id="31337",layer="page",node_name="n1"} 1`,
		`bsvm_woc_cache_misses_total{chain_id="31337",layer="tx",node_name="n1"} 1`,
		`bsvm_claim_broadcast_total{chain_id="31337",node_name="n1",result="ok"} 1`,
		`bsvm_claim_broadcast_total{chain_id="31337",node_name="n1",result="transient_fail"} 1`,
		`bsvm_claim_broadcast_total{chain_id="31337",node_name="n1",result="permanent_fail"} 1`,
		`bsvm_anchor_pending_total{chain_id="31337",node_name="n1"} 3`,
	}
	for _, want := range wantNames {
		if !strings.Contains(body, want) {
			t.Errorf("expected %q in scrape body, missing\nfull body:\n%s", want, body)
		}
	}
}

// TestDisabledCounters_NilSafe confirms the helper methods are safe on
// a nil *Counters and that DisabledCounters() yields a usable value
// that doesn't panic on .Inc() / .Observe().
func TestDisabledCounters_NilSafe(t *testing.T) {
	var c *Counters
	c.IncARCBroadcastFailed("transient")
	c.IncWoCCacheHit("tx")
	c.IncWoCCacheMiss("page")
	c.IncClaimBroadcast("ok")

	d := DisabledCounters()
	if d == nil {
		t.Fatal("DisabledCounters() returned nil")
	}
	d.BridgeDepositsTotal.Inc()
	d.ProverProofDurationSeconds.Observe(1.0)
	d.IncARCBroadcastFailed("transient")
	d.IncWoCCacheHit("tx")
	d.IncClaimBroadcast("permanent_fail")
	d.AnchorPendingTotal.Set(0)
}

// TestDisabledCounters_Independent confirms each DisabledCounters()
// call yields an independent registry — two calls in the same test
// must not collide on collector registration.
func TestDisabledCounters_Independent(t *testing.T) {
	a := DisabledCounters()
	b := DisabledCounters()
	a.BridgeDepositsTotal.Inc()
	b.BridgeDepositsTotal.Inc()
	// No panic on duplicate construction is the assertion. If a global
	// registry were used, the second call would crash MustRegister.
}

// TestCounters_CustomNamespace asserts every Counters-owned metric
// is rebranded under the operator-supplied prefix when the registry
// is constructed via NewRegistryWithNamespace. Pins the contract that
// [metrics].namespace works without per-call-site changes.
func TestCounters_CustomNamespace(t *testing.T) {
	const customNS = "myshard"

	r := NewRegistryWithNamespace(Labels{NodeName: "n1", ChainID: "31337"}, customNS)
	c := NewCounters(r)

	// Touch every collector once so it shows up in the scrape.
	c.BridgeDepositsTotal.Inc()
	c.BridgeWithdrawalsClaimedTotal.Inc()
	c.BridgeRetractsTotal.Inc()
	c.OverlayBatchesAdvancedTotal.Inc()
	c.OverlayStateRootMismatchTotal.Inc()
	c.ProverProofDurationSeconds.Observe(0.5)
	c.ProverProofSizeBytes.Observe(1024)
	c.ChaintracksReorgsTotal.Inc()
	c.ChaintracksReconnectsTotal.Inc()
	c.ARCBroadcastAttemptsTotal.Inc()
	c.IncARCBroadcastFailed("transient")
	c.IncWoCCacheHit("tx")
	c.IncWoCCacheMiss("tx")
	c.IncClaimBroadcast("ok")
	c.AnchorPendingTotal.Set(2)

	rec := httptest.NewRecorder()
	r.HTTPHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body := rec.Body.String()

	// Every Counters metric must carry the new prefix.
	wantPrefixed := []string{
		"myshard_bridge_deposits_total",
		"myshard_bridge_withdrawals_claimed_total",
		"myshard_bridge_retracts_total",
		"myshard_overlay_batches_advanced_total",
		"myshard_overlay_state_root_mismatch_total",
		"myshard_prover_proof_duration_seconds_count",
		"myshard_prover_proof_size_bytes_count",
		"myshard_chaintracks_reorgs_total",
		"myshard_chaintracks_reconnects_total",
		"myshard_arc_broadcast_attempts_total",
		"myshard_arc_broadcast_failed_total",
		"myshard_woc_cache_hits_total",
		"myshard_woc_cache_misses_total",
		"myshard_claim_broadcast_total",
		"myshard_anchor_pending_total",
	}
	for _, want := range wantPrefixed {
		if !strings.Contains(body, want) {
			t.Errorf("expected %q in scrape, missing", want)
		}
	}

	// And the default bsvm_ prefix must NOT appear for any Counters
	// metric — operators expect the rebrand to be total.
	bsvmLeaks := []string{
		"bsvm_bridge_deposits_total",
		"bsvm_overlay_batches_advanced_total",
		"bsvm_arc_broadcast_attempts_total",
	}
	for _, leak := range bsvmLeaks {
		if strings.Contains(body, leak) {
			t.Errorf("bsvm_-prefixed metric leaked under custom namespace: %q", leak)
		}
	}
}

// TestCounters_EmptyNamespaceFallsBackToDefault asserts an empty
// override leaves the default "bsvm" prefix in place — empty config
// values must not produce nameless metrics.
func TestCounters_EmptyNamespaceFallsBackToDefault(t *testing.T) {
	r := NewRegistryWithNamespace(Labels{NodeName: "n1", ChainID: "31337"}, "")
	c := NewCounters(r)
	c.BridgeDepositsTotal.Inc()

	rec := httptest.NewRecorder()
	r.HTTPHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body := rec.Body.String()
	if !strings.Contains(body, "bsvm_bridge_deposits_total") {
		t.Errorf("empty namespace should fall back to default; missing bsvm_bridge_deposits_total")
	}
}
