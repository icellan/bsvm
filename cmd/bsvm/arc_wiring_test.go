package main

import (
	"testing"

	"github.com/icellan/bsvm/pkg/arc"
	"github.com/icellan/bsvm/pkg/metrics"
)

// TestBuildARCClient_NoConfigReturnsNil asserts an empty BSV section
// yields (nil, nil) rather than an error or a half-built client.
// Operators on a regtest harness without ARC must still see the
// daemon start; the nil client surfaces ErrProviderDisabled at call
// time downstream.
func TestBuildARCClient_NoConfigReturnsNil(t *testing.T) {
	c, err := BuildARCClient(BSVSection{}, nil)
	if err != nil {
		t.Fatalf("BuildARCClient returned error on empty config: %v", err)
	}
	if c != nil {
		t.Fatalf("BuildARCClient returned non-nil client on empty config: %T", c)
	}
}

// TestBuildARCClient_LegacyARCURLBecomesSingleEndpointMultiClient
// covers the legacy [bsv].arc_url path. The result MUST be an
// *arc.MultiClient (so callers always work against the same interface)
// with exactly one endpoint mirroring the configured URL.
func TestBuildARCClient_LegacyARCURLBecomesSingleEndpointMultiClient(t *testing.T) {
	cfg := BSVSection{
		ARCURL:           "https://arc.taal.com",
		ARCCallbackURL:   "https://node.example.com/arc-callback",
		ARCCallbackToken: "token-abc",
	}
	c, err := BuildARCClient(cfg, metrics.DisabledCounters())
	if err != nil {
		t.Fatalf("BuildARCClient: %v", err)
	}
	mc, ok := c.(*arc.MultiClient)
	if !ok {
		t.Fatalf("expected *arc.MultiClient, got %T", c)
	}
	endpoints := mc.Endpoints()
	if len(endpoints) != 1 {
		t.Fatalf("got %d endpoints, want 1", len(endpoints))
	}
	if endpoints[0].URL != cfg.ARCURL {
		t.Errorf("endpoint URL = %q, want %q", endpoints[0].URL, cfg.ARCURL)
	}
	if endpoints[0].CallbackURL != cfg.ARCCallbackURL {
		t.Errorf("CallbackURL = %q, want %q", endpoints[0].CallbackURL, cfg.ARCCallbackURL)
	}
}

// TestBuildARCClient_MultiEndpoint covers the W6-3 multi-endpoint
// path. Every entry under [bsv].arc_endpoint becomes one inner
// *arc.Client; the strategy is forwarded.
func TestBuildARCClient_MultiEndpoint(t *testing.T) {
	cfg := BSVSection{
		ARCEndpoints: []ARCEndpointSection{
			{Name: "primary", URL: "https://arc-a.example.com"},
			{Name: "secondary", URL: "https://arc-b.example.com", AuthToken: "auth-b"},
		},
		ARCStrategy:    "quorum",
		ARCQuorum:      2,
		ARCCallbackURL: "https://node.example.com/arc-callback",
	}
	c, err := BuildARCClient(cfg, metrics.DisabledCounters())
	if err != nil {
		t.Fatalf("BuildARCClient: %v", err)
	}
	mc, ok := c.(*arc.MultiClient)
	if !ok {
		t.Fatalf("expected *arc.MultiClient, got %T", c)
	}
	endpoints := mc.Endpoints()
	if len(endpoints) != 2 {
		t.Fatalf("got %d endpoints, want 2", len(endpoints))
	}
	if mc.Strategy() != arc.StrategyQuorum {
		t.Errorf("strategy = %q, want %q", mc.Strategy(), arc.StrategyQuorum)
	}
}

// TestBuildARCClient_BadDefaultTimeoutErrors ensures a malformed
// duration in [bsv].arc_default_timeout fails fast at startup rather
// than silently degrading to the package default.
func TestBuildARCClient_BadDefaultTimeoutErrors(t *testing.T) {
	cfg := BSVSection{
		ARCURL:            "https://arc.taal.com",
		ARCDefaultTimeout: "not-a-duration",
	}
	if _, err := BuildARCClient(cfg, nil); err == nil {
		t.Fatalf("expected error on bad arc_default_timeout, got nil")
	}
}

// TestBuildARCClient_EmptyEndpointURLsSkipped asserts entries with a
// blank URL are filtered before reaching arc.NewMultiClient (which
// would otherwise reject the whole config).
func TestBuildARCClient_EmptyEndpointURLsSkipped(t *testing.T) {
	cfg := BSVSection{
		ARCEndpoints: []ARCEndpointSection{
			{Name: "blank", URL: ""},
			{Name: "real", URL: "https://arc.example.com"},
		},
	}
	c, err := BuildARCClient(cfg, nil)
	if err != nil {
		t.Fatalf("BuildARCClient: %v", err)
	}
	mc := c.(*arc.MultiClient)
	if len(mc.Endpoints()) != 1 {
		t.Fatalf("got %d endpoints, want 1 (blank URL should have been filtered)", len(mc.Endpoints()))
	}
}
