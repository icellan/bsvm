package main

import (
	"testing"

	"github.com/icellan/bsvm/pkg/bsvclient"
)

// TestBuildBSVProvider_NoURLs returns (nil, nil) so follower nodes
// without a BSV-node endpoint can boot.
func TestBuildBSVProvider_NoURLs(t *testing.T) {
	got, err := BuildBSVProvider(BSVSection{Network: "regtest"})
	if err != nil {
		t.Fatalf("BuildBSVProvider: %v", err)
	}
	if got != nil {
		t.Fatalf("expected nil provider when no URLs set, got %T", got)
	}
}

// TestBuildBSVProvider_LegacySingleURL wraps the legacy single
// NodeURL in a MultiRPCProvider so the failover surface is uniform
// across single- and multi-node deployments. Failover is a no-op when
// there is only one backing provider.
func TestBuildBSVProvider_LegacySingleURL(t *testing.T) {
	got, err := BuildBSVProvider(BSVSection{
		NodeURL: "http://alice:s3cr3t@127.0.0.1:18332/",
		Network: "regtest",
	})
	if err != nil {
		t.Fatalf("BuildBSVProvider: %v", err)
	}
	if got == nil {
		t.Fatal("expected non-nil provider")
	}
	if _, ok := got.(*bsvclient.MultiRPCProvider); !ok {
		t.Fatalf("expected *MultiRPCProvider, got %T", got)
	}
}

// TestBuildBSVProvider_MultiURL builds a failover wrapper around N
// providers in declared order. NodeURLs takes precedence over the
// legacy NodeURL.
func TestBuildBSVProvider_MultiURL(t *testing.T) {
	got, err := BuildBSVProvider(BSVSection{
		NodeURL: "http://alice:s3cr3t@unused.example/",
		NodeURLs: []string{
			"http://alice:s3cr3t@127.0.0.1:18332/",
			"http://alice:s3cr3t@127.0.0.1:28332/",
		},
		Network:                    "regtest",
		NodeMaxConsecutiveFailures: 5,
		NodeCooldown:               "1m",
	})
	if err != nil {
		t.Fatalf("BuildBSVProvider: %v", err)
	}
	mp, ok := got.(*bsvclient.MultiRPCProvider)
	if !ok {
		t.Fatalf("expected *MultiRPCProvider, got %T", got)
	}
	snap := mp.HealthSnapshot()
	if len(snap) != 2 {
		t.Fatalf("expected 2 providers, got %d", len(snap))
	}
	// Primary slot is index 0 — the first URL in NodeURLs, NOT the
	// legacy NodeURL.
	if want := "http://127.0.0.1:18332/"; snap[0].Endpoint != want {
		t.Fatalf("primary endpoint = %q, want %q (NodeURLs[0] should win over NodeURL)", snap[0].Endpoint, want)
	}
}

// TestBuildBSVProvider_BadCooldown surfaces config errors at startup
// rather than silently defaulting away an invalid duration string.
func TestBuildBSVProvider_BadCooldown(t *testing.T) {
	_, err := BuildBSVProvider(BSVSection{
		NodeURL:      "http://alice:s3cr3t@127.0.0.1:18332/",
		Network:      "regtest",
		NodeCooldown: "not-a-duration",
	})
	if err == nil {
		t.Fatal("expected error for malformed node_cooldown")
	}
}

// TestEffectiveNodeURLs_Precedence locks in the precedence rule
// EffectiveNodeURLs uses: NodeURLs (when set) wins over NodeURL,
// and an empty BSVSection returns nil.
func TestEffectiveNodeURLs_Precedence(t *testing.T) {
	cases := []struct {
		name string
		in   BSVSection
		want []string
	}{
		{"empty", BSVSection{}, nil},
		{"legacy_only", BSVSection{NodeURL: "http://a/"}, []string{"http://a/"}},
		{"new_only", BSVSection{NodeURLs: []string{"http://a/", "http://b/"}}, []string{"http://a/", "http://b/"}},
		{"both_new_wins", BSVSection{
			NodeURL:  "http://legacy/",
			NodeURLs: []string{"http://primary/", "http://backup/"},
		}, []string{"http://primary/", "http://backup/"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.in.EffectiveNodeURLs()
			if len(got) != len(tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("got[%d]=%q want %q", i, got[i], tc.want[i])
				}
			}
		})
	}
}
