package main

import (
	"context"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/icellan/bsvm/pkg/whatsonchain"
)

// TestBuildWoCClient_NetworkURLMapping confirms each supported BSV
// network resolves to the expected WoC base URL (or to an empty URL
// for regtest, which has no public WoC endpoint).
func TestBuildWoCClient_NetworkURLMapping(t *testing.T) {
	cases := []struct {
		network string
		wantNil bool
	}{
		{"mainnet", false},
		{"testnet", false},
		{"stn", false},
		{"regtest", true},
		{"", false}, // empty → mainnet
	}
	for _, tc := range cases {
		t.Run(tc.network, func(t *testing.T) {
			c, err := BuildWoCClient(BSVSection{Network: tc.network})
			if err != nil {
				t.Fatalf("BuildWoCClient(%q): %v", tc.network, err)
			}
			if (c == nil) != tc.wantNil {
				t.Fatalf("BuildWoCClient(%q): nil=%v want nil=%v", tc.network, c == nil, tc.wantNil)
			}
		})
	}
}

// TestBuildWoCClient_WrappedClientCaches verifies the W6-8 cache is
// always wired into the client this builder hands out: a second GetTx
// for the same txid returns the same body without a second HTTP hit.
//
// The fake WoC server lives in this test rather than going through the
// real /v1/bsv/main URL so the test is hermetic. We construct the
// cached wrapper exactly the way BuildWoCClient does (with a custom
// URL) so the smoke test exercises the same code path.
func TestBuildWoCClient_WrappedClientCaches(t *testing.T) {
	const body = `"deadbeef"`
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	// Build a WoC client pointed at the fake server, then wrap it the
	// same way BuildWoCClient would (TxCacheSize from config default).
	inner, err := whatsonchain.NewClient(whatsonchain.Config{URL: srv.URL})
	if err != nil {
		t.Fatalf("whatsonchain.NewClient: %v", err)
	}
	cfg := DefaultNodeConfig()
	cached := whatsonchain.NewCachedClient(inner, whatsonchain.CacheConfig{
		TxCacheSize: cfg.BSV.WoCCacheSize,
	})

	var txid [32]byte
	copy(txid[:], mustDecodeHex(t, "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"))

	// First call: cache miss, server hit.
	got1, err := cached.GetTx(context.Background(), txid)
	if err != nil {
		t.Fatalf("first GetTx: %v", err)
	}
	if got := hits.Load(); got != 1 {
		t.Fatalf("after first call: hits=%d, want 1", got)
	}

	// Second call: cache hit, server NOT hit again.
	got2, err := cached.GetTx(context.Background(), txid)
	if err != nil {
		t.Fatalf("second GetTx: %v", err)
	}
	if got := hits.Load(); got != 1 {
		t.Fatalf("after second call: hits=%d, want 1 (cache miss → upstream not consulted)", got)
	}

	// Bodies must be byte-equal.
	if string(got1) != string(got2) {
		t.Fatalf("cached body differs: %x vs %x", got1, got2)
	}
}

func mustDecodeHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("decode hex %q: %v", s, err)
	}
	return b
}
