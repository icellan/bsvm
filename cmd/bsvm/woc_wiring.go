// Daemon-side WhatsOnChain client wiring. The helper here turns the
// operator's [bsv] section (URL + WoCCacheSize) into a live, LRU-
// cached whatsonchain.WhatsOnChainClient.
//
// W6-8 added pkg/whatsonchain.NewCachedClient: a singleflight + LRU
// wrapper around the bare HTTP client so repeated content-addressed
// lookups (GetTx) consume our WoC budget exactly once. Until this
// retrofit, no production call site constructed a WoC client at all
// — NetworkClient.WhatsOnChain() was only set by tests. This builder
// makes the cache the default for any future call site that wants WoC
// access, and gives operators one place to flip the cache size knob
// (BSVSection.WoCCacheSize, default 1000).
//
// The HTTP base URL is derived from the configured BSV network so
// devnet (regtest) fails fast (no public WoC endpoint) and mainnet/
// testnet route to the correct WoC subdomain. Callers can override by
// passing an explicit URL string.
package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/icellan/bsvm/pkg/whatsonchain"
)

// wocBaseURLFor returns the canonical WhatsOnChain v1 base URL for the
// given BSV network name. Empty / unknown networks return the empty
// string so callers can decide whether to error or skip.
func wocBaseURLFor(network string) string {
	switch strings.ToLower(strings.TrimSpace(network)) {
	case "mainnet", "main", "":
		return "https://api.whatsonchain.com/v1/bsv/main"
	case "testnet", "test":
		return "https://api.whatsonchain.com/v1/bsv/test"
	case "stn":
		return "https://api.whatsonchain.com/v1/bsv/stn"
	case "regtest":
		// WoC has no public regtest endpoint; callers running on regtest
		// must inject their own URL or skip WoC entirely.
		return ""
	default:
		return ""
	}
}

// BuildWoCClient assembles a cached WhatsOnChain client from the
// operator's [bsv] config section. The returned client is always the
// LRU-cached wrapper (W6-8); BSVSection.WoCCacheSize controls the
// bound (0 disables caching but the wrapper is still returned so
// callers see a consistent interface).
//
// Returns (nil, nil) when no WoC URL is derivable for the configured
// network (e.g. regtest with no override) — bridges + ancestor
// fetching simply fall through to other sources in that case. The
// caller decides whether the absence is fatal.
func BuildWoCClient(cfg BSVSection) (whatsonchain.WhatsOnChainClient, error) {
	url := wocBaseURLFor(cfg.Network)
	if url == "" {
		return nil, nil
	}
	inner, err := whatsonchain.NewClient(whatsonchain.Config{
		URL:     url,
		Timeout: 30 * time.Second,
	})
	if err != nil {
		return nil, fmt.Errorf("whatsonchain client: %w", err)
	}
	return whatsonchain.NewCachedClient(inner, whatsonchain.CacheConfig{
		TxCacheSize: cfg.WoCCacheSize,
	}), nil
}
