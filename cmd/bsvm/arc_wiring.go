// Daemon-side ARC client bootstrap. Round-9 UU added the ARC metrics
// counters (Counters.ARCBroadcastAttemptsTotal,
// Counters.ARCBroadcastFailedTotal{class}) but the cmd/bsvm side never
// built a production *arc.Client / *arc.MultiClient — every code path
// that wanted broadcast capability rebuilt one ad-hoc or routed through
// the Rúnar contract.Call path. This sibling helper closes that gap:
// it turns the operator's [bsv].arc_url / [bsv].arc_endpoint config
// into an arc.ARCClient with metrics already wired so the result can
// be handed to NetworkClient / BEEF endpoints / future RPC dispatch
// without duplicating the construction logic.
//
// The cmd-side wireBSVBroadcast call site is the one place this fires
// at startup. Other consumers (BEEF endpoints, future bridge claim
// retries) take the returned client from bsvBroadcastResult.
package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/icellan/bsvm/pkg/arc"
	"github.com/icellan/bsvm/pkg/metrics"
)

// BuildARCClient assembles an arc.ARCClient from the operator's [bsv]
// config. Resolution order:
//
//  1. ARCEndpoints non-empty (W6-3 multi-endpoint deployments) — every
//     entry becomes one endpoint of an *arc.MultiClient with the
//     configured Strategy / Quorum.
//  2. ARCURL non-empty (legacy single-endpoint deployments) — wrapped
//     in a one-entry *arc.MultiClient so callers always work against
//     the same ARCClient interface.
//  3. Both empty — returns (nil, nil). The daemon still starts; ARC-
//     dependent surfaces (NetworkClient.Broadcast, the BEEF callback
//     handler) will surface ErrProviderDisabled at call time.
//
// counters is the daemon's shared *metrics.Counters. Each per-endpoint
// *arc.Client receives the pointer via SetMetrics so the ARCBroadcast
// attempt / failure counters fire on every call. Pass nil only in
// tests; production code threads the same Counters used by every
// other subsystem.
func BuildARCClient(cfg BSVSection, counters *metrics.Counters) (arc.ARCClient, error) {
	endpoints := effectiveARCEndpoints(cfg)
	if len(endpoints) == 0 {
		return nil, nil
	}

	defaultTimeout := 30 * time.Second
	if strings.TrimSpace(cfg.ARCDefaultTimeout) != "" {
		d, err := time.ParseDuration(cfg.ARCDefaultTimeout)
		if err != nil {
			return nil, fmt.Errorf("arc: parse default timeout %q: %w", cfg.ARCDefaultTimeout, err)
		}
		defaultTimeout = d
	}

	multiCfg := arc.MultiConfig{
		Endpoints:      endpoints,
		Strategy:       parseARCStrategy(cfg.ARCStrategy),
		Quorum:         cfg.ARCQuorum,
		DefaultTimeout: defaultTimeout,
		CallbackURL:    cfg.ARCCallbackURL,
		CallbackToken:  cfg.ARCCallbackToken,
	}

	mc, err := arc.NewMultiClient(multiCfg)
	if err != nil {
		return nil, fmt.Errorf("arc: building multi-client: %w", err)
	}

	// MultiClient stores its inner *arc.Client values internally; expose
	// them via the unexported clients field through a helper rather than
	// reflection. We add a SetMetrics passthrough on MultiClient so the
	// const-Counters pointer reaches every endpoint without leaking
	// internals to the cmd-side caller.
	mc.SetMetrics(counters)
	return mc, nil
}

// effectiveARCEndpoints flattens the [bsv].ARCEndpoints / [bsv].ARCURL
// resolution into a single slice the MultiClient constructor accepts.
// Duplicates are NOT deduplicated — operators who list the same URL
// twice get two parallel calls (rare and harmless).
func effectiveARCEndpoints(cfg BSVSection) []arc.EndpointConfig {
	if len(cfg.ARCEndpoints) > 0 {
		out := make([]arc.EndpointConfig, 0, len(cfg.ARCEndpoints))
		for _, ep := range cfg.ARCEndpoints {
			if strings.TrimSpace(ep.URL) == "" {
				continue
			}
			converted := arc.EndpointConfig{
				Name:          ep.Name,
				URL:           ep.URL,
				AuthToken:     ep.AuthToken,
				CallbackURL:   ep.CallbackURL,
				CallbackToken: ep.CallbackToken,
				MaxRetries:    ep.MaxRetries,
			}
			if d, err := time.ParseDuration(strings.TrimSpace(ep.Timeout)); err == nil && d > 0 {
				converted.Timeout = d
			}
			if d, err := time.ParseDuration(strings.TrimSpace(ep.RetryBackoff)); err == nil && d > 0 {
				converted.RetryBackoff = d
			}
			out = append(out, converted)
		}
		return out
	}
	if strings.TrimSpace(cfg.ARCURL) != "" {
		return []arc.EndpointConfig{{
			Name:          "primary",
			URL:           cfg.ARCURL,
			CallbackURL:   cfg.ARCCallbackURL,
			CallbackToken: cfg.ARCCallbackToken,
		}}
	}
	return nil
}

// parseARCStrategy maps the config string to the arc package enum.
// Empty falls through to MultiClient's default (StrategyFirstSuccess).
func parseARCStrategy(s string) arc.Strategy {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "":
		return ""
	case "first_success":
		return arc.StrategyFirstSuccess
	case "quorum":
		return arc.StrategyQuorum
	default:
		// Pass through unknown values so arc.NewMultiClient can decide
		// whether to error. Centralises the failure mode there.
		return arc.Strategy(s)
	}
}
