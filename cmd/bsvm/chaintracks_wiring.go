// Daemon-side chaintracks bootstrap wiring. The helper in this file
// turns the operator's [bsv.chaintracks] config section into a live
// chaintracks.ChaintracksClient — a single RemoteClient when one
// provider is configured, a MultiClient with the operator-supplied
// quorum policy otherwise.
//
// This sits between the static config schema (cmd/bsvm/config.go) and
// the BEEF wiring (cmd/bsvm/beef_wiring.go): the BEEF verifier needs a
// ChaintracksClient to bind merkle paths to confirmed BSV headers, and
// before this file existed there was no place that constructed one at
// daemon startup. Without it, /bsvm/bridge/deposit logged "no verifier
// wired" and the bridge's fail-closed branch fired on every deposit.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/icellan/bsvm/pkg/chaintracks"
)

// BuildChaintracksClient assembles a chaintracks.ChaintracksClient from
// the operator's [bsv.chaintracks] config. The returned client wraps
// every enabled provider in a RemoteClient and feeds them to a
// MultiClient with the configured quorum policy.
//
// Behaviour for edge cases:
//
//   - cfg.Providers empty (or every entry disabled): returns
//     (nil, nil). The daemon still starts; bridge deposits remain
//     fail-closed at the BEEF consumer with a WARN-level log so
//     operators can see why /bsvm/bridge/deposit isn't crediting.
//   - cfg.Providers contains entries with malformed URLs / durations:
//     returns a non-nil error so the daemon fails fast at startup
//     rather than silently degrading.
//
// The resulting client owns goroutines (per-provider streaming hubs);
// the caller MUST defer Close() to free them on shutdown.
func BuildChaintracksClient(_ context.Context, cfg ChaintracksSection, logger *slog.Logger) (chaintracks.ChaintracksClient, error) {
	if logger == nil {
		logger = slog.Default()
	}

	// Filter to enabled providers up front so the multi-client construction
	// reflects only the live set. An empty result here is the operator's
	// signal that they want the daemon up without an SPV anchor.
	enabled := make([]ChaintracksProvider, 0, len(cfg.Providers))
	for _, p := range cfg.Providers {
		if !p.Enabled {
			continue
		}
		if strings.TrimSpace(p.URL) == "" {
			return nil, fmt.Errorf("chaintracks provider %q: URL required", p.Name)
		}
		enabled = append(enabled, p)
	}
	if len(enabled) == 0 {
		return nil, nil
	}

	// Build one RemoteClient per enabled provider. Per-provider Timeout
	// overrides the MultiClient's default; an empty Timeout falls back
	// to the RemoteClient default (30s).
	providers := make([]chaintracks.Provider, 0, len(enabled))
	urls := make([]string, 0, len(enabled))
	for _, p := range enabled {
		var perTimeout time.Duration
		if strings.TrimSpace(p.Timeout) != "" {
			d, err := time.ParseDuration(p.Timeout)
			if err != nil {
				return nil, fmt.Errorf("chaintracks provider %q: timeout: %w", p.Name, err)
			}
			perTimeout = d
		}
		remote, err := chaintracks.NewRemoteClient(chaintracks.RemoteConfig{
			URL:     p.URL,
			Timeout: perTimeout,
			APIKey:  p.APIKey,
		})
		if err != nil {
			return nil, fmt.Errorf("chaintracks provider %q: %w", p.Name, err)
		}
		providers = append(providers, chaintracks.Provider{
			Name:    providerName(p),
			Weight:  p.Weight,
			Timeout: perTimeout,
			Client:  remote,
		})
		urls = append(urls, fmt.Sprintf("%s=%s", providerName(p), p.URL))
	}

	mc := chaintracks.MultiConfig{
		Providers: providers,
		Strategy:  parseQuorumStrategy(cfg.QuorumStrategy),
		QuorumM:   cfg.QuorumM,
		Logger:    logger,
	}
	if action, err := parseDisagreementAction(cfg.DisagreementAction); err != nil {
		return nil, err
	} else if action != "" {
		mc.DisagreementAction = action
	}
	if d, err := parseOptionalDuration(cfg.DisagreementCooldown, "disagreement_cooldown"); err != nil {
		return nil, err
	} else {
		mc.DisagreementCooldown = d
	}
	if d, err := parseOptionalDuration(cfg.ResponseTimeout, "response_timeout"); err != nil {
		return nil, err
	} else {
		mc.ResponseTimeout = d
	}
	if d, err := parseOptionalDuration(cfg.StreamSkewWindow, "stream_skew_window"); err != nil {
		return nil, err
	} else {
		mc.StreamSkewWindow = d
	}
	if cfg.StreamBufferMax > 0 {
		mc.StreamBufferMax = cfg.StreamBufferMax
	}

	client, err := chaintracks.NewMultiClient(mc)
	if err != nil {
		// Best-effort cleanup of any RemoteClients we already opened.
		for _, p := range providers {
			if p.Client != nil {
				_ = p.Client.Close()
			}
		}
		return nil, fmt.Errorf("chaintracks multi-client: %w", err)
	}

	logger.Info("chaintracks client built",
		"providers", urls,
		"strategy", string(mc.Strategy),
		"quorum_m", mc.QuorumM,
		"disagreement_action", string(mc.DisagreementAction),
	)
	return client, nil
}

// providerName returns a stable name for the provider, falling back to
// its URL when the operator left the explicit Name blank. MultiClient
// uses the name as a map key in its health stats.
func providerName(p ChaintracksProvider) string {
	if name := strings.TrimSpace(p.Name); name != "" {
		return name
	}
	return p.URL
}

// parseQuorumStrategy maps the config string to the chaintracks enum.
// Empty falls through to the package default (StrategyHybrid).
func parseQuorumStrategy(s string) chaintracks.QuorumStrategy {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "":
		return ""
	case "hybrid":
		return chaintracks.StrategyHybrid
	case "m_of_n", "mofn":
		return chaintracks.StrategyMOfN
	default:
		// MultiClient accepts a custom string; if the operator typed a
		// strategy we don't recognise we let chaintracks decide whether
		// to error so the failure mode is centralised there. In practice
		// the package's NewMultiClient defaults unknown strategies to
		// hybrid, which matches our own default.
		return chaintracks.QuorumStrategy(s)
	}
}

// parseDisagreementAction maps the config string to the chaintracks enum.
// An empty string returns ("", nil) so the caller can leave the
// MultiClient default in place.
func parseDisagreementAction(s string) (chaintracks.DisagreementAction, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "":
		return "", nil
	case "log":
		return chaintracks.ActionLog, nil
	case "drop":
		return chaintracks.ActionDrop, nil
	case "halt":
		return chaintracks.ActionHalt, nil
	default:
		return "", fmt.Errorf("chaintracks: invalid disagreement_action %q (expected log|drop|halt)", s)
	}
}

// parseOptionalDuration converts an empty-or-set duration string into a
// time.Duration, returning zero (not an error) when the input is empty
// so callers can detect "operator didn't set this" and let downstream
// defaults apply.
func parseOptionalDuration(s, label string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("chaintracks %s: %w", label, err)
	}
	return d, nil
}

// ErrNoChaintracksProviders is returned by callers that treat a missing
// chaintracks config as a hard error rather than a soft warn. The
// daemon currently chooses the warn path (BuildChaintracksClient returns
// (nil, nil)); this sentinel exists so future callers — e.g. a
// production-only build that mandates an SPV anchor — can branch on it
// cleanly.
var ErrNoChaintracksProviders = errors.New("chaintracks: no providers configured")
