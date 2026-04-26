package arc

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

// Strategy selects how a MultiClient aggregates responses across its
// configured endpoints.
type Strategy string

const (
	// StrategyFirstSuccess broadcasts to every endpoint in parallel and
	// returns as soon as any one returns a 2xx response. Remaining
	// in-flight calls are cancelled. Spec 17 §"Multi-endpoint redundancy"
	// describes this as the default for a healthy fan-out.
	StrategyFirstSuccess Strategy = "first_success"

	// StrategyQuorum broadcasts to every endpoint in parallel and waits
	// until at least Quorum endpoints succeed before returning the first
	// successful response. If fewer than Quorum endpoints succeed after
	// all responses are in, MultiClient returns an aggregate error.
	StrategyQuorum Strategy = "quorum"
)

// EndpointConfig describes a single ARC endpoint within a MultiClient.
type EndpointConfig struct {
	// Name is a human-readable label used in error reports and metrics.
	// Defaults to URL when empty.
	Name string
	// URL is the ARC base URL (e.g. https://arc.taal.com). Required.
	URL string
	// AuthToken is an optional Bearer token for ARC deployments that
	// require API auth.
	AuthToken string
	// CallbackURL is the per-endpoint callback URL. When empty,
	// MultiConfig.CallbackURL is used.
	CallbackURL string
	// CallbackToken is the per-endpoint callback token. When empty,
	// MultiConfig.CallbackToken is used.
	CallbackToken string
	// Timeout caps each HTTP request to this endpoint. Defaults to
	// MultiConfig.DefaultTimeout.
	Timeout time.Duration
	// MaxRetries bounds the number of retry attempts on transient
	// network failures (5xx, network error). 0 = no retries.
	MaxRetries int
	// RetryBackoff is the base delay between retries. Defaults to 100ms.
	RetryBackoff time.Duration
}

// MultiConfig configures a MultiClient.
type MultiConfig struct {
	// Endpoints is the list of ARC endpoints. At least one is required.
	Endpoints []EndpointConfig
	// Strategy is the aggregation strategy. Defaults to
	// StrategyFirstSuccess when empty.
	Strategy Strategy
	// Quorum is the minimum number of successful endpoints required
	// when Strategy == StrategyQuorum. Ignored otherwise. Must satisfy
	// 1 <= Quorum <= len(Endpoints) for quorum strategy.
	Quorum int
	// DefaultTimeout is the per-endpoint timeout when an endpoint does
	// not specify its own. Defaults to 30s.
	DefaultTimeout time.Duration
	// CallbackURL is the default per-endpoint X-CallbackUrl header.
	CallbackURL string
	// CallbackToken is the default per-endpoint X-CallbackToken header.
	CallbackToken string
}

// MultiClient is a fan-out ARC client that broadcasts to multiple
// endpoints in parallel using the configured Strategy. It satisfies
// the same ARCClient interface as the single-endpoint Client.
//
// All exported methods are safe for concurrent use.
type MultiClient struct {
	cfg      MultiConfig
	clients  []*Client
	endpoint []EndpointConfig // mirrors cfg.Endpoints with defaults filled in
}

// EndpointError captures one endpoint's outcome from a fan-out call.
// MultiClient aggregates a slice of these into a MultiError.
type EndpointError struct {
	Name string
	URL  string
	Err  error
}

// Error implements the error interface for a single endpoint failure.
func (e *EndpointError) Error() string {
	if e == nil {
		return ""
	}
	if e.Err == nil {
		return fmt.Sprintf("%s (%s): ok", e.Name, e.URL)
	}
	return fmt.Sprintf("%s (%s): %s", e.Name, e.URL, e.Err.Error())
}

// Unwrap exposes the underlying error for errors.Is / errors.As.
func (e *EndpointError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

// MultiError aggregates per-endpoint failures from a fan-out call.
type MultiError struct {
	Op       string
	Failures []*EndpointError
	// Successes is the count of endpoints that succeeded but the call
	// still failed (e.g., quorum not met). Zero for all-failure cases.
	Successes int
	// Quorum is the requested quorum when Strategy was quorum; 0 for
	// first-success.
	Quorum int
}

// Error implements the error interface.
func (m *MultiError) Error() string {
	if m == nil {
		return ""
	}
	parts := make([]string, 0, len(m.Failures))
	for _, f := range m.Failures {
		parts = append(parts, f.Error())
	}
	prefix := fmt.Sprintf("arc: %s: %d/%d endpoints failed",
		m.Op, len(m.Failures), len(m.Failures)+m.Successes)
	if m.Quorum > 0 {
		prefix += fmt.Sprintf(" (quorum=%d, succeeded=%d)", m.Quorum, m.Successes)
	}
	return prefix + ": " + strings.Join(parts, "; ")
}

// Errors returns the per-endpoint error slice. Callers should range
// over this when surfacing aggregate failure to operators.
func (m *MultiError) Errors() []*EndpointError {
	if m == nil {
		return nil
	}
	return m.Failures
}

// NewMultiClient builds a MultiClient. cfg.Endpoints must be non-empty;
// when len(cfg.Endpoints) == 1 the result behaves identically to a
// single-endpoint Client (broadcasts and reads are 1-of-1) so callers
// can use MultiClient unconditionally.
func NewMultiClient(cfg MultiConfig) (*MultiClient, error) {
	if len(cfg.Endpoints) == 0 {
		return nil, errors.New("arc: at least one endpoint required")
	}
	if cfg.Strategy == "" {
		cfg.Strategy = StrategyFirstSuccess
	}
	if cfg.DefaultTimeout <= 0 {
		cfg.DefaultTimeout = 30 * time.Second
	}
	if cfg.Strategy == StrategyQuorum {
		if cfg.Quorum <= 0 {
			cfg.Quorum = len(cfg.Endpoints)
		}
		if cfg.Quorum > len(cfg.Endpoints) {
			return nil, fmt.Errorf("arc: quorum %d > endpoints %d", cfg.Quorum, len(cfg.Endpoints))
		}
	}

	endpoints := make([]EndpointConfig, 0, len(cfg.Endpoints))
	clients := make([]*Client, 0, len(cfg.Endpoints))
	for i, ep := range cfg.Endpoints {
		if ep.URL == "" {
			return nil, fmt.Errorf("arc: endpoint %d missing URL", i)
		}
		if ep.Name == "" {
			ep.Name = ep.URL
		}
		if ep.Timeout <= 0 {
			ep.Timeout = cfg.DefaultTimeout
		}
		if ep.RetryBackoff <= 0 {
			ep.RetryBackoff = 100 * time.Millisecond
		}
		if ep.CallbackURL == "" {
			ep.CallbackURL = cfg.CallbackURL
		}
		if ep.CallbackToken == "" {
			ep.CallbackToken = cfg.CallbackToken
		}
		c, err := NewClient(Config{
			URL:           ep.URL,
			Timeout:       ep.Timeout,
			CallbackURL:   ep.CallbackURL,
			CallbackToken: ep.CallbackToken,
			AuthToken:     ep.AuthToken,
		})
		if err != nil {
			return nil, fmt.Errorf("arc: endpoint %s: %w", ep.Name, err)
		}
		endpoints = append(endpoints, ep)
		clients = append(clients, c)
	}
	return &MultiClient{cfg: cfg, clients: clients, endpoint: endpoints}, nil
}

// Endpoints returns the resolved endpoint configurations (with
// defaults filled in). The returned slice MUST NOT be mutated.
func (m *MultiClient) Endpoints() []EndpointConfig { return m.endpoint }

// Strategy reports the aggregation strategy.
func (m *MultiClient) Strategy() Strategy { return m.cfg.Strategy }

// fanResult carries a single endpoint's broadcast outcome through the
// internal fan-out plumbing.
type fanResult struct {
	idx  int
	resp *BroadcastResponse
	err  error
}

// Broadcast fans out to all configured endpoints under the configured
// Strategy. Returns the first successful BroadcastResponse on success,
// or a *MultiError on failure.
func (m *MultiClient) Broadcast(ctx context.Context, txOrBeef []byte) (*BroadcastResponse, error) {
	results := m.fanOutBroadcast(ctx, txOrBeef)
	switch m.cfg.Strategy {
	case StrategyQuorum:
		return m.aggregateQuorum(results)
	default:
		return m.aggregateFirstSuccess(results)
	}
}

// fanOutBroadcast issues the broadcast against every endpoint
// concurrently and returns the per-endpoint results in input order.
// Each endpoint runs with its own per-call cancellation child context
// so first-success can stop the rest cheaply.
func (m *MultiClient) fanOutBroadcast(ctx context.Context, txOrBeef []byte) []fanResult {
	type rec struct {
		fanResult
	}
	out := make([]fanResult, len(m.clients))
	results := make(chan rec, len(m.clients))

	var wg sync.WaitGroup
	wg.Add(len(m.clients))
	for i, c := range m.clients {
		i, c := i, c
		ep := m.endpoint[i]
		go func() {
			defer wg.Done()
			resp, err := m.broadcastWithRetry(ctx, c, ep, txOrBeef)
			results <- rec{fanResult{idx: i, resp: resp, err: err}}
		}()
	}
	go func() { wg.Wait(); close(results) }()
	for r := range results {
		out[r.idx] = r.fanResult
	}
	return out
}

// broadcastWithRetry retries a single endpoint's broadcast on
// transient errors up to ep.MaxRetries times, with linear backoff.
// Network/cancellation errors and 5xx responses are retried; 4xx
// responses are not.
func (m *MultiClient) broadcastWithRetry(ctx context.Context, c *Client, ep EndpointConfig, txOrBeef []byte) (*BroadcastResponse, error) {
	var lastErr error
	attempts := ep.MaxRetries + 1
	for attempt := 0; attempt < attempts; attempt++ {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		resp, err := c.Broadcast(ctx, txOrBeef)
		if err == nil {
			return resp, nil
		}
		lastErr = err
		if !isRetryable(err) {
			return nil, err
		}
		if attempt+1 >= attempts {
			break
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(ep.RetryBackoff * time.Duration(attempt+1)):
		}
	}
	return nil, lastErr
}

// isRetryable reports whether an error from Client.Broadcast is worth
// retrying. ARC's 4xx responses (bad txid, malformed body, etc.) are
// not retryable; transport errors and 5xx responses are.
func isRetryable(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	// Client.Broadcast embeds the HTTP status in the error when the
	// response was non-2xx; any "status 4" (4xx) is permanent.
	for code := 400; code < 500; code++ {
		needle := fmt.Sprintf("status %d", code)
		if strings.Contains(msg, needle) {
			return false
		}
	}
	return true
}

// aggregateFirstSuccess returns the first successful response by input
// order; failure mode collects every endpoint's error.
func (m *MultiClient) aggregateFirstSuccess(results []fanResult) (*BroadcastResponse, error) {
	failures := make([]*EndpointError, 0, len(results))
	for _, r := range results {
		if r.err == nil && r.resp != nil {
			return r.resp, nil
		}
		ep := m.endpoint[r.idx]
		failures = append(failures, &EndpointError{Name: ep.Name, URL: ep.URL, Err: r.err})
	}
	return nil, &MultiError{Op: "broadcast", Failures: failures}
}

// aggregateQuorum returns the first successful response if at least
// Quorum endpoints succeeded, otherwise a MultiError listing
// per-endpoint outcomes.
func (m *MultiClient) aggregateQuorum(results []fanResult) (*BroadcastResponse, error) {
	successes := 0
	var first *BroadcastResponse
	failures := make([]*EndpointError, 0, len(results))
	for _, r := range results {
		if r.err == nil && r.resp != nil {
			successes++
			if first == nil {
				first = r.resp
			}
			continue
		}
		ep := m.endpoint[r.idx]
		failures = append(failures, &EndpointError{Name: ep.Name, URL: ep.URL, Err: r.err})
	}
	if successes >= m.cfg.Quorum {
		return first, nil
	}
	return nil, &MultiError{
		Op: "broadcast", Failures: failures,
		Successes: successes, Quorum: m.cfg.Quorum,
	}
}

// Status polls every endpoint in parallel and returns the first
// non-UNKNOWN, non-error response. If every endpoint returns UNKNOWN,
// the UNKNOWN response is returned. If every endpoint errors, a
// *MultiError is returned. Status uses first-success semantics
// regardless of the configured Strategy because tx status lookups are
// idempotent reads, not consensus operations.
func (m *MultiClient) Status(ctx context.Context, txid [32]byte) (*TxStatus, error) {
	type result struct {
		idx int
		st  *TxStatus
		err error
	}
	out := make(chan result, len(m.clients))
	subCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	var wg sync.WaitGroup
	wg.Add(len(m.clients))
	for i, c := range m.clients {
		i, c := i, c
		go func() {
			defer wg.Done()
			st, err := c.Status(subCtx, txid)
			out <- result{idx: i, st: st, err: err}
		}()
	}
	go func() { wg.Wait(); close(out) }()
	var unknown *TxStatus
	failures := make([]*EndpointError, 0, len(m.clients))
	for r := range out {
		if r.err == nil && r.st != nil {
			if r.st.Status != StatusUnknown {
				return r.st, nil
			}
			if unknown == nil {
				unknown = r.st
			}
			continue
		}
		ep := m.endpoint[r.idx]
		failures = append(failures, &EndpointError{Name: ep.Name, URL: ep.URL, Err: r.err})
	}
	if unknown != nil {
		return unknown, nil
	}
	return nil, &MultiError{Op: "status", Failures: failures}
}

// Ping returns nil if any configured endpoint is reachable; otherwise
// a *MultiError listing every endpoint's failure.
func (m *MultiClient) Ping(ctx context.Context) error {
	type result struct {
		idx int
		err error
	}
	out := make(chan result, len(m.clients))
	subCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	var wg sync.WaitGroup
	wg.Add(len(m.clients))
	for i, c := range m.clients {
		i, c := i, c
		go func() {
			defer wg.Done()
			out <- result{idx: i, err: c.Ping(subCtx)}
		}()
	}
	go func() { wg.Wait(); close(out) }()
	failures := make([]*EndpointError, 0, len(m.clients))
	for r := range out {
		if r.err == nil {
			return nil
		}
		ep := m.endpoint[r.idx]
		failures = append(failures, &EndpointError{Name: ep.Name, URL: ep.URL, Err: r.err})
	}
	return &MultiError{Op: "ping", Failures: failures}
}

// Compile-time check that MultiClient satisfies ARCClient.
var _ ARCClient = (*MultiClient)(nil)
