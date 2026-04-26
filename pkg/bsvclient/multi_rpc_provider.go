// multi_rpc_provider.go: MultiRPCProvider — failover wrapper around N
// RPCProviders for the spec-17 "BSV-node optional backup" path
// (W6-11). Each underlying provider is treated as one BSV node URL;
// the wrapper tries them in preference order until one succeeds.
//
// Design intent (mirrors W6-2 chaintracks quorum and W6-3 ARC fan-out):
//
//   - Order: providers[0] is the primary; providers[1:] are backups
//     consulted in declared order.
//   - Retryable failures (transport / connection errors and HTTP 5xx
//     translated by RPCProvider.Call into wrapped errors) trigger
//     failover to the next provider.
//   - Application errors (a node returning a JSON-RPC error code,
//     e.g. "tx not found") are NOT retried — they are deterministic
//     and would just be re-emitted by the next node.
//   - Per-provider health: consecutive failures are counted; once a
//     node hits MaxConsecutiveFailures it is parked for a cooldown
//     window before being retried. Cooldown elapses on a per-call
//     basis (no background goroutine); this keeps the wrapper
//     allocation-free and side-effect-free between calls.
//
// The wrapper is not a full RPC client — it delegates every method to
// the underlying RPCProvider it currently selects. Callers that need
// the typed runar.Provider methods get the same behaviour as the
// single-node path; the failover happens transparently.

package bsvclient

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/bsv-blockchain/go-sdk/transaction"
	runar "github.com/icellan/runar/packages/runar-go"
)

// MultiRPCProviderOpts configures the failover policy. Sensible
// defaults apply when fields are zero.
type MultiRPCProviderOpts struct {
	// MaxConsecutiveFailures is the number of consecutive failures
	// after which a provider enters cooldown. Default 3.
	MaxConsecutiveFailures int
	// Cooldown is how long a provider stays parked after hitting
	// MaxConsecutiveFailures. Default 30s.
	Cooldown time.Duration
	// now is an injectable clock for tests; nil falls back to
	// time.Now.
	now func() time.Time
}

// MultiRPCProvider wraps an ordered list of RPCProviders and routes
// each call to the first healthy one, failing over on retryable
// errors. Implements runar.Provider and covenant.ConfirmationSource
// transparently (same surface as RPCProvider).
type MultiRPCProvider struct {
	providers []*RPCProvider
	health    []*providerHealth
	opts      MultiRPCProviderOpts
}

type providerHealth struct {
	mu               sync.Mutex
	failures         int
	cooldownUntil    time.Time
	lastErr          error
	consecutiveCalls int // total ever, for diagnostics
}

// NewMultiRPCProvider builds a failover provider from one or more
// RPCProviders in preference order (primary first). Returns an error
// if providers is empty or any element is nil.
func NewMultiRPCProvider(providers []*RPCProvider, opts MultiRPCProviderOpts) (*MultiRPCProvider, error) {
	if len(providers) == 0 {
		return nil, errors.New("bsvclient: NewMultiRPCProvider requires at least one provider")
	}
	for i, p := range providers {
		if p == nil {
			return nil, fmt.Errorf("bsvclient: provider at index %d is nil", i)
		}
	}
	if opts.MaxConsecutiveFailures <= 0 {
		opts.MaxConsecutiveFailures = 3
	}
	if opts.Cooldown <= 0 {
		opts.Cooldown = 30 * time.Second
	}
	if opts.now == nil {
		opts.now = time.Now
	}
	health := make([]*providerHealth, len(providers))
	for i := range providers {
		health[i] = &providerHealth{}
	}
	return &MultiRPCProvider{
		providers: providers,
		health:    health,
		opts:      opts,
	}, nil
}

// Primary returns the first configured provider. Convenience accessor
// for callers that need the underlying RPCProvider's network-config
// metadata (e.g. Network()).
func (m *MultiRPCProvider) Primary() *RPCProvider { return m.providers[0] }

// runWithFailover invokes fn against each healthy provider in order,
// returning the first success. Errors from skipped (cooldown) and
// failed providers are aggregated for the final error message.
func (m *MultiRPCProvider) runWithFailover(name string, fn func(p *RPCProvider) error) error {
	now := m.opts.now()
	var aggregated []string
	tried := 0
	for i, p := range m.providers {
		h := m.health[i]
		h.mu.Lock()
		if !h.cooldownUntil.IsZero() && now.Before(h.cooldownUntil) {
			h.mu.Unlock()
			aggregated = append(aggregated, fmt.Sprintf("provider[%d]=cooldown(until %s)", i, h.cooldownUntil.Format(time.RFC3339)))
			continue
		}
		// Reset cooldown marker if we've passed it.
		if !h.cooldownUntil.IsZero() && !now.Before(h.cooldownUntil) {
			h.cooldownUntil = time.Time{}
			h.failures = 0
		}
		h.mu.Unlock()

		tried++
		err := fn(p)
		if err == nil {
			h.mu.Lock()
			h.failures = 0
			h.lastErr = nil
			h.mu.Unlock()
			return nil
		}
		if !isRetryable(err) {
			// Application-level error from a healthy node — surface
			// immediately. Do not penalise the node and do not try
			// backups (they would return the same answer).
			return err
		}
		h.mu.Lock()
		h.failures++
		h.lastErr = err
		if h.failures >= m.opts.MaxConsecutiveFailures {
			h.cooldownUntil = now.Add(m.opts.Cooldown)
		}
		h.mu.Unlock()
		aggregated = append(aggregated, fmt.Sprintf("provider[%d]=%v", i, err))
	}
	if tried == 0 {
		return fmt.Errorf("bsvclient: %s: all %d providers in cooldown (%s)", name, len(m.providers), strings.Join(aggregated, "; "))
	}
	return fmt.Errorf("bsvclient: %s: all %d providers failed (%s)", name, len(m.providers), strings.Join(aggregated, "; "))
}

// runWithFailoverResult is the typed-result variant of runWithFailover.
// It captures the result via a closure; unfortunately Go has no
// generics-friendly way to express "fn returns (T, error)" against a
// variable T without an extra wrapper, so each caller threads its own
// result through a captured local.

// isRetryable returns true when err looks like a transport / 5xx
// failure that another provider might survive. We deliberately do
// NOT retry application-level RPC errors (deterministic answers).
func isRetryable(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	// RPCProvider.call() wraps these specific cases:
	//   "...connection failed: <net.Error>"      → transport error
	//   "...build/marshal/read body: ..."        → local I/O glitch
	//   "...response parse error: ..."           → malformed body
	// All three are treated as retryable. JSON-RPC envelope errors
	// (RPC error %d: %s) are NOT retried.
	switch {
	case strings.Contains(msg, "connection failed"):
		return true
	case strings.Contains(msg, "read body"):
		return true
	case strings.Contains(msg, "response parse error"):
		return true
	case strings.Contains(msg, "build "):
		return true
	}
	return false
}

// HealthSnapshot returns a per-provider failure summary. The returned
// slice is a copy and safe to inspect concurrently.
type ProviderHealthSnapshot struct {
	Index           int
	Endpoint        string
	Failures        int
	CooldownUntil   time.Time
	LastError       string
	HealthyForCalls bool
}

// HealthSnapshot reports the current health of every configured
// provider. Cheap; intended for /debug or operator dashboards.
func (m *MultiRPCProvider) HealthSnapshot() []ProviderHealthSnapshot {
	out := make([]ProviderHealthSnapshot, len(m.providers))
	now := m.opts.now()
	for i, p := range m.providers {
		h := m.health[i]
		h.mu.Lock()
		snap := ProviderHealthSnapshot{
			Index:           i,
			Endpoint:        p.endpoint,
			Failures:        h.failures,
			CooldownUntil:   h.cooldownUntil,
			HealthyForCalls: h.cooldownUntil.IsZero() || !now.Before(h.cooldownUntil),
		}
		if h.lastErr != nil {
			snap.LastError = h.lastErr.Error()
		}
		h.mu.Unlock()
		out[i] = snap
	}
	return out
}

// ---------------------------------------------------------------------
// Provider / ConfirmationSource interface methods (delegate via
// runWithFailover).
// ---------------------------------------------------------------------

// Call implements the raw JSON-RPC escape hatch with failover.
func (m *MultiRPCProvider) Call(method string, params ...interface{}) (json.RawMessage, error) {
	var out json.RawMessage
	err := m.runWithFailover("Call("+method+")", func(p *RPCProvider) error {
		r, e := p.Call(method, params...)
		if e != nil {
			return e
		}
		out = r
		return nil
	})
	return out, err
}

// GetTransaction tries each provider in order.
func (m *MultiRPCProvider) GetTransaction(txid string) (*runar.TransactionData, error) {
	var out *runar.TransactionData
	err := m.runWithFailover("GetTransaction", func(p *RPCProvider) error {
		r, e := p.GetTransaction(txid)
		if e != nil {
			return e
		}
		out = r
		return nil
	})
	return out, err
}

// Broadcast tries each provider in order.
//
// Note: when a primary node accepts the broadcast and a backup is
// later asked, the backup may return a "tx already in mempool" error
// — application-level, not retryable. Production should expect this
// to be rare because the failover only activates on transport errors.
func (m *MultiRPCProvider) Broadcast(tx *transaction.Transaction) (string, error) {
	var out string
	err := m.runWithFailover("Broadcast", func(p *RPCProvider) error {
		r, e := p.Broadcast(tx)
		if e != nil {
			return e
		}
		out = r
		return nil
	})
	return out, err
}

// GetUtxos tries each provider in order. Note that listunspent
// requires the address to be imported on the queried node's wallet;
// this wrapper does not transfer wallet state across nodes.
func (m *MultiRPCProvider) GetUtxos(address string) ([]runar.UTXO, error) {
	var out []runar.UTXO
	err := m.runWithFailover("GetUtxos", func(p *RPCProvider) error {
		r, e := p.GetUtxos(address)
		if e != nil {
			return e
		}
		out = r
		return nil
	})
	return out, err
}

// GetContractUtxo is unsupported on every backing provider; surface
// the deterministic error from the primary without retrying.
func (m *MultiRPCProvider) GetContractUtxo(scriptHash string) (*runar.UTXO, error) {
	return m.providers[0].GetContractUtxo(scriptHash)
}

// GetNetwork returns the primary's network. All providers must be
// configured for the same network (caller's invariant).
func (m *MultiRPCProvider) GetNetwork() string {
	return m.providers[0].GetNetwork()
}

// GetFeeRate returns the primary's reported fee rate without
// failover — fee rate is a per-node policy, not network truth.
func (m *MultiRPCProvider) GetFeeRate() (int64, error) {
	return m.providers[0].GetFeeRate()
}

// GetRawTransaction tries each provider in order.
func (m *MultiRPCProvider) GetRawTransaction(txid string) (string, error) {
	var out string
	err := m.runWithFailover("GetRawTransaction", func(p *RPCProvider) error {
		r, e := p.GetRawTransaction(txid)
		if e != nil {
			return e
		}
		out = r
		return nil
	})
	return out, err
}

// GetRawTransactionVerbose tries each provider in order. This is the
// covenant.ConfirmationSource entry point.
func (m *MultiRPCProvider) GetRawTransactionVerbose(txid string) (map[string]interface{}, error) {
	var out map[string]interface{}
	err := m.runWithFailover("GetRawTransactionVerbose", func(p *RPCProvider) error {
		r, e := p.GetRawTransactionVerbose(txid)
		if e != nil {
			return e
		}
		out = r
		return nil
	})
	return out, err
}

// compile-time interface checks — MultiRPCProvider must continue to
// satisfy whatever surface RPCProvider satisfies.
var (
	_ runar.Provider = (*MultiRPCProvider)(nil)
)
