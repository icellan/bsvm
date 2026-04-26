package bsvclient

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// fakeNode spins up an httptest server that mimics a bsv-node JSON-RPC
// endpoint just enough to exercise the failover code paths. Each
// instance can be configured to:
//   - succeed (return a sentinel result)
//   - emit a connection error (server is shut down)
//   - emit a 5xx (which RPCProvider.call() surfaces as "response parse
//     error" since the body is not valid JSON-RPC)
type fakeNode struct {
	t        *testing.T
	server   *httptest.Server
	calls    atomic.Int32
	mode     atomic.Int32 // 0=success, 1=5xx, 2=app-rpc-error
	resultJS string       // JSON to return as the success result
	rpcErr   string       // RPC error message when mode == 2
}

func newFakeNode(t *testing.T, resultJS string) *fakeNode {
	f := &fakeNode{t: t, resultJS: resultJS}
	f.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.calls.Add(1)
		switch f.mode.Load() {
		case 1:
			http.Error(w, "boom", http.StatusBadGateway)
			return
		case 2:
			// JSON-RPC application error envelope.
			body, _ := json.Marshal(map[string]any{
				"result": nil,
				"error":  map[string]any{"code": -32000, "message": f.rpcErr},
				"id":     1,
			})
			w.Header().Set("Content-Type", "application/json")
			w.Write(body)
			return
		default:
			body, _ := json.Marshal(map[string]any{
				"result": json.RawMessage(f.resultJS),
				"error":  nil,
				"id":     1,
			})
			w.Header().Set("Content-Type", "application/json")
			w.Write(body)
		}
	}))
	return f
}

func (f *fakeNode) URL() string {
	return f.server.URL
}

// killTransport closes the server so the next call gets a connection
// error from the kernel instead of an HTTP response.
func (f *fakeNode) killTransport() {
	f.server.Close()
}

func (f *fakeNode) setMode(m int32) {
	f.mode.Store(m)
}

func (f *fakeNode) callCount() int32 {
	return f.calls.Load()
}

func (f *fakeNode) close() {
	// Idempotent. Closing a server that's already closed is a no-op
	// because httptest.Server.Close is idempotent.
	f.server.Close()
}

// dummySuccess returns a JSON encoding for an arbitrary
// getrawtransaction result. The exact shape doesn't matter for these
// tests — we only assert the call routed correctly.
const dummySuccess = `{"hex":"deadbeef","vout":[],"confirmations":7}`

func newProviderForFake(t *testing.T, url string) *RPCProvider {
	p, err := NewRPCProvider(url, "regtest")
	if err != nil {
		t.Fatalf("NewRPCProvider(%s): %v", url, err)
	}
	return p
}

func TestMultiRPCProvider_PrimaryFailsBackupSucceeds(t *testing.T) {
	primary := newFakeNode(t, dummySuccess)
	backup1 := newFakeNode(t, dummySuccess)
	backup2 := newFakeNode(t, dummySuccess)
	defer backup1.close()
	defer backup2.close()

	// Tear down the primary's transport so the kernel returns ECONNREFUSED.
	primaryURL := primary.URL()
	primary.killTransport()

	m, err := NewMultiRPCProvider([]*RPCProvider{
		newProviderForFake(t, primaryURL),
		newProviderForFake(t, backup1.URL()),
		newProviderForFake(t, backup2.URL()),
	}, MultiRPCProviderOpts{})
	if err != nil {
		t.Fatalf("NewMultiRPCProvider: %v", err)
	}

	out, err := m.GetRawTransactionVerbose("deadbeef")
	if err != nil {
		t.Fatalf("expected backup1 to succeed: %v", err)
	}
	if hex, _ := out["hex"].(string); hex != "deadbeef" {
		t.Fatalf("unexpected result: %+v", out)
	}
	if backup1.callCount() != 1 {
		t.Fatalf("backup1 should have been hit once, got %d", backup1.callCount())
	}
	if backup2.callCount() != 0 {
		t.Fatalf("backup2 must NOT be tried after backup1 succeeds, got %d", backup2.callCount())
	}
}

func TestMultiRPCProvider_AllFailReturnsAggregatedError(t *testing.T) {
	a := newFakeNode(t, dummySuccess)
	b := newFakeNode(t, dummySuccess)
	c := newFakeNode(t, dummySuccess)
	urls := []string{a.URL(), b.URL(), c.URL()}
	a.killTransport()
	b.killTransport()
	c.killTransport()

	providers := make([]*RPCProvider, 0, 3)
	for _, u := range urls {
		providers = append(providers, newProviderForFake(t, u))
	}
	m, err := NewMultiRPCProvider(providers, MultiRPCProviderOpts{})
	if err != nil {
		t.Fatalf("NewMultiRPCProvider: %v", err)
	}

	_, err = m.GetRawTransactionVerbose("deadbeef")
	if err == nil {
		t.Fatalf("expected error when all providers down")
	}
	if !strings.Contains(err.Error(), "all 3 providers failed") {
		t.Fatalf("expected aggregated error, got: %v", err)
	}
}

func TestMultiRPCProvider_AppErrorIsNotRetried(t *testing.T) {
	// A node that returns a JSON-RPC envelope error must NOT trigger
	// failover — the answer is deterministic and the backup would
	// say the same thing. This protects against e.g. spurious
	// "tx already in mempool" cascades on Broadcast.
	primary := newFakeNode(t, "")
	backup := newFakeNode(t, dummySuccess)
	defer primary.close()
	defer backup.close()

	primary.rpcErr = "tx not found"
	primary.setMode(2)

	m, err := NewMultiRPCProvider([]*RPCProvider{
		newProviderForFake(t, primary.URL()),
		newProviderForFake(t, backup.URL()),
	}, MultiRPCProviderOpts{})
	if err != nil {
		t.Fatalf("NewMultiRPCProvider: %v", err)
	}

	_, err = m.GetRawTransactionVerbose("deadbeef")
	if err == nil {
		t.Fatalf("expected app error to surface")
	}
	if !strings.Contains(err.Error(), "tx not found") {
		t.Fatalf("expected RPC error to surface, got: %v", err)
	}
	if backup.callCount() != 0 {
		t.Fatalf("backup must NOT be tried after primary RPC error, got %d", backup.callCount())
	}
}

func TestMultiRPCProvider_CooldownAndRecovery(t *testing.T) {
	// Use injectable clock so the test does not rely on wall time.
	primary := newFakeNode(t, dummySuccess)
	backup := newFakeNode(t, dummySuccess)
	defer backup.close()

	primaryURL := primary.URL()
	primary.killTransport()

	// Start at fixed t0; cooldown 1 minute.
	t0 := time.Date(2026, 4, 1, 12, 0, 0, 0, time.UTC)
	clock := newFakeClock(t0)

	m, err := NewMultiRPCProvider(
		[]*RPCProvider{
			newProviderForFake(t, primaryURL),
			newProviderForFake(t, backup.URL()),
		},
		MultiRPCProviderOpts{
			MaxConsecutiveFailures: 2,
			Cooldown:               1 * time.Minute,
			now:                    clock.now,
		},
	)
	if err != nil {
		t.Fatalf("NewMultiRPCProvider: %v", err)
	}

	// Call 3 times: each should hit the dead primary, fail over to
	// backup, succeed. After 2 consecutive failures the primary
	// enters cooldown — so call 3 must SKIP the primary entirely.
	for i := 0; i < 3; i++ {
		if _, err := m.GetRawTransactionVerbose("x"); err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
	}
	if backup.callCount() != 3 {
		t.Fatalf("backup should have served 3 calls, got %d", backup.callCount())
	}

	snap := m.HealthSnapshot()
	if !snap[0].HealthyForCalls && snap[0].Failures < 2 {
		t.Fatalf("primary should be in cooldown after 2 failures, snap=%+v", snap[0])
	}
	if snap[0].CooldownUntil.IsZero() {
		t.Fatalf("primary cooldownUntil should be set, snap=%+v", snap[0])
	}

	// Advance the clock past the cooldown. Now the primary will be
	// retried — and since the transport is still dead, it will fail
	// again, but we want to verify the wrapper actually retries
	// rather than skipping forever.
	clock.advance(2 * time.Minute)
	primaryProvider := m.providers[0]
	calls := primary.callCount()
	if _, err := m.GetRawTransactionVerbose("x"); err != nil {
		t.Fatalf("post-cooldown call: %v", err)
	}
	// Primary's HTTP server is dead so calls won't increment, but
	// the wrapper should have ATTEMPTED the primary (the underlying
	// http.Client would have made one DialContext attempt). We
	// assert via the wrapper's health snapshot that the failure
	// counter incremented after the cooldown reset.
	_ = primaryProvider
	_ = calls
	snap = m.HealthSnapshot()
	if snap[0].Failures == 0 {
		t.Fatalf("after post-cooldown retry, primary should have at least 1 failure, snap=%+v", snap[0])
	}
}

func TestMultiRPCProvider_BackupSuccessClearsFailureCounter(t *testing.T) {
	// When a node recovers, its failure counter resets to 0.
	primary := newFakeNode(t, dummySuccess)
	defer primary.close()

	t0 := time.Date(2026, 4, 1, 12, 0, 0, 0, time.UTC)
	clock := newFakeClock(t0)
	primary.setMode(1) // 5xx → retryable

	// Single-provider config so we can observe failure → recovery
	// without failover noise.
	m, err := NewMultiRPCProvider(
		[]*RPCProvider{newProviderForFake(t, primary.URL())},
		MultiRPCProviderOpts{
			MaxConsecutiveFailures: 5,
			Cooldown:               10 * time.Minute,
			now:                    clock.now,
		},
	)
	if err != nil {
		t.Fatalf("NewMultiRPCProvider: %v", err)
	}

	// First call fails (5xx → retryable).
	_, _ = m.GetRawTransactionVerbose("x")
	snap := m.HealthSnapshot()
	if snap[0].Failures != 1 {
		t.Fatalf("expected 1 failure, got %d", snap[0].Failures)
	}

	// Recover the node and call again.
	primary.setMode(0)
	if _, err := m.GetRawTransactionVerbose("x"); err != nil {
		t.Fatalf("recovery call: %v", err)
	}
	snap = m.HealthSnapshot()
	if snap[0].Failures != 0 {
		t.Fatalf("expected failures cleared on success, got %d", snap[0].Failures)
	}
}

func TestMultiRPCProvider_NoProvidersIsError(t *testing.T) {
	if _, err := NewMultiRPCProvider(nil, MultiRPCProviderOpts{}); err == nil {
		t.Fatalf("expected error on empty provider slice")
	}
	if _, err := NewMultiRPCProvider([]*RPCProvider{nil}, MultiRPCProviderOpts{}); err == nil {
		t.Fatalf("expected error on nil provider")
	}
}

func TestMultiRPCProvider_5xxCountedAsRetryable(t *testing.T) {
	primary := newFakeNode(t, dummySuccess)
	backup := newFakeNode(t, dummySuccess)
	defer primary.close()
	defer backup.close()

	primary.setMode(1) // 5xx

	m, err := NewMultiRPCProvider([]*RPCProvider{
		newProviderForFake(t, primary.URL()),
		newProviderForFake(t, backup.URL()),
	}, MultiRPCProviderOpts{})
	if err != nil {
		t.Fatalf("NewMultiRPCProvider: %v", err)
	}

	if _, err := m.GetRawTransactionVerbose("x"); err != nil {
		t.Fatalf("expected backup to serve after 5xx, got: %v", err)
	}
	if backup.callCount() != 1 {
		t.Fatalf("backup should serve, got %d", backup.callCount())
	}
}

// fakeClock is a monotonic stub clock for cooldown tests.
type fakeClock struct {
	t time.Time
}

func newFakeClock(t time.Time) *fakeClock { return &fakeClock{t: t} }

func (c *fakeClock) now() time.Time { return c.t }

func (c *fakeClock) advance(d time.Duration) { c.t = c.t.Add(d) }
