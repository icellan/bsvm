package arc

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// stubBroadcastServer is an httptest server that responds to POST
// /v1/tx with a configurable status + body, and counts hits.
func stubBroadcastServer(status int, body string, delay time.Duration, hits *int32) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hits != nil {
			atomic.AddInt32(hits, 1)
		}
		if delay > 0 {
			time.Sleep(delay)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
}

func okBody(txidHex string) string {
	return `{"txStatus":"SEEN_ON_NETWORK","txid":"` + txidHex + `"}`
}

func TestMultiClientFirstSuccess(t *testing.T) {
	var aHits, bHits, cHits int32
	a := stubBroadcastServer(http.StatusInternalServerError, `{"err":"boom"}`, 0, &aHits)
	defer a.Close()
	b := stubBroadcastServer(http.StatusOK, okBody(strings.Repeat("ab", 32)), 0, &bHits)
	defer b.Close()
	c := stubBroadcastServer(http.StatusInternalServerError, `{"err":"boom"}`, 50*time.Millisecond, &cHits)
	defer c.Close()

	mc, err := NewMultiClient(MultiConfig{
		Strategy: StrategyFirstSuccess,
		Endpoints: []EndpointConfig{
			{Name: "a", URL: a.URL},
			{Name: "b", URL: b.URL},
			{Name: "c", URL: c.URL},
		},
	})
	if err != nil {
		t.Fatalf("NewMultiClient: %v", err)
	}
	resp, err := mc.Broadcast(context.Background(), []byte{0xde, 0xad})
	if err != nil {
		t.Fatalf("Broadcast: %v", err)
	}
	if resp.Status != StatusSeenOnNetwork {
		t.Fatalf("status %s", resp.Status)
	}
	// All three should have been called (firstSuccess waits for the
	// successful one; cancellation lets the slow ones still finish if
	// they were already in flight, which is fine).
	if atomic.LoadInt32(&bHits) != 1 {
		t.Fatalf("expected b hit once, got %d", bHits)
	}
}

func TestMultiClientFirstSuccessAllFail(t *testing.T) {
	var hits int32
	a := stubBroadcastServer(http.StatusBadGateway, `{"err":"a"}`, 0, &hits)
	defer a.Close()
	b := stubBroadcastServer(http.StatusBadGateway, `{"err":"b"}`, 0, &hits)
	defer b.Close()
	mc, err := NewMultiClient(MultiConfig{
		Strategy: StrategyFirstSuccess,
		Endpoints: []EndpointConfig{
			{Name: "a", URL: a.URL},
			{Name: "b", URL: b.URL},
		},
	})
	if err != nil {
		t.Fatalf("NewMultiClient: %v", err)
	}
	_, err = mc.Broadcast(context.Background(), []byte{0xde})
	if err == nil {
		t.Fatalf("expected error")
	}
	var me *MultiError
	if !errors.As(err, &me) {
		t.Fatalf("not MultiError: %v", err)
	}
	if len(me.Errors()) != 2 {
		t.Fatalf("want 2 endpoint errors, got %d", len(me.Errors()))
	}
	for _, ee := range me.Errors() {
		if ee.Name == "" || ee.URL == "" || ee.Err == nil {
			t.Fatalf("bad endpoint error %+v", ee)
		}
		if !strings.Contains(ee.Err.Error(), "502") {
			t.Fatalf("expected 502 in error %v", ee.Err)
		}
	}
}

func TestMultiClientQuorumSatisfied(t *testing.T) {
	a := stubBroadcastServer(http.StatusOK, okBody(strings.Repeat("aa", 32)), 0, nil)
	defer a.Close()
	b := stubBroadcastServer(http.StatusOK, okBody(strings.Repeat("aa", 32)), 0, nil)
	defer b.Close()
	c := stubBroadcastServer(http.StatusBadGateway, `{"err":"c"}`, 0, nil)
	defer c.Close()
	mc, err := NewMultiClient(MultiConfig{
		Strategy: StrategyQuorum,
		Quorum:   2,
		Endpoints: []EndpointConfig{
			{Name: "a", URL: a.URL},
			{Name: "b", URL: b.URL},
			{Name: "c", URL: c.URL},
		},
	})
	if err != nil {
		t.Fatalf("NewMultiClient: %v", err)
	}
	resp, err := mc.Broadcast(context.Background(), []byte{0x01})
	if err != nil {
		t.Fatalf("Broadcast: %v", err)
	}
	if resp.Status != StatusSeenOnNetwork {
		t.Fatalf("status %s", resp.Status)
	}
}

func TestMultiClientQuorumUnsatisfied(t *testing.T) {
	a := stubBroadcastServer(http.StatusOK, okBody(strings.Repeat("aa", 32)), 0, nil)
	defer a.Close()
	b := stubBroadcastServer(http.StatusBadGateway, `{"err":"b"}`, 0, nil)
	defer b.Close()
	c := stubBroadcastServer(http.StatusBadGateway, `{"err":"c"}`, 0, nil)
	defer c.Close()
	mc, err := NewMultiClient(MultiConfig{
		Strategy: StrategyQuorum,
		Quorum:   2,
		Endpoints: []EndpointConfig{
			{Name: "a", URL: a.URL},
			{Name: "b", URL: b.URL},
			{Name: "c", URL: c.URL},
		},
	})
	if err != nil {
		t.Fatalf("NewMultiClient: %v", err)
	}
	_, err = mc.Broadcast(context.Background(), []byte{0x01})
	var me *MultiError
	if !errors.As(err, &me) {
		t.Fatalf("expected MultiError, got %v", err)
	}
	if me.Successes != 1 || me.Quorum != 2 {
		t.Fatalf("succ=%d q=%d", me.Successes, me.Quorum)
	}
	if len(me.Errors()) != 2 {
		t.Fatalf("want 2 failures, got %d", len(me.Errors()))
	}
	if !strings.Contains(me.Error(), "quorum=2") {
		t.Fatalf("aggregate error missing quorum context: %s", me.Error())
	}
}

func TestMultiClientSingleEndpointBackcompat(t *testing.T) {
	srv := stubBroadcastServer(http.StatusOK, okBody(strings.Repeat("ab", 32)), 0, nil)
	defer srv.Close()
	mc, err := NewMultiClient(MultiConfig{
		Endpoints: []EndpointConfig{{URL: srv.URL}},
	})
	if err != nil {
		t.Fatalf("NewMultiClient: %v", err)
	}
	resp, err := mc.Broadcast(context.Background(), []byte{0x02})
	if err != nil {
		t.Fatalf("Broadcast: %v", err)
	}
	if resp.Status != StatusSeenOnNetwork {
		t.Fatalf("status %s", resp.Status)
	}
}

func TestMultiClientRetryTransient(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&calls, 1)
		if n < 3 {
			http.Error(w, "transient", http.StatusBadGateway)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(okBody(strings.Repeat("aa", 32))))
	}))
	defer srv.Close()
	mc, err := NewMultiClient(MultiConfig{
		Endpoints: []EndpointConfig{{
			URL:          srv.URL,
			MaxRetries:   3,
			RetryBackoff: 1 * time.Millisecond,
		}},
	})
	if err != nil {
		t.Fatalf("NewMultiClient: %v", err)
	}
	resp, err := mc.Broadcast(context.Background(), []byte{0xfe})
	if err != nil {
		t.Fatalf("Broadcast: %v", err)
	}
	if resp.Status != StatusSeenOnNetwork {
		t.Fatalf("status %s", resp.Status)
	}
	if atomic.LoadInt32(&calls) != 3 {
		t.Fatalf("want 3 calls (2 transient + 1 ok), got %d", calls)
	}
}

func TestMultiClientRetryStopsOn4xx(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		http.Error(w, "bad", http.StatusBadRequest)
	}))
	defer srv.Close()
	mc, _ := NewMultiClient(MultiConfig{
		Endpoints: []EndpointConfig{{
			URL: srv.URL, MaxRetries: 5, RetryBackoff: time.Millisecond,
		}},
	})
	_, err := mc.Broadcast(context.Background(), []byte{0x00})
	if err == nil {
		t.Fatalf("expected error")
	}
	if atomic.LoadInt32(&calls) != 1 {
		t.Fatalf("want 1 call (no retry on 4xx), got %d", calls)
	}
}

func TestMultiClientStatusFirstNonUnknown(t *testing.T) {
	a := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r) // → UNKNOWN
	}))
	defer a.Close()
	b := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"txStatus":"MINED","txid":"%s","blockHeight":99}`, strings.Repeat("ab", 32))
	}))
	defer b.Close()
	mc, _ := NewMultiClient(MultiConfig{
		Endpoints: []EndpointConfig{{Name: "a", URL: a.URL}, {Name: "b", URL: b.URL}},
	})
	var txid [32]byte
	st, err := mc.Status(context.Background(), txid)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if st.Status != StatusMined {
		t.Fatalf("want MINED, got %s", st.Status)
	}
	if st.BlockHeight != 99 {
		t.Fatalf("bh %d", st.BlockHeight)
	}
}

func TestMultiClientPing(t *testing.T) {
	a := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "bad", http.StatusInternalServerError)
	}))
	defer a.Close()
	b := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer b.Close()
	mc, _ := NewMultiClient(MultiConfig{
		Endpoints: []EndpointConfig{{Name: "a", URL: a.URL}, {Name: "b", URL: b.URL}},
	})
	if err := mc.Ping(context.Background()); err != nil {
		t.Fatalf("Ping: %v", err)
	}
}

func TestMultiClientPingAllFail(t *testing.T) {
	a := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "bad", http.StatusInternalServerError)
	}))
	defer a.Close()
	mc, _ := NewMultiClient(MultiConfig{
		Endpoints: []EndpointConfig{{Name: "a", URL: a.URL}},
	})
	err := mc.Ping(context.Background())
	if err == nil {
		t.Fatalf("expected error")
	}
	var me *MultiError
	if !errors.As(err, &me) {
		t.Fatalf("not MultiError: %v", err)
	}
	if len(me.Errors()) != 1 {
		t.Fatalf("want 1 failure, got %d", len(me.Errors()))
	}
}

func TestMultiClientConcurrentSafety(t *testing.T) {
	var hits int32
	srv := stubBroadcastServer(http.StatusOK, okBody(strings.Repeat("ab", 32)), 0, &hits)
	defer srv.Close()
	mc, _ := NewMultiClient(MultiConfig{Endpoints: []EndpointConfig{{URL: srv.URL}}})
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = mc.Broadcast(context.Background(), []byte{0x01})
		}()
	}
	wg.Wait()
	if atomic.LoadInt32(&hits) != 32 {
		t.Fatalf("want 32 hits, got %d", hits)
	}
}

func TestMultiClientConfigErrors(t *testing.T) {
	if _, err := NewMultiClient(MultiConfig{}); err == nil {
		t.Fatalf("expected error: no endpoints")
	}
	if _, err := NewMultiClient(MultiConfig{
		Endpoints: []EndpointConfig{{Name: "a"}},
	}); err == nil {
		t.Fatalf("expected error: missing URL")
	}
	if _, err := NewMultiClient(MultiConfig{
		Strategy:  StrategyQuorum,
		Quorum:    5,
		Endpoints: []EndpointConfig{{URL: "http://x"}, {URL: "http://y"}},
	}); err == nil {
		t.Fatalf("expected error: quorum > endpoints")
	}
}
