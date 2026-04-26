package arc

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func TestCallbackHandlerAuthAndDispatch(t *testing.T) {
	var (
		mu    sync.Mutex
		seen  []*CallbackEvent
	)
	h := NewCallbackHandler([]string{"tok-1"}, func(ev *CallbackEvent) {
		mu.Lock()
		seen = append(seen, ev)
		mu.Unlock()
	})

	body := `{"txid":"` + strings.Repeat("aa", 32) + `","txStatus":"MINED","blockHash":"` + strings.Repeat("bb", 32) + `","blockHeight":42,"merklePath":"deadbeef"}`

	// missing token => 401
	req := httptest.NewRequest(http.MethodPost, "/cb", bytes.NewReader([]byte(body)))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("missing token: code %d", rec.Code)
	}

	// wrong token => 401
	req = httptest.NewRequest(http.MethodPost, "/cb", bytes.NewReader([]byte(body)))
	req.Header.Set("X-CallbackToken", "nope")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("bad token: code %d", rec.Code)
	}

	// good token (X-CallbackToken)
	req = httptest.NewRequest(http.MethodPost, "/cb", bytes.NewReader([]byte(body)))
	req.Header.Set("X-CallbackToken", "tok-1")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("good token: code %d body %s", rec.Code, rec.Body.String())
	}
	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 1 {
		t.Fatalf("seen %d events", len(seen))
	}
	ev := seen[0]
	if ev.Status != StatusMined {
		t.Fatalf("bad status %s", ev.Status)
	}
	if ev.BlockHeight != 42 {
		t.Fatalf("bad height %d", ev.BlockHeight)
	}
	if len(ev.MerklePath) != 4 || ev.MerklePath[0] != 0xde {
		t.Fatalf("bad merkle path %x", ev.MerklePath)
	}
}

func TestCallbackHandlerBadPayload(t *testing.T) {
	h := NewCallbackHandler([]string{"tok"}, nil)
	req := httptest.NewRequest(http.MethodPost, "/cb", bytes.NewReader([]byte("not json")))
	req.Header.Set("X-CallbackToken", "tok")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("got %d", rec.Code)
	}
}

func TestCallbackHandlerMethodCheck(t *testing.T) {
	h := NewCallbackHandler(nil, nil)
	req := httptest.NewRequest(http.MethodGet, "/cb", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("got %d", rec.Code)
	}
}

func TestCallbackTokenRotation(t *testing.T) {
	h := NewCallbackHandler([]string{"old"}, nil)
	h.SetTokens([]string{"old", "new"})
	body := `{"txid":"` + strings.Repeat("aa", 32) + `","txStatus":"SEEN_ON_NETWORK"}`
	for _, tok := range []string{"old", "new"} {
		req := httptest.NewRequest(http.MethodPost, "/cb", bytes.NewReader([]byte(body)))
		req.Header.Set("X-CallbackToken", tok)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusNoContent {
			t.Fatalf("token %s rejected: %d", tok, rec.Code)
		}
	}
}
