package arc

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestClientBroadcast(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/tx" || r.Method != http.MethodPost {
			http.Error(w, "bad", http.StatusBadRequest)
			return
		}
		if r.Header.Get("X-CallbackUrl") != "https://my.example/cb" {
			t.Errorf("missing callback url header")
		}
		if r.Header.Get("X-CallbackToken") != "secret" {
			t.Errorf("missing callback token header")
		}
		body, _ := io.ReadAll(r.Body)
		var req map[string]string
		_ = json.Unmarshal(body, &req)
		if !strings.HasPrefix(req["rawTx"], "deadbeef") {
			t.Errorf("rawTx not hex-encoded")
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"txStatus":"SEEN_ON_NETWORK","txid":"` + strings.Repeat("ab", 32) + `"}`))
	}))
	defer srv.Close()
	c, err := NewClient(Config{
		URL:           srv.URL,
		Timeout:       2 * time.Second,
		CallbackURL:   "https://my.example/cb",
		CallbackToken: "secret",
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	tx := []byte{0xde, 0xad, 0xbe, 0xef}
	resp, err := c.Broadcast(context.Background(), tx)
	if err != nil {
		t.Fatalf("Broadcast: %v", err)
	}
	if resp.Status != StatusSeenOnNetwork {
		t.Fatalf("status = %s", resp.Status)
	}
	wantHex := strings.Repeat("ab", 32)
	gotHex := hex.EncodeToString(resp.TxID[:])
	if gotHex != wantHex {
		t.Fatalf("txid hex %s want %s", gotHex, wantHex)
	}
}

func TestClientStatusUnknown(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()
	c, _ := NewClient(Config{URL: srv.URL, Timeout: 2 * time.Second})
	var txid [32]byte
	st, err := c.Status(context.Background(), txid)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if st.Status != StatusUnknown {
		t.Fatalf("expected UNKNOWN, got %s", st.Status)
	}
}

func TestClientPing(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/policy" {
			http.NotFound(w, r)
			return
		}
		w.Write([]byte("ok"))
	}))
	defer srv.Close()
	c, _ := NewClient(Config{URL: srv.URL, Timeout: 2 * time.Second})
	if err := c.Ping(context.Background()); err != nil {
		t.Fatalf("Ping: %v", err)
	}
}
