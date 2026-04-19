package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// rpcMethodCall captures one inbound JSON-RPC request so tests can
// assert on method + params without parsing the raw body repeatedly.
type rpcMethodCall struct {
	Method string
	Params []interface{}
	Auth   string // Authorization header as supplied by the client
}

// newFakeBSVServer returns an httptest.Server that replies with the
// supplied results keyed by method name. Missing methods produce a
// 500. Every inbound call is appended to *calls.
func newFakeBSVServer(t *testing.T, results map[string]interface{}, calls *[]rpcMethodCall) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req struct {
			Method string        `json:"method"`
			Params []interface{} `json:"params"`
			ID     int           `json:"id"`
		}
		if err := json.Unmarshal(body, &req); err != nil {
			t.Errorf("bad request body: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if calls != nil {
			*calls = append(*calls, rpcMethodCall{
				Method: req.Method,
				Params: req.Params,
				Auth:   r.Header.Get("Authorization"),
			})
		}
		result, ok := results[req.Method]
		if !ok {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"error":{"code":-1,"message":"unknown method"}}`))
			return
		}
		payload := map[string]interface{}{
			"result": result,
			"error":  nil,
			"id":     req.ID,
		}
		raw, _ := json.Marshal(payload)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(raw)
	}))
}

func TestBSVRPCClient_GenerateToAddress(t *testing.T) {
	var calls []rpcMethodCall
	srv := newFakeBSVServer(t, map[string]interface{}{
		"generatetoaddress": []string{"hash1", "hash2", "hash3"},
	}, &calls)
	defer srv.Close()

	c := newBSVRPCClient(srv.URL)
	hashes, err := c.generateToAddress(3, "1FakeAddr")
	if err != nil {
		t.Fatalf("generateToAddress: %v", err)
	}
	if len(hashes) != 3 || hashes[0] != "hash1" || hashes[2] != "hash3" {
		t.Errorf("unexpected hashes: %v", hashes)
	}
	if len(calls) != 1 || calls[0].Method != "generatetoaddress" {
		t.Errorf("expected 1 call to generatetoaddress, got %+v", calls)
	}
	if len(calls[0].Params) != 2 {
		t.Errorf("expected 2 params (blocks, address), got %v", calls[0].Params)
	}
	// JSON parses ints as float64 by default.
	if blocks, ok := calls[0].Params[0].(float64); !ok || int(blocks) != 3 {
		t.Errorf("blocks param: expected 3, got %v", calls[0].Params[0])
	}
	if addr, ok := calls[0].Params[1].(string); !ok || addr != "1FakeAddr" {
		t.Errorf("address param: expected 1FakeAddr, got %v", calls[0].Params[1])
	}
}

func TestBSVRPCClient_GetNewAddress(t *testing.T) {
	srv := newFakeBSVServer(t, map[string]interface{}{
		"getnewaddress": "1GeneratedAddress",
	}, nil)
	defer srv.Close()

	c := newBSVRPCClient(srv.URL)
	addr, err := c.getNewAddress()
	if err != nil {
		t.Fatalf("getNewAddress: %v", err)
	}
	if addr != "1GeneratedAddress" {
		t.Errorf("unexpected addr: %q", addr)
	}
}

func TestBSVRPCClient_BasicAuthStrippedFromEndpoint(t *testing.T) {
	// Verify credentials in the URL are applied as basic auth and
	// scrubbed from the request target.
	var calls []rpcMethodCall
	srv := newFakeBSVServer(t, map[string]interface{}{
		"getnewaddress": "1addr",
	}, &calls)
	defer srv.Close()

	// Rewrite the server URL to include credentials.
	withCreds := strings.Replace(srv.URL, "http://", "http://alice:s3cret@", 1)
	c := newBSVRPCClient(withCreds)

	if c.username != "alice" || c.password != "s3cret" {
		t.Errorf("expected creds parsed, got user=%q pass=%q", c.username, c.password)
	}
	if strings.Contains(c.endpoint, "alice") {
		t.Errorf("endpoint still carries creds: %q", c.endpoint)
	}
	if _, err := c.getNewAddress(); err != nil {
		t.Fatalf("getNewAddress: %v", err)
	}
	if len(calls) != 1 {
		t.Fatalf("expected 1 call, got %d", len(calls))
	}
	// Authorization header present on the real request.
	if !strings.HasPrefix(calls[0].Auth, "Basic ") {
		t.Errorf("expected basic auth header, got %q", calls[0].Auth)
	}
}

func TestBSVRPCClient_ErrorSurface(t *testing.T) {
	// A JSON-RPC error body should surface as a Go error rather than a
	// silent empty result.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"result":null,"error":{"code":-32601,"message":"method not found"},"id":1}`))
	}))
	defer srv.Close()

	c := newBSVRPCClient(srv.URL)
	_, err := c.getNewAddress()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "method not found") {
		t.Errorf("unexpected error text: %v", err)
	}
}
