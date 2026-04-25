package bsvclient

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/bsv-blockchain/go-sdk/transaction"
)

// ---------------------------------------------------------------------
// URL / constructor parsing
// ---------------------------------------------------------------------

func TestNewRPCProvider_WithAuth(t *testing.T) {
	p, err := NewRPCProvider("http://alice:s3cr3t@127.0.0.1:18332/", "regtest")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !p.hasAuth {
		t.Fatalf("expected hasAuth=true")
	}
	if p.user != "alice" || p.pass != "s3cr3t" {
		t.Fatalf("user/pass not captured: %q / %q", p.user, p.pass)
	}
	if strings.Contains(p.endpoint, "alice") || strings.Contains(p.endpoint, "s3cr3t") {
		t.Fatalf("endpoint must be stripped of userinfo, got %q", p.endpoint)
	}
	if p.GetNetwork() != "regtest" {
		t.Fatalf("network=%q, want regtest", p.GetNetwork())
	}
}

func TestNewRPCProvider_NoAuth(t *testing.T) {
	p, err := NewRPCProvider("http://localhost:18332/", "testnet")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.hasAuth {
		t.Fatalf("expected hasAuth=false for URL without userinfo")
	}
	if p.user != "" || p.pass != "" {
		t.Fatalf("expected empty user/pass, got %q / %q", p.user, p.pass)
	}
	if p.GetNetwork() != "testnet" {
		t.Fatalf("network=%q, want testnet", p.GetNetwork())
	}
}

func TestNewRPCProvider_EmptyPassword(t *testing.T) {
	// URL with userinfo that has a username but no password — valid,
	// must still be treated as auth-present.
	p, err := NewRPCProvider("http://alice@localhost:18332/", "mainnet")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !p.hasAuth {
		t.Fatalf("expected hasAuth=true when username is present")
	}
	if p.user != "alice" || p.pass != "" {
		t.Fatalf("user=%q pass=%q, want alice / empty", p.user, p.pass)
	}
}

func TestNewRPCProvider_Invalid(t *testing.T) {
	cases := []struct {
		name, url, network string
	}{
		{"empty url", "", "regtest"},
		{"bad network", "http://localhost:18332/", "ghostnet"},
		{"bad scheme", "ftp://localhost:18332/", "regtest"},
		{"no host", "http://", "regtest"},
		{"unparseable", "http://[::1", "regtest"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewRPCProvider(tc.url, tc.network); err == nil {
				t.Fatalf("expected error, got nil")
			}
		})
	}
}

// ---------------------------------------------------------------------
// Mock JSON-RPC server fixture
// ---------------------------------------------------------------------

// mockRPC is a test double that dispatches JSON-RPC 1.0 requests to
// per-method handlers supplied by the test.
type mockRPC struct {
	t           *testing.T
	handlers    map[string]func(params []interface{}) (interface{}, *rpcErrorBody)
	requireUser string
	requirePass string
	calls       atomic.Int64
}

func newMockRPC(t *testing.T) *mockRPC {
	return &mockRPC{
		t:        t,
		handlers: make(map[string]func([]interface{}) (interface{}, *rpcErrorBody)),
	}
}

func (m *mockRPC) on(method string, h func(params []interface{}) (interface{}, *rpcErrorBody)) {
	m.handlers[method] = h
}

func (m *mockRPC) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	m.calls.Add(1)

	if m.requireUser != "" || m.requirePass != "" {
		u, p, ok := r.BasicAuth()
		if !ok || u != m.requireUser || p != m.requirePass {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	var req rpcRequestEnvelope
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	h, ok := m.handlers[req.Method]
	if !ok {
		m.t.Errorf("unexpected RPC method: %s", req.Method)
		http.Error(w, "unknown method", http.StatusNotFound)
		return
	}
	result, rpcErr := h(req.Params)

	env := struct {
		Result interface{}   `json:"result"`
		Error  *rpcErrorBody `json:"error"`
		ID     uint64        `json:"id"`
	}{Result: result, Error: rpcErr, ID: req.ID}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(env)
}

// ---------------------------------------------------------------------
// GetTransaction / GetRawTransaction / GetRawTransactionVerbose
// ---------------------------------------------------------------------

func TestGetTransaction_MockServer(t *testing.T) {
	mock := newMockRPC(t)
	mock.on("getrawtransaction", func(params []interface{}) (interface{}, *rpcErrorBody) {
		if len(params) != 2 {
			t.Errorf("want 2 params, got %d", len(params))
		}
		if params[0].(string) != "deadbeef" {
			t.Errorf("txid param = %v", params[0])
		}
		// Verbose param must be the integer 1, not bool true.
		if v, ok := params[1].(float64); !ok || v != 1 {
			t.Errorf("verbose param = %v (%T), want 1 (number)", params[1], params[1])
		}
		return map[string]interface{}{
			"hex": "01000000aabb",
			"vout": []interface{}{
				map[string]interface{}{
					"value": 0.00012345,
					"scriptPubKey": map[string]interface{}{
						"hex": "76a914abcdef88ac",
					},
				},
				map[string]interface{}{
					"value": 1.0,
					"scriptPubKey": map[string]interface{}{
						"hex": "6a044d454d4f",
					},
				},
			},
			"confirmations": float64(7),
		}, nil
	})

	srv := httptest.NewServer(mock)
	defer srv.Close()

	p, err := NewRPCProvider(srv.URL+"/", "regtest")
	if err != nil {
		t.Fatalf("NewRPCProvider: %v", err)
	}

	td, err := p.GetTransaction("deadbeef")
	if err != nil {
		t.Fatalf("GetTransaction: %v", err)
	}
	if td.Raw != "01000000aabb" {
		t.Errorf("Raw = %q", td.Raw)
	}
	if td.Txid != "deadbeef" {
		t.Errorf("Txid = %q", td.Txid)
	}
	if td.Version != 1 {
		t.Errorf("Version = %d", td.Version)
	}
	if len(td.Outputs) != 2 {
		t.Fatalf("Outputs len = %d, want 2", len(td.Outputs))
	}
	if td.Outputs[0].Satoshis != 12345 {
		t.Errorf("Outputs[0].Satoshis = %d, want 12345", td.Outputs[0].Satoshis)
	}
	if td.Outputs[0].Script != "76a914abcdef88ac" {
		t.Errorf("Outputs[0].Script = %q", td.Outputs[0].Script)
	}
	if td.Outputs[1].Satoshis != 100_000_000 {
		t.Errorf("Outputs[1].Satoshis = %d, want 100000000", td.Outputs[1].Satoshis)
	}

	// Same fixture exercises GetRawTransaction and GetRawTransactionVerbose.
	rawHex, err := p.GetRawTransaction("deadbeef")
	if err != nil {
		t.Fatalf("GetRawTransaction: %v", err)
	}
	if rawHex != "01000000aabb" {
		t.Errorf("GetRawTransaction = %q", rawHex)
	}

	verbose, err := p.GetRawTransactionVerbose("deadbeef")
	if err != nil {
		t.Fatalf("GetRawTransactionVerbose: %v", err)
	}
	if conf, _ := verbose["confirmations"].(float64); conf != 7 {
		t.Errorf("verbose confirmations = %v, want 7", verbose["confirmations"])
	}
	if _, ok := verbose["vout"]; !ok {
		t.Errorf("verbose result missing vout field")
	}
}

// ---------------------------------------------------------------------
// GetUtxos
// ---------------------------------------------------------------------

func TestGetUtxos_MockServer(t *testing.T) {
	mock := newMockRPC(t)
	mock.on("listunspent", func(params []interface{}) (interface{}, *rpcErrorBody) {
		if len(params) != 3 {
			t.Errorf("want 3 params, got %d", len(params))
		}
		return []interface{}{
			map[string]interface{}{
				"txid":         "11aa",
				"vout":         float64(0),
				"amount":       0.5,
				"scriptPubKey": "76a9abcd88ac",
			},
			map[string]interface{}{
				"txid":         "22bb",
				"vout":         float64(3),
				"amount":       0.00000001,
				"scriptPubKey": "deadbeef",
			},
		}, nil
	})
	srv := httptest.NewServer(mock)
	defer srv.Close()

	p, err := NewRPCProvider(srv.URL+"/", "regtest")
	if err != nil {
		t.Fatalf("NewRPCProvider: %v", err)
	}
	utxos, err := p.GetUtxos("mxxx")
	if err != nil {
		t.Fatalf("GetUtxos: %v", err)
	}
	if len(utxos) != 2 {
		t.Fatalf("len=%d, want 2", len(utxos))
	}
	if utxos[0].Txid != "11aa" || utxos[0].OutputIndex != 0 || utxos[0].Satoshis != 50_000_000 {
		t.Errorf("utxo[0]=%+v", utxos[0])
	}
	if utxos[1].Txid != "22bb" || utxos[1].OutputIndex != 3 || utxos[1].Satoshis != 1 {
		t.Errorf("utxo[1]=%+v", utxos[1])
	}
}

// ---------------------------------------------------------------------
// Broadcast
// ---------------------------------------------------------------------

func TestBroadcast_MockServer(t *testing.T) {
	mock := newMockRPC(t)
	mock.requireUser = "alice"
	mock.requirePass = "s3cr3t"

	var captured string
	mock.on("sendrawtransaction", func(params []interface{}) (interface{}, *rpcErrorBody) {
		if len(params) != 1 {
			t.Errorf("want 1 param, got %d", len(params))
		}
		captured, _ = params[0].(string)
		return "cafef00d", nil
	})
	srv := httptest.NewServer(mock)
	defer srv.Close()

	// Inject basic-auth via userinfo.
	rpcURL := strings.Replace(srv.URL, "http://", "http://alice:s3cr3t@", 1) + "/"
	p, err := NewRPCProvider(rpcURL, "regtest")
	if err != nil {
		t.Fatalf("NewRPCProvider: %v", err)
	}

	tx := transaction.NewTransaction()
	txid, err := p.Broadcast(tx)
	if err != nil {
		t.Fatalf("Broadcast: %v", err)
	}
	if txid != "cafef00d" {
		t.Errorf("txid=%q", txid)
	}
	if captured == "" {
		t.Errorf("server did not observe raw hex")
	}
	if mock.calls.Load() != 1 {
		t.Errorf("expected exactly 1 RPC call (no auto-mine), got %d", mock.calls.Load())
	}
}

func TestBroadcast_RPCError(t *testing.T) {
	mock := newMockRPC(t)
	mock.on("sendrawtransaction", func(params []interface{}) (interface{}, *rpcErrorBody) {
		return nil, &rpcErrorBody{Code: -26, Message: "dust"}
	})
	srv := httptest.NewServer(mock)
	defer srv.Close()

	p, err := NewRPCProvider(srv.URL+"/", "regtest")
	if err != nil {
		t.Fatalf("NewRPCProvider: %v", err)
	}
	if _, err := p.Broadcast(transaction.NewTransaction()); err == nil {
		t.Fatalf("expected error from dust response")
	} else if !strings.Contains(err.Error(), "dust") {
		t.Errorf("err does not surface node message: %v", err)
	}
}

// ---------------------------------------------------------------------
// Static / trivial methods
// ---------------------------------------------------------------------

func TestGetFeeRate_NoRPC(t *testing.T) {
	// Server will t.Errorf on any unexpected method. GetFeeRate must
	// not call any RPC.
	mock := newMockRPC(t)
	srv := httptest.NewServer(mock)
	defer srv.Close()

	p, err := NewRPCProvider(srv.URL+"/", "regtest")
	if err != nil {
		t.Fatalf("NewRPCProvider: %v", err)
	}
	rate, err := p.GetFeeRate()
	if err != nil {
		t.Fatalf("GetFeeRate: %v", err)
	}
	if rate != 1 {
		t.Errorf("rate=%d, want 1", rate)
	}
	if mock.calls.Load() != 0 {
		t.Errorf("GetFeeRate issued %d RPC calls, want 0", mock.calls.Load())
	}
}

func TestGetContractUtxo_NotSupported(t *testing.T) {
	p, err := NewRPCProvider("http://localhost:18332/", "regtest")
	if err != nil {
		t.Fatalf("NewRPCProvider: %v", err)
	}
	u, err := p.GetContractUtxo("abcd")
	if u != nil {
		t.Errorf("UTXO should be nil, got %+v", u)
	}
	if err == nil {
		t.Fatalf("expected explicit error")
	}
	if !strings.Contains(err.Error(), "not supported") {
		t.Errorf("error should say 'not supported', got %v", err)
	}
}

// ---------------------------------------------------------------------
// Call (public raw RPC wrapper)
// ---------------------------------------------------------------------

func TestCall_ForwardsMethodAndParams(t *testing.T) {
	mock := newMockRPC(t)
	mock.on("importaddress", func(params []interface{}) (interface{}, *rpcErrorBody) {
		if len(params) != 3 {
			t.Errorf("want 3 params, got %d", len(params))
		}
		if addr, _ := params[0].(string); addr != "mabc" {
			t.Errorf("address param=%v", params[0])
		}
		if label, _ := params[1].(string); label != "" {
			t.Errorf("label param=%v", params[1])
		}
		// JSON decodes booleans as bool.
		if rescan, _ := params[2].(bool); rescan != false {
			t.Errorf("rescan param=%v", params[2])
		}
		return nil, nil
	})
	srv := httptest.NewServer(mock)
	defer srv.Close()

	p, err := NewRPCProvider(srv.URL+"/", "regtest")
	if err != nil {
		t.Fatalf("NewRPCProvider: %v", err)
	}
	result, err := p.Call("importaddress", "mabc", "", false)
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	// Result may be JSON `null` for importaddress; either way, no error.
	if result != nil && string(result) != "null" {
		t.Errorf("unexpected result: %s", string(result))
	}
	if mock.calls.Load() != 1 {
		t.Errorf("expected 1 RPC call, got %d", mock.calls.Load())
	}
}

func TestCall_ErrorPropagates(t *testing.T) {
	mock := newMockRPC(t)
	mock.on("sendtoaddress", func(params []interface{}) (interface{}, *rpcErrorBody) {
		return nil, &rpcErrorBody{Code: -6, Message: "Insufficient funds"}
	})
	srv := httptest.NewServer(mock)
	defer srv.Close()

	p, err := NewRPCProvider(srv.URL+"/", "regtest")
	if err != nil {
		t.Fatalf("NewRPCProvider: %v", err)
	}
	_, err = p.Call("sendtoaddress", "mabc", 5.0)
	if err == nil {
		t.Fatalf("expected error from RPC error response")
	}
	if !strings.Contains(err.Error(), "Insufficient funds") {
		t.Errorf("err does not surface node message: %v", err)
	}
}

func TestGetNetwork(t *testing.T) {
	for _, n := range []string{"regtest", "testnet", "mainnet"} {
		p, err := NewRPCProvider("http://localhost:18332/", n)
		if err != nil {
			t.Fatalf("NewRPCProvider(%q): %v", n, err)
		}
		if p.GetNetwork() != n {
			t.Errorf("GetNetwork()=%q, want %q", p.GetNetwork(), n)
		}
	}
}
