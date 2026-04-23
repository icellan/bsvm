package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/icellan/bsvm/internal/db"
	"github.com/icellan/bsvm/pkg/bsvclient"
	"github.com/icellan/bsvm/pkg/overlay"
	"github.com/icellan/bsvm/pkg/types"
)

// ---------------------------------------------------------------------
// Mock RPC fixture mirrored from pkg/bsvclient/rpc_provider_test.go.
// Kept private to this test file so the two mocks can evolve
// independently.
// ---------------------------------------------------------------------

type mockRPCRequest struct {
	JSONRPC string        `json:"jsonrpc"`
	ID      uint64        `json:"id"`
	Method  string        `json:"method"`
	Params  []interface{} `json:"params"`
}

type mockRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type mockRPC struct {
	t        *testing.T
	handlers map[string]func(params []interface{}) (interface{}, *mockRPCError)
	calls    atomic.Int64
	// callLog records every method the server saw, in order. Lets
	// tests assert the full RPC call sequence.
	callLog []string
}

func newMockRPC(t *testing.T) *mockRPC {
	return &mockRPC{
		t:        t,
		handlers: make(map[string]func([]interface{}) (interface{}, *mockRPCError)),
	}
}

func (m *mockRPC) on(method string, h func(params []interface{}) (interface{}, *mockRPCError)) {
	m.handlers[method] = h
}

func (m *mockRPC) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	m.calls.Add(1)

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	var req mockRPCRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	m.callLog = append(m.callLog, req.Method)

	h, ok := m.handlers[req.Method]
	if !ok {
		m.t.Errorf("unexpected RPC method: %s", req.Method)
		http.Error(w, "unknown method", http.StatusNotFound)
		return
	}
	result, rpcErr := h(req.Params)

	env := struct {
		Result interface{}   `json:"result"`
		Error  *mockRPCError `json:"error"`
		ID     uint64        `json:"id"`
	}{Result: result, Error: rpcErr, ID: req.ID}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(env)
}

// newFeeWallet returns a fresh FeeWallet backed by in-memory db.
func newFeeWallet(t *testing.T) *overlay.FeeWallet {
	t.Helper()
	fw := overlay.NewFeeWallet(db.NewMemoryDB())
	if err := fw.LoadFromDB(); err != nil {
		t.Fatalf("FeeWallet.LoadFromDB: %v", err)
	}
	return fw
}

// seedFeeWallet pre-funds the wallet with a single UTXO worth `sats`.
func seedFeeWallet(t *testing.T, fw *overlay.FeeWallet, sats uint64) {
	t.Helper()
	if err := fw.AddUTXO(&overlay.FeeUTXO{
		TxID:         types.HexToHash("00"),
		Vout:         0,
		Satoshis:     sats,
		ScriptPubKey: []byte{0xaa, 0xbb},
		Confirmed:    true,
	}); err != nil {
		t.Fatalf("seed AddUTXO: %v", err)
	}
}

// ---------------------------------------------------------------------
// Table-driven tests
// ---------------------------------------------------------------------

// TestBootstrapFeeWallet_AlreadyFunded confirms that when the wallet
// balance is already above MinBalanceSats the bootstrap returns
// immediately without issuing any RPC calls.
func TestBootstrapFeeWallet_AlreadyFunded(t *testing.T) {
	mock := newMockRPC(t)
	srv := httptest.NewServer(mock)
	defer srv.Close()

	provider, err := bsvclient.NewRPCProvider(srv.URL+"/", "regtest")
	if err != nil {
		t.Fatalf("NewRPCProvider: %v", err)
	}
	fw := newFeeWallet(t)
	seedFeeWallet(t, fw, defaultMinBalanceSats+1)

	ingested, err := BootstrapFeeWallet(context.Background(), BootstrapOpts{
		Provider:  provider,
		FeeWallet: fw,
		Address:   "mabc",
		Network:   "regtest",
	})
	if err != nil {
		t.Fatalf("BootstrapFeeWallet: %v", err)
	}
	if ingested != 0 {
		t.Errorf("ingested=%d, want 0", ingested)
	}
	if mock.calls.Load() != 0 {
		t.Errorf("expected 0 RPC calls on already-funded wallet, got %d (methods: %v)",
			mock.calls.Load(), mock.callLog)
	}
}

// TestBootstrapFeeWallet_NonRegtest confirms the bootstrap is a no-op
// on testnet/mainnet and issues zero RPC calls.
func TestBootstrapFeeWallet_NonRegtest(t *testing.T) {
	for _, network := range []string{"testnet", "mainnet", ""} {
		t.Run(network, func(t *testing.T) {
			mock := newMockRPC(t)
			srv := httptest.NewServer(mock)
			defer srv.Close()

			// Provider must be built with a legal network value; the
			// non-regtest NETWORK under test is the one passed into
			// BootstrapOpts.Network. For "" we still need a legal
			// provider.
			provider, err := bsvclient.NewRPCProvider(srv.URL+"/", "testnet")
			if err != nil {
				t.Fatalf("NewRPCProvider: %v", err)
			}
			fw := newFeeWallet(t)

			ingested, err := BootstrapFeeWallet(context.Background(), BootstrapOpts{
				Provider:  provider,
				FeeWallet: fw,
				Address:   "mabc",
				Network:   network,
			})
			if err != nil {
				t.Fatalf("BootstrapFeeWallet: %v", err)
			}
			if ingested != 0 {
				t.Errorf("ingested=%d, want 0", ingested)
			}
			if mock.calls.Load() != 0 {
				t.Errorf("expected 0 RPC calls on non-regtest, got %d (methods: %v)",
					mock.calls.Load(), mock.callLog)
			}
		})
	}
}

// TestBootstrapFeeWallet_FundMineIngest exercises the full happy path:
// importaddress → sendtoaddress → generatetoaddress → listunspent
// (poll) → AddUTXO. Asserts at least one UTXO ends up in the wallet
// with the satoshi value the listunspent response advertised.
func TestBootstrapFeeWallet_FundMineIngest(t *testing.T) {
	mock := newMockRPC(t)

	// Track which methods have already run so listunspent only returns
	// the funded UTXO after generatetoaddress has been observed.
	var funded atomic.Bool

	mock.on("importaddress", func(params []interface{}) (interface{}, *mockRPCError) {
		if len(params) != 3 {
			t.Errorf("importaddress: want 3 params, got %d", len(params))
		}
		if got, _ := params[0].(string); got != "mfee" {
			t.Errorf("importaddress address=%v, want mfee", params[0])
		}
		// label must be empty string
		if got, _ := params[1].(string); got != "" {
			t.Errorf("importaddress label=%v, want empty", params[1])
		}
		// rescan must be false
		if got, _ := params[2].(bool); got != false {
			t.Errorf("importaddress rescan=%v, want false", params[2])
		}
		return nil, nil
	})

	mock.on("sendtoaddress", func(params []interface{}) (interface{}, *mockRPCError) {
		if len(params) != 2 {
			t.Errorf("sendtoaddress: want 2 params, got %d", len(params))
		}
		if got, _ := params[0].(string); got != "mfee" {
			t.Errorf("sendtoaddress address=%v", params[0])
		}
		if got, _ := params[1].(float64); got != 5.0 {
			t.Errorf("sendtoaddress amount=%v, want 5.0", params[1])
		}
		return "f00dcafe", nil
	})

	mock.on("generatetoaddress", func(params []interface{}) (interface{}, *mockRPCError) {
		if len(params) != 2 {
			t.Errorf("generatetoaddress: want 2 params, got %d", len(params))
		}
		if got, _ := params[0].(float64); got != 1 {
			t.Errorf("generatetoaddress blocks=%v, want 1", params[0])
		}
		if got, _ := params[1].(string); got != "mfee" {
			t.Errorf("generatetoaddress address=%v", params[1])
		}
		funded.Store(true)
		return []interface{}{"0000deadbeef"}, nil
	})

	mock.on("listunspent", func(params []interface{}) (interface{}, *mockRPCError) {
		if !funded.Load() {
			// Surface empty until fund+mine has happened so we prove
			// the poll loop waits for real data.
			return []interface{}{}, nil
		}
		return []interface{}{
			map[string]interface{}{
				"txid":         "aa11bb22",
				"vout":         float64(0),
				"amount":       5.0,
				"scriptPubKey": "76a914cafe88ac",
			},
		}, nil
	})

	srv := httptest.NewServer(mock)
	defer srv.Close()

	provider, err := bsvclient.NewRPCProvider(srv.URL+"/", "regtest")
	if err != nil {
		t.Fatalf("NewRPCProvider: %v", err)
	}
	fw := newFeeWallet(t)

	// Bound the whole test aggressively — the real poll budget is 30s
	// but on the happy path the UTXO should land on the first ticker.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ingested, err := BootstrapFeeWallet(ctx, BootstrapOpts{
		Provider:  provider,
		FeeWallet: fw,
		Address:   "mfee",
		Network:   "regtest",
	})
	if err != nil {
		t.Fatalf("BootstrapFeeWallet: %v", err)
	}
	if ingested < 1 {
		t.Fatalf("ingested=%d, want >=1", ingested)
	}

	// Ingested UTXO shows up in the wallet with the advertised value.
	if got, want := fw.UTXOCount(), 1; got != want {
		t.Errorf("wallet.UTXOCount=%d, want %d", got, want)
	}
	if got, want := fw.Balance(), uint64(500_000_000); got != want {
		t.Errorf("wallet.Balance=%d sats, want %d", got, want)
	}

	// The four RPC methods must all have been called, and in the
	// advertised order. importaddress first, ingest-poll last.
	wantFirst := "importaddress"
	if len(mock.callLog) == 0 || mock.callLog[0] != wantFirst {
		t.Errorf("first call=%v, want %q", mock.callLog, wantFirst)
	}
	// send + generate must appear before any listunspent.
	sawSend, sawGen, sawList := false, false, false
	for _, m := range mock.callLog {
		switch m {
		case "sendtoaddress":
			sawSend = true
		case "generatetoaddress":
			if !sawSend {
				t.Errorf("generatetoaddress ran before sendtoaddress: %v", mock.callLog)
			}
			sawGen = true
		case "listunspent":
			if !sawGen {
				t.Errorf("listunspent ran before generatetoaddress: %v", mock.callLog)
			}
			sawList = true
		}
	}
	if !sawSend || !sawGen || !sawList {
		t.Errorf("missing expected RPC methods in %v", mock.callLog)
	}
}

// TestBootstrapFeeWallet_ImportAddressAlreadyImportedOK confirms that
// an "already imported" importaddress error does NOT fail the whole
// bootstrap — it's treated as a benign idempotency hit.
func TestBootstrapFeeWallet_ImportAddressAlreadyImportedOK(t *testing.T) {
	mock := newMockRPC(t)
	mock.on("importaddress", func(params []interface{}) (interface{}, *mockRPCError) {
		return nil, &mockRPCError{Code: -4, Message: "The wallet already contains the private key for this address or script"}
	})
	mock.on("sendtoaddress", func(params []interface{}) (interface{}, *mockRPCError) {
		return "txid", nil
	})
	mock.on("generatetoaddress", func(params []interface{}) (interface{}, *mockRPCError) {
		return []interface{}{"blockhash"}, nil
	})
	mock.on("listunspent", func(params []interface{}) (interface{}, *mockRPCError) {
		return []interface{}{
			map[string]interface{}{
				"txid":         "11",
				"vout":         float64(0),
				"amount":       1.0,
				"scriptPubKey": "76a9aabb88ac",
			},
		}, nil
	})
	srv := httptest.NewServer(mock)
	defer srv.Close()

	provider, err := bsvclient.NewRPCProvider(srv.URL+"/", "regtest")
	if err != nil {
		t.Fatalf("NewRPCProvider: %v", err)
	}
	fw := newFeeWallet(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ingested, err := BootstrapFeeWallet(ctx, BootstrapOpts{
		Provider:  provider,
		FeeWallet: fw,
		Address:   "mfee",
		Network:   "regtest",
	})
	if err != nil {
		t.Fatalf("BootstrapFeeWallet: %v", err)
	}
	if ingested != 1 {
		t.Errorf("ingested=%d, want 1", ingested)
	}
}

// TestBootstrapFeeWallet_SendFailsBubblesError confirms a genuine
// sendtoaddress failure is surfaced (not swallowed).
func TestBootstrapFeeWallet_SendFailsBubblesError(t *testing.T) {
	mock := newMockRPC(t)
	mock.on("importaddress", func(params []interface{}) (interface{}, *mockRPCError) {
		return nil, nil
	})
	mock.on("sendtoaddress", func(params []interface{}) (interface{}, *mockRPCError) {
		return nil, &mockRPCError{Code: -6, Message: "Insufficient funds"}
	})
	srv := httptest.NewServer(mock)
	defer srv.Close()

	provider, err := bsvclient.NewRPCProvider(srv.URL+"/", "regtest")
	if err != nil {
		t.Fatalf("NewRPCProvider: %v", err)
	}
	fw := newFeeWallet(t)

	_, err = BootstrapFeeWallet(context.Background(), BootstrapOpts{
		Provider:  provider,
		FeeWallet: fw,
		Address:   "mfee",
		Network:   "regtest",
	})
	if err == nil {
		t.Fatalf("expected error when sendtoaddress fails")
	}
	if !strings.Contains(err.Error(), "Insufficient funds") {
		t.Errorf("err does not surface node message: %v", err)
	}
}

// Sanity check: the hex script round-trips into FeeUTXO.ScriptPubKey.
func TestBootstrapFeeWallet_ScriptBytesDecoded(t *testing.T) {
	mock := newMockRPC(t)
	mock.on("importaddress", func(params []interface{}) (interface{}, *mockRPCError) { return nil, nil })
	mock.on("sendtoaddress", func(params []interface{}) (interface{}, *mockRPCError) { return "x", nil })
	mock.on("generatetoaddress", func(params []interface{}) (interface{}, *mockRPCError) {
		return []interface{}{"h"}, nil
	})
	mock.on("listunspent", func(params []interface{}) (interface{}, *mockRPCError) {
		return []interface{}{
			map[string]interface{}{
				"txid":         "dead",
				"vout":         float64(7),
				"amount":       0.5,
				"scriptPubKey": "76a914cafebabe88ac",
			},
		}, nil
	})
	srv := httptest.NewServer(mock)
	defer srv.Close()

	provider, err := bsvclient.NewRPCProvider(srv.URL+"/", "regtest")
	if err != nil {
		t.Fatalf("NewRPCProvider: %v", err)
	}
	fw := newFeeWallet(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if _, err := BootstrapFeeWallet(ctx, BootstrapOpts{
		Provider:  provider,
		FeeWallet: fw,
		Address:   "mfee",
		Network:   "regtest",
	}); err != nil {
		t.Fatalf("BootstrapFeeWallet: %v", err)
	}

	// Inspect the UTXOs the wallet ingested.
	inputs := fw.ConsolidationInputs()
	if len(inputs) != 1 {
		t.Fatalf("len(inputs)=%d, want 1", len(inputs))
	}
	u := inputs[0]
	wantScript, _ := hex.DecodeString("76a914cafebabe88ac")
	if string(u.ScriptPubKey) != string(wantScript) {
		t.Errorf("ScriptPubKey=%x, want %x", u.ScriptPubKey, wantScript)
	}
	if u.Vout != 7 {
		t.Errorf("Vout=%d, want 7", u.Vout)
	}
	if u.Satoshis != 50_000_000 {
		t.Errorf("Satoshis=%d, want 50_000_000", u.Satoshis)
	}
	if !u.Confirmed {
		t.Errorf("Confirmed=false, want true")
	}
}
