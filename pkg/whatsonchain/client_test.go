package whatsonchain

import (
	"context"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestGetTx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/hex") {
			http.NotFound(w, r)
			return
		}
		w.Write([]byte(`"deadbeef00"`))
	}))
	defer srv.Close()
	c, err := NewClient(Config{URL: srv.URL, Timeout: time.Second})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	var txid [32]byte
	for i := range txid {
		txid[i] = 1
	}
	raw, err := c.GetTx(context.Background(), txid)
	if err != nil {
		t.Fatalf("GetTx: %v", err)
	}
	if hex.EncodeToString(raw) != "deadbeef00" {
		t.Fatalf("got %x", raw)
	}
}

func TestGetUTXOs(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`[{"tx_hash":"` + strings.Repeat("ab", 32) + `","tx_pos":1,"value":42,"height":100,"scriptPubKey":"76a900"}]`))
	}))
	defer srv.Close()
	c, _ := NewClient(Config{URL: srv.URL, Timeout: time.Second})
	utxos, err := c.GetUTXOs(context.Background(), "1abc")
	if err != nil {
		t.Fatalf("GetUTXOs: %v", err)
	}
	if len(utxos) != 1 || utxos[0].Vout != 1 || utxos[0].Satoshis != 42 {
		t.Fatalf("bad utxo: %+v", utxos)
	}
}

func TestNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()
	c, _ := NewClient(Config{URL: srv.URL, Timeout: time.Second})
	var txid [32]byte
	_, err := c.GetTx(context.Background(), txid)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestChainInfo(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/chain/info" {
			http.NotFound(w, r)
			return
		}
		w.Write([]byte(`{"chain":"main","blocks":850000,"bestblockhash":"` + strings.Repeat("aa", 32) + `","difficulty":12.34}`))
	}))
	defer srv.Close()
	c, _ := NewClient(Config{URL: srv.URL, Timeout: time.Second})
	info, err := c.ChainInfo(context.Background())
	if err != nil {
		t.Fatalf("ChainInfo: %v", err)
	}
	if info.Blocks != 850000 || info.Chain != "main" {
		t.Fatalf("bad info %+v", info)
	}
}
