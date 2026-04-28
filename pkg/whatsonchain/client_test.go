package whatsonchain

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
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

// makeTxIDHex returns a 64-char (32-byte) hex string deterministically
// derived from i, suitable for use as a WoC-style big-endian txid.
func makeTxIDHex(i int) string {
	var b [32]byte
	for j := range b {
		b[j] = byte(i + j)
	}
	return hex.EncodeToString(b[:])
}

// TestGetBlockTxIDs_InlineManifest exercises the small-block path: the
// `/block/hash/<hash>` response carries the full tx list inline (no
// pagination). GetBlockTxIDs must decode and reverse-byte-order each
// txid and return them in manifest order.
func TestGetBlockTxIDs_InlineManifest(t *testing.T) {
	wantHexes := []string{makeTxIDHex(0), makeTxIDHex(1), makeTxIDHex(2)}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/block/hash/") {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"tx": wantHexes,
		})
	}))
	defer srv.Close()

	c, _ := NewClient(Config{URL: srv.URL, Timeout: time.Second})
	var blockHash [32]byte
	for i := range blockHash {
		blockHash[i] = byte(0xc0 + i)
	}
	got, err := c.GetBlockTxIDs(context.Background(), blockHash)
	if err != nil {
		t.Fatalf("GetBlockTxIDs: %v", err)
	}
	if len(got) != len(wantHexes) {
		t.Fatalf("got %d txids, want %d", len(got), len(wantHexes))
	}
	// The client reverses BE→LE, so the LE-form txid[i] must equal the
	// reverse of wantHexes[i].
	for i, want := range wantHexes {
		raw, _ := hex.DecodeString(want)
		var le [32]byte
		for j := 0; j < 32; j++ {
			le[j] = raw[31-j]
		}
		if got[i] != le {
			t.Errorf("txid[%d] = %x, want (LE) %x", i, got[i][:], le[:])
		}
	}
}

// TestGetBlockTxIDs_PaginatedThreePages drives the large-block path:
// the `/block/hash/<hash>` response carries an empty `tx` plus a
// `pages.uri` list of three pages. GetBlockTxIDs must fetch each page,
// concatenate in manifest order, and decode each txid.
func TestGetBlockTxIDs_PaginatedThreePages(t *testing.T) {
	// Each page carries a deterministic batch of 4 txids; total 12.
	pages := [][]string{
		{makeTxIDHex(0), makeTxIDHex(1), makeTxIDHex(2), makeTxIDHex(3)},
		{makeTxIDHex(4), makeTxIDHex(5), makeTxIDHex(6), makeTxIDHex(7)},
		{makeTxIDHex(8), makeTxIDHex(9), makeTxIDHex(10), makeTxIDHex(11)},
	}

	var pageHits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Paginated header response.
		if r.URL.Path == "/block/hash/test" || strings.HasSuffix(r.URL.Path, "/block/hash/"+strings.Repeat("ab", 32)) {
			pageURIs := []string{
				"/block/hash/test/page/1",
				"/block/hash/test/page/2",
				"/block/hash/test/page/3",
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"tx":    []string{},
				"pages": map[string]any{"uri": pageURIs},
			})
			return
		}
		// Page endpoints.
		for i := range pages {
			if strings.HasSuffix(r.URL.Path, fmt.Sprintf("/page/%d", i+1)) {
				pageHits.Add(1)
				_ = json.NewEncoder(w).Encode(pages[i])
				return
			}
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	c, _ := NewClient(Config{URL: srv.URL, Timeout: 5 * time.Second})
	var blockHash [32]byte
	// blockHash whose BE-hex is "abab...ab" (32 ab bytes) so the server's
	// path-match arm fires.
	for i := range blockHash {
		blockHash[i] = 0xab
	}
	got, err := c.GetBlockTxIDs(context.Background(), blockHash)
	if err != nil {
		t.Fatalf("GetBlockTxIDs: %v", err)
	}

	wantTotal := 0
	for _, p := range pages {
		wantTotal += len(p)
	}
	if len(got) != wantTotal {
		t.Fatalf("got %d txids, want %d", len(got), wantTotal)
	}
	if pageHits.Load() != 3 {
		t.Errorf("expected 3 page fetches, got %d", pageHits.Load())
	}

	// Aggregate must be in manifest order: page1 ids first, then page2,
	// then page3. Compare against the LE-reversed expectation.
	idx := 0
	for _, p := range pages {
		for _, h := range p {
			raw, _ := hex.DecodeString(h)
			var le [32]byte
			for j := 0; j < 32; j++ {
				le[j] = raw[31-j]
			}
			if got[idx] != le {
				t.Errorf("aggregate[%d] = %x, want (LE) %x", idx, got[idx][:], le[:])
			}
			idx++
		}
	}
}

// TestGetBlockTxIDs_MalformedPagination exercises the fault-tolerance
// posture for a malformed paginated response: a header that names
// pages whose payload doesn't decode. GetBlockTxIDs must surface a
// typed error rather than partially aggregating.
func TestGetBlockTxIDs_MalformedPagination(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(r.URL.Path, "/page/") {
			// Garbage page payload — neither array nor object.
			w.Write([]byte(`{"this is not": "an array of strings"}`))
			return
		}
		// Header response advertising one page.
		_ = json.NewEncoder(w).Encode(map[string]any{
			"tx":    []string{},
			"pages": map[string]any{"uri": []string{"/block/hash/test/page/1"}},
		})
	}))
	defer srv.Close()

	c, _ := NewClient(Config{URL: srv.URL, Timeout: time.Second})
	var blockHash [32]byte
	_, err := c.GetBlockTxIDs(context.Background(), blockHash)
	if err == nil {
		t.Fatal("expected error from malformed page response, got nil")
	}
	if !strings.Contains(err.Error(), "page") {
		t.Errorf("error should mention page decode failure: %v", err)
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
