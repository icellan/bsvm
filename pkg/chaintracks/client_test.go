package chaintracks

import (
	"context"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func mkHash(b byte) [32]byte {
	var h [32]byte
	for i := range h {
		h[i] = b
	}
	return h
}

func TestInMemoryClientLookups(t *testing.T) {
	c := NewInMemoryClient()
	h1 := &BlockHeader{Height: 100, Hash: mkHash(0x10), MerkleRoot: mkHash(0x20), Work: big.NewInt(1)}
	h2 := &BlockHeader{Height: 101, Hash: mkHash(0x11), PrevHash: h1.Hash, MerkleRoot: mkHash(0x21), Work: big.NewInt(2)}
	c.PutHeader(h1)
	c.PutHeader(h2)

	tip, err := c.Tip(context.Background())
	if err != nil {
		t.Fatalf("Tip: %v", err)
	}
	if tip.Height != 101 {
		t.Fatalf("tip height %d want 101", tip.Height)
	}

	got, err := c.HeaderByHeight(context.Background(), 100)
	if err != nil || got.Hash != h1.Hash {
		t.Fatalf("HeaderByHeight: %v %v", got, err)
	}
	got, err = c.HeaderByHash(context.Background(), h2.Hash)
	if err != nil || got.Height != 101 {
		t.Fatalf("HeaderByHash: %v %v", got, err)
	}
	root, err := c.MerkleRootAtHeight(context.Background(), 100)
	if err != nil || root != h1.MerkleRoot {
		t.Fatalf("MerkleRootAtHeight: %v %v", root, err)
	}
	confs, err := c.Confirmations(context.Background(), 100, h1.Hash)
	if err != nil || confs != 2 {
		t.Fatalf("Confirmations 100: %d %v", confs, err)
	}
	confs, err = c.Confirmations(context.Background(), 100, mkHash(0x99))
	if err != nil || confs != -1 {
		t.Fatalf("Confirmations reorged: %d %v", confs, err)
	}
}

func TestInMemoryClientReorgSubscribe(t *testing.T) {
	c := NewInMemoryClient()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ch, err := c.SubscribeReorgs(ctx)
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	want := &ReorgEvent{CommonAncestor: mkHash(0x01), OldTip: mkHash(0x02), NewTip: mkHash(0x03), OldChainLen: 5, NewChainLen: 7}
	c.EmitReorg(want)
	select {
	case got := <-ch:
		if got != want {
			t.Fatalf("got %+v want %+v", got, want)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for reorg")
	}
}

func TestRemoteClientTip(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/tip":
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"height":12345,"hash":"` + hex32(0xaa) + `","prevhash":"` + hex32(0xbb) + `","merkleroot":"` + hex32(0xcc) + `","timestamp":1700000000,"bits":1,"nonce":1,"work":"0x100"}`))
		case "/header/height/12345":
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"height":12345,"hash":"` + hex32(0xaa) + `","prevhash":"` + hex32(0xbb) + `","merkleroot":"` + hex32(0xcc) + `","timestamp":1700000000,"bits":1,"nonce":1}`))
		case "/ping":
			w.Write([]byte("ok"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	c, err := NewRemoteClient(RemoteConfig{URL: srv.URL, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("NewRemoteClient: %v", err)
	}
	tip, err := c.Tip(context.Background())
	if err != nil {
		t.Fatalf("Tip: %v", err)
	}
	if tip.Height != 12345 {
		t.Fatalf("height %d", tip.Height)
	}
	if tip.Hash != mkHash(0xaa) {
		t.Fatalf("hash mismatch")
	}
	if err := c.Ping(context.Background()); err != nil {
		t.Fatalf("Ping: %v", err)
	}
	h, err := c.HeaderByHeight(context.Background(), 12345)
	if err != nil || h.Height != 12345 {
		t.Fatalf("HeaderByHeight: %v %v", h, err)
	}
}

func hex32(b byte) string {
	var s string
	for i := 0; i < 32; i++ {
		s += "aa"
		_ = i
		_ = b
	}
	// override with all bytes b
	out := make([]byte, 64)
	for i := 0; i < 64; i += 2 {
		out[i] = hexNibble(b >> 4)
		out[i+1] = hexNibble(b & 0xf)
	}
	return string(out)
}

func hexNibble(b byte) byte {
	if b < 10 {
		return '0' + b
	}
	return 'a' + (b - 10)
}

func TestRemoteClient404(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()
	c, _ := NewRemoteClient(RemoteConfig{URL: srv.URL, Timeout: 2 * time.Second})
	if _, err := c.Tip(context.Background()); err == nil {
		t.Fatal("expected err on 404")
	}
}
