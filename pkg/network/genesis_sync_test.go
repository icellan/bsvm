package network

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
)

// TestLowerHex exercises the lowercase + 0x-strip helper used by the
// genesis sync protocol. It's small but load-bearing — if the peer
// and boot layers disagree on normalisation, hash comparisons fail
// silently and followers never bootstrap.
func TestLowerHex(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"", ""},
		{"AB", "ab"},
		{"0xAB", "ab"},
		{"0XAB", "ab"},
		{"abc123", "abc123"},
	}
	for _, c := range cases {
		got := lowerHex(c.in)
		if got != c.want {
			t.Errorf("lowerHex(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// newInProcessGossipPair creates two GossipManagers sharing a libp2p
// host each, then dials one from the other so they are connected on
// the shard protocol. Used for the genesis-sync equivalence tests.
func newInProcessGossipPair(t *testing.T) (*GossipManager, *GossipManager) {
	t.Helper()

	h1, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatalf("libp2p.New h1: %v", err)
	}
	h2, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		h1.Close()
		t.Fatalf("libp2p.New h2: %v", err)
	}

	cfg := DefaultConfig()
	cfg.ChainID = testChainID
	cfg.EnableMDNS = false

	gm1 := newGossipManagerWithHost(cfg, nil, h1)
	gm2 := newGossipManagerWithHost(cfg, nil, h2)

	// Install the genesis-sync stream handler on both hosts (the
	// normal Start path does this, but the tests drive the host
	// lifecycle manually to avoid needing an overlay).
	gm1.registerGenesisSyncHandler()
	gm2.registerGenesisSyncHandler()

	// Dial gm2 from gm1 so gm1.AllPeers() contains gm2.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	addrInfo := peer.AddrInfo{ID: h2.ID(), Addrs: h2.Addrs()}
	if err := h1.Connect(ctx, addrInfo); err != nil {
		h1.Close()
		h2.Close()
		t.Fatalf("h1.Connect(h2): %v", err)
	}
	// Record the peer on both sides so AllPeers() returns each other.
	if err := gm1.peers.AddPeer(h2.ID(), h2.Addrs()); err != nil {
		t.Fatalf("gm1.AddPeer(gm2): %v", err)
	}
	if err := gm2.peers.AddPeer(h1.ID(), h1.Addrs()); err != nil {
		t.Fatalf("gm2.AddPeer(gm1): %v", err)
	}

	t.Cleanup(func() {
		h1.Close()
		h2.Close()
	})

	return gm1, gm2
}

// TestGenesisSync_Success spins up two in-process GossipManagers. One
// has a cached genesis (the "prover"); the other requests it via
// RequestGenesisFromPeers and receives the matching raw hex.
func TestGenesisSync_Success(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network test in short mode")
	}

	gmRequester, gmPeer := newInProcessGossipPair(t)

	// Register a fake genesis on the peer.
	const (
		txidHex  = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"
		rawTxHex = "0100000001deadbeef"
	)
	gmPeer.SetLocalGenesis(txidHex, rawTxHex)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	got, err := gmRequester.RequestGenesisFromPeers(ctx, txidHex, 3*time.Second)
	if err != nil {
		t.Fatalf("RequestGenesisFromPeers: %v", err)
	}
	if got != rawTxHex {
		t.Errorf("raw tx = %q, want %q", got, rawTxHex)
	}

	// And uppercase / 0x-prefixed expected txid should also work:
	got2, err := gmRequester.RequestGenesisFromPeers(ctx, "0x"+strings.ToUpper(txidHex), 3*time.Second)
	if err != nil {
		t.Fatalf("RequestGenesisFromPeers (0x upper): %v", err)
	}
	if got2 != rawTxHex {
		t.Errorf("normalisation-insensitive request failed: got %q", got2)
	}
}

// TestGenesisSync_PeerHasNoGenesis asserts that a peer with no cached
// genesis is treated as "can't help": the requester's call times out
// with a clear error rather than hanging indefinitely.
func TestGenesisSync_PeerHasNoGenesis(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network test in short mode")
	}
	gmRequester, _ := newInProcessGossipPair(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := gmRequester.RequestGenesisFromPeers(ctx, strings.Repeat("aa", 32), 1500*time.Millisecond)
	if err == nil {
		t.Fatal("expected timeout error when peer has no genesis")
	}
	if !strings.Contains(err.Error(), "timed out") && !strings.Contains(err.Error(), "deadline") {
		t.Errorf("expected timeout-ish error, got %v", err)
	}
}

// TestGenesisSync_WrongTxID covers the "peer has a different shard's
// genesis" scenario. The requester expects txid X but the peer's
// cache holds Y; the boot layer would reject, but the network helper
// simply treats it as a mismatch and keeps polling.
func TestGenesisSync_WrongTxID(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network test in short mode")
	}
	gmRequester, gmPeer := newInProcessGossipPair(t)

	const peerTxID = "1111111111111111111111111111111111111111111111111111111111111111"
	gmPeer.SetLocalGenesis(peerTxID, "0100000099")

	// Directly exercise fetchOneGenesis so we can observe the
	// mismatch-error shape even though RequestGenesisFromPeers would
	// keep retrying until timeout.
	want := "2222222222222222222222222222222222222222222222222222222222222222"
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	res := fetchOneGenesis(ctx, gmRequester.host, gmPeer.host.ID(), protocol.ID(GenesisSyncProtocolID), want)
	if res.err == nil {
		t.Fatal("expected mismatch error")
	}
	if !strings.Contains(res.err.Error(), want) {
		t.Errorf("expected error to mention expected txid; got %v", res.err)
	}
}

// TestSetLocalGenesis_ClearRoundTrip verifies the setter / getter
// round-trip; empty inputs clear the cache.
func TestSetLocalGenesis_ClearRoundTrip(t *testing.T) {
	gm := &GossipManager{}
	gm.SetLocalGenesis("abc", "deadbeef")
	tx, raw := gm.localGenesis()
	if tx != "abc" || raw != "deadbeef" {
		t.Errorf("round-trip failed: got (%q, %q)", tx, raw)
	}
	gm.SetLocalGenesis("", "")
	tx, raw = gm.localGenesis()
	if tx != "" || raw != "" {
		t.Errorf("clear failed: got (%q, %q)", tx, raw)
	}
}
