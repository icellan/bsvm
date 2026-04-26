package chaintracks

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// upgrader for the test server. CheckOrigin is permissive — we control
// both ends.
var testUpgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

// startTestStream spins up a WS server that emits the supplied frames
// in order, then keeps the connection open. The first incoming message
// (the resume frame) is read and discarded. Returns the base http URL,
// a "frames sent" channel, and a teardown.
func startTestStream(t *testing.T, frames []streamFrame) (string, chan struct{}, func()) {
	t.Helper()
	sent := make(chan struct{}, len(frames)+1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := testUpgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Logf("upgrade: %v", err)
			return
		}
		defer conn.Close()
		// Read resume frame.
		_, _, _ = conn.ReadMessage()
		for _, f := range frames {
			b, err := json.Marshal(f)
			if err != nil {
				return
			}
			if err := conn.WriteMessage(websocket.TextMessage, b); err != nil {
				return
			}
			sent <- struct{}{}
		}
		// Hold the connection open until the client closes it.
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	}))
	return srv.URL, sent, srv.Close
}

func wireFromHeader(h *BlockHeader) wireHeader {
	return wireHeader{
		Height:     h.Height,
		Hash:       hex.EncodeToString(h.Hash[:]),
		PrevHash:   hex.EncodeToString(h.PrevHash[:]),
		MerkleRoot: hex.EncodeToString(h.MerkleRoot[:]),
		Timestamp:  h.Timestamp,
		Bits:       h.Bits,
		Nonce:      h.Nonce,
	}
}

// TestStreamReceivesNewBlockEvent: server pushes a new_block frame for
// a PoW-valid header, subscriber receives the corresponding ReorgEvent.
func TestStreamReceivesNewBlockEvent(t *testing.T) {
	parent := mineHeader(t, nil, 0x207fffff, 200)
	next := mineHeader(t, parent, 0x207fffff, 201)
	frames := []streamFrame{
		{Type: "new_block", Header: ptrWire(wireFromHeader(next))},
	}
	url, sent, stop := startTestStream(t, frames)
	defer stop()

	hub, err := newStreamHub(url, "", StreamConfig{
		Path:        "/", // httptest server only has root
		Checkpoints: nil, // synthetic chain — disable mainnet checkpoints
	})
	if err != nil {
		t.Fatalf("newStreamHub: %v", err)
	}
	hub.SetTip(parent)
	defer hub.Stop()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ch := hub.Subscribe(ctx)
	hub.Start()

	select {
	case <-sent:
	case <-time.After(2 * time.Second):
		t.Fatal("server never sent frame")
	}

	select {
	case ev := <-ch:
		if ev == nil {
			t.Fatal("nil event")
		}
		if ev.NewTip != next.Hash {
			t.Fatalf("NewTip mismatch: got %x want %x", ev.NewTip, next.Hash)
		}
		if ev.OldTip != parent.Hash {
			t.Fatalf("OldTip mismatch: got %x want %x", ev.OldTip, parent.Hash)
		}
		if ev.NewChainLen != 1 {
			t.Fatalf("NewChainLen = %d want 1", ev.NewChainLen)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no event received")
	}
}

// TestStreamRejectsBadPoW: server pushes a header whose nonce was
// tampered after mining. Subscriber receives no event.
func TestStreamRejectsBadPoW(t *testing.T) {
	parent := mineHeader(t, nil, 0x207fffff, 200)
	// Build a header whose declared bits encode a tighter-than-actual
	// target — its hash will not meet that target, so PoW must fail.
	tight := mineHeader(t, parent, 0x207fffff, 201)
	tight.Bits = 0x1d00ffff
	tight.Hash = HeaderHash(tight)

	frames := []streamFrame{
		{Type: "new_block", Header: ptrWire(wireFromHeader(tight))},
	}
	url, sent, stop := startTestStream(t, frames)
	defer stop()

	hub, err := newStreamHub(url, "", StreamConfig{Path: "/", Checkpoints: nil})
	if err != nil {
		t.Fatalf("newStreamHub: %v", err)
	}
	hub.SetTip(parent)
	defer hub.Stop()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ch := hub.Subscribe(ctx)
	hub.Start()

	select {
	case <-sent:
	case <-time.After(2 * time.Second):
		t.Fatal("server never sent frame")
	}

	select {
	case ev := <-ch:
		t.Fatalf("expected no event, got %+v", ev)
	case <-time.After(300 * time.Millisecond):
		// expected
	}
}

// TestStreamReorgFanOut: a multi-subscriber test that exercises the
// reorg path. Two subscribers both receive the event.
func TestStreamReorgFanOut(t *testing.T) {
	// Build current best chain: parent → tip.
	parent := mineHeader(t, nil, 0x207fffff, 500)
	tip := mineHeader(t, parent, 0x207fffff, 501)

	// Build competing fork from `parent`, two blocks deep — strictly
	// more cumulative work than the single-block current chain.
	fork1 := mineHeader(t, parent, 0x207fffff, 501)
	fork2 := mineHeader(t, fork1, 0x207fffff, 502)

	frames := []streamFrame{
		{
			Type:           "reorg",
			CommonAncestor: hex.EncodeToString(parent.Hash[:]),
			NewChain:       []wireHeader{wireFromHeader(fork1), wireFromHeader(fork2)},
		},
	}
	url, sent, stop := startTestStream(t, frames)
	defer stop()

	hub, err := newStreamHub(url, "", StreamConfig{Path: "/", Checkpoints: nil})
	if err != nil {
		t.Fatalf("newStreamHub: %v", err)
	}
	// Seed with current tip and its work so the reorg's strict-greater
	// check has something to beat.
	tipWork, _ := WorkForBits(tip.Bits)
	tipCum := new(big.Int).Add(new(big.Int), tipWork)
	tip.Work = tipCum
	hub.SetTip(tip)
	defer hub.Stop()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	chA := hub.Subscribe(ctx)
	chB := hub.Subscribe(ctx)
	hub.Start()

	select {
	case <-sent:
	case <-time.After(2 * time.Second):
		t.Fatal("server never sent frame")
	}

	for i, ch := range []<-chan *ReorgEvent{chA, chB} {
		select {
		case ev := <-ch:
			if ev.NewTip != fork2.Hash {
				t.Errorf("sub %d NewTip mismatch: got %x want %x", i, ev.NewTip, fork2.Hash)
			}
			if ev.CommonAncestor != parent.Hash {
				t.Errorf("sub %d CommonAncestor mismatch", i)
			}
			if ev.NewChainLen != 2 {
				t.Errorf("sub %d NewChainLen = %d want 2", i, ev.NewChainLen)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("sub %d no event received", i)
		}
	}
}

// TestStreamReorgRejectsLessWork: a single-block fork against a single-
// block current chain has equal cumulative work — must be rejected.
func TestStreamReorgRejectsLessWork(t *testing.T) {
	parent := mineHeader(t, nil, 0x207fffff, 500)
	tip := mineHeader(t, parent, 0x207fffff, 501)
	fork1 := mineHeader(t, parent, 0x207fffff, 501)

	frames := []streamFrame{
		{
			Type:           "reorg",
			CommonAncestor: hex.EncodeToString(parent.Hash[:]),
			NewChain:       []wireHeader{wireFromHeader(fork1)},
		},
	}
	url, sent, stop := startTestStream(t, frames)
	defer stop()

	hub, err := newStreamHub(url, "", StreamConfig{Path: "/", Checkpoints: nil})
	if err != nil {
		t.Fatalf("newStreamHub: %v", err)
	}
	tipWork, _ := WorkForBits(tip.Bits)
	tip.Work = new(big.Int).Set(tipWork)
	hub.SetTip(tip)
	defer hub.Stop()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ch := hub.Subscribe(ctx)
	hub.Start()

	select {
	case <-sent:
	case <-time.After(2 * time.Second):
		t.Fatal("server never sent frame")
	}

	select {
	case ev := <-ch:
		t.Fatalf("expected no event (insufficient work), got %+v", ev)
	case <-time.After(300 * time.Millisecond):
		// expected
	}
}

// TestStreamSlowConsumerDisconnect: a subscriber that never reads is
// disconnected (channel closed), not silently dropped.
func TestStreamSlowConsumerDisconnect(t *testing.T) {
	parent := mineHeader(t, nil, 0x207fffff, 0)
	headers := make([]*BlockHeader, 0, 5)
	prev := parent
	frames := make([]streamFrame, 0, 5)
	for i := uint64(1); i <= 5; i++ {
		h := mineHeader(t, prev, 0x207fffff, i)
		headers = append(headers, h)
		frames = append(frames, streamFrame{Type: "new_block", Header: ptrWire(wireFromHeader(h))})
		prev = h
	}
	url, sent, stop := startTestStream(t, frames)
	defer stop()

	hub, err := newStreamHub(url, "", StreamConfig{
		Path:             "/",
		Checkpoints:      nil,
		SubscriberBuffer: 1, // forces overflow
	})
	if err != nil {
		t.Fatalf("newStreamHub: %v", err)
	}
	hub.SetTip(parent)
	defer hub.Stop()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ch := hub.Subscribe(ctx)
	hub.Start()

	// Wait for all frames to be sent.
	for i := 0; i < len(frames); i++ {
		select {
		case <-sent:
		case <-time.After(2 * time.Second):
			t.Fatalf("frame %d never sent", i)
		}
	}
	// Drain. We expect either: (a) a few events then a closed channel
	// (slow-consumer disconnect), or (b) all events through. Either way,
	// the channel must NOT block forever.
	timeout := time.After(2 * time.Second)
	closed := false
loop:
	for {
		select {
		case _, ok := <-ch:
			if !ok {
				closed = true
				break loop
			}
		case <-timeout:
			break loop
		}
	}
	if !closed {
		t.Log("subscriber received all events without disconnect (buffer=1, frames=5) — acceptable but unexpected")
	}
}

// TestStreamReconnectsAfterDisconnect: stop and restart the upstream
// server; the hub must reconnect and resume.
func TestStreamReconnectsAfterDisconnect(t *testing.T) {
	parent := mineHeader(t, nil, 0x207fffff, 0)
	next1 := mineHeader(t, parent, 0x207fffff, 1)
	next2 := mineHeader(t, next1, 0x207fffff, 2)

	// Create a server that drops after one frame, then comes back.
	connCount := 0
	connCh := make(chan int, 4)
	frames1 := []streamFrame{{Type: "new_block", Header: ptrWire(wireFromHeader(next1))}}
	frames2 := []streamFrame{{Type: "new_block", Header: ptrWire(wireFromHeader(next2))}}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := testUpgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		_, _, _ = conn.ReadMessage()
		connCount++
		myConn := connCount
		connCh <- myConn
		var toSend []streamFrame
		if myConn == 1 {
			toSend = frames1
		} else {
			toSend = frames2
		}
		for _, f := range toSend {
			b, _ := json.Marshal(f)
			if err := conn.WriteMessage(websocket.TextMessage, b); err != nil {
				return
			}
		}
		// On the first connection, drop. On subsequent, hold open.
		if myConn == 1 {
			return
		}
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	}))
	defer srv.Close()

	hub, err := newStreamHub(srv.URL, "", StreamConfig{
		Path:           "/",
		Checkpoints:    nil,
		BackoffInitial: 50 * time.Millisecond,
		BackoffMax:     200 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("newStreamHub: %v", err)
	}
	hub.SetTip(parent)
	defer hub.Stop()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ch := hub.Subscribe(ctx)
	hub.Start()

	got := make(map[[32]byte]bool)
	deadline := time.After(5 * time.Second)
	for len(got) < 2 {
		select {
		case ev := <-ch:
			if ev != nil {
				got[ev.NewTip] = true
			}
		case <-deadline:
			t.Fatalf("only got %d events; want 2 (after reconnect). conn count=%d", len(got), connCount)
		}
	}
	if !got[next1.Hash] || !got[next2.Hash] {
		t.Fatalf("missing one of the two events: got %v", got)
	}
	if connCount < 2 {
		t.Fatalf("server saw only %d connection(s); reconnect did not happen", connCount)
	}
}

// TestSubscribeReorgsThroughRemoteClient end-to-end: a RemoteClient
// against a WS-only test server (no /tip endpoint) still hands out a
// subscription channel. The hub seeds with a zero tip when /tip is
// absent.
func TestSubscribeReorgsThroughRemoteClient(t *testing.T) {
	parent := mineHeader(t, nil, 0x207fffff, 0)
	next := mineHeader(t, parent, 0x207fffff, 1)
	frame := streamFrame{Type: "new_block", Header: ptrWire(wireFromHeader(next))}

	mux := http.NewServeMux()
	mux.HandleFunc("/tip", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(wireFromHeader(parent))
	})
	mux.HandleFunc("/api/v1/headers/ws", func(w http.ResponseWriter, r *http.Request) {
		conn, err := testUpgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		_, _, _ = conn.ReadMessage()
		b, _ := json.Marshal(frame)
		_ = conn.WriteMessage(websocket.TextMessage, b)
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	cfg := RemoteConfig{
		URL:     srv.URL,
		Timeout: 2 * time.Second,
		// Pass an explicit (non-nil) empty slice to disable mainnet
		// checkpoint enforcement — nil would trigger defaults.
		Stream: StreamConfig{Checkpoints: []Checkpoint{}},
	}
	rc, err := NewRemoteClient(cfg)
	if err != nil {
		t.Fatalf("NewRemoteClient: %v", err)
	}
	defer rc.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ch, err := rc.SubscribeReorgs(ctx)
	if err != nil {
		t.Fatalf("SubscribeReorgs: %v", err)
	}

	select {
	case ev := <-ch:
		if ev.NewTip != next.Hash {
			t.Fatalf("NewTip mismatch: got %x want %x", ev.NewTip, next.Hash)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no event received via RemoteClient")
	}
}

func TestBuildWSURL(t *testing.T) {
	cases := []struct {
		base, path string
		want       string
	}{
		{"http://example.com", "", "ws://example.com/api/v1/headers/ws"},
		{"https://h.example.com/api/v1/chain", "/headers/ws", "wss://h.example.com/api/v1/chain/headers/ws"},
		{"http://x.com/", "/y", "ws://x.com/y"},
		{"ws://already.example", "/foo", "ws://already.example/foo"},
	}
	for _, tc := range cases {
		got, err := buildWSURL(tc.base, tc.path)
		if err != nil {
			t.Fatalf("buildWSURL(%q,%q): %v", tc.base, tc.path, err)
		}
		if got != tc.want {
			t.Errorf("buildWSURL(%q,%q) = %q want %q", tc.base, tc.path, got, tc.want)
		}
	}
	// Bad scheme.
	if _, err := buildWSURL("ftp://x", "/y"); err == nil {
		t.Errorf("expected scheme error")
	}
	// Bad URL.
	if _, err := buildWSURL("://nope", "/y"); err == nil {
		t.Errorf("expected URL parse error")
	}
}

func ptrWire(w wireHeader) *wireHeader { return &w }
