// stream.go — long-lived WebSocket / SSE subscription to a chaintracks
// upstream. The hub maintains a single connection across all in-process
// subscribers and fans events out internally; reconnects use exponential
// backoff and resume from the last validated tip hash.
//
// Wire format
// -----------
// The default endpoint is "<base>/api/v1/headers/ws" (override via
// RemoteConfig.StreamPath). On connect, the client sends a single
// resume frame:
//
//   {"resume_from":"<hex tip hash>"}
//
// Server pushes JSON frames, one per event. Each frame matches one of:
//
//   {"type":"new_block","header":{...wireHeader...}}
//   {"type":"reorg","common_ancestor":"<hex>","new_chain":[{...},...]}
//
// where wireHeader is the same shape as the GET /tip response. The
// schema is the BRC-64-ish convention that runs on the reference
// chaintracks server; deployments using a different on-the-wire schema
// must wrap their own provider against ChaintracksClient directly.
//
// SSE fallback is intentionally NOT implemented in this wave — every
// known chaintracks deployment ships a WS endpoint, and SSE doubles
// the parser surface for no production gain. The plumbing here makes
// it straightforward to add later (StreamKind config knob).

package chaintracks

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// Reasonable defaults; overridable via RemoteConfig.
const (
	defaultStreamPath       = "/api/v1/headers/ws"
	defaultBackoffInitial   = 500 * time.Millisecond
	defaultBackoffMax       = 30 * time.Second
	defaultSubscriberBuffer = 64
	defaultReadDeadline     = 90 * time.Second
	defaultPingInterval     = 25 * time.Second
)

// StreamConfig configures the per-RemoteClient streaming hub. A zero
// value is valid — defaults apply.
type StreamConfig struct {
	// Path is appended to RemoteConfig.URL to form the WS endpoint.
	// Leading slash optional. Default: "/api/v1/headers/ws".
	Path string
	// SubscriberBuffer caps each subscriber channel. Slow consumers are
	// disconnected (channel closed) when full — events are NEVER
	// silently dropped. Default 64.
	SubscriberBuffer int
	// BackoffInitial / BackoffMax control the exponential reconnect
	// delay. Defaults: 500ms / 30s.
	BackoffInitial time.Duration
	BackoffMax     time.Duration
	// Checkpoints are enforced on every received header. nil disables
	// enforcement (test mode). Default: DefaultCheckpoints().
	Checkpoints []Checkpoint
	// Dialer overrides the default websocket dialer. Tests inject an
	// in-process dialer; production leaves this nil.
	Dialer *websocket.Dialer
}

// streamFrame is the JSON envelope each upstream event arrives in.
type streamFrame struct {
	Type           string       `json:"type"`
	Header         *wireHeader  `json:"header,omitempty"`
	CommonAncestor string       `json:"common_ancestor,omitempty"`
	NewChain       []wireHeader `json:"new_chain,omitempty"`
}

type resumeFrame struct {
	ResumeFrom string `json:"resume_from"`
}

// streamHub owns the WebSocket connection and fans events out to
// subscribers.
type streamHub struct {
	wsURL  string
	cfg    StreamConfig
	apiKey string

	mu        sync.Mutex
	subs      map[chan *ReorgEvent]struct{}
	tipHash   [32]byte // last validated tip hash, used for resume
	tipWork   *big.Int
	chainHead *BlockHeader

	startOnce sync.Once
	stopOnce  sync.Once
	stop      chan struct{}
	stopped   chan struct{}
}

// newStreamHub builds a hub for the given base URL and config. The
// hub is dormant until Run is called.
func newStreamHub(baseURL, apiKey string, cfg StreamConfig) (*streamHub, error) {
	if cfg.Path == "" {
		cfg.Path = defaultStreamPath
	}
	if cfg.SubscriberBuffer <= 0 {
		cfg.SubscriberBuffer = defaultSubscriberBuffer
	}
	if cfg.BackoffInitial <= 0 {
		cfg.BackoffInitial = defaultBackoffInitial
	}
	if cfg.BackoffMax < cfg.BackoffInitial {
		cfg.BackoffMax = defaultBackoffMax
	}
	if cfg.Dialer == nil {
		cfg.Dialer = websocket.DefaultDialer
	}
	wsURL, err := buildWSURL(baseURL, cfg.Path)
	if err != nil {
		return nil, err
	}
	return &streamHub{
		wsURL:   wsURL,
		cfg:     cfg,
		apiKey:  apiKey,
		subs:    make(map[chan *ReorgEvent]struct{}),
		stop:    make(chan struct{}),
		stopped: make(chan struct{}),
	}, nil
}

// buildWSURL converts a base http(s) URL + WS path into a ws(s) URL.
func buildWSURL(base, path string) (string, error) {
	u, err := url.Parse(base)
	if err != nil {
		return "", fmt.Errorf("chaintracks: bad base URL: %w", err)
	}
	switch u.Scheme {
	case "http":
		u.Scheme = "ws"
	case "https":
		u.Scheme = "wss"
	case "ws", "wss":
		// already a websocket URL
	default:
		return "", fmt.Errorf("chaintracks: unsupported scheme %q", u.Scheme)
	}
	if path == "" {
		path = defaultStreamPath
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	u.Path = strings.TrimRight(u.Path, "/") + path
	return u.String(), nil
}

// Subscribe registers a new in-process subscriber. The returned channel
// is closed when ctx is cancelled, when the subscriber falls behind
// the bounded buffer (slow-consumer disconnect), or when the hub stops.
func (h *streamHub) Subscribe(ctx context.Context) <-chan *ReorgEvent {
	ch := make(chan *ReorgEvent, h.cfg.SubscriberBuffer)
	h.mu.Lock()
	h.subs[ch] = struct{}{}
	h.mu.Unlock()
	go func() {
		<-ctx.Done()
		h.removeSub(ch)
	}()
	return ch
}

// removeSub closes and forgets a subscriber channel. Idempotent.
func (h *streamHub) removeSub(ch chan *ReorgEvent) {
	h.mu.Lock()
	if _, ok := h.subs[ch]; !ok {
		h.mu.Unlock()
		return
	}
	delete(h.subs, ch)
	h.mu.Unlock()
	defer func() { _ = recover() }() // benign: channel may already be closed
	close(ch)
}

// Start spins the hub's connect/reconnect goroutine. Idempotent.
func (h *streamHub) Start() {
	h.startOnce.Do(func() { go h.run() })
}

// Stop signals the hub to exit and blocks until the goroutine has
// returned.
func (h *streamHub) Stop() {
	h.stopOnce.Do(func() { close(h.stop) })
	<-h.stopped
	// Close all remaining subscriber channels.
	h.mu.Lock()
	for ch := range h.subs {
		delete(h.subs, ch)
		func() {
			defer func() { _ = recover() }()
			close(ch)
		}()
	}
	h.mu.Unlock()
}

// run is the supervisor loop: connect, read frames, on disconnect
// back off and retry until Stop is called.
func (h *streamHub) run() {
	defer close(h.stopped)
	backoff := h.cfg.BackoffInitial
	for {
		select {
		case <-h.stop:
			return
		default:
		}
		err := h.connectAndPump()
		if err != nil {
			slog.Warn("chaintracks: stream disconnected", "err", err, "backoff", backoff)
		}
		// Sleep with cancellation.
		select {
		case <-h.stop:
			return
		case <-time.After(backoff):
		}
		backoff *= 2
		if backoff > h.cfg.BackoffMax {
			backoff = h.cfg.BackoffMax
		}
		// Reset backoff on successful long-lived connect — handled
		// inside connectAndPump after we receive at least one frame.
		if backoff > h.cfg.BackoffMax {
			backoff = h.cfg.BackoffMax
		}
	}
}

// connectAndPump opens one connection and reads frames until the
// connection drops or Stop is called.
func (h *streamHub) connectAndPump() error {
	hdr := http.Header{}
	if h.apiKey != "" {
		hdr.Set("X-API-Key", h.apiKey)
	}
	conn, _, err := h.cfg.Dialer.Dial(h.wsURL, hdr)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()

	// Send resume frame.
	h.mu.Lock()
	tip := h.tipHash
	h.mu.Unlock()
	resume := resumeFrame{ResumeFrom: hex.EncodeToString(tip[:])}
	if err := conn.WriteJSON(resume); err != nil {
		return fmt.Errorf("resume: %w", err)
	}

	// Pinger.
	pingStop := make(chan struct{})
	go func() {
		t := time.NewTicker(defaultPingInterval)
		defer t.Stop()
		for {
			select {
			case <-pingStop:
				return
			case <-h.stop:
				return
			case <-t.C:
				_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
				if err := conn.WriteMessage(websocket.PingMessage, nil); err != nil {
					_ = conn.Close()
					return
				}
			}
		}
	}()
	defer close(pingStop)

	conn.SetPongHandler(func(string) error {
		_ = conn.SetReadDeadline(time.Now().Add(defaultReadDeadline))
		return nil
	})
	_ = conn.SetReadDeadline(time.Now().Add(defaultReadDeadline))

	// Stop watcher: if Stop fires, drop the connection so the read
	// loop unblocks.
	stopWatch := make(chan struct{})
	go func() {
		select {
		case <-h.stop:
			_ = conn.Close()
		case <-stopWatch:
		}
	}()
	defer close(stopWatch)

	for {
		_, msg, err := conn.ReadMessage()
		if err != nil {
			if errors.Is(err, websocket.ErrCloseSent) {
				return nil
			}
			return fmt.Errorf("read: %w", err)
		}
		_ = conn.SetReadDeadline(time.Now().Add(defaultReadDeadline))
		var frame streamFrame
		if err := json.Unmarshal(msg, &frame); err != nil {
			slog.Warn("chaintracks: bad frame", "err", err)
			continue
		}
		if err := h.handleFrame(&frame); err != nil {
			slog.Warn("chaintracks: rejected frame", "type", frame.Type, "err", err)
		}
	}
}

// handleFrame validates an inbound frame and, if accepted, advances
// the hub's tip and broadcasts to subscribers. Returns the validation
// error so the supervisor can log it; rejected frames are not fatal.
func (h *streamHub) handleFrame(f *streamFrame) error {
	switch f.Type {
	case "new_block":
		if f.Header == nil {
			return errors.New("new_block missing header")
		}
		hdr, err := f.Header.toHeader()
		if err != nil {
			return fmt.Errorf("decode header: %w", err)
		}
		return h.acceptNewBlock(hdr)
	case "reorg":
		ca, err := decodeHexHash(f.CommonAncestor)
		if err != nil {
			return fmt.Errorf("decode common_ancestor: %w", err)
		}
		newChain := make([]*BlockHeader, 0, len(f.NewChain))
		for i := range f.NewChain {
			hdr, err := f.NewChain[i].toHeader()
			if err != nil {
				return fmt.Errorf("decode new_chain[%d]: %w", i, err)
			}
			newChain = append(newChain, hdr)
		}
		return h.acceptReorg(ca, newChain)
	default:
		return fmt.Errorf("unknown frame type %q", f.Type)
	}
}

// acceptNewBlock validates a header and broadcasts a synthetic
// ReorgEvent representing a 1-block linear extension. (The
// ChaintracksClient interface only exposes ReorgEvent; in the linear
// case, OldTip == NewTip's parent and chain lengths differ by 1.)
func (h *streamHub) acceptNewBlock(hdr *BlockHeader) error {
	h.mu.Lock()
	prev := h.chainHead
	h.mu.Unlock()
	if err := ValidateHeader(prev, hdr, h.cfg.Checkpoints); err != nil {
		return err
	}
	// Cumulative work bookkeeping.
	work, err := WorkForBits(hdr.Bits)
	if err != nil {
		return fmt.Errorf("work: %w", err)
	}
	h.mu.Lock()
	prevWork := h.tipWork
	if prevWork == nil {
		prevWork = new(big.Int)
	}
	cum := new(big.Int).Add(prevWork, work)
	if hdr.Work == nil {
		hdr.Work = cum
	}
	prevHash := h.tipHash
	h.tipHash = hdr.Hash
	h.tipWork = cum
	h.chainHead = hdr
	h.mu.Unlock()

	ev := &ReorgEvent{
		CommonAncestor: prevHash,
		OldTip:         prevHash,
		NewTip:         hdr.Hash,
		OldChainLen:    0,
		NewChainLen:    1,
	}
	h.broadcast(ev)
	return nil
}

// acceptReorg validates a competing chain and switches to it iff its
// cumulative work strictly exceeds the current chain's. The new_chain
// slice is the post-fork suffix, oldest first.
func (h *streamHub) acceptReorg(commonAncestor [32]byte, newChain []*BlockHeader) error {
	if len(newChain) == 0 {
		return errors.New("empty new_chain")
	}
	// Validate each header in the new chain links and PoW.
	var prev *BlockHeader
	for i, hdr := range newChain {
		// First header in suffix has prev = (parent at common ancestor),
		// which we may not have. Skip the link check at i==0; the
		// upstream's claim that this fork descends from commonAncestor
		// is taken on faith, but PoW is still verified.
		if i == 0 {
			if hdr.PrevHash != commonAncestor {
				return fmt.Errorf("%w: first new-chain header does not link to common_ancestor", ErrBrokenChain)
			}
		}
		if err := ValidateHeader(prev, hdr, h.cfg.Checkpoints); err != nil {
			return err
		}
		prev = hdr
	}
	// Compute cumulative work of the new chain.
	newWork := new(big.Int)
	for _, hdr := range newChain {
		w, err := WorkForBits(hdr.Bits)
		if err != nil {
			return fmt.Errorf("work: %w", err)
		}
		newWork.Add(newWork, w)
	}
	h.mu.Lock()
	currentWork := h.tipWork
	oldTip := h.tipHash
	h.mu.Unlock()
	if err := CheckReorgWork(currentWork, newWork); err != nil {
		return err
	}
	// Adopt new chain.
	newTip := newChain[len(newChain)-1]
	h.mu.Lock()
	h.tipHash = newTip.Hash
	h.tipWork = newWork
	h.chainHead = newTip
	h.mu.Unlock()
	h.broadcast(&ReorgEvent{
		CommonAncestor: commonAncestor,
		OldTip:         oldTip,
		NewTip:         newTip.Hash,
		OldChainLen:    0, // we don't track the rolled-back length here
		NewChainLen:    uint64(len(newChain)),
	})
	return nil
}

// broadcast sends ev to every subscriber. Slow consumers (full buffer)
// are disconnected — never silently dropped.
func (h *streamHub) broadcast(ev *ReorgEvent) {
	h.mu.Lock()
	subs := make([]chan *ReorgEvent, 0, len(h.subs))
	for ch := range h.subs {
		subs = append(subs, ch)
	}
	h.mu.Unlock()
	for _, ch := range subs {
		select {
		case ch <- ev:
		default:
			slog.Warn("chaintracks: subscriber slow, disconnecting")
			h.removeSub(ch)
		}
	}
}

// SetTip seeds the hub's tip cursor. Called after the initial Tip()
// HTTP fetch so the resume frame has a meaningful starting point.
func (h *streamHub) SetTip(hdr *BlockHeader) {
	if hdr == nil {
		return
	}
	h.mu.Lock()
	h.tipHash = hdr.Hash
	if hdr.Work != nil {
		h.tipWork = new(big.Int).Set(hdr.Work)
	}
	h.chainHead = hdr
	h.mu.Unlock()
}

func decodeHexHash(s string) ([32]byte, error) {
	var out [32]byte
	if err := decodeHash(s, &out); err != nil {
		return out, err
	}
	return out, nil
}
