package chaintracks

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// RemoteConfig configures a RemoteClient. URL is the BRC-64 base URL
// (e.g. https://headers.example.com/api/v1/chain). Timeout caps each
// HTTP request. APIKey is forwarded via the X-API-Key header when set.
//
// Stream configures the long-lived WS subscription used by
// SubscribeReorgs. A zero value yields production defaults
// (path=/api/v1/headers/ws, 64-event buffer, exponential backoff
// 500ms → 30s, default BSV mainnet checkpoints enforced).
type RemoteConfig struct {
	URL     string
	Timeout time.Duration
	APIKey  string
	Stream  StreamConfig
}

// RemoteClient is the BRC-64-style HTTP + WebSocket client for a
// chaintracks Block Headers Service. It implements the read-only
// header lookups required for SPV verification and a long-lived
// SubscribeReorgs stream. Multi-upstream quorum is follow-up work
// (see W6-2); a single RemoteClient talks to a single upstream.
type RemoteClient struct {
	cfg  RemoteConfig
	http *http.Client

	hubOnce sync.Once
	hub     *streamHub
	hubErr  error
}

// NewRemoteClient builds a RemoteClient. cfg.URL is required.
func NewRemoteClient(cfg RemoteConfig) (*RemoteClient, error) {
	if cfg.URL == "" {
		return nil, errors.New("chaintracks: URL required")
	}
	if _, err := url.Parse(cfg.URL); err != nil {
		return nil, fmt.Errorf("chaintracks: parse URL: %w", err)
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 30 * time.Second
	}
	if cfg.Stream.Checkpoints == nil {
		cfg.Stream.Checkpoints = DefaultCheckpoints()
	}
	return &RemoteClient{
		cfg:  cfg,
		http: &http.Client{Timeout: cfg.Timeout},
	}, nil
}

type wireHeader struct {
	Height     uint64 `json:"height"`
	Hash       string `json:"hash"`
	PrevHash   string `json:"prevhash"`
	MerkleRoot string `json:"merkleroot"`
	Timestamp  uint32 `json:"timestamp"`
	Bits       uint32 `json:"bits"`
	Nonce      uint32 `json:"nonce"`
	Work       string `json:"work,omitempty"`
}

func (w wireHeader) toHeader() (*BlockHeader, error) {
	h := &BlockHeader{
		Height:    w.Height,
		Timestamp: w.Timestamp,
		Bits:      w.Bits,
		Nonce:     w.Nonce,
	}
	if err := decodeHash(w.Hash, &h.Hash); err != nil {
		return nil, fmt.Errorf("hash: %w", err)
	}
	if w.PrevHash != "" {
		if err := decodeHash(w.PrevHash, &h.PrevHash); err != nil {
			return nil, fmt.Errorf("prevhash: %w", err)
		}
	}
	if w.MerkleRoot != "" {
		if err := decodeHash(w.MerkleRoot, &h.MerkleRoot); err != nil {
			return nil, fmt.Errorf("merkleroot: %w", err)
		}
	}
	if w.Work != "" {
		work, ok := new(big.Int).SetString(strings.TrimPrefix(w.Work, "0x"), 16)
		if !ok {
			return nil, fmt.Errorf("work: not hex %q", w.Work)
		}
		h.Work = work
	}
	return h, nil
}

func decodeHash(s string, out *[32]byte) error {
	b, err := hex.DecodeString(strings.TrimPrefix(s, "0x"))
	if err != nil {
		return err
	}
	if len(b) != 32 {
		return fmt.Errorf("expected 32 bytes, got %d", len(b))
	}
	copy(out[:], b)
	return nil
}

func (c *RemoteClient) doGet(ctx context.Context, path string, query url.Values) ([]byte, error) {
	endpoint := strings.TrimRight(c.cfg.URL, "/") + "/" + strings.TrimLeft(path, "/")
	if query != nil {
		endpoint += "?" + query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	if c.cfg.APIKey != "" {
		req.Header.Set("X-API-Key", c.cfg.APIKey)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("chaintracks: %s: %w", path, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("chaintracks: read %s: %w", path, err)
	}
	if resp.StatusCode == http.StatusNotFound {
		return nil, ErrUnknownHeader
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("chaintracks: %s status %d: %s", path, resp.StatusCode, string(body))
	}
	return body, nil
}

// Tip implements ChaintracksClient by GETing /tip.
func (c *RemoteClient) Tip(ctx context.Context) (*BlockHeader, error) {
	body, err := c.doGet(ctx, "tip", nil)
	if err != nil {
		return nil, err
	}
	var w wireHeader
	if err := json.Unmarshal(body, &w); err != nil {
		return nil, fmt.Errorf("chaintracks: tip decode: %w", err)
	}
	return w.toHeader()
}

// HeaderByHash implements ChaintracksClient.
func (c *RemoteClient) HeaderByHash(ctx context.Context, hash [32]byte) (*BlockHeader, error) {
	body, err := c.doGet(ctx, "header/hash/"+hex.EncodeToString(hash[:]), nil)
	if err != nil {
		return nil, err
	}
	var w wireHeader
	if err := json.Unmarshal(body, &w); err != nil {
		return nil, fmt.Errorf("chaintracks: header decode: %w", err)
	}
	return w.toHeader()
}

// HeaderByHeight implements ChaintracksClient.
func (c *RemoteClient) HeaderByHeight(ctx context.Context, height uint64) (*BlockHeader, error) {
	body, err := c.doGet(ctx, "header/height/"+strconv.FormatUint(height, 10), nil)
	if err != nil {
		return nil, err
	}
	var w wireHeader
	if err := json.Unmarshal(body, &w); err != nil {
		return nil, fmt.Errorf("chaintracks: header decode: %w", err)
	}
	return w.toHeader()
}

// MerkleRootAtHeight implements ChaintracksClient.
func (c *RemoteClient) MerkleRootAtHeight(ctx context.Context, height uint64) ([32]byte, error) {
	h, err := c.HeaderByHeight(ctx, height)
	if err != nil {
		return [32]byte{}, err
	}
	return h.MerkleRoot, nil
}

// Confirmations implements ChaintracksClient.
func (c *RemoteClient) Confirmations(ctx context.Context, height uint64, blockHash [32]byte) (int64, error) {
	h, err := c.HeaderByHeight(ctx, height)
	if err != nil {
		if errors.Is(err, ErrUnknownHeader) {
			return 0, nil
		}
		return 0, err
	}
	if h.Hash != blockHash {
		return -1, nil
	}
	tip, err := c.Tip(ctx)
	if err != nil {
		return 0, err
	}
	return int64(tip.Height-h.Height) + 1, nil
}

// SubscribeReorgs opens (lazily, once) a long-lived WebSocket
// subscription to the upstream and returns a channel of ReorgEvents.
// Multiple in-process callers share a single connection; each receives
// its own bounded channel. Slow consumers are disconnected (channel
// closed) when the buffer overflows — events are NEVER silently
// dropped.
//
// On disconnect the hub reconnects with exponential backoff
// (cfg.Stream.BackoffInitial → BackoffMax) and resumes from the last
// validated tip hash. Every received header is PoW-verified, link-
// checked, and matched against the configured checkpoints before being
// fanned out; reorgs that fail cumulative-work checks are rejected.
//
// The returned channel is closed when ctx is cancelled.
func (c *RemoteClient) SubscribeReorgs(ctx context.Context) (<-chan *ReorgEvent, error) {
	c.hubOnce.Do(func() {
		hub, err := newStreamHub(c.cfg.URL, c.cfg.APIKey, c.cfg.Stream)
		if err != nil {
			c.hubErr = err
			return
		}
		// Seed the resume cursor with the current tip, best-effort.
		seedCtx, cancel := context.WithTimeout(context.Background(), c.cfg.Timeout)
		if tip, err := c.Tip(seedCtx); err == nil {
			hub.SetTip(tip)
		}
		cancel()
		c.hub = hub
		c.hub.Start()
	})
	if c.hubErr != nil {
		return nil, c.hubErr
	}
	return c.hub.Subscribe(ctx), nil
}

// Ping implements ChaintracksClient by GETing /ping.
func (c *RemoteClient) Ping(ctx context.Context) error {
	_, err := c.doGet(ctx, "ping", nil)
	return err
}

// Close implements ChaintracksClient. Tears down the streaming hub if
// one was started.
func (c *RemoteClient) Close() error {
	if c.hub != nil {
		c.hub.Stop()
	}
	return nil
}
