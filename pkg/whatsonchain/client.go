// Package whatsonchain is the BSVM client for the WhatsOnChain
// (WoC) HTTPS API. WoC is a supplementary lookup path used for
// ancestor fetching, fee-wallet bootstrap, header cross-check, and
// bridge-deposit fallback. It is never the sole source of truth: every
// transaction fetched via WoC is re-verified through chaintracks
// before being trusted.
//
// This wave ships a minimal client: GetTx and GetUTXOs cover the two
// most common consumer call sites; the broader interface (ChainInfo,
// AddressHistory, BUMP retrieval) is stubbed for follow-up. The
// HTTP client is request-token compatible (Config.APIKey is
// forwarded as the `woc-api-key` header).
package whatsonchain

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Config configures a WhatsOnChain Client.
type Config struct {
	URL     string        // base URL, e.g. https://api.whatsonchain.com/v1/bsv/main
	Timeout time.Duration // HTTP request timeout (default 30s)
	APIKey  string        // optional WoC API key
}

// UTXO is a single unspent output as returned by /address/<addr>/unspent.
type UTXO struct {
	TxID         [32]byte
	Vout         uint32
	Satoshis     uint64
	Height       uint64
	ScriptPubKey []byte // raw script bytes (may be nil if WoC didn't return it)
}

// ChainInfo summarises the WoC tip view.
type ChainInfo struct {
	Chain      string
	Blocks     uint64
	BestHash   [32]byte
	Difficulty float64
}

// Client is the canonical WoC client.
type Client struct {
	cfg  Config
	http *http.Client
}

// WhatsOnChainClient is the interface BSVM consumes.
type WhatsOnChainClient interface {
	GetTx(ctx context.Context, txid [32]byte) ([]byte, error)
	GetUTXOs(ctx context.Context, address string) ([]UTXO, error)
	ChainInfo(ctx context.Context) (*ChainInfo, error)
	Ping(ctx context.Context) error
}

// NewClient builds a Client. cfg.URL is required.
func NewClient(cfg Config) (*Client, error) {
	if cfg.URL == "" {
		return nil, errors.New("woc: URL required")
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 30 * time.Second
	}
	return &Client{
		cfg:  cfg,
		http: &http.Client{Timeout: cfg.Timeout},
	}, nil
}

func (c *Client) get(ctx context.Context, path string) ([]byte, error) {
	endpoint := strings.TrimRight(c.cfg.URL, "/") + "/" + strings.TrimLeft(path, "/")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	if c.cfg.APIKey != "" {
		req.Header.Set("woc-api-key", c.cfg.APIKey)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("woc: %s: %w", path, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("woc: read %s: %w", path, err)
	}
	if resp.StatusCode == http.StatusNotFound {
		return nil, ErrNotFound
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("woc: %s status %d: %s", path, resp.StatusCode, string(body))
	}
	return body, nil
}

// ErrNotFound is returned when WoC reports 404 for a lookup.
var ErrNotFound = errors.New("woc: not found")

// GetTx returns the raw transaction bytes for txid.
func (c *Client) GetTx(ctx context.Context, txid [32]byte) ([]byte, error) {
	body, err := c.get(ctx, "/tx/"+hex.EncodeToString(txid[:])+"/hex")
	if err != nil {
		return nil, err
	}
	hexStr := strings.TrimSpace(strings.Trim(string(body), `"`))
	raw, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, fmt.Errorf("woc: tx hex: %w", err)
	}
	return raw, nil
}

// GetUTXOs returns the UTXO set for an address via /address/<addr>/unspent.
func (c *Client) GetUTXOs(ctx context.Context, address string) ([]UTXO, error) {
	body, err := c.get(ctx, "/address/"+address+"/unspent")
	if err != nil {
		return nil, err
	}
	var rows []struct {
		TxHash    string `json:"tx_hash"`
		TxPos     uint32 `json:"tx_pos"`
		Value     uint64 `json:"value"`
		Height    uint64 `json:"height"`
		ScriptHex string `json:"scriptPubKey"`
	}
	if err := json.Unmarshal(body, &rows); err != nil {
		return nil, fmt.Errorf("woc: unspent decode: %w", err)
	}
	out := make([]UTXO, 0, len(rows))
	for _, r := range rows {
		var u UTXO
		if err := decodeHashBE(r.TxHash, &u.TxID); err != nil {
			continue
		}
		u.Vout = r.TxPos
		u.Satoshis = r.Value
		u.Height = r.Height
		if r.ScriptHex != "" {
			if raw, err := hex.DecodeString(r.ScriptHex); err == nil {
				u.ScriptPubKey = raw
			}
		}
		out = append(out, u)
	}
	return out, nil
}

// ChainInfo returns the current chain tip. SCAFFOLD: the JSON shape
// matches WoC's /chain/info but only the fields BSVM consumes are
// decoded.
func (c *Client) ChainInfo(ctx context.Context) (*ChainInfo, error) {
	body, err := c.get(ctx, "/chain/info")
	if err != nil {
		return nil, err
	}
	var w struct {
		Chain      string  `json:"chain"`
		Blocks     uint64  `json:"blocks"`
		BestHash   string  `json:"bestblockhash"`
		Difficulty float64 `json:"difficulty"`
	}
	if err := json.Unmarshal(body, &w); err != nil {
		return nil, fmt.Errorf("woc: chain info decode: %w", err)
	}
	out := &ChainInfo{
		Chain:      w.Chain,
		Blocks:     w.Blocks,
		Difficulty: w.Difficulty,
	}
	if w.BestHash != "" {
		_ = decodeHashBE(w.BestHash, &out.BestHash)
	}
	return out, nil
}

// Ping reports liveness via /chain/info.
func (c *Client) Ping(ctx context.Context) error {
	_, err := c.ChainInfo(ctx)
	return err
}

func decodeHashBE(s string, out *[32]byte) error {
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

var _ WhatsOnChainClient = (*Client)(nil)
