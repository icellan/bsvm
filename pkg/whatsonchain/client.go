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
	"sync"
	"time"
)

// Config configures a WhatsOnChain Client.
type Config struct {
	URL     string        // base URL, e.g. https://api.whatsonchain.com/v1/bsv/main
	Timeout time.Duration // HTTP request timeout (default 30s)
	APIKey  string        // optional WoC API key
	// BlockPageFetchWorkers overrides the per-block page-fetch
	// concurrency used by the paginated GetBlockTxIDs path. Zero or
	// negative falls back to the package default
	// (blockPageFetchWorkers). Operators on a WoC paid tier may raise
	// this; rate-limit-budget-constrained operators may dial it lower.
	BlockPageFetchWorkers int
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
	// pageWorkers is the resolved per-block page-fetch concurrency. It
	// is populated from cfg.BlockPageFetchWorkers if positive, else
	// the package default blockPageFetchWorkers.
	pageWorkers int
}

// WhatsOnChainClient is the interface BSVM consumes.
type WhatsOnChainClient interface {
	GetTx(ctx context.Context, txid [32]byte) ([]byte, error)
	GetUTXOs(ctx context.Context, address string) ([]UTXO, error)
	ChainInfo(ctx context.Context) (*ChainInfo, error)
	// GetBlockTxIDs returns the txid list for a block, identified by
	// its (BSV-internal little-endian) hash. Used by the bridge block
	// scanner's WoC fan-out fallback when no BSV-node RPC is wired.
	// The returned txids are in the same little-endian convention used
	// elsewhere in BSVM (types.Hash). WoC speaks big-endian on the wire;
	// the implementation handles the reversal.
	GetBlockTxIDs(ctx context.Context, blockHash [32]byte) ([][32]byte, error)
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
	workers := cfg.BlockPageFetchWorkers
	if workers <= 0 {
		workers = blockPageFetchWorkers
	}
	return &Client{
		cfg:         cfg,
		http:        &http.Client{Timeout: cfg.Timeout},
		pageWorkers: workers,
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

// blockTxIDsAbsoluteMax is a defensive upper bound on the total number
// of txids GetBlockTxIDs will accept from WoC (header + paginated
// pages combined). With BSV scaling, a single block can in principle
// be very large; pagination removes the legacy ~10k inline cap, but
// we still want an outer guard against a runaway fetch storm or a
// malformed `pages.uri` that would loop forever. 1M txs is well above
// any block ever mined to date and trivial in memory cost (~32 MB of
// txid bytes).
const blockTxIDsAbsoluteMax = 1_000_000

// blockPageFetchWorkers caps the per-block page-fetch concurrency.
// 4 balances aggregate throughput against burst-load on the WoC API,
// matching the per-tx fan-out posture in cmd/bsvm/bridge_bsv_client.go.
const blockPageFetchWorkers = 4

// blockHeaderResponse is the JSON shape of `/block/hash/<hash>` for
// both inline-tx and paginated cases.
//
//   - Inline (small block): `tx` is non-empty; `pages.uri` is absent or
//     empty. Decode `tx` directly.
//   - Paginated (large block): `tx` is typically empty (or capped at
//     ~10k); `pages.uri` is a non-empty list of page paths
//     (`/block/hash/<hash>/page/<n>`). Each page returns a flat JSON
//     array of txid hex strings.
//
// We tolerate either side carrying data; if `tx` is partially populated
// AND `pages` is set we treat it as paginated and rely on the page list
// for the full manifest (which is what WoC actually documents).
type blockHeaderResponse struct {
	Tx    []string `json:"tx"`
	Pages struct {
		URI []string `json:"uri"`
	} `json:"pages"`
}

// GetBlockTxIDs returns the list of txids in the block identified by
// blockHash (BSVM-internal little-endian). The implementation hits
// WoC's `/block/hash/<be-hex>` endpoint and decodes the `tx` field; WoC
// returns txids in big-endian display hex, which we reverse before
// surfacing so callers see the canonical little-endian byte order used
// throughout BSVM.
//
// WoC paginates very-large blocks (~10k+ txs) via
// `/block/hash/<hash>/page/<n>`. The header response in the paginated
// case carries an empty (or partial) `tx` array plus a non-empty
// `pages.uri` list pointing at the per-page endpoints. This method
// transparently fans out the page fetches with a bounded worker pool,
// concatenating results in manifest order. The aggregated result is
// capped at blockTxIDsAbsoluteMax as a defensive guard against a
// runaway fetch.
func (c *Client) GetBlockTxIDs(ctx context.Context, blockHash [32]byte) ([][32]byte, error) {
	beHash := make([]byte, 32)
	for i := 0; i < 32; i++ {
		beHash[i] = blockHash[31-i]
	}
	body, err := c.get(ctx, "/block/hash/"+hex.EncodeToString(beHash))
	if err != nil {
		return nil, err
	}
	hdr, err := parseBlockHeaderResponse(body)
	if err != nil {
		return nil, err
	}
	// Paginated path: WoC returned a `pages.uri` list. Fetch each page
	// (with bounded concurrency) and concatenate in order.
	if len(hdr.Pages.URI) > 0 {
		return c.fetchPagedBlockTxIDs(ctx, hdr.Pages.URI, fetchBlockPage)
	}
	// Inline path: the `tx` field carries the full manifest.
	return decodeBlockTxIDs(hdr.Tx, blockTxIDsAbsoluteMax)
}

// parseBlockHeaderResponse decodes the JSON body returned by
// `/block/hash/<hash>`. The parser is permissive — WoC has historically
// returned a few subtly different shapes; we extract only the fields
// BSVM consumes. A malformed body surfaces as a typed error so the
// pagination test can assert graceful failure.
func parseBlockHeaderResponse(body []byte) (*blockHeaderResponse, error) {
	var hdr blockHeaderResponse
	if err := json.Unmarshal(body, &hdr); err != nil {
		return nil, fmt.Errorf("woc: block decode: %w", err)
	}
	return &hdr, nil
}

// decodeBlockTxIDs converts a slice of big-endian hex txid strings into
// the BSVM-internal little-endian [32]byte form. Malformed entries are
// log-skipped (same posture parseVerboseBlock takes). The slice is
// truncated at maxIDs as a defensive bound.
func decodeBlockTxIDs(in []string, maxIDs int) ([][32]byte, error) {
	if len(in) > maxIDs {
		in = in[:maxIDs]
	}
	out := make([][32]byte, 0, len(in))
	for _, s := range in {
		var h [32]byte
		if err := decodeHashBE(s, &h); err != nil {
			continue
		}
		var le [32]byte
		for i := 0; i < 32; i++ {
			le[i] = h[31-i]
		}
		out = append(out, le)
	}
	return out, nil
}

// pageFetchFn is the page-fetch primitive GetBlockTxIDs hands to its
// pagination worker. Pulling it out to a function-typed parameter lets
// the cache wrapper inject a singleflight+LRU-backed implementation
// without exposing internal helpers across packages.
type pageFetchFn func(ctx context.Context, c *Client, pageURI string) ([]string, error)

// fetchBlockPage fetches a single page of a paginated block-tx manifest.
// The response is a flat JSON array of big-endian hex txid strings.
func fetchBlockPage(ctx context.Context, c *Client, pageURI string) ([]string, error) {
	body, err := c.get(ctx, pageURI)
	if err != nil {
		return nil, err
	}
	var ids []string
	if err := json.Unmarshal(body, &ids); err != nil {
		return nil, fmt.Errorf("woc: page decode %s: %w", pageURI, err)
	}
	return ids, nil
}

// getBlockTxIDsWithPageFetcher is the testable / cache-injectable form
// of GetBlockTxIDs. It runs the same header→pagination flow but lets
// the caller supply a custom page-fetch primitive — used by
// CachedClient to wire each page through its singleflight+LRU gate so
// repeated block lookups skip the page fetch entirely on a cache HIT.
func (c *Client) getBlockTxIDsWithPageFetcher(ctx context.Context, blockHash [32]byte, fetch pageFetchFn) ([][32]byte, error) {
	beHash := make([]byte, 32)
	for i := 0; i < 32; i++ {
		beHash[i] = blockHash[31-i]
	}
	body, err := c.get(ctx, "/block/hash/"+hex.EncodeToString(beHash))
	if err != nil {
		return nil, err
	}
	hdr, err := parseBlockHeaderResponse(body)
	if err != nil {
		return nil, err
	}
	if len(hdr.Pages.URI) > 0 {
		return c.fetchPagedBlockTxIDs(ctx, hdr.Pages.URI, fetch)
	}
	return decodeBlockTxIDs(hdr.Tx, blockTxIDsAbsoluteMax)
}

// fetchPagedBlockTxIDs fans out the paginated page-fetches using a
// bounded worker pool, preserving manifest order. A failure on any
// page is fatal — partial block-tx manifests would silently drop
// deposits, so we surface the first error.
func (c *Client) fetchPagedBlockTxIDs(ctx context.Context, pageURIs []string, fetch pageFetchFn) ([][32]byte, error) {
	type pageResult struct {
		idx int
		ids []string
		err error
	}

	workers := c.pageWorkers
	if workers <= 0 {
		workers = blockPageFetchWorkers
	}
	if workers > len(pageURIs) {
		workers = len(pageURIs)
	}
	if workers < 1 {
		workers = 1
	}

	jobs := make(chan int, len(pageURIs))
	results := make(chan pageResult, len(pageURIs))
	var wg sync.WaitGroup
	wg.Add(workers)
	for w := 0; w < workers; w++ {
		go func() {
			defer wg.Done()
			for i := range jobs {
				if ctx.Err() != nil {
					results <- pageResult{idx: i, err: ctx.Err()}
					continue
				}
				ids, err := fetch(ctx, c, pageURIs[i])
				results <- pageResult{idx: i, ids: ids, err: err}
			}
		}()
	}
	for i := range pageURIs {
		jobs <- i
	}
	close(jobs)
	wg.Wait()
	close(results)

	ordered := make([][]string, len(pageURIs))
	var firstErr error
	for r := range results {
		if r.err != nil {
			if firstErr == nil {
				firstErr = r.err
			}
			continue
		}
		ordered[r.idx] = r.ids
	}
	if firstErr != nil {
		return nil, fmt.Errorf("woc: page fetch: %w", firstErr)
	}

	// Concatenate in manifest order, decoding each big-endian hex into
	// a BSVM-internal little-endian [32]byte. The aggregate is capped
	// at blockTxIDsAbsoluteMax; any pages beyond the cap are dropped.
	totalCap := 0
	for _, p := range ordered {
		totalCap += len(p)
	}
	if totalCap > blockTxIDsAbsoluteMax {
		totalCap = blockTxIDsAbsoluteMax
	}
	out := make([][32]byte, 0, totalCap)
	for _, p := range ordered {
		for _, s := range p {
			if len(out) >= blockTxIDsAbsoluteMax {
				return out, nil
			}
			var h [32]byte
			if err := decodeHashBE(s, &h); err != nil {
				continue
			}
			var le [32]byte
			for i := 0; i < 32; i++ {
				le[i] = h[31-i]
			}
			out = append(out, le)
		}
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
