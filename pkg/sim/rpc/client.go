// Package rpc is a JSON-RPC 2.0 client tailored for the bsvm traffic
// simulator. It speaks the subset of eth_* / bsv_* / net_* methods the
// sim drives + reads. It does not depend on go-ethereum (per the
// repo's zero-geth rule).
package rpc

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/holiman/uint256"

	"github.com/icellan/bsvm/pkg/types"
)

type Client struct {
	url    string
	http   *http.Client
	nextID atomic.Int64
}

func NewClient(url string) *Client {
	return &Client{
		url:  url,
		http: &http.Client{Timeout: 15 * time.Second},
	}
}

func (c *Client) URL() string { return c.url }

type rpcRequest struct {
	JSONRPC string `json:"jsonrpc"`
	Method  string `json:"method"`
	Params  []any  `json:"params"`
	ID      int64  `json:"id"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *RPCError       `json:"error,omitempty"`
	ID      int64           `json:"id"`
}

type RPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (e *RPCError) Error() string { return fmt.Sprintf("rpc error %d: %s", e.Code, e.Message) }

func (c *Client) Call(ctx context.Context, method string, params ...any) (json.RawMessage, error) {
	if params == nil {
		params = []any{}
	}
	body, err := json.Marshal(rpcRequest{JSONRPC: "2.0", Method: method, Params: params, ID: c.nextID.Add(1)})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("http %d: %s", resp.StatusCode, string(raw))
	}
	var out rpcResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("decode response: %w (body=%q)", err, string(raw))
	}
	if out.Error != nil {
		return nil, out.Error
	}
	return out.Result, nil
}

func decodeHexString(raw json.RawMessage) (string, error) {
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", err
	}
	return s, nil
}

func parseHexUint64(s string) (uint64, error) {
	s = trim0x(s)
	if s == "" {
		return 0, nil
	}
	return strconv.ParseUint(s, 16, 64)
}

func trim0x(s string) string {
	if len(s) >= 2 && (s[0:2] == "0x" || s[0:2] == "0X") {
		return s[2:]
	}
	return s
}

// ChainID returns eth_chainId as uint64.
func (c *Client) ChainID(ctx context.Context) (uint64, error) {
	raw, err := c.Call(ctx, "eth_chainId")
	if err != nil {
		return 0, err
	}
	s, err := decodeHexString(raw)
	if err != nil {
		return 0, err
	}
	return parseHexUint64(s)
}

// BlockNumber returns eth_blockNumber.
func (c *Client) BlockNumber(ctx context.Context) (uint64, error) {
	raw, err := c.Call(ctx, "eth_blockNumber")
	if err != nil {
		return 0, err
	}
	s, err := decodeHexString(raw)
	if err != nil {
		return 0, err
	}
	return parseHexUint64(s)
}

// Balance returns eth_getBalance(addr, "latest") as wei.
func (c *Client) Balance(ctx context.Context, addr types.Address) (*uint256.Int, error) {
	raw, err := c.Call(ctx, "eth_getBalance", addr.Hex(), "latest")
	if err != nil {
		return nil, err
	}
	s, err := decodeHexString(raw)
	if err != nil {
		return nil, err
	}
	b, ok := new(big.Int).SetString(trim0x(s), 16)
	if !ok {
		return nil, fmt.Errorf("balance parse %q", s)
	}
	v, overflow := uint256.FromBig(b)
	if overflow {
		return nil, fmt.Errorf("balance overflow: %s", b.String())
	}
	return v, nil
}

// Nonce returns eth_getTransactionCount(addr, "pending").
func (c *Client) Nonce(ctx context.Context, addr types.Address) (uint64, error) {
	raw, err := c.Call(ctx, "eth_getTransactionCount", addr.Hex(), "pending")
	if err != nil {
		return 0, err
	}
	s, err := decodeHexString(raw)
	if err != nil {
		return 0, err
	}
	return parseHexUint64(s)
}

// SendRawTx submits an RLP-encoded signed transaction.
func (c *Client) SendRawTx(ctx context.Context, txRLPHex string) (types.Hash, error) {
	if !strings.HasPrefix(txRLPHex, "0x") && !strings.HasPrefix(txRLPHex, "0X") {
		txRLPHex = "0x" + txRLPHex
	}
	raw, err := c.Call(ctx, "eth_sendRawTransaction", txRLPHex)
	if err != nil {
		return types.Hash{}, err
	}
	s, err := decodeHexString(raw)
	if err != nil {
		return types.Hash{}, err
	}
	return types.HexToHash(s), nil
}

// Receipt is the decoded subset of an eth_getTransactionReceipt response.
type Receipt struct {
	Status          uint64
	BlockNumber     uint64
	GasUsed         uint64
	ContractAddress *types.Address
	TxHash          types.Hash
}

// Raw is the decoded JSON object; nil if the receipt is not yet known.
type rawReceipt struct {
	Status            string `json:"status"`
	BlockNumber       string `json:"blockNumber"`
	GasUsed           string `json:"gasUsed"`
	ContractAddress   string `json:"contractAddress"`
	TransactionHash   string `json:"transactionHash"`
}

// GetReceipt returns nil when the receipt is not yet available.
func (c *Client) GetReceipt(ctx context.Context, hash types.Hash) (*Receipt, error) {
	raw, err := c.Call(ctx, "eth_getTransactionReceipt", hash.Hex())
	if err != nil {
		return nil, err
	}
	if bytes.Equal(raw, []byte("null")) {
		return nil, nil
	}
	var r rawReceipt
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, fmt.Errorf("decode receipt: %w", err)
	}
	rec := &Receipt{TxHash: hash}
	rec.Status, _ = parseHexUint64(r.Status)
	rec.BlockNumber, _ = parseHexUint64(r.BlockNumber)
	rec.GasUsed, _ = parseHexUint64(r.GasUsed)
	if r.ContractAddress != "" && r.ContractAddress != "null" {
		a := types.HexToAddress(r.ContractAddress)
		rec.ContractAddress = &a
	}
	return rec, nil
}

// WaitReceipt polls GetReceipt until a receipt appears or ctx expires.
func (c *Client) WaitReceipt(ctx context.Context, hash types.Hash, poll time.Duration) (*Receipt, error) {
	if poll <= 0 {
		poll = 250 * time.Millisecond
	}
	t := time.NewTicker(poll)
	defer t.Stop()
	for {
		r, err := c.GetReceipt(ctx, hash)
		if err != nil {
			return nil, err
		}
		if r != nil {
			return r, nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-t.C:
		}
	}
}

// Call runs eth_call against `latest`.
func (c *Client) EthCall(ctx context.Context, from, to types.Address, data []byte) ([]byte, error) {
	params := map[string]string{
		"from": from.Hex(),
		"to":   to.Hex(),
		"data": "0x" + hex.EncodeToString(data),
	}
	raw, err := c.Call(ctx, "eth_call", params, "latest")
	if err != nil {
		return nil, err
	}
	s, err := decodeHexString(raw)
	if err != nil {
		return nil, err
	}
	return hex.DecodeString(trim0x(s))
}

// GasPrice returns eth_gasPrice.
func (c *Client) GasPrice(ctx context.Context) (*big.Int, error) {
	raw, err := c.Call(ctx, "eth_gasPrice")
	if err != nil {
		return nil, err
	}
	s, err := decodeHexString(raw)
	if err != nil {
		return nil, err
	}
	b, ok := new(big.Int).SetString(trim0x(s), 16)
	if !ok {
		return nil, fmt.Errorf("gas price parse %q", s)
	}
	return b, nil
}

// PeerCount returns net_peerCount.
func (c *Client) PeerCount(ctx context.Context) (uint64, error) {
	raw, err := c.Call(ctx, "net_peerCount")
	if err != nil {
		return 0, err
	}
	s, err := decodeHexString(raw)
	if err != nil {
		return 0, err
	}
	return parseHexUint64(s)
}

// BsvNetworkHealth returns the raw bsv_networkHealth response.
func (c *Client) BsvNetworkHealth(ctx context.Context) (map[string]any, error) {
	raw, err := c.Call(ctx, "bsv_networkHealth")
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	return m, nil
}

// BsvProvingStatus returns the raw bsv_provingStatus response.
func (c *Client) BsvProvingStatus(ctx context.Context) (map[string]any, error) {
	raw, err := c.Call(ctx, "bsv_provingStatus")
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	return m, nil
}

// MetricsURL returns the base /metrics URL derived from the RPC URL by
// swapping the RPC path ("" or "/") for "/metrics" on the same host.
func (c *Client) MetricsURL() string {
	u := c.url
	u = strings.TrimSuffix(u, "/")
	return u + "/metrics"
}

// ScrapeMetrics performs an HTTP GET on the node's /metrics endpoint
// and returns the raw Prometheus text payload.
func (c *Client) ScrapeMetrics(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.MetricsURL(), nil)
	if err != nil {
		return "", err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	if resp.StatusCode/100 != 2 {
		return "", fmt.Errorf("metrics http %d", resp.StatusCode)
	}
	return string(body), nil
}

// ErrNotFound is returned when a lookup turns up no result.
var ErrNotFound = errors.New("not found")
