//go:build multinode

package multinode

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"sync/atomic"
)

// requestID is a monotonically increasing counter for JSON-RPC request IDs.
var requestID atomic.Int64

// jsonRPCRequest is a JSON-RPC 2.0 request.
type jsonRPCRequest struct {
	JSONRPC string        `json:"jsonrpc"`
	Method  string        `json:"method"`
	Params  []interface{} `json:"params"`
	ID      int64         `json:"id"`
}

// jsonRPCResponse is a JSON-RPC 2.0 response.
type jsonRPCResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *jsonRPCError   `json:"error,omitempty"`
	ID      int64           `json:"id"`
}

// jsonRPCError is a JSON-RPC 2.0 error object.
type jsonRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (e *jsonRPCError) Error() string {
	return fmt.Sprintf("rpc error %d: %s", e.Code, e.Message)
}

// rpcCall sends a JSON-RPC 2.0 request and returns the raw result.
func rpcCall(ctx context.Context, url, method string, params ...interface{}) (json.RawMessage, error) {
	if params == nil {
		params = []interface{}{}
	}
	req := jsonRPCRequest{
		JSONRPC: "2.0",
		Method:  method,
		Params:  params,
		ID:      requestID.Add(1),
	}

	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshaling request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("sending request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	var rpcResp jsonRPCResponse
	if err := json.Unmarshal(respBody, &rpcResp); err != nil {
		return nil, fmt.Errorf("unmarshaling response: %w", err)
	}

	if rpcResp.Error != nil {
		return nil, rpcResp.Error
	}

	return rpcResp.Result, nil
}

// GetBlockNumber calls eth_blockNumber and returns the block number.
func GetBlockNumber(ctx context.Context, url string) (uint64, error) {
	result, err := rpcCall(ctx, url, "eth_blockNumber")
	if err != nil {
		return 0, err
	}

	var hexStr string
	if err := json.Unmarshal(result, &hexStr); err != nil {
		return 0, fmt.Errorf("unmarshaling block number: %w", err)
	}

	n, err := strconv.ParseUint(stripHexPrefix(hexStr), 16, 64)
	if err != nil {
		return 0, fmt.Errorf("parsing block number %q: %w", hexStr, err)
	}
	return n, nil
}

// GetPeerCount calls net_peerCount and returns the number of connected peers.
func GetPeerCount(ctx context.Context, url string) (uint64, error) {
	result, err := rpcCall(ctx, url, "net_peerCount")
	if err != nil {
		return 0, err
	}

	var hexStr string
	if err := json.Unmarshal(result, &hexStr); err != nil {
		return 0, fmt.Errorf("unmarshaling peer count: %w", err)
	}

	n, err := strconv.ParseUint(stripHexPrefix(hexStr), 16, 64)
	if err != nil {
		return 0, fmt.Errorf("parsing peer count %q: %w", hexStr, err)
	}
	return n, nil
}

// SendRawTransaction calls eth_sendRawTransaction with the given hex-encoded
// signed transaction and returns the transaction hash.
func SendRawTransaction(ctx context.Context, url, txHex string) (string, error) {
	result, err := rpcCall(ctx, url, "eth_sendRawTransaction", txHex)
	if err != nil {
		return "", err
	}

	var txHash string
	if err := json.Unmarshal(result, &txHash); err != nil {
		return "", fmt.Errorf("unmarshaling tx hash: %w", err)
	}
	return txHash, nil
}

// GetBalance calls eth_getBalance for the given address at the latest block.
func GetBalance(ctx context.Context, url, addr string) (string, error) {
	result, err := rpcCall(ctx, url, "eth_getBalance", addr, "latest")
	if err != nil {
		return "", err
	}

	var balance string
	if err := json.Unmarshal(result, &balance); err != nil {
		return "", fmt.Errorf("unmarshaling balance: %w", err)
	}
	return balance, nil
}

// stripHexPrefix removes a leading "0x" or "0X" from a hex string.
func stripHexPrefix(s string) string {
	if len(s) >= 2 && (s[:2] == "0x" || s[:2] == "0X") {
		return s[2:]
	}
	return s
}
