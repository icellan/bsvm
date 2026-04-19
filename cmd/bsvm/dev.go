package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	cli "github.com/urfave/cli/v2"
)

// devCommand groups the devnet-only helpers under `bsv-evm dev ...`.
// These subcommands talk to the BSV regtest node (via JSON-RPC) and
// are used by docker-compose healthchecks, integration tests, and
// developers who want to manually advance regtest state.
func devCommand() *cli.Command {
	return &cli.Command{
		Name:  "dev",
		Usage: "Developer utilities for a local BSVM devnet",
		Subcommands: []*cli.Command{
			{
				Name:  "mine",
				Usage: "Mine N blocks on the configured BSV regtest node",
				Flags: []cli.Flag{
					&cli.IntFlag{Name: "blocks", Value: 1, Usage: "number of blocks to mine"},
					&cli.StringFlag{
						Name:  "rpc",
						Value: "",
						Usage: "BSV RPC URL (default: $BSVM_BSV_RPC)",
					},
					&cli.StringFlag{
						Name:  "address",
						Value: "",
						Usage: "BSV address to mine to (default: call getnewaddress on the node)",
					},
				},
				Action: cmdDevMine,
			},
		},
	}
}

// cmdDevMine mines the requested number of blocks on a BSV regtest
// node. It reads the RPC URL from --rpc or BSVM_BSV_RPC, generates a
// fresh payout address if none is supplied, and prints the resulting
// block hashes to stdout (one per line).
//
// This subcommand is the Go equivalent of the `generatetoaddress`
// helper used by the runar integration tests.
func cmdDevMine(ctx *cli.Context) error {
	blocks := ctx.Int("blocks")
	if blocks < 1 {
		return fmt.Errorf("--blocks must be >= 1 (got %d)", blocks)
	}

	rpcURL := strings.TrimSpace(ctx.String("rpc"))
	if rpcURL == "" {
		rpcURL = strings.TrimSpace(os.Getenv("BSVM_BSV_RPC"))
	}
	if rpcURL == "" {
		return fmt.Errorf("BSV RPC URL must be set via --rpc or BSVM_BSV_RPC")
	}

	client := newBSVRPCClient(rpcURL)

	addr := strings.TrimSpace(ctx.String("address"))
	if addr == "" {
		var err error
		addr, err = client.getNewAddress()
		if err != nil {
			return fmt.Errorf("getnewaddress failed: %w", err)
		}
	}

	hashes, err := client.generateToAddress(blocks, addr)
	if err != nil {
		return fmt.Errorf("generatetoaddress failed: %w", err)
	}

	for _, h := range hashes {
		fmt.Println(h)
	}
	return nil
}

// bsvRPCClient is a tiny JSON-RPC 1.0 client used by `bsv-evm dev mine`
// (and, by extension, integration smoke tests). It intentionally does
// NOT pull in a heavy BSV SDK dependency — the only operations we need
// here are `getnewaddress` and `generatetoaddress`, and the JSON
// envelope is trivial.
type bsvRPCClient struct {
	endpoint string
	username string
	password string
	http     *http.Client
}

// newBSVRPCClient parses the URL and extracts basic-auth credentials
// from the "user:pass@" section if present. BSV regtest nodes
// traditionally publish an RPC URL of the form
// http://devuser:devpass@host:18332.
func newBSVRPCClient(rawURL string) *bsvRPCClient {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		// Fall back to using the raw string as the endpoint; requests
		// will fail downstream with a clearer error than a URL parse.
		return &bsvRPCClient{
			endpoint: rawURL,
			http:     &http.Client{Timeout: 30 * time.Second},
		}
	}
	c := &bsvRPCClient{
		http: &http.Client{Timeout: 30 * time.Second},
	}
	if parsed.User != nil {
		c.username = parsed.User.Username()
		pw, _ := parsed.User.Password()
		c.password = pw
		// Strip credentials from the endpoint so net/http doesn't log
		// them.
		parsed.User = nil
	}
	c.endpoint = parsed.String()
	return c
}

type rpcRequest struct {
	JSONRPC string        `json:"jsonrpc"`
	Method  string        `json:"method"`
	Params  []interface{} `json:"params"`
	ID      int           `json:"id"`
}

type rpcResponse struct {
	Result json.RawMessage `json:"result"`
	Error  *rpcError       `json:"error,omitempty"`
	ID     int             `json:"id"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (c *bsvRPCClient) call(method string, params []interface{}, out interface{}) error {
	body, err := json.Marshal(rpcRequest{
		JSONRPC: "1.0",
		Method:  method,
		Params:  params,
		ID:      1,
	})
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, c.endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.username != "" {
		req.SetBasicAuth(c.username, c.password)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("posting to %s: %w", c.endpoint, err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("reading response: %w", err)
	}
	if resp.StatusCode/100 != 2 && len(raw) == 0 {
		return fmt.Errorf("HTTP %d from BSV RPC", resp.StatusCode)
	}

	var r rpcResponse
	if err := json.Unmarshal(raw, &r); err != nil {
		return fmt.Errorf("parsing response (status %d): %w: %s",
			resp.StatusCode, err, string(raw))
	}
	if r.Error != nil {
		return fmt.Errorf("BSV RPC %s: code=%d %s", method, r.Error.Code, r.Error.Message)
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(r.Result, out)
}

func (c *bsvRPCClient) getNewAddress() (string, error) {
	var addr string
	if err := c.call("getnewaddress", []interface{}{}, &addr); err != nil {
		return "", err
	}
	return addr, nil
}

func (c *bsvRPCClient) generateToAddress(blocks int, address string) ([]string, error) {
	var hashes []string
	if err := c.call("generatetoaddress", []interface{}{blocks, address}, &hashes); err != nil {
		return nil, err
	}
	return hashes, nil
}
