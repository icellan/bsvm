package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	cli "github.com/urfave/cli/v2"
)

// adminCommand groups the spec-15 admin CLI helpers. These talk to a
// node's /admin/rpc endpoint using the spec-16 dev-auth header. They
// are the shell-side counterpart to the explorer admin panel —
// operators use whichever is more convenient for the task.
func adminCommand() *cli.Command {
	return &cli.Command{
		Name:  "admin",
		Usage: "Operator commands against a node's /admin/rpc endpoint",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "rpc",
				Value:   "http://localhost:8545",
				Usage:   "base URL of the target bsvm node",
				EnvVars: []string{"BSVM_ADMIN_RPC"},
			},
			&cli.StringFlag{
				Name:    "dev-auth",
				Value:   "",
				Usage:   "dev-auth shared secret (default: $BSVM_ADMIN_DEV_SECRET, falls back to the devnet default when mock/execute)",
				EnvVars: []string{"BSVM_ADMIN_DEV_SECRET"},
			},
		},
		Subcommands: []*cli.Command{
			{
				Name:   "freeze",
				Usage:  "Request a governance freeze proposal",
				Action: cmdAdminFreeze,
			},
			{
				Name:   "unfreeze",
				Usage:  "Request a governance unfreeze proposal",
				Action: cmdAdminUnfreeze,
			},
			{
				Name:   "pause-proving",
				Usage:  "Pause the node's batcher (stops taking new txs)",
				Action: cmdAdminPauseProving,
			},
			{
				Name:   "resume-proving",
				Usage:  "Resume the node's batcher after a pause",
				Action: cmdAdminResumeProving,
			},
			{
				Name:   "force-flush",
				Usage:  "Force an immediate flush of the pending batch",
				Action: cmdAdminForceFlush,
			},
			{
				Name:   "get-config",
				Usage:  "Print the node's runtime configuration",
				Action: cmdAdminGetConfig,
			},
			{
				Name:   "peer-list",
				Usage:  "Print the node's peer list (currently empty until gossip wire-up)",
				Action: cmdAdminPeerList,
			},
		},
	}
}

// adminClient wraps a single /admin/rpc endpoint, carrying the
// dev-auth header on every request.
type adminClient struct {
	endpoint string
	secret   string
	http     *http.Client
}

func newAdminClient(ctx *cli.Context) *adminClient {
	rpc := strings.TrimSpace(ctx.String("rpc"))
	if rpc == "" {
		rpc = "http://localhost:8545"
	}
	// Normalise so we always post to /admin/rpc.
	rpc = strings.TrimRight(rpc, "/")
	if !strings.HasSuffix(rpc, "/admin/rpc") {
		rpc = rpc + "/admin/rpc"
	}

	secret := strings.TrimSpace(ctx.String("dev-auth"))
	if secret == "" {
		secret = strings.TrimSpace(os.Getenv("BSVM_ADMIN_DEV_SECRET"))
	}
	if secret == "" {
		// Match the server-side devnet fallback so `bsvm admin freeze`
		// just works against a stock `docker compose up` cluster.
		secret = "devnet-secret-do-not-use-in-production"
	}

	return &adminClient{
		endpoint: rpc,
		secret:   secret,
		http:     &http.Client{Timeout: 30 * time.Second},
	}
}

type adminRequest struct {
	JSONRPC string        `json:"jsonrpc"`
	Method  string        `json:"method"`
	Params  []interface{} `json:"params"`
	ID      int           `json:"id"`
}

type adminResponse struct {
	Result json.RawMessage `json:"result"`
	Error  *adminError     `json:"error,omitempty"`
}

type adminError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (c *adminClient) call(method string, params []interface{}, out interface{}) error {
	if params == nil {
		params = []interface{}{}
	}
	body, err := json.Marshal(adminRequest{JSONRPC: "2.0", Method: method, Params: params, ID: 1})
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, c.endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-bsvm-dev-auth", c.secret)

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("POST %s: %w", c.endpoint, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)

	switch resp.StatusCode {
	case http.StatusOK:
		// Fall through to JSON-RPC envelope parsing below.
	case http.StatusUnauthorized:
		return fmt.Errorf("admin auth rejected (check BSVM_ADMIN_DEV_SECRET): %s", strings.TrimSpace(string(raw)))
	case http.StatusForbidden:
		return fmt.Errorf("dev-auth not accepted in current proving mode (only mock/execute): %s", strings.TrimSpace(string(raw)))
	default:
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}

	var envelope adminResponse
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return fmt.Errorf("parsing response: %w: %s", err, raw)
	}
	if envelope.Error != nil {
		return fmt.Errorf("admin RPC %s: code=%d %s", method, envelope.Error.Code, envelope.Error.Message)
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(envelope.Result, out)
}

// printJSON emits a pretty-printed representation of v on stdout.
func printJSON(v interface{}) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// ---- Subcommand handlers ------------------------------------------------

func cmdAdminFreeze(ctx *cli.Context) error {
	c := newAdminClient(ctx)
	var result json.RawMessage
	if err := c.call("admin_createGovernanceProposal", []interface{}{"freeze"}, &result); err != nil {
		return err
	}
	return printJSON(result)
}

func cmdAdminUnfreeze(ctx *cli.Context) error {
	c := newAdminClient(ctx)
	var result json.RawMessage
	if err := c.call("admin_createGovernanceProposal", []interface{}{"unfreeze"}, &result); err != nil {
		return err
	}
	return printJSON(result)
}

func cmdAdminPauseProving(ctx *cli.Context) error {
	c := newAdminClient(ctx)
	var result json.RawMessage
	if err := c.call("admin_pauseProving", nil, &result); err != nil {
		return err
	}
	return printJSON(result)
}

func cmdAdminResumeProving(ctx *cli.Context) error {
	c := newAdminClient(ctx)
	var result json.RawMessage
	if err := c.call("admin_resumeProving", nil, &result); err != nil {
		return err
	}
	return printJSON(result)
}

func cmdAdminForceFlush(ctx *cli.Context) error {
	c := newAdminClient(ctx)
	var result json.RawMessage
	if err := c.call("admin_forceFlushBatch", nil, &result); err != nil {
		return err
	}
	return printJSON(result)
}

func cmdAdminGetConfig(ctx *cli.Context) error {
	c := newAdminClient(ctx)
	var result json.RawMessage
	if err := c.call("admin_getConfig", nil, &result); err != nil {
		return err
	}
	return printJSON(result)
}

func cmdAdminPeerList(ctx *cli.Context) error {
	c := newAdminClient(ctx)
	var result json.RawMessage
	if err := c.call("admin_peerList", nil, &result); err != nil {
		return err
	}
	return printJSON(result)
}
