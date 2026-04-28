// Package arc is the BSVM client for the ARC / ARCADE transaction
// broadcast service. ARC is BSVM's primary path for both broadcasting
// covenant-advance / bridge / inbox transactions and for receiving
// MINED-status callbacks containing a BRC-74 BUMP.
//
// This package ships:
//
//   - The ARCClient interface and a Client implementation backed by
//     ARC's HTTPS API.
//   - A CallbackHandler that receives ARC callbacks (POST /v1/tx
//     callback shape) and authenticates them via X-ARC-Callback-Token.
//
// Multi-endpoint redundancy and full BRC-104 mutual auth on
// authenticated ARC deployments are follow-up work; this wave gets the
// basic broadcast / status / callback wiring shipped behind a stable
// interface so the rest of the node can be plumbed onto it.
package arc

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/icellan/bsvm/pkg/metrics"
)

// Status is an ARC transaction status code.
type Status string

const (
	StatusUnknown              Status = "UNKNOWN"
	StatusQueued               Status = "QUEUED"
	StatusReceived             Status = "RECEIVED"
	StatusStored               Status = "STORED"
	StatusAnnouncedToNetwork   Status = "ANNOUNCED_TO_NETWORK"
	StatusRequestedByNetwork   Status = "REQUESTED_BY_NETWORK"
	StatusSentToNetwork        Status = "SENT_TO_NETWORK"
	StatusAcceptedByNetwork    Status = "ACCEPTED_BY_NETWORK"
	StatusSeenOnNetwork        Status = "SEEN_ON_NETWORK"
	StatusMined                Status = "MINED"
	StatusConfirmed            Status = "CONFIRMED"
	StatusRejected             Status = "REJECTED"
	StatusSeenInOrphanMempool  Status = "SEEN_IN_ORPHAN_MEMPOOL"
	StatusDoubleSpendAttempted Status = "DOUBLE_SPEND_ATTEMPTED"
	StatusDoubleSpendConfirmed Status = "DOUBLE_SPEND_CONFIRMED"
)

// BroadcastResponse is the parsed result of a successful Broadcast
// call. ARC may return MerklePath bytes inline when the tx was mined
// before broadcast (rare but legal); otherwise MerklePath is nil and
// the caller waits for the callback.
type BroadcastResponse struct {
	TxID        [32]byte
	Status      Status
	BlockHash   [32]byte
	BlockHeight uint64
	ExtraInfo   string
	MerklePath  []byte
	SubmittedAt time.Time
}

// TxStatus is the parsed result of a Status() call.
type TxStatus struct {
	TxID           [32]byte
	Status         Status
	BlockHash      [32]byte
	BlockHeight    uint64
	MerklePath     []byte
	CompetingTxIDs [][32]byte
	ExtraInfo      string
}

// Client is the canonical ARC client. Construct via NewClient.
type Client struct {
	cfg     Config
	http    *http.Client
	metrics *metrics.Counters
}

// SetMetrics swaps the ARC client's Counters pointer. Pass the daemon's
// shared *metrics.Counters at boot to enable broadcast-attempt /
// failure counters; passing nil falls back to a fresh no-op registry.
func (c *Client) SetMetrics(m *metrics.Counters) {
	if m == nil {
		c.metrics = metrics.DisabledCounters()
		return
	}
	c.metrics = m
}

// Config configures an ARC Client.
type Config struct {
	// URL is the ARC base URL (e.g. https://arc.taal.com).
	URL string
	// Timeout caps each HTTP request. Defaults to 30s.
	Timeout time.Duration
	// CallbackURL is registered on every Broadcast call via
	// X-CallbackUrl so ARC POSTs status updates here.
	CallbackURL string
	// CallbackToken is forwarded via X-CallbackToken and must match
	// the token configured on CallbackHandler.
	CallbackToken string
	// AuthToken is an optional Bearer token for ARC deployments that
	// require API auth.
	AuthToken string
}

// ARCClient is the interface BSVM consumes. Test fakes implement it
// directly; production wiring uses *Client.
type ARCClient interface {
	Broadcast(ctx context.Context, txOrBeef []byte) (*BroadcastResponse, error)
	Status(ctx context.Context, txid [32]byte) (*TxStatus, error)
	Ping(ctx context.Context) error
}

// NewClient builds a Client. cfg.URL is required.
func NewClient(cfg Config) (*Client, error) {
	if cfg.URL == "" {
		return nil, errors.New("arc: URL required")
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 30 * time.Second
	}
	return &Client{
		cfg:     cfg,
		http:    &http.Client{Timeout: cfg.Timeout},
		metrics: metrics.DisabledCounters(),
	}, nil
}

type wireBroadcast struct {
	TxStatus    string `json:"txStatus"`
	TxID        string `json:"txid"`
	BlockHash   string `json:"blockHash"`
	BlockHeight uint64 `json:"blockHeight"`
	MerklePath  string `json:"merklePath"`
	ExtraInfo   string `json:"extraInfo"`
}

func (w wireBroadcast) toBroadcastResponse() (*BroadcastResponse, error) {
	out := &BroadcastResponse{
		Status:      Status(w.TxStatus),
		BlockHeight: w.BlockHeight,
		ExtraInfo:   w.ExtraInfo,
		SubmittedAt: time.Now().UTC(),
	}
	if w.TxID != "" {
		if err := decodeHashBE(w.TxID, &out.TxID); err != nil {
			return nil, fmt.Errorf("arc: txid: %w", err)
		}
	}
	if w.BlockHash != "" {
		if err := decodeHashBE(w.BlockHash, &out.BlockHash); err != nil {
			return nil, fmt.Errorf("arc: blockHash: %w", err)
		}
	}
	if w.MerklePath != "" {
		raw, err := hex.DecodeString(strings.TrimPrefix(w.MerklePath, "0x"))
		if err != nil {
			return nil, fmt.Errorf("arc: merklePath: %w", err)
		}
		out.MerklePath = raw
	}
	return out, nil
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

// Broadcast posts txOrBeef (raw tx bytes or BEEF) to ARC's POST /v1/tx
// endpoint. It encodes the body as hex per ARC's standard wire shape
// (body is `{"rawTx":"<hex>"}`); deployments that prefer
// application/octet-stream BEEF can be added once the surface
// stabilises.
func (c *Client) Broadcast(ctx context.Context, txOrBeef []byte) (*BroadcastResponse, error) {
	if c.metrics != nil {
		c.metrics.ARCBroadcastAttemptsTotal.Inc()
	}
	endpoint := strings.TrimRight(c.cfg.URL, "/") + "/v1/tx"
	body, err := json.Marshal(map[string]string{"rawTx": hex.EncodeToString(txOrBeef)})
	if err != nil {
		return nil, fmt.Errorf("arc: marshal: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if c.cfg.AuthToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.cfg.AuthToken)
	}
	if c.cfg.CallbackURL != "" {
		req.Header.Set("X-CallbackUrl", c.cfg.CallbackURL)
	}
	if c.cfg.CallbackToken != "" {
		req.Header.Set("X-CallbackToken", c.cfg.CallbackToken)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		// Pre-response transport failure (dial refused, EOF, timeout
		// before a status was received). Surface as an ARCBroadcastError
		// with HTTPStatus=0 so callers can classify via IsTransient
		// without resorting to string matching.
		brErr := &ARCBroadcastError{Underlying: err}
		c.recordBroadcastFailure(brErr)
		return nil, brErr
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		brErr := &ARCBroadcastError{
			HTTPStatus: resp.StatusCode,
			Underlying: err,
			Detail:     "read response body",
		}
		c.recordBroadcastFailure(brErr)
		return nil, brErr
	}
	if resp.StatusCode >= 400 {
		// Parse the body opportunistically — ARC frequently returns the
		// wireBroadcast shape on 4xx (txStatus=REJECTED + extraInfo) so
		// IsPermanent / IsTransient can use the BSV-side TxStatus
		// directly. Failure to parse is non-fatal: we fall back to the
		// raw body in Detail.
		var w wireBroadcast
		txStatus := ""
		_ = json.Unmarshal(respBody, &w)
		txStatus = w.TxStatus
		brErr := &ARCBroadcastError{
			HTTPStatus: resp.StatusCode,
			TxStatus:   txStatus,
			Detail:     string(respBody),
		}
		c.recordBroadcastFailure(brErr)
		return nil, brErr
	}
	var w wireBroadcast
	if err := json.Unmarshal(respBody, &w); err != nil {
		return nil, fmt.Errorf("arc: decode broadcast: %w", err)
	}
	// ARC may return 200 with a terminal-rejection txStatus
	// (REJECTED, DOUBLE_SPEND_*, SEEN_IN_ORPHAN_MEMPOOL). Surface those
	// as typed errors so the caller can drop the claim instead of
	// treating it as a successful broadcast.
	switch Status(w.TxStatus) {
	case StatusRejected,
		StatusDoubleSpendAttempted,
		StatusDoubleSpendConfirmed,
		StatusSeenInOrphanMempool:
		brErr := &ARCBroadcastError{
			HTTPStatus: resp.StatusCode,
			TxStatus:   w.TxStatus,
			Detail:     w.ExtraInfo,
		}
		c.recordBroadcastFailure(brErr)
		return nil, brErr
	}
	return w.toBroadcastResponse()
}

// recordBroadcastFailure bumps the ARC broadcast failure counter under
// the appropriate class label. Permanent (terminal) errors increment
// class=permanent; everything else (transport, 5xx, 4xx without a
// terminal txStatus) is bucketed as class=transient. Safe when c.metrics
// is nil — the metrics field is always seeded by NewClient and SetMetrics
// guards nil values, but the helper is defensive.
func (c *Client) recordBroadcastFailure(err *ARCBroadcastError) {
	if c.metrics == nil || err == nil {
		return
	}
	if err.IsPermanent() {
		c.metrics.IncARCBroadcastFailed("permanent")
		return
	}
	c.metrics.IncARCBroadcastFailed("transient")
}

type wireStatus struct {
	TxStatus       string   `json:"txStatus"`
	TxID           string   `json:"txid"`
	BlockHash      string   `json:"blockHash"`
	BlockHeight    uint64   `json:"blockHeight"`
	MerklePath     string   `json:"merklePath"`
	CompetingTxids []string `json:"competingTxs"`
	ExtraInfo      string   `json:"extraInfo"`
}

// Status polls ARC for the current status of a txid.
func (c *Client) Status(ctx context.Context, txid [32]byte) (*TxStatus, error) {
	endpoint := strings.TrimRight(c.cfg.URL, "/") + "/v1/tx/" + hex.EncodeToString(txid[:])
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	if c.cfg.AuthToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.cfg.AuthToken)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("arc: status: %w", err)
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("arc: read status response: %w", err)
	}
	if resp.StatusCode == http.StatusNotFound {
		return &TxStatus{TxID: txid, Status: StatusUnknown}, nil
	}
	if resp.StatusCode >= 400 {
		var w wireStatus
		_ = json.Unmarshal(respBody, &w)
		return nil, &ARCBroadcastError{
			HTTPStatus: resp.StatusCode,
			TxStatus:   w.TxStatus,
			Detail:     string(respBody),
		}
	}
	var w wireStatus
	if err := json.Unmarshal(respBody, &w); err != nil {
		return nil, fmt.Errorf("arc: decode status: %w", err)
	}
	out := &TxStatus{
		Status:      Status(w.TxStatus),
		BlockHeight: w.BlockHeight,
		ExtraInfo:   w.ExtraInfo,
	}
	if w.TxID != "" {
		if err := decodeHashBE(w.TxID, &out.TxID); err != nil {
			return nil, fmt.Errorf("arc: status txid: %w", err)
		}
	} else {
		out.TxID = txid
	}
	if w.BlockHash != "" {
		if err := decodeHashBE(w.BlockHash, &out.BlockHash); err != nil {
			return nil, fmt.Errorf("arc: status blockHash: %w", err)
		}
	}
	if w.MerklePath != "" {
		raw, err := hex.DecodeString(strings.TrimPrefix(w.MerklePath, "0x"))
		if err != nil {
			return nil, fmt.Errorf("arc: status merklePath: %w", err)
		}
		out.MerklePath = raw
	}
	for _, t := range w.CompetingTxids {
		var h [32]byte
		if err := decodeHashBE(t, &h); err == nil {
			out.CompetingTxIDs = append(out.CompetingTxIDs, h)
		}
	}
	return out, nil
}

// Ping reports liveness via GET /v1/policy. ARC deployments expose
// /v1/policy unauthenticated; if your deployment requires auth on
// the endpoint, set Config.AuthToken.
func (c *Client) Ping(ctx context.Context) error {
	endpoint := strings.TrimRight(c.cfg.URL, "/") + "/v1/policy"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	if c.cfg.AuthToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.cfg.AuthToken)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("arc: ping: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("arc: ping status %d", resp.StatusCode)
	}
	io.Copy(io.Discard, resp.Body)
	return nil
}

// IsAdvanceClient implements covenant.BroadcastClient so the ARC
// client can be plugged into the covenant manager directly. Production
// wiring composes this with a higher-level adapter that builds the
// covenant-advance transaction; the raw Broadcast / Status surface is
// what the adapter consumes.
//
// Compile-time check.
var _ ARCClient = (*Client)(nil)
