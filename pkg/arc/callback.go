package arc

import (
	"bytes"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// CallbackPayload is the JSON body ARC POSTs to the callback URL.
// The schema mirrors ARC's `TransactionStatus` callback shape.
type CallbackPayload struct {
	TxID         string   `json:"txid"`
	TxStatus     Status   `json:"txStatus"`
	BlockHash    string   `json:"blockHash,omitempty"`
	BlockHeight  uint64   `json:"blockHeight,omitempty"`
	MerklePath   string   `json:"merklePath,omitempty"`
	ExtraInfo    string   `json:"extraInfo,omitempty"`
	CompetingTxs []string `json:"competingTxs,omitempty"`
	Timestamp    string   `json:"timestamp,omitempty"`
}

// CallbackEvent is the parsed form of a callback payload, with hashes
// normalised to [32]byte and merkle path bytes pre-decoded.
type CallbackEvent struct {
	TxID         [32]byte
	Status       Status
	BlockHash    [32]byte
	BlockHeight  uint64
	MerklePath   []byte
	ExtraInfo    string
	CompetingTxs [][32]byte
	ReceivedAt   time.Time
}

// CallbackHandler is the HTTP handler attached at
// `POST /bsv/arc/callback`. Each incoming callback is authenticated
// against either a shared token (legacy X-CallbackToken pattern) or a
// BRC-104 mutual-auth verifier (preferred, see brc104.go). The
// callback is parsed into a CallbackEvent and delivered to the
// registered consumer (typically the overlay's ARC consumer that
// upgrades the matching BEEF and gossips it).
//
// The handler enforces ONE of three authentication regimes, selected
// at construction time:
//
//  1. BRC-104 only — pass a non-nil verifier and AllowToken=false. The
//     recommended setting for new deployments.
//  2. Token only — pass a nil verifier with one or more tokens. The
//     legacy / migration setting.
//  3. Both accepted — pass a verifier AND AllowToken=true. Useful as
//     an interim during the BRC-104 rollout: requests carrying
//     BRC-104 headers are verified strictly, requests carrying only
//     a token use the legacy path. Both are accepted; neither is
//     accepted means 401.
type CallbackHandler struct {
	tokens     []string
	consumer   func(*CallbackEvent)
	verifier   *BRC104Verifier
	allowToken bool
	tokenMu    sync.RWMutex
}

// NewCallbackHandler constructs a CallbackHandler in legacy
// token-auth mode. tokens contains one or more shared secrets that
// ARC must present via the X-CallbackToken header; multiple tokens
// are supported so operators can rotate without downtime. Pass an
// empty slice to disable auth (NOT recommended outside dev). consumer
// is invoked synchronously for every accepted callback; pass nil to
// drop events.
//
// New deployments should prefer NewBRC104CallbackHandler.
func NewCallbackHandler(tokens []string, consumer func(*CallbackEvent)) *CallbackHandler {
	cleaned := make([]string, 0, len(tokens))
	for _, t := range tokens {
		t = strings.TrimSpace(t)
		if t != "" {
			cleaned = append(cleaned, t)
		}
	}
	return &CallbackHandler{tokens: cleaned, consumer: consumer, allowToken: true}
}

// NewBRC104CallbackHandler constructs a CallbackHandler that
// authenticates incoming callbacks using BRC-104 mutual auth.
// allowToken controls the migration mode: when true, requests that
// carry only the legacy X-CallbackToken (no BRC-104 headers) are
// also accepted against the supplied tokens slice; when false, every
// callback MUST present valid BRC-104 headers and the tokens slice
// is ignored. consumer is invoked synchronously for every accepted
// callback; pass nil to drop events.
func NewBRC104CallbackHandler(verifier *BRC104Verifier, tokens []string, allowToken bool, consumer func(*CallbackEvent)) (*CallbackHandler, error) {
	if verifier == nil {
		return nil, errors.New("arc: BRC-104 callback handler requires a verifier")
	}
	cleaned := make([]string, 0, len(tokens))
	for _, t := range tokens {
		t = strings.TrimSpace(t)
		if t != "" {
			cleaned = append(cleaned, t)
		}
	}
	return &CallbackHandler{
		tokens:     cleaned,
		consumer:   consumer,
		verifier:   verifier,
		allowToken: allowToken,
	}, nil
}

// SetVerifier installs a BRC-104 verifier on an existing handler. Use
// this to transition a token-mode handler to BRC-104 without
// recreating the consumer wiring. Pass nil to revert to token-only
// mode.
func (h *CallbackHandler) SetVerifier(v *BRC104Verifier) {
	h.tokenMu.Lock()
	defer h.tokenMu.Unlock()
	h.verifier = v
}

// SetAllowToken toggles whether the legacy token path is accepted in
// addition to BRC-104. Defaults to true for backward compatibility.
func (h *CallbackHandler) SetAllowToken(allow bool) {
	h.tokenMu.Lock()
	defer h.tokenMu.Unlock()
	h.allowToken = allow
}

// SetTokens replaces the authorised token list. Used for atomic
// rotation per spec 17 §"ARC callbacks are authenticated".
func (h *CallbackHandler) SetTokens(tokens []string) {
	h.tokenMu.Lock()
	defer h.tokenMu.Unlock()
	cleaned := make([]string, 0, len(tokens))
	for _, t := range tokens {
		t = strings.TrimSpace(t)
		if t != "" {
			cleaned = append(cleaned, t)
		}
	}
	h.tokens = cleaned
}

// SetConsumer replaces the registered consumer.
func (h *CallbackHandler) SetConsumer(consumer func(*CallbackEvent)) {
	h.tokenMu.Lock()
	defer h.tokenMu.Unlock()
	h.consumer = consumer
}

// ServeHTTP implements http.Handler.
func (h *CallbackHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	h.tokenMu.RLock()
	tokens := append([]string(nil), h.tokens...)
	consumer := h.consumer
	verifier := h.verifier
	allowToken := h.allowToken
	h.tokenMu.RUnlock()

	// We need the body twice: once for BRC-104 canonical-bytes signing
	// (over the raw bytes) and once for JSON decoding. Read it fully
	// up front and substitute a bytes.Reader for json.NewDecoder.
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	hasBRC104 := r.Header.Get(HeaderBRC104Signature) != "" ||
		r.Header.Get(HeaderBRC104Identity) != ""
	switch {
	case verifier != nil && hasBRC104:
		// BRC-104 path: any presented BRC-104 header MUST verify.
		// Falling back to the token path on a BRC-104 failure would
		// let an attacker downgrade the auth.
		in := CallbackAuthInputs{
			IdentityHex:  r.Header.Get(HeaderBRC104Identity),
			NonceHex:     r.Header.Get(HeaderBRC104Nonce),
			TimestampStr: r.Header.Get(HeaderBRC104Timestamp),
			SignatureHex: r.Header.Get(HeaderBRC104Signature),
			VersionStr:   r.Header.Get(HeaderBRC104Version),
			Body:         body,
		}
		if _, err := verifier.VerifyCallback(in); err != nil {
			http.Error(w, "unauthorized: "+err.Error(), http.StatusUnauthorized)
			return
		}
	case verifier != nil && !allowToken:
		// BRC-104 required and no headers presented.
		http.Error(w, "unauthorized: BRC-104 required", http.StatusUnauthorized)
		return
	case len(tokens) > 0:
		got := r.Header.Get("X-CallbackToken")
		if got == "" {
			got = r.Header.Get("X-ARC-Callback-Token")
		}
		if !tokenAccepted(got, tokens) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
	}

	var payload CallbackPayload
	if err := json.NewDecoder(bytes.NewReader(body)).Decode(&payload); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	ev, err := payload.toEvent()
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if consumer != nil {
		consumer(ev)
	}
	w.WriteHeader(http.StatusNoContent)
}

func tokenAccepted(got string, tokens []string) bool {
	got = strings.TrimSpace(got)
	if got == "" {
		return false
	}
	for _, t := range tokens {
		if subtle.ConstantTimeCompare([]byte(got), []byte(t)) == 1 {
			return true
		}
	}
	return false
}

func (p CallbackPayload) toEvent() (*CallbackEvent, error) {
	if p.TxID == "" {
		return nil, errors.New("arc: callback missing txid")
	}
	ev := &CallbackEvent{
		Status:      p.TxStatus,
		BlockHeight: p.BlockHeight,
		ExtraInfo:   p.ExtraInfo,
		ReceivedAt:  time.Now().UTC(),
	}
	if err := decodeHashBE(p.TxID, &ev.TxID); err != nil {
		return nil, err
	}
	if p.BlockHash != "" {
		if err := decodeHashBE(p.BlockHash, &ev.BlockHash); err != nil {
			return nil, err
		}
	}
	if p.MerklePath != "" {
		raw, err := decodeHexBytes(p.MerklePath)
		if err != nil {
			return nil, err
		}
		ev.MerklePath = raw
	}
	for _, c := range p.CompetingTxs {
		var h [32]byte
		if err := decodeHashBE(c, &h); err == nil {
			ev.CompetingTxs = append(ev.CompetingTxs, h)
		}
	}
	return ev, nil
}

func decodeHexBytes(s string) ([]byte, error) {
	s = strings.TrimPrefix(s, "0x")
	if len(s)%2 != 0 {
		return nil, errors.New("arc: odd-length hex")
	}
	out := make([]byte, len(s)/2)
	for i := 0; i < len(out); i++ {
		hi, err := hexNibble(s[2*i])
		if err != nil {
			return nil, err
		}
		lo, err := hexNibble(s[2*i+1])
		if err != nil {
			return nil, err
		}
		out[i] = hi<<4 | lo
	}
	return out, nil
}

func hexNibble(c byte) (byte, error) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', nil
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, nil
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, nil
	default:
		return 0, errors.New("arc: bad hex char")
	}
}
