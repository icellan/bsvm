package arc

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
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
// against a shared token, parsed into a CallbackEvent, and delivered to
// the registered consumer (typically the overlay's ARC consumer that
// upgrades the matching BEEF and gossips it).
type CallbackHandler struct {
	tokens   []string
	consumer func(*CallbackEvent)
	tokenMu  sync.RWMutex
}

// NewCallbackHandler constructs a CallbackHandler. tokens contains
// one or more shared secrets that ARC must present via the
// X-CallbackToken header; multiple tokens are supported so operators
// can rotate without downtime. Pass an empty slice to disable auth
// (NOT recommended outside dev). consumer is invoked synchronously
// for every accepted callback; pass nil to drop events.
func NewCallbackHandler(tokens []string, consumer func(*CallbackEvent)) *CallbackHandler {
	cleaned := make([]string, 0, len(tokens))
	for _, t := range tokens {
		t = strings.TrimSpace(t)
		if t != "" {
			cleaned = append(cleaned, t)
		}
	}
	return &CallbackHandler{tokens: cleaned, consumer: consumer}
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
	h.tokenMu.RUnlock()

	if len(tokens) > 0 {
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
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
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
