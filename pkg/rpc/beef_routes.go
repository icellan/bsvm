package rpc

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/icellan/bsvm/pkg/arc"
	"github.com/icellan/bsvm/pkg/beef"
	"github.com/icellan/bsvm/pkg/metrics"
)

// BEEFEndpointConfig wires the BEEF gossip endpoints into the RPC
// server. Each handler field is optional: if nil, the corresponding
// endpoint accepts and stores the envelope but does not dispatch to a
// downstream consumer. This lets the spec-17 receive path light up
// before every consumer is wired.
type BEEFEndpointConfig struct {
	// Store is the BEEFStore to which accepted envelopes are written.
	// Required; if nil, the endpoints return 503.
	Store beef.Store
	// ShardID is the shard ID this node serves. Envelopes whose
	// shard-bound flag is set and whose ShardID does not match are
	// rejected. Zero is permitted (and treated as "match-any") for
	// devnet harnesses.
	ShardID uint64
	// Metrics is an optional NetworkMetrics for receive/reject
	// counters. May be nil.
	Metrics *metrics.NetworkMetrics
	// CovenantConsumer receives covenant-advance envelopes
	// (intents 0x01 + 0x02). Optional.
	CovenantConsumer func(*beef.Envelope)
	// BridgeConsumer receives bridge-deposit envelopes (intent 0x03).
	BridgeConsumer func(*beef.Envelope)
	// FeeWalletConsumer receives fee-wallet-funding envelopes (0x04).
	FeeWalletConsumer func(*beef.Envelope)
	// InboxConsumer receives inbox-submission envelopes (0x05).
	InboxConsumer func(*beef.Envelope)
	// GovernanceConsumer receives governance-action envelopes (0x06).
	GovernanceConsumer func(*beef.Envelope)
	// ARCCallback is the optional ARC callback handler mounted at
	// /bsv/arc/callback. May be nil to disable the callback path.
	ARCCallback http.Handler
}

// BEEFEndpoints exposes the spec-17 BEEF gossip + ARC callback HTTP
// surface. Constructed by NewBEEFEndpoints and mounted by
// RPCServer.SetBEEFEndpoints.
type BEEFEndpoints struct {
	cfg BEEFEndpointConfig
}

// NewBEEFEndpoints constructs a BEEFEndpoints from cfg.
func NewBEEFEndpoints(cfg BEEFEndpointConfig) *BEEFEndpoints {
	return &BEEFEndpoints{cfg: cfg}
}

// Mount registers every spec-17 HTTP endpoint on mux at the
// canonical paths.
func (b *BEEFEndpoints) Mount(mux *http.ServeMux) {
	mux.HandleFunc("/bsvm/beef/covenant-chain", b.handleCovenantChain)
	mux.HandleFunc("/bsvm/bridge/deposit", b.handleBridgeDeposit)
	mux.HandleFunc("/bsvm/inbox/submission", b.handleInbox)
	mux.HandleFunc("/bsvm/governance/action", b.handleGovernance)
	if b.cfg.ARCCallback != nil {
		mux.Handle("/bsv/arc/callback", b.cfg.ARCCallback)
	}
}

// maxBEEFRequestSize caps the size of a BEEF gossip POST body. 10 MB
// covers covenant-advance BEEFs that include the Mode 1 covenant
// script ancestor (~1 MB) plus a generous BUMP and frontier set.
const maxBEEFRequestSize = 10 * 1024 * 1024

// covenantChainCatchUpDefaultLimit is the default value of the `limit`
// query parameter on GET /bsvm/beef/covenant-chain when the client
// omits it. Picked to bound a single response to a few MB of BEEFs in
// practice while remaining useful for steady-state catch-up.
const covenantChainCatchUpDefaultLimit = 100

// covenantChainCatchUpMaxLimit is the hard cap on the `limit` query
// parameter on GET /bsvm/beef/covenant-chain. Requests exceeding this
// are rejected with 400 so peers can't induce unbounded server work.
// See docs/decisions/W6-beef-covenant-chain-get.md.
const covenantChainCatchUpMaxLimit = 500

// handleCovenantChain dispatches the spec-17 §949 covenant-chain
// endpoint based on HTTP method:
//   - GET serves the catch-up stream
//     (`?from=<txid>&limit=<n>` → length-prefixed BEEF envelopes,
//     oldest first, strictly after `from`).
//   - POST is the existing gossip-receive path (intent 0x01/0x02
//     covenant-advance envelopes).
//
// TODO(spec-17): once spec 17 §949 is updated to pin the wire format,
// drop this comment in favour of a spec reference. The format is
// captured in docs/decisions/W6-beef-covenant-chain-get.md.
func (b *BEEFEndpoints) handleCovenantChain(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		b.handleCovenantChainCatchUp(w, r)
	case http.MethodPost:
		b.handle(w, r, b.cfg.CovenantConsumer, "covenant-chain", true)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleCovenantChainCatchUp serves the spec-17 §949 GET endpoint that
// lets a follower bootstrap by pulling confirmed covenant-advance
// BEEFs from a peer. Wire format:
//
//	GET /bsvm/beef/covenant-chain?from=<txid>&limit=<n>
//	Response 200 OK, Content-Type: application/octet-stream
//	Body: repeated <u32 BE length><envelope bytes>, oldest first,
//	      strictly after the envelope identified by `from`.
//
// Errors:
//   - missing `from`     → 400 "from query param required"
//   - malformed `from`   → 400 "from must be 32-byte hex txid"
//   - unknown `from`     → 404 "from txid not found"
//   - oversized `limit`  → 400 "limit must be 1..500"
//
// Only IntentCovenantAdvanceConfirmed envelopes are returned;
// unconfirmed advances have no SPV proof yet so a fresh follower
// cannot validate them, per spec 17 §"Bootstrap".
//
// The all-zero `from` txid is accepted as the "genesis" cursor and
// returns every confirmed covenant-advance envelope from the start.
func (b *BEEFEndpoints) handleCovenantChainCatchUp(w http.ResponseWriter, r *http.Request) {
	if b.cfg.Store == nil {
		http.Error(w, "beef store unavailable", http.StatusServiceUnavailable)
		return
	}
	q := r.URL.Query()
	fromRaw := strings.TrimSpace(q.Get("from"))
	if fromRaw == "" {
		http.Error(w, "from query param required", http.StatusBadRequest)
		return
	}
	fromTxID, ok := parseTxIDHex(fromRaw)
	if !ok {
		http.Error(w, "from must be 32-byte hex txid", http.StatusBadRequest)
		return
	}
	limit := covenantChainCatchUpDefaultLimit
	if raw := strings.TrimSpace(q.Get("limit")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > covenantChainCatchUpMaxLimit {
			http.Error(w,
				fmt.Sprintf("limit must be 1..%d", covenantChainCatchUpMaxLimit),
				http.StatusBadRequest)
			return
		}
		limit = parsed
	}
	// Buffer the framed body in memory before writing. Keeps the
	// 200/404 distinction clean: if the cursor is unknown we emit a
	// 404 *without* having sent any bytes yet. The buffer is bounded
	// by limit (max 500) * envelope-size, well below the 10 MB
	// gossip cap a peer is already willing to accept.
	body := make([]byte, 0)
	count := 0
	found, err := b.cfg.Store.IterateSince(
		beef.IntentCovenantAdvanceConfirmed,
		fromTxID,
		limit,
		func(env *beef.Envelope) bool {
			encoded, encErr := beef.EncodeEnvelope(env.Header, env.Beef)
			if encErr != nil {
				slog.Warn("beef catch-up: skip unencodable envelope",
					"txid", hex.EncodeToString(env.TargetTxID[:]),
					"err", encErr)
				return true
			}
			var lenBuf [4]byte
			binary.BigEndian.PutUint32(lenBuf[:], uint32(len(encoded)))
			body = append(body, lenBuf[:]...)
			body = append(body, encoded...)
			count++
			return true
		},
	)
	if err != nil {
		slog.Error("beef catch-up: store error", "err", err)
		http.Error(w, "store error", http.StatusInternalServerError)
		return
	}
	if !found {
		http.Error(w, "from txid not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(http.StatusOK)
	if _, werr := w.Write(body); werr != nil {
		slog.Warn("beef catch-up: write failed", "err", werr)
		return
	}
	slog.Debug("beef catch-up served",
		"from", hex.EncodeToString(fromTxID[:]),
		"limit", limit,
		"returned", count,
		"bytes", len(body),
	)
}

// parseTxIDHex parses a 32-byte hex txid (with or without 0x prefix).
// Returns the decoded bytes and true on success.
func parseTxIDHex(s string) ([32]byte, bool) {
	var out [32]byte
	s = strings.TrimPrefix(s, "0x")
	s = strings.TrimPrefix(s, "0X")
	if len(s) != 64 {
		return out, false
	}
	decoded, err := hex.DecodeString(s)
	if err != nil {
		return out, false
	}
	copy(out[:], decoded)
	return out, true
}

func (b *BEEFEndpoints) handleBridgeDeposit(w http.ResponseWriter, r *http.Request) {
	b.handle(w, r, b.cfg.BridgeConsumer, "bridge-deposit", true)
}

func (b *BEEFEndpoints) handleInbox(w http.ResponseWriter, r *http.Request) {
	b.handle(w, r, b.cfg.InboxConsumer, "inbox-submission", true)
}

func (b *BEEFEndpoints) handleGovernance(w http.ResponseWriter, r *http.Request) {
	b.handle(w, r, b.cfg.GovernanceConsumer, "governance-action", true)
}

func (b *BEEFEndpoints) handle(
	w http.ResponseWriter,
	r *http.Request,
	consumer func(*beef.Envelope),
	endpoint string,
	requireShardBound bool,
) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if b.cfg.Store == nil {
		http.Error(w, "beef store unavailable", http.StatusServiceUnavailable)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBEEFRequestSize))
	if err != nil {
		b.recordReject(0, "read-error")
		http.Error(w, "failed to read body", http.StatusBadRequest)
		return
	}
	hdr, beefBody, err := beef.DecodeEnvelopeHeader(body)
	if err != nil {
		b.recordReject(0, "malformed-envelope")
		http.Error(w, fmt.Sprintf("malformed envelope: %v", err), http.StatusBadRequest)
		return
	}
	if requireShardBound && !hdr.ShardBound() {
		b.recordReject(hdr.Intent, "shard-bound-required")
		http.Error(w, "shard binding required", http.StatusBadRequest)
		return
	}
	if hdr.ShardBound() && b.cfg.ShardID != 0 && hdr.ShardID != b.cfg.ShardID {
		b.recordReject(hdr.Intent, "wrong-shard")
		http.Error(w, "wrong shard", http.StatusBadRequest)
		return
	}
	parsed, err := beef.ParseBEEF(beefBody)
	if err != nil {
		b.recordReject(hdr.Intent, "malformed-beef")
		http.Error(w, fmt.Sprintf("malformed beef: %v", err), http.StatusBadRequest)
		return
	}
	target := parsed.Target()
	if target == nil {
		b.recordReject(hdr.Intent, "no-target")
		http.Error(w, "beef has no target tx", http.StatusBadRequest)
		return
	}
	env := &beef.Envelope{
		Header:     hdr,
		Beef:       beefBody,
		TargetTxID: target.TxID,
	}
	if hdr.Intent == beef.IntentCovenantAdvanceConfirmed ||
		hdr.Intent == beef.IntentBridgeDeposit ||
		hdr.Intent == beef.IntentFeeWalletFunding ||
		hdr.Intent == beef.IntentGovernanceAction {
		env.Confirmed = target.HasBUMP
	}
	if err := b.cfg.Store.Put(env); err != nil {
		b.recordReject(hdr.Intent, "store-error")
		http.Error(w, "store error", http.StatusInternalServerError)
		return
	}
	b.recordAccept(hdr.Intent)
	if consumer != nil {
		consumer(env)
	}
	slog.Debug("beef envelope accepted",
		"endpoint", endpoint,
		"intent", beef.IntentName(hdr.Intent),
		"shardID", hdr.ShardID,
		"size", len(body),
	)
	w.WriteHeader(http.StatusNoContent)
}

func (b *BEEFEndpoints) recordAccept(intent byte) {
	if b.cfg.Metrics == nil {
		return
	}
	b.cfg.Metrics.RecordBEEFAccepted(intent)
}

func (b *BEEFEndpoints) recordReject(intent byte, reason string) {
	if b.cfg.Metrics == nil {
		return
	}
	b.cfg.Metrics.RecordBEEFRejected(intent, reason)
}

// SetBEEFEndpoints attaches the spec-17 BEEF gossip + ARC callback
// HTTP surface. Must be called before Start(). Passing nil unmounts
// any previously-attached endpoints.
func (s *RPCServer) SetBEEFEndpoints(b *BEEFEndpoints) {
	s.beefEndpoints = b
}

// ARCBroadcastClient is the optional ARC client used by RPC handlers
// that need to broadcast on behalf of an authenticated admin call.
// SCAFFOLD: not yet wired into the JSON-RPC dispatch surface.
type ARCBroadcastClient = arc.ARCClient

// errBEEFEndpointDisabled is returned when an HTTP-layer caller asks
// for a BEEF endpoint that has not been wired.
var errBEEFEndpointDisabled = errors.New("rpc: beef endpoints not configured")
