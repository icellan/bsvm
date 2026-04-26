package rpc

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"

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

func (b *BEEFEndpoints) handleCovenantChain(w http.ResponseWriter, r *http.Request) {
	b.handle(w, r, b.cfg.CovenantConsumer, "covenant-chain", true)
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
