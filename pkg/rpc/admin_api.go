package rpc

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"github.com/icellan/bsvm/pkg/governance"
	"github.com/icellan/bsvm/pkg/overlay"
	"github.com/icellan/bsvm/pkg/rpc/auth"
)

// AdminAPI implements the admin_* JSON-RPC namespace described in
// spec 15. Handlers mounted here are reachable only through the
// /admin/rpc endpoint which sits behind the auth middleware — see
// RPCServer.Start.
//
// Design:
//
//   - This struct intentionally holds no state beyond handles to
//     other subsystems. Each handler dispatches directly to the
//     corresponding prover / batcher / bridge call, so the auth layer
//     remains the only security boundary.
//
//   - Governance proposal methods (create / list / sign) route
//     through a governance.Workflow so their replication across
//     peers is the same workflow used by direct gossip. When the
//     workflow is nil (single-node or tests) the handlers return a
//     clear error so the UI doesn't silently lose writes.
type AdminAPI struct {
	overlay    overlayAdminAccessor
	governance *governance.Workflow
	// governanceThreshold is the M-of-N value from the shard
	// config. admin_createGovernanceProposal writes it into the new
	// proposal so signers know how many signatures are required.
	governanceThreshold int
}

// SetGovernanceWorkflow installs the governance workflow that
// backs admin_{create,list,sign}GovernanceProposal. When not
// configured, governance RPC returns "not configured" errors.
func (a *AdminAPI) SetGovernanceWorkflow(w *governance.Workflow, threshold int) {
	a.governance = w
	a.governanceThreshold = threshold
}

// overlayAdminAccessor is the minimum slice of OverlayNode that the
// admin namespace touches. Defining it as an interface (rather than a
// concrete *overlay.OverlayNode) lets tests inject lightweight mocks
// without constructing a full node.
type overlayAdminAccessor interface {
	BatcherPause()
	BatcherResume()
	BatcherIsPaused() bool
	BatcherPendingCount() int
	BatcherForceFlush() error

	ProverMetrics() (mode string, workers, inFlight, queueDepth int, proofsStarted, proofsSucceeded, proofsFailed, avgMs uint64)
	PeerSummary() []overlay.RPCPeerSummary

	RuntimeConfig() overlay.RuntimeConfigView
}

// NewAdminAPI constructs an AdminAPI bound to the given overlay
// accessor.
func NewAdminAPI(ov overlayAdminAccessor) *AdminAPI {
	return &AdminAPI{overlay: ov}
}

// --- admin_peerList ----------------------------------------------------

// PeerList implements admin_peerList.
func (a *AdminAPI) PeerList() []overlay.RPCPeerSummary {
	return a.overlay.PeerSummary()
}

// --- admin_getConfig / admin_setConfig --------------------------------

// GetConfig implements admin_getConfig. Returns the live RuntimeConfigView.
func (a *AdminAPI) GetConfig() overlay.RuntimeConfigView {
	return a.overlay.RuntimeConfig()
}

// SetConfig implements admin_setConfig. Until live-reload lands for
// individual settings, this handler accepts the request but always
// returns an error indicating a restart is required. The explorer UI
// relies on the `restartRequired` field of GetConfig() to guide the
// operator.
func (a *AdminAPI) SetConfig(key string, value json.RawMessage) (map[string]interface{}, error) {
	return nil, fmt.Errorf("admin_setConfig: live reload not yet implemented (restart required to change %q)", key)
}

// --- admin_pauseProving / admin_resumeProving / admin_forceFlushBatch --

// PauseProving implements admin_pauseProving. It pauses the batcher —
// new transactions are rejected with a clear error — and returns the
// number of pending transactions at the moment of the pause.
func (a *AdminAPI) PauseProving() map[string]interface{} {
	a.overlay.BatcherPause()
	return map[string]interface{}{
		"success":        true,
		"pending":        a.overlay.BatcherPendingCount(),
		"batcherPaused":  true,
	}
}

// ResumeProving implements admin_resumeProving.
func (a *AdminAPI) ResumeProving() map[string]interface{} {
	a.overlay.BatcherResume()
	return map[string]interface{}{
		"success":       true,
		"batcherPaused": false,
	}
}

// ForceFlushBatch implements admin_forceFlushBatch — flushes the
// current pending batch without waiting for the timer or size
// threshold. Useful for local testing and for operators nudging the
// proving loop after a pause.
func (a *AdminAPI) ForceFlushBatch() (map[string]interface{}, error) {
	pending := a.overlay.BatcherPendingCount()
	if err := a.overlay.BatcherForceFlush(); err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"success":   true,
		"batchSize": pending,
	}, nil
}

// --- governance proposal handlers ------------------------------------

// CreateGovernanceProposal creates a new proposal and gossips it to
// peers. Returns the initial proposal state. When the shard is
// single_key-governed the caller can follow up with a direct sign +
// broadcast; multisig shards expect other governance keys to sign
// before threshold is met.
func (a *AdminAPI) CreateGovernanceProposal(action string, params json.RawMessage) (map[string]interface{}, error) {
	if a.governance == nil {
		return nil, fmt.Errorf("admin_createGovernanceProposal: governance workflow not configured on this node")
	}
	threshold := a.governanceThreshold
	if threshold < 1 {
		// GovernanceSingleKey has Threshold=0 per the covenant type;
		// treat it as one-of-one so the workflow gets a valid Required.
		threshold = 1
	}
	p, err := governance.NewProposal(governance.Action(action), params, threshold, 0)
	if err != nil {
		return nil, err
	}
	merged, err := a.governance.CreateOrMerge(p)
	if err != nil {
		return nil, err
	}
	return proposalAsMap(merged), nil
}

// ListGovernanceProposals returns the local view of the proposal
// queue. Callers rely on gossip-driven eventual consistency — two
// nodes may briefly disagree, but the content-addressed IDs and
// idempotent signature merges ensure they converge without manual
// reconciliation.
func (a *AdminAPI) ListGovernanceProposals() []map[string]interface{} {
	if a.governance == nil {
		return []map[string]interface{}{}
	}
	proposals, err := a.governance.List()
	if err != nil {
		return []map[string]interface{}{}
	}
	out := make([]map[string]interface{}, 0, len(proposals))
	for _, p := range proposals {
		out = append(out, proposalAsMap(p))
	}
	return out
}

// SignGovernanceProposal verifies a signature and records it against
// the proposal. When the signature count crosses the required
// threshold the workflow fires its readyCallback (set up in main.go
// to schedule the BSV broadcast). Returns the updated proposal
// state.
func (a *AdminAPI) SignGovernanceProposal(id string, signature string) (map[string]interface{}, error) {
	if a.governance == nil {
		return nil, fmt.Errorf("admin_signGovernanceProposal: governance workflow not configured on this node")
	}
	updated, err := a.governance.Sign(id, signature)
	if err != nil {
		return nil, err
	}
	return proposalAsMap(updated), nil
}

// proposalAsMap serialises a proposal in the explorer-friendly shape
// the admin UI consumes. Kept out of the governance package so it
// stays free of HTTP / JSON-RPC encoding concerns.
func proposalAsMap(p *governance.Proposal) map[string]interface{} {
	if p == nil {
		return map[string]interface{}{}
	}
	sigs := make([]map[string]string, 0, len(p.Signatures))
	for pub, sig := range p.Signatures {
		sigs = append(sigs, map[string]string{"pubKey": pub, "signature": sig})
	}
	return map[string]interface{}{
		"id":             p.ID,
		"action":         string(p.Action),
		"params":         json.RawMessage(p.Params),
		"required":       p.Required,
		"signatureCount": len(p.Signatures),
		"signatures":     sigs,
		"createdAt":      p.CreatedAt.UTC().Format("2006-01-02T15:04:05Z"),
		"expiresAt":      p.ExpiresAt.UTC().Format("2006-01-02T15:04:05Z"),
		"ready":          p.Ready(),
		"broadcastTxid":  p.BroadcastTxID,
	}
}

// BridgeHealth is a spec 15 stub. A real implementation calls into
// pkg/bridge once the monitor is attached to the overlay node.
func (a *AdminAPI) BridgeHealth() map[string]interface{} {
	return map[string]interface{}{
		"subCovenants":  []map[string]interface{}{},
		"mismatch":      false,
		"totalLocked":   "0",
		"totalSupply":   "0",
		"lastScanned":   0,
		"rescanPending": false,
		"note":          "bridge monitor not yet attached to overlay — returning zero state",
	}
}

// RescanDeposits is a spec 15 stub.
func (a *AdminAPI) RescanDeposits(fromHeight uint64) (map[string]interface{}, error) {
	return nil, fmt.Errorf("admin_rescanDeposits: bridge monitor not yet attached to overlay")
}

// --- HTTP handler -----------------------------------------------------

// dispatchAdmin routes parsed JSON-RPC admin_* calls to the relevant
// AdminAPI method. Unknown methods produce the standard JSON-RPC
// "method not found" error.
func (s *RPCServer) dispatchAdmin(ctx sessionContext, method string, params json.RawMessage) (interface{}, error) {
	switch method {
	case "admin_peerList":
		return s.adminAPI.PeerList(), nil

	case "admin_getConfig":
		return s.adminAPI.GetConfig(), nil

	case "admin_setConfig":
		return s.handleAdminSetConfig(params)

	case "admin_pauseProving":
		s.logAdmin(ctx, method, "")
		return s.adminAPI.PauseProving(), nil

	case "admin_resumeProving":
		s.logAdmin(ctx, method, "")
		return s.adminAPI.ResumeProving(), nil

	case "admin_forceFlushBatch":
		s.logAdmin(ctx, method, "")
		return s.adminAPI.ForceFlushBatch()

	case "admin_createGovernanceProposal":
		return s.handleAdminCreateProposal(params)

	case "admin_listGovernanceProposals":
		return s.adminAPI.ListGovernanceProposals(), nil

	case "admin_signGovernanceProposal":
		return s.handleAdminSignProposal(params)

	case "admin_bridgeHealth":
		return s.adminAPI.BridgeHealth(), nil

	case "admin_rescanDeposits":
		return s.handleAdminRescanDeposits(params)

	default:
		return nil, newRPCError(errCodeMethodNotFound, fmt.Sprintf("method %q not found", method))
	}
}

// logAdmin writes a single-line audit record per mutating admin call.
// Read-only calls (getConfig, peerList, bridgeHealth, list proposals)
// are intentionally noisy-free.
func (s *RPCServer) logAdmin(ctx sessionContext, method, extra string) {
	sess := ctx.Session
	if sess == nil {
		return
	}
	slog.Info("admin rpc",
		"method", method,
		"identity", auth.HashIdentity(sess.Identity),
		"kind", sess.Kind,
		"ip", sess.RemoteIP,
		"extra", extra,
	)
}

// sessionContext carries the authenticated session into dispatchAdmin.
// Wrapped in a struct so future additions (request ID, trace context)
// don't change the dispatcher signature.
type sessionContext struct {
	Session *auth.Session
}

// handleAdminSetConfig parses [key, value] and calls SetConfig.
func (s *RPCServer) handleAdminSetConfig(params json.RawMessage) (interface{}, error) {
	var args []json.RawMessage
	if err := json.Unmarshal(params, &args); err != nil || len(args) < 2 {
		return nil, newRPCError(errCodeInvalidParams, "expected [key, value]")
	}
	var key string
	if err := json.Unmarshal(args[0], &key); err != nil {
		return nil, newRPCError(errCodeInvalidParams, "invalid key: "+err.Error())
	}
	return s.adminAPI.SetConfig(key, args[1])
}

// handleAdminCreateProposal parses [action, params] for
// admin_createGovernanceProposal.
func (s *RPCServer) handleAdminCreateProposal(params json.RawMessage) (interface{}, error) {
	var args []json.RawMessage
	if err := json.Unmarshal(params, &args); err != nil || len(args) < 1 {
		return nil, newRPCError(errCodeInvalidParams, "expected [action, params?]")
	}
	var action string
	if err := json.Unmarshal(args[0], &action); err != nil {
		return nil, newRPCError(errCodeInvalidParams, "invalid action: "+err.Error())
	}
	var paramBytes json.RawMessage
	if len(args) >= 2 {
		paramBytes = args[1]
	} else {
		paramBytes = json.RawMessage("null")
	}
	return s.adminAPI.CreateGovernanceProposal(action, paramBytes)
}

// handleAdminSignProposal parses [proposalId, signatureHex]. Proposal
// IDs are 32-byte content hashes in hex (64 chars) — see the
// governance package.
func (s *RPCServer) handleAdminSignProposal(params json.RawMessage) (interface{}, error) {
	var args []json.RawMessage
	if err := json.Unmarshal(params, &args); err != nil || len(args) < 2 {
		return nil, newRPCError(errCodeInvalidParams, "expected [proposalId, signatureHex]")
	}
	var id string
	if err := json.Unmarshal(args[0], &id); err != nil {
		return nil, newRPCError(errCodeInvalidParams, "invalid proposalId: "+err.Error())
	}
	var sig string
	if err := json.Unmarshal(args[1], &sig); err != nil {
		return nil, newRPCError(errCodeInvalidParams, "invalid signatureHex: "+err.Error())
	}
	return s.adminAPI.SignGovernanceProposal(id, sig)
}

// handleAdminRescanDeposits parses [fromHeight].
func (s *RPCServer) handleAdminRescanDeposits(params json.RawMessage) (interface{}, error) {
	var args []json.RawMessage
	if err := json.Unmarshal(params, &args); err != nil || len(args) < 1 {
		return nil, newRPCError(errCodeInvalidParams, "expected [fromHeight]")
	}
	var heightHex string
	if err := json.Unmarshal(args[0], &heightHex); err != nil {
		return nil, newRPCError(errCodeInvalidParams, "invalid fromHeight: "+err.Error())
	}
	height, err := parseHexUint64(heightHex)
	if err != nil {
		return nil, newRPCError(errCodeInvalidParams, "invalid fromHeight: "+err.Error())
	}
	return s.adminAPI.RescanDeposits(height)
}

// handleAdminRPC is the HTTP entry point for POST /admin/rpc. It is
// reached only when the request survived the auth middleware — the
// session is guaranteed non-nil here.
func (s *RPCServer) handleAdminRPC(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, maxRequestSize))
	if err != nil {
		writeJSONResponse(w, &jsonrpcResponse{
			JSONRPC: "2.0",
			Error:   &jsonrpcError{Code: errCodeInvalidRequest, Message: "failed to read request body"},
			ID:      json.RawMessage("null"),
		})
		return
	}

	var req jsonrpcRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeJSONResponse(w, &jsonrpcResponse{
			JSONRPC: "2.0",
			Error:   &jsonrpcError{Code: errCodeInvalidRequest, Message: "invalid JSON"},
			ID:      json.RawMessage("null"),
		})
		return
	}

	if !strings.HasPrefix(req.Method, "admin_") {
		writeJSONResponse(w, &jsonrpcResponse{
			JSONRPC: "2.0",
			Error:   &jsonrpcError{Code: errCodeMethodNotFound, Message: "only admin_* methods are allowed on /admin/rpc"},
			ID:      req.ID,
		})
		return
	}

	sess := auth.FromContext(r.Context())
	result, rpcErr := s.dispatchAdmin(sessionContext{Session: sess}, req.Method, req.Params)
	resp := &jsonrpcResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
	}
	if rpcErr != nil {
		if re, ok := rpcErr.(*rpcError); ok {
			resp.Error = &jsonrpcError{Code: re.code, Message: re.message}
		} else {
			resp.Error = &jsonrpcError{Code: errCodeServerError, Message: rpcErr.Error()}
		}
	} else {
		resp.Result = result
	}
	writeJSONResponse(w, resp)
}
