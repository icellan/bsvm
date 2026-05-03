// governance/broadcaster.go — at-threshold BSV broadcast for the
// governance proposal workflow.
//
// Background
// ----------
// Spec 15 §"Multisig governance actions" mandates that, when a
// proposal collects M-of-N signatures, the overlay node broadcasts
// the corresponding BSV transaction. Until WW-governance-broadcast-
// onready landed, the OnReady callback in cmd/bsvm/main.go was log-
// only — operators expecting freeze/unfreeze/upgrade actions to take
// effect at threshold saw nothing happen. This file is the broadcast
// half of the closure: callers wire a Broadcaster up to the workflow
// via Workflow.OnReady(b.OnReady) and the threshold-event path now
// reaches ARC.
//
// What ships
// ----------
// Freeze and unfreeze proposals are fully wired here:
//
//   - Look up the live covenant UTXO + locking script via
//     CovenantStateReader (a narrow interface implemented by
//     pkg/covenant.CovenantManager) so the spend binds to the
//     freshest tip.
//   - Decode the threshold-many DER signatures off the proposal.
//   - Assemble the unlock script via covenant.BuildFreezeUnlockScript
//     / BuildUnfreezeUnlockScript.
//   - Build a 1-input/1-output BSV transaction continuing the
//     covenant under its existing locking script (freeze/unfreeze
//     only flip the on-chain `frozen` byte; the script bytes stay
//     identical).
//   - Broadcast via the supplied arc.ARCClient.
//
// Upgrade proposals are NOT broadcast from this path today. The
// proposal payload as defined in spec 15 only carries the new
// covenant script hex — it does NOT carry the SP1 proof bundle
// (publicValues / batchData / proofBlob), the current state root, or
// the canonical ANF document hash that BuildUpgradeUnlockScript
// requires. Adding those fields to the gossip wire format is
// invasive and out of scope here. The deferred path is tracked under
// WW-governance-payload-extension; see the godoc on
// onReadyUpgrade below.
//
// Failure semantics
// -----------------
// An ARC broadcast failure is logged at WARN and surfaced through
// BroadcastResult so the operator can retry from the workflow
// surface. The proposal stays in the workflow's store (we never
// stamp BroadcastTxID on failure) so a subsequent restart-or-re-sign
// can re-attempt without re-collecting signatures.
package governance

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/icellan/bsvm/pkg/arc"
	"github.com/icellan/bsvm/pkg/covenant"
	"github.com/icellan/bsvm/pkg/types"
)

// CovenantStateReader is the minimal slice of pkg/covenant.CovenantManager
// the broadcaster needs to assemble a spend tx. Defining this as a
// narrow interface keeps the governance package free of a hard
// dependency on the full manager type and makes the broadcaster
// trivially mockable in tests.
type CovenantStateReader interface {
	// CurrentTxID returns the live covenant UTXO transaction ID.
	CurrentTxID() types.Hash
	// CurrentVout returns the live covenant UTXO output index.
	CurrentVout() uint32
	// Covenant returns the compiled covenant artefact whose
	// LockingScript is reused as the continuation output for
	// freeze/unfreeze (script bytes don't change across those
	// actions). May return nil before the covenant has been
	// compiled — broadcaster surfaces a clear error in that case.
	Covenant() *covenant.CompiledCovenant
	// GovernanceConfig returns the shard's compiled-in governance
	// shape (mode + threshold + keys). The broadcaster uses this to
	// pick the right contract method name.
	GovernanceConfig() covenant.GovernanceConfig
}

// CovenantUTXOReader extends CovenantStateReader with the satoshi
// value carried by the live UTXO. The covenant manager exposes this
// indirectly (currentSats is unexported); the broadcaster receives it
// via this optional surface and falls back to a configured default
// otherwise.
type CovenantUTXOReader interface {
	CurrentSats() uint64
}

// SpendTxBuilder is the dependency-injection seam for the
// 1-input/1-output BSV transaction the broadcaster assembles. The
// production wire is deploy/covenant.BuildUpgradeSpendTx (which is
// reused for freeze/unfreeze because the continuation output shape
// is identical: same satoshi value, locking-script chosen by the
// caller). Tests inject a stub that captures the inputs without
// touching the BSV-SDK transaction encoder.
type SpendTxBuilder func(
	covenantTxID string,
	covenantVout uint32,
	covenantSatsLive uint64,
	continuationLockingScript []byte,
	unlockBytes []byte,
) (txHex string, txID string, err error)

// BroadcastResult is the post-broadcast summary the broadcaster
// surfaces. ARC failures populate Err and leave TxID empty; success
// populates TxID and BroadcastedAt.
type BroadcastResult struct {
	ProposalID    string
	Action        Action
	TxID          string
	TxHex         string
	BroadcastedAt time.Time
	Err           error
}

// Broadcaster drives the threshold-broadcast for governance
// proposals. Construct via NewBroadcaster and register the OnReady
// method on a workflow.
type Broadcaster struct {
	arc           arc.ARCClient
	state         CovenantStateReader
	spendBuilder  SpendTxBuilder
	defaultSats   uint64
	broadcastCtx  func() (context.Context, context.CancelFunc)
	logger        *slog.Logger

	// Subscribers receive every BroadcastResult (success or failure).
	// Used by the admin RPC layer to surface broadcast outcomes back
	// to operator dashboards.
	mu          sync.Mutex
	subscribers []func(BroadcastResult)
}

// BroadcasterConfig packages the broadcaster's dependencies. All
// fields are required EXCEPT Logger and BroadcastTimeout, which fall
// back to slog.Default and 60s respectively.
type BroadcasterConfig struct {
	// ARC is the broadcast client. Nil disables the broadcaster
	// entirely — OnReady becomes a no-op (with a WARN) so a
	// misconfigured operator gets a loud signal rather than a silent
	// drop.
	ARC arc.ARCClient

	// State exposes the live covenant tip + locking script the
	// broadcaster spends.
	State CovenantStateReader

	// SpendBuilder constructs the BSV transaction. Required.
	SpendBuilder SpendTxBuilder

	// DefaultSats is the satoshi value used for the continuation
	// output when State does not implement CovenantUTXOReader. Pass
	// covenant.DefaultCovenantSats from the boot path.
	DefaultSats uint64

	// BroadcastTimeout caps each ARC.Broadcast call. Defaults to 60s.
	BroadcastTimeout time.Duration

	// Logger is the structured logger. Defaults to slog.Default.
	Logger *slog.Logger
}

// NewBroadcaster constructs a Broadcaster. Returns an error when
// any required dependency is nil.
func NewBroadcaster(cfg BroadcasterConfig) (*Broadcaster, error) {
	if cfg.State == nil {
		return nil, errors.New("broadcaster: State is required")
	}
	if cfg.SpendBuilder == nil {
		return nil, errors.New("broadcaster: SpendBuilder is required")
	}
	timeout := cfg.BroadcastTimeout
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &Broadcaster{
		arc:          cfg.ARC,
		state:        cfg.State,
		spendBuilder: cfg.SpendBuilder,
		defaultSats:  cfg.DefaultSats,
		broadcastCtx: func() (context.Context, context.CancelFunc) {
			return context.WithTimeout(context.Background(), timeout)
		},
		logger: logger,
	}, nil
}

// Subscribe registers a callback invoked with every BroadcastResult.
// Used by the admin RPC layer to surface broadcast outcomes.
func (b *Broadcaster) Subscribe(cb func(BroadcastResult)) {
	if cb == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.subscribers = append(b.subscribers, cb)
}

// OnReady is the workflow.OnReady-compatible callback. Dispatches
// to the freeze / unfreeze / upgrade handler based on p.Action.
func (b *Broadcaster) OnReady(p *Proposal) {
	if p == nil {
		return
	}
	if p.BroadcastTxID != "" {
		// Already broadcast — defensive guard against double-fire.
		// The workflow itself only fires OnReady once per crossing,
		// but a re-stored proposal could re-trigger after restart.
		return
	}
	if b.arc == nil {
		b.logger.Warn("governance broadcaster: ARC client not configured — proposal at threshold but no broadcast will happen",
			"id", p.ID, "action", p.Action,
			"signatures", len(p.Signatures), "required", p.Required)
		return
	}
	switch p.Action {
	case ActionFreeze, ActionUnfreeze:
		b.dispatchFreezeUnfreeze(p)
	case ActionUpgrade:
		b.dispatchUpgrade(p)
	default:
		b.logger.Warn("governance broadcaster: unknown action — no broadcast",
			"id", p.ID, "action", p.Action)
	}
}

// dispatchFreezeUnfreeze handles freeze + unfreeze proposals — both
// take only governance signatures as inputs and re-use the live
// covenant locking script as the continuation output.
func (b *Broadcaster) dispatchFreezeUnfreeze(p *Proposal) {
	gov := b.state.GovernanceConfig()
	cov := b.state.Covenant()
	if cov == nil || len(cov.LockingScript) == 0 {
		b.publish(BroadcastResult{
			ProposalID: p.ID,
			Action:     p.Action,
			Err:        errors.New("compiled covenant unavailable — node started without covenant.anf.json"),
		})
		return
	}

	sigs, err := decodeProposalSigsForGov(p, gov)
	if err != nil {
		b.publish(BroadcastResult{ProposalID: p.ID, Action: p.Action, Err: err})
		return
	}

	var unlock []byte
	switch p.Action {
	case ActionFreeze:
		unlock, err = covenant.BuildFreezeUnlockScript(sigs, gov)
	case ActionUnfreeze:
		unlock, err = covenant.BuildUnfreezeUnlockScript(sigs, gov)
	}
	if err != nil {
		b.publish(BroadcastResult{ProposalID: p.ID, Action: p.Action, Err: fmt.Errorf("build unlock script: %w", err)})
		return
	}

	b.assembleAndBroadcast(p, cov.LockingScript, unlock)
}

// dispatchUpgrade is the deferred upgrade path. Today the proposal
// payload (Proposal.Params) does NOT carry the SP1 proof bundle that
// BuildUpgradeUnlockScript requires. Until the gossip wire format is
// extended (tracked as WW-governance-payload-extension), upgrade
// proposals at threshold log a WARN and surface a typed error to
// subscribers — the operator can fall back to the rotate-vk binary
// for upgrades.
func (b *Broadcaster) dispatchUpgrade(p *Proposal) {
	err := errors.New(
		"upgrade proposal at threshold but the gossip wire format does not yet carry the SP1 proof bundle " +
			"(publicValues/batchData/proofBlob) needed for BuildUpgradeUnlockScript. " +
			"Fall back to deploy/covenant/rotate-vk for upgrades, or extend the proposal payload " +
			"(tracked as WW-governance-payload-extension).",
	)
	b.logger.Warn("governance broadcaster: upgrade path not wired",
		"id", p.ID, "action", p.Action, "err", err)
	b.publish(BroadcastResult{ProposalID: p.ID, Action: p.Action, Err: err})
}

// assembleAndBroadcast builds the spend tx + dispatches to ARC.
// Shared by all action paths so failure semantics stay uniform.
func (b *Broadcaster) assembleAndBroadcast(p *Proposal, continuationLockingScript, unlock []byte) {
	sats := b.defaultSats
	if u, ok := b.state.(CovenantUTXOReader); ok {
		if v := u.CurrentSats(); v > 0 {
			sats = v
		}
	}

	covTxID := b.state.CurrentTxID()
	covVout := b.state.CurrentVout()
	if isZeroHash(covTxID) {
		b.publish(BroadcastResult{
			ProposalID: p.ID,
			Action:     p.Action,
			Err:        errors.New("covenant manager has no current tip txid — has the node finished syncing?"),
		})
		return
	}

	txHex, predictedTxID, err := b.spendBuilder(
		covTxID.BSVString(),
		covVout,
		sats,
		continuationLockingScript,
		unlock,
	)
	if err != nil {
		b.publish(BroadcastResult{ProposalID: p.ID, Action: p.Action, Err: fmt.Errorf("build spend tx: %w", err)})
		return
	}

	rawBytes, err := hex.DecodeString(txHex)
	if err != nil {
		b.publish(BroadcastResult{
			ProposalID: p.ID, Action: p.Action, TxHex: txHex,
			Err: fmt.Errorf("decode tx hex: %w", err),
		})
		return
	}

	ctx, cancel := b.broadcastCtx()
	defer cancel()
	resp, err := b.arc.Broadcast(ctx, rawBytes)
	if err != nil {
		b.logger.Warn("governance broadcaster: ARC broadcast failed",
			"id", p.ID, "action", p.Action,
			"predicted_txid", predictedTxID,
			"err", err)
		b.publish(BroadcastResult{
			ProposalID: p.ID, Action: p.Action, TxHex: txHex,
			TxID: predictedTxID, Err: err,
		})
		return
	}

	actualTxID := hex.EncodeToString(resp.TxID[:])
	if actualTxID == "" {
		actualTxID = predictedTxID
	}
	b.logger.Info("governance broadcaster: ARC broadcast accepted",
		"id", p.ID, "action", p.Action,
		"txid", actualTxID, "status", string(resp.Status))
	b.publish(BroadcastResult{
		ProposalID:    p.ID,
		Action:        p.Action,
		TxID:          actualTxID,
		TxHex:         txHex,
		BroadcastedAt: time.Now().UTC(),
	})
}

// publish fans the result out to every subscribed callback.
func (b *Broadcaster) publish(r BroadcastResult) {
	b.mu.Lock()
	subs := append([]func(BroadcastResult){}, b.subscribers...)
	b.mu.Unlock()
	for _, cb := range subs {
		cb(r)
	}
}

// decodeProposalSigsForGov pulls the threshold-many governance
// signatures off the proposal. Order is determined by walking the
// shard's GovernanceConfig.Keys list — the on-chain CheckMultiSig
// expects sigs in key-list order. Returns an error when fewer sigs
// than the on-chain method requires are present (which Workflow
// guarantees should not happen, but the broadcaster guards anyway).
func decodeProposalSigsForGov(p *Proposal, gov covenant.GovernanceConfig) ([][]byte, error) {
	want := 0
	switch gov.Mode {
	case covenant.GovernanceSingleKey:
		want = 1
	case covenant.GovernanceMultiSig:
		want = gov.Threshold
	default:
		return nil, fmt.Errorf("governance mode %v has no broadcast path", gov.Mode)
	}

	out := make([][]byte, 0, want)
	for _, k := range gov.Keys {
		hexKey := hex.EncodeToString(k)
		sigHex, ok := p.Signatures[hexKey]
		if !ok {
			continue
		}
		raw, err := hex.DecodeString(sigHex)
		if err != nil {
			return nil, fmt.Errorf("signature for key %s: %w", hexKey[:16], err)
		}
		out = append(out, raw)
		if len(out) == want {
			break
		}
	}
	if len(out) < want {
		return nil, fmt.Errorf("expected %d governance signature(s), found %d in proposal (signatures present: %d)",
			want, len(out), len(p.Signatures))
	}
	return out, nil
}

// isZeroHash reports whether h is the all-zeros sentinel.
func isZeroHash(h types.Hash) bool {
	for _, b := range h {
		if b != 0 {
			return false
		}
	}
	return true
}
