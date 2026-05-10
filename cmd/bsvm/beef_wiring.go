// Spec-17 BEEF endpoint wiring for the bsvm binary. The helpers in this
// file construct the BEEFEndpoints surface (BEEFStore + per-intent
// consumer callbacks) and attach it to the JSON-RPC HTTP server so
// /bsvm/bridge/deposit, /bsvm/inbox/submission, /bsvm/governance/action
// and /bsvm/beef/covenant-chain become reachable on the daemon's listen
// port.
//
// The actual envelope parsing, shard-binding check, and store write
// live inside pkg/rpc/beef_routes.go — this file is the cmd-side glue
// that decides which consumer fires for each intent and what policy
// applies.
//
// As of W6-4 the bridge-deposit consumer runs full BRC-62 graph
// verification (ancestry against chaintracks, BUMP against confirmed
// headers, every input script re-executed) before crediting the
// bridge monitor.
//
// As of the 2026-05-03 follow-up, all four previously log-only
// consumers (inbox, governance, fee-wallet, covenant-advance) now
// dispatch to their real receivers via the per-extractor helpers in
// cmd/bsvm/beef_extractors.go:
//
//   - WW-inbox-consumer            — recovers the EVM txRLP from input
//     0's unlock script (inbox covenant
//     Submit() call) and queues it via
//     InboxMonitor.AddInboxTransaction.
//     Consumer-side dedup by target txid
//     prevents re-broadcast double-fire.
//   - WW-governance-consumer       — decodes the new CovenantState
//     from output 0, diffs Frozen against
//     the local covenant tip, and creates
//     a freeze/unfreeze proposal via
//     governance.Workflow.CreateOrMerge.
//     Workflow content-hash IDs dedup
//     across the existing
//     covenantMgr.SetStateChangeCallback
//     path. Upgrade actions still need
//     the new-script-hash extractor —
//     tracked as
//     WW-governance-upgrade-extractor.
//   - WW-fee-wallet-consumer       — walks tx outputs against the fee
//     wallet's published expected script
//     (FeeWallet.ExpectedScriptPubKey,
//     set at boot in bsv_wiring.go) and
//     credits matching outputs via the
//     idempotent FeeWallet.AddUTXO.
//   - WW-overlay-covenant-consumer — extracts the spec-12 OP_RETURN
//     payload (BSVM\x02 || withdrawalRoot
//     || batchData), decodes the batch
//     data, and notifies the race
//     detector via
//     RaceDetector.HandleCovenantAdvance.
//     Consumer-side dedup blocks the
//     unconfirmed/confirmed pair from
//     double-firing; the libp2p
//     MsgCovenantAdvance path
//     (pkg/network/sync.go) is
//     independent and the race detector
//     itself tolerates the secondary
//     event.
//
// One upstream gap remains as a documented inline note:
// `WW-runar-inbox-decoder` — runar-go does not expose a public
// unlock-script decoder for the Submit() shape; the in-tree extractor
// reverse-engineers the codegen invariant. When runar-go lands a
// public decoder we should swap to it.
package main

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/icellan/bsvm/internal/db"
	"github.com/icellan/bsvm/pkg/beef"
	"github.com/icellan/bsvm/pkg/bridge"
	"github.com/icellan/bsvm/pkg/chaintracks"
	"github.com/icellan/bsvm/pkg/covenant"
	"github.com/icellan/bsvm/pkg/governance"
	"github.com/icellan/bsvm/pkg/metrics"
	"github.com/icellan/bsvm/pkg/overlay"
	"github.com/icellan/bsvm/pkg/rpc"
	"github.com/icellan/bsvm/pkg/types"
)

// txDedupSet is a small concurrency-safe set of BEEF target txids
// used by the inbox + covenant-advance consumers to drop duplicate
// envelopes (e.g. an unconfirmed envelope followed by the matching
// confirmed envelope, or the same envelope re-broadcast by two
// peers). Sized at sixteen for the typical race-detection cadence;
// the consumer wraps it in a sync.Mutex.
type txDedupSet struct {
	mu  sync.Mutex
	set map[[32]byte]struct{}
}

// newTxDedupSet returns an empty dedup set ready for concurrent use.
func newTxDedupSet() *txDedupSet {
	return &txDedupSet{set: make(map[[32]byte]struct{}, 16)}
}

// addOnce returns true the first time txid is observed and false on
// every subsequent call with the same txid. Used to gate consumer
// dispatch so a re-broadcast envelope does not double-fire the
// receiver.
func (s *txDedupSet) addOnce(txid [32]byte) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.set[txid]; ok {
		return false
	}
	s.set[txid] = struct{}{}
	return true
}

// beefWireOpts gathers everything WireBEEFEndpoints needs. Splitting
// the call site from the construction makes the cmdRun glue smaller
// and lets the BEEF integration test exercise the same builder.
type beefWireOpts struct {
	// Cfg is the operator-supplied [beef] config section. Drives the
	// enable flag, depth/width limits, anchor depth, and the bridge-
	// deposit security policy.
	Cfg BEEFSection
	// DB is the shared LevelDB used by the rest of the node. The BEEF
	// store reuses it under the dedicated "beef:" key prefix per spec
	// 17 §BEEFStore.
	DB db.Database
	// ShardID is the spec-17 shard identifier (low 64 bits of the
	// genesis covenant txid). Envelopes whose shard-bound flag is set
	// MUST match this ID; anything else is rejected with HTTP 400.
	// A zero ID disables the shard-binding check (devnet harnesses
	// only — production shards always have a non-zero ID).
	ShardID uint64
	// BridgeMonitor is the sink for verified bridge deposits. When
	// non-nil and the BEEF passes the W6-4 verifier, the parsed
	// deposit is forwarded to the monitor's pending list. When nil,
	// verified deposits are stored in the BEEF store but not credited
	// (e.g. the daemon hasn't yet wired the bridge subsystem).
	BridgeMonitor *bridge.BridgeMonitor
	// BridgeScriptHash is the bridge covenant script hash used to
	// identify deposit outputs inside the BEEF target tx. Required
	// when BridgeMonitor is non-nil; ignored otherwise.
	BridgeScriptHash []byte
	// LocalShardID is the bridge monitor's shard ID (uint32). Only
	// referenced when BridgeMonitor is non-nil.
	LocalShardID uint32
	// Metrics is the optional shared NetworkMetrics. When nil the
	// endpoints still serve traffic but no per-intent counters are
	// recorded.
	Metrics *metrics.NetworkMetrics
	// Chaintracks is the SPV anchor the BEEF verifier consults for
	// BUMP-to-header binding and confirmation depth. When nil the
	// verifier cannot run; the bridge consumer then falls back to the
	// pre-W6-4 fail-closed policy (envelope stored but never
	// credited) so a misconfigured daemon never silently mints wBSV.
	Chaintracks chaintracks.ChaintracksClient

	// InboxMonitor is the receiver subsystem the inbox-submission
	// consumer (intent 0x05) will dispatch to once the BSV-tx Rúnar
	// unlock-script decoder lands (tracked: WW-inbox-consumer). The
	// handle is plumbed through today so the future graduation is a
	// one-call-site change. Nil is acceptable — the consumer logs and
	// records "inbox monitor not wired" in the structured log line so
	// operators see why a posted inbox-submission BEEF did not extend
	// the local queue.
	InboxMonitor *overlay.InboxMonitor

	// ProposalWorkflow is the receiver subsystem the governance-action
	// consumer (intent 0x06) will dispatch to once the covenant-output
	// state decoder + tip-diff lands (tracked: WW-governance-consumer).
	// The handle is plumbed today so the future graduation is one
	// call site. Nil is acceptable — the consumer logs and records
	// "proposal workflow not wired" so operators see why a posted
	// governance-action BEEF did not surface in the proposal store.
	ProposalWorkflow *governance.Workflow

	// FeeWallet is the receiver subsystem the fee-wallet-funding
	// consumer (intent 0x04) will dispatch to once the BSV-tx output
	// walker that matches outputs to the wallet's locking script lands
	// (tracked: WW-fee-wallet-consumer). The handle is plumbed today
	// so the future graduation is one call site. Nil is acceptable —
	// the consumer logs "fee wallet not wired" so operators see why a
	// posted fee-wallet-funding BEEF did not extend the spendable
	// UTXO set.
	FeeWallet *overlay.FeeWallet

	// OverlayCovenantManager is the receiver subsystem the covenant-
	// advance consumer (intents 0x01 + 0x02) will dispatch to once the
	// OP_RETURN extractor + batch-data decoder land (tracked:
	// WW-overlay-covenant-consumer). The handle is plumbed today so
	// the future graduation is one call site. Nil is acceptable — the
	// consumer logs "covenant manager not wired" so operators see why
	// a posted covenant-advance BEEF did not feed the race detector.
	OverlayCovenantManager *covenant.CovenantManager

	// OverlayNode is the receiver subsystem hook for the covenant-
	// advance consumer's race-resolution path
	// (RaceDetector.HandleCovenantAdvance). Held alongside the
	// covenant manager so the WW-overlay-covenant-consumer
	// dispatch can reach both APIs from a single handle. Nil is
	// acceptable — the consumer logs and records the missing wiring.
	OverlayNode *overlay.OverlayNode

	// RaceDetector is the direct race-detector handle the covenant-
	// advance consumer dispatches to. When nil the consumer falls
	// back to overlay.RaceDetector() (production wiring); the
	// explicit field exists so tests that don't want to stand up a
	// full OverlayNode can still exercise the consumer's race-
	// detector handoff. Production callers leave this nil and let
	// the consumer pull through OverlayNode.
	RaceDetector *overlay.RaceDetector
}

type beefRuntime struct {
	Endpoints        *rpc.BEEFEndpoints
	Store            beef.Store
	CovenantConsumer func(*beef.Envelope)
}

// WireBEEFEndpoints constructs the spec-17 BEEF endpoint surface and
// attaches it to the RPC server. Call BEFORE rpcServer.Start().
//
// # Bridge deposit policy (post-W6-4)
//
// The /bsvm/bridge/deposit endpoint is the only consumer with a
// security implication. A deposit BEEF, if trusted, becomes free wBSV
// on L2.
//
// As of W6-4 the bridge consumer runs the full BRC-62 graph verifier
// before crediting:
//
//  1. Every ancestor BUMP is verified against chaintracks (root binds
//     to a confirmed header at the BUMP's declared height).
//  2. Every input's unlocking script is executed against the
//     corresponding ancestor output's locking script under standard
//     BSV consensus (post-Genesis, ForkID sighash).
//  3. The target tx must itself carry a BUMP confirmed at depth
//     >= cfg.AnchorDepth (default 6).
//  4. If all checks pass, the parsed deposit is handed to
//     bridge.BridgeMonitor.PersistDeposit; the monitor then drives the
//     normal deposit-horizon inclusion flow on the next L2 block.
//
// AcceptUnverifiedBridgeDeposits no longer disables ancestry / script
// verification — it ONLY relaxes the anchor-depth requirement to
// allow devnet harnesses that mine on demand to credit deposits at 0
// confirmations. Operators cannot turn off the per-input script
// engine; that's a hard W6-4 invariant.
//
// When Chaintracks is nil OR BridgeMonitor is nil, the bridge consumer
// falls back to the pre-W6-4 fail-closed policy: store the envelope in
// the BEEF store and log it. No credit is ever applied. The endpoint
// still returns HTTP 204 so a wallet retry loop does not back off.
//
// Other intents (covenant-advance, fee-wallet-funding, inbox,
// governance) carry no minting power on their own, so the default is
// to log + persist. Their consumers will graduate as the matching
// subsystem wires in (inbox → forced-inclusion submission, governance
// → governance proposal store, covenant-advance → overlay's covenant
// manager re-execute path).
//
// Returns nil when cfg.Enabled is false — callers can ignore the
// returned endpoints in that case.
func WireBEEFEndpoints(opts beefWireOpts, rpcServer *rpc.RPCServer) *rpc.BEEFEndpoints {
	rt := BuildBEEFRuntime(opts, rpcServer)
	if rt == nil {
		return nil
	}
	return rt.Endpoints
}

// BuildBEEFRuntime constructs the same endpoint surface as
// WireBEEFEndpoints and additionally returns the store + covenant
// consumer so follower catch-up can replay peer-fetched BEEFs through
// the exact same cmd-side receiver path as HTTP POST gossip.
func BuildBEEFRuntime(opts beefWireOpts, rpcServer *rpc.RPCServer) *beefRuntime {
	if !opts.Cfg.Enabled {
		slog.Info("beef endpoints disabled by config; /bsvm/* surface unmounted")
		return nil
	}
	if opts.DB == nil {
		slog.Warn("beef endpoints enabled but no DB supplied; using in-memory store (envelopes lost on restart)")
	}

	var store beef.Store
	if opts.DB != nil {
		store = beef.NewLevelStore(opts.DB)
	} else {
		store = beef.NewMemoryStore()
	}

	bridgeConsumer := makeBridgeConsumer(opts)
	inboxConsumer := makeInboxConsumer(opts)
	governanceConsumer := makeGovernanceConsumer(opts)
	feeWalletConsumer := makeFeeWalletConsumer(opts)
	covenantConsumer := makeCovenantConsumer(opts)

	cfg := rpc.BEEFEndpointConfig{
		Store:              store,
		ShardID:            opts.ShardID,
		Metrics:            opts.Metrics,
		BridgeConsumer:     bridgeConsumer,
		InboxConsumer:      inboxConsumer,
		GovernanceConsumer: governanceConsumer,
		FeeWalletConsumer:  feeWalletConsumer,
		CovenantConsumer:   covenantConsumer,
		// ARCCallback is intentionally nil here. The ARC callback
		// handler (spec 17 §"ARC / ARCADE") is wired by the BSV
		// broadcast stack which already owns the BUMP-verification
		// path; bolting it onto this constructor would duplicate that
		// wiring. Wire it in a follow-up once the ARC client lives in
		// a sibling helper rather than under wireBSVBroadcast's
		// closure.
	}
	endpoints := rpc.NewBEEFEndpoints(cfg)
	rpcServer.SetBEEFEndpoints(endpoints)
	slog.Info("beef endpoints mounted",
		"shard_id", opts.ShardID,
		"accept_unverified_bridge_deposits", opts.Cfg.AcceptUnverifiedBridgeDeposits,
		"chaintracks_wired", opts.Chaintracks != nil,
		"bridge_monitor_wired", opts.BridgeMonitor != nil,
		"inbox_monitor_wired", opts.InboxMonitor != nil,
		"proposal_workflow_wired", opts.ProposalWorkflow != nil,
		"fee_wallet_wired", opts.FeeWallet != nil,
		"overlay_covenant_wired", opts.OverlayCovenantManager != nil && opts.OverlayNode != nil,
		"anchor_depth", opts.Cfg.AnchorDepth,
		"max_depth", opts.Cfg.MaxDepth,
		"max_width", opts.Cfg.MaxWidth,
	)
	return &beefRuntime{
		Endpoints:        endpoints,
		Store:            store,
		CovenantConsumer: covenantConsumer,
	}
}

// makeBridgeConsumer returns the consumer callback the BEEF endpoint
// dispatches when a /bsvm/bridge/deposit envelope is accepted. The
// consumer enforces the W6-4 verification policy:
//
//   - When Chaintracks is wired AND BridgeMonitor is non-nil, the
//     consumer runs the full BRC-62 graph verifier (ancestry + BUMP +
//     script + anchor depth) and forwards a verified deposit to the
//     bridge monitor's pending list.
//   - When either dependency is missing the consumer falls back to the
//     pre-W6-4 fail-closed policy: log the envelope and return without
//     crediting anything. The envelope is still stored in the BEEF
//     store (the rpc layer does that before invoking the consumer) so
//     a future reconciliation pass can replay it once the dependencies
//     are wired.
func makeBridgeConsumer(opts beefWireOpts) func(*beef.Envelope) {
	if opts.Chaintracks == nil || opts.BridgeMonitor == nil {
		return func(env *beef.Envelope) {
			slog.Info("bridge deposit BEEF stored, no verifier wired (chaintracks/bridge monitor missing)",
				"target_txid", env.TargetTxID,
				"shard_id", env.Header.ShardID,
				"confirmed", env.Confirmed,
				"size", len(env.Beef),
				"chaintracks_wired", opts.Chaintracks != nil,
				"bridge_monitor_wired", opts.BridgeMonitor != nil,
			)
		}
	}

	// Compute the effective anchor depth. The unverified knob lowers
	// it to 0 so devnet harnesses can credit immediately, but ancestry
	// + script verification ALWAYS run regardless.
	effectiveAnchorDepth := opts.Cfg.AnchorDepth
	if opts.Cfg.AcceptUnverifiedBridgeDeposits {
		effectiveAnchorDepth = 0
	}
	verifier := beef.NewVerifier(opts.Chaintracks, beef.VerifyConfig{
		MaxDepth:           opts.Cfg.MaxDepth,
		MaxWidth:           opts.Cfg.MaxWidth,
		AnchorDepth:        effectiveAnchorDepth,
		ValidatedCacheSize: opts.Cfg.ValidatedCacheSize,
	})

	monitor := opts.BridgeMonitor
	scriptHash := opts.BridgeScriptHash
	localShardID := opts.LocalShardID

	return func(env *beef.Envelope) {
		// Bound verification work per envelope. A single BEEF should
		// not stall the endpoint for arbitrarily long; 30s is generous
		// for the largest legitimate envelope (10k ancestors at ~ms
		// per script execution).
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		verified, err := verifier.Verify(ctx, env.Beef)
		if err != nil {
			slog.Warn("bridge deposit BEEF verification failed",
				"target_txid", env.TargetTxID,
				"err", err,
				"reason", classifyVerifyError(err),
			)
			return
		}

		// The verifier returned a fully-validated tx. Walk its outputs
		// to recover the deposit envelope; we no longer need the
		// scaffold-quality decoder that lived here pre-W6-4.
		bsvTx := buildBridgeViewFromVerifiedBEEF(verified, scriptHash, localShardID, env)
		dep := bridge.ParseDeposit(bsvTx, scriptHash, localShardID)
		if dep == nil {
			slog.Debug("bridge deposit BEEF: target tx has no deposit output for this shard",
				"target_txid", env.TargetTxID,
			)
			return
		}
		// Override BSVBlockHeight with the verifier's authoritative
		// number (env.BlockHeight is taken from the gossip header,
		// which is unauthenticated). Confirmed iff the verifier saw a
		// BUMP on the target.
		dep.BSVBlockHeight = verified.TargetHeight
		dep.Confirmed = verified.Target.MerklePath != nil

		if perr := monitor.PersistDeposit(dep); perr != nil {
			slog.Warn("bridge deposit persist failed", "err", perr)
			return
		}
		slog.Info("bridge deposit BEEF verified and persisted",
			"target_txid", env.TargetTxID,
			"l2_address", dep.L2Address.Hex(),
			"satoshis", dep.SatoshiAmount,
			"bsv_height", dep.BSVBlockHeight,
			"confirmations", verified.Confirmations,
			"ancestor_count", verified.AncestorCount,
			"max_depth", verified.MaxAncestorDepth,
		)
	}
}

// buildBridgeViewFromVerifiedBEEF projects the SDK's verified
// transaction into the bridge package's BSVTransaction shape so the
// existing ParseDeposit code path can run against it. We copy output
// scripts + values and the verifier-derived txid + height; the rest of
// the bridge code does not read input data.
func buildBridgeViewFromVerifiedBEEF(
	v *beef.VerifiedBEEF,
	_ []byte, // scriptHash kept in signature for symmetry with ParseDeposit
	_ uint32,
	env *beef.Envelope,
) *bridge.BSVTransaction {
	out := &bridge.BSVTransaction{
		TxID:        types.Hash(v.TargetTxID),
		BlockHeight: v.TargetHeight,
		Outputs:     make([]bridge.BSVOutput, 0, len(v.Target.Outputs)),
	}
	for _, o := range v.Target.Outputs {
		var script []byte
		if o != nil && o.LockingScript != nil {
			script = []byte(*o.LockingScript)
		}
		out.Outputs = append(out.Outputs, bridge.BSVOutput{
			Value:  o.Satoshis,
			Script: script,
		})
	}
	// env may carry a populated BlockHeight even when the verifier
	// disagrees; prefer the verifier's value above and only fall back
	// to env when the verifier had nothing (unconfirmed envelope under
	// AcceptUnverifiedBridgeDeposits).
	if out.BlockHeight == 0 {
		out.BlockHeight = env.BlockHeight
	}
	return out
}

// makeInboxConsumer returns the consumer callback the BEEF endpoint
// dispatches when a /bsvm/inbox/submission envelope (intent 0x05) is
// accepted. The envelope is always logged + persisted to the BEEF
// store by the rpc layer; this callback is the cmd-side handoff to
// the InboxMonitor.
//
// The consumer:
//
//  1. Drops duplicate envelopes (same target txid) via dedupe.
//  2. Walks the BEEF target tx and extracts the EVM txRLP push from
//     input 0's unlock script (the inbox covenant's Submit() call).
//     The unlock-script shape is a 3-push sequence ([codePart,
//     opPushTxSig, txRLP]) emitted by runar-go's BuildUnlockingScript
//     for a stateful single-public-method contract.
//  3. Hands the recovered txRLP to InboxMonitor.AddInboxTransaction
//     so the next batch can drain it under the spec-10 forced-
//     inclusion rules.
//
// When opts.InboxMonitor is nil the consumer falls back to a
// structured log (the receiver isn't wired yet) so operators see why
// a posted envelope did not extend the queue.
//
// Upstream gap: runar-go does not expose an unlock-script decoder for
// the inbox Submit() shape. The minimal in-tree extractor in
// cmd/bsvm/beef_extractors.go::extractInboxTxRLP fills that gap. When
// runar-go grows its own decoder this consumer should swap to the
// upstream API; the gap is tracked as `WW-runar-inbox-decoder` in
// docs/decisions/spec-review-triage-2026-05.md.
func makeInboxConsumer(opts beefWireOpts) func(*beef.Envelope) {
	dedup := newTxDedupSet()
	return func(env *beef.Envelope) {
		fields := []any{
			"hook", "WW-inbox-consumer",
			"intent", beef.IntentName(env.Header.Intent),
			"target_txid", env.TargetTxID,
			"shard_id", env.Header.ShardID,
			"confirmed", env.Confirmed,
			"inbox_monitor_wired", opts.InboxMonitor != nil,
		}
		if opts.InboxMonitor == nil {
			fields = append(fields, "todo_hook", "WW-inbox-consumer")
			slog.Info("beef inbox-submission envelope received but inbox monitor not wired", fields...)
			return
		}
		if !dedup.addOnce(env.TargetTxID) {
			fields = append(fields, "skipped", "duplicate-target-txid")
			slog.Debug("beef inbox-submission envelope duplicate, skipping", fields...)
			return
		}
		txRLP, err := extractInboxTxRLP(env)
		if err != nil {
			fields = append(fields, "err", err.Error())
			slog.Warn("beef inbox-submission extractor failed", fields...)
			return
		}
		opts.InboxMonitor.AddInboxTransaction(txRLP)
		fields = append(fields,
			"tx_rlp_size", len(txRLP),
			"pending_inbox_txs", opts.InboxMonitor.PendingCount(),
		)
		slog.Info("beef inbox-submission txRLP queued", fields...)
	}
}

// makeGovernanceConsumer returns the consumer callback the BEEF
// endpoint dispatches when a /bsvm/governance/action envelope
// (intent 0x06) is accepted. The envelope is always logged +
// persisted to the BEEF store by the rpc layer; this callback is
// the cmd-side handoff to the governance proposal workflow.
//
// The consumer:
//
//  1. Walks the BEEF target tx output 0 and extracts the new
//     CovenantState (frozen flag + state root + block number).
//  2. Diffs against the local covenant manager's currentState. When
//     opts.OverlayCovenantManager is wired the diff is taken against
//     CurrentState(); when nil we still emit a proposal so a
//     governance-only deployment (no overlay) records the action.
//  3. Constructs a governance.Proposal for the observed action
//     (freeze when curr.Frozen=1 and prev.Frozen=0; unfreeze when
//     curr.Frozen=0 and prev.Frozen=1) and calls
//     ProposalWorkflow.CreateOrMerge(p). The workflow's content-
//     addressed Proposal.ID dedups identical proposals across BEEF
//     replays and across the cmd-side state-change callback path
//     (covenantMgr.SetStateChangeCallback in pkg/overlay/node.go) —
//     no double-fire is possible because both paths produce the
//     same content hash.
//
// Upgrade actions are not yet emitted from the BEEF path because
// they require recovering the new covenant script hash, which the
// CovenantState struct does not carry. That sub-gap is tracked as
// `WW-governance-upgrade-extractor` and the consumer logs +
// short-circuits when it sees a state change that is not a
// freeze/unfreeze transition.
//
// When opts.ProposalWorkflow is nil the consumer falls back to a
// structured log so operators see why a posted envelope did not
// surface in the proposal store.
func makeGovernanceConsumer(opts beefWireOpts) func(*beef.Envelope) {
	return func(env *beef.Envelope) {
		fields := []any{
			"hook", "WW-governance-consumer",
			"intent", beef.IntentName(env.Header.Intent),
			"target_txid", env.TargetTxID,
			"shard_id", env.Header.ShardID,
			"confirmed", env.Confirmed,
			"proposal_workflow_wired", opts.ProposalWorkflow != nil,
		}
		if opts.ProposalWorkflow == nil {
			fields = append(fields, "todo_hook", "WW-governance-consumer")
			slog.Info("beef governance-action envelope received but proposal workflow not wired", fields...)
			return
		}
		curr, err := extractCovenantStateFromTx(env)
		if err != nil {
			fields = append(fields, "err", err.Error())
			slog.Warn("beef governance-action extractor failed", fields...)
			return
		}
		var prev covenant.CovenantState
		if opts.OverlayCovenantManager != nil {
			prev = opts.OverlayCovenantManager.CurrentState()
		}
		// Identify the action by diffing Frozen. Other fields
		// (StateRoot, BlockNumber) advance on every covenant tick
		// and are not governance signals on their own.
		var action governance.Action
		switch {
		case prev.Frozen == 0 && curr.Frozen == 1:
			action = governance.ActionFreeze
		case prev.Frozen == 1 && curr.Frozen == 0:
			action = governance.ActionUnfreeze
		default:
			fields = append(fields,
				"prev_frozen", prev.Frozen != 0,
				"curr_frozen", curr.Frozen != 0,
				"todo_hook", "WW-governance-upgrade-extractor",
			)
			slog.Debug("beef governance-action: no freeze/unfreeze diff against local tip; not yet emitting upgrade proposals", fields...)
			return
		}
		// required=1 here is a placeholder for the content-hash
		// derivation — CreateOrMerge dedups by ID, and the proposal
		// store's Required count is irrelevant to dispatch
		// correctness (the broadcast path enforces the real
		// threshold from cluster config). 24h expiry matches
		// governance.DefaultExpiry.
		p, err := governance.NewProposal(action, nil, 1, governance.DefaultExpiry)
		if err != nil {
			fields = append(fields, "err", err.Error())
			slog.Warn("beef governance-action: NewProposal failed", fields...)
			return
		}
		if _, merr := opts.ProposalWorkflow.CreateOrMerge(p); merr != nil {
			fields = append(fields, "err", merr.Error())
			slog.Warn("beef governance-action: CreateOrMerge failed", fields...)
			return
		}
		proposals, _ := opts.ProposalWorkflow.List()
		fields = append(fields,
			"action", string(action),
			"proposal_id", p.ID,
			"local_proposal_count", len(proposals),
		)
		slog.Info("beef governance-action proposal merged", fields...)
	}
}

// makeFeeWalletConsumer returns the consumer callback the BEEF
// endpoint dispatches when a fee-wallet-funding envelope (intent
// 0x04) is accepted. The envelope is always logged + persisted to the
// BEEF store by the rpc layer; this callback is the cmd-side handoff
// to the FeeWallet.
//
// The consumer:
//
//  1. Reads the wallet's expected locking script via
//     FeeWallet.ExpectedScriptPubKey(). When nil (the cmd wiring has
//     not yet derived the wallet's script — only happens in tests)
//     the consumer falls back to a structured log without crediting.
//  2. Walks the BEEF target tx outputs and matches each output's
//     locking script against the expected script byte-for-byte.
//  3. Constructs a FeeUTXO per matched output and calls
//     FeeWallet.AddUTXO. The Confirmed flag inherits from
//     env.Confirmed so a still-unconfirmed funding tx is held as
//     unconfirmed in the wallet (the existing reconciler eventually
//     promotes it once chaintracks observes the BUMP).
//
// AddUTXO is idempotent on (txid, vout) so a re-broadcast envelope
// safely no-ops at the wallet level — no consumer-side dedup is
// needed for correctness. The structured log distinguishes
// first-time credits from re-broadcasts.
//
// When opts.FeeWallet is nil the consumer falls back to a structured
// log (the receiver isn't wired yet) so operators see why a posted
// envelope did not credit.
func makeFeeWalletConsumer(opts beefWireOpts) func(*beef.Envelope) {
	return func(env *beef.Envelope) {
		fields := []any{
			"hook", "WW-fee-wallet-consumer",
			"intent", beef.IntentName(env.Header.Intent),
			"target_txid", env.TargetTxID,
			"shard_id", env.Header.ShardID,
			"confirmed", env.Confirmed,
			"fee_wallet_wired", opts.FeeWallet != nil,
		}
		if opts.FeeWallet == nil {
			fields = append(fields, "todo_hook", "WW-fee-wallet-consumer")
			slog.Info("beef fee-wallet-funding envelope received but fee wallet not wired", fields...)
			return
		}
		expected := opts.FeeWallet.ExpectedScriptPubKey()
		if len(expected) == 0 {
			fields = append(fields,
				"todo_hook", "WW-fee-wallet-consumer-script",
				"reason", "fee wallet has not published its expected ScriptPubKey",
			)
			slog.Info("beef fee-wallet-funding envelope received but wallet script not set", fields...)
			return
		}
		matches, err := extractFeeWalletOutputs(env, expected)
		if err != nil {
			fields = append(fields, "err", err.Error())
			slog.Warn("beef fee-wallet-funding extractor failed", fields...)
			return
		}
		if len(matches) == 0 {
			fields = append(fields, "matched_outputs", 0)
			slog.Debug("beef fee-wallet-funding envelope: no outputs match wallet script", fields...)
			return
		}
		var totalSats uint64
		for _, m := range matches {
			utxo := &overlay.FeeUTXO{
				TxID:         types.Hash(env.TargetTxID),
				Vout:         m.Vout,
				Satoshis:     m.Satoshis,
				ScriptPubKey: m.Script,
				Confirmed:    env.Confirmed,
			}
			if addErr := opts.FeeWallet.AddUTXO(utxo); addErr != nil {
				slog.Warn("beef fee-wallet-funding AddUTXO failed",
					"hook", "WW-fee-wallet-consumer",
					"target_txid", env.TargetTxID,
					"vout", m.Vout,
					"err", addErr.Error(),
				)
				continue
			}
			totalSats += m.Satoshis
		}
		fields = append(fields,
			"matched_outputs", len(matches),
			"credited_sats", totalSats,
			"fee_wallet_balance_sats", opts.FeeWallet.Balance(),
		)
		slog.Info("beef fee-wallet-funding outputs credited", fields...)
	}
}

// makeCovenantConsumer returns the consumer callback the BEEF
// endpoint dispatches when a /bsvm/beef/covenant-chain POST envelope
// (intents 0x01 + 0x02) is accepted. The envelope is always logged +
// persisted to the BEEF store by the rpc layer; this callback is the
// cmd-side handoff to the overlay race detector.
//
// The consumer:
//
//  1. Drops duplicate envelopes (same target txid) via dedupe — the
//     unconfirmed/confirmed pair for the same tx, or a re-broadcast
//     from a peer, must not double-fire RaceDetector handlers.
//  2. Walks the BEEF target tx and extracts the spec-12 OP_RETURN
//     payload (BSVM\x02 || withdrawalRoot(32) || batchData). The
//     batch is decoded via block.DecodeBatchData to recover the
//     transaction list + parent hash + bsv block hash (the post-
//     state root is computed downstream by re-execution; the BEEF
//     envelope is purely a heads-up that an advance landed).
//  3. Constructs a CovenantAdvanceEvent and calls
//     RaceDetector.HandleCovenantAdvance. IsOurs is set by comparing
//     the target txid against the covenant manager's currentTxID so
//     a re-broadcast of our own advance correctly trips the
//     race-won path. PostStateRoot is left zero — re-execution at
//     the overlay level fills it in via process.go.
//
// When the covenant manager or overlay node isn't wired, the
// consumer falls back to a structured log so operators see why a
// posted envelope did not reach the race detector.
//
// Coordination with the libp2p MsgCovenantAdvance path
// (pkg/network/sync.go): both feed the same RaceDetector. The dedup
// set inside RaceDetector itself (consecutiveLosses logic) tolerates
// two events for the same advance — the first wins, the second is a
// no-op. Our consumer-level dedup is an early short-circuit that
// avoids the second call entirely.
func makeCovenantConsumer(opts beefWireOpts) func(*beef.Envelope) {
	dedup := newTxDedupSet()
	return func(env *beef.Envelope) {
		fields := []any{
			"hook", "WW-overlay-covenant-consumer",
			"intent", beef.IntentName(env.Header.Intent),
			"target_txid", env.TargetTxID,
			"shard_id", env.Header.ShardID,
			"confirmed", env.Confirmed,
			"covenant_manager_wired", opts.OverlayCovenantManager != nil,
			"overlay_node_wired", opts.OverlayNode != nil,
		}
		if opts.OverlayCovenantManager != nil {
			st := opts.OverlayCovenantManager.CurrentState()
			fields = append(fields,
				"local_covenant_tx", opts.OverlayCovenantManager.CurrentTxID(),
				"local_covenant_block", st.BlockNumber,
				"local_covenant_frozen", st.Frozen != 0,
			)
		}
		if opts.OverlayNode != nil {
			fields = append(fields, "local_execution_tip", opts.OverlayNode.ExecutionTip())
		}
		// Resolve the race-detector handle. Tests may pass it
		// directly via opts.RaceDetector to avoid standing up a
		// full OverlayNode; production wiring leaves it nil and we
		// pull through OverlayNode.
		rd := opts.RaceDetector
		if rd == nil && opts.OverlayNode != nil {
			rd = opts.OverlayNode.RaceDetector()
		}
		if rd == nil {
			fields = append(fields, "todo_hook", "WW-overlay-covenant-consumer")
			slog.Info("beef covenant-advance envelope received but race detector not wired", fields...)
			return
		}
		if !dedup.addOnce(env.TargetTxID) {
			fields = append(fields, "skipped", "duplicate-target-txid")
			slog.Debug("beef covenant-advance envelope duplicate, skipping", fields...)
			return
		}
		adv, err := extractCovenantAdvance(env)
		if err != nil {
			fields = append(fields, "err", err.Error())
			slog.Warn("beef covenant-advance extractor failed", fields...)
			return
		}
		var isOurs bool
		if opts.OverlayCovenantManager != nil {
			localTx := opts.OverlayCovenantManager.CurrentTxID()
			isOurs = types.Hash(env.TargetTxID) == localTx
		}
		event := &overlay.CovenantAdvanceEvent{
			BSVTxID:    types.Hash(env.TargetTxID),
			L2BlockNum: 0, // see extractCovenantAdvance: block number is not in BatchData
			BatchData:  adv.BatchData,
			IsOurs:     isOurs,
		}
		if herr := rd.HandleCovenantAdvance(event); herr != nil {
			fields = append(fields, "err", herr.Error())
			slog.Warn("beef covenant-advance HandleCovenantAdvance failed", fields...)
			return
		}
		fields = append(fields,
			"is_ours", isOurs,
			"batch_tx_count", len(adv.Decoded.Transactions),
			"deposit_horizon", adv.Decoded.DepositHorizon,
			"withdrawal_root", adv.WithdrawalRoot,
		)
		slog.Info("beef covenant-advance race detector notified", fields...)
	}
}

// classifyVerifyError returns a short label for the metrics layer +
// log search. Keeps the verifier's error vocabulary out of operator-
// facing strings.
func classifyVerifyError(err error) string {
	switch {
	case errors.Is(err, beef.ErrParse):
		return "parse"
	case errors.Is(err, beef.ErrNoTarget):
		return "no-target"
	case errors.Is(err, beef.ErrEmptyBEEF):
		return "empty"
	case errors.Is(err, beef.ErrNoChaintracks):
		return "no-chaintracks"
	case errors.Is(err, beef.ErrTooDeep):
		return "too-deep"
	case errors.Is(err, beef.ErrTooWide):
		return "too-wide"
	case errors.Is(err, beef.ErrBUMP):
		return "bad-bump"
	case errors.Is(err, beef.ErrMissingAncestor):
		return "missing-ancestor"
	case errors.Is(err, beef.ErrScript):
		return "bad-script"
	case errors.Is(err, beef.ErrAnchorMissing):
		return "no-anchor"
	case errors.Is(err, beef.ErrAnchorTooShallow):
		return "anchor-shallow"
	case errors.Is(err, beef.ErrAnchorReorged):
		return "anchor-reorged"
	case errors.Is(err, beef.ErrAnchorHeader),
		errors.Is(err, beef.ErrAnchorConfirms):
		return "anchor-lookup"
	default:
		return "other"
	}
}
