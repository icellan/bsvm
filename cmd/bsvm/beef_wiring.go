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
// applies. As of W6-4 the bridge-deposit consumer runs full BRC-62
// graph verification (ancestry against chaintracks, BUMP against
// confirmed headers, every input script re-executed) before crediting
// the bridge monitor.
//
// The other four consumers (inbox, governance, fee-wallet, covenant-
// advance) accept the receiver-subsystem handle through beefWireOpts so
// the consumer factory can dispatch directly when the matching
// extractor lands. Today each factory still logs the envelope and
// records a tracked-WW-hook field in the log line so operators can
// grep for which subsystem is still deferred. The named hooks are:
//
//   - WW-inbox-consumer            — needs a BSV-tx Rúnar unlock-script
//     decoder to recover the EVM txRLP
//     argument from the inbox covenant
//     Submit() call before the queue can
//     be extended via
//     InboxMonitor.AddInboxTransaction.
//   - WW-governance-consumer       — needs a covenant-output state
//     decoder + diff against the local
//     covenant tip before the
//     GovernanceMonitor.HandleGovernance{
//     Freeze,Unfreeze,Upgrade} can be
//     invoked. The cmd-side state-change
//     callback already fires these
//     handlers when the local covenant
//     manager applies the advance, so a
//     naive BEEF-driven dispatch would
//     double-fire — the extractor MUST
//     diff against currentState first.
//   - WW-fee-wallet-consumer       — needs a BSV-tx output walker that
//     matches outputs to the fee
//     wallet's locking script before
//     FeeWallet.AddUTXO can be called.
//     The fee wallet handle is plumbed
//     through opts so the future change
//     is one call site.
//   - WW-overlay-covenant-consumer — needs an OP_RETURN extractor to
//     recover the spec-12 advance payload
//     (BSVM\x02 || withdrawalRoot ||
//     batchData) and a batch-data decoder
//     to recover the post-state-root +
//     L2 block number before
//     RaceDetector.HandleCovenantAdvance
//     can be called with a fully-
//     populated CovenantAdvanceEvent.
//
// Each deferred sink is therefore intentionally not a half-wired
// dispatch — the envelope is logged + persisted in the BEEF store, and
// the receiver handle is held ready for the one-line graduation the
// extractor unlocks.
package main

import (
	"context"
	"errors"
	"log/slog"
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
	// covenant manager so the future WW-overlay-covenant-consumer
	// graduation can reach both APIs from a single handle. Nil is
	// acceptable — the consumer logs and records the missing wiring.
	OverlayNode *overlay.OverlayNode
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
	return endpoints
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
// # Status: deferred (WW-inbox-consumer)
//
// Graduating this consumer to a real AddInboxTransaction call requires
// a BSV-tx Rúnar unlock-script decoder that recovers the EVM txRLP
// argument from the inbox covenant Submit() call (see
// pkg/covenant/contracts/inbox.runar.go). That decoder does not exist
// yet — the existing pkg/beef ParseBEEF returns the raw target tx
// bytes but no structured input/unlock-script view.
//
// Until WW-inbox-consumer lands, the consumer logs the envelope at INFO
// with the tracked hook name in the structured fields so operators
// grepping daemon logs can confirm the BEEF was received and stored
// (it is — the rpc handler runs Store.Put before invoking us). When
// opts.InboxMonitor is non-nil the log line surfaces the queue depth
// at receive time so the operator can correlate a BEEF arrival with
// the next batch's drain event.
func makeInboxConsumer(opts beefWireOpts) func(*beef.Envelope) {
	return func(env *beef.Envelope) {
		fields := []any{
			"todo_hook", "WW-inbox-consumer",
			"intent", beef.IntentName(env.Header.Intent),
			"target_txid", env.TargetTxID,
			"shard_id", env.Header.ShardID,
			"confirmed", env.Confirmed,
			"inbox_monitor_wired", opts.InboxMonitor != nil,
		}
		if opts.InboxMonitor != nil {
			fields = append(fields, "pending_inbox_txs", opts.InboxMonitor.PendingCount())
		}
		slog.Info("beef inbox-submission envelope received (deferred consumer)", fields...)
	}
}

// makeGovernanceConsumer returns the consumer callback the BEEF
// endpoint dispatches when a /bsvm/governance/action envelope
// (intent 0x06) is accepted. The envelope is always logged +
// persisted to the BEEF store by the rpc layer; this callback is
// the cmd-side handoff to the governance proposal workflow / overlay
// governance monitor.
//
// # Status: deferred (WW-governance-consumer)
//
// Graduating this consumer requires a covenant-output state decoder
// that walks the BSV target tx, finds the covenant continuation
// output, extracts the CovenantState push-data via
// covenant.DecodeCovenantState, and diffs against the local covenant
// tip before invoking GovernanceMonitor.HandleGovernanceFreeze /
// HandleGovernanceUnfreeze / HandleGovernanceUpgrade (per spec 17
// §"Governance-Event Detection via BEEF Gossip").
//
// The naive dispatch — call the handlers unconditionally on every
// 0x06 envelope — would double-fire alongside the existing state-
// change callback wired in pkg/overlay/node.go (covenantMgr.
// SetStateChangeCallback), so the extractor MUST diff against
// currentState first. That diff is also what allows the consumer to
// reject a stale or reorged 0x06 envelope without disrupting an
// active session.
//
// Until WW-governance-consumer lands, the consumer logs the envelope
// at INFO with the tracked hook name. When opts.ProposalWorkflow is
// non-nil the log line surfaces the workflow's current proposal
// count so the operator can correlate a BEEF arrival with the
// matching local proposal record.
func makeGovernanceConsumer(opts beefWireOpts) func(*beef.Envelope) {
	return func(env *beef.Envelope) {
		fields := []any{
			"todo_hook", "WW-governance-consumer",
			"intent", beef.IntentName(env.Header.Intent),
			"target_txid", env.TargetTxID,
			"shard_id", env.Header.ShardID,
			"confirmed", env.Confirmed,
			"proposal_workflow_wired", opts.ProposalWorkflow != nil,
		}
		if opts.ProposalWorkflow != nil {
			if proposals, err := opts.ProposalWorkflow.List(); err == nil {
				fields = append(fields, "local_proposal_count", len(proposals))
			}
		}
		slog.Info("beef governance-action envelope received (deferred consumer)", fields...)
	}
}

// makeFeeWalletConsumer returns the consumer callback the BEEF
// endpoint dispatches when a /bsvm/inbox/submission envelope is
// accepted with intent 0x04 (fee-wallet-funding). The envelope is
// always logged + persisted to the BEEF store by the rpc layer; this
// callback is the cmd-side handoff to the FeeWallet.
//
// # Status: deferred (WW-fee-wallet-consumer)
//
// Graduating this consumer to a real AddUTXO call requires a BSV-tx
// output walker that matches outputs against the fee wallet's locking
// script. The fee wallet does not currently expose its locking script
// (see pkg/overlay/fee_wallet.go — the wallet is keyed by FeeUTXO
// {TxID, Vout, Satoshis, ScriptPubKey} but does not publish the
// expected ScriptPubKey for matching). The cmd-side wiring would also
// need to convert env.Confirmed into the FeeUTXO.Confirmed flag and
// call AddUTXO once per matching output.
//
// Until WW-fee-wallet-consumer lands, the consumer logs the envelope
// at INFO with the tracked hook name. When opts.FeeWallet is non-nil
// the log line surfaces the wallet's current spendable balance so the
// operator can correlate a BEEF arrival with the future credit.
func makeFeeWalletConsumer(opts beefWireOpts) func(*beef.Envelope) {
	return func(env *beef.Envelope) {
		fields := []any{
			"todo_hook", "WW-fee-wallet-consumer",
			"intent", beef.IntentName(env.Header.Intent),
			"target_txid", env.TargetTxID,
			"shard_id", env.Header.ShardID,
			"confirmed", env.Confirmed,
			"fee_wallet_wired", opts.FeeWallet != nil,
		}
		if opts.FeeWallet != nil {
			fields = append(fields, "fee_wallet_balance_sats", opts.FeeWallet.Balance())
		}
		slog.Info("beef fee-wallet-funding envelope received (deferred consumer)", fields...)
	}
}

// makeCovenantConsumer returns the consumer callback the BEEF
// endpoint dispatches when a /bsvm/beef/covenant-chain POST envelope
// (intents 0x01 + 0x02) is accepted. The envelope is always logged +
// persisted to the BEEF store by the rpc layer; this callback is the
// cmd-side handoff to the overlay covenant manager / race detector.
//
// # Status: deferred (WW-overlay-covenant-consumer)
//
// Graduating this consumer to a real RaceDetector.HandleCovenantAdvance
// call requires:
//
//  1. An OP_RETURN extractor that recovers the spec-12 advance payload
//     (BSVM\x02 || withdrawalRoot(32) || batchData) from the BSV
//     target tx's outputs. pkg/bridge/withdrawer.go already has
//     extractRefsFromAdvanceTx for the withdrawal-root path; we'd
//     reuse the OP_RETURN walker but extract the full payload, not
//     just the first 32 bytes.
//  2. A batch-data decoder that recovers the post-state-root + L2
//     block number from the embedded block.BatchData blob. The
//     overlay's process.go path already has block.DecodeBatchData;
//     this consumer would use it identically.
//  3. A naive dispatch would also need to coordinate with the
//     existing libp2p MsgCovenantAdvance path (pkg/network/sync.go)
//     to avoid double-fed RaceDetector events for the same advance.
//
// Until WW-overlay-covenant-consumer lands, the consumer logs the
// envelope at INFO with the tracked hook name + the local covenant
// manager's current tip / block number so the operator can correlate
// a BEEF-driven advance arrival with the local execution tip.
func makeCovenantConsumer(opts beefWireOpts) func(*beef.Envelope) {
	return func(env *beef.Envelope) {
		fields := []any{
			"todo_hook", "WW-overlay-covenant-consumer",
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
		slog.Info("beef covenant-advance envelope received (deferred consumer)", fields...)
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
