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
// applies (in particular: bridge deposits are NOT credited to L2 on
// the default path, see "Bridge deposit policy" below).
package main

import (
	"fmt"
	"log/slog"

	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/icellan/bsvm/internal/db"
	"github.com/icellan/bsvm/pkg/beef"
	"github.com/icellan/bsvm/pkg/bridge"
	"github.com/icellan/bsvm/pkg/metrics"
	"github.com/icellan/bsvm/pkg/rpc"
	"github.com/icellan/bsvm/pkg/types"
)

// beefWireOpts gathers everything WireBEEFEndpoints needs. Splitting
// the call site from the construction makes the cmdRun glue smaller
// and lets the BEEF integration test exercise the same builder.
type beefWireOpts struct {
	// Cfg is the operator-supplied [beef] config section. Drives the
	// enable flag and the bridge-deposit security policy.
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
	// BridgeMonitor is the optional sink for verified bridge deposits.
	// When AcceptUnverifiedBridgeDeposits is true AND BridgeMonitor is
	// non-nil, deposits parsed from the BEEF target tx are forwarded
	// to the monitor's pending list. Otherwise deposits are stored in
	// the BEEFStore but NOT credited on L2 — see security rationale on
	// WireBEEFEndpoints.
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
}

// WireBEEFEndpoints constructs the spec-17 BEEF endpoint surface and
// attaches it to the RPC server. Call BEFORE rpcServer.Start().
//
// # Bridge deposit policy
//
// The /bsvm/bridge/deposit endpoint is the only consumer with a
// security implication. A deposit BEEF, if trusted, becomes free wBSV
// on L2 — so anyone able to push an envelope past the parser could
// mint wBSV at will until the underlying BSV tx fails inclusion.
//
// Spec 17 §"Bridge Deposits: Push Model via BEEF" requires the node to
// verify the BEEF (ancestors against chaintracks, BUMP against headers
// at depth ≥ 6, target script paying the bridge covenant) before the
// deposit hits the bridge monitor. Today pkg/beef parses the structure
// but performs none of those checks — that work is W6-4.
//
// Until W6-4 lands the policy is FAIL-CLOSED: bridge deposits are
// stored (so we can replay them after W6-4 ships) but NOT credited on
// L2. The monitor only learns about a deposit when the operator opts
// in via beef.accept_unverified_bridge_deposits = true (devnet
// harness convenience; never set this on mainnet).
//
// Other intents (covenant-advance, fee-wallet-funding, inbox,
// governance) carry no minting power on their own, so the default is
// to log + persist. Inbox specifically MAY graduate to forced-
// inclusion submission once W6-4 wires the BSV-side pre-confirmation
// check; for now we leave the consumer at log-only too so we don't
// queue a tx whose BSV-anchored unlock cannot be re-derived.
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

	// Bridge consumer. The default fail-closed path logs the envelope
	// and exits — the deposit sits in the BEEF store waiting for
	// W6-4's verification gate to credit it on L2. When the operator
	// opts in via accept_unverified_bridge_deposits the parsed target
	// tx is funneled to the bridge monitor's pending list AS IF the
	// ancestry check had passed.
	bridgeConsumer := makeBridgeConsumer(opts)

	// Inbox / governance / fee-wallet-funding / covenant-advance:
	// log-only. Each intent will graduate to a real consumer once the
	// matching subsystem is wired (inbox → forced-inclusion submission
	// after W6-4; governance → governance proposal store; covenant-
	// advance → overlay's covenant manager re-execute path).
	logOnly := func(name string) func(*beef.Envelope) {
		return func(env *beef.Envelope) {
			slog.Info("beef envelope received (log-only consumer)",
				"intent", beef.IntentName(env.Header.Intent),
				"sink", name,
				"target_txid", env.TargetTxID,
				"shard_id", env.Header.ShardID,
				"confirmed", env.Confirmed,
				// TODO(W6-4): replace with full BRC-62 verification +
				// real consumer dispatch once chaintracks-backed BUMP
				// and script re-exec land.
			)
		}
	}

	cfg := rpc.BEEFEndpointConfig{
		Store:              store,
		ShardID:            opts.ShardID,
		Metrics:            opts.Metrics,
		BridgeConsumer:     bridgeConsumer,
		InboxConsumer:      logOnly("inbox"),
		GovernanceConsumer: logOnly("governance"),
		FeeWalletConsumer:  logOnly("fee-wallet"),
		CovenantConsumer:   logOnly("covenant-advance"),
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
	)
	return endpoints
}

// makeBridgeConsumer returns the consumer callback the BEEF endpoint
// dispatches when a /bsvm/bridge/deposit envelope is accepted. The
// consumer enforces the fail-closed policy described on
// WireBEEFEndpoints: a deposit BEEF is stored unconditionally, but
// only routed to the bridge monitor when the operator has opted in to
// the unverified-deposits relaxation.
func makeBridgeConsumer(opts beefWireOpts) func(*beef.Envelope) {
	if !opts.Cfg.AcceptUnverifiedBridgeDeposits {
		return func(env *beef.Envelope) {
			slog.Info("bridge deposit BEEF stored, awaiting W6-4 verification",
				"target_txid", env.TargetTxID,
				"shard_id", env.Header.ShardID,
				"confirmed", env.Confirmed,
				"size", len(env.Beef),
				// TODO(W6-4): replace with full BRC-62 verification:
				//   1. walk ancestor BUMPs against chaintracks
				//   2. re-execute target tx input scripts
				//   3. confirm target BUMP at depth >= 6
				//   4. parse OP_RETURN deposit envelope
				//   5. forward to bridge.BridgeMonitor.PersistDeposit
			)
		}
	}
	if opts.BridgeMonitor == nil {
		return func(env *beef.Envelope) {
			slog.Warn("bridge deposit BEEF accepted but no monitor wired; dropping",
				"target_txid", env.TargetTxID,
			)
		}
	}
	// Devnet/relaxed path: parse the underlying BSV tx out of the BEEF
	// body and feed it to the bridge monitor as if W6-4 had verified
	// it. Caller MUST understand that this opens a free-mint vector if
	// the parser ever accepts a forged envelope — only flip the config
	// in environments where the BEEF source is fully trusted.
	monitor := opts.BridgeMonitor
	scriptHash := opts.BridgeScriptHash
	localShardID := opts.LocalShardID
	return func(env *beef.Envelope) {
		parsed, err := beef.ParseBEEF(env.Beef)
		if err != nil || parsed.Target() == nil {
			slog.Warn("bridge deposit BEEF parse failed", "err", err)
			return
		}
		// TODO(W6-4): the call below trusts env.Beef structurally — it
		// does NOT verify the ancestry, BUMP, or input scripts. Replace
		// with a verifying BEEF reader before shipping this code path
		// to mainnet.
		raw := parsed.Target().RawTx
		bsvTx, err := decodeBSVTransactionForBridge(raw, parsed.Target().TxID)
		if err != nil {
			slog.Warn("bridge deposit BEEF: decode bsv tx failed", "err", err)
			return
		}
		dep := bridge.ParseDeposit(bsvTx, scriptHash, localShardID)
		if dep == nil {
			slog.Debug("bridge deposit BEEF: target tx has no deposit output for this shard",
				"target_txid", env.TargetTxID,
			)
			return
		}
		dep.BSVBlockHeight = env.BlockHeight
		dep.Confirmed = env.Confirmed
		if perr := monitor.PersistDeposit(dep); perr != nil {
			slog.Warn("bridge deposit persist failed", "err", perr)
			return
		}
		slog.Info("bridge deposit BEEF persisted (UNVERIFIED PATH)",
			"target_txid", env.TargetTxID,
			"l2_address", dep.L2Address.Hex(),
			"satoshis", dep.SatoshiAmount,
		)
	}
}

// decodeBSVTransactionForBridge unpacks a raw BSV transaction (in BSV
// wire form) into the bridge package's BSVTransaction shape so
// bridge.ParseDeposit can run against it. The conversion is
// scaffold-quality: it copies output scripts + values and the
// supplied txid; the rest of the bridge code path doesn't read input
// data.
//
// TODO(W6-4): once full BRC-62 verification lands the BEEF reader
// will yield a fully validated tx representation; this adapter goes
// away in favour of the verified-tx path.
func decodeBSVTransactionForBridge(rawTx []byte, txid [32]byte) (*bridge.BSVTransaction, error) {
	parsed, err := transaction.NewTransactionFromBytes(rawTx)
	if err != nil {
		return nil, fmt.Errorf("parse bsv tx: %w", err)
	}
	out := &bridge.BSVTransaction{
		TxID:    types.Hash(txid),
		Outputs: make([]bridge.BSVOutput, 0, len(parsed.Outputs)),
	}
	for _, o := range parsed.Outputs {
		var script []byte
		if o.LockingScript != nil {
			script = []byte(*o.LockingScript)
		}
		out.Outputs = append(out.Outputs, bridge.BSVOutput{
			Value:  o.Satoshis,
			Script: script,
		})
	}
	return out, nil
}
