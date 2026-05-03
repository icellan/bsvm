# BSVM operator admin runbook

This document covers the operator-facing surface for running a BSVM
node: the `admin_*` JSON-RPC namespace, the multisig governance
proposal flow, and where each surface plugs into the underlying
covenant + ARC machinery.

The companion documents are:

* `docs/operator/vk-rotation.md` — VK rotation runbook (uses the
  `rotate-vk` binary; orthogonal to the multisig flow described
  here).
* `docs/operator/sp1-build.md` — building the SP1 guest + reproducing
  the in-tree `SP1VerifyingKeyHash.txt`.

## Admin RPC namespace

Mounted at `POST /admin/rpc`. Every method requires the operator's
admin auth (BRC-100 handshake or `BSVM_ADMIN_DEV_SECRET` on dev
proving modes — see `cmd/bsvm/main.go` and `pkg/rpc/auth/`).

### Currently implemented

| Method | What it does |
|---|---|
| `admin_peerList` | Snapshot of the libp2p peer set. |
| `admin_getConfig` | Returns the live runtime config (`overlay.RuntimeConfigView`) plus the `liveReloadWhitelist` so the explorer UI knows which keys can be applied without restart. |
| `admin_setConfig` | Accepts a single `[key, value]` pair. Whitelisted keys are applied at runtime AND persisted to `<datadir>/admin_overrides.json`. Non-whitelisted keys are rejected with a structured "restart required" error. See "Live-reload whitelist" below. |
| `admin_pauseProving` / `admin_resumeProving` | Flip the batcher. New txs are rejected while paused. |
| `admin_forceFlushBatch` | Flush the current pending batch immediately. |
| `admin_bridgeHealth` | Returns the live BridgeUTXO snapshot, deposit horizon, pending-deposit count, and shard ID. When `[bridge].bridge_script_hex` is empty surfaces `monitorAttached=false` with operator guidance. |
| `admin_rescanDeposits` | Rewinds the bridge block-scanner's resume cursor to `fromHeight - 1` so subsequent chaintracks events at-or-above `fromHeight` flow through `BridgeMonitor.ProcessBlock` again instead of being short-circuited by the resume-cursor dedup. Returns `{success, fromHeight, scheduled}` where `scheduled = currentTip - fromHeight`. Requires both the bridge monitor AND the rescanner callback wired (the latter is wired automatically in `cmd/bsvm/main.go` once `startBridgeBlockScanner` returns a non-nil handle). |
| `admin_createGovernanceProposal` | Create + gossip a freeze/unfreeze/upgrade proposal (see below). |
| `admin_listGovernanceProposals` | Local view of the proposal queue. |
| `admin_signGovernanceProposal` | Verify a governance signature against an existing proposal. |

### Live-reload whitelist (`admin_setConfig`)

Spec 15 §"Configuration" describes the explorer UI showing a "Restart
Required" hint per field. The reloader implements the inverse: a tiny
whitelist of keys that explicitly DO support live reload. Anything
outside the whitelist returns a structured error of the form:

```
admin_setConfig: key "X" requires restart (not in live-reload whitelist; whitelisted keys: [...])
```

Whitelisted keys today:

| Key | Type | Notes |
|---|---|---|
| `log_level` | string | One of `debug`, `info`, `warn`, `error`. Mutates the shared `*slog.LevelVar` so the next slog record sees the new filter immediately. |

Each successful apply is mirrored to `<datadir>/admin_overrides.json`
so the change survives a restart. On boot, `cmd/bsvm/main.go` reads
the sidecar and re-applies each entry through the same applier path
— invalid overrides log a WARN and are skipped rather than blocking
boot. To revert a runtime change, delete the entry from
`admin_overrides.json` (or the entire file) and restart the daemon.

Adding a key requires (a) defining + wiring an applier in
`pkg/rpc/admin_live_reload.go`, (b) unit-testing the applier against
valid + invalid inputs, (c) verifying the persisted override is
re-applied on the next boot. Keys that change subsystem identity
(chain ID, governance keys, SP1 verifying key, bridge configuration)
MUST stay outside the whitelist — those are genesis-level invariants.

### Bridge admin (`admin_bridgeHealth`, `admin_rescanDeposits`)

Both RPCs delegate to `pkg/bridge.BridgeMonitor`. The monitor is
constructed in `cmd/bsvm/main.go` via `BuildBridgeMonitor` and wired
into the admin API via `rpcServer.AdminAPI().SetBridgeMonitor(...)`
immediately after construction.

`admin_bridgeHealth` response shape:

```jsonc
{
  "monitorAttached": true,
  "rescannerWired":  true,             // true once cmd-side wires SetBridgeRescanner (wired by default in main.go when startBridgeBlockScanner returns a handle)
  "subCovenants": [
    {
      "bsvTxid":          "abc...",     // hex
      "vout":             0,
      "balance":          8700000000,   // satoshis
      "lastClaimedNonce": 41,           // ^uint64(0) → "no claim yet"
      "status":           "active"
    }
  ],
  "mismatch":         false,            // l2 supply check belongs to the indexer
  "totalLocked":      "8700000000",
  "totalSupply":      "8700000000",
  "lastScanned":      800123,           // BridgeMonitor.DepositHorizon()
  "pendingDeposits":  3,
  "localShardId":     1234,
  "rescanPending":    false
}
```

When no bridge is configured (`[bridge].bridge_script_hex` empty) the
response surfaces `monitorAttached=false` and includes a `note`
field directing the operator at this runbook. The shape is otherwise
the same so the explorer UI doesn't need to special-case "no bridge".

`admin_rescanDeposits` accepts `[fromHeight]` (hex-encoded uint64) and
returns `{success, fromHeight, scheduled}`. The rescanner is wired
automatically by `cmd/bsvm/main.go` whenever `startBridgeBlockScanner`
returns a non-nil `BlockScannerHandle` (i.e. whenever the bridge AND
chaintracks are both configured). Internally the call rewinds the
block-scanner's in-memory resume cursor to `fromHeight - 1` so the
next chaintracks event at-or-above `fromHeight` is processed rather
than skipped by the resume-cursor dedup.

Wire path:

```
admin_rescanDeposits        (pkg/rpc/admin_bridge.go)
   → BridgeRescanFn closure (cmd/bsvm/main.go)
   → BlockScannerHandle.RewindToHeight  (cmd/bsvm/bridge_blockscan_wiring.go)
   → channel-based command into the supervisor goroutine
   → supervisor mutates its private resume-cursor + publishes the
     new value for CurrentCursor() readers
```

Important properties:

* **One-shot, not persistent.** The rewind only mutates the in-memory
  cursor of the running supervisor goroutine. It does NOT change the
  daemon's resume-after-restart semantics — restarting the daemon
  will resume from wherever the BridgeMonitor's persisted
  DepositHorizon left off, not from the rescan cursor. Use the rescan
  RPC for "operator wants to replay a window of historical blocks
  RIGHT NOW", not for "operator wants the daemon to start at height N
  on the next boot".
* **Concurrency-safe.** `RewindToHeight` is safe to call from the RPC
  goroutine while the supervisor is mid-scan; commands serialise via
  a buffered channel that the supervisor drains between block events,
  during reconnect-backoff sleeps, and around chaintracks subscribe
  attempts.
* **Idempotent.** Rewinding to a height at-or-above the current cursor
  is a no-op (the cursor stays put). The `scheduled` count is still
  computed and returned so the operator UI's progress indicator gets
  a meaningful estimate either way.
* **Tip-failure-tolerant.** If the chaintracks tip lookup fails the
  rewind STILL applies (the operator's intent wins) but the response's
  `scheduled` field falls back to `0` and the wrapped error is
  surfaced through the RPC error channel so the operator sees the
  degraded mode rather than a silent "scheduled zero blocks" success.

Errors:

| Condition | RPC error |
|---|---|
| `[bridge].bridge_script_hex` not configured | `admin_rescanDeposits: bridge monitor not attached (configure [bridge].bridge_script_hex; see docs/operator/admin.md)` |
| Bridge configured but no chaintracks anchor | `admin_rescanDeposits: bridge rescanner not wired (cmd-side wire missing; tracked as WW-bridge-rescanner-attach)` (the cmd-side wire is conditional on `startBridgeBlockScanner` returning a handle, which requires chaintracks) |
| Daemon shutting down (supervisor goroutine exited) | `admin_rescanDeposits: bridge block scanner: handle closed (daemon shutting down)` |

## Multisig governance proposals

This section covers the spec 15 §"Multisig governance actions" flow:
operator → proposal → gossip → at-threshold → BSV broadcast.

### Threshold flow

```
operator A: admin_createGovernanceProposal(action, params?)
             │
             ▼ (gossip via libp2p MsgProposal)
all peers: store the proposal, ID-by-content-hash
             │
operator B: admin_signGovernanceProposal(id, signatureHex)
             │
             ▼ (gossip the updated proposal)
all peers: merge signatures into the local store
             │
             ▼ (every node independently)
when len(p.Signatures) >= p.Required:
             │
             ▼
governance.Workflow.OnReady fires →
governance.Broadcaster.OnReady (cmd/bsvm/main.go) →
covenant.BuildFreezeUnlockScript / BuildUnfreezeUnlockScript →
deploy/covenant.BuildUpgradeSpendTx →
arc.ARCClient.Broadcast →
covenant UTXO is spent on BSV with the frozen byte flipped
```

The broadcast happens **on every node that has reached threshold**.
ARC and the BSV mempool deduplicate the duplicate spends — the first
to land wins. There is no leader election here; this matches the
trustless-prover-race model used for the advance path.

### Signing convention

Governance keys sign `sha256(proposalID)` where `proposalID` is the
hex-encoded 32-byte content hash returned by
`admin_createGovernanceProposal`. The verifier accepts any DER
signature from a key listed in the shard's `GovernanceConfig.Keys`.

The wallet helper that produces the signature is the same BRC-3
`signMessage` flow operators already use — pass `proposalID` as the
message and post the resulting hex to `admin_signGovernanceProposal`.

### What broadcasts today

| Action | At-threshold behaviour |
|---|---|
| `freeze` | Builds + broadcasts the spend tx via ARC. Live covenant locking script is reused as the continuation output (the `frozen` flag flips inside the covenant state, not the script). |
| `unfreeze` | Identical to freeze, mirrored to the unfreeze method. |
| `upgrade` | **Deferred**. The proposal payload as defined in spec 15 does not carry the SP1 proof bundle that `BuildUpgradeUnlockScript` requires. The broadcaster surfaces a typed error referencing `WW-governance-payload-extension`; operators must fall back to `deploy/covenant/rotate-vk` for upgrades today. |

### Broadcast result fan-out

The broadcaster fans every result (success or failure) out through a
subscriber surface. The daemon registers one subscriber that logs
INFO on success:

```
governance proposal broadcast id=<proposal-id> action=freeze \
    txid=<bsv-txid> broadcastedAt=<rfc3339>
```

ARC failures are logged at WARN inside the broadcaster:

```
governance broadcaster: ARC broadcast failed id=<proposal-id> action=freeze \
    predicted_txid=<txid> err="<arc error>"
```

When ARC fails, the proposal stays in the workflow's local store
(its `BroadcastTxID` field stays empty) so an operator can retry by
re-issuing `admin_signGovernanceProposal` from any peer or by
restarting the daemon — the same threshold-crossing event will re-
fire `OnReady`.

### What happens when ARC isn't configured

The broadcaster degrades gracefully: `OnReady` logs a single WARN
and returns without attempting any spend-tx assembly. The proposal
stays in the workflow store. Configure `[bsv].arc_url` (or
`[[bsv.arc_endpoints]]` for multi-endpoint redundancy) before
relying on the at-threshold broadcast.

## Operator UX cheat-sheet

```bash
# Create a freeze proposal (single-key shards: this also broadcasts
# at threshold immediately because Required=1).
curl -X POST -H "Content-Type: application/json" \
     -H "Authorization: Bearer $BSVM_ADMIN_DEV_SECRET" \
     http://localhost:8545/admin/rpc \
     -d '{"jsonrpc":"2.0","id":1,"method":"admin_createGovernanceProposal","params":["freeze",null]}'

# List proposals + their signature counts.
curl ... -d '{"jsonrpc":"2.0","id":1,"method":"admin_listGovernanceProposals","params":[]}'

# Sign a multisig proposal from a second governance key.
curl ... -d '{"jsonrpc":"2.0","id":1,"method":"admin_signGovernanceProposal","params":["<proposal-id-hex>","<der-sig-hex>"]}'
```

The proposal IDs are content-addressed: two operators creating an
identical proposal (same action, same params) end up with the same
ID and their signatures merge automatically via gossip.

## Related code

* `pkg/governance/workflow.go` — the proposal store + at-threshold
  callback.
* `pkg/governance/broadcaster.go` — the at-threshold BSV broadcast
  (this is the closure registered as `OnReady` in
  `cmd/bsvm/main.go`).
* `cmd/bsvm/governance_broadcast.go` — the daemon-side wiring
  (covenant adapter + spend-tx builder).
* `pkg/covenant/freeze.go` — `BuildFreezeUnlockScript` /
  `BuildUnfreezeUnlockScript`.
* `pkg/covenant/upgrade.go` — `BuildUpgradeUnlockScript` (used by
  `rotate-vk` today; the multisig broadcaster will adopt it once the
  proposal payload extension lands).
* `deploy/covenant/rotate-vk.go` — the operator-driven upgrade path
  for VK rotations (orthogonal to the multisig governance flow).
