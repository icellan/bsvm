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
| `admin_getConfig` | Returns the live runtime config (`overlay.RuntimeConfigView`). |
| `admin_pauseProving` / `admin_resumeProving` | Flip the batcher. New txs are rejected while paused. |
| `admin_forceFlushBatch` | Flush the current pending batch immediately. |
| `admin_createGovernanceProposal` | Create + gossip a freeze/unfreeze/upgrade proposal (see below). |
| `admin_listGovernanceProposals` | Local view of the proposal queue. |
| `admin_signGovernanceProposal` | Verify a governance signature against an existing proposal. |

### Stubs / placeholders (TODO)

| Method | Status |
|---|---|
| `admin_setConfig` | Always errors with "live reload not yet implemented". Tracked as `admin-setConfig-live-reload`. |
| `admin_bridgeHealth` / `admin_rescanDeposits` | Return zero-state stubs until the bridge monitor is attached to the overlay node. Tracked as `admin-bridge-monitor-rpc`. |

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
