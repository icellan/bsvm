# Spec 17: Chaintracks, BEEF, and ARC / ARCADE Integration

## Goal

A BSVM overlay node runs **without a direct BSV full-node connection**
as its default configuration. All BSV interaction flows through three
boundaries:

1. **ARC / ARCADE** — the broadcast and transaction-status endpoint.
   The node submits covenant-advance transactions to ARC and receives
   a callback containing the BSV Unified Merkle Path (BUMP, BRC-74)
   once the transaction is mined.
2. **Chaintracks** — a Block-Headers-Service (BRC-64) feed that
   delivers BSV block headers only. The node uses headers as the
   trusted SPV anchor for BUMP verification. No block bodies, no UTXO
   set, no mempool subscription.
3. **BEEF** (BRC-62, Background Evaluation Extended Format) — the
   canonical wire format for sharing BSV transactions between shard
   nodes and between wallets and nodes. A BEEF envelope carries a
   target transaction plus the portion of its ancestry needed to
   SPV-verify it against chaintracks headers.

When a node wins a covenant-advance race and its transaction is mined,
the node upgrades its local BEEF for that advance with the BUMP
returned by ARC, then gossips the upgraded BEEF to its shard peers.
Peers update their view from the BEEF alone — they never consult BSV
directly, and they never trust the winner for anything: every claim
(signatures, covenant continuity, proof validity, BUMP-to-header
inclusion) is re-verified locally against chaintracks.

### Provider stack

The node sits on top of a pluggable provider stack. Defaults and
optional backups are wired as follows:

| Role                          | Default                       | Supplementary                 | Optional backup               |
|-------------------------------|-------------------------------|-------------------------------|-------------------------------|
| Transaction broadcast         | ARC / ARCADE                  | —                             | BSV node `sendrawtransaction` |
| Transaction-status callback   | ARC / ARCADE                  | WhatsOnChain status polling   | BSV node `gettransaction`     |
| Block headers (chaintracks)   | BRC-64 BHS                    | WhatsOnChain `/chain/info`    | BSV node `getblockheader`     |
| Ancestor tx lookup            | Peer BEEF store               | WhatsOnChain `/tx/:txid/hex`  | BSV node `getrawtransaction`  |
| Merkle proof (BUMP) retrieval | ARC callback                  | WhatsOnChain `/tx/:txid/proof`| BSV node `gettxoutproof`      |
| Server-side wallet / BEEF     | `go-wallet-toolbox`           | —                             | —                             |

The BSV-node backup row is provided so an operator who *does* run a
BSV node can use it — but no part of BSVM mandates it, and the
reference deployment (spec 16 devnet, and the mainnet node image) ship
with ARC + chaintracks + WhatsOnChain configured and the BSV-node
backup disabled.

This spec supersedes the `BSVClient` interface sketched in specs 10
and 11 (direct JSON-RPC to a BSV node, subscribe-to-blocks,
subscribe-to-DS). That interface is collapsed into a thinner
`BSVNetworkClient` built from `ARCClient`, `ChaintracksClient`,
`WhatsOnChainClient`, and the BEEF/wallet facilities of
`go-wallet-toolbox`. See **"Migration from spec 11's BSVClient"** at
the end of this document for the field-by-field mapping.

---

## Motivation

The existing design in spec 11 (`BSVClient.SubscribeBlocks`,
`SubscribeDoubleSpendAlerts`, `GetUTXOs`, `GetSpendingTx`) implicitly
assumes each shard node runs its own BSV full node or has trusted
JSON-RPC access to one. That is wrong for three reasons:

1. **Operational weight.** Running a BSV full node is a non-trivial
   commitment (disk, bandwidth, maintenance, keeping up with protocol
   changes). Most shard operators are EVM developers. Requiring a
   full node as a hard dependency concentrates shard operation among
   people who already run BSV infrastructure.
2. **Deposit-scanning asymmetry.** Spec 07's `BridgeMonitor`
   `processBlock()` scans every BSV block for deposit transactions to
   the bridge covenant. This forces every shard node to see every BSV
   block, which is the main reason a full node was assumed. A push
   model — the depositor's wallet hands the node a pre-proven deposit
   BEEF — eliminates that requirement.
3. **Peer verification cost.** When node A wins a race and node B
   observes node A's covenant-advance via its local BSV mempool, node
   B has to fetch ancestors to re-verify. In the BEEF model, node A
   ships the full verification bundle to node B in a single
   self-contained envelope. No fetch, no round-trip, no mempool
   subscription.

BEEF + chaintracks + ARC is the minimal SPV toolkit for a node to
participate in a shard with full verification but without running BSV
infrastructure. It aligns the BSVM operator profile with the rest of
the BSV ecosystem: ARC is the standard broadcaster, chaintracks is the
standard BRC-64 header service, BEEF is the standard wallet-to-service
transaction format, and `go-wallet-toolbox` is the standard Go
implementation of the BRC-100 wallet stack that already knows how to
consume all three.

---

## Architecture

```
┌────────────────────────────────────────────────────────────────────────┐
│  Overlay Node (Go)                                                      │
│                                                                         │
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │  Covenant Manager  /  Overlay  /  Bridge  /  Inbox                │  │
│  │  (specs 07, 10, 11)                                               │  │
│  └───────┬──────────────┬──────────────┬──────────────┬─────────────┘  │
│          │              │              │              │                 │
│          ▼              ▼              ▼              ▼                 │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │               BSVNetworkClient  (this spec, §10)                 │  │
│  │                                                                   │  │
│  │  ┌───────────┐  ┌──────────────┐  ┌──────────┐  ┌─────────────┐  │  │
│  │  │ BEEFStore │  │  FeeWallet   │  │ Peer BEEF│  │ Governance  │  │  │
│  │  │ (BRC-62)  │  │(go-wallet-   │  │  Gossip  │  │  Monitor    │  │  │
│  │  │           │  │  toolbox)    │  │          │  │             │  │  │
│  │  └─────┬─────┘  └──────┬───────┘  └────┬─────┘  └─────┬───────┘  │  │
│  │        │               │               │              │           │  │
│  │        └───────┬───────┴───────┬───────┴──────────────┘           │  │
│  │                ▼               ▼                                   │  │
│  │  ┌────────────────────┐  ┌────────────────────┐                    │  │
│  │  │   ARCClient        │  │  ChaintracksClient │                    │  │
│  │  │  (primary tx path) │  │  (BRC-64 headers)  │                    │  │
│  │  └─────────┬──────────┘  └─────────┬──────────┘                    │  │
│  │            │                       │                               │  │
│  │  ┌─────────┴───────────┐  ┌────────┴────────────┐                  │  │
│  │  │ WhatsOnChainClient  │  │  BSVNodeClient      │                  │  │
│  │  │ (supplementary      │  │  (optional backup,  │                  │  │
│  │  │  lookup)            │  │   disabled default) │                  │  │
│  │  └─────────────────────┘  └─────────────────────┘                  │  │
│  └──────────────────────────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────────────────────┘
         │                       │                  │             │
         │ HTTPS + BRC-104       │ HTTPS            │ libp2p      │ JSON-RPC
         │ (POST /v1/tx,         │ (streaming       │ (spec 11    │ (optional)
         │  callback)            │  headers)        │  gossip)    │
         ▼                       ▼                  ▼             ▼
    ARC / ARCADE           Chaintracks /       Shard peers      BSV node
    (TAAL, GP,              WhatsOnChain                        (self-hosted
     self-hosted)           /chain/info                          only)
```

Compare to spec 11's earlier diagram: the single **BSV Network** box
that sat below the overlay node is replaced by four orthogonal
services, each swappable and with its own health envelope. The node
holds no full-node state. It holds headers, BEEFs for transactions
that matter to it (its own covenant chain, recent deposits and
withdrawals), and fee-wallet UTXO metadata that came in via BEEF.

---

## BEEF: The Wire Format

BSVM adopts **BRC-62 BEEF** unchanged as the canonical transaction
serialisation between any pair of BSVM participants (node↔node,
wallet↔node, node↔external indexer). The format and semantics match
`go-wallet-toolbox`'s BEEF implementation byte-for-byte, so a BEEF
produced by any `go-wallet-toolbox`-based wallet is directly consumable
by a shard node and vice versa.

A BEEF bundles:

- The target transaction (raw BSV transaction bytes).
- Every ancestor transaction required to recover the input scripts the
  target spends, recursively, up to a frontier.
- A BUMP (BRC-74) for every frontier ancestor that has been mined,
  proving its inclusion under a specific block's Merkle root.

A BEEF is **SPV-verifiable** against chaintracks headers alone: for
every ancestor covered by a BUMP, the verifier walks the BUMP to a
Merkle root and checks that root against a known block header. For
the target transaction itself, the verifier re-executes each input
script against the ancestor outputs the inputs reference (see
"Script Verification" below).

### Confirmation state encoded by BEEF

A BEEF is in one of two states with respect to its target:

- **Unconfirmed-target BEEF**: every ancestor covered by a BUMP, target
  has no BUMP. This is what a node produces and ships on broadcast.
- **Confirmed-target BEEF**: the target also carries a BUMP anchored
  under a block header that chaintracks knows. This is what a node
  ships after ARC delivers the callback.

BEEFs are upgraded in place: the unconfirmed variant is replaced by
the confirmed variant when the BUMP arrives. Peers holding the
unconfirmed BEEF accept the confirmed BEEF as an upgrade keyed by
txid; they do not re-verify the tx body, only the new BUMP.

### Gossip envelope

On the libp2p BEEF-gossip topic, a BEEF is wrapped in a 17-byte
envelope header so peers can route it without parsing the BEEF
first:

```
Gossip envelope (17-byte prefix + BRC-62 BEEF bytes):
  [4 bytes]  Topic magic:    "BSVB" (0x42535642)
  [1 byte]   Envelope ver:   0x01
  [1 byte]   Intent:
               0x01 = covenant-advance (unconfirmed)
               0x02 = covenant-advance (confirmed, target BUMP attached)
               0x03 = bridge-deposit (confirmed)
               0x04 = fee-wallet-funding (confirmed)
               0x05 = inbox-submission (unconfirmed or confirmed)
               0x06 = governance action (confirmed)
  [1 byte]   Flags:
               bit 0 = shard-bound (shard_id meaningful)
               bits 1..7 = reserved, must be 0
  [8 bytes]  Shard ID (uint64 BE, zero when shard-bound=0)
  [2 bytes]  Reserved (0x00 0x00)
  [remainder] BRC-62 BEEF bytes
```

Fee-wallet-funding is the only intent that is not shard-bound —
funding goes to an address, not a covenant. Every other intent is
shard-bound to prevent cross-shard misrouting.

### BEEFStore

The node's authoritative view of the covenant chain and the ambient
BEEF-relevant transactions lives in a local BEEF store keyed by txid,
backed by the same LevelDB/Pebble instance as the rest of node state
(spec 02) under a dedicated keyspace `beef:<txid>`:

```go
// pkg/beef/store.go

type BEEFStore interface {
    // Put stores a BEEF. If a BEEF with the same txid already exists,
    // the store keeps the "better" one: confirmed beats unconfirmed,
    // and among confirmed entries the deeper BUMP wins.
    Put(env *BEEFEnvelope) error

    // Get returns the BEEF for a txid, or nil if not present.
    Get(txid [32]byte) (*BEEFEnvelope, error)

    // GetBUMP returns the BUMP for a confirmed tx, or nil if unknown
    // or still unconfirmed.
    GetBUMP(txid [32]byte) (*BUMP, error)

    // Delete removes a BEEF. Only used for explicit pruning (e.g.,
    // deep reorg). BEEFs are never auto-expired; the covenant chain
    // references them indefinitely.
    Delete(txid [32]byte) error

    // Iterate all BEEFs of a given intent, oldest first.
    Iterate(intent uint8) (BEEFIterator, error)
}

type BEEFEnvelope struct {
    Intent      uint8
    ShardID     uint64      // 0 for shard-agnostic envelopes
    Beef        []byte      // BRC-62 binary
    TargetTxID  [32]byte
    Confirmed   bool
    BlockHeight uint64      // 0 if unconfirmed
    ReceivedAt  time.Time
}
```

The store is append-mostly. A BEEF for a covenant advance at L2 block
N is kept for the lifetime of the shard (auditors and syncing nodes
rely on it). Fee-wallet-funding and bridge-deposit BEEFs are kept
until the node has confirmed their outputs are fully consumed and
finalised — a space-reclamation policy, not a correctness requirement.

`go-wallet-toolbox`'s internal `BeefStore` is compatible with this
interface; the BSVM implementation wraps it and adds the intent +
shard-id metadata columns.

---

## Chaintracks: Block Headers Service

Chaintracks is a strict BRC-64 Block Headers Service client. It streams
BSV block headers from one or more upstream providers and persists them
locally, giving the node a verified view of the BSV header chain. The
shard uses `go-wallet-toolbox`'s `ChaintracksClient` as the reference
implementation.

### Responsibilities

1. **Bootstrap from a trusted seed.** The shard genesis config
   (spec 08) includes a BSV block-header checkpoint: `(height, hash)`
   at the height of the genesis covenant transaction. Chaintracks
   starts from this checkpoint and streams forward.
2. **Stream forward.** As new BSV blocks are mined, upstreams push new
   headers. The client verifies PoW and chain linkage before
   accepting.
3. **Serve `HeaderByHash`, `HeaderByHeight`, `Tip`, `MerkleRootAtHeight`.**
   These are the only queries the rest of the node performs.
4. **Reorg handling.** If an upstream delivers a competing header at a
   known height, the client compares cumulative work, switches chains
   if the new chain has more work, and emits `ReorgEvent` with the
   fork point. The overlay subscribes and handles it per spec 11's
   existing rollback protocol.

### Interface

```go
// pkg/chaintracks/client.go

type ChaintracksClient interface {
    Tip() (*BlockHeader, error)
    HeaderByHash(hash [32]byte) (*BlockHeader, error)
    HeaderByHeight(height uint64) (*BlockHeader, error)
    MerkleRootAtHeight(height uint64) ([32]byte, error)
    SubscribeReorgs(ctx context.Context) (<-chan *ReorgEvent, error)
    Confirmations(height uint64, blockHash [32]byte) (int64, error)
}

type BlockHeader struct {
    Height     uint64
    Hash       [32]byte
    PrevHash   [32]byte
    MerkleRoot [32]byte
    Timestamp  uint32
    Bits       uint32
    Nonce      uint32
    Work       *big.Int   // cumulative chainwork
}

type ReorgEvent struct {
    CommonAncestor [32]byte
    OldTip         [32]byte
    NewTip         [32]byte
    OldChainLen    uint64
    NewChainLen    uint64
}
```

### Upstream providers and quorum

The chaintracks client supports **multiple parallel upstream providers**
and majority-agreement as a safeguard against a single provider lying:

```toml
[chaintracks]
# Minimum upstreams that must agree on a header before it is committed.
# 1 = trust any upstream (faster to tip, less robust).
# 2 = require two agreeing upstreams (default for mainnet shards).
quorum = 2

[[chaintracks.upstream]]
name = "bhs-primary"
url  = "https://headers.example.com/api/v1/chain"
kind = "brc-64"

[[chaintracks.upstream]]
name = "bhs-secondary"
url  = "https://headers.other.example/headers"
kind = "brc-64"

[[chaintracks.upstream]]
# Supplementary: WhatsOnChain as a header tip/cross-check source.
name = "whatsonchain"
url  = "https://api.whatsonchain.com/v1/bsv/main"
kind = "whatsonchain"

[[chaintracks.upstream]]
# Optional backup: a self-hosted BSV node. Disabled by default.
name = "local-bsv-node"
url  = "http://127.0.0.1:8332"
kind = "bsv-rpc"
rpc_user = "..."
rpc_pass = "..."
enabled = false
```

If `quorum` upstreams disagree at a given height, the client refuses
to commit and alerts the operator. The overlay treats chaintracks-
stalled as BSV-connectivity-degraded (same handling as `BSVDegraded`
in spec 11's connectivity monitor): execution continues, covenant
broadcasts pause, alerts fire.

Headers occupy 80 bytes on disk each plus a small index. One year of
BSV headers is ~4 MB. Storage is colocated with the node at
`data/chaintracks/`.

---

## ARC / ARCADE: Broadcast and Callback (Primary)

BSVM's primary transaction path is ARC-protocol-compatible. Both the
reference ARC implementation and ARCADE-family services are supported
with the same client code; the user's BRC-104-compliant
authentication (spec 15) is used as the auth envelope when required
by the endpoint.

The node uses two ARC endpoints:

1. **`POST /v1/tx`** — broadcast. The body is a BEEF (ARC accepts
   BEEF-formatted inputs) or raw tx bytes with extended metadata.
   Response includes the txid and the broadcast status
   (`SEEN_ON_NETWORK`, `ACCEPTED_BY_NETWORK`, etc.).
2. **Callback** — a webhook URL the node registers at broadcast time.
   When the transaction is mined, ARC POSTs a status update with the
   BUMP for the mined transaction. ARC also posts DOUBLE-SPEND and
   REJECTED updates.

The node publishes its callback URL via `X-CallbackUrl` and
`X-CallbackToken` headers on the broadcast request. The token is a
shared secret used to authenticate incoming callbacks.

### Interface

```go
// pkg/arc/client.go

type ARCClient interface {
    Broadcast(ctx context.Context, beef []byte) (*BroadcastResponse, error)
    Status(ctx context.Context, txid [32]byte) (*TxStatus, error)
    Ping(ctx context.Context) error
}

type BroadcastResponse struct {
    TxID        [32]byte
    Status      ARCStatus
    ExtraInfo   string
    SubmittedAt time.Time
}

type TxStatus struct {
    TxID           [32]byte
    Status         ARCStatus
    BlockHash      [32]byte
    BlockHeight    uint64
    BUMP           *BUMP        // nil if unmined
    CompetingTxIDs [][32]byte   // non-empty on double-spend
    MerklePath     []byte       // raw BUMP bytes (BRC-74)
}
```

`go-wallet-toolbox` exposes an `ArcBroadcaster` implementation of this
interface that the node uses directly; no separate reimplementation is
needed.

### Callback HTTP handler

Inside the overlay's HTTP server (same server as spec 15's explorer
UI and the JSON-RPC endpoint), the ARC callback arrives at
`POST /bsv/arc/callback`:

```go
// pkg/rpc/arc_callback.go

func (h *ARCCallbackHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
    if r.Header.Get("X-ARC-Callback-Token") != h.expectedToken {
        http.Error(w, "unauthorized", http.StatusUnauthorized)
        return
    }
    var update ARCStatusUpdate
    if err := json.NewDecoder(r.Body).Decode(&update); err != nil {
        http.Error(w, "bad request", http.StatusBadRequest)
        return
    }
    switch update.Status {
    case StatusMined:
        h.handleMined(&update)
    case StatusDoubleSpendAttempted, StatusDoubleSpendConfirmed:
        h.overlay.HandleARCDoubleSpend(&update)
    case StatusRejected:
        h.overlay.HandleARCRejection(&update)
    }
    w.WriteHeader(http.StatusNoContent)
}

func (h *ARCCallbackHandler) handleMined(u *ARCStatusUpdate) {
    existing, _ := h.beefStore.Get(u.TxID)
    if existing == nil {
        slog.Warn("arc callback for unknown tx", "txid", u.TxID)
        return
    }
    bump, err := DecodeBUMP(u.MerklePath)
    if err != nil { return }
    if err := h.verifier.VerifyBUMP(bump, u.TxID); err != nil {
        slog.Error("arc callback: BUMP verification failed", "err", err)
        return
    }
    upgraded, _ := UpgradeBEEF(existing.Beef, u.TxID, bump)
    confirmed := &BEEFEnvelope{
        Intent: existing.Intent, ShardID: existing.ShardID,
        Beef: upgraded, TargetTxID: existing.TargetTxID,
        Confirmed: true, BlockHeight: bump.BlockHeight,
        ReceivedAt: time.Now(),
    }
    h.beefStore.Put(confirmed)
    h.gossip.Publish(confirmed)
    h.overlay.OnBEEFConfirmed(u.TxID, bump.BlockHeight)
}
```

### Callback reachability and polling fallback

The ARC callback URL must be reachable from ARC's infrastructure.
Two deployment patterns:

- **Direct**: the node's HTTPS endpoint is reachable at
  `https://<public-hostname>/bsv/arc/callback`.
- **Relayed**: the node sits behind a tunnel (Cloudflare Tunnel,
  ngrok, or a shard-operated relay).

If callback reachability is impossible (e.g., CGNAT), the node falls
back to **polling mode**: every 2 seconds, for each in-flight broadcast
tracked in a local `InFlightBroadcastQueue`, call
`ARCClient.Status(txid)`. Strictly inferior to the callback path but
supported for dev and for nodes that cannot expose HTTP. Turned on
with `arc.callback_mode = "poll"` in config.

### Multi-endpoint redundancy

A node can register multiple ARC endpoints:

```toml
[[arc]]
name = "taal"
url  = "https://arc.taal.com"
callback_url = "https://my-node.example.com/bsv/arc/callback"
callback_token = "..."

[[arc]]
name = "gorillapool"
url  = "https://arc.gorillapool.io"
callback_url = "https://my-node.example.com/bsv/arc/callback"
callback_token = "..."
```

When broadcasting, the node submits to **all** configured ARC
endpoints in parallel. A broadcast succeeds as soon as any one ARC
returns `SEEN_ON_NETWORK` or deeper. Callbacks may arrive from any
ARC; the handler is idempotent on txid. Per-ARC latency and success
rate are tracked in metrics (`bsvevm_arc_broadcast_latency_seconds`,
`bsvevm_arc_broadcast_failures_total`).

---

## WhatsOnChain: Supplementary Lookup

WhatsOnChain (WoC) is **not** a primary path — it is a supplementary
HTTP lookup service that fills gaps ARC and chaintracks do not cover.
It is enabled by default on mainnet and regtest shards and is used
for:

1. **Ancestor fetching for BEEF completion.** When a peer sends a
   BEEF whose ancestor frontier references a tx we don't have and we
   cannot reconstruct from our BEEFStore, WoC's `GET /tx/:txid/hex`
   and `GET /tx/:txid/proof` (or `/tx/:txid/beef` where available)
   are used to fetch the missing ancestor.
2. **Fee-wallet bootstrap.** When a new node starts with a fee wallet
   address that already has UTXOs (because the operator funded it
   externally), `GET /address/:addr/unspent` returns the UTXO set,
   and `GET /tx/:txid/beef` (or individual tx + merkle-proof calls)
   builds the funding BEEFs.
3. **Header cross-check.** `GET /chain/info` and
   `GET /block/height/:h/header` are used as a supplementary upstream
   for chaintracks quorum (see `kind = "whatsonchain"` in the
   chaintracks config above).
4. **Bridge-deposit fallback.** If the primary push model fails (a
   depositor's wallet cannot reach any shard node), a separate
   relayer process can poll `GET /address/:addr/history` for the
   bridge covenant addresses and build deposit BEEFs from WoC data
   — see spec 07 revision in this document.

### Interface

```go
// pkg/whatsonchain/client.go

type WhatsOnChainClient interface {
    // RawTx returns the raw transaction bytes for a given txid.
    RawTx(ctx context.Context, txid [32]byte) ([]byte, error)

    // TxBEEF returns a BEEF for a given txid, if WoC supports /beef
    // for this network. Returns ErrUnsupported if not.
    TxBEEF(ctx context.Context, txid [32]byte) ([]byte, error)

    // TxMerkleProof returns the Merkle path for a mined tx.
    TxMerkleProof(ctx context.Context, txid [32]byte) (*BUMP, error)

    // AddressUnspent returns the UTXO set for an address.
    AddressUnspent(ctx context.Context, addr string) ([]UTXO, error)

    // AddressHistory returns confirmed tx history for an address.
    AddressHistory(ctx context.Context, addr string, since uint64) ([]HistoryEntry, error)

    // ChainInfo returns the current tip height and hash.
    ChainInfo(ctx context.Context) (*ChainInfo, error)

    // BlockHeaderByHeight returns a single block header.
    BlockHeaderByHeight(ctx context.Context, height uint64) (*BlockHeader, error)

    Ping(ctx context.Context) error
}

type HistoryEntry struct {
    TxID        [32]byte
    BlockHeight uint64
    Confirmed   bool
}

type ChainInfo struct {
    Height     uint64
    BestHash   [32]byte
    Difficulty float64
    Chain      string  // "main" / "test" / "regtest"
}
```

### Rate limits and API keys

WhatsOnChain imposes per-IP rate limits on unauthenticated calls.
The config supports an optional API key and caches recently-fetched
ancestors for 24 hours to avoid re-querying.

```toml
[whatsonchain]
enabled = true
url     = "https://api.whatsonchain.com/v1/bsv/main"
api_key = ""          # optional; higher rate limits with a key
cache_ttl = "24h"
```

WhatsOnChain is never the sole source of truth. Every tx fetched from
WoC is placed into the `BEEFStore` only after its BUMP verifies
against chaintracks headers; this means a lying WoC cannot insert
fake confirmations (it can only fail to answer or return data the
SPV layer rejects).

---

## BSV Node: Optional Backup

A direct BSV node JSON-RPC client is supported as an **optional
backup** for operators who already run a BSV node. It is **disabled
by default** on mainnet and in spec 16's devnet (which uses only
ARC + chaintracks + WoC against BSV regtest).

```toml
[bsv_node]
enabled = false
url     = "http://127.0.0.1:8332"
rpc_user = "..."
rpc_pass = "..."
# Which roles this backup can fill. Each defaults to false.
use_for_broadcast     = false
use_for_ancestors     = false
use_for_headers       = false
use_for_merkle_proofs = false
```

The BSV-node client implements the same interfaces as ARC / WoC /
chaintracks for the roles it is enabled for:

```go
// pkg/bsvnode/client.go

type BSVNodeClient interface {
    // Satisfies ARCClient.Broadcast (only when use_for_broadcast).
    SendRawTransaction(ctx context.Context, rawTx []byte) ([32]byte, error)

    // Satisfies ChaintracksClient upstream (only when use_for_headers).
    GetBlockHeader(ctx context.Context, hash [32]byte) (*BlockHeader, error)
    GetBlockHeaderByHeight(ctx context.Context, height uint64) (*BlockHeader, error)

    // Satisfies WhatsOnChainClient.RawTx (only when use_for_ancestors).
    GetRawTransaction(ctx context.Context, txid [32]byte) ([]byte, error)

    // Satisfies WhatsOnChainClient.TxMerkleProof (only when
    // use_for_merkle_proofs). Uses gettxoutproof under the hood and
    // re-shapes the output into a BUMP.
    GetTxOutProof(ctx context.Context, txid [32]byte) (*BUMP, error)
}
```

When enabled for a role, the BSV-node client is tried **last** in
the failover chain — ARC/chaintracks/WoC are always tried first.
This keeps the default, ARC-centric hot path active even on nodes
that happen to run their own BSV node; the backup only fires under
failure.

---

## Server-Side Wallet: go-wallet-toolbox

The shard node uses `go-wallet-toolbox` as its server-side wallet
library. `go-wallet-toolbox` provides, out of the box:

- A BRC-100-compliant wallet with BRC-42/43 key derivation.
- A persistent `WalletStorage` backend (SQLite or Postgres).
- `WalletCrypto` for signing (BRC-3 ECDSA) and BRC-104 mutual auth.
- A `WalletBroadcaster` abstraction that wraps ARC.
- A `ChaintracksClient` (the BRC-64 client used in §Chaintracks above).
- BEEF encode/decode and BUMP verification primitives.
- A UTXO manager ("basket" in BRC-100 terms) with concurrency-safe
  reservation and spend tracking.

BSVM wires these building blocks into three responsibilities:

### 1. The fee wallet

The fee wallet pays BSV mining fees for covenant-advance transactions
(and bridge/governance/inbox transactions). It replaces the custom
`FeeWallet` sketched in spec 10 with a thin wrapper around
`go-wallet-toolbox`:

```go
// pkg/covenant/fee_wallet.go

import "github.com/bsv-blockchain/go-wallet-toolbox/pkg/wallet"

type FeeWallet struct {
    w *wallet.Wallet   // from go-wallet-toolbox

    // BRC-42/43 protocol and key IDs under which fee-wallet UTXOs
    // are held (so this wallet can coexist with other uses of the
    // same storage backend).
    protocolID [2]any
    keyID      string

    // Basket name for fee-funding UTXOs.
    basket string
}

// SelectFunding picks UTXOs summing to >= requiredSats + estimatedFee,
// reserving them atomically so concurrent advances don't double-spend.
func (fw *FeeWallet) SelectFunding(ctx context.Context, requiredSats, estimatedFee uint64) ([]wallet.UTXO, wallet.Release, error) {
    return fw.w.ListAndReserveOutputs(ctx, wallet.ListOutputsArgs{
        Basket:  fw.basket,
        Minimum: requiredSats + estimatedFee,
    })
}

// SignFeeInputs signs the fee-funding inputs of a covenant-advance tx.
// The covenant input is NOT signed here — the STARK proof authorizes it.
func (fw *FeeWallet) SignFeeInputs(ctx context.Context, tx *wallet.Tx, feeInputIdxs []int) error {
    return fw.w.SignInputs(ctx, tx, feeInputIdxs, fw.protocolID, fw.keyID)
}

// IngestFunding accepts a fee-wallet-funding BEEF (intent 0x04), verifies
// it against chaintracks, and credits the output(s) that pay this wallet's
// address. Used when an operator tops up the fee wallet by having their
// wallet POST a funding BEEF to the node, or by the WoC bootstrap path.
func (fw *FeeWallet) IngestFunding(ctx context.Context, env *BEEFEnvelope) error {
    if err := fw.w.VerifyBEEF(ctx, env.Beef); err != nil {
        return err
    }
    return fw.w.ImportOutputsFromBEEF(ctx, env.Beef, fw.basket)
}

// ReconcileOnStartup lists UTXOs from wallet storage, checks each against
// ARC/WoC/BSV-node to confirm it is still unspent, and prunes stale ones.
// Then, optionally, scans the wallet address via WhatsOnChain.AddressUnspent
// to discover UTXOs that arrived while the node was offline.
func (fw *FeeWallet) ReconcileOnStartup(ctx context.Context, net BSVNetworkClient) error { ... }
```

All of `go-wallet-toolbox`'s persistence guarantees (WAL, atomic
reservation/release, crash recovery) transfer directly. The custom
`FeeWalletDB`, `Consolidate`, and `ReconcileOnStartup` scaffolding in
spec 10 is replaced by the corresponding `wallet-toolbox` APIs; what
remains BSVM-specific is only the basket name, the BRC-42/43
protocolID/keyID scheme, and the BSVM-specific ingest path for
funding BEEFs.

### 2. Bridge-covenant-adjacent signing

`go-wallet-toolbox` also owns the signing of any BSV transaction the
node needs to build that is **not** a covenant advance: bridge
deposit-credit acknowledgements (if the bridge design requires
returning a change output), inbox-covenant-advance transactions with
P2PKH fee inputs, and governance freeze/upgrade transactions (signed
by a configured governance key, multisig-aware — see spec 15).

### 3. BEEF construction and verification

The node does not hand-roll BEEF. Every BEEF produced by the node is
built via `go-wallet-toolbox`'s `BuildBEEF(targetTx, ancestors[],
bumpsByTxID)` helper, and every BEEF consumed by the node is
verified via the toolbox's `VerifyBEEF(beef, chaintracks)` helper.
This ensures byte-for-byte compatibility with any BRC-100 wallet
producing BEEFs for the node to consume (bridge deposits, inbox
submissions).

### Storage model

`go-wallet-toolbox` uses a SQLite or Postgres backend for its wallet
storage. The mainnet reference deployment uses SQLite colocated at
`data/wallet/wallet.db`; multi-node operators with shared DB
infrastructure can point the toolbox at Postgres. The BSVM storage
spec (spec 02) is extended to treat `data/wallet/` as wallet-toolbox
managed — BSVM code reads and writes the shard's EVM state
independently.

---

## Unified BSVNetworkClient

All of the above is composed into a single client interface the rest
of BSVM imports:

```go
// pkg/bsvnetwork/client.go

type BSVNetworkClient interface {
    // Broadcast a BEEF. Returns as soon as any configured primary
    // endpoint accepts.
    Broadcast(ctx context.Context, beef []byte) (*BroadcastResponse, error)

    // Tip height of the BSV best chain (from chaintracks).
    ChainTip() (uint64, [32]byte, error)

    // Confirmations for a mined tx. Returns 0 if unknown or
    // unmined, -1 if reorged off.
    Confirmations(txid [32]byte) (int64, error)

    // FetchAncestor fetches the raw bytes of a given txid, trying
    // BEEFStore → WhatsOnChain → BSV node (if enabled). Used for
    // BEEF completion when building or verifying envelopes.
    FetchAncestor(ctx context.Context, txid [32]byte) ([]byte, error)

    // FetchBUMP fetches a merkle path for a mined tx, trying
    // ARC.Status → WhatsOnChain.TxMerkleProof → BSV node
    // GetTxOutProof (if enabled).
    FetchBUMP(ctx context.Context, txid [32]byte) (*BUMP, error)

    // SubscribeReorgs proxies chaintracks.SubscribeReorgs.
    SubscribeReorgs(ctx context.Context) (<-chan *ReorgEvent, error)

    // HealthStatus reports per-provider reachability.
    HealthStatus() NetworkHealth

    // Lower-level sub-interfaces, exposed for subsystems that need
    // provider-specific behaviour (e.g., the callback handler
    // needs direct ARCClient access).
    ARC() ARCClient
    Chaintracks() ChaintracksClient
    WoC() WhatsOnChainClient                 // nil if disabled
    BSVNode() BSVNodeClient                   // nil if disabled
    Wallet() *wallet.Wallet                   // go-wallet-toolbox
    BEEFStore() BEEFStore
}

type NetworkHealth struct {
    ARC          []ProviderHealth  // one per configured ARC endpoint
    Chaintracks  []ProviderHealth  // one per configured upstream
    WoC          *ProviderHealth   // nil if disabled
    BSVNode      *ProviderHealth   // nil if disabled
}

type ProviderHealth struct {
    Name         string
    Reachable    bool
    LastSuccess  time.Time
    Latency      time.Duration
    ErrorRate24h float64
}
```

Constructing it is straightforward from config:

```go
net, err := bsvnetwork.New(ctx, cfg.BSVNetwork)
// Inside New: build ARCClient (multi-endpoint), ChaintracksClient
// (multi-upstream with quorum), WhatsOnChainClient (if enabled),
// BSVNodeClient (if enabled), wallet-toolbox Wallet (init storage,
// load keys), BEEFStore; wire them together and return.
```

---

## The Advance Path, End-to-End

The covenant-advance flow from spec 11 is refined for the BEEF model:

```
1. Overlay executes batch, produces STARK proof.
2. Covenant Manager builds the BSV tx:
     - Covenant input     (proof-authorized, no signature)
     - Fee input(s)       (FeeWallet.SelectFunding + SignFeeInputs)
     - Covenant output    (new state)
     - OP_RETURN output   (batch data)
     - Fee change output
3. BEEFStore.WrapAsUnconfirmedBEEF(tx) constructs a BEEF by:
     a. Including tx as the target (no target BUMP).
     b. Including the previous covenant tx as an ancestor. If it is
        confirmed (BUMP in store), include that BUMP; otherwise
        include its own ancestor frontier recursively.
     c. Including each fee-funding ancestor tx (BUMPs from store).
4. Broadcast:
     - Gossip.Publish(intent=0x01, env)           // peers, immediate
     - net.Broadcast(beef)                         // ARC / ARCADE
5. Append to TxCache as unconfirmed (spec 11 behaviour).
6. Return the L2 receipt to the user (status: "proven").
7. When the ARC callback arrives with a BUMP:
     a. Verify BUMP against chaintracks.
     b. UpgradeBEEF → confirmed.
     c. BEEFStore.Put(confirmed envelope).
     d. Gossip.Publish(intent=0x02, env)           // confirmed
     e. TxCache.Confirm(txid, block_height).
     f. updateFinalizedTip() per spec 11.
```

The gossip at step 4 lets peers follow the covenant tip in real time
without waiting for BSV mining. The gossip at step 7 is what *proves*
inclusion — peers previously held a speculative "someone won the race"
state; now they hold a BSV-anchored one that reconciles with their
chaintracks view.

---

## The Follower Path, End-to-End

When a peer receives a covenant-advance BEEF (intent 0x01 or 0x02):

```
1. Check shard binding: envelope.shard_id must match this node's
   shard_id. Drop otherwise.
2. Decode the BEEF via wallet-toolbox.
3. Verify ancestors: for every ancestor BUMP, verify against
   chaintracks. Reject if any BUMP fails, if any BUMP's block is
   not on chaintracks' best chain, or if any input-referenced
   ancestor is missing — in which case the node MAY call
   net.FetchAncestor(txid) to complete the BEEF before giving up.
4. Verify target inputs:
     a. Re-derive each input's referenced output from ancestors.
     b. Execute each input's unlocking script against the referenced
        locking script using the Bitcoin Script evaluator.
5. Recognise the target as a covenant-advance: its first input must
   spend a UTXO the node currently treats as the covenant tip (or a
   recent ancestor, for race-resolution).
6. Extract batch data from the OP_RETURN output and re-execute the
   batch as spec 11's `ExecutionVerifier.VerifyCovenantAdvance`
   describes. Compare the computed state root to the one committed
   by the covenant.
7. Extract the SP1 proof from the unlocking script of the covenant
   input and call the local prover to verify the proof off-chain
   (since it has been verified on-chain by BSV Script evaluation,
   this step is redundant for confirmed envelopes but cheap and
   valuable for unconfirmed ones, where on-chain evaluation has not
   happened yet).
8. Accept: update TxCache, advance the covenant tip, replay any
   orphaned transactions (spec 11's race-loss logic).
9. If the envelope is confirmed (intent=0x02), additionally verify
   the target's BUMP and update confirmation/finalisation bookkeeping.
```

When a node joins a shard fresh, it bootstraps by repeatedly calling
a peer's `GET /bsvm/beef/covenant-chain?from=<tip>` RPC (exposed on
the same HTTP server as the explorer UI, spec 15) to pull the
covenant BEEFs sequentially, verifying each via the follower path
above, until it has caught up to the shard tip. This entirely
replaces spec 11's `SyncFromBSV` walk via `findNextCovenantAdvance` —
no BSV node or block-body source is consulted at all.

### Distinguishing race-loss from BSV reorg

With spec 11's BSV-node subscription model, a node distinguished
race-loss from BSV-reorg via mempool double-spend alerts and block
reorgs. In the BEEF model:

- **Race loss**: a peer gossips a covenant-advance BEEF (intent 0x01
  or 0x02) whose first input spends the same UTXO as our pending
  unconfirmed advance, and whose target txid differs from ours. The
  node compares timestamps or, if both are confirmed, compares block
  heights. On loss, call `ReplayFromWinner` (spec 11) using the peer's
  batch data.
- **Reorg**: chaintracks emits a `ReorgEvent` whose fork point is at
  or below the block height at which our confirmed covenant advance
  was mined. This invalidates our confirmed BEEF. The node clears the
  `Confirmed` flag on affected envelopes, re-broadcasts them via ARC,
  and waits for new callbacks. If the reorg crossed the finalized
  depth (`ConfirmationsFinalized = 6`), spec 11's full `Rollback` is
  invoked.

ARC's double-spend callback remains a supplementary signal: if ARC
reports `DOUBLE_SPEND_CONFIRMED` on our tx and we haven't yet seen a
peer BEEF, the node calls `net.FetchAncestor(competitor_txid)` and
`net.FetchBUMP(competitor_txid)` to build the winner's BEEF locally,
then proceeds as if we'd received it via peer gossip.

---

## Bridge Deposits: Push Model via BEEF

Spec 07's deposit flow, which scans every BSV block for deposits to
the bridge covenant, is replaced by a **push model**:

```
DEPOSIT (BSV → L2):
  1. User's wallet (BRC-100-compliant) builds a deposit BSV tx:
       Output 0: <shard_bridge_covenant>  <deposit_amount>
       Output 1: OP_RETURN "BSVM" 0x03 <shard_id> <l2_address>
       Output 2: change
  2. User's wallet broadcasts the tx (via its own ARC) AND waits for
     confirmation.
  3. Once confirmed, the wallet builds a BEEF for the deposit tx
     (target = deposit tx, ancestors + target BUMP attached) and
     POSTs it to any shard node's new endpoint:

       POST /bsvm/bridge/deposit
         Content-Type: application/octet-stream
         Body: BRC-62 BEEF bytes

  4. Node verifies the BEEF:
       a. net.VerifyBEEF(body) — ancestors verify against chaintracks.
       b. Target tx script check: output 0 pays the shard's bridge
          covenant address; output 1 has the 0x03 deposit envelope.
       c. Target BUMP verifies against chaintracks (≥ 6 confirmations).
  5. If valid, node emits a bridge-deposit BEEF to peers (intent 0x03)
     so every shard node sees the same deposit and credits it
     deterministically.
  6. Node includes the deposit as a system transaction on the next
     L2 block, following spec 07's deposit-horizon determinism rules.
     The deposit horizon is now computed as "the maximum BSV block
     height for which the node has received bridge-deposit BEEFs and
     chaintracks has confirmed at depth ≥ 6".
```

The `/bsvm/bridge/deposit` endpoint is **open** (no auth required)
because BEEF verification is the only gate that matters — a fake or
malicious BEEF fails chaintracks-SPV and is dropped. Accepting a
valid BEEF from any sender cannot harm the shard.

### Fallback: WoC-scanned deposit relay

For users whose wallets do not yet produce BEEFs (edge cases or older
wallets), a separate **relayer process** polls
`WhatsOnChain.AddressHistory(<bridge_covenant_addr>, since=last_scanned)`
every few BSV blocks, constructs a BEEF for each new deposit via
`net.FetchAncestor` + `net.FetchBUMP`, and POSTs it to the shard
node on the depositor's behalf. The relayer may be operated by the
shard, by a third party, or by the depositor themselves; it is not
a privileged role.

### Relationship to the deposit determinism protocol (spec 07)

Spec 07's deposit-horizon determinism rules are unchanged — what
changes is the **source** of the deposit set. Previously each node
scanned BSV blocks independently; now each node sees deposit BEEFs
via gossip. The determinism rules (horizon chosen by proposer,
canonical sort order by `(BSV block height, BSV tx index, output
index)`, monotonic horizon, replay verbatim) still apply and still
make deposit inclusion a public-inputs property of the proof.

---

## Forced-Inclusion Inbox Submissions

Spec 11's forced-inclusion inbox lets users bypass shard RPC entirely
by posting a signed EVM transaction to an on-BSV inbox covenant. In
the BEEF model the inbox covenant is unchanged; what changes is how
nodes learn about inbox entries:

- When a user's wallet submits an inbox-covenant transaction, it
  publishes an **inbox-submission BEEF** (intent 0x05) either by
  POSTing it to any shard node (`POST /bsvm/inbox/submission`) or by
  publishing it directly on the shard's libp2p BEEF-gossip topic.
- Nodes observing intent 0x05 BEEFs add them to their inbox scanner's
  pending queue.
- The state covenant's forced-inclusion check (spec 07 §"Forced-
  Inclusion Inbox") is unchanged: if any inbox entry has age ≥ δ
  advances, the next advance must include it. The age is measured
  against chaintracks' observed BSV tip, consistent across nodes.

Inbox submissions are shard-bound (the envelope's `shard_id` matches
the inbox covenant's chain ID) and are verified against chaintracks
at acceptance time. A malicious inbox BEEF (fake BUMP, wrong script)
fails verification and is dropped.

---

## Script Verification

The follower path requires the shard node to execute BSV Script to
verify that a BEEF's target-transaction inputs correctly spend their
referenced ancestor outputs. BSVM adopts `go-wallet-toolbox`'s
pure-Go Script evaluator for this (which is itself derived from the
BSV reference interpreter). No custom evaluator is implemented.

Two script evaluations are relevant:

- **Fee-input scripts**: standard P2PKH. Cheap, ms-scale.
- **Covenant-input script**: the Rúnar-compiled covenant verifier,
  including the Mode 1 / 2 / 3 proof-verification sub-script
  (spec 12, spec 13). This is expensive — seconds to evaluate for
  Mode 1 (FRI) and hundreds of milliseconds for Mode 3 (Groth16-WA).

To keep the follower path fast, nodes **skip covenant-input
evaluation for intent 0x02 (confirmed) envelopes**: the BSV miners
already validated the script at block-acceptance time, and the
confirmed BUMP is itself a commitment to that validation (blocks
that contain invalid scripts would not be mined). For intent 0x01
(unconfirmed) envelopes, evaluation is **mandatory** — no BSV miner
has checked the script yet, and skipping would let a malicious peer
gossip a BEEF with a garbage proof and invalidate our local state
before the error surfaces.

Nodes that consistently receive unconfirmed BEEFs from a
high-latency ARC can choose to defer covenant evaluation and rely
purely on off-chain `prover.Verify(proof, public_values)` (the
same verification the node does for its own proofs before broadcast).
This is a configurable trade-off:

```toml
[follower]
# verify_mode:
#   "script"     — evaluate the covenant Script locally (slow, strong)
#   "prover"     — off-chain prover.Verify only (fast, weaker)
#   "both"       — script OR prover, accept if either succeeds
#   "strict"     — script AND prover, accept only if both succeed
verify_mode = "both"
```

The default is `"both"` on mainnet and `"prover"` on the devnet
(spec 16) so test iterations are fast.

---

## Multi-Endpoint Redundancy and Health

The overlay node's existing `BSVConnectivityState` in spec 11 is
generalised to a per-provider health matrix:

```go
type ProviderRole int
const (
    RoleARC ProviderRole = iota
    RoleChaintracks
    RoleWhatsOnChain
    RoleBSVNode
)

type ConnectivityState int
const (
    StateConnected  ConnectivityState = iota  // ≥1 primary provider reachable
    StateDegraded                               // primaries failing, fallbacks reachable
    StateDisconnected                           // all providers for at least one critical role unreachable
)

func (n *OverlayNode) connectivityState() ConnectivityState {
    // "Connected" requires at least one reachable ARC AND a reachable
    // chaintracks quorum.
    // "Degraded" allows WoC or BSV-node backups to take over for ARC
    // or chaintracks roles, but emits alerts.
    // "Disconnected" means broadcasting cannot proceed. Execution
    // continues speculatively; covenant advances pause.
}
```

Behaviour mirrors spec 11's BSV-connectivity-loss section: execution
continues speculatively, proving continues, covenant advances pause
when `StateDisconnected`, and the batcher applies backpressure per
`MaxSpeculativeDepth` (default 16).

---

## Governance-Event Detection via BEEF Gossip

Spec 11's governance monitor watched the BSV covenant UTXO chain
directly for freeze/unfreeze/upgrade transactions. In the BEEF model
the monitor reads from the BEEF-gossip topic for intent 0x06
envelopes. The detection logic is otherwise unchanged:

- Parse the covenant output of the target tx.
- Compare the frozen flag and the locking script hash against the
  node's last-seen covenant state.
- Invoke `HandleGovernanceFreeze` / `Unfreeze` / `Upgrade`.

Governance-initiating clients (operators, multisig signers in the
spec-15 admin UI) emit intent-0x06 BEEFs by pushing to any shard
node's `POST /bsvm/governance/action` endpoint once the signed BSV
transaction has been broadcast and confirmed.

---

## Reorg Handling via Chaintracks

Spec 11's `DoubleSpendMonitor.processConfirmedBlock` used BSV block
subscriptions to detect reorgs. In the BEEF model, reorgs are
surfaced by `ChaintracksClient.SubscribeReorgs`, which emits a
`ReorgEvent` whenever the client's best-chain view changes:

```go
func (n *OverlayNode) runReorgHandler(ctx context.Context) {
    ch, _ := n.net.SubscribeReorgs(ctx)
    for ev := range ch {
        n.handleChaintracksReorg(ev)
    }
}

func (n *OverlayNode) handleChaintracksReorg(ev *ReorgEvent) {
    // 1. For every confirmed BEEF whose BlockHeight is on the old
    //    chain after ev.CommonAncestor, clear the Confirmed flag.
    //    These BEEFs revert to unconfirmed state and must be
    //    re-broadcast if they were ours, or re-heard if they were
    //    peer-originated.
    n.beefStore.UnconfirmAbove(ev.CommonAncestor)

    // 2. If any of those BEEFs was for our own covenant-advance, check
    //    whether the advance is still in our TxCache at the affected
    //    L2 block heights. If yes, re-broadcast via ARC.
    // 3. If the reorg crosses the finalized depth, invoke Rollback.
    if ev.OldChainLen - commonHeight(ev) >= ConfirmationsFinalized {
        n.Rollback(affectedL2Block)
    }
}
```

---

## Security Considerations

1. **Chaintracks is the root of SPV trust.** Any adversary who can
   lie to chaintracks without being caught by the quorum check can
   feed the node an invented BUMP and trick the follower path. The
   `quorum ≥ 2` default, with upstreams from independent operators
   (BHS providers + WoC + optionally a self-hosted BSV node), makes
   this a meaningful attack surface only if multiple header sources
   collude. Operators concerned about this should run a self-hosted
   BSV node as a third chaintracks upstream; the backup path is
   supported precisely for this role.

2. **ARC callbacks are authenticated.** The `X-ARC-Callback-Token`
   must match a per-deployment secret. A stolen token lets an
   attacker inject fake `MINED` callbacks — but since every callback's
   BUMP is re-verified against chaintracks before the BEEF is
   upgraded, a fake callback cannot inject a fake confirmation. It
   can at most spam the node with rejected callbacks. Rotate tokens
   periodically; the node supports atomic token rotation by accepting
   old and new tokens during a grace window.

3. **WhatsOnChain cannot poison the BEEFStore.** Every WoC-fetched
   transaction is either re-hashed (verifying the ancestor's txid) or
   verified via a BUMP (for deposit fallback paths). WoC serving
   stale or wrong data causes lookup failure, not incorrect state.

4. **Peer BEEFs are never trusted.** Every peer-gossiped BEEF is
   re-verified end to end against chaintracks and (for unconfirmed
   envelopes) re-executed via the Script evaluator. A malicious peer
   cannot cause the node to accept an invalid advance; at worst it
   causes CPU wastage, which the node rate-limits per peer.

5. **Push-model bridge deposits are safe.** A malicious pusher can
   at worst submit a BEEF the node rejects. Real deposits all verify
   the same way regardless of who relays them; no double-credit is
   possible because spec 07's nullifier / nonce bookkeeping is
   unchanged.

6. **Server-side wallet security.** The fee wallet's private keys
   are held inside `go-wallet-toolbox`'s `WalletCrypto` layer, which
   enforces BRC-42/43 derivation and supports HSM-backed signing via
   its configurable signer interface. Operators concerned about key
   custody can point the toolbox at an HSM or KMS without changing
   any BSVM code.

7. **Optional BSV-node backup does not relax security.** When
   enabled, the BSV-node backup is only consulted if primary
   providers fail for the role, and every answer it gives is still
   subject to the same SPV verification (BUMPs must verify against
   chaintracks regardless of where the BUMP was sourced). The
   backup cannot unilaterally advance the node's confirmed state.

---

## Configuration Example (Full)

```toml
[bsv_network]

  [arc]
  # Mandatory. At least one ARC endpoint required for broadcasting.
  callback_mode  = "direct"       # "direct" | "poll"
  callback_url   = "https://my-node.example.com/bsv/arc/callback"
  callback_token = "env:ARC_CALLBACK_TOKEN"

    [[arc.endpoint]]
    name = "taal"
    url  = "https://arc.taal.com"

    [[arc.endpoint]]
    name = "gorillapool"
    url  = "https://arc.gorillapool.io"

  [chaintracks]
  quorum = 2
  checkpoint_height = 872340
  checkpoint_hash   = "0000000000000000036c2d7f9e3a..."

    [[chaintracks.upstream]]
    name = "bhs-primary"
    url  = "https://headers.example.com/api/v1/chain"
    kind = "brc-64"

    [[chaintracks.upstream]]
    name = "whatsonchain"
    url  = "https://api.whatsonchain.com/v1/bsv/main"
    kind = "whatsonchain"

  [whatsonchain]
  enabled   = true
  url       = "https://api.whatsonchain.com/v1/bsv/main"
  api_key   = "env:WOC_API_KEY"
  cache_ttl = "24h"

  [bsv_node]
  # Optional backup. Disabled by default.
  enabled               = false
  url                   = "http://127.0.0.1:8332"
  rpc_user              = "env:BSV_RPC_USER"
  rpc_pass              = "env:BSV_RPC_PASS"
  use_for_broadcast     = false
  use_for_ancestors     = false
  use_for_headers       = false
  use_for_merkle_proofs = false

  [wallet]
  # go-wallet-toolbox configuration.
  storage_backend = "sqlite"
  storage_path    = "data/wallet/wallet.db"
  fee_basket      = "bsvm-fee-wallet"
  protocol_id     = ["bsvm", 1]
  key_id          = "fee-wallet-v1"
  # Address derived from this wallet's standard BRC-42/43 path.
  # Fund this address to top up fee UTXOs.

[follower]
verify_mode = "both"     # "script" | "prover" | "both" | "strict"

[health]
min_nodes                 = 3
heartbeat_interval        = "10s"
max_proven_lag            = 32
max_proven_lag_follower   = 64
alert_webhook             = "https://my-monitoring.example.com/alert"
```

---

## Metrics

New Prometheus metrics exposed at `/metrics` (in addition to spec 11's):

| Metric                                           | Type      | Description                                                   |
|--------------------------------------------------|-----------|---------------------------------------------------------------|
| `bsvevm_arc_broadcast_latency_seconds`           | histogram | Per-endpoint broadcast latency                                |
| `bsvevm_arc_broadcast_failures_total`            | counter   | Per-endpoint broadcast failure count                          |
| `bsvevm_arc_callback_received_total`             | counter   | Callbacks received, labelled by status                        |
| `bsvevm_arc_callback_verification_failures_total`| counter   | BUMP verification failures on callbacks                       |
| `bsvevm_chaintracks_tip_height`                  | gauge     | Current chaintracks tip                                       |
| `bsvevm_chaintracks_quorum_failures_total`       | counter   | Headers where upstreams disagreed                             |
| `bsvevm_chaintracks_reorg_events_total`          | counter   | Reorgs surfaced by chaintracks                                |
| `bsvevm_beef_store_size`                         | gauge     | Number of BEEFs in the store, by intent                       |
| `bsvevm_beef_gossip_received_total`              | counter   | Peer BEEFs received, by intent                                |
| `bsvevm_beef_gossip_rejected_total`              | counter   | Peer BEEFs rejected during verification, by reason            |
| `bsvevm_woc_requests_total`                      | counter   | WhatsOnChain requests, by endpoint                            |
| `bsvevm_woc_cache_hit_rate`                      | gauge     | WhatsOnChain ancestor cache hit rate                          |
| `bsvevm_bsv_node_backup_used_total`              | counter   | Backup BSV-node calls, by role (only non-zero if enabled)     |
| `bsvevm_fee_wallet_utxo_count`                   | gauge     | From go-wallet-toolbox ListOutputs                            |
| `bsvevm_fee_wallet_balance_sats`                 | gauge     | Aggregate fee-wallet balance                                  |

---

## Migration from Spec 11's `BSVClient`

For reference during implementation, here is how each method of
spec 11's `BSVClient` maps to the new provider stack. Methods marked
**removed** are no longer needed at all because the underlying
pattern is replaced (push model, BEEF gossip, etc.).

| Spec-11 method                    | Replacement                                                      |
|-----------------------------------|------------------------------------------------------------------|
| `Broadcast(tx)`                   | `BSVNetworkClient.Broadcast(beef)` (ARC primary, BSV-node backup)|
| `GetTransaction(txid)`            | `BSVNetworkClient.FetchAncestor(txid)` (BEEFStore → WoC → backup)|
| `GetTransactionStatus(txid)`      | `ARCClient.Status(txid)` (callback-driven, polling fallback)     |
| `GetUTXOs(address)`               | `Wallet.ListOutputs()` (for fee wallet) / `WoC.AddressUnspent`   |
| `GetUTXO(txid, vout)`             | **removed** — not used on hot path in BEEF model                 |
| `IsUTXOSpent(txid, vout)`         | Implicit in `Wallet.ListOutputs` reconciliation                  |
| `GetSpendingTx(txid, vout)`       | **removed** — covenant chain is walked via `BEEFStore` only      |
| `GetBlockByHeight(h)`             | **removed** — nodes don't need block bodies                      |
| `GetBlockHeader(h)`               | `ChaintracksClient.HeaderByHeight(h)`                            |
| `GetChainTip()`                   | `ChaintracksClient.Tip()`                                        |
| `SubscribeBlocks(ctx)`            | **removed** — replaced by chaintracks-tip updates + BEEF gossip  |
| `SubscribeDoubleSpendAlerts(ctx)` | ARC callback `DOUBLE_SPEND_*` + peer BEEF comparison             |
| `GetMerkleProof(txid)`            | `ARCClient.Status(txid).BUMP` / `WoC.TxMerkleProof` / backup     |
| `Ping()`                          | `BSVNetworkClient.HealthStatus()` (per-provider)                 |

Specs affected by this migration:

- **Spec 07** (Bridge): replace `BridgeMonitor.processBlock`
  block-scanning loop with `POST /bsvm/bridge/deposit` push endpoint +
  intent-0x03 BEEF gossip consumer; keep the `WhatsOnChain`-polling
  relayer as a documented fallback.
- **Spec 10** (Deep BSV Integration / Rúnar / Fee Wallet): replace
  the custom `FeeWallet` struct and its DB/reconcile scaffolding
  with a `go-wallet-toolbox`-backed `FeeWallet` wrapper.
- **Spec 11** (Overlay): replace `BSVClient` interface with
  `BSVNetworkClient`; replace `DoubleSpendMonitor` BSV-block
  subscription with chaintracks reorg subscription + BEEF-gossip race
  detection; keep the Rollback / ReplayFromWinner logic unchanged
  (only the trigger sources change).
- **Spec 16** (Devnet): update Docker Compose to launch a local
  ARC/ARCADE stack + a chaintracks BRC-64 instance pointing at BSV
  regtest, pre-fund the fee wallets via wallet-toolbox seed
  fixtures, and remove any requirement for each node to hold its
  own bitcoind RPC credentials.

Each dependent spec will be revised in its own PR; this spec is the
design-of-record that those PRs should conform to.
