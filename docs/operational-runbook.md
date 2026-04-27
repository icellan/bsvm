# BSVM Operational Runbook — Boot from Genesis

This runbook walks an operator through bringing up a `bsvm` daemon
from a clean checkout to a serving node. It is deliberately
prescriptive: every command and every config knob is named
explicitly. Where output cannot be reproduced without a real
environment, the expected output is bracketed `[expected: ...]`.

For deeper rationale on individual subsystems, see
`docs/decisions/`. Specs 10, 11, 12, 13, and 17 are the
authoritative architectural references.

---

## 1. Prerequisites

### 1.1 Toolchain pins

| Tool | Pinned version | Source of truth |
|------|----------------|-----------------|
| Go | 1.26 | `go.mod:3` |
| Rust (host crates) | stable | `prover/host*/Cargo.toml` |
| Rust (SP1 guest) | nightly-2025-10-01 | `prover/guest/rust-toolchain.toml` |
| SP1 | v6.0.2 | spec 12 §"SP1 Version Requirements" |
| SP1 zkVM crate | =6.0.2 | `prover/guest/Cargo.toml` |
| LLVM components for guest | `llvm-tools`, `rustc-dev`, `rustfmt` | `prover/guest/rust-toolchain.toml` |
| RISC-V target | `riscv64imac-unknown-none-elf` | same |

The guest nightly is the most fragile pin — Rust nightlies age out of
the upstream mirrors after roughly 6-12 months. See
`docs/decisions/U-toolchain-pin-strategy.md` for the mitigation
strategy (mirror snapshot, periodic bumps, recovery via Docker
image).

If you only need to run a follower (no SP1 proving), you can skip
the guest toolchain entirely — the daemon itself is a Go binary and
builds with the stable Go toolchain only.

### 1.2 System dependencies

```
# Linux/macOS:
- gcc / clang (for Go cgo, BoltDB, leveldb)
- git
- make
```

For full prover builds:

```
- rustup
- cargo-prove (SP1 toolchain) - install via:
    curl -L https://sp1.succinct.xyz | bash && sp1up
```

### 1.3 BSV node access

Choose one of the following deployment shapes:

1. **Self-hosted BSV node**: provide one or more JSON-RPC endpoints
   in `[bsv].node_urls` (W6-11 failover). The prover node uses these
   to broadcast covenant-advance transactions.
2. **Chaintracks-only follower**: a follower node can run with
   *only* a Block Headers Service (BHS) endpoint configured under
   `[[bsv.chaintracks.providers]]`. It will not be able to broadcast
   covenant advances, but it can verify them, replay batches, and
   serve RPC. See `docs/decisions/header-oracle-quorum.md`.
3. **Devnet**: regtest BSV via `docker-compose.proving.yml` (see
   `docker-compose.README.md`). No external dependencies.

---

## 2. Configuration

The full reference config lives at
`cmd/bsvm/bsvm.example.toml`. Copy it to `bsvm.toml`, then edit per
the table below. Every section currently present in
`bsvm.example.toml` is documented here.

### 2.1 Top-level

| Key | Default | Notes |
|-----|---------|-------|
| `datadir` | `"./data"` | Per-node state. Holds `chaindata/`, `shard.json`, `covenant.anf.json`, `genesis.txid`, `indexer/`, the BRC-100 server identity, and the fee-wallet keys file. **NOT shared across nodes** — each node owns its own datadir. |
| `genesis` | `""` | Optional path to a genesis manifest file. Usually empty; genesis is derived from BSV via `--genesis-txid` at boot (preferred) or from a shared `shard.json` (legacy). |
| `log_level` | `"info"` | `debug` / `info` / `warn` / `error`. |
| `log_format` | `"text"` | `text` or `json`. JSON streams cleanly into log aggregators. |

### 2.2 `[shard]` and `[overlay]`

| Key | Default | Notes |
|-----|---------|-------|
| `shard.chain_id` | `8453111` | EVM chain ID. Must match what the genesis manifest binds. EIP-155 signs over this — wallets must be configured with the same chain ID. |
| `shard.genesis_covenant_txid` | `""` | Filled in after `bsvm deploy-shard` runs (or by passing `--genesis-txid` at run time). |
| `shard.covenant_sats` | `10000` | Fixed sats carried by the covenant UTXO. Above the BSV dust limit (546). Don't change unless you know exactly why. |
| `overlay.coinbase` | `0x000…0` | L2 address that receives prover coinbase fees. Set to a real address you control on a prover node. Followers can leave at zero. |
| `overlay.block_gas_limit` | `30000000` | Standard EVM block gas limit. |
| `overlay.batch_size` | `128` | Target txs per covenant advance. Spec 12 §"BSV Transaction Cost" sizes the prover economics off this number. |
| `overlay.max_batch_flush_delay` | `"2s"` | Latency cap on batching — flush when full or when this elapses, whichever first. |
| `overlay.min_gas_price` | `"1000000000"` | 1 gwei floor. |
| `overlay.max_speculative_depth` | `16` | How many unproven blocks the node will hold ahead of the proven tip before back-pressuring. |

### 2.3 `[rpc]`

| Key | Default | Notes |
|-----|---------|-------|
| `http_addr` | `0.0.0.0:8545` | JSON-RPC HTTP listener. Standard Ethereum port. |
| `ws_addr`   | `0.0.0.0:8546` | WebSocket listener (subscriptions + admin log stream). |
| `cors_origins` | `["*"]` | Tighten in production. |

### 2.4 `[prover]`

| Key | Notes |
|-----|-------|
| `mode` | `mock`, `execute`, or `prove`. `mock` is fastest (devkey covenant, no STARK, no BSV broadcast). `execute` uses the real FRI covenant and broadcasts to BSV but proves with a placeholder. `prove` runs the full SP1 prover. See spec 16. |
| `workers` | Parallel proving workers. Local-CPU shards: 1. GPU shards: ≥ GPU count. |

### 2.5 `[network]` (libp2p)

| Key | Notes |
|-----|-------|
| `listen_addr` | libp2p multiaddr. Default `tcp/9945`. |
| `bootstrap_peers` | Multiaddrs of seed peers in the same shard. Required for followers booting via `--genesis-txid` without BSV RPC (see `bootstrapPeerSync` in `cmd/bsvm/main.go`). |
| `max_peers` | 50 by default. |

### 2.6 `[bsv]`

The most operator-sensitive block. Defaults are devnet-friendly;
mainnet operators must fill in real endpoints.

| Key | Notes |
|-----|-------|
| `node_url` | **Legacy.** Single BSV-node JSON-RPC endpoint. Prefer `node_urls`. |
| `node_urls` | List of BSV-node JSON-RPC endpoints in preference order (W6-11 failover). Index 0 is primary; 1+ are consulted on transport / 5xx errors. Application-level errors (tx not found, mempool conflict) are NOT retried — different nodes return the same answer. |
| `node_max_consecutive_failures` | Park a node after this many consecutive transport / 5xx failures. Default 3. |
| `node_cooldown` | How long parked nodes wait before retry. Default 30s. |
| `arc_url` / `arc_endpoint` | Single legacy or multi-endpoint ARC fan-out (W6-3). Used to broadcast covenant advances. |
| `arc_strategy` | `first_success` (default) or `quorum`. |
| `arc_quorum` | Required when strategy is `quorum`. |
| `arc_callback_url` / `arc_callback_token` | Inbound ARC callback delivery. |
| `network` | `mainnet` / `testnet` / `regtest`. Drives address parsing, BIP32 prefixes, etc. |
| `fee_wallet_key` | Hex-encoded WIF / private key for the BSV wallet that pays mining fees on covenant advances. **REQUIRED on prover nodes**; followers leave empty. See §3.3. |
| `confirmations` | BSV confirmations before bridge deposits / `finalized` block tag. Default 6. |
| `woc_cache_size` | LRU bound on cached WhatsOnChain GetTx lookups. Default 1000. |

### 2.7 `[bsv.chaintracks]`

The header oracle quorum (W6-2). At least one provider is required
for BEEF deposit verification — without it, the bridge stays
fail-closed and `/bsvm/bridge/deposit` posts will not credit L2
balances. See `docs/decisions/header-oracle-quorum.md`.

| Key | Notes |
|-----|-------|
| `quorum_strategy` | `hybrid` (weighted + floor) or `m_of_n` (strict). |
| `quorum_m` | Minimum providers that must agree. Mainnet shards SHOULD set `>= 2`. |
| `disagreement_action` | `log` / `drop` / `halt`. |
| `disagreement_cooldown` | How long a deviant provider stays suspended (when action is `drop`). Default 10m. |
| `response_timeout` | Per-provider call timeout. Default 5s. |
| `stream_skew_window` | Stream event buffer window. Default 750ms. |
| `stream_buffer_max` | Per-child reorg buffer cap. Default 32. |
| `[[bsv.chaintracks.providers]]` | Repeating block per BHS endpoint. Each carries `name`, `url`, `api_key`, `weight`, `timeout`, `enabled`. |

### 2.8 `[bsv.arc_brc104]`

BRC-104 mutual-auth for inbound ARC callbacks (W6-10).

| Key | Notes |
|-----|-------|
| `enabled` | When true and at least one identity is configured, callbacks must carry valid BRC-104 headers. |
| `timestamp_window` | Replay-window. Default 60s. |
| `nonce_cache_size` | LRU. Default 8192. |
| `allow_token` | Set true during migration to also accept the legacy `X-CallbackToken` header. |
| `[[bsv.arc_brc104.identity]]` | Repeating block: `name`, `public_key_hex` (33-byte compressed or 65-byte uncompressed). |

### 2.9 `[bridge]`

| Key | Default | Notes |
|-----|---------|-------|
| `min_deposit_satoshis` | `10000` | Below this is dust. |
| `min_withdrawal_satoshis` | `10000` | Same. |
| `bsv_confirmations` | `6` | Required before crediting a deposit on L2. |

The bridge predeploy address itself is `0x4200…0010`
(`pkg/bridge/predeploy.go`); it is wired by `block.InitGenesis` and
not configurable.

### 2.10 `[beef]`

| Key | Default | Notes |
|-----|---------|-------|
| `enabled` | `true` | Mounts `/bsvm/bridge/deposit`, `/bsvm/inbox/submission`, `/bsvm/governance/action`, `/bsvm/beef/covenant-chain` on the JSON-RPC HTTP listener. |
| `accept_unverified_bridge_deposits` | `false` | Devnet-only escape hatch. Leave false on mainnet. See `docs/decisions/beef-graph-validation.md`. |

### 2.11 `[evm]`

| Key | Default | Notes |
|-----|---------|-------|
| `fork` | `cancun` | The only valid value in v1. Adding Prague requires updating both EVMs and the `supportedEVMForks` set in `cmd/bsvm/config.go`. |

---

## 3. First-time setup

### 3.1 Build

```bash
make build            # produces ./bin/bsvm and ./bin/evm-cli
[expected: go build messages, no errors]
```

For full prover builds (only needed on prover nodes running
`prover.mode = "prove"`):

```bash
cd prover/guest && cargo prove build
[expected: SP1 toolchain produces guest ELF at prover/guest/target/...]
```

### 3.2 Datadir layout

Pick a location for `datadir` and create it:

```bash
mkdir -p /var/lib/bsvm/data
chmod 700 /var/lib/bsvm/data
```

The daemon writes the following inside `datadir/`:

| Path | Purpose |
|------|---------|
| `chaindata/` | LevelDB. Block headers, bodies, receipts, state trie nodes. |
| `shard.json` | Legacy shard manifest (only present if booted via `init` / `init-cluster`; absent when booting from `--genesis-txid`). |
| `covenant.anf.json` | Compiled covenant ANF — auditable IR. Cross-checks the locking script. |
| `genesis.txid` | Cached genesis covenant txid. |
| `indexer/` | Per-address tx indexer (when enabled). |
| `identity.json` | BRC-100 admin server identity. Auto-generated on first admin auth. |
| `fee_wallet.key` | Fee-wallet key file (when `[bsv].fee_wallet_key` points at a path rather than inline hex). |

### 3.3 Keys

Two key types are operator-relevant:

**Governance keys** (compressed secp256k1 pubkeys, 33 bytes hex).
Configured at genesis via `--governance` and the genesis manifest;
control freeze / unfreeze / upgrade. **Cannot advance state**. Lost
governance keys cannot withdraw funds — they only freeze. Generate
with any standard secp256k1 toolchain (e.g. `bsv-cli` or
`./bin/evm-cli wallet new`).

**Fee-wallet key** (BSV WIF / hex private key). Funds covenant
advances. Required on prover nodes only. Generate with `bsv-cli
new-keys` or equivalent. Fund the corresponding address with enough
BSV to cover ~21,600 sats per advance (spec 12 §"BSV Transaction
Cost"). Set as `[bsv].fee_wallet_key` (inline) or write the hex to
`<datadir>/fee_wallet.key` and `chmod 600` it. See
`cmd/bsvm/fee_wallet_key.go`.

Followers leave `[bsv].fee_wallet_key` empty — they do not broadcast.

### 3.4 Initialize a new shard (one-time, by the founding operator)

For a *brand new* shard, deploy the covenant + genesis to BSV:

```bash
./bin/bsvm deploy-shard \
    --datadir /var/lib/bsvm/data \
    --bsv-rpc 'http://user:pass@bsv-node:8332/' \
    --bsv-network mainnet \
    --prove-mode execute \
    --verification fri \
    --governance single_key \
    --chain-id 8453111 \
    --prefund-accounts none
```

`[expected:`
```
shard initialized chainID=8453111 genesisRoot=0x... dataDir=...
covenant deployed txid=<64-hex>
genesis manifest written to <datadir>/shard.json
```
`]`

The covenant txid printed here is the **public shard identifier** —
it is what every other node uses to bootstrap (see §5).

For a devnet shard (no BSV broadcast, dev key signs advances):

```bash
./bin/bsvm init --datadir ./data --prove-mode mock
```

### 3.5 Joining an existing shard

If someone else already deployed the shard, you do NOT run
`deploy-shard`. Skip directly to §5 — point your `bsvm run` at the
known genesis txid via `--genesis-txid` (or `BSVM_GENESIS_TXID`).
The daemon fetches the covenant tx from BSV (or from a peer via
libp2p genesis-sync) and derives every config dimension from it.

---

## 4. Genesis

When the daemon starts on an empty datadir, it calls
`block.InitGenesis` (`pkg/block/genesis.go:62`) to:

1. Write the genesis L2 block (block 0) with the configured chain
   ID, gas limit, timestamp = 0, parent hash = 0.
2. Predeploy the bridge contract at `0x4200…0010`
   (`pkg/bridge/predeploy.go`).
3. Apply the funded-address allocations from the manifest (or
   `--alloc` / `--prefund-accounts hardhat` for devnet).
4. Compute the genesis state root and write it as the head block.

The chain DB is at `<datadir>/chaindata/` (LevelDB). To fully reset
a node:

```bash
rm -rf /var/lib/bsvm/data/chaindata
rm -f  /var/lib/bsvm/data/shard.json
rm -f  /var/lib/bsvm/data/genesis.txid
rm -f  /var/lib/bsvm/data/covenant.anf.json
rm -rf /var/lib/bsvm/data/indexer
# Keep identity.json / fee_wallet.key only if you want to preserve them.
```

The next `bsvm run` rebuilds from the configured genesis source.

---

## 5. Boot

### 5.1 Run command

The recommended boot path is "boot from genesis txid" — every config
dimension is derived from the on-chain covenant tx, so a fresh
operator only needs the txid + a way to reach BSV (or a peer):

```bash
export BSVM_GENESIS_TXID=<the public shard genesis txid>
export BSVM_BSV_RPC='http://user:pass@bsv-node:8332/'
./bin/bsvm run \
    --config /etc/bsvm/bsvm.toml \
    --datadir /var/lib/bsvm/data
```

A follower without BSV RPC dials the configured bootstrap peers on
the chain-agnostic genesis-sync protocol and asks them for the raw
genesis tx (see `bootstrapPeerSync` in `cmd/bsvm/main.go`). Set
`[network].bootstrap_peers` to at least one online peer.

### 5.2 Expected log output (success indicators)

```
[expected: text-format slog output, abridged]
INFO bsvm node started chainID=8453111 rpc=0.0.0.0:8545 p2p=/ip4/0.0.0.0/tcp/9945
INFO shard loaded chainID=8453111 txid=<64-hex> verification=VerifyFRI synced=false
INFO BEEF verifier active (ancestry + script re-exec) providers=2 quorum_m=2
INFO bridge monitor wired script_hash_bytes=32 local_shard_id=8453111
INFO indexer enabled path=/var/lib/bsvm/data/indexer cacheMB=256
```

Warnings worth investigating:

```
[expected for misconfigured nodes]
WARN no chaintracks providers configured — bridge deposits will fail-closed
WARN bridge monitor not wired — [bridge].bridge_script_hex is empty
INFO BSV client not configured, will sync via P2P gossip
INFO node role=follower — skipping BSV broadcast wiring
```

### 5.3 Common immediate failures

| Symptom | Cause | Fix |
|---------|-------|-----|
| `WARN no chaintracks providers configured — bridge deposits will fail-closed (no L2 credit)` | `[[bsv.chaintracks.providers]]` empty | Add at least one BHS endpoint. See §2.7. |
| `WARN bridge monitor not wired — [bridge].bridge_script_hex is empty, BEEF deposits will not credit L2` | Genesis manifest didn't specify the L1 bridge script | Re-run `deploy-shard` with bridge wiring, or import the existing manifest. |
| `INFO BSV client not configured, will sync via P2P gossip` | `[bsv].node_urls` empty | Expected on followers. On prover nodes: covenant broadcast disabled; node serves RPC only. |
| `failed to load node config: ...` | TOML parse error or missing required field | Run `./bin/bsvm run --config ... --datadir ./tmp` against a known-good config to bisect. |
| `boot from genesis txid: ...` | Genesis tx fetch failed (no RPC, no peers, no file) | Set `BSVM_BSV_RPC`, list bootstrap peers, or pass `--genesis-tx-file <path>`. |
| `bsvm node started` followed by no further activity | No peers, no RPC traffic | Check `[network].listen_addr`, firewalls, peer reachability. |

---

## 6. Verification

Once `bsvm node started` appears, smoke-test the JSON-RPC layer:

### 6.1 Standard Ethereum RPC

```bash
curl -s -H 'Content-Type: application/json' \
    -d '{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}' \
    http://localhost:8545
```
`[expected: {"jsonrpc":"2.0","id":1,"result":"0x80f5e7"}]` (0x80f5e7 = 8453111)

```bash
curl -s -H 'Content-Type: application/json' \
    -d '{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}' \
    http://localhost:8545
```
`[expected: {"jsonrpc":"2.0","id":1,"result":"0x0"}]` immediately after genesis.

```bash
# Bridge predeploy address. Should always exist (codeHash != empty).
curl -s -H 'Content-Type: application/json' \
    -d '{"jsonrpc":"2.0","id":1,"method":"eth_getCode",
         "params":["0x4200000000000000000000000000000000000010","latest"]}' \
    http://localhost:8545
```
`[expected: result is non-empty hex bytecode]`

### 6.2 BSVM-specific RPC

```bash
curl -s -H 'Content-Type: application/json' \
    -d '{"jsonrpc":"2.0","id":1,"method":"bsv_shardInfo","params":[]}' \
    http://localhost:8545
```
`[expected: {"chainID":8453111,"genesisCovenantTxid":"...","verification":"VerifyFRI","governance":{"mode":"single_key",...}}]`

```bash
curl -s -H 'Content-Type: application/json' \
    -d '{"jsonrpc":"2.0","id":1,"method":"bsv_getGovernanceState","params":[]}' \
    http://localhost:8545
```
`[expected: governance config + freeze status]`

### 6.3 BEEF deposit endpoint

```bash
# A POST with a BEEF-encoded deposit envelope.
curl -i -X POST \
    -H 'Content-Type: application/octet-stream' \
    --data-binary @deposit.beef \
    http://localhost:8545/bsvm/bridge/deposit
```
`[expected: 202 Accepted on success; 400 on malformed BEEF; 503 if chaintracks unavailable]`

If the verifier path is fully wired (chaintracks providers
configured, bridge monitor wired), an L2 balance for the recipient
appears within `[bridge].bsv_confirmations` BSV blocks. Otherwise
the envelope is stored but no L2 credit happens (fail-closed) — see
the WARN logs from §5.2.

### 6.4 WebSocket subscription

```bash
# Quick sanity check of newHeads subscription.
wscat -c ws://localhost:8546 \
    -x '{"jsonrpc":"2.0","id":1,"method":"eth_subscribe","params":["newHeads"]}'
```
`[expected: subscription id, then one event per new L2 block]`

---

## 7. Operational concerns

### 7.1 Logging

Structured slog (`log/slog`). `--log-format json` for ingestion; the
default `text` is human-readable. Levels: `debug` / `info` / `warn`
/ `error`. Set via `[log_level]` in TOML or `BSVM_LOG_LEVEL` env.
Live tail of the slog stream is available over the admin
WebSocket subscription `adminLogs` (spec 15 A9) once admin auth is
configured (see §7.2).

### 7.2 Metrics

**Prometheus is not yet wired.** The metrics registry exists
(`pkg/metrics/`) and is exposed at `/metrics` on the JSON-RPC
listener, but in v1 the registry is mostly informational — the
wiring of individual subsystem counters is incomplete. For now,
operators should rely on slog for observability and treat Prometheus
as a "coming soon" surface.

OpenTelemetry tracing is wired (`pkg/tracing/`) and best-effort —
the daemon still boots if the OTLP endpoint is unreachable. Set
standard `OTEL_EXPORTER_OTLP_ENDPOINT` env vars to enable.

### 7.3 Backup / restore

The chain DB at `<datadir>/chaindata/` is a LevelDB — a flat-file
copy taken while the daemon is shut down is sufficient. Hot backups
require an external snapshot tool that respects LevelDB's MANIFEST
ordering.

A second recovery path exists: `bsvm recover --genesis-txid <txid>
--datadir <fresh-dir> --chain-id <id>` walks the BSV covenant chain
and re-derives state. As of this writing the recover subcommand is
a stub
(`cmd/bsvm/main.go:cmdRecover` logs `recovery requires BSV client
integration -- not yet available`); manual replay via
`docs/decisions/S-withdrawal-and-rollback.md` is the practical
fallback today.

### 7.4 Upgrades

Two distinct upgrade paths:

1. **Daemon binary upgrade**: stop, replace binary, start. The chain
   DB is forward-compatible across patch releases. Major-version
   upgrades document any required reindex steps in their release
   notes.
2. **Covenant migration** (genuinely rare): requires governance
   freeze → upgrade transaction → unfreeze on BSV. See spec 12
   §"GovernanceMode" and `pkg/covenant/governance.go`. This is the
   only path that changes the on-chain script — it is *not*
   triggered by a daemon upgrade.

SP1 version bumps fall under the covenant migration path because
the verifying key changes (spec 12 §"Version upgrade policy").

---

## 8. Failure modes

### 8.1 Chaintracks WebSocket drop

Symptom: brief `WARN chaintracks stream EOF`. The chaintracks
client now auto-resubscribes (per agent R's work — see
`docs/decisions/header-oracle-quorum.md` §"Stream resubscribe" and
related changes in `pkg/chaintracks/`). No operator action required
on transient drops.

If the resubscribe loop fails repeatedly (`disagreement_action =
halt` plus all providers down), the bridge stops crediting deposits
until at least one provider is restored. Logs surface
`chaintracks: all providers unavailable`.

### 8.2 BSV reorg

Symptom: a recently-confirmed covenant advance becomes unconfirmed
because BSV reorganises away the block that contained it. Per agent
S's work (`docs/decisions/S-withdrawal-and-rollback.md`), the L2
detects the retraction via the chaintracks reorg notification and
**halts the L2** (cascade rollback in `pkg/overlay/cascade_rollback.go`).
Withdrawals dispatched against the now-orphaned advance are revoked.

Recovery: the daemon waits for the new BSV tip to either:

1. Re-include the orphaned advance (cooperative reorg) — L2 resumes
   from where it was.
2. Replace the orphaned advance with a competing one (race lost).
   The losing prover replays the winning batch; speculative
   receipts ahead of the orphaned advance are invalidated.

Operators should not intervene during a reorg — the cascade
rollback is the deterministic recovery path. Monitor the
`adminLogs` subscription for `reorg detected` and `cascade
rollback complete` markers.

### 8.3 Prover timeout

Symptom: SP1 proving exceeds `[prover].timeout` (spec 12
§"Head-of-Line Blocking Mitigation", default 60s). The proving job
is cancelled. After three timeouts (`3 × ProvingTimeout`), the node
enters follower-only mode and waits for another node to advance the
covenant.

Recovery: another shard node generates the proof and the local node
detects the covenant advance via the double-spend monitor, replays
the winning batch, and resumes. Operator action is needed only if
*every* shard node is exceeding the timeout — that means the batch
size or batch contents are too aggressive for the prover hardware,
and `[overlay].batch_size` should be reduced.

### 8.4 Batch advance race lost

Symptom: this node proved a batch and broadcast a covenant advance,
but BSV miners confirmed a competing advance from another node
first. The local cache marks our broadcast tx as orphaned; we
discard our proof and replay the winner's batch. Speculative
receipts for transactions absent from the winner's batch are
invalidated.

This is the *normal* multi-node competitive flow. No operator
action. Spec 11 §"Speculative Receipts" covers the receipt
semantics.

### 8.5 EVM disagreement

Symptom: the local Go EVM produced state root R1 but the SP1
guest's revm produced R2, R1 != R2. The local broadcast is aborted
and the proving job is re-queued. If the disagreement persists
across retries it indicates a bug in one of the two EVMs — see spec
12 §"Cross-EVM Differential Testing".

This is a P0 invariant violation. File an incident, capture the
batch inputs, the access set, and both state-root traces.
Differential test infrastructure under `test/evmtest/` is the
canonical reproduction harness.

### 8.6 Missing chaintracks providers

Symptom: `WARN no chaintracks providers configured — bridge
deposits will fail-closed`. The daemon boots and serves RPC, but
the BEEF deposit endpoint accepts envelopes without crediting L2
balances. This is the safe default — never relax to
`accept_unverified_bridge_deposits = true` on mainnet.

Recovery: configure at least one `[[bsv.chaintracks.providers]]`
block. Restart.

### 8.7 Missing fee wallet

Symptom: `INFO BSV client not configured, will sync via P2P gossip`,
*OR* `INFO node role=follower — skipping BSV broadcast wiring`. The
daemon runs but cannot submit covenant advances. On a node that
*should* be a prover, this means `[bsv].fee_wallet_key` is empty or
`BSVM_NODE_ROLE=follower` is set inadvertently. Fix the config and
restart.

---

## 9. Pointers

For the design rationale behind individual subsystems, see:

- `docs/decisions/U-spec-drift-audit.md` — current spec/code
  alignment audit.
- `docs/decisions/U-toolchain-pin-strategy.md` — Rust nightly pin
  strategy and CI workflow draft.
- `docs/decisions/U-runar-api-pinning.md` — runar-go API pinning.
- `docs/decisions/U-testdata-submodule.md` — ethereum/tests
  submodule layout.
- `docs/decisions/header-oracle-quorum.md` — chaintracks W6-2
  multi-provider quorum design.
- `docs/decisions/beef-graph-validation.md` — W6-4 BEEF deposit
  ancestry verification.
- `docs/decisions/S-withdrawal-and-rollback.md` — BSV reorg
  detection and L2 cascade rollback.
- `docs/decisions/inbox-drain.md` — forced-inclusion inbox witness
  + drain cap.
- `docs/decisions/W6-7-runar-broadcast-status.md` — runar-broadcast
  triage.
- `docs/decisions/P-versioned-hash-audit.md` — Cancun versioned
  hash semantics audit.

Authoritative architecture: `spec/00-PROJECT-OVERVIEW.md` is the
top-level entry point. Specs 10-13 + 17 are the mainnet-critical
documents.
