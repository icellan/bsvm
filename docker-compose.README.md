# Docker Compose files in this repo

There are two Compose setups with different audiences. They are
intentionally distinct so you can run both on the same machine without
port collisions.

| File | Audience | Purpose |
|---|---|---|
| `docker-compose.yml` | Developers | Spec 16 local devnet. `docker compose up` brings up BSV regtest + auto-miner + 3 BSVM nodes. Chain ID 31337 (Hardhat default). Hardhat test accounts pre-funded. |
| `test/multinode/docker/docker-compose.yml` | Go test harness (`go test ./test/multinode/...`) | 3-node cluster on a fixed subnet (172.50.0.0/24) used by `DockerCluster` to run deterministic integration tests. Chain ID 8453111. Ports 18545–18547 to avoid collisions with a dev instance. |

## Developer workflow

```bash
# Default: mock mode (no GPU, sub-second "proofs")
docker compose up

# Dual-EVM correctness testing
BSVM_PROVE_MODE=execute docker compose up

# Full production proving (groth16-wa covenant + real STARK proofs)
docker compose -f docker-compose.yml -f docker-compose.proving.yml up
```

## Observability

Every node exposes Prometheus metrics and (optionally) OpenTelemetry traces.

| Endpoint | URL | Purpose |
|---|---|---|
| Prometheus scrape | `http://localhost:8545/metrics` | Point Grafana or Prometheus here. Works on every node port (8545/8546/8547). |
| OTLP traces | `$OTEL_EXPORTER_OTLP_ENDPOINT` | Set on node env to stream spans to Jaeger / Tempo / Honeycomb. Unset = stdout pretty-print. Set to `disabled` to skip exporter. |

Key Prometheus series:

- `bsvm_prover_proofs_{started,succeeded,failed}_total{node_name, chain_id}`
- `bsvm_prover_in_flight` / `bsvm_prover_queue_depth`
- `bsvm_prover_prove_duration_seconds` (histogram)
- `bsvm_batcher_pending` / `bsvm_batcher_accepted_total` / `bsvm_batcher_flushes_total`
- `bsvm_batcher_flush_duration_seconds` (histogram)

Constant labels `node_name` and `chain_id` let a single Grafana dashboard slice any metric by shard and by peer.

Ports on `docker-compose.yml`:

| Service | Port | Purpose |
|---|---|---|
| BSV regtest | 18332 | Bitcoin RPC (auth: devuser / devpass) |
| Node 1 (prover) | 8545 / 18546 / 9945 | JSON-RPC / WebSocket / libp2p |
| Node 2 (prover) | 8546 / 18548 / 9946 | JSON-RPC / WebSocket / libp2p |
| Node 3 (follower) | 8547 / 18550 / 9947 | JSON-RPC / WebSocket / libp2p |

Pre-funded accounts (1000 wBSV each) follow the standard Hardhat test
mnemonic — see `pkg/shard/hardhat_accounts.go`. Private keys are
published in every Hardhat install and must never hold real funds.

## BSV regtest settings

The regtest service boots with BSV-SV v1.2.1 and these flags:

- `genesisactivationheight=1` and `chronicleactivationheight=1` — activate both protocol upgrades at block 1 so the regtest chain is Chronicle-era from genesis. Matches `runar/integration/regtest.sh` so the covenant script sizes / opcodes used by Rúnar work uniformly here.
- `maxstackmemoryusagepolicy=100000000`, `maxscriptsizepolicy=0`, `maxscriptnumlengthpolicy=0`, `maxtxsizepolicy=0` — Chronicle-era policy relaxations. Covenant locking scripts can grow into the tens-of-MB range and need these.
- `minminingtxfee=0.00000001` — required since BSV-SV 1.2. Setting is explicit so startup doesn't fail with "mandatory policy parameter is not set."
- External port: `18335` (not 18332) to avoid collisions with other regtest instances on the host (e.g. `runar-integration-regtest`).

The Go code in `github.com/bsv-blockchain/go-sdk` exposes `interpreter.WithAfterChronicle()` for locally evaluating Chronicle-era UTXOs. BSVM doesn't currently use the SDK's interpreter — scripts run on the regtest node. When BSVM starts broadcasting covenant advances (deferred milestone), Chronicle mode will be passed through the SDK at that seam.

## Why two files

- The test compose pins a subnet and chain ID so the Go test harness
  (`test/multinode/harness.go`) can assert on deterministic container
  addresses and avoid flakes under parallel CI runs.
- The dev compose uses the default Docker bridge network and the
  Hardhat chain ID so developers can point MetaMask / Hardhat / Foundry
  at `http://localhost:8545` without any configuration.
- Keeping them separate lets a developer run the devnet locally while
  CI runs the test cluster on the same machine.

## Shared pieces

Both files reference the same Docker image built from the repo-root
`Dockerfile`. The expected local tags differ (`bsvm:devnet` vs
`bsvm:test`) — build with:

```bash
docker build -t bsvm:devnet -t bsvm:test .
```

to satisfy both. Future work will consolidate this behind a single
`scripts/docker-build.sh` helper referenced by both composes.

## What's not in the dev compose yet

- The shard's BSV genesis covenant transaction is not broadcast on
  regtest — that requires BSV SDK integration still in flight.
- The explorer UI (spec 15) is not yet embedded — the banner URLs
  currently return JSON-RPC, not HTML.
- Admin CLI helpers (`bsv-evm dev mine`, `bsv-evm admin freeze`) are
  stubs pending later milestones.
- Prove mode (`docker-compose.proving.yml`, GPU override) is pending.
