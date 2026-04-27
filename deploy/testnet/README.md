# BSVM testnet boot — operator walkthrough

This directory ships a reproducible BSVM testnet boot harness:

| File                  | Purpose                                                              |
|-----------------------|----------------------------------------------------------------------|
| `bsvm.testnet.toml`   | Documented testnet node config (every field annotated)               |
| `boot-testnet.sh`     | Preflight + start the daemon under the TOML                          |
| `verify-testnet.sh`   | Post-boot smoke test of JSON-RPC + BEEF surfaces                     |

Everything below assumes you are at the repo root.

---

## 1. Pre-flight checklist

You will need:

1. **The `bsvm` daemon binary**
   ```bash
   go build -o ./build/bsvm ./cmd/bsvm
   ./build/bsvm version
   # [expected: bsvm version 0.1.0]
   ```
2. **Go 1.22+** (the boot script enforces this).
3. **Rust toolchain** if `[prover].mode = "local"` (the testnet TOML default).
   `rustup toolchain list` should show the SP1 toolchain you've installed.
4. **A BSV testnet node JSON-RPC endpoint with credentials.**
   Either self-hosted (recommended) or a paid provider. The script does NOT
   ship credentials — you paste them into `[bsv].node_urls` in the TOML.
5. **A chaintracks (Block Headers Service) endpoint serving testnet headers.**
   Self-host the public [block-headers-service](https://github.com/bsv-blockchain/block-headers-service)
   in `--network=testnet` mode, or point at a vendor BHS that supports testnet.
6. **A funded testnet fee wallet.** The daemon will create one for you on
   first boot (`<datadir>/fee_wallet.wif`); send ≥0.1 testnet BSV to its
   derived address before the prover tries to broadcast a covenant advance.
   Use the public testnet faucets (e.g.
   `https://testnet.bitcoinabc.org/faucet`).

---

## 2. Generate keys

The daemon owns the **fee wallet key** (auto-created in `<datadir>` on
first boot, mode 0600). You only need to generate a **governance key**
yourself, and only if you deployed the shard with `--governance single_key`
or `--governance multisig`.

```bash
mkdir -p keys/testnet && chmod 700 keys/testnet

# One-line WIF generation using the bsvm binary's BSV SDK:
./build/bsvm dev gen-wif --network testnet --out keys/testnet/governance.wif
chmod 600 keys/testnet/governance.wif

# Derive its 33-byte compressed pubkey for [governance].keys in the TOML:
./build/bsvm dev derive-pubkey --wif keys/testnet/governance.wif
# [expected: 02xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx]
```

Paste the pubkey into `[governance].keys = ["02..."]` in
`deploy/testnet/bsvm.testnet.toml`.

> Note: `bsvm dev gen-wif` / `derive-pubkey` are convenience helpers under
> the existing `bsvm dev` command tree. If your local binary's `dev`
> subcommands differ, fall back to standard BSV SDK tools — the TOML
> only needs the hex pubkey + the WIF on disk.

---

## 3. Edit the config

Open `deploy/testnet/bsvm.testnet.toml` and replace every line with a
`# REQUIRED:` annotation. At minimum:

| Field                                    | What to set                                                          |
|------------------------------------------|----------------------------------------------------------------------|
| `[shard].chain_id`                       | The chain ID the shard was deployed under                            |
| `[shard].genesis_covenant_txid`          | TXID printed by `bsvm deploy-shard --bsv-network testnet`            |
| `[overlay].coinbase`                     | Your L2 coinbase address (gets the prover reward on advance)         |
| `[bsv].node_urls`                        | At least one BSV-testnet RPC endpoint with creds                     |
| `[[bsv.arc_endpoint]].url`               | Real ARC testnet URL (e.g. `https://arc-test.taal.com`)              |
| `[[bsv.chaintracks.providers]].url`      | Real BHS-testnet URL                                                 |
| `[bridge].bridge_script_hex`             | Hex of the bridge covenant locking script                            |
| `[governance].keys`                      | The pubkey from step 2 (or leave `[]` for `mode = "none"`)           |

For follower-only nodes (`BSVM_NODE_ROLE=follower`) you can leave
`[bsv].node_urls` empty and the node will sync via P2P.

---

## 4. Run `boot-testnet.sh`

```bash
./deploy/testnet/boot-testnet.sh
```

The script will:

1. Verify Go 1.22+ and (optionally) cargo are on PATH.
2. Build `./build/bsvm` if it's missing.
3. Parse the TOML.
4. Create `./data/testnet/` and `./keys/testnet/` (mode 700).
5. Probe the first chaintracks provider with a HEAD request (skippable via
   `--skip-chaintracks-check`).
6. `exec` the daemon — SIGINT/SIGTERM go straight to bsvm.

Expected log output (text format; switch to JSON via `log_format = "json"`
in the TOML):

```
[boot-testnet] preflight: toolchain
[boot-testnet]   Go 1.22.4 OK
[boot-testnet]   cargo 1.78.0 OK
[boot-testnet] preflight: daemon binary at ./build/bsvm
[boot-testnet]   bsvm version 0.1.0 OK
[boot-testnet] preflight: config file at deploy/testnet/bsvm.testnet.toml
[boot-testnet]   config parses OK
[boot-testnet] preflight: data dir ./data/testnet
[boot-testnet]   data dir OK
[boot-testnet] preflight: keys dir ./keys/testnet
[boot-testnet]   keys dir OK (mode 700)
[boot-testnet] preflight: probing chaintracks https://chaintracks-testnet.example/api/v1
[boot-testnet]   skipping chaintracks probe (placeholder URL still in config)
[boot-testnet] starting bsvm run
[boot-testnet]   config:  deploy/testnet/bsvm.testnet.toml
[boot-testnet]   datadir: ./data/testnet
time=... level=INFO msg="shard loaded" chainID=8453111 verification=fri synced=false
time=... level=INFO msg="bsvm node started" rpc=0.0.0.0:8545 p2p=/ip4/0.0.0.0/tcp/9945
[expected: BEEF verifier active OR "no chaintracks providers configured" warn]
[expected: bridge monitor wired OR "bridge monitor not wired" warn]
```

Override paths via env vars:

```bash
BSVM_BIN=/usr/local/bin/bsvm \
BSVM_DATADIR=/srv/bsvm/testnet \
BSVM_KEYSDIR=/srv/bsvm/keys/testnet \
./deploy/testnet/boot-testnet.sh
```

Idempotency: re-running after `Ctrl-C` is safe. The chaindata in
`<datadir>/chaindata/` is left alone; the daemon picks up at the last
written head. You only need a clean wipe if the DB is corrupted (see §6).

---

## 5. Run `verify-testnet.sh`

In a second terminal, while the daemon is running:

```bash
./deploy/testnet/verify-testnet.sh
```

Expected outcome (with placeholder BEEF + no test key):

```
[verify-testnet] step 0: probing http://127.0.0.1:8545
[verify-testnet] PASS: JSON-RPC reachable
[verify-testnet] step 1: polling eth_blockNumber for chain advance (timeout 60s)
[verify-testnet] PASS: chain advanced to block 1 (0x1)
[verify-testnet] step 2: POST /bsvm/bridge/deposit
[verify-testnet]   [REQUIRES: real BEEF envelope] — using shape-valid placeholder; expect 4xx from verifier
[verify-testnet] PASS: placeholder rejected (HTTP 400) — verifier is fail-closed as expected on testnet
[verify-testnet] step 3: eth_getBalance 0xD0E057051000000000000000000000000000DEAD
[verify-testnet]   balance is 0x0 (expected when no real BEEF envelope was supplied)
[verify-testnet] PASS: eth_getBalance succeeded (zero balance — fail-closed)
[verify-testnet] step 4: eth_sendRawTransaction
[verify-testnet]   [SKIPPED] BSVM_TEST_KEY not set — cannot sign a tx without a key
[verify-testnet] PASS: all checks passed
```

To exercise the full deposit + transfer path:

```bash
# Real BEEF envelope (BRC-62 BUMP + bridge tx, hex-encoded), produced by
# your testnet wallet.
BEEF_ENVELOPE_HEX_FILE=./tmp/deposit.hex \
BSVM_TEST_KEY=0xabc...32-byte-hex-key \
./deploy/testnet/verify-testnet.sh
```

The signed-tx path needs Foundry's `cast` on `PATH` (script skips with a
warning otherwise — install via `curl -L https://foundry.paradigm.xyz | bash`).

---

## 6. Common failure modes

| Symptom (log/output)                                               | Likely cause                                                                  | Fix                                                                                                                  |
|--------------------------------------------------------------------|-------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------------------|
| `WARN no chaintracks providers configured — bridge deposits will fail-closed` | `[[bsv.chaintracks.providers]]` URL is unreachable or `enabled=false`         | Stand up / point at a real BHS-testnet endpoint; bump `quorum_m` only after ≥2 providers are healthy.                |
| `WARN bridge monitor not wired — [bridge].bridge_script_hex is empty` | The L1 bridge covenant has not been deployed for this shard                   | Run `bsvm deploy-shard ...` for the bridge or paste the hex from your existing deploy artifact.                      |
| `boot from genesis txid: ... not found in BSV`                     | `--genesis-txid` set but `[bsv].node_urls` cannot serve the tx                | Either supply `BSVM_GENESIS_TX_FILE=<path>` with the raw hex, or fix the BSV-RPC creds, or use a valid bootstrap peer. |
| `eth_sendRawTransaction: insufficient funds for gas`               | The signing key has no L2 balance                                             | Bridge a deposit first, or pre-fund the address via `bsvm init --alloc 0x...=<wei>` at genesis.                      |
| `chain stayed at block 0 after 60s`                                | Batcher not flushing — usually an empty mempool                                | Send a tx (step 4 of verify) to trigger a flush, or lower `[overlay].max_batch_flush_delay`.                          |
| `PORT 8545 already in use`                                         | Another process owns the JSON-RPC port                                        | `lsof -i :8545` to find the offender, or change `[rpc].http_addr`.                                                   |
| `cargo not on PATH`                                                | SP1 prover can't compile/run                                                   | Install Rust + the SP1 toolchain, OR set `[prover].mode = "mock"` in the TOML for a non-proving smoke run.            |

---

## 7. Wipe + restart

```bash
# Daemon is idempotent, so a normal restart is just Ctrl-C + re-run boot.
./deploy/testnet/boot-testnet.sh    # resumes at last persisted head

# Full wipe (DB corruption, schema migration, switching shards):
rm -rf ./data/testnet
# Keep keys/testnet/* — those are durable identities, not chain state.
./deploy/testnet/boot-testnet.sh    # genesis-replays + re-syncs from BSV

# Forget everything (including the auto-generated fee wallet):
rm -rf ./data/testnet ./keys/testnet
```

> The fee wallet WIF lives in `<datadir>/fee_wallet.wif`. Wiping
> `data/testnet` regenerates the wallet — fund the new address before
> the prover tries to broadcast.

---

## Tests run on the harness

```bash
bash -n deploy/testnet/boot-testnet.sh         # syntax OK
bash -n deploy/testnet/verify-testnet.sh       # syntax OK
python3 -c "import tomllib; tomllib.loads(open('deploy/testnet/bsvm.testnet.toml').read())"   # parse OK
```
