# `deploy/covenant/` — covenant deployment + VK rotation

This directory ships the operator tooling for two manual workflows
that the cmd/bsvm node binary deliberately leaves out of its
runtime path:

| Workflow      | Binary               | Wrapper        | When you run it                                              |
|---------------|----------------------|----------------|--------------------------------------------------------------|
| New shard     | `deploy-covenant`    | `deploy.sh`    | Once per shard, before any node boots                        |
| VK rotation   | `rotate-vk`          | `rotate-vk.sh` | After every guest-ELF change (commit-by-commit on `main`)    |

Both binaries share a single Go library (`deploy/covenant/*.go`,
package `covenantdeploy`) so the JSON-summary shape and the
governance-config validator are identical across the two paths.

The cmd/bsvm node binary's `bsvm deploy-shard` subcommand is the
"single-tx, regtest-only" entry point. The tooling here is the
"one-tx genesis with bridge included, mainnet-eligible, scriptable"
upgrade.

---

## 1. Pre-flight

You will need:

1. **Go 1.22+** (the wrappers enforce this).
2. **Python 3** for the tiny TOML/JSON shims in the bash wrappers.
3. **An ARC endpoint URL** with credentials (mainnet or testnet).
   See `pkg/arc/client.go` for the API surface.
4. **A funded BSV deployer wallet.** The deploy binary signs the
   genesis tx with a 32-byte hex private key read from a file path
   you supply via `deployerKeyFile` in the config. The key MUST NOT
   be inlined in any committed file. `chmod 600` the file.
5. **`prover/guest/elf/SP1VerifyingKeyHash.txt`** stamped with the
   current guest-ELF hash. See `prover/guest/elf/README.md` for the
   stamping procedure.

---

## 2. New shard deploy

### 2.1 Operator config

Create `deploy/covenant/operator.json` (gitignored — never commit):

```json
{
  "shardId": "bsvm-mainnet-1",
  "chainId": 8453111,
  "verificationMode": "fri",
  "governance": {
    "mode": "single_key",
    "threshold": 0,
    "keys": ["02aabbcc...3300"]
  },
  "bridgeAdminPubKeyHex": "",
  "bridgeInitialBalanceSats": 0,
  "covenantSats": 10000,
  "vkHashFile": "prover/guest/elf/SP1VerifyingKeyHash.txt",
  "deployerKeyFile": "/secure/path/deployer.hex",
  "fundingTxId": "abcdef...",
  "fundingVout": 0,
  "fundingSats": 200000,
  "fundingScriptHex": "76a914...88ac",
  "arcEndpoint": "https://arc.taal.com",
  "arcAuthToken": "...",
  "arcCallbackUrl": ""
}
```

Field reference:

| Field                        | Notes                                                               |
|------------------------------|---------------------------------------------------------------------|
| `shardId`                    | Free-form label. Echoed in the JSON summary.                        |
| `chainId`                    | EIP-155 chain id; baked into the rollup covenant readonly.          |
| `verificationMode`           | `fri` only today. `groth16` / `groth16-wa` are stubbed (TODO WW-mode23). |
| `governance.mode`            | `none` / `single_key` / `multisig`. Validated against the same rules `pkg/covenant.GovernanceConfig.Validate` enforces. |
| `governance.keys`            | 33-byte compressed secp256k1 pubkey hex strings.                    |
| `bridgeInitialBalanceSats`   | Initial liquidity for the bridge. Most operators leave this 0.      |
| `covenantSats`               | Sats pinned to the rollup covenant UTXO. Default 10_000.            |
| `vkHashFile`                 | Path to the stamped `SP1VerifyingKeyHash.txt`. Default `prover/guest/elf/SP1VerifyingKeyHash.txt`. |
| `deployerKeyFile`            | Path to a file containing a 32-byte hex private key. `chmod 600`.    |
| `funding*`                   | Single P2PKH input the deployer pre-funded.                         |
| `arcEndpoint`                | ARC URL (e.g. `https://arc-test.taal.com`).                         |

### 2.2 Run the wrapper

```bash
DEPLOY_CONFIG=deploy/covenant/operator.json ./deploy/covenant/deploy.sh
```

Output on stdout (JSON Summary, formatted):

```json
{
  "shardId": "bsvm-mainnet-1",
  "chainId": 8453111,
  "vkHash": "0x008e9a57...",
  "vkHashSource": "prover/guest/elf/SP1VerifyingKeyHash.txt",
  "bridgeScriptHex": "<hex>",
  "bridgeScriptHash": "<sha256>",
  "rollupScriptHex": "<hex>",
  "rollupScriptHash": "<sha256>",
  "verificationMode": "fri",
  "genesisTxidPredicted": "<hex>",
  "broadcast": false,
  "generatedAt": "2026-04-26T14:32:01Z"
}
```

The wrapper performs a `--dry-run` first, asks the operator to
confirm, then re-runs with `--broadcast`. After broadcast the
wrapper writes the full summary (now including `genesisTxidActual`)
to `deploy/covenant/.last-deploy.json`.

### 2.3 What the binary does

1. Reads the operator config JSON.
2. Reads `prover/guest/elf/SP1VerifyingKeyHash.txt` (or the override
   in `vkHashFile`) — the first non-empty hex line is the VK hash.
3. Compiles the rollup covenant (`rollup_fri.runar.go` for Mode 1,
   `rollup_devkey.runar.go` for devnet) via the runar-go compiler API.
4. Compiles the bridge covenant (`bridge.runar.go`) with the rollup
   script's `hash256` baked into the readonly
   `StateCovenantScriptHash` slot — so the bridge cross-covenant
   verification check passes for this exact rollup deploy.
5. Constructs the genesis tx (P2WSH-style outputs paying to each
   covenant locking-script hash, plus an OP_RETURN manifest envelope).
6. With `--dry-run`: emits the JSON summary and exits.
   With `--broadcast`: signs the funding input with the deployer
   key, posts via ARC, returns the broadcast txid.

### 2.4 Common failure modes

| Symptom (stderr)                              | Likely cause                                      | Fix                                                                   |
|-----------------------------------------------|---------------------------------------------------|-----------------------------------------------------------------------|
| `read VK hash: open ...: no such file`        | `vkHashFile` not stamped post `cargo prove vkey`  | Stamp it per `prover/guest/elf/README.md`                             |
| `validate config: deployerKeyFile must be set in --broadcast mode` | Missing key path in config           | Set `deployerKeyFile`; `chmod 600` the file                           |
| `funding 200000 sats < required ...`          | `fundingSats` too small for rollup + bridge + fee | Increase the funding UTXO                                             |
| `arc client: arc: URL required`               | `arcEndpoint` empty in config                     | Paste a real ARC URL                                                  |
| `compile: ... governance config: ...`         | Bad governance keys (wrong length, dup, etc.)     | The error message names the slot — fix the hex                        |

---

## 3. VK rotation

### 3.1 When to rotate

Every time `prover/guest/src/**/*.rs` changes the bytes of the SP1
guest binary. The current rotation history lives in
`docs/decisions/CC-vk-rotation-2026-04.md` (the 2026-04 rotation).

### 3.2 Procedure

1. Rebuild the guest:

   ```bash
   cd prover/guest
   cargo prove build
   NEW=$(cargo prove vkey --elf target/elf-compilation/riscv64im-succinct-zkvm-elf/release/bsvm-guest)
   echo "$NEW" > elf/SP1VerifyingKeyHash.txt
   ```

   Commit `elf/SP1VerifyingKeyHash.txt` in the SAME commit as the
   `.rs` change.

2. Update every per-shard rotation config:

   ```json
   {
     "shardId": "bsvm-mainnet-1",
     "chainId": 8453111,
     "verificationMode": "fri",
     "governance": { "mode": "single_key", "threshold": 0, "keys": ["02..."] },
     "deployerKeyFile": "/secure/path/deployer.hex",

     "covenantTxId": "<live rollup utxo txid>",
     "covenantVout": 0,
     "covenantSatsLive": 10000,
     "governanceSigsHex": ["<hex sig1>"],
     "newVKHashFile": "prover/guest/elf/SP1VerifyingKeyHash.txt",

     "arcEndpoint": "https://arc.taal.com",
     "arcAuthToken": "..."
   }
   ```

3. Run `./deploy/covenant/rotate-vk.sh` (with `ROTATE_OLD_VK=...` set
   if you want the JSON summary to include the OLD locking-script
   hex for diffing).

### 3.3 What the rotate-vk binary does

1. Reads the rotate-vk config + the NEW VK hash file (and optionally
   the OLD VK hash file for the summary diff).
2. Re-compiles the rollup covenant with the NEW hash, identical
   governance config + chainID. Spec 12 mandates that ONLY the VK
   hash differs across the rotation — chainID and governance MUST
   be unchanged.
3. With `--dry-run`: emits the JSON summary (NEW + OLD locking
   scripts side-by-side).
4. With `--broadcast`: validates that all governance signatures are
   present (M-of-N for multisig), then refuses with a clear error
   if the on-chain wrapper helper hasn't landed yet
   (`TODO(WW-rotate-onchain)`). For now, sign + broadcast the
   upgrade tx manually (see §3.5).

### 3.4 What the rotate-vk binary deliberately does NOT do

- It never advances state. The Upgrade method on the rollup
  contract uses a governance signature, not an SP1 proof.
- It never touches the bridge covenant. The bridge's
  `StateCovenantScriptHash` readonly pins to the OLD rollup script —
  rotating the rollup VK changes the rollup script bytes, which
  means the bridge no longer cross-covenant-verifies. **You must
  redeploy the bridge** with the NEW `StateCovenantScriptHash`
  after the rollup rotation lands. The wrapper prints a reminder
  on the final line.

### 3.5 §manual-broadcast — temporary procedure

Until the `WW-rotate-onchain` helper lands:

1. Run `rotate-vk.sh` in `--dry-run` mode and capture the new
   locking-script hex.
2. Build the upgrade tx by hand (consume the live covenant UTXO;
   create a new output under the new locking script with the same
   sats; attach an unlocking script that satisfies the rollup
   contract's Upgrade method's `CheckSig` / `CheckMultiSig`
   gate).
3. Broadcast via `bsvm dev sign-tx` + a direct ARC submission. The
   wrapper's `--broadcast` path will refuse with a clear error
   message until the helper is wired.

### 3.6 Per-shard manifest repin

Every per-shard genesis manifest's `sp1_verifying_key_hash` MUST be
re-pinned to the NEW value before the new guest is allowed to
advance state on that shard. Without this, nodes will reject every
new advance because the proof's VK doesn't match the manifest.

---

## 4. Tests

```bash
# Library + binaries build clean.
go build ./deploy/covenant/...

# Wrappers parse.
bash -n deploy/covenant/deploy.sh
bash -n deploy/covenant/rotate-vk.sh

# Validation test (uses a fake ARC, never broadcasts).
go test ./test/integration/... -count=1 -short -run TestCovenantDeploy
```

---

## 5. Open follow-ups

- `WW-mode23`: wire Mode 2 (Groth16 generic) and Mode 3 (Groth16-WA)
  through `Compile()` once the trusted-setup VK fixtures land. Today
  the binary errors out with a clear message on those modes.
- `WW-rotate-onchain`: build a `pkg/covenant.BuildUpgradeUnlockScript`
  helper that takes the governance signature bundle + the new
  locking script and returns the unlocking script the upgrade tx
  needs. Then wire `RunRotateVK` through it so the binary fully
  builds + signs the upgrade tx.
- Auto-redeploy the bridge after a VK rotation. Today this is a
  manual step; the wrapper just prints a reminder.
- WIF support in `loadDeployerKey`. Today only 32-byte hex keys are
  accepted to keep the surface minimal.
