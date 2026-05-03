# VK Rotation — Operator Runbook

This runbook walks an operator through executing an on-chain SP1
verifying-key rotation against a live BSVM shard. It is the
operational counterpart to `docs/decisions/vk-rotation-wire-format-2026-04.md`
(why the bytes change) and `docs/decisions/sp1-reproducible-build-2026-05.md`
(how the new VK is derived reproducibly).

The rotation core is `deploy/covenant/cmd/rotate-vk` (a thin flag
parser around `deploy/covenant/rotate-vk.go::RunRotateVK`). Most of
this runbook is wiring around that binary's inputs.

> **Implementation status (as of 2026-05-03)**: the rotate-vk binary
> itself is wired end-to-end and covered by
> `test/integration/rotate_vk_test.go` (assembly + partial-sig flow,
> ARC-broadcast-rejected fixture). Several **operator-side helpers
> the binary's inputs depend on are not yet shipped** — see the
> "TODO" markers throughout. Until those land, operators must
> assemble those inputs by hand or via small one-off scripts. None
> of those gaps are blocking; they are documented here so a future
> session can close them with named hooks.

When you must rotate:

* The pinned `prover/guest/elf/SP1VerifyingKeyHash.txt` changed in a
  commit that lands on `main`. Every deployed shard's covenant must
  be advanced to the new VK before the next batch can be proven.
* You need to deploy a fix to the SP1 guest in production (e.g. a
  new precompile, a tx-pricing fix, a wire-format correction).

When you do **not** rotate:

* You only changed host-side Go code (no `prover/guest/**` or
  `prover/guest/Cargo.{toml,lock}` change). The pin file is
  unaffected; the existing covenant accepts proofs against the same
  ELF.
* You're on a pre-deployment shard that has never been broadcast.
  In that case, `deploy/covenant/deploy.sh` will bake in the new VK
  on the next deploy — no rotation needed.

---

## 1. Pre-flight checklist

You will need:

1. **The `rotate-vk` binary**:
   ```bash
   go build -o build/rotate-vk ./deploy/covenant/cmd/rotate-vk
   ./build/rotate-vk --help | head -5
   # [expected: Usage of ./build/rotate-vk:]
   ```

2. **The same `OperatorConfig` JSON that originally deployed the shard.**
   This is the file you used with `deploy/covenant/deploy.sh` —
   typically `deploy/covenant/operator.json`. The rotation re-uses
   every field except the VK hash, so the chainID, governance mode,
   governance pubkeys, and verification mode MUST be unchanged.
   Per spec 12, ANY drift in these fields is a different shard —
   the on-chain verifier will reject the upgrade tx.

3. **The live covenant UTXO coordinates** (`covenantTxId`,
   `covenantVout`, `covenantSatsLive`, `currentStateRootHex`,
   `currentBlockNumber`).

   **TODO(WW-covenant-tip)**: `bsvm` does not yet expose a
   `covenant tip` subcommand. Read these from your node's
   `chaindata/` via the existing `pkg/covenant.LoadState(...)` helper,
   or instrument `cmd/bsvm` with a small read-only subcommand. As an
   immediate workaround you can:

   * Inspect the post-deploy summary written by
     `deploy/covenant/.last-deploy.json` for the original txid (vout
     0, sats from `covenantSats` in the OperatorConfig). For
     subsequent advances, query the BSV chain for spends of that
     outpoint via your BSV node's `gettxout` and follow forward.
   * Read `currentStateRootHex` and `currentBlockNumber` from the
     RollupState readonly via the existing
     `pkg/covenant.ReadRollupState` helper, given the latest
     covenant UTXO's locking script bytes. The integration test at
     `pkg/covenant/state_test.go` shows the call shape.

4. **A fresh SP1 proof bundle** (`publicValuesHex`, `batchDataHex`,
   `proofBlobHex`) that proves the no-op upgrade transition
   (preStateRoot → preStateRoot, blockNumber+1, new covenant script
   bound).

   **TODO(WW-upgrade-proof-bridge)**: `bsvm-host-bridge` exposes
   `mode = "execute"|"core"|"compressed"|"groth16"` (per
   `prover/host-bridge/src/main.rs::129`) but does not yet have an
   `upgrade-proof` mode that takes `pre_state_root +
   new_covenant_script + block_number` and produces the JSON shape
   `RotateVKConfig.proofBundlePath` consumes. As a workaround:

   * For testnet/staging rotations, use the synthetic stand-in
     (`proofBundlePath` empty in the config). `rotate-vk` will fall
     back to `covenant.SyntheticUpgradeProofBundle` (per
     `rotate-vk.go::resolveProofBundle`); the on-chain SP1 verifier
     rejects this proof, so the broadcast tx will fail in
     `verifyScript` — useful only for assembly testing.
   * For real rotations, build and prove the upgrade-input
     manually: write a small Rust binary that imports the same
     `bsvm-guest` ELF, populates the upgrade transition's
     `BatchInput`, calls `prover.prove(&pk, stdin)` from
     `sp1-sdk`, and writes the JSON shape rotate-vk reads. The
     integration test `rotate_vk_test.go` shows the required JSON
     shape.

5. **Governance signatures.** What you need depends on the shard's
   governance mode:
   * `none`: rotations are **not possible**. The shard cannot
     upgrade. Re-deploy from scratch is the only path. (`rotate-vk`
     surfaces this with an explicit error per
     `rotate-vk.go::runBroadcastUpgrade::261`.)
   * `single_key`: one ECDSA signature over the upgrade transaction's
     sighash, computed against the governance key's secp256k1 WIF.
   * `multisig` (M-of-N): collect M signatures via the partial-sig
     bundle flow described in §4 below.

   **TODO(WW-rotation-sign)**: `bsvm` does not yet expose a
   `dev sign-rotation` (or equivalent) helper. For now use the
   bsv-blockchain go-sdk's `transaction.Sign(...)` against the
   sighash that `pkg/covenant.BuildUpgradeUnlockScript` would
   consume, OR use any standard secp256k1 signer (the sighash is
   the upgrade tx's BIP-143 SigHash for input 0 with the live
   covenant's locking script as `prevLockScript`).

6. **Optional**: stop the live prover node(s) on the shard during
   the rotation. Strictly not required (the upgrade tx race-loses
   gracefully against any in-flight covenant advance), but reduces
   the chance of broadcasting an upgrade against a stale outpoint.

---

## 2. Build the rotation config

Copy the deploy-time `operator.json` to a rotation-specific file
and add the rotation-only fields. The full set of fields is
documented in `RotateVKConfig` (see `deploy/covenant/rotate-vk.go`).
Minimal example:

```json
{
  "shardId": "bsvm-testnet-1",
  "chainId": 8453111,
  "covenantSats": 10000,
  "governance": {
    "mode": "single_key",
    "keys": ["02abc..."]
  },
  "verificationMode": "fri",
  "vkHashFile": "prover/guest/elf/SP1VerifyingKeyHash.txt",
  "arcEndpoint": "https://arc.taal.com",
  "arcAuthToken": "<paste from your secret store>",

  "covenantTxId":         "7a8c1f...",
  "covenantVout":         0,
  "covenantSatsLive":     10000,
  "currentStateRootHex":  "0x4f9b...",
  "currentBlockNumber":   12847,
  "newVKHashFile":        "prover/guest/elf/SP1VerifyingKeyHash.txt",
  "proofBundlePath":      "rotation-upgrade-proof.json",
  "governanceSigsHex":    ["abcdef..."]
}
```

Field reference: `RotateVKConfig` doc comments in
`deploy/covenant/rotate-vk.go::71-129`. Every rotation-only field is
required for `--broadcast`; `--dry-run` is more permissive (no
`arcEndpoint`, no `governanceSigsHex`, no `proofBundlePath`).

---

## 3. Dry-run

Always dry-run before broadcasting:

```bash
./build/rotate-vk \
    --config rotation.json \
    --old-vk-hash-file path/to/old/SP1VerifyingKeyHash.txt \
    --dry-run \
    --out /tmp/rotation-summary.json
```

(The `--old-vk-hash-file` is the previous pin you saved before
re-stamping; optional but recommended so the summary surfaces
`oldVKHash` and `oldRollupScriptHex` for audit.)

The summary JSON includes:

| Field | Why it matters |
| --- | --- |
| `newVKHash` | Must match the in-tree pin you stamped. |
| `newRollupScriptHex` | The full rebuilt covenant script. Audit by recompiling the contract from source via `pkg/covenant/compile_test.go`. |
| `oldVKHash`, `oldRollupScriptHex` | Pre-rotation state for diff. |

The dry-run does NOT touch BSV or ARC. If anything fails here
(governance config parse error, vk hash file unreadable, mode
unsupported), fix locally before continuing.

---

## 4. Coordinate signatures (multisig only)

Skip this section for `single_key` shards.

For an M-of-N rotation, the first operator runs:

```bash
./build/rotate-vk \
    --config rotation.json \
    --broadcast
```

with `governanceSigsHex` containing only their own signature. The
binary detects insufficient signatures, writes a partial bundle to
`rotate-vk.partial.json` (alongside the config), and exits with:

```
rotate-vk: 1-of-3 signature(s) collected; 2 more needed.
Wrote partial bundle to rotate-vk.partial.json.
Re-run with the additional governanceSigsHex once the next operator
signs.
```

(See `rotate-vk.go::runBroadcastUpgrade::343-360` for the
exact branching condition.)

Each subsequent operator:

1. Pulls the partial bundle JSON out-of-band (Slack, encrypted email,
   shared secret store).
2. Verifies the bundle's `publicValuesHex` and `batchDataHex` match
   the rotation they expected to sign (avoid blind signing).
3. Computes their signature against the upgrade tx's sighash for
   input 0 (see TODO(WW-rotation-sign) in §1 for the sighash details
   until a `bsvm dev sign-rotation` helper lands).
4. Appends the new signature to `governanceSigsHex` in the
   ROTATION CONFIG (not the partial bundle).
5. Re-runs `rotate-vk --broadcast` with the now-fuller config.

When the M-th operator runs the binary, the count check passes and
the assembly + ARC broadcast path activates.

---

## 5. Broadcast

```bash
./build/rotate-vk \
    --config rotation.json \
    --broadcast \
    --out /tmp/rotation-summary.json
```

Successful output:

```json
{
  ...
  "upgradeTxidActual": "ef41a3...",
  "upgradeUnlockHex":  "...",
  "upgradeMethod":     "Upgrade",
  "broadcast":         true
}
```

If ARC rejects the broadcast:

* `MISSING_INPUT` → the live covenant outpoint moved (someone
  advanced state between your tip read and the broadcast). Re-read
  the tip and rebuild the rotation config.
* `INVALID_SCRIPT` → the upgrade unlock script's signature does
  not satisfy the rollup contract's `Upgrade` method. Almost always
  a wrong governance key or a mis-encoded signature, OR the supplied
  proof bundle is the synthetic stand-in (which the on-chain SP1
  verifier always rejects).
* `BAD_PUBKEY` (multisig) → one of the supplied signatures is for a
  pubkey not in `governance.keys`. Confirm the active key set in
  the deploy-time config.
* ARC HTTP 5xx → retry. The summary surfaces `upgradeTxHex` even
  when ARC fails (see `rotate-vk.go::runBroadcastUpgrade::389-394`)
  so you can re-broadcast manually against a different ARC instance.

---

## 6. Verify on-chain

After broadcast, confirm the new covenant state matches expectations
on every node operating this shard.

**TODO(WW-covenant-tip)**: same gap as in §1. Until a
`bsvm covenant tip` subcommand lands, the verification is:

1. Query your BSV node for the broadcast txid:
   ```bash
   bitcoin-cli -testnet getrawtransaction "$UPGRADE_TXID" 1
   ```
2. Confirm the txid is mined (≥1 confirmation) and that its single
   output's locking script hex equals the `newRollupScriptHex` from
   the rotation summary.
3. On each node operating this shard, restart the daemon (or wait
   for its next covenant-state read) and confirm it picks up the
   new tip via the existing structured-log emission in
   `pkg/covenant/state.go` (`level=info msg="rollup advance"
   covenantTxId=...`).

If a node disagrees with the rest of the shard's view of the
covenant tip, that node has a stale BSV connection or has been
network-partitioned during the rotation. Restart its BSV peer
connections.

---

## 7. Bridge re-deploy

The bridge covenant is **not** auto-rotated. Its
`StateCovenantScriptHash` readonly is bound to the OLD rollup
script's hash; with the new rollup deployed, deposits are still
accepted (the bridge never reads the new script directly), but
withdrawal proofs that bind to the rollup script will be rejected
by the bridge until you redeploy it. (See
`rotate-vk.go::32-50` for the rationale.)

The redeploy is intentionally manual because:

* The bridge holds bridged BSV. Touching it carries higher blast
  radius than rotating the rollup.
* In-flight withdrawals proven under the OLD bridge must be drained
  or re-proven before the bridge swap. We do not want a rotation
  script to silently invalidate user-visible state.

Sequence (high level — `bridge-only` redeploy CLI is shipped via
`deploy/covenant/cmd/bridge-compile`; consult its `--help`):

1. Drain or re-prove all pending withdrawals (manual, per
   operator workflow — see `docs/decisions/S-withdrawal-and-rollback.md`).
2. Re-compile the bridge with the rotated rollup script hash.
3. Inspect the dry-run summary, then re-run with `--broadcast`.

---

## 8. Rollback

There is **no on-chain rollback** for a successfully-broadcast
rotation. The new covenant UTXO is now the canonical state. If the
new VK turns out to be defective, you must:

1. Stop all prover nodes on the shard so no new proofs land
   against the bad VK.
2. Re-stamp the pin file with the previous VK hash AND restore the
   previous in-tree ELF blob at `prover/guest/elf/bsvm-guest`
   (Phase 2 will pick it up automatically on next host-* build).
3. Run a SECOND rotation back to the previous VK
   (the original VK is just another rotation target — if you have
   the old guest ELF or can rebuild it, you can rotate to it).
4. Once the second rotation lands, restart the prover nodes.

The window between a bad rotation and the corrective rotation is
where the shard is unprovable. Plan rotations against periods of
low traffic; for non-urgent fixes, broadcast against testnet first
(`BSVM_TESTNET=1` integration tests in
`test/integration/rotate_vk_test.go` are the closest existing
testnet hook).

---

## 9. TODO summary (helpers that would shrink this runbook)

The cross-cutting helper gaps surfaced above:

* **`bsvm covenant tip`** — read-only subcommand that prints
  `covenantTxId`, `covenantVout`, `covenantSatsLive`,
  `currentStateRootHex`, `currentBlockNumber` for the live shard.
  Wraps `pkg/covenant.LoadState` + `pkg/covenant.ReadRollupState`.
  Eliminates the manual chain-walking step in §1.
* **`bsvm-host-bridge --mode upgrade-proof`** — produces the
  upgrade-input proof bundle (`publicValuesHex`, `batchDataHex`,
  `proofBlobHex`) given `pre_state_root`, `new_covenant_script`,
  `block_number`. Eliminates the "write a one-off Rust binary" step
  in §1.
* **`bsvm dev sign-rotation`** — signs the upgrade tx's input-0
  sighash with the supplied governance WIF. Either standalone or
  takes the `rotate-vk.partial.json` and emits the signature hex.
  Eliminates the cross-tool secp256k1-signing step.
* **`bsvm covenant tail` / structured-log helper** — surfaces the
  existing `rollup advance` log lines in a format suitable for
  copy-paste auditing.

These are the right scope for a follow-up "rotation operator
ergonomics" milestone; tracking them here so they don't get lost.

---

## 10. Cross-references

* `deploy/covenant/cmd/rotate-vk/main.go` — the binary entry point.
* `deploy/covenant/rotate-vk.go` — the library half + config doc.
* `deploy/covenant/README.md` — deploy / compile companion runbook.
* `docs/decisions/sp1-reproducible-build-2026-05.md` — why the VK
  is now reproducible across operators.
* `docs/decisions/vk-rotation-wire-format-2026-04.md` — example
  rotation event with full pre/post hash recording.
* `docs/operator/sp1-build.md` — how to obtain the new VK from a
  fresh guest source change.
* `pkg/covenant/upgrade.go` — the on-chain `Upgrade` method
  semantics; reading this is the way to understand which fields are
  asserted on-chain.
* `test/integration/rotate_vk_test.go` — assembly-path coverage
  (real testnet rotation gated behind `BSVM_TESTNET=1`).
