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
   `currentBlockNumber`, `lockingScriptHex`).

   Use the read-only `bsvm covenant tip` subcommand against any
   node's data directory:

   ```bash
   bsvm covenant tip \
       --datadir /path/to/node/data \
       --bsv-rpc "$BSVM_BSV_RPC" \
       --bsv-network "$BSVM_BSV_NETWORK" \
       > tip.json
   ```

   The emitted JSON carries every rotation-only field
   `RotateVKConfig` requires (`covenantTxId`, `covenantVout`,
   `covenantSatsLive`, `currentStateRootHex`, `currentBlockNumber`)
   plus the live `lockingScriptHex` and its `lockingScriptSha256`
   (the latter is the `StateCovenantScriptHash` shape the bridge re-
   deploy in §7 consumes). Internally it pulls the cached covenant
   tip from `pkg/block.ChainDB` (`ReadCovenantTxID` +
   `ReadCovenantState`, decoded via `pkg/covenant.DecodeCovenantState`)
   and asks the BSV node for the live UTXO's script + value via
   `getrawtransaction verbose=1`. Stop the node before running it if
   you want a guaranteed-stable snapshot — the daemon is the single
   writer to chaindata, so a running daemon may apply an advance
   between your tip read and the rotation broadcast (in which case
   ARC will reject with `MISSING_INPUT` and you simply re-read).

4. **A fresh SP1 proof bundle** (`publicValuesHex`, `batchDataHex`,
   `proofBlobHex`) that proves the no-op upgrade transition
   (preStateRoot → preStateRoot, blockNumber+1, new covenant script
   bound).

   `bsvm-host-bridge` exposes `mode = "upgrade-proof"` for this. It
   takes the rotation inputs on stdin and emits the JSON shape
   `RotateVKConfig.proofBundlePath` consumes directly:

   ```bash
   cat <<EOF | ./prover/host-bridge/target/release/bsvm-host-bridge \
     > rotation-upgrade-proof.json
   {
     "mode": "upgrade-proof",
     "pre_state_root":         "$CURRENT_STATE_ROOT_HEX",
     "new_covenant_script_hex": "$NEW_ROLLUP_SCRIPT_HEX",
     "block_number":           $CURRENT_BLOCK_NUMBER,
     "chain_id":               $CHAIN_ID
   }
   EOF
   ```

   Where:

   * `$CURRENT_STATE_ROOT_HEX` is the live covenant's `StateRoot`
     readonly (32 bytes hex, with or without `0x` prefix).
   * `$NEW_ROLLUP_SCRIPT_HEX` is the dry-run summary's
     `newRollupScriptHex` (the rebuilt rollup locking script bytes).
   * `$CURRENT_BLOCK_NUMBER` is the live covenant's `BlockNumber`
     readonly (the upgrade tx advances this to `+1`).
   * `$CHAIN_ID` is the EIP-155 chain id from the OperatorConfig.

   The output JSON has fields `publicValuesHex` (always 280 bytes per
   spec 12), `batchDataHex`, `proofBlobHex`, `vkHash`, `real_proof`,
   and `note`. Wire it into the rotation config as
   `proofBundlePath: "rotation-upgrade-proof.json"`.

   > **Synthetic-proof caveat**: the bundle that `mode=upgrade-proof`
   > emits today is **shape-correct but not cryptographically valid**
   > (`real_proof: false`). The on-chain `runar.VerifySP1FRI`
   > assertion in the `Upgrade*` methods rejects it. This is useful
   > for assembly + multisig partial-sig coordination + dry-run
   > broadcast against a testnet ARC instance, BUT a real mainnet
   > rotation requires a real STARK proof. Generating a real proof
   > requires a guest entry point that commits the spec-12 upgrade
   > publicValues layout — that entry point doesn't exist yet (the
   > production `prover/guest/src/main.rs::main` commits a different
   > layout: receiptsHash at pv[64..96), withdrawalRoot at
   > pv[144..176), migrateScriptHash hard-coded to zeros, and
   > big-endian chainId/blockNumber instead of little-endian).
   > Adding it would rotate the SP1 verifying key (the very thing
   > this runbook coordinates), so the migration path is:
   > (1) ship the guest entry point in a regular SP1 build cycle
   > (which itself requires a VK rotation against the synthetic
   > stand-in path on testnet), then (2) point this command at the
   > new entry point. Tracked alongside `WW-upgrade-proof-real-stark`.

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

   Use `bsvm dev sign-rotation` to compute the sighash and sign it
   with a governance WIF. The helper has two input modes:

   ```bash
   # Mode A — sign a fully-built unsigned upgrade tx (HSM/airgap):
   bsvm dev sign-rotation \
       --wif path/to/governance.wif \
       --upgrade-tx-hex "$UPGRADE_TX_HEX" \
       --prev-locking-script-hex "$LIVE_COVENANT_LOCK_HEX" \
       --prev-sats "$COVENANT_SATS_LIVE"
   # → prints the BSV-canonical signature hex (DER + 0x41 sighashType
   #   byte) on stdout. Paste into governanceSigsHex in rotation.json.

   # Mode B — sign + append into an in-flight rotate-vk.partial.json:
   bsvm dev sign-rotation \
       --wif path/to/governance.wif \
       --partial-bundle rotate-vk.partial.json \
       --covenant-txid "$COVENANT_TXID" \
       --covenant-vout 0 \
       --covenant-sats "$COVENANT_SATS_LIVE" \
       --prev-locking-script-hex "$LIVE_COVENANT_LOCK_HEX" \
       --out rotate-vk.partial.json
   # → appends the new signature to the bundle's governanceSigsHex
   #   and prints the same hex on stdout for audit.
   ```

   Both modes compute BIP-143 `SIGHASH_ALL | SIGHASH_FORKID = 0x41`
   over input 0 with `prevLockScript = current covenant locking
   script`, `prevSats = covenantSatsLive`. The emitted signature
   is DER + sighashType byte, matching what
   `covenant.BuildUpgradeUnlockScript` consumes for the
   `Upgrade*` methods.

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
   input 0 via `bsvm dev sign-rotation --partial-bundle ...` (Mode B
   in §1 step 5). The helper appends the signature directly to the
   bundle's `governanceSigsHex` when `--out` is set, OR prints the
   signature hex on stdout for hand-off into the rotation config.
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
4. On each node, re-run `bsvm covenant tip --datadir ... --bsv-rpc ...`
   and assert that `covenantTxId == $UPGRADE_TXID` and that
   `lockingScriptHex` equals the rotation summary's
   `newRollupScriptHex`. Disagreement here means that node has not
   yet observed the upgrade — restart its BSV peer connections (see
   below).

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

* ~~**`bsvm covenant tip`**~~ — **shipped.** Read-only subcommand
  that prints `covenantTxId`, `covenantVout`, `covenantSatsLive`,
  `currentStateRootHex`, `currentBlockNumber`, `lockingScriptHex`,
  and `lockingScriptSha256` for the live shard. Wraps
  `pkg/block.ChainDB.ReadCovenantTxID` /
  `ReadCovenantState` (decoded via
  `pkg/covenant.DecodeCovenantState`) plus a
  `getrawtransaction verbose=1` round-trip for the live UTXO's
  script + sats. See `cmd/bsvm/covenant.go`.
* ~~**`bsvm-host-bridge --mode upgrade-proof`**~~ — **shipped
  (synthetic-proof phase).** Produces the upgrade-input proof bundle
  (`publicValuesHex`, `batchDataHex`, `proofBlobHex`, `vkHash`)
  given `pre_state_root`, `new_covenant_script_hex`, `block_number`,
  `chain_id` on stdin. Today the bundle is shape-correct but the
  STARK proof bytes are synthetic (`real_proof: false`); the
  follow-up `WW-upgrade-proof-real-stark` work adds a guest entry
  point that commits the spec-12 upgrade publicValues layout so the
  on-chain `VerifySP1FRI` accepts the proof. See
  `prover/host-bridge/src/main.rs::run_upgrade_proof`.
* ~~**`bsvm dev sign-rotation`**~~ — **shipped 2026-05.** Signs the
  upgrade tx's input-0 sighash with the supplied governance WIF.
  Two modes: `--upgrade-tx-hex` (raw, HSM/airgap workflow) and
  `--partial-bundle` (chains into the rotate-vk M-of-N partial-sig
  flow). See §1 step 5 for invocation.
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
* `cmd/bsvm/dev_sign_rotation.go` — the `bsvm dev sign-rotation`
  helper that closes the operator-side signing gap (covered by
  `cmd/bsvm/dev_sign_rotation_test.go`).
* `test/integration/rotate_vk_test.go` — assembly-path coverage
  (real testnet rotation gated behind `BSVM_TESTNET=1`).
