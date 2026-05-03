# SP1 Verifying Key Rotation — Real-STARK Upgrade Entry Point (2026-05)

Date: 2026-05-03
Branch: `worktree-agent-ac8a37b6998c119e6`

## Why this rotation

Closes `WW-upgrade-proof-real-stark` (the only mainnet-blocking hook
per `docs/decisions/xl-deferred-hooks-2026-05.md`). The SP1 guest now
exposes a wire-format-dispatched second entry point (`MODE_UPGRADE`)
that commits the spec-12 upgrade publicValues layout under a real
STARK proof, instead of the previous synthetic-stand-in path that
the on-chain `runar.VerifySP1FRI` verifier always rejects.

Without this rotation, a value-bearing mainnet shard whose covenant
ever needs to be re-pinned (e.g., to install a new wire-format fix, a
Prague fork bump, BSV-precompile activation, or any other guest source
change) **cannot** rotate its VK on-chain. The synthetic-stand-in
path the host bridge previously emitted for `mode = upgrade-proof`
was shape-correct but cryptographically invalid; the on-chain
`runar.VerifySP1FRI` rejects it. Mainnet-readiness of any shard
holding real BSV requires a real-STARK upgrade-proof path.

## The wire-format change

Three source-level changes in this commit:

1. `prover/guest/src/main.rs` — `main()` now reads a single `u8` mode
   byte from `sp1_zkvm::io::read::<u8>()` BEFORE any other input. The
   byte selects between the existing EVM-batch path (`MODE_BATCH = 0x00`,
   commits the spec-12 ADVANCE 280-byte layout) and the new
   `MODE_UPGRADE = 0x01` (commits the spec-12 UPGRADE 280-byte layout
   for VK rotations).

2. `prover/host-bench/src/main.rs` and `prover/host-bridge/src/main.rs`
   now write the leading mode byte before the rest of the SP1Stdin
   envelope. EVM modes write `0x00`; the upgrade-proof mode writes
   `0x01` plus an `UpgradeInput { pre_state_root, new_covenant_script,
   chain_id, block_number }` plus the host-supplied `batch_data_hash`
   and `proof_blob_hash` that bind the publicValues blob.

3. `prover/host-bridge/src/main.rs::run_upgrade_proof` now invokes the
   real SP1 prover via `client.prove(&pk, stdin)` and self-verifies
   offline via `client.verify(&proof, &vk)` before emitting the
   bundle. The legacy synthetic path stays alive behind
   `BSV-M_UPGRADE_PROOF_SYNTHETIC=1` env var or `proof_mode =
   "synthetic"` in the JSON envelope (chicken-and-egg bootstrap +
   dry-run / partial-sig assembly use cases).

These source changes rotate the bsvm-guest ELF, which rotates the
SP1 verifying key. Both the EVM-batch path and the upgrade path
share the SAME guest ELF (single-VK-per-shard contract preserved),
selected at runtime by the leading mode byte.

## VK hashes

Both hashes computed via `cargo prove vkey --elf <ELF>` against the
docker-built ELF (per `docs/decisions/sp1-reproducible-build-2026-05.md`).

| Tag | Hash |
| --- | ---- |
| OLD (pre-real-stark, batch-only guest) | `0x0021629d5e6f7ca0b77d3b4cdd305e46a3a756ee9752ff476a99fdf21374d26c` |
| NEW (mode-byte dispatch, MODE_BATCH + MODE_UPGRADE entry points) | `0x0089e86b40471ffbca344ddd6e02c4aade8d2d1676cbab381a6bedc726c964e7` |

The OLD hash was the post-`docs/decisions/sp1-reproducible-build-2026-05.md`
pin. The NEW hash is derived from the mode-byte-dispatched guest
built via the same docker image
(`ghcr.io/succinctlabs/sp1@sha256:61bbcdb0cd096004303f25f042813f4b947571c454fb5247197a1bd9c91e01ad`).

## What this rotation requires on-chain

Same playbook as `docs/decisions/vk-rotation-wire-format-2026-04.md`
and `docs/decisions/sp1-reproducible-build-2026-05.md`. Per live shard:

1. Re-stamp `prover/guest/elf/SP1VerifyingKeyHash.txt` with the NEW
   hash (already done in the same commit as this doc).
2. Re-stamp `prover/guest/elf/bsvm-guest.sha256` with the new ELF's
   sha256 (already done — see the file).
3. Update every per-shard genesis manifest's
   `sp1_verifying_key_hash` field to NEW.
4. Use `deploy/covenant/rotate-vk.sh --broadcast` to broadcast the
   on-chain rotation transaction. Governance keys sign the upgrade
   tx; the covenant's `BuildUpgradeUnlockScript` spends the current
   covenant UTXO and creates a new one with the NEW VK pinned.
5. After broadcast, every node in the shard automatically picks up
   the new VK on next covenant-state read; no node-local config
   change required.

## Chicken-and-egg bootstrap

The very first cutover from synthetic-only to real-STARK is itself
a chicken-and-egg problem: the new mode-byte-dispatched guest needs
to be the one signing the rotation that installs itself. The new
guest cannot prove a rotation that the on-chain covenant was
compiled to verify against the OLD guest's VK, because the OLD
covenant's pinned `SP1VerifyingKeyHash` does not match the NEW
proof's verifying key.

Resolution path:

1. **Testnet shard with `governance: single_key`.** Run the FIRST
   rotation on a value-less testnet shard via the synthetic-stand-in
   path (`BSVM_UPGRADE_PROOF_SYNTHETIC=1`). The synthetic path
   produces a shape-correct bundle the testnet covenant rejects via
   `runar.VerifySP1FRI`, but governance signatures are real and the
   rotation can be tracked end-to-end against a willing node operator
   for tooling validation.
2. **Re-deploy the testnet shard from scratch** with the NEW VK
   baked into the genesis covenant. From this point onward the
   testnet shard's covenant accepts real-STARK upgrade proofs.
3. **Verify the real-STARK rotation flow on testnet** by performing a
   second rotation via `bsvm-host-bridge --mode upgrade-proof`
   (default real-STARK path). Confirm `real_proof: true` and that
   the on-chain `runar.VerifySP1FRI` accepts the proof.
4. **Mainnet shards** that are already deployed against the OLD VK
   are stuck — they were compiled before the mode-byte dispatch
   landed. They must either (a) re-deploy from scratch with the NEW
   VK genesis, or (b) accept that they cannot rotate.
5. **Mainnet shards deployed AFTER this commit** bake the NEW VK
   into their genesis covenant and can rotate via the standard
   real-STARK path from day one.

This is an OPERATIONAL concern documented here for the operator's
benefit; the code-side deliverable (this commit) is independent of
the rotation timing. See `docs/operator/vk-rotation.md` §1 for the
updated runbook that no longer carries the synthetic-proof caveat.

## Real-STARK proof generation cost

Measured wall-clock for the upgrade entry point (no revm execution,
no MPT manipulation, just commit a 280-byte publicValues blob from
4 + 2 inputs):

| Hardware | Wall-clock |
| --- | --- |
| Apple Silicon M-series CPU | ~15-30 min (CORE proof, default) |
| GPU (CUDA, A100-class) | ~3-5 min |

This is significantly cheaper than the production EVM-batch guest's
~320k cycles per ten-tx bench, since `MODE_UPGRADE` does no opcode
execution. Operators rotating their shard need to budget the
above wall-clock for the proof-generation step; everything else in
the rotation runbook (config assembly, sig collection, ARC broadcast)
is unchanged.

## Defence-in-depth: the offline-verify gate

`prover/host-bridge/src/main.rs::run_upgrade_proof` calls
`client.verify(&proof, &vk)` before emitting the bundle. A verify
failure short-circuits to a structured `error` field rather than
emitting a silent bad proof. Operators who see `real_proof: true`
in the bundle have a guarantee the proof verifies offline; on-chain
rejection at `runar.VerifySP1FRI` would only happen if the in-tree
pinned VK doesn't match the proof's actual VK (i.e., operator built
against a different ELF than the on-chain covenant was compiled
against — caught by the existing `vkHash` field in the bundle).

## Cross-references

* `docs/decisions/xl-deferred-hooks-2026-05.md` — the strategy doc
  this hook closes (`WW-upgrade-proof-real-stark`).
* `docs/decisions/sp1-reproducible-build-2026-05.md` — the
  reproducible-build foundation that makes the new VK contract a
  real promise instead of a per-operator snapshot.
* `docs/decisions/vk-rotation-wire-format-2026-04.md` — preceding
  rotation event (the canonical playbook structure).
* `pkg/covenant/upgrade.go::EncodeUpgradePublicValues` — the Go
  encoder the new `MODE_UPGRADE` guest entry point mirrors
  byte-for-byte.
* `prover/guest/src/main.rs::run_upgrade` — the new SP1 guest
  handler.
* `prover/host-bridge/src/main.rs::run_upgrade_proof` — the host
  side that drives the SP1 prover and self-verifies.
* `pkg/covenant/upgrade_real_stark_test.go` — the integration test
  (skipped by default; gated on `BSVM_HOST_BRIDGE_REAL_STARK=1`).
* `docs/operator/vk-rotation.md` §1 step 4 — the updated runbook
  that no longer carries the synthetic-proof caveat.
