# SP1 Verifying Key Rotation — Wire-Format Fix (2026-04)

Date: 2026-04-29
Branch: `main`

## Why this rotation

The SP1 cycle bench (`pkg/prover.TestSP1Bench`, wired in round-9
XX) reported all five fixtures at exactly `cycles=10_227` with empty
public values (`pv_hash = SHA256("")`) on its first end-to-end run.
Investigation traced this to a **silent bincode wire-format mismatch**
between the host (`prover/host-bridge/`, `prover/host-bench/`) and the
guest:

  * Host wrote `[u8; 20]` for addresses and `[u8; 32]` for U256/B256
    — bincode emits raw fixed-byte arrays with no length prefix.
  * Guest's `BatchInput` (and nested `AccountState`,
    `EvmTransaction`, `BlockContext`, `AccountProofWitness`,
    `StorageSlot`) used `alloy_primitives` types whose default
    `Serialize` routes through `serialize_bytes`, which bincode
    encodes as a length-prefixed byte string (8-byte u64 length +
    bytes).
  * The guest's `bincode::deserialize::<BatchInput>` read the host's
    first 8 raw bytes as a length, panicked or returned garbage, and
    exited with empty public values.

The fix is `prover/guest/src/wire_format.rs`: serde-with helpers
(`address_as_bytes`, `option_address_as_bytes`, `b256_as_bytes`,
`u256_as_bytes`) that force every alloy-typed wire field to the raw
fixed-byte layout the host actually writes.
`#[serde(with = "wire_format::…")]` annotations were applied to the
six wire-facing structs.

These annotations change the bytes of `prover/guest/src/main.rs` and
`prover/guest/src/mpt.rs`, which means the compiled
`bsvm-guest` ELF rotates, which means the SP1 verifying key rotates.

The fix also affects production proving — `prover/host-bridge/`
shipped the same wire-broken behaviour; the bug was hidden because no
test exercised the full host-bridge → SP1 guest → public-values
pipeline (the dual-EVM equivalence test bypasses SP1 by running
`host-revm` directly).

## VK hashes

Both hashes computed with `cargo prove vkey --elf <ELF>` against the
ELF rebuilt from a clean tree by SP1's deterministic build script.

| Tag | Hash |
| --- | ---- |
| OLD (pre-fix, wire-broken `BatchInput`) | `0x008e9a57422fe11b537d0d2e21c323074e2bb61f2f4d99dd41cd1d5b8a853914` |
| NEW (post-fix, `wire_format` helpers in place) | `0x0012da50069d745a7ae20f4c5ea2920f5dbb4e83594ce8f34d3e3c62c1bfa04e` |

The OLD hash was the round-9 WW pin (CC-vk-rotation-2026-04 →
WW-vk-pin-2026-04). The NEW hash was sampled by running
`prover/host-bridge/target/release/bsvm-host-bridge` against a
real bench envelope and reading `vk_hash` from its JSON output.

## SP1 ELF non-determinism (caveat the operator MUST know)

A surprise surfaced while wiring the bench's VK-pin canary: SP1's
`sp1_build::build_program` produces a **different ELF on every
rebuild even from byte-identical source**. The output ELF carries
build-time metadata that perturbs its bytes, which rotates the
verifying key on every rebuild.

Concretely, two rebuilds done from the same commit on the same
machine produced `vk_hash = 0x00932d7e…` (host-bench at 13:20) and
`vk_hash = 0x0012da50…` (host-bridge at 13:26). Same source, same
Cargo.lock, same toolchain — different ELF. The bench's first
end-to-end VK check (added in this same change set) fired against
the local rebuild because the locally-rebuilt ELF naturally
disagrees with whatever pin was committed to git.

Implication: `prover/guest/elf/SP1VerifyingKeyHash.txt` is a
**snapshot of one specific reference build**, not a value any
contributor can reproduce on demand. The pin's role is:

* Document the VK the operator chose to deploy on a particular
  shard.
* Drive `deploy/covenant/compile.go` and
  `deploy/covenant/rotate-vk.go` so they bake / verify the same
  value the operator audited.

It is NOT:

* A unit-test gate. The bench's VK check is an informational log
  line, not a `t.Fatalf` (would otherwise fail every fresh local
  build).
* A reproducibility claim. A second operator rebuilding from the
  same commit will get a different VK and need to re-run the
  rotate-vk path on every shard they administer (or co-ordinate to
  share one operator's ELF artefact).

Reproducible-build follow-up tracked separately. Possible paths:

1. SP1 supports `cargo prove build --reproducible` (community
   discussion ongoing); enabling it inside `sp1_build::build_program`
   would let every rebuild yield a bit-identical ELF.
2. Pin a single canonical operator ELF in the repo as a binary
   artifact (large, but unambiguous).
3. Build the ELF in CI from a hermetic Docker image and publish the
   artifact + VK alongside each release.

Until that lands, every rotation event is keyed off "the operator
who runs `cargo prove build` on a clean tree at this commit" — the
NEW value in the table above is from this 2026-04-29 reference
build.

## What this rotation requires on-chain

Same playbook as the prior CC rotation. For each live shard:

1. Re-stamp `prover/guest/elf/SP1VerifyingKeyHash.txt` with the NEW
   hash:
   `0x0012da50069d745a7ae20f4c5ea2920f5dbb4e83594ce8f34d3e3c62c1bfa04e`
   (already done in the same commit as this doc).
2. Update every per-shard genesis manifest's
   `sp1_verifying_key_hash` field to NEW.
3. Use `deploy/covenant/rotate-vk.sh --broadcast` (built in round-10
   YY) to broadcast the on-chain rotation transaction. Governance keys
   sign the upgrade tx; the covenant's `BuildUpgradeUnlockScript`
   spends the current covenant UTXO and creates a new one with the
   NEW VK pinned.
4. After broadcast, every node in the shard automatically picks up
   the new VK on next covenant-state read; no node-local config
   change required.

For shards still on testnet / pre-deployment, no on-chain action is
needed — re-running `deploy/covenant/deploy.sh` will bake the NEW
hash into a fresh genesis covenant.

## Defence-in-depth: the wire-compat tests

`prover/guest/src/wire_format.rs::tests` adds six unit tests
(`cargo test --lib`) that bincode-encode synthetic mirrors of
host-bridge's `Guest*` struct shapes and decode them as guest types
with the wire helpers, asserting field-by-field equality. A future
serde change in either direction now breaks these tests at
compile/test time instead of producing silent zero-pv proofs at run
time.

The host-bridge → guest end-to-end was also verified manually by
piping a captured bench envelope into the rebuilt
`bsvm-host-bridge` binary; the JSON output reports
`cycles=329_685`, `pv_bytes=280`, real distinct pre/post-state roots,
and the NEW vk_hash above.

## Cross-references

* `docs/perf/sp1-cycles-2026-04.md` — full bench-run snapshot, all
  five fixtures, cycles + budget headroom.
* `docs/decisions/CC-vk-rotation-2026-04.md` — prior rotation (the
  `tx_type` defaulting bug).
* `prover/guest/src/wire_format.rs` — the fix and its unit tests.
* `prover/guest/elf/SP1VerifyingKeyHash.txt` — canonical pin file.
* `deploy/covenant/rotate-vk.go` — the rotation entry point that
  reads this pin.
