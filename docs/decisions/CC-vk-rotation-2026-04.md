# CC: SP1 Verifying Key Rotation — 2026-04

Author: agent-a3acc150029b70c3c (CC-vk-rotation-2026-04)
Date: 2026-04-26
Branch: `worktree-agent-a3acc150029b70c3c`

## Why this rotation

`prover/guest/src/main.rs` constructed `revm::context::TxEnv { ... }`
without setting the `tx_type` field. `TxEnv` derives a default value
of `0` (Legacy) for `tx_type` when the field is omitted, so revm
priced every EIP-2930 / EIP-1559 / EIP-4844 transaction in the guest
as if it were a legacy tx:

  * Coinbase received `gas_used * gas_price` (max-fee-per-gas times
    gas) instead of priority-tip-only.
  * The basefee burn was not subtracted from the sender as a separate
    deduction.

That mis-pricing changed the post-state root the guest committed, so
the Go EVM (which prices these tx types correctly via
`pkg/block/state_transition.go`) and the SP1 STARK proof drifted on
every batch that contained a typed tx. Under the dual-EVM equivalence
guarantee in `CLAUDE.md`, that is a critical correctness bug.

The fix is a single-line addition (`tx_type: decoded.tx_type,`) in the
`TxEnv` literal in `prover/guest/src/main.rs`. The decoder
(`prover/guest/src/tx.rs`) already pins each supported wire type to its
canonical value — Legacy=0x00, EIP-2930=0x01, EIP-1559=0x02,
EIP-4844=0x03 — and deposits (0x7E) are handled in the sibling branch
above the construction site, so they never reach this `TxEnv`.

Because the fix lives inside the SP1 guest, it changes the guest ELF
and therefore the SP1 verifying key. Mainnet eligibility under specs
10–12 requires VK pinning, so this rotation must be propagated through
every shard's genesis manifest before the new guest is allowed to
advance state on-chain.

## VK hashes

Both hashes computed with `cargo prove vkey --elf <ELF>` against the
`riscv64im-succinct-zkvm-elf` ELF produced by `cargo prove build` from
`prover/guest/`. SP1 toolchain at the time of rotation:
`cargo-prove sp1 (7028cb0 2026-02-26)`.

| | VK Hash |
|---|---|
| OLD (pre-rotation, buggy `tx_type` default) | `0x00077ef240240194cd9596b290e8067082cc5481893a76f66b43806e0e572fce` |
| NEW (post-rotation, `tx_type` from decoder) | `0x008e9a57422fe11b537d0d2e21c323074e2bb61f2f4d99dd41cd1d5b8a853914` |

The hashes were sampled by stashing the source-code change, running
`cargo prove build` + `cargo prove vkey` for the OLD reading, then
restoring the change and re-running the same pipeline for the NEW
reading. Build artifacts live under
`prover/guest/target/elf-compilation/riscv64im-succinct-zkvm-elf/release/bsvm-guest`.

## Files touched

| Path | Change |
|---|---|
| `prover/guest/src/main.rs` | Add `tx_type: decoded.tx_type,` inside the `TxEnv { ... }` literal in the user-tx branch (around line 471). Comment block above the field explains the bug, the four supported wire values, and why deposits never reach this site. |

No source-code constants in `pkg/` were touched. The pinned VK enters
the system through per-shard genesis manifests
(`pkg/shard/manifest.go`, `pkg/shard/derive.go`) — the
`SP1VerifyingKeyHash` is supplied at deploy time, not baked into Go
source. Operators perform the rotation by re-deploying the covenant
script with the NEW VK on each shard.

## Operator action required

Before the new guest may advance state on any shard:

1. Rebuild the SP1 guest from `prover/guest/` (`cargo prove build`).
   Confirm the resulting ELF prints
   `0x008e9a57422fe11b537d0d2e21c323074e2bb61f2f4d99dd41cd1d5b8a853914`
   under `cargo prove vkey`.
2. Update every per-shard genesis manifest's `sp1_verifying_key_hash`
   to the NEW value.
3. Compile a fresh covenant locking script per mode (FRI / Groth16 /
   Groth16WA) using the updated manifest. The on-chain
   `SP1VerifyingKeyHash` readonly slot must equal the NEW hash.
4. Deploy the new covenant on testnet first; verify a real-prover
   advance succeeds (`make e2e-testnet`). Only then promote to
   mainnet.
5. Pin the OLD hash in the operator runbook as the "do not deploy"
   sentinel until the rotation has propagated to every shard.

The rotation is one-way. Old proofs (generated against OLD VK) cannot
be replayed on a covenant pinned to NEW, and vice versa, so the
governance freeze + script-upgrade path is the only safe route. Mode
choice does not change: this is a guest-ELF bump, not a verification
mode swap.

## Verification

| Check | Result |
|---|---|
| `gofmt -l pkg/block/` | clean |
| `go vet ./pkg/block/...` | clean |
| `go test ./pkg/block/... -count=1` | PASS |
| `go test ./pkg/prover/ -run TestDualEVMEquivalence -count=1` | PASS (host-side internal-consistency only — see `equivalence_test.go` TODO(equivalence)) |
| `cargo prove build` (`prover/guest/`) | clean (1 dead-code warning, pre-existing) |
| `cargo prove vkey` against rebuilt ELF | matches NEW hash above |

The dual-EVM real-revm comparator described in
`pkg/prover/equivalence_test.go::TestDualEVMEquivalence_RealRevmHarness`
is still skipped — `prover/host-revm` does not exist in-tree. Once
that comparator lands, the EIP-1559 fixture will be the canonical
post-rotation regression check (the Go side spends `gas_used * tip`
on the coinbase; the OLD guest would have spent `gas_used * fee_cap`
and diverged here).

## Open follow-ups

  * Land `prover/host-revm` so the equivalence harness exercises a
    real revm comparator on every CI run. Without it the rotation is
    correctness-by-inspection only — the Rust unit tests in
    `prover/guest/src/tx.rs` cover decoding but not pricing.
  * Add a guest-side regression test that asserts an EIP-1559 batch
    leaves the coinbase with priority-tip-only revenue (not
    `gas_used * fee_cap`). The existing `prover/guest/src/main.rs`
    has no `#[cfg(test)]` block; the closest existing surface is
    `lib.rs` which only re-exports `tx::`.
  * Rotate VK pin on every operator-controlled shard manifest. Track
    completion in a separate operations follow-up.
