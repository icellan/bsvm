# SP1 Cycle Bench — 2026-04 Snapshot

End-to-end run of the `prover/host-bench/` harness over the dual-EVM
equivalence fixture set. Captures cycle counts in EXECUTE mode (no
proof). All numbers below are post-fix; see "What was broken" for the
silent-failure story the first run uncovered.

## Machine

- CPU: Apple M3
- RAM: 24 GB (25,769,803,776 bytes)
- macOS 26.3
- SP1 SDK 6.1.0 (Cargo resolved up from the 6.0.2 floor)
- SP1 toolchain `gkgUAXxgDg` (rustc 1.93.0-dev, succinct fork)

## Raw results — TestSP1Bench, EXECUTE mode

| Fixture            | Cycles  | Wall (ms) | PV bytes | PV hash                                                              |
| ------------------ | ------: | --------: | -------: | -------------------------------------------------------------------- |
| LegacyTransfer     | 319,432 |        28 |      280 | `0xcdfb18ea4cba4e9509de11808b21b80c5c9c7a77e4bc581032272a640a4982b0` |
| AccessListTransfer | 319,782 |        36 |      280 | `0x85854d819c6db3e63a1e65352a4ef3c9b3667033c43f8b426f31c63b0d8cc4a3` |
| DynamicFeeTransfer | 332,747 |        35 |      280 | `0x62035eeb12bd59f63dda289ba34d301e478beae8cb8d98b9c1efd5efcc1caacc` |
| BlobTx             | 301,073 |        43 |      280 | `0x492c7c420ae5ef535b43b1abfbc189569da4fe6146f21416aaa5e0237469940e` |
| ContractCreate     | 319,080 |        43 |      280 | `0x5972ba7be4c826904e372c70916cbd9efa044e6af8d93d6239dfb32dbb1f65f8` |

Per-fixture wall time on the native CPU SP1 prover: ~22 s setup + ~30
ms execute. Setup is one-shot per `client.setup(GUEST_ELF)` call.

Decoded public-values for `LegacyTransfer` (proof of real EVM run):

```
[0..32]    pre_state_root  = 6d17fd75955d877fa350b427922ccd41110421f019e91c1f279856dde7a31984
[32..64]   post_state_root = d79a2dc3c929b8653f66a30d7e40a23c62e85ab217e9453a4b7fc339238d04a1
[64..96]   receipts_hash   = b2916363ed9596c7d5739323195f858a36885e64a41fa6997c61c87e252b5d65
[96..104]  gas_used        = 0x5208 = 21000  ← simple transfer baseline
[104..136] batch_data_hash = e7d71164c25a643bd4ff28f9f371803451981e1da0f0f40d97456c876d73ea58
[136..144] chain_id        = 0x080fbf7 = 8453111  (matches benchChainID / guest CHAIN_ID)
[144..176] withdrawal_root = 00…00
[176..208] inbox_before    = 2b32db6c…  (hash256(zero32) — empty queue marker)
[208..240] inbox_after     = 2b32db6c…  (no draining in bench fixtures)
[240..272] migrate_hash    = 00…00
[272..280] block_number    = 0x01
```

## Interpretation

All five fixtures execute the EVM, commit the full 280-byte public
values block, and produce **distinct** post-state roots / receipts
hashes / pv hashes. Cycle counts are well within budget across the
board:

- Transfers (Legacy / AccessList / DynamicFee / BlobTx): ~300 K – 333
  K cycles. Budget 5 M. **~15× headroom.**
- ContractCreate: ~319 K cycles. Budget 50 M. **~157× headroom.**

The bench fixtures are intentionally tiny (single tx, single
pre-funded sender, no contract calls beyond ContractCreate's empty
constructor). Real workloads with multiple txs, storage reads, and
non-trivial contract calls will scale up linearly per tx; spec 11's
budget targets are sized for batches of ~64 txs.

The cycle delta between fixtures is small (~30 K range) because the
overhead of guest setup + state-export verification dominates per-tx
cost at this fixture size. ContractCreate is essentially the same as
a transfer here because the deployed bytecode is empty in the fixture.

Native CPU SP1 prover wall is ~22 s per fixture (almost all
`client.setup` cost). This is wall-clock for an aarch64 laptop with
no CUDA — production proving runs on RTX 4090-class GPUs with
proof-time budgets in the tens of seconds.

## Mainnet readiness

The execute-mode numbers fit spec 11's per-tx budgets with two orders
of magnitude of headroom. The remaining open question is **proof-time
on production GPU hardware**, which the bench reports separately when
invoked with `BSVM_HOST_BENCH_PROVE=1`. That requires the operator to
run on a CUDA host; `pkg/prover/bench_test.go::TestSP1Bench` skips
cleanly if the binary isn't built and never asserts on wall budgets
(per spec 11's "informational only" guidance).

## What was broken (the silent-failure story)

The very first run of this bench found **identical cycle counts of
exactly `10_227` across all five fixtures with empty public values
(`pv_hash = SHA256("")`)**. The harness wired up cleanly end-to-end
(binary builds, JSON envelope round-trips, exit code 0), but the
guest was short-circuiting before reaching the EVM execution path.
Three layered bugs masked each other:

1. **Wire-format mismatch (`pkg/prover/wire_format.rs` did not
   exist).** The host (`prover/host-bridge/`, `prover/host-bench/`)
   serialized addresses as raw `[u8; 20]` and U256/B256 as raw
   `[u8; 32]` arrays — bincode emits no length prefix. The guest's
   `BatchInput` (and nested `AccountState` / `EvmTransaction` /
   `BlockContext` / `AccountProofWitness`) used `alloy_primitives`
   types whose default `Serialize` routes through `serialize_bytes`,
   which bincode encodes as a length-prefixed byte string (8-byte
   u64 length + bytes). The guest's `bincode::deserialize::<BatchInput>`
   read the host's first 8 raw bytes as a length, panicked or read
   garbage, and exited with empty public values. **Fixed:**
   `prover/guest/src/wire_format.rs` introduces serde-with helpers
   that force every alloy-typed wire field to the raw fixed-byte
   layout the host actually writes; six unit tests in that module
   verify byte-image compatibility.
2. **Missing `inbox_root_before` empty-queue marker.** Once the wire
   decoded, the guest hit `commit_error(0x10, …)` because the bench
   sent `inbox_root_before = [0; 32]` while the guest expects
   `hash256(zero32)` (= `0x2b32db6c…`) for an empty queue (per spec
   10 and `pkg/covenant.EmptyInboxState`). **Fixed:** the bench
   envelope now uses `covenant.EmptyInboxState().TxQueueHash` for
   both `before` and `after`.
3. **Chain-id mismatch.** The bench signed with
   `equivalenceChainID = 1337` (inherited from the dual-EVM
   equivalence test). The guest hardcodes `CHAIN_ID = 8453111`.
   `tx::decode_and_recover` rejected every signature because EIP-155
   binds chain id into the signature, and the guest committed
   `commit_error(0x20, …)`. **Fixed:** the bench uses a separate
   `benchChainID = 8453111` constant aligned to the guest. The
   equivalence test continues to use 1337 because it never touches
   the SP1 guest (it compares against host-side revm directly).

The combined fix surfaces the real cycle counts in the table above.

## Production-proving implications

The wire-format bug also affects `prover/host-bridge/` (the
production proving binary), which carries the identical parallel-type
pattern. **Until host-bridge ships the same wire-format fix, every
production proof attempt would fail the same way** — silent zero-pv
output, no real EVM execution attested. There is no test in the
repository that exercises the full host-bridge → SP1 guest →
public-values pipeline today; the dual-EVM equivalence test
(`TestDualEVMEquivalence_Fixtures`) bypasses SP1 by running revm
directly via `prover/host-revm/`.

The host-bridge fix is straightforward — copy the `wire_format`
helpers (or import from `bsvm_guest::wire_format`) and apply the same
`#[serde(with = …)]` annotations. The empty-inbox-marker and
chain-id fixes are bench-test-local; the production daemon
(`pkg/overlay/process.go`) already uses
`covenant.EmptyInboxState()` and threads chain id from
`vm.DefaultL2Config`, so those bugs only manifest in test fixtures.

## Follow-up

1. **Apply the wire_format helpers to `prover/host-bridge/`.** This
   is a real production-blocker — all current host-bridge → guest
   proofs would fail wire-decode and stall. The fix is purely
   serde-attribute additions; no behavior change required.
2. **Run with `BSVM_HOST_BENCH_PROVE=1`** on a CUDA host to capture a
   single proof-time data point per fixture. The bench logs proof
   time + proof size when prove mode is enabled, and the SP1
   community-shared budget targets are 60s wall on RTX 4090.
3. **Larger fixtures.** Add a 64-tx batch fixture to
   `equivalenceFixtures` so cycle counts scale into the realistic
   batch range. Today's per-tx cycle delta is dominated by setup
   overhead; the bench needs a multi-tx workload to show the
   per-opcode cost dominates.
4. **In-guest sanity check.** Add `commit_error(0x07, …)` (or
   similar) to the guest when `transactions.is_empty()` AND
   `inbox_drain_count == 0`, so a future wire-decode regression is
   caught loudly at the guest's first commit instead of producing
   pretty-looking zero-pv output that silently passes the bench.
