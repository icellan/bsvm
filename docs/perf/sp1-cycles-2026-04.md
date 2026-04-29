# SP1 Cycle Bench — 2026-04 Snapshot

First end-to-end run of the `prover/host-bench/` harness wired in round-9
XX. Captures cycle counts in EXECUTE mode (no proof) across the same
fixture set the dual-EVM equivalence harness uses.

## Harness state

- `prover/host-bench/target/release/bsvm-host-bench` builds clean (after
  fix to import the `ProvingKey` trait — `sp1-sdk` 6.1.0 moved the
  `verifying_key` method behind a trait import).
- `bsvm-guest` ELF rebuilds clean inside the build script
  (`riscv64im-succinct-zkvm-elf` target, ~1m16s after deps cached).
- `pkg/prover.TestSP1Bench` end-to-end run completes 5/5 fixtures in
  92 s wall on the native CPU prover.

## Machine

- CPU: Apple M3
- RAM: 24 GB (25,769,803,776 bytes)
- macOS 26.3
- SP1 SDK 6.1.0 (Cargo resolved up from the 6.0.2 floor)
- SP1 toolchain `gkgUAXxgDg` (rustc 1.93.0-dev, succinct fork)

## Raw results — TestSP1Bench, EXECUTE mode

| Fixture            | Cycles  | Instructions | Segments | Wall (ms) | PV bytes | PV hash                                                              |
| ------------------ | ------: | -----------: | -------: | --------: | -------: | -------------------------------------------------------------------- |
| LegacyTransfer     |  10,227 |       10,227 |        0 |        12 |        0 | `0xe3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| AccessListTransfer |  10,227 |       10,227 |        0 |        13 |        0 | `0xe3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| DynamicFeeTransfer |  10,227 |       10,227 |        0 |        12 |        0 | `0xe3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| BlobTx             |  10,227 |       10,227 |        0 |        13 |        0 | `0xe3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| ContractCreate     |  10,227 |       10,227 |        0 |        13 |        0 | `0xe3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |

Per-fixture wall time on the native CPU SP1 prover: ~18 s setup + ~12 ms
execute. Setup is one-shot per `client.setup(GUEST_ELF)` call.

## Interpretation

The cycle counts are **identical across all five fixtures** and the
public-values blob is **empty** (`pv_hash = SHA256("")`). A real EVM
batch should commit a 280-byte public-values block (spec 12, see
`prover/guest/src/main.rs:630-640`), and cycle counts should differ
materially between a 21k-gas transfer and a contract-creation fixture.

That means the harness wires up cleanly end-to-end (binary builds,
guest ELF builds, SP1 simulator runs, JSON envelope round-trips, exit
code 0), but the **guest is short-circuiting before reaching the EVM
execution path** — almost certainly a serde/bincode wire-format
mismatch between the host-bench's `GuestBatchInput` definition and the
guest's `BatchInput`.

Specifically: the host-bench uses raw byte arrays for `address: [u8;
20]`, `balance: [u8; 32]`, `code_hash: [u8; 32]`, while the guest's
types use the alloy primitive types (`Address`, `U256`, `B256`). These
share the same logical layout but their `Serialize` impls may differ
in the bincode wire format SP1's `io::read()` consumes (notably,
`U256` has been observed to serialize as four `u64` limbs in some
configs).

`prover/host-bridge/` (the production proving binary) carries the same
parallel-type pattern with a `// Field order MUST match
prover/guest/src/main.rs::BatchInput exactly` comment, but no test in
the suite actually exercises the host-bridge → guest wire path
end-to-end with a non-trivial state — `TestDualEVMEquivalence_Fixtures`
runs `revm` directly via `prover/host-revm/`, bypassing the SP1
simulator. So the same wire-format issue probably affects production
proving today and has been silent.

## Production-blocker assessment

The number `10_227` is below every cycle budget logged by the bench
(`5M` for transfers, `50M` for contract creation), so the test passes —
but it passes for the wrong reason. Trusting the current bench output as
mainnet go/no-go signal would be wrong.

**This needs fixing before mainnet:** verify the host-bench/host-bridge
parallel `Guest*` types produce a bincode wire image bit-identical to
the guest's `BatchInput`/`AccountState`/`EvmTransaction`/`InboxTx`
types. The cleanest fix is to expose the guest's types from
`bsvm-guest`'s lib facet and have the hosts use them directly instead
of duplicating definitions; the duplication that exists today is the
root cause of the silent wire-format drift.

## Follow-up

1. Confirm the wire mismatch hypothesis: add a unit test in
   `prover/host-bridge/src/main.rs` that round-trips a `GuestBatchInput`
   bincode-encoded by the host through the guest's `BatchInput` decoder
   in-process. If decode fails or fields drift, the assertion catches
   it without touching SP1.
2. Once the wire is bit-identical, re-run `TestSP1Bench` and update
   this doc with the real numbers. Also spot-check
   `BSVM_HOST_BENCH_PROVE=1 go test ./pkg/prover/ -run
   TestSP1Bench/LegacyTransfer` to capture a single proof-time data
   point.
3. Wire `prover/host-bridge/`'s parallel types to the same root-cause
   fix so production proving stops passing the same broken envelope.
4. Add an in-guest sanity check that fails LOUDLY when
   `accounts.is_empty() && transactions.is_empty()` since that's the
   silent-failure mode the wire bug surfaces as.
