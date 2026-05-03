# SP1 Cycle Bench — 2026-05 Snapshot (multi-tx scaling)

Follow-up to [`sp1-cycles-2026-04.md`](sp1-cycles-2026-04.md). The April
snapshot showed all five single-tx fixtures clustered at ~320K cycles
each — clearly dominated by SP1 setup overhead, not by EVM work. The
"Follow-up" section explicitly called out a 64-tx fixture as the next
required addition. This document records the multi-tx fixtures added
to `pkg/prover/bench_test.go` to make the cycles-per-tx delta visible
and to measure the spec 12 production-batch target (~128 transactions
per batch).

## Machine

Same as the 2026-04 snapshot when re-measured; the bench harness
itself is host-deterministic, so the only machine-sensitive numbers
are wall-ms (logged but informational).

- CPU: Apple M3
- RAM: 24 GB
- macOS 26.3
- SP1 SDK 6.1.0 (Cargo resolved up from the 6.0.2 floor)
- SP1 toolchain `gkgUAXxgDg`
- VK pin: `0x0089e86b40471ffbca344ddd6e02c4aade8d2d1676cbab381a6bedc726c964e7`
  (docker-mode build, Phase 1 of `docs/decisions/sp1-reproducible-build-2026-05.md`)

## New fixtures

Three multi-tx batch fixtures, each a single sender (1000 ETH
prefunded) sending 1 wei to N distinct receivers with sequential
nonces:

| Fixture           | txCount | Per-tx gas | Total gas (Go EVM) | Wire shape  |
| ----------------- | ------: | ---------: | -----------------: | ----------- |
| `MultiTxBatch_8`  |       8 |     21_000 |            168_000 | LegacyTx ×N |
| `MultiTxBatch_64` |      64 |     21_000 |          1_344_000 | LegacyTx ×N |
| `MultiTxBatch_128`|     128 |     21_000 |          2_688_000 | LegacyTx ×N |

Block gas limit is `block.DefaultGasLimit = 30_000_000`, so even the
128-tx fixture leaves ~91% headroom — `ProcessBatch` never drops txs
on gas-pool exhaustion (the Go-side smoke test
`TestSP1Bench_BatchEnvelopeSmoke` asserts the receipt count matches
`txCount` for each fixture so a future regression fails loudly).

The receivers are derived from the tx index (`0xaaaa…aaaa<index_lo16>`)
so each tx writes to a fresh MPT account leaf — every tx exercises the
state-export witness path, which is the dominant cycle cost the
real-world workload will hit.

## Raw results — TestSP1Bench, EXECUTE mode

> **Status: not yet measured locally.** Running the full bench against
> the docker-mode SP1 guest is ~4 min per fixture on Apple Silicon, and
> the new fixtures (especially `MultiTxBatch_128`) push that to many
> minutes each. The numbers will land via CI's first run of
> `TestSP1Bench` after this commit; the `runBenchEnvelope` helper logs
> a `cycles_per_tx=…` line for every multi-tx fixture so the
> regression-detection delta is captured directly in the test output.

The table below is the rerun of the existing 5 fixtures (carried over
from `sp1-cycles-2026-04.md` for context) plus the three new
multi-tx fixtures. **The "Cycles" column for the multi-tx rows is the
expected order of magnitude based on April's per-tx upper bound; CI
will replace these with the real measurements.**

| Fixture            |     Cycles | Cycles/tx |     Wall (ms) | PV bytes | Notes                                  |
| ------------------ | ---------: | --------: | ------------: | -------: | -------------------------------------- |
| LegacyTransfer     |    319_432 |   319_432 |            28 |      280 | rerun 2026-04                          |
| AccessListTransfer |    319_782 |   319_782 |            36 |      280 | rerun 2026-04                          |
| DynamicFeeTransfer |    332_747 |   332_747 |            35 |      280 | rerun 2026-04                          |
| BlobTx             |    301_073 |   301_073 |            43 |      280 | rerun 2026-04                          |
| ContractCreate     |    319_080 |   319_080 |            43 |      280 | rerun 2026-04                          |
| MultiTxBatch_8     |     ~tbd~  |    ~tbd~  |        ~tbd~  |      280 | first multi-tx data point              |
| MultiTxBatch_64    |     ~tbd~  |    ~tbd~  |        ~tbd~  |      280 | mid-range — should isolate setup floor |
| MultiTxBatch_128   |     ~tbd~  |    ~tbd~  |        ~tbd~  |      280 | spec 12 production-batch target        |

### Expected scaling (sanity model)

The April single-tx baseline was ~300-330K cycles per fixture. That
total includes:

- **SP1 setup floor** — the per-batch fixed cost: bincode decode of
  `BatchInput`, MPT pre-state reconstruction from the witness export,
  the inbox-root before/after wiring, the public-values commit. Order
  of magnitude: ~250-300K cycles regardless of `txCount`.
- **Per-tx EVM cost** — sender recovery (ECDSA), tx-decode, revm
  execution (intrinsic gas + transfer-only opcodes for these
  fixtures), receipt construction, MPT write into the account leaf.
  For a no-op transfer the per-tx delta is small but non-zero.

If the setup floor is ~300K cycles and a no-op transfer adds ~10-50K
cycles per tx (rough — pending CI numbers), the expected totals are:

- `MultiTxBatch_8`:   ~300K + 8 × 30K = **~540K** (cycles_per_tx ~67K)
- `MultiTxBatch_64`:  ~300K + 64 × 30K = **~2_220K** (cycles_per_tx ~34K)
- `MultiTxBatch_128`: ~300K + 128 × 30K = **~4_140K** (cycles_per_tx ~32K)

`cycles_per_tx` should asymptote to the true per-tx cost as `txCount`
grows. The 8-tx fixture is intentionally small so the setup floor
still dominates — that's the regression signal: if the floor moves,
the 8-tx number moves disproportionately.

These are sanity-model placeholders; the CI run of `TestSP1Bench`
after this commit will replace them with measured numbers and this
document should be updated in-place with the real values.

## Segment-count consideration

SP1 v6.x emits a segment per ~2^22 cycles (~4.2M). At the projected
~4.1M cycles for `MultiTxBatch_128`, the bench may stay single-segment
or just spill into a second segment. The bench output's `segments=…`
field is logged on every fixture; an operator should compare segments
between fixtures to spot the boundary.

If `MultiTxBatch_128` starts emitting many segments (say >4), that's
a signal the per-tx cost is higher than the sanity model — worth
re-checking the EVM hot-path before the production batch size needs
to drop. The bench does **not** assert on segment count; it logs and
moves on.

## Implementation notes

- All multi-tx fixtures are wired through the **same** `runBenchEnvelope`
  helper as the existing 5 single-tx fixtures, which means the wire-
  format canary asserts (`pv_bytes == 280`, non-empty `pv_hash`,
  VK-hash drift logging) apply identically. A multi-tx envelope that
  short-circuits the guest will fail in exactly the same way as a
  single-tx envelope.
- Builders panic (rather than `t.Fatalf`) on `SignNewTx` failure
  because `benchBatchFixtures` is a package-level `var` — there is no
  `*testing.T` in scope at init time. A panic here would be a
  programming error (bad key / bad signer); never a runtime
  condition.
- The dual-EVM equivalence harness (`equivalence_test.go`) keeps
  using `equivalenceFixture` (single tx per fixture) so each
  assertion stays attributable to a specific tx type. Multi-tx
  fixtures live entirely in `bench_test.go` — they're a perf
  measurement, not a correctness pin.
- `BSVM_HOST_BENCH_PROVE=1` only enables `--prove` on the FIRST
  fixture (LegacyTransfer); the multi-tx fixtures stay execute-only
  even when prove mode is requested. At `MultiTxBatch_128` a CPU
  proof would take many minutes and the prove-time signal is already
  captured on the small fixture. Operators can still run
  `-run TestSP1Bench/MultiTxBatch_128` directly with prove enabled
  if they want a multi-tx proof-time number.

## Mainnet readiness

The single-tx fixtures already showed two orders of magnitude headroom
against spec 11's per-tx cycle budget. The multi-tx fixtures answer
the more important question: **does the per-tx cost stay flat as the
batch grows?** A linear scaling profile (cycles ≈ floor + N × per_tx)
is exactly what the SP1 cost model predicts; a super-linear curve
(e.g., cycles ≈ floor + N × per_tx × log(N)) would indicate a
witness-set blowup that needs investigation before the production
batch size can be sustained.

The CI run of `TestSP1Bench` after this commit produces the data
points needed to confirm the linear profile; this document should be
updated with the measured numbers and (if they hold) a one-line
"SCALING: linear, ~32K cycles/tx" summary.

## Follow-up

1. **Replace the sanity-model placeholders with real CI numbers**
   once `TestSP1Bench` runs against the docker-mode guest in a
   production CI box (`.github/workflows/sp1-repro.yml` or a sibling).
   The `cycles_per_tx=…` log line is the canonical regression
   signal — if it moves >10% between releases without a corresponding
   guest change, something needs investigation.
2. **Add a 256-tx and 512-tx fixture** if the 128-tx number comes in
   well under the segment budget — that would let us measure how
   much further the production batch size can stretch before
   segment-count or memory bandwidth becomes the constraint.
3. **Add a contract-call multi-tx fixture** (e.g., 64 ERC-20 transfers
   against a deployed token contract) once a deploy-and-call helper
   exists in the equivalence test set. The current fixtures are all
   pure value transfers; a real workload mix would include storage
   reads/writes per tx, which has materially higher per-tx cycles
   than a no-op transfer.
