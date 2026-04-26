# W4-3: Forced-Inclusion Inbox Drain — Decisions

Author: agent-a4b6da833d17712d7 (W4-3)
Branch: `w4-3-inbox-drain`
Specs: 10 (forced inclusion), 11 (overlay), 12 (state-transition proofs).

## Summary

Implements the SP1 guest's drain of the on-chain inbox covenant queue,
closing the censorship-resistance gap where a malicious overlay node
could either withhold a queued tx (censorship) or fabricate inbox txs
(out of thin air). The guest now:

1. Receives the **full ordered queue** from the host plus a `drain_count`.
2. Recomputes the inbox hash chain and asserts equality with the
   committed `inboxRootBefore` — this catches a host that omits or
   reorders queued entries.
3. Applies the leading `drain_count` entries through revm at the **head**
   of the batch.
4. Commits `inboxRootAfter` derived from the carry-forward remainder
   (`hash256(zero32)` for full drain).

Also fixes a pre-existing bug where `pkg/overlay/process.go` captured
`inboxRootBefore` AFTER `DrainPending()` reset the monitor — emitting
the empty-genesis hash for both before/after on every forced-drain
batch, which would have prevented the covenant from ever resetting
`advancesSinceInbox`.

## Spec ambiguities and chosen defaults

### D1. Empty-queue marker

**Question:** Spec 12 §"Public Values Layout" says `inboxRootAfter =
bytes32(0)` for a full drain. But `pkg/covenant/inbox_state.go::EmptyInboxState`
and `pkg/overlay/inbox_monitor.go::NewInboxMonitor` use
`hash256(zero32)` as the genesis empty-chain marker.

**Decision:** Use **`hash256(zero32)`** for the full-drain `inboxRootAfter`.

Rationale:
- The actual covenant code in `pkg/covenant/contracts/rollup_*.runar.go`
  does NOT compare `inboxRootAfter` against literal `bytes32(0)`. It
  uses `before != after` as the drain detector (see
  `rollup_inbox_test.go::TestFRIRollup_InboxDrainResetsCounter`,
  which uses arbitrary `rawSha256("post-drain")` values and still
  passes the drain-detection branch).
- Using the genesis marker keeps the wire-level invariant that
  `inboxRootAfter` is **always a valid chain root**. A literal zero
  would be a special-case sentinel that no other code path produces.
- Round-trips through `EmptyInboxState()` / `EmptyInboxRoot()`
  trivially.

Spec 12 should be updated to clarify the marker is `hash256(zero32)`,
not `bytes32(0)` — but that's a doc-only change.

### D2. Ordering within a batch

**Decision:** Drained inbox txs go at the **HEAD** of the batch,
before user-submitted txs.

This matches spec 11 §"Inbox Scanning":
> The overlay node includes inbox transactions at the START of each
> batch (before user-submitted transactions via RPC/gossip), ensuring
> they execute first.

Both the Go overlay (`process.go::ProcessBatch` already does this) and
the Rust guest (new `all_txs = drained_inbox.chain(user_txs)`) follow
this rule.

### D3. Partial drain

**Decision:** **Allowed** when not under forced inclusion.

The covenant treats `before != after` as "drain happened" and resets
the `advancesSinceInbox` counter — it doesn't require `after == 0`
(empty marker) for that reset. So a producer is free to drain the
top N entries when N is bounded by the batch's gas budget; the
remainder carries forward and the counter still resets.

When forced inclusion is in play (`advancesSinceInbox >= 10`), the
host signals `inbox_must_drain_all = true` and the guest aborts the
proof if any tx is left in the queue. This matches the covenant's
behaviour of REJECTING any advance at the threshold without a drain
(spec 10).

### D4. Witness shape — full queue vs. proof-bearing subset

**Decision:** The guest receives the **full ordered queue**, not a
proof-bearing subset.

Rationale:
- The inbox is a **hash chain**, not a Merkle tree (`pkg/covenant/contracts/inbox.runar.go`).
  There is no efficient inclusion proof primitive; verifying any
  position requires walking the chain.
- The bounded queue size (forced-inclusion fires after 10 advances at
  most) plus per-tx submission cost on BSV makes the queue length
  practically small.
- The "send the whole queue" design is the same one geth uses for
  L1->L2 messages on Optimism / Arbitrum: the witness is the queue,
  not Merkle proofs.

### D5. Sender recovery for inbox txs

The guest treats inbox txs as standard EVM txs with a pre-decoded
`from` field. Sender recovery is the host's responsibility (sister
W4-2 task). The `InboxTx` struct carries both the raw RLP (for chain
hashing) and the pre-decoded `EvmTransaction` (for revm) so the guest
doesn't need an EIP-2718 decoder of its own — that decoder's
correctness is part of the `from` binding the host commits to via the
existing `raw_bytes` field.

### D6. Witness size cap (W4-3 mainnet hardening, follow-up)

**Decision:** Hard-cap inbox queue witnesses at
**`MAX_INBOX_DRAIN_PER_BATCH = 1024`** entries on both sides.

Rationale:
- Without an upper bound a malicious / misconfigured host could ship
  an unbounded `inbox_queue` and exhaust SP1 cycles — a DoS on batch
  advance. Even on a benign host, an unbounded queue is unsafe to
  size proofs / witness buffers against.
- 1024 matches typical Ethereum block transaction ceilings (~1500
  was the historical L1 max; rollup batches sit comfortably below
  1k). Cheap arithmetic check inside SP1 (single `usize` compare).
- Spec 10's forced-inclusion threshold fires after 10 advances, so
  natural queue depth is well below 1k under any sane operator
  config. The cap is a DoS guard, not a throughput throttle.

Where the cap is enforced:
- **Guest** (`prover/guest/src/inbox.rs`): `verify_and_split` rejects
  over-cap queues with `InboxError::QueueExceedsCap` (error code
  `0x13`) BEFORE any Merkle/PoW work. A malicious host pays no SP1
  cycles for an oversized witness.
- **Host** (`pkg/prover/inbox_witness.go::BuildInboxWitness`):
  returns a hard error when the queue exceeds
  `MaxInboxDrainPerBatch` (= 1024). The producer never even tries
  to prove an unprovable batch.
- **Overlay producer** (`pkg/overlay/process.go::processBatchInternal`):
  propagates the witness-build error so `ProcessBatch` fails fast
  rather than silently producing a batch the guest will reject.

This closes the "Witness size cap" follow-up listed below in the
"Open questions" section.

### D7. Cap violation → error vs. truncate

**Decision:** **ERROR**, do not silently truncate.

Truncation would hide the configuration bug from the operator and
risk leaving inbox txs un-drained past spec-10's forced-inclusion
threshold (10 advances). The covenant would then REJECT every
subsequent advance until the queue is drained, tipping the producer
into an unrecoverable state without a clear root cause. Failing
fast surfaces the bug in the operator's logs the moment it happens.

The expected operator response is to drain the on-chain inbox via
multiple smaller batches (the producer code in `process.go` already
paginates via `DrainPending`/`MustDrainInbox`; D6's cap is purely a
defensive ceiling).

## What changed

### Guest (`prover/guest/`)

- New module `inbox.rs`: `chain_root`, `empty_inbox_root`,
  `verify_and_split` with `InboxError` variants for the three reject
  cases.
- `main.rs::BatchInput` extended with `inbox_queue`, `inbox_drain_count`,
  `inbox_must_drain_all` (replaces the host-supplied `inbox_root_after`
  pass-through).
- `main.rs` step 4a: verify inbox witness, build the combined tx list
  (drained inbox first, then user txs), execute through revm.
- `main.rs` step 8 inbox commit uses the guest-computed
  `inbox_root_after` (from `verify_and_split`) instead of trusting the
  host.
- New error codes: `0x10` (BeforeRootMismatch), `0x11` (DrainCountExceedsQueue),
  `0x12` (PartialDrainWhileForced).

### Host bridge (`prover/host-bridge/`)

- `HostInput` accepts `inbox_queue`, `inbox_drain_count`,
  `inbox_must_drain_all` (the legacy `inbox_root_after` is still
  accepted on the wire but ignored).
- `GuestBatchInput` field order updated to match the new `BatchInput`.
- `convert_input` ships an `InboxQueuedTx` per queue entry; the
  pre-decoded `tx` field is currently a placeholder pending W4-2
  (sender recovery). Hosts that exercise the drain branch with a
  non-zero count today must wait for W4-2 to land for execution to
  succeed; the chain-root verification works regardless.

### Go host (`pkg/prover/`)

- New `inbox_witness.go` with `InboxQueuedTx`, `EmptyInboxRoot`,
  `InboxChainRoot`, `BuildInboxWitness`. Byte-parity with the Rust
  guest's `inbox` module.
- `host.go::ProveInput` extended with `InboxQueue`, `InboxDrainCount`,
  `InboxMustDrainAll`.
- `inbox_witness_test.go`: 9 unit tests covering empty queue, partial
  drain, full drain, no drain, drain overflow, stepwise parity with
  the on-chain hash chain, order sensitivity, and the W4-3 acceptance
  scenario (3 txs drain 2).

### Go overlay (`pkg/overlay/`)

- `inbox_monitor.go`: new `PendingTxsSnapshot()` accessor that returns
  the queue without resetting it.
- `process.go::ProcessBatch`:
  - Captures the pre-drain root + queue snapshot **before** calling
    `DrainPending()` (the bug fix).
  - Carries the snapshot into `processBatchInternal` via a new
    `producerInboxWitness` struct.
- `process.go::processBatchInternal`:
  - Uses the pre-drain root for `inboxRootBefore` when available.
  - Builds the inbox witness via `prover.BuildInboxWitness` and
    populates the new `ProveInput.InboxQueue`/`InboxDrainCount`/
    `InboxMustDrainAll` fields.
- `inbox_drain_witness_test.go`: 2 integration tests that exercise
  the producer-side forced-drain path end-to-end and confirm the
  bug-fix assertion (`inboxRootBefore == pre-drain chain root`,
  not the empty-genesis hash).

## Tests and pass/fail

All Go: `go test ./pkg/... ./internal/... -short -count=1` → all
packages PASS (33 packages, no regressions).

New tests (all PASS):
- `pkg/prover/inbox_witness_test.go`: 9 tests
- `pkg/overlay/inbox_drain_witness_test.go`: 2 tests

Rust guest builds clean for SP1 target via `cargo prove build`. Rust
host bridge builds clean via `cargo +succinct build`.

Standalone Rust unit tests for `inbox.rs` exist in the module's
`#[cfg(test)] mod tests` block (10 cases) but cannot be run from a
host stable rust toolchain due to SP1 dependency MSRV gates. The Go
parity tests (`TestInboxChainRoot_StepwiseParity`,
`TestInboxChainRoot_EmptyMatchesGenesis`) cover the same correctness
properties end-to-end against the live `InboxMonitor`, which is the
behavioural binding that matters for production.

## Open questions for follow-up

1. **W4-2 dependency**: `InboxTx::tx` pre-decoded fields are currently
   placeholder zeros in the host bridge. Once W4-2 (sender recovery)
   lands, the host bridge needs to populate this from a real EIP-2718
   decode of `raw_tx_rlp`. Until then, the drain branch executes inbox
   txs as no-ops (which the EVM rejects with status=0 receipts —
   verifiable but not useful).

2. **Spec doc clarification**: Spec 12 says `inboxRootAfter = bytes32(0)`
   for full drain; the implementation uses `hash256(zero32)`. Same
   semantics from the covenant's perspective (`before != after`) but
   the spec text should be updated.

3. **Witness size cap**: ~~No upper bound on `inbox_queue.len()` is
   enforced today~~. **CLOSED in W4-3 mainnet hardening.** See D6 / D7
   above: the cap is `MAX_INBOX_DRAIN_PER_BATCH = 1024`, enforced in
   the guest (`InboxError::QueueExceedsCap`, code `0x13`), the host
   (`BuildInboxWitness` hard error), and the overlay producer
   (`processBatchInternal` propagates the error). Spec 09 / spec 12
   carry `TODO(spec)` markers pointing at the canonical constant —
   pin the value in the spec text in the next spec sweep.
