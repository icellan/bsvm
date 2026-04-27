# S — Withdrawal Flow and L2 Rollback Hook

Status: design + scope cap, this wave. Author: agent-a3cf98a5.
Specs: 07 (bridge), 11 (overlay), 12 (verification), 13 (Rúnar).

## Audit findings

### What already exists for withdrawals

The withdrawal flow is **substantially complete** in the codebase. Spec 07
end-to-end coverage:

- L2 burn + storage update (Phase 1):
  `pkg/block/system_tx.go::ApplyWithdrawTx` — decodes
  `withdraw(uint256,bytes20)` calldata, enforces rate limit via
  `bridge.CheckWithdrawalRateLimit`, sub-balance the caller, credits the
  burn address, and calls `bridge.RecordWithdrawal` to update slots
  2/5/6 + `withdrawalHashes[nonce]`.
- Withdrawal hash + Merkle tree:
  `pkg/bridge/withdrawal.go::WithdrawalHash` (hash256 of
  bsvAddr||sat_be||nonce_be) + `BuildWithdrawalMerkleTree` /
  `WithdrawalProof` / `VerifyWithdrawalProof`.
- L2 event extraction (Phase 2):
  `pkg/overlay/process.go::extractWithdrawals` reads
  `WithdrawalInitiated` logs from the batch's receipts, threads them
  through to `prover.Withdrawal`, and the SP1 host
  (`pkg/prover/withdrawal_root.go`) folds them into the public-values
  `withdrawalRoot` at offset 144. A consistency test
  (`pkg/prover/withdrawal_root_test.go`) pins prover↔bridge tree parity.
- BSV claim path (Phase 3):
  `pkg/bridge/withdrawer.go::Withdrawer.ProcessFinalizedWithdrawals`
  scans pending withdrawals, builds the SHA256 Merkle inclusion proof
  via `buildMerkleProof`, locates the covenant-advance tx via
  `CovenantAdvanceFinder`, extracts `refOutputScript` / `refOpReturn` /
  `withdrawalRoot` (offset 5 in the OP_RETURN payload), constructs the
  unsigned skeleton via `BuildWithdrawalClaimTx`, signs input 0 via the
  `BSVSigner` seam, and broadcasts with the standard 1s/3s/9s retry
  curve. Loop wrapper `ProcessFinalizedWithdrawalsLoop` is wired.
- Bridge UTXO tracking: `pkg/bridge/withdrawer.go::BridgeUTXO` +
  `UpdateAfterWithdrawal`.
- Predeploy genesis state: `pkg/bridge/predeploy.go::DeployBridgePredeploy`.
- Bridge covenant withdraw method (Rúnar):
  `pkg/covenant/contracts/` (compiled `bridge_*.runar.go` artifacts).

### Concrete gap list — withdrawals

1. The CSV-locked P2PKH output script in
   `pkg/bridge/withdrawer.go::buildCSVLockedP2PKH` matches spec 07 §
   "Bridge Confirmation Enforcement via CSV". It is **not yet
   exercised end-to-end** against a live bridge covenant on regtest
   (only unit tested). This is a follow-up validation item, not a code
   gap.
2. `WithdrawalScanner` is an interface — there is **no production
   implementation** that scans `ChainDB` for `WithdrawalInitiated`
   events filtered by `FinalizedTip`. Tests use a mock. This is a real
   gap but mostly plumbing.
3. There is **no automatic wiring** of the `Withdrawer` from the
   overlay node — the daemon (`cmd/bsvm/`) does not currently
   instantiate a `Withdrawer`, attach the BSV fee-wallet `Signer`, or
   start the loop. The pieces all exist; only the wiring is missing.

### What already exists for L2 rollback

- `pkg/overlay/rollback.go::OverlayNode.Rollback(toBlock)` — reverts
  `executionTip`, reloads state from `targetHeader.StateRoot`, marks
  receipts rolled-back, clears canonical hashes, truncates the TxCache.
- `pkg/overlay/cascade_rollback.go` — cascades rollback through
  speculative blocks when a covenant race is lost. Driven by the race
  detector + confirmation watcher.
- `pkg/overlay/circuit_breaker.go` — pauses the batcher (via
  `BatcherPause` -> `ErrBatcherPaused` with reason "shard frozen") on 3
  consecutive Go-vs-SP1 disagreements. Has `Reset()` for operator
  recovery.
- `pkg/bridge/monitor.go::RetractDepositsAbove(minHeight)` — drops
  pending + persisted deposits with `BSVBlockHeight > minHeight` from
  the BridgeMonitor's bookkeeping.
- `cmd/bsvm/bridge_bsv_client.go::handleReorgEvent` — calls
  `monitor.RetractDepositsAbove(commonAncestor.Height)` when
  chaintracks reports a reorg.

### Concrete gap list — rollback

1. `RetractDepositsAbove` un-credits the **monitor's** view of pending
   deposits, but does NOT un-credit the **L2 wBSV mint** that
   `ApplyDepositTx` already wrote in `state.StateDB` for blocks above
   the reorg point. The retract docstring even says: "the L2-side
   rollback (overlay re-execute / Block.SafeHead retreat) is the
   responsibility of the reorg subscriber that calls this — this
   method only reverses the monitor's own bookkeeping." That subscriber
   does not exist. **This is the primary gap this wave fixes.**
2. There is no callback from `BridgeMonitor` (or its caller in
   `cmd/bsvm/bridge_bsv_client.go`) to inform the `OverlayNode` that a
   retraction happened and L2 must respond.
3. There is no helper on `OverlayNode` that combines "pause batcher +
   rollback to last safe checkpoint" into one safe operation.

## Withdrawal flow — design (current state mapped to spec)

The end-to-end flow is exactly what specs 07 + 13 prescribe:

1. **L2 user calls** `L2Bridge.withdraw(satoshiAmount, bsvAddr20)` on
   the predeploy at `0x4200…0010`. Calldata uses the
   `withdraw(uint256,bytes20)` selector. Existing implementation:
   `pkg/block/system_tx.go::ApplyWithdrawTx`. Burns wBSV to
   `0x…dEaD`, increments slot 2, writes
   `withdrawalHashes[nonce]` = hash256(bsvAddr||sat_be||nonce_be).

2. **Overlay aggregates per batch.**
   `pkg/overlay/process.go::extractWithdrawals` reads `WithdrawalInitiated`
   logs and threads `[]prover.Withdrawal` into the prover.

3. **Covenant advance public values commit to the root.**
   `pkg/prover/withdrawal_root.go::ComputeWithdrawalRoot` returns the
   bytes32 that the SP1 guest places at PV offset 144. The OP_RETURN
   batch payload "BSVM\\x02 || withdrawalRoot(32) || batchData" makes the
   root public on-chain.

4. **Claim on BSV.** `pkg/bridge/withdrawer.go::ProcessFinalizedWithdrawals`
   builds the SHA256 Merkle proof, references the advance tx outputs,
   signs input 0 via `BSVSigner`, and broadcasts. The bridge covenant
   verifies inclusion + cross-covenant reference and emits the CSV-locked
   payment.

5. **Spend after CSV.** Standard P2PKH after the 6/20/100-block delay.

**What's missing for a fully wired withdrawal v1:** a `WithdrawalScanner`
that reads `ChainDB` for finalized `WithdrawalInitiated` events with
`BatchHashes` populated; daemon-side wiring of `NewWithdrawer` /
`WithSigner` / `ProcessFinalizedWithdrawalsLoop`; a regtest-level
end-to-end claim test against the compiled bridge covenant.

## L2 rollback hook — design

### Options considered

(a) **One-way trapdoor.** Never rollback wBSV mints. Documents that
   deposits with < `confirmations` are unsafe under reorg. *Rejected* —
   the deposit horizon already enforces 6 confirmations before credit;
   any reorg deeper than 6 blocks is a Bitcoin-level catastrophe and
   the spec already cites this assumption ("This is the same security
   assumption as Bitcoin itself", spec 07 § Bridge Behavior During
   Rollbacks). However: the existing
   `BridgeMonitor.RetractDepositsAbove` is wired to *any* reorg via
   `chaintracks.SubscribeReorgs`, including 1-block reorgs at the tip
   that happen routinely. Doing nothing on the L2 side after retract
   would leave wBSV minted against a deposit the monitor no longer
   trusts.

(b) **Negative deposit / penalty system tx.** Issue a system tx that
   subtracts wBSV from the recipient on the next batch. Rejected —
   recipient may have already moved or burned the funds; the negative
   tx may underflow; introduces a system-tx type that can fail (in
   conflict with the deposit-tx invariant that system txs cannot fail).
   Also requires committing this tx into a STARK proof, which forces
   the prover to model "subtract balance, even into negative" semantics
   that are not in spec 07.

(c) **Halt + replay-from-checkpoint** (recommended). When the
   BridgeMonitor retracts deposits above `minHeight`, an
   `OverlayNode.HaltAndRollbackForReorg(bsvHeight)` callback:
   1. Pauses the batcher with reason "bsv reorg, awaiting replay" —
      reuses the existing `BatcherPause(reason)` machinery and the
      "shard frozen" sentinel so RPC clients see a uniform error.
   2. Determines the lowest L2 block whose deposit horizon
      ≤ `minHeight` (i.e. the last L2 block that is safe to keep).
      Calls `OverlayNode.Rollback(toBlock=safeL2Block)`.
   3. Emits a structured slog event so operators can observe the halt
      and the prover/explorer see the wallet-side flag (spec 15 admin
      panel surfaces it via `BatcherIsPaused()` already).
   4. Stays paused until the operator runs `bsvm admin reset-…` (same
      pattern as the circuit breaker). This is conservative on
      purpose: the reorg may reshape the deposit-horizon protocol's
      assumptions, and a human eyeball before resuming is the cheap
      safety net.

   Trade-off: halts liveness on every chaintracks reorg, even
   1-block. In practice 1-block reorgs are rare and short; a paused
   batcher reactivates in seconds once the operator confirms the new
   chain. The alternative (autonomous resume on N-block silence) is
   doable as a follow-up but adds policy complexity we don't want now.

**Decision: option (c).** It is the only option that preserves the
"deposits cannot fail, wBSV is always 1:1 backed by locked BSV"
invariant, without requiring negative-balance plumbing in the EVM.

### Wiring

```
chaintracks.ReorgEvent
   │
   ▼
cmd/bsvm/bridge_bsv_client.go::handleReorgEvent
   │  (calls monitor.RetractDepositsAbove(commonAncestorHeight))
   ▼
BridgeMonitor (memory + DB drop)
   │  (NEW: invokes optional rollback callback if registered)
   ▼
OverlayNode.HaltAndRollbackForReorg(bsvHeight)   ← NEW
   ├─ BatcherPause("bsv reorg, awaiting replay")
   ├─ resolve lowestL2 with depositHorizon ≤ bsvHeight
   ├─ Rollback(lowestL2)
   └─ slog.Warn(...) for ops
```

The callback is an interface registered via
`BridgeMonitor.SetReorgRollbackCallback(fn func(bsvHeight uint64))` so
`pkg/bridge` does not import `pkg/overlay`.

The "lowest safe L2 block" lookup is conservative: if the overlay does
not yet track per-block deposit horizons in a queryable index, the
callback can use `executionTip - 1` (rollback by one) as a safe
fallback, OR rollback to the last finalized tip (already tracked by
`finalizedTip`). The default we ship is **rollback to
`finalizedTip`** — it is a known-safe checkpoint that, by definition,
has 6+ BSV confirmations and is therefore beyond the reorg depth that
chaintracks could possibly report. This avoids needing a new index.

## Scope cap and selection

Estimated hours, with experience from the existing bridge code:

- Withdrawal `WithdrawalScanner` production impl + tests: ~6h.
- Daemon-side `Withdrawer` wiring + signer plumbing: ~3h.
- Regtest e2e claim test against compiled bridge covenant: ~1d
  (requires compiling/aligning bridge covenant + funding flow).
- L2 rollback hook (callback + halt + rollback to finalizedTip +
  tests): ~3h.

Total withdrawal: ~2 days. Total rollback: ~3h.

**Decision:** ship the L2 rollback hook this wave (option c). Defer
the withdrawal end-to-end wiring to a follow-up; the on-chain pieces
already work in unit tests, and the missing scanner + daemon wiring is
straightforward but does not fit the time budget alongside e2e
validation. Mark the gaps with `TODO(S-followup):` markers in the
relevant files so the follow-up is easy to pick up.

## Acceptance for this wave

- BridgeMonitor exposes a `SetReorgRollbackCallback`.
- OverlayNode exposes `HaltAndRollbackForReorg(bsvHeight)` that:
  pauses the batcher with a structured reason; rolls back to
  `finalizedTip`; logs the event.
- Daemon wiring connects the two via the existing
  `cmd/bsvm/bridge_blockscan_wiring.go` start path (or a sibling).
- Unit tests cover: callback fires only on retract, halt + rollback
  drive the right state, reset path resumes the batcher.
- Existing tests (including
  `pkg/bridge/retract_test.go`,
  `pkg/overlay/race_and_rollback_test.go`,
  `pkg/overlay/cascade_rollback_test.go`) stay green.
