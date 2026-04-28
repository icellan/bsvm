# II — Withdrawal Nonce Convention

Status: alignment fix, applied. Author: agent-ab818a0f.
Specs: 07 (bridge §"Sequential claiming", §"Bridge UTXO Model").

## Problem

`pkg/block/system_tx.go::ApplyWithdrawTx` emits the **first** withdrawal
log with `nonce = 0` (it reads slot 2 *before* `RecordWithdrawal`
increments it, and the predeploy initializes slot 2 to zero). The
matching Solidity contract in spec 07 mirrors the same `nonce =
withdrawalNonce++` pattern, also starting at 0.

`pkg/bridge/withdrawer.go::Withdrawer.ProcessFinalizedWithdrawals`
gates on `wd.Nonce == LastClaimedNonce + 1` with a default-init
`BridgeUTXO{LastClaimedNonce: 0}`. The gate therefore expects the first
acceptable nonce to be `1` — off-by-one against the producer.

Pre-fix tests papered over the gap by *also* setting `Nonce: 1` on the
first `PendingWithdrawal`, which contradicts what `ApplyWithdrawTx`
actually emits in production.

The regtest e2e claim test (agent FF) tripped over this and proposed
the sentinel `LastClaimedNonce: ^uint64(0)` as a workaround. We now
adopt the sentinel as the official convention so the producer and
consumer agree without divergence.

## Decision

**Option (a)**: producer is 0-indexed (unchanged), consumer
`LastClaimedNonce` is initialized to `^uint64(0)` (the canonical
"no-nonce-yet" sentinel). The gate `nonce == LastClaimedNonce + 1`
relies on uint64 wraparound — `^uint64(0) + 1 == 0` — so the first
withdrawal (nonce 0) passes naturally. The gate is unchanged
afterwards: `LastClaimedNonce` is set to the just-claimed nonce on
each successful claim, so the next gate reads `last+1` as expected.

### Why (a) over (b) — making the producer 1-indexed

(b) would require:

- changing `ApplyWithdrawTx` to read-then-increment with `+1`
  semantics (or initialize slot 2 to 1 in the predeploy);
- updating the L2Bridge Solidity contract in spec 07 (lines 502, 736),
  the SP1 guest (witness extraction), explorer/RPC indexing
  (`WithdrawalInitiated.nonce`), and any client SDK that decodes the
  emitted log;
- a state-format change to `withdrawalHashes[nonce]` keying.

Option (a) keeps the on-chain contract semantics — Solidity, Rúnar,
SP1, RPC — exactly as the spec describes ("Withdrawal nonce 0 must
be claimed first"), and only formalises a one-constant initial value
on the off-chain `BridgeUTXO` tracker. The Rúnar bridge `withdraw`
method's gate `nonce == lastClaimedNonce + 1` works identically with
the same wraparound semantics (uint64 in script arithmetic).

## Convention

```go
// Canonical "no-withdrawal-claimed-yet" sentinel for the off-chain
// BridgeUTXO tracker and the on-chain bridge covenant's lastClaimedNonce
// state. The producer (`ApplyWithdrawTx`) emits 0-indexed nonces, so
// the first acceptable claim has nonce 0; the gate
// `nonce == LastClaimedNonce + 1` matches via uint64 wraparound
// (^uint64(0) + 1 == 0).
const LastClaimedNonceUnset = ^uint64(0)
```

`NewBridgeUTXO()` (a small helper added in this fix) initializes
`LastClaimedNonce` to `LastClaimedNonceUnset`. Direct struct literals
must do the same — a unit test enforces the convention against any
default-init regression.

## Properties

- **First withdrawal passes**: `LastClaimedNonceUnset + 1` is `0`,
  matches the producer's first nonce.
- **Producer + consumer agree without per-test sentinel**: the
  sentinel is now baked into the constructor; tests no longer have
  to set `Nonce: 1` to align with the off-by-one default.
- **Replay rejected**: after claiming nonce 0, `LastClaimedNonce` is
  `0`, so the gate next demands nonce `1`. A replay of nonce 0 is
  filtered by the `wd.Nonce != LastClaimedNonce+1` check.

## Migration

The production overlay does **not** persist `BridgeUTXO` yet (no
production `Withdrawer` wiring exists — see
`cmd/bsvm/bridge_wiring.go::TODO(S-followup)`). When that wiring
lands and BridgeUTXO is persisted, fresh shards initialize to
`LastClaimedNonceUnset`. Any pre-existing persisted state from prior
test or devnet runs that wrote `LastClaimedNonce: 0` should be
re-genesis'd — there is no on-chain bridge UTXO yet, so this is a
test-only concern at the moment.

The on-chain Rúnar bridge contract's `lastClaimedNonce` state must
be initialized to `^uint64(0)` at deployment (or the equivalent in
the contract's chosen serialization). When the bridge covenant is
deployed for the first time, the genesis output's serialized state
field must reflect this. Since no bridge covenant has been deployed
to mainnet yet, this is captured here for the eventual mainnet
deployment runbook.

## Files changed

- `pkg/bridge/withdrawer.go` — added `LastClaimedNonceUnset`
  constant, `NewBridgeUTXO()` constructor, doc on the wraparound
  semantics in `ProcessFinalizedWithdrawals`.
- `pkg/bridge/withdrawer_test.go` — replaced the `LastClaimedNonce: 0`
  + `Nonce: 1` test pattern with `NewBridgeUTXO()` + `Nonce: 0`.
  Added `TestWithdrawer_FirstClaim_NonceZeroPasses` covering the
  producer-emits-0 / consumer-accepts-0 / replay-0-rejected /
  next-1-accepted property chain.
- `pkg/bridge/bridge_test.go` — same test pattern fix.
