# Header Oracle Quorum (W6-2)

## Problem

A BSVM node anchors all of its SPV reasoning — bridge deposits, BUMP
verification, reorg handling, finality counters — on the chaintracks
view of the BSV best chain. With a single chaintracks upstream, every
one of those checks reduces to "trust this provider". A compromised
or merely stale provider can:

- Withhold blocks (delay tip); the node still believes the BSV chain
  has not advanced and refuses to advance the covenant.
- Inject a short-range fork that is internally PoW-valid (PoW costs
  scale linearly with depth, so brief private chains are cheap to
  forge against a single victim).
- Censor specific BSV blocks (e.g. one carrying a withdrawal proof).

W6-9's PoW + checkpoint validation already rejects junk, but it
cannot distinguish between two PoW-valid header chains that differ
above the deepest checkpoint. That is the niche W6-2 closes.

## Decision: hybrid M-of-N agreement (default M=2 of N=3)

Spec 17 §"Upstream providers and quorum" already pins the high-level
shape (`quorum = 2` default, multiple `[[chaintracks.upstream]]`
blocks). W6-2 implements that with the following hybrid:

1. **Per-tip M-of-N agreement** as the steady-state check. On each
   tip refresh the `MultiClient` polls every healthy provider, groups
   the results by `(height, hash)`, and accepts the group with at
   least M votes. This catches the 99% case (one provider drifts /
   lies) cheaply.
2. **Cumulative-work tiebreak** when no group reaches M. Among groups
   that satisfy `EnforceCheckpoints` and pass PoW (W6-9), pick the
   one with the highest `Work`. This keeps the node live when M-1
   providers are temporarily silent — a single honest provider can
   carry the network as long as the proposed tip extends a known
   checkpoint.
3. **Hard halt on cross-checkpoint disagreement**. If any two groups
   have ancestors that fork below the deepest pinned checkpoint, the
   client raises an unrecoverable error and refuses to serve reads.
   This is the spec-12 "BSV-degraded → covenant broadcasts pause"
   trigger.

Pure (a) strong consensus is too brittle (one slow provider stalls
the whole shard). Pure (c) highest-work is too liveness-biased — a
single compromised high-work feed wins. The hybrid gives M-of-N
safety in the common case, single-provider liveness when others are
silent (cheap to verify because PoW + checkpoints are still enforced),
and an absolute safety floor at the checkpoint depth.

## Disagreement handling

Three configurable actions via `disagreement_action`:

- `log` — record the divergence in the per-provider health stats and
  serve the highest-work group. Default for devnet.
- `drop` — log + temporarily suspend the deviant provider for
  `disagreement_cooldown` (default 10 min). Default for mainnet.
- `halt` — refuse to serve any reads until operator intervention.
  Use when running with M=N (strong consensus opt-in).

Cross-checkpoint disagreement always halts regardless of setting.

## Liveness

If fewer than M healthy providers respond inside the per-call
`response_timeout` (default 5 s), the call returns an error
identifiable as `ErrQuorumUnavailable`. Callers (overlay,
reorg_subscriber) must surface this as BSV-degraded, not as a
header-not-found. The hybrid's tiebreak rule does NOT lower M below
the configured value silently; the operator must opt-in by setting
`quorum_m = 1`, which collapses to the highest-work behaviour.

## Reorg consistency

Quorum is checked **per tip**, not per historical header. Historical
`HeaderByHash` / `HeaderByHeight` are still fanned out and quorum-
checked, but with a 30 s per-call cache: providers that already
agreed once on a buried header are not re-asked on every read.

Stream events from `SubscribeReorgs` are buffered per child for a
bounded window (`stream_skew_window`, default 750 ms) before being
re-emitted upward, to swallow the inevitable network-RTT skew between
providers. Only the post-window quorum decision propagates to the
overlay. Buffer sizes are bounded (`stream_buffer_max`, default 32
events per child) to prevent a chatty provider from OOMing the node.

## Trust bootstrap

Providers are added/removed via the static config file
(`bsvm.example.toml`'s new `[[chaintracks.providers]]` blocks). A
signed-list endpoint is explicitly out of scope for W6-2 — operators
manage their own trust set, identical to how `bootstrap_peers` works
for libp2p. Each provider entry carries an optional `weight` (default
1) for future weighted-quorum, currently unused.

## Compatibility

`MultiClient` implements `ChaintracksClient` and wraps N child
`ChaintracksClient` instances. Existing single-provider configs keep
working unchanged: when only one provider is configured the higher
layers can either keep using `RemoteClient` directly or wrap it in a
`MultiClient` with `quorum_m = 1`. The default `bsvm.example.toml`
ships a single provider so quorum stays opt-in until operators
explicitly enable it.
