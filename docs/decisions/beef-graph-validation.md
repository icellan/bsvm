# W6-4: Full BRC-62 BEEF Graph Reconstruction + Script Re-Execution

Author: agent-a9a9038a29340991d (W6-4)
Branch: `w6-4-beef-graph`
Specs: 07 (bridge deposits), 08 (genesis/node), 12 (state-transition proofs),
17 (Chaintracks/BEEF/ARC). Specs 10–13 win on conflict.

## Problem

`pkg/beef/parse.go` is structural-only: it walks the BRC-62 wire format,
recovers the target tx and ancestor tx blobs, and skips through BUMPs
without verifying anything. F's just-landed `cmd/bsvm/beef_wiring.go`
mounts the spec-17 endpoint surface but leaves bridge deposits **fail-
closed** until W6-4 produces a verifying reader; deposits are stored in
the BEEF store and never credited on L2. Inbox / governance / fee-wallet
funding / covenant-advance intents are similarly log-only.

This commit closes that gap. After W6-4 lands, a BEEF envelope arriving
on `/bsvm/bridge/deposit` is fully verified before the bridge monitor
sees it: ancestry checked against chaintracks, BUMPs anchored to known
headers, every input script re-executed, and the target tx confirmed at
≥ N BSV blocks.

## What "valid BEEF" means (per BRC-62 / spec 17 §"BEEF: The Wire Format")

A BEEF body decodes successfully and:

1. **Ancestry coverage.** Every input of the target tx references a
   parent tx that is either (a) included in the BEEF as a raw tx with
   its own BUMP merkle proof to a confirmed header, or (b) a transitive
   ancestor that is itself reachable via the same rule. A "bottom"
   ancestor is one whose own inputs are not required because the
   ancestor itself is BUMP-anchored — its in-block inclusion is the
   trust boundary.
2. **BUMP-to-header binding.** Every BUMP referenced by an ancestor (or
   by the target, for a confirmed envelope) verifies against a
   chaintracks-known confirmed BSV header at the BUMP's declared block
   height. The merkle root the BUMP computes from the leaf must match
   the header's `MerkleRoot`.
3. **Script execution.** Every input's unlocking script, when executed
   against the corresponding ancestor output's locking script, evaluates
   to TRUE under standard BSV consensus rules (post-Genesis,
   `ForkID` sighash, no `MAX_SCRIPT_SIZE` cap).
4. **Anchor depth.** For bridge-deposit BEEFs, the target tx must itself
   have a BUMP and the BUMP's block must be at depth ≥ `anchor_depth`
   blocks below chaintracks' tip (default 6, configurable). Other intent
   types do not require target depth at this layer — covenant-advance
   confirmation is gated by spec 11's finalization tier; fee-wallet
   funding only credits when the wallet itself is reconciled; inbox
   submission depth is gated by spec 11's `δ` aging.

## Script interpreter — decision

**Use `github.com/bsv-blockchain/go-sdk` v1.2.21**, already on
`go.mod` line 7. The package ships:

- `transaction` — full BRC-62 BEEF reader (`NewBeefFromBytes`,
  `Beef.Verify`), `MerklePath` (BRC-74 BUMP) with `Verify` against any
  `chaintracker.ChainTracker`, plus `Transaction.FromBEEF`.
- `transaction/chaintracker` — the `ChainTracker` interface
  (`IsValidRootForHeight`, `CurrentHeight`) we adapt our existing
  `pkg/chaintracks` to.
- `script/interpreter` — pure-Go BSV Script evaluator (`NewEngine`,
  `Execute(WithTx, WithForkID, WithAfterGenesis)`), the BSV reference
  interpreter port the SDK is built around.
- `spv` — convenience `Verify(ctx, tx, chainTracker, feeModel)` that
  walks ancestry, verifies merkle paths, AND re-executes scripts in a
  single call.

**License**: Open BSV License (`go-sdk` is the official BSV Blockchain
Association SDK; matches the project's existing dependency policy —
spec/00 lists go-sdk as the assumed BSV stack and we already depend on
it for BSV tx parsing in `cmd/bsvm/beef_wiring.go`).

**Maturity**: v1.2.x is the stable line, the SDK is the production
broadcaster + wallet substrate for ARC-class deployments, and the
package backs `go-wallet-toolbox` per spec 17 §"Server-Side Wallet".

We do **not** add a new dependency — this is reuse. We do not hand-roll
a script interpreter; rejected for the obvious correctness-risk reasons.

## Anchor depth

Spec 07 line 81 / 220 / 596 documents the default of **6 BSV
confirmations** for bridge deposits. We expose this as
`beef.anchor_depth = 6` and pass it through to the verifier. Other
intent types use the same knob if/when they graduate beyond log-only.

## Performance bounds

BEEF ancestry can in principle be unbounded (arbitrary BSV history).
Reasonable defaults:

| Knob                  | Default | Why                                                                                       |
|-----------------------|---------|-------------------------------------------------------------------------------------------|
| `max_depth`           | 32      | A BEEF reaches a BUMPed ancestor at every level under spec 17; 32 covers normal wallets.  |
| `max_width`           | 10000   | Total ancestor count across all levels — caps absolute size of an envelope.               |
| `anchor_depth`        | 6       | Spec 07 default for bridge confirmation.                                                  |
| `validated_cache_size`| 4096    | LRU on validated outpoints (txid+vout); ancestors shared across BEEFs validate once only. |

The verifier rejects envelopes that exceed `max_depth` or `max_width`
before walking, so a malicious peer cannot consume unbounded CPU.

## Caching

The verifier owns a process-local `validatedTxCache` keyed by ancestor
txid. An entry exists once an ancestor has fully verified its BUMP
against chaintracks AND every input script has executed TRUE. Subsequent
BEEFs that re-include the same ancestor reuse the cached result and do
not re-execute the script interpreter. The cache is a fixed-size LRU
(`validated_cache_size`); eviction is benign — cold ancestors will just
be re-verified the next time they appear. The cache is **never**
populated from peer claims — only from this node's own successful
verification path.

## Failure surface

Any single verification failure → **reject the entire envelope**, return
HTTP 400 from the endpoint, increment the existing
`bsvevm_beef_gossip_rejected_total` counter with a reason label. No
partial credit, no degraded acceptance. This matches spec 17's "every
claim is re-verified" doctrine (§Architecture).

## Lifting F's fail-closed gate

`cmd/bsvm/beef_wiring.go` carries 4 `TODO(W6-4):` markers. After this
commit:

| File:line                      | Marker                                                         | Disposition                                              |
|--------------------------------|----------------------------------------------------------------|----------------------------------------------------------|
| `beef_wiring.go:135`           | log-only consumer for inbox / governance / fee-wallet / cov    | **Keep** — this commit only lifts the bridge gate. The other intents need their own subsystem wiring (spec 11 inbox-drain, spec 15 governance, spec 17 fee-wallet ingestion). Marker is updated to `TODO(W6-5):` to point at the next-wave consumer landing. |
| `beef_wiring.go:181-186`       | bridge fail-closed log-only sink                               | **Lifted** — replaced with a verifier+credit consumer that calls the new `pkg/beef.Verify` and forwards the parsed deposit to `bridge.BridgeMonitor.PersistDeposit` on success. |
| `beef_wiring.go:213`           | trusts env.Beef structurally in opt-in path                    | **Lifted** — the opt-in path now also runs the verifier first; `accept_unverified_bridge_deposits = true` only affects target-anchor-depth handling (it lowers `anchor_depth` to 0 for devnet), NOT script + ancestry checks. Marker repurposed to document the new policy. |
| `beef_wiring.go:248-250`       | `decodeBSVTransactionForBridge` adapter                        | **Removed** — the verifier emits a fully-validated `*transaction.Transaction` from the SDK; we read outputs directly off it instead of re-walking raw bytes through the scaffold adapter. |

The `accept_unverified_bridge_deposits` config knob stays as an explicit
operator override but its semantics change: it now only relaxes the
**anchor depth** requirement (so a devnet harness can credit a deposit
at 0 confirmations). Ancestry, BUMP, and script verification ALWAYS run.
Operators can no longer opt out of those, full stop.

## Config additions

`[beef]` section in `cmd/bsvm/config.go`:

```toml
[beef]
enabled = true
accept_unverified_bridge_deposits = false
# W6-4 additions:
max_depth = 32                  # max ancestor depth a BEEF may carry
max_width = 10000               # max total ancestor count
anchor_depth = 6                # required BSV confirmations on the target
validated_cache_size = 4096     # LRU bound on the validated-tx cache
```

All four new fields default to the values in the table above; an
operator can lower `anchor_depth` to 1 on devnet without flipping the
unverified knob.

## Recommended path

(a) — reuse the go-sdk's `transaction` + `script/interpreter` +
`chaintracker` packages. Confirmed: package is on `go.mod`, license is
acceptable, the API is exactly the verification surface we need.
Implementation is a thin adapter layer in `pkg/beef/` that:

1. Adapts `chaintracks.ChaintracksClient` to the SDK's
   `chaintracker.ChainTracker` interface (one extra file, `chaintracker_adapter.go`).
2. Adds `pkg/beef/verify.go` exposing `Verifier` with `Verify(ctx,
   beefBody)` returning a `*VerifiedBEEF` (parsed target tx + verified
   ancestors + BUMP block heights + computed deposit struct when the
   target carries a bridge output).
3. Owns the LRU cache and the depth/width limits.

`parse.go` stays as-is (other code paths still consume it for the
metadata-only walk on the gossip hot path). The verifier is layered on
top.
