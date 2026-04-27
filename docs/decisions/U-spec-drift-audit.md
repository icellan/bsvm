# U: Spec Drift Audit (Post-30-Deliverable Session)

Author: agent-a5a853b4cf5c1dec5 (U-spec-drift-audit)
Date: 2026-04-26
Branch: `worktree-agent-a5a853b4cf5c1dec5`

## Method

For each numbered spec under `<worktree>/spec/`, this audit compares the
spec text against the live tree (`pkg/`, `cmd/`, `internal/`, `test/`).
Drift severity scale:

- **current** — spec matches code; no remediation required.
- **drifted (minor)** — small inconsistencies (stale comments, renamed
  fields, additive features the spec does not mention). Code is correct;
  spec is slightly stale. Rewrite NOT required.
- **drifted (major)** — spec contradicts shipped behaviour in a way that
  could mislead an implementer or auditor. Spec rewrite required before
  next milestone.
- **stale (file may need rewrite)** — spec describes a model that has
  been superseded or whose interfaces no longer resemble the code. The
  whole file is misleading; rewrite or delete.

Mainnet-critical specs (09, 11, 12, 13, 17) audited first per task
priority.

---

## spec/00-PROJECT-OVERVIEW.md — current

Repo structure (lines 109–143) matches `pkg/` exactly; `pkg/sequencer/`
and `pkg/anchor/` correctly absent. Phase table (line 82) names match
milestones in spec 09. Mode 1 is described correctly here as a
mainnet-eligible STARK verifier.

No drift.

---

## spec/01-EVM-EXTRACTION.md — drifted (minor)

`pkg/vm/` is fully populated and gofmts clean (`pkg/vm/opcodes.go`,
`evm.go`, `interpreter.go`, `instructions.go`, etc.) — extraction list
in lines 13–36 matches reality. `pkg/types`, `pkg/crypto`, `pkg/rlp`,
`pkg/vm/tracing` all exist (we have them as siblings, see
`pkg/vm/tracing/`).

Drift items:

1. **Cancun/Prague fork progress not pinned in spec.** Lines 90–96
   describe `ChainConfig` with `CancunTime`, `PragueTime`, `FusakaTime`.
   Code at `pkg/vm/config.go` matches the field set, but EIP-4844 blob
   transactions, point-evaluation precompile, BLOBHASH opcode are
   already wired (`pkg/vm/contracts.go:670-681`,
   `pkg/vm/kzg.go:13-19`). Spec does not enumerate which post-Cancun
   EIPs are live — see decision doc `P-versioned-hash-audit.md`. Minor
   drift: spec is silent on what's actually been implemented vs. just
   declared.
2. **External `github.com/holiman/uint256` is at v1.3.2** (see
   `go.mod:13`); spec line 47 just says "uint256" with no pin. Not a
   bug — minor doc drift.

Recommendation: small spec sweep listing live EIPs and pinning
external deps. No code changes.

---

## spec/02-STATE-DB.md — current

`pkg/state/` matches: `account.go`, `state_object.go`, `journal.go`,
`statedb.go`, `transient_storage.go`, `access_list.go`, `proof.go`,
`snapshot.go`. Account struct at `pkg/state/account.go` matches lines
44–53. Journal entries (lines 156–199) match `pkg/state/journal.go`.

`StateDB.GetProof()` / `GetStorageProof()` referenced in spec 05 are
in `pkg/state/proof.go`. Snapshot is in `pkg/state/snapshot.go`.

No drift.

---

## spec/03-BLOCK-ENGINE.md — drifted (minor)

`pkg/block/` carries `types.go`, `apply.go`, `batch.go`, `executor.go`,
`state_transition.go`, `gas_pool.go`, `genesis.go`, `chaindb.go`,
`anchor.go`, `system_tx.go`, `log_index.go`. Matches the spec's
high-level shape.

Drift item:

1. **Spec lines 32–53 describe `AnchorRecord` but call it a "BSV
   covenant" tracking record.** Code has `AnchorRecord` in
   `pkg/block/anchor.go` but the role is now described in spec 11/12
   terms (covenant advance, not "anchor"). Spec text talks about
   "anchor" semantics that overlap with the superseded spec 04 vocab.
   Minor — code is fine, terminology is stale.

Recommendation: when spec 03 is next touched, replace "anchor" with
"covenant advance" everywhere. No code changes.

---

## spec/04-BSV-ANCHOR.md — current (stub)

Already marked superseded by spec 10. File is a 5-line redirect. No
drift — by design.

---

## spec/05-RPC-GATEWAY.md — drifted (minor)

`pkg/rpc/` has `eth_api.go`, `bsv_api.go`, `bsv_api_ext.go`,
`net_api.go`, `web3_api.go`, `admin_api.go`, `debug_api.go`, plus
`ws.go` for subscriptions. Bulk of P0/P1 methods present (the
`eth_*` table at lines 11–40 is largely covered).

Drift items:

1. **`bsv_buildWithdrawalClaim`** (spec line 75) is wired
   (`pkg/rpc/bsv_api_ext.go` exposes it), but the spec does not
   document a recently added parameter / return shape. Verify by
   reading `pkg/rpc/bsv_api_ext.go` against spec lines 75–80 once a
   spec sweep is scheduled. Minor.
2. **Admin RPC** (`pkg/rpc/admin_api.go`) has more methods than spec
   05 describes — those belong to spec 15 (explorer/admin UI). Doc
   drift only; admin endpoints are not mainnet-blocking.

No code changes recommended.

---

## spec/06-SEQUENCER.md — current (stub)

Already marked superseded by spec 11. 5-line redirect. No drift.

---

## spec/07-BRIDGE.md — drifted (minor)

`pkg/bridge/` has `monitor.go`, `deposit.go`, `withdrawal.go`,
`withdrawer.go`, `deposit_tree.go`, `replay_test.go`, `retract_test.go`,
`predeploy.go`, `ordering.go`. Bulk of bridge model in lines 1–100
matches.

Drift items (overlapping with spec 17 BEEF integration that landed
this session):

1. **Spec 07 (lines 70–95) describes `BridgeMonitor` constructed from
   a `BSVClient`** — the legacy direct-RPC interface. After
   `docs/decisions/beef-graph-validation.md` (W6-4), the BEEF
   ingestion path now front-runs `bridgeMonitor.PersistDeposit` via
   the spec-17 verifier (`pkg/beef/verify.go`). The legacy `BSVClient`
   interface in `pkg/bridge/monitor.go:25-42` still exists and still
   works, but spec 07 doesn't mention the BEEF path now lifted from
   fail-closed. Minor — code is correct; spec needs a one-paragraph
   update pointing at spec 17 and `pkg/beef/`.
2. **Spec line 41** says "1 satoshi = 10^10 L2 wei" — code matches
   (`pkg/bridge/deposit.go` deposit-credit conversion). Confirmed.
3. **Spec is 1500 lines** and the bulk of it is still accurate. Just
   needs a "see spec 17" callout and a pointer to W6-4's verifier.

Recommendation: append a "BEEF deposit ingestion" subsection to spec
07 referencing spec 17 §"BEEF: The Wire Format". Spec 07 is otherwise
mainnet-relevant and current.

---

## spec/08-GENESIS-AND-NODE.md — drifted (minor)

`pkg/block/genesis.go` matches the `Genesis` struct (lines 41–67) on
the major fields. `pkg/covenant/genesis.go` provides
`PrepareGenesis(*GenesisConfig) (*GenesisResult, error)` — matches
spec semantics.

Drift items:

1. **`bsvm init` / `bsvm run` lifecycle** (lines 19, 23) — actual
   commands are in `cmd/bsvm/cluster_init.go` and
   `cmd/bsvm/deploy_shard.go`. Spec wording is high-level enough to
   still be correct, just doesn't match new file layout.
2. **Governance config** is described at line 56; matches
   `pkg/covenant/governance.go`'s `GovernanceConfig` struct.
3. **Bridge predeploy** is at `pkg/bridge/predeploy.go`. Spec doesn't
   document the predeploy address registry (spec 09 milestone hooks
   are the closest mention).

No mainnet-blocking drift.

---

## spec/09-IMPLEMENTATION-ORDER.md — drifted (major)

The dependency graph (lines 4–48) and milestone breakdown (lines 52+)
are still accurate at the architectural level. The Gate 0a /
Gate 0b status callouts have been kept up to date inline.

Drift items:

1. **Lines 75–90 announce "Gate 0a Full — COMPLETE."** matching the
   recent commit `6bf7751` (Mode 1 verifies SP1 STARK on-chain). Good.
2. **Line 88** says "The previous `PrepareGenesis` Mode 1 mainnet
   guardrail has been lifted." Code at
   `pkg/covenant/genesis.go:84-89` confirms this — the guardrail is
   indeed lifted. Spec and code agree here.
3. **However**, the doc-comment on `GenesisConfig.Mainnet` at
   `pkg/covenant/genesis.go:31-36` STILL reads "rejects Verification
   == VerifyFRI (Mode 1 has no on-chain proof check and is not
   mainnet-eligible until Gate 0a Full lands)". The actual code body
   no longer rejects Mode 1 — the comment is a stale half-update.
   This is **doc drift inside the codebase, not the spec**. Minor in
   scope, but I'm flagging it here because it's adjacent to spec 09's
   Gate 0a story.
4. **Spec line 643 talks about `tests/sp1/...` deliverables** — these
   are at `prover/host-bridge/`, `prover/guest/`, and the proof blobs
   are referenced from `pkg/proofmode/`. Path drift only.

Recommendation: fix the comment at `pkg/covenant/genesis.go:31-36`
during the next non-spec sweep. Spec 09 itself is current.

---

## spec/10-DEEP-BSV-INTEGRATION.md — drifted (minor)

Recently updated with spec 12 cross-references. Mode 1 / Mode 2 /
Mode 3 verification model matches `pkg/covenant/contracts/`.

Drift items:

1. **Lines 60–73** describe the covenant as a single `rollup.go`. Code
   has three: `rollup_fri.runar.go`, `rollup_groth16.runar.go`,
   `rollup_groth16_wa.runar.go`, plus `rollup_devkey.runar.go` for
   devnet. Spec language ("collapsed into a single rollup.go") is
   pre-spec-12 phrasing. Reality is "one per mode." Minor.
2. **ANF audit artifact** (lines 115–119) — `pkg/covenant/compile.go`
   does export the ANF; matches.
3. **Inbox covenant** at lines elsewhere matches
   `pkg/covenant/contracts/inbox.runar.go` and
   `pkg/covenant/inbox_state.go`. The W4-3 inbox-drain witness work
   (see `docs/decisions/inbox-drain.md`) is in code, and spec 10 was
   updated to make `hash256(zero32)` normative for the empty-inbox
   sentinel.

No mainnet-blocking drift.

---

## spec/11-BSV-OVERLAY.md — drifted (minor)

`pkg/overlay/` has full implementation: `node.go`, `process.go`,
`batch.go`, `cache.go`, `confirmation_watcher.go`,
`circuit_breaker.go`, `inbox_monitor.go`, `governance_freeze.go`,
`fee_wallet.go`, `fee_wallet_reconciler.go`, `migration_monitor.go`,
`execution_verifier.go`, `cascade_rollback.go`, `dsmonitor.go`.

Drift items:

1. **Spec lines 31–60 describe propose-and-accept** — matches
   `pkg/overlay/process.go::ProcessBatch` and the cascade rollback
   path (`pkg/overlay/cascade_rollback.go`).
2. **Speculative receipts** (CLAUDE.md and spec 11) — code in
   `pkg/overlay/process.go` and `pkg/rpc/eth_api.go`'s block-tag
   handling (`safe`, `finalized`, `latest`) matches spec.
3. **`BSVClient` interface** (`pkg/overlay/dsmonitor.go:24-42`) is
   present. Spec 11 §"BSVClient" defines it. Spec 17 §"Migration from
   spec 11's BSVClient" claims it's collapsed onto `BSVNetworkClient`,
   but the type still exists in code. This is an additive coexistence
   — both interfaces work — but spec 17's "migration" wording
   over-promises. Minor doc drift; no functional drift.
4. **Forced-inclusion threshold** (10 advances) — matches
   `pkg/covenant/contracts/rollup_fri.runar.go` and
   `pkg/overlay/inbox_monitor.go`. Inbox sentinel is `hash256(zero32)`
   per spec update; matches code.
5. **Inbox queue cap** at `MAX_INBOX_DRAIN_PER_BATCH = 1024` is
   enforced at three layers (see `docs/decisions/inbox-drain.md` D6),
   but spec 11 / spec 12 still carry `TODO(spec)` markers for the
   constant. Minor — fix in next spec sweep.

No mainnet-blocking drift.

---

## spec/12-STATE-TRANSITION-PROOFS.md — drifted (MAJOR)

This is the biggest drift in the codebase.

**Spec lines 12–24 (Verification modes table)** state:

> Mode 1 `VerifyFRI` (trust-minimized FRI bridge): On-chain check =
> "**None.** Covenant binds state roots, batch hash, chain id via
> public-value slots and emits the batch OP_RETURN. The SP1 FRI proof
> is NOT verified on-chain. Off-chain nodes verify and trigger
> governance freeze on an invalid advance."
>
> Status: "**Testnet / experimental.** Mainnet-blocked by
> `PrepareGenesis` guardrail."

**Spec lines 26–42 (Mode 1 security model)** state:

> Mode 1 is the **trust-minimized FRI bridge**. The covenant does NOT
> verify the SP1 FRI proof. A malicious prover can advance the state
> with an invalid proof; the only recourse is governance freeze.
> ...
> Mode 1 is NOT mainnet-eligible. `PrepareGenesis` rejects
> `Mainnet=true && Verification=VerifyFRI` with a clear error. The
> guardrail is lifted when Gate 0a Full lands with a real on-chain
> FRI verifier.

**Spec lines 44–51 (Future: Gate 0a Full)** state:

> A full on-chain FRI verifier ... is tracked as Gate 0a Full ... When
> it lands, Mode 1 upgrades from a bridge to a fully self-verifying
> rollup. ... **No work is scheduled against Gate 0a Full at the time
> of writing.**

**Reality (commit 6bf7751, plus CLAUDE.md, plus spec 09 lines 81–90):**

- Gate 0a Full **has landed**.
- `pkg/covenant/contracts/rollup_fri.runar.go:121` calls
  `runar.Assert(runar.VerifySP1FRI(proofBlob, publicValues, c.SP1VerifyingKeyHash))`
  on every `AdvanceState` invocation. Lines 307, 366, 421 carry the
  same call for the freeze/unfreeze/upgrade paths.
- `pkg/covenant/genesis.go:84-89` says Mode 1 is mainnet-eligible
  ("Mode 1 (VerifyFRI) is mainnet-eligible. Gate 0a Full has landed").
- `runar.VerifySP1FRI` is exported from
  `/Users/siggioskarsson/gitcheckout/runar/packages/runar-go/runar.go:325`
  (sibling repo, confirmed alive).

**Severity: MAJOR.** Anyone reading spec 12 today will get the
opposite of the truth: they will believe Mode 1 is testnet-only and
bridge-style, when in reality it is the on-chain SP1 STARK verifier
with the largest locking script (~849 KB) of the three modes.

**Remediation**: Spec 12 §"Verification modes", §"Mode 1 security
model", §"Future: Gate 0a Full" all need rewrite. Mode 1 should be
described as the on-chain SP1 FRI verifier (mainnet-eligible under VK
pinning), and the "Future" section should be retired or repurposed.

This is the highest-priority spec fix in the audit.

---

## spec/13-RUNAR-REQUIREMENTS.md — drifted (MAJOR)

Same drift class as spec 12, propagating from the same source.

**Spec lines 36–44 (Mode 1 description)** state:

> **Mode 1 `VerifyFRI`** — trust-minimized FRI bridge. `advanceState`
> takes 5 args ... and performs **NO on-chain FRI verification**.
> ... **Not mainnet-eligible.**

**Spec lines 174–186 (SP1 FRI Verifier section)** state:

> **Status**: **Gate 0a Full — future work, not scheduled.** This
> section describes the design target for the on-chain FRI verifier.
> The compiled Mode 1 rollup covenant today (`rollup_fri.runar.go`)
> does NOT verify the FRI proof on-chain; it is the trust-minimized
> FRI bridge described in spec 12 ...

**Reality**: Gate 0a Full landed. `runar.VerifySP1FRI` is the Rúnar
intrinsic that performs the full SP1 v6.0.2 STARK verifier
(KoalaBear + Poseidon2 + colinearity + Fiat-Shamir) inline and
compiles to Bitcoin Script.

**Severity: MAJOR.** Same reason as spec 12.

**Other drift in spec 13 (minor):**

1. **Lines 165–169 inbox covenant** — describes hash-chain default,
   matches `pkg/covenant/contracts/inbox.runar.go`. Current.
2. **Lines 245–256 measured primitive script sizes** — these are the
   Gate 0a primitive measurements; current.
3. **Lines 415–420 "no Keccak in Script"** — current.
4. **Lines 678–712 Rúnar DSL Subroutine Reference** — large table.
   Most entries match the live Rúnar surface (cross-checked
   `runar.Assert`, `runar.Cat`, `runar.SHA256`, `runar.Hash256`,
   `runar.Substr`, `runar.MerkleRootSha256`, etc. — all present in
   the sibling repo). One missing intrinsic from the table:
   **`m.Verify(vk, proof)`** is described as "Runs FRI verification
   of SP1 proof" — in code this is exposed as **`runar.VerifySP1FRI`**
   (not `m.Verify`). Minor naming drift; the spec table needs the
   real symbol name.

**Remediation**: Spec 13 §"State Covenant" §Mode 1 description and
§"4. SP1 FRI Verifier" need rewrite. Subroutine reference table
needs `m.Verify` → `runar.VerifySP1FRI` and the signature pin
(`(proofBlob, publicValues, sp1VKeyHash) bool`).

---

## spec/15-EXPLORER-ADMIN-UI.md — drifted (minor)

`pkg/webui/` exists with `embed.go` and `dist/`. `pkg/rpc/admin_api.go`
and `pkg/rpc/auth/` (BRC-104) cover the admin RPC surface. `pkg/admin/`
does not exist as its own package (admin lives in `pkg/rpc/`).

Drift items:

1. **Lines 26–42 architecture diagram** describes a React SPA. Code
   has `pkg/webui/dist/` with the embedded build, served by the
   overlay node's HTTP layer. Matches.
2. **BRC-100 wallet auth** (lines 46–66) — `pkg/rpc/auth/`
   implements BRC-3 / BRC-103 / BRC-104. Cross-check the exact field
   names if a spec sweep is scheduled.
3. **Multisig governance proposal flow** (lines 70–80) — present in
   `pkg/covenant/governance.go` and the admin RPC. Looks current.

No mainnet-blocking drift.

---

## spec/16-DEVNET.md — drifted (minor)

`test/devnet/sim_smoke_test.go`, `test/devnet/smoke_test.go`,
`cmd/bsvm-sim/main.go`, `pkg/sim/` — devnet infrastructure exists.
Mode 1 / Mode 2 / Mode 3 proving-mode story matches code's actual
mode set.

Drift items:

1. **Spec uses `mock` / `execute` / `prove`** as the three proving
   modes. `pkg/proofmode/proofmode.go` exposes these. Match.
2. **Spec line 41–42** says mock mode "covenant's FRI verification
   step is replaced by a dev key signature check". Code at
   `pkg/covenant/contracts/rollup_devkey.runar.go` is exactly this
   variant. Match.
3. **Devnet funding** at `cmd/bsvm/devnet_funding.go` is referenced
   but not deeply spec'd. No drift, just a gap.

No mainnet-blocking drift.

---

## spec/17-CHAINTRACKS-BEEF-ARC.md — drifted (minor)

`pkg/chaintracks/`, `pkg/arc/`, `pkg/beef/`, `pkg/whatsonchain/`,
`pkg/bsvclient/` — all subsystems present. Recent decision docs
(`beef-graph-validation.md`, `header-oracle-quorum.md`,
`W6-7-runar-broadcast-status.md`) confirm the BEEF/ARC/quorum
framework is largely landed.

Drift items:

1. **Spec lines 51–58** says the `BSVClient` interface is "collapsed
   into a thinner `BSVNetworkClient`". Reality: the legacy
   `BSVClient` interface still exists in `pkg/bridge/monitor.go:25`
   and `pkg/overlay/dsmonitor.go:24`. The new BEEF/ARC stack has
   been added alongside, not in place of. This is "additive, not
   replacement". Spec 17 over-promises a hard migration that didn't
   happen — the two surfaces coexist. Minor doc drift; no functional
   bug.
2. **`runar_broadcast.go` triage** (see
   `docs/decisions/W6-7-runar-broadcast-status.md`) — confirmed not
   legacy, used by `cmd/bsvm/bsv_wiring.go`. Spec 17 doesn't mention
   it explicitly; OK.
3. **Header-oracle quorum** — `pkg/chaintracks/multi_client.go`
   matches the spec-17 + W6-2 design (see
   `docs/decisions/header-oracle-quorum.md`).

No mainnet-blocking drift.

---

## Summary table

| Spec | Status | Severity | Mainnet-blocking? |
|------|--------|----------|-------------------|
| 00   | current | — | no |
| 01   | drifted | minor | no |
| 02   | current | — | no |
| 03   | drifted | minor | no |
| 04   | current (stub) | — | no |
| 05   | drifted | minor | no |
| 06   | current (stub) | — | no |
| 07   | drifted | minor | no (BEEF callout deferred) |
| 08   | drifted | minor | no |
| 09   | drifted | minor (+ adjacent code-comment drift) | no |
| 10   | drifted | minor | no |
| 11   | drifted | minor | no |
| **12** | **drifted** | **MAJOR** | **YES — auditors will be misled** |
| **13** | **drifted** | **MAJOR** | **YES — same Mode 1 mis-statement** |
| 15   | drifted | minor | no |
| 16   | drifted | minor | no |
| 17   | drifted | minor | no |

## Recommended fix order

1. **Spec 12 + spec 13** (Mode 1 mainnet eligibility + Gate 0a Full
   status). Single coordinated rewrite; both specs reference each
   other. **Highest priority.**
2. `pkg/covenant/genesis.go:31-36` doc comment — small in-code fix,
   stale half-update.
3. Spec 07 BEEF-deposit callout pointing at spec 17 + W6-4.
4. Spec 13 subroutine reference table: `m.Verify` →
   `runar.VerifySP1FRI`.
5. Spec 17 "Migration from spec 11's BSVClient" — soften the
   "collapsed" wording to "additive" until the legacy
   `BSVClient` interfaces are actually retired.
6. Cosmetic / minor drift across specs 01, 03, 05, 08, 09, 10, 11,
   15, 16 — bundle into a single sweep when convenient.

No spec was found to be irreparably stale. The two majors are
isolated to the Mode 1 / Gate 0a Full story and are mechanically
fixable.
