# XL-Scope Deferred Hooks (2026-05)

Date: 2026-05-03
Branch: worktree-agent-adfacda178aa2c816
Author: planning research

## Context

The 2026-05 spec-review triage (`docs/decisions/spec-review-triage-2026-05.md`)
identified a number of named `WW-*` / `BSV-*` hooks. Most are S/M-scoped
gaps that close in a single session. Four are XL-scoped — they each
require multi-week effort, cross-repo coordination, on-chain VK or
covenant rotation, or some combination thereof, and **cannot be closed
inside a single working session**. This document captures, for each of
those four hooks, what shipping it actually requires, what blocks it
today, and what the operator/team should do in the meantime.

This is research/audit only. No code is changed.

The four hooks covered:

1. `WW-anf-runar` — replace the in-tree ANF emitter with upstream
   `runar-go`'s ANF API once it lands.
2. `WW-upgrade-proof-real-stark` — replace the synthetic upgrade-proof
   bundle with a real STARK proof.
3. `WW-prague-fork-bump` — bump both the Go EVM and the Rust SP1 guest
   from Cancun to Prague/Pectra.
4. `BSV-precompiles-activation` — activate the live BSV precompiles
   (`BSV_VERIFY_TX`, `BSV_VERIFY_SCRIPT`, `BSV_BLOCK_HASH`) that today
   stub-revert with `ErrBSVPrecompileNotActive`.

Pre-existing decision docs that frame these hooks:

* `docs/decisions/spec-review-triage-2026-05.md` — original triage
  that named claims #1, #4 and #5 (the prover wiring, the Cancun-vs-
  Prague mismatch, and the BSV precompile status).
* `docs/decisions/sp1-reproducible-build-2026-05.md` — explains why
  any guest source change rotates the SP1 verifying key, which is the
  cost premium attached to hooks 2 and 3.
* `docs/decisions/vk-rotation-wire-format-2026-04.md` — the canonical
  example of a VK rotation event; the playbook hooks 2 and 3 will
  reuse.

---

## Hook: `WW-anf-runar`

**Status**: deferred (XL-scope)

**One-liner**: Replace the in-tree `pkg/covenant/anf` emitter with a
thin wrapper around upstream `runar-go`'s `runar.PublishANF` /
`runar.ANFInscriptionPayload` API once that API ships.

**Why deferred**:
- Cross-repo dependency: runar-go does not yet expose a first-class
  ANF inscription emitter (`runar.PublishANF` /
  `runar.ANFInscriptionPayload`). The block waiting on us is
  precisely zero; the block waiting on runar-go is "design + ship
  that API," which is upstream effort outside this repo.
- Per the user's standing instruction (`feedback_no_cross_repo_edits`),
  BSVM does NOT edit sibling repos directly. The hand-off is a spec
  PR at the bsv-evm root describing what BSVM needs from runar-go;
  the actual implementation happens in runar-go on its own cadence.
- Hash stability: `pkg/covenant/anf/anf.go` (`SchemaVersion = "bsvm.anf/1"`)
  is the on-chain commitment for `pv[240..272)` of every covenant
  rotation. Replacing the emitter cannot change the canonical hash
  for any pre-existing ANF — old documents in BSV history must
  continue to verify against their on-chain commitments. The
  upstream API has to either reproduce our canonical-form bytes
  exactly OR we keep our emitter alive in parallel for backward
  compatibility, which negates much of the benefit.

**What shipping requires**:
- runar-go ships `runar.PublishANF(...) (Document, error)` and
  `runar.ANFInscriptionPayload` types. The shape MUST be a strict
  superset of `anf.Document` (`pkg/covenant/anf/anf.go:99-128`) so
  the BSVM-side wrapper can fill the same fields.
- runar-go MUST guarantee deterministic byte output (matching the
  contract spelled out in `anf.go:130-166` / `CanonicalJSON`).
  Specifically: stable struct field ordering, sorted map keys at
  every depth, and round-trippable embedded `anfIR` (because the
  ANF IR is itself a runar-go artifact whose ordering can drift
  across runar-go releases — `anf.go:212-247::canonicaliseRaw` /
  `marshalSorted` is the in-tree workaround).
- Replace `BuildDocument` in `pkg/covenant/anf/anf.go` with a thin
  delegate that calls the upstream emitter and asserts the returned
  bytes hash to the same `pv[240..272)` value the in-tree emitter
  produced for the same inputs.
- Keep the in-tree emitter behind a `// LEGACY` build tag for at
  least one release cycle, so observers can replay old ANFs minted
  before the cutover. The `SchemaVersion` const (`bsvm.anf/1`) does
  NOT bump unless the canonical bytes change.
- Differential test: feed a corpus of historical ANF inputs (genesis
  + every rotation event) through both emitters and assert
  `ComputeHash` returns identical 32-byte digests.

**Cross-cutting impacts**:
- Subsystems touched: `pkg/covenant/anf/`, `deploy/covenant/compile.go`
  (consumes `BuildDocument`), `deploy/covenant/rotate-vk.go` (consumes
  `BuildDocument` for rotation ANFs).
- VK rotation required: **NO**. The ANF emitter is not part of the
  SP1 guest; swapping it does not perturb the verifying key.
- Covenant rotation required: **NO** as long as the emitter produces
  byte-identical canonical form for any given input. If the upstream
  emitter changes the canonical bytes (e.g., swaps key ordering),
  every shard that wants to publish a *new* ANF would need a
  rotation event; live shards' historical ANFs are unaffected
  because they're already inscribed on BSV.
- Spec drift: `spec/13-RUNAR-REQUIREMENTS.md` does not currently
  list ANF publishing as a required runar-go capability. Closing
  this hook starts with a spec PR adding it under a new
  §"ANF Inscription" section, written from the BSVM root, then
  hand-off to runar-go.
- Changes in runar-go: **YES** — the upstream change is the load-
  bearing piece.

**Operator interim**:
- Continue to use `pkg/covenant/anf` as the authoritative ANF
  emitter. Per the package doc (`anf.go:9-13`) it is explicitly
  designed to be the emitter "until upstream lands a `runar.PublishANF`
  / `runar.ANFInscriptionPayload` API". Operators do not need to do
  anything different.
- Continue to inscribe ANFs at every genesis + rotation. The on-
  chain hash commitment in `pv[240..272)` is the source of truth; the
  ANF JSON is the audit-grade companion and is verified against the
  hash by `Document.ComputeHash` (`anf.go:172-178`).
- Treat any ANF schema or shape change as a backwards-incompatible
  break that requires a `SchemaVersion` bump and a coordinated
  release across all shards.

**Acceptance criteria**:
- Upstream runar-go has tagged a release exposing `runar.PublishANF`
  and `runar.ANFInscriptionPayload` types.
- `pkg/covenant/anf/anf.go::BuildDocument` is a delegate (≤ 30 lines
  of glue) over the upstream API.
- A differential test in `pkg/covenant/anf/anf_test.go` proves
  byte-identical canonical form across the legacy and delegated
  paths over a fixed corpus of historical ANF inputs.
- All on-chain commitments computed by the legacy emitter still
  verify against `Document.ComputeHash` after the switch.

**Effort estimate**: L (≤1mo elapsed) — most of the wall-clock is
in runar-go upstream, not in BSVM. BSVM-side work is ~1-2 days
(the delegate + the diff test).

**Dependencies**:
- runar-go upstream must ship the `runar.PublishANF` API first.
- (Optional, recommended) `WW-prague-fork-bump` should NOT block this
  hook; the two are orthogonal. Likewise this hook does not need to
  precede or follow `WW-upgrade-proof-real-stark`.

**Suggested owner / next-action**: Whoever owns the BSVM/runar-go
boundary. First hour: write the spec PR adding §"ANF Inscription"
to `spec/13-RUNAR-REQUIREMENTS.md`, summarising the contract spelled
out in `pkg/covenant/anf/anf.go` (the schema, the canonical-form
rules, the hash256-to-publicValues binding). Then file the upstream
issue against runar-go citing that section.

---

## Hook: `WW-upgrade-proof-real-stark`

**Status**: deferred (XL-scope)

**One-liner**: Generate a real (cryptographically valid) STARK proof
for the upgrade transition so on-chain `runar.VerifySP1FRI` accepts
the rotate-vk bundle, instead of the current shape-correct synthetic
stand-in.

**Why deferred**:
- The production SP1 guest (`prover/guest/src/main.rs::main`) commits
  a public-values layout that is **incompatible** with the on-chain
  `Upgrade*` verifier's expectations:
  - Production guest emits **big-endian** `chainId` at `pv[136..144)`
    and **big-endian** `block_number` at `pv[272..280)`
    (`prover/guest/src/main.rs:674,679`).
  - The on-chain upgrade verifier asserts **little-endian** layouts
    in those slots (`pkg/covenant/upgrade.go:166,172` —
    `binary.LittleEndian.PutUint64`).
  - Production guest emits `receiptsHash` at `pv[64..96)`
    (`main.rs:671`); the upgrade verifier expects `hash256(proofBlob)`
    at the same offset (`upgrade.go:159-160`).
  - Production guest emits `withdrawalRoot` at `pv[144..176)`,
    `inboxBefore`/`inboxAfter` at `pv[176..240)`, and a hard-coded
    zero `migrationScriptHash` at `pv[240..272)`
    (`main.rs:675-678`); the upgrade verifier expects the real
    `hash256(newCovenantScript)` at `pv[240..272)`
    (`upgrade.go:169-170`) and zeros across `pv[144..240)`.
  These are five separate slot mismatches, not a single byte-order
  flip — the production guest is by design committing a state-
  transition proof, and the upgrade transition is a no-op state
  transition with a covenant-script binding instead.
- A new guest entry point that commits the spec-12 upgrade public-
  values layout would change the bytes of
  `prover/guest/src/main.rs`, which rotates the bsvm-guest ELF,
  which rotates the SP1 verifying key
  (per `docs/decisions/sp1-reproducible-build-2026-05.md` §"What's
  actually non-deterministic"). That in turn requires a coordinated
  VK rotation on every live shard (`docs/decisions/vk-rotation-wire-
  format-2026-04.md` §"What this rotation requires on-chain"), and
  rotating the VK is precisely the on-chain operation the upgrade-
  proof tooling is *for*. So the migration path is itself a chicken-
  and-egg coordination problem.
- Today the host bridge falls back to a synthetic, shape-correct
  bundle that the on-chain verifier rejects
  (`prover/host-bridge/src/main.rs:737-844::run_upgrade_proof`,
  `real_proof: false`, `note: "synthetic upgrade-proof bundle ...
  WILL reject this proof"`). This is documented as a known limitation
  in `docs/operator/vk-rotation.md:130-147` and `docs/operator/vk-
  rotation.md:452-461`.

**What shipping requires**:
- Add a second guest entry point in `prover/guest/src/main.rs` (or a
  separate `prover/guest-upgrade/`) that commits exactly the 280-byte
  layout specified in `pkg/covenant/upgrade.go:130-174::EncodeUpgradePublicValues`:
  - `pv[0..32)` preStateRoot
  - `pv[32..64)` postStateRoot (== preStateRoot for upgrade)
  - `pv[64..96)` hash256(proofBlob)  *[reserved slot, on-chain unchecked]*
  - `pv[96..104)` 8 zero bytes
  - `pv[104..136)` hash256(batchData)
  - `pv[136..144)` chainId LE
  - `pv[144..240)` 96 zero bytes
  - `pv[240..272)` hash256(newCovenantScript)
  - `pv[272..280)` newBlockNumber LE
- The entry point must take `(preStateRoot, newCovenantScript,
  chainId, blockNumber)` as guest input and produce the above layout.
  No EVM execution is needed (the upgrade tx is a no-op state
  transition by definition); the guest's job is purely to commit
  these values under a STARK so the on-chain verifier accepts them.
- Wire the host bridge `--mode upgrade-proof` path
  (`prover/host-bridge/src/main.rs:737`) to invoke the new entry
  point via `ProverClient::prove(...)` instead of emitting the
  synthetic stand-in. Set `real_proof: true` in the JSON output.
- Either (a) fold the upgrade entry point into the same ELF as the
  production main entry point (selectable via guest input flag),
  which keeps the VK count at one per shard, or (b) ship as a
  separate ELF with its own VK pinned in a sibling file
  (`prover/guest/elf/SP1VerifyingKeyHash-upgrade.txt`) and update
  the on-chain covenant to know about both keys.
- Whichever option is chosen, the first deployment requires *one*
  on-chain VK rotation per live shard, executed via the existing
  synthetic-proof path during a maintenance window where the shard
  is frozen. Spec 15's freeze-then-upgrade flow already covers this.
- Update `docs/operator/vk-rotation.md` §1 step 4 to remove the
  current "synthetic bundle, on-chain verifier WILL reject" caveat
  (lines 130-147) and the §9 follow-ups list (lines 452-461).

**Cross-cutting impacts**:
- Subsystems touched: `prover/guest/src/main.rs` (new entry point or
  selector), `prover/host-bridge/src/main.rs::run_upgrade_proof`,
  `prover/guest/elf/SP1VerifyingKeyHash.txt` (re-stamped), every
  per-shard genesis manifest, the on-chain covenant via
  `deploy/covenant/rotate-vk.sh`.
- VK rotation required: **YES**. This is the dominant cost. Any
  source change in `prover/guest/src/**` rotates the VK. The
  rotation playbook in `docs/decisions/vk-rotation-wire-format-
  2026-04.md` applies verbatim.
- Covenant rotation required: **YES** — the VK rotation IS a
  covenant rotation (the on-chain `Upgrade*` method spends the
  current covenant UTXO and creates a new one with the new
  `SP1VerifyingKeyHash` baked in).
- Changes in runar-go: **NO** — `runar.VerifySP1FRI` already does
  the right thing; the gap is entirely on the SP1 guest + host
  bridge side. (The Mode 1 covenant
  `pkg/covenant/contracts/rollup_fri.runar.go:121` already invokes
  `runar.VerifySP1FRI` and is ready.)
- Spec drift: spec 12 is silent on the "two entry points or one"
  question; closing this hook starts with adding a §"Upgrade Public
  Values" sub-section to spec 12 that pins the layout the host
  bridge already targets.
- Self-rotation chicken-and-egg: the very first cutover from
  synthetic-stand-in to real-STARK requires one rotation that the
  current synthetic path *cannot do* (because the new guest needs
  to be the one signing the rotation that installs itself). The
  bootstrap path is: (1) ship the new guest on testnet using the
  synthetic-stand-in rotation flow against a testnet shard with
  `governance: single_key`, (2) verify the new guest's real STARK
  passes the on-chain verifier on that testnet shard, (3) repeat
  for every mainnet shard during a freeze window, signing each
  rotation with the live governance keys.

**Operator interim**:
- The `bsvm-host-bridge --mode upgrade-proof` command continues to
  emit a shape-correct synthetic bundle. Operators can use this for:
  - Partial-sig assembly + multisig signature collection (the
    sighash + governance sigs are real even if the proof bytes are
    not).
  - Dry-run broadcast against a testnet ARC instance to exercise
    the rotation tooling end-to-end.
  - Cold-storage rehearsal of the rotation procedure.
- Operators MUST NOT broadcast a synthetic-proof rotation against
  any shard whose covenant uses `Mode 1` (FRI). The on-chain
  `runar.VerifySP1FRI` will reject it and the BSV broadcast will
  fail. The synthetic bundle's `note` field
  (`prover/host-bridge/src/main.rs:834-840`) makes this explicit.
- Mode 2 / Mode 3 (Groth16) shards face the same gap
  (the upgrade-proof bundle is mode-agnostic in this respect — it
  is always a synthetic stand-in until this hook ships); rotations
  for those shards require the real-Groth16 equivalent of this
  work, which is a sibling track not covered by this hook.
- For shards in `governance: none` mode, rotation is impossible by
  design (`docs/operator/vk-rotation.md:151-153`); this hook is
  irrelevant to those shards (re-deployment is the only path).

**Acceptance criteria**:
- The bsvm-guest ELF (or a sibling upgrade-only ELF) commits the
  spec-12 upgrade public-values layout for the upgrade transition.
- `bsvm-host-bridge --mode upgrade-proof` emits `real_proof: true`
  and the bundle's `proof_blob_hex` is a real SP1 STARK that
  `cargo prove verify` accepts locally.
- An integration test in `pkg/covenant/contracts/rollup_fri_test.go`
  (or a new `upgrade_fri_test.go`) builds a real upgrade-transition
  proof end-to-end and asserts the on-chain `Upgrade*` method
  accepts it on regtest.
- `docs/operator/vk-rotation.md` no longer carries the "synthetic
  bundle, on-chain verifier WILL reject" caveat (the §1 step 4
  blockquote at lines 130-147 disappears).

**Effort estimate**: XL (4-8 weeks elapsed):
- ~1 week guest entry-point implementation + local testing.
- ~1 week host-bridge wiring + bench-loop integration.
- ~1 week reproducible-build verification (the new ELF must hash
  identically across operators per
  `docs/decisions/sp1-reproducible-build-2026-05.md`).
- ~1-2 weeks per-shard rotation coordination (governance signature
  collection + freeze windows + audit trail).
- Plus testnet-first migration cycle before mainnet shards see it.

**Dependencies**:
- `docs/decisions/sp1-reproducible-build-2026-05.md` Phase 1 must
  be live so the new guest ELF is deterministic across operators.
  (Today this is on the verge of shipping per the decision doc;
  treat it as a soft prerequisite.)
- Per-shard governance configurations must be able to authorise an
  upgrade — `governance: none` shards are out of scope for this
  hook.

**Suggested owner / next-action**: Whoever owns the SP1 guest
program. First hour: open `prover/guest/src/main.rs` and the
`pkg/covenant/upgrade.go::EncodeUpgradePublicValues` doc-comment
side-by-side, write a one-page design note on the
"two entry points vs one ELF with selector" question (each has a
specific cost — two entry points means two pinned VKs per shard;
one ELF with selector means a tiny rotation that touches every
shard right now and changes nothing observable until upgrade-proof
is invoked). Land that note as a sibling decision doc before
writing any guest code.

---

## Hook: `WW-prague-fork-bump`

**Status**: deferred (XL-scope)

**One-liner**: Upgrade both the Go EVM (`pkg/vm/`) and the Rust SP1
guest (`prover/guest/`) from Cancun to Prague/Pectra, keeping the
two implementations bit-equivalent so the proof public-values layout
stays byte-identical.

**Why deferred**:
- Dual-EVM coordination: the Cancun→Prague delta must land in BOTH
  the Go EVM and the Rust SP1 guest in the same release. CLAUDE.md's
  "Dual-EVM Architecture" rule is non-negotiable: "Both EVMs MUST
  pass ethereum/tests and produce identical state roots for
  identical inputs." A Prague bump that lands in only one EVM is a
  critical bug, not a partial improvement.
- The Prague EIPs are individually substantial:
  - **EIP-7702** SetCode-for-EOAs introduces a new tx type and a
    delegation-designator code path. The Go EVM stubs the resolver
    (`pkg/vm/evm.go::resolveCode` / `resolveCodeHash` at the
    locations cited in `docs/decisions/spec-review-triage-2026-05.md`
    Claim 4 §"Verification") with comments saying
    "After Prague, it can also resolve code pointed to by a
    delegation designator", but no delegation logic is wired. This
    is ~2 weeks of work on its own per the triage doc
    (Claim 4 §"Notes for the operator").
  - **EIP-2537** BLS12-381 precompiles (0x0b-0x11) require a pure-Go
    BLS12-381 implementation (or a CGO binding to `blst`, which
    violates the project's no-CGO-in-EVM rule per spec 01).
  - The consensus-layer Prague EIPs (6110, 7002, 7251, 7549, 7685)
    are L1-validator-economy and likely **not relevant** to this L2,
    but spec 01 does not enumerate which Prague EIPs are in scope;
    closing the hook starts with that scoping decision.
- VK rotation: any guest source change rotates the VK
  (`docs/decisions/sp1-reproducible-build-2026-05.md`). A Prague
  bump on the Rust side is a substantial guest source change —
  touching `revm` version pin, `SpecId::CANCUN` →
  `SpecId::PRAGUE` (`prover/guest/src/main.rs:557` per the triage
  doc), and any precompile/opcode dispatch tables. Every live
  shard would need a coordinated VK rotation.
- The spec already labels this as deferred. Spec 01 §"Source"
  (`spec/01-EVM-EXTRACTION.md:11-23`) and §"EVM version note"
  (lines 452-468) both name `WW-prague-fork-bump` explicitly and
  document that v1 is Cancun-only.
- Runtime guard: `cmd/bsvm/config.go:100-122` (`supportedEVMForks`)
  only allows `"cancun"` today and explicitly names the hook in its
  comment. Bumping that map is part of the work, not a precursor.

**What shipping requires**:
- A scoping decision: which Prague EIPs are in scope for the L2.
  The L1-validator-economy EIPs (6110, 7002, 7251, 7549, 7685) are
  almost certainly out of scope. EIP-7702 and EIP-2537 are almost
  certainly in scope (they're application-layer features developers
  expect from a "Prague" L2). Document the scope in spec 01.
- Pure-Go BLS12-381: pick a library (`gnark-crypto`, `kilic/bls12-381`,
  or `cloudflare/circl`) that has no CGO dependency. Wire its
  primitives into the seven Prague precompile addresses
  (`pkg/vm/contracts.go`).
- EIP-7702 delegation resolver: add the delegation-designator code
  path to `pkg/vm/evm.go::resolveCode` and `resolveCodeHash`, plus
  the matching Tx Type 4 handling in the block executor. Add the
  same to the Rust side via `revm`'s Prague support (revm v29+ has
  it; check the pin).
- Bump `prover/guest/src/main.rs` from `SpecId::CANCUN` to
  `SpecId::PRAGUE`. Make sure revm's BLS12-381 precompile
  implementation matches the pure-Go implementation byte-for-byte
  on the public-values layout — differential test in
  `pkg/prover/dual_evm_test.go` (or wherever the dual-EVM
  equivalence harness lives).
- Bump the `supportedEVMForks` map in `cmd/bsvm/config.go:105` to
  include `"prague"`. Add a config knob letting operators choose
  Cancun vs Prague at startup time, so existing shards can stay on
  Cancun while new shards launch on Prague.
- Update `pkg/vm/jump_table.go::newPragueInstructionSet` (today an
  alias for `newCancunInstructionSet` per the triage doc) with the
  actual Prague opcode set.
- Update the `DefaultL2Config` in `pkg/vm/config.go` to set
  `PragueTime: &zeroTime` (today nil).
- Activate the spec 01 §"Source" wording change pending under the
  hook (the spec says "v1 fork target: Cancun (Prague deferred)" —
  flip that once the implementation actually supports Prague).

**Cross-cutting impacts**:
- Subsystems touched: `pkg/vm/` (jump tables, contracts, evm.go,
  config.go), `prover/guest/src/main.rs`, `prover/guest/Cargo.lock`
  (revm bump), `pkg/state/` (EIP-7702 may need new account fields),
  `cmd/bsvm/config.go` (`supportedEVMForks` + new fork knob),
  `spec/01-EVM-EXTRACTION.md`, every shard genesis manifest's
  `[evm]` section.
- VK rotation required: **YES**. Guest source change rotates the VK
  on every live shard. Per
  `docs/decisions/sp1-reproducible-build-2026-05.md`, the cost of
  a rotation is ~1 hour per shard once the playbook is rehearsed,
  but coordination across N shards and N governance signing
  ceremonies dominates.
- Covenant rotation required: **YES** — every shard that wants to
  run Prague must rotate its covenant to bake in the new VK.
- Changes in runar-go: **NO**. The covenant scripts and
  `runar.VerifySP1FRI` are EVM-fork-agnostic; they verify the SP1
  proof against the pinned VK regardless of which fork the proof
  was generated under.
- Compatibility surprise (mainnet blast): per the triage doc
  Claim 4 §"Mainnet blast radius" — third-party tooling that
  assumes Prague rules and gets surprised when an EIP-7702
  delegated-call fails. Mitigated for now by the runtime guard
  rejecting any non-`cancun` fork string, but third-party
  contract authors will eventually deploy contracts assuming
  features the L2 doesn't have until this hook ships.

**Operator interim**:
- The shard runs Cancun. The `[evm].fork` config knob accepts only
  `"cancun"` (`cmd/bsvm/config.go:118-121`). A typo or future-fork
  attempt fails at startup with a clear error.
- Document on the BSVM landing page / README that v1 ships Cancun
  and that Prague is on the post-v1 roadmap. Solidity contract
  authors targeting BSVM should compile with `--evm-version cancun`.
- Watch for third-party "is this Prague?" questions. If the L2
  later lands on chainlist.org or any explorer, label the chain as
  "Cancun" not "Prague" so authors don't deploy EIP-7702-dependent
  contracts that will revert.
- Do NOT toggle `PragueTime` non-nil in any operator config —
  there are no Prague-specific opcodes wired, so it would be a
  cosmetic flag only and could mislead a future maintainer.

**Acceptance criteria**:
- `pkg/vm/jump_table.go::newPragueInstructionSet` returns a real
  Prague instruction set (not an alias for Cancun).
- `pkg/vm/contracts.go` registers the seven BLS12-381 precompiles
  at addresses 0x0b-0x11 under `IsPrague` rules.
- `pkg/vm/evm.go::resolveCode` honours EIP-7702 delegation
  designators.
- `prover/guest/src/main.rs` pins `SpecId::PRAGUE`, and the dual-
  EVM equivalence test (the one referenced by CLAUDE.md's "Dual-EVM
  Architecture" rule) passes for a Prague-tagged ethereum/tests run.
- `cmd/bsvm/config.go::supportedEVMForks` includes `"prague"`.
- All ethereum/tests at the Prague difficulty level pass for both
  EVMs.
- At least one testnet shard has been rotated to a Prague VK and
  has produced + verified a Prague-fork batch end-to-end.

**Effort estimate**: XL (8-12 weeks elapsed):
- ~2 weeks EIP-7702 in the Go EVM.
- ~2 weeks EIP-2537 (BLS12-381 precompiles) in pure Go.
- ~1 week Rust guest bump + revm version compatibility.
- ~1-2 weeks dual-EVM equivalence testing under Prague.
- ~2 weeks ethereum/tests Prague-level conformance.
- ~1-2 weeks per-shard VK rotation + coordination.

**Dependencies**:
- `docs/decisions/sp1-reproducible-build-2026-05.md` Phase 1 must
  be live so the new guest ELF is deterministic across operators
  (same prerequisite as `WW-upgrade-proof-real-stark`).
- Scoping decision (which Prague EIPs are in scope) must precede
  any code work.

**Suggested owner / next-action**: Whoever owns the EVM extraction
+ the SP1 guest. First hour: write the Prague-EIP scoping note —
read EIPs 7702, 2537, 6110, 7002, 7251, 7549, 7685 with a "is this
relevant to a BSV-anchored L2 with no validator economy?" filter,
and produce a one-page recommendation. Land that as a sibling
decision doc before any code work. Then file an upstream issue
against the chosen pure-Go BLS12-381 library to confirm it's
maintained and CGO-free.

---

## Hook: `BSV-precompiles-activation`

**Status**: deferred (XL-scope)

**One-liner**: Implement the live `BSV_VERIFY_TX` (0x80),
`BSV_VERIFY_SCRIPT` (0x81), and `BSV_BLOCK_HASH` (0x82) precompiles
that today stub-revert with `ErrBSVPrecompileNotActive`, including
the host-side data-injection mechanism the SP1 guest needs to
consult BSV-chain state from inside the zkVM (which has no network).

**Why deferred**:
- The hard problem is not the Go EVM side — it's the Rust SP1 guest
  side. The SP1 zkVM is hermetic: the guest program has no network
  access, no filesystem, no syscalls beyond the SP1 syscall set.
  Yet the live precompile implementations need to consult BSV-chain
  state (a BSV transaction, its Merkle proof, a BSV block hash by
  height). The guest cannot fetch any of that on its own.
- The mechanism this requires is "host-side data injection": the
  prover (running on a node with BSV connectivity) feeds the
  required SPV proof bundle into the guest as part of `BatchInput`,
  the guest verifies the bundle against an authenticated BSV-chain
  oracle (e.g., a header chain commitment baked into `BatchInput`),
  and the precompile uses the verified data to answer the call.
  None of this infrastructure exists today.
- Determinism requirement: the same EVM transaction calling
  `BSV_VERIFY_TX` must produce identical output across the Go EVM
  (running in the overlay node) and the Rust SP1 guest (running
  inside the proof). If the Go EVM consults a live BSV node and
  the SP1 guest consults a host-injected SPV proof, the two paths
  must agree byte-for-byte. This requires:
  - A canonical SPV-proof format that both EVMs accept.
  - A canonical BSV block-hash oracle format the guest can verify.
  - Reorg handling: what happens if the Go EVM saw a BSV tx at
    block height H but by the time the proof is generated, the BSV
    chain has reorged that tx out? The current spec is silent.
- Spec 01 §"Custom BSV Precompiles" (`spec/01-EVM-EXTRACTION.md:470-519`)
  reserves the address range and pins the input/output formats but
  is explicit (line 484-489 + line 518-519) that live implementations
  ship under this hook.
- The on-chain `Mode 1` covenant verifies the SP1 proof but does
  NOT verify the SPV bundle the guest consumed — that bundle's
  validity must be self-contained inside the guest (proven against
  a Bitcoin-header oracle that the guest also verifies internally).
  Designing that oracle is the load-bearing piece of work.

**What shipping requires**:
- Spec extension: add §"BSV-Chain Oracle" to spec 12 describing how
  the SP1 guest authenticates BSV-chain data. Likely a Bitcoin-
  header chain commitment baked into `BatchInput.bsv_header_root`
  + a guest-side header verifier that walks proof-of-work back to
  a hard-coded checkpoint. This is a non-trivial design problem in
  its own right.
- Reorg policy: define what the precompile returns when the BSV
  tx the EVM contract is asking about has been reorged out. Likely
  options: (a) revert with a specific error code, (b) return
  zero/false. Document the choice.
- Wire the host bridge to gather, for each precompile call in a
  batch, the relevant SPV proof + header chain data and inject it
  into `BatchInput` as a per-tx witness bundle.
- Implement the live Go-side precompiles in `pkg/vm/contracts.go`
  to replace `stubBSVPrecompile` (lines 746-760). The Go EVM
  consults a live BSV node directly; the SP1 guest consults the
  injected witness bundle. Both must produce identical outputs.
- Implement the matching Rust-side precompile handlers in
  `prover/guest/src/`. These verify the injected witness bundle
  against the in-`BatchInput` BSV-header commitment, then return
  the same bytes the Go EVM returned.
- Differential test in `pkg/prover/dual_evm_test.go`: a fixture
  contract calls each precompile with known inputs; both EVMs
  must return identical bytes.
- Update spec 01 §"Custom BSV Precompiles" to remove the "reserved
  in v1" wording for the three activated addresses and document
  the input witness format.
- Bump the `IsBSVM` rule in `pkg/vm/contracts.go:92-96` to register
  the live precompile types instead of stubs (or, for a phased
  rollout, register live precompiles only when a chain-config flag
  `BSVPrecompilesActive` is set, defaulting to false).

**Cross-cutting impacts**:
- Subsystems touched: `pkg/vm/contracts.go` (live precompile
  implementations), `pkg/vm/config.go` (new `BSVPrecompilesActive`
  rule), `prover/guest/src/main.rs` + new `prover/guest/src/bsv_*.rs`
  modules (Rust-side precompile handlers + header verifier),
  `pkg/prover/host.go` (witness-bundle gathering during proof
  generation), `pkg/state/` or `pkg/block/` (BSV-header chain
  storage), `spec/01-EVM-EXTRACTION.md`, `spec/12-STATE-TRANSITION-PROOFS.md`
  (new oracle section).
- VK rotation required: **YES**. Guest source change rotates the
  VK; all live shards need to rotate.
- Covenant rotation required: **YES** (the VK rotation IS a
  covenant rotation). Plus, if the design includes a header-chain
  checkpoint baked into the guest, every guest re-deployment
  needs to forward-roll the checkpoint.
- Changes in runar-go: **POSSIBLY**. If the design needs new
  `runar.VerifyBSVHeader` / `runar.VerifyMerkleProof` primitives
  on-chain (i.e. the on-chain covenant does any cross-checking of
  what the guest committed vs. live BSV state), then yes — but
  the natural design keeps all BSV verification inside the guest
  and has the on-chain covenant only verify the resulting STARK,
  in which case no runar-go change is needed. **Uncertain** —
  flagging honestly.
- Spec drift: spec 01 already names the hook; spec 12 is silent
  on the oracle design. Both need updates as part of closing.
- Ecosystem effect: once this hook ships, BSV-aware Solidity
  contracts become possible. This is the single biggest "BSVM is
  not just an L2, it is THE L2 for BSV-aware applications"
  unlock. Worth flagging that the value of shipping is
  asymmetrically high.

**Operator interim**:
- The three precompiles continue to revert with
  `ErrBSVPrecompileNotActive` and consume gas proportional to
  input length. This matches the spec 01 §"Before implementation"
  contract.
- Per the triage doc Claim 5 §"Mainnet blast radius": the failure
  mode is contract-developer-facing, not node-correctness-facing.
  A Solidity contract that calls `address(0x80)` reverts loudly
  and with an explicit error rather than silently returning zero
  data. That is exactly the right behaviour.
- Document in the operator README and in the developer-facing
  contract-deployment guide that addresses 0x80-0x82 are
  reserved-but-inactive in v1. Authors who want to write BSV-aware
  contracts can target the spec-pinned input/output formats
  speculatively (the addresses won't move) but the contracts will
  not work end-to-end until this hook ships.
- DO NOT remove the stubs prematurely. The triage doc Claim 5
  §"Notes for the operator" is explicit on this point.

**Acceptance criteria**:
- `pkg/vm/contracts.go` registers live precompile implementations
  for 0x80, 0x81, 0x82 (replacing `stubBSVPrecompile`).
- The Rust SP1 guest implements matching handlers that verify a
  host-injected SPV-witness bundle against a guest-internal
  BSV-header oracle.
- Differential test in `pkg/prover/dual_evm_test.go` (or sibling)
  passes: a fixture contract calls each precompile with known
  inputs and both EVMs return byte-identical output.
- Spec 01 §"Custom BSV Precompiles" no longer carries the "reserved
  in v1" wording for the three live addresses; spec 12 has a new
  §"BSV-Chain Oracle" section pinning the witness format.
- At least one shard has accepted a batch on-chain whose proof
  commits a successful precompile call.

**Effort estimate**: XL (12-16 weeks elapsed):
- ~3-4 weeks BSV-header oracle design + spec sign-off.
- ~2-3 weeks Go-side live precompile implementations + tests.
- ~3-4 weeks Rust-side guest precompile handlers + header verifier.
- ~2 weeks witness-bundle plumbing in the host bridge.
- ~2 weeks dual-EVM differential testing.
- ~1-2 weeks per-shard VK rotation + coordination.

**Dependencies**:
- `docs/decisions/sp1-reproducible-build-2026-05.md` Phase 1 must
  be live (same prereq as the other guest-changing hooks).
- Spec 12 §"BSV-Chain Oracle" must be written and reviewed before
  any guest code work.
- (Optional) `WW-prague-fork-bump` could land first or in
  parallel; the two are orthogonal except both rotate the VK,
  and an operator who wants to minimise rotation events would
  want to land them together.

**Suggested owner / next-action**: Whoever owns the SP1 guest +
the BSV-bridge integration. First hour: write a one-page design
note answering the four critical questions:
(1) header-oracle authentication (PoW chain checkpoint? committee?
something else?), (2) reorg policy (revert vs return-zero?),
(3) witness-bundle wire format, (4) on-chain vs in-guest
verification split. Land it as a sibling decision doc before any
code work begins.

---

## Aggregate ranking

Sorted by (mainnet blast radius × scope), highest priority first.
"Blast radius" here is "what is at risk on mainnet if we never
close this hook"; scope is the elapsed-weeks effort estimate.
Both axes are subjective; this ordering is the one reasonable
interpretation, not the only one.

| Rank | Hook | Blast radius | Scope | Why this rank |
|------|------|--------------|-------|----------------|
| 1 | `WW-upgrade-proof-real-stark` | **High** | XL (4-8w) | A mainnet shard whose VK ever needs to rotate (e.g., to patch a covenant bug, to bump the SP1 toolchain, or to land any other guest change) **cannot** rotate today. Synthetic proofs are rejected on-chain. This is the difference between "shard is upgradeable" and "shard is permanently frozen at v1". The chicken-and-egg coordination problem makes the work itself non-trivial. |
| 2 | `BSV-precompiles-activation` | **Medium-High** | XL (12-16w) | Without this hook, BSVM is "an L2 that happens to run on BSV" rather than "the L2 for BSV-aware applications". The mainnet failure mode is a class of contracts that never gets written. Not a correctness bug, but a strategic one. The XL scope reflects the genuinely-novel host-injection design work. |
| 3 | `WW-prague-fork-bump` | **Medium** | XL (8-12w) | Cosmetic-but-real. Third-party tooling assuming Prague will be surprised. Mainnet contracts targeting `--evm-version prague` (specifically EIP-7702 delegated calls) revert. The runtime fork guard makes the failure loud, but the developer-experience tax is real. |
| 4 | `WW-anf-runar` | **Low** | L (≤1mo, mostly upstream) | The in-tree emitter is a working substitute that produces stable canonical output. Nothing breaks on mainnet if this never closes; it is purely a code-architecture cleanup deferred until upstream catches up. Lowest urgency because the in-tree emitter is the contract today and its hash output is on-chain forever already. |

Note that the rank order is dominated by "can the shard upgrade?"
(`WW-upgrade-proof-real-stark`) — that is the single hook with a
real mainnet-correctness blast. The other three are
roadmap/strategic items.

## What we'd need to commit to before mainnet

**Required-before-mainnet** (must close before any value-bearing
shard goes live):

* `WW-upgrade-proof-real-stark` — **REQUIRED.** A shard that
  cannot rotate its VK is a shard that cannot patch any future
  bug in the covenant, the guest, the host bridge, or the SP1
  toolchain. That is not an acceptable mainnet posture for a
  shard that holds real BSV. The synthetic-proof workaround is
  fine for testnet rehearsal but disqualifying for mainnet. This
  hook's XL effort estimate is the principal mainnet-readiness
  gating item among the four.

**Can-be-post-mainnet** (acceptable to defer past a v1 launch
of value-bearing shards):

* `BSV-precompiles-activation` — **DEFER OK.** The stubs are
  loud-and-correct (revert with a typed error). v1 shards launch
  without BSV-aware precompiles; that is documented to contract
  authors and to operators. Closing this hook later is purely
  additive — it unlocks new contract use-cases without breaking
  any existing ones.
* `WW-prague-fork-bump` — **DEFER OK.** v1 launches Cancun. Spec
  01 already labels the chain as Cancun-only (`spec/01-EVM-EXTRACTION.md:11-23`).
  The runtime fork guard refuses to start a node configured for
  Prague (`cmd/bsvm/config.go:118-121`). Contract authors
  targeting BSVM compile with `--evm-version cancun`. Deferring
  past mainnet imposes a known cost (no EIP-7702, no BLS12-381
  precompiles for L2 contracts) but no correctness risk.
* `WW-anf-runar` — **DEFER OK.** The in-tree emitter is the
  contract; closing the hook is a code-architecture cleanup
  that does not change observable behaviour. Track it as a
  long-tail upstream-blocked item.

**Therefore the mainnet-readiness subset is exactly one of these
four hooks**: `WW-upgrade-proof-real-stark`. Closing it before
mainnet is the only one of the four that is non-negotiable. The
other three can each ship in a post-v1 release without blocking
launch, provided we are honest about each deferred capability in
the operator-facing docs and the developer-facing chain spec.
