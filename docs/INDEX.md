# BSVM Documentation Index

This index categorises the per-decision and per-subsystem documents
under `docs/`. The numbered specifications under `spec/` are the
primary architectural reference (specs 10–17 win on conflict); the
documents linked here record session-specific decisions, audits, and
empirical results that shaped the live tree.

For reference, the spec set:

- [spec/00-PROJECT-OVERVIEW.md](../spec/00-PROJECT-OVERVIEW.md)
- [spec/01-EVM-EXTRACTION.md](../spec/01-EVM-EXTRACTION.md)
- [spec/02-STATE-DB.md](../spec/02-STATE-DB.md)
- [spec/03-BLOCK-ENGINE.md](../spec/03-BLOCK-ENGINE.md)
- [spec/04-BSV-ANCHOR.md](../spec/04-BSV-ANCHOR.md) (superseded by spec 10)
- [spec/05-RPC-GATEWAY.md](../spec/05-RPC-GATEWAY.md)
- [spec/06-SEQUENCER.md](../spec/06-SEQUENCER.md) (superseded by spec 11)
- [spec/07-BRIDGE.md](../spec/07-BRIDGE.md)
- [spec/08-GENESIS-AND-NODE.md](../spec/08-GENESIS-AND-NODE.md)
- [spec/09-IMPLEMENTATION-ORDER.md](../spec/09-IMPLEMENTATION-ORDER.md)
- [spec/10-DEEP-BSV-INTEGRATION.md](../spec/10-DEEP-BSV-INTEGRATION.md)
- [spec/11-BSV-OVERLAY.md](../spec/11-BSV-OVERLAY.md)
- [spec/12-STATE-TRANSITION-PROOFS.md](../spec/12-STATE-TRANSITION-PROOFS.md)
- [spec/13-RUNAR-REQUIREMENTS.md](../spec/13-RUNAR-REQUIREMENTS.md)
- [spec/15-EXPLORER-ADMIN-UI.md](../spec/15-EXPLORER-ADMIN-UI.md)
- [spec/16-DEVNET.md](../spec/16-DEVNET.md)
- [spec/17-CHAINTRACKS-BEEF-ARC.md](../spec/17-CHAINTRACKS-BEEF-ARC.md)

(Specs 14 is intentionally absent.)

---

## Architecture and design

- [decisions/U-spec-drift-audit.md](decisions/U-spec-drift-audit.md) —
  Per-spec audit (00–17) of where shipped code has drifted from the
  written spec. Severity-graded; flags which specs need rewrites
  before the next milestone vs which are merely cosmetically stale.
- [decisions/U-runar-api-pinning.md](decisions/U-runar-api-pinning.md) —
  Pinned versions of `runar/compilers/go`, `runar-go`, and the
  `runar-integration` local-replace target; smoke-check showing the
  Rúnar surface that the covenant and FRI verifier compile against.
- [decisions/U-toolchain-pin-strategy.md](decisions/U-toolchain-pin-strategy.md) —
  Strategy for the SP1 guest's Rust nightly pin
  (`nightly-2025-10-01`), the mirror-snapshot mitigation, and CI
  recovery procedure when nightlies age out of upstream mirrors.
- [decisions/U-testdata-submodule.md](decisions/U-testdata-submodule.md) —
  Investigation into `test/evmtest/testdata` showing it as a git
  gitlink (mode 160000) without a committed `.gitmodules` mapping.
  Repository hygiene issue, not a code bug.

## Bridge and withdrawals

- [decisions/S-withdrawal-and-rollback.md](decisions/S-withdrawal-and-rollback.md) —
  Audit of the spec-07 withdrawal pipeline (L2 burn, withdrawal hash,
  Merkle commitment, claim-tx construction) against the live tree;
  scopes the L2 rollback hook needed when a covenant advance is
  reorged out.
- [decisions/II-withdrawal-nonce-convention.md](decisions/II-withdrawal-nonce-convention.md) —
  Off-by-one alignment fix between `ApplyWithdrawTx` (emits first
  withdrawal at `nonce = 0`) and the bridge claimer's gate (expected
  first acceptable nonce to be `1`). Records the chosen 0-indexed
  convention.
- [decisions/beef-graph-validation.md](decisions/beef-graph-validation.md) —
  W6-4 design for full BRC-62 BEEF graph reconstruction plus
  Bitcoin-Script re-execution on bridge deposits, replacing the prior
  fail-closed `accept_unverified_bridge_deposits` gate.

## Prover and EVM

- [decisions/CC-vk-rotation-2026-04.md](decisions/CC-vk-rotation-2026-04.md) —
  SP1 verifying-key rotation (2026-04) triggered by a missing
  `tx_type` field in the guest's `revm::context::TxEnv`, which
  mis-priced EIP-2930 / EIP-1559 / EIP-4844 transactions and changed
  the post-state root the guest committed.
- [decisions/vk-rotation-wire-format-2026-04.md](decisions/vk-rotation-wire-format-2026-04.md) —
  SP1 verifying-key rotation (2026-04) triggered by a bincode
  wire-format mismatch between host and guest (`alloy_primitives`
  defaulted to length-prefixed bytes, host wrote raw fixed arrays);
  also surfaces the SP1 ELF non-determinism caveat.
- [decisions/sp1-reproducible-build-2026-05.md](decisions/sp1-reproducible-build-2026-05.md) —
  Strategy + measured A/B verdict for switching `prover/host-*/build.rs`
  to `BuildArgs { docker: true }` so the SP1 guest ELF is bit-identical
  across operators. Phase 1 (docker-mode flip + sha256 sidecar +
  CI gate) landed 2026-05-03.
- [operator/sp1-build.md](operator/sp1-build.md) — Operator-side
  workflow for building and verifying the SP1 guest ELF: docker
  prerequisites, expected wall-clock, sha256/VK verification, restamp
  procedure when the guest source legitimately changes.
- [decisions/P-versioned-hash-audit.md](decisions/P-versioned-hash-audit.md) —
  Audit of the EIP-4844 versioned-hash `0x01` prefix check on the
  point-evaluation precompile (address `0x0a`); concludes the check
  is functionally equivalent via the equality between the supplied
  hash and the freshly recomputed `kzgVersionedHash(commitment)`.
- [decisions/inbox-drain.md](decisions/inbox-drain.md) — W4-3 SP1
  guest implementation of the on-chain inbox drain (forced-inclusion
  censorship resistance): reconstructs the inbox hash chain from the
  full ordered queue, asserts equality with the committed
  `inboxRootBefore`, applies the leading `drain_count` entries via
  revm, and commits the carry-forward `inboxRootAfter`.

Empirical SP1 / proof artefacts (top-level `docs/`, not under
`decisions/`):

- [sp1-proof-format.md](sp1-proof-format.md) — SP1 v6 proof-format
  documentation captured during Gate 0b (steps 1–3).
- [sp1-fri-parameters.md](sp1-fri-parameters.md) — Captured FRI
  parameters from Gate 0b. Note: documents v4 BabyBear+FRI
  parameters; SP1 v6 uses KoalaBear + StackedBasefold. Treat as
  historical reference; spec 13 is authoritative for the live
  KoalaBear/Poseidon2 setup.
- [sp1-evm-proof-metrics.md](sp1-evm-proof-metrics.md) — Gate 0b
  step 4 metrics from a simplified balance-transfer guest (not the
  full revm guest).
- [gate0-results.md](gate0-results.md) — End-to-end Gate 0 PASS
  result: real SP1 v6 Groth16 proof verified on BSV regtest via the
  Rúnar witness-assisted Groth16 verifier, with positive and
  negative tests both passing.

## Network and BSV integration

- [decisions/header-oracle-quorum.md](decisions/header-oracle-quorum.md) —
  W6-2 design for multi-upstream Block Headers Service (BHS) /
  chaintracks quorum. Defines hybrid weighted-and-floor voting,
  disagreement actions (log / drop / halt), and the
  `[bsv.chaintracks]` config block exposed in `bsvm.example.toml`.
- [decisions/W6-7-runar-broadcast-status.md](decisions/W6-7-runar-broadcast-status.md) —
  Triage finding: `pkg/covenant/runar_broadcast.go` is
  actively-used (the BSV covenant-advance broadcaster), not a legacy
  file the ARC client supersedes. No action required.

## Roadmap and miscellaneous

No documents currently sit outside the categories above. Future
session decisions should land under `docs/decisions/` and be linked
from the appropriate section here.

---

## How to use this index

- **Tracking a spec drift?** Start with `U-spec-drift-audit.md` and
  the relevant `spec/NN-*.md`.
- **Operating a node?** `operational-runbook.md` is the prescriptive
  walkthrough; `deploy/testnet/README.md` boots a real testnet node;
  per-subsystem decision docs explain the *why* behind config knobs.
- **Modifying the prover?** Re-check `CC-vk-rotation-2026-04.md`
  before editing the SP1 guest; verifying-key rotations require
  coordinated changes to the pinned `SP1VerifyingKeyHash` in the
  covenant.
- **Modifying the bridge?** `S-withdrawal-and-rollback.md`,
  `II-withdrawal-nonce-convention.md`, and `beef-graph-validation.md`
  together cover the deposit, withdrawal, and reorg paths.

When a decision is superseded, update the entry above with a
"Note: superseded by …" pointer rather than deleting it; the original
decision text is the audit trail.
