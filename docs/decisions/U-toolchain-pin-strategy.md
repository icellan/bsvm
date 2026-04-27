# U: Rust Toolchain Pin Replay + CI Strategy

Author: agent-a5a853b4cf5c1dec5 (U-toolchain-pin-strategy)
Date: 2026-04-26
Branch: `worktree-agent-a5a853b4cf5c1dec5`

## The pin

`prover/guest/rust-toolchain.toml`:

```toml
[toolchain]
channel = "nightly-2025-10-01"
components = ["llvm-tools", "rustc-dev", "rustfmt"]
targets = ["riscv64imac-unknown-none-elf"]
```

Bumped this session by agent M.

## The problem

Nightly Rust toolchains are not preserved indefinitely. The
`https://static.rust-lang.org/dist/<date>/...` mirrors keep nightlies
for the rolling window the Rust project chooses to host. Older
nightlies become harder to install via `rustup` after roughly 6–12
months; `rustup toolchain install nightly-2025-10-01` may succeed
today, may print "no manifest" 12 months from now without warning.

Two failure modes:

1. **Cold build, 12+ months on**: An operator clones bsvm, runs
   `cargo prove build` inside `prover/guest/`, rustup tries to
   install `nightly-2025-10-01`, the manifest 404s. The build is
   stuck until either (a) the pin is bumped (which requires
   re-validating the SP1 build against the new nightly) or (b) the
   exact archived toolchain is found and installed manually.
2. **Reproducibility**: An auditor wants to reproduce a release
   binary's SHA-256. They need the **exact** nightly. If it's
   unavailable, they can't reproduce.

This applies only to the guest crate (`prover/guest/`). Host crates
(`prover/host/`, `prover/host-bridge/`, `prover/host-evm/`) build on
stable and are not affected.

## Why nightly is required

The SP1 zkVM guest needs:

- `riscv64imac-unknown-none-elf` target (must be installable; stable
  doesn't ship the `rustc-dev` and `llvm-tools` for this target).
- Specific `rustc-dev` + `llvm-tools` components — these are
  nightly-only.
- A nightly that matches what SP1 v6.0.2 was built / tested against.

Switching the guest to stable is **not** an option; it would require
an SP1 redesign upstream. The pin is structurally necessary.

## Mitigation strategy

Three layers, in increasing assurance:

### Layer 1: CI pinning (eliminates daily exposure)

CI must install the exact pinned nightly on every guest-touching run.
Today, `.github/workflows/rust-check.yml` only runs `cargo fmt
--check` and `cargo metadata` against host crates using stable Rust
(`dtolnay/rust-toolchain@stable`). Guest is **not** built or even
metadata-checked in CI today. Recommendation: add a workflow that
installs the exact nightly via the toolchain file and runs at least
`cargo metadata` + a target-install smoke check, so a missing-mirror
breakage is caught in CI on the day it happens, not by a developer
two months later.

### Layer 2: Mirror snapshot (insurance for slow rot)

Snapshot the Rust dist artifacts for `nightly-2025-10-01` to a
project-controlled mirror **once**, while they are still available
upstream. Two cheap options:

- **GitHub release assets**: Tar up the rustup-installed toolchain
  and attach to a `toolchain-2025-10-01` release of the bsvm repo.
  Document the install path in the README. ~2 GB of artifacts; well
  under GitHub's per-asset limit.
- **S3 / R2 bucket**: Same artifacts, longer-term ownership, costs
  pennies per month at this size.

Set rustup's `RUSTUP_DIST_SERVER` env var to the mirror URL when the
upstream manifest disappears. Both options use the same protocol
(HTTPS + the rustup manifest layout); rustup mirrors are
well-supported.

This insurance is **only worth taking once** — capture the toolchain
artifacts before they age out of the upstream mirrors.

### Layer 3: Periodic bumps (forces re-validation)

Schedule guest-toolchain bumps every ~6 months. Each bump:

1. Pick a new nightly (typically aligned with what SP1 v6.x.y is
   testing against — read SP1's `rust-toolchain.toml` upstream).
2. Update `prover/guest/rust-toolchain.toml`.
3. Rebuild the SP1 guest, re-derive the verifying key, confirm proof
   format is unchanged (or, if changed, follow the spec 12 SP1
   version-upgrade policy with covenant migration).
4. Document the bump in `docs/decisions/`.

Periodic bumps have a side-benefit: they keep the guest aligned with
SP1's own moving toolchain target, which reduces the frog-boil risk
of getting stranded on a wildly-old nightly.

## Concrete CI: pinning workflow

A draft workflow file is provided at:

`.github/workflows/rust-toolchain.yml.draft`

This file is **not active** (the `.draft` suffix). Operator can
review, rename to `.yml`, and commit when ready.

The draft does:

1. Triggers on push/PR that touches `prover/guest/**` or the
   workflow itself.
2. Reads `prover/guest/rust-toolchain.toml` directly — no duplication
   of the pin in the workflow YAML; the toolchain file is the single
   source of truth.
3. Installs the pinned nightly via `dtolnay/rust-toolchain` action,
   with the `riscv64imac-unknown-none-elf` target and the
   `llvm-tools, rustc-dev, rustfmt` components.
4. Runs `cargo metadata --locked` against `prover/guest/` to
   exercise the pin without paying for a full proving build.
5. Caches `~/.cargo/registry` and `~/.rustup` so subsequent runs are
   fast.
6. Fails CI immediately if the pinned nightly cannot be installed —
   this is the early-warning signal that the pin has rotted.

The full guest build (`cargo prove build` → produces the SP1 guest
ELF) is intentionally NOT part of PR-gate CI for the same reason
`rust-check.yml` excludes host builds: it pulls multi-GB toolchain +
SP1 runtime artifacts and is too slow for every push. A weekly
`workflow_dispatch` job that runs the full build on a beefier
runner is the right home for that — out of scope for this draft.

## Operator runbook (months from now)

If `rustup toolchain install nightly-2025-10-01` fails:

1. **Check the project mirror first** (Layer 2 above). Set
   `RUSTUP_DIST_SERVER=<mirror-url>` and retry. If the mirror was
   set up, this is the happy path.
2. **Check the rust-lang archive** at
   `https://static.rust-lang.org/dist/2025-10-01/`. Sometimes the
   manifest is missing but the per-component tarballs are still
   available; you can reconstruct a manual install.
3. **Use a Docker image** that captured the toolchain. The
   bsvm-prover Docker image at the time of the release should have
   the toolchain baked in; pull that exact tag and use it as the
   reproducible build environment.
4. **Fall back to "best-known-good newer nightly"** documented in
   the bumps log. This re-runs the verifier-key change ceremony — it
   is NOT a transparent fix.

## Recommendations summary

| Action | Owner | When |
|--------|-------|------|
| Snapshot `nightly-2025-10-01` to project mirror | Operator (one-time) | Now, while still available upstream |
| Add CI workflow that installs the pinned nightly | Operator | Next CI sweep — draft attached |
| Schedule 6-month toolchain bump cycle | Project | Add to roadmap |
| Document mirror URL + recovery in README | Project | When mirror is created |

## Action taken in this commit

1. Wrote this decision document.
2. Wrote a draft CI workflow at
   `.github/workflows/rust-toolchain.yml.draft` (NOT active —
   operator must rename `.draft` → empty suffix and commit when
   ready).

No changes to live CI. No changes to `prover/guest/rust-toolchain.toml`.
No changes to any source.
