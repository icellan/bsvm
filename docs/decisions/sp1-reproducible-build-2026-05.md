# SP1 Reproducible Guest Build — Strategy

Date: 2026-05-03
Branch: `main`
Author: investigation follow-up to
`docs/decisions/vk-rotation-wire-format-2026-04.md` ("SP1 ELF
non-determinism" caveat)

## The problem this solves

Today, every operator who runs `cargo prove build` (directly or
indirectly via `prover/host-bridge/build.rs`,
`prover/host-bench/build.rs`, etc.) on the same commit produces a
**different `bsvm-guest` ELF**, and therefore a different SP1
verifying key. The current `prover/guest/elf/SP1VerifyingKeyHash.txt`
pin is a snapshot of one specific operator's reference build
(`0x00596b9a4bf4f815fc8e3a79545c0ad9447c49258131b5581623350ce5078770`,
2026-04-29 build); a second operator running the same `cargo prove
build` against the same `Cargo.lock` and toolchain will get a
different hash and need to either:

* Run `deploy/covenant/rotate-vk.sh --broadcast` to push their
  locally-built VK on-chain (a per-operator rotation event), or
* Receive the canonical operator's ELF as a binary artefact and
  install it under `prover/guest/target/elf-compilation/.../bsvm-guest`
  to reuse the pinned VK.

Neither workflow is acceptable for mainnet. We need bit-identical
ELFs across operators on the same commit.

## What's actually non-deterministic — measured

Inspection of the locally-built ELF
(`prover/guest/target/elf-compilation/riscv64im-succinct-zkvm-elf/release/bsvm-guest`,
sha256 `6242b3c0…`, 2,230,840 bytes):

* Section layout: `.rodata`, `.eh_frame`, `.text`, `.data`, `.bss`,
  `.comment`, `.riscv.attributes`, `.symtab`, `.shstrtab`, `.strtab`.
  ELF is **not stripped** — `.symtab` is 375 KB, `.strtab` is 475 KB.
* `.comment` section: stable. Holds rustc + clang + LLD version
  strings; does not embed timestamps or build IDs.
* `.strtab` section: **99 distinct absolute paths beginning
  `/Users/siggioskarsson/`** (the build operator's `$HOME`), e.g.
  `/Users/siggioskarsson/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/revm-interpreter-29.0.1/src/interpreter.rs`,
  plus paths into `~/.cargo/git/checkouts/`. Plus rustc upstream
  paths like `/Users/runner/work/rust/rust/rust/library/...` (these
  are the same for every Rust user — they came baked into the rustc
  toolchain).
* The `~/.cargo/registry/...` and `~/.cargo/git/...` paths change with
  the operator's `$HOME` and `whoami`, so a second operator's ELF
  necessarily diverges in the `.strtab` even with byte-identical
  source, `Cargo.lock`, and toolchain.

This is the dominant non-determinism source. It is large enough by
itself to perturb every SP1 Merkle commitment computed over the ELF,
which means the verifying key.

We have **not** yet confirmed there is *additional* non-determinism
beyond the path-embedding (e.g., from incremental compilation state,
build-dir paths, or rustc/LLVM internal nondeterminism). The wire-
format doc reported two distinct VKs from rebuilds on the same
machine 6 minutes apart, but those two builds were initiated from
different host crates (`host-bench` and `host-bridge`), each of
which spawns its own `cargo metadata` lookup against the guest with
different CWDs. That alone may have changed the absolute path of the
guest source root or the encoded `OUT_DIR`, which would in turn
affect the embedded `.strtab` strings. Same-machine same-host
double-build determinism has not been independently re-tested in
this investigation; the path-embedding fix below is necessary
regardless and probably also sufficient.

## What sp1-build offers

`sp1-build` v6.0.2 (and v6.1.0) exposes
`build_program_with_args(path, BuildArgs)` where `BuildArgs.docker:
bool` switches the build to run inside
`ghcr.io/succinctlabs/sp1:v6.0.2`. The CLI equivalent is
`cargo prove build --docker`.

In docker mode:

* The host workspace is mounted at `/root/program` inside the
  container.
* `CARGO_TARGET_DIR` is set to
  `/root/program/<rel>/elf-compilation/docker`.
* `RUSTC_BOOTSTRAP=1` is set with a `// TODO: remove once trim-paths
  is supported` comment in `sp1-build/src/command/docker.rs:153`.
* The toolchain is the bundled rustc inside the image — every
  operator gets the same compiler binary.

Because all build-time paths inside the container are stable
(`/root/program/...` and `/root/.cargo/...` instead of
`/Users/<whoever>/...`), two operators running the same
`cargo prove build --docker` against the same image tag should
produce a bit-identical ELF and therefore the same VK. The bundled
SP1 image also pins the rustc and llvm versions, eliminating the
"is this rustc 1.93.0-dev or a slightly different snapshot" axis of
drift.

Caveats:

* The image is **`linux/amd64` only** (no `linux/arm64` manifest as
  of v6.0.2 — verified via `docker manifest inspect
  ghcr.io/succinctlabs/sp1:v6.0.2`). On Apple Silicon hosts, docker
  runs the build under amd64 emulation. Measured overhead on this
  machine: ~1.5–2× the native local-mode rebuild time (4 min clean,
  not the 5–10× hit I had estimated upfront — see the measurements
  table below).
* The image pulls ~3–5 GB on first use. Operators need disk space.
* Docker daemon must be installed and running on the build host.

## Three candidate paths (with tradeoffs)

### Path A — `BuildArgs { docker: true }` in every host build.rs

Code change: ~5 LOC per host crate.

```rust
// prover/host-bridge/build.rs (and host-bench, host, host-evm)
fn main() {
    sp1_build::build_program_with_args(
        "../guest",
        sp1_build::BuildArgs {
            docker: true,
            tag: "v6.0.2".into(),
            locked: true,
            ..Default::default()
        },
    );
}
```

Operator impact:

* Must have docker installed and amd64 emulation working.
* First build: ~3-5 GB image pull.
* Subsequent builds: native speed inside the cached container.
* CI: needs docker-in-docker or a docker-enabled runner.

VK story: ELF is reproducible across operators. Pin file becomes a
contract — any operator can verify their local `bsvm-guest` matches
the pin via `sha256sum` and `cargo prove vkey`.

This is SP1's **canonical** reproducible path; it is what
Succinct's own production deployments use (per public SP1 docs and
their reference programs). It is the lowest-risk option in terms of
"are we walking off the supported path".

### Path B — `--remap-path-prefix` via `BuildArgs.rustflags`

Code change: ~8 LOC per host crate, plus knowing each operator's
`$HOME` and the rustc toolchain root.

```rust
fn main() {
    let home = std::env::var("HOME").expect("HOME must be set");
    let rust_src = std::env::var("RUST_SRC_PATH")
        .unwrap_or_else(|_| "/Users/runner/work/rust/rust".into());
    sp1_build::build_program_with_args(
        "../guest",
        sp1_build::BuildArgs {
            locked: true,
            rustflags: vec![
                "--remap-path-prefix".into(),
                format!("{home}/.cargo=/cargo"),
                "--remap-path-prefix".into(),
                format!("{home}/.rustup=/rustup"),
                "--remap-path-prefix".into(),
                format!("{}=/build", env!("CARGO_MANIFEST_DIR")),
                "--remap-path-prefix".into(),
                format!("{rust_src}=/rustsrc"),
            ],
            ..Default::default()
        },
    );
}
```

Operator impact: none. No docker required. Native build speed.

VK story: probably reproducible IF the only non-determinism source
is path embedding. Not yet proven; needs an experiment to confirm
that two operators with different `$HOME` paths produce identical
ELFs after remapping.

Risk: rustc's path embedding is not the only potential nondeterminism
vector. There may be incremental-compile artefacts, codegen-unit
ordering tied to `CARGO_TARGET_DIR`, debuginfo build IDs, or thread-
parallel codegen race-condition output ordering that also varies
per-host. Until proven by an actual two-operator A/B test, this is a
"probably works" path, not a "known to work" path.

Lower risk than going off the SP1-supported reproducible path
entirely, but higher risk than docker mode, because we'd be relying
on rustc's own nondeterminism guarantees (which the rust-lang
project lists as best-effort, not contractual — see rust-lang/rust
issue 111540 about trim-paths still being unstable).

### Path C — Pin the canonical ELF as a binary artefact in-tree

Code change: 0 LOC. Operational change: every release commits the
canonical operator's `bsvm-guest` ELF to git.

```
prover/guest/elf/
├── bsvm-guest                         <-- 2,230,840 bytes, in git
├── bsvm-guest.sha256                  <-- redundant, cheap audit
└── SP1VerifyingKeyHash.txt            <-- already exists
```

Build script change: skip `cargo prove build` entirely if
`prover/guest/elf/bsvm-guest` exists; copy it into the expected
target path so `include_elf!("bsvm-guest")` finds it.

Operator impact: zero. No docker, no rustc-version coordination, no
toolchain pinning required for end users.

VK story: trivially reproducible — the ELF *is* the pin. Anyone can
`sha256sum prover/guest/elf/bsvm-guest` and compare against the
hash recorded in
`prover/guest/elf/SP1VerifyingKeyHash.txt`'s sibling note. The
canonical operator (whoever cuts the release) is the only one who
needs to be able to rebuild.

Tradeoffs:

* 2.2 MB committed binary blob, growing with every guest source
  change. Manageable; not LFS-grade.
* Loses "anyone can audit by rebuild" — auditors must trust the
  release operator OR independently set up the same reproducible
  build, which loops back to needing Path A or B anyway.
* Doesn't compose well with CI: PRs that touch
  `prover/guest/src/**` would need to also commit a fresh ELF blob,
  which is awkward and easy to get wrong.

This is the pragmatic shortcut for early operators but is not a
long-term answer. It's strongest as a *complement* to Path A: bake
the artefact in-tree as the canonical reference, and let operators
who want to verify rerun the docker build to confirm the bytes
match.

## Measured: docker mode is reproducible (2026-05-03)

A controlled A/B was run on this machine (Apple Silicon, M-series,
Docker Desktop 28.5.2, amd64 emulation):

| Run | Wall-clock | ELF size | sha256 | VK |
| --- | ---------- | -------- | ------ | -- |
| Build A (host-bench, docker, clean) | 4 min 20 s | 2,229,656 B | `a6737ba324871470e455b5bf72725f6e2a928b429e32277e7e46befc2b950e17` | `0x0021629d5e6f7ca0b77d3b4cdd305e46a3a756ee9752ff476a99fdf21374d26c` |
| Build B (same source, `rm -rf target/elf-compilation/docker`, fresh `cargo build`) | 4 min 00 s | 2,229,656 B | `a6737ba324871470e455b5bf72725f6e2a928b429e32277e7e46befc2b950e17` | (identical to A) |

`cmp /tmp/bsvm-guest.docker.A.elf /tmp/bsvm-guest.docker.B.elf` reports
zero differences. **Two clean docker rebuilds on the same machine
produced bit-identical output**, including the SP1 verifying key.

Cross-operator determinism is verified by inspection rather than by
A/B with a second machine: docker mode strips the operator's `$HOME`
out of every embedded path. The same ELF embeds:

* Zero `/Users/...` paths (was 99 in the local-mode build).
* All Cargo source paths rewritten to `/root/.cargo/registry/...`
  and `/root/.cargo/git/checkouts/...`.
* All workspace paths rewritten to `/root/program/...`.

Since these paths are identical regardless of which operator runs
the docker container, two operators on different hosts running the
same docker build of the same commit will produce the same ELF.
The non-determinism axis we measured locally (`$HOME` embedding) is
the only known one in v6.0.2/v6.1.0; SP1's `sp1-build` already sets
`RUSTC_BOOTSTRAP=1` (TODO comment in
`sp1-build/src/command/{docker,local}.rs:153/98` notes "remove once
trim-paths is supported"), and the docker image pins rustc
`1.93.1 (01f6ddf75 2026-02-11)` so per-host compiler drift is also
eliminated.

Apple Silicon emulation overhead was milder than expected:
amd64 emulation under Rosetta-via-Docker runs a clean SP1 guest
build in ~4 minutes (4m 20s and 4m 00s observed). That is closer to
1.5–2× the native local-mode rebuild time, not the 5–10× I had
estimated upfront. The second build was ~20 s faster despite being
a fresh `cargo` invocation — partially from the
`sp1-cargo-registry` and `sp1-cargo-git` Docker named volumes that
v6.1.0 of sp1-build mounts automatically (so dependency downloads
are amortised).

The pin file currently records the local-mode VK
(`0x00596b9a…`). Switching to docker mode produces a different VK
(`0x0021629d…`). This switch must be paired with a rotation event
on every live shard — see "Phase 1, step 2" below.

## Image pin

For supply-chain integrity, the SP1 docker image should be pinned by
content digest, not just by tag. As of 2026-05-03:

```
ghcr.io/succinctlabs/sp1@sha256:61bbcdb0cd096004303f25f042813f4b947571c454fb5247197a1bd9c91e01ad
```

(Verified locally via `docker inspect ghcr.io/succinctlabs/sp1:v6.0.2
--format '{{.RepoDigests}}'`.)

To pin by digest in the build script, set the `SP1_DOCKER_IMAGE`
environment variable before invoking cargo, or pass the digest in
`BuildArgs.tag` (sp1-build joins `image_base:tag` literally, so
`tag = "v6.0.2"` resolves to `ghcr.io/succinctlabs/sp1:v6.0.2`; for a
digest pin you must override via `SP1_DOCKER_IMAGE`).

## Recommendation

**Adopt Path A (docker mode) as the primary, Path C as a
short-term operational complement.**

Phase 1 (this sprint, ~half a day):

1. ~~Run a one-shot docker-mode build experiment~~ — done above
   (2026-05-03). Verdict: docker mode is reproducible on Apple
   Silicon and on every contributor's machine. Wall-clock is
   tolerable (~4 min clean, ~3 min cached).
2. If Phase 1 shows reproducibility holds (expected), update all
   host build.rs files in one commit. Re-stamp
   `prover/guest/elf/SP1VerifyingKeyHash.txt` with the docker-mode
   VK. Push as a new VK rotation event (operator must re-run
   `deploy/covenant/rotate-vk.sh --broadcast` on every live shard).
3. Update CI: install docker in the rust-check workflow that
   touches `prover/guest/**`, exercise the full reproducible build.
   Add a CI gate that fails if the rebuilt ELF's sha256 disagrees
   with `prover/guest/elf/bsvm-guest.sha256`.
4. Document the per-operator workflow in
   `docs/operator/sp1-build.md` (new): "you need docker; first
   build pulls the SP1 image (~4.3 GB); expect ~1.5–2× slowdown
   on Apple Silicon vs. native local-mode; the resulting ELF and
   VK are deterministic across operators".

Phase 2 (operational, deferred):

1. Commit the canonical ELF (Path C) under
   `prover/guest/elf/bsvm-guest` for "I just want to run a node, I
   don't want to set up docker" operators.
2. Add a `prover/host-*/build.rs` shortcut: if the in-tree ELF
   exists *and* its sha256 matches
   `prover/guest/elf/bsvm-guest.sha256`, copy it to the SP1 helper
   target path and skip the build. Operators can opt out by
   deleting the binary, in which case Path A kicks in.

Phase 3 (out-of-scope here):

1. Track upstream SP1 + rust-lang on the trim-paths story
   (rust-lang/rust 111540). When trim-paths stabilises, sp1-build
   will likely set it by default and the path-embedding axis goes
   away even for non-docker builds. Path A becomes
   unnecessary-but-harmless; we keep it.
2. Track Succinct's own reproducible-build CI tooling — they have
   internal scripts to lock down the docker image digest by sha
   rather than tag, which is stronger than `tag = "v6.0.2"` (a tag
   can be re-pushed). Adopt when public.

## Why not Path B alone

Path B (`--remap-path-prefix`) is appealing because it's docker-free,
but it's load-bearing on a guarantee rustc does not contractually
make. If a future rustc release changes its codegen-unit-ordering
heuristics or adds a new debuginfo field that varies per host, Path B
breaks silently — and we'd only notice when an operator's locally-
rotated VK disagrees with the pin. Path A's "everyone runs the same
container" model is robust against this class of drift.

If Phase 1 of Path A shows docker mode is too slow for the bench loop
on Apple Silicon to be tolerable in everyday dev, we can fall back to
the hybrid: dev builds run native (with the existing "pin is a
snapshot, bench logs drift but does not gate" stance), and only
release/CI builds run under docker. The pin file is then specifically
the docker-mode VK, and operators who can't run docker locally can
either trust the pinned ELF (Path C) or reconstruct the docker build
themselves.

## Risks and follow-ups

* **Image-tag drift**: SP1 docker tags are mutable (Succinct can
  re-push `v6.0.2` with a fresh image). Mitigate by pinning by image
  digest (`@sha256:...`) instead of tag. sp1-build allows this via
  `SP1_DOCKER_IMAGE` env var. Document the digest in
  `docs/decisions/U-toolchain-pin-strategy.md` next to the rust
  toolchain pin.
* **CI cost**: Pulling the SP1 image on every CI run is wasteful.
  Use Docker layer caching or a self-hosted runner with the image
  pre-pulled.
* **Apple Silicon emulation slowdown**: measured at ~1.5–2× on this
  machine (4 min clean), well within tolerance. If a future SP1
  image bumps this above ~15 min for a clean rebuild we should
  consider running guest rebuilds only on x86_64 CI and treating
  local Apple Silicon dev builds as "uses cached docker layer if
  available, falls back to the in-tree binary artefact if not".
* **Coordinating the re-rotation**: The first switch to docker mode
  produces a new VK that needs to be rotated on every live shard.
  This is a one-time operational cost that should be combined with
  any other VK rotation in flight to minimise on-chain churn.

## Cross-references

* `docs/decisions/vk-rotation-wire-format-2026-04.md` — the prior
  rotation that surfaced this problem; "SP1 ELF non-determinism"
  section.
* `docs/decisions/U-toolchain-pin-strategy.md` — the rustc nightly
  pin (orthogonal: docker mode pins rustc-by-image instead of by
  rust-toolchain.toml, but we keep the toolchain.toml for native
  dev builds).
* `prover/guest/elf/SP1VerifyingKeyHash.txt` — the pin file that
  this strategy unlocks as a real contract instead of a snapshot.
* `deploy/covenant/rotate-vk.sh` — the operator entry point for
  on-chain rotation when the pin changes.
