# SP1 Guest Build — Operator Workflow

This is the per-operator workflow for building the SP1 guest ELF
(`bsvm-guest`) and verifying its sha256/VK against the in-tree pin.

The build is **reproducible across operators** — every contributor
runs the exact same docker image (pinned in
`prover/host-*/build.rs`) and produces a bit-identical ELF and
verifying key. This is how the on-chain covenant's
`SP1VerifyingKeyHash` pin can be a real contract instead of a
per-operator snapshot.

For background and the path-not-taken rationale, see
`docs/decisions/sp1-reproducible-build-2026-05.md` and
`docs/decisions/vk-rotation-wire-format-2026-04.md`.

## TL;DR

```
$ docker pull ghcr.io/succinctlabs/sp1:v6.0.2     # ~4.3 GB, once
$ cd prover/host-bridge
$ cargo build --release                            # ~2-4 min
$ sha256sum prover/guest/target/elf-compilation/docker/riscv64im-succinct-zkvm-elf/release/bsvm-guest
$ cat prover/guest/elf/bsvm-guest.sha256           # expect a match
$ cat prover/guest/elf/SP1VerifyingKeyHash.txt     # expect to match cargo prove vkey output
```

If the rebuilt ELF's sha256 matches `prover/guest/elf/bsvm-guest.sha256`,
your local build is **identical** to the canonical reference build
the in-tree pin tracks. You can deploy without re-rotating the
covenant's verifying key.

## Prerequisites

* **Docker**, with `--platform linux/amd64` support. On amd64 hosts
  this is native; on Apple Silicon, Docker Desktop's built-in
  emulation handles it transparently.
* **~4.3 GB** of disk for the SP1 image
  (`ghcr.io/succinctlabs/sp1:v6.0.2`, sha256
  `61bbcdb0cd096004303f25f042813f4b947571c454fb5247197a1bd9c91e01ad`).
* **Rust stable**, for the host crate (the guest itself is
  compiled inside the docker container; the host wrapper that
  launches it builds with stable Rust).
* **Optional**, only if you want to verify the VK matches the pin:
  `cargo-prove` (install via `curl -L https://sp1up.succinct.xyz |
  bash && sp1up --version v6.0.2`).

## Wall-clock expectations

Measured 2026-05-03 on Apple Silicon (M-series, Docker Desktop
28.5.2):

| Build phase | Time |
|-------------|------|
| First-ever pull of `ghcr.io/succinctlabs/sp1:v6.0.2` | 1–3 min depending on network |
| Clean guest rebuild via `cargo build` | ~4 min |
| Cached guest rebuild (after wipe of `target/elf-compilation/docker/`) | ~4 min (cargo cache + sp1-cargo named volumes amortise dependency fetches) |
| `cargo build` no-op (guest source unchanged) | < 5 s |

On amd64-native hosts (Linux x86_64, GitHub Actions ubuntu-latest):
no emulation overhead — clean guest rebuild is ~2 min.

If you want fast cargo-check loops without paying the docker cost
on every iteration, set `SP1_SKIP_PROGRAM_BUILD=true` in the
environment before `cargo build`. The build script will skip the
guest rebuild and reuse whatever ELF is already at
`prover/guest/target/elf-compilation/docker/.../bsvm-guest`. This is
fine for code-completion and Rust analysis but is **not** a valid
mode for actually running the prover, since you risk shipping an
out-of-date ELF.

## How to verify your local build matches the pin

After `cargo build` completes:

```
$ ELF=prover/guest/target/elf-compilation/docker/riscv64im-succinct-zkvm-elf/release/bsvm-guest
$ sha256sum "$ELF"
a6737ba324871470e455b5bf72725f6e2a928b429e32277e7e46befc2b950e17  ...

$ awk '{print $1}' prover/guest/elf/bsvm-guest.sha256
a6737ba324871470e455b5bf72725f6e2a928b429e32277e7e46befc2b950e17

$ cargo prove vkey --elf "$ELF"
Verification Key Hash:
0x0021629d5e6f7ca0b77d3b4cdd305e46a3a756ee9752ff476a99fdf21374d26c

$ cat prover/guest/elf/SP1VerifyingKeyHash.txt
0x0021629d5e6f7ca0b77d3b4cdd305e46a3a756ee9752ff476a99fdf21374d26c
```

All three should match. If sha256 mismatches the sidecar:

1. The pin is stale — someone bumped the guest source without re-
   stamping the pin/sha256 in the same commit. Don't deploy until
   the pin catches up. CI will catch this on the next push to main.
2. Or: your docker image is not v6.0.2. Verify with
   `docker inspect ghcr.io/succinctlabs/sp1:v6.0.2 --format
   '{{.RepoDigests}}'` and confirm it reports
   `sha256:61bbcdb0cd096004303f25f042813f4b947571c454fb5247197a1bd9c91e01ad`.
   If not, force a re-pull: `docker pull ghcr.io/succinctlabs/sp1:v6.0.2`.

## What if I can't run docker

You have two escape hatches, both compromised:

1. `SP1_SKIP_PROGRAM_BUILD=true cargo build` — uses whatever ELF is
   already present in the target directory. If you have never built
   the guest, the ELF won't exist and the build will fail. If
   another operator has shipped you an ELF, you can drop it at
   `prover/guest/target/elf-compilation/docker/riscv64im-succinct-zkvm-elf/release/bsvm-guest`
   and this mode will pick it up. The covenant will reject any
   proof that doesn't match the pinned VK, so you can't accidentally
   ship the wrong ELF in production this way.
2. Modify `prover/host-bridge/build.rs` locally to remove the
   `docker: true` flag. This is non-reproducible — the resulting ELF
   and VK will differ from the pin. You must run
   `deploy/covenant/rotate-vk.sh --broadcast` to push your local VK
   on-chain before any node will accept your proofs. Don't commit
   this change.

The supported path is: install docker.

## What if the pin is stale (you legitimately changed guest source)

If you intentionally modified `prover/guest/src/**`,
`prover/guest/Cargo.toml`, or `prover/guest/Cargo.lock`, the rebuilt
ELF will (almost always) have a new sha256 and a new VK. The CI
gate at `.github/workflows/sp1-repro.yml` will fail.

To re-stamp:

```
$ ELF=prover/guest/target/elf-compilation/docker/riscv64im-succinct-zkvm-elf/release/bsvm-guest
$ sha256sum "$ELF" | awk '{print $1, "bsvm-guest"}' > prover/guest/elf/bsvm-guest.sha256
$ cargo prove vkey --elf "$ELF" 2>&1 | awk '/Verification Key Hash:/ { getline; print $1 }' > prover/guest/elf/SP1VerifyingKeyHash.txt
```

Then add a decision-doc entry under `docs/decisions/` describing
the rotation event (model after
`docs/decisions/vk-rotation-wire-format-2026-04.md`) and broadcast
the on-chain rotation per `deploy/covenant/rotate-vk.sh
--broadcast` on every live shard.

## Image pin maintenance

`prover/host-*/build.rs` references the SP1 docker image by **tag**
(`v6.0.2`). Tags are mutable — Succinct could in principle re-push
`v6.0.2` with different bytes, which would silently rotate every
operator's VK. Mitigations:

* The CI gate (`.github/workflows/sp1-repro.yml`) runs on a weekly
  cron and re-derives the VK from a fresh pull, so a re-pushed image
  becomes visible within a week even if no PR triggers the gate.
* For stronger pinning, set the `SP1_DOCKER_IMAGE` environment
  variable to the digest:
  `SP1_DOCKER_IMAGE=ghcr.io/succinctlabs/sp1@sha256:61bbcdb0cd096004303f25f042813f4b947571c454fb5247197a1bd9c91e01ad cargo build`.
  Adopting digest pinning at the build.rs level is a Phase 3
  follow-up — see the decision doc.

## Cross-references

* `docs/decisions/sp1-reproducible-build-2026-05.md` — strategy +
  measured A/B verdict.
* `docs/decisions/vk-rotation-wire-format-2026-04.md` — the
  preceding rotation event that surfaced the non-determinism issue.
* `docs/decisions/U-toolchain-pin-strategy.md` — the host-side rust
  nightly pin (orthogonal: docker mode pins rustc by image, but the
  toolchain pin still applies for native dev / `cargo metadata`).
* `prover/host-bridge/build.rs` — the canonical build wiring that
  every other host crate mirrors.
* `prover/guest/elf/SP1VerifyingKeyHash.txt` — the contract.
* `prover/guest/elf/bsvm-guest.sha256` — the byte-level pin.
