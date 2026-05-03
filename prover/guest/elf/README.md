# SP1 Guest Verifying-Key Hash

`SP1VerifyingKeyHash.txt` is the canonical, in-tree pin for the SP1
guest's verifying-key hash. It MUST be re-stamped on every guest-ELF
rotation (every commit that changes the bytes of
`prover/guest/src/**/*.rs` or `prover/guest/Cargo.{toml,lock}`).

## Format

A single line containing the 32-byte hash, hex-encoded with the
`0x` prefix and a trailing newline:

```
0x0021629d5e6f7ca0b77d3b4cdd305e46a3a756ee9752ff476a99fdf21374d26c
```

Trailing whitespace and `0x` prefix are tolerated by readers. No JSON,
no TOML, no comments — every consumer reads the first non-empty line
verbatim.

A sibling file `bsvm-guest.sha256` records the byte-level pin of the
ELF that derived this VK (sha256sum-compatible format, used by the
reproducible-build CI gate at `.github/workflows/sp1-repro.yml`).

## Why this file exists

Operators previously copied the VK hash out of the
`docs/decisions/CC-vk-rotation-2026-04.md` runbook by hand, which is
error-prone and impossible to script against. Centralising the value
here means:

* `deploy/covenant/compile.go` reads it once at deploy-time and bakes
  it into the rollup covenant locking script.
* `deploy/covenant/rotate-vk.go` re-reads it on rotation and refuses
  to upgrade unless the value matches the rebuilt ELF.
* CI can diff against this file to assert that
  `git log --grep "SP1 VK"` matches the actual on-disk pin.

The file is in-tree (not a build artifact) because every developer
needs the value at compile-time of the deploy tooling, even if they
have not run `cargo prove build` locally.

## How to update

After modifying `prover/guest/src/**/*.rs` (the build runs in docker
mode by default — see `docs/operator/sp1-build.md`):

```bash
cd prover/host-bridge
cargo build --release
ELF=../../prover/guest/target/elf-compilation/docker/riscv64im-succinct-zkvm-elf/release/bsvm-guest
sha256sum "$ELF" | awk '{print $1, "bsvm-guest"}' > ../../prover/guest/elf/bsvm-guest.sha256
cargo prove vkey --elf "$ELF" 2>&1 | awk '/Verification Key Hash:/ { getline; print $1 }' > ../../prover/guest/elf/SP1VerifyingKeyHash.txt
```

Then commit `elf/SP1VerifyingKeyHash.txt` AND `elf/bsvm-guest.sha256`
alongside the source change in the SAME commit so a `git bisect`
never lands on a state where the pin disagrees with the code.

## Cross-references

* `docs/decisions/sp1-reproducible-build-2026-05.md` — the strategy
  + measured A/B that put this pin file under contract via the
  reproducible docker build.
* `docs/operator/sp1-build.md` — operator workflow.
* `docs/decisions/vk-rotation-wire-format-2026-04.md` — preceding
  rotation event.
* `docs/decisions/CC-vk-rotation-2026-04.md` — historical OLD/NEW hash
  table for the 2026-04 rotation.
* `deploy/covenant/README.md` — operator workflow that consumes this
  file.
* `deploy/covenant/rotate-vk.go` — the rotation entry point.
