# SP1 Guest Verifying-Key Hash

`SP1VerifyingKeyHash.txt` is the canonical, in-tree pin for the SP1
guest's verifying-key hash. It MUST be re-stamped on every guest-ELF
rotation (every commit that changes the bytes of
`prover/guest/src/**/*.rs` or `prover/guest/Cargo.{toml,lock}`).

## Format

A single line containing the 32-byte hash, hex-encoded with the
`0x` prefix and a trailing newline:

```
0x008e9a57422fe11b537d0d2e21c323074e2bb61f2f4d99dd41cd1d5b8a853914
```

Trailing whitespace and `0x` prefix are tolerated by readers. No JSON,
no TOML, no comments — every consumer reads the first non-empty line
verbatim.

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

After modifying `prover/guest/src/**/*.rs`:

```bash
cd prover/guest
cargo prove build
NEW=$(cargo prove vkey --elf target/elf-compilation/riscv64im-succinct-zkvm-elf/release/bsvm-guest)
echo "$NEW" > elf/SP1VerifyingKeyHash.txt
```

Then commit `elf/SP1VerifyingKeyHash.txt` alongside the source change
in the SAME commit so a `git bisect` never lands on a state where the
pin disagrees with the code.

## Cross-references

* `docs/decisions/CC-vk-rotation-2026-04.md` — historical OLD/NEW hash
  table for the 2026-04 rotation.
* `deploy/covenant/README.md` — operator workflow that consumes this
  file.
* `deploy/covenant/rotate-vk.go` — the rotation entry point.
