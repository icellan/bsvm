// Reproducible-build wiring for the production SP1 guest. See
// docs/decisions/sp1-reproducible-build-2026-05.md.
//
// Two layers, in order:
//
//   1. **Path C (in-tree ELF fast-path)**: if
//      `prover/guest/elf/bsvm-guest` exists and its sha256 matches
//      `prover/guest/elf/bsvm-guest.sha256`, use it directly. Operators
//      without docker installed can still build and run a node — the
//      covenant on-chain rejects any proof whose VK doesn't match the
//      pin, so a stale or tampered blob can't slip through to mainnet.
//
//   2. **Path A (dockerized rebuild)**: invoke `sp1_build` with
//      `BuildArgs { docker: true, .. }` against the
//      `ghcr.io/succinctlabs/sp1` image, **pinned by content digest**
//      (not just by the mutable `v6.0.2` tag) via the
//      `SP1_DOCKER_IMAGE` env var. This is the canonical reproducible
//      path; every operator's docker container produces a
//      bit-identical ELF.
//
// Set `SP1_SKIP_PROGRAM_BUILD=true` to bypass both layers (the
// existing escape hatch for fast cargo-check loops).

use sha2::{Digest, Sha256};
use std::env;
use std::fs;
use std::path::PathBuf;

// SP1 docker image, pinned by content digest. Resolves to the same
// bytes as `ghcr.io/succinctlabs/sp1:v6.0.2` as of 2026-05-03.
// Re-pin alongside any sp1-build version bump (`docker manifest
// inspect ghcr.io/succinctlabs/sp1:vX.Y.Z`).
const SP1_IMAGE_DIGEST: &str =
    "ghcr.io/succinctlabs/sp1@sha256:61bbcdb0cd096004303f25f042813f4b947571c454fb5247197a1bd9c91e01ad";

fn main() {
    if let Some(elf_path) = use_in_tree_elf() {
        println!("cargo:rustc-env=SP1_ELF_bsvm-guest={}", elf_path.display());
        println!("cargo:rerun-if-changed={}", elf_path.display());
        println!(
            "cargo:warning=using in-tree pinned bsvm-guest ELF (Path C); \
             skipping docker rebuild"
        );
        return;
    }

    env::set_var("SP1_DOCKER_IMAGE", SP1_IMAGE_DIGEST);
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

fn use_in_tree_elf() -> Option<PathBuf> {
    let elf_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("guest")
        .join("elf");
    let elf_path = elf_dir.join("bsvm-guest");
    let sha_path = elf_dir.join("bsvm-guest.sha256");
    println!("cargo:rerun-if-changed={}", sha_path.display());

    if !elf_path.exists() || !sha_path.exists() {
        return None;
    }
    let elf_bytes = fs::read(&elf_path).ok()?;
    let mut hasher = Sha256::new();
    hasher.update(&elf_bytes);
    let actual = hex::encode(hasher.finalize());
    let expected = fs::read_to_string(&sha_path).ok()?;
    let expected = expected.split_whitespace().next()?.to_lowercase();
    if actual == expected {
        elf_path.canonicalize().ok()
    } else {
        println!(
            "cargo:warning=in-tree ELF sha256 ({actual}) does not match pin ({expected}); \
             falling back to docker build"
        );
        None
    }
}
