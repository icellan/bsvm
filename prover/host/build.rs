// See prover/host-bridge/build.rs for the design rationale; this
// file mirrors that build wiring (Path C in-tree ELF fast-path with a
// docker-mode fallback pinned by SP1 image digest).

use sha2::{Digest, Sha256};
use std::env;
use std::fs;
use std::path::PathBuf;

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
