//! BSVM Host-revm — binary entrypoint.
//!
//! Reads a `ComparatorInput` JSON envelope from stdin, runs the batch
//! through revm (when built with `--features revm`), and writes a
//! `ComparatorOutput` JSON envelope to stdout. See `lib.rs` for the
//! envelope shapes and overall design.
//!
//! Build modes:
//!
//!   cargo build --release                   # schema-only smoke binary
//!   cargo build --release --features revm   # full revm executor
//!
//! In schema-only mode the binary parses the input envelope and emits
//! a `ComparatorOutput` with `gas_used = 0`, no receipts, an empty
//! `accounts` list, and a `structural_digest` over that empty list —
//! enough for CI to round-trip the wire format end-to-end without
//! pulling in the revm dependency tree. The Go test harness skips the
//! real comparison in this mode (see `pkg/prover/equivalence_test.go`,
//! `runHostRevm`).
//!
//! In `revm` mode the binary calls into the optional `revm_runner`
//! module which wires up revm 31.0.2 / revm-primitives 21.0.2 — the
//! SAME versions the SP1 guest uses (prover/guest/Cargo.toml) — so
//! the dual-EVM comparison is byte-identical between the two legs.

use bsvm_host_revm::{structural_digest, ComparatorInput, ComparatorOutput};

use std::io::{self, Read, Write};

#[cfg(feature = "revm")]
mod revm_runner;

fn main() {
    let mut buf = String::new();
    io::stdin()
        .read_to_string(&mut buf)
        .expect("read stdin: ComparatorInput JSON");
    let input: ComparatorInput =
        serde_json::from_str(&buf).expect("parse stdin as ComparatorInput JSON");

    let output = run(input);

    let json = serde_json::to_string(&output).expect("serialize ComparatorOutput");
    io::stdout()
        .write_all(json.as_bytes())
        .expect("write ComparatorOutput to stdout");
}

#[cfg(not(feature = "revm"))]
fn run(input: ComparatorInput) -> ComparatorOutput {
    // Schema-only mode: echo the pre_state_root, emit an empty post-state
    // and a structural digest over it. The Go side recognises this empty
    // envelope and skips the dual-EVM comparison with a clear message
    // (see pkg/prover/equivalence_test.go, runHostRevm).
    let accounts = Vec::new();
    let digest = structural_digest(&accounts);
    ComparatorOutput {
        pre_state_root: input.pre_state_root,
        accounts,
        receipts: Vec::new(),
        gas_used: 0,
        structural_digest: digest,
    }
}

#[cfg(feature = "revm")]
fn run(input: ComparatorInput) -> ComparatorOutput {
    revm_runner::execute(input).expect("revm execution failed")
}
