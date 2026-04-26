//! Host-buildable shim around prover/guest/src/proof_verify.rs.
//!
//! The guest crate cannot be `cargo test`-ed directly (it pins an old SP1
//! nightly toolchain that other deps no longer support). This shim mounts
//! the proof_verify module under a normal stable toolchain so its unit
//! tests can run end-to-end.
//!
//! IMPORTANT: this crate must NOT diverge from the guest's copy. Only the
//! file path differs.

#[path = "../../guest/src/proof_verify.rs"]
mod proof_verify;

pub use proof_verify::*;
