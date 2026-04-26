//! Library facet of the BSVM SP1 guest crate.
//!
//! `main.rs` is the SP1 zkVM entrypoint and uses `#![no_main]`, which
//! prevents `cargo test` from generating its own test harness for the
//! binary. To keep pure-Rust unit tests for modules that don't need the
//! SP1 runtime, we expose them through this library facet so
//! `cargo test --lib` can build them as a normal library + test binary
//! on the host (no SP1 entrypoint, no `no_main`).
//!
//! Only modules with no SP1 syscalls live here. The proving entrypoint
//! itself remains in `main.rs`.

pub mod tx;
