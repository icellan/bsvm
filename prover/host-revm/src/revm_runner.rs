//! revm-driven post-state runner. Compiled only with `--features revm`.
//!
//! This module is the integration seam where revm meets the comparator's
//! wire format. It is intentionally separate from the lightweight schema
//! crate so the default build stays cheap.
//!
//! The implementation is currently a structured stub that delegates to
//! the alloy_consensus tx envelope decoder + a CacheDB-backed revm
//! executor. The first-pass scaffolding is here; the integrators
//! enabling the dual-EVM comparator on a developer machine will fill
//! in any tx-type-specific paths. The Go side (pkg/prover/revm_comparator.go)
//! is already wired to the output schema, so as long as this module
//! produces a valid `ComparatorOutput`, the comparison runs.
//!
//! NOTE: revm 31.0.2's API surface is large and version-pinned; do not
//! bump revm here without bumping it in lockstep with prover/guest/.

use crate::{ComparatorInput, ComparatorOutput};

/// Run the batch and produce the canonical post-state envelope.
///
/// Returns `Err` on revm-side failure; the binary surfaces the error
/// rather than emitting a partial JSON envelope.
pub fn execute(_input: ComparatorInput) -> Result<ComparatorOutput, String> {
    // Wiring revm + alloy-consensus is a multi-step integration:
    //
    //   1. Seed CacheDB<EmptyDB> from `input.accounts` (nonce/balance/
    //      code/storage_slots).
    //   2. For each `input.transactions[i].raw_bytes`, decode via
    //      `alloy_consensus::TxEnvelope::decode(&mut &raw[..])`,
    //      recover the signer, and translate into a revm TxEnv.
    //   3. Build a `Context::mainnet().with_db(&mut db).with_block(...)
    //      .with_cfg(CfgEnv::default().with_chain_id(chain_id)
    //      .with_spec(SpecId::CANCUN))` and call `replay()`.
    //   4. After each tx, `db.commit(result.state)` so subsequent txs
    //      see the updated state.
    //   5. Walk `db.cache.accounts` to emit the sorted `OutputAccount`
    //      list and compute `structural_digest`.
    //
    // Each of those steps is a few lines but they touch heavy
    // dependencies that compile slowly; we leave the wiring deferred
    // until a developer explicitly opts in. The default schema-only
    // build at `src/main.rs` stays usable for CI round-trip checks
    // of the wire format.
    Err(
        "revm runner not yet wired — build with --features revm AND \
         fill in src/revm_runner.rs::execute. See module-level doc comment \
         for the step-by-step integration plan."
            .to_string(),
    )
}
