//! `bsvm-host-revm` binary — the dual-EVM equivalence comparator.
//!
//! Reads a JSON `HostInput` envelope on stdin, runs it through revm
//! directly (no SP1, no proving), and emits a JSON `HostOutput`
//! envelope on stdout. The Go test harness in
//! `pkg/prover/equivalence_test.go::TestDualEVMEquivalence_RealRevmHarness`
//! drives this binary alongside `pkg/vm` and asserts byte-for-byte
//! equality on the cross-EVM observables.
//!
//! Exit code:
//!   0 — comparator ran the batch through revm and emitted output.
//!   1 — envelope-shape error (bad hex, missing chain_id, …).
//!   2 — EVM-level execution failure (e.g. signature recovery failed,
//!       balance underflow, nonce mismatch). The error message is
//!       printed to stderr; stdout still carries a JSON envelope with
//!       `error` populated so the Go side can pick the message up.
//!
//! See `lib.rs` for the wire format and the structural-digest scheme
//! used to compare post-states across the two EVMs without porting an
//! MPT into the comparator.

use bsvm_host_revm::{run_batch, HostInput, HostOutput};
use std::io::{self, Read, Write};
use std::process::ExitCode;

fn main() -> ExitCode {
    let mut buf = String::new();
    if let Err(e) = io::stdin().read_to_string(&mut buf) {
        eprintln!("host-revm: failed to read stdin: {}", e);
        return ExitCode::from(1);
    }

    let input: HostInput = match serde_json::from_str(&buf) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("host-revm: failed to parse input JSON: {}", e);
            return ExitCode::from(1);
        }
    };

    match run_batch(&input) {
        Ok(out) => {
            // Emit a single JSON line so the Go test can scanline it.
            let s = serde_json::to_string(&out)
                .expect("HostOutput is always serializable");
            let mut stdout = io::stdout().lock();
            let _ = stdout.write_all(s.as_bytes());
            let _ = stdout.write_all(b"\n");
            ExitCode::SUCCESS
        }
        Err(msg) => {
            eprintln!("host-revm: {}", msg);
            // Still emit a structured output on stdout so the Go side
            // can distinguish "subprocess crashed" from "comparator ran
            // and reported a structured error".
            let stub = HostOutput {
                post_state_digest: String::new(),
                receipts_hash: String::new(),
                batch_data_hash: String::new(),
                logs_bloom: String::new(),
                gas_used: 0,
                per_tx_gas: Vec::new(),
                per_tx_success: Vec::new(),
                post_state_account_count: 0,
                error: Some(msg),
            };
            let s = serde_json::to_string(&stub).unwrap();
            let mut stdout = io::stdout().lock();
            let _ = stdout.write_all(s.as_bytes());
            let _ = stdout.write_all(b"\n");
            ExitCode::from(2)
        }
    }
}
