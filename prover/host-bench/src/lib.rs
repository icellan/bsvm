//! `bsvm-host-bench` — SP1 circuit performance benchmark harness.
//!
//! This is the CHEAP-PERF-BENCH path: it runs the production SP1 guest
//! (`../guest`, the same ELF that `host-bridge` ships in production) in
//! `ProverClient::execute` mode, which evaluates the guest end-to-end
//! WITHOUT generating a proof and reports the RISC-V cycle count and
//! instruction count. That number is the variable the on-chain
//! verifier's locking-script size + the proof-generation wall-time scale
//! against, so it is the right perf signal to pin a budget on.
//!
//! Why a separate crate from `host-bridge`? `host-bridge` is the
//! production proving path — it needs an opinionated "execute / core /
//! compressed" interface and lives on the critical path of the prover
//! pipeline. The bench harness is a one-shot dev tool whose output is
//! the cycle count itself; mixing the two would muddy `host-bridge`'s
//! production responsibilities and force every bench iteration to drag
//! the proving-mode plumbing along.
//!
//! Wire format: this binary accepts the EXACT same JSON envelope shape
//! as `host-bridge` (see `prover/host-bridge/src/main.rs::HostInput`) so
//! the Go-side `pkg/prover.buildBridgeInput` can drive both binaries
//! without bespoke serialization. The output schema is bench-specific
//! (`BenchOutput` below); the production prove envelope is not used.
//!
//! Output is a single JSON line on stdout. On guest panic / SP1 error,
//! the binary prints a structured error message to stderr and emits a
//! `BenchOutput` with `error` populated and `cycles = 0`, then exits
//! non-zero. The Go bench driver picks the message up from the JSON.

use serde::{Deserialize, Serialize};

/// The bench output envelope written to stdout. The Go-side driver
/// (`pkg/prover/bench_test.go`) parses this and logs cycle counts.
///
/// Field shape MUST stay stable — the Go side decodes by name. Adding
/// fields is fine (Go `json.Unmarshal` ignores unknown keys); renaming
/// or removing existing fields breaks the bench harness silently.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BenchOutput {
    /// Total RISC-V instruction count consumed by the guest. SP1 calls
    /// this `total_instruction_count`; we report it under the bench-
    /// friendly name `cycles` because cycle ≈ instruction is the
    /// industry-standard framing for STARK provers.
    pub cycles: u64,
    /// Number of execution segments SP1 split the run into. Useful when
    /// debugging memory pressure (each segment is a proving unit).
    pub segments: u64,
    /// Raw instruction count, kept alongside `cycles` to disambiguate
    /// the two numbers if SP1's accounting ever splits them.
    pub instructions: u64,
    /// Hex-encoded sha256 of the committed public values blob. The Go
    /// side uses this as a quick sanity check that the guest committed
    /// the expected 280-byte blob; mismatches against the Go EVM's
    /// expected post-state are surface-level signals of a guest bug.
    pub public_values_hash: String,
    /// Hex-encoded committed public values (the full 280-byte blob, or
    /// whatever the guest commits). Empty in proof-mode if the guest
    /// failed to produce a proof.
    pub public_values: String,
    /// Process-level exit code reported by the guest. Always `0` on a
    /// successful execute (SP1 doesn't expose a guest-level rc; we use
    /// this slot for forward-compat). Non-zero if the guest panicked.
    pub exit_code: i32,
    /// Wall-clock duration (milliseconds) spent inside
    /// `ProverClient::execute` (or `prove` in `--prove` mode). Captured
    /// around the SP1 entry point only — does not include input
    /// serialization or stdout writes.
    pub wall_ms: u64,

    /// Proof generation wall-clock (milliseconds). `0` in execute mode.
    /// Populated only when `--prove` is set.
    #[serde(default)]
    pub proof_gen_ms: u64,
    /// Size of the serialized proof in bytes. `0` in execute mode.
    /// Populated only when `--prove` is set.
    #[serde(default)]
    pub proof_bytes: u64,
    /// Hex-encoded verifying-key hash. Populated in both execute and
    /// prove modes (the VK is derived from the ELF, not from a proof).
    #[serde(default)]
    pub vk_hash: String,
    /// SP1 SDK version string. Populated only when `--prove` returns a
    /// real proof (the proof object carries its own version stamp).
    #[serde(default)]
    pub sp1_version: String,

    /// Optional structured error message. Set when SP1 reports a guest
    /// panic, an execute failure, or a proof-generation failure. The Go
    /// driver treats `error.is_some()` as a fatal bench-step failure
    /// regardless of the process exit code.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Parse the host-bench input envelope from a JSON string. Re-uses the
/// host-bridge envelope shape verbatim so the Go-side serializer is
/// shared between the two binaries.
///
/// Returns `serde_json::Error` on a malformed envelope (bad JSON, missing
/// required fields, type mismatches). The bench main() forwards the
/// error message to stderr verbatim so the Go test can surface it.
pub fn parse_envelope(json: &str) -> Result<serde_json::Value, serde_json::Error> {
    serde_json::from_str(json)
}

/// Hex-encode a byte slice with the `0x` prefix the Go side expects.
/// Centralised here so the unit tests can pin the format.
pub fn to_hex(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(bytes))
}

/// Compute sha256 of the public-values blob and return the hex-encoded
/// result. Used by `BenchOutput::public_values_hash` so the Go-side
/// driver can pin "the guest committed *some* blob" without having to
/// re-decode the full public values structure on every bench run.
pub fn public_values_digest(blob: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(blob);
    let out = h.finalize();
    to_hex(&out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `parse_envelope` accepts the host-bridge JSON shape. We don't
    /// re-validate every field here — that's host-bridge's job — but we
    /// do pin that the bench shares the wire format so the Go side can
    /// drive both binaries with the same serializer.
    #[test]
    fn parse_envelope_accepts_host_bridge_shape() {
        let json = r#"{
            "pre_state_root": "0x00",
            "accounts": [],
            "transactions": [],
            "block_context": {
                "number": 1,
                "timestamp": 2,
                "coinbase": "0x0000000000000000000000000000000000000000",
                "gas_limit": 30000000,
                "base_fee": 0
            },
            "mode": "execute"
        }"#;
        let v = parse_envelope(json).expect("parse must accept host-bridge JSON");
        assert_eq!(v["mode"], "execute");
        assert_eq!(v["block_context"]["number"], 1);
    }

    /// Empty / malformed envelopes surface as a clean serde error
    /// rather than panicking. The bench main() relays the message to
    /// stderr; this test pins the failure mode.
    #[test]
    fn parse_envelope_rejects_garbage() {
        assert!(parse_envelope("not json at all").is_err());
        assert!(parse_envelope("").is_err());
    }

    /// `to_hex` always emits a `0x` prefix even for the empty slice.
    /// The Go side strips `0x` before decoding so this is the contract
    /// it relies on.
    #[test]
    fn to_hex_includes_0x_prefix() {
        assert_eq!(to_hex(&[]), "0x");
        assert_eq!(to_hex(&[0xab, 0xcd]), "0xabcd");
        assert_eq!(to_hex(&[0u8; 32]), format!("0x{}", "00".repeat(32)));
    }

    /// `public_values_digest` is sha256(blob) for any input. We pin the
    /// empty-input digest because that's the value the Go side asserts
    /// against in the empty-batch happy path.
    #[test]
    fn public_values_digest_is_sha256() {
        // sha256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        assert_eq!(
            public_values_digest(&[]),
            "0xe3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    /// `BenchOutput` round-trips through serde without losing fields.
    /// This is the contract the Go-side `benchOutput` struct decodes
    /// against; drift here breaks the bench driver.
    #[test]
    fn bench_output_round_trips_through_json() {
        let original = BenchOutput {
            cycles: 1234,
            segments: 1,
            instructions: 1234,
            public_values_hash: "0x".repeat(33),
            public_values: "0xdeadbeef".to_string(),
            exit_code: 0,
            wall_ms: 42,
            proof_gen_ms: 0,
            proof_bytes: 0,
            vk_hash: "0xcafe".to_string(),
            sp1_version: String::new(),
            error: None,
        };
        let s = serde_json::to_string(&original).expect("serialize");
        let decoded: BenchOutput = serde_json::from_str(&s).expect("deserialize");
        assert_eq!(decoded.cycles, original.cycles);
        assert_eq!(decoded.public_values, original.public_values);
        assert_eq!(decoded.vk_hash, original.vk_hash);
        assert!(decoded.error.is_none());
    }

    /// When `error` is `None`, the JSON output OMITS the `error` field
    /// entirely (per `skip_serializing_if`). The Go side relies on the
    /// missing field to mean "success"; emitting `"error": null` would
    /// trip a stricter Go decoder if we ever switch one in.
    #[test]
    fn bench_output_omits_error_when_none() {
        let out = BenchOutput::default();
        let s = serde_json::to_string(&out).expect("serialize");
        assert!(!s.contains("\"error\""), "error field should be omitted when None: {s}");
    }
}
