//! Cross-implementation MPT conformance runner.
//!
//! Loads a JSON fixture (the same format consumed by the Go runner in
//! `test/mpt_conformance/`) and replays each test case's operation sequence
//! against an `alloy-trie`-backed Merkle Patricia Trie. After every operation
//! the root hash is recorded so the Go-side cross-runner test can compare
//! step-by-step against the Go MPT.
//!
//! `alloy-trie` exposes a one-shot `HashBuilder` that consumes leaves in
//! sorted nibble order and emits the root. To support delete and overwrite
//! semantics we maintain the live keyset in a `BTreeMap<key_bytes, raw_value>`
//! and rebuild a fresh `HashBuilder` after each operation. This is O(N) per
//! step but the conformance fixtures are tiny, and it matches what the Go
//! MPT does internally on each `Hash()` call.
//!
//! ## Encoding contract
//!
//! Both runners speak the same low-level MPT (NOT the secure trie):
//! - The JSON `key` is hex-decoded and used as the raw trie key (no extra
//!   keccak hashing). It is unpacked into nibbles via `Nibbles::unpack`
//!   exactly the way `pkg/mpt/trie.go::keybytesToHex` does on the Go side.
//! - The JSON `value` is hex-decoded and inserted as a raw byte string. Both
//!   the Go MPT (`valueNode.encode` -> `WriteBytes`) and `alloy-trie`
//!   (`LeafNodeRef::encode` -> `value.encode(out)` where `value: &[u8]`)
//!   wrap the value in exactly one RLP byte-string header at hash time, so
//!   we hand the raw value directly to `HashBuilder::add_leaf` — no
//!   pre-encoding.
//!
//! Empty value = delete (matches the Go runner's `"action": "delete"`).

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

use alloy_primitives::B256;
use alloy_trie::{HashBuilder, Nibbles};
use anyhow::{anyhow, Context, Result};
use clap::Parser;
use serde::{Deserialize, Serialize};

/// Canonical empty-trie root: keccak256(rlp("")).
const EMPTY_ROOT: [u8; 32] = [
    0x56, 0xe8, 0x1f, 0x17, 0x1b, 0xcc, 0x55, 0xa6, 0xff, 0x83, 0x45, 0xe6, 0x92, 0xc0, 0xf8, 0x6e,
    0x5b, 0x48, 0xe0, 0x1b, 0x99, 0x6c, 0xad, 0xc0, 0x01, 0x62, 0x2f, 0xb5, 0xe3, 0x63, 0xb4, 0x21,
];

#[derive(Parser, Debug)]
#[command(
    name = "rust_runner",
    about = "Run an MPT conformance fixture against alloy-trie and emit a step-by-step root report."
)]
struct Cli {
    /// Path to the JSON fixture file (e.g. ../empty_trie.json).
    #[arg(long)]
    fixture: PathBuf,

    /// Path where the JSON report should be written.
    #[arg(long)]
    report: PathBuf,
}

#[derive(Debug, Deserialize)]
struct FixtureCase {
    name: String,
    operations: Vec<Operation>,
    #[serde(default, rename = "expectedRoot")]
    expected_root: String,
}

#[derive(Debug, Deserialize)]
struct Operation {
    action: String,
    key: String,
    #[serde(default)]
    value: String,
}

#[derive(Debug, Serialize)]
struct StepReport {
    /// Index within the case's operation list (0-based).
    index: usize,
    /// The operation that was applied at this step.
    action: String,
    /// Hex of the trie root after this step (0x-prefixed lowercase).
    actual: String,
}

#[derive(Debug, Serialize)]
struct CaseReport {
    name: String,
    /// Hex of the case's `expectedRoot` field (echoed; empty if fixture omits it).
    expected_root: String,
    /// Hex of the final root computed by alloy-trie (0x-prefixed).
    final_root: String,
    /// Whether the final root matches `expected_root` (true if fixture omits the field).
    final_match: bool,
    /// Per-step roots so the cross-runner can diff against the Go MPT after every op.
    steps: Vec<StepReport>,
    /// Non-empty if the case failed to execute (e.g. malformed op).
    error: Option<String>,
}

#[derive(Debug, Serialize)]
struct FixtureReport {
    fixture: String,
    cases: Vec<CaseReport>,
    /// Aggregate pass/fail across all cases.
    pass: bool,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let raw = fs::read_to_string(&cli.fixture)
        .with_context(|| format!("read fixture {}", cli.fixture.display()))?;
    let cases: Vec<FixtureCase> = serde_json::from_str(&raw)
        .with_context(|| format!("parse fixture {}", cli.fixture.display()))?;

    let mut report = FixtureReport {
        fixture: cli.fixture.display().to_string(),
        cases: Vec::with_capacity(cases.len()),
        pass: true,
    };

    for case in cases {
        let case_report = run_case(case);
        if !case_report.final_match || case_report.error.is_some() {
            report.pass = false;
        }
        report.cases.push(case_report);
    }

    let json = serde_json::to_string_pretty(&report)?;
    fs::write(&cli.report, json)
        .with_context(|| format!("write report {}", cli.report.display()))?;

    if !report.pass {
        // Non-zero exit so a CI invocation surfaces a failure even without
        // the Go-side cross-runner picking up the report.
        std::process::exit(1);
    }
    Ok(())
}

fn run_case(case: FixtureCase) -> CaseReport {
    let mut state: BTreeMap<Vec<u8>, Vec<u8>> = BTreeMap::new();
    let mut steps = Vec::with_capacity(case.operations.len());
    let mut last_err: Option<String> = None;

    for (idx, op) in case.operations.iter().enumerate() {
        match apply_op(&mut state, op) {
            Ok(()) => {}
            Err(e) => {
                last_err = Some(format!("op {idx}: {e}"));
                break;
            }
        }
        let root = compute_root(&state);
        steps.push(StepReport {
            index: idx,
            action: op.action.clone(),
            actual: hex_root(&root),
        });
    }

    let final_root = if steps.is_empty() {
        // No operations applied -> empty trie.
        EMPTY_ROOT
    } else {
        // Recompute (cheap) so we never publish a stale value if a future
        // refactor stops appending steps.
        compute_root(&state)
    };
    let final_root_hex = hex_root(&final_root);

    let expected_norm = normalize_hex(&case.expected_root);
    let final_match = if expected_norm.is_empty() {
        // Fixture omitted the expected root — treat as a pass for the
        // standalone Rust report. The cross-runner test still catches
        // divergence by comparing per-step roots against Go.
        true
    } else {
        expected_norm == final_root_hex
    };

    CaseReport {
        name: case.name,
        expected_root: expected_norm,
        final_root: final_root_hex,
        final_match,
        steps,
        error: last_err,
    }
}

fn apply_op(state: &mut BTreeMap<Vec<u8>, Vec<u8>>, op: &Operation) -> Result<()> {
    let key = hex::decode(strip_0x(&op.key))
        .with_context(|| format!("invalid key hex {:?}", op.key))?;

    match op.action.as_str() {
        "put" => {
            let value = hex::decode(strip_0x(&op.value))
                .with_context(|| format!("invalid value hex {:?}", op.value))?;
            if value.is_empty() {
                // Match Go's `Update(key, value)` semantics: empty value = delete.
                state.remove(&key);
            } else {
                state.insert(key, value);
            }
        }
        "delete" => {
            state.remove(&key);
        }
        other => return Err(anyhow!("unknown action {other:?}")),
    }
    Ok(())
}

/// Compute the MPT root for the current keyset using alloy-trie's HashBuilder.
///
/// Behaviour parity with `pkg/mpt`:
/// 1. The trie key is the raw byte sequence (no keccak hashing). We unpack it
///    into nibbles via `Nibbles::unpack`.
/// 2. The leaf payload is the raw value bytes. `alloy-trie`'s `LeafNodeRef`
///    RLP-encodes the value internally as a byte string, exactly matching
///    `pkg/mpt`'s `valueNode.encode` -> `WriteBytes`.
fn compute_root(state: &BTreeMap<Vec<u8>, Vec<u8>>) -> [u8; 32] {
    if state.is_empty() {
        return EMPTY_ROOT;
    }

    let mut hb = HashBuilder::default();
    // BTreeMap iteration is already key-sorted, which is what HashBuilder requires.
    for (key, value) in state.iter() {
        let nibbles = Nibbles::unpack(key);
        hb.add_leaf(nibbles, value.as_slice());
    }
    let root: B256 = hb.root();
    root.0
}

fn strip_0x(s: &str) -> &str {
    s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s)
}

fn normalize_hex(s: &str) -> String {
    if s.is_empty() {
        return String::new();
    }
    let body = strip_0x(s).to_ascii_lowercase();
    format!("0x{body}")
}

fn hex_root(root: &[u8; 32]) -> String {
    format!("0x{}", hex::encode(root))
}
