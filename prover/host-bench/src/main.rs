//! `bsvm-host-bench` binary entry point.
//!
//! Reads a JSON `HostInput` envelope (same shape as `prover/host-
//! bridge`'s input) on stdin, runs the production guest in EXECUTE mode
//! (no proof) by default, and writes a JSON `BenchOutput` line on
//! stdout. With `--prove`, also generates the real STARK proof and
//! reports proof time + size + VK hash. See `lib.rs` for the wire
//! format pin.
//!
//! Why duplicate the conversion code from `host-bridge`? The bridge's
//! conversion helpers are `pub(crate)` (private to that binary), so
//! sharing them would require turning that crate into a `lib` first —
//! invasive change for a one-shot bench tool. The conversion here is
//! kept byte-identical to `host-bridge::convert_input` so any future
//! drift between the two would surface immediately as a guest decode
//! error in the bench (which is itself a useful signal).
//!
//! Exit codes:
//!   0 — bench ran the batch and emitted output (cycles/proof reported).
//!   1 — envelope-shape error (bad JSON, missing fields). stderr carries
//!       the message; stdout still emits a stub `BenchOutput` with
//!       `error` populated so the Go driver can pick it up.
//!   2 — SP1-level execution / proving failure (guest panic, prover
//!       error). Same stderr + stub-stdout convention.

use bsvm_host_bench::{public_values_digest, to_hex, BenchOutput};
use serde::{Deserialize, Serialize};
use sp1_sdk::{include_elf, Elf, HashableKey, ProveRequest, Prover, ProverClient, SP1Stdin};
use std::io::{self, Read, Write};
use std::process::ExitCode;
use std::time::Instant;

/// Production SP1 guest ELF, built by `sp1_build` in `build.rs`. This is
/// the SAME ELF `host-bridge` ships in production proving — using a
/// different one would invalidate the bench (we'd be measuring something
/// other than what mainnet actually runs).
const GUEST_ELF: Elf = include_elf!("bsvm-guest");

// ─── Input wire format ───────────────────────────────────────────────────────
//
// These types mirror `prover/host-bridge/src/main.rs::HostInput` exactly.
// Drift here means the Go-side `pkg/prover.buildBridgeInput` produces
// JSON the bench can't decode, which is itself a useful canary, but the
// goal is to keep them in sync. See the `parse_envelope` test in
// `lib.rs::tests` for the shared-shape pin.

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BlockContext {
    number: u64,
    timestamp: u64,
    coinbase: String,
    gas_limit: u64,
    base_fee: u64,
    #[serde(default)]
    prev_randao: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AccountExport {
    address: String,
    nonce: u64,
    balance: String,
    code_hash: String,
    code: String,
    #[serde(default)]
    storage_slots: Vec<StorageSlotExport>,
    /// W4-1 witness — required by the production guest. The bench
    /// surfaces a missing-witness envelope as a regular envelope-shape
    /// error so the Go driver fails loudly.
    account_proof: Vec<String>,
    storage_root: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StorageSlotExport {
    key: String,
    value: String,
    #[serde(default)]
    proof: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TransactionExport {
    #[serde(default)]
    tx_type: u8,
    from: String,
    to: Option<String>,
    value: String,
    data: String,
    nonce: u64,
    gas_limit: u64,
    gas_price: u64,
    #[serde(default)]
    max_priority_fee: u64,
    raw_bytes: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct InboxQueuedTxExport {
    raw_tx_rlp: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct HostInput {
    pre_state_root: String,
    accounts: Vec<AccountExport>,
    transactions: Vec<TransactionExport>,
    block_context: BlockContext,
    #[serde(default)]
    inbox_root_before: String,
    #[serde(default)]
    inbox_root_after: String,
    #[serde(default)]
    inbox_queue: Vec<InboxQueuedTxExport>,
    #[serde(default)]
    inbox_drain_count: u32,
    #[serde(default)]
    inbox_must_drain_all: bool,
    /// `mode` is accepted but ignored — the bench's mode is selected via
    /// the `--prove` CLI flag, not the envelope. Keeping the field on
    /// the wire means the Go side's `buildBridgeInput` (which always
    /// stamps a mode) round-trips cleanly through the bench.
    #[serde(default)]
    mode: String,
}

// ─── Guest-compatible wire types ─────────────────────────────────────────────
//
// Exactly mirrors the layout in `prover/guest/src/main.rs::BatchInput`
// (and `host-bridge`'s `GuestBatchInput`). Field order is load-bearing
// because bincode under serde derives is positional; drift between
// these and the guest silently corrupts the input.

#[derive(Debug, Clone, Serialize, Deserialize)]
struct GuestAccountState {
    address: [u8; 20],
    nonce: u64,
    balance: [u8; 32],
    code_hash: [u8; 32],
    code: Vec<u8>,
    storage: Vec<GuestStorageSlot>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct GuestStorageSlot {
    key: [u8; 32],
    value: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct GuestTransaction {
    tx_type: u8,
    from: [u8; 20],
    to: Option<[u8; 20]>,
    value: [u8; 32],
    data: Vec<u8>,
    nonce: u64,
    gas_limit: u64,
    gas_price: u64,
    max_priority_fee: u64,
    raw_bytes: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct GuestBlockContext {
    number: u64,
    timestamp: u64,
    coinbase: [u8; 20],
    gas_limit: u64,
    base_fee: u64,
    prev_randao: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct GuestStorageProofWitness {
    key: [u8; 32],
    value: [u8; 32],
    proof: Vec<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct GuestAccountProofWitness {
    address: [u8; 20],
    account_proof: Vec<Vec<u8>>,
    storage_root: [u8; 32],
    storage_slots: Vec<GuestStorageProofWitness>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct GuestInboxTx {
    tx: GuestTransaction,
    raw_tx_rlp: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct GuestBatchInput {
    pre_state_root: [u8; 32],
    accounts: Vec<GuestAccountState>,
    transactions: Vec<GuestTransaction>,
    block_context: GuestBlockContext,
    inbox_root_before: [u8; 32],
    inbox_queue: Vec<GuestInboxTx>,
    inbox_drain_count: u32,
    inbox_must_drain_all: bool,
    state_proofs: Vec<GuestAccountProofWitness>,
}

// ─── Conversion helpers ──────────────────────────────────────────────────────

fn hex_decode(s: &str) -> Vec<u8> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    hex::decode(s).unwrap_or_default()
}

fn hex_to_bytes32(s: &str) -> [u8; 32] {
    let bytes = hex_decode(s);
    let mut out = [0u8; 32];
    let start = 32usize.saturating_sub(bytes.len());
    out[start..].copy_from_slice(&bytes[..bytes.len().min(32)]);
    out
}

fn hex_to_address(s: &str) -> [u8; 20] {
    let bytes = hex_decode(s);
    let mut out = [0u8; 20];
    let start = 20usize.saturating_sub(bytes.len());
    out[start..].copy_from_slice(&bytes[..bytes.len().min(20)]);
    out
}

/// Build the guest-side `BatchInput` from the JSON envelope. Returns an
/// error message on a malformed input — surface the same envelope-level
/// rejections `host-bridge` enforces (W4-1 mainnet hardening) so the
/// bench fails fast on a bad envelope rather than blowing up inside the
/// guest after wasted execute cycles.
fn convert_input(input: &HostInput) -> Result<GuestBatchInput, String> {
    let pre_state_root = hex_to_bytes32(&input.pre_state_root);

    let accounts: Vec<GuestAccountState> = input
        .accounts
        .iter()
        .map(|a| GuestAccountState {
            address: hex_to_address(&a.address),
            nonce: a.nonce,
            balance: hex_to_bytes32(&a.balance),
            code_hash: hex_to_bytes32(&a.code_hash),
            code: hex_decode(&a.code),
            storage: a
                .storage_slots
                .iter()
                .map(|s| GuestStorageSlot {
                    key: hex_to_bytes32(&s.key),
                    value: hex_to_bytes32(&s.value),
                })
                .collect(),
        })
        .collect();

    // W4-1 envelope rule: every account must carry a witness. We mirror
    // `host-bridge`'s rejection here so the bench fails loudly rather
    // than handing the guest an envelope it would surface as error 0x06
    // after wasting setup cycles.
    for a in &input.accounts {
        if a.account_proof.is_empty() {
            return Err(format!(
                "account {} is missing the W4-1 account_proof — \
                 the production guest requires Merkle witnesses for \
                 every account in state_proofs",
                a.address
            ));
        }
    }
    let state_proofs: Vec<GuestAccountProofWitness> = input
        .accounts
        .iter()
        .map(|a| GuestAccountProofWitness {
            address: hex_to_address(&a.address),
            account_proof: a.account_proof.iter().map(|h| hex_decode(h)).collect(),
            storage_root: hex_to_bytes32(&a.storage_root),
            storage_slots: a
                .storage_slots
                .iter()
                .map(|s| GuestStorageProofWitness {
                    key: hex_to_bytes32(&s.key),
                    value: hex_to_bytes32(&s.value),
                    proof: s.proof.iter().map(|h| hex_decode(h)).collect(),
                })
                .collect(),
        })
        .collect();

    let transactions: Vec<GuestTransaction> = input
        .transactions
        .iter()
        .map(|t| GuestTransaction {
            // Match host-bridge's default-to-EIP-1559 behaviour for the
            // legacy zero-typed envelopes some Go-side serializers ship.
            // Drift here would mis-price txs in revm's TxEnv (see the
            // long comment in the production guest's tx-type pin).
            tx_type: if t.tx_type == 0 { 0x02 } else { t.tx_type },
            from: hex_to_address(&t.from),
            to: t.to.as_ref().map(|s| hex_to_address(s)),
            value: hex_to_bytes32(&t.value),
            data: hex_decode(&t.data),
            nonce: t.nonce,
            gas_limit: t.gas_limit,
            gas_price: t.gas_price,
            max_priority_fee: t.max_priority_fee,
            raw_bytes: hex_decode(&t.raw_bytes),
        })
        .collect();

    let block_context = GuestBlockContext {
        number: input.block_context.number,
        timestamp: input.block_context.timestamp,
        coinbase: hex_to_address(&input.block_context.coinbase),
        gas_limit: input.block_context.gas_limit,
        base_fee: input.block_context.base_fee,
        prev_randao: hex_to_bytes32(&input.block_context.prev_randao),
    };

    let inbox_root_before = if input.inbox_root_before.is_empty() {
        [0u8; 32]
    } else {
        hex_to_bytes32(&input.inbox_root_before)
    };

    // Same simplified inbox queue handling as host-bridge: the bench
    // does not currently exercise drain-then-execute (the Go bench
    // driver feeds all-zero inbox state). Keep the placeholder shape so
    // an inbox-aware envelope still serializes cleanly.
    let inbox_queue: Vec<GuestInboxTx> = input
        .inbox_queue
        .iter()
        .map(|t| GuestInboxTx {
            tx: GuestTransaction {
                tx_type: 0x02,
                from: [0u8; 20],
                to: None,
                value: [0u8; 32],
                data: Vec::new(),
                nonce: 0,
                gas_limit: 0,
                gas_price: 0,
                max_priority_fee: 0,
                raw_bytes: hex_decode(&t.raw_tx_rlp),
            },
            raw_tx_rlp: hex_decode(&t.raw_tx_rlp),
        })
        .collect();

    Ok(GuestBatchInput {
        pre_state_root,
        accounts,
        transactions,
        block_context,
        inbox_root_before,
        inbox_queue,
        inbox_drain_count: input.inbox_drain_count,
        inbox_must_drain_all: input.inbox_must_drain_all,
        state_proofs,
    })
}

// ─── CLI ─────────────────────────────────────────────────────────────────────

/// Parsed CLI flags. We deliberately roll our own parser here to keep
/// the dependency surface minimal — adding `clap` would inflate the
/// bench's compile time noticeably for a 1-flag binary.
#[derive(Debug, Default)]
struct Args {
    /// When `true`, also generate a real STARK proof and report proof
    /// time / size / VK hash. Default `false` (execute-only mode).
    prove: bool,
    /// SP1 proving mode for `--prove`: "core" (default), "compressed",
    /// or "groth16". Ignored unless `--prove` is set.
    proof_mode: String,
}

fn parse_args() -> Args {
    let mut args = Args {
        prove: false,
        proof_mode: "core".to_string(),
    };
    let mut iter = std::env::args().skip(1);
    while let Some(a) = iter.next() {
        match a.as_str() {
            "--prove" => args.prove = true,
            "--proof-mode" => {
                if let Some(v) = iter.next() {
                    args.proof_mode = v;
                }
            }
            // Ignore unknown args silently — the bench is invoked from
            // tests that may stamp on extra flags down the line.
            _ => {}
        }
    }
    args
}

// ─── Output helpers ──────────────────────────────────────────────────────────

/// Emit a `BenchOutput` to stdout as a single JSON line. The Go-side
/// driver `bufio.Scanner`s on this line.
fn emit(out: &BenchOutput) {
    let s = serde_json::to_string(out).expect("BenchOutput is always serializable");
    let mut stdout = io::stdout().lock();
    let _ = stdout.write_all(s.as_bytes());
    let _ = stdout.write_all(b"\n");
}

/// Emit a stub error envelope — used when input parsing fails or when
/// SP1 returns an error before producing any cycle counts.
fn emit_error(stage: &str, err: &str, vk_hash: Option<String>) {
    let out = BenchOutput {
        cycles: 0,
        segments: 0,
        instructions: 0,
        public_values_hash: String::new(),
        public_values: String::new(),
        exit_code: 1,
        wall_ms: 0,
        proof_gen_ms: 0,
        proof_bytes: 0,
        vk_hash: vk_hash.unwrap_or_default(),
        sp1_version: String::new(),
        error: Some(format!("{stage}: {err}")),
    };
    emit(&out);
}

// ─── Main ────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> ExitCode {
    let args = parse_args();

    // Read stdin.
    let mut input_json = String::new();
    if let Err(e) = io::stdin().read_to_string(&mut input_json) {
        eprintln!("host-bench: failed to read stdin: {e}");
        emit_error("stdin", &e.to_string(), None);
        return ExitCode::from(1);
    }

    // Parse envelope.
    let host_input: HostInput = match serde_json::from_str(&input_json) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("host-bench: failed to parse input JSON: {e}");
            emit_error("parse", &e.to_string(), None);
            return ExitCode::from(1);
        }
    };

    // Convert to guest types (W4-1 envelope check folded in).
    let guest_input = match convert_input(&host_input) {
        Ok(g) => g,
        Err(e) => {
            eprintln!("host-bench: invalid host input: {e}");
            emit_error("convert", &e, None);
            return ExitCode::from(1);
        }
    };

    // Set up SP1 prover client. CPU backend is correct for the bench:
    // `execute` mode never touches a GPU, and `--prove` falls back to
    // CPU proving by design (this is the "what does it cost on a stock
    // box" measurement; GPU-class numbers are the operator's job to
    // replicate with their own cargo flags).
    let client = ProverClient::builder().cpu().build().await;

    // Set up VK once — same in execute and prove paths.
    let pk = match client.setup(GUEST_ELF.clone()).await {
        Ok(pk) => pk,
        Err(e) => {
            eprintln!("host-bench: SP1 setup failed: {e}");
            emit_error("setup", &e.to_string(), None);
            return ExitCode::from(2);
        }
    };
    let vk = pk.verifying_key().clone();
    let vk_hash = vk.bytes32();

    // Build SP1 stdin from the converted guest input.
    let mut stdin = SP1Stdin::new();
    stdin.write(&guest_input);

    // Execute path: cheap-perf-bench measurement. No proof. Reports
    // cycle count + instruction count + (for now, zero) segment count.
    if !args.prove {
        let start = Instant::now();
        let (public_values, report) = match client.execute(GUEST_ELF.clone(), stdin).await {
            Ok(r) => r,
            Err(e) => {
                eprintln!("host-bench: execute failed: {e}");
                emit_error("execute", &e.to_string(), Some(vk_hash.to_string()));
                return ExitCode::from(2);
            }
        };
        let wall = start.elapsed();

        let pv_bytes = public_values.as_slice();
        let out = BenchOutput {
            cycles: report.total_instruction_count(),
            // SP1 v6's `ExecutionReport` does not expose a segment count
            // (it's an opcode/syscall counter only). We keep the field
            // on the wire as `0` for forward-compat — if SP1 starts
            // surfacing segments we wire them in here without a wire-
            // format break.
            segments: 0,
            instructions: report.total_instruction_count(),
            public_values_hash: public_values_digest(pv_bytes),
            public_values: to_hex(pv_bytes),
            exit_code: 0,
            wall_ms: wall.as_millis() as u64,
            proof_gen_ms: 0,
            proof_bytes: 0,
            vk_hash: vk_hash.to_string(),
            sp1_version: String::new(),
            error: None,
        };
        emit(&out);
        return ExitCode::SUCCESS;
    }

    // Prove path: also produces a real STARK proof. SLOW (~minutes).
    // Operators run this on demand once the cycle bench confirms the
    // guest is in budget.
    let start = Instant::now();
    let proof_result = match args.proof_mode.as_str() {
        "compressed" => client.prove(&pk, stdin).compressed().await,
        // "core" is the default — a regular STARK proof, no recursion.
        // We don't surface "groth16" here because the bench is about the
        // STARK cost, not the wrapping cost; operators that want
        // wrapping numbers use host-bridge directly.
        _ => client.prove(&pk, stdin).await,
    };
    let proof = match proof_result {
        Ok(p) => p,
        Err(e) => {
            eprintln!("host-bench: prove ({}) failed: {e}", args.proof_mode);
            emit_error("prove", &e.to_string(), Some(vk_hash.to_string()));
            return ExitCode::from(2);
        }
    };
    let wall = start.elapsed();

    let proof_bytes = match bincode::serialize(&proof) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("host-bench: proof serialization failed: {e}");
            emit_error("serialize", &e.to_string(), Some(vk_hash.to_string()));
            return ExitCode::from(2);
        }
    };

    let pv_bytes = proof.public_values.as_slice();
    let out = BenchOutput {
        // SP1 doesn't surface a cycle count from the produced proof
        // object (it's available via execute); leave 0 here so the Go
        // driver knows to fall back to a separate execute call when it
        // needs the cycle number alongside the proof.
        cycles: 0,
        segments: 0,
        instructions: 0,
        public_values_hash: public_values_digest(pv_bytes),
        public_values: to_hex(pv_bytes),
        exit_code: 0,
        // wall_ms == proof_gen_ms in --prove mode; keep both populated
        // so the Go driver doesn't have to special-case the field.
        wall_ms: wall.as_millis() as u64,
        proof_gen_ms: wall.as_millis() as u64,
        proof_bytes: proof_bytes.len() as u64,
        vk_hash: vk_hash.to_string(),
        sp1_version: proof.sp1_version.clone(),
        error: None,
    };
    emit(&out);
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `parse_args` is a hand-rolled flag parser; pin its happy paths
    /// here so a typo in `main()` doesn't silently change bench
    /// behaviour. We can't drive `parse_args` from std::env in a unit
    /// test (it reads the test binary's own args), so this test stays
    /// thin — but the conversion code below covers the data shape.
    #[test]
    fn args_default_is_execute_mode() {
        let a = Args::default();
        assert!(!a.prove);
    }

    /// `convert_input` rejects an envelope where any account is missing
    /// its W4-1 witness. Mirrors the host-bridge contract.
    #[test]
    fn convert_input_rejects_missing_witness() {
        let input = HostInput {
            pre_state_root: "0x00".to_string(),
            accounts: vec![AccountExport {
                address: "0x1111111111111111111111111111111111111111".to_string(),
                nonce: 0,
                balance: "0x00".to_string(),
                code_hash: "0x00".to_string(),
                code: "0x".to_string(),
                storage_slots: vec![],
                account_proof: vec![], // ← missing
                storage_root: "0x00".to_string(),
            }],
            transactions: vec![],
            block_context: BlockContext {
                number: 1,
                timestamp: 1,
                coinbase: "0x0000000000000000000000000000000000000000".to_string(),
                gas_limit: 1,
                base_fee: 0,
                prev_randao: String::new(),
            },
            inbox_root_before: String::new(),
            inbox_root_after: String::new(),
            inbox_queue: vec![],
            inbox_drain_count: 0,
            inbox_must_drain_all: false,
            mode: "execute".to_string(),
        };
        let err = convert_input(&input).expect_err("missing witness must be rejected");
        assert!(err.contains("account_proof"), "unexpected error message: {err}");
    }

    /// `convert_input` accepts an empty-batch envelope (no accounts, no
    /// txs). This is the trivial happy path the Go driver hits when the
    /// bench harness boots and runs a minimal sanity bench.
    #[test]
    fn convert_input_accepts_empty_batch() {
        let input = HostInput {
            pre_state_root: "0x00".to_string(),
            accounts: vec![],
            transactions: vec![],
            block_context: BlockContext {
                number: 1,
                timestamp: 1,
                coinbase: "0x0000000000000000000000000000000000000000".to_string(),
                gas_limit: 1,
                base_fee: 0,
                prev_randao: String::new(),
            },
            inbox_root_before: String::new(),
            inbox_root_after: String::new(),
            inbox_queue: vec![],
            inbox_drain_count: 0,
            inbox_must_drain_all: false,
            mode: "execute".to_string(),
        };
        let g = convert_input(&input).expect("empty batch must convert cleanly");
        assert!(g.accounts.is_empty());
        assert!(g.state_proofs.is_empty());
        assert!(g.transactions.is_empty());
    }

    /// `hex_to_bytes32` left-pads short hex strings with zeros, matching
    /// the host-bridge's behaviour. The Go-side `bytesToHex` already
    /// emits 32-byte hex for balances and roots, but envelopes coming
    /// from hand-written tests may shorten them.
    #[test]
    fn hex_to_bytes32_left_pads_short_inputs() {
        let b = hex_to_bytes32("0xabcd");
        let mut want = [0u8; 32];
        want[30] = 0xab;
        want[31] = 0xcd;
        assert_eq!(b, want);
    }

    /// `hex_to_address` left-pads short hex strings to 20 bytes; same
    /// pin as the bytes32 case.
    #[test]
    fn hex_to_address_left_pads_short_inputs() {
        let a = hex_to_address("0x01");
        let mut want = [0u8; 20];
        want[19] = 0x01;
        assert_eq!(a, want);
    }
}
