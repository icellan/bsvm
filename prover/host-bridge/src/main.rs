//! BSVM Host Bridge — Go Host <-> SP1 Prover Bridge
//!
//! This Rust binary bridges the Go host with the SP1 prover. It:
//! 1. Reads JSON input on stdin (from the Go host)
//! 2. Converts the input to SP1Stdin
//! 3. Invokes the SP1 prover (execute, core, compressed, or groth16)
//! 4. Returns JSON output on stdout (proof + public values)
//!
//! The Go host calls this binary via exec.Command and communicates
//! via stdin/stdout JSON.

use serde::{Deserialize, Serialize};
use sp1_sdk::{
    include_elf, Elf, HashableKey, ProveRequest, Prover, ProverClient, ProvingKey, SP1Stdin,
};
use std::io::{self, Read};
use std::time::Instant;

/// The ELF binary of the BSVM guest program, built by sp1_build in build.rs.
const GUEST_ELF: Elf = include_elf!("bsvm-guest");

// ─── Input types (JSON from Go host) ─────────────────────────────────────────

/// Block context for EVM execution.
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

/// Account state from the Go host's state export.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct AccountExport {
    address: String,
    nonce: u64,
    balance: String,
    code_hash: String,
    code: String,
    storage: Vec<StorageExport>,
}

/// Storage slot from the state export.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct StorageExport {
    key: String,
    value: String,
}

/// Transaction from the Go host.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct TransactionExport {
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

/// Complete input from the Go host.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct HostInput {
    pre_state_root: String,
    accounts: Vec<AccountExport>,
    transactions: Vec<TransactionExport>,
    block_context: BlockContext,
    /// Proving mode: "execute" (no proof), "core", "compressed", or "groth16".
    mode: String,
}

// ─── Guest-compatible types (must match guest's serde deserialization) ────────

/// Account state as expected by the guest program.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct GuestAccountState {
    address: [u8; 20],
    nonce: u64,
    balance: [u8; 32],
    code_hash: [u8; 32],
    code: Vec<u8>,
    storage: Vec<GuestStorageSlot>,
}

/// Storage slot as expected by the guest program.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct GuestStorageSlot {
    key: [u8; 32],
    value: [u8; 32],
}

/// Transaction as expected by the guest program.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct GuestTransaction {
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

/// Block context as expected by the guest program.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct GuestBlockContext {
    number: u64,
    timestamp: u64,
    coinbase: [u8; 20],
    gas_limit: u64,
    base_fee: u64,
    prev_randao: [u8; 32],
}

/// Complete batch input as expected by the guest program.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct GuestBatchInput {
    pre_state_root: [u8; 32],
    accounts: Vec<GuestAccountState>,
    transactions: Vec<GuestTransaction>,
    block_context: GuestBlockContext,
}

// ─── Output types (JSON to Go host) ──────────────────────────────────────────

/// Output returned to the Go host.
#[derive(Debug, Serialize, Deserialize)]
struct HostOutput {
    /// Hex-encoded proof bytes.
    proof: String,
    /// Hex-encoded public values (272 bytes).
    public_values: String,
    /// Hex-encoded verifying key hash.
    vk_hash: String,
    /// RISC-V cycle count.
    cycles: u64,
    /// Proving time in milliseconds.
    proving_time_ms: u64,
    /// SP1 version string.
    sp1_version: String,
    /// Any error message.
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

// ─── Conversion helpers ──────────────────────────────────────────────────────

/// Parse a hex string (with or without 0x prefix) into bytes.
fn hex_decode(s: &str) -> Vec<u8> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    hex::decode(s).unwrap_or_default()
}

/// Parse a hex string into a fixed-size byte array.
fn hex_to_bytes32(s: &str) -> [u8; 32] {
    let bytes = hex_decode(s);
    let mut out = [0u8; 32];
    let start = 32usize.saturating_sub(bytes.len());
    out[start..].copy_from_slice(&bytes[..bytes.len().min(32)]);
    out
}

/// Parse a hex string into a 20-byte address.
fn hex_to_address(s: &str) -> [u8; 20] {
    let bytes = hex_decode(s);
    let mut out = [0u8; 20];
    let start = 20usize.saturating_sub(bytes.len());
    out[start..].copy_from_slice(&bytes[..bytes.len().min(20)]);
    out
}

/// Convert host input to guest-compatible format.
fn convert_input(input: &HostInput) -> GuestBatchInput {
    let pre_state_root = hex_to_bytes32(&input.pre_state_root);

    let accounts: Vec<GuestAccountState> = input
        .accounts
        .iter()
        .map(|a| {
            let storage: Vec<GuestStorageSlot> = a
                .storage
                .iter()
                .map(|s| GuestStorageSlot {
                    key: hex_to_bytes32(&s.key),
                    value: hex_to_bytes32(&s.value),
                })
                .collect();

            GuestAccountState {
                address: hex_to_address(&a.address),
                nonce: a.nonce,
                balance: hex_to_bytes32(&a.balance),
                code_hash: hex_to_bytes32(&a.code_hash),
                code: hex_decode(&a.code),
                storage,
            }
        })
        .collect();

    let transactions: Vec<GuestTransaction> = input
        .transactions
        .iter()
        .map(|t| GuestTransaction {
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

    GuestBatchInput {
        pre_state_root,
        accounts,
        transactions,
        block_context,
    }
}

// ─── Main ────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    // Read JSON input from stdin.
    let mut input_json = String::new();
    io::stdin()
        .read_to_string(&mut input_json)
        .expect("failed to read stdin");

    let host_input: HostInput = match serde_json::from_str(&input_json) {
        Ok(input) => input,
        Err(e) => {
            let output = HostOutput {
                proof: String::new(),
                public_values: String::new(),
                vk_hash: String::new(),
                cycles: 0,
                proving_time_ms: 0,
                sp1_version: String::new(),
                error: Some(format!("failed to parse input JSON: {}", e)),
            };
            println!("{}", serde_json::to_string(&output).unwrap());
            return;
        }
    };

    // Convert to guest-compatible format.
    let guest_input = convert_input(&host_input);

    // Set up SP1 prover client.
    let client = ProverClient::builder().cpu().build().await;

    // Prepare SP1 stdin.
    let mut stdin = SP1Stdin::new();
    stdin.write(&guest_input);

    // Set up proving and verifying keys.
    let pk = client.setup(GUEST_ELF.clone()).await.expect("setup failed");
    let vk = pk.verifying_key().clone();
    let vk_hash = vk.bytes32();

    let mode = host_input.mode.as_str();

    match mode {
        "execute" => {
            // Execute only (no proof) — fast validation and cycle counting.
            let start = Instant::now();
            match client.execute(GUEST_ELF.clone(), stdin).await {
                Ok((public_values, report)) => {
                    let duration = start.elapsed();
                    let output = HostOutput {
                        proof: String::new(),
                        public_values: format!("0x{}", hex::encode(public_values.as_slice())),
                        vk_hash: vk_hash.to_string(),
                        cycles: report.total_instruction_count(),
                        proving_time_ms: duration.as_millis() as u64,
                        sp1_version: String::new(),
                        error: None,
                    };
                    println!("{}", serde_json::to_string(&output).unwrap());
                }
                Err(e) => {
                    let output = HostOutput {
                        proof: String::new(),
                        public_values: String::new(),
                        vk_hash: vk_hash.to_string(),
                        cycles: 0,
                        proving_time_ms: 0,
                        sp1_version: String::new(),
                        error: Some(format!("execution failed: {}", e)),
                    };
                    println!("{}", serde_json::to_string(&output).unwrap());
                }
            }
        }

        "core" => {
            // Generate a CORE proof (real STARK, size scales with cycles).
            let start = Instant::now();
            match client.prove(&pk, stdin).await {
                Ok(proof) => {
                    let duration = start.elapsed();
                    let proof_bytes =
                        bincode::serialize(&proof).expect("failed to serialize proof");
                    let output = HostOutput {
                        proof: format!("0x{}", hex::encode(&proof_bytes)),
                        public_values: format!("0x{}", hex::encode(proof.public_values.as_slice())),
                        vk_hash: vk_hash.to_string(),
                        cycles: 0,
                        proving_time_ms: duration.as_millis() as u64,
                        sp1_version: proof.sp1_version.clone(),
                        error: None,
                    };
                    println!("{}", serde_json::to_string(&output).unwrap());
                }
                Err(e) => {
                    let output = HostOutput {
                        proof: String::new(),
                        public_values: String::new(),
                        vk_hash: vk_hash.to_string(),
                        cycles: 0,
                        proving_time_ms: 0,
                        sp1_version: String::new(),
                        error: Some(format!("core proof generation failed: {}", e)),
                    };
                    println!("{}", serde_json::to_string(&output).unwrap());
                }
            }
        }

        "compressed" => {
            // Generate a COMPRESSED proof (constant size via recursive compression).
            let start = Instant::now();
            match client.prove(&pk, stdin).compressed().await {
                Ok(proof) => {
                    let duration = start.elapsed();
                    let proof_bytes =
                        bincode::serialize(&proof).expect("failed to serialize proof");
                    let output = HostOutput {
                        proof: format!("0x{}", hex::encode(&proof_bytes)),
                        public_values: format!("0x{}", hex::encode(proof.public_values.as_slice())),
                        vk_hash: vk_hash.to_string(),
                        cycles: 0,
                        proving_time_ms: duration.as_millis() as u64,
                        sp1_version: proof.sp1_version.clone(),
                        error: None,
                    };
                    println!("{}", serde_json::to_string(&output).unwrap());
                }
                Err(e) => {
                    let output = HostOutput {
                        proof: String::new(),
                        public_values: String::new(),
                        vk_hash: vk_hash.to_string(),
                        cycles: 0,
                        proving_time_ms: 0,
                        sp1_version: String::new(),
                        error: Some(format!("compressed proof generation failed: {}", e)),
                    };
                    println!("{}", serde_json::to_string(&output).unwrap());
                }
            }
        }

        other => {
            let output = HostOutput {
                proof: String::new(),
                public_values: String::new(),
                vk_hash: String::new(),
                cycles: 0,
                proving_time_ms: 0,
                sp1_version: String::new(),
                error: Some(format!(
                    "unsupported proving mode: '{}' (use 'execute', 'core', or 'compressed')",
                    other
                )),
            };
            println!("{}", serde_json::to_string(&output).unwrap());
        }
    }
}
