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

/// Account state from the Go host's state export. Carries both the flat
/// account data revm needs to populate its CacheDB AND the Merkle witness
/// the SP1 guest uses to bind that data to `pre_state_root`. The witness
/// fields (`account_proof`, `storage_root`, `storage_slots[].proof`) come
/// from `pkg/prover/state_export.go` and the older flat encoding (storage
/// list with no proofs) is retained as a fallback for legacy callers.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct AccountExport {
    address: String,
    nonce: u64,
    balance: String,
    code_hash: String,
    code: String,
    /// Flat storage list (legacy wire format). Only populated by older
    /// callers. New callers use `storage_slots` which carries proofs.
    #[serde(default)]
    storage: Vec<StorageExport>,
    /// W4-1 witness: storage slots with proofs against `storage_root`.
    /// Optional for backward compatibility.
    #[serde(default)]
    storage_slots: Vec<StorageSlotExport>,
    /// W4-1 witness: hex-encoded RLP MPT nodes proving this account
    /// against `pre_state_root`. Optional for backward compatibility.
    #[serde(default)]
    account_proof: Vec<String>,
    /// Storage trie root for this account. Required when `storage_slots`
    /// is present so the guest can verify each slot proof.
    #[serde(default)]
    storage_root: String,
}

/// Storage slot from the legacy state export (no proof).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct StorageExport {
    key: String,
    value: String,
}

/// Storage slot from the W4-1 witness (with proof against storage_root).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct StorageSlotExport {
    key: String,
    value: String,
    /// Hex-encoded RLP MPT nodes from the storage root down to this slot.
    #[serde(default)]
    proof: Vec<String>,
}

/// Transaction from the Go host.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct TransactionExport {
    /// Transaction type byte (0x00 = legacy, 0x02 = EIP-1559, 0x7E = deposit).
    /// Optional for backward compatibility — defaults to 0x02 (EIP-1559).
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

/// Inbox witness entry from the Go host.
///
/// Mirrors `pkg/prover/inbox_witness.go::InboxQueuedTx`. The host must
/// supply the FULL ordered queue; the guest recomputes the hash chain
/// over `raw_tx_rlp` and asserts equality with `inbox_root_before`
/// (W4-3, spec 10).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct InboxQueuedTxExport {
    /// Hex-encoded raw EVM tx RLP bytes — the exact `evmTxRLP` argument
    /// passed to the inbox covenant's `submit` method.
    raw_tx_rlp: String,
}

/// Complete input from the Go host.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct HostInput {
    pre_state_root: String,
    accounts: Vec<AccountExport>,
    transactions: Vec<TransactionExport>,
    block_context: BlockContext,
    /// Inbox queue hash before draining (hex, optional — defaults to zeros).
    #[serde(default)]
    inbox_root_before: String,
    /// Inbox queue hash after draining (hex, optional — defaults to zeros).
    /// W4-3: ignored by the production guest; the guest recomputes this
    /// from `inbox_queue` + `inbox_drain_count`. Kept on the wire for
    /// host-side cross-check / mock-mode use.
    #[serde(default)]
    inbox_root_after: String,
    /// Full ordered list of currently-queued inbox txs (W4-3, spec 10).
    /// Empty when there's nothing in the on-chain inbox.
    #[serde(default)]
    inbox_queue: Vec<InboxQueuedTxExport>,
    /// How many leading entries from `inbox_queue` to consume.
    #[serde(default)]
    inbox_drain_count: u32,
    /// Forced-inclusion guard (spec 10): when true the guest aborts if
    /// the carry-forward remainder is non-empty.
    #[serde(default)]
    inbox_must_drain_all: bool,
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
///
/// Field shape MUST match prover/guest/src/main.rs::EvmTransaction exactly,
/// including field order — bincode is positional under serde derives, so any
/// drift here silently corrupts guest input.
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

/// Per-storage-slot Merkle witness (mirrors guest's StorageProofWitness).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct GuestStorageProofWitness {
    key: [u8; 32],
    value: [u8; 32],
    proof: Vec<Vec<u8>>,
}

/// Per-account Merkle witness (mirrors guest's AccountProofWitness).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct GuestAccountProofWitness {
    address: [u8; 20],
    account_proof: Vec<Vec<u8>>,
    storage_root: [u8; 32],
    storage_slots: Vec<GuestStorageProofWitness>,
}

/// An inbox witness entry as expected by the guest program.
///
/// Field order MUST match prover/guest/src/main.rs::InboxTx exactly.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct GuestInboxTx {
    tx: GuestTransaction,
    raw_tx_rlp: Vec<u8>,
}

/// Complete batch input as expected by the guest program.
///
/// Field order MUST match prover/guest/src/main.rs::BatchInput exactly.
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
    /// W4-1 / Gate-0 Merkle witnesses. `None` falls back to the legacy
    /// host-trusted path in the guest. The host always populates this when
    /// the input carries proof data.
    state_proofs: Option<Vec<GuestAccountProofWitness>>,
}

// ─── Output types (JSON to Go host) ──────────────────────────────────────────

/// Output returned to the Go host.
#[derive(Debug, Serialize, Deserialize)]
struct HostOutput {
    /// Hex-encoded proof bytes.
    proof: String,
    /// Hex-encoded public values (280 bytes for the production guest;
    /// see prover/guest/src/main.rs and pkg/prover/proof.go::PublicValuesSize).
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

    // Each account is forwarded in two parallel arrays: the flat
    // GuestAccountState that revm consumes, and the witness that the
    // guest's W4-1 verifier uses to bind that state to pre_state_root.
    let accounts: Vec<GuestAccountState> = input
        .accounts
        .iter()
        .map(|a| {
            // Prefer the proof-bearing storage_slots when present; fall
            // back to the legacy flat storage list otherwise.
            let storage: Vec<GuestStorageSlot> = if !a.storage_slots.is_empty() {
                a.storage_slots
                    .iter()
                    .map(|s| GuestStorageSlot {
                        key: hex_to_bytes32(&s.key),
                        value: hex_to_bytes32(&s.value),
                    })
                    .collect()
            } else {
                a.storage
                    .iter()
                    .map(|s| GuestStorageSlot {
                        key: hex_to_bytes32(&s.key),
                        value: hex_to_bytes32(&s.value),
                    })
                    .collect()
            };

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

    // Build the Merkle witness array iff at least one account carries a
    // proof. The guest treats `None` as legacy (host-trusted) input.
    let any_proofs = input
        .accounts
        .iter()
        .any(|a| !a.account_proof.is_empty() || !a.storage_slots.is_empty());
    let state_proofs: Option<Vec<GuestAccountProofWitness>> = if any_proofs {
        Some(
            input
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
                .collect(),
        )
    } else {
        None
    };

    let transactions: Vec<GuestTransaction> = input
        .transactions
        .iter()
        .map(|t| GuestTransaction {
            // Default tx_type to 0x02 (EIP-1559) when host omits it; older
            // wire formats predate the deposit-tx-type-aware production guest.
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

    // Inbox roots: optional in wire format, default to zeros (no inbox).
    // Note: `inbox_root_after` from the host is intentionally dropped — the
    // production guest recomputes it from `inbox_queue`/`inbox_drain_count`
    // and commits the recomputed value (W4-3, spec 10). The host field
    // remains on the wire for cross-check / mock-mode use.
    let inbox_root_before = if input.inbox_root_before.is_empty() {
        [0u8; 32]
    } else {
        hex_to_bytes32(&input.inbox_root_before)
    };

    // Convert the inbox witness (W4-3). Each entry carries the raw RLP
    // (used to recompute the chain root) plus a pre-decoded EvmTransaction
    // ready to feed into revm at the head of the batch.
    //
    // Today the host-bridge only receives `raw_tx_rlp` from the Go host —
    // sender recovery / EIP-2718 envelope decoding for inbox txs lives in
    // a sister task (W4-2). Until that lands, the pre-decoded `tx` field
    // is populated as a zeroed placeholder; if the production guest path
    // exercises the drain branch with a non-zero count the placeholder
    // will produce an invalid revm tx and the batch will fail. Hosts that
    // need real drain-then-execute today should keep `inbox_drain_count`
    // at zero (the queue is still verified against `inbox_root_before`).
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

    GuestBatchInput {
        pre_state_root,
        accounts,
        transactions,
        block_context,
        inbox_root_before,
        inbox_queue,
        inbox_drain_count: input.inbox_drain_count,
        inbox_must_drain_all: input.inbox_must_drain_all,
        state_proofs,
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
