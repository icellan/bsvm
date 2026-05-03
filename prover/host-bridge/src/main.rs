//! BSVM Host Bridge — Go Host <-> SP1 Prover Bridge
//!
//! This Rust binary bridges the Go host with the SP1 prover. It:
//! 1. Reads JSON input on stdin (from the Go host)
//! 2. Converts the input to SP1Stdin
//! 3. Invokes the SP1 prover (execute, core, compressed, or groth16)
//!    OR builds a spec-12 upgrade-transition proof bundle for VK rotations.
//! 4. Returns JSON output on stdout (proof + public values)
//!
//! The Go host calls this binary via exec.Command and communicates
//! via stdin/stdout JSON.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sp1_sdk::{
    include_elf, Elf, HashableKey, ProveRequest, Prover, ProverClient, ProvingKey, SP1Stdin,
};
use std::io::{self, Read};
use std::time::Instant;

/// The ELF binary of the BSVM guest program, built by sp1_build in build.rs.
const GUEST_ELF: Elf = include_elf!("bsvm-guest");

// ─── Input types (JSON from Go host) ─────────────────────────────────────────

/// Block context for EVM execution.
///
/// Default values are zeros / empty so the upgrade-proof mode (which
/// has no execution context) can omit the field entirely from its
/// stdin envelope.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct BlockContext {
    #[serde(default)]
    number: u64,
    #[serde(default)]
    timestamp: u64,
    #[serde(default)]
    coinbase: String,
    #[serde(default)]
    gas_limit: u64,
    #[serde(default)]
    base_fee: u64,
    #[serde(default)]
    prev_randao: String,
}

/// Account state from the Go host's state export. Carries both the flat
/// account data revm needs to populate its CacheDB AND the Merkle witness
/// the SP1 guest uses to bind that data to `pre_state_root`. The witness
/// fields (`account_proof`, `storage_root`, `storage_slots[].proof`) come
/// from `pkg/prover/state_export.go` and are MANDATORY (W4-1 mainnet
/// hardening): an envelope without proofs is rejected at decode time.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct AccountExport {
    address: String,
    nonce: u64,
    balance: String,
    code_hash: String,
    code: String,
    /// W4-1 witness: storage slots with proofs against `storage_root`.
    #[serde(default)]
    storage_slots: Vec<StorageSlotExport>,
    /// W4-1 witness: hex-encoded RLP MPT nodes proving this account
    /// against `pre_state_root`. Required (must be non-empty).
    account_proof: Vec<String>,
    /// Storage trie root for this account. Required so the guest can
    /// verify each storage slot proof under it.
    storage_root: String,
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
///
/// The `mode` field selects the dispatch path. Most fields are only
/// consumed by the EVM-execution modes (`execute` / `core` /
/// `compressed`); the `upgrade-proof` mode reads only `pre_state_root`,
/// `chain_id`, `block_number`, and `new_covenant_script_hex`. The
/// EVM-execution modes leave `chain_id` / `block_number` /
/// `new_covenant_script_hex` unset; the upgrade mode leaves
/// `accounts` / `transactions` / `inbox_*` empty.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct HostInput {
    pre_state_root: String,
    /// EVM accounts. Required for execute/core/compressed; ignored by
    /// upgrade-proof. Defaults to empty so an upgrade-mode JSON
    /// envelope doesn't have to carry the field.
    #[serde(default)]
    accounts: Vec<AccountExport>,
    /// EVM transactions. Required for execute/core/compressed; ignored
    /// by upgrade-proof.
    #[serde(default)]
    transactions: Vec<TransactionExport>,
    /// Block context. Required for execute/core/compressed; ignored by
    /// upgrade-proof (which derives blockNumber from the dedicated
    /// `block_number` field).
    #[serde(default)]
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
    /// Proving mode: "execute" (no proof), "core", "compressed", or
    /// "upgrade-proof" (covenant VK rotation).
    mode: String,

    // ── upgrade-proof mode inputs (ignored by other modes) ───────────────

    /// Hex-encoded new covenant locking-script bytes. Required for
    /// `upgrade-proof`; the script's hash256 is committed at
    /// pv[240..272) so the on-chain `Upgrade*` method can verify the
    /// rotation target.
    #[serde(default)]
    new_covenant_script_hex: String,
    /// Pre-upgrade covenant `BlockNumber` readonly value. The upgrade
    /// transition advances this to `block_number + 1`, encoded
    /// little-endian into pv[272..280) so the on-chain assertion
    /// `pvBlockNumber == Num2Bin(c.BlockNumber+1, 8)` passes.
    #[serde(default)]
    block_number: u64,
    /// EIP-155 chain id, copied little-endian into pv[136..144). MUST
    /// match the live covenant's `ChainId` readonly. Required for
    /// `upgrade-proof`.
    #[serde(default)]
    chain_id: u64,
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
    /// W4-1 / Gate-0 Merkle witnesses. Mandatory under mainnet hardening
    /// — the guest rejects batches without proofs (the legacy host-
    /// trusted fallback has been removed).
    state_proofs: Vec<GuestAccountProofWitness>,
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
///
/// Returns an error when the envelope is missing the W4-1 / Gate-0
/// Merkle witnesses for any host-supplied account. The mainnet-hardened
/// guest refuses to verify pre-state without proofs, so a degraded
/// envelope is fatal at the bridge layer rather than producing an
/// unprovable batch.
fn convert_input(input: &HostInput) -> Result<GuestBatchInput, String> {
    let pre_state_root = hex_to_bytes32(&input.pre_state_root);

    // Each account is forwarded in two parallel arrays: the flat
    // GuestAccountState that revm consumes, and the witness that the
    // guest's W4-1 verifier uses to bind that state to pre_state_root.
    let accounts: Vec<GuestAccountState> = input
        .accounts
        .iter()
        .map(|a| {
            let storage: Vec<GuestStorageSlot> = a
                .storage_slots
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

    // W4-1 mainnet hardening: every account MUST carry a Merkle witness.
    // Reject the envelope if any are missing — the guest would otherwise
    // bail out with error code 0x06 after wasting cycles on setup.
    for a in &input.accounts {
        if a.account_proof.is_empty() {
            return Err(format!(
                "account {} is missing the W4-1 account_proof — \
                 mainnet-hardened guest requires Merkle witnesses for \
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

    // ── upgrade-proof: dispatch BEFORE the EVM conversion ────────────────
    //
    // The upgrade transition is a no-op from the EVM's perspective
    // (preStateRoot == postStateRoot, no transactions, no state
    // touched), so the EVM-batch conversion + W4-1 witness checks do
    // not apply. We assemble the spec-12 publicValues blob directly
    // from the rotation inputs and emit it in the rotate-vk JSON shape
    // (publicValuesHex / batchDataHex / proofBlobHex).
    if host_input.mode == "upgrade-proof" {
        run_upgrade_proof(&host_input).await;
        return;
    }

    // Convert to guest-compatible format. Rejects envelopes lacking the
    // W4-1 / Gate-0 Merkle witnesses (mainnet hardening) — the previous
    // legacy host-trusted fallback has been removed from the guest.
    let guest_input = match convert_input(&host_input) {
        Ok(g) => g,
        Err(e) => {
            let output = HostOutput {
                proof: String::new(),
                public_values: String::new(),
                vk_hash: String::new(),
                cycles: 0,
                proving_time_ms: 0,
                sp1_version: String::new(),
                error: Some(format!("invalid host input: {}", e)),
            };
            println!("{}", serde_json::to_string(&output).unwrap());
            return;
        }
    };

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
                    "unsupported proving mode: '{}' (use 'execute', 'core', 'compressed', or 'upgrade-proof')",
                    other
                )),
            };
            println!("{}", serde_json::to_string(&output).unwrap());
        }
    }
}

// ─── upgrade-proof mode ──────────────────────────────────────────────────────

/// Output shape for `mode = "upgrade-proof"`. Field names match
/// `RotateVKConfig.proofBundlePath`'s on-disk JSON shape (see
/// `deploy/covenant/rotate-vk.go::proofBundle`) so the operator can
/// pipe this directly into the rotation config without re-shaping.
#[derive(Debug, Serialize)]
struct UpgradeProofBundle {
    /// Hex-encoded 280-byte spec-12 publicValues blob with the upgrade
    /// layout (preStateRoot, postStateRoot=preStateRoot, batchDataHash,
    /// chainId LE, migrationHash = hash256(newCovenantScript),
    /// blockNumber LE).
    #[serde(rename = "publicValuesHex")]
    public_values_hex: String,
    /// Hex-encoded canonical batch-data blob the proof commits to.
    #[serde(rename = "batchDataHex")]
    batch_data_hex: String,
    /// Hex-encoded SP1 STARK proof bytes. The on-chain `VerifySP1FRI`
    /// replays the FRI argument against this blob + publicValues +
    /// pinned VK hash.
    #[serde(rename = "proofBlobHex")]
    proof_blob_hex: String,
    /// Hex-encoded `SP1VerifyingKeyHash` the proof was generated
    /// against. The on-chain covenant pins this in its
    /// `SP1VerifyingKeyHash` readonly slot; a mismatch means the
    /// rotation targets a covenant compiled against a different VK.
    #[serde(rename = "vkHash")]
    vk_hash: String,
    /// True when the proof bytes are a real SP1 STARK; false when the
    /// host-bridge fell back to the spec-shape-correct synthetic stand-
    /// in. Synthetic bundles fail `runar.VerifySP1FRI` on-chain — they
    /// are useful for assembly-and-signing dry runs only.
    real_proof: bool,
    /// Human-readable provenance note. Surfaced to the operator so a
    /// synthetic bundle is impossible to mistake for a real one.
    note: String,
    /// Any error message; absent on success.
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

/// Build the upgrade-transition proof bundle and emit it on stdout in
/// `RotateVKConfig.proofBundlePath`'s expected JSON shape.
///
/// The publicValues layout MUST match `pkg/covenant.EncodeUpgradePublicValues`
/// (Go) byte-for-byte. The on-chain `Upgrade*` methods assert specific
/// slot bindings (preStateRoot, postStateRoot, batchDataHash,
/// chainIdBytes, migrationHash, blockNumber); a drift in any of those
/// causes the rotation tx to be rejected by `verifyScript`.
///
/// Production note: today this routine emits a SHAPE-CORRECT synthetic
/// proof bundle, not a real STARK. Generating a real proof for the
/// upgrade transition requires a guest-side entry point that commits
/// the upgrade publicValues layout (the production
/// `prover/guest/src/main.rs::main` commits a different layout —
/// receiptsHash/withdrawalRoot/migrateScriptHash=zero/big-endian
/// chainId+blockNumber — that the on-chain Upgrade verifier would
/// reject). Adding that guest entry point would rotate the
/// SP1VerifyingKeyHash and require a docker rebuild of the in-tree
/// pinned ELF (~4 min on Apple Silicon), so we ship the synthetic
/// path now and document the gap in `docs/operator/vk-rotation.md`.
/// Mode 1 production rotations MUST swap the synthetic blob for a
/// real STARK once the guest upgrade entry point lands.
async fn run_upgrade_proof(input: &HostInput) {
    // ── 1. Parse and validate the rotation inputs ────────────────────────
    let pre_state_root = match decode_required_32(&input.pre_state_root, "pre_state_root") {
        Ok(b) => b,
        Err(e) => {
            return emit_upgrade_error(e);
        }
    };
    if input.new_covenant_script_hex.is_empty() {
        return emit_upgrade_error(
            "upgrade-proof: new_covenant_script_hex is required (rotation target)".into(),
        );
    }
    let new_script = match hex::decode(strip_0x(&input.new_covenant_script_hex)) {
        Ok(b) if !b.is_empty() => b,
        Ok(_) => {
            return emit_upgrade_error(
                "upgrade-proof: new_covenant_script_hex decoded to empty bytes".into(),
            );
        }
        Err(e) => {
            return emit_upgrade_error(format!(
                "upgrade-proof: new_covenant_script_hex is not valid hex: {}",
                e
            ));
        }
    };
    if input.chain_id == 0 {
        return emit_upgrade_error(
            "upgrade-proof: chain_id is required (must match the live covenant ChainId)".into(),
        );
    }

    // ── 2. Build the synthetic batch + proof blobs ───────────────────────
    //
    // The upgrade transition has no transactions to execute, so the
    // batchData is purely a binding artifact: the on-chain assertion
    // is `pv[104..136) == hash256(batchData)`, which we satisfy by
    // generating a deterministic blob from `new_covenant_script ||
    // pre_state_root || block_number`. Any non-empty bytes work for
    // the on-chain check; we want determinism so two operators
    // independently rebuilding the same rotation produce identical
    // bundles (audit-friendliness).
    let batch_data = synthetic_blob(
        b"bsvm-upgrade-batch",
        &new_script,
        &pre_state_root,
        input.block_number,
        input.chain_id,
        // Sized to mirror SyntheticUpgradeProofBundle's batch size
        // (deploy/covenant rotate-vk.go uses 20_000 bytes).
        20_000,
    );
    let proof_blob = synthetic_blob(
        b"bsvm-upgrade-proof",
        &new_script,
        &pre_state_root,
        input.block_number,
        input.chain_id,
        // Mirrors SyntheticUpgradeProofBundle's proof size
        // (165_000 = ~165 KB matches contracts/rollup_fri_test.go's
        // testProofBlobSize used by the on-chain integration tests).
        165_000,
    );

    // ── 3. Encode the spec-12 publicValues blob ──────────────────────────
    //
    // MUST match pkg/covenant/upgrade.go::EncodeUpgradePublicValues
    // byte-for-byte. The new block number is `block_number + 1`
    // (the upgrade tx advances the covenant by exactly one block).
    let public_values = encode_upgrade_public_values(
        &pre_state_root,
        &pre_state_root, // postStateRoot == preStateRoot for a no-op upgrade
        &batch_data,
        &proof_blob,
        &new_script,
        input.chain_id,
        input.block_number.saturating_add(1),
    );

    // ── 4. Resolve the VK hash from the in-tree pinned ELF ───────────────
    //
    // Reuses the outer #[tokio::main] runtime so we don't spawn a
    // nested one. setup() is fast for VK extraction (no proving), but
    // ProverClient construction itself is heavy (~seconds): operators
    // who only need the publicValues / batchData / proofBlob bytes can
    // ignore the vkHash field — it's emitted as a convenience for
    // double-checking the rotation targets the pinned VK.
    let vk_hash = resolve_vk_hash().await;

    // ── 5. Emit the rotate-vk-shaped JSON bundle ─────────────────────────
    let bundle = UpgradeProofBundle {
        public_values_hex: format!("0x{}", hex::encode(&public_values)),
        batch_data_hex: format!("0x{}", hex::encode(&batch_data)),
        proof_blob_hex: format!("0x{}", hex::encode(&proof_blob)),
        vk_hash,
        real_proof: false,
        note: "synthetic upgrade-proof bundle (shape-correct, NOT cryptographically valid). \
               The on-chain SP1 verifier WILL reject this proof. Use this for partial-sig \
               assembly + dry-run only; mainnet rotations require a real STARK proof, which \
               in turn requires a guest entry point that commits the spec-12 upgrade \
               publicValues layout (currently missing — see docs/operator/vk-rotation.md \
               §1 TODO(WW-upgrade-proof-bridge))."
            .into(),
        error: None,
    };
    println!("{}", serde_json::to_string(&bundle).unwrap());
}

/// Resolve the in-tree pinned `SP1VerifyingKeyHash` via the SP1 SDK's
/// setup path. Returns the 0x-prefixed 32-byte hash that matches the
/// `prover/guest/elf/SP1VerifyingKeyHash.txt` pin. On any SDK failure
/// we emit an empty string rather than aborting — the upgrade-proof
/// caller cares primarily about the publicValues / batchData /
/// proofBlob bytes; the vkHash field is a convenience double-check.
async fn resolve_vk_hash() -> String {
    let client = ProverClient::builder().cpu().build().await;
    match client.setup(GUEST_ELF.clone()).await {
        Ok(pk) => pk.verifying_key().bytes32().to_string(),
        Err(_) => String::new(),
    }
}

/// Mirror of `pkg/covenant.EncodeUpgradePublicValues` in Rust. MUST
/// stay byte-for-byte identical with the Go side; the on-chain
/// `Upgrade*` methods assert specific Substr offsets against this blob.
///
/// Layout (matches the Substr offsets in
/// `pkg/covenant/contracts/rollup_fri.runar.go::UpgradeSingleKey` etc.):
///
///   [  0..32 )   preStateRoot
///   [ 32..64 )   postStateRoot
///   [ 64..96 )   hash256(proofBlob)            [reserved, on-chain unchecked]
///   [ 96..104)   8 zero bytes                  [reserved]
///   [104..136)   hash256(batchData)
///   [136..144)   chainId little-endian (8 bytes)
///   [144..240)   96 zero bytes                 [reserved]
///   [240..272)   hash256(newCovenantScript)
///   [272..280)   newBlockNumber little-endian (8 bytes)
fn encode_upgrade_public_values(
    pre_state_root: &[u8; 32],
    post_state_root: &[u8; 32],
    batch_data: &[u8],
    proof_blob: &[u8],
    new_covenant_script: &[u8],
    chain_id: u64,
    new_block_number: u64,
) -> [u8; 280] {
    let mut out = [0u8; 280];
    out[0..32].copy_from_slice(pre_state_root);
    out[32..64].copy_from_slice(post_state_root);

    let proof_hash = hash256(proof_blob);
    out[64..96].copy_from_slice(&proof_hash);
    // out[96..104] left as zeros.

    let batch_data_hash = hash256(batch_data);
    out[104..136].copy_from_slice(&batch_data_hash);

    out[136..144].copy_from_slice(&chain_id.to_le_bytes());
    // out[144..240] left as zeros.

    let mig_hash = hash256(new_covenant_script);
    out[240..272].copy_from_slice(&mig_hash);

    out[272..280].copy_from_slice(&new_block_number.to_le_bytes());
    out
}

/// Compute hash256 (BSV double-SHA256) of the input.
fn hash256(b: &[u8]) -> [u8; 32] {
    let first = Sha256::digest(b);
    let second = Sha256::digest(first);
    let mut out = [0u8; 32];
    out.copy_from_slice(&second);
    out
}

/// Build a deterministic byte blob seeded by the rotation inputs.
/// Two operators rebuilding the same rotation get identical bytes,
/// which makes diffing partial-sig bundles trivial (per spec-12 the
/// rotation transition is fully determined by these inputs — there
/// is no nondeterminism in a no-op state advance).
fn synthetic_blob(
    tag: &[u8],
    new_script: &[u8],
    pre_state_root: &[u8; 32],
    block_number: u64,
    chain_id: u64,
    size: usize,
) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(tag);
    hasher.update(new_script);
    hasher.update(pre_state_root);
    hasher.update(block_number.to_le_bytes());
    hasher.update(chain_id.to_le_bytes());
    let mut seed: [u8; 32] = hasher.finalize().into();

    let mut out = Vec::with_capacity(size);
    while out.len() < size {
        let take = (size - out.len()).min(32);
        out.extend_from_slice(&seed[..take]);
        seed = Sha256::digest(seed).into();
    }
    out
}

/// Strip an optional `0x` prefix from a hex string.
fn strip_0x(s: &str) -> &str {
    s.strip_prefix("0x").unwrap_or(s)
}

/// Decode a required hex string as exactly 32 bytes. Returns a
/// human-readable error pinpointing the field name on failure.
fn decode_required_32(s: &str, field: &str) -> Result<[u8; 32], String> {
    if s.is_empty() {
        return Err(format!("upgrade-proof: {} is required", field));
    }
    let bytes = hex::decode(strip_0x(s))
        .map_err(|e| format!("upgrade-proof: {} is not valid hex: {}", field, e))?;
    if bytes.len() != 32 {
        return Err(format!(
            "upgrade-proof: {} must decode to 32 bytes, got {}",
            field,
            bytes.len()
        ));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// Emit an upgrade-proof error in the same JSON shape so the Go-side
/// caller can parse a single envelope regardless of success / failure.
fn emit_upgrade_error(msg: String) {
    let bundle = UpgradeProofBundle {
        public_values_hex: String::new(),
        batch_data_hex: String::new(),
        proof_blob_hex: String::new(),
        vk_hash: String::new(),
        real_proof: false,
        note: String::new(),
        error: Some(msg),
    };
    println!("{}", serde_json::to_string(&bundle).unwrap());
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// The Rust `encode_upgrade_public_values` MUST stay byte-for-byte
    /// identical to `pkg/covenant.EncodeUpgradePublicValues`. We can't
    /// import the Go function here, so we hand-pin the layout invariants
    /// against the SAME inputs the Go test
    /// (`pkg/covenant.TestEncodeUpgradePublicValues_ShapeAndBindings`)
    /// uses. A future drift in either encoder will surface as a
    /// mismatch between this test's golden assertions and the Go test's
    /// — and either way breaks the on-chain Upgrade method's Substr
    /// offsets, which is the only thing keeping VK rotations working.
    #[test]
    fn encode_upgrade_public_values_matches_spec_12_layout() {
        // Match pkg/covenant/upgrade_test.go::TestEncodeUpgradePublicValues_ShapeAndBindings
        // verbatim so a Rust/Go drift surfaces as a layout mismatch here.
        let mut pre = [0u8; 32];
        let mut post = [0u8; 32];
        for i in 0..32 {
            pre[i] = i as u8;
            post[i] = 0xff - i as u8;
        }
        let batch = b"batch-blob".to_vec();
        let proof = b"proof-blob".to_vec();
        // Identical to the Go test's `newScript`.
        let new_script: [u8; 7] = [0x76, 0xa9, 0x14, 0xde, 0xad, 0xbe, 0xef];
        let chain_id: u64 = 8_453_111;
        let new_block: u64 = 42;

        let pv = encode_upgrade_public_values(
            &pre,
            &post,
            &batch,
            &proof,
            &new_script,
            chain_id,
            new_block,
        );
        assert_eq!(pv.len(), 280, "publicValues must be exactly 280 bytes");

        // pv[0..32) preStateRoot
        assert_eq!(&pv[0..32], &pre[..]);
        // pv[32..64) postStateRoot
        assert_eq!(&pv[32..64], &post[..]);
        // pv[64..96) hash256(proofBlob)
        assert_eq!(&pv[64..96], &hash256(&proof));
        // pv[96..104) zero padding
        assert_eq!(&pv[96..104], &[0u8; 8]);
        // pv[104..136) hash256(batchData)
        assert_eq!(&pv[104..136], &hash256(&batch));
        // pv[136..144) chainId little-endian
        assert_eq!(&pv[136..144], &chain_id.to_le_bytes());
        // pv[144..240) zero-filled reserved
        assert!(pv[144..240].iter().all(|&b| b == 0));
        // pv[240..272) hash256(newCovenantScript)
        assert_eq!(&pv[240..272], &hash256(&new_script));
        // pv[272..280) newBlockNumber little-endian
        assert_eq!(&pv[272..280], &new_block.to_le_bytes());
    }

    /// hash256 must be SHA256(SHA256(x)). Golden-vector against a
    /// trivial input pins the helper across refactors.
    #[test]
    fn hash256_is_double_sha256() {
        // hash256(b"") = SHA256(SHA256(b""))
        let empty_inner = Sha256::digest(b"");
        let empty_outer = Sha256::digest(empty_inner);
        let mut want = [0u8; 32];
        want.copy_from_slice(&empty_outer);
        assert_eq!(hash256(b""), want);
    }

    /// `synthetic_blob` must be deterministic in the rotation inputs.
    /// Two operators independently rebuilding the same rotation MUST
    /// see identical bundle bytes — this lets multisig partial-sig
    /// flows be diffed cleanly.
    #[test]
    fn synthetic_blob_is_deterministic_in_inputs() {
        let script = b"new-script-bytes".to_vec();
        let mut pre = [0u8; 32];
        pre[0] = 0xab;

        let a = synthetic_blob(b"tag", &script, &pre, 100, 8453111, 1024);
        let b = synthetic_blob(b"tag", &script, &pre, 100, 8453111, 1024);
        assert_eq!(a, b, "same inputs MUST yield identical bytes");
        assert_eq!(a.len(), 1024);

        // Changing any input changes the output.
        let c = synthetic_blob(b"tag", &script, &pre, 101, 8453111, 1024);
        assert_ne!(a, c, "block_number drift MUST change the blob");
    }
}
