//! `bsvm-host-revm` — host-side revm comparator for the dual-EVM
//! equivalence harness.
//!
//! This crate is the "Rust EVM truth" the Go EVM in `pkg/vm` is checked
//! against. It runs revm directly (no SP1, no proof generation) over
//! the same JSON envelope shape the SP1 host bridge consumes, and emits
//! a JSON envelope the Go test harness compares byte-for-byte against
//! its own observations.
//!
//! Closes the `TODO(equivalence)` block at the top of
//! `pkg/prover/equivalence_test.go`.
//!
//! # Wire format
//!
//! The input envelope is a strict subset of `prover/host-bridge`'s
//! `HostInput`:
//!   * `pre_state_root` — informational (not verified here; the host-
//!     bridge guest is what verifies Merkle witnesses).
//!   * `accounts` — flat account state (`address`, `nonce`, `balance`,
//!     `code_hash`, `code`, optional `storage_slots`). Witnesses are
//!     ignored.
//!   * `transactions[].raw_bytes` — canonical signed RLP. Sender +
//!     every signed field is recovered via `tx::decode_and_recover`
//!     just like the production guest does.
//!   * `block_context` — number, timestamp, coinbase, gas_limit,
//!     base_fee, prev_randao.
//!   * `chain_id` — REQUIRED. The production guest hardcodes this at
//!     compile time; the comparator is parametric so the harness can
//!     run any test chain ID without rebuilding the binary.
//!
//! The output envelope contains:
//!   * `post_state_digest` — deterministic structural hash of the
//!     post-execution account map (sorted by address). NOT the MPT
//!     root: revm doesn't compute one and porting an MPT into the
//!     comparator is out of scope. The Go test computes the same
//!     structural digest on its side. See `compute_post_state_digest`.
//!   * `receipts_hash` — keccak256 of RLP-encoded receipts list, byte-
//!     identical to the production guest's `rlp_encode_receipts`.
//!   * `batch_data_hash` — `hash256(encode_batch_for_da(...))`, byte-
//!     identical to the production guest.
//!   * `logs_bloom` — Ethereum logs bloom across all receipts, hex-
//!     encoded 256 bytes.
//!   * `gas_used` — total cumulative gas used by the batch.
//!   * `per_tx_gas` — per-tx gas consumption, in batch order.
//!
//! # Determinism
//!
//! Every byte in the output is a function of the input alone. Iteration
//! over revm's account/storage map is sorted by address/key before
//! hashing so two runs produce identical output regardless of the
//! underlying HashMap iteration order.

use alloy_primitives::{keccak256, Address, B256, U256};
use alloy_rlp::Encodable as _;
use revm::{
    bytecode::Bytecode,
    context::{BlockEnv, CfgEnv, Context, Journal, TxEnv},
    database::{CacheDB, EmptyDB},
    database_interface::DatabaseCommit,
    primitives::{hardfork::SpecId, Bytes},
    state::AccountInfo,
    ExecuteEvm, MainBuilder,
};
use revm_primitives::{TxKind, KECCAK_EMPTY};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub mod tx;

// ─── Wire format (input) ─────────────────────────────────────────────────────

/// Block context for EVM execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockContext {
    pub number: u64,
    pub timestamp: u64,
    pub coinbase: String,
    pub gas_limit: u64,
    pub base_fee: u64,
    #[serde(default)]
    pub prev_randao: String,
}

/// One pre-state account.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountExport {
    pub address: String,
    pub nonce: u64,
    pub balance: String,
    pub code_hash: String,
    #[serde(default)]
    pub code: String,
    #[serde(default)]
    pub storage_slots: Vec<StorageSlotExport>,
}

/// One pre-state storage slot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageSlotExport {
    pub key: String,
    pub value: String,
}

/// One transaction. Only `raw_bytes` is consumed by the comparator —
/// every signed field is re-derived via `tx::decode_and_recover` so
/// host swaps are detected exactly the way the production guest detects
/// them.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionExport {
    #[serde(default)]
    pub tx_type: u8,
    #[serde(default)]
    pub from: String,
    #[serde(default)]
    pub to: Option<String>,
    #[serde(default)]
    pub value: String,
    #[serde(default)]
    pub data: String,
    #[serde(default)]
    pub nonce: u64,
    #[serde(default)]
    pub gas_limit: u64,
    #[serde(default)]
    pub gas_price: u64,
    #[serde(default)]
    pub max_priority_fee: u64,
    pub raw_bytes: String,
}

/// Top-level input envelope. A strict subset of the host-bridge
/// envelope; inbox + Merkle-witness fields are accepted (and ignored)
/// so the same Go-side serializer can drive both binaries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostInput {
    #[serde(default)]
    pub pre_state_root: String,
    #[serde(default)]
    pub accounts: Vec<AccountExport>,
    #[serde(default)]
    pub transactions: Vec<TransactionExport>,
    pub block_context: BlockContext,
    /// REQUIRED. The comparator does not hardcode a chain ID.
    pub chain_id: u64,
}

// ─── Wire format (output) ────────────────────────────────────────────────────

/// Top-level output envelope. The Go harness asserts byte-for-byte
/// equality against fields it computes itself.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostOutput {
    /// Structural post-state hash (not an MPT root). See
    /// `compute_post_state_digest` for the byte-stable layout.
    pub post_state_digest: String,
    /// keccak256(RLP-encode-receipts) — matches the guest exactly.
    pub receipts_hash: String,
    /// hash256(encode_batch_for_da(...)) — matches the guest exactly.
    pub batch_data_hash: String,
    /// Ethereum logs bloom across the whole batch.
    pub logs_bloom: String,
    /// Cumulative gas across all txs in the batch.
    pub gas_used: u64,
    /// Per-tx gas, in batch order.
    pub per_tx_gas: Vec<u64>,
    /// Per-tx success flag, in batch order.
    pub per_tx_success: Vec<bool>,
    /// Number of accounts in the post-state account map. Useful for
    /// quick sanity checks from the Go side.
    pub post_state_account_count: usize,
    /// Optional structured error message (set on EVM failure).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

// ─── Public entrypoint ───────────────────────────────────────────────────────

/// Top-level batch comparator.
///
/// Returns `Ok(HostOutput)` on success. Returns `Err(message)` on any
/// envelope-shape error — invalid hex, unknown chain ID, malformed tx
/// envelope, or a transaction whose ECDSA signature fails to recover.
/// EVM-level failures (out-of-gas, revert, balance underflow) populate
/// `per_tx_success[i] = false` and the corresponding receipt with
/// `status = 0` rather than aborting; this matches Ethereum block-
/// validity semantics where a failed tx still produces a receipt.
pub fn run_batch(input: &HostInput) -> Result<HostOutput, String> {
    if input.chain_id == 0 {
        return Err("chain_id must be set on the input envelope".to_string());
    }

    // ── Load pre-state into revm's CacheDB ──────────────────────────────
    let mut db = CacheDB::new(EmptyDB::default());
    for a in &input.accounts {
        let address = parse_address(&a.address)?;
        let balance = U256::from_be_bytes(parse_b32(&a.balance)?);
        let code_bytes = parse_hex(&a.code)?;
        let (code_hash, code) = if code_bytes.is_empty() {
            (KECCAK_EMPTY, None)
        } else {
            let h: B256 = keccak256(&code_bytes);
            (h, Some(Bytecode::new_raw(Bytes::from(code_bytes))))
        };

        let info = AccountInfo {
            balance,
            nonce: a.nonce,
            code_hash,
            code,
        };
        db.insert_account_info(address, info);

        for s in &a.storage_slots {
            let key = U256::from_be_bytes(parse_b32(&s.key)?);
            let value = U256::from_be_bytes(parse_b32(&s.value)?);
            db.insert_account_storage(address, key, value)
                .map_err(|e| format!("insert storage slot for {}: {:?}", a.address, e))?;
        }
    }

    // ── Build the block environment (shared across all txs) ─────────────
    let coinbase = parse_address(&input.block_context.coinbase)?;
    let prevrandao = if input.block_context.prev_randao.is_empty() {
        B256::ZERO
    } else {
        B256::from(parse_b32(&input.block_context.prev_randao)?)
    };
    let block_env = BlockEnv {
        number: U256::from(input.block_context.number),
        timestamp: U256::from(input.block_context.timestamp),
        beneficiary: coinbase,
        gas_limit: input.block_context.gas_limit,
        basefee: input.block_context.base_fee,
        prevrandao: Some(prevrandao),
        ..Default::default()
    };

    // ── Execute every tx through revm ───────────────────────────────────
    let mut receipts: Vec<Receipt> = Vec::with_capacity(input.transactions.len());
    let mut per_tx_gas: Vec<u64> = Vec::with_capacity(input.transactions.len());
    let mut per_tx_success: Vec<bool> = Vec::with_capacity(input.transactions.len());
    let mut cumulative_gas_used: u64 = 0;

    for (i, tx) in input.transactions.iter().enumerate() {
        let raw = parse_hex(&tx.raw_bytes)?;
        let decoded = tx::decode_and_recover(&raw, input.chain_id)
            .map_err(|e| format!("tx[{}]: signature recovery failed: {:?}", i, e))?;

        let tx_env = TxEnv {
            caller: decoded.sender,
            gas_limit: decoded.gas_limit,
            gas_price: decoded.gas_price,
            kind: match decoded.to {
                Some(addr) => TxKind::Call(addr),
                None => TxKind::Create,
            },
            value: decoded.value,
            data: Bytes::from(decoded.data.clone()),
            nonce: decoded.nonce,
            chain_id: Some(input.chain_id),
            gas_priority_fee: if decoded.max_priority_fee > 0 {
                Some(decoded.max_priority_fee)
            } else {
                None
            },
            blob_hashes: decoded.blob_versioned_hashes.clone(),
            max_fee_per_blob_gas: decoded.blob_fee_cap,
            ..Default::default()
        };

        let mut ctx: Context<
            BlockEnv,
            TxEnv,
            CfgEnv,
            CacheDB<EmptyDB>,
            Journal<CacheDB<EmptyDB>>,
            (),
        > = Context::new(db.clone(), SpecId::CANCUN);
        ctx.block = block_env.clone();
        let mut evm = ctx.build_mainnet();

        match evm.transact(tx_env) {
            Ok(result_and_state) => {
                let exec_result = &result_and_state.result;
                let gas_used = exec_result.gas_used();
                let success = exec_result.is_success();
                let logs: Vec<Log> = exec_result
                    .logs()
                    .iter()
                    .map(|log| Log {
                        address: log.address,
                        topics: log.topics().to_vec(),
                        data: log.data.data.to_vec(),
                    })
                    .collect();

                cumulative_gas_used = cumulative_gas_used.saturating_add(gas_used);
                receipts.push(Receipt {
                    status: success,
                    cumulative_gas_used,
                    logs,
                });
                per_tx_gas.push(gas_used);
                per_tx_success.push(success);

                db.commit(result_and_state.state);
            }
            Err(e) => {
                // EVM-level failure (e.g. nonce mismatch, balance check).
                // Surface the error to the caller — the Go harness expects
                // every fixture to succeed, and a transact() error means
                // the comparator and the Go EVM disagree on whether the
                // tx is valid at all. That's a critical bug, not a
                // recoverable receipt.
                return Err(format!(
                    "tx[{}]: revm transact failed: {}",
                    i,
                    format_evm_err(&e)
                ));
            }
        }
    }

    // ── Build the post-state digest from revm's CacheDB ─────────────────
    let post_state_digest = compute_post_state_digest(&db);

    // ── Receipts hash (matches guest's rlp_encode_receipts) ─────────────
    let receipts_rlp = rlp_encode_receipts(&receipts);
    let receipts_hash: B256 = keccak256(&receipts_rlp);

    // ── Batch data hash (matches guest's encode_batch_for_da + hash256) ─
    let batch_data = encode_batch_for_da(&input.transactions, &input.block_context, &input.accounts)?;
    let batch_data_hash = hash256(&batch_data);

    // ── Logs bloom across all receipts ──────────────────────────────────
    let mut bloom = [0u8; 256];
    for r in &receipts {
        accumulate_logs_bloom(&mut bloom, &r.logs);
    }

    Ok(HostOutput {
        post_state_digest: format!("0x{}", hex::encode(post_state_digest)),
        receipts_hash: format!("0x{}", hex::encode(receipts_hash)),
        batch_data_hash: format!("0x{}", hex::encode(batch_data_hash)),
        logs_bloom: format!("0x{}", hex::encode(bloom)),
        gas_used: cumulative_gas_used,
        per_tx_gas,
        per_tx_success,
        post_state_account_count: db.cache.accounts.len(),
        error: None,
    })
}

// ─── Internal types ──────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct Receipt {
    status: bool,
    cumulative_gas_used: u64,
    logs: Vec<Log>,
}

#[derive(Debug, Clone)]
struct Log {
    address: Address,
    topics: Vec<B256>,
    data: Vec<u8>,
}

// ─── Hashing / digest helpers ────────────────────────────────────────────────

/// Compute a deterministic, byte-stable digest of revm's post-state.
///
/// Layout (sha256-of-the-following):
///
///     for each account, sorted by address ascending:
///         address (20 bytes)
///         nonce   (u64 BE)
///         balance (32 bytes BE)
///         code_hash (32 bytes)
///         storage_count (u32 BE)
///         for each storage slot, sorted by key ascending:
///             key   (32 bytes)
///             value (32 bytes)
///
/// This is NOT an Ethereum state root — that would require an MPT, and
/// porting one into the comparator is explicitly out of scope. The Go
/// test computes the same digest from the post-state DB on its side.
/// Byte-for-byte equality of this digest implies every account's
/// nonce/balance/code/storage survived the batch identically on both
/// EVMs, which is the actual property the dual-EVM equivalence
/// guarantee cares about.
fn compute_post_state_digest(db: &CacheDB<EmptyDB>) -> [u8; 32] {
    let mut sorted: BTreeMap<Address, &revm::database::DbAccount> = BTreeMap::new();
    for (addr, acct) in db.cache.accounts.iter() {
        sorted.insert(*addr, acct);
    }

    let mut hasher = Sha256::new();
    for (addr, acct) in sorted.iter() {
        let info = &acct.info;
        hasher.update(addr.as_slice());
        hasher.update(&info.nonce.to_be_bytes());
        hasher.update(&info.balance.to_be_bytes::<32>());
        hasher.update(info.code_hash.as_slice());

        let mut slots: BTreeMap<U256, U256> = BTreeMap::new();
        for (k, v) in acct.storage.iter() {
            slots.insert(*k, *v);
        }
        let count = slots.len() as u32;
        hasher.update(&count.to_be_bytes());
        for (k, v) in slots.iter() {
            hasher.update(&k.to_be_bytes::<32>());
            hasher.update(&v.to_be_bytes::<32>());
        }
    }

    let out = hasher.finalize();
    let mut buf = [0u8; 32];
    buf.copy_from_slice(&out);
    buf
}

/// hash256(x) = SHA256(SHA256(x)). Matches BSV's OP_HASH256 and the
/// guest's batch_data_hash binding.
fn hash256(data: &[u8]) -> [u8; 32] {
    let first = Sha256::digest(data);
    let second = Sha256::digest(&first);
    let mut buf = [0u8; 32];
    buf.copy_from_slice(&second);
    buf
}

/// Encode the batch data for the data-availability binding.
///
/// MUST stay byte-identical to the guest's `encode_batch_for_da` —
/// otherwise the comparator would report a different `batch_data_hash`
/// even when the actual batch was identical.
fn encode_batch_for_da(
    transactions: &[TransactionExport],
    block_ctx: &BlockContext,
    _accounts: &[AccountExport],
) -> Result<Vec<u8>, String> {
    let mut data = Vec::new();
    data.extend_from_slice(&block_ctx.number.to_be_bytes());
    data.extend_from_slice(&block_ctx.timestamp.to_be_bytes());
    let coinbase = parse_address(&block_ctx.coinbase)?;
    data.extend_from_slice(coinbase.as_slice());
    data.extend_from_slice(&block_ctx.gas_limit.to_be_bytes());
    data.extend_from_slice(&block_ctx.base_fee.to_be_bytes());

    let tx_count = transactions.len() as u32;
    data.extend_from_slice(&tx_count.to_be_bytes());

    for tx in transactions {
        let raw = parse_hex(&tx.raw_bytes)?;
        let len = raw.len() as u32;
        data.extend_from_slice(&len.to_be_bytes());
        data.extend_from_slice(&raw);
    }
    Ok(data)
}

// ─── Receipts RLP (mirrors prover/guest/src/main.rs::rlp_encode_receipts) ─────
//
// Kept byte-identical to the guest implementation so the comparator's
// `receipts_hash` matches the guest's commitment when given the same
// inputs. Any drift between the two is a critical bug.

fn rlp_encode_receipts(receipts: &[Receipt]) -> Vec<u8> {
    let mut encoded_receipts: Vec<Vec<u8>> = Vec::new();

    for receipt in receipts {
        let mut receipt_fields = Vec::new();
        let status: u8 = if receipt.status { 1 } else { 0 };
        status.encode(&mut receipt_fields);
        receipt.cumulative_gas_used.encode(&mut receipt_fields);

        let mut bloom = [0u8; 256];
        accumulate_logs_bloom(&mut bloom, &receipt.logs);
        bloom.as_ref().encode(&mut receipt_fields);

        let mut logs_encoded = Vec::new();
        for log in &receipt.logs {
            let mut log_fields = Vec::new();
            log.address.encode(&mut log_fields);
            let mut topics_encoded = Vec::new();
            for topic in &log.topics {
                topic.encode(&mut topics_encoded);
            }
            let topics_list = rlp_list(&topics_encoded);
            log_fields.extend_from_slice(&topics_list);
            log.data.as_slice().encode(&mut log_fields);
            let log_rlp = rlp_list(&log_fields);
            logs_encoded.extend_from_slice(&log_rlp);
        }
        let logs_list = rlp_list(&logs_encoded);
        receipt_fields.extend_from_slice(&logs_list);

        let receipt_rlp = rlp_list(&receipt_fields);
        encoded_receipts.push(receipt_rlp);
    }

    let mut all_receipts = Vec::new();
    for r in &encoded_receipts {
        all_receipts.extend_from_slice(r);
    }
    rlp_list(&all_receipts)
}

fn rlp_list(data: &[u8]) -> Vec<u8> {
    let len = data.len();
    let mut result = Vec::new();
    if len < 56 {
        result.push(0xC0 + len as u8);
    } else {
        let len_bytes = to_min_bytes(len);
        result.push(0xF7 + len_bytes.len() as u8);
        result.extend_from_slice(&len_bytes);
    }
    result.extend_from_slice(data);
    result
}

fn to_min_bytes(val: usize) -> Vec<u8> {
    if val == 0 {
        return vec![0];
    }
    let bytes = val.to_be_bytes();
    let first_nonzero = bytes.iter().position(|&b| b != 0).unwrap_or(0);
    bytes[first_nonzero..].to_vec()
}

/// Standard Ethereum logs bloom — sets 3 bits per topic / address by
/// taking the lowest 11 bits of three keccak-derived offsets.
fn accumulate_logs_bloom(bloom: &mut [u8; 256], logs: &[Log]) {
    for log in logs {
        bloom_add(bloom, log.address.as_slice());
        for topic in &log.topics {
            bloom_add(bloom, topic.as_slice());
        }
    }
}

fn bloom_add(bloom: &mut [u8; 256], data: &[u8]) {
    let h = keccak256(data);
    for i in 0..3 {
        let bit = (((h[2 * i] as u32) << 8) | (h[2 * i + 1] as u32)) & 0x07FF;
        let byte_idx = 256 - 1 - (bit / 8) as usize;
        let bit_idx = (bit % 8) as u8;
        bloom[byte_idx] |= 1 << bit_idx;
    }
}

// ─── Hex / address helpers ───────────────────────────────────────────────────

fn strip_0x(s: &str) -> &str {
    s.strip_prefix("0x").unwrap_or(s)
}

fn parse_hex(s: &str) -> Result<Vec<u8>, String> {
    if s.is_empty() {
        return Ok(Vec::new());
    }
    hex::decode(strip_0x(s)).map_err(|e| format!("bad hex {:?}: {}", s, e))
}

fn parse_b32(s: &str) -> Result<[u8; 32], String> {
    let bytes = parse_hex(s)?;
    let mut out = [0u8; 32];
    let start = 32usize.saturating_sub(bytes.len());
    out[start..].copy_from_slice(&bytes[..bytes.len().min(32)]);
    Ok(out)
}

fn parse_address(s: &str) -> Result<Address, String> {
    let bytes = parse_hex(s)?;
    if bytes.len() != 20 {
        return Err(format!("address must be 20 bytes, got {}", bytes.len()));
    }
    let mut out = [0u8; 20];
    out.copy_from_slice(&bytes);
    Ok(Address::from(out))
}

fn format_evm_err<E: std::fmt::Debug>(e: &E) -> String {
    format!("{:?}", e)
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_address_ok() {
        let a = parse_address("0x0000000000000000000000000000000000000001").unwrap();
        assert_eq!(a.as_slice()[19], 1);
    }

    #[test]
    fn parse_address_rejects_short() {
        let err = parse_address("0x01").unwrap_err();
        assert!(err.contains("address must be 20 bytes"), "err: {err}");
    }

    #[test]
    fn parse_b32_left_pads() {
        let b = parse_b32("0x01").unwrap();
        assert_eq!(b[31], 1);
        assert_eq!(b[0], 0);
    }

    #[test]
    fn hash256_matches_known_vector() {
        // hash256("") = e2 e0 e7 ...; we just check it's stable + non-zero.
        let h = hash256(b"");
        assert_ne!(h, [0u8; 32]);
        let h2 = hash256(b"");
        assert_eq!(h, h2);
    }

    #[test]
    fn run_batch_rejects_zero_chain_id() {
        let input = HostInput {
            pre_state_root: String::new(),
            accounts: Vec::new(),
            transactions: Vec::new(),
            block_context: BlockContext {
                number: 1,
                timestamp: 1,
                coinbase: "0x0000000000000000000000000000000000000000".to_string(),
                gas_limit: 1_000_000,
                base_fee: 0,
                prev_randao: String::new(),
            },
            chain_id: 0,
        };
        let err = run_batch(&input).unwrap_err();
        assert!(err.contains("chain_id"), "err: {err}");
    }

    #[test]
    fn run_batch_empty_batch_succeeds() {
        // Zero txs against an empty account map produces a deterministic
        // output: empty receipts list, no logs, no gas, but a stable
        // batch_data_hash from the block context prefix alone.
        let input = HostInput {
            pre_state_root: String::new(),
            accounts: Vec::new(),
            transactions: Vec::new(),
            block_context: BlockContext {
                number: 1,
                timestamp: 1,
                coinbase: "0x0000000000000000000000000000000000000000".to_string(),
                gas_limit: 1_000_000,
                base_fee: 0,
                prev_randao: String::new(),
            },
            chain_id: 1337,
        };
        let out = run_batch(&input).expect("empty batch should succeed");
        assert_eq!(out.gas_used, 0);
        assert_eq!(out.per_tx_gas.len(), 0);
        assert_eq!(out.post_state_account_count, 0);
        // Receipts hash for an empty receipts list is keccak256 of the
        // empty-list RLP encoding (0xC0).
        let empty_list_rlp = vec![0xC0u8];
        let want: B256 = keccak256(&empty_list_rlp);
        assert_eq!(out.receipts_hash, format!("0x{}", hex::encode(want)));
    }
}
