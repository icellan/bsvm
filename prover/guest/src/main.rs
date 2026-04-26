//! BSVM Guest Program — Full EVM Execution via revm inside SP1 zkVM
//!
//! This is the Milestone 3 guest program that proves correct EVM execution.
//! It runs revm (from bluealloy/revm) inside SP1's RISC-V zkVM to generate
//! a STARK proof covering every opcode, every storage write, every balance
//! transfer, and every gas deduction.
//!
//! Public values layout (280 bytes, spec 12):
//!   [0..32]    preStateRoot
//!   [32..64]   postStateRoot
//!   [64..96]   receiptsHash (keccak256 of RLP-encoded receipts)
//!   [96..104]  gasUsed (uint64 big-endian)
//!   [104..136] batchDataHash (hash256 = SHA256(SHA256(batchData)))
//!   [136..144] chainId (uint64 big-endian)
//!   [144..176] withdrawalRoot (Merkle root of withdrawal hashes, or zeros if none)
//!   [176..208] inboxRootBefore (inbox queue hash before drain, from host)
//!   [208..240] inboxRootAfter (inbox queue hash after drain, from host)
//!   [240..272] migrateScriptHash ([0;32] — reserved for covenant migration)
//!   [272..280] blockNumber (uint64 big-endian) — post-state block number,
//!              bound by the covenant to c.BlockNumber+1 so the proof cannot
//!              be replayed at a different height.

#![no_main]
sp1_zkvm::entrypoint!(main);

mod inbox;
mod mpt;
mod proof_verify;

// `tx` lives in the crate's library facet (see `lib.rs`) so its pure-Rust
// unit tests can run on the host with `cargo test --lib`. Re-exporting
// here lets the binary use it via the same `tx::` path the rest of the
// guest already uses.
use bsvm_guest::tx;

use alloy_primitives::{keccak256, Address, Bytes, B256, U256};
use alloy_rlp::Encodable;
use mpt::{AccountState, EthMPT, StorageSlot, EMPTY_ROOT, KECCAK_EMPTY};
use proof_verify::verify_proof;
use revm::{
    bytecode::Bytecode,
    context::{BlockEnv, CfgEnv, Context, Journal, TxEnv},
    database::{CacheDB, EmptyDB},
    database_interface::DatabaseCommit,
    primitives::hardfork::SpecId,
    state::AccountInfo,
    ExecuteEvm, MainBuilder,
};
use revm_primitives::TxKind;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Chain ID is a compile-time constant, set per shard at build time.
/// This ensures the guest ELF (and therefore the SP1 verifying key)
/// is unique per shard. See spec 12 "Cross-shard proof replay prevention".
const CHAIN_ID: u64 = 8453111;

/// The L2 bridge predeploy address (spec 12: bridge contract at 0x4200...0010).
const BRIDGE_CONTRACT_ADDRESS: Address = Address::new([
    0x42, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x10,
]);

/// Reserved transaction type byte for deposit system transactions.
/// Identified by a 0x7E prefix in the transaction encoding. Deposits
/// are handled as direct state mutations -- NO EVM calls, NO Solidity.
const DEPOSIT_TX_TYPE: u8 = 0x7E;

/// Solidity storage slot 4 in the L2Bridge contract: `totalDeposited`.
/// Updated via direct storage mutation during deposit processing.
const TOTAL_DEPOSITED_SLOT: U256 = U256::from_limbs([4, 0, 0, 0]);

// ─── Input types ─────────────────────────────────────────────────────────────

/// Block context provided by the host.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockContext {
    pub number: u64,
    pub timestamp: u64,
    pub coinbase: Address,
    pub gas_limit: u64,
    pub base_fee: u64,
    pub prev_randao: B256,
}

/// A serialized EVM transaction.
///
/// IMPORTANT (Gate 0 / W4-2): for user-signed transactions (legacy,
/// EIP-2930, EIP-1559) the `from` field is NOT trusted — the guest
/// re-decodes `raw_bytes` and recovers the sender from the signature
/// using SP1's secp256k1 + keccak256 precompiles via
/// `tx::decode_and_recover`. The `to`, `value`, `nonce`, `gas_limit`,
/// `gas_price`, and `max_priority_fee` fields are likewise re-derived
/// from `raw_bytes` by the guest before being fed to revm — that way
/// the proof covers the canonical signed contents end-to-end and a
/// malicious host cannot swap any signed field without invalidating
/// the signature.
///
/// Deposit system transactions (`tx_type = 0x7E`) are the ONE exception:
/// they have no ECDSA signature (the bridge inbox covenant has already
/// verified them on-chain), so the guest uses the host-supplied `from`,
/// `to`, `value`, and `nonce` directly.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvmTransaction {
    /// Transaction type byte. 0x7E = deposit system transaction.
    /// 0x00 = legacy, 0x01 = EIP-2930, 0x02 = EIP-1559.
    pub tx_type: u8,
    /// Sender address. Trusted ONLY for deposit system txs (`tx_type=0x7E`);
    /// IGNORED for all signed user txs (the guest recovers the sender from
    /// `raw_bytes` instead).
    pub from: Address,
    /// The destination address. For non-deposit txs, re-derived from
    /// `raw_bytes`; for deposits, used as-is. None for contract creation.
    pub to: Option<Address>,
    /// The value to transfer in wei. Re-derived from `raw_bytes` for
    /// non-deposit txs; used as-is for deposits.
    pub value: U256,
    /// The transaction data (calldata or init code). Re-derived from
    /// `raw_bytes` for non-deposit txs; ignored for deposits.
    pub data: Vec<u8>,
    /// The nonce of the sender. Re-derived from `raw_bytes` for non-deposit
    /// txs; used as-is for deposits (deposits don't actually consume a
    /// nonce, but the field is retained for wire-format stability).
    pub nonce: u64,
    /// The gas limit for this transaction. Re-derived from `raw_bytes` for
    /// non-deposit txs.
    pub gas_limit: u64,
    /// The gas price (for legacy txs) or max fee per gas (for EIP-1559).
    /// Re-derived from `raw_bytes` for non-deposit txs.
    pub gas_price: u64,
    /// The max priority fee per gas (EIP-1559). 0 for legacy. Re-derived
    /// from `raw_bytes` for non-deposit txs.
    pub max_priority_fee: u64,
    /// The raw RLP-encoded transaction bytes. For non-deposit txs this is
    /// the full signed RLP (legacy `RLP([... v r s])` or `0x{type} ||
    /// RLP([... v r s])` for typed txs); the guest uses these as the
    /// authoritative source for sender + every signed field. Also used by
    /// the batch-data-hash binding (spec 12).
    pub raw_bytes: Vec<u8>,
}

impl EvmTransaction {
    /// Returns true if this is a deposit system transaction (type 0x7E).
    pub fn is_deposit(&self) -> bool {
        self.tx_type == DEPOSIT_TX_TYPE
    }
}

/// One per-account witness shipped from the host so the guest can verify
/// the pre-state root with Merkle proofs (W4-1 / Gate-0). Each witness
/// proves either inclusion (the account exists with the claimed values) or
/// absence (the account is provably not in the trie at `pre_state_root`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountProofWitness {
    /// Account address being proved.
    pub address: Address,
    /// RLP-encoded MPT nodes from the state root down to the account leaf
    /// (or down to the deepest unmatched node, for an exclusion proof).
    pub account_proof: Vec<Vec<u8>>,
    /// Storage trie root claimed for this account. Used as the root for
    /// per-slot proof verification.
    pub storage_root: [u8; 32],
    /// Per-slot witnesses for storage reads against this account.
    pub storage_slots: Vec<StorageProofWitness>,
}

/// Per-storage-slot witness: proves the value of one slot under
/// `storage_root` of the parent `AccountProofWitness`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageProofWitness {
    /// Storage slot key (raw 32-byte slot index).
    pub key: [u8; 32],
    /// Storage slot value (left-padded big-endian u256, 32 bytes). Empty
    /// (== zero) for an exclusion proof.
    pub value: [u8; 32],
    /// RLP-encoded MPT nodes from the storage root down to the value leaf
    /// (or proof of absence).
    pub proof: Vec<Vec<u8>>,
}

/// A pending inbox transaction provided as part of the drain witness.
///
/// Carries both the on-chain RLP (used to recompute the inbox hash chain
/// against `inbox_root_before`) and the pre-decoded EVM tx fields the
/// guest needs to apply it through revm exactly like a user tx. The host
/// is responsible for sender recovery on these — the guest treats them
/// as standard EVM transactions inserted at the head of the batch.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InboxTx {
    /// Pre-decoded EVM fields, ready to feed into revm.
    pub tx: EvmTransaction,
    /// The exact on-chain RLP bytes the inbox covenant hashed (i.e. the
    /// `evmTxRLP` parameter passed to the inbox `Submit` method). Used by
    /// `inbox::verify_and_split` to recompute the queue chain root.
    pub raw_tx_rlp: Vec<u8>,
}

/// Complete batch input from the Go host to the SP1 guest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchInput {
    /// The claimed pre-state root.
    pub pre_state_root: [u8; 32],
    /// The state export: accounts and their storage needed for this batch.
    pub accounts: Vec<AccountState>,
    /// The transactions to execute.
    pub transactions: Vec<EvmTransaction>,
    /// The block context for execution.
    pub block_context: BlockContext,
    /// The inbox queue hash before draining pending inbox transactions.
    /// Claimed by the host; the guest verifies it by recomputing the hash
    /// chain over `inbox_queue` (W4-3, spec 10).
    pub inbox_root_before: [u8; 32],
    /// The full ordered list of currently-queued inbox transactions, exactly
    /// as the on-chain inbox covenant has them. The leading
    /// `inbox_drain_count` entries are applied as part of this batch (at the
    /// HEAD, before user txs); the remainder is carried forward and used to
    /// recompute `inboxRootAfter`.
    ///
    /// Empty vec means the on-chain inbox queue is empty: in that case
    /// `inbox_root_before` MUST equal `hash256(zero32)` (the genesis empty-
    /// chain marker).
    #[serde(default)]
    pub inbox_queue: Vec<InboxTx>,
    /// Number of leading entries from `inbox_queue` to consume in this
    /// batch. Must be `<= inbox_queue.len()`.
    #[serde(default)]
    pub inbox_drain_count: u32,
    /// True when the on-chain `advancesSinceInbox` counter is at the
    /// forced-inclusion threshold and the covenant will REJECT any advance
    /// that doesn't fully drain the queue (spec 10). The guest enforces
    /// this defensively: if set and the host left a non-empty remainder,
    /// the proof is aborted.
    #[serde(default)]
    pub inbox_must_drain_all: bool,
    /// Merkle witnesses that bind every account/storage value the guest
    /// loads to `pre_state_root`. The guest verifies each entry against
    /// the committed root before any opcode executes — this is the
    /// W4-1 / Gate-0 anti-host-trust path mandated by spec 12 §"Verify
    /// the pre-state root".
    ///
    /// MUST cover every entry in `accounts` (one witness per address).
    /// A missing witness is treated as a fatal error (code 0x06): the
    /// host could otherwise hide an account from verification while
    /// still feeding it to revm.
    pub state_proofs: Vec<AccountProofWitness>,
}

/// A simplified receipt for RLP encoding and hashing.
#[derive(Debug, Clone)]
struct Receipt {
    status: bool,
    cumulative_gas_used: u64,
    logs: Vec<Log>,
}

/// A log entry from EVM execution.
#[derive(Debug, Clone)]
struct Log {
    address: Address,
    topics: Vec<B256>,
    data: Vec<u8>,
}

// ─── Main entry point ────────────────────────────────────────────────────────

pub fn main() {
    // ── 1. Read inputs from the SP1 host ─────────────────────────────────
    let input: BatchInput = sp1_zkvm::io::read();

    // ── 2. Load state into revm's CacheDB AND the MPT ────────────────────
    let mut db = CacheDB::new(EmptyDB::default());
    let mut mpt = EthMPT::new();

    // Load each account into both revm's DB and the MPT.
    for account in &input.accounts {
        let code_hash = if account.code.is_empty() {
            KECCAK_EMPTY
        } else {
            account.code_hash
        };

        let info = AccountInfo {
            balance: account.balance,
            nonce: account.nonce,
            code_hash,
            code: if account.code.is_empty() {
                None
            } else {
                Some(Bytecode::new_raw(Bytes::from(account.code.clone())))
            },
        };

        db.insert_account_info(account.address, info);

        // Insert storage slots.
        for slot in &account.storage {
            db.insert_account_storage(account.address, slot.key, slot.value)
                .expect("storage insert failed");
        }
    }

    // Load accounts into the MPT for state root computation.
    mpt.load_accounts(input.accounts.clone());

    // ── 3. Verify the pre-state root matches ─────────────────────────────
    //
    // W4-1 (Gate-0, mainnet hardening): the host MUST ship Merkle
    // witnesses for every accessed account/storage slot, and the guest
    // verifies each against the committed `pre_state_root` before any
    // opcode executes. This is the only binding that prevents a
    // malicious host from feeding the guest fabricated state. See
    // spec 12 §"Verify the pre-state root" and pkg/prover/state_export.go.
    if let Err(code) = verify_pre_state(
        &input.pre_state_root,
        &input.accounts,
        input.state_proofs.as_slice(),
    ) {
        // Error code 0x02..0x06: per-witness proof failure (see
        // verify_pre_state for the code map). The host can detect
        // this by inspecting public values [64..96].
        let mut probe = [0u8; 32];
        probe[0] = code;
        commit_error(code, &input.pre_state_root, &probe);
        return;
    }
    // `mpt` is still loaded so the post-state root can be computed in
    // step 5; it is no longer used for pre-state verification.
    let _ = &mpt;

    // ── 4. Execute each transaction through revm ─────────────────────────
    let mut receipts: Vec<Receipt> = Vec::new();
    let mut cumulative_gas_used: u64 = 0;

    // Build the block environment once (shared across all transactions).
    let block_env = BlockEnv {
        number: U256::from(input.block_context.number),
        timestamp: U256::from(input.block_context.timestamp),
        beneficiary: input.block_context.coinbase,
        gas_limit: input.block_context.gas_limit,
        basefee: input.block_context.base_fee,
        prevrandao: Some(input.block_context.prev_randao),
        ..Default::default()
    };

    // ── 4a. Verify the inbox witness and split the queue ─────────────────
    // The host hands us the full ordered queue and a `drain_count`. We
    // recompute the chain root from the queue and check it equals
    // `inbox_root_before` — this catches a censoring host that withholds
    // a queued tx (W4-3, spec 10). The leading `drain_count` entries are
    // executed at the HEAD of the batch, before user-submitted txs (spec
    // 11, "Inbox Scanning"). The remainder is carried forward and used to
    // recompute `inbox_root_after`.
    let raw_queue: Vec<Vec<u8>> = input
        .inbox_queue
        .iter()
        .map(|t| t.raw_tx_rlp.clone())
        .collect();
    let drain_count_usize = input.inbox_drain_count as usize;
    let inbox_plan = match inbox::verify_and_split(
        &raw_queue,
        &input.inbox_root_before,
        drain_count_usize,
        input.inbox_must_drain_all,
    ) {
        Ok(plan) => plan,
        Err(inbox::InboxError::BeforeRootMismatch) => {
            // Host claimed an inbox_root_before that doesn't match the
            // queue it provided — this is the censorship-resistance gate
            // tripping. Surface the mismatch as a structured error.
            commit_error(0x10, &input.inbox_root_before, &inbox::chain_root(&raw_queue));
            return;
        }
        Err(inbox::InboxError::DrainCountExceedsQueue) => {
            commit_error(0x11, &input.inbox_root_before, &[0u8; 32]);
            return;
        }
        Err(inbox::InboxError::PartialDrainWhileForced) => {
            commit_error(0x12, &input.inbox_root_before, &[0u8; 32]);
            return;
        }
        Err(inbox::InboxError::QueueExceedsCap) => {
            // W4-3 mainnet hardening: the host shipped more than
            // inbox::MAX_INBOX_DRAIN_PER_BATCH queued txs. Surface the
            // observed length in `actual` so the operator can debug the
            // producer-side pagination bug; `expected` carries the cap.
            let mut expected = [0u8; 32];
            let cap_bytes = (inbox::MAX_INBOX_DRAIN_PER_BATCH as u64).to_be_bytes();
            expected[24..32].copy_from_slice(&cap_bytes);
            let mut actual = [0u8; 32];
            let len_bytes = (raw_queue.len() as u64).to_be_bytes();
            actual[24..32].copy_from_slice(&len_bytes);
            commit_error(0x13, &expected, &actual);
            return;
        }
    };
    let inbox_root_after = inbox_plan.root_after;

    // Execute drained inbox txs first (at the HEAD), then the user-
    // submitted batch. Both go through the exact same EVM path — there
    // is no inbox-specific opcode handling on the L2.
    let drained_inbox_txs: Vec<&EvmTransaction> = input
        .inbox_queue
        .iter()
        .take(drain_count_usize)
        .map(|t| &t.tx)
        .collect();
    let user_txs: Vec<&EvmTransaction> = input.transactions.iter().collect();
    let all_txs: Vec<&EvmTransaction> =
        drained_inbox_txs.into_iter().chain(user_txs).collect();

    for tx in all_txs {
        if tx.is_deposit() {
            // ── Deposit system transaction (type 0x7E) ──────────────
            // Direct state mutations, NOT an EVM call. No Solidity code
            // is executed. This matches the Go block executor exactly.
            let recipient = match tx.to {
                Some(addr) => addr,
                None => continue, // malformed deposit — skip
            };

            // 1. Credit recipient balance directly.
            //    Access the CacheDB's account cache to mutate balance.
            {
                let acct = db.cache.accounts.entry(recipient).or_default();
                acct.info.balance = acct.info.balance.wrapping_add(tx.value);
            }

            // 2. Update bridge contract's totalDeposited via direct
            //    storage mutation — identical to the Go executor.
            {
                let bridge_acct = db
                    .cache
                    .accounts
                    .entry(BRIDGE_CONTRACT_ADDRESS)
                    .or_default();
                let current_total = bridge_acct
                    .storage
                    .get(&TOTAL_DEPOSITED_SLOT)
                    .copied()
                    .unwrap_or(U256::ZERO);
                let new_total = current_total.wrapping_add(tx.value);
                bridge_acct.storage.insert(TOTAL_DEPOSITED_SLOT, new_total);
            }

            // Deposit does not consume gas, does not increment nonce.
            // Receipt: status=1, gasUsed=0, logs=[].
            receipts.push(Receipt {
                status: true,
                cumulative_gas_used,
                logs: Vec::new(),
            });
        } else {
            // ── Standard EVM transaction ────────────────────────────
            // Re-decode every signed field — including the sender — from
            // `raw_bytes` so the proof attests to the canonical signed
            // contents. A malicious host cannot swap any signed field
            // (sender, nonce, value, to, data, gas, fees) without
            // invalidating the signature, which `decode_and_recover`
            // detects and reports as a fatal batch error.
            let decoded = match tx::decode_and_recover(&tx.raw_bytes, CHAIN_ID) {
                Ok(d) => d,
                Err(_) => {
                    // A single bad signature invalidates the whole batch
                    // (matches Ethereum block validity). Bail out with a
                    // structured error code; do NOT panic, because panics
                    // produce no proof and stall the pipeline.
                    commit_error(0x20, &[0u8; 32], &[0u8; 32]);
                    return;
                }
            };
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
                chain_id: Some(CHAIN_ID),
                gas_priority_fee: if decoded.max_priority_fee > 0 {
                    Some(decoded.max_priority_fee)
                } else {
                    None
                },
                // EIP-4844: surface blob_versioned_hashes + max_fee_per_blob_gas
                // to the EVM context so BLOBHASH (0x49) returns the correct
                // values during execution. For non-blob txs both fields are
                // zero / empty (set by tx::decode_and_recover).
                blob_hashes: decoded.blob_versioned_hashes.clone(),
                max_fee_per_blob_gas: decoded.blob_fee_cap,
                ..Default::default()
            };

            // Build the EVM context with our current DB state.
            let mut ctx: Context<
                BlockEnv,
                TxEnv,
                CfgEnv,
                CacheDB<EmptyDB>,
                Journal<CacheDB<EmptyDB>>,
                (),
            > = Context::new(db.clone(), SpecId::CANCUN);
            ctx.block = block_env.clone();

            // Build the mainnet EVM.
            let mut evm = ctx.build_mainnet();

            match evm.transact(tx_env) {
                Ok(result_and_state) => {
                    let exec_result = &result_and_state.result;
                    let gas_used = exec_result.gas_used();

                    // Collect logs from the execution result.
                    let logs: Vec<Log> = exec_result
                        .logs()
                        .iter()
                        .map(|log| Log {
                            address: log.address,
                            topics: log.topics().to_vec(),
                            data: log.data.data.to_vec(),
                        })
                        .collect();

                    cumulative_gas_used += gas_used;

                    let receipt = Receipt {
                        status: exec_result.is_success(),
                        cumulative_gas_used,
                        logs,
                    };
                    receipts.push(receipt);

                    // Commit state changes back to the shared database.
                    db.commit(result_and_state.state);
                }
                Err(_) => {
                    // Transaction failed at the EVM level — create a failed receipt.
                    // In Ethereum, failed transactions still consume gas and
                    // are included in the block. Use the signature-derived
                    // gas limit so a malicious host can't inflate it.
                    cumulative_gas_used += decoded.gas_limit;
                    receipts.push(Receipt {
                        status: false,
                        cumulative_gas_used,
                        logs: Vec::new(),
                    });
                }
            }
        }
    }

    // ── 5. Compute post-state root ───────────────────────────────────────
    // Apply all state changes from revm execution to the MPT.
    apply_db_changes_to_mpt(&mut mpt, &db);
    let post_state_root = mpt.root_hash();

    // ── 6. Compute receipts hash ─────────────────────────────────────────
    let receipts_rlp = rlp_encode_receipts(&receipts);
    let receipts_hash: [u8; 32] = keccak256(&receipts_rlp).0;

    // ── 7. Compute batch data hash (hash256 = double-SHA256) ─────────────
    // CRITICAL: Uses hash256 (double-SHA256), NOT keccak256. The BSV
    // covenant must independently verify this hash using native OP_HASH256.
    let batch_data = encode_batch_for_da(&input.transactions, &input.block_context);
    let batch_data_hash = hash256(&batch_data);

    // ── 8. Detect withdrawals from bridge contract logs ────────────────
    // WithdrawalInitiated event topic: keccak256("WithdrawalInitiated(address,uint64,uint64)")
    let withdrawal_event_topic = keccak256(b"WithdrawalInitiated(address,uint64,uint64)");
    let mut withdrawal_hashes: Vec<[u8; 32]> = Vec::new();
    for receipt in &receipts {
        for log in &receipt.logs {
            if log.address == BRIDGE_CONTRACT_ADDRESS
                && !log.topics.is_empty()
                && log.topics[0] == withdrawal_event_topic
            {
                // Extract bsvAddress (20 bytes from topic[1]), satoshiAmount
                // (uint64 from topic[2]), and nonce (uint64 from topic[3]).
                // Topics are left-padded to 32 bytes per ABI encoding.
                if log.topics.len() >= 4 {
                    let bsv_addr = &log.topics[1].0[12..32]; // last 20 bytes
                    let amount_bytes = &log.topics[2].0[24..32]; // last 8 bytes (u64 BE)
                    let nonce_bytes = &log.topics[3].0[24..32]; // last 8 bytes (u64 BE)

                    // Compute withdrawal hash: hash256(bsvAddr || amount_be || nonce_be)
                    let mut preimage = Vec::with_capacity(36);
                    preimage.extend_from_slice(bsv_addr);
                    preimage.extend_from_slice(amount_bytes);
                    preimage.extend_from_slice(nonce_bytes);
                    withdrawal_hashes.push(hash256(&preimage));
                }
            }
        }
    }

    // Build withdrawal Merkle tree (binary SHA-256).
    let withdrawal_root = build_withdrawal_merkle_root(&withdrawal_hashes);

    // Inbox roots: `inbox_root_before` was independently verified above
    // against the host-supplied queue (W4-3, spec 10). `inbox_root_after`
    // was computed by `inbox::verify_and_split` from the carry-forward
    // remainder. The covenant reads these out of the public-values blob
    // at offsets 176/208 and applies the spec-10 forced-inclusion rule.
    let inbox_root_before = input.inbox_root_before;
    // (`inbox_root_after` already declared above in step 4a.)

    // Migration script hash: reserved for future covenant migration.
    // Currently unused — set to zeros. Will be populated when the Upgrade
    // governance flow is implemented.
    let migration_script_hash: [u8; 32] = [0u8; 32];

    // ── 9. Commit public values (280 bytes, spec 12 layout) ──────────────
    // ORDER MUST MATCH the Public Values Layout table exactly.
    sp1_zkvm::io::commit_slice(&input.pre_state_root); // [0..32]
    sp1_zkvm::io::commit_slice(&post_state_root); // [32..64]
    sp1_zkvm::io::commit_slice(&receipts_hash); // [64..96]
    sp1_zkvm::io::commit_slice(&cumulative_gas_used.to_be_bytes()); // [96..104]
    sp1_zkvm::io::commit_slice(&batch_data_hash); // [104..136]
    sp1_zkvm::io::commit_slice(&CHAIN_ID.to_be_bytes()); // [136..144]
    sp1_zkvm::io::commit_slice(&withdrawal_root); // [144..176]
    sp1_zkvm::io::commit_slice(&inbox_root_before); // [176..208]
    sp1_zkvm::io::commit_slice(&inbox_root_after); // [208..240]
    sp1_zkvm::io::commit_slice(&migration_script_hash); // [240..272]
    sp1_zkvm::io::commit_slice(&input.block_context.number.to_be_bytes()); // [272..280]
}

// ─── Helper functions ────────────────────────────────────────────────────────

/// Commit an error code and relevant data as public values, then return.
/// This allows the host to detect the error and retry without the guest
/// panicking (which would produce no proof and stall the pipeline).
fn commit_error(error_code: u8, expected: &[u8; 32], actual: &[u8; 32]) {
    // For error reporting: commit a 280-byte public values block with
    // the error code in a recognizable pattern.
    let mut error_marker = [0u8; 32];
    error_marker[0] = 0xFF; // Error sentinel
    error_marker[1] = error_code;

    // Fill in expected and actual roots for debugging.
    sp1_zkvm::io::commit_slice(expected); // [0..32] pre_state_root (expected)
    sp1_zkvm::io::commit_slice(actual); // [32..64] what we computed
    sp1_zkvm::io::commit_slice(&error_marker); // [64..96] error marker
    sp1_zkvm::io::commit_slice(&0u64.to_be_bytes()); // [96..104]
    sp1_zkvm::io::commit_slice(&[0u8; 32]); // [104..136]
    sp1_zkvm::io::commit_slice(&CHAIN_ID.to_be_bytes()); // [136..144]
    sp1_zkvm::io::commit_slice(&[0u8; 32]); // [144..176]
    sp1_zkvm::io::commit_slice(&[0u8; 32]); // [176..208]
    sp1_zkvm::io::commit_slice(&[0u8; 32]); // [208..240]
    sp1_zkvm::io::commit_slice(&[0u8; 32]); // [240..272]
    sp1_zkvm::io::commit_slice(&0u64.to_be_bytes()); // [272..280] block_number sentinel
}

/// Verify every host-supplied account (and accessed storage slot) against
/// `pre_state_root` using the supplied Merkle witnesses. Returns an error
/// code in the range 0x02..=0x06 on mismatch (see `commit_error` for the
/// reporting layout).
///
/// This is the W4-1 / Gate-0 anti-host-trust check. Without it, the guest
/// would prove "EVM ran on whatever the host claimed" rather than "EVM ran
/// on the actual chain state at pre_state_root".
///
/// Error codes:
///   0x02 — account proof did not reconcile with pre_state_root
///   0x03 — account leaf disagrees with the host-supplied AccountState
///   0x04 — storage proof did not reconcile with the account's storage_root
///   0x05 — storage value disagrees with the host-supplied StorageSlot
///   0x06 — host-supplied account is missing a corresponding witness
///          (the host could otherwise feed unverified state to revm)
fn verify_pre_state(
    pre_state_root: &[u8; 32],
    accounts: &[AccountState],
    witnesses: &[AccountProofWitness],
) -> Result<(), u8> {
    // Coverage check (W4-1 mainnet hardening): every account that the
    // host loads into revm MUST have a matching witness. Without this
    // check, a malicious host could ship `accounts: [forged]` paired
    // with `state_proofs: []` and the rest of the loop would happily
    // verify zero witnesses against `pre_state_root`.
    for acct in accounts {
        if !witnesses.iter().any(|w| w.address == acct.address) {
            return Err(0x06);
        }
    }

    // Build address -> account lookup.
    for w in witnesses {
        let host_acct = accounts.iter().find(|a| a.address == w.address);

        // Verify the account proof against pre_state_root.
        let key = keccak256(w.address.as_slice());
        let proved = match verify_proof(pre_state_root, key.as_slice(), &w.account_proof) {
            Ok(v) => v,
            Err(_) => return Err(0x02),
        };

        match (proved.as_ref(), host_acct) {
            (Some(rlp_account), Some(acct)) => {
                // Inclusion: encode the host-claimed AccountState the same
                // way and demand byte-equality.
                let storage_root_b256 = B256::from(w.storage_root);
                let code_hash = if acct.code.is_empty() {
                    KECCAK_EMPTY
                } else {
                    acct.code_hash
                };
                let mut want = Vec::new();
                AccountRlpView {
                    nonce: acct.nonce,
                    balance: acct.balance,
                    storage_root: storage_root_b256,
                    code_hash,
                }
                .encode(&mut want);

                if rlp_account.as_slice() != want.as_slice() {
                    return Err(0x03);
                }
            }
            (None, None) => {
                // Absent in the trie AND no host claim — fine.
            }
            (None, Some(acct)) => {
                // Host claims an account, but the trie says it's absent.
                // This is only OK if the host claim is the empty-account
                // sentinel (nonce=0, balance=0, no code, no storage).
                let is_empty = acct.nonce == 0
                    && acct.balance.is_zero()
                    && acct.code.is_empty()
                    && acct.storage.is_empty()
                    && (acct.code_hash == KECCAK_EMPTY || acct.code_hash == B256::ZERO);
                if !is_empty {
                    return Err(0x03);
                }
            }
            (Some(_), None) => {
                // Trie has data but host omitted the account. Treat as a
                // mismatch — the prover MUST surface every read it made.
                return Err(0x03);
            }
        }

        // Verify each storage slot proof against the account's storage_root.
        // For an absent account, storage_root MUST be EMPTY_ROOT and any
        // accessed slot MUST be a proof of absence (value = 0).
        let storage_root = if proved.is_some() {
            w.storage_root
        } else {
            EMPTY_ROOT.0
        };

        for s in &w.storage_slots {
            let slot_key = keccak256(s.key);
            let proved_value = match verify_proof(&storage_root, slot_key.as_slice(), &s.proof) {
                Ok(v) => v,
                Err(_) => return Err(0x04),
            };

            // The host-claimed value (32-byte big-endian U256, possibly zero).
            let host_value_u256 = U256::from_be_bytes(s.value);

            match proved_value {
                Some(raw_value) => {
                    // The MPT proof verifier returns the *unwrapped* leaf
                    // value bytes. For the storage trie that is the trimmed
                    // big-endian U256 (without leading zero bytes). Re-pad
                    // and compare numerically against the host claim.
                    if raw_value.len() > 32 {
                        return Err(0x05);
                    }
                    let mut padded = [0u8; 32];
                    padded[32 - raw_value.len()..].copy_from_slice(&raw_value);
                    let trie_value = U256::from_be_bytes(padded);
                    if trie_value != host_value_u256 {
                        return Err(0x05);
                    }
                }
                None => {
                    // Trie says slot is absent => value MUST be zero.
                    if !host_value_u256.is_zero() {
                        return Err(0x05);
                    }
                }
            }
        }
    }
    Ok(())
}

/// RLP view of an Ethereum account (matches geth and `pkg/mpt`).
#[derive(alloy_rlp::RlpEncodable)]
struct AccountRlpView {
    nonce: u64,
    balance: U256,
    storage_root: B256,
    code_hash: B256,
}

/// Apply state changes from revm's CacheDB back to the MPT.
///
/// After revm executes transactions, the CacheDB contains the updated
/// account states. We extract these and update the MPT to compute the
/// correct post-state root.
fn apply_db_changes_to_mpt(mpt: &mut EthMPT, db: &CacheDB<EmptyDB>) {
    for (address, db_account) in db.cache.accounts.iter() {
        let info = &db_account.info;

        // Collect storage from the DB account.
        let storage: Vec<StorageSlot> = db_account
            .storage
            .iter()
            .map(|(key, value)| StorageSlot {
                key: *key,
                value: *value,
            })
            .collect();

        let code_hash = if info.code_hash == B256::ZERO || info.code.is_none() {
            KECCAK_EMPTY
        } else {
            info.code_hash
        };

        let code: Vec<u8> = match &info.code {
            Some(bytecode) => bytecode.bytes().to_vec(),
            None => Vec::new(),
        };

        let account_state = AccountState {
            address: *address,
            nonce: info.nonce,
            balance: info.balance,
            code_hash,
            code,
            storage,
        };

        mpt.update_account(account_state);
    }
}

/// RLP-encode a list of receipts for hashing.
///
/// Each receipt is encoded as: RLP([status, cumulativeGasUsed, logsBloom, logs])
/// The receipts list is then RLP-encoded as a list.
fn rlp_encode_receipts(receipts: &[Receipt]) -> Vec<u8> {
    let mut encoded_receipts: Vec<Vec<u8>> = Vec::new();

    for receipt in receipts {
        let mut receipt_fields = Vec::new();

        // Status: 1 for success, 0 for failure.
        let status: u8 = if receipt.status { 1 } else { 0 };
        alloy_rlp::Encodable::encode(&status, &mut receipt_fields);

        // Cumulative gas used.
        alloy_rlp::Encodable::encode(&receipt.cumulative_gas_used, &mut receipt_fields);

        // Compute the Ethereum logs bloom for this receipt's logs.
        let logs_bloom = compute_logs_bloom(&receipt.logs);
        alloy_rlp::Encodable::encode(&logs_bloom.as_ref(), &mut receipt_fields);

        // Encode logs as a list.
        let mut logs_encoded = Vec::new();
        for log in &receipt.logs {
            let mut log_fields = Vec::new();
            // Address
            alloy_rlp::Encodable::encode(&log.address, &mut log_fields);
            // Topics as a list
            let mut topics_encoded = Vec::new();
            for topic in &log.topics {
                alloy_rlp::Encodable::encode(topic, &mut topics_encoded);
            }
            // Wrap topics in a list header
            let topics_list = rlp_list(&topics_encoded);
            log_fields.extend_from_slice(&topics_list);
            // Data
            alloy_rlp::Encodable::encode(&log.data.as_slice(), &mut log_fields);
            // Wrap log fields in a list header
            let log_rlp = rlp_list(&log_fields);
            logs_encoded.extend_from_slice(&log_rlp);
        }
        let logs_list = rlp_list(&logs_encoded);
        receipt_fields.extend_from_slice(&logs_list);

        // Wrap receipt fields in a list header.
        let receipt_rlp = rlp_list(&receipt_fields);
        encoded_receipts.push(receipt_rlp);
    }

    // Concatenate all encoded receipts and wrap in a list header.
    let mut all_receipts = Vec::new();
    for r in &encoded_receipts {
        all_receipts.extend_from_slice(r);
    }
    rlp_list(&all_receipts)
}

/// Encode data with an RLP list header.
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

/// Convert a usize to its minimal big-endian byte representation.
fn to_min_bytes(val: usize) -> Vec<u8> {
    if val == 0 {
        return vec![0];
    }
    let bytes = val.to_be_bytes();
    let first_nonzero = bytes.iter().position(|&b| b != 0).unwrap_or(0);
    bytes[first_nonzero..].to_vec()
}

/// Encode the batch data for data availability binding.
///
/// The batch data is the concatenation of all raw transaction bytes
/// prefixed with block context, matching the Go host's encoding.
fn encode_batch_for_da(transactions: &[EvmTransaction], block_ctx: &BlockContext) -> Vec<u8> {
    let mut data = Vec::new();

    // Block context prefix.
    data.extend_from_slice(&block_ctx.number.to_be_bytes());
    data.extend_from_slice(&block_ctx.timestamp.to_be_bytes());
    data.extend_from_slice(block_ctx.coinbase.as_slice());
    data.extend_from_slice(&block_ctx.gas_limit.to_be_bytes());
    data.extend_from_slice(&block_ctx.base_fee.to_be_bytes());

    // Transaction count.
    let tx_count = transactions.len() as u32;
    data.extend_from_slice(&tx_count.to_be_bytes());

    // Each transaction: length-prefixed raw bytes.
    for tx in transactions {
        let tx_len = tx.raw_bytes.len() as u32;
        data.extend_from_slice(&tx_len.to_be_bytes());
        data.extend_from_slice(&tx.raw_bytes);
    }

    data
}

/// Compute hash256 (double-SHA256) as used in Bitcoin/BSV.
///
/// hash256(x) = SHA256(SHA256(x))
///
/// This is used for the batch data hash so the BSV covenant can verify
/// it using native OP_HASH256.
fn hash256(data: &[u8]) -> [u8; 32] {
    let first = sha256(data);
    sha256(&first)
}

/// Compute SHA-256 hash.
///
/// SP1 automatically accelerates this via its SHA-256 precompile.
fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// Build a binary SHA-256 Merkle tree from withdrawal hashes.
/// Returns the root hash, or zeros if empty.
///
/// Algorithm (must stay byte-identical to pkg/bridge/withdrawal.go and
/// pkg/prover/withdrawal_root.go):
///   - Empty list ⇒ bytes32(0)
///   - Single leaf ⇒ that leaf is the root (no extra hashing)
///   - Internal nodes:  SHA256(left || right)   (single-block, NOT hash256)
///   - Odd-sized levels: pad with bytes32(0)    (NOT last-element duplication)
///
/// Bit-identical to:
///   - pkg/bridge/withdrawal.go::BuildWithdrawalMerkleTree (on-chain reference)
///   - pkg/prover/withdrawal_root.go::computeWithdrawalRoot (Go host mirror)
///   - prover/guest-evm/src/main.rs::compute_withdrawal_root (Gate 0b stub)
///
/// Tested by pkg/prover/withdrawal_root_test.go::TestWithdrawalRoot_GoldenAgainstBridge.
fn build_withdrawal_merkle_root(hashes: &[[u8; 32]]) -> [u8; 32] {
    if hashes.is_empty() {
        return [0u8; 32];
    }

    let mut level: Vec<[u8; 32]> = hashes.to_vec();

    if level.len() == 1 {
        return level[0];
    }

    while level.len() > 1 {
        // Zero-pad odd levels (NOT last-leaf duplication).
        if level.len() % 2 != 0 {
            level.push([0u8; 32]);
        }
        let mut next: Vec<[u8; 32]> = Vec::with_capacity(level.len() / 2);
        let mut i = 0;
        while i < level.len() {
            // Internal node: single-block SHA256(left || right), NOT hash256.
            let mut hasher = Sha256::new();
            hasher.update(&level[i]);
            hasher.update(&level[i + 1]);
            let result = hasher.finalize();
            let mut out = [0u8; 32];
            out.copy_from_slice(&result);
            next.push(out);
            i += 2;
        }
        level = next;
    }
    level[0]
}

/// Compute the Ethereum logs bloom for a set of logs.
///
/// The bloom filter is 2048 bits (256 bytes) and uses three hash
/// positions derived from keccak256. Each log's address and topics
/// are added to the bloom.
fn compute_logs_bloom(logs: &[Log]) -> [u8; 256] {
    let mut bloom = [0u8; 256];
    for log in logs {
        bloom_add(&mut bloom, log.address.as_slice());
        for topic in &log.topics {
            bloom_add(&mut bloom, topic.as_slice());
        }
    }
    bloom
}

/// Add data to a bloom filter using three hash positions.
///
/// Each position is derived from consecutive 2-byte pairs of the
/// keccak256 hash of the data, masked to 11 bits (0-2047).
fn bloom_add(bloom: &mut [u8; 256], data: &[u8]) {
    let hash = keccak256(data);
    for i in 0..3 {
        let bit = (((hash[2 * i] as usize) << 8) | (hash[2 * i + 1] as usize)) & 2047;
        bloom[255 - bit / 8] |= 1 << (bit % 8);
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────
//
// As with `inbox::tests` and `proof_verify::tests`, these cases live in a
// `#[cfg(test)]` block alongside the production code. They cannot run on
// the host stable rust toolchain today because the SP1 v6.0.2 SDK pins
// MSRV gates the workspace crates inherit (see docs/decisions/inbox-drain.md
// "D5 / D6"), but they document the contract and run inside the SP1
// testing path when the toolchain catches up. The Go-side tests in
// `pkg/prover/bridge_input_test.go` cover the host-bridge invariant end-
// to-end against the public ProveInput API, which is the binding that
// matters for production.
#[cfg(test)]
mod tests {
    use super::*;

    /// Build an empty `AccountState` for a given address.
    fn empty_acct(addr: Address) -> AccountState {
        AccountState {
            address: addr,
            nonce: 0,
            balance: U256::ZERO,
            code_hash: KECCAK_EMPTY,
            code: Vec::new(),
            storage: Vec::new(),
        }
    }

    /// Build a witness-shaped value pointing at `addr` with no actual
    /// proof data. We never invoke `verify_proof` from these unit tests
    /// — the coverage rule fires before the proof walk on missing
    /// witness, and the empty-accounts path doesn't enter the loop at
    /// all.
    fn empty_witness(addr: Address) -> AccountProofWitness {
        AccountProofWitness {
            address: addr,
            account_proof: Vec::new(),
            storage_root: EMPTY_ROOT.0,
            storage_slots: Vec::new(),
        }
    }

    /// W4-1 mainnet hardening: `state_proofs` may legitimately be empty
    /// only when the host also passes zero accounts. This is the trivial
    /// "empty batch" path — no opcode runs, no state is read, so there
    /// is nothing to prove. `verify_pre_state` exits cleanly.
    #[test]
    fn empty_state_proofs_ok_when_no_accounts() {
        let pre_state_root = [0u8; 32];
        let accounts: Vec<AccountState> = Vec::new();
        let witnesses: Vec<AccountProofWitness> = Vec::new();
        let res = verify_pre_state(&pre_state_root, &accounts, &witnesses);
        assert!(res.is_ok());
    }

    /// Coverage gate: any host-supplied account that has no matching
    /// witness MUST trigger error 0x06. Without this rule a malicious
    /// host could ship a forged account in `accounts` and an empty
    /// `state_proofs` array — the rest of `verify_pre_state` would
    /// happily verify zero witnesses against `pre_state_root` and revm
    /// would then execute against the forged account.
    #[test]
    fn missing_witness_for_account_is_rejected() {
        let pre_state_root = [0u8; 32];
        let addr_a = Address::new([0xAA; 20]);
        let accounts = vec![empty_acct(addr_a)];
        let witnesses: Vec<AccountProofWitness> = Vec::new();
        let err = verify_pre_state(&pre_state_root, &accounts, &witnesses)
            .expect_err("must reject account without matching witness");
        assert_eq!(err, 0x06);
    }

    /// Same coverage gate when ONE of N accounts is missing a witness.
    /// The first uncovered account triggers the rejection.
    #[test]
    fn missing_witness_for_one_of_many_is_rejected() {
        let pre_state_root = [0u8; 32];
        let addr_a = Address::new([0xAA; 20]);
        let addr_b = Address::new([0xBB; 20]);
        let accounts = vec![empty_acct(addr_a), empty_acct(addr_b)];
        // Only addr_a has a witness; addr_b is uncovered.
        let witnesses = vec![empty_witness(addr_a)];
        let err = verify_pre_state(&pre_state_root, &accounts, &witnesses)
            .expect_err("must reject when ANY account lacks a witness");
        assert_eq!(err, 0x06);
    }
}
