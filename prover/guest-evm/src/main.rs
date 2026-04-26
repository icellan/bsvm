//! BSVM Guest EVM — Simplified Balance Transfer
//!
//! This is the Gate 0b Step 4 guest program. It proves a single ETH-style
//! balance transfer inside SP1's zkVM. The full revm-based guest comes in
//! Milestone 3; this version validates the proof pipeline end-to-end with
//! minimal complexity.
//!
//! Public values layout (Gate 0b stub, 144 bytes):
//!   [0..32]    preStateRoot   (SHA-256 of pre-state)
//!   [32..64]   postStateRoot  (SHA-256 of post-state)
//!   [64..72]   gasUsed        (uint64 big-endian)
//!   [72..104]  batchDataHash  (SHA-256 of batch data)
//!   [104..112] chainId        (uint64 big-endian)
//!   [112..144] withdrawalRoot (binary SHA-256 Merkle root over hash256
//!                              leaves; bytes32(0) when no withdrawals)
//!
//! NOTE on layout: the full revm guest at prover/guest/src/main.rs
//! commits the canonical 280-byte spec-12 layout (with withdrawalRoot at
//! [144..176)). This stub uses an abbreviated 144-byte layout because it
//! omits the unused fields (receiptsHash, inbox roots, migrateScriptHash,
//! blockNumber). The withdrawalRoot computation itself is bit-identical
//! to pkg/bridge/withdrawal.go and the full guest's
//! `build_withdrawal_merkle_root` will be replaced with the same binary
//! SHA-256 + zero-pad scheme to converge on the Go reference.

#![no_main]
sp1_zkvm::entrypoint!(main);

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// A simplified account: address + nonce + balance.
/// Balance is u64 (wei-scale for this gate check; the full guest uses U256).
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Account {
    pub address: [u8; 20],
    pub nonce: u64,
    pub balance: u64,
}

/// A simplified transfer transaction.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Transfer {
    pub from: [u8; 20],
    pub to: [u8; 20],
    pub value: u64,
    pub nonce: u64,
    pub gas_limit: u64,
    pub gas_price: u64,
}

/// A withdrawal record matching the Go reference (pkg/bridge/withdrawal.go).
/// `recipient` is the 20-byte BSV address (RIPEMD160(SHA256(pubkey))).
/// `amount` is satoshis (uint64 BE), `nonce` is the L2-side withdrawal nonce.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct Withdrawal {
    pub recipient: [u8; 20],
    pub amount: u64,
    pub nonce: u64,
}

/// Everything the guest needs to execute and prove a single transfer plus
/// optionally commit a withdrawalRoot.
#[derive(Serialize, Deserialize, Debug)]
pub struct BatchInput {
    pub accounts: Vec<Account>,
    pub transfer: Transfer,
    pub chain_id: u64,
    /// Withdrawals included in this batch. May be empty.
    /// `#[serde(default)]` keeps backward compatibility with hosts that do
    /// not yet send the field.
    #[serde(default)]
    pub withdrawals: Vec<Withdrawal>,
}

pub fn main() {
    // ── 1. Read inputs from host ──────────────────────────────────────
    let input: BatchInput = sp1_zkvm::io::read();

    // ── 2. Compute pre-state root ─────────────────────────────────────
    let pre_state_root = compute_state_root(&input.accounts);

    // ── 3. Execute the transfer ───────────────────────────────────────
    let mut accounts = input.accounts.clone();
    let tx = &input.transfer;

    // Find sender
    let sender_idx = accounts
        .iter()
        .position(|a| a.address == tx.from)
        .expect("sender not found in pre-state");

    // Find recipient
    let recipient_idx = accounts
        .iter()
        .position(|a| a.address == tx.to)
        .expect("recipient not found in pre-state");

    // Validate nonce
    assert!(accounts[sender_idx].nonce == tx.nonce, "nonce mismatch");

    // Validate balance (value + gas cost)
    let gas_cost = tx.gas_limit * tx.gas_price;
    let total_cost = tx.value.checked_add(gas_cost).expect("total cost overflow");
    assert!(
        accounts[sender_idx].balance >= total_cost,
        "insufficient balance"
    );

    // Apply the transfer
    accounts[sender_idx].balance -= total_cost;
    accounts[sender_idx].nonce += 1;
    accounts[recipient_idx].balance += tx.value;

    // Gas used for a simple transfer is always 21000
    let gas_used: u64 = 21000;

    // ── 4. Compute post-state root ────────────────────────────────────
    let post_state_root = compute_state_root(&accounts);

    // ── 5. Compute batch data hash (SHA-256 of the encoded transfer) ──
    let batch_data = encode_transfer(tx);
    let batch_data_hash = sha256(&batch_data);

    // ── 6. Compute withdrawal Merkle root (matches pkg/bridge/withdrawal.go).
    let withdrawal_root = compute_withdrawal_root(&input.withdrawals);

    // ── 7. Commit public values (144 bytes, stub layout) ──────────────
    sp1_zkvm::io::commit_slice(&pre_state_root); // [0..32]
    sp1_zkvm::io::commit_slice(&post_state_root); // [32..64]
    sp1_zkvm::io::commit_slice(&gas_used.to_be_bytes()); // [64..72]
    sp1_zkvm::io::commit_slice(&batch_data_hash); // [72..104]
    sp1_zkvm::io::commit_slice(&input.chain_id.to_be_bytes()); // [104..112]
    sp1_zkvm::io::commit_slice(&withdrawal_root); // [112..144]
}

/// Compute a deterministic state root by sorting accounts by address,
/// concatenating (address || nonce_be || balance_be), and SHA-256 hashing.
fn compute_state_root(accounts: &[Account]) -> [u8; 32] {
    let mut sorted = accounts.to_vec();
    sorted.sort_by_key(|a| a.address);

    let mut data = Vec::new();
    for acct in &sorted {
        data.extend_from_slice(&acct.address);
        data.extend_from_slice(&acct.nonce.to_be_bytes());
        data.extend_from_slice(&acct.balance.to_be_bytes());
    }
    sha256(&data)
}

/// Deterministic encoding of a transfer for batch data hashing.
fn encode_transfer(tx: &Transfer) -> Vec<u8> {
    let mut data = Vec::with_capacity(20 + 20 + 8 + 8 + 8 + 8);
    data.extend_from_slice(&tx.from);
    data.extend_from_slice(&tx.to);
    data.extend_from_slice(&tx.value.to_be_bytes());
    data.extend_from_slice(&tx.nonce.to_be_bytes());
    data.extend_from_slice(&tx.gas_limit.to_be_bytes());
    data.extend_from_slice(&tx.gas_price.to_be_bytes());
    data
}

/// SHA-256 hash. SP1 automatically accelerates this via its SHA-256
/// precompile when running inside the zkVM.
fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// hash256(x) = SHA256(SHA256(x)) — matches BSV's OP_HASH256.
fn hash256(data: &[u8]) -> [u8; 32] {
    sha256(&sha256(data))
}

/// Compute the leaf hash for a withdrawal:
///   hash256(recipient || amount_u64_be || nonce_u64_be)
/// Mirrors pkg/bridge/withdrawal.go::WithdrawalHash exactly.
fn withdrawal_leaf(w: &Withdrawal) -> [u8; 32] {
    let mut buf = Vec::with_capacity(20 + 8 + 8);
    buf.extend_from_slice(&w.recipient);
    buf.extend_from_slice(&w.amount.to_be_bytes());
    buf.extend_from_slice(&w.nonce.to_be_bytes());
    hash256(&buf)
}

/// SHA256(left || right) — single-block internal node.
/// Matches pkg/bridge/withdrawal.go::sha256Pair.
fn sha256_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(left);
    hasher.update(right);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// Build a binary SHA-256 Merkle tree over withdrawal hashes and return
/// the root. Internal nodes are SHA256(left || right) (NOT hash256). Odd
/// levels are padded with the all-zero hash. Empty list returns [0u8; 32].
/// Bit-identical to pkg/bridge/withdrawal.go::BuildWithdrawalMerkleTree.
fn compute_withdrawal_root(withdrawals: &[Withdrawal]) -> [u8; 32] {
    if withdrawals.is_empty() {
        return [0u8; 32];
    }

    let mut level: Vec<[u8; 32]> = withdrawals.iter().map(withdrawal_leaf).collect();

    if level.len() == 1 {
        return level[0];
    }

    while level.len() > 1 {
        if level.len() % 2 != 0 {
            level.push([0u8; 32]);
        }
        let mut next = Vec::with_capacity(level.len() / 2);
        let mut i = 0;
        while i < level.len() {
            next.push(sha256_pair(&level[i], &level[i + 1]));
            i += 2;
        }
        level = next;
    }
    level[0]
}
