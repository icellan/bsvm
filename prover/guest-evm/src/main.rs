//! BSVM Guest EVM — Simplified Balance Transfer
//!
//! This is the Gate 0b Step 4 guest program. It proves a single ETH-style
//! balance transfer inside SP1's zkVM. The full revm-based guest comes in
//! Milestone 3; this version validates the proof pipeline end-to-end with
//! minimal complexity.
//!
//! Public values layout (spec 12, simplified to 112 bytes for Gate 0b):
//!   [0..32]    preStateRoot   (SHA-256 of pre-state)
//!   [32..64]   postStateRoot  (SHA-256 of post-state)
//!   [64..72]   gasUsed        (uint64 big-endian)
//!   [72..104]  batchDataHash  (SHA-256 of batch data)
//!   [104..112] chainId        (uint64 big-endian)

#![no_main]
sp1_zkvm::entrypoint!(main);

use sha2::{Digest, Sha256};
use serde::{Deserialize, Serialize};

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

/// Everything the guest needs to execute and prove a single transfer.
#[derive(Serialize, Deserialize, Debug)]
pub struct BatchInput {
    pub accounts: Vec<Account>,
    pub transfer: Transfer,
    pub chain_id: u64,
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
    assert!(
        accounts[sender_idx].nonce == tx.nonce,
        "nonce mismatch"
    );

    // Validate balance (value + gas cost)
    let gas_cost = tx.gas_limit * tx.gas_price;
    let total_cost = tx
        .value
        .checked_add(gas_cost)
        .expect("total cost overflow");
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

    // ── 6. Commit public values (112 bytes, spec 12 layout) ───────────
    sp1_zkvm::io::commit_slice(&pre_state_root);              // [0..32]
    sp1_zkvm::io::commit_slice(&post_state_root);             // [32..64]
    sp1_zkvm::io::commit_slice(&gas_used.to_be_bytes());      // [64..72]
    sp1_zkvm::io::commit_slice(&batch_data_hash);             // [72..104]
    sp1_zkvm::io::commit_slice(&input.chain_id.to_be_bytes()); // [104..112]
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
