//! Ethereum Merkle Patricia Trie (MPT) wrapper for state root computation.
//!
//! Uses `alloy-trie` to compute keccak256-based MPT roots identical to geth.
//! The trie is used to:
//! 1. Verify the pre-state root from Merkle proofs
//! 2. Compute the post-state root after revm execution
//!
//! This wrapper operates on RLP-encoded account data and produces roots
//! that match Ethereum's world state trie specification.

use alloy_primitives::{keccak256, Address, B256, U256};
use alloy_rlp::{Encodable, RlpEncodable};
use alloy_trie::{HashBuilder, Nibbles};
use serde::{Deserialize, Serialize};

/// RLP-encodable Ethereum account for trie insertion.
/// Matches the Ethereum account encoding: [nonce, balance, storageRoot, codeHash].
#[derive(Debug, Clone, RlpEncodable)]
struct AccountRlp {
    nonce: u64,
    balance: U256,
    storage_root: B256,
    code_hash: B256,
}

/// Represents an account's state for trie operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountState {
    pub address: Address,
    pub nonce: u64,
    pub balance: U256,
    pub code_hash: B256,
    pub code: Vec<u8>,
    pub storage: Vec<StorageSlot>,
}

/// A single storage key-value pair.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageSlot {
    pub key: U256,
    pub value: U256,
}

/// Ethereum-compatible Merkle Patricia Trie for state root computation.
///
/// Uses alloy-trie's HashBuilder which produces keccak256-based MPT roots
/// identical to geth's implementation. The trie stores accounts keyed by
/// keccak256(address) and each account's storage trie is keyed by
/// keccak256(slot).
pub struct EthMPT {
    /// Account data indexed by address for state root computation.
    accounts: Vec<AccountState>,
}

/// Empty trie root: keccak256 of the RLP encoding of an empty string.
pub const EMPTY_ROOT: B256 = B256::new([
    0x56, 0xe8, 0x1f, 0x17, 0x1b, 0xcc, 0x55, 0xa6,
    0xff, 0x83, 0x45, 0xe6, 0x92, 0xc0, 0xf8, 0x6e,
    0x5b, 0x48, 0xe0, 0x1b, 0x99, 0x6c, 0xad, 0xc0,
    0x01, 0x62, 0x2f, 0xb5, 0xe3, 0x63, 0xb4, 0x21,
]);

/// Keccak256 of empty byte array — used as code hash for EOAs.
pub const KECCAK_EMPTY: B256 = B256::new([
    0xc5, 0xd2, 0x46, 0x01, 0x86, 0xf7, 0x23, 0x3c,
    0x92, 0x7e, 0x7d, 0xb2, 0xdc, 0xc7, 0x03, 0xc0,
    0xe5, 0x00, 0xb6, 0x53, 0xca, 0x82, 0x27, 0x3b,
    0x7b, 0xfa, 0xd8, 0x04, 0x5d, 0x85, 0xa4, 0x70,
]);

impl EthMPT {
    /// Create a new empty trie.
    pub fn new() -> Self {
        EthMPT {
            accounts: Vec::new(),
        }
    }

    /// Load accounts into the trie from the state export.
    pub fn load_accounts(&mut self, accounts: Vec<AccountState>) {
        self.accounts = accounts;
    }

    /// Update an account in the trie. If the account exists, replace it;
    /// otherwise, insert it.
    pub fn update_account(&mut self, account: AccountState) {
        if let Some(existing) = self.accounts.iter_mut().find(|a| a.address == account.address) {
            *existing = account;
        } else {
            self.accounts.push(account);
        }
    }

    /// Compute the storage trie root for a single account.
    /// Returns EMPTY_ROOT if the account has no storage.
    fn compute_storage_root(storage: &[StorageSlot]) -> B256 {
        if storage.is_empty() {
            return EMPTY_ROOT;
        }

        // Collect non-zero storage entries with their hashed keys.
        let mut entries: Vec<(B256, Vec<u8>)> = Vec::new();
        for slot in storage {
            if slot.value.is_zero() {
                continue;
            }
            // Key: keccak256 of the storage slot index (left-padded to 32 bytes).
            let slot_key = B256::from(slot.key);
            let hashed_key = keccak256(slot_key);

            // Value: RLP-encoded U256 (without leading zeros).
            let mut value_buf = Vec::new();
            // Trim leading zero bytes from U256 for RLP encoding.
            let value_bytes = slot.value.to_be_bytes::<32>();
            let trimmed = trim_leading_zeros(&value_bytes);
            alloy_rlp::Encodable::encode(&trimmed, &mut value_buf);

            entries.push((hashed_key, value_buf));
        }

        if entries.is_empty() {
            return EMPTY_ROOT;
        }

        // Sort by hashed key (this is required for HashBuilder).
        entries.sort_by(|a, b| a.0.cmp(&b.0));

        // Build the storage trie.
        let mut hb = HashBuilder::default();
        for (hashed_key, rlp_value) in &entries {
            let nibbles = Nibbles::unpack(hashed_key);
            hb.add_leaf(nibbles, rlp_value);
        }

        hb.root()
    }

    /// Compute the world state trie root hash.
    ///
    /// This produces a keccak256-based MPT root identical to geth's.
    /// Accounts are keyed by keccak256(address) and encoded as
    /// RLP([nonce, balance, storageRoot, codeHash]).
    pub fn root_hash(&self) -> [u8; 32] {
        if self.accounts.is_empty() {
            return EMPTY_ROOT.0;
        }

        // Compute each account's trie entry.
        let mut entries: Vec<(B256, Vec<u8>)> = Vec::new();
        for account in &self.accounts {
            let hashed_addr = keccak256(account.address);

            // Compute storage root for this account.
            let storage_root = Self::compute_storage_root(&account.storage);

            // Determine code hash.
            let code_hash = if account.code.is_empty() {
                KECCAK_EMPTY
            } else {
                account.code_hash
            };

            // RLP-encode the account.
            let acct_rlp = AccountRlp {
                nonce: account.nonce,
                balance: account.balance,
                storage_root,
                code_hash,
            };
            let mut rlp_buf = Vec::new();
            acct_rlp.encode(&mut rlp_buf);

            entries.push((hashed_addr, rlp_buf));
        }

        // Sort by hashed address (required for HashBuilder).
        entries.sort_by(|a, b| a.0.cmp(&b.0));

        // Build the world state trie.
        let mut hb = HashBuilder::default();
        for (hashed_addr, rlp_account) in &entries {
            let nibbles = Nibbles::unpack(hashed_addr);
            hb.add_leaf(nibbles, &rlp_account);
        }

        hb.root().0
    }
}

/// Trim leading zero bytes from a byte slice.
fn trim_leading_zeros(bytes: &[u8]) -> &[u8] {
    let first_nonzero = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
    if first_nonzero == bytes.len() {
        // Value is zero — return a single zero byte for RLP.
        &[]
    } else {
        &bytes[first_nonzero..]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_trie_root() {
        let mpt = EthMPT::new();
        assert_eq!(mpt.root_hash(), EMPTY_ROOT.0);
    }

    #[test]
    fn test_single_account_root() {
        let mut mpt = EthMPT::new();
        mpt.load_accounts(vec![AccountState {
            address: Address::ZERO,
            nonce: 0,
            balance: U256::ZERO,
            code_hash: KECCAK_EMPTY,
            code: Vec::new(),
            storage: Vec::new(),
        }]);
        let root = mpt.root_hash();
        // Root should be deterministic and non-empty.
        assert_ne!(root, [0u8; 32]);
        assert_ne!(root, EMPTY_ROOT.0);
    }
}
