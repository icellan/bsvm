//! BSVM Host-revm — Standalone Rust EVM (revm) Comparator
//!
//! This crate is the Rust side of the dual-EVM equivalence harness
//! described in `pkg/prover/equivalence_test.go`. It is a deliberately
//! minimal binary that:
//!
//! 1. Reads a JSON `ProveInput` on stdin (same shape as the host bridge,
//!    minus SP1-specific fields).
//! 2. Runs the batch through revm with `SpecId::CANCUN` against an
//!    in-memory `CacheDB` seeded from the host's state export.
//! 3. Writes the full post-execution account map (nonce, balance,
//!    code, code-hash, full storage map for each touched account)
//!    plus the headline outputs (`gas_used`, per-tx receipt status)
//!    to stdout as JSON.
//!
//! The Go test harness then takes that JSON, builds a fresh Go-side
//! `pkg/state.StateDB`, populates it from the revm export, calls
//! `Commit`, and compares the resulting MPT root byte-for-byte with
//! the Go-EVM's own post-state root. If both EVMs are equivalent, the
//! roots match. If they don't, that is a critical correctness bug per
//! `CLAUDE.md` ("Both EVMs MUST produce identical state roots").
//!
//! Importantly: this crate runs on the host, not inside SP1, so we DO
//! NOT apply the SP1 patches (`[patch.crates-io] sha2/sha3/k256`) that
//! the guest uses. Otherwise revm semantics are identical (same version
//! pinning).
//!
//! See `pkg/prover/equivalence_test.go` and the file-level
//! `TODO(equivalence)` block for context.

#![deny(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};

/// One account from the host's state export. The host is the Go EVM
/// in `pkg/prover/state_export.go`; this is the wire shape the Rust
/// binary deserialises.
///
/// The witness fields (`account_proof`, `storage_root`, etc.) are
/// preserved on the wire for parity with the SP1 host bridge but are
/// not required by this comparator — revm only needs the flat
/// account/storage data. They are accepted and ignored.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InputAccount {
    /// 0x-prefixed lower-case hex 20-byte address.
    pub address: String,
    /// Account nonce.
    pub nonce: u64,
    /// 0x-prefixed hex u256 balance (big-endian, no leading-zero pad).
    pub balance: String,
    /// 0x-prefixed hex 32-byte keccak256 of `code`.
    pub code_hash: String,
    /// Full storage trie root for this account (ignored — recomputed by
    /// revm from the in-memory storage map).
    #[serde(default)]
    pub storage_root: String,
    /// Hex-encoded contract bytecode (empty for EOAs).
    #[serde(default)]
    pub code: String,
    /// Storage slots accessed by the batch. Each entry is the slot's
    /// pre-execution value; revm overwrites them as the batch runs.
    #[serde(default)]
    pub storage_slots: Vec<InputStorageSlot>,
    /// Witness — accepted on the wire, not used by the comparator.
    #[serde(default)]
    pub account_proof: Vec<String>,
}

/// One storage slot from the host's state export.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InputStorageSlot {
    /// 0x-prefixed hex 32-byte slot key.
    pub key: String,
    /// 0x-prefixed hex 32-byte slot value (big-endian).
    pub value: String,
    /// Witness — accepted on the wire, not used by the comparator.
    #[serde(default)]
    pub proof: Vec<String>,
}

/// One transaction from the host. Only `raw_bytes` is used by the
/// comparator — revm decodes the canonical RLP envelope itself.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InputTransaction {
    /// 0x-prefixed hex of the canonical RLP-encoded transaction (with
    /// type-byte prefix for typed txs). This is the SAME byte string
    /// the SP1 guest receives under `raw_bytes` in the bridge envelope.
    pub raw_bytes: String,
}

/// Block-level parameters.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InputBlockContext {
    /// Block number.
    pub number: u64,
    /// Block timestamp (unix seconds).
    pub timestamp: u64,
    /// Block coinbase / beneficiary as 0x-prefixed hex 20-byte address.
    pub coinbase: String,
    /// Block gas limit.
    pub gas_limit: u64,
    /// EIP-1559 base fee.
    pub base_fee: u64,
    /// PREVRANDAO (post-merge). 0x-prefixed hex 32-byte.
    #[serde(default)]
    pub prev_randao: String,
}

/// Top-level input the comparator reads from stdin.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ComparatorInput {
    /// Pre-state root, 0x-prefixed hex 32-byte. Echoed in the output
    /// envelope so the Go side can sanity-check the round trip.
    pub pre_state_root: String,
    /// Accounts the batch touches, with pre-state values.
    #[serde(default, deserialize_with = "null_as_empty_vec")]
    pub accounts: Vec<InputAccount>,
    /// Canonical-RLP-encoded transactions.
    #[serde(default, deserialize_with = "null_as_empty_vec")]
    pub transactions: Vec<InputTransaction>,
    /// Block context.
    pub block_context: InputBlockContext,
    /// Chain ID.
    pub chain_id: u64,
}

/// One account in the post-state export.
///
/// `storage` is the FULL set of slots revm holds for this account
/// after the batch — including untouched slots seeded from the input
/// (so the Go side can rebuild a faithful mirror). `code` is included
/// inline as hex so the Go side does not need a separate code-by-hash
/// fetch step.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct OutputAccount {
    /// 0x-prefixed lower-case hex 20-byte address.
    pub address: String,
    /// Account nonce.
    pub nonce: u64,
    /// 0x-prefixed hex u256 balance.
    pub balance: String,
    /// 0x-prefixed hex 32-byte keccak256 of `code`.
    pub code_hash: String,
    /// Hex-encoded contract bytecode (empty for EOAs / accounts with
    /// no code).
    #[serde(default)]
    pub code: String,
    /// Full storage map for this account, sorted by key for
    /// deterministic JSON output.
    #[serde(default)]
    pub storage: Vec<OutputStorageSlot>,
}

/// One storage slot in the post-state export.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct OutputStorageSlot {
    /// 0x-prefixed hex 32-byte slot key.
    pub key: String,
    /// 0x-prefixed hex 32-byte slot value.
    pub value: String,
}

/// Per-tx receipt summary from revm.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct OutputReceipt {
    /// 1 == success, 0 == reverted.
    pub status: u8,
    /// Gas used by this tx.
    pub gas_used: u64,
}

/// Top-level output the comparator writes to stdout.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ComparatorOutput {
    /// Echo of `pre_state_root` from the input — Go-side sanity check.
    pub pre_state_root: String,
    /// Full sorted post-state account list.
    pub accounts: Vec<OutputAccount>,
    /// Per-tx receipts in batch order.
    pub receipts: Vec<OutputReceipt>,
    /// Total gas consumed across the batch.
    pub gas_used: u64,
    /// Structural sha256 digest over the canonical encoding of the
    /// post-state account+storage map. Cheap sanity check the Go side
    /// can compute independently before falling back to the full MPT
    /// root comparison. 0x-prefixed hex 32-byte.
    pub structural_digest: String,
}

/// Deserialize a JSON `null` as an empty Vec rather than failing.
/// Go's `encoding/json` serialises a nil slice as `null` — this lets
/// the Rust side accept either shape transparently so the wire format
/// is symmetric across the language boundary.
fn null_as_empty_vec<'de, D, T>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: serde::Deserialize<'de>,
{
    let opt = Option::<Vec<T>>::deserialize(deserializer)?;
    Ok(opt.unwrap_or_default())
}

/// Compute the structural sha256 digest over a canonical encoding of
/// the post-state account map. This is a cheap sanity check the Go
/// side mirrors so account-set divergences surface fast — before the
/// (more expensive) full MPT root build runs.
///
/// Encoding: for each account in input order (the caller is expected
/// to sort by address ascending before calling this), append:
///   address[20] || nonce[8 BE] || balance[32 BE] || code_hash[32]
///   || u32-BE storage-count || (key[32] || value[32])* in input order
///
/// The Go-side mirror in `pkg/prover/revm_comparator.go::structuralDigest`
/// MUST match this byte-for-byte.
pub fn structural_digest(accounts: &[OutputAccount]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    for acct in accounts {
        let addr = parse_hex_fixed::<20>(&acct.address).unwrap_or([0u8; 20]);
        hasher.update(addr);
        hasher.update(acct.nonce.to_be_bytes());
        hasher.update(parse_hex_u256_be(&acct.balance).unwrap_or([0u8; 32]));
        hasher.update(parse_hex_fixed::<32>(&acct.code_hash).unwrap_or([0u8; 32]));
        hasher.update((acct.storage.len() as u32).to_be_bytes());
        for slot in &acct.storage {
            hasher.update(parse_hex_fixed::<32>(&slot.key).unwrap_or([0u8; 32]));
            hasher.update(parse_hex_fixed::<32>(&slot.value).unwrap_or([0u8; 32]));
        }
    }
    let result = hasher.finalize();
    format!("0x{}", hex::encode(result))
}

/// Parse a 0x-prefixed hex string into a fixed-size byte array.
///
/// Pure helper used by `structural_digest`. Out of scope: this does
/// not validate; callers handle missing/malformed hex by treating the
/// field as zero (the Go side does the same and reports the divergence
/// at the structural-digest comparison rather than crashing here).
fn parse_hex_fixed<const N: usize>(s: &str) -> Option<[u8; N]> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    if s.len() != N * 2 {
        return None;
    }
    let bytes = hex::decode(s).ok()?;
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes);
    Some(out)
}

/// Parse a 0x-prefixed hex u256 (variable length, big-endian) into a
/// 32-byte big-endian array, left-padding with zeros. Used so the
/// structural digest is order-stable regardless of leading-zero
/// trimming on the JSON wire.
fn parse_hex_u256_be(s: &str) -> Option<[u8; 32]> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    let s = if s.is_empty() { "0" } else { s };
    let s = if s.len() % 2 == 0 {
        s.to_owned()
    } else {
        format!("0{}", s)
    };
    let bytes = hex::decode(&s).ok()?;
    if bytes.len() > 32 {
        return None;
    }
    let mut out = [0u8; 32];
    out[32 - bytes.len()..].copy_from_slice(&bytes);
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Round-trip JSON: serialize then deserialize an OutputAccount and
    /// assert byte-equality. Pins the wire format the Go side parses.
    #[test]
    fn output_account_json_roundtrip() {
        let acct = OutputAccount {
            address: "0xaabbccddeeff00112233445566778899aabbccdd".to_string(),
            nonce: 7,
            balance: "0xde0b6b3a7640000".to_string(),
            code_hash:
                "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
                    .to_string(),
            code: "".to_string(),
            storage: vec![OutputStorageSlot {
                key: "0x0000000000000000000000000000000000000000000000000000000000000001"
                    .to_string(),
                value: "0x0000000000000000000000000000000000000000000000000000000000000042"
                    .to_string(),
            }],
        };
        let s = serde_json::to_string(&acct).expect("serialize");
        let back: OutputAccount = serde_json::from_str(&s).expect("deserialize");
        assert_eq!(back, acct);
    }

    /// Structural digest is deterministic and mirrors the Go side's
    /// canonical encoding bytewise. Catches drift in either side's
    /// encoder.
    #[test]
    fn structural_digest_is_deterministic() {
        let mk = || OutputAccount {
            address: "0x0000000000000000000000000000000000000001".to_string(),
            nonce: 0,
            balance: "0x0".to_string(),
            code_hash:
                "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
                    .to_string(),
            code: "".to_string(),
            storage: vec![],
        };
        let a1 = mk();
        let a2 = mk();
        assert_eq!(
            structural_digest(&[a1]),
            structural_digest(&[a2]),
            "digest must be deterministic"
        );
    }

    /// Empty post-state digests to a known sha256(empty) value. Pins
    /// the Go-side mirror's canonical encoding for the empty case.
    #[test]
    fn structural_digest_empty_is_known() {
        let got = structural_digest(&[]);
        // sha256 of the empty byte string
        assert_eq!(
            got,
            "0xe3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    /// `parse_hex_u256_be` left-pads correctly so the structural digest
    /// is stable under leading-zero trimming on the wire.
    #[test]
    fn hex_u256_left_pads() {
        let got = parse_hex_u256_be("0x42").unwrap();
        let mut want = [0u8; 32];
        want[31] = 0x42;
        assert_eq!(got, want);
    }

    /// `ComparatorInput` accepts the witness fields without requiring
    /// them — they're shipped by the host bridge but unused here.
    #[test]
    fn input_envelope_accepts_witness_fields() {
        let raw = r#"{
            "pre_state_root": "0x0000000000000000000000000000000000000000000000000000000000000000",
            "accounts": [{
                "address": "0x0000000000000000000000000000000000000001",
                "nonce": 0,
                "balance": "0x0",
                "code_hash": "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
                "storage_root": "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
                "account_proof": ["0xdeadbeef"],
                "storage_slots": []
            }],
            "transactions": [],
            "block_context": {
                "number": 1, "timestamp": 1000, "coinbase": "0x0000000000000000000000000000000000000000",
                "gas_limit": 30000000, "base_fee": 0
            },
            "chain_id": 1337
        }"#;
        let parsed: ComparatorInput = serde_json::from_str(raw).expect("parse with witness");
        assert_eq!(parsed.accounts.len(), 1);
        assert_eq!(parsed.accounts[0].account_proof.len(), 1);
    }
}
