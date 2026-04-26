//! Ethereum Merkle Patricia Trie proof verifier (W4-1, Gate-0 host trust).
//!
//! This module verifies Merkle Patricia Trie inclusion and exclusion proofs
//! against a committed root hash. It is the security boundary between the
//! SP1 guest and the (untrusted) Go host:
//!
//!   * Without it, the guest TRUSTS the host to ship the correct pre-state
//!     accounts and storage. The STARK then proves only "EVM ran correctly
//!     on whatever state the host claimed."
//!   * With it, the guest verifies every (account, storage_slot) read against
//!     the `pre_state_root` that is later committed as a public value. The
//!     STARK then proves "EVM ran correctly on the actual chain state."
//!
//! Implementation notes
//! --------------------
//! * Pure-Rust. No std dependencies inside the verifier core. Compiles for
//!   SP1's RISC-V target (`riscv32im-succinct-zkvm-elf`).
//! * Uses `alloy_primitives::keccak256`, which the SP1 build patches to
//!   route through the SP1 keccak precompile when running inside the zkVM.
//!   On the host (unit tests) it falls back to the software implementation.
//! * Mirrors `pkg/mpt/proof.go::VerifyProof` byte-for-byte (HP encoding,
//!   compact-to-hex, branch[16] = value, hash references >= 32 bytes,
//!   embedded short references < 32 bytes).
//! * Only verifies — does NOT build a trie. Walking a proof is O(depth).
//! * Returns the value that the proof attests to (or `None` for a valid
//!   proof of absence). Any inconsistency between the proof and `root` is
//!   reported as `ProofError`.

use alloy_primitives::{keccak256, B256};

#[derive(Debug, PartialEq, Eq)]
pub enum ProofError {
    /// A node referenced by the path was not present in the proof.
    MissingNode,
    /// A node's hash did not match the parent's hash reference.
    HashMismatch,
    /// RLP decode failed.
    BadRlp,
    /// The node has an invalid structure (wrong list length, bad tag, ...).
    BadNode,
    /// The proof took an unexpected path (e.g. a branch at an exhausted key).
    BadPath,
}

/// Verify an MPT proof for `key` against `root_hash`. The `proof` slice is a
/// list of RLP-encoded MPT nodes; nodes may appear in any order.
///
/// Returns:
/// * `Ok(Some(value))` — proof of inclusion, value attested by the trie.
/// * `Ok(None)`        — proof of absence, key is provably not in the trie.
/// * `Err(_)`          — the proof is malformed or does not reconcile.
pub fn verify_proof(
    root_hash: &[u8; 32],
    key: &[u8],
    proof: &[Vec<u8>],
) -> Result<Option<Vec<u8>>, ProofError> {
    // Build a content-addressed lookup: keccak256(node) -> &node bytes. A
    // simple linear scan is fine — proofs are O(log N) entries.
    let mut nodes_by_hash: Vec<(B256, Vec<u8>)> = Vec::with_capacity(proof.len());
    for n in proof {
        let h = keccak256(n);
        nodes_by_hash.push((h, n.clone()));
    }

    // Convert the lookup key to nibble form (one nibble per element, 0..16).
    let key_hex = bytes_to_nibbles(key);
    let mut key_pos: usize = 0;

    // Each iteration walks one MPT node. The "current" node is identified
    // either by its hash (via the lookup table) or by its raw bytes when an
    // embedded child was inlined into its parent.
    let mut current: NodeBytes = NodeBytes::Hashed(*root_hash);

    loop {
        let node_bytes: Vec<u8> = match &current {
            NodeBytes::Hashed(h) => match lookup(&nodes_by_hash, h) {
                Some(b) => b.to_vec(),
                None => {
                    // Special case: the canonical empty trie root. A
                    // missing node here is legitimate proof of absence over
                    // an empty trie.
                    if *h == EMPTY_TRIE_ROOT {
                        return Ok(None);
                    }
                    return Err(ProofError::MissingNode);
                }
            },
            NodeBytes::Inline(b) => b.clone(),
        };

        let node = decode_node(&node_bytes)?;

        match node {
            DecodedNode::Branch { children, value } => {
                if key_pos == key_hex.len() {
                    // Key exhausted at a branch — value lives in slot 16.
                    return Ok(value.map(|v| v.to_vec()));
                }
                let nib = key_hex[key_pos] as usize;
                if nib >= 16 {
                    return Err(ProofError::BadPath);
                }
                key_pos += 1;
                current = match &children[nib] {
                    NodeRef::Empty => return Ok(None),
                    NodeRef::Hash(h) => NodeBytes::Hashed(*h),
                    NodeRef::Embedded(b) => NodeBytes::Inline(b.clone()),
                };
            }
            DecodedNode::Leaf { key_nibbles, value } => {
                // Leaf: the remaining nibbles in the lookup key MUST equal
                // the leaf's stored nibbles, otherwise the key is absent.
                let remaining = &key_hex[key_pos..];
                if remaining == key_nibbles.as_slice() {
                    return Ok(Some(value.to_vec()));
                }
                return Ok(None);
            }
            DecodedNode::Extension { key_nibbles, child } => {
                let remaining = &key_hex[key_pos..];
                if !remaining.starts_with(key_nibbles.as_slice()) {
                    return Ok(None);
                }
                key_pos += key_nibbles.len();
                current = match child {
                    NodeRef::Empty => return Ok(None),
                    NodeRef::Hash(h) => NodeBytes::Hashed(h),
                    NodeRef::Embedded(b) => NodeBytes::Inline(b),
                };
            }
        }
    }
}

/// What the verifier loop is currently working on. Either a hash to look up
/// in the proof DB or an inlined child body shorter than 32 bytes.
enum NodeBytes {
    Hashed([u8; 32]),
    Inline(Vec<u8>),
}

fn lookup<'a>(
    nodes_by_hash: &'a [(B256, Vec<u8>)],
    hash: &[u8; 32],
) -> Option<&'a [u8]> {
    for (h, bytes) in nodes_by_hash {
        if h.0 == *hash {
            return Some(bytes.as_slice());
        }
    }
    None
}

// ─── Decoded node representation ─────────────────────────────────────────────

enum DecodedNode<'a> {
    /// 17-element list: 16 children + value-at-this-prefix.
    Branch {
        children: [NodeRef; 16],
        value: Option<&'a [u8]>,
    },
    /// 2-element list with terminator flag set: leaf node carrying a value.
    Leaf {
        key_nibbles: Vec<u8>,
        value: &'a [u8],
    },
    /// 2-element list without terminator flag: extension node forwarding to
    /// another node.
    Extension {
        key_nibbles: Vec<u8>,
        child: NodeRef,
    },
}

#[derive(Clone)]
enum NodeRef {
    Empty,
    Hash([u8; 32]),
    Embedded(Vec<u8>),
}

// ─── RLP decoding ────────────────────────────────────────────────────────────

/// keccak256(rlp("")) — the "no trie" root every empty MPT collapses to.
/// Equal to `pkg/mpt::EMPTY_ROOT` and `geth.types.EmptyRootHash`.
const EMPTY_TRIE_ROOT: [u8; 32] = [
    0x56, 0xe8, 0x1f, 0x17, 0x1b, 0xcc, 0x55, 0xa6, 0xff, 0x83, 0x45, 0xe6, 0x92, 0xc0, 0xf8, 0x6e,
    0x5b, 0x48, 0xe0, 0x1b, 0x99, 0x6c, 0xad, 0xc0, 0x01, 0x62, 0x2f, 0xb5, 0xe3, 0x63, 0xb4, 0x21,
];

/// Decode a raw RLP-encoded MPT node into its semantic form.
///
/// The decoding rules are:
///   * 17-item list → branch (children[0..16] + value-slot)
///   * 2-item list  → leaf (terminator flag set) or extension (cleared)
///
/// Each child slot is one of:
///   * empty string (b"\x80")    — no child
///   * 32-byte string            — hash reference to another node
///   * embedded list (< 32 bytes encoded total) — inlined child node
fn decode_node(bytes: &[u8]) -> Result<DecodedNode<'_>, ProofError> {
    let (list_payload, _payload_len) = rlp_split_list(bytes)?;
    let items = rlp_split_items(list_payload)?;

    match items.len() {
        17 => {
            let mut children: [NodeRef; 16] = Default::default();
            for i in 0..16 {
                children[i] = decode_ref(&items[i])?;
            }
            // Branch's 17th item is the value at this prefix, encoded as a
            // string. An empty string (rlp tag 0x80) means "no value here".
            let value_item = &items[16];
            let value = match value_item.kind {
                ItemKind::String if !value_item.payload.is_empty() => Some(value_item.payload),
                _ => None,
            };
            Ok(DecodedNode::Branch { children, value })
        }
        2 => {
            // First item is the compact-encoded key, second is value or child.
            let key_item = &items[0];
            if key_item.kind != ItemKind::String {
                return Err(ProofError::BadNode);
            }
            let (key_nibbles, terminator) = compact_to_hex(key_item.payload);
            if terminator {
                // Leaf — second item is the raw value.
                let value_item = &items[1];
                if value_item.kind != ItemKind::String {
                    return Err(ProofError::BadNode);
                }
                Ok(DecodedNode::Leaf {
                    key_nibbles,
                    value: value_item.payload,
                })
            } else {
                // Extension — second item is a child reference.
                let child = decode_ref(&items[1])?;
                Ok(DecodedNode::Extension { key_nibbles, child })
            }
        }
        _ => Err(ProofError::BadNode),
    }
}

impl Default for NodeRef {
    fn default() -> Self {
        NodeRef::Empty
    }
}

/// Decode an MPT child reference. A reference is either:
///   * an empty string (no child),
///   * a 32-byte string (hash of another node),
///   * an embedded list that itself is a complete node, < 32 bytes encoded.
fn decode_ref(item: &RlpItem<'_>) -> Result<NodeRef, ProofError> {
    match item.kind {
        ItemKind::String => match item.payload.len() {
            0 => Ok(NodeRef::Empty),
            32 => {
                let mut h = [0u8; 32];
                h.copy_from_slice(item.payload);
                Ok(NodeRef::Hash(h))
            }
            // Other string sizes are invalid for a child reference.
            _ => Err(ProofError::BadNode),
        },
        ItemKind::List => {
            // Embedded child: re-emit the full encoding (header + payload).
            let mut buf = Vec::with_capacity(item.full_len);
            buf.extend_from_slice(&item.header);
            buf.extend_from_slice(item.payload);
            Ok(NodeRef::Embedded(buf))
        }
    }
}

// ─── Minimal RLP split helpers ───────────────────────────────────────────────
//
// We do RLP splitting by hand rather than via `alloy_rlp::Decodable` because
// MPT nodes contain heterogeneous items (mix of strings and lists at the same
// level) and we only need to identify item boundaries — never construct typed
// decoded values.

#[derive(PartialEq, Eq, Clone, Copy)]
enum ItemKind {
    String,
    List,
}

/// One RLP item carved out of a parent payload.
struct RlpItem<'a> {
    kind: ItemKind,
    /// Just the encoded header bytes (1-9 bytes). Useful for re-emitting
    /// embedded children verbatim.
    header: Vec<u8>,
    /// The item's payload, NOT including the header.
    payload: &'a [u8],
    /// Total length consumed by this item in its parent (header + payload).
    full_len: usize,
}

/// Split the top-level list out of a buffer. Returns the payload (the bytes
/// inside the list) and the total bytes consumed.
fn rlp_split_list(bytes: &[u8]) -> Result<(&[u8], usize), ProofError> {
    if bytes.is_empty() {
        return Err(ProofError::BadRlp);
    }
    let tag = bytes[0];
    if tag < 0xC0 {
        return Err(ProofError::BadRlp);
    }
    if tag <= 0xF7 {
        let len = (tag - 0xC0) as usize;
        if bytes.len() < 1 + len {
            return Err(ProofError::BadRlp);
        }
        Ok((&bytes[1..1 + len], 1 + len))
    } else {
        let lol = (tag - 0xF7) as usize;
        if bytes.len() < 1 + lol {
            return Err(ProofError::BadRlp);
        }
        let len = decode_len_be(&bytes[1..1 + lol])?;
        if bytes.len() < 1 + lol + len {
            return Err(ProofError::BadRlp);
        }
        Ok((&bytes[1 + lol..1 + lol + len], 1 + lol + len))
    }
}

/// Walk the items inside a list payload and return the parsed item list.
fn rlp_split_items(mut payload: &[u8]) -> Result<Vec<RlpItem<'_>>, ProofError> {
    let mut items = Vec::with_capacity(17);
    while !payload.is_empty() {
        let (item, rest) = rlp_split_one(payload)?;
        items.push(item);
        payload = rest;
    }
    Ok(items)
}

/// Carve the next RLP item out of a buffer. Returns (item, remaining bytes).
fn rlp_split_one(bytes: &[u8]) -> Result<(RlpItem<'_>, &[u8]), ProofError> {
    if bytes.is_empty() {
        return Err(ProofError::BadRlp);
    }
    let tag = bytes[0];
    if tag < 0x80 {
        // Single-byte string (literal).
        let item = RlpItem {
            kind: ItemKind::String,
            header: Vec::new(),
            payload: &bytes[..1],
            full_len: 1,
        };
        return Ok((item, &bytes[1..]));
    }
    if tag <= 0xB7 {
        let len = (tag - 0x80) as usize;
        if bytes.len() < 1 + len {
            return Err(ProofError::BadRlp);
        }
        let item = RlpItem {
            kind: ItemKind::String,
            header: vec![tag],
            payload: &bytes[1..1 + len],
            full_len: 1 + len,
        };
        return Ok((item, &bytes[1 + len..]));
    }
    if tag <= 0xBF {
        let lol = (tag - 0xB7) as usize;
        if bytes.len() < 1 + lol {
            return Err(ProofError::BadRlp);
        }
        let len = decode_len_be(&bytes[1..1 + lol])?;
        if bytes.len() < 1 + lol + len {
            return Err(ProofError::BadRlp);
        }
        let mut header = Vec::with_capacity(1 + lol);
        header.push(tag);
        header.extend_from_slice(&bytes[1..1 + lol]);
        let item = RlpItem {
            kind: ItemKind::String,
            header,
            payload: &bytes[1 + lol..1 + lol + len],
            full_len: 1 + lol + len,
        };
        return Ok((item, &bytes[1 + lol + len..]));
    }
    if tag <= 0xF7 {
        let len = (tag - 0xC0) as usize;
        if bytes.len() < 1 + len {
            return Err(ProofError::BadRlp);
        }
        let item = RlpItem {
            kind: ItemKind::List,
            header: vec![tag],
            payload: &bytes[1..1 + len],
            full_len: 1 + len,
        };
        return Ok((item, &bytes[1 + len..]));
    }
    // tag in 0xF8..=0xFF: long list.
    let lol = (tag - 0xF7) as usize;
    if bytes.len() < 1 + lol {
        return Err(ProofError::BadRlp);
    }
    let len = decode_len_be(&bytes[1..1 + lol])?;
    if bytes.len() < 1 + lol + len {
        return Err(ProofError::BadRlp);
    }
    let mut header = Vec::with_capacity(1 + lol);
    header.push(tag);
    header.extend_from_slice(&bytes[1..1 + lol]);
    let item = RlpItem {
        kind: ItemKind::List,
        header,
        payload: &bytes[1 + lol..1 + lol + len],
        full_len: 1 + lol + len,
    };
    Ok((item, &bytes[1 + lol + len..]))
}

fn decode_len_be(bytes: &[u8]) -> Result<usize, ProofError> {
    if bytes.is_empty() || bytes.len() > core::mem::size_of::<usize>() {
        return Err(ProofError::BadRlp);
    }
    let mut v: usize = 0;
    for &b in bytes {
        v = (v << 8) | b as usize;
    }
    Ok(v)
}

// ─── Hex Prefix encoding ─────────────────────────────────────────────────────
//
// MPT encodes node keys as "compact" / "hex prefix" form (Yellow Paper).
// First byte:
//   high nibble = (terminator << 1) | (odd_length & 1)
// Lower nibbles follow.

fn compact_to_hex(compact: &[u8]) -> (Vec<u8>, bool) {
    if compact.is_empty() {
        return (Vec::new(), false);
    }
    let first = compact[0];
    let terminator = (first >> 5) & 1 == 1;
    let odd_len = (first >> 4) & 1 == 1;

    let mut nibbles = Vec::with_capacity(2 * (compact.len() - 1) + if odd_len { 1 } else { 0 });
    if odd_len {
        nibbles.push(first & 0x0F);
    }
    for b in &compact[1..] {
        nibbles.push(b >> 4);
        nibbles.push(b & 0x0F);
    }
    (nibbles, terminator)
}

fn bytes_to_nibbles(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(b >> 4);
        out.push(b & 0x0F);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// keccak256("") -- handy for empty-bytecode account checks.
    #[test]
    fn empty_root_constant_matches_geth() {
        // Verify the constant matches keccak256(rlp("")). rlp("") = 0x80.
        let want = keccak256([0x80u8]).0;
        assert_eq!(EMPTY_TRIE_ROOT, want);
    }

    /// Single-leaf trie. Root is keccak256(leaf_rlp), proof is just [leaf].
    #[test]
    fn single_leaf_inclusion_and_absence() {
        // Leaf with key = 0xaabb (hex), value = 0xdeadbeef.
        // Compact-encoded key with terminator+even-length flag: 0x20 || 0xaabb.
        let key_bytes = [0xaa, 0xbb];
        let value: &[u8] = &[0xde, 0xad, 0xbe, 0xef];

        // RLP encode [compact_key, value]:
        // compact_key = 0x20aabb (3 bytes)
        // value = 0x84deadbeef (5 bytes encoded)
        // list payload = 3 + 1 + 4 = 8 bytes? wait — recompute:
        let mut compact_key = vec![0x20u8]; // terminator=1, odd=0, no first nibble
        compact_key.extend_from_slice(&key_bytes);

        let mut leaf_rlp = Vec::new();
        // String header for compact_key (3 bytes payload).
        leaf_rlp.push(0x80 + compact_key.len() as u8);
        leaf_rlp.extend_from_slice(&compact_key);
        // String header for value (4 bytes payload).
        leaf_rlp.push(0x80 + value.len() as u8);
        leaf_rlp.extend_from_slice(value);
        // Wrap in list header.
        let mut node = Vec::new();
        node.push(0xC0 + leaf_rlp.len() as u8);
        node.extend_from_slice(&leaf_rlp);

        let root = keccak256(&node).0;
        let proof = vec![node];

        // Inclusion succeeds.
        let got = verify_proof(&root, &key_bytes, &proof).unwrap();
        assert_eq!(got.as_deref(), Some(value));

        // Absence: a different key under the same root should yield Ok(None)
        // because the leaf's stored nibbles don't match.
        let absent_key = [0xaa, 0xcc];
        let got = verify_proof(&root, &absent_key, &proof).unwrap();
        assert_eq!(got, None);
    }

    /// Empty trie: proof of absence with no nodes succeeds against the
    /// canonical empty-trie root.
    #[test]
    fn empty_trie_absence() {
        let proof: Vec<Vec<u8>> = Vec::new();
        let got = verify_proof(&EMPTY_TRIE_ROOT, &[0xff, 0xee], &proof).unwrap();
        assert_eq!(got, None);
    }

    /// Tampered proof bytes are detected via the hash mismatch.
    #[test]
    fn tampered_proof_detected() {
        let key_bytes = [0xaa, 0xbb];
        let value: &[u8] = &[0xde, 0xad, 0xbe, 0xef];
        let mut compact_key = vec![0x20u8];
        compact_key.extend_from_slice(&key_bytes);

        let mut leaf_rlp = Vec::new();
        leaf_rlp.push(0x80 + compact_key.len() as u8);
        leaf_rlp.extend_from_slice(&compact_key);
        leaf_rlp.push(0x80 + value.len() as u8);
        leaf_rlp.extend_from_slice(value);
        let mut node = Vec::new();
        node.push(0xC0 + leaf_rlp.len() as u8);
        node.extend_from_slice(&leaf_rlp);

        let root = keccak256(&node).0;

        // Flip a byte in the proof — the lookup table will no longer find a
        // node hashing to `root`, so the verifier returns MissingNode.
        let mut tampered = node.clone();
        tampered[node.len() - 1] ^= 0x01;
        let proof = vec![tampered];

        let res = verify_proof(&root, &key_bytes, &proof);
        assert_eq!(res, Err(ProofError::MissingNode));
    }

    /// Wrong root is detected.
    #[test]
    fn wrong_root_detected() {
        let key_bytes = [0xaa, 0xbb];
        let value: &[u8] = &[0xde, 0xad, 0xbe, 0xef];
        let mut compact_key = vec![0x20u8];
        compact_key.extend_from_slice(&key_bytes);

        let mut leaf_rlp = Vec::new();
        leaf_rlp.push(0x80 + compact_key.len() as u8);
        leaf_rlp.extend_from_slice(&compact_key);
        leaf_rlp.push(0x80 + value.len() as u8);
        leaf_rlp.extend_from_slice(value);
        let mut node = Vec::new();
        node.push(0xC0 + leaf_rlp.len() as u8);
        node.extend_from_slice(&leaf_rlp);

        let proof = vec![node];
        let bogus_root = [0u8; 32];

        let res = verify_proof(&bogus_root, &key_bytes, &proof);
        assert_eq!(res, Err(ProofError::MissingNode));
    }

    #[test]
    fn compact_to_hex_decoding() {
        // Even-length leaf: 0x20 || 0xaabb -> nibbles [a,a,b,b], terminator
        let (nib, term) = compact_to_hex(&[0x20, 0xaa, 0xbb]);
        assert_eq!(nib, vec![0xa, 0xa, 0xb, 0xb]);
        assert!(term);

        // Odd-length leaf: 0x3a || 0xbb -> nibbles [a,b,b], terminator
        let (nib, term) = compact_to_hex(&[0x3a, 0xbb]);
        assert_eq!(nib, vec![0xa, 0xb, 0xb]);
        assert!(term);

        // Even-length extension: 0x00 || 0xaabb -> nibbles [a,a,b,b]
        let (nib, term) = compact_to_hex(&[0x00, 0xaa, 0xbb]);
        assert_eq!(nib, vec![0xa, 0xa, 0xb, 0xb]);
        assert!(!term);

        // Odd-length extension: 0x1a || 0xbb -> nibbles [a,b,b]
        let (nib, term) = compact_to_hex(&[0x1a, 0xbb]);
        assert_eq!(nib, vec![0xa, 0xb, 0xb]);
        assert!(!term);
    }

    #[test]
    fn bytes_to_nibbles_basic() {
        assert_eq!(bytes_to_nibbles(&[0xab, 0xcd]), vec![0xa, 0xb, 0xc, 0xd]);
        assert_eq!(bytes_to_nibbles(&[]), Vec::<u8>::new());
    }

    /// Build a leaf node manually: RLP([compact(key, terminator=true), value]).
    fn build_leaf(remaining_nibbles: &[u8], value: &[u8]) -> Vec<u8> {
        let compact = nibbles_to_compact(remaining_nibbles, true);
        let mut payload = Vec::new();
        rlp_string_into(&compact, &mut payload);
        rlp_string_into(value, &mut payload);
        rlp_list_wrap(payload)
    }

    /// Build a branch node by hand: 17 items, children + value-slot.
    fn build_branch(children: [Option<Vec<u8>>; 16], value: Option<&[u8]>) -> Vec<u8> {
        let mut payload = Vec::new();
        for c in &children {
            match c {
                None => payload.push(0x80), // empty string
                Some(b) => {
                    if b.len() < 32 {
                        // Embedded — append the raw node bytes (a list).
                        payload.extend_from_slice(b);
                    } else {
                        // Hash reference — RLP-string of the 32-byte hash.
                        let mut buf = Vec::new();
                        rlp_string_into(&keccak256(b).0, &mut buf);
                        payload.extend_from_slice(&buf);
                    }
                }
            }
        }
        match value {
            None => payload.push(0x80),
            Some(v) => rlp_string_into(v, &mut payload),
        }
        rlp_list_wrap(payload)
    }

    fn rlp_list_wrap(payload: Vec<u8>) -> Vec<u8> {
        let mut out = Vec::with_capacity(payload.len() + 9);
        let len = payload.len();
        if len < 56 {
            out.push(0xC0 + len as u8);
        } else {
            let lol = (len.checked_ilog2().unwrap_or(0) / 8 + 1) as usize;
            out.push(0xF7 + lol as u8);
            for i in (0..lol).rev() {
                out.push(((len >> (8 * i)) & 0xff) as u8);
            }
        }
        out.extend_from_slice(&payload);
        out
    }

    fn rlp_string_into(bytes: &[u8], out: &mut Vec<u8>) {
        let len = bytes.len();
        if len == 1 && bytes[0] < 0x80 {
            out.push(bytes[0]);
            return;
        }
        if len < 56 {
            out.push(0x80 + len as u8);
        } else {
            let lol = (len.checked_ilog2().unwrap_or(0) / 8 + 1) as usize;
            out.push(0xB7 + lol as u8);
            for i in (0..lol).rev() {
                out.push(((len >> (8 * i)) & 0xff) as u8);
            }
        }
        out.extend_from_slice(bytes);
    }

    /// Inverse of compact_to_hex.
    fn nibbles_to_compact(nibbles: &[u8], terminator: bool) -> Vec<u8> {
        let mut out = Vec::with_capacity(nibbles.len() / 2 + 1);
        let term_bit = if terminator { 1 << 5 } else { 0 };
        let odd = nibbles.len() % 2 == 1;
        let first = if odd {
            term_bit | (1 << 4) | nibbles[0]
        } else {
            term_bit
        };
        out.push(first);
        let mut i = if odd { 1 } else { 0 };
        while i < nibbles.len() {
            out.push((nibbles[i] << 4) | nibbles[i + 1]);
            i += 2;
        }
        out
    }

    /// Two-leaf trie under a branch node. Inclusion and exclusion proofs
    /// must both work. This exercises the branch -> embedded leaf case
    /// (both leaves are < 32 bytes RLP, so the branch inlines them rather
    /// than hashing).
    #[test]
    fn branch_with_two_embedded_leaves() {
        // Two keys that share the empty prefix and diverge on the first
        // nibble: 0x10 and 0x20.
        let key_a = [0x10u8];
        let key_b = [0x20u8];
        let val_a: &[u8] = b"A";
        let val_b: &[u8] = b"B";

        // Each leaf consumes one branch slot; remaining nibbles after the
        // branch are the second nibble (0x0).
        let leaf_a = build_leaf(&[0x0], val_a);
        let leaf_b = build_leaf(&[0x0], val_b);

        // Sanity: each leaf must be < 32 bytes so it inlines into the branch.
        assert!(leaf_a.len() < 32);
        assert!(leaf_b.len() < 32);

        let mut children: [Option<Vec<u8>>; 16] = Default::default();
        children[1] = Some(leaf_a.clone());
        children[2] = Some(leaf_b.clone());
        let branch = build_branch(children, None);

        let root = keccak256(&branch).0;
        let proof = vec![branch.clone()];

        // Inclusion proofs.
        let got_a = verify_proof(&root, &key_a, &proof).unwrap();
        assert_eq!(got_a.as_deref(), Some(val_a));
        let got_b = verify_proof(&root, &key_b, &proof).unwrap();
        assert_eq!(got_b.as_deref(), Some(val_b));

        // Exclusion: a key whose first nibble has no entry in the branch.
        let absent = [0x30u8];
        let got = verify_proof(&root, &absent, &proof).unwrap();
        assert_eq!(got, None);

        // Exclusion: same leading nibble as A (1) but different second nibble.
        let absent_same_branch = [0x1fu8];
        let got = verify_proof(&root, &absent_same_branch, &proof).unwrap();
        assert_eq!(got, None);
    }

    /// Branch with one HASHED child (i.e. the leaf's RLP is >= 32 bytes so
    /// the branch stores its hash, not the inline body). Forces the proof
    /// DB lookup path.
    #[test]
    fn branch_with_hashed_leaf() {
        let key = [0x10u8];
        // Big value forces leaf RLP > 32 bytes.
        let value: Vec<u8> = (0..40).collect();
        let leaf = build_leaf(&[0x0], &value);
        assert!(leaf.len() >= 32);

        let mut children: [Option<Vec<u8>>; 16] = Default::default();
        children[1] = Some(leaf.clone());
        let branch = build_branch(children, None);

        let root = keccak256(&branch).0;
        let proof = vec![branch.clone(), leaf.clone()];

        let got = verify_proof(&root, &key, &proof).unwrap();
        assert_eq!(got.as_deref(), Some(value.as_slice()));

        // Tamper with the leaf in the proof DB — should fail to find the
        // child node, surfacing as MissingNode.
        let mut tampered_leaf = leaf.clone();
        let last = tampered_leaf.len() - 1;
        tampered_leaf[last] ^= 0x01;
        let tampered_proof = vec![branch.clone(), tampered_leaf];
        let res = verify_proof(&root, &key, &tampered_proof);
        assert_eq!(res, Err(ProofError::MissingNode));
    }

    /// Extension node forwarding to a hashed branch.
    #[test]
    fn extension_into_branch() {
        // Two leaves sharing a 6-nibble prefix: 0xabcd1_ and 0xabcd2_.
        // The extension stores the shared prefix [a,b,c,d], the branch
        // dispatches on nibble 1 vs 2, then each leaf carries the
        // remaining nibble.
        let val_a: &[u8] = b"AAAA";
        let val_b: &[u8] = b"BBBB";

        // Leaves consume 1 branch slot then carry remaining nibble [0x0].
        let leaf_a = build_leaf(&[0x0], val_a);
        let leaf_b = build_leaf(&[0x0], val_b);

        let mut children: [Option<Vec<u8>>; 16] = Default::default();
        children[1] = Some(leaf_a.clone());
        children[2] = Some(leaf_b.clone());
        let branch = build_branch(children, None);

        // Extension key: nibbles [a,b,c,d] (even length, terminator=false).
        let ext_compact = nibbles_to_compact(&[0xa, 0xb, 0xc, 0xd], false);
        // Extension's child slot stores the branch by reference. Since the
        // branch is likely >= 32 bytes, we use a hash reference.
        let mut ext_payload = Vec::new();
        rlp_string_into(&ext_compact, &mut ext_payload);
        if branch.len() >= 32 {
            rlp_string_into(&keccak256(&branch).0, &mut ext_payload);
        } else {
            ext_payload.extend_from_slice(&branch);
        }
        let ext = rlp_list_wrap(ext_payload);

        let root = keccak256(&ext).0;
        let mut proof = vec![ext.clone()];
        if branch.len() >= 32 {
            proof.push(branch.clone());
        }

        // Inclusion of key 0xabcd10.
        let key_a = [0xab, 0xcd, 0x10];
        let got = verify_proof(&root, &key_a, &proof).unwrap();
        assert_eq!(got.as_deref(), Some(val_a));

        // Inclusion of key 0xabcd20.
        let key_b = [0xab, 0xcd, 0x20];
        let got = verify_proof(&root, &key_b, &proof).unwrap();
        assert_eq!(got.as_deref(), Some(val_b));

        // Exclusion: key that breaks the extension's shared prefix.
        let absent = [0xab, 0xcc, 0x10];
        let got = verify_proof(&root, &absent, &proof).unwrap();
        assert_eq!(got, None);
    }
}
