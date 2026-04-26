//! Signed-transaction decoding and sender recovery inside the SP1 guest.
//!
//! This module is the Gate-0 critical correctness fix for sender recovery:
//! the SP1 guest MUST recover the sender of every user-signed EVM
//! transaction from the signature, NOT trust a host-supplied `from` field.
//! Without this, a malicious host could swap senders without invalidating
//! the proof.
//!
//! The recovery uses k256 (patched to call SP1's secp256k1 precompile)
//! plus alloy_primitives::keccak256 (also accelerated). Signature
//! malleability is enforced by rejecting `s > n/2` (EIP-2). Chain ID is
//! checked against the compile-time `expected_chain_id` so a proof
//! generated for shard A cannot be replayed against a transaction signed
//! for shard B.
//!
//! Supported transaction types:
//!   * Legacy        (no type byte, EIP-155 or pre-155)
//!   * EIP-2930 / 0x01 (access list)
//!   * EIP-1559 / 0x02 (dynamic fee)
//!   * EIP-4844 / 0x03 (blob)
//!
//! Deposit system transactions (0x7E) are handled separately in `main.rs`:
//! they have no signature and the SourceHash binds them to the on-chain
//! BSV deposit txid that the inbox covenant has already verified.

// We use std::vec::Vec via the crate prelude when building the library
// facet (host target) and alloc::vec::Vec when the guest binary pulls
// us in under `no_main` on the zkVM target. Either way the import is
// the same path:
use alloy_primitives::{keccak256, Address, Signature, B256, U256};
use alloy_rlp::Header;

/// secp256k1 group order n. Source: SECG SEC 2 (the curve is secp256k1).
/// Used for the EIP-2 low-s malleability check.
pub const SECP256K1_N: U256 = U256::from_be_slice(&[
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
    0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41,
]);

/// secp256k1 half group order n/2 — the EIP-2 high-s rejection threshold.
pub const SECP256K1_HALF_N: U256 = U256::from_be_slice(&[
    0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x5D, 0x57, 0x6E, 0x73, 0x57, 0xA4, 0x50, 0x1D, 0xDF, 0xE9, 0x2F, 0x46, 0x68, 0x1B, 0x20, 0xA0,
]);

/// Decoded fields of a signed user EVM transaction, used to drive revm.
/// The `sender` is recovered from the signature inside the guest, NEVER
/// taken from the host.
///
/// EIP-4844 (type 0x03) additionally exposes:
///   * `blob_fee_cap`            — `max_fee_per_blob_gas`
///   * `blob_versioned_hashes`   — list of 32-byte hashes the BLOBHASH
///                                 opcode resolves against
/// For non-blob txs both fields are zero / empty.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedTx {
    pub tx_type: u8,
    pub chain_id: u64,
    pub nonce: u64,
    pub gas_limit: u64,
    pub gas_price: u128,
    pub max_priority_fee: u128,
    pub to: Option<Address>,
    pub value: U256,
    pub data: Vec<u8>,
    pub sender: Address,
    /// EIP-4844 max_fee_per_blob_gas. Zero for non-blob txs.
    pub blob_fee_cap: u128,
    /// EIP-4844 blob_versioned_hashes. Empty for non-blob txs.
    /// MUST be non-empty for type-0x03 — the wire decoder rejects empty.
    pub blob_versioned_hashes: Vec<B256>,
}

/// Errors that can arise while decoding or recovering a signed transaction.
/// The guest treats any error as a fatal batch failure (matches Ethereum
/// block validity: a single invalid tx invalidates the whole block).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxError {
    EmptyInput,
    UnsupportedType,
    Rlp,
    InvalidSignature,
    HighS,
    ChainIdMismatch,
    Recover,
    /// EIP-4844: a type-0x03 tx must reference at least one blob versioned
    /// hash. An empty list is wire-invalid and the guest rejects it before
    /// signature recovery.
    EmptyBlobHashes,
    /// EIP-4844: a type-0x03 tx must specify a 20-byte recipient address.
    /// Contract creation via blob tx is forbidden by the spec.
    BlobMissingTo,
}

/// Decode a signed transaction from its raw RLP-encoded bytes and recover
/// the sender. The sender is derived purely from the signature and the
/// canonical signing hash for this transaction type. Chain ID is checked
/// against `expected_chain_id` (the guest's compile-time CHAIN_ID).
pub fn decode_and_recover(
    raw: &[u8],
    expected_chain_id: u64,
) -> Result<DecodedTx, TxError> {
    if raw.is_empty() {
        return Err(TxError::EmptyInput);
    }
    // Legacy txs are RLP lists, so the first byte is >= 0xC0. Typed txs
    // (EIP-2718) start with their type byte: 0x01 (access list) or
    // 0x02 (dynamic fee).
    let first = raw[0];
    if first >= 0xC0 {
        decode_legacy(raw, expected_chain_id)
    } else if first == 0x01 {
        decode_access_list(&raw[1..], expected_chain_id)
    } else if first == 0x02 {
        decode_dynamic_fee(&raw[1..], expected_chain_id)
    } else if first == 0x03 {
        decode_blob(&raw[1..], expected_chain_id)
    } else {
        Err(TxError::UnsupportedType)
    }
}

// ─── Legacy (pre-EIP-2718) ──────────────────────────────────────────────────

/// Decode a legacy transaction. Layout (post-EIP-155):
///   RLP([nonce, gasPrice, gas, to, value, data, v, r, s])
///
/// Signing hash:
///   * pre-EIP-155 (v ∈ {27, 28}):
///       keccak256(RLP([nonce, gasPrice, gas, to, value, data]))
///   * EIP-155 (v = chainId * 2 + {35, 36}):
///       keccak256(RLP([nonce, gasPrice, gas, to, value, data, chainId, 0, 0]))
fn decode_legacy(raw: &[u8], expected_chain_id: u64) -> Result<DecodedTx, TxError> {
    let mut buf = raw;
    let payload = decode_list_payload(&mut buf)?;
    let mut p = payload;

    let nonce = decode_u64(&mut p)?;
    let gas_price = decode_u256(&mut p)?;
    let gas_limit = decode_u64(&mut p)?;
    let to = decode_optional_address(&mut p)?;
    let value = decode_u256(&mut p)?;
    let data = decode_bytes(&mut p)?.to_vec();
    let v = decode_u256(&mut p)?;
    let r = decode_u256(&mut p)?;
    let s = decode_u256(&mut p)?;

    enforce_low_s(s)?;

    // Recover the y_parity bit and decide whether this is EIP-155 or pre-155.
    // Pre-EIP-155 v ∈ {27, 28}; EIP-155 v = chainId*2 + 35 + recid.
    let v_u64 = u256_to_u64(v).ok_or(TxError::InvalidSignature)?;
    let (y_parity, eip155_chain_id) = if v_u64 == 27 || v_u64 == 28 {
        (v_u64 == 28, None)
    } else if v_u64 >= 35 {
        let recid = (v_u64 - 35) & 1;
        let chain_id = (v_u64 - 35 - recid) / 2;
        (recid == 1, Some(chain_id))
    } else {
        return Err(TxError::InvalidSignature);
    };

    // EIP-155 chain ID must match the guest's compile-time CHAIN_ID. We
    // accept pre-EIP-155 (no chain id baked into v) only if no chain id is
    // expected — i.e., effectively never on a real shard. A shard may opt
    // out by setting expected_chain_id = 0.
    let chain_id = match eip155_chain_id {
        Some(cid) => {
            if cid != expected_chain_id {
                return Err(TxError::ChainIdMismatch);
            }
            cid
        }
        None => {
            if expected_chain_id != 0 {
                return Err(TxError::ChainIdMismatch);
            }
            0
        }
    };

    // Build the signing hash.
    let sig_hash = if eip155_chain_id.is_some() {
        // EIP-155: keccak256(RLP([nonce, gasPrice, gas, to, value, data, chainId, 0, 0])).
        let mut body = Vec::with_capacity(raw.len());
        encode_legacy_signing_fields(
            &mut body,
            nonce,
            gas_price,
            gas_limit,
            to,
            value,
            &data,
            Some(chain_id),
        );
        keccak256(rlp_list_envelope(&body))
    } else {
        // Pre-EIP-155: keccak256(RLP([nonce, gasPrice, gas, to, value, data])).
        let mut body = Vec::with_capacity(raw.len());
        encode_legacy_signing_fields(
            &mut body, nonce, gas_price, gas_limit, to, value, &data, None,
        );
        keccak256(rlp_list_envelope(&body))
    };

    let sender = recover(sig_hash, r, s, y_parity)?;

    let gp = u256_to_u128(gas_price).ok_or(TxError::InvalidSignature)?;
    let val = value;

    Ok(DecodedTx {
        tx_type: 0x00,
        chain_id,
        nonce,
        gas_limit,
        gas_price: gp,
        max_priority_fee: 0,
        to,
        value: val,
        data,
        sender,
        blob_fee_cap: 0,
        blob_versioned_hashes: Vec::new(),
    })
}

// ─── EIP-2930 (0x01) ────────────────────────────────────────────────────────

/// Decode an EIP-2930 access list transaction. Body layout:
///   RLP([chainId, nonce, gasPrice, gas, to, value, data, accessList, v, r, s])
///
/// Signing hash:
///   keccak256(0x01 || RLP([chainId, nonce, gasPrice, gas, to, value, data, accessList]))
fn decode_access_list(body: &[u8], expected_chain_id: u64) -> Result<DecodedTx, TxError> {
    let mut buf = body;
    let payload = decode_list_payload(&mut buf)?;
    let mut p = payload;

    let chain_id = decode_u64(&mut p)?;
    if chain_id != expected_chain_id {
        return Err(TxError::ChainIdMismatch);
    }
    let nonce = decode_u64(&mut p)?;
    let gas_price = decode_u256(&mut p)?;
    let gas_limit = decode_u64(&mut p)?;
    let to = decode_optional_address(&mut p)?;
    let value = decode_u256(&mut p)?;
    let data = decode_bytes(&mut p)?.to_vec();
    let access_list_raw = take_list_with_header(&mut p)?;
    let v = decode_u256(&mut p)?;
    let r = decode_u256(&mut p)?;
    let s = decode_u256(&mut p)?;

    enforce_low_s(s)?;
    let v_u64 = u256_to_u64(v).ok_or(TxError::InvalidSignature)?;
    if v_u64 > 1 {
        return Err(TxError::InvalidSignature);
    }
    let y_parity = v_u64 == 1;

    // Reconstruct the signing payload by re-emitting the decoded fields
    // through the signing-list builder so we are byte-identical to what
    // the sender hashed (independent of how the original encoder framed
    // the access-list header). This protects against any subtle re-encode
    // drift from third-party libraries.
    let signing_body = encode_typed_signing_payload(
        chain_id,
        nonce,
        gas_price,
        None,
        None,
        gas_limit,
        to,
        value,
        &data,
        access_list_raw,
        false,
    );
    let mut buf2 = Vec::with_capacity(signing_body.len() + 1);
    buf2.push(0x01);
    buf2.extend_from_slice(&signing_body);
    let sig_hash = keccak256(&buf2);

    let sender = recover(sig_hash, r, s, y_parity)?;
    let gp = u256_to_u128(gas_price).ok_or(TxError::InvalidSignature)?;

    Ok(DecodedTx {
        tx_type: 0x01,
        chain_id,
        nonce,
        gas_limit,
        gas_price: gp,
        max_priority_fee: 0,
        to,
        value,
        data,
        sender,
        blob_fee_cap: 0,
        blob_versioned_hashes: Vec::new(),
    })
}

// ─── EIP-1559 (0x02) ────────────────────────────────────────────────────────

/// Decode an EIP-1559 dynamic-fee transaction. Body layout:
///   RLP([chainId, nonce, maxPriorityFeePerGas, maxFeePerGas, gas, to, value,
///        data, accessList, v, r, s])
///
/// Signing hash:
///   keccak256(0x02 || RLP([chainId, nonce, maxPriorityFeePerGas, maxFeePerGas,
///                          gas, to, value, data, accessList]))
fn decode_dynamic_fee(body: &[u8], expected_chain_id: u64) -> Result<DecodedTx, TxError> {
    let mut buf = body;
    let payload = decode_list_payload(&mut buf)?;
    let mut p = payload;

    let chain_id = decode_u64(&mut p)?;
    if chain_id != expected_chain_id {
        return Err(TxError::ChainIdMismatch);
    }
    let nonce = decode_u64(&mut p)?;
    let max_priority_fee = decode_u256(&mut p)?;
    let max_fee = decode_u256(&mut p)?;
    let gas_limit = decode_u64(&mut p)?;
    let to = decode_optional_address(&mut p)?;
    let value = decode_u256(&mut p)?;
    let data = decode_bytes(&mut p)?.to_vec();
    let access_list_raw = take_list_with_header(&mut p)?;
    let v = decode_u256(&mut p)?;
    let r = decode_u256(&mut p)?;
    let s = decode_u256(&mut p)?;

    enforce_low_s(s)?;
    let v_u64 = u256_to_u64(v).ok_or(TxError::InvalidSignature)?;
    if v_u64 > 1 {
        return Err(TxError::InvalidSignature);
    }
    let y_parity = v_u64 == 1;

    let signing_body = encode_typed_signing_payload(
        chain_id,
        nonce,
        U256::ZERO,
        Some(max_priority_fee),
        Some(max_fee),
        gas_limit,
        to,
        value,
        &data,
        access_list_raw,
        true,
    );
    let mut buf2 = Vec::with_capacity(signing_body.len() + 1);
    buf2.push(0x02);
    buf2.extend_from_slice(&signing_body);
    let sig_hash = keccak256(&buf2);

    let sender = recover(sig_hash, r, s, y_parity)?;

    let gp = u256_to_u128(max_fee).ok_or(TxError::InvalidSignature)?;
    let mpf = u256_to_u128(max_priority_fee).ok_or(TxError::InvalidSignature)?;

    Ok(DecodedTx {
        tx_type: 0x02,
        chain_id,
        nonce,
        gas_limit,
        gas_price: gp,
        max_priority_fee: mpf,
        to,
        value,
        data,
        sender,
        blob_fee_cap: 0,
        blob_versioned_hashes: Vec::new(),
    })
}

// ─── EIP-4844 (0x03) ────────────────────────────────────────────────────────

/// Decode an EIP-4844 blob transaction. Body layout:
///   RLP([chainId, nonce, maxPriorityFeePerGas, maxFeePerGas, gas, to, value,
///        data, accessList, maxFeePerBlobGas, blobVersionedHashes, v, r, s])
///
/// Signing hash:
///   keccak256(0x03 || RLP([chainId, nonce, maxPriorityFeePerGas,
///                          maxFeePerGas, gas, to, value, data, accessList,
///                          maxFeePerBlobGas, blobVersionedHashes]))
///
/// EIP-4844 constraints enforced here:
///   * `to` MUST be a 20-byte address (no contract creation).
///   * `blobVersionedHashes` MUST be a non-empty list. Empty lists are
///     wire-invalid and the guest pins the batch as failed before recovery.
///   * Chain id binding, low-s, and recovery-id range mirror type-2.
fn decode_blob(body: &[u8], expected_chain_id: u64) -> Result<DecodedTx, TxError> {
    let mut buf = body;
    let payload = decode_list_payload(&mut buf)?;
    let mut p = payload;

    let chain_id = decode_u64(&mut p)?;
    if chain_id != expected_chain_id {
        return Err(TxError::ChainIdMismatch);
    }
    let nonce = decode_u64(&mut p)?;
    let max_priority_fee = decode_u256(&mut p)?;
    let max_fee = decode_u256(&mut p)?;
    let gas_limit = decode_u64(&mut p)?;
    let to = decode_optional_address(&mut p)?;
    // EIP-4844: blob txs MUST have a non-nil destination. Contract creation
    // is forbidden — an empty `to` field invalidates the tx.
    let to_addr = to.ok_or(TxError::BlobMissingTo)?;
    let value = decode_u256(&mut p)?;
    let data = decode_bytes(&mut p)?.to_vec();
    let access_list_raw = take_list_with_header(&mut p)?;
    let max_fee_per_blob_gas = decode_u256(&mut p)?;
    let blob_versioned_hashes_raw = take_list_with_header(&mut p)?;
    let v = decode_u256(&mut p)?;
    let r = decode_u256(&mut p)?;
    let s = decode_u256(&mut p)?;

    enforce_low_s(s)?;
    let v_u64 = u256_to_u64(v).ok_or(TxError::InvalidSignature)?;
    if v_u64 > 1 {
        return Err(TxError::InvalidSignature);
    }
    let y_parity = v_u64 == 1;

    // Decode the blob versioned hashes list — each entry is a 32-byte string.
    let blob_versioned_hashes = decode_b256_list(blob_versioned_hashes_raw)?;
    if blob_versioned_hashes.is_empty() {
        return Err(TxError::EmptyBlobHashes);
    }

    // Reconstruct the signing payload by re-emitting decoded fields, then
    // prepend the type byte and hash. Re-emitting keeps the access-list and
    // blob-hash-list bytes opaque/byte-identical to what the sender hashed.
    let signing_body = encode_blob_signing_payload(
        chain_id,
        nonce,
        max_priority_fee,
        max_fee,
        gas_limit,
        to_addr,
        value,
        &data,
        access_list_raw,
        max_fee_per_blob_gas,
        blob_versioned_hashes_raw,
    );
    let mut buf2 = Vec::with_capacity(signing_body.len() + 1);
    buf2.push(0x03);
    buf2.extend_from_slice(&signing_body);
    let sig_hash = keccak256(&buf2);

    let sender = recover(sig_hash, r, s, y_parity)?;

    let gp = u256_to_u128(max_fee).ok_or(TxError::InvalidSignature)?;
    let mpf = u256_to_u128(max_priority_fee).ok_or(TxError::InvalidSignature)?;
    let bfc = u256_to_u128(max_fee_per_blob_gas).ok_or(TxError::InvalidSignature)?;

    Ok(DecodedTx {
        tx_type: 0x03,
        chain_id,
        nonce,
        gas_limit,
        gas_price: gp,
        max_priority_fee: mpf,
        to: Some(to_addr),
        value,
        data,
        sender,
        blob_fee_cap: bfc,
        blob_versioned_hashes,
    })
}

// ─── Helpers: secp256k1 recovery, EIP-2 low-s enforcement ───────────────────

/// Reject `s > n/2` per EIP-2. Without this, every signature has a malleable
/// twin (s, n-s); accepting both would let an attacker reuse a valid
/// signature to craft a different txid. Geth and revm enforce the same.
fn enforce_low_s(s: U256) -> Result<(), TxError> {
    if s == U256::ZERO || s > SECP256K1_HALF_N || s >= SECP256K1_N {
        return Err(TxError::HighS);
    }
    Ok(())
}

/// Recover the Ethereum address from the signing hash and (r, s, v_parity).
/// Internally calls k256 (patched by sp1-patches/elliptic-curves to use
/// SP1's secp256k1 precompile) and alloy_primitives::keccak256 (SP1
/// precompile-accelerated).
fn recover(prehash: B256, r: U256, s: U256, y_parity: bool) -> Result<Address, TxError> {
    if r == U256::ZERO || r >= SECP256K1_N {
        return Err(TxError::InvalidSignature);
    }
    let sig = Signature::new(r, s, y_parity);
    sig.recover_address_from_prehash(&prehash)
        .map_err(|_| TxError::Recover)
}

// ─── RLP helpers ────────────────────────────────────────────────────────────

/// Consume one RLP list header from `buf` and return the payload slice. The
/// payload covers exactly the list contents — i.e., the trailer past the
/// list bytes is left in `buf` (we don't use it for tx parsing).
fn decode_list_payload<'a>(buf: &mut &'a [u8]) -> Result<&'a [u8], TxError> {
    Header::decode_bytes(buf, true).map_err(|_| TxError::Rlp)
}

/// Decode an RLP byte string and return its inner slice.
fn decode_bytes<'a>(buf: &mut &'a [u8]) -> Result<&'a [u8], TxError> {
    Header::decode_bytes(buf, false).map_err(|_| TxError::Rlp)
}

/// Decode a u64 from a (possibly-empty / left-trimmed) RLP byte string.
fn decode_u64(buf: &mut &[u8]) -> Result<u64, TxError> {
    let bytes = decode_bytes(buf)?;
    if bytes.len() > 8 {
        return Err(TxError::Rlp);
    }
    let mut padded = [0u8; 8];
    padded[8 - bytes.len()..].copy_from_slice(bytes);
    Ok(u64::from_be_bytes(padded))
}

/// Decode a U256 from a (possibly-empty / left-trimmed) RLP byte string.
fn decode_u256(buf: &mut &[u8]) -> Result<U256, TxError> {
    let bytes = decode_bytes(buf)?;
    if bytes.len() > 32 {
        return Err(TxError::Rlp);
    }
    Ok(U256::from_be_slice(bytes))
}

/// Decode an optional address: empty byte string ⇒ None (contract creation),
/// otherwise an exactly-20-byte string.
fn decode_optional_address(buf: &mut &[u8]) -> Result<Option<Address>, TxError> {
    let bytes = decode_bytes(buf)?;
    if bytes.is_empty() {
        Ok(None)
    } else if bytes.len() == 20 {
        let mut a = [0u8; 20];
        a.copy_from_slice(bytes);
        Ok(Some(Address::from(a)))
    } else {
        Err(TxError::Rlp)
    }
}

/// Take the next RLP list (header + payload) and return its bytes verbatim.
/// Used for re-emitting the access list during signing-hash reconstruction:
/// we never inspect or normalise its contents — the access list is opaque
/// to sender recovery.
fn take_list_with_header<'a>(buf: &mut &'a [u8]) -> Result<&'a [u8], TxError> {
    let start: &'a [u8] = *buf;
    let mut cursor: &[u8] = start;
    let header = Header::decode(&mut cursor).map_err(|_| TxError::Rlp)?;
    if !header.list {
        return Err(TxError::Rlp);
    }
    let header_len = start.len() - cursor.len();
    let total = header_len
        .checked_add(header.payload_length)
        .ok_or(TxError::Rlp)?;
    if total > start.len() {
        return Err(TxError::Rlp);
    }
    let raw = &start[..total];
    *buf = &start[total..];
    Ok(raw)
}

/// Wrap `body` in an RLP list header.
fn rlp_list_envelope(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len() + 9);
    encode_list_header(body.len(), &mut out);
    out.extend_from_slice(body);
    out
}

fn encode_list_header(len: usize, out: &mut Vec<u8>) {
    if len < 56 {
        out.push(0xC0 + len as u8);
    } else {
        let mut be = [0u8; 8];
        be.copy_from_slice(&(len as u64).to_be_bytes());
        let lz = be.iter().take_while(|&&b| b == 0).count();
        let n = be.len() - lz;
        out.push(0xF7 + n as u8);
        out.extend_from_slice(&be[lz..]);
    }
}

fn encode_string_header(len: usize, out: &mut Vec<u8>) {
    if len < 56 {
        out.push(0x80 + len as u8);
    } else {
        let mut be = [0u8; 8];
        be.copy_from_slice(&(len as u64).to_be_bytes());
        let lz = be.iter().take_while(|&&b| b == 0).count();
        let n = be.len() - lz;
        out.push(0xB7 + n as u8);
        out.extend_from_slice(&be[lz..]);
    }
}

fn encode_bytes(bytes: &[u8], out: &mut Vec<u8>) {
    if bytes.len() == 1 && bytes[0] < 0x80 {
        out.push(bytes[0]);
    } else {
        encode_string_header(bytes.len(), out);
        out.extend_from_slice(bytes);
    }
}

fn encode_u64(v: u64, out: &mut Vec<u8>) {
    encode_uint_be(&v.to_be_bytes(), out);
}

fn encode_u256(v: U256, out: &mut Vec<u8>) {
    encode_uint_be(&v.to_be_bytes::<32>(), out);
}

fn encode_uint_be(be: &[u8], out: &mut Vec<u8>) {
    let lz = be.iter().take_while(|&&b| b == 0).count();
    let stripped = &be[lz..];
    if stripped.is_empty() {
        // Canonical RLP for zero: empty string.
        out.push(0x80);
    } else {
        encode_bytes(stripped, out);
    }
}

fn encode_optional_address(to: Option<Address>, out: &mut Vec<u8>) {
    match to {
        Some(addr) => encode_bytes(addr.as_slice(), out),
        None => out.push(0x80),
    }
}

/// Re-emit the legacy signing fields. With `chain_id`, this is the EIP-155
/// 9-field form `[nonce, gasPrice, gas, to, value, data, chainId, 0, 0]`;
/// without, the 6-field pre-EIP-155 form.
fn encode_legacy_signing_fields(
    out: &mut Vec<u8>,
    nonce: u64,
    gas_price: U256,
    gas: u64,
    to: Option<Address>,
    value: U256,
    data: &[u8],
    chain_id: Option<u64>,
) {
    encode_u64(nonce, out);
    encode_u256(gas_price, out);
    encode_u64(gas, out);
    encode_optional_address(to, out);
    encode_u256(value, out);
    encode_bytes(data, out);
    if let Some(cid) = chain_id {
        encode_u64(cid, out);
        out.push(0x80); // 0
        out.push(0x80); // 0
    }
}

/// Decode an RLP-encoded list of 32-byte strings (B256). Used for the
/// EIP-4844 blob_versioned_hashes field. Each entry must be exactly 32
/// bytes; any deviation invalidates the tx.
fn decode_b256_list(raw: &[u8]) -> Result<Vec<B256>, TxError> {
    let mut buf = raw;
    let payload = decode_list_payload(&mut buf)?;
    let mut p = payload;
    let mut out = Vec::new();
    while !p.is_empty() {
        let bytes = decode_bytes(&mut p)?;
        if bytes.len() != 32 {
            return Err(TxError::Rlp);
        }
        let mut h = [0u8; 32];
        h.copy_from_slice(bytes);
        out.push(B256::from(h));
    }
    Ok(out)
}

/// Re-emit an EIP-4844 signing payload wrapped in an RLP list header. The
/// access list and blob-versioned-hashes list are passed through verbatim
/// (`*_raw`) — they are opaque to sender recovery, and re-encoding them via
/// our own emitter would risk drift from what the original signer hashed.
#[allow(clippy::too_many_arguments)]
fn encode_blob_signing_payload(
    chain_id: u64,
    nonce: u64,
    max_priority_fee: U256,
    max_fee: U256,
    gas: u64,
    to: Address,
    value: U256,
    data: &[u8],
    access_list_raw: &[u8],
    max_fee_per_blob_gas: U256,
    blob_versioned_hashes_raw: &[u8],
) -> Vec<u8> {
    let mut body = Vec::with_capacity(
        96 + data.len() + access_list_raw.len() + blob_versioned_hashes_raw.len(),
    );
    encode_u64(chain_id, &mut body);
    encode_u64(nonce, &mut body);
    encode_u256(max_priority_fee, &mut body);
    encode_u256(max_fee, &mut body);
    encode_u64(gas, &mut body);
    // EIP-4844 forbids contract creation, so the `to` field is always a
    // 20-byte address — never the empty-string creation marker.
    encode_bytes(to.as_slice(), &mut body);
    encode_u256(value, &mut body);
    encode_bytes(data, &mut body);
    body.extend_from_slice(access_list_raw);
    encode_u256(max_fee_per_blob_gas, &mut body);
    body.extend_from_slice(blob_versioned_hashes_raw);

    let mut out = Vec::with_capacity(body.len() + 9);
    encode_list_header(body.len(), &mut out);
    out.extend_from_slice(&body);
    out
}

/// Re-emit a typed-tx signing payload (EIP-2930 / EIP-1559) wrapped in an
/// RLP list header. `is_dynamic` selects between the 9-field 2930 form and
/// the 10-field 1559 form (which inserts maxPriorityFeePerGas + maxFeePerGas
/// in place of gasPrice).
#[allow(clippy::too_many_arguments)]
fn encode_typed_signing_payload(
    chain_id: u64,
    nonce: u64,
    gas_price: U256,
    max_priority_fee: Option<U256>,
    max_fee: Option<U256>,
    gas: u64,
    to: Option<Address>,
    value: U256,
    data: &[u8],
    access_list_raw: &[u8],
    is_dynamic: bool,
) -> Vec<u8> {
    let mut body = Vec::with_capacity(64 + data.len() + access_list_raw.len());
    encode_u64(chain_id, &mut body);
    encode_u64(nonce, &mut body);
    if is_dynamic {
        encode_u256(max_priority_fee.unwrap_or_default(), &mut body);
        encode_u256(max_fee.unwrap_or_default(), &mut body);
    } else {
        encode_u256(gas_price, &mut body);
    }
    encode_u64(gas, &mut body);
    encode_optional_address(to, &mut body);
    encode_u256(value, &mut body);
    encode_bytes(data, &mut body);
    body.extend_from_slice(access_list_raw);

    let mut out = Vec::with_capacity(body.len() + 9);
    encode_list_header(body.len(), &mut out);
    out.extend_from_slice(&body);
    out
}

fn u256_to_u64(v: U256) -> Option<u64> {
    let limbs = v.as_limbs();
    if limbs[1] != 0 || limbs[2] != 0 || limbs[3] != 0 {
        return None;
    }
    Some(limbs[0])
}

fn u256_to_u128(v: U256) -> Option<u128> {
    let limbs = v.as_limbs();
    if limbs[2] != 0 || limbs[3] != 0 {
        return None;
    }
    Some(((limbs[1] as u128) << 64) | (limbs[0] as u128))
}

// ─── Tests ──────────────────────────────────────────────────────────────────
//
// Tests run in a normal cargo-test environment (host x86/arm), where the
// SP1 entrypoint is gated out by `#[cfg(not(test))]` in main.rs. The
// k256 SP1 patch falls back to its software implementation when not
// executing under SP1, so signing + recovery work for these vectors.

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::hex;
    use k256::ecdsa::{signature::hazmat::PrehashSigner, RecoveryId, SigningKey};
    // Brings `to_encoded_point` into scope on `VerifyingKey`. Compiler
    // marks it as unused via the lint, but the trait method is invoked.
    #[allow(unused_imports)]
    use k256::elliptic_curve::sec1::ToEncodedPoint;

    /// Sign `prehash` with `key` and return (r, s, y_parity) where s is
    /// already low-s normalised. Mirrors what `pkg/types/signer.go`
    /// produces on the Go side.
    fn sign_prehash(key: &SigningKey, prehash: &[u8; 32]) -> (U256, U256, bool) {
        let (sig, recid): (k256::ecdsa::Signature, RecoveryId) =
            key.sign_prehash(prehash).expect("sign prehash");
        let s_bytes_orig = sig.s().to_bytes();
        let sig_norm = sig.normalize_s().unwrap_or(sig);
        let s_bytes_norm = sig_norm.s().to_bytes();
        let r = U256::from_be_slice(&sig_norm.r().to_bytes());
        let s = U256::from_be_slice(&s_bytes_norm);
        // recid.is_y_odd() returns the parity bit. normalize_s flips s
        // iff it was originally high; the recovery parity flips with it.
        let was_high = AsRef::<[u8]>::as_ref(&s_bytes_orig)
            != AsRef::<[u8]>::as_ref(&s_bytes_norm);
        let y_parity = recid.is_y_odd() ^ was_high;
        (r, s, y_parity)
    }

    fn key_to_address(key: &SigningKey) -> Address {
        // `to_sec1_bytes()` returns the SEC1 compressed form by default;
        // VerifyingKey's `to_encoded_point(false)` returns the uncompressed
        // (`0x04 || X || Y`) form which is what Ethereum's address
        // derivation expects.
        let vk = key.verifying_key();
        let point = vk.to_encoded_point(false);
        let bytes = point.as_bytes();
        // Strip the 0x04 SEC1 prefix; keccak256 the 64-byte XY; take last 20.
        let h = keccak256(&bytes[1..]);
        Address::from_slice(&h[12..])
    }

    fn build_legacy_eip155_signed(
        key: &SigningKey,
        chain_id: u64,
        nonce: u64,
        gas_price: u64,
        gas: u64,
        to: Address,
        value: U256,
        data: &[u8],
    ) -> Vec<u8> {
        let mut signing_body = Vec::new();
        encode_legacy_signing_fields(
            &mut signing_body,
            nonce,
            U256::from(gas_price),
            gas,
            Some(to),
            value,
            data,
            Some(chain_id),
        );
        let signing_envelope = rlp_list_envelope(&signing_body);
        let prehash: [u8; 32] = keccak256(&signing_envelope).0;
        let (r, s, y_parity) = sign_prehash(key, &prehash);
        let v_u64 = chain_id * 2 + 35 + (y_parity as u64);
        // Now emit the signed tx: the same 6 fields + v + r + s.
        let mut signed_body = Vec::new();
        encode_u64(nonce, &mut signed_body);
        encode_u256(U256::from(gas_price), &mut signed_body);
        encode_u64(gas, &mut signed_body);
        encode_optional_address(Some(to), &mut signed_body);
        encode_u256(value, &mut signed_body);
        encode_bytes(data, &mut signed_body);
        encode_u64(v_u64, &mut signed_body);
        encode_u256(r, &mut signed_body);
        encode_u256(s, &mut signed_body);
        rlp_list_envelope(&signed_body)
    }

    fn build_eip1559_signed(
        key: &SigningKey,
        chain_id: u64,
        nonce: u64,
        max_priority_fee: u64,
        max_fee: u64,
        gas: u64,
        to: Address,
        value: U256,
        data: &[u8],
    ) -> Vec<u8> {
        let empty_access_list: [u8; 1] = [0xC0];
        let signing_body = encode_typed_signing_payload(
            chain_id,
            nonce,
            U256::ZERO,
            Some(U256::from(max_priority_fee)),
            Some(U256::from(max_fee)),
            gas,
            Some(to),
            value,
            data,
            &empty_access_list,
            true,
        );
        let mut prehash_input = Vec::with_capacity(signing_body.len() + 1);
        prehash_input.push(0x02);
        prehash_input.extend_from_slice(&signing_body);
        let prehash: [u8; 32] = keccak256(&prehash_input).0;
        let (r, s, y_parity) = sign_prehash(key, &prehash);

        let mut signed_body_inner = Vec::new();
        encode_u64(chain_id, &mut signed_body_inner);
        encode_u64(nonce, &mut signed_body_inner);
        encode_u256(U256::from(max_priority_fee), &mut signed_body_inner);
        encode_u256(U256::from(max_fee), &mut signed_body_inner);
        encode_u64(gas, &mut signed_body_inner);
        encode_optional_address(Some(to), &mut signed_body_inner);
        encode_u256(value, &mut signed_body_inner);
        encode_bytes(data, &mut signed_body_inner);
        signed_body_inner.extend_from_slice(&empty_access_list);
        encode_u64(y_parity as u64, &mut signed_body_inner);
        encode_u256(r, &mut signed_body_inner);
        encode_u256(s, &mut signed_body_inner);
        let signed_list = rlp_list_envelope(&signed_body_inner);
        let mut out = Vec::with_capacity(signed_list.len() + 1);
        out.push(0x02);
        out.extend_from_slice(&signed_list);
        out
    }

    fn build_eip2930_signed(
        key: &SigningKey,
        chain_id: u64,
        nonce: u64,
        gas_price: u64,
        gas: u64,
        to: Address,
        value: U256,
        data: &[u8],
    ) -> Vec<u8> {
        let empty_access_list: [u8; 1] = [0xC0];
        let signing_body = encode_typed_signing_payload(
            chain_id,
            nonce,
            U256::from(gas_price),
            None,
            None,
            gas,
            Some(to),
            value,
            data,
            &empty_access_list,
            false,
        );
        let mut prehash_input = Vec::with_capacity(signing_body.len() + 1);
        prehash_input.push(0x01);
        prehash_input.extend_from_slice(&signing_body);
        let prehash: [u8; 32] = keccak256(&prehash_input).0;
        let (r, s, y_parity) = sign_prehash(key, &prehash);

        let mut signed_body_inner = Vec::new();
        encode_u64(chain_id, &mut signed_body_inner);
        encode_u64(nonce, &mut signed_body_inner);
        encode_u256(U256::from(gas_price), &mut signed_body_inner);
        encode_u64(gas, &mut signed_body_inner);
        encode_optional_address(Some(to), &mut signed_body_inner);
        encode_u256(value, &mut signed_body_inner);
        encode_bytes(data, &mut signed_body_inner);
        signed_body_inner.extend_from_slice(&empty_access_list);
        encode_u64(y_parity as u64, &mut signed_body_inner);
        encode_u256(r, &mut signed_body_inner);
        encode_u256(s, &mut signed_body_inner);
        let signed_list = rlp_list_envelope(&signed_body_inner);
        let mut out = Vec::with_capacity(signed_list.len() + 1);
        out.push(0x01);
        out.extend_from_slice(&signed_list);
        out
    }

    fn fixed_key() -> SigningKey {
        // Deterministic key — never use this for anything real.
        let bytes = hex!("4646464646464646464646464646464646464646464646464646464646464646");
        SigningKey::from_bytes((&bytes).into()).expect("valid key")
    }

    #[test]
    fn legacy_eip155_roundtrip_recovers_signer() {
        let key = fixed_key();
        let expected = key_to_address(&key);
        let to = Address::from(hex!("3535353535353535353535353535353535353535"));
        let raw = build_legacy_eip155_signed(
            &key,
            1,
            0,
            20_000_000_000,
            21_000,
            to,
            U256::from(1_000_000_000_000_000_000u64),
            &[],
        );
        let dec = decode_and_recover(&raw, 1).expect("decode_and_recover");
        assert_eq!(dec.tx_type, 0x00);
        assert_eq!(dec.chain_id, 1);
        assert_eq!(dec.nonce, 0);
        assert_eq!(dec.gas_limit, 21_000);
        assert_eq!(dec.gas_price, 20_000_000_000);
        assert_eq!(dec.to, Some(to));
        assert_eq!(dec.sender, expected);
    }

    #[test]
    fn eip1559_roundtrip_recovers_signer() {
        let key = fixed_key();
        let expected = key_to_address(&key);
        let to = Address::from(hex!("3535353535353535353535353535353535353535"));
        let raw = build_eip1559_signed(
            &key,
            8453111,
            7,
            1_000_000_000,
            2_000_000_000,
            21_000,
            to,
            U256::from(42u64),
            &[0xDE, 0xAD, 0xBE, 0xEF],
        );
        let dec = decode_and_recover(&raw, 8453111).expect("decode_and_recover");
        assert_eq!(dec.tx_type, 0x02);
        assert_eq!(dec.chain_id, 8453111);
        assert_eq!(dec.nonce, 7);
        assert_eq!(dec.gas_limit, 21_000);
        assert_eq!(dec.gas_price, 2_000_000_000);
        assert_eq!(dec.max_priority_fee, 1_000_000_000);
        assert_eq!(dec.to, Some(to));
        assert_eq!(dec.value, U256::from(42u64));
        assert_eq!(dec.data, vec![0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(dec.sender, expected);
    }

    #[test]
    fn eip2930_roundtrip_recovers_signer() {
        let key = fixed_key();
        let expected = key_to_address(&key);
        let to = Address::from(hex!("4242424242424242424242424242424242424242"));
        let raw = build_eip2930_signed(
            &key,
            8453111,
            3,
            5_000_000_000,
            50_000,
            to,
            U256::from(7u64),
            &[0x12, 0x34],
        );
        let dec = decode_and_recover(&raw, 8453111).expect("decode_and_recover");
        assert_eq!(dec.tx_type, 0x01);
        assert_eq!(dec.chain_id, 8453111);
        assert_eq!(dec.nonce, 3);
        assert_eq!(dec.sender, expected);
    }

    #[test]
    fn rejects_chain_id_mismatch_legacy() {
        let key = fixed_key();
        let raw = build_legacy_eip155_signed(
            &key,
            1,
            0,
            1,
            21000,
            Address::ZERO,
            U256::ZERO,
            &[],
        );
        assert_eq!(
            decode_and_recover(&raw, 2),
            Err(TxError::ChainIdMismatch)
        );
    }

    #[test]
    fn rejects_chain_id_mismatch_eip1559() {
        let key = fixed_key();
        let raw =
            build_eip1559_signed(&key, 1, 0, 1, 1, 21000, Address::ZERO, U256::ZERO, &[]);
        assert_eq!(
            decode_and_recover(&raw, 2),
            Err(TxError::ChainIdMismatch)
        );
    }

    #[test]
    fn rejects_unknown_tx_type() {
        let raw = vec![0x05, 0xc0];
        assert_eq!(
            decode_and_recover(&raw, 1),
            Err(TxError::UnsupportedType)
        );
    }

    #[test]
    fn rejects_empty_input() {
        assert_eq!(decode_and_recover(&[], 1), Err(TxError::EmptyInput));
    }

    #[test]
    fn enforce_low_s_rejects_high() {
        let s = SECP256K1_HALF_N + U256::from(1u64);
        assert_eq!(enforce_low_s(s), Err(TxError::HighS));
        assert_eq!(enforce_low_s(SECP256K1_HALF_N), Ok(()));
        assert_eq!(enforce_low_s(U256::ZERO), Err(TxError::HighS));
    }

    /// Build a signed EIP-4844 type-3 tx with an explicit blob versioned
    /// hash list. `blob_hashes` MUST be non-empty per the spec, but we
    /// allow callers to pass an empty list so we can exercise the
    /// EmptyBlobHashes rejection path.
    fn build_eip4844_signed(
        key: &SigningKey,
        chain_id: u64,
        nonce: u64,
        max_priority_fee: u64,
        max_fee: u64,
        gas: u64,
        to: Address,
        value: U256,
        data: &[u8],
        max_fee_per_blob_gas: u64,
        blob_hashes: &[B256],
    ) -> Vec<u8> {
        let empty_access_list: [u8; 1] = [0xC0];
        // Encode the blob versioned hashes list as RLP([h0, h1, ...]).
        let mut hashes_body = Vec::new();
        for h in blob_hashes {
            encode_bytes(h.as_slice(), &mut hashes_body);
        }
        let blob_hashes_raw = rlp_list_envelope(&hashes_body);

        let signing_body = encode_blob_signing_payload(
            chain_id,
            nonce,
            U256::from(max_priority_fee),
            U256::from(max_fee),
            gas,
            to,
            value,
            data,
            &empty_access_list,
            U256::from(max_fee_per_blob_gas),
            &blob_hashes_raw,
        );
        let mut prehash_input = Vec::with_capacity(signing_body.len() + 1);
        prehash_input.push(0x03);
        prehash_input.extend_from_slice(&signing_body);
        let prehash: [u8; 32] = keccak256(&prehash_input).0;
        let (r, s, y_parity) = sign_prehash(key, &prehash);

        let mut signed_body_inner = Vec::new();
        encode_u64(chain_id, &mut signed_body_inner);
        encode_u64(nonce, &mut signed_body_inner);
        encode_u256(U256::from(max_priority_fee), &mut signed_body_inner);
        encode_u256(U256::from(max_fee), &mut signed_body_inner);
        encode_u64(gas, &mut signed_body_inner);
        // EIP-4844 forbids creation: emit `to` as a 20-byte string, never
        // the 0x80 empty-string marker.
        encode_bytes(to.as_slice(), &mut signed_body_inner);
        encode_u256(value, &mut signed_body_inner);
        encode_bytes(data, &mut signed_body_inner);
        signed_body_inner.extend_from_slice(&empty_access_list);
        encode_u256(U256::from(max_fee_per_blob_gas), &mut signed_body_inner);
        signed_body_inner.extend_from_slice(&blob_hashes_raw);
        encode_u64(y_parity as u64, &mut signed_body_inner);
        encode_u256(r, &mut signed_body_inner);
        encode_u256(s, &mut signed_body_inner);
        let signed_list = rlp_list_envelope(&signed_body_inner);
        let mut out = Vec::with_capacity(signed_list.len() + 1);
        out.push(0x03);
        out.extend_from_slice(&signed_list);
        out
    }

    #[test]
    fn eip4844_roundtrip_recovers_signer() {
        let key = fixed_key();
        let expected = key_to_address(&key);
        let to = Address::from(hex!("4242424242424242424242424242424242424242"));
        let h0 = B256::from(hex!(
            "0100000000000000000000000000000000000000000000000000000000000001"
        ));
        let h1 = B256::from(hex!(
            "0100000000000000000000000000000000000000000000000000000000000002"
        ));
        let raw = build_eip4844_signed(
            &key,
            8453111,
            9,
            1_000_000_000,
            2_000_000_000,
            100_000,
            to,
            U256::from(7u64),
            &[0xCA, 0xFE, 0xBA, 0xBE],
            3_000_000_000,
            &[h0, h1],
        );
        let dec = decode_and_recover(&raw, 8453111).expect("decode_and_recover");
        assert_eq!(dec.tx_type, 0x03);
        assert_eq!(dec.chain_id, 8453111);
        assert_eq!(dec.nonce, 9);
        assert_eq!(dec.gas_limit, 100_000);
        assert_eq!(dec.gas_price, 2_000_000_000);
        assert_eq!(dec.max_priority_fee, 1_000_000_000);
        assert_eq!(dec.blob_fee_cap, 3_000_000_000);
        assert_eq!(dec.to, Some(to));
        assert_eq!(dec.value, U256::from(7u64));
        assert_eq!(dec.data, vec![0xCA, 0xFE, 0xBA, 0xBE]);
        assert_eq!(dec.blob_versioned_hashes, vec![h0, h1]);
        assert_eq!(dec.sender, expected);
    }

    #[test]
    fn eip4844_rejects_empty_blob_hashes() {
        // Per EIP-4844: blob_versioned_hashes must be non-empty. Sign a
        // type-3 tx with an empty list and confirm the guest rejects it
        // BEFORE running signature recovery.
        let key = fixed_key();
        let to = Address::from(hex!("4242424242424242424242424242424242424242"));
        let raw = build_eip4844_signed(
            &key,
            8453111,
            0,
            1,
            1,
            21_000,
            to,
            U256::ZERO,
            &[],
            1,
            &[], // empty blob hash list — wire-invalid
        );
        assert_eq!(
            decode_and_recover(&raw, 8453111),
            Err(TxError::EmptyBlobHashes)
        );
    }

    #[test]
    fn eip4844_rejects_chain_id_mismatch() {
        let key = fixed_key();
        let to = Address::from(hex!("4242424242424242424242424242424242424242"));
        let h0 = B256::from(hex!(
            "0100000000000000000000000000000000000000000000000000000000000001"
        ));
        let raw = build_eip4844_signed(
            &key, 1, 0, 1, 1, 21_000, to, U256::ZERO, &[], 1, &[h0],
        );
        assert_eq!(decode_and_recover(&raw, 2), Err(TxError::ChainIdMismatch));
    }

    #[test]
    fn eip4844_rejects_creation() {
        // EIP-4844 forbids contract creation. Build a malformed signed type-3
        // tx whose `to` field is an RLP empty string (0x80 — the creation
        // marker) and confirm the guest refuses it. We construct this by
        // hand because build_eip4844_signed always emits a 20-byte `to`.
        let chain_id = 8453111u64;
        let mut signed_body_inner = Vec::new();
        encode_u64(chain_id, &mut signed_body_inner);
        encode_u64(0, &mut signed_body_inner); // nonce
        encode_u256(U256::from(1u64), &mut signed_body_inner); // priority fee
        encode_u256(U256::from(1u64), &mut signed_body_inner); // max fee
        encode_u64(21_000, &mut signed_body_inner); // gas
        signed_body_inner.push(0x80); // `to` = empty string -> creation marker
        encode_u256(U256::ZERO, &mut signed_body_inner); // value
        encode_bytes(&[], &mut signed_body_inner); // data
        signed_body_inner.extend_from_slice(&[0xC0]); // empty access list
        encode_u256(U256::from(1u64), &mut signed_body_inner); // blob fee cap
        // One blob hash so we don't fail EmptyBlobHashes first.
        let mut hashes_body = Vec::new();
        encode_bytes(&[0x01u8; 32], &mut hashes_body);
        let hashes_raw = rlp_list_envelope(&hashes_body);
        signed_body_inner.extend_from_slice(&hashes_raw);
        encode_u64(0, &mut signed_body_inner); // v
        encode_u256(U256::from(1u64), &mut signed_body_inner); // r
        encode_u256(U256::from(1u64), &mut signed_body_inner); // s
        let signed_list = rlp_list_envelope(&signed_body_inner);
        let mut raw = Vec::with_capacity(signed_list.len() + 1);
        raw.push(0x03);
        raw.extend_from_slice(&signed_list);
        assert_eq!(
            decode_and_recover(&raw, chain_id),
            Err(TxError::BlobMissingTo)
        );
    }

    #[test]
    fn eip4844_rejects_tampered_blob_hash() {
        // Flip a byte inside the blob_versioned_hashes list. The tampered
        // payload must NOT recover the original signer (or must fail
        // decode/recovery outright).
        let key = fixed_key();
        let expected = key_to_address(&key);
        let to = Address::from(hex!("4242424242424242424242424242424242424242"));
        let h0 = B256::from(hex!(
            "0100000000000000000000000000000000000000000000000000000000000033"
        ));
        let mut raw = build_eip4844_signed(
            &key,
            8453111,
            0,
            1,
            1,
            21_000,
            to,
            U256::ZERO,
            &[],
            1,
            &[h0],
        );
        // Find and flip the marker byte 0x33 inside the encoded blob hash.
        let pos = raw.iter().rposition(|&b| b == 0x33).expect("marker");
        raw[pos] = 0x77;
        match decode_and_recover(&raw, 8453111) {
            Ok(dec) => assert_ne!(dec.sender, expected),
            Err(_) => {}
        }
    }

    #[test]
    fn rejects_tampered_payload() {
        // Sign a tx, then flip a byte in the data field. Recovery should
        // either yield a different address or fail outright. Either way,
        // it must NOT yield the original signer's address.
        let key = fixed_key();
        let expected = key_to_address(&key);
        let to = Address::from([0x11u8; 20]);
        let mut raw = build_eip1559_signed(
            &key,
            8453111,
            0,
            1,
            1,
            21000,
            to,
            U256::from(1u64),
            &[0xAA],
        );
        // Mutate a byte in the value/data region — find the 0xAA marker
        // and flip it.
        let pos = raw.iter().rposition(|&b| b == 0xAA).expect("marker");
        raw[pos] = 0xBB;
        match decode_and_recover(&raw, 8453111) {
            Ok(dec) => assert_ne!(dec.sender, expected),
            Err(_) => {} // also acceptable
        }
    }
}
