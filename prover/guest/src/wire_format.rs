//! Bincode-compatible wire-format helpers for the input envelope.
//!
//! The Go host (via `prover/host-bridge/` and `prover/host-bench/`)
//! ships `GuestBatchInput` with raw fixed-size byte arrays for every
//! address / 256-bit-int / hash field — `[u8; 20]` for addresses,
//! `[u8; 32]` for U256 and B256. Bincode serializes those as raw bytes
//! with no length prefix.
//!
//! The guest types in `main.rs` hold the equivalent values as
//! `alloy_primitives::{Address, U256, B256}` because every other use
//! inside the guest (revm, alloy-trie, RLP) speaks alloy. The default
//! `Serialize` / `Deserialize` impls for those alloy types route
//! through `serialize_bytes` / `deserialize_bytes`, which bincode
//! treats as **length-prefixed** byte strings (8-byte u64 length, then
//! the bytes).
//!
//! Without the `#[serde(with = ...)]` annotations from this module,
//! the guest's `bincode::deserialize::<BatchInput>` reads 8 bytes that
//! the host wrote as actual data, treats them as a length, and
//! attempts to read that many bytes — silently producing garbage or
//! panicking before the EVM ever starts.
//!
//! Each helper here serializes the alloy type as the raw fixed-byte
//! image the host actually writes, so the wire format on both sides
//! matches byte-for-byte. Use via `#[serde(with = "wire_format::Xxx")]`
//! on any wire-facing field of an alloy type.

use alloy_primitives::{Address, B256, U256};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Wire-compatible serde for `Address`. Mirrors the host's `[u8; 20]`.
pub mod address_as_bytes {
    use super::*;

    pub fn serialize<S: Serializer>(addr: &Address, s: S) -> Result<S::Ok, S::Error> {
        let arr: [u8; 20] = addr.into_array();
        arr.serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Address, D::Error> {
        let arr = <[u8; 20]>::deserialize(d)?;
        Ok(Address::from(arr))
    }
}

/// Wire-compatible serde for `Option<Address>`. The host writes the
/// option discriminant followed by either nothing (None) or a raw
/// `[u8; 20]` (Some). Bincode encodes the discriminant as a single
/// `u32` tag matching `Option`'s default representation, so we only
/// need to override the inner Address layout.
pub mod option_address_as_bytes {
    use super::*;

    pub fn serialize<S: Serializer>(addr: &Option<Address>, s: S) -> Result<S::Ok, S::Error> {
        let opt: Option<[u8; 20]> = addr.map(|a| a.into_array());
        opt.serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Address>, D::Error> {
        let opt = <Option<[u8; 20]>>::deserialize(d)?;
        Ok(opt.map(Address::from))
    }
}

/// Wire-compatible serde for `B256`. Mirrors the host's `[u8; 32]`.
pub mod b256_as_bytes {
    use super::*;

    pub fn serialize<S: Serializer>(b: &B256, s: S) -> Result<S::Ok, S::Error> {
        let arr: [u8; 32] = (*b).into();
        arr.serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<B256, D::Error> {
        let arr = <[u8; 32]>::deserialize(d)?;
        Ok(B256::from(arr))
    }
}

/// Wire-compatible serde for `U256`. Mirrors the host's big-endian
/// `[u8; 32]`. Match `to_be_bytes` ↔ `from_be_bytes` byte-for-byte
/// (the host serializes `U256` via `to_be_bytes_vec` semantics).
pub mod u256_as_bytes {
    use super::*;

    pub fn serialize<S: Serializer>(v: &U256, s: S) -> Result<S::Ok, S::Error> {
        let arr: [u8; 32] = v.to_be_bytes();
        arr.serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<U256, D::Error> {
        let arr = <[u8; 32]>::deserialize(d)?;
        Ok(U256::from_be_bytes(arr))
    }
}

#[cfg(test)]
mod tests {
    //! Wire-format compatibility regression tests.
    //!
    //! Each test constructs a "host mirror" struct using the same raw
    //! byte-array layout `prover/host-bridge/src/main.rs::GuestBatchInput`
    //! (and `prover/host-bench/`) actually writes, bincode-encodes it,
    //! then decodes through a guest-shape struct that uses the
    //! `wire_format` helpers. A passing test means the bincode wire
    //! image matches byte-for-byte and the production proving path
    //! (host → SP1 io::read → guest) decodes successfully.
    //!
    //! Without these tests, the previous host-bridge → guest pipeline
    //! had been silently wire-broken: alloy primitives' default serde
    //! routes through `serialize_bytes`, which bincode encodes as a
    //! length-prefixed byte string (8-byte u64 length + bytes), while
    //! the host writes raw fixed-size arrays. The cycle bench
    //! (`pkg/prover.TestSP1Bench`) caught the smoke (all five fixtures
    //! reported identical `cycles=10_227` with empty public values
    //! `pv_hash = SHA256("")`) but no test fixed the wire format.

    use super::*;
    use serde::{Deserialize, Serialize};

    /// Mirrors host-bridge's `GuestAccountState` exactly.
    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    struct HostAccount {
        address: [u8; 20],
        nonce: u64,
        balance: [u8; 32],
        code_hash: [u8; 32],
        code: Vec<u8>,
    }

    /// Wire-shape mirror of `mpt::AccountState` minus the storage Vec
    /// (kept simple for the regression — the storage Vec uses the same
    /// `u256_as_bytes` helper covered by `host_storage_slot_decodes`).
    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    struct GuestAccount {
        #[serde(with = "address_as_bytes")]
        address: Address,
        nonce: u64,
        #[serde(with = "u256_as_bytes")]
        balance: U256,
        #[serde(with = "b256_as_bytes")]
        code_hash: B256,
        code: Vec<u8>,
    }

    #[test]
    fn host_account_decodes_as_guest_account() {
        let host = HostAccount {
            address: [0x11; 20],
            nonce: 7,
            balance: [0x22; 32],
            code_hash: [0x33; 32],
            code: vec![0x60, 0x60, 0x60, 0x40],
        };

        let host_bytes = bincode::serialize(&host).expect("host serialize");

        let guest: GuestAccount = bincode::deserialize(&host_bytes)
            .expect("guest deserialize must succeed — wire image mismatch breaks production proving");

        assert_eq!(guest.nonce, 7);
        assert_eq!(guest.address, Address::from([0x11; 20]));
        assert_eq!(guest.balance, U256::from_be_bytes::<32>([0x22; 32]));
        assert_eq!(guest.code_hash, B256::from([0x33; 32]));
        assert_eq!(guest.code, vec![0x60, 0x60, 0x60, 0x40]);
    }

    #[test]
    fn guest_account_round_trips_through_host_shape() {
        // Same value, encoded by the guest annotations; the host shape
        // must decode it to its raw-bytes form bit-for-bit.
        let guest = GuestAccount {
            address: Address::from([0xab; 20]),
            nonce: 99,
            balance: U256::from_be_bytes::<32>([0xcd; 32]),
            code_hash: B256::from([0xef; 32]),
            code: vec![0xde, 0xad, 0xbe, 0xef],
        };

        let guest_bytes = bincode::serialize(&guest).expect("guest serialize");
        let host: HostAccount = bincode::deserialize(&guest_bytes).expect("host deserialize");

        assert_eq!(host.address, [0xab; 20]);
        assert_eq!(host.nonce, 99);
        assert_eq!(host.balance, [0xcd; 32]);
        assert_eq!(host.code_hash, [0xef; 32]);
        assert_eq!(host.code, vec![0xde, 0xad, 0xbe, 0xef]);
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    struct HostStorageSlot {
        key: [u8; 32],
        value: [u8; 32],
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    struct GuestStorageSlot {
        #[serde(with = "u256_as_bytes")]
        key: U256,
        #[serde(with = "u256_as_bytes")]
        value: U256,
    }

    #[test]
    fn host_storage_slot_decodes() {
        let host = HostStorageSlot {
            key: [0x01; 32],
            value: [0x02; 32],
        };
        let bytes = bincode::serialize(&host).expect("ser");
        let guest: GuestStorageSlot = bincode::deserialize(&bytes).expect("deser");
        assert_eq!(guest.key, U256::from_be_bytes::<32>([0x01; 32]));
        assert_eq!(guest.value, U256::from_be_bytes::<32>([0x02; 32]));
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    struct HostBlockContext {
        number: u64,
        timestamp: u64,
        coinbase: [u8; 20],
        gas_limit: u64,
        base_fee: u64,
        prev_randao: [u8; 32],
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    struct GuestBlockContext {
        number: u64,
        timestamp: u64,
        #[serde(with = "address_as_bytes")]
        coinbase: Address,
        gas_limit: u64,
        base_fee: u64,
        #[serde(with = "b256_as_bytes")]
        prev_randao: B256,
    }

    #[test]
    fn host_block_context_decodes() {
        let host = HostBlockContext {
            number: 42,
            timestamp: 1_700_000_000,
            coinbase: [0xcc; 20],
            gas_limit: 30_000_000,
            base_fee: 1_000_000_000,
            prev_randao: [0xee; 32],
        };
        let bytes = bincode::serialize(&host).expect("ser");
        let guest: GuestBlockContext = bincode::deserialize(&bytes).expect("deser");
        assert_eq!(guest.number, 42);
        assert_eq!(guest.timestamp, 1_700_000_000);
        assert_eq!(guest.coinbase, Address::from([0xcc; 20]));
        assert_eq!(guest.gas_limit, 30_000_000);
        assert_eq!(guest.base_fee, 1_000_000_000);
        assert_eq!(guest.prev_randao, B256::from([0xee; 32]));
    }

    /// Mirrors host-bridge's `GuestTransaction.to: Option<[u8; 20]>`.
    /// Verifies both Some and None paths round-trip — the option-tag
    /// encoding (single byte: 0 for None, 1 for Some) must match.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    struct HostTxAddrShape {
        from: [u8; 20],
        to: Option<[u8; 20]>,
        value: [u8; 32],
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    struct GuestTxAddrShape {
        #[serde(with = "address_as_bytes")]
        from: Address,
        #[serde(with = "option_address_as_bytes")]
        to: Option<Address>,
        #[serde(with = "u256_as_bytes")]
        value: U256,
    }

    #[test]
    fn host_tx_with_to_decodes() {
        let host = HostTxAddrShape {
            from: [0xaa; 20],
            to: Some([0xbb; 20]),
            value: [0x01; 32],
        };
        let bytes = bincode::serialize(&host).expect("ser");
        let guest: GuestTxAddrShape = bincode::deserialize(&bytes).expect("deser");
        assert_eq!(guest.from, Address::from([0xaa; 20]));
        assert_eq!(guest.to, Some(Address::from([0xbb; 20])));
        assert_eq!(guest.value, U256::from_be_bytes::<32>([0x01; 32]));
    }

    #[test]
    fn host_tx_without_to_decodes() {
        let host = HostTxAddrShape {
            from: [0xaa; 20],
            to: None,
            value: [0x00; 32],
        };
        let bytes = bincode::serialize(&host).expect("ser");
        let guest: GuestTxAddrShape = bincode::deserialize(&bytes).expect("deser");
        assert_eq!(guest.to, None);
        assert_eq!(guest.value, U256::ZERO);
    }
}
