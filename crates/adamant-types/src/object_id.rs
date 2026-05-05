//! Object identifier — 32-byte unique identifier for an on-chain object.
//!
//! Per whitepaper section 5.1.1: "32 bytes, computed as
//! `SHA3-256(domain_tag || creation_tx_hash || creator_address || creation_index)`.
//! Once assigned, an `ObjectId` never changes." Object identifiers
//! are stable across the object's lifetime, in deliberate contrast
//! to UTXO models where each version of a piece of state has a
//! distinct identifier.
//!
//! This crate carries the type only. The derivation logic lands in
//! `adamant-state` (Phase 4); the domain tag is registered there
//! per the deferred entry in `adamant-crypto::domain`.

use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;

use crate::address::hex_encode;

/// `ObjectId` byte length: 32 bytes per whitepaper section 5.1.1.
pub const OBJECT_ID_BYTES: usize = 32;

/// A 32-byte object identifier (whitepaper section 5.1.1).
#[derive(Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct ObjectId(#[serde(with = "BigArray")] [u8; OBJECT_ID_BYTES]);

impl ObjectId {
    /// Construct from raw 32-byte material.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; OBJECT_ID_BYTES]) -> Self {
        Self(bytes)
    }

    /// Canonical 32-byte encoding.
    #[must_use]
    pub const fn to_bytes(&self) -> [u8; OBJECT_ID_BYTES] {
        self.0
    }

    /// Borrow the underlying byte array.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; OBJECT_ID_BYTES] {
        &self.0
    }
}

impl core::fmt::Debug for ObjectId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "ObjectId(0x{})", hex_encode(&self.0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn declared_length_matches_whitepaper() {
        assert_eq!(OBJECT_ID_BYTES, 32);
    }

    #[test]
    fn bytes_round_trip() {
        let bytes = [0xcd_u8; OBJECT_ID_BYTES];
        let id = ObjectId::from_bytes(bytes);
        assert_eq!(id.to_bytes(), bytes);
    }

    #[test]
    fn debug_is_hex() {
        let id = ObjectId::from_bytes([0x42; OBJECT_ID_BYTES]);
        let s = format!("{id:?}");
        assert!(s.contains("42424242"));
        assert!(s.starts_with("ObjectId(0x"));
    }

    /// BCS canonical serialisation roundtrip. Per whitepaper 5.1.8
    /// and the `serde(transparent)` derive, [`ObjectId`] encodes as
    /// exactly its 32 inner bytes — same format used to produce the
    /// hash inputs in section 5.1.1's derivation formula.
    #[test]
    fn bcs_round_trip() {
        let original = ObjectId::from_bytes([
            0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22,
            0x11, 0x00, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xa0, 0xb0, 0xc0,
            0xd0, 0xe0, 0xf0, 0xa5,
        ]);
        let encoded = bcs::to_bytes(&original).expect("bcs encode");
        assert_eq!(encoded.len(), OBJECT_ID_BYTES);
        assert_eq!(encoded, original.as_bytes());

        let decoded: ObjectId = bcs::from_bytes(&encoded).expect("bcs decode");
        assert_eq!(decoded, original);
    }
}
