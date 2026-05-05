//! Type identifier — 32-byte content-addressed hash of a type definition.
//!
//! Per whitepaper section 5.1.2: "A `TypeId` is itself a 32-byte hash
//! of the type's canonical definition. Two distinct type definitions
//! with identical canonical encodings produce the same `TypeId`; this
//! is intentional and supports content-addressed type registration."
//!
//! Object types are themselves on-chain objects (`Type` meta-type
//! instances, registered through the type-registration mechanism in
//! whitepaper section 6). This crate carries only the identifier
//! type; type-registration logic lives in `adamant-vm` (Phase 5).

use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;

use crate::address::hex_encode;

/// `TypeId` byte length: 32 bytes per whitepaper section 5.1.2.
pub const TYPE_ID_BYTES: usize = 32;

/// A 32-byte content-addressed hash of a type definition (whitepaper
/// section 5.1.2).
#[derive(Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct TypeId(#[serde(with = "BigArray")] [u8; TYPE_ID_BYTES]);

impl TypeId {
    /// Construct from raw 32-byte material.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; TYPE_ID_BYTES]) -> Self {
        Self(bytes)
    }

    /// Canonical 32-byte encoding.
    #[must_use]
    pub const fn to_bytes(&self) -> [u8; TYPE_ID_BYTES] {
        self.0
    }

    /// Borrow the underlying byte array.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; TYPE_ID_BYTES] {
        &self.0
    }
}

impl core::fmt::Debug for TypeId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "TypeId(0x{})", hex_encode(&self.0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn declared_length_matches_whitepaper() {
        assert_eq!(TYPE_ID_BYTES, 32);
    }

    #[test]
    fn bytes_round_trip() {
        let bytes = [0x55_u8; TYPE_ID_BYTES];
        let tid = TypeId::from_bytes(bytes);
        assert_eq!(tid.to_bytes(), bytes);
    }

    #[test]
    fn debug_is_hex() {
        let tid = TypeId::from_bytes([0xaa; TYPE_ID_BYTES]);
        let s = format!("{tid:?}");
        assert!(s.contains("aaaaaaaa"));
        assert!(s.starts_with("TypeId(0x"));
    }

    /// BCS canonical serialisation roundtrip. Per whitepaper 5.1.8
    /// and the `serde(transparent)` derive, [`TypeId`] encodes as
    /// exactly its 32 inner bytes — same format used as the hash
    /// input by the section-5.1.2 derivation formula.
    #[test]
    fn bcs_round_trip() {
        let original = TypeId::from_bytes([
            0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad,
            0xae, 0xaf, 0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb,
            0xbc, 0xbd, 0xbe, 0xbf,
        ]);
        let encoded = bcs::to_bytes(&original).expect("bcs encode");
        assert_eq!(encoded.len(), TYPE_ID_BYTES);
        assert_eq!(encoded, original.as_bytes());

        let decoded: TypeId = bcs::from_bytes(&encoded).expect("bcs decode");
        assert_eq!(decoded, original);
    }
}
