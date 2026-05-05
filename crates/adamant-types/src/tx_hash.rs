//! Transaction hash — 32-byte hash of a canonically-encoded transaction.
//!
//! Per whitepaper section 4.2, the address-derivation formula
//! consumes a `creation_tx_hash` value: the hash of the
//! account-creation transaction, computed under the protocol's
//! canonical encoding (BCS, whitepaper section 5.1.8) and the
//! consensus hash function (SHA3-256 with a domain tag, whitepaper
//! section 3.3.1).
//!
//! Phase 2 of the implementation carries the **type** here as a
//! peer of [`crate::Address`], [`crate::ObjectId`], and
//! [`crate::TypeId`]. The hashing logic that produces a [`TxHash`]
//! from a transaction lands in `adamant-vm` (Phase 5), where the
//! transaction format itself is specified per whitepaper section 6.
//! Until that phase, `TxHash` values are constructed from raw
//! 32-byte material — typically by callers that already hold a
//! computed hash or a stub value for testing.

use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;

use crate::address::hex_encode;

/// `TxHash` byte length: 32 bytes, matching the SHA3-256 output
/// width specified in whitepaper section 3.3.1.
pub const TX_HASH_BYTES: usize = 32;

/// A 32-byte transaction hash (whitepaper section 4.2 input field
/// to the address-derivation formula; produced canonically by the
/// transaction-hashing logic that lands in `adamant-vm`).
#[derive(Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct TxHash(#[serde(with = "BigArray")] [u8; TX_HASH_BYTES]);

impl TxHash {
    /// Construct from raw 32-byte material.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; TX_HASH_BYTES]) -> Self {
        Self(bytes)
    }

    /// Canonical 32-byte encoding.
    #[must_use]
    pub const fn to_bytes(&self) -> [u8; TX_HASH_BYTES] {
        self.0
    }

    /// Borrow the underlying byte array.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; TX_HASH_BYTES] {
        &self.0
    }
}

impl core::fmt::Debug for TxHash {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "TxHash(0x{})", hex_encode(&self.0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn declared_length_matches_whitepaper() {
        assert_eq!(TX_HASH_BYTES, 32);
    }

    #[test]
    fn bytes_round_trip() {
        let bytes = [0x99_u8; TX_HASH_BYTES];
        let h = TxHash::from_bytes(bytes);
        assert_eq!(h.to_bytes(), bytes);
        assert_eq!(h.as_bytes(), &bytes);
    }

    #[test]
    fn debug_is_hex() {
        let h = TxHash::from_bytes([0x7e; TX_HASH_BYTES]);
        let s = format!("{h:?}");
        assert!(s.contains("7e7e7e7e"));
        assert!(s.starts_with("TxHash(0x"));
    }

    /// BCS canonical serialisation roundtrip. Per whitepaper 5.1.8,
    /// fixed-size byte arrays encode as elements in order with no
    /// length prefix; routing through `serde-big-array` produces
    /// the identical 32-byte encoding.
    #[test]
    fn bcs_round_trip() {
        let original = TxHash::from_bytes([
            0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
            0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 0x11, 0x22, 0x33, 0x44,
            0x55, 0x66, 0x77, 0x88,
        ]);
        let encoded = bcs::to_bytes(&original).expect("bcs encode");
        assert_eq!(encoded.len(), TX_HASH_BYTES);
        assert_eq!(encoded, original.as_bytes());

        let decoded: TxHash = bcs::from_bytes(&encoded).expect("bcs decode");
        assert_eq!(decoded, original);
    }
}
