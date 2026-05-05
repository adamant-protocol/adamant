//! Stealth-address commitment — 32-byte commitment used in
//! `AccountRef::Shielded` per whitepaper section 6.0.7.
//!
//! Per whitepaper section 6.0.7:
//!
//! > "**`StealthCommitment`.** A 32-byte fixed-size value used in
//! > `AccountRef::Shielded(StealthCommitment)` per section 6.0.2. The
//! > cryptographic construction — what the bytes mean as a
//! > stealth-address commitment — is specified in section 7
//! > (privacy layer). Section 6.0.7 pins only the encoding:
//! > `[u8; 32]`."
//!
//! This crate carries the **encoding** only. The cryptographic
//! construction (curve point, Pedersen commitment, etc.) is a
//! whitepaper section 7 / Phase 6 concern. Validators that hash a
//! `TxBody` containing `AccountRef::Shielded(_)` produce a `TxHash`
//! over these 32 bytes regardless of how the bytes are interpreted
//! at the privacy layer.

use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;

use crate::address::hex_encode;

/// `StealthCommitment` byte length: 32 bytes per whitepaper
/// section 6.0.7.
pub const STEALTH_COMMITMENT_BYTES: usize = 32;

/// A 32-byte stealth-address commitment (whitepaper section 6.0.7).
///
/// Same byte-newtype pattern as [`crate::Address`],
/// [`crate::ObjectId`], [`crate::TxHash`], and [`crate::TypeId`].
/// `Serialize`/`Deserialize` route the inner array through
/// `serde-big-array` for canonical BCS encoding; the encoding is 32
/// bytes with no length prefix per whitepaper 5.1.8.
#[derive(Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct StealthCommitment(#[serde(with = "BigArray")] [u8; STEALTH_COMMITMENT_BYTES]);

impl StealthCommitment {
    /// Construct from raw 32-byte material.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; STEALTH_COMMITMENT_BYTES]) -> Self {
        Self(bytes)
    }

    /// Canonical 32-byte encoding.
    #[must_use]
    pub const fn to_bytes(&self) -> [u8; STEALTH_COMMITMENT_BYTES] {
        self.0
    }

    /// Borrow the underlying byte array.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; STEALTH_COMMITMENT_BYTES] {
        &self.0
    }
}

impl core::fmt::Debug for StealthCommitment {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "StealthCommitment(0x{})", hex_encode(&self.0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn declared_length_matches_whitepaper() {
        assert_eq!(STEALTH_COMMITMENT_BYTES, 32);
    }

    #[test]
    fn bytes_round_trip() {
        let bytes = [0x5c_u8; STEALTH_COMMITMENT_BYTES];
        let sc = StealthCommitment::from_bytes(bytes);
        assert_eq!(sc.to_bytes(), bytes);
        assert_eq!(sc.as_bytes(), &bytes);
    }

    #[test]
    fn debug_is_hex() {
        let sc = StealthCommitment::from_bytes([0xa5; STEALTH_COMMITMENT_BYTES]);
        let s = format!("{sc:?}");
        assert!(s.contains("a5a5a5a5"));
        assert!(s.starts_with("StealthCommitment(0x"));
    }

    /// BCS canonical serialisation roundtrip: 32 bytes with no
    /// length prefix, identical to other byte newtypes in this
    /// crate.
    #[test]
    fn bcs_round_trip() {
        let original = StealthCommitment::from_bytes([
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff, 0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87, 0x98, 0xa9, 0xba, 0xcb,
            0xdc, 0xed, 0xfe, 0x0f,
        ]);
        let encoded = bcs::to_bytes(&original).expect("bcs encode");
        assert_eq!(encoded.len(), STEALTH_COMMITMENT_BYTES);
        assert_eq!(encoded, original.as_bytes());

        let decoded: StealthCommitment = bcs::from_bytes(&encoded).expect("bcs decode");
        assert_eq!(decoded, original);
    }

    /// All-zero is a representable value; the type imposes no
    /// constraint on the byte content (cryptographic interpretation
    /// is a whitepaper section 7 concern).
    #[test]
    fn all_zero_round_trips() {
        let zero = StealthCommitment::from_bytes([0u8; STEALTH_COMMITMENT_BYTES]);
        let encoded = bcs::to_bytes(&zero).expect("bcs encode");
        let decoded: StealthCommitment = bcs::from_bytes(&encoded).expect("bcs decode");
        assert_eq!(decoded, zero);
    }
}
