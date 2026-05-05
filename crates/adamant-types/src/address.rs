//! Account address — 32-byte identifier for an account.
//!
//! Per whitepaper section 4.1: "An [`Address`] is a 32-byte identifier
//! derived deterministically from the account's initial public key
//! material at creation time. Addresses are stable: an account's
//! address never changes, even if its keys are rotated." Section 4.2
//! gives the derivation:
//! `SHA3-256(domain_tag || creation_tx_hash || creator_address || index)`.
//!
//! This crate carries the type only. The derivation logic lands in
//! `adamant-account` (Phase 3); the domain tag is registered there
//! per the deferred entry in `adamant-crypto::domain`.

use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;

/// Address byte length: 32 bytes per whitepaper section 4.1.
pub const ADDRESS_BYTES: usize = 32;

/// A 32-byte account identifier (whitepaper section 4.1).
///
/// `Address` is the canonical name used by the protocol. Whitepaper
/// section 5.1.4 occasionally writes `AccountId` for the same type
/// in field annotations on [`crate::Mutability`] variants; that
/// usage is descriptive, not a separate type.
///
/// `Serialize`/`Deserialize` route the inner array through
/// `serde-big-array`. Even at `N = 32` (where `serde` ships a
/// hand-written impl), routing through `BigArray` gives the same
/// canonical BCS encoding (whitepaper 5.1.8: fixed-size arrays are
/// elements in order with no length prefix) and lets every byte
/// newtype in this crate use a single uniform mechanism regardless
/// of array length.
#[derive(Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct Address(#[serde(with = "BigArray")] [u8; ADDRESS_BYTES]);

impl Address {
    /// Construct from raw 32-byte material.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; ADDRESS_BYTES]) -> Self {
        Self(bytes)
    }

    /// Canonical 32-byte encoding.
    #[must_use]
    pub const fn to_bytes(&self) -> [u8; ADDRESS_BYTES] {
        self.0
    }

    /// Borrow the underlying byte array.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; ADDRESS_BYTES] {
        &self.0
    }
}

impl core::fmt::Debug for Address {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Address(0x{})", hex_encode(&self.0))
    }
}

/// Lower-case hex encoding helper for `Debug` impls in this crate.
/// Local copy mirrors the helpers in `adamant-crypto::bls`,
/// `adamant-crypto::sig_classical`, etc. Kept private to avoid
/// cross-module coupling for what is a diagnostic concern.
pub(crate) fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(char::from_digit(u32::from(b >> 4), 16).unwrap_or('?'));
        out.push(char::from_digit(u32::from(b & 0x0f), 16).unwrap_or('?'));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn declared_length_matches_whitepaper() {
        assert_eq!(ADDRESS_BYTES, 32);
    }

    #[test]
    fn bytes_round_trip() {
        let bytes = [0xab_u8; ADDRESS_BYTES];
        let addr = Address::from_bytes(bytes);
        assert_eq!(addr.to_bytes(), bytes);
        assert_eq!(addr.as_bytes(), &bytes);
    }

    #[test]
    fn debug_is_hex() {
        let addr = Address::from_bytes([0x01; ADDRESS_BYTES]);
        let s = format!("{addr:?}");
        assert!(s.contains("01010101"));
        assert!(s.starts_with("Address(0x"));
    }

    /// BCS canonical serialisation roundtrip.
    ///
    /// `#[serde(transparent)]` makes [`Address`] encode as exactly the
    /// 32 bytes of its inner array, with no struct framing. This is
    /// the encoding consensus depends on (whitepaper section 5.1.8):
    /// `Address` flows into `ObjectId` derivation, `TypeId`
    /// derivation, and every transaction hash, so byte-equivalent
    /// encoding across implementations is mandatory.
    #[test]
    fn bcs_round_trip() {
        let original = Address::from_bytes([
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ]);
        let encoded = bcs::to_bytes(&original).expect("bcs encode");
        // Per whitepaper 5.1.8: fixed-size arrays encode as elements
        // in order with no length prefix. With `serde(transparent)`,
        // the wrapper adds nothing. Expected length: exactly 32.
        assert_eq!(encoded.len(), ADDRESS_BYTES);
        assert_eq!(encoded, original.as_bytes());

        let decoded: Address = bcs::from_bytes(&encoded).expect("bcs decode");
        assert_eq!(decoded, original);
    }

    /// All-zero address (the additive identity in the byte space) is
    /// a representable value. The protocol does not reserve any
    /// specific Address as "null" — derivation is via SHA3-256 which
    /// effectively never collides with the all-zero pattern, but the
    /// type itself imposes no constraint.
    #[test]
    fn all_zero_round_trips() {
        let zero = Address::from_bytes([0u8; ADDRESS_BYTES]);
        let encoded = bcs::to_bytes(&zero).expect("bcs encode");
        let decoded: Address = bcs::from_bytes(&encoded).expect("bcs decode");
        assert_eq!(decoded, zero);
    }
}
