//! Object metadata — protocol-managed bookkeeping fields.
//!
//! Per whitepaper section 5.1.7, the metadata fields are descriptive
//! rather than prescriptive: they record what happened to the object
//! (when it was created, when it was last modified, who created it,
//! how rent has been paid, what the proof commitment is). They are
//! updated by the protocol as side-effects of valid state transitions
//! and are not user-writable.
//!
//! The lifecycle field is **not** part of metadata — it is a
//! prescriptive consensus property (it gates whether modifications
//! are permitted) and lives as a top-level field on [`crate::Object`]
//! per whitepaper section 5.4 and the design discipline that
//! prescriptive and descriptive concerns get different homes.

use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;

use crate::address::{hex_encode, Address};

/// `ProofCommitment` byte length: 48 bytes per whitepaper section
/// 5.1.7. The commitment is a KZG commitment on BLS12-381
/// (whitepaper section 3.7.2), serialised as a compressed G₁ element.
pub const PROOF_COMMITMENT_BYTES: usize = 48;

/// A 48-byte KZG commitment on BLS12-381, compressed G₁ encoding
/// (whitepaper section 5.1.7, referencing 3.7.2).
///
/// Phase 2 of the implementation carries only the type. KZG
/// computation, verification, and the recursive-proof aggregation
/// over [`ProofCommitment`] values land in `adamant-state` (Phase 4)
/// and `adamant-consensus` (Phase 8).
#[derive(Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct ProofCommitment(#[serde(with = "BigArray")] [u8; PROOF_COMMITMENT_BYTES]);

impl ProofCommitment {
    /// Construct from raw 48-byte material.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; PROOF_COMMITMENT_BYTES]) -> Self {
        Self(bytes)
    }

    /// Canonical 48-byte compressed-G₁ encoding.
    #[must_use]
    pub const fn to_bytes(&self) -> [u8; PROOF_COMMITMENT_BYTES] {
        self.0
    }

    /// Borrow the underlying byte array.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; PROOF_COMMITMENT_BYTES] {
        &self.0
    }
}

impl core::fmt::Debug for ProofCommitment {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "ProofCommitment(0x{})", hex_encode(&self.0))
    }
}

/// Object metadata — protocol-managed bookkeeping (whitepaper
/// section 5.1.7).
///
/// All fields are descriptive: they record protocol-observed facts
/// about the object. The fields are updated by the protocol as a
/// side-effect of valid state transitions; users do not write them
/// directly.
///
/// **Lifecycle is intentionally not in metadata.** Lifecycle is a
/// prescriptive field — it determines whether modifications are
/// permitted — and lives at the top level on [`crate::Object`].
#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
pub struct ObjectMetadata {
    /// Consensus height at which the object was created.
    pub created_at_height: u64,
    /// Consensus height of the most recent state transition.
    pub last_modified_height: u64,
    /// The account that created the object.
    pub creator: Address,
    /// Consensus height through which storage rent has been paid
    /// (whitepaper section 5.6).
    pub storage_rent_paid_through: u64,
    /// Cryptographic commitment to the object's history, used by the
    /// privacy layer (section 7) and recursive verification
    /// (section 8). KZG on BLS12-381, compressed G₁ (48 bytes).
    pub proof_commitment: ProofCommitment,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixed_address() -> Address {
        Address::from_bytes([0x11; 32])
    }

    fn fixed_proof_commitment() -> ProofCommitment {
        ProofCommitment::from_bytes([0x22; PROOF_COMMITMENT_BYTES])
    }

    #[test]
    fn proof_commitment_declared_length_matches_whitepaper() {
        assert_eq!(PROOF_COMMITMENT_BYTES, 48);
    }

    #[test]
    fn proof_commitment_bytes_round_trip() {
        let bytes = [0x77_u8; PROOF_COMMITMENT_BYTES];
        let pc = ProofCommitment::from_bytes(bytes);
        assert_eq!(pc.to_bytes(), bytes);
    }

    #[test]
    fn proof_commitment_debug_is_hex() {
        let pc = ProofCommitment::from_bytes([0x42; PROOF_COMMITMENT_BYTES]);
        let s = format!("{pc:?}");
        assert!(s.contains("42424242"));
        assert!(s.starts_with("ProofCommitment(0x"));
    }

    #[test]
    fn proof_commitment_bcs_round_trip() {
        let original = ProofCommitment::from_bytes([
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29,
            0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
        ]);
        let encoded = bcs::to_bytes(&original).expect("bcs encode");
        assert_eq!(encoded.len(), PROOF_COMMITMENT_BYTES);
        assert_eq!(encoded, original.as_bytes());

        let decoded: ProofCommitment = bcs::from_bytes(&encoded).expect("bcs decode");
        assert_eq!(decoded, original);
    }

    #[test]
    fn object_metadata_constructs() {
        let m = ObjectMetadata {
            created_at_height: 100,
            last_modified_height: 200,
            creator: fixed_address(),
            storage_rent_paid_through: 1_000_000,
            proof_commitment: fixed_proof_commitment(),
        };
        assert_eq!(m.created_at_height, 100);
    }

    /// BCS canonical serialisation roundtrip for [`ObjectMetadata`].
    /// Per whitepaper 5.1.8, struct fields encode in source-declaration
    /// order with no separators. The expected encoded length is the
    /// sum of the field encodings:
    ///   `8 (created_at_height u64)`
    /// + `8 (last_modified_height u64)`
    /// + `32 (creator Address — 32 bytes via tuple codec)`
    /// + `8 (storage_rent_paid_through u64)`
    /// + `48 (proof_commitment — 48 bytes via tuple codec)`
    ///   `= 104 bytes`.
    #[test]
    fn object_metadata_bcs_round_trip() {
        let original = ObjectMetadata {
            created_at_height: 0x1122_3344_5566_7788,
            last_modified_height: 0x99aa_bbcc_ddee_ff00,
            creator: Address::from_bytes([0xab; 32]),
            storage_rent_paid_through: 42,
            proof_commitment: ProofCommitment::from_bytes([0xcd; PROOF_COMMITMENT_BYTES]),
        };
        let encoded = bcs::to_bytes(&original).expect("bcs encode");
        assert_eq!(encoded.len(), 8 + 8 + 32 + 8 + PROOF_COMMITMENT_BYTES);

        let decoded: ObjectMetadata = bcs::from_bytes(&encoded).expect("bcs decode");
        assert_eq!(decoded, original);
    }

    /// Field-order assertion: BCS encodes struct fields in source
    /// order, so the first 8 bytes of the encoding are the
    /// little-endian `created_at_height`. This test fails if a
    /// future contributor reorders the fields.
    #[test]
    fn object_metadata_first_8_bytes_are_created_at_height() {
        let original = ObjectMetadata {
            created_at_height: 0x0807_0605_0403_0201,
            last_modified_height: 0,
            creator: Address::from_bytes([0; 32]),
            storage_rent_paid_through: 0,
            proof_commitment: ProofCommitment::from_bytes([0; PROOF_COMMITMENT_BYTES]),
        };
        let encoded = bcs::to_bytes(&original).expect("bcs encode");
        assert_eq!(
            &encoded[0..8],
            &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
        );
    }
}
