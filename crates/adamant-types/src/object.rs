//! On-chain object — the protocol's unit of state.
//!
//! Per whitepaper section 5.1: every object is a typed, addressed,
//! ownership-tracked piece of state. The object model is the
//! foundation of consensus throughput and parallelism (section
//! 5.2.1) and the surface on which the privacy layer (section 7)
//! operates.
//!
//! # Field-shape note: `lifecycle` lives on [`Object`], not metadata
//!
//! Whitepaper section 5.1's Object listing shows `metadata:
//! ObjectMetadata` and not a separate lifecycle field, but section
//! 5.4 enumerates four lifecycle states whose effect on consensus
//! is prescriptive (they gate whether modifications are permitted).
//! In this implementation, [`Object`] carries a top-level
//! [`crate::Lifecycle`] field separate from
//! [`crate::ObjectMetadata`]:
//!
//! - [`crate::Lifecycle`] is **prescriptive**: it determines what
//!   can happen next. Consensus checks it directly.
//! - [`crate::ObjectMetadata`] is **descriptive**: it records what
//!   has happened. Consensus updates it as a side-effect.
//!
//! These are different concerns and live in different homes. The
//! BCS encoding of [`Object`] reflects the field order declared in
//! this module.

use serde::{Deserialize, Serialize};

use crate::{
    lifecycle::Lifecycle, metadata::ObjectMetadata, mutability::Mutability, object_id::ObjectId,
    ownership::Ownership, type_id::TypeId,
};

/// Maximum [`Contents`] payload length, per whitepaper section
/// 5.1.5: "1 MiB. Objects requiring more state are expected to
/// split themselves into multiple linked objects."
pub const MAX_CONTENTS_BYTES: usize = 1024 * 1024;

/// Type-specific serialised payload of an object (whitepaper section
/// 5.1.5).
///
/// The protocol does not interpret `contents` directly; the schema
/// is specified by the object's type ([`TypeId`]) and the VM
/// (whitepaper section 6) is responsible for deserialising,
/// manipulating, and re-serialising it. This crate only enforces
/// the per-object size cap.
#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Contents(Vec<u8>);

/// Error returned when a [`Contents`] payload would exceed
/// [`MAX_CONTENTS_BYTES`].
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct ContentsTooLarge {
    /// Length of the offending payload, in bytes.
    pub actual: usize,
    /// The cap the payload exceeded.
    pub maximum: usize,
}

impl core::fmt::Display for ContentsTooLarge {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "contents length {} exceeds per-object cap {} (whitepaper 5.1.5)",
            self.actual, self.maximum,
        )
    }
}

impl std::error::Error for ContentsTooLarge {}

impl Contents {
    /// Construct from a byte slice, validating the per-object size
    /// cap from whitepaper section 5.1.5.
    ///
    /// # Errors
    ///
    /// Returns [`ContentsTooLarge`] if the payload exceeds
    /// [`MAX_CONTENTS_BYTES`] (1 MiB).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ContentsTooLarge> {
        if bytes.len() > MAX_CONTENTS_BYTES {
            return Err(ContentsTooLarge {
                actual: bytes.len(),
                maximum: MAX_CONTENTS_BYTES,
            });
        }
        Ok(Self(bytes.to_vec()))
    }

    /// Construct from an owned `Vec<u8>`, validating the per-object
    /// size cap.
    ///
    /// # Errors
    ///
    /// Returns [`ContentsTooLarge`] if the payload exceeds
    /// [`MAX_CONTENTS_BYTES`].
    pub fn from_vec(bytes: Vec<u8>) -> Result<Self, ContentsTooLarge> {
        if bytes.len() > MAX_CONTENTS_BYTES {
            return Err(ContentsTooLarge {
                actual: bytes.len(),
                maximum: MAX_CONTENTS_BYTES,
            });
        }
        Ok(Self(bytes))
    }

    /// Construct an empty `Contents`.
    #[must_use]
    pub fn empty() -> Self {
        Self(Vec::new())
    }

    /// Borrow the underlying bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Length in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the payload is zero-length.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// On-chain object (whitepaper section 5.1).
///
/// Field order matches the source-declaration order which BCS
/// preserves byte-for-byte (whitepaper section 5.1.8). Reordering
/// fields is a consensus rule change, not a refactor; the test
/// suite asserts the BCS encoding's prefix to catch accidental
/// reorderings.
#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
pub struct Object {
    /// 32-byte unique identifier (whitepaper section 5.1.1).
    pub id: ObjectId,
    /// Identifier of the object's type definition (whitepaper
    /// section 5.1.2).
    pub type_id: TypeId,
    /// Ownership mode (whitepaper section 5.1.3).
    pub owner: Ownership,
    /// Mutability declaration (whitepaper section 5.1.4).
    pub mutability: Mutability,
    /// Lifecycle state — prescriptive consensus property
    /// (whitepaper section 5.4).
    pub lifecycle: Lifecycle,
    /// Type-specific serialised payload (whitepaper section 5.1.5).
    pub contents: Contents,
    /// Monotonically-increasing version counter (whitepaper section
    /// 5.1.6).
    pub version: u64,
    /// Protocol-managed bookkeeping (whitepaper section 5.1.7).
    pub metadata: ObjectMetadata,
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::{
        address::Address,
        metadata::{ProofCommitment, PROOF_COMMITMENT_BYTES},
    };

    // ---------- Contents ----------

    #[test]
    fn contents_max_is_1_mib() {
        assert_eq!(MAX_CONTENTS_BYTES, 1024 * 1024);
    }

    #[test]
    fn contents_empty_is_valid() {
        let c = Contents::empty();
        assert!(c.is_empty());
        assert_eq!(c.len(), 0);
    }

    #[test]
    fn contents_at_cap_accepted() {
        let bytes = vec![0u8; MAX_CONTENTS_BYTES];
        let c = Contents::from_vec(bytes).expect("at cap is valid");
        assert_eq!(c.len(), MAX_CONTENTS_BYTES);
    }

    #[test]
    fn contents_above_cap_rejected() {
        let bytes = vec![0u8; MAX_CONTENTS_BYTES + 1];
        let err = Contents::from_vec(bytes).expect_err("above cap rejected");
        assert_eq!(err.maximum, MAX_CONTENTS_BYTES);
        assert_eq!(err.actual, MAX_CONTENTS_BYTES + 1);
    }

    #[test]
    fn contents_from_bytes_above_cap_rejected() {
        // Construct on the heap so the slice doesn't blow up the
        // stack on systems with small default stacks.
        let bytes = vec![0u8; MAX_CONTENTS_BYTES + 1];
        assert!(Contents::from_bytes(&bytes).is_err());
    }

    #[test]
    fn contents_bcs_round_trip_short() {
        let original = Contents::from_bytes(b"hello").expect("valid");
        let encoded = bcs::to_bytes(&original).expect("bcs encode");
        // Per whitepaper 5.1.8: Vec<T> is ULEB128 length prefix +
        // elements. 5 bytes is one-byte ULEB128 length 0x05.
        assert_eq!(encoded, b"\x05hello");
        let decoded: Contents = bcs::from_bytes(&encoded).expect("bcs decode");
        assert_eq!(decoded, original);
    }

    #[test]
    fn contents_bcs_round_trip_empty() {
        let original = Contents::empty();
        let encoded = bcs::to_bytes(&original).expect("bcs encode");
        // Empty Vec: ULEB128 length 0 = single byte 0x00.
        assert_eq!(encoded, [0x00]);
        let decoded: Contents = bcs::from_bytes(&encoded).expect("bcs decode");
        assert_eq!(decoded, original);
    }

    /// Like `BasisPoints` (see [`crate::mutability`]), `Contents`'s
    /// invariant is enforced by the validating constructor, not by
    /// the deserialiser. A peer-supplied BCS-encoded `Contents` of
    /// > 1 MiB will deserialise successfully here; consensus is
    /// > responsible for re-validating size on inbound transactions.
    /// > This test documents the gap; it does not encode a 2 MiB
    /// > payload (memory-cost reasons), but verifies the
    /// > `serde(transparent)` derive is in fact transparent and that
    /// > the deserialiser does not consult [`MAX_CONTENTS_BYTES`].
    #[test]
    fn contents_serde_transparent_decodes_arbitrary_vec_u8() {
        let plain_vec = vec![0xab_u8; 100];
        let encoded = bcs::to_bytes(&plain_vec).expect("bcs encode");
        let decoded: Contents = bcs::from_bytes(&encoded).expect("bcs decode");
        assert_eq!(decoded.as_bytes(), &plain_vec[..]);
    }

    // ---------- Object ----------

    fn fixed_metadata() -> ObjectMetadata {
        ObjectMetadata {
            created_at_height: 100,
            last_modified_height: 200,
            creator: Address::from_bytes([0xab; 32]),
            storage_rent_paid_through: 1_000_000,
            proof_commitment: ProofCommitment::from_bytes([0xcd; PROOF_COMMITMENT_BYTES]),
        }
    }

    fn fixed_object() -> Object {
        Object {
            id: ObjectId::from_bytes([0x01; 32]),
            type_id: TypeId::from_bytes([0x02; 32]),
            owner: Ownership::Address(Address::from_bytes([0x03; 32])),
            mutability: Mutability::Immutable,
            lifecycle: Lifecycle::Active,
            contents: Contents::from_bytes(b"object-contents").expect("valid"),
            version: 1,
            metadata: fixed_metadata(),
        }
    }

    #[test]
    fn object_constructs() {
        let _ = fixed_object();
    }

    /// BCS roundtrip for a representative [`Object`] value.
    /// Field order matches source declaration. The encoding's prefix
    /// is the [`ObjectId`]'s 32 bytes (no struct framing); subsequent
    /// fields follow in order.
    #[test]
    fn object_bcs_round_trip() {
        let original = fixed_object();
        let encoded = bcs::to_bytes(&original).expect("bcs encode");
        // First 32 bytes are the ObjectId.
        assert_eq!(encoded[..32], [0x01_u8; 32]);
        // Bytes 32..64 are the TypeId.
        assert_eq!(encoded[32..64], [0x02_u8; 32]);

        let decoded: Object = bcs::from_bytes(&encoded).expect("bcs decode");
        assert_eq!(decoded, original);
    }

    /// Variations across enum-typed fields: every `Mutability`
    /// variant the spec defines should encode-decode round-trip
    /// inside an `Object`. This catches any accidental field-shape
    /// drift between the enum's standalone tests and its in-Object
    /// usage.
    #[test]
    fn object_with_each_mutability_variant_round_trips() {
        let base = fixed_object();
        let variants = [
            Mutability::Immutable,
            Mutability::OwnerUpgradeable {
                owner: Address::from_bytes([0xaa; 32]),
            },
            Mutability::UpgradeableUntilFrozen {
                owner: Address::from_bytes([0xbb; 32]),
            },
            Mutability::Custom {
                upgrade_validator: TypeId::from_bytes([0xcc; 32]),
                validator_id: ObjectId::from_bytes([0xdd; 32]),
            },
            Mutability::Forked {
                original: ObjectId::from_bytes([0xee; 32]),
                fork_height: 42,
            },
        ];
        for m in variants {
            let object = Object {
                mutability: m.clone(),
                ..base.clone()
            };
            let encoded = bcs::to_bytes(&object).expect("encode");
            let decoded: Object = bcs::from_bytes(&encoded).expect("decode");
            assert_eq!(decoded, object);
        }
    }

    /// Variations across [`Lifecycle`] values: every state should
    /// round-trip inside an `Object`.
    #[test]
    fn object_with_each_lifecycle_round_trips() {
        let base = fixed_object();
        for state in [
            Lifecycle::Active,
            Lifecycle::Frozen,
            Lifecycle::Archived,
            Lifecycle::Destroyed,
        ] {
            let object = Object {
                lifecycle: state,
                ..base.clone()
            };
            let encoded = bcs::to_bytes(&object).expect("encode");
            let decoded: Object = bcs::from_bytes(&encoded).expect("decode");
            assert_eq!(decoded, object);
        }
    }

    /// Variations across [`Ownership`] values: every variant should
    /// round-trip inside an `Object`.
    #[test]
    fn object_with_each_ownership_round_trips() {
        let base = fixed_object();
        let variants = [
            Ownership::Address(Address::from_bytes([0x11; 32])),
            Ownership::Shared,
            Ownership::Immutable,
            Ownership::Group(ObjectId::from_bytes([0x22; 32])),
        ];
        for o in variants {
            let object = Object {
                owner: o.clone(),
                ..base.clone()
            };
            let encoded = bcs::to_bytes(&object).expect("encode");
            let decoded: Object = bcs::from_bytes(&encoded).expect("decode");
            assert_eq!(decoded, object);
        }
    }
}
