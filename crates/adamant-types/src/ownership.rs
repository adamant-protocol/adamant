//! Object ownership mode.
//!
//! Per whitepaper section 5.1.3: every object declares one of four
//! ownership modes. Ownership is a property of the object, not of
//! the account; transferring an object updates this field rather
//! than moving the object between containers.
//!
//! Note the deliberate distinction:
//! - [`Ownership::Immutable`] — the object can never be mutated by
//!   anyone; ownership-side concept.
//! - [`crate::Mutability::Immutable`] — the object's *rules* can
//!   never change; mutability-side concept.
//!
//! These are orthogonal: an [`Ownership::Immutable`] object cannot
//! be mutated regardless of its mutability declaration; an
//! [`crate::Mutability::Immutable`]-mutability object can still
//! have its `contents` mutated according to its (frozen) rules if
//! it is, say, `Address`-owned.

use serde::{Deserialize, Serialize};

use crate::{address::Address, object_id::ObjectId};

/// Object ownership mode (whitepaper section 5.1.3).
///
/// Variants and their semantics:
///
/// - [`Ownership::Address`] — owned by a single account; only
///   transactions authorised under that account's validation logic
///   may mutate it. Default for user-held assets.
/// - [`Ownership::Shared`] — no single owner; any transaction may
///   mutate it subject to the object's own validation rules.
///   Mutations require consensus because two transactions touching
///   the same shared object may conflict (whitepaper section 8).
/// - [`Ownership::Immutable`] — the object cannot be mutated after
///   creation. Useful for published documents, code modules, type
///   definitions, and other permanent reference material.
/// - [`Ownership::Group`] — owned by a *group object*, itself an
///   on-chain object. The group's validation logic determines
///   authorisation. Supports multi-signature, organisational, and
///   nested-control patterns.
#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
pub enum Ownership {
    /// Owned by a single account.
    Address(Address),
    /// No single owner; mutations subject to the object's own rules.
    Shared,
    /// Cannot be mutated by anyone.
    Immutable,
    /// Owned by a group object, identified by its [`ObjectId`].
    Group(ObjectId),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixed_address() -> Address {
        Address::from_bytes([0x44; 32])
    }

    fn fixed_object_id() -> ObjectId {
        ObjectId::from_bytes([0x55; 32])
    }

    /// Variant tags assigned in source-declaration order. Reordering
    /// is a consensus rule change, not a refactor.
    #[test]
    fn variant_tags_are_stable() {
        assert_eq!(
            bcs::to_bytes(&Ownership::Address(fixed_address())).expect("encode")[0],
            0x00
        );
        assert_eq!(bcs::to_bytes(&Ownership::Shared).expect("encode")[0], 0x01);
        assert_eq!(
            bcs::to_bytes(&Ownership::Immutable).expect("encode")[0],
            0x02
        );
        assert_eq!(
            bcs::to_bytes(&Ownership::Group(fixed_object_id())).expect("encode")[0],
            0x03
        );
    }

    #[test]
    fn address_variant_bcs_round_trip() {
        let original = Ownership::Address(fixed_address());
        let encoded = bcs::to_bytes(&original).expect("encode");
        // Variant tag (1 byte) + 32-byte Address.
        assert_eq!(encoded.len(), 1 + 32);
        let decoded: Ownership = bcs::from_bytes(&encoded).expect("decode");
        assert_eq!(decoded, original);
    }

    #[test]
    fn shared_variant_bcs_round_trip() {
        let original = Ownership::Shared;
        let encoded = bcs::to_bytes(&original).expect("encode");
        // Variant tag only.
        assert_eq!(encoded, [0x01]);
        let decoded: Ownership = bcs::from_bytes(&encoded).expect("decode");
        assert_eq!(decoded, original);
    }

    #[test]
    fn immutable_variant_bcs_round_trip() {
        let original = Ownership::Immutable;
        let encoded = bcs::to_bytes(&original).expect("encode");
        assert_eq!(encoded, [0x02]);
        let decoded: Ownership = bcs::from_bytes(&encoded).expect("decode");
        assert_eq!(decoded, original);
    }

    #[test]
    fn group_variant_bcs_round_trip() {
        let original = Ownership::Group(fixed_object_id());
        let encoded = bcs::to_bytes(&original).expect("encode");
        assert_eq!(encoded.len(), 1 + 32);
        let decoded: Ownership = bcs::from_bytes(&encoded).expect("decode");
        assert_eq!(decoded, original);
    }
}
