//! Object model and state management for the Adamant protocol.
//!
//! Phase 4 surface so far:
//!
//! - [`derive_object_id`] — the [`ObjectId`] derivation formula
//!   from whitepaper section 5.1.1
//!   (`ObjectId = sha3_256_tagged(OBJECT_ID, BCS(creation_tx_hash, creator_address, creation_index))`).
//! - [`rules`] — protocol-level structural rules for object state
//!   transitions (whitepaper sections 5.3, 5.4, and 5.4.1). These
//!   functions answer the consensus-layer question "is this
//!   operation structurally permitted given the object's current
//!   state?"
//!
//! Subsequent commits in Phase 4 will add object storage, version
//! tracking, transition application (mutating an `Object`'s fields
//! when a validator returns `Ok`; this layer only validates), and
//! the global note-commitment-tree (GNCT) skeleton per CLAUDE.md
//! section 6.
//!
//! # Module map
//!
//! | Module      | Whitepaper section      | Surface                                             |
//! |-------------|-------------------------|-----------------------------------------------------|
//! | (root)      | 5.1.1                   | [`derive_object_id`], `DerivationInput` (private)   |
//! | [`rules`]   | 5.3, 5.4, 5.4.1, 5.1.4  | [`can_modify_contents`], [`can_upgrade_rules`], [`can_freeze`], [`can_archive`], [`can_destroy`], [`can_restore`], [`RuleViolation`] |
//!
//! Derivation logic and structural-rule checks are deliberately in
//! separate modules: the derivation surface implements
//! consensus-canonical hashing, while the rules surface implements
//! consensus-layer structural enforcement. They will compose at
//! consensus integration (Phase 8) but they are distinct concerns.
//!
//! # Discipline reference
//!
//! See `CONTRIBUTING.md` "Derivation discipline" for the four
//! invariants every protocol-level identifier derivation must
//! satisfy (registered tag, BCS canonical input, tagged-SHA3
//! composition, KAT regression vector). The prior reference
//! implementation is `adamant-account::derive_address` (whitepaper
//! 4.2); this module mirrors its shape with a different domain tag
//! ([`adamant_crypto::domain::OBJECT_ID`]) and a different output
//! type ([`ObjectId`]).

pub mod rules;

pub use rules::{
    can_archive, can_destroy, can_freeze, can_modify_contents, can_restore, can_upgrade_rules,
    RuleViolation,
};

use adamant_crypto::{domain, hash::sha3_256_tagged};
use adamant_types::{Address, ObjectId, TxHash};
use serde::Serialize;

/// Canonical input to the [`ObjectId`] derivation formula
/// (whitepaper section 5.1.1).
///
/// Field order matches the byte order specified in the formula:
/// `creation_tx_hash || creator_address || creation_index`. BCS
/// (whitepaper section 5.1.8) encodes struct fields in
/// source-declaration order, so reordering these fields is a
/// consensus rule change. The BCS-canonicality test below pins the
/// byte layout.
///
/// Encoded length is exactly 72 bytes:
///   - 32 bytes `creation_tx_hash` (fixed-size byte array, no length prefix)
///   - 32 bytes `creator_address` (fixed-size byte array, no length prefix)
///   - 8 bytes `creation_index` (`u64` little-endian)
///
/// Private struct — used only by [`derive_object_id`]; callers do
/// not construct one directly.
#[derive(Serialize)]
struct DerivationInput<'a> {
    creation_tx_hash: &'a TxHash,
    creator_address: &'a Address,
    creation_index: u64,
}

/// Derive an [`ObjectId`] from its creation context, per whitepaper
/// section 5.1.1.
///
/// # Inputs
///
/// - `creation_tx_hash` — hash of the transaction that creates the
///   object. The hashing logic that produces a [`TxHash`] from a
///   transaction lands in `adamant-vm` (Phase 5) when the transaction
///   format is specified in whitepaper section 6.
/// - `creator_address` — address of the account that submitted the
///   creation transaction.
/// - `creation_index` — per-creator counter ensuring uniqueness when
///   one transaction creates multiple objects. The counter discipline
///   is the creator's responsibility; this function does not maintain
///   it.
///
/// # Output
///
/// A 32-byte [`ObjectId`] computed as
/// `sha3_256_tagged(OBJECT_ID, BCS(creation_tx_hash, creator_address, creation_index))`.
///
/// # Determinism
///
/// Identical inputs always produce identical output. Required by
/// consensus — every validator must derive the same [`ObjectId`] for
/// the same creation context.
///
/// # Panics
///
/// Cannot panic in practice. The internal `expect` is a contract
/// assertion: BCS encoding of [`DerivationInput`] is fixed-size
/// (32 + 32 + 8 = 72 bytes) and `bcs::to_bytes` does not fail for
/// inputs of this shape. A panic would indicate a defect in BCS or
/// in this crate's `Serialize` derive on [`DerivationInput`], not a
/// runtime failure mode.
#[must_use]
pub fn derive_object_id(
    creation_tx_hash: &TxHash,
    creator_address: &Address,
    creation_index: u64,
) -> ObjectId {
    let input = DerivationInput {
        creation_tx_hash,
        creator_address,
        creation_index,
    };
    let bcs_bytes = bcs::to_bytes(&input).expect(
        "DerivationInput is consensus-spec'd as 72 bytes (32 + 32 + 8) per whitepaper 5.1.1 \
         and BCS canonical encoding never fails for fixed-size types of this shape; if this \
         trips, the spec was changed without updating the type",
    );
    let hash = sha3_256_tagged(&domain::OBJECT_ID, &bcs_bytes);
    ObjectId::from_bytes(hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    use hex_literal::hex;

    fn fixed_tx_hash() -> TxHash {
        TxHash::from_bytes([
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
            0x1d, 0x1e, 0x1f, 0x20,
        ])
    }

    fn fixed_creator() -> Address {
        Address::from_bytes([
            0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e,
            0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c,
            0x3d, 0x3e, 0x3f, 0x40,
        ])
    }

    // ---------- determinism ----------

    /// Same inputs produce the same output. The protocol's minimum
    /// consensus requirement: every validator derives the same
    /// [`ObjectId`] for the same creation context.
    #[test]
    fn derivation_is_deterministic() {
        let a = derive_object_id(&fixed_tx_hash(), &fixed_creator(), 0);
        let b = derive_object_id(&fixed_tx_hash(), &fixed_creator(), 0);
        assert_eq!(a, b);
    }

    // ---------- distinct inputs distinguish ----------

    #[test]
    fn distinct_tx_hash_distinguishes() {
        let creator = fixed_creator();
        let a = derive_object_id(&fixed_tx_hash(), &creator, 0);
        let b = derive_object_id(&TxHash::from_bytes([0xff; 32]), &creator, 0);
        assert_ne!(a, b);
    }

    #[test]
    fn distinct_creator_distinguishes() {
        let tx = fixed_tx_hash();
        let a = derive_object_id(&tx, &fixed_creator(), 0);
        let b = derive_object_id(&tx, &Address::from_bytes([0xff; 32]), 0);
        assert_ne!(a, b);
    }

    #[test]
    fn distinct_creation_index_distinguishes() {
        let a = derive_object_id(&fixed_tx_hash(), &fixed_creator(), 0);
        let b = derive_object_id(&fixed_tx_hash(), &fixed_creator(), 1);
        assert_ne!(a, b);
    }

    // ---------- domain tag bytes ----------

    /// The domain tag is taken from the centralised registry, not
    /// inlined as a string literal. This test pins the registry's
    /// byte string against whitepaper section 5.1.1: renaming,
    /// reformatting, or replacing the tag fails this assertion.
    /// Tag changes are consensus rule changes per whitepaper 3.3.1.
    #[test]
    fn domain_tag_is_registry_value() {
        assert_eq!(domain::OBJECT_ID.as_bytes(), b"ADAMANT-v1-object-id");
    }

    // ---------- BCS canonicality ----------

    /// The BCS encoding of [`DerivationInput`] matches a manual
    /// concatenation of the three input fields in their canonical
    /// order — 32 bytes [`TxHash`] + 32 bytes [`Address`] + 8 bytes
    /// `u64` little-endian = 72 bytes. Per whitepaper 5.1.8.
    /// Failing this test indicates BCS or the `serde-big-array`
    /// integration has drifted, which would be a consensus-relevant
    /// change.
    #[test]
    fn bcs_input_layout_matches_manual_concatenation() {
        let tx_hash = fixed_tx_hash();
        let creator = fixed_creator();
        let creation_index: u64 = 0x0807_0605_0403_0201;

        let input = DerivationInput {
            creation_tx_hash: &tx_hash,
            creator_address: &creator,
            creation_index,
        };
        let bcs_bytes = bcs::to_bytes(&input).expect("bcs encode");

        let mut manual = Vec::with_capacity(72);
        manual.extend_from_slice(tx_hash.as_bytes());
        manual.extend_from_slice(creator.as_bytes());
        manual.extend_from_slice(&creation_index.to_le_bytes());

        assert_eq!(bcs_bytes, manual);
        assert_eq!(bcs_bytes.len(), 32 + 32 + 8);
    }

    // ---------- known-answer regression vector ----------

    /// Known-answer test pinning the canonical wire format for
    /// [`ObjectId`] derivation under fixed inputs. Per CONTRIBUTING.md
    /// "Derivation discipline" rule 4: the regression test catches
    /// any future change that would produce a different `ObjectId`
    /// from the same input.
    ///
    /// # Inputs
    ///
    /// - `creation_tx_hash` = `0x01_02_03_..._20` (32 bytes, `1..=32` ascending)
    /// - `creator_address` = `0x21_22_23_..._40` (32 bytes, `33..=64` ascending)
    /// - `creation_index` = `0`
    ///
    /// Inputs are byte-identical to `adamant-account::derive_address`'s
    /// KAT (commit 59a2e0d). Under identical inputs, the two
    /// derivations produce different outputs because the [`OBJECT_ID`]
    /// and [`adamant_crypto::domain::ACCOUNT_ADDRESS`] domain tags
    /// differ — this test thus also verifies domain separation
    /// between the two protocol-level identifier derivations. The
    /// `derive_address` KAT under these inputs is
    /// `0x76dd35e96242ef5dec1c5320f53eb2ea2724923e32f64e6843a7edcd8cc474a3`;
    /// `derive_object_id` produces a completely distinct output
    /// (asserted below) despite identical input bytes.
    ///
    /// # Computation a reviewer can verify by hand
    ///
    /// 1. Construct the BCS-encoded input (72 bytes):
    ///    - 32 bytes of the `creation_tx_hash` (`01 02 03 ... 20`)
    ///    - 32 bytes of the `creator_address` (`21 22 23 ... 40`)
    ///    - 8 bytes of `creation_index = 0` little-endian (`00 00 00 00 00 00 00 00`)
    /// 2. Compute the tag prefix
    ///    `prefix = SHA3-256(b"ADAMANT-v1-object-id")` (32 bytes).
    /// 3. Compute the tagged-hash output
    ///    `output = SHA3-256(prefix || prefix || BCS_input)` (32 bytes).
    /// 4. The returned [`ObjectId`] wraps `output` directly.
    ///
    /// The expected bytes were generated by running this derivation
    /// once and committing the output. A different result from the
    /// same inputs would indicate the `ObjectId` wire format has
    /// drifted.
    #[test]
    fn known_answer_regression_vector() {
        let actual = derive_object_id(&fixed_tx_hash(), &fixed_creator(), 0);
        let expected = ObjectId::from_bytes(hex!(
            "29dc934af31250ff64058b3ba70c2fadc84795fd94fd5fc6461500b8fbb1132f"
        ));
        assert_eq!(
            actual, expected,
            "object-id derivation regression — input/output stable wire format \
             for `derive_object_id(0x01..0x20, 0x21..0x40, 0)`. If this fails, \
             the protocol's ObjectId wire format has drifted; investigate \
             before changing the expected bytes."
        );
    }
}
