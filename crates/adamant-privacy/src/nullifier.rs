//! Nullifier construction per whitepaper §7.1.2.
//!
//! Phase 6.2 ships the [`SpendingKey`] / [`NullifierKey`] /
//! [`Nullifier`] / [`LeafPosition`] types and the two derivation
//! functions: [`derive_nullifier_key`] (inner Poseidon over
//! `(domain, spending_key)`) and [`derive_nullifier`] (outer
//! Poseidon over `(domain, nullifier_key, note_commitment,
//! position)`).
//!
//! # Spec basis
//!
//! Whitepaper §7.1.2 verbatim:
//!
//! > Nullifier construction:
//! >
//! > ```text
//! > nullifier = Poseidon(domain_tag || nullifier_key || note_commitment || position_in_tree)
//! > ```
//! >
//! > Where:
//! > - `nullifier_key` is a key derived from the owner's spending
//! >   key (specifically: `nullifier_key = Poseidon(domain ||
//! >   spending_key)`)
//! > - `position_in_tree` is the note's leaf index in the global
//! >   commitment tree
//!
//! Critical properties (also from §7.1.2):
//!
//! > - **Unlinkability.** A nullifier reveals nothing about the
//! >   note it nullifies — neither value, recipient, nor commitment.
//! > - **Uniqueness.** Each note has exactly one valid nullifier.
//! > - **Unforgeability.** Producing the correct nullifier requires
//! >   the spending key.
//!
//! # Domain separation
//!
//! Two distinct registered domain tags per §3.3.1:
//!
//! - [`adamant_crypto::domain::NULLIFIER_HASH`] —
//!   `b"ADAMANT-v1-nullifier-hash"`. Used as the first
//!   field-element input to the outer Poseidon hash.
//! - [`adamant_crypto::domain::NULLIFIER_KEY_DERIVATION`] —
//!   `b"ADAMANT-v1-nullifier-key-derivation"`. Used as the first
//!   field-element input to the inner Poseidon derivation.
//!
//! Both byte tags are converted to Pallas-base-field elements
//! via [`domain_tag_to_field`] (tagged SHA3-256 of the empty
//! input under the registered tag, then reduced into the field).
//! This keeps the byte-level tag registry auditable while
//! providing field-element values usable inside Poseidon.
//!
//! # `SpendingKey` placeholder
//!
//! [`SpendingKey`] is a 32-byte newtype at this sub-arc.
//! Phase 6.5 (§7.4 view-key hierarchy + spending-key derivation
//! framing) refines its semantics; the wire-format byte width
//! stays at 32 bytes so the nullifier-key derivation and its KAT
//! vector remain stable across the 6.2 → 6.5 transition. Same
//! posture as Phase 6.1's [`crate::StealthAddress`] placeholder.

use adamant_crypto::domain;
use adamant_crypto::hash::sha3_256_tagged;
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use zeroize::Zeroize;

use crate::note::NoteCommitment;
use crate::poseidon::{poseidon_hash, FieldBytes};

/// Spending key per whitepaper §7.1.2 (placeholder shape at
/// Phase 6.2; semantic construction lands at Phase 6.5).
///
/// 32-byte canonical encoding pinned now so the
/// nullifier-key-derivation formula and its KAT regression
/// vector remain stable across the 6.2 → 6.5 transition.
///
/// `Zeroize` is implemented on drop because spending keys are
/// the protocol's most sensitive secret — exposure of a single
/// note's spending key allows construction of its nullifier and
/// thus a double-spend.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SpendingKey(#[serde(with = "BigArray")] [u8; 32]);

impl SpendingKey {
    /// Construct from raw 32-byte material.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Canonical 32-byte encoding.
    #[must_use]
    pub const fn to_bytes(&self) -> [u8; 32] {
        self.0
    }

    /// Borrow the underlying bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Drop for SpendingKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl Zeroize for SpendingKey {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

/// Nullifier key derived from a [`SpendingKey`] via the inner
/// Poseidon construction `Poseidon(domain || spending_key)` per
/// whitepaper §7.1.2.
///
/// Held in the wallet's secret state. Knowing a `NullifierKey`
/// is sufficient to construct nullifiers for any note whose
/// commitment + tree position the wallet observes — but
/// constructing valid nullifiers also requires knowing the
/// note's commitment + position, both of which are derived only
/// when scanning the chain with the corresponding view key.
///
/// `Zeroize` for the same reason as [`SpendingKey`]: leaking a
/// nullifier-key allows nullifier construction for any note the
/// holder owns.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct NullifierKey(#[serde(with = "BigArray")] [u8; 32]);

impl NullifierKey {
    /// Construct from raw 32-byte material (e.g., for tests
    /// or for loading from encrypted wallet storage).
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Canonical 32-byte encoding.
    #[must_use]
    pub const fn to_bytes(&self) -> [u8; 32] {
        self.0
    }
}

impl Drop for NullifierKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl Zeroize for NullifierKey {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

/// Position of a note's commitment in the global note commitment
/// tree per whitepaper §7.1.3.
///
/// 64-bit unsigned integer matching the GNCT depth of 64 (per
/// §7.1.3 "fixed depth of 64, allowing 2^64 notes"). Encoded as
/// a single Pallas-base-field element when fed into the
/// nullifier construction (`u64 < p` so no reduction needed).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct LeafPosition(pub u64);

impl LeafPosition {
    /// Encode as a [`FieldBytes`] field element. The u64 occupies
    /// the low 8 bytes; the upper 24 bytes are zero (well within
    /// the field).
    fn to_field_bytes(self) -> FieldBytes {
        let mut bytes = [0u8; 32];
        bytes[..8].copy_from_slice(&self.0.to_le_bytes());
        FieldBytes::from_bytes(bytes).expect(
            "u64 zero-padded to 32 bytes is always less than the Pallas base field characteristic",
        )
    }
}

/// 256-bit nullifier published on-chain when a note is spent per
/// whitepaper §7.1.2.
///
/// Two transactions publishing the same `Nullifier` are an
/// attempted double-spend; the chain rejects the second.
///
/// 32 bytes per Pallas base field canonical encoding.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct Nullifier(#[serde(with = "BigArray")] [u8; 32]);

impl Nullifier {
    /// Construct from raw 32-byte material.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Canonical 32-byte encoding.
    #[must_use]
    pub const fn to_bytes(self) -> [u8; 32] {
        self.0
    }

    /// Borrow the underlying bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Convert a registered byte-tag to its Pallas-base-field
/// element equivalent for use as a Poseidon domain-separation
/// input.
///
/// `tagged_hash_sha3(tag, b"")` followed by the standard
/// reduction (`FieldBytes::from_bytes_reduced`). Empty
/// tagged-hash input ensures the field-element value is
/// uniquely determined by the byte tag alone — adding context
/// bytes would change the output, but for domain-tag use we
/// want a constant per tag.
fn domain_tag_to_field(tag: &domain::DomainTag) -> FieldBytes {
    let bytes = sha3_256_tagged(tag, b"");
    FieldBytes::from_bytes_reduced(bytes)
}

/// Derive a [`NullifierKey`] from a [`SpendingKey`] per the
/// inner Poseidon construction in whitepaper §7.1.2.
///
/// `nullifier_key = Poseidon(NULLIFIER_KEY_DERIVATION_domain ||
/// spending_key)`
///
/// where the domain field element is derived from the
/// registered [`domain::NULLIFIER_KEY_DERIVATION`] byte tag.
#[must_use]
pub fn derive_nullifier_key(spending_key: &SpendingKey) -> NullifierKey {
    let inputs = [
        domain_tag_to_field(&domain::NULLIFIER_KEY_DERIVATION),
        FieldBytes::from_bytes_reduced(spending_key.to_bytes()),
    ];
    let output = poseidon_hash::<2>(inputs);
    NullifierKey::from_bytes(output.to_bytes())
}

/// Derive a [`Nullifier`] from a [`NullifierKey`], a
/// [`NoteCommitment`], and a [`LeafPosition`] per the outer
/// Poseidon construction in whitepaper §7.1.2.
///
/// `nullifier = Poseidon(NULLIFIER_HASH_domain || nullifier_key ||
/// note_commitment || position_in_tree)`
///
/// where the domain field element is derived from the
/// registered [`domain::NULLIFIER_HASH`] byte tag.
#[must_use]
pub fn derive_nullifier(
    nullifier_key: &NullifierKey,
    note_commitment: &NoteCommitment,
    position: LeafPosition,
) -> Nullifier {
    let inputs = [
        domain_tag_to_field(&domain::NULLIFIER_HASH),
        FieldBytes::from_bytes_reduced(nullifier_key.to_bytes()),
        FieldBytes::from_bytes_reduced(note_commitment.to_bytes()),
        position.to_field_bytes(),
    ];
    let output = poseidon_hash::<4>(inputs);
    Nullifier::from_bytes(output.to_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    fn fixed_spending_key() -> SpendingKey {
        SpendingKey::from_bytes([0x44; 32])
    }

    fn fixed_note_commitment() -> NoteCommitment {
        NoteCommitment::from_bytes([0x55; 32])
    }

    // ---------- Type-shape tests ----------

    #[test]
    fn spending_key_round_trips_bytes() {
        let bytes = [0x77; 32];
        let sk = SpendingKey::from_bytes(bytes);
        assert_eq!(sk.to_bytes(), bytes);
        assert_eq!(sk.as_bytes(), &bytes);
    }

    #[test]
    fn nullifier_key_round_trips_bytes() {
        let bytes = [0x88; 32];
        let nk = NullifierKey::from_bytes(bytes);
        assert_eq!(nk.to_bytes(), bytes);
    }

    #[test]
    fn nullifier_round_trips_bytes() {
        let bytes = [0x99; 32];
        let n = Nullifier::from_bytes(bytes);
        assert_eq!(n.to_bytes(), bytes);
        assert_eq!(n.as_bytes(), &bytes);
    }

    #[test]
    fn nullifier_bcs_round_trip() {
        let n = Nullifier::from_bytes([0xAB; 32]);
        let encoded = bcs::to_bytes(&n).unwrap();
        let decoded: Nullifier = bcs::from_bytes(&encoded).unwrap();
        assert_eq!(n, decoded);
        assert_eq!(encoded.len(), 32);
    }

    #[test]
    fn leaf_position_zero_field_encoding() {
        let fb = LeafPosition(0).to_field_bytes();
        assert_eq!(fb.to_bytes(), [0u8; 32]);
    }

    #[test]
    fn leaf_position_max_u64_field_encoding() {
        let fb = LeafPosition(u64::MAX).to_field_bytes();
        let mut expected = [0u8; 32];
        expected[..8].copy_from_slice(&u64::MAX.to_le_bytes());
        assert_eq!(fb.to_bytes(), expected);
    }

    // ---------- Domain-tag pins ----------

    #[test]
    fn nullifier_hash_tag_is_registry_value() {
        assert_eq!(
            domain::NULLIFIER_HASH.as_bytes(),
            b"ADAMANT-v1-nullifier-hash"
        );
    }

    #[test]
    fn nullifier_key_derivation_tag_is_registry_value() {
        assert_eq!(
            domain::NULLIFIER_KEY_DERIVATION.as_bytes(),
            b"ADAMANT-v1-nullifier-key-derivation"
        );
    }

    /// The two domain field-element values must differ, otherwise
    /// the inner-key derivation and outer-nullifier hash would
    /// share domain — defeating the cross-domain-attack defence.
    #[test]
    fn nullifier_domain_field_elements_distinct() {
        let outer = domain_tag_to_field(&domain::NULLIFIER_HASH);
        let inner = domain_tag_to_field(&domain::NULLIFIER_KEY_DERIVATION);
        assert_ne!(outer, inner);
    }

    // ---------- derive_nullifier_key ----------

    #[test]
    fn derive_nullifier_key_deterministic() {
        let sk = fixed_spending_key();
        let a = derive_nullifier_key(&sk);
        let b = derive_nullifier_key(&sk);
        assert_eq!(a, b);
    }

    #[test]
    fn derive_nullifier_key_distinct_spending_keys() {
        let a = derive_nullifier_key(&SpendingKey::from_bytes([0x01; 32]));
        let b = derive_nullifier_key(&SpendingKey::from_bytes([0x02; 32]));
        assert_ne!(a, b);
    }

    // ---------- derive_nullifier ----------

    #[test]
    fn derive_nullifier_deterministic() {
        let sk = fixed_spending_key();
        let nk = derive_nullifier_key(&sk);
        let nc = fixed_note_commitment();
        let pos = LeafPosition(42);
        let a = derive_nullifier(&nk, &nc, pos);
        let b = derive_nullifier(&nk, &nc, pos);
        assert_eq!(a, b);
    }

    #[test]
    fn derive_nullifier_distinct_nullifier_key() {
        let nc = fixed_note_commitment();
        let pos = LeafPosition(0);
        let a = derive_nullifier(&NullifierKey::from_bytes([0x01; 32]), &nc, pos);
        let b = derive_nullifier(&NullifierKey::from_bytes([0x02; 32]), &nc, pos);
        assert_ne!(a, b);
    }

    #[test]
    fn derive_nullifier_distinct_note_commitment() {
        let nk = derive_nullifier_key(&fixed_spending_key());
        let pos = LeafPosition(0);
        let a = derive_nullifier(&nk, &NoteCommitment::from_bytes([0x01; 32]), pos);
        let b = derive_nullifier(&nk, &NoteCommitment::from_bytes([0x02; 32]), pos);
        assert_ne!(a, b);
    }

    /// Whitepaper §7.1.2 uniqueness: each note has exactly one
    /// valid nullifier — implicitly, distinct positions for the
    /// same note produce distinct nullifiers (since position is
    /// in the hash input).
    #[test]
    fn derive_nullifier_distinct_position() {
        let nk = derive_nullifier_key(&fixed_spending_key());
        let nc = fixed_note_commitment();
        let a = derive_nullifier(&nk, &nc, LeafPosition(7));
        let b = derive_nullifier(&nk, &nc, LeafPosition(11));
        assert_ne!(a, b);
    }

    /// Cross-domain-attack defence: the field-element output of
    /// the inner derivation must NOT collide with the outer
    /// hash's output even when fed otherwise-identical inputs.
    /// This is structurally guaranteed by the distinct domain
    /// tags + the 2-input vs 4-input arity (Poseidon's
    /// `ConstantLength` domain mixes arity into the hash). Pin
    /// it explicitly.
    #[test]
    fn derive_nullifier_key_and_nullifier_outputs_distinct() {
        let sk = fixed_spending_key();
        let nk = derive_nullifier_key(&sk);
        // Construct a "synthetic" nullifier where every input
        // matches the inner derivation's shape if interpreted
        // generously: nullifier_key = sk, note_commitment = 0,
        // position = 0.
        let synthetic_nullifier = derive_nullifier(
            &NullifierKey::from_bytes(sk.to_bytes()),
            &NoteCommitment::from_bytes([0u8; 32]),
            LeafPosition(0),
        );
        assert_ne!(nk.to_bytes(), synthetic_nullifier.to_bytes());
    }

    // ---------- KAT regression vector ----------

    /// # Inputs
    ///
    /// - `spending_key` = `SpendingKey([0x44; 32])`
    /// - `note_commitment` = `NoteCommitment([0x55; 32])`
    /// - `position` = `LeafPosition(42)`
    ///
    /// Pins the canonical wire format end-to-end:
    /// - `derive_nullifier_key(spending_key)`
    /// - `derive_nullifier(nullifier_key, note_commitment, position)`
    ///
    /// A different output from these inputs indicates the
    /// protocol's nullifier wire format has drifted —
    /// hard-fork-grade change.
    #[test]
    fn nullifier_known_answer_regression() {
        let sk = fixed_spending_key();
        let nk = derive_nullifier_key(&sk);
        let nc = fixed_note_commitment();
        let pos = LeafPosition(42);
        let nullifier = derive_nullifier(&nk, &nc, pos);

        let expected_nk = NullifierKey::from_bytes(hex!(
            "8c1d82eede4466430bb445bfa4d4d703641bce7fac136f7d1e1be8f249585610"
        ));
        let expected_n = Nullifier::from_bytes(hex!(
            "f94a46d5ca2d23cf39c65292df8c5910f34a317ea8cf67d62c88370df4916f00"
        ));
        assert_eq!(
            nk.to_bytes(),
            expected_nk.to_bytes(),
            "nullifier-key regression — input/output stable wire format \
             for fixed_spending_key(). If this fails, the protocol's \
             nullifier-key derivation has drifted; investigate before \
             changing the expected bytes."
        );
        assert_eq!(
            nullifier.to_bytes(),
            expected_n.to_bytes(),
            "nullifier regression — input/output stable wire format for \
             fixed_spending_key() + fixed_note_commitment() + LeafPosition(42). \
             If this fails, the protocol's nullifier derivation has drifted; \
             investigate before changing the expected bytes."
        );
    }
}
