//! Note model + commitment derivation per whitepaper §7.1.
//!
//! Phase 6.1 ships the [`Note`] struct, [`NoteCommitment`] type,
//! and [`derive_note_commitment`] function. A note represents a
//! shielded value held by a specified recipient under specified
//! conditions; the commitment is what appears on-chain in the
//! global note commitment tree (§7.1.3).
//!
//! # Spec basis
//!
//! Whitepaper §7.1 verbatim:
//!
//! > A note is a tuple:
//! >
//! > ```text
//! > Note {
//! >     value:        u64,           // the amount, in the smallest unit
//! >     asset_type:   TypeId,        // identifies the type of asset (e.g. ADM, a token type)
//! >     recipient:    StealthAddress, // see section 7.2
//! >     randomness:   [u8; 32],      // sampled per note; ensures uncorrelatable commitments
//! >     metadata:     NoteMetadata,  // application-specific data
//! > }
//! > ```
//! >
//! > A note never appears on the chain in cleartext. What appears
//! > on the chain is the note's commitment, computed as:
//! >
//! > `commitment = Poseidon(value || asset_type || recipient || randomness || metadata_hash)`
//! >
//! > The commitment is 256 bits and reveals nothing about its
//! > inputs.
//!
//! # Field encoding for Poseidon inputs
//!
//! Per §3.3.3 (post-amendment instance 31), Poseidon operates on
//! Pallas base field elements. The five commitment inputs are
//! encoded as field elements:
//!
//! 1. `value` (u64): little-endian 8 bytes zero-padded to 32 bytes.
//!    `2^64 < p` so no reduction is needed; the canonical encoding
//!    is in range.
//! 2. `asset_type` ([`TypeId`], 32 bytes): reduced via
//!    [`FieldBytes::from_bytes_reduced`] (top 2 bits cleared). The
//!    2-bit entropy loss is documented at the helper's doc-comment;
//!    SHA3-derived `TypeId`s are uniform on input so the reduction
//!    preserves uniformity within `[0, 2^254)`.
//! 3. `recipient` ([`StealthAddress`], 32 bytes): same reduction.
//! 4. `randomness` ([u8; 32]): same reduction.
//! 5. `metadata_hash` (32 bytes): SHA3-256 of BCS-encoded
//!    [`NoteMetadata`] tagged with the registered
//!    `NOTE_METADATA_HASH` domain tag, then reduced.
//!
//! # `StealthAddress` placeholder
//!
//! [`StealthAddress`] is a 32-byte newtype at this sub-arc.
//! Phase 6.4 (§7.2 stealth-address construction) will replace its
//! semantic content with the ML-KEM-derived one-time address per
//! §7.2.2; the wire-format byte width stays at 32 bytes so the
//! commitment formula and its KAT vector are stable across the
//! 6.1 → 6.4 transition. Same posture as Phase 5/5b.1b's `U256`
//! thin newtype — encoding pinned now, semantic construction at
//! the section that defines it.

use adamant_crypto::domain;
use adamant_crypto::hash::sha3_256_tagged;
use adamant_types::TypeId;
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;

use crate::poseidon::{poseidon_hash, FieldBytes, POSEIDON_OUTPUT_BYTES};

/// One-time stealth address per whitepaper §7.2 (placeholder
/// shape at Phase 6.1; semantic construction lands at Phase 6.4).
///
/// 32-byte canonical encoding pinned now so the [`Note`]
/// commitment formula and its KAT regression vector remain
/// stable across the 6.1 → 6.4 transition. The byte width
/// matches §7.2.2's "one-time stealth address `P` derived from
/// `pk_s + s · G`" output (a Pallas base-field point's
/// canonical x-coordinate encoding will be this 32-byte width
/// when 6.4 ships).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct StealthAddress(#[serde(with = "BigArray")] [u8; 32]);

impl StealthAddress {
    /// Construct from raw 32-byte material. At Phase 6.1, the
    /// caller is responsible for the byte content; at Phase 6.4
    /// this constructor will be the entry point for ML-KEM-
    /// derived stealth addresses.
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

/// Application-specific metadata attached to a [`Note`] per
/// whitepaper §7.1 + §7.1.4.
///
/// > Adamant notes carry application-specific metadata, allowing
/// > contracts to attach arbitrary data to notes (e.g. a vesting
/// > schedule, an unlock condition, an attached message hash).
/// > The metadata is committed in the note commitment but visible
/// > only to view-key holders.
///
/// Opaque byte sequence at the protocol level. Application-level
/// schemas (token-amount vesting tables, NFT-metadata pointers,
/// etc.) are layered on top; the protocol commits to bytes only.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct NoteMetadata {
    /// Application-defined byte payload. Byte content is opaque
    /// to the protocol; the commitment binds the bytes via SHA3-
    /// 256 hash per §3.3.1's tagged-hash composition.
    pub data: Vec<u8>,
}

impl NoteMetadata {
    /// Construct an empty note metadata. The empty case is the
    /// natural default for notes without application-specific
    /// extensions (simple value transfers).
    #[must_use]
    pub fn empty() -> Self {
        Self { data: Vec::new() }
    }

    /// Construct from raw bytes.
    #[must_use]
    pub fn from_bytes(data: Vec<u8>) -> Self {
        Self { data }
    }
}

/// A shielded note per whitepaper §7.1.
///
/// `Note` carries the cleartext content. Only [`NoteCommitment`]
/// (the Poseidon hash of `Note`'s fields) appears on-chain;
/// `Note` itself is held off-chain by the recipient (decrypted
/// from the on-chain `EncryptedNote` via §7.3.1.1) and never
/// transmitted in cleartext.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Note {
    /// Amount in the asset's smallest unit. `u64` per §7.1; range
    /// proofs in the validity circuit (§7.3.2 step 5) ensure
    /// `value < 2^64`.
    pub value: u64,
    /// Type of asset (ADM, a token type, an NFT type, etc.) per
    /// §5.1.2.
    pub asset_type: TypeId,
    /// One-time stealth address of the recipient per §7.2.
    pub recipient: StealthAddress,
    /// Per-note randomness ensuring uncorrelatable commitments
    /// even when `(value, asset_type, recipient, metadata_hash)`
    /// match across notes. Sampled fresh per note construction;
    /// 256-bit entropy.
    #[serde(with = "BigArray")]
    pub randomness: [u8; 32],
    /// Application-specific metadata. Opaque to the protocol.
    pub metadata: NoteMetadata,
}

/// A 256-bit cryptographic commitment to a [`Note`] per
/// whitepaper §7.1.
///
/// `NoteCommitment` is what appears on-chain — published into the
/// global note commitment tree (§7.1.3) when a note is created.
/// The commitment reveals nothing about the note's contents;
/// recovering any of `(value, asset_type, recipient, randomness,
/// metadata_hash)` from `commitment` reduces to inverting
/// Poseidon, which is intractable.
///
/// 32 bytes per Pallas base field element canonical encoding.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct NoteCommitment(#[serde(with = "BigArray")] [u8; POSEIDON_OUTPUT_BYTES]);

impl NoteCommitment {
    /// Construct from raw 32-byte material. Used by tree-loaders
    /// that read commitments from on-chain serialized form.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; POSEIDON_OUTPUT_BYTES]) -> Self {
        Self(bytes)
    }

    /// Canonical 32-byte encoding.
    #[must_use]
    pub const fn to_bytes(self) -> [u8; POSEIDON_OUTPUT_BYTES] {
        self.0
    }

    /// Borrow the underlying bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; POSEIDON_OUTPUT_BYTES] {
        &self.0
    }
}

/// Encode a `u64` as a [`FieldBytes`] for Poseidon input.
///
/// `value < 2^64 < p`, so the value is always in field range
/// without reduction. The canonical encoding is little-endian
/// matching Pallas base field's `to_repr()` shape: 8 bytes of
/// the value in the low-order positions, 24 bytes of zero
/// padding above.
fn value_to_field_bytes(value: u64) -> FieldBytes {
    let mut bytes = [0u8; 32];
    bytes[..8].copy_from_slice(&value.to_le_bytes());
    // 2^64 < p: directly canonical, no reduction needed. Use
    // `from_bytes` rather than `from_bytes_reduced` to preserve
    // full entropy (the top 24 bytes are zero anyway).
    FieldBytes::from_bytes(bytes).expect(
        "u64 zero-padded to 32 bytes is always less than the Pallas base field characteristic",
    )
}

/// Compute the SHA3-256 hash of the note's metadata, tagged with
/// the registered `NOTE_METADATA_HASH` domain tag. Used as the
/// fifth Poseidon-input field element in
/// [`derive_note_commitment`].
fn metadata_hash(metadata: &NoteMetadata) -> [u8; 32] {
    let bcs_bytes = bcs::to_bytes(metadata).expect(
        "NoteMetadata is a Vec<u8> wrapped in a struct; BCS encoding never fails for this shape",
    );
    sha3_256_tagged(&domain::NOTE_METADATA_HASH, &bcs_bytes)
}

/// Derive the [`NoteCommitment`] for a [`Note`] per whitepaper
/// §7.1.
///
/// Implements the formula:
///
/// `commitment = Poseidon(value || asset_type || recipient || randomness || metadata_hash)`
///
/// where each input is encoded as a Pallas base field element
/// per the field-encoding rules documented at the module
/// preamble. Output is the canonical 32-byte little-endian
/// encoding of the resulting field element.
///
/// # Determinism
///
/// Identical [`Note`] inputs always produce identical
/// [`NoteCommitment`] output — required for consensus per §6.2.4.
/// Pinned by the deterministic test below; further pinned by the
/// known-answer test which catches any drift in:
///
/// - `halo2_gadgets`'s `P128Pow5T3` parameters (round constants,
///   MDS matrix)
/// - The field-encoding rules for `value` / `asset_type` /
///   `recipient` / `randomness`
/// - The `NOTE_METADATA_HASH_TAG` registered tag
/// - This module's input ordering
#[must_use]
pub fn derive_note_commitment(note: &Note) -> NoteCommitment {
    let inputs = [
        value_to_field_bytes(note.value),
        FieldBytes::from_bytes_reduced(note.asset_type.to_bytes()),
        FieldBytes::from_bytes_reduced(note.recipient.to_bytes()),
        FieldBytes::from_bytes_reduced(note.randomness),
        FieldBytes::from_bytes_reduced(metadata_hash(&note.metadata)),
    ];
    let output = poseidon_hash::<5>(inputs);
    NoteCommitment::from_bytes(output.to_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    fn fixed_type_id() -> TypeId {
        TypeId::from_bytes([0x11; 32])
    }

    fn fixed_recipient() -> StealthAddress {
        StealthAddress::from_bytes([0x22; 32])
    }

    fn fixed_note() -> Note {
        Note {
            value: 0x0807_0605_0403_0201,
            asset_type: fixed_type_id(),
            recipient: fixed_recipient(),
            randomness: [0x33; 32],
            metadata: NoteMetadata::from_bytes(b"app-metadata".to_vec()),
        }
    }

    // ---------- StealthAddress / NoteMetadata / NoteCommitment shape ----------

    #[test]
    fn stealth_address_round_trips_bytes() {
        let bytes = [0x77; 32];
        let addr = StealthAddress::from_bytes(bytes);
        assert_eq!(addr.to_bytes(), bytes);
        assert_eq!(addr.as_bytes(), &bytes);
    }

    #[test]
    fn note_metadata_empty_default() {
        let m = NoteMetadata::empty();
        assert!(m.data.is_empty());
        let m2 = NoteMetadata::default();
        assert_eq!(m, m2);
    }

    #[test]
    fn note_commitment_round_trips_bytes() {
        let bytes = [0x99; 32];
        let nc = NoteCommitment::from_bytes(bytes);
        assert_eq!(nc.to_bytes(), bytes);
        assert_eq!(nc.as_bytes(), &bytes);
    }

    #[test]
    fn note_commitment_bcs_round_trip() {
        let nc = NoteCommitment::from_bytes([0xAB; 32]);
        let encoded = bcs::to_bytes(&nc).unwrap();
        let decoded: NoteCommitment = bcs::from_bytes(&encoded).unwrap();
        assert_eq!(nc, decoded);
        assert_eq!(encoded.len(), 32);
    }

    // ---------- value_to_field_bytes ----------

    #[test]
    fn value_to_field_bytes_zero() {
        let fb = value_to_field_bytes(0);
        assert_eq!(fb.to_bytes(), [0u8; 32]);
    }

    #[test]
    fn value_to_field_bytes_max_u64() {
        let fb = value_to_field_bytes(u64::MAX);
        let mut expected = [0u8; 32];
        expected[..8].copy_from_slice(&u64::MAX.to_le_bytes());
        assert_eq!(fb.to_bytes(), expected);
    }

    #[test]
    fn value_to_field_bytes_distinct_values() {
        let a = value_to_field_bytes(7);
        let b = value_to_field_bytes(11);
        assert_ne!(a, b);
    }

    // ---------- metadata_hash ----------

    #[test]
    fn metadata_hash_empty_metadata_distinct_from_nonempty() {
        let h_empty = metadata_hash(&NoteMetadata::empty());
        let h_data = metadata_hash(&NoteMetadata::from_bytes(b"x".to_vec()));
        assert_ne!(h_empty, h_data);
    }

    #[test]
    fn metadata_hash_deterministic() {
        let m = NoteMetadata::from_bytes(b"deterministic".to_vec());
        assert_eq!(metadata_hash(&m), metadata_hash(&m));
    }

    // ---------- derive_note_commitment ----------

    /// Determinism per §6.2.4: same `Note` → same `NoteCommitment`.
    #[test]
    fn derive_note_commitment_deterministic() {
        let note = fixed_note();
        let a = derive_note_commitment(&note);
        let b = derive_note_commitment(&note);
        assert_eq!(a, b);
    }

    #[test]
    fn derive_note_commitment_distinct_value() {
        let mut note_a = fixed_note();
        let mut note_b = fixed_note();
        note_a.value = 100;
        note_b.value = 101;
        assert_ne!(
            derive_note_commitment(&note_a),
            derive_note_commitment(&note_b)
        );
    }

    #[test]
    fn derive_note_commitment_distinct_asset_type() {
        let mut note_a = fixed_note();
        let mut note_b = fixed_note();
        note_a.asset_type = TypeId::from_bytes([0xAA; 32]);
        note_b.asset_type = TypeId::from_bytes([0xBB; 32]);
        assert_ne!(
            derive_note_commitment(&note_a),
            derive_note_commitment(&note_b)
        );
    }

    #[test]
    fn derive_note_commitment_distinct_recipient() {
        let mut note_a = fixed_note();
        let mut note_b = fixed_note();
        note_a.recipient = StealthAddress::from_bytes([0xCC; 32]);
        note_b.recipient = StealthAddress::from_bytes([0xDD; 32]);
        assert_ne!(
            derive_note_commitment(&note_a),
            derive_note_commitment(&note_b)
        );
    }

    /// Whitepaper §7.1: "Two notes with the same `value`,
    /// `asset_type`, and `recipient` but different `randomness`
    /// values produce uncorrelated commitments." Pin this
    /// property.
    #[test]
    fn derive_note_commitment_distinct_randomness_uncorrelated() {
        let mut note_a = fixed_note();
        let mut note_b = fixed_note();
        note_a.randomness = [0x01; 32];
        note_b.randomness = [0x02; 32];
        let c_a = derive_note_commitment(&note_a);
        let c_b = derive_note_commitment(&note_b);
        assert_ne!(c_a, c_b);
        // Sanity: the two commitments differ in many bytes
        // (Poseidon is a hash; a 1-bit input change cascades).
        let differing_bytes = c_a
            .to_bytes()
            .iter()
            .zip(c_b.to_bytes().iter())
            .filter(|(a, b)| a != b)
            .count();
        assert!(
            differing_bytes >= 16,
            "expected substantial avalanche from differing randomness; got {differing_bytes} differing bytes"
        );
    }

    #[test]
    fn derive_note_commitment_distinct_metadata() {
        let mut note_a = fixed_note();
        let mut note_b = fixed_note();
        note_a.metadata = NoteMetadata::from_bytes(b"alpha".to_vec());
        note_b.metadata = NoteMetadata::from_bytes(b"beta".to_vec());
        assert_ne!(
            derive_note_commitment(&note_a),
            derive_note_commitment(&note_b)
        );
    }

    /// Domain-tag pin: the `NOTE_METADATA_HASH` byte string is
    /// consensus-critical (changing it changes every commitment
    /// derivation forever). Pin the registry value against the
    /// tag pattern §3.3.1 specifies.
    #[test]
    fn note_metadata_hash_tag_is_registry_value() {
        assert_eq!(
            domain::NOTE_METADATA_HASH.as_bytes(),
            b"ADAMANT-v1-note-metadata-hash"
        );
    }

    /// Known-answer regression vector for the canonical wire
    /// format of [`derive_note_commitment`] under the
    /// [`fixed_note`] fixture. This pin catches any drift in:
    ///
    /// - `halo2_gadgets`'s `P128Pow5T3` parameters
    /// - The field-encoding rules for any of the five inputs
    /// - The `NOTE_METADATA_HASH_TAG` byte string
    /// - This module's input ordering or BCS encoding of metadata
    ///
    /// The expected bytes were generated by running this test
    /// once and committing the output. A different result from
    /// the same `fixed_note()` would indicate a hard-fork-grade
    /// change to the protocol's note-commitment wire format;
    /// investigate before changing the expected bytes.
    /// # Inputs
    ///
    /// - `value` = `0x0807_0605_0403_0201`
    /// - `asset_type` = `TypeId([0x11; 32])`
    /// - `recipient` = `StealthAddress([0x22; 32])`
    /// - `randomness` = `[0x33; 32]`
    /// - `metadata` = `NoteMetadata { data: b"app-metadata" }`
    ///
    /// # Computation a reviewer can verify
    ///
    /// 1. Compute the metadata hash:
    ///    `metadata_hash = tagged_sha3_256(NOTE_METADATA_HASH, BCS(metadata))`
    /// 2. Encode each field as a `FieldBytes`:
    ///    - `value` zero-padded to 32 bytes (already < p)
    ///    - `asset_type`/`recipient`/`randomness`/`metadata_hash`
    ///      reduced via top-2-bits-clear (`from_bytes_reduced`)
    /// 3. Compute `Poseidon<P128Pow5T3, 5>([f1, f2, f3, f4, f5])`
    ///    via the `halo2_gadgets` out-of-circuit hash.
    /// 4. Output the 32-byte little-endian Pallas-base-field
    ///    canonical encoding of the result.
    ///
    /// The expected bytes were generated by running this
    /// derivation once and committing the output. A different
    /// result from the same inputs would indicate the protocol's
    /// note-commitment wire format has drifted, which is a hard-
    /// fork-grade change. Investigate before changing the
    /// expected bytes.
    #[test]
    fn derive_note_commitment_known_answer() {
        let actual = derive_note_commitment(&fixed_note());
        let expected = NoteCommitment::from_bytes(hex!(
            "15863c1901594d6401ae2f13e32cf91d03335f11e68eb5627ea2462703ef7b38"
        ));
        assert_eq!(
            actual, expected,
            "note-commitment regression — input/output stable wire format \
             for fixed_note(). If this fails, the protocol's note-commitment \
             wire format has drifted; investigate before changing the \
             expected bytes."
        );
    }
}
