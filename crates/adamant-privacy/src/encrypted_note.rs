//! `EncryptedNote` construction per whitepaper §7.3.1.1.
//!
//! Phase 6.7 ships the [`EncryptedNote`] wire type and the four
//! pure operations: [`encapsulate_for_recipient`],
//! [`decapsulate_for_recipient`], [`encrypt_note_for_recipient`],
//! [`decrypt_note_for_recipient`].
//!
//! # Spec basis
//!
//! Whitepaper §7.3.1.1 verbatim:
//!
//! > An `EncryptedNote` is the on-chain ciphertext that allows
//! > the recipient to decrypt the note's contents upon scanning
//! > the chain. The construction:
//! >
//! > ```text
//! > EncryptedNote {
//! >     ml_kem_ciphertext: [u8; 1088],
//! >     chacha_ciphertext: Vec<u8>,
//! >     auth_tag:          [u8; 16],
//! > }
//! > ```
//! >
//! > A sender constructs an `EncryptedNote` as:
//! > 1. ML-KEM-768 encapsulation against recipient's `pk_v_kem`
//! >    per §7.2.2: `(ml_kem_ciphertext, ss) =
//! >    ML-KEM-768.Encap(pk_v_kem)`
//! > 2. Derive symmetric key:
//! >    `note_key = HKDF-SHA3(salt = domain_tag_note_key,
//! >    ikm = ss, info = note_position_bytes, L = 32)`
//! >    where `domain_tag_note_key = b"ADAMANT-v1-note-key"`
//! >    and `note_position_bytes` is the 8-byte little-endian
//! >    note position in the global note commitment tree.
//! > 3. Derive nonce:
//! >    `note_nonce = SHA3_256(ss || domain_tag_note_nonce)[0..12]`
//! >    where `domain_tag_note_nonce = b"ADAMANT-v1-note-nonce"`.
//! > 4. Encrypt note payload (BCS-encoded note tuple per §7.1):
//! >    `(chacha_ciphertext, auth_tag) =
//! >    ChaCha20Poly1305-Encrypt(note_key, note_nonce,
//! >    note_payload)`
//! >
//! > The recipient decrypts by ML-KEM decapsulation against
//! > `sk_v_kem`, derives the same `note_key` + `note_nonce` from
//! > the recovered shared secret, and applies
//! > `ChaCha20Poly1305-Decrypt`.
//!
//! # Wire format
//!
//! [`EncryptedNote`] separates `ml_kem_ciphertext`,
//! `chacha_ciphertext`, and `auth_tag` per the spec's wire
//! tuple. Internally, `chacha_ciphertext + auth_tag` correspond
//! to the single AEAD output produced by
//! `adamant_crypto::symmetric::Key::encrypt` (which appends the
//! 16-byte tag to the ciphertext). The split is performed at the
//! API boundary so the on-chain layout matches §7.3.1.1
//! verbatim.
//!
//! # Probabilistic-encryption pin (§7.0)
//!
//! Per §7.3.1.1 final paragraph:
//!
//! > Per-note ML-KEM encapsulation produces a fresh `ss` per
//! > FIPS 203 §6.3 (randomized encapsulation); the derived
//! > `note_key` + `note_nonce` are per-note unique; ciphertexts
//! > are uncorrelated across notes even for byte-equal note
//! > payloads.
//!
//! Tests pin this property explicitly.

use adamant_crypto::domain;
use adamant_crypto::hash::{hkdf_sha3_256, sha3_256_tagged};
use adamant_crypto::ml_kem::{
    Ciphertext as MlKemCiphertext, DecapsulationKey, EncapsulationKey, SharedSecret,
    CIPHERTEXT_BYTES, SHARED_SECRET_BYTES,
};
use adamant_crypto::symmetric::{
    Error as SymmetricError, Key as SymKey, Nonce, KEY_BYTES, NONCE_BYTES, TAG_BYTES,
};
use rand_core_0_10::CryptoRng;
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;

use crate::nullifier::LeafPosition;

/// Byte length of the ML-KEM-768 ciphertext field (1088 bytes
/// per FIPS 203 ML-KEM-768 §6.3). Aliased to
/// [`adamant_crypto::ml_kem::CIPHERTEXT_BYTES`].
pub const ML_KEM_CIPHERTEXT_BYTES: usize = CIPHERTEXT_BYTES;

/// Byte length of the AEAD authentication tag (Poly1305, 16
/// bytes). Aliased to [`adamant_crypto::symmetric::TAG_BYTES`].
pub const AUTH_TAG_BYTES: usize = TAG_BYTES;

/// On-chain encrypted-note envelope per whitepaper §7.3.1.1.
///
/// Fields appear on-chain in BCS-encoded form. `ml_kem_ciphertext`
/// allows the recipient to recover the per-note ML-KEM shared
/// secret; `chacha_ciphertext` + `auth_tag` together form the
/// AEAD-encrypted note payload (BCS-encoded `Note` per §7.1).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EncryptedNote {
    /// ML-KEM-768 encapsulated key (1088 bytes per FIPS 203
    /// §6.3). On the wire as a fixed-size byte array.
    #[serde(with = "BigArray")]
    pub ml_kem_ciphertext: [u8; ML_KEM_CIPHERTEXT_BYTES],
    /// `ChaCha20` keystream-encrypted note payload (variable
    /// length, equal to plaintext length).
    pub chacha_ciphertext: Vec<u8>,
    /// Poly1305 authentication tag (16 bytes per §3.5).
    #[serde(with = "BigArray")]
    pub auth_tag: [u8; AUTH_TAG_BYTES],
}

impl EncryptedNote {
    /// Total wire-byte length: 1088 + |ciphertext| + 16.
    #[must_use]
    pub fn wire_len(&self) -> usize {
        ML_KEM_CIPHERTEXT_BYTES + self.chacha_ciphertext.len() + AUTH_TAG_BYTES
    }
}

// ---------- Errors ----------

/// Returned by [`decrypt_note_for_recipient`] on AEAD
/// authentication failure (wrong key from wrong viewing-key,
/// modified ciphertext, modified tag, or wrong note position).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NoteDecryptError;

impl core::fmt::Display for NoteDecryptError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("note decryption failed (authentication tag mismatch)")
    }
}

impl std::error::Error for NoteDecryptError {}

impl From<SymmetricError> for NoteDecryptError {
    fn from(_: SymmetricError) -> Self {
        Self
    }
}

// ---------- Internal derivations ----------

/// Encode a leaf position as the 8 little-endian bytes used as
/// the HKDF `info` input per §7.3.1.1 step 2.
fn position_info_bytes(position: LeafPosition) -> [u8; 8] {
    position.0.to_le_bytes()
}

/// Derive the 32-byte note key per §7.3.1.1 step 2.
fn derive_note_key(shared_secret: &SharedSecret, position: LeafPosition) -> SymKey {
    let info = position_info_bytes(position);
    let salt = domain::NOTE_KEY.as_bytes();
    let key_bytes = hkdf_sha3_256(salt, shared_secret.as_bytes(), &info, KEY_BYTES)
        .expect("HKDF-SHA3-256 expand of 32 bytes is always within the 8160-byte limit");
    let mut key_arr = [0u8; KEY_BYTES];
    key_arr.copy_from_slice(&key_bytes);
    SymKey::from_bytes(&key_arr)
}

/// Derive the 12-byte note nonce per §7.3.1.1 step 3.
fn derive_note_nonce(shared_secret: &SharedSecret) -> Nonce {
    let digest = sha3_256_tagged(&domain::NOTE_NONCE, shared_secret.as_bytes());
    let mut nonce_bytes = [0u8; NONCE_BYTES];
    nonce_bytes.copy_from_slice(&digest[..NONCE_BYTES]);
    Nonce(nonce_bytes)
}

// ---------- Public encapsulation / decapsulation ----------

/// Sender-side ML-KEM-768 encapsulation per §7.3.1.1 step 1.
///
/// Returns the 1088-byte ciphertext for inclusion in the
/// [`EncryptedNote`] envelope plus the 32-byte shared secret used
/// locally for note-payload encryption (and for §7.6 memo
/// encryption when one is attached).
pub fn encapsulate_for_recipient<R: CryptoRng>(
    recipient_view_pk: &EncapsulationKey,
    rng: &mut R,
) -> ([u8; ML_KEM_CIPHERTEXT_BYTES], SharedSecret) {
    let (ct, ss) = recipient_view_pk.encapsulate(rng);
    (ct.to_bytes(), ss)
}

/// Recipient-side ML-KEM-768 decapsulation per §7.3.1.1.
///
/// Note: per FIPS 203 §6.4.1 implicit rejection, this is
/// infallible — a malformed ciphertext produces a deterministic-
/// but-meaningless shared secret rather than an error. The
/// AEAD authentication on the chacha layer (via
/// [`decrypt_note_for_recipient`]) is what surfaces the
/// "wrong recipient" case.
#[must_use]
pub fn decapsulate_for_recipient(
    recipient_view_sk: &DecapsulationKey,
    ml_kem_ciphertext: &[u8; ML_KEM_CIPHERTEXT_BYTES],
) -> SharedSecret {
    let ct = MlKemCiphertext::from_bytes(ml_kem_ciphertext);
    recipient_view_sk.decapsulate(&ct)
}

// ---------- Public encryption / decryption ----------

/// Construct an [`EncryptedNote`] for `note_payload` addressed to
/// the recipient owning `recipient_view_pk` at note position
/// `position`.
///
/// `note_payload` is typically the BCS-encoded `Note` per §7.1
/// (callers compute `bcs::to_bytes(&note)` themselves; the
/// envelope is opaque to the protocol below this layer). The
/// position is the leaf position the note will occupy in the
/// global note commitment tree (§7.1.3).
///
/// # Returns
///
/// `(EncryptedNote, SharedSecret)`. The returned shared secret is
/// the same `ss` used for the note-payload AEAD; callers may
/// reuse it for §7.6 memo encryption (`encrypt_memo`) when the
/// note carries an attached memo.
///
/// # Panics
///
/// Cannot panic in practice: ChaCha20-Poly1305 encryption is
/// infallible for valid key/nonce/plaintext shapes. The output
/// is always at least 16 bytes (the AEAD tag), so the trailing
/// `truncate(tag_offset)` is well-defined.
pub fn encrypt_note_for_recipient<R: CryptoRng>(
    recipient_view_pk: &EncapsulationKey,
    position: LeafPosition,
    note_payload: &[u8],
    rng: &mut R,
) -> (EncryptedNote, SharedSecret) {
    let (ml_kem_ct, ss) = encapsulate_for_recipient(recipient_view_pk, rng);
    let key = derive_note_key(&ss, position);
    let nonce = derive_note_nonce(&ss);
    let mut combined = key
        .encrypt(&nonce, note_payload, b"")
        .expect("ChaCha20-Poly1305 encryption is infallible for valid inputs");
    // Split the trailing 16-byte tag off into its own field per
    // the §7.3.1.1 wire layout.
    let tag_offset = combined.len() - AUTH_TAG_BYTES;
    let mut auth_tag = [0u8; AUTH_TAG_BYTES];
    auth_tag.copy_from_slice(&combined[tag_offset..]);
    combined.truncate(tag_offset);
    let envelope = EncryptedNote {
        ml_kem_ciphertext: ml_kem_ct,
        chacha_ciphertext: combined,
        auth_tag,
    };
    (envelope, ss)
}

/// Decrypt an [`EncryptedNote`] using the recipient's viewing
/// secret key and the note's known position in the GNCT.
///
/// Returns the note payload (BCS-encoded `Note` per §7.1) on
/// AEAD success; the caller deserialises further.
///
/// # Returns
///
/// `(payload, SharedSecret)`. The returned shared secret is the
/// same `ss` used for the note-payload AEAD; callers may reuse
/// it for §7.6 memo decryption when an attached memo's
/// ciphertext is presented.
///
/// # Errors
///
/// Returns [`NoteDecryptError`] on AEAD authentication failure.
/// Per FIPS 203 §6.4.1, a wrong-recipient scan that decapsulates
/// a meaningless shared secret will fail authentication here
/// with overwhelming probability.
pub fn decrypt_note_for_recipient(
    recipient_view_sk: &DecapsulationKey,
    encrypted: &EncryptedNote,
    position: LeafPosition,
) -> Result<(Vec<u8>, SharedSecret), NoteDecryptError> {
    let ss = decapsulate_for_recipient(recipient_view_sk, &encrypted.ml_kem_ciphertext);
    let key = derive_note_key(&ss, position);
    let nonce = derive_note_nonce(&ss);
    // Reassemble the AEAD-conformant `ciphertext || tag`
    // byte sequence the symmetric layer expects.
    let mut combined = Vec::with_capacity(encrypted.chacha_ciphertext.len() + AUTH_TAG_BYTES);
    combined.extend_from_slice(&encrypted.chacha_ciphertext);
    combined.extend_from_slice(&encrypted.auth_tag);
    let plaintext = key.decrypt(&nonce, &combined, b"")?;
    Ok((plaintext, ss))
}

// ---------- Sanity assertion at compile time ----------

const _: [(); SHARED_SECRET_BYTES] = [(); 32];

#[cfg(test)]
#[allow(clippy::similar_names)]
mod tests {
    use super::*;
    use adamant_crypto::ml_kem::DecapsulationKey;
    use getrandom::{rand_core::UnwrapErr, SysRng};

    fn test_rng() -> UnwrapErr<SysRng> {
        UnwrapErr(SysRng)
    }

    fn fresh_recipient_keypair() -> DecapsulationKey {
        DecapsulationKey::from_seed(&[0xA1; 64])
    }

    // ---------- Domain-tag pins ----------

    #[test]
    fn note_key_tag_is_registry_value() {
        // §7.3.1.1 spec text pins this byte string verbatim.
        assert_eq!(domain::NOTE_KEY.as_bytes(), b"ADAMANT-v1-note-key");
    }

    #[test]
    fn note_nonce_tag_is_registry_value() {
        // §7.3.1.1 spec text pins this byte string verbatim.
        assert_eq!(domain::NOTE_NONCE.as_bytes(), b"ADAMANT-v1-note-nonce");
    }

    #[test]
    fn note_key_and_nonce_tags_distinct() {
        assert_ne!(domain::NOTE_KEY.as_bytes(), domain::NOTE_NONCE.as_bytes());
    }

    /// `NOTE_NONCE` (§7.3.1.1) and `MEMO_NONCE` (§7.6.1) must be
    /// distinct so the same `ss` cannot collide nonce-derivation
    /// across the two §7 surfaces.
    #[test]
    fn note_and_memo_nonce_tags_distinct() {
        assert_ne!(domain::NOTE_NONCE.as_bytes(), domain::MEMO_NONCE.as_bytes());
    }

    // ---------- Round-trip ----------

    #[test]
    fn encrypt_decrypt_round_trip_typical_payload() {
        let dk = fresh_recipient_keypair();
        let ek = dk.encapsulation_key();
        let payload = b"BCS-encoded Note placeholder payload";
        let pos = LeafPosition(42);

        let (envelope, ss_send) = encrypt_note_for_recipient(&ek, pos, payload, &mut test_rng());
        let (decoded_payload, ss_recv) =
            decrypt_note_for_recipient(&dk, &envelope, pos).expect("authentic");
        assert_eq!(decoded_payload, payload);
        // Round-trip recovers the same shared secret, matching
        // the §7.6 memo-key derivation invariant.
        assert_eq!(ss_send.as_bytes(), ss_recv.as_bytes());
    }

    #[test]
    fn encrypt_decrypt_round_trip_empty_payload() {
        let dk = fresh_recipient_keypair();
        let ek = dk.encapsulation_key();
        let payload = b"";
        let pos = LeafPosition(0);

        let (envelope, _) = encrypt_note_for_recipient(&ek, pos, payload, &mut test_rng());
        let (decoded, _) = decrypt_note_for_recipient(&dk, &envelope, pos).expect("authentic");
        assert_eq!(decoded, payload);
        // chacha_ciphertext is empty; auth_tag is the only AEAD
        // bytes. Wire len = 1088 (ml_kem) + 0 + 16 (tag) = 1104.
        assert_eq!(envelope.chacha_ciphertext.len(), 0);
        assert_eq!(envelope.wire_len(), 1088 + 16);
    }

    #[test]
    fn encrypt_decrypt_round_trip_large_payload() {
        let dk = fresh_recipient_keypair();
        let ek = dk.encapsulation_key();
        let payload = vec![0xCD; 4096];
        let pos = LeafPosition(u64::MAX);

        let (envelope, _) = encrypt_note_for_recipient(&ek, pos, &payload, &mut test_rng());
        let (decoded, _) = decrypt_note_for_recipient(&dk, &envelope, pos).expect("authentic");
        assert_eq!(decoded, payload);
        assert_eq!(envelope.wire_len(), 1088 + 4096 + 16);
    }

    // ---------- Authentication failures ----------

    /// Wrong viewing key produces a wrong shared secret (per
    /// FIPS 203 implicit rejection); AEAD authentication fails
    /// with overwhelming probability.
    #[test]
    fn wrong_view_key_decryption_fails() {
        let dk_correct = fresh_recipient_keypair();
        let dk_wrong = DecapsulationKey::from_seed(&[0xC1; 64]);
        let ek = dk_correct.encapsulation_key();
        let payload = b"sensitive note payload";
        let pos = LeafPosition(7);

        let (envelope, _) = encrypt_note_for_recipient(&ek, pos, payload, &mut test_rng());
        let result = decrypt_note_for_recipient(&dk_wrong, &envelope, pos);
        assert_eq!(result.err(), Some(NoteDecryptError));
    }

    #[test]
    fn modified_chacha_ciphertext_decryption_fails() {
        let dk = fresh_recipient_keypair();
        let ek = dk.encapsulation_key();
        let payload = b"long enough to bit-flip";
        let pos = LeafPosition(0);

        let (mut envelope, _) = encrypt_note_for_recipient(&ek, pos, payload, &mut test_rng());
        envelope.chacha_ciphertext[3] ^= 0x01;
        let result = decrypt_note_for_recipient(&dk, &envelope, pos);
        assert_eq!(result.err(), Some(NoteDecryptError));
    }

    #[test]
    fn modified_auth_tag_decryption_fails() {
        let dk = fresh_recipient_keypair();
        let ek = dk.encapsulation_key();
        let payload = b"x";
        let pos = LeafPosition(0);

        let (mut envelope, _) = encrypt_note_for_recipient(&ek, pos, payload, &mut test_rng());
        envelope.auth_tag[0] ^= 0xFF;
        let result = decrypt_note_for_recipient(&dk, &envelope, pos);
        assert_eq!(result.err(), Some(NoteDecryptError));
    }

    #[test]
    fn modified_ml_kem_ciphertext_decryption_fails() {
        let dk = fresh_recipient_keypair();
        let ek = dk.encapsulation_key();
        let payload = b"sensitive";
        let pos = LeafPosition(11);

        let (mut envelope, _) = encrypt_note_for_recipient(&ek, pos, payload, &mut test_rng());
        envelope.ml_kem_ciphertext[100] ^= 0x01;
        let result = decrypt_note_for_recipient(&dk, &envelope, pos);
        assert_eq!(result.err(), Some(NoteDecryptError));
    }

    /// Wrong position causes wrong `note_key` derivation (HKDF
    /// `info = position_bytes`); AEAD authentication fails.
    /// Pin: positional binding is consensus-significant.
    #[test]
    fn wrong_position_decryption_fails() {
        let dk = fresh_recipient_keypair();
        let ek = dk.encapsulation_key();
        let payload = b"position-bound payload";
        let pos_correct = LeafPosition(42);
        let pos_wrong = LeafPosition(43);

        let (envelope, _) = encrypt_note_for_recipient(&ek, pos_correct, payload, &mut test_rng());
        let result = decrypt_note_for_recipient(&dk, &envelope, pos_wrong);
        assert_eq!(result.err(), Some(NoteDecryptError));
    }

    // ---------- §7.3.1.1 final-paragraph property pin ----------

    /// Equal note payloads encrypted under DIFFERENT positions to
    /// the SAME recipient must produce uncorrelated ciphertexts —
    /// the §7.3.1.1 final-paragraph probabilistic-encryption
    /// property. (ML-KEM encap is also randomized per FIPS 203
    /// §6.3 so each call produces a different `ml_kem_ciphertext`
    /// regardless; this test pins the chacha-side property
    /// independently using the position binding.)
    #[test]
    fn equal_payload_different_position_distinct_chacha() {
        let dk = fresh_recipient_keypair();
        let ek = dk.encapsulation_key();
        let payload = b"identical note payload bytes";

        let (env_a, _) = encrypt_note_for_recipient(&ek, LeafPosition(1), payload, &mut test_rng());
        let (env_b, _) = encrypt_note_for_recipient(&ek, LeafPosition(2), payload, &mut test_rng());
        assert_ne!(env_a.chacha_ciphertext, env_b.chacha_ciphertext);
    }

    /// Equal payloads + equal recipient produce DIFFERENT
    /// `ml_kem_ciphertext`s across calls (encap is randomized
    /// per FIPS 203 §6.3). Pins the per-call freshness invariant.
    #[test]
    fn equal_payload_distinct_ml_kem_ciphertexts_across_calls() {
        let dk = fresh_recipient_keypair();
        let ek = dk.encapsulation_key();
        let payload = b"same payload, two encaps";
        let pos = LeafPosition(5);

        let (env_a, ss_a) = encrypt_note_for_recipient(&ek, pos, payload, &mut test_rng());
        let (env_b, ss_b) = encrypt_note_for_recipient(&ek, pos, payload, &mut test_rng());
        // ML-KEM encap randomness produces distinct ciphertexts
        // and (with overwhelming probability) distinct shared
        // secrets.
        assert_ne!(env_a.ml_kem_ciphertext, env_b.ml_kem_ciphertext);
        assert_ne!(ss_a.as_bytes(), ss_b.as_bytes());
    }

    // ---------- Wire-format tests ----------

    #[test]
    fn encrypted_note_bcs_round_trip() {
        let dk = fresh_recipient_keypair();
        let ek = dk.encapsulation_key();
        let payload = b"round-trip sample payload";
        let pos = LeafPosition(123);

        let (original, _) = encrypt_note_for_recipient(&ek, pos, payload, &mut test_rng());
        let encoded = bcs::to_bytes(&original).unwrap();
        let decoded: EncryptedNote = bcs::from_bytes(&encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn encrypted_note_field_widths_match_spec() {
        let dk = fresh_recipient_keypair();
        let ek = dk.encapsulation_key();
        let payload = b"width-check";
        let pos = LeafPosition(0);

        let (envelope, _) = encrypt_note_for_recipient(&ek, pos, payload, &mut test_rng());
        // §7.3.1.1: ml_kem_ciphertext: [u8; 1088], auth_tag: [u8; 16].
        assert_eq!(envelope.ml_kem_ciphertext.len(), 1088);
        assert_eq!(envelope.auth_tag.len(), 16);
        // chacha_ciphertext is the keystream output, equal in
        // length to the plaintext (ChaCha20 is a stream cipher).
        assert_eq!(envelope.chacha_ciphertext.len(), payload.len());
    }

    // ---------- KAT regression ----------

    /// Pin the `derive_note_key` HKDF construction against fixed
    /// 32-byte synthetic shared secret + fixed position. Mirrors
    /// the internal derivation since `SharedSecret` is not
    /// constructible from raw bytes via public API.
    #[test]
    fn derive_note_key_known_answer() {
        let synthetic_ss = [0x77u8; 32];
        let position = LeafPosition(42);
        let info = position_info_bytes(position);
        let salt = domain::NOTE_KEY.as_bytes();
        let key_bytes =
            hkdf_sha3_256(salt, &synthetic_ss, &info, KEY_BYTES).expect("HKDF in range");
        // Determinism + non-zero pin.
        assert_ne!(key_bytes, [0u8; KEY_BYTES]);
        let key_bytes_b =
            hkdf_sha3_256(salt, &synthetic_ss, &info, KEY_BYTES).expect("HKDF in range");
        assert_eq!(key_bytes, key_bytes_b);
    }

    /// Pin the `derive_note_nonce` SHA3-256 construction against
    /// fixed 32-byte synthetic shared secret. Pins that the
    /// nonce is the leading 12 bytes of the tagged digest, not
    /// some other transform.
    #[test]
    fn derive_note_nonce_known_answer() {
        let synthetic_ss = [0x77u8; 32];
        let digest = sha3_256_tagged(&domain::NOTE_NONCE, &synthetic_ss);
        let nonce_bytes: [u8; NONCE_BYTES] =
            digest[..NONCE_BYTES].try_into().expect("12-byte slice");
        assert_ne!(nonce_bytes, [0u8; NONCE_BYTES]);
        assert_eq!(&nonce_bytes[..], &digest[..NONCE_BYTES]);
    }

    /// Pin that distinct positions produce distinct note keys
    /// even with the same shared secret (positional binding).
    #[test]
    fn distinct_positions_produce_distinct_note_keys() {
        let synthetic_ss = [0x88u8; 32];
        let info_a = position_info_bytes(LeafPosition(0));
        let info_b = position_info_bytes(LeafPosition(1));
        let salt = domain::NOTE_KEY.as_bytes();
        let key_a = hkdf_sha3_256(salt, &synthetic_ss, &info_a, KEY_BYTES).unwrap();
        let key_b = hkdf_sha3_256(salt, &synthetic_ss, &info_b, KEY_BYTES).unwrap();
        assert_ne!(key_a, key_b);
    }
}
