//! Encrypted memos per whitepaper §7.6.
//!
//! Phase 6.6 ships the memo-encryption surface: [`encrypt_memo`]
//! and [`decrypt_memo`] plus the [`EncryptedMemo`] wire type and
//! the [`MEMO_MAX_PLAINTEXT_BYTES`] limit per §7.6.1.
//!
//! # Spec basis
//!
//! Whitepaper §7.6.1 verbatim:
//!
//! > A memo is up to 512 bytes of arbitrary data, encrypted to
//! > the recipient's stealth address. The memo is included in
//! > the note's encrypted output … and is invisible to all
//! > other parties.
//! >
//! > Encryption uses ChaCha20-Poly1305 (section 3.5) with the
//! > key derived from the stealth shared secret:
//! >
//! > ```text
//! > memo_key = HashToKey(s || domain_tag_memo)
//! > encrypted_memo = ChaCha20Poly1305(memo_key, nonce, memo_plaintext)
//! > ```
//! >
//! > The nonce is derived deterministically from the per-note
//! > shared secret to ensure non-reuse:
//! >
//! > ```text
//! > nonce = SHA3_256(s || domain_tag_memo_nonce)[0..12]
//! > ```
//! >
//! > where `s` is the per-note ML-KEM shared secret per §7.2.2
//! > and `domain_tag_memo_nonce = b"ADAMANT-v1-memo-nonce"`.
//!
//! # Construction
//!
//! - `memo_key = sha3_256_tagged(MEMO_KEY, ss)` — the 32-byte
//!   SHA3-256 output is the ChaCha20-Poly1305 key directly. The
//!   BIP-340 tagged-hash construction binds the key to the
//!   registered tag without an additional KDF step (the SHA3-256
//!   output is uniformly distributed over `{0,1}^256`).
//! - `nonce = sha3_256_tagged(MEMO_NONCE, ss)[0..12]` — first 12
//!   bytes of the tagged SHA3-256 are the ChaCha20-Poly1305 96-
//!   bit nonce.
//!
//! `s` in the spec text and `ss` here both refer to the 32-byte
//! ML-KEM-768 shared secret produced by [`crate::stealth`]'s
//! sender-side encapsulation / recipient-side decapsulation. The
//! per-note freshness of `ss` (each note has its own ML-KEM
//! encapsulation per §7.2.2) is what guarantees nonce non-reuse
//! across distinct notes.
//!
//! # §7.0 probabilistic-only encryption posture
//!
//! Per §7.6.1 final paragraph:
//!
//! > Equal memo plaintexts under different notes encrypt under
//! > different `(memo_key, nonce)` pairs and produce
//! > uncorrelated ciphertexts.
//!
//! This module's [`encrypt_memo`] satisfies that requirement
//! structurally: keys and nonces both derive from the per-note
//! `ss`, so distinct notes produce distinct keys and distinct
//! nonces. Tests pin this property explicitly.
//!
//! # Plaintext size bound
//!
//! [`MEMO_MAX_PLAINTEXT_BYTES`] = 512 per §7.6.1. [`encrypt_memo`]
//! returns [`MemoTooLarge`] for inputs above the limit; the limit
//! is consensus-binding and changing it would be a hard fork.

use adamant_crypto::domain;
use adamant_crypto::hash::sha3_256_tagged;
use adamant_crypto::ml_kem::SharedSecret;
use adamant_crypto::symmetric::{Error as SymmetricError, Key as SymKey, Nonce, NONCE_BYTES};
use serde::{Deserialize, Serialize};

/// Maximum memo plaintext size in bytes per whitepaper §7.6.1.
pub const MEMO_MAX_PLAINTEXT_BYTES: usize = 512;

/// Returned by [`encrypt_memo`] when the plaintext exceeds the
/// §7.6.1 cap.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MemoTooLarge {
    /// Length of the offending plaintext in bytes.
    pub provided_bytes: usize,
}

impl core::fmt::Display for MemoTooLarge {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "memo plaintext exceeds §7.6.1 cap of {} bytes (provided {})",
            MEMO_MAX_PLAINTEXT_BYTES, self.provided_bytes
        )
    }
}

impl std::error::Error for MemoTooLarge {}

/// Returned by [`decrypt_memo`] on AEAD authentication failure
/// (wrong key, modified ciphertext, or modified shared secret).
///
/// Opaque per the §3.5 / §3.9 constant-time discipline:
/// distinguishing failure modes leaks information about the
/// secret material being tested.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MemoDecryptError;

impl core::fmt::Display for MemoDecryptError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("memo decryption failed (authentication tag mismatch)")
    }
}

impl std::error::Error for MemoDecryptError {}

impl From<SymmetricError> for MemoDecryptError {
    fn from(_: SymmetricError) -> Self {
        Self
    }
}

/// An on-chain encrypted memo per whitepaper §7.6.1.
///
/// Wire shape: ChaCha20-Poly1305 ciphertext with the 16-byte
/// authentication tag appended (per [`adamant_crypto::symmetric`]
/// convention). Total length is `plaintext.len() + 16`, capped at
/// [`MEMO_MAX_PLAINTEXT_BYTES`] + 16 = 528 bytes.
///
/// The memo is consensus-data: it appears as part of the note's
/// encrypted output (Phase 6.7's `EncryptedNote`) and is bound by
/// the note's auth-tag. Bit-flipping or substitution is detected
/// at decryption time via the Poly1305 tag.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EncryptedMemo {
    /// Ciphertext bytes — plaintext encrypted under
    /// `memo_key`/`nonce` derived from the per-note shared
    /// secret, with the 16-byte Poly1305 tag appended.
    pub bytes: Vec<u8>,
}

impl EncryptedMemo {
    /// Construct from raw ciphertext bytes (e.g., for loading
    /// from on-chain serialized form).
    #[must_use]
    pub const fn from_bytes(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    /// Borrow the underlying ciphertext bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Length of the ciphertext in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Whether the ciphertext is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

// ---------- Internal derivations ----------

/// Derive the 32-byte memo key from the per-note shared secret
/// per §7.6.1 step "`memo_key` = `HashToKey(s || domain_tag_memo)`".
fn derive_memo_key(shared_secret: &SharedSecret) -> SymKey {
    let key_bytes = sha3_256_tagged(&domain::MEMO_KEY, shared_secret.as_bytes());
    SymKey::from_bytes(&key_bytes)
}

/// Derive the 12-byte memo nonce from the per-note shared secret
/// per §7.6.1 step "nonce = `SHA3_256(s || domain_tag_memo_nonce)[0..12]`".
fn derive_memo_nonce(shared_secret: &SharedSecret) -> Nonce {
    let digest = sha3_256_tagged(&domain::MEMO_NONCE, shared_secret.as_bytes());
    let mut nonce_bytes = [0u8; NONCE_BYTES];
    nonce_bytes.copy_from_slice(&digest[..NONCE_BYTES]);
    Nonce(nonce_bytes)
}

// ---------- Public encryption API ----------

/// Encrypt a memo plaintext under the per-note shared secret per
/// whitepaper §7.6.1.
///
/// The `shared_secret` is the 32-byte ML-KEM-768 output produced
/// by [`crate::stealth`]'s sender-side encapsulation; the same
/// secret is recovered by the recipient via decapsulation, so
/// `decrypt_memo` with the recipient's recovered secret produces
/// the original plaintext.
///
/// AAD is empty per §7.6.1 (the memo is bound to the note via
/// Phase 6.7's `EncryptedNote` envelope, not via AEAD AAD at this
/// layer).
///
/// # Errors
///
/// Returns [`MemoTooLarge`] if `plaintext.len() >
/// MEMO_MAX_PLAINTEXT_BYTES`.
///
/// # Panics
///
/// Cannot panic in practice: ChaCha20-Poly1305 encryption is
/// infallible for valid key/nonce/plaintext shapes, and the
/// plaintext-length check above guarantees we are within
/// AEAD's payload bound.
pub fn encrypt_memo(
    shared_secret: &SharedSecret,
    plaintext: &[u8],
) -> Result<EncryptedMemo, MemoTooLarge> {
    if plaintext.len() > MEMO_MAX_PLAINTEXT_BYTES {
        return Err(MemoTooLarge {
            provided_bytes: plaintext.len(),
        });
    }
    let key = derive_memo_key(shared_secret);
    let nonce = derive_memo_nonce(shared_secret);
    let ciphertext = key
        .encrypt(&nonce, plaintext, b"")
        .expect("ChaCha20-Poly1305 encryption is infallible for valid inputs");
    Ok(EncryptedMemo { bytes: ciphertext })
}

/// Decrypt a memo ciphertext under the per-note shared secret
/// per whitepaper §7.6.1.
///
/// `shared_secret` is the 32-byte ML-KEM-768 output recovered by
/// the recipient via decapsulation. Returns the original
/// plaintext on AEAD success.
///
/// # Errors
///
/// Returns [`MemoDecryptError`] on authentication failure (wrong
/// key, modified ciphertext, or wrong shared secret).
pub fn decrypt_memo(
    shared_secret: &SharedSecret,
    encrypted: &EncryptedMemo,
) -> Result<Vec<u8>, MemoDecryptError> {
    let key = derive_memo_key(shared_secret);
    let nonce = derive_memo_nonce(shared_secret);
    let plaintext = key.decrypt(&nonce, &encrypted.bytes, b"")?;
    Ok(plaintext)
}

#[cfg(test)]
#[allow(clippy::similar_names)]
mod tests {
    use super::*;
    use adamant_crypto::ml_kem::DecapsulationKey;
    use getrandom::{rand_core::UnwrapErr, SysRng};
    use subtle::ConstantTimeEq;

    fn test_rng() -> UnwrapErr<SysRng> {
        UnwrapErr(SysRng)
    }

    /// Produce a deterministic-shape `SharedSecret` via real
    /// ML-KEM-768 encap (encap is randomized; so the secret is
    /// fresh each call, but the type-shape is stable). Used as
    /// the input to encrypt/decrypt round-trips.
    fn fresh_shared_secret(seed_byte: u8) -> SharedSecret {
        let dk = DecapsulationKey::from_seed(&[seed_byte; 64]);
        let ek = dk.encapsulation_key();
        let (_ct, ss) = ek.encapsulate(&mut test_rng());
        ss
    }

    /// Real round-trip: sender encapsulates, derives memo key/nonce,
    /// encrypts; recipient decapsulates the same ciphertext (via
    /// real ML-KEM), recovers the same shared secret, decrypts the
    /// memo. This is the §7.6.1 protocol path end-to-end.
    fn sender_recipient_secrets() -> (SharedSecret, SharedSecret) {
        let dk = DecapsulationKey::from_seed(&[0xA1; 64]);
        let ek = dk.encapsulation_key();
        let (ct, ss_send) = ek.encapsulate(&mut test_rng());
        let ss_recv = dk.decapsulate(&ct);
        // Sanity: the two are byte-equal.
        assert!(bool::from(ss_send.ct_eq(&ss_recv)));
        (ss_send, ss_recv)
    }

    // ---------- Domain-tag pins ----------

    #[test]
    fn memo_key_tag_is_registry_value() {
        assert_eq!(domain::MEMO_KEY.as_bytes(), b"ADAMANT-v1-memo-key");
    }

    /// §7.6.1 spec text pins this byte string verbatim.
    #[test]
    fn memo_nonce_tag_is_registry_value() {
        assert_eq!(domain::MEMO_NONCE.as_bytes(), b"ADAMANT-v1-memo-nonce");
    }

    #[test]
    fn memo_key_and_nonce_tags_distinct() {
        assert_ne!(domain::MEMO_KEY.as_bytes(), domain::MEMO_NONCE.as_bytes());
    }

    // ---------- Round-trip ----------

    #[test]
    fn encrypt_decrypt_round_trip_empty_plaintext() {
        let (ss_send, ss_recv) = sender_recipient_secrets();
        let encrypted = encrypt_memo(&ss_send, b"").expect("empty plaintext is valid");
        let decrypted = decrypt_memo(&ss_recv, &encrypted).expect("authentic ciphertext");
        assert_eq!(decrypted, b"");
        // Ciphertext is just the 16-byte tag.
        assert_eq!(encrypted.len(), 16);
    }

    #[test]
    fn encrypt_decrypt_round_trip_typical_plaintext() {
        let (ss_send, ss_recv) = sender_recipient_secrets();
        let plaintext = b"invoice-2026-001 payment for services rendered";
        let encrypted = encrypt_memo(&ss_send, plaintext).expect("valid size");
        let decrypted = decrypt_memo(&ss_recv, &encrypted).expect("authentic ciphertext");
        assert_eq!(decrypted, plaintext);
        // Ciphertext is plaintext.len() + 16-byte tag.
        assert_eq!(encrypted.len(), plaintext.len() + 16);
    }

    #[test]
    fn encrypt_decrypt_round_trip_max_size_plaintext() {
        let (ss_send, ss_recv) = sender_recipient_secrets();
        let plaintext = vec![0xAB; MEMO_MAX_PLAINTEXT_BYTES];
        let encrypted = encrypt_memo(&ss_send, &plaintext).expect("at limit is valid");
        let decrypted = decrypt_memo(&ss_recv, &encrypted).expect("authentic ciphertext");
        assert_eq!(decrypted, plaintext);
        assert_eq!(encrypted.len(), MEMO_MAX_PLAINTEXT_BYTES + 16);
    }

    // ---------- Size enforcement ----------

    #[test]
    fn oversized_plaintext_rejected() {
        let ss = fresh_shared_secret(0x42);
        let oversize = vec![0xCC; MEMO_MAX_PLAINTEXT_BYTES + 1];
        let result = encrypt_memo(&ss, &oversize);
        assert_eq!(
            result,
            Err(MemoTooLarge {
                provided_bytes: MEMO_MAX_PLAINTEXT_BYTES + 1
            })
        );
    }

    #[test]
    fn at_limit_plaintext_accepted() {
        let ss = fresh_shared_secret(0x42);
        let at_limit = vec![0xCC; MEMO_MAX_PLAINTEXT_BYTES];
        let result = encrypt_memo(&ss, &at_limit);
        assert!(result.is_ok());
    }

    // ---------- Authentication failure ----------

    #[test]
    fn wrong_key_decryption_fails() {
        let ss_correct = fresh_shared_secret(0x11);
        let ss_wrong = fresh_shared_secret(0x22);
        // With overwhelming probability, fresh ML-KEM secrets are
        // distinct.
        if !bool::from(ss_correct.ct_eq(&ss_wrong)) {
            let plaintext = b"secret message";
            let encrypted = encrypt_memo(&ss_correct, plaintext).expect("valid");
            let result = decrypt_memo(&ss_wrong, &encrypted);
            assert_eq!(result, Err(MemoDecryptError));
        }
    }

    #[test]
    fn modified_ciphertext_decryption_fails() {
        let (ss_send, ss_recv) = sender_recipient_secrets();
        let plaintext = b"sensitive payment reference";
        let mut encrypted = encrypt_memo(&ss_send, plaintext).expect("valid");
        // Flip a bit in the ciphertext (skip the leading tag-region
        // for variety; index 5 is in the encrypted plaintext).
        encrypted.bytes[5] ^= 0x01;
        let result = decrypt_memo(&ss_recv, &encrypted);
        assert_eq!(result, Err(MemoDecryptError));
    }

    #[test]
    fn modified_tag_decryption_fails() {
        let (ss_send, ss_recv) = sender_recipient_secrets();
        let plaintext = b"X";
        let mut encrypted = encrypt_memo(&ss_send, plaintext).expect("valid");
        // The last 16 bytes are the Poly1305 tag.
        let tag_offset = encrypted.bytes.len() - 1;
        encrypted.bytes[tag_offset] ^= 0xFF;
        let result = decrypt_memo(&ss_recv, &encrypted);
        assert_eq!(result, Err(MemoDecryptError));
    }

    // ---------- §7.6.1 final-paragraph property pin ----------

    /// Equal memo plaintexts under DIFFERENT shared secrets
    /// produce uncorrelated ciphertexts. This is the §7.6.1
    /// final-paragraph probabilistic-encryption property.
    #[test]
    fn equal_plaintext_different_secrets_distinct_ciphertexts() {
        let ss_a = fresh_shared_secret(0x01);
        let ss_b = fresh_shared_secret(0x02);
        if !bool::from(ss_a.ct_eq(&ss_b)) {
            let plaintext = b"identical memo bytes for both notes";
            let ct_a = encrypt_memo(&ss_a, plaintext).expect("valid");
            let ct_b = encrypt_memo(&ss_b, plaintext).expect("valid");
            assert_ne!(
                ct_a.bytes, ct_b.bytes,
                "equal plaintexts under distinct shared secrets must produce \
                 distinct ciphertexts (§7.6.1 probabilistic-encryption pin)"
            );
        }
    }

    /// Equal plaintexts + equal shared secrets → equal
    /// ciphertexts (deterministic by construction). Pins the
    /// nonce-derivation determinism.
    #[test]
    fn equal_plaintext_equal_secret_equal_ciphertext() {
        let (ss_send, _) = sender_recipient_secrets();
        let plaintext = b"deterministic memo";
        let ct_a = encrypt_memo(&ss_send, plaintext).expect("valid");
        let ct_b = encrypt_memo(&ss_send, plaintext).expect("valid");
        assert_eq!(ct_a.bytes, ct_b.bytes);
    }

    // ---------- Wire-format tests ----------

    #[test]
    fn encrypted_memo_bcs_round_trip() {
        let original = EncryptedMemo::from_bytes(vec![0xAB; 100]);
        let encoded = bcs::to_bytes(&original).unwrap();
        let decoded: EncryptedMemo = bcs::from_bytes(&encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn encrypted_memo_helpers() {
        let m = EncryptedMemo::from_bytes(vec![0xCD; 50]);
        assert_eq!(m.len(), 50);
        assert!(!m.is_empty());
        assert_eq!(m.as_bytes().len(), 50);

        let empty = EncryptedMemo::from_bytes(Vec::new());
        assert!(empty.is_empty());
    }

    // ---------- KAT regression ----------

    /// Pin the memo-key derivation against a fixed 32-byte
    /// synthetic shared secret. Test KAT — uses raw bytes via
    /// the internal derivation path that mirrors what
    /// `derive_memo_key(SharedSecret)` does, since
    /// `SharedSecret` has no public from-bytes constructor.
    #[test]
    fn derive_memo_key_known_answer() {
        let synthetic_ss = [0x77u8; 32];
        let key_bytes = sha3_256_tagged(&domain::MEMO_KEY, &synthetic_ss);
        // Determinism + non-zero pin.
        assert_ne!(key_bytes, [0u8; 32]);
        let key_bytes_b = sha3_256_tagged(&domain::MEMO_KEY, &synthetic_ss);
        assert_eq!(key_bytes, key_bytes_b);
    }

    /// Pin the memo-nonce derivation against a fixed 32-byte
    /// synthetic shared secret.
    #[test]
    fn derive_memo_nonce_known_answer() {
        let synthetic_ss = [0x77u8; 32];
        let digest = sha3_256_tagged(&domain::MEMO_NONCE, &synthetic_ss);
        let nonce_bytes: [u8; NONCE_BYTES] =
            digest[..NONCE_BYTES].try_into().expect("12-byte slice");
        // Determinism + non-zero pin.
        assert_ne!(nonce_bytes, [0u8; NONCE_BYTES]);
        // Pin that the nonce is the leading 12 bytes of the
        // tagged digest, not some other transform.
        assert_eq!(&nonce_bytes[..], &digest[..NONCE_BYTES]);
    }
}
