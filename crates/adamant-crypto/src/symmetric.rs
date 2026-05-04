//! ChaCha20-Poly1305 AEAD wrapper, per whitepaper section 3.5.
//!
//! Implementation library: `chacha20poly1305` (`RustCrypto`). Per
//! whitepaper 3.5, the protocol uses ChaCha20-Poly1305 as defined in
//! RFC 8439, with 256-bit keys, 96-bit nonces, and 128-bit
//! authentication tags. AES-256-GCM is rejected on portable-performance
//! and constant-time grounds (3.5 quote: "constant-time by
//! construction... software-efficient on platforms without AES-NI
//! hardware acceleration").
//!
//! # API shape
//!
//! Three primary types:
//!
//! - [`Key`] — 32-byte symmetric key. Zeroizes on drop.
//! - [`Nonce`] — 12-byte nonce newtype. The wrapper does not generate
//!   or manage nonces; see "Nonce discipline" below.
//! - [`Error`] — opaque error returned from decryption failures.
//!
//! Two operations:
//!
//! - [`Key::encrypt`] — returns ciphertext with authentication tag
//!   appended (`plaintext.len() + 16` bytes).
//! - [`Key::decrypt`] — verifies the appended tag, returns plaintext on
//!   success or [`Error`] on failure (tag mismatch, modified
//!   ciphertext, modified AAD, or wrong key).
//!
//! # Nonce discipline
//!
//! Whitepaper 3.5: "Nonce-uniqueness is enforced by deriving nonces
//! deterministically from a counter that `MUST NOT` be reused with
//! the same key. Implementation details for nonce derivation are
//! specified per-use in subsequent sections."
//!
//! This primitive layer takes the nonce as an explicit parameter and
//! does not derive it. The decision is deliberate:
//!
//! - Nonce uniqueness within a (key, nonce) pair is the entire
//!   security invariant of ChaCha20-Poly1305. Reuse leaks the
//!   keystream and the Poly1305 key, breaking confidentiality and
//!   authentication catastrophically.
//! - Different protocol layers need different nonce-management
//!   strategies. Transport encryption uses an incrementing counter
//!   (one direction per peer pair). Mempool-envelope nonces are
//!   derived deterministically from a per-transaction context per
//!   whitepaper 3.8. Account-encryption nonces are scoped per
//!   record. Baking any single strategy into the primitive layer
//!   would force later layers to fight it.
//! - The IRTF spec (RFC 8439) takes an explicit nonce; this
//!   wrapper matches that interface exactly. Existing AEAD tooling
//!   and audit literature assume this shape.
//!
//! Higher-level modules (`adamant-network`, `adamant-mempool`,
//! `adamant-account`) MUST manage nonce uniqueness; this primitive
//! enforces nothing beyond the type-level distinction between key
//! and nonce.
//!
//! # Constant-time discipline
//!
//! - `ChaCha20` is constant-time by design (no S-box lookups and no
//!   timing-variable branches). The upstream crate preserves this.
//! - `Poly1305` verification is constant-time: tag comparison uses
//!   the upstream crate's constant-time path. Our wrapper does not
//!   touch the comparison.
//! - The `Error` type is opaque ([`Error`] carries no detail).
//!   Distinguishing decryption failure modes (bad tag vs malformed
//!   length vs other) leaks information and is intentionally not
//!   exposed (whitepaper 3.9).
//!
//! # Zeroization discipline
//!
//! - [`Key`] derives [`zeroize::Zeroize`] and
//!   [`zeroize::ZeroizeOnDrop`]. The `[u8; 32]` field zeroizes via
//!   the blanket array impl. Verification chain matches the
//!   established pattern in the signature wrappers (compile-time
//!   trait-bound check + in-place byte-zero check).

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key as BlstKey, Nonce as BlstNonce};
use rand_core::{CryptoRng, RngCore};
use subtle::{Choice, ConstantTimeEq};

/// Symmetric key length in bytes (256-bit), per whitepaper section 3.5.
pub const KEY_BYTES: usize = 32;

/// Nonce length in bytes (96-bit), per whitepaper section 3.5.
pub const NONCE_BYTES: usize = 12;

/// Authentication-tag length in bytes (128-bit), per whitepaper
/// section 3.5. Appended to the end of every ciphertext returned by
/// [`Key::encrypt`].
pub const TAG_BYTES: usize = 16;

/// A ChaCha20-Poly1305 symmetric key. 32 bytes. Zeroizes on drop.
///
/// Does not implement [`PartialEq`]: comparing keys via plain `==` is
/// a footgun even when the underlying byte comparison would be
/// constant-time. Use [`Key::ct_eq`] (from [`ConstantTimeEq`]) when
/// comparison is needed.
#[derive(zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct Key {
    bytes: [u8; KEY_BYTES],
}

/// A 12-byte nonce. Newtype around `[u8; 12]` for type-safety.
///
/// The wrapper does not generate or manage nonces. Per the module
/// documentation, **nonce uniqueness within a (key, nonce) pair is
/// the entire security invariant of ChaCha20-Poly1305 and must be
/// enforced by the caller**. Different protocol layers use different
/// nonce-derivation strategies; see whitepaper sections 3.5, 3.8,
/// and the relevant subsystem documentation.
#[derive(Clone, Copy, Eq, PartialEq, Debug)]
pub struct Nonce(pub [u8; NONCE_BYTES]);

/// Opaque ChaCha20-Poly1305 operation error.
///
/// Returned by decryption failures. Details are intentionally not
/// exposed — distinguishing "bad authentication tag" from other
/// failure modes leaks information that AEAD's authentication
/// guarantee is meant to hide. See whitepaper section 3.9.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct Error;

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ChaCha20-Poly1305 operation failed")
    }
}

impl std::error::Error for Error {}

// ---------- Key ----------

impl Key {
    /// Generate a new symmetric key by drawing 32 cryptographically
    /// random bytes from `rng`.
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let mut bytes = [0u8; KEY_BYTES];
        rng.fill_bytes(&mut bytes);
        Self { bytes }
    }

    /// Construct a key from raw 32-byte material.
    #[must_use]
    pub fn from_bytes(bytes: &[u8; KEY_BYTES]) -> Self {
        Self { bytes: *bytes }
    }

    /// Canonical 32-byte serialised form.
    ///
    /// **Use with care.** The returned array is secret material;
    /// caller is responsible for zeroizing it after use. Prefer
    /// keeping the [`Key`] wrapper itself in the caller's scope and
    /// letting drop handle zeroization.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; KEY_BYTES] {
        self.bytes
    }

    /// Encrypt `plaintext` with this key under `nonce`. Returns the
    /// ciphertext with the 16-byte Poly1305 authentication tag
    /// appended. The output length is `plaintext.len() + 16`.
    ///
    /// `aad` is the associated data — authenticated but not
    /// encrypted. Pass an empty slice if no associated data is
    /// required.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] if the underlying AEAD operation fails. In
    /// practice ChaCha20-Poly1305 encryption fails only when the
    /// allocator cannot grow the output buffer — astronomically rare,
    /// but the API surfaces it as an error rather than panicking.
    pub fn encrypt(&self, nonce: &Nonce, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, Error> {
        let cipher = ChaCha20Poly1305::new(BlstKey::from_slice(&self.bytes));
        let nonce_arr = BlstNonce::from_slice(&nonce.0);
        cipher
            .encrypt(
                nonce_arr,
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_| Error)
    }

    /// Decrypt `ciphertext` (which must include the 16-byte
    /// appended tag) with this key under `nonce`, verifying the tag
    /// against the supplied `aad`. Returns the recovered plaintext on
    /// success.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] if the tag does not authenticate (wrong key,
    /// modified ciphertext, modified AAD, modified nonce, or
    /// truncated input). The error is intentionally opaque — see the
    /// module-level "Constant-time discipline" section.
    pub fn decrypt(&self, nonce: &Nonce, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, Error> {
        let cipher = ChaCha20Poly1305::new(BlstKey::from_slice(&self.bytes));
        let nonce_arr = BlstNonce::from_slice(&nonce.0);
        cipher
            .decrypt(
                nonce_arr,
                Payload {
                    msg: ciphertext,
                    aad,
                },
            )
            .map_err(|_| Error)
    }
}

impl ConstantTimeEq for Key {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.bytes.ct_eq(&other.bytes)
    }
}

impl core::fmt::Debug for Key {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Key(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    /// Helper: a fixed test nonce. Tests must NOT reuse this nonce
    /// across (key, plaintext) pairs in real code; for unit-test
    /// scoping it's fine.
    fn fixed_nonce() -> Nonce {
        Nonce([
            0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
        ])
    }

    fn fixed_key() -> Key {
        let mut bytes = [0u8; KEY_BYTES];
        for (i, b) in bytes.iter_mut().enumerate() {
            // i ∈ 0..32, so the cast is exact.
            #[allow(clippy::cast_possible_truncation)]
            let i_u8 = i as u8;
            *b = 0x80u8 + i_u8;
        }
        Key::from_bytes(&bytes)
    }

    // ---------- declared lengths match the whitepaper ----------

    #[test]
    fn declared_lengths_match_whitepaper() {
        assert_eq!(KEY_BYTES, 32);
        assert_eq!(NONCE_BYTES, 12);
        assert_eq!(TAG_BYTES, 16);
    }

    // ---------- RFC 8439 §A.5 / §2.8.2 known-answer test ----------

    /// RFC 8439 §A.5 (Test vector 1, the IETF reference AEAD example).
    ///
    /// Source: <https://www.rfc-editor.org/rfc/rfc8439#appendix-A.5>
    /// Plaintext: the famous "Ladies and Gentlemen of the class of '99…"
    /// 114-byte message authenticated with 12-byte AAD.
    #[test]
    fn rfc8439_a5_kat() {
        let key: [u8; 32] = [
            0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d,
            0x8e, 0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b,
            0x9c, 0x9d, 0x9e, 0x9f,
        ];
        let nonce_bytes: [u8; 12] = [
            0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
        ];
        let aad: [u8; 12] = [
            0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
        ];
        let plaintext: &[u8] = b"Ladies and Gentlemen of the class of '99: \
                                 If I could offer you only one tip for the future, \
                                 sunscreen would be it.";

        // Expected ciphertext + tag, RFC 8439 §A.5 (lines 21-26 of the table).
        let expected_ciphertext_hex = concat!(
            "d31a8d34648e60db7b86afbc53ef7ec2",
            "a4aded51296e08fea9e2b5a736ee62d6",
            "3dbea45e8ca9671282fafb69da92728b",
            "1a71de0a9e060b2905d6a5b67ecd3b36",
            "92ddbd7f2d778b8c9803aee328091b58",
            "fab324e4fad675945585808b4831d7bc",
            "3ff4def08e4b7a9de576d26586cec64b",
            "6116",
        );
        let expected_tag_hex = "1ae10b594f09e26a7e902ecbd0600691";
        let expected_combined = format!("{expected_ciphertext_hex}{expected_tag_hex}");

        let key_obj = Key::from_bytes(&key);
        let nonce = Nonce(nonce_bytes);
        let actual = key_obj.encrypt(&nonce, plaintext, &aad).expect("encrypt");

        assert_eq!(hex_encode(&actual), expected_combined);

        // Round-trip decrypt.
        let recovered = key_obj.decrypt(&nonce, &actual, &aad).expect("decrypt");
        assert_eq!(recovered, plaintext);
    }

    // ---------- encrypt/decrypt roundtrip ----------

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let key = Key::generate(&mut OsRng);
        let nonce = fixed_nonce();
        let plaintext = b"the quick brown fox jumps over the lazy dog";
        let aad = b"associated data goes here";

        let ciphertext = key.encrypt(&nonce, plaintext, aad).expect("encrypt");
        assert_eq!(ciphertext.len(), plaintext.len() + TAG_BYTES);

        let recovered = key.decrypt(&nonce, &ciphertext, aad).expect("decrypt");
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn empty_plaintext_roundtrip() {
        let key = fixed_key();
        let nonce = fixed_nonce();
        let plaintext: &[u8] = b"";
        let aad: &[u8] = b"";

        let ciphertext = key.encrypt(&nonce, plaintext, aad).expect("encrypt");
        assert_eq!(ciphertext.len(), TAG_BYTES); // just the tag
        let recovered = key.decrypt(&nonce, &ciphertext, aad).expect("decrypt");
        assert_eq!(recovered, plaintext);
    }

    // ---------- tampering rejection ----------

    #[test]
    fn tampered_ciphertext_rejected() {
        let key = fixed_key();
        let nonce = fixed_nonce();
        let mut ciphertext = key.encrypt(&nonce, b"original", b"").expect("encrypt");
        ciphertext[0] ^= 0x01;
        assert!(key.decrypt(&nonce, &ciphertext, b"").is_err());
    }

    #[test]
    fn tampered_tag_rejected() {
        let key = fixed_key();
        let nonce = fixed_nonce();
        let mut ciphertext = key.encrypt(&nonce, b"original", b"").expect("encrypt");
        let last = ciphertext.len() - 1;
        ciphertext[last] ^= 0x01;
        assert!(key.decrypt(&nonce, &ciphertext, b"").is_err());
    }

    #[test]
    fn tampered_aad_rejected() {
        let key = fixed_key();
        let nonce = fixed_nonce();
        let ciphertext = key
            .encrypt(&nonce, b"plaintext", b"original aad")
            .expect("encrypt");
        assert!(key.decrypt(&nonce, &ciphertext, b"different aad").is_err());
    }

    #[test]
    fn wrong_nonce_rejected() {
        let key = fixed_key();
        let ciphertext = key
            .encrypt(&fixed_nonce(), b"plaintext", b"")
            .expect("encrypt");
        let other_nonce = Nonce([0u8; NONCE_BYTES]);
        assert!(key.decrypt(&other_nonce, &ciphertext, b"").is_err());
    }

    #[test]
    fn wrong_key_rejected() {
        let key_a = Key::from_bytes(&[1u8; KEY_BYTES]);
        let key_b = Key::from_bytes(&[2u8; KEY_BYTES]);
        let nonce = fixed_nonce();
        let ciphertext = key_a.encrypt(&nonce, b"plaintext", b"").expect("encrypt");
        assert!(key_b.decrypt(&nonce, &ciphertext, b"").is_err());
    }

    // ---------- determinism (same key + nonce + pt → same ct) ----------

    /// ChaCha20-Poly1305 is a counter-mode stream cipher with a
    /// deterministic Poly1305 tag derived from the same key/nonce
    /// stream — encrypting the same `(key, nonce, plaintext, aad)`
    /// twice must produce byte-identical ciphertext. This is also
    /// the property that makes nonce reuse catastrophic.
    #[test]
    fn encrypt_is_deterministic_for_fixed_inputs() {
        let key = fixed_key();
        let nonce = fixed_nonce();
        let pt = b"deterministic check";
        let aad = b"context";
        let ct_1 = key.encrypt(&nonce, pt, aad).expect("encrypt");
        let ct_2 = key.encrypt(&nonce, pt, aad).expect("encrypt");
        assert_eq!(ct_1, ct_2);
    }

    // ---------- AAD distinguishes ciphertexts ----------

    #[test]
    fn different_aad_produces_different_ciphertext_tag() {
        let key = fixed_key();
        let nonce = fixed_nonce();
        let pt = b"plaintext";
        let ct_1 = key.encrypt(&nonce, pt, b"aad-1").expect("encrypt");
        let ct_2 = key.encrypt(&nonce, pt, b"aad-2").expect("encrypt");
        // Same plaintext + same nonce + same key → ciphertext bytes
        // are equal up to the tag, but the tag differs because AAD is
        // mixed in.
        assert_eq!(
            &ct_1[..ct_1.len() - TAG_BYTES],
            &ct_2[..ct_2.len() - TAG_BYTES]
        );
        assert_ne!(
            &ct_1[ct_1.len() - TAG_BYTES..],
            &ct_2[ct_2.len() - TAG_BYTES..]
        );
    }

    // ---------- generation produces distinct keys ----------

    #[test]
    fn generate_produces_distinct_keys() {
        let a = Key::generate(&mut OsRng);
        let b = Key::generate(&mut OsRng);
        assert!(!bool::from(a.ct_eq(&b)));
    }

    // ---------- constant-time equality ----------

    #[test]
    fn constant_time_eq_matches_byte_equality() {
        let k1 = Key::from_bytes(&[3u8; KEY_BYTES]);
        let k2 = Key::from_bytes(&[3u8; KEY_BYTES]);
        let k3 = Key::from_bytes(&[4u8; KEY_BYTES]);
        assert!(bool::from(k1.ct_eq(&k2)));
        assert!(!bool::from(k1.ct_eq(&k3)));
    }

    // ---------- byte round-trip ----------

    #[test]
    fn key_bytes_round_trip() {
        let bytes = [9u8; KEY_BYTES];
        let key = Key::from_bytes(&bytes);
        assert_eq!(key.to_bytes(), bytes);
    }

    // ---------- zeroize ----------

    #[test]
    fn key_impls_zeroize_on_drop() {
        fn assert_impls<T: zeroize::ZeroizeOnDrop>() {}
        assert_impls::<Key>();
    }

    #[test]
    fn key_zeroize_zeros_bytes() {
        use zeroize::Zeroize;
        let mut key = Key::from_bytes(&[1u8; KEY_BYTES]);
        let before = key.to_bytes();
        assert_ne!(before, [0u8; KEY_BYTES]);
        key.zeroize();
        let after = key.to_bytes();
        assert_eq!(after, [0u8; KEY_BYTES]);
    }

    /// Lower-case hex encoding helper for the RFC 8439 KAT comparison.
    fn hex_encode(bytes: &[u8]) -> String {
        let mut out = String::with_capacity(bytes.len() * 2);
        for &b in bytes {
            out.push(char::from_digit(u32::from(b >> 4), 16).unwrap_or('?'));
            out.push(char::from_digit(u32::from(b & 0x0f), 16).unwrap_or('?'));
        }
        out
    }
}
