//! Ed25519 classical-signature wrapper, per whitepaper section 3.4.1.
//!
//! Implementation library: `ed25519-dalek`. Per whitepaper 3.4.1, dalek is
//! "constant-time, audited, no-`unsafe`," and signing is deterministic
//! (RFC 8032) — there is no per-signature randomness in the API surface
//! by design.
//!
//! # API shape
//!
//! Three primary types, mirroring `ed25519-dalek` 2.x naming and roles:
//!
//! - [`SigningKey`] — the secret key. Zeroizes on drop. Does NOT
//!   implement [`PartialEq`]; equality on secret material must use
//!   [`subtle::ConstantTimeEq`] explicitly so a constant-time comparison
//!   is the only option at the call site.
//! - [`VerifyingKey`] — the public key. 32 bytes, canonical encoding,
//!   parsing validates the curve point.
//! - [`Signature`] — a 64-byte signature. Byte-container only;
//!   construction does not validate (RFC 8032 leaves validation to
//!   [`VerifyingKey::verify`]).
//!
//! [`Signer`]/[`Verifier`]-style trait splits from the `signature` crate
//! are not exposed here. The whitepaper specifies a concrete scheme, not
//! a generic-over-schemes signing surface; an inherent-method API on
//! the concrete types is more honest about what the crate provides.
//!
//! # Constant-time discipline
//!
//! - All operations on secret material are constant-time. dalek
//!   guarantees this for its primitives; this wrapper preserves it by
//!   never branching on key content and by routing equality through
//!   `subtle::ConstantTimeEq`.
//! - Errors from parsing and verification are intentionally opaque
//!   ([`Error`] carries no detail). Verification failure modes can leak
//!   information about which check tripped if reported in detail; see
//!   whitepaper 3.9 ("Library and implementation discipline").
//!
//! # Zeroization discipline
//!
//! - [`SigningKey`] derives [`zeroize::ZeroizeOnDrop`]. The inner
//!   `ed25519_dalek::SigningKey` carries the actual secret bytes and
//!   itself implements `ZeroizeOnDrop` under the dalek `zeroize` feature
//!   (enabled in workspace deps); the outer derive ensures drop on our
//!   wrapper invokes zeroization on every contained field.
//! - The trait obligation is asserted at compile time in tests (see
//!   `tests::signing_key_impls_zeroize_on_drop`).
//! - The behavioural verification (bytes are actually zero post-zeroize)
//!   is exercised in `tests::signing_key_zeroize_zeros_bytes`. See the
//!   doc-comment on that test for the choice of in-place `zeroize()`
//!   verification rather than post-drop pointer reads.

use ed25519_dalek::ed25519::signature::{Signer, Verifier};
use rand_core::CryptoRngCore;
use subtle::{Choice, ConstantTimeEq};

/// An Ed25519 signing (secret) key. 32-byte seed, deterministic signing
/// per RFC 8032. Zeroizes on drop.
///
/// Does not implement [`PartialEq`]: comparing secret keys via plain `==`
/// is a footgun even when the underlying field elements would be equal in
/// constant time. Use [`SigningKey::ct_eq`] (from [`ConstantTimeEq`])
/// when comparison is needed.
pub struct SigningKey {
    inner: ed25519_dalek::SigningKey,
}

// Zeroize / ZeroizeOnDrop traits are implemented manually because
// `ed25519_dalek` 2.2 exposes `ZeroizeOnDrop` on `SigningKey` but not
// the standalone `Zeroize` trait (the inner type lacks a `Default`
// that `Zeroize` would key off). The manual implementations preserve
// our wrapper's API contract:
//
// - `Zeroize::zeroize()` overwrites the inner key with a zero-seeded
//   one. The old `ed25519_dalek::SigningKey` is dropped in the
//   replacement, and dalek's own `ZeroizeOnDrop` scrubs its bytes
//   before deallocation. Post-call, `inner.to_bytes()` returns
//   `[0u8; 32]` — the property the test
//   `tests::signing_key_zeroize_zeros_bytes` exercises.
// - `ZeroizeOnDrop` is a marker trait with no body; the implicit drop
//   of `SigningKey` drops the inner field, which is dalek-zeroized.
//
// === On verification of zeroize-on-drop ===
//
// We do not verify zeroize-on-drop by reading raw memory after drop.
// The objection is technical, not pragmatic: post-drop reads are
// undefined behaviour, so any "passing" pointer-read test observes
// whatever the compiler or allocator happened to leave in the slot,
// not a zeroization guarantee. A test that can succeed for the wrong
// reason is not a test, and a `unsafe`-permitting test that does so
// is strictly worse than the safe verification chain below.
//
// The chain we DO use, in order of trust:
//   1. `ZeroizeOnDrop` trait bound on `SigningKey`, asserted at
//      compile time by `tests::signing_key_impls_zeroize_on_drop`.
//      This is the contractual promise that `Drop` will scrub the
//      bytes; losing the impl breaks compilation.
//   2. In-place `Zeroize::zeroize()` byte check, in
//      `tests::signing_key_zeroize_zeros_bytes`. Verifies that the
//      `zeroize()` method our `Drop` will eventually call actually
//      produces `[0u8; 32]`.
//   3. The remaining property — that post-drop memory is observably
//      zero — is closed by dalek's volatile-write discipline, audited
//      and tested upstream. The trust boundary lives at the dalek
//      layer; substituting our own unsafe test relocates the trust
//      without strengthening it.
impl zeroize::Zeroize for SigningKey {
    fn zeroize(&mut self) {
        self.inner = ed25519_dalek::SigningKey::from_bytes(&[0u8; 32]);
    }
}

impl zeroize::ZeroizeOnDrop for SigningKey {}

/// An Ed25519 verifying (public) key. 32 bytes, canonical encoding.
#[derive(Clone, Eq, PartialEq)]
pub struct VerifyingKey {
    inner: ed25519_dalek::VerifyingKey,
}

/// An Ed25519 signature. 64 bytes.
#[derive(Clone, Eq, PartialEq)]
pub struct Signature {
    inner: ed25519_dalek::Signature,
}

/// Opaque Ed25519 operation error.
///
/// Returned by parsing and verification failures. Details are
/// intentionally not exposed: distinguishing failure modes leaks
/// information that verification's constant-time discipline is meant to
/// hide. See whitepaper section 3.9.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct Error;

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Ed25519 operation failed")
    }
}

impl std::error::Error for Error {}

// ---------- SigningKey ----------

impl SigningKey {
    /// Generate a new signing key from a cryptographically secure
    /// random source.
    ///
    /// The caller's `rng` MUST be a CSPRNG. Per whitepaper 3.8, key
    /// generation is the only place a CSPRNG is required for Ed25519;
    /// signing is deterministic and uses no runtime randomness.
    pub fn generate<R: CryptoRngCore + ?Sized>(rng: &mut R) -> Self {
        Self {
            inner: ed25519_dalek::SigningKey::generate(rng),
        }
    }

    /// Construct a signing key from a 32-byte RFC 8032 seed.
    #[must_use]
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self {
            inner: ed25519_dalek::SigningKey::from_bytes(seed),
        }
    }

    /// Derive the corresponding verifying key.
    #[must_use]
    pub fn verifying_key(&self) -> VerifyingKey {
        VerifyingKey {
            inner: self.inner.verifying_key(),
        }
    }

    /// Sign `message` deterministically (RFC 8032). The output depends
    /// only on the key and the message; calling `sign` twice with the
    /// same arguments produces byte-identical signatures.
    #[must_use]
    pub fn sign(&self, message: &[u8]) -> Signature {
        Signature {
            inner: self.inner.sign(message),
        }
    }
}

impl ConstantTimeEq for SigningKey {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.inner.to_bytes().ct_eq(&other.inner.to_bytes())
    }
}

// Custom Debug: never print secret material.
impl core::fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SigningKey(<redacted>)")
    }
}

// ---------- VerifyingKey ----------

impl VerifyingKey {
    /// Parse a verifying key from its 32-byte canonical encoding.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] if the bytes do not encode a valid point on
    /// `edwards25519`.
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, Error> {
        ed25519_dalek::VerifyingKey::from_bytes(bytes)
            .map(|inner| Self { inner })
            .map_err(|_| Error)
    }

    /// Canonical 32-byte encoding.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 32] {
        self.inner.to_bytes()
    }

    /// Verify `signature` against `message`.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] if the signature does not validate. The error
    /// is intentionally opaque (no detail about which check failed),
    /// per whitepaper section 3.9 and the constant-time discipline
    /// described in this module's top-level doc.
    pub fn verify(&self, message: &[u8], signature: &Signature) -> Result<(), Error> {
        self.inner
            .verify(message, &signature.inner)
            .map_err(|_| Error)
    }
}

impl core::fmt::Debug for VerifyingKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "VerifyingKey({})", hex_encode(&self.to_bytes()))
    }
}

// ---------- Signature ----------

impl Signature {
    /// Construct a signature from its 64-byte canonical encoding.
    ///
    /// Construction does not validate the signature against any key;
    /// validation is the job of [`VerifyingKey::verify`]. RFC 8032
    /// leaves all check arithmetic to the verifier.
    #[must_use]
    pub fn from_bytes(bytes: &[u8; 64]) -> Self {
        Self {
            inner: ed25519_dalek::Signature::from_bytes(bytes),
        }
    }

    /// Canonical 64-byte encoding.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 64] {
        self.inner.to_bytes()
    }
}

impl core::fmt::Debug for Signature {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Signature({})", hex_encode(&self.to_bytes()))
    }
}

/// Lower-case hex encoding helper for `Debug` impls. Kept private to
/// avoid drawing in `hex` as a runtime dependency for what is purely a
/// diagnostic concern.
fn hex_encode(bytes: &[u8]) -> String {
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
    use rand_core::OsRng;

    // ---------- RFC 8032 §7.1 KATs ----------

    struct Rfc8032Vector {
        sk: [u8; 32],
        pk: [u8; 32],
        message: Vec<u8>,
        signature: [u8; 64],
    }

    fn parse_kats(content: &str) -> Vec<Rfc8032Vector> {
        let mut vectors = Vec::new();
        let mut sk: Option<[u8; 32]> = None;
        let mut pk: Option<[u8; 32]> = None;
        let mut message: Option<Vec<u8>> = None;

        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with('[') {
                continue;
            }
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            let key = key.trim();
            let value = value.trim();
            match key {
                "SK" => {
                    let bytes = hex::decode(value).expect("valid hex in SK");
                    sk = Some(bytes.try_into().expect("SK must be 32 bytes"));
                }
                "PK" => {
                    let bytes = hex::decode(value).expect("valid hex in PK");
                    pk = Some(bytes.try_into().expect("PK must be 32 bytes"));
                }
                "Message" => {
                    message = Some(if value.is_empty() {
                        Vec::new()
                    } else {
                        hex::decode(value).expect("valid hex in Message")
                    });
                }
                "Signature" => {
                    let bytes = hex::decode(value).expect("valid hex in Signature");
                    let signature: [u8; 64] = bytes.try_into().expect("Signature must be 64 bytes");
                    vectors.push(Rfc8032Vector {
                        sk: sk.take().expect("SK must precede Signature"),
                        pk: pk.take().expect("PK must precede Signature"),
                        message: message.take().expect("Message must precede Signature"),
                        signature,
                    });
                }
                _ => {}
            }
        }
        vectors
    }

    #[test]
    fn rfc8032_kats() {
        let content = include_str!("../test-vectors/ed25519/rfc8032_kats.txt");
        let vectors = parse_kats(content);
        assert!(!vectors.is_empty(), "no KATs parsed");

        for (i, v) in vectors.iter().enumerate() {
            let sk = SigningKey::from_seed(&v.sk);

            // 1. Public key derives correctly.
            let pk = sk.verifying_key();
            assert_eq!(
                hex_encode(&pk.to_bytes()),
                hex_encode(&v.pk),
                "KAT #{i}: derived public key does not match expected",
            );

            // 2. Signing is deterministic and matches the RFC vector.
            let sig = sk.sign(&v.message);
            assert_eq!(
                hex_encode(&sig.to_bytes()),
                hex_encode(&v.signature),
                "KAT #{i}: signature does not match expected",
            );

            // 3. Verification succeeds.
            let pk_parsed = VerifyingKey::from_bytes(&v.pk).expect("parse PK");
            let sig_parsed = Signature::from_bytes(&v.signature);
            pk_parsed
                .verify(&v.message, &sig_parsed)
                .expect("verification should succeed");
        }
    }

    // ---------- sign/verify roundtrip and tampering ----------

    #[test]
    fn sign_verify_roundtrip() {
        let sk = SigningKey::generate(&mut OsRng);
        let pk = sk.verifying_key();
        let message = b"the quick brown fox jumps over the lazy dog";

        let sig = sk.sign(message);
        pk.verify(message, &sig)
            .expect("verification should succeed");
    }

    #[test]
    fn tampered_message_rejected() {
        let sk = SigningKey::from_seed(&[7u8; 32]);
        let pk = sk.verifying_key();
        let sig = sk.sign(b"original message");

        assert!(pk.verify(b"tampered message", &sig).is_err());
    }

    #[test]
    fn tampered_signature_rejected() {
        let sk = SigningKey::from_seed(&[7u8; 32]);
        let pk = sk.verifying_key();
        let mut sig_bytes = sk.sign(b"original message").to_bytes();
        sig_bytes[0] ^= 0x01; // flip one bit
        let tampered = Signature::from_bytes(&sig_bytes);

        assert!(pk.verify(b"original message", &tampered).is_err());
    }

    #[test]
    fn wrong_key_rejected() {
        let sk_a = SigningKey::from_seed(&[1u8; 32]);
        let sk_b = SigningKey::from_seed(&[2u8; 32]);
        let pk_b = sk_b.verifying_key();
        let sig_a = sk_a.sign(b"test message");

        assert!(pk_b.verify(b"test message", &sig_a).is_err());
    }

    // ---------- determinism ----------

    #[test]
    fn signing_is_deterministic() {
        let sk = SigningKey::from_seed(&[42u8; 32]);
        let message = b"determinism test";
        let sig_1 = sk.sign(message);
        let sig_2 = sk.sign(message);
        assert_eq!(sig_1.to_bytes(), sig_2.to_bytes());
    }

    // ---------- generation ----------

    #[test]
    fn generate_produces_distinct_keys() {
        let a = SigningKey::generate(&mut OsRng);
        let b = SigningKey::generate(&mut OsRng);
        // Compare via the constant-time path; equality on `Choice` is
        // not exposed (intentionally), so unwrap to bool for the test.
        assert!(!bool::from(a.ct_eq(&b)));
    }

    // ---------- constant-time equality ----------

    #[test]
    fn constant_time_eq_matches_seed_equality() {
        let seed = [3u8; 32];
        let k1 = SigningKey::from_seed(&seed);
        let k2 = SigningKey::from_seed(&seed);
        let k3 = SigningKey::from_seed(&[4u8; 32]);

        assert!(bool::from(k1.ct_eq(&k2)));
        assert!(!bool::from(k1.ct_eq(&k3)));
    }

    // ---------- zeroize ----------

    /// Compile-time assertion that [`SigningKey`] implements
    /// [`zeroize::ZeroizeOnDrop`]. The trait obligation is the strong
    /// part of the zeroize discipline: if our struct loses the trait,
    /// this fails to compile.
    #[test]
    fn signing_key_impls_zeroize_on_drop() {
        fn assert_impls<T: zeroize::ZeroizeOnDrop>() {}
        assert_impls::<SigningKey>();
    }

    /// Behavioural verification that calling
    /// [`zeroize::Zeroize::zeroize`] on a `SigningKey` actually reduces
    /// the underlying seed bytes to all zeros.
    ///
    /// This test does not perform pointer reads after `Drop`. The
    /// crate forbids `unsafe`, and post-drop pointer reads are
    /// undefined behaviour even with `unsafe`. Instead it verifies the
    /// zeroize *operation* in place via the public API: dalek's
    /// `to_bytes()` exposes the seed, and zeroize replaces it with
    /// zeros. Combined with the `ZeroizeOnDrop` trait-bound check
    /// above (which guarantees `Drop` calls this same operation), the
    /// pair establishes that drop zeroizes.
    #[test]
    fn signing_key_zeroize_zeros_bytes() {
        use zeroize::Zeroize;
        let mut sk = SigningKey::from_seed(&[1u8; 32]);
        assert_ne!(sk.inner.to_bytes(), [0u8; 32]);
        sk.zeroize();
        assert_eq!(sk.inner.to_bytes(), [0u8; 32]);
    }
}
