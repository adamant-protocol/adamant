//! ML-DSA-65 post-quantum signature wrapper, per whitepaper section 3.4.2.
//!
//! Implementation library: `ml-dsa` (`RustCrypto` / FIPS-204-compliant).
//! The protocol uses **ML-DSA-65 only** (security level 3); other
//! parameter sets (44 / 87) exist in the upstream crate but are not
//! exposed by this wrapper. Per whitepaper 3.4.2 the algorithm choice
//! is fixed.
//!
//! # API shape
//!
//! Mirrors [`crate::sig_classical`] as closely as the underlying
//! primitive allows. Three primary types:
//!
//! - [`SigningKey`] — the secret key. 32-byte seed, deterministic
//!   signing per FIPS 204 Algorithm 2 (`ML-DSA.Sign_internal`). Does
//!   NOT implement [`PartialEq`]; equality on secret material must use
//!   [`subtle::ConstantTimeEq`] explicitly.
//! - [`VerifyingKey`] — the public key. 1952 bytes, canonical
//!   encoding. Decoding is infallible at the byte level (per FIPS 204
//!   §8.2 Algorithm 22 — the encoding is a fixed-layout packing);
//!   validity is checked at verify time.
//! - [`Signature`] — a 3309-byte signature (FIPS 204 final size, per
//!   whitepaper 3.4.2). Decoding is fallible because the upstream
//!   `decode` returns `Option<Self>` (the internal `c̃ ‖ z ‖ h`
//!   packing has structural validity checks at parse time).
//!
//! # Constant-time discipline
//!
//! - All operations on secret material are constant-time. The upstream
//!   `ml-dsa` crate uses `ctutils::CtEq` and `ctutils::Choice` (its
//!   own constant-time helper crate, distinct from `subtle`) for
//!   comparisons; this wrapper routes our public `ConstantTimeEq` impl
//!   through equivalent comparisons on the seed bytes.
//! - Errors from parsing and verification are intentionally opaque
//!   ([`Error`] carries no detail). Verification failure modes can
//!   leak information about which check tripped if reported in detail
//!   (whitepaper 3.9).
//!
//! # Zeroization discipline
//!
//! - [`SigningKey`] manually impls [`zeroize::Zeroize`] and
//!   [`zeroize::ZeroizeOnDrop`]. The verification chain is the same
//!   as for [`crate::sig_classical::SigningKey`] — see the comment
//!   block above the `Zeroize` impl in this file.
//!
//! # Determinism
//!
//! - `SigningKey::sign` uses the **deterministic** ML-DSA mode
//!   (FIPS 204 Algorithm 2). The randomized variant (Algorithm 4)
//!   is intentionally not exposed. Whitepaper 3.4.2: "ML-DSA is also
//!   deterministic in its standard mode. The protocol uses
//!   deterministic signing throughout."

use ml_dsa::signature::rand_core::CryptoRng;
use ml_dsa::signature::{Error as SignatureCrateError, Keypair, Signer, Verifier};
use ml_dsa::{KeyGen, MlDsa65, B32};
use subtle::{Choice, ConstantTimeEq};

// Note: `CryptoRng` is imported from `ml_dsa::signature::rand_core` rather
// than the workspace `rand_core` because ml-dsa's `KeyGen::key_gen` is
// bounded by signature 3.0's rand_core (currently 0.10), distinct from
// rand_core 0.6 used by ed25519-dalek. This is a symptom of the
// RustCrypto ecosystem skew documented in SECURITY.md and clippy.toml.

/// Public-key length for ML-DSA-65 in bytes, per whitepaper section 3.4.2.
pub const PUBLIC_KEY_BYTES: usize = 1952;

/// Signature length for ML-DSA-65 in bytes, per whitepaper section 3.4.2
/// (FIPS 204 final, August 2024). Pre-finalization CRYSTALS-Dilithium
/// round 3 specified 3293 bytes for the equivalent parameter set; the
/// FIPS 204 standardisation expanded the encoding by 16 bytes.
pub const SIGNATURE_BYTES: usize = 3309;

/// Seed length for ML-DSA-65 in bytes (FIPS 204 §3.2: ξ ∈ {0,1}^256).
pub const SEED_BYTES: usize = 32;

/// An ML-DSA-65 signing (secret) key. 32-byte seed; the expanded
/// signing-key form used internally by FIPS 204 is held alongside the
/// seed by the upstream crate. Zeroizes on drop.
///
/// Does not implement [`PartialEq`]: comparing secret keys via plain
/// `==` is a footgun even when the underlying field elements would be
/// equal in constant time. Use [`SigningKey::ct_eq`] (from
/// [`ConstantTimeEq`]) when comparison is needed.
pub struct SigningKey {
    inner: ml_dsa::SigningKey<MlDsa65>,
}

// Zeroize / ZeroizeOnDrop are implemented manually for the same
// reason as in `sig_classical`: the upstream `ml_dsa::SigningKey` does
// not impl the standalone `Zeroize` trait (its expanded inner state
// has no sensible `Default`). The verification chain is the same one
// established for Ed25519 — see the comment block above the
// equivalent impls in `sig_classical.rs`. Briefly:
//
//   1. `ZeroizeOnDrop` trait bound on `SigningKey` is asserted at
//      compile time by `tests::signing_key_impls_zeroize_on_drop`.
//   2. In-place `Zeroize::zeroize()` byte check is exercised by
//      `tests::signing_key_zeroize_replaces_seed_with_zero`.
//   3. The post-drop "memory observably zero" property is closed by
//      the upstream zeroize impl on `ml_dsa::ExpandedSigningKey`
//      (manual `Drop` that scrubs every field — see ml-dsa
//      src/lib.rs). Trust boundary lives at the upstream layer;
//      adding an `unsafe` post-drop pointer-read test would relocate
//      the trust without strengthening it.
impl zeroize::Zeroize for SigningKey {
    fn zeroize(&mut self) {
        let zero_seed = B32::default();
        self.inner = MlDsa65::from_seed(&zero_seed);
    }
}

impl zeroize::ZeroizeOnDrop for SigningKey {}

/// An ML-DSA-65 verifying (public) key. 1952 bytes, canonical encoding.
///
/// `Eq` is intentionally not derived: the upstream `ml_dsa::VerifyingKey`
/// implements `PartialEq` only (no `Eq`). The protocol does not rely on
/// `Eq` for verifying keys — comparison via `PartialEq` is sufficient
/// for all consensus-relevant operations.
#[derive(Clone, PartialEq)]
pub struct VerifyingKey {
    inner: ml_dsa::VerifyingKey<MlDsa65>,
}

/// An ML-DSA-65 signature. 3309 bytes, canonical encoding.
///
/// `Eq` is intentionally not derived; same reason as [`VerifyingKey`].
#[derive(Clone, PartialEq)]
pub struct Signature {
    inner: ml_dsa::Signature<MlDsa65>,
}

/// Opaque ML-DSA operation error.
///
/// Returned by parsing, signing, and verification failures. Details
/// are intentionally not exposed: distinguishing failure modes leaks
/// information that verification's constant-time discipline is meant
/// to hide. See whitepaper section 3.9.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct Error;

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ML-DSA operation failed")
    }
}

impl std::error::Error for Error {}

impl From<SignatureCrateError> for Error {
    fn from(_: SignatureCrateError) -> Self {
        Self
    }
}

// ---------- SigningKey ----------

impl SigningKey {
    /// Generate a new signing key from a cryptographically secure
    /// random source. Per whitepaper section 3.8, key generation is
    /// the only operation in this primitive that consumes runtime
    /// randomness — signing itself is deterministic.
    pub fn generate<R: CryptoRng>(rng: &mut R) -> Self {
        Self {
            inner: <MlDsa65 as KeyGen>::key_gen(rng),
        }
    }

    /// Construct a signing key deterministically from a 32-byte seed
    /// (FIPS 204 Algorithm 6, `ML-DSA.KeyGen_internal`).
    #[must_use]
    pub fn from_seed(seed: &[u8; SEED_BYTES]) -> Self {
        let xi = B32::from(*seed);
        Self {
            inner: <MlDsa65 as KeyGen>::from_seed(&xi),
        }
    }

    /// Derive the corresponding verifying key.
    #[must_use]
    pub fn verifying_key(&self) -> VerifyingKey {
        VerifyingKey {
            inner: self.inner.verifying_key(),
        }
    }

    /// Sign `message` deterministically (FIPS 204 Algorithm 2,
    /// `ML-DSA.Sign_internal`). The output depends only on the key
    /// and the message; calling `sign` twice with the same arguments
    /// produces byte-identical signatures.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] if the underlying signing operation fails.
    /// In FIPS 204 ML-DSA the signing loop has a small theoretical
    /// failure rate due to rejection sampling exceeding its retry
    /// budget; the probability is astronomically small but not zero,
    /// so the API is fallible rather than panic-on-failure.
    pub fn sign(&self, message: &[u8]) -> Result<Signature, Error> {
        self.inner
            .try_sign(message)
            .map(|inner| Signature { inner })
            .map_err(Error::from)
    }
}

impl ConstantTimeEq for SigningKey {
    fn ct_eq(&self, other: &Self) -> Choice {
        // Route through the seeds. The expanded signing-key form is a
        // deterministic function of the seed (FIPS 204 Algorithm 6),
        // so seed equality implies expanded-key equality.
        let mine = self.inner.to_seed();
        let theirs = other.inner.to_seed();
        mine.as_slice().ct_eq(theirs.as_slice())
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
    /// Parse a verifying key from its canonical 1952-byte encoding
    /// (FIPS 204 §8.2 Algorithm 22). The decoding is structurally
    /// infallible: every 1952-byte input maps to a `VerifyingKey`,
    /// because the encoding is a fixed-layout packing of `ρ ‖ t1`.
    /// Public-key validity is checked at [`verify`](Self::verify)
    /// time.
    #[must_use]
    pub fn from_bytes(bytes: &[u8; PUBLIC_KEY_BYTES]) -> Self {
        let array = ml_dsa::EncodedVerifyingKey::<MlDsa65>::from(*bytes);
        Self {
            inner: ml_dsa::VerifyingKey::<MlDsa65>::decode(&array),
        }
    }

    /// Canonical 1952-byte encoding.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; PUBLIC_KEY_BYTES] {
        let encoded = self.inner.encode();
        let slice: &[u8] = encoded.as_ref();
        let mut out = [0u8; PUBLIC_KEY_BYTES];
        out.copy_from_slice(slice);
        out
    }

    /// Verify `signature` against `message`.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] if the signature does not validate. The
    /// error is intentionally opaque (no detail about which check
    /// failed), per whitepaper section 3.9 and the constant-time
    /// discipline described in this module's top-level doc.
    pub fn verify(&self, message: &[u8], signature: &Signature) -> Result<(), Error> {
        self.inner
            .verify(message, &signature.inner)
            .map_err(Error::from)
    }
}

impl core::fmt::Debug for VerifyingKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Print the first 8 bytes only — full key is 1952 bytes which
        // is unhelpful in trace output. The verify path uses the
        // full key; this is for diagnostic identification only.
        let bytes = self.to_bytes();
        write!(f, "VerifyingKey(ml-dsa-65, {})…", hex_encode(&bytes[..8]))
    }
}

// ---------- Signature ----------

impl Signature {
    /// Parse a signature from its canonical 3309-byte encoding.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] if the bytes do not form a structurally
    /// valid encoding (FIPS 204 §8.2 Algorithm 26). Cryptographic
    /// validity against any specific message is checked separately
    /// by [`VerifyingKey::verify`].
    pub fn from_bytes(bytes: &[u8; SIGNATURE_BYTES]) -> Result<Self, Error> {
        let array = ml_dsa::EncodedSignature::<MlDsa65>::from(*bytes);
        ml_dsa::Signature::<MlDsa65>::decode(&array)
            .map(|inner| Self { inner })
            .ok_or(Error)
    }

    /// Canonical 3309-byte encoding.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; SIGNATURE_BYTES] {
        let encoded = self.inner.encode();
        let slice: &[u8] = encoded.as_ref();
        let mut out = [0u8; SIGNATURE_BYTES];
        out.copy_from_slice(slice);
        out
    }
}

impl core::fmt::Debug for Signature {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let bytes = self.to_bytes();
        write!(f, "Signature(ml-dsa-65, {})…", hex_encode(&bytes[..8]))
    }
}

/// Lower-case hex encoding helper for `Debug` impls. Identical in
/// shape to the helper in `sig_classical`; kept private here to avoid
/// a cross-module dependency for what is purely a diagnostic concern.
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
    use getrandom::{rand_core::UnwrapErr, SysRng};

    // ---------- NIST ACVP keyGen KATs ----------

    /// Reads a fixed-shape ACVP-style block file:
    ///
    /// ```text
    /// tcId = <number>
    /// Seed = <hex>
    /// PK   = <hex>
    /// ```
    ///
    /// Returns `(tcId, seed, pk)` triples. Comments / `[bracketed]`
    /// headers / blank lines are skipped.
    fn parse_key_gen_kats(content: &str) -> Vec<(u64, [u8; SEED_BYTES], [u8; PUBLIC_KEY_BYTES])> {
        let mut out = Vec::new();
        let mut tc_id: Option<u64> = None;
        let mut seed: Option<[u8; SEED_BYTES]> = None;

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
                "tcId" => {
                    tc_id = Some(value.parse().expect("valid tcId"));
                }
                "Seed" => {
                    let bytes = hex::decode(value).expect("valid hex in Seed");
                    seed = Some(bytes.try_into().expect("Seed must be 32 bytes"));
                }
                "PK" => {
                    let bytes = hex::decode(value).expect("valid hex in PK");
                    let pk: [u8; PUBLIC_KEY_BYTES] =
                        bytes.try_into().expect("PK must be 1952 bytes");
                    let id = tc_id.take().expect("tcId must precede PK");
                    let s = seed.take().expect("Seed must precede PK");
                    out.push((id, s, pk));
                }
                _ => {}
            }
        }
        out
    }

    /// `(tcId, public-key bytes, message, signature bytes)` row from
    /// the sigVer KAT file. Aliased to placate `clippy::type_complexity`.
    type SigVerKat = (u64, [u8; PUBLIC_KEY_BYTES], Vec<u8>, [u8; SIGNATURE_BYTES]);

    /// Same shape as [`parse_key_gen_kats`] but reads
    /// `(tcId, pk, message, signature)` rows for the sigVer KAT file.
    fn parse_sig_ver_kats(content: &str) -> Vec<SigVerKat> {
        let mut out = Vec::new();
        let mut tc_id: Option<u64> = None;
        let mut pk: Option<[u8; PUBLIC_KEY_BYTES]> = None;
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
                "tcId" => {
                    tc_id = Some(value.parse().expect("valid tcId"));
                }
                "PK" => {
                    let bytes = hex::decode(value).expect("valid hex in PK");
                    pk = Some(bytes.try_into().expect("PK must be 1952 bytes"));
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
                    let sig: [u8; SIGNATURE_BYTES] =
                        bytes.try_into().expect("Signature must be 3309 bytes");
                    let id = tc_id.take().expect("tcId must precede Signature");
                    let p = pk.take().expect("PK must precede Signature");
                    let m = message.take().expect("Message must precede Signature");
                    out.push((id, p, m, sig));
                }
                _ => {}
            }
        }
        out
    }

    /// Verifies that `SigningKey::from_seed(seed)` produces a
    /// verifying key whose canonical encoding matches each NIST ACVP
    /// keyGen vector for ML-DSA-65.
    #[test]
    fn nist_acvp_key_gen_kats() {
        let content = include_str!("../test-vectors/ml-dsa/key_gen_kats.txt");
        let kats = parse_key_gen_kats(content);
        assert!(!kats.is_empty(), "no keyGen KATs parsed");

        for (tc_id, seed, expected_pk) in &kats {
            let sk = SigningKey::from_seed(seed);
            let derived_pk = sk.verifying_key().to_bytes();
            assert_eq!(
                hex_encode(&derived_pk),
                hex_encode(expected_pk),
                "keyGen tcId = {tc_id}: derived PK does not match NIST expected",
            );
        }
    }

    /// Verifies that NIST ACVP sigVer vectors verify successfully
    /// through our public verify path.
    #[test]
    fn nist_acvp_sig_ver_kats() {
        let content = include_str!("../test-vectors/ml-dsa/sig_ver_kats.txt");
        let kats = parse_sig_ver_kats(content);
        assert!(!kats.is_empty(), "no sigVer KATs parsed");

        for (tc_id, pk_bytes, message, sig_bytes) in &kats {
            let pk = VerifyingKey::from_bytes(pk_bytes);
            let sig = Signature::from_bytes(sig_bytes)
                .unwrap_or_else(|_| panic!("sigVer tcId = {tc_id}: signature parse failed"));
            pk.verify(message, &sig)
                .unwrap_or_else(|_| panic!("sigVer tcId = {tc_id}: verification failed"));
        }
    }

    // ---------- sign/verify roundtrip and tampering ----------

    #[test]
    fn sign_verify_roundtrip() {
        let sk = SigningKey::generate(&mut UnwrapErr(SysRng));
        let pk = sk.verifying_key();
        let message = b"the quick brown fox jumps over the lazy dog";

        let sig = sk.sign(message).expect("signing should succeed");
        pk.verify(message, &sig)
            .expect("verification should succeed");
    }

    #[test]
    fn tampered_message_rejected() {
        let sk = SigningKey::from_seed(&[7u8; SEED_BYTES]);
        let pk = sk.verifying_key();
        let sig = sk
            .sign(b"original message")
            .expect("signing should succeed");

        assert!(pk.verify(b"tampered message", &sig).is_err());
    }

    #[test]
    fn tampered_signature_rejected() {
        let sk = SigningKey::from_seed(&[7u8; SEED_BYTES]);
        let pk = sk.verifying_key();
        let mut sig_bytes = sk
            .sign(b"original message")
            .expect("signing should succeed")
            .to_bytes();
        sig_bytes[0] ^= 0x01; // flip one bit
        let tampered = Signature::from_bytes(&sig_bytes)
            .expect("tampered signature should still parse structurally");
        assert!(pk.verify(b"original message", &tampered).is_err());
    }

    #[test]
    fn wrong_key_rejected() {
        let sk_a = SigningKey::from_seed(&[1u8; SEED_BYTES]);
        let sk_b = SigningKey::from_seed(&[2u8; SEED_BYTES]);
        let pk_b = sk_b.verifying_key();
        let sig_a = sk_a.sign(b"test message").expect("signing should succeed");

        assert!(pk_b.verify(b"test message", &sig_a).is_err());
    }

    // ---------- determinism ----------

    /// Per FIPS 204 §3.6 and whitepaper 3.4.2: ML-DSA standard mode
    /// is deterministic. Same key + same message ⇒ same signature.
    #[test]
    fn signing_is_deterministic() {
        let sk = SigningKey::from_seed(&[42u8; SEED_BYTES]);
        let message = b"determinism test";
        let sig_1 = sk.sign(message).expect("signing should succeed");
        let sig_2 = sk.sign(message).expect("signing should succeed");
        assert_eq!(sig_1.to_bytes(), sig_2.to_bytes());
    }

    // ---------- generation ----------

    #[test]
    fn generate_produces_distinct_keys() {
        let a = SigningKey::generate(&mut UnwrapErr(SysRng));
        let b = SigningKey::generate(&mut UnwrapErr(SysRng));
        assert!(!bool::from(a.ct_eq(&b)));
    }

    // ---------- constant-time equality ----------

    #[test]
    fn constant_time_eq_matches_seed_equality() {
        let seed = [3u8; SEED_BYTES];
        let k1 = SigningKey::from_seed(&seed);
        let k2 = SigningKey::from_seed(&seed);
        let k3 = SigningKey::from_seed(&[4u8; SEED_BYTES]);

        assert!(bool::from(k1.ct_eq(&k2)));
        assert!(!bool::from(k1.ct_eq(&k3)));
    }

    // ---------- byte-array round trips ----------

    #[test]
    fn verifying_key_bytes_round_trip() {
        let sk = SigningKey::from_seed(&[5u8; SEED_BYTES]);
        let pk = sk.verifying_key();
        let bytes = pk.to_bytes();
        let parsed = VerifyingKey::from_bytes(&bytes);
        assert_eq!(parsed, pk);
        assert_eq!(parsed.to_bytes(), bytes);
    }

    #[test]
    fn signature_bytes_round_trip() {
        let sk = SigningKey::from_seed(&[6u8; SEED_BYTES]);
        let sig = sk.sign(b"round trip").expect("signing should succeed");
        let bytes = sig.to_bytes();
        let parsed = Signature::from_bytes(&bytes).expect("parse should succeed");
        assert_eq!(parsed.to_bytes(), bytes);
    }

    // ---------- key/signature lengths match the whitepaper ----------

    #[test]
    fn declared_lengths_match_whitepaper() {
        assert_eq!(PUBLIC_KEY_BYTES, 1952);
        assert_eq!(SIGNATURE_BYTES, 3309);
        assert_eq!(SEED_BYTES, 32);
    }

    // ---------- zeroize ----------

    #[test]
    fn signing_key_impls_zeroize_on_drop() {
        fn assert_impls<T: zeroize::ZeroizeOnDrop>() {}
        assert_impls::<SigningKey>();
    }

    /// Behavioural verification: after `.zeroize()`, the inner seed
    /// is replaced with the zero seed. See the comment block above
    /// the `Zeroize` impl in this file for the rationale on this
    /// verification approach.
    #[test]
    fn signing_key_zeroize_replaces_seed_with_zero() {
        use zeroize::Zeroize;
        let mut sk = SigningKey::from_seed(&[1u8; SEED_BYTES]);
        let before = sk.inner.to_seed();
        assert_ne!(before.as_slice(), [0u8; SEED_BYTES].as_slice());
        sk.zeroize();
        let after = sk.inner.to_seed();
        assert_eq!(after.as_slice(), [0u8; SEED_BYTES].as_slice());
    }
}
