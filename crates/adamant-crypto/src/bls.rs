//! BLS12-381 signature and pairing wrappers, per whitepaper section 3.4.3.
//!
//! Implementation library: `blst` (Supranational). Per whitepaper 3.4.3,
//! "the highest-performance audited BLS12-381 implementation in current
//! use." Audited by NCC Group (2020 and subsequent); deployed in Ethereum
//! consensus, Filecoin, Chia. Note: `blst` is **not** a `RustCrypto` crate
//! — different lineage, different versioning, no participation in the
//!  `RustCrypto` 0.10 / post-0.10 ecosystem skew documented in `SECURITY.md`.
//!
//! # API shape
//!
//! Five primary types, mirroring the conventional BLS surface used by
//! every BLS12-381 deployment we draw test vectors from:
//!
//! - [`SecretKey`] — 32-byte secret key (BLS scalar). Zeroizes on drop.
//!   Does NOT implement [`PartialEq`]; equality on secret material must
//!   use [`subtle::ConstantTimeEq`] explicitly.
//! - [`PublicKey`] — 96 bytes (G2 point, compressed). Per whitepaper
//!   3.4.3 the protocol uses the **G1 signature, G2 public key** variant.
//! - [`Signature`] — 48 bytes (G1 point, compressed).
//! - [`AggregatePublicKey`] — combined public key for N validators
//!   sharing a single message; constructed via [`AggregatePublicKey::aggregate`].
//! - [`AggregateSignature`] — combined signature on the same or different
//!   messages; constructed via [`AggregateSignature::aggregate`] and
//!   verified via either [`AggregateSignature::fast_aggregate_verify`]
//!   (one shared message) or [`AggregateSignature::aggregate_verify`]
//!   (multiple messages).
//!
//! Aggregation is the whole reason the protocol uses BLS over Ed25519
//! for consensus (whitepaper 3.4.3); both aggregate types are part of
//! the API from day one.
//!
//! # Domain separation and the SHA-256 question
//!
//! Hash-to-curve uses the IRTF `draft-irtf-cfrg-hash-to-curve`
//! ciphersuite [`crate::domain::BLS_SIG_HASH_TO_CURVE`]
//! (`BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_ADAMANT_v1`). The SHA-256
//! prefix is the IRTF ciphersuite's internal hash, fixed by the
//! BLS12-381 G1 ciphersuite specification — *not* a protocol choice.
//! Changing it would mean the wrapper's BLS implementation no longer
//! matches the IETF spec, breaking interoperability with every other
//! BLS12-381 deployment (Ethereum consensus, Filecoin, Zcash Sapling).
//! Protocol-level hashing — transaction identifiers, state commitments,
//! the BIP-340 tagged-hash construction — still uses SHA3-256
//! (whitepaper 3.3.1); the SHA-256 internal use is contained inside
//! the BLS hash-to-curve operation only.
//!
//! # Constant-time discipline
//!
//! - All operations on secret material are constant-time. blst is
//!   constant-time by design at the C-library level. The wrapper
//!   preserves this by routing equality through [`ConstantTimeEq`].
//! - Errors from parsing and verification are intentionally opaque
//!   ([`Error`] carries no detail), per whitepaper 3.9.
//!
//! # Zeroization discipline
//!
//! - [`SecretKey`] manually impls [`zeroize::Zeroize`] and
//!   [`zeroize::ZeroizeOnDrop`]. The verification chain is the same
//!   one established for Ed25519 and ML-DSA — see the comment block
//!   above the `Zeroize` impl in this file.
//!
//! # `unsafe` surface
//!
//! `blst` is a Rust binding over a C library (whitepaper 3.4.3). It
//! contains `unsafe` for FFI; this is the canonical example of
//! "upstream `unsafe` permitted only in audited cryptographic
//! libraries" from `SECURITY.md`. The `blst` row in `SECURITY.md`
//! records the audit history.

use blst::min_sig::{
    AggregatePublicKey as BlstAggregatePublicKey, AggregateSignature as BlstAggregateSignature,
    PublicKey as BlstPublicKey, SecretKey as BlstSecretKey, Signature as BlstSignature,
};
use blst::BLST_ERROR;
use rand_core::{CryptoRng, RngCore};
use subtle::{Choice, ConstantTimeEq};

use crate::domain::BLS_SIG_HASH_TO_CURVE;

/// Secret-key length in bytes (BLS12-381 scalar serialised big-endian).
pub const SECRET_KEY_BYTES: usize = 32;

/// Public-key length in bytes (G2 compressed), per whitepaper section 3.4.3.
pub const PUBLIC_KEY_BYTES: usize = 96;

/// Signature length in bytes (G1 compressed), per whitepaper section 3.4.3.
pub const SIGNATURE_BYTES: usize = 48;

/// Minimum input-key-material length for [`SecretKey::from_ikm`], from
/// IRTF `draft-irtf-cfrg-bls-signature` §2.3.
pub const MIN_IKM_BYTES: usize = 32;

/// A BLS12-381 secret key (scalar). 32 bytes serialised. Zeroizes on
/// drop.
///
/// Does not implement [`PartialEq`]: comparing secret keys via plain
/// `==` is a footgun even when the underlying field elements would be
/// equal in constant time. Use [`SecretKey::ct_eq`] (from
/// [`ConstantTimeEq`]) when comparison is needed.
pub struct SecretKey {
    inner: BlstSecretKey,
}

// Zeroize / ZeroizeOnDrop are implemented manually for parity with the
// Ed25519 and ML-DSA wrappers, even though `blst::min_sig::SecretKey`
// derives `Zeroize` directly. The verification chain is the same one
// established for the other two signature schemes:
//
//   1. `ZeroizeOnDrop` trait bound on `SecretKey` is asserted at compile
//      time by `tests::secret_key_impls_zeroize_on_drop`.
//   2. In-place `Zeroize::zeroize()` byte check is exercised by
//      `tests::secret_key_zeroize_zeros_bytes`.
//   3. The post-drop "memory observably zero" property is closed by
//      blst's `Zeroize` derive on its `SecretKey` (the inner scalar is
//      scrubbed when `Drop` runs). Trust boundary lives at the upstream
//      layer; an `unsafe` post-drop pointer-read test would relocate the
//      trust without strengthening it.
impl zeroize::Zeroize for SecretKey {
    fn zeroize(&mut self) {
        // `blst::min_sig::SecretKey` derives `Zeroize`. Fully-qualified
        // call avoids needing `Zeroize` in module-level scope while
        // still routing through the trait method.
        <BlstSecretKey as zeroize::Zeroize>::zeroize(&mut self.inner);
    }
}

impl zeroize::ZeroizeOnDrop for SecretKey {}

/// A BLS12-381 public key (G2 point). 96 bytes compressed.
#[derive(Clone, Eq, PartialEq)]
pub struct PublicKey {
    inner: BlstPublicKey,
}

/// A BLS12-381 signature (G1 point). 48 bytes compressed.
#[derive(Clone, Eq, PartialEq)]
pub struct Signature {
    inner: BlstSignature,
}

/// A BLS12-381 aggregate public key — the sum (in G2) of N individual
/// public keys. Used for aggregate verification; constructed via
/// [`AggregatePublicKey::aggregate`].
#[derive(Clone)]
pub struct AggregatePublicKey {
    inner: BlstAggregatePublicKey,
}

/// A BLS12-381 aggregate signature — the sum (in G1) of N individual
/// signatures. Verified against either a single message
/// ([`AggregateSignature::fast_aggregate_verify`]) or a list of
/// messages aligned with a list of public keys
/// ([`AggregateSignature::aggregate_verify`]).
#[derive(Clone)]
pub struct AggregateSignature {
    inner: BlstAggregateSignature,
}

/// Opaque BLS operation error.
///
/// Returned by parsing, signing, aggregation, and verification
/// failures. Details are intentionally not exposed: distinguishing
/// failure modes leaks information that verification's constant-time
/// discipline is meant to hide. See whitepaper section 3.9.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct Error;

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("BLS operation failed")
    }
}

impl std::error::Error for Error {}

impl From<BLST_ERROR> for Error {
    fn from(_: BLST_ERROR) -> Self {
        Self
    }
}

/// Returns `Ok(())` if the blst error is `BLST_SUCCESS`, otherwise
/// our opaque [`Error`]. Internal helper.
fn check(err: BLST_ERROR) -> Result<(), Error> {
    match err {
        BLST_ERROR::BLST_SUCCESS => Ok(()),
        _ => Err(Error),
    }
}

// ---------- SecretKey ----------

impl SecretKey {
    /// Generate a new secret key by drawing 32 bytes of input key
    /// material from `rng` and running the IRTF
    /// `draft-irtf-cfrg-bls-signature` `KeyGen` algorithm. Per
    /// whitepaper section 3.8 this is the only operation that consumes
    /// runtime randomness for BLS — signing is deterministic over
    /// `(secret_key, message)`.
    ///
    /// # Panics
    ///
    /// Cannot panic in practice: the spec-mandated minimum IKM length
    /// is 32 bytes, which is exactly what we provide. The internal
    /// `expect` is a contract assertion against the only failure mode
    /// the underlying `key_gen` exposes (short IKM).
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let mut ikm = [0u8; MIN_IKM_BYTES];
        rng.fill_bytes(&mut ikm);
        let inner = BlstSecretKey::key_gen(&ikm, &[])
            .expect("32-byte IKM is the spec-mandated minimum and always valid");
        Self { inner }
    }

    /// Derive a secret key from arbitrary input key material per IRTF
    /// `draft-irtf-cfrg-bls-signature` `KeyGen`. The IKM must be at
    /// least [`MIN_IKM_BYTES`] (32) bytes long.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] if `ikm.len() < MIN_IKM_BYTES` or if the
    /// underlying derivation rejects the input.
    pub fn from_ikm(ikm: &[u8]) -> Result<Self, Error> {
        if ikm.len() < MIN_IKM_BYTES {
            return Err(Error);
        }
        BlstSecretKey::key_gen(ikm, &[])
            .map(|inner| Self { inner })
            .map_err(Error::from)
    }

    /// Construct a secret key from its 32-byte serialised form.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] if the bytes do not encode a valid scalar
    /// (zero is rejected; values ≥ curve order are rejected).
    pub fn from_bytes(bytes: &[u8; SECRET_KEY_BYTES]) -> Result<Self, Error> {
        BlstSecretKey::from_bytes(bytes)
            .map(|inner| Self { inner })
            .map_err(Error::from)
    }

    /// Canonical 32-byte serialised form.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; SECRET_KEY_BYTES] {
        self.inner.to_bytes()
    }

    /// Derive the corresponding public key.
    #[must_use]
    pub fn public_key(&self) -> PublicKey {
        PublicKey {
            inner: self.inner.sk_to_pk(),
        }
    }

    /// Sign `message` with this secret key. Hash-to-curve uses the
    /// IRTF DST [`crate::domain::BLS_SIG_HASH_TO_CURVE`].
    #[must_use]
    pub fn sign(&self, message: &[u8]) -> Signature {
        Signature {
            inner: self
                .inner
                .sign(message, BLS_SIG_HASH_TO_CURVE.as_bytes(), &[]),
        }
    }
}

impl ConstantTimeEq for SecretKey {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.inner.to_bytes().ct_eq(&other.inner.to_bytes())
    }
}

impl core::fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SecretKey(<redacted>)")
    }
}

// ---------- PublicKey ----------

impl PublicKey {
    /// Parse a public key from its 96-byte canonical compressed
    /// encoding (G2 point).
    ///
    /// # Errors
    ///
    /// Returns [`Error`] if the bytes do not encode a valid G2 point
    /// in the prime-order subgroup.
    pub fn from_bytes(bytes: &[u8; PUBLIC_KEY_BYTES]) -> Result<Self, Error> {
        BlstPublicKey::key_validate(bytes)
            .map(|inner| Self { inner })
            .map_err(Error::from)
    }

    /// Canonical 96-byte compressed encoding.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; PUBLIC_KEY_BYTES] {
        self.inner.compress()
    }

    /// Verify `signature` against `message`.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] if the signature does not validate. The
    /// error is intentionally opaque — see this module's top-level
    /// doc comment.
    pub fn verify(&self, message: &[u8], signature: &Signature) -> Result<(), Error> {
        check(signature.inner.verify(
            true, // sig_groupcheck
            message,
            BLS_SIG_HASH_TO_CURVE.as_bytes(),
            &[],
            &self.inner,
            true, // pk_validate
        ))
    }
}

impl core::fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let bytes = self.to_bytes();
        write!(f, "PublicKey(bls12-381-g2, {})…", hex_encode(&bytes[..8]))
    }
}

// ---------- Signature ----------

impl Signature {
    /// Parse a signature from its 48-byte canonical compressed
    /// encoding (G1 point).
    ///
    /// # Errors
    ///
    /// Returns [`Error`] if the bytes do not encode a valid G1 point
    /// in the prime-order subgroup.
    pub fn from_bytes(bytes: &[u8; SIGNATURE_BYTES]) -> Result<Self, Error> {
        BlstSignature::sig_validate(bytes, true)
            .map(|inner| Self { inner })
            .map_err(Error::from)
    }

    /// Canonical 48-byte compressed encoding.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; SIGNATURE_BYTES] {
        self.inner.compress()
    }
}

impl core::fmt::Debug for Signature {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let bytes = self.to_bytes();
        write!(f, "Signature(bls12-381-g1, {})…", hex_encode(&bytes[..8]))
    }
}

// ---------- AggregatePublicKey ----------

impl AggregatePublicKey {
    /// Aggregate a slice of public keys into a single aggregate.
    /// Inputs are subgroup-validated.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] if `public_keys` is empty or if any key
    /// fails validation.
    pub fn aggregate(public_keys: &[&PublicKey]) -> Result<Self, Error> {
        if public_keys.is_empty() {
            return Err(Error);
        }
        let inner_pks: alloc::vec::Vec<&BlstPublicKey> =
            public_keys.iter().map(|pk| &pk.inner).collect();
        BlstAggregatePublicKey::aggregate(&inner_pks, true)
            .map(|inner| Self { inner })
            .map_err(Error::from)
    }

    /// Convert the aggregate back to a single [`PublicKey`].
    #[must_use]
    pub fn to_public_key(&self) -> PublicKey {
        PublicKey {
            inner: self.inner.to_public_key(),
        }
    }
}

// ---------- AggregateSignature ----------

impl AggregateSignature {
    /// Aggregate a slice of signatures into a single aggregate.
    /// Inputs are subgroup-validated.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] if `signatures` is empty or if any signature
    /// fails validation.
    pub fn aggregate(signatures: &[&Signature]) -> Result<Self, Error> {
        if signatures.is_empty() {
            return Err(Error);
        }
        let inner_sigs: alloc::vec::Vec<&BlstSignature> =
            signatures.iter().map(|s| &s.inner).collect();
        BlstAggregateSignature::aggregate(&inner_sigs, true)
            .map(|inner| Self { inner })
            .map_err(Error::from)
    }

    /// Convert the aggregate back to a single [`Signature`].
    #[must_use]
    pub fn to_signature(&self) -> Signature {
        Signature {
            inner: self.inner.to_signature(),
        }
    }

    /// Verify the aggregate against a single shared message — the
    /// common consensus case where N validators all sign the same
    /// vote. Faster than [`Self::aggregate_verify`] because the
    /// hash-to-curve operation is performed once rather than N times.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] if `public_keys` is empty or if verification
    /// fails. The error is intentionally opaque.
    pub fn fast_aggregate_verify(
        &self,
        message: &[u8],
        public_keys: &[&PublicKey],
    ) -> Result<(), Error> {
        if public_keys.is_empty() {
            return Err(Error);
        }
        let sig = self.to_signature();
        let inner_pks: alloc::vec::Vec<&BlstPublicKey> =
            public_keys.iter().map(|pk| &pk.inner).collect();
        check(sig.inner.fast_aggregate_verify(
            true, // sig_groupcheck
            message,
            BLS_SIG_HASH_TO_CURVE.as_bytes(),
            &inner_pks,
        ))
    }

    /// Verify the aggregate against a list of messages aligned with a
    /// list of public keys. Used when each signer signed a different
    /// message; per whitepaper 3.4.3, BLS aggregation supports this
    /// natively.
    ///
    /// `messages` and `public_keys` must have the same length and be
    /// in matching order.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] if the lengths disagree, if either slice is
    /// empty, or if verification fails. Opaque.
    pub fn aggregate_verify(
        &self,
        messages: &[&[u8]],
        public_keys: &[&PublicKey],
    ) -> Result<(), Error> {
        if messages.is_empty() || messages.len() != public_keys.len() {
            return Err(Error);
        }
        let sig = self.to_signature();
        let inner_pks: alloc::vec::Vec<&BlstPublicKey> =
            public_keys.iter().map(|pk| &pk.inner).collect();
        check(sig.inner.aggregate_verify(
            true, // sig_groupcheck
            messages,
            BLS_SIG_HASH_TO_CURVE.as_bytes(),
            &inner_pks,
            true, // pks_validate
        ))
    }
}

// `alloc::vec::Vec` is the no_std-compatible path; the std prelude
// re-exports it so we use it uniformly here for clarity.
extern crate alloc;

/// Lower-case hex encoding helper for `Debug` impls. Same shape as
/// the helpers in `sig_classical` and `sig_pq`; kept private to avoid
/// cross-module coupling for what is a diagnostic concern.
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

    fn sk_from_seed(seed: u8) -> SecretKey {
        // 32-byte deterministic IKM derived from a one-byte seed; used
        // throughout the tests for repeatable key generation.
        let mut ikm = [0u8; 32];
        ikm[31] = seed;
        ikm[0] = 1; // ensure non-trivial IKM that key_gen accepts
        SecretKey::from_ikm(&ikm).expect("valid IKM")
    }

    // ---------- declared lengths match the whitepaper ----------

    #[test]
    fn declared_lengths_match_whitepaper() {
        assert_eq!(SECRET_KEY_BYTES, 32);
        assert_eq!(PUBLIC_KEY_BYTES, 96);
        assert_eq!(SIGNATURE_BYTES, 48);
    }

    // ---------- DST is the registry constant, not an inline literal ----------

    #[test]
    fn dst_is_sourced_from_domain_registry() {
        let expected = b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_ADAMANT_v1";
        assert_eq!(BLS_SIG_HASH_TO_CURVE.as_bytes(), expected);
    }

    // ---------- single-signature roundtrip ----------

    #[test]
    fn sign_verify_roundtrip() {
        let sk = SecretKey::generate(&mut OsRng);
        let pk = sk.public_key();
        let message = b"the quick brown fox jumps over the lazy dog";

        let sig = sk.sign(message);
        pk.verify(message, &sig)
            .expect("verification should succeed");
    }

    #[test]
    fn tampered_message_rejected() {
        let sk = sk_from_seed(7);
        let pk = sk.public_key();
        let sig = sk.sign(b"original message");

        assert!(pk.verify(b"tampered message", &sig).is_err());
    }

    #[test]
    fn tampered_signature_rejected() {
        let sk = sk_from_seed(7);
        let pk = sk.public_key();
        let mut sig_bytes = sk.sign(b"original message").to_bytes();
        // Flip a bit in the trailing bytes. BLS12-381 G1 compressed
        // encodings carry subgroup-validation information densely;
        // most byte mutations produce inputs that fail at parse time
        // rather than verify time. Either rejection layer is correct
        // — what matters is that tampering is rejected somewhere.
        sig_bytes[10] ^= 0x01;
        let result = Signature::from_bytes(&sig_bytes)
            .and_then(|tampered| pk.verify(b"original message", &tampered));
        assert!(result.is_err());
    }

    #[test]
    fn wrong_key_rejected() {
        let sk_a = sk_from_seed(1);
        let sk_b = sk_from_seed(2);
        let sig_a = sk_a.sign(b"test message");
        let pk_b = sk_b.public_key();

        assert!(pk_b.verify(b"test message", &sig_a).is_err());
    }

    // ---------- determinism ----------

    /// BLS signatures over the same (sk, message) pair are deterministic.
    /// This is a property of the BLS scheme, not specific to blst.
    #[test]
    fn signing_is_deterministic() {
        let sk = sk_from_seed(42);
        let msg = b"determinism test";
        let sig_1 = sk.sign(msg);
        let sig_2 = sk.sign(msg);
        assert_eq!(sig_1.to_bytes(), sig_2.to_bytes());
    }

    // ---------- generation ----------

    #[test]
    fn generate_produces_distinct_keys() {
        let a = SecretKey::generate(&mut OsRng);
        let b = SecretKey::generate(&mut OsRng);
        assert!(!bool::from(a.ct_eq(&b)));
    }

    // ---------- byte round-trips ----------

    #[test]
    fn secret_key_bytes_round_trip() {
        let sk = sk_from_seed(5);
        let bytes = sk.to_bytes();
        let parsed = SecretKey::from_bytes(&bytes).expect("parse");
        assert_eq!(parsed.to_bytes(), bytes);
    }

    #[test]
    fn public_key_bytes_round_trip() {
        let sk = sk_from_seed(6);
        let pk = sk.public_key();
        let bytes = pk.to_bytes();
        let parsed = PublicKey::from_bytes(&bytes).expect("parse");
        assert_eq!(parsed, pk);
    }

    #[test]
    fn signature_bytes_round_trip() {
        let sk = sk_from_seed(7);
        let sig = sk.sign(b"round trip");
        let bytes = sig.to_bytes();
        let parsed = Signature::from_bytes(&bytes).expect("parse");
        assert_eq!(parsed, sig);
    }

    // ---------- constant-time equality ----------

    #[test]
    fn constant_time_eq_matches_byte_equality() {
        let a = sk_from_seed(3);
        let b = sk_from_seed(3);
        let c = sk_from_seed(4);
        assert!(bool::from(a.ct_eq(&b)));
        assert!(!bool::from(a.ct_eq(&c)));
    }

    // ---------- IKM length validation ----------

    #[test]
    fn from_ikm_rejects_short_ikm() {
        let short = [0u8; 31];
        assert!(SecretKey::from_ikm(&short).is_err());
    }

    // ---------- aggregation: same-message ----------

    /// Per whitepaper 3.4.3: aggregating N signatures on the same
    /// message produces a verifying aggregate.
    #[test]
    fn fast_aggregate_verify_same_message() {
        let sks: Vec<SecretKey> = (1u8..=5).map(sk_from_seed).collect();
        let pks: Vec<PublicKey> = sks.iter().map(SecretKey::public_key).collect();
        let pk_refs: Vec<&PublicKey> = pks.iter().collect();
        let message = b"shared consensus message";
        let sigs: Vec<Signature> = sks.iter().map(|sk| sk.sign(message)).collect();
        let sig_refs: Vec<&Signature> = sigs.iter().collect();

        let agg = AggregateSignature::aggregate(&sig_refs).expect("aggregate");
        agg.fast_aggregate_verify(message, &pk_refs)
            .expect("fast aggregate verify");
    }

    /// Per whitepaper 3.4.3: aggregate-public-key construction allows
    /// a single verify call against the combined key.
    #[test]
    fn aggregate_public_key_verifies_against_aggregate_signature() {
        let sks: Vec<SecretKey> = (1u8..=4).map(sk_from_seed).collect();
        let pks: Vec<PublicKey> = sks.iter().map(SecretKey::public_key).collect();
        let pk_refs: Vec<&PublicKey> = pks.iter().collect();
        let message = b"common message";
        let sigs: Vec<Signature> = sks.iter().map(|sk| sk.sign(message)).collect();
        let sig_refs: Vec<&Signature> = sigs.iter().collect();

        let agg_pk = AggregatePublicKey::aggregate(&pk_refs)
            .expect("aggregate")
            .to_public_key();
        let agg_sig = AggregateSignature::aggregate(&sig_refs)
            .expect("aggregate")
            .to_signature();

        agg_pk.verify(message, &agg_sig).expect("verify");
    }

    // ---------- aggregation: different messages ----------

    /// Per whitepaper 3.4.3: aggregating heterogeneous signatures on
    /// different messages requires the multi-message verify variant.
    #[test]
    fn aggregate_verify_different_messages() {
        let sk_a = sk_from_seed(11);
        let sk_b = sk_from_seed(12);
        let sk_c = sk_from_seed(13);
        let pk_a = sk_a.public_key();
        let pk_b = sk_b.public_key();
        let pk_c = sk_c.public_key();
        let msg_a = b"message a";
        let msg_b = b"message b";
        let msg_c = b"message c";
        let sig_a = sk_a.sign(msg_a);
        let sig_b = sk_b.sign(msg_b);
        let sig_c = sk_c.sign(msg_c);

        let agg = AggregateSignature::aggregate(&[&sig_a, &sig_b, &sig_c]).expect("aggregate");
        let messages: &[&[u8]] = &[msg_a, msg_b, msg_c];
        let public_keys = [&pk_a, &pk_b, &pk_c];
        agg.aggregate_verify(messages, &public_keys)
            .expect("aggregate verify");
    }

    // ---------- aggregation: tampering ----------

    /// Per whitepaper 3.4.3: tampering with one signature in the
    /// aggregate causes verification to fail.
    #[test]
    fn aggregate_verify_rejects_tampered_member() {
        let sks: Vec<SecretKey> = (1u8..=3).map(sk_from_seed).collect();
        let pks: Vec<PublicKey> = sks.iter().map(SecretKey::public_key).collect();
        let pk_refs: Vec<&PublicKey> = pks.iter().collect();
        let message = b"victim message";

        let mut sigs: Vec<Signature> = sks.iter().map(|sk| sk.sign(message)).collect();
        // Tamper: replace one signature with a signature of a different message.
        sigs[1] = sks[1].sign(b"a different message entirely");
        let sig_refs: Vec<&Signature> = sigs.iter().collect();

        let agg = AggregateSignature::aggregate(&sig_refs).expect("aggregate");
        assert!(agg.fast_aggregate_verify(message, &pk_refs).is_err());
    }

    /// Tampering with the aggregate signature bytes after aggregation
    /// also rejects (either at parse time, when the mutated bytes
    /// don't form a valid G1 point, or at verify time).
    #[test]
    fn aggregate_verify_rejects_tampered_aggregate_bytes() {
        let sks: Vec<SecretKey> = (1u8..=3).map(sk_from_seed).collect();
        let pks: Vec<PublicKey> = sks.iter().map(SecretKey::public_key).collect();
        let pk_refs: Vec<&PublicKey> = pks.iter().collect();
        let message = b"victim message";
        let sigs: Vec<Signature> = sks.iter().map(|sk| sk.sign(message)).collect();
        let sig_refs: Vec<&Signature> = sigs.iter().collect();

        let agg_sig = AggregateSignature::aggregate(&sig_refs)
            .expect("aggregate")
            .to_signature();
        let mut sig_bytes = agg_sig.to_bytes();
        sig_bytes[10] ^= 0x01;
        let agg_pk = AggregatePublicKey::aggregate(&pk_refs)
            .expect("aggregate")
            .to_public_key();
        let result = Signature::from_bytes(&sig_bytes)
            .and_then(|tampered| agg_pk.verify(message, &tampered));
        assert!(result.is_err());
    }

    // ---------- empty-input rejection on aggregation ----------

    #[test]
    fn aggregate_empty_inputs_rejected() {
        assert!(AggregatePublicKey::aggregate(&[]).is_err());
        assert!(AggregateSignature::aggregate(&[]).is_err());
    }

    // ---------- length-mismatch rejection on aggregate_verify ----------

    #[test]
    fn aggregate_verify_length_mismatch_rejected() {
        let sk = sk_from_seed(1);
        let pk = sk.public_key();
        let sig = sk.sign(b"m");
        let agg = AggregateSignature::aggregate(&[&sig]).expect("aggregate");
        // Two messages, one key.
        let messages: &[&[u8]] = &[b"m", b"x"];
        let public_keys = [&pk];
        assert!(agg.aggregate_verify(messages, &public_keys).is_err());
    }

    // ---------- zeroize ----------

    #[test]
    fn secret_key_impls_zeroize_on_drop() {
        fn assert_impls<T: zeroize::ZeroizeOnDrop>() {}
        assert_impls::<SecretKey>();
    }

    /// Behavioural verification: after `.zeroize()`, the inner secret
    /// bytes are observably zero. See the comment block above the
    /// `Zeroize` impl in this file for the rationale on this
    /// verification approach.
    #[test]
    fn secret_key_zeroize_zeros_bytes() {
        use zeroize::Zeroize;
        let mut sk = sk_from_seed(1);
        let before = sk.to_bytes();
        assert_ne!(before, [0u8; SECRET_KEY_BYTES]);
        sk.zeroize();
        let after = sk.to_bytes();
        assert_eq!(after, [0u8; SECRET_KEY_BYTES]);
    }
}
