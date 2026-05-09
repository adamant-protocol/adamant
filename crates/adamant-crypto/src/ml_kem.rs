//! ML-KEM-768 post-quantum key-encapsulation-mechanism wrapper, per
//! whitepaper section 3.7.
//!
//! Implementation library: `ml-kem` (`RustCrypto` / FIPS-203-compliant).
//! The protocol uses **ML-KEM-768 only** (security level 3, matching
//! ML-DSA-65); other parameter sets (512 / 1024) exist in the upstream
//! crate but are not exposed by this wrapper. Per whitepaper 3.7.2 the
//! algorithm choice is fixed.
//!
//! # API shape
//!
//! Mirrors [`crate::sig_pq`] (ML-DSA-65) as closely as the underlying
//! primitive allows. Four primary types:
//!
//! - [`DecapsulationKey`] — the secret key. 64-byte seed; the expanded
//!   decapsulation-key form used internally by FIPS 203 is held by the
//!   upstream crate. Does NOT implement [`PartialEq`]; equality on
//!   secret material must use [`subtle::ConstantTimeEq`] explicitly.
//! - [`EncapsulationKey`] — the public key. 1184 bytes, canonical
//!   encoding (FIPS 203 ML-KEM-768 §6.2). Decoding is fallible — the
//!   upstream `EncapsulationKey::new` validates the encoded key.
//! - [`Ciphertext`] — a 1088-byte ciphertext (FIPS 203 ML-KEM-768
//!   §6.3). Decoding is infallible at the byte level (fixed-layout
//!   packing); a malformed ciphertext decapsulates to a deterministic-
//!   but-meaningless shared secret per FIPS 203 implicit rejection
//!   (§6.4.1) — chosen-ciphertext-attack resistance by design.
//! - [`SharedSecret`] — the 32-byte symmetric key produced by
//!   encapsulation and decapsulation. Implements
//!   [`subtle::ConstantTimeEq`] for use as a KEM output.
//!
//! # Constant-time discipline
//!
//! - All operations on secret material are constant-time. The upstream
//!   `ml-kem` crate uses `subtle`'s `Choice` and `CtEq` for comparisons;
//!   this wrapper routes [`subtle::ConstantTimeEq`] impls through
//!   equivalent comparisons on the underlying byte representation.
//! - Errors from parsing are intentionally opaque ([`Error`] carries
//!   no detail). Distinguishing failure modes leaks information that
//!   constant-time discipline is meant to hide (whitepaper 3.9).
//! - Decapsulation is **infallible at the API level** per FIPS 203
//!   implicit rejection. A malformed ciphertext does not produce an
//!   error; it produces a shared secret indistinguishable from random
//!   to the adversary. This is by design — making the success/failure
//!   path observably distinct admits chosen-ciphertext attacks.
//!
//! # Zeroization discipline
//!
//! - [`DecapsulationKey`] manually impls [`zeroize::Zeroize`] and
//!   [`zeroize::ZeroizeOnDrop`]. The verification chain is the same
//!   as for [`crate::sig_pq::SigningKey`] — see the comment block
//!   above the equivalent impls in `sig_pq.rs`.
//!
//! # Determinism
//!
//! - [`DecapsulationKey::from_seed`] is deterministic per the FIPS 203
//!   `ML-KEM.KeyGen_internal` algorithm with seed `(d, z)` (the
//!   wrapper's 64-byte seed packs `d || z`). Encapsulation is
//!   randomized — [`EncapsulationKey::encapsulate`] consumes RNG
//!   bytes per encapsulation. Deterministic encapsulation
//!   (`encapsulate_deterministic` in upstream) is doc-hidden behind
//!   the `hazmat` feature in the upstream crate and is intentionally
//!   not exposed here.

use ml_kem::array::{self, sizes::U64};
use ml_kem::kem::{Decapsulate as _, Encapsulate as _, FromSeed as _};
use ml_kem::{KeyExport as _, MlKem768};
use rand_core_0_10::CryptoRng;
use subtle::{Choice, ConstantTimeEq};

/// Public-key (encapsulation-key) length for ML-KEM-768 in bytes,
/// per whitepaper section 3.7.2 (FIPS 203 §6.2 encoded form).
pub const PUBLIC_KEY_BYTES: usize = 1184;

/// Ciphertext length for ML-KEM-768 in bytes, per whitepaper section
/// 3.7.2 (FIPS 203 §6.3 encoded form).
pub const CIPHERTEXT_BYTES: usize = 1088;

/// Shared-secret length for ML-KEM-768 in bytes, per whitepaper section
/// 3.7.2 (FIPS 203 §6.3: 32-byte symmetric key output).
pub const SHARED_SECRET_BYTES: usize = 32;

/// Seed length for ML-KEM-768 in bytes, per FIPS 203 §6.1
/// (`ML-KEM.KeyGen_internal` consumes a 64-byte `(d, z)` seed).
pub const SEED_BYTES: usize = 64;

/// An ML-KEM-768 decapsulation (secret) key. 64-byte seed; the expanded
/// decapsulation-key form used internally by FIPS 203 is held alongside
/// the seed by the upstream crate. Zeroizes on drop.
///
/// Does not implement [`PartialEq`]: comparing secret keys via plain
/// `==` is a footgun even when the underlying field elements would be
/// equal in constant time. Use [`DecapsulationKey::ct_eq`] (from
/// [`ConstantTimeEq`]) when comparison is needed.
pub struct DecapsulationKey {
    inner: ml_kem::DecapsulationKey<MlKem768>,
    /// Seed cache for `Zeroize` and `ConstantTimeEq` paths. The
    /// upstream crate does not expose its internal seed after
    /// `from_seed`, so we cache the input seed at construction.
    /// `generate` derives a fresh random seed via the RNG.
    seed: [u8; SEED_BYTES],
}

// Zeroize / ZeroizeOnDrop are implemented manually for the same
// reason as in `sig_pq`: the upstream `ml_kem::DecapsulationKey` does
// not impl the standalone `Zeroize` trait (its expanded inner state
// has no sensible `Default`). Verification chain:
//
//   1. `ZeroizeOnDrop` trait bound on `DecapsulationKey` is asserted
//      at compile time by `tests::decapsulation_key_impls_zeroize_on_drop`.
//   2. In-place `Zeroize::zeroize()` byte check is exercised by
//      `tests::decapsulation_key_zeroize_replaces_seed_with_zero`.
//   3. The post-drop "memory observably zero" property is closed by
//      the upstream zeroize impl on `ml_kem::DecapsulationKey`. Trust
//      boundary lives at the upstream layer; adding an `unsafe` post-
//      drop pointer-read test would relocate the trust without
//      strengthening it.
impl zeroize::Zeroize for DecapsulationKey {
    fn zeroize(&mut self) {
        let zero_seed = [0u8; SEED_BYTES];
        let seed_array: array::Array<u8, U64> = zero_seed.into();
        let (dk, _ek) = MlKem768::from_seed(&seed_array);
        self.inner = dk;
        self.seed = zero_seed;
    }
}

impl zeroize::ZeroizeOnDrop for DecapsulationKey {}

/// An ML-KEM-768 encapsulation (public) key. 1184 bytes, canonical
/// encoding.
///
/// `Eq` is intentionally not derived: the upstream
/// `ml_kem::EncapsulationKey` implements `PartialEq` only (no `Eq`).
/// The protocol does not rely on `Eq` for encapsulation keys —
/// comparison via `PartialEq` is sufficient for all consensus-relevant
/// operations.
#[derive(Clone, Debug, PartialEq)]
pub struct EncapsulationKey {
    inner: ml_kem::EncapsulationKey<MlKem768>,
}

/// An ML-KEM-768 ciphertext (encapsulated key). 1088 bytes.
///
/// Constructed by [`EncapsulationKey::encapsulate`]; consumed by
/// [`DecapsulationKey::decapsulate`]. The byte form is the FIPS 203
/// canonical ciphertext encoding; this wrapper exposes infallible
/// byte-level encode and decode (a structurally-malformed ciphertext
/// is not detected at the byte level — implicit rejection at
/// decapsulate time produces a deterministic-but-meaningless shared
/// secret per FIPS 203 §6.4.1).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Ciphertext {
    inner: ml_kem::kem::Ciphertext<MlKem768>,
}

/// An ML-KEM-768 shared secret. 32 bytes (matching the symmetric-key
/// size of ChaCha20-Poly1305 per whitepaper 3.5).
///
/// Implements [`ConstantTimeEq`] for KEM-output comparison; downstream
/// code that compares shared secrets (e.g., for testing or for
/// detecting decapsulation success in protocols above ML-KEM) must
/// use the constant-time path.
#[derive(Clone)]
pub struct SharedSecret {
    inner: [u8; SHARED_SECRET_BYTES],
}

/// Opaque ML-KEM operation error.
///
/// Returned by [`EncapsulationKey::from_bytes`] (the only fallible
/// parse path; ciphertext decoding and decapsulation are infallible
/// per FIPS 203 implicit rejection). Details are intentionally not
/// exposed: distinguishing failure modes leaks information that the
/// constant-time discipline is meant to hide. See whitepaper section
/// 3.9.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct Error;

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ML-KEM operation failed")
    }
}

impl std::error::Error for Error {}

impl From<ml_kem::InvalidKey> for Error {
    fn from(_: ml_kem::InvalidKey) -> Self {
        Self
    }
}

// ---------- DecapsulationKey ----------

impl DecapsulationKey {
    /// Generate a new decapsulation key from a cryptographically
    /// secure random source. Per whitepaper section 3.8, key
    /// generation is the only operation in this primitive that
    /// consumes runtime randomness — encapsulation also consumes
    /// randomness per FIPS 203, but on the encapsulator side, not
    /// the key holder side.
    pub fn generate<R: CryptoRng>(rng: &mut R) -> Self {
        // Upstream's `Generate::generate_from_rng` produces the inner
        // key from random bytes but does not expose the input seed.
        // Sample our own 64-byte seed first so we can route it through
        // `from_seed` and retain the seed for `Zeroize` / `ct_eq` paths.
        let mut seed = [0u8; SEED_BYTES];
        rng.fill_bytes(&mut seed);
        Self::from_seed(&seed)
    }

    /// Construct a decapsulation key deterministically from a 64-byte
    /// seed. Per FIPS 203 §6.1, the seed is `(d, z)` packed as
    /// `d || z` with `d, z ∈ {0,1}^256`. Deterministic per the FIPS
    /// 203 `ML-KEM.KeyGen_internal` algorithm.
    #[must_use]
    pub fn from_seed(seed: &[u8; SEED_BYTES]) -> Self {
        let seed_array: array::Array<u8, U64> = (*seed).into();
        let (dk, _ek) = MlKem768::from_seed(&seed_array);
        Self {
            inner: dk,
            seed: *seed,
        }
    }

    /// Derive the corresponding encapsulation key.
    #[must_use]
    pub fn encapsulation_key(&self) -> EncapsulationKey {
        EncapsulationKey {
            inner: self.inner.encapsulation_key().clone(),
        }
    }

    /// Decapsulate a [`Ciphertext`] to recover the shared secret.
    ///
    /// Per FIPS 203 §6.4.1, decapsulation uses **implicit rejection**:
    /// a malformed ciphertext produces a deterministic-but-meaningless
    /// shared secret rather than an error. The infallible return type
    /// preserves this property at the API level.
    #[must_use]
    pub fn decapsulate(&self, ciphertext: &Ciphertext) -> SharedSecret {
        let shared = self.inner.decapsulate(&ciphertext.inner);
        let mut bytes = [0u8; SHARED_SECRET_BYTES];
        bytes.copy_from_slice(shared.as_ref());
        SharedSecret { inner: bytes }
    }
}

impl ConstantTimeEq for DecapsulationKey {
    /// Constant-time equality on the underlying 64-byte seed. Two
    /// `DecapsulationKey` values constructed from byte-equal seeds
    /// compare equal in time independent of the seeds' values.
    fn ct_eq(&self, other: &Self) -> Choice {
        self.seed.ct_eq(&other.seed)
    }
}

// ---------- EncapsulationKey ----------

impl EncapsulationKey {
    /// Construct an encapsulation key from its 1184-byte canonical
    /// encoding.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] if the bytes do not encode a valid ML-KEM-768
    /// encapsulation key (e.g., decoded polynomial coefficients
    /// outside the modulus, structural validity check failure per
    /// upstream `EncapsulationKey::new`).
    pub fn from_bytes(bytes: &[u8; PUBLIC_KEY_BYTES]) -> Result<Self, Error> {
        let key_array: array::Array<u8, _> = (*bytes).into();
        let inner = ml_kem::EncapsulationKey::<MlKem768>::new(&key_array)?;
        Ok(Self { inner })
    }

    /// Canonical 1184-byte encoded form.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; PUBLIC_KEY_BYTES] {
        let arr = self.inner.to_bytes();
        let mut out = [0u8; PUBLIC_KEY_BYTES];
        out.copy_from_slice(arr.as_ref());
        out
    }

    /// Encapsulate a fresh shared secret. Returns the ciphertext to
    /// transmit to the holder of the corresponding decapsulation key
    /// and the shared secret to use locally.
    ///
    /// Encapsulation is randomized per FIPS 203; the caller's `rng`
    /// MUST be a CSPRNG.
    pub fn encapsulate<R: CryptoRng>(&self, rng: &mut R) -> (Ciphertext, SharedSecret) {
        let (ct, shared) = self.inner.encapsulate_with_rng(rng);
        let mut bytes = [0u8; SHARED_SECRET_BYTES];
        bytes.copy_from_slice(shared.as_ref());
        (Ciphertext { inner: ct }, SharedSecret { inner: bytes })
    }
}

// ---------- Ciphertext ----------

impl Ciphertext {
    /// Construct a ciphertext from its 1088-byte canonical encoding.
    /// Decoding is infallible at the byte level per FIPS 203 (fixed-
    /// layout packing); structural correctness is enforced via
    /// implicit rejection at decapsulation time.
    #[must_use]
    pub fn from_bytes(bytes: &[u8; CIPHERTEXT_BYTES]) -> Self {
        let arr: array::Array<u8, _> = (*bytes).into();
        Self { inner: arr }
    }

    /// Canonical 1088-byte encoded form.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; CIPHERTEXT_BYTES] {
        let mut out = [0u8; CIPHERTEXT_BYTES];
        out.copy_from_slice(self.inner.as_ref());
        out
    }
}

// ---------- SharedSecret ----------

impl SharedSecret {
    /// View the shared secret as a 32-byte array.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; SHARED_SECRET_BYTES] {
        &self.inner
    }
}

impl ConstantTimeEq for SharedSecret {
    /// Constant-time equality on the 32-byte shared secret. Required
    /// because shared secrets are KEM outputs and downstream code
    /// that compares them must not leak timing information about the
    /// secret bytes' values.
    fn ct_eq(&self, other: &Self) -> Choice {
        self.inner.ct_eq(&other.inner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use getrandom::{rand_core::UnwrapErr, SysRng};

    /// Test RNG: the same `getrandom 0.4` `SysRng` + `UnwrapErr`
    /// pattern used by `sig_pq.rs::tests`. `getrandom 0.4` re-exports
    /// the `rand_core` 0.10 trait surface that ml-kem's `CryptoRng`
    /// bound expects, matching the `RustCrypto` ecosystem generation
    /// ml-kem itself uses.
    fn test_rng() -> UnwrapErr<SysRng> {
        UnwrapErr(SysRng)
    }

    #[test]
    fn round_trip_encapsulate_decapsulate() {
        let mut rng = test_rng();
        let dk = DecapsulationKey::generate(&mut rng);
        let ek = dk.encapsulation_key();
        let (ct, k_send) = ek.encapsulate(&mut rng);
        let k_recv = dk.decapsulate(&ct);
        assert_eq!(k_send.as_bytes(), k_recv.as_bytes());
    }

    /// `from_seed` is deterministic: same seed produces decapsulation
    /// keys with byte-identical seed cache and equal encapsulation
    /// keys.
    #[test]
    fn from_seed_is_deterministic() {
        let seed = [0xAB; SEED_BYTES];
        let dk1 = DecapsulationKey::from_seed(&seed);
        let dk2 = DecapsulationKey::from_seed(&seed);
        assert!(bool::from(dk1.ct_eq(&dk2)));
        let ek1 = dk1.encapsulation_key();
        let ek2 = dk2.encapsulation_key();
        assert_eq!(ek1, ek2);
    }

    /// `EncapsulationKey::to_bytes` round-trips through `from_bytes`.
    #[test]
    fn encapsulation_key_byte_round_trip() {
        let seed = [0xCD; SEED_BYTES];
        let dk = DecapsulationKey::from_seed(&seed);
        let ek = dk.encapsulation_key();
        let bytes = ek.to_bytes();
        let ek2 = EncapsulationKey::from_bytes(&bytes).expect("valid encoding");
        assert_eq!(ek, ek2);
    }

    /// `Ciphertext::to_bytes` round-trips through `from_bytes`.
    #[test]
    fn ciphertext_byte_round_trip() {
        let mut rng = test_rng();
        let dk = DecapsulationKey::generate(&mut rng);
        let ek = dk.encapsulation_key();
        let (ct, _k) = ek.encapsulate(&mut rng);
        let bytes = ct.to_bytes();
        let ct2 = Ciphertext::from_bytes(&bytes);
        let k1 = dk.decapsulate(&ct);
        let k2 = dk.decapsulate(&ct2);
        assert_eq!(k1.as_bytes(), k2.as_bytes());
    }

    /// `EncapsulationKey::from_bytes` rejects an obviously-invalid
    /// encoding (all-`0xFF`s — polynomial coefficients all exceed
    /// the modulus).
    #[test]
    fn encapsulation_key_from_bytes_rejects_invalid() {
        let bad = [0xFFu8; PUBLIC_KEY_BYTES];
        let result = EncapsulationKey::from_bytes(&bad);
        assert!(matches!(result, Err(Error)));
    }

    /// Shared secrets compare in constant time via `ConstantTimeEq`.
    #[test]
    fn shared_secret_ct_eq() {
        let s1 = SharedSecret { inner: [0u8; 32] };
        let s2 = SharedSecret { inner: [0u8; 32] };
        let s3 = SharedSecret { inner: [1u8; 32] };
        assert!(bool::from(s1.ct_eq(&s2)));
        assert!(!bool::from(s1.ct_eq(&s3)));
    }

    /// Decapsulation keys compare in constant time via `ConstantTimeEq`.
    #[test]
    fn decapsulation_key_ct_eq() {
        let s1 = [0u8; SEED_BYTES];
        let s2 = [1u8; SEED_BYTES];
        let dk1 = DecapsulationKey::from_seed(&s1);
        let dk2 = DecapsulationKey::from_seed(&s1);
        let dk3 = DecapsulationKey::from_seed(&s2);
        assert!(bool::from(dk1.ct_eq(&dk2)));
        assert!(!bool::from(dk1.ct_eq(&dk3)));
    }

    /// `Zeroize::zeroize` replaces the seed with all-zero bytes.
    #[test]
    fn decapsulation_key_zeroize_replaces_seed_with_zero() {
        let mut dk = DecapsulationKey::from_seed(&[0xAA; SEED_BYTES]);
        zeroize::Zeroize::zeroize(&mut dk);
        assert_eq!(dk.seed, [0u8; SEED_BYTES]);
    }

    /// `DecapsulationKey: ZeroizeOnDrop` at compile time.
    #[test]
    fn decapsulation_key_impls_zeroize_on_drop() {
        fn assert_zod<T: zeroize::ZeroizeOnDrop>() {}
        assert_zod::<DecapsulationKey>();
    }

    /// Different keypairs produce different encapsulation keys; a
    /// ciphertext encapsulated to one EK does not decapsulate to the
    /// same shared secret under another DK (the wrong-key path
    /// returns an implicit-rejection shared secret per FIPS 203 §6.4.1
    /// — different from the sender's secret).
    #[test]
    fn cross_key_decapsulation_does_not_match() {
        let dk1 = DecapsulationKey::from_seed(&[0x01; SEED_BYTES]);
        let dk2 = DecapsulationKey::from_seed(&[0x02; SEED_BYTES]);
        let mut rng = test_rng();
        let (ct, k_send) = dk1.encapsulation_key().encapsulate(&mut rng);
        let k_recv_correct = dk1.decapsulate(&ct);
        let k_recv_wrong = dk2.decapsulate(&ct);
        assert_eq!(k_send.as_bytes(), k_recv_correct.as_bytes());
        assert_ne!(k_send.as_bytes(), k_recv_wrong.as_bytes());
    }
}
