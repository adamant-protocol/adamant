//! Time-lock envelope encryption per whitepaper §3.8.1 + §3.8.8.
//!
//! Phase 7.5.4 ships the user-side and anchor-side wiring that
//! turns the §3.8.7 Wesolowski operations into a publicly-
//! verifiable time-lock encryption scheme:
//!
//! - [`derive_symmetric_key`] — derives the ChaCha20-Poly1305
//!   key from the VDF solution `h` via the
//!   [`crate::domain::TIME_LOCK_SYMMETRIC_KEY`] domain tag.
//! - [`encrypt_with_randomness`] — deterministic encryption
//!   given explicit randomness (32-byte seed for `g`, 12-byte
//!   nonce). Used by tests and by any caller that needs
//!   reproducibility.
//! - [`encrypt`] — convenience wrapper around
//!   `encrypt_with_randomness` that fills the randomness from a
//!   `CryptoRng`.
//! - [`decrypt`] — round-anchor-side decryption. Performs the
//!   `T`-sequential-squarings work and returns both the
//!   plaintext and a [`crate::vdf::TimeLockDecryption`] for
//!   publication.
//! - [`verify_decryption`] — public observer-side fast path.
//!   Verifies the anchor's evaluation proof in `O(log ℓ) ≈ 128`
//!   class-group operations and recovers the plaintext.
//!
//! # Spec basis
//!
//! Whitepaper §3.8.1 step 2 (Encryption) + §3.8.1 step 3
//! (Decryption) + §3.8.8 (Time-lock envelope encryption — the
//! Phase 7.5.4 amendment) jointly pin the byte recipe. The
//! wire types `TimeLockEnvelope` and `TimeLockDecryption` were
//! shipped at Phase 7.5.0.
//!
//! # Closes Phase 7.5
//!
//! Phase 7.5.4 is the final sub-arc in the §3.8 time-lock VDF
//! workstream. The pipeline is now complete end-to-end:
//!
//! 1. **Parameters** — `derive_discriminant` (Phase 7.5.2a) gives
//!    the chain-fixed `D` from the genesis seed.
//! 2. **Generator** — `hash_to_element` (Phase 7.5.2b) gives a
//!    canonical `g₀`.
//! 3. **Arithmetic** — `BinaryQuadraticForm` (Phase 7.5.1)
//!    provides class-group composition + squaring.
//! 4. **VDF operations** — `evaluate` / `prove` / `verify`
//!    (Phase 7.5.3) give the time-lock and its public-verifier
//!    short-cut.
//! 5. **Envelope** — `encrypt` / `decrypt` / `verify_decryption`
//!    (this module) thread the user-anchor-observer flow.
//!
//! Next: Phase 7.6 — threshold mempool + two-regime hysteresis
//! at the §8.4.2 viability boundary.

use rand_core::{CryptoRng, RngCore};

use crate::domain::TIME_LOCK_SYMMETRIC_KEY;
use crate::hash::shake_256_tagged;
use crate::symmetric::{Error as SymmetricError, Key, Nonce, NONCE_BYTES};
use crate::vdf::bqf::{BinaryQuadraticForm, BqfError};
use crate::vdf::setup::{hash_to_element, SetupError};
use crate::vdf::wesolowski::{self, ProveResult, WesolowskiError};
use crate::vdf::{
    ClassGroupElement, TimeLockDecryption, TimeLockEnvelope, TimeLockParameters, WesolowskiProof,
};

/// Bit-length of the leading coefficient `a` for `g` per
/// §3.8.8 step 1 + §3.8.6 canonical choice (`m = |D|/2`).
///
/// For the genesis discriminant width of 2048 bits, this gives
/// `m = 1024`. The constant is parameterised on the supplied
/// `TimeLockParameters.discriminant.len()`, not on this
/// constant directly; the constant exists as a reference for
/// the canonical-value documentation.
const CANONICAL_M_DIVISOR: u32 = 2;

/// Errors produced by the envelope flow.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EnvelopeError {
    /// `hash_to_element` or `derive_discriminant` raised an
    /// underlying setup error during encryption (e.g., the
    /// supplied parameters' discriminant width is not a
    /// multiple of 8 or below the §3.8.2 minimum).
    Setup(SetupError),

    /// `prove` raised an underlying Wesolowski error during
    /// encryption or decryption (e.g., a non-positive-definite
    /// operand surfacing through `g`).
    Wesolowski(WesolowskiError),

    /// A class-group element on the wire failed to decode under
    /// the chain-fixed discriminant.
    MalformedWireElement(BqfError),

    /// The envelope's ciphertext field is shorter than the
    /// 12-byte nonce prefix required by §3.8.8.
    CiphertextTooShort,

    /// ChaCha20-Poly1305 decryption failed (authentication tag
    /// mismatch, malformed ciphertext, etc.). Per §3.5 the
    /// underlying AEAD does not distinguish between failure
    /// modes; this variant rolls them all up.
    SymmetricDecryptionFailed,

    /// The anchor's evaluation proof did not verify against
    /// `(g, h, T)`. Returned by [`verify_decryption`] when the
    /// public-verification check fails.
    EvaluationProofInvalid,
}

impl core::fmt::Display for EnvelopeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Setup(err) => write!(f, "time-lock setup error: {err}"),
            Self::Wesolowski(err) => write!(f, "time-lock Wesolowski error: {err}"),
            Self::MalformedWireElement(err) => {
                write!(f, "time-lock wire-element decode failed: {err}")
            }
            Self::CiphertextTooShort => {
                f.write_str("time-lock envelope ciphertext shorter than 12-byte nonce prefix")
            }
            Self::SymmetricDecryptionFailed => {
                f.write_str("time-lock envelope ChaCha20-Poly1305 decryption failed")
            }
            Self::EvaluationProofInvalid => f.write_str(
                "time-lock decryption's Wesolowski evaluation proof failed verification",
            ),
        }
    }
}

impl std::error::Error for EnvelopeError {}

impl From<SetupError> for EnvelopeError {
    fn from(err: SetupError) -> Self {
        Self::Setup(err)
    }
}

impl From<WesolowskiError> for EnvelopeError {
    fn from(err: WesolowskiError) -> Self {
        Self::Wesolowski(err)
    }
}

impl From<BqfError> for EnvelopeError {
    fn from(err: BqfError) -> Self {
        Self::MalformedWireElement(err)
    }
}

impl From<SymmetricError> for EnvelopeError {
    fn from(_err: SymmetricError) -> Self {
        // Per §3.5 the AEAD does not distinguish failure modes;
        // collapse all variants into a single envelope error.
        Self::SymmetricDecryptionFailed
    }
}

/// Derives the ChaCha20-Poly1305 symmetric key from the VDF
/// solution `h` per whitepaper §3.8.8 "Symmetric-key derivation".
///
/// Composition:
///
/// ```text
/// key = shake_256_tagged(TIME_LOCK_SYMMETRIC_KEY, BCS(ClassGroupElement(h)), 32)
/// ```
///
/// Both the user-side encryption and the round-anchor-side
/// decryption derive the same key from the same `h`. The user
/// computes `h` by performing `T` sequential squarings of their
/// freshly-sampled `g` (per §3.8.1 step 2); the anchor recomputes
/// `h` by repeating the same `T` squarings on the published `g`
/// (per §3.8.1 step 3). Both flows arrive at the same `h` because
/// class-group squaring is deterministic.
///
/// # Panics
///
/// Cannot panic in practice: `BinaryQuadraticForm` encodes via
/// `to_class_group_element` is total over valid forms.
#[must_use]
pub fn derive_symmetric_key(h: &BinaryQuadraticForm) -> Key {
    let element = h.to_class_group_element();
    let mut bytes = [0u8; 32];
    shake_256_tagged(&TIME_LOCK_SYMMETRIC_KEY, &element.encoded, &mut bytes);
    Key::from_bytes(&bytes)
}

/// Computes the bit-length of the leading coefficient `a` used
/// when sampling the user's `g` via `hash_to_element`. The
/// §3.8.6 canonical choice is `m = |D| / 2`.
fn canonical_m_bits(params: &TimeLockParameters) -> u32 {
    let d_byte_len = params.discriminant.len();
    let d_bit_len = u32::try_from(d_byte_len * 8)
        .expect("discriminant byte length fits in u32 (≤ 2^29 bytes); 256-byte canonical width");
    d_bit_len / CANONICAL_M_DIVISOR
}

/// Encrypts a plaintext under the chain-fixed time-lock
/// parameters using explicit randomness per whitepaper §3.8.8
/// "Encryption (user-side)".
///
/// # Parameters
///
/// - `params` — the chain-fixed `TimeLockParameters {D, T}`.
/// - `plaintext` — the byte-string message to encrypt.
/// - `g_seed` — 32 bytes of randomness used to sample `g` via
///   `hash_to_element`.
/// - `nonce_bytes` — 12 bytes of randomness used as the
///   ChaCha20-Poly1305 nonce.
///
/// # Returns
///
/// On success, the constructed [`TimeLockEnvelope`] plus the
/// VDF solution `h` (returned alongside for caller convenience —
/// e.g., the sender can use `h` to derive the same key and
/// decrypt for themselves without re-running the VDF).
///
/// # Errors
///
/// Returns [`EnvelopeError::Setup`] if the parameters'
/// discriminant width is rejected by `hash_to_element` (below
/// minimum, non-byte-aligned, or `D ≢ 1 (mod 4)`).
/// Returns [`EnvelopeError::Wesolowski`] if `prove` rejects the
/// sampled `g` (vanishingly improbable for a valid discriminant).
///
/// # Panics
///
/// Cannot panic in practice. All internal operations are total
/// over the validated inputs.
pub fn encrypt_with_randomness(
    params: &TimeLockParameters,
    plaintext: &[u8],
    g_seed: &[u8; 32],
    nonce_bytes: &[u8; NONCE_BYTES],
) -> Result<(TimeLockEnvelope, BinaryQuadraticForm), EnvelopeError> {
    // Decode the chain-fixed discriminant from its parameter bytes.
    // The §3.8.6 derivation produces D = -d where d is the
    // big-endian magnitude. Reconstruct here.
    let d_magnitude = num_bigint::BigUint::from_bytes_be(&params.discriminant);
    let d_signed = num_bigint::BigInt::from_biguint(num_bigint::Sign::Plus, d_magnitude);
    let d = -d_signed;

    // Step 1: g ← hash_to_element(s_g, D, m_bits)
    let m_bits = canonical_m_bits(params);
    let g = hash_to_element(g_seed, &d, m_bits)?;

    // Step 2: (h, π) ← prove(g, T)
    let ProveResult { h, pi } = wesolowski::prove(&g, params.time_parameter_t)?;

    // Step 3: key ← derive_symmetric_key(h)
    let key = derive_symmetric_key(&h);

    // Step 4: body ← ChaCha20-Poly1305-Encrypt(key, nonce, m, aad=∅)
    let nonce = Nonce(*nonce_bytes);
    let body = key.encrypt(&nonce, plaintext, &[])?;

    // Step 5: assemble envelope.
    let mut ciphertext = Vec::with_capacity(NONCE_BYTES + body.len());
    ciphertext.extend_from_slice(nonce_bytes);
    ciphertext.extend_from_slice(&body);

    let envelope = TimeLockEnvelope {
        puzzle: g.to_class_group_element(),
        ciphertext,
        well_formedness_proof: WesolowskiProof {
            pi: pi.to_class_group_element(),
        },
    };

    Ok((envelope, h))
}

/// Encrypts a plaintext under the chain-fixed time-lock
/// parameters using fresh randomness drawn from a `CryptoRng`.
///
/// Convenience wrapper around [`encrypt_with_randomness`] for
/// callers that don't need explicit-randomness reproducibility.
///
/// # Errors
///
/// Same as [`encrypt_with_randomness`].
pub fn encrypt<R: CryptoRng + RngCore>(
    params: &TimeLockParameters,
    plaintext: &[u8],
    rng: &mut R,
) -> Result<(TimeLockEnvelope, BinaryQuadraticForm), EnvelopeError> {
    let mut g_seed = [0u8; 32];
    rng.fill_bytes(&mut g_seed);
    let mut nonce_bytes = [0u8; NONCE_BYTES];
    rng.fill_bytes(&mut nonce_bytes);
    encrypt_with_randomness(params, plaintext, &g_seed, &nonce_bytes)
}

/// Recovers the plaintext from a published envelope per
/// whitepaper §3.8.8 "Decryption (round-anchor-side)".
///
/// Performs the `T`-sequential-squarings work to derive `h`,
/// then derives the symmetric key, decrypts the ciphertext, and
/// returns the plaintext alongside a [`TimeLockDecryption`]
/// suitable for publication.
///
/// # Performance
///
/// `T` class-group squarings (the time-lock work) plus `O(T)`
/// additional class-group operations for `prove`'s
/// square-and-multiply, plus a sub-millisecond ChaCha20-Poly1305
/// decryption. For the genesis target `T ∈ [2M, 7.5M]`, this is
/// ~10-15 seconds on consensus-grade hardware per §3.8.2.
///
/// # Errors
///
/// - [`EnvelopeError::MalformedWireElement`] if `envelope.puzzle`
///   does not decode as a valid form of `params.discriminant`.
/// - [`EnvelopeError::CiphertextTooShort`] if `envelope.ciphertext`
///   is shorter than 12 bytes (the nonce prefix).
/// - [`EnvelopeError::Wesolowski`] if `prove` rejects the
///   recovered `g`.
/// - [`EnvelopeError::SymmetricDecryptionFailed`] if the
///   ChaCha20-Poly1305 authentication tag check fails.
///
/// # Optional `well_formedness_proof` cross-check
///
/// Per §3.8.8 the anchor MAY verify `envelope.well_formedness_proof`
/// against its recomputed `h` before publishing. This function
/// does NOT perform that check — callers that want it should
/// invoke [`wesolowski::verify`] on the recomputed `(g, h, T,
/// envelope.well_formedness_proof)` and reject the envelope on
/// failure. For honest users, the user's `well_formedness_proof`
/// is byte-identical to the anchor's `evaluation_proof` because
/// `prove` is deterministic.
///
/// # Panics
///
/// Cannot panic in practice. The `expect("…")` on the nonce slice
/// is guarded by an explicit length check earlier in the function.
pub fn decrypt(
    params: &TimeLockParameters,
    envelope: &TimeLockEnvelope,
) -> Result<(Vec<u8>, TimeLockDecryption), EnvelopeError> {
    if envelope.ciphertext.len() < NONCE_BYTES {
        return Err(EnvelopeError::CiphertextTooShort);
    }

    // Decode the chain-fixed discriminant.
    let d_magnitude = num_bigint::BigUint::from_bytes_be(&params.discriminant);
    let d_signed = num_bigint::BigInt::from_biguint(num_bigint::Sign::Plus, d_magnitude);
    let d = -d_signed;

    // Step 1: g from the wire.
    let g = BinaryQuadraticForm::from_class_group_element(&envelope.puzzle, &d)?;

    // Step 2: (h, π) ← prove(g, T) — the T-sequential-squarings work.
    let ProveResult { h, pi } = wesolowski::prove(&g, params.time_parameter_t)?;

    // Step 3: key ← derive_symmetric_key(h).
    let key = derive_symmetric_key(&h);

    // Step 4-6: parse nonce + body, decrypt.
    let nonce_slice: &[u8; NONCE_BYTES] = envelope.ciphertext[..NONCE_BYTES]
        .try_into()
        .expect("slice of length 12 fits the array; length checked above");
    let nonce = Nonce(*nonce_slice);
    let body = &envelope.ciphertext[NONCE_BYTES..];
    let plaintext = key.decrypt(&nonce, body, &[])?;

    // Step 7: package the anchor's decryption.
    let decryption = TimeLockDecryption {
        solution: h.to_class_group_element(),
        evaluation_proof: WesolowskiProof {
            pi: pi.to_class_group_element(),
        },
    };

    Ok((plaintext, decryption))
}

/// Public-verifier fast path per whitepaper §3.8.8 "Public
/// verification".
///
/// Given the envelope, the anchor's published decryption, and
/// the chain-fixed parameters, verifies the anchor's evaluation
/// proof and recovers the plaintext in `O(log ℓ) ≈ 128`
/// class-group operations plus a ChaCha20-Poly1305 decryption.
///
/// # Errors
///
/// - [`EnvelopeError::MalformedWireElement`] if any of `g`, `h`,
///   or `pi` does not decode under the chain-fixed discriminant.
/// - [`EnvelopeError::CiphertextTooShort`] as in [`decrypt`].
/// - [`EnvelopeError::EvaluationProofInvalid`] if
///   `wesolowski::verify(g, h, T, π)` returns `false` — the
///   anchor's claim that `h = g^(2^T)` does not check out.
/// - [`EnvelopeError::SymmetricDecryptionFailed`] if the AEAD
///   decryption fails (e.g., a different `h` than the user used,
///   indicating either a malformed envelope or a tampered
///   decryption).
///
/// # Panics
///
/// Cannot panic in practice. The `expect("…")` on the nonce slice
/// is guarded by an explicit length check earlier in the function.
pub fn verify_decryption(
    params: &TimeLockParameters,
    envelope: &TimeLockEnvelope,
    decryption: &TimeLockDecryption,
) -> Result<Vec<u8>, EnvelopeError> {
    if envelope.ciphertext.len() < NONCE_BYTES {
        return Err(EnvelopeError::CiphertextTooShort);
    }

    // Decode the chain-fixed discriminant.
    let d_magnitude = num_bigint::BigUint::from_bytes_be(&params.discriminant);
    let d_signed = num_bigint::BigInt::from_biguint(num_bigint::Sign::Plus, d_magnitude);
    let d = -d_signed;

    // Decode the wire elements.
    let g = BinaryQuadraticForm::from_class_group_element(&envelope.puzzle, &d)?;
    let h = BinaryQuadraticForm::from_class_group_element(&decryption.solution, &d)?;
    let pi = BinaryQuadraticForm::from_class_group_element(&decryption.evaluation_proof.pi, &d)?;

    // Step 4: verify(g, h, T, π).
    let ok = wesolowski::verify(&g, &h, params.time_parameter_t, &pi)?;
    if !ok {
        return Err(EnvelopeError::EvaluationProofInvalid);
    }

    // Step 5-8: derive key, parse nonce + body, decrypt.
    let key = derive_symmetric_key(&h);
    let nonce_slice: &[u8; NONCE_BYTES] = envelope.ciphertext[..NONCE_BYTES]
        .try_into()
        .expect("slice of length 12 fits the array; length checked above");
    let nonce = Nonce(*nonce_slice);
    let body = &envelope.ciphertext[NONCE_BYTES..];
    let plaintext = key.decrypt(&nonce, body, &[])?;
    Ok(plaintext)
}

// Silence unused-import warnings for the wire-type re-exports
// that are only used as type names in this module's API.
#[allow(dead_code)]
const _: fn() = || {
    let _: Option<ClassGroupElement> = None;
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vdf::setup::derive_discriminant;

    /// Returns a small chain-realistic `TimeLockParameters` for
    /// tests. The discriminant is 2048-bit (per §3.8.2) but `T`
    /// is small (5) so the encrypt/decrypt round-trip runs in
    /// seconds, not minutes.
    fn fixture_params() -> TimeLockParameters {
        let mut seed = [0u8; 32];
        for (i, byte) in seed.iter_mut().enumerate() {
            *byte = u8::try_from(i * 11 % 256).expect("mod 256 fits in u8");
        }
        let d = derive_discriminant(&seed, 2048).expect("derive_discriminant");
        let d_magnitude = (-d.clone()).to_biguint().expect("D < 0");
        TimeLockParameters {
            discriminant: d_magnitude.to_bytes_be(),
            time_parameter_t: 5,
        }
    }

    fn fixture_seed() -> [u8; 32] {
        let mut s = [0u8; 32];
        for (i, byte) in s.iter_mut().enumerate() {
            *byte = u8::try_from(i * 7 % 256).expect("mod 256 fits in u8");
        }
        s
    }

    fn fixture_nonce() -> [u8; NONCE_BYTES] {
        [0xAA; NONCE_BYTES]
    }

    #[test]
    fn derive_symmetric_key_is_deterministic() {
        let d = num_bigint::BigInt::from(-23);
        let h = hash_to_element(b"test", &d, 32).expect("hash_to_element");
        let key1 = derive_symmetric_key(&h);
        let key2 = derive_symmetric_key(&h);
        assert_eq!(key1.to_bytes(), key2.to_bytes());
    }

    #[test]
    fn derive_symmetric_key_distinct_h_distinct_key() {
        let d = num_bigint::BigInt::from(-23);
        let h1 = hash_to_element(b"seed-1", &d, 32).expect("hash_to_element");
        let h2 = hash_to_element(b"seed-2", &d, 32).expect("hash_to_element");
        // Two genuinely different h values.
        assert_ne!(h1, h2);
        let key1 = derive_symmetric_key(&h1);
        let key2 = derive_symmetric_key(&h2);
        assert_ne!(key1.to_bytes(), key2.to_bytes());
    }

    #[test]
    fn derive_symmetric_key_uses_time_lock_symmetric_key_tag() {
        // Pin the byte recipe: rederive via the documented composition
        // and confirm the helper agrees.
        let d = num_bigint::BigInt::from(-23);
        let h = hash_to_element(b"tag-test", &d, 32).expect("hash_to_element");
        let element = h.to_class_group_element();
        let mut expected = [0u8; 32];
        shake_256_tagged(&TIME_LOCK_SYMMETRIC_KEY, &element.encoded, &mut expected);
        let actual = derive_symmetric_key(&h);
        assert_eq!(actual.to_bytes(), expected);
    }

    #[test]
    fn encrypt_decrypt_round_trip() {
        let params = fixture_params();
        let plaintext = b"hello time-lock world".as_slice();
        let (envelope, _h) =
            encrypt_with_randomness(&params, plaintext, &fixture_seed(), &fixture_nonce())
                .expect("encrypt");
        let (recovered, _decryption) = decrypt(&params, &envelope).expect("decrypt");
        assert_eq!(recovered.as_slice(), plaintext);
    }

    #[test]
    fn encrypt_decrypt_round_trip_empty_plaintext() {
        let params = fixture_params();
        let (envelope, _h) =
            encrypt_with_randomness(&params, b"", &fixture_seed(), &fixture_nonce())
                .expect("encrypt");
        let (recovered, _decryption) = decrypt(&params, &envelope).expect("decrypt");
        assert_eq!(recovered.as_slice(), b"");
    }

    #[test]
    fn encrypt_decrypt_round_trip_large_plaintext() {
        let params = fixture_params();
        let plaintext: Vec<u8> = (0u8..255).cycle().take(8192).collect();
        let (envelope, _h) =
            encrypt_with_randomness(&params, &plaintext, &fixture_seed(), &fixture_nonce())
                .expect("encrypt");
        let (recovered, _decryption) = decrypt(&params, &envelope).expect("decrypt");
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn encrypt_is_deterministic_given_explicit_randomness() {
        let params = fixture_params();
        let plaintext = b"deterministic".as_slice();
        let (a, _h1) =
            encrypt_with_randomness(&params, plaintext, &fixture_seed(), &fixture_nonce())
                .expect("encrypt a");
        let (b, _h2) =
            encrypt_with_randomness(&params, plaintext, &fixture_seed(), &fixture_nonce())
                .expect("encrypt b");
        assert_eq!(a, b);
    }

    #[test]
    fn distinct_g_seeds_produce_distinct_envelopes() {
        let params = fixture_params();
        let mut seed_b = fixture_seed();
        seed_b[0] ^= 0x01;
        let (a, _) =
            encrypt_with_randomness(&params, b"x", &fixture_seed(), &fixture_nonce()).expect("a");
        let (b, _) = encrypt_with_randomness(&params, b"x", &seed_b, &fixture_nonce()).expect("b");
        assert_ne!(a.puzzle, b.puzzle);
    }

    #[test]
    fn distinct_nonces_produce_distinct_envelopes_but_same_puzzle() {
        let params = fixture_params();
        let mut nonce_b = fixture_nonce();
        nonce_b[0] ^= 0x01;
        let (a, _) =
            encrypt_with_randomness(&params, b"x", &fixture_seed(), &fixture_nonce()).expect("a");
        let (b, _) = encrypt_with_randomness(&params, b"x", &fixture_seed(), &nonce_b).expect("b");
        // Same g_seed → same g, but ciphertext differs in both the
        // 12-byte nonce prefix and the encrypted body.
        assert_eq!(a.puzzle, b.puzzle);
        assert_ne!(a.ciphertext, b.ciphertext);
    }

    #[test]
    fn encrypt_returns_h_consistent_with_decrypt() {
        // The h returned by encrypt should equal the h the anchor
        // recovers during decrypt. This is the property that lets
        // the original encryptor recover their key without
        // re-running the VDF.
        let params = fixture_params();
        let (envelope, h_user) =
            encrypt_with_randomness(&params, b"check", &fixture_seed(), &fixture_nonce())
                .expect("encrypt");
        let (_, decryption) = decrypt(&params, &envelope).expect("decrypt");
        let d_magnitude = num_bigint::BigUint::from_bytes_be(&params.discriminant);
        let d = -num_bigint::BigInt::from_biguint(num_bigint::Sign::Plus, d_magnitude);
        let h_anchor = BinaryQuadraticForm::from_class_group_element(&decryption.solution, &d)
            .expect("decode");
        assert_eq!(h_user, h_anchor);
    }

    // ---- verify_decryption ----

    #[test]
    fn verify_decryption_accepts_honest_decryption() {
        let params = fixture_params();
        let plaintext = b"honest plaintext".as_slice();
        let (envelope, _h) =
            encrypt_with_randomness(&params, plaintext, &fixture_seed(), &fixture_nonce())
                .expect("encrypt");
        let (_, decryption) = decrypt(&params, &envelope).expect("decrypt");
        let recovered =
            verify_decryption(&params, &envelope, &decryption).expect("verify_decryption");
        assert_eq!(recovered.as_slice(), plaintext);
    }

    #[test]
    fn verify_decryption_rejects_tampered_solution() {
        let params = fixture_params();
        let (envelope, _h) =
            encrypt_with_randomness(&params, b"x", &fixture_seed(), &fixture_nonce())
                .expect("encrypt");
        let (_, decryption) = decrypt(&params, &envelope).expect("decrypt");

        // Tamper with the solution: swap in a different element.
        let d_magnitude = num_bigint::BigUint::from_bytes_be(&params.discriminant);
        let d = -num_bigint::BigInt::from_biguint(num_bigint::Sign::Plus, d_magnitude);
        let fake_h = hash_to_element(b"tampered", &d, 32).expect("hash_to_element");
        let mut tampered = decryption.clone();
        tampered.solution = fake_h.to_class_group_element();

        let err = verify_decryption(&params, &envelope, &tampered)
            .expect_err("tampered solution must be rejected");
        // Either the proof check fails first (most likely, since the
        // proof was computed against the original h) or the symmetric
        // decryption fails (if by extreme coincidence the proof
        // happens to check out). Both are valid rejections.
        assert!(matches!(
            err,
            EnvelopeError::EvaluationProofInvalid | EnvelopeError::SymmetricDecryptionFailed
        ));
    }

    #[test]
    fn verify_decryption_rejects_tampered_evaluation_proof() {
        let params = fixture_params();
        let (envelope, _h) =
            encrypt_with_randomness(&params, b"x", &fixture_seed(), &fixture_nonce())
                .expect("encrypt");
        let (_, decryption) = decrypt(&params, &envelope).expect("decrypt");

        // Tamper with the evaluation proof.
        let d_magnitude = num_bigint::BigUint::from_bytes_be(&params.discriminant);
        let d = -num_bigint::BigInt::from_biguint(num_bigint::Sign::Plus, d_magnitude);
        let fake_pi = hash_to_element(b"fake-pi", &d, 32).expect("hash_to_element");
        let mut tampered = decryption.clone();
        tampered.evaluation_proof = WesolowskiProof {
            pi: fake_pi.to_class_group_element(),
        };

        let err = verify_decryption(&params, &envelope, &tampered)
            .expect_err("tampered proof must be rejected");
        assert_eq!(err, EnvelopeError::EvaluationProofInvalid);
    }

    #[test]
    fn verify_decryption_rejects_tampered_ciphertext() {
        let params = fixture_params();
        let (mut envelope, _h) =
            encrypt_with_randomness(&params, b"hello", &fixture_seed(), &fixture_nonce())
                .expect("encrypt");
        // Tamper with one byte of the ciphertext body (not the nonce
        // prefix). The auth tag will fail.
        let len = envelope.ciphertext.len();
        envelope.ciphertext[len - 1] ^= 0x01;
        let err = decrypt(&params, &envelope).expect_err("AEAD tag must reject tamper");
        assert_eq!(err, EnvelopeError::SymmetricDecryptionFailed);
    }

    #[test]
    fn decrypt_rejects_short_ciphertext() {
        let params = fixture_params();
        // Build an envelope with a 5-byte ciphertext — shorter than
        // the 12-byte nonce prefix.
        let (envelope, _h) =
            encrypt_with_randomness(&params, b"x", &fixture_seed(), &fixture_nonce())
                .expect("encrypt");
        let bad = TimeLockEnvelope {
            puzzle: envelope.puzzle.clone(),
            ciphertext: vec![0; 5],
            well_formedness_proof: envelope.well_formedness_proof.clone(),
        };
        let err = decrypt(&params, &bad).expect_err("must reject");
        assert_eq!(err, EnvelopeError::CiphertextTooShort);
    }

    #[test]
    fn verify_decryption_rejects_short_ciphertext() {
        let params = fixture_params();
        let (envelope, _h) =
            encrypt_with_randomness(&params, b"x", &fixture_seed(), &fixture_nonce())
                .expect("encrypt");
        let (_, decryption) = decrypt(&params, &envelope).expect("decrypt");
        let bad = TimeLockEnvelope {
            puzzle: envelope.puzzle,
            ciphertext: vec![0; 5],
            well_formedness_proof: envelope.well_formedness_proof,
        };
        let err = verify_decryption(&params, &bad, &decryption).expect_err("must reject");
        assert_eq!(err, EnvelopeError::CiphertextTooShort);
    }

    #[test]
    fn well_formedness_proof_byte_identical_to_evaluation_proof() {
        // Per §3.8.8 honest users compute prove(g, T) and use the
        // resulting π. The anchor independently computes prove(g, T)
        // during decrypt. Both should produce byte-identical proofs
        // since prove is deterministic in (g, T). This is the
        // optional-cross-check property.
        let params = fixture_params();
        let (envelope, _h) =
            encrypt_with_randomness(&params, b"check", &fixture_seed(), &fixture_nonce())
                .expect("encrypt");
        let (_, decryption) = decrypt(&params, &envelope).expect("decrypt");
        assert_eq!(
            envelope.well_formedness_proof.pi, decryption.evaluation_proof.pi,
            "user's well_formedness_proof must equal anchor's evaluation_proof"
        );
    }

    /// Headline integration check: encrypt → publish → anchor
    /// decrypts → publishes (m, decryption) → observer verifies +
    /// recovers m. The full §3.8 time-lock flow end-to-end.
    #[test]
    fn full_envelope_pipeline_end_to_end() {
        let params = fixture_params();
        let plaintext = b"the full pipeline of time-lock encryption".as_slice();

        // 1. User encrypts.
        let (envelope, h_user) =
            encrypt_with_randomness(&params, plaintext, &fixture_seed(), &fixture_nonce())
                .expect("user encrypt");

        // 2. Anchor decrypts (does T-sequential-squarings).
        let (m_anchor, decryption) = decrypt(&params, &envelope).expect("anchor decrypt");
        assert_eq!(m_anchor.as_slice(), plaintext);

        // 3. Observer verifies + recovers plaintext fast.
        let m_observer =
            verify_decryption(&params, &envelope, &decryption).expect("observer verify");
        assert_eq!(m_observer.as_slice(), plaintext);

        // Sanity: the h the user computed matches the h the anchor
        // recovered.
        let d_magnitude = num_bigint::BigUint::from_bytes_be(&params.discriminant);
        let d = -num_bigint::BigInt::from_biguint(num_bigint::Sign::Plus, d_magnitude);
        let h_anchor = BinaryQuadraticForm::from_class_group_element(&decryption.solution, &d)
            .expect("decode");
        assert_eq!(h_user, h_anchor);
    }

    #[test]
    fn encrypt_with_cryptorng_round_trips() {
        // The convenience `encrypt(rng)` path round-trips correctly.
        let params = fixture_params();
        let plaintext = b"with rng".as_slice();
        let mut rng = rand_core::OsRng;
        let (envelope, _h) = encrypt(&params, plaintext, &mut rng).expect("encrypt");
        let (recovered, _decryption) = decrypt(&params, &envelope).expect("decrypt");
        assert_eq!(recovered.as_slice(), plaintext);
    }

    #[test]
    fn envelope_error_display_messages_are_meaningful() {
        let variants = [
            EnvelopeError::CiphertextTooShort,
            EnvelopeError::SymmetricDecryptionFailed,
            EnvelopeError::EvaluationProofInvalid,
        ];
        let messages: Vec<String> = variants.iter().map(ToString::to_string).collect();
        for msg in &messages {
            assert!(!msg.is_empty());
        }
        for i in 0..messages.len() {
            for j in (i + 1)..messages.len() {
                assert_ne!(messages[i], messages[j]);
            }
        }
    }

    #[test]
    fn envelope_error_implements_std_error() {
        fn assert_err<E: std::error::Error>() {}
        assert_err::<EnvelopeError>();
    }
}
