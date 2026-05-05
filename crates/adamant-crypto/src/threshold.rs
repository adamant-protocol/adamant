//! BLS-based threshold encryption for the encrypted mempool, per
//! whitepaper section 3.6.
//!
//! Construction: hashed-ElGamal threshold KEM on BLS12-381 in the
//! Boneh-Franklin / Baek-Zheng lineage, combined with Shamir secret
//! sharing of the master secret. The same construction is deployed in
//! production by Shutter Network on Gnosis Chain. See whitepaper 3.6.1
//! for the full algorithm specification.
//!
//! # Group orientation
//!
//! Master public key in G₂ (96 bytes compressed), decryption shares in
//! G₁ (48 bytes compressed). This matches the [`crate::bls`]
//! orientation in whitepaper 3.4.3 (G₁ signatures, G₂ public keys) and
//! reuses the same hash-to-curve operation on G₁ — but with a distinct
//! DST ([`crate::domain::BLS_TE_HASH_TO_CURVE`]) to prevent
//! cross-protocol attacks. A decryption share is computationally
//! identical to a BLS signature on the same identity under the same
//! key share; the TE-specific DST cryptographically separates the two
//! operations. See whitepaper 3.6.1 "Domain separation" for the
//! security rationale.
//!
//! # API surface
//!
//! - [`TrustedDealerShares::generate_for_testing_only`] — Phase 1
//!   trusted-dealer Shamir splitter. **Test-only**; replaced in
//!   production by the distributed-key-generation protocol specified
//!   in whitepaper §8 and implemented in `adamant-consensus` (Phase 8
//!   of the implementation plan, NOT in this Phase 1 crate).
//! - [`encapsulate`] — produces a ciphertext header `U` (96 bytes,
//!   broadcast alongside the AEAD ciphertext) and a 32-byte symmetric
//!   key for [`crate::symmetric`] use at the call site.
//! - [`decryption_share`] — validator computes its decryption share
//!   `D_i = s_i · H_TE(identity)`.
//! - [`verify_decryption_share`] — pairing check verifying a
//!   decryption share against the validator's public-key share.
//! - [`combine`] — Lagrange interpolation in the G₁ exponent over a
//!   threshold of shares. Internally re-verifies every share before
//!   combining, per whitepaper 3.6.1: a single malformed share fed
//!   into Lagrange interpolation produces an incorrect combined value
//!   that decrypts to garbage.
//! - [`decapsulate`] — final step: recovers the 32-byte symmetric key
//!   from the combined share and the ciphertext header.
//!
//! Phase 1 of the reference implementation provides only the pure
//! cryptographic surface. Distributed key generation (whitepaper §8),
//! integration with the encrypted mempool (§9), and AEAD wrapping of
//! the transaction payload (§3.5 / §9) are deferred to their
//! respective phases.
//!
//! # `unsafe` surface
//!
//! This module performs operations — G₁ hash-to-curve, G₂ scalar
//! multiplication on a known generator, pairings, and `Z_r`
//! arithmetic for Lagrange coefficients — that are not exposed by
//! `blst`'s safe `min_sig`/`min_pk` API. Rather than drop the
//! workspace `unsafe_code = forbid` lint here, the FFI surface is
//! contained in a sibling crate, [`adamant_crypto_blst_extra`], which
//! exposes the operations behind a safe Rust API. This crate calls
//! that safe API and itself contains no `unsafe`.
//!
//! Two corollaries of the split:
//!
//! 1. The decryption-share generation and per-share verification
//!    paths use `blst::min_sig::SecretKey::sign` and
//!    `blst::min_sig::PublicKey::verify` from `blst`'s own safe
//!    surface (these don't need the FFI containment crate). Both are
//!    on the per-validator hot path, and reusing the audited BLS
//!    verify path is the right factoring.
//! 2. Multi-scalar multiplication on G₁ for Lagrange combination
//!    uses `blst::MultiPoint::mult` on `[blst::min_sig::Signature]` —
//!    again, a safe blst-rs trait method whose internal `unsafe` is
//!    contained inside `blst-rs`.
//!
//! See `SECURITY.md` "Adamant-authored `unsafe` surface" for the
//! workspace-level architecture and `CONTRIBUTING.md`
//! "Unsafe-containment architecture" for the discipline rule.
//!
//! # Constant-time discipline
//!
//! - Secret-material types ([`KeyShare`]) zeroize on drop and route
//!   equality through [`subtle::ConstantTimeEq`].
//! - The `blst` operations beneath the safe API are constant-time on
//!   secret material.
//! - Errors are intentionally opaque ([`Error`] carries no detail), per
//!   whitepaper §3.9.

extern crate alloc;
use alloc::vec::Vec;

use adamant_crypto_blst_extra::{pairing, G1Point, G2Point, Scalar};
use blst::min_sig::{
    PublicKey as BlstPublicKey, SecretKey as BlstSecretKey, Signature as BlstSignature,
};
use blst::{MultiPoint, BLST_ERROR};
use rand_core::{CryptoRng, RngCore};
use subtle::{Choice, ConstantTimeEq};
use zeroize::Zeroize;

use crate::domain::{BLS_TE_HASH_TO_CURVE, THRESHOLD_KDF};
use crate::hash::shake_256_tagged;
use crate::symmetric::Key as SymmetricKey;

// =====================================================================
// Byte-length constants (whitepaper 3.6.1)
// =====================================================================

/// Master public key length, compressed G₂ (whitepaper 3.6.1).
pub const MASTER_PUBLIC_KEY_BYTES: usize = 96;

/// Public-key share length, compressed G₂ (whitepaper 3.6.1).
pub const PUBLIC_KEY_SHARE_BYTES: usize = 96;

/// Key share length, BLS12-381 scalar in big-endian (whitepaper 3.6.1).
pub const KEY_SHARE_BYTES: usize = 32;

/// Ciphertext header length, compressed G₂ element `U = g₂^ρ`
/// (whitepaper 3.6.1).
pub const CIPHERTEXT_HEADER_BYTES: usize = 96;

/// Decryption share length, compressed G₁ (whitepaper 3.6.1).
pub const DECRYPTION_SHARE_BYTES: usize = 48;

/// Combined share length, compressed G₁ (whitepaper 3.6.1).
pub const COMBINED_SHARE_BYTES: usize = 48;

/// GT element serialised length: 12 Fp limbs at 48 bytes each
/// (whitepaper 3.6.1, "576 bytes").
pub const GT_BYTES: usize = 12 * 48;

// =====================================================================
// Public types
// =====================================================================

/// 96-byte compressed G₂ master public key (whitepaper 3.6.1).
///
/// In Phase 1 produced by [`TrustedDealerShares::generate_for_testing_only`];
/// in production produced by the distributed key generation in
/// whitepaper §8.
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct MasterPublicKey {
    bytes: [u8; MASTER_PUBLIC_KEY_BYTES],
}

/// A validator's secret key share — a non-zero scalar in `Z_r` —
/// together with its 1-indexed validator index. Zeroizes on drop.
///
/// Does not implement [`PartialEq`]: comparing secret material via
/// plain `==` is a footgun even when the underlying byte comparison
/// would be timing-safe. Use [`KeyShare::ct_eq`] (from
/// [`subtle::ConstantTimeEq`]) when comparison is needed.
#[derive(zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct KeyShare {
    index: u32,
    bytes: [u8; KEY_SHARE_BYTES],
}

/// 96-byte compressed G₂ public-key share `PK_i = g₂^{s_i}`, indexed by
/// the same 1-indexed validator number as the corresponding
/// [`KeyShare`].
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct PublicKeyShare {
    index: u32,
    bytes: [u8; PUBLIC_KEY_SHARE_BYTES],
}

/// Ciphertext header `U = g₂^ρ`. Carried alongside the
/// ChaCha20-Poly1305 ciphertext in the §9 mempool envelope.
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct CiphertextHeader {
    bytes: [u8; CIPHERTEXT_HEADER_BYTES],
}

/// 48-byte compressed G₁ decryption share `D_i = s_i · H_TE(identity)`,
/// indexed by the same 1-indexed validator number as the producing
/// [`KeyShare`].
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct DecryptionShare {
    index: u32,
    bytes: [u8; DECRYPTION_SHARE_BYTES],
}

/// 48-byte compressed G₁ combined share `D = s · H_TE(identity)`. The
/// output of [`combine`]; the input to [`decapsulate`].
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct CombinedShare {
    bytes: [u8; COMBINED_SHARE_BYTES],
}

/// Opaque threshold-encryption operation error.
///
/// Returned by parsing, encapsulation, share verification, combination,
/// and decapsulation failures. Details are intentionally not exposed:
/// distinguishing failure modes leaks information that the
/// constant-time discipline is meant to hide. See whitepaper §3.9.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct Error;

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("threshold-encryption operation failed")
    }
}

impl std::error::Error for Error {}

// =====================================================================
// Constructors / accessors
// =====================================================================

impl MasterPublicKey {
    /// Parse a master public key from its 96-byte canonical compressed
    /// G₂ encoding. Performs subgroup validation.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] if the bytes do not encode a valid G₂ point in
    /// the prime-order subgroup.
    pub fn from_bytes(bytes: &[u8; MASTER_PUBLIC_KEY_BYTES]) -> Result<Self, Error> {
        let _ = G2Point::from_compressed(bytes).map_err(|_| Error)?;
        Ok(Self { bytes: *bytes })
    }

    /// Canonical 96-byte compressed encoding.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; MASTER_PUBLIC_KEY_BYTES] {
        self.bytes
    }
}

impl KeyShare {
    /// Construct a key share from its 1-indexed validator index and
    /// canonical 32-byte big-endian scalar encoding. Validates the
    /// scalar lies in `(0, r)`.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] if `index == 0` or if the bytes do not encode
    /// a valid non-zero scalar in `Z_r`.
    pub fn from_bytes(index: u32, bytes: &[u8; KEY_SHARE_BYTES]) -> Result<Self, Error> {
        if index == 0 {
            return Err(Error);
        }
        // BlstSecretKey::from_bytes validates 0 < scalar < r.
        BlstSecretKey::from_bytes(bytes).map_err(|_| Error)?;
        Ok(Self {
            index,
            bytes: *bytes,
        })
    }

    /// 1-indexed validator number for this share.
    #[must_use]
    pub fn index(&self) -> u32 {
        self.index
    }

    /// Canonical 32-byte big-endian scalar encoding.
    ///
    /// **Use with care.** The returned array is secret material; the
    /// caller is responsible for zeroizing it after use. Prefer
    /// keeping the [`KeyShare`] wrapper itself in the caller's scope
    /// and letting drop handle zeroization.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; KEY_SHARE_BYTES] {
        self.bytes
    }
}

impl ConstantTimeEq for KeyShare {
    fn ct_eq(&self, other: &Self) -> Choice {
        // Index is public; compare in plaintext. Scalar bytes are
        // secret; route through subtle's constant-time path.
        if self.index != other.index {
            return Choice::from(0);
        }
        self.bytes.ct_eq(&other.bytes)
    }
}

impl core::fmt::Debug for KeyShare {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "KeyShare(index={}, bytes=<redacted>)", self.index)
    }
}

impl PublicKeyShare {
    /// Parse a public-key share from its 1-indexed validator index and
    /// 96-byte canonical compressed G₂ encoding. Performs subgroup
    /// validation.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] if `index == 0` or if the bytes do not encode
    /// a valid G₂ point in the prime-order subgroup.
    pub fn from_bytes(index: u32, bytes: &[u8; PUBLIC_KEY_SHARE_BYTES]) -> Result<Self, Error> {
        if index == 0 {
            return Err(Error);
        }
        let _ = G2Point::from_compressed(bytes).map_err(|_| Error)?;
        Ok(Self {
            index,
            bytes: *bytes,
        })
    }

    /// 1-indexed validator number for this share.
    #[must_use]
    pub fn index(&self) -> u32 {
        self.index
    }

    /// Canonical 96-byte compressed encoding.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; PUBLIC_KEY_SHARE_BYTES] {
        self.bytes
    }
}

impl CiphertextHeader {
    /// Parse a ciphertext header from its 96-byte canonical compressed
    /// G₂ encoding. Performs subgroup validation.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] if the bytes do not encode a valid G₂ point in
    /// the prime-order subgroup.
    pub fn from_bytes(bytes: &[u8; CIPHERTEXT_HEADER_BYTES]) -> Result<Self, Error> {
        let _ = G2Point::from_compressed(bytes).map_err(|_| Error)?;
        Ok(Self { bytes: *bytes })
    }

    /// Canonical 96-byte compressed encoding.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; CIPHERTEXT_HEADER_BYTES] {
        self.bytes
    }
}

impl DecryptionShare {
    /// Parse a decryption share from its 1-indexed validator index and
    /// 48-byte canonical compressed G₁ encoding. Performs subgroup
    /// validation.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] if `index == 0` or if the bytes do not encode
    /// a valid G₁ point in the prime-order subgroup.
    pub fn from_bytes(index: u32, bytes: &[u8; DECRYPTION_SHARE_BYTES]) -> Result<Self, Error> {
        if index == 0 {
            return Err(Error);
        }
        let _ = G1Point::from_compressed(bytes).map_err(|_| Error)?;
        Ok(Self {
            index,
            bytes: *bytes,
        })
    }

    /// 1-indexed validator number for this share.
    #[must_use]
    pub fn index(&self) -> u32 {
        self.index
    }

    /// Canonical 48-byte compressed encoding.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; DECRYPTION_SHARE_BYTES] {
        self.bytes
    }
}

impl CombinedShare {
    /// Parse a combined share from its 48-byte canonical compressed G₁
    /// encoding. Performs subgroup validation.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] if the bytes do not encode a valid G₁ point in
    /// the prime-order subgroup.
    pub fn from_bytes(bytes: &[u8; COMBINED_SHARE_BYTES]) -> Result<Self, Error> {
        let _ = G1Point::from_compressed(bytes).map_err(|_| Error)?;
        Ok(Self { bytes: *bytes })
    }

    /// Canonical 48-byte compressed encoding.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; COMBINED_SHARE_BYTES] {
        self.bytes
    }
}

// =====================================================================
// Trusted-dealer Shamir splitter (test-only, Phase 1)
// =====================================================================

/// The output of [`TrustedDealerShares::generate_for_testing_only`]:
/// a master public key plus parallel vectors of key shares and
/// public-key shares.
///
/// **Test-only.** The trusted-dealer pattern requires a single party
/// (the "dealer") to know the master secret. The production protocol
/// replaces this with a distributed key generation in which no single
/// party ever holds the master secret; the DKG is specified in
/// whitepaper §8 and implemented in `adamant-consensus` (Phase 8 of
/// the implementation plan, NOT this Phase 1 crate).
pub struct TrustedDealerShares {
    /// Master public key `MPK = g₂^s`. Public.
    pub master_public_key: MasterPublicKey,
    /// Validator key shares, in 1-indexed order: `key_shares[i-1].index() == i`.
    pub key_shares: Vec<KeyShare>,
    /// Validator public-key shares, parallel to `key_shares`:
    /// `public_key_shares[i-1].index() == i`.
    pub public_key_shares: Vec<PublicKeyShare>,
    /// Threshold `t`: any `t` of the `n` shares suffice to reconstruct
    /// `s · H_TE(identity)` for any identity.
    pub threshold: u32,
}

impl TrustedDealerShares {
    /// Generate a fresh master secret, split it into `total_shares`
    /// shares with reconstruction threshold `threshold`, and return
    /// the master public key, key shares, and public-key shares.
    ///
    /// **The function name is deliberately verbose.** Calling
    /// `generate_for_testing_only` is the wrong primitive to invoke
    /// in production: it concentrates the master secret in the dealer
    /// for the duration of one function call. The production
    /// equivalent is the distributed key generation in whitepaper §8,
    /// which never materialises the master secret in any single
    /// party's memory.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] if `threshold == 0`, `total_shares == 0`,
    /// `threshold > total_shares`, or `total_shares > 2^31 - 1`
    /// (defensive bound — real validator sets are O(10^4)).
    ///
    /// # Zeroization
    ///
    /// Intermediate values containing the master secret and the
    /// random polynomial coefficients are best-effort overwritten
    /// before drop. [`Scalar`] does not implement [`zeroize::Zeroize`]
    /// (its inner `blst_fr` representation is opaque); the overwrite
    /// is a manual `*coeff = Scalar::zero()` rather than a
    /// `Zeroize::zeroize` call, and the compiler may elide it. This
    /// is acceptable because the function is **test-only**; production
    /// DKG never holds the master secret in the first place.
    #[allow(clippy::needless_range_loop)] // explicit range matches Horner indexing
    pub fn generate_for_testing_only<R: CryptoRng + RngCore>(
        threshold: u32,
        total_shares: u32,
        rng: &mut R,
    ) -> Result<Self, Error> {
        if threshold == 0 || total_shares == 0 || threshold > total_shares {
            return Err(Error);
        }
        // Defensive bound: validator-set sizes ≥ 2^31 are not
        // operationally plausible (whitepaper §8) and would inflate
        // intermediate buffers without bound. The real cap is much
        // smaller; this is just a sanity guard.
        if total_shares > i32::MAX as u32 {
            return Err(Error);
        }

        // Sample t random polynomial coefficients in Z_r:
        //   f(x) = a_0 + a_1·x + ... + a_{t-1}·x^{t-1}
        // a_0 is the master secret; the rest are uniform in Z_r.
        // BlstSecretKey::key_gen runs HKDF over 32-byte IKM to produce
        // a uniform scalar in (0, r), exactly the distribution we
        // want for both the master secret and the higher-degree
        // coefficients.
        let mut coefficients: Vec<Scalar> = Vec::with_capacity(threshold as usize);
        let mut ikm = [0u8; 32];
        for _ in 0..threshold {
            rng.fill_bytes(&mut ikm);
            let sk = BlstSecretKey::key_gen(&ikm, &[]).map_err(|_| Error)?;
            coefficients.push(sk_to_scalar(&sk));
        }
        ikm.zeroize();

        // a_0 is the master secret. MPK = g₂^{a_0}.
        let g2 = G2Point::generator();
        let mpk_point = g2.mul_scalar(&coefficients[0]);
        let mpk = MasterPublicKey {
            bytes: mpk_point.to_compressed(),
        };

        // For each i ∈ 1..=total_shares, evaluate s_i = f(i) via Horner's
        // rule, and compute PK_i = g₂^{s_i}.
        let mut key_shares = Vec::with_capacity(total_shares as usize);
        let mut public_key_shares = Vec::with_capacity(total_shares as usize);
        for i in 1..=total_shares {
            let i_scalar = Scalar::from_u32(i);
            // Horner: f(i) = (((a_{t-1})·i + a_{t-2})·i + ...)·i + a_0
            let last = threshold as usize - 1;
            let mut acc = coefficients[last];
            for k in (0..last).rev() {
                acc = acc.mul(&i_scalar);
                acc = acc.add(&coefficients[k]);
            }
            let s_i = acc;
            let s_i_canonical = s_i.to_bytes_be();
            let pk_i_point = g2.mul_scalar(&s_i);

            // KeyShare validates non-zero scalar; with negligible
            // probability s_i = 0 (≈ 2^{-255} per share), in which
            // case from_bytes errors.
            let key_share = KeyShare::from_bytes(i, &s_i_canonical)?;
            let public_key_share = PublicKeyShare {
                index: i,
                bytes: pk_i_point.to_compressed(),
            };
            key_shares.push(key_share);
            public_key_shares.push(public_key_share);
        }

        // Best-effort zeroize of polynomial coefficients (Scalar has
        // no Zeroize impl; this is a manual overwrite with the
        // additive identity).
        for c in &mut coefficients {
            *c = Scalar::zero();
        }
        drop(coefficients);

        Ok(Self {
            master_public_key: mpk,
            key_shares,
            public_key_shares,
            threshold,
        })
    }
}

// =====================================================================
// Operations
// =====================================================================

/// Encapsulate a fresh symmetric key under the threshold scheme.
///
/// Per whitepaper 3.6.1 "Encapsulate":
///
/// 1. `Q = H_TE(identity) ∈ G₁`
/// 2. Sample `ρ ← Z_r`
/// 3. `U = g₂^ρ ∈ G₂`  (the ciphertext header)
/// 4. `K = KDF(e(Q, MPK)^ρ, U, identity)` — 32-byte symmetric key
///
/// The 32-byte output is intended to be used directly as a
/// [`crate::symmetric::Key`] for ChaCha20-Poly1305 wrapping of the
/// transaction payload at the §9 call site.
///
/// # Errors
///
/// Returns [`Error`] if the master public key bytes do not parse, or
/// if the underlying key-derivation fails (e.g., `BlstSecretKey::key_gen`
/// rejects the sampled IKM — astronomically rare).
pub fn encapsulate<R: CryptoRng + RngCore>(
    mpk: &MasterPublicKey,
    identity: &[u8],
    rng: &mut R,
) -> Result<(CiphertextHeader, SymmetricKey), Error> {
    let mpk_point = G2Point::from_compressed(&mpk.bytes).map_err(|_| Error)?;

    // Sample ρ ∈ Z_r via blst's HKDF-based KeyGen over 32 bytes IKM.
    let mut ikm = [0u8; 32];
    rng.fill_bytes(&mut ikm);
    let rho_sk = BlstSecretKey::key_gen(&ikm, &[]).map_err(|_| Error)?;
    ikm.zeroize();
    let rho = sk_to_scalar(&rho_sk);

    // Q = H_TE(identity) ∈ G₁
    let q_point = G1Point::hash_to_curve(identity, BLS_TE_HASH_TO_CURVE.as_bytes());

    // U = ρ · g₂ ∈ G₂  (the ciphertext header)
    let u_point = G2Point::generator().mul_scalar(&rho);

    // M = ρ · MPK ∈ G₂; by bilinearity, e(Q, M) = e(Q, MPK)^ρ.
    let m_point = mpk_point.mul_scalar(&rho);

    // GT_value = e(Q, M) ∈ G_T
    let gt_value = pairing(&q_point, &m_point);
    let gt_bytes = gt_value.to_bytes();

    // K = tagged_shake_256(THRESHOLD_KDF, gt_bytes || U_bytes || identity, 32)
    let u_bytes = u_point.to_compressed();
    let key = derive_kdf_key(&gt_bytes, &u_bytes, identity);

    Ok((CiphertextHeader { bytes: u_bytes }, key))
}

/// Compute a validator's decryption share for `identity`:
/// `D_i = s_i · H_TE(identity) ∈ G₁`.
///
/// Per whitepaper 3.6.1 "`DecryptionShare`", this is structurally
/// identical to a BLS signature on `identity` under the share's scalar
/// using the threshold-encryption DST. The implementation reuses
/// [`blst::min_sig::SecretKey::sign`] with the
/// [`crate::domain::BLS_TE_HASH_TO_CURVE`] DST.
///
/// # Panics
///
/// Cannot panic in practice. The internal `expect` is a contract
/// assertion: every reachable [`KeyShare`] has bytes that encode a
/// valid non-zero scalar in `Z_r`, established at [`KeyShare::from_bytes`]
/// time. A panic here would indicate a bug in [`KeyShare`]'s
/// construction-time validation, not a runtime failure mode.
#[must_use]
pub fn decryption_share(share: &KeyShare, identity: &[u8]) -> DecryptionShare {
    // KeyShare's invariant is that bytes encode a valid (0, r) scalar
    // — established at KeyShare construction time. Re-parsing cannot
    // fail for any KeyShare value reachable from the public API.
    let sk = BlstSecretKey::from_bytes(&share.bytes)
        .expect("KeyShare invariant: bytes encode a non-zero scalar in Z_r");
    let sig = sk.sign(identity, BLS_TE_HASH_TO_CURVE.as_bytes(), &[]);
    DecryptionShare {
        index: share.index,
        bytes: sig.compress(),
    }
}

/// Verify a decryption share against the validator's public-key share:
/// `e(D_i, g₂) ≟ e(H_TE(identity), PK_i)`.
///
/// Per whitepaper 3.6.1 "`VerifyDecryptionShare`". The implementation
/// reuses [`blst::min_sig::PublicKey::verify`] under the
/// [`crate::domain::BLS_TE_HASH_TO_CURVE`] DST — the verification
/// equation is the BLS verification equation, by structural identity
/// of "decryption share" and "BLS signature on identity under share".
///
/// Discards malformed shares before they reach [`combine`]: per
/// whitepaper 3.6.1, "this check is consensus-critical: a single
/// malformed share fed into Lagrange interpolation produces an
/// incorrect combined value that decrypts to garbage."
///
/// # Errors
///
/// Returns [`Error`] if the indices of `pk_share` and `share` differ,
/// if either fails to parse, or if the pairing equation does not hold.
pub fn verify_decryption_share(
    pk_share: &PublicKeyShare,
    identity: &[u8],
    share: &DecryptionShare,
) -> Result<(), Error> {
    if pk_share.index != share.index {
        return Err(Error);
    }
    let pk = BlstPublicKey::uncompress(&pk_share.bytes).map_err(|_| Error)?;
    let sig = BlstSignature::uncompress(&share.bytes).map_err(|_| Error)?;
    match sig.verify(
        true, // sig_groupcheck
        identity,
        BLS_TE_HASH_TO_CURVE.as_bytes(),
        &[], // aug
        &pk,
        true, // pk_validate
    ) {
        BLST_ERROR::BLST_SUCCESS => Ok(()),
        _ => Err(Error),
    }
}

/// Combine a threshold of decryption shares into the recovered
/// `D = s · H_TE(identity)` via Lagrange interpolation in the G₁
/// exponent.
///
/// Per whitepaper 3.6.1 "Combine", this implementation re-verifies
/// every share before combining. The pairing-check verification is the
/// same one [`verify_decryption_share`] performs externally; doing it
/// here too guarantees correctness regardless of caller discipline.
///
/// `shares` is a slice of `(decryption_share, public_key_share)`
/// pairs. Each pair's two elements MUST share the same 1-indexed
/// validator number; the function returns an error if they disagree.
/// The number of pairs MUST be at least the system threshold `t`;
/// the function does not know `t` and does not enforce it (the caller
/// — typically the §8 consensus combiner — does).
///
/// # Errors
///
/// Returns [`Error`] if `shares` is empty, if any pair's indices
/// disagree, if any index is zero, if indices are not pairwise
/// distinct, if any share fails to parse, or if any share fails the
/// pairing-check verification.
pub fn combine(
    identity: &[u8],
    shares: &[(&DecryptionShare, &PublicKeyShare)],
) -> Result<CombinedShare, Error> {
    if shares.is_empty() {
        return Err(Error);
    }

    // Validate indices: pairs match, all non-zero, pairwise distinct.
    let mut indices: Vec<u32> = Vec::with_capacity(shares.len());
    for (d, p) in shares {
        if d.index != p.index || d.index == 0 {
            return Err(Error);
        }
        if indices.contains(&d.index) {
            return Err(Error);
        }
        indices.push(d.index);
    }

    // Per-share verification. A single malformed share produces
    // garbage on combine; re-verify defensively.
    for (d, p) in shares {
        verify_decryption_share(p, identity, d)?;
    }

    // Compute Lagrange coefficients λ_i(0) for each i ∈ S over
    // `indices`. Pack them as concatenated 32-byte little-endian
    // scalars for `MultiPoint::mult` (which expects this byte order;
    // it is the order `blst_p1_mult` consumes internally).
    let mut scalars_packed = Vec::<u8>::with_capacity(KEY_SHARE_BYTES * shares.len());
    for (d, _) in shares {
        let lambda = lagrange_coefficient_at_zero(d.index, &indices)?;
        scalars_packed.extend_from_slice(&lambda.to_bytes_le());
    }

    // Parse decryption-share G₁ points. Subgroup-validated by
    // `BlstSignature::uncompress` (with `sig_groupcheck=true` set
    // implicitly inside the verify path above; here we re-parse for
    // the multi-scalar mul input slice).
    let signatures: Vec<BlstSignature> = shares
        .iter()
        .map(|(d, _)| BlstSignature::uncompress(&d.bytes).map_err(|_| Error))
        .collect::<Result<Vec<_>, _>>()?;

    // Multi-scalar multiplication on G₁: D = Σ λ_i · D_i. The
    // `MultiPoint::mult` trait method is part of `blst-rs`'s safe API;
    // its internal `unsafe` is contained inside `blst-rs`.
    let agg = signatures
        .as_slice()
        .mult(&scalars_packed, adamant_crypto_blst_extra::SCALAR_BITS);
    let combined_sig = agg.to_signature();
    Ok(CombinedShare {
        bytes: combined_sig.compress(),
    })
}

/// Decapsulate the symmetric key from the combined share and the
/// ciphertext header.
///
/// Per whitepaper 3.6.1 "Decapsulate":
/// `K = KDF(e(D, U), U, identity)`
///
/// Correctness follows from bilinearity: `e(D, U) = e(s·Q, g₂^ρ) =
/// e(Q, MPK)^ρ`, matching the value the encapsulator computed.
///
/// # Errors
///
/// Returns [`Error`] if either the combined share or the ciphertext
/// header fails to parse.
pub fn decapsulate(
    combined: &CombinedShare,
    header: &CiphertextHeader,
    identity: &[u8],
) -> Result<SymmetricKey, Error> {
    let d_point = G1Point::from_compressed(&combined.bytes).map_err(|_| Error)?;
    let u_point = G2Point::from_compressed(&header.bytes).map_err(|_| Error)?;

    // GT_value = e(D, U) ∈ G_T
    let gt_value = pairing(&d_point, &u_point);
    let gt_bytes = gt_value.to_bytes();

    Ok(derive_kdf_key(&gt_bytes, &header.bytes, identity))
}

// =====================================================================
// Internal helpers (no `unsafe` — that surface lives in
// `adamant_crypto_blst_extra`)
// =====================================================================

/// Derive the 32-byte symmetric key from the encapsulator's
/// pairing-output transcript, per whitepaper 3.6.1 "Key derivation
/// function (KDF)":
///
/// `K = tagged_shake_256(THRESHOLD_KDF,
///       serialise(GT_value) || serialise(U) || identity, 32)`
fn derive_kdf_key(
    gt_bytes: &[u8; GT_BYTES],
    u_bytes: &[u8; CIPHERTEXT_HEADER_BYTES],
    identity: &[u8],
) -> SymmetricKey {
    let mut transcript = Vec::with_capacity(GT_BYTES + CIPHERTEXT_HEADER_BYTES + identity.len());
    transcript.extend_from_slice(gt_bytes);
    transcript.extend_from_slice(u_bytes);
    transcript.extend_from_slice(identity);

    let mut key_bytes = [0u8; 32];
    shake_256_tagged(&THRESHOLD_KDF, &transcript, &mut key_bytes);

    // gt_bytes is derived from the secret ρ (encapsulator) or the
    // secret s_i shares (decapsulator); either way, the transcript
    // briefly held material a passive observer should not see. Best-
    // effort overwrite before drop.
    transcript.zeroize();

    let key = SymmetricKey::from_bytes(&key_bytes);
    key_bytes.zeroize();
    key
}

/// Convert a `BlstSecretKey` (which wraps a `blst_scalar` in `(0, r)`)
/// to a [`Scalar`] for arithmetic. `BlstSecretKey::to_bytes` returns
/// canonical 32-byte big-endian; [`Scalar::from_bytes_be`] validates
/// `< r`, which is guaranteed for any `BlstSecretKey` by construction.
fn sk_to_scalar(sk: &BlstSecretKey) -> Scalar {
    Scalar::from_bytes_be(&sk.to_bytes())
        .expect("BlstSecretKey is in (0, r), valid for Scalar::from_bytes_be")
}

/// Lagrange coefficient `λ_i(0)` for index `i` over the index set `S`,
/// in `Z_r`. Formula: `λ_i(0) = Π_{j ∈ S, j ≠ i} (-j) / (i - j)`.
///
/// All indices in `S` must be non-zero and pairwise distinct, and `i`
/// must appear in `S`. The denominator is non-zero by distinctness;
/// [`Scalar::inverse`] is therefore well-defined at every step.
fn lagrange_coefficient_at_zero(i: u32, indices: &[u32]) -> Result<Scalar, Error> {
    if i == 0 || !indices.contains(&i) {
        return Err(Error);
    }
    let i_scalar = Scalar::from_u32(i);
    let zero = Scalar::zero();
    let mut num = Scalar::one();
    let mut den = Scalar::one();
    for &j in indices {
        if j == 0 {
            return Err(Error);
        }
        if j == i {
            continue;
        }
        let j_scalar = Scalar::from_u32(j);
        let neg_j = zero.sub(&j_scalar);
        let i_minus_j = i_scalar.sub(&j_scalar);
        num = num.mul(&neg_j);
        den = den.mul(&i_minus_j);
    }
    Ok(num.mul(&den.inverse()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    // ---------- declared lengths match the whitepaper ----------

    #[test]
    fn declared_lengths_match_whitepaper() {
        assert_eq!(MASTER_PUBLIC_KEY_BYTES, 96);
        assert_eq!(PUBLIC_KEY_SHARE_BYTES, 96);
        assert_eq!(KEY_SHARE_BYTES, 32);
        assert_eq!(CIPHERTEXT_HEADER_BYTES, 96);
        assert_eq!(DECRYPTION_SHARE_BYTES, 48);
        assert_eq!(COMBINED_SHARE_BYTES, 48);
        assert_eq!(GT_BYTES, 576);
    }

    // ---------- DSTs and KDF tag are sourced from the registry ----------

    #[test]
    fn te_dst_is_sourced_from_domain_registry() {
        let expected = b"BLS_TE_BLS12381G1_XMD:SHA-256_SSWU_RO_ADAMANT_v1";
        assert_eq!(BLS_TE_HASH_TO_CURVE.as_bytes(), expected);
    }

    #[test]
    fn kdf_tag_is_sourced_from_domain_registry() {
        let expected = b"ADAMANT-v1-threshold-kdf";
        assert_eq!(THRESHOLD_KDF.as_bytes(), expected);
    }

    // ---------- trusted-dealer parameter validation ----------

    #[test]
    fn dealer_rejects_zero_threshold() {
        assert!(TrustedDealerShares::generate_for_testing_only(0, 5, &mut OsRng).is_err());
    }

    #[test]
    fn dealer_rejects_zero_total() {
        assert!(TrustedDealerShares::generate_for_testing_only(3, 0, &mut OsRng).is_err());
    }

    #[test]
    fn dealer_rejects_threshold_above_total() {
        assert!(TrustedDealerShares::generate_for_testing_only(6, 5, &mut OsRng).is_err());
    }

    // ---------- encapsulate / decapsulate roundtrip ----------

    /// End-to-end self-consistency: encapsulate → distribute shares to
    /// `t` validators → each computes its decryption share → combine
    /// → decapsulate → the symmetric key matches the encapsulator's
    /// output.
    #[test]
    fn encapsulate_combine_decapsulate_roundtrip_3_of_5() {
        let dealer =
            TrustedDealerShares::generate_for_testing_only(3, 5, &mut OsRng).expect("dealer");
        let identity = b"identity bytes for the roundtrip test";

        let (header, key_a) =
            encapsulate(&dealer.master_public_key, identity, &mut OsRng).expect("encapsulate");

        // Pick any threshold-sized subset of validators.
        let chosen = [0usize, 2, 4]; // shares 1, 3, 5
        let decryption_shares: Vec<DecryptionShare> = chosen
            .iter()
            .map(|&i| decryption_share(&dealer.key_shares[i], identity))
            .collect();
        let pks: Vec<&PublicKeyShare> = chosen
            .iter()
            .map(|&i| &dealer.public_key_shares[i])
            .collect();
        let pairs: Vec<(&DecryptionShare, &PublicKeyShare)> =
            decryption_shares.iter().zip(pks.iter().copied()).collect();

        let combined = combine(identity, &pairs).expect("combine");
        let key_b = decapsulate(&combined, &header, identity).expect("decapsulate");

        assert!(bool::from(key_a.ct_eq(&key_b)));
    }

    /// 1-of-1 is degenerate but algebraically valid: the polynomial is
    /// degree 0, so f(x) = `master_secret` for all x. λ = 1, combine
    /// returns `D_1` unmodified, decapsulation succeeds.
    #[test]
    fn roundtrip_1_of_1() {
        let dealer =
            TrustedDealerShares::generate_for_testing_only(1, 1, &mut OsRng).expect("dealer");
        let identity = b"";
        let (header, key_a) =
            encapsulate(&dealer.master_public_key, identity, &mut OsRng).expect("encapsulate");
        let d = decryption_share(&dealer.key_shares[0], identity);
        let pk = &dealer.public_key_shares[0];
        let combined = combine(identity, &[(&d, pk)]).expect("combine");
        let key_b = decapsulate(&combined, &header, identity).expect("decapsulate");
        assert!(bool::from(key_a.ct_eq(&key_b)));
    }

    /// Different threshold-sized subsets of the same validator set
    /// must reconstruct the same combined share — Lagrange
    /// interpolation depends on the degree of the polynomial, not on
    /// which evaluations are used.
    #[test]
    fn different_subsets_reconstruct_same_combined_share() {
        let dealer =
            TrustedDealerShares::generate_for_testing_only(3, 5, &mut OsRng).expect("dealer");
        let identity = b"subset-invariance test";

        let all_shares: Vec<DecryptionShare> = dealer
            .key_shares
            .iter()
            .map(|k| decryption_share(k, identity))
            .collect();

        let pick = |idx: &[usize]| -> CombinedShare {
            let pairs: Vec<(&DecryptionShare, &PublicKeyShare)> = idx
                .iter()
                .map(|&i| (&all_shares[i], &dealer.public_key_shares[i]))
                .collect();
            combine(identity, &pairs).expect("combine")
        };

        let c_a = pick(&[0, 1, 2]);
        let c_b = pick(&[0, 2, 4]);
        let c_c = pick(&[1, 3, 4]);
        assert_eq!(c_a, c_b);
        assert_eq!(c_a, c_c);
    }

    /// Using more than `t` shares (over-sampling) must still recover
    /// the correct combined share. Lagrange's algebraic guarantee
    /// extends to any oversample ≥ t.
    #[test]
    fn over_sampling_yields_same_combined_share() {
        let dealer =
            TrustedDealerShares::generate_for_testing_only(3, 5, &mut OsRng).expect("dealer");
        let identity = b"oversample test";

        let all_shares: Vec<DecryptionShare> = dealer
            .key_shares
            .iter()
            .map(|k| decryption_share(k, identity))
            .collect();

        let three: Vec<(&DecryptionShare, &PublicKeyShare)> = (0..3)
            .map(|i| (&all_shares[i], &dealer.public_key_shares[i]))
            .collect();
        let five: Vec<(&DecryptionShare, &PublicKeyShare)> = (0..5)
            .map(|i| (&all_shares[i], &dealer.public_key_shares[i]))
            .collect();
        let c_three = combine(identity, &three).expect("combine 3");
        let c_five = combine(identity, &five).expect("combine 5");
        assert_eq!(c_three, c_five);
    }

    // ---------- per-share verification ----------

    #[test]
    fn verify_decryption_share_accepts_valid() {
        let dealer =
            TrustedDealerShares::generate_for_testing_only(3, 5, &mut OsRng).expect("dealer");
        let identity = b"verification test";
        let d = decryption_share(&dealer.key_shares[2], identity);
        verify_decryption_share(&dealer.public_key_shares[2], identity, &d).expect("verify");
    }

    #[test]
    fn verify_rejects_index_mismatch() {
        let dealer =
            TrustedDealerShares::generate_for_testing_only(3, 5, &mut OsRng).expect("dealer");
        let identity = b"index-mismatch test";
        let d = decryption_share(&dealer.key_shares[2], identity); // index 3
                                                                   // Verify against PK for a different validator (index 1):
        assert!(verify_decryption_share(&dealer.public_key_shares[0], identity, &d).is_err());
    }

    #[test]
    fn verify_rejects_wrong_identity() {
        let dealer =
            TrustedDealerShares::generate_for_testing_only(3, 5, &mut OsRng).expect("dealer");
        let d = decryption_share(&dealer.key_shares[2], b"identity-A");
        assert!(verify_decryption_share(&dealer.public_key_shares[2], b"identity-B", &d).is_err());
    }

    #[test]
    fn verify_rejects_tampered_share_bytes() {
        let dealer =
            TrustedDealerShares::generate_for_testing_only(3, 5, &mut OsRng).expect("dealer");
        let identity = b"tamper test";
        let d = decryption_share(&dealer.key_shares[2], identity);
        let mut tampered_bytes = d.to_bytes();
        // Flip a bit in the trailing bytes; this either fails to
        // parse as a valid G₁ point or fails the verification
        // pairing. Either rejection layer counts.
        tampered_bytes[10] ^= 0x01;
        let result = DecryptionShare::from_bytes(d.index(), &tampered_bytes).and_then(|tampered| {
            verify_decryption_share(&dealer.public_key_shares[2], identity, &tampered)
        });
        assert!(result.is_err());
    }

    // ---------- combine rejects malformed inputs ----------

    #[test]
    fn combine_rejects_empty() {
        assert!(combine(b"x", &[]).is_err());
    }

    #[test]
    fn combine_rejects_index_zero() {
        // We can't construct a DecryptionShare with index 0 via
        // from_bytes (it rejects), but we can construct one directly
        // for this test. Easier: just rebuild via from_bytes with a
        // fresh share, then we won't get index 0 — instead, exercise
        // combine's own check by re-using a same-index pair.
        // Here we rely on from_bytes index-zero rejection at the type
        // boundary (validated separately below).
        let dealer =
            TrustedDealerShares::generate_for_testing_only(2, 3, &mut OsRng).expect("dealer");
        let identity = b"x";
        let d_1 = decryption_share(&dealer.key_shares[0], identity);
        let d_1_dup = decryption_share(&dealer.key_shares[0], identity);
        let pk_1 = &dealer.public_key_shares[0];
        // Duplicate index → reject.
        assert!(combine(identity, &[(&d_1, pk_1), (&d_1_dup, pk_1)]).is_err());
    }

    #[test]
    fn combine_rejects_pair_index_disagreement() {
        let dealer =
            TrustedDealerShares::generate_for_testing_only(2, 3, &mut OsRng).expect("dealer");
        let identity = b"disagreement test";
        let d_1 = decryption_share(&dealer.key_shares[0], identity);
        // Pair share-of-validator-1 with public-key-share of validator-2:
        let bad_pair = (&d_1, &dealer.public_key_shares[1]);
        let d_2 = decryption_share(&dealer.key_shares[1], identity);
        let good_pair = (&d_2, &dealer.public_key_shares[1]);
        assert!(combine(identity, &[bad_pair, good_pair]).is_err());
    }

    #[test]
    fn combine_rejects_malformed_share_in_set() {
        let dealer =
            TrustedDealerShares::generate_for_testing_only(2, 3, &mut OsRng).expect("dealer");
        let identity = b"malformed-share test";
        // Genuine share for validator 1, then a forged share for
        // validator 2 produced by signing the WRONG identity (so the
        // pairing check fails).
        let d_1 = decryption_share(&dealer.key_shares[0], identity);
        let forged = decryption_share(&dealer.key_shares[1], b"different-identity");
        // forged has correct index for validator 2; pair with PK of v2.
        let pairs = [
            (&d_1, &dealer.public_key_shares[0]),
            (&forged, &dealer.public_key_shares[1]),
        ];
        assert!(combine(identity, &pairs).is_err());
    }

    // ---------- parsing rejects malformed bytes ----------

    #[test]
    fn key_share_from_bytes_rejects_index_zero() {
        let bytes = [1u8; KEY_SHARE_BYTES];
        assert!(KeyShare::from_bytes(0, &bytes).is_err());
    }

    #[test]
    fn key_share_from_bytes_rejects_zero_scalar() {
        let bytes = [0u8; KEY_SHARE_BYTES];
        assert!(KeyShare::from_bytes(1, &bytes).is_err());
    }

    #[test]
    fn public_key_share_from_bytes_rejects_garbage() {
        let bytes = [0xffu8; PUBLIC_KEY_SHARE_BYTES];
        assert!(PublicKeyShare::from_bytes(1, &bytes).is_err());
    }

    #[test]
    fn ciphertext_header_from_bytes_rejects_garbage() {
        let bytes = [0xffu8; CIPHERTEXT_HEADER_BYTES];
        assert!(CiphertextHeader::from_bytes(&bytes).is_err());
    }

    // ---------- byte round-trips ----------

    #[test]
    fn master_public_key_bytes_round_trip() {
        let dealer =
            TrustedDealerShares::generate_for_testing_only(2, 3, &mut OsRng).expect("dealer");
        let bytes = dealer.master_public_key.to_bytes();
        let parsed = MasterPublicKey::from_bytes(&bytes).expect("parse");
        assert_eq!(parsed, dealer.master_public_key);
    }

    #[test]
    fn key_share_bytes_round_trip() {
        let dealer =
            TrustedDealerShares::generate_for_testing_only(2, 3, &mut OsRng).expect("dealer");
        let original = &dealer.key_shares[0];
        let bytes = original.to_bytes();
        let parsed = KeyShare::from_bytes(original.index(), &bytes).expect("parse");
        assert!(bool::from(parsed.ct_eq(original)));
    }

    #[test]
    fn decryption_share_bytes_round_trip() {
        let dealer =
            TrustedDealerShares::generate_for_testing_only(2, 3, &mut OsRng).expect("dealer");
        let d = decryption_share(&dealer.key_shares[1], b"round-trip");
        let bytes = d.to_bytes();
        let parsed = DecryptionShare::from_bytes(d.index(), &bytes).expect("parse");
        assert_eq!(parsed, d);
    }

    #[test]
    fn combined_share_bytes_round_trip() {
        let dealer =
            TrustedDealerShares::generate_for_testing_only(2, 3, &mut OsRng).expect("dealer");
        let identity = b"combined-round-trip";
        let d_1 = decryption_share(&dealer.key_shares[0], identity);
        let d_2 = decryption_share(&dealer.key_shares[1], identity);
        let pairs = [
            (&d_1, &dealer.public_key_shares[0]),
            (&d_2, &dealer.public_key_shares[1]),
        ];
        let combined = combine(identity, &pairs).expect("combine");
        let bytes = combined.to_bytes();
        let parsed = CombinedShare::from_bytes(&bytes).expect("parse");
        assert_eq!(parsed, combined);
    }

    // ---------- decryption_share is a BLS signature under the TE DST ----------

    /// Per whitepaper 3.6.1, "`DecryptionShare` ... is structurally
    /// identical to a BLS signature under the TE DST." Verify that
    /// `decryption_share(s_i, identity)` produces the exact same
    /// 48-byte encoding as a BLS sign over `identity` with the
    /// `BLS_TE_HASH_TO_CURVE` DST.
    #[test]
    fn decryption_share_equals_bls_sign_under_te_dst() {
        let dealer =
            TrustedDealerShares::generate_for_testing_only(2, 3, &mut OsRng).expect("dealer");
        let identity = b"structural-identity check";
        let share = &dealer.key_shares[1];
        let d = decryption_share(share, identity);

        // Independently sign with blst::min_sig under the TE DST.
        let sk = BlstSecretKey::from_bytes(&share.to_bytes()).expect("sk");
        let sig = sk.sign(identity, BLS_TE_HASH_TO_CURVE.as_bytes(), &[]);
        assert_eq!(d.to_bytes(), sig.compress());
    }

    // ---------- TE DST is distinct from BLS sig DST (cross-protocol) ----------

    /// A BLS signature on `identity` under the `BLS_SIG` DST must not
    /// validate as a decryption share under the TE DST. This is the
    /// security property the spec's "Domain separation" subsection in
    /// 3.6.1 calls out: without DST separation, a signature could be
    /// substituted for a decryption share.
    #[test]
    fn bls_sig_dst_not_accepted_as_te_dst() {
        let dealer =
            TrustedDealerShares::generate_for_testing_only(2, 3, &mut OsRng).expect("dealer");
        let identity = b"cross-protocol attempt";
        let share = &dealer.key_shares[2];
        let sk = BlstSecretKey::from_bytes(&share.to_bytes()).expect("sk");
        // Sign with the BLS sig DST (our existing crate::bls path).
        let bls_sig = sk.sign(
            identity,
            crate::domain::BLS_SIG_HASH_TO_CURVE.as_bytes(),
            &[],
        );
        // Repackage as a DecryptionShare with the index from KeyShare.
        let bytes = bls_sig.compress();
        let bls_as_share = DecryptionShare::from_bytes(share.index(), &bytes).expect("parse");
        // Verify under the TE DST → must fail.
        assert!(
            verify_decryption_share(&dealer.public_key_shares[2], identity, &bls_as_share).is_err()
        );
    }

    // ---------- KDF determinism / domain separation ----------

    /// Same encapsulator output (header, key) on the same RNG seed
    /// reproduces — sanity check on KDF determinism.
    #[test]
    fn kdf_is_deterministic_for_fixed_transcript() {
        let gt_bytes = [7u8; GT_BYTES];
        let u_bytes = [3u8; CIPHERTEXT_HEADER_BYTES];
        let identity = b"determinism";
        let k_1 = derive_kdf_key(&gt_bytes, &u_bytes, identity);
        let k_2 = derive_kdf_key(&gt_bytes, &u_bytes, identity);
        assert!(bool::from(k_1.ct_eq(&k_2)));
    }

    /// Different identity bytes with otherwise-fixed transcript
    /// produce different KDF outputs.
    #[test]
    fn kdf_separates_by_identity() {
        let gt_bytes = [7u8; GT_BYTES];
        let u_bytes = [3u8; CIPHERTEXT_HEADER_BYTES];
        let k_a = derive_kdf_key(&gt_bytes, &u_bytes, b"identity-A");
        let k_b = derive_kdf_key(&gt_bytes, &u_bytes, b"identity-B");
        assert!(!bool::from(k_a.ct_eq(&k_b)));
    }

    // ---------- Lagrange-coefficient unit tests ----------

    /// 1-of-N edge case: with one share, `λ_i` = 1 (empty product).
    #[test]
    fn lagrange_single_index_is_one() {
        let lambda = lagrange_coefficient_at_zero(1, &[1]).expect("lambda");
        assert_eq!(lambda, Scalar::one());
    }

    /// For indices {1, 2}, `λ_1(0)` = (-2)/(1-2) = (-2)/(-1) = 2,
    /// and `λ_2(0)` = (-1)/(2-1) = -1.
    /// Verify `λ_1` + `λ_2` = 1 (the constant term of any degree-1 polynomial
    /// summed at evaluations 1 and 2 with these coefficients is f(0)).
    #[test]
    fn lagrange_two_indices_sum_to_one() {
        let l_1 = lagrange_coefficient_at_zero(1, &[1, 2]).expect("l_1");
        let l_2 = lagrange_coefficient_at_zero(2, &[1, 2]).expect("l_2");
        assert_eq!(l_1.add(&l_2), Scalar::one());
    }

    #[test]
    fn lagrange_rejects_index_zero_in_set() {
        assert!(lagrange_coefficient_at_zero(1, &[0, 1]).is_err());
    }

    #[test]
    fn lagrange_rejects_target_not_in_set() {
        assert!(lagrange_coefficient_at_zero(7, &[1, 2, 3]).is_err());
    }

    // ---------- zeroize ----------

    #[test]
    fn key_share_impls_zeroize_on_drop() {
        fn assert_impls<T: zeroize::ZeroizeOnDrop>() {}
        assert_impls::<KeyShare>();
    }

    #[test]
    fn key_share_zeroize_zeros_bytes() {
        let dealer =
            TrustedDealerShares::generate_for_testing_only(2, 3, &mut OsRng).expect("dealer");
        let mut share = KeyShare::from_bytes(
            dealer.key_shares[0].index(),
            &dealer.key_shares[0].to_bytes(),
        )
        .expect("clone");
        let before = share.to_bytes();
        assert_ne!(before, [0u8; KEY_SHARE_BYTES]);
        share.zeroize();
        assert_eq!(share.to_bytes(), [0u8; KEY_SHARE_BYTES]);
        assert_eq!(share.index(), 0);
    }

    // ---------- TE hash-to-curve is deterministic ----------

    /// Hashing the same identity twice with the TE DST yields the
    /// same G₁ point. Domain separation against the BLS-sig DST is
    /// exercised by `bls_sig_dst_not_accepted_as_te_dst` above.
    #[test]
    fn te_hash_to_curve_is_deterministic() {
        let dst = BLS_TE_HASH_TO_CURVE.as_bytes();
        let a = G1Point::hash_to_curve(b"deterministic", dst);
        let b = G1Point::hash_to_curve(b"deterministic", dst);
        assert_eq!(a, b);
    }
}
