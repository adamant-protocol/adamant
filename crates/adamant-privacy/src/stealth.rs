//! Stealth address construction per whitepaper §7.2.2 (post-
//! amendment instance 32).
//!
//! Phase 6.4 ships the [`SpendingPrivateKey`] / [`SpendingPublicKey`]
//! / [`Address`] / [`EncapsulatedSecret`] / [`StealthSecret`] /
//! [`ViewTag`] types, plus the four pure derivation primitives:
//! [`derive_shared_scalar`], [`derive_view_tag`],
//! [`derive_stealth_address`], [`recover_stealth_spending_key`].
//!
//! # Spec basis
//!
//! Whitepaper §7.2.2 (post-amendment) verbatim:
//!
//! > The protocol uses an **ML-KEM-based stealth address scheme**.
//! >
//! > A recipient's long-term identity comprises:
//! > - **Spending key** `sk_s`: scalar in the **Pallas scalar
//! >   field**
//! > - **Viewing keypair** `(sk_v_kem, pk_v_kem)`: an ML-KEM-768
//! >   keypair (public key 1184 bytes, secret key 2400 bytes)
//! > - **Spending public key** `pk_s = sk_s · G` where G is the
//! >   **Pallas curve generator**
//! >
//! > To send a note to this recipient, a sender:
//! > 1. Performs ML-KEM-768 encapsulation against `pk_v_kem`,
//! >    producing `(ct, ss)`
//! > 2. Stores `ct` as part of the note's on-chain data
//! > 3. Computes the shared scalar:
//! >    `s = HashToScalar(ss || domain_tag)`
//! >    where `HashToScalar` produces a **Pallas scalar field
//! >    element**
//! > 4. Computes the one-time stealth address:
//! >    `P = pk_s + s · G` (a Pallas point)
//! > 5. Constructs the note with `recipient = P`, where `recipient`
//! >    is the canonical 32-byte encoding of `P`'s base-field
//! >    x-coordinate
//! >
//! > The recipient's wallet, upon scanning the chain, performs for
//! > each note:
//! > 1. ML-KEM-768 decapsulation: `ss' = Decap(sk_v_kem, ct)`
//! > 2. `s' = HashToScalar(ss' || domain_tag)`
//! > 3. `P' = pk_s + s' · G`
//! > 4. If `P' == note.recipient`, the note is for this recipient
//! >
//! > If the note is theirs, the recipient derives the corresponding
//! > spending key as `sk' = sk_s + s'`.
//!
//! # Domain separation
//!
//! Two distinct registered domain tags per §3.3.1:
//!
//! - [`adamant_crypto::domain::STEALTH_SHARED_SCALAR`] —
//!   `b"ADAMANT-v1-stealth-shared-scalar"`. Used by
//!   [`derive_shared_scalar`] in the BIP-340 tagged-SHAKE-256
//!   construction to produce 64 uniform bytes that
//!   `pallas::Scalar::from_uniform_bytes` reduces into the scalar
//!   field.
//! - [`adamant_crypto::domain::STEALTH_VIEW_TAG`] —
//!   `b"ADAMANT-v1-stealth-view-tag"`. Used by [`derive_view_tag`]
//!   in the BIP-340 tagged-SHA3-256 construction; the first output
//!   byte is the published view tag per §7.2.4.
//!
//! Distinct tags ensure the view-tag's 8-bit signal cannot be used
//! to short-cut shared-scalar derivation, and vice versa.
//!
//! # `StealthAddress` placeholder bridge
//!
//! Phase 6.1 pinned [`crate::StealthAddress`] as a 32-byte
//! placeholder; this sub-arc reuses that 32-byte width to encode
//! the Pallas base-field x-coordinate of `P` per the spec
//! ("canonical 32-byte encoding of `P`'s base-field
//! x-coordinate"). The Phase 6.1 KAT for note commitments stays
//! valid because the byte width is unchanged.
//!
//! # Cross-curve note
//!
//! Per §7.2.2 amended Cross-curve note paragraph: the stealth-
//! address arithmetic operates on the Pasta cycle (Pallas/Vesta);
//! BLS12-381 does not appear in stealth-address derivation. Pre-
//! amendment drafts conflicted with §3.3.3's Pallas-base-field
//! Poseidon and §7.1's commitment formula; the amendment unifies
//! the privacy-layer arithmetic on Pasta cycle native fields.

use adamant_crypto::domain;
use adamant_crypto::hash::{sha3_256_tagged, shake_256_tagged};
use adamant_crypto::ml_kem;
use pasta_curves::arithmetic::CurveAffine;
use pasta_curves::group::ff::{Field, FromUniformBytes, PrimeField};
use pasta_curves::group::{Curve, Group, GroupEncoding};
use pasta_curves::pallas;

use crate::StealthAddress;

/// Byte length of a canonical Pallas-scalar encoding (§3.9.1).
pub const SCALAR_BYTES: usize = 32;

/// Byte length of a canonical Pallas-base-field encoding (§3.9.1).
pub const BASE_FIELD_BYTES: usize = 32;

/// Byte length of a canonical Pallas-affine compressed encoding
/// (x-coordinate plus 1-bit y-sign in the high bit of byte 31)
/// per `pasta_curves`' `GroupEncoding`. Used by
/// [`SpendingPublicKey`] for the on-the-wire address form.
pub const POINT_COMPRESSED_BYTES: usize = 32;

// ---------- SpendingPrivateKey ----------

/// Spending key per whitepaper §7.2.2: a scalar in the Pallas
/// scalar field used both to compute the spending public key
/// `pk_s = sk_s · G` and to recover stealth-spending keys
/// `sk' = sk_s + s'` when spending received notes.
///
/// Wraps a `pallas::Scalar` (Pallas's scalar field `Fq`). The
/// 32-byte canonical encoding via [`SpendingPrivateKey::to_bytes`]
/// is the same shape used by [`crate::SpendingKey`] (the §7.1.2
/// nullifier-side spending key); the two surfaces are deliberately
/// kept independent at this sub-arc and are unified at Phase 6.5
/// (§7.4 view-key hierarchy + spending-key derivation).
///
/// Drop-time zeroization is delegated to `pallas::Scalar`'s
/// `Default`-via-zero shape — secret-key material stored as a raw
/// scalar in `Fq` is overwritten with `Fq::zero()` on drop. This
/// is the same posture as `adamant_crypto::ed25519::SigningKey`
/// for analogous secret material.
#[derive(Clone, Debug)]
pub struct SpendingPrivateKey(pallas::Scalar);

impl SpendingPrivateKey {
    /// Construct from 64 uniformly-distributed bytes (e.g., the
    /// output of `tagged_shake_256(domain, seed, 64)`). The bytes
    /// are reduced modulo the Pallas scalar field characteristic
    /// per `pallas::Scalar::from_uniform_bytes` (`ff::FromUniformBytes`).
    ///
    /// Use this constructor when wallet code derives the spending
    /// key from a master seed (Phase 6.5 will pin the exact KDF
    /// chain). The 64-byte input width produces negligible bias
    /// modulo the ~252-bit scalar field.
    #[must_use]
    pub fn from_uniform_bytes(bytes: &[u8; 64]) -> Self {
        Self(pallas::Scalar::from_uniform_bytes(bytes))
    }

    /// Construct from the canonical 32-byte little-endian scalar
    /// encoding. Returns `None` if the bytes encode an integer ≥
    /// the Pallas scalar field characteristic.
    #[must_use]
    pub fn from_bytes(bytes: &[u8; SCALAR_BYTES]) -> Option<Self> {
        let opt = pallas::Scalar::from_repr(*bytes);
        if bool::from(opt.is_some()) {
            Some(Self(opt.unwrap()))
        } else {
            None
        }
    }

    /// Canonical 32-byte little-endian encoding of the scalar.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; SCALAR_BYTES] {
        self.0.to_repr()
    }

    /// Derive the corresponding spending public key
    /// `pk_s = sk_s · G`.
    #[must_use]
    pub fn public_key(&self) -> SpendingPublicKey {
        let p = pallas::Point::generator() * self.0;
        SpendingPublicKey(p.to_affine())
    }

    /// Borrow the underlying scalar. Crate-internal — used by
    /// [`recover_stealth_spending_key`] for `sk_s + s'`.
    pub(crate) const fn as_scalar(&self) -> &pallas::Scalar {
        &self.0
    }
}

impl Drop for SpendingPrivateKey {
    fn drop(&mut self) {
        // pallas::Scalar's representation is internally
        // [u64; 4]; overwriting with Fq::ZERO ensures the secret
        // bytes do not linger in stack memory after drop.
        self.0 = pallas::Scalar::ZERO;
    }
}

impl PartialEq for SpendingPrivateKey {
    /// Field-element equality. Constant-time on `pallas::Scalar`
    /// per the upstream `ff` crate (uses `subtle::ConstantTimeEq`
    /// internally).
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl Eq for SpendingPrivateKey {}

// ---------- SpendingPublicKey ----------

/// Spending public key per whitepaper §7.2.2: a Pallas point
/// `pk_s = sk_s · G`. Encoded on the wire as a 32-byte compressed
/// point (x-coordinate plus 1-bit y-sign per `pasta_curves`'
/// `GroupEncoding`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SpendingPublicKey(pallas::Affine);

impl SpendingPublicKey {
    /// Construct from a 32-byte compressed point encoding. Returns
    /// `None` if the bytes do not encode a valid Pallas point.
    #[must_use]
    pub fn from_bytes(bytes: &[u8; POINT_COMPRESSED_BYTES]) -> Option<Self> {
        let opt = pallas::Affine::from_bytes(bytes);
        if bool::from(opt.is_some()) {
            Some(Self(opt.unwrap()))
        } else {
            None
        }
    }

    /// Canonical 32-byte compressed point encoding (x-coordinate
    /// in low 255 bits, y-sign in the high bit of byte 31 per
    /// `pasta_curves`' `GroupEncoding`).
    #[must_use]
    pub fn to_bytes(&self) -> [u8; POINT_COMPRESSED_BYTES] {
        self.0.to_bytes()
    }

    /// Borrow the underlying affine point. Crate-internal — used
    /// by [`derive_stealth_address`] for `pk_s + s · G`.
    pub(crate) const fn as_affine(&self) -> &pallas::Affine {
        &self.0
    }
}

// ---------- Address ----------

/// A recipient's published stealth-address identity per whitepaper
/// §7.2.2: the pair `(pk_s, pk_v_kem)`.
///
/// Published off-chain (in payment URIs, QR codes, etc.); not a
/// chain object. Wire size is dominated by the ML-KEM-768
/// encapsulation key (1184 bytes); the spending public key is 32
/// bytes for a total of 1216 bytes.
#[derive(Clone, Debug)]
pub struct Address {
    /// Spending public key `pk_s = sk_s · G` (Pallas point).
    pub spending_pk: SpendingPublicKey,
    /// Viewing-keypair public component `pk_v_kem` (ML-KEM-768
    /// encapsulation key, 1184 bytes).
    pub view_pk: ml_kem::EncapsulationKey,
}

impl Address {
    /// Construct from components.
    #[must_use]
    pub const fn new(spending_pk: SpendingPublicKey, view_pk: ml_kem::EncapsulationKey) -> Self {
        Self {
            spending_pk,
            view_pk,
        }
    }
}

// ---------- EncapsulatedSecret ----------

/// Output of the sender-side ML-KEM-768 encapsulation step per
/// whitepaper §7.2.2: the 1088-byte ciphertext that goes on-chain
/// alongside the note, paired with the 32-byte shared secret used
/// locally for stealth-address derivation.
///
/// The recipient reconstructs the shared secret by decapsulating
/// the ciphertext with their viewing secret key.
pub struct EncapsulatedSecret {
    /// ML-KEM-768 ciphertext (1088 bytes) — published on-chain.
    pub ciphertext: ml_kem::Ciphertext,
    /// ML-KEM-768 shared secret (32 bytes) — held only by the
    /// sender (and reproducible by the recipient via decapsulation).
    pub shared_secret: ml_kem::SharedSecret,
}

// ---------- StealthSecret ----------

/// The per-note shared scalar `s` derived from the ML-KEM shared
/// secret per whitepaper §7.2.2: `s = HashToScalar(ss || domain_tag)`.
///
/// `s` is the bridge between the post-quantum-secure key agreement
/// (ML-KEM) and the in-circuit-friendly Pallas point arithmetic
/// (`P = pk_s + s · G`). Knowing `s` allows constructing the
/// stealth address but NOT spending it; spending requires `sk_s`.
#[derive(Clone, Debug)]
pub struct StealthSecret(pallas::Scalar);

impl StealthSecret {
    /// Borrow the underlying scalar. Crate-internal use only.
    pub(crate) const fn as_scalar(&self) -> &pallas::Scalar {
        &self.0
    }

    /// Canonical 32-byte little-endian encoding. Useful for
    /// debugging and KAT regression vectors; do NOT publish on-
    /// chain (would link the note to the recipient's `pk_v_kem`).
    #[must_use]
    pub fn to_bytes(&self) -> [u8; SCALAR_BYTES] {
        self.0.to_repr()
    }
}

impl Drop for StealthSecret {
    fn drop(&mut self) {
        self.0 = pallas::Scalar::ZERO;
    }
}

impl PartialEq for StealthSecret {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl Eq for StealthSecret {}

// ---------- ViewTag ----------

/// 8-bit view tag per whitepaper §7.2.4: the first byte of
/// `SHA3_256(ss || tag_domain)`, used as a fast filter when
/// scanning the chain for received notes (rejects ~255/256 of
/// unrelated notes before computing the full stealth-address
/// derivation).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
pub struct ViewTag(pub u8);

impl ViewTag {
    /// Underlying byte value.
    #[must_use]
    pub const fn to_u8(self) -> u8 {
        self.0
    }
}

// ---------- Derivation primitives ----------

/// Derive the per-note shared scalar `s = HashToScalar(ss ||
/// domain_tag)` per whitepaper §7.2.2 step 3.
///
/// Composition: 64 uniform bytes via [`shake_256_tagged`] under the
/// registered [`domain::STEALTH_SHARED_SCALAR`] tag, reduced to a
/// Pallas scalar via `pallas::Scalar::from_uniform_bytes`. The
/// 64-byte SHAKE output and the modular reduction together produce
/// negligible bias (`< 2^-256`) modulo the ~252-bit scalar field —
/// far below any cryptographically meaningful threshold.
///
/// Distinct from [`derive_view_tag`]: the two derivations use
/// distinct registered domain tags so the 8-bit view-tag signal
/// cannot be used to short-cut shared-scalar derivation, and vice
/// versa.
#[must_use]
pub fn derive_shared_scalar(shared_secret: &ml_kem::SharedSecret) -> StealthSecret {
    let mut uniform = [0u8; 64];
    shake_256_tagged(
        &domain::STEALTH_SHARED_SCALAR,
        shared_secret.as_bytes(),
        &mut uniform,
    );
    let s = pallas::Scalar::from_uniform_bytes(&uniform);
    StealthSecret(s)
}

/// Derive the 8-bit view tag per whitepaper §7.2.4:
/// `view_tag = SHA3_256(ss || tag_domain)[0]`.
///
/// Composition: the first byte of [`sha3_256_tagged`] under the
/// registered [`domain::STEALTH_VIEW_TAG`] tag.
#[must_use]
pub fn derive_view_tag(shared_secret: &ml_kem::SharedSecret) -> ViewTag {
    let digest = sha3_256_tagged(&domain::STEALTH_VIEW_TAG, shared_secret.as_bytes());
    ViewTag(digest[0])
}

/// Returned by [`derive_stealth_address`] when the derived point
/// `P = pk_s + s · G` is the curve identity. Probability is
/// negligible (`< 2^-250`) for any honest input distribution; the
/// error variant exists so the API is total without resorting to
/// a panic that would gate consensus on a probabilistic event.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StealthAddressIsIdentity;

impl core::fmt::Display for StealthAddressIsIdentity {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("derived stealth-address point is the curve identity")
    }
}

impl std::error::Error for StealthAddressIsIdentity {}

/// Derive the one-time stealth address `P = pk_s + s · G` per
/// whitepaper §7.2.2 step 4, encoded as the canonical 32-byte
/// little-endian Pallas-base-field x-coordinate per step 5.
///
/// The 32-byte x-coordinate encoding (rather than the 32-byte
/// compressed point encoding used by [`SpendingPublicKey`])
/// matches the Phase 6.1 [`StealthAddress`] placeholder width and
/// the §7.1 note-commitment formula's Pallas-base-field-element
/// shape for `recipient`.
///
/// # Errors
///
/// Returns [`StealthAddressIsIdentity`] in the negligible-
/// probability case where `pk_s + s · G` is the curve identity.
pub fn derive_stealth_address(
    spending_pk: &SpendingPublicKey,
    s: &StealthSecret,
) -> Result<StealthAddress, StealthAddressIsIdentity> {
    let g = pallas::Point::generator();
    let p = pallas::Point::from(*spending_pk.as_affine()) + g * s.as_scalar();
    let p_affine = p.to_affine();
    let coords = p_affine.coordinates();
    if bool::from(coords.is_none()) {
        return Err(StealthAddressIsIdentity);
    }
    let coords = coords.unwrap();
    let x_bytes = coords.x().to_repr();
    Ok(StealthAddress::from_bytes(x_bytes))
}

/// Recover the per-note spending key `sk' = sk_s + s'` per
/// whitepaper §7.2.2: the recipient computes `sk'` after
/// confirming the note is theirs (via stealth-address match);
/// `sk'` then signs / authorizes the spend transaction.
///
/// The returned scalar is the secret material that authorizes
/// spending the note at on-chain stealth address
/// `derive_stealth_address(pk_s, s')`.
#[must_use]
pub fn recover_stealth_spending_key(
    spending_sk: &SpendingPrivateKey,
    s: &StealthSecret,
) -> SpendingPrivateKey {
    SpendingPrivateKey(spending_sk.as_scalar() + s.as_scalar())
}

#[cfg(test)]
#[allow(clippy::similar_names)]
mod tests {
    use super::*;
    use adamant_crypto::ml_kem::{DecapsulationKey, SharedSecret};
    use getrandom::{rand_core::UnwrapErr, SysRng};
    use hex_literal::hex;
    use subtle::ConstantTimeEq;

    fn test_rng() -> UnwrapErr<SysRng> {
        UnwrapErr(SysRng)
    }

    /// Construct a deterministic [`SharedSecret`]-shaped value for
    /// KAT vectors. `SharedSecret` itself does not expose a public
    /// constructor (it can only come from encap/decap), so we
    /// construct it via a deterministic ML-KEM-768 encapsulation
    /// against a fixed-seed key.
    ///
    /// `from_bytes` for `SharedSecret` is intentionally not
    /// exposed by `adamant-crypto::ml_kem` — see that module's
    /// constant-time discipline. Tests work from real KEM outputs
    /// instead.
    fn deterministic_shared_secret(seed_byte: u8) -> SharedSecret {
        let dk = DecapsulationKey::from_seed(&[seed_byte; 64]);
        let ek = dk.encapsulation_key();
        // Encapsulation is randomized per FIPS 203, so we cannot
        // rebuild a fully-deterministic shared secret without
        // hazmat APIs. Use real randomness; the deterministic
        // KAT vector is anchored by the spending-key path
        // instead (see `derive_shared_scalar_known_answer`).
        let (_ct, ss) = ek.encapsulate(&mut test_rng());
        ss
    }

    fn fixed_spending_private_key() -> SpendingPrivateKey {
        // 64 deterministic bytes (Pallas scalar reduction via
        // from_uniform_bytes).
        let bytes = [0x33u8; 64];
        SpendingPrivateKey::from_uniform_bytes(&bytes)
    }

    // ---------- Domain-tag pins ----------

    #[test]
    fn stealth_shared_scalar_tag_is_registry_value() {
        assert_eq!(
            domain::STEALTH_SHARED_SCALAR.as_bytes(),
            b"ADAMANT-v1-stealth-shared-scalar"
        );
    }

    #[test]
    fn stealth_view_tag_tag_is_registry_value() {
        assert_eq!(
            domain::STEALTH_VIEW_TAG.as_bytes(),
            b"ADAMANT-v1-stealth-view-tag"
        );
    }

    // ---------- SpendingPrivateKey / SpendingPublicKey ----------

    #[test]
    fn spending_private_key_from_uniform_bytes_deterministic() {
        let a = SpendingPrivateKey::from_uniform_bytes(&[0x11u8; 64]);
        let b = SpendingPrivateKey::from_uniform_bytes(&[0x11u8; 64]);
        assert_eq!(a, b);
    }

    #[test]
    fn spending_private_key_distinct_seeds_distinct_keys() {
        let a = SpendingPrivateKey::from_uniform_bytes(&[0x11u8; 64]);
        let b = SpendingPrivateKey::from_uniform_bytes(&[0x22u8; 64]);
        assert_ne!(a, b);
    }

    #[test]
    fn spending_private_key_to_from_bytes_round_trip() {
        let original = fixed_spending_private_key();
        let encoded = original.to_bytes();
        let decoded = SpendingPrivateKey::from_bytes(&encoded).expect("canonical encoding");
        assert_eq!(original, decoded);
    }

    /// All-ones is well above the Pallas scalar field
    /// characteristic; `from_bytes` rejects it.
    #[test]
    fn spending_private_key_from_bytes_out_of_range_rejected() {
        let result = SpendingPrivateKey::from_bytes(&[0xFFu8; 32]);
        assert!(result.is_none());
    }

    #[test]
    fn spending_public_key_to_from_bytes_round_trip() {
        let sk = fixed_spending_private_key();
        let pk = sk.public_key();
        let encoded = pk.to_bytes();
        let decoded = SpendingPublicKey::from_bytes(&encoded).expect("valid point");
        assert_eq!(pk, decoded);
    }

    #[test]
    fn spending_public_key_from_bytes_invalid_rejected() {
        // 0xFF in the low byte combined with a generic high-bit
        // flip is unlikely to encode a curve point; the upstream
        // `Affine::from_bytes` will reject (or compute a
        // never-on-curve representative, the CtOption is_none).
        let result = SpendingPublicKey::from_bytes(&[0xFFu8; 32]);
        // The check is non-trivial: not every 32-byte value
        // encodes a curve point. If by coincidence this byte
        // pattern is on-curve (Pallas covers ~half of all x's),
        // skip the assertion. Invariant: a known-bad pattern is
        // always rejected — try another shape if needed.
        if result.is_some() {
            // Try a clearly-impossible pattern: the modulus of
            // the base field encodes an integer ≥ p, which is
            // not a valid x-coordinate. (Pallas base p has top
            // byte 0x40; setting top byte to 0x40 with all
            // lower bytes 0 produces exactly p.)
            let mut bad = [0u8; 32];
            bad[31] = 0x40;
            assert!(SpendingPublicKey::from_bytes(&bad).is_none());
        }
    }

    /// `pk_s = sk_s · G` is deterministic.
    #[test]
    fn spending_public_key_derivation_deterministic() {
        let sk = fixed_spending_private_key();
        let pk_a = sk.public_key();
        let pk_b = sk.public_key();
        assert_eq!(pk_a, pk_b);
    }

    /// Distinct spending keys produce distinct public keys.
    #[test]
    fn spending_public_key_distinct_keys_distinct_points() {
        let pk_a = SpendingPrivateKey::from_uniform_bytes(&[0x11u8; 64]).public_key();
        let pk_b = SpendingPrivateKey::from_uniform_bytes(&[0x22u8; 64]).public_key();
        assert_ne!(pk_a, pk_b);
    }

    // ---------- derive_shared_scalar ----------

    #[test]
    fn derive_shared_scalar_deterministic_from_same_secret() {
        let ss = deterministic_shared_secret(0x42);
        let s_a = derive_shared_scalar(&ss);
        let s_b = derive_shared_scalar(&ss);
        assert_eq!(s_a, s_b);
    }

    /// Distinct shared secrets produce distinct scalars (with
    /// overwhelming probability).
    #[test]
    fn derive_shared_scalar_distinct_secrets() {
        let ss_a = deterministic_shared_secret(0x01);
        let ss_b = deterministic_shared_secret(0x02);
        let s_a = derive_shared_scalar(&ss_a);
        let s_b = derive_shared_scalar(&ss_b);
        // Real ML-KEM encapsulation against different keys
        // produces distinct shared secrets (assuming randomness).
        // If by coincidence ss_a == ss_b (probability 2^-256),
        // the assertion fails — re-run; not a real failure.
        if !bool::from(ss_a.ct_eq(&ss_b)) {
            assert_ne!(s_a, s_b);
        }
    }

    // ---------- derive_view_tag ----------

    #[test]
    fn derive_view_tag_deterministic() {
        let ss = deterministic_shared_secret(0x42);
        let tag_a = derive_view_tag(&ss);
        let tag_b = derive_view_tag(&ss);
        assert_eq!(tag_a, tag_b);
    }

    /// View-tag and shared-scalar use distinct domain tags, so
    /// the byte-0 of the view-tag derivation cannot equal the
    /// byte-0 of the shared-scalar's underlying field bytes for
    /// any collision-avoiding-domain reason; structural domain-
    /// separation pin.
    #[test]
    fn view_tag_and_shared_scalar_use_distinct_domains() {
        // Inputs match exactly; domain tags differ. Outputs are
        // computed under different tagged-hash prefixes and so
        // are independent — no inferable relation.
        let ss = deterministic_shared_secret(0x55);
        let scalar_bytes = derive_shared_scalar(&ss).to_bytes();
        let tag = derive_view_tag(&ss).to_u8();
        // The view-tag byte is independent of the scalar byte 0
        // (different domain tags). For a fixed input, the bytes
        // could coincide — pin: the tag function uses
        // `STEALTH_VIEW_TAG`, which is distinct from
        // `STEALTH_SHARED_SCALAR` under the registry.
        assert_ne!(
            domain::STEALTH_VIEW_TAG.as_bytes(),
            domain::STEALTH_SHARED_SCALAR.as_bytes()
        );
        // Sanity that both derivations return well-formed values.
        let _ = scalar_bytes;
        let _ = tag;
    }

    // ---------- derive_stealth_address ----------

    #[test]
    fn derive_stealth_address_deterministic() {
        let sk = fixed_spending_private_key();
        let pk = sk.public_key();
        let ss = deterministic_shared_secret(0x42);
        let s = derive_shared_scalar(&ss);
        let addr_a = derive_stealth_address(&pk, &s).expect("not identity");
        let addr_b = derive_stealth_address(&pk, &s).expect("not identity");
        assert_eq!(addr_a.to_bytes(), addr_b.to_bytes());
    }

    /// Distinct shared scalars produce distinct stealth
    /// addresses for the same recipient — the unlinkability
    /// property of §7.2.3.
    #[test]
    fn derive_stealth_address_distinct_for_distinct_secrets() {
        let sk = fixed_spending_private_key();
        let pk = sk.public_key();
        let ss_a = deterministic_shared_secret(0x01);
        let ss_b = deterministic_shared_secret(0x02);
        if !bool::from(ss_a.ct_eq(&ss_b)) {
            let s_a = derive_shared_scalar(&ss_a);
            let s_b = derive_shared_scalar(&ss_b);
            let addr_a = derive_stealth_address(&pk, &s_a).expect("not identity");
            let addr_b = derive_stealth_address(&pk, &s_b).expect("not identity");
            assert_ne!(addr_a.to_bytes(), addr_b.to_bytes());
        }
    }

    /// Distinct recipients (different `pk_s`) under the same
    /// shared scalar produce distinct stealth addresses.
    #[test]
    fn derive_stealth_address_distinct_for_distinct_recipients() {
        let pk_a = SpendingPrivateKey::from_uniform_bytes(&[0x11u8; 64]).public_key();
        let pk_b = SpendingPrivateKey::from_uniform_bytes(&[0x22u8; 64]).public_key();
        let ss = deterministic_shared_secret(0x33);
        let s = derive_shared_scalar(&ss);
        let addr_a = derive_stealth_address(&pk_a, &s).expect("not identity");
        let addr_b = derive_stealth_address(&pk_b, &s).expect("not identity");
        assert_ne!(addr_a.to_bytes(), addr_b.to_bytes());
    }

    // ---------- recover_stealth_spending_key ----------

    /// `sk' = sk_s + s'` is deterministic.
    #[test]
    fn recover_stealth_spending_key_deterministic() {
        let sk = fixed_spending_private_key();
        let ss = deterministic_shared_secret(0x77);
        let s = derive_shared_scalar(&ss);
        let sk_a = recover_stealth_spending_key(&sk, &s);
        let sk_b = recover_stealth_spending_key(&sk, &s);
        assert_eq!(sk_a, sk_b);
    }

    // ---------- End-to-end protocol round-trip ----------

    /// Sender-recipient round-trip per §7.2.2 — the heart of the
    /// scheme. If this fails, the protocol is broken.
    ///
    /// 1. Recipient publishes `(pk_s, pk_v_kem)`.
    /// 2. Sender encapsulates against `pk_v_kem`, computes `s` and
    ///    `view_tag`, derives stealth address `P = pk_s + s · G`.
    /// 3. Sender attaches `(ct, view_tag, P)` to the note.
    /// 4. Recipient scans: decapsulates `ct` to recover `ss'`,
    ///    computes `s'`, computes `P' = pk_s + s' · G`, checks
    ///    `P' == P`.
    /// 5. Recipient derives `sk' = sk_s + s'` for spending.
    ///
    /// Properties pinned: (a) recipient's stealth address matches
    /// sender's; (b) recipient's recovered scalar matches sender's;
    /// (c) view tags match.
    #[test]
    fn sender_recipient_round_trip() {
        // Recipient's keys.
        let sk_s = fixed_spending_private_key();
        let pk_s = sk_s.public_key();
        let sk_v_kem = DecapsulationKey::from_seed(&[0xA1u8; 64]);
        let pk_v_kem = sk_v_kem.encapsulation_key();

        // Sender side.
        let (ct, ss_sender) = pk_v_kem.encapsulate(&mut test_rng());
        let s_sender = derive_shared_scalar(&ss_sender);
        let view_tag_sender = derive_view_tag(&ss_sender);
        let stealth_addr_sender = derive_stealth_address(&pk_s, &s_sender).expect("not identity");

        // Recipient side.
        let ss_recipient = sk_v_kem.decapsulate(&ct);
        let s_recipient = derive_shared_scalar(&ss_recipient);
        let view_tag_recipient = derive_view_tag(&ss_recipient);
        let stealth_addr_recipient =
            derive_stealth_address(&pk_s, &s_recipient).expect("not identity");

        // (a) Stealth addresses match.
        assert_eq!(
            stealth_addr_sender.to_bytes(),
            stealth_addr_recipient.to_bytes(),
            "sender's and recipient's stealth address derivations diverged"
        );
        // (b) Scalars match.
        assert_eq!(s_sender, s_recipient, "shared scalar mismatch");
        // (c) View tags match.
        assert_eq!(view_tag_sender, view_tag_recipient, "view-tag mismatch");

        // Recipient can derive the spending key for this note.
        let sk_prime = recover_stealth_spending_key(&sk_s, &s_recipient);
        // sk' · G should equal P (the stealth address point).
        // Verify via: sk' · G = (sk_s + s) · G = pk_s + s · G = P.
        let p_from_sk_prime = sk_prime.public_key();
        // Re-encode P from the stealth address for comparison.
        // The stealth address holds only the x-coordinate, so we
        // compare x-coordinate to x-coordinate.
        let p_x_from_sk_prime = p_from_sk_prime
            .as_affine()
            .coordinates()
            .map(|c| c.x().to_repr())
            .unwrap();
        assert_eq!(
            p_x_from_sk_prime,
            stealth_addr_recipient.to_bytes(),
            "sk' · G x-coord must match stealth address"
        );
    }

    /// A "wrong recipient" scan must NOT match a stealth address
    /// destined for a different recipient. Pins the unlinkability
    /// property at the protocol level.
    #[test]
    fn wrong_recipient_does_not_match() {
        let sk_alice = SpendingPrivateKey::from_uniform_bytes(&[0xA1u8; 64]);
        let pk_alice = sk_alice.public_key();
        let sk_v_alice = DecapsulationKey::from_seed(&[0xB1u8; 64]);
        let pk_v_alice = sk_v_alice.encapsulation_key();

        // Bob's keypair (decapsulation will silently produce a
        // meaningless secret per FIPS 203 implicit rejection if
        // Bob tries to decapsulate Alice's ct).
        let sk_bob = SpendingPrivateKey::from_uniform_bytes(&[0xC1u8; 64]);
        let pk_bob = sk_bob.public_key();
        let sk_v_bob = DecapsulationKey::from_seed(&[0xD1u8; 64]);
        let _pk_v_bob = sk_v_bob.encapsulation_key();

        // Sender encapsulates against Alice.
        let (ct, ss_sender) = pk_v_alice.encapsulate(&mut test_rng());
        let s_sender = derive_shared_scalar(&ss_sender);
        let stealth_addr = derive_stealth_address(&pk_alice, &s_sender).expect("not identity");

        // Bob tries to decapsulate Alice's ciphertext: implicit
        // rejection per FIPS 203 produces a deterministic-but-
        // meaningless ss'. Bob computes a stealth address and
        // checks against the on-chain one.
        let ss_bob_garbage = sk_v_bob.decapsulate(&ct);
        let s_bob_garbage = derive_shared_scalar(&ss_bob_garbage);
        let bob_check_addr = derive_stealth_address(&pk_bob, &s_bob_garbage).expect("not identity");
        // Bob is checking against pk_bob (his own pk_s), not
        // pk_alice — so even if ss collided he wouldn't see a
        // match. This test pins: with overwhelming probability
        // Bob's check produces a different address.
        assert_ne!(
            bob_check_addr.to_bytes(),
            stealth_addr.to_bytes(),
            "Bob's wrong-key check must not match Alice's stealth address"
        );
    }

    // ---------- KAT regression ----------

    /// Pin the wire format of [`derive_shared_scalar`] against a
    /// fully-deterministic 32-byte input. The shared-secret bytes
    /// are produced by `[0x77; 32]` interpreted as the
    /// `ml_kem::SharedSecret`'s 32-byte canonical form via the
    /// only deterministic path: replicate the SHAKE-256 derivation
    /// directly using a fixed-byte input that mimics what
    /// `derive_shared_scalar` does internally.
    ///
    /// Because `ml_kem::SharedSecret` is not constructible from
    /// raw bytes via public API, we KAT the underlying derivation
    /// at the scalar layer: take 64 deterministic bytes from
    /// `tagged_shake_256(STEALTH_SHARED_SCALAR, [0x77; 32], 64)`
    /// and reduce. If this regression vector ever changes, the
    /// stealth-address scheme has hard-forked.
    #[test]
    fn derive_shared_scalar_known_answer_via_layer() {
        let mut uniform = [0u8; 64];
        let synthetic_ss_bytes = [0x77u8; 32];
        shake_256_tagged(
            &domain::STEALTH_SHARED_SCALAR,
            &synthetic_ss_bytes,
            &mut uniform,
        );
        let s = pallas::Scalar::from_uniform_bytes(&uniform);
        let s_bytes = s.to_repr();
        // KAT: pin the 32-byte canonical encoding.
        let expected = hex!("de250352c7b00e1839df12d887b54f1192cf187617c11d414e20331f61df4508");
        assert_eq!(
            s_bytes, expected,
            "stealth-shared-scalar derivation regression: \
             input [0x77;32] under STEALTH_SHARED_SCALAR domain has drifted"
        );
    }

    /// Pin the wire format of [`derive_view_tag`] against a
    /// fixed 32-byte synthetic shared secret.
    #[test]
    fn derive_view_tag_known_answer_via_layer() {
        let synthetic_ss_bytes = [0x77u8; 32];
        let digest = sha3_256_tagged(&domain::STEALTH_VIEW_TAG, &synthetic_ss_bytes);
        let view_tag = digest[0];
        let expected = hex!("f6");
        assert_eq!(
            [view_tag],
            expected,
            "stealth-view-tag derivation regression: \
             input [0x77;32] under STEALTH_VIEW_TAG domain has drifted"
        );
    }
}
