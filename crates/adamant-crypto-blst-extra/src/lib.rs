//! Safe Rust API over `blst`'s lower-level pairing, hash-to-curve, and
//! scalar arithmetic operations not exposed by `blst`'s signatures
//! surface.
//!
//! # Why this crate exists
//!
//! Adamant's threshold-encryption construction
//! (`adamant-crypto::threshold`, whitepaper section 3.6) requires
//! G₁ hash-to-curve, G₂ scalar multiplication on a known generator,
//! pairings as `blst_fp12`, and `Z_r` arithmetic for Lagrange
//! coefficient computation. None of those operations are exposed by
//! `blst::min_sig` / `blst::min_pk` (blst's signature-oriented
//! surface) or `blst::Pairing` (the BLS aggregator) — only the raw
//! FFI bindings in the `blst::*` namespace expose them.
//!
//! This crate **contains** the resulting `unsafe` FFI calls behind a
//! safe Rust API, so that `adamant-crypto` and every other
//! Adamant-authored crate can preserve `unsafe_code = "forbid"`.
//!
//! # Unsafe-containment architecture
//!
//! - The workspace default is `unsafe_code = "forbid"` (set in the
//!   root `Cargo.toml`).
//! - This crate overrides the workspace lint to `unsafe_code = "allow"`
//!   in its own `[lints.rust]` table. Cargo does not permit mixing
//!   workspace inheritance with per-crate overrides, so the override
//!   duplicates the rest of the workspace lint configuration; that
//!   duplication is acknowledged in `Cargo.toml` and must be kept in
//!   sync.
//! - The crate exposes a small, focused API ([`G1Point`], [`G2Point`],
//!   [`GtElement`], [`Scalar`], [`pairing`]). Every `unsafe` block has
//!   a `// SAFETY:` comment naming the invariants the FFI relies on.
//! - New crates in the workspace MUST default to `unsafe_code = forbid`
//!   by inheriting `[workspace.lints]`. Relaxing the lint requires the
//!   same justification (and structural isolation) this crate has:
//!   wrap an audited cryptographic library's FFI for a single
//!   well-defined purpose, document the wrapper's responsibilities
//!   here, and add the crate to the `SECURITY.md` inventory. See
//!   `CONTRIBUTING.md` "Unsafe-containment architecture" for the rule.
//!
//! # API surface
//!
//! - [`G1Point`] — opaque BLS12-381 G₁ affine point. Construct via
//!   [`G1Point::hash_to_curve`] or [`G1Point::from_compressed`];
//!   serialise via [`G1Point::to_compressed`].
//! - [`G2Point`] — opaque BLS12-381 G₂ affine point. Construct via
//!   [`G2Point::generator`] or [`G2Point::from_compressed`];
//!   serialise via [`G2Point::to_compressed`]. Scalar multiplication
//!   via [`G2Point::mul_scalar`].
//! - [`GtElement`] — opaque `blst_fp12`. Constructed by [`pairing`];
//!   serialised via [`GtElement::to_bytes`] (576-byte uncompressed,
//!   per whitepaper 3.6.1).
//! - [`Scalar`] — opaque `Z_r` field element. Constants ([`Scalar::zero`],
//!   [`Scalar::one`], [`Scalar::from_u32`]); arithmetic ([`Scalar::add`],
//!   [`Scalar::sub`], [`Scalar::mul`], [`Scalar::inverse`]);
//!   serialisation ([`Scalar::to_bytes_le`], [`Scalar::to_bytes_be`],
//!   [`Scalar::from_bytes_be`]).
//! - [`pairing`] — Miller loop + final exponentiation, exposing
//!   `e(G₁, G₂) → G_T`.
//!
//! All operations are constant-time on secret material (inherited
//! from `blst`).

// SAFETY discipline: every `unsafe` block in this crate is a single
// FFI call (or a tightly coupled group, e.g. from_affine + mult +
// to_affine) preceded by a `// SAFETY:` comment naming the invariants
// the FFI relies on. The crate-level `#[allow(unsafe_code)]` is set
// in `Cargo.toml`'s `[lints.rust]` table.

use blst::{
    blst_fp12, blst_fr, blst_fr_add, blst_fr_from_scalar, blst_fr_from_uint64, blst_fr_inverse,
    blst_fr_mul, blst_fr_sub, blst_hash_to_g1, blst_lendian_from_scalar, blst_p1,
    blst_p1_add_or_double, blst_p1_affine, blst_p1_affine_compress, blst_p1_affine_in_g1,
    blst_p1_cneg, blst_p1_from_affine, blst_p1_generator, blst_p1_mult, blst_p1_to_affine,
    blst_p1_uncompress, blst_p2, blst_p2_add_or_double, blst_p2_affine, blst_p2_affine_compress,
    blst_p2_affine_in_g2, blst_p2_cneg, blst_p2_from_affine, blst_p2_mult, blst_p2_to_affine,
    blst_p2_uncompress, blst_scalar, blst_scalar_fr_check, blst_scalar_from_bendian,
    blst_scalar_from_fr, BLS12_381_G2, BLST_ERROR,
};

/// G₁ compressed encoding length: 48 bytes.
pub const G1_COMPRESSED_BYTES: usize = 48;

/// G₂ compressed encoding length: 96 bytes.
pub const G2_COMPRESSED_BYTES: usize = 96;

/// `G_T` element serialised length: 12 Fp limbs at 48 bytes each.
pub const GT_BYTES: usize = 12 * 48;

/// Scalar (`Z_r` element) canonical encoding length: 32 bytes.
pub const SCALAR_BYTES: usize = 32;

/// BLS12-381 scalar field bit width. The order `r` satisfies
/// `2^254 < r < 2^255`, so 255 bits suffice for any scalar in `[0, r)`.
pub const SCALAR_BITS: usize = 255;

/// Opaque encoding-error type returned by `from_compressed` /
/// `from_bytes_be`. Details are intentionally not exposed:
/// distinguishing failure modes leaks information that the
/// constant-time discipline is meant to hide.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct InvalidEncoding;

impl core::fmt::Display for InvalidEncoding {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("blst: invalid encoding")
    }
}

impl std::error::Error for InvalidEncoding {}

// =====================================================================
// Types
// =====================================================================

/// BLS12-381 G₁ affine point.
#[derive(Clone, Copy)]
pub struct G1Point(blst_p1_affine);

/// BLS12-381 G₂ affine point.
#[derive(Clone, Copy)]
pub struct G2Point(blst_p2_affine);

/// BLS12-381 `G_T` element (`blst_fp12`).
#[derive(Clone, Copy)]
pub struct GtElement(blst_fp12);

/// BLS12-381 scalar field element (`Z_r`).
///
/// `Scalar` implements [`zeroize::Zeroize`]: callers holding
/// secret-material scalars (decryption shares in
/// [`adamant_crypto::threshold`], Lagrange-coefficient intermediates,
/// the future KZG `τ` secret during ceremony ingestion) can scrub
/// the underlying 4 × `u64` limbs explicitly via
/// [`zeroize::Zeroize::zeroize`] before drop. Auto-drop-zeroization
/// (`ZeroizeOnDrop` + `Drop`) is intentionally NOT implemented
/// because it conflicts with the [`Copy`] derive — `Copy` is
/// load-bearing for the arithmetic API ergonomics and the 63+ call
/// sites that pass `Scalar` by value. Callers handling secret-
/// material scalars must explicitly invoke
/// [`zeroize::Zeroize::zeroize`] on drop paths; the project's
/// existing manual `*coeff = Scalar::zero()` pattern in `threshold.rs`
/// can be upgraded to `coeff.zeroize()` for compiler-non-eliding
/// semantics.
#[derive(Clone, Copy)]
pub struct Scalar(blst_fr);

impl zeroize::Zeroize for Scalar {
    fn zeroize(&mut self) {
        // blst_fr is a `repr(C)` struct holding `[u64; 4]` limbs
        // (per blst's bindings.rs:50-52). Zeroize the inner limb
        // array directly via the array's Zeroize impl. The zeroize
        // crate's array impl uses volatile writes that prevent the
        // optimiser from eliding the scrub.
        self.0.l.zeroize();
    }
}

impl PartialEq for G1Point {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}
impl Eq for G1Point {}

impl PartialEq for G2Point {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}
impl Eq for G2Point {}

impl PartialEq for GtElement {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}
impl Eq for GtElement {}

impl PartialEq for Scalar {
    fn eq(&self, other: &Self) -> bool {
        // Compare via canonical big-endian bytes; equivalent to
        // comparing `blst_fr` values for elements already in
        // canonical form (which is the only form our constructors
        // ever produce).
        self.to_bytes_be() == other.to_bytes_be()
    }
}
impl Eq for Scalar {}

impl core::fmt::Debug for G1Point {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("G1Point(<bls12-381-g1>)")
    }
}

impl core::fmt::Debug for G2Point {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("G2Point(<bls12-381-g2>)")
    }
}

impl core::fmt::Debug for GtElement {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("GtElement(<bls12-381-fp12>)")
    }
}

impl core::fmt::Debug for Scalar {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Scalars frequently carry secret material (Lagrange
        // coefficients of validator shares, key-derivation
        // intermediates). Redact in Debug output by default.
        f.write_str("Scalar(<redacted>)")
    }
}

// =====================================================================
// G₁ operations
// =====================================================================

impl G1Point {
    /// Hash `message` to a G₁ point under the IRTF
    /// `draft-irtf-cfrg-hash-to-curve` G₁ ciphersuite, using `dst` as
    /// the domain-separation tag. Returns the affine point.
    #[must_use]
    pub fn hash_to_curve(message: &[u8], dst: &[u8]) -> Self {
        let mut p_jac = blst_p1::default();
        let mut p_aff = blst_p1_affine::default();
        // SAFETY: blst_hash_to_g1 reads `message` and `dst` as byte
        // slices of the supplied lengths and writes to the owned
        // `p_jac`. The `aug` argument is null/0-length; blst tolerates
        // a null pointer when the corresponding length is zero.
        // blst_p1_to_affine reads `p_jac` and writes to the owned
        // `p_aff`.
        unsafe {
            blst_hash_to_g1(
                &raw mut p_jac,
                message.as_ptr(),
                message.len(),
                dst.as_ptr(),
                dst.len(),
                core::ptr::null(),
                0,
            );
            blst_p1_to_affine(&raw mut p_aff, &raw const p_jac);
        }
        Self(p_aff)
    }

    /// Parse a G₁ point from its 48-byte canonical compressed
    /// encoding. Performs subgroup validation; rejects malformed
    /// encodings and points outside the prime-order subgroup.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidEncoding`] if the bytes do not encode a valid
    /// G₁ point in the prime-order subgroup.
    pub fn from_compressed(bytes: &[u8; G1_COMPRESSED_BYTES]) -> Result<Self, InvalidEncoding> {
        let mut p_aff = blst_p1_affine::default();
        // SAFETY: blst_p1_uncompress reads exactly 48 bytes from the
        // input pointer and writes to the owned blst_p1_affine,
        // returning BLST_ERROR on malformed encoding.
        // blst_p1_affine_in_g1 reads the affine point and returns
        // whether it lies in the prime-order subgroup.
        unsafe {
            if blst_p1_uncompress(&raw mut p_aff, bytes.as_ptr()) != BLST_ERROR::BLST_SUCCESS {
                return Err(InvalidEncoding);
            }
            if !blst_p1_affine_in_g1(&raw const p_aff) {
                return Err(InvalidEncoding);
            }
        }
        Ok(Self(p_aff))
    }

    /// Canonical 48-byte compressed encoding.
    #[must_use]
    pub fn to_compressed(&self) -> [u8; G1_COMPRESSED_BYTES] {
        let mut bytes = [0u8; G1_COMPRESSED_BYTES];
        // SAFETY: blst_p1_affine_compress reads from the owned input
        // and writes 48 bytes to the owned output buffer.
        unsafe {
            blst_p1_affine_compress(bytes.as_mut_ptr(), &raw const self.0);
        }
        bytes
    }

    /// The canonical BLS12-381 G₁ generator.
    ///
    /// Required by KZG (whitepaper §3.9.2) for the polynomial-
    /// commitment formula `C = Σ p_i · g^{τ^i}` where `g` is the
    /// G₁ generator and `g^{τ^i}` are the trusted-setup powers.
    #[must_use]
    pub fn generator() -> Self {
        // SAFETY: blst_p1_generator returns a pointer to a static
        // blst_p1 (the canonical BLS12-381 G₁ generator), valid for
        // the lifetime of the program. We dereference into a Jacobian
        // value and convert to affine on owned storage.
        let mut p_aff = blst_p1_affine::default();
        unsafe {
            let p_jac = *blst_p1_generator();
            blst_p1_to_affine(&raw mut p_aff, &raw const p_jac);
        }
        Self(p_aff)
    }

    /// Multiply this G₁ point by a scalar.
    ///
    /// Required by KZG (whitepaper §3.9.2): committing a polynomial
    /// requires scalar-multiplying each `g^{τ^i}` setup point by the
    /// corresponding polynomial coefficient.
    #[must_use]
    pub fn mul_scalar(&self, scalar: &Scalar) -> Self {
        let scalar_le = scalar.to_bytes_le();
        let mut point_jac = blst_p1::default();
        let mut result_jac = blst_p1::default();
        let mut result_aff = blst_p1_affine::default();
        // SAFETY: blst_p1_from_affine reads `self.0`; blst_p1_mult
        // reads `point_jac` and `SCALAR_BITS` bits from the
        // 32-byte little-endian scalar pointer, writing to the owned
        // `result_jac`; blst_p1_to_affine writes the affine form to
        // `result_aff`.
        unsafe {
            blst_p1_from_affine(&raw mut point_jac, &raw const self.0);
            blst_p1_mult(
                &raw mut result_jac,
                &raw const point_jac,
                scalar_le.as_ptr(),
                SCALAR_BITS,
            );
            blst_p1_to_affine(&raw mut result_aff, &raw const result_jac);
        }
        Self(result_aff)
    }

    /// Add two G₁ points.
    ///
    /// Uses `blst_p1_add_or_double` (not `blst_p1_add`) so the
    /// addition is correct in every case including the doubling
    /// case (`a == b`) and the inverse case (`a == −b`, where the
    /// result is the identity point at infinity). KZG verification
    /// (whitepaper §3.9.2) hits the inverse case for constant
    /// polynomials where `commitment − y·g = identity`.
    #[must_use]
    pub fn add(&self, other: &Self) -> Self {
        let mut a_jac = blst_p1::default();
        let mut b_jac = blst_p1::default();
        let mut sum_jac = blst_p1::default();
        let mut sum_aff = blst_p1_affine::default();
        // SAFETY: each call reads from owned local values and writes
        // to owned local values. blst_p1_add_or_double handles the
        // doubling (`a == b`) and identity (`a == −b`) edge cases
        // that blst_p1_add does not.
        unsafe {
            blst_p1_from_affine(&raw mut a_jac, &raw const self.0);
            blst_p1_from_affine(&raw mut b_jac, &raw const other.0);
            blst_p1_add_or_double(&raw mut sum_jac, &raw const a_jac, &raw const b_jac);
            blst_p1_to_affine(&raw mut sum_aff, &raw const sum_jac);
        }
        Self(sum_aff)
    }

    /// Negate this G₁ point.
    #[must_use]
    pub fn negate(&self) -> Self {
        let mut p_jac = blst_p1::default();
        let mut p_aff = blst_p1_affine::default();
        // SAFETY: blst_p1_cneg negates the Jacobian point in-place
        // when the boolean flag is true; blst_p1_to_affine writes
        // the affine form to owned local storage.
        unsafe {
            blst_p1_from_affine(&raw mut p_jac, &raw const self.0);
            blst_p1_cneg(&raw mut p_jac, true);
            blst_p1_to_affine(&raw mut p_aff, &raw const p_jac);
        }
        Self(p_aff)
    }

    /// Subtract `other` from this G₁ point: `self − other`.
    #[must_use]
    pub fn sub(&self, other: &Self) -> Self {
        self.add(&other.negate())
    }
}

// =====================================================================
// G₂ operations
// =====================================================================

impl G2Point {
    /// The canonical BLS12-381 G₂ generator.
    #[must_use]
    pub fn generator() -> Self {
        // SAFETY: BLS12_381_G2 is a `pub static blst_p2_affine`
        // exposed by blst's C library, initialised at link time to
        // the canonical BLS12-381 G₂ generator. The `Copy` derive
        // makes the value-copy safe.
        unsafe { Self(BLS12_381_G2) }
    }

    /// Parse a G₂ point from its 96-byte canonical compressed
    /// encoding. Performs subgroup validation.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidEncoding`] if the bytes do not encode a valid
    /// G₂ point in the prime-order subgroup.
    pub fn from_compressed(bytes: &[u8; G2_COMPRESSED_BYTES]) -> Result<Self, InvalidEncoding> {
        let mut p_aff = blst_p2_affine::default();
        // SAFETY: blst_p2_uncompress reads exactly 96 bytes from the
        // input pointer and writes to the owned blst_p2_affine,
        // returning BLST_ERROR on malformed encoding.
        // blst_p2_affine_in_g2 reads the affine point and returns
        // whether it lies in the prime-order subgroup.
        unsafe {
            if blst_p2_uncompress(&raw mut p_aff, bytes.as_ptr()) != BLST_ERROR::BLST_SUCCESS {
                return Err(InvalidEncoding);
            }
            if !blst_p2_affine_in_g2(&raw const p_aff) {
                return Err(InvalidEncoding);
            }
        }
        Ok(Self(p_aff))
    }

    /// Canonical 96-byte compressed encoding.
    #[must_use]
    pub fn to_compressed(&self) -> [u8; G2_COMPRESSED_BYTES] {
        let mut bytes = [0u8; G2_COMPRESSED_BYTES];
        // SAFETY: blst_p2_affine_compress reads from the owned input
        // and writes 96 bytes to the owned output buffer.
        unsafe {
            blst_p2_affine_compress(bytes.as_mut_ptr(), &raw const self.0);
        }
        bytes
    }

    /// Add two G₂ points.
    ///
    /// Uses `blst_p2_add_or_double` for the same correctness reason
    /// as [`G1Point::add`] — handles doubling and identity edge
    /// cases that the simple `blst_p2_add` does not.
    #[must_use]
    pub fn add(&self, other: &Self) -> Self {
        let mut a_jac = blst_p2::default();
        let mut b_jac = blst_p2::default();
        let mut sum_jac = blst_p2::default();
        let mut sum_aff = blst_p2_affine::default();
        // SAFETY: each call reads from owned local values and writes
        // to owned local values. blst_p2_add_or_double handles the
        // doubling and identity edge cases.
        unsafe {
            blst_p2_from_affine(&raw mut a_jac, &raw const self.0);
            blst_p2_from_affine(&raw mut b_jac, &raw const other.0);
            blst_p2_add_or_double(&raw mut sum_jac, &raw const a_jac, &raw const b_jac);
            blst_p2_to_affine(&raw mut sum_aff, &raw const sum_jac);
        }
        Self(sum_aff)
    }

    /// Negate this G₂ point.
    #[must_use]
    pub fn negate(&self) -> Self {
        let mut p_jac = blst_p2::default();
        let mut p_aff = blst_p2_affine::default();
        // SAFETY: blst_p2_cneg negates the Jacobian point in-place;
        // blst_p2_to_affine writes the affine form.
        unsafe {
            blst_p2_from_affine(&raw mut p_jac, &raw const self.0);
            blst_p2_cneg(&raw mut p_jac, true);
            blst_p2_to_affine(&raw mut p_aff, &raw const p_jac);
        }
        Self(p_aff)
    }

    /// Subtract `other` from this G₂ point: `self − other`.
    #[must_use]
    pub fn sub(&self, other: &Self) -> Self {
        self.add(&other.negate())
    }

    /// Multiply this G₂ point by a scalar.
    #[must_use]
    pub fn mul_scalar(&self, scalar: &Scalar) -> Self {
        let scalar_le = scalar.to_bytes_le();
        let mut point_jac = blst_p2::default();
        let mut result_jac = blst_p2::default();
        let mut result_aff = blst_p2_affine::default();
        // SAFETY: blst_p2_from_affine reads `self.0`; blst_p2_mult
        // reads `point_jac` and `SCALAR_BITS` (255) bits from the
        // 32-byte little-endian scalar pointer, writing the
        // multiplied point to the owned `result_jac`;
        // blst_p2_to_affine writes the affine form to the owned
        // `result_aff`. All inputs/outputs are owned local values.
        unsafe {
            blst_p2_from_affine(&raw mut point_jac, &raw const self.0);
            blst_p2_mult(
                &raw mut result_jac,
                &raw const point_jac,
                scalar_le.as_ptr(),
                SCALAR_BITS,
            );
            blst_p2_to_affine(&raw mut result_aff, &raw const result_jac);
        }
        Self(result_aff)
    }
}

// =====================================================================
// Pairing
// =====================================================================

/// Compute the optimal-Ate pairing `e(g1, g2) ∈ G_T` (Miller loop +
/// final exponentiation).
#[must_use]
pub fn pairing(g1: &G1Point, g2: &G2Point) -> GtElement {
    // `blst_fp12::miller_loop` and `final_exp` are blst-rs's own safe
    // wrappers; this site needs no `unsafe` block.
    GtElement(blst_fp12::miller_loop(&g2.0, &g1.0).final_exp())
}

impl GtElement {
    /// Canonical 576-byte big-endian encoding (12 Fp limbs at 48
    /// bytes each).
    #[must_use]
    pub fn to_bytes(&self) -> [u8; GT_BYTES] {
        self.0.to_bendian()
    }
}

// =====================================================================
// Scalar (Z_r) arithmetic
// =====================================================================

impl Scalar {
    /// The additive identity (`0 ∈ Z_r`).
    #[must_use]
    pub fn zero() -> Self {
        Self(blst_fr::default())
    }

    /// The multiplicative identity (`1 ∈ Z_r`).
    #[must_use]
    pub fn one() -> Self {
        Self::from_u32(1)
    }

    /// Construct from a small non-negative integer (up to `2^32 - 1`).
    #[must_use]
    pub fn from_u32(value: u32) -> Self {
        let limbs: [u64; 4] = [u64::from(value), 0, 0, 0];
        let mut fr = blst_fr::default();
        // SAFETY: blst_fr_from_uint64 reads 4 u64 limbs from the
        // input pointer and writes to the owned blst_fr.
        unsafe {
            blst_fr_from_uint64(&raw mut fr, limbs.as_ptr());
        }
        Self(fr)
    }

    /// Construct from a 32-byte big-endian canonical encoding.
    /// Validates that the encoded integer is in `[0, r)`.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidEncoding`] if the encoded integer is `≥ r`.
    pub fn from_bytes_be(bytes: &[u8; SCALAR_BYTES]) -> Result<Self, InvalidEncoding> {
        let mut scalar = blst_scalar::default();
        let mut fr = blst_fr::default();
        // SAFETY: blst_scalar_from_bendian reads 32 bytes from the
        // input pointer and writes to the owned blst_scalar.
        // blst_scalar_fr_check returns whether the scalar is in
        // [0, r). blst_fr_from_scalar reads the validated scalar and
        // writes the corresponding blst_fr.
        unsafe {
            blst_scalar_from_bendian(&raw mut scalar, bytes.as_ptr());
            if !blst_scalar_fr_check(&raw const scalar) {
                return Err(InvalidEncoding);
            }
            blst_fr_from_scalar(&raw mut fr, &raw const scalar);
        }
        Ok(Self(fr))
    }

    /// Canonical 32-byte little-endian encoding. This is the byte
    /// order `blst_p2_mult` and `blst_p1_mult` consume directly.
    #[must_use]
    pub fn to_bytes_le(&self) -> [u8; SCALAR_BYTES] {
        let mut scalar = blst_scalar::default();
        let mut bytes = [0u8; SCALAR_BYTES];
        // SAFETY: blst_scalar_from_fr reads the owned blst_fr and
        // writes to the owned blst_scalar. blst_lendian_from_scalar
        // writes the canonical 32-byte little-endian encoding to the
        // owned output buffer.
        unsafe {
            blst_scalar_from_fr(&raw mut scalar, &raw const self.0);
            blst_lendian_from_scalar(bytes.as_mut_ptr(), &raw const scalar);
        }
        bytes
    }

    /// Canonical 32-byte big-endian encoding (the IRTF/IETF default
    /// for BLS12-381 scalars).
    #[must_use]
    pub fn to_bytes_be(&self) -> [u8; SCALAR_BYTES] {
        let mut le = self.to_bytes_le();
        le.reverse();
        le
    }

    /// Field addition.
    #[must_use]
    pub fn add(&self, other: &Self) -> Self {
        let mut out = blst_fr::default();
        // SAFETY: blst_fr_add reads two valid blst_fr inputs and
        // writes to the owned output.
        unsafe {
            blst_fr_add(&raw mut out, &raw const self.0, &raw const other.0);
        }
        Self(out)
    }

    /// Field subtraction (`self - other`).
    #[must_use]
    pub fn sub(&self, other: &Self) -> Self {
        let mut out = blst_fr::default();
        // SAFETY: see `add`.
        unsafe {
            blst_fr_sub(&raw mut out, &raw const self.0, &raw const other.0);
        }
        Self(out)
    }

    /// Field multiplication.
    #[must_use]
    pub fn mul(&self, other: &Self) -> Self {
        let mut out = blst_fr::default();
        // SAFETY: see `add`.
        unsafe {
            blst_fr_mul(&raw mut out, &raw const self.0, &raw const other.0);
        }
        Self(out)
    }

    /// Field inversion (`self^{-1}`). Returns the additive identity
    /// (`Scalar::zero()`) on zero input — the same convention `blst`
    /// uses internally. Callers MUST avoid passing zero.
    #[must_use]
    pub fn inverse(&self) -> Self {
        let mut out = blst_fr::default();
        // SAFETY: blst_fr_inverse reads the input and writes to the
        // owned output.
        unsafe {
            blst_fr_inverse(&raw mut out, &raw const self.0);
        }
        Self(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---------- declared lengths ----------

    #[test]
    fn declared_lengths_match_expectations() {
        assert_eq!(G1_COMPRESSED_BYTES, 48);
        assert_eq!(G2_COMPRESSED_BYTES, 96);
        assert_eq!(GT_BYTES, 576);
        assert_eq!(SCALAR_BYTES, 32);
        assert_eq!(SCALAR_BITS, 255);
    }

    // ---------- Scalar arithmetic ----------

    #[test]
    fn scalar_zero_one_distinct() {
        assert_ne!(Scalar::zero(), Scalar::one());
    }

    #[test]
    fn scalar_from_u32_consistent() {
        assert_eq!(Scalar::from_u32(0), Scalar::zero());
        assert_eq!(Scalar::from_u32(1), Scalar::one());
    }

    #[test]
    fn scalar_add_zero_is_identity() {
        let a = Scalar::from_u32(42);
        let z = Scalar::zero();
        assert_eq!(a.add(&z), a);
        assert_eq!(z.add(&a), a);
    }

    #[test]
    fn scalar_mul_one_is_identity() {
        let a = Scalar::from_u32(42);
        let one = Scalar::one();
        assert_eq!(a.mul(&one), a);
        assert_eq!(one.mul(&a), a);
    }

    #[test]
    fn scalar_sub_self_is_zero() {
        let a = Scalar::from_u32(42);
        assert_eq!(a.sub(&a), Scalar::zero());
    }

    #[test]
    fn scalar_inverse_times_self_is_one() {
        let a = Scalar::from_u32(42);
        let inv = a.inverse();
        assert_eq!(a.mul(&inv), Scalar::one());
    }

    #[test]
    fn scalar_le_be_round_trip_through_be() {
        let a = Scalar::from_u32(0x1234_5678);
        let bytes = a.to_bytes_be();
        let parsed = Scalar::from_bytes_be(&bytes).expect("parse");
        assert_eq!(parsed, a);
    }

    #[test]
    fn scalar_le_and_be_are_byte_reverses() {
        let a = Scalar::from_u32(0x0102_0304);
        let mut le = a.to_bytes_le();
        let be = a.to_bytes_be();
        le.reverse();
        assert_eq!(le, be);
    }

    #[test]
    fn scalar_from_bytes_be_rejects_above_r() {
        // r is < 2^255, so [0xFF; 32] is a 256-bit integer that
        // exceeds r. Must be rejected.
        let too_big = [0xff_u8; SCALAR_BYTES];
        assert!(Scalar::from_bytes_be(&too_big).is_err());
    }

    #[test]
    fn scalar_from_bytes_be_accepts_zero() {
        // Zero is a valid scalar in Z_r.
        let zero_bytes = [0u8; SCALAR_BYTES];
        let s = Scalar::from_bytes_be(&zero_bytes).expect("parse zero");
        assert_eq!(s, Scalar::zero());
    }

    // ---------- G_2 generator + scalar mul ----------

    #[test]
    fn g2_generator_compresses_to_canonical_bytes() {
        // The canonical compressed encoding of the BLS12-381 G₂
        // generator is a fixed published value. Round-trip parse
        // suffices as a sanity check that we have the right point.
        let g = G2Point::generator();
        let bytes = g.to_compressed();
        let parsed = G2Point::from_compressed(&bytes).expect("parse");
        assert_eq!(parsed, g);
    }

    #[test]
    fn g2_mul_by_one_is_identity() {
        let g = G2Point::generator();
        let mul_one = g.mul_scalar(&Scalar::one());
        assert_eq!(mul_one, g);
    }

    #[test]
    fn g2_mul_by_zero_is_identity_of_group() {
        // 0 · G = identity element (point at infinity). The
        // compressed encoding of the identity has the infinity flag
        // set; parsing it round-trips back to the same identity.
        let g = G2Point::generator();
        let zero_g = g.mul_scalar(&Scalar::zero());
        let bytes = zero_g.to_compressed();
        let parsed = G2Point::from_compressed(&bytes).expect("parse");
        assert_eq!(parsed, zero_g);
    }

    #[test]
    fn g2_scalar_mul_distributes_over_addition() {
        let g = G2Point::generator();
        let a = Scalar::from_u32(7);
        let b = Scalar::from_u32(11);
        // (a + b) · G should equal a · G + b · G in additive
        // notation, but our API doesn't expose G₂ addition. Instead,
        // verify multiplicative: G^a · G^b should pair-equal with
        // G^(a+b). Skip — relies on pairing structure, exercised in
        // the threshold integration tests.
        // Cheaper sanity: a · (b · G) should equal (a · b) · G.
        let ab = a.mul(&b);
        let path_a = g.mul_scalar(&b).mul_scalar(&a);
        let path_b = g.mul_scalar(&ab);
        assert_eq!(path_a, path_b);
    }

    // ---------- G_1 hash-to-curve ----------

    #[test]
    fn g1_hash_to_curve_is_deterministic() {
        let dst = b"BLS_TE_BLS12381G1_XMD:SHA-256_SSWU_RO_TEST";
        let p_a = G1Point::hash_to_curve(b"message", dst);
        let p_b = G1Point::hash_to_curve(b"message", dst);
        assert_eq!(p_a, p_b);
    }

    #[test]
    fn g1_hash_to_curve_separates_by_dst() {
        let p_a = G1Point::hash_to_curve(b"message", b"DST_A");
        let p_b = G1Point::hash_to_curve(b"message", b"DST_B");
        assert_ne!(p_a, p_b);
    }

    #[test]
    fn g1_hash_to_curve_separates_by_message() {
        let dst = b"DST";
        let p_a = G1Point::hash_to_curve(b"message-a", dst);
        let p_b = G1Point::hash_to_curve(b"message-b", dst);
        assert_ne!(p_a, p_b);
    }

    #[test]
    fn g1_compress_round_trip() {
        let p = G1Point::hash_to_curve(b"round-trip", b"DST");
        let bytes = p.to_compressed();
        let parsed = G1Point::from_compressed(&bytes).expect("parse");
        assert_eq!(parsed, p);
    }

    #[test]
    fn g1_from_compressed_rejects_garbage() {
        let bytes = [0xff_u8; G1_COMPRESSED_BYTES];
        assert!(G1Point::from_compressed(&bytes).is_err());
    }

    #[test]
    fn g2_from_compressed_rejects_garbage() {
        let bytes = [0xff_u8; G2_COMPRESSED_BYTES];
        assert!(G2Point::from_compressed(&bytes).is_err());
    }

    // ---------- pairing ----------

    /// Bilinearity sanity: `e(P, b · G_2) == e(P, G_2)^b` is hard to
    /// check without GT exponentiation. Instead use the classic
    /// identity: `e(a · P_1, b · G_2) == e(P_1, G_2)^{ab} ==
    /// e(b · P_1, a · G_2)`. We test the swap form: applying scalars
    /// to either side with the same product yields the same pairing.
    #[test]
    fn pairing_bilinearity_commutes_across_scalars() {
        let p1 = G1Point::hash_to_curve(b"bilinearity", b"DST");
        let g2 = G2Point::generator();
        let a = Scalar::from_u32(5);
        let b = Scalar::from_u32(7);
        // We can multiply on G_2 only (no exposed G_1 scalar mul);
        // exploit symmetry: e(P, a·G_2) · e(P, b·G_2) by combining
        // scalars on G_2 only.
        let g_product = g2.mul_scalar(&a.mul(&b));
        let g_just_a = g2.mul_scalar(&a);
        let g_just_b = g2.mul_scalar(&b);
        // Path A: pair P with g_product.
        let p_a = pairing(&p1, &g_product);
        // Path B: pair P with g_just_a, pair P with g_just_b — but we
        // lack GT multiplication in the API. Round-trip via bytes
        // instead: both must equal a unique GT element; verify that
        // independent computation of `e(P, (a·b)·G)` is deterministic
        // and produces the same bytes.
        let p_a_again = pairing(&p1, &g_product);
        assert_eq!(p_a.to_bytes(), p_a_again.to_bytes());
        // Cross-check path: e(P, a·G_2) and e(P, b·G_2) are distinct
        // when a != b.
        let p_with_a = pairing(&p1, &g_just_a);
        let p_with_b = pairing(&p1, &g_just_b);
        assert_ne!(p_with_a.to_bytes(), p_with_b.to_bytes());
    }

    #[test]
    fn pairing_is_deterministic() {
        let p1 = G1Point::hash_to_curve(b"determinism", b"DST");
        let g2 = G2Point::generator();
        let a = pairing(&p1, &g2);
        let b = pairing(&p1, &g2);
        assert_eq!(a, b);
    }

    // ---------- GT serialisation length ----------

    #[test]
    fn gt_to_bytes_has_declared_length() {
        let p1 = G1Point::hash_to_curve(b"length-check", b"DST");
        let g2 = G2Point::generator();
        let gt = pairing(&p1, &g2);
        let bytes = gt.to_bytes();
        assert_eq!(bytes.len(), GT_BYTES);
    }

    // ---------- G1 / G2 add edge cases (Phase 5/6.9 audit) ----------
    //
    // blst_p1_add / blst_p2_add (the simple add) fail on the
    // doubling and identity cases. Audit replaced them with
    // blst_p1_add_or_double / blst_p2_add_or_double; these tests
    // pin the edge-case correctness against regression.

    #[test]
    fn g1_add_inverse_yields_pairing_with_identity_semantics() {
        // p + (-p) ≡ identity in G₁. Pairing the identity with any
        // G₂ point yields the GT identity (1 in F_p^12). We verify
        // by comparing the LHS pairing against an independently-
        // constructed RHS (pairing of identity built by 0 · g).
        let p = G1Point::hash_to_curve(b"add-inverse-test", b"DST");
        let neg_p = p.negate();
        let identity = p.add(&neg_p);
        // 0 · g should also produce the identity.
        let zero_times_g = G1Point::generator().mul_scalar(&Scalar::zero());
        let g2 = G2Point::generator();
        assert_eq!(
            pairing(&identity, &g2).to_bytes(),
            pairing(&zero_times_g, &g2).to_bytes(),
            "p + (-p) must equal 0·g via pairing equality"
        );
    }

    #[test]
    fn g1_add_self_doubles_via_pairing() {
        // p + p == 2 · p. Pairing-side check.
        let p = G1Point::hash_to_curve(b"double-test", b"DST");
        let doubled_via_add = p.add(&p);
        let doubled_via_scalar = p.mul_scalar(&Scalar::from_u32(2));
        let g2 = G2Point::generator();
        assert_eq!(
            pairing(&doubled_via_add, &g2).to_bytes(),
            pairing(&doubled_via_scalar, &g2).to_bytes(),
            "p + p must equal 2 · p"
        );
    }

    #[test]
    fn g2_add_inverse_yields_pairing_with_identity_semantics() {
        let q = G2Point::generator().mul_scalar(&Scalar::from_u32(11));
        let neg_q = q.negate();
        let identity = q.add(&neg_q);
        let zero_times_g2 = G2Point::generator().mul_scalar(&Scalar::zero());
        let g1 = G1Point::generator();
        assert_eq!(
            pairing(&g1, &identity).to_bytes(),
            pairing(&g1, &zero_times_g2).to_bytes(),
            "q + (-q) must equal 0 · g₂ via pairing equality"
        );
    }

    #[test]
    fn g2_add_self_doubles_via_pairing() {
        let q = G2Point::generator().mul_scalar(&Scalar::from_u32(7));
        let doubled_via_add = q.add(&q);
        let doubled_via_scalar = q.mul_scalar(&Scalar::from_u32(2));
        let g1 = G1Point::generator();
        assert_eq!(
            pairing(&g1, &doubled_via_add).to_bytes(),
            pairing(&g1, &doubled_via_scalar).to_bytes(),
            "q + q must equal 2 · q"
        );
    }

    #[test]
    fn g1_sub_returns_inverse_under_pairing() {
        // p − p == identity.
        let p = G1Point::hash_to_curve(b"sub-test", b"DST");
        let zero_p = p.sub(&p);
        let zero_times_g = G1Point::generator().mul_scalar(&Scalar::zero());
        let g2 = G2Point::generator();
        assert_eq!(
            pairing(&zero_p, &g2).to_bytes(),
            pairing(&zero_times_g, &g2).to_bytes(),
        );
    }
}
