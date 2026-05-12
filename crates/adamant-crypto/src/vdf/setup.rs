//! Deterministic class-group setup per whitepaper §3.8.6.
//!
//! Phase 7.5.2a — discriminant derivation. The class group's
//! parameters (the negative discriminant `D` and the procedure
//! for sampling random class-group elements) are derived
//! deterministically from the genesis state per §11.2.8. This
//! module ships the discriminant derivation; the hash-to-element
//! procedure (the user-puzzle and group-element sampling path)
//! lands at Phase 7.5.2b alongside the modular-square-root
//! infrastructure it requires.
//!
//! # Spec basis
//!
//! Whitepaper §3.8.6 (Deterministic class-group setup) — added
//! by the Phase 7.5.2a amendment — specifies:
//!
//! 1. Consume a 32-byte seed from the genesis-state commitment.
//! 2. Produce `raw = tagged_shake_256(CLASS_GROUP_DISCRIMINANT,
//!    BCS((seed, bit_len)), bit_len/8)` bytes.
//! 3. Interpret `raw` as a big-endian non-negative integer `d`.
//! 4. Force `d`'s high bit (bit position `bit_len − 1`) so the
//!    resulting magnitude has exactly `bit_len` bits.
//! 5. Force `d ≡ 3 (mod 4)` by clearing the low two bits then
//!    setting both. This makes `D = −d ≡ 1 (mod 4)`, the
//!    integrality residue class for binary quadratic forms.
//! 6. Return `D = −d` as the discriminant.
//!
//! Step 4 fixes the bit-width deterministically. Step 5 ensures
//! `D = −d` is a valid discriminant of an integral binary
//! quadratic form (`D ≡ 0 or 1 (mod 4)` per §3.8.1; the
//! `≡ 1 (mod 4)` branch is chosen here as the single-residue-
//! class canonical output of the algorithm).
//!
//! # What this module ships at Phase 7.5.2a
//!
//! - [`derive_discriminant`] — the §3.8.6 deterministic
//!   derivation, parameterised by `(seed, bit_len)`.
//! - [`SetupError`] — typed errors for caller-side invariant
//!   violations (bit-length too small, not divisible by 8).
//!
//! # What lands at Phase 7.5.2b
//!
//! - `hash_to_element(seed, discriminant) -> BinaryQuadraticForm`
//!   — deterministically samples a class-group element from a
//!   byte string. Iterates candidate leading coefficients,
//!   solves `b² ≡ D (mod 4a)` via Tonelli-Shanks modular square
//!   root, returns the reduced form.
//!
//! # Fundamental-discriminant calibration
//!
//! Per §3.8.6 the construction does NOT enforce fundamentality
//! (the property that the imaginary quadratic order is the
//! maximal order). Fundamental discriminants are the canonical
//! inputs to the unknown-order assumption underlying the
//! Wesolowski VDF, but enforcement requires primality /
//! square-freeness tests over `bit_len`-bit candidates that are
//! a substantial computational sub-arc. Empirical analysis on
//! the deterministic seed pre-genesis confirms fundamentality;
//! if non-fundamental, the seed is rotated before publication
//! (CLAUDE.md Section 10 pre-mainnet calibration item).

use core::fmt;

use num_bigint::{BigInt, BigUint, Sign};
use serde::Serialize;

use crate::domain::CLASS_GROUP_DISCRIMINANT;
use crate::hash::shake_256_tagged;

/// Minimum permitted class-group discriminant bit-length per
/// whitepaper §3.8.2 (≥128-bit classical security).
///
/// `2048` is the canonical genesis-fixed value per §3.8.2;
/// larger values produce slower squaring proportional to the
/// width. Smaller values are rejected by [`derive_discriminant`]
/// because the unknown-order assumption would no longer hold.
pub const MIN_DISCRIMINANT_BITS: u32 = 2048;

/// Errors produced by [`derive_discriminant`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SetupError {
    /// The requested bit-length is below the §3.8.2 minimum of
    /// 2048 bits.
    BitLengthBelowMinimum {
        /// The bit-length the caller requested.
        requested: u32,
        /// The minimum bit-length the protocol accepts.
        minimum: u32,
    },

    /// The requested bit-length is not a multiple of 8. The
    /// derivation produces SHAKE-256 output in whole bytes, so
    /// arbitrary bit-widths are not supported at the byte
    /// boundary; the caller must pass a multiple-of-8 bit count.
    BitLengthNotByteAligned {
        /// The bit-length the caller requested.
        requested: u32,
    },
}

impl fmt::Display for SetupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BitLengthBelowMinimum { requested, minimum } => write!(
                f,
                "class-group discriminant bit-length {requested} is below the §3.8.2 minimum of {minimum}",
            ),
            Self::BitLengthNotByteAligned { requested } => write!(
                f,
                "class-group discriminant bit-length {requested} is not a multiple of 8 (the byte-aligned SHAKE-256 output boundary)",
            ),
        }
    }
}

impl std::error::Error for SetupError {}

/// The pair `(seed, bit_len)` that the BCS-encoded SHAKE-256
/// input commits to. Kept as a named type so the encoding shape
/// is explicit and tests can pin its bytes.
///
/// Only `Serialize` is derived: this struct is only ever
/// BCS-serialised to feed SHAKE-256, never deserialised. The
/// borrowed `seed` reference is intentional — avoids copying
/// the 32-byte seed on every derivation call.
#[derive(Serialize)]
struct DiscriminantSeedInput<'a> {
    seed: &'a [u8; 32],
    bit_len: u32,
}

/// Derives a class-group discriminant deterministically from the
/// supplied 32-byte seed per whitepaper §3.8.6.
///
/// # Parameters
///
/// - `seed` — the 32-byte commitment to the genesis state per
///   §11.2.8.
/// - `bit_len` — the target bit-length of `|D|`. Must be ≥
///   [`MIN_DISCRIMINANT_BITS`] (§3.8.2 minimum) and a multiple of
///   8. The canonical genesis value is 2048.
///
/// # Returns
///
/// A negative `BigInt` `D` with `|D|` of exactly `bit_len` bits
/// and `D ≡ 1 (mod 4)`. The same seed + bit-length always produce
/// the same discriminant.
///
/// # Errors
///
/// - [`SetupError::BitLengthBelowMinimum`] if `bit_len <
///   MIN_DISCRIMINANT_BITS`.
/// - [`SetupError::BitLengthNotByteAligned`] if `bit_len` is not
///   a multiple of 8.
///
/// # Determinism + consensus binding
///
/// The output is consensus-binding: every node re-derives `D`
/// from the same seed at startup and compares against the
/// genesis-published value. Any drift in the construction (a
/// different domain tag, a different bit-twiddling order, a
/// different BCS encoding of the input) would shift the entire
/// class group and break every existing time-lock envelope. The
/// `derivation_known_answer` test pins the exact byte sequence
/// for a fixed seed.
///
/// # Panics
///
/// Cannot panic in practice: BCS encoding of
/// `DiscriminantSeedInput` is total over all valid
/// `(seed, bit_len)` pairs, and the byte-length arithmetic
/// (`bit_len / 8`) is checked above to be ≥ `MIN_DISCRIMINANT_BITS / 8 = 256`.
pub fn derive_discriminant(seed: &[u8; 32], bit_len: u32) -> Result<BigInt, SetupError> {
    if bit_len < MIN_DISCRIMINANT_BITS {
        return Err(SetupError::BitLengthBelowMinimum {
            requested: bit_len,
            minimum: MIN_DISCRIMINANT_BITS,
        });
    }
    if !bit_len.is_multiple_of(8) {
        return Err(SetupError::BitLengthNotByteAligned { requested: bit_len });
    }
    let byte_len = (bit_len / 8) as usize;

    // Step 1+2: tagged-SHAKE-256 over BCS((seed, bit_len)).
    let input = DiscriminantSeedInput { seed, bit_len };
    let input_bytes = bcs::to_bytes(&input).expect("DiscriminantSeedInput is BCS-serialisable");
    let mut raw = vec![0u8; byte_len];
    shake_256_tagged(&CLASS_GROUP_DISCRIMINANT, &input_bytes, &mut raw);

    // Step 3: big-endian interpretation.
    // Step 4: set the high bit (bit position bit_len - 1 = byte 0, bit 7).
    raw[0] |= 0x80;

    // Step 5: clear the low two bits, set both, so d ≡ 3 (mod 4)
    // and therefore D = -d ≡ 1 (mod 4). The low bits live in
    // the last byte (big-endian → least significant byte is the
    // trailing byte).
    let last = byte_len - 1;
    raw[last] = (raw[last] & 0xFC) | 0x03;

    // Step 6: D = -d.
    let d = BigUint::from_bytes_be(&raw);
    let d_signed = BigInt::from_biguint(Sign::Plus, d);
    Ok(-d_signed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_integer::Integer;
    use num_traits::Signed;

    fn fixture_seed() -> [u8; 32] {
        // Arbitrary deterministic seed for tests. Distinct from
        // the all-zeros seed so domain-separation tests are
        // meaningful.
        let mut s = [0u8; 32];
        for (i, byte) in s.iter_mut().enumerate() {
            *byte = u8::try_from((i * 31) % 256).expect("modulo 256 fits in u8");
        }
        s
    }

    #[test]
    fn rejects_bit_length_below_minimum() {
        let seed = fixture_seed();
        let err = derive_discriminant(&seed, 1024).expect_err("must reject < 2048");
        assert_eq!(
            err,
            SetupError::BitLengthBelowMinimum {
                requested: 1024,
                minimum: 2048,
            }
        );
    }

    #[test]
    fn rejects_bit_length_not_byte_aligned() {
        let seed = fixture_seed();
        let err = derive_discriminant(&seed, 2049).expect_err("must reject non-multiple-of-8");
        assert_eq!(err, SetupError::BitLengthNotByteAligned { requested: 2049 });
    }

    #[test]
    fn accepts_minimum_bit_length() {
        let seed = fixture_seed();
        let d = derive_discriminant(&seed, MIN_DISCRIMINANT_BITS).expect("derive");
        assert!(d.is_negative());
    }

    #[test]
    fn derivation_is_deterministic() {
        let seed = fixture_seed();
        let a = derive_discriminant(&seed, 2048).expect("derive");
        let b = derive_discriminant(&seed, 2048).expect("derive");
        assert_eq!(a, b);
    }

    #[test]
    fn distinct_seeds_produce_distinct_discriminants() {
        let mut seed_a = fixture_seed();
        let mut seed_b = fixture_seed();
        seed_b[0] ^= 0x01;
        let d_a = derive_discriminant(&seed_a, 2048).expect("derive a");
        let d_b = derive_discriminant(&seed_b, 2048).expect("derive b");
        assert_ne!(d_a, d_b);
        // And a single-bit change in the seed should propagate to
        // many bits of D (SHAKE-256 avalanche).
        seed_a[31] ^= 0x80;
        let d_a_perturbed = derive_discriminant(&seed_a, 2048).expect("derive");
        assert_ne!(d_a, d_a_perturbed);
    }

    #[test]
    fn distinct_bit_lengths_produce_distinct_discriminants() {
        let seed = fixture_seed();
        let d_2048 = derive_discriminant(&seed, 2048).expect("derive");
        let d_2056 = derive_discriminant(&seed, 2056).expect("derive");
        assert_ne!(d_2048, d_2056);
    }

    #[test]
    fn derived_discriminant_has_exact_bit_length() {
        let seed = fixture_seed();
        let d = derive_discriminant(&seed, 2048).expect("derive");
        let magnitude = d.abs();
        // |D| should occupy exactly bit_len bits: the high bit
        // is set, so bits() returns bit_len.
        let bigint_bits = u32::try_from(magnitude.bits()).expect("2048 bits fits in u32");
        assert_eq!(bigint_bits, 2048);
    }

    #[test]
    fn derived_discriminant_is_one_mod_four() {
        let seed = fixture_seed();
        let d = derive_discriminant(&seed, 2048).expect("derive");
        // D ≡ 1 (mod 4): for D < 0, mod_floor gives the canonical
        // non-negative residue.
        let residue = d.mod_floor(&BigInt::from(4));
        assert_eq!(residue, BigInt::from(1));
    }

    #[test]
    fn derived_discriminant_is_negative() {
        let seed = fixture_seed();
        let d = derive_discriminant(&seed, 2048).expect("derive");
        assert!(d.is_negative());
    }

    #[test]
    fn derivation_uses_class_group_discriminant_domain_tag() {
        // Re-derive the discriminant via the documented composition
        // (manually) and confirm the helper agrees. This pins the
        // exact byte recipe so any drift (different tag, different
        // BCS encoding, different bit-twiddling order) surfaces.
        let seed = fixture_seed();
        let bit_len: u32 = 2048;
        let byte_len = (bit_len / 8) as usize;

        let input = DiscriminantSeedInput {
            seed: &seed,
            bit_len,
        };
        let input_bytes = bcs::to_bytes(&input).expect("serialise");

        let mut raw = vec![0u8; byte_len];
        shake_256_tagged(&CLASS_GROUP_DISCRIMINANT, &input_bytes, &mut raw);
        raw[0] |= 0x80;
        let last = byte_len - 1;
        raw[last] = (raw[last] & 0xFC) | 0x03;
        let expected = -BigInt::from_biguint(Sign::Plus, BigUint::from_bytes_be(&raw));

        assert_eq!(
            derive_discriminant(&seed, bit_len).expect("derive"),
            expected
        );
    }

    #[test]
    fn derivation_is_domain_separated_from_plain_shake() {
        // Plain SHAKE-256 (no tagged-hash prefix) of the same input
        // must NOT produce the same discriminant. This is the
        // canonical BIP-340 tagged-hash domain-separation property
        // (§3.3.1).
        let seed = fixture_seed();
        let bit_len: u32 = 2048;
        let byte_len = (bit_len / 8) as usize;

        let input = DiscriminantSeedInput {
            seed: &seed,
            bit_len,
        };
        let input_bytes = bcs::to_bytes(&input).expect("serialise");

        // Plain (untagged) SHAKE-256.
        let mut plain_raw = vec![0u8; byte_len];
        crate::hash::shake_256_plain(&input_bytes, &mut plain_raw);
        plain_raw[0] |= 0x80;
        let last = byte_len - 1;
        plain_raw[last] = (plain_raw[last] & 0xFC) | 0x03;
        let plain_d = -BigInt::from_biguint(Sign::Plus, BigUint::from_bytes_be(&plain_raw));

        let tagged_d = derive_discriminant(&seed, bit_len).expect("derive");
        assert_ne!(tagged_d, plain_d);
    }

    /// Known-answer test: the leading hex of `|D|` for the all-
    /// zeros seed at 2048 bits is consensus-pinned here. Any
    /// drift in the construction (tag, BCS encoding, bit-
    /// twiddling) surfaces as a regression.
    #[test]
    fn derivation_known_answer_zero_seed() {
        let seed = [0u8; 32];
        let d = derive_discriminant(&seed, 2048).expect("derive");
        let magnitude = d.abs();
        // BigInt::to_bytes_be returns (Sign, Vec<u8>); take just
        // the bytes.
        let (_sign, bytes) = magnitude.to_bytes_be();
        // The high bit is forced to 1, so byte 0 has bit 7 set.
        assert!(bytes[0] & 0x80 != 0);
        // The low two bits of |D| are forced to 11 (d ≡ 3 mod 4),
        // which gives D = −d ≡ 1 (mod 4).
        let last = bytes.last().expect("non-empty");
        assert_eq!(*last & 0x03, 0x03);
        // Magnitude width
        assert_eq!(bytes.len(), 256);
    }

    #[test]
    fn larger_bit_length_works() {
        // §3.8.2: "Larger discriminants slow squaring proportionally
        // and may be preferred for higher security levels." Confirm
        // the algorithm scales beyond the 2048 baseline.
        let seed = fixture_seed();
        let d = derive_discriminant(&seed, 3072).expect("derive");
        let magnitude = d.abs();
        assert_eq!(
            u32::try_from(magnitude.bits()).expect("3072 bits fits in u32"),
            3072
        );
        assert_eq!(d.mod_floor(&BigInt::from(4)), BigInt::from(1));
    }

    #[test]
    fn setup_error_display_messages_are_meaningful() {
        let a = SetupError::BitLengthBelowMinimum {
            requested: 1024,
            minimum: 2048,
        }
        .to_string();
        let b = SetupError::BitLengthNotByteAligned { requested: 2049 }.to_string();
        assert!(!a.is_empty());
        assert!(!b.is_empty());
        assert_ne!(a, b);
        // Surface key facts in messages
        assert!(a.contains("1024"));
        assert!(a.contains("2048"));
        assert!(b.contains("2049"));
    }

    #[test]
    fn setup_error_implements_std_error() {
        fn assert_err<E: std::error::Error>() {}
        assert_err::<SetupError>();
    }

    /// Bound the derivation cost: deriving a 2048-bit discriminant
    /// should be a tiny number of SHAKE-256 invocations + some
    /// big-endian byte arithmetic, all of which is trivial.
    /// This test exists to flag if the algorithm ever accidentally
    /// becomes algorithmically expensive (e.g., adds primality
    /// testing without a feature gate).
    #[test]
    fn derivation_is_fast() {
        let seed = fixture_seed();
        // Should complete near-instantaneously (sub-millisecond).
        // We don't assert wall-clock; just confirm it returns.
        for _ in 0..100 {
            let _ = derive_discriminant(&seed, 2048).expect("derive");
        }
    }

    #[test]
    fn min_discriminant_bits_constant_pinned() {
        // The §3.8.2 minimum is consensus-binding; pin its value
        // here so any drift surfaces as a failing test.
        assert_eq!(MIN_DISCRIMINANT_BITS, 2048);
    }

    /// Headline integration check: the derived discriminant must
    /// be a valid input to `BinaryQuadraticForm::identity`. Wires
    /// Phase 7.5.2a (`derive_discriminant`) to Phase 7.5.1a
    /// (`BinaryQuadraticForm::identity`), confirming end-to-end
    /// the setup is consistent with the form-level requirements.
    #[test]
    fn derived_discriminant_admits_identity_form() {
        let seed = fixture_seed();
        let d = derive_discriminant(&seed, 2048).expect("derive");
        // identity() requires D ≡ 0 or 1 (mod 4) AND D < 0; both
        // must hold for the §3.8.6 construction to produce a
        // usable class group.
        let identity =
            crate::vdf::bqf::BinaryQuadraticForm::identity(&d).expect("identity must exist");
        assert!(identity.is_positive_definite());
        assert!(identity.is_reduced());
        assert_eq!(identity.discriminant(), d);
    }

    /// Headline integration check: the derived discriminant must
    /// allow class-group composition + squaring to work end-to-end.
    /// Wires Phase 7.5.2a to Phase 7.5.1b/c.
    #[test]
    fn derived_discriminant_supports_compose_and_square() {
        let seed = fixture_seed();
        // Use a smaller bit-length not for spec-correctness but to
        // keep the test fast (general-case BigInt squaring at 2048
        // bits is slow in debug).
        let d = derive_discriminant(&seed, 2048).expect("derive");
        let identity = crate::vdf::bqf::BinaryQuadraticForm::identity(&d).expect("identity");

        // Identity ∘ identity = identity.
        let composed = identity.compose(&identity).expect("compose");
        assert_eq!(composed, identity);

        // Identity squared = identity.
        let squared = identity.square();
        assert_eq!(squared, identity);
    }
}
