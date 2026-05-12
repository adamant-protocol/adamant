//! Wesolowski VDF evaluate / prove / verify per whitepaper
//! §3.8.1 + §3.8.7.
//!
//! Phase 7.5.3 ships the three operations that consume the
//! class-group arithmetic + setup landed at Phase 7.5.1 + 7.5.2:
//!
//! - [`evaluate`] — `h = g^(2^T)` via `T` sequential class-group
//!   squarings (the time-lock work).
//! - [`prove`] — produces the Wesolowski proof
//!   `π = g^q` where `q = ⌊2^T / ℓ⌋` and `ℓ = hash_to_prime(g, h, T)`
//!   (the Fiat-Shamir prime challenge).
//! - [`verify`] — the constant-time check `π^ℓ · g^r ≡ h` where
//!   `r = 2^T mod ℓ`. Fast at any `T` because both exponents are
//!   bounded by `ℓ < 2^128`.
//!
//! # Spec basis
//!
//! Whitepaper §3.8.1 gives the Wesolowski construction at the
//! description level; §3.8.7 (Phase 7.5.3 amendment) pins the
//! byte-level algorithms for each operation and for the
//! Fiat-Shamir prime challenge derivation that ties them
//! together.
//!
//! # Adamant-native posture
//!
//! Per CLAUDE.md §14, the Wesolowski operations are Adamant-
//! authored on top of the `vdf::bqf` (class-group arithmetic)
//! and `vdf::modular` (Miller-Rabin / primality) layers also
//! authored by Adamant. No external VDF crate is consumed.
//!
//! # Performance
//!
//! - `evaluate(g, T)`: `T` class-group squarings. Each squaring
//!   is `O(|D|² / 4) = O(|D|²)` `BigInt` operations via Cohen 5.4.8.
//!   For the genesis target `T ∈ [2_000_000, 7_500_000]` and
//!   `|D| ≈ 2048`, evaluate takes ~10-15 seconds on consensus-
//!   grade hardware per §3.8.2.
//! - `prove(g, T)`: approximately `2T` class-group operations
//!   (the `T` from evaluate plus `T − log₂(ℓ) ≈ T` for the
//!   `g^q` exponentiation via square-and-multiply). The
//!   §3.8.7 canonical-prove form is intentionally simple;
//!   future optimisations (Pietrzak halving, Wesolowski
//!   streaming witness tracking) reduce this but are not
//!   required for protocol conformance.
//! - `verify(g, h, T, π)`: `O(log ℓ) ≈ 128` class-group
//!   operations regardless of `T`. Sub-millisecond at any
//!   `T` on consensus-grade hardware.
//!
//! # What this module does NOT cover
//!
//! - **Time-lock envelope encryption / decryption.** The
//!   ChaCha20-Poly1305 envelope wiring (key derivation from `h`
//!   via [`crate::domain::TIME_LOCK_SYMMETRIC_KEY`]) lands at a
//!   subsequent Phase 7.5 sub-arc when the consensus-layer
//!   integration is wired (§8.4.4 round-anchor publication
//!   path).
//! - **Optimisation passes.** Pietrzak halving and Wesolowski's
//!   streaming witness tracking are pre-mainnet performance
//!   work, not protocol-conformance items. The canonical
//!   `evaluate + g^q` form here is what the spec pins.

use num_bigint::BigUint;
use num_integer::Integer;
use num_traits::{One, Zero};
use serde::Serialize;

use crate::domain::WESOLOWSKI_CHALLENGE;
use crate::hash::shake_256_tagged;
use crate::vdf::bqf::BinaryQuadraticForm;
use crate::vdf::modular::is_probable_prime;

/// Bit-length of the Fiat-Shamir prime challenge `ℓ` per
/// whitepaper §3.8.7.
///
/// Genesis-fixed at 128 bits. Wesolowski 2019 §4 soundness:
/// cheating probability is `≤ 1/ℓ ≤ 2^-128`, comfortably above
/// the §3.8.2 128-bit classical security target.
pub const CHALLENGE_BITS: u32 = 128;

/// Number of Miller-Rabin rounds per primality test in the
/// `hash_to_prime` candidate-prime search. 40 rounds gives
/// `4^-40 < 2^-80` soundness error per composite test — the
/// standard cryptographic threshold for any bit-width.
const MILLER_RABIN_ROUNDS: usize = 40;

/// Outer-loop iteration budget for `hash_to_prime`. Each
/// candidate passes primality testing with probability
/// `~1/ln(2^128) ≈ 1/89` (prime number theorem on 128-bit
/// candidates), so the expected outer-loop count is ~89.
/// A budget of 4096 iterations gives essentially zero probability
/// of exhaustion under any reasonable input distribution.
const HASH_TO_PRIME_BUDGET: u64 = 4096;

/// BCS input for the `hash_to_prime` candidate-seed derivation
/// per §3.8.7.
#[derive(Serialize)]
struct HashToPrimeCandidateInput<'a> {
    g_encoded: &'a [u8],
    h_encoded: &'a [u8],
    time_parameter_t: u64,
    counter: u64,
}

/// BCS input for the Miller-Rabin witness derivation inside
/// `hash_to_prime`. Distinct from the candidate-seed input by
/// the witness-index field.
#[derive(Serialize)]
struct HashToPrimeWitnessInput<'a> {
    g_encoded: &'a [u8],
    h_encoded: &'a [u8],
    time_parameter_t: u64,
    counter: u64,
    witness_index: u32,
}

/// Errors produced by [`prove`] and [`verify`] preconditions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WesolowskiError {
    /// The two operands `g` and `h` (or the inputs against which
    /// verification compares) do not share a discriminant. The
    /// Wesolowski VDF operates within a single class group;
    /// composition or equality across class groups is undefined.
    MismatchedDiscriminants,

    /// The supplied class-group element is not positive definite.
    /// The Wesolowski construction over the §3.8 imaginary
    /// quadratic order requires positive definite operands.
    NotPositiveDefinite,

    /// `hash_to_prime` exhausted its outer-loop iteration budget
    /// without finding a prime challenge. Vanishingly improbable
    /// for well-formed inputs (probability `~e^(-4096/89) ≈ 0`);
    /// surfacing this error indicates either a pathological input
    /// or an implementation bug.
    HashToPrimeBudgetExhausted,
}

impl core::fmt::Display for WesolowskiError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::MismatchedDiscriminants => f.write_str(
                "Wesolowski operands must share a discriminant (operate within one class group)",
            ),
            Self::NotPositiveDefinite => f.write_str(
                "Wesolowski operations require positive definite class-group elements (a > 0, c > 0, D < 0)",
            ),
            Self::HashToPrimeBudgetExhausted => f.write_str(
                "Wesolowski hash_to_prime exhausted the outer-loop budget without finding a prime challenge",
            ),
        }
    }
}

impl std::error::Error for WesolowskiError {}

/// The result of [`prove`]: the evaluation `h = g^(2^T)` paired
/// with the Wesolowski proof `π`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProveResult {
    /// The evaluation `h = g^(2^T)`.
    pub h: BinaryQuadraticForm,
    /// The Wesolowski proof `π = g^q` where `q = ⌊2^T / ℓ⌋` and
    /// `ℓ = hash_to_prime(g, h, T)`.
    pub pi: BinaryQuadraticForm,
}

/// Computes `h = g^(2^T)` via `T` sequential class-group
/// squarings per whitepaper §3.8.7.
///
/// # Performance
///
/// `T` calls to [`BinaryQuadraticForm::square`]. By construction
/// sequential: the result of squaring `i` is the input to
/// squaring `i + 1`, so no parallel speedup is known.
///
/// # Panics
///
/// Panics if `g` is not positive definite. The Wesolowski VDF
/// over the §3.8 imaginary quadratic order operates only on
/// positive definite elements.
#[must_use]
pub fn evaluate(g: &BinaryQuadraticForm, time_parameter_t: u64) -> BinaryQuadraticForm {
    assert!(
        g.is_positive_definite(),
        "Wesolowski evaluate requires a positive definite operand"
    );
    let mut h = g.clone();
    for _ in 0..time_parameter_t {
        h = h.square();
    }
    h
}

/// Derives the Fiat-Shamir prime challenge `ℓ` for the Wesolowski
/// proof per whitepaper §3.8.7 "Fiat-Shamir prime challenge".
///
/// Given `(g, h, T)`, deterministically produces a [`CHALLENGE_BITS`]-bit
/// prime `ℓ` via SHAKE-256-derived candidates and Miller-Rabin
/// primality testing.
///
/// # Errors
///
/// Returns [`WesolowskiError::HashToPrimeBudgetExhausted`] if the
/// outer-loop budget is exhausted without finding a prime —
/// effectively impossible (`~e^(-46)` probability) for any
/// realistic input.
///
/// # Panics
///
/// Cannot panic in practice. All operations are total over valid
/// inputs.
#[allow(
    clippy::cast_possible_truncation,
    reason = "MILLER_RABIN_ROUNDS = 40 fits in u32; the witness-index cast is safe by construction"
)]
fn hash_to_prime(
    g: &BinaryQuadraticForm,
    h: &BinaryQuadraticForm,
    time_parameter_t: u64,
) -> Result<BigUint, WesolowskiError> {
    let g_encoded = g.to_class_group_element().encoded;
    let h_encoded = h.to_class_group_element().encoded;
    let byte_len = (CHALLENGE_BITS / 8) as usize;

    for counter in 0..HASH_TO_PRIME_BUDGET {
        // Derive candidate.
        let cand_input = HashToPrimeCandidateInput {
            g_encoded: &g_encoded,
            h_encoded: &h_encoded,
            time_parameter_t,
            counter,
        };
        let cand_input_bytes =
            bcs::to_bytes(&cand_input).expect("HashToPrimeCandidateInput is BCS-serialisable");
        let mut raw = vec![0u8; byte_len];
        shake_256_tagged(&WESOLOWSKI_CHALLENGE, &cand_input_bytes, &mut raw);
        // Force high bit (exact width) + low bit (odd).
        raw[0] |= 0x80;
        raw[byte_len - 1] |= 0x01;
        let cand = BigUint::from_bytes_be(&raw);

        // Derive Miller-Rabin witnesses.
        let mut witnesses = Vec::with_capacity(MILLER_RABIN_ROUNDS);
        for witness_index in 0..MILLER_RABIN_ROUNDS {
            let w_input = HashToPrimeWitnessInput {
                g_encoded: &g_encoded,
                h_encoded: &h_encoded,
                time_parameter_t,
                counter,
                witness_index: witness_index as u32,
            };
            let w_input_bytes =
                bcs::to_bytes(&w_input).expect("HashToPrimeWitnessInput is BCS-serialisable");
            let mut w_bytes = vec![0u8; byte_len];
            shake_256_tagged(&WESOLOWSKI_CHALLENGE, &w_input_bytes, &mut w_bytes);
            witnesses.push(BigUint::from_bytes_be(&w_bytes));
        }

        // Test primality.
        if is_probable_prime(&cand, &witnesses) {
            return Ok(cand);
        }
    }

    Err(WesolowskiError::HashToPrimeBudgetExhausted)
}

/// Computes `base^exponent` in the class group via left-to-right
/// square-and-multiply.
///
/// Cost: `O(log₂(exponent))` class-group operations. Used by
/// [`prove`] for `π = g^q` and by [`verify`] for `π^ℓ · g^r`.
///
/// Identity convention: if `exponent` is zero, returns the
/// principal form (class-group identity) of `base`'s discriminant.
#[must_use]
fn pow(base: &BinaryQuadraticForm, exponent: &BigUint) -> BinaryQuadraticForm {
    if exponent.is_zero() {
        // x^0 = identity in the class group.
        return BinaryQuadraticForm::identity(&base.discriminant())
            .expect("base.discriminant() is valid by construction");
    }

    // Left-to-right square-and-multiply. The MSB seeds `result`
    // with `base`; subsequent bits (from second-MSB down to LSB)
    // each cause one square step, and multiply-by-base if set.
    let bit_count = exponent.bits();
    let mut result = base.clone();
    // For exponent = 1 (bit_count = 1), no further bits to process.
    // For exponent = 2 (bit_count = 2), one iteration at bit 0.
    // General: iterate bit positions (bit_count - 2) down to 0.
    if bit_count >= 2 {
        for i in (0..(bit_count - 1)).rev() {
            result = result.square();
            if exponent.bit(i) {
                result = result
                    .compose(base)
                    .expect("base and result share a discriminant by construction");
            }
        }
    }
    result
}

/// Produces the Wesolowski VDF proof for `(g, T)` per whitepaper
/// §3.8.7 "Prove".
///
/// Returns the pair `(h, π)` where:
///
/// - `h = g^(2^T)` is the evaluation produced by `T` sequential
///   class-group squarings.
/// - `π = g^q` is the proof, with `q = ⌊2^T / ℓ⌋` and
///   `ℓ = hash_to_prime(g, h, T)` the Fiat-Shamir prime challenge.
///
/// # Performance
///
/// Approximately `2T` class-group operations: `T` for evaluate
/// and `~T − log₂(ℓ) ≈ T` for the square-and-multiply on
/// the `T`-bit exponent `q`.
///
/// # Errors
///
/// Returns [`WesolowskiError::HashToPrimeBudgetExhausted`] only
/// in the vanishingly improbable case that `hash_to_prime` cannot
/// find a prime in 4096 attempts (`~e^(-46)` probability).
/// Returns [`WesolowskiError::NotPositiveDefinite`] if `g` is not
/// positive definite.
///
/// # Panics
///
/// Cannot panic in practice. All internal operations are total
/// over the validated inputs.
pub fn prove(
    g: &BinaryQuadraticForm,
    time_parameter_t: u64,
) -> Result<ProveResult, WesolowskiError> {
    if !g.is_positive_definite() {
        return Err(WesolowskiError::NotPositiveDefinite);
    }

    // Step 1: h ← evaluate(g, T).
    let h = evaluate(g, time_parameter_t);

    // Step 2: ℓ ← hash_to_prime(g, h, T).
    let ell = hash_to_prime(g, &h, time_parameter_t)?;

    // Step 3: q ← ⌊2^T / ℓ⌋.
    // 2^T is just a 1 followed by T zero bits.
    let shift = usize::try_from(time_parameter_t)
        .expect("time_parameter_t fits in usize on any 64-bit target; spec range [2M, 7.5M]");
    let two_to_t = BigUint::one() << shift;
    let q = two_to_t.div_floor(&ell);

    // Step 4: π ← g^q.
    let pi = pow(g, &q);

    Ok(ProveResult { h, pi })
}

/// Verifies a Wesolowski VDF proof against `(g, h, T)` per
/// whitepaper §3.8.7 "Verify".
///
/// Returns `true` iff `π^ℓ · g^r ≡ h` in the class group of
/// `g`'s discriminant, where `ℓ = hash_to_prime(g, h, T)` and
/// `r = 2^T mod ℓ`.
///
/// # Performance
///
/// `O(log ℓ) ≈ 128` class-group operations regardless of `T`.
/// Sub-millisecond at any `T` on consensus-grade hardware. This
/// is the property §3.8.3 calls "publicly verifiable in constant
/// time" (the verifier's cost is independent of the
/// time-parameter `T`).
///
/// # Errors
///
/// Returns [`WesolowskiError::NotPositiveDefinite`] if `g` or `h`
/// or `pi` is not positive definite.
/// Returns [`WesolowskiError::MismatchedDiscriminants`] if `g`,
/// `h`, and `pi` do not all share a discriminant.
/// Returns [`WesolowskiError::HashToPrimeBudgetExhausted`] only
/// in the vanishingly improbable case that `hash_to_prime` cannot
/// find a prime.
///
/// # Panics
///
/// Cannot panic in practice. All internal operations are total
/// over the validated inputs.
pub fn verify(
    g: &BinaryQuadraticForm,
    h: &BinaryQuadraticForm,
    time_parameter_t: u64,
    pi: &BinaryQuadraticForm,
) -> Result<bool, WesolowskiError> {
    if !g.is_positive_definite() || !h.is_positive_definite() || !pi.is_positive_definite() {
        return Err(WesolowskiError::NotPositiveDefinite);
    }
    let d = g.discriminant();
    if h.discriminant() != d || pi.discriminant() != d {
        return Err(WesolowskiError::MismatchedDiscriminants);
    }

    // Recompute the prime challenge ℓ.
    let ell = hash_to_prime(g, h, time_parameter_t)?;

    // r ← 2^T mod ℓ via fast modular exponentiation.
    // BigUint::modpow handles this in O(log T · log ℓ) operations
    // on O(log ℓ)-bit numbers.
    let two_to_t_mod_ell = BigUint::from(2u32).modpow(&BigUint::from(time_parameter_t), &ell);

    // lhs ← π^ℓ · g^r.
    let pi_to_ell = pow(pi, &ell);
    let g_to_r = pow(g, &two_to_t_mod_ell);
    let lhs = pi_to_ell
        .compose(&g_to_r)
        .expect("shared discriminant by construction");

    // Compare reduced forms — both are already reduced because the
    // class-group compose operation reduces its output.
    Ok(lhs == *h)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vdf::setup::{derive_discriminant, hash_to_element};
    use num_bigint::BigInt;

    /// Returns a chain-realistic discriminant + a hashed
    /// generator against it. The discriminant is 2048 bits per
    /// §3.8.2 — exactly the canonical genesis width — so the
    /// class group is large enough that distinct test inputs
    /// do not collide on a tiny group of order < 10. The
    /// generator's leading coefficient `a` is small (64 bits)
    /// to keep `hash_to_element` fast in test mode; only the
    /// discriminant width matters for class-group-size
    /// non-collision.
    fn fixture() -> (BigInt, BinaryQuadraticForm) {
        // Cache-friendly fixed seed.
        let mut seed = [0u8; 32];
        for (i, byte) in seed.iter_mut().enumerate() {
            *byte = u8::try_from(i * 17 % 256).expect("mod 256 fits in u8");
        }
        let d = derive_discriminant(&seed, 2048).expect("derive_discriminant");
        let g = hash_to_element(b"wesolowski-test-generator", &d, 64).expect("hash_to_element");
        (d, g)
    }

    #[test]
    fn evaluate_t_zero_returns_input() {
        let (_d, g) = fixture();
        let h = evaluate(&g, 0);
        assert_eq!(h, g);
    }

    #[test]
    fn evaluate_t_one_is_square() {
        let (_d, g) = fixture();
        let h = evaluate(&g, 1);
        assert_eq!(h, g.square());
    }

    #[test]
    fn evaluate_is_deterministic() {
        let (_d, g) = fixture();
        let h1 = evaluate(&g, 10);
        let h2 = evaluate(&g, 10);
        assert_eq!(h1, h2);
    }

    #[test]
    fn evaluate_preserves_discriminant() {
        let (d, g) = fixture();
        let h = evaluate(&g, 50);
        assert_eq!(h.discriminant(), d);
    }

    #[test]
    fn evaluate_result_is_reduced() {
        let (_d, g) = fixture();
        let h = evaluate(&g, 100);
        assert!(h.is_reduced());
        assert!(h.is_positive_definite());
    }

    #[test]
    #[should_panic(expected = "positive definite")]
    fn evaluate_panics_on_non_positive_definite() {
        // Construct a non-positive-definite form (a < 0).
        let bad = BinaryQuadraticForm::new(BigInt::from(-1), BigInt::from(0), BigInt::from(5))
            .expect("construct");
        let _ = evaluate(&bad, 5);
    }

    // ---- hash_to_prime ----

    #[test]
    fn hash_to_prime_is_deterministic() {
        let (_d, g) = fixture();
        let h = evaluate(&g, 10);
        let ell1 = hash_to_prime(&g, &h, 10).expect("hash_to_prime");
        let ell2 = hash_to_prime(&g, &h, 10).expect("hash_to_prime");
        assert_eq!(ell1, ell2);
    }

    #[test]
    fn hash_to_prime_distinct_t_distinct_ell() {
        let (_d, g) = fixture();
        let h_10 = evaluate(&g, 10);
        let h_20 = evaluate(&g, 20);
        let ell_10 = hash_to_prime(&g, &h_10, 10).expect("hash_to_prime");
        let ell_20 = hash_to_prime(&g, &h_20, 20).expect("hash_to_prime");
        assert_ne!(ell_10, ell_20);
    }

    #[test]
    fn hash_to_prime_returns_actual_prime() {
        let (_d, g) = fixture();
        let h = evaluate(&g, 5);
        let ell = hash_to_prime(&g, &h, 5).expect("hash_to_prime");
        // The standard small-prime witness set is exact for
        // n < 3.3·10^24; ℓ is ~2^128 which exceeds that, so we use
        // a deterministic 40-witness Miller-Rabin check.
        let witnesses: Vec<BigUint> = (2u32..=42).map(BigUint::from).collect();
        assert!(is_probable_prime(&ell, &witnesses));
        // ℓ has exactly CHALLENGE_BITS bits (high bit forced).
        assert_eq!(
            u32::try_from(ell.bits()).expect("128 bits fits in u32"),
            CHALLENGE_BITS
        );
    }

    // ---- pow ----

    #[test]
    fn pow_zero_returns_identity() {
        let (d, g) = fixture();
        let result = pow(&g, &BigUint::zero());
        let identity = BinaryQuadraticForm::identity(&d).expect("identity");
        assert_eq!(result, identity);
    }

    #[test]
    fn pow_one_returns_base() {
        let (_d, g) = fixture();
        let result = pow(&g, &BigUint::one());
        assert_eq!(result, g);
    }

    #[test]
    fn pow_two_returns_square() {
        let (_d, g) = fixture();
        let result = pow(&g, &BigUint::from(2u32));
        assert_eq!(result, g.square());
    }

    #[test]
    fn pow_four_matches_iterated_squaring() {
        let (_d, g) = fixture();
        let result = pow(&g, &BigUint::from(4u32));
        // g^4 = g^(2²) = (g²)²
        let expected = g.square().square();
        assert_eq!(result, expected);
    }

    #[test]
    fn pow_eight_matches_iterated_squaring() {
        let (_d, g) = fixture();
        let result = pow(&g, &BigUint::from(8u32));
        let expected = g.square().square().square();
        assert_eq!(result, expected);
    }

    #[test]
    fn pow_2_to_t_matches_evaluate() {
        // g^(2^T) computed via pow should match evaluate(g, T).
        let (_d, g) = fixture();
        for t in [1u64, 3, 5, 7, 10] {
            let via_pow = pow(
                &g,
                &(BigUint::one() << usize::try_from(t).expect("test fixture T fits in usize")),
            );
            let via_evaluate = evaluate(&g, t);
            assert_eq!(via_pow, via_evaluate, "T = {t}");
        }
    }

    // ---- prove + verify round-trip ----

    #[test]
    fn prove_and_verify_round_trip_t_1() {
        let (_d, g) = fixture();
        let result = prove(&g, 1).expect("prove");
        assert!(verify(&g, &result.h, 1, &result.pi).expect("verify"));
    }

    #[test]
    fn prove_and_verify_round_trip_t_10() {
        let (_d, g) = fixture();
        let result = prove(&g, 10).expect("prove");
        assert!(verify(&g, &result.h, 10, &result.pi).expect("verify"));
    }

    #[test]
    fn prove_and_verify_round_trip_t_50() {
        let (_d, g) = fixture();
        let result = prove(&g, 50).expect("prove");
        assert!(verify(&g, &result.h, 50, &result.pi).expect("verify"));
    }

    #[test]
    fn prove_h_matches_evaluate() {
        let (_d, g) = fixture();
        let result = prove(&g, 20).expect("prove");
        let h_via_evaluate = evaluate(&g, 20);
        assert_eq!(result.h, h_via_evaluate);
    }

    #[test]
    fn prove_rejects_non_positive_definite_base() {
        let bad = BinaryQuadraticForm::new(BigInt::from(-1), BigInt::from(0), BigInt::from(5))
            .expect("construct");
        let err = prove(&bad, 5).expect_err("must reject");
        assert_eq!(err, WesolowskiError::NotPositiveDefinite);
    }

    // ---- verify rejection paths ----

    #[test]
    fn verify_rejects_tampered_h() {
        let (_d, g) = fixture();
        let result = prove(&g, 10).expect("prove");
        // Use g.square() as a fake h. With overwhelming probability,
        // verify rejects.
        let fake_h = g.square();
        assert_ne!(fake_h, result.h);
        let ok = verify(&g, &fake_h, 10, &result.pi).expect("verify");
        assert!(!ok);
    }

    #[test]
    fn verify_rejects_tampered_pi() {
        let (_d, g) = fixture();
        let result = prove(&g, 10).expect("prove");
        // Use g.square() as a fake pi.
        let fake_pi = g.square();
        // It's unlikely that fake_pi happens to be a valid proof
        // for h = evaluate(g, 10), but in principle possible. Skip
        // the assertion if they happen to collide.
        if fake_pi != result.pi {
            let ok = verify(&g, &result.h, 10, &fake_pi).expect("verify");
            assert!(!ok);
        }
    }

    #[test]
    fn verify_rejects_wrong_t() {
        let (_d, g) = fixture();
        let result = prove(&g, 10).expect("prove");
        // Verify against T = 11 instead of 10: h was computed for
        // T = 10, but the verifier expects T = 11. Cheating is
        // impossible because ℓ depends on (g, h, T) and the
        // identity g^(2^11) = π^ℓ · g^(2^11 mod ℓ) does not hold
        // when h corresponds to T = 10.
        let ok = verify(&g, &result.h, 11, &result.pi).expect("verify");
        assert!(!ok);
    }

    #[test]
    fn verify_rejects_swapped_g_and_h() {
        let (_d, g) = fixture();
        let result = prove(&g, 10).expect("prove");
        // Swap g and h: verifying h^(2^10) ?= g would require
        // h^(2^10) = g — impossible for nontrivial group order
        // and a generic g.
        let ok = verify(&result.h, &g, 10, &result.pi).expect("verify");
        assert!(!ok);
    }

    #[test]
    fn verify_rejects_mismatched_discriminants() {
        let (_d_a, g_a) = fixture();
        let result = prove(&g_a, 10).expect("prove");
        // Use a different discriminant for one of the operands.
        let other_d = BigInt::from(-23);
        let other_g = hash_to_element(b"other", &other_d, 32).expect("hash_to_element");
        let err = verify(&other_g, &result.h, 10, &result.pi)
            .expect_err("must reject discriminant mismatch");
        assert_eq!(err, WesolowskiError::MismatchedDiscriminants);
    }

    #[test]
    fn verify_rejects_non_positive_definite_operands() {
        let (_d, g) = fixture();
        let result = prove(&g, 5).expect("prove");
        let bad = BinaryQuadraticForm::new(BigInt::from(-1), BigInt::from(0), BigInt::from(5))
            .expect("construct");
        let err = verify(&bad, &result.h, 5, &result.pi).expect_err("must reject");
        assert_eq!(err, WesolowskiError::NotPositiveDefinite);
    }

    // ---- determinism + cross-property checks ----

    #[test]
    fn prove_is_deterministic() {
        let (_d, g) = fixture();
        let a = prove(&g, 8).expect("prove");
        let b = prove(&g, 8).expect("prove");
        assert_eq!(a, b);
    }

    #[test]
    fn verify_accepts_proofs_from_different_seeds() {
        // Independent generators g₁, g₂ → independent (h, π) →
        // both verify successfully. Same 2048-bit-discriminant
        // fixture; T = 200 so the proof exercises the real
        // square-and-multiply path.
        let (d, _) = fixture();
        let g1 = hash_to_element(b"g1-seed", &d, 64).expect("hash_to_element");
        let g2 = hash_to_element(b"g2-seed", &d, 64).expect("hash_to_element");
        let r1 = prove(&g1, 200).expect("prove g1");
        let r2 = prove(&g2, 200).expect("prove g2");
        assert!(verify(&g1, &r1.h, 200, &r1.pi).expect("verify"));
        assert!(verify(&g2, &r2.h, 200, &r2.pi).expect("verify"));
    }

    #[test]
    fn cross_seed_proofs_do_not_verify() {
        // A proof for (g₁, T) should not verify against g₂.
        // Use the 2048-bit-discriminant fixture so the class group
        // is large enough that g₁ != g₂ and their orbits don't
        // collide. Use T = 200 so q = ⌊2^T / ℓ⌋ ≈ 2^72 — non-zero,
        // testing the actual square-and-multiply path in `pow`.
        let (d, _) = fixture();
        let g1 = hash_to_element(b"g1-seed", &d, 64).expect("hash_to_element");
        let g2 = hash_to_element(b"g2-seed", &d, 64).expect("hash_to_element");
        assert_ne!(g1, g2);
        let r1 = prove(&g1, 200).expect("prove g1");
        let ok = verify(&g2, &r1.h, 200, &r1.pi).expect("verify");
        assert!(!ok);
    }

    /// End-to-end integration: a chain-derived discriminant + a
    /// hashed generator + the Wesolowski VDF round-trip. Wires
    /// Phase 7.5.2a + 7.5.2b + 7.5.3 together against the
    /// full setup pipeline.
    #[test]
    fn full_setup_pipeline_prove_verify_round_trip() {
        let mut seed = [0u8; 32];
        seed[0] = 0xAA;
        seed[31] = 0x55;
        let d = derive_discriminant(&seed, 2048).expect("derive_discriminant");
        let g = hash_to_element(b"g0", &d, 64).expect("hash_to_element");
        let result = prove(&g, 5).expect("prove");
        assert!(verify(&g, &result.h, 5, &result.pi).expect("verify"));
        assert_eq!(result.h.discriminant(), d);
        assert_eq!(result.pi.discriminant(), d);
    }

    #[test]
    fn wesolowski_error_display_messages_are_meaningful() {
        let variants = [
            WesolowskiError::MismatchedDiscriminants,
            WesolowskiError::NotPositiveDefinite,
            WesolowskiError::HashToPrimeBudgetExhausted,
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
    fn wesolowski_error_implements_std_error() {
        fn assert_err<E: std::error::Error>() {}
        assert_err::<WesolowskiError>();
    }

    #[test]
    fn challenge_bits_constant_pinned() {
        // Consensus-binding: any change to CHALLENGE_BITS is a
        // hard fork. Pin its value here so drift surfaces.
        assert_eq!(CHALLENGE_BITS, 128);
    }
}
