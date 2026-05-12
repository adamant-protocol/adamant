//! Modular-arithmetic primitives over `num_bigint::BigUint`, per
//! whitepaper §3.8.6 hash-to-element infrastructure.
//!
//! Phase 7.5.2b ships three classical number-theoretic algorithms
//! the §3.8.6 hash-to-element procedure consumes:
//!
//! - [`is_probable_prime`] — Miller-Rabin primality testing with
//!   deterministically-derived witnesses.
//! - [`jacobi_symbol`] — the Jacobi symbol `(a/n)`, used as the
//!   quadratic-residue test in the hash-to-element pipeline.
//! - [`tonelli_shanks_sqrt_mod_prime`] — modular square root in
//!   `ℤ/p` (Tonelli-Shanks algorithm) for odd prime `p`.
//!
//! Plus the public helper [`next_prime`] that advances from a
//! candidate integer to the next prime above it; the §3.8.6
//! algorithm calls this to land on a prime leading coefficient
//! `a` from a hash-derived seed.
//!
//! # Adamant-native posture
//!
//! Per CLAUDE.md §14, these algorithms are Adamant-authored on
//! top of the `num-bigint` Cat E workspace utility. The
//! algorithms themselves are classical (Miller 1976 / Rabin
//! 1980; Tonelli 1891 / Shanks 1972; Jacobi 1846) and Adamant
//! ships its own implementation rather than pulling in an
//! external number-theory crate.
//!
//! # Determinism
//!
//! All three algorithms are deterministic by construction:
//!
//! - `is_probable_prime` accepts an explicit witness vector
//!   chosen by the caller; consensus call-sites derive the
//!   witnesses from a tagged-SHAKE-256 hash of the
//!   `(seed, candidate)` pair, so the test is reproducible
//!   bit-for-bit across implementations.
//! - `jacobi_symbol` is a pure number-theoretic function with no
//!   randomness.
//! - `tonelli_shanks_sqrt_mod_prime` is deterministic given its
//!   non-residue search (which deterministically scans `z = 2,
//!   3, 5, ...` until a non-residue is found).
//!
//! # What this module does NOT cover
//!
//! - **Constant-time discipline.** These algorithms operate on
//!   public values (the seed, the discriminant, the candidate
//!   prime) and produce public outputs (the class-group
//!   element). No secret-dependent branching exists at the
//!   call-sites, so constant-time implementation is not a
//!   correctness requirement. (Contrast with the threshold-
//!   encryption secret-share path in §3.6, where every
//!   operation on key material is constant-time.)
//! - **General integer factorisation.** This module covers
//!   primality testing (is `n` prime?) but not factorisation
//!   (what are `n`'s prime factors?). The Wesolowski VDF
//!   construction does not require factorisation of any value
//!   the VDF operates on; class-group security is independent
//!   of factorisation hardness.

use num_bigint::BigUint;
use num_integer::Integer;
use num_traits::{One, Zero};

/// The Jacobi symbol `(a/n)` for odd positive `n`.
///
/// Generalises the Legendre symbol to composite moduli. For prime
/// `n`, the Jacobi symbol equals the Legendre symbol and
/// indicates whether `a` is a quadratic residue mod `n`:
///
/// - `(a/n) = 1`  iff `a` is a non-zero QR mod `n`
/// - `(a/n) = -1` iff `a` is a non-residue mod `n`
/// - `(a/n) = 0`  iff `gcd(a, n) > 1`
///
/// The `i8` return value encodes these three cases as `1`, `-1`,
/// `0`.
///
/// Used by the §3.8.6 hash-to-element procedure to test whether
/// the chain-fixed discriminant `D` is a QR mod a candidate
/// prime `a` before attempting the more-expensive Tonelli-Shanks
/// square root.
///
/// # Algorithm
///
/// The implementation uses the classical quadratic-reciprocity
/// based descent (Cohen Algorithm 1.4.10):
///
/// 1. Reduce `a` modulo `n`.
/// 2. While `a > 0`, extract factors of 2 from `a` (each factor
///    of 2 contributes `+1` or `-1` to the result via the
///    "second supplementary law" depending on `n mod 8`).
/// 3. Apply the quadratic-reciprocity flip on the odd part of
///    `a` versus `n`.
/// 4. Recurse with the swapped/reduced pair.
///
/// Termination follows the same shape as the Euclidean algorithm
/// in `O(log(max(a, n)))` iterations.
///
/// # Panics
///
/// Panics if `n` is zero or even. The Jacobi symbol is defined
/// only for odd positive `n`.
#[must_use]
#[allow(
    clippy::many_single_char_names,
    reason = "the published Jacobi algorithm uses single-letter \
              variable names a, n, r matching Cohen 1.4.10 and \
              the standard number-theory literature; renaming \
              would obscure the spec correspondence"
)]
pub fn jacobi_symbol(a: &BigUint, n: &BigUint) -> i8 {
    assert!(!n.is_zero(), "Jacobi symbol requires non-zero modulus");
    assert!(n.bit(0), "Jacobi symbol requires odd modulus (n mod 2 = 1)");

    let mut a = a.mod_floor(n);
    let mut n = n.clone();
    let mut result: i8 = 1;

    while !a.is_zero() {
        // Extract factors of 2 from `a`. For each factor of 2,
        // multiply the result by (2/n) = ±1, where the sign
        // depends on n mod 8:
        //   (2/n) = +1 if n ≡ 1 or 7 (mod 8)
        //   (2/n) = -1 if n ≡ 3 or 5 (mod 8)
        while !a.bit(0) {
            a >>= 1;
            let n_mod_8 = (&n & BigUint::from(7u32)).to_u32_digits();
            // n_mod_8 is in [0, 7]; pick the appropriate sign.
            let r = if n_mod_8.is_empty() { 0u32 } else { n_mod_8[0] };
            if r == 3 || r == 5 {
                result = -result;
            }
        }

        // Quadratic-reciprocity flip on the swap: (a/n)(n/a) =
        // -1 iff both a ≡ 3 (mod 4) and n ≡ 3 (mod 4).
        // After this, swap (a, n) so the smaller value becomes
        // the modulus.
        let a_mod_4 = (&a & BigUint::from(3u32)).to_u32_digits();
        let n_mod_4 = (&n & BigUint::from(3u32)).to_u32_digits();
        let a_r = if a_mod_4.is_empty() { 0u32 } else { a_mod_4[0] };
        let n_r = if n_mod_4.is_empty() { 0u32 } else { n_mod_4[0] };
        if a_r == 3 && n_r == 3 {
            result = -result;
        }
        core::mem::swap(&mut a, &mut n);
        a = a.mod_floor(&n);
    }

    if n.is_one() {
        result
    } else {
        // gcd(original a, original n) > 1 — by convention (a/n) = 0.
        0
    }
}

/// Miller-Rabin probable-prime test with caller-supplied witnesses.
///
/// Returns `true` if `n` passes the Miller-Rabin test for every
/// witness in `witnesses`; otherwise returns `false`.
///
/// For a fixed witness set, the test is exact below specific
/// bounds (e.g., `[2, 3]` is exact for `n < 1,373,653`); for
/// arbitrary witnesses against random composite `n`, each round
/// has at most a `1/4` error probability. For cryptographic use
/// at any bit-width, 40 rounds with seed-derived witnesses give
/// a soundness error below `2^-80`.
///
/// The §3.8.6 hash-to-element procedure uses this test with 40
/// rounds; witnesses are derived deterministically from
/// `tagged_shake_256(CLASS_GROUP_ELEMENT_SEED, BCS(seed, candidate))`,
/// so the test is reproducible bit-for-bit across implementations.
///
/// # Algorithm
///
/// 1. Reject `n < 2`, `n = 2`, `n = 3` directly; reject even `n`.
/// 2. Write `n − 1 = d · 2^r` with `d` odd.
/// 3. For each witness `a`:
///    - If `a mod n ∈ {0, 1, n−1}`, the witness is uninformative — continue.
///    - Compute `x = a^d (mod n)`.
///    - If `x = 1` or `x = n − 1`, the witness is satisfied — continue.
///    - Otherwise, square `x` up to `r − 1` times. If any intermediate
///      result equals `n − 1`, the witness is satisfied. If not, `n` is
///      composite — return `false`.
/// 4. If every witness is satisfied, return `true`.
///
/// # Panics
///
/// Cannot panic. All operations are total over `BigUint`.
#[must_use]
#[allow(
    clippy::many_single_char_names,
    reason = "the Miller-Rabin algorithm uses single-letter variable names \
              (n, a, d, r, x) matching the standard number-theory \
              literature; renaming would obscure the spec correspondence"
)]
pub fn is_probable_prime(n: &BigUint, witnesses: &[BigUint]) -> bool {
    let two = BigUint::from(2u32);
    let three = BigUint::from(3u32);

    // Trivial cases.
    if n < &two {
        return false;
    }
    if n == &two || n == &three {
        return true;
    }
    if !n.bit(0) {
        // n is even and > 2.
        return false;
    }

    // Write n - 1 = d * 2^r with d odd.
    let n_minus_1 = n - BigUint::one();
    let mut d = n_minus_1.clone();
    let mut r: u32 = 0;
    while !d.bit(0) {
        d >>= 1;
        r += 1;
    }

    'outer: for raw_witness in witnesses {
        // Reduce witness mod n; skip uninformative witnesses.
        let a = raw_witness.mod_floor(n);
        if a.is_zero() || a.is_one() || a == n_minus_1 {
            continue;
        }

        let mut x = a.modpow(&d, n);
        if x.is_one() || x == n_minus_1 {
            continue;
        }

        // Square up to r - 1 times looking for n - 1.
        for _ in 0..r.saturating_sub(1) {
            x = x.modpow(&two, n);
            if x == n_minus_1 {
                continue 'outer;
            }
            if x.is_one() {
                // Hit 1 before n-1: composite (non-trivial root).
                return false;
            }
        }
        // Witness rejected n.
        return false;
    }

    true
}

/// Finds the smallest prime ≥ `start` via Miller-Rabin testing
/// with caller-supplied witnesses.
///
/// Used by the §3.8.6 hash-to-element procedure to land on a
/// prime leading coefficient `a` from a hash-derived candidate.
/// The candidate is already guaranteed odd and of fixed bit-
/// width by the caller (steps 4 and 5 of the §3.8.6 algorithm);
/// `next_prime` increments by 2 until a prime is found.
///
/// # Panics
///
/// Panics if `start < 2`.
#[must_use]
pub fn next_prime(start: &BigUint, witnesses: &[BigUint]) -> BigUint {
    assert!(
        start >= &BigUint::from(2u32),
        "next_prime requires start ≥ 2"
    );
    let mut candidate = start.clone();
    // Make candidate odd if it isn't already (only `2` is the
    // even prime; if start = 2 we return immediately).
    if candidate == BigUint::from(2u32) {
        return candidate;
    }
    if !candidate.bit(0) {
        candidate += BigUint::one();
    }
    let two = BigUint::from(2u32);
    loop {
        if is_probable_prime(&candidate, witnesses) {
            return candidate;
        }
        candidate += &two;
    }
}

/// Computes `x` such that `x² ≡ n (mod p)`, given that `n` is a
/// quadratic residue modulo the odd prime `p`.
///
/// Returns `None` if `n` is not a quadratic residue mod `p` (the
/// caller should normally test this via [`jacobi_symbol`] first
/// to avoid the wasted computation), or if `p` is even (other
/// than `p = 2` — `p = 2` returns `n mod 2` directly since the
/// field is `{0, 1}`).
///
/// # Algorithm
///
/// Tonelli-Shanks (Tonelli 1891, refined by Shanks 1972). The
/// implementation follows the canonical four-step structure:
///
/// 1. **Special case `p ≡ 3 (mod 4)`**: the square root is
///    `n^((p+1)/4) mod p` directly. This covers a large fraction
///    of primes in practice.
/// 2. **Find a non-residue** `z` by scanning `z = 2, 3, ...`
///    until `jacobi(z, p) = −1`. On average, the search costs
///    `O(1)` iterations (about half of all residues are
///    non-residues).
/// 3. **Decompose** `p − 1 = Q · 2^S` with `Q` odd.
/// 4. **Iteratively refine** the root: starting from
///    `R = n^((Q+1)/2)`, `t = n^Q`, `c = z^Q`, repeatedly square
///    `t` until it equals `1`, and adjust `R, c, M` accordingly.
///    The loop runs at most `S` times.
///
/// Total cost: `O(log² p)` field operations.
#[must_use]
#[allow(
    clippy::many_single_char_names,
    reason = "the published Tonelli-Shanks algorithm uses single-letter \
              variable names (Q, S, z, c, t, R, M, b, i) matching the \
              standard number-theory literature; renaming would obscure \
              the spec correspondence"
)]
pub fn tonelli_shanks_sqrt_mod_prime(n: &BigUint, p: &BigUint) -> Option<BigUint> {
    let zero = BigUint::zero();
    let one = BigUint::one();
    let two = BigUint::from(2u32);

    // Edge cases.
    if p.is_zero() {
        return None;
    }
    if p == &two {
        // ℤ/2: x² ≡ n (mod 2) iff x ≡ n (mod 2). Both 0 and 1
        // are self-square in ℤ/2.
        return Some(n.mod_floor(&two));
    }
    if !p.bit(0) {
        // Even modulus > 2: not a prime field for our purposes.
        return None;
    }

    let n = n.mod_floor(p);
    if n.is_zero() {
        return Some(zero);
    }

    // Verify n is a QR mod p. Skip the expensive computation if not.
    if jacobi_symbol(&n, p) != 1 {
        return None;
    }

    // Special case: p ≡ 3 (mod 4) → sqrt(n) = n^((p+1)/4) mod p.
    let p_mod_4 = (p & BigUint::from(3u32)).to_u32_digits();
    let p_mod_4_val = if p_mod_4.is_empty() { 0u32 } else { p_mod_4[0] };
    if p_mod_4_val == 3 {
        let exponent = (p + &one) >> 2;
        return Some(n.modpow(&exponent, p));
    }

    // General case: Tonelli-Shanks.
    // Step 3: p - 1 = Q · 2^S with Q odd.
    let p_minus_1 = p - &one;
    let mut q = p_minus_1.clone();
    let mut s: u32 = 0;
    while !q.bit(0) {
        q >>= 1;
        s += 1;
    }

    // Step 2: find a non-residue z.
    let mut z = BigUint::from(2u32);
    while jacobi_symbol(&z, p) != -1 {
        z += &one;
    }

    // Initial state.
    let mut m = s;
    let mut c = z.modpow(&q, p);
    let mut t = n.modpow(&q, p);
    let q_plus_1_over_2 = (&q + &one) >> 1;
    let mut r = n.modpow(&q_plus_1_over_2, p);

    // Step 4: iterate.
    loop {
        if t.is_one() {
            return Some(r);
        }

        // Find least i in [1, M) such that t^(2^i) = 1.
        let mut i: u32 = 0;
        let mut temp = t.clone();
        while !temp.is_one() {
            temp = temp.modpow(&two, p);
            i += 1;
            if i >= m {
                // Should not happen if `n` is a QR. Defensive return.
                return None;
            }
        }

        // b = c^(2^(M - i - 1)) mod p.
        let exp = BigUint::one() << ((m - i - 1) as usize);
        let b = c.modpow(&exp, p);

        m = i;
        c = b.modpow(&two, p);
        t = (&t * &c).mod_floor(p);
        r = (&r * &b).mod_floor(p);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn b(n: u64) -> BigUint {
        BigUint::from(n)
    }

    // ---- jacobi_symbol ----

    #[test]
    fn jacobi_rejects_even_modulus() {
        // jacobi_symbol panics on even modulus
        let r = std::panic::catch_unwind(|| jacobi_symbol(&b(3), &b(4)));
        assert!(r.is_err());
    }

    #[test]
    fn jacobi_rejects_zero_modulus() {
        let r = std::panic::catch_unwind(|| jacobi_symbol(&b(3), &b(0)));
        assert!(r.is_err());
    }

    #[test]
    fn jacobi_one_mod_n_is_one() {
        // (1/n) = 1 for any odd n ≥ 1.
        for n in [1u64, 3, 5, 7, 9, 15, 101] {
            assert_eq!(jacobi_symbol(&b(1), &b(n)), 1, "(1/{n})");
        }
    }

    #[test]
    fn jacobi_known_legendre_values() {
        // Legendre symbol over small primes — known values.
        // (a/p) for a < p, p prime.
        // Quadratic residues mod 7: {1, 2, 4}; non-residues: {3, 5, 6}.
        assert_eq!(jacobi_symbol(&b(1), &b(7)), 1);
        assert_eq!(jacobi_symbol(&b(2), &b(7)), 1);
        assert_eq!(jacobi_symbol(&b(3), &b(7)), -1);
        assert_eq!(jacobi_symbol(&b(4), &b(7)), 1);
        assert_eq!(jacobi_symbol(&b(5), &b(7)), -1);
        assert_eq!(jacobi_symbol(&b(6), &b(7)), -1);
        // QR mod 11: {1, 3, 4, 5, 9}; NR: {2, 6, 7, 8, 10}.
        assert_eq!(jacobi_symbol(&b(1), &b(11)), 1);
        assert_eq!(jacobi_symbol(&b(3), &b(11)), 1);
        assert_eq!(jacobi_symbol(&b(4), &b(11)), 1);
        assert_eq!(jacobi_symbol(&b(5), &b(11)), 1);
        assert_eq!(jacobi_symbol(&b(9), &b(11)), 1);
        assert_eq!(jacobi_symbol(&b(2), &b(11)), -1);
        assert_eq!(jacobi_symbol(&b(6), &b(11)), -1);
        assert_eq!(jacobi_symbol(&b(7), &b(11)), -1);
        assert_eq!(jacobi_symbol(&b(8), &b(11)), -1);
        assert_eq!(jacobi_symbol(&b(10), &b(11)), -1);
    }

    #[test]
    fn jacobi_multiplicativity_in_top_argument() {
        // (ab/n) = (a/n) · (b/n) — Jacobi symbol is multiplicative
        // in its top argument. Check across some small values.
        let n = b(15); // 15 = 3 · 5 (composite)
        for a in [1u64, 2, 4, 7, 8, 11, 13, 14] {
            for c in [1u64, 2, 4, 7, 8, 11, 13, 14] {
                let lhs = jacobi_symbol(&(b(a) * b(c)), &n);
                let rhs = jacobi_symbol(&b(a), &n) * jacobi_symbol(&b(c), &n);
                assert_eq!(lhs, rhs, "({a}·{c} / 15) ≠ ({a}/15)·({c}/15)");
            }
        }
    }

    #[test]
    fn jacobi_returns_zero_on_shared_factor() {
        // (a/n) = 0 if gcd(a, n) > 1.
        assert_eq!(jacobi_symbol(&b(3), &b(9)), 0);
        assert_eq!(jacobi_symbol(&b(6), &b(15)), 0);
    }

    // ---- is_probable_prime ----

    fn small_witnesses() -> Vec<BigUint> {
        // The first 12 primes form a deterministic Miller-Rabin
        // witness set that's exact for n < 3.3·10^24.
        vec![
            b(2),
            b(3),
            b(5),
            b(7),
            b(11),
            b(13),
            b(17),
            b(19),
            b(23),
            b(29),
            b(31),
            b(37),
        ]
    }

    #[test]
    fn mr_rejects_small_non_primes() {
        let w = small_witnesses();
        for n in [
            0u64, 1, 4, 6, 8, 9, 10, 12, 14, 15, 16, 18, 20, 21, 25, 27, 33, 35, 49, 91,
        ] {
            assert!(
                !is_probable_prime(&b(n), &w),
                "{n} should be detected as composite"
            );
        }
    }

    #[test]
    fn mr_accepts_small_primes() {
        let w = small_witnesses();
        for n in [
            2u64, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71,
        ] {
            assert!(
                is_probable_prime(&b(n), &w),
                "{n} should be accepted as prime"
            );
        }
    }

    #[test]
    fn mr_detects_carmichael_numbers() {
        let w = small_witnesses();
        // Carmichael numbers: composite n that pass Fermat's
        // little theorem for every witness coprime to n. Must
        // still be rejected by Miller-Rabin.
        for n in [561u64, 1105, 1729, 2465, 2821, 6601, 8911, 10585] {
            assert!(
                !is_probable_prime(&b(n), &w),
                "Carmichael number {n} not detected"
            );
        }
    }

    #[test]
    fn mr_accepts_mersenne_primes() {
        let w = small_witnesses();
        // 2^31 - 1 = 2147483647 is the Mersenne prime M31.
        assert!(is_probable_prime(&b(2_147_483_647), &w));
        // 2^61 - 1 = 2305843009213693951 is the Mersenne prime M61.
        assert!(is_probable_prime(&b(2_305_843_009_213_693_951), &w));
    }

    #[test]
    fn mr_rejects_2_to_32_minus_1() {
        // 2^32 - 1 = 4294967295 = 3 · 5 · 17 · 257 · 65537 (composite).
        let w = small_witnesses();
        assert!(!is_probable_prime(&b(4_294_967_295), &w));
    }

    #[test]
    fn mr_deterministic_for_fixed_witnesses() {
        let w = small_witnesses();
        for n in [101u64, 1009, 10_007, 100_003] {
            let a = is_probable_prime(&b(n), &w);
            let c = is_probable_prime(&b(n), &w);
            assert_eq!(a, c);
        }
    }

    // ---- next_prime ----

    #[test]
    fn next_prime_finds_next_prime_above_start() {
        let w = small_witnesses();
        // Smallest prime ≥ 4 is 5; ≥ 14 is 17; ≥ 24 is 29; etc.
        assert_eq!(next_prime(&b(4), &w), b(5));
        assert_eq!(next_prime(&b(14), &w), b(17));
        assert_eq!(next_prime(&b(24), &w), b(29));
        // Already prime ≥ 2.
        assert_eq!(next_prime(&b(2), &w), b(2));
        assert_eq!(next_prime(&b(7), &w), b(7));
    }

    #[test]
    #[should_panic(expected = "next_prime requires start \u{2265} 2")]
    fn next_prime_panics_on_start_below_2() {
        let w = small_witnesses();
        let _ = next_prime(&b(1), &w);
    }

    // ---- tonelli_shanks_sqrt_mod_prime ----

    fn verify_sqrt(n: u64, p: u64) {
        let w = small_witnesses();
        assert!(
            is_probable_prime(&b(p), &w),
            "test fixture {p} must be prime"
        );
        let r_opt = tonelli_shanks_sqrt_mod_prime(&b(n), &b(p));
        if jacobi_symbol(&b(n % p), &b(p)) == 1 {
            let r = r_opt.expect("QR must have a square root");
            // Verify r² ≡ n (mod p).
            let r_sq = (&r * &r).mod_floor(&b(p));
            assert_eq!(r_sq, b(n).mod_floor(&b(p)), "({r})² mod {p} ≠ {n} mod {p}");
        } else if !b(n).mod_floor(&b(p)).is_zero() {
            assert!(r_opt.is_none(), "non-residue {n} mod {p} returned a root");
        }
    }

    #[test]
    fn tonelli_shanks_p_equiv_3_mod_4_easy_case() {
        // p = 7 ≡ 3 mod 4. QRs mod 7: {0, 1, 2, 4}.
        for n in 0u64..14 {
            verify_sqrt(n, 7);
        }
        // p = 11 ≡ 3 mod 4.
        for n in 0u64..22 {
            verify_sqrt(n, 11);
        }
        // p = 23 ≡ 3 mod 4.
        for n in 0u64..46 {
            verify_sqrt(n, 23);
        }
    }

    #[test]
    fn tonelli_shanks_p_equiv_1_mod_4_general_case() {
        // p = 13 ≡ 1 mod 4 — exercises the general TS branch.
        for n in 0u64..26 {
            verify_sqrt(n, 13);
        }
        // p = 17 ≡ 1 mod 4.
        for n in 0u64..34 {
            verify_sqrt(n, 17);
        }
        // p = 41 ≡ 1 mod 4.
        for n in 0u64..82 {
            verify_sqrt(n, 41);
        }
    }

    #[test]
    fn tonelli_shanks_specific_known_values() {
        // Known: 6² = 36 ≡ 10 (mod 13).
        let r = tonelli_shanks_sqrt_mod_prime(&b(10), &b(13)).expect("QR");
        let r_sq = (&r * &r).mod_floor(&b(13));
        assert_eq!(r_sq, b(10));
        // Known: 4² = 16 ≡ 2 (mod 7) — so sqrt(2) mod 7 ∈ {3, 4}.
        let r = tonelli_shanks_sqrt_mod_prime(&b(2), &b(7)).expect("QR");
        assert!(
            r == b(3) || r == b(4),
            "sqrt(2) mod 7 must be 3 or 4, got {r}"
        );
    }

    #[test]
    fn tonelli_shanks_returns_none_for_non_residue() {
        // 3 is a non-residue mod 7 (jacobi = -1).
        assert!(tonelli_shanks_sqrt_mod_prime(&b(3), &b(7)).is_none());
        // 2 is a non-residue mod 5.
        assert!(tonelli_shanks_sqrt_mod_prime(&b(2), &b(5)).is_none());
    }

    #[test]
    fn tonelli_shanks_zero_returns_zero() {
        // 0² ≡ 0 (mod p) for every p.
        assert_eq!(tonelli_shanks_sqrt_mod_prime(&b(0), &b(7)), Some(b(0)));
        assert_eq!(tonelli_shanks_sqrt_mod_prime(&b(13), &b(13)), Some(b(0)));
    }

    #[test]
    fn tonelli_shanks_handles_p_2() {
        // ℤ/2: x² = n iff x = n mod 2.
        assert_eq!(tonelli_shanks_sqrt_mod_prime(&b(0), &b(2)), Some(b(0)));
        assert_eq!(tonelli_shanks_sqrt_mod_prime(&b(1), &b(2)), Some(b(1)));
    }

    #[test]
    fn tonelli_shanks_rejects_even_p_greater_than_2() {
        assert!(tonelli_shanks_sqrt_mod_prime(&b(3), &b(4)).is_none());
        assert!(tonelli_shanks_sqrt_mod_prime(&b(5), &b(10)).is_none());
    }

    #[test]
    fn tonelli_shanks_deterministic() {
        // Same input must produce the same output across calls.
        let a = tonelli_shanks_sqrt_mod_prime(&b(10), &b(13));
        let b_result = tonelli_shanks_sqrt_mod_prime(&b(10), &b(13));
        assert_eq!(a, b_result);
    }

    /// Stress test on a larger prime in the TS-general branch.
    #[test]
    fn tonelli_shanks_large_p_equiv_1_mod_4() {
        // p = 1009 ≡ 1 (mod 4). Pick a QR.
        let p = b(1009);
        // 64 = 8² is obviously a QR mod 1009.
        let r = tonelli_shanks_sqrt_mod_prime(&b(64), &p).expect("QR");
        let r_sq = (&r * &r).mod_floor(&p);
        assert_eq!(r_sq, b(64));
    }
}
