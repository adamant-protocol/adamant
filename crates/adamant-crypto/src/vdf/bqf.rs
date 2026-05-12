//! Binary quadratic forms over imaginary quadratic order, per
//! whitepaper §3.8.1.
//!
//! Phase 7.5.1a — the class-group arithmetic foundation. The
//! Wesolowski VDF over class groups of imaginary quadratic order
//! per §3.8.1 represents group elements as **reduced positive
//! definite binary quadratic forms** `f(x, y) = ax² + bxy + cy²`
//! with negative discriminant `D = b² − 4ac < 0`. This module
//! ships the form type, the reduction algorithm that brings any
//! form to its canonical representative, and the form-level
//! predicates the rest of the VDF layer relies on (identity,
//! inverse, equality via canonical reduction).
//!
//! Composition (NUDPL) lands at Phase 7.5.1b; squaring at 7.5.1c;
//! the `ClassGroupElement ↔ BinaryQuadraticForm` encoding bridge
//! at 7.5.1d.
//!
//! # Background
//!
//! The class group of imaginary quadratic order of discriminant
//! `D` is the quotient of the group of proper equivalence classes
//! of integral primitive positive definite binary quadratic forms
//! of discriminant `D` modulo proper equivalence. The order of
//! this group is `h(D)`, the class number — for `|D|` of size 2^k
//! the class number is roughly 2^(k/2). The Wesolowski VDF security
//! reduces to the adaptive root assumption in this group, which is
//! conjectured to hold against both classical and quantum
//! adversaries (Wesolowski 2019; §3.8.4).
//!
//! # Reduction
//!
//! Every proper equivalence class of positive definite binary
//! quadratic forms of discriminant `D < 0` contains a unique
//! **reduced** representative defined by:
//!
//! 1. `a > 0` (positive definite ⇒ leading coefficient positive)
//! 2. `|b| ≤ a ≤ c`
//! 3. If `|b| = a`, then `b ≥ 0`
//! 4. If `a = c`, then `b ≥ 0`
//!
//! Conditions 3 and 4 break the ties that would otherwise produce
//! two reduced representatives per class (`(a, b, c)` and
//! `(a, −b, c)` when `|b| = a` or `a = c`).
//!
//! The reduction algorithm here follows Cohen, "A Course in
//! Computational Algebraic Number Theory" (Springer 1993),
//! Algorithm 5.4.2. It alternates between two operations until
//! convergence:
//!
//! - **Normalize:** find an integer `s` such that
//!   `b' = b + 2as ∈ (−a, a]`, then update `c` to preserve the
//!   discriminant: `c' = c + s(b + sa)`.
//! - **Swap:** if `a > c`, replace `(a, b, c)` with `(c, −b, a)`.
//!   (Properly equivalent; preserves discriminant.)
//!
//! The algorithm terminates in `O(log(max(a, b, c)))` iterations
//! because every swap strictly decreases `a` until `a ≤ c`.
//!
//! # Adamant-native posture
//!
//! Per CLAUDE.md §14, this module is Adamant-authored against the
//! `num-bigint` workspace utility (Cat E). No external class-group
//! crate is consumed; the class-group arithmetic is owned by
//! Adamant end-to-end. `num-bigint` provides only the `BigInt`
//! primitive — the form-level mathematics here is original code.
//!
//! # What this module ships at Phase 7.5.1a
//!
//! - [`BinaryQuadraticForm`] — the `(a, b, c)` triple over `BigInt`.
//! - [`BqfError`] — typed construction-error variants.
//! - [`BinaryQuadraticForm::new`] — validating constructor.
//! - [`BinaryQuadraticForm::discriminant`] — `D = b² − 4ac`.
//! - [`BinaryQuadraticForm::identity`] — principal form for `D`.
//! - [`BinaryQuadraticForm::is_positive_definite`] —
//!   `a > 0 ∧ c > 0 ∧ D < 0`.
//! - [`BinaryQuadraticForm::is_normal`] — `−a < b ≤ a`.
//! - [`BinaryQuadraticForm::is_reduced`] — Cohen 5.4.2.
//! - [`BinaryQuadraticForm::normalize`] — bring `b` into `(−a, a]`.
//! - [`BinaryQuadraticForm::reduce`] — full Cohen 5.4.2 reduction.
//! - [`BinaryQuadraticForm::inverse`] — `(a, b, c) ↦ (a, −b, c)`.
//!
//! # What lands at later Phase 7.5.1 sub-sub-arcs
//!
//! - **7.5.1b** — composition (NUDPL). The class-group operation.
//! - **7.5.1c** — squaring. Fast special case of composition for
//!   the `T` sequential squarings the VDF evaluation performs.
//! - **7.5.1d** — canonical byte encoding for [`crate::vdf::ClassGroupElement`].
//!   The form is encoded as `(a, b)` only — `c` is recoverable
//!   from `c = (b² − D) / (4a)` given the chain-fixed discriminant.

use core::fmt;

use num_bigint::BigInt;
use num_integer::Integer;
use num_traits::{One, Signed, Zero};
use serde::{Deserialize, Serialize};

/// A binary quadratic form `f(x, y) = ax² + bxy + cy²` over the
/// integers, represented by its coefficient triple `(a, b, c)`.
///
/// Used as the in-memory representation of class-group elements in
/// the Wesolowski VDF per whitepaper §3.8.1. Coefficients are
/// arbitrary-precision integers (`num_bigint::BigInt`) because the
/// VDF operates over class groups of discriminant size ≥ 2048 bits
/// per §3.8.2.
///
/// # Invariants
///
/// `BinaryQuadraticForm` does NOT enforce reduction or positive
/// definiteness at construction time — those are properties of
/// specific values, validated via [`Self::is_reduced`] and
/// [`Self::is_positive_definite`] respectively. The validating
/// constructor [`Self::new`] only rejects coefficients with
/// `a == 0` (which would degenerate the quadratic form).
///
/// In Wesolowski-VDF use sites, every form produced by the class-
/// group operations is brought to reduced canonical form at the
/// end of each operation; equality on reduced forms is the
/// equivalence relation the class group quotients by.
///
/// # Serialisation
///
/// `BinaryQuadraticForm` derives `Serialize` / `Deserialize` via
/// `num-bigint`'s `serde` feature. BCS round-trip is supported but
/// the precise byte layout for the [`crate::vdf::ClassGroupElement`]
/// wire encoding is pinned at Phase 7.5.1d (currently the wire
/// encoding is opaque bytes; Phase 7.5.1d introduces the
/// `to_class_group_element` / `from_class_group_element` bridge).
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BinaryQuadraticForm {
    /// The leading coefficient `a` in `ax² + bxy + cy²`.
    pub a: BigInt,

    /// The middle coefficient `b` in `ax² + bxy + cy²`.
    pub b: BigInt,

    /// The trailing coefficient `c` in `ax² + bxy + cy²`.
    pub c: BigInt,
}

/// Errors produced by [`BinaryQuadraticForm`] construction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BqfError {
    /// The leading coefficient `a` is zero, which would degenerate
    /// the quadratic form into a linear polynomial in `y`.
    ZeroLeadingCoefficient,

    /// The supplied discriminant is non-negative. Positive definite
    /// binary quadratic forms require `D < 0`; this error fires
    /// when a caller asks for the identity element under a
    /// discriminant that doesn't correspond to an imaginary
    /// quadratic order.
    NonNegativeDiscriminant,

    /// The supplied discriminant is incompatible with any integral
    /// binary quadratic form. Concretely: `D ≢ 0, 1 (mod 4)`.
    /// Quadratic discriminants must satisfy `D ≡ b² (mod 4)` and
    /// `b² mod 4 ∈ {0, 1}`, so any integer ≡ 2 or 3 mod 4 cannot
    /// be the discriminant of an integral form.
    InvalidDiscriminantResidue,
}

impl fmt::Display for BqfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroLeadingCoefficient => {
                f.write_str("binary quadratic form has zero leading coefficient")
            }
            Self::NonNegativeDiscriminant => f.write_str(
                "imaginary quadratic order requires negative discriminant; supplied D ≥ 0",
            ),
            Self::InvalidDiscriminantResidue => {
                f.write_str("integral quadratic discriminant must satisfy D ≡ 0 or 1 (mod 4)")
            }
        }
    }
}

impl std::error::Error for BqfError {}

impl BinaryQuadraticForm {
    /// Constructs a binary quadratic form from its coefficients,
    /// rejecting only the structurally invalid `a = 0` case.
    ///
    /// Reduction, positive-definiteness, and a specific discriminant
    /// value are NOT enforced here — they are properties checked
    /// separately via [`Self::is_reduced`], [`Self::is_positive_definite`],
    /// and [`Self::discriminant`].
    ///
    /// # Errors
    ///
    /// Returns [`BqfError::ZeroLeadingCoefficient`] if `a == 0`.
    pub fn new(a: BigInt, b: BigInt, c: BigInt) -> Result<Self, BqfError> {
        if a.is_zero() {
            return Err(BqfError::ZeroLeadingCoefficient);
        }
        Ok(Self { a, b, c })
    }

    /// Returns the discriminant `D = b² − 4ac`.
    ///
    /// Any operation preserving proper equivalence (normalize,
    /// reduce, compose, invert) preserves the discriminant. The
    /// discriminant is the invariant that determines which class
    /// group a form belongs to.
    #[must_use]
    pub fn discriminant(&self) -> BigInt {
        &self.b * &self.b - BigInt::from(4) * &self.a * &self.c
    }

    /// Returns the principal form (the class-group identity element)
    /// for the supplied discriminant.
    ///
    /// The principal form is `(1, 0, −D/4)` when `D ≡ 0 (mod 4)`,
    /// and `(1, 1, (1−D)/4)` when `D ≡ 1 (mod 4)`. Both choices
    /// yield discriminant `D` by direct computation and are reduced
    /// by inspection (`a = 1`, `|b| ≤ a`, `a ≤ c` for `D < −4`).
    ///
    /// # Errors
    ///
    /// - [`BqfError::NonNegativeDiscriminant`] if `D ≥ 0`.
    /// - [`BqfError::InvalidDiscriminantResidue`] if
    ///   `D ≢ 0, 1 (mod 4)`.
    pub fn identity(discriminant: &BigInt) -> Result<Self, BqfError> {
        if !discriminant.is_negative() {
            return Err(BqfError::NonNegativeDiscriminant);
        }
        let four = BigInt::from(4);
        // mod_floor gives a non-negative result in [0, 4) regardless
        // of sign — the canonical "least non-negative residue".
        let residue = discriminant.mod_floor(&four);
        if residue == BigInt::zero() {
            // D ≡ 0 (mod 4): identity = (1, 0, −D/4).
            let c = -discriminant / &four;
            Ok(Self {
                a: BigInt::one(),
                b: BigInt::zero(),
                c,
            })
        } else if residue == BigInt::one() {
            // D ≡ 1 (mod 4): identity = (1, 1, (1−D)/4).
            let c = (BigInt::one() - discriminant) / &four;
            Ok(Self {
                a: BigInt::one(),
                b: BigInt::one(),
                c,
            })
        } else {
            Err(BqfError::InvalidDiscriminantResidue)
        }
    }

    /// Returns the inverse of this form in the class group.
    ///
    /// For a form `(a, b, c)`, the inverse is `(a, −b, c)`. The
    /// discriminant `b² − 4ac = (−b)² − 4ac` is preserved.
    ///
    /// The result is reduced iff the input is reduced AND `b ≠ a`
    /// AND `a ≠ c`; the boundary cases produce a non-reduced form
    /// that must be re-reduced before equality comparison.
    #[must_use]
    pub fn inverse(&self) -> Self {
        Self {
            a: self.a.clone(),
            b: -self.b.clone(),
            c: self.c.clone(),
        }
    }

    /// Returns `true` iff the form is positive definite, i.e.
    /// `a > 0 ∧ c > 0 ∧ D < 0`.
    ///
    /// Positive definite forms are the ones used in the imaginary
    /// quadratic class group: their values `f(x, y)` are always
    /// non-negative for real `(x, y)`, and the class-group operations
    /// preserve positive definiteness.
    #[must_use]
    pub fn is_positive_definite(&self) -> bool {
        self.a.is_positive() && self.c.is_positive() && self.discriminant().is_negative()
    }

    /// Returns `true` iff the form is **normalized**: `−a < b ≤ a`.
    ///
    /// Every form can be normalized in one step via [`Self::normalize`].
    /// Normalization is a prerequisite for the swap-step of the
    /// reduction algorithm.
    #[must_use]
    pub fn is_normal(&self) -> bool {
        // -a < b  iff  b > -a  iff  b + a > 0
        // b ≤ a  iff  a - b ≥ 0
        let neg_a = -&self.a;
        self.b > neg_a && self.b <= self.a
    }

    /// Returns `true` iff the form is **reduced** per Cohen 5.4.2.
    ///
    /// A positive definite form `(a, b, c)` is reduced iff:
    ///
    /// 1. `a > 0`
    /// 2. `|b| ≤ a ≤ c`
    /// 3. If `|b| = a`, then `b ≥ 0`
    /// 4. If `a = c`, then `b ≥ 0`
    ///
    /// Every proper equivalence class of positive definite forms
    /// of a fixed discriminant `D < 0` contains exactly one reduced
    /// representative.
    #[must_use]
    pub fn is_reduced(&self) -> bool {
        if !self.a.is_positive() {
            return false;
        }
        let abs_b = self.b.abs();
        // |b| ≤ a ≤ c
        if abs_b > self.a || self.a > self.c {
            return false;
        }
        // Tie-breakers: if |b| = a or a = c, require b ≥ 0
        if (abs_b == self.a || self.a == self.c) && self.b.is_negative() {
            return false;
        }
        true
    }

    /// Brings `b` into the canonical range `(−a, a]` in a single
    /// step, adjusting `c` to preserve the discriminant.
    ///
    /// Concretely, finds `s = ⌊(a − b) / (2a)⌋` and applies the
    /// substitution
    ///
    /// ```text
    /// b' = b + 2as
    /// c' = c + s(b + sa)
    /// ```
    ///
    /// One verifies directly that `(b')² − 4ac' = b² − 4ac`, so the
    /// discriminant is preserved. The substitution is a proper
    /// equivalence: it corresponds to the unimodular change of
    /// variables `(x, y) ↦ (x + sy, y)` of determinant 1.
    ///
    /// After [`Self::normalize`] returns, [`Self::is_normal`] is
    /// `true`.
    ///
    /// # Panics
    ///
    /// Panics if `a == 0`. Use [`Self::new`] to construct forms;
    /// the validating constructor rejects `a == 0`, so a form built
    /// via the public API never panics here.
    pub fn normalize(&mut self) {
        assert!(
            !self.a.is_zero(),
            "BinaryQuadraticForm with a = 0 cannot be normalized; construct via `new` which rejects this case"
        );
        // Compute s = floor((a - b) / (2a)).
        // For a > 0 this is the unique integer such that
        // -a < b + 2as ≤ a.
        let two_a = BigInt::from(2) * &self.a;
        // If a is already positive, division-floor is well-defined.
        // If a is negative (which positive-definite forms forbid but
        // the structural type allows), Integer::div_floor still
        // returns a deterministic result via the standard
        // floor-division semantics; the caller is responsible for
        // ensuring the form is positive definite before relying on
        // normalize's mathematical meaning.
        let numerator = &self.a - &self.b;
        let s = numerator.div_floor(&two_a);
        if s.is_zero() {
            return;
        }
        // c' = c + s * (b + s * a)
        let b_plus_sa = &self.b + &s * &self.a;
        self.c = &self.c + &s * b_plus_sa;
        // b' = b + 2as
        self.b = &self.b + &s * &two_a;
    }

    /// Reduces the form to its unique reduced canonical
    /// representative per Cohen 5.4.2.
    ///
    /// Alternates [`Self::normalize`] and a swap step
    /// (`(a, b, c) ↦ (c, −b, a)` when `a > c`) until both
    /// conditions hold. Terminates in `O(log(max(|a|, |b|, |c|)))`
    /// iterations.
    ///
    /// After the algorithm exits the loop, an explicit edge case
    /// handles the `a = c ∧ b < 0` boundary by flipping `b`'s sign.
    /// This corresponds to choosing the `b ≥ 0` representative when
    /// the form sits on the `a = c` boundary of the fundamental
    /// domain.
    ///
    /// # Panics
    ///
    /// Panics if the form is not positive definite. The reduction
    /// algorithm is defined only for positive definite forms; on
    /// indefinite forms it may not terminate or may produce a
    /// nonsensical result. Use [`Self::is_positive_definite`] to
    /// validate before calling.
    pub fn reduce(&mut self) {
        assert!(
            self.is_positive_definite(),
            "BinaryQuadraticForm::reduce requires a positive definite form (a > 0, c > 0, D < 0)"
        );
        loop {
            self.normalize();
            if self.a > self.c {
                // Swap: (a, b, c) ↦ (c, −b, a)
                std::mem::swap(&mut self.a, &mut self.c);
                self.b = -self.b.clone();
            } else {
                break;
            }
        }
        // Edge case: on the a = c boundary, choose b ≥ 0.
        // Same shape as the |b| = a boundary, which `normalize`
        // already handles via the half-open interval (−a, a].
        if self.a == self.c && self.b.is_negative() {
            self.b = -self.b.clone();
        }
    }

    /// Returns the reduced form equivalent to `self`, without
    /// mutating `self`.
    ///
    /// Convenience wrapper around [`Self::reduce`] for cases where
    /// the caller wants to compute a reduced representative without
    /// disturbing the input. Allocates one fresh form.
    ///
    /// # Panics
    ///
    /// Panics if the form is not positive definite. See
    /// [`Self::reduce`].
    #[must_use]
    pub fn reduced(&self) -> Self {
        let mut clone = self.clone();
        clone.reduce();
        clone
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Small-discriminant fixture: D = −23. Class number is 3;
    /// reduced forms are `(1, 1, 6)`, `(2, 1, 3)`, `(2, −1, 3)`.
    fn discriminant_neg_23() -> BigInt {
        BigInt::from(-23)
    }

    /// Discriminant ≡ 0 mod 4 fixture: D = −20. Class number is 2;
    /// reduced forms are `(1, 0, 5)` and `(2, 2, 3)`.
    fn discriminant_neg_20() -> BigInt {
        BigInt::from(-20)
    }

    #[test]
    fn new_accepts_nonzero_a() {
        let f = BinaryQuadraticForm::new(BigInt::from(1), BigInt::from(0), BigInt::from(5))
            .expect("construct");
        assert_eq!(f.a, BigInt::from(1));
    }

    #[test]
    fn new_rejects_zero_a() {
        let err = BinaryQuadraticForm::new(BigInt::zero(), BigInt::from(1), BigInt::from(2))
            .expect_err("zero-a must be rejected");
        assert_eq!(err, BqfError::ZeroLeadingCoefficient);
    }

    #[test]
    fn discriminant_matches_formula() {
        let f = BinaryQuadraticForm::new(BigInt::from(2), BigInt::from(1), BigInt::from(3))
            .expect("construct");
        // D = 1 - 24 = -23
        assert_eq!(f.discriminant(), BigInt::from(-23));
    }

    #[test]
    fn identity_d_minus_23_is_one_one_six() {
        let f = BinaryQuadraticForm::identity(&discriminant_neg_23()).expect("identity");
        assert_eq!(f.a, BigInt::from(1));
        assert_eq!(f.b, BigInt::from(1));
        assert_eq!(f.c, BigInt::from(6));
        assert_eq!(f.discriminant(), discriminant_neg_23());
        assert!(f.is_reduced());
        assert!(f.is_positive_definite());
    }

    #[test]
    fn identity_d_minus_20_is_one_zero_five() {
        let f = BinaryQuadraticForm::identity(&discriminant_neg_20()).expect("identity");
        assert_eq!(f.a, BigInt::from(1));
        assert_eq!(f.b, BigInt::from(0));
        assert_eq!(f.c, BigInt::from(5));
        assert_eq!(f.discriminant(), discriminant_neg_20());
        assert!(f.is_reduced());
        assert!(f.is_positive_definite());
    }

    #[test]
    fn identity_rejects_positive_discriminant() {
        let err = BinaryQuadraticForm::identity(&BigInt::from(20)).expect_err("must reject");
        assert_eq!(err, BqfError::NonNegativeDiscriminant);
    }

    #[test]
    fn identity_rejects_zero_discriminant() {
        let err = BinaryQuadraticForm::identity(&BigInt::zero()).expect_err("must reject");
        assert_eq!(err, BqfError::NonNegativeDiscriminant);
    }

    #[test]
    fn identity_rejects_d_equiv_2_mod_4() {
        // D = -2 ≡ 2 (mod 4); invalid integral discriminant.
        let err = BinaryQuadraticForm::identity(&BigInt::from(-2)).expect_err("must reject");
        assert_eq!(err, BqfError::InvalidDiscriminantResidue);
    }

    #[test]
    fn identity_rejects_d_equiv_3_mod_4() {
        // D = -1 ≡ 3 (mod 4); invalid integral discriminant.
        let err = BinaryQuadraticForm::identity(&BigInt::from(-1)).expect_err("must reject");
        assert_eq!(err, BqfError::InvalidDiscriminantResidue);
    }

    #[test]
    fn is_positive_definite_rejects_non_positive_a() {
        let f = BinaryQuadraticForm::new(BigInt::from(-1), BigInt::from(0), BigInt::from(5))
            .expect("construct");
        assert!(!f.is_positive_definite());
    }

    #[test]
    fn is_positive_definite_rejects_non_negative_discriminant() {
        // a = 1, b = 3, c = 1 → D = 9 - 4 = 5 > 0
        let f = BinaryQuadraticForm::new(BigInt::from(1), BigInt::from(3), BigInt::from(1))
            .expect("construct");
        assert!(!f.is_positive_definite());
    }

    #[test]
    fn is_normal_boundary_b_equals_a_is_normal() {
        // b = a (upper bound, inclusive): normal
        let f = BinaryQuadraticForm::new(BigInt::from(3), BigInt::from(3), BigInt::from(5))
            .expect("construct");
        assert!(f.is_normal());
    }

    #[test]
    fn is_normal_boundary_b_equals_neg_a_is_not_normal() {
        // b = -a (lower bound, exclusive): not normal
        let f = BinaryQuadraticForm::new(BigInt::from(3), BigInt::from(-3), BigInt::from(5))
            .expect("construct");
        assert!(!f.is_normal());
    }

    #[test]
    fn is_normal_rejects_b_above_a() {
        let f = BinaryQuadraticForm::new(BigInt::from(3), BigInt::from(7), BigInt::from(5))
            .expect("construct");
        assert!(!f.is_normal());
    }

    #[test]
    fn is_reduced_for_canonical_d_minus_23_forms() {
        // The three reduced forms of class group for D = -23
        let principal = BinaryQuadraticForm::new(BigInt::from(1), BigInt::from(1), BigInt::from(6))
            .expect("construct");
        assert!(principal.is_reduced());

        let f2 = BinaryQuadraticForm::new(BigInt::from(2), BigInt::from(1), BigInt::from(3))
            .expect("construct");
        assert!(f2.is_reduced());

        let f3 = BinaryQuadraticForm::new(BigInt::from(2), BigInt::from(-1), BigInt::from(3))
            .expect("construct");
        assert!(f3.is_reduced());
    }

    #[test]
    fn is_reduced_rejects_a_greater_than_c() {
        let f = BinaryQuadraticForm::new(BigInt::from(5), BigInt::from(1), BigInt::from(2))
            .expect("construct");
        assert!(!f.is_reduced());
    }

    #[test]
    fn is_reduced_rejects_tie_break_violation_abs_b_equals_a_with_negative_b() {
        // |b| = a but b < 0: not reduced
        let f = BinaryQuadraticForm::new(BigInt::from(3), BigInt::from(-3), BigInt::from(5))
            .expect("construct");
        assert!(!f.is_reduced());
    }

    #[test]
    fn is_reduced_accepts_tie_break_abs_b_equals_a_with_positive_b() {
        let f = BinaryQuadraticForm::new(BigInt::from(3), BigInt::from(3), BigInt::from(5))
            .expect("construct");
        assert!(f.is_reduced());
    }

    #[test]
    fn is_reduced_rejects_tie_break_a_equals_c_with_negative_b() {
        let f = BinaryQuadraticForm::new(BigInt::from(3), BigInt::from(-2), BigInt::from(3))
            .expect("construct");
        assert!(!f.is_reduced());
    }

    #[test]
    fn is_reduced_accepts_tie_break_a_equals_c_with_positive_b() {
        let f = BinaryQuadraticForm::new(BigInt::from(3), BigInt::from(2), BigInt::from(3))
            .expect("construct");
        assert!(f.is_reduced());
    }

    #[test]
    fn normalize_brings_b_into_canonical_range() {
        // Start with (3, 5, 4): D = 25 - 48 = -23
        let mut f = BinaryQuadraticForm::new(BigInt::from(3), BigInt::from(5), BigInt::from(4))
            .expect("construct");
        let d_before = f.discriminant();
        f.normalize();
        assert!(f.is_normal());
        // Discriminant preserved
        assert_eq!(f.discriminant(), d_before);
    }

    #[test]
    fn normalize_is_idempotent_on_normal_form() {
        let mut f = BinaryQuadraticForm::new(BigInt::from(3), BigInt::from(2), BigInt::from(5))
            .expect("construct");
        let before = f.clone();
        f.normalize();
        assert_eq!(f, before);
    }

    #[test]
    fn reduce_worked_example_d_minus_23() {
        // From the module docs' worked example:
        // (3, 5, 4) reduces to (2, 1, 3).
        let mut f = BinaryQuadraticForm::new(BigInt::from(3), BigInt::from(5), BigInt::from(4))
            .expect("construct");
        f.reduce();
        assert_eq!(f.a, BigInt::from(2));
        assert_eq!(f.b, BigInt::from(1));
        assert_eq!(f.c, BigInt::from(3));
        assert!(f.is_reduced());
    }

    #[test]
    fn reduce_preserves_discriminant() {
        let mut f = BinaryQuadraticForm::new(BigInt::from(7), BigInt::from(13), BigInt::from(8))
            .expect("construct");
        let d_before = f.discriminant();
        f.reduce();
        assert_eq!(f.discriminant(), d_before);
        assert!(f.is_reduced());
    }

    #[test]
    fn reduce_idempotent_on_already_reduced_form() {
        let f = BinaryQuadraticForm::new(BigInt::from(2), BigInt::from(1), BigInt::from(3))
            .expect("construct");
        let reduced = f.reduced();
        assert_eq!(reduced, f);
    }

    #[test]
    fn reduce_identity_d_minus_23_is_fixed() {
        let identity = BinaryQuadraticForm::identity(&discriminant_neg_23()).expect("identity");
        let reduced = identity.reduced();
        assert_eq!(reduced, identity);
    }

    #[test]
    fn reduce_handles_a_equals_c_boundary() {
        // (3, -2, 3) is normalized (|b| < a) but not reduced (b < 0 at a = c)
        let f = BinaryQuadraticForm::new(BigInt::from(3), BigInt::from(-2), BigInt::from(3))
            .expect("construct");
        let reduced = f.reduced();
        assert_eq!(reduced.a, BigInt::from(3));
        assert_eq!(reduced.b, BigInt::from(2));
        assert_eq!(reduced.c, BigInt::from(3));
        assert!(reduced.is_reduced());
    }

    #[test]
    fn inverse_negates_b() {
        let f = BinaryQuadraticForm::new(BigInt::from(2), BigInt::from(1), BigInt::from(3))
            .expect("construct");
        let inv = f.inverse();
        assert_eq!(inv.a, BigInt::from(2));
        assert_eq!(inv.b, BigInt::from(-1));
        assert_eq!(inv.c, BigInt::from(3));
    }

    #[test]
    fn inverse_preserves_discriminant() {
        let f = BinaryQuadraticForm::new(BigInt::from(2), BigInt::from(1), BigInt::from(3))
            .expect("construct");
        let inv = f.inverse();
        assert_eq!(f.discriminant(), inv.discriminant());
    }

    #[test]
    fn inverse_is_involutive() {
        let f = BinaryQuadraticForm::new(BigInt::from(2), BigInt::from(1), BigInt::from(3))
            .expect("construct");
        let inv_inv = f.inverse().inverse();
        assert_eq!(inv_inv, f);
    }

    #[test]
    fn inverse_of_identity_d_minus_20_is_self() {
        // For D ≡ 0 (mod 4), the identity is (1, 0, c) and its
        // inverse is itself because b = 0 → -b = 0.
        let identity = BinaryQuadraticForm::identity(&discriminant_neg_20()).expect("identity");
        let inv = identity.inverse();
        assert_eq!(inv, identity);
    }

    #[test]
    fn reduce_handles_large_initial_form() {
        // Moderate-sized positive definite form: confirm the
        // algorithm terminates and produces a reduced result
        // preserving the discriminant. We pick `c` large enough that
        // `4ac > b²` so D < 0 (positive definite).
        let mut f =
            BinaryQuadraticForm::new(BigInt::from(5), BigInt::from(3), BigInt::from(10_000))
                .expect("construct");
        let d_before = f.discriminant();
        assert!(f.is_positive_definite());
        f.reduce();
        assert!(f.is_reduced());
        assert_eq!(f.discriminant(), d_before);
    }

    #[test]
    fn bqf_serde_round_trips_via_bcs() {
        let f = BinaryQuadraticForm::new(BigInt::from(2), BigInt::from(1), BigInt::from(3))
            .expect("construct");
        let bytes = bcs::to_bytes(&f).expect("serialise");
        let recovered: BinaryQuadraticForm = bcs::from_bytes(&bytes).expect("deserialise");
        assert_eq!(f, recovered);
    }

    #[test]
    fn bqf_error_display_messages_are_meaningful() {
        let variants = [
            BqfError::ZeroLeadingCoefficient,
            BqfError::NonNegativeDiscriminant,
            BqfError::InvalidDiscriminantResidue,
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
    fn bqf_error_implements_std_error() {
        fn assert_err<E: std::error::Error>() {}
        assert_err::<BqfError>();
    }

    /// Property test: every reduction of a positive definite form
    /// produces a result satisfying `is_reduced` AND preserving the
    /// discriminant.
    #[test]
    fn reduce_invariants_across_several_inputs() {
        // A handful of positive definite forms with various
        // discriminants and unreduced starting points.
        let inputs = [
            (BigInt::from(3), BigInt::from(5), BigInt::from(4)),
            (BigInt::from(7), BigInt::from(13), BigInt::from(11)),
            (BigInt::from(11), BigInt::from(7), BigInt::from(13)),
            (BigInt::from(5), BigInt::from(2), BigInt::from(7)),
            (BigInt::from(101), BigInt::from(99), BigInt::from(103)),
        ];
        for (a, b, c) in inputs {
            let f = BinaryQuadraticForm::new(a.clone(), b.clone(), c.clone()).expect("construct");
            if !f.is_positive_definite() {
                continue;
            }
            let d_before = f.discriminant();
            let reduced = f.reduced();
            assert!(
                reduced.is_reduced(),
                "reduction of ({a}, {b}, {c}) failed to produce a reduced form: ({}, {}, {})",
                reduced.a,
                reduced.b,
                reduced.c,
            );
            assert_eq!(
                reduced.discriminant(),
                d_before,
                "reduction of ({a}, {b}, {c}) did not preserve discriminant"
            );
            assert!(
                reduced.is_positive_definite(),
                "reduction of ({a}, {b}, {c}) lost positive definiteness"
            );
        }
    }

    /// Property: equivalence-class equality via reduction. Two
    /// forms are properly equivalent iff their reductions are
    /// byte-equal.
    #[test]
    fn equivalent_forms_reduce_to_same_representative() {
        // (3, 5, 4) and (2, 1, 3) are in the same class for D = -23.
        let f1 = BinaryQuadraticForm::new(BigInt::from(3), BigInt::from(5), BigInt::from(4))
            .expect("construct");
        let f2 = BinaryQuadraticForm::new(BigInt::from(2), BigInt::from(1), BigInt::from(3))
            .expect("construct");
        assert_eq!(f1.discriminant(), f2.discriminant());
        assert_eq!(f1.reduced(), f2.reduced());
    }
}
