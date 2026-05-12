//! Binary quadratic forms over imaginary quadratic order, per
//! whitepaper §3.8.1.
//!
//! Phase 7.5.1a/b — the class-group arithmetic foundation. The
//! Wesolowski VDF over class groups of imaginary quadratic order
//! per §3.8.1 represents group elements as **reduced positive
//! definite binary quadratic forms** `f(x, y) = ax² + bxy + cy²`
//! with negative discriminant `D = b² − 4ac < 0`. This module
//! ships the form type (Phase 7.5.1a), the reduction algorithm
//! that brings any form to its canonical representative
//! (Phase 7.5.1a), the form-level predicates the rest of the VDF
//! layer relies on (Phase 7.5.1a), and Gauss composition — the
//! class-group multiplication operation (Phase 7.5.1b).
//!
//! Fast squaring (NUDPL specialisation) lands at Phase 7.5.1c;
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
//! # What this module adds at Phase 7.5.1b
//!
//! - [`BinaryQuadraticForm::compose`] — Gauss composition per
//!   Cohen "A Course in Computational Algebraic Number Theory"
//!   Algorithm 5.4.7. Returns the **reduced** product
//!   `f₁ ∘ f₂` in the class group of their shared discriminant.
//! - [`BqfError::MismatchedDiscriminants`] — error variant for
//!   composition of forms living in different class groups.
//!
//! # What lands at later Phase 7.5.1 sub-sub-arcs
//!
//! - **7.5.1c** — fast squaring (Shanks NUDPL specialisation).
//!   The Wesolowski VDF performs `T` sequential squarings during
//!   evaluation, and a specialised squaring saves one extended
//!   GCD per iteration. General composition (this commit) covers
//!   correctness; `square()` lands at 7.5.1c as a performance
//!   optimisation.
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

    /// Composition was attempted on two forms with different
    /// discriminants. The class group is parameterised by its
    /// discriminant; composition is only defined for forms living
    /// in the same class group. Phase 7.5.1b's
    /// [`BinaryQuadraticForm::compose`] is the production site.
    MismatchedDiscriminants,
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
            Self::MismatchedDiscriminants => f.write_str(
                "binary quadratic form composition requires both operands to share a discriminant",
            ),
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

    /// Composes `self` with `other` in their shared class group,
    /// returning the reduced product.
    ///
    /// Implements Cohen, "A Course in Computational Algebraic
    /// Number Theory" Algorithm 5.4.7 (Composition of Forms).
    /// Given `f₁ = (a₁, b₁, c₁)` and `f₂ = (a₂, b₂, c₂)` of the
    /// same discriminant `D`, computes the product `f₁ ∘ f₂` in
    /// the proper-equivalence class group of `D` and returns its
    /// reduced canonical representative.
    ///
    /// # Algorithm sketch
    ///
    /// 1. If `a₁ < a₂`, swap. After swap, `a₁ ≥ a₂`.
    /// 2. Set `s = (b₁ + b₂) / 2` and `n = b₂ − s = (b₂ − b₁) / 2`.
    /// 3. Apply extended Euclid to `(a₂, a₁)`, obtaining
    ///    `d₁ = gcd(a₂, a₁)` and `u, v` with `u·a₂ + v·a₁ = d₁`.
    /// 4. If `d₁ ∣ s`, set `d := d₁` and `A := −u · n`.
    ///    Otherwise apply extended Euclid to `(s, d₁)`, obtaining
    ///    `d = gcd(s, d₁)` and `x, y` with `x·s + y·d₁ = d`. Set
    ///    `A := −y · u · n − x · c₂`.
    /// 5. Reduce `A` modulo `a₁/d` to canonical range `[0, a₁/d)`.
    /// 6. Set
    ///    - `A_new = (a₁ / d) · (a₂ / d) = (a₁ · a₂) / d²`
    ///    - `B_new = b₂ + 2 · (a₂ / d) · A`
    ///    - `C_new = (B_new² − D) / (4 · A_new)`
    ///
    ///    and reduce the resulting form to its canonical
    ///    representative.
    ///
    /// # Correctness
    ///
    /// `b₁ ≡ b₂ (mod 2)` because both forms share the same
    /// discriminant `D ≡ b² (mod 4)`, so `s = (b₁ + b₂)/2 ∈ ℤ`.
    /// Each step preserves the discriminant `D`; step 6
    /// computes `C_new` to make the discriminant of the result
    /// match `D` exactly. Reduction at the end produces the
    /// unique canonical representative of the resulting class.
    ///
    /// # Errors
    ///
    /// Returns [`BqfError::MismatchedDiscriminants`] if `self`
    /// and `other` have different discriminants.
    ///
    /// # Panics
    ///
    /// Panics if either operand is not positive definite. The
    /// composition algorithm here is specialised for the
    /// imaginary quadratic class group; for the indefinite case
    /// the reduction step at the end would diverge. Use
    /// [`Self::is_positive_definite`] to validate inputs.
    #[allow(
        clippy::many_single_char_names,
        reason = "Cohen Algorithm 5.4.7 uses single-letter variable names \
                  (s, n, d, u, v, x, y, l) that match the published \
                  algorithm; renaming would obscure the spec correspondence \
                  and break the comment-vs-code traceability the security \
                  review will rely on."
    )]
    pub fn compose(&self, other: &Self) -> Result<Self, BqfError> {
        // Same-discriminant precondition: composition is only
        // defined within a single class group.
        let d_self = self.discriminant();
        if d_self != other.discriminant() {
            return Err(BqfError::MismatchedDiscriminants);
        }

        assert!(
            self.is_positive_definite() && other.is_positive_definite(),
            "BinaryQuadraticForm::compose requires both operands to be positive definite (a > 0, c > 0, D < 0)"
        );

        // Step 1: swap so a₁ ≥ a₂.
        let (f1, f2) = if self.a < other.a {
            (other, self)
        } else {
            (self, other)
        };

        // Step 2: s = (b₁ + b₂) / 2, n = b₂ − s.
        let two = BigInt::from(2);
        let s = (&f1.b + &f2.b).div_floor(&two);
        let n = &f2.b - &s;

        // Step 3: extended Euclid for (a₂, a₁).
        // ExtendedGcd.x * a₂ + ExtendedGcd.y * a₁ = ExtendedGcd.gcd.
        let eg1 = f2.a.extended_gcd(&f1.a);
        let d1 = eg1.gcd;
        let u = eg1.x;

        // Step 4: branch on d₁ ∣ s.
        let (d, a_pre) = if s.mod_floor(&d1).is_zero() {
            // Simpler case: d := d₁, A := −u · n.
            let a_pre = -&u * &n;
            (d1.clone(), a_pre)
        } else {
            // General case: d := gcd(s, d₁); recompute A.
            // x * s + y * d₁ = d
            let eg2 = s.extended_gcd(&d1);
            let d = eg2.gcd;
            let x = eg2.x;
            let y = eg2.y;
            // A := −y · u · n − x · c₂
            let a_pre = -&y * &u * &n - &x * &f2.c;
            (d, a_pre)
        };

        // Step 5: reduce A mod (a₁ / d) to [0, a₁/d).
        let a1_over_d = &f1.a / &d;
        let l = a_pre.mod_floor(&a1_over_d);

        // Step 6: build (A_new, B_new, C_new).
        // A_new = (a₁ / d) · (a₂ / d) = a₁ · a₂ / d².
        let a2_over_d = &f2.a / &d;
        let a_new = &a1_over_d * &a2_over_d;
        // B_new = b₂ + 2 · (a₂/d) · l.
        let b_new = &f2.b + &two * &a2_over_d * &l;
        // C_new = (B_new² − D) / (4 · A_new). Discriminant
        // preservation guarantees exact divisibility.
        let four_a_new = BigInt::from(4) * &a_new;
        let c_new = (&b_new * &b_new - &d_self).div_floor(&four_a_new);

        // Construct + reduce. The resulting form's discriminant
        // equals `d_self` by construction; positive definiteness
        // follows because A_new > 0 (product of two positive
        // integers) and D < 0.
        let mut result = Self::new(a_new, b_new, c_new)?;
        result.reduce();
        Ok(result)
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

    // ---- Phase 7.5.1b: composition tests ----
    //
    // Most tests below exercise the D = -23 class group. The
    // class number is 3; the three reduced classes are represented
    // by the principal form `e = (1, 1, 6)`, `f = (2, 1, 3)`, and
    // `f² = (2, -1, 3)`. Composition follows the relations of the
    // cyclic group of order 3: f ∘ f = f², f ∘ f² = e, f² ∘ f² = f.

    /// The principal form for D = -23.
    fn principal_d23() -> BinaryQuadraticForm {
        BinaryQuadraticForm::new(BigInt::from(1), BigInt::from(1), BigInt::from(6))
            .expect("identity D=-23")
    }

    /// The generator form `f = (2, 1, 3)` for D = -23.
    fn generator_d23() -> BinaryQuadraticForm {
        BinaryQuadraticForm::new(BigInt::from(2), BigInt::from(1), BigInt::from(3))
            .expect("generator D=-23")
    }

    /// `f² = f⁻¹ = (2, -1, 3)` for D = -23 (class number 3).
    fn generator_squared_d23() -> BinaryQuadraticForm {
        BinaryQuadraticForm::new(BigInt::from(2), BigInt::from(-1), BigInt::from(3))
            .expect("generator squared D=-23")
    }

    #[test]
    fn compose_rejects_mismatched_discriminants() {
        // f₁ has D = -23, f₂ has D = -20.
        let f1 = generator_d23();
        let f2 = BinaryQuadraticForm::new(BigInt::from(1), BigInt::from(0), BigInt::from(5))
            .expect("construct"); // D = -20
        let err = f1
            .compose(&f2)
            .expect_err("composition across discriminants must fail");
        assert_eq!(err, BqfError::MismatchedDiscriminants);
    }

    #[test]
    fn compose_left_identity_is_identity() {
        // e ∘ f = f
        let e = principal_d23();
        let f = generator_d23();
        let result = e.compose(&f).expect("compose");
        assert_eq!(result, f);
    }

    #[test]
    fn compose_right_identity_is_identity() {
        // f ∘ e = f
        let f = generator_d23();
        let e = principal_d23();
        let result = f.compose(&e).expect("compose");
        assert_eq!(result, f);
    }

    #[test]
    fn compose_identity_with_itself_is_identity() {
        // e ∘ e = e
        let e = principal_d23();
        let result = e.compose(&e).expect("compose");
        assert_eq!(result, e);
    }

    #[test]
    fn compose_generator_with_itself_is_generator_squared() {
        // f ∘ f = f²
        let f = generator_d23();
        let result = f.compose(&f).expect("compose");
        assert_eq!(result, generator_squared_d23());
    }

    #[test]
    fn compose_generator_with_inverse_is_identity() {
        // f ∘ f⁻¹ = e (since f² = f⁻¹ in a group of order 3)
        let f = generator_d23();
        let f_inv = generator_squared_d23();
        let result = f.compose(&f_inv).expect("compose");
        assert_eq!(result, principal_d23());
    }

    #[test]
    fn compose_inverse_then_generator_is_identity() {
        // f⁻¹ ∘ f = e
        let f_inv = generator_squared_d23();
        let f = generator_d23();
        let result = f_inv.compose(&f).expect("compose");
        assert_eq!(result, principal_d23());
    }

    #[test]
    fn compose_generator_squared_with_itself_is_generator() {
        // f² ∘ f² = f⁴ = f (class number 3, so f³ = e ⇒ f⁴ = f)
        let f_sq = generator_squared_d23();
        let result = f_sq.compose(&f_sq).expect("compose");
        assert_eq!(result, generator_d23());
    }

    #[test]
    fn compose_generator_cubed_is_identity() {
        // f ∘ f ∘ f = e (class number = 3)
        let f = generator_d23();
        let f_sq = f.compose(&f).expect("compose");
        let f_cu = f_sq.compose(&f).expect("compose");
        assert_eq!(f_cu, principal_d23());
    }

    #[test]
    fn compose_preserves_discriminant() {
        let f = generator_d23();
        let result = f.compose(&f).expect("compose");
        assert_eq!(result.discriminant(), BigInt::from(-23));
    }

    #[test]
    fn compose_result_is_reduced() {
        let f = generator_d23();
        let result = f.compose(&f).expect("compose");
        assert!(result.is_reduced());
    }

    #[test]
    fn compose_is_commutative_on_d23() {
        // f₁ ∘ f₂ = f₂ ∘ f₁ for every pair in the class group.
        let classes = [principal_d23(), generator_d23(), generator_squared_d23()];
        for (i, f1) in classes.iter().enumerate() {
            for (j, f2) in classes.iter().enumerate() {
                let ab = f1.compose(f2).expect("compose");
                let ba = f2.compose(f1).expect("compose");
                assert_eq!(
                    ab, ba,
                    "composition not commutative for class {i} ∘ class {j}"
                );
            }
        }
    }

    #[test]
    fn compose_is_associative_on_d23() {
        // (f₁ ∘ f₂) ∘ f₃ = f₁ ∘ (f₂ ∘ f₃) for every triple.
        let classes = [principal_d23(), generator_d23(), generator_squared_d23()];
        for f1 in &classes {
            for f2 in &classes {
                for f3 in &classes {
                    let left = f1
                        .compose(f2)
                        .expect("compose")
                        .compose(f3)
                        .expect("compose");
                    let right = f1
                        .compose(&f2.compose(f3).expect("compose"))
                        .expect("compose");
                    assert_eq!(
                        left, right,
                        "composition not associative: ({f1:?} ∘ {f2:?}) ∘ {f3:?} ≠ {f1:?} ∘ ({f2:?} ∘ {f3:?})"
                    );
                }
            }
        }
    }

    #[test]
    fn compose_handles_a1_less_than_a2_swap() {
        // f₁ = principal (a = 1), f₂ = generator (a = 2). a₁ < a₂.
        // The algorithm must swap internally and still produce the
        // correct result f₁ ∘ f₂ = f₂.
        let f1 = principal_d23();
        let f2 = generator_d23();
        assert!(f1.a < f2.a);
        let result = f1.compose(&f2).expect("compose");
        assert_eq!(result, f2);
    }

    #[test]
    fn compose_d_minus_20_class_group() {
        // For D = -20, the class group has order 2. Reduced classes:
        //   e = (1, 0, 5)   (principal)
        //   g = (2, 2, 3)
        // Group relations: g ∘ g = e.
        let e = BinaryQuadraticForm::new(BigInt::from(1), BigInt::from(0), BigInt::from(5))
            .expect("identity D=-20");
        let g = BinaryQuadraticForm::new(BigInt::from(2), BigInt::from(2), BigInt::from(3))
            .expect("g D=-20");
        assert_eq!(e.discriminant(), BigInt::from(-20));
        assert_eq!(g.discriminant(), BigInt::from(-20));
        assert!(e.is_reduced());
        assert!(g.is_reduced());

        // g ∘ g = e
        let g_sq = g.compose(&g).expect("compose");
        assert_eq!(g_sq, e);

        // e ∘ g = g and g ∘ e = g
        assert_eq!(e.compose(&g).expect("compose"), g);
        assert_eq!(g.compose(&e).expect("compose"), g);
    }

    #[test]
    fn compose_with_unreduced_inputs_still_correct() {
        // Composition should be well-defined modulo proper equivalence,
        // so feeding unreduced (but equivalent) inputs should produce
        // the same reduced output as feeding reduced inputs.
        let f_reduced = generator_d23();
        let f_unreduced =
            BinaryQuadraticForm::new(BigInt::from(3), BigInt::from(5), BigInt::from(4))
                .expect("unreduced equivalent of f");
        // Confirm equivalence
        assert_eq!(f_unreduced.reduced(), f_reduced);

        let reduced_result = f_reduced.compose(&f_reduced).expect("compose");
        let unreduced_result = f_unreduced.compose(&f_unreduced).expect("compose");
        assert_eq!(reduced_result, unreduced_result);
    }
}
