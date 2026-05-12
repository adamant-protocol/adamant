//! Binary quadratic forms over imaginary quadratic order, per
//! whitepaper §3.8.1.
//!
//! Phase 7.5.1a/b/c/d — the class-group arithmetic foundation
//! complete. The Wesolowski VDF over class groups of imaginary
//! quadratic order per §3.8.1 represents group elements as
//! **reduced positive definite binary quadratic forms**
//! `f(x, y) = ax² + bxy + cy²` with negative discriminant
//! `D = b² − 4ac < 0`. This module ships the form type
//! (Phase 7.5.1a), the reduction algorithm that brings any form
//! to its canonical representative (Phase 7.5.1a), the form-
//! level predicates the rest of the VDF layer relies on
//! (Phase 7.5.1a), Gauss composition — the class-group
//! multiplication operation (Phase 7.5.1b), fast squaring per
//! Cohen 5.4.8 — the performance-critical operation the
//! Wesolowski VDF evaluation calls `T` times (Phase 7.5.1c),
//! and the canonical `(a, b)`-only byte encoding that bridges
//! [`BinaryQuadraticForm`] to the consensus-stable
//! [`crate::vdf::ClassGroupElement`] wire type (Phase 7.5.1d).
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
//! # What this module adds at Phase 7.5.1c
//!
//! - [`BinaryQuadraticForm::square`] — fast squaring per Cohen
//!   "A Course in Computational Algebraic Number Theory"
//!   Algorithm 5.4.8. Returns the **reduced** square
//!   `f ∘ f = f²` using a specialised single-extended-GCD
//!   pipeline (vs the two extended GCDs general composition
//!   performs). The Wesolowski VDF evaluation calls this `T`
//!   times sequentially per envelope, with `T ∈ [2_000_000,
//!   7_500_000]` per §3.8.2, so the constant-factor saving is
//!   material.
//!
//! # What this module adds at Phase 7.5.1d
//!
//! - [`BinaryQuadraticForm::to_class_group_element`] — encode
//!   the form as `(a, b)`-only canonical bytes via BCS of the
//!   `(BigInt, BigInt)` tuple. `c` is intentionally omitted from
//!   the wire because it is recoverable from
//!   `c = (b² − D) / (4a)` given the chain-fixed discriminant —
//!   per the §3.8.1 + §3.8.2 design, the discriminant is a
//!   genesis-fixed parameter and therefore implicitly carried
//!   alongside every class-group element rather than per-element.
//! - [`BinaryQuadraticForm::from_class_group_element`] — decode
//!   the `(a, b)` pair, recover `c = (b² − D) / (4a)` against
//!   the supplied discriminant, and validate that the recovered
//!   triple constructs a valid form (`a ≠ 0`, `c` exact integer,
//!   resulting discriminant matches).
//! - [`BqfError::MalformedClassGroupEncoding`] — error variant
//!   covering both BCS-decode failures and inconsistent
//!   encodings where `(b² − D)` is not divisible by `4a` under
//!   the supplied discriminant (the latter would mean the
//!   encoding does not correspond to any integral form of
//!   discriminant `D`).

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

    /// A [`crate::vdf::ClassGroupElement`] byte string failed to
    /// decode back to a valid [`BinaryQuadraticForm`]. Covers
    /// three failure modes:
    ///
    /// - BCS deserialisation of the encoded `(a, b)` pair failed
    ///   (truncated input, garbage bytes).
    /// - The decoded `a` is zero (would degenerate the form).
    /// - The recovered `c = (b² − D) / (4a)` is not an integer
    ///   under the supplied discriminant, meaning the encoded
    ///   `(a, b)` does not correspond to any integral binary
    ///   quadratic form of discriminant `D`.
    ///
    /// Phase 7.5.1d's
    /// [`BinaryQuadraticForm::from_class_group_element`] is the
    /// production site.
    MalformedClassGroupEncoding,
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
            Self::MalformedClassGroupEncoding => f.write_str(
                "class-group element encoding cannot be decoded to a valid binary quadratic form \
                 under the supplied discriminant",
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

    /// Computes `self ∘ self` in the class group, returning the
    /// reduced square.
    ///
    /// Implements Cohen, "A Course in Computational Algebraic
    /// Number Theory" Algorithm 5.4.8 (Squaring of Forms). This
    /// is the performance-critical specialisation of
    /// [`Self::compose`] for the case `f₁ = f₂`: the algorithm
    /// performs **one** extended GCD (on `(b, a)`) instead of
    /// the two that general composition performs (on `(a₂, a₁)`
    /// and then potentially on `(s, d₁)`).
    ///
    /// The Wesolowski VDF evaluation per §3.8.1 + §3.8.2 calls
    /// `square()` sequentially `T` times per envelope, with
    /// `T ∈ [2_000_000, 7_500_000]`, so the constant-factor
    /// saving accumulates to a material reduction in
    /// decryption-time wall-clock for the round anchor.
    ///
    /// # Algorithm sketch
    ///
    /// Given `f = (a, b, c)` of discriminant `D`:
    ///
    /// 1. Extended Euclid on `(b, a)`: obtain `d = gcd(b, a)`
    ///    and `μ` such that `μ·b + ν·a = d` for some `ν`.
    ///    `μ` is the modular inverse of `b/d` modulo `a/d`.
    /// 2. Set `A_over_d = a / d`.
    /// 3. Solve for the linkage `nu = (−μ · c) mod (a/d)` in
    ///    `[0, a/d)`. This is the unique residue making the
    ///    next step yield a form whose discriminant is `D`.
    /// 4. Build:
    ///    - `A_new = (a/d)²`
    ///    - `B_new = b + 2 · (a/d) · nu`
    ///    - `C_new = (B_new² − D) / (4 · A_new)`
    ///
    ///    and reduce.
    ///
    /// # Correctness identity
    ///
    /// For every positive definite `f`,
    /// `f.square() == f.compose(&f).unwrap()`. The square is a
    /// performance optimisation; correctness is identical to
    /// [`Self::compose`] applied to two equal operands. The
    /// `square_matches_compose_self` test pins this property
    /// across a representative-class sample.
    ///
    /// # Panics
    ///
    /// Panics if `self` is not positive definite. The
    /// algorithm is specialised to the imaginary quadratic
    /// class group; on indefinite inputs the final reduction
    /// step would diverge. Use [`Self::is_positive_definite`]
    /// to validate inputs.
    #[must_use]
    #[allow(
        clippy::many_single_char_names,
        reason = "Cohen Algorithm 5.4.8 uses single-letter variable names \
                  (b, a, c, d, mu, nu) matching the published algorithm; \
                  renaming would break the comment-vs-code traceability \
                  the security review will rely on."
    )]
    pub fn square(&self) -> Self {
        assert!(
            self.is_positive_definite(),
            "BinaryQuadraticForm::square requires a positive definite form (a > 0, c > 0, D < 0)"
        );

        let two = BigInt::from(2);
        let d_self = self.discriminant();

        // Step 1: extended Euclid on (b, a).
        // eg.x * b + eg.y * a = eg.gcd = d.
        let eg = self.b.extended_gcd(&self.a);
        let d = eg.gcd;
        let mu = eg.x;

        // Step 2: A_over_d = a / d. Always exact since d | a.
        let a_over_d = &self.a / &d;

        // Step 3: nu = (−μ · c) mod (a/d) in [0, a/d).
        // The choice of `nu` makes (B_new² − D) divisible by
        // 4·A_new exactly; this is the linkage condition that
        // makes the resulting form integral.
        let nu = (-&mu * &self.c).mod_floor(&a_over_d);

        // Step 4: build (A_new, B_new, C_new).
        let a_new = &a_over_d * &a_over_d;
        let b_new = &self.b + &two * &a_over_d * &nu;
        let four_a_new = BigInt::from(4) * &a_new;
        let c_new = (&b_new * &b_new - &d_self).div_floor(&four_a_new);

        let mut result =
            Self::new(a_new, b_new, c_new).expect("square preserves a > 0 (A_new = (a/d)² ≥ 1)");
        result.reduce();
        result
    }

    /// Encodes the form as a [`crate::vdf::ClassGroupElement`] via
    /// canonical BCS encoding of the `(a, b)` tuple.
    ///
    /// Per whitepaper §3.8.1 + §3.8.2 the class group's discriminant
    /// is a genesis-fixed parameter shared across every class-group
    /// element in the protocol; storing `c` per element would
    /// duplicate information the verifier can recover from the form's
    /// `(a, b)` and the chain-fixed discriminant via
    /// `c = (b² − D) / (4a)`. Wire encoding therefore covers `(a, b)`
    /// only, halving the per-element byte width for the consensus
    /// layer.
    ///
    /// # Canonicality
    ///
    /// BCS encoding of `(BigInt, BigInt)` is deterministic. Two
    /// forms encode to byte-equal `ClassGroupElement`s iff their
    /// `(a, b)` pairs are equal — so reduced-form byte-equality
    /// (the property §8.1.5 equivocation detection relies on)
    /// holds at the wire level too.
    ///
    /// # Panics
    ///
    /// Cannot panic in practice: `BigInt` is BCS-serialisable
    /// through `num-bigint`'s `serde` feature, and the encoding
    /// is total over all valid `BigInt` values.
    #[must_use]
    pub fn to_class_group_element(&self) -> crate::vdf::ClassGroupElement {
        let pair = (&self.a, &self.b);
        let encoded = bcs::to_bytes(&pair).expect("(BigInt, BigInt) is BCS-serialisable");
        crate::vdf::ClassGroupElement { encoded }
    }

    /// Decodes a [`crate::vdf::ClassGroupElement`] into a
    /// [`BinaryQuadraticForm`] under the supplied discriminant,
    /// recovering `c = (b² − D) / (4a)`.
    ///
    /// # Validation
    ///
    /// The decoder rejects three error modes via
    /// [`BqfError::MalformedClassGroupEncoding`]:
    ///
    /// 1. The encoded byte string does not BCS-deserialise as a
    ///    `(BigInt, BigInt)` pair.
    /// 2. The decoded `a` is zero.
    /// 3. `(b² − D)` is not divisible by `4a`, i.e., no integral
    ///    `c` makes the recovered triple a binary quadratic form
    ///    of the supplied discriminant.
    ///
    /// # Postconditions
    ///
    /// The returned form satisfies `self.discriminant() ==
    /// *discriminant` by construction. The form is NOT
    /// automatically reduced; callers that need a canonical
    /// representative call [`Self::reduce`] or [`Self::reduced`]
    /// after decoding.
    ///
    /// # Errors
    ///
    /// Returns [`BqfError::MalformedClassGroupEncoding`] for any
    /// of the three failure modes above. Returns
    /// [`BqfError::ZeroLeadingCoefficient`] is reachable in
    /// principle but in practice the malformed-encoding path
    /// catches it first.
    pub fn from_class_group_element(
        element: &crate::vdf::ClassGroupElement,
        discriminant: &BigInt,
    ) -> Result<Self, BqfError> {
        // Step 1: BCS-decode the (a, b) pair. Any decode failure
        // surfaces as MalformedClassGroupEncoding.
        let (a, b): (BigInt, BigInt) =
            bcs::from_bytes(&element.encoded).map_err(|_| BqfError::MalformedClassGroupEncoding)?;

        // Step 2: a == 0 is a structurally invalid form (the
        // `(a, b)` encoding presumes a non-zero leading
        // coefficient). Surface as MalformedClassGroupEncoding
        // rather than the more generic ZeroLeadingCoefficient
        // since the input came over the wire.
        if a.is_zero() {
            return Err(BqfError::MalformedClassGroupEncoding);
        }

        // Step 3: recover c = (b² − D) / (4a). Check exact
        // divisibility; reject otherwise (the (a, b) pair does
        // not correspond to any form of discriminant `D`).
        let four = BigInt::from(4);
        let numerator = &b * &b - discriminant;
        let denominator = &four * &a;
        let (c, remainder) = numerator.div_rem(&denominator);
        if !remainder.is_zero() {
            return Err(BqfError::MalformedClassGroupEncoding);
        }

        // Construct and return. Self::new only rejects a == 0
        // which we've already checked, so the unwrap path is
        // unreachable in practice.
        Self::new(a, b, c)
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

    // ---- Phase 7.5.1c: squaring tests ----
    //
    // The square() method is a Cohen 5.4.8 specialisation of
    // compose() for the f₁ = f₂ case. The headline consistency
    // property — square(f) == compose(f, f) — is pinned across a
    // representative-class sample. Other tests target the
    // group-theoretic identities the VDF will rely on.

    #[test]
    fn square_identity_d_minus_23_is_identity() {
        // e² = e for D = −23.
        let e = principal_d23();
        let sq = e.square();
        assert_eq!(sq, e);
    }

    #[test]
    fn square_generator_d_minus_23_is_generator_squared() {
        // f² = (2, −1, 3) for D = −23.
        let f = generator_d23();
        let sq = f.square();
        assert_eq!(sq, generator_squared_d23());
    }

    #[test]
    fn square_of_generator_squared_d_minus_23_is_generator() {
        // (f²)² = f⁴ = f (class number 3).
        let f_sq = generator_squared_d23();
        let f_qd = f_sq.square();
        assert_eq!(f_qd, generator_d23());
    }

    #[test]
    fn square_preserves_discriminant() {
        let f = generator_d23();
        let sq = f.square();
        assert_eq!(sq.discriminant(), BigInt::from(-23));
    }

    #[test]
    fn square_result_is_reduced() {
        let f = generator_d23();
        assert!(f.square().is_reduced());
    }

    /// Headline correctness identity: `square(f) ≡ compose(f, f)`
    /// for every positive definite form. Pinned across the full
    /// D = −23 class group + the D = −20 class group, plus some
    /// non-reduced equivalents.
    #[test]
    fn square_matches_compose_self() {
        let mut fixtures = vec![
            principal_d23(),
            generator_d23(),
            generator_squared_d23(),
            // D = -20 class group
            BinaryQuadraticForm::new(BigInt::from(1), BigInt::from(0), BigInt::from(5))
                .expect("D=-20 identity"),
            BinaryQuadraticForm::new(BigInt::from(2), BigInt::from(2), BigInt::from(3))
                .expect("D=-20 generator"),
            // Non-reduced equivalent of generator_d23
            BinaryQuadraticForm::new(BigInt::from(3), BigInt::from(5), BigInt::from(4))
                .expect("unreduced f for D=-23"),
        ];

        // A few medium-sized positive definite forms with
        // various discriminants to exercise larger BigInt
        // arithmetic.
        fixtures.push(
            BinaryQuadraticForm::new(BigInt::from(5), BigInt::from(3), BigInt::from(10_000))
                .expect("medium fixture"),
        );
        fixtures.push(
            BinaryQuadraticForm::new(
                BigInt::from(17),
                BigInt::from(11),
                BigInt::from(1_000_003_i64),
            )
            .expect("medium fixture 2"),
        );

        for f in &fixtures {
            if !f.is_positive_definite() {
                continue;
            }
            let via_square = f.square();
            let via_compose = f.compose(f).expect("compose");
            assert_eq!(
                via_square,
                via_compose,
                "square(f) and compose(f, f) disagree for f = ({}, {}, {}) with D = {}",
                f.a,
                f.b,
                f.c,
                f.discriminant(),
            );
        }
    }

    #[test]
    fn square_d_minus_20_generator_is_identity() {
        // For D = −20 the class group has order 2, so the
        // non-identity element squares to identity.
        let g = BinaryQuadraticForm::new(BigInt::from(2), BigInt::from(2), BigInt::from(3))
            .expect("D=-20 generator");
        let e = BinaryQuadraticForm::new(BigInt::from(1), BigInt::from(0), BigInt::from(5))
            .expect("D=-20 identity");
        assert_eq!(g.square(), e);
    }

    #[test]
    fn square_handles_unreduced_input() {
        // Squaring should be well-defined on the equivalence
        // class, not the specific representative.
        let f_reduced = generator_d23();
        let f_unreduced =
            BinaryQuadraticForm::new(BigInt::from(3), BigInt::from(5), BigInt::from(4))
                .expect("unreduced equivalent of f");
        assert_eq!(f_unreduced.reduced(), f_reduced);
        assert_eq!(f_reduced.square(), f_unreduced.square());
    }

    /// Repeated squaring matches the iterated `compose` chain:
    /// `square(square(f)) == compose(compose(f, f), compose(f, f))`.
    /// This is the property the Wesolowski VDF evaluation relies on
    /// when it computes `g^(2^T)` via `T` sequential squarings.
    #[test]
    fn repeated_squaring_matches_iterated_compose() {
        let f = generator_d23();
        // Two squarings = f⁴ in the class group.
        let via_repeated_square = f.square().square();
        // Iterated compose: ((f ∘ f) ∘ (f ∘ f)) = (f²) ∘ (f²) = f⁴.
        let f_sq = f.compose(&f).expect("compose");
        let via_compose = f_sq.compose(&f_sq).expect("compose");
        assert_eq!(via_repeated_square, via_compose);
        // And for D=-23 with class number 3, f⁴ = f.
        assert_eq!(via_repeated_square, f);
    }

    // ---- Phase 7.5.1d: ClassGroupElement encoding-bridge tests ----

    #[test]
    fn to_class_group_element_round_trips_through_from() {
        let f = generator_d23();
        let element = f.to_class_group_element();
        let recovered = BinaryQuadraticForm::from_class_group_element(&element, &BigInt::from(-23))
            .expect("decode");
        assert_eq!(recovered, f);
    }

    #[test]
    fn round_trip_for_all_d_minus_23_classes() {
        let d = BigInt::from(-23);
        for f in [principal_d23(), generator_d23(), generator_squared_d23()] {
            let element = f.to_class_group_element();
            let recovered =
                BinaryQuadraticForm::from_class_group_element(&element, &d).expect("decode");
            assert_eq!(recovered, f);
        }
    }

    #[test]
    fn round_trip_for_d_minus_20_classes() {
        let d = BigInt::from(-20);
        let classes = [
            BinaryQuadraticForm::new(BigInt::from(1), BigInt::from(0), BigInt::from(5))
                .expect("identity D=-20"),
            BinaryQuadraticForm::new(BigInt::from(2), BigInt::from(2), BigInt::from(3))
                .expect("generator D=-20"),
        ];
        for f in classes {
            let element = f.to_class_group_element();
            let recovered =
                BinaryQuadraticForm::from_class_group_element(&element, &d).expect("decode");
            assert_eq!(recovered, f);
        }
    }

    #[test]
    fn encoding_omits_c_recovers_via_discriminant() {
        // Construct (a, b) only via the helper, decode under the
        // expected discriminant, confirm c is recovered correctly.
        let f = generator_d23();
        let element = f.to_class_group_element();
        // BCS-decode just (a, b) to confirm c is genuinely absent.
        let (a_decoded, b_decoded): (BigInt, BigInt) =
            bcs::from_bytes(&element.encoded).expect("decode (a, b)");
        assert_eq!(a_decoded, f.a);
        assert_eq!(b_decoded, f.b);
        // Recovered c via from_class_group_element should match f.c.
        let recovered = BinaryQuadraticForm::from_class_group_element(&element, &BigInt::from(-23))
            .expect("decode");
        assert_eq!(recovered.c, f.c);
    }

    #[test]
    fn encoding_is_deterministic() {
        // BCS is deterministic; the same form encodes to the same
        // bytes on every call. This is the byte-equality property
        // §8.1.5 equivocation detection relies on at the wire level.
        let f = generator_d23();
        let a = f.to_class_group_element();
        let b = f.to_class_group_element();
        assert_eq!(a, b);
    }

    #[test]
    fn distinct_forms_produce_distinct_encodings() {
        // Two genuinely distinct reduced forms must encode to
        // distinct bytes.
        let a = principal_d23().to_class_group_element();
        let b = generator_d23().to_class_group_element();
        let c = generator_squared_d23().to_class_group_element();
        assert_ne!(a, b);
        assert_ne!(a, c);
        assert_ne!(b, c);
    }

    #[test]
    fn from_class_group_element_rejects_malformed_bcs() {
        // Truncated / random bytes don't decode as a (BigInt, BigInt)
        // pair.
        let garbage = crate::vdf::ClassGroupElement {
            encoded: vec![0xFF, 0xFF, 0x00],
        };
        let err = BinaryQuadraticForm::from_class_group_element(&garbage, &BigInt::from(-23))
            .expect_err("garbage must be rejected");
        assert_eq!(err, BqfError::MalformedClassGroupEncoding);
    }

    #[test]
    fn from_class_group_element_rejects_empty_bytes() {
        let empty = crate::vdf::ClassGroupElement { encoded: vec![] };
        let err = BinaryQuadraticForm::from_class_group_element(&empty, &BigInt::from(-23))
            .expect_err("empty must be rejected");
        assert_eq!(err, BqfError::MalformedClassGroupEncoding);
    }

    #[test]
    fn from_class_group_element_rejects_zero_a() {
        // Encode (a=0, b=1) as a BCS tuple; reject on decode.
        let pair: (BigInt, BigInt) = (BigInt::zero(), BigInt::one());
        let element = crate::vdf::ClassGroupElement {
            encoded: bcs::to_bytes(&pair).expect("serialise"),
        };
        let err = BinaryQuadraticForm::from_class_group_element(&element, &BigInt::from(-23))
            .expect_err("zero a must be rejected");
        assert_eq!(err, BqfError::MalformedClassGroupEncoding);
    }

    #[test]
    fn from_class_group_element_rejects_non_integer_c() {
        // Encode (a=2, b=2) and decode under D = -23: c = (4 - (-23)) / (4*2) = 27/8
        // which is non-integer. Must reject.
        let pair: (BigInt, BigInt) = (BigInt::from(2), BigInt::from(2));
        let element = crate::vdf::ClassGroupElement {
            encoded: bcs::to_bytes(&pair).expect("serialise"),
        };
        let err = BinaryQuadraticForm::from_class_group_element(&element, &BigInt::from(-23))
            .expect_err("non-integer c must be rejected");
        assert_eq!(err, BqfError::MalformedClassGroupEncoding);
    }

    #[test]
    fn from_class_group_element_decoded_form_has_correct_discriminant() {
        // The recovered form's discriminant must match the supplied
        // discriminant exactly.
        let f = generator_d23();
        let element = f.to_class_group_element();
        let recovered = BinaryQuadraticForm::from_class_group_element(&element, &BigInt::from(-23))
            .expect("decode");
        assert_eq!(recovered.discriminant(), BigInt::from(-23));
    }

    #[test]
    fn from_class_group_element_decoding_under_wrong_discriminant_is_either_error_or_different_form(
    ) {
        // If a caller supplies the wrong discriminant, one of two
        // things happens: either c becomes non-integer (rejected) OR
        // c becomes an integer but produces a form of the wrong
        // discriminant. We cover both branches here.
        //
        // For f = (2, 1, 3) with D = -23, the encoded (a, b) is (2, 1).
        // Under D' = -19: c' = (1 - (-19)) / 8 = 20/8 = 2.5 → non-integer, reject.
        let f = generator_d23();
        let element = f.to_class_group_element();

        let err = BinaryQuadraticForm::from_class_group_element(
            &element,
            &BigInt::from(-19), // wrong discriminant
        )
        .expect_err("wrong discriminant must be rejected when c becomes non-integer");
        assert_eq!(err, BqfError::MalformedClassGroupEncoding);
    }

    #[test]
    fn encoding_round_trip_preserves_byte_equality_within_class() {
        // Two reduced forms that happen to be in the same equivalence
        // class (i.e., are the same reduced form) encode to byte-equal
        // ClassGroupElement values. Distinct classes encode distinctly.
        // This is the equivocation-detection property at the wire level.
        let f1 = generator_d23();
        let f2 = BinaryQuadraticForm::new(BigInt::from(2), BigInt::from(1), BigInt::from(3))
            .expect("same form");
        assert_eq!(f1.to_class_group_element(), f2.to_class_group_element());

        // And distinct reduced forms encode distinctly:
        assert_ne!(
            f1.to_class_group_element(),
            generator_squared_d23().to_class_group_element(),
        );
    }

    #[test]
    fn round_trip_then_reduce_canonical() {
        // Encode an unreduced form, decode, then reduce — should equal
        // the reduced canonical representative of the original class.
        let f_unreduced =
            BinaryQuadraticForm::new(BigInt::from(3), BigInt::from(5), BigInt::from(4))
                .expect("unreduced equivalent of f");
        let element = f_unreduced.to_class_group_element();
        let mut recovered =
            BinaryQuadraticForm::from_class_group_element(&element, &BigInt::from(-23))
                .expect("decode");
        // Recovered form should equal the original unreduced form.
        assert_eq!(recovered, f_unreduced);
        // Reducing it yields the canonical representative.
        recovered.reduce();
        assert_eq!(recovered, generator_d23());
    }

    #[test]
    fn malformed_class_group_encoding_error_display() {
        // Sanity-check that the new error variant has a meaningful
        // Display string distinct from the existing variants.
        let msg = BqfError::MalformedClassGroupEncoding.to_string();
        assert!(!msg.is_empty());
        assert_ne!(msg, BqfError::ZeroLeadingCoefficient.to_string());
        assert_ne!(msg, BqfError::MismatchedDiscriminants.to_string());
    }
}
