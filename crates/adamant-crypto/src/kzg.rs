//! KZG vector and polynomial commitments on BLS12-381, per
//! whitepaper §3.9.2.
//!
//! Phase 5/6.9 (KZG sub-arc) — Adamant-native math layered on the
//! `adamant-crypto-blst-extra` BLS12-381 primitive surface per the
//! §3.9.2 amendment (CONTRIBUTING.md spec-first verification
//! instance 30): Adamant owns the KZG implementation; no
//! `arkworks` or other external KZG library is consumed.
//!
//! # Spec basis
//!
//! Whitepaper §3.9.2 (verbatim, post-amendment): "The reference
//! implementation provides KZG operations (commit, open, verify)
//! over BLS12-381 primitives consistent with the rest of
//! `adamant-crypto`. The implementation uses the project's
//! existing BLS12-381 primitive layer (`blst`-based) and standard
//! polynomial arithmetic; no external KZG library is consumed.
//! Adamant-native posture per §6.2.1.8 resistant-proof commitment
//! extends to the KZG implementation: the production-binary
//! dependency graph remains Adamant-controlled."
//!
//! Whitepaper §3.9.2: "KZG commitments are used inside the
//! consensus layer for state commitments and for certain
//! operations within the encrypted mempool. KZG commitments
//! require a trusted setup: a set of values `[g, g^τ, g^{τ^2}, …,
//! g^{τ^n}]` for a secret `τ` that must be irrecoverably
//! destroyed."
//!
//! Whitepaper §3.9.2 + §11: "The protocol uses the Ethereum KZG
//! Powers of Tau ceremony output ... a trusted setup of size
//! 2^16."
//!
//! # API surface
//!
//! - [`KzgSetup`] — trusted-setup parameters: `g^{τ^i}` for
//!   `i = 0..=max_degree` in G₁, plus `g_2` and `g_2^τ` in G₂.
//! - [`Polynomial`] — coefficient-form polynomial over `Z_r`.
//! - [`Commitment`] — opaque G₁ commitment to a polynomial.
//! - [`Proof`] — opaque G₁ opening-proof at an evaluation point.
//! - [`commit`] — produce a [`Commitment`] for a [`Polynomial`].
//! - [`open`] — produce `(evaluation, proof)` at a point.
//! - [`verify`] — pairing-based verification of an opening.
//!
//! # Verification equation
//!
//! For a commitment `C` to polynomial `p(x)`, an opening at
//! point `z` yields `y = p(z)` and proof `π = commit(q)` where
//! `q(x) = (p(x) − y) / (x − z)`. Verification checks the
//! pairing equation:
//!
//! ```text
//! e(C − y·g, g_2) == e(π, g_2^τ − z·g_2)
//! ```
//!
//! Equivalent forms exist; the form above matches the Kate-
//! Zaverucha-Goldberg 2010 construction directly.
//!
//! # What this layer does NOT (yet) cover
//!
//! - **Trusted-setup ingestion from `EthPoT` format.** The setup
//!   construction in this module accepts pre-decoded G₁ powers
//!   and a G₂ `τ` point. Wiring the `EthPoT` JSON / binary format
//!   ingestion to those types is a pre-mainnet hardening item
//!   per whitepaper §11 (genesis trusted-setup procurement).
//! - **Multi-scalar multiplication (MSM) optimisations.** The
//!   commit path is the naive `Σ p_i · g^{τ^i}` linear loop;
//!   Pippenger / bucket-method optimisations are deferred to
//!   pre-mainnet performance hardening.
//! - **FFT-based polynomial arithmetic.** Coefficient-form is
//!   sufficient for committed-vectors-of-validator-set-size; FFT
//!   becomes worth the complexity at much larger degrees than
//!   Adamant's consensus layer needs.
//! - **Batch openings.** Single-point openings cover §3.9.2's
//!   stated use cases; multi-point batch openings are a future
//!   sub-arc if/when state-commitment workloads warrant.

use adamant_crypto_blst_extra::{pairing, G1Point, G2Point, Scalar};

/// A polynomial in coefficient form over the BLS12-381 scalar
/// field `Z_r`.
///
/// `coefficients[i]` is the coefficient of `x^i`. The empty vector
/// represents the zero polynomial. Trailing-zero coefficients are
/// permitted and do not affect correctness (the corresponding
/// `g^{τ^i}` powers contribute zero to the commitment), but
/// callers may choose to strip them for canonicalisation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Polynomial {
    /// Coefficients, low-degree to high-degree:
    /// `p(x) = coefficients[0] + coefficients[1]·x + … + coefficients[n]·x^n`.
    pub coefficients: Vec<Scalar>,
}

impl Polynomial {
    /// Construct from a coefficient vector. Empty vector ⇒ zero
    /// polynomial.
    #[must_use]
    pub fn new(coefficients: Vec<Scalar>) -> Self {
        Self { coefficients }
    }

    /// The zero polynomial.
    #[must_use]
    pub fn zero() -> Self {
        Self {
            coefficients: Vec::new(),
        }
    }

    /// Degree as `coefficients.len() - 1`. Returns `0` for the
    /// zero polynomial (consistent with treating empty as the
    /// degree-0 zero element).
    #[must_use]
    pub fn degree(&self) -> usize {
        self.coefficients.len().saturating_sub(1)
    }

    /// Evaluate via Horner's method:
    /// `p(z) = coeff[0] + z·(coeff[1] + z·(coeff[2] + …))`.
    #[must_use]
    pub fn evaluate(&self, z: &Scalar) -> Scalar {
        let mut acc = Scalar::zero();
        for coeff in self.coefficients.iter().rev() {
            acc = acc.mul(z).add(coeff);
        }
        acc
    }
}

/// KZG trusted-setup parameters per whitepaper §3.9.2.
///
/// `g1_powers[i]` is `g^{τ^i}` in G₁ for `i = 0..=max_degree`
/// (so `g1_powers.len() == max_degree + 1`).
/// `g2` is the G₂ generator (i.e., `g_2^1`).
/// `g2_tau` is `g_2^τ` in G₂.
///
/// `τ` is the toxic-waste secret destroyed by the ceremony per
/// §3.9.2; the live setup never holds it. The fields above are
/// the only setup material the verifier and prover need.
#[derive(Clone, Debug)]
pub struct KzgSetup {
    /// `[g^{τ^0}, g^{τ^1}, …, g^{τ^max_degree}]` — G₁ powers of τ.
    pub g1_powers: Vec<G1Point>,
    /// `g_2` — the G₂ generator (i.e., `g_2^τ^0`).
    pub g2: G2Point,
    /// `g_2^τ` — required by the verification pairing equation.
    pub g2_tau: G2Point,
}

impl KzgSetup {
    /// Construct from pre-decoded parameters. Used by the
    /// genesis loader after parsing the `EthPoT` trusted-setup
    /// output (whitepaper §11 trusted-setup procurement).
    ///
    /// # Panics
    ///
    /// Panics if `g1_powers` is empty (degree-0 polynomials still
    /// require `g^{τ^0} = g`).
    #[must_use]
    pub fn from_parameters(g1_powers: Vec<G1Point>, g2: G2Point, g2_tau: G2Point) -> Self {
        assert!(
            !g1_powers.is_empty(),
            "KZG trusted setup must contain at least g^{{τ^0}} = g for degree-0 commitments"
        );
        Self {
            g1_powers,
            g2,
            g2_tau,
        }
    }

    /// Maximum polynomial degree this setup supports.
    #[must_use]
    pub fn max_degree(&self) -> usize {
        self.g1_powers.len() - 1
    }

    /// Generate a deterministic test-only setup for a chosen
    /// secret `τ`.
    ///
    /// **Test-only.** Production uses [`Self::from_parameters`]
    /// with the genesis-fixed `EthPoT` output per §11. This helper
    /// exists so unit tests can construct working setups without
    /// the `EthPoT` ceremony's 8 GB binary blob; it is not exposed
    /// outside `cfg(test)` callers.
    ///
    /// # Panics
    ///
    /// Panics if `tau` is zero (degenerate setup — every `g^{τ^i}`
    /// for `i ≥ 1` would collapse to the identity).
    #[cfg(test)]
    pub(crate) fn generate_for_testing(tau: &Scalar, max_degree: usize) -> Self {
        assert!(*tau != Scalar::zero(), "τ must be non-zero");
        let g1 = G1Point::generator();
        let g2 = G2Point::generator();
        let mut g1_powers = Vec::with_capacity(max_degree + 1);
        // τ^0 = 1 ⇒ g^{τ^0} = g.
        g1_powers.push(g1);
        // τ^i = τ^{i-1} · τ for i >= 1.
        let mut tau_pow = Scalar::one();
        for _ in 1..=max_degree {
            tau_pow = tau_pow.mul(tau);
            g1_powers.push(g1.mul_scalar(&tau_pow));
        }
        let g2_tau = g2.mul_scalar(tau);
        Self::from_parameters(g1_powers, g2, g2_tau)
    }
}

/// KZG commitment — a single G₁ point.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Commitment(pub G1Point);

/// KZG opening proof — a single G₁ point.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Proof(pub G1Point);

/// Errors returned from KZG operations that can fail at the
/// shape boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KzgError {
    /// The polynomial's degree exceeds the trusted-setup's
    /// maximum supported degree (`poly.coefficients.len() >
    /// setup.g1_powers.len()`).
    DegreeExceedsSetup,
}

impl core::fmt::Display for KzgError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::DegreeExceedsSetup => {
                f.write_str("polynomial degree exceeds trusted-setup maximum supported degree")
            }
        }
    }
}

impl std::error::Error for KzgError {}

/// Commit to a polynomial under the trusted setup.
///
/// `C = Σ p_i · g^{τ^i}` — naive linear MSM. Pre-mainnet
/// performance work may replace this with a Pippenger or bucket-
/// method MSM; for now the linear path is correctness-establishing
/// and matches the validator-set-size workload described in
/// §3.9.2.
///
/// # Errors
///
/// Returns [`KzgError::DegreeExceedsSetup`] if the polynomial has
/// more coefficients than the setup's `g1_powers`.
pub fn commit(setup: &KzgSetup, polynomial: &Polynomial) -> Result<Commitment, KzgError> {
    if polynomial.coefficients.len() > setup.g1_powers.len() {
        return Err(KzgError::DegreeExceedsSetup);
    }
    if polynomial.coefficients.is_empty() {
        // Zero polynomial: commitment is the identity in G₁,
        // expressed as 0·g via the first setup power. Equivalent
        // to scalar-multiplying any G₁ point by zero.
        let zero = Scalar::zero();
        return Ok(Commitment(setup.g1_powers[0].mul_scalar(&zero)));
    }
    // Initialise accumulator with c[0] · g^{τ^0}.
    let mut acc = setup.g1_powers[0].mul_scalar(&polynomial.coefficients[0]);
    // Add c[i] · g^{τ^i} for i = 1..n.
    for (coeff, power) in polynomial
        .coefficients
        .iter()
        .zip(setup.g1_powers.iter())
        .skip(1)
    {
        let term = power.mul_scalar(coeff);
        acc = acc.add(&term);
    }
    Ok(Commitment(acc))
}

/// Open a polynomial at point `z`.
///
/// Returns `(y, π)` where:
/// - `y = p(z)` (Horner-evaluated).
/// - `π = commit(q)` where `q(x) = (p(x) − y) / (x − z)`
///   computed by synthetic division (exact since `(p(x) − y)` has
///   `z` as a root by construction).
///
/// # Errors
///
/// Returns [`KzgError::DegreeExceedsSetup`] if committing the
/// quotient polynomial would exceed the setup's maximum degree.
/// In practice this cannot happen if `commit(setup, polynomial)`
/// already succeeded — the quotient has degree exactly one less
/// than `polynomial`.
pub fn open(
    setup: &KzgSetup,
    polynomial: &Polynomial,
    z: &Scalar,
) -> Result<(Scalar, Proof), KzgError> {
    let y = polynomial.evaluate(z);
    let quotient = quotient_polynomial(polynomial, z, &y);
    let proof_commitment = commit(setup, &quotient)?;
    Ok((y, Proof(proof_commitment.0)))
}

/// Compute `q(x) = (p(x) − y) / (x − z)` via synthetic division.
///
/// Precondition: `p(z) == y`. The construction guarantees `(x −
/// z)` divides `p(x) − y` exactly; synthetic division produces
/// the integer quotient with no remainder.
///
/// Algorithm (synthetic division at root z):
///
/// Given `p(x) = c_0 + c_1·x + … + c_n·x^n`, the quotient
/// `q(x) = b_0 + b_1·x + … + b_{n-1}·x^{n-1}` satisfies
/// `p(x) − y = (x − z)·q(x)`, which expands to
/// `b_{n-1} = c_n`, `b_{i-1} = c_i + z·b_i` for `i = n-1..1`.
/// The constant `c_0 − y + z·b_0` equals zero by construction.
fn quotient_polynomial(polynomial: &Polynomial, z: &Scalar, evaluation: &Scalar) -> Polynomial {
    let coeffs = &polynomial.coefficients;
    if coeffs.is_empty() {
        // Zero polynomial: quotient is also zero.
        return Polynomial::zero();
    }
    if coeffs.len() == 1 {
        // Constant polynomial p(x) = c_0; if y = c_0, the
        // numerator is zero ⇒ quotient is zero.
        debug_assert!(
            coeffs[0] == *evaluation,
            "p(z) must equal evaluation for opening"
        );
        return Polynomial::zero();
    }
    let _ = evaluation; // unused outside the debug assertion path
    let n = coeffs.len();
    // The quotient has degree n - 2 (i.e., n - 1 coefficients).
    let mut quotient = vec![Scalar::zero(); n - 1];
    // b_{n-2} = c_{n-1} (since p has n coefficients indexed 0..n-1).
    quotient[n - 2] = coeffs[n - 1];
    // b_{i-1} = c_i + z · b_i for i = n-2..1.
    for i in (1..=n - 2).rev() {
        let term = z.mul(&quotient[i]);
        quotient[i - 1] = coeffs[i].add(&term);
    }
    Polynomial::new(quotient)
}

/// Verify a KZG opening: does `proof` attest that
/// `commitment` opens to `evaluation` at `z`?
///
/// Pairing equation:
/// `e(C − y·g, g_2) == e(π, g_2^τ − z·g_2)`
///
/// Both sides are computed via the BLS12-381 optimal-Ate pairing
/// per `adamant_crypto_blst_extra::pairing`. Equality is
/// byte-equality on the `G_T` outputs (576-byte uncompressed
/// `blst_fp12`).
#[must_use]
pub fn verify(
    setup: &KzgSetup,
    commitment: &Commitment,
    z: &Scalar,
    evaluation: &Scalar,
    proof: &Proof,
) -> bool {
    // LHS: e(C − y·g, g_2)
    //   where g = setup.g1_powers[0] (= g^{τ^0} = g).
    let g = &setup.g1_powers[0];
    let y_g = g.mul_scalar(evaluation);
    let c_minus_yg = commitment.0.sub(&y_g);
    let lhs = pairing(&c_minus_yg, &setup.g2);

    // RHS: e(π, g_2^τ − z·g_2)
    let z_g2 = setup.g2.mul_scalar(z);
    let g2tau_minus_zg2 = setup.g2_tau.sub(&z_g2);
    let rhs = pairing(&proof.0, &g2tau_minus_zg2);

    lhs.to_bytes() == rhs.to_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scalar(n: u32) -> Scalar {
        Scalar::from_u32(n)
    }

    fn poly(coeffs: &[u32]) -> Polynomial {
        Polynomial::new(coeffs.iter().copied().map(Scalar::from_u32).collect())
    }

    fn fixed_setup(max_degree: usize) -> KzgSetup {
        // Use a fixed-but-non-zero τ so the test setup is
        // deterministic. τ = 7 is convenient and far from edge
        // cases (zero, one).
        KzgSetup::generate_for_testing(&scalar(7), max_degree)
    }

    // ---------- Polynomial ----------

    #[test]
    fn evaluate_zero_polynomial_is_zero() {
        let p = Polynomial::zero();
        assert_eq!(p.evaluate(&scalar(42)), Scalar::zero());
    }

    #[test]
    fn evaluate_constant_polynomial_returns_constant() {
        let p = poly(&[5]);
        assert_eq!(p.evaluate(&scalar(42)), scalar(5));
    }

    #[test]
    fn evaluate_linear_polynomial_at_root() {
        // p(x) = -3 + x ⇒ p(3) = 0.
        // -3 ≡ r - 3 in Z_r; use Scalar::sub instead.
        let coeffs = vec![Scalar::zero().sub(&scalar(3)), scalar(1)];
        let p = Polynomial::new(coeffs);
        assert_eq!(p.evaluate(&scalar(3)), Scalar::zero());
    }

    #[test]
    fn evaluate_quadratic_polynomial_horner() {
        // p(x) = 1 + 2x + 3x²; p(2) = 1 + 4 + 12 = 17.
        let p = poly(&[1, 2, 3]);
        assert_eq!(p.evaluate(&scalar(2)), scalar(17));
    }

    // ---------- KzgSetup ----------

    #[test]
    fn setup_max_degree_matches_powers_len() {
        let setup = fixed_setup(8);
        assert_eq!(setup.max_degree(), 8);
        assert_eq!(setup.g1_powers.len(), 9);
    }

    #[test]
    #[should_panic(expected = "at least g")]
    fn setup_panics_on_empty_powers() {
        let _ = KzgSetup::from_parameters(vec![], G2Point::generator(), G2Point::generator());
    }

    // ---------- commit / open / verify round trips ----------

    #[test]
    fn commit_open_verify_round_trip_constant_polynomial() {
        let setup = fixed_setup(4);
        let p = poly(&[42]);
        let z = scalar(13);
        let commitment = commit(&setup, &p).expect("commit ok");
        let (y, proof) = open(&setup, &p, &z).expect("open ok");
        assert_eq!(y, scalar(42));
        assert!(verify(&setup, &commitment, &z, &y, &proof));
    }

    #[test]
    fn commit_open_verify_round_trip_linear() {
        let setup = fixed_setup(4);
        // p(x) = 5 + 3x ⇒ p(2) = 11.
        let p = poly(&[5, 3]);
        let z = scalar(2);
        let commitment = commit(&setup, &p).expect("commit ok");
        let (y, proof) = open(&setup, &p, &z).expect("open ok");
        assert_eq!(y, scalar(11));
        assert!(verify(&setup, &commitment, &z, &y, &proof));
    }

    #[test]
    fn commit_open_verify_round_trip_quadratic() {
        let setup = fixed_setup(4);
        // p(x) = 1 + 2x + 3x²; p(5) = 1 + 10 + 75 = 86.
        let p = poly(&[1, 2, 3]);
        let z = scalar(5);
        let commitment = commit(&setup, &p).expect("commit ok");
        let (y, proof) = open(&setup, &p, &z).expect("open ok");
        assert_eq!(y, scalar(86));
        assert!(verify(&setup, &commitment, &z, &y, &proof));
    }

    #[test]
    fn commit_open_verify_round_trip_random_polynomial_at_random_point() {
        let setup = fixed_setup(8);
        // Mid-range coefficients; not all powers exercised.
        let p = poly(&[17, 31, 0, 41, 13, 7, 23]); // degree 6
        let z = scalar(42);
        let commitment = commit(&setup, &p).expect("commit ok");
        let (y, proof) = open(&setup, &p, &z).expect("open ok");
        assert_eq!(y, p.evaluate(&z));
        assert!(verify(&setup, &commitment, &z, &y, &proof));
    }

    #[test]
    fn commit_open_verify_round_trip_evaluation_at_zero() {
        let setup = fixed_setup(4);
        // p(x) = 100 + 5x + x² ⇒ p(0) = 100.
        let p = poly(&[100, 5, 1]);
        let z = Scalar::zero();
        let commitment = commit(&setup, &p).expect("commit ok");
        let (y, proof) = open(&setup, &p, &z).expect("open ok");
        assert_eq!(y, scalar(100));
        assert!(verify(&setup, &commitment, &z, &y, &proof));
    }

    // ---------- soundness: tampering ----------

    #[test]
    fn verify_rejects_tampered_evaluation() {
        let setup = fixed_setup(4);
        let p = poly(&[1, 2, 3]);
        let z = scalar(5);
        let commitment = commit(&setup, &p).expect("commit ok");
        let (y, proof) = open(&setup, &p, &z).expect("open ok");
        let tampered_y = y.add(&scalar(1));
        assert!(!verify(&setup, &commitment, &z, &tampered_y, &proof));
    }

    #[test]
    fn verify_rejects_tampered_proof() {
        let setup = fixed_setup(4);
        let p = poly(&[1, 2, 3]);
        let z = scalar(5);
        let commitment = commit(&setup, &p).expect("commit ok");
        let (y, _proof) = open(&setup, &p, &z).expect("open ok");
        // Use the commitment itself as a fake proof — wrong shape,
        // pairing equation must fail.
        let tampered_proof = Proof(commitment.0);
        assert!(!verify(&setup, &commitment, &z, &y, &tampered_proof));
    }

    #[test]
    fn verify_rejects_wrong_evaluation_point() {
        let setup = fixed_setup(4);
        let p = poly(&[1, 2, 3]);
        let z = scalar(5);
        let commitment = commit(&setup, &p).expect("commit ok");
        let (y, proof) = open(&setup, &p, &z).expect("open ok");
        // Verify at a different point with the original (z, y, π)
        // — should fail.
        let wrong_z = scalar(6);
        assert!(!verify(&setup, &commitment, &wrong_z, &y, &proof));
    }

    #[test]
    fn verify_rejects_wrong_commitment() {
        let setup = fixed_setup(4);
        let p1 = poly(&[1, 2, 3]);
        let p2 = poly(&[7, 8, 9]); // distinct polynomial
        let z = scalar(5);
        let _c1 = commit(&setup, &p1).expect("ok");
        let c2 = commit(&setup, &p2).expect("ok");
        let (y, proof) = open(&setup, &p1, &z).expect("ok");
        // Try to attest p1's opening with p2's commitment.
        assert!(!verify(&setup, &c2, &z, &y, &proof));
    }

    // ---------- error paths ----------

    #[test]
    fn commit_rejects_polynomial_exceeding_setup_degree() {
        let setup = fixed_setup(2); // supports degree up to 2 (3 coeffs)
        let too_big = poly(&[1, 2, 3, 4]); // 4 coeffs ⇒ degree 3
        let result = commit(&setup, &too_big);
        assert_eq!(result.err(), Some(KzgError::DegreeExceedsSetup));
    }

    #[test]
    fn commit_zero_polynomial_returns_identity() {
        let setup = fixed_setup(4);
        let zero_poly = Polynomial::zero();
        let result = commit(&setup, &zero_poly).expect("ok");
        // Zero polynomial commits to the identity element of G₁.
        // We construct the identity independently as 0·g and
        // compare via the verify equation degenerating: the zero
        // polynomial opens to zero at any point with a zero proof.
        let z = scalar(11);
        let (y, proof) = open(&setup, &zero_poly, &z).expect("ok");
        assert_eq!(y, Scalar::zero());
        assert!(verify(&setup, &result, &z, &y, &proof));
    }

    // ---------- determinism ----------

    #[test]
    fn commit_is_deterministic() {
        let setup = fixed_setup(4);
        let p = poly(&[7, 11, 13, 17]);
        let c1 = commit(&setup, &p).expect("ok");
        let c2 = commit(&setup, &p).expect("ok");
        assert_eq!(c1, c2);
    }

    #[test]
    fn open_is_deterministic() {
        let setup = fixed_setup(4);
        let p = poly(&[7, 11, 13, 17]);
        let z = scalar(31);
        let (y1, proof1) = open(&setup, &p, &z).expect("ok");
        let (y2, proof2) = open(&setup, &p, &z).expect("ok");
        assert_eq!(y1, y2);
        assert_eq!(proof1, proof2);
    }
}
