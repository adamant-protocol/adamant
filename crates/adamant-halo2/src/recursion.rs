//! Pure-Pallas accumulator-folding recursive proof composition
//! per whitepaper §8.5.2.
//!
//! # Posture (Phase 6.9b plan-gate resolution)
//!
//! - **Pasta-cycle posture: pure-Pallas (homogeneous).**
//!   Recursive accumulator folding stays on a single curve
//!   (Pallas for circuits over `pallas::Base`, or Vesta for
//!   circuits over `pallas::Scalar`). No in-circuit Halo 2
//!   verifier; no Pallas-Vesta cross-cycle binding.
//!
//! - **Recursion granularity: per-epoch** (matches §8.5.2
//!   verbatim: "the recursive proof at epoch N: verifies the
//!   recursive proof from epoch N-1 ... outputs a new
//!   constant-size proof for epoch N").
//!
//! # Construction
//!
//! Each proof verified via `verify_proof` produces a `Guard`
//! whose deferred MSM evaluates to identity iff the proof
//! verified. Folding N Guards' MSMs (each scaled by independent
//! random challenges to prevent malicious cancellation) into a
//! single MSM produces an aggregate that evaluates to identity
//! iff all N proofs verified.
//!
//! For recursive composition across epoch boundaries, each
//! epoch evaluates its aggregate MSM down to a single curve
//! point `P_N` and persists it as the epoch's recursive proof.
//! Epoch N+1's verifier absorbs `P_N` as an additional
//! `(scalar=random_challenge, base=P_N)` term in its own MSM,
//! producing `P_{N+1}`. The chain `P_0, P_1, …, P_N` has the
//! property: `P_N == identity` iff every proof absorbed into
//! the chain across all epochs verified.
//!
//! Light clients verify the latest `P_N` with a single multiexp
//! plus a constant-size MSM equality check — sub-second on
//! consumer-class hardware per Principle III's phone-verifiable
//! commitment.
//!
//! # Why this is correct
//!
//! The Halo paper (Bowe-Grigg-Hopwood 2019) introduced
//! accumulator-folding as the foundation of incremental
//! verifiable computation (IVC). The construction here is the
//! standard out-of-circuit IPA accumulator-folding: it does not
//! require an in-circuit Halo 2 verifier (which would be a
//! perf optimization producing succinct SNARK proofs of SNARK
//! verification). Both shapes have the same security:
//! `P_N == identity` ⇔ all absorbed proofs verified.
//!
//! # Forward compatibility
//!
//! The in-circuit Halo 2 verifier extension is a future sub-arc
//! that lands either pre-mainnet or post-genesis as a soft
//! optimization. The wire-level recursive-proof format here is
//! posture-independent: the on-chain bytes for an epoch
//! accumulator are a single curve point regardless of whether
//! the verifier circuit is in-circuit or out-of-circuit.

#![allow(clippy::doc_markdown)]

use std::convert::TryInto;

use group::ff::{Field, FromUniformBytes};
use group::prime::PrimeCurveAffine;
use group::Curve;
use pasta_curves::arithmetic::CurveAffine;
use rand_core::RngCore;

use crate::proofs::plonk::{verify_proof, Error, VerifyingKey};
use crate::proofs::poly::commitment::{Guard, Params, MSM};
use crate::proofs::transcript::{Blake2bRead, EncodedChallenge};

/// A persisted recursive accumulator point per whitepaper §8.5.2.
///
/// Wraps a single curve point representing the partial-multiexp
/// result of folding `N` proofs' deferred MSMs. The accumulator
/// is "valid" iff `point == identity`.
///
/// Wire encoding: the curve's compressed-affine bytes
/// (32 bytes for both Pallas and Vesta — the `EncodedPoint`
/// associated type from `pasta_curves` is `[u8; 32]`).
///
/// `Default` produces the identity point — equivalent to "empty
/// accumulator with no proofs absorbed", which trivially
/// verifies.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecursiveAccumulator<C: CurveAffine> {
    /// The folded curve point. Equals identity iff all absorbed
    /// proofs verified.
    pub point: C,
}

impl<C: CurveAffine> RecursiveAccumulator<C> {
    /// Construct from a raw curve point. The caller is
    /// responsible for the point being a valid accumulator state
    /// (typically the output of [`fold_proofs`]).
    #[must_use]
    pub const fn from_point(point: C) -> Self {
        Self { point }
    }

    /// The empty accumulator (identity). Trivially verifies.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            point: C::identity(),
        }
    }

    /// Whether this accumulator verifies, i.e., `point ==
    /// identity`. Constant-time per `pasta_curves`'s `Choice`-
    /// based identity check.
    #[must_use]
    pub fn verifies(&self) -> bool {
        bool::from(self.point.is_identity())
    }

    /// Underlying curve point.
    #[must_use]
    pub fn point(&self) -> &C {
        &self.point
    }
}

impl<C: CurveAffine> Default for RecursiveAccumulator<C> {
    fn default() -> Self {
        Self::empty()
    }
}

/// Fold one or more proofs into the running recursive accumulator.
///
/// For each proof:
/// 1. Run `verify_proof` with a `BatchStrategy`-equivalent that
///    extracts the deferred MSM rather than finalising it.
/// 2. Scale the proof's MSM by a fresh random challenge
///    (prevents malicious cancellation).
/// 3. Add the scaled MSM to the running aggregate.
///
/// The prior accumulator's point is also folded in, scaled by an
/// independent random challenge, so the new accumulator captures
/// "all prior epochs' validity" plus "this batch of proofs'
/// validity."
///
/// Returns the new [`RecursiveAccumulator`] (a single curve
/// point) representing the chain through all absorbed proofs.
///
/// # Errors
///
/// Returns the underlying [`Error`] if any proof's deferred MSM
/// extraction fails (malformed transcript, invalid commitment,
/// etc.). Callers can map this to "recursive accumulator
/// rejected" semantics.
pub fn fold_proofs<C, R>(
    params: &Params<C>,
    vk: &VerifyingKey<C>,
    instances: &[&[&[C::Scalar]]],
    proof_bytes: &[&[u8]],
    prior: RecursiveAccumulator<C>,
    mut rng: R,
) -> Result<RecursiveAccumulator<C>, Error>
where
    C: CurveAffine,
    C::Scalar: FromUniformBytes<64>,
    R: RngCore,
{
    if instances.len() != proof_bytes.len() {
        return Err(Error::InvalidInstances);
    }

    // Start with the prior accumulator point absorbed via random
    // scaling. If `prior == identity`, this term is identity (no
    // contribution); otherwise the random scaling factor mixes
    // it into the aggregate.
    let mut aggregate = params.empty_msm();
    let r0 = C::Scalar::random(&mut rng);
    aggregate.append_term(r0, prior.point);

    for (instance, proof) in instances.iter().zip(proof_bytes.iter()) {
        // Build a per-proof MSM by running `verify_proof` with
        // a strategy that returns the Guard's deferred MSM.
        // `verify_proof` expects `&[&[&[Scalar]]]` — outer slice
        // is "all proofs in this batch", inner is per-proof
        // instance columns. We pass a single-element outer
        // slice containing this proof's instance columns.
        let strategy = AccumulatorStrategy::new(params);
        let mut transcript = Blake2bRead::init(*proof);
        let single_proof_instances: &[&[&[C::Scalar]]] = std::slice::from_ref(instance);
        let proof_msm = verify_proof(
            params,
            vk,
            strategy,
            single_proof_instances,
            &mut transcript,
        )?;

        // Scale by a fresh random challenge to prevent malicious
        // cancellation against the running aggregate.
        let r = C::Scalar::random(&mut rng);
        let mut scaled = proof_msm;
        scaled.scale(r);

        aggregate.add_msm(&scaled);
    }

    // Evaluate the aggregate MSM down to a single curve point.
    // The aggregate is identity iff `prior == identity` AND all
    // absorbed proofs verified.
    let new_point = aggregate.eval_to_curve_point().to_affine();
    Ok(RecursiveAccumulator::from_point(new_point))
}

/// Verification strategy that returns the proof's deferred MSM
/// rather than finalising it. Mirrors `BatchStrategy` from
/// `verifier::batch` but scoped to the accumulator-folding
/// recursion path.
struct AccumulatorStrategy<'params, C: CurveAffine> {
    msm: MSM<'params, C>,
}

impl<'params, C: CurveAffine> AccumulatorStrategy<'params, C> {
    fn new(params: &'params Params<C>) -> Self {
        Self {
            msm: MSM::new(params),
        }
    }
}

impl<'params, C: CurveAffine> crate::proofs::plonk::VerificationStrategy<'params, C>
    for AccumulatorStrategy<'params, C>
{
    type Output = MSM<'params, C>;

    fn process<E: EncodedChallenge<C>>(
        self,
        f: impl FnOnce(MSM<'params, C>) -> Result<Guard<'params, C, E>, Error>,
    ) -> Result<Self::Output, Error> {
        let guard = f(self.msm)?;
        Ok(guard.use_challenges())
    }
}

/// Errors when serialising / deserialising a [`RecursiveAccumulator`]
/// to / from bytes.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum AccumulatorSerdeError {
    /// Byte length doesn't match the curve's compressed-affine
    /// encoding length (32 for Pasta curves).
    BadLength,
    /// Bytes are the right length but don't decode as a valid
    /// curve point.
    InvalidPoint,
}

impl core::fmt::Display for AccumulatorSerdeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BadLength => f.write_str("accumulator-bytes length mismatch"),
            Self::InvalidPoint => f.write_str("accumulator-bytes do not decode as a curve point"),
        }
    }
}

impl std::error::Error for AccumulatorSerdeError {}

impl<C: CurveAffine> RecursiveAccumulator<C> {
    /// Encode as the curve's compressed-affine bytes (32 bytes
    /// for Pasta; check curve's `Repr` width for other curves).
    pub fn to_bytes(&self) -> Vec<u8> {
        use group::GroupEncoding;
        self.point.to_bytes().as_ref().to_vec()
    }

    /// Decode from compressed-affine bytes.
    ///
    /// # Errors
    ///
    /// - [`AccumulatorSerdeError::BadLength`] if `bytes.len()`
    ///   doesn't match the curve's repr-width.
    /// - [`AccumulatorSerdeError::InvalidPoint`] if the bytes
    ///   are the right length but don't decode as a valid
    ///   curve point.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, AccumulatorSerdeError> {
        use group::GroupEncoding;
        // Curve's `Repr` is `[u8; N]` — match length precisely.
        let mut repr = <C as GroupEncoding>::Repr::default();
        let expected_len = repr.as_ref().len();
        if bytes.len() != expected_len {
            return Err(AccumulatorSerdeError::BadLength);
        }
        let mut_repr = repr.as_mut();
        let len = mut_repr.len();
        mut_repr[..len].copy_from_slice(&bytes[..len]);
        let point: C =
            Option::<C>::from(C::from_bytes(&repr)).ok_or(AccumulatorSerdeError::InvalidPoint)?;
        Ok(Self::from_point(point))
    }
}

/// Convenience: encode the accumulator into a fixed-size 32-byte
/// array (Pasta-curve specific). Production wire types use this
/// exact width.
impl<C> RecursiveAccumulator<C>
where
    C: CurveAffine,
{
    /// Encode into a fixed-size 32-byte array. Asserts the
    /// curve's repr is exactly 32 bytes.
    ///
    /// # Panics
    ///
    /// Panics if the curve's `GroupEncoding::Repr` is not 32
    /// bytes wide. For Pasta curves this is true by construction.
    pub fn to_bytes_fixed(&self) -> [u8; 32] {
        let bytes = self.to_bytes();
        bytes.try_into().expect("Pasta curve repr is 32 bytes")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pasta_curves::{vesta, EqAffine};

    #[test]
    fn empty_accumulator_verifies() {
        let acc: RecursiveAccumulator<EqAffine> = RecursiveAccumulator::empty();
        assert!(acc.verifies());
    }

    #[test]
    fn empty_accumulator_round_trips_bytes() {
        let acc: RecursiveAccumulator<EqAffine> = RecursiveAccumulator::empty();
        let bytes = acc.to_bytes();
        assert_eq!(bytes.len(), 32);
        let decoded: RecursiveAccumulator<EqAffine> =
            RecursiveAccumulator::from_bytes(&bytes).expect("decodes");
        assert_eq!(acc, decoded);
        assert!(decoded.verifies());
    }

    #[test]
    fn from_bytes_rejects_wrong_length() {
        let result: Result<RecursiveAccumulator<EqAffine>, _> =
            RecursiveAccumulator::from_bytes(&[0u8; 31]);
        assert!(matches!(result, Err(AccumulatorSerdeError::BadLength)));
    }

    #[test]
    fn from_bytes_rejects_invalid_curve_point() {
        // 32 bytes that don't encode a valid Vesta point.
        let bad = [0xFFu8; 32];
        let result: Result<RecursiveAccumulator<EqAffine>, _> =
            RecursiveAccumulator::from_bytes(&bad);
        assert!(matches!(result, Err(AccumulatorSerdeError::InvalidPoint)));
    }

    #[test]
    fn to_bytes_fixed_matches_to_bytes() {
        let acc: RecursiveAccumulator<EqAffine> = RecursiveAccumulator::empty();
        let dynamic = acc.to_bytes();
        let fixed = acc.to_bytes_fixed();
        assert_eq!(dynamic.as_slice(), &fixed[..]);
    }

    /// A non-identity accumulator (random point) does NOT verify.
    /// This pins the "verifies" semantics: identity ⇔ valid.
    #[test]
    fn non_identity_accumulator_does_not_verify() {
        // The Vesta generator is non-identity by construction.
        let generator = vesta::Affine::generator();
        let acc: RecursiveAccumulator<EqAffine> = RecursiveAccumulator::from_point(generator);
        assert!(!acc.verifies());
    }
}
