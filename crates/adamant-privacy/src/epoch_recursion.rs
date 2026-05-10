//! Per-epoch recursive proof composition wiring — Phase 6.9b.
//!
//! Builds on [`adamant_halo2::recursion::RecursiveAccumulator`]
//! to give Adamant validators a full prove + verify path for
//! per-epoch recursive proof composition per whitepaper §8.5.2.
//!
//! # Workflow
//!
//! Per §8.5.2, the recursive proof at epoch N attests:
//!
//! - The recursive proof from epoch N-1 (i.e., the prior
//!   accumulator was identity).
//! - All per-transaction proofs in epoch N verified.
//! - The chain state at the end of epoch N is a specific
//!   commitment.
//!
//! Construction (homogeneous pure-Pallas accumulator-folding):
//!
//! 1. Validator collects all per-transaction validity proofs
//!    accepted in this epoch.
//! 2. Validator (or prover-market participant per §8.5.3)
//!    invokes [`fold_epoch`], passing the prior epoch's
//!    accumulator + this epoch's per-tx proofs (each as
//!    `(public_inputs_rows, proof_bytes)`).
//! 3. The function:
//!    - Verifies each per-tx proof against the validity-circuit
//!      verifying key (extracts the deferred MSM via
//!      [`adamant_halo2::recursion::fold_proofs`]).
//!    - Folds all MSMs into a single curve point.
//!    - Returns a [`RecursiveAccumulator`] that captures
//!      "epoch N's per-tx proofs verified AND the prior
//!      accumulator was identity."
//! 4. Validator constructs a [`RecursiveProofEnvelope`] wrapping
//!    the accumulator's bytes, the public inputs (genesis +
//!    prev + curr commitments + epoch number), and the cadence
//!    tag.
//! 5. Light clients verify the envelope via [`verify_envelope`]:
//!    decode the accumulator bytes, check `verifies()` returns
//!    true.
//!
//! # Posture-independence of the wire format
//!
//! The on-chain `RecursiveProof` is a single 32-byte curve point
//! regardless of whether the recursive verifier is
//! out-of-circuit (this sub-arc) or in-circuit (future sub-arc).
//! Switching to the in-circuit verifier (a perf optimisation
//! producing succinct SNARK-of-SNARK proofs) does not change
//! the on-chain envelope shape; it changes only how validators
//! produce the bytes and how light clients verify them. The
//! wire format pinned at Phase 6.9a stays valid.

#![allow(clippy::doc_markdown)]

use adamant_halo2::proofs::plonk::VerifyingKey;
use adamant_halo2::proofs::poly::commitment::Params;
use adamant_halo2::recursion::{fold_proofs, AccumulatorSerdeError, RecursiveAccumulator};
use pasta_curves::pallas;
use pasta_curves::vesta;
use rand_core::RngCore;

use crate::proving::CommitmentCurve;
use crate::recursive_proof::{
    EpochCommitment, ProofCadence, RecursiveProof, RecursiveProofEnvelope,
    RecursiveProofPublicInputs,
};

/// Pasta-cycle accumulator curve for Adamant validity proofs.
///
/// Validity circuits live on `pallas::Base`; their IPA
/// commitments (and thus the recursive-accumulator points) live
/// on Vesta (`vesta::Affine`, == `pasta_curves::EqAffine`).
/// This is the same Pasta-cycle pin documented at
/// [`crate::proving::CommitmentCurve`].
pub type EpochAccumulator = RecursiveAccumulator<vesta::Affine>;

/// Errors surfaced by the epoch-recursion entry points.
#[derive(Debug)]
pub enum EpochRecursionError {
    /// Underlying halo2 plonk error from one of the per-proof
    /// verifications (malformed transcript, invalid commitment,
    /// etc).
    Plonk(adamant_halo2::proofs::plonk::Error),
    /// Mismatch between the count of public inputs and the
    /// count of proof byte buffers passed to [`fold_epoch`].
    InstanceProofCountMismatch {
        /// Number of `Vec<pallas::Base>` public-input rows
        /// supplied.
        instance_count: usize,
        /// Number of proof byte buffers supplied.
        proof_count: usize,
    },
    /// Failed to deserialise the accumulator bytes embedded in
    /// the recursive-proof envelope.
    AccumulatorSerdeError(AccumulatorSerdeError),
    /// Recursive accumulator did not verify (its point is not
    /// the curve identity, meaning at least one absorbed proof
    /// failed).
    AccumulatorRejected,
    /// Public inputs don't structurally chain onto the prior
    /// envelope (genesis commitments don't match, or epoch
    /// numbers aren't sequential, or `previous_epoch` of next
    /// doesn't equal `current_epoch` of prior).
    EnvelopeChainBroken,
}

impl core::fmt::Display for EpochRecursionError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Plonk(e) => write!(f, "halo2 plonk error: {e:?}"),
            Self::InstanceProofCountMismatch {
                instance_count,
                proof_count,
            } => write!(
                f,
                "instance count {instance_count} != proof count {proof_count}"
            ),
            Self::AccumulatorSerdeError(e) => write!(f, "accumulator serde error: {e}"),
            Self::AccumulatorRejected => f.write_str("recursive accumulator rejected"),
            Self::EnvelopeChainBroken => f.write_str("envelope chain broken"),
        }
    }
}

impl std::error::Error for EpochRecursionError {}

impl From<adamant_halo2::proofs::plonk::Error> for EpochRecursionError {
    fn from(e: adamant_halo2::proofs::plonk::Error) -> Self {
        Self::Plonk(e)
    }
}

impl From<AccumulatorSerdeError> for EpochRecursionError {
    fn from(e: AccumulatorSerdeError) -> Self {
        Self::AccumulatorSerdeError(e)
    }
}

/// Fold this epoch's per-transaction validity proofs into the
/// running recursive accumulator.
///
/// Each per-tx proof is verified against the validity-circuit
/// verifying key; the deferred MSM is folded into the running
/// aggregate; the aggregate evaluates to a single Vesta-affine
/// point representing the new accumulator state.
///
/// Returns the new accumulator and the bytes-encoded form
/// suitable for inclusion in a [`RecursiveProofEnvelope`].
///
/// # Errors
///
/// - [`EpochRecursionError::InstanceProofCountMismatch`] if the
///   public-input vector count doesn't match the proof byte
///   buffer count.
/// - [`EpochRecursionError::Plonk`] if any per-tx proof's MSM
///   extraction fails.
pub fn fold_epoch<R>(
    params: &Params<CommitmentCurve>,
    vk: &VerifyingKey<CommitmentCurve>,
    public_inputs_rows: &[Vec<pallas::Base>],
    proof_bytes: &[Vec<u8>],
    prior: EpochAccumulator,
    rng: R,
) -> Result<EpochAccumulator, EpochRecursionError>
where
    R: RngCore,
{
    if public_inputs_rows.len() != proof_bytes.len() {
        return Err(EpochRecursionError::InstanceProofCountMismatch {
            instance_count: public_inputs_rows.len(),
            proof_count: proof_bytes.len(),
        });
    }

    // Reshape inputs to the verify_proof shape: each proof's
    // instances are a single instance column of public-input
    // rows.
    let instances_per_proof: Vec<Vec<&[pallas::Base]>> = public_inputs_rows
        .iter()
        .map(|rows| vec![rows.as_slice()])
        .collect();
    let instances_borrowed: Vec<&[&[pallas::Base]]> =
        instances_per_proof.iter().map(Vec::as_slice).collect();
    let proofs_borrowed: Vec<&[u8]> = proof_bytes.iter().map(Vec::as_slice).collect();

    let new_acc = fold_proofs(
        params,
        vk,
        &instances_borrowed,
        &proofs_borrowed,
        prior,
        rng,
    )?;
    Ok(new_acc)
}

/// Build the on-chain [`RecursiveProofEnvelope`] for an epoch
/// from a freshly-folded accumulator + the genesis/prev/curr
/// chain commitments.
///
/// The envelope's `proof` field carries the accumulator bytes;
/// the `public_inputs` field carries the chain commitments;
/// the `cadence` field tags whether the proof came from the
/// permissionless prover market (`Steady`) or validator-fallback
/// (`Fallback`) per §8.5.4.
#[must_use]
pub fn envelope_from_accumulator(
    accumulator: EpochAccumulator,
    genesis: EpochCommitment,
    previous_epoch: EpochCommitment,
    current_epoch: EpochCommitment,
    epoch_number: u64,
    cadence: ProofCadence,
) -> RecursiveProofEnvelope {
    let proof_bytes = accumulator.to_bytes();
    RecursiveProofEnvelope::new(
        RecursiveProof::from_bytes(proof_bytes),
        RecursiveProofPublicInputs {
            genesis,
            previous_epoch,
            current_epoch,
            epoch_number,
        },
        cadence,
    )
}

/// Verify a [`RecursiveProofEnvelope`] cryptographically.
///
/// Light-client + validator entry point. Steps:
///
/// 1. Decode the envelope's `proof.bytes` as an [`EpochAccumulator`].
/// 2. Check `accumulator.verifies()` (the accumulator point
///    equals the curve identity ⇔ all absorbed proofs verified).
///
/// # Errors
///
/// - [`EpochRecursionError::AccumulatorSerdeError`] if the
///   bytes don't decode as a valid accumulator (wrong length,
///   not a curve point).
/// - [`EpochRecursionError::AccumulatorRejected`] if the
///   accumulator fails its identity check.
pub fn verify_envelope(envelope: &RecursiveProofEnvelope) -> Result<(), EpochRecursionError> {
    let accumulator = EpochAccumulator::from_bytes(envelope.proof.as_bytes())?;
    if !accumulator.verifies() {
        return Err(EpochRecursionError::AccumulatorRejected);
    }
    Ok(())
}

/// Verify that `next` chains structurally onto `prev`. Combines
/// [`RecursiveProofEnvelope::chains_to`]'s structural check with
/// [`verify_envelope`]'s cryptographic check on `next`.
///
/// `prev` is expected to have already been verified by an
/// earlier call to [`verify_envelope`]; this function does not
/// re-verify it.
///
/// # Errors
///
/// - [`EpochRecursionError::EnvelopeChainBroken`] if the
///   structural check fails.
/// - Errors from [`verify_envelope`] for `next`.
pub fn verify_chain_link(
    prev: &RecursiveProofEnvelope,
    next: &RecursiveProofEnvelope,
) -> Result<(), EpochRecursionError> {
    if !prev.chains_to(next) {
        return Err(EpochRecursionError::EnvelopeChainBroken);
    }
    verify_envelope(next)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixed_genesis() -> EpochCommitment {
        EpochCommitment::from_bytes([0xAA; 32])
    }

    fn fixed_chain_commitment(epoch: u64) -> EpochCommitment {
        let mut bytes = [0u8; 32];
        bytes[..8].copy_from_slice(&epoch.to_le_bytes());
        EpochCommitment::from_bytes(bytes)
    }

    /// Genesis envelope (epoch 0) with empty accumulator
    /// verifies. The empty accumulator IS the identity, so it
    /// trivially satisfies the recursion base case.
    #[test]
    fn genesis_empty_accumulator_envelope_verifies() {
        let acc = EpochAccumulator::empty();
        let genesis = fixed_genesis();
        let envelope = envelope_from_accumulator(
            acc,
            genesis,
            genesis, // prev = genesis at epoch 0
            genesis, // curr = genesis at epoch 0
            0,
            ProofCadence::Steady,
        );

        assert!(envelope.is_genesis_envelope());
        verify_envelope(&envelope).expect("genesis envelope verifies");
    }

    /// An envelope whose accumulator bytes don't decode as a
    /// curve point is rejected.
    #[test]
    fn envelope_with_invalid_accumulator_bytes_rejected() {
        let envelope = RecursiveProofEnvelope::new(
            RecursiveProof::from_bytes(vec![0xFFu8; 32]),
            RecursiveProofPublicInputs {
                genesis: fixed_genesis(),
                previous_epoch: fixed_genesis(),
                current_epoch: fixed_genesis(),
                epoch_number: 0,
            },
            ProofCadence::Steady,
        );

        let result = verify_envelope(&envelope);
        assert!(matches!(
            result,
            Err(EpochRecursionError::AccumulatorSerdeError(_))
        ));
    }

    /// An envelope whose accumulator bytes are wrong length is
    /// rejected.
    #[test]
    fn envelope_with_wrong_length_accumulator_bytes_rejected() {
        let envelope = RecursiveProofEnvelope::new(
            RecursiveProof::from_bytes(vec![0u8; 31]),
            RecursiveProofPublicInputs {
                genesis: fixed_genesis(),
                previous_epoch: fixed_genesis(),
                current_epoch: fixed_genesis(),
                epoch_number: 0,
            },
            ProofCadence::Steady,
        );

        let result = verify_envelope(&envelope);
        assert!(matches!(
            result,
            Err(EpochRecursionError::AccumulatorSerdeError(_))
        ));
    }

    /// An envelope whose accumulator is a non-identity curve
    /// point (e.g., the generator) is rejected.
    #[test]
    fn envelope_with_non_identity_accumulator_rejected() {
        use pasta_curves::group::prime::PrimeCurveAffine;
        let non_id = vesta::Affine::generator();
        let acc = EpochAccumulator::from_point(non_id);

        let envelope = envelope_from_accumulator(
            acc,
            fixed_genesis(),
            fixed_genesis(),
            fixed_genesis(),
            0,
            ProofCadence::Steady,
        );

        let result = verify_envelope(&envelope);
        assert!(matches!(
            result,
            Err(EpochRecursionError::AccumulatorRejected)
        ));
    }

    /// A two-epoch chain: genesis (epoch 0) → epoch 1, with both
    /// accumulators empty (identity). Structural chain link
    /// holds; both verify.
    #[test]
    fn two_epoch_chain_verifies() {
        let genesis = fixed_genesis();
        let curr_e0 = genesis;
        let curr_e1 = fixed_chain_commitment(1);

        let env0 = envelope_from_accumulator(
            EpochAccumulator::empty(),
            genesis,
            genesis,
            curr_e0,
            0,
            ProofCadence::Steady,
        );
        let env1 = envelope_from_accumulator(
            EpochAccumulator::empty(),
            genesis,
            curr_e0, // prev = e0's curr
            curr_e1,
            1,
            ProofCadence::Steady,
        );

        assert!(env0.chains_to(&env1));
        verify_envelope(&env0).expect("e0 verifies");
        verify_chain_link(&env0, &env1).expect("e1 chains + verifies");
    }

    /// A chain break (epoch 1's previous_epoch != epoch 0's
    /// current_epoch) is rejected by `verify_chain_link`.
    #[test]
    fn chain_break_rejected() {
        let genesis = fixed_genesis();

        let env0 = envelope_from_accumulator(
            EpochAccumulator::empty(),
            genesis,
            genesis,
            fixed_chain_commitment(1),
            0,
            ProofCadence::Steady,
        );
        // env1 claims previous_epoch = different commitment.
        let env1 = envelope_from_accumulator(
            EpochAccumulator::empty(),
            genesis,
            fixed_chain_commitment(99), // wrong; should be commitment(1)
            fixed_chain_commitment(2),
            1,
            ProofCadence::Steady,
        );

        let result = verify_chain_link(&env0, &env1);
        assert!(matches!(
            result,
            Err(EpochRecursionError::EnvelopeChainBroken)
        ));
    }

    /// Arity-mismatch surfaces as a typed error (instance count
    /// != proof count). Caller-side hygiene check.
    #[test]
    fn fold_epoch_arity_mismatch_typed_error() {
        use crate::circuit::validity::ValidityDomainTags;
        use crate::proving::ValidityKeySet;
        use rand::rngs::OsRng;

        let dt = ValidityDomainTags {
            nullifier_key_inner: pallas::Base::from(1u64),
            nullifier_outer: pallas::Base::from(2u64),
        };
        // K=12 keygen — same setup as proving::tests.
        let keys: ValidityKeySet<4, 1, 1> = ValidityKeySet::keygen(12, dt).expect("keygen");

        let public = vec![pallas::Base::from(0u64); 7];
        let proof_a = vec![0u8; 100];
        let proof_b = vec![0u8; 100];

        // Mismatched arities: 1 instance vs 2 proofs.
        let result = fold_epoch(
            &keys.params,
            keys.vk(),
            &[public],
            &[proof_a, proof_b],
            EpochAccumulator::empty(),
            OsRng,
        );

        assert!(matches!(
            result,
            Err(EpochRecursionError::InstanceProofCountMismatch { .. })
        ));
    }

    /// Empty proof set (no per-tx proofs in this epoch — e.g.,
    /// a validator-fallback proof during low-traffic epoch)
    /// produces an accumulator equal to the prior accumulator
    /// scaled by a random factor. If the prior was identity,
    /// the new accumulator is also identity (random * identity
    /// = identity).
    #[test]
    fn fold_epoch_no_proofs_preserves_prior_identity() {
        use crate::circuit::validity::ValidityDomainTags;
        use crate::proving::ValidityKeySet;
        use rand::rngs::OsRng;

        let dt = ValidityDomainTags {
            nullifier_key_inner: pallas::Base::from(1u64),
            nullifier_outer: pallas::Base::from(2u64),
        };
        let keys: ValidityKeySet<4, 1, 1> = ValidityKeySet::keygen(12, dt).expect("keygen");

        let new_acc = fold_epoch(
            &keys.params,
            keys.vk(),
            &[],
            &[],
            EpochAccumulator::empty(),
            OsRng,
        )
        .expect("fold succeeds");

        assert!(new_acc.verifies());
    }

    /// Diagnostic: verify a single real proof folds to identity.
    /// Isolates the fold path before testing multi-proof folding.
    #[test]
    fn fold_epoch_single_real_proof_verifies() {
        use crate::proving::{prove, verify, ValidityKeySet};
        use rand::rngs::OsRng;

        let dt = real_domain_tags();
        let keys: ValidityKeySet<4, 1, 1> = ValidityKeySet::keygen(12, dt).expect("keygen");

        let (circuit, public) = build_minimal_proof_fixture(&dt);
        let proof = prove(&keys, circuit, &public, OsRng).expect("prove");

        // Sanity: the proof verifies via the existing verify path.
        verify(&keys, &public, &proof).expect("verify via SingleVerifier");

        // Fold via accumulator-folding.
        let acc = fold_epoch(
            &keys.params,
            keys.vk(),
            &[public.to_rows()],
            &[proof],
            EpochAccumulator::empty(),
            OsRng,
        )
        .expect("fold succeeds");
        assert!(
            acc.verifies(),
            "single real proof should fold to identity accumulator (point bytes: {:?})",
            acc.to_bytes_fixed()
        );
    }

    /// **Canonical soundness pin**: fold two real validity-circuit
    /// proofs through the epoch accumulator and verify the
    /// result. Then tamper one proof's bytes and refold;
    /// verification must reject.
    ///
    /// This exercises the full pipeline:
    ///   - Real `ValidityCircuit::prove` to produce two
    ///     valid Halo 2 IPA proofs.
    ///   - `fold_epoch` extracts each proof's deferred MSM,
    ///     scales by random challenges, accumulates.
    ///   - `verify_envelope` decodes the accumulator point and
    ///     checks identity.
    ///
    /// This is the soundness story for §8.5.2 pure-Pallas
    /// accumulator-folding recursion: identity ⇔ all proofs
    /// verified.
    #[test]
    fn end_to_end_real_proofs_round_trip_and_tamper_rejection() {
        use crate::proving::{prove, ValidityKeySet};
        use rand::rngs::OsRng;

        // Build the validity-circuit keyset at the same shape as
        // proving::tests (DEPTH=4, N=M=1, K=12).
        let dt = real_domain_tags();
        // We construct the keyset's `(circuit, public)` via the
        // proving module's existing test fixture builder, exposed
        // through the public test surface. To avoid adding more
        // re-exports, we duplicate the minimal setup here.
        let keys: ValidityKeySet<4, 1, 1> = ValidityKeySet::keygen(12, dt).expect("keygen");

        // Build two consistent validity proofs via the proving
        // module. We can't call `proving::tests::fixed_setup_1x1`
        // directly (test-private), but we can re-derive the same
        // fixture path: see `proving.rs::tests` for the canonical
        // setup. For the soundness test we reuse two identical
        // copies of the same fixture, which is sufficient — each
        // produces an independent proof with fresh randomness.
        let (circuit_1, public_1) = build_minimal_proof_fixture(&dt);
        let (circuit_2, public_2) = build_minimal_proof_fixture(&dt);

        let proof_1 = prove(&keys, circuit_1, &public_1, OsRng).expect("prove 1");
        let proof_2 = prove(&keys, circuit_2, &public_2, OsRng).expect("prove 2");

        // Fold both into a single accumulator.
        let public_rows_1 = public_1.to_rows();
        let public_rows_2 = public_2.to_rows();
        let accumulator = fold_epoch(
            &keys.params,
            keys.vk(),
            &[public_rows_1.clone(), public_rows_2.clone()],
            &[proof_1.clone(), proof_2.clone()],
            EpochAccumulator::empty(),
            OsRng,
        )
        .expect("fold succeeds");

        assert!(
            accumulator.verifies(),
            "real proofs should fold to identity accumulator"
        );

        // Wrap in an envelope and verify the wire path.
        let envelope = envelope_from_accumulator(
            accumulator,
            fixed_genesis(),
            fixed_genesis(),
            fixed_chain_commitment(1),
            1,
            ProofCadence::Steady,
        );
        verify_envelope(&envelope).expect("envelope verifies");

        // Tamper: flip a byte in proof_2 and refold. The
        // accumulator must reject.
        let mut tampered = proof_2.clone();
        // Flip a byte deep enough that it lands inside the proof
        // body, not the header.
        let idx = tampered.len() / 2;
        tampered[idx] ^= 0x01;

        let tampered_acc = fold_epoch(
            &keys.params,
            keys.vk(),
            &[public_rows_1, public_rows_2],
            &[proof_1, tampered],
            EpochAccumulator::empty(),
            OsRng,
        );

        // Tampering should either:
        //   (a) cause verify_proof to fail during the fold (the
        //       transcript Blake2b chain notices the byte flip
        //       and the proof's MSM extraction errors), or
        //   (b) pass through but produce a non-identity
        //       accumulator that fails verify_envelope.
        // Both branches are acceptable rejections.
        match tampered_acc {
            Err(_) => { /* (a) — rejected at fold time */ }
            Ok(acc) => {
                assert!(
                    !acc.verifies(),
                    "tampered proof must produce non-identity accumulator"
                );
            }
        }
    }

    /// Build a minimal valid validity-circuit witness + public
    /// inputs suitable for the round-trip soundness test.
    /// Mirrors `proving::tests::fixed_setup_1x1` but keeps this
    /// test module self-contained.
    #[allow(clippy::too_many_lines)]
    fn build_minimal_proof_fixture(
        domain_tags: &crate::circuit::validity::ValidityDomainTags,
    ) -> (
        crate::circuit::validity::ValidityCircuit<4, 1, 1>,
        crate::circuit::validity::ValidityPublicInputs,
    ) {
        use crate::circuit::range_check::u64_to_bit_witnesses;
        use crate::circuit::validity::{
            InputNoteWitness, OutputNoteWitness, ValidityCircuit, ValidityPublicInputs,
            ValidityWitness,
        };
        use crate::nullifier::{derive_nullifier, derive_nullifier_key, LeafPosition, SpendingKey};
        use crate::poseidon::{poseidon_hash, FieldBytes};
        use crate::value_commitment::{asset_value_generator, commit, ValueCommitmentRandomness};
        use crate::NoteCommitment;
        use adamant_halo2::proofs::circuit::Value;
        use adamant_types::TypeId;
        use pasta_curves::group::ff::PrimeField;
        use pasta_curves::group::Curve;

        fn fb_to_base(fb: FieldBytes) -> pallas::Base {
            pallas::Base::from_repr(fb.to_bytes())
                .expect("FieldBytes invariant: bytes encode a valid field element")
        }

        let value_in = 1_000u64;
        let asset = TypeId::from_bytes([0x01; 32]);
        let recipient_in = FieldBytes::from_bytes_reduced([0x10; 32]);
        let randomness_in = FieldBytes::from_bytes_reduced([0x11; 32]);
        let meta_in = FieldBytes::from_bytes_reduced([0x12; 32]);
        let value_in_fb = FieldBytes::from_bytes_reduced(pallas::Base::from(value_in).to_repr());
        let cm_in_fb = poseidon_hash::<5>([
            value_in_fb,
            FieldBytes::from_bytes_reduced(asset.to_bytes()),
            recipient_in,
            randomness_in,
            meta_in,
        ]);
        let cm_in = fb_to_base(cm_in_fb);

        let sk_bytes = [0x44; 32];
        let position = 5u64;
        let siblings = [
            fb_to_base(FieldBytes::from_bytes_reduced([0x21; 32])),
            fb_to_base(FieldBytes::from_bytes_reduced([0x22; 32])),
            fb_to_base(FieldBytes::from_bytes_reduced([0x23; 32])),
            fb_to_base(FieldBytes::from_bytes_reduced([0x24; 32])),
        ];
        let bits = [true, false, true, false];
        let mut current = cm_in;
        for (sibling, &bit) in siblings.iter().zip(bits.iter()) {
            let (l, r) = if bit {
                (*sibling, current)
            } else {
                (current, *sibling)
            };
            let l_fb = FieldBytes::from_bytes(l.to_repr()).unwrap();
            let r_fb = FieldBytes::from_bytes(r.to_repr()).unwrap();
            current = fb_to_base(poseidon_hash::<2>([l_fb, r_fb]));
        }
        let gnct_root = current;

        let sk_obj = SpendingKey::from_bytes(sk_bytes);
        let nk = derive_nullifier_key(&sk_obj);
        let cm_in_obj = NoteCommitment::from_bytes(cm_in_fb.to_bytes());
        let nullifier = derive_nullifier(&nk, &cm_in_obj, LeafPosition(position));
        let nullifier_base = pallas::Base::from_repr(nullifier.to_bytes()).unwrap();

        let value_in_w = u64_to_bit_witnesses(value_in);
        let v_tau_in = asset_value_generator(asset).to_affine();
        let r_in = ValueCommitmentRandomness::from_uniform_bytes(&[0x55; 64]);
        let r_in_scalar = pallas::Scalar::from_repr(r_in.to_bytes()).unwrap();
        let vc_in = commit(value_in, asset, &r_in);
        let vc_in_pt = vc_in.to_point().unwrap();
        let vc_in_xy = pasta_curves::arithmetic::CurveAffine::coordinates(&vc_in_pt).unwrap();

        let value_out = 1_000u64;
        let recipient_out = FieldBytes::from_bytes_reduced([0x30; 32]);
        let randomness_out = FieldBytes::from_bytes_reduced([0x31; 32]);
        let meta_out = FieldBytes::from_bytes_reduced([0x32; 32]);
        let value_out_fb = FieldBytes::from_bytes_reduced(pallas::Base::from(value_out).to_repr());
        let cm_out_fb = poseidon_hash::<5>([
            value_out_fb,
            FieldBytes::from_bytes_reduced(asset.to_bytes()),
            recipient_out,
            randomness_out,
            meta_out,
        ]);
        let cm_out = fb_to_base(cm_out_fb);

        let value_out_w = u64_to_bit_witnesses(value_out);
        let v_tau_out = asset_value_generator(asset).to_affine();
        let r_out = ValueCommitmentRandomness::from_uniform_bytes(&[0x66; 64]);
        let r_out_scalar = pallas::Scalar::from_repr(r_out.to_bytes()).unwrap();
        let vc_out = commit(value_out, asset, &r_out);
        let vc_out_pt = vc_out.to_point().unwrap();
        let vc_out_xy = pasta_curves::arithmetic::CurveAffine::coordinates(&vc_out_pt).unwrap();

        let input = InputNoteWitness {
            value: value_in_w.value,
            asset_type: Value::known(fb_to_base(FieldBytes::from_bytes_reduced(asset.to_bytes()))),
            recipient: Value::known(fb_to_base(recipient_in)),
            randomness: Value::known(fb_to_base(randomness_in)),
            metadata_hash: Value::known(fb_to_base(meta_in)),
            spending_key: Value::known(fb_to_base(FieldBytes::from_bytes_reduced(sk_bytes))),
            position: Value::known(pallas::Base::from(position)),
            path_siblings: siblings.map(Value::known),
            path_bits: bits.map(Value::known),
            value_bits: value_in_w.bits,
            value_generator: Value::known(v_tau_in),
            vc_randomness: Value::known(r_in_scalar),
        };
        let output = OutputNoteWitness {
            value: value_out_w.value,
            asset_type: Value::known(fb_to_base(FieldBytes::from_bytes_reduced(asset.to_bytes()))),
            recipient: Value::known(fb_to_base(recipient_out)),
            randomness: Value::known(fb_to_base(randomness_out)),
            metadata_hash: Value::known(fb_to_base(meta_out)),
            value_bits: value_out_w.bits,
            value_generator: Value::known(v_tau_out),
            vc_randomness: Value::known(r_out_scalar),
        };

        let witness = ValidityWitness::<4, 1, 1> {
            inputs: [input],
            outputs: [output],
        };
        let circuit = ValidityCircuit::new(witness, *domain_tags);

        let public = ValidityPublicInputs {
            gnct_root,
            nullifiers: vec![nullifier_base],
            output_commitments: vec![cm_out],
            vc_in: vec![(*vc_in_xy.x(), *vc_in_xy.y())],
            vc_out: vec![(*vc_out_xy.x(), *vc_out_xy.y())],
        };

        (circuit, public)
    }

    /// Real circuit-locked domain tags matching the §7.4 spec's
    /// nullifier derivation. Must match what the circuit
    /// constrains and what off-circuit `derive_nullifier_key` /
    /// `derive_nullifier` use, otherwise the proof's nullifier
    /// won't match the public-input nullifier and verification
    /// fails.
    fn real_domain_tags() -> crate::circuit::validity::ValidityDomainTags {
        use crate::poseidon::FieldBytes;
        use adamant_crypto::domain;
        use adamant_crypto::hash::sha3_256_tagged;
        use pasta_curves::group::ff::PrimeField;

        fn dt_field(tag: &domain::DomainTag) -> pallas::Base {
            let bytes = sha3_256_tagged(tag, b"");
            let fb = FieldBytes::from_bytes_reduced(bytes);
            pallas::Base::from_repr(fb.to_bytes()).expect("FieldBytes invariant")
        }

        crate::circuit::validity::ValidityDomainTags {
            nullifier_key_inner: dt_field(&domain::NULLIFIER_KEY_DERIVATION),
            nullifier_outer: dt_field(&domain::NULLIFIER_HASH),
        }
    }
}
