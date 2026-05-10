//! Phase 6.8b.5 — proving / verifying infrastructure for the
//! Adamant validity circuit (§7.3.2).
//!
//! Wraps `adamant-halo2`'s PLONK keygen / prove / verify
//! surface in Adamant-shape APIs that take a
//! [`ValidityCircuit`] + [`ValidityPublicInputs`] and produce
//! / consume opaque proof bytes.
//!
//! # Pasta-cycle commitment surface
//!
//! The validity circuit is defined over `pallas::Base` (= Fp).
//! Halo 2's IPA polynomial commitments require a curve whose
//! **scalar** field equals the circuit's base field, which on
//! the Pasta cycle is **Vesta** (`vesta::Affine`, also known
//! as `EqAffine` in `pasta_curves`). All commitments,
//! transcripts, and verifying-key fixed-commitment vectors
//! therefore live on Vesta; only the witness arithmetic lives
//! on Pallas-base. This is the standard Pasta-cycle pin.
//!
//! # Transcript hash
//!
//! Halo 2's standard Fiat-Shamir transcript uses Blake2b
//! (`Blake2bWrite` / `Blake2bRead` over a `Challenge255`
//! domain separator). Adamant inherits this from the
//! `adamant-halo2` fork per CLAUDE.md §14.4 Decision 1
//! (Path C2 — fork rather than reimplement). Changing the
//! transcript hash would change proof bytes and is therefore
//! a hard-fork-only decision.
//!
//! # Key serialization
//!
//! Phase 6.8b.5 ships in-memory keysets via
//! [`ValidityKeySet::keygen`]. Wire-format serialization of
//! the verifying key (proving keys are deterministic from the
//! circuit shape + Params and so don't need to ship over the
//! wire) is deferred to a follow-up sub-arc; Adamant's wire
//! envelopes ship proof bytes only, and verifiers re-derive
//! the verifying key from the genesis-fixed circuit shape.
//! The `cs_pinned` / `transcript_repr` invariants of the VK
//! are deterministic, so this re-derivation is reproducible.
//!
//! # Errors
//!
//! All public APIs return [`ProvingError`], a small enum
//! collapsing `adamant_halo2`'s `plonk::Error` plus an
//! Adamant-specific arity-mismatch variant.

#![allow(clippy::doc_markdown, clippy::too_many_lines)]

use adamant_halo2::proofs::plonk::{
    create_proof, keygen_pk, keygen_vk, verify_proof, Error as PlonkError, ProvingKey,
    SingleVerifier, VerifyingKey,
};
use adamant_halo2::proofs::poly::commitment::Params;
use adamant_halo2::proofs::transcript::{Blake2bRead, Blake2bWrite, Challenge255};
use pasta_curves::vesta;
use rand_core::RngCore;

use crate::circuit::validity::{ValidityCircuit, ValidityDomainTags, ValidityPublicInputs};

/// Pasta-cycle commitment curve: Vesta carries the IPA
/// commitments for circuits over `pallas::Base`.
pub type CommitmentCurve = vesta::Affine;

/// Bundled keygen artifacts for a particular `(DEPTH, N_INPUTS,
/// N_OUTPUTS)` arity. The proving key embeds the verifying key
/// (via `pk.get_vk()`), and both are derivable from `params + k
/// + circuit shape`.
///
/// Production deployments cache this per-arity at validator
/// startup; tests construct it on demand.
#[derive(Debug)]
pub struct ValidityKeySet<const DEPTH: usize, const N_INPUTS: usize, const N_OUTPUTS: usize> {
    /// IPA public parameters at row count `2^k`.
    pub params: Params<CommitmentCurve>,
    /// Proving key (also exposes the verifying key via
    /// [`ProvingKey::get_vk`]).
    pub pk: ProvingKey<CommitmentCurve>,
    /// Halo 2 row-count parameter (rows = `2^k`).
    pub k: u32,
    /// Domain tags this key was generated against. The
    /// verifying key encodes these via the constraint system
    /// shape; rebuilding with different tags produces a
    /// different VK.
    pub domain_tags: ValidityDomainTags,
}

impl<const DEPTH: usize, const N_INPUTS: usize, const N_OUTPUTS: usize>
    ValidityKeySet<DEPTH, N_INPUTS, N_OUTPUTS>
{
    /// Run keygen for the validity circuit at the given `k`
    /// row-count parameter.
    ///
    /// `k` must satisfy `2^k >= circuit_row_count + blinding`
    /// for the circuit at this `(DEPTH, N, M)` arity.
    /// Empirical sizing for DEPTH=4 / N=M=1 is `k = 12`; for
    /// the production DEPTH=64 / N=M=1 instantiation, expect
    /// `k ≈ 17`.
    ///
    /// # Errors
    ///
    /// Returns [`ProvingError::Plonk`] if keygen fails — most
    /// commonly because `k` is too small for the circuit's
    /// row count.
    pub fn keygen(k: u32, domain_tags: ValidityDomainTags) -> Result<Self, ProvingError> {
        let params = Params::<CommitmentCurve>::new(k);
        let circuit = ValidityCircuit::<DEPTH, N_INPUTS, N_OUTPUTS>::keygen(domain_tags);
        let vk = keygen_vk(&params, &circuit)?;
        let pk = keygen_pk(&params, vk, &circuit)?;
        Ok(Self {
            params,
            pk,
            k,
            domain_tags,
        })
    }

    /// Borrow the verifying key.
    #[must_use]
    pub fn vk(&self) -> &VerifyingKey<CommitmentCurve> {
        self.pk.get_vk()
    }
}

/// Errors surfaced by the prove / verify entry points.
#[derive(Debug)]
pub enum ProvingError {
    /// Underlying `adamant_halo2::plonk::Error`.
    Plonk(PlonkError),
    /// Public inputs don't match the declared `(N_INPUTS,
    /// N_OUTPUTS)` arity.
    ArityMismatch(String),
}

impl core::fmt::Display for ProvingError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Plonk(e) => write!(f, "halo2 plonk error: {e:?}"),
            Self::ArityMismatch(s) => write!(f, "public-input arity mismatch: {s}"),
        }
    }
}

impl std::error::Error for ProvingError {}

impl From<PlonkError> for ProvingError {
    fn from(e: PlonkError) -> Self {
        Self::Plonk(e)
    }
}

/// Generate a Halo 2 proof attesting the validity circuit's
/// statements over the given witness + public inputs.
///
/// # Errors
///
/// Returns [`ProvingError::ArityMismatch`] if `public` doesn't
/// match `(N_INPUTS, N_OUTPUTS)`. Returns [`ProvingError::Plonk`]
/// for proof-construction failures (witness inconsistency,
/// transcript I/O, etc).
pub fn prove<const DEPTH: usize, const N_INPUTS: usize, const N_OUTPUTS: usize>(
    keys: &ValidityKeySet<DEPTH, N_INPUTS, N_OUTPUTS>,
    circuit: ValidityCircuit<DEPTH, N_INPUTS, N_OUTPUTS>,
    public: &ValidityPublicInputs,
    rng: impl RngCore,
) -> Result<Vec<u8>, ProvingError> {
    public
        .check_arity(N_INPUTS, N_OUTPUTS)
        .map_err(ProvingError::ArityMismatch)?;

    let public_rows = public.to_rows();
    let mut transcript =
        Blake2bWrite::<Vec<u8>, CommitmentCurve, Challenge255<CommitmentCurve>>::init(vec![]);

    create_proof(
        &keys.params,
        &keys.pk,
        &[circuit],
        &[&[&public_rows[..]]],
        rng,
        &mut transcript,
    )?;

    Ok(transcript.finalize())
}

/// Verify a Halo 2 proof previously produced by [`prove`].
///
/// # Errors
///
/// Returns [`ProvingError::ArityMismatch`] if `public` doesn't
/// match `(N_INPUTS, N_OUTPUTS)`. Returns [`ProvingError::Plonk`]
/// if the proof is malformed or fails verification.
pub fn verify<const DEPTH: usize, const N_INPUTS: usize, const N_OUTPUTS: usize>(
    keys: &ValidityKeySet<DEPTH, N_INPUTS, N_OUTPUTS>,
    public: &ValidityPublicInputs,
    proof_bytes: &[u8],
) -> Result<(), ProvingError> {
    public
        .check_arity(N_INPUTS, N_OUTPUTS)
        .map_err(ProvingError::ArityMismatch)?;

    let public_rows = public.to_rows();
    let strategy = SingleVerifier::new(&keys.params);
    let mut transcript =
        Blake2bRead::<&[u8], CommitmentCurve, Challenge255<CommitmentCurve>>::init(proof_bytes);

    verify_proof(
        &keys.params,
        keys.vk(),
        strategy,
        &[&[&public_rows[..]]],
        &mut transcript,
    )?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circuit::range_check::u64_to_bit_witnesses;
    use crate::circuit::validity::{InputNoteWitness, OutputNoteWitness, ValidityWitness};
    use crate::nullifier::{derive_nullifier, derive_nullifier_key, LeafPosition, SpendingKey};
    use crate::poseidon::{poseidon_hash, FieldBytes};
    use crate::value_commitment::{asset_value_generator, commit, ValueCommitmentRandomness};
    use crate::NoteCommitment;
    use adamant_crypto::domain;
    use adamant_crypto::hash::sha3_256_tagged;
    use adamant_halo2::proofs::circuit::Value;
    use adamant_halo2::proofs::pasta::pallas;
    use adamant_types::TypeId;
    use pasta_curves::group::ff::PrimeField;
    use pasta_curves::group::Curve;
    use rand::rngs::OsRng;

    type TestCircuit = ValidityCircuit<4, 1, 1>;
    type TestKeys = ValidityKeySet<4, 1, 1>;

    fn fb_to_base(fb: FieldBytes) -> pallas::Base {
        pallas::Base::from_repr(fb.to_bytes())
            .expect("FieldBytes invariant: bytes encode a valid field element")
    }

    fn dt_field(tag: &domain::DomainTag) -> pallas::Base {
        let bytes = sha3_256_tagged(tag, b"");
        fb_to_base(FieldBytes::from_bytes_reduced(bytes))
    }

    fn recompute_root(
        leaf: pallas::Base,
        siblings: &[pallas::Base],
        bits: &[bool],
    ) -> pallas::Base {
        let mut current = leaf;
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
        current
    }

    /// Build a deterministic 1-input + 1-output transaction
    /// shape for prove/verify round-tripping. Same shape as
    /// `circuit::validity::tests::fixed_setup_1x1`, copied to
    /// keep the test module self-contained.
    fn fixed_setup_1x1() -> (TestCircuit, ValidityPublicInputs, ValidityDomainTags) {
        let value_in_u64 = 1_000u64;
        let asset_in = TypeId::from_bytes([0x01; 32]);
        let recipient_in = FieldBytes::from_bytes_reduced([0x10; 32]);
        let randomness_in = FieldBytes::from_bytes_reduced([0x11; 32]);
        let meta_in = FieldBytes::from_bytes_reduced([0x12; 32]);
        let value_in_fb =
            FieldBytes::from_bytes_reduced(pallas::Base::from(value_in_u64).to_repr());
        let cm_in_fb = poseidon_hash::<5>([
            value_in_fb,
            FieldBytes::from_bytes_reduced(asset_in.to_bytes()),
            recipient_in,
            randomness_in,
            meta_in,
        ]);
        let cm_in = fb_to_base(cm_in_fb);

        let sk_bytes = [0x44; 32];
        let position_u64 = 5u64;
        let siblings = [
            fb_to_base(FieldBytes::from_bytes_reduced([0x21; 32])),
            fb_to_base(FieldBytes::from_bytes_reduced([0x22; 32])),
            fb_to_base(FieldBytes::from_bytes_reduced([0x23; 32])),
            fb_to_base(FieldBytes::from_bytes_reduced([0x24; 32])),
        ];
        let bits = [true, false, true, false];
        let gnct_root = recompute_root(cm_in, &siblings, &bits);

        let sk_obj = SpendingKey::from_bytes(sk_bytes);
        let nk = derive_nullifier_key(&sk_obj);
        let cm_in_obj = NoteCommitment::from_bytes(cm_in_fb.to_bytes());
        let nullifier = derive_nullifier(&nk, &cm_in_obj, LeafPosition(position_u64));
        let nullifier_base = pallas::Base::from_repr(nullifier.to_bytes()).unwrap();

        let value_in_bits_w = u64_to_bit_witnesses(value_in_u64);
        let v_tau_in = asset_value_generator(asset_in).to_affine();
        let r_in = ValueCommitmentRandomness::from_uniform_bytes(&[0x55; 64]);
        let r_in_scalar = pallas::Scalar::from_repr(r_in.to_bytes()).unwrap();
        let vc_in_obj = commit(value_in_u64, asset_in, &r_in);
        let vc_in_point = vc_in_obj.to_point().unwrap();
        let vc_in_coords =
            pasta_curves::arithmetic::CurveAffine::coordinates(&vc_in_point).unwrap();

        let value_out_u64 = 1_000u64;
        let asset_out = TypeId::from_bytes([0x01; 32]);
        let recipient_out = FieldBytes::from_bytes_reduced([0x30; 32]);
        let randomness_out = FieldBytes::from_bytes_reduced([0x31; 32]);
        let meta_out = FieldBytes::from_bytes_reduced([0x32; 32]);
        let value_out_fb =
            FieldBytes::from_bytes_reduced(pallas::Base::from(value_out_u64).to_repr());
        let cm_out_fb = poseidon_hash::<5>([
            value_out_fb,
            FieldBytes::from_bytes_reduced(asset_out.to_bytes()),
            recipient_out,
            randomness_out,
            meta_out,
        ]);
        let cm_out = fb_to_base(cm_out_fb);

        let value_out_bits_w = u64_to_bit_witnesses(value_out_u64);
        let v_tau_out = asset_value_generator(asset_out).to_affine();
        let r_out = ValueCommitmentRandomness::from_uniform_bytes(&[0x66; 64]);
        let r_out_scalar = pallas::Scalar::from_repr(r_out.to_bytes()).unwrap();
        let vc_out_obj = commit(value_out_u64, asset_out, &r_out);
        let vc_out_point = vc_out_obj.to_point().unwrap();
        let vc_out_coords =
            pasta_curves::arithmetic::CurveAffine::coordinates(&vc_out_point).unwrap();

        let input = InputNoteWitness {
            value: value_in_bits_w.value,
            asset_type: Value::known(fb_to_base(FieldBytes::from_bytes_reduced(
                asset_in.to_bytes(),
            ))),
            recipient: Value::known(fb_to_base(recipient_in)),
            randomness: Value::known(fb_to_base(randomness_in)),
            metadata_hash: Value::known(fb_to_base(meta_in)),
            spending_key: Value::known(fb_to_base(FieldBytes::from_bytes_reduced(sk_bytes))),
            position: Value::known(pallas::Base::from(position_u64)),
            path_siblings: siblings.map(Value::known),
            path_bits: bits.map(Value::known),
            value_bits: value_in_bits_w.bits,
            value_generator: Value::known(v_tau_in),
            vc_randomness: Value::known(r_in_scalar),
        };
        let output = OutputNoteWitness {
            value: value_out_bits_w.value,
            asset_type: Value::known(fb_to_base(FieldBytes::from_bytes_reduced(
                asset_out.to_bytes(),
            ))),
            recipient: Value::known(fb_to_base(recipient_out)),
            randomness: Value::known(fb_to_base(randomness_out)),
            metadata_hash: Value::known(fb_to_base(meta_out)),
            value_bits: value_out_bits_w.bits,
            value_generator: Value::known(v_tau_out),
            vc_randomness: Value::known(r_out_scalar),
        };

        let witness = ValidityWitness::<4, 1, 1> {
            inputs: [input],
            outputs: [output],
        };
        let domain_tags = ValidityDomainTags {
            nullifier_key_inner: dt_field(&domain::NULLIFIER_KEY_DERIVATION),
            nullifier_outer: dt_field(&domain::NULLIFIER_HASH),
        };
        let circuit = TestCircuit::new(witness, domain_tags);

        let public = ValidityPublicInputs {
            gnct_root,
            nullifiers: vec![nullifier_base],
            output_commitments: vec![cm_out],
            vc_in: vec![(*vc_in_coords.x(), *vc_in_coords.y())],
            vc_out: vec![(*vc_out_coords.x(), *vc_out_coords.y())],
        };

        (circuit, public, domain_tags)
    }

    /// End-to-end keygen → prove → verify round-trip.
    #[test]
    fn prove_verify_round_trip() {
        let (circuit, public, dt) = fixed_setup_1x1();
        let keys = TestKeys::keygen(12, dt).expect("keygen succeeds");

        let proof = prove(&keys, circuit, &public, OsRng).expect("prove succeeds");

        // Proof should be non-empty (Halo 2 IPA proofs at K=12
        // are roughly 4-8 KiB).
        assert!(!proof.is_empty(), "proof should be non-empty");
        assert!(
            proof.len() >= 1024,
            "proof should be ≥ 1 KiB at K=12, was {}",
            proof.len()
        );

        verify(&keys, &public, &proof).expect("verify succeeds");
    }

    /// Verifier rejects a tampered nullifier in the public
    /// inputs (without re-proving).
    #[test]
    fn verify_rejects_tampered_public_inputs() {
        let (circuit, public, dt) = fixed_setup_1x1();
        let keys = TestKeys::keygen(12, dt).expect("keygen succeeds");

        let proof = prove(&keys, circuit, &public, OsRng).expect("prove succeeds");

        let mut tampered = public.clone();
        tampered.nullifiers[0] = pallas::Base::from(0xDEADu64);

        let err = verify(&keys, &tampered, &proof).expect_err("verify must reject");
        assert!(matches!(err, ProvingError::Plonk(_)));
    }

    /// Verifier rejects a corrupted proof byte stream.
    #[test]
    fn verify_rejects_corrupted_proof() {
        let (circuit, public, dt) = fixed_setup_1x1();
        let keys = TestKeys::keygen(12, dt).expect("keygen succeeds");

        let mut proof = prove(&keys, circuit, &public, OsRng).expect("prove succeeds");

        // Flip the first byte.
        proof[0] ^= 0x01;

        let err = verify(&keys, &public, &proof).expect_err("verify must reject");
        assert!(matches!(err, ProvingError::Plonk(_)));
    }

    /// Arity-mismatch surfaces as a typed error, not a panic.
    #[test]
    fn arity_mismatch_is_typed_error() {
        let (circuit, mut public, dt) = fixed_setup_1x1();
        let keys = TestKeys::keygen(12, dt).expect("keygen succeeds");

        // Push an extra nullifier so arity goes 1→2 and check
        // breaks before we ever call into halo2.
        public.nullifiers.push(pallas::Base::from(0u64));

        let err = prove(&keys, circuit, &public, OsRng).expect_err("arity check must reject");
        assert!(
            matches!(err, ProvingError::ArityMismatch(_)),
            "expected ArityMismatch, got {err:?}"
        );
    }

    /// Verifying-key access via `keys.vk()` returns the same
    /// VK as `keys.pk.get_vk()`. (Pin the accessor surface.)
    #[test]
    fn vk_accessor_matches_proving_key() {
        let dt = ValidityDomainTags {
            nullifier_key_inner: pallas::Base::from(1u64),
            nullifier_outer: pallas::Base::from(2u64),
        };
        let keys = TestKeys::keygen(12, dt).expect("keygen succeeds");
        // Pointer identity check: vk() returns &pk.vk.
        let a: *const VerifyingKey<CommitmentCurve> = keys.vk();
        let b: *const VerifyingKey<CommitmentCurve> = keys.pk.get_vk();
        assert_eq!(a, b);
    }
}
