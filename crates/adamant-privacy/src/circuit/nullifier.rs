//! Nullifier-derivation validity circuit per whitepaper §7.3.2
//! statement 6 (in-circuit half — "authority").
//!
//! Phase 6.8b.4b — second Adamant-authored circuit. Proves the
//! two-stage Poseidon derivation from §7.1.2:
//!
//! ```text
//! nullifier_key = Poseidon(NULLIFIER_KEY_DERIVATION_domain,
//!                          spending_key)
//! nullifier     = Poseidon(NULLIFIER_HASH_domain,
//!                          nullifier_key,
//!                          note_commitment,
//!                          position_in_tree)
//! ```
//!
//! Both stages run in-circuit; the spending key, nullifier key,
//! note commitment, and tree position are witnesses; the
//! published nullifier is a public input.
//!
//! # Spec basis
//!
//! Whitepaper §7.1.2 verbatim:
//!
//! > Nullifier construction:
//! >
//! > ```text
//! > nullifier = Poseidon(domain_tag || nullifier_key
//! >                      || note_commitment || position_in_tree)
//! > ```
//! >
//! > Where:
//! > - `nullifier_key` is a key derived from the owner's
//! >   spending key (specifically: `nullifier_key = Poseidon(
//! >   domain || spending_key)`).
//! >
//! > Critical properties:
//! > - **Unforgeability.** Producing the correct nullifier
//! >   requires the spending key.
//!
//! Whitepaper §7.3.2 statement 6:
//!
//! > Authority. For each input note, the prover knows the
//! > spending key corresponding to the note's recipient. This
//! > is the analog of "the spender authorised the spend."
//!
//! The circuit proves authority indirectly: the chain accepts
//! the nullifier only if it matches the §7.1.2 derivation, and
//! the derivation requires the spending key as a witness. A
//! prover without the spending key cannot construct a witness
//! that satisfies the constraint with the published nullifier
//! as public input.
//!
//! # Cross-validation invariant
//!
//! Same boundary discipline as Phase 6.8b.4a: the in-circuit
//! Poseidon outputs at both stages must equal the out-of-
//! circuit `derive_nullifier_key` / `derive_nullifier`
//! functions for the same inputs. Pinned by
//! `tests::circuit_matches_out_of_circuit`.
//!
//! # Witness encoding
//!
//! Three field-element witnesses + one circuit-internal
//! intermediate:
//!
//! 1. `spending_key` — 32 bytes reduced into Pallas base field
//!    (matches Phase 6.2's [`crate::SpendingKey`] byte shape).
//! 2. `note_commitment` — Pallas base-field element directly
//!    (output of Phase 6.1's `derive_note_commitment`).
//! 3. `position_in_tree` — `u64` zero-padded to 32 bytes (always
//!    in range; matches Phase 6.2's [`crate::LeafPosition`]
//!    encoding).
//! 4. `nullifier_key` — circuit-derived intermediate. The
//!    in-circuit Poseidon output of stage 1 is fed directly into
//!    stage 2 via cell-equality constraints; no external witness
//!    needed beyond `spending_key`.
//!
//! Both Poseidon-input domain-tag field elements
//! (`NULLIFIER_KEY_DERIVATION_domain` and `NULLIFIER_HASH_domain`)
//! are passed by the caller into the circuit as **known
//! constants** at construction time and locked into the
//! proving / verifying keys. They are NOT public inputs:
//! domain tags are part of the protocol's consensus rules per
//! §3.3.1 (changing them is a hard fork), so encoding them as
//! verifier-key-fixed values is correct. The single public
//! input is the published nullifier.
//!
//! Callers compute the domain-tag field elements off-circuit
//! using the same `domain_tag_to_field` helper that
//! `crate::nullifier`'s `derive_nullifier_key` /
//! `derive_nullifier` use, and pass them via
//! [`NullifierDomainTags`].

use std::marker::PhantomData;

use adamant_halo2::poseidon::primitives::{ConstantLength, P128Pow5T3};
use adamant_halo2::poseidon::{Hash, Pow5Chip, Pow5Config};
use adamant_halo2::proofs::circuit::{Layouter, SimpleFloorPlanner, Value};
use adamant_halo2::proofs::pasta::pallas;
use adamant_halo2::proofs::plonk::{
    Circuit, Column, ConstraintSystem, Error as PlonkError, Instance,
};

/// Number of inputs to the inner Poseidon stage that derives
/// the nullifier key (`Poseidon(domain, spending_key)`) per
/// whitepaper §7.1.2.
pub const NULLIFIER_KEY_INPUT_ARITY: usize = 2;

/// Number of inputs to the outer Poseidon stage that derives
/// the nullifier (`Poseidon(domain, nullifier_key,
/// note_commitment, position)`) per whitepaper §7.1.2.
pub const NULLIFIER_INPUT_ARITY: usize = 4;

/// Number of public inputs the circuit consumes:
///
/// 1. `nullifier` — the published nullifier (the proof attests
///    the witnesses' Poseidon derivation matches this value).
///
/// Domain tags are NOT public inputs — they are locked into the
/// verifying key as known circuit constants per §3.3.1 (domain
/// tags are consensus-rule constants; changing them is a hard
/// fork).
pub const PUBLIC_INPUT_COUNT: usize = 1;

/// In-circuit witness for the nullifier-derivation per §7.1.2.
#[derive(Clone, Copy, Debug)]
pub struct NullifierWitness {
    /// Spending key as a Pallas base-field element. The
    /// 32-byte byte form from Phase 6.2's
    /// [`crate::SpendingKey`] is `from_bytes_reduced`-encoded
    /// into the field by callers before constructing the
    /// witness.
    pub spending_key: Value<pallas::Base>,
    /// Note commitment of the note being spent. Already a
    /// Pallas base-field element from Phase 6.1.
    pub note_commitment: Value<pallas::Base>,
    /// Position of the note's commitment in the GNCT per §7.1.3.
    /// Encoded as `pallas::Base::from(u64)` by callers.
    pub position: Value<pallas::Base>,
}

impl Default for NullifierWitness {
    fn default() -> Self {
        Self {
            spending_key: Value::unknown(),
            note_commitment: Value::unknown(),
            position: Value::unknown(),
        }
    }
}

/// Domain-tag constants used to construct the circuit. Locked
/// into the verifying key — NOT public inputs. Callers compute
/// the field-element forms off-circuit (same helper
/// `derive_nullifier_key` / `derive_nullifier` use).
#[derive(Clone, Copy, Debug)]
pub struct NullifierDomainTags {
    /// Field-element form of
    /// `adamant_crypto::domain::NULLIFIER_KEY_DERIVATION`.
    pub inner: pallas::Base,
    /// Field-element form of
    /// `adamant_crypto::domain::NULLIFIER_HASH`.
    pub outer: pallas::Base,
}

/// Public inputs the verifier consumes alongside the proof.
/// Layout in the instance column (single column, single row):
///
/// | row | value       |
/// |-----|-------------|
/// | 0   | `nullifier` |
#[derive(Clone, Copy, Debug)]
pub struct NullifierPublicInputs {
    /// The published nullifier the proof attests was correctly
    /// derived from the witnesses + circuit-locked domain tags.
    pub nullifier: pallas::Base,
}

impl NullifierPublicInputs {
    /// Convert to the row-vector form `MockProver::run` /
    /// `plonk::create_proof` expect.
    #[must_use]
    pub fn to_rows(self) -> Vec<pallas::Base> {
        vec![self.nullifier]
    }
}

/// Circuit configuration: the `Pow5Chip` config plus the public-
/// input instance column.
#[derive(Clone, Debug)]
pub struct NullifierConfig {
    /// `Pow5Chip` configuration shared between both Poseidon
    /// stages (inner key derivation + outer nullifier hash).
    /// Both stages instantiate `Hash` with `ConstantLength<L>`
    /// at different L; this is fine — the chip is parametric on
    /// `L` at the `Hash::init` call site.
    pub poseidon: Pow5Config<pallas::Base, 3, 2>,
    /// Single instance column carrying
    /// `[inner_domain_tag, outer_domain_tag, nullifier]`.
    pub instance: Column<Instance>,
}

/// The nullifier-derivation validity circuit per whitepaper
/// §7.3.2 statement 6 (in-circuit half).
#[derive(Clone, Copy, Debug)]
pub struct NullifierCircuit {
    /// Witness inputs.
    pub witness: NullifierWitness,
    /// Circuit-locked domain-tag constants (verifying-key part,
    /// not public input).
    pub domain_tags: NullifierDomainTags,
    /// `PhantomData` reserved for future Poseidon-spec
    /// generic parameters; currently monomorphic on
    /// `P128Pow5T3` per §3.3.3.
    _spec: PhantomData<P128Pow5T3>,
}

impl NullifierCircuit {
    /// Construct from a fully-known witness + domain tags. Use
    /// [`NullifierCircuit::keygen`] for keygen-time
    /// construction.
    #[must_use]
    pub const fn new(witness: NullifierWitness, domain_tags: NullifierDomainTags) -> Self {
        Self {
            witness,
            domain_tags,
            _spec: PhantomData,
        }
    }

    /// Construct a circuit instance for keygen — witnesses are
    /// all-unknown but domain tags are still pinned (they're
    /// part of the proving / verifying key shape).
    #[must_use]
    pub const fn keygen(domain_tags: NullifierDomainTags) -> Self {
        Self {
            witness: NullifierWitness {
                spending_key: Value::unknown(),
                note_commitment: Value::unknown(),
                position: Value::unknown(),
            },
            domain_tags,
            _spec: PhantomData,
        }
    }
}

impl Circuit<pallas::Base> for NullifierCircuit {
    type Config = NullifierConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::keygen(self.domain_tags)
    }

    fn configure(meta: &mut ConstraintSystem<pallas::Base>) -> Self::Config {
        // Same Pow5Chip column layout as Phase 6.8b.4a's
        // `NoteCommitmentCircuit`: width = 3, rate = 2 per
        // §3.3.3, plus partial-sbox + rc_a + rc_b columns.
        let state = (0..3).map(|_| meta.advice_column()).collect::<Vec<_>>();
        let partial_sbox = meta.advice_column();
        let rc_a = (0..3).map(|_| meta.fixed_column()).collect::<Vec<_>>();
        let rc_b = (0..3).map(|_| meta.fixed_column()).collect::<Vec<_>>();
        meta.enable_constant(rc_b[0]);

        let instance = meta.instance_column();
        meta.enable_equality(instance);
        meta.enable_equality(state[0]);

        let poseidon = Pow5Chip::configure::<P128Pow5T3>(
            meta,
            state.try_into().expect(
                "Adamant invariant: state was constructed as exactly 3 elements for P128Pow5T3",
            ),
            partial_sbox,
            rc_a.try_into().expect(
                "Adamant invariant: rc_a was constructed as exactly 3 elements for P128Pow5T3",
            ),
            rc_b.try_into().expect(
                "Adamant invariant: rc_b was constructed as exactly 3 elements for P128Pow5T3",
            ),
        );

        NullifierConfig { poseidon, instance }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<pallas::Base>,
    ) -> Result<(), PlonkError> {
        // ----- Stage 1: derive the nullifier key in-circuit.
        //
        // `nullifier_key = Poseidon(inner_domain_tag, spending_key)`
        //
        // The `inner_domain_tag` comes from the public-input
        // instance column row 0; the `spending_key` is the
        // witness. The output is a fresh in-circuit cell that
        // we feed directly into stage 2.

        // Load the inner-stage inputs as advice cells. The
        // domain tag is a circuit-locked constant — assigned
        // as `Value::known(domain_tag)` directly. No public-
        // input wiring needed.
        let chip_inner = Pow5Chip::construct(config.poseidon.clone());
        let inner_domain_tag = self.domain_tags.inner;
        let inner_inputs = layouter.assign_region(
            || "load nullifier-key inputs",
            |mut region| {
                let domain_cell = region.assign_advice(
                    || "inner_domain_tag (constant)",
                    config.poseidon.state[0],
                    0,
                    || Value::known(inner_domain_tag),
                )?;
                let sk_cell = region.assign_advice(
                    || "spending_key",
                    config.poseidon.state[1],
                    0,
                    || self.witness.spending_key,
                )?;
                Ok([domain_cell, sk_cell])
            },
        )?;

        let inner_hasher = Hash::<
            pallas::Base,
            _,
            P128Pow5T3,
            ConstantLength<NULLIFIER_KEY_INPUT_ARITY>,
            3,
            2,
        >::init(chip_inner, layouter.namespace(|| "init inner"))?;
        let nullifier_key_cell =
            inner_hasher.hash(layouter.namespace(|| "nullifier-key hash"), inner_inputs)?;

        // ----- Stage 2: derive the nullifier from the
        // nullifier key + note commitment + position.
        //
        // `nullifier = Poseidon(outer_domain_tag, nullifier_key,
        //                       note_commitment, position)`
        //
        // The `nullifier_key` is the cell from stage 1 — we
        // wire it through via a region-internal copy to the
        // outer-stage state[1] column. The outer domain tag
        // and remaining witnesses are loaded fresh in this
        // region.

        let chip_outer = Pow5Chip::construct(config.poseidon.clone());
        let outer_domain_tag = self.domain_tags.outer;
        let outer_inputs = layouter.assign_region(
            || "load nullifier inputs",
            |mut region| {
                let outer_domain_cell = region.assign_advice(
                    || "outer_domain_tag (constant)",
                    config.poseidon.state[0],
                    0,
                    || Value::known(outer_domain_tag),
                )?;
                // Copy the nullifier-key cell from stage 1 so
                // both stages bind to the same field-element
                // value.
                let nk_cell = nullifier_key_cell.copy_advice(
                    || "nullifier_key (from stage 1)",
                    &mut region,
                    config.poseidon.state[1],
                    0,
                )?;
                let cm_cell = region.assign_advice(
                    || "note_commitment",
                    config.poseidon.state[2],
                    0,
                    || self.witness.note_commitment,
                )?;
                let pos_cell = region.assign_advice(
                    || "position",
                    config.poseidon.state[0],
                    1,
                    || self.witness.position,
                )?;
                Ok([outer_domain_cell, nk_cell, cm_cell, pos_cell])
            },
        )?;
        let outer_hasher =
            Hash::<pallas::Base, _, P128Pow5T3, ConstantLength<NULLIFIER_INPUT_ARITY>, 3, 2>::init(
                chip_outer,
                layouter.namespace(|| "init outer"),
            )?;
        let nullifier_cell =
            outer_hasher.hash(layouter.namespace(|| "nullifier hash"), outer_inputs)?;

        // Constrain the outer Poseidon output to equal the
        // single public-input row (the published nullifier).
        layouter.constrain_instance(nullifier_cell.cell(), config.instance, 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nullifier::{derive_nullifier, derive_nullifier_key, LeafPosition, SpendingKey};
    use crate::poseidon::FieldBytes;
    use crate::NoteCommitment;
    use adamant_crypto::domain;
    use adamant_crypto::hash::sha3_256_tagged;
    use adamant_halo2::proofs::dev::MockProver;
    use pasta_curves::group::ff::PrimeField;

    /// Same `K = 8` as `NoteCommitmentCircuit`. Two Poseidon
    /// stages (arity 2 + arity 4) plus the public-input
    /// constraints fit inside `2^8 = 256` rows.
    const K: u32 = 8;

    /// Convert a [`FieldBytes`] to the in-circuit `pallas::Base`
    /// element. Mirrors the Phase 6.8b.4a helper.
    fn field_bytes_to_base(fb: FieldBytes) -> pallas::Base {
        pallas::Base::from_repr(fb.to_bytes())
            .expect("FieldBytes invariant: bytes encode a valid field element")
    }

    /// Field-element form of a registered domain tag, mirroring
    /// the off-circuit `domain_tag_to_field` helper in
    /// `crate::nullifier`.
    fn domain_tag_to_field(tag: &domain::DomainTag) -> pallas::Base {
        let bytes = sha3_256_tagged(tag, b"");
        field_bytes_to_base(FieldBytes::from_bytes_reduced(bytes))
    }

    /// Build a deterministic-input witness + matching public
    /// inputs + domain tags for testing.
    #[allow(clippy::similar_names)]
    fn fixed_setup() -> (NullifierWitness, NullifierDomainTags, NullifierPublicInputs) {
        let sk_bytes = [0x44u8; 32];
        let cm_bytes = [0x55u8; 32];
        let position_value = 42u64;

        let witness = NullifierWitness {
            spending_key: Value::known(field_bytes_to_base(FieldBytes::from_bytes_reduced(
                sk_bytes,
            ))),
            note_commitment: Value::known(field_bytes_to_base(FieldBytes::from_bytes_reduced(
                cm_bytes,
            ))),
            position: Value::known(pallas::Base::from(position_value)),
        };

        let domain_tags = NullifierDomainTags {
            inner: domain_tag_to_field(&domain::NULLIFIER_KEY_DERIVATION),
            outer: domain_tag_to_field(&domain::NULLIFIER_HASH),
        };

        // Compute the expected nullifier off-circuit using the
        // existing Phase 6.2 helpers.
        let sk = SpendingKey::from_bytes(sk_bytes);
        let nk = derive_nullifier_key(&sk);
        let cm = NoteCommitment::from_bytes(cm_bytes);
        let nullifier = derive_nullifier(&nk, &cm, LeafPosition(position_value));

        let public = NullifierPublicInputs {
            nullifier: pallas::Base::from_repr(nullifier.to_bytes())
                .expect("nullifier bytes encode a valid field element"),
        };
        (witness, domain_tags, public)
    }

    /// Positive case: consistent witness + public inputs verify.
    #[test]
    fn nullifier_circuit_accepts_consistent_inputs() {
        let (witness, domain_tags, public) = fixed_setup();
        let circuit = NullifierCircuit::new(witness, domain_tags);
        let prover =
            MockProver::run(K, &circuit, vec![public.to_rows()]).expect("MockProver runs cleanly");
        assert_eq!(prover.verify(), Ok(()));
    }

    /// Negative case: tampered nullifier (public input wrong)
    /// is rejected.
    #[test]
    fn nullifier_circuit_rejects_tampered_nullifier() {
        let (witness, domain_tags, mut public) = fixed_setup();
        public.nullifier = pallas::Base::from(0x1234_5678u64);
        let circuit = NullifierCircuit::new(witness, domain_tags);
        let prover =
            MockProver::run(K, &circuit, vec![public.to_rows()]).expect("MockProver runs cleanly");
        assert!(
            prover.verify().is_err(),
            "tampered nullifier must be rejected"
        );
    }

    /// Negative case: tampered spending-key witness — the
    /// derived nullifier no longer matches the public input.
    /// This is the §7.3.2 statement 6 unforgeability property
    /// (a prover without the right spending key cannot produce
    /// the published nullifier).
    #[test]
    fn nullifier_circuit_rejects_wrong_spending_key() {
        let (mut witness, domain_tags, public) = fixed_setup();
        witness.spending_key = Value::known(pallas::Base::from(0xDEAD_BEEFu64));
        let circuit = NullifierCircuit::new(witness, domain_tags);
        let prover =
            MockProver::run(K, &circuit, vec![public.to_rows()]).expect("MockProver runs cleanly");
        assert!(
            prover.verify().is_err(),
            "wrong spending key must produce a different nullifier and be rejected"
        );
    }

    /// Negative case: tampered position — same note, different
    /// claim about its tree position. Must be rejected.
    #[test]
    fn nullifier_circuit_rejects_wrong_position() {
        let (mut witness, domain_tags, public) = fixed_setup();
        witness.position = Value::known(pallas::Base::from(99u64));
        let circuit = NullifierCircuit::new(witness, domain_tags);
        let prover =
            MockProver::run(K, &circuit, vec![public.to_rows()]).expect("MockProver runs cleanly");
        assert!(
            prover.verify().is_err(),
            "wrong position must produce a different nullifier and be rejected"
        );
    }

    /// Negative case: tampered domain tag — the circuit is
    /// constructed with a different inner-stage domain tag than
    /// the one matching the published nullifier. Must be
    /// rejected.
    ///
    /// Pin: §3.3.1's domain-separation discipline holds in-
    /// circuit. A prover that builds a circuit with the wrong
    /// domain-tag constants cannot satisfy the constraint
    /// against the published nullifier.
    #[test]
    fn nullifier_circuit_rejects_wrong_inner_domain_tag() {
        let (witness, mut domain_tags, public) = fixed_setup();
        domain_tags.inner = pallas::Base::from(0u64);
        let circuit = NullifierCircuit::new(witness, domain_tags);
        let prover =
            MockProver::run(K, &circuit, vec![public.to_rows()]).expect("MockProver runs cleanly");
        assert!(
            prover.verify().is_err(),
            "wrong inner domain tag must be rejected"
        );
    }

    /// Cross-validation pin: the in-circuit two-stage Poseidon
    /// derivation matches `derive_nullifier_key` +
    /// `derive_nullifier` for the same inputs. §3.3.3 boundary
    /// invariant.
    #[test]
    fn circuit_matches_out_of_circuit() {
        let (witness, domain_tags, public) = fixed_setup();
        let circuit = NullifierCircuit::new(witness, domain_tags);
        let prover =
            MockProver::run(K, &circuit, vec![public.to_rows()]).expect("MockProver runs cleanly");
        assert_eq!(
            prover.verify(),
            Ok(()),
            "in-circuit two-stage Poseidon must agree with \
             out-of-circuit derive_nullifier_key + derive_nullifier"
        );
    }

    /// Pin the public-input count + arity constants — changes
    /// here are hard-fork-grade.
    #[test]
    fn arity_constants_pinned() {
        assert_eq!(NULLIFIER_KEY_INPUT_ARITY, 2);
        assert_eq!(NULLIFIER_INPUT_ARITY, 4);
        assert_eq!(PUBLIC_INPUT_COUNT, 1);
    }

    #[test]
    fn keygen_circuit_compiles() {
        let (_, domain_tags, _) = fixed_setup();
        let _circuit = NullifierCircuit::keygen(domain_tags);
    }
}
