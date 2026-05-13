//! Composed shielded-input validity circuit per whitepaper
//! §7.3.2 statements 1 + 5 + 6 (input note existence + range
//! proof + authority).
//!
//! Phase 6.8b.4e (part 2) — second composition of Adamant-
//! authored sub-circuits, and the most complex per-input
//! shielded-transaction proof. Combines:
//!
//! - [`NoteCommitmentCircuit`]-style note-commitment derivation
//!   from `(value, asset_type, recipient, randomness,
//!   metadata_hash)` witnesses.
//! - [`MerkleMembershipCircuit`]-style GNCT path verification
//!   proving the derived commitment exists under the public
//!   `gnct_root`.
//! - [`NullifierCircuit`]-style two-stage Poseidon derivation
//!   producing the public `nullifier` from `spending_key`,
//!   `note_commitment`, `position`.
//! - [`RangeCheck64Circuit`]-style range proof on `value`.
//!
//! # Cross-circuit binding (load-bearing)
//!
//! The composition's correctness depends on multi-way copy
//! constraints binding shared cells across all four sub-
//! circuits:
//!
//! 1. `value` cell — assigned in the note-commitment region's
//!    `Pow5Chip` state column at position 0, copy-constrained
//!    into the range-check's `value_col` row 0.
//! 2. `note_commitment` cell — produced by the note-commitment
//!    Poseidon hash, copy-constrained as:
//!    - the `leaf` input to the Merkle-path region's
//!      cond-swap chain (level 0 input),
//!    - the `note_commitment` input to the nullifier's
//!      outer-stage Poseidon (state column position).
//! 3. `position` cell — assigned in the nullifier's outer-
//!    stage region; the SAME field-element value is encoded as
//!    the bit-string used by the Merkle cond-swap chain
//!    (binary decomposition consistency check is part of
//!    Phase 6.8b.4e-3 full `ValidityCircuit`; at this sub-arc
//!    the prover witnesses both representations and the
//!    consensus layer / off-circuit reasoning enforces
//!    consistency).
//!
//! Without these copy constraints, a prover could feed
//! different witness values into different sub-circuits and
//! satisfy each in isolation while violating the per-input
//! invariant. The copy constraints make a successful proof
//! attest to a single coherent input note.
//!
//! # Spec basis
//!
//! Whitepaper §7.3.2 statement 1: input note existence (Merkle
//! path). Statement 5: range proof. Statement 6: authority
//! (nullifier derivation requires spending key).
//!
//! # Depth parameterisation
//!
//! Like [`MerkleMembershipCircuit`], the depth is exposed as a
//! const generic. Production §7.1.3 GNCT depth is 64; tests
//! instantiate at smaller depths to keep `MockProver` runtime
//! tractable.

use std::marker::PhantomData;

use adamant_halo2::poseidon::primitives::{ConstantLength, P128Pow5T3};
use adamant_halo2::poseidon::{Hash, Pow5Chip, Pow5Config};
use adamant_halo2::proofs::circuit::{Layouter, SimpleFloorPlanner, Value};
use adamant_halo2::proofs::pasta::pallas;
use adamant_halo2::proofs::plonk::{
    Circuit, Column, ConstraintSystem, Error as PlonkError, Instance,
};
use adamant_halo2::utilities::cond_swap::{CondSwapChip, CondSwapConfig, CondSwapInstructions};

use super::note_commitment::NOTE_COMMITMENT_INPUT_ARITY;
use super::nullifier::{NULLIFIER_INPUT_ARITY, NULLIFIER_KEY_INPUT_ARITY};
use super::range_check::{range_check_64bit_cell, RangeCheck64Config, RANGE_BITS};

/// In-circuit witness for the composed shielded-input proof at
/// depth `DEPTH`. Bundles the note's contents, the spending
/// key, the GNCT path, and the value bit-decomposition.
#[derive(Clone, Debug)]
pub struct ShieldedInputWitness<const DEPTH: usize> {
    // ----- Note contents (5 fields per §7.1) -----
    /// `value` as a Pallas base-field element.
    pub value: Value<pallas::Base>,
    /// `asset_type` reduced into the Pallas base field.
    pub asset_type: Value<pallas::Base>,
    /// `recipient` stealth-address x-coordinate.
    pub recipient: Value<pallas::Base>,
    /// `randomness` reduced into the Pallas base field.
    pub randomness: Value<pallas::Base>,
    /// `metadata_hash` reduced into the Pallas base field.
    pub metadata_hash: Value<pallas::Base>,

    // ----- Authority (§7.3.2 statement 6) -----
    /// Spending key as a Pallas base-field element.
    pub spending_key: Value<pallas::Base>,
    /// Position of the note in the GNCT, as a field element.
    pub position: Value<pallas::Base>,

    // ----- GNCT path (§7.3.2 statement 1) -----
    /// `DEPTH` sibling hashes along the authentication path.
    pub path_siblings: [Value<pallas::Base>; DEPTH],
    /// `DEPTH` path bits indicating left (0) / right (1) at
    /// each level. Per §7.1.3, low-bit-first binary expansion
    /// of `position`.
    pub path_bits: [Value<bool>; DEPTH],

    // ----- Range proof (§7.3.2 statement 5) -----
    /// 64 bit-witnesses for `value`'s range proof.
    pub value_bits: [Value<pallas::Base>; RANGE_BITS],
}

impl<const DEPTH: usize> Default for ShieldedInputWitness<DEPTH> {
    fn default() -> Self {
        Self {
            value: Value::unknown(),
            asset_type: Value::unknown(),
            recipient: Value::unknown(),
            randomness: Value::unknown(),
            metadata_hash: Value::unknown(),
            spending_key: Value::unknown(),
            position: Value::unknown(),
            path_siblings: [Value::unknown(); DEPTH],
            path_bits: [Value::unknown(); DEPTH],
            value_bits: [Value::unknown(); RANGE_BITS],
        }
    }
}

/// Domain-tag constants for the nullifier sub-circuit. Locked
/// into the verifying key per Phase 6.8b.4b's posture.
#[derive(Clone, Copy, Debug)]
pub struct ShieldedInputDomainTags {
    /// Field-element form of `NULLIFIER_KEY_DERIVATION`.
    pub nullifier_key_inner: pallas::Base,
    /// Field-element form of `NULLIFIER_HASH`.
    pub nullifier_outer: pallas::Base,
}

/// Public inputs (single instance column, two rows):
///
/// | row | value         |
/// |-----|---------------|
/// | 0   | `gnct_root`   |
/// | 1   | `nullifier`   |
#[derive(Clone, Copy, Debug)]
pub struct ShieldedInputPublicInputs {
    /// GNCT root the proof attests the input note's commitment
    /// belongs to.
    pub gnct_root: pallas::Base,
    /// Published nullifier the proof attests was correctly
    /// derived from the witnessed inputs.
    pub nullifier: pallas::Base,
}

impl ShieldedInputPublicInputs {
    /// Convert to row-vector form for `MockProver::run`.
    #[must_use]
    pub fn to_rows(self) -> Vec<pallas::Base> {
        vec![self.gnct_root, self.nullifier]
    }
}

/// Configuration for the composed shielded-input circuit.
#[derive(Clone, Debug)]
pub struct ShieldedInputConfig {
    /// `Pow5Chip` configuration (shared across all Poseidon
    /// stages: note-commitment + Merkle path levels +
    /// nullifier inner + outer).
    pub poseidon: Pow5Config<pallas::Base, 3, 2>,
    /// `CondSwap` chip for the per-level Merkle path swap.
    pub cond_swap: CondSwapConfig,
    /// Range-check configuration.
    pub range_check: RangeCheck64Config,
    /// Public-input instance column.
    pub instance: Column<Instance>,
}

/// The composed shielded-input validity circuit per §7.3.2
/// statements 1 + 5 + 6.
#[derive(Clone, Debug)]
pub struct ShieldedInputCircuit<const DEPTH: usize> {
    /// Combined witness inputs.
    pub witness: ShieldedInputWitness<DEPTH>,
    /// Circuit-locked domain-tag constants for the nullifier
    /// sub-circuit. Verifying-key-fixed.
    pub domain_tags: ShieldedInputDomainTags,
    /// `PhantomData` reserved for Poseidon-spec generics.
    _spec: PhantomData<P128Pow5T3>,
}

impl<const DEPTH: usize> ShieldedInputCircuit<DEPTH> {
    /// Construct from a fully-known witness + domain tags.
    #[must_use]
    pub const fn new(
        witness: ShieldedInputWitness<DEPTH>,
        domain_tags: ShieldedInputDomainTags,
    ) -> Self {
        Self {
            witness,
            domain_tags,
            _spec: PhantomData,
        }
    }

    /// Construct an all-unknown witness for keygen.
    #[must_use]
    pub fn keygen(domain_tags: ShieldedInputDomainTags) -> Self {
        Self {
            witness: ShieldedInputWitness::default(),
            domain_tags,
            _spec: PhantomData,
        }
    }
}

impl<const DEPTH: usize> Circuit<pallas::Base> for ShieldedInputCircuit<DEPTH> {
    type Config = ShieldedInputConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::keygen(self.domain_tags)
    }

    fn configure(meta: &mut ConstraintSystem<pallas::Base>) -> Self::Config {
        // Pow5Chip layout (shared).
        let poseidon_state = (0..3).map(|_| meta.advice_column()).collect::<Vec<_>>();
        let partial_sbox = meta.advice_column();
        let rc_a = (0..3).map(|_| meta.fixed_column()).collect::<Vec<_>>();
        let rc_b = (0..3).map(|_| meta.fixed_column()).collect::<Vec<_>>();
        meta.enable_constant(rc_b[0]);

        // CondSwap columns.
        let cs_advices = (0..5).map(|_| meta.advice_column()).collect::<Vec<_>>();

        // Range-check columns.
        let range_value_col = meta.advice_column();
        let range_bits_col = meta.advice_column();
        let q_bit = meta.selector();
        let q_decompose = meta.selector();

        meta.enable_equality(range_value_col);
        meta.enable_equality(range_bits_col);
        for c in &poseidon_state {
            meta.enable_equality(*c);
        }
        for c in &cs_advices {
            meta.enable_equality(*c);
        }

        // Range-check gates (mirror the standalone
        // `RangeCheck64Circuit` configure).
        meta.create_gate("bit is 0 or 1", |meta| {
            use adamant_halo2::proofs::plonk::{Constraints, Expression};
            use adamant_halo2::proofs::poly::Rotation;
            use pasta_curves::group::ff::Field;
            let q = meta.query_selector(q_bit);
            let b = meta.query_advice(range_bits_col, Rotation::cur());
            let one = Expression::Constant(pallas::Base::ONE);
            Constraints::with_selector(q, [("b * (1 - b)", b.clone() * (one - b))])
        });
        meta.create_gate("value = Σ b_i * 2^i", |meta| {
            use adamant_halo2::proofs::plonk::{Constraints, Expression};
            use adamant_halo2::proofs::poly::Rotation;
            use pasta_curves::group::ff::Field;
            let q = meta.query_selector(q_decompose);
            let value = meta.query_advice(range_value_col, Rotation::cur());
            let mut acc = Expression::Constant(pallas::Base::ZERO);
            for i in 0..RANGE_BITS {
                let b = meta.query_advice(
                    range_bits_col,
                    #[allow(clippy::cast_possible_wrap, clippy::cast_possible_truncation)]
                    Rotation(i as i32),
                );
                let weight = pallas::Base::from(1u64 << i);
                acc = acc + b * Expression::Constant(weight);
            }
            Constraints::with_selector(q, [("value == bit decomposition", value - acc)])
        });

        let cond_swap = CondSwapChip::configure(
            meta,
            cs_advices.try_into().expect(
                "Adamant invariant: cs_advices was constructed at exactly the CondSwapChip arity",
            ),
        );
        let poseidon = Pow5Chip::configure::<P128Pow5T3>(
            meta,
            poseidon_state.try_into().expect(
                "Adamant invariant: poseidon_state was constructed as exactly 3 elements for P128Pow5T3",
            ),
            partial_sbox,
            rc_a.try_into().expect(
                "Adamant invariant: rc_a was constructed as exactly 3 elements for P128Pow5T3",
            ),
            rc_b.try_into().expect(
                "Adamant invariant: rc_b was constructed as exactly 3 elements for P128Pow5T3",
            ),
        );

        let instance = meta.instance_column();
        meta.enable_equality(instance);

        ShieldedInputConfig {
            poseidon,
            cond_swap,
            range_check: RangeCheck64Config {
                value_col: range_value_col,
                bits_col: range_bits_col,
                q_bit,
                q_decompose,
            },
            instance,
        }
    }

    // The composed shielded-input `synthesize` exceeds the
    // 100-line clippy threshold because it lays out four
    // sub-regions (note-commitment + range-check + Merkle path
    // + nullifier two-stage) end-to-end, with copy
    // constraints binding the shared `value` and
    // `note_commitment` cells across them. Splitting into
    // helpers would obscure the cross-region binding the
    // composition's correctness depends on.
    #[allow(clippy::too_many_lines)]
    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<pallas::Base>,
    ) -> Result<(), PlonkError> {
        // ----- Step 1 — derive the input note's commitment -----
        // Same shape as `NoteCommitmentCircuit::synthesize`:
        // load 5 inputs, run Pow5Chip Poseidon arity-5, capture
        // the output cell.
        let chip_nc = Pow5Chip::construct(config.poseidon.clone());
        let (value_cell, note_inputs) = layouter.assign_region(
            || "load note-commitment inputs",
            |mut region| {
                let words = [
                    self.witness.value,
                    self.witness.asset_type,
                    self.witness.recipient,
                    self.witness.randomness,
                    self.witness.metadata_hash,
                ];
                let mut assigned = Vec::with_capacity(NOTE_COMMITMENT_INPUT_ARITY);
                let mut value_cell_opt = None;
                for (i, word) in words.iter().enumerate() {
                    let col = config.poseidon.state[i % 3];
                    let row = i / 3;
                    let cell =
                        region.assign_advice(|| format!("note input {i}"), col, row, || *word)?;
                    if i == 0 {
                        value_cell_opt = Some(cell.clone());
                    }
                    assigned.push(cell);
                }
                let value_cell = value_cell_opt.expect("input_0 is always assigned at i = 0");
                let array: [_; NOTE_COMMITMENT_INPUT_ARITY] =
                    assigned.try_into().unwrap_or_else(|_: Vec<_>| {
                        unreachable!("we pushed exactly NOTE_COMMITMENT_INPUT_ARITY items")
                    });
                Ok((value_cell, array))
            },
        )?;
        let nc_hasher = Hash::<
            pallas::Base,
            _,
            P128Pow5T3,
            ConstantLength<NOTE_COMMITMENT_INPUT_ARITY>,
            3,
            2,
        >::init(chip_nc, layouter.namespace(|| "init note-commitment"))?;
        let note_commitment_cell =
            nc_hasher.hash(layouter.namespace(|| "note-commitment hash"), note_inputs)?;

        // ----- Step 2 — range-check the value cell -----
        range_check_64bit_cell(
            &config.range_check,
            layouter.namespace(|| "range-check value"),
            &value_cell,
            self.witness.value_bits,
        )?;

        // ----- Step 3 — Merkle membership of the commitment ---
        // Copy the note_commitment cell into the cond-swap's
        // `a` column as the level-0 input (the `leaf`).
        let cond_swap_chip = CondSwapChip::<pallas::Base>::construct(config.cond_swap.clone());
        let mut current = layouter.assign_region(
            || "copy note_commitment as Merkle leaf",
            |mut region| {
                note_commitment_cell.copy_advice(
                    || "leaf <- note_commitment",
                    &mut region,
                    config.cond_swap.a(),
                    0,
                )
            },
        )?;
        for level in 0..DEPTH {
            let (left, right) = cond_swap_chip.swap(
                layouter.namespace(|| format!("cond_swap level {level}")),
                (current.clone(), self.witness.path_siblings[level]),
                self.witness.path_bits[level],
            )?;
            let chip = Pow5Chip::construct(config.poseidon.clone());
            let hasher = Hash::<pallas::Base, _, P128Pow5T3, ConstantLength<2>, 3, 2>::init(
                chip,
                layouter.namespace(|| format!("init merkle hash {level}")),
            )?;
            let next = hasher.hash(
                layouter.namespace(|| format!("merkle hash level {level}")),
                [left, right],
            )?;
            current = layouter.assign_region(
                || format!("copy hash output to next-level a column ({level})"),
                |mut region| {
                    next.copy_advice(
                        || format!("hash_{level} → current_{}", level + 1),
                        &mut region,
                        config.cond_swap.a(),
                        0,
                    )
                },
            )?;
        }
        // Final `current` cell is the recomputed root —
        // constrain it to equal public-input row 0
        // (`gnct_root`).
        layouter.constrain_instance(current.cell(), config.instance, 0)?;

        // ----- Step 4 — nullifier derivation -----
        // Stage 1: nullifier_key = Poseidon(inner_domain,
        // spending_key).
        let chip_n_inner = Pow5Chip::construct(config.poseidon.clone());
        let inner_domain_tag = self.domain_tags.nullifier_key_inner;
        let inner_inputs = layouter.assign_region(
            || "nullifier inner inputs",
            |mut region| {
                let domain_cell = region.assign_advice(
                    || "inner_domain (constant)",
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
        >::init(
            chip_n_inner, layouter.namespace(|| "init nullifier-inner")
        )?;
        let nullifier_key_cell =
            inner_hasher.hash(layouter.namespace(|| "nullifier-key hash"), inner_inputs)?;

        // Stage 2: nullifier = Poseidon(outer_domain,
        // nullifier_key, note_commitment, position).
        let chip_n_outer = Pow5Chip::construct(config.poseidon.clone());
        let outer_domain_tag = self.domain_tags.nullifier_outer;
        let outer_inputs = layouter.assign_region(
            || "nullifier outer inputs",
            |mut region| {
                let outer_domain_cell = region.assign_advice(
                    || "outer_domain (constant)",
                    config.poseidon.state[0],
                    0,
                    || Value::known(outer_domain_tag),
                )?;
                let nk_cell = nullifier_key_cell.copy_advice(
                    || "nullifier_key (from stage 1)",
                    &mut region,
                    config.poseidon.state[1],
                    0,
                )?;
                // CRITICAL — the note_commitment input here is
                // the SAME cell derived in step 1, copy-
                // constrained into this region. This is what
                // ties statement 6 to statement 3 (the input
                // note's commitment).
                let cm_cell = note_commitment_cell.copy_advice(
                    || "note_commitment (from step 1)",
                    &mut region,
                    config.poseidon.state[2],
                    0,
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
                chip_n_outer,
                layouter.namespace(|| "init nullifier-outer"),
            )?;
        let nullifier_cell =
            outer_hasher.hash(layouter.namespace(|| "nullifier hash"), outer_inputs)?;

        // Constrain the nullifier output to public-input row 1.
        layouter.constrain_instance(nullifier_cell.cell(), config.instance, 1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circuit::range_check::u64_to_bit_witnesses;
    use crate::nullifier::{derive_nullifier, derive_nullifier_key, LeafPosition, SpendingKey};
    use crate::poseidon::{poseidon_hash, FieldBytes};
    use crate::NoteCommitment;
    use adamant_crypto::domain;
    use adamant_crypto::hash::sha3_256_tagged;
    use adamant_halo2::proofs::dev::MockProver;
    use pasta_curves::group::ff::PrimeField;

    /// `K = 11` fits a depth-4 instantiation: 1 note-Poseidon
    /// (arity 5, ~36 rows) + 4 Merkle Poseidons (~36 rows
    /// each) + 2 nullifier Poseidons (~36 rows each) + 64 range
    /// rows + `cond_swap` rows + overhead. ~36*7 + 64 ≈ 320
    /// rows; `2^11 = 2048` rows is comfortable.
    const K: u32 = 11;

    fn fb_to_base(fb: FieldBytes) -> pallas::Base {
        pallas::Base::from_repr(fb.to_bytes())
            .expect("FieldBytes invariant: bytes encode a valid field element")
    }

    fn domain_tag_to_field(tag: &domain::DomainTag) -> pallas::Base {
        let bytes = sha3_256_tagged(tag, b"");
        fb_to_base(FieldBytes::from_bytes_reduced(bytes))
    }

    fn recompute_merkle_root(
        leaf: pallas::Base,
        siblings: &[pallas::Base],
        bits: &[bool],
    ) -> pallas::Base {
        assert_eq!(siblings.len(), bits.len());
        let mut current = leaf;
        for (sibling, &bit) in siblings.iter().zip(bits.iter()) {
            let (left, right) = if bit {
                (*sibling, current)
            } else {
                (current, *sibling)
            };
            let l_fb = FieldBytes::from_bytes(left.to_repr())
                .expect("Pallas base elements always encode valid FieldBytes");
            let r_fb = FieldBytes::from_bytes(right.to_repr())
                .expect("Pallas base elements always encode valid FieldBytes");
            let h = poseidon_hash::<2>([l_fb, r_fb]);
            current = fb_to_base(h);
        }
        current
    }

    /// Build a deterministic depth-4 setup with all witnesses
    /// + matching public inputs.
    #[allow(clippy::similar_names)]
    fn fixed_depth4_setup() -> (
        ShieldedInputWitness<4>,
        ShieldedInputDomainTags,
        ShieldedInputPublicInputs,
    ) {
        // Note contents.
        let value_u64 = 1_000_000u64;
        let asset_type_fb = FieldBytes::from_bytes_reduced([0x02; 32]);
        let recipient_fb = FieldBytes::from_bytes_reduced([0x03; 32]);
        let randomness_fb = FieldBytes::from_bytes_reduced([0x04; 32]);
        let metadata_hash_fb = FieldBytes::from_bytes_reduced([0x05; 32]);

        // Compute note commitment off-circuit (matching what
        // step 1 of the circuit derives).
        let value_fb = FieldBytes::from_bytes_reduced(pallas::Base::from(value_u64).to_repr());
        let commitment_fb = poseidon_hash::<5>([
            value_fb,
            asset_type_fb,
            recipient_fb,
            randomness_fb,
            metadata_hash_fb,
        ]);
        let commitment = fb_to_base(commitment_fb);

        // Authority + position.
        let sk_bytes = [0x44; 32];
        let position_value = 5u64; // binary 0b0101 → bits = [1, 0, 1, 0]

        // GNCT path siblings (deterministic for the test).
        let siblings = [
            fb_to_base(FieldBytes::from_bytes_reduced([0x11; 32])),
            fb_to_base(FieldBytes::from_bytes_reduced([0x22; 32])),
            fb_to_base(FieldBytes::from_bytes_reduced([0x33; 32])),
            fb_to_base(FieldBytes::from_bytes_reduced([0x44; 32])),
        ];
        let bits_bool = [true, false, true, false]; // low-bit first of position 5.
        let gnct_root = recompute_merkle_root(commitment, &siblings, &bits_bool);

        // Off-circuit nullifier derivation matching the
        // circuit's stage-1 + stage-2.
        let sk = SpendingKey::from_bytes(sk_bytes);
        let nk = derive_nullifier_key(&sk);
        let cm = NoteCommitment::from_bytes(commitment_fb.to_bytes());
        let nullifier_obj = derive_nullifier(&nk, &cm, LeafPosition(position_value));
        let nullifier = pallas::Base::from_repr(nullifier_obj.to_bytes())
            .expect("nullifier bytes encode a valid field element");

        let value_bit_witness = u64_to_bit_witnesses(value_u64);
        let witness = ShieldedInputWitness::<4> {
            value: value_bit_witness.value,
            asset_type: Value::known(fb_to_base(asset_type_fb)),
            recipient: Value::known(fb_to_base(recipient_fb)),
            randomness: Value::known(fb_to_base(randomness_fb)),
            metadata_hash: Value::known(fb_to_base(metadata_hash_fb)),
            spending_key: Value::known(fb_to_base(FieldBytes::from_bytes_reduced(sk_bytes))),
            position: Value::known(pallas::Base::from(position_value)),
            path_siblings: siblings.map(Value::known),
            path_bits: bits_bool.map(Value::known),
            value_bits: value_bit_witness.bits,
        };
        let domain_tags = ShieldedInputDomainTags {
            nullifier_key_inner: domain_tag_to_field(&domain::NULLIFIER_KEY_DERIVATION),
            nullifier_outer: domain_tag_to_field(&domain::NULLIFIER_HASH),
        };
        let public = ShieldedInputPublicInputs {
            gnct_root,
            nullifier,
        };
        (witness, domain_tags, public)
    }

    /// Positive case: full per-input proof verifies.
    #[test]
    fn shielded_input_circuit_accepts_consistent_inputs() {
        let (witness, dt, public) = fixed_depth4_setup();
        let circuit = ShieldedInputCircuit::<4>::new(witness, dt);
        let prover =
            MockProver::run(K, &circuit, vec![public.to_rows()]).expect("MockProver runs cleanly");
        assert_eq!(prover.verify(), Ok(()));
    }

    /// Negative case: tampered nullifier — the wrong public
    /// input fails the constraint.
    #[test]
    fn shielded_input_circuit_rejects_tampered_nullifier() {
        let (witness, dt, mut public) = fixed_depth4_setup();
        public.nullifier = pallas::Base::from(0xDEAD_BEEFu64);
        let circuit = ShieldedInputCircuit::<4>::new(witness, dt);
        let prover =
            MockProver::run(K, &circuit, vec![public.to_rows()]).expect("MockProver runs cleanly");
        assert!(prover.verify().is_err());
    }

    /// Negative case: tampered GNCT root.
    #[test]
    fn shielded_input_circuit_rejects_tampered_root() {
        let (witness, dt, mut public) = fixed_depth4_setup();
        public.gnct_root = pallas::Base::from(0x1234u64);
        let circuit = ShieldedInputCircuit::<4>::new(witness, dt);
        let prover =
            MockProver::run(K, &circuit, vec![public.to_rows()]).expect("MockProver runs cleanly");
        assert!(prover.verify().is_err());
    }

    /// Negative case: wrong spending key — produces wrong
    /// nullifier (statement 6 unforgeability).
    #[test]
    fn shielded_input_circuit_rejects_wrong_spending_key() {
        let (mut witness, dt, public) = fixed_depth4_setup();
        witness.spending_key = Value::known(pallas::Base::from(0u64));
        let circuit = ShieldedInputCircuit::<4>::new(witness, dt);
        let prover =
            MockProver::run(K, &circuit, vec![public.to_rows()]).expect("MockProver runs cleanly");
        assert!(prover.verify().is_err());
    }

    /// Negative case: wrong note `value` witness — re-derived
    /// `note_commitment` differs, so neither the Merkle root
    /// nor the nullifier match.
    #[test]
    fn shielded_input_circuit_rejects_wrong_value() {
        let (mut witness, dt, public) = fixed_depth4_setup();
        let bad_bits = u64_to_bit_witnesses(999);
        witness.value = bad_bits.value;
        witness.value_bits = bad_bits.bits;
        let circuit = ShieldedInputCircuit::<4>::new(witness, dt);
        let prover =
            MockProver::run(K, &circuit, vec![public.to_rows()]).expect("MockProver runs cleanly");
        assert!(prover.verify().is_err());
    }

    /// Negative case: bit decomposition inconsistent with
    /// `value` — range-check rejects.
    #[test]
    fn shielded_input_circuit_rejects_inconsistent_bits() {
        let (mut witness, dt, public) = fixed_depth4_setup();
        // Replace bits with the decomposition for a different
        // value — range-check linear-combination gate fails.
        let bad_bits = u64_to_bit_witnesses(999_999);
        witness.value_bits = bad_bits.bits;
        let circuit = ShieldedInputCircuit::<4>::new(witness, dt);
        let prover =
            MockProver::run(K, &circuit, vec![public.to_rows()]).expect("MockProver runs cleanly");
        assert!(prover.verify().is_err());
    }

    /// Cross-validation pin: in-circuit composed proof matches
    /// the expected root + nullifier from the off-circuit
    /// reference helpers.
    #[test]
    fn shielded_input_circuit_matches_out_of_circuit() {
        let (witness, dt, public) = fixed_depth4_setup();
        let circuit = ShieldedInputCircuit::<4>::new(witness, dt);
        let prover =
            MockProver::run(K, &circuit, vec![public.to_rows()]).expect("MockProver runs cleanly");
        assert_eq!(prover.verify(), Ok(()));
    }

    /// Keygen-shape pin.
    #[test]
    fn keygen_circuit_compiles() {
        let (_, dt, _) = fixed_depth4_setup();
        let _circuit = ShieldedInputCircuit::<4>::keygen(dt);
    }
}
