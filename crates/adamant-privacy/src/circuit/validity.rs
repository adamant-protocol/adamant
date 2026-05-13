#![allow(
    clippy::doc_markdown,
    clippy::doc_lazy_continuation,
    clippy::too_many_lines,
    clippy::similar_names
)]
//! Full shielded-transaction validity circuit per whitepaper
//! §7.3.2.
//!
//! Phase 6.8b.4e-3 (initial 1×1) closed at commit 17153c7.
//! Phase 6.8b.5 (this sub-arc) lifts the circuit to const-
//! generic `N_INPUTS` / `N_OUTPUTS` and adds the DEPTH=64
//! production instantiation.
//!
//! # In-circuit statements
//!
//! - Statement 1: each input note exists in the GNCT (Merkle
//!   path over its recomputed note commitment).
//! - Statement 3: each output note commitment is correctly
//!   computed.
//! - Statement 4: in-circuit half — each value commitment is a
//!   correct Pedersen opening per §7.3.1.2. The chain-level
//!   homomorphic balance check
//!   `Σ vc_in − Σ vc_out − Σ_τ (fee_τ · V_τ) = r_balance · R`
//!   is enforced off-circuit by validators on public data
//!   (the [`crate::value_commitment::balance_lhs`] helper).
//! - Statement 5: range proofs on each input/output value.
//! - Statement 6: each nullifier correctly derived from
//!   `(sk, cm_in, position)`.
//!
//! Statement 2 (nullifier uniqueness) is consensus-layer; not
//! in-circuit. Statement 7 (shielded contract execution) is
//! Phase 7+ AVM integration; not yet wired.
//!
//! # Cross-circuit cell binding
//!
//! Every witness flowing into more than one constraint binds
//! via `copy_advice` / `copy` across regions. For each input
//! `i` and output `j`:
//!
//! - `value_in[i]` cell — note-commitment input #0, range-check
//!   value, value-commitment scalar (as base-field element).
//! - `cm_in[i]` (Pow5Chip output) — Merkle leaf, nullifier
//!   outer-stage `note_commitment` input.
//! - `value_out[j]` cell — note-commitment input #0, range-
//!   check value, value-commitment scalar.
//! - `cm_out[j]` (Pow5Chip output) — equals public-input
//!   `output_commitment[j]`.
//!
//! # Public inputs (one instance column)
//!
//! For `N_INPUTS = N`, `N_OUTPUTS = M`:
//!
//! | row range                   | value             |
//! |-----------------------------|-------------------|
//! | `0`                         | `gnct_root`       |
//! | `1..1+N`                    | `nullifier[i]`    |
//! | `1+N..1+N+M`                | `cm_out[j]`       |
//! | `1+N+M..1+N+M+2N` (pairs)   | `(vc_in[i].x, vc_in[i].y)` |
//! | `1+N+M+2N..1+N+M+2N+2M`     | `(vc_out[j].x, vc_out[j].y)` |
//!
//! Total rows = `1 + 3·N + 3·M`. At `N=M=1` this is the 7-row
//! shape from Phase 6.8b.4e-3.
//!
//! # Production instantiation
//!
//! [`ProductionValidityCircuit`] pins `DEPTH = 64` per
//! whitepaper §7.2 GNCT-depth specification. MockProver tests
//! at production depth bump K to ~17 (≈131,072 rows) and so
//! gate behind the `expensive-tests` feature.

use std::marker::PhantomData;

use adamant_halo2::ecc::chip::{EccChip, EccConfig};
use adamant_halo2::ecc::{FixedPoint as EccFixedPoint, NonIdentityPoint, ScalarFixed, ScalarVar};
use adamant_halo2::poseidon::primitives::{ConstantLength, P128Pow5T3};
use adamant_halo2::poseidon::{Hash, Pow5Chip, Pow5Config};
use adamant_halo2::proofs::circuit::{Layouter, SimpleFloorPlanner, Value};
use adamant_halo2::proofs::pasta::pallas;
use adamant_halo2::proofs::plonk::{
    Circuit, Column, ConstraintSystem, Error as PlonkError, Instance,
};
use adamant_halo2::utilities::cond_swap::{CondSwapChip, CondSwapConfig, CondSwapInstructions};
use adamant_halo2::utilities::lookup_range_check::LookupRangeCheckConfig;

use super::note_commitment::NOTE_COMMITMENT_INPUT_ARITY;
use super::nullifier::{NULLIFIER_INPUT_ARITY, NULLIFIER_KEY_INPUT_ARITY};
use super::range_check::{range_check_64bit_cell, RangeCheck64Config, RANGE_BITS};
use super::value_commitment_chip::{AdamantFixedPoints, RFullScalar};

/// GNCT depth pinned at production per whitepaper §7.2. Used
/// by [`ProductionValidityCircuit`] and any consumer that
/// wants the production shape.
pub const PRODUCTION_GNCT_DEPTH: usize = 64;

/// Compute the public-input row count for an `N`-input
/// `M`-output validity circuit. `1 + 3N + 3M`.
#[must_use]
pub const fn validity_public_input_count(n_inputs: usize, n_outputs: usize) -> usize {
    1 + 3 * n_inputs + 3 * n_outputs
}

/// In-circuit witness for one input note.
#[derive(Clone, Copy, Debug)]
pub struct InputNoteWitness<const DEPTH: usize> {
    /// Note value as a Pallas base-field element.
    pub value: Value<pallas::Base>,
    /// Asset_type reduced into Pallas base.
    pub asset_type: Value<pallas::Base>,
    /// Recipient stealth-address x-coordinate.
    pub recipient: Value<pallas::Base>,
    /// Per-note randomness reduced into Pallas base.
    pub randomness: Value<pallas::Base>,
    /// Metadata-hash reduced into Pallas base.
    pub metadata_hash: Value<pallas::Base>,
    /// Spending key as Pallas base.
    pub spending_key: Value<pallas::Base>,
    /// Position in the GNCT.
    pub position: Value<pallas::Base>,
    /// Authentication path siblings.
    pub path_siblings: [Value<pallas::Base>; DEPTH],
    /// Authentication path bits (low-bit-first position).
    pub path_bits: [Value<bool>; DEPTH],
    /// Value 64-bit decomposition.
    pub value_bits: [Value<pallas::Base>; RANGE_BITS],
    /// Asset-specific value generator V_τ (Pallas affine
    /// point). Caller computes off-circuit via
    /// [`crate::value_commitment::asset_value_generator`].
    pub value_generator: Value<pallas::Affine>,
    /// Value-commitment randomness r (Pallas scalar).
    pub vc_randomness: Value<pallas::Scalar>,
}

impl<const DEPTH: usize> Default for InputNoteWitness<DEPTH> {
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
            value_generator: Value::unknown(),
            vc_randomness: Value::unknown(),
        }
    }
}

/// In-circuit witness for one output note.
#[derive(Clone, Copy, Debug)]
pub struct OutputNoteWitness {
    /// Note value as a Pallas base-field element.
    pub value: Value<pallas::Base>,
    /// Asset_type reduced into Pallas base.
    pub asset_type: Value<pallas::Base>,
    /// Recipient stealth-address x-coordinate.
    pub recipient: Value<pallas::Base>,
    /// Per-note randomness reduced into Pallas base.
    pub randomness: Value<pallas::Base>,
    /// Metadata-hash reduced into Pallas base.
    pub metadata_hash: Value<pallas::Base>,
    /// Value 64-bit decomposition.
    pub value_bits: [Value<pallas::Base>; RANGE_BITS],
    /// Asset-specific value generator V_τ.
    pub value_generator: Value<pallas::Affine>,
    /// Value-commitment randomness r (Pallas scalar).
    pub vc_randomness: Value<pallas::Scalar>,
}

impl Default for OutputNoteWitness {
    fn default() -> Self {
        Self {
            value: Value::unknown(),
            asset_type: Value::unknown(),
            recipient: Value::unknown(),
            randomness: Value::unknown(),
            metadata_hash: Value::unknown(),
            value_bits: [Value::unknown(); RANGE_BITS],
            value_generator: Value::unknown(),
            vc_randomness: Value::unknown(),
        }
    }
}

/// In-circuit witness for the full validity proof at
/// `(N_INPUTS, N_OUTPUTS)`-arity.
#[derive(Clone, Copy, Debug)]
pub struct ValidityWitness<const DEPTH: usize, const N_INPUTS: usize, const N_OUTPUTS: usize> {
    /// Input-note witnesses.
    pub inputs: [InputNoteWitness<DEPTH>; N_INPUTS],
    /// Output-note witnesses.
    pub outputs: [OutputNoteWitness; N_OUTPUTS],
}

impl<const DEPTH: usize, const N_INPUTS: usize, const N_OUTPUTS: usize> Default
    for ValidityWitness<DEPTH, N_INPUTS, N_OUTPUTS>
{
    fn default() -> Self {
        Self {
            inputs: core::array::from_fn(|_| InputNoteWitness::default()),
            outputs: core::array::from_fn(|_| OutputNoteWitness::default()),
        }
    }
}

/// Circuit-locked domain-tag constants for the nullifier
/// derivation. Same posture as
/// [`crate::circuit::nullifier::NullifierDomainTags`].
#[derive(Clone, Copy, Debug)]
pub struct ValidityDomainTags {
    /// Field-element form of `NULLIFIER_KEY_DERIVATION` tag.
    pub nullifier_key_inner: pallas::Base,
    /// Field-element form of `NULLIFIER_HASH` tag.
    pub nullifier_outer: pallas::Base,
}

/// Public inputs the verifier consumes.
#[derive(Clone, Debug)]
pub struct ValidityPublicInputs {
    /// GNCT root (one, shared across all inputs).
    pub gnct_root: pallas::Base,
    /// Published nullifiers, one per input.
    pub nullifiers: Vec<pallas::Base>,
    /// Output note commitments, one per output.
    pub output_commitments: Vec<pallas::Base>,
    /// Input value commitments (x, y) pairs, one per input.
    pub vc_in: Vec<(pallas::Base, pallas::Base)>,
    /// Output value commitments (x, y) pairs, one per output.
    pub vc_out: Vec<(pallas::Base, pallas::Base)>,
}

impl ValidityPublicInputs {
    /// Convert to row-vector form for `MockProver::run` /
    /// `create_proof`. Layout is the §7.3.1 / §7.3.2 fixed
    /// shape: `[gnct_root, nullifier...,
    /// output_commitment..., vc_in.x, vc_in.y...,
    /// vc_out.x, vc_out.y...]`.
    #[must_use]
    pub fn to_rows(&self) -> Vec<pallas::Base> {
        let n = self.nullifiers.len();
        let m = self.output_commitments.len();
        let mut rows = Vec::with_capacity(1 + 3 * n + 3 * m);
        rows.push(self.gnct_root);
        rows.extend_from_slice(&self.nullifiers);
        rows.extend_from_slice(&self.output_commitments);
        for (x, y) in &self.vc_in {
            rows.push(*x);
            rows.push(*y);
        }
        for (x, y) in &self.vc_out {
            rows.push(*x);
            rows.push(*y);
        }
        rows
    }

    /// Sanity-check arity invariants. Returns `Ok(())` iff
    /// `nullifiers.len() == n_inputs`,
    /// `output_commitments.len() == n_outputs`, etc.
    ///
    /// # Errors
    ///
    /// Returns a description string if any invariant is broken.
    pub fn check_arity(&self, n_inputs: usize, n_outputs: usize) -> Result<(), String> {
        if self.nullifiers.len() != n_inputs {
            return Err(format!(
                "nullifiers.len()={} != n_inputs={n_inputs}",
                self.nullifiers.len()
            ));
        }
        if self.output_commitments.len() != n_outputs {
            return Err(format!(
                "output_commitments.len()={} != n_outputs={n_outputs}",
                self.output_commitments.len()
            ));
        }
        if self.vc_in.len() != n_inputs {
            return Err(format!(
                "vc_in.len()={} != n_inputs={n_inputs}",
                self.vc_in.len()
            ));
        }
        if self.vc_out.len() != n_outputs {
            return Err(format!(
                "vc_out.len()={} != n_outputs={n_outputs}",
                self.vc_out.len()
            ));
        }
        Ok(())
    }
}

/// Configuration: bundles all the chip configs plus the
/// public-input instance column.
#[derive(Clone, Debug)]
pub struct ValidityConfig {
    /// Pow5Chip — shared across all Poseidon stages.
    pub poseidon: Pow5Config<pallas::Base, 3, 2>,
    /// CondSwapChip — Merkle-path swap.
    pub cond_swap: CondSwapConfig,
    /// Range-check config — input + output values.
    pub range_check: RangeCheck64Config,
    /// EccChip — value-commitment derivations.
    pub ecc: EccConfig<AdamantFixedPoints>,
    /// Public-input instance column.
    pub instance: Column<Instance>,
}

/// The composed full validity circuit at `(N_INPUTS,
/// N_OUTPUTS, DEPTH)`-arity.
#[derive(Clone, Copy, Debug)]
pub struct ValidityCircuit<const DEPTH: usize, const N_INPUTS: usize, const N_OUTPUTS: usize> {
    /// All witnesses.
    pub witness: ValidityWitness<DEPTH, N_INPUTS, N_OUTPUTS>,
    /// VK-fixed nullifier domain tags.
    pub domain_tags: ValidityDomainTags,
    /// Reserved for future generic parameters (Poseidon spec,
    /// hash variant).
    _spec: PhantomData<P128Pow5T3>,
}

impl<const DEPTH: usize, const N_INPUTS: usize, const N_OUTPUTS: usize>
    ValidityCircuit<DEPTH, N_INPUTS, N_OUTPUTS>
{
    /// Construct from a fully-known witness + domain tags.
    #[must_use]
    pub const fn new(
        witness: ValidityWitness<DEPTH, N_INPUTS, N_OUTPUTS>,
        domain_tags: ValidityDomainTags,
    ) -> Self {
        Self {
            witness,
            domain_tags,
            _spec: PhantomData,
        }
    }

    /// Construct an all-unknown witness for keygen.
    #[must_use]
    pub fn keygen(domain_tags: ValidityDomainTags) -> Self {
        Self {
            witness: ValidityWitness::default(),
            domain_tags,
            _spec: PhantomData,
        }
    }

    /// Public-input row count for this arity.
    #[must_use]
    pub const fn public_input_count() -> usize {
        validity_public_input_count(N_INPUTS, N_OUTPUTS)
    }
}

/// Production-shape validity circuit alias: GNCT-depth-64 per
/// whitepaper §7.2, with caller-chosen N/M arity.
pub type ProductionValidityCircuit<const N_INPUTS: usize, const N_OUTPUTS: usize> =
    ValidityCircuit<PRODUCTION_GNCT_DEPTH, N_INPUTS, N_OUTPUTS>;

impl<const DEPTH: usize, const N_INPUTS: usize, const N_OUTPUTS: usize> Circuit<pallas::Base>
    for ValidityCircuit<DEPTH, N_INPUTS, N_OUTPUTS>
{
    type Config = ValidityConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::keygen(self.domain_tags)
    }

    fn configure(meta: &mut ConstraintSystem<pallas::Base>) -> Self::Config {
        // ECC chip column setup (10 advice + 8 lagrange + 1
        // lookup-table). The ECC chip's advice columns are
        // also reused by Pow5Chip, CondSwap, and range-check
        // where layouts permit — we allocate ECC-shape first
        // because it has the strictest constraint set.
        let advices = [
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
        ];
        let lookup_table = meta.lookup_table_column();
        let lagrange_coeffs = [
            meta.fixed_column(),
            meta.fixed_column(),
            meta.fixed_column(),
            meta.fixed_column(),
            meta.fixed_column(),
            meta.fixed_column(),
            meta.fixed_column(),
            meta.fixed_column(),
        ];
        let constants = meta.fixed_column();
        meta.enable_constant(constants);

        // Pow5Chip columns (3 advice for state, 1 partial
        // sbox, 3 fixed rc_a, 3 fixed rc_b). Allocated
        // separately so Poseidon and ECC don't conflict.
        let poseidon_state = (0..3).map(|_| meta.advice_column()).collect::<Vec<_>>();
        let partial_sbox = meta.advice_column();
        let rc_a = (0..3).map(|_| meta.fixed_column()).collect::<Vec<_>>();
        let rc_b = (0..3).map(|_| meta.fixed_column()).collect::<Vec<_>>();
        meta.enable_constant(rc_b[0]);
        for c in &poseidon_state {
            meta.enable_equality(*c);
        }

        // CondSwap columns (5 advice).
        let cs_advices = (0..5).map(|_| meta.advice_column()).collect::<Vec<_>>();
        for c in &cs_advices {
            meta.enable_equality(*c);
        }

        // Range-check columns (2 advice + 2 selectors).
        let range_value_col = meta.advice_column();
        let range_bits_col = meta.advice_column();
        let q_bit = meta.selector();
        let q_decompose = meta.selector();
        meta.enable_equality(range_value_col);
        meta.enable_equality(range_bits_col);

        // Range-check gates.
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

        let range_check =
            adamant_halo2_range_check_config(range_value_col, range_bits_col, q_bit, q_decompose);

        // Instantiate sub-chips.
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
        let range_check_lookup = LookupRangeCheckConfig::configure(meta, advices[9], lookup_table);
        let ecc = EccChip::<AdamantFixedPoints>::configure(
            meta,
            advices,
            lagrange_coeffs,
            range_check_lookup,
        );

        let instance = meta.instance_column();
        meta.enable_equality(instance);

        ValidityConfig {
            poseidon,
            cond_swap,
            range_check,
            ecc,
            instance,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<pallas::Base>,
    ) -> Result<(), PlonkError> {
        // Load the lookup table for the EccChip's range-check.
        config.ecc.lookup_config.load(&mut layouter)?;

        // Public-input row layout per the type-level docs:
        //   row 0                            : gnct_root
        //   rows 1..1+N                      : nullifier[i]
        //   rows 1+N..1+N+M                  : cm_out[j]
        //   rows 1+N+M..1+N+M+2N (pairs)     : (vc_in[i].x, vc_in[i].y)
        //   rows 1+N+M+2N..end (pairs)       : (vc_out[j].x, vc_out[j].y)
        let nullifier_row = |i: usize| 1 + i;
        let cm_out_row = |j: usize| 1 + N_INPUTS + j;
        let vc_in_x_row = |i: usize| 1 + N_INPUTS + N_OUTPUTS + 2 * i;
        let vc_in_y_row = |i: usize| 1 + N_INPUTS + N_OUTPUTS + 2 * i + 1;
        let vc_out_x_row = |j: usize| 1 + N_INPUTS + N_OUTPUTS + 2 * N_INPUTS + 2 * j;
        let vc_out_y_row = |j: usize| 1 + N_INPUTS + N_OUTPUTS + 2 * N_INPUTS + 2 * j + 1;

        // Pre-allocate the EccChip once; it is cheap-clone.
        let ecc = EccChip::<AdamantFixedPoints>::construct(config.ecc.clone());
        let r_fixed = EccFixedPoint::from_inner(ecc.clone(), RFullScalar);

        // ---------- INPUT NOTES ----------
        for i in 0..N_INPUTS {
            let input = self.witness.inputs[i];

            // Step 1: derive cm_in[i].
            let chip_nc_in = Pow5Chip::construct(config.poseidon.clone());
            let (value_in_cell, note_in_inputs) = layouter.assign_region(
                || format!("load input note {i}"),
                |mut region| {
                    let words = [
                        input.value,
                        input.asset_type,
                        input.recipient,
                        input.randomness,
                        input.metadata_hash,
                    ];
                    let mut assigned = Vec::with_capacity(NOTE_COMMITMENT_INPUT_ARITY);
                    let mut value_cell_opt = None;
                    for (k, word) in words.iter().enumerate() {
                        let col = config.poseidon.state[k % 3];
                        let row = k / 3;
                        let cell = region.assign_advice(
                            || format!("input[{i}] word {k}"),
                            col,
                            row,
                            || *word,
                        )?;
                        if k == 0 {
                            value_cell_opt = Some(cell.clone());
                        }
                        assigned.push(cell);
                    }
                    let value_cell = value_cell_opt.expect(
                        "Adamant invariant: NOTE_COMMITMENT_INPUT_ARITY >= 1 so the k==0 branch is always taken",
                    );
                    let array: [_; NOTE_COMMITMENT_INPUT_ARITY] = assigned.try_into().expect(
                        "Adamant invariant: assigned was pushed to exactly NOTE_COMMITMENT_INPUT_ARITY times in the loop above",
                    );
                    Ok((value_cell, array))
                },
            )?;
            let nc_hasher_in = Hash::<
                pallas::Base,
                _,
                P128Pow5T3,
                ConstantLength<NOTE_COMMITMENT_INPUT_ARITY>,
                3,
                2,
            >::init(
                chip_nc_in, layouter.namespace(|| format!("init NC in {i}"))
            )?;
            let cm_in =
                nc_hasher_in.hash(layouter.namespace(|| format!("cm in {i}")), note_in_inputs)?;

            // Step 2: range-check value_in[i].
            range_check_64bit_cell(
                &config.range_check,
                layouter.namespace(|| format!("range-check value_in[{i}]")),
                &value_in_cell,
                input.value_bits,
            )?;

            // Step 3: Merkle membership of cm_in[i] → gnct_root.
            let cs_chip = CondSwapChip::<pallas::Base>::construct(config.cond_swap.clone());
            let mut current = layouter.assign_region(
                || format!("leaf <- cm_in[{i}]"),
                |mut region| {
                    cm_in.copy_advice(
                        || format!("merkle leaf {i}"),
                        &mut region,
                        config.cond_swap.a(),
                        0,
                    )
                },
            )?;
            for level in 0..DEPTH {
                let (left, right) = cs_chip.swap(
                    layouter.namespace(|| format!("cond_swap [{i}].{level}")),
                    (current.clone(), input.path_siblings[level]),
                    input.path_bits[level],
                )?;
                let chip = Pow5Chip::construct(config.poseidon.clone());
                let hasher = Hash::<pallas::Base, _, P128Pow5T3, ConstantLength<2>, 3, 2>::init(
                    chip,
                    layouter.namespace(|| format!("merkle init [{i}].{level}")),
                )?;
                let next = hasher.hash(
                    layouter.namespace(|| format!("merkle hash [{i}].{level}")),
                    [left, right],
                )?;
                current = layouter.assign_region(
                    || format!("copy hash → next [{i}].{level}"),
                    |mut region| {
                        next.copy_advice(
                            || format!("hash → current [{i}].{level}"),
                            &mut region,
                            config.cond_swap.a(),
                            0,
                        )
                    },
                )?;
            }
            // All inputs share the same gnct_root at row 0.
            layouter.constrain_instance(current.cell(), config.instance, 0)?;

            // Step 4: nullifier two-stage Poseidon.
            let chip_nk = Pow5Chip::construct(config.poseidon.clone());
            let inner_dt = self.domain_tags.nullifier_key_inner;
            let nk_inputs = layouter.assign_region(
                || format!("nk inputs [{i}]"),
                |mut region| {
                    let dt = region.assign_advice(
                        || "inner_dt",
                        config.poseidon.state[0],
                        0,
                        || Value::known(inner_dt),
                    )?;
                    let sk = region.assign_advice(
                        || "spending_key",
                        config.poseidon.state[1],
                        0,
                        || input.spending_key,
                    )?;
                    Ok([dt, sk])
                },
            )?;
            let nk_hasher = Hash::<
                pallas::Base,
                _,
                P128Pow5T3,
                ConstantLength<NULLIFIER_KEY_INPUT_ARITY>,
                3,
                2,
            >::init(
                chip_nk, layouter.namespace(|| format!("init NK [{i}]"))
            )?;
            let nk_cell =
                nk_hasher.hash(layouter.namespace(|| format!("nk hash [{i}]")), nk_inputs)?;

            let chip_n = Pow5Chip::construct(config.poseidon.clone());
            let outer_dt = self.domain_tags.nullifier_outer;
            let n_inputs = layouter.assign_region(
                || format!("n inputs [{i}]"),
                |mut region| {
                    let dt = region.assign_advice(
                        || "outer_dt",
                        config.poseidon.state[0],
                        0,
                        || Value::known(outer_dt),
                    )?;
                    let nk = nk_cell.copy_advice(
                        || "nk → outer",
                        &mut region,
                        config.poseidon.state[1],
                        0,
                    )?;
                    let cm = cm_in.copy_advice(
                        || "cm_in → outer",
                        &mut region,
                        config.poseidon.state[2],
                        0,
                    )?;
                    let pos = region.assign_advice(
                        || "position",
                        config.poseidon.state[0],
                        1,
                        || input.position,
                    )?;
                    Ok([dt, nk, cm, pos])
                },
            )?;
            let n_hasher = Hash::<
                pallas::Base,
                _,
                P128Pow5T3,
                ConstantLength<NULLIFIER_INPUT_ARITY>,
                3,
                2,
            >::init(
                chip_n, layouter.namespace(|| format!("init N [{i}]"))
            )?;
            let nullifier_cell =
                n_hasher.hash(layouter.namespace(|| format!("n hash [{i}]")), n_inputs)?;
            layouter.constrain_instance(
                nullifier_cell.cell(),
                config.instance,
                nullifier_row(i),
            )?;

            // Step 5: input value commitment vc_in[i].
            let value_in_ecc_cell = layouter.assign_region(
                || format!("value_in[{i}] for ECC"),
                |mut region| {
                    let cell = region.assign_advice(
                        || format!("value_in[{i}]"),
                        config.ecc.advices[0],
                        0,
                        || input.value,
                    )?;
                    region.constrain_equal(value_in_cell.cell(), cell.cell())?;
                    Ok(cell)
                },
            )?;
            let value_in_scalar = ScalarVar::from_base(
                ecc.clone(),
                layouter.namespace(|| format!("value_in[{i}] scalar")),
                &value_in_ecc_cell,
            )?;
            let v_tau_in = NonIdentityPoint::new(
                ecc.clone(),
                layouter.namespace(|| format!("V_τ in [{i}]")),
                input.value_generator,
            )?;
            let (v_v_tau_in, _) = v_tau_in.mul(
                layouter.namespace(|| format!("v · V_τ in [{i}]")),
                value_in_scalar,
            )?;

            let r_scalar_in = ScalarFixed::new(
                ecc.clone(),
                layouter.namespace(|| format!("r in [{i}]")),
                input.vc_randomness,
            )?;
            let (r_r_in, _) = r_fixed.mul(
                layouter.namespace(|| format!("r · R in [{i}]")),
                r_scalar_in,
            )?;
            let vc_in = v_v_tau_in.add(layouter.namespace(|| format!("vc_in[{i}]")), &r_r_in)?;
            let vc_in_inner = vc_in.inner();
            layouter.constrain_instance(vc_in_inner.x().cell(), config.instance, vc_in_x_row(i))?;
            layouter.constrain_instance(vc_in_inner.y().cell(), config.instance, vc_in_y_row(i))?;
        }

        // ---------- OUTPUT NOTES ----------
        for j in 0..N_OUTPUTS {
            let output = self.witness.outputs[j];

            // Step 6: derive cm_out[j].
            let chip_nc_out = Pow5Chip::construct(config.poseidon.clone());
            let (value_out_cell, note_out_inputs) = layouter.assign_region(
                || format!("load output note {j}"),
                |mut region| {
                    let words = [
                        output.value,
                        output.asset_type,
                        output.recipient,
                        output.randomness,
                        output.metadata_hash,
                    ];
                    let mut assigned = Vec::with_capacity(NOTE_COMMITMENT_INPUT_ARITY);
                    let mut value_cell_opt = None;
                    for (k, word) in words.iter().enumerate() {
                        let col = config.poseidon.state[k % 3];
                        let row = k / 3;
                        let cell = region.assign_advice(
                            || format!("output[{j}] word {k}"),
                            col,
                            row,
                            || *word,
                        )?;
                        if k == 0 {
                            value_cell_opt = Some(cell.clone());
                        }
                        assigned.push(cell);
                    }
                    let value_cell = value_cell_opt.expect(
                        "Adamant invariant: NOTE_COMMITMENT_INPUT_ARITY >= 1 so the k==0 branch is always taken",
                    );
                    let array: [_; NOTE_COMMITMENT_INPUT_ARITY] = assigned.try_into().expect(
                        "Adamant invariant: assigned was pushed to exactly NOTE_COMMITMENT_INPUT_ARITY times in the loop above",
                    );
                    Ok((value_cell, array))
                },
            )?;
            let nc_hasher_out = Hash::<
                pallas::Base,
                _,
                P128Pow5T3,
                ConstantLength<NOTE_COMMITMENT_INPUT_ARITY>,
                3,
                2,
            >::init(
                chip_nc_out,
                layouter.namespace(|| format!("init NC out {j}")),
            )?;
            let cm_out = nc_hasher_out.hash(
                layouter.namespace(|| format!("cm out {j}")),
                note_out_inputs,
            )?;
            layouter.constrain_instance(cm_out.cell(), config.instance, cm_out_row(j))?;

            // Step 7: range-check value_out[j].
            range_check_64bit_cell(
                &config.range_check,
                layouter.namespace(|| format!("range-check value_out[{j}]")),
                &value_out_cell,
                output.value_bits,
            )?;

            // Step 8: output value commitment vc_out[j].
            let value_out_ecc_cell = layouter.assign_region(
                || format!("value_out[{j}] for ECC"),
                |mut region| {
                    let cell = region.assign_advice(
                        || format!("value_out[{j}]"),
                        config.ecc.advices[0],
                        0,
                        || output.value,
                    )?;
                    region.constrain_equal(value_out_cell.cell(), cell.cell())?;
                    Ok(cell)
                },
            )?;
            let value_out_scalar = ScalarVar::from_base(
                ecc.clone(),
                layouter.namespace(|| format!("value_out[{j}] scalar")),
                &value_out_ecc_cell,
            )?;
            let v_tau_out = NonIdentityPoint::new(
                ecc.clone(),
                layouter.namespace(|| format!("V_τ out [{j}]")),
                output.value_generator,
            )?;
            let (v_v_tau_out, _) = v_tau_out.mul(
                layouter.namespace(|| format!("v · V_τ out [{j}]")),
                value_out_scalar,
            )?;
            let r_scalar_out = ScalarFixed::new(
                ecc.clone(),
                layouter.namespace(|| format!("r out [{j}]")),
                output.vc_randomness,
            )?;
            let (r_r_out, _) = r_fixed.mul(
                layouter.namespace(|| format!("r · R out [{j}]")),
                r_scalar_out,
            )?;
            let vc_out =
                v_v_tau_out.add(layouter.namespace(|| format!("vc_out[{j}]")), &r_r_out)?;
            let vc_out_inner = vc_out.inner();
            layouter.constrain_instance(
                vc_out_inner.x().cell(),
                config.instance,
                vc_out_x_row(j),
            )?;
            layouter.constrain_instance(
                vc_out_inner.y().cell(),
                config.instance,
                vc_out_y_row(j),
            )?;
        }

        Ok(())
    }
}

/// Helper: build a [`RangeCheck64Config`] from already-allocated
/// columns + selectors. The `RangeCheck64Config` struct is
/// trivially constructible since all fields are pub.
fn adamant_halo2_range_check_config(
    value_col: adamant_halo2::proofs::plonk::Column<adamant_halo2::proofs::plonk::Advice>,
    bits_col: adamant_halo2::proofs::plonk::Column<adamant_halo2::proofs::plonk::Advice>,
    q_bit: adamant_halo2::proofs::plonk::Selector,
    q_decompose: adamant_halo2::proofs::plonk::Selector,
) -> RangeCheck64Config {
    RangeCheck64Config {
        value_col,
        bits_col,
        q_bit,
        q_decompose,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circuit::range_check::u64_to_bit_witnesses;
    use crate::nullifier::{derive_nullifier, derive_nullifier_key, LeafPosition, SpendingKey};
    use crate::poseidon::{poseidon_hash, FieldBytes};
    use crate::value_commitment::{asset_value_generator, commit, ValueCommitmentRandomness};
    use crate::NoteCommitment;
    use adamant_crypto::domain;
    use adamant_crypto::hash::sha3_256_tagged;
    use adamant_halo2::proofs::dev::MockProver;
    use adamant_types::TypeId;
    use pasta_curves::group::ff::PrimeField;
    use pasta_curves::group::Curve;

    type TestCircuit = ValidityCircuit<4, 1, 1>;

    /// `K = 12` fits the ValidityCircuit at depth 4: 8+
    /// Poseidons + 4 Merkle levels + 128 range rows + 2 ECC
    /// chips (each ≈ 1000+ rows for the full mul + add).
    /// `2^12 = 4096` rows accommodates with margin.
    const K: u32 = 12;

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

    fn type_id(byte: u8) -> TypeId {
        TypeId::from_bytes([byte; 32])
    }

    /// Build a deterministic 1-input + 1-output transaction
    /// shape suitable for MockProver. Same value/asset on
    /// both sides means trivially balanced, but the circuit
    /// itself doesn't enforce balance — it only attests
    /// per-commitment openings.
    #[allow(clippy::too_many_lines)]
    fn fixed_setup_1x1() -> (TestCircuit, ValidityPublicInputs) {
        // Input note.
        let value_in_u64 = 1_000u64;
        let asset_in = type_id(0x01);
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

        // Spending key + position + path.
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

        // Output note.
        let value_out_u64 = 1_000u64;
        let asset_out = type_id(0x01);
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

        (circuit, public)
    }

    /// Positive-case round-trip.
    #[test]
    fn validity_circuit_accepts_consistent_tx() {
        let (circuit, public) = fixed_setup_1x1();
        let prover =
            MockProver::run(K, &circuit, vec![public.to_rows()]).expect("MockProver runs cleanly");
        assert_eq!(prover.verify(), Ok(()));
    }

    /// Negative case: tampered nullifier rejected.
    #[test]
    fn validity_circuit_rejects_tampered_nullifier() {
        let (circuit, mut public) = fixed_setup_1x1();
        public.nullifiers[0] = pallas::Base::from(0xDEADu64);
        let prover =
            MockProver::run(K, &circuit, vec![public.to_rows()]).expect("MockProver runs cleanly");
        assert!(prover.verify().is_err());
    }

    /// Negative case: tampered input vc rejected.
    #[test]
    fn validity_circuit_rejects_tampered_vc_in() {
        let (circuit, mut public) = fixed_setup_1x1();
        public.vc_in[0].0 = pallas::Base::from(1u64);
        let prover =
            MockProver::run(K, &circuit, vec![public.to_rows()]).expect("MockProver runs cleanly");
        assert!(prover.verify().is_err());
    }

    /// Pin the public-input-count formula across arities.
    #[test]
    fn public_input_count_pinned() {
        assert_eq!(TestCircuit::public_input_count(), 7);
        assert_eq!(validity_public_input_count(1, 1), 7);
        assert_eq!(validity_public_input_count(2, 2), 13);
        assert_eq!(validity_public_input_count(0, 0), 1);
        assert_eq!(validity_public_input_count(2, 3), 16);
    }

    /// Pin the arity-check helper.
    #[test]
    fn public_input_arity_check_works() {
        let (_, public) = fixed_setup_1x1();
        assert!(public.check_arity(1, 1).is_ok());
        assert!(public.check_arity(2, 1).is_err());
        assert!(public.check_arity(1, 2).is_err());
    }

    /// Keygen-shape compile check.
    #[test]
    fn keygen_compiles() {
        let dt = ValidityDomainTags {
            nullifier_key_inner: pallas::Base::from(1u64),
            nullifier_outer: pallas::Base::from(2u64),
        };
        let circuit = TestCircuit::keygen(dt);
        let _ = circuit.without_witnesses();
    }

    /// Production-shape DEPTH=64 type-construction check.
    /// Type-construction is free; running MockProver at
    /// K~17 (≈131,072 rows) takes minutes and is gated
    /// behind `expensive-tests`.
    #[test]
    fn production_circuit_type_constructs() {
        let dt = ValidityDomainTags {
            nullifier_key_inner: pallas::Base::from(0u64),
            nullifier_outer: pallas::Base::from(0u64),
        };
        let _circuit: ProductionValidityCircuit<1, 1> = ProductionValidityCircuit::keygen(dt);
        let _circuit: ProductionValidityCircuit<2, 2> = ProductionValidityCircuit::keygen(dt);
    }
}
