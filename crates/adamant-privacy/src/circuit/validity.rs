#![allow(
    clippy::doc_markdown,
    clippy::doc_lazy_continuation,
    clippy::too_many_lines,
    clippy::similar_names
)]
//! Full shielded-transaction validity circuit per whitepaper
//! §7.3.2.
//!
//! Phase 6.8b.4e-3 — final composition. A single Halo 2
//! circuit binding ALL the in-circuit §7.3.2 statements
//! together via copy constraints across shared witness
//! cells:
//!
//! - Statement 1: input note exists in the GNCT (Merkle path
//!   over the recomputed input note commitment).
//! - Statement 3: output note commitment is correctly computed.
//! - Statement 4: in-circuit half — each value commitment is a
//!   correct Pedersen opening per §7.3.1.2. The chain-level
//!   homomorphic balance check
//!   `Σ vc_in − Σ vc_out − Σ_τ (fee_τ · V_τ) = r_balance · R`
//!   is enforced off-circuit by validators on public data
//!   (the `crate::value_commitment::balance_lhs` helper).
//! - Statement 5: range proofs on input/output values.
//! - Statement 6: nullifier correctly derived from
//!   `(sk, cm_in, position)`.
//!
//! Statement 2 (nullifier uniqueness) is consensus-layer; not
//! in-circuit. Statement 7 (shielded contract execution) is
//! Phase 7+ AVM integration; not yet wired.
//!
//! # Cross-circuit cell binding
//!
//! Every witness flowing into more than one constraint binds
//! via `copy_advice` / `copy` across regions:
//!
//! - `value_in` cell — note-commitment input #0, range-check
//!   value, value-commitment scalar (as base-field element).
//! - `note_commitment_in` (Pow5Chip output) — Merkle leaf,
//!   nullifier outer-stage `note_commitment` input.
//! - `value_out` cell — note-commitment input #0, range-check
//!   value, value-commitment scalar.
//! - `note_commitment_out` (Pow5Chip output) — equals public-
//!   input `output_commitment`.
//!
//! # Public inputs (one instance column, 7 rows)
//!
//! | row | value                        |
//! |-----|------------------------------|
//! | 0   | `gnct_root`                  |
//! | 1   | `nullifier`                  |
//! | 2   | `output_commitment`          |
//! | 3   | `vc_in.x`                    |
//! | 4   | `vc_in.y`                    |
//! | 5   | `vc_out.x`                   |
//! | 6   | `vc_out.y`                   |
//!
//! # Scope at this sub-arc
//!
//! Phase 6.8b.4e-3 ships `ValidityCircuit<const DEPTH: usize>`
//! at fixed `N_INPUTS = 1`, `N_OUTPUTS = 1`. Const-generic
//! `N`/`M` parameterisation is a future sub-arc — array-based
//! const generics over witness types add Rust-edition-specific
//! friction. The single-input single-output shape covers the
//! simplest non-trivial shielded transaction (e.g., a 1-input
//! 1-output transfer), and demonstrates the composition
//! pattern that scales to larger N/M.

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

/// Number of input notes the circuit attests at this sub-arc.
/// Future const-generic generalisation lifts this.
pub const VALIDITY_N_INPUTS: usize = 1;

/// Number of output notes the circuit attests at this sub-arc.
pub const VALIDITY_N_OUTPUTS: usize = 1;

/// Number of public inputs per the §7.3.1 / §7.3.2 layout.
pub const VALIDITY_PUBLIC_INPUT_COUNT: usize = 7;

/// In-circuit witness for the full validity proof.
#[derive(Clone, Debug)]
pub struct ValidityWitness<const DEPTH: usize> {
    // ----- Input note (§7.3.2 statements 1, 3, 5, 6) -----
    /// Input note value as a Pallas base-field element.
    pub value_in: Value<pallas::Base>,
    /// Input asset_type reduced into Pallas base.
    pub asset_type_in: Value<pallas::Base>,
    /// Input recipient stealth-address x-coordinate.
    pub recipient_in: Value<pallas::Base>,
    /// Input per-note randomness reduced into Pallas base.
    pub randomness_in: Value<pallas::Base>,
    /// Input metadata-hash reduced into Pallas base.
    pub metadata_hash_in: Value<pallas::Base>,
    /// Spending key as Pallas base.
    pub spending_key: Value<pallas::Base>,
    /// Position in the GNCT.
    pub position: Value<pallas::Base>,
    /// Authentication path siblings.
    pub path_siblings: [Value<pallas::Base>; DEPTH],
    /// Authentication path bits (low-bit-first position).
    pub path_bits: [Value<bool>; DEPTH],
    /// Input value 64-bit decomposition.
    pub value_in_bits: [Value<pallas::Base>; RANGE_BITS],
    /// Input asset-specific value generator V_τ_in (Pallas
    /// affine point). Caller computes off-circuit via
    /// [`crate::value_commitment::asset_value_generator`].
    pub value_generator_in: Value<pallas::Affine>,
    /// Input value-commitment randomness r_in (Pallas scalar).
    pub vc_randomness_in: Value<pallas::Scalar>,

    // ----- Output note (§7.3.2 statements 3, 5) -----
    /// Output note value.
    pub value_out: Value<pallas::Base>,
    /// Output asset_type.
    pub asset_type_out: Value<pallas::Base>,
    /// Output recipient.
    pub recipient_out: Value<pallas::Base>,
    /// Output randomness.
    pub randomness_out: Value<pallas::Base>,
    /// Output metadata-hash.
    pub metadata_hash_out: Value<pallas::Base>,
    /// Output value 64-bit decomposition.
    pub value_out_bits: [Value<pallas::Base>; RANGE_BITS],
    /// Output asset-specific value generator.
    pub value_generator_out: Value<pallas::Affine>,
    /// Output value-commitment randomness.
    pub vc_randomness_out: Value<pallas::Scalar>,
}

impl<const DEPTH: usize> Default for ValidityWitness<DEPTH> {
    fn default() -> Self {
        Self {
            value_in: Value::unknown(),
            asset_type_in: Value::unknown(),
            recipient_in: Value::unknown(),
            randomness_in: Value::unknown(),
            metadata_hash_in: Value::unknown(),
            spending_key: Value::unknown(),
            position: Value::unknown(),
            path_siblings: [Value::unknown(); DEPTH],
            path_bits: [Value::unknown(); DEPTH],
            value_in_bits: [Value::unknown(); RANGE_BITS],
            value_generator_in: Value::unknown(),
            vc_randomness_in: Value::unknown(),
            value_out: Value::unknown(),
            asset_type_out: Value::unknown(),
            recipient_out: Value::unknown(),
            randomness_out: Value::unknown(),
            metadata_hash_out: Value::unknown(),
            value_out_bits: [Value::unknown(); RANGE_BITS],
            value_generator_out: Value::unknown(),
            vc_randomness_out: Value::unknown(),
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
#[derive(Clone, Copy, Debug)]
pub struct ValidityPublicInputs {
    /// GNCT root.
    pub gnct_root: pallas::Base,
    /// Published nullifier for the input note.
    pub nullifier: pallas::Base,
    /// Output note commitment.
    pub output_commitment: pallas::Base,
    /// Input value commitment (x, y) — Pallas point coords.
    pub vc_in_x: pallas::Base,
    /// Input value commitment y.
    pub vc_in_y: pallas::Base,
    /// Output value commitment x.
    pub vc_out_x: pallas::Base,
    /// Output value commitment y.
    pub vc_out_y: pallas::Base,
}

impl ValidityPublicInputs {
    /// Convert to row-vector form for `MockProver::run`.
    #[must_use]
    pub fn to_rows(self) -> Vec<pallas::Base> {
        vec![
            self.gnct_root,
            self.nullifier,
            self.output_commitment,
            self.vc_in_x,
            self.vc_in_y,
            self.vc_out_x,
            self.vc_out_y,
        ]
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

/// The composed full validity circuit.
#[derive(Clone, Debug)]
pub struct ValidityCircuit<const DEPTH: usize> {
    /// All witnesses.
    pub witness: ValidityWitness<DEPTH>,
    /// VK-fixed nullifier domain tags.
    pub domain_tags: ValidityDomainTags,
    /// Reserved for future generic parameters.
    _spec: PhantomData<P128Pow5T3>,
}

impl<const DEPTH: usize> ValidityCircuit<DEPTH> {
    /// Construct from a fully-known witness + domain tags.
    #[must_use]
    pub const fn new(witness: ValidityWitness<DEPTH>, domain_tags: ValidityDomainTags) -> Self {
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
}

impl<const DEPTH: usize> Circuit<pallas::Base> for ValidityCircuit<DEPTH> {
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
        let cond_swap = CondSwapChip::configure(meta, cs_advices.try_into().unwrap());
        let poseidon = Pow5Chip::configure::<P128Pow5T3>(
            meta,
            poseidon_state.try_into().unwrap(),
            partial_sbox,
            rc_a.try_into().unwrap(),
            rc_b.try_into().unwrap(),
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

        // ---------- INPUT NOTE ----------
        // Step 1: derive cm_in.
        let chip_nc_in = Pow5Chip::construct(config.poseidon.clone());
        let (value_in_cell, note_in_inputs) = layouter.assign_region(
            || "load input note inputs",
            |mut region| {
                let words = [
                    self.witness.value_in,
                    self.witness.asset_type_in,
                    self.witness.recipient_in,
                    self.witness.randomness_in,
                    self.witness.metadata_hash_in,
                ];
                let mut assigned = Vec::with_capacity(NOTE_COMMITMENT_INPUT_ARITY);
                let mut value_cell_opt = None;
                for (i, word) in words.iter().enumerate() {
                    let col = config.poseidon.state[i % 3];
                    let row = i / 3;
                    let cell = region.assign_advice(
                        || format!("input_note word {i}"),
                        col,
                        row,
                        || *word,
                    )?;
                    if i == 0 {
                        value_cell_opt = Some(cell.clone());
                    }
                    assigned.push(cell);
                }
                let value_cell = value_cell_opt.unwrap();
                let array: [_; NOTE_COMMITMENT_INPUT_ARITY] = assigned.try_into().unwrap();
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
        >::init(chip_nc_in, layouter.namespace(|| "init NC in"))?;
        let cm_in = nc_hasher_in.hash(layouter.namespace(|| "cm in"), note_in_inputs)?;

        // Step 2: range-check value_in.
        range_check_64bit_cell(
            &config.range_check,
            layouter.namespace(|| "range-check value_in"),
            &value_in_cell,
            self.witness.value_in_bits,
        )?;

        // Step 3: Merkle membership of cm_in.
        let cs_chip = CondSwapChip::<pallas::Base>::construct(config.cond_swap.clone());
        let mut current = layouter.assign_region(
            || "leaf <- cm_in",
            |mut region| {
                cm_in.copy_advice(
                    || "merkle leaf <- cm_in",
                    &mut region,
                    config.cond_swap.a(),
                    0,
                )
            },
        )?;
        for level in 0..DEPTH {
            let (left, right) = cs_chip.swap(
                layouter.namespace(|| format!("cond_swap {level}")),
                (current.clone(), self.witness.path_siblings[level]),
                self.witness.path_bits[level],
            )?;
            let chip = Pow5Chip::construct(config.poseidon.clone());
            let hasher = Hash::<pallas::Base, _, P128Pow5T3, ConstantLength<2>, 3, 2>::init(
                chip,
                layouter.namespace(|| format!("merkle init {level}")),
            )?;
            let next = hasher.hash(
                layouter.namespace(|| format!("merkle hash {level}")),
                [left, right],
            )?;
            current = layouter.assign_region(
                || format!("copy hash → next a ({level})"),
                |mut region| {
                    next.copy_advice(
                        || format!("hash {level} → current"),
                        &mut region,
                        config.cond_swap.a(),
                        0,
                    )
                },
            )?;
        }
        layouter.constrain_instance(current.cell(), config.instance, 0)?;

        // Step 4: nullifier two-stage.
        let chip_nk = Pow5Chip::construct(config.poseidon.clone());
        let inner_dt = self.domain_tags.nullifier_key_inner;
        let nk_inputs = layouter.assign_region(
            || "nk inputs",
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
                    || self.witness.spending_key,
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
        >::init(chip_nk, layouter.namespace(|| "init NK"))?;
        let nk_cell = nk_hasher.hash(layouter.namespace(|| "nk hash"), nk_inputs)?;

        let chip_n = Pow5Chip::construct(config.poseidon.clone());
        let outer_dt = self.domain_tags.nullifier_outer;
        let n_inputs = layouter.assign_region(
            || "n inputs",
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
                    || self.witness.position,
                )?;
                Ok([dt, nk, cm, pos])
            },
        )?;
        let n_hasher =
            Hash::<pallas::Base, _, P128Pow5T3, ConstantLength<NULLIFIER_INPUT_ARITY>, 3, 2>::init(
                chip_n,
                layouter.namespace(|| "init N"),
            )?;
        let nullifier_cell = n_hasher.hash(layouter.namespace(|| "n hash"), n_inputs)?;
        layouter.constrain_instance(nullifier_cell.cell(), config.instance, 1)?;

        // Step 5: input value commitment via EccChip.
        let ecc = EccChip::<AdamantFixedPoints>::construct(config.ecc.clone());
        // Re-load value_in into an EccChip-managed cell; the
        // existing value_in_cell is in the Pow5Chip's state
        // column, which is equality-enabled, so we copy-
        // constrain into the EccChip's advice column.
        let value_in_ecc_cell = layouter.assign_region(
            || "value_in for ECC",
            |mut region| {
                let cell = region.assign_advice(
                    || "value_in",
                    config.ecc.advices[0],
                    0,
                    || self.witness.value_in,
                )?;
                region.constrain_equal(value_in_cell.cell(), cell.cell())?;
                Ok(cell)
            },
        )?;
        let value_in_scalar = ScalarVar::from_base(
            ecc.clone(),
            layouter.namespace(|| "value_in scalar"),
            &value_in_ecc_cell,
        )?;
        let v_tau_in = NonIdentityPoint::new(
            ecc.clone(),
            layouter.namespace(|| "V_τ in"),
            self.witness.value_generator_in,
        )?;
        let (v_v_tau_in, _) = v_tau_in.mul(layouter.namespace(|| "v · V_τ in"), value_in_scalar)?;

        let r_fixed = EccFixedPoint::from_inner(ecc.clone(), RFullScalar);
        let r_scalar_in = ScalarFixed::new(
            ecc.clone(),
            layouter.namespace(|| "r in"),
            self.witness.vc_randomness_in,
        )?;
        let (r_r_in, _) = r_fixed.mul(layouter.namespace(|| "r · R in"), r_scalar_in)?;
        let vc_in = v_v_tau_in.add(layouter.namespace(|| "vc_in"), &r_r_in)?;
        let vc_in_inner = vc_in.inner();
        layouter.constrain_instance(vc_in_inner.x().cell(), config.instance, 3)?;
        layouter.constrain_instance(vc_in_inner.y().cell(), config.instance, 4)?;

        // ---------- OUTPUT NOTE ----------
        // Step 6: derive cm_out.
        let chip_nc_out = Pow5Chip::construct(config.poseidon.clone());
        let (value_out_cell, note_out_inputs) = layouter.assign_region(
            || "load output note inputs",
            |mut region| {
                let words = [
                    self.witness.value_out,
                    self.witness.asset_type_out,
                    self.witness.recipient_out,
                    self.witness.randomness_out,
                    self.witness.metadata_hash_out,
                ];
                let mut assigned = Vec::with_capacity(NOTE_COMMITMENT_INPUT_ARITY);
                let mut value_cell_opt = None;
                for (i, word) in words.iter().enumerate() {
                    let col = config.poseidon.state[i % 3];
                    let row = i / 3;
                    let cell = region.assign_advice(
                        || format!("output_note word {i}"),
                        col,
                        row,
                        || *word,
                    )?;
                    if i == 0 {
                        value_cell_opt = Some(cell.clone());
                    }
                    assigned.push(cell);
                }
                let value_cell = value_cell_opt.unwrap();
                let array: [_; NOTE_COMMITMENT_INPUT_ARITY] = assigned.try_into().unwrap();
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
        >::init(chip_nc_out, layouter.namespace(|| "init NC out"))?;
        let cm_out = nc_hasher_out.hash(layouter.namespace(|| "cm out"), note_out_inputs)?;
        layouter.constrain_instance(cm_out.cell(), config.instance, 2)?;

        // Step 7: range-check value_out.
        range_check_64bit_cell(
            &config.range_check,
            layouter.namespace(|| "range-check value_out"),
            &value_out_cell,
            self.witness.value_out_bits,
        )?;

        // Step 8: output value commitment.
        let value_out_ecc_cell = layouter.assign_region(
            || "value_out for ECC",
            |mut region| {
                let cell = region.assign_advice(
                    || "value_out",
                    config.ecc.advices[0],
                    0,
                    || self.witness.value_out,
                )?;
                region.constrain_equal(value_out_cell.cell(), cell.cell())?;
                Ok(cell)
            },
        )?;
        let value_out_scalar = ScalarVar::from_base(
            ecc.clone(),
            layouter.namespace(|| "value_out scalar"),
            &value_out_ecc_cell,
        )?;
        let v_tau_out = NonIdentityPoint::new(
            ecc.clone(),
            layouter.namespace(|| "V_τ out"),
            self.witness.value_generator_out,
        )?;
        let (v_v_tau_out, _) =
            v_tau_out.mul(layouter.namespace(|| "v · V_τ out"), value_out_scalar)?;

        let r_scalar_out = ScalarFixed::new(
            ecc.clone(),
            layouter.namespace(|| "r out"),
            self.witness.vc_randomness_out,
        )?;
        let (r_r_out, _) = r_fixed.mul(layouter.namespace(|| "r · R out"), r_scalar_out)?;
        let vc_out = v_v_tau_out.add(layouter.namespace(|| "vc_out"), &r_r_out)?;
        let vc_out_inner = vc_out.inner();
        layouter.constrain_instance(vc_out_inner.x().cell(), config.instance, 5)?;
        layouter.constrain_instance(vc_out_inner.y().cell(), config.instance, 6)?;

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
    fn fixed_setup() -> (ValidityWitness<4>, ValidityDomainTags, ValidityPublicInputs) {
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
        let bits = [true, false, true, false]; // pos = 5
        let gnct_root = recompute_root(cm_in, &siblings, &bits);

        let sk_obj = SpendingKey::from_bytes(sk_bytes);
        let nk = derive_nullifier_key(&sk_obj);
        let cm_in_obj = NoteCommitment::from_bytes(cm_in_fb.to_bytes());
        let nullifier = derive_nullifier(&nk, &cm_in_obj, LeafPosition(position_u64));
        let nullifier_base = pallas::Base::from_repr(nullifier.to_bytes()).unwrap();

        let value_in_bits = u64_to_bit_witnesses(value_in_u64);
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

        let value_out_bits = u64_to_bit_witnesses(value_out_u64);
        let v_tau_out = asset_value_generator(asset_out).to_affine();
        let r_out = ValueCommitmentRandomness::from_uniform_bytes(&[0x66; 64]);
        let r_out_scalar = pallas::Scalar::from_repr(r_out.to_bytes()).unwrap();
        let vc_out_obj = commit(value_out_u64, asset_out, &r_out);
        let vc_out_point = vc_out_obj.to_point().unwrap();
        let vc_out_coords =
            pasta_curves::arithmetic::CurveAffine::coordinates(&vc_out_point).unwrap();

        let witness = ValidityWitness::<4> {
            value_in: value_in_bits.value,
            asset_type_in: Value::known(fb_to_base(FieldBytes::from_bytes_reduced(
                asset_in.to_bytes(),
            ))),
            recipient_in: Value::known(fb_to_base(recipient_in)),
            randomness_in: Value::known(fb_to_base(randomness_in)),
            metadata_hash_in: Value::known(fb_to_base(meta_in)),
            spending_key: Value::known(fb_to_base(FieldBytes::from_bytes_reduced(sk_bytes))),
            position: Value::known(pallas::Base::from(position_u64)),
            path_siblings: siblings.map(Value::known),
            path_bits: bits.map(Value::known),
            value_in_bits: value_in_bits.bits,
            value_generator_in: Value::known(v_tau_in),
            vc_randomness_in: Value::known(r_in_scalar),
            value_out: value_out_bits.value,
            asset_type_out: Value::known(fb_to_base(FieldBytes::from_bytes_reduced(
                asset_out.to_bytes(),
            ))),
            recipient_out: Value::known(fb_to_base(recipient_out)),
            randomness_out: Value::known(fb_to_base(randomness_out)),
            metadata_hash_out: Value::known(fb_to_base(meta_out)),
            value_out_bits: value_out_bits.bits,
            value_generator_out: Value::known(v_tau_out),
            vc_randomness_out: Value::known(r_out_scalar),
        };

        let domain_tags = ValidityDomainTags {
            nullifier_key_inner: dt_field(&domain::NULLIFIER_KEY_DERIVATION),
            nullifier_outer: dt_field(&domain::NULLIFIER_HASH),
        };

        let public = ValidityPublicInputs {
            gnct_root,
            nullifier: nullifier_base,
            output_commitment: cm_out,
            vc_in_x: *vc_in_coords.x(),
            vc_in_y: *vc_in_coords.y(),
            vc_out_x: *vc_out_coords.x(),
            vc_out_y: *vc_out_coords.y(),
        };

        let _ = (r_in, r_out); // silence unused-binding warnings on drop
        (witness, domain_tags, public)
    }

    /// Positive-case round-trip: a fully consistent 1-input
    /// 1-output validity proof verifies under MockProver.
    #[test]
    fn validity_circuit_accepts_consistent_tx() {
        let (witness, dt, public) = fixed_setup();
        let circuit = ValidityCircuit::<4>::new(witness, dt);
        let prover =
            MockProver::run(K, &circuit, vec![public.to_rows()]).expect("MockProver runs cleanly");
        assert_eq!(prover.verify(), Ok(()));
    }

    /// Negative case: tampered nullifier rejected.
    #[test]
    fn validity_circuit_rejects_tampered_nullifier() {
        let (witness, dt, mut public) = fixed_setup();
        public.nullifier = pallas::Base::from(0xDEADu64);
        let circuit = ValidityCircuit::<4>::new(witness, dt);
        let prover =
            MockProver::run(K, &circuit, vec![public.to_rows()]).expect("MockProver runs cleanly");
        assert!(prover.verify().is_err());
    }

    /// Negative case: tampered input vc rejected.
    #[test]
    fn validity_circuit_rejects_tampered_vc_in() {
        let (witness, dt, mut public) = fixed_setup();
        public.vc_in_x = pallas::Base::from(1u64);
        let circuit = ValidityCircuit::<4>::new(witness, dt);
        let prover =
            MockProver::run(K, &circuit, vec![public.to_rows()]).expect("MockProver runs cleanly");
        assert!(prover.verify().is_err());
    }

    /// Pin the public-input count constant.
    #[test]
    fn public_input_count_pinned() {
        assert_eq!(VALIDITY_PUBLIC_INPUT_COUNT, 7);
        assert_eq!(VALIDITY_N_INPUTS, 1);
        assert_eq!(VALIDITY_N_OUTPUTS, 1);
    }

    /// Keygen-shape compile check.
    #[test]
    fn keygen_compiles() {
        let dt = ValidityDomainTags {
            nullifier_key_inner: pallas::Base::from(1u64),
            nullifier_outer: pallas::Base::from(2u64),
        };
        let _circuit = ValidityCircuit::<4>::keygen(dt);
    }
}
