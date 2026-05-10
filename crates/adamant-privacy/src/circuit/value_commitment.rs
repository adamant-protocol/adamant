#![allow(clippy::doc_markdown, clippy::doc_lazy_continuation)]
//! In-circuit value-commitment derivation per whitepaper
//! §7.3.1.2 (post-amendment instance 33).
//!
//! Phase 6.8b.4d-2.c.2 — fifth Adamant-authored circuit.
//! Proves the prover knows an opening `(v, V_τ, r)` for a
//! published value commitment `vc`:
//!
//! ```text
//! vc = v · V_τ + r · R
//! ```
//!
//! where:
//! - `R` is the §7.3.1.2 universal randomness generator,
//!   used in-circuit as a fixed-base point via Adamant's
//!   [`AdamantFixedPoints`] impl (Phase 6.8b.4d-2.c.1).
//! - `V_τ` is the asset-specific value generator,
//!   witnessed as a non-identity Pallas point. The
//!   chain-level binding from `V_τ` to the asset type is
//!   enforced off-circuit via
//!   [`crate::value_commitment::asset_value_generator`]
//!   consistency at validation time.
//! - `v` is a Pallas base-field element (u64 lifted),
//!   consumed by `mul::base_field_element` variable-base
//!   scalar multiplication.
//! - `r` is a Pallas scalar field element (Fq), consumed
//!   by `mul_fixed::full_width` fixed-base scalar
//!   multiplication.
//!
//! # Why this split (fixed-base R + variable-base V_τ)
//!
//! Upstream `halo2_gadgets 0.3.1` ships `EccChip::mul` for
//! the `BaseFieldElem` scalar variant but leaves
//! `FullWidth` as `todo!()`. Adamant works around this by
//! using fixed-base `mul_fixed` for the FullWidth term
//! (`r · R`, where `R` is fixed at protocol level) and
//! variable-base `mul::base_field_element` for the
//! BaseFieldElem term (`v · V_τ`, where `V_τ` varies per
//! asset but `v` is a u64 ⊂ Pallas base field).
//!
//! Future work: filling the upstream `mul::FullWidth`
//! `todo!()` gap unlocks `r · V_τ` for full per-asset-
//! type-private value commitments (in-circuit hash-to-curve
//! for V_τ derivation from witnessed asset_type).
//!
//! # Public-input layout
//!
//! Single instance column, two rows:
//!
//! | row | value         |
//! |-----|---------------|
//! | 0   | `vc.x()`      |
//! | 1   | `vc.y()`      |
//!
//! Both x and y are exposed so the chain can reconstruct
//! the full Pallas point for the §7.3.2 statement 4
//! homomorphic balance check. The on-chain wire encoding
//! of `vc` (compressed form per [`crate::ValueCommitment`])
//! recovers the same point via
//! [`crate::ValueCommitment::to_point`]; the chain checks
//! `vc.x() == row 0 ∧ vc.y() == row 1`.

use std::marker::PhantomData;

use adamant_halo2::ecc::chip::{EccChip, EccConfig};
use adamant_halo2::ecc::{
    FixedPoint as EccFixedPoint, NonIdentityPoint, Point, ScalarFixed, ScalarVar,
};
use adamant_halo2::proofs::circuit::{Layouter, SimpleFloorPlanner, Value};
use adamant_halo2::proofs::pasta::pallas;
use adamant_halo2::proofs::plonk::{
    Circuit, Column, ConstraintSystem, Error as PlonkError, Instance,
};
use adamant_halo2::utilities::lookup_range_check::LookupRangeCheckConfig;
use adamant_halo2::utilities::UtilitiesInstructions;

use super::value_commitment_chip::{AdamantFixedPoints, RFullScalar};

/// Number of public inputs the value-commitment circuit
/// consumes: `vc.x()` at row 0, `vc.y()` at row 1.
pub const VALUE_COMMITMENT_PUBLIC_INPUT_COUNT: usize = 2;

/// In-circuit witness for the value-commitment derivation.
#[derive(Clone, Debug)]
pub struct ValueCommitmentWitness {
    /// Note value as a Pallas base-field element. Caller
    /// uses `pallas::Base::from(value_u64)`.
    pub value: Value<pallas::Base>,
    /// Asset-specific value generator `V_τ` (a non-identity
    /// Pallas point). Caller computes off-circuit via
    /// [`crate::value_commitment::asset_value_generator`]
    /// and passes the resulting point.
    pub asset_value_generator: Value<pallas::Affine>,
    /// Per-commitment randomness `r ∈ Pallas scalar field`.
    pub randomness: Value<pallas::Scalar>,
}

impl Default for ValueCommitmentWitness {
    fn default() -> Self {
        Self {
            value: Value::unknown(),
            asset_value_generator: Value::unknown(),
            randomness: Value::unknown(),
        }
    }
}

/// Public inputs the verifier consumes:
///
/// - Row 0: `vc.x()` (Pallas base-field element).
/// - Row 1: `vc.y()` (Pallas base-field element).
#[derive(Clone, Copy, Debug)]
pub struct ValueCommitmentPublicInputs {
    /// x-coordinate of the value commitment Pallas point.
    pub vc_x: pallas::Base,
    /// y-coordinate of the value commitment Pallas point.
    pub vc_y: pallas::Base,
}

impl ValueCommitmentPublicInputs {
    /// Construct from a Pallas affine point.
    #[must_use]
    pub fn from_point(point: &pallas::Affine) -> Self {
        use pasta_curves::arithmetic::CurveAffine;
        let coords = point.coordinates().expect("non-identity point");
        Self {
            vc_x: *coords.x(),
            vc_y: *coords.y(),
        }
    }

    /// Convert to row-vector form for `MockProver::run`.
    #[must_use]
    pub fn to_rows(self) -> Vec<pallas::Base> {
        vec![self.vc_x, self.vc_y]
    }
}

/// Configuration: the [`EccChip`] config + lookup-table
/// column + public-input instance.
#[derive(Clone, Debug)]
pub struct ValueCommitmentConfig {
    /// EccChip config parameterised on Adamant's FixedPoints.
    pub ecc: EccConfig<AdamantFixedPoints>,
    /// Public-input instance column carrying `(vc_x, vc_y)`.
    pub instance: Column<Instance>,
}

/// The value-commitment validity circuit.
#[derive(Clone, Debug, Default)]
pub struct ValueCommitmentCircuit {
    /// Witness inputs.
    pub witness: ValueCommitmentWitness,
    /// PhantomData reserved for generic parameters.
    _spec: PhantomData<()>,
}

impl ValueCommitmentCircuit {
    /// Construct from a fully-known witness. Use
    /// [`ValueCommitmentCircuit::default`] for keygen.
    #[must_use]
    pub const fn new(witness: ValueCommitmentWitness) -> Self {
        Self {
            witness,
            _spec: PhantomData,
        }
    }
}

impl Circuit<pallas::Base> for ValueCommitmentCircuit {
    type Config = ValueCommitmentConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<pallas::Base>) -> Self::Config {
        // Standard ecc-chip column setup per upstream's
        // MyCircuit reference layout: 10 advice + 8 fixed
        // (lagrange_coeffs) + 1 fixed (constants) + 1
        // lookup-table column + 1 instance.
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
        // Shared fixed column for loading constants.
        let constants = meta.fixed_column();
        meta.enable_constant(constants);

        let range_check = LookupRangeCheckConfig::configure(meta, advices[9], lookup_table);

        let ecc =
            EccChip::<AdamantFixedPoints>::configure(meta, advices, lagrange_coeffs, range_check);

        let instance = meta.instance_column();
        meta.enable_equality(instance);

        ValueCommitmentConfig { ecc, instance }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<pallas::Base>,
    ) -> Result<(), PlonkError> {
        let chip = EccChip::<AdamantFixedPoints>::construct(config.ecc.clone());

        // Step 1 — load the 10-bit lookup table required by
        // the EccChip's variable-base scalar mul.
        config.ecc.lookup_config.load(&mut layouter)?;

        // Step 2 — load `value` as an advice cell (a Pallas
        // base-field element) and convert to a ScalarVar via
        // BaseFieldElem.
        let value_cell = chip.load_private(
            layouter.namespace(|| "load value"),
            config.ecc.advices[0],
            self.witness.value,
        )?;
        let value_scalar = ScalarVar::from_base(
            chip.clone(),
            layouter.namespace(|| "value as ScalarVar"),
            &value_cell,
        )?;

        // Step 3 — witness V_τ as a non-identity point.
        let v_tau = NonIdentityPoint::new(
            chip.clone(),
            layouter.namespace(|| "witness V_τ"),
            self.witness.asset_value_generator,
        )?;

        // Step 4 — compute v · V_τ via variable-base mul
        // (BaseFieldElem variant — `v` is a base-field
        // element, `V_τ` is the variable point).
        let (v_v_tau, _) = v_tau.mul(layouter.namespace(|| "v · V_τ"), value_scalar)?;

        // Step 5 — compute r · R via fixed-base mul
        // (FullWidth variant — `r` is a Pallas scalar field
        // element, `R` is the protocol-fixed generator).
        let r_fixed = EccFixedPoint::from_inner(chip.clone(), RFullScalar);
        let r_scalar = ScalarFixed::new(
            chip.clone(),
            layouter.namespace(|| "witness r"),
            self.witness.randomness,
        )?;
        let (r_r, _) = r_fixed.mul(layouter.namespace(|| "r · R"), r_scalar)?;

        // Step 6 — sum the two terms: vc = v · V_τ + r · R.
        let vc = v_v_tau.add(layouter.namespace(|| "vc = v · V_τ + r · R"), &r_r)?;

        // Step 7 — extract the (x, y) of vc and constrain
        // them to public-input rows 0 and 1.
        let (vc_x, vc_y) = extract_xy(&vc)?;
        layouter.constrain_instance(vc_x.cell(), config.instance, 0)?;
        layouter.constrain_instance(vc_y.cell(), config.instance, 1)?;

        Ok(())
    }
}

/// Type alias for an in-circuit assigned cell of a Pallas-base
/// field element — the form `EccPoint::x()` and `EccPoint::y()`
/// return.
type AssignedBaseCell = adamant_halo2::proofs::circuit::AssignedCell<pallas::Base, pallas::Base>;

/// Extract the x and y advice cells from an [`EccChip`] point
/// for use in [`Layouter::constrain_instance`]. The point's
/// internal `EccPoint` carries x and y as `AssignedCell`s.
#[allow(clippy::unnecessary_wraps)]
fn extract_xy(
    point: &Point<pallas::Affine, EccChip<AdamantFixedPoints>>,
) -> Result<(AssignedBaseCell, AssignedBaseCell), PlonkError> {
    let inner = point.inner();
    Ok((inner.x(), inner.y()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::value_commitment::{
        asset_value_generator, commit, ValueCommitment, ValueCommitmentRandomness,
    };
    use adamant_halo2::proofs::dev::MockProver;
    use adamant_types::TypeId;
    use pasta_curves::group::ff::PrimeField;
    use pasta_curves::group::Curve;

    /// `K = 11` matches the per-input shielded-input circuit.
    /// Single value-commitment circuit fits comfortably.
    const K: u32 = 11;

    fn type_id(byte: u8) -> TypeId {
        TypeId::from_bytes([byte; 32])
    }

    /// Build a deterministic value-commitment setup +
    /// matching public inputs.
    fn fixed_setup(
        value_u64: u64,
        asset_byte: u8,
        randomness_seed: u8,
    ) -> (
        ValueCommitmentWitness,
        ValueCommitmentPublicInputs,
        ValueCommitment,
    ) {
        let asset = type_id(asset_byte);
        let randomness = ValueCommitmentRandomness::from_uniform_bytes(&[randomness_seed; 64]);
        let vc = commit(value_u64, asset, &randomness);
        let vc_point = vc.to_point().expect("commitment encodes valid point");

        let v_tau = asset_value_generator(asset).to_affine();
        let r_scalar = pallas::Scalar::from_repr(randomness.to_bytes())
            .expect("ValueCommitmentRandomness round-trips through Fq");

        let witness = ValueCommitmentWitness {
            value: Value::known(pallas::Base::from(value_u64)),
            asset_value_generator: Value::known(v_tau),
            randomness: Value::known(r_scalar),
        };
        let public = ValueCommitmentPublicInputs::from_point(&vc_point);
        (witness, public, vc)
    }

    /// Positive case: a circuit constructed with consistent
    /// witness + public inputs verifies.
    /// MockProver-based positive-case test. Phase 6.8b.4d-2.c.3
    /// replaced the runtime `find_zs_and_us` computation with
    /// hardcoded tables generated by
    /// `tools/gen-fixed-base-tables`, so this test now runs
    /// at normal cargo-test speed (no longer `#[ignore]`-d).
    #[test]
    fn value_commitment_circuit_accepts_consistent_inputs() {
        let (witness, public, _) = fixed_setup(1_000, 0x42, 0x33);
        let circuit = ValueCommitmentCircuit::new(witness);
        let prover =
            MockProver::run(K, &circuit, vec![public.to_rows()]).expect("MockProver runs cleanly");
        assert_eq!(prover.verify(), Ok(()));
    }

    /// Negative case: tampered public input (wrong vc) is
    /// rejected.
    #[test]
    fn value_commitment_circuit_rejects_tampered_vc() {
        let (witness, mut public, _) = fixed_setup(1_000, 0x42, 0x33);
        public.vc_x = pallas::Base::from(0xDEADu64);
        let circuit = ValueCommitmentCircuit::new(witness);
        let prover =
            MockProver::run(K, &circuit, vec![public.to_rows()]).expect("MockProver runs cleanly");
        assert!(prover.verify().is_err());
    }

    /// Negative case: tampered value witness produces a
    /// different commitment.
    #[test]
    fn value_commitment_circuit_rejects_wrong_value() {
        let (mut witness, public, _) = fixed_setup(1_000, 0x42, 0x33);
        witness.value = Value::known(pallas::Base::from(2_000u64));
        let circuit = ValueCommitmentCircuit::new(witness);
        let prover =
            MockProver::run(K, &circuit, vec![public.to_rows()]).expect("MockProver runs cleanly");
        assert!(prover.verify().is_err());
    }

    /// Pin the public-input count constant.
    #[test]
    fn public_input_count_pinned() {
        assert_eq!(VALUE_COMMITMENT_PUBLIC_INPUT_COUNT, 2);
    }
}
