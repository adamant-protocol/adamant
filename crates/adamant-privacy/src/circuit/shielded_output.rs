//! Composed shielded-output validity circuit per whitepaper
//! §7.3.2 statements 3 + 5 (output note well-formedness +
//! range proof on the output's value).
//!
//! Phase 6.8b.4e — first composition of Adamant-authored
//! sub-circuits. The standalone circuits at 6.8b.4a–4d each
//! prove one statement in isolation. This sub-arc binds two
//! of them together via copy constraints on shared cells:
//!
//! - The `value` cell is consumed by [`NoteCommitmentCircuit`]
//!   (as the first Poseidon input) and by [`RangeCheck64Circuit`]
//!   (as the value-decomposition target). The composed circuit
//!   constrains the same field-element cell into both
//!   sub-circuits' regions.
//!
//! # Spec basis
//!
//! Whitepaper §7.3.2 statement 3 (output note well-formedness)
//! and statement 5 (range proofs) are both per-output-note
//! constraints. Combining them into a single per-output proof
//! is the natural composition shape. Phase 6.8b.4e-2 will
//! compose the per-input-note circuit (statements 1 + 5 + 6 +
//! note-commitment-binding); Phase 6.8b.4d-2 + 4e-3 add
//! statement 4 (value conservation, blocked on §7.3 value-
//! commitment-scheme spec input).
//!
//! # Construction
//!
//! 1. Lay out the [`NoteCommitmentCircuit`] sub-region. The
//!    `value` cell is assigned in the `Pow5Chip`'s state column
//!    at position 0 and used as the first Poseidon input.
//! 2. Lay out the [`RangeCheck64Circuit`]'s
//!    [`range_check_64bit_cell`] sub-region, copy-constraining
//!    the `value` cell from step 1 into the range-check's
//!    `value_col` row 0. The 64 bit witnesses are loaded
//!    fresh.
//! 3. Constrain the note-commitment Poseidon output to equal
//!    the public-input `commitment` (single instance row).
//!
//! # Public input
//!
//! Same as [`NoteCommitmentCircuit`]: a single `commitment`
//! field element. The range-check half emits no additional
//! public inputs — the bound value is already covered by the
//! commitment, which the chain sees.

use std::marker::PhantomData;

use adamant_halo2::poseidon::primitives::{ConstantLength, P128Pow5T3};
use adamant_halo2::poseidon::{Hash, Pow5Chip, Pow5Config};
use adamant_halo2::proofs::circuit::{Layouter, SimpleFloorPlanner, Value};
use adamant_halo2::proofs::pasta::pallas;
use adamant_halo2::proofs::plonk::{
    Circuit, Column, ConstraintSystem, Error as PlonkError, Instance,
};

use super::note_commitment::NOTE_COMMITMENT_INPUT_ARITY;
use super::range_check::{range_check_64bit_cell, RangeCheck64Config, RANGE_BITS};

/// In-circuit witness for the composed shielded-output proof.
/// Bundles the note-commitment witness's five inputs with the
/// 64 range-proof bits for the value.
#[derive(Clone, Copy, Debug)]
pub struct ShieldedOutputWitness {
    /// `value` as a Pallas base-field element. Must equal
    /// `pallas::Base::from(u64)` for some u64 — the
    /// 64-bit decomposition below pins the range.
    pub value: Value<pallas::Base>,
    /// `asset_type` reduced into the Pallas base field per
    /// §7.1.
    pub asset_type: Value<pallas::Base>,
    /// `recipient` stealth-address x-coordinate per §7.2.2 /
    /// Phase 6.4.
    pub recipient: Value<pallas::Base>,
    /// Per-note `randomness` reduced into the Pallas base
    /// field.
    pub randomness: Value<pallas::Base>,
    /// `metadata_hash` (tagged-SHA3 of the BCS-encoded
    /// `NoteMetadata`) reduced into the Pallas base field.
    pub metadata_hash: Value<pallas::Base>,
    /// 64 bit-witnesses for `value`'s range proof. Must
    /// satisfy `Σ bits[i] * 2^i == value`. Use
    /// [`crate::u64_to_bit_witnesses`] to compute.
    pub value_bits: [Value<pallas::Base>; RANGE_BITS],
}

impl Default for ShieldedOutputWitness {
    fn default() -> Self {
        Self {
            value: Value::unknown(),
            asset_type: Value::unknown(),
            recipient: Value::unknown(),
            randomness: Value::unknown(),
            metadata_hash: Value::unknown(),
            value_bits: [Value::unknown(); RANGE_BITS],
        }
    }
}

/// Configuration for the composed circuit. Bundles the
/// note-commitment `Pow5Chip` config + the range-check config +
/// the public-input instance column.
#[derive(Clone, Debug)]
pub struct ShieldedOutputConfig {
    /// `Pow5Chip` configuration for the note-commitment
    /// Poseidon hash.
    pub poseidon: Pow5Config<pallas::Base, 3, 2>,
    /// Range-check configuration — its `value_col` is
    /// copy-constrained against the note-commitment's value
    /// cell.
    pub range_check: RangeCheck64Config,
    /// Public-input instance column carrying the expected
    /// `commitment`.
    pub instance: Column<Instance>,
}

/// The composed shielded-output validity circuit per §7.3.2
/// statements 3 + 5 combined.
///
/// Public-input layout: single instance column, single row,
/// carrying the expected `commitment`.
#[derive(Clone, Copy, Debug, Default)]
pub struct ShieldedOutputCircuit {
    /// Combined witness inputs.
    pub witness: ShieldedOutputWitness,
    /// `PhantomData` reserved for future generic parameters
    /// (e.g., a different Poseidon spec). Currently
    /// monomorphic on `P128Pow5T3` per §3.3.3.
    _spec: PhantomData<P128Pow5T3>,
}

impl ShieldedOutputCircuit {
    /// Construct from a fully-known witness. Use
    /// [`ShieldedOutputCircuit::default`] for keygen.
    #[must_use]
    pub const fn new(witness: ShieldedOutputWitness) -> Self {
        Self {
            witness,
            _spec: PhantomData,
        }
    }
}

impl Circuit<pallas::Base> for ShieldedOutputCircuit {
    type Config = ShieldedOutputConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<pallas::Base>) -> Self::Config {
        // Note-commitment Pow5Chip layout (3 advice for state,
        // 1 partial-sbox, 3 fixed rc_a, 3 fixed rc_b).
        let state = (0..3).map(|_| meta.advice_column()).collect::<Vec<_>>();
        let partial_sbox = meta.advice_column();
        let rc_a = (0..3).map(|_| meta.fixed_column()).collect::<Vec<_>>();
        let rc_b = (0..3).map(|_| meta.fixed_column()).collect::<Vec<_>>();
        meta.enable_constant(rc_b[0]);

        // Range-check columns (separate from Pow5Chip's so the
        // bit-decomposition gate's `Rotation(0..63)` queries
        // don't collide with the Poseidon layout).
        let range_value_col = meta.advice_column();
        let range_bits_col = meta.advice_column();
        let q_bit = meta.selector();
        let q_decompose = meta.selector();

        meta.enable_equality(range_value_col);
        meta.enable_equality(range_bits_col);

        // Per-bit binary check.
        meta.create_gate("bit is 0 or 1", |meta| {
            use adamant_halo2::proofs::plonk::{Constraints, Expression};
            use adamant_halo2::proofs::poly::Rotation;
            use pasta_curves::group::ff::Field;
            let q = meta.query_selector(q_bit);
            let b = meta.query_advice(range_bits_col, Rotation::cur());
            let one = Expression::Constant(pallas::Base::ONE);
            Constraints::with_selector(q, [("b * (1 - b)", b.clone() * (one - b))])
        });

        // Value-decomposition gate.
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

        let instance = meta.instance_column();
        meta.enable_equality(instance);
        // The Pow5Chip output cell sits in `state[0]` — enable
        // equality so we can wire it to both the public-input
        // instance and to the range-check's value column via
        // `copy_advice`.
        meta.enable_equality(state[0]);

        let poseidon = Pow5Chip::configure::<P128Pow5T3>(
            meta,
            state.clone().try_into().unwrap(),
            partial_sbox,
            rc_a.try_into().unwrap(),
            rc_b.try_into().unwrap(),
        );

        let range_check = RangeCheck64Config {
            value_col: range_value_col,
            bits_col: range_bits_col,
            q_bit,
            q_decompose,
        };

        ShieldedOutputConfig {
            poseidon,
            range_check,
            instance,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<pallas::Base>,
    ) -> Result<(), PlonkError> {
        let chip = Pow5Chip::construct(config.poseidon.clone());

        // Step 1 — load the five note-commitment inputs. The
        // `value` cell at position 0 is captured for later
        // copy-constraint into the range-check region.
        let (value_cell, inputs) = layouter.assign_region(
            || "load shielded-output inputs",
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
                    let column = config.poseidon.state[i % 3];
                    let row = i / 3;
                    let cell =
                        region.assign_advice(|| format!("input_{i}"), column, row, || *word)?;
                    if i == 0 {
                        value_cell_opt = Some(cell.clone());
                    }
                    assigned.push(cell);
                }
                let value_cell =
                    value_cell_opt.expect("input_0 (value) is always assigned at i = 0");
                let array: [_; NOTE_COMMITMENT_INPUT_ARITY] =
                    assigned.try_into().unwrap_or_else(|_: Vec<_>| {
                        unreachable!("we pushed exactly NOTE_COMMITMENT_INPUT_ARITY items")
                    });
                Ok((value_cell, array))
            },
        )?;

        // Step 2 — Poseidon hash of the five inputs.
        let hasher = Hash::<
            pallas::Base,
            _,
            P128Pow5T3,
            ConstantLength<NOTE_COMMITMENT_INPUT_ARITY>,
            3,
            2,
        >::init(chip, layouter.namespace(|| "init poseidon"))?;
        let output = hasher.hash(layouter.namespace(|| "note-commitment hash"), inputs)?;

        // Step 3 — range-check the value cell against the
        // 64 bit witnesses. The `range_check_64bit_cell`
        // helper copy-constrains the input cell into the
        // range-check region's value column, so the `value`
        // bound by the bit-decomposition is exactly the same
        // field element that was the first Poseidon input.
        range_check_64bit_cell(
            &config.range_check,
            layouter.namespace(|| "range-check value"),
            &value_cell,
            self.witness.value_bits,
        )?;

        // Step 4 — constrain the Poseidon output to equal the
        // public-input `commitment` (instance column row 0).
        layouter.constrain_instance(output.cell(), config.instance, 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circuit::range_check::u64_to_bit_witnesses;
    use crate::poseidon::{poseidon_hash, FieldBytes};
    use adamant_halo2::proofs::dev::MockProver;
    use pasta_curves::group::ff::PrimeField;

    /// `K = 8` fits both the note-commitment Poseidon (5
    /// inputs at K=8 per Phase 6.8b.4a) and the range-check's
    /// 64 bit rows (K=8 per Phase 6.8b.4d). Combined circuit
    /// runs in the larger budget.
    const K: u32 = 9;

    fn fb_to_base(fb: FieldBytes) -> pallas::Base {
        pallas::Base::from_repr(fb.to_bytes())
            .expect("FieldBytes invariant: bytes encode a valid field element")
    }

    /// Build a deterministic shielded-output setup.
    fn fixed_setup(value_u64: u64) -> (ShieldedOutputWitness, pallas::Base) {
        let asset_type = FieldBytes::from_bytes_reduced([0x02; 32]);
        let recipient = FieldBytes::from_bytes_reduced([0x03; 32]);
        let randomness = FieldBytes::from_bytes_reduced([0x04; 32]);
        let metadata_hash = FieldBytes::from_bytes_reduced([0x05; 32]);

        // Compute the expected commitment off-circuit using
        // the existing Phase 6.0 Poseidon helper.
        let value_fb = FieldBytes::from_bytes_reduced(pallas::Base::from(value_u64).to_repr());
        let commitment_fb =
            poseidon_hash::<5>([value_fb, asset_type, recipient, randomness, metadata_hash]);
        let commitment = fb_to_base(commitment_fb);

        let bit_witness = u64_to_bit_witnesses(value_u64);
        let witness = ShieldedOutputWitness {
            value: bit_witness.value,
            asset_type: Value::known(fb_to_base(asset_type)),
            recipient: Value::known(fb_to_base(recipient)),
            randomness: Value::known(fb_to_base(randomness)),
            metadata_hash: Value::known(fb_to_base(metadata_hash)),
            value_bits: bit_witness.bits,
        };
        (witness, commitment)
    }

    /// Positive case at a typical value.
    #[test]
    fn shielded_output_circuit_accepts_typical_value() {
        let (witness, commitment) = fixed_setup(1_000_000);
        let circuit = ShieldedOutputCircuit::new(witness);
        let prover =
            MockProver::run(K, &circuit, vec![vec![commitment]]).expect("MockProver runs cleanly");
        assert_eq!(prover.verify(), Ok(()));
    }

    /// Positive case at boundary values.
    #[test]
    fn shielded_output_circuit_accepts_boundary_values() {
        for v in [0u64, 1, u64::MAX] {
            let (witness, commitment) = fixed_setup(v);
            let circuit = ShieldedOutputCircuit::new(witness);
            let prover = MockProver::run(K, &circuit, vec![vec![commitment]])
                .expect("MockProver runs cleanly");
            assert_eq!(prover.verify(), Ok(()), "value {v} at boundary should pass");
        }
    }

    /// Negative case: tampered commitment is rejected.
    #[test]
    fn shielded_output_circuit_rejects_tampered_commitment() {
        let (witness, _) = fixed_setup(42);
        let bad_commitment = pallas::Base::from(0xDEAD_BEEFu64);
        let circuit = ShieldedOutputCircuit::new(witness);
        let prover = MockProver::run(K, &circuit, vec![vec![bad_commitment]])
            .expect("MockProver runs cleanly");
        assert!(prover.verify().is_err());
    }

    /// Negative case: bit decomposition doesn't match the
    /// `value` witness — the range-check's linear-combination
    /// gate fails.
    #[test]
    fn shielded_output_circuit_rejects_inconsistent_bits() {
        let (mut witness, commitment) = fixed_setup(42);
        // Replace bits with the decomposition for 43 — same
        // value witness in note-commitment, but bits don't sum
        // to it.
        let bad_bits = u64_to_bit_witnesses(43);
        witness.value_bits = bad_bits.bits;
        let circuit = ShieldedOutputCircuit::new(witness);
        let prover =
            MockProver::run(K, &circuit, vec![vec![commitment]]).expect("MockProver runs cleanly");
        assert!(
            prover.verify().is_err(),
            "inconsistent bit decomposition must be rejected by the range-check"
        );
    }

    /// Negative case: a "bit" witness is set to 2 (not binary).
    /// The bit-binary gate fires.
    #[test]
    fn shielded_output_circuit_rejects_non_binary_bit() {
        let (mut witness, commitment) = fixed_setup(2);
        // Set bits so the linear combination would still sum
        // to 2 (e.g., bit_0 = 2 and all others 0): value
        // matches but bit_0 is not binary.
        witness.value_bits = [Value::known(pallas::Base::from(0u64)); RANGE_BITS];
        witness.value_bits[0] = Value::known(pallas::Base::from(2u64));
        // Force value to equal 2.
        witness.value = Value::known(pallas::Base::from(2u64));
        // Need to adjust commitment for value = 2 (it's the
        // same value as fixed_setup's), so it should already
        // match — pass through.
        let circuit = ShieldedOutputCircuit::new(witness);
        let prover =
            MockProver::run(K, &circuit, vec![vec![commitment]]).expect("MockProver runs cleanly");
        assert!(
            prover.verify().is_err(),
            "non-binary bit must be rejected by the bit-binary gate"
        );
    }

    /// Cross-validation pin: the in-circuit Poseidon output
    /// equals the out-of-circuit `poseidon_hash::<5>` for the
    /// same inputs. Same as Phase 6.8b.4a's pin, exercised
    /// here through the composed circuit.
    #[test]
    fn circuit_matches_out_of_circuit() {
        let (witness, commitment) = fixed_setup(0xCAFE);
        let circuit = ShieldedOutputCircuit::new(witness);
        let prover =
            MockProver::run(K, &circuit, vec![vec![commitment]]).expect("MockProver runs cleanly");
        assert_eq!(prover.verify(), Ok(()));
    }

    /// Default-witness keygen-shape pin.
    #[test]
    fn default_witness_keygen_shape() {
        let _circuit = ShieldedOutputCircuit::default();
    }
}
