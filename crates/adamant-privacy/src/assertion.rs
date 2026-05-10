//! §7.4.3 provable-disclosure framework — Phase 6.10b foundation.
//!
//! Provides the [`AssertionCircuit`] trait that all provable-
//! disclosure circuits implement, plus one concrete circuit
//! [`RangeAssertionCircuit`] that demonstrates the pattern.
//!
//! # Spec basis
//!
//! Whitepaper §7.4.3 verbatim:
//!
//! > A user can produce cryptographic proofs of specific facts
//! > about their transactions without revealing other facts.
//! > Examples:
//! >
//! > - "I received at least X ADM from address Y between dates
//! >   D1 and D2."
//! > - "My current shielded balance is at least Z." Useful for
//! >   proof-of-solvency to a counterparty.
//! > - "I have not received any notes from sanctioned address
//! >   X."
//! >
//! > The protocol provides circuit primitives for constructing
//! > such proofs (`adamant::privacy::prove_assertion(...)` in
//! > the standard library, section 6.5).
//!
//! # Framework shape
//!
//! Each concrete assertion is a Halo 2 circuit. Different
//! assertions take different witness shapes (a balance proof
//! needs note ownership + summed values; a counterparty proof
//! needs sender-or-recipient bindings; etc.) so the framework
//! cannot prescribe a single witness type — the trait's
//! [`AssertionCircuit::PublicInputs`] associated type lets
//! each assertion declare its own public-input shape, and the
//! trait extends `halo2::Circuit<pallas::Base>` so the same
//! prove/verify machinery used by the validity circuit
//! (§7.3.2) works for assertions too.
//!
//! # Phase scope
//!
//! Phase 6.10b ships:
//!
//! - The trait + its public-input row helpers.
//! - One concrete circuit: [`RangeAssertionCircuit`] proving
//!   "I know a value `v` such that `v ≥ threshold` and
//!   `v < 2^64`", suitable as the building block for proof-
//!   of-solvency assertions and as a worked example of the
//!   pattern.
//!
//! Future sub-arcs add more concrete assertions:
//!
//! - **proof-of-solvency** at full §7.4.3 shape (subset-of-
//!   GNCT-notes + ownership + summed-values ≥ threshold)
//! - **received-from-X-between-D1-and-D2** (memo / counterparty
//!   bound)
//! - **not-received-from-X** (set-membership negative)
//!
//! These build on §7.3.2's existing gadgets (Merkle membership,
//! note commitment, range check, value commitment) plus
//! assertion-specific composition.

#![allow(clippy::doc_markdown, clippy::too_many_lines)]

use adamant_halo2::proofs::circuit::{Layouter, SimpleFloorPlanner, Value};
use adamant_halo2::proofs::pasta::pallas;
use adamant_halo2::proofs::plonk::{
    Advice, Circuit, Column, ConstraintSystem, Constraints, Error as PlonkError, Expression,
    Instance, Selector,
};
use adamant_halo2::proofs::poly::Rotation;
use pasta_curves::group::ff::Field;

use crate::circuit::range_check::{
    range_check_64bit_cell, u64_to_bit_witnesses, RangeCheck64Config, RANGE_BITS,
};

/// §7.4.3 provable-disclosure circuit trait.
///
/// Implementors are Halo 2 circuits over `pallas::Base` that
/// attest a specific fact about the prover's notes. Each
/// implementor declares its own public-input shape.
///
/// The trait is consumed by callers that want to prove or
/// verify any §7.4.3 assertion generically (e.g., a wallet's
/// "produce audit proof" entry point that branches on the user-
/// requested assertion type).
///
/// # Pasta-cycle pin
///
/// All assertion circuits live on `pallas::Base` (Fp). This
/// mirrors the validity circuit's choice and is the only
/// curve-side commitment that lets the recursive epoch proof
/// (§8.5.2) verify both validity and assertion proofs in the
/// same Halo 2 cycle.
pub trait AssertionCircuit: Circuit<pallas::Base> + Sized {
    /// Public inputs the verifier supplies. The verifier learns
    /// only what these public inputs encode — anything not
    /// included here is hidden.
    type PublicInputs;

    /// Convert public inputs to the row-vector form Halo 2
    /// expects (single instance column, one entry per row).
    fn public_input_rows(public: &Self::PublicInputs) -> Vec<pallas::Base>;

    /// Halo 2 row-count parameter `k`: circuit has at most
    /// `2^k` rows. MockProver / keygen / prove use this; the
    /// implementor pins it based on the circuit's empirical
    /// row count.
    const K: u32;
}

// ============================================================
// RangeAssertionCircuit — the §7.4.3 worked-example assertion
// ============================================================

/// A concrete §7.4.3 assertion: "I know a value `v` such that
/// `v ≥ threshold` and `v < 2^64`."
///
/// # Why this assertion
///
/// "Range with a threshold" is the smallest non-trivial
/// provable-disclosure assertion that exercises the same
/// gadgets larger assertions need (range checks, public-input
/// binding, witness-cell wiring). It's also a useful primitive
/// in its own right — proof-of-solvency reduces to a sum of
/// values plus this assertion on the sum.
///
/// # Construction
///
/// 1. Witness `v` and its 64-bit decomposition.
/// 2. Witness `delta = v - threshold` and its 64-bit
///    decomposition.
/// 3. Range-check both `v` and `delta` to prove they each lie
///    in `[0, 2^64)`. `delta ∈ [0, 2^64)` proves `delta ≥ 0`,
///    which combined with step 4 proves `v ≥ threshold`.
/// 4. A custom sum gate constrains
///    `v - threshold_pub - delta == 0`, where `threshold_pub`
///    is copy-constrained from public-input row 0 into an
///    advice cell.
///
/// All arithmetic happens in `pallas::Base`, which is far
/// larger than `2^65`, so `v + delta` and `threshold + delta`
/// don't overflow.
///
/// # Public input
///
/// The verifier supplies `threshold` only (one row). Witnessed
/// `v` and `delta` are hidden.
#[derive(Clone, Copy, Debug)]
pub struct RangeAssertionCircuit {
    /// Witness `v` (the value being asserted).
    pub value: Value<pallas::Base>,
    /// 64-bit decomposition of `v`.
    pub value_bits: [Value<pallas::Base>; RANGE_BITS],
    /// Witness `delta = v - threshold`.
    pub delta: Value<pallas::Base>,
    /// 64-bit decomposition of `delta`.
    pub delta_bits: [Value<pallas::Base>; RANGE_BITS],
}

impl Default for RangeAssertionCircuit {
    fn default() -> Self {
        Self {
            value: Value::unknown(),
            value_bits: [Value::unknown(); RANGE_BITS],
            delta: Value::unknown(),
            delta_bits: [Value::unknown(); RANGE_BITS],
        }
    }
}

impl RangeAssertionCircuit {
    /// Build a circuit from concrete `value` + `threshold`.
    ///
    /// # Panics
    ///
    /// Panics if `value < threshold` (the witness shape
    /// requires `delta = value - threshold ≥ 0`). The check is
    /// caller-side hygiene — a prover who attempts to construct
    /// a circuit for a false statement would fail proof
    /// generation; this surfaces the impossibility earlier.
    #[must_use]
    pub fn new(value: u64, threshold: u64) -> Self {
        assert!(
            value >= threshold,
            "RangeAssertionCircuit: value ({value}) < threshold ({threshold})"
        );
        let delta = value - threshold;
        let value_w = u64_to_bit_witnesses(value);
        let delta_w = u64_to_bit_witnesses(delta);
        Self {
            value: value_w.value,
            value_bits: value_w.bits,
            delta: delta_w.value,
            delta_bits: delta_w.bits,
        }
    }

    /// Construct an all-unknown witness for keygen.
    #[must_use]
    pub fn keygen() -> Self {
        Self::default()
    }
}

/// Public inputs for [`RangeAssertionCircuit`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RangeAssertionPublicInputs {
    /// The threshold the prover commits to. The proof attests
    /// "I know `v ≥ threshold` with `v ∈ [0, 2^64)`."
    pub threshold: u64,
}

impl RangeAssertionPublicInputs {
    /// Construct from a `u64` threshold.
    #[must_use]
    pub const fn new(threshold: u64) -> Self {
        Self { threshold }
    }

    /// Convert to row-vector form for `MockProver::run`.
    #[must_use]
    pub fn to_rows(&self) -> Vec<pallas::Base> {
        vec![pallas::Base::from(self.threshold)]
    }
}

/// Configuration for [`RangeAssertionCircuit`].
#[derive(Clone, Debug)]
pub struct RangeAssertionConfig {
    /// Range-check config for `value`.
    pub range_check_value: RangeCheck64Config,
    /// Range-check config for `delta`. Allocated separately so
    /// the two range checks live in independent column +
    /// selector groups (avoids selector-collision when both
    /// fire at row 0 of their respective regions).
    pub range_check_delta: RangeCheck64Config,
    /// Sum-gate column carrying `threshold`, `value`, `delta`
    /// at rows 0/1/2 respectively. The custom sum gate fires
    /// at row 0 with selector [`q_sum`].
    pub sum_col: Column<Advice>,
    /// Selector enabling the sum gate at row 0 of `sum_col`.
    pub q_sum: Selector,
    /// Public-input instance column.
    pub instance: Column<Instance>,
}

impl Circuit<pallas::Base> for RangeAssertionCircuit {
    type Config = RangeAssertionConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::keygen()
    }

    fn configure(meta: &mut ConstraintSystem<pallas::Base>) -> Self::Config {
        // Range-check for `value`.
        let value_col_v = meta.advice_column();
        let bits_col_v = meta.advice_column();
        let q_bit_v = meta.selector();
        let q_decompose_v = meta.selector();
        meta.enable_equality(value_col_v);
        meta.enable_equality(bits_col_v);

        // Range-check for `delta`.
        let value_col_d = meta.advice_column();
        let bits_col_d = meta.advice_column();
        let q_bit_d = meta.selector();
        let q_decompose_d = meta.selector();
        meta.enable_equality(value_col_d);
        meta.enable_equality(bits_col_d);

        // Sum gate column. Layout in this column:
        //   row 0: threshold (copy-constrained from instance)
        //   row 1: value     (copy-constrained from value_col_v)
        //   row 2: delta     (copy-constrained from value_col_d)
        let sum_col = meta.advice_column();
        meta.enable_equality(sum_col);
        let q_sum = meta.selector();

        // Per-bit binary checks for both range checks.
        meta.create_gate("value bit is 0 or 1", |meta| {
            let q = meta.query_selector(q_bit_v);
            let b = meta.query_advice(bits_col_v, Rotation::cur());
            let one = Expression::Constant(pallas::Base::ONE);
            Constraints::with_selector(q, [("b * (1 - b)", b.clone() * (one - b))])
        });
        meta.create_gate("delta bit is 0 or 1", |meta| {
            let q = meta.query_selector(q_bit_d);
            let b = meta.query_advice(bits_col_d, Rotation::cur());
            let one = Expression::Constant(pallas::Base::ONE);
            Constraints::with_selector(q, [("b * (1 - b)", b.clone() * (one - b))])
        });

        // Bit-decomposition gates for both range checks.
        meta.create_gate("value = Σ b_i * 2^i", |meta| {
            let q = meta.query_selector(q_decompose_v);
            let value = meta.query_advice(value_col_v, Rotation::cur());
            let mut acc = Expression::Constant(pallas::Base::ZERO);
            for i in 0..RANGE_BITS {
                let b = meta.query_advice(
                    bits_col_v,
                    #[allow(clippy::cast_possible_wrap, clippy::cast_possible_truncation)]
                    Rotation(i as i32),
                );
                let weight = pallas::Base::from(1u64 << i);
                acc = acc + b * Expression::Constant(weight);
            }
            Constraints::with_selector(q, [("value == bit decomposition", value - acc)])
        });
        meta.create_gate("delta = Σ b_i * 2^i", |meta| {
            let q = meta.query_selector(q_decompose_d);
            let delta = meta.query_advice(value_col_d, Rotation::cur());
            let mut acc = Expression::Constant(pallas::Base::ZERO);
            for i in 0..RANGE_BITS {
                let b = meta.query_advice(
                    bits_col_d,
                    #[allow(clippy::cast_possible_wrap, clippy::cast_possible_truncation)]
                    Rotation(i as i32),
                );
                let weight = pallas::Base::from(1u64 << i);
                acc = acc + b * Expression::Constant(weight);
            }
            Constraints::with_selector(q, [("delta == bit decomposition", delta - acc)])
        });

        // Sum gate: at row 0 of `sum_col`, constrain
        //   row 1 - row 0 - row 2 == 0
        // i.e. value - threshold - delta == 0,
        // i.e. value == threshold + delta.
        meta.create_gate("value == threshold + delta", |meta| {
            let q = meta.query_selector(q_sum);
            let threshold = meta.query_advice(sum_col, Rotation::cur());
            let value = meta.query_advice(sum_col, Rotation::next());
            #[allow(clippy::cast_possible_wrap, clippy::cast_possible_truncation)]
            let delta = meta.query_advice(sum_col, Rotation(2));
            Constraints::with_selector(q, [("v - t - d == 0", value - threshold - delta)])
        });

        let instance = meta.instance_column();
        meta.enable_equality(instance);

        RangeAssertionConfig {
            range_check_value: RangeCheck64Config {
                value_col: value_col_v,
                bits_col: bits_col_v,
                q_bit: q_bit_v,
                q_decompose: q_decompose_v,
            },
            range_check_delta: RangeCheck64Config {
                value_col: value_col_d,
                bits_col: bits_col_d,
                q_bit: q_bit_d,
                q_decompose: q_decompose_d,
            },
            sum_col,
            q_sum,
            instance,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<pallas::Base>,
    ) -> Result<(), PlonkError> {
        // Step 1: assign the value cell + run the range check on it.
        let value_cell = layouter.assign_region(
            || "value cell",
            |mut region| {
                region.assign_advice(
                    || "value",
                    config.range_check_value.value_col,
                    0,
                    || self.value,
                )
            },
        )?;
        range_check_64bit_cell(
            &config.range_check_value,
            layouter.namespace(|| "range-check value"),
            &value_cell,
            self.value_bits,
        )?;

        // Step 2: assign the delta cell + run the range check on it.
        let delta_cell = layouter.assign_region(
            || "delta cell",
            |mut region| {
                region.assign_advice(
                    || "delta",
                    config.range_check_delta.value_col,
                    0,
                    || self.delta,
                )
            },
        )?;
        range_check_64bit_cell(
            &config.range_check_delta,
            layouter.namespace(|| "range-check delta"),
            &delta_cell,
            self.delta_bits,
        )?;

        // Step 3: sum gate region. Lay out [threshold, value,
        // delta] at rows [0, 1, 2] of sum_col with the q_sum
        // selector enabled at row 0; copy-constrain row 0 to
        // public-input row 0, row 1 to value_cell, row 2 to
        // delta_cell.
        let threshold_cell = layouter.assign_region(
            || "sum gate region",
            |mut region| {
                config.q_sum.enable(&mut region, 0)?;

                // Row 0: threshold. We assign as a known-but-
                // unspecified value; the actual binding comes
                // from constrain_instance after this region.
                let threshold = region.assign_advice(
                    || "threshold (sum row 0)",
                    config.sum_col,
                    0,
                    || self.value - self.delta,
                )?;

                // Row 1: value (copy from value_cell).
                value_cell.copy_advice(|| "value (sum row 1)", &mut region, config.sum_col, 1)?;

                // Row 2: delta (copy from delta_cell).
                delta_cell.copy_advice(|| "delta (sum row 2)", &mut region, config.sum_col, 2)?;

                Ok(threshold)
            },
        )?;

        // Bind threshold to public-input row 0.
        layouter.constrain_instance(threshold_cell.cell(), config.instance, 0)?;

        Ok(())
    }
}

impl AssertionCircuit for RangeAssertionCircuit {
    type PublicInputs = RangeAssertionPublicInputs;

    fn public_input_rows(public: &Self::PublicInputs) -> Vec<pallas::Base> {
        public.to_rows()
    }

    /// `K = 9`: two 64-bit range checks (~128 rows each) plus
    /// the sum-gate region fit comfortably in `2^9 = 512` rows.
    const K: u32 = 9;
}

#[cfg(test)]
mod tests {
    use super::*;
    use adamant_halo2::proofs::dev::MockProver;

    /// Positive case: prover knows `value = 100`, attests
    /// `value ≥ 83`. Verifier supplies `threshold = 83`.
    #[test]
    fn range_assertion_accepts_value_above_threshold() {
        let circuit = RangeAssertionCircuit::new(100, 83);
        let public = RangeAssertionPublicInputs::new(83);
        let prover = MockProver::run(
            RangeAssertionCircuit::K,
            &circuit,
            vec![RangeAssertionCircuit::public_input_rows(&public)],
        )
        .expect("MockProver runs");
        assert_eq!(prover.verify(), Ok(()));
    }

    /// Positive case: equality boundary. `value = threshold`.
    #[test]
    fn range_assertion_accepts_value_equal_threshold() {
        let circuit = RangeAssertionCircuit::new(100, 100);
        let public = RangeAssertionPublicInputs::new(100);
        let prover = MockProver::run(
            RangeAssertionCircuit::K,
            &circuit,
            vec![RangeAssertionCircuit::public_input_rows(&public)],
        )
        .expect("MockProver runs");
        assert_eq!(prover.verify(), Ok(()));
    }

    /// Negative case: verifier supplies a different threshold
    /// than the prover used for `delta`. Sum-gate detects.
    #[test]
    fn range_assertion_rejects_threshold_mismatch() {
        let circuit = RangeAssertionCircuit::new(100, 83);
        // Prover witnessed delta = 100 - 83 = 17. Verifier
        // supplies threshold = 50, expecting delta = 50. The
        // sum-gate constraint `value - threshold - delta == 0`
        // becomes `100 - 50 - 17 = 33 ≠ 0`, rejected.
        let public = RangeAssertionPublicInputs::new(50);
        let prover = MockProver::run(
            RangeAssertionCircuit::K,
            &circuit,
            vec![RangeAssertionCircuit::public_input_rows(&public)],
        )
        .expect("MockProver runs");
        assert!(prover.verify().is_err());
    }

    /// Negative case: a malformed bit decomposition for
    /// `value` is rejected by the range check.
    #[test]
    fn range_assertion_rejects_malformed_value_bits() {
        let value_w = u64_to_bit_witnesses(100);
        let delta_w = u64_to_bit_witnesses(17);
        // 100 = 0b1100100, so bit 2 is 1. Tamper to 0.
        let mut bad_value_bits = value_w.bits;
        bad_value_bits[2] = Value::known(pallas::Base::from(0u64));

        let circuit = RangeAssertionCircuit {
            value: value_w.value,
            value_bits: bad_value_bits,
            delta: delta_w.value,
            delta_bits: delta_w.bits,
        };
        let public = RangeAssertionPublicInputs::new(83);
        let prover = MockProver::run(
            RangeAssertionCircuit::K,
            &circuit,
            vec![RangeAssertionCircuit::public_input_rows(&public)],
        )
        .expect("MockProver runs");
        assert!(prover.verify().is_err());
    }

    /// Negative case: a malformed bit decomposition for
    /// `delta` is rejected.
    #[test]
    fn range_assertion_rejects_malformed_delta_bits() {
        let value_w = u64_to_bit_witnesses(100);
        let delta_w = u64_to_bit_witnesses(17);
        // 17 = 0b10001, so bit 4 is 1. Tamper to 0.
        let mut bad_delta_bits = delta_w.bits;
        bad_delta_bits[4] = Value::known(pallas::Base::from(0u64));

        let circuit = RangeAssertionCircuit {
            value: value_w.value,
            value_bits: value_w.bits,
            delta: delta_w.value,
            delta_bits: bad_delta_bits,
        };
        let public = RangeAssertionPublicInputs::new(83);
        let prover = MockProver::run(
            RangeAssertionCircuit::K,
            &circuit,
            vec![RangeAssertionCircuit::public_input_rows(&public)],
        )
        .expect("MockProver runs");
        assert!(prover.verify().is_err());
    }

    /// Pin the K row-count parameter.
    #[test]
    fn range_assertion_k_pinned() {
        assert_eq!(RangeAssertionCircuit::K, 9);
    }

    /// Pin the public-input row count.
    #[test]
    fn range_assertion_public_input_arity() {
        let public = RangeAssertionPublicInputs::new(83);
        let rows = RangeAssertionCircuit::public_input_rows(&public);
        assert_eq!(rows.len(), 1);
    }

    /// Constructor panics if `value < threshold`.
    #[test]
    #[should_panic(expected = "value (50) < threshold (100)")]
    fn range_assertion_constructor_rejects_value_below_threshold() {
        let _ = RangeAssertionCircuit::new(50, 100);
    }

    /// Keygen-shape compile check.
    #[test]
    fn range_assertion_keygen_compiles() {
        let circuit = RangeAssertionCircuit::keygen();
        let _ = circuit.without_witnesses();
    }
}
