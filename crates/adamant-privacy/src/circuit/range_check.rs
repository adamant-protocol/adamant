//! 64-bit range-proof validity circuit per whitepaper §7.3.2
//! statement 5 ("range proofs").
//!
//! Phase 6.8b.4d (range-proof half) — fourth Adamant-authored
//! circuit. Proves: a witnessed `value` lies in `[0, 2^64)`.
//!
//! # Spec basis
//!
//! Whitepaper §7.3.2 statement 5:
//!
//! > Range proofs. Every value in the transaction lies in
//! > `[0, 2^64)`. Without this, an attacker could create notes
//! > with negative values that nominally satisfy value
//! > conservation while creating value.
//!
//! # Construction
//!
//! Bit-decomposition approach:
//!
//! 1. Witness 64 bits `b_0, b_1, …, b_63` (each a
//!    `pallas::Base` element).
//! 2. Constrain each `b_i ∈ {0, 1}` (binary check via
//!    `b_i * (1 - b_i) == 0`).
//! 3. Constrain `value == Σ b_i * 2^i` (linear-combination
//!    check).
//!
//! Both constraints fire under a single custom gate per bit
//! row plus a single linear-combination gate at the end.
//!
//! # No public input
//!
//! The standalone circuit takes `value` as a witness and
//! emits no public inputs — the proof attests "I know a value
//! in `[0, 2^64)`". Phase 6.8b.4e composition wires the
//! `value` cell from this sub-circuit's witness to the
//! corresponding `value` input of the
//! [`crate::NoteCommitmentCircuit`] (or its in-circuit
//! equivalent), so the range-check binds the same `value`
//! that flows into the note commitment.
//!
//! # Statement 4 (value conservation) — design pending
//!
//! Whitepaper §7.3.2 statement 4 requires per-asset-type
//! value conservation: `sum(inputs) == sum(outputs) + fees`,
//! grouped by asset type. The current §7.1 Poseidon-based
//! note commitment is NOT homomorphic, so multi-asset multi-
//! value conservation requires an additional value-
//! commitment scheme (e.g., Pedersen value commitments on
//! Pallas, parallel to Zcash Sapling/Orchard). The spec
//! does not currently pin which scheme. Phase 6.8b.4d-2
//! ships the conservation circuit once the spec author
//! resolves the question; this sub-arc covers only the
//! range-proof half (statement 5).

use std::marker::PhantomData;

use adamant_halo2::proofs::circuit::{AssignedCell, Layouter, Region, SimpleFloorPlanner, Value};
use adamant_halo2::proofs::pasta::pallas;
use adamant_halo2::proofs::plonk::{
    Advice, Circuit, Column, ConstraintSystem, Constraints, Error as PlonkError, Expression,
    Selector,
};
use adamant_halo2::proofs::poly::Rotation;
use pasta_curves::group::ff::Field;

/// Bit width of the range proof. Per whitepaper §7.1's note
/// `value: u64` field and §7.3.2 statement 5's `[0, 2^64)`
/// range, this is fixed at 64.
pub const RANGE_BITS: usize = 64;

/// In-circuit witness for a single 64-bit range proof.
#[derive(Clone, Copy, Debug)]
pub struct RangeCheck64Witness {
    /// The value being range-checked. Encoded as a
    /// `pallas::Base` element with `pallas::Base::from(u64)`
    /// by the caller.
    pub value: Value<pallas::Base>,
    /// 64 bit-witnesses. Each must be `0` or `1`. The circuit
    /// constrains `Σ bits[i] * 2^i == value`. Callers compute
    /// the bit decomposition off-circuit; this module's
    /// helper [`u64_to_bit_witnesses`] does it.
    pub bits: [Value<pallas::Base>; RANGE_BITS],
}

impl Default for RangeCheck64Witness {
    fn default() -> Self {
        Self {
            value: Value::unknown(),
            bits: [Value::unknown(); RANGE_BITS],
        }
    }
}

/// Convert a `u64` into a [`RangeCheck64Witness`] with the
/// canonical low-bit-first bit decomposition.
#[must_use]
pub fn u64_to_bit_witnesses(value: u64) -> RangeCheck64Witness {
    let mut bits = [Value::unknown(); RANGE_BITS];
    for (i, bit) in bits.iter_mut().enumerate() {
        let b = (value >> i) & 1;
        *bit = Value::known(pallas::Base::from(b));
    }
    RangeCheck64Witness {
        value: Value::known(pallas::Base::from(value)),
        bits,
    }
}

/// Configuration for [`RangeCheck64Circuit`].
#[derive(Clone, Debug)]
pub struct RangeCheck64Config {
    /// Advice column carrying the value being range-checked
    /// (single row).
    pub value_col: Column<Advice>,
    /// Advice column carrying the 64 bit witnesses (one per
    /// row, rows 0..64).
    pub bits_col: Column<Advice>,
    /// Selector enabling the per-row binary check
    /// (`bits_col_cur * (1 - bits_col_cur) == 0`).
    pub q_bit: Selector,
    /// Selector enabling the value-decomposition gate that
    /// fires at row 0 of `value_col`. The gate constrains
    /// `value == Σ bits[i] * 2^i` by querying all 64 bit-
    /// rows via `Rotation(i as i32)`.
    pub q_decompose: Selector,
}

/// The 64-bit range-proof validity circuit per whitepaper
/// §7.3.2 statement 5.
#[derive(Clone, Copy, Debug, Default)]
pub struct RangeCheck64Circuit {
    /// Witness inputs.
    pub witness: RangeCheck64Witness,
    /// `PhantomData` reserved for future generic parameters
    /// (e.g., a smaller bit width). Currently the circuit is
    /// monomorphic on `RANGE_BITS = 64` per §7.1.
    _spec: PhantomData<()>,
}

impl RangeCheck64Circuit {
    /// Construct a circuit instance from a fully-known witness.
    #[must_use]
    pub const fn new(witness: RangeCheck64Witness) -> Self {
        Self {
            witness,
            _spec: PhantomData,
        }
    }

    /// Build a circuit from a `u64` directly (uses
    /// [`u64_to_bit_witnesses`] for the bit decomposition).
    #[must_use]
    pub fn from_u64(value: u64) -> Self {
        Self::new(u64_to_bit_witnesses(value))
    }
}

impl Circuit<pallas::Base> for RangeCheck64Circuit {
    type Config = RangeCheck64Config;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<pallas::Base>) -> Self::Config {
        let value_col = meta.advice_column();
        let bits_col = meta.advice_column();
        let q_bit = meta.selector();
        let q_decompose = meta.selector();

        meta.enable_equality(value_col);
        meta.enable_equality(bits_col);

        // Per-bit binary check: `bits_col_cur * (1 - bits_col_cur) = 0`.
        meta.create_gate("bit is 0 or 1", |meta| {
            let q = meta.query_selector(q_bit);
            let b = meta.query_advice(bits_col, Rotation::cur());
            let one = Expression::Constant(pallas::Base::ONE);
            Constraints::with_selector(q, [("b * (1 - b)", b.clone() * (one - b))])
        });

        // Value-decomposition gate, fires at row 0 of
        // `value_col`. Queries `bits_col` at rotations 0..63
        // (the 64 bit rows) and constrains
        // `value == Σ bits[i] * 2^i`.
        meta.create_gate("value = Σ b_i * 2^i", |meta| {
            let q = meta.query_selector(q_decompose);
            let value = meta.query_advice(value_col, Rotation::cur());
            let mut acc = Expression::Constant(pallas::Base::ZERO);
            for i in 0..RANGE_BITS {
                let b = meta.query_advice(
                    bits_col,
                    // `i ∈ [0, 64)`; the cast is safe and the
                    // Rotation constructor takes `i32`.
                    #[allow(clippy::cast_possible_wrap, clippy::cast_possible_truncation)]
                    Rotation(i as i32),
                );
                // Bit weight: `2^i` as a `pallas::Base` element.
                // `1u64 << i` works for i ∈ [0, 63] (the loop
                // range); for i = 63 the result is `2^63` which
                // fits in u64.
                let weight = pallas::Base::from(1u64 << i);
                acc = acc + b * Expression::Constant(weight);
            }
            Constraints::with_selector(q, [("value == bit decomposition", value - acc)])
        });

        RangeCheck64Config {
            value_col,
            bits_col,
            q_bit,
            q_decompose,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<pallas::Base>,
    ) -> Result<(), PlonkError> {
        layouter.assign_region(
            || "range-check 64",
            |mut region: Region<'_, pallas::Base>| {
                // Row 0: the value cell + the value-decomposition
                // selector. The same row is also bit_0's row in
                // `bits_col`.
                let _value_cell =
                    region.assign_advice(|| "value", config.value_col, 0, || self.witness.value)?;
                config.q_decompose.enable(&mut region, 0)?;

                // Rows 0..64: the 64 bits in `bits_col`, each
                // with the `q_bit` selector enabled.
                for (i, bit_witness) in self.witness.bits.iter().enumerate() {
                    region.assign_advice(
                        || format!("bit_{i}"),
                        config.bits_col,
                        i,
                        || *bit_witness,
                    )?;
                    config.q_bit.enable(&mut region, i)?;
                }

                Ok(())
            },
        )?;
        Ok(())
    }
}

/// Helper: range-check an existing [`AssignedCell`] in a
/// caller-supplied layouter without going through the full
/// `Circuit` trait. Useful for composition at Phase 6.8b.4e.
///
/// The caller supplies the value cell + the bit-witness
/// values; this function lays out a fresh region containing
/// the bit-decomposition gate and copy-constrains the input
/// cell into the region's `value` row.
///
/// # Errors
///
/// Returns the synthesis error if region assignment fails.
pub fn range_check_64bit_cell(
    config: &RangeCheck64Config,
    mut layouter: impl Layouter<pallas::Base>,
    value_cell: &AssignedCell<pallas::Base, pallas::Base>,
    bits: [Value<pallas::Base>; RANGE_BITS],
) -> Result<(), PlonkError> {
    layouter.assign_region(
        || "range-check 64 (composed)",
        |mut region: Region<'_, pallas::Base>| {
            let region_value_cell = region.assign_advice(
                || "value (composed copy)",
                config.value_col,
                0,
                || value_cell.value().copied(),
            )?;
            // Copy-constrain the caller's cell to the region's
            // value cell so they bind to the same field-element
            // value.
            region.constrain_equal(value_cell.cell(), region_value_cell.cell())?;
            config.q_decompose.enable(&mut region, 0)?;

            for (i, bit_witness) in bits.iter().enumerate() {
                region.assign_advice(|| format!("bit_{i}"), config.bits_col, i, || *bit_witness)?;
                config.q_bit.enable(&mut region, i)?;
            }
            Ok(())
        },
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use adamant_halo2::proofs::dev::MockProver;

    /// `K = 8` fits the 64-bit decomposition. Empirically:
    /// `K = 7` (`2^7 = 128` rows) trips
    /// `NotEnoughRowsAvailable` because Halo 2 reserves a
    /// chunk of rows for blinding plus accounting overhead;
    /// `K = 8` (`2^8 = 256` rows) runs cleanly. The 64
    /// bit rows + 1 value row + Halo 2's reserved overhead
    /// fit inside the K = 8 budget.
    const K: u32 = 8;

    /// Positive cases at boundary values: 0, 1, 2^64 - 1, plus
    /// some interior points.
    #[test]
    fn range_check_accepts_zero() {
        let circuit = RangeCheck64Circuit::from_u64(0);
        let prover = MockProver::run(K, &circuit, vec![]).expect("MockProver runs cleanly");
        assert_eq!(prover.verify(), Ok(()));
    }

    #[test]
    fn range_check_accepts_one() {
        let circuit = RangeCheck64Circuit::from_u64(1);
        let prover = MockProver::run(K, &circuit, vec![]).expect("MockProver runs cleanly");
        assert_eq!(prover.verify(), Ok(()));
    }

    #[test]
    fn range_check_accepts_max_u64() {
        let circuit = RangeCheck64Circuit::from_u64(u64::MAX);
        let prover = MockProver::run(K, &circuit, vec![]).expect("MockProver runs cleanly");
        assert_eq!(prover.verify(), Ok(()));
    }

    #[test]
    fn range_check_accepts_typical_interior() {
        for v in [42u64, 1_000_000_000, 0xDEAD_BEEF_DEAD_BEEF] {
            let circuit = RangeCheck64Circuit::from_u64(v);
            let prover = MockProver::run(K, &circuit, vec![]).expect("MockProver runs cleanly");
            assert_eq!(
                prover.verify(),
                Ok(()),
                "v = {v} should pass the range check"
            );
        }
    }

    /// Negative case: bit decomposition doesn't sum to the
    /// claimed value.
    #[test]
    fn range_check_rejects_inconsistent_bit_decomposition() {
        let mut witness = u64_to_bit_witnesses(42);
        // Flip the value but keep the bit decomposition for 42.
        witness.value = Value::known(pallas::Base::from(43u64));
        let circuit = RangeCheck64Circuit::new(witness);
        let prover = MockProver::run(K, &circuit, vec![]).expect("MockProver runs cleanly");
        assert!(
            prover.verify().is_err(),
            "inconsistent value vs bit decomposition must be rejected"
        );
    }

    /// Negative case: a "bit" witness is set to 2 (not binary).
    #[test]
    fn range_check_rejects_non_binary_bit() {
        let mut witness = u64_to_bit_witnesses(0);
        witness.bits[0] = Value::known(pallas::Base::from(2u64));
        // Adjust the value so the linear-combination
        // constraint would otherwise pass — `value == 2 * 1 = 2`
        // would be consistent if 2 were binary.
        witness.value = Value::known(pallas::Base::from(2u64));
        let circuit = RangeCheck64Circuit::new(witness);
        let prover = MockProver::run(K, &circuit, vec![]).expect("MockProver runs cleanly");
        assert!(
            prover.verify().is_err(),
            "non-binary bit must be rejected by the bit-binary gate"
        );
    }

    /// Negative case: a value larger than 2^64 cannot be
    /// represented by the 64-bit decomposition. We construct a
    /// witness where the value is 2^64 (one too large) and the
    /// bit decomposition is all zero plus an attempt to satisfy
    /// the constraint.
    #[test]
    fn range_check_rejects_value_exceeding_2_to_64() {
        // 2^64 = 18446744073709551616 — outside `u64`. Construct
        // as a `pallas::Base` element directly.
        let two_to_64 = pallas::Base::from(2u64).pow_vartime([64u64]);
        let mut witness = RangeCheck64Witness {
            value: Value::known(two_to_64),
            bits: [Value::known(pallas::Base::ZERO); RANGE_BITS],
        };
        // Try setting the highest bit to 1 — but bit 63 has
        // weight 2^63, so all bits = 1 gives 2^64 - 1, still
        // less than 2^64. There's NO 64-bit decomposition that
        // sums to 2^64; the linear-combination gate will fail.
        for b in &mut witness.bits {
            *b = Value::known(pallas::Base::ONE);
        }
        // Now the bit-sum is 2^64 - 1, but the value claims 2^64.
        let circuit = RangeCheck64Circuit::new(witness);
        let prover = MockProver::run(K, &circuit, vec![]).expect("MockProver runs cleanly");
        assert!(
            prover.verify().is_err(),
            "2^64 cannot be represented in 64 bits; circuit must reject"
        );
    }

    /// Pin the `RANGE_BITS` constant — a change here is
    /// hard-fork-grade per §7.1's `value: u64` field.
    #[test]
    fn range_bits_pinned_at_64() {
        assert_eq!(RANGE_BITS, 64);
    }

    /// `u64_to_bit_witnesses` round-trip: extract the bits
    /// and reconstruct the value via the same `Σ bit * 2^i`
    /// formula the circuit uses.
    #[test]
    fn u64_bit_witness_round_trip() {
        for v in [0u64, 1, 42, u64::MAX, 0xCAFE_BABE_DEAD_BEEF] {
            let witness = u64_to_bit_witnesses(v);
            let mut reconstructed: u64 = 0;
            for (i, bit) in witness.bits.iter().enumerate() {
                bit.map(|b| {
                    if b == pallas::Base::ONE {
                        reconstructed |= 1u64 << i;
                    }
                });
            }
            assert_eq!(reconstructed, v, "bit decomposition round-trips for {v}");
        }
    }

    /// Default-witness keygen-shape check.
    #[test]
    fn default_witness_keygen_shape() {
        let _circuit = RangeCheck64Circuit::default();
    }
}
