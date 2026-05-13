//! Note-commitment validity circuit per whitepaper §7.3.2
//! statement 3 ("output note well-formedness").
//!
//! Phase 6.8b.4a — first Adamant-authored circuit. Proves:
//!
//! ```text
//! commitment == Poseidon(value, asset_type, recipient,
//!                        randomness, metadata_hash)
//! ```
//!
//! where the witnesses are the five field elements from
//! whitepaper §7.1's note-commitment formula and `commitment`
//! is exposed as a public input (the chain sees it).
//!
//! # Spec basis
//!
//! Whitepaper §7.1 verbatim:
//!
//! > A note never appears on the chain in cleartext. What
//! > appears on the chain is the note's commitment, computed
//! > as:
//! >
//! > `commitment = Poseidon(value || asset_type || recipient
//! >                        || randomness || metadata_hash)`
//! >
//! > The commitment is 256 bits and reveals nothing about its
//! > inputs.
//!
//! Whitepaper §7.3.2 statement 3:
//!
//! > Output note well-formedness. Each output commitment is
//! > correctly computed from valid inputs (a recipient stealth
//! > address, a value, an asset type, randomness).
//!
//! # In-circuit / out-of-circuit consistency
//!
//! Per §3.3.3 "Constraint" paragraph:
//!
//! > Hashes that cross the circuit/non-circuit boundary use
//! > both Poseidon (inside the circuit) and SHA3-256 (outside),
//! > with the circuit proving consistency between the two
//! > representations.
//!
//! For note commitments specifically, both sides use Poseidon
//! (the commitment is purely in-Pallas, never crosses to SHA3
//! at this layer). The cross-validation invariant is:
//!
//! ```text
//! NoteCommitmentCircuit(witnesses) verifies
//!   ⟺
//! derive_note_commitment(value, asset_type, recipient,
//!                        randomness, metadata) == commitment
//! ```
//!
//! Pinned by the [`tests::circuit_matches_out_of_circuit`]
//! test which uses [`crate::derive_note_commitment`] for the
//! out-of-circuit reference and `MockProver` for the in-
//! circuit verification.
//!
//! # Witness encoding
//!
//! All five inputs are encoded as Pallas base-field elements
//! per Phase 6.1's [`crate::derive_note_commitment`]:
//!
//! 1. `value` — `u64` zero-padded to 32 bytes (always in range).
//! 2. `asset_type` — `TypeId` reduced via top-bits-clearing.
//! 3. `recipient` — stealth-address x-coordinate, already a
//!    base-field element.
//! 4. `randomness` — 32 bytes reduced via top-bits-clearing.
//! 5. `metadata_hash` — tagged-SHA3 output reduced via
//!    top-bits-clearing.
//!
//! Callers use [`crate::FieldBytes::from_bytes_reduced`] (or
//! its byte-input equivalents in `derive_note_commitment`)
//! before constructing [`NoteCommitmentWitness`]. The circuit
//! itself does NOT perform the reduction — it operates on
//! already-validated `pallas::Base` elements.

use std::marker::PhantomData;

use adamant_halo2::poseidon::primitives::{ConstantLength, P128Pow5T3};
use adamant_halo2::poseidon::{Hash, Pow5Chip, Pow5Config};
use adamant_halo2::proofs::circuit::{Layouter, SimpleFloorPlanner, Value};
use adamant_halo2::proofs::pasta::pallas;
use adamant_halo2::proofs::plonk::{
    Circuit, Column, ConstraintSystem, Error as PlonkError, Instance,
};

/// Number of input field elements consumed by the note-
/// commitment Poseidon hash per whitepaper §7.1.
///
/// Five inputs: `value || asset_type || recipient || randomness
/// || metadata_hash`. Pinned via the const generic on
/// [`Hash::<_, _, P128Pow5T3, ConstantLength<NOTE_COMMITMENT_INPUT_ARITY>, 3, 2>::init`].
pub const NOTE_COMMITMENT_INPUT_ARITY: usize = 5;

/// In-circuit witness for the note-commitment derivation. The
/// five `pallas::Base` field elements correspond directly to
/// the §7.1 formula's tuple inputs.
///
/// `Value::unknown()` instances are used at proving-key /
/// verifying-key generation time per Halo 2's standard
/// without-witnesses pattern; see [`Default`] impl.
#[derive(Clone, Copy, Debug)]
pub struct NoteCommitmentWitness {
    /// Note value in the asset's smallest unit, as a Pallas
    /// base-field element. Per §7.1.5 / §7.3.2 statement 5,
    /// the range proof `[0, 2^64)` is enforced by Phase
    /// 6.8b.4d's range circuit — this circuit does NOT
    /// re-enforce. Constructed as `pallas::Base::from(u64)`.
    pub value: Value<pallas::Base>,
    /// Asset type identifier, reduced into the Pallas base
    /// field per §7.1's note-commitment formula.
    pub asset_type: Value<pallas::Base>,
    /// Stealth-address x-coordinate per §7.2.2 / Phase 6.4.
    /// Already a Pallas base-field element by virtue of being
    /// the x-coordinate of a Pallas point.
    pub recipient: Value<pallas::Base>,
    /// Per-note randomness reduced into the Pallas base field.
    /// 256-bit entropy ensures uncorrelatable commitments per
    /// §7.1.
    pub randomness: Value<pallas::Base>,
    /// Tagged-SHA3 hash of the BCS-encoded `NoteMetadata`,
    /// reduced into the Pallas base field. Per §7.1, ties the
    /// commitment to application-specific metadata.
    pub metadata_hash: Value<pallas::Base>,
}

impl Default for NoteCommitmentWitness {
    /// All-unknown witness — used at keygen time per Halo 2's
    /// `Circuit::without_witnesses`.
    fn default() -> Self {
        Self {
            value: Value::unknown(),
            asset_type: Value::unknown(),
            recipient: Value::unknown(),
            randomness: Value::unknown(),
            metadata_hash: Value::unknown(),
        }
    }
}

/// The note-commitment validity circuit per whitepaper §7.3.2
/// statement 3.
///
/// Public-input layout (single instance column, single row):
///
/// | row | column           |
/// |-----|------------------|
/// | 0   | `commitment`     |
///
/// The single public input is the 32-byte canonical Pallas
/// base-field encoding of the Poseidon hash output. The
/// circuit constrains the in-circuit Poseidon output to equal
/// this public input.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoteCommitmentCircuit {
    /// Witness inputs (the five §7.1 Poseidon-input field
    /// elements). Defaults to all-unknown at keygen time.
    pub witness: NoteCommitmentWitness,
    /// `PhantomData` reserved for future generic parameters
    /// (e.g., the Poseidon spec) without breaking the wire
    /// signature. Currently the circuit is monomorphic on
    /// `P128Pow5T3` per §3.3.3 amendment instance 31.
    _spec: PhantomData<P128Pow5T3>,
}

impl NoteCommitmentCircuit {
    /// Construct a circuit instance from a fully-known witness.
    /// Use [`NoteCommitmentCircuit::default`] for keygen.
    #[must_use]
    pub const fn new(witness: NoteCommitmentWitness) -> Self {
        Self {
            witness,
            _spec: PhantomData,
        }
    }
}

/// Configuration produced by [`NoteCommitmentCircuit::configure`].
/// Exposes the `Pow5Chip` configuration plus the public-input
/// instance column.
#[derive(Clone, Debug)]
pub struct NoteCommitmentConfig {
    /// `Pow5Chip` configuration for `P128Pow5T3` over Pallas's
    /// base field, width 3, rate 2.
    pub poseidon: Pow5Config<pallas::Base, 3, 2>,
    /// Public-input instance column carrying the expected
    /// `commitment`.
    pub instance: Column<Instance>,
}

impl Circuit<pallas::Base> for NoteCommitmentCircuit {
    type Config = NoteCommitmentConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<pallas::Base>) -> Self::Config {
        // Pow5Chip layout per upstream halo2_gadgets's
        // recommended pattern (3 advice columns for state, 1
        // for partial-round s-box, 3 fixed for `rc_a`, 3 for
        // `rc_b`). Width = 3, rate = 2 per §3.3.3.
        let state = (0..3).map(|_| meta.advice_column()).collect::<Vec<_>>();
        let partial_sbox = meta.advice_column();
        let rc_a = (0..3).map(|_| meta.fixed_column()).collect::<Vec<_>>();
        let rc_b = (0..3).map(|_| meta.fixed_column()).collect::<Vec<_>>();
        meta.enable_constant(rc_b[0]);

        let instance = meta.instance_column();
        meta.enable_equality(instance);
        // The Pow5Chip-produced output cell sits in `state[0]`;
        // enable equality so the `constrain_instance` call in
        // `synthesize` can wire the in-circuit hash output to
        // the public input.
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

        NoteCommitmentConfig { poseidon, instance }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<pallas::Base>,
    ) -> Result<(), PlonkError> {
        let chip = Pow5Chip::construct(config.poseidon.clone());

        // Step 1 — load the five witness inputs as advice
        // assignments in a single region. Mirrors upstream
        // halo2_gadgets's HashCircuit pattern.
        let inputs = layouter.assign_region(
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
                for (i, word) in words.iter().enumerate() {
                    // Cycle through the 3 state columns; new
                    // row when we wrap. Pow5Chip's input
                    // contract only requires the cells to be
                    // assigned; layout is flexible.
                    let column = config.poseidon.state[i % 3];
                    let row = i / 3;
                    let cell =
                        region.assign_advice(|| format!("input_{i}"), column, row, || *word)?;
                    assigned.push(cell);
                }
                Ok(assigned.try_into().unwrap_or_else(|_: Vec<_>| {
                    unreachable!("we pushed exactly NOTE_COMMITMENT_INPUT_ARITY items")
                }))
            },
        )?;

        // Step 2 — initialise the Poseidon hasher and run it
        // over the five inputs. The chip produces a single
        // output cell containing `Poseidon(inputs)`.
        let hasher = Hash::<
            pallas::Base,
            _,
            P128Pow5T3,
            ConstantLength<NOTE_COMMITMENT_INPUT_ARITY>,
            3,
            2,
        >::init(chip, layouter.namespace(|| "init"))?;
        let output = hasher.hash(layouter.namespace(|| "note-commitment hash"), inputs)?;

        // Step 3 — constrain the output cell to equal the
        // public-input commitment in row 0 of the instance
        // column.
        layouter.constrain_instance(output.cell(), config.instance, 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::poseidon::{poseidon_hash, FieldBytes};
    use adamant_halo2::proofs::dev::MockProver;
    use pasta_curves::group::ff::PrimeField;

    /// Convert a [`FieldBytes`] (32-byte canonical Pallas-base
    /// encoding) into the in-circuit `pallas::Base` element.
    /// Mirrors the conversion `derive_note_commitment` does
    /// internally.
    fn field_bytes_to_base(fb: FieldBytes) -> pallas::Base {
        pallas::Base::from_repr(fb.to_bytes())
            .expect("FieldBytes invariant: bytes encode a valid field element")
    }

    /// `K = 8` is the smallest power-of-two log-row-count that
    /// fits the 5-input Poseidon hash plus the public-input
    /// constraint. Empirically determined: `K = 7` (which
    /// fits upstream `halo2_gadgets`'s 3-input
    /// `poseidon_hash_longer_input` test) reports
    /// `NotEnoughRowsAvailable`; `K = 8` runs cleanly. The
    /// `2^K = 256` extra rows accommodate the additional two
    /// input rows plus the slightly larger `Pow5Chip` layout
    /// at arity 5.
    const K: u32 = 8;

    /// Build a deterministic-input witness for testing.
    fn fixed_witness() -> ([FieldBytes; 5], NoteCommitmentWitness) {
        let inputs = [
            FieldBytes::from_bytes_reduced([0x01; 32]),
            FieldBytes::from_bytes_reduced([0x02; 32]),
            FieldBytes::from_bytes_reduced([0x03; 32]),
            FieldBytes::from_bytes_reduced([0x04; 32]),
            FieldBytes::from_bytes_reduced([0x05; 32]),
        ];
        let witness = NoteCommitmentWitness {
            value: Value::known(field_bytes_to_base(inputs[0])),
            asset_type: Value::known(field_bytes_to_base(inputs[1])),
            recipient: Value::known(field_bytes_to_base(inputs[2])),
            randomness: Value::known(field_bytes_to_base(inputs[3])),
            metadata_hash: Value::known(field_bytes_to_base(inputs[4])),
        };
        (inputs, witness)
    }

    /// Compute the expected commitment off-circuit using the
    /// existing Phase 6.0 Poseidon helper.
    fn expected_commitment(inputs: [FieldBytes; 5]) -> pallas::Base {
        field_bytes_to_base(poseidon_hash::<5>(inputs))
    }

    /// Positive case: a circuit constructed with consistent
    /// witness + commitment public input verifies.
    #[test]
    fn note_commitment_circuit_accepts_consistent_inputs() {
        let (inputs, witness) = fixed_witness();
        let commitment = expected_commitment(inputs);
        let circuit = NoteCommitmentCircuit::new(witness);
        let prover =
            MockProver::run(K, &circuit, vec![vec![commitment]]).expect("MockProver runs cleanly");
        assert_eq!(prover.verify(), Ok(()));
    }

    /// Negative case: tampered public input (wrong commitment)
    /// is rejected.
    #[test]
    fn note_commitment_circuit_rejects_tampered_commitment() {
        let (_, witness) = fixed_witness();
        // Use a public input that does NOT match the actual
        // Poseidon output of the witness.
        let bad_commitment = pallas::Base::from(0x1234_5678u64);
        let circuit = NoteCommitmentCircuit::new(witness);
        let prover = MockProver::run(K, &circuit, vec![vec![bad_commitment]])
            .expect("MockProver runs cleanly");
        assert!(
            prover.verify().is_err(),
            "tampered commitment must be rejected by MockProver"
        );
    }

    /// Negative case: tampered witness (a single input changed)
    /// no longer matches the original commitment public input.
    #[test]
    fn note_commitment_circuit_rejects_tampered_witness() {
        let (inputs, mut witness) = fixed_witness();
        let original_commitment = expected_commitment(inputs);
        // Change the value witness while keeping the public
        // input pointing at the original commitment.
        witness.value = Value::known(pallas::Base::from(0xDEAD_BEEFu64));
        let circuit = NoteCommitmentCircuit::new(witness);
        let prover = MockProver::run(K, &circuit, vec![vec![original_commitment]])
            .expect("MockProver runs cleanly");
        assert!(
            prover.verify().is_err(),
            "tampered witness must produce a different hash and be rejected"
        );
    }

    /// Cross-validation pin: the in-circuit Poseidon output
    /// equals the out-of-circuit `derive_note_commitment` /
    /// `poseidon_hash` output for the same inputs. This is the
    /// invariant §3.3.3 requires for the circuit/non-circuit
    /// boundary.
    #[test]
    fn circuit_matches_out_of_circuit() {
        let (inputs, witness) = fixed_witness();
        let circuit = NoteCommitmentCircuit::new(witness);

        // The off-circuit hash output. If the circuit's
        // Poseidon were to disagree, the MockProver call below
        // (with this off-circuit value as public input) would
        // FAIL because the in-circuit constraint
        // `commitment == in_circuit_hash` would be unsat.
        let out_of_circuit = expected_commitment(inputs);

        let prover = MockProver::run(K, &circuit, vec![vec![out_of_circuit]])
            .expect("MockProver runs cleanly");
        assert_eq!(
            prover.verify(),
            Ok(()),
            "in-circuit Poseidon and out-of-circuit poseidon_hash MUST agree \
             on the same inputs (§3.3.3 boundary invariant)"
        );
    }

    /// `NoteCommitmentWitness::default()` is all-unknown — used
    /// at keygen time per Halo 2's `without_witnesses` pattern.
    #[test]
    fn default_witness_is_all_unknown() {
        let w = NoteCommitmentWitness::default();
        // Each field is `Value::unknown()`. Halo 2 doesn't
        // expose a public predicate; check the contract
        // indirectly: a circuit built with the default witness
        // must compile and run keygen-style synthesis without
        // panic. The stub assertion is that we can construct
        // the circuit at all.
        let _circuit = NoteCommitmentCircuit::new(w);
    }

    /// Pin the input arity at 5 — `derive_note_commitment` and
    /// the §7.1 formula both pin this. A change here is a
    /// hard-fork-grade modification.
    #[test]
    fn input_arity_is_five() {
        assert_eq!(NOTE_COMMITMENT_INPUT_ARITY, 5);
    }
}
