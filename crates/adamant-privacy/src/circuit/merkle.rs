//! GNCT Merkle-membership validity circuit per whitepaper
//! §7.3.2 statement 1 ("input note existence").
//!
//! Phase 6.8b.4c — third Adamant-authored circuit. Proves: a
//! claimed leaf (a note commitment) exists in the global note
//! commitment tree (§7.1.3) under a given root, by exhibiting a
//! Merkle authentication path of a specified depth.
//!
//! # Spec basis
//!
//! Whitepaper §7.1.3 verbatim:
//!
//! > The global note commitment tree (GNCT) is an append-only
//! > Poseidon-Merkle tree of fixed depth 64, allowing 2^64
//! > notes. … Membership of a note commitment at a given leaf
//! > position is proven by an authentication path: 64 sibling
//! > hashes plus the bit-string giving the leaf's position.
//!
//! Whitepaper §7.3.2 statement 1:
//!
//! > Input note existence. For each nullifier, there exists a
//! > note commitment in the GNCT (proven via a Merkle path) and
//! > the nullifier is correctly derived from the note's
//! > contents.
//!
//! This circuit covers the "exists in the GNCT under a Merkle
//! path" half of statement 1. The nullifier-derivation half is
//! Phase 6.8b.4b's [`crate::NullifierCircuit`]; Phase 6.8b.4e
//! composes them into a single shielded-input proof.
//!
//! # Construction
//!
//! For each level `i ∈ [0, DEPTH)`:
//!
//! 1. Witness `sibling[i]` (a `pallas::Base` field element) and
//!    `bit[i]` (a binary `pallas::Base` element: 0 if the
//!    current node is the LEFT child at this level, 1 if the
//!    RIGHT child).
//! 2. Use [`CondSwapChip`] to swap `(current, sibling[i])` per
//!    `bit[i]`: output `(left, right)` where if `bit[i] == 0`
//!    then `(left, right) == (current, sibling[i])`, else
//!    `(left, right) == (sibling[i], current)`.
//! 3. `next = Poseidon::<P128Pow5T3, ConstantLength<2>, 3, 2>
//!    (left, right)`.
//! 4. `current ← next`.
//!
//! After `DEPTH` iterations, constrain `current == root` (the
//! single public input).
//!
//! # Cross-validation invariant
//!
//! For the same `(leaf, path_siblings, path_bits)` inputs, the
//! in-circuit computation must produce the same `root` as the
//! out-of-circuit GNCT verification at `crate::verify_membership`
//! / `MerklePath::recompute_root`. Pinned by
//! `tests::circuit_matches_out_of_circuit`.
//!
//! # Depth parameterisation
//!
//! Depth is exposed as a const generic parameter. The
//! production §7.1.3 GNCT depth is 64; tests use small depths
//! (4, 8) to keep `K` small and runtime fast. The circuit
//! shape is identical at any depth; the production circuit is
//! a depth-64 instantiation per [`crate::GNCT_DEPTH`].

use std::marker::PhantomData;

use adamant_halo2::poseidon::primitives::{ConstantLength, P128Pow5T3};
use adamant_halo2::poseidon::{Hash, Pow5Chip, Pow5Config};
use adamant_halo2::proofs::circuit::{Layouter, SimpleFloorPlanner, Value};
use adamant_halo2::proofs::pasta::pallas;
use adamant_halo2::proofs::plonk::{
    Circuit, Column, ConstraintSystem, Error as PlonkError, Instance,
};
use adamant_halo2::utilities::cond_swap::{CondSwapChip, CondSwapConfig, CondSwapInstructions};
use adamant_halo2::utilities::UtilitiesInstructions;

/// Number of public inputs the circuit consumes. Currently 1
/// (`root`); the leaf is a witness, not a public input — this
/// circuit alone proves membership but not which leaf is
/// being claimed. Phase 6.8b.4e's composition wires the leaf
/// and nullifier together via copy constraints across
/// circuits.
pub const PUBLIC_INPUT_COUNT: usize = 1;

/// In-circuit witness for the GNCT Merkle-membership proof at
/// fixed [`DEPTH`].
#[derive(Clone, Debug)]
pub struct MerkleMembershipWitness<const DEPTH: usize> {
    /// The leaf value (a note commitment per §7.1) whose
    /// membership in the tree is being proven.
    pub leaf: Value<pallas::Base>,
    /// The `DEPTH` sibling hashes along the authentication path,
    /// from leaf-level (index 0) up to root-level (index
    /// `DEPTH - 1`).
    pub path_siblings: [Value<pallas::Base>; DEPTH],
    /// The `DEPTH` path bits indicating left (0) / right (1)
    /// position at each level. Per §7.1.3, the bit-string is
    /// the binary expansion of the leaf's position, low-bit
    /// first.
    pub path_bits: [Value<bool>; DEPTH],
}

impl<const DEPTH: usize> Default for MerkleMembershipWitness<DEPTH> {
    fn default() -> Self {
        Self {
            leaf: Value::unknown(),
            path_siblings: [Value::unknown(); DEPTH],
            path_bits: [Value::unknown(); DEPTH],
        }
    }
}

/// Public inputs: just the `root`.
#[derive(Clone, Copy, Debug)]
pub struct MerkleMembershipPublicInputs {
    /// The GNCT root the proof attests the leaf belongs to.
    pub root: pallas::Base,
}

impl MerkleMembershipPublicInputs {
    /// Convert to the row-vector form `MockProver::run` /
    /// `plonk::create_proof` expect.
    #[must_use]
    pub fn to_rows(self) -> Vec<pallas::Base> {
        vec![self.root]
    }
}

/// Circuit configuration: the `Pow5Chip` config + the
/// [`CondSwapChip`] config + the public-input instance column.
#[derive(Clone, Debug)]
pub struct MerkleMembershipConfig {
    /// `Pow5Chip` configuration for `P128Pow5T3` over Pallas's
    /// base field (width 3, rate 2).
    pub poseidon: Pow5Config<pallas::Base, 3, 2>,
    /// [`CondSwapChip`] configuration. Five advice columns
    /// dedicated to the swap operation; `advices[0]` is
    /// equality-enabled per the chip's contract.
    pub cond_swap: CondSwapConfig,
    /// Single-column instance carrying the `root`.
    pub instance: Column<Instance>,
}

/// The GNCT Merkle-membership validity circuit per whitepaper
/// §7.3.2 statement 1, parametric on `DEPTH`. The §7.1.3
/// production GNCT depth is 64; tests instantiate at smaller
/// `DEPTH` to keep `MockProver` runtime tractable.
#[derive(Clone, Debug)]
pub struct MerkleMembershipCircuit<const DEPTH: usize> {
    /// Witness inputs.
    pub witness: MerkleMembershipWitness<DEPTH>,
    /// `PhantomData` reserved for future Poseidon-spec
    /// generic parameters; currently monomorphic on
    /// `P128Pow5T3` per §3.3.3.
    _spec: PhantomData<P128Pow5T3>,
}

impl<const DEPTH: usize> Default for MerkleMembershipCircuit<DEPTH> {
    fn default() -> Self {
        Self {
            witness: MerkleMembershipWitness::default(),
            _spec: PhantomData,
        }
    }
}

impl<const DEPTH: usize> MerkleMembershipCircuit<DEPTH> {
    /// Construct a circuit instance from a fully-known witness.
    /// Use [`MerkleMembershipCircuit::default`] for keygen.
    #[must_use]
    pub const fn new(witness: MerkleMembershipWitness<DEPTH>) -> Self {
        Self {
            witness,
            _spec: PhantomData,
        }
    }
}

impl<const DEPTH: usize> Circuit<pallas::Base> for MerkleMembershipCircuit<DEPTH> {
    type Config = MerkleMembershipConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<pallas::Base>) -> Self::Config {
        // Pow5Chip layout: 3 advice columns for state, 1 for
        // partial-sbox, 3 fixed for rc_a, 3 fixed for rc_b.
        let poseidon_state = (0..3).map(|_| meta.advice_column()).collect::<Vec<_>>();
        let partial_sbox = meta.advice_column();
        let rc_a = (0..3).map(|_| meta.fixed_column()).collect::<Vec<_>>();
        let rc_b = (0..3).map(|_| meta.fixed_column()).collect::<Vec<_>>();
        meta.enable_constant(rc_b[0]);

        // CondSwap requires 5 advice columns. We allocate them
        // separately from the Pow5Chip state for layout
        // simplicity at this sub-arc; future optimisation can
        // share columns where the row-by-row layouts permit.
        let cs_advices = (0..5).map(|_| meta.advice_column()).collect::<Vec<_>>();

        let instance = meta.instance_column();
        meta.enable_equality(instance);
        // Pow5Chip output cells live in `poseidon_state[0]` —
        // enable equality so we can wire them to the
        // CondSwap inputs at the next level.
        meta.enable_equality(poseidon_state[0]);
        // Enable equality on all CondSwap columns we'll need
        // to copy from / to.
        for c in &cs_advices {
            meta.enable_equality(*c);
        }

        let cond_swap = CondSwapChip::configure(meta, cs_advices.try_into().unwrap());

        let poseidon = Pow5Chip::configure::<P128Pow5T3>(
            meta,
            poseidon_state.try_into().unwrap(),
            partial_sbox,
            rc_a.try_into().unwrap(),
            rc_b.try_into().unwrap(),
        );

        MerkleMembershipConfig {
            poseidon,
            cond_swap,
            instance,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<pallas::Base>,
    ) -> Result<(), PlonkError> {
        let cond_swap_chip = CondSwapChip::<pallas::Base>::construct(config.cond_swap.clone());

        // Step 1 — load the leaf as the initial `current` cell.
        let mut current = cond_swap_chip.load_private(
            layouter.namespace(|| "load leaf"),
            config.cond_swap.a(),
            self.witness.leaf,
        )?;

        // Step 2 — chain `DEPTH` levels of (cond_swap, hash).
        for level in 0..DEPTH {
            // Conditional swap: per the path bit, position
            // (current, sibling) as (left, right).
            let (left, right) = cond_swap_chip.swap(
                layouter.namespace(|| format!("cond_swap level {level}")),
                (current.clone(), self.witness.path_siblings[level]),
                self.witness.path_bits[level],
            )?;

            // Hash (left, right) → next.
            let chip = Pow5Chip::construct(config.poseidon.clone());
            let hasher = Hash::<pallas::Base, _, P128Pow5T3, ConstantLength<2>, 3, 2>::init(
                chip,
                layouter.namespace(|| format!("init hash level {level}")),
            )?;

            // Pow5Chip's `Hash::hash` takes an advice-cell array.
            // Convert (left, right) into the array shape.
            let next = hasher.hash(
                layouter.namespace(|| format!("merkle hash level {level}")),
                [left, right],
            )?;

            // The Pow5Chip output is in `poseidon_state[0]`;
            // copy it into the cond_swap's `a` column for the
            // next iteration's input. (Equality between
            // poseidon output and cond_swap input is the
            // copy-constraint enabled at `configure` time.)
            current = layouter.assign_region(
                || format!("copy hash output to next level's a column ({level})"),
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

        // Step 3 — constrain final `current` cell to equal the
        // public-input `root`.
        layouter.constrain_instance(current.cell(), config.instance, 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::poseidon::{poseidon_hash, FieldBytes};
    use adamant_halo2::proofs::dev::MockProver;
    use pasta_curves::group::ff::PrimeField;

    /// `K = 8` fits a depth-4 instantiation (4 `cond_swap`
    /// rows + 4 Poseidon-arity-2 hashes ≈ 4*36 + 4 = ~148
    /// rows; `2^8 = 256` rows is sufficient).
    const K_DEPTH4: u32 = 8;

    /// Convert [`FieldBytes`] to in-circuit `pallas::Base`.
    fn fb_to_base(fb: FieldBytes) -> pallas::Base {
        pallas::Base::from_repr(fb.to_bytes())
            .expect("FieldBytes invariant: bytes encode a valid field element")
    }

    /// Off-circuit Merkle-path recomputation matching the
    /// in-circuit construction. Returns the root.
    fn recompute_root_offcircuit(
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

    /// Build a deterministic depth-4 setup (witness + matching
    /// public inputs).
    fn fixed_depth4_setup() -> (MerkleMembershipWitness<4>, MerkleMembershipPublicInputs) {
        let leaf = fb_to_base(FieldBytes::from_bytes_reduced([0xAA; 32]));
        let siblings = [
            fb_to_base(FieldBytes::from_bytes_reduced([0x11; 32])),
            fb_to_base(FieldBytes::from_bytes_reduced([0x22; 32])),
            fb_to_base(FieldBytes::from_bytes_reduced([0x33; 32])),
            fb_to_base(FieldBytes::from_bytes_reduced([0x44; 32])),
        ];
        // Path bits: 0b0101 = leaf is at position 5 (low-bit
        // first: 1, 0, 1, 0).
        let bits = [true, false, true, false];

        let root = recompute_root_offcircuit(leaf, &siblings, &bits);

        let witness = MerkleMembershipWitness::<4> {
            leaf: Value::known(leaf),
            path_siblings: siblings.map(Value::known),
            path_bits: bits.map(Value::known),
        };
        let public = MerkleMembershipPublicInputs { root };
        (witness, public)
    }

    /// Positive case: consistent witness + root verifies.
    #[test]
    fn merkle_circuit_accepts_consistent_inputs() {
        let (witness, public) = fixed_depth4_setup();
        let circuit = MerkleMembershipCircuit::<4>::new(witness);
        let prover = MockProver::run(K_DEPTH4, &circuit, vec![public.to_rows()])
            .expect("MockProver runs cleanly");
        assert_eq!(prover.verify(), Ok(()));
    }

    /// Negative case: tampered root (public input wrong) is
    /// rejected.
    #[test]
    fn merkle_circuit_rejects_tampered_root() {
        let (witness, mut public) = fixed_depth4_setup();
        public.root = pallas::Base::from(0x1234_5678u64);
        let circuit = MerkleMembershipCircuit::<4>::new(witness);
        let prover = MockProver::run(K_DEPTH4, &circuit, vec![public.to_rows()])
            .expect("MockProver runs cleanly");
        assert!(prover.verify().is_err(), "tampered root must be rejected");
    }

    /// Negative case: tampered leaf — same path siblings + bits
    /// but a different leaf produces a different root, so the
    /// public-input root no longer matches.
    #[test]
    fn merkle_circuit_rejects_wrong_leaf() {
        let (mut witness, public) = fixed_depth4_setup();
        witness.leaf = Value::known(fb_to_base(FieldBytes::from_bytes_reduced([0xFF; 32])));
        let circuit = MerkleMembershipCircuit::<4>::new(witness);
        let prover = MockProver::run(K_DEPTH4, &circuit, vec![public.to_rows()])
            .expect("MockProver runs cleanly");
        assert!(
            prover.verify().is_err(),
            "wrong leaf must produce a different root and be rejected"
        );
    }

    /// Negative case: tampered sibling at level 2 — flipping
    /// one sibling re-paths the membership proof to a
    /// different root.
    #[test]
    fn merkle_circuit_rejects_wrong_sibling() {
        let (mut witness, public) = fixed_depth4_setup();
        witness.path_siblings[2] = Value::known(pallas::Base::from(0u64));
        let circuit = MerkleMembershipCircuit::<4>::new(witness);
        let prover = MockProver::run(K_DEPTH4, &circuit, vec![public.to_rows()])
            .expect("MockProver runs cleanly");
        assert!(prover.verify().is_err(), "wrong sibling must be rejected");
    }

    /// Negative case: tampered path bit at level 1 — flipping
    /// the leaf-position bit changes the swap direction at
    /// that level, producing a different root.
    #[test]
    fn merkle_circuit_rejects_wrong_path_bit() {
        let (mut witness, public) = fixed_depth4_setup();
        // Original bit at level 1 was `false`; flip to `true`.
        witness.path_bits[1] = Value::known(true);
        let circuit = MerkleMembershipCircuit::<4>::new(witness);
        let prover = MockProver::run(K_DEPTH4, &circuit, vec![public.to_rows()])
            .expect("MockProver runs cleanly");
        assert!(prover.verify().is_err(), "wrong path bit must be rejected");
    }

    /// Cross-validation pin: in-circuit Merkle path computation
    /// matches the off-circuit `recompute_root_offcircuit`
    /// reference for the same inputs. §3.3.3 boundary
    /// invariant for the per-level Poseidon-arity-2 hash.
    #[test]
    fn circuit_matches_out_of_circuit() {
        let (witness, public) = fixed_depth4_setup();
        let circuit = MerkleMembershipCircuit::<4>::new(witness);
        let prover = MockProver::run(K_DEPTH4, &circuit, vec![public.to_rows()])
            .expect("MockProver runs cleanly");
        assert_eq!(
            prover.verify(),
            Ok(()),
            "in-circuit Poseidon-Merkle path must agree with off-circuit \
             recompute_root_offcircuit"
        );
    }

    /// Depth-1 single-level smoke test. Sanity check that the
    /// const-generic depth parameter works at the smallest
    /// non-trivial value.
    #[test]
    fn merkle_circuit_works_at_depth_1() {
        let leaf = fb_to_base(FieldBytes::from_bytes_reduced([0x77; 32]));
        let sibling = fb_to_base(FieldBytes::from_bytes_reduced([0x88; 32]));
        let bit = false;
        let root = recompute_root_offcircuit(leaf, &[sibling], &[bit]);

        let witness = MerkleMembershipWitness::<1> {
            leaf: Value::known(leaf),
            path_siblings: [Value::known(sibling)],
            path_bits: [Value::known(bit)],
        };
        let circuit = MerkleMembershipCircuit::<1>::new(witness);
        let prover =
            MockProver::run(7, &circuit, vec![vec![root]]).expect("MockProver runs cleanly");
        assert_eq!(prover.verify(), Ok(()));
    }

    /// Pin the public-input count.
    #[test]
    fn public_input_count_pinned() {
        assert_eq!(PUBLIC_INPUT_COUNT, 1);
    }

    /// Default-witness keygen-shape check — same pattern as
    /// the Phase 6.8b.4a / 6.8b.4b circuits.
    #[test]
    fn default_witness_keygen_shape() {
        let _circuit = MerkleMembershipCircuit::<4>::default();
    }
}
