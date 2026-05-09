//! Halo 2 validity-circuit gadgets per whitepaper §7.3.2.
//!
//! Phase 6.8b.4 vehicle. Adamant-authored ZK code (NOT a fork).
//! The chips this module composes (`Pow5Chip` for Poseidon,
//! ECC chips for Pallas) are forked into `adamant-halo2` per
//! Phase 6.8b.0–6.8b.3; the §7.3.2 validity-circuit logic
//! is original Adamant code anchoring on those chips.
//!
//! # §7.3.2 statements (whitepaper)
//!
//! > A shielded transaction's correctness is attested by a
//! > Halo 2 zero-knowledge proof. The proof asserts that the
//! > transaction is valid:
//! >
//! > 1. **Input note existence.** For each nullifier, there
//! >    exists a note commitment in the GNCT (proven via a
//! >    Merkle path) and the nullifier is correctly derived
//! >    from the note's contents.
//! > 2. **Nullifier uniqueness.** Each published nullifier has
//! >    not previously appeared on the chain. (Partly in-
//! >    circuit, partly enforced by the consensus layer's
//! >    nullifier set.)
//! > 3. **Output note well-formedness.** Each output commitment
//! >    is correctly computed from valid inputs.
//! > 4. **Value conservation.** Sum of input values equals sum
//! >    of output values plus explicit fees, per asset type.
//! > 5. **Range proofs.** Every value in the transaction lies
//! >    in `[0, 2^64)`.
//! > 6. **Authority.** For each input note, the prover knows
//! >    the spending key.
//! > 7. **Smart-contract execution.** For shielded `#[shielded]`
//! >    function executions, the function executed correctly.
//!
//! # Sub-arc map
//!
//! | Sub-arc | Statement | Surface | Status |
//! |---------|-----------|---------|--------|
//! | 6.8b.4a | 3 | [`note_commitment`] — output well-formedness | THIS SUB-ARC |
//! | 6.8b.4b | 6 (in-circuit half) | nullifier-derivation circuit | pending |
//! | 6.8b.4c | 1 | GNCT Merkle-membership circuit | pending |
//! | 6.8b.4d | 4 + 5 | value conservation + range proofs | pending |
//! | 6.8b.4e | composition | full `ValidityCircuit` + transaction wiring | pending |
//! | 6.8b.4f | 7 | shielded contract execution (depends on Phase 7+ VM) | pending |
//!
//! Statement 2 (nullifier uniqueness) is enforced at the
//! consensus layer (Phase 7+), not in-circuit — the chain's
//! nullifier set is the gating check.

pub mod merkle;
pub mod note_commitment;
pub mod nullifier;
pub mod range_check;
pub mod shielded_output;

pub use merkle::{MerkleMembershipCircuit, MerkleMembershipPublicInputs, MerkleMembershipWitness};
pub use note_commitment::{NoteCommitmentCircuit, NoteCommitmentWitness};
pub use nullifier::{
    NullifierCircuit, NullifierDomainTags, NullifierPublicInputs, NullifierWitness,
};
pub use range_check::{u64_to_bit_witnesses, RangeCheck64Circuit, RangeCheck64Witness};
pub use shielded_output::{ShieldedOutputCircuit, ShieldedOutputWitness};
