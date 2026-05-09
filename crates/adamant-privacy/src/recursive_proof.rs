//! Recursive proof composition wire types per whitepaper §8.5
//! and §3.9 ("Recursive proof composition" paragraph).
//!
//! Phase 6.9a ships the data-type layer of recursive proof
//! composition — the [`RecursiveProof`], [`EpochCommitment`],
//! and [`RecursiveProofPublicInputs`] types plus the
//! [`RecursiveProofEnvelope`] composition struct.
//!
//! Phase 6.9b (the actual Halo 2 recursive proving system per
//! §8.5.2) lands alongside Phase 6.8b at the §14.4 Decision 1
//! plan-gate (C1 native / C2 fork / C3 bounded-ecosystem). The
//! 6.9a wire types here are posture-independent: the recursive
//! proof is treated as opaque bytes at this layer, so adding the
//! actual Halo 2 recursion later does not require changing the
//! on-chain wire format.
//!
//! # Spec basis
//!
//! Whitepaper §8.5.1 verbatim:
//!
//! > The recursive proof, at any given epoch boundary, attests:
//! > - The genesis state is a specific commitment (anchored at
//! >   the protocol's genesis block).
//! > - Every transaction in the committed DAG history was
//! >   authorised, well-formed, and correctly executed.
//! > - Every shielded transaction's Halo 2 proof verified.
//! > - The chain state at the end of the current epoch is a
//! >   specific commitment.
//!
//! Whitepaper §8.5.2 verbatim:
//!
//! > The protocol's recursive proof at epoch N:
//! > - Verifies the recursive proof from epoch N-1 (constant
//! >   size, ~5-10 KB)
//! > - Verifies all per-transaction proofs in epoch N (typically
//! >   thousands)
//! > - Outputs a new constant-size proof for epoch N
//! >
//! > The total proof at any point in time is a single artifact,
//! > ~5-10 KB, attesting to the validity of the entire chain
//! > history.
//!
//! Whitepaper §3.9 verbatim:
//!
//! > Halo 2's design supports efficient recursive proof
//! > composition through the Pasta cycle: a Pallas-curve proof
//! > can be verified in a Vesta-curve circuit and vice versa.
//! > This is the foundation of Adamant's phone-verifiable
//! > property: the entire chain history is compressed into a
//! > single recursive proof verifiable on consumer hardware.
//!
//! # Wire-format strategy
//!
//! - `proof` is an opaque-bytes [`RecursiveProof`] newtype. The
//!   constant-size invariant per §8.5.2 (~5-10 KB) is a property
//!   of the underlying proving system, not of this wire type;
//!   Phase 6.9b pins the structured shape.
//! - `public_inputs` is [`RecursiveProofPublicInputs`], a
//!   structured triple of genesis / previous-epoch / current-
//!   epoch commitments per §8.5.1.
//! - [`EpochCommitment`] is a 32-byte commitment to chain state
//!   at an epoch boundary (composition of GNCT root, nullifier
//!   set commitment, transparent state root, and active-set
//!   commitment per §8.5; the exact composition lands at Phase
//!   7+ consensus integration).
//!
//! # Cadence
//!
//! Per §8.5.4, the chain operates in two recursive-proof
//! cadence modes:
//!
//! - **Steady-state.** Sub-second cadence, produced by external
//!   provers on GPU-class hardware (§8.5.3).
//! - **Fallback.** Approximately one proof per N blocks (default
//!   N = 10, ~5-second cadence), produced by active validators
//!   on consumer-desktop hardware when the prover market is
//!   non-responsive.
//!
//! [`ProofCadence`] tags the cadence mode of a recursive proof.
//! The mode is observable on-chain from the proof submission
//! source (prover bounty vs validator-fallback) per §8.5.4
//! "Transition is automatic."

use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;

/// Byte length of an [`EpochCommitment`] (256 bits).
pub const EPOCH_COMMITMENT_BYTES: usize = 32;

/// 256-bit commitment to chain state at an epoch boundary per
/// whitepaper §8.5.1.
///
/// The commitment is the structured composition of:
///
/// - the GNCT root (§7.1.3),
/// - the nullifier-set commitment (§7.1.2 / consensus-state),
/// - the transparent-state Merkle root (§5.1 object model),
/// - the active-validator-set commitment (§8.x).
///
/// The exact composition formula is pinned at Phase 7+ consensus
/// integration. Phase 6.9a treats the commitment as a 32-byte
/// opaque value at the wire layer; the recursive proof's public
/// inputs bind the value, and consensus-side integration ensures
/// the byte content matches the canonical composition.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct EpochCommitment(#[serde(with = "BigArray")] [u8; EPOCH_COMMITMENT_BYTES]);

impl EpochCommitment {
    /// Construct from raw 32-byte material.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; EPOCH_COMMITMENT_BYTES]) -> Self {
        Self(bytes)
    }

    /// Canonical 32-byte encoding.
    #[must_use]
    pub const fn to_bytes(self) -> [u8; EPOCH_COMMITMENT_BYTES] {
        self.0
    }

    /// Borrow the underlying bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; EPOCH_COMMITMENT_BYTES] {
        &self.0
    }
}

/// A constant-size recursive Halo 2 proof per whitepaper §8.5.2.
///
/// Phase 6.9a stores the proof as an opaque byte buffer. Phase
/// 6.9b will replace the internal representation with a
/// structured Halo-2-recursive-proof shape resolved at the §14.4
/// Decision 1 plan-gate. The on-chain wire format stays bytes-
/// on-the-wire, so the §14.4 posture decision does NOT require a
/// hard fork of the recursive-proof envelope.
///
/// Per §8.5.2: "constant size, ~5-10 KB". The byte length is a
/// property of the underlying proving system, not enforced here.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RecursiveProof {
    /// Opaque proof bytes. Format is defined by the recursive
    /// proving system selected at Phase 6.9b plan-gate.
    pub bytes: Vec<u8>,
}

impl RecursiveProof {
    /// Construct from raw proof bytes.
    #[must_use]
    pub const fn from_bytes(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    /// Borrow the raw proof bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Length in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Whether the proof byte buffer is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

/// The public inputs of a recursive proof per whitepaper §8.5.1.
///
/// A verifier checking [`RecursiveProof::bytes`] against these
/// public inputs learns: "the chain state at this epoch is
/// `current_epoch`, derived correctly from `genesis` via valid
/// transactions" per §8.5.1.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RecursiveProofPublicInputs {
    /// The genesis commitment per §8.5.1 first bullet ("The
    /// genesis state is a specific commitment, anchored at the
    /// protocol's genesis block"). Identical across the entire
    /// chain history; pinned at genesis activation per §11.
    pub genesis: EpochCommitment,
    /// The previous epoch's commitment (epoch N-1 per §8.5.2).
    /// The recursive proof at epoch N verifies the proof at
    /// epoch N-1 against this commitment as a public input;
    /// chains the recursion.
    pub previous_epoch: EpochCommitment,
    /// The current epoch's commitment (epoch N per §8.5.2). The
    /// recursive proof at epoch N attests that this is the
    /// correctly-derived state after applying epoch N's
    /// transactions to `previous_epoch`.
    pub current_epoch: EpochCommitment,
    /// Epoch number being proven. 0 at genesis; monotonically
    /// increasing by 1 per epoch per §8.x. Wire-typed as `u64`
    /// — sufficient for `2^64` epochs (~10^11 years at 1-minute
    /// epochs).
    pub epoch_number: u64,
}

/// Cadence mode under which a recursive proof was produced per
/// whitepaper §8.5.4.
///
/// Observable on-chain from the proof submission source: a proof
/// claimed by an external prover from the §8.5.3 prover market
/// is `Steady`; a proof produced by validator-fallback per
/// §8.5.4 is `Fallback`. Both modes produce identically-valid
/// proofs verifiable by the same Halo 2 verifier; the tag is
/// for observability and for the §10.4 fee/bounty accounting.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub enum ProofCadence {
    /// Steady-state cadence: external prover from the §8.5.3
    /// permissionless prover market. Sub-second target per
    /// §8.5.4.
    Steady,
    /// Fallback cadence: produced by active validators on
    /// consumer-desktop hardware when the prover market did not
    /// submit a valid proof within the §8.5.4 timeout window.
    /// Target ~5-second cadence (one proof per ~10 blocks).
    Fallback,
}

/// On-chain envelope for a recursive proof per whitepaper §8.5.
///
/// Wire shape: the recursive proof bytes, the public inputs the
/// proof verifies against, and a [`ProofCadence`] tag for
/// observability. Phase 7+ consensus integration wires this
/// struct into the per-epoch recursive-proof submission path.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RecursiveProofEnvelope {
    /// The recursive Halo 2 proof per §8.5.2.
    pub proof: RecursiveProof,
    /// The public inputs the proof verifies against per §8.5.1.
    pub public_inputs: RecursiveProofPublicInputs,
    /// Cadence mode under which the proof was produced per
    /// §8.5.4.
    pub cadence: ProofCadence,
}

impl RecursiveProofEnvelope {
    /// Construct from components.
    #[must_use]
    pub const fn new(
        proof: RecursiveProof,
        public_inputs: RecursiveProofPublicInputs,
        cadence: ProofCadence,
    ) -> Self {
        Self {
            proof,
            public_inputs,
            cadence,
        }
    }

    /// Whether this envelope is structurally consistent with
    /// being the genesis-epoch proof: the previous-epoch and
    /// current-epoch commitments equal the genesis commitment,
    /// and the epoch number is 0.
    ///
    /// Genesis is the unique base case of the recursion: there
    /// is no earlier epoch, so the recursive proof's "verify the
    /// previous proof" step is short-circuited by the genesis
    /// equality.
    #[must_use]
    pub fn is_genesis_envelope(&self) -> bool {
        self.public_inputs.epoch_number == 0
            && self.public_inputs.previous_epoch == self.public_inputs.genesis
            && self.public_inputs.current_epoch == self.public_inputs.genesis
    }

    /// Whether `next` could chain onto this envelope as the
    /// epoch immediately following: the next envelope's
    /// `previous_epoch` must equal this envelope's
    /// `current_epoch`, the genesis commitments must match, and
    /// the epoch numbers must be sequential.
    ///
    /// **Structural** check only — does NOT verify either
    /// proof's cryptographic validity. Phase 6.9b (proof
    /// verification) and Phase 7+ consensus integration cover
    /// the cryptographic checks.
    #[must_use]
    pub fn chains_to(&self, next: &Self) -> bool {
        self.public_inputs.genesis == next.public_inputs.genesis
            && self.public_inputs.current_epoch == next.public_inputs.previous_epoch
            && next
                .public_inputs
                .epoch_number
                .checked_sub(1)
                .is_some_and(|prev| prev == self.public_inputs.epoch_number)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn epoch_commitment(byte: u8) -> EpochCommitment {
        EpochCommitment::from_bytes([byte; EPOCH_COMMITMENT_BYTES])
    }

    fn sample_genesis_envelope() -> RecursiveProofEnvelope {
        let g = epoch_commitment(0x00);
        RecursiveProofEnvelope::new(
            RecursiveProof::from_bytes(vec![0xAA; 8192]),
            RecursiveProofPublicInputs {
                genesis: g,
                previous_epoch: g,
                current_epoch: g,
                epoch_number: 0,
            },
            ProofCadence::Steady,
        )
    }

    fn sample_envelope_at(
        prev: EpochCommitment,
        curr: EpochCommitment,
        n: u64,
    ) -> RecursiveProofEnvelope {
        RecursiveProofEnvelope::new(
            RecursiveProof::from_bytes(vec![0xBB; 8192]),
            RecursiveProofPublicInputs {
                genesis: epoch_commitment(0x00),
                previous_epoch: prev,
                current_epoch: curr,
                epoch_number: n,
            },
            ProofCadence::Steady,
        )
    }

    // ---------- Type-shape tests ----------

    #[test]
    fn epoch_commitment_round_trips_bytes() {
        let bytes = [0xAB; EPOCH_COMMITMENT_BYTES];
        let c = EpochCommitment::from_bytes(bytes);
        assert_eq!(c.to_bytes(), bytes);
        assert_eq!(c.as_bytes(), &bytes);
    }

    #[test]
    fn epoch_commitment_distinct_bytes_distinct_values() {
        assert_ne!(epoch_commitment(0x01), epoch_commitment(0x02));
    }

    #[test]
    fn recursive_proof_round_trips_bytes() {
        let p = RecursiveProof::from_bytes(vec![0xCD; 8192]);
        assert_eq!(p.as_bytes(), &[0xCD; 8192][..]);
        assert_eq!(p.len(), 8192);
        assert!(!p.is_empty());
        assert!(RecursiveProof::from_bytes(Vec::new()).is_empty());
    }

    #[test]
    fn proof_cadence_distinct_modes() {
        assert_ne!(ProofCadence::Steady, ProofCadence::Fallback);
    }

    // ---------- Genesis-envelope shape ----------

    #[test]
    fn genesis_envelope_is_genesis() {
        let e = sample_genesis_envelope();
        assert!(e.is_genesis_envelope());
    }

    #[test]
    fn non_genesis_envelope_is_not_genesis() {
        let g = epoch_commitment(0x00);
        let e = sample_envelope_at(g, epoch_commitment(0x11), 1);
        assert!(!e.is_genesis_envelope());
    }

    #[test]
    fn envelope_with_nonzero_epoch_number_not_genesis() {
        let g = epoch_commitment(0x00);
        // Same commitments but epoch_number != 0.
        let e = sample_envelope_at(g, g, 1);
        assert!(!e.is_genesis_envelope());
    }

    // ---------- Chaining ----------

    #[test]
    fn chains_to_passes_for_sequential_envelopes() {
        let g = epoch_commitment(0x00);
        let s1 = epoch_commitment(0x11);
        let s2 = epoch_commitment(0x22);
        let e_genesis = sample_genesis_envelope();
        let e1 = sample_envelope_at(g, s1, 1);
        let e2 = sample_envelope_at(s1, s2, 2);
        assert!(e_genesis.chains_to(&e1));
        assert!(e1.chains_to(&e2));
    }

    #[test]
    fn chains_to_fails_on_state_mismatch() {
        let g = epoch_commitment(0x00);
        let s1 = epoch_commitment(0x11);
        let s2 = epoch_commitment(0x22);
        let other = epoch_commitment(0x99);
        let e1 = sample_envelope_at(g, s1, 1);
        // e2's previous != e1's current.
        let e2_bad = sample_envelope_at(other, s2, 2);
        assert!(!e1.chains_to(&e2_bad));
    }

    #[test]
    fn chains_to_fails_on_epoch_number_skip() {
        let g = epoch_commitment(0x00);
        let s1 = epoch_commitment(0x11);
        let s2 = epoch_commitment(0x22);
        let e1 = sample_envelope_at(g, s1, 1);
        // e2's epoch_number is 3 (should be 2).
        let e2_skip = sample_envelope_at(s1, s2, 3);
        assert!(!e1.chains_to(&e2_skip));
    }

    #[test]
    fn chains_to_fails_on_genesis_mismatch() {
        let g_a = epoch_commitment(0x00);
        let g_b = epoch_commitment(0x77);
        let s1 = epoch_commitment(0x11);
        let e_a = RecursiveProofEnvelope::new(
            RecursiveProof::from_bytes(Vec::new()),
            RecursiveProofPublicInputs {
                genesis: g_a,
                previous_epoch: g_a,
                current_epoch: s1,
                epoch_number: 1,
            },
            ProofCadence::Steady,
        );
        let e_b = RecursiveProofEnvelope::new(
            RecursiveProof::from_bytes(Vec::new()),
            RecursiveProofPublicInputs {
                genesis: g_b,
                previous_epoch: s1,
                current_epoch: epoch_commitment(0x33),
                epoch_number: 2,
            },
            ProofCadence::Steady,
        );
        assert!(!e_a.chains_to(&e_b));
    }

    /// `chains_to` from epoch N to "epoch 0" is rejected: the
    /// `checked_sub(1)` underflow on the `0u64 - 1` pattern in
    /// the chain-check returns `None`. Pin: chaining from a
    /// non-genesis envelope to a genesis-numbered envelope is
    /// structurally invalid.
    #[test]
    fn chains_to_fails_on_chain_to_zero() {
        let g = epoch_commitment(0x00);
        let s1 = epoch_commitment(0x11);
        let e1 = sample_envelope_at(g, s1, 1);
        // e_zero claims epoch_number = 0 but has prev = e1's curr.
        let e_zero = RecursiveProofEnvelope::new(
            RecursiveProof::from_bytes(Vec::new()),
            RecursiveProofPublicInputs {
                genesis: g,
                previous_epoch: s1,
                current_epoch: g,
                epoch_number: 0,
            },
            ProofCadence::Steady,
        );
        assert!(!e1.chains_to(&e_zero));
    }

    // ---------- BCS round-trip ----------

    #[test]
    fn epoch_commitment_bcs_round_trip() {
        let original = epoch_commitment(0xAB);
        let encoded = bcs::to_bytes(&original).unwrap();
        let decoded: EpochCommitment = bcs::from_bytes(&encoded).unwrap();
        assert_eq!(original, decoded);
        assert_eq!(encoded.len(), EPOCH_COMMITMENT_BYTES);
    }

    #[test]
    fn recursive_proof_bcs_round_trip() {
        let original = RecursiveProof::from_bytes(vec![0xCD; 8192]);
        let encoded = bcs::to_bytes(&original).unwrap();
        let decoded: RecursiveProof = bcs::from_bytes(&encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn recursive_proof_public_inputs_bcs_round_trip() {
        let original = RecursiveProofPublicInputs {
            genesis: epoch_commitment(0x00),
            previous_epoch: epoch_commitment(0x11),
            current_epoch: epoch_commitment(0x22),
            epoch_number: u64::MAX,
        };
        let encoded = bcs::to_bytes(&original).unwrap();
        let decoded: RecursiveProofPublicInputs = bcs::from_bytes(&encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn proof_cadence_bcs_round_trip() {
        for c in [ProofCadence::Steady, ProofCadence::Fallback] {
            let encoded = bcs::to_bytes(&c).unwrap();
            let decoded: ProofCadence = bcs::from_bytes(&encoded).unwrap();
            assert_eq!(c, decoded);
        }
    }

    #[test]
    fn recursive_proof_envelope_bcs_round_trip() {
        let original = sample_envelope_at(epoch_commitment(0x00), epoch_commitment(0x11), 1);
        let encoded = bcs::to_bytes(&original).unwrap();
        let decoded: RecursiveProofEnvelope = bcs::from_bytes(&encoded).unwrap();
        assert_eq!(original, decoded);
    }

    /// Genesis-envelope BCS round-trip: edge case for the
    /// `is_genesis_envelope` predicate.
    #[test]
    fn genesis_envelope_bcs_round_trip() {
        let original = sample_genesis_envelope();
        let encoded = bcs::to_bytes(&original).unwrap();
        let decoded: RecursiveProofEnvelope = bcs::from_bytes(&encoded).unwrap();
        assert_eq!(original, decoded);
        assert!(decoded.is_genesis_envelope());
    }
}
