//! Genesis cohort marker per whitepaper §8.1.9.
//!
//! The first 75 validator addresses to register and successfully
//! take an active-set slot during the chain's launch period
//! constitute the **genesis cohort**. The chain commits two on-
//! chain artefacts to recognise their bootstrapping role:
//!
//! 1. A non-transferable, permanent **marker** attached to each
//!    of the first 75 validator addresses. Records position
//!    (1–75), activation epoch, and a chain-state commitment at
//!    the moment of activation. Stays attached to the original
//!    address even if the slot is later transferred or the
//!    validator is slashed.
//! 2. A **Genesis NFT** minted to the same addresses. Freely
//!    transferable as a cultural artefact; conveys no protocol-
//!    level rights.
//!
//! Phase 7.0 ships the marker. The NFT is a Phase 7.10 / Phase
//! 10 (genesis economics) deliverable.
//!
//! The cohort is **closed** once 75 distinct validator addresses
//! have taken active-set slots. Slot 76 onward is a regular
//! validator slot with no marker.

use serde::{Deserialize, Serialize};

use crate::epoch::EpochNumber;

/// Size of the genesis cohort per whitepaper §8.1.9.
///
/// **Constitutional value.** The first 75 validators to take an
/// active-set slot bootstrap the chain; the count matches the
/// §8.1.3 active-set ceiling exactly. Revisions to the active-set
/// ceiling per §8.1.10 do not retroactively change the genesis
/// cohort size — the cohort is defined by the chain's first 75
/// active-set assignments and stays at 75 forever.
pub const GENESIS_COHORT_SIZE: u8 = 75;

/// Byte width of the chain-state commitment in [`GenesisCohortMarker`].
/// Same width as [`crate::identity::ValidatorId`] / `Address` /
/// other 256-bit commitments — 32 bytes.
pub const GENESIS_COHORT_MARKER_BYTES: usize = 32;

/// On-chain marker recognising a validator's membership in the
/// §8.1.9 genesis cohort.
///
/// Attached to a validator's `Address` at the moment they take
/// their active-set slot during the launch period. The marker is:
///
/// - **Non-transferable.** The marker stays attached to the
///   original address. A genesis-cohort validator who later
///   transfers their slot per §8.1.8 keeps the marker; the buyer
///   does not inherit it.
/// - **Permanent.** Cannot be moved between addresses, cannot be
///   revoked. Survives slashing, voluntary unbonding, and slot
///   transfer.
/// - **Historical.** Records who the validator was at the moment
///   of activation, not what they later did.
///
/// # Field declaration order is consensus-binding
///
/// Per §5.1.8 BCS canonicality, reordering fields is a hard fork.
/// The order chosen here matches the natural §8.1.9 description:
/// position → activation epoch → chain-state commitment.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct GenesisCohortMarker {
    /// Position in the genesis cohort, 1-indexed. Range
    /// `1..=GENESIS_COHORT_SIZE` (= 1..=75).
    ///
    /// Position 1 is the validator that anchored block 1
    /// (whichever validator's vertex deterministically anchors
    /// the first round per the §8.6 consensus VRF). Subsequent
    /// positions are filled in active-set-slot-acquisition order
    /// during the launch period.
    pub position: u8,
    /// Epoch at which the marker was attached. Equals the epoch
    /// at which the validator took their active-set slot.
    pub activated_at_epoch: EpochNumber,
    /// 32-byte commitment to chain state at the activation
    /// moment. Composition mirrors [`adamant_privacy::EpochCommitment`]
    /// (GNCT root + nullifier-set commitment + transparent-state
    /// root + active-set commitment); Phase 7.7 wires the
    /// composition formula. Phase 7.0 treats the bytes as opaque
    /// at the wire layer.
    pub chain_state_commitment: [u8; GENESIS_COHORT_MARKER_BYTES],
}

impl GenesisCohortMarker {
    /// Construct a marker for the given cohort position. Asserts
    /// `1 <= position <= GENESIS_COHORT_SIZE` per §8.1.9.
    ///
    /// # Panics
    ///
    /// Panics if `position` is `0` or exceeds [`GENESIS_COHORT_SIZE`].
    /// Position 0 has no meaning (§8.1.9 specifies 1-indexed
    /// positions); position > 75 means the cohort is closed.
    #[must_use]
    pub fn new(
        position: u8,
        activated_at_epoch: EpochNumber,
        chain_state_commitment: [u8; GENESIS_COHORT_MARKER_BYTES],
    ) -> Self {
        assert!(
            (1..=GENESIS_COHORT_SIZE).contains(&position),
            "GenesisCohortMarker: position {position} out of range \
             1..={GENESIS_COHORT_SIZE} per §8.1.9"
        );
        Self {
            position,
            activated_at_epoch,
            chain_state_commitment,
        }
    }

    /// Whether this marker represents the chain-anchoring
    /// (position-1) genesis validator. The position-1 validator
    /// is the one whose vertex deterministically anchors the
    /// first round per §8.1.6 + §8.6.
    #[must_use]
    pub const fn is_chain_anchor(&self) -> bool {
        self.position == 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixed_marker(position: u8) -> GenesisCohortMarker {
        GenesisCohortMarker::new(
            position,
            EpochNumber::new(0),
            [0xAA; GENESIS_COHORT_MARKER_BYTES],
        )
    }

    /// Pin the §8.1.9 cohort size constant.
    #[test]
    fn cohort_size_pinned_at_75() {
        assert_eq!(GENESIS_COHORT_SIZE, 75);
    }

    /// Pin the marker chain-state-commitment width.
    #[test]
    fn marker_commitment_width_pinned() {
        assert_eq!(GENESIS_COHORT_MARKER_BYTES, 32);
    }

    /// Marker for position 1 is the chain anchor.
    #[test]
    fn position_1_is_chain_anchor() {
        let m = fixed_marker(1);
        assert!(m.is_chain_anchor());
        let m_other = fixed_marker(2);
        assert!(!m_other.is_chain_anchor());
    }

    /// Marker for position 75 is valid (boundary).
    #[test]
    fn marker_position_75_valid() {
        let m = fixed_marker(75);
        assert_eq!(m.position, 75);
    }

    /// Position 0 is rejected.
    #[test]
    #[should_panic(expected = "out of range 1..=75")]
    fn marker_position_0_rejected() {
        let _ = fixed_marker(0);
    }

    /// Position 76 (post-cohort-closure) is rejected.
    #[test]
    #[should_panic(expected = "out of range 1..=75")]
    fn marker_position_76_rejected() {
        let _ = fixed_marker(76);
    }

    /// Marker BCS round-trip preserves all fields.
    #[test]
    fn marker_bcs_round_trip() {
        let m =
            GenesisCohortMarker::new(42, EpochNumber::new(7), [0xCD; GENESIS_COHORT_MARKER_BYTES]);
        let bytes = bcs::to_bytes(&m).unwrap();
        let decoded: GenesisCohortMarker = bcs::from_bytes(&bytes).unwrap();
        assert_eq!(m, decoded);
    }

    /// BCS encoding of the marker is exactly 1 (position) + 8
    /// (epoch number) + 32 (commitment) = 41 bytes (no length
    /// prefixes for fixed-size members).
    #[test]
    fn marker_bcs_size_pinned() {
        let m = fixed_marker(1);
        let bytes = bcs::to_bytes(&m).unwrap();
        assert_eq!(bytes.len(), 1 + 8 + 32);
    }
}
