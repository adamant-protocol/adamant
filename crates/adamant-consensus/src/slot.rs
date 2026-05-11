//! Slot types per whitepaper §8.1.3 + §8.1.8.
//!
//! A "slot" is a position in the active set or standby queue.
//! Each slot binds to exactly one [`crate::ValidatorId`] at any
//! given time; the binding may be transferred to a different
//! validator per §8.1.8 (slot transfer), but the slot's
//! sequence-number identity is preserved across the transfer.
//!
//! # Slot lifecycle
//!
//! ```text
//!     Standby ─────────► Active ─────────► Inactive
//!        ▲                  │
//!        │                  │ (slot transfer per §8.1.8)
//!        │                  ▼
//!        └────  reset on transfer; new validator inherits Active
//! ```
//!
//! - **Standby**: validator is registered + stake-eligible but
//!   the active-set ceiling is full. Slot waits in FIFO queue.
//! - **Active**: validator is producing consensus messages. Slot
//!   has the most recent `last_participation_epoch` recorded.
//! - **Inactive**: validator was unbonded, slashed for
//!   equivocation, or removed for liveness failure (§8.1.5).
//!   The slot is freed and the next standby validator advances
//!   to Active at the next epoch boundary (§8.1.3).
//!
//! # Liveness detection
//!
//! Per §8.1.5, "failing to participate in consensus for more
//! than 2 consecutive epochs while in the active set" triggers
//! liveness-failure removal. [`Slot::is_liveness_failed`]
//! computes this from `current_epoch - last_participation_epoch`:
//! if the count of missed epochs exceeds 2, the slot is failed.

use serde::{Deserialize, Serialize};

use crate::epoch::EpochNumber;
use crate::identity::ValidatorId;

/// Sequence-number identifier for an active-set or standby-queue
/// slot per §8.1.3.
///
/// `u16` is comfortably above any plausible active-set ceiling
/// (the §8.1.3 launch ceiling is 75; even a 100x revision per
/// §8.1.10 stays under `u16::MAX`).
#[derive(
    Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize,
)]
#[repr(transparent)]
pub struct SlotId(pub u16);

impl SlotId {
    /// Construct from a raw `u16` index.
    #[must_use]
    pub const fn new(index: u16) -> Self {
        Self(index)
    }

    /// Underlying `u16`.
    #[must_use]
    pub const fn as_u16(self) -> u16 {
        self.0
    }
}

/// Slot lifecycle state per §8.1.3.
///
/// Variant tags are pinned at genesis-fixed BCS encoding values:
/// `Active = 0x00`, `Standby = 0x01`, `Inactive = 0x02`.
/// Reordering is a hard fork.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub enum SlotStatus {
    /// Validator is producing consensus messages from this slot.
    Active,
    /// Validator is registered + stake-eligible but waiting in
    /// the FIFO standby queue for an active-set slot to open.
    Standby,
    /// Slot has been freed (validator unbonded, slashed for
    /// equivocation, or removed for liveness failure). Awaits
    /// reuse at the next epoch boundary when the next standby
    /// validator advances.
    Inactive,
}

/// A slot in the active set or standby queue per §8.1.3.
///
/// Bound to exactly one [`ValidatorId`] at any time; the
/// binding may be reassigned via [`SlotTransfer`] per §8.1.8
/// without changing the slot's `id` or registration ordering.
///
/// # Field declaration order is consensus-binding
///
/// Per §5.1.8 BCS canonicality, reordering fields is a hard
/// fork. The order chosen here matches a natural read order:
/// slot identifier → bound validator → registration history →
/// participation history → current status.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct Slot {
    /// Sequence-number identifier per §8.1.3.
    pub id: SlotId,
    /// Validator currently bound to this slot. Reassigned on
    /// [`SlotTransfer`] per §8.1.8.
    pub validator_id: ValidatorId,
    /// Epoch at which the *current* validator-binding was
    /// registered. On a slot transfer this advances to the
    /// transfer epoch; on the original registration it equals
    /// the validator's [`crate::Validator::registered_at_epoch`].
    pub bound_at_epoch: EpochNumber,
    /// Epoch in which the bound validator most recently
    /// participated in consensus. Used by the §8.1.5 liveness-
    /// failure detector. Initialised to `bound_at_epoch` at
    /// binding time; advances on each consensus participation.
    pub last_participation_epoch: EpochNumber,
    /// Current lifecycle state per §8.1.3.
    pub status: SlotStatus,
}

impl Slot {
    /// Construct a slot for a freshly-registered or freshly-
    /// transferred validator. `last_participation_epoch` is
    /// initialised to `bound_at_epoch` (the validator hasn't
    /// missed any epoch yet — the clock starts here).
    #[must_use]
    pub const fn new(
        id: SlotId,
        validator_id: ValidatorId,
        bound_at_epoch: EpochNumber,
        status: SlotStatus,
    ) -> Self {
        Self {
            id,
            validator_id,
            bound_at_epoch,
            last_participation_epoch: bound_at_epoch,
            status,
        }
    }

    /// Record consensus participation in `participation_epoch`.
    /// Resets the liveness counter implicitly (it's derived from
    /// `current_epoch - last_participation_epoch`).
    ///
    /// No-op if `participation_epoch` is older than the recorded
    /// last participation (clock-going-backwards safeguard).
    pub fn record_participation(&mut self, participation_epoch: EpochNumber) {
        if participation_epoch > self.last_participation_epoch {
            self.last_participation_epoch = participation_epoch;
        }
    }

    /// Whether this slot is in liveness-failure state per §8.1.5.
    ///
    /// Returns `true` iff the validator has missed more than 2
    /// consecutive epochs:
    ///
    /// ```text
    ///   missed = current_epoch - last_participation_epoch - 1
    ///   failed = missed > 2
    /// ```
    ///
    /// Equivalently: `current_epoch - last_participation_epoch > 3`.
    ///
    /// Edge cases:
    /// - `current_epoch <= last_participation_epoch`: not failed
    ///   (validator participated at or after the queried epoch).
    /// - Slot status not `Active`: `is_liveness_failed` returns
    ///   `false` regardless of epoch math (only active slots can
    ///   fail liveness per §8.1.3).
    #[must_use]
    pub fn is_liveness_failed(&self, current_epoch: EpochNumber) -> bool {
        if !matches!(self.status, SlotStatus::Active) {
            return false;
        }
        let cur = current_epoch.as_u64();
        let last = self.last_participation_epoch.as_u64();
        cur > last && cur - last > 3
    }
}

/// An atomic slot-transfer record per whitepaper §8.1.8.
///
/// Transfers the slot's binding from `seller_validator_id` to
/// `buyer_validator_id` at `initiated_at_epoch`'s next epoch
/// boundary. The buyer's [`crate::Validator`] must already be
/// registered (i.e., already have a `Validator` object on chain
/// with their public-key bundle, operator address, and stake);
/// the transfer doesn't create a new validator, only reassigns
/// the slot.
///
/// # Atomic state transition (§8.1.8 Mechanism)
///
/// At the next epoch boundary after `initiated_at_epoch`:
///
/// 1. Seller's bonded stake released (subject to 28-day
///    unbonding window for slashing accountability against any
///    pre-transfer offences).
/// 2. Buyer's `MIN_VALIDATOR_STAKE_LAUNCH` bonded.
/// 3. Slot's `validator_id` reassigned from seller to buyer.
///    Slot ordering / seniority unchanged.
/// 4. Active delegations migrated to seller (§8.1.4); 7-day
///    re-delegation window for delegators.
///
/// # No protocol-imposed price or fee
///
/// Per §8.1.8: "The chain does not set a price for slot
/// transfers, does not collect a fee on the transfer, and does
/// not constrain who the buyer may be." This type carries no
/// price field; off-chain compensation is the seller and
/// buyer's concern.
///
/// # Genesis-cohort marker stays with seller
///
/// Per §8.1.8 + §8.1.9: "Genesis cohort marker does not
/// transfer with the slot." If the seller carries a
/// [`crate::GenesisCohortMarker`], it remains attached to the
/// seller's address — the buyer takes operational control of
/// consensus from the slot but does not inherit the historical
/// recognition.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct SlotTransfer {
    /// Slot whose binding is being transferred.
    pub slot_id: SlotId,
    /// Validator currently bound to the slot (the "seller").
    pub seller_validator_id: ValidatorId,
    /// Validator the slot is being transferred to (the "buyer").
    pub buyer_validator_id: ValidatorId,
    /// Epoch at which the `transfer_slot` transaction was
    /// included on chain. The actual binding swap happens at
    /// `initiated_at_epoch.saturating_succ()` per §8.1.8 step 3.
    pub initiated_at_epoch: EpochNumber,
}

impl SlotTransfer {
    /// Construct a slot-transfer record.
    #[must_use]
    pub const fn new(
        slot_id: SlotId,
        seller_validator_id: ValidatorId,
        buyer_validator_id: ValidatorId,
        initiated_at_epoch: EpochNumber,
    ) -> Self {
        Self {
            slot_id,
            seller_validator_id,
            buyer_validator_id,
            initiated_at_epoch,
        }
    }

    /// Epoch at which the binding swap takes effect — the epoch
    /// immediately following `initiated_at_epoch` per §8.1.8
    /// step 3.
    #[must_use]
    pub const fn effective_at_epoch(&self) -> EpochNumber {
        self.initiated_at_epoch.saturating_succ()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixed_validator_id(byte: u8) -> ValidatorId {
        ValidatorId::from_bytes([byte; 32])
    }

    fn fixed_slot(id: u16, bound_at: u64, status: SlotStatus) -> Slot {
        Slot::new(
            SlotId::new(id),
            fixed_validator_id(0xAA),
            EpochNumber::new(bound_at),
            status,
        )
    }

    // ---------- SlotId ----------

    #[test]
    fn slot_id_round_trip() {
        let s = SlotId::new(42);
        assert_eq!(s.as_u16(), 42);
        let bytes = bcs::to_bytes(&s).unwrap();
        let decoded: SlotId = bcs::from_bytes(&bytes).unwrap();
        assert_eq!(s, decoded);
    }

    #[test]
    fn slot_id_bcs_size_pinned() {
        // u16 BCS-encodes as 2 bytes (little-endian).
        assert_eq!(bcs::to_bytes(&SlotId::new(0)).unwrap().len(), 2);
    }

    // ---------- SlotStatus ----------

    #[test]
    fn slot_status_bcs_variant_tags_pinned() {
        assert_eq!(bcs::to_bytes(&SlotStatus::Active).unwrap(), vec![0x00]);
        assert_eq!(bcs::to_bytes(&SlotStatus::Standby).unwrap(), vec![0x01]);
        assert_eq!(bcs::to_bytes(&SlotStatus::Inactive).unwrap(), vec![0x02]);
    }

    #[test]
    fn slot_status_bcs_round_trip() {
        for s in [
            SlotStatus::Active,
            SlotStatus::Standby,
            SlotStatus::Inactive,
        ] {
            let bytes = bcs::to_bytes(&s).unwrap();
            let decoded: SlotStatus = bcs::from_bytes(&bytes).unwrap();
            assert_eq!(s, decoded);
        }
    }

    // ---------- Slot construction ----------

    #[test]
    fn slot_new_initialises_last_participation_to_bound_at() {
        let s = fixed_slot(1, 7, SlotStatus::Active);
        assert_eq!(s.last_participation_epoch, EpochNumber::new(7));
    }

    #[test]
    fn slot_record_participation_advances() {
        let mut s = fixed_slot(1, 5, SlotStatus::Active);
        s.record_participation(EpochNumber::new(10));
        assert_eq!(s.last_participation_epoch, EpochNumber::new(10));
    }

    #[test]
    fn slot_record_participation_does_not_go_backwards() {
        let mut s = fixed_slot(1, 10, SlotStatus::Active);
        // Already at 10; recording 5 should be a no-op.
        s.record_participation(EpochNumber::new(5));
        assert_eq!(s.last_participation_epoch, EpochNumber::new(10));
    }

    // ---------- Liveness detection ----------

    /// Per §8.1.5: "failing to participate in consensus for more
    /// than 2 consecutive epochs" triggers removal. Pin the
    /// boundary: 2 missed epochs = OK, 3 missed = FAILED.
    #[test]
    fn liveness_failure_boundary_pinned() {
        let mut s = fixed_slot(1, 5, SlotStatus::Active);
        // Last participation: epoch 5.
        // current=5: just participated, not failed.
        assert!(!s.is_liveness_failed(EpochNumber::new(5)));
        // current=6: missed 0 epochs (we're CURRENTLY at 6, may
        // still participate). Not failed.
        assert!(!s.is_liveness_failed(EpochNumber::new(6)));
        // current=7: missed epoch 6. 1 miss. Not failed.
        assert!(!s.is_liveness_failed(EpochNumber::new(7)));
        // current=8: missed 6, 7. 2 misses. Not failed (the spec
        // says "more than 2", so exactly 2 still OK).
        assert!(!s.is_liveness_failed(EpochNumber::new(8)));
        // current=9: missed 6, 7, 8. 3 misses (= more than 2).
        // FAILED.
        assert!(s.is_liveness_failed(EpochNumber::new(9)));
        // current=10: missed 6, 7, 8, 9. 4 misses. FAILED.
        assert!(s.is_liveness_failed(EpochNumber::new(10)));

        // After participation reset, counter resets.
        s.record_participation(EpochNumber::new(10));
        assert!(!s.is_liveness_failed(EpochNumber::new(10)));
        assert!(!s.is_liveness_failed(EpochNumber::new(13)));
        assert!(s.is_liveness_failed(EpochNumber::new(14)));
    }

    /// Liveness failure only applies to Active slots per §8.1.3
    /// "failure to participate ... while in the active set".
    /// Standby + Inactive slots return false unconditionally.
    #[test]
    fn liveness_failure_only_active_slots() {
        let s_standby = fixed_slot(1, 0, SlotStatus::Standby);
        assert!(!s_standby.is_liveness_failed(EpochNumber::new(100)));
        let s_inactive = fixed_slot(1, 0, SlotStatus::Inactive);
        assert!(!s_inactive.is_liveness_failed(EpochNumber::new(100)));
    }

    /// Edge case: current_epoch < last_participation_epoch
    /// (clock-going-backwards). Should not be failed.
    #[test]
    fn liveness_failure_clock_backwards_safe() {
        let s = fixed_slot(1, 100, SlotStatus::Active);
        assert!(!s.is_liveness_failed(EpochNumber::new(50)));
    }

    // ---------- BCS round-trips ----------

    #[test]
    fn slot_bcs_round_trip() {
        let mut s = fixed_slot(7, 42, SlotStatus::Active);
        s.record_participation(EpochNumber::new(50));
        let bytes = bcs::to_bytes(&s).unwrap();
        let decoded: Slot = bcs::from_bytes(&bytes).unwrap();
        assert_eq!(s, decoded);
    }

    /// Slot BCS encoding: id (2) + validator_id (32) +
    /// bound_at_epoch (8) + last_participation_epoch (8) + status
    /// tag (1) = 51 bytes.
    #[test]
    fn slot_bcs_size_pinned() {
        let s = fixed_slot(0, 0, SlotStatus::Active);
        let bytes = bcs::to_bytes(&s).unwrap();
        assert_eq!(bytes.len(), 2 + 32 + 8 + 8 + 1);
    }

    // ---------- SlotTransfer ----------

    #[test]
    fn slot_transfer_effective_epoch_pin() {
        let t = SlotTransfer::new(
            SlotId::new(1),
            fixed_validator_id(0x11),
            fixed_validator_id(0x22),
            EpochNumber::new(10),
        );
        assert_eq!(t.effective_at_epoch(), EpochNumber::new(11));
    }

    #[test]
    fn slot_transfer_effective_epoch_saturates() {
        let t = SlotTransfer::new(
            SlotId::new(1),
            fixed_validator_id(0x11),
            fixed_validator_id(0x22),
            EpochNumber::new(u64::MAX),
        );
        // Saturating successor — stays at u64::MAX.
        assert_eq!(t.effective_at_epoch(), EpochNumber::new(u64::MAX));
    }

    #[test]
    fn slot_transfer_bcs_round_trip() {
        let t = SlotTransfer::new(
            SlotId::new(42),
            fixed_validator_id(0xAA),
            fixed_validator_id(0xBB),
            EpochNumber::new(7),
        );
        let bytes = bcs::to_bytes(&t).unwrap();
        let decoded: SlotTransfer = bcs::from_bytes(&bytes).unwrap();
        assert_eq!(t, decoded);
    }

    /// SlotTransfer BCS encoding: slot_id (2) + seller (32) +
    /// buyer (32) + initiated_at_epoch (8) = 74 bytes.
    #[test]
    fn slot_transfer_bcs_size_pinned() {
        let t = SlotTransfer::new(
            SlotId::new(0),
            fixed_validator_id(0),
            fixed_validator_id(0),
            EpochNumber::new(0),
        );
        let bytes = bcs::to_bytes(&t).unwrap();
        assert_eq!(bytes.len(), 2 + 32 + 32 + 8);
    }
}
