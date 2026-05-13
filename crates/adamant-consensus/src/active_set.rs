//! Active set + standby queue per whitepaper §8.1.3.
//!
//! The **active set** is the subset of registered validators
//! currently responsible for consensus. Membership is granted
//! **first-come-first-served**: when the count of registered,
//! stake-eligible, currently-online validators is at or below
//! the soft ceiling, every such validator is in the active set;
//! when the count exceeds the ceiling, validators are admitted
//! in registration order and the rest enter the standby queue.
//!
//! # Floor (constitutional)
//!
//! [`ACTIVE_SET_FLOOR`] = 7. Below 7 simultaneously-online stake-
//! eligible validators, the chain halts on disagreement per
//! §8.7.1 rather than producing blocks under reduced safety.
//! This is the BFT-with-margin minimum (f=2 Byzantine tolerated
//! plus one offline still leaves the chain safe).
//!
//! # Soft ceiling (launch)
//!
//! [`ACTIVE_SET_LAUNCH_CEILING`] = 75. Calibrated to the
//! residential-fibre profile of the launch period (50,000+ TPS
//! at N=75 on commodity desktop, 1 Gbps fibre, ~100 ms WAN
//! latency). Subject to revision via hard fork per §8.1.10 as
//! the chain's hardware composition evolves.
//!
//! # Slot release mechanisms (§8.1.3)
//!
//! A slot is released when:
//!
//! - (a) the validator is removed for **liveness failure**
//!   (>2 consecutive missed epochs while active per §8.1.5)
//! - (b) the validator **voluntarily unbonds**
//! - (c) the validator **transfers the slot** to another
//!   address per §8.1.8
//!
//! On release, the next standby validator is admitted at the
//! next epoch boundary. There is no forced rotation — a
//! continuously-participating validator retains their slot
//! indefinitely.
//!
//! # Phase 7.1 scope
//!
//! Phase 7.1 ships the in-memory [`ActiveSet`] data structure
//! that validators consult to determine consensus participation.
//! Wiring the on-chain commitment to the active set (referenced
//! by [`crate::GenesisCohortMarker`] and the §8.5.1
//! `EpochCommitment`'s active-validator-set commitment) lands at
//! Phase 7.7 alongside consensus integration.

use std::collections::VecDeque;

use serde::{Deserialize, Serialize};

use crate::epoch::EpochNumber;
use crate::identity::ValidatorId;
use crate::slot::{Slot, SlotId, SlotStatus, SlotTransfer};
use crate::tier::SecurityTier;

/// Constitutional minimum active-set size per whitepaper §8.1.3.
///
/// Below 7 simultaneously-online stake-eligible validators, the
/// chain halts on disagreement per §8.7.1. This is a
/// **constitutional** minimum and is not subject to revision
/// unless the BFT mathematics that justify it changes (per
/// §8.1.10).
pub const ACTIVE_SET_FLOOR: usize = 7;

/// Launch-period soft ceiling per whitepaper §8.1.3.
///
/// 75 validators is the upper bound at which per-validator
/// bandwidth + verification cost remain tractable on residential-
/// fibre hardware (~1 Gbps, commodity desktop). Matches
/// [`crate::GENESIS_COHORT_SIZE`] exactly: the first 75 validators
/// to take an active-set slot during the launch period constitute
/// the genesis cohort.
///
/// **Soft ceiling, subject to revision** via hard fork per
/// §8.1.10 as the chain's hardware composition evolves.
pub const ACTIVE_SET_LAUNCH_CEILING: usize = 75;

/// Errors surfaced by [`ActiveSet`] operations.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum ActiveSetError {
    /// Validator is already registered (either in the active
    /// slots or the standby queue).
    AlreadyRegistered,
    /// Validator is not registered (lookup returned nothing).
    NotRegistered,
    /// Slot id does not correspond to any registered validator.
    UnknownSlot,
    /// Slot-transfer attempted but the buyer validator is not
    /// yet registered. Per §8.1.8 the buyer must already hold a
    /// registered `Validator` record before the transfer can
    /// complete.
    BuyerNotRegistered,
    /// BLS proof-of-possession verification failed at
    /// registration time. Per §3.4.3 + the Crypto C-2
    /// remediation, every validator MUST present a valid PoP
    /// signature binding their BLS public key to the rest of
    /// their key material; without PoP, BLS aggregate
    /// verification is vulnerable to the rogue-key attack.
    /// The validator is NOT admitted; the caller is expected
    /// to reject the registration outright.
    InvalidProofOfPossession(crate::identity::PopError),
}

impl core::fmt::Display for ActiveSetError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::AlreadyRegistered => f.write_str("validator already registered"),
            Self::NotRegistered => f.write_str("validator not registered"),
            Self::UnknownSlot => f.write_str("slot id not found"),
            Self::BuyerNotRegistered => f.write_str("slot-transfer buyer is not registered"),
            Self::InvalidProofOfPossession(e) => write!(
                f,
                "validator registration rejected: invalid BLS proof-of-possession: {e}"
            ),
        }
    }
}

impl std::error::Error for ActiveSetError {}

/// The active set + standby queue per whitepaper §8.1.3.
///
/// Holds:
///
/// - `active`: registration-ordered list of active slots. Length
///   is bounded by `ceiling`.
/// - `standby`: FIFO queue of standby slots. Validators advance
///   from this queue to `active` at epoch boundaries when slots
///   become free.
/// - `ceiling`: configurable soft ceiling. At launch this is
///   [`ACTIVE_SET_LAUNCH_CEILING`] (= 75); §8.1.10 hard-fork
///   revisions modify this value.
/// - `next_slot_id`: monotonic counter so each new registration
///   gets a fresh [`SlotId`]. Slot ids are stable across the
///   slot's lifetime (a slot retains its id across transfers
///   per §8.1.8).
///
/// # Consensus-binding wire format
///
/// On-chain serialisation of the active set per epoch is a
/// `Vec<Slot>` (active slots in registration order). The
/// standby queue is consensus-binding only insofar as the
/// next-to-advance position must be deterministic; Phase 7.7
/// will pin the exact wire commitment shape when consensus
/// integration lands.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ActiveSet {
    /// Active slots in registration order. Length ≤ `ceiling`.
    active: Vec<Slot>,
    /// FIFO standby queue. Validators advance to `active` at
    /// epoch boundaries when active slots open.
    standby: VecDeque<Slot>,
    /// Soft ceiling per §8.1.3. Defaults to
    /// [`ACTIVE_SET_LAUNCH_CEILING`].
    ceiling: usize,
    /// Monotonic counter for next-slot-id assignment.
    next_slot_id: u16,
}

impl ActiveSet {
    /// Construct an empty active set at the launch-period soft
    /// ceiling of 75 per §8.1.3.
    #[must_use]
    pub fn new() -> Self {
        Self::with_ceiling(ACTIVE_SET_LAUNCH_CEILING)
    }

    /// Construct with an explicit ceiling. For tests and for
    /// post-§8.1.10 hard-fork revisions.
    #[must_use]
    pub fn with_ceiling(ceiling: usize) -> Self {
        Self {
            active: Vec::new(),
            standby: VecDeque::new(),
            ceiling,
            next_slot_id: 0,
        }
    }

    /// Current ceiling.
    #[must_use]
    pub const fn ceiling(&self) -> usize {
        self.ceiling
    }

    /// Number of currently-active validators.
    #[must_use]
    pub fn active_size(&self) -> usize {
        self.active.len()
    }

    /// Number of validators in the standby queue.
    #[must_use]
    pub fn standby_size(&self) -> usize {
        self.standby.len()
    }

    /// Whether the chain is dormant per §8.1.6 / §8.7.1:
    /// fewer than [`ACTIVE_SET_FLOOR`] active validators means
    /// the chain halts on disagreement and produces no blocks.
    ///
    /// Returns `true` when `active_size() < ACTIVE_SET_FLOOR`.
    #[must_use]
    pub fn is_dormant(&self) -> bool {
        self.active_size() < ACTIVE_SET_FLOOR
    }

    /// Compute the §8.1.7 [`SecurityTier`] signal. Returns
    /// `None` when the active set is below the constitutional
    /// floor (i.e., dormant).
    #[must_use]
    pub fn tier(&self) -> Option<SecurityTier> {
        SecurityTier::from_active_set_size(self.active_size())
    }

    /// Iterate over active slots in registration order.
    pub fn active_slots(&self) -> impl Iterator<Item = &Slot> {
        self.active.iter()
    }

    /// Iterate over standby slots in queue order (front =
    /// next-to-advance).
    pub fn standby_slots(&self) -> impl Iterator<Item = &Slot> {
        self.standby.iter()
    }

    /// Lookup the [`SlotId`] for a registered [`ValidatorId`].
    /// Returns `None` if the validator is neither active nor in
    /// the standby queue.
    #[must_use]
    pub fn slot_id_of(&self, validator_id: ValidatorId) -> Option<SlotId> {
        self.find_slot(validator_id).map(|s| s.id)
    }

    /// Borrow the slot for a registered validator.
    #[must_use]
    pub fn find_slot(&self, validator_id: ValidatorId) -> Option<&Slot> {
        self.active
            .iter()
            .chain(self.standby.iter())
            .find(|s| s.validator_id == validator_id)
    }

    /// Whether the given validator is in the active set
    /// (producing consensus messages).
    #[must_use]
    pub fn is_active(&self, validator_id: ValidatorId) -> bool {
        self.active.iter().any(|s| s.validator_id == validator_id)
    }

    /// Whether the given validator is in the standby queue.
    #[must_use]
    pub fn is_standby(&self, validator_id: ValidatorId) -> bool {
        self.standby.iter().any(|s| s.validator_id == validator_id)
    }

    /// Register a new validator's [`crate::ValidatorPublicKeys`]
    /// bundle, verifying the bundled BLS proof-of-possession
    /// before admission per the §3.4.3 + Crypto C-2
    /// remediation.
    ///
    /// This is the consensus-binding registration path. The
    /// `ValidatorId` is derived from the bundle and used to
    /// admit the validator into either the active set (FCFS at
    /// or below ceiling) or the standby queue.
    ///
    /// # Errors
    ///
    /// - [`ActiveSetError::InvalidProofOfPossession`] if the
    ///   bundle's PoP doesn't verify. The validator is NOT
    ///   admitted; this is the canonical rogue-key-attack
    ///   defence point.
    /// - [`ActiveSetError::AlreadyRegistered`] if the
    ///   validator (by id) is already in the active set or
    ///   standby queue.
    pub fn register_with_pop(
        &mut self,
        keys: &crate::identity::ValidatorPublicKeys,
        registered_at_epoch: EpochNumber,
    ) -> Result<SlotId, ActiveSetError> {
        keys.verify_pop()
            .map_err(ActiveSetError::InvalidProofOfPossession)?;
        self.register(keys.derive_id(), registered_at_epoch)
    }

    /// Register a new validator by `ValidatorId` directly,
    /// **without** the §3.4.3 PoP check. Reserved for paths
    /// that already verified PoP at a higher layer (e.g.,
    /// deserialising an on-chain `Validator` record that was
    /// admitted under an earlier `register_with_pop` call) and
    /// for test fixtures that don't exercise the PoP path.
    ///
    /// Production-path callers SHOULD invoke
    /// [`Self::register_with_pop`] instead; this method is
    /// retained for backward compatibility with fixture code
    /// that builds an `ActiveSet` from a synthetic validator-id
    /// without going through the full keypair bundle.
    ///
    /// Implements §8.1.3 FCFS admission: if `active.len() <
    /// ceiling`, the validator goes into the active set with
    /// [`SlotStatus::Active`]; otherwise they go to the back of
    /// the standby queue with [`SlotStatus::Standby`].
    ///
    /// Returns the assigned [`SlotId`].
    ///
    /// # Errors
    ///
    /// Returns [`ActiveSetError::AlreadyRegistered`] if the
    /// validator is already in the active set or standby queue.
    pub fn register(
        &mut self,
        validator_id: ValidatorId,
        registered_at_epoch: EpochNumber,
    ) -> Result<SlotId, ActiveSetError> {
        if self.find_slot(validator_id).is_some() {
            return Err(ActiveSetError::AlreadyRegistered);
        }
        let slot_id = SlotId::new(self.next_slot_id);
        self.next_slot_id = self.next_slot_id.saturating_add(1);

        if self.active.len() < self.ceiling {
            self.active.push(Slot::new(
                slot_id,
                validator_id,
                registered_at_epoch,
                SlotStatus::Active,
            ));
        } else {
            self.standby.push_back(Slot::new(
                slot_id,
                validator_id,
                registered_at_epoch,
                SlotStatus::Standby,
            ));
        }
        Ok(slot_id)
    }

    /// Record that a validator participated in consensus at
    /// `participation_epoch`. Used by the liveness-failure
    /// detector ([`Slot::is_liveness_failed`]) to track the
    /// most recent epoch each validator was online.
    ///
    /// No-op if the validator is not registered or not active.
    /// Per §8.1.3 / §8.1.5, only active slots can fail liveness
    /// — standby validators are not expected to participate.
    pub fn record_participation(
        &mut self,
        validator_id: ValidatorId,
        participation_epoch: EpochNumber,
    ) {
        if let Some(slot) = self
            .active
            .iter_mut()
            .find(|s| s.validator_id == validator_id)
        {
            slot.record_participation(participation_epoch);
        }
    }

    /// Remove a validator from the active set (e.g., for
    /// liveness failure per §8.1.5, voluntary unbonding, or
    /// equivocation slashing). Frees the slot for the next
    /// standby validator to advance at the next epoch boundary
    /// via [`Self::advance_standby`].
    ///
    /// Returns the removed [`Slot`] for caller-side accounting
    /// (recording the slashing event, the unbonding-period
    /// start, etc.).
    ///
    /// # Errors
    ///
    /// Returns [`ActiveSetError::NotRegistered`] if the
    /// validator is not in the active set.
    pub fn remove_active(&mut self, validator_id: ValidatorId) -> Result<Slot, ActiveSetError> {
        let pos = self
            .active
            .iter()
            .position(|s| s.validator_id == validator_id)
            .ok_or(ActiveSetError::NotRegistered)?;
        let mut removed = self.active.remove(pos);
        removed.status = SlotStatus::Inactive;
        Ok(removed)
    }

    /// Advance the front of the standby queue into the active
    /// set, taking the open slot. Called at epoch boundaries
    /// after a [`Self::remove_active`] frees a slot per §8.1.3.
    ///
    /// Returns the [`SlotId`] of the validator that advanced,
    /// or `None` if the standby queue was empty (active set
    /// stays under-filled).
    pub fn advance_standby(&mut self) -> Option<SlotId> {
        if self.active.len() >= self.ceiling {
            // No room — caller should have removed an active
            // validator first.
            return None;
        }
        let mut advanced = self.standby.pop_front()?;
        advanced.status = SlotStatus::Active;
        let slot_id = advanced.id;
        self.active.push(advanced);
        Some(slot_id)
    }

    /// Scan the active set for validators in liveness-failure
    /// state per §8.1.5 (more than 2 consecutive missed epochs).
    /// Returns the [`ValidatorId`]s of every active validator
    /// that has failed liveness at `current_epoch`.
    ///
    /// The caller is responsible for removing the failed
    /// validators ([`Self::remove_active`]) and applying the
    /// §8.1.5 slashing penalty.
    #[must_use]
    pub fn liveness_failed_at(&self, current_epoch: EpochNumber) -> Vec<ValidatorId> {
        self.active
            .iter()
            .filter(|s| s.is_liveness_failed(current_epoch))
            .map(|s| s.validator_id)
            .collect()
    }

    /// Apply a [`SlotTransfer`] per §8.1.8: reassign the bound
    /// validator on `slot_id` from the seller to the buyer.
    /// Slot ordering / seniority is preserved (the slot's
    /// position in the active list is not changed).
    ///
    /// Both seller and buyer must already be registered. The
    /// seller must currently hold the slot identified by
    /// `transfer.slot_id`. After the transfer, the buyer is
    /// active in that slot and the seller is removed from the
    /// active set (their previous standby/active record is
    /// dropped).
    ///
    /// # Errors
    ///
    /// - [`ActiveSetError::UnknownSlot`] if `slot_id` does not
    ///   match any active slot, or the slot's bound validator
    ///   does not equal `seller_validator_id`.
    /// - [`ActiveSetError::BuyerNotRegistered`] if the buyer is
    ///   not currently registered (either active or standby).
    ///
    /// # Panics
    ///
    /// Cannot panic in practice: the function first verifies
    /// the buyer is in standby (or rejects via `BuyerNotRegistered`)
    /// before extracting their standby position, so the
    /// `.expect("checked buyer_in_standby")` is unreachable.
    pub fn apply_transfer(&mut self, transfer: &SlotTransfer) -> Result<(), ActiveSetError> {
        // Locate the seller's slot in the active list.
        let seller_pos = self
            .active
            .iter()
            .position(|s| {
                s.id == transfer.slot_id && s.validator_id == transfer.seller_validator_id
            })
            .ok_or(ActiveSetError::UnknownSlot)?;

        // Locate the buyer. If buyer is in standby, remove from
        // standby. If buyer is also in active, that's a buyer
        // already-holds-a-slot case — caller should have
        // de-registered first. For Phase 7.1 simplicity, reject.
        let buyer_in_active = self
            .active
            .iter()
            .any(|s| s.validator_id == transfer.buyer_validator_id);
        let buyer_in_standby = self
            .standby
            .iter()
            .any(|s| s.validator_id == transfer.buyer_validator_id);
        if !buyer_in_active && !buyer_in_standby {
            return Err(ActiveSetError::BuyerNotRegistered);
        }
        if buyer_in_active {
            // Already-held slot for the buyer: spec leaves this
            // edge case implicit (the buyer would presumably
            // hold two slots, which contradicts §8.1.3's "every
            // validator has at most one slot" implication).
            // Phase 7.1: reject as an unsupported pre-condition.
            return Err(ActiveSetError::AlreadyRegistered);
        }

        // Remove buyer from standby.
        let buyer_standby_pos = self
            .standby
            .iter()
            .position(|s| s.validator_id == transfer.buyer_validator_id)
            .expect("checked buyer_in_standby");
        let _buyer_slot = self.standby.remove(buyer_standby_pos);

        // Rewrite seller's slot to bind to buyer per §8.1.8
        // step 3 ("Reassigns the slot to the buyer's address
        // with no change in slot ordering or seniority").
        let seller_slot = &mut self.active[seller_pos];
        seller_slot.validator_id = transfer.buyer_validator_id;
        seller_slot.bound_at_epoch = transfer.effective_at_epoch();
        seller_slot.last_participation_epoch = transfer.effective_at_epoch();
        // status stays Active; slot id stays the same.

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vid(byte: u8) -> ValidatorId {
        ValidatorId::from_bytes([byte; 32])
    }

    #[allow(
        clippy::cast_possible_truncation,
        reason = "test fixture caps n at u8::MAX"
    )]
    fn fill_active_set(set: &mut ActiveSet, n: usize) -> Vec<ValidatorId> {
        let mut ids = Vec::with_capacity(n);
        for i in 0..n {
            let id = vid(i as u8);
            set.register(id, EpochNumber::new(0)).unwrap();
            ids.push(id);
        }
        ids
    }

    // ---------- constants ----------

    #[test]
    fn floor_pinned_at_7() {
        assert_eq!(ACTIVE_SET_FLOOR, 7);
    }

    #[test]
    fn launch_ceiling_pinned_at_75() {
        assert_eq!(ACTIVE_SET_LAUNCH_CEILING, 75);
    }

    #[test]
    fn launch_ceiling_matches_genesis_cohort_size() {
        assert_eq!(
            u8::try_from(ACTIVE_SET_LAUNCH_CEILING).expect("75 fits in u8"),
            crate::GENESIS_COHORT_SIZE,
            "§8.1.3 ceiling must match §8.1.9 genesis cohort size at launch"
        );
    }

    // ---------- empty / dormant ----------

    #[test]
    fn empty_set_is_dormant() {
        let set = ActiveSet::new();
        assert!(set.is_dormant());
        assert_eq!(set.tier(), None);
        assert_eq!(set.active_size(), 0);
        assert_eq!(set.standby_size(), 0);
    }

    #[test]
    fn at_floor_minus_one_still_dormant() {
        let mut set = ActiveSet::new();
        fill_active_set(&mut set, 6);
        assert!(set.is_dormant());
        assert_eq!(set.tier(), None);
    }

    #[test]
    fn at_floor_is_active() {
        let mut set = ActiveSet::new();
        fill_active_set(&mut set, 7);
        assert!(!set.is_dormant());
        assert_eq!(set.tier(), Some(SecurityTier::Tier1));
    }

    // ---------- registration / FCFS ----------

    #[test]
    fn registration_at_or_below_ceiling_is_active() {
        let mut set = ActiveSet::with_ceiling(3);
        let slot0 = set.register(vid(1), EpochNumber::new(0)).unwrap();
        let slot1 = set.register(vid(2), EpochNumber::new(0)).unwrap();
        let slot2 = set.register(vid(3), EpochNumber::new(0)).unwrap();
        assert_eq!(slot0, SlotId::new(0));
        assert_eq!(slot1, SlotId::new(1));
        assert_eq!(slot2, SlotId::new(2));
        assert_eq!(set.active_size(), 3);
        assert_eq!(set.standby_size(), 0);
        assert!(set.is_active(vid(1)));
        assert!(set.is_active(vid(2)));
        assert!(set.is_active(vid(3)));
    }

    #[test]
    fn registration_above_ceiling_goes_to_standby() {
        let mut set = ActiveSet::with_ceiling(2);
        set.register(vid(1), EpochNumber::new(0)).unwrap();
        set.register(vid(2), EpochNumber::new(0)).unwrap();
        // Third registration overflows the ceiling.
        let slot2 = set.register(vid(3), EpochNumber::new(0)).unwrap();
        assert_eq!(slot2, SlotId::new(2));
        assert_eq!(set.active_size(), 2);
        assert_eq!(set.standby_size(), 1);
        assert!(set.is_standby(vid(3)));
        assert!(!set.is_active(vid(3)));
    }

    #[test]
    fn double_registration_rejected() {
        let mut set = ActiveSet::new();
        set.register(vid(1), EpochNumber::new(0)).unwrap();
        let result = set.register(vid(1), EpochNumber::new(0));
        assert_eq!(result, Err(ActiveSetError::AlreadyRegistered));
    }

    #[test]
    fn slot_ids_are_monotonic_and_stable() {
        let mut set = ActiveSet::with_ceiling(3);
        let s0 = set.register(vid(1), EpochNumber::new(0)).unwrap();
        let s1 = set.register(vid(2), EpochNumber::new(0)).unwrap();
        assert_eq!(s0.as_u16(), 0);
        assert_eq!(s1.as_u16(), 1);
        // Remove + re-add: monotonic counter advances; the
        // removed slot id is NOT reused (consensus-binding
        // stability).
        set.remove_active(vid(1)).unwrap();
        let s2 = set.register(vid(3), EpochNumber::new(0)).unwrap();
        assert_eq!(s2.as_u16(), 2);
    }

    // ---------- liveness ----------

    #[test]
    fn record_participation_updates_active_slot() {
        let mut set = ActiveSet::new();
        set.register(vid(1), EpochNumber::new(0)).unwrap();
        set.record_participation(vid(1), EpochNumber::new(5));
        let slot = set.find_slot(vid(1)).unwrap();
        assert_eq!(slot.last_participation_epoch, EpochNumber::new(5));
    }

    #[test]
    fn liveness_failed_at_detects_missed_validators() {
        let mut set = ActiveSet::new();
        set.register(vid(1), EpochNumber::new(0)).unwrap();
        set.register(vid(2), EpochNumber::new(0)).unwrap();
        // vid(2) participates at epoch 10; vid(1) does not.
        set.record_participation(vid(2), EpochNumber::new(10));
        // At epoch 4, vid(1) has missed epochs 1,2,3 (3 misses,
        // > 2). vid(1) should be flagged. vid(2)'s last
        // participation is 10, far in the future relative to 4
        // — not failed.
        let failed = set.liveness_failed_at(EpochNumber::new(4));
        assert_eq!(failed, vec![vid(1)]);
    }

    #[test]
    fn standby_validators_never_fail_liveness() {
        let mut set = ActiveSet::with_ceiling(1);
        set.register(vid(1), EpochNumber::new(0)).unwrap();
        set.register(vid(2), EpochNumber::new(0)).unwrap();
        assert!(set.is_standby(vid(2)));
        // Many epochs later, vid(2) is still in standby. Should
        // NOT be flagged for liveness failure even though their
        // last_participation_epoch is at 0.
        let failed = set.liveness_failed_at(EpochNumber::new(100));
        assert!(!failed.contains(&vid(2)));
    }

    // ---------- removal / standby advancement ----------

    #[test]
    fn remove_active_then_advance_promotes_standby() {
        let mut set = ActiveSet::with_ceiling(2);
        set.register(vid(1), EpochNumber::new(0)).unwrap();
        set.register(vid(2), EpochNumber::new(0)).unwrap();
        set.register(vid(3), EpochNumber::new(0)).unwrap();
        assert!(set.is_active(vid(1)));
        assert!(set.is_standby(vid(3)));

        // Remove vid(1) — slot frees.
        let removed = set.remove_active(vid(1)).unwrap();
        assert_eq!(removed.validator_id, vid(1));
        assert_eq!(removed.status, SlotStatus::Inactive);
        assert_eq!(set.active_size(), 1);
        assert_eq!(set.standby_size(), 1);

        // Advance standby — vid(3) promotes.
        let promoted = set.advance_standby();
        assert_eq!(promoted, Some(SlotId::new(2)));
        assert!(set.is_active(vid(3)));
        assert_eq!(set.active_size(), 2);
        assert_eq!(set.standby_size(), 0);
    }

    #[test]
    fn advance_standby_no_room_returns_none() {
        let mut set = ActiveSet::with_ceiling(1);
        set.register(vid(1), EpochNumber::new(0)).unwrap();
        set.register(vid(2), EpochNumber::new(0)).unwrap();
        // Active is full; advance refuses.
        assert_eq!(set.advance_standby(), None);
    }

    #[test]
    fn advance_standby_empty_queue_returns_none() {
        let mut set = ActiveSet::with_ceiling(5);
        set.register(vid(1), EpochNumber::new(0)).unwrap();
        // No standby — advance returns None.
        assert_eq!(set.advance_standby(), None);
    }

    #[test]
    fn standby_advances_fifo() {
        let mut set = ActiveSet::with_ceiling(1);
        set.register(vid(1), EpochNumber::new(0)).unwrap();
        // vid(2), vid(3), vid(4) enter standby in order.
        set.register(vid(2), EpochNumber::new(0)).unwrap();
        set.register(vid(3), EpochNumber::new(0)).unwrap();
        set.register(vid(4), EpochNumber::new(0)).unwrap();

        set.remove_active(vid(1)).unwrap();
        set.advance_standby();
        // First-in (vid(2)) advances first.
        assert!(set.is_active(vid(2)));

        set.remove_active(vid(2)).unwrap();
        set.advance_standby();
        // Then vid(3).
        assert!(set.is_active(vid(3)));
        assert!(set.is_standby(vid(4)));
    }

    // ---------- slot transfer ----------

    #[test]
    fn apply_transfer_swaps_binding_preserves_slot_id() {
        // Ceiling=1 ensures vid(2) is in standby (the buyer
        // pre-condition per §8.1.8: buyer must be registered
        // but not occupy an active slot of their own).
        let mut set = ActiveSet::with_ceiling(1);
        set.register(vid(1), EpochNumber::new(0)).unwrap();
        set.register(vid(2), EpochNumber::new(0)).unwrap();
        assert!(set.is_active(vid(1)));
        assert!(set.is_standby(vid(2)));

        let transfer = SlotTransfer::new(SlotId::new(0), vid(1), vid(2), EpochNumber::new(5));
        set.apply_transfer(&transfer).unwrap();

        // Buyer is now active in the seller's old slot.
        assert!(set.is_active(vid(2)));
        // Seller is no longer in the active set.
        assert!(!set.is_active(vid(1)));
        // Slot id is preserved.
        assert_eq!(set.slot_id_of(vid(2)), Some(SlotId::new(0)));
        // Standby no longer contains buyer (they advanced via
        // transfer, not via standby promotion).
        assert!(!set.is_standby(vid(2)));
        // bound_at_epoch advances to the effective epoch.
        let slot = set.find_slot(vid(2)).unwrap();
        assert_eq!(slot.bound_at_epoch, EpochNumber::new(6));
    }

    #[test]
    fn apply_transfer_unknown_slot_rejected() {
        let mut set = ActiveSet::new();
        set.register(vid(1), EpochNumber::new(0)).unwrap();
        set.register(vid(2), EpochNumber::new(0)).unwrap();
        let transfer = SlotTransfer::new(SlotId::new(99), vid(1), vid(2), EpochNumber::new(5));
        let result = set.apply_transfer(&transfer);
        assert_eq!(result, Err(ActiveSetError::UnknownSlot));
    }

    #[test]
    fn apply_transfer_buyer_not_registered_rejected() {
        let mut set = ActiveSet::new();
        set.register(vid(1), EpochNumber::new(0)).unwrap();
        // Buyer vid(2) is NOT registered.
        let transfer = SlotTransfer::new(SlotId::new(0), vid(1), vid(2), EpochNumber::new(5));
        let result = set.apply_transfer(&transfer);
        assert_eq!(result, Err(ActiveSetError::BuyerNotRegistered));
    }

    #[test]
    fn apply_transfer_seller_validator_id_mismatch_rejected() {
        let mut set = ActiveSet::new();
        set.register(vid(1), EpochNumber::new(0)).unwrap();
        set.register(vid(2), EpochNumber::new(0)).unwrap();
        // Transfer claims vid(3) is the seller, but slot 0 is
        // held by vid(1).
        let transfer = SlotTransfer::new(SlotId::new(0), vid(3), vid(2), EpochNumber::new(5));
        let result = set.apply_transfer(&transfer);
        assert_eq!(result, Err(ActiveSetError::UnknownSlot));
    }

    // ---------- BCS round-trip ----------

    #[test]
    fn active_set_bcs_round_trip() {
        let mut set = ActiveSet::with_ceiling(3);
        set.register(vid(1), EpochNumber::new(0)).unwrap();
        set.register(vid(2), EpochNumber::new(0)).unwrap();
        set.register(vid(3), EpochNumber::new(0)).unwrap();
        set.register(vid(4), EpochNumber::new(0)).unwrap();
        let bytes = bcs::to_bytes(&set).unwrap();
        let decoded: ActiveSet = bcs::from_bytes(&bytes).unwrap();
        assert_eq!(set, decoded);
    }

    // ---------- tier transitions during operation ----------

    #[test]
    fn tier_transitions_as_active_set_grows() {
        let mut set = ActiveSet::new();
        for i in 0u8..7 {
            set.register(vid(i), EpochNumber::new(0)).unwrap();
        }
        assert_eq!(set.tier(), Some(SecurityTier::Tier1));
        // Grow to 15: crosses into Tier II.
        for i in 7u8..15 {
            set.register(vid(i), EpochNumber::new(0)).unwrap();
        }
        assert_eq!(set.tier(), Some(SecurityTier::Tier2));
        // Grow to 30: crosses into Tier III.
        for i in 15u8..30 {
            set.register(vid(i), EpochNumber::new(0)).unwrap();
        }
        assert_eq!(set.tier(), Some(SecurityTier::Tier3));
    }

    // ---------- Crypto C-2 remediation: register_with_pop ----------

    /// `register_with_pop` admits a validator whose bundle
    /// carries a valid PoP.
    #[test]
    fn register_with_pop_admits_honest_validator() {
        use crate::identity::ValidatorPublicKeys;
        let sk = adamant_crypto::bls::SecretKey::from_ikm(&[0x77; 32]).expect("bls");
        let keys = ValidatorPublicKeys::with_pop(
            [0x11; 32],
            [0x22; 1952],
            sk.public_key().to_bytes(),
            &sk,
        )
        .expect("ok");
        let mut set = ActiveSet::new();
        set.register_with_pop(&keys, EpochNumber::new(0))
            .expect("honest validator must be admitted");
        assert_eq!(set.active_size(), 1);
    }

    /// `register_with_pop` REJECTS a validator whose bundle
    /// carries a forged or otherwise-invalid PoP — the canonical
    /// rogue-key-attack defence point.
    #[test]
    fn register_with_pop_rejects_invalid_pop() {
        use crate::identity::ValidatorPublicKeys;
        let sk_target = adamant_crypto::bls::SecretKey::from_ikm(&[0xAA; 32]).expect("target");
        let sk_attacker = adamant_crypto::bls::SecretKey::from_ikm(&[0xBB; 32]).expect("attacker");
        // Attacker constructs a bundle advertising the target's
        // BLS public key with a PoP signed under their own secret.
        let ed = [0x11; 32];
        let ml = [0x22; 1952];
        let pop_message =
            crate::identity::compute_bls_pop_message(&ed, &ml, &sk_target.public_key().to_bytes());
        let forged_pop = sk_attacker.sign(&pop_message);
        let attack_bundle = ValidatorPublicKeys::new(
            ed,
            ml,
            sk_target.public_key().to_bytes(),
            forged_pop.to_bytes(),
        );
        let mut set = ActiveSet::new();
        let err = set
            .register_with_pop(&attack_bundle, EpochNumber::new(0))
            .expect_err("must reject rogue-key bundle");
        assert!(matches!(err, ActiveSetError::InvalidProofOfPossession(_)));
        // State unchanged.
        assert_eq!(set.active_size(), 0);
    }
}
