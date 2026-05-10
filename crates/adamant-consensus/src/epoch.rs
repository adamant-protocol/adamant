//! Epoch + round sequence-number newtypes per whitepaper §8.2.
//!
//! [`EpochNumber`] is the count of completed epochs since
//! genesis. Epoch 0 is the genesis epoch; epoch N runs from the
//! `N`-th epoch boundary to the `(N+1)`-th. Validator-set
//! changes, slashing finalisation, and recursive proof
//! aggregation all happen at epoch boundaries.
//!
//! [`RoundNumber`] is the count of consensus rounds within (or
//! across) epochs. The round number is a monotonic index over
//! the chain's full DAG history, NOT reset per epoch.
//!
//! Both types are `u64` newtypes. `u64` capacity at one round
//! per second yields ~5.85 × 10^11 years of unique values —
//! comfortably above any realistic chain lifetime.

use serde::{Deserialize, Serialize};

/// Epoch number per whitepaper §8.2.
///
/// Genesis is `EpochNumber::ZERO`. Each subsequent epoch
/// increments by 1 at the epoch boundary. The recursive proof
/// from epoch N attests "the chain state at the end of epoch N
/// is X" per §8.5.1; the chain of epoch numbers (0, 1, 2, ...)
/// is the index over the recursive-proof chain.
#[derive(
    Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize,
)]
#[repr(transparent)]
pub struct EpochNumber(pub u64);

impl EpochNumber {
    /// Genesis epoch.
    pub const ZERO: Self = Self(0);

    /// Construct from a raw `u64`.
    #[must_use]
    pub const fn new(n: u64) -> Self {
        Self(n)
    }

    /// Underlying `u64`.
    #[must_use]
    pub const fn as_u64(self) -> u64 {
        self.0
    }

    /// Next epoch (saturates at `u64::MAX`).
    #[must_use]
    pub const fn saturating_succ(self) -> Self {
        Self(self.0.saturating_add(1))
    }

    /// Checked next-epoch increment. Returns `None` on overflow
    /// (only possible at `u64::MAX`, which is ~5.85 × 10^11 years
    /// at 1-minute epochs).
    #[must_use]
    pub const fn checked_succ(self) -> Option<Self> {
        match self.0.checked_add(1) {
            Some(v) => Some(Self(v)),
            None => None,
        }
    }
}

/// Consensus round number per whitepaper §8.3.2.
///
/// Round numbers are monotonic over the full DAG history; they
/// are NOT reset at epoch boundaries. The §8.6 consensus VRF
/// binds to `(epoch, round, validator_id)`; the round number is
/// part of the VRF-input domain.
#[derive(
    Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize,
)]
#[repr(transparent)]
pub struct RoundNumber(pub u64);

impl RoundNumber {
    /// Round 0 — the chain's first round, anchored at genesis
    /// activation per §8.1.6.
    pub const ZERO: Self = Self(0);

    /// Construct from a raw `u64`.
    #[must_use]
    pub const fn new(n: u64) -> Self {
        Self(n)
    }

    /// Underlying `u64`.
    #[must_use]
    pub const fn as_u64(self) -> u64 {
        self.0
    }

    /// Next round (saturates at `u64::MAX`).
    #[must_use]
    pub const fn saturating_succ(self) -> Self {
        Self(self.0.saturating_add(1))
    }

    /// Checked next-round increment.
    #[must_use]
    pub const fn checked_succ(self) -> Option<Self> {
        match self.0.checked_add(1) {
            Some(v) => Some(Self(v)),
            None => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_genesis_is_zero() {
        assert_eq!(EpochNumber::ZERO, EpochNumber::new(0));
        assert_eq!(EpochNumber::default(), EpochNumber::ZERO);
    }

    #[test]
    fn epoch_succ_increments() {
        assert_eq!(EpochNumber::new(0).saturating_succ(), EpochNumber::new(1));
        assert_eq!(EpochNumber::new(7).saturating_succ(), EpochNumber::new(8));
    }

    #[test]
    fn epoch_succ_saturates() {
        assert_eq!(
            EpochNumber::new(u64::MAX).saturating_succ(),
            EpochNumber::new(u64::MAX)
        );
        assert_eq!(EpochNumber::new(u64::MAX).checked_succ(), None);
    }

    #[test]
    fn round_zero_is_default() {
        assert_eq!(RoundNumber::ZERO, RoundNumber::new(0));
        assert_eq!(RoundNumber::default(), RoundNumber::ZERO);
    }

    #[test]
    fn round_succ_increments() {
        assert_eq!(RoundNumber::new(5).saturating_succ(), RoundNumber::new(6));
    }

    #[test]
    fn epoch_bcs_round_trip() {
        let e = EpochNumber::new(123_456);
        let bytes = bcs::to_bytes(&e).unwrap();
        let decoded: EpochNumber = bcs::from_bytes(&bytes).unwrap();
        assert_eq!(e, decoded);
    }

    #[test]
    fn round_bcs_round_trip() {
        let r = RoundNumber::new(42);
        let bytes = bcs::to_bytes(&r).unwrap();
        let decoded: RoundNumber = bcs::from_bytes(&bytes).unwrap();
        assert_eq!(r, decoded);
    }

    /// `EpochNumber` and `RoundNumber` are 8-byte little-endian
    /// `u64`s under BCS. Pin the wire size.
    #[test]
    fn sequence_number_bcs_size_pinned() {
        assert_eq!(bcs::to_bytes(&EpochNumber::new(0)).unwrap().len(), 8);
        assert_eq!(bcs::to_bytes(&RoundNumber::new(0)).unwrap().len(), 8);
    }

    /// Ordering is preserved: lower epoch < higher epoch.
    #[test]
    fn epoch_ordering_pin() {
        assert!(EpochNumber::new(0) < EpochNumber::new(1));
        assert!(EpochNumber::new(100) > EpochNumber::new(99));
    }
}
