//! Security-tier signal per whitepaper §8.1.7.
//!
//! Adamant exposes a verifiable on-chain property indicating
//! the active set's current size and the resulting security tier.
//! Wallets and applications read the tier signal to adjust user-
//! facing warnings and confirmation requirements.
//!
//! Three tiers are defined:
//!
//! | Tier | Active set | Use cases |
//! |------|------------|-----------|
//! | I    | 7–14       | Ordinary transfers, validator registrations, low-value tx |
//! | II   | 15–29      | Most user transactions, moderate-value contracts |
//! | III  | 30+        | Full design-target security; any application |
//!
//! The N=15 boundary aligns with the §8.4 threshold-encryption
//! viability transition (the chain transitions from time-lock
//! encryption to threshold-encrypted mempool at the same point).
//! The N=30 boundary reflects the point at which BFT collusion
//! attacks (requiring f+1 = 11+ Byzantine validators) are
//! commercially infeasible.
//!
//! Below N=7 the chain halts on disagreement (§8.7); below the
//! constitutional floor there is no tier — the chain is dormant
//! per §8.1.6 / §8.7.1.

use serde::{Deserialize, Serialize};

/// Security-tier signal computed from the active-set size per
/// whitepaper §8.1.7.
///
/// Variant tags are pinned at genesis-fixed BCS encoding values:
/// `Tier1 = 0x00`, `Tier2 = 0x01`, `Tier3 = 0x02`. Reordering
/// is a hard fork.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub enum SecurityTier {
    /// Tier I (low). N=7–14. The chain is operational and
    /// Byzantine-fault-tolerant within its size; suitable for
    /// ordinary transfers, validator registrations, and low-value
    /// transactions. Not suitable for mission-critical
    /// applications.
    Tier1,
    /// Tier II (medium). N=15–29. The chain has crossed the
    /// threshold-encryption viability boundary (§8.4); suitable
    /// for most user transactions and moderate-value contracts.
    /// Not suitable for mission-critical applications.
    Tier2,
    /// Tier III (full). N=30+. Full design-target security; any
    /// application.
    Tier3,
}

impl SecurityTier {
    /// Compute the tier from the active-set size.
    ///
    /// Returns `None` for `n < 7` (below the §8.1.3 constitutional
    /// floor; the chain halts on disagreement per §8.7.1 rather
    /// than producing blocks under reduced safety, so there's no
    /// meaningful tier signal). Returns `Some(Tier1)` for N=7–14,
    /// `Some(Tier2)` for N=15–29, `Some(Tier3)` for N>=30.
    #[must_use]
    pub const fn from_active_set_size(n: usize) -> Option<Self> {
        if n < 7 {
            None
        } else if n < 15 {
            Some(Self::Tier1)
        } else if n < 30 {
            Some(Self::Tier2)
        } else {
            Some(Self::Tier3)
        }
    }

    /// Whether this tier admits the given application class.
    /// Convenience helper for application-side gating per §8.1.7
    /// "applications can choose to gate features by minimum tier."
    ///
    /// Returns `true` iff `self >= required_minimum`. Tier
    /// ordering is `Tier1 < Tier2 < Tier3`.
    #[must_use]
    pub const fn meets_minimum(self, required_minimum: SecurityTier) -> bool {
        self.rank() >= required_minimum.rank()
    }

    /// Numeric rank for ordering. `Tier1 = 1`, `Tier2 = 2`,
    /// `Tier3 = 3`.
    #[must_use]
    const fn rank(self) -> u8 {
        match self {
            Self::Tier1 => 1,
            Self::Tier2 => 2,
            Self::Tier3 => 3,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn below_floor_no_tier() {
        for n in 0..7 {
            assert_eq!(SecurityTier::from_active_set_size(n), None, "n={n}");
        }
    }

    #[test]
    fn tier1_boundary_pin() {
        // §8.1.7: Tier I covers N=7..=14
        assert_eq!(
            SecurityTier::from_active_set_size(7),
            Some(SecurityTier::Tier1)
        );
        assert_eq!(
            SecurityTier::from_active_set_size(14),
            Some(SecurityTier::Tier1)
        );
    }

    #[test]
    fn tier1_to_tier2_transition_at_15() {
        // §8.1.7 + §8.4 threshold-encryption viability boundary
        assert_eq!(
            SecurityTier::from_active_set_size(14),
            Some(SecurityTier::Tier1)
        );
        assert_eq!(
            SecurityTier::from_active_set_size(15),
            Some(SecurityTier::Tier2)
        );
    }

    #[test]
    fn tier2_boundary_pin() {
        // §8.1.7: Tier II covers N=15..=29
        assert_eq!(
            SecurityTier::from_active_set_size(15),
            Some(SecurityTier::Tier2)
        );
        assert_eq!(
            SecurityTier::from_active_set_size(29),
            Some(SecurityTier::Tier2)
        );
    }

    #[test]
    fn tier2_to_tier3_transition_at_30() {
        // §8.1.7: Tier III boundary "f+1 = 11+ Byzantine validators
        // is commercially infeasible" — reaches at N=30
        assert_eq!(
            SecurityTier::from_active_set_size(29),
            Some(SecurityTier::Tier2)
        );
        assert_eq!(
            SecurityTier::from_active_set_size(30),
            Some(SecurityTier::Tier3)
        );
    }

    #[test]
    fn tier3_extends_to_large_active_sets() {
        assert_eq!(
            SecurityTier::from_active_set_size(75),
            Some(SecurityTier::Tier3)
        );
        // Beyond §8.1.3's launch ceiling — soft-ceiling revisions
        // per §8.1.10 stay in Tier III.
        assert_eq!(
            SecurityTier::from_active_set_size(200),
            Some(SecurityTier::Tier3)
        );
    }

    #[test]
    fn meets_minimum_pin() {
        assert!(SecurityTier::Tier1.meets_minimum(SecurityTier::Tier1));
        assert!(!SecurityTier::Tier1.meets_minimum(SecurityTier::Tier2));
        assert!(!SecurityTier::Tier1.meets_minimum(SecurityTier::Tier3));
        assert!(SecurityTier::Tier2.meets_minimum(SecurityTier::Tier1));
        assert!(SecurityTier::Tier2.meets_minimum(SecurityTier::Tier2));
        assert!(!SecurityTier::Tier2.meets_minimum(SecurityTier::Tier3));
        assert!(SecurityTier::Tier3.meets_minimum(SecurityTier::Tier1));
        assert!(SecurityTier::Tier3.meets_minimum(SecurityTier::Tier2));
        assert!(SecurityTier::Tier3.meets_minimum(SecurityTier::Tier3));
    }

    #[test]
    fn bcs_variant_tags_pinned() {
        // §8.1.7 BCS encoding is consensus-binding.
        // BCS uses ULEB128 variant tags; first byte for the first
        // 128 variants is just the tag value.
        assert_eq!(bcs::to_bytes(&SecurityTier::Tier1).unwrap(), vec![0x00]);
        assert_eq!(bcs::to_bytes(&SecurityTier::Tier2).unwrap(), vec![0x01]);
        assert_eq!(bcs::to_bytes(&SecurityTier::Tier3).unwrap(), vec![0x02]);
    }

    #[test]
    fn bcs_round_trip_all_variants() {
        for tier in [
            SecurityTier::Tier1,
            SecurityTier::Tier2,
            SecurityTier::Tier3,
        ] {
            let bytes = bcs::to_bytes(&tier).unwrap();
            let decoded: SecurityTier = bcs::from_bytes(&bytes).unwrap();
            assert_eq!(tier, decoded);
        }
    }
}
