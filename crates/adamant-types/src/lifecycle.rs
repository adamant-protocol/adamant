//! Object lifecycle state.
//!
//! Per whitepaper section 5.4: an object passes through a defined
//! lifecycle whose state is enforced at the consensus layer. The
//! lifecycle is a **prescriptive** field — it determines whether
//! modifications are permitted — and lives at the top level on
//! [`crate::Object`] rather than inside [`crate::ObjectMetadata`]
//! (which is descriptive bookkeeping).
//!
//! The four runtime states are [`Lifecycle::Active`],
//! [`Lifecycle::Frozen`], [`Lifecycle::Archived`], and
//! [`Lifecycle::Destroyed`]. "Creation" (whitepaper 5.4 step 1) is
//! the entry point into [`Lifecycle::Active`] and is not a separate
//! state.
//!
//! [`Lifecycle::Frozen`] is meaningful only for objects with
//! [`crate::Mutability::UpgradeableUntilFrozen`]: when the freeze
//! operation is invoked, the lifecycle transitions from `Active` to
//! `Frozen` and consensus blocks subsequent upgrades regardless of
//! the [`crate::Mutability`] variant.

use serde::{Deserialize, Serialize};

/// Object lifecycle state (whitepaper section 5.4).
#[derive(Clone, Copy, Eq, PartialEq, Hash, Debug, Serialize, Deserialize)]
pub enum Lifecycle {
    /// The object exists and is subject to mutation per its rules.
    Active,
    /// `UpgradeableUntilFrozen` object on which the freeze operation
    /// has been invoked. Consensus blocks further upgrades; ordinary
    /// state transitions per the existing rules continue to be
    /// valid.
    Frozen,
    /// Storage rent has lapsed; the object's contents are pruned
    /// from validator working storage but its `ObjectId` and
    /// commitment remain in chain state. Cannot be referenced by
    /// new transactions until restored (whitepaper section 5.6.2).
    Archived,
    /// The object has been explicitly destroyed by its type's
    /// logic. Removed from the active state set; the `ObjectId`
    /// cannot be reused.
    Destroyed,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Each lifecycle state has a distinct BCS encoding starting
    /// with its variant tag (a single byte, since there are four
    /// variants and ULEB128 of small values is one byte each).
    /// Tags assigned in source-declaration order.
    #[test]
    fn variant_tags_are_stable() {
        assert_eq!(bcs::to_bytes(&Lifecycle::Active).expect("encode"), [0x00]);
        assert_eq!(bcs::to_bytes(&Lifecycle::Frozen).expect("encode"), [0x01]);
        assert_eq!(bcs::to_bytes(&Lifecycle::Archived).expect("encode"), [0x02]);
        assert_eq!(
            bcs::to_bytes(&Lifecycle::Destroyed).expect("encode"),
            [0x03]
        );
    }

    /// BCS roundtrip for every variant.
    #[test]
    fn bcs_round_trip_all_variants() {
        for variant in [
            Lifecycle::Active,
            Lifecycle::Frozen,
            Lifecycle::Archived,
            Lifecycle::Destroyed,
        ] {
            let encoded = bcs::to_bytes(&variant).expect("encode");
            let decoded: Lifecycle = bcs::from_bytes(&encoded).expect("decode");
            assert_eq!(decoded, variant);
        }
    }
}
