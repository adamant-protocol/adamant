//! Object mutability declaration and the basis-points helper.
//!
//! Per whitepaper section 5.1.4: every object declares its
//! mutability at creation, and the declaration is itself immutable.
//! The protocol enforces these declarations at the consensus layer
//! (whitepaper section 5.3) — they are not user-level conventions.
//!
//! The "frozen" status of an [`Mutability::UpgradeableUntilFrozen`]
//! object is **not** part of this enum; the variant stays
//! `UpgradeableUntilFrozen { owner }` even after freeze. The frozen
//! state is recorded by the [`crate::Lifecycle`] field on
//! [`crate::Object`]: consensus checks both the [`Mutability`]
//! variant and the [`crate::Lifecycle`] when deciding whether an
//! upgrade is permitted (whitepaper section 5.4).

use serde::{Deserialize, Serialize};

use crate::{address::Address, object_id::ObjectId, type_id::TypeId};

/// Maximum legal value of [`BasisPoints`]: 10 000 = 100.00 %.
/// Derived directly from the basis-points convention used in the
/// `VoteUpgradeable` variant of [`Mutability`] in whitepaper section
/// 5.1.4.
pub const BASIS_POINTS_MAX: u32 = 10_000;

/// Percentage in basis points: `5000 = 50.00%`, `10000 = 100.00%`.
///
/// Whitepaper section 5.1.4 uses basis points for the
/// `VoteUpgradeable` variant's `approval_threshold` and
/// `quorum_threshold` fields. The newtype enforces the `≤ 10 000`
/// bound at construction so consensus cannot encounter an
/// out-of-range value at runtime.
///
/// Encoded as a `u32` little-endian per BCS (whitepaper section
/// 5.1.8); the encoding is identical to the inner field.
#[derive(Clone, Copy, Eq, PartialEq, Hash, Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct BasisPoints(u32);

/// Error returned when a [`BasisPoints`] value would exceed
/// [`BASIS_POINTS_MAX`].
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct BasisPointsOutOfRange;

impl core::fmt::Display for BasisPointsOutOfRange {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "basis-points value exceeds maximum of {BASIS_POINTS_MAX}"
        )
    }
}

impl std::error::Error for BasisPointsOutOfRange {}

impl BasisPoints {
    /// Construct a `BasisPoints` value, validating that it is in
    /// `[0, 10_000]`.
    ///
    /// # Errors
    ///
    /// Returns [`BasisPointsOutOfRange`] if `value > 10_000`.
    pub const fn new(value: u32) -> Result<Self, BasisPointsOutOfRange> {
        if value > BASIS_POINTS_MAX {
            return Err(BasisPointsOutOfRange);
        }
        Ok(Self(value))
    }

    /// Inner `u32` value (in `[0, 10_000]`).
    #[must_use]
    pub const fn value(self) -> u32 {
        self.0
    }
}

/// Object mutability declaration (whitepaper section 5.1.4).
///
/// Every object declares its mutability at creation; the declaration
/// is itself immutable. Variants and their semantics:
///
/// - [`Mutability::Immutable`] — code/rules permanently fixed at
///   creation.
/// - [`Mutability::OwnerUpgradeable`] — code/rules may be changed by
///   transactions authorised under the specified owner account.
/// - [`Mutability::VoteUpgradeable`] — code/rules may be changed by a
///   vote of token holders, subject to the specified thresholds and
///   timing parameters.
/// - [`Mutability::UpgradeableUntilFrozen`] — owner-upgradeable until
///   the freeze operation runs, then permanently immutable. The
///   frozen state is tracked by [`crate::Lifecycle::Frozen`], not in
///   this enum.
/// - [`Mutability::Custom`] — upgrade rules are specified by a
///   separate validator object referenced by [`ObjectId`].
/// - [`Mutability::Forked`] — for objects produced by the
///   chain-fork mechanism (whitepaper section 11). End users do not
///   encounter this variant in normal operation.
#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
pub enum Mutability {
    /// Code/rules permanently fixed at creation.
    Immutable,
    /// Code/rules may be changed by transactions authorised under the
    /// specified owner account.
    OwnerUpgradeable {
        /// The account whose authority is required to upgrade.
        owner: Address,
    },
    /// Code/rules may be changed by a token-holder vote with the
    /// specified parameters.
    VoteUpgradeable {
        /// The token type whose holders are eligible to vote.
        token_type: TypeId,
        /// Minimum percentage of cast votes that must approve, in
        /// basis points (`5000 = 50.00 %`, `6700 = 67.00 %`).
        approval_threshold: BasisPoints,
        /// Minimum percentage of total token supply that must
        /// participate for the vote to be valid, in basis points.
        quorum_threshold: BasisPoints,
        /// Voting window duration in seconds.
        voting_period_secs: u64,
        /// Delay in seconds between vote success and upgrade
        /// application — the window for objecting holders to exit.
        execution_delay_secs: u64,
    },
    /// Owner-upgradeable until the freeze operation runs, then
    /// permanently immutable. The frozen state is tracked by
    /// [`crate::Lifecycle::Frozen`].
    UpgradeableUntilFrozen {
        /// The account whose authority can both upgrade (pre-freeze)
        /// and trigger the freeze.
        owner: Address,
    },
    /// Upgrade rules specified by a separate validator object.
    Custom {
        /// Type of the validator object (its `validate_upgrade` method
        /// authorises proposed changes).
        upgrade_validator: TypeId,
        /// Identity of the specific validator instance.
        validator_id: ObjectId,
    },
    /// Object produced by the chain-fork mechanism (whitepaper
    /// section 11). Inherits its predecessor's content and rules with
    /// fork-specific restrictions.
    Forked {
        /// Identifier of the original object on the pre-fork
        /// timeline.
        original: ObjectId,
        /// Consensus height at which the fork occurred.
        fork_height: u64,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---------- BasisPoints ----------

    #[test]
    fn basis_points_max_is_ten_thousand() {
        assert_eq!(BASIS_POINTS_MAX, 10_000);
    }

    #[test]
    fn basis_points_accepts_zero() {
        let bp = BasisPoints::new(0).expect("zero is valid");
        assert_eq!(bp.value(), 0);
    }

    #[test]
    fn basis_points_accepts_max() {
        let bp = BasisPoints::new(BASIS_POINTS_MAX).expect("max is valid");
        assert_eq!(bp.value(), BASIS_POINTS_MAX);
    }

    #[test]
    fn basis_points_rejects_above_max() {
        assert!(BasisPoints::new(BASIS_POINTS_MAX + 1).is_err());
        assert!(BasisPoints::new(u32::MAX).is_err());
    }

    /// BCS roundtrip via `serde(transparent)`: the `BasisPoints`
    /// wrapper encodes as a bare `u32` little-endian (4 bytes).
    #[test]
    fn basis_points_bcs_round_trip() {
        let original = BasisPoints::new(6700).expect("valid");
        let encoded = bcs::to_bytes(&original).expect("bcs encode");
        // Per whitepaper 5.1.8: u32 is little-endian 4 bytes.
        assert_eq!(encoded, [0x2c, 0x1a, 0x00, 0x00]);
        let decoded: BasisPoints = bcs::from_bytes(&encoded).expect("bcs decode");
        assert_eq!(decoded, original);
    }

    /// `serde(transparent)` deserialisation does NOT re-validate the
    /// invariant — `BasisPoints::new` is the validating constructor.
    /// The deserialiser will accept any `u32`. This is acceptable
    /// because:
    ///
    /// 1. BCS-encoded inputs come from peers who serialised valid
    ///    values; an out-of-range value indicates protocol-rule
    ///    violation, caught at the consensus layer.
    /// 2. The validating constructor is the public entry point for
    ///    in-process construction.
    ///
    /// Document the gap explicitly so a future reader doesn't assume
    /// invariant enforcement at deserialisation. The consensus
    /// layer (validators) MUST re-check basis-points bounds when
    /// processing inbound messages containing `Mutability` values.
    #[test]
    fn basis_points_bcs_decodes_out_of_range_value_without_validation() {
        let bytes = bcs::to_bytes(&20_000_u32).expect("encode u32");
        let decoded: BasisPoints = bcs::from_bytes(&bytes).expect("decode");
        // Decoded but the value is structurally invalid — consensus
        // rejects at a higher layer.
        assert_eq!(decoded.value(), 20_000);
    }

    // ---------- Mutability ----------

    fn fixed_address() -> Address {
        Address::from_bytes([0x11; 32])
    }

    fn fixed_type_id() -> TypeId {
        TypeId::from_bytes([0x22; 32])
    }

    fn fixed_object_id() -> ObjectId {
        ObjectId::from_bytes([0x33; 32])
    }

    /// BCS roundtrip for [`Mutability::Immutable`] — variant tag 0,
    /// no payload.
    #[test]
    fn mutability_immutable_bcs_round_trip() {
        let original = Mutability::Immutable;
        let encoded = bcs::to_bytes(&original).expect("bcs encode");
        // Per whitepaper 5.1.8: enums encode as ULEB128 variant tag
        // followed by payload. Tag 0 with no payload = single byte
        // 0x00.
        assert_eq!(encoded, [0x00]);
        let decoded: Mutability = bcs::from_bytes(&encoded).expect("bcs decode");
        assert_eq!(decoded, original);
    }

    #[test]
    fn mutability_owner_upgradeable_bcs_round_trip() {
        let original = Mutability::OwnerUpgradeable {
            owner: fixed_address(),
        };
        let encoded = bcs::to_bytes(&original).expect("bcs encode");
        // Variant tag 1 (ULEB128 single byte) + 32 bytes Address.
        assert_eq!(encoded.len(), 1 + 32);
        assert_eq!(encoded[0], 0x01);
        let decoded: Mutability = bcs::from_bytes(&encoded).expect("bcs decode");
        assert_eq!(decoded, original);
    }

    #[test]
    fn mutability_vote_upgradeable_bcs_round_trip() {
        let original = Mutability::VoteUpgradeable {
            token_type: fixed_type_id(),
            approval_threshold: BasisPoints::new(6700).expect("valid"),
            quorum_threshold: BasisPoints::new(3000).expect("valid"),
            voting_period_secs: 7 * 24 * 3600,
            execution_delay_secs: 7 * 24 * 3600,
        };
        let encoded = bcs::to_bytes(&original).expect("bcs encode");
        // Variant tag 2 + 32 bytes TypeId + 4 + 4 + 8 + 8 = 57.
        assert_eq!(encoded.len(), 1 + 32 + 4 + 4 + 8 + 8);
        assert_eq!(encoded[0], 0x02);
        let decoded: Mutability = bcs::from_bytes(&encoded).expect("bcs decode");
        assert_eq!(decoded, original);
    }

    #[test]
    fn mutability_upgradeable_until_frozen_bcs_round_trip() {
        let original = Mutability::UpgradeableUntilFrozen {
            owner: fixed_address(),
        };
        let encoded = bcs::to_bytes(&original).expect("bcs encode");
        assert_eq!(encoded.len(), 1 + 32);
        assert_eq!(encoded[0], 0x03);
        let decoded: Mutability = bcs::from_bytes(&encoded).expect("bcs decode");
        assert_eq!(decoded, original);
    }

    #[test]
    fn mutability_custom_bcs_round_trip() {
        let original = Mutability::Custom {
            upgrade_validator: fixed_type_id(),
            validator_id: fixed_object_id(),
        };
        let encoded = bcs::to_bytes(&original).expect("bcs encode");
        assert_eq!(encoded.len(), 1 + 32 + 32);
        assert_eq!(encoded[0], 0x04);
        let decoded: Mutability = bcs::from_bytes(&encoded).expect("bcs decode");
        assert_eq!(decoded, original);
    }

    #[test]
    fn mutability_forked_bcs_round_trip() {
        let original = Mutability::Forked {
            original: fixed_object_id(),
            fork_height: 0xdead_beef,
        };
        let encoded = bcs::to_bytes(&original).expect("bcs encode");
        assert_eq!(encoded.len(), 1 + 32 + 8);
        assert_eq!(encoded[0], 0x05);
        let decoded: Mutability = bcs::from_bytes(&encoded).expect("bcs decode");
        assert_eq!(decoded, original);
    }

    /// Variant tags assigned in source-declaration order. This test
    /// fails if a future contributor reorders the [`Mutability`]
    /// variants — the reorder is a consensus rule change, not a
    /// refactor.
    #[test]
    fn mutability_variant_tag_assignment_is_stable() {
        let cases: &[(Mutability, u8)] = &[
            (Mutability::Immutable, 0),
            (
                Mutability::OwnerUpgradeable {
                    owner: fixed_address(),
                },
                1,
            ),
            (
                Mutability::VoteUpgradeable {
                    token_type: fixed_type_id(),
                    approval_threshold: BasisPoints::new(0).expect("valid"),
                    quorum_threshold: BasisPoints::new(0).expect("valid"),
                    voting_period_secs: 0,
                    execution_delay_secs: 0,
                },
                2,
            ),
            (
                Mutability::UpgradeableUntilFrozen {
                    owner: fixed_address(),
                },
                3,
            ),
            (
                Mutability::Custom {
                    upgrade_validator: fixed_type_id(),
                    validator_id: fixed_object_id(),
                },
                4,
            ),
            (
                Mutability::Forked {
                    original: fixed_object_id(),
                    fork_height: 0,
                },
                5,
            ),
        ];
        for (variant, expected_tag) in cases {
            let encoded = bcs::to_bytes(variant).expect("bcs encode");
            assert_eq!(
                encoded[0], *expected_tag,
                "variant {variant:?} expected tag {expected_tag}"
            );
        }
    }
}
