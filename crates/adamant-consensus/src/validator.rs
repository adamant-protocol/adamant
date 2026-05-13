//! Bonded stake + on-chain `Validator` object types per
//! whitepaper §8.1.2.
//!
//! A `Validator` is the on-chain record that a particular
//! account has registered as a validator with a specific public-
//! key bundle and bonded stake. Stake is at risk of slashing for
//! the §8.1.5 misbehaviour categories ([`crate::SlashOffence`]).
//!
//! # Stake units
//!
//! [`Stake`] is a `u64` count of ADM **micro-units**: 1 ADM =
//! 10^6 micro-units. Per §11.5.4 the launch minimum validator
//! stake is `1_000` ADM = `1_000_000_000` micro-units; pre-mainnet
//! calibration may revise this value, with revisions tracked in
//! `crate::MIN_VALIDATOR_STAKE_LAUNCH`'s doc comment.
//!
//! # `Validator` object shape
//!
//! Per §8.1.2 the on-chain `Validator` is created by a
//! `register_validator` transaction. Phase 7.0 defines the wire
//! shape; Phase 7.10 wires the actual deployment-transaction
//! handler that constructs a `Validator` object on chain.

use adamant_types::Address;
use serde::{Deserialize, Serialize};

use crate::epoch::EpochNumber;
use crate::identity::{ValidatorId, ValidatorPublicKeys};

/// Bonded validator stake in ADM micro-units (1 ADM = 10^6
/// micro-units per §10).
///
/// `Stake` is a transparent newtype around `u64` chosen for
/// type-safety (no accidental mixing with non-stake `u64`s) and
/// compile-time clarity at API boundaries. The `u64` capacity is
/// `~1.84e19` micro-units = `~1.84e13` ADM; vastly more than the
/// `100_000_000` ADM total supply per §10, so no overflow concerns.
///
/// # Operations
///
/// `Stake` supports addition (delegations are aggregated into a
/// validator's total) and subtraction (slashing reduces the
/// total). Both operations saturate on overflow / underflow per
/// the safe-arithmetic discipline; callers requiring strict
/// overflow checks should use the `checked_*` variants.
#[derive(
    Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize,
)]
#[repr(transparent)]
pub struct Stake(pub u64);

impl Stake {
    /// Construct from a raw `u64` count of micro-units.
    #[must_use]
    pub const fn new(micro_units: u64) -> Self {
        Self(micro_units)
    }

    /// Underlying micro-unit count.
    #[must_use]
    pub const fn as_micro_units(self) -> u64 {
        self.0
    }

    /// Construct from a whole-ADM count. Saturates at `u64::MAX`
    /// micro-units if `adm` would overflow.
    #[must_use]
    pub const fn from_adm(adm: u64) -> Self {
        Self(adm.saturating_mul(1_000_000))
    }

    /// Saturating addition.
    #[must_use]
    pub const fn saturating_add(self, other: Self) -> Self {
        Self(self.0.saturating_add(other.0))
    }

    /// Saturating subtraction.
    #[must_use]
    pub const fn saturating_sub(self, other: Self) -> Self {
        Self(self.0.saturating_sub(other.0))
    }

    /// Checked addition. Returns `None` on overflow.
    #[must_use]
    pub const fn checked_add(self, other: Self) -> Option<Self> {
        match self.0.checked_add(other.0) {
            Some(v) => Some(Self(v)),
            None => None,
        }
    }

    /// Checked subtraction. Returns `None` on underflow.
    #[must_use]
    pub const fn checked_sub(self, other: Self) -> Option<Self> {
        match self.0.checked_sub(other.0) {
            Some(v) => Some(Self(v)),
            None => None,
        }
    }
}

/// Launch-period minimum validator stake per whitepaper §8.1.6
/// and §11.5.4: `1_000` ADM = `1_000_000_000` micro-units.
///
/// **Subject to pre-mainnet calibration per §11.5.4.** This value
/// may be revised before genesis based on simulation analysis of
/// the launch-period validator economics. After genesis, the
/// value is immutable per §11; revisions require a hard fork.
pub const MIN_VALIDATOR_STAKE_LAUNCH: Stake = Stake::from_adm(1_000);

/// On-chain validator record per whitepaper §8.1.2.
///
/// Created by a `register_validator` transaction (Phase 7.10);
/// updated by `delegate` / `undelegate` (§8.1.4), `transfer_slot`
/// (§8.1.8), and slashing (§8.1.5). Stored as an Adamant Object
/// (§5.1) wrapped via the deployment-transaction handler.
///
/// # Fields
///
/// - `id` — content-derived [`ValidatorId`] over `public_keys`.
///   Recomputable; redundancy with `public_keys` is intentional
///   (faster lookup at consensus-time without re-hashing).
/// - `public_keys` — the (Ed25519, ML-DSA-65, BLS12-381) public-
///   key bundle per §8.1.1.
/// - `operator` — the [`Address`] that operationally controls
///   the validator. Signs `register_validator` / `transfer_slot`
///   transactions; receives the validator's share of rewards
///   (less delegator commission per §8.1.4).
/// - `stake` — the validator's total bonded stake (operator self-
///   stake + delegated stake). Slashed on §8.1.5 offences.
/// - `registered_at_epoch` — epoch at which the validator was
///   first registered. Used by §8.1.3 first-come-first-served
///   active-set selection.
///
/// # Field declaration order is consensus-binding
///
/// BCS encodes struct fields in source-declaration order per
/// §5.1.8. Reordering any field is a hard fork. The order chosen
/// here matches the natural §8.1.2 description order: identity →
/// keys → operator → stake → registration epoch.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct Validator {
    /// Content-derived 32-byte identifier per §8.1.2 / [`ValidatorId`].
    pub id: ValidatorId,
    /// (Ed25519, ML-DSA-65, BLS12-381) public-key bundle per §8.1.1.
    pub public_keys: ValidatorPublicKeys,
    /// Address that operationally controls the validator.
    pub operator: Address,
    /// Total bonded stake (operator + delegated) in ADM micro-units.
    pub stake: Stake,
    /// Epoch at which this validator was registered.
    pub registered_at_epoch: EpochNumber,
}

impl Validator {
    /// Construct a `Validator` with the supplied operator + stake +
    /// registration epoch, deriving `id` from `public_keys` per
    /// §8.1.2.
    ///
    /// Performs the content-derivation but no other validation.
    /// Eligibility checks (`stake >= MIN_VALIDATOR_STAKE_LAUNCH`
    /// per §8.1.6, etc.) are the caller's responsibility — they
    /// happen at the deployment-transaction handler at Phase 7.10.
    #[must_use]
    pub fn new(
        public_keys: ValidatorPublicKeys,
        operator: Address,
        stake: Stake,
        registered_at_epoch: EpochNumber,
    ) -> Self {
        let id = public_keys.derive_id();
        Self {
            id,
            public_keys,
            operator,
            stake,
            registered_at_epoch,
        }
    }

    /// Whether this validator's bonded stake meets or exceeds the
    /// launch-period minimum per §8.1.6. Per-validator stake floor
    /// gating happens at the active-set admission check (Phase 7.1);
    /// this helper is for callers that want to surface the
    /// stake-eligible flag without duplicating the comparison.
    #[must_use]
    pub fn meets_launch_stake_floor(&self) -> bool {
        self.stake >= MIN_VALIDATOR_STAKE_LAUNCH
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::{
        BLS_PUBLIC_KEY_BYTES, BLS_SIGNATURE_BYTES, ED25519_PUBLIC_KEY_BYTES,
        ML_DSA_PUBLIC_KEY_BYTES,
    };

    fn fixed_validator() -> Validator {
        let keys = ValidatorPublicKeys::new(
            [0x11; ED25519_PUBLIC_KEY_BYTES],
            [0x22; ML_DSA_PUBLIC_KEY_BYTES],
            [0x33; BLS_PUBLIC_KEY_BYTES],
            [0x44; BLS_SIGNATURE_BYTES],
        );
        let operator = Address::from_bytes([0x44; 32]);
        Validator::new(keys, operator, Stake::from_adm(1_500), EpochNumber::new(0))
    }

    #[test]
    fn stake_micro_unit_arithmetic_works() {
        assert_eq!(Stake::from_adm(1).as_micro_units(), 1_000_000);
        assert_eq!(Stake::from_adm(1_000), Stake::new(1_000_000_000));
    }

    #[test]
    fn stake_saturating_arithmetic() {
        assert_eq!(
            Stake::new(u64::MAX).saturating_add(Stake::new(1)),
            Stake::new(u64::MAX)
        );
        assert_eq!(Stake::new(0).saturating_sub(Stake::new(1)), Stake::new(0));
    }

    #[test]
    fn stake_checked_arithmetic() {
        assert_eq!(Stake::new(u64::MAX).checked_add(Stake::new(1)), None);
        assert_eq!(Stake::new(0).checked_sub(Stake::new(1)), None);
        assert_eq!(
            Stake::new(100).checked_add(Stake::new(50)),
            Some(Stake::new(150))
        );
    }

    /// Pin the §8.1.6 / §11.5.4 launch-period minimum stake.
    #[test]
    fn launch_period_minimum_stake_pinned() {
        assert_eq!(
            MIN_VALIDATOR_STAKE_LAUNCH,
            Stake::from_adm(1_000),
            "launch minimum is 1,000 ADM per §8.1.6 / §11.5.4"
        );
        assert_eq!(MIN_VALIDATOR_STAKE_LAUNCH.as_micro_units(), 1_000_000_000);
    }

    #[test]
    fn validator_id_matches_derived_id() {
        let v = fixed_validator();
        assert_eq!(v.id, v.public_keys.derive_id());
    }

    #[test]
    fn validator_meets_stake_floor_pin() {
        let mut v = fixed_validator();
        // 1500 ADM > 1000 ADM minimum
        assert!(v.meets_launch_stake_floor());
        v.stake = Stake::from_adm(999);
        assert!(!v.meets_launch_stake_floor());
        v.stake = Stake::from_adm(1_000); // exactly at floor
        assert!(v.meets_launch_stake_floor());
    }

    /// Validator BCS round-trip preserves all fields.
    #[test]
    fn validator_bcs_round_trip() {
        let v = fixed_validator();
        let bytes = bcs::to_bytes(&v).unwrap();
        let decoded: Validator = bcs::from_bytes(&bytes).unwrap();
        assert_eq!(v, decoded);
    }

    /// Validator BCS encoding has the expected structure: id
    /// (32) + public_keys (2080) + operator (32) + stake (8) +
    /// registered_at_epoch (8) = 2160 bytes (no length prefixes
    /// for fixed-size members).
    #[test]
    fn validator_bcs_size_pinned() {
        let v = fixed_validator();
        let bytes = bcs::to_bytes(&v).unwrap();
        // Post Crypto C-2 PoP: ValidatorPublicKeys is 2128 bytes
        // (32 + 1952 + 96 + 48). Address is 32 bytes;
        // EpochNumber and Stake are 8 bytes each; ValidatorId is
        // 32 bytes. 32 + 2128 + 32 + 8 + 8 = 2208.
        assert_eq!(bytes.len(), 2208);
    }

    #[test]
    fn stake_bcs_round_trip() {
        let s = Stake::from_adm(42);
        let bytes = bcs::to_bytes(&s).unwrap();
        let decoded: Stake = bcs::from_bytes(&bytes).unwrap();
        assert_eq!(s, decoded);
    }
}
