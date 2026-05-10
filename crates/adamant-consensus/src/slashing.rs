//! Slashing types per whitepaper §8.1.5.
//!
//! Validators face automatic slashing of their bonded stake for
//! provable misbehaviour. The protocol slashes for four
//! categories:
//!
//! | Offence                          | Slashing penalty | Section |
//! |----------------------------------|------------------|---------|
//! | Equivocation                     | 100% of stake    | §8.1.5  |
//! | Invalid proof                    | 10% of stake     | §8.1.5  |
//! | Incorrect threshold decryption   | 5% of stake      | §8.1.5  |
//! | Liveness failure                 | 0.5% of stake    | §8.1.5  |
//!
//! Slashed stake is **burned**, not redistributed (§8.1.5).
//! Slashing is automatic and on-chain: any party can submit
//! evidence, and the protocol slashes without governance review.
//! The rules are mechanical.
//!
//! Phase 7.0 ships the offence-category enum + per-offence
//! penalty table. Phase 7.10 wires the on-chain slashing-evidence
//! handlers + actual stake reduction.

use serde::{Deserialize, Serialize};

/// Denominator for basis-point penalty values. `10_000` basis
/// points = `100%`.
///
/// Penalties are expressed in basis points to avoid floating-
/// point arithmetic in consensus paths. To compute the slashed
/// amount: `(stake * penalty_bp) / BASIS_POINTS_DENOMINATOR`.
pub const BASIS_POINTS_DENOMINATOR: u32 = 10_000;

/// Slashing offence category per whitepaper §8.1.5.
///
/// Variant tags are pinned at genesis-fixed BCS encoding values:
/// `Equivocation = 0x00`, `IncorrectThresholdDecryption = 0x01`,
/// `LivenessFailure = 0x02`, `InvalidProof = 0x03`. Reordering is
/// a hard fork.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub enum SlashOffence {
    /// Signing two distinct consensus messages for the same DAG
    /// round. The most severe offence; any party can submit
    /// evidence (the two signed messages) and the validator is
    /// slashed without further review.
    ///
    /// Slashing penalty: **100%** of stake (§8.1.5).
    Equivocation,

    /// Publishing a threshold-decryption share that does not
    /// correctly correspond to the validator's threshold key.
    /// Detected by the §8.4.3 threshold-decryption protocol's
    /// share-verification step.
    ///
    /// Slashing penalty: **5%** of stake (§8.1.5).
    IncorrectThresholdDecryption,

    /// Failing to participate in consensus for more than 2
    /// consecutive epochs while in the active set. Triggers
    /// removal from the active set in addition to the stake
    /// penalty.
    ///
    /// Slashing penalty: **0.5%** of stake plus removal from the
    /// active set (§8.1.5).
    LivenessFailure,

    /// Producing a partial recursive proof that does not verify.
    /// Detected by the §8.5 recursive-proof aggregation step.
    ///
    /// Slashing penalty: **10%** of stake (§8.1.5).
    InvalidProof,
}

impl SlashOffence {
    /// Whether this offence triggers removal from the active set
    /// in addition to the stake penalty per §8.1.5.
    #[must_use]
    pub const fn triggers_active_set_removal(self) -> bool {
        matches!(self, Self::LivenessFailure)
    }
}

/// Per-offence slashing penalty in basis points (1 bp = 0.01%).
///
/// To compute the slashed amount in stake micro-units:
/// `(stake_micro_units * penalty_bp) / BASIS_POINTS_DENOMINATOR`.
///
/// Returns the §8.1.5 verbatim values:
///
/// - [`SlashOffence::Equivocation`] → `10_000` bp = `100%`.
/// - [`SlashOffence::InvalidProof`] → `1_000` bp = `10%`.
/// - [`SlashOffence::IncorrectThresholdDecryption`] → `500` bp = `5%`.
/// - [`SlashOffence::LivenessFailure`] → `50` bp = `0.5%`.
#[must_use]
pub const fn slashing_penalty_basis_points(offence: SlashOffence) -> u32 {
    match offence {
        SlashOffence::Equivocation => 10_000,
        SlashOffence::IncorrectThresholdDecryption => 500,
        SlashOffence::LivenessFailure => 50,
        SlashOffence::InvalidProof => 1_000,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::validator::Stake;

    /// Pin the §8.1.5 penalty values verbatim.
    #[test]
    fn slashing_penalties_pinned() {
        assert_eq!(
            slashing_penalty_basis_points(SlashOffence::Equivocation),
            10_000,
            "§8.1.5 equivocation = 100% of stake"
        );
        assert_eq!(
            slashing_penalty_basis_points(SlashOffence::InvalidProof),
            1_000,
            "§8.1.5 invalid proof = 10% of stake"
        );
        assert_eq!(
            slashing_penalty_basis_points(SlashOffence::IncorrectThresholdDecryption),
            500,
            "§8.1.5 incorrect threshold decryption = 5% of stake"
        );
        assert_eq!(
            slashing_penalty_basis_points(SlashOffence::LivenessFailure),
            50,
            "§8.1.5 liveness failure = 0.5% of stake"
        );
    }

    /// Pin the basis-points denominator.
    #[test]
    fn basis_points_denominator_pinned() {
        assert_eq!(BASIS_POINTS_DENOMINATOR, 10_000);
    }

    /// Liveness failure triggers active-set removal; other
    /// offences do not.
    #[test]
    fn active_set_removal_pin() {
        assert!(SlashOffence::LivenessFailure.triggers_active_set_removal());
        assert!(!SlashOffence::Equivocation.triggers_active_set_removal());
        assert!(!SlashOffence::IncorrectThresholdDecryption.triggers_active_set_removal());
        assert!(!SlashOffence::InvalidProof.triggers_active_set_removal());
    }

    /// Worked example: equivocation on a 1,000 ADM bond burns
    /// 1,000 ADM (100%).
    #[test]
    fn equivocation_burns_full_stake() {
        let stake = Stake::from_adm(1_000);
        let penalty_bp = slashing_penalty_basis_points(SlashOffence::Equivocation);
        let slashed =
            stake.as_micro_units() * u64::from(penalty_bp) / u64::from(BASIS_POINTS_DENOMINATOR);
        assert_eq!(slashed, stake.as_micro_units());
    }

    /// Worked example: liveness failure on a 1,000 ADM bond
    /// burns 5 ADM (0.5%).
    #[test]
    fn liveness_failure_burns_half_percent() {
        let stake = Stake::from_adm(1_000);
        let penalty_bp = slashing_penalty_basis_points(SlashOffence::LivenessFailure);
        let slashed =
            stake.as_micro_units() * u64::from(penalty_bp) / u64::from(BASIS_POINTS_DENOMINATOR);
        // 1000 ADM = 1_000_000_000 micro; 0.5% = 5_000_000 micro = 5 ADM
        assert_eq!(slashed, 5_000_000);
    }

    /// BCS variant tags: pinned consensus encoding.
    #[test]
    fn bcs_variant_tags_pinned() {
        assert_eq!(
            bcs::to_bytes(&SlashOffence::Equivocation).unwrap(),
            vec![0x00]
        );
        assert_eq!(
            bcs::to_bytes(&SlashOffence::IncorrectThresholdDecryption).unwrap(),
            vec![0x01]
        );
        assert_eq!(
            bcs::to_bytes(&SlashOffence::LivenessFailure).unwrap(),
            vec![0x02]
        );
        assert_eq!(
            bcs::to_bytes(&SlashOffence::InvalidProof).unwrap(),
            vec![0x03]
        );
    }

    #[test]
    fn bcs_round_trip_all_offences() {
        for o in [
            SlashOffence::Equivocation,
            SlashOffence::IncorrectThresholdDecryption,
            SlashOffence::LivenessFailure,
            SlashOffence::InvalidProof,
        ] {
            let bytes = bcs::to_bytes(&o).unwrap();
            let decoded: SlashOffence = bcs::from_bytes(&bytes).unwrap();
            assert_eq!(o, decoded);
        }
    }
}
