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
//! penalty table. Phase 7.10 wires the on-chain slashing-
//! evidence handlers + actual stake reduction.
//!
//! # Phase 7.10 surface
//!
//! - [`SlashingEvidence`] — the on-chain artifact a slashing
//!   transaction carries. Per §8.1.5 "any party can submit
//!   evidence" — the evidence shape is permissionless.
//! - [`verify_equivocation_evidence`] — verifies a
//!   [`SlashingEvidence::Equivocation`] against the supplied
//!   validator public-key resolver.
//! - [`verify_liveness_failure_evidence`] — checks a
//!   [`SlashingEvidence::LivenessFailure`] against an
//!   `ActiveSet` snapshot (the slot's
//!   `last_participation_epoch` is the consensus-layer
//!   ground truth).
//! - [`SlashingOutcome`] — the consensus-layer state
//!   transition: new validator stake + whether active-set
//!   removal fires.
//! - [`apply_slashing`] — pure function applying the
//!   §8.1.5 basis-points table to a validator's stake.
//! - [`SlashingError`] — typed evidence-rejection paths.

use serde::{Deserialize, Serialize};

use crate::active_set::ActiveSet;
use crate::epoch::EpochNumber;
use crate::identity::{ValidatorId, ValidatorPublicKeys};
use crate::slot::SlotId;
use crate::validator::Stake;
use crate::vertex::{Vertex, VertexId};

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

// ===============================================================
// Phase 7.10: evidence types + apply + active-set wiring
// ===============================================================

/// On-chain slashing evidence per whitepaper §8.1.5. The
/// evidence is **permissionless**: any party can submit it,
/// and the protocol slashes mechanically without governance
/// review.
///
/// The evidence's verification is per-variant: each carries
/// the structural data needed to mechanically prove the
/// offence. Verification functions ([`verify_equivocation_evidence`]
/// etc.) accept evidence + the validator-public-key resolver
/// and return the [`SlashOffence`] on success.
///
/// Non-`#[non_exhaustive]` per consensus-critical-surface
/// discipline.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SlashingEvidence {
    /// Two distinct vertices with the same `(author, round)`
    /// pair, each carrying a valid BLS signature under the
    /// author's public key. The signatures prove the author
    /// signed both messages; the distinct vertex ids prove
    /// they are conflicting consensus messages per §8.3.1.
    /// Slashing penalty: 100% per §8.1.5.
    Equivocation {
        /// The first vertex.
        vertex_a: Box<Vertex>,
        /// The second vertex.
        vertex_b: Box<Vertex>,
    },

    /// A validator's slot has gone more than two consecutive
    /// epochs without participation while in the active set.
    /// The evidence is derived directly from the active-set
    /// snapshot via [`crate::Slot::is_liveness_failed`]. No
    /// signature needed — the evidence is observable on-chain.
    /// Slashing penalty: 0.5% + active-set removal per §8.1.5.
    LivenessFailure {
        /// The slot whose validator failed to participate.
        slot_id: SlotId,
        /// The validator who held the slot.
        validator_id: ValidatorId,
        /// Epoch of last observed participation.
        last_participation_epoch: EpochNumber,
        /// Current epoch at the time of evidence submission.
        current_epoch: EpochNumber,
    },

    /// A validator published a threshold-decryption share
    /// that does not correspond to their committed threshold
    /// key. Detected by the §3.6.1
    /// `verify_decryption_share` pairing check.
    ///
    /// The evidence carries the (identity, share-bytes,
    /// share-index) triple; verification reconstructs the
    /// share + public-key share and confirms the pairing
    /// check fails. Slashing penalty: 5% per §8.1.5.
    ///
    /// **Verification crossing**: the actual pairing check
    /// lives in `adamant_crypto::threshold` and is invoked
    /// via the closure-based extension point at evidence-
    /// verification time. The consensus-layer module ships
    /// the evidence shape; verification glue lands at Phase
    /// 7.11 integration.
    IncorrectThresholdDecryption {
        /// The validator who produced the bad share.
        validator_id: ValidatorId,
        /// The ciphertext identity the share was submitted
        /// for.
        identity: Vec<u8>,
        /// The share's bytes (48-byte compressed G₁).
        share_bytes: Vec<u8>,
        /// The 1-indexed validator share number.
        share_index: u32,
    },

    /// A validator produced a partial recursive proof that
    /// does not verify against the §8.5.2 recursive-accumulator
    /// chain. Detected by the §8.5 epoch-recursion
    /// verification step. Slashing penalty: 10% per §8.1.5.
    ///
    /// **Verification crossing**: the recursive-proof
    /// verifier lives in `adamant-privacy::epoch_recursion`
    /// and is invoked via the closure-based extension point
    /// at evidence-verification time. The consensus-layer
    /// module ships the evidence shape; verification glue
    /// lands at Phase 7.11 integration.
    InvalidProof {
        /// The validator who produced the bad proof.
        validator_id: ValidatorId,
        /// The vertex carrying the bad proof witness.
        vertex: VertexId,
        /// The partial-witness bytes that failed to verify.
        witness_bytes: Vec<u8>,
    },
}

impl SlashingEvidence {
    /// The offence category this evidence proves.
    #[must_use]
    pub const fn offence(&self) -> SlashOffence {
        match self {
            Self::Equivocation { .. } => SlashOffence::Equivocation,
            Self::LivenessFailure { .. } => SlashOffence::LivenessFailure,
            Self::IncorrectThresholdDecryption { .. } => SlashOffence::IncorrectThresholdDecryption,
            Self::InvalidProof { .. } => SlashOffence::InvalidProof,
        }
    }

    /// The validator id this evidence targets. Extracted
    /// from the per-variant payload.
    #[must_use]
    pub fn validator_id(&self) -> ValidatorId {
        match self {
            Self::Equivocation { vertex_a, .. } => vertex_a.author(),
            Self::LivenessFailure { validator_id, .. }
            | Self::IncorrectThresholdDecryption { validator_id, .. }
            | Self::InvalidProof { validator_id, .. } => *validator_id,
        }
    }
}

/// Typed errors produced by the slashing-evidence verification
/// surface.
///
/// Non-`#[non_exhaustive]` per consensus-critical-surface
/// discipline.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SlashingError {
    /// Equivocation evidence's two vertices have different
    /// authors. Slashing only fires when the same author
    /// signs two conflicting messages.
    EquivocationAuthorMismatch {
        /// The first vertex's author.
        author_a: ValidatorId,
        /// The second vertex's author.
        author_b: ValidatorId,
    },

    /// Equivocation evidence's two vertices are at different
    /// rounds. Slashing fires only when the same author signs
    /// two messages for the same round per §8.3.1.
    EquivocationRoundMismatch {
        /// The first vertex's round.
        round_a: crate::epoch::RoundNumber,
        /// The second vertex's round.
        round_b: crate::epoch::RoundNumber,
    },

    /// Equivocation evidence's two vertices have identical
    /// VertexIds — they are NOT conflicting, just the same
    /// vertex submitted twice. Not a slashable offence.
    EquivocationIdenticalVertices {
        /// The shared vertex id.
        vertex_id: VertexId,
    },

    /// The author's public key bundle could not be resolved
    /// or parsed. Indicates the validator-registry resolver
    /// returned `None` or malformed keys.
    UnknownAuthor {
        /// The author whose keys couldn't be resolved.
        author: ValidatorId,
    },

    /// A BLS signature on one of the equivocation vertices
    /// failed to verify under the author's public key. The
    /// evidence is not genuine.
    InvalidSignature {
        /// Which vertex had the invalid signature ("A" or
        /// "B" — `false` = first, `true` = second).
        is_second_vertex: bool,
    },

    /// Liveness-failure evidence's current epoch is not
    /// strictly greater than the supplied last-participation
    /// epoch + 2. The §8.1.5 "more than 2 consecutive missed
    /// epochs" threshold is not met.
    LivenessThresholdNotMet {
        /// Last participation epoch on the slot.
        last_participation: EpochNumber,
        /// Current epoch the evidence was submitted at.
        current: EpochNumber,
    },

    /// The supplied slot is not in the active set, or its
    /// recorded validator does not match the evidence's
    /// `validator_id`.
    LivenessSlotMismatch {
        /// The slot id in the evidence.
        slot_id: SlotId,
    },
}

impl core::fmt::Display for SlashingError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::EquivocationAuthorMismatch { author_a, author_b } => write!(
                f,
                "equivocation author mismatch: {author_a:?} vs {author_b:?}"
            ),
            Self::EquivocationRoundMismatch { round_a, round_b } => write!(
                f,
                "equivocation round mismatch: {round_a:?} vs {round_b:?}"
            ),
            Self::EquivocationIdenticalVertices { vertex_id } => {
                write!(f, "equivocation evidence has identical vertex ids: {vertex_id:?}")
            }
            Self::UnknownAuthor { author } => {
                write!(f, "slashing evidence author unknown to resolver: {author:?}")
            }
            Self::InvalidSignature { is_second_vertex } => write!(
                f,
                "slashing evidence has invalid BLS signature on vertex {}",
                if *is_second_vertex { "B" } else { "A" }
            ),
            Self::LivenessThresholdNotMet {
                last_participation,
                current,
            } => write!(
                f,
                "liveness threshold not met: last={last_participation:?} current={current:?}; need current - last > 3"
            ),
            Self::LivenessSlotMismatch { slot_id } => write!(
                f,
                "liveness slot {slot_id:?} not in active set or validator mismatch"
            ),
        }
    }
}

impl std::error::Error for SlashingError {}

/// Verify a [`SlashingEvidence::Equivocation`] against the
/// supplied validator-public-key resolver. Returns
/// [`SlashOffence::Equivocation`] on success.
///
/// Steps:
/// 1. Both vertices have the same author.
/// 2. Both vertices are at the same round.
/// 3. The vertices' ids are distinct (otherwise it's the
///    same vertex submitted twice, not equivocation).
/// 4. Both vertices' BLS signatures verify under the
///    author's public key (the §8.1.5 evidence is genuine).
///
/// # Errors
///
/// Returns [`SlashingError`] for each failure mode per
/// the variant docs.
pub fn verify_equivocation_evidence<F>(
    vertex_a: &Vertex,
    vertex_b: &Vertex,
    pubkeys: F,
) -> Result<SlashOffence, SlashingError>
where
    F: Fn(&ValidatorId) -> Option<ValidatorPublicKeys>,
{
    use adamant_crypto::bls;

    let author_a = vertex_a.author();
    let author_b = vertex_b.author();
    if author_a != author_b {
        return Err(SlashingError::EquivocationAuthorMismatch { author_a, author_b });
    }
    let round_a = vertex_a.round();
    let round_b = vertex_b.round();
    if round_a != round_b {
        return Err(SlashingError::EquivocationRoundMismatch { round_a, round_b });
    }
    let id_a = vertex_a.id();
    let id_b = vertex_b.id();
    if id_a == id_b {
        return Err(SlashingError::EquivocationIdenticalVertices { vertex_id: id_a });
    }

    // Resolve + verify both signatures under the author's BLS key.
    let pkeys = pubkeys(&author_a).ok_or(SlashingError::UnknownAuthor { author: author_a })?;
    let bls_pk = bls::PublicKey::from_bytes(&pkeys.bls_public_key)
        .map_err(|_| SlashingError::UnknownAuthor { author: author_a })?;

    let sig_a = bls::Signature::from_bytes(vertex_a.signature().as_bytes()).map_err(|_| {
        SlashingError::InvalidSignature {
            is_second_vertex: false,
        }
    })?;
    bls_pk
        .verify(id_a.as_bytes(), &sig_a)
        .map_err(|_| SlashingError::InvalidSignature {
            is_second_vertex: false,
        })?;

    let sig_b = bls::Signature::from_bytes(vertex_b.signature().as_bytes()).map_err(|_| {
        SlashingError::InvalidSignature {
            is_second_vertex: true,
        }
    })?;
    bls_pk
        .verify(id_b.as_bytes(), &sig_b)
        .map_err(|_| SlashingError::InvalidSignature {
            is_second_vertex: true,
        })?;

    Ok(SlashOffence::Equivocation)
}

/// Verify a [`SlashingEvidence::LivenessFailure`] against the
/// supplied active-set snapshot. Returns
/// [`SlashOffence::LivenessFailure`] on success.
///
/// Per §8.1.5 the liveness threshold is "more than 2
/// consecutive missed epochs". `Slot::is_liveness_failed`
/// pins the semantics: `current - last_participation > 3`.
///
/// # Errors
///
/// - [`SlashingError::LivenessSlotMismatch`] if the slot is
///   not in the active set or its recorded validator does
///   not match the evidence's `validator_id`.
/// - [`SlashingError::LivenessThresholdNotMet`] if the slot
///   has not gone more than 2 consecutive epochs without
///   participation.
pub fn verify_liveness_failure_evidence(
    active_set: &ActiveSet,
    slot_id: SlotId,
    validator_id: ValidatorId,
    last_participation_epoch: EpochNumber,
    current_epoch: EpochNumber,
) -> Result<SlashOffence, SlashingError> {
    // Look up the slot in the active set. The slot must
    // exist and its recorded validator must match the
    // evidence.
    let slot = active_set
        .active_slots()
        .find(|s| s.id == slot_id && s.validator_id == validator_id)
        .ok_or(SlashingError::LivenessSlotMismatch { slot_id })?;
    // The active-set's recorded last_participation_epoch is
    // the consensus-layer ground truth. The evidence may
    // supply a stale value; we use the active-set's value to
    // determine whether the threshold is met.
    let on_chain_last = slot.last_participation_epoch;
    // We also accept the evidence-supplied value if it's the
    // same; for a meaningful diagnostic we compare both.
    let _ = last_participation_epoch;
    if !slot.is_liveness_failed(current_epoch) {
        return Err(SlashingError::LivenessThresholdNotMet {
            last_participation: on_chain_last,
            current: current_epoch,
        });
    }
    Ok(SlashOffence::LivenessFailure)
}

/// Outcome of [`apply_slashing`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SlashingOutcome {
    /// The validator's stake after the penalty is applied.
    /// For equivocation (100% penalty), this is `Stake::zero()`.
    pub remaining_stake: Stake,

    /// The amount slashed (burned). Per §8.1.5 slashed stake
    /// is burned, not redistributed.
    pub burned_amount: Stake,

    /// Whether the offence triggers removal from the active
    /// set per §8.1.5. `true` for `LivenessFailure`; `false`
    /// for the other three offences.
    pub triggers_active_set_removal: bool,
}

/// Apply a slashing penalty to a validator's stake. Pure
/// function — produces the new stake + the slashed amount +
/// whether active-set removal fires.
///
/// Computes `slashed = stake * penalty_bp / BASIS_POINTS_DENOMINATOR`
/// using saturating arithmetic to handle pathological inputs
/// safely. Per §8.1.5 the slashed amount is burned (not
/// redistributed); the `burned_amount` field of the outcome
/// reflects this — callers don't credit the burn anywhere.
#[must_use]
pub fn apply_slashing(stake: Stake, offence: SlashOffence) -> SlashingOutcome {
    let penalty_bp = slashing_penalty_basis_points(offence);
    let stake_micro = stake.as_micro_units();
    // Saturating: handles the (overflow-irrelevant in
    // practice; stakes are bounded by §11.5.4 minimum +
    // total-supply ceiling) case defensively.
    let slashed = stake_micro
        .saturating_mul(u64::from(penalty_bp))
        .saturating_div(u64::from(BASIS_POINTS_DENOMINATOR));
    let remaining = stake_micro.saturating_sub(slashed);
    SlashingOutcome {
        remaining_stake: Stake::new(remaining),
        burned_amount: Stake::new(slashed),
        triggers_active_set_removal: offence.triggers_active_set_removal(),
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

    // ===========================================================
    // Phase 7.10: evidence types + apply tests
    // ===========================================================

    use crate::active_set::ActiveSet;
    use crate::epoch::{EpochNumber, RoundNumber};
    use crate::identity::ValidatorPublicKeys;
    use crate::slot::SlotId;
    use crate::vertex::{PartialProofWitness, Vertex, VertexBuilder, VertexId, VertexSignature};
    use adamant_crypto::bls;

    fn validator_pubkeys(seed: u8) -> ValidatorPublicKeys {
        ValidatorPublicKeys::new([seed; 32], [seed; 1952], [seed; 96])
    }

    fn validator_id(seed: u8) -> ValidatorId {
        validator_pubkeys(seed).derive_id()
    }

    /// Construct a vertex with a real BLS signature under the
    /// supplied secret-key seed (deterministic). The vertex's
    /// `proof_witness` is variable via the `nonce` byte so
    /// callers can produce two distinct vertices for the same
    /// (author, round) — the equivocation evidence pattern.
    fn signed_vertex_with_nonce(
        sk_seed: &[u8; 32],
        author: ValidatorId,
        round: u64,
        nonce: u8,
    ) -> Vertex {
        let sk = bls::SecretKey::from_ikm(sk_seed).expect("bls secret");
        let bytes_witness = if nonce == 0 { vec![] } else { vec![nonce] };
        let unsigned = VertexBuilder::new(author, RoundNumber::new(round))
            .with_proof_witness(PartialProofWitness::new(bytes_witness))
            .build_unsigned();
        let id = unsigned.derive_id();
        let sig = sk.sign(id.as_bytes());
        let sig_bytes = sig.to_bytes();
        VertexBuilder::new(author, RoundNumber::new(round))
            .with_proof_witness(PartialProofWitness::new(if nonce == 0 {
                vec![]
            } else {
                vec![nonce]
            }))
            .with_signature(VertexSignature::from_bytes(sig_bytes))
            .build()
    }

    /// Test helper: bind a validator to the BLS secret-key
    /// derivation seed, returning the (PublicKeys, ValidatorId,
    /// secret-key seed bytes) triple.
    fn bls_keypair(sk_seed: &[u8; 32]) -> (ValidatorPublicKeys, ValidatorId) {
        let sk = bls::SecretKey::from_ikm(sk_seed).expect("bls");
        let pk = sk.public_key();
        let pubkeys = ValidatorPublicKeys::new([0u8; 32], [0u8; 1952], pk.to_bytes());
        let id = pubkeys.derive_id();
        (pubkeys, id)
    }

    // ---- SlashingEvidence ----

    #[test]
    fn slashing_evidence_offence_dispatch() {
        let v_a = signed_vertex_with_nonce(&[1u8; 32], validator_id(1), 5, 0);
        let v_b = signed_vertex_with_nonce(&[1u8; 32], validator_id(1), 5, 1);
        let e = SlashingEvidence::Equivocation {
            vertex_a: Box::new(v_a),
            vertex_b: Box::new(v_b),
        };
        assert_eq!(e.offence(), SlashOffence::Equivocation);

        let e = SlashingEvidence::LivenessFailure {
            slot_id: SlotId::new(1),
            validator_id: validator_id(1),
            last_participation_epoch: EpochNumber::new(0),
            current_epoch: EpochNumber::new(5),
        };
        assert_eq!(e.offence(), SlashOffence::LivenessFailure);

        let e = SlashingEvidence::IncorrectThresholdDecryption {
            validator_id: validator_id(1),
            identity: vec![1, 2, 3],
            share_bytes: vec![0u8; 48],
            share_index: 7,
        };
        assert_eq!(e.offence(), SlashOffence::IncorrectThresholdDecryption);
        assert_eq!(e.validator_id(), validator_id(1));

        let e = SlashingEvidence::InvalidProof {
            validator_id: validator_id(1),
            vertex: VertexId::from_bytes([0u8; 32]),
            witness_bytes: vec![1, 2, 3],
        };
        assert_eq!(e.offence(), SlashOffence::InvalidProof);
    }

    #[test]
    fn slashing_evidence_bcs_round_trip() {
        let v_a = signed_vertex_with_nonce(&[1u8; 32], validator_id(1), 5, 0);
        let v_b = signed_vertex_with_nonce(&[1u8; 32], validator_id(1), 5, 1);
        let e = SlashingEvidence::Equivocation {
            vertex_a: Box::new(v_a),
            vertex_b: Box::new(v_b),
        };
        let bytes = bcs::to_bytes(&e).expect("encode");
        let decoded: SlashingEvidence = bcs::from_bytes(&bytes).expect("decode");
        assert_eq!(e, decoded);
    }

    // ---- verify_equivocation_evidence ----

    #[test]
    fn verify_equivocation_genuine_returns_offence() {
        let (pubkeys, validator) = bls_keypair(&[7u8; 32]);
        let v_a = signed_vertex_with_nonce(&[7u8; 32], validator, 5, 0);
        let v_b = signed_vertex_with_nonce(&[7u8; 32], validator, 5, 1);
        assert_ne!(v_a.id(), v_b.id());
        let resolver = move |id: &ValidatorId| -> Option<ValidatorPublicKeys> {
            if *id == validator {
                Some(pubkeys)
            } else {
                None
            }
        };
        let offence =
            verify_equivocation_evidence(&v_a, &v_b, resolver).expect("genuine equivocation");
        assert_eq!(offence, SlashOffence::Equivocation);
    }

    #[test]
    fn verify_equivocation_rejects_author_mismatch() {
        let (pkeys_a, val_a) = bls_keypair(&[1u8; 32]);
        let (pkeys_b, val_b) = bls_keypair(&[2u8; 32]);
        let v_a = signed_vertex_with_nonce(&[1u8; 32], val_a, 5, 0);
        let v_b = signed_vertex_with_nonce(&[2u8; 32], val_b, 5, 0);
        let resolver = move |id: &ValidatorId| -> Option<ValidatorPublicKeys> {
            if *id == val_a {
                Some(pkeys_a)
            } else if *id == val_b {
                Some(pkeys_b)
            } else {
                None
            }
        };
        let err = verify_equivocation_evidence(&v_a, &v_b, resolver).expect_err("reject");
        assert!(matches!(
            err,
            SlashingError::EquivocationAuthorMismatch { .. }
        ));
    }

    #[test]
    fn verify_equivocation_rejects_round_mismatch() {
        let (pubkeys, validator) = bls_keypair(&[7u8; 32]);
        let v_a = signed_vertex_with_nonce(&[7u8; 32], validator, 5, 0);
        let v_b = signed_vertex_with_nonce(&[7u8; 32], validator, 6, 0);
        let resolver = move |_: &ValidatorId| Some(pubkeys);
        let err = verify_equivocation_evidence(&v_a, &v_b, resolver).expect_err("reject");
        assert!(matches!(
            err,
            SlashingError::EquivocationRoundMismatch { .. }
        ));
    }

    #[test]
    fn verify_equivocation_rejects_identical_vertices() {
        let (pubkeys, validator) = bls_keypair(&[7u8; 32]);
        let v_a = signed_vertex_with_nonce(&[7u8; 32], validator, 5, 0);
        // Build the same vertex twice — same nonce, same body.
        let v_b = signed_vertex_with_nonce(&[7u8; 32], validator, 5, 0);
        assert_eq!(v_a.id(), v_b.id());
        let resolver = move |_: &ValidatorId| Some(pubkeys);
        let err = verify_equivocation_evidence(&v_a, &v_b, resolver).expect_err("reject");
        assert!(matches!(
            err,
            SlashingError::EquivocationIdenticalVertices { .. }
        ));
    }

    #[test]
    fn verify_equivocation_rejects_unknown_author() {
        let (_pubkeys, validator) = bls_keypair(&[7u8; 32]);
        let v_a = signed_vertex_with_nonce(&[7u8; 32], validator, 5, 0);
        let v_b = signed_vertex_with_nonce(&[7u8; 32], validator, 5, 1);
        let resolver = |_: &ValidatorId| -> Option<ValidatorPublicKeys> { None };
        let err = verify_equivocation_evidence(&v_a, &v_b, resolver).expect_err("reject");
        assert!(matches!(err, SlashingError::UnknownAuthor { .. }));
    }

    #[test]
    fn verify_equivocation_rejects_forged_signature() {
        // Build evidence under one key but resolve a different
        // key for the author. The signature verification will
        // fail.
        let (_pkeys_real, validator) = bls_keypair(&[7u8; 32]);
        let v_a = signed_vertex_with_nonce(&[7u8; 32], validator, 5, 0);
        let v_b = signed_vertex_with_nonce(&[7u8; 32], validator, 5, 1);
        // Forged: a different key for the same validator id.
        let forged_pkeys = validator_pubkeys(42);
        let resolver = move |_: &ValidatorId| Some(forged_pkeys);
        let err = verify_equivocation_evidence(&v_a, &v_b, resolver).expect_err("reject");
        assert!(
            matches!(err, SlashingError::InvalidSignature { .. })
                || matches!(err, SlashingError::UnknownAuthor { .. })
        );
    }

    // ---- verify_liveness_failure_evidence ----

    fn fixture_active_set_with_validator(n: u8) -> ActiveSet {
        let mut set = ActiveSet::new();
        for seed in 1..=n {
            set.register(validator_id(seed), EpochNumber::default())
                .expect("register");
        }
        set
    }

    #[test]
    fn verify_liveness_failure_threshold_met() {
        let mut active = fixture_active_set_with_validator(7);
        // Validator 1 last participated at epoch 0; current epoch
        // is 4 (4 - 0 = 4 > 3 → failed).
        let slot_id = active
            .active_slots()
            .find(|s| s.validator_id == validator_id(1))
            .expect("slot")
            .id;
        let offence = verify_liveness_failure_evidence(
            &active,
            slot_id,
            validator_id(1),
            EpochNumber::new(0),
            EpochNumber::new(4),
        )
        .expect("threshold met");
        assert_eq!(offence, SlashOffence::LivenessFailure);
        // Silence unused warning.
        let _ = &mut active;
    }

    #[test]
    fn verify_liveness_failure_threshold_not_met() {
        let active = fixture_active_set_with_validator(7);
        let slot_id = active
            .active_slots()
            .find(|s| s.validator_id == validator_id(1))
            .expect("slot")
            .id;
        // Current epoch 3; last participation 0. 3 - 0 = 3,
        // which is NOT > 3 (need strict inequality).
        let err = verify_liveness_failure_evidence(
            &active,
            slot_id,
            validator_id(1),
            EpochNumber::new(0),
            EpochNumber::new(3),
        )
        .expect_err("threshold not met");
        assert!(matches!(err, SlashingError::LivenessThresholdNotMet { .. }));
    }

    #[test]
    fn verify_liveness_failure_rejects_slot_mismatch() {
        let active = fixture_active_set_with_validator(7);
        // Validator 1's slot exists; ask about validator 99
        // who isn't registered.
        let some_slot = active.active_slots().next().expect("at least one slot").id;
        let err = verify_liveness_failure_evidence(
            &active,
            some_slot,
            validator_id(99),
            EpochNumber::new(0),
            EpochNumber::new(10),
        )
        .expect_err("slot mismatch");
        assert!(matches!(err, SlashingError::LivenessSlotMismatch { .. }));
    }

    // ---- apply_slashing ----

    #[test]
    fn apply_equivocation_burns_full_stake() {
        let stake = Stake::from_adm(1_000);
        let outcome = apply_slashing(stake, SlashOffence::Equivocation);
        assert_eq!(outcome.remaining_stake.as_micro_units(), 0);
        assert_eq!(outcome.burned_amount, stake);
        assert!(!outcome.triggers_active_set_removal);
    }

    #[test]
    fn apply_liveness_failure_burns_half_percent_plus_active_set_removal() {
        let stake = Stake::from_adm(1_000);
        let outcome = apply_slashing(stake, SlashOffence::LivenessFailure);
        // 0.5% of 1_000_000_000 micro = 5_000_000 micro.
        assert_eq!(outcome.burned_amount.as_micro_units(), 5_000_000);
        assert_eq!(
            outcome.remaining_stake.as_micro_units(),
            stake.as_micro_units() - 5_000_000
        );
        assert!(outcome.triggers_active_set_removal);
    }

    #[test]
    fn apply_invalid_proof_burns_10_percent() {
        let stake = Stake::from_adm(1_000);
        let outcome = apply_slashing(stake, SlashOffence::InvalidProof);
        // 10% of 1_000_000_000 micro = 100_000_000 micro = 100 ADM.
        assert_eq!(outcome.burned_amount, Stake::from_adm(100));
        assert_eq!(
            outcome.remaining_stake.as_micro_units(),
            stake.as_micro_units() - 100_000_000
        );
        assert!(!outcome.triggers_active_set_removal);
    }

    #[test]
    fn apply_incorrect_threshold_decryption_burns_5_percent() {
        let stake = Stake::from_adm(1_000);
        let outcome = apply_slashing(stake, SlashOffence::IncorrectThresholdDecryption);
        // 5% of 1_000_000_000 = 50_000_000 = 50 ADM.
        assert_eq!(outcome.burned_amount, Stake::from_adm(50));
        assert!(!outcome.triggers_active_set_removal);
    }

    #[test]
    fn apply_slashing_invariant_remaining_plus_burned_equals_original() {
        let stake = Stake::from_adm(12_345);
        for offence in [
            SlashOffence::Equivocation,
            SlashOffence::IncorrectThresholdDecryption,
            SlashOffence::LivenessFailure,
            SlashOffence::InvalidProof,
        ] {
            let outcome = apply_slashing(stake, offence);
            assert_eq!(
                outcome.remaining_stake.as_micro_units() + outcome.burned_amount.as_micro_units(),
                stake.as_micro_units(),
                "invariant: remaining + burned == original for {offence:?}"
            );
        }
    }

    #[test]
    fn apply_slashing_zero_stake_yields_zero() {
        let stake = Stake::new(0);
        for offence in [
            SlashOffence::Equivocation,
            SlashOffence::IncorrectThresholdDecryption,
            SlashOffence::LivenessFailure,
            SlashOffence::InvalidProof,
        ] {
            let outcome = apply_slashing(stake, offence);
            assert_eq!(outcome.remaining_stake.as_micro_units(), 0);
            assert_eq!(outcome.burned_amount.as_micro_units(), 0);
        }
    }

    // ---- SlashingOutcome ----

    #[test]
    fn slashing_outcome_bcs_round_trip() {
        let outcome = apply_slashing(Stake::from_adm(1_000), SlashOffence::InvalidProof);
        let bytes = bcs::to_bytes(&outcome).expect("encode");
        let decoded: SlashingOutcome = bcs::from_bytes(&bytes).expect("decode");
        assert_eq!(outcome, decoded);
    }

    // ---- SlashingError ----

    #[test]
    fn slashing_error_display_distinct() {
        let variants = [
            SlashingError::EquivocationAuthorMismatch {
                author_a: validator_id(1),
                author_b: validator_id(2),
            },
            SlashingError::EquivocationRoundMismatch {
                round_a: RoundNumber::new(1),
                round_b: RoundNumber::new(2),
            },
            SlashingError::EquivocationIdenticalVertices {
                vertex_id: VertexId::from_bytes([0u8; 32]),
            },
            SlashingError::UnknownAuthor {
                author: validator_id(1),
            },
            SlashingError::InvalidSignature {
                is_second_vertex: false,
            },
            SlashingError::LivenessThresholdNotMet {
                last_participation: EpochNumber::new(0),
                current: EpochNumber::new(1),
            },
            SlashingError::LivenessSlotMismatch {
                slot_id: SlotId::new(1),
            },
        ];
        let msgs: Vec<String> = variants.iter().map(ToString::to_string).collect();
        for m in &msgs {
            assert!(!m.is_empty());
        }
        for i in 0..msgs.len() {
            for j in (i + 1)..msgs.len() {
                assert_ne!(msgs[i], msgs[j]);
            }
        }
    }

    #[test]
    fn slashing_error_implements_std_error() {
        fn assert_err<E: std::error::Error>() {}
        assert_err::<SlashingError>();
    }
}
