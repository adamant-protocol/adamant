//! Light-client observation layer per whitepaper §8.1.7 + §8.9.
//!
//! Phase 7.9 deliverable — the consensus-side surface a light
//! client consumes to track chain state without holding the full
//! state itself. Wraps the existing [`SecurityTier`] +
//! [`EpochNumber`] types into observation-oriented APIs that
//! wallets and explorers consume directly.
//!
//! [`SecurityTier`]: crate::SecurityTier
//! [`EpochNumber`]: crate::EpochNumber
//!
//! # Spec basis
//!
//! §8.1.7 ("Security tier disclosure"): "The chain commits a
//! verifiable on-chain property indicating the current
//! active-set size and the resulting security tier. … The tier
//! is computed deterministically from the active-set size
//! committed each epoch and is **queryable as a constant-time
//! chain-state property accessible to light clients**."
//!
//! §8.9 ("Light clients and verification"): "Anyone may run a
//! **light client** that follows the chain without storing full
//! state. Light clients receive the recursive proof at each
//! epoch boundary and verify it; this is sufficient to know the
//! current state commitment without trusting any validator."
//!
//! # Phase 7.9 scope
//!
//! Phase 7.9 ships the **observation layer** — the data shapes
//! light clients consume at each epoch boundary plus the
//! running-state machinery wallets and explorers maintain.
//! Specifically:
//!
//! - [`EpochBoundary`] — the artifact the consensus layer
//!   emits at each epoch boundary. Carries the epoch number,
//!   the active-set size, the state commitment, and an opaque
//!   recursive-proof envelope payload.
//! - [`TierSignal`] — the §8.1.7 tier disclosure wrapped with
//!   the epoch + active-set-size metadata. What
//!   [`ActiveSet::tier`] returns is the raw [`SecurityTier`];
//!   `TierSignal` adds the observation context wallets need to
//!   display halt warnings and gate features by minimum tier.
//! - [`LightClientState`] — the running state machine. Accepts
//!   a sequence of [`EpochBoundary`] artifacts, tracks the
//!   latest one, exposes the current tier signal + state
//!   commitment.
//! - [`LightClientError`] — typed errors for monotonicity
//!   violations and other state-machine misuse.
//!
//! # What Phase 7.9 does NOT ship (deferred to Phase 7.11)
//!
//! - **Recursive-proof verification** of the [`EpochBoundary`]'s
//!   `proof_envelope` against the previous boundary's
//!   accumulator. The verification primitive
//!   ([`adamant_privacy::epoch_recursion::verify_envelope`])
//!   lives in `adamant-privacy`; wiring it through requires
//!   coupling `adamant-consensus` to the privacy crate, which
//!   crosses the §14 layering. Phase 7.11 end-to-end
//!   integration is the venue for that wiring.
//! - **Claim verification** (account balance, transaction
//!   inclusion, object existence per §8.9). These verify via
//!   Merkle paths into the state commitment; the state-
//!   commitment Merkle tree itself is a §5 / Phase 4 concern
//!   (the GNCT is for shielded notes only; transparent-state
//!   commitment is pending Phase 4 backfill).
//!
//! Phase 7.9 ships the **consumption-side data shapes** so
//! that downstream wallets + explorers + service nodes can
//! consume the API surface now and the verification wiring
//! lands later without API churn.
//!
//! # Determinism
//!
//! Every method is deterministic in its inputs. Two light
//! clients receiving the same sequence of [`EpochBoundary`]
//! artifacts produce identical [`LightClientState`]s. This is
//! essential for the §8.7 + §8.9 convergence property.

use serde::{Deserialize, Serialize};

use crate::active_set::ActiveSet;
use crate::epoch::EpochNumber;
use crate::tier::SecurityTier;

/// Length of the 32-byte state commitment that the recursive
/// proof attests to at each epoch boundary per §8.5.1.
///
/// This is the canonical "chain state commitment" — a SHA3-256-
/// scale hash committing to every account + object + tier
/// signal at the end of the epoch. Light clients store this
/// commitment + the recursive proof; that combination is
/// sufficient to know the chain's current state without
/// trusting any validator.
pub const STATE_COMMITMENT_BYTES: usize = 32;

/// Length of the 32-byte recursive-proof commitment per §8.6
/// VRF input: "For active set selection at epoch boundaries:
/// the previous epoch's recursive proof commitment."
///
/// The proof envelope itself (per Phase 6.9b
/// `EpochAccumulator`) is a class-group element; the
/// commitment is a 32-byte hash of the envelope used as VRF
/// input + as the canonical light-client identifier for "I am
/// at epoch N's boundary state".
pub const PROOF_COMMITMENT_BYTES: usize = 32;

/// 32-byte chain-state commitment per §8.5.1.
///
/// Opaque newtype around a 32-byte hash. The concrete
/// derivation (state-tree-Merkle-root vs full SHA3 of
/// canonicalized state vs Halo-2-recursive accumulator over
/// account-tree updates) is pinned at Phase 4 backfill + Phase
/// 6.9b's recursive proof envelope; Phase 7.9 treats it as
/// opaque bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct StateCommitment([u8; STATE_COMMITMENT_BYTES]);

impl StateCommitment {
    /// Construct from raw bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; STATE_COMMITMENT_BYTES]) -> Self {
        Self(bytes)
    }

    /// The raw 32-byte commitment.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; STATE_COMMITMENT_BYTES] {
        &self.0
    }

    /// Consume into raw bytes.
    #[must_use]
    pub const fn into_bytes(self) -> [u8; STATE_COMMITMENT_BYTES] {
        self.0
    }
}

/// 32-byte recursive-proof commitment per §8.6.
///
/// This is the hash of the per-epoch recursive proof envelope
/// (Phase 6.9b `EpochAccumulator`'s canonical 32-byte
/// fingerprint). Light clients track the commitment rather
/// than the full envelope for storage efficiency; Phase 7.11
/// integration wires through full-envelope verification.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct ProofCommitment([u8; PROOF_COMMITMENT_BYTES]);

impl ProofCommitment {
    /// Construct from raw bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; PROOF_COMMITMENT_BYTES]) -> Self {
        Self(bytes)
    }

    /// The raw 32-byte commitment.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; PROOF_COMMITMENT_BYTES] {
        &self.0
    }

    /// Consume into raw bytes.
    #[must_use]
    pub const fn into_bytes(self) -> [u8; PROOF_COMMITMENT_BYTES] {
        self.0
    }
}

/// The §8.1.7 security tier signal with observation context.
///
/// What [`ActiveSet::tier`] returns is the raw [`SecurityTier`]
/// (an enum). `TierSignal` adds the **active-set size** and
/// **epoch** at which the tier was computed — wallets need
/// both pieces of context to display halt-state warnings and
/// gate features by minimum tier per §8.1.7's "Use" section.
///
/// `tier` is `Option<SecurityTier>`: `None` means the chain is
/// **dormant** (active set below the §8.1.6 constitutional
/// floor `ACTIVE_SET_FLOOR = 7`), which is honestly distinct
/// from "Tier I (low)" — the chain is paused, not just
/// weakly-secure. Per §8.7.1, wallets `SHOULD` display a
/// halt-state warning when this returns `None`.
///
/// # Honest framing
///
/// Per §8.1.7 footnote: "The chain is honest about being weak
/// when it is weak. This is a feature of credibly neutral
/// launch, not a workaround." `TierSignal::Dormant` (the
/// `None` case) goes one step further: the chain is honest
/// about being **paused**, not pretending to operate at
/// weak-but-non-zero security.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct TierSignal {
    /// The §8.1.7 tier, or `None` if the chain is dormant.
    pub tier: Option<SecurityTier>,
    /// Active-set size at the epoch the signal was observed.
    /// Encoded as `u32` for cross-platform wire portability —
    /// BCS encodes `usize` differently on 32-bit vs 64-bit
    /// targets, which would split the consensus-observable
    /// byte layout. `u32` is more than sufficient for the
    /// §8.1.3 ceiling (75) and gives ~4 billion headroom for
    /// any future ceiling expansion. Pre-Phase-10 audit closure.
    pub active_set_size: u32,
    /// Epoch at which the signal was observed.
    pub epoch: EpochNumber,
}

impl TierSignal {
    /// Construct from raw fields.
    #[must_use]
    pub const fn new(tier: Option<SecurityTier>, active_set_size: u32, epoch: EpochNumber) -> Self {
        Self {
            tier,
            active_set_size,
            epoch,
        }
    }

    /// Derive a tier signal from an [`ActiveSet`] + epoch.
    /// Convenience constructor — wraps
    /// [`SecurityTier::from_active_set_size`] with the
    /// observation context.
    ///
    /// # Panics
    ///
    /// Cannot panic in practice. The internal `expect` is a
    /// contract assertion: `ActiveSet::active_size()` is bounded
    /// by `ACTIVE_SET_LAUNCH_CEILING` (75) per §8.1.3, so the
    /// `usize → u32` conversion is structurally non-truncating.
    /// A panic here would indicate a defect in
    /// [`ActiveSet::register`]'s ceiling enforcement, not a
    /// runtime failure mode.
    #[must_use]
    pub fn from_active_set(active_set: &ActiveSet, epoch: EpochNumber) -> Self {
        let n_usize = active_set.active_size();
        // ActiveSet is bounded by ACTIVE_SET_LAUNCH_CEILING (75)
        // per §8.1.3; the cast is provably non-truncating.
        let n: u32 = u32::try_from(n_usize).expect(
            "Adamant invariant: ActiveSet size is bounded by ACTIVE_SET_LAUNCH_CEILING per §8.1.3",
        );
        Self {
            tier: SecurityTier::from_active_set_size(n_usize),
            active_set_size: n,
            epoch,
        }
    }

    /// `true` iff the chain is dormant (active set below the
    /// §8.1.6 floor). Wallets `SHOULD` display a halt-state
    /// warning when this returns `true`.
    #[must_use]
    pub const fn is_dormant(&self) -> bool {
        self.tier.is_none()
    }

    /// `true` iff the chain meets the supplied minimum tier
    /// threshold. Convenience helper for the §8.1.7 "Use"
    /// pattern: applications can choose to gate features by
    /// minimum tier (a high-value DeFi contract may refuse to
    /// execute below Tier II, for example).
    ///
    /// Returns `false` if the chain is dormant.
    #[must_use]
    pub fn meets_minimum(&self, required: SecurityTier) -> bool {
        match self.tier {
            Some(t) => t.meets_minimum(required),
            None => false,
        }
    }
}

/// The per-epoch-boundary artifact a light client consumes.
///
/// Emitted by the consensus layer at each epoch boundary per
/// §8.9: light clients receive this artifact, verify the
/// recursive proof, and update their tracked state commitment.
///
/// # Wire-stability posture
///
/// `EpochBoundary` is BCS-serialisable. Field order is
/// observation-stable but **not consensus-binding** — the
/// underlying recursive proof + state commitment are the
/// consensus-binding artifacts; this wrapper is the wire shape
/// the §9 networking layer uses to ship them to light clients.
/// Reordering fields is a non-hard-fork operational change
/// (the recursive proof verification works against the
/// envelope bytes, not the wrapper shape).
#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct EpochBoundary {
    /// The epoch this boundary closes.
    pub epoch: EpochNumber,

    /// Active-set size at the end of `epoch`. Drives the
    /// §8.1.7 tier signal for the *next* epoch (tier
    /// transitions are automatic per §8.1.7: "as N crosses a
    /// tier boundary, the next epoch's tier signal updates").
    ///
    /// Encoded as `u32` for cross-platform wire portability —
    /// BCS encodes `usize` differently on 32-bit vs 64-bit
    /// targets, which would split the consensus-observable
    /// byte layout. `u32` is more than sufficient for the
    /// §8.1.3 ceiling (75) and gives ~4 billion headroom for
    /// any future ceiling expansion. Pre-Phase-10 audit closure.
    pub active_set_size: u32,

    /// 32-byte chain-state commitment per §8.5.1. Light
    /// clients store this commitment + the recursive proof;
    /// that combination is sufficient to verify state without
    /// trusting any validator.
    pub state_commitment: StateCommitment,

    /// 32-byte recursive-proof commitment per §8.6. Used as
    /// VRF input for the next epoch's anchor election and as
    /// the canonical "I observed epoch N's state" fingerprint
    /// in the light-client API.
    pub proof_commitment: ProofCommitment,
}

impl EpochBoundary {
    /// Construct from raw fields.
    #[must_use]
    pub const fn new(
        epoch: EpochNumber,
        active_set_size: u32,
        state_commitment: StateCommitment,
        proof_commitment: ProofCommitment,
    ) -> Self {
        Self {
            epoch,
            active_set_size,
            state_commitment,
            proof_commitment,
        }
    }

    /// Derive the tier signal that this boundary's
    /// `active_set_size` produces. The signal observes against
    /// the boundary's own epoch (the closing epoch); per §8.1.7
    /// the tier transition takes effect at the *next* epoch
    /// boundary.
    #[must_use]
    pub fn tier_signal(&self) -> TierSignal {
        TierSignal {
            tier: SecurityTier::from_active_set_size(self.active_set_size as usize),
            active_set_size: self.active_set_size,
            epoch: self.epoch,
        }
    }
}

/// Typed errors produced by [`LightClientState::advance`].
///
/// Non-`#[non_exhaustive]` per consensus-critical-surface
/// discipline (mirrors the workspace-wide closed-enum posture
/// from `adamant-consensus`'s `DagError`, `SequencerError`,
/// `MempoolDecryptionError`).
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum LightClientError {
    /// The supplied boundary's epoch is not strictly greater
    /// than the latest observed epoch. Light clients advance
    /// **forwards only**; epoch reordering is a state-machine
    /// misuse error.
    NonMonotonicEpoch {
        /// The latest epoch the light client has observed.
        latest: EpochNumber,
        /// The supplied (rejected) epoch.
        supplied: EpochNumber,
    },

    /// The supplied boundary skipped one or more epochs
    /// without the light client having observed them. Per §8.9
    /// the light client receives the recursive proof at EACH
    /// epoch boundary — gaps in the boundary sequence are a
    /// trust failure (the gap-boundary's recursive proof
    /// cannot be verified without the intermediate proofs).
    EpochGap {
        /// The latest epoch the light client has observed.
        latest: EpochNumber,
        /// The supplied epoch (must be `latest + 1`).
        supplied: EpochNumber,
    },
}

impl core::fmt::Display for LightClientError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NonMonotonicEpoch { latest, supplied } => write!(
                f,
                "non-monotonic epoch advance: latest={latest:?} supplied={supplied:?}"
            ),
            Self::EpochGap { latest, supplied } => write!(
                f,
                "epoch gap: latest={latest:?} supplied={supplied:?}; expected {latest:?}+1"
            ),
        }
    }
}

impl std::error::Error for LightClientError {}

/// Light-client running state per §8.9.
///
/// Tracks the latest observed [`EpochBoundary`]; exposes the
/// derived [`TierSignal`] + state/proof commitments for
/// downstream consumers (wallets, explorers).
///
/// # Genesis posture
///
/// A new light client starts with **no observed boundary**
/// (constructed via [`Self::new`]). The first
/// [`Self::advance`] call accepts any epoch as the genesis
/// observation; subsequent advances must be strictly monotonic
/// with no gaps.
///
/// Operators MAY also construct a light client from a
/// **published genesis boundary** via [`Self::from_genesis`]
/// — useful when bootstrapping from a known good checkpoint
/// (e.g., a wallet syncing from epoch 100 rather than
/// epoch 0). The genesis boundary is trusted-by-construction;
/// recursive-proof verification of subsequent boundaries
/// chains back to it.
///
/// # Determinism
///
/// Pure state machine. Two light clients receiving the same
/// sequence of [`EpochBoundary`] artifacts produce identical
/// state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LightClientState {
    latest: Option<EpochBoundary>,
}

impl LightClientState {
    /// New light client with no observed boundary.
    #[must_use]
    pub const fn new() -> Self {
        Self { latest: None }
    }

    /// New light client initialised from a published
    /// (trusted-by-construction) genesis boundary. Subsequent
    /// [`Self::advance`] calls must be monotonic against this
    /// genesis.
    #[must_use]
    pub const fn from_genesis(genesis: EpochBoundary) -> Self {
        Self {
            latest: Some(genesis),
        }
    }

    /// The latest observed boundary, or `None` if no boundary
    /// has been observed yet.
    #[must_use]
    pub const fn latest(&self) -> Option<&EpochBoundary> {
        self.latest.as_ref()
    }

    /// The latest observed tier signal, or `None` if no
    /// boundary has been observed yet.
    #[must_use]
    pub fn tier_signal(&self) -> Option<TierSignal> {
        self.latest.as_ref().map(EpochBoundary::tier_signal)
    }

    /// The latest observed state commitment, or `None` if no
    /// boundary has been observed yet.
    #[must_use]
    pub fn state_commitment(&self) -> Option<&StateCommitment> {
        self.latest.as_ref().map(|b| &b.state_commitment)
    }

    /// The latest observed proof commitment, or `None` if no
    /// boundary has been observed yet.
    #[must_use]
    pub fn proof_commitment(&self) -> Option<&ProofCommitment> {
        self.latest.as_ref().map(|b| &b.proof_commitment)
    }

    /// Advance the light client by one epoch boundary.
    ///
    /// Per §8.9 the light client observes EVERY epoch boundary
    /// — gaps are rejected with [`LightClientError::EpochGap`].
    /// Out-of-order observations are rejected with
    /// [`LightClientError::NonMonotonicEpoch`].
    ///
    /// On success the boundary becomes the new latest;
    /// downstream `tier_signal()` / `state_commitment()` /
    /// `proof_commitment()` reflect it.
    ///
    /// # Recursive-proof verification
    ///
    /// Phase 7.9 does NOT verify the recursive proof against
    /// the previous boundary's accumulator — that crosses
    /// into `adamant-privacy::epoch_recursion` and lands at
    /// Phase 7.11 integration. Phase 7.9 ships the state-
    /// machine framing; the verification call is bolted on
    /// later without API churn.
    ///
    /// # Errors
    ///
    /// - [`LightClientError::NonMonotonicEpoch`] when
    ///   `boundary.epoch <= latest.epoch`.
    /// - [`LightClientError::EpochGap`] when
    ///   `boundary.epoch > latest.epoch + 1`.
    pub fn advance(&mut self, boundary: EpochBoundary) -> Result<(), LightClientError> {
        if let Some(latest) = &self.latest {
            let latest_n = latest.epoch.as_u64();
            let supplied_n = boundary.epoch.as_u64();
            if supplied_n <= latest_n {
                return Err(LightClientError::NonMonotonicEpoch {
                    latest: latest.epoch,
                    supplied: boundary.epoch,
                });
            }
            if supplied_n != latest_n.saturating_add(1) {
                return Err(LightClientError::EpochGap {
                    latest: latest.epoch,
                    supplied: boundary.epoch,
                });
            }
        }
        self.latest = Some(boundary);
        Ok(())
    }
}

impl Default for LightClientState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::active_set::{ActiveSet, ACTIVE_SET_FLOOR};
    use crate::identity::{ValidatorId, ValidatorPublicKeys};

    fn validator_id(seed: u8) -> ValidatorId {
        ValidatorPublicKeys::new([seed; 32], [seed; 1952], [seed; 96]).derive_id()
    }

    fn fixture_active_set(n: u8) -> ActiveSet {
        let mut set = ActiveSet::new();
        for seed in 1..=n {
            set.register(validator_id(seed), EpochNumber::default())
                .expect("register");
        }
        set
    }

    fn fixture_boundary(epoch_n: u64, active_size: u32) -> EpochBoundary {
        EpochBoundary::new(
            EpochNumber::new(epoch_n),
            active_size,
            StateCommitment::from_bytes([0xAAu8; STATE_COMMITMENT_BYTES]),
            ProofCommitment::from_bytes([0xBBu8; PROOF_COMMITMENT_BYTES]),
        )
    }

    // ---- Constants ----

    #[test]
    fn commitment_byte_widths_pinned() {
        assert_eq!(STATE_COMMITMENT_BYTES, 32);
        assert_eq!(PROOF_COMMITMENT_BYTES, 32);
    }

    // ---- StateCommitment + ProofCommitment ----

    #[test]
    fn state_commitment_round_trip() {
        let bytes = [0x42u8; STATE_COMMITMENT_BYTES];
        let c = StateCommitment::from_bytes(bytes);
        assert_eq!(c.as_bytes(), &bytes);
        assert_eq!(c.into_bytes(), bytes);
    }

    #[test]
    fn proof_commitment_round_trip() {
        let bytes = [0x55u8; PROOF_COMMITMENT_BYTES];
        let c = ProofCommitment::from_bytes(bytes);
        assert_eq!(c.as_bytes(), &bytes);
        assert_eq!(c.into_bytes(), bytes);
    }

    #[test]
    fn state_commitment_bcs_round_trip() {
        let c = StateCommitment::from_bytes([0x42u8; STATE_COMMITMENT_BYTES]);
        let bytes = bcs::to_bytes(&c).expect("encode");
        let decoded: StateCommitment = bcs::from_bytes(&bytes).expect("decode");
        assert_eq!(c, decoded);
    }

    #[test]
    fn proof_commitment_bcs_round_trip() {
        let c = ProofCommitment::from_bytes([0x55u8; PROOF_COMMITMENT_BYTES]);
        let bytes = bcs::to_bytes(&c).expect("encode");
        let decoded: ProofCommitment = bcs::from_bytes(&bytes).expect("decode");
        assert_eq!(c, decoded);
    }

    // ---- TierSignal ----

    #[test]
    fn tier_signal_dormant_below_floor() {
        // Need an active set < ACTIVE_SET_FLOOR for None tier.
        let active =
            fixture_active_set(u8::try_from(ACTIVE_SET_FLOOR - 1).expect("floor-1 fits in u8"));
        let signal = TierSignal::from_active_set(&active, EpochNumber::new(0));
        assert!(signal.is_dormant());
        assert!(signal.tier.is_none());
        assert_eq!(
            signal.active_set_size,
            u32::try_from(ACTIVE_SET_FLOOR - 1).expect("floor-1 fits in u32")
        );
    }

    #[test]
    fn tier_signal_tier_i_at_floor() {
        let active = fixture_active_set(7);
        let signal = TierSignal::from_active_set(&active, EpochNumber::new(5));
        assert!(!signal.is_dormant());
        assert_eq!(signal.tier, Some(SecurityTier::Tier1));
        assert_eq!(signal.active_set_size, 7);
        assert_eq!(signal.epoch, EpochNumber::new(5));
    }

    #[test]
    fn tier_signal_tier_ii_at_15() {
        let active = fixture_active_set(15);
        let signal = TierSignal::from_active_set(&active, EpochNumber::new(0));
        assert_eq!(signal.tier, Some(SecurityTier::Tier2));
    }

    #[test]
    fn tier_signal_tier_iii_at_30() {
        let active = fixture_active_set(30);
        let signal = TierSignal::from_active_set(&active, EpochNumber::new(0));
        assert_eq!(signal.tier, Some(SecurityTier::Tier3));
    }

    #[test]
    fn tier_signal_meets_minimum_correctly() {
        let tier_ii = TierSignal::new(Some(SecurityTier::Tier2), 20, EpochNumber::new(0));
        assert!(tier_ii.meets_minimum(SecurityTier::Tier1));
        assert!(tier_ii.meets_minimum(SecurityTier::Tier2));
        assert!(!tier_ii.meets_minimum(SecurityTier::Tier3));
    }

    #[test]
    fn dormant_signal_meets_no_minimum() {
        let dormant = TierSignal::new(None, 5, EpochNumber::new(0));
        assert!(!dormant.meets_minimum(SecurityTier::Tier1));
        assert!(!dormant.meets_minimum(SecurityTier::Tier2));
        assert!(!dormant.meets_minimum(SecurityTier::Tier3));
    }

    #[test]
    fn tier_signal_bcs_round_trip() {
        let signal = TierSignal::new(Some(SecurityTier::Tier2), 20, EpochNumber::new(42));
        let bytes = bcs::to_bytes(&signal).expect("encode");
        let decoded: TierSignal = bcs::from_bytes(&bytes).expect("decode");
        assert_eq!(signal, decoded);
    }

    // ---- EpochBoundary ----

    #[test]
    fn epoch_boundary_new_sets_all_fields() {
        let boundary = fixture_boundary(5, 20);
        assert_eq!(boundary.epoch, EpochNumber::new(5));
        assert_eq!(boundary.active_set_size, 20);
    }

    #[test]
    fn epoch_boundary_tier_signal_matches_active_set_size() {
        let boundary = fixture_boundary(10, 15);
        let signal = boundary.tier_signal();
        assert_eq!(signal.tier, Some(SecurityTier::Tier2));
        assert_eq!(signal.epoch, EpochNumber::new(10));
        assert_eq!(signal.active_set_size, 15);
    }

    #[test]
    fn epoch_boundary_bcs_round_trip() {
        let boundary = fixture_boundary(100, 50);
        let bytes = bcs::to_bytes(&boundary).expect("encode");
        let decoded: EpochBoundary = bcs::from_bytes(&bytes).expect("decode");
        assert_eq!(boundary, decoded);
    }

    // ---- LightClientState ----

    #[test]
    fn new_light_client_is_empty() {
        let lc = LightClientState::new();
        assert!(lc.latest().is_none());
        assert!(lc.tier_signal().is_none());
        assert!(lc.state_commitment().is_none());
        assert!(lc.proof_commitment().is_none());
    }

    #[test]
    fn default_light_client_is_empty() {
        let lc = LightClientState::default();
        assert!(lc.latest().is_none());
    }

    #[test]
    fn from_genesis_initialises_state() {
        let genesis = fixture_boundary(0, 30);
        let lc = LightClientState::from_genesis(genesis.clone());
        assert_eq!(lc.latest(), Some(&genesis));
        assert!(lc.tier_signal().is_some());
        assert!(lc.state_commitment().is_some());
        assert!(lc.proof_commitment().is_some());
    }

    #[test]
    fn advance_from_empty_accepts_any_epoch() {
        let mut lc = LightClientState::new();
        // Even non-zero genesis epoch is accepted for a fresh
        // light client (the wallet may bootstrap from a known
        // good checkpoint).
        lc.advance(fixture_boundary(50, 20)).expect("ok");
        assert_eq!(lc.latest().expect("present").epoch, EpochNumber::new(50));
    }

    #[test]
    fn advance_monotonically_succeeds() {
        let mut lc = LightClientState::from_genesis(fixture_boundary(0, 30));
        for epoch in 1..=5 {
            lc.advance(fixture_boundary(epoch, 30)).expect("advance");
        }
        assert_eq!(lc.latest().expect("present").epoch, EpochNumber::new(5));
    }

    #[test]
    fn advance_with_gap_errors() {
        let mut lc = LightClientState::from_genesis(fixture_boundary(0, 30));
        // Skip epoch 1.
        let err = lc.advance(fixture_boundary(2, 30)).expect_err("gap");
        match err {
            LightClientError::EpochGap { latest, supplied } => {
                assert_eq!(latest, EpochNumber::new(0));
                assert_eq!(supplied, EpochNumber::new(2));
            }
            LightClientError::NonMonotonicEpoch { .. } => {
                panic!("expected EpochGap, got NonMonotonicEpoch");
            }
        }
        // The light client state is unchanged after the failure.
        assert_eq!(lc.latest().expect("present").epoch, EpochNumber::new(0));
    }

    #[test]
    fn advance_non_monotonic_errors() {
        let mut lc = LightClientState::from_genesis(fixture_boundary(5, 30));
        // Backwards epoch.
        let err = lc.advance(fixture_boundary(3, 30)).expect_err("backwards");
        match err {
            LightClientError::NonMonotonicEpoch { latest, supplied } => {
                assert_eq!(latest, EpochNumber::new(5));
                assert_eq!(supplied, EpochNumber::new(3));
            }
            LightClientError::EpochGap { .. } => {
                panic!("expected NonMonotonicEpoch, got EpochGap");
            }
        }
        // Same epoch.
        let err = lc.advance(fixture_boundary(5, 30)).expect_err("same");
        match err {
            LightClientError::NonMonotonicEpoch { latest, supplied } => {
                assert_eq!(latest, EpochNumber::new(5));
                assert_eq!(supplied, EpochNumber::new(5));
            }
            LightClientError::EpochGap { .. } => {
                panic!("expected NonMonotonicEpoch, got EpochGap");
            }
        }
    }

    #[test]
    fn tier_signal_updates_on_advance() {
        let mut lc = LightClientState::new();
        lc.advance(fixture_boundary(0, 7)).expect("advance");
        assert_eq!(
            lc.tier_signal().expect("present").tier,
            Some(SecurityTier::Tier1)
        );
        lc.advance(fixture_boundary(1, 15)).expect("advance");
        assert_eq!(
            lc.tier_signal().expect("present").tier,
            Some(SecurityTier::Tier2)
        );
        lc.advance(fixture_boundary(2, 30)).expect("advance");
        assert_eq!(
            lc.tier_signal().expect("present").tier,
            Some(SecurityTier::Tier3)
        );
    }

    #[test]
    fn state_and_proof_commitments_track_latest() {
        let mut lc = LightClientState::new();
        let boundary_a = EpochBoundary::new(
            EpochNumber::new(0),
            10,
            StateCommitment::from_bytes([0x11u8; STATE_COMMITMENT_BYTES]),
            ProofCommitment::from_bytes([0x22u8; PROOF_COMMITMENT_BYTES]),
        );
        let boundary_b = EpochBoundary::new(
            EpochNumber::new(1),
            10,
            StateCommitment::from_bytes([0x33u8; STATE_COMMITMENT_BYTES]),
            ProofCommitment::from_bytes([0x44u8; PROOF_COMMITMENT_BYTES]),
        );
        lc.advance(boundary_a).expect("advance");
        assert_eq!(
            lc.state_commitment().expect("present").as_bytes(),
            &[0x11u8; 32]
        );
        lc.advance(boundary_b).expect("advance");
        assert_eq!(
            lc.state_commitment().expect("present").as_bytes(),
            &[0x33u8; 32]
        );
        assert_eq!(
            lc.proof_commitment().expect("present").as_bytes(),
            &[0x44u8; 32]
        );
    }

    #[test]
    fn determinism_two_clients_same_sequence_converge() {
        // §8.9 convergence: two light clients consuming the
        // same EpochBoundary sequence produce identical state.
        let boundaries: Vec<_> = (0..5).map(|n| fixture_boundary(n, 20)).collect();
        let mut lc1 = LightClientState::new();
        let mut lc2 = LightClientState::new();
        for b in &boundaries {
            lc1.advance(b.clone()).expect("lc1");
            lc2.advance(b.clone()).expect("lc2");
        }
        assert_eq!(lc1, lc2);
    }

    // ---- LightClientError ----

    #[test]
    fn light_client_error_display_messages_distinct() {
        let v1 = LightClientError::NonMonotonicEpoch {
            latest: EpochNumber::new(5),
            supplied: EpochNumber::new(3),
        };
        let v2 = LightClientError::EpochGap {
            latest: EpochNumber::new(5),
            supplied: EpochNumber::new(10),
        };
        let m1 = v1.to_string();
        let m2 = v2.to_string();
        assert!(!m1.is_empty());
        assert!(!m2.is_empty());
        assert_ne!(m1, m2);
    }

    #[test]
    fn light_client_error_implements_std_error() {
        fn assert_err<E: std::error::Error>() {}
        assert_err::<LightClientError>();
    }

    #[test]
    fn light_client_error_bcs_round_trip() {
        for variant in [
            LightClientError::NonMonotonicEpoch {
                latest: EpochNumber::new(5),
                supplied: EpochNumber::new(3),
            },
            LightClientError::EpochGap {
                latest: EpochNumber::new(5),
                supplied: EpochNumber::new(10),
            },
        ] {
            let bytes = bcs::to_bytes(&variant).expect("encode");
            let decoded: LightClientError = bcs::from_bytes(&bytes).expect("decode");
            assert_eq!(variant, decoded);
        }
    }
}
