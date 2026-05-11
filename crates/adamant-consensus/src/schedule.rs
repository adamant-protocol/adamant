//! Epoch / round scheduling per whitepaper §8.2 + §8.3.2 + §8.3.3.
//!
//! Consensus operates on two timescales:
//!
//! - **Rounds** — the basic unit of DAG progression. Each round
//!   adds one layer to the DAG. Target duration: 250 ms.
//! - **Epochs** — a fixed number of rounds. Active-set selection,
//!   threshold-key generation, recursive-proof aggregation, and
//!   reward distribution all occur on epoch boundaries.
//!
//! Phase 7.0 shipped the [`EpochNumber`] / [`RoundNumber`]
//! newtypes. Phase 7.2 (this module) ships the *timing constants*
//! + *arithmetic helpers* + *commit-wave indexing* layered on
//!   top of those newtypes.
//!
//! # Calibration values (subject to pre-mainnet revision per §8.10)
//!
//! - `ROUND_DURATION_TARGET_MS = 250` — sub-second finality.
//! - `ROUNDS_PER_EPOCH = 144` — ~36 seconds per epoch.
//! - `COMMIT_WAVE_PERIOD_ROUNDS = 4` — wave anchor every 4 rounds.
//! - `QUORUM_NUMERATOR = 2`, `QUORUM_DENOMINATOR = 3` — "2/3 + 1"
//!   supermajority threshold.
//!
//! These are genesis-fixed at launch but subject to revision via
//! hard fork per §8.10 as the chain's hardware composition
//! evolves.
//!
//! # Phase 7.2 scope
//!
//! This module ships *pure arithmetic* — no consensus state, no
//! DAG, no vertex production. Phase 7.3 (DAG vertex structure)
//! consumes the timing helpers here; Phase 7.7 (DAG-BFT
//! consensus core) wires the commit-wave + quorum check into the
//! actual consensus path.

use serde::{Deserialize, Serialize};

use crate::epoch::{EpochNumber, RoundNumber};

// ---------------------------------------------------------------
// Timing constants (§8.2)
// ---------------------------------------------------------------

/// Target round duration in milliseconds per §8.2. 250 ms
/// targets sub-second finality (4–6 rounds → ~1–1.5 s for
/// shared-state transactions, well below Principle IV's
/// commitments).
///
/// This is a target; actual round latency depends on network
/// conditions and validator hardware. The §8.7 liveness
/// invariants accommodate transient deviations.
pub const ROUND_DURATION_TARGET_MS: u64 = 250;

/// Number of rounds per epoch per §8.2. 144 rounds × 250 ms ≈
/// 36 seconds per epoch.
///
/// Calibration trade-off per §8.2: shorter epochs mean more
/// frequent DKG (cryptographically expensive); longer epochs
/// mean validators leaving the active set face longer delays;
/// reward-distribution granularity prefers shorter. 36 seconds
/// is in the range used by other DAG protocols (1–60 s).
pub const ROUNDS_PER_EPOCH: u64 = 144;

/// Target epoch duration in milliseconds. Derived as
/// `ROUNDS_PER_EPOCH * ROUND_DURATION_TARGET_MS` for use in
/// reward-rate / inflation-rate calculations downstream.
/// 144 × 250 = 36_000 ms = 36 seconds.
pub const EPOCH_DURATION_TARGET_MS: u64 = ROUNDS_PER_EPOCH * ROUND_DURATION_TARGET_MS;

/// Commit-wave period in rounds per §8.3.3. The DAG enters a
/// commit wave every `COMMIT_WAVE_PERIOD_ROUNDS` rounds; a
/// specific vertex from that round is elected as the wave's
/// anchor (§8.6 VRF), and the anchor's causal history is
/// committed if validators have built sufficient supermajority
/// on top of it.
///
/// Default per spec: 4 rounds.
pub const COMMIT_WAVE_PERIOD_ROUNDS: u64 = 4;

/// Numerator of the "2/3 + 1" supermajority threshold used by
/// §8.3.1 vertex-quorum + §8.7 safety invariants. Pinned at 2.
pub const QUORUM_NUMERATOR: usize = 2;

/// Denominator of the supermajority threshold. Pinned at 3.
pub const QUORUM_DENOMINATOR: usize = 3;

/// Compute the supermajority threshold `floor(2n/3) + 1` per
/// §8.3.1. This is the minimum number of validators (out of
/// `n` active) whose agreement constitutes a quorum: vertex
/// parent-quorum, commit-wave anchor commit, threshold-
/// decryption share count, etc.
///
/// # Edge cases
///
/// - `n == 0`: returns `1` (vacuously: any non-empty agreement
///   trivially exceeds the threshold). Callers should typically
///   reject empty active sets via the §8.1.3 floor check
///   ([`crate::ActiveSet::is_dormant`]) before invoking this.
/// - `n == 1`: returns `1`.
/// - `n == 7` (§8.1.3 floor): `floor(14/3) + 1 = 4 + 1 = 5`.
/// - `n == 75` (§8.1.3 ceiling): `floor(150/3) + 1 = 50 + 1 = 51`.
#[must_use]
pub const fn quorum_threshold(n: usize) -> usize {
    (QUORUM_NUMERATOR * n) / QUORUM_DENOMINATOR + 1
}

// ---------------------------------------------------------------
// EpochSchedule — round ↔ epoch arithmetic
// ---------------------------------------------------------------

/// Round-by-round position within an epoch per §8.2.
///
/// Genesis-anchor round is `RoundNumber::ZERO` in epoch
/// `EpochNumber::ZERO`. Epoch N runs from round
/// `N * ROUNDS_PER_EPOCH` (inclusive) to round
/// `(N+1) * ROUNDS_PER_EPOCH - 1` (inclusive).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct EpochSchedule {
    /// Genesis round (chain anchor). Currently
    /// `RoundNumber::ZERO`; future hard forks per §8.10 may
    /// pin a different value if chain re-anchoring is ever
    /// specified.
    pub genesis_round: RoundNumber,
    /// Rounds per epoch. Defaults to [`ROUNDS_PER_EPOCH`]
    /// (= 144); customisable for tests and post-§8.10 hard-fork
    /// revisions.
    pub rounds_per_epoch: u64,
}

impl Default for EpochSchedule {
    fn default() -> Self {
        Self::launch()
    }
}

impl EpochSchedule {
    /// Launch-period schedule: 144 rounds per epoch (~36 s),
    /// genesis at round 0.
    #[must_use]
    pub const fn launch() -> Self {
        Self {
            genesis_round: RoundNumber::ZERO,
            rounds_per_epoch: ROUNDS_PER_EPOCH,
        }
    }

    /// Construct with explicit parameters. For tests + post-
    /// §8.10 hard-fork revisions.
    ///
    /// # Panics
    ///
    /// Panics if `rounds_per_epoch == 0` (degenerate schedule;
    /// every round would be an epoch boundary).
    #[must_use]
    pub const fn new(genesis_round: RoundNumber, rounds_per_epoch: u64) -> Self {
        assert!(
            rounds_per_epoch > 0,
            "EpochSchedule: rounds_per_epoch must be > 0"
        );
        Self {
            genesis_round,
            rounds_per_epoch,
        }
    }

    /// Epoch containing `round`.
    ///
    /// Returns `EpochNumber::ZERO` if `round` is before
    /// `genesis_round` (pre-genesis rounds are nominally part
    /// of epoch 0; in practice rounds before genesis don't
    /// exist).
    #[must_use]
    pub const fn epoch_of(&self, round: RoundNumber) -> EpochNumber {
        let r = round.as_u64();
        let g = self.genesis_round.as_u64();
        if r < g {
            return EpochNumber::ZERO;
        }
        EpochNumber::new((r - g) / self.rounds_per_epoch)
    }

    /// First round of `epoch` (inclusive).
    #[must_use]
    pub const fn first_round_of(&self, epoch: EpochNumber) -> RoundNumber {
        RoundNumber::new(
            self.genesis_round
                .as_u64()
                .saturating_add(epoch.as_u64().saturating_mul(self.rounds_per_epoch)),
        )
    }

    /// Last round of `epoch` (inclusive).
    #[must_use]
    pub const fn last_round_of(&self, epoch: EpochNumber) -> RoundNumber {
        let first = self.first_round_of(epoch).as_u64();
        RoundNumber::new(first.saturating_add(self.rounds_per_epoch - 1))
    }

    /// Whether `round` is the first round of its epoch (an
    /// epoch boundary). Epoch boundaries are when active-set
    /// changes, threshold-key churn, recursive-proof aggregation,
    /// and reward distribution all happen.
    #[must_use]
    pub const fn is_epoch_boundary(&self, round: RoundNumber) -> bool {
        let r = round.as_u64();
        let g = self.genesis_round.as_u64();
        if r < g {
            return false;
        }
        (r - g).is_multiple_of(self.rounds_per_epoch)
    }

    /// Zero-based position of `round` within its epoch.
    /// Returns a value in `0..rounds_per_epoch`.
    #[must_use]
    pub const fn round_within_epoch(&self, round: RoundNumber) -> u64 {
        let r = round.as_u64();
        let g = self.genesis_round.as_u64();
        if r < g {
            return 0;
        }
        (r - g) % self.rounds_per_epoch
    }
}

// ---------------------------------------------------------------
// CommitWave — wave indexing per §8.3.3
// ---------------------------------------------------------------

/// Index of a commit wave per §8.3.3. Wave 0 is the first wave
/// after genesis; wave N covers rounds
/// `N * COMMIT_WAVE_PERIOD_ROUNDS` through
/// `(N+1) * COMMIT_WAVE_PERIOD_ROUNDS - 1` (with the *last*
/// round of the wave hosting the wave's anchor vertex per
/// §8.3.3).
#[derive(
    Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize,
)]
#[repr(transparent)]
pub struct WaveIndex(pub u64);

impl WaveIndex {
    /// Genesis wave.
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
}

/// Commit-wave indexing helpers per §8.3.3.
///
/// Like [`EpochSchedule`], parameterised by:
///
/// - `genesis_round`: chain anchor round.
/// - `period_rounds`: wave period (default
///   [`COMMIT_WAVE_PERIOD_ROUNDS`] = 4).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct CommitWaveSchedule {
    /// Genesis round (matches [`EpochSchedule::genesis_round`]).
    pub genesis_round: RoundNumber,
    /// Wave period in rounds.
    pub period_rounds: u64,
}

impl Default for CommitWaveSchedule {
    fn default() -> Self {
        Self::launch()
    }
}

impl CommitWaveSchedule {
    /// Launch-period wave schedule: 4 rounds per wave, genesis
    /// at round 0.
    #[must_use]
    pub const fn launch() -> Self {
        Self {
            genesis_round: RoundNumber::ZERO,
            period_rounds: COMMIT_WAVE_PERIOD_ROUNDS,
        }
    }

    /// Construct with explicit parameters.
    ///
    /// # Panics
    ///
    /// Panics if `period_rounds == 0`.
    #[must_use]
    pub const fn new(genesis_round: RoundNumber, period_rounds: u64) -> Self {
        assert!(
            period_rounds > 0,
            "CommitWaveSchedule: period_rounds must be > 0"
        );
        Self {
            genesis_round,
            period_rounds,
        }
    }

    /// Wave containing `round`.
    #[must_use]
    pub const fn wave_of(&self, round: RoundNumber) -> WaveIndex {
        let r = round.as_u64();
        let g = self.genesis_round.as_u64();
        if r < g {
            return WaveIndex::ZERO;
        }
        WaveIndex::new((r - g) / self.period_rounds)
    }

    /// First round of `wave` (inclusive).
    #[must_use]
    pub const fn first_round_of(&self, wave: WaveIndex) -> RoundNumber {
        RoundNumber::new(
            self.genesis_round
                .as_u64()
                .saturating_add(wave.as_u64().saturating_mul(self.period_rounds)),
        )
    }

    /// Anchor round of `wave` — the last round of the wave, in
    /// which the wave's anchor vertex is elected per §8.3.3
    /// step 1. The wave's commit decision (§8.3.3 step 2)
    /// happens at the *following* wave's first round, when
    /// enough validators have built on top of this wave's
    /// anchor to make the commit decision determinable.
    #[must_use]
    pub const fn anchor_round_of(&self, wave: WaveIndex) -> RoundNumber {
        let first = self.first_round_of(wave).as_u64();
        RoundNumber::new(first.saturating_add(self.period_rounds - 1))
    }

    /// Whether `round` is the anchor round of its wave —
    /// equivalently, the last round of a wave. The VRF-elected
    /// anchor vertex (§8.3.3 step 1 + §8.6) lives on an
    /// anchor round.
    #[must_use]
    pub const fn is_anchor_round(&self, round: RoundNumber) -> bool {
        let r = round.as_u64();
        let g = self.genesis_round.as_u64();
        if r < g {
            return false;
        }
        (r - g + 1).is_multiple_of(self.period_rounds)
    }

    /// Zero-based position of `round` within its wave. Returns
    /// a value in `0..period_rounds`. Position `period_rounds-1`
    /// is the anchor round.
    #[must_use]
    pub const fn round_within_wave(&self, round: RoundNumber) -> u64 {
        let r = round.as_u64();
        let g = self.genesis_round.as_u64();
        if r < g {
            return 0;
        }
        (r - g) % self.period_rounds
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---------- timing constants ----------

    #[test]
    fn round_duration_pinned_at_250ms() {
        assert_eq!(ROUND_DURATION_TARGET_MS, 250);
    }

    #[test]
    fn rounds_per_epoch_pinned_at_144() {
        assert_eq!(ROUNDS_PER_EPOCH, 144);
    }

    #[test]
    fn epoch_duration_derived_correctly() {
        // 144 rounds × 250 ms = 36_000 ms = 36 seconds.
        assert_eq!(EPOCH_DURATION_TARGET_MS, 36_000);
    }

    #[test]
    fn commit_wave_period_pinned_at_4() {
        assert_eq!(COMMIT_WAVE_PERIOD_ROUNDS, 4);
    }

    #[test]
    fn quorum_ratio_pinned_at_2_3() {
        assert_eq!(QUORUM_NUMERATOR, 2);
        assert_eq!(QUORUM_DENOMINATOR, 3);
    }

    // ---------- quorum_threshold ----------

    /// §8.3.1: "Each vertex must reference at least 2/3+1
    /// vertices from the previous round." Pin the formula
    /// `floor(2n/3) + 1` at canonical sizes.
    #[test]
    fn quorum_threshold_canonical_sizes() {
        // n=1: floor(2/3) + 1 = 0 + 1 = 1.
        assert_eq!(quorum_threshold(1), 1);
        // n=4 (absolute BFT minimum): floor(8/3) + 1 = 2 + 1 = 3.
        assert_eq!(quorum_threshold(4), 3);
        // n=7 (§8.1.3 floor): floor(14/3) + 1 = 4 + 1 = 5.
        assert_eq!(quorum_threshold(7), 5);
        // n=10: floor(20/3) + 1 = 6 + 1 = 7.
        assert_eq!(quorum_threshold(10), 7);
        // n=15 (§8.4 threshold-encryption boundary): floor(30/3) + 1 = 10 + 1 = 11.
        assert_eq!(quorum_threshold(15), 11);
        // n=30 (§8.1.7 Tier III boundary): floor(60/3) + 1 = 20 + 1 = 21.
        assert_eq!(quorum_threshold(30), 21);
        // n=75 (§8.1.3 launch ceiling): floor(150/3) + 1 = 50 + 1 = 51.
        assert_eq!(quorum_threshold(75), 51);
        // n=100: floor(200/3) + 1 = 66 + 1 = 67.
        assert_eq!(quorum_threshold(100), 67);
    }

    #[test]
    fn quorum_threshold_n_0_returns_1() {
        // Degenerate but well-defined: floor(0) + 1 = 1.
        assert_eq!(quorum_threshold(0), 1);
    }

    /// Quorum at n=15 (Tier I → Tier II boundary) requires 11
    /// validators to agree — exactly the §8.4 threshold-
    /// decryption viability threshold "t-of-N for some honest
    /// threshold t" calibrated for N≥15. Pin the alignment.
    #[test]
    fn quorum_alignment_with_threshold_encryption_boundary() {
        // f = floor((n-1) / 3) Byzantine validators tolerated;
        // quorum = n - f covers the remaining honest.
        // n=15 ⇒ f=4, quorum = 11. Matches our formula.
        assert_eq!(quorum_threshold(15), 11);
    }

    // ---------- EpochSchedule ----------

    #[test]
    fn epoch_schedule_launch_defaults() {
        let s = EpochSchedule::launch();
        assert_eq!(s.genesis_round, RoundNumber::ZERO);
        assert_eq!(s.rounds_per_epoch, 144);
    }

    #[test]
    fn epoch_schedule_default_matches_launch() {
        assert_eq!(EpochSchedule::default(), EpochSchedule::launch());
    }

    #[test]
    fn epoch_of_round_zero_is_epoch_zero() {
        let s = EpochSchedule::launch();
        assert_eq!(s.epoch_of(RoundNumber::new(0)), EpochNumber::ZERO);
    }

    #[test]
    fn epoch_boundaries_at_canonical_rounds() {
        let s = EpochSchedule::launch();
        // Rounds 0..143 are epoch 0 (144 rounds per epoch).
        assert_eq!(s.epoch_of(RoundNumber::new(0)), EpochNumber::new(0));
        assert_eq!(s.epoch_of(RoundNumber::new(143)), EpochNumber::new(0));
        // Round 144 begins epoch 1.
        assert_eq!(s.epoch_of(RoundNumber::new(144)), EpochNumber::new(1));
        // Round 287 ends epoch 1.
        assert_eq!(s.epoch_of(RoundNumber::new(287)), EpochNumber::new(1));
        // Round 288 begins epoch 2.
        assert_eq!(s.epoch_of(RoundNumber::new(288)), EpochNumber::new(2));
    }

    #[test]
    fn first_and_last_round_of_epoch_pin() {
        let s = EpochSchedule::launch();
        // Epoch 0: rounds 0..=143.
        assert_eq!(s.first_round_of(EpochNumber::new(0)), RoundNumber::new(0));
        assert_eq!(s.last_round_of(EpochNumber::new(0)), RoundNumber::new(143));
        // Epoch 1: rounds 144..=287.
        assert_eq!(s.first_round_of(EpochNumber::new(1)), RoundNumber::new(144));
        assert_eq!(s.last_round_of(EpochNumber::new(1)), RoundNumber::new(287));
        // Epoch 100: rounds 14_400..=14_543.
        assert_eq!(
            s.first_round_of(EpochNumber::new(100)),
            RoundNumber::new(14_400)
        );
        assert_eq!(
            s.last_round_of(EpochNumber::new(100)),
            RoundNumber::new(14_543)
        );
    }

    #[test]
    fn is_epoch_boundary_pin() {
        let s = EpochSchedule::launch();
        // Genesis round IS a boundary (epoch 0 begins).
        assert!(s.is_epoch_boundary(RoundNumber::new(0)));
        // Mid-epoch rounds aren't boundaries.
        assert!(!s.is_epoch_boundary(RoundNumber::new(1)));
        assert!(!s.is_epoch_boundary(RoundNumber::new(143)));
        // Every 144th round IS a boundary.
        assert!(s.is_epoch_boundary(RoundNumber::new(144)));
        assert!(s.is_epoch_boundary(RoundNumber::new(288)));
        assert!(s.is_epoch_boundary(RoundNumber::new(14_400)));
    }

    #[test]
    fn round_within_epoch_pin() {
        let s = EpochSchedule::launch();
        assert_eq!(s.round_within_epoch(RoundNumber::new(0)), 0);
        assert_eq!(s.round_within_epoch(RoundNumber::new(1)), 1);
        assert_eq!(s.round_within_epoch(RoundNumber::new(143)), 143);
        assert_eq!(s.round_within_epoch(RoundNumber::new(144)), 0);
        assert_eq!(s.round_within_epoch(RoundNumber::new(145)), 1);
        assert_eq!(s.round_within_epoch(RoundNumber::new(287)), 143);
        assert_eq!(s.round_within_epoch(RoundNumber::new(288)), 0);
    }

    #[test]
    fn epoch_schedule_with_custom_genesis() {
        // Hypothetical hard-fork scenario: chain re-anchored at
        // round 1000.
        let s = EpochSchedule::new(RoundNumber::new(1000), 144);
        assert_eq!(s.epoch_of(RoundNumber::new(1000)), EpochNumber::ZERO);
        assert_eq!(s.epoch_of(RoundNumber::new(1143)), EpochNumber::new(0));
        assert_eq!(s.epoch_of(RoundNumber::new(1144)), EpochNumber::new(1));
        // Pre-genesis rounds clamp to epoch 0.
        assert_eq!(s.epoch_of(RoundNumber::new(500)), EpochNumber::ZERO);
        assert!(!s.is_epoch_boundary(RoundNumber::new(500)));
    }

    #[test]
    fn epoch_schedule_bcs_round_trip() {
        let s = EpochSchedule::launch();
        let bytes = bcs::to_bytes(&s).unwrap();
        let decoded: EpochSchedule = bcs::from_bytes(&bytes).unwrap();
        assert_eq!(s, decoded);
    }

    #[test]
    #[should_panic(expected = "rounds_per_epoch must be > 0")]
    fn epoch_schedule_rejects_zero_rounds_per_epoch() {
        let _ = EpochSchedule::new(RoundNumber::new(0), 0);
    }

    // ---------- CommitWaveSchedule ----------

    #[test]
    fn wave_schedule_launch_defaults() {
        let s = CommitWaveSchedule::launch();
        assert_eq!(s.genesis_round, RoundNumber::ZERO);
        assert_eq!(s.period_rounds, 4);
    }

    /// §8.3.3: "every 4 rounds, by default" — pin wave
    /// boundaries.
    #[test]
    fn wave_indexing_pin() {
        let s = CommitWaveSchedule::launch();
        // Wave 0: rounds 0..=3.
        assert_eq!(s.wave_of(RoundNumber::new(0)), WaveIndex::ZERO);
        assert_eq!(s.wave_of(RoundNumber::new(3)), WaveIndex::ZERO);
        // Wave 1: rounds 4..=7.
        assert_eq!(s.wave_of(RoundNumber::new(4)), WaveIndex::new(1));
        assert_eq!(s.wave_of(RoundNumber::new(7)), WaveIndex::new(1));
        // Wave 2: rounds 8..=11.
        assert_eq!(s.wave_of(RoundNumber::new(8)), WaveIndex::new(2));
    }

    /// Anchor round = last round of a wave per §8.3.3 step 1.
    #[test]
    fn anchor_round_pin() {
        let s = CommitWaveSchedule::launch();
        // Wave 0 anchor = round 3.
        assert_eq!(s.anchor_round_of(WaveIndex::ZERO), RoundNumber::new(3));
        // Wave 1 anchor = round 7.
        assert_eq!(s.anchor_round_of(WaveIndex::new(1)), RoundNumber::new(7));
        // Wave 100 anchor = round 403.
        assert_eq!(
            s.anchor_round_of(WaveIndex::new(100)),
            RoundNumber::new(403)
        );
    }

    #[test]
    fn is_anchor_round_pin() {
        let s = CommitWaveSchedule::launch();
        // Round 0, 1, 2 not anchors.
        assert!(!s.is_anchor_round(RoundNumber::new(0)));
        assert!(!s.is_anchor_round(RoundNumber::new(1)));
        assert!(!s.is_anchor_round(RoundNumber::new(2)));
        // Round 3 IS an anchor.
        assert!(s.is_anchor_round(RoundNumber::new(3)));
        // Rounds 4, 5, 6 not.
        assert!(!s.is_anchor_round(RoundNumber::new(4)));
        // Round 7 IS.
        assert!(s.is_anchor_round(RoundNumber::new(7)));
        // Round 11 IS.
        assert!(s.is_anchor_round(RoundNumber::new(11)));
    }

    #[test]
    fn round_within_wave_pin() {
        let s = CommitWaveSchedule::launch();
        assert_eq!(s.round_within_wave(RoundNumber::new(0)), 0);
        assert_eq!(s.round_within_wave(RoundNumber::new(3)), 3);
        assert_eq!(s.round_within_wave(RoundNumber::new(4)), 0);
        assert_eq!(s.round_within_wave(RoundNumber::new(7)), 3);
    }

    #[test]
    fn first_round_of_wave_pin() {
        let s = CommitWaveSchedule::launch();
        assert_eq!(s.first_round_of(WaveIndex::ZERO), RoundNumber::new(0));
        assert_eq!(s.first_round_of(WaveIndex::new(1)), RoundNumber::new(4));
        assert_eq!(s.first_round_of(WaveIndex::new(100)), RoundNumber::new(400));
    }

    /// Each wave covers exactly `COMMIT_WAVE_PERIOD_ROUNDS`
    /// rounds, ending with an anchor round. Pin the invariant
    /// across the first 10 waves.
    #[test]
    fn wave_invariant_anchor_is_last_round() {
        let s = CommitWaveSchedule::launch();
        for w in 0..10u64 {
            let wave = WaveIndex::new(w);
            let first = s.first_round_of(wave).as_u64();
            let anchor = s.anchor_round_of(wave).as_u64();
            assert_eq!(anchor - first + 1, COMMIT_WAVE_PERIOD_ROUNDS);
            assert!(s.is_anchor_round(s.anchor_round_of(wave)));
            assert!(!s.is_anchor_round(s.first_round_of(wave)));
        }
    }

    #[test]
    fn wave_schedule_bcs_round_trip() {
        let s = CommitWaveSchedule::launch();
        let bytes = bcs::to_bytes(&s).unwrap();
        let decoded: CommitWaveSchedule = bcs::from_bytes(&bytes).unwrap();
        assert_eq!(s, decoded);
    }

    #[test]
    fn wave_index_bcs_round_trip() {
        let w = WaveIndex::new(42);
        let bytes = bcs::to_bytes(&w).unwrap();
        let decoded: WaveIndex = bcs::from_bytes(&bytes).unwrap();
        assert_eq!(w, decoded);
        assert_eq!(bytes.len(), 8); // u64 LE
    }

    #[test]
    #[should_panic(expected = "period_rounds must be > 0")]
    fn wave_schedule_rejects_zero_period() {
        let _ = CommitWaveSchedule::new(RoundNumber::new(0), 0);
    }

    // ---------- alignment of epoch and wave boundaries ----------

    /// 144 rounds per epoch ÷ 4 rounds per wave = 36 waves per
    /// epoch. Pin: the last wave of each epoch's anchor is the
    /// last round of that epoch.
    #[test]
    fn epoch_and_wave_alignment_at_launch() {
        let epoch_s = EpochSchedule::launch();
        let wave_s = CommitWaveSchedule::launch();
        // Wave 35 anchor = round 143 (last round of epoch 0).
        assert_eq!(
            wave_s.anchor_round_of(WaveIndex::new(35)),
            RoundNumber::new(143)
        );
        assert_eq!(
            epoch_s.last_round_of(EpochNumber::new(0)),
            RoundNumber::new(143)
        );
        // Wave 36 begins at round 144 (epoch 1 boundary).
        assert_eq!(
            wave_s.first_round_of(WaveIndex::new(36)),
            RoundNumber::new(144)
        );
        assert!(epoch_s.is_epoch_boundary(wave_s.first_round_of(WaveIndex::new(36))));
    }
}
