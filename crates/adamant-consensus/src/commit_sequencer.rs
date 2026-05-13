//! Commit sequencer + indirect commit rule + halt detection per
//! whitepaper §8.3.3 + §8.7.
//!
//! Phase 7.7c deliverable — the stateful commit-decision tracker
//! that layers on top of Phase 7.7b's direct commit rule. Three
//! responsibilities:
//!
//! 1. **Indirect commit rule.** When a wave's direct commit
//!    decision is [`CommitDecision::Pending`], the wave is held
//!    [`WaveOutcome::Undecided`]. A later wave's direct
//!    [`CommitDecision::Committed`] resolves every earlier
//!    undecided wave: the later anchor's causal-reach status
//!    decides whether each earlier anchor is committed or
//!    skipped. This is Mysticeti's "indirect commit at
//!    `anchor_round + 3`" — but Adamant generalises: any later
//!    direct-committed anchor (not just the next wave) can pull
//!    forward all earlier undecided waves.
//!
//! 2. **Chronological commit ordering.** When wave `W` commits
//!    and resolves earlier undecided waves `W_0, W_1, …, W_{W-1}`,
//!    the sequencer emits the totally-ordered commit sequences
//!    in **wave order** — wave `W_0`'s ordered closure first,
//!    then `W_1`'s, …, then `W`'s. Each wave's [`commit_order`]
//!    walk excludes the running committed set, so the resulting
//!    per-wave `ordered` lists partition the §6 execution input.
//!
//! 3. **Halt detection.** Per §8.7.1, when the active set is at
//!    or near the constitutional floor and quorum cannot be
//!    reached, the chain halts rather than forks. Phase 7.7c
//!    ships [`is_chain_dormant`] — a thin wrapper over
//!    [`ActiveSet::is_dormant`] that surfaces the
//!    chain-fully-paused signal. The "near floor" range (N=7–14
//!    per §8.7.1) is observable via [`ActiveSet::tier`] returning
//!    [`SecurityTier::Tier1`]; consumers gate their halt-warning
//!    UI on that signal.
//!
//! [`SecurityTier::Tier1`]: crate::SecurityTier
//!
//! # Spec basis
//!
//! - §8.3.3: "Periodically (every 4 rounds, by default), the DAG
//!   enters a **commit wave**…" — the per-wave commit-decision
//!   shape Phase 7.7b implemented.
//! - §8.3.3 footnote: "This is a simplified description of the
//!   Mysticeti commit rule. The full rule handles edge cases
//!   (multiple consecutive anchor failures, network partitions)
//!   with care…" — Phase 7.7c is the "full rule" layer.
//! - §8.7 Theorem 1 (Safety): "If fewer than 1/3 of validators
//!   by stake are Byzantine, the chain never commits two
//!   conflicting transactions." → the `committed_set`
//!   discipline + no-double-commit invariant tested below.
//! - §8.7 Theorem 2 (Liveness): "…the chain commits transactions
//!   at a rate determined by network conditions … except during
//!   periods when the active set is below the constitutional
//!   floor of 7, in which case the chain halts rather than fork
//!   (subsection 8.7.1)." → halt detection.
//! - §8.7.1: "When the active set is at or near the
//!   constitutional floor (N=7–14), the chain halts on
//!   disagreement rather than forking. … Safety is preserved
//!   (no double-spends, no forks). Liveness is weak at low N —
//!   this is an honest cost, not a hidden one." → the framing
//!   adopted by [`is_chain_dormant`].
//!
//! # Indirect-commit chain
//!
//! Scenario A (indirect commit pulls forward):
//! - Wave 0 direct decision: [`CommitDecision::Pending`].
//! - Wave 1 direct decision: [`CommitDecision::Committed`] AND
//!   `A_1` causally reaches `A_0`.
//! - Outcome: wave 0 indirect-committed; wave 1 directly
//!   committed. Commit sequence: `ordered_0 ++ ordered_1`.
//!
//! Scenario B (indirect skip):
//! - Wave 0 anchor `A_0` is unreferenced by any later vertex.
//! - Wave 1 direct decision: [`CommitDecision::Committed`].
//!   `A_1` does NOT causally reach `A_0`.
//! - Outcome: wave 0 indirect-skipped; wave 1 directly
//!   committed. Commit sequence: `ordered_1` only.
//!
//! Scenario C (skip doesn't propagate):
//! - Wave 0 direct decision: [`CommitDecision::Pending`].
//! - Wave 1 direct decision: [`CommitDecision::Skipped`].
//! - Outcome: wave 0 stays undecided; wave 1 skipped. Earlier
//!   waves are not resolved by a later skip. They wait for a
//!   future direct commit.
//!
//! # Phase 7.7 sub-arc roadmap (updated)
//!
//! | Sub-arc | Surface | Status |
//! |---------|---------|--------|
//! | 7.7a   | DAG storage + insertion validation | closed |
//! | 7.7b   | Direct commit-wave logic | closed |
//! | 7.7c   | Indirect commit + halt detection (this sub-arc) | **THIS SUB-ARC** |
//! | 7.7d   | Mempool integration (threshold/time-lock decryption flows) | pending |
//! | 7.7e   | End-to-end integration tests | pending |

use std::collections::{BTreeMap, HashSet};

use serde::{Deserialize, Serialize};

use crate::active_set::ActiveSet;
use crate::commit_wave::{commit_order, CommitDecision};
use crate::dag::DagState;
use crate::schedule::{CommitWaveSchedule, WaveIndex};
use crate::vertex::VertexId;

/// Final outcome for a commit wave per §8.3.3 + the §8.7 safety
/// invariants.
///
/// Non-`#[non_exhaustive]` per consensus-critical-surface
/// discipline (same posture as [`crate::DagError`] and
/// [`CommitDecision`]); adding a variant is a hard-fork-aware
/// deliberate change.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum WaveOutcome {
    /// The wave is directly or indirectly committed. `ordered`
    /// is the totally-ordered list of vertices this wave brings
    /// into the chain (anchor + new causal ancestors, sorted by
    /// `(round, author, vertex_id)`). The §6 execution layer
    /// consumes this list at step 4 of §8.3.3.
    Committed {
        /// The wave's anchor (committed vertex).
        anchor: VertexId,
        /// The new vertices this wave commits, in totally-
        /// ordered execution sequence.
        ordered: Vec<VertexId>,
    },

    /// The wave's anchor was rejected — either directly (the
    /// decision round had quorum vertices but anchor support
    /// fell short) or indirectly (a later wave committed but
    /// did not causally reach this anchor). Skipped anchors
    /// contribute nothing to the execution sequence.
    Skipped {
        /// The skipped anchor (carried for traceability).
        anchor: VertexId,
    },

    /// The wave's anchor has not yet been resolved. Direct
    /// commit returned [`CommitDecision::Pending`] and no later
    /// wave has directly committed yet. The wave waits for
    /// either a late direct decision (more vertices arrive at
    /// the decision round) or a future wave's indirect commit
    /// pulling it forward.
    Undecided {
        /// The pending anchor (carried so the indirect commit
        /// path can look up its [`DagState::reaches`] status).
        anchor: VertexId,
    },
}

/// Typed errors produced by [`CommitSequencer::record_decision`].
///
/// Non-`#[non_exhaustive]` per consensus-critical-surface
/// discipline.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SequencerError {
    /// The supplied wave is already resolved (Committed or
    /// Skipped) and cannot be re-recorded with a new decision.
    /// Once a wave is decided — directly OR indirectly — the
    /// outcome is final; this error surfaces accidental double-
    /// recording from the caller orchestration layer.
    AlreadyResolved {
        /// The wave whose outcome was already final.
        wave: WaveIndex,
    },

    /// The supplied wave was previously recorded with a
    /// different anchor. Two distinct anchors for the same wave
    /// indicates a caller bug (the anchor for wave W is
    /// uniquely determined by the §8.6 VRF + the DAG state at
    /// the anchor round; if the caller is computing different
    /// anchors, the §8.6 inputs disagree).
    AnchorMismatch {
        /// The wave with the conflicting anchor record.
        wave: WaveIndex,
        /// The anchor already on record for this wave.
        existing: VertexId,
        /// The newly-supplied anchor.
        supplied: VertexId,
    },
}

impl core::fmt::Display for SequencerError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::AlreadyResolved { wave } => {
                write!(f, "wave {wave:?} already resolved")
            }
            Self::AnchorMismatch {
                wave,
                existing,
                supplied,
            } => write!(
                f,
                "wave {wave:?} anchor mismatch: existing={existing:?} supplied={supplied:?}"
            ),
        }
    }
}

impl std::error::Error for SequencerError {}

/// Stateful commit-decision tracker per §8.3.3 + §8.7.
///
/// Owns the running [`committed_set`](Self::committed_set) and
/// the per-wave outcome log. Drives the indirect commit rule
/// internally on every [`record_decision`](Self::record_decision)
/// that resolves to [`CommitDecision::Committed`].
///
/// # Memory shape
///
/// At steady state with `W` waves processed, the sequencer
/// holds:
/// - `W` entries in the decision log (one [`WaveOutcome`] each),
/// - A `HashSet<VertexId>` of all committed vertices to date.
///
/// Both are bounded by chain history; the chain prunes
/// committed-set entries past a configurable horizon at the
/// Phase 7.7e integration layer (the per-vertex membership
/// check only needs the *currently-decidable* horizon).
///
/// # Determinism
///
/// Every method is deterministic in its inputs. Two honest
/// nodes processing the same sequence of (DAG snapshot, wave,
/// anchor, decision) tuples converge to identical
/// `CommitSequencer` state. This is essential for §8.7 safety.
#[derive(Clone, Debug)]
pub struct CommitSequencer {
    /// Wave schedule (commit period + first-round anchor). The
    /// sequencer itself doesn't use `schedule` for the indirect-
    /// commit decision — that's purely DAG-driven — but it's
    /// carried for caller-side queries about the wave layout and
    /// for the [`Self::launch`] constructor symmetry with other
    /// schedule-bound types.
    schedule: CommitWaveSchedule,

    /// Per-wave outcome log. BTreeMap so iteration is in wave-
    /// index order (chronological); this is what makes the
    /// indirect-commit propagation deterministic.
    decided: BTreeMap<WaveIndex, WaveOutcome>,

    /// Running set of all committed vertices. Used to exclude
    /// already-committed vertices from each new wave's
    /// [`commit_order`] output, ensuring the per-wave `ordered`
    /// lists partition the §6 execution input.
    committed: HashSet<VertexId>,
}

impl CommitSequencer {
    /// New sequencer with the default §8.3.3 schedule
    /// ([`CommitWaveSchedule::launch`]).
    #[must_use]
    pub fn launch() -> Self {
        Self::new(CommitWaveSchedule::launch())
    }

    /// New sequencer with a caller-supplied schedule. Used for
    /// parameterised tests and for chain restarts with a non-
    /// default schedule.
    #[must_use]
    pub fn new(schedule: CommitWaveSchedule) -> Self {
        Self {
            schedule,
            decided: BTreeMap::new(),
            committed: HashSet::new(),
        }
    }

    /// The current committed-vertex set. Pass into
    /// [`commit_order`] when computing a wave's ordered closure.
    #[must_use]
    pub const fn committed_set(&self) -> &HashSet<VertexId> {
        &self.committed
    }

    /// Number of committed vertices to date.
    #[must_use]
    pub fn committed_count(&self) -> usize {
        self.committed.len()
    }

    /// Whether `id` has been committed (directly or indirectly).
    #[must_use]
    pub fn is_committed(&self, id: &VertexId) -> bool {
        self.committed.contains(id)
    }

    /// The wave schedule this sequencer was constructed with.
    #[must_use]
    pub const fn schedule(&self) -> &CommitWaveSchedule {
        &self.schedule
    }

    /// The outcome of a specific wave, if it has been recorded.
    /// Returns `None` for waves not yet processed.
    #[must_use]
    pub fn outcome(&self, wave: WaveIndex) -> Option<&WaveOutcome> {
        self.decided.get(&wave)
    }

    /// Iterator over `(wave, outcome)` pairs in wave-index order.
    /// Useful for caller-side traversal of the resolved-waves
    /// history (e.g., feeding committed anchors to the §6
    /// execution layer).
    pub fn outcomes(&self) -> impl Iterator<Item = (&WaveIndex, &WaveOutcome)> {
        self.decided.iter()
    }

    /// Number of waves with any recorded outcome (Committed,
    /// Skipped, or Undecided). Useful for halt-monitor heuristics.
    #[must_use]
    pub fn recorded_waves(&self) -> usize {
        self.decided.len()
    }

    /// Number of waves currently in [`WaveOutcome::Undecided`].
    /// Used by Phase 7.7e halt-monitor heuristics to flag
    /// extended consensus stagnation.
    #[must_use]
    pub fn undecided_waves(&self) -> usize {
        self.decided
            .values()
            .filter(|o| matches!(o, WaveOutcome::Undecided { .. }))
            .count()
    }

    /// Record the direct-commit decision for a wave.
    ///
    /// # Behaviour by decision type
    ///
    /// - [`CommitDecision::Pending`] — wave is held as
    ///   [`WaveOutcome::Undecided`]. Re-recording a wave that's
    ///   already Undecided with the same anchor is a no-op (the
    ///   caller's pipeline may poll a still-pending wave
    ///   repeatedly).
    /// - [`CommitDecision::Skipped`] — wave is recorded as
    ///   [`WaveOutcome::Skipped`]. Earlier undecided waves are
    ///   NOT resolved by a skip (per §8.7 indirect commit rule:
    ///   skips don't propagate).
    /// - [`CommitDecision::Committed`] — wave is recorded as
    ///   [`WaveOutcome::Committed`] AND the **indirect commit
    ///   rule** fires: every earlier undecided wave is resolved
    ///   as Committed (if `anchor` causally reaches the earlier
    ///   anchor) or Skipped (otherwise). The earlier waves'
    ///   ordered closures are computed first (chronologically),
    ///   then this wave's.
    ///
    /// # Errors
    ///
    /// - [`SequencerError::AlreadyResolved`] if the wave is
    ///   already in a final state (Committed or Skipped).
    /// - [`SequencerError::AnchorMismatch`] if the wave was
    ///   previously recorded with a different anchor.
    ///
    /// # Determinism
    ///
    /// Pure function of (sequencer state, DAG, wave, anchor,
    /// decision). Two honest nodes processing the same sequence
    /// converge to identical state.
    pub fn record_decision(
        &mut self,
        dag: &DagState,
        wave: WaveIndex,
        anchor: VertexId,
        decision: CommitDecision,
    ) -> Result<(), SequencerError> {
        // Reject re-recording of finalised waves and reject
        // anchor mismatches against a held undecided record.
        if let Some(existing) = self.decided.get(&wave) {
            match existing {
                WaveOutcome::Committed { .. } | WaveOutcome::Skipped { .. } => {
                    return Err(SequencerError::AlreadyResolved { wave });
                }
                WaveOutcome::Undecided {
                    anchor: existing_anchor,
                } => {
                    if *existing_anchor != anchor {
                        return Err(SequencerError::AnchorMismatch {
                            wave,
                            existing: *existing_anchor,
                            supplied: anchor,
                        });
                    }
                    // Same wave, same anchor, still pending —
                    // treat re-recording of Pending as no-op.
                    if matches!(decision, CommitDecision::Pending) {
                        return Ok(());
                    }
                    // Otherwise fall through to handle the new
                    // (Committed or Skipped) decision — this is
                    // the "late direct commit" path: a wave was
                    // Undecided, then enough vertices land to
                    // make it directly decidable.
                }
            }
        }

        match decision {
            CommitDecision::Pending => {
                self.decided.insert(wave, WaveOutcome::Undecided { anchor });
            }
            CommitDecision::Skipped => {
                // Skips don't propagate. Just record this wave.
                self.decided.insert(wave, WaveOutcome::Skipped { anchor });
            }
            CommitDecision::Committed => {
                // Indirect commit rule fires. Collect every
                // earlier undecided wave (BTreeMap iteration is
                // wave-index-ordered, so this is chronological).
                let undecided_earlier: Vec<(WaveIndex, VertexId)> = self
                    .decided
                    .iter()
                    .filter_map(|(w, o)| {
                        if *w < wave {
                            if let WaveOutcome::Undecided { anchor: a } = o {
                                return Some((*w, *a));
                            }
                        }
                        None
                    })
                    .collect();

                for (earlier_wave, earlier_anchor) in undecided_earlier {
                    if dag.reaches(&anchor, &earlier_anchor) {
                        // Indirect commit: this anchor's causal
                        // history includes the earlier anchor,
                        // so the earlier anchor is now committed.
                        let ordered = commit_order(dag, earlier_anchor, &self.committed);
                        self.committed.extend(ordered.iter().copied());
                        self.decided.insert(
                            earlier_wave,
                            WaveOutcome::Committed {
                                anchor: earlier_anchor,
                                ordered,
                            },
                        );
                    } else {
                        // Indirect skip: this anchor's causal
                        // history does NOT include the earlier
                        // anchor; the earlier wave is finalised
                        // as skipped.
                        self.decided.insert(
                            earlier_wave,
                            WaveOutcome::Skipped {
                                anchor: earlier_anchor,
                            },
                        );
                    }
                }

                // Now commit this wave itself (after earlier
                // waves so the chronological order property
                // holds in the committed_set evolution).
                let ordered = commit_order(dag, anchor, &self.committed);
                self.committed.extend(ordered.iter().copied());
                self.decided
                    .insert(wave, WaveOutcome::Committed { anchor, ordered });
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------
// Halt detection per §8.7.1
// ---------------------------------------------------------------

/// Whether the chain is **dormant** per §8.7.1 — the active set
/// is below the constitutional floor [`ACTIVE_SET_FLOOR`]
/// (`= 7`), so the chain cannot progress at all (insufficient
/// participants to form a quorum).
///
/// This is the strongest halt signal: the chain cannot commit
/// any transaction until at least `ACTIVE_SET_FLOOR` validators
/// are registered. Per §8.1.6 + §8.7.1 this is the "below floor"
/// regime; the chain is paused, not forked, and safety is
/// preserved.
///
/// Wallets and explorers SHOULD display a halt-state warning
/// when this returns `true`.
///
/// [`ACTIVE_SET_FLOOR`]: crate::ACTIVE_SET_FLOOR
#[must_use]
pub fn is_chain_dormant(active_set: &ActiveSet) -> bool {
    active_set.is_dormant()
}

/// Whether the chain is operating "at or near the floor" per
/// §8.7.1 — the active set is in `[ACTIVE_SET_FLOOR, 14]`, the
/// §8.1.7 Security Tier I range. The chain is operational here
/// but with weaker liveness: occasional halts of several rounds
/// are expected per the §8.7.1 liveness math.
///
/// This is a softer signal than [`is_chain_dormant`]; it does
/// NOT mean the chain is currently paused, only that halts are
/// more likely. Phase 7.7e integration may surface this signal
/// as a "weak liveness" indicator alongside [`SecurityTier`].
///
/// [`SecurityTier`]: crate::SecurityTier
#[must_use]
pub fn is_chain_at_floor(active_set: &ActiveSet) -> bool {
    use crate::tier::SecurityTier;
    matches!(active_set.tier(), Some(SecurityTier::Tier1))
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::active_set::ActiveSet;
    use crate::commit_wave::elect_anchor;
    use crate::epoch::{EpochNumber, RoundNumber};
    use crate::identity::{ValidatorId, ValidatorPublicKeys};
    use crate::schedule::quorum_threshold;
    use crate::vertex::{Vertex, VertexBuilder, VertexSignature, BLS_SIGNATURE_BYTES};
    use crate::vrf::VRF_RANDOMNESS_BYTES;

    // ---- Fixtures (mirrors commit_wave + dag test helpers) ----

    fn validator_pubkeys(seed: u8) -> ValidatorPublicKeys {
        ValidatorPublicKeys::new([seed; 32], [seed; 1952], [seed; 96])
    }

    fn validator_id(seed: u8) -> ValidatorId {
        validator_pubkeys(seed).derive_id()
    }

    fn fixture_active_set(n: u8) -> ActiveSet {
        let mut set = ActiveSet::new();
        for seed in 1..=n {
            set.register(validator_id(seed), EpochNumber::default())
                .expect("register");
        }
        set
    }

    fn make_genesis_vertex(author_seed: u8) -> Vertex {
        VertexBuilder::new(validator_id(author_seed), RoundNumber::default())
            .with_signature(VertexSignature::from_bytes([0u8; BLS_SIGNATURE_BYTES]))
            .build()
    }

    fn make_vertex(author_seed: u8, round: u64, parents: Vec<VertexId>) -> Vertex {
        VertexBuilder::new(validator_id(author_seed), RoundNumber::new(round))
            .with_parents(parents)
            .with_signature(VertexSignature::from_bytes([0u8; BLS_SIGNATURE_BYTES]))
            .build()
    }

    fn populate_round(
        dag: &mut DagState,
        active: &ActiveSet,
        n: u8,
        round: u64,
        parents: &[VertexId],
    ) -> Vec<VertexId> {
        let mut ids = Vec::new();
        for seed in 1..=n {
            let v = if round == 0 {
                make_genesis_vertex(seed)
            } else {
                make_vertex(seed, round, parents.to_vec())
            };
            let id = v.id();
            dag.insert(v, active).expect("insert");
            ids.push(id);
        }
        ids
    }

    /// Build a fully-populated DAG through `last_round` rounds.
    /// Each non-genesis vertex references the first
    /// `quorum_threshold(n)` vertices of the previous round.
    fn populated_dag(n: u8, last_round: u64) -> (DagState, ActiveSet, Vec<Vec<VertexId>>) {
        let active = fixture_active_set(n);
        let mut dag = DagState::new();
        let mut rounds: Vec<Vec<VertexId>> = Vec::new();
        let r0 = populate_round(&mut dag, &active, n, 0, &[]);
        rounds.push(r0);
        for r in 1..=last_round {
            let prev = usize::try_from(r - 1).expect("round index fits in usize");
            let quorum = quorum_threshold(usize::from(n));
            let parents = rounds[prev][..quorum].to_vec();
            let ids = populate_round(&mut dag, &active, n, r, &parents);
            rounds.push(ids);
        }
        (dag, active, rounds)
    }

    // ---- CommitSequencer basics ----

    #[test]
    fn new_sequencer_is_empty() {
        let seq = CommitSequencer::launch();
        assert_eq!(seq.committed_count(), 0);
        assert_eq!(seq.recorded_waves(), 0);
        assert_eq!(seq.undecided_waves(), 0);
        assert!(seq.outcome(WaveIndex::ZERO).is_none());
    }

    #[test]
    fn schedule_accessor_returns_supplied_schedule() {
        let seq = CommitSequencer::launch();
        assert_eq!(seq.schedule().period_rounds, 4);
    }

    #[test]
    fn committed_set_starts_empty() {
        let seq = CommitSequencer::launch();
        assert!(seq.committed_set().is_empty());
    }

    // ---- record_decision: Pending ----

    #[test]
    fn record_pending_inserts_undecided() {
        let (dag, _active, rounds) = populated_dag(7, 3);
        let anchor = rounds[3][0];
        let mut seq = CommitSequencer::launch();
        seq.record_decision(&dag, WaveIndex::ZERO, anchor, CommitDecision::Pending)
            .expect("record");
        match seq.outcome(WaveIndex::ZERO) {
            Some(WaveOutcome::Undecided { anchor: a }) => assert_eq!(*a, anchor),
            other => panic!("expected Undecided, got {other:?}"),
        }
        assert_eq!(seq.undecided_waves(), 1);
        assert_eq!(seq.committed_count(), 0);
    }

    #[test]
    fn record_pending_twice_with_same_anchor_is_idempotent() {
        let (dag, _active, rounds) = populated_dag(7, 3);
        let anchor = rounds[3][0];
        let mut seq = CommitSequencer::launch();
        seq.record_decision(&dag, WaveIndex::ZERO, anchor, CommitDecision::Pending)
            .expect("first");
        seq.record_decision(&dag, WaveIndex::ZERO, anchor, CommitDecision::Pending)
            .expect("idempotent re-record");
        assert_eq!(seq.recorded_waves(), 1);
    }

    #[test]
    fn record_pending_with_different_anchor_errors() {
        let (dag, _active, rounds) = populated_dag(7, 3);
        let a1 = rounds[3][0];
        let a2 = rounds[3][1];
        let mut seq = CommitSequencer::launch();
        seq.record_decision(&dag, WaveIndex::ZERO, a1, CommitDecision::Pending)
            .expect("first");
        let err = seq
            .record_decision(&dag, WaveIndex::ZERO, a2, CommitDecision::Pending)
            .expect_err("anchor mismatch");
        match err {
            SequencerError::AnchorMismatch {
                wave,
                existing,
                supplied,
            } => {
                assert_eq!(wave, WaveIndex::ZERO);
                assert_eq!(existing, a1);
                assert_eq!(supplied, a2);
            }
            SequencerError::AlreadyResolved { .. } => {
                panic!("expected AnchorMismatch, got AlreadyResolved")
            }
        }
    }

    // ---- record_decision: Skipped ----

    #[test]
    fn record_skipped_inserts_skipped() {
        let (dag, _active, rounds) = populated_dag(7, 3);
        let anchor = rounds[3][6]; // unreferenced
        let mut seq = CommitSequencer::launch();
        seq.record_decision(&dag, WaveIndex::ZERO, anchor, CommitDecision::Skipped)
            .expect("record");
        match seq.outcome(WaveIndex::ZERO) {
            Some(WaveOutcome::Skipped { anchor: a }) => assert_eq!(*a, anchor),
            other => panic!("expected Skipped, got {other:?}"),
        }
        assert_eq!(seq.committed_count(), 0);
    }

    #[test]
    fn skipped_does_not_propagate_to_earlier_undecided() {
        // Wave 0 Undecided, wave 1 Skipped → wave 0 stays Undecided.
        let (dag, _active, rounds) = populated_dag(7, 7);
        let a0 = rounds[3][0];
        let a1 = rounds[7][6]; // round-7 unreferenced
        let mut seq = CommitSequencer::launch();
        seq.record_decision(&dag, WaveIndex::ZERO, a0, CommitDecision::Pending)
            .expect("w0 pending");
        seq.record_decision(&dag, WaveIndex::new(1), a1, CommitDecision::Skipped)
            .expect("w1 skipped");
        // Wave 0 still Undecided.
        match seq.outcome(WaveIndex::ZERO) {
            Some(WaveOutcome::Undecided { .. }) => {}
            other => panic!("expected wave 0 Undecided, got {other:?}"),
        }
        // Wave 1 Skipped.
        match seq.outcome(WaveIndex::new(1)) {
            Some(WaveOutcome::Skipped { .. }) => {}
            other => panic!("expected wave 1 Skipped, got {other:?}"),
        }
    }

    // ---- record_decision: Committed (direct) ----

    #[test]
    fn record_committed_inserts_committed_and_extends_set() {
        let (dag, _active, rounds) = populated_dag(7, 3);
        let anchor = rounds[3][0];
        let mut seq = CommitSequencer::launch();
        seq.record_decision(&dag, WaveIndex::ZERO, anchor, CommitDecision::Committed)
            .expect("record");
        let outcome = seq.outcome(WaveIndex::ZERO).expect("present");
        match outcome {
            WaveOutcome::Committed { anchor: a, ordered } => {
                assert_eq!(*a, anchor);
                assert!(!ordered.is_empty());
                // Last in ordered is the anchor.
                assert_eq!(*ordered.last().expect("non-empty"), anchor);
            }
            other => panic!("expected Committed, got {other:?}"),
        }
        // committed_set non-empty.
        assert!(seq.committed_count() > 0);
        assert!(seq.is_committed(&anchor));
    }

    #[test]
    fn record_already_committed_wave_errors() {
        let (dag, _active, rounds) = populated_dag(7, 3);
        let anchor = rounds[3][0];
        let mut seq = CommitSequencer::launch();
        seq.record_decision(&dag, WaveIndex::ZERO, anchor, CommitDecision::Committed)
            .expect("first");
        let err = seq
            .record_decision(&dag, WaveIndex::ZERO, anchor, CommitDecision::Committed)
            .expect_err("already resolved");
        match err {
            SequencerError::AlreadyResolved { wave } => {
                assert_eq!(wave, WaveIndex::ZERO);
            }
            SequencerError::AnchorMismatch { .. } => {
                panic!("expected AlreadyResolved, got AnchorMismatch")
            }
        }
    }

    #[test]
    fn record_already_skipped_wave_errors() {
        let (dag, _active, rounds) = populated_dag(7, 3);
        let anchor = rounds[3][0];
        let mut seq = CommitSequencer::launch();
        seq.record_decision(&dag, WaveIndex::ZERO, anchor, CommitDecision::Skipped)
            .expect("first");
        let err = seq
            .record_decision(&dag, WaveIndex::ZERO, anchor, CommitDecision::Skipped)
            .expect_err("already resolved");
        assert!(matches!(err, SequencerError::AlreadyResolved { .. }));
    }

    // ---- Indirect commit rule ----

    #[test]
    fn indirect_commit_pulls_forward_earlier_undecided() {
        // Wave 0 anchor at round 3 (first round-3 vertex —
        // referenced by all later rounds).
        // Wave 1 anchor at round 7 (first round-7 vertex —
        // reaches r3[0] via causal chain).
        let (dag, _active, rounds) = populated_dag(7, 9);
        let a0 = rounds[3][0];
        let a1 = rounds[7][0];
        assert!(dag.reaches(&a1, &a0), "a1 must reach a0 for this test");

        let mut seq = CommitSequencer::launch();
        seq.record_decision(&dag, WaveIndex::ZERO, a0, CommitDecision::Pending)
            .expect("w0 pending");
        seq.record_decision(&dag, WaveIndex::new(1), a1, CommitDecision::Committed)
            .expect("w1 committed");

        // Wave 0 indirectly committed.
        match seq.outcome(WaveIndex::ZERO) {
            Some(WaveOutcome::Committed { anchor: a, .. }) => assert_eq!(*a, a0),
            other => panic!("expected wave 0 Committed, got {other:?}"),
        }
        // Wave 1 directly committed.
        match seq.outcome(WaveIndex::new(1)) {
            Some(WaveOutcome::Committed { anchor: a, .. }) => assert_eq!(*a, a1),
            other => panic!("expected wave 1 Committed, got {other:?}"),
        }
        // Both anchors in committed_set.
        assert!(seq.is_committed(&a0));
        assert!(seq.is_committed(&a1));
    }

    #[test]
    fn indirect_skip_when_later_committed_anchor_does_not_reach() {
        // Wave 0 anchor: unreferenced round-3 vertex (last).
        // Wave 1 anchor: referenced round-7 vertex.
        // a1 does NOT reach a0 → wave 0 indirect-skipped.
        let (dag, _active, rounds) = populated_dag(7, 9);
        let a0 = rounds[3][6]; // unreferenced
        let a1 = rounds[7][0]; // referenced
        assert!(!dag.reaches(&a1, &a0), "a1 must NOT reach a0");

        let mut seq = CommitSequencer::launch();
        seq.record_decision(&dag, WaveIndex::ZERO, a0, CommitDecision::Pending)
            .expect("w0 pending");
        seq.record_decision(&dag, WaveIndex::new(1), a1, CommitDecision::Committed)
            .expect("w1 committed");

        match seq.outcome(WaveIndex::ZERO) {
            Some(WaveOutcome::Skipped { anchor: a }) => assert_eq!(*a, a0),
            other => panic!("expected wave 0 Skipped, got {other:?}"),
        }
        assert!(!seq.is_committed(&a0));
        assert!(seq.is_committed(&a1));
    }

    #[test]
    fn consecutive_undecided_stay_undecided() {
        let (dag, _active, rounds) = populated_dag(7, 9);
        let a0 = rounds[3][0];
        let a1 = rounds[7][0];
        let mut seq = CommitSequencer::launch();
        seq.record_decision(&dag, WaveIndex::ZERO, a0, CommitDecision::Pending)
            .expect("w0 pending");
        seq.record_decision(&dag, WaveIndex::new(1), a1, CommitDecision::Pending)
            .expect("w1 pending");
        assert_eq!(seq.undecided_waves(), 2);
        assert_eq!(seq.committed_count(), 0);
    }

    #[test]
    fn indirect_commit_resolves_multiple_earlier_waves() {
        // Wave 0, 1 both Undecided; wave 2 directly commits and
        // reaches both earlier anchors → both indirect-committed.
        let (dag, _active, rounds) = populated_dag(7, 11);
        let a0 = rounds[3][0];
        let a1 = rounds[7][0];
        let a2 = rounds[11][0];
        assert!(dag.reaches(&a2, &a0));
        assert!(dag.reaches(&a2, &a1));

        let mut seq = CommitSequencer::launch();
        seq.record_decision(&dag, WaveIndex::ZERO, a0, CommitDecision::Pending)
            .expect("w0");
        seq.record_decision(&dag, WaveIndex::new(1), a1, CommitDecision::Pending)
            .expect("w1");
        seq.record_decision(&dag, WaveIndex::new(2), a2, CommitDecision::Committed)
            .expect("w2");

        for w in 0..3 {
            match seq.outcome(WaveIndex::new(w)) {
                Some(WaveOutcome::Committed { .. }) => {}
                other => panic!("expected wave {w} Committed, got {other:?}"),
            }
        }
        assert!(seq.is_committed(&a0));
        assert!(seq.is_committed(&a1));
        assert!(seq.is_committed(&a2));
    }

    #[test]
    fn indirect_commit_mixed_reach_resolves_each_appropriately() {
        // Wave 0 anchor referenced; wave 1 anchor unreferenced;
        // wave 2 directly commits and reaches a0 but not a1.
        // → wave 0 indirect-Committed; wave 1 indirect-Skipped.
        let (dag, _active, rounds) = populated_dag(7, 11);
        let a0 = rounds[3][0];
        let a1 = rounds[7][6]; // unreferenced
        let a2 = rounds[11][0];
        assert!(dag.reaches(&a2, &a0));
        assert!(!dag.reaches(&a2, &a1));

        let mut seq = CommitSequencer::launch();
        seq.record_decision(&dag, WaveIndex::ZERO, a0, CommitDecision::Pending)
            .expect("w0");
        seq.record_decision(&dag, WaveIndex::new(1), a1, CommitDecision::Pending)
            .expect("w1");
        seq.record_decision(&dag, WaveIndex::new(2), a2, CommitDecision::Committed)
            .expect("w2");

        assert!(matches!(
            seq.outcome(WaveIndex::ZERO),
            Some(WaveOutcome::Committed { .. })
        ));
        assert!(matches!(
            seq.outcome(WaveIndex::new(1)),
            Some(WaveOutcome::Skipped { .. })
        ));
        assert!(matches!(
            seq.outcome(WaveIndex::new(2)),
            Some(WaveOutcome::Committed { .. })
        ));
    }

    // ---- §8.7 safety invariants ----

    #[test]
    fn no_double_commit_across_waves() {
        // Property: across multiple wave commits, no vertex
        // appears in two different waves' ordered lists.
        // This is the consensus-level expression of §8.7 Theorem 1.
        let (dag, _active, rounds) = populated_dag(7, 11);
        let a0 = rounds[3][0];
        let a1 = rounds[7][0];
        let a2 = rounds[11][0];
        let mut seq = CommitSequencer::launch();
        seq.record_decision(&dag, WaveIndex::ZERO, a0, CommitDecision::Committed)
            .expect("w0");
        seq.record_decision(&dag, WaveIndex::new(1), a1, CommitDecision::Committed)
            .expect("w1");
        seq.record_decision(&dag, WaveIndex::new(2), a2, CommitDecision::Committed)
            .expect("w2");

        let mut seen: HashSet<VertexId> = HashSet::new();
        for (_w, outcome) in seq.outcomes() {
            if let WaveOutcome::Committed { ordered, .. } = outcome {
                for id in ordered {
                    assert!(
                        seen.insert(*id),
                        "vertex {id:?} appears in two committed wave outcomes"
                    );
                }
            }
        }
        // committed_set matches union of ordered lists.
        assert_eq!(seen.len(), seq.committed_count());
    }

    #[test]
    fn chronological_commit_order_preserved_under_indirect_resolution() {
        // When wave 2 commits and pulls forward waves 0 + 1,
        // the order of commit_order computations must be
        // chronological: wave 0 first, then wave 1, then wave 2.
        // This means wave 0's ordered closure includes vertices
        // wave 1 and wave 2 don't; wave 1's includes only what
        // wasn't in wave 0; etc.
        let (dag, _active, rounds) = populated_dag(7, 11);
        let a0 = rounds[3][0];
        let a1 = rounds[7][0];
        let a2 = rounds[11][0];

        let mut seq = CommitSequencer::launch();
        seq.record_decision(&dag, WaveIndex::ZERO, a0, CommitDecision::Pending)
            .expect("w0");
        seq.record_decision(&dag, WaveIndex::new(1), a1, CommitDecision::Pending)
            .expect("w1");
        seq.record_decision(&dag, WaveIndex::new(2), a2, CommitDecision::Committed)
            .expect("w2 + indirect-resolves w0 + w1");

        let mut o0 = Vec::new();
        let mut o1 = Vec::new();
        let mut o2 = Vec::new();
        for (w, outcome) in seq.outcomes() {
            if let WaveOutcome::Committed { ordered, .. } = outcome {
                match w.as_u64() {
                    0 => o0.clone_from(ordered),
                    1 => o1.clone_from(ordered),
                    2 => o2.clone_from(ordered),
                    _ => {}
                }
            }
        }
        // Wave 0 ordered ends with a0.
        assert_eq!(*o0.last().expect("non-empty"), a0);
        // Wave 1 ordered ends with a1.
        assert_eq!(*o1.last().expect("non-empty"), a1);
        // Wave 2 ordered ends with a2.
        assert_eq!(*o2.last().expect("non-empty"), a2);
        // Partition: no overlap.
        let s0: HashSet<VertexId> = o0.iter().copied().collect();
        let s1: HashSet<VertexId> = o1.iter().copied().collect();
        let s2: HashSet<VertexId> = o2.iter().copied().collect();
        assert!(s0.is_disjoint(&s1));
        assert!(s1.is_disjoint(&s2));
        assert!(s0.is_disjoint(&s2));
    }

    #[test]
    fn deterministic_across_invocations() {
        // Property: the same sequence of (DAG, wave, anchor,
        // decision) inputs produces identical sequencer state.
        // This is the §8.7 safety convergence property.
        let (dag, _active, rounds) = populated_dag(7, 11);
        let a0 = rounds[3][0];
        let a1 = rounds[7][0];
        let a2 = rounds[11][0];

        let mut s1 = CommitSequencer::launch();
        s1.record_decision(&dag, WaveIndex::ZERO, a0, CommitDecision::Pending)
            .expect("s1 w0");
        s1.record_decision(&dag, WaveIndex::new(1), a1, CommitDecision::Pending)
            .expect("s1 w1");
        s1.record_decision(&dag, WaveIndex::new(2), a2, CommitDecision::Committed)
            .expect("s1 w2");

        let mut s2 = CommitSequencer::launch();
        s2.record_decision(&dag, WaveIndex::ZERO, a0, CommitDecision::Pending)
            .expect("s2 w0");
        s2.record_decision(&dag, WaveIndex::new(1), a1, CommitDecision::Pending)
            .expect("s2 w1");
        s2.record_decision(&dag, WaveIndex::new(2), a2, CommitDecision::Committed)
            .expect("s2 w2");

        assert_eq!(s1.committed_count(), s2.committed_count());
        for w in 0..3 {
            assert_eq!(s1.outcome(WaveIndex::new(w)), s2.outcome(WaveIndex::new(w)));
        }
    }

    // ---- Halt detection ----

    #[test]
    fn is_chain_dormant_returns_true_below_floor() {
        // Active set of 6 — below ACTIVE_SET_FLOOR = 7.
        let active = fixture_active_set(6);
        assert!(is_chain_dormant(&active));
    }

    #[test]
    fn is_chain_dormant_returns_false_at_or_above_floor() {
        let active7 = fixture_active_set(7);
        let active15 = fixture_active_set(15);
        let active30 = fixture_active_set(30);
        assert!(!is_chain_dormant(&active7));
        assert!(!is_chain_dormant(&active15));
        assert!(!is_chain_dormant(&active30));
    }

    #[test]
    fn is_chain_at_floor_returns_true_in_tier_i_range() {
        // Tier I range per §8.1.7: N ∈ [7, 14].
        for n in 7u8..=14 {
            let active = fixture_active_set(n);
            assert!(
                is_chain_at_floor(&active),
                "N={n} should be at-floor (Tier I)"
            );
        }
    }

    #[test]
    fn is_chain_at_floor_returns_false_outside_tier_i_range() {
        // Below floor (dormant; no tier) → false.
        let active6 = fixture_active_set(6);
        assert!(!is_chain_at_floor(&active6));
        // Tier II (N=15-29) → false.
        let active15 = fixture_active_set(15);
        let active29 = fixture_active_set(29);
        assert!(!is_chain_at_floor(&active15));
        assert!(!is_chain_at_floor(&active29));
        // Tier III (N=30+) → false.
        let active30 = fixture_active_set(30);
        assert!(!is_chain_at_floor(&active30));
    }

    // ---- SequencerError ----

    #[test]
    fn sequencer_error_display_messages_are_distinct() {
        let v1 = SequencerError::AlreadyResolved {
            wave: WaveIndex::ZERO,
        };
        let v2 = SequencerError::AnchorMismatch {
            wave: WaveIndex::ZERO,
            existing: VertexId::from_bytes([0u8; 32]),
            supplied: VertexId::from_bytes([1u8; 32]),
        };
        let m1 = v1.to_string();
        let m2 = v2.to_string();
        assert!(!m1.is_empty());
        assert!(!m2.is_empty());
        assert_ne!(m1, m2);
    }

    #[test]
    fn sequencer_error_implements_std_error() {
        fn assert_err<E: std::error::Error>() {}
        assert_err::<SequencerError>();
    }

    // ---- BCS round-trips ----

    #[test]
    fn wave_outcome_bcs_round_trip() {
        let outcomes = vec![
            WaveOutcome::Committed {
                anchor: VertexId::from_bytes([1u8; 32]),
                ordered: vec![
                    VertexId::from_bytes([2u8; 32]),
                    VertexId::from_bytes([3u8; 32]),
                ],
            },
            WaveOutcome::Skipped {
                anchor: VertexId::from_bytes([4u8; 32]),
            },
            WaveOutcome::Undecided {
                anchor: VertexId::from_bytes([5u8; 32]),
            },
        ];
        for o in &outcomes {
            let bytes = bcs::to_bytes(o).expect("encode");
            let decoded: WaveOutcome = bcs::from_bytes(&bytes).expect("decode");
            assert_eq!(*o, decoded);
        }
    }

    /// Pin the BCS variant tag for each [`WaveOutcome`] variant.
    /// Reordering the enum variants would change the leading
    /// byte of the BCS encoding — a consensus-binding change
    /// for any chain-state commitment that includes wave
    /// outcomes. Reordering is a hard fork.
    #[test]
    fn wave_outcome_bcs_variant_tags_pinned() {
        let anchor = VertexId::from_bytes([0u8; 32]);
        // Committed = variant 0
        let committed = WaveOutcome::Committed {
            anchor,
            ordered: vec![],
        };
        let bytes = bcs::to_bytes(&committed).expect("encode");
        assert_eq!(bytes[0], 0x00, "WaveOutcome::Committed variant tag");

        // Skipped = variant 1
        let skipped = WaveOutcome::Skipped { anchor };
        let bytes = bcs::to_bytes(&skipped).expect("encode");
        assert_eq!(bytes[0], 0x01, "WaveOutcome::Skipped variant tag");

        // Undecided = variant 2
        let undecided = WaveOutcome::Undecided { anchor };
        let bytes = bcs::to_bytes(&undecided).expect("encode");
        assert_eq!(bytes[0], 0x02, "WaveOutcome::Undecided variant tag");
    }

    // ---- Cross-pipeline integration ----

    #[test]
    fn elect_then_sequence_pipeline() {
        // Full pipeline: elect anchor → record_decision →
        // committed_set evolves.
        let (dag, _active, _rounds) = populated_dag(7, 5);
        let randomness = [0xa1u8; VRF_RANDOMNESS_BYTES];
        let anchor = elect_anchor(&dag, RoundNumber::new(3), &randomness).expect("anchor elected");
        let mut seq = CommitSequencer::launch();
        // Suppose the direct decision lands as Committed —
        // record it and verify the sequencer's invariants hold.
        seq.record_decision(&dag, WaveIndex::ZERO, anchor, CommitDecision::Committed)
            .expect("record");
        assert!(seq.is_committed(&anchor));
        assert!(seq.committed_count() > 0);
        // Re-recording is rejected.
        let err = seq
            .record_decision(&dag, WaveIndex::ZERO, anchor, CommitDecision::Committed)
            .expect_err("double-record");
        assert!(matches!(err, SequencerError::AlreadyResolved { .. }));
    }
}
