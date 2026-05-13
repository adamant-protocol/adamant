//! Local mempool per whitepaper §9.7.
//!
//! Phase 7.8.4 deliverable — the per-validator local mempool
//! data structure plus the Phase 7.8.2 anti-DoS gating wired
//! into the insertion path per §9.5.4 ("cryptographic
//! verification before propagation").
//!
//! # §9.7 spec posture
//!
//! Per §9.7 the mempool is:
//! - A priority queue ranked by **(fee tip DESC, submission
//!   time ASC)** per §9.7's three-criterion ordering. The
//!   third criterion ("encrypted vs transparent") is
//!   deliberately a no-op — encryption MUST NOT affect mempool
//!   priority per §9.7.
//! - Capped at ~100,000 entries per §9.7.1. When at capacity,
//!   the lowest-priority entry is evicted to make room for a
//!   higher-priority arrival; a lower-priority arrival at
//!   capacity is rejected outright.
//!
//! Per §9.7.2 the mempool is **per-validator local** — there
//! is no protocol-level mempool synchronisation. Validators
//! observe the gossipsub stream independently and decide
//! which transactions to retain. Consensus does not require
//! mempool agreement; the §8 DAG-BFT consensus core only
//! requires agreement on which transactions appear in
//! committed vertices.
//!
//! **The mempool is therefore NOT a consensus-critical
//! structure.** Its API can evolve freely; reordering fields
//! or renaming variants is a non-hard-fork operational
//! refinement (unlike the §8.3.1 vertex format or the §9.3.1
//! transaction wire shape, both of which are wire-pinned).
//!
//! # TTL semantics
//!
//! Per [`NetworkTransaction::expiration_round`], transactions
//! become invalid after a specified round. The mempool prunes
//! expired entries **lazily** — on `insert` and on
//! `pop_highest` calls, expired entries are dropped from the
//! head of the priority queue before the operation proceeds.
//! Callers supply the current round; the mempool itself does
//! not reach into chain state.
//!
//! # Anti-DoS gating
//!
//! [`Mempool::validate_and_insert`] orchestrates the §9.5
//! anti-DoS pipeline against a candidate submission before
//! admitting it to the mempool. The pipeline runs the Phase
//! 7.8.2 [`validate_submission`](crate::anti_dos::validate_submission)
//! function — submission-proof verification + fee-floor check
//! — then enforces the TTL + capacity rules.
//!
//! Per §9.5.4 the protocol also requires cryptographic
//! verification of the underlying transaction's signature
//! and proofs before propagation. **That check crosses into
//! the §6 execution layer** (the AVM transaction format) and
//! is wired through Phase 7.11 integration; Phase 7.8.4 ships
//! the §9.5.1/2 + §9.7 layers only.

use std::cmp::Reverse;
use std::collections::BTreeMap;

use adamant_consensus::RoundNumber;

use crate::anti_dos::{self, AntiDosError, FeeFloor};
use crate::NetworkTransaction;

/// Maximum mempool capacity per whitepaper §9.7.1. Operators
/// MAY tune this downward for resource-constrained validators
/// (consensus does not depend on mempool agreement per §9.7.2),
/// but the default matches the spec text's "~100,000 pending
/// transactions" guideline.
pub const DEFAULT_MEMPOOL_CAPACITY: usize = 100_000;

/// Outcome of an [`Mempool::insert`] / [`Mempool::validate_and_insert`]
/// call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InsertOutcome {
    /// The transaction was admitted; the mempool had room.
    Inserted,

    /// The transaction was admitted; the lowest-priority
    /// existing entry was evicted to make room (the mempool
    /// was at capacity). The evicted transaction is returned
    /// for caller-side bookkeeping / logging.
    InsertedWithEviction(Box<NetworkTransaction>),

    /// The transaction was rejected: the mempool was at
    /// capacity AND the candidate had lower priority than
    /// the lowest-priority existing entry. The mempool is
    /// unchanged.
    RejectedAsLowerPriority,

    /// The transaction was rejected: its `expiration_round`
    /// was already past the supplied current round. The
    /// mempool is unchanged.
    RejectedAsExpired,
}

/// Typed errors produced by [`Mempool::validate_and_insert`].
///
/// Wraps [`AntiDosError`] for the §9.5 anti-DoS rejection
/// paths; the mempool-specific outcomes (capacity, TTL) are
/// expressed as [`InsertOutcome`] return values rather than
/// errors because they aren't anomalous conditions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MempoolError {
    /// §9.5 anti-DoS verification failed for the submission.
    AntiDos(AntiDosError),
}

impl core::fmt::Display for MempoolError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::AntiDos(e) => write!(f, "mempool anti-DoS check failed: {e}"),
        }
    }
}

impl std::error::Error for MempoolError {}

impl From<AntiDosError> for MempoolError {
    fn from(e: AntiDosError) -> Self {
        Self::AntiDos(e)
    }
}

/// Priority key for the mempool's `BTreeMap` ordering. Sorts:
/// 1. Higher `fee_tip` first (via `Reverse`).
/// 2. Among equal-tip entries, earlier `arrival_seq` first.
///
/// `arrival_seq` is a per-mempool monotonic counter populated
/// at insertion time. It approximates §9.7's "submission
/// time" criterion using a strictly-monotonic local proxy —
/// this is intentional: relying on submitter-supplied
/// timestamps would create a manipulation vector (any
/// validator could backdate their preferred transactions).
/// Local arrival order is the honest proxy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct PriorityKey {
    fee_tip_desc: Reverse<u64>,
    arrival_seq: u64,
}

/// Per-entry record stored inside the mempool. Carries the
/// transaction plus its expiration round (denormalised from
/// `tx.expiration_round` for TTL-pruning convenience).
#[derive(Debug, Clone)]
struct MempoolEntry {
    tx: NetworkTransaction,
    expiration_round: RoundNumber,
}

/// Per-validator local mempool per whitepaper §9.7.
///
/// Priority queue with eviction; ranks by (`fee_tip` DESC,
/// `arrival_seq` ASC). At capacity, lower-priority insertions
/// are rejected; equal-or-higher-priority insertions evict
/// the lowest-priority entry.
///
/// **Not consensus-critical.** Two validators may have
/// disjoint mempools at any given moment per §9.7.2.
#[derive(Debug, Clone)]
pub struct Mempool {
    capacity: usize,
    next_seq: u64,
    entries: BTreeMap<PriorityKey, MempoolEntry>,
}

impl Mempool {
    /// New mempool with [`DEFAULT_MEMPOOL_CAPACITY`].
    #[must_use]
    pub fn launch_default() -> Self {
        Self::with_capacity(DEFAULT_MEMPOOL_CAPACITY)
    }

    /// New mempool with the supplied capacity. A `capacity`
    /// of 0 is permitted (degenerate; every insert is
    /// rejected as lower-priority) but discouraged.
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            capacity,
            next_seq: 0,
            entries: BTreeMap::new(),
        }
    }

    /// The configured capacity.
    #[must_use]
    pub const fn capacity(&self) -> usize {
        self.capacity
    }

    /// Number of currently-held transactions (including any
    /// expired-but-not-yet-pruned entries; expiration is
    /// lazily applied on next access).
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the mempool currently holds zero entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Insert a transaction with no anti-DoS validation. For
    /// callers that have already validated (e.g., trusted-
    /// path test fixtures) or for tests of the
    /// priority/eviction logic itself. Production callers
    /// should use [`Self::validate_and_insert`].
    ///
    /// # Panics
    ///
    /// Cannot panic in practice. The internal
    /// `expect("tail key exists; just observed")` at the
    /// eviction path is guarded by the immediately-preceding
    /// `let Some((tail_key, _)) = self.entries.iter().next_back()`
    /// pattern — the key is present in the map at the time
    /// of the lookup.
    pub fn insert(&mut self, tx: NetworkTransaction, current_round: RoundNumber) -> InsertOutcome {
        if tx.expiration_round.as_u64() < current_round.as_u64() {
            return InsertOutcome::RejectedAsExpired;
        }
        self.prune_expired(current_round);

        let fee_tip = tx.fee_tip;
        let expiration_round = tx.expiration_round;
        let key = PriorityKey {
            fee_tip_desc: Reverse(fee_tip),
            arrival_seq: self.next_seq,
        };
        self.next_seq = self.next_seq.saturating_add(1);
        let entry = MempoolEntry {
            tx,
            expiration_round,
        };

        if self.entries.len() < self.capacity {
            self.entries.insert(key, entry);
            return InsertOutcome::Inserted;
        }

        // At capacity. Find the lowest-priority entry (the
        // tail of the BTreeMap iteration order). If the
        // candidate's priority is strictly higher, evict the
        // tail and insert.
        let Some((tail_key, _)) = self.entries.iter().next_back() else {
            // Capacity is 0; the previous block returned
            // Inserted only if entries.len() < capacity (=0),
            // which is impossible. Reject.
            return InsertOutcome::RejectedAsLowerPriority;
        };
        if key < *tail_key {
            // candidate has lower-key (= higher priority); evict tail.
            let tail_key = *tail_key;
            let evicted = self
                .entries
                .remove(&tail_key)
                .expect("tail key exists; just observed");
            self.entries.insert(key, entry);
            InsertOutcome::InsertedWithEviction(Box::new(evicted.tx))
        } else {
            InsertOutcome::RejectedAsLowerPriority
        }
    }

    /// Validate the submission via the Phase 7.8.2 §9.5
    /// anti-DoS pipeline (submission proof + fee floor), then
    /// insert if valid.
    ///
    /// Per §9.5.4 the underlying transaction's signature and
    /// proofs must also be verified before propagation; that
    /// crosses into the §6 execution layer and is wired
    /// through Phase 7.11 integration. Phase 7.8.4's mempool
    /// orchestrates the §9.5.1/2 layers only.
    ///
    /// # Errors
    ///
    /// Returns [`MempoolError::AntiDos`] wrapping the
    /// underlying [`AntiDosError`] if anti-DoS validation
    /// fails. Returns `Ok(outcome)` with an
    /// [`InsertOutcome::RejectedAsExpired`] /
    /// [`InsertOutcome::RejectedAsLowerPriority`] for the
    /// mempool-level rejections (these are normal mempool
    /// outcomes, not error conditions).
    pub fn validate_and_insert(
        &mut self,
        tx: NetworkTransaction,
        fee_floor: &FeeFloor,
        min_difficulty: u8,
        current_round: RoundNumber,
    ) -> Result<InsertOutcome, MempoolError> {
        anti_dos::validate_submission(&tx, fee_floor, min_difficulty)?;
        Ok(self.insert(tx, current_round))
    }

    /// Pop the highest-priority non-expired transaction.
    /// Lazily prunes any expired entries encountered at the
    /// head.
    ///
    /// # Panics
    ///
    /// Cannot panic in practice. The internal
    /// `expect("key just observed")` is guarded by the
    /// `let key = *self.entries.keys().next()?` immediately
    /// preceding it — the key is present in the map at the
    /// time of the lookup.
    pub fn pop_highest(&mut self, current_round: RoundNumber) -> Option<NetworkTransaction> {
        loop {
            let key = *self.entries.keys().next()?;
            let entry = self.entries.remove(&key).expect("key just observed");
            if entry.expiration_round.as_u64() < current_round.as_u64() {
                // Expired; drop and continue.
                continue;
            }
            return Some(entry.tx);
        }
    }

    /// Peek at the highest-priority non-expired transaction
    /// without consuming it. Lazily prunes any expired
    /// entries encountered at the head.
    pub fn peek_highest(&mut self, current_round: RoundNumber) -> Option<&NetworkTransaction> {
        self.prune_expired_head(current_round);
        // BTreeMap iteration is ordered; the first key is
        // the highest-priority entry post-pruning.
        let (_, entry) = self.entries.iter().next()?;
        Some(&entry.tx)
    }

    /// Drop expired entries from the mempool in bulk. Useful
    /// for periodic cleanup ticks; the lazy in-place pruning
    /// in `insert` / `pop_highest` / `peek_highest` already
    /// handles individual operations correctly.
    pub fn prune_expired(&mut self, current_round: RoundNumber) -> usize {
        let mut removed = 0usize;
        self.entries.retain(|_, entry| {
            if entry.expiration_round.as_u64() < current_round.as_u64() {
                removed += 1;
                false
            } else {
                true
            }
        });
        removed
    }

    /// Internal helper: prune expired entries from the head
    /// of the priority order only. Used by `peek_highest` to
    /// avoid scanning the entire map.
    fn prune_expired_head(&mut self, current_round: RoundNumber) {
        while let Some((key, entry)) = self.entries.iter().next() {
            if entry.expiration_round.as_u64() < current_round.as_u64() {
                let key = *key;
                self.entries.remove(&key);
            } else {
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::SubmissionProof;
    use adamant_consensus::RoundNumber;

    fn fixture_tx(fee_tip: u64, expiration: u64) -> NetworkTransaction {
        NetworkTransaction::transparent(1, vec![0xCA, 0xFE], fee_tip, RoundNumber::new(expiration))
    }

    // ---- Constants ----

    #[test]
    fn default_capacity_pinned() {
        assert_eq!(DEFAULT_MEMPOOL_CAPACITY, 100_000);
    }

    // ---- Construction ----

    #[test]
    fn new_mempool_is_empty() {
        let mp = Mempool::launch_default();
        assert!(mp.is_empty());
        assert_eq!(mp.len(), 0);
        assert_eq!(mp.capacity(), DEFAULT_MEMPOOL_CAPACITY);
    }

    #[test]
    fn with_capacity_overrides_default() {
        let mp = Mempool::with_capacity(10);
        assert_eq!(mp.capacity(), 10);
    }

    // ---- Insert + priority ordering ----

    #[test]
    fn insert_returns_inserted_when_room_available() {
        let mut mp = Mempool::with_capacity(10);
        let outcome = mp.insert(fixture_tx(100, 1000), RoundNumber::default());
        assert_eq!(outcome, InsertOutcome::Inserted);
        assert_eq!(mp.len(), 1);
    }

    #[test]
    fn insert_expired_tx_is_rejected() {
        let mut mp = Mempool::with_capacity(10);
        let outcome = mp.insert(fixture_tx(100, 5), RoundNumber::new(10));
        assert_eq!(outcome, InsertOutcome::RejectedAsExpired);
        assert!(mp.is_empty());
    }

    #[test]
    fn higher_fee_tip_pops_first() {
        let mut mp = Mempool::with_capacity(10);
        mp.insert(fixture_tx(50, 1000), RoundNumber::default());
        mp.insert(fixture_tx(200, 1000), RoundNumber::default());
        mp.insert(fixture_tx(100, 1000), RoundNumber::default());
        // Pop order: 200, 100, 50.
        assert_eq!(mp.pop_highest(RoundNumber::default()).unwrap().fee_tip, 200);
        assert_eq!(mp.pop_highest(RoundNumber::default()).unwrap().fee_tip, 100);
        assert_eq!(mp.pop_highest(RoundNumber::default()).unwrap().fee_tip, 50);
        assert!(mp.pop_highest(RoundNumber::default()).is_none());
    }

    #[test]
    fn equal_fee_tip_breaks_tie_by_arrival_order() {
        let mut mp = Mempool::with_capacity(10);
        // All three have the same fee_tip; insertion order
        // determines pop order (earliest first).
        let mut tx_a = fixture_tx(100, 1000);
        tx_a.payload = vec![0xAA];
        let mut tx_b = fixture_tx(100, 1000);
        tx_b.payload = vec![0xBB];
        let mut tx_c = fixture_tx(100, 1000);
        tx_c.payload = vec![0xCC];
        mp.insert(tx_a, RoundNumber::default());
        mp.insert(tx_b, RoundNumber::default());
        mp.insert(tx_c, RoundNumber::default());
        assert_eq!(
            mp.pop_highest(RoundNumber::default()).unwrap().payload,
            vec![0xAA]
        );
        assert_eq!(
            mp.pop_highest(RoundNumber::default()).unwrap().payload,
            vec![0xBB]
        );
        assert_eq!(
            mp.pop_highest(RoundNumber::default()).unwrap().payload,
            vec![0xCC]
        );
    }

    // ---- Eviction at capacity ----

    #[test]
    fn at_capacity_higher_priority_evicts_lowest() {
        let mut mp = Mempool::with_capacity(2);
        mp.insert(fixture_tx(10, 1000), RoundNumber::default());
        mp.insert(fixture_tx(50, 1000), RoundNumber::default());
        // At capacity. Insert tx with fee 100 → evicts fee 10.
        let outcome = mp.insert(fixture_tx(100, 1000), RoundNumber::default());
        match outcome {
            InsertOutcome::InsertedWithEviction(evicted) => {
                assert_eq!(evicted.fee_tip, 10);
            }
            other => panic!("expected InsertedWithEviction, got {other:?}"),
        }
        assert_eq!(mp.len(), 2);
        // Pop order: 100, 50.
        assert_eq!(mp.pop_highest(RoundNumber::default()).unwrap().fee_tip, 100);
        assert_eq!(mp.pop_highest(RoundNumber::default()).unwrap().fee_tip, 50);
    }

    #[test]
    fn at_capacity_lower_priority_is_rejected() {
        let mut mp = Mempool::with_capacity(2);
        mp.insert(fixture_tx(50, 1000), RoundNumber::default());
        mp.insert(fixture_tx(100, 1000), RoundNumber::default());
        // At capacity. Insert tx with fee 10 → rejected.
        let outcome = mp.insert(fixture_tx(10, 1000), RoundNumber::default());
        assert_eq!(outcome, InsertOutcome::RejectedAsLowerPriority);
        assert_eq!(mp.len(), 2);
    }

    #[test]
    fn at_capacity_equal_priority_to_tail_is_rejected() {
        let mut mp = Mempool::with_capacity(2);
        // Two equal-fee entries; second one arrives later.
        mp.insert(fixture_tx(50, 1000), RoundNumber::default());
        mp.insert(fixture_tx(50, 1000), RoundNumber::default());
        // Third equal-fee arrival should be rejected (its
        // arrival_seq is strictly larger than the tail's, so
        // its priority is strictly lower).
        let outcome = mp.insert(fixture_tx(50, 1000), RoundNumber::default());
        assert_eq!(outcome, InsertOutcome::RejectedAsLowerPriority);
        assert_eq!(mp.len(), 2);
    }

    // ---- TTL / expiration ----

    #[test]
    fn pop_skips_expired_entries() {
        let mut mp = Mempool::with_capacity(10);
        // Insert at round 0; one expires at round 5, one at
        // round 100.
        mp.insert(fixture_tx(100, 5), RoundNumber::default());
        mp.insert(fixture_tx(50, 100), RoundNumber::default());
        // Now we're at round 50. The fee=100 tx is expired;
        // pop should return fee=50.
        let popped = mp.pop_highest(RoundNumber::new(50)).expect("non-empty");
        assert_eq!(popped.fee_tip, 50);
        assert!(mp.is_empty());
    }

    #[test]
    fn peek_skips_expired_entries() {
        let mut mp = Mempool::with_capacity(10);
        mp.insert(fixture_tx(100, 5), RoundNumber::default());
        mp.insert(fixture_tx(50, 100), RoundNumber::default());
        let peeked = mp.peek_highest(RoundNumber::new(50)).expect("non-empty");
        assert_eq!(peeked.fee_tip, 50);
        // peek didn't consume.
        assert_eq!(mp.len(), 1);
    }

    #[test]
    fn prune_expired_bulk_removes_all_past_expirations() {
        let mut mp = Mempool::with_capacity(10);
        mp.insert(fixture_tx(100, 5), RoundNumber::default());
        mp.insert(fixture_tx(50, 10), RoundNumber::default());
        mp.insert(fixture_tx(200, 100), RoundNumber::default());
        let removed = mp.prune_expired(RoundNumber::new(50));
        assert_eq!(removed, 2);
        assert_eq!(mp.len(), 1);
        let popped = mp.pop_highest(RoundNumber::new(50)).expect("non-empty");
        assert_eq!(popped.fee_tip, 200);
    }

    #[test]
    fn expiration_exactly_at_current_round_still_valid() {
        // Per spec: "round after which this tx is invalid".
        // Inclusive: at round == expiration, the tx is still
        // valid; at round > expiration, it's not.
        let mut mp = Mempool::with_capacity(10);
        mp.insert(fixture_tx(100, 50), RoundNumber::default());
        // At round 50, the tx is exactly at expiration → still valid.
        let popped = mp.pop_highest(RoundNumber::new(50));
        assert!(popped.is_some());
    }

    // ---- validate_and_insert (anti-DoS gating) ----

    #[test]
    fn validate_and_insert_rejects_missing_submission_proof() {
        let mut mp = Mempool::launch_default();
        let tx = fixture_tx(100, 1000); // no submission_proof
        let floor = FeeFloor::new(0);
        let err = mp
            .validate_and_insert(tx, &floor, 0, RoundNumber::default())
            .expect_err("must reject");
        assert!(matches!(err, MempoolError::AntiDos(_)));
        assert!(mp.is_empty());
    }

    #[test]
    fn validate_and_insert_admits_valid_submission() {
        let mut tx = fixture_tx(1_000_000, 1000); // ample fee tip
        let proof = crate::anti_dos::compute_submission_proof(&tx, 4, 10_000).expect("solve");
        tx = tx.with_submission_proof(proof);
        let mut mp = Mempool::launch_default();
        let floor = FeeFloor::new(0);
        let outcome = mp
            .validate_and_insert(tx, &floor, 4, RoundNumber::default())
            .expect("ok");
        assert_eq!(outcome, InsertOutcome::Inserted);
        assert_eq!(mp.len(), 1);
    }

    #[test]
    fn validate_and_insert_rejects_below_fee_floor() {
        let mut tx = fixture_tx(0, 1000);
        let proof = crate::anti_dos::compute_submission_proof(&tx, 4, 10_000).expect("solve");
        tx = tx.with_submission_proof(proof);
        let mut mp = Mempool::launch_default();
        let floor = FeeFloor::new(1_000_000);
        let err = mp
            .validate_and_insert(tx, &floor, 4, RoundNumber::default())
            .expect_err("must reject");
        assert!(matches!(err, MempoolError::AntiDos(_)));
    }

    // ---- Encrypted vs transparent has no priority effect ----

    #[test]
    fn encryption_mode_does_not_affect_priority() {
        // Per §9.7: "Encrypted transactions are propagated
        // identically to transparent ones; encryption does not
        // affect mempool priority. (This is a deliberate
        // choice...)"
        let mut mp = Mempool::with_capacity(10);
        let transparent_tx =
            NetworkTransaction::transparent(1, vec![0xAA], 100, RoundNumber::new(1000));
        let encrypted_tx = NetworkTransaction::encrypted(
            1,
            vec![0xBB; 50],
            100, // same fee_tip
            RoundNumber::new(1000),
        );
        mp.insert(transparent_tx.clone(), RoundNumber::default());
        mp.insert(encrypted_tx.clone(), RoundNumber::default());
        // The transparent tx arrived first; tie-break by
        // arrival order should put it first regardless of
        // encryption mode.
        let first = mp.pop_highest(RoundNumber::default()).expect("non-empty");
        assert_eq!(first.payload, transparent_tx.payload);
        let second = mp.pop_highest(RoundNumber::default()).expect("non-empty");
        assert_eq!(second.payload, encrypted_tx.payload);
    }

    // ---- MempoolError ----

    #[test]
    fn mempool_error_display_includes_inner_anti_dos_message() {
        let err = MempoolError::AntiDos(AntiDosError::MissingSubmissionProof);
        let msg = err.to_string();
        assert!(msg.contains("mempool"));
        assert!(msg.contains("submission proof"));
    }

    #[test]
    fn mempool_error_implements_std_error() {
        fn assert_err<E: std::error::Error>() {}
        assert_err::<MempoolError>();
    }

    #[test]
    fn mempool_error_from_anti_dos_error() {
        let err: MempoolError = AntiDosError::MissingSubmissionProof.into();
        assert!(matches!(err, MempoolError::AntiDos(_)));
    }

    // ---- Capacity 0 edge case ----

    #[test]
    fn zero_capacity_rejects_every_insert() {
        let mut mp = Mempool::with_capacity(0);
        let outcome = mp.insert(fixture_tx(100, 1000), RoundNumber::default());
        assert_eq!(outcome, InsertOutcome::RejectedAsLowerPriority);
        assert!(mp.is_empty());
    }

    // ---- SubmissionProof regression: the with_submission_proof
    //      builder doesn't accidentally change fee_tip / payload
    //      / etc., so the proof-bound hash matches the
    //      validation-time hash.

    #[test]
    fn with_submission_proof_does_not_disturb_other_fields() {
        let tx = fixture_tx(100, 1000);
        let original_fee = tx.fee_tip;
        let original_payload = tx.payload.clone();
        let original_expiration = tx.expiration_round;
        let proof = SubmissionProof::new(0xDEADu64, 4);
        let tx_with_proof = tx.with_submission_proof(proof);
        assert_eq!(tx_with_proof.fee_tip, original_fee);
        assert_eq!(tx_with_proof.payload, original_payload);
        assert_eq!(tx_with_proof.expiration_round, original_expiration);
        assert_eq!(tx_with_proof.submission_proof, Some(proof));
    }
}
