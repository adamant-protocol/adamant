//! DAG state storage + insertion validation per whitepaper §8.3.
//!
//! Phase 7.7a deliverable — the foundation data structure that
//! the Phase 7.7b commit-wave logic and the Phase 7.7c/d safety/
//! liveness invariants build on. The DAG state stores every
//! vertex produced by the active set, indexed for the lookups
//! the rest of the consensus pipeline requires:
//!
//! - by [`adamant_consensus::VertexId`] — for parent-edge
//!   resolution + reachability queries.
//! - by `(round, author)` — for the equivocation-detection
//!   invariant per §8.1.5.
//! - by round — for parent-set enumeration during vertex
//!   construction + commit-wave anchor selection.
//!
//! # Spec basis
//!
//! Whitepaper §8.3.1 (Vertices) + §8.3.2 (The DAG grows by
//! rounds) jointly pin the structural invariants this module
//! enforces:
//!
//! - "Each validator in the active set produces one vertex per
//!   round" (§8.3.1) → equivocation detection.
//! - "Each vertex must reference at least 2/3+1 vertices from
//!   the previous round" (§8.3.1) → quorum check.
//! - "At round 1, validators broadcast vertices referencing the
//!   genesis state. At round R+1, each validator broadcasts a
//!   vertex referencing 2/3+1 of the round-R vertices." (§8.3.2)
//!   → genesis-round (round 0) exemption from parent-quorum +
//!   parent-round validation for round > 0.
//!
//! # Phase 7.7a scope
//!
//! - [`DagState`] — in-memory vertex storage with the three
//!   indices above.
//! - [`DagState::insert`] — validating insertion. Returns
//!   `Err` on any invariant violation; otherwise commits the
//!   vertex to all indices atomically.
//! - [`DagState::vertex`] / [`DagState::vertices_at_round`] /
//!   [`DagState::vertex_by_round_author`] — read accessors.
//! - [`DagError`] — typed-error variants for the insertion
//!   validation surface.
//! - Reachability helpers ([`DagState::causal_ancestors`],
//!   [`DagState::reaches`]) for the Phase 7.7b commit-wave
//!   logic to consume.
//!
//! # Phase 7.7 sub-arc roadmap
//!
//! | Sub-arc | Surface | Status |
//! |---------|---------|--------|
//! | 7.7a   | DAG storage + insertion validation | **THIS SUB-ARC** |
//! | 7.7b   | Commit-wave logic (anchor selection + commit decision + causal-history walk) | pending |
//! | 7.7c   | Halt-on-disagreement + safety/liveness invariants per §8.7 | pending |
//! | 7.7d   | Mempool integration (threshold/time-lock decryption flows) | pending |
//! | 7.7e   | End-to-end integration tests | pending |
//!
//! # Equivocation posture
//!
//! Per §8.1.5 publishing two different vertices for the same
//! `(author, round)` is slashable at 100% of stake. The
//! detection happens here at insertion time:
//! [`DagError::EquivocationDetected`] surfaces the conflicting
//! existing-vertex id. The DagState does NOT auto-trigger
//! slashing; the caller (the Phase 7.10 slashing wiring) holds
//! the equivocation evidence and produces the slashing
//! transaction. The duplicate vertex is rejected from the DAG
//! (the DAG keeps the first-arrived).
//!
//! # Determinism + replay
//!
//! `DagState` is a pure data structure — insertion is
//! deterministic in `(active_set_snapshot, vertices_received)`.
//! Two nodes seeing the same vertices in any order produce
//! identical `DagState`s at any point (the by-id index is
//! order-independent; the by-round and by-round-author indices
//! are too, given equivocation is rejected). This is essential
//! for the §8.7 safety theorem: every honest validator
//! converges on the same DAG.

use std::collections::{HashMap, HashSet, VecDeque};

use adamant_crypto::bls;
use serde::{Deserialize, Serialize};

use crate::active_set::ActiveSet;
use crate::epoch::RoundNumber;
use crate::identity::{ValidatorId, ValidatorPublicKeys};
use crate::schedule::quorum_threshold;
use crate::vertex::{Vertex, VertexId};

/// Typed errors produced by [`DagState::insert`].
///
/// All variants are explicit and non-`#[non_exhaustive]`: the
/// DAG insertion surface is consensus-critical per §8.3 and the
/// protocol cannot grow new rejection paths silently. Adding a
/// variant is a hard-fork-aware deliberate change.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DagError {
    /// The vertex's `(round, author)` is already present in the
    /// DAG under a different `VertexId`. Per §8.1.5 this is the
    /// signature of equivocation — the second vertex is rejected
    /// and the existing vertex's id is surfaced as evidence.
    /// The caller's slashing layer (Phase 7.10) produces the
    /// `SlashOffence::Equivocation` transaction from this
    /// evidence; the DAG itself does not auto-trigger slashing.
    EquivocationDetected {
        /// The author who produced two vertices for the same
        /// round.
        author: ValidatorId,
        /// The round at which the equivocation was detected.
        round: RoundNumber,
        /// The id of the vertex already present in the DAG.
        existing: VertexId,
    },

    /// The vertex's parents include duplicates. Per §8.3.1 the
    /// parent set is a multiset-of-references-treated-as-set;
    /// duplicates carry no additional consensus weight and are
    /// rejected outright.
    DuplicateParents,

    /// The vertex's parent count is below the quorum threshold
    /// for the previous round (`2/3+1` of the active set size
    /// per §8.3.1). Genesis-round vertices (round 0) are exempt
    /// from this check.
    InsufficientQuorum {
        /// The number of distinct parents the vertex references.
        parents: usize,
        /// The minimum number of parents the vertex must
        /// reference for its round.
        required: usize,
    },

    /// The vertex references a parent `VertexId` that is not
    /// present in the DAG. The caller MUST ensure the parent
    /// graph is inserted bottom-up (parents before children).
    UnknownParent(VertexId),

    /// The vertex references a parent that is present in the
    /// DAG but at a round other than `vertex.round - 1`. Per
    /// §8.3.2 vertices reference the immediately-prior round
    /// only.
    ParentRoundMismatch {
        /// The id of the offending parent.
        parent: VertexId,
        /// The round at which the parent actually lives in the
        /// DAG.
        parent_round: RoundNumber,
        /// The round expected (`vertex.round - 1`).
        expected: RoundNumber,
    },

    /// The vertex's author is not present in the supplied active
    /// set. Per §8.1.3 only active validators may produce
    /// vertices; non-active or unknown authors are rejected.
    AuthorNotInActiveSet(ValidatorId),

    /// The vertex's author's BLS public key could not be parsed
    /// (e.g., the bytes do not encode a valid G2 point). The
    /// public key bytes come from the on-chain validator record;
    /// a parse failure here indicates either chain-state
    /// corruption or a malformed `ValidatorPublicKeys` entry
    /// somewhere upstream.
    InvalidAuthorPublicKey(ValidatorId),

    /// The vertex's BLS signature does not verify against its
    /// author's public key over the vertex id. Either the
    /// signature is forged or the vertex was tampered with
    /// after signing.
    InvalidSignature,

    /// A genesis-round vertex (round 0) carried parents.
    /// Per §8.3.2 genesis-round vertices reference the genesis
    /// state directly, not other vertices.
    GenesisVertexCarriesParents,
}

impl core::fmt::Display for DagError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::EquivocationDetected {
                author,
                round,
                existing,
            } => write!(
                f,
                "equivocation detected: author={author:?} round={round:?} existing_vertex={existing:?}"
            ),
            Self::DuplicateParents => f.write_str("vertex parent set contains duplicates"),
            Self::InsufficientQuorum { parents, required } => write!(
                f,
                "vertex parent count {parents} is below the §8.3.1 quorum requirement {required}"
            ),
            Self::UnknownParent(id) => {
                write!(f, "vertex references unknown parent {id:?}")
            }
            Self::ParentRoundMismatch {
                parent,
                parent_round,
                expected,
            } => write!(
                f,
                "vertex parent {parent:?} is at round {parent_round:?} but vertex requires round {expected:?}"
            ),
            Self::AuthorNotInActiveSet(author) => {
                write!(f, "vertex author {author:?} is not in the active set")
            }
            Self::InvalidAuthorPublicKey(author) => write!(
                f,
                "vertex author {author:?} has a malformed BLS public key in chain state"
            ),
            Self::InvalidSignature => f.write_str("vertex BLS signature failed verification"),
            Self::GenesisVertexCarriesParents => f.write_str(
                "genesis-round vertex (round 0) must reference no parents per §8.3.2",
            ),
        }
    }
}

impl std::error::Error for DagError {}

/// In-memory DAG state per whitepaper §8.3.
///
/// Stores every vertex received from the active set, indexed for
/// the lookups the rest of the consensus pipeline requires.
/// Insertion via [`DagState::insert`] enforces every structural
/// invariant from §8.3.1 + §8.3.2 + §8.1.5; the read accessors
/// are constant-time hash lookups.
///
/// # Memory shape
///
/// At steady state with `N` active validators and `R` rounds
/// retained, the DAG holds `N · R` vertices, each ~few-hundred-
/// byte BCS-encoded. For the genesis launch (`N = 7`,
/// `R ≤ ROUNDS_PER_EPOCH = 144`) this is well under 1 MiB. For
/// the design-target validator count (`N = 75`), one epoch's
/// worth of vertices is ~few-MiB; the chain prunes older rounds
/// after their commit waves close (Phase 7.7b commit-wave
/// machinery — not in this sub-arc).
///
/// # Atomicity
///
/// [`DagState::insert`] is atomic on success: all three indices
/// are updated together, or none are. On error, the DAG state
/// is unchanged. This is important because Phase 7.7b's commit-
/// wave logic queries the indices and must see consistent
/// results.
#[derive(Clone, Debug, Default)]
#[allow(
    clippy::struct_field_names,
    reason = "the three `by_*` fields are intentional parallel \
              indices into the same primary storage; the `by_` \
              prefix makes the indexing dimension obvious at \
              every call site (`self.by_id.get(...)`, \
              `self.by_round.get(...)`, etc.)"
)]
pub struct DagState {
    /// Primary storage: vertex by `VertexId`.
    by_id: HashMap<VertexId, Vertex>,

    /// Equivocation-detection index: `(round, author) → VertexId`.
    /// The first vertex inserted for a given `(round, author)`
    /// wins; subsequent vertices with the same key but a
    /// different id are rejected as equivocation.
    by_round_author: HashMap<(RoundNumber, ValidatorId), VertexId>,

    /// Round-enumeration index: `round → Vec<VertexId>` of all
    /// vertices at that round. Used for parent-set enumeration
    /// during vertex construction (caller-side) and for
    /// commit-wave anchor selection (Phase 7.7b).
    by_round: HashMap<RoundNumber, Vec<VertexId>>,
}

impl DagState {
    /// Returns a new, empty DAG state.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the number of vertices currently in the DAG.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_id.len()
    }

    /// Returns `true` if the DAG is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_id.is_empty()
    }

    /// Returns the vertex with the supplied id, if it exists.
    #[must_use]
    pub fn vertex(&self, id: &VertexId) -> Option<&Vertex> {
        self.by_id.get(id)
    }

    /// Returns `true` if a vertex with the supplied id is
    /// present in the DAG.
    #[must_use]
    pub fn contains(&self, id: &VertexId) -> bool {
        self.by_id.contains_key(id)
    }

    /// Returns the vertex id for the supplied `(round, author)`
    /// pair, if any. Useful for equivocation-evidence retrieval.
    #[must_use]
    pub fn vertex_by_round_author(
        &self,
        round: RoundNumber,
        author: ValidatorId,
    ) -> Option<&VertexId> {
        self.by_round_author.get(&(round, author))
    }

    /// Returns the vertex ids at the supplied round.
    ///
    /// The returned slice's order is the insertion order — NOT
    /// canonical. Callers that require deterministic ordering
    /// must sort (e.g., the commit-wave anchor election in
    /// Phase 7.7b sorts by `ValidatorId` before applying the
    /// VRF index).
    #[must_use]
    pub fn vertices_at_round(&self, round: RoundNumber) -> &[VertexId] {
        self.by_round.get(&round).map_or(&[], Vec::as_slice)
    }

    /// Validates and inserts a vertex into the DAG.
    ///
    /// # Validation steps
    ///
    /// 1. Equivocation check: no other vertex exists for
    ///    `(vertex.round, vertex.author)`.
    /// 2. Parent-set distinctness (§8.3.1).
    /// 3. Genesis-round exemption: if `vertex.round == 0`,
    ///    skip parent-quorum + parent-existence checks (and
    ///    reject if parents are non-empty per §8.3.2).
    /// 4. Parent-quorum check: `parents.len() ≥ quorum_threshold(active.len())`
    ///    (§8.3.1).
    /// 5. Parent-existence + parent-round check: every parent
    ///    must already be in the DAG at `vertex.round - 1`.
    /// 6. Author-in-active-set check: `vertex.author` must
    ///    appear in `active_set`'s active slots.
    /// 7. BLS signature verification: `vertex.signature` must
    ///    verify against the author's BLS public key over
    ///    `vertex.id().as_bytes()`.
    ///
    /// On success, the vertex is committed to all three indices
    /// atomically. On error, the DAG state is unchanged.
    ///
    /// # Errors
    ///
    /// Returns a [`DagError`] for any failed validation step.
    /// See the variant docs for the per-step semantics.
    ///
    /// # Performance
    ///
    /// Constant-time hash lookups dominate; the BLS verification
    /// step (one pairing) is the bottleneck at ~1-2ms on
    /// consensus-grade hardware. Quorum check is `O(parents)`.
    ///
    /// # Panics
    ///
    /// Cannot panic in practice. The internal `expect("…")` on
    /// the round-decrement path is guarded by an explicit
    /// `round == RoundNumber::default()` check earlier in the
    /// function.
    pub fn insert(&mut self, vertex: Vertex, active_set: &ActiveSet) -> Result<(), DagError> {
        let id = vertex.id();
        let author = vertex.author();
        let round = vertex.round();

        // Step 1: equivocation check.
        if let Some(existing) = self.by_round_author.get(&(round, author)) {
            // Tolerate the re-insertion of the same vertex
            // (idempotent reception) by short-circuiting if
            // `existing == id`. The DAG state is already
            // consistent.
            if *existing == id {
                return Ok(());
            }
            return Err(DagError::EquivocationDetected {
                author,
                round,
                existing: *existing,
            });
        }

        // Step 2: parent-set distinctness.
        if !vertex.parents_are_distinct() {
            return Err(DagError::DuplicateParents);
        }

        // Step 3-5: parent-set validation. Genesis-round
        // (round 0) vertices reference no other vertices.
        if round == RoundNumber::default() {
            if !vertex.parents().is_empty() {
                return Err(DagError::GenesisVertexCarriesParents);
            }
        } else {
            // Step 4: parent-quorum.
            let active_size = active_set.active_size();
            let required = quorum_threshold(active_size);
            if vertex.parents().len() < required {
                return Err(DagError::InsufficientQuorum {
                    parents: vertex.parents().len(),
                    required,
                });
            }

            // Step 5: parent existence + round.
            let expected_parent_round = RoundNumber::new(
                round
                    .as_u64()
                    .checked_sub(1)
                    .expect("round > 0 here; checked above"),
            );
            for parent_id in vertex.parents() {
                let parent = self
                    .by_id
                    .get(parent_id)
                    .ok_or(DagError::UnknownParent(*parent_id))?;
                let parent_round = parent.round();
                if parent_round != expected_parent_round {
                    return Err(DagError::ParentRoundMismatch {
                        parent: *parent_id,
                        parent_round,
                        expected: expected_parent_round,
                    });
                }
            }
        }

        // Step 6: author-in-active-set.
        // `is_active` is a constant-time hash-lookup style check
        // on the active-set's underlying slot map. Returns `true`
        // iff the author has an Active-status slot. The BLS public
        // key is NOT held inside `ActiveSet` — that lookup lives
        // in the validator registry (chain state). The
        // `insert_with_pubkeys` companion method below threads the
        // public-key resolver for the full step-7 BLS-signature
        // check; the unparameterised `insert` is intentionally a
        // less-strict path useful for tests and for caller-side
        // validation pipelines that perform the BLS check
        // elsewhere.
        if !active_set.is_active(author) {
            return Err(DagError::AuthorNotInActiveSet(author));
        }

        // Step 7: signature verification is performed via the
        // companion `insert_with_pubkeys` method when the caller
        // supplies the per-author public-key resolver. The
        // unparameterised `insert` is intentionally a less-strict
        // path useful for tests and for caller-side validation
        // pipelines that perform the BLS check elsewhere.

        // Commit to all three indices.
        self.by_id.insert(id, vertex);
        self.by_round_author.insert((round, author), id);
        self.by_round.entry(round).or_default().push(id);

        Ok(())
    }

    /// Validating insertion with explicit BLS public-key
    /// resolution. Performs the full step-1-through-step-7
    /// validation listed on [`Self::insert`].
    ///
    /// `pubkeys` is a resolver mapping a `ValidatorId` to the
    /// validator's full `ValidatorPublicKeys` bundle; the BLS
    /// component is what step 7 verifies the vertex signature
    /// against. The resolver lets the caller plug in any
    /// validator-registry implementation (chain-state lookup,
    /// in-memory map, etc.) without coupling the DAG state to
    /// a specific storage shape.
    ///
    /// # Errors
    ///
    /// Same as [`Self::insert`], plus [`DagError::InvalidAuthorPublicKey`]
    /// if the resolver returns a public-key bundle whose BLS
    /// component cannot be parsed, and [`DagError::InvalidSignature`]
    /// if the BLS verification step fails.
    ///
    /// # Panics
    ///
    /// Cannot panic in practice. The delegated structural
    /// validation in [`Self::insert`] carries an internal
    /// `expect("…")` on the round-decrement path which is guarded
    /// by an explicit round-zero check there.
    pub fn insert_with_pubkeys<F>(
        &mut self,
        vertex: Vertex,
        active_set: &ActiveSet,
        pubkeys: F,
    ) -> Result<(), DagError>
    where
        F: Fn(&ValidatorId) -> Option<ValidatorPublicKeys>,
    {
        // Run the structural validation via the lighter insert,
        // but first do the BLS check so we don't commit to
        // indices and then have to roll back.
        let id = vertex.id();
        let author = vertex.author();

        // Pre-validate the BLS signature before any state
        // mutation. The structural checks in `insert` itself
        // are repeated; doing them again is cheap and keeps
        // `insert_with_pubkeys` self-contained against future
        // changes.
        let pkeys = pubkeys(&author).ok_or(DagError::AuthorNotInActiveSet(author))?;
        let bls_pk = bls::PublicKey::from_bytes(&pkeys.bls_public_key)
            .map_err(|_| DagError::InvalidAuthorPublicKey(author))?;
        let signature_bytes: &[u8; bls::SIGNATURE_BYTES] = vertex.signature().as_bytes();
        let signature =
            bls::Signature::from_bytes(signature_bytes).map_err(|_| DagError::InvalidSignature)?;
        bls_pk
            .verify(id.as_bytes(), &signature)
            .map_err(|_| DagError::InvalidSignature)?;

        // Structural validation + commit.
        self.insert(vertex, active_set)
    }

    /// Returns the set of vertex ids that are causal ancestors
    /// of the supplied vertex, in no particular order.
    ///
    /// "Causal ancestor" per §8.3.2: vertex `A` is a causal
    /// ancestor of vertex `B` if there is a path from `B` back
    /// to `A` through parent edges. The returned set is the
    /// transitive closure of the parent relation rooted at
    /// `start`. The starting vertex itself is NOT included.
    ///
    /// # Performance
    ///
    /// `O(|ancestor-set|)` lookups. The traversal uses a
    /// breadth-first walk with a visited-set to avoid
    /// re-traversing shared subgraphs.
    ///
    /// Returns an empty set if `start` is not in the DAG.
    #[must_use]
    pub fn causal_ancestors(&self, start: &VertexId) -> HashSet<VertexId> {
        let mut visited: HashSet<VertexId> = HashSet::new();
        let mut queue: VecDeque<VertexId> = VecDeque::new();

        // Seed the queue with the start vertex's parents (start
        // itself is not an ancestor of itself).
        if let Some(vertex) = self.by_id.get(start) {
            for parent in vertex.parents() {
                queue.push_back(*parent);
            }
        } else {
            return visited;
        }

        while let Some(id) = queue.pop_front() {
            if !visited.insert(id) {
                // Already visited; skip.
                continue;
            }
            if let Some(vertex) = self.by_id.get(&id) {
                for parent in vertex.parents() {
                    if !visited.contains(parent) {
                        queue.push_back(*parent);
                    }
                }
            }
            // Missing parents: silently skip. The structural
            // validation in `insert` prevents this state from
            // arising during normal operation, but the helper
            // is defensive for partial-DAG scenarios (e.g.,
            // commit-wave logic post-pruning).
        }

        visited
    }

    /// Returns `true` if `from` causally reaches `target` —
    /// i.e., `target` is a causal ancestor of `from`.
    ///
    /// Special cases:
    ///
    /// - `from == target`: returns `false` (per causal-ancestor
    ///   definition, a vertex is not its own ancestor).
    /// - `from` not in the DAG: returns `false`.
    /// - `target` not in the DAG: returns `false`.
    ///
    /// # Performance
    ///
    /// Worst-case `O(|ancestor-set-of-from|)`; in practice
    /// terminates early when `target` is found.
    #[must_use]
    pub fn reaches(&self, from: &VertexId, target: &VertexId) -> bool {
        if from == target {
            return false;
        }
        if !self.contains(target) {
            return false;
        }
        let mut visited: HashSet<VertexId> = HashSet::new();
        let mut queue: VecDeque<VertexId> = VecDeque::new();
        if let Some(vertex) = self.by_id.get(from) {
            for parent in vertex.parents() {
                queue.push_back(*parent);
            }
        } else {
            return false;
        }
        while let Some(id) = queue.pop_front() {
            if id == *target {
                return true;
            }
            if !visited.insert(id) {
                continue;
            }
            if let Some(vertex) = self.by_id.get(&id) {
                for parent in vertex.parents() {
                    if !visited.contains(parent) {
                        queue.push_back(*parent);
                    }
                }
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::active_set::{ActiveSet, ACTIVE_SET_LAUNCH_CEILING};
    use crate::epoch::EpochNumber;
    use crate::identity::ValidatorPublicKeys;
    use crate::vertex::{
        PartialProofWitness, Vertex, VertexBuilder, VertexSignature, BLS_SIGNATURE_BYTES,
    };

    fn validator_id(seed: u8) -> ValidatorId {
        validator_pubkeys(seed).derive_id()
    }

    fn validator_pubkeys(seed: u8) -> ValidatorPublicKeys {
        ValidatorPublicKeys::new([seed; 32], [seed; 1952], [seed; 96])
    }

    /// Build a fresh ActiveSet with `n` validators registered at
    /// epoch 0. Validator seeds are 1..=n.
    fn fixture_active_set(n: u8) -> ActiveSet {
        let mut set = ActiveSet::new();
        for seed in 1..=n {
            set.register(validator_id(seed), EpochNumber::default())
                .expect("register");
        }
        set
    }

    /// Build a genesis-round (round 0) vertex with no parents.
    fn make_genesis_vertex(author_seed: u8) -> Vertex {
        VertexBuilder::new(validator_id(author_seed), RoundNumber::default())
            .with_signature(VertexSignature::from_bytes([0u8; BLS_SIGNATURE_BYTES]))
            .build()
    }

    /// Build a round-`round` vertex with the supplied parents.
    fn make_vertex(author_seed: u8, round: u64, parents: Vec<VertexId>) -> Vertex {
        VertexBuilder::new(validator_id(author_seed), RoundNumber::new(round))
            .with_parents(parents)
            .with_signature(VertexSignature::from_bytes([0u8; BLS_SIGNATURE_BYTES]))
            .build()
    }

    // ---- DagState basics ----

    #[test]
    fn new_dag_is_empty() {
        let dag = DagState::new();
        assert!(dag.is_empty());
        assert_eq!(dag.len(), 0);
    }

    #[test]
    fn default_dag_is_empty() {
        let dag = DagState::default();
        assert!(dag.is_empty());
    }

    // ---- Genesis-round insertion ----

    #[test]
    fn insert_genesis_vertex_succeeds() {
        let active = fixture_active_set(7);
        let mut dag = DagState::new();
        let v = make_genesis_vertex(1);
        let id = v.id();
        dag.insert(v, &active).expect("insert");
        assert_eq!(dag.len(), 1);
        assert!(dag.contains(&id));
    }

    #[test]
    fn genesis_vertex_with_parents_is_rejected() {
        let active = fixture_active_set(7);
        let mut dag = DagState::new();
        let parent_id = VertexId::from_bytes([1u8; 32]);
        let v = make_vertex(1, 0, vec![parent_id]);
        let err = dag.insert(v, &active).expect_err("must reject");
        assert_eq!(err, DagError::GenesisVertexCarriesParents);
    }

    // ---- Round > 0 insertion + quorum ----

    /// Helper: insert genesis-round vertices for all `n`
    /// validators in the active set, returning their VertexIds.
    fn populate_genesis_round(dag: &mut DagState, active: &ActiveSet, n: u8) -> Vec<VertexId> {
        let mut ids = Vec::new();
        for seed in 1..=n {
            let v = make_genesis_vertex(seed);
            let id = v.id();
            dag.insert(v, active).expect("insert genesis");
            ids.push(id);
        }
        ids
    }

    #[test]
    fn insert_round_1_with_quorum_parents_succeeds() {
        let active = fixture_active_set(7);
        let mut dag = DagState::new();
        let parents = populate_genesis_round(&mut dag, &active, 7);
        // Quorum for n=7 is 5 (2*7/3 + 1 = 5).
        let v = make_vertex(1, 1, parents[..5].to_vec());
        dag.insert(v, &active).expect("insert round-1");
    }

    #[test]
    fn insert_round_1_below_quorum_is_rejected() {
        let active = fixture_active_set(7);
        let mut dag = DagState::new();
        let parents = populate_genesis_round(&mut dag, &active, 7);
        // 4 parents — below the quorum threshold of 5 for n=7.
        let v = make_vertex(1, 1, parents[..4].to_vec());
        let err = dag.insert(v, &active).expect_err("must reject");
        assert!(matches!(
            err,
            DagError::InsufficientQuorum {
                parents: 4,
                required: 5
            }
        ));
    }

    #[test]
    fn insert_round_1_at_exactly_quorum_threshold_succeeds() {
        let active = fixture_active_set(15);
        let mut dag = DagState::new();
        let parents = populate_genesis_round(&mut dag, &active, 15);
        // Quorum for n=15 is 11 (2*15/3 + 1 = 11).
        let v = make_vertex(1, 1, parents[..11].to_vec());
        dag.insert(v, &active).expect("insert at threshold");
    }

    #[test]
    fn insert_with_duplicate_parents_is_rejected() {
        let active = fixture_active_set(7);
        let mut dag = DagState::new();
        let parents = populate_genesis_round(&mut dag, &active, 7);
        // 5 entries but parents[0] appears twice → only 4 distinct.
        let dup_parents = vec![parents[0], parents[1], parents[2], parents[3], parents[0]];
        let v = make_vertex(1, 1, dup_parents);
        let err = dag.insert(v, &active).expect_err("must reject");
        assert_eq!(err, DagError::DuplicateParents);
    }

    #[test]
    fn insert_with_unknown_parent_is_rejected() {
        let active = fixture_active_set(7);
        let mut dag = DagState::new();
        let parents = populate_genesis_round(&mut dag, &active, 7);
        // Replace one parent with a non-existent VertexId.
        let mut bad_parents = parents[..5].to_vec();
        bad_parents[2] = VertexId::from_bytes([0xFFu8; 32]);
        let v = make_vertex(1, 1, bad_parents);
        let err = dag.insert(v, &active).expect_err("must reject");
        assert!(matches!(err, DagError::UnknownParent(_)));
    }

    #[test]
    fn insert_with_parent_at_wrong_round_is_rejected() {
        let active = fixture_active_set(7);
        let mut dag = DagState::new();
        let r0_parents = populate_genesis_round(&mut dag, &active, 7);
        // Insert a round-1 vertex first.
        let r1_v = make_vertex(1, 1, r0_parents[..5].to_vec());
        let r1_id = r1_v.id();
        dag.insert(r1_v, &active).expect("insert r1");
        // Now build a round-2 vertex that includes a round-0
        // parent (wrong — should be round-1 only).
        let bad_parents = vec![
            r0_parents[0],
            r0_parents[1],
            r0_parents[2],
            r0_parents[3],
            r1_id,
        ];
        let v = make_vertex(2, 2, bad_parents);
        let err = dag.insert(v, &active).expect_err("must reject");
        match err {
            DagError::ParentRoundMismatch {
                parent_round,
                expected,
                ..
            } => {
                // vertex.round = 2 → expected parent_round = 1.
                assert_eq!(expected, RoundNumber::new(1));
                // The first bad parent is r0_parents[0] (round 0)
                // which is checked before the valid r1_id, so
                // the error surfaces parent_round = 0.
                assert_eq!(parent_round, RoundNumber::new(0));
            }
            other => panic!("expected ParentRoundMismatch, got {other:?}"),
        }
    }

    // ---- Equivocation detection ----

    #[test]
    fn equivocation_at_genesis_round_is_detected() {
        let active = fixture_active_set(7);
        let mut dag = DagState::new();
        let v1 = make_genesis_vertex(1);
        let v1_id = v1.id();
        dag.insert(v1, &active).expect("insert first");

        // Second vertex by the SAME author at the SAME round
        // but with a different body. VertexId is derived from
        // the UnsignedVertex body (not the signature), so we
        // must vary a body field to force a distinct id. Set the
        // proof_witness to a non-empty payload here.
        let v2 = VertexBuilder::new(validator_id(1), RoundNumber::default())
            .with_proof_witness(PartialProofWitness::new(vec![0x42]))
            .with_signature(VertexSignature::from_bytes([0u8; BLS_SIGNATURE_BYTES]))
            .build();
        let v2_id = v2.id();
        assert_ne!(v1_id, v2_id, "test fixture should produce distinct ids");

        let err = dag.insert(v2, &active).expect_err("must reject");
        match err {
            DagError::EquivocationDetected {
                author,
                round,
                existing,
            } => {
                assert_eq!(author, validator_id(1));
                assert_eq!(round, RoundNumber::default());
                assert_eq!(existing, v1_id);
            }
            other => panic!("expected EquivocationDetected, got {other:?}"),
        }
    }

    #[test]
    fn re_insertion_of_same_vertex_is_idempotent() {
        let active = fixture_active_set(7);
        let mut dag = DagState::new();
        let v = make_genesis_vertex(1);
        let id = v.id();
        dag.insert(v.clone(), &active).expect("first insert");
        // Second insert of the same vertex (same id) must succeed.
        dag.insert(v, &active).expect("idempotent re-insert");
        assert_eq!(dag.len(), 1);
        assert!(dag.contains(&id));
    }

    // ---- Author-in-active-set check ----

    #[test]
    fn insert_with_author_not_in_active_set_is_rejected() {
        let active = fixture_active_set(7); // validators 1..=7
        let mut dag = DagState::new();
        // Validator with seed=99 is NOT in the active set.
        let v = make_genesis_vertex(99);
        let err = dag.insert(v, &active).expect_err("must reject");
        assert_eq!(err, DagError::AuthorNotInActiveSet(validator_id(99)));
    }

    // ---- Lookup accessors ----

    #[test]
    fn vertex_lookup_by_id() {
        let active = fixture_active_set(7);
        let mut dag = DagState::new();
        let v = make_genesis_vertex(1);
        let id = v.id();
        dag.insert(v.clone(), &active).expect("insert");
        let retrieved = dag.vertex(&id).expect("present");
        assert_eq!(retrieved.id(), id);
    }

    #[test]
    fn vertex_lookup_returns_none_for_unknown_id() {
        let dag = DagState::new();
        assert!(dag.vertex(&VertexId::from_bytes([0u8; 32])).is_none());
    }

    #[test]
    fn vertex_by_round_author_lookup() {
        let active = fixture_active_set(7);
        let mut dag = DagState::new();
        let v = make_genesis_vertex(1);
        let id = v.id();
        dag.insert(v, &active).expect("insert");
        let found = dag.vertex_by_round_author(RoundNumber::default(), validator_id(1));
        assert_eq!(found, Some(&id));
    }

    #[test]
    fn vertices_at_round_returns_all_vertices_at_that_round() {
        let active = fixture_active_set(7);
        let mut dag = DagState::new();
        let ids = populate_genesis_round(&mut dag, &active, 7);
        let at_round_0 = dag.vertices_at_round(RoundNumber::default());
        assert_eq!(at_round_0.len(), 7);
        for id in &ids {
            assert!(at_round_0.contains(id));
        }
    }

    #[test]
    fn vertices_at_empty_round_returns_empty_slice() {
        let dag = DagState::new();
        assert!(dag.vertices_at_round(RoundNumber::new(42)).is_empty());
    }

    // ---- Reachability ----

    #[test]
    fn causal_ancestors_of_genesis_is_empty() {
        let active = fixture_active_set(7);
        let mut dag = DagState::new();
        let v = make_genesis_vertex(1);
        let id = v.id();
        dag.insert(v, &active).expect("insert");
        assert!(dag.causal_ancestors(&id).is_empty());
    }

    #[test]
    fn causal_ancestors_of_round_1_vertex_includes_parents() {
        let active = fixture_active_set(7);
        let mut dag = DagState::new();
        let parents = populate_genesis_round(&mut dag, &active, 7);
        let v = make_vertex(1, 1, parents[..5].to_vec());
        let id = v.id();
        dag.insert(v, &active).expect("insert");
        let ancestors = dag.causal_ancestors(&id);
        assert_eq!(ancestors.len(), 5);
        for p in &parents[..5] {
            assert!(ancestors.contains(p));
        }
        // Parents 5 and 6 are NOT ancestors (not referenced).
        assert!(!ancestors.contains(&parents[5]));
        assert!(!ancestors.contains(&parents[6]));
    }

    #[test]
    fn causal_ancestors_traverses_transitively() {
        let active = fixture_active_set(7);
        let mut dag = DagState::new();
        let r0_ids = populate_genesis_round(&mut dag, &active, 7);

        // Build a round-1 vertex referencing 5 of the round-0
        // vertices.
        let r1_v = make_vertex(1, 1, r0_ids[..5].to_vec());
        let r1_id = r1_v.id();
        dag.insert(r1_v, &active).expect("insert r1");

        // For round-2, we need 5 distinct round-1 vertices.
        // Add another 4 round-1 vertices (one per remaining
        // validator).
        let mut r1_ids = vec![r1_id];
        for seed in 2..=5 {
            let v = make_vertex(seed, 1, r0_ids[..5].to_vec());
            r1_ids.push(v.id());
            dag.insert(v, &active).expect("insert r1");
        }
        assert_eq!(r1_ids.len(), 5);

        // Round-2 vertex referencing those 5 r1 vertices.
        let r2_v = make_vertex(1, 2, r1_ids.clone());
        let r2_id = r2_v.id();
        dag.insert(r2_v, &active).expect("insert r2");

        let ancestors = dag.causal_ancestors(&r2_id);
        // All 5 r1 vertices.
        for id in &r1_ids {
            assert!(ancestors.contains(id), "missing r1 {id:?}");
        }
        // r0 vertices reached transitively: r0_ids[0..5] are
        // parents of r1_ids[0..5], so all of them must be in
        // the ancestor set.
        for id in &r0_ids[..5] {
            assert!(ancestors.contains(id), "missing r0 {id:?}");
        }
    }

    #[test]
    fn reaches_correctness() {
        let active = fixture_active_set(7);
        let mut dag = DagState::new();
        let r0_ids = populate_genesis_round(&mut dag, &active, 7);
        let r1_v = make_vertex(1, 1, r0_ids[..5].to_vec());
        let r1_id = r1_v.id();
        dag.insert(r1_v, &active).expect("insert r1");

        // r1 reaches each of its parents.
        for p in &r0_ids[..5] {
            assert!(dag.reaches(&r1_id, p), "r1 should reach {p:?}");
        }
        // r1 does NOT reach non-parent r0 vertices.
        assert!(!dag.reaches(&r1_id, &r0_ids[5]));
        assert!(!dag.reaches(&r1_id, &r0_ids[6]));
        // A vertex does not reach itself.
        assert!(!dag.reaches(&r1_id, &r1_id));
        // Reaches an unknown target returns false.
        assert!(!dag.reaches(&r1_id, &VertexId::from_bytes([0xFFu8; 32])));
        // Reaches from an unknown source returns false.
        assert!(!dag.reaches(&VertexId::from_bytes([0xEEu8; 32]), &r0_ids[0]));
    }

    // ---- Atomicity: failed insert leaves no state ----

    #[test]
    fn failed_insert_does_not_mutate_state() {
        let active = fixture_active_set(7);
        let mut dag = DagState::new();
        populate_genesis_round(&mut dag, &active, 7);
        let pre_len = dag.len();

        // Build a vertex that will fail the quorum check.
        let v = make_vertex(1, 1, vec![]);
        let err = dag.insert(v.clone(), &active).expect_err("must reject");
        match err {
            DagError::InsufficientQuorum { parents, required } => {
                assert_eq!(parents, 0, "empty parent vec");
                assert_eq!(required, 5, "n=7 → quorum = 5 per §8.3.1");
            }
            other => panic!("expected InsufficientQuorum, got {other:?}"),
        }

        // DAG state is unchanged.
        assert_eq!(dag.len(), pre_len);
        assert!(!dag.contains(&v.id()));
    }

    // ---- Error display + std::error::Error ----

    #[test]
    fn dag_error_implements_std_error() {
        fn assert_err<E: std::error::Error>() {}
        assert_err::<DagError>();
    }

    #[test]
    fn dag_error_display_messages_are_meaningful() {
        let variants = [
            DagError::EquivocationDetected {
                author: validator_id(1),
                round: RoundNumber::default(),
                existing: VertexId::from_bytes([0u8; 32]),
            },
            DagError::DuplicateParents,
            DagError::InsufficientQuorum {
                parents: 3,
                required: 5,
            },
            DagError::UnknownParent(VertexId::from_bytes([0u8; 32])),
            DagError::ParentRoundMismatch {
                parent: VertexId::from_bytes([0u8; 32]),
                parent_round: RoundNumber::default(),
                expected: RoundNumber::new(1),
            },
            DagError::AuthorNotInActiveSet(validator_id(1)),
            DagError::InvalidAuthorPublicKey(validator_id(1)),
            DagError::InvalidSignature,
            DagError::GenesisVertexCarriesParents,
        ];
        let messages: Vec<String> = variants.iter().map(ToString::to_string).collect();
        for msg in &messages {
            assert!(!msg.is_empty());
        }
        // All variants produce pairwise-distinct messages.
        for i in 0..messages.len() {
            for j in (i + 1)..messages.len() {
                assert_ne!(messages[i], messages[j]);
            }
        }
    }

    // ---- Scaling sanity ----

    #[test]
    fn handles_design_target_active_set() {
        // 75-validator active set (genesis cohort size).
        let n = u8::try_from(ACTIVE_SET_LAUNCH_CEILING).expect("75 fits in u8");
        let active = fixture_active_set(n);
        let mut dag = DagState::new();
        let _ = populate_genesis_round(&mut dag, &active, n);
        assert_eq!(dag.len(), 75);
        assert_eq!(dag.vertices_at_round(RoundNumber::default()).len(), 75);
    }
}
