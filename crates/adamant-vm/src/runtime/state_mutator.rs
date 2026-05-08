//! Write-side state interface — whitepaper §6.2.2 step 7.
//!
//! Per Phase 5/6 plan-gate Q8 disposition, the runtime operates
//! against a [`StateMutator`] trait abstraction rather than against
//! a concrete chain-state backend. Same posture as [`StateView`]
//! at [`super::state_view`].
//!
//! # Whitepaper §6.2.2 step 7 (verbatim)
//!
//! > "Commit or abort. If execution succeeded and (for shielded
//! > transactions) the proof verifies, state changes are committed:
//! > object versions increment, ownership transfers apply, new
//! > objects are created, destroyed objects are removed. If
//! > execution failed, all state changes are discarded except for
//! > the gas charged."
//!
//! The runtime accumulates state changes in a transaction-local
//! [`crate::runtime::TransactionStateBuffer`] per §6.2.2 step 5
//! ("State changes are accumulated in a transaction-local buffer;
//! chain state is not mutated until execution succeeds"). On
//! successful execution, the buffer is consumed into a
//! [`TransactionStateChanges`] payload and submitted to
//! [`StateMutator::commit`] for atomic application. On failure,
//! the buffer is dropped without invoking the mutator.
//!
//! [`StateView`]: super::state_view::StateView

use adamant_types::{Object, ObjectId};

/// Write-side mutator over chain state.
///
/// Implemented by:
///
/// - **Production:** RocksDB-backed chain-state implementation
///   landing in the Phase 4 object-storage backfill workstream.
/// - **Test-only:** [`crate::runtime::test_helpers::InMemoryStateMutator`]
///   backed by a [`HashMap`].
///
/// The trait surface is a single atomic [`Self::commit`] method.
/// Per §6.2.2 step 5, state changes accumulate in the runtime's
/// [`crate::runtime::TransactionStateBuffer`]; the mutator is
/// invoked exactly once at the commit boundary with the full
/// [`TransactionStateChanges`] payload, or not at all if execution
/// failed.
///
/// [`HashMap`]: std::collections::HashMap
pub trait StateMutator {
    /// Apply the transaction's accumulated state changes atomically.
    ///
    /// Per whitepaper §6.2.2 step 7. The full [`TransactionStateChanges`]
    /// payload is applied as a single atomic operation: either all
    /// changes apply (transaction succeeds) or none apply
    /// (transaction failed at the mutator boundary).
    ///
    /// # Errors
    ///
    /// - [`CommitError::ConflictingWrite`] — a concurrent commit
    ///   advanced an affected object's version between the
    ///   transaction's read-pin and the commit attempt. Distinct
    ///   from [`super::state_view::LoadError::VersionMismatch`]
    ///   which is detected at load time; this variant is the
    ///   commit-time check for late-arriving conflicts.
    /// - [`CommitError::ObjectIdCollision`] — a created object's
    ///   derived `ObjectId` collides with an existing object's
    ///   `ObjectId`. This is a defensive case — `derive_object_id`
    ///   per §5.1.1 produces collision-resistant identifiers, so
    ///   this variant fires only on hash-collision-class events.
    fn commit(&mut self, changes: TransactionStateChanges) -> Result<(), CommitError>;
}

/// The set of state changes a single transaction applies at commit.
///
/// Per whitepaper §6.2.2 step 7: "object versions increment,
/// ownership transfers apply, new objects are created, destroyed
/// objects are removed." This struct is the payload form of those
/// changes — produced by the runtime when execution succeeds, and
/// consumed by [`StateMutator::commit`].
///
/// At sub-arc 5/6.1 the struct's surface is minimal: object
/// creation, object update (covering version increment + ownership
/// transfer + contents update via the updated `Object` carrying
/// the new field values), and object destruction. Subsequent sub-
/// arcs (5/6.6 object loader integration; 5/6.7 stdlib `adamant::module::deploy`
/// + cross-module Rule 3 wiring) may extend the struct.
#[derive(Debug, Default, Clone, Eq, PartialEq)]
pub struct TransactionStateChanges {
    /// Newly created objects per the transaction's `created_objects`
    /// declaration in `TxBody` per §6.0.2. Each object's `id`
    /// field carries the derived `ObjectId` per §5.1.1
    /// (`derive_object_id(creation_tx_hash, creator, creation_index)`).
    /// `version` is `1` for newly created objects per §5.4 step 1.
    pub created: Vec<Object>,

    /// Objects updated by the transaction. Each entry's `version`
    /// is the post-increment version (one greater than the
    /// version at load time per §6.2.2 step 7's "object versions
    /// increment"). The mutator validates that the pre-update
    /// version (one less than `version` for each updated object)
    /// matches the version currently in chain state; a mismatch
    /// surfaces as [`CommitError::ConflictingWrite`].
    pub updated: Vec<Object>,

    /// Objects transitioning to [`adamant_types::Lifecycle::Destroyed`]
    /// per the transaction's type-logic-driven destruction operations.
    ///
    /// Per §5.4.1: destruction transitions the object's `Lifecycle`
    /// to `Destroyed`; the `ObjectId` cannot be reused. The mutator
    /// applies the lifecycle transition; the post-commit pruning
    /// of destroyed-object contents from working storage is the
    /// mutator implementation's concern, not the runtime's.
    pub destroyed: Vec<ObjectId>,
}

impl TransactionStateChanges {
    /// Construct an empty change-set. Same as [`Self::default`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether the change-set is empty — no creations, updates,
    /// or destructions.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.created.is_empty() && self.updated.is_empty() && self.destroyed.is_empty()
    }
}

/// Errors returned by [`StateMutator::commit`].
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub enum CommitError {
    /// A concurrent commit advanced an affected object's version
    /// between the transaction's read-pin and the commit attempt.
    ///
    /// The transaction is treated as failed and gas is charged per
    /// whitepaper §6.3.3.
    ConflictingWrite {
        /// The object whose version diverged at commit time.
        id: ObjectId,
        /// The version the transaction expected to update from
        /// (the read-pin version).
        expected_pre_version: u64,
        /// The version currently in chain state.
        actual_pre_version: u64,
    },

    /// A created object's derived `ObjectId` collides with an
    /// existing object's `ObjectId`.
    ///
    /// Defensive: `derive_object_id` per whitepaper §5.1.1
    /// produces collision-resistant identifiers via tagged SHA3-256
    /// hashing. This variant fires only on hash-collision-class
    /// events that should not occur under correct operation. Same
    /// posture as [`super::error::InvariantViolationReason`]
    /// — the variant exists for completeness of the audit
    /// surface, not because it is an expected error condition.
    ObjectIdCollision {
        /// The colliding `ObjectId`.
        id: ObjectId,
    },
}

#[cfg(test)]
mod tests {
    //! Verbatim-spec-quote-grounds-runtime-fixture discipline.

    use super::*;
    use crate::runtime::test_helpers::InMemoryStateMutator;

    use adamant_types::{
        metadata::{ObjectMetadata, ProofCommitment, PROOF_COMMITMENT_BYTES},
        Address, Contents, Lifecycle, Mutability, Object, Ownership, TypeId,
    };

    fn fixed_object_id(seed: u8) -> ObjectId {
        ObjectId::from_bytes([seed; 32])
    }

    fn make_object(id: ObjectId, version: u64, lifecycle: Lifecycle) -> Object {
        Object {
            id,
            type_id: TypeId::from_bytes([0u8; 32]),
            owner: Ownership::Address(Address::from_bytes([0u8; 32])),
            mutability: Mutability::Immutable,
            lifecycle,
            contents: Contents::empty(),
            version,
            metadata: ObjectMetadata {
                created_at_height: 0,
                last_modified_height: 0,
                creator: Address::from_bytes([0u8; 32]),
                storage_rent_paid_through: 0,
                proof_commitment: ProofCommitment::from_bytes([0u8; PROOF_COMMITMENT_BYTES]),
            },
        }
    }

    /// Whitepaper §6.2.2 step 7 (verbatim): "If execution succeeded
    /// ... state changes are committed: object versions increment,
    /// ownership transfers apply, new objects are created, destroyed
    /// objects are removed."
    ///
    /// Committing an empty change-set succeeds (a transaction may
    /// produce no state changes but still terminate successfully).
    #[test]
    fn commit_empty_change_set_succeeds() {
        let mut mutator = InMemoryStateMutator::new();
        mutator.commit(TransactionStateChanges::new()).expect("ok");
        assert!(mutator.is_empty());
    }

    /// Whitepaper §6.2.2 step 7 (verbatim): "new objects are
    /// created."
    ///
    /// Committing a `created` change inserts the object at its
    /// derived `ObjectId`.
    #[test]
    fn commit_created_object_is_inserted() {
        let id = fixed_object_id(0x10);
        let mut mutator = InMemoryStateMutator::new();
        let mut changes = TransactionStateChanges::new();
        changes.created.push(make_object(id, 1, Lifecycle::Active));
        mutator.commit(changes).expect("ok");
        assert!(mutator.get(&id).is_some());
    }

    /// Whitepaper §6.2.2 step 7 (verbatim): "object versions
    /// increment."
    ///
    /// Committing an `updated` change requires the pre-update
    /// version to match the version currently in chain state.
    /// A divergence surfaces `CommitError::ConflictingWrite`.
    #[test]
    fn commit_updated_object_with_diverged_pre_version_fails() {
        let id = fixed_object_id(0x11);
        let mut mutator = InMemoryStateMutator::new();
        // Chain state has the object at version 5.
        mutator.insert(make_object(id, 5, Lifecycle::Active));

        // Transaction commits an update with post-version 7 — i.e.,
        // expecting pre-version 6, but chain state is at 5.
        let mut changes = TransactionStateChanges::new();
        changes.updated.push(make_object(id, 7, Lifecycle::Active));

        let err = mutator.commit(changes).expect_err("commit fails");
        assert_eq!(
            err,
            CommitError::ConflictingWrite {
                id,
                expected_pre_version: 6,
                actual_pre_version: 5,
            }
        );
    }

    /// Whitepaper §6.2.2 step 7 (verbatim): "destroyed objects
    /// are removed."
    ///
    /// Committing a `destroyed` change transitions the object's
    /// lifecycle to `Destroyed`. Subsequent loads surface
    /// `LoadError::ObjectDestroyed` rather than `ObjectNotFound`,
    /// matching whitepaper §5.4.1: "Destroyed objects are pruned
    /// from working storage but their existence is permanently
    /// recorded in the chain's history."
    #[test]
    fn commit_destroyed_object_marks_lifecycle_destroyed() {
        let id = fixed_object_id(0x12);
        let mut mutator = InMemoryStateMutator::new();
        mutator.insert(make_object(id, 1, Lifecycle::Active));

        let mut changes = TransactionStateChanges::new();
        changes.destroyed.push(id);
        mutator.commit(changes).expect("ok");

        let post_state = mutator.get(&id).expect("object record retained");
        assert_eq!(post_state.lifecycle, Lifecycle::Destroyed);
    }

    /// Whitepaper §6.2.2 step 7 (verbatim): "If execution failed,
    /// all state changes are discarded except for the gas charged."
    ///
    /// Committing a change-set with a colliding-create entry
    /// surfaces `CommitError::ObjectIdCollision`. The atomic-
    /// commit invariant ensures no partial application occurs —
    /// the mutator's state is unchanged after the failed commit.
    #[test]
    fn commit_with_colliding_create_fails_atomically() {
        let id = fixed_object_id(0x13);
        let mut mutator = InMemoryStateMutator::new();
        mutator.insert(make_object(id, 1, Lifecycle::Active));

        let mut changes = TransactionStateChanges::new();
        changes.created.push(make_object(id, 1, Lifecycle::Active));

        let err = mutator.commit(changes).expect_err("commit fails");
        assert_eq!(err, CommitError::ObjectIdCollision { id });

        // Atomic-commit invariant: the mutator's state matches
        // its pre-commit state.
        assert_eq!(mutator.len(), 1);
        assert!(mutator.get(&id).is_some());
    }

    // ---------- TransactionStateChanges ----------

    #[test]
    fn empty_changes_is_empty() {
        let changes = TransactionStateChanges::new();
        assert!(changes.is_empty());
    }
}
