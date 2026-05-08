//! Transaction-local state-change accumulator — whitepaper §6.2.2 step 5.
//!
//! # Whitepaper §6.2.2 step 5 (verbatim)
//!
//! > "Execution. Bytecode runs to completion or until gas is
//! > exhausted. State changes are accumulated in a transaction-
//! > local buffer; chain state is not mutated until execution
//! > succeeds."
//!
//! [`TransactionStateBuffer`] is the runtime-side accumulator
//! that holds object creations, updates, and destructions during
//! execution. On successful execution, the buffer is consumed
//! into a [`TransactionStateChanges`] payload and submitted to
//! [`crate::runtime::StateMutator::commit`]. On execution failure,
//! the buffer is dropped without invoking the mutator, satisfying
//! whitepaper §6.2.2 step 7's "if execution failed, all state
//! changes are discarded except for the gas charged."

use std::collections::HashMap;

use adamant_types::{Object, ObjectId};

use crate::runtime::state_mutator::TransactionStateChanges;

/// Transaction-local state-change accumulator.
///
/// Holds the state changes produced during a single transaction's
/// execution. Methods on the buffer are called by the runtime as
/// instructions execute; the buffer's contents are converted into
/// a [`TransactionStateChanges`] payload via [`Self::into_changes`]
/// at the commit boundary, or dropped on execution failure.
///
/// # Invariants
///
/// 1. An `ObjectId` appears in at most one of `created` /
///    `updated` / `destroyed`. Updating an object after creating
///    it within the same transaction collapses to creation with
///    the latest values; destroying an object after creating it
///    within the same transaction is a no-op (the object never
///    exists in chain state).
///
/// 2. `created` entries' `version` field is `1` per whitepaper
///    §5.4 step 1 ("Creation. ... The object is assigned an
///    `ObjectId`, set to version 1, and added to the chain state").
///
/// 3. `updated` entries' `version` field is the post-increment
///    version (one greater than the version at load time per
///    §6.2.2 step 7's "object versions increment").
#[derive(Debug, Default, Clone, Eq, PartialEq)]
pub struct TransactionStateBuffer {
    created: HashMap<ObjectId, Object>,
    updated: HashMap<ObjectId, Object>,
    destroyed: Vec<ObjectId>,
}

impl TransactionStateBuffer {
    /// Construct an empty buffer.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether the buffer holds no pending changes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.created.is_empty() && self.updated.is_empty() && self.destroyed.is_empty()
    }

    /// Record an object creation. The `Object`'s `id` field is
    /// the `ObjectId` derived per whitepaper §5.1.1 from the
    /// transaction's `created_objects` declaration in `TxBody`
    /// per §6.0.2.
    ///
    /// Subsequent updates or destructions for the same `ObjectId`
    /// within this transaction collapse with the create entry per
    /// invariant (1) above.
    pub fn record_create(&mut self, object: Object) {
        let id = object.id;
        // If this id was previously destroyed in the same
        // transaction (which would be invariant-violating), drop
        // the destroy entry. The runtime's higher-layer logic is
        // expected to prevent this case at instruction-handler
        // level; the buffer is defensive about its own invariant.
        self.destroyed.retain(|&d| d != id);
        self.updated.remove(&id);
        self.created.insert(id, object);
    }

    /// Record an object update. The `Object` carries the post-
    /// update field values; its `version` field is the post-
    /// increment version per invariant (3) above.
    ///
    /// If the same `ObjectId` was previously created within this
    /// transaction, the update overwrites the create entry (the
    /// final committed value is what matters; the intermediate
    /// state is invisible to chain state per the §6.2.2 step 5
    /// "transaction-local buffer" framing).
    pub fn record_update(&mut self, object: Object) {
        let id = object.id;
        if let Some(existing) = self.created.get_mut(&id) {
            *existing = object;
            return;
        }
        self.updated.insert(id, object);
    }

    /// Record an object destruction. The `ObjectId` transitions
    /// to [`adamant_types::Lifecycle::Destroyed`] at commit per
    /// whitepaper §5.4.1.
    ///
    /// If the same `ObjectId` was previously created within this
    /// transaction, the destruction collapses with the create
    /// entry: the object never appears in chain state. This
    /// matches the "transaction-local buffer" framing — the
    /// intermediate state is invisible.
    pub fn record_destroy(&mut self, id: ObjectId) {
        if self.created.remove(&id).is_some() {
            return;
        }
        self.updated.remove(&id);
        if !self.destroyed.contains(&id) {
            self.destroyed.push(id);
        }
    }

    /// Consume the buffer into a [`TransactionStateChanges`]
    /// payload for [`crate::runtime::StateMutator::commit`].
    ///
    /// Called at the commit boundary on successful execution.
    /// On execution failure the buffer is dropped without invoking
    /// this method, satisfying whitepaper §6.2.2 step 7's "if
    /// execution failed, all state changes are discarded."
    #[must_use]
    pub fn into_changes(self) -> TransactionStateChanges {
        TransactionStateChanges {
            created: self.created.into_values().collect(),
            updated: self.updated.into_values().collect(),
            destroyed: self.destroyed,
        }
    }
}

#[cfg(test)]
mod tests {
    //! Verbatim-spec-quote-grounds-runtime-fixture discipline.

    use super::*;

    use adamant_types::{
        metadata::{ObjectMetadata, ProofCommitment, PROOF_COMMITMENT_BYTES},
        Address, Contents, Lifecycle, Mutability, Ownership, TypeId,
    };

    fn fixed_object_id(seed: u8) -> ObjectId {
        ObjectId::from_bytes([seed; 32])
    }

    fn make_object(id: ObjectId, version: u64) -> Object {
        Object {
            id,
            type_id: TypeId::from_bytes([0u8; 32]),
            owner: Ownership::Address(Address::from_bytes([0u8; 32])),
            mutability: Mutability::Immutable,
            lifecycle: Lifecycle::Active,
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

    /// Whitepaper §6.2.2 step 5 (verbatim): "State changes are
    /// accumulated in a transaction-local buffer; chain state is
    /// not mutated until execution succeeds."
    ///
    /// A freshly-constructed buffer holds no pending changes.
    #[test]
    fn new_buffer_is_empty() {
        let buf = TransactionStateBuffer::new();
        assert!(buf.is_empty());
    }

    /// Whitepaper §6.2.2 step 7 (verbatim): "new objects are
    /// created."
    ///
    /// `record_create` adds an entry to the `created` set.
    /// `into_changes` surfaces it.
    #[test]
    fn record_create_surfaces_in_changes() {
        let id = fixed_object_id(0x20);
        let mut buf = TransactionStateBuffer::new();
        buf.record_create(make_object(id, 1));
        let changes = buf.into_changes();
        assert_eq!(changes.created.len(), 1);
        assert_eq!(changes.created[0].id, id);
        assert!(changes.updated.is_empty());
        assert!(changes.destroyed.is_empty());
    }

    /// Whitepaper §6.2.2 step 7 (verbatim): "object versions
    /// increment."
    ///
    /// `record_update` adds an entry to the `updated` set with the
    /// post-increment version. `into_changes` surfaces it.
    #[test]
    fn record_update_surfaces_in_changes() {
        let id = fixed_object_id(0x21);
        let mut buf = TransactionStateBuffer::new();
        buf.record_update(make_object(id, 6));
        let changes = buf.into_changes();
        assert!(changes.created.is_empty());
        assert_eq!(changes.updated.len(), 1);
        assert_eq!(changes.updated[0].version, 6);
        assert!(changes.destroyed.is_empty());
    }

    /// Whitepaper §6.2.2 step 7 (verbatim): "destroyed objects
    /// are removed."
    ///
    /// `record_destroy` adds the `ObjectId` to the `destroyed`
    /// set. `into_changes` surfaces it.
    #[test]
    fn record_destroy_surfaces_in_changes() {
        let id = fixed_object_id(0x22);
        let mut buf = TransactionStateBuffer::new();
        buf.record_destroy(id);
        let changes = buf.into_changes();
        assert!(changes.created.is_empty());
        assert!(changes.updated.is_empty());
        assert_eq!(changes.destroyed, vec![id]);
    }

    /// Whitepaper §6.2.2 step 5 (verbatim): "State changes are
    /// accumulated in a transaction-local buffer; chain state is
    /// not mutated until execution succeeds."
    ///
    /// Recording a create followed by an update for the same
    /// `ObjectId` collapses to a single create entry with the
    /// updated value. The intermediate state is invisible to
    /// chain state per the "transaction-local buffer" framing.
    #[test]
    fn create_then_update_collapses_to_create_with_latest_value() {
        let id = fixed_object_id(0x23);
        let mut buf = TransactionStateBuffer::new();
        buf.record_create(make_object(id, 1));
        // The runtime would not normally update an object's
        // version field in the same transaction that created it
        // (creation pins version=1 per §5.4 step 1); this test
        // uses contents-mutation distinguishability via the
        // version field for shape-pinning purposes only.
        let mut updated = make_object(id, 1);
        updated.contents = Contents::from_bytes(b"updated").expect("valid");
        buf.record_update(updated);

        let changes = buf.into_changes();
        assert_eq!(changes.created.len(), 1);
        assert!(changes.updated.is_empty());
        assert_eq!(
            changes.created[0].contents.as_bytes(),
            b"updated",
            "the latest value won; intermediate is invisible"
        );
    }

    /// Whitepaper §6.2.2 step 5 + §5.4.1.
    ///
    /// Recording a create followed by a destroy for the same
    /// `ObjectId` collapses to a no-op. The object never appears
    /// in chain state — neither as created nor as destroyed.
    #[test]
    fn create_then_destroy_collapses_to_noop() {
        let id = fixed_object_id(0x24);
        let mut buf = TransactionStateBuffer::new();
        buf.record_create(make_object(id, 1));
        buf.record_destroy(id);

        let changes = buf.into_changes();
        assert!(changes.is_empty());
    }
}
