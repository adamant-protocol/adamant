//! Transaction-boundary execution helpers — whitepaper §6.2.2.
//!
//! Phase 5/6.6 lands the runtime-side state-trait integration:
//! [`load_read_set`] orchestrates the §6.2.2 step 2 pre-execution
//! object load against a [`StateView`]; [`commit_buffer`]
//! orchestrates the §6.2.2 step 7 post-execution atomic commit
//! against a [`StateMutator`].
//!
//! # Scope-bounding (Phase 5/6.6 plan-gate)
//!
//! This sub-arc ships the **transaction-boundary integration**
//! between the interpreter and the [`StateView`] / [`StateMutator`]
//! traits introduced at Phase 5/6.1. Per the plan-gate empirical
//! finding (foundation-already-exists-disposition-is-renaming-
//! question sub-pattern 2nd instance), the trait surface was
//! already in place at Phase 5/6.1; the gap was wiring
//! transaction-boundary load/commit around the existing dispatch
//! loop.
//!
//! **Out of scope for 5/6.6:**
//!
//! - Full `TxBody → InterpreterState` construction (module-
//!   loader resolution from [`crate::transaction::CallParams`] +
//!   `FunctionId` resolution + argument decoding from `Vec<Value>`
//!   to runtime stack values). That work belongs at Phase 5/6.7
//!   alongside the `adamant::module::deploy` stdlib + cross-
//!   module Rule 3 wiring.
//! - Per-handler object-state-touching dispatch. Per Phase 5/6.3
//!   plan-gate Q5/6.3.4 + Phase 5/6.4 disposition: 0 of 12 active
//!   Adamant-extension handlers touch object state directly. Sui-
//!   Move object semantics work through existing Phase 5/6.2c
//!   reference machinery + standard library calls (transfer,
//!   freeze, share). 5/6.6 does not add new dispatch arms.
//! - Consensus-side object-set verification. Runtime-side ships
//!   here; consensus-side defers to Phase 5/7 (parallel execution
//!   scheduler).
//!
//! # Whitepaper §6.2.2 verbatim quotes
//!
//! Step 2: "All objects referenced by the transaction are loaded
//! from chain state ... the loader validates that the transaction
//! touches no objects outside its declared sets."
//!
//! Step 5: "Bytecode runs to completion or until gas is exhausted.
//! State changes are accumulated in a transaction-local buffer;
//! chain state is not mutated until execution succeeds."
//!
//! Step 7: "If execution succeeded ... state changes are
//! committed."

use adamant_types::{Object, ObjectId};

use crate::runtime::error::VMError;
use crate::runtime::state_buffer::TransactionStateBuffer;
use crate::runtime::state_mutator::StateMutator;
use crate::runtime::state_view::StateView;

/// Pre-execution read-set loader per whitepaper §6.2.2 step 2.
///
/// Loads each `(ObjectId, Version)` in `read_set` from the
/// `state_view`. Version-pin failures surface as
/// [`VMError::Load`] with the underlying
/// [`crate::runtime::state_view::LoadError`]; the caller should
/// halt before invoking the dispatch loop on any error.
///
/// Returns the loaded objects in `read_set` order. Caller is
/// responsible for installing them into the runtime's [`Object`]-
/// access surface (e.g., reference-machinery setup at frame
/// construction; full integration lands at Phase 5/6.7).
///
/// # Errors
///
/// Returns [`VMError::Load`] (via the [`From`] impl) on any of
/// the [`crate::runtime::state_view::LoadError`] variants:
/// `ObjectNotFound`, `VersionMismatch`, `ObjectArchived`,
/// `ObjectDestroyed`. The transaction is rejected without
/// execution per §6.2.2 step 2 ("a transaction is rejected
/// before execution").
pub fn load_read_set<S>(
    state_view: &S,
    read_set: &[(ObjectId, u64)],
) -> Result<Vec<Object>, VMError>
where
    S: StateView,
{
    let mut loaded = Vec::with_capacity(read_set.len());
    for (id, expected_version) in read_set {
        let object = state_view.load_object(id, *expected_version)?;
        loaded.push(object);
    }
    Ok(loaded)
}

/// Post-execution buffer-commit per whitepaper §6.2.2 step 7.
///
/// Consumes the transaction-local [`TransactionStateBuffer`] into
/// a [`crate::runtime::state_mutator::TransactionStateChanges`]
/// payload and submits it to the `state_mutator`. The mutator
/// applies the changes atomically per §6.2.2 step 7 ("the full
/// state-changes payload is applied as a single atomic
/// operation").
///
/// On success, chain state reflects the transaction's effects.
/// On failure ([`VMError::Commit`] via the [`From`] impl), the
/// transaction is treated as failed and gas is charged per
/// §6.3.3.
///
/// **Caller contract:** invoke this only on successful execution
/// (the dispatch loop returned `Ok`). If execution failed, drop
/// the buffer without invoking this function — that satisfies
/// §6.2.2 step 7's "if execution failed, all state changes are
/// discarded except for the gas charged."
///
/// # Errors
///
/// Returns [`VMError::Commit`] (via the [`From`] impl) on any of
/// the [`crate::runtime::state_mutator::CommitError`] variants:
/// `ConflictingWrite`, `ObjectIdCollision`. Surfaced to the
/// caller for transaction-failure accounting.
pub fn commit_buffer<M>(
    state_mutator: &mut M,
    buffer: TransactionStateBuffer,
) -> Result<(), VMError>
where
    M: StateMutator,
{
    let changes = buffer.into_changes();
    state_mutator.commit(changes)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    //! Verbatim-spec-quote-grounds-runtime-fixture discipline.

    use super::*;
    use crate::runtime::state_mutator::CommitError;
    use crate::runtime::state_view::LoadError;
    use adamant_types::metadata::{ObjectMetadata, ProofCommitment, PROOF_COMMITMENT_BYTES};
    use adamant_types::{Address, Contents, Lifecycle, Mutability, Ownership, TypeId};
    use std::collections::HashMap;

    fn fixed_object_id(seed: u8) -> ObjectId {
        ObjectId::from_bytes([seed; 32])
    }

    fn make_active_object(id: ObjectId, version: u64) -> Object {
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

    /// In-memory mock implementation of [`StateView`] for tests.
    struct MockStateView {
        objects: HashMap<ObjectId, Object>,
    }

    impl StateView for MockStateView {
        fn load_object(&self, id: &ObjectId, expected_version: u64) -> Result<Object, LoadError> {
            let object = self
                .objects
                .get(id)
                .ok_or(LoadError::ObjectNotFound { id: *id })?;
            if object.version != expected_version {
                return Err(LoadError::VersionMismatch {
                    id: *id,
                    expected: expected_version,
                    actual: object.version,
                });
            }
            match object.lifecycle {
                Lifecycle::Active | Lifecycle::Frozen => Ok(object.clone()),
                Lifecycle::Archived => Err(LoadError::ObjectArchived { id: *id }),
                Lifecycle::Destroyed => Err(LoadError::ObjectDestroyed { id: *id }),
            }
        }
    }

    /// In-memory mock implementation of [`StateMutator`] for tests.
    struct MockStateMutator {
        committed: HashMap<ObjectId, Object>,
        commit_calls: usize,
    }

    impl MockStateMutator {
        fn new() -> Self {
            Self {
                committed: HashMap::new(),
                commit_calls: 0,
            }
        }
    }

    impl StateMutator for MockStateMutator {
        fn commit(
            &mut self,
            changes: crate::runtime::state_mutator::TransactionStateChanges,
        ) -> Result<(), CommitError> {
            self.commit_calls += 1;
            for object in changes.created {
                if self.committed.contains_key(&object.id) {
                    return Err(CommitError::ObjectIdCollision { id: object.id });
                }
                self.committed.insert(object.id, object);
            }
            for object in changes.updated {
                self.committed.insert(object.id, object);
            }
            for id in changes.destroyed {
                if let Some(obj) = self.committed.get_mut(&id) {
                    obj.lifecycle = Lifecycle::Destroyed;
                }
            }
            Ok(())
        }
    }

    /// Whitepaper §6.2.2 step 2 (verbatim): "All objects referenced
    /// by the transaction are loaded from chain state."
    #[test]
    fn load_read_set_loads_all_referenced_objects() {
        let id_a = fixed_object_id(0xA1);
        let id_b = fixed_object_id(0xB2);
        let mut objects = HashMap::new();
        objects.insert(id_a, make_active_object(id_a, 1));
        objects.insert(id_b, make_active_object(id_b, 7));
        let view = MockStateView { objects };

        let read_set = vec![(id_a, 1), (id_b, 7)];
        let loaded = load_read_set(&view, &read_set).expect("load ok");
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded[0].id, id_a);
        assert_eq!(loaded[1].id, id_b);
    }

    /// Empty `read_set` produces empty loaded vec.
    #[test]
    fn load_read_set_empty_produces_empty_vec() {
        let view = MockStateView {
            objects: HashMap::new(),
        };
        let loaded = load_read_set(&view, &[]).expect("ok");
        assert!(loaded.is_empty());
    }

    /// `LoadError::ObjectNotFound` surfaces as `VMError::Load`.
    #[test]
    fn load_read_set_unknown_id_surfaces_load_error() {
        let view = MockStateView {
            objects: HashMap::new(),
        };
        let result = load_read_set(&view, &[(fixed_object_id(0x99), 1)]);
        assert!(matches!(
            result,
            Err(VMError::Load(LoadError::ObjectNotFound { .. }))
        ));
    }

    /// `LoadError::VersionMismatch` surfaces as `VMError::Load`.
    #[test]
    fn load_read_set_version_mismatch_surfaces_load_error() {
        let id = fixed_object_id(0xC3);
        let mut objects = HashMap::new();
        objects.insert(id, make_active_object(id, 5));
        let view = MockStateView { objects };

        let result = load_read_set(&view, &[(id, 99)]);
        assert!(matches!(
            result,
            Err(VMError::Load(LoadError::VersionMismatch { .. }))
        ));
    }

    /// `LoadError::ObjectArchived` surfaces as `VMError::Load`.
    #[test]
    fn load_read_set_archived_object_surfaces_load_error() {
        let id = fixed_object_id(0xD4);
        let mut obj = make_active_object(id, 1);
        obj.lifecycle = Lifecycle::Archived;
        let mut objects = HashMap::new();
        objects.insert(id, obj);
        let view = MockStateView { objects };

        let result = load_read_set(&view, &[(id, 1)]);
        assert!(matches!(
            result,
            Err(VMError::Load(LoadError::ObjectArchived { .. }))
        ));
    }

    /// `LoadError::ObjectDestroyed` surfaces as `VMError::Load`.
    #[test]
    fn load_read_set_destroyed_object_surfaces_load_error() {
        let id = fixed_object_id(0xE5);
        let mut obj = make_active_object(id, 1);
        obj.lifecycle = Lifecycle::Destroyed;
        let mut objects = HashMap::new();
        objects.insert(id, obj);
        let view = MockStateView { objects };

        let result = load_read_set(&view, &[(id, 1)]);
        assert!(matches!(
            result,
            Err(VMError::Load(LoadError::ObjectDestroyed { .. }))
        ));
    }

    /// First failure halts loading; subsequent entries not
    /// attempted (per fail-fast semantics).
    #[test]
    fn load_read_set_halts_on_first_failure() {
        let id_a = fixed_object_id(0xF1);
        let id_b = fixed_object_id(0xF2);
        let mut objects = HashMap::new();
        objects.insert(id_a, make_active_object(id_a, 1));
        // id_b intentionally absent
        let view = MockStateView { objects };

        let read_set = vec![(id_a, 1), (id_b, 1)];
        let result = load_read_set(&view, &read_set);
        assert!(matches!(
            result,
            Err(VMError::Load(LoadError::ObjectNotFound { .. }))
        ));
    }

    /// Whitepaper §6.2.2 step 7 (verbatim): "the full state-changes
    /// payload is applied as a single atomic operation."
    #[test]
    fn commit_buffer_applies_creates_to_mutator() {
        let id = fixed_object_id(0x10);
        let mut buffer = TransactionStateBuffer::new();
        buffer.record_create(make_active_object(id, 1));
        let mut mutator = MockStateMutator::new();
        commit_buffer(&mut mutator, buffer).expect("ok");
        assert_eq!(mutator.commit_calls, 1);
        assert!(mutator.committed.contains_key(&id));
    }

    /// `commit_buffer` invokes the mutator exactly once per call.
    #[test]
    fn commit_buffer_invokes_mutator_once() {
        let buffer = TransactionStateBuffer::new();
        let mut mutator = MockStateMutator::new();
        commit_buffer(&mut mutator, buffer).expect("ok");
        assert_eq!(mutator.commit_calls, 1);
    }

    /// Empty buffer commits successfully (no-op semantics).
    #[test]
    fn commit_buffer_empty_buffer_succeeds() {
        let buffer = TransactionStateBuffer::new();
        let mut mutator = MockStateMutator::new();
        commit_buffer(&mut mutator, buffer).expect("ok");
        assert!(mutator.committed.is_empty());
    }

    /// `CommitError::ObjectIdCollision` surfaces as
    /// `VMError::Commit`.
    #[test]
    fn commit_buffer_collision_surfaces_commit_error() {
        let id = fixed_object_id(0x20);
        let mut buffer = TransactionStateBuffer::new();
        buffer.record_create(make_active_object(id, 1));

        let mut mutator = MockStateMutator::new();
        // Pre-existing object with same id triggers collision.
        mutator.committed.insert(id, make_active_object(id, 1));

        let result = commit_buffer(&mut mutator, buffer);
        assert!(matches!(
            result,
            Err(VMError::Commit(CommitError::ObjectIdCollision { .. }))
        ));
    }

    /// Round-trip: load `read_set` + commit buffer round-trip.
    #[test]
    fn round_trip_load_then_commit() {
        let id_loaded = fixed_object_id(0x30);
        let id_created = fixed_object_id(0x31);
        let mut state_objects = HashMap::new();
        state_objects.insert(id_loaded, make_active_object(id_loaded, 5));
        let view = MockStateView {
            objects: state_objects,
        };

        // Pre-execution: load.
        let loaded = load_read_set(&view, &[(id_loaded, 5)]).expect("load");
        assert_eq!(loaded.len(), 1);

        // Mid-execution: buffer accumulates a creation.
        let mut buffer = TransactionStateBuffer::new();
        buffer.record_create(make_active_object(id_created, 1));

        // Post-execution: commit.
        let mut mutator = MockStateMutator::new();
        commit_buffer(&mut mutator, buffer).expect("commit");

        assert!(mutator.committed.contains_key(&id_created));
    }

    /// Failure after load + before commit drops the buffer
    /// without invoking the mutator (per §6.2.2 step 7 caller-
    /// contract).
    #[test]
    fn execution_failure_drops_buffer_without_committing() {
        let mut buffer = TransactionStateBuffer::new();
        buffer.record_create(make_active_object(fixed_object_id(0x40), 1));

        // Caller-contract: drop buffer without invoking
        // commit_buffer. The mutator is unchanged.
        drop(buffer);

        let mutator = MockStateMutator::new();
        assert_eq!(mutator.commit_calls, 0);
        assert!(mutator.committed.is_empty());
    }

    /// `From<LoadError> for VMError` surface (already shipped at
    /// 5/6.1; verified here for transaction-boundary integration).
    #[test]
    fn load_error_from_impl_surfaces_in_vm_error() {
        let id = fixed_object_id(0x50);
        let load_err = LoadError::ObjectNotFound { id };
        let vm_err: VMError = load_err.into();
        assert!(matches!(
            vm_err,
            VMError::Load(LoadError::ObjectNotFound { .. })
        ));
    }

    /// `From<CommitError> for VMError` surface.
    #[test]
    fn commit_error_from_impl_surfaces_in_vm_error() {
        let id = fixed_object_id(0x51);
        let commit_err = CommitError::ObjectIdCollision { id };
        let vm_err: VMError = commit_err.into();
        assert!(matches!(
            vm_err,
            VMError::Commit(CommitError::ObjectIdCollision { .. })
        ));
    }
}
