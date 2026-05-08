//! In-memory [`StateView`] + [`StateMutator`] implementations for
//! tests.
//!
//! Mirrors the [`crate::validator::cross_module::test_helpers::InMemoryModuleResolver`]
//! shape established at Phase 5/5b.5 E-2a. Tests use these
//! implementations to exercise runtime logic without depending on
//! the chain-state backend; the production-side concrete
//! implementations land in the Phase 4 object-storage backfill
//! workstream.

use std::collections::HashMap;

use adamant_types::{Lifecycle, Object, ObjectId};

use crate::runtime::state_mutator::{CommitError, StateMutator, TransactionStateChanges};
use crate::runtime::state_view::{LoadError, StateView};

/// In-memory [`StateView`] backed by a [`HashMap`] keyed by
/// [`ObjectId`].
///
/// Test fixtures populate the map via [`Self::insert`] before
/// invoking runtime logic.
#[derive(Debug, Default, Clone)]
pub(in crate::runtime) struct InMemoryStateView {
    objects: HashMap<ObjectId, Object>,
}

impl InMemoryStateView {
    /// Construct an empty view.
    #[must_use]
    pub(in crate::runtime) fn new() -> Self {
        Self::default()
    }

    /// Insert or replace the object at `id`. Tests use this to
    /// populate the view before invoking runtime logic.
    pub(in crate::runtime) fn insert(&mut self, object: Object) {
        self.objects.insert(object.id, object);
    }
}

impl StateView for InMemoryStateView {
    fn load_object(&self, id: &ObjectId, expected_version: u64) -> Result<Object, LoadError> {
        let object = self
            .objects
            .get(id)
            .cloned()
            .ok_or(LoadError::ObjectNotFound { id: *id })?;
        match object.lifecycle {
            Lifecycle::Archived => return Err(LoadError::ObjectArchived { id: *id }),
            Lifecycle::Destroyed => return Err(LoadError::ObjectDestroyed { id: *id }),
            Lifecycle::Active | Lifecycle::Frozen => {}
        }
        if object.version != expected_version {
            return Err(LoadError::VersionMismatch {
                id: *id,
                expected: expected_version,
                actual: object.version,
            });
        }
        Ok(object)
    }
}

/// In-memory [`StateMutator`] backed by a [`HashMap`] keyed by
/// [`ObjectId`].
#[derive(Debug, Default, Clone)]
pub(in crate::runtime) struct InMemoryStateMutator {
    objects: HashMap<ObjectId, Object>,
}

impl InMemoryStateMutator {
    /// Construct an empty mutator.
    #[must_use]
    pub(in crate::runtime) fn new() -> Self {
        Self::default()
    }

    /// Insert or replace the object at `id`. Tests use this to
    /// populate the mutator's pre-state before invoking runtime
    /// commit logic.
    pub(in crate::runtime) fn insert(&mut self, object: Object) {
        self.objects.insert(object.id, object);
    }

    /// Read-only accessor for inspecting committed state in tests.
    #[must_use]
    pub(in crate::runtime) fn get(&self, id: &ObjectId) -> Option<&Object> {
        self.objects.get(id)
    }

    /// Number of objects currently held by the mutator.
    #[must_use]
    pub(in crate::runtime) fn len(&self) -> usize {
        self.objects.len()
    }

    /// Whether the mutator holds no objects.
    #[must_use]
    pub(in crate::runtime) fn is_empty(&self) -> bool {
        self.objects.is_empty()
    }
}

impl StateMutator for InMemoryStateMutator {
    fn commit(&mut self, changes: TransactionStateChanges) -> Result<(), CommitError> {
        // Pre-validate every change before applying any. Per
        // whitepaper §6.2.2 step 7, commit is atomic — either all
        // changes apply or none do. The HashMap-backed in-memory
        // mutator achieves atomicity by validating first and
        // applying second.
        for created in &changes.created {
            if self.objects.contains_key(&created.id) {
                return Err(CommitError::ObjectIdCollision { id: created.id });
            }
        }
        for updated in &changes.updated {
            // Per TransactionStateBuffer invariant (3), updated
            // entries' version is the post-increment version
            // (one greater than the version at load time). The
            // mutator validates that the pre-update version
            // matches the version currently in chain state.
            let expected_pre_version = updated.version.saturating_sub(1);
            match self.objects.get(&updated.id) {
                Some(existing) if existing.version == expected_pre_version => {}
                Some(existing) => {
                    return Err(CommitError::ConflictingWrite {
                        id: updated.id,
                        expected_pre_version,
                        actual_pre_version: existing.version,
                    });
                }
                None => {
                    return Err(CommitError::ConflictingWrite {
                        id: updated.id,
                        expected_pre_version,
                        actual_pre_version: 0,
                    });
                }
            }
        }
        // All validations passed. Apply changes.
        for created in changes.created {
            self.objects.insert(created.id, created);
        }
        for updated in changes.updated {
            self.objects.insert(updated.id, updated);
        }
        for destroyed in changes.destroyed {
            // Per whitepaper §5.4.1, destruction transitions the
            // object's Lifecycle to Destroyed; the ObjectId
            // cannot be reused. The in-memory mutator keeps the
            // object record with the lifecycle field flipped to
            // Destroyed so that subsequent loads surface
            // LoadError::ObjectDestroyed rather than ObjectNotFound.
            if let Some(existing) = self.objects.get_mut(&destroyed) {
                existing.lifecycle = Lifecycle::Destroyed;
            }
        }
        Ok(())
    }
}
