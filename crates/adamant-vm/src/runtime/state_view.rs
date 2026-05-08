//! Read-side state interface — whitepaper §6.2.2 step 2.
//!
//! Per Phase 5/6 plan-gate Q8 disposition, the runtime operates
//! against a [`StateView`] trait abstraction rather than against
//! a concrete chain-state backend. Same posture as
//! [`crate::validator::cross_module::ModuleResolver`] at Phase
//! 5/5b.5 E-2a.
//!
//! # Whitepaper §6.2.2 step 2 (verbatim)
//!
//! > "Object loading. All objects referenced by the transaction
//! > are loaded from chain state. The transaction declares its
//! > read-set and write-set in advance; the loader validates that
//! > the transaction touches no objects outside its declared sets."
//!
//! # Version-pinning per whitepaper §6.0.2
//!
//! > "The version pin protects against read-write conflicts: if
//! > any read object's version has advanced beyond the declared
//! > version at execution time, the transaction is rejected
//! > without execution."
//!
//! [`StateView::load_object`] takes the declared `expected_version`
//! and returns [`LoadError::VersionMismatch`] when the object's
//! current version differs.

use adamant_types::{Object, ObjectId};

/// Read-side view into chain state.
///
/// Implemented by:
///
/// - **Production:** RocksDB-backed chain-state implementation
///   landing in the Phase 4 object-storage backfill workstream
///   (parallel to Phase 5/6; not a Phase 5/6 prerequisite).
/// - **Test-only:** [`crate::runtime::test_helpers::InMemoryStateView`]
///   backed by a [`HashMap`], mirroring
///   [`crate::validator::cross_module::test_helpers::InMemoryModuleResolver`]
///   at Phase 5/5b.5 E-2a.
///
/// [`HashMap`]: std::collections::HashMap
pub trait StateView {
    /// Load the object identified by `id`, asserting the loaded
    /// object's `version` field equals `expected_version`.
    ///
    /// Per whitepaper §6.2.2 step 2 + §6.0.2's version-pinning
    /// requirement. The `expected_version` argument is taken from
    /// the transaction's declared `read_set: Vec<(ObjectId,
    /// Version)>` per §6.0.2. A version mismatch at execution time
    /// rejects the transaction without execution.
    ///
    /// # Errors
    ///
    /// - [`LoadError::ObjectNotFound`] — no object exists in
    ///   chain state for `id`.
    /// - [`LoadError::VersionMismatch`] — an object exists for
    ///   `id` but its `version` field differs from
    ///   `expected_version`.
    /// - [`LoadError::ObjectArchived`] — the object exists but
    ///   is in [`adamant_types::Lifecycle::Archived`] state per
    ///   whitepaper §5.4.1; archived objects "cannot be referenced
    ///   by new transactions until restored" per §5.6.2.
    /// - [`LoadError::ObjectDestroyed`] — the object exists in
    ///   chain history but is in [`adamant_types::Lifecycle::Destroyed`]
    ///   state per §5.4.1; "Destroyed is terminal" and "any
    ///   subsequent reference to the `ObjectId` is invalid at the
    ///   consensus layer."
    fn load_object(&self, id: &ObjectId, expected_version: u64) -> Result<Object, LoadError>;
}

/// Errors returned by [`StateView::load_object`].
///
/// Each variant maps to a specific whitepaper-defined rejection
/// condition; documented in the [`StateView::load_object`]
/// `# Errors` section.
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub enum LoadError {
    /// No object exists in chain state for the given `ObjectId`.
    ///
    /// Either the object was never created or it was destroyed
    /// and pruned past the chain's destroyed-object retention
    /// horizon. Distinguished from [`Self::ObjectDestroyed`] which
    /// covers the case where the destroyed-object record is still
    /// retained.
    ObjectNotFound {
        /// The `ObjectId` that was not found.
        id: ObjectId,
    },

    /// An object exists for the given `ObjectId` but its `version`
    /// field differs from the transaction's declared
    /// `expected_version`.
    ///
    /// Per whitepaper §6.0.2: "if any read object's version has
    /// advanced beyond the declared version at execution time,
    /// the transaction is rejected without execution." The
    /// canonical case is a read-write conflict where another
    /// transaction committed a version increment between the
    /// transaction's submission and its execution.
    VersionMismatch {
        /// The `ObjectId` whose version diverged.
        id: ObjectId,
        /// The version the transaction declared in its `read_set`.
        expected: u64,
        /// The current version of the object in chain state.
        actual: u64,
    },

    /// The object exists but is in [`adamant_types::Lifecycle::Archived`]
    /// state.
    ///
    /// Per whitepaper §5.6.2: "Archived objects cannot be
    /// referenced by new transactions until restored." Restoration
    /// requires paying accumulated rent plus a restoration fee
    /// and submitting a contents proof.
    ObjectArchived {
        /// The archived object's `ObjectId`.
        id: ObjectId,
    },

    /// The object exists in chain history but is in
    /// [`adamant_types::Lifecycle::Destroyed`] state.
    ///
    /// Per whitepaper §5.4.1: "Destroyed is terminal. No transition
    /// out of `Destroyed` exists. Any transaction referencing a
    /// destroyed `ObjectId` is invalid at the consensus layer."
    ObjectDestroyed {
        /// The destroyed object's `ObjectId`.
        id: ObjectId,
    },
}

#[cfg(test)]
mod tests {
    //! Each test's doc-comment registers a verbatim whitepaper
    //! quote from §6.2.2 / §5.4.1 / §5.6.2 / §6.0.2 grounding the
    //! expected outcome — 1st instance of the verbatim-spec-quote-
    //! grounds-runtime-fixture discipline introduced at Phase
    //! 5/6.1 plan-gate Q1.4.

    use super::*;
    use crate::runtime::test_helpers::InMemoryStateView;

    use adamant_types::{
        metadata::{ObjectMetadata, ProofCommitment, PROOF_COMMITMENT_BYTES},
        Address, Contents, Lifecycle, Mutability, Ownership, TypeId,
    };

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

    /// Whitepaper §6.2.2 step 2 (verbatim): "All objects referenced
    /// by the transaction are loaded from chain state. The
    /// transaction declares its read-set and write-set in advance."
    ///
    /// Loading an object that exists at the declared version
    /// succeeds.
    #[test]
    fn load_object_succeeds_when_object_exists_at_expected_version() {
        let id = fixed_object_id(0x01);
        let mut view = InMemoryStateView::new();
        view.insert(make_active_object(id, 5));

        let loaded = view.load_object(&id, 5).expect("load succeeds");
        assert_eq!(loaded.id, id);
        assert_eq!(loaded.version, 5);
    }

    /// Whitepaper §6.2.2 step 2 (verbatim): "All objects referenced
    /// by the transaction are loaded from chain state."
    ///
    /// Loading an `ObjectId` that does not exist surfaces
    /// `LoadError::ObjectNotFound`.
    #[test]
    fn load_object_fails_with_object_not_found_when_id_unknown() {
        let id = fixed_object_id(0x02);
        let view = InMemoryStateView::new();

        let err = view.load_object(&id, 1).expect_err("load fails");
        assert_eq!(err, LoadError::ObjectNotFound { id });
    }

    /// Whitepaper §6.0.2 (verbatim): "The version pin protects
    /// against read-write conflicts: if any read object's version
    /// has advanced beyond the declared version at execution time,
    /// the transaction is rejected without execution."
    ///
    /// Loading an object whose current version differs from the
    /// declared `expected_version` surfaces
    /// `LoadError::VersionMismatch`.
    #[test]
    fn load_object_fails_with_version_mismatch_when_version_diverged() {
        let id = fixed_object_id(0x03);
        let mut view = InMemoryStateView::new();
        view.insert(make_active_object(id, 7));

        let err = view.load_object(&id, 5).expect_err("load fails");
        assert_eq!(
            err,
            LoadError::VersionMismatch {
                id,
                expected: 5,
                actual: 7,
            }
        );
    }

    /// Whitepaper §5.6.2 (verbatim): "Archived objects cannot be
    /// referenced by new transactions until restored."
    ///
    /// Loading an `Archived` object surfaces
    /// `LoadError::ObjectArchived` regardless of version pin.
    #[test]
    fn load_object_fails_with_object_archived_when_lifecycle_is_archived() {
        let id = fixed_object_id(0x04);
        let mut view = InMemoryStateView::new();
        let mut obj = make_active_object(id, 3);
        obj.lifecycle = Lifecycle::Archived;
        view.insert(obj);

        let err = view.load_object(&id, 3).expect_err("load fails");
        assert_eq!(err, LoadError::ObjectArchived { id });
    }

    /// Whitepaper §5.4.1 (verbatim): "Destroyed is terminal. ... Any
    /// transaction referencing a destroyed `ObjectId` is invalid at
    /// the consensus layer."
    ///
    /// Loading a `Destroyed` object surfaces
    /// `LoadError::ObjectDestroyed` regardless of version pin.
    #[test]
    fn load_object_fails_with_object_destroyed_when_lifecycle_is_destroyed() {
        let id = fixed_object_id(0x05);
        let mut view = InMemoryStateView::new();
        let mut obj = make_active_object(id, 3);
        obj.lifecycle = Lifecycle::Destroyed;
        view.insert(obj);

        let err = view.load_object(&id, 3).expect_err("load fails");
        assert_eq!(err, LoadError::ObjectDestroyed { id });
    }
}
