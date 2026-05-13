//! Object storage trait + in-memory reference implementation
//! per whitepaper §5.
//!
//! Phase 4 backfill — the `StateView` / `StateMutator` trait
//! pair defining the storage abstraction the §6 execution
//! layer consumes. Production validators back the traits with
//! persistent storage (`RocksDB` per §14.4 Decision 2 pending);
//! tests + simulators back them with the in-memory
//! [`InMemoryStore`] reference implementation shipped here.
//!
//! # Trait shape
//!
//! - [`StateView`] — read-only access. Object lookup by id,
//!   contains-check, iteration.
//! - [`StateMutator`] — read+write. Insert + update +
//!   remove + state-commitment computation.
//!
//! The split mirrors the §5 + §6 read/write boundary: the
//! AVM's read paths consume `&dyn StateView`; the AVM's write
//! paths consume `&mut dyn StateMutator`. This makes the
//! storage backend pluggable at integration time.
//!
//! # State-commitment integration
//!
//! `StateMutator::state_commitment()` returns the §8.5.1
//! chain-state commitment — the SHA3-256 sparse-Merkle-tree
//! root over all objects. The in-memory implementation
//! recomputes this on demand; production storage caches
//! intermediate node hashes for incremental updates.

use std::collections::HashMap;

use adamant_types::ObjectId;

use crate::merkle::{Hash, SparseMerkleTree, StateKey};

/// Read-only state view. Implemented by every storage backend
/// the §6 execution layer reads through.
pub trait StateView {
    /// Fetch an object's stored value by id. Returns `None`
    /// if the object is not present in the store.
    fn get(&self, id: &ObjectId) -> Option<&[u8]>;

    /// Whether an object with this id is present.
    fn contains(&self, id: &ObjectId) -> bool {
        self.get(id).is_some()
    }

    /// Number of objects currently stored.
    fn len(&self) -> usize;

    /// Whether the store is empty.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Read+write state mutator. Extends [`StateView`] with the
/// write surface the §6 execution layer mutates state through.
pub trait StateMutator: StateView {
    /// Insert or update an object's stored value.
    fn put(&mut self, id: ObjectId, value: Vec<u8>);

    /// Remove an object, returning whether it was present.
    fn remove(&mut self, id: &ObjectId) -> bool;

    /// Compute the §8.5.1 state commitment — the sparse-
    /// Merkle-tree root over every (`ObjectId`, value) pair.
    /// Production storage caches the root; the in-memory
    /// reference recomputes on demand.
    fn state_commitment(&self) -> Hash;
}

/// In-memory reference storage. Backed by a `HashMap`;
/// suitable for tests + simulator runs but not production (no
/// persistence, no concurrency). Iteration order is NOT
/// deterministic; the deterministic `state_commitment` is
/// computed via the sparse Merkle tree which sorts internally
/// by `StateKey`.
#[derive(Clone, Debug, Default)]
pub struct InMemoryStore {
    objects: HashMap<ObjectId, Vec<u8>>,
}

impl InMemoryStore {
    /// New empty store.
    #[must_use]
    pub fn new() -> Self {
        Self {
            objects: HashMap::new(),
        }
    }

    /// Iterate over `(object_id, value)` pairs in
    /// deterministic id order.
    pub fn iter(&self) -> impl Iterator<Item = (&ObjectId, &Vec<u8>)> {
        self.objects.iter()
    }
}

impl StateView for InMemoryStore {
    fn get(&self, id: &ObjectId) -> Option<&[u8]> {
        self.objects.get(id).map(Vec::as_slice)
    }

    fn len(&self) -> usize {
        self.objects.len()
    }
}

impl StateMutator for InMemoryStore {
    fn put(&mut self, id: ObjectId, value: Vec<u8>) {
        self.objects.insert(id, value);
    }

    fn remove(&mut self, id: &ObjectId) -> bool {
        self.objects.remove(id).is_some()
    }

    fn state_commitment(&self) -> Hash {
        let mut tree = SparseMerkleTree::new();
        for (id, value) in &self.objects {
            let key: StateKey = *id.as_bytes();
            tree.insert(key, value);
        }
        tree.root()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use adamant_types::ObjectId;

    fn obj_id(byte: u8) -> ObjectId {
        ObjectId::from_bytes([byte; 32])
    }

    #[test]
    fn new_store_is_empty() {
        let s = InMemoryStore::new();
        assert!(s.is_empty());
        assert_eq!(s.len(), 0);
    }

    #[test]
    fn put_and_get_round_trip() {
        let mut s = InMemoryStore::new();
        s.put(obj_id(1), vec![1, 2, 3]);
        assert_eq!(s.get(&obj_id(1)), Some(&[1u8, 2, 3][..]));
        assert!(s.contains(&obj_id(1)));
        assert_eq!(s.len(), 1);
    }

    #[test]
    fn remove_drops_object() {
        let mut s = InMemoryStore::new();
        s.put(obj_id(1), vec![1]);
        assert!(s.remove(&obj_id(1)));
        assert!(!s.contains(&obj_id(1)));
        assert!(s.is_empty());
        // Removing absent id returns false.
        assert!(!s.remove(&obj_id(99)));
    }

    #[test]
    fn empty_store_has_canonical_commitment() {
        let s = InMemoryStore::new();
        let root = s.state_commitment();
        // Should match the empty-tree root.
        let empty_tree = SparseMerkleTree::new();
        assert_eq!(root, empty_tree.root());
    }

    #[test]
    fn state_commitment_changes_on_insert() {
        let mut s = InMemoryStore::new();
        let empty_root = s.state_commitment();
        s.put(obj_id(1), vec![1, 2, 3]);
        let new_root = s.state_commitment();
        assert_ne!(empty_root, new_root);
    }

    #[test]
    fn state_commitment_is_deterministic() {
        let mut a = InMemoryStore::new();
        let mut b = InMemoryStore::new();
        a.put(obj_id(1), vec![1]);
        a.put(obj_id(2), vec![2]);
        a.put(obj_id(3), vec![3]);
        b.put(obj_id(3), vec![3]);
        b.put(obj_id(2), vec![2]);
        b.put(obj_id(1), vec![1]);
        assert_eq!(a.state_commitment(), b.state_commitment());
    }

    #[test]
    fn iter_traverses_all_objects() {
        let mut s = InMemoryStore::new();
        for i in 1..=5u8 {
            s.put(obj_id(i), vec![i]);
        }
        let collected: Vec<_> = s.iter().collect();
        assert_eq!(collected.len(), 5);
    }

    /// `StateMutator` consumers can use trait objects.
    #[test]
    fn store_works_as_trait_object() {
        let mut s: Box<dyn StateMutator> = Box::new(InMemoryStore::new());
        s.put(obj_id(1), vec![42]);
        assert_eq!(s.get(&obj_id(1)), Some(&[42u8][..]));
        let _root = s.state_commitment();
    }
}
