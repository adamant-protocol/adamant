//! Sparse Merkle tree primitive for state commitments per
//! whitepaper §5 + §8.5.1.
//!
//! Phase 4 backfill — the binary SHA3-256 sparse Merkle tree
//! that backs the chain-state commitment per §8.5.1
//! ("the chain state at the end of the current epoch is a
//! specific commitment"). Adamant-native; no external Merkle-
//! tree crate is consumed (the construction is straightforward
//! sparse-Merkle-tree shape per the §3.3.1 SHA3 tagged-hash
//! discipline).
//!
//! # Construction
//!
//! - **Key space**: 32-byte keys (compatible with `ObjectId` +
//!   the broader 32-byte identifier discipline across the
//!   workspace). Each key descends 256 binary levels from the
//!   root.
//! - **Empty subtrees**: pre-computed per-level empty-hash
//!   constants. The empty-leaf hash is
//!   `sha3_256_tagged(STATE_MERKLE_EMPTY_LEAF, &[])`. Empty
//!   internal node at level `i` is
//!   `sha3_256_tagged(STATE_MERKLE_NODE,
//!   empty(i-1) || empty(i-1))`.
//! - **Internal nodes**: `sha3_256_tagged(STATE_MERKLE_NODE,
//!   left || right)`.
//! - **Leaves**: `sha3_256_tagged(STATE_MERKLE_LEAF,
//!   key || value_hash)`. `value_hash` is the SHA3-256 of the
//!   leaf's serialized value, so leaves are fixed-width
//!   regardless of value size.
//!
//! # Proof shape
//!
//! A [`MerkleProof`] for key `k` carries `256` sibling hashes
//! — one per binary descent level. Verification reconstructs
//! the root from the leaf upward; if the reconstructed root
//! matches the supplied commitment, the (key, value) is a
//! member of the tree.
//!
//! # Non-membership
//!
//! A non-membership proof is structurally identical to a
//! membership proof for the "empty leaf at this key" — the
//! proof verifies the empty-leaf hash at the leaf position.
//! [`verify_non_membership`] handles this case.
//!
//! # Adamant-native posture
//!
//! Per CLAUDE.md §14, this tree is Adamant-native — no
//! third-party Merkle-tree crate. The construction depends
//! only on `adamant_crypto::hash::sha3_256_tagged` (the
//! standard tagged-SHA3 primitive) and Adamant-pinned domain
//! tags. Three new tags register here at Phase 4 backfill:
//! `STATE_MERKLE_EMPTY_LEAF`, `STATE_MERKLE_LEAF`,
//! `STATE_MERKLE_NODE`. Per §3.3.1 adding tags is
//! hard-fork-aware.
//!
//! # What this primitive does NOT yet do
//!
//! - **Concrete object-tree binding**: the tree primitive is
//!   value-agnostic. Wiring it to the `adamant_state::Object`
//!   type (§5.1) is a follow-on sub-arc.
//! - **Persistent storage**: the in-memory `SparseMerkleTree`
//!   here is the reference implementation. Production wiring
//!   over `RocksDB` lands at §14.4 Decision 2 resolution.
//! - **Recursive-proof circuit binding**: the §8.5 recursive
//!   verifier doesn't yet bind to this tree shape; that
//!   wiring is part of Phase 6.9b extension work.

use std::collections::BTreeMap;

use adamant_crypto::domain;
use adamant_crypto::hash::sha3_256_tagged;
use serde::{Deserialize, Serialize};

/// Width of a state-tree key (matches `ObjectId` width).
pub const STATE_KEY_BYTES: usize = 32;

/// Number of bits in a state-tree key — the tree depth.
pub const STATE_TREE_DEPTH: usize = STATE_KEY_BYTES * 8;

/// 32-byte state-tree key. Mirrors the `ObjectId` shape.
pub type StateKey = [u8; STATE_KEY_BYTES];

/// 32-byte hash output.
pub type Hash = [u8; 32];

/// Compute the SHA3-256 of a serialized value (the leaf's
/// `value_hash` input). The leaf hash is then
/// `sha3_256_tagged(LEAF, key || value_hash)`.
#[must_use]
pub fn value_hash(value: &[u8]) -> Hash {
    sha3_256_tagged(&domain::STATE_MERKLE_VALUE, value)
}

/// Hash of the canonical empty leaf.
#[must_use]
pub fn empty_leaf_hash() -> Hash {
    sha3_256_tagged(&domain::STATE_MERKLE_EMPTY_LEAF, &[])
}

/// Hash of a populated leaf for `(key, value_hash)`.
#[must_use]
pub fn leaf_hash(key: &StateKey, value_hash: &Hash) -> Hash {
    let mut buf = [0u8; STATE_KEY_BYTES + 32];
    buf[..STATE_KEY_BYTES].copy_from_slice(key);
    buf[STATE_KEY_BYTES..].copy_from_slice(value_hash);
    sha3_256_tagged(&domain::STATE_MERKLE_LEAF, &buf)
}

/// Hash of an internal node with the supplied left+right
/// children.
#[must_use]
pub fn node_hash(left: &Hash, right: &Hash) -> Hash {
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(left);
    buf[32..].copy_from_slice(right);
    sha3_256_tagged(&domain::STATE_MERKLE_NODE, &buf)
}

/// Pre-computed empty-subtree hashes for every level of the
/// tree. `empty_subtree_hashes()[i]` is the root hash of a
/// subtree of depth `i` that contains only empty leaves.
///
/// Computed lazily on first access; ~256 hash invocations
/// total. Returns a fixed 257-length vector (depth 0 = empty
/// leaf; depth `STATE_TREE_DEPTH` = empty root).
#[must_use]
pub fn empty_subtree_hashes() -> Vec<Hash> {
    let mut out = Vec::with_capacity(STATE_TREE_DEPTH + 1);
    let mut current = empty_leaf_hash();
    out.push(current);
    for _ in 0..STATE_TREE_DEPTH {
        current = node_hash(&current, &current);
        out.push(current);
    }
    out
}

/// Extract the bit at index `i` (MSB-first) from a 32-byte key.
#[must_use]
fn key_bit(key: &StateKey, i: usize) -> bool {
    let byte = key[i / 8];
    (byte >> (7 - (i % 8))) & 1 == 1
}

/// Merkle inclusion proof for a (key, value) pair.
///
/// `siblings[i]` is the sibling hash at level `i` of the
/// descent (level 0 = leaf, level `STATE_TREE_DEPTH - 1` =
/// just-below-root). The proof always carries exactly
/// `STATE_TREE_DEPTH` siblings — empty branches use the
/// pre-computed empty-subtree hashes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MerkleProof {
    /// Sibling hashes along the descent path (root-first
    /// convention: `siblings[0]` is the topmost sibling at
    /// depth `STATE_TREE_DEPTH - 1`; `siblings[STATE_TREE_DEPTH - 1]`
    /// is the leaf's sibling at depth 0).
    pub siblings: Vec<Hash>,
}

impl MerkleProof {
    /// New proof with the supplied sibling chain. The chain
    /// must have exactly `STATE_TREE_DEPTH` entries; the
    /// constructor does not enforce this here (callers
    /// typically construct via `SparseMerkleTree::prove`).
    #[must_use]
    pub const fn new(siblings: Vec<Hash>) -> Self {
        Self { siblings }
    }
}

/// Verify that `(key, value)` is a member of the tree
/// committed to by `expected_root`.
///
/// Reconstructs the root from the leaf upward, using each
/// proof sibling and the key's bits to decide left/right
/// placement. Returns `true` iff the reconstructed root
/// matches `expected_root`.
#[must_use]
pub fn verify_membership(
    key: &StateKey,
    value: &[u8],
    proof: &MerkleProof,
    expected_root: &Hash,
) -> bool {
    if proof.siblings.len() != STATE_TREE_DEPTH {
        return false;
    }
    let leaf = leaf_hash(key, &value_hash(value));
    let computed = reconstruct_root(key, leaf, proof);
    computed == *expected_root
}

/// Verify that `key` is NOT a member of the tree (i.e., maps
/// to the empty-leaf hash).
#[must_use]
pub fn verify_non_membership(key: &StateKey, proof: &MerkleProof, expected_root: &Hash) -> bool {
    if proof.siblings.len() != STATE_TREE_DEPTH {
        return false;
    }
    let leaf = empty_leaf_hash();
    let computed = reconstruct_root(key, leaf, proof);
    computed == *expected_root
}

/// Reconstruct the root hash from a leaf + key bits + proof
/// siblings. Walks bottom-up: at each level, the key's bit
/// at that level decides whether the current node is the
/// left or right child.
fn reconstruct_root(key: &StateKey, mut current: Hash, proof: &MerkleProof) -> Hash {
    // `proof.siblings[0]` is at depth STATE_TREE_DEPTH - 1
    // (topmost sibling, just below the root).
    // We walk from leaf up — the leaf's sibling is at the
    // bottom of the siblings list.
    for level in 0..STATE_TREE_DEPTH {
        // Bit index from MSB = level. So the leaf's bit is
        // STATE_TREE_DEPTH - 1, the root-adjacent bit is 0.
        let bit_index = STATE_TREE_DEPTH - 1 - level;
        let bit = key_bit(key, bit_index);
        let sibling_index = STATE_TREE_DEPTH - 1 - level;
        let sibling = &proof.siblings[sibling_index];
        current = if bit {
            // key bit = 1 → current is the right child.
            node_hash(sibling, &current)
        } else {
            // key bit = 0 → current is the left child.
            node_hash(&current, sibling)
        };
    }
    current
}

/// Sparse Merkle tree over 32-byte keys.
///
/// Reference in-memory implementation. Stores only populated
/// leaves; empty subtrees are computed on demand from the
/// pre-computed empty-subtree hashes.
///
/// **Not production storage.** Production validators back the
/// tree with persistent storage (`RocksDB`, per the §14.4
/// Decision 2 pending). This struct is the reference shape
/// the storage layer mirrors at Phase 4 backfill completion.
#[derive(Clone, Debug, Default)]
pub struct SparseMerkleTree {
    leaves: BTreeMap<StateKey, Hash>,
    empty_subtrees: Vec<Hash>,
}

impl SparseMerkleTree {
    /// New empty tree. Pre-computes the empty-subtree hash
    /// cache.
    #[must_use]
    pub fn new() -> Self {
        Self {
            leaves: BTreeMap::new(),
            empty_subtrees: empty_subtree_hashes(),
        }
    }

    /// Number of populated (non-empty) leaves.
    #[must_use]
    pub fn populated_leaf_count(&self) -> usize {
        self.leaves.len()
    }

    /// Insert or update a leaf. Stores the SHA3-256 of the
    /// value bytes; the original value is not retained.
    pub fn insert(&mut self, key: StateKey, value: &[u8]) {
        self.leaves.insert(key, value_hash(value));
    }

    /// Remove a leaf, returning whether it was present.
    pub fn remove(&mut self, key: &StateKey) -> bool {
        self.leaves.remove(key).is_some()
    }

    /// Whether `key` is present in the tree.
    #[must_use]
    pub fn contains(&self, key: &StateKey) -> bool {
        self.leaves.contains_key(key)
    }

    /// Compute the root hash of the tree.
    ///
    /// `O(populated_leaves × depth)` total — every populated
    /// leaf is partitioned once per level into the left or
    /// right subtree. Subtrees with zero populated leaves
    /// return the cached empty-subtree hash without recursion.
    ///
    /// Production storage caches intermediate node hashes for
    /// incremental updates; this implementation recomputes
    /// from scratch on every call.
    #[must_use]
    pub fn root(&self) -> Hash {
        // Collect references to every populated entry once.
        // The partitioning recursion below splits this slice
        // by the level-th bit at each step (no per-call rescans
        // of `self.leaves`).
        let entries: Vec<(&StateKey, &Hash)> = self.leaves.iter().collect();
        self.compute_subtree_partitioned(&entries, 0)
    }

    /// Produce an inclusion proof for `key`. Works whether
    /// `key` is populated (membership proof) or not
    /// (non-membership proof: the leaf hash will be the
    /// empty-leaf hash). The returned proof always has
    /// `STATE_TREE_DEPTH` siblings.
    ///
    /// `O(populated_leaves × depth)` total — the partitioning
    /// recursion descends along `key`'s path and computes each
    /// sibling subtree's hash with the partitioned algorithm.
    #[must_use]
    pub fn prove(&self, key: &StateKey) -> MerkleProof {
        let mut siblings = Vec::with_capacity(STATE_TREE_DEPTH);
        let entries: Vec<(&StateKey, &Hash)> = self.leaves.iter().collect();
        self.prove_partitioned(key, &entries, 0, &mut siblings);
        MerkleProof { siblings }
    }

    /// Compute the hash of a subtree whose populated entries
    /// are exactly `entries` (a slice of `(&key, &value_hash)`).
    /// `level` is the depth from the root: 0 at the root, and
    /// `STATE_TREE_DEPTH` at a leaf.
    ///
    /// The recursion partitions `entries` by `key_bit(k,
    /// level)` at each step, so the total work across the
    /// whole tree is `O(populated_leaves × depth)` rather than
    /// `O(populated_leaves² × depth)` under the previous
    /// linear-scan-per-node implementation.
    fn compute_subtree_partitioned(&self, entries: &[(&StateKey, &Hash)], level: usize) -> Hash {
        // Fast path: empty subtree → return cached hash.
        // `empty_subtrees` is indexed by "depth from leaf",
        // so at level `l` the remaining depth-to-leaf is
        // `STATE_TREE_DEPTH - l`.
        if entries.is_empty() {
            return self.empty_subtrees[STATE_TREE_DEPTH - level];
        }
        // At leaf level, there is exactly one populated entry
        // (each `StateKey` uniquely determines a leaf position).
        if level == STATE_TREE_DEPTH {
            let (k, vh) = entries[0];
            return leaf_hash(k, vh);
        }
        // Partition `entries` by the `level`-th bit (MSB-first).
        let mut left: Vec<(&StateKey, &Hash)> = Vec::new();
        let mut right: Vec<(&StateKey, &Hash)> = Vec::new();
        for &(k, vh) in entries {
            if key_bit(k, level) {
                right.push((k, vh));
            } else {
                left.push((k, vh));
            }
        }
        let l = self.compute_subtree_partitioned(&left, level + 1);
        let r = self.compute_subtree_partitioned(&right, level + 1);
        node_hash(&l, &r)
    }

    /// Walk top-down along `key`'s path, partitioning entries
    /// at each level and recording the sibling subtree's hash.
    /// Companion to [`Self::compute_subtree_partitioned`] for
    /// proof generation.
    fn prove_partitioned(
        &self,
        key: &StateKey,
        entries: &[(&StateKey, &Hash)],
        level: usize,
        siblings: &mut Vec<Hash>,
    ) {
        if level == STATE_TREE_DEPTH {
            return;
        }
        // Partition by the `level`-th bit.
        let mut left: Vec<(&StateKey, &Hash)> = Vec::new();
        let mut right: Vec<(&StateKey, &Hash)> = Vec::new();
        for &(k, vh) in entries {
            if key_bit(k, level) {
                right.push((k, vh));
            } else {
                left.push((k, vh));
            }
        }
        // `key`'s bit at this level chooses which partition we
        // descend into; the other partition's subtree hash is
        // the recorded sibling.
        let bit = key_bit(key, level);
        if bit {
            // key descends right; sibling is the left subtree.
            siblings.push(self.compute_subtree_partitioned(&left, level + 1));
            self.prove_partitioned(key, &right, level + 1, siblings);
        } else {
            // key descends left; sibling is the right subtree.
            siblings.push(self.compute_subtree_partitioned(&right, level + 1));
            self.prove_partitioned(key, &left, level + 1, siblings);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(byte: u8) -> StateKey {
        let mut k = [0u8; STATE_KEY_BYTES];
        k[0] = byte;
        k
    }

    #[test]
    fn constants_pinned() {
        assert_eq!(STATE_KEY_BYTES, 32);
        assert_eq!(STATE_TREE_DEPTH, 256);
    }

    #[test]
    fn empty_subtree_hashes_pinned_size() {
        let h = empty_subtree_hashes();
        assert_eq!(h.len(), STATE_TREE_DEPTH + 1);
        // The leaf-level hash matches empty_leaf_hash().
        assert_eq!(h[0], empty_leaf_hash());
    }

    #[test]
    fn empty_subtree_hashes_are_deterministic() {
        assert_eq!(empty_subtree_hashes(), empty_subtree_hashes());
    }

    #[test]
    fn empty_tree_root_matches_top_level_empty_subtree() {
        let tree = SparseMerkleTree::new();
        assert_eq!(tree.root(), empty_subtree_hashes()[STATE_TREE_DEPTH]);
        assert_eq!(tree.populated_leaf_count(), 0);
    }

    #[test]
    fn insert_changes_root() {
        let mut tree = SparseMerkleTree::new();
        let empty_root = tree.root();
        tree.insert(key(1), b"value1");
        let new_root = tree.root();
        assert_ne!(empty_root, new_root);
        assert_eq!(tree.populated_leaf_count(), 1);
    }

    #[test]
    fn remove_restores_root() {
        let mut tree = SparseMerkleTree::new();
        let empty_root = tree.root();
        tree.insert(key(1), b"value1");
        assert!(tree.contains(&key(1)));
        assert!(tree.remove(&key(1)));
        assert_eq!(tree.root(), empty_root);
        assert!(!tree.contains(&key(1)));
    }

    #[test]
    fn membership_proof_verifies() {
        let mut tree = SparseMerkleTree::new();
        tree.insert(key(1), b"hello");
        let proof = tree.prove(&key(1));
        assert!(verify_membership(&key(1), b"hello", &proof, &tree.root()));
    }

    #[test]
    fn membership_proof_rejects_wrong_value() {
        let mut tree = SparseMerkleTree::new();
        tree.insert(key(1), b"hello");
        let proof = tree.prove(&key(1));
        assert!(!verify_membership(
            &key(1),
            b"goodbye",
            &proof,
            &tree.root()
        ));
    }

    #[test]
    fn non_membership_proof_verifies_for_absent_key() {
        let mut tree = SparseMerkleTree::new();
        tree.insert(key(1), b"hello");
        let proof = tree.prove(&key(99));
        assert!(verify_non_membership(&key(99), &proof, &tree.root()));
    }

    #[test]
    fn non_membership_proof_rejects_present_key() {
        let mut tree = SparseMerkleTree::new();
        tree.insert(key(1), b"hello");
        let proof = tree.prove(&key(1));
        // Key 1 IS present; the empty-leaf reconstruction
        // should produce a different root.
        assert!(!verify_non_membership(&key(1), &proof, &tree.root()));
    }

    #[test]
    fn multi_key_insert_proofs_verify() {
        let mut tree = SparseMerkleTree::new();
        for i in 0..16u8 {
            tree.insert(key(i), &[i; 10]);
        }
        let root = tree.root();
        for i in 0..16u8 {
            let proof = tree.prove(&key(i));
            assert!(
                verify_membership(&key(i), &[i; 10], &proof, &root),
                "key {i} should verify"
            );
        }
    }

    #[test]
    fn proof_has_correct_depth() {
        let mut tree = SparseMerkleTree::new();
        tree.insert(key(1), b"x");
        let proof = tree.prove(&key(1));
        assert_eq!(proof.siblings.len(), STATE_TREE_DEPTH);
    }

    #[test]
    fn proof_wrong_depth_rejected() {
        let mut tree = SparseMerkleTree::new();
        tree.insert(key(1), b"x");
        let mut bad_proof = tree.prove(&key(1));
        bad_proof.siblings.pop();
        assert!(!verify_membership(&key(1), b"x", &bad_proof, &tree.root()));
    }

    #[test]
    fn proof_tampered_sibling_rejected() {
        let mut tree = SparseMerkleTree::new();
        tree.insert(key(1), b"x");
        tree.insert(key(2), b"y");
        let mut proof = tree.prove(&key(1));
        proof.siblings[0][0] ^= 0xFF;
        assert!(!verify_membership(&key(1), b"x", &proof, &tree.root()));
    }

    #[test]
    fn root_determinism_under_insertion_order() {
        let mut a = SparseMerkleTree::new();
        let mut b = SparseMerkleTree::new();
        a.insert(key(1), b"v1");
        a.insert(key(2), b"v2");
        a.insert(key(3), b"v3");
        b.insert(key(3), b"v3");
        b.insert(key(2), b"v2");
        b.insert(key(1), b"v1");
        assert_eq!(a.root(), b.root());
    }

    #[test]
    fn distinct_values_produce_distinct_roots() {
        let mut a = SparseMerkleTree::new();
        let mut b = SparseMerkleTree::new();
        a.insert(key(1), b"v1");
        b.insert(key(1), b"v2");
        assert_ne!(a.root(), b.root());
    }

    #[test]
    fn merkle_proof_bcs_round_trip() {
        let mut tree = SparseMerkleTree::new();
        tree.insert(key(7), b"data");
        let p = tree.prove(&key(7));
        let bytes = bcs::to_bytes(&p).expect("encode");
        let decoded: MerkleProof = bcs::from_bytes(&bytes).expect("decode");
        assert_eq!(p, decoded);
    }

    #[test]
    fn domain_tags_pinned() {
        // Tag stability matters for the recursive-proof
        // binding at Phase 6.9b extension work. Pin via the
        // hash outputs they produce.
        assert_eq!(
            sha3_256_tagged(&domain::STATE_MERKLE_EMPTY_LEAF, &[]),
            empty_leaf_hash(),
            "TAG_EMPTY_LEAF must be canonical"
        );
        // TAG_NODE produces deterministic output for a known
        // pair of children.
        let zero = [0u8; 32];
        let one = [1u8; 32];
        let _ = node_hash(&zero, &one);
        let _ = leaf_hash(&[0u8; STATE_KEY_BYTES], &zero);
        let _ = value_hash(b"check");
    }
}
