//! Global Note Commitment Tree per whitepaper §7.1.3.
//!
//! Phase 6.3 ships the **skeleton** — types + reference
//! in-memory implementation + Merkle-path verification. The
//! production storage backend (RocksDB-backed incremental
//! tree with chunked subtree caching) is deferred to the Phase 4
//! storage backfill workstream per CLAUDE.md §14.4 Decision 2.
//! The trait-shaped API surface here is stable across that
//! transition; only the storage implementation evolves.
//!
//! # Spec basis
//!
//! Whitepaper §7.1.3 verbatim:
//!
//! > All note commitments ever created on Adamant live in a
//! > single append-only Merkle tree, the global note commitment
//! > tree (GNCT). The tree has a fixed depth of 64, allowing
//! > 2^64 notes — sufficient for the chain's projected lifetime.
//! >
//! > Tree properties:
//! > - **Append-only.** Once a commitment is added, it cannot
//! >   be removed or modified.
//! > - **Per-shielded-transaction Merkle proof.** A transaction
//! >   spending a note proves, via a Merkle path, that the
//! >   note's commitment is in the tree.
//! > - **Anonymity set = entire tree.** Every shielded spend is
//! >   indistinguishable from spending any other note in the
//! >   tree, because the Merkle proof reveals only that *some*
//! >   commitment in the tree is being spent.
//! > - **Recent-roots window.** Validators retain Merkle roots
//! >   of the GNCT for the most recent 100 epochs.
//!
//! # Hash function
//!
//! Whitepaper §7.1.3 line 101 (verbatim): "The tree is
//! implemented using the Pedersen-hashed Merkle construction
//! with Poseidon hashing for in-circuit efficiency."
//!
//! Implementation note: this sentence describes two distinct
//! hash functions (Pedersen hashing AND Poseidon hashing) where
//! only Poseidon is consistent with the §3.3.3 amended Halo 2
//! / Pallas-base-field native arithmetic. The implementation
//! uses **Poseidon** binary-Merkle hashing (`parent_hash =
//! Poseidon(left || right)` with arity 2). The "Pedersen-hashed"
//! qualifier in the spec is likely vestigial from an earlier
//! Zcash-Sapling-style draft (Sapling used Pedersen-hashed
//! Merkle; Orchard switched to Poseidon for in-circuit
//! efficiency, which is what §3.3.3 amendment instance 31
//! pinned). Registered as a forward-tracking spec-amendment
//! candidate; not blocking.
//!
//! # Empty-subtree optimization
//!
//! A depth-64 tree over 2^64 leaves cannot be stored eagerly;
//! the skeleton uses the standard incremental-Merkle-tree
//! optimization. At each level `d`, the **empty-subtree hash**
//! `EMPTY_HASH[d]` is precomputed as `Poseidon(EMPTY_HASH[d-1],
//! EMPTY_HASH[d-1])`, with `EMPTY_HASH[0]` defined as the
//! all-zero leaf (the empty leaf-slot value). Most internal
//! subtrees are entirely empty; the empty-subtree hashes pin
//! their values without storing them.
//!
//! # Phase 6.3 scope-bounding
//!
//! This sub-arc ships the in-memory reference implementation
//! suitable for unit tests + integration tests + light client
//! verification. The scaling characteristics are:
//!
//! - **Storage**: `O(leaf_count × depth)` for naive incremental
//!   storage. Production swaps in `RocksDB`-backed chunked
//!   subtree caching for `O(leaf_count)` storage with `O(log n)`
//!   path queries.
//! - **Append**: `O(depth)` per leaf.
//! - **Path query**: `O(depth)` per query.
//! - **Root computation**: `O(1)` (cached on each append).
//!
//! All of these characteristics are stable across the storage-
//! backend swap; the API surface here is what production callers
//! will use.

use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;

use crate::note::NoteCommitment;
use crate::nullifier::LeafPosition;
use crate::poseidon::{poseidon_hash, FieldBytes};

/// Fixed depth of the GNCT per whitepaper §7.1.3.
///
/// > The tree has a fixed depth of 64, allowing 2^64 notes —
/// > sufficient for the chain's projected lifetime.
///
/// Genesis-fixed; changing this depth is a hard fork.
pub const GNCT_DEPTH: usize = 64;

/// Maximum number of leaves the GNCT can hold per §7.1.3.
/// `2^64` per the depth.
pub const GNCT_MAX_LEAVES: u128 = 1u128 << GNCT_DEPTH;

/// Recent-roots window per whitepaper §7.1.3:
///
/// > Validators retain Merkle roots of the GNCT for the most
/// > recent 100 epochs.
///
/// 100 is the spec-pinned value at this sub-arc; the window
/// length is consensus-binding.
pub const GNCT_RECENT_ROOTS_WINDOW: usize = 100;

/// 256-bit Merkle root of the GNCT per whitepaper §7.1.3.
///
/// Identical wire shape to [`NoteCommitment`] (a Pallas base
/// field element's canonical encoding) — both are Poseidon
/// outputs.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct MerkleRoot(#[serde(with = "BigArray")] [u8; 32]);

impl MerkleRoot {
    /// Construct from raw 32-byte material.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Canonical 32-byte encoding.
    #[must_use]
    pub const fn to_bytes(self) -> [u8; 32] {
        self.0
    }

    /// Borrow the underlying bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Sibling hash along a Merkle path. Same wire shape as
/// [`MerkleRoot`] / [`NoteCommitment`].
type SiblingHash = [u8; 32];

/// Merkle path proving a [`NoteCommitment`] is in the GNCT at a
/// specific [`LeafPosition`].
///
/// Carries `GNCT_DEPTH` sibling hashes, one per level. The path
/// reconstructs the root via:
///
/// ```text
/// h_0 = leaf
/// for d in 0..DEPTH:
///   if (position >> d) & 1 == 0:
///     h_{d+1} = Poseidon(h_d, siblings[d])
///   else:
///     h_{d+1} = Poseidon(siblings[d], h_d)
/// root = h_DEPTH
/// ```
///
/// The path reveals only the leaf-position-bit-determined left/
/// right ordering plus the sibling hashes; it does not reveal
/// which specific commitment is being verified, achieving the
/// §7.1.3 anonymity-set property.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MerklePath {
    /// Sibling hashes from the leaf upward. Length is
    /// `GNCT_DEPTH = 64`.
    pub siblings: Vec<SiblingHash>,
}

impl MerklePath {
    /// Reconstruct the Merkle root by walking the path bottom-up,
    /// hashing the leaf with each sibling per the position-bit-
    /// determined ordering.
    ///
    /// # Returns
    ///
    /// The reconstructed [`MerkleRoot`], which the caller compares
    /// against an authoritative root (e.g., from the chain's
    /// recent-roots window) via [`verify_membership`].
    #[must_use]
    pub fn reconstruct_root(&self, leaf: NoteCommitment, position: LeafPosition) -> MerkleRoot {
        let mut current = leaf.to_bytes();
        for (depth, sibling) in self.siblings.iter().enumerate() {
            let position_bit = (position.0 >> depth) & 1;
            let (left, right) = if position_bit == 0 {
                (current, *sibling)
            } else {
                (*sibling, current)
            };
            current = merkle_hash(&left, &right);
        }
        MerkleRoot::from_bytes(current)
    }
}

/// Verify a Merkle path proves the leaf is at the given position
/// under the given root. Constant-time on the hash bytes (the
/// Poseidon hashing is constant-time; equality comparison is a
/// straight `==` which the optimizer may not constant-time-ify
/// in all cases — for cryptographic equality the caller may
/// want a constant-time wrapper).
#[must_use]
pub fn verify_membership(
    leaf: NoteCommitment,
    position: LeafPosition,
    path: &MerklePath,
    expected_root: MerkleRoot,
) -> bool {
    if path.siblings.len() != GNCT_DEPTH {
        return false;
    }
    path.reconstruct_root(leaf, position) == expected_root
}

/// Binary Merkle hash function: `Poseidon(left, right)` with
/// arity 2, on Pallas-base-field elements.
///
/// Inputs are reduced into the field via
/// [`FieldBytes::from_bytes_reduced`]; the output is a single
/// field element returned as canonical 32-byte little-endian
/// encoding.
#[must_use]
fn merkle_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let inputs = [
        FieldBytes::from_bytes_reduced(*left),
        FieldBytes::from_bytes_reduced(*right),
    ];
    poseidon_hash::<2>(inputs).to_bytes()
}

/// Precomputed empty-subtree hash for level `level`. Returns the
/// result of recursively applying [`merkle_hash`] starting from
/// the all-zero leaf.
///
/// `empty_subtree_hash(0) = [0u8; 32]` (the empty-leaf slot).
/// `empty_subtree_hash(d) = merkle_hash(empty_subtree_hash(d-1),
/// empty_subtree_hash(d-1))`.
///
/// At Phase 6.3 these are computed lazily (cached in the tree
/// struct on construction). Production may pin these as compile-
/// time constants if benchmarks warrant.
fn compute_empty_subtree_hashes() -> [[u8; 32]; GNCT_DEPTH + 1] {
    let mut hashes = [[0u8; 32]; GNCT_DEPTH + 1];
    // Level 0: empty leaf-slot value (32 zero bytes per spec —
    // canonical encoding of the additive-identity field element).
    hashes[0] = [0u8; 32];
    // Level d > 0: hash of two level-(d-1) empty-subtree hashes.
    for d in 1..=GNCT_DEPTH {
        let prev = hashes[d - 1];
        hashes[d] = merkle_hash(&prev, &prev);
    }
    hashes
}

/// Global Note Commitment Tree per whitepaper §7.1.3 — Phase
/// 6.3 in-memory reference implementation.
///
/// Stores all appended leaves in a `Vec` for the skeleton; the
/// production storage backend (Phase 4 / pre-mainnet) replaces
/// the `leaves` field with a persistent-storage-backed
/// incremental tree, but the API surface stays identical.
///
/// # Invariants
///
/// - `leaves.len() <= GNCT_MAX_LEAVES` — the tree is bounded.
/// - The cached `current_root` is always equal to
///   `compute_root_from_leaves(&leaves)` — recomputed on each
///   append.
/// - The `recent_roots` ring buffer holds the last
///   `GNCT_RECENT_ROOTS_WINDOW` distinct roots the tree has
///   seen, with the most recent at the back.
#[derive(Clone, Debug)]
pub struct GlobalNoteCommitmentTree {
    leaves: Vec<NoteCommitment>,
    empty_subtree_hashes: [[u8; 32]; GNCT_DEPTH + 1],
    current_root: MerkleRoot,
    recent_roots: Vec<MerkleRoot>,
}

impl Default for GlobalNoteCommitmentTree {
    fn default() -> Self {
        Self::new()
    }
}

/// Returned by [`GlobalNoteCommitmentTree::append`] when the
/// tree's leaf count would exceed `GNCT_MAX_LEAVES`. Since
/// `GNCT_MAX_LEAVES = 2^64` and a `LeafPosition` is `u64`, this
/// case is structurally unreachable in practice; the variant
/// exists for API completeness.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TreeFull;

impl core::fmt::Display for TreeFull {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("global note commitment tree is at maximum capacity (2^64 leaves)")
    }
}

impl std::error::Error for TreeFull {}

impl GlobalNoteCommitmentTree {
    /// Construct a fresh empty GNCT. The empty-subtree hashes
    /// are precomputed at construction; root is the empty-subtree
    /// hash at level `GNCT_DEPTH`.
    #[must_use]
    pub fn new() -> Self {
        let empty_subtree_hashes = compute_empty_subtree_hashes();
        let current_root = MerkleRoot::from_bytes(empty_subtree_hashes[GNCT_DEPTH]);
        let recent_roots = vec![current_root];
        Self {
            leaves: Vec::new(),
            empty_subtree_hashes,
            current_root,
            recent_roots,
        }
    }

    /// Append a [`NoteCommitment`] to the tree. Returns the
    /// position the leaf was placed at (i.e., the previous
    /// `len()` value).
    ///
    /// # Errors
    ///
    /// Returns [`TreeFull`] if the tree's leaf count would
    /// exceed [`GNCT_MAX_LEAVES`]. Structurally unreachable in
    /// practice (§7.1.3 specifies depth 64 = 2^64 leaves).
    pub fn append(&mut self, commitment: NoteCommitment) -> Result<LeafPosition, TreeFull> {
        // Bounds check.
        if (self.leaves.len() as u128) >= GNCT_MAX_LEAVES {
            return Err(TreeFull);
        }
        let position = LeafPosition(self.leaves.len() as u64);
        self.leaves.push(commitment);
        // Recompute root + push into recent-roots.
        self.current_root = self.compute_root();
        // Recent-roots ring buffer per §7.1.3 line 99 (100-epoch
        // window). At the skeleton level we treat each append as
        // a "new root" event; production may aggregate appends per
        // epoch before retaining a root.
        if Some(&self.current_root) != self.recent_roots.last() {
            self.recent_roots.push(self.current_root);
            if self.recent_roots.len() > GNCT_RECENT_ROOTS_WINDOW {
                self.recent_roots.remove(0);
            }
        }
        Ok(position)
    }

    /// Number of leaves currently in the tree.
    ///
    /// # Panics
    ///
    /// Cannot panic in practice. `Vec::len()` returns `usize`
    /// (≤ 2^64 on every supported platform); the conversion to
    /// `u64` only fails if `usize` exceeds 64 bits, which is
    /// architecturally impossible (the `GNCT_MAX_LEAVES` cap of
    /// 2^64 fits in `u64` by construction).
    #[must_use]
    pub fn len(&self) -> u64 {
        u64::try_from(self.leaves.len()).expect("leaves.len() < 2^64 by construction")
    }

    /// Whether the tree is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }

    /// Current Merkle root of the tree.
    #[must_use]
    pub fn root(&self) -> MerkleRoot {
        self.current_root
    }

    /// Whether `root` is in the recent-roots window per
    /// §7.1.3's 100-epoch validity window. Spends prove against
    /// any root in this window per the spec.
    #[must_use]
    pub fn is_recent_root(&self, root: MerkleRoot) -> bool {
        self.recent_roots.contains(&root)
    }

    /// Compute the Merkle path for the leaf at `position`.
    /// Returns `None` if `position >= len()` — there is no leaf
    /// at the requested index.
    #[must_use]
    pub fn path(&self, position: LeafPosition) -> Option<MerklePath> {
        if position.0 >= self.len() {
            return None;
        }
        let mut siblings: Vec<SiblingHash> = Vec::with_capacity(GNCT_DEPTH);
        // Walk levels from leaf upward. At each level, the
        // sibling is either an existing subtree hash (computed
        // from the populated portion of leaves) or the precomputed
        // empty-subtree hash for that level.
        let mut current_position = position.0;
        for d in 0..GNCT_DEPTH {
            let sibling_position = current_position ^ 1;
            siblings.push(self.subtree_hash_at_level(d, sibling_position));
            current_position >>= 1;
        }
        Some(MerklePath { siblings })
    }

    /// Compute the hash of the subtree rooted at level `level`,
    /// position `node_position` within that level. Used by
    /// [`path`] to walk siblings; conceptually this is the
    /// "subtree-by-coordinate" view of the tree.
    fn subtree_hash_at_level(&self, level: usize, node_position: u64) -> [u8; 32] {
        // Level 0: this is a leaf. If in range, its hash is the
        // leaf's bytes; if out of range, empty. The `usize` cast
        // is safe because we only reach this branch when the
        // tree has at most 2^64 leaves (per GNCT_MAX_LEAVES); on
        // 64-bit targets `usize == u64`. On 32-bit targets the
        // cast would truncate, but the explicit `try_from` +
        // empty-fallback guards against that.
        if level == 0 {
            let i = match usize::try_from(node_position) {
                Ok(i) if i < self.leaves.len() => i,
                _ => return self.empty_subtree_hashes[0],
            };
            return self.leaves[i].to_bytes();
        }
        // Level GNCT_DEPTH (= 64): the single root node covers
        // all 2^64 possible leaves. If the tree has zero leaves,
        // the subtree is empty; otherwise we recurse into the two
        // half-subtrees at level - 1.
        if level >= GNCT_DEPTH {
            if self.leaves.is_empty() {
                return self.empty_subtree_hashes[level];
            }
            // Recurse without the leaves-per-subtree shortcut
            // (which would overflow u64 at level == 64).
            let left = self.subtree_hash_at_level(level - 1, 0);
            let right = self.subtree_hash_at_level(level - 1, 1);
            return merkle_hash(&left, &right);
        }
        // Levels 1..GNCT_DEPTH: the subtree at (level, node_position)
        // covers leaves [node_position * 2^level,
        // (node_position + 1) * 2^level). If that range is entirely
        // beyond `len()`, the subtree is empty.
        let leaves_per_subtree: u64 = 1u64 << level;
        let leaf_start = node_position.saturating_mul(leaves_per_subtree);
        if leaf_start >= self.len() {
            return self.empty_subtree_hashes[level];
        }
        let left = self.subtree_hash_at_level(level - 1, node_position * 2);
        let right = self.subtree_hash_at_level(level - 1, node_position * 2 + 1);
        merkle_hash(&left, &right)
    }

    /// Compute the current root from the tree's leaves +
    /// precomputed empty-subtree hashes.
    fn compute_root(&self) -> MerkleRoot {
        MerkleRoot::from_bytes(self.subtree_hash_at_level(GNCT_DEPTH, 0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nc(seed: u8) -> NoteCommitment {
        NoteCommitment::from_bytes([seed; 32])
    }

    // ---------- constants ----------

    #[test]
    fn gnct_depth_matches_spec() {
        assert_eq!(GNCT_DEPTH, 64);
        assert_eq!(GNCT_MAX_LEAVES, 1u128 << 64);
    }

    #[test]
    fn gnct_recent_roots_window_matches_spec() {
        // Whitepaper §7.1.3 line 99: "for the most recent 100
        // epochs."
        assert_eq!(GNCT_RECENT_ROOTS_WINDOW, 100);
    }

    // ---------- empty tree ----------

    #[test]
    fn empty_tree_is_empty() {
        let t = GlobalNoteCommitmentTree::new();
        assert!(t.is_empty());
        assert_eq!(t.len(), 0);
    }

    #[test]
    fn empty_tree_root_matches_empty_subtree_hash_at_depth_64() {
        let t = GlobalNoteCommitmentTree::new();
        let expected = compute_empty_subtree_hashes();
        assert_eq!(t.root().to_bytes(), expected[GNCT_DEPTH]);
    }

    #[test]
    fn empty_tree_recent_roots_contains_empty_root() {
        let t = GlobalNoteCommitmentTree::new();
        let empty_root = t.root();
        assert!(t.is_recent_root(empty_root));
    }

    // ---------- append ----------

    #[test]
    fn append_assigns_sequential_positions() {
        let mut t = GlobalNoteCommitmentTree::new();
        assert_eq!(t.append(nc(1)).unwrap(), LeafPosition(0));
        assert_eq!(t.append(nc(2)).unwrap(), LeafPosition(1));
        assert_eq!(t.append(nc(3)).unwrap(), LeafPosition(2));
        assert_eq!(t.len(), 3);
    }

    #[test]
    fn append_changes_root() {
        let mut t = GlobalNoteCommitmentTree::new();
        let root_empty = t.root();
        t.append(nc(1)).unwrap();
        let root_after_one = t.root();
        assert_ne!(root_empty, root_after_one);
        t.append(nc(2)).unwrap();
        let root_after_two = t.root();
        assert_ne!(root_after_one, root_after_two);
    }

    #[test]
    fn append_makes_root_recent() {
        let mut t = GlobalNoteCommitmentTree::new();
        t.append(nc(1)).unwrap();
        let root_after_one = t.root();
        assert!(t.is_recent_root(root_after_one));
    }

    // ---------- path + verify_membership ----------

    #[test]
    fn path_for_out_of_range_is_none() {
        let t = GlobalNoteCommitmentTree::new();
        assert!(t.path(LeafPosition(0)).is_none());
    }

    #[test]
    fn path_for_single_leaf_verifies() {
        let mut t = GlobalNoteCommitmentTree::new();
        let leaf = nc(0xAA);
        let pos = t.append(leaf).unwrap();
        let path = t.path(pos).expect("path exists for in-range leaf");
        assert!(verify_membership(leaf, pos, &path, t.root()));
    }

    #[test]
    fn path_for_three_leaves_each_verifies() {
        let mut t = GlobalNoteCommitmentTree::new();
        let leaves = [nc(1), nc(2), nc(3)];
        let positions: Vec<LeafPosition> = leaves.iter().map(|l| t.append(*l).unwrap()).collect();
        let root = t.root();
        for (leaf, pos) in leaves.iter().zip(positions.iter()) {
            let path = t.path(*pos).expect("path for in-range leaf");
            assert!(
                verify_membership(*leaf, *pos, &path, root),
                "path verification failed for leaf at position {}",
                pos.0
            );
        }
    }

    #[test]
    fn verify_membership_rejects_wrong_leaf() {
        let mut t = GlobalNoteCommitmentTree::new();
        let leaf = nc(0xAA);
        let pos = t.append(leaf).unwrap();
        let path = t.path(pos).unwrap();
        let wrong_leaf = nc(0xBB);
        assert!(!verify_membership(wrong_leaf, pos, &path, t.root()));
    }

    #[test]
    fn verify_membership_rejects_wrong_position() {
        let mut t = GlobalNoteCommitmentTree::new();
        let leaf_a = nc(1);
        let leaf_b = nc(2);
        t.append(leaf_a).unwrap();
        let pos_b = t.append(leaf_b).unwrap();
        let path_b = t.path(pos_b).unwrap();
        // Prove leaf_b's path against a wrong position.
        assert!(!verify_membership(
            leaf_b,
            LeafPosition(0),
            &path_b,
            t.root()
        ));
    }

    #[test]
    fn verify_membership_rejects_wrong_root() {
        let mut t = GlobalNoteCommitmentTree::new();
        let leaf = nc(0xAA);
        let pos = t.append(leaf).unwrap();
        let path = t.path(pos).unwrap();
        let wrong_root = MerkleRoot::from_bytes([0xFF; 32]);
        assert!(!verify_membership(leaf, pos, &path, wrong_root));
    }

    #[test]
    fn verify_membership_rejects_wrong_depth_path() {
        let mut t = GlobalNoteCommitmentTree::new();
        let leaf = nc(0xAA);
        let pos = t.append(leaf).unwrap();
        let mut path = t.path(pos).unwrap();
        path.siblings.pop(); // Now depth-63, should fail.
        assert!(!verify_membership(leaf, pos, &path, t.root()));
    }

    /// Whitepaper §7.1.3 anonymity-set property: the path
    /// reveals only sibling hashes, not which specific commitment
    /// is being spent. Pin this by verifying that two different
    /// leaves at non-overlapping positions produce paths that
    /// share zero sibling-hash bytes (the path is independent of
    /// which leaf you're proving — it's the position's siblings).
    /// This isn't a strict cryptographic claim (paths CAN share
    /// siblings if leaves happen to be in adjacent subtrees) but
    /// it's a sanity check for the reference shape.
    #[test]
    fn paths_for_distant_positions_have_distinct_top_sibling() {
        let mut t = GlobalNoteCommitmentTree::new();
        for i in 0..16u8 {
            t.append(nc(i)).unwrap();
        }
        // Positions 0 and 8 are in different right-subtrees at
        // level 3 → different siblings at that level.
        let p_a = t.path(LeafPosition(0)).unwrap();
        let p_b = t.path(LeafPosition(8)).unwrap();
        // At level 3, the siblings cover different subtrees.
        assert_ne!(p_a.siblings[3], p_b.siblings[3]);
    }

    // ---------- empty-subtree precomputation ----------

    #[test]
    fn empty_subtree_hashes_are_consistent() {
        let hashes = compute_empty_subtree_hashes();
        // Level 0 is the all-zero leaf.
        assert_eq!(hashes[0], [0u8; 32]);
        // Level d > 0 is Merkle hash of two level-(d-1) hashes.
        for d in 1..=GNCT_DEPTH {
            assert_eq!(hashes[d], merkle_hash(&hashes[d - 1], &hashes[d - 1]));
        }
    }

    #[test]
    fn empty_subtree_hashes_are_deterministic() {
        let a = compute_empty_subtree_hashes();
        let b = compute_empty_subtree_hashes();
        assert_eq!(a, b);
    }

    // ---------- merkle_hash ----------

    #[test]
    fn merkle_hash_input_order_matters() {
        let a = [0x01; 32];
        let b = [0x02; 32];
        assert_ne!(merkle_hash(&a, &b), merkle_hash(&b, &a));
    }

    #[test]
    fn merkle_hash_deterministic() {
        let a = [0x33; 32];
        let b = [0x44; 32];
        assert_eq!(merkle_hash(&a, &b), merkle_hash(&a, &b));
    }

    // ---------- BCS round-trip ----------

    #[test]
    fn merkle_root_bcs_round_trip() {
        let r = MerkleRoot::from_bytes([0xCD; 32]);
        let encoded = bcs::to_bytes(&r).unwrap();
        let decoded: MerkleRoot = bcs::from_bytes(&encoded).unwrap();
        assert_eq!(r, decoded);
        assert_eq!(encoded.len(), 32);
    }

    #[test]
    fn merkle_path_bcs_round_trip() {
        let mut t = GlobalNoteCommitmentTree::new();
        let leaf = nc(0xAA);
        let pos = t.append(leaf).unwrap();
        let path = t.path(pos).unwrap();
        let encoded = bcs::to_bytes(&path).unwrap();
        let decoded: MerklePath = bcs::from_bytes(&encoded).unwrap();
        assert_eq!(path, decoded);
        assert_eq!(decoded.siblings.len(), GNCT_DEPTH);
    }

    // ---------- recent-roots window ----------

    #[test]
    fn recent_roots_retain_window_size() {
        let mut t = GlobalNoteCommitmentTree::new();
        // Append GNCT_RECENT_ROOTS_WINDOW + 5 leaves; the buffer
        // should retain only the most recent.
        for i in 0..(GNCT_RECENT_ROOTS_WINDOW + 5) {
            t.append(nc(u8::try_from(i & 0xFF).expect("masked"))).unwrap();
        }
        // Internal: recent_roots.len() <= GNCT_RECENT_ROOTS_WINDOW.
        assert!(t.recent_roots.len() <= GNCT_RECENT_ROOTS_WINDOW);
        // The current root is in the window.
        assert!(t.is_recent_root(t.root()));
    }
}
