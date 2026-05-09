//! Adamant-native borrow-graph foundation (whitepaper §6.2.1.6
//! Rule "reference safety" support).
//!
//! Forked byte-faithfully from `vendor/move-borrow-graph/` at
//! Sui-Move tag `mainnet-v1.66.2`, consolidating four upstream
//! source files into a single Adamant-native module:
//!
//! - `vendor/move-borrow-graph/src/graph.rs` (479 LOC) →
//!   [`BorrowGraph`] and its method impls.
//! - `vendor/move-borrow-graph/src/references.rs` (253 LOC) →
//!   [`RefID`], [`BorrowEdge`], [`BorrowEdgeSet`], `BorrowEdges`,
//!   `Ref` and their impls; trait impls (`PartialEq`, `Eq`,
//!   `PartialOrd`, `Ord`, `Debug`, `IntoIterator`).
//! - `vendor/move-borrow-graph/src/paths.rs` (22 LOC) →
//!   [`Path`] / [`PathSlice`] type aliases plus [`paths::leq`],
//!   [`paths::factor`], [`paths::append`].
//! - `vendor/move-borrow-graph/src/shared.rs` (14 LOC) →
//!   `remap_set` helper.
//!
//! # Adamant deviations
//!
//! - **Single-file consolidation.** Four upstream files merged
//!   into one module per sub-shape α (inline within `adamant-vm`)
//!   of the vendored-Sui-crates-port canonical principle (5th
//!   instance — D-1a CFG, D-1b `AbstractInterpreter`, D-2
//!   `LoopSummary`, D-5a.0 `AbstractStack` precedents).
//! - **Visibility narrowed.** Upstream's `pub` items consumed
//!   by `reference_safety/abstract_state.rs` become `pub(super)`
//!   (visible to the parent `reference_safety` module only).
//!   Upstream's `pub(crate)` items (internal to the vendored
//!   borrow-graph crate) become private here (no `pub`).
//! - **No metering.** Move-borrow-graph itself carries no
//!   metering constants; the metering surface lives in
//!   `reference_safety/abstract_state.rs`'s pass code (`STEP_BASE_COST`,
//!   `JOIN_BASE_COST`, `PER_GRAPH_ITEM_COST`, etc.) and is dropped
//!   at D-5b.2 per the no-metering precedent (D-1a / D-1b / D-2
//!   / D-3 / D-4 / D-5a.0 / D-5a.1.a / D-5a.1.b).
//! - **`MAX_EDGE_SET_SIZE = 10` preserved as genesis-fixed
//!   structural bound** (NOT metering). When a borrow-edge set
//!   hits the cap, it becomes "lossy" and is treated as
//!   borrowing any possible edge from the source reference;
//!   this is consensus-binding and registered for §6.2.1.7
//!   spec-amendment workstream carry-forward.
//! - **`paths` and `shared` namespacing.** Upstream's
//!   `paths::leq` / `paths::factor` / `paths::append` helpers
//!   live inside an inline `paths` submodule within this file
//!   to preserve the call-site namespace (`paths::leq(...)`)
//!   without introducing a separate file. `remap_set` (from
//!   upstream's `shared.rs`) is a private free function at
//!   module scope.
//!
//! # Public API surface (consumed by `reference_safety/abstract_state.rs` at D-5b.2)
//!
//! - [`RefID`] — opaque borrow-graph reference identifier.
//! - [`RefID::new`], [`RefID::number`].
//! - [`BorrowGraph`] — generic borrow graph parameterized by
//!   location and label types.
//! - [`BorrowGraph::new`], [`BorrowGraph::graph_size`],
//!   [`BorrowGraph::is_mutable`], [`BorrowGraph::new_ref`],
//!   [`BorrowGraph::borrowed_by`],
//!   [`BorrowGraph::between_edges`],
//!   [`BorrowGraph::out_edges`], [`BorrowGraph::in_edges`],
//!   [`BorrowGraph::add_strong_borrow`],
//!   [`BorrowGraph::add_strong_field_borrow`],
//!   [`BorrowGraph::add_weak_borrow`],
//!   [`BorrowGraph::add_weak_field_borrow`],
//!   [`BorrowGraph::release`], [`BorrowGraph::leq`],
//!   [`BorrowGraph::remap_refs`], [`BorrowGraph::join`],
//!   [`BorrowGraph::contains_id`], [`BorrowGraph::all_refs`],
//!   [`BorrowGraph::display`].
//! - [`MAX_EDGE_SET_SIZE`].
//! - [`Path`] / [`PathSlice`] type aliases.
//! - [`paths::leq`] / [`paths::factor`] / [`paths::append`].

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fmt::Debug;

// ===========================================================
// `paths` submodule (forked from
// `vendor/move-borrow-graph/src/paths.rs`)
// ===========================================================

/// Path utilities for borrow-graph edge labels.
pub(super) mod paths {
    pub(in super::super) type PathSlice<Lbl> = [Lbl];
    pub(in super::super) type Path<Lbl> = Vec<Lbl>;

    /// Returns `true` if `lhs` is a prefix of `rhs`.
    pub(in super::super) fn leq<Lbl: Eq>(lhs: &PathSlice<Lbl>, rhs: &PathSlice<Lbl>) -> bool {
        lhs.len() <= rhs.len() && lhs.iter().zip(rhs).all(|(l, r)| l == r)
    }

    /// Splits `rhs` by removing the prefix `lhs`. Caller must
    /// satisfy `leq(lhs, rhs)`.
    pub(in super::super) fn factor<Lbl: Eq>(
        lhs: &PathSlice<Lbl>,
        mut rhs: Path<Lbl>,
    ) -> (Path<Lbl>, Path<Lbl>) {
        assert!(leq(lhs, &rhs));
        let suffix = rhs.split_off(lhs.len());
        (rhs, suffix)
    }

    /// Concatenates two paths.
    pub(in super::super) fn append<Lbl: Clone>(
        lhs: &PathSlice<Lbl>,
        rhs: &PathSlice<Lbl>,
    ) -> Path<Lbl> {
        let mut path: Path<Lbl> = lhs.into();
        path.append(&mut rhs.to_owned());
        path
    }
}

pub(super) use paths::Path;
#[cfg(test)]
pub(super) use paths::PathSlice;

// ===========================================================
// `shared` helper (forked from
// `vendor/move-borrow-graph/src/shared.rs`)
// ===========================================================

/// Remap a `BTreeSet` of copyable, comparable items through
/// `id_map`. Items not in the map are passed through unchanged.
fn remap_set<T: Copy + Ord>(set: &mut BTreeSet<T>, id_map: &BTreeMap<T, T>) {
    let before = set.len();
    *set = std::mem::take(set)
        .into_iter()
        .map(|x| id_map.get(&x).copied().unwrap_or(x))
        .collect();
    let after = set.len();
    debug_assert!(before == after);
}

// ===========================================================
// `references` types (forked from
// `vendor/move-borrow-graph/src/references.rs`)
// ===========================================================

/// Unique identifier for a reference within a [`BorrowGraph`].
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub(super) struct RefID(pub(super) usize);

impl RefID {
    /// Creates a new reference identifier.
    pub(super) const fn new(x: usize) -> Self {
        RefID(x)
    }

    /// Returns the integer representing this reference identifier.
    pub(super) fn number(self) -> usize {
        self.0
    }
}

/// An edge in the borrow graph.
#[derive(Clone)]
struct BorrowEdge<Loc: Copy, Lbl: Clone + Ord> {
    /// `true` if this is an exact (strong) edge,
    /// `false` if it is a prefix (weak) edge.
    strong: bool,
    /// The path (either exact/prefix strong/weak) for the borrow
    /// relationship of this edge.
    path: Path<Lbl>,
    /// Location information for the edge (e.g. the `CodeOffset`
    /// at which the borrow was created).
    loc: Loc,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct BorrowEdgeSet<Loc: Copy, Lbl: Clone + Ord> {
    edges: BTreeSet<BorrowEdge<Loc, Lbl>>,
    /// `true` if the set has hit [`MAX_EDGE_SET_SIZE`]. See
    /// [`MAX_EDGE_SET_SIZE`] for details on lossy-overflow
    /// semantics.
    overflown: bool,
}

/// Represents outgoing edges in the borrow graph.
#[derive(Clone, Debug, PartialEq, Eq)]
struct BorrowEdges<Loc: Copy, Lbl: Clone + Ord>(BTreeMap<RefID, BorrowEdgeSet<Loc, Lbl>>);

/// Represents the borrow relationships and information for a
/// node in the borrow graph (i.e. for a single reference).
#[derive(Clone, Debug, PartialEq, Eq)]
struct Ref<Loc: Copy, Lbl: Clone + Ord> {
    /// Parent → child: "self is borrowed by _".
    borrowed_by: BorrowEdges<Loc, Lbl>,
    /// Child → parent: "self borrows from _". Maintained for
    /// efficient querying; in one-to-one correspondence with
    /// `borrowed_by` (i.e. `x.borrowed_by[y]` exists IFF
    /// `y.borrows_from` contains `x`).
    borrows_from: BTreeSet<RefID>,
    /// `true` if this reference is mutable, `false` for
    /// immutable.
    mutable: bool,
}

impl<Loc: Copy, Lbl: Clone + Ord> BorrowEdge<Loc, Lbl> {
    fn leq(&self, other: &Self) -> bool {
        self == other || (!self.strong && paths::leq(&self.path, &other.path))
    }
}

/// Maximum size of a borrow-edge set. **Genesis-fixed** —
/// changing this value alters validator accept/reject decisions
/// and is therefore consensus-binding (subject to §6.2.1.7
/// spec-amendment workstream carry-forward; see module preamble
/// in [`super`]).
///
/// Beyond this size, the borrow-set becomes lossy and is
/// considered to borrow any possible edge (or extension) from
/// the source reference.
pub(super) const MAX_EDGE_SET_SIZE: usize = 10;

impl<Loc: Copy, Lbl: Clone + Ord> BorrowEdgeSet<Loc, Lbl> {
    fn new() -> Self {
        Self {
            edges: BTreeSet::new(),
            overflown: false,
        }
    }

    fn insert(&mut self, edge: BorrowEdge<Loc, Lbl>) {
        debug_assert!(self.edges.len() <= MAX_EDGE_SET_SIZE);
        if self.overflown {
            debug_assert!(!self.is_empty());
            return;
        }
        if self.edges.len() + 1 > MAX_EDGE_SET_SIZE {
            let loc = edge.loc;
            self.edges = BTreeSet::from([BorrowEdge {
                strong: false,
                path: vec![],
                loc,
            }]);
            self.overflown = true;
        } else {
            self.edges.insert(edge);
        }
    }

    fn remove(&mut self, edge: &BorrowEdge<Loc, Lbl>) -> bool {
        let was_removed = self.edges.remove(edge);
        debug_assert!(was_removed);
        was_removed
    }

    fn len(&self) -> usize {
        self.edges.len()
    }

    fn is_empty(&self) -> bool {
        self.edges.is_empty()
    }

    fn iter(&self) -> std::collections::btree_set::Iter<'_, BorrowEdge<Loc, Lbl>> {
        debug_assert!(self.overflown || !self.is_empty());
        self.edges.iter()
    }
}

impl<Loc: Copy, Lbl: Clone + Ord> BorrowEdges<Loc, Lbl> {
    fn new() -> Self {
        Self(BTreeMap::new())
    }
}

impl<Loc: Copy, Lbl: Clone + Ord> Ref<Loc, Lbl> {
    fn new(mutable: bool) -> Self {
        let borrowed_by = BorrowEdges::new();
        let borrows_from = BTreeSet::new();
        Self {
            borrowed_by,
            borrows_from,
            mutable,
        }
    }
}

// ----- Remap impls -----

impl<Loc: Copy, Lbl: Clone + Ord> BorrowEdges<Loc, Lbl> {
    /// Utility for remapping the reference ids according to
    /// `id_map`. Ids not in the map are passed through unchanged.
    fn remap_refs(&mut self, id_map: &BTreeMap<RefID, RefID>) {
        let before = self.0.len();
        self.0 = std::mem::take(&mut self.0)
            .into_iter()
            .map(|(id, edges)| (id_map.get(&id).copied().unwrap_or(id), edges))
            .collect();
        let after = self.0.len();
        debug_assert!(before == after);
    }
}

impl<Loc: Copy, Lbl: Clone + Ord> Ref<Loc, Lbl> {
    fn remap_refs(&mut self, id_map: &BTreeMap<RefID, RefID>) {
        self.borrowed_by.remap_refs(id_map);
        remap_set(&mut self.borrows_from, id_map);
    }
}

// ----- Trait impls (skip-loc equality / ordering / debug) -----

/// Helper for trait impls that skip over the `loc` field.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
struct BorrowEdgeNoLoc<'a, Lbl: Clone> {
    strong: bool,
    path: &'a Path<Lbl>,
}

impl<'a, Lbl: Clone + Ord> BorrowEdgeNoLoc<'a, Lbl> {
    fn new<Loc: Copy>(e: &'a BorrowEdge<Loc, Lbl>) -> Self {
        BorrowEdgeNoLoc {
            strong: e.strong,
            path: &e.path,
        }
    }
}

impl<Loc: Copy, Lbl: Clone + Ord> PartialEq for BorrowEdge<Loc, Lbl> {
    fn eq(&self, other: &BorrowEdge<Loc, Lbl>) -> bool {
        BorrowEdgeNoLoc::new(self) == BorrowEdgeNoLoc::new(other)
    }
}

impl<Loc: Copy, Lbl: Clone + Ord> Eq for BorrowEdge<Loc, Lbl> {}

#[allow(
    clippy::non_canonical_partial_ord_impl,
    reason = "byte-faithful mirror of upstream `vendor/move-borrow-graph/src/references.rs:213`; \
              the canonical impl would diverge from upstream's audit anchor"
)]
impl<Loc: Copy, Lbl: Clone + Ord> PartialOrd for BorrowEdge<Loc, Lbl> {
    fn partial_cmp(&self, other: &BorrowEdge<Loc, Lbl>) -> Option<Ordering> {
        BorrowEdgeNoLoc::new(self).partial_cmp(&BorrowEdgeNoLoc::new(other))
    }
}

impl<Loc: Copy, Lbl: Clone + Ord> Ord for BorrowEdge<Loc, Lbl> {
    fn cmp(&self, other: &BorrowEdge<Loc, Lbl>) -> Ordering {
        BorrowEdgeNoLoc::new(self).cmp(&BorrowEdgeNoLoc::new(other))
    }
}

impl<Loc: Copy, Lbl: Clone + Ord + Debug> Debug for BorrowEdge<Loc, Lbl> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        BorrowEdgeNoLoc::new(self).fmt(f)
    }
}

// ----- Iteration impls -----

impl<Loc: Copy, Lbl: Clone + Ord> IntoIterator for BorrowEdgeSet<Loc, Lbl> {
    type Item = BorrowEdge<Loc, Lbl>;
    type IntoIter = std::collections::btree_set::IntoIter<BorrowEdge<Loc, Lbl>>;

    fn into_iter(self) -> Self::IntoIter {
        debug_assert!(self.overflown || !self.is_empty());
        self.edges.into_iter()
    }
}

impl<'a, Loc: Copy, Lbl: Clone + Ord> IntoIterator for &'a BorrowEdgeSet<Loc, Lbl> {
    type Item = &'a BorrowEdge<Loc, Lbl>;
    type IntoIter = std::collections::btree_set::Iter<'a, BorrowEdge<Loc, Lbl>>;

    fn into_iter(self) -> Self::IntoIter {
        debug_assert!(self.overflown || !self.is_empty());
        self.edges.iter()
    }
}

// ===========================================================
// `BorrowGraph` (forked from
// `vendor/move-borrow-graph/src/graph.rs`)
// ===========================================================

/// The borrow graph: a directed graph over [`RefID`] nodes
/// where edges encode borrow relationships parameterized by
/// location (`Loc`) and field-path label (`Lbl`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct BorrowGraph<Loc: Copy, Lbl: Clone + Ord>(BTreeMap<RefID, Ref<Loc, Lbl>>);

impl<Loc: Copy, Lbl: Clone + Ord> BorrowGraph<Loc, Lbl> {
    /// Creates an empty borrow graph.
    #[allow(clippy::new_without_default)]
    pub(super) fn new() -> Self {
        Self(BTreeMap::new())
    }

    /// Returns the graph size, that is the number of nodes plus
    /// the number of edges.
    pub(super) fn graph_size(&self) -> usize {
        self.0
            .values()
            .map(|r| {
                1 + r
                    .borrowed_by
                    .0
                    .values()
                    .map(BorrowEdgeSet::len)
                    .sum::<usize>()
            })
            .sum()
    }

    /// Checks if the given reference is mutable.
    pub(super) fn is_mutable(&self, id: RefID) -> bool {
        self.0.get(&id).expect("borrow-graph invariant: ref_id/edge present by construction (reference-safety abstract interpreter never queries removed refs)").mutable
    }

    /// Adds a new reference to the borrow graph.
    ///
    /// # Panics
    ///
    /// Panics if `id` is already present.
    pub(super) fn new_ref(&mut self, id: RefID, mutable: bool) {
        assert!(
            self.0.insert(id, Ref::new(mutable)).is_none(),
            "ref {} exists",
            id.0
        );
    }

    /// Returns the references borrowing the `id` reference,
    /// collected by first label in the borrow edge:
    ///
    /// - `BTreeMap<RefID, Loc>` — "full" / "epsilon" borrows
    ///   (non-field borrows).
    /// - `BTreeMap<Lbl, BTreeMap<RefID, Loc>>` — field borrows,
    ///   collected over the first label.
    pub(super) fn borrowed_by(
        &self,
        id: RefID,
    ) -> (BTreeMap<RefID, Loc>, BTreeMap<Lbl, BTreeMap<RefID, Loc>>) {
        let borrowed_by = &self.0.get(&id).expect("borrow-graph invariant: ref_id/edge present by construction (reference-safety abstract interpreter never queries removed refs)").borrowed_by;
        let mut full_borrows: BTreeMap<RefID, Loc> = BTreeMap::new();
        let mut field_borrows: BTreeMap<Lbl, BTreeMap<RefID, Loc>> = BTreeMap::new();
        for (borrower, edges) in &borrowed_by.0 {
            let borrower = *borrower;
            for edge in edges {
                match edge.path.first() {
                    None => full_borrows.insert(borrower, edge.loc),
                    Some(f) => field_borrows
                        .entry(f.clone())
                        .or_default()
                        .insert(borrower, edge.loc),
                };
            }
        }
        (full_borrows, field_borrows)
    }

    /// Returns the edges between `parent` and `child`.
    pub(super) fn between_edges(&self, parent: RefID, child: RefID) -> Vec<(Loc, Path<Lbl>, bool)> {
        let edges = &self.0.get(&parent).expect("borrow-graph invariant: ref_id/edge present by construction (reference-safety abstract interpreter never queries removed refs)").borrowed_by.0[&child];
        edges
            .iter()
            .map(|edge| (edge.loc, edge.path.clone(), edge.strong))
            .collect()
    }

    /// Returns the outgoing edges from `id`.
    pub(super) fn out_edges(&self, id: RefID) -> Vec<(Loc, Path<Lbl>, bool, RefID)> {
        let mut returned_edges = vec![];
        let borrowed_by = &self.0.get(&id).expect("borrow-graph invariant: ref_id/edge present by construction (reference-safety abstract interpreter never queries removed refs)").borrowed_by;
        for (borrower, edges) in &borrowed_by.0 {
            let borrower = *borrower;
            for edge in edges {
                returned_edges.push((edge.loc, edge.path.clone(), edge.strong, borrower));
            }
        }
        returned_edges
    }

    /// Returns the incoming edges into `id`.
    pub(super) fn in_edges(&self, id: RefID) -> Vec<(Loc, RefID, Path<Lbl>, bool)> {
        let mut returned_edges = vec![];
        let borrows_from = &self.0.get(&id).expect("borrow-graph invariant: ref_id/edge present by construction (reference-safety abstract interpreter never queries removed refs)").borrows_from;
        for src in borrows_from {
            for edge in self.between_edges(*src, id) {
                returned_edges.push((edge.0, *src, edge.1, edge.2));
            }
        }
        returned_edges
    }

    // ----- Edges/Borrows -----

    /// Add a strong (exact) epsilon borrow from `parent_id` to
    /// `child_id`.
    pub(super) fn add_strong_borrow(&mut self, loc: Loc, parent_id: RefID, child_id: RefID) {
        self.factor(parent_id, loc, vec![], child_id);
    }

    /// Add a strong (exact) field borrow from `parent_id` to
    /// `child_id` at field `field`.
    pub(super) fn add_strong_field_borrow(
        &mut self,
        loc: Loc,
        parent_id: RefID,
        field: Lbl,
        child_id: RefID,
    ) {
        self.factor(parent_id, loc, vec![field], child_id);
    }

    /// Add a weak (prefix) epsilon borrow from `parent_id` to
    /// `child_id`. `child_id` might be borrowing from ANY field
    /// in `parent_id`.
    pub(super) fn add_weak_borrow(&mut self, loc: Loc, parent_id: RefID, child_id: RefID) {
        self.add_path(parent_id, loc, false, vec![], child_id);
    }

    /// Add a weak (prefix) field borrow from `parent_id` to
    /// `child_id` at field `field`. `child_id` might be
    /// borrowing from ANY field in `parent_id` rooted at `field`.
    pub(super) fn add_weak_field_borrow(
        &mut self,
        loc: Loc,
        parent_id: RefID,
        field: Lbl,
        child_id: RefID,
    ) {
        self.add_path(parent_id, loc, false, vec![field], child_id);
    }

    fn add_edge(&mut self, parent_id: RefID, edge: BorrowEdge<Loc, Lbl>, child_id: RefID) {
        assert!(parent_id != child_id);
        let parent = self.0.get_mut(&parent_id).expect("borrow-graph invariant: ref_id/edge present by construction (reference-safety abstract interpreter never queries removed refs)");
        parent
            .borrowed_by
            .0
            .entry(child_id)
            .or_insert_with(BorrowEdgeSet::new)
            .insert(edge);
        let child = self.0.get_mut(&child_id).expect("borrow-graph invariant: ref_id/edge present by construction (reference-safety abstract interpreter never queries removed refs)");
        child.borrows_from.insert(parent_id);
    }

    fn add_path(
        &mut self,
        parent_id: RefID,
        loc: Loc,
        strong: bool,
        path: Path<Lbl>,
        child_id: RefID,
    ) {
        let edge = BorrowEdge { strong, path, loc };
        self.add_edge(parent_id, edge, child_id);
    }

    fn factor(&mut self, parent_id: RefID, loc: Loc, path: Path<Lbl>, intermediate_id: RefID) {
        debug_assert!(self.check_invariant());
        let parent = self.0.get_mut(&parent_id).expect("borrow-graph invariant: ref_id/edge present by construction (reference-safety abstract interpreter never queries removed refs)");
        let mut needs_factored = vec![];
        for (child_id, parent_to_child_edges) in &parent.borrowed_by.0 {
            for parent_to_child_edge in parent_to_child_edges {
                if paths::leq(&path, &parent_to_child_edge.path) {
                    let factored_edge = (*child_id, parent_to_child_edge.clone());
                    needs_factored.push(factored_edge);
                }
            }
        }

        let mut cleanup_ids = BTreeSet::new();
        for (child_id, parent_to_child_edge) in &needs_factored {
            let parent_to_child_edges = parent.borrowed_by.0.get_mut(child_id).expect("borrow-graph invariant: ref_id/edge present by construction (reference-safety abstract interpreter never queries removed refs)");
            assert!(parent_to_child_edges.remove(parent_to_child_edge));
            if parent_to_child_edges.is_empty() {
                assert!(parent.borrowed_by.0.remove(child_id).is_some());
                cleanup_ids.insert(child_id);
            }
        }

        for child_id in cleanup_ids {
            assert!(self
                .0
                .get_mut(child_id)
                .expect("borrow-graph invariant: ref_id/edge present by construction (reference-safety abstract interpreter never queries removed refs)")
                .borrows_from
                .remove(&parent_id));
        }

        for (child_id, parent_to_child_edge) in needs_factored {
            let (_, intermediate_to_child_suffix) = paths::factor(&path, parent_to_child_edge.path);
            self.add_path(
                intermediate_id,
                parent_to_child_edge.loc,
                parent_to_child_edge.strong,
                intermediate_to_child_suffix,
                child_id,
            );
        }
        self.add_path(
            parent_id,
            loc,
            /* strong */ true,
            path,
            intermediate_id,
        );
        debug_assert!(self.check_invariant());
    }

    // ----- Release -----

    /// Remove reference `id` from the graph. Fixes any
    /// transitive borrows: if `parent` borrowed by `id` borrowed
    /// by `child`, after the release `parent` is borrowed by
    /// `child`.
    ///
    /// Returns the count of edges spliced through during the
    /// release.
    pub(super) fn release(&mut self, id: RefID) -> usize {
        debug_assert!(self.check_invariant());
        let Ref {
            borrowed_by,
            borrows_from,
            ..
        } = self.0.remove(&id).expect("borrow-graph invariant: ref_id/edge present by construction (reference-safety abstract interpreter never queries removed refs)");
        let mut released_edges = 0;
        for parent_ref_id in borrows_from {
            let parent = self.0.get_mut(&parent_ref_id).expect("borrow-graph invariant: ref_id/edge present by construction (reference-safety abstract interpreter never queries removed refs)");
            let parent_edges = parent.borrowed_by.0.remove(&id).expect("borrow-graph invariant: ref_id/edge present by construction (reference-safety abstract interpreter never queries removed refs)");
            for parent_edge in parent_edges {
                for (child_ref_id, child_edges) in &borrowed_by.0 {
                    for child_edge in child_edges {
                        released_edges += 1;
                        self.splice_out_intermediate(
                            parent_ref_id,
                            &parent_edge,
                            *child_ref_id,
                            child_edge,
                        );
                    }
                }
            }
        }
        for child_ref_id in borrowed_by.0.keys() {
            let child = self.0.get_mut(child_ref_id).expect("borrow-graph invariant: ref_id/edge present by construction (reference-safety abstract interpreter never queries removed refs)");
            child.borrows_from.remove(&id);
        }
        debug_assert!(self.check_invariant());
        released_edges
    }

    fn splice_out_intermediate(
        &mut self,
        parent_id: RefID,
        parent_to_intermediate: &BorrowEdge<Loc, Lbl>,
        child_id: RefID,
        intermediate_to_child: &BorrowEdge<Loc, Lbl>,
    ) {
        // Don't add an edge if releasing from a cycle.
        if parent_id == child_id {
            return;
        }

        let path = if parent_to_intermediate.strong {
            paths::append(&parent_to_intermediate.path, &intermediate_to_child.path)
        } else {
            parent_to_intermediate.path.clone()
        };
        let strong = parent_to_intermediate.strong && intermediate_to_child.strong;
        let loc = intermediate_to_child.loc;
        let parent_to_child = BorrowEdge { strong, path, loc };
        self.add_edge(parent_id, parent_to_child, child_id);
    }

    // ----- Subsumes/weakens -----

    /// Checks if `self` covers `other` (every edge in `other`
    /// has a `<=` edge in `self`).
    pub(super) fn leq(&self, other: &Self) -> bool {
        self.unmatched_edges(other).is_empty()
    }

    fn unmatched_edges(&self, other: &Self) -> BTreeMap<RefID, BorrowEdges<Loc, Lbl>> {
        let mut unmatched_edges = BTreeMap::new();
        for (parent_id, other_ref) in &other.0 {
            let self_ref = &self.0[parent_id];
            let self_borrowed_by = &self_ref.borrowed_by.0;
            for (child_id, other_edges) in &other_ref.borrowed_by.0 {
                for other_edge in other_edges {
                    let found_match =
                        self_borrowed_by
                            .get(child_id)
                            .is_some_and(|parent_to_child| {
                                parent_to_child
                                    .iter()
                                    .any(|self_edge| self_edge.leq(other_edge))
                            });
                    if !found_match {
                        assert!(parent_id != child_id);
                        unmatched_edges
                            .entry(*parent_id)
                            .or_insert_with(BorrowEdges::new)
                            .0
                            .entry(*child_id)
                            .or_insert_with(BorrowEdgeSet::new)
                            .insert(other_edge.clone());
                    }
                }
            }
        }
        unmatched_edges
    }

    // ----- Remap -----

    /// Utility for remapping the reference ids according to
    /// `id_map`. Ids not in the map are passed through unchanged.
    pub(super) fn remap_refs(&mut self, id_map: &BTreeMap<RefID, RefID>) {
        debug_assert!(self.check_invariant());
        let before = self.0.len();
        self.0 = std::mem::take(&mut self.0)
            .into_iter()
            .map(|(id, mut info)| {
                info.remap_refs(id_map);
                (id_map.get(&id).copied().unwrap_or(id), info)
            })
            .collect();
        let after = self.0.len();
        debug_assert!(before == after);
        debug_assert!(self.check_invariant());
    }

    // ----- Joins -----

    /// Joins `other` into `self`. Adds only "unmatched" edges
    /// from `other` into `self`: for any edge in `other`, if
    /// there is an edge in `self` that is `<=` than that edge,
    /// it is not added.
    pub(super) fn join(&self, other: &Self) -> Self {
        debug_assert!(self.check_invariant());
        debug_assert!(other.check_invariant());
        debug_assert!(self.0.keys().all(|id| other.0.contains_key(id)));
        debug_assert!(other.0.keys().all(|id| self.0.contains_key(id)));

        let mut joined = self.clone();
        for (parent_id, unmatched_borrowed_by) in self.unmatched_edges(other) {
            for (child_id, unmatched_edges) in unmatched_borrowed_by.0 {
                for unmatched_edge in unmatched_edges {
                    joined.add_edge(parent_id, unmatched_edge, child_id);
                }
            }
        }
        debug_assert!(joined.check_invariant());
        joined
    }

    // ----- Consistency/Invariants -----

    fn check_invariant(&self) -> bool {
        self.id_consistency() && self.edge_consistency() && self.no_self_loops()
    }

    /// Checks that all ids in edges are contained in the borrow
    /// map (i.e. that each id corresponds to a reference).
    fn id_consistency(&self) -> bool {
        let contains_id = |id| self.0.contains_key(id);
        self.0.values().all(|r| {
            r.borrowed_by.0.keys().all(contains_id) && r.borrows_from.iter().all(contains_id)
        })
    }

    /// Checks that for every edge in `borrowed_by` there is a
    /// flipped edge in `borrows_from` (and vice versa).
    fn edge_consistency(&self) -> bool {
        let parent_to_child_consistency =
            |cur_parent, child| self.0[child].borrows_from.contains(cur_parent);
        let child_to_parent_consistency =
            |cur_child, parent| self.0[parent].borrowed_by.0.contains_key(cur_child);
        self.0.iter().all(|(id, r)| {
            let borrowed_by_is_bounded = r
                .borrowed_by
                .0
                .values()
                .all(|edges| edges.len() <= MAX_EDGE_SET_SIZE);
            let borrowed_by_is_consistent = r
                .borrowed_by
                .0
                .keys()
                .all(|c| parent_to_child_consistency(id, c));
            let borrows_from_is_consistent = r
                .borrows_from
                .iter()
                .all(|p| child_to_parent_consistency(id, p));
            borrowed_by_is_bounded && borrowed_by_is_consistent && borrows_from_is_consistent
        })
    }

    /// Checks that no reference borrows from itself.
    fn no_self_loops(&self) -> bool {
        self.0.iter().all(|(id, r)| {
            r.borrowed_by.0.keys().all(|to_id| id != to_id)
                && r.borrows_from.iter().all(|from_id| id != from_id)
        })
    }

    // ----- Util -----

    /// Returns `true` if `ref_id` is in the graph.
    pub(super) fn contains_id(&self, ref_id: RefID) -> bool {
        self.0.contains_key(&ref_id)
    }

    /// Returns all reference ids in the graph.
    pub(super) fn all_refs(&self) -> BTreeSet<RefID> {
        self.0.keys().copied().collect()
    }

    /// Prints a textual view of the borrow graph for debugging
    /// borrow-graph behaviour from inside test fixtures.
    ///
    /// Gated under `#[cfg(test)]` so the `println!` calls do not
    /// ship in production builds — production paths must not write
    /// to stdout per CLAUDE.md §8 (audit-pass discipline finding).
    #[cfg(test)]
    #[allow(
        dead_code,
        reason = "test-only debugging helper; reserved for future use"
    )]
    pub(super) fn display(&self)
    where
        Lbl: std::fmt::Display,
    {
        fn path_to_string<Lbl: std::fmt::Display>(p: &PathSlice<Lbl>) -> String {
            p.iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(".")
        }

        for (id, ref_info) in &self.0 {
            if ref_info.borrowed_by.0.is_empty() && ref_info.borrows_from.is_empty() {
                println!("{}", id.0);
            }
            for (borrower, edges) in &ref_info.borrowed_by.0 {
                for edge in edges {
                    let edisp = if edge.strong { "=" } else { "-" };
                    println!(
                        "{} {}{}{}> {}",
                        id.0,
                        edisp,
                        path_to_string(&edge.path),
                        edisp,
                        borrower.0,
                    );
                }
            }
            for parent in &ref_info.borrows_from {
                println!("{} <- {}", parent.0, id.0);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    //! Layer A unit tests for the borrow-graph foundation.
    //!
    //! Coverage at D-5b.1: public API methods consumed by
    //! `reference_safety/abstract_state.rs` at D-5b.2. Mirrors
    //! D-1a / D-1b / D-5a.0 unit-test posture for foundational
    //! ports — exercising the data-structure operations
    //! independently before any consumer wires in.

    use super::*;

    type Loc = u16;
    type Lbl = u8;

    fn rid(i: usize) -> RefID {
        RefID::new(i)
    }

    fn graph() -> BorrowGraph<Loc, Lbl> {
        BorrowGraph::new()
    }

    // --- Scaffolding ---

    #[test]
    fn ref_id_round_trips_through_number() {
        let r = RefID::new(42);
        assert_eq!(r.number(), 42);
    }

    #[test]
    fn empty_graph_has_size_zero_and_no_refs() {
        let g: BorrowGraph<Loc, Lbl> = graph();
        assert_eq!(g.graph_size(), 0);
        assert!(g.all_refs().is_empty());
        assert!(!g.contains_id(rid(0)));
    }

    #[test]
    fn new_ref_inserts_into_graph() {
        let mut g: BorrowGraph<Loc, Lbl> = graph();
        g.new_ref(rid(0), true);
        assert!(g.contains_id(rid(0)));
        assert!(g.is_mutable(rid(0)));
        assert_eq!(g.graph_size(), 1);
    }

    #[test]
    fn new_ref_immutable() {
        let mut g: BorrowGraph<Loc, Lbl> = graph();
        g.new_ref(rid(0), false);
        assert!(!g.is_mutable(rid(0)));
    }

    #[test]
    #[should_panic(expected = "ref 0 exists")]
    fn new_ref_duplicate_panics() {
        let mut g: BorrowGraph<Loc, Lbl> = graph();
        g.new_ref(rid(0), true);
        g.new_ref(rid(0), false);
    }

    // --- Strong / weak / field borrows ---

    #[test]
    fn add_strong_borrow_creates_parent_child_edge() {
        let mut g: BorrowGraph<Loc, Lbl> = graph();
        g.new_ref(rid(0), true);
        g.new_ref(rid(1), true);
        g.add_strong_borrow(7u16, rid(0), rid(1));
        let (full, fields) = g.borrowed_by(rid(0));
        assert_eq!(full.len(), 1);
        assert_eq!(full.get(&rid(1)), Some(&7u16));
        assert!(fields.is_empty());
    }

    #[test]
    fn add_weak_borrow_creates_parent_child_edge() {
        let mut g: BorrowGraph<Loc, Lbl> = graph();
        g.new_ref(rid(0), true);
        g.new_ref(rid(1), true);
        g.add_weak_borrow(3u16, rid(0), rid(1));
        let (full, fields) = g.borrowed_by(rid(0));
        // Weak/epsilon path is empty, so it counts as a full
        // borrow from `borrowed_by`'s point of view.
        assert_eq!(full.len(), 1);
        assert!(fields.is_empty());
    }

    #[test]
    fn add_strong_field_borrow_records_field_label() {
        let mut g: BorrowGraph<Loc, Lbl> = graph();
        g.new_ref(rid(0), true);
        g.new_ref(rid(1), true);
        g.add_strong_field_borrow(1u16, rid(0), 42u8, rid(1));
        let (full, fields) = g.borrowed_by(rid(0));
        assert!(full.is_empty());
        assert_eq!(fields.len(), 1);
        let inner = fields.get(&42u8).expect("field 42 borrow");
        assert_eq!(inner.get(&rid(1)), Some(&1u16));
    }

    #[test]
    fn add_weak_field_borrow_records_field_label() {
        let mut g: BorrowGraph<Loc, Lbl> = graph();
        g.new_ref(rid(0), true);
        g.new_ref(rid(1), true);
        g.add_weak_field_borrow(2u16, rid(0), 9u8, rid(1));
        let (_full, fields) = g.borrowed_by(rid(0));
        assert!(fields.contains_key(&9u8));
    }

    #[test]
    fn out_edges_lists_borrow_to_children() {
        let mut g: BorrowGraph<Loc, Lbl> = graph();
        g.new_ref(rid(0), true);
        g.new_ref(rid(1), true);
        g.new_ref(rid(2), true);
        g.add_strong_borrow(10u16, rid(0), rid(1));
        g.add_strong_field_borrow(11u16, rid(0), 5u8, rid(2));
        let edges = g.out_edges(rid(0));
        assert_eq!(edges.len(), 2);
        let children: Vec<_> = edges.iter().map(|(_, _, _, c)| *c).collect();
        assert!(children.contains(&rid(1)));
        assert!(children.contains(&rid(2)));
    }

    #[test]
    fn in_edges_lists_borrow_from_parents() {
        let mut g: BorrowGraph<Loc, Lbl> = graph();
        g.new_ref(rid(0), true);
        g.new_ref(rid(1), true);
        g.add_strong_borrow(4u16, rid(0), rid(1));
        let edges = g.in_edges(rid(1));
        assert_eq!(edges.len(), 1);
        assert_eq!(edges[0].1, rid(0));
    }

    // --- Release ---

    #[test]
    fn release_disconnects_intermediate_and_splices_through() {
        // 0 -> 1 -> 2; release 1; result: 0 -> 2.
        let mut g: BorrowGraph<Loc, Lbl> = graph();
        g.new_ref(rid(0), true);
        g.new_ref(rid(1), true);
        g.new_ref(rid(2), true);
        g.add_strong_borrow(0u16, rid(0), rid(1));
        g.add_strong_borrow(0u16, rid(1), rid(2));
        let released = g.release(rid(1));
        assert!(!g.contains_id(rid(1)));
        assert_eq!(released, 1);
        // 0 should now borrow 2 directly.
        let edges_from_0 = g.out_edges(rid(0));
        assert_eq!(edges_from_0.len(), 1);
        assert_eq!(edges_from_0[0].3, rid(2));
    }

    #[test]
    fn release_leaf_drops_one_edge() {
        let mut g: BorrowGraph<Loc, Lbl> = graph();
        g.new_ref(rid(0), true);
        g.new_ref(rid(1), true);
        g.add_strong_borrow(0u16, rid(0), rid(1));
        let released = g.release(rid(1));
        assert!(!g.contains_id(rid(1)));
        // Releasing a leaf with no children produces 0
        // splice-throughs (the `released_edges` counter counts
        // splices, not removals).
        assert_eq!(released, 0);
        // 0 has no outgoing edges left.
        assert!(g.out_edges(rid(0)).is_empty());
    }

    // --- leq / join ---

    #[test]
    fn leq_self_is_true_for_empty() {
        let g: BorrowGraph<Loc, Lbl> = graph();
        assert!(g.leq(&g));
    }

    #[test]
    fn leq_directions_reflect_edge_inclusion() {
        // smaller_g has no edges; larger_g has 0 -> 1.
        // `leq` semantics: `a.leq(&b)` means `a` covers `b`, i.e.
        // every edge in `b` has a covering edge in `a`. Therefore:
        // - smaller_g does NOT cover larger_g (extra edge in
        //   larger_g unmatched in smaller_g).
        // - larger_g DOES cover smaller_g (smaller_g has no
        //   edges; trivially covered).
        let mut smaller_g: BorrowGraph<Loc, Lbl> = graph();
        smaller_g.new_ref(rid(0), true);
        smaller_g.new_ref(rid(1), true);
        let mut larger_g = smaller_g.clone();
        larger_g.add_strong_borrow(0u16, rid(0), rid(1));
        assert!(!smaller_g.leq(&larger_g), "smaller does not cover larger");
        assert!(
            larger_g.leq(&smaller_g),
            "larger trivially covers empty smaller"
        );
    }

    #[test]
    fn join_merges_edges_from_other() {
        let mut a: BorrowGraph<Loc, Lbl> = graph();
        a.new_ref(rid(0), true);
        a.new_ref(rid(1), true);
        a.new_ref(rid(2), true);
        let mut b = a.clone();
        a.add_strong_borrow(0u16, rid(0), rid(1));
        b.add_strong_borrow(0u16, rid(0), rid(2));
        let joined = a.join(&b);
        let edges = joined.out_edges(rid(0));
        let children: Vec<_> = edges.iter().map(|(_, _, _, c)| *c).collect();
        assert!(children.contains(&rid(1)));
        assert!(children.contains(&rid(2)));
    }

    // --- remap ---

    #[test]
    fn remap_refs_renumbers_ids() {
        let mut g: BorrowGraph<Loc, Lbl> = graph();
        g.new_ref(rid(0), true);
        g.new_ref(rid(1), true);
        g.add_strong_borrow(0u16, rid(0), rid(1));
        let mut id_map = BTreeMap::new();
        id_map.insert(rid(0), rid(10));
        id_map.insert(rid(1), rid(11));
        g.remap_refs(&id_map);
        assert!(g.contains_id(rid(10)));
        assert!(g.contains_id(rid(11)));
        assert!(!g.contains_id(rid(0)));
        assert!(!g.contains_id(rid(1)));
        let edges = g.out_edges(rid(10));
        assert_eq!(edges[0].3, rid(11));
    }

    // --- MAX_EDGE_SET_SIZE overflow ---

    #[test]
    fn edge_set_overflow_collapses_to_lossy_single_edge() {
        // Push MAX_EDGE_SET_SIZE + 1 distinct edges between
        // parent and child by varying field labels.
        let mut g: BorrowGraph<Loc, Lbl> = graph();
        g.new_ref(rid(0), true);
        g.new_ref(rid(1), true);
        let cap = u8::try_from(MAX_EDGE_SET_SIZE).expect("MAX_EDGE_SET_SIZE = 10 fits u8");
        for i in 0..=cap {
            g.add_strong_field_borrow(u16::from(i), rid(0), i, rid(1));
        }
        // After overflow, the set collapses to a single weak-
        // epsilon edge; observed via `between_edges` on the
        // 0 -> 1 pair.
        let edges = g.between_edges(rid(0), rid(1));
        assert_eq!(edges.len(), 1, "lossy-overflow collapses to one edge");
        let (_loc, path, strong) = &edges[0];
        assert!(path.is_empty(), "overflow edge is epsilon");
        assert!(!strong, "overflow edge is weak");
    }

    // --- paths submodule helpers ---

    #[test]
    fn paths_leq_prefix_relation() {
        let a: Vec<u8> = vec![1, 2];
        let b: Vec<u8> = vec![1, 2, 3];
        let c: Vec<u8> = vec![1, 4];
        assert!(paths::leq(&a, &b));
        assert!(!paths::leq(&b, &a));
        assert!(!paths::leq(&a, &c));
        assert!(paths::leq(&[][..], &a));
    }

    #[test]
    fn paths_factor_splits_by_prefix() {
        let prefix: Vec<u8> = vec![1, 2];
        let full: Vec<u8> = vec![1, 2, 3, 4];
        let (left, suffix) = paths::factor(&prefix, full);
        assert_eq!(left, vec![1, 2]);
        assert_eq!(suffix, vec![3, 4]);
    }

    #[test]
    fn paths_append_concatenates() {
        let lhs: Vec<u8> = vec![1, 2];
        let rhs: Vec<u8> = vec![3, 4];
        let joined = paths::append(&lhs, &rhs);
        assert_eq!(joined, vec![1, 2, 3, 4]);
    }
}
