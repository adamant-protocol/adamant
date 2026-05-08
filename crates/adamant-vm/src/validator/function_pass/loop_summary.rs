//! Loop-structure summary for the reducibility check (whitepaper
//! §6.2.1.8 step 4).
//!
//! Forked byte-faithfully from
//! `vendor/move-bytecode-verifier/src/loop_summary.rs` at
//! Sui-Move tag `mainnet-v1.66.2`. Computes the depth-first
//! spanning tree (DFST) of an [`AdamantControlFlowGraph`] and
//! derives:
//!
//! - The **DFST edge classification.** Edges are partitioned
//!   into back edges (cycle-creating: target's exploration is
//!   `InProgress` when the edge is traversed) and predecessor
//!   edges (everything else: cross edges and tree edges).
//! - The **descendant relation.** [`LoopSummary::is_descendant`]
//!   answers ancestry queries in O(1) via a preorder-numbering
//!   invariant: a node's descendants in the DFST occupy the
//!   contiguous range `[id, id + descs[id]]` in [`NodeId`]
//!   space. Tarjan 1974, used by the reducibility check to
//!   verify the "every node in a loop's body is dominated by
//!   the loop head" property.
//! - The **block mapping.** [`LoopSummary::block`] recovers the
//!   originating CFG block id (a [`CodeOffset`]) for any
//!   `NodeId`, used for diagnostic messaging.
//!
//! [`LoopPartition`] sits on top of [`LoopSummary`] as a
//! disjoint-set data structure tracking loop-nesting depth as
//! the reducibility check collapses each loop's body into its
//! head.
//!
//! # Adamant deviations
//!
//! - Operates on [`AdamantControlFlowGraph`] (D-1a) directly
//!   rather than upstream's `VMControlFlowGraph` via the
//!   `move_abstract_interpreter::control_flow_graph::ControlFlowGraph`
//!   trait. Adamant has a single CFG type; the trait
//!   abstraction doesn't earn its keep. Same shape rationale as
//!   D-1a's CFG specialisation.
//! - The `NodeId(u16)` dense-index abstraction over `BlockId =
//!   CodeOffset` is preserved byte-faithfully — load-bearing
//!   for [`Self::is_descendant`]'s O(1) ancestor check via the
//!   preorder-numbering invariant
//!   `ancestor <= descendant && descendant <= ancestor + descs[ancestor]`
//!   (Tarjan 1974). Removing the indirection would force a
//!   different reducibility implementation; per Q1 walk-back
//!   precedent (3rd instance at D-2 closure, rule-of-three
//!   threshold met), byte-faithful preservation rules.

use std::collections::{btree_map::Entry, BTreeMap, BTreeSet};

use adamant_bytecode_format::CodeOffset;

use super::cfg::AdamantControlFlowGraph;

type BlockId = CodeOffset;

/// Dense index into nodes in the same [`LoopSummary`].
///
/// Assigned in DFST preorder by [`LoopSummary::new`], so that
/// `NodeId` ordering matches DFST preorder ordering. Load-
/// bearing for [`LoopSummary::is_descendant`]'s O(1) check.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct NodeId(u16);

/// Type alias to treat vectors as `NodeId -> T` maps.
type NodeMap<T> = Vec<T>;

/// Summary of an [`AdamantControlFlowGraph`]'s DFST + edge
/// classification + block mapping. See module-level doc.
pub(super) struct LoopSummary {
    /// Original CFG block corresponding to each `NodeId`.
    blocks: NodeMap<BlockId>,
    /// Number of transitive descendants for each node in the
    /// DFST. Used to answer ancestry queries via the preorder-
    /// numbering invariant.
    descs: NodeMap<u16>,
    /// Back-edge sources for each node. Back edges are
    /// detected when a successor's exploration is
    /// `InProgress` at edge-traversal time.
    backs: NodeMap<Vec<NodeId>>,
    /// Non-back predecessor edges for each node (tree edges +
    /// cross edges).
    preds: NodeMap<Vec<NodeId>>,
}

/// Disjoint-set data structure used by the reducibility check
/// to collapse loops into single nodes while tracking nesting
/// depth.
pub(super) struct LoopPartition {
    /// Parent relationship in the disjoint-set. The transitive
    /// closure maps each node to its representative (the head
    /// of the collapsed loop containing it).
    parents: NodeMap<NodeId>,
    /// Nesting depth of each (collapsed) representative node.
    /// Uncollapsed nodes have depth 0; each
    /// [`Self::collapse_loop`] call increments the head's
    /// depth.
    depths: NodeMap<u16>,
}

impl LoopSummary {
    /// Build a [`LoopSummary`] for the given CFG.
    ///
    /// Algorithm: iterative depth-first traversal from the CFG's
    /// entry block. The frontier carries `Visit` actions (visit
    /// the target block of an edge) and `Finish` actions (close
    /// out a node and propagate its descendant count to its
    /// parent). Pre-order assigns `NodeId`s in the order each
    /// new block is first reached.
    pub(super) fn new(cfg: &AdamantControlFlowGraph) -> Self {
        use Exploration::{Done, InProgress};
        use Frontier::{Finish, Visit};

        let num_blocks = cfg.num_blocks();

        let mut blocks: NodeMap<BlockId> = vec![0; num_blocks];
        let mut descs: NodeMap<u16> = vec![0; num_blocks];
        let mut backs: NodeMap<Vec<NodeId>> = vec![vec![]; num_blocks];
        let mut preds: NodeMap<Vec<NodeId>> = vec![vec![]; num_blocks];

        let mut next_node = NodeId(0);

        let root_block = cfg.entry_block_id();
        let root_node = next_node.bump();

        let mut exploration: BTreeMap<BlockId, Exploration> = BTreeMap::new();
        blocks[usize::from(root_node)] = root_block;
        exploration.insert(root_block, InProgress(root_node));

        let mut stack: Vec<Frontier> = cfg
            .successors(root_block)
            .map(|succ| Visit {
                from_node: root_node,
                to_block: succ,
            })
            .collect();

        while let Some(action) = stack.pop() {
            match action {
                Finish {
                    block,
                    node_id,
                    parent,
                } => {
                    descs[usize::from(parent)] += 1 + descs[usize::from(node_id)];
                    *exploration
                        .get_mut(&block)
                        .expect("Finish for a block whose Visit was processed") = Done(node_id);
                }
                Visit {
                    from_node,
                    to_block,
                } => match exploration.entry(to_block) {
                    Entry::Occupied(entry) => match entry.get() {
                        // Back edge: re-visiting `to` while it
                        // is still being explored.
                        InProgress(to_node) => backs[usize::from(*to_node)].push(from_node),
                        // Cross edge: re-visiting `to` after
                        // it has been fully explored.
                        Done(to_node) => preds[usize::from(*to_node)].push(from_node),
                    },
                    // Tree edge: first visit. `from` is the
                    // DFST parent of `to`.
                    Entry::Vacant(entry) => {
                        let to_node = next_node.bump();
                        entry.insert(InProgress(to_node));
                        blocks[usize::from(to_node)] = to_block;
                        preds[usize::from(to_node)].push(from_node);

                        stack.push(Finish {
                            block: to_block,
                            node_id: to_node,
                            parent: from_node,
                        });

                        stack.extend(cfg.successors(to_block).map(|succ| Visit {
                            from_node: to_node,
                            to_block: succ,
                        }));
                    }
                },
            }
        }

        // The DFST may not reach every CFG block (orphaned
        // unreachable blocks have no incoming-from-entry path).
        // Truncate the per-NodeId vectors to only the visited
        // count so vector indexing is bounded by the actual
        // node count.
        let visited = usize::from(next_node);
        blocks.truncate(visited);
        descs.truncate(visited);
        backs.truncate(visited);
        preds.truncate(visited);

        Self {
            blocks,
            descs,
            backs,
            preds,
        }
    }

    /// Returns `true` if `descendant` is a descendant (or self)
    /// of `ancestor` in the DFST.
    ///
    /// Uses the preorder-numbering invariant: descendants of a
    /// node occupy the contiguous range
    /// `[ancestor, ancestor + descs[ancestor]]` in `NodeId`
    /// space (Tarjan 1974). O(1) per query.
    pub(super) fn is_descendant(
        &self,
        NodeId(ancestor): NodeId,
        NodeId(descendant): NodeId,
    ) -> bool {
        ancestor <= descendant && descendant <= ancestor + self.descs[ancestor as usize]
    }

    /// Returns an iterator over `NodeId`s in DFST preorder.
    ///
    /// `LoopSummary::new` assigns `NodeId`s in preorder, so the
    /// natural ordering of `NodeId`s is the preorder.
    pub(super) fn preorder(&self) -> impl DoubleEndedIterator<Item = NodeId> + '_ {
        (0..self.blocks.len()).map(|id| {
            NodeId(
                u16::try_from(id).expect(
                    "DFST node count fits u16; CFG block count is bounded by binary format",
                ),
            )
        })
    }

    /// Returns the CFG block id (a [`CodeOffset`]) backing
    /// `node`.
    pub(super) fn block(&self, node: NodeId) -> BlockId {
        self.blocks[usize::from(node)]
    }

    /// Returns the back-edge source list for `node`.
    pub(super) fn back_edges(&self, node: NodeId) -> &Vec<NodeId> {
        &self.backs[usize::from(node)]
    }

    /// Returns the non-back predecessor list for `node` (tree +
    /// cross edges).
    pub(super) fn pred_edges(&self, node: NodeId) -> &Vec<NodeId> {
        &self.preds[usize::from(node)]
    }
}

impl LoopPartition {
    /// Build a fresh [`LoopPartition`] over `summary`. Initially
    /// every node is its own representative with nesting depth
    /// 0.
    pub(super) fn new(summary: &LoopSummary) -> Self {
        let num_blocks = summary.blocks.len();
        Self {
            parents: (0..num_blocks)
                .map(|id| {
                    NodeId(u16::try_from(id).expect(
                        "DFST node count fits u16; CFG block count is bounded by binary format",
                    ))
                })
                .collect(),
            depths: vec![0; num_blocks],
        }
    }

    /// Find the head of the collapsed loop containing `id`.
    /// Uses path-compression to amortise future lookups.
    pub(super) fn containing_loop(&mut self, id: NodeId) -> NodeId {
        let mut child = id;
        let mut parent = self.parent(child);
        let mut grandparent = self.parent(parent);

        if child == parent || parent == grandparent {
            return parent;
        }

        let mut descendants = vec![];
        loop {
            // Invariant: child -> parent -> grandparent
            //       and  parent != grandparent
            //       and  forall d in descendants. parent(d) != parent(parent(d))
            descendants.push(child);
            (child, parent, grandparent) = (parent, grandparent, self.parent(grandparent));
            if parent == grandparent {
                break;
            }
        }

        for descendant in descendants {
            *self.parent_mut(descendant) = parent;
        }

        parent
    }

    /// Collapse `body` of a loop into the single representative
    /// `head`. Returns the new nesting depth of `head`.
    ///
    /// Assumes every member of `body ∪ {head}` is currently its
    /// own partition representative (callers ensure this by
    /// resolving `containing_loop` before adding to `body`).
    /// `body` may be empty, in which case `head` is the only
    /// node in the loop (a self-loop); the depth is still
    /// incremented by 1.
    pub(super) fn collapse_loop(&mut self, head: NodeId, body: &BTreeSet<NodeId>) -> u16 {
        debug_assert_eq!(head, self.parent(head));

        let mut depth = self.depth(head);
        for constituent in body {
            debug_assert_eq!(*constituent, self.parent(*constituent));
            *self.parent_mut(*constituent) = head;
            depth = self.depth(*constituent).max(depth);
        }

        depth += 1;
        *self.depth_mut(head) = depth;
        depth
    }

    fn parent(&self, n: NodeId) -> NodeId {
        self.parents[usize::from(n)]
    }

    fn parent_mut(&mut self, n: NodeId) -> &mut NodeId {
        &mut self.parents[usize::from(n)]
    }

    fn depth(&self, n: NodeId) -> u16 {
        self.depths[usize::from(n)]
    }

    fn depth_mut(&mut self, n: NodeId) -> &mut u16 {
        &mut self.depths[usize::from(n)]
    }
}

impl NodeId {
    /// Post-increment (`self++`); returns the value before the
    /// increment.
    fn bump(&mut self) -> Self {
        let ret = *self;
        self.0 += 1;
        ret
    }
}

impl From<NodeId> for usize {
    fn from(NodeId(id): NodeId) -> Self {
        Self::from(id)
    }
}

/// Hoisted to module level (rather than nested inside
/// [`LoopSummary::new`]) per the `hoisted-enum-for-clippy-items-
/// after-statements` pattern (registered at D-1a).
enum Exploration {
    /// Block's sub-graph is being explored. Re-visiting the
    /// block from a successor edge identifies a back edge.
    InProgress(NodeId),
    /// Block has been fully explored. Re-visiting the block
    /// from a successor edge identifies a cross edge.
    Done(NodeId),
}

/// Frontier action used by the iterative DFS in
/// [`LoopSummary::new`]. Hoisted to module level (rather than
/// nested) per the same pattern as [`Exploration`].
enum Frontier {
    /// Visit the target block of an edge from `from_node`.
    Visit {
        from_node: NodeId,
        to_block: BlockId,
    },
    /// Close out the visit of `block` (assigned `node_id`) and
    /// propagate its transitive descendant count up to
    /// `parent`.
    Finish {
        block: BlockId,
        node_id: NodeId,
        parent: NodeId,
    },
}

#[cfg(test)]
mod tests {
    //! Layer A unit tests for [`LoopSummary`] + [`LoopPartition`].
    //! Exercises DFST construction, edge classification,
    //! ancestor queries, and partition collapse semantics on
    //! synthetic CFGs covering linear, diamond, simple-loop, and
    //! nested-loop shapes.

    use super::*;
    use crate::bytecode::BytecodeInstruction;
    use adamant_bytecode_format::{Bytecode, VariantJumpTable};

    fn ret() -> BytecodeInstruction {
        BytecodeInstruction::Inherited(Bytecode::Ret)
    }

    fn nop() -> BytecodeInstruction {
        BytecodeInstruction::Inherited(Bytecode::Nop)
    }

    fn ld_true() -> BytecodeInstruction {
        BytecodeInstruction::Inherited(Bytecode::LdTrue)
    }

    fn br_true(target: CodeOffset) -> BytecodeInstruction {
        BytecodeInstruction::Inherited(Bytecode::BrTrue(target))
    }

    fn branch(target: CodeOffset) -> BytecodeInstruction {
        BytecodeInstruction::Inherited(Bytecode::Branch(target))
    }

    fn cfg_of(code: &[BytecodeInstruction]) -> AdamantControlFlowGraph {
        let jts: Vec<VariantJumpTable> = vec![];
        AdamantControlFlowGraph::new(code, &jts)
    }

    /// `NodeId`s are assigned in DFST preorder; `preorder()`
    /// iterates them in that order.
    #[test]
    fn node_id_preorder_assignment() {
        // 0: LdTrue
        // 1: BrTrue 3
        // 2: Nop      <- fall-through
        // 3: Ret
        let cfg = cfg_of(&[ld_true(), br_true(3), nop(), ret()]);
        let summary = LoopSummary::new(&cfg);
        let preorder: Vec<NodeId> = summary.preorder().collect();
        // Three blocks reachable from entry: 0, 2, 3.
        assert_eq!(preorder.len(), 3);
        // Ascending NodeIds.
        for w in preorder.windows(2) {
            assert!(w[0] < w[1]);
        }
        // Entry block always gets NodeId(0).
        assert_eq!(summary.block(NodeId(0)), 0);
    }

    /// Every node is its own descendant (reflexive ancestry).
    #[test]
    fn is_descendant_self() {
        let cfg = cfg_of(&[ret()]);
        let summary = LoopSummary::new(&cfg);
        let entry = NodeId(0);
        assert!(summary.is_descendant(entry, entry));
    }

    /// In a linear chain, every later node is a descendant of
    /// every earlier node in the DFST.
    #[test]
    fn is_descendant_via_dfst() {
        let cfg = cfg_of(&[ld_true(), br_true(2), nop(), ret()]);
        let summary = LoopSummary::new(&cfg);
        let preorder: Vec<NodeId> = summary.preorder().collect();
        let root = preorder[0];
        for descendant in &preorder[1..] {
            assert!(
                summary.is_descendant(root, *descendant),
                "every node should be a descendant of root in preorder DFST"
            );
        }
    }

    /// A back edge populates the target's `back_edges` list.
    #[test]
    fn back_edges_recorded() {
        // 0: LdTrue          <- header (loop head)
        // 1: BrTrue 4        <- exit
        // 2: Nop
        // 3: Branch 0        <- back edge to entry
        // 4: Ret
        let cfg = cfg_of(&[ld_true(), br_true(4), nop(), branch(0), ret()]);
        let summary = LoopSummary::new(&cfg);
        // Find the entry node (block 0).
        let entry = summary
            .preorder()
            .find(|n| summary.block(*n) == 0)
            .expect("entry block exists");
        // It should have at least one back edge.
        assert!(
            !summary.back_edges(entry).is_empty(),
            "entry node should have a back edge from the loop body"
        );
    }

    /// Cross/tree edges populate `pred_edges`.
    #[test]
    fn pred_edges_recorded_for_cross_edges() {
        // If-else diamond: both arms reach the join block.
        // 0: LdTrue
        // 1: BrTrue 4
        // 2: Nop                  <- false arm
        // 3: Branch 5
        // 4: Nop                  <- true arm
        // 5: Ret                  <- join
        let cfg = cfg_of(&[ld_true(), br_true(4), nop(), branch(5), nop(), ret()]);
        let summary = LoopSummary::new(&cfg);
        // The join block (offset 5) should have a non-empty
        // pred_edges list — at least one arm reaches it via a
        // tree or cross edge.
        let join = summary
            .preorder()
            .find(|n| summary.block(*n) == 5)
            .expect("join block exists");
        assert!(
            !summary.pred_edges(join).is_empty(),
            "join block must have predecessors recorded"
        );
    }

    /// Collapsing a loop increments the head's depth.
    #[test]
    fn loop_partition_collapse_increments_depth() {
        let cfg = cfg_of(&[ld_true(), br_true(4), nop(), branch(0), ret()]);
        let summary = LoopSummary::new(&cfg);
        let mut partition = LoopPartition::new(&summary);
        let entry = NodeId(0);
        let body: BTreeSet<NodeId> = BTreeSet::new();
        let depth = partition.collapse_loop(entry, &body);
        assert_eq!(depth, 1, "single self-loop collapse increments depth to 1");
    }

    /// `containing_loop` performs path-compression so repeated
    /// calls return the representative cheaply.
    #[test]
    fn loop_partition_path_compression() {
        let cfg = cfg_of(&[ld_true(), br_true(4), nop(), branch(0), ret()]);
        let summary = LoopSummary::new(&cfg);
        let mut partition = LoopPartition::new(&summary);
        let entry = NodeId(0);
        // Initially every node is its own representative.
        assert_eq!(partition.containing_loop(entry), entry);
        // After collapse_loop, the body's representative is
        // the head.
        if summary.preorder().count() >= 2 {
            let body_node = summary.preorder().nth(1).unwrap();
            let mut body = BTreeSet::new();
            body.insert(body_node);
            partition.collapse_loop(entry, &body);
            assert_eq!(
                partition.containing_loop(body_node),
                entry,
                "body node's representative is now the head"
            );
        }
    }

    /// Nested loop collapse increments depth by the sum of the
    /// inner depth + 1.
    #[test]
    fn nested_loop_partition_correct_depth() {
        // Nested-loop CFG:
        // 0: LdTrue          <- outer header
        // 1: BrTrue 8        <- exit outer
        // 2: LdTrue          <- inner header
        // 3: BrTrue 6        <- exit inner
        // 4: Nop
        // 5: Branch 2        <- inner back-edge
        // 6: Nop
        // 7: Branch 0        <- outer back-edge
        // 8: Ret
        let cfg = cfg_of(&[
            ld_true(),
            br_true(8),
            ld_true(),
            br_true(6),
            nop(),
            branch(2),
            nop(),
            branch(0),
            ret(),
        ]);
        let summary = LoopSummary::new(&cfg);
        let mut partition = LoopPartition::new(&summary);
        let outer = summary
            .preorder()
            .find(|n| summary.block(*n) == 0)
            .expect("outer header exists");
        let inner = summary
            .preorder()
            .find(|n| summary.block(*n) == 2)
            .expect("inner header exists");
        // Collapse the inner loop first.
        let inner_body: BTreeSet<NodeId> = BTreeSet::new();
        let inner_depth = partition.collapse_loop(inner, &inner_body);
        assert_eq!(inner_depth, 1, "inner loop has depth 1");
        // Now collapse the outer loop with the inner head as
        // body.
        let mut outer_body = BTreeSet::new();
        outer_body.insert(inner);
        let outer_depth = partition.collapse_loop(outer, &outer_body);
        assert_eq!(
            outer_depth, 2,
            "outer loop containing a depth-1 inner has depth 2"
        );
    }
}
