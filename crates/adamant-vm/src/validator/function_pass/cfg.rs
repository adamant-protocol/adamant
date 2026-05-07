//! Control-flow graph construction for the Adamant per-function
//! verifier passes (whitepaper §6.2.1.8 step 4).
//!
//! Forked from `vendor/move-abstract-interpreter/src/control_flow_graph.rs`
//! at Sui-Move tag `mainnet-v1.66.2`. Specialised to
//! [`BytecodeInstruction`] (Sui-base + Adamant extensions)
//! rather than the generic [`Instruction`][ins] trait — Adamant
//! has a single bytecode shape and no need for the trait
//! abstraction upstream uses to share the CFG between
//! `move-binary-format` and `move-abstract-interpreter`.
//!
//! [ins]: move_abstract_interpreter::control_flow_graph::Instruction
//!
//! # Adamant deviations
//!
//! - Operates on [`BytecodeInstruction`] directly (Adamant
//!   composite enum) rather than upstream's generic `I:
//!   Instruction`. Adamant extensions are non-branching, so
//!   [`BytecodeInstruction`]'s `is_branch` / `offsets` /
//!   `get_successors` helpers fall through to the inherited
//!   [`Bytecode`][adamant_bytecode_format::Bytecode] for any
//!   `Inherited(_)` arm and emit no offsets / no branch flags
//!   for any `Adamant(_)` arm.
//! - No `Display`-on-`BasicBlock` debug printer (upstream's
//!   `display()` is dev-only and prints to stdout; Adamant
//!   relies on `#[derive(Debug)]` for the same diagnostic).
//! - No `BoundMeter` integration. Upstream meters CFG
//!   construction; Adamant's metering surface lives elsewhere
//!   in the per-function pipeline (D-3+ scope) and is not
//!   exposed here.
//! - Returns `AdamantControlFlowGraph` directly rather than
//!   wrapping it in upstream's `FunctionContext`. The
//!   per-function passes operate on the CFG plus the function's
//!   `code_unit` and `function_handle` separately; the
//!   `FunctionContext` aggregator pattern is a D-2..D-5 shape
//!   decision rather than a D-1a foundation concern.
//!
//! # Preconditions
//!
//! [`AdamantControlFlowGraph::new`] assumes branch targets and
//! jump-table indices are in range — the bounds-checker pass at
//! step 3 is the cross-pass-pipeline-dependency that establishes
//! this invariant. Calling [`AdamantControlFlowGraph::new`] on
//! an unvalidated module with out-of-range branch targets may
//! panic via `BytecodeInstruction::offsets`'s assertion. The
//! per-function entry point at [`super::verify_function_bodies`]
//! is invoked only after step 3 has accepted the module, so the
//! invariant always holds in the validator's pipeline.

use std::collections::{btree_map::Entry, BTreeMap, BTreeSet};

use adamant_bytecode_format::{CodeOffset, VariantJumpTable};

use crate::bytecode::BytecodeInstruction;

/// Depth-first exploration state for a basic block during CFG
/// construction. `InProgress` means the block's sub-graph is
/// being walked; `Done` means it's been fully visited and
/// committed to the post-order vector. Hoisted to module level
/// (rather than nested in `new`) to satisfy clippy's
/// items-after-statements lint while preserving the upstream
/// state-machine shape.
#[derive(Clone, Copy)]
enum Exploration {
    InProgress,
    Done,
}

/// The entry block ID for every CFG: bytecode offset 0.
///
/// Mirrors upstream's `Bytecode::ENTRY_BLOCK_ID` from the
/// `Instruction` trait impl on `move_binary_format::file_format::Bytecode`.
pub(super) const ENTRY_BLOCK_ID: CodeOffset = 0;

/// A basic block in an [`AdamantControlFlowGraph`].
///
/// Identified by its `entry` offset (the offset of its first
/// instruction); carries its `exit` offset (the offset of its
/// last instruction — the block's terminator) and the list of
/// successor block-entry offsets.
#[derive(Clone, Debug)]
struct BasicBlock {
    /// Bytecode offset of the block's last instruction.
    exit: CodeOffset,
    /// Entry offsets of the block's successor blocks. Sorted
    /// ascending per [`BytecodeInstruction::get_successors`]'s
    /// invariant.
    successors: Vec<CodeOffset>,
}

/// Adamant-native control-flow graph over a function body.
///
/// Built once per function at the start of the per-function
/// pipeline; consumed by the control-flow validation pass
/// (D-2), the abstract-interpretation framework (D-1b), and
/// each downstream per-function pass (D-3..D-5).
#[derive(Clone, Debug)]
pub(super) struct AdamantControlFlowGraph {
    /// Basic blocks keyed by entry offset.
    blocks: BTreeMap<CodeOffset, BasicBlock>,
    /// Reverse-post-order traversal: maps each block's entry
    /// offset to the next block's entry offset in RPO. The last
    /// block in RPO has no entry in the map.
    traversal_successors: BTreeMap<CodeOffset, CodeOffset>,
    /// Loop heads: maps each loop-head block's entry offset to
    /// the set of back-edge source-block entry offsets.
    loop_heads: BTreeMap<CodeOffset, BTreeSet<CodeOffset>>,
}

impl AdamantControlFlowGraph {
    /// Build a CFG from the given code unit's instructions and
    /// jump tables.
    ///
    /// Algorithm (forked byte-faithfully from
    /// `vendor/move-abstract-interpreter/src/control_flow_graph.rs`'s
    /// `VMControlFlowGraph::new`):
    ///
    /// 1. Collect block-entry offsets: every branch target plus
    ///    `pc + 1` after every branch (the fall-through landing).
    /// 2. Walk `code` left-to-right; close a block at every
    ///    end-of-block PC (immediately before the next block
    ///    entry, or at `code.len() - 1`); record successors via
    ///    [`BytecodeInstruction::get_successors`].
    /// 3. Identify loops via depth-first traversal from the
    ///    entry block; classify each successor edge as
    ///    forward / back / cross based on the target's
    ///    exploration state at edge-traversal time. Back edges
    ///    populate `loop_heads`.
    /// 4. Compute RPO traversal order from the post-order
    ///    accumulated during step 3.
    ///
    /// # Preconditions
    ///
    /// `code` must be non-empty (D-2's control-flow validation
    /// pass rejects empty bodies before this constructor is
    /// called) and all branch targets / jump-table indices
    /// must be in range (bounds-checker invariant).
    ///
    /// # Panics
    ///
    /// Panics if `code` is empty (no entry block can be built).
    /// Panics if any branch target / jump-table index is out of
    /// range (mirrors [`BytecodeInstruction::offsets`]'s
    /// assertion).
    pub(super) fn new(code: &[BytecodeInstruction], jump_tables: &[VariantJumpTable]) -> Self {
        assert!(
            !code.is_empty(),
            "AdamantControlFlowGraph::new requires non-empty code; the per-function \
             pipeline's fall-through check fires before this constructor"
        );

        // Step 1: collect block-entry offsets.
        let mut block_ids = BTreeSet::new();
        block_ids.insert(ENTRY_BLOCK_ID);
        for pc in 0..code.len() {
            record_block_ids(pc, code, jump_tables, &mut block_ids);
        }

        // Step 2: walk code, close basic blocks at end-of-block
        // boundaries.
        let mut blocks: BTreeMap<CodeOffset, BasicBlock> = BTreeMap::new();
        let mut entry: usize = 0;
        for pc in 0..code.len() {
            let co_pc = pc_as_code_offset(pc);
            if is_end_of_block(pc, code, &block_ids) {
                let exit = co_pc;
                let successors = BytecodeInstruction::get_successors(co_pc, code, jump_tables);
                let bb = BasicBlock { exit, successors };
                blocks.insert(pc_as_code_offset(entry), bb);
                entry = pc + 1;
            }
        }
        assert_eq!(
            entry,
            code.len(),
            "basic-block construction must consume every instruction"
        );

        // Step 3: depth-first walk from entry to identify loop
        // heads + accumulate post-order. Mirrors upstream's
        // `Exploration::{InProgress, Done}` state machine.
        let mut exploration: BTreeMap<CodeOffset, Exploration> = BTreeMap::new();
        let mut stack = vec![ENTRY_BLOCK_ID];
        let mut loop_heads: BTreeMap<CodeOffset, BTreeSet<CodeOffset>> = BTreeMap::new();
        let mut post_order: Vec<CodeOffset> = Vec::with_capacity(blocks.len());

        while let Some(block) = stack.pop() {
            match exploration.entry(block) {
                Entry::Vacant(slot) => {
                    slot.insert(Exploration::InProgress);
                    stack.push(block);
                    for succ in &blocks[&block].successors {
                        match exploration.get(succ) {
                            None => stack.push(*succ),
                            Some(Exploration::InProgress) => {
                                loop_heads.entry(*succ).or_default().insert(block);
                            }
                            Some(Exploration::Done) => {}
                        }
                    }
                }
                Entry::Occupied(mut slot) => match slot.get() {
                    Exploration::Done => {}
                    Exploration::InProgress => {
                        post_order.push(block);
                        slot.insert(Exploration::Done);
                    }
                },
            }
        }

        // Step 4: derive RPO from post-order; build the next-
        // block traversal map.
        post_order.reverse();
        let traversal_successors = post_order
            .windows(2)
            .map(|w| (w[0], w[1]))
            .collect::<BTreeMap<_, _>>();

        Self {
            blocks,
            traversal_successors,
            loop_heads,
        }
    }

    /// Returns the entry offset of `block_id`. Block IDs are
    /// equal to entry offsets, so this is the identity. Kept
    /// as `&self` for call-site uniformity with the rest of
    /// the CFG accessors (callers invoke `cfg.block_start(b)`).
    #[allow(clippy::unused_self)]
    pub(super) fn block_start(&self, block_id: CodeOffset) -> CodeOffset {
        block_id
    }

    /// Returns the exit (terminator) offset of `block_id`.
    ///
    /// # Panics
    ///
    /// Panics if `block_id` is not a known block.
    pub(super) fn block_end(&self, block_id: CodeOffset) -> CodeOffset {
        self.blocks[&block_id].exit
    }

    /// Returns an iterator over `block_id`'s successor block
    /// IDs, in ascending order.
    ///
    /// # Panics
    ///
    /// Panics if `block_id` is not a known block.
    pub(super) fn successors(&self, block_id: CodeOffset) -> impl Iterator<Item = CodeOffset> + '_ {
        self.blocks[&block_id].successors.iter().copied()
    }

    /// Returns the next block in reverse-post-order traversal,
    /// or `None` if `block_id` is the last block in RPO.
    pub(super) fn next_block(&self, block_id: CodeOffset) -> Option<CodeOffset> {
        debug_assert!(self.blocks.contains_key(&block_id));
        self.traversal_successors.get(&block_id).copied()
    }

    /// Returns an iterator over every block's entry offset in
    /// ascending order.
    pub(super) fn blocks(&self) -> impl Iterator<Item = CodeOffset> + '_ {
        self.blocks.keys().copied()
    }

    /// Returns the number of basic blocks.
    pub(super) fn num_blocks(&self) -> usize {
        self.blocks.len()
    }

    /// Returns the entry block ID — always `ENTRY_BLOCK_ID` (0).
    /// Kept as `&self` for call-site uniformity with the rest
    /// of the CFG accessors.
    #[allow(clippy::unused_self)]
    pub(super) fn entry_block_id(&self) -> CodeOffset {
        ENTRY_BLOCK_ID
    }

    /// Returns `true` if `block_id` is a loop head.
    pub(super) fn is_loop_head(&self, block_id: CodeOffset) -> bool {
        self.loop_heads.contains_key(&block_id)
    }

    /// Returns `true` if the edge `cur -> next` is a back edge.
    pub(super) fn is_back_edge(&self, cur: CodeOffset, next: CodeOffset) -> bool {
        self.loop_heads
            .get(&next)
            .is_some_and(|edges| edges.contains(&cur))
    }

    /// Returns the back-edge source set for the given loop
    /// head, or `None` if `head` is not a loop head.
    pub(super) fn back_edges(&self, head: CodeOffset) -> Option<&BTreeSet<CodeOffset>> {
        self.loop_heads.get(&head)
    }

    /// Returns the total number of back edges across all loops.
    pub(super) fn num_back_edges(&self) -> usize {
        self.loop_heads.values().map(BTreeSet::len).sum()
    }

    /// Returns the entry offsets of every block reachable from
    /// `block_id` via successor edges, in BFS order.
    pub(super) fn reachable_from(&self, block_id: CodeOffset) -> Vec<CodeOffset> {
        let mut out = Vec::new();
        let mut seen = BTreeSet::new();
        out.push(block_id);
        seen.insert(block_id);
        let mut idx = 0;
        while idx < out.len() {
            let block = out[idx];
            idx += 1;
            for succ in self.successors(block) {
                if seen.insert(succ) {
                    out.push(succ);
                }
            }
        }
        out
    }
}

// --- helpers ---

/// Cast a `usize` index into `code` to `CodeOffset` (`u16`).
///
/// Used during CFG construction to bridge `code.len()`'s `usize`
/// world and the binary format's `u16`-indexed world.
///
/// # Panics
///
/// Panics if `pc > u16::MAX`. The bounds-checker pass at step
/// 3 already validates that `code.len() <= u16::MAX` (each
/// branch target's `CodeOffset` operand caps function-body
/// length at `u16::MAX` per upstream's binary format), so this
/// invariant always holds in the validator's pipeline.
fn pc_as_code_offset(pc: usize) -> CodeOffset {
    CodeOffset::try_from(pc)
        .expect("function-body length is bounded by u16::MAX per the binary format")
}

/// Returns `true` if `pc` is the last instruction of a basic
/// block — either the last instruction of the function body
/// (`pc + 1 == code.len()`) or the instruction immediately
/// before another block's entry.
fn is_end_of_block(
    pc: usize,
    code: &[BytecodeInstruction],
    block_ids: &BTreeSet<CodeOffset>,
) -> bool {
    pc + 1 == code.len() || block_ids.contains(&pc_as_code_offset(pc + 1))
}

/// Extend `block_ids` with the block-entry offsets contributed
/// by the instruction at `pc`: its branch targets via
/// [`BytecodeInstruction::offsets`], plus `pc + 1` if the
/// instruction is a branch and has a fall-through PC in range.
fn record_block_ids(
    pc: usize,
    code: &[BytecodeInstruction],
    jump_tables: &[VariantJumpTable],
    block_ids: &mut BTreeSet<CodeOffset>,
) {
    let bytecode = &code[pc];
    block_ids.extend(bytecode.offsets(jump_tables));
    if bytecode.is_branch() && pc + 1 < code.len() {
        block_ids.insert(pc_as_code_offset(pc + 1));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use adamant_bytecode_format::handle::JumpTableInner;
    use adamant_bytecode_format::{Bytecode, EnumDefinitionIndex, VariantJumpTableIndex};

    fn ret() -> BytecodeInstruction {
        BytecodeInstruction::Inherited(Bytecode::Ret)
    }

    fn pop() -> BytecodeInstruction {
        BytecodeInstruction::Inherited(Bytecode::Pop)
    }

    fn nop() -> BytecodeInstruction {
        BytecodeInstruction::Inherited(Bytecode::Nop)
    }

    fn branch(target: CodeOffset) -> BytecodeInstruction {
        BytecodeInstruction::Inherited(Bytecode::Branch(target))
    }

    fn br_true(target: CodeOffset) -> BytecodeInstruction {
        BytecodeInstruction::Inherited(Bytecode::BrTrue(target))
    }

    fn br_false(target: CodeOffset) -> BytecodeInstruction {
        BytecodeInstruction::Inherited(Bytecode::BrFalse(target))
    }

    fn ld_true() -> BytecodeInstruction {
        BytecodeInstruction::Inherited(Bytecode::LdTrue)
    }

    fn variant_switch(idx: u16) -> BytecodeInstruction {
        BytecodeInstruction::Inherited(Bytecode::VariantSwitch(VariantJumpTableIndex(idx)))
    }

    fn out_of_gas() -> BytecodeInstruction {
        BytecodeInstruction::Adamant(crate::bytecode::AdamantBytecode::OutOfGas)
    }

    /// Smallest possible CFG: a single instruction (`Ret`)
    /// is a single block ending at offset 0.
    #[test]
    fn single_instruction_one_block() {
        let code = vec![ret()];
        let cfg = AdamantControlFlowGraph::new(&code, &[]);
        assert_eq!(cfg.num_blocks(), 1);
        assert_eq!(cfg.entry_block_id(), 0);
        assert_eq!(cfg.block_start(0), 0);
        assert_eq!(cfg.block_end(0), 0);
        assert_eq!(
            cfg.successors(0).collect::<Vec<_>>(),
            Vec::<CodeOffset>::new()
        );
        assert!(!cfg.is_loop_head(0));
        assert_eq!(cfg.num_back_edges(), 0);
    }

    /// Linear sequence of non-branching instructions terminated
    /// by `Ret` is a single block.
    #[test]
    fn linear_sequence_one_block() {
        let code = vec![pop(), nop(), nop(), ret()];
        let cfg = AdamantControlFlowGraph::new(&code, &[]);
        assert_eq!(cfg.num_blocks(), 1);
        assert_eq!(cfg.block_start(0), 0);
        assert_eq!(cfg.block_end(0), 3);
        assert_eq!(
            cfg.successors(0).collect::<Vec<_>>(),
            Vec::<CodeOffset>::new()
        );
    }

    /// Adamant extensions are non-branching: a body of
    /// `[Adamant(OutOfGas), Ret]` is a single block. Pins the
    /// Adamant-extension treatment in CFG construction.
    #[test]
    fn adamant_extension_does_not_split_block() {
        let code = vec![out_of_gas(), ret()];
        let cfg = AdamantControlFlowGraph::new(&code, &[]);
        assert_eq!(cfg.num_blocks(), 1);
        assert_eq!(cfg.block_end(0), 1);
    }

    /// Conditional branch creates two blocks: the head (offset
    /// 0..=branch) and the fall-through landing.
    #[test]
    fn conditional_branch_two_blocks() {
        // 0: LdTrue
        // 1: BrTrue 3
        // 2: Pop      <- fall-through
        // 3: Ret      <- branch target
        let code = vec![ld_true(), br_true(3), pop(), ret()];
        let cfg = AdamantControlFlowGraph::new(&code, &[]);
        assert_eq!(cfg.num_blocks(), 3);
        // Block at 0 ends at offset 1 (the BrTrue); successors
        // are {2, 3}.
        assert_eq!(cfg.block_end(0), 1);
        assert_eq!(cfg.successors(0).collect::<Vec<_>>(), vec![2, 3]);
        // Block at 2 ends at 2 (Pop falls through to 3).
        assert_eq!(cfg.block_end(2), 2);
        assert_eq!(cfg.successors(2).collect::<Vec<_>>(), vec![3]);
        // Block at 3 ends at 3 (Ret).
        assert_eq!(cfg.block_end(3), 3);
        assert_eq!(
            cfg.successors(3).collect::<Vec<_>>(),
            Vec::<CodeOffset>::new()
        );
    }

    /// Unconditional `Branch` skips the fall-through PC: the
    /// instruction immediately after `Branch` is unreachable
    /// (and isn't a successor) but is still a block boundary
    /// because the target may also branch back to it.
    #[test]
    fn unconditional_branch_skips_fallthrough() {
        // 0: Branch 2
        // 1: Pop     <- unreachable but separate block
        // 2: Ret
        let code = vec![branch(2), pop(), ret()];
        let cfg = AdamantControlFlowGraph::new(&code, &[]);
        assert_eq!(cfg.num_blocks(), 3);
        // Block at 0 has successor {2}; no fall-through to 1.
        assert_eq!(cfg.successors(0).collect::<Vec<_>>(), vec![2]);
        // Block 1 (the orphan Pop) still exists structurally;
        // it's just not reachable from entry.
        assert!(cfg.blocks().any(|b| b == 1));
    }

    /// If-else diamond: two branches from the head, both reach
    /// the join block, terminator after the join.
    #[test]
    fn if_else_diamond() {
        // 0: LdTrue
        // 1: BrTrue 4
        // 2: Pop           <- false arm
        // 3: Branch 5
        // 4: Nop           <- true arm
        // 5: Ret
        let code = vec![ld_true(), br_true(4), pop(), branch(5), nop(), ret()];
        let cfg = AdamantControlFlowGraph::new(&code, &[]);
        assert_eq!(cfg.num_blocks(), 4);
        // Head: entry 0, exit 1 (the BrTrue).
        assert_eq!(cfg.block_end(0), 1);
        assert_eq!(cfg.successors(0).collect::<Vec<_>>(), vec![2, 4]);
        // False arm: entry 2, exit 3 (the unconditional Branch).
        assert_eq!(cfg.block_end(2), 3);
        assert_eq!(cfg.successors(2).collect::<Vec<_>>(), vec![5]);
        // True arm: entry 4, exit 4 (Nop falls through to 5).
        assert_eq!(cfg.block_end(4), 4);
        assert_eq!(cfg.successors(4).collect::<Vec<_>>(), vec![5]);
        // Join: entry 5, exit 5 (Ret).
        assert_eq!(cfg.block_end(5), 5);
        assert_eq!(
            cfg.successors(5).collect::<Vec<_>>(),
            Vec::<CodeOffset>::new()
        );
    }

    /// Simple while-loop pattern: header block branches back to
    /// itself via a conditional. Asserts loop-head detection
    /// and back-edge classification.
    #[test]
    fn while_loop_one_loop_head() {
        // 0: LdTrue
        // 1: BrTrue 4    <- exit-on-true
        // 2: Nop
        // 3: Branch 0    <- back-edge to header
        // 4: Ret
        let code = vec![ld_true(), br_true(4), nop(), branch(0), ret()];
        let cfg = AdamantControlFlowGraph::new(&code, &[]);
        assert!(cfg.is_loop_head(0));
        assert_eq!(cfg.num_back_edges(), 1);
        let back_edges = cfg.back_edges(0).expect("loop head 0 has back edges");
        assert!(back_edges.contains(&2));
    }

    /// Reachability: from entry, every reachable block appears
    /// in the result set; orphaned blocks do not.
    #[test]
    fn reachable_from_entry_excludes_orphan() {
        let code = vec![branch(2), pop(), ret()];
        let cfg = AdamantControlFlowGraph::new(&code, &[]);
        let reach = cfg.reachable_from(0);
        assert!(reach.contains(&0));
        assert!(reach.contains(&2));
        assert!(
            !reach.contains(&1),
            "orphan block 1 should not be reachable from entry"
        );
    }

    /// RPO traversal on a linear three-block chain: entry → mid
    /// → tail.
    #[test]
    fn rpo_linear_chain() {
        // 0: LdTrue
        // 1: BrTrue 2
        // 2: Nop
        // 3: Ret
        let code = vec![ld_true(), br_true(2), nop(), ret()];
        let cfg = AdamantControlFlowGraph::new(&code, &[]);
        // RPO walks entry → fall-through → branch-target. Each
        // RPO-edge is captured in `next_block`.
        let after_entry = cfg.next_block(0).expect("entry has a next block in RPO");
        // Next block after entry is one of the two successors;
        // the other is the RPO tail.
        assert!(after_entry == 2);
        let tail = cfg.next_block(after_entry);
        assert!(tail.is_none(), "the last block in RPO has no next block");
    }

    /// `VariantSwitch` consumes its jump table for successor
    /// resolution. Pins the jump-table integration path.
    #[test]
    fn variant_switch_uses_jump_table() {
        // 0: VariantSwitch 0
        // 1: Pop      <- target a
        // 2: Ret      <- target b
        // 3: Ret      <- (orphan if not in table)
        let code = vec![variant_switch(0), pop(), ret(), ret()];
        let jt = vec![VariantJumpTable {
            head_enum: EnumDefinitionIndex(0),
            jump_table: JumpTableInner::Full(vec![1, 2]),
        }];
        let cfg = AdamantControlFlowGraph::new(&code, &jt);
        let succs: Vec<_> = cfg.successors(0).collect();
        assert_eq!(succs, vec![1, 2]);
    }

    /// Empty-code precondition is enforced via `assert!`.
    /// The per-function pipeline's fall-through check rejects
    /// empty bodies before this constructor sees them, but
    /// pinning the panic guards against direct unvalidated
    /// callers.
    #[test]
    #[should_panic(expected = "non-empty code")]
    fn empty_code_panics() {
        let _ = AdamantControlFlowGraph::new(&[], &[]);
    }

    /// Nested loops: inner header is a loop head with a back
    /// edge from inside the outer loop.
    #[test]
    fn nested_loops_two_loop_heads() {
        // 0: LdTrue          <- outer header
        // 1: BrTrue 8        <- exit outer
        // 2: LdTrue          <- inner header
        // 3: BrTrue 6        <- exit inner
        // 4: Nop
        // 5: Branch 2        <- inner back-edge
        // 6: Nop
        // 7: Branch 0        <- outer back-edge
        // 8: Ret
        let code = vec![
            ld_true(),
            br_true(8),
            ld_true(),
            br_true(6),
            nop(),
            branch(2),
            nop(),
            branch(0),
            ret(),
        ];
        let cfg = AdamantControlFlowGraph::new(&code, &[]);
        assert!(cfg.is_loop_head(0), "outer header should be a loop head");
        assert!(cfg.is_loop_head(2), "inner header should be a loop head");
        assert_eq!(cfg.num_back_edges(), 2);
    }

    /// Back-edge predicate fires only for the recorded edge.
    #[test]
    fn is_back_edge_predicate() {
        let code = vec![ld_true(), br_true(4), nop(), branch(0), ret()];
        let cfg = AdamantControlFlowGraph::new(&code, &[]);
        assert!(cfg.is_back_edge(2, 0));
        assert!(!cfg.is_back_edge(0, 2));
        assert!(!cfg.is_back_edge(0, 4));
    }

    /// Block iteration order is ascending (BTreeMap-keyed).
    #[test]
    fn blocks_iter_ascending() {
        let code = vec![ld_true(), br_true(4), pop(), branch(5), nop(), ret()];
        let cfg = AdamantControlFlowGraph::new(&code, &[]);
        let blocks: Vec<_> = cfg.blocks().collect();
        let mut sorted = blocks.clone();
        sorted.sort_unstable();
        assert_eq!(blocks, sorted);
    }

    /// `BrFalse` equivalence with `BrTrue` for block boundaries.
    #[test]
    fn br_false_creates_block_split() {
        let code = vec![ld_true(), br_false(3), pop(), ret()];
        let cfg = AdamantControlFlowGraph::new(&code, &[]);
        assert_eq!(cfg.num_blocks(), 3);
        let succs: Vec<_> = cfg.successors(0).collect();
        assert_eq!(succs, vec![2, 3]);
    }

    /// Self-loop: a block whose conditional branch targets
    /// itself counts as a loop head with one back edge.
    #[test]
    fn self_loop_is_loop_head() {
        // 0: LdTrue
        // 1: BrTrue 0   <- back to entry
        // 2: Ret
        let code = vec![ld_true(), br_true(0), ret()];
        let cfg = AdamantControlFlowGraph::new(&code, &[]);
        assert!(cfg.is_loop_head(0));
        assert_eq!(cfg.num_back_edges(), 1);
    }

    /// Unreachable orphan blocks are still constructed (they
    /// appear as block-id keys) but they're not loop heads and
    /// they don't contribute back edges.
    #[test]
    fn orphan_block_not_loop_head() {
        let code = vec![branch(2), pop(), ret()];
        let cfg = AdamantControlFlowGraph::new(&code, &[]);
        assert!(!cfg.is_loop_head(1));
        assert_eq!(cfg.num_back_edges(), 0);
    }

    /// Two-target jump table with the targets in non-ascending
    /// payload order: successors are returned in ascending
    /// order per [`BytecodeInstruction::get_successors`].
    #[test]
    fn variant_switch_successors_ascending() {
        // 0: VariantSwitch 0
        // 1: Ret
        // 2: Ret
        let code = vec![variant_switch(0), ret(), ret()];
        let jt = vec![VariantJumpTable {
            head_enum: EnumDefinitionIndex(0),
            jump_table: JumpTableInner::Full(vec![2, 1]),
        }];
        let cfg = AdamantControlFlowGraph::new(&code, &jt);
        let succs: Vec<_> = cfg.successors(0).collect();
        assert_eq!(succs, vec![1, 2]);
    }
}
