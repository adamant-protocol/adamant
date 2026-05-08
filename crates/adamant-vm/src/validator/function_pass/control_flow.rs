//! Adamant-native control-flow validation pass (whitepaper
//! §6.2.1.8 step 4).
//!
//! Forked byte-faithfully from
//! `vendor/move-bytecode-verifier/src/control_flow.rs` at
//! Sui-Move tag `mainnet-v1.66.2`. Implements the two
//! per-function checks upstream pins for bytecode versions ≥ 6
//! (Adamant has no version-5-and-below path):
//!
//! 1. **Fall-through.** The function body must be non-empty and
//!    end in an unconditional terminator (`Ret`, `Abort`,
//!    `Branch`, `VariantSwitch`). Without an unconditional
//!    terminator the function would fall off the end of its
//!    body. Adamant extensions are non-branching by construction
//!    ([`BytecodeInstruction::is_unconditional_branch`] returns
//!    `false` for any `Adamant(_)` arm); a function ending in
//!    an Adamant extension is therefore rejected here, which is
//!    correct — the Adamant-extension treatment sub-shape 3
//!    (extensions don't have branches; pass through) was
//!    pre-assigned at the D-1 plan-gate.
//! 2. **Reducibility.** Tarjan 1974 — every loop in the CFG
//!    must have a unique head that dominates all other nodes in
//!    the loop. Reducible CFGs decompose into nested loops,
//!    which makes downstream abstract-interpretation passes
//!    (D-3..D-5) terminate in time bounded by the CFG's static
//!    structure. An irreducible CFG can force exponential blowup
//!    in the abstract-interpretation runtime; rejection here is
//!    the consensus-binding deploy-time guard.
//!
//!    Optionally bounds loop nesting depth via
//!    [`AdamantStructuralLimits::max_loop_depth`][max] — D-2
//!    ships `Some(64)` as a Bucket C provisional value (see
//!    `module_pass/PROVENANCE.md`). The depth check is gated
//!    on `Some(N)`; setting `None` skips the check entirely.
//!
//! [`BytecodeInstruction::is_unconditional_branch`]: crate::bytecode::BytecodeInstruction::is_unconditional_branch
//! [max]: super::super::config::AdamantStructuralLimits::max_loop_depth
//!
//! # Adamant deviations
//!
//! - Operates on [`AdamantCompiledModule`] +
//!   [`AdamantControlFlowGraph`] (D-1a) directly rather than
//!   upstream's `FunctionContext` aggregator. Adamant has a
//!   single CFG type and no v5 fallback; the aggregator
//!   doesn't earn its keep. Same shape rationale as D-1a's CFG
//!   specialisation.
//! - No metering surface (D-1a/D-1b precedent). Adamant's
//!   metering surface is a runtime concern, not a deploy-time
//!   verifier concern.
//! - Closed-enum sub-reason on the
//!   [`AdamantValidationError::IrreducibleControlFlow`] error
//!   ([`IrreducibleReason`]) — upstream uses two separate
//!   `StatusCode` values (`INVALID_LOOP_SPLIT` and
//!   `LOOP_MAX_DEPTH_REACHED`). Same pattern as C-3's
//!   [`InvalidSignatureReason`]; 5th deliberate-Adamant-decision
//!   instance.
//!
//! # Cross-pass-pipeline-dependency
//!
//! This pass relies on [`module_pass::bounds_checker`] (step 3)
//! having validated branch targets, jump-table indices, and
//! code-length — the [`AdamantControlFlowGraph::new`]
//! precondition (cfg.rs:40-48) is established by step 3's
//! success. Cross-pass-pipeline-dependency sub-pattern (5th
//! sub-pattern of structural-impossibility-checks, registered
//! at C-5).
//!
//! [`module_pass::bounds_checker`]: super::super::module_pass::bounds_checker
//! [`AdamantValidationError::IrreducibleControlFlow`]: super::super::error::AdamantValidationError::IrreducibleControlFlow
//! [`InvalidSignatureReason`]: super::super::error::InvalidSignatureReason

use std::collections::BTreeSet;

use adamant_bytecode_format::{CodeOffset, FunctionDefinitionIndex, VariantJumpTable};

use super::cfg::AdamantControlFlowGraph;
use super::loop_summary::{LoopPartition, LoopSummary};
use crate::bytecode::BytecodeInstruction;
use crate::validator::config::AdamantStructuralLimits;
use crate::validator::error::{AdamantValidationError, IrreducibleReason};

/// Verify the per-function control-flow rules for one function
/// body and return its [`AdamantControlFlowGraph`] for
/// downstream consumers (D-3..D-5; D-6 wires the orchestration).
///
/// Pre-positions the orchestration shape D-6 will consume:
/// downstream passes accept the CFG without rebuilding, mirroring
/// upstream's `FunctionContext` lifecycle.
pub(super) fn verify_function(
    config: &AdamantStructuralLimits,
    fn_def_idx: FunctionDefinitionIndex,
    code: &[BytecodeInstruction],
    jump_tables: &[VariantJumpTable],
) -> Result<AdamantControlFlowGraph, AdamantValidationError> {
    verify_fallthrough(fn_def_idx, code)?;
    let cfg = AdamantControlFlowGraph::new(code, jump_tables);
    verify_reducibility(config, fn_def_idx, &cfg)?;
    Ok(cfg)
}

/// Reject empty function bodies and bodies whose last
/// instruction does not unconditionally terminate.
fn verify_fallthrough(
    fn_def_idx: FunctionDefinitionIndex,
    code: &[BytecodeInstruction],
) -> Result<(), AdamantValidationError> {
    match code.last() {
        None => Err(AdamantValidationError::EmptyFunctionBody { fn_def_idx }),
        Some(last) if !last.is_unconditional_branch() => {
            let code_offset = CodeOffset::try_from(code.len() - 1)
                .expect("function-body length is bounded by u16::MAX per the binary format");
            Err(AdamantValidationError::MissingFallthroughTerminator {
                fn_def_idx,
                code_offset,
            })
        }
        Some(_) => Ok(()),
    }
}

/// Verify that the function's CFG is reducible per Tarjan 1974,
/// and (if [`AdamantStructuralLimits::max_loop_depth`] is
/// `Some(N)`) that no loop's nesting depth exceeds N.
///
/// Algorithm:
///
/// 1. Compute the [`LoopSummary`] (DFST + edge classification).
/// 2. Iterate `summary.preorder().rev()` (deeper loops first).
///    For each `head` with non-empty back edges:
///    - Collect the loop body by starting from each back-edge
///      source (resolved through the partition's containing
///      loop) and growing the body via predecessor edges.
///    - For every predecessor encountered, verify it is a
///      descendant of `head` in the DFST. A non-descendant
///      predecessor means a node in the loop's body is not
///      dominated by `head` — Tarjan property 1 violated; the
///      CFG is irreducible.
/// 3. Collapse the loop's body into `head`. The new depth is
///    `1 + max(depth of any constituent)`. If it exceeds
///    `max_loop_depth`, the CFG is reducible but pathologically
///    nested.
///
/// `&AdamantStructuralLimits::max_loop_depth` is consulted only
/// after the irreducibility check fires for the same head, per
/// upstream's pinning order.
fn verify_reducibility(
    config: &AdamantStructuralLimits,
    fn_def_idx: FunctionDefinitionIndex,
    cfg: &AdamantControlFlowGraph,
) -> Result<(), AdamantValidationError> {
    let summary = LoopSummary::new(cfg);
    let mut partition = LoopPartition::new(&summary);

    for head in summary.preorder().rev() {
        let back = summary.back_edges(head);
        if back.is_empty() {
            continue;
        }

        let mut body = BTreeSet::new();
        for node in back {
            let node = partition.containing_loop(*node);
            if node != head {
                body.insert(node);
            }
        }

        let mut frontier: Vec<_> = body.iter().copied().collect();
        while let Some(node) = frontier.pop() {
            for pred in summary.pred_edges(node) {
                let pred = partition.containing_loop(*pred);

                // `pred` can eventually jump back to `head`, so
                // is part of its body. If it is not a descendant
                // of `head` in the DFST, then `head` does not
                // dominate a node in its loop, so the CFG is
                // not reducible (Tarjan property 1).
                if !summary.is_descendant(head, pred) {
                    return Err(AdamantValidationError::IrreducibleControlFlow {
                        fn_def_idx,
                        code_offset: summary.block(pred),
                        reason: IrreducibleReason::InvalidLoopSplit,
                    });
                }

                let body_extended = pred != head && body.insert(pred);
                if body_extended {
                    frontier.push(pred);
                }
            }
        }

        // Collapse the loop body into `head` (sequence of
        // operation 4(b) followed by 4(a) per Tarjan 1974);
        // increments `head`'s depth in the partition.
        let depth = partition.collapse_loop(head, &body);
        if let Some(max_depth) = config.max_loop_depth {
            if depth > max_depth {
                return Err(AdamantValidationError::IrreducibleControlFlow {
                    fn_def_idx,
                    code_offset: summary.block(head),
                    reason: IrreducibleReason::LoopMaxDepthReached,
                });
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    //! Layer A unit tests for the control-flow validation pass.
    //!
    //! Covers fall-through (empty body / non-terminator last /
    //! every terminator kind / Adamant extension as last) +
    //! reducibility happy paths (linear / diamond / loop /
    //! nested / self-loop / orphan-tolerant) + irreducibility
    //! detection + `max_loop_depth` gating.

    use super::*;
    use crate::bytecode::AdamantBytecode;
    use adamant_bytecode_format::handle::JumpTableInner;
    use adamant_bytecode_format::{Bytecode, EnumDefinitionIndex, VariantJumpTableIndex};

    fn ret() -> BytecodeInstruction {
        BytecodeInstruction::Inherited(Bytecode::Ret)
    }

    fn abort() -> BytecodeInstruction {
        BytecodeInstruction::Inherited(Bytecode::Abort)
    }

    fn pop() -> BytecodeInstruction {
        BytecodeInstruction::Inherited(Bytecode::Pop)
    }

    fn nop() -> BytecodeInstruction {
        BytecodeInstruction::Inherited(Bytecode::Nop)
    }

    fn ld_true() -> BytecodeInstruction {
        BytecodeInstruction::Inherited(Bytecode::LdTrue)
    }

    fn ld_u64(v: u64) -> BytecodeInstruction {
        BytecodeInstruction::Inherited(Bytecode::LdU64(v))
    }

    fn br_true(target: CodeOffset) -> BytecodeInstruction {
        BytecodeInstruction::Inherited(Bytecode::BrTrue(target))
    }

    fn br_false(target: CodeOffset) -> BytecodeInstruction {
        BytecodeInstruction::Inherited(Bytecode::BrFalse(target))
    }

    fn branch(target: CodeOffset) -> BytecodeInstruction {
        BytecodeInstruction::Inherited(Bytecode::Branch(target))
    }

    fn variant_switch(idx: u16) -> BytecodeInstruction {
        BytecodeInstruction::Inherited(Bytecode::VariantSwitch(VariantJumpTableIndex::new(idx)))
    }

    fn out_of_gas() -> BytecodeInstruction {
        BytecodeInstruction::Adamant(AdamantBytecode::OutOfGas)
    }

    fn limits_with_max_loop_depth(d: Option<u16>) -> AdamantStructuralLimits {
        let mut l = AdamantStructuralLimits::genesis();
        l.max_loop_depth = d;
        l
    }

    fn fn_idx(i: u16) -> FunctionDefinitionIndex {
        FunctionDefinitionIndex::new(i)
    }

    // --- fall-through tests ---

    #[test]
    fn empty_body_rejected() {
        let code: Vec<BytecodeInstruction> = vec![];
        let jts: Vec<VariantJumpTable> = vec![];
        let result = verify_function(&AdamantStructuralLimits::genesis(), fn_idx(7), &code, &jts);
        match result {
            Err(AdamantValidationError::EmptyFunctionBody { fn_def_idx }) => {
                assert_eq!(fn_def_idx, fn_idx(7));
            }
            other => panic!("expected EmptyFunctionBody, got {other:?}"),
        }
    }

    #[test]
    fn single_ret_accepted() {
        let code = vec![ret()];
        let jts: Vec<VariantJumpTable> = vec![];
        verify_function(&AdamantStructuralLimits::genesis(), fn_idx(0), &code, &jts)
            .expect("Ret-only body is well-formed");
    }

    #[test]
    fn single_abort_accepted() {
        let code = vec![ld_u64(99), abort()];
        let jts: Vec<VariantJumpTable> = vec![];
        verify_function(&AdamantStructuralLimits::genesis(), fn_idx(0), &code, &jts)
            .expect("Abort terminates the function");
    }

    #[test]
    fn single_branch_accepted() {
        // 0: Branch 0   <- self-loop without terminator? Wait,
        //                  the function ends at offset 0 with
        //                  an unconditional Branch. Reducibility
        //                  check sees a single block looping
        //                  back to itself.
        let code = vec![branch(0)];
        let jts: Vec<VariantJumpTable> = vec![];
        verify_function(&AdamantStructuralLimits::genesis(), fn_idx(0), &code, &jts)
            .expect("Branch is unconditional terminator (self-loop is reducible)");
    }

    #[test]
    fn single_variant_switch_accepted() {
        // 0: VariantSwitch 0
        // 1: Ret (first arm target)
        let code = vec![variant_switch(0), ret()];
        let jts = vec![VariantJumpTable {
            head_enum: EnumDefinitionIndex::new(0),
            jump_table: JumpTableInner::Full(vec![1]),
        }];
        verify_function(&AdamantStructuralLimits::genesis(), fn_idx(0), &code, &jts)
            .expect("VariantSwitch as last instruction is unconditional terminator");
    }

    #[test]
    fn last_brtrue_rejected() {
        // BrTrue is conditional — falls through if condition false.
        let code = vec![ld_true(), br_true(0)];
        let jts: Vec<VariantJumpTable> = vec![];
        let result = verify_function(&AdamantStructuralLimits::genesis(), fn_idx(3), &code, &jts);
        match result {
            Err(AdamantValidationError::MissingFallthroughTerminator {
                fn_def_idx,
                code_offset,
            }) => {
                assert_eq!(fn_def_idx, fn_idx(3));
                assert_eq!(code_offset, 1);
            }
            other => panic!("expected MissingFallthroughTerminator, got {other:?}"),
        }
    }

    #[test]
    fn last_pop_rejected() {
        // Pop is not a branch at all — the function falls off
        // the end of its body.
        let code = vec![ld_u64(1), pop()];
        let jts: Vec<VariantJumpTable> = vec![];
        match verify_function(&AdamantStructuralLimits::genesis(), fn_idx(0), &code, &jts) {
            Err(AdamantValidationError::MissingFallthroughTerminator { code_offset, .. }) => {
                assert_eq!(code_offset, 1);
            }
            other => panic!("expected MissingFallthroughTerminator, got {other:?}"),
        }
    }

    /// Pins Adamant-extension treatment sub-shape 3
    /// (extensions are non-branching; pass through). A function
    /// ending in any `Adamant(_)` arm is rejected as missing a
    /// terminator — `is_unconditional_branch` returns false for
    /// every Adamant extension.
    #[test]
    fn last_adamant_extension_rejected() {
        let code = vec![nop(), out_of_gas()];
        let jts: Vec<VariantJumpTable> = vec![];
        match verify_function(&AdamantStructuralLimits::genesis(), fn_idx(0), &code, &jts) {
            Err(AdamantValidationError::MissingFallthroughTerminator { .. }) => {}
            other => panic!("expected MissingFallthroughTerminator, got {other:?}"),
        }
    }

    // --- reducibility happy paths ---

    #[test]
    fn linear_body_reducible() {
        let code = vec![nop(), nop(), ret()];
        let jts: Vec<VariantJumpTable> = vec![];
        verify_function(&AdamantStructuralLimits::genesis(), fn_idx(0), &code, &jts)
            .expect("linear body is reducible");
    }

    #[test]
    fn if_else_diamond_reducible() {
        // 0: LdTrue
        // 1: BrTrue 4
        // 2: Pop
        // 3: Branch 5
        // 4: Nop
        // 5: Ret
        let code = vec![ld_true(), br_true(4), pop(), branch(5), nop(), ret()];
        let jts: Vec<VariantJumpTable> = vec![];
        verify_function(&AdamantStructuralLimits::genesis(), fn_idx(0), &code, &jts)
            .expect("if-else diamond is reducible");
    }

    #[test]
    fn simple_while_loop_reducible() {
        // 0: LdTrue          <- header
        // 1: BrTrue 4        <- exit-on-true
        // 2: Nop
        // 3: Branch 0        <- back-edge
        // 4: Ret
        let code = vec![ld_true(), br_true(4), nop(), branch(0), ret()];
        let jts: Vec<VariantJumpTable> = vec![];
        verify_function(&AdamantStructuralLimits::genesis(), fn_idx(0), &code, &jts)
            .expect("simple while-loop is reducible");
    }

    #[test]
    fn nested_loops_reducible() {
        // Depth 2 nested loops.
        let code = vec![
            ld_true(),
            br_true(8), // outer header (0,1)
            ld_true(),
            br_true(6), // inner header (2,3)
            nop(),
            branch(2), // inner body, back-edge
            nop(),
            branch(0), // outer body, back-edge
            ret(),     // exit (8)
        ];
        let jts: Vec<VariantJumpTable> = vec![];
        verify_function(&AdamantStructuralLimits::genesis(), fn_idx(0), &code, &jts)
            .expect("nested loops are reducible");
    }

    #[test]
    fn self_loop_reducible() {
        // 0: LdTrue
        // 1: BrTrue 0   <- back to entry — self-loop, depth 1
        // 2: Ret
        let code = vec![ld_true(), br_true(0), ret()];
        let jts: Vec<VariantJumpTable> = vec![];
        verify_function(&AdamantStructuralLimits::genesis(), fn_idx(0), &code, &jts)
            .expect("self-loop is reducible");
    }

    #[test]
    fn unreachable_orphan_reducible() {
        // 0: Branch 2
        // 1: Pop      <- orphan: unreachable from entry
        // 2: Ret
        let code = vec![branch(2), pop(), ret()];
        let jts: Vec<VariantJumpTable> = vec![];
        verify_function(&AdamantStructuralLimits::genesis(), fn_idx(0), &code, &jts)
            .expect("orphan blocks don't break reducibility");
    }

    // --- reducibility — irreducible ---

    /// Classic two-entry irreducible CFG: blocks 2 and 3 each
    /// reachable directly from entry; 2 → 3, 3 → 2 forms a
    /// cycle whose head is ambiguous (neither dominates the
    /// other).
    #[test]
    fn irreducible_two_entry_loop() {
        // 0: LdTrue
        // 1: BrTrue 3       <- entry → block 3 (true) or 2 (fall-through)
        // 2: Branch 3       <- block 2 → block 3
        // 3: Branch 2       <- block 3 → block 2 (cycle)
        let code = vec![ld_true(), br_true(3), branch(3), branch(2)];
        let jts: Vec<VariantJumpTable> = vec![];
        match verify_function(&AdamantStructuralLimits::genesis(), fn_idx(0), &code, &jts) {
            Err(AdamantValidationError::IrreducibleControlFlow {
                reason: IrreducibleReason::InvalidLoopSplit,
                ..
            }) => {}
            other => panic!("expected IrreducibleControlFlow(InvalidLoopSplit), got {other:?}"),
        }
    }

    /// Variant of the two-entry shape using `BrFalse` to confirm
    /// conditional-branch flavour doesn't matter for
    /// reducibility.
    #[test]
    fn irreducible_diamond_back_edges() {
        // 0: LdTrue
        // 1: BrFalse 3
        // 2: Branch 3
        // 3: Branch 2
        let code = vec![ld_true(), br_false(3), branch(3), branch(2)];
        let jts: Vec<VariantJumpTable> = vec![];
        assert!(matches!(
            verify_function(&AdamantStructuralLimits::genesis(), fn_idx(0), &code, &jts,),
            Err(AdamantValidationError::IrreducibleControlFlow {
                reason: IrreducibleReason::InvalidLoopSplit,
                ..
            })
        ));
    }

    /// Irreducibility detection survives orphan blocks.
    #[test]
    fn irreducible_with_orphan() {
        // Same two-entry shape with an extra orphan Pop block.
        // 0: LdTrue
        // 1: BrTrue 4
        // 2: Branch 4
        // 3: Pop          <- orphan after the Branch
        // 4: Branch 2
        let code = vec![ld_true(), br_true(4), branch(4), pop(), branch(2)];
        let jts: Vec<VariantJumpTable> = vec![];
        assert!(matches!(
            verify_function(&AdamantStructuralLimits::genesis(), fn_idx(0), &code, &jts,),
            Err(AdamantValidationError::IrreducibleControlFlow {
                reason: IrreducibleReason::InvalidLoopSplit,
                ..
            })
        ));
    }

    /// Pins payload values on `InvalidLoopSplit`: the
    /// `code_offset` is the offending pred's block start.
    #[test]
    fn invalid_loop_split_payload_pinned() {
        let code = vec![ld_true(), br_true(3), branch(3), branch(2)];
        let jts: Vec<VariantJumpTable> = vec![];
        match verify_function(&AdamantStructuralLimits::genesis(), fn_idx(11), &code, &jts) {
            Err(AdamantValidationError::IrreducibleControlFlow {
                fn_def_idx,
                code_offset,
                reason,
            }) => {
                assert_eq!(fn_def_idx, fn_idx(11));
                assert_eq!(reason, IrreducibleReason::InvalidLoopSplit);
                // The offending pred is the entry block (offset
                // 0), which has an edge to one of the two
                // would-be loop heads but isn't dominated by it.
                assert_eq!(code_offset, 0);
            }
            other => panic!("expected IrreducibleControlFlow, got {other:?}"),
        }
    }

    // --- reducibility — depth gating ---

    /// Depth equal to the limit accepts.
    #[test]
    fn loop_depth_at_limit_accepted() {
        let code = vec![ld_true(), br_true(4), nop(), branch(0), ret()];
        let jts: Vec<VariantJumpTable> = vec![];
        let limits = limits_with_max_loop_depth(Some(1));
        verify_function(&limits, fn_idx(0), &code, &jts).expect("depth-1 loop accepted at limit 1");
    }

    /// Depth exceeding the limit rejects.
    #[test]
    fn loop_depth_above_limit_rejected() {
        // Depth-2 nested loop.
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
        let jts: Vec<VariantJumpTable> = vec![];
        let limits = limits_with_max_loop_depth(Some(1));
        match verify_function(&limits, fn_idx(0), &code, &jts) {
            Err(AdamantValidationError::IrreducibleControlFlow {
                reason: IrreducibleReason::LoopMaxDepthReached,
                ..
            }) => {}
            other => panic!("expected IrreducibleControlFlow(LoopMaxDepthReached), got {other:?}"),
        }
    }

    /// Pins payload values on `LoopMaxDepthReached`: the
    /// `code_offset` is the offending head's block start.
    #[test]
    fn loop_max_depth_reached_payload_pinned() {
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
        let jts: Vec<VariantJumpTable> = vec![];
        let limits = limits_with_max_loop_depth(Some(1));
        match verify_function(&limits, fn_idx(2), &code, &jts) {
            Err(AdamantValidationError::IrreducibleControlFlow {
                fn_def_idx,
                code_offset,
                reason,
            }) => {
                assert_eq!(fn_def_idx, fn_idx(2));
                assert_eq!(reason, IrreducibleReason::LoopMaxDepthReached);
                // The reducibility loop processes deeper loops
                // first (preorder reversal). At limit 1, the
                // inner loop (depth 1) accepts; the outer loop
                // (depth 2 after collapsing inner) is what
                // rejects. Outer header is block 0.
                assert_eq!(code_offset, 0);
            }
            other => panic!("expected IrreducibleControlFlow, got {other:?}"),
        }
    }

    /// `max_loop_depth = None` disables the depth check; deeply
    /// nested CFGs that would reject under any `Some(N)` still
    /// pass when the gate is open.
    #[test]
    fn loop_max_depth_disabled_for_reducibility_check() {
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
        let jts: Vec<VariantJumpTable> = vec![];
        let limits = limits_with_max_loop_depth(None);
        verify_function(&limits, fn_idx(0), &code, &jts)
            .expect("depth-2 loop accepted when max_loop_depth is None");
    }

    // --- Adamant-extension treatment ---

    /// Adamant extension between non-branch instructions doesn't
    /// split blocks and doesn't break fall-through (terminator
    /// is the trailing `Ret`).
    #[test]
    fn function_with_adamant_extension_in_middle_accepted() {
        let code = vec![nop(), out_of_gas(), nop(), ret()];
        let jts: Vec<VariantJumpTable> = vec![];
        verify_function(&AdamantStructuralLimits::genesis(), fn_idx(0), &code, &jts)
            .expect("Adamant extension in middle is structurally fine");
    }

    /// Adamant extension immediately before terminator is
    /// accepted — extensions never branch, so they pass through
    /// to the next instruction (the terminator).
    #[test]
    fn function_with_only_extension_then_ret_accepted() {
        let code = vec![out_of_gas(), ret()];
        let jts: Vec<VariantJumpTable> = vec![];
        verify_function(&AdamantStructuralLimits::genesis(), fn_idx(0), &code, &jts)
            .expect("extension-then-Ret terminates correctly");
    }

    // --- Layer B: cross-validation against vendored Sui ---
    //
    // For each fixture below, run Adamant's `verify_function` and
    // Sui's `move_bytecode_verifier::control_flow::verify_function`
    // over the same single-function module (after BCS round-trip
    // via `to_sui_module`), assert accept/reject parity via the
    // shared `assert_function_pass_parity` helper extracted at
    // D-7a. Adamant extensions are excluded from Layer B by design
    // (no upstream counterpart); the Adamant-extension tests above
    // cover the per-extension shape at Layer A only.

    use super::super::test_helpers::{assert_function_pass_parity, sui_config_from, to_sui};
    use crate::module::{AdamantCodeUnit, AdamantCompiledModule, AdamantFunctionDefinition};
    use adamant_bytecode_format::{
        AddressIdentifierIndex, FunctionHandle, Identifier, IdentifierIndex, ModuleHandle,
        ModuleHandleIndex, Signature, SignatureIndex,
    };
    use adamant_types::Address as AccountAddress;
    use move_bytecode_verifier_meter::dummy::DummyMeter;

    /// Build a single-function module wrapping `code` + `jts`.
    /// Mirrors the minimal valid module shape `stack_usage`'s
    /// fixture uses, with empty parameter / locals / returns.
    fn module_with_body(
        code: Vec<BytecodeInstruction>,
        jts: Vec<VariantJumpTable>,
    ) -> AdamantCompiledModule {
        let mut m = AdamantCompiledModule::default();
        m.module_handles.push(ModuleHandle {
            address: AddressIdentifierIndex(0),
            name: IdentifierIndex(0),
        });
        m.signatures.push(Signature(vec![])); // SignatureIndex(0): empty
        m.function_handles.push(FunctionHandle {
            module: ModuleHandleIndex(0),
            name: IdentifierIndex(0),
            parameters: SignatureIndex(0),
            return_: SignatureIndex(0),
            type_parameters: vec![],
        });
        m.function_defs.push(AdamantFunctionDefinition {
            function: adamant_bytecode_format::FunctionHandleIndex(0),
            code: Some(AdamantCodeUnit {
                locals: SignatureIndex(0),
                code,
                jump_tables: jts,
            }),
            ..AdamantFunctionDefinition::default()
        });
        m.identifiers.push(Identifier::new("f").unwrap());
        m.address_identifiers
            .push(AccountAddress::from_bytes([0u8; 32]));
        m
    }

    /// Run both sides of `control_flow`'s `verify_function` and
    /// assert accept/reject parity.
    fn cross_validate_control_flow(m: &AdamantCompiledModule) {
        let limits = AdamantStructuralLimits::genesis();
        let function_def = &m.function_defs[0];
        let code_unit = function_def.code.as_ref().expect("test fixture has body");
        let adamant_result =
            verify_function(&limits, fn_idx(0), &code_unit.code, &code_unit.jump_tables)
                .map(|_| ());

        let sui_module = to_sui(m);
        let sui_config = sui_config_from(&limits);
        let sui_fn_def_idx = move_binary_format::file_format::FunctionDefinitionIndex(0);
        let sui_function_def = &sui_module.function_defs()[0];
        let sui_code_unit = sui_function_def
            .code
            .as_ref()
            .expect("Sui twin has body too");
        let sui_result = move_bytecode_verifier::control_flow::verify_function(
            &sui_config,
            &sui_module,
            sui_fn_def_idx,
            sui_function_def,
            sui_code_unit,
            &mut DummyMeter,
        )
        .map(|_| ());

        assert_function_pass_parity("control_flow", adamant_result, sui_result);
    }

    #[test]
    fn cross_validation_accepts_single_ret() {
        let m = module_with_body(vec![ret()], vec![]);
        cross_validate_control_flow(&m);
    }

    #[test]
    fn cross_validation_accepts_single_abort() {
        let m = module_with_body(vec![abort()], vec![]);
        cross_validate_control_flow(&m);
    }

    #[test]
    fn cross_validation_accepts_single_branch() {
        // Branch(0) — self-loop on the only block; CFG is reducible
        // (self-loop has unique back edge).
        let m = module_with_body(vec![branch(0)], vec![]);
        cross_validate_control_flow(&m);
    }

    #[test]
    fn cross_validation_rejects_empty_body() {
        let m = module_with_body(vec![], vec![]);
        cross_validate_control_flow(&m);
    }

    #[test]
    fn cross_validation_rejects_pop_terminator() {
        // Last instruction is `Pop`, which is not an unconditional
        // branch — fall-through violation.
        let m = module_with_body(vec![ld_u64(0), pop()], vec![]);
        cross_validate_control_flow(&m);
    }

    #[test]
    fn cross_validation_rejects_nop_terminator() {
        let m = module_with_body(vec![nop()], vec![]);
        cross_validate_control_flow(&m);
    }

    #[test]
    fn cross_validation_rejects_brtrue_terminator() {
        // BrTrue is a conditional branch (not unconditional);
        // last-instruction-must-be-unconditional violated.
        let m = module_with_body(vec![ld_true(), br_true(0)], vec![]);
        cross_validate_control_flow(&m);
    }

    #[test]
    fn cross_validation_rejects_irreducible_two_entry_loop() {
        // Same shape as `irreducible_two_entry_loop` Layer A test:
        // blocks 2 and 3 form a cycle with no unique dominator.
        let m = module_with_body(vec![ld_true(), br_true(3), branch(3), branch(2)], vec![]);
        cross_validate_control_flow(&m);
    }

    #[test]
    fn cross_validation_accepts_diamond_cfg() {
        // 0: BrTrue 3
        // 1: LdU64 0
        // 2: Branch 4
        // 3: LdU64 1
        // 4: Pop
        // 5: Ret
        let m = module_with_body(
            vec![
                ld_true(),
                br_true(4),
                ld_u64(0),
                branch(5),
                ld_u64(1),
                pop(),
                ret(),
            ],
            vec![],
        );
        cross_validate_control_flow(&m);
    }
}
