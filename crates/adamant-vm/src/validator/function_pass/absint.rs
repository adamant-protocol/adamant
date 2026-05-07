//! Abstract-interpretation framework for the Adamant
//! per-function verifier passes (whitepaper §6.2.1.8 step 4).
//!
//! Forked from `vendor/move-abstract-interpreter/src/absint.rs`
//! at Sui-Move tag `mainnet-v1.66.2`. Specialised to
//! [`BytecodeInstruction`] (Sui-base + Adamant extensions) and
//! to [`AdamantControlFlowGraph`] (D-1a output) rather than
//! upstream's generic `I: Instruction` / `CFG: ControlFlowGraph`
//! abstractions — same shape rationale as D-1a's CFG
//! specialisation.
//!
//! # Adamant deviations
//!
//! - Operates on [`BytecodeInstruction`] / [`AdamantControlFlowGraph`]
//!   directly rather than upstream's generic associated types.
//!   Adamant has a single bytecode shape and a single CFG type;
//!   the generic trait surface upstream uses to share between
//!   `move-binary-format` and `move-abstract-interpreter`
//!   doesn't earn its keep.
//! - **Hard-wires [`AdamantValidationError`] as the framework's
//!   error type** (4th deliberate-Adamant-decision instance,
//!   per Q2 plan-gate disposition). Upstream uses a
//!   `type Error;` associated type for trait-level genericity;
//!   Adamant's framework is consumed only within the
//!   per-function pipeline and Adamant has a single validator
//!   error type, so the associated type doesn't earn its keep.
//!   Removing the associated type simplifies the trait surface
//!   at no cost.
//! - The `BlockId` / `InstructionIndex` / `Instruction`
//!   associated types are likewise removed — they would all
//!   pin to [`CodeOffset`] / [`CodeOffset`] /
//!   [`BytecodeInstruction`]. The trait reads cleaner with
//!   them as concrete types.
//! - No metering surface (consistent with D-1a).
//!
//! # Trait shape (consolidated, not split)
//!
//! Upstream consolidates the conceptual three-piece structure
//! (abstract-domain operations, transfer functions, fixpoint
//! driver) into a single [`AbstractInterpreter`] trait. Plan-
//! gate framing surfaced this as "`AbstractDomain` trait +
//! `TransferFunctions` trait + `AbstractInterpreter` trait" —
//! the conceptual three-piece view; upstream's implementation
//! consolidates them into one trait. Adamant preserves the
//! consolidation byte-faithfully (no Adamant deviation here)
//! per the byte-faithful preservation pattern.
//!
//! # Fixpoint algorithm
//!
//! [`analyze_function`] drives the fixpoint:
//!
//! 1. Seed entry block's `pre` with `initial_state`.
//! 2. Walk blocks in RPO ([`AdamantControlFlowGraph::next_block`]);
//!    for each block:
//!    1. Compute `post` by folding `execute` over each
//!       instruction starting from `pre`.
//!    2. For each successor, join `post` into successor's
//!       `pre`. If `pre` changed and the edge is a back edge,
//!       jump back to the loop head and continue from there.
//! 3. Terminate when no successor's `pre` is `Changed` by a
//!    join — fixpoint reached.

use std::collections::BTreeMap;

use adamant_bytecode_format::CodeOffset;

use super::cfg::AdamantControlFlowGraph;
use crate::bytecode::BytecodeInstruction;
use crate::validator::error::AdamantValidationError;

/// Result of joining a fresh `post` into an existing `pre`
/// state during fixpoint propagation.
///
/// Mirrors upstream's `JoinResult`. Two-variant enum (rather
/// than `bool`) per Q1b plan-gate disposition: semantic
/// clarity at the trait boundary; allows future extension to a
/// three-state if needed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum JoinResult {
    /// Pre changed during the join; successor's invariant
    /// needs reanalysis.
    Changed,
    /// Pre is the same after the join; reanalysis would
    /// produce the same post.
    Unchanged,
}

/// Post-condition slot of a basic block during fixpoint
/// iteration. Mirrors upstream's `BlockPostCondition`.
#[derive(Clone, Debug)]
pub(super) enum BlockPostCondition<State> {
    /// Block hasn't been executed yet (or its pre changed
    /// since the last execution and it needs reanalysis).
    Unprocessed,
    /// Block has been executed; the carried state is the
    /// transfer-function output for the most recent `pre`.
    Processed(State),
}

/// Pre-/post-condition pair attached to a basic block during
/// fixpoint iteration. Mirrors upstream's `BlockInvariant`.
#[derive(Clone, Debug)]
pub(super) struct BlockInvariant<State> {
    /// State at block entry — joined from every predecessor's
    /// post during fixpoint propagation.
    pub pre: State,
    /// State at block exit — the transfer function applied
    /// across every instruction in the block, starting from
    /// `pre`.
    pub post: BlockPostCondition<State>,
}

/// Per-block invariants keyed by block-entry offset.
/// Mirrors upstream's `InvariantMap`.
pub(super) type InvariantMap<A> =
    BTreeMap<CodeOffset, BlockInvariant<<A as AbstractInterpreter>::State>>;

/// Per-function abstract interpreter trait.
///
/// Each concrete per-function pass (D-3 locals safety, D-4
/// type safety, D-5 reference safety) implements this trait
/// with its own [`State`][Self::State] type, [`join`][Self::join]
/// implementation, and [`execute`][Self::execute] transfer
/// functions. The framework's [`analyze_function`] free function
/// drives the fixpoint over an [`AdamantControlFlowGraph`].
///
/// Mirrors upstream's `AbstractInterpreter` trait byte-faithfully
/// in shape, with the deliberate-Adamant-decision deviations
/// listed in the module doc-comment (hard-wired
/// [`AdamantValidationError`]; concrete `BlockId` /
/// `InstructionIndex` / `Instruction` types).
pub(super) trait AbstractInterpreter {
    /// The abstract state type. Cloned at predecessor-state
    /// propagation and entry-block seeding.
    type State: Clone;

    /// Join `post` into `pre`. Returns
    /// [`JoinResult::Changed`] if `pre` was actually mutated
    /// by the join (which forces successor reanalysis), or
    /// [`JoinResult::Unchanged`] if `pre` remains equivalent.
    ///
    /// `&mut self` is preserved (rather than `&self`) per Q1a
    /// plan-gate disposition: the framework's join may need to
    /// mutate auxiliary bookkeeping on the interpreter
    /// (consistent with upstream's `&mut self` shape).
    fn join(
        &mut self,
        pre: &mut Self::State,
        post: &Self::State,
    ) -> Result<JoinResult, AdamantValidationError>;

    /// Apply the transfer function for the instruction at
    /// `offset` (within `bounds = (block_start, block_end)`)
    /// to `state` in place. Should return `Err(_)` if the
    /// transfer function rejects the instruction.
    ///
    /// Implementations may use `bounds` to detect
    /// last-instruction-of-block special cases (e.g.,
    /// normalizing the abstract state before a join).
    fn execute(
        &mut self,
        block_id: CodeOffset,
        bounds: (CodeOffset, CodeOffset),
        state: &mut Self::State,
        offset: CodeOffset,
        instr: &BytecodeInstruction,
    ) -> Result<(), AdamantValidationError>;

    /// Bookkeeping visitor called once before any block is
    /// processed. Default impl is a no-op.
    fn start(&mut self) -> Result<(), AdamantValidationError> {
        Ok(())
    }

    /// Bookkeeping visitor called before each block's transfer
    /// functions run. Default impl is a no-op.
    ///
    /// Implementations should not modify the abstract state
    /// from this visitor — it's intended for diagnostic /
    /// bookkeeping use only.
    fn visit_block_pre_execution(
        &mut self,
        _block_id: CodeOffset,
        _invariant: &mut BlockInvariant<Self::State>,
    ) -> Result<(), AdamantValidationError> {
        Ok(())
    }

    /// Bookkeeping visitor called after each block's transfer
    /// functions finish. Default impl is a no-op.
    fn visit_block_post_execution(
        &mut self,
        _block_id: CodeOffset,
        _invariant: &mut BlockInvariant<Self::State>,
    ) -> Result<(), AdamantValidationError> {
        Ok(())
    }

    /// Bookkeeping visitor called once per successor edge
    /// before the successor's `pre` is joined. Default impl
    /// is a no-op.
    fn visit_successor(&mut self, _block_id: CodeOffset) -> Result<(), AdamantValidationError> {
        Ok(())
    }

    /// Bookkeeping visitor called when a back edge is
    /// traversed (i.e., when a successor's joined `pre`
    /// changed and the edge is a CFG back edge). Default impl
    /// is a no-op.
    fn visit_back_edge(
        &mut self,
        _from: CodeOffset,
        _to: CodeOffset,
    ) -> Result<(), AdamantValidationError> {
        Ok(())
    }
}

/// Run the fixpoint analysis for `interpreter` over `cfg` and
/// `code`, starting from `initial_state` at the entry block.
///
/// Returns the final per-block invariant map on success, or
/// the first [`AdamantValidationError`] returned by `interpreter`
/// on any callback (`start`, `execute`, `join`, or any
/// visitor).
///
/// Mirrors upstream's `analyze_function` byte-faithfully in
/// algorithm and signature; specialised to
/// [`AdamantControlFlowGraph`] + [`BytecodeInstruction`].
/// `initial_state` is taken by value (rather than `&A::State`)
/// to mirror upstream — the framework clones it whenever it
/// seeds a new block's pre, and switching to a borrowed
/// signature would be an Adamant-side deviation. Per Q1
/// walk-back precedent (deviations introduced at
/// implementation-gate without plan-gate pre-approval are
/// avoided), the byte-faithful signature is preserved and
/// `clippy::needless_pass_by_value` is suppressed at the
/// call site with this rationale.
#[allow(clippy::needless_pass_by_value)]
pub(super) fn analyze_function<A: AbstractInterpreter>(
    interpreter: &mut A,
    cfg: &AdamantControlFlowGraph,
    code: &[BytecodeInstruction],
    initial_state: A::State,
) -> Result<InvariantMap<A>, AdamantValidationError> {
    interpreter.start()?;
    let mut inv_map: InvariantMap<A> = BTreeMap::new();
    let entry_block_id = cfg.entry_block_id();
    let mut next_block = Some(entry_block_id);
    inv_map.insert(
        entry_block_id,
        BlockInvariant {
            pre: initial_state.clone(),
            post: BlockPostCondition::Unprocessed,
        },
    );

    while let Some(block_id) = next_block {
        // Borrow the block's invariant just long enough to run
        // its pre-execution visitor and snapshot `pre`. Drop
        // the borrow before calling `execute_block` (which
        // doesn't touch `inv_map`) so the post-execution path
        // can re-borrow without conflict.
        let pre_state = {
            let block_invariant = inv_map.entry(block_id).or_insert_with(|| BlockInvariant {
                pre: initial_state.clone(),
                post: BlockPostCondition::Unprocessed,
            });
            interpreter.visit_block_pre_execution(block_id, block_invariant)?;
            block_invariant.pre.clone()
        };

        let post_state = execute_block(interpreter, cfg, code, block_id, &pre_state)?;

        // Re-borrow to write `post` and run the post-execution
        // visitor.
        {
            let block_invariant = inv_map.get_mut(&block_id).expect(
                "block_invariant inserted above; map entries are not removed during analysis",
            );
            block_invariant.post = BlockPostCondition::Processed(post_state.clone());
            interpreter.visit_block_post_execution(block_id, block_invariant)?;
        }

        let mut next_block_candidate = cfg.next_block(block_id);
        // Propagate this block's post-state to each successor.
        for successor_block_id in cfg.successors(block_id) {
            interpreter.visit_successor(successor_block_id)?;
            match inv_map.get_mut(&successor_block_id) {
                Some(next_block_invariant) => {
                    let join_result =
                        interpreter.join(&mut next_block_invariant.pre, &post_state)?;
                    match join_result {
                        JoinResult::Unchanged => {
                            // pre is the same after join;
                            // reanalysis would produce same post.
                        }
                        JoinResult::Changed => {
                            next_block_invariant.post = BlockPostCondition::Unprocessed;
                            // If the edge is a back edge, jump
                            // back to the loop head instead of
                            // continuing in RPO.
                            if cfg.is_back_edge(block_id, successor_block_id) {
                                interpreter.visit_back_edge(block_id, successor_block_id)?;
                                next_block_candidate = Some(successor_block_id);
                                break;
                            }
                        }
                    }
                }
                None => {
                    // Haven't visited the successor yet; seed
                    // its pre with this block's post.
                    inv_map.insert(
                        successor_block_id,
                        BlockInvariant {
                            pre: post_state.clone(),
                            post: BlockPostCondition::Unprocessed,
                        },
                    );
                }
            }
        }
        next_block = next_block_candidate;
    }
    Ok(inv_map)
}

/// Fold `interpreter.execute` across every instruction in
/// `block_id`, starting from `pre_state`. Returns the resulting
/// state (the block's post-state).
///
/// Mirrors upstream's `execute_block`.
fn execute_block<A: AbstractInterpreter>(
    interpreter: &mut A,
    cfg: &AdamantControlFlowGraph,
    code: &[BytecodeInstruction],
    block_id: CodeOffset,
    pre_state: &A::State,
) -> Result<A::State, AdamantValidationError> {
    let mut state_acc = pre_state.clone();
    let bounds = (cfg.block_start(block_id), cfg.block_end(block_id));
    for (offset, instr) in cfg.instructions(code, block_id) {
        interpreter.execute(block_id, bounds, &mut state_acc, offset, instr)?;
    }
    Ok(state_acc)
}

#[cfg(test)]
mod tests {
    //! Synthetic-domain tests for the abstract-interpretation
    //! framework. Exercises framework-plumbing-correctness
    //! (fixpoint termination, RPO traversal, joins at
    //! predecessors, back-edge propagation, visitor callback
    //! ordering, error propagation) using minimal abstract
    //! domains. Per Q3 plan-gate disposition: framework-
    //! consumer-interaction (real transfer functions for
    //! actual instructions) is the responsibility of D-3+
    //! implementation-gates to surface if any issues emerge.
    //!
    //! Domain choice: `SawPop` — abstract state is a single
    //! `bool` tracking whether any path has executed a `Pop`.
    //! Join is `pre |= post` (any path saw it); transfer
    //! function flips the flag on `Pop`. Simple enough that
    //! the expected post-condition is trivially derivable for
    //! every test fixture; rich enough to exercise join
    //! semantics, fixpoint convergence, and back-edge
    //! propagation.

    use super::*;
    use adamant_bytecode_format::Bytecode;

    fn pop() -> BytecodeInstruction {
        BytecodeInstruction::Inherited(Bytecode::Pop)
    }

    fn nop() -> BytecodeInstruction {
        BytecodeInstruction::Inherited(Bytecode::Nop)
    }

    fn ret() -> BytecodeInstruction {
        BytecodeInstruction::Inherited(Bytecode::Ret)
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

    /// Synthetic abstract domain: tracks whether any path has
    /// executed a `Pop` instruction. State is `bool`; join is
    /// disjunction; transfer function flips the flag on `Pop`.
    struct SawPop {
        /// Trace of every visitor callback fired, in order.
        /// Used by visitor-ordering tests.
        trace: Vec<String>,
    }

    impl SawPop {
        fn new() -> Self {
            Self { trace: Vec::new() }
        }
    }

    impl AbstractInterpreter for SawPop {
        type State = bool;

        fn join(
            &mut self,
            pre: &mut Self::State,
            post: &Self::State,
        ) -> Result<JoinResult, AdamantValidationError> {
            let before = *pre;
            *pre = before || *post;
            if *pre == before {
                Ok(JoinResult::Unchanged)
            } else {
                Ok(JoinResult::Changed)
            }
        }

        fn execute(
            &mut self,
            _block_id: CodeOffset,
            _bounds: (CodeOffset, CodeOffset),
            state: &mut Self::State,
            _offset: CodeOffset,
            instr: &BytecodeInstruction,
        ) -> Result<(), AdamantValidationError> {
            if matches!(instr, BytecodeInstruction::Inherited(Bytecode::Pop)) {
                *state = true;
            }
            Ok(())
        }

        fn start(&mut self) -> Result<(), AdamantValidationError> {
            self.trace.push("start".into());
            Ok(())
        }

        fn visit_block_pre_execution(
            &mut self,
            block_id: CodeOffset,
            _invariant: &mut BlockInvariant<Self::State>,
        ) -> Result<(), AdamantValidationError> {
            self.trace.push(format!("pre({block_id})"));
            Ok(())
        }

        fn visit_block_post_execution(
            &mut self,
            block_id: CodeOffset,
            _invariant: &mut BlockInvariant<Self::State>,
        ) -> Result<(), AdamantValidationError> {
            self.trace.push(format!("post({block_id})"));
            Ok(())
        }

        fn visit_successor(&mut self, block_id: CodeOffset) -> Result<(), AdamantValidationError> {
            self.trace.push(format!("succ({block_id})"));
            Ok(())
        }

        fn visit_back_edge(
            &mut self,
            from: CodeOffset,
            to: CodeOffset,
        ) -> Result<(), AdamantValidationError> {
            self.trace.push(format!("back({from}->{to})"));
            Ok(())
        }
    }

    /// Linear no-Pop body: final post-state is `false`
    /// throughout.
    #[test]
    fn linear_no_pop() {
        let code = vec![nop(), nop(), ret()];
        let cfg = AdamantControlFlowGraph::new(&code, &[]);
        let mut interp = SawPop::new();
        let inv = analyze_function(&mut interp, &cfg, &code, false).expect("analysis succeeds");
        let entry_post = match &inv[&0].post {
            BlockPostCondition::Processed(s) => *s,
            BlockPostCondition::Unprocessed => panic!("entry block must be processed"),
        };
        assert!(!entry_post, "no Pop in body, post-state must remain false");
    }

    /// Linear with Pop: post-state of the block containing
    /// `Pop` is `true`.
    #[test]
    fn linear_with_pop() {
        let code = vec![pop(), ret()];
        let cfg = AdamantControlFlowGraph::new(&code, &[]);
        let mut interp = SawPop::new();
        let inv = analyze_function(&mut interp, &cfg, &code, false).expect("analysis succeeds");
        let entry_post = match &inv[&0].post {
            BlockPostCondition::Processed(s) => *s,
            BlockPostCondition::Unprocessed => panic!("entry block must be processed"),
        };
        assert!(entry_post, "Pop in body must flip post-state to true");
    }

    /// Branch with `Pop` only on one arm: join state at the
    /// successor block is `true`.
    #[test]
    fn join_at_successor_or_semantics() {
        // 0: LdTrue
        // 1: BrTrue 4    <- branch over Pop arm
        // 2: Pop         <- false arm: sees Pop
        // 3: Branch 5    <- skip true arm
        // 4: Nop         <- true arm: no Pop
        // 5: Ret         <- join block
        let code = vec![ld_true(), br_true(4), pop(), branch(5), nop(), ret()];
        let cfg = AdamantControlFlowGraph::new(&code, &[]);
        let mut interp = SawPop::new();
        let inv = analyze_function(&mut interp, &cfg, &code, false).expect("analysis succeeds");
        let join_pre = inv[&5].pre;
        assert!(
            join_pre,
            "join block at offset 5 receives true-via-Pop arm and false-via-no-Pop arm; \
             OR-semantics join must be true"
        );
    }

    /// Loop with `Pop` in the body: fixpoint converges.
    #[test]
    fn loop_converges_with_pop_in_body() {
        // 0: LdTrue          <- header (loop head)
        // 1: BrTrue 5        <- exit-on-true
        // 2: Pop             <- body: sees Pop
        // 3: Nop
        // 4: Branch 0        <- back-edge to header
        // 5: Ret
        let code = vec![ld_true(), br_true(5), pop(), nop(), branch(0), ret()];
        let cfg = AdamantControlFlowGraph::new(&code, &[]);
        assert!(cfg.is_loop_head(0));
        let mut interp = SawPop::new();
        let inv = analyze_function(&mut interp, &cfg, &code, false).expect("analysis terminates");
        // After fixpoint: header's pre receives the back-edge
        // post-state which is true (Pop in body), so header
        // pre converges to true.
        assert!(
            inv[&0].pre,
            "loop header pre converges to true after back-edge join"
        );
        assert!(inv[&5].pre, "exit block pre is true via header propagation");
    }

    /// Loop with no `Pop` in the body: fixpoint converges with
    /// state staying `false` throughout.
    #[test]
    fn loop_converges_without_pop() {
        // 0: LdTrue          <- header
        // 1: BrTrue 4        <- exit-on-true
        // 2: Nop
        // 3: Branch 0        <- back-edge
        // 4: Ret
        let code = vec![ld_true(), br_true(4), nop(), branch(0), ret()];
        let cfg = AdamantControlFlowGraph::new(&code, &[]);
        let mut interp = SawPop::new();
        let inv = analyze_function(&mut interp, &cfg, &code, false).expect("analysis terminates");
        assert!(!inv[&0].pre, "no Pop anywhere; header pre stays false");
        assert!(!inv[&4].pre, "no Pop anywhere; exit pre stays false");
    }

    /// Nested loops both converge.
    #[test]
    fn nested_loops_converge() {
        // 0: LdTrue          <- outer header
        // 1: BrTrue 8        <- exit outer
        // 2: LdTrue          <- inner header
        // 3: BrTrue 6        <- exit inner
        // 4: Pop             <- inner body: sees Pop
        // 5: Branch 2        <- inner back-edge
        // 6: Nop
        // 7: Branch 0        <- outer back-edge
        // 8: Ret
        let code = vec![
            ld_true(),
            br_true(8),
            ld_true(),
            br_true(6),
            pop(),
            branch(2),
            nop(),
            branch(0),
            ret(),
        ];
        let cfg = AdamantControlFlowGraph::new(&code, &[]);
        assert!(cfg.is_loop_head(0));
        assert!(cfg.is_loop_head(2));
        let mut interp = SawPop::new();
        let inv = analyze_function(&mut interp, &cfg, &code, false).expect("analysis terminates");
        // Pop in inner body propagates through both loops.
        assert!(
            inv[&8].pre,
            "exit block sees Pop via nested-loop propagation"
        );
    }

    /// `start` callback fires first; visitor-ordering trace is
    /// recorded.
    #[test]
    fn start_callback_first() {
        let code = vec![nop(), ret()];
        let cfg = AdamantControlFlowGraph::new(&code, &[]);
        let mut interp = SawPop::new();
        let _ = analyze_function(&mut interp, &cfg, &code, false).expect("analysis succeeds");
        assert_eq!(interp.trace.first().map(String::as_str), Some("start"));
    }

    /// Pre/post block visitors fire in pairs around each
    /// block's execution.
    #[test]
    fn pre_post_visitors_paired() {
        let code = vec![nop(), ret()];
        let cfg = AdamantControlFlowGraph::new(&code, &[]);
        let mut interp = SawPop::new();
        let _ = analyze_function(&mut interp, &cfg, &code, false).expect("analysis succeeds");
        // The first pre/post pair is around block 0.
        let pre_idx = interp.trace.iter().position(|s| s == "pre(0)");
        let post_idx = interp.trace.iter().position(|s| s == "post(0)");
        assert!(pre_idx.is_some());
        assert!(post_idx.is_some());
        assert!(
            pre_idx.unwrap() < post_idx.unwrap(),
            "pre must precede post for the same block"
        );
    }

    /// `visit_back_edge` fires when a loop's back-edge join
    /// changes the loop head's pre.
    #[test]
    fn back_edge_visitor_fires_on_loop_iteration() {
        // Same loop fixture as `loop_converges_with_pop_in_body`.
        let code = vec![ld_true(), br_true(5), pop(), nop(), branch(0), ret()];
        let cfg = AdamantControlFlowGraph::new(&code, &[]);
        let mut interp = SawPop::new();
        let _ = analyze_function(&mut interp, &cfg, &code, false).expect("analysis terminates");
        let saw_back_edge = interp.trace.iter().any(|s| s.starts_with("back("));
        assert!(
            saw_back_edge,
            "back-edge visitor must fire at least once when the back-edge join changes pre"
        );
    }

    /// `execute` errors propagate out of `analyze_function`.
    /// Uses an existing `AdamantValidationError` variant
    /// (`TooManyTypeNodes` — payload-free, semantically
    /// unrelated to absint, but valid for testing error
    /// propagation through the framework).
    #[test]
    fn execute_error_propagates() {
        struct Failing;
        impl AbstractInterpreter for Failing {
            type State = ();
            fn join(
                &mut self,
                _pre: &mut Self::State,
                _post: &Self::State,
            ) -> Result<JoinResult, AdamantValidationError> {
                Ok(JoinResult::Unchanged)
            }
            fn execute(
                &mut self,
                _block_id: CodeOffset,
                _bounds: (CodeOffset, CodeOffset),
                _state: &mut Self::State,
                _offset: CodeOffset,
                _instr: &BytecodeInstruction,
            ) -> Result<(), AdamantValidationError> {
                Err(AdamantValidationError::TooManyTypeNodes)
            }
        }
        let code = vec![nop(), ret()];
        let cfg = AdamantControlFlowGraph::new(&code, &[]);
        let mut interp = Failing;
        let result = analyze_function(&mut interp, &cfg, &code, ());
        assert!(matches!(
            result,
            Err(AdamantValidationError::TooManyTypeNodes)
        ));
    }

    /// `start` errors propagate before any block is processed.
    #[test]
    fn start_error_propagates() {
        struct StartFails;
        impl AbstractInterpreter for StartFails {
            type State = ();
            fn join(
                &mut self,
                _pre: &mut Self::State,
                _post: &Self::State,
            ) -> Result<JoinResult, AdamantValidationError> {
                Ok(JoinResult::Unchanged)
            }
            fn execute(
                &mut self,
                _block_id: CodeOffset,
                _bounds: (CodeOffset, CodeOffset),
                _state: &mut Self::State,
                _offset: CodeOffset,
                _instr: &BytecodeInstruction,
            ) -> Result<(), AdamantValidationError> {
                Ok(())
            }
            fn start(&mut self) -> Result<(), AdamantValidationError> {
                Err(AdamantValidationError::TooManyTypeNodes)
            }
        }
        let code = vec![ret()];
        let cfg = AdamantControlFlowGraph::new(&code, &[]);
        let mut interp = StartFails;
        let result = analyze_function(&mut interp, &cfg, &code, ());
        assert!(matches!(
            result,
            Err(AdamantValidationError::TooManyTypeNodes)
        ));
    }

    /// Single-block (entry-only) function: `analyze_function`
    /// returns an invariant map with one entry.
    #[test]
    fn single_block_function() {
        let code = vec![ret()];
        let cfg = AdamantControlFlowGraph::new(&code, &[]);
        let mut interp = SawPop::new();
        let inv = analyze_function(&mut interp, &cfg, &code, false).expect("analysis succeeds");
        assert_eq!(inv.len(), 1);
        assert!(inv.contains_key(&0));
    }
}
