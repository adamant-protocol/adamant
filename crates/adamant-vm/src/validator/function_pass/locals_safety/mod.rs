//! Adamant-native locals-safety pass (whitepaper §6.2.1.8 step
//! 4).
//!
//! Forked byte-faithfully from
//! `vendor/move-bytecode-verifier/src/locals_safety/mod.rs` at
//! Sui-Move tag `mainnet-v1.66.2` (196 LOC upstream). First
//! consumer of D-1b's
//! [`AbstractInterpreter`][super::absint::AbstractInterpreter]
//! framework — locals safety uses control-flow-sensitive
//! availability tracking via abstract interpretation over the
//! CFG built at D-1a.
//!
//! Plus a structural-impossibility check that
//! `function_definition.acquires_global_resources.is_empty()`
//! per the §6.2.1.6 Rule 5 architectural decision (CLAUDE.md
//! Section 10) — the deserializer rejects all 10 deprecated
//! global-storage opcodes at parse time inside
//! `AdamantDeserializeError::Bytecode::DeprecatedGlobalStorageOpcode`,
//! so any module that reaches the per-function pipeline cannot
//! contain global-storage ops, so its `acquires_global_resources`
//! field is always empty in valid Adamant modules. **2nd
//! instance of structural-impossibility-checks sub-shape 2**
//! (`unreachable!`-three-anchor; 1st was B-2.4 deprecated arms).
//!
//! # Cross-pass-pipeline-dependency
//!
//! - **Step 3** validates locals-signature pool indices,
//!   function-handle indices, and signature ranges. Per-token
//!   ability resolution can index `module.signatures[locals_idx]`
//!   without OOB.
//! - **Step 4 D-2** (`control_flow`) establishes a non-empty
//!   reducible CFG with bounded loop depth; the
//!   [`super::absint::analyze_function`] fixpoint is guaranteed
//!   to terminate.
//! - **Step 4 D-3** (`stack_usage`) establishes per-block
//!   stack balance; D-4's transfer functions can assume
//!   well-formed stack inputs.
//!
//! Cross-pass-pipeline-dependency sub-pattern (registered at
//! C-5); D-4 instantiates without surfacing new sub-pattern
//! instances.
//!
//! # Adamant-extension treatment sub-shape 3
//!
//! The 17 Adamant extensions don't read/write/borrow locals;
//! none are `Loc(idx)` flavored. Per-extension treatment
//! sub-shape 3 (extensions don't have X — pass through)
//! applies: the [`execute_inner`] transfer function's catchall
//! arm covers all `BytecodeInstruction::Adamant(_)` arms.
//! **3rd instance of sub-shape 3** (D-1a CFG branches; D-2
//! fall-through; D-4 locals access). **Rule-of-three for
//! sub-shape 3 met at D-4 closure.**

mod abstract_state;

use abstract_state::{LocalState, LocalsAbstractState};

use adamant_bytecode_format::{
    AbilitySet, Bytecode, CodeOffset, FunctionDefinitionIndex, FunctionHandle,
};

use super::absint::{analyze_function, AbstractInterpreter, JoinResult};
use super::cfg::AdamantControlFlowGraph;
use crate::bytecode::BytecodeInstruction;
use crate::module::{AdamantCompiledModule, AdamantFunctionDefinition};
use crate::validator::error::AdamantValidationError;

/// Three-anchor message stem for the acquires structural-
/// impossibility check. Hoisted to module-level const per the
/// discipline established at D-3.
const ACQUIRES_THREE_ANCHOR_STEM: &str =
    "Rule 5 deserializer-enforcement makes acquires_global_resources trivially-empty; \
     should be unreachable in pipeline; if this fires from direct-unvalidated-input \
     caller, caller violates the deserializer-precondition";

/// Verify locals safety for one function body, plus the
/// structural-impossibility check on the function's
/// `acquires_global_resources` list.
pub(super) fn verify_function(
    module: &AdamantCompiledModule,
    fn_def_idx: FunctionDefinitionIndex,
    function_definition: &AdamantFunctionDefinition,
    code: &[BytecodeInstruction],
    cfg: &AdamantControlFlowGraph,
) -> Result<(), AdamantValidationError> {
    // acquires_check runs first so any structural-impossibility
    // violation surfaces with the three-anchor message rather
    // than being shadowed by downstream errors. Same temporal-
    // ordering discipline as D-3's pre-resolved return_count
    // (resolved before the per-block iteration begins).
    verify_acquires(function_definition);

    let function_handle = resolve_function_handle(module, function_definition);
    // FunctionHandle::type_parameters is `Vec<AbilitySet>` directly
    // (each entry is the ability constraint set on that type
    // parameter). Distinct from DatatypeHandle's
    // `Vec<DatatypeTyParameter>` shape (which carries an extra
    // `is_phantom` flag alongside the constraints).
    let type_parameter_abilities: Vec<AbilitySet> = function_handle.type_parameters.clone();

    let code_unit = function_definition
        .code
        .as_ref()
        .expect("verify_function called on a function-def with a body; native skip is upstream");

    let initial_state = LocalsAbstractState::new(
        module,
        fn_def_idx,
        function_handle.parameters,
        code_unit.locals,
        &type_parameter_abilities,
    )?;

    let mut analysis = LocalsSafetyAnalysis;
    analyze_function(&mut analysis, cfg, code, initial_state)?;
    Ok(())
}

/// Structural-impossibility check (sub-shape 2 of structural-
/// impossibility-checks): Rule 5 deserializer-enforcement makes
/// `acquires_global_resources` always-empty in valid Adamant
/// modules. Panics rather than returns an error because
/// reaching the function-level pipeline with a non-empty
/// acquires list would mean the deserializer let a deprecated
/// global-storage opcode through — a structural impossibility
/// in any conforming Adamant implementation.
fn verify_acquires(function_definition: &AdamantFunctionDefinition) {
    if !function_definition.acquires_global_resources.is_empty() {
        unreachable!(
            "{ACQUIRES_THREE_ANCHOR_STEM}. acquires_global_resources.len() = {}",
            function_definition.acquires_global_resources.len()
        );
    }
}

fn resolve_function_handle<'a>(
    module: &'a AdamantCompiledModule,
    function_definition: &AdamantFunctionDefinition,
) -> &'a FunctionHandle {
    let handle_idx = function_definition.function.0 as usize;
    debug_assert!(
        handle_idx < module.function_handles.len(),
        "bounds_checker invariant violated; should be unreachable in pipeline; \
         if this fires from direct-unvalidated-input caller, caller violates the \
         precondition. FunctionHandleIndex {} >= function_handles.len() {}",
        handle_idx,
        module.function_handles.len(),
    );
    &module.function_handles[handle_idx]
}

struct LocalsSafetyAnalysis;

impl AbstractInterpreter for LocalsSafetyAnalysis {
    type State = LocalsAbstractState;

    fn join(
        &mut self,
        pre: &mut Self::State,
        post: &Self::State,
    ) -> Result<JoinResult, AdamantValidationError> {
        let (joined, changed) = pre.join_internal(post);
        if changed {
            *pre = joined;
            Ok(JoinResult::Changed)
        } else {
            Ok(JoinResult::Unchanged)
        }
    }

    fn execute(
        &mut self,
        _block_id: CodeOffset,
        _bounds: (CodeOffset, CodeOffset),
        state: &mut Self::State,
        offset: CodeOffset,
        instr: &BytecodeInstruction,
    ) -> Result<(), AdamantValidationError> {
        execute_inner(state, instr, offset)
    }
}

/// Per-instruction transfer function. Mirrors upstream's
/// `execute_inner` byte-faithfully for the inherited Sui-Move
/// instructions; Adamant extensions fall into the catchall
/// (sub-shape 3 — extensions don't touch locals).
fn execute_inner(
    state: &mut LocalsAbstractState,
    instr: &BytecodeInstruction,
    offset: CodeOffset,
) -> Result<(), AdamantValidationError> {
    let inherited = match instr {
        BytecodeInstruction::Inherited(b) => b,
        // Sub-shape 3: Adamant extensions don't touch locals.
        BytecodeInstruction::Adamant(_) => return Ok(()),
    };

    match inherited {
        Bytecode::StLoc(idx) => {
            match state.local_state(*idx) {
                LocalState::MaybeAvailable | LocalState::Available
                    if !state.local_abilities(*idx).has_drop() =>
                {
                    return Err(AdamantValidationError::StLocDestroysNonDrop {
                        fn_def_idx: state.fn_def_idx(),
                        code_offset: offset,
                    });
                }
                LocalState::Unavailable => {
                    state.set_available(*idx);
                }
                LocalState::MaybeAvailable | LocalState::Available => {
                    // Drop-able value already present; StLoc
                    // overwrites with the new one. Keep
                    // Available (the prior value is silently
                    // dropped).
                    state.set_available(*idx);
                }
            }
        }
        Bytecode::MoveLoc(idx) => match state.local_state(*idx) {
            LocalState::MaybeAvailable | LocalState::Unavailable => {
                return Err(AdamantValidationError::MoveLocUnavailable {
                    fn_def_idx: state.fn_def_idx(),
                    code_offset: offset,
                });
            }
            LocalState::Available => state.set_unavailable(*idx),
        },
        Bytecode::CopyLoc(idx) => match state.local_state(*idx) {
            LocalState::MaybeAvailable | LocalState::Unavailable => {
                return Err(AdamantValidationError::CopyLocUnavailable {
                    fn_def_idx: state.fn_def_idx(),
                    code_offset: offset,
                });
            }
            LocalState::Available => {}
        },
        Bytecode::MutBorrowLoc(idx) | Bytecode::ImmBorrowLoc(idx) => {
            match state.local_state(*idx) {
                LocalState::Unavailable | LocalState::MaybeAvailable => {
                    return Err(AdamantValidationError::BorrowLocUnavailable {
                        fn_def_idx: state.fn_def_idx(),
                        code_offset: offset,
                    });
                }
                LocalState::Available => {}
            }
        }
        Bytecode::Ret => {
            for (local_state, local_abilities) in
                state.local_states().iter().zip(state.all_local_abilities())
            {
                match local_state {
                    LocalState::MaybeAvailable | LocalState::Available
                        if !local_abilities.has_drop() =>
                    {
                        return Err(AdamantValidationError::RetWithUndroppedLocals {
                            fn_def_idx: state.fn_def_idx(),
                            code_offset: offset,
                        });
                    }
                    _ => {}
                }
            }
        }
        // All other inherited bytecode does not affect locals
        // state. Mirrors upstream's catchall arm verbatim.
        _ => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    //! Layer A unit tests for the locals-safety pass.
    //!
    //! Covers per-instruction transfer-function correctness,
    //! lattice meet semantics at branch joins, Adamant-extension
    //! sub-shape 3 confirmation, the acquires structural-
    //! impossibility check, eager-error semantics, and
    //! inherited-bytecode catchall behavior.

    use super::*;
    use adamant_bytecode_format::{
        AbilitySet, Ability, AddressIdentifierIndex, DatatypeHandle, DatatypeHandleIndex,
        FunctionHandle, FunctionHandleIndex, Identifier, IdentifierIndex, ModuleHandle,
        ModuleHandleIndex, Signature, SignatureIndex, SignatureToken, StructDefinitionIndex,
        Visibility,
    };
    use crate::bytecode::{AdamantBytecode, BytecodeInstruction};
    use crate::module::{AdamantCodeUnit, AdamantCompiledModule, AdamantFunctionDefinition};

    // --- builders ---

    fn ld_u64(v: u64) -> BytecodeInstruction {
        BytecodeInstruction::Inherited(Bytecode::LdU64(v))
    }

    fn ld_true() -> BytecodeInstruction {
        BytecodeInstruction::Inherited(Bytecode::LdTrue)
    }

    fn pop() -> BytecodeInstruction {
        BytecodeInstruction::Inherited(Bytecode::Pop)
    }

    fn nop() -> BytecodeInstruction {
        BytecodeInstruction::Inherited(Bytecode::Nop)
    }

    fn ret() -> BytecodeInstruction {
        BytecodeInstruction::Inherited(Bytecode::Ret)
    }

    fn add() -> BytecodeInstruction {
        BytecodeInstruction::Inherited(Bytecode::Add)
    }

    fn st_loc(idx: u8) -> BytecodeInstruction {
        BytecodeInstruction::Inherited(Bytecode::StLoc(idx))
    }

    fn mv_loc(idx: u8) -> BytecodeInstruction {
        BytecodeInstruction::Inherited(Bytecode::MoveLoc(idx))
    }

    fn cp_loc(idx: u8) -> BytecodeInstruction {
        BytecodeInstruction::Inherited(Bytecode::CopyLoc(idx))
    }

    fn mut_borrow_loc(idx: u8) -> BytecodeInstruction {
        BytecodeInstruction::Inherited(Bytecode::MutBorrowLoc(idx))
    }

    fn imm_borrow_loc(idx: u8) -> BytecodeInstruction {
        BytecodeInstruction::Inherited(Bytecode::ImmBorrowLoc(idx))
    }

    fn br_true(target: CodeOffset) -> BytecodeInstruction {
        BytecodeInstruction::Inherited(Bytecode::BrTrue(target))
    }

    fn branch(target: CodeOffset) -> BytecodeInstruction {
        BytecodeInstruction::Inherited(Bytecode::Branch(target))
    }

    /// Build a module with one function definition. Parameters
    /// are the given signatures (Available at entry); locals
    /// are the given signatures (Unavailable at entry).
    fn module_with_function(
        param_tokens: Vec<SignatureToken>,
        local_tokens: Vec<SignatureToken>,
        body: Vec<BytecodeInstruction>,
    ) -> AdamantCompiledModule {
        let mut m = AdamantCompiledModule::default();
        m.module_handles.push(ModuleHandle {
            address: AddressIdentifierIndex(0),
            name: IdentifierIndex(0),
        });
        m.identifiers.push(Identifier::new("f").unwrap());
        m.signatures.push(Signature(param_tokens)); // 0 -> params
        m.signatures.push(Signature(local_tokens)); // 1 -> locals
        m.function_handles.push(FunctionHandle {
            module: ModuleHandleIndex(0),
            name: IdentifierIndex(0),
            parameters: SignatureIndex(0),
            return_: SignatureIndex(0), // empty by default; tests can override
            type_parameters: vec![],
        });
        m.function_defs.push(AdamantFunctionDefinition {
            function: FunctionHandleIndex(0),
            visibility: Visibility::default(),
            is_entry: false,
            acquires_global_resources: vec![],
            code: Some(AdamantCodeUnit {
                locals: SignatureIndex(1),
                code: body,
                jump_tables: vec![],
            }),
        });
        m
    }

    fn run(m: &AdamantCompiledModule) -> Result<(), AdamantValidationError> {
        let function_definition = &m.function_defs[0];
        let code_unit = function_definition.code.as_ref().expect("body");
        let cfg = AdamantControlFlowGraph::new(&code_unit.code, &code_unit.jump_tables);
        verify_function(
            m,
            FunctionDefinitionIndex::new(0),
            function_definition,
            &code_unit.code,
            &cfg,
        )
    }

    /// Add a non-drop datatype to the module's
    /// `datatype_handles` pool. Returns the `SignatureToken`
    /// referring to it.
    fn add_non_drop_datatype(m: &mut AdamantCompiledModule) -> SignatureToken {
        let handle_idx = u16::try_from(m.datatype_handles.len())
            .expect("test fixture handle count fits u16");
        m.identifiers.push(Identifier::new("S").unwrap());
        let name_idx = u16::try_from(m.identifiers.len() - 1)
            .expect("test fixture identifier count fits u16");
        // Abilities = key only (no drop).
        m.datatype_handles.push(DatatypeHandle {
            module: ModuleHandleIndex(0),
            name: IdentifierIndex(name_idx),
            abilities: AbilitySet::EMPTY | Ability::Key,
            type_parameters: vec![],
        });
        SignatureToken::Datatype(DatatypeHandleIndex(handle_idx))
    }

    // --- per-instruction transfer ---

    #[test]
    fn stloc_to_unavailable_local_makes_available() {
        // Function: () -> (); locals = [u64]. Body: LdU64 0;
        // StLoc 0; MoveLoc 0; Pop; Ret.
        let m = module_with_function(
            vec![],
            vec![SignatureToken::U64],
            vec![ld_u64(0), st_loc(0), mv_loc(0), pop(), ret()],
        );
        run(&m).expect("StLoc on Unavailable local makes it Available");
    }

    #[test]
    fn stloc_to_available_drop_local_succeeds() {
        // u64 has drop. StLoc on Available drop-local OK.
        let m = module_with_function(
            vec![SignatureToken::U64],
            vec![],
            vec![ld_u64(0), st_loc(0), mv_loc(0), pop(), ret()],
        );
        run(&m).expect("StLoc on Available drop-local OK");
    }

    #[test]
    fn stloc_to_available_non_drop_local_rejects() {
        // Non-drop datatype as the local; StLoc on Available
        // would destroy the prior value.
        let mut m = module_with_function(
            vec![],
            vec![],
            vec![/* placeholder */ ret()],
        );
        let s_token = add_non_drop_datatype(&mut m);
        // Reset locals to [non-drop]; param is Available at entry
        // via an extra parameter of the same type.
        m.signatures[0] = Signature(vec![s_token.clone()]); // params: 1 non-drop
        m.signatures[1] = Signature(vec![s_token.clone()]); // locals: 1 non-drop
        // Body: param idx 0 is Available; local idx 1 is Unavailable.
        // CopyLoc 0 (push non-drop value via copy — but non-drop
        // also lacks copy, so use MoveLoc).
        // Simpler: MoveLoc 0 (push from param), StLoc 1 (write to
        // unavailable local — succeeds, makes it Available),
        // MoveLoc 0 (already moved out — would error). Use
        // MoveLoc to non-drop is fine for movement.
        // Actually simplest: param is Available, local is
        // Unavailable. StLoc 1 (Unavailable -> Available) needs
        // a value pushed. MoveLoc 0 pushes the param value.
        // Then StLoc 1 again with another MoveLoc would try
        // to overwrite. Need: param twice, MoveLoc 0; StLoc 1;
        // MoveLoc 0 again would be unavailable.
        // Cleanest: 2 params, both non-drop. Push first via
        // MoveLoc 0, StLoc 2 (local). Push second via MoveLoc 1,
        // StLoc 2 again — Available + non-drop -> StLocDestroysNonDrop.
        m.signatures[0] = Signature(vec![s_token.clone(), s_token.clone()]); // 2 params
        m.signatures[1] = Signature(vec![s_token.clone()]); // 1 local
        m.function_defs[0].code = Some(AdamantCodeUnit {
            locals: SignatureIndex(1),
            code: vec![mv_loc(0), st_loc(2), mv_loc(1), st_loc(2), mv_loc(2), ret()],
            jump_tables: vec![],
        });
        match run(&m) {
            Err(AdamantValidationError::StLocDestroysNonDrop { .. }) => {}
            other => panic!("expected StLocDestroysNonDrop, got {other:?}"),
        }
    }

    #[test]
    fn moveloc_available_makes_unavailable() {
        let m = module_with_function(
            vec![SignatureToken::U64],
            vec![],
            vec![mv_loc(0), pop(), ret()],
        );
        run(&m).expect("MoveLoc on Available local OK");
    }

    #[test]
    fn moveloc_unavailable_rejects() {
        // Local 0 is Unavailable at entry; MoveLoc 0 rejects.
        let m = module_with_function(
            vec![],
            vec![SignatureToken::U64],
            vec![mv_loc(0), pop(), ret()],
        );
        match run(&m) {
            Err(AdamantValidationError::MoveLocUnavailable { .. }) => {}
            other => panic!("expected MoveLocUnavailable, got {other:?}"),
        }
    }

    #[test]
    fn copyloc_available_succeeds() {
        let m = module_with_function(
            vec![SignatureToken::U64],
            vec![],
            vec![cp_loc(0), pop(), ret()],
        );
        run(&m).expect("CopyLoc on Available local OK");
    }

    #[test]
    fn copyloc_unavailable_rejects() {
        let m = module_with_function(
            vec![],
            vec![SignatureToken::U64],
            vec![cp_loc(0), pop(), ret()],
        );
        match run(&m) {
            Err(AdamantValidationError::CopyLocUnavailable { .. }) => {}
            other => panic!("expected CopyLocUnavailable, got {other:?}"),
        }
    }

    #[test]
    fn mut_borrowloc_unavailable_rejects() {
        let m = module_with_function(
            vec![],
            vec![SignatureToken::U64],
            vec![mut_borrow_loc(0), pop(), ret()],
        );
        match run(&m) {
            Err(AdamantValidationError::BorrowLocUnavailable { .. }) => {}
            other => panic!("expected BorrowLocUnavailable, got {other:?}"),
        }
    }

    #[test]
    fn imm_borrowloc_unavailable_rejects() {
        let m = module_with_function(
            vec![],
            vec![SignatureToken::U64],
            vec![imm_borrow_loc(0), pop(), ret()],
        );
        match run(&m) {
            Err(AdamantValidationError::BorrowLocUnavailable { .. }) => {}
            other => panic!("expected BorrowLocUnavailable, got {other:?}"),
        }
    }

    #[test]
    fn ret_with_undropped_local_rejects() {
        // Param is non-drop and Available at Ret — reject.
        let mut m = module_with_function(vec![], vec![], vec![ret()]);
        let s_token = add_non_drop_datatype(&mut m);
        m.signatures[0] = Signature(vec![s_token.clone()]); // param
        m.function_defs[0].code = Some(AdamantCodeUnit {
            locals: SignatureIndex(1),
            code: vec![ret()],
            jump_tables: vec![],
        });
        match run(&m) {
            Err(AdamantValidationError::RetWithUndroppedLocals { .. }) => {}
            other => panic!("expected RetWithUndroppedLocals, got {other:?}"),
        }
    }

    // --- branch-join semantics ---

    /// **Load-bearing test: pins the lattice meet operator's
    /// `MaybeAvailable` production at branch joins.** The
    /// soundness of the entire locals-safety analysis depends
    /// on this property — without correct meet semantics, paths
    /// where a local is assigned in one branch but not the
    /// other would be silently treated as `Available`,
    /// producing false negatives on `MoveLocUnavailable` /
    /// `BorrowLocUnavailable` / `CopyLocUnavailable` /
    /// `RetWithUndroppedLocals` checks.
    ///
    /// Fixture: param 0 (u64, drop) is Available throughout;
    /// local 1 (u64) is assigned only on the `BrTrue` arm.
    /// After the join, local 1 is `MaybeAvailable`. Trying to
    /// `MoveLoc 1` after the join must reject with
    /// `MoveLocUnavailable`.
    #[test]
    fn branch_join_makes_local_maybe_available() {
        // 0: LdTrue                  push 1
        // 1: BrTrue 4                pop 1 -> branch to 4
        // 2: LdU64 0                 push 1 (false arm)
        // 3: StLoc 1                 pop 1, local 1 -> Available
        // 4: MoveLoc 1               <-- meet point: local 1 is
        //                                `MaybeAvailable` here;
        //                                `MoveLoc` rejects
        // 5: Pop
        // 6: Ret
        let m = module_with_function(
            vec![SignatureToken::U64],
            vec![SignatureToken::U64],
            vec![
                ld_true(),
                br_true(4),
                ld_u64(0),
                st_loc(1),
                mv_loc(1),
                pop(),
                ret(),
            ],
        );
        match run(&m) {
            Err(AdamantValidationError::MoveLocUnavailable { .. }) => {}
            other => panic!("expected MoveLocUnavailable at branch-join, got {other:?}"),
        }
    }

    #[test]
    fn loop_back_edge_converges() {
        // Trivial loop: header -> exit, no local manipulation.
        // Confirms fixpoint terminates in the locals-safety
        // analysis on a back-edge.
        let m = module_with_function(
            vec![],
            vec![],
            vec![ld_true(), br_true(4), nop(), branch(0), ret()],
        );
        run(&m).expect("loop with no local manipulation converges");
    }

    #[test]
    fn unreachable_block_local_state_doesnt_propagate() {
        // Branch skips block 1 (orphan); analysis of block 1
        // doesn't propagate to reachable blocks.
        let m = module_with_function(
            vec![],
            vec![SignatureToken::U64],
            vec![branch(2), pop(), ret()],
        );
        run(&m).expect("orphan block doesn't propagate locals state");
    }

    // --- Adamant extension sub-shape 3 ---

    #[test]
    fn adamant_extension_does_not_affect_locals_state() {
        // Extension between StLoc and Ret; locals state
        // unchanged.
        let m = module_with_function(
            vec![SignatureToken::U64],
            vec![],
            vec![
                mv_loc(0),
                BytecodeInstruction::Adamant(AdamantBytecode::Sha3_256),
                pop(),
                ret(),
            ],
        );
        run(&m).expect("Adamant extension passes through locals-safety");
    }

    #[test]
    fn out_of_gas_passes_through() {
        let m = module_with_function(
            vec![],
            vec![],
            vec![BytecodeInstruction::Adamant(AdamantBytecode::OutOfGas), ret()],
        );
        run(&m).expect("OutOfGas passes through locals-safety");
    }

    #[test]
    fn kzg_commit_in_middle_passes_through() {
        let m = module_with_function(
            vec![],
            vec![],
            vec![
                ld_u64(0),
                BytecodeInstruction::Adamant(AdamantBytecode::KzgCommit),
                pop(),
                ret(),
            ],
        );
        run(&m).expect("KzgCommit passes through locals-safety");
    }

    // --- acquires structural-impossibility ---

    #[test]
    fn acquires_empty_passes_silently() {
        let m = module_with_function(vec![], vec![], vec![ret()]);
        // Default acquires_global_resources is empty.
        run(&m).expect("empty acquires list passes silently");
    }

    /// `verify_acquires` runs first so any structural-
    /// impossibility violation surfaces with the three-anchor
    /// message rather than being shadowed by downstream errors.
    /// Same temporal-ordering discipline as D-3's pre-resolved
    /// `return_count` (resolved before per-block iteration
    /// begins). Direct-unvalidated callers (e.g., this test)
    /// trigger the unreachable! defensively.
    #[test]
    #[should_panic(expected = "Rule 5 deserializer-enforcement")]
    fn acquires_non_empty_panics_with_three_anchor() {
        let mut m = module_with_function(vec![], vec![], vec![ret()]);
        m.function_defs[0].acquires_global_resources = vec![StructDefinitionIndex(0)];
        let _ = run(&m);
    }

    // --- inherited-bytecode catchall ---

    #[test]
    fn binop_does_not_affect_locals_state() {
        let m = module_with_function(
            vec![SignatureToken::U64],
            vec![],
            vec![ld_u64(1), ld_u64(2), add(), pop(), mv_loc(0), pop(), ret()],
        );
        run(&m).expect("Add doesn't affect locals state");
    }

    #[test]
    fn branch_does_not_affect_locals_state() {
        let m = module_with_function(
            vec![],
            vec![],
            vec![branch(2), nop(), ret()],
        );
        run(&m).expect("Branch doesn't affect locals state");
    }

    // --- eager-error semantics ---

    #[test]
    fn first_block_locals_failure_aborts_function_pass() {
        // Local 0 Unavailable; MoveLoc 0 rejects on the first
        // block before any later instruction can mask.
        let m = module_with_function(
            vec![],
            vec![SignatureToken::U64],
            vec![mv_loc(0), pop(), mv_loc(0), pop(), ret()],
        );
        match run(&m) {
            Err(AdamantValidationError::MoveLocUnavailable { code_offset, .. }) => {
                assert_eq!(code_offset, 0, "first MoveLoc fires; second is dead");
            }
            other => panic!("expected MoveLocUnavailable on first MoveLoc, got {other:?}"),
        }
    }

    // --- LocalState lattice (in tests via the Local API) ---

    #[test]
    fn local_state_unavailable_default() {
        let m = module_with_function(vec![], vec![SignatureToken::U64], vec![ret()]);
        let function_definition = &m.function_defs[0];
        let function_handle = &m.function_handles[0];
        let code_unit = function_definition.code.as_ref().unwrap();
        let initial = LocalsAbstractState::new(
            &m,
            FunctionDefinitionIndex::new(0),
            function_handle.parameters,
            code_unit.locals,
            &[],
        )
        .unwrap();
        assert_eq!(initial.local_state(0), LocalState::Unavailable);
    }

    #[test]
    fn parameters_are_available_at_entry() {
        let m = module_with_function(vec![SignatureToken::U64], vec![], vec![ret()]);
        let function_definition = &m.function_defs[0];
        let function_handle = &m.function_handles[0];
        let code_unit = function_definition.code.as_ref().unwrap();
        let initial = LocalsAbstractState::new(
            &m,
            FunctionDefinitionIndex::new(0),
            function_handle.parameters,
            code_unit.locals,
            &[],
        )
        .unwrap();
        assert_eq!(initial.local_state(0), LocalState::Available);
    }
}
