//! Adamant-native type-safety pass (whitepaper §6.2.1.8 step 4).
//!
//! Forked byte-faithfully from
//! `vendor/move-bytecode-verifier/src/type_safety.rs` at
//! Sui-Move tag `mainnet-v1.66.2` (1278 LOC upstream). Per-block-
//! and-per-instruction typed-stack tracking; **does NOT use the
//! `AbstractInterpreter` framework** (per upstream comment line 6:
//! "It does not utilize control flow, but does check each block
//! independently"). Per-block iteration shape parallel to D-3
//! `stack_usage`.
//!
//! # D-5a.1 staging note
//!
//! D-5a.1 was split into D-5a.1.a + D-5a.1.b at D-5a.1
//! implementation-gate per quality-over-speed discipline (CLAUDE.md
//! Section 4); session-pacing-split sub-shape 3 of empirical-
//! complexity-drives-sub-checkpoint-shape pattern, 2nd instance
//! after D-5a.0/D-5a.1.
//!
//! - **D-5a.1.a.** Foundation: `TypeSafetyChecker` struct +
//!   helpers + per-instruction transfer for the first ~30-40
//!   inherited bytecode arms (load/move/copy/store/binop/eq/cast/
//!   branch/ret/abort/pop) + structural-impossibility
//!   `unreachable!`-three-anchor consolidating 10 deprecated
//!   global-storage opcodes (sub-shape 2 instance, 3rd at D-5a.1.a
//!   closure — rule-of-three threshold met for sub-shape 2).
//! - **D-5a.1.b (this commit).** Remaining inherited arms
//!   (refs / pack / unpack / calls / vector / variant) + 17
//!   Adamant extensions per §6.2.1.4 lines 408-423 (Categories
//!   A/B/C/D on record at D-3's 10th verification gate) +
//!   orchestration chain wired in at
//!   [`super::verify_function_bodies`]. Closes the deferral
//!   flagged at D-5a.1.a impl-gate (honest-scope-flagging
//!   opening + closure phases — NEW sub-pattern; opening at
//!   D-5a.1.a, closure at D-5a.1.b). Closes the variant-vs-test
//!   mapping audit deferred from D-5a.0 (8 of 14 sub-reasons
//!   audit-close at D-5a.1.b; 6 audit-closed at D-5a.1.a;
//!   14 total = 14 declared = plan-incremental-disposition
//!   sub-pattern β closure phase 1st instance).
//!
//! # Adamant deviations
//!
//! - **Per-pass-instance `AdamantAbilityCache` lifecycle** (Q2(a)
//!   at D-5 plan-gate; mirrors B-2.3's per-pass-instance shape;
//!   stricter than D-4's per-function-instance lifecycle). Cache
//!   is constructed once at the per-function batch entry
//!   ([`super::verify_function_bodies`] hoists the cache outside
//!   the function loop) and reused across all functions within
//!   the type-safety pass.
//! - **Adamant-native [`AbstractStack`]** (Q1(a) at D-5a plan-gate;
//!   9th deliberate-Adamant-decision instance via D-5a.0 port).
//!   Same vendored-Sui-crates-port canonical principle as D-1a /
//!   D-1b / D-2.
//! - **Closed-enum sub-reason on `TypeMismatch`** (Q4(a) at D-5
//!   plan-gate; 7th deliberate-Adamant-decision instance via
//!   `TypeMismatchReason`). 14 sub-reasons declared at D-5a.0;
//!   variant-vs-test mapping audit closes across D-5a.1.a +
//!   D-5a.1.b at 14 total.
//! - **`expect()`-three-anchor on `AbsStackError` for single-
//!   pop/push paths** (Q1(a) at D-5a.1 plan-gate; sub-shape 4 of
//!   structural-impossibility-checks pattern; **1 instance with
//!   continued use** through D-5a.1.b per per-mechanism counting
//!   discipline — same mechanism applied across additional code
//!   paths, not 2 instances). D-3's per-block-balance precondition
//!   makes `Underflow` structurally impossible at type-safety's
//!   pipeline position; D-3's `max_push_size` check makes
//!   `Overflow` structurally impossible. **Note on `pop_eq_n`:**
//!   for `num > 1`, `pop_eq_n`'s `ElementNotEqual` is a
//!   legitimate type-safety error path (used by `VecPack` to
//!   check that all elements share the declared element type),
//!   handled via upstream's `unwrap_or(true)` collapse pattern
//!   rather than the panicking pop helper. Sub-shape 4's
//!   structural-impossibility scope is restricted to single-
//!   pop/push paths.
//! - **Hierarchical type-rule pinning for Adamant extensions per
//!   §6.2.1.4 lines 408-423** (Q1(a) at D-5a.1.b plan-gate). All
//!   12 Category A extensions pin pop and push types per Sui-Move
//!   convention (`vector<u8>` for cryptographic byte containers,
//!   `bool` for verify outputs, `u64` for gas operands)
//!   consistent with §6.2.1.4's explicit pins where present
//!   (`Sha3_256` / `Blake3` pop `vector<u8>` per lines 416-417;
//!   `KzgVerify` push `bool` per line 414; `Ed25519Verify` /
//!   `MlDsaVerify65` / `BlsVerify` push `bool` per lines 418-420;
//!   `ChargeGas` pop `u64` per line 421; `RemainingGas` push
//!   `u64` per line 422). Notation-
//!   precision
//!   footnote: §6.2.1.4 lines 416-417's `[u8; 32]` is Rust
//!   syntax; the bytecode-Move-type for hash outputs is
//!   `vector<u8>` per Sui's `move-stdlib/sources/hash.move`
//!   convention (`sha2_256` / `sha3_256` both
//!   `(vector<u8>) -> vector<u8>`). Registered as plan-gate-
//!   level instance of citation-precision discipline
//!   (PROVENANCE.md canonical at D-7).
//! - **Cat B (`InvokeShielded` / `InvokeTransparent`) reuses the
//!   [`call`] helper.** Per §6.2.1.4 line 408 verbatim ("the
//!   verifier...treat reference inputs and outputs of
//!   `InvokeShielded` exactly as they would for an inherited
//!   `Call`"). 1st instance of NEW spec-text-to-shared-helper
//!   canonical principle: when spec text says 'extension treats
//!   X exactly as inherited Y', implementation is a shared helper
//!   rather than duplicated logic. Rule-of-three pending; D-7
//!   PROVENANCE.md canonicalization deferred until threshold met.
//! - **Cat C / Cat D fail open at the type layer.**
//!   `GenerateProof` / `VerifyProof` (Cat C) resolve type
//!   contracts through circuit signatures specified by §7;
//!   `RecursiveVerify` (Cat D) resolves through §8.5; verifier
//!   makes no type assertions, runtime carries the binding. Same
//!   shielding-vs-runtime canonical pattern as D-3's stack-effect
//!   treatment. Per-mechanism counting: deferred-to-§7 stays at
//!   2 (`CircuitId` resolution mechanism cited at D-3 stack +
//!   D-5a.1.b type); deferred-to-§8 stays at 1.
//! - No metering surface (D-1a / D-1b / D-2 / D-3 / D-4 /
//!   D-5a.0 / D-5a.1.a precedent; `TYPE_NODE_COST`,
//!   `TYPE_NODE_QUADRATIC_THRESHOLD`, `TYPE_PUSH_COST` constants
//!   not ported). Confirmed at D-5a plan-gate Q4.
//!
//! # Cross-pass-pipeline-dependency
//!
//! Four intra-pipeline preconditions:
//! - **Step 3** (`module_pass::bounds_checker`,
//!   `signature_checker`, `instruction_consistency`): handle and
//!   signature-pool indices validated; per-instruction lookups
//!   in [`verify_inherited_instr`] / helpers cannot panic.
//! - **Step 4 D-2** (`function_pass::control_flow`): non-empty
//!   reducible CFG; [`verify_function`] iterates `cfg.blocks()`.
//! - **Step 4 D-3** (`function_pass::stack_usage`): per-block
//!   stack balance; single-pop/push [`AbstractStack`] operations
//!   are structurally infallible (sub-shape 4).
//! - **Step 4 D-4** (`function_pass::locals_safety`): locals
//!   availability; `CopyLoc` / `MoveLoc` lookups assume the local
//!   has a value, then this pass type-checks the value.
//!
//! Cross-pass-pipeline-dependency sub-pattern (registered at
//! C-5); D-5a.1 instantiates without surfacing new sub-pattern
//! instances.

use std::num::NonZeroU64;

use adamant_bytecode_format::{
    AbilitySet, Bytecode, CodeOffset, FieldHandleIndex, FunctionDefinitionIndex, JumpTableInner,
    LocalIndex, Signature, SignatureToken, StructDefinition, StructFieldInformation,
    VariantJumpTable,
};

use super::abstract_stack::AbstractStack;
use super::cfg::AdamantControlFlowGraph;
use crate::bytecode::{AdamantBytecode, BytecodeInstruction};
use crate::module::{AdamantCompiledModule, AdamantFunctionDefinition};
use crate::validator::error::{AdamantValidationError, TypeMismatchReason};
use crate::validator::module_pass::ability_cache::AdamantAbilityCache;

/// Three-anchor message stem for the [`AbstractStack`] structural-
/// impossibility check on single-pop/push paths. Sub-shape 4 of the
/// structural-impossibility-checks pattern. `expect()` fires in
/// BOTH debug AND release builds — the invariant is consensus-
/// binding (D-3's per-block-balance precondition is what makes
/// type-safety's stack ops well-formed; a violation indicates an
/// Adamant implementation bug, not malformed input).
const STACK_INVARIANT_THREE_ANCHOR_STEM: &str =
    "AbstractStack invariant violated; should be unreachable in pipeline (D-3's per-block-balance \
     + max_push_size preconditions); if this fires from direct-unvalidated-input caller, caller \
     violates the precondition";

/// Three-anchor message stem for the deprecated global-storage
/// `unreachable!` arm. Sub-shape 2 of structural-impossibility-
/// checks (3rd instance at D-5a.1.a closure — rule-of-three for
/// sub-shape 2 specifically met: B-2.4 deprecated arms + D-4
/// acquires-list + D-5a.1.a deprecated global-storage in
/// type-safety).
const DEPRECATED_GLOBAL_STORAGE_THREE_ANCHOR_STEM: &str =
    "Rule 5 deserializer-enforcement makes deprecated global-storage opcodes (MoveTo/MoveFrom/\
     BorrowGlobal/Exists × {Deprecated, GenericDeprecated}) unreachable in valid Adamant modules; \
     should be unreachable in pipeline; if this fires from direct-unvalidated-input caller, caller \
     violates the deserializer-precondition";

/// Per-function type-safety verifier state.
///
/// Mirrors upstream's `TypeSafetyChecker` byte-faithfully:
/// constructed once per function, holds the typed [`AbstractStack`]
/// and references to the module + function-context state.
pub(super) struct TypeSafetyChecker<'env, 'a> {
    module: &'env AdamantCompiledModule,
    fn_def_idx: FunctionDefinitionIndex,
    type_parameters: Vec<AbilitySet>,
    parameters: &'env Signature,
    locals: &'env Signature,
    return_: &'env Signature,
    ability_cache: &'a mut AdamantAbilityCache<'env>,
    stack: AbstractStack<SignatureToken>,
}

impl<'env, 'a> TypeSafetyChecker<'env, 'a> {
    /// Build a new type-safety checker for the given function.
    pub(super) fn new(
        module: &'env AdamantCompiledModule,
        fn_def_idx: FunctionDefinitionIndex,
        type_parameters: Vec<AbilitySet>,
        parameters: &'env Signature,
        locals: &'env Signature,
        return_: &'env Signature,
        ability_cache: &'a mut AdamantAbilityCache<'env>,
    ) -> Self {
        Self {
            module,
            fn_def_idx,
            type_parameters,
            parameters,
            locals,
            return_,
            ability_cache,
            stack: AbstractStack::new(),
        }
    }

    /// Resolve the type of the local at `i`. Local index is
    /// `parameters_count + locals_count` flat — first
    /// `parameters_count` indices refer to parameters; the rest
    /// refer to locals.
    fn local_at(&self, i: LocalIndex) -> &SignatureToken {
        let idx = i as usize;
        let param_count = self.parameters.0.len();
        if idx < param_count {
            &self.parameters.0[idx]
        } else {
            &self.locals.0[idx - param_count]
        }
    }

    /// Resolve the [`AbilitySet`] of a [`SignatureToken`] under
    /// the function's type-parameter constraints. Panics via
    /// `expect()` on cache resolution because `bounds_checker`
    /// makes the failure paths structurally impossible at
    /// step 3 (same posture as D-4's `locals_safety`).
    fn abilities(&mut self, t: &SignatureToken) -> AbilitySet {
        self.ability_cache
            .abilities(&self.type_parameters, t)
            .expect(
                "AdamantAbilityCache resolution is structurally infallible after bounds_checker; \
                 type-parameter and datatype indices are validated at step 3",
            )
    }

    /// Build a typed [`AdamantValidationError::TypeMismatch`] at
    /// the current function offset.
    fn type_mismatch(
        &self,
        code_offset: CodeOffset,
        reason: TypeMismatchReason,
    ) -> AdamantValidationError {
        AdamantValidationError::TypeMismatch {
            fn_def_idx: self.fn_def_idx,
            code_offset,
            reason,
        }
    }

    /// Push a value onto the abstract typed-stack. Sub-shape 4
    /// `expect()`-three-anchor on overflow.
    fn push(&mut self, ty: SignatureToken) {
        self.stack
            .push(ty)
            .unwrap_or_else(|e| panic!("{STACK_INVARIANT_THREE_ANCHOR_STEM}. push error: {e:?}"));
    }

    /// Push `n` copies of a value onto the abstract typed-stack.
    /// Sub-shape 4 `expect()`-three-anchor on overflow.
    fn push_n(&mut self, ty: SignatureToken, n: u64) {
        self.stack
            .push_n(ty, n)
            .unwrap_or_else(|e| panic!("{STACK_INVARIANT_THREE_ANCHOR_STEM}. push_n error: {e:?}"));
    }

    /// Pop a value from the abstract typed-stack. Sub-shape 4
    /// `expect()`-three-anchor on underflow.
    fn pop(&mut self) -> SignatureToken {
        match self.stack.pop() {
            Ok(t) => t,
            Err(e) => {
                panic!("{STACK_INVARIANT_THREE_ANCHOR_STEM}. pop error: {e:?}")
            }
        }
    }
}

/// Verify type safety for one function body.
///
/// Constructs a [`TypeSafetyChecker`], iterates every basic block
/// in the CFG, and applies [`verify_instr`] per instruction.
///
/// The `ability_cache` parameter implements per-pass-instance
/// memoization (Q2(a) at D-5 plan-gate): the caller (function-
/// pass orchestration) constructs one cache shared across all
/// functions in a module; lookups for the same signature token
/// in different functions hit the cache.
pub(super) fn verify_function<'env>(
    module: &'env AdamantCompiledModule,
    fn_def_idx: FunctionDefinitionIndex,
    function_definition: &'env AdamantFunctionDefinition,
    code: &[BytecodeInstruction],
    cfg: &AdamantControlFlowGraph,
    ability_cache: &mut AdamantAbilityCache<'env>,
) -> Result<(), AdamantValidationError> {
    let function_handle = resolve_function_handle(module, function_definition);
    let type_parameters: Vec<AbilitySet> = function_handle.type_parameters.clone();

    let parameters_idx = function_handle.parameters.0 as usize;
    let return_idx = function_handle.return_.0 as usize;
    let code_unit = function_definition
        .code
        .as_ref()
        .expect("verify_function called with body; native skip is upstream");
    let locals_idx = code_unit.locals.0 as usize;

    debug_assert!(parameters_idx < module.signatures.len());
    debug_assert!(return_idx < module.signatures.len());
    debug_assert!(locals_idx < module.signatures.len());

    let parameters = &module.signatures[parameters_idx];
    let locals = &module.signatures[locals_idx];
    let return_ = &module.signatures[return_idx];

    let mut checker = TypeSafetyChecker::new(
        module,
        fn_def_idx,
        type_parameters,
        parameters,
        locals,
        return_,
        ability_cache,
    );

    let jump_tables = &code_unit.jump_tables;
    for block_id in cfg.blocks() {
        for (offset, instr) in cfg.instructions(code, block_id) {
            verify_instr(&mut checker, instr, jump_tables, offset)?;
        }
    }

    Ok(())
}

fn resolve_function_handle<'a>(
    module: &'a AdamantCompiledModule,
    function_definition: &AdamantFunctionDefinition,
) -> &'a adamant_bytecode_format::FunctionHandle {
    let handle_idx = function_definition.function.0 as usize;
    debug_assert!(handle_idx < module.function_handles.len());
    &module.function_handles[handle_idx]
}

/// Top-level per-instruction dispatch. Mirrors upstream's
/// `verify_instr` byte-faithfully; routes to
/// [`verify_inherited_instr`] for inherited Sui-Move bytecode arms
/// and [`verify_adamant_instr`] for Adamant extensions per
/// §6.2.1.4.
fn verify_instr(
    verifier: &mut TypeSafetyChecker<'_, '_>,
    instr: &BytecodeInstruction,
    jump_tables: &[VariantJumpTable],
    offset: CodeOffset,
) -> Result<(), AdamantValidationError> {
    match instr {
        BytecodeInstruction::Inherited(b) => {
            verify_inherited_instr(verifier, b, jump_tables, offset)
        }
        BytecodeInstruction::Adamant(a) => verify_adamant_instr(verifier, a, offset),
    }
}

/// Per-instruction transfer for inherited Sui-Move bytecode.
///
/// Mirrors upstream's `verify_instr` byte-faithfully across all
/// inherited arms: stack/locals, refs, calls, pack/unpack,
/// reads/writes, casts, arithmetic, equality/comparison, vector
/// ops, variant ops. The 10 deprecated global-storage arms hit
/// `unreachable!` (Rule 5 deserializer-enforcement).
#[allow(
    clippy::too_many_lines,
    clippy::match_same_arms,
    reason = "byte-faithful per-instruction table mirroring upstream's `verify_instr`; \
              merging same-result arms would lose the per-instruction audit anchor"
)]
fn verify_inherited_instr(
    verifier: &mut TypeSafetyChecker<'_, '_>,
    bytecode: &Bytecode,
    jump_tables: &[VariantJumpTable],
    offset: CodeOffset,
) -> Result<(), AdamantValidationError> {
    use SignatureToken as ST;
    match bytecode {
        Bytecode::Pop => {
            let operand = verifier.pop();
            let abilities = verifier.abilities(&operand);
            if !abilities.has_drop() {
                return Err(verifier.type_mismatch(offset, TypeMismatchReason::OperandTypeMismatch));
            }
        }

        Bytecode::BrTrue(_) | Bytecode::BrFalse(_) => {
            let operand = verifier.pop();
            if operand != ST::Bool {
                return Err(verifier.type_mismatch(offset, TypeMismatchReason::OperandTypeMismatch));
            }
        }

        Bytecode::StLoc(idx) => {
            let operand = verifier.pop();
            if &operand != verifier.local_at(*idx) {
                return Err(verifier.type_mismatch(offset, TypeMismatchReason::LocalTypeMismatch));
            }
        }

        Bytecode::Abort => {
            let operand = verifier.pop();
            if operand != ST::U64 {
                return Err(verifier.type_mismatch(offset, TypeMismatchReason::OperandTypeMismatch));
            }
        }

        Bytecode::Ret => {
            let return_tokens = verifier.return_.0.clone();
            for return_type in return_tokens.iter().rev() {
                let operand = verifier.pop();
                if &operand != return_type {
                    return Err(verifier.type_mismatch(offset, TypeMismatchReason::RetTypeMismatch));
                }
            }
        }

        Bytecode::Branch(_) | Bytecode::Nop => {}

        Bytecode::FreezeRef => {
            let operand = verifier.pop();
            match operand {
                ST::MutableReference(inner) => verifier.push(ST::Reference(inner)),
                _ => {
                    return Err(verifier.type_mismatch(
                        offset,
                        TypeMismatchReason::FreezeRefRequiresMutableReference,
                    ));
                }
            }
        }

        Bytecode::MutBorrowField(field_handle_index) => borrow_field(
            verifier,
            offset,
            true,
            *field_handle_index,
            &Signature(vec![]),
        )?,

        Bytecode::MutBorrowFieldGeneric(field_inst_index) => {
            let field_inst = &verifier.module.field_instantiations[field_inst_index.0 as usize];
            let type_inst_idx = field_inst.type_parameters.0 as usize;
            let type_inst = verifier.module.signatures[type_inst_idx].clone();
            borrow_field(verifier, offset, true, field_inst.handle, &type_inst)?;
        }

        Bytecode::ImmBorrowField(field_handle_index) => borrow_field(
            verifier,
            offset,
            false,
            *field_handle_index,
            &Signature(vec![]),
        )?,

        Bytecode::ImmBorrowFieldGeneric(field_inst_index) => {
            let field_inst = &verifier.module.field_instantiations[field_inst_index.0 as usize];
            let type_inst_idx = field_inst.type_parameters.0 as usize;
            let type_inst = verifier.module.signatures[type_inst_idx].clone();
            borrow_field(verifier, offset, false, field_inst.handle, &type_inst)?;
        }

        Bytecode::LdU8(_) => verifier.push(ST::U8),
        Bytecode::LdU16(_) => verifier.push(ST::U16),
        Bytecode::LdU32(_) => verifier.push(ST::U32),
        Bytecode::LdU64(_) => verifier.push(ST::U64),
        Bytecode::LdU128(_) => verifier.push(ST::U128),
        Bytecode::LdU256(_) => verifier.push(ST::U256),

        Bytecode::LdConst(idx) => {
            let const_idx = idx.0 as usize;
            debug_assert!(const_idx < verifier.module.constant_pool.len());
            let signature = verifier.module.constant_pool[const_idx].type_.clone();
            verifier.push(signature);
        }

        Bytecode::LdTrue | Bytecode::LdFalse => verifier.push(ST::Bool),

        Bytecode::CopyLoc(idx) => {
            let local_signature = verifier.local_at(*idx).clone();
            if !verifier.abilities(&local_signature).has_copy() {
                return Err(verifier.type_mismatch(offset, TypeMismatchReason::OperandTypeMismatch));
            }
            verifier.push(local_signature);
        }

        Bytecode::MoveLoc(idx) => {
            let local_signature = verifier.local_at(*idx).clone();
            verifier.push(local_signature);
        }

        Bytecode::MutBorrowLoc(idx) => borrow_loc(verifier, offset, true, *idx)?,
        Bytecode::ImmBorrowLoc(idx) => borrow_loc(verifier, offset, false, *idx)?,

        Bytecode::Call(idx) => {
            let handle_idx = idx.0 as usize;
            debug_assert!(handle_idx < verifier.module.function_handles.len());
            let function_handle = verifier.module.function_handles[handle_idx].clone();
            call(verifier, offset, &function_handle, &Signature(vec![]))?;
        }

        Bytecode::CallGeneric(idx) => {
            let inst_idx = idx.0 as usize;
            debug_assert!(inst_idx < verifier.module.function_instantiations.len());
            let func_inst = verifier.module.function_instantiations[inst_idx].clone();
            let handle_idx = func_inst.handle.0 as usize;
            debug_assert!(handle_idx < verifier.module.function_handles.len());
            let func_handle = verifier.module.function_handles[handle_idx].clone();
            let type_args_idx = func_inst.type_parameters.0 as usize;
            debug_assert!(type_args_idx < verifier.module.signatures.len());
            let type_args = verifier.module.signatures[type_args_idx].clone();
            call(verifier, offset, &func_handle, &type_args)?;
        }

        Bytecode::Pack(idx) => {
            let def_idx = idx.0 as usize;
            debug_assert!(def_idx < verifier.module.struct_defs.len());
            let struct_def = verifier.module.struct_defs[def_idx].clone();
            pack_struct(verifier, offset, &struct_def, &Signature(vec![]))?;
        }

        Bytecode::PackGeneric(idx) => {
            let inst_idx = idx.0 as usize;
            debug_assert!(inst_idx < verifier.module.struct_def_instantiations.len());
            let struct_inst = verifier.module.struct_def_instantiations[inst_idx].clone();
            let def_idx = struct_inst.def.0 as usize;
            debug_assert!(def_idx < verifier.module.struct_defs.len());
            let struct_def = verifier.module.struct_defs[def_idx].clone();
            let type_args_idx = struct_inst.type_parameters.0 as usize;
            let type_args = verifier.module.signatures[type_args_idx].clone();
            pack_struct(verifier, offset, &struct_def, &type_args)?;
        }

        Bytecode::Unpack(idx) => {
            let def_idx = idx.0 as usize;
            debug_assert!(def_idx < verifier.module.struct_defs.len());
            let struct_def = verifier.module.struct_defs[def_idx].clone();
            unpack_struct(verifier, offset, &struct_def, &Signature(vec![]))?;
        }

        Bytecode::UnpackGeneric(idx) => {
            let inst_idx = idx.0 as usize;
            debug_assert!(inst_idx < verifier.module.struct_def_instantiations.len());
            let struct_inst = verifier.module.struct_def_instantiations[inst_idx].clone();
            let def_idx = struct_inst.def.0 as usize;
            debug_assert!(def_idx < verifier.module.struct_defs.len());
            let struct_def = verifier.module.struct_defs[def_idx].clone();
            let type_args_idx = struct_inst.type_parameters.0 as usize;
            let type_args = verifier.module.signatures[type_args_idx].clone();
            unpack_struct(verifier, offset, &struct_def, &type_args)?;
        }

        Bytecode::ReadRef => {
            let operand = verifier.pop();
            match operand {
                ST::Reference(inner) | ST::MutableReference(inner) => {
                    if !verifier.abilities(&inner).has_copy() {
                        return Err(
                            verifier.type_mismatch(offset, TypeMismatchReason::OperandTypeMismatch)
                        );
                    }
                    verifier.push(*inner);
                }
                _ => {
                    return Err(
                        verifier.type_mismatch(offset, TypeMismatchReason::ReferenceTypeNotMatched)
                    );
                }
            }
        }

        Bytecode::WriteRef => {
            let ref_operand = verifier.pop();
            let val_operand = verifier.pop();
            let ref_inner_signature = match ref_operand {
                ST::MutableReference(inner) => *inner,
                _ => {
                    return Err(verifier.type_mismatch(
                        offset,
                        TypeMismatchReason::WriteRefRequiresMutableReference,
                    ));
                }
            };
            if !verifier.abilities(&ref_inner_signature).has_drop() {
                return Err(verifier.type_mismatch(offset, TypeMismatchReason::OperandTypeMismatch));
            }
            if val_operand != ref_inner_signature {
                return Err(
                    verifier.type_mismatch(offset, TypeMismatchReason::ReferenceTypeNotMatched)
                );
            }
        }

        Bytecode::CastU8 => {
            let operand = verifier.pop();
            if !is_integer(&operand) {
                return Err(
                    verifier.type_mismatch(offset, TypeMismatchReason::CastTargetTypeInvalid)
                );
            }
            verifier.push(ST::U8);
        }
        Bytecode::CastU16 => {
            let operand = verifier.pop();
            if !is_integer(&operand) {
                return Err(
                    verifier.type_mismatch(offset, TypeMismatchReason::CastTargetTypeInvalid)
                );
            }
            verifier.push(ST::U16);
        }
        Bytecode::CastU32 => {
            let operand = verifier.pop();
            if !is_integer(&operand) {
                return Err(
                    verifier.type_mismatch(offset, TypeMismatchReason::CastTargetTypeInvalid)
                );
            }
            verifier.push(ST::U32);
        }
        Bytecode::CastU64 => {
            let operand = verifier.pop();
            if !is_integer(&operand) {
                return Err(
                    verifier.type_mismatch(offset, TypeMismatchReason::CastTargetTypeInvalid)
                );
            }
            verifier.push(ST::U64);
        }
        Bytecode::CastU128 => {
            let operand = verifier.pop();
            if !is_integer(&operand) {
                return Err(
                    verifier.type_mismatch(offset, TypeMismatchReason::CastTargetTypeInvalid)
                );
            }
            verifier.push(ST::U128);
        }
        Bytecode::CastU256 => {
            let operand = verifier.pop();
            if !is_integer(&operand) {
                return Err(
                    verifier.type_mismatch(offset, TypeMismatchReason::CastTargetTypeInvalid)
                );
            }
            verifier.push(ST::U256);
        }

        Bytecode::Add
        | Bytecode::Sub
        | Bytecode::Mul
        | Bytecode::Mod
        | Bytecode::Div
        | Bytecode::BitOr
        | Bytecode::BitAnd
        | Bytecode::Xor => {
            let operand1 = verifier.pop();
            let operand2 = verifier.pop();
            if is_integer(&operand1) && operand1 == operand2 {
                verifier.push(operand1);
            } else {
                return Err(
                    verifier.type_mismatch(offset, TypeMismatchReason::BinaryOpTypeMismatch)
                );
            }
        }

        Bytecode::Shl | Bytecode::Shr => {
            let operand1 = verifier.pop();
            let operand2 = verifier.pop();
            if is_integer(&operand2) && operand1 == ST::U8 {
                verifier.push(operand2);
            } else {
                return Err(
                    verifier.type_mismatch(offset, TypeMismatchReason::BinaryOpTypeMismatch)
                );
            }
        }

        Bytecode::Or | Bytecode::And => {
            let operand1 = verifier.pop();
            let operand2 = verifier.pop();
            if operand1 == ST::Bool && operand2 == ST::Bool {
                verifier.push(ST::Bool);
            } else {
                return Err(verifier.type_mismatch(offset, TypeMismatchReason::OperandTypeMismatch));
            }
        }

        Bytecode::Not => {
            let operand = verifier.pop();
            if operand == ST::Bool {
                verifier.push(ST::Bool);
            } else {
                return Err(verifier.type_mismatch(offset, TypeMismatchReason::OperandTypeMismatch));
            }
        }

        Bytecode::Eq | Bytecode::Neq => {
            let operand1 = verifier.pop();
            let operand2 = verifier.pop();
            if verifier.abilities(&operand1).has_drop() && operand1 == operand2 {
                verifier.push(ST::Bool);
            } else {
                return Err(
                    verifier.type_mismatch(offset, TypeMismatchReason::EqualityComparisonInvalid)
                );
            }
        }

        Bytecode::Lt | Bytecode::Gt | Bytecode::Le | Bytecode::Ge => {
            let operand1 = verifier.pop();
            let operand2 = verifier.pop();
            if is_integer(&operand1) && operand1 == operand2 {
                verifier.push(ST::Bool);
            } else {
                return Err(
                    verifier.type_mismatch(offset, TypeMismatchReason::BinaryOpTypeMismatch)
                );
            }
        }

        // --- Sub-shape 2 of structural-impossibility-checks
        // (3rd instance at D-5a.1.a closure; rule-of-three for
        // sub-shape 2 specifically met). 10 deprecated global-
        // storage opcodes consolidated into one match arm with
        // one `unreachable!` call site (per-mechanism counting
        // discipline = 1 instance). Rule 5 deserializer-
        // enforcement at parse time inside
        // `AdamantDeserializeError::Bytecode::DeprecatedGlobalStorageOpcode`
        // makes any of these opcodes unreachable in the
        // validator's pipeline.
        Bytecode::MutBorrowGlobalDeprecated(_)
        | Bytecode::MutBorrowGlobalGenericDeprecated(_)
        | Bytecode::ImmBorrowGlobalDeprecated(_)
        | Bytecode::ImmBorrowGlobalGenericDeprecated(_)
        | Bytecode::ExistsDeprecated(_)
        | Bytecode::ExistsGenericDeprecated(_)
        | Bytecode::MoveFromDeprecated(_)
        | Bytecode::MoveFromGenericDeprecated(_)
        | Bytecode::MoveToDeprecated(_)
        | Bytecode::MoveToGenericDeprecated(_) => {
            unreachable!("{DEPRECATED_GLOBAL_STORAGE_THREE_ANCHOR_STEM}. opcode = {bytecode:?}")
        }

        Bytecode::VecPack(idx, num) => {
            let sig_idx = idx.0 as usize;
            debug_assert!(sig_idx < verifier.module.signatures.len());
            let element_type = verifier.module.signatures[sig_idx].0[0].clone();
            if let Some(num_to_pop) = NonZeroU64::new(*num) {
                // `pop_eq_n`'s `ElementNotEqual` is a legitimate
                // type-safety error path here (mirrors upstream
                // line 977-984's `unwrap_or(true)` collapse
                // pattern). Sub-shape 4 structural-impossibility
                // does NOT apply to multi-pop equality checks.
                let matched = verifier
                    .stack
                    .pop_eq_n(num_to_pop)
                    .is_ok_and(|t| element_type == t);
                if !matched {
                    return Err(
                        verifier.type_mismatch(offset, TypeMismatchReason::VecOpTypeMismatch)
                    );
                }
            }
            verifier.push(ST::Vector(Box::new(element_type)));
        }

        Bytecode::VecLen(idx) => {
            let operand = verifier.pop();
            let sig_idx = idx.0 as usize;
            debug_assert!(sig_idx < verifier.module.signatures.len());
            let declared_element_type = verifier.module.signatures[sig_idx].0[0].clone();
            match get_vector_element_type(operand, false) {
                Some(derived_element_type) if derived_element_type == declared_element_type => {
                    verifier.push(ST::U64);
                }
                _ => {
                    return Err(
                        verifier.type_mismatch(offset, TypeMismatchReason::VecOpTypeMismatch)
                    )
                }
            }
        }

        Bytecode::VecImmBorrow(idx) => {
            let sig_idx = idx.0 as usize;
            debug_assert!(sig_idx < verifier.module.signatures.len());
            let declared_element_type = verifier.module.signatures[sig_idx].0[0].clone();
            borrow_vector_element(verifier, &declared_element_type, offset, false)?;
        }

        Bytecode::VecMutBorrow(idx) => {
            let sig_idx = idx.0 as usize;
            debug_assert!(sig_idx < verifier.module.signatures.len());
            let declared_element_type = verifier.module.signatures[sig_idx].0[0].clone();
            borrow_vector_element(verifier, &declared_element_type, offset, true)?;
        }

        Bytecode::VecPushBack(idx) => {
            let operand_elem = verifier.pop();
            let operand_vec = verifier.pop();
            let sig_idx = idx.0 as usize;
            debug_assert!(sig_idx < verifier.module.signatures.len());
            let declared_element_type = verifier.module.signatures[sig_idx].0[0].clone();
            if declared_element_type != operand_elem {
                return Err(verifier.type_mismatch(offset, TypeMismatchReason::VecOpTypeMismatch));
            }
            match get_vector_element_type(operand_vec, true) {
                Some(derived_element_type) if derived_element_type == declared_element_type => {}
                _ => {
                    return Err(
                        verifier.type_mismatch(offset, TypeMismatchReason::VecOpTypeMismatch)
                    )
                }
            }
        }

        Bytecode::VecPopBack(idx) => {
            let operand_vec = verifier.pop();
            let sig_idx = idx.0 as usize;
            debug_assert!(sig_idx < verifier.module.signatures.len());
            let declared_element_type = verifier.module.signatures[sig_idx].0[0].clone();
            match get_vector_element_type(operand_vec, true) {
                Some(derived_element_type) if derived_element_type == declared_element_type => {
                    verifier.push(derived_element_type);
                }
                _ => {
                    return Err(
                        verifier.type_mismatch(offset, TypeMismatchReason::VecOpTypeMismatch)
                    )
                }
            }
        }

        Bytecode::VecUnpack(idx, num) => {
            let operand_vec = verifier.pop();
            let sig_idx = idx.0 as usize;
            debug_assert!(sig_idx < verifier.module.signatures.len());
            let declared_element_type = verifier.module.signatures[sig_idx].0[0].clone();
            let correct_vec_ty =
                matches!(operand_vec, ST::Vector(ref inner) if **inner == declared_element_type);
            if !correct_vec_ty {
                return Err(verifier.type_mismatch(offset, TypeMismatchReason::VecOpTypeMismatch));
            }
            verifier.push_n(declared_element_type, *num);
        }

        Bytecode::VecSwap(idx) => {
            let operand_idx2 = verifier.pop();
            let operand_idx1 = verifier.pop();
            let operand_vec = verifier.pop();
            if operand_idx1 != ST::U64 || operand_idx2 != ST::U64 {
                return Err(verifier.type_mismatch(offset, TypeMismatchReason::VecOpTypeMismatch));
            }
            let sig_idx = idx.0 as usize;
            debug_assert!(sig_idx < verifier.module.signatures.len());
            let declared_element_type = verifier.module.signatures[sig_idx].0[0].clone();
            match get_vector_element_type(operand_vec, true) {
                Some(derived_element_type) if derived_element_type == declared_element_type => {}
                _ => {
                    return Err(
                        verifier.type_mismatch(offset, TypeMismatchReason::VecOpTypeMismatch)
                    )
                }
            }
        }

        Bytecode::PackVariant(vidx) => {
            let h_idx = vidx.0 as usize;
            debug_assert!(h_idx < verifier.module.variant_handles.len());
            let handle = verifier.module.variant_handles[h_idx].clone();
            let enum_idx = handle.enum_def.0 as usize;
            debug_assert!(enum_idx < verifier.module.enum_defs.len());
            let enum_def = verifier.module.enum_defs[enum_idx].clone();
            let variant_def = enum_def.variants[handle.variant as usize].clone();
            pack_enum_variant(
                verifier,
                offset,
                &enum_def,
                &variant_def,
                &Signature(vec![]),
            )?;
        }
        Bytecode::PackVariantGeneric(vidx) => {
            let h_idx = vidx.0 as usize;
            debug_assert!(h_idx < verifier.module.variant_instantiation_handles.len());
            let handle = verifier.module.variant_instantiation_handles[h_idx].clone();
            let inst_idx = handle.enum_def.0 as usize;
            debug_assert!(inst_idx < verifier.module.enum_def_instantiations.len());
            let enum_inst = verifier.module.enum_def_instantiations[inst_idx].clone();
            let type_args_idx = enum_inst.type_parameters.0 as usize;
            let type_args = verifier.module.signatures[type_args_idx].clone();
            let enum_idx = enum_inst.def.0 as usize;
            let enum_def = verifier.module.enum_defs[enum_idx].clone();
            let variant_def = enum_def.variants[handle.variant as usize].clone();
            pack_enum_variant(verifier, offset, &enum_def, &variant_def, &type_args)?;
        }
        Bytecode::UnpackVariant(vidx) => {
            let h_idx = vidx.0 as usize;
            debug_assert!(h_idx < verifier.module.variant_handles.len());
            let handle = verifier.module.variant_handles[h_idx].clone();
            let enum_idx = handle.enum_def.0 as usize;
            let enum_def = verifier.module.enum_defs[enum_idx].clone();
            let variant_def = enum_def.variants[handle.variant as usize].clone();
            unpack_enum_variant_by_value(
                verifier,
                offset,
                &enum_def,
                &variant_def,
                &Signature(vec![]),
            )?;
        }
        Bytecode::UnpackVariantGeneric(vidx) => {
            let h_idx = vidx.0 as usize;
            debug_assert!(h_idx < verifier.module.variant_instantiation_handles.len());
            let handle = verifier.module.variant_instantiation_handles[h_idx].clone();
            let inst_idx = handle.enum_def.0 as usize;
            let enum_inst = verifier.module.enum_def_instantiations[inst_idx].clone();
            let type_args_idx = enum_inst.type_parameters.0 as usize;
            let type_args = verifier.module.signatures[type_args_idx].clone();
            let enum_idx = enum_inst.def.0 as usize;
            let enum_def = verifier.module.enum_defs[enum_idx].clone();
            let variant_def = enum_def.variants[handle.variant as usize].clone();
            unpack_enum_variant_by_value(verifier, offset, &enum_def, &variant_def, &type_args)?;
        }
        Bytecode::UnpackVariantImmRef(vidx) => {
            let h_idx = vidx.0 as usize;
            debug_assert!(h_idx < verifier.module.variant_handles.len());
            let handle = verifier.module.variant_handles[h_idx].clone();
            let enum_idx = handle.enum_def.0 as usize;
            let enum_def = verifier.module.enum_defs[enum_idx].clone();
            let variant_def = enum_def.variants[handle.variant as usize].clone();
            unpack_enum_variant_by_ref(
                verifier,
                offset,
                false,
                &enum_def,
                &variant_def,
                &Signature(vec![]),
            )?;
        }
        Bytecode::UnpackVariantMutRef(vidx) => {
            let h_idx = vidx.0 as usize;
            debug_assert!(h_idx < verifier.module.variant_handles.len());
            let handle = verifier.module.variant_handles[h_idx].clone();
            let enum_idx = handle.enum_def.0 as usize;
            let enum_def = verifier.module.enum_defs[enum_idx].clone();
            let variant_def = enum_def.variants[handle.variant as usize].clone();
            unpack_enum_variant_by_ref(
                verifier,
                offset,
                true,
                &enum_def,
                &variant_def,
                &Signature(vec![]),
            )?;
        }
        Bytecode::UnpackVariantGenericImmRef(vidx) => {
            let h_idx = vidx.0 as usize;
            debug_assert!(h_idx < verifier.module.variant_instantiation_handles.len());
            let handle = verifier.module.variant_instantiation_handles[h_idx].clone();
            let inst_idx = handle.enum_def.0 as usize;
            let enum_inst = verifier.module.enum_def_instantiations[inst_idx].clone();
            let type_args_idx = enum_inst.type_parameters.0 as usize;
            let type_args = verifier.module.signatures[type_args_idx].clone();
            let enum_idx = enum_inst.def.0 as usize;
            let enum_def = verifier.module.enum_defs[enum_idx].clone();
            let variant_def = enum_def.variants[handle.variant as usize].clone();
            unpack_enum_variant_by_ref(
                verifier,
                offset,
                false,
                &enum_def,
                &variant_def,
                &type_args,
            )?;
        }
        Bytecode::UnpackVariantGenericMutRef(vidx) => {
            let h_idx = vidx.0 as usize;
            debug_assert!(h_idx < verifier.module.variant_instantiation_handles.len());
            let handle = verifier.module.variant_instantiation_handles[h_idx].clone();
            let inst_idx = handle.enum_def.0 as usize;
            let enum_inst = verifier.module.enum_def_instantiations[inst_idx].clone();
            let type_args_idx = enum_inst.type_parameters.0 as usize;
            let type_args = verifier.module.signatures[type_args_idx].clone();
            let enum_idx = enum_inst.def.0 as usize;
            let enum_def = verifier.module.enum_defs[enum_idx].clone();
            let variant_def = enum_def.variants[handle.variant as usize].clone();
            unpack_enum_variant_by_ref(
                verifier,
                offset,
                true,
                &enum_def,
                &variant_def,
                &type_args,
            )?;
        }
        Bytecode::VariantSwitch(jti) => {
            let jt_idx = jti.0 as usize;
            debug_assert!(jt_idx < jump_tables.len());
            let jump_table = jump_tables[jt_idx].clone();
            variant_switch(verifier, offset, &jump_table)?;
        }
    }
    Ok(())
}

/// Per-instruction transfer for Adamant extensions per
/// §6.2.1.4 lines 408-423.
///
/// **Category A (11 — static type rules per Sui-Move
/// convention).** Hardcoded per-extension type rules:
/// `Sha3_256` / `Blake3` / `KzgCommit` / `ReleaseSubViewKey`
/// pop `vector<u8>` and push `vector<u8>`; `KzgVerify` /
/// `Ed25519Verify` / `MlDsaVerify65` / `BlsVerify` pop
/// `vector<u8>` × 3 and push `bool`;
/// `ChargeGas` pops `u64`; `RemainingGas` pushes `u64`;
/// `OutOfGas` has no stack effect.
///
/// **Category B (2 — parametric in `FunctionHandle`).**
/// `InvokeShielded` / `InvokeTransparent` reuse the [`call`]
/// helper (per §6.2.1.4 line 408 verbatim).
///
/// **Category C (2 — parametric, deferred to §7).**
/// `GenerateProof` / `VerifyProof` fail open (no pop, no
/// push); runtime carries the type binding via §7's
/// circuit-pool resolution.
///
/// **Category D (1 — parametric, deferred to §8.5).**
/// `RecursiveVerify` fails open; runtime carries the binding.
#[allow(
    clippy::match_same_arms,
    reason = "Cat A `vector<u8>` → `vector<u8>` arms (Sha3_256 / Blake3 / KzgCommit / \
              ReleaseSubViewKey) share an implementation but are distinct per-extension audit \
              anchors against §6.2.1.4 lines 412-417"
)]
fn verify_adamant_instr(
    verifier: &mut TypeSafetyChecker<'_, '_>,
    instr: &AdamantBytecode,
    offset: CodeOffset,
) -> Result<(), AdamantValidationError> {
    use SignatureToken as ST;
    let vec_u8 = || ST::Vector(Box::new(ST::U8));

    match instr {
        // Category B: parametric in FunctionHandle (same shape
        // as Call per §6.2.1.4 line 408 verbatim). Spec-text-
        // to-shared-helper canonical principle 1st instance.
        AdamantBytecode::InvokeShielded(idx) | AdamantBytecode::InvokeTransparent(idx) => {
            let handle_idx = idx.0 as usize;
            debug_assert!(handle_idx < verifier.module.function_handles.len());
            let function_handle = verifier.module.function_handles[handle_idx].clone();
            call(verifier, offset, &function_handle, &Signature(vec![]))?;
        }

        // Category C (GenerateProof / VerifyProof) and Category
        // D (RecursiveVerify) both fail open per §6.2.1.4 lines
        // 410-411 (deferred to §7) and line 415 (deferred to
        // §8.5). Same shielding-vs-runtime canonical pattern;
        // identical body but distinct audit anchors against
        // their respective spec lines.
        AdamantBytecode::GenerateProof(_)
        | AdamantBytecode::VerifyProof(_)
        | AdamantBytecode::RecursiveVerify => {}

        // Category A static (pop, push) type rules per
        // §6.2.1.4 lines 412-423 verbatim. Hashes (Sha3_256,
        // Blake3) and KZG-commit and ReleaseSubViewKey share a
        // `vector<u8>` → `vector<u8>` shape; arms kept distinct
        // for per-extension audit anchor.
        AdamantBytecode::Sha3_256
        | AdamantBytecode::Blake3
        | AdamantBytecode::KzgCommit
        | AdamantBytecode::ReleaseSubViewKey => {
            let operand = verifier.pop();
            if operand != vec_u8() {
                return Err(verifier.type_mismatch(offset, TypeMismatchReason::OperandTypeMismatch));
            }
            verifier.push(vec_u8());
        }

        AdamantBytecode::KzgVerify
        | AdamantBytecode::Ed25519Verify
        | AdamantBytecode::MlDsaVerify65
        | AdamantBytecode::BlsVerify => {
            // Three vector<u8> operands; spec orders pops:
            // sig (top), msg, pk (bottom) — but for type-
            // checking the order is symmetric since all three
            // are vector<u8>. We pop in stack order and check
            // each.
            for _ in 0..3 {
                let operand = verifier.pop();
                if operand != vec_u8() {
                    return Err(
                        verifier.type_mismatch(offset, TypeMismatchReason::OperandTypeMismatch)
                    );
                }
            }
            verifier.push(ST::Bool);
        }

        AdamantBytecode::ChargeGas(_) => {
            let operand = verifier.pop();
            if operand != ST::U64 {
                return Err(verifier.type_mismatch(offset, TypeMismatchReason::OperandTypeMismatch));
            }
        }

        AdamantBytecode::RemainingGas(_) => {
            verifier.push(ST::U64);
        }

        // OutOfGas aborts the transaction at runtime per §6.2.1.4
        // line 423; verifier sees no stack effect.
        AdamantBytecode::OutOfGas => {}

        // ML-KEM-768 per §6.2.1.4 lines 419-420.
        AdamantBytecode::MlKemEncapsulate => {
            // Pop pubkey (vector<u8>); push (ciphertext, ss) as two
            // vector<u8> values.
            let operand = verifier.pop();
            if operand != vec_u8() {
                return Err(verifier.type_mismatch(offset, TypeMismatchReason::OperandTypeMismatch));
            }
            verifier.push(vec_u8());
            verifier.push(vec_u8());
        }
        AdamantBytecode::MlKemDecapsulate => {
            // Pop ct (top), sk (bottom); push ss as vector<u8>.
            for _ in 0..2 {
                let operand = verifier.pop();
                if operand != vec_u8() {
                    return Err(
                        verifier.type_mismatch(offset, TypeMismatchReason::OperandTypeMismatch)
                    );
                }
            }
            verifier.push(vec_u8());
        }
    }
    Ok(())
}

// ===========================================================
// Helpers — byte-faithful mirrors of upstream
// `vendor/move-bytecode-verifier/src/type_safety.rs` helpers,
// adapted for Adamant's no-meter posture and infallible
// instantiate / materialize_type signatures.
// ===========================================================

/// Helper for both `ImmBorrowField` and `MutBorrowField`. Pops a
/// reference, checks it points to the expected struct type, and
/// pushes a reference to the field's type.
fn borrow_field(
    verifier: &mut TypeSafetyChecker<'_, '_>,
    offset: CodeOffset,
    mut_: bool,
    field_handle_index: FieldHandleIndex,
    type_args: &Signature,
) -> Result<(), AdamantValidationError> {
    use SignatureToken as ST;
    let operand = verifier.pop();
    if mut_ && !operand.is_mutable_reference() {
        return Err(verifier.type_mismatch(offset, TypeMismatchReason::BorrowFieldTypeMismatch));
    }

    let fh_idx = field_handle_index.0 as usize;
    debug_assert!(fh_idx < verifier.module.field_handles.len());
    let field_handle = verifier.module.field_handles[fh_idx].clone();
    let owner_idx = field_handle.owner.0 as usize;
    debug_assert!(owner_idx < verifier.module.struct_defs.len());
    let struct_def = verifier.module.struct_defs[owner_idx].clone();
    let expected_type = materialize_type(struct_def.struct_handle, type_args);
    let inner_match = match operand {
        ST::Reference(ref inner) | ST::MutableReference(ref inner) => **inner == expected_type,
        _ => false,
    };
    if !inner_match {
        return Err(verifier.type_mismatch(offset, TypeMismatchReason::BorrowFieldTypeMismatch));
    }

    let field_def = match &struct_def.field_information {
        StructFieldInformation::Native => {
            // Native struct has no exposed fields; upstream
            // returns BORROWFIELD_BAD_FIELD_ERROR. Adamant
            // consolidates into BorrowFieldTypeMismatch.
            return Err(verifier.type_mismatch(offset, TypeMismatchReason::BorrowFieldTypeMismatch));
        }
        StructFieldInformation::Declared(fields) => &fields[field_handle.field as usize],
    };
    let field_type = Box::new(instantiate(&field_def.signature.0, type_args));
    verifier.push(if mut_ {
        ST::MutableReference(field_type)
    } else {
        ST::Reference(field_type)
    });
    Ok(())
}

/// Helper for both `ImmBorrowLoc` and `MutBorrowLoc`. Pushes a
/// reference to the local at `idx`. Local must not itself be a
/// reference (no references-to-references).
fn borrow_loc(
    verifier: &mut TypeSafetyChecker<'_, '_>,
    offset: CodeOffset,
    mut_: bool,
    idx: LocalIndex,
) -> Result<(), AdamantValidationError> {
    use SignatureToken as ST;
    let loc_signature = verifier.local_at(idx).clone();
    if loc_signature.is_reference() {
        return Err(verifier.type_mismatch(offset, TypeMismatchReason::BorrowFieldTypeMismatch));
    }
    verifier.push(if mut_ {
        ST::MutableReference(Box::new(loc_signature))
    } else {
        ST::Reference(Box::new(loc_signature))
    });
    Ok(())
}

/// Helper for `Call` / `CallGeneric` / `InvokeShielded` /
/// `InvokeTransparent`. Pops one operand per parameter (in
/// reverse declaration order — top of stack is the last
/// parameter), type-checks each, then pushes one operand per
/// return value.
///
/// Spec-text-to-shared-helper canonical principle: §6.2.1.4
/// line 408 says "the verifier...treat reference inputs and
/// outputs of `InvokeShielded` exactly as they would for an
/// inherited `Call`" — same helper across 4 call sites.
fn call(
    verifier: &mut TypeSafetyChecker<'_, '_>,
    offset: CodeOffset,
    function_handle: &adamant_bytecode_format::FunctionHandle,
    type_actuals: &Signature,
) -> Result<(), AdamantValidationError> {
    let parameters_idx = function_handle.parameters.0 as usize;
    debug_assert!(parameters_idx < verifier.module.signatures.len());
    let parameters = verifier.module.signatures[parameters_idx].clone();
    for parameter in parameters.0.iter().rev() {
        let arg = verifier.pop();
        let expected = if type_actuals.0.is_empty() {
            parameter.clone()
        } else {
            instantiate(parameter, type_actuals)
        };
        if arg != expected {
            return Err(verifier.type_mismatch(offset, TypeMismatchReason::WrongFunctionSignature));
        }
    }
    let return_idx = function_handle.return_.0 as usize;
    debug_assert!(return_idx < verifier.module.signatures.len());
    let returns = verifier.module.signatures[return_idx].clone();
    for return_type in &returns.0 {
        let sig = instantiate(return_type, type_actuals);
        verifier.push(sig);
    }
    Ok(())
}

/// Compute the field-signature list for a struct definition,
/// instantiated against `type_args` if generic.
fn type_fields_signature(
    verifier: &mut TypeSafetyChecker<'_, '_>,
    offset: CodeOffset,
    struct_def: &StructDefinition,
    type_args: &Signature,
) -> Result<Signature, AdamantValidationError> {
    match &struct_def.field_information {
        StructFieldInformation::Native => {
            // Upstream marks this as "TODO: this is more of
            // 'unreachable'"; native structs have no declared
            // fields exposed to Pack/Unpack. Adamant returns
            // WrongPackUnpackType for the same condition.
            Err(verifier.type_mismatch(offset, TypeMismatchReason::WrongPackUnpackType))
        }
        StructFieldInformation::Declared(fields) => {
            let field_sig = fields
                .iter()
                .map(|field_def| instantiate(&field_def.signature.0, type_args))
                .collect();
            Ok(Signature(field_sig))
        }
    }
}

/// Pack a struct: pop one operand per field (reverse field
/// order), type-check each against the field type, push the
/// struct value.
fn pack_struct(
    verifier: &mut TypeSafetyChecker<'_, '_>,
    offset: CodeOffset,
    struct_def: &StructDefinition,
    type_args: &Signature,
) -> Result<(), AdamantValidationError> {
    let field_sig = type_fields_signature(verifier, offset, struct_def, type_args)?;
    for sig in field_sig.0.iter().rev() {
        let arg = verifier.pop();
        if &arg != sig {
            return Err(verifier.type_mismatch(offset, TypeMismatchReason::WrongPackUnpackType));
        }
    }
    let struct_type = materialize_type(struct_def.struct_handle, type_args);
    verifier.push(struct_type);
    Ok(())
}

/// Unpack a struct: pop the struct value, type-check it, push
/// one operand per field (forward field order).
fn unpack_struct(
    verifier: &mut TypeSafetyChecker<'_, '_>,
    offset: CodeOffset,
    struct_def: &StructDefinition,
    type_args: &Signature,
) -> Result<(), AdamantValidationError> {
    let struct_type = materialize_type(struct_def.struct_handle, type_args);
    let arg = verifier.pop();
    if arg != struct_type {
        return Err(verifier.type_mismatch(offset, TypeMismatchReason::WrongPackUnpackType));
    }
    let field_sig = type_fields_signature(verifier, offset, struct_def, type_args)?;
    for sig in field_sig.0 {
        verifier.push(sig);
    }
    Ok(())
}

/// Pack an enum variant: pop one operand per field, type-check,
/// push the enum value.
fn pack_enum_variant(
    verifier: &mut TypeSafetyChecker<'_, '_>,
    offset: CodeOffset,
    enum_def: &adamant_bytecode_format::EnumDefinition,
    variant_def: &adamant_bytecode_format::VariantDefinition,
    type_args: &Signature,
) -> Result<(), AdamantValidationError> {
    for field_def in variant_def.fields.iter().rev() {
        let sig = instantiate(&field_def.signature.0, type_args);
        let arg = verifier.pop();
        if arg != sig {
            return Err(verifier.type_mismatch(offset, TypeMismatchReason::WrongPackUnpackType));
        }
    }
    let enum_type = materialize_type(enum_def.enum_handle, type_args);
    verifier.push(enum_type);
    Ok(())
}

/// Unpack an enum variant by value: pop the enum value, type-
/// check, push one operand per field.
fn unpack_enum_variant_by_value(
    verifier: &mut TypeSafetyChecker<'_, '_>,
    offset: CodeOffset,
    enum_def: &adamant_bytecode_format::EnumDefinition,
    variant_def: &adamant_bytecode_format::VariantDefinition,
    type_args: &Signature,
) -> Result<(), AdamantValidationError> {
    let enum_type = materialize_type(enum_def.enum_handle, type_args);
    let arg = verifier.pop();
    if arg != enum_type {
        return Err(verifier.type_mismatch(offset, TypeMismatchReason::WrongPackUnpackType));
    }
    for field_def in &variant_def.fields {
        let sig = instantiate(&field_def.signature.0, type_args);
        verifier.push(sig);
    }
    Ok(())
}

/// Unpack an enum variant by reference: pop a reference to the
/// enum, type-check (mutability matches), push references to
/// each field.
fn unpack_enum_variant_by_ref(
    verifier: &mut TypeSafetyChecker<'_, '_>,
    offset: CodeOffset,
    mut_: bool,
    enum_def: &adamant_bytecode_format::EnumDefinition,
    variant_def: &adamant_bytecode_format::VariantDefinition,
    type_args: &Signature,
) -> Result<(), AdamantValidationError> {
    use SignatureToken as ST;
    let arg = verifier.pop();
    let ((ST::Reference(inner), false) | (ST::MutableReference(inner), true)) = (arg, mut_) else {
        return Err(verifier.type_mismatch(offset, TypeMismatchReason::WrongPackUnpackType));
    };
    let enum_type = materialize_type(enum_def.enum_handle, type_args);
    if *inner != enum_type {
        return Err(verifier.type_mismatch(offset, TypeMismatchReason::WrongPackUnpackType));
    }
    for field_def in &variant_def.fields {
        let sig = instantiate(&field_def.signature.0, type_args);
        let pushed = if mut_ {
            ST::MutableReference(Box::new(sig))
        } else {
            ST::Reference(Box::new(sig))
        };
        verifier.push(pushed);
    }
    Ok(())
}

/// Verify a `VariantSwitch`: top-of-stack must be an immutable
/// reference to the jump table's head enum; jump-table size
/// must equal the enum's variant count (cardinality check =
/// exhaustivity guarantee).
fn variant_switch(
    verifier: &mut TypeSafetyChecker<'_, '_>,
    offset: CodeOffset,
    jump_table: &VariantJumpTable,
) -> Result<(), AdamantValidationError> {
    use SignatureToken as ST;
    let operand = verifier.pop();
    let ST::Reference(inner_type) = operand else {
        return Err(verifier.type_mismatch(offset, TypeMismatchReason::VariantSwitchTypeMismatch));
    };
    let handle = match *inner_type {
        ST::Datatype(handle) => handle,
        ST::DatatypeInstantiation(inst) => inst.0,
        _ => {
            return Err(
                verifier.type_mismatch(offset, TypeMismatchReason::VariantSwitchTypeMismatch)
            );
        }
    };
    let enum_idx = jump_table.head_enum.0 as usize;
    debug_assert!(enum_idx < verifier.module.enum_defs.len());
    let enum_def = &verifier.module.enum_defs[enum_idx];
    if handle != enum_def.enum_handle {
        return Err(verifier.type_mismatch(offset, TypeMismatchReason::VariantSwitchTypeMismatch));
    }
    let JumpTableInner::Full(jt) = &jump_table.jump_table;
    if jt.len() != enum_def.variants.len() {
        return Err(verifier.type_mismatch(offset, TypeMismatchReason::VariantSwitchTypeMismatch));
    }
    Ok(())
}

/// Helper for `VecImmBorrow` and `VecMutBorrow`. Pops the index
/// (must be `u64`) and the vector reference; pushes a reference
/// to the element type.
fn borrow_vector_element(
    verifier: &mut TypeSafetyChecker<'_, '_>,
    declared_element_type: &SignatureToken,
    offset: CodeOffset,
    mut_ref_only: bool,
) -> Result<(), AdamantValidationError> {
    use SignatureToken as ST;
    let operand_idx = verifier.pop();
    let operand_vec = verifier.pop();
    if operand_idx != ST::U64 {
        return Err(verifier.type_mismatch(offset, TypeMismatchReason::VecOpTypeMismatch));
    }
    let element_type = match get_vector_element_type(operand_vec, mut_ref_only) {
        Some(ty) if &ty == declared_element_type => ty,
        _ => return Err(verifier.type_mismatch(offset, TypeMismatchReason::VecOpTypeMismatch)),
    };
    let element_ref_type = if mut_ref_only {
        ST::MutableReference(Box::new(element_type))
    } else {
        ST::Reference(Box::new(element_type))
    };
    verifier.push(element_ref_type);
    Ok(())
}

/// Materialize a struct/enum type token from its handle and
/// type arguments. `type_args` empty → bare `Datatype`; non-
/// empty → `DatatypeInstantiation`.
fn materialize_type(
    struct_handle: adamant_bytecode_format::DatatypeHandleIndex,
    type_args: &Signature,
) -> SignatureToken {
    if type_args.0.is_empty() {
        SignatureToken::Datatype(struct_handle)
    } else {
        SignatureToken::DatatypeInstantiation(Box::new((struct_handle, type_args.0.clone())))
    }
}

/// Recursively substitute type parameters in `token` with the
/// corresponding tokens in `subst`. Mirrors upstream's
/// `instantiate` byte-faithfully without metering. Infallible
/// in the Adamant pipeline because `bounds_checker` validates
/// type-parameter indices at step 3.
fn instantiate(token: &SignatureToken, subst: &Signature) -> SignatureToken {
    use SignatureToken as ST;
    if subst.0.is_empty() {
        return token.clone();
    }
    match token {
        ST::Bool => ST::Bool,
        ST::U8 => ST::U8,
        ST::U16 => ST::U16,
        ST::U32 => ST::U32,
        ST::U64 => ST::U64,
        ST::U128 => ST::U128,
        ST::U256 => ST::U256,
        ST::Address => ST::Address,
        ST::Signer => ST::Signer,
        ST::Vector(ty) => ST::Vector(Box::new(instantiate(ty, subst))),
        ST::Datatype(idx) => ST::Datatype(*idx),
        ST::DatatypeInstantiation(inst) => {
            let (idx, type_args) = &**inst;
            ST::DatatypeInstantiation(Box::new((
                *idx,
                type_args.iter().map(|ty| instantiate(ty, subst)).collect(),
            )))
        }
        ST::Reference(ty) => ST::Reference(Box::new(instantiate(ty, subst))),
        ST::MutableReference(ty) => ST::MutableReference(Box::new(instantiate(ty, subst))),
        ST::TypeParameter(idx) => {
            debug_assert!(
                (*idx as usize) < subst.0.len(),
                "TypeParameter index out of bounds; bounds_checker should validate at step 3"
            );
            subst.0[*idx as usize].clone()
        }
    }
}

/// Returns `true` if `t` is one of the integer types
/// (`U8`, `U16`, `U32`, `U64`, `U128`, `U256`). Mirrors
/// `move_binary_format::SignatureToken::is_integer` byte-
/// faithfully.
fn is_integer(t: &SignatureToken) -> bool {
    matches!(
        t,
        SignatureToken::U8
            | SignatureToken::U16
            | SignatureToken::U32
            | SignatureToken::U64
            | SignatureToken::U128
            | SignatureToken::U256
    )
}

/// Extract the element type from a vector reference. Returns
/// `None` if the operand is not a vector reference of the
/// requested mutability. Mirrors upstream's
/// `get_vector_element_type` byte-faithfully.
fn get_vector_element_type(
    vector_ref_ty: SignatureToken,
    mut_ref_only: bool,
) -> Option<SignatureToken> {
    use SignatureToken as ST;
    match vector_ref_ty {
        ST::Reference(referred_type) => {
            if mut_ref_only {
                None
            } else if let ST::Vector(element_type) = *referred_type {
                Some(*element_type)
            } else {
                None
            }
        }
        ST::MutableReference(referred_type) => {
            if let ST::Vector(element_type) = *referred_type {
                Some(*element_type)
            } else {
                None
            }
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    //! Layer A unit tests for the type-safety pass at D-5a.1.b.
    //!
    //! Tests invoke [`verify_function`] directly. The orchestration
    //! chain wire-in landing in [`super::super::verify_function_bodies`]
    //! at this same commit does NOT affect these tests since they
    //! bypass the orchestration.
    //!
    //! Coverage at D-5a.1.b closure:
    //! - Inherited bytecode arms (full coverage; D-5a.1.a +
    //!   D-5a.1.b combined).
    //! - 17 Adamant-extension type-rule pins (Cat A static,
    //!   Cat B parametric-FH happy path, Cat C/D fail-open).
    //! - Variant-vs-test mapping audit closure for all 14
    //!   `TypeMismatchReason` sub-reasons (6 at D-5a.1.a + 8 at
    //!   D-5a.1.b = 14 declared at D-5a.0).
    //! - Eager-error semantics (per-instruction first-failure).
    //! - Structural-impossibility `unreachable!` for the
    //!   deprecated global-storage arm (`#[should_panic]`).

    use super::*;
    use crate::bytecode::{AdamantBytecode, BytecodeInstruction, CircuitId, GasDimension};
    use crate::module::{AdamantCodeUnit, AdamantCompiledModule, AdamantFunctionDefinition};
    use crate::validator::module_pass::ability_cache::AdamantAbilityCache;
    use adamant_bytecode_format::{
        Ability, AbilitySet, AddressIdentifierIndex, Constant, ConstantPoolIndex, DatatypeHandle,
        DatatypeHandleIndex, EnumDefinition, EnumDefinitionIndex, FieldDefinition, FieldHandle,
        FieldHandleIndex, FieldInstantiation, FieldInstantiationIndex, FunctionHandle,
        FunctionHandleIndex, FunctionInstantiation, FunctionInstantiationIndex, Identifier,
        IdentifierIndex, JumpTableInner, ModuleHandle, ModuleHandleIndex, Signature,
        SignatureIndex, SignatureToken, StructDefInstantiation, StructDefInstantiationIndex,
        StructDefinition, StructDefinitionIndex, StructFieldInformation, TypeSignature,
        VariantDefinition, VariantHandle, VariantHandleIndex, VariantInstantiationHandle,
        VariantInstantiationHandleIndex, VariantJumpTable, VariantJumpTableIndex, Visibility,
    };

    // --- builders ---

    fn ld_u8(v: u8) -> BytecodeInstruction {
        BytecodeInstruction::Inherited(Bytecode::LdU8(v))
    }

    fn ld_u64(v: u64) -> BytecodeInstruction {
        BytecodeInstruction::Inherited(Bytecode::LdU64(v))
    }

    fn ld_true() -> BytecodeInstruction {
        BytecodeInstruction::Inherited(Bytecode::LdTrue)
    }

    fn pop() -> BytecodeInstruction {
        BytecodeInstruction::Inherited(Bytecode::Pop)
    }

    fn ret() -> BytecodeInstruction {
        BytecodeInstruction::Inherited(Bytecode::Ret)
    }

    fn add() -> BytecodeInstruction {
        BytecodeInstruction::Inherited(Bytecode::Add)
    }

    fn eq() -> BytecodeInstruction {
        BytecodeInstruction::Inherited(Bytecode::Eq)
    }

    fn cast_u8() -> BytecodeInstruction {
        BytecodeInstruction::Inherited(Bytecode::CastU8)
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

    fn extension(a: AdamantBytecode) -> BytecodeInstruction {
        BytecodeInstruction::Adamant(a)
    }

    fn module_with_function(
        param_tokens: Vec<SignatureToken>,
        local_tokens: Vec<SignatureToken>,
        return_tokens: Vec<SignatureToken>,
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
        m.signatures.push(Signature(return_tokens)); // 2 -> returns
        m.function_handles.push(FunctionHandle {
            module: ModuleHandleIndex(0),
            name: IdentifierIndex(0),
            parameters: SignatureIndex(0),
            return_: SignatureIndex(2),
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
        let mut cache = AdamantAbilityCache::new(m);
        verify_function(
            m,
            FunctionDefinitionIndex::new(0),
            function_definition,
            &code_unit.code,
            &cfg,
            &mut cache,
        )
    }

    /// Add a non-drop datatype to the module; returns the
    /// `SignatureToken` referring to it.
    fn add_non_drop_datatype(m: &mut AdamantCompiledModule) -> SignatureToken {
        let handle_idx =
            u16::try_from(m.datatype_handles.len()).expect("test fixture handle count fits u16");
        m.identifiers.push(Identifier::new("S").unwrap());
        let name_idx =
            u16::try_from(m.identifiers.len() - 1).expect("test fixture identifier count fits u16");
        m.datatype_handles.push(DatatypeHandle {
            module: ModuleHandleIndex(0),
            name: IdentifierIndex(name_idx),
            abilities: AbilitySet::EMPTY | Ability::Key,
            type_parameters: vec![],
        });
        SignatureToken::Datatype(DatatypeHandleIndex(handle_idx))
    }

    /// Add a struct with one declared u64 field. Returns the
    /// (struct token, `struct_def_index`, `field_handle_index`).
    fn add_simple_struct(
        m: &mut AdamantCompiledModule,
    ) -> (SignatureToken, StructDefinitionIndex, FieldHandleIndex) {
        let dt_idx = u16::try_from(m.datatype_handles.len()).unwrap();
        m.identifiers.push(Identifier::new("S").unwrap());
        let name_id = u16::try_from(m.identifiers.len() - 1).unwrap();
        m.datatype_handles.push(DatatypeHandle {
            module: ModuleHandleIndex(0),
            name: IdentifierIndex(name_id),
            abilities: AbilitySet::EMPTY | Ability::Drop | Ability::Copy,
            type_parameters: vec![],
        });
        m.identifiers.push(Identifier::new("x").unwrap());
        let field_name_id = u16::try_from(m.identifiers.len() - 1).unwrap();
        let def_idx = u16::try_from(m.struct_defs.len()).unwrap();
        m.struct_defs.push(StructDefinition {
            struct_handle: DatatypeHandleIndex(dt_idx),
            field_information: StructFieldInformation::Declared(vec![FieldDefinition {
                name: IdentifierIndex(field_name_id),
                signature: TypeSignature(SignatureToken::U64),
            }]),
        });
        let fh_idx = u16::try_from(m.field_handles.len()).unwrap();
        m.field_handles.push(FieldHandle {
            owner: StructDefinitionIndex(def_idx),
            field: 0,
        });
        (
            SignatureToken::Datatype(DatatypeHandleIndex(dt_idx)),
            StructDefinitionIndex(def_idx),
            FieldHandleIndex(fh_idx),
        )
    }

    /// Add a function handle with given param/return signatures.
    /// Returns the `FunctionHandleIndex`.
    fn add_function_handle(
        m: &mut AdamantCompiledModule,
        params: Vec<SignatureToken>,
        returns: Vec<SignatureToken>,
    ) -> FunctionHandleIndex {
        m.identifiers.push(Identifier::new("g").unwrap());
        let name_id = u16::try_from(m.identifiers.len() - 1).unwrap();
        let p_idx = u16::try_from(m.signatures.len()).unwrap();
        m.signatures.push(Signature(params));
        let r_idx = u16::try_from(m.signatures.len()).unwrap();
        m.signatures.push(Signature(returns));
        let h_idx = u16::try_from(m.function_handles.len()).unwrap();
        m.function_handles.push(FunctionHandle {
            module: ModuleHandleIndex(0),
            name: IdentifierIndex(name_id),
            parameters: SignatureIndex(p_idx),
            return_: SignatureIndex(r_idx),
            type_parameters: vec![],
        });
        FunctionHandleIndex(h_idx)
    }

    // ===========================================================
    // D-5a.1.a smoke regression — ensure first-half arms still
    // accept after the rewrite.
    // ===========================================================

    #[test]
    fn ld_const_pushes_correct_type() {
        let mut m = module_with_function(vec![], vec![], vec![], vec![ret()]);
        m.constant_pool.push(Constant {
            type_: SignatureToken::U64,
            data: vec![0u8; 8],
        });
        m.function_defs[0].code = Some(AdamantCodeUnit {
            locals: SignatureIndex(1),
            code: vec![
                BytecodeInstruction::Inherited(Bytecode::LdConst(ConstantPoolIndex(0))),
                pop(),
                ret(),
            ],
            jump_tables: vec![],
        });
        run(&m).expect("LdConst pushes the constant's declared type");
    }

    #[test]
    fn add_on_u64_pushes_u64() {
        let m = module_with_function(
            vec![],
            vec![],
            vec![SignatureToken::U64],
            vec![ld_u64(1), ld_u64(2), add(), ret()],
        );
        run(&m).expect("Add on u64 operands pushes u64");
    }

    #[test]
    fn ret_with_matching_return_type() {
        let m = module_with_function(
            vec![],
            vec![],
            vec![SignatureToken::U64],
            vec![ld_u64(1), ret()],
        );
        run(&m).expect("Ret with matching return type OK");
    }

    // --- D-5a.1.a audit closures (regression) ---

    #[test]
    fn br_true_on_non_bool_rejected_operand_type_mismatch() {
        let m = module_with_function(
            vec![],
            vec![],
            vec![],
            vec![
                ld_u64(0),
                BytecodeInstruction::Inherited(Bytecode::BrTrue(2)),
                ret(),
                ret(),
            ],
        );
        match run(&m) {
            Err(AdamantValidationError::TypeMismatch {
                reason: TypeMismatchReason::OperandTypeMismatch,
                ..
            }) => {}
            other => panic!("expected OperandTypeMismatch, got {other:?}"),
        }
    }

    #[test]
    fn eq_on_non_droppable_type_rejected() {
        let mut m = module_with_function(vec![], vec![], vec![], vec![ret()]);
        let s_token = add_non_drop_datatype(&mut m);
        m.signatures[0] = Signature(vec![s_token.clone(), s_token.clone()]);
        m.function_defs[0].code = Some(AdamantCodeUnit {
            locals: SignatureIndex(1),
            code: vec![mv_loc(0), mv_loc(1), eq(), pop(), ret()],
            jump_tables: vec![],
        });
        match run(&m) {
            Err(AdamantValidationError::TypeMismatch {
                reason: TypeMismatchReason::EqualityComparisonInvalid,
                ..
            }) => {}
            other => panic!("expected EqualityComparisonInvalid, got {other:?}"),
        }
    }

    #[test]
    fn cast_to_u8_on_bool_rejected() {
        let m = module_with_function(
            vec![],
            vec![],
            vec![SignatureToken::U8],
            vec![ld_true(), cast_u8(), ret()],
        );
        match run(&m) {
            Err(AdamantValidationError::TypeMismatch {
                reason: TypeMismatchReason::CastTargetTypeInvalid,
                ..
            }) => {}
            other => panic!("expected CastTargetTypeInvalid, got {other:?}"),
        }
    }

    #[test]
    fn add_with_mismatched_int_widths_rejected() {
        let m = module_with_function(
            vec![],
            vec![],
            vec![SignatureToken::U64],
            vec![ld_u8(1), ld_u64(2), add(), ret()],
        );
        match run(&m) {
            Err(AdamantValidationError::TypeMismatch {
                reason: TypeMismatchReason::BinaryOpTypeMismatch,
                ..
            }) => {}
            other => panic!("expected BinaryOpTypeMismatch, got {other:?}"),
        }
    }

    #[test]
    fn ret_with_wrong_return_type_rejected() {
        let m = module_with_function(
            vec![],
            vec![],
            vec![SignatureToken::U64],
            vec![ld_true(), ret()],
        );
        match run(&m) {
            Err(AdamantValidationError::TypeMismatch {
                reason: TypeMismatchReason::RetTypeMismatch,
                ..
            }) => {}
            other => panic!("expected RetTypeMismatch, got {other:?}"),
        }
    }

    #[test]
    fn st_loc_wrong_value_type_rejected() {
        let m = module_with_function(
            vec![],
            vec![SignatureToken::U64],
            vec![],
            vec![ld_true(), st_loc(0), ret()],
        );
        match run(&m) {
            Err(AdamantValidationError::TypeMismatch {
                reason: TypeMismatchReason::LocalTypeMismatch,
                ..
            }) => {}
            other => panic!("expected LocalTypeMismatch, got {other:?}"),
        }
    }

    // --- structural-impossibility unreachable! for deprecated
    // global-storage arm (regression from D-5a.1.a) ---

    #[test]
    #[should_panic(expected = "Rule 5 deserializer-enforcement")]
    fn deprecated_global_storage_panics_with_three_anchor() {
        let m = module_with_function(
            vec![SignatureToken::Address],
            vec![],
            vec![],
            vec![
                mv_loc(0),
                BytecodeInstruction::Inherited(Bytecode::ExistsDeprecated(StructDefinitionIndex(
                    0,
                ))),
                pop(),
                ret(),
            ],
        );
        let _ = run(&m);
    }

    // ===========================================================
    // D-5a.1.b: 8 of 14 TypeMismatchReason audit closures
    // ===========================================================

    /// `WrongFunctionSignature` audit pin: Call with arg type
    /// not matching parameter type.
    #[test]
    fn call_with_wrong_arg_type_rejected() {
        let mut m = module_with_function(vec![], vec![], vec![], vec![ret()]);
        let h = add_function_handle(&mut m, vec![SignatureToken::U64], vec![]);
        m.function_defs[0].code = Some(AdamantCodeUnit {
            locals: SignatureIndex(1),
            code: vec![
                ld_true(),
                BytecodeInstruction::Inherited(Bytecode::Call(h)),
                ret(),
            ],
            jump_tables: vec![],
        });
        match run(&m) {
            Err(AdamantValidationError::TypeMismatch {
                reason: TypeMismatchReason::WrongFunctionSignature,
                ..
            }) => {}
            other => panic!("expected WrongFunctionSignature, got {other:?}"),
        }
    }

    /// `WrongPackUnpackType` audit pin: Pack with wrong field
    /// type on stack.
    #[test]
    fn pack_with_wrong_field_type_rejected() {
        let mut m = module_with_function(vec![], vec![], vec![], vec![ret()]);
        let (_s_token, def_idx, _fh_idx) = add_simple_struct(&mut m);
        m.function_defs[0].code = Some(AdamantCodeUnit {
            locals: SignatureIndex(1),
            code: vec![
                ld_true(), // Pack expects U64
                BytecodeInstruction::Inherited(Bytecode::Pack(def_idx)),
                pop(),
                ret(),
            ],
            jump_tables: vec![],
        });
        match run(&m) {
            Err(AdamantValidationError::TypeMismatch {
                reason: TypeMismatchReason::WrongPackUnpackType,
                ..
            }) => {}
            other => panic!("expected WrongPackUnpackType, got {other:?}"),
        }
    }

    /// `ReferenceTypeNotMatched` audit pin: `ReadRef` on
    /// non-reference.
    #[test]
    fn read_ref_on_non_reference_rejected() {
        let m = module_with_function(
            vec![],
            vec![],
            vec![],
            vec![
                ld_u64(0),
                BytecodeInstruction::Inherited(Bytecode::ReadRef),
                pop(),
                ret(),
            ],
        );
        match run(&m) {
            Err(AdamantValidationError::TypeMismatch {
                reason: TypeMismatchReason::ReferenceTypeNotMatched,
                ..
            }) => {}
            other => panic!("expected ReferenceTypeNotMatched, got {other:?}"),
        }
    }

    /// `BorrowFieldTypeMismatch` audit pin: `MutBorrowField` on
    /// immutable reference (`mut_=true` requires mutable ref).
    #[test]
    fn mut_borrow_field_on_imm_ref_rejected() {
        let mut m = module_with_function(vec![], vec![], vec![], vec![ret()]);
        let (s_token, _def_idx, fh_idx) = add_simple_struct(&mut m);
        // params[0] = &S (immutable)
        m.signatures[0] = Signature(vec![SignatureToken::Reference(Box::new(s_token))]);
        m.function_defs[0].code = Some(AdamantCodeUnit {
            locals: SignatureIndex(1),
            code: vec![
                cp_loc(0),
                BytecodeInstruction::Inherited(Bytecode::MutBorrowField(fh_idx)),
                BytecodeInstruction::Inherited(Bytecode::ReadRef),
                pop(),
                ret(),
            ],
            jump_tables: vec![],
        });
        match run(&m) {
            Err(AdamantValidationError::TypeMismatch {
                reason: TypeMismatchReason::BorrowFieldTypeMismatch,
                ..
            }) => {}
            other => panic!("expected BorrowFieldTypeMismatch, got {other:?}"),
        }
    }

    /// `VecOpTypeMismatch` audit pin: `VecPushBack` with element
    /// type ≠ vector element type.
    #[test]
    fn vec_push_back_with_wrong_element_type_rejected() {
        // params[0] = &mut vector<u64>, body pushes u8 onto it.
        let m = module_with_function(
            vec![SignatureToken::MutableReference(Box::new(
                SignatureToken::Vector(Box::new(SignatureToken::U64)),
            ))],
            vec![],
            vec![],
            vec![
                cp_loc(0),
                ld_u8(7),
                BytecodeInstruction::Inherited(Bytecode::VecPushBack(SignatureIndex(0))),
                ret(),
            ],
        );
        // Need signatures[0] to be `[u64]` for VecPushBack idx=0
        // declared element type. Override:
        let mut m = m;
        m.signatures[0] = Signature(vec![SignatureToken::U64]);
        // params[0] index points to signatures[0] which now is
        // [u64], not [&mut vector<u64>]. Adjust: we need a
        // separate signature for params and a separate one for
        // VecPushBack's declared element type. Build fresh:
        let mut m = AdamantCompiledModule::default();
        m.module_handles.push(ModuleHandle {
            address: AddressIdentifierIndex(0),
            name: IdentifierIndex(0),
        });
        m.identifiers.push(Identifier::new("f").unwrap());
        // sig 0: declared element type = vector<u64>'s element = u64
        m.signatures.push(Signature(vec![SignatureToken::U64]));
        // sig 1: parameters = [&mut vector<u64>]
        m.signatures
            .push(Signature(vec![SignatureToken::MutableReference(Box::new(
                SignatureToken::Vector(Box::new(SignatureToken::U64)),
            ))]));
        // sig 2: locals = []
        m.signatures.push(Signature(vec![]));
        // sig 3: returns = []
        m.signatures.push(Signature(vec![]));
        m.function_handles.push(FunctionHandle {
            module: ModuleHandleIndex(0),
            name: IdentifierIndex(0),
            parameters: SignatureIndex(1),
            return_: SignatureIndex(3),
            type_parameters: vec![],
        });
        m.function_defs.push(AdamantFunctionDefinition {
            function: FunctionHandleIndex(0),
            visibility: Visibility::default(),
            is_entry: false,
            acquires_global_resources: vec![],
            code: Some(AdamantCodeUnit {
                locals: SignatureIndex(2),
                code: vec![
                    cp_loc(0),
                    ld_u8(7),
                    BytecodeInstruction::Inherited(Bytecode::VecPushBack(SignatureIndex(0))),
                    ret(),
                ],
                jump_tables: vec![],
            }),
        });
        match run(&m) {
            Err(AdamantValidationError::TypeMismatch {
                reason: TypeMismatchReason::VecOpTypeMismatch,
                ..
            }) => {}
            other => panic!("expected VecOpTypeMismatch, got {other:?}"),
        }
    }

    /// `FreezeRefRequiresMutableReference` audit pin: `FreezeRef`
    /// on immutable reference.
    #[test]
    fn freeze_ref_on_imm_ref_rejected() {
        let m = module_with_function(
            vec![SignatureToken::Reference(Box::new(SignatureToken::U64))],
            vec![],
            vec![],
            vec![
                cp_loc(0),
                BytecodeInstruction::Inherited(Bytecode::FreezeRef),
                BytecodeInstruction::Inherited(Bytecode::ReadRef),
                pop(),
                ret(),
            ],
        );
        match run(&m) {
            Err(AdamantValidationError::TypeMismatch {
                reason: TypeMismatchReason::FreezeRefRequiresMutableReference,
                ..
            }) => {}
            other => panic!("expected FreezeRefRequiresMutableReference, got {other:?}"),
        }
    }

    /// `WriteRefRequiresMutableReference` audit pin: `WriteRef`
    /// on immutable reference.
    #[test]
    fn write_ref_on_imm_ref_rejected() {
        let m = module_with_function(
            vec![SignatureToken::Reference(Box::new(SignatureToken::U64))],
            vec![],
            vec![],
            vec![
                ld_u64(7),
                cp_loc(0),
                BytecodeInstruction::Inherited(Bytecode::WriteRef),
                ret(),
            ],
        );
        match run(&m) {
            Err(AdamantValidationError::TypeMismatch {
                reason: TypeMismatchReason::WriteRefRequiresMutableReference,
                ..
            }) => {}
            other => panic!("expected WriteRefRequiresMutableReference, got {other:?}"),
        }
    }

    /// `VariantSwitchTypeMismatch` audit pin: `VariantSwitch` on
    /// non-reference.
    #[test]
    fn variant_switch_on_non_reference_rejected() {
        let mut m = AdamantCompiledModule::default();
        m.module_handles.push(ModuleHandle {
            address: AddressIdentifierIndex(0),
            name: IdentifierIndex(0),
        });
        m.identifiers.push(Identifier::new("f").unwrap());
        m.identifiers.push(Identifier::new("E").unwrap());
        // Enum handle at datatype 0
        m.datatype_handles.push(DatatypeHandle {
            module: ModuleHandleIndex(0),
            name: IdentifierIndex(1),
            abilities: AbilitySet::EMPTY | Ability::Drop,
            type_parameters: vec![],
        });
        // Enum def with 1 variant (named V0, no fields)
        m.identifiers.push(Identifier::new("V0").unwrap());
        m.enum_defs.push(EnumDefinition {
            enum_handle: DatatypeHandleIndex(0),
            variants: vec![VariantDefinition {
                variant_name: IdentifierIndex(2),
                fields: vec![],
            }],
        });
        // Signatures
        m.signatures.push(Signature(vec![])); // 0: params
        m.signatures.push(Signature(vec![])); // 1: locals
        m.signatures.push(Signature(vec![])); // 2: returns
        m.function_handles.push(FunctionHandle {
            module: ModuleHandleIndex(0),
            name: IdentifierIndex(0),
            parameters: SignatureIndex(0),
            return_: SignatureIndex(2),
            type_parameters: vec![],
        });
        m.function_defs.push(AdamantFunctionDefinition {
            function: FunctionHandleIndex(0),
            visibility: Visibility::default(),
            is_entry: false,
            acquires_global_resources: vec![],
            code: Some(AdamantCodeUnit {
                locals: SignatureIndex(1),
                code: vec![
                    ld_u64(0),
                    BytecodeInstruction::Inherited(Bytecode::VariantSwitch(VariantJumpTableIndex(
                        0,
                    ))),
                    ret(),
                ],
                jump_tables: vec![VariantJumpTable {
                    head_enum: EnumDefinitionIndex(0),
                    jump_table: JumpTableInner::Full(vec![2]),
                }],
            }),
        });
        match run(&m) {
            Err(AdamantValidationError::TypeMismatch {
                reason: TypeMismatchReason::VariantSwitchTypeMismatch,
                ..
            }) => {}
            other => panic!("expected VariantSwitchTypeMismatch, got {other:?}"),
        }
    }

    // ===========================================================
    // Per-extension type-rule pins (17 extensions, Q1/Q2)
    // ===========================================================

    // --- Cat A static (12) ---

    /// `Sha3_256` happy path: vector<u8> in, vector<u8> out.
    #[test]
    fn sha3_256_happy_path() {
        // params[0] = vector<u8>; body: mv_loc, Sha3_256, pop, ret.
        let m = module_with_function(
            vec![SignatureToken::Vector(Box::new(SignatureToken::U8))],
            vec![],
            vec![],
            vec![
                mv_loc(0),
                extension(AdamantBytecode::Sha3_256),
                pop(),
                ret(),
            ],
        );
        run(&m).expect("Sha3_256 with vector<u8> in pushes vector<u8>");
    }

    /// `Sha3_256` rejects non-vector<u8> input.
    #[test]
    fn sha3_256_with_non_byte_vector_rejected() {
        let m = module_with_function(
            vec![],
            vec![],
            vec![],
            vec![
                ld_u64(0),
                extension(AdamantBytecode::Sha3_256),
                pop(),
                ret(),
            ],
        );
        match run(&m) {
            Err(AdamantValidationError::TypeMismatch {
                reason: TypeMismatchReason::OperandTypeMismatch,
                ..
            }) => {}
            other => panic!("expected OperandTypeMismatch, got {other:?}"),
        }
    }

    /// `Blake3` happy path.
    #[test]
    fn blake3_happy_path() {
        let m = module_with_function(
            vec![SignatureToken::Vector(Box::new(SignatureToken::U8))],
            vec![],
            vec![],
            vec![mv_loc(0), extension(AdamantBytecode::Blake3), pop(), ret()],
        );
        run(&m).expect("Blake3 with vector<u8> in pushes vector<u8>");
    }

    /// `KzgCommit` happy path.
    #[test]
    fn kzg_commit_happy_path() {
        let m = module_with_function(
            vec![SignatureToken::Vector(Box::new(SignatureToken::U8))],
            vec![],
            vec![],
            vec![
                mv_loc(0),
                extension(AdamantBytecode::KzgCommit),
                pop(),
                ret(),
            ],
        );
        run(&m).expect("KzgCommit accepts vector<u8>, pushes vector<u8>");
    }

    /// `KzgVerify` happy path: 3 vector<u8> in, bool out.
    #[test]
    fn kzg_verify_happy_path() {
        let m = module_with_function(
            vec![SignatureToken::Vector(Box::new(SignatureToken::U8))],
            vec![],
            vec![],
            vec![
                cp_loc(0),
                cp_loc(0),
                cp_loc(0),
                extension(AdamantBytecode::KzgVerify),
                pop(), // pop the bool
                ret(),
            ],
        );
        run(&m).expect("KzgVerify pops 3 vector<u8>, pushes bool");
    }

    /// `Ed25519Verify` happy path: 3 vector<u8> in, bool out.
    #[test]
    fn ed25519_verify_happy_path() {
        let m = module_with_function(
            vec![SignatureToken::Vector(Box::new(SignatureToken::U8))],
            vec![],
            vec![],
            vec![
                cp_loc(0),
                cp_loc(0),
                cp_loc(0),
                extension(AdamantBytecode::Ed25519Verify),
                pop(),
                ret(),
            ],
        );
        run(&m).expect("Ed25519Verify happy path");
    }

    /// `MlDsaVerify65` happy path.
    #[test]
    fn ml_dsa_verify65_happy_path() {
        let m = module_with_function(
            vec![SignatureToken::Vector(Box::new(SignatureToken::U8))],
            vec![],
            vec![],
            vec![
                cp_loc(0),
                cp_loc(0),
                cp_loc(0),
                extension(AdamantBytecode::MlDsaVerify65),
                pop(),
                ret(),
            ],
        );
        run(&m).expect("MlDsaVerify65 happy path");
    }

    /// `BlsVerify` happy path.
    #[test]
    fn bls_verify_happy_path() {
        let m = module_with_function(
            vec![SignatureToken::Vector(Box::new(SignatureToken::U8))],
            vec![],
            vec![],
            vec![
                cp_loc(0),
                cp_loc(0),
                cp_loc(0),
                extension(AdamantBytecode::BlsVerify),
                pop(),
                ret(),
            ],
        );
        run(&m).expect("BlsVerify happy path");
    }

    /// `Ed25519Verify` rejects non-vector<u8> operands.
    #[test]
    fn ed25519_verify_with_non_byte_vector_rejected() {
        let m = module_with_function(
            vec![],
            vec![],
            vec![],
            vec![
                ld_u64(0),
                ld_u64(0),
                ld_u64(0),
                extension(AdamantBytecode::Ed25519Verify),
                pop(),
                ret(),
            ],
        );
        match run(&m) {
            Err(AdamantValidationError::TypeMismatch {
                reason: TypeMismatchReason::OperandTypeMismatch,
                ..
            }) => {}
            other => panic!("expected OperandTypeMismatch, got {other:?}"),
        }
    }

    /// `ReleaseSubViewKey` happy path.
    #[test]
    fn release_sub_view_key_happy_path() {
        let m = module_with_function(
            vec![SignatureToken::Vector(Box::new(SignatureToken::U8))],
            vec![],
            vec![],
            vec![
                mv_loc(0),
                extension(AdamantBytecode::ReleaseSubViewKey),
                pop(),
                ret(),
            ],
        );
        run(&m).expect("ReleaseSubViewKey accepts vector<u8>, pushes vector<u8>");
    }

    /// `ChargeGas` happy path: pops u64.
    #[test]
    fn charge_gas_happy_path() {
        let m = module_with_function(
            vec![],
            vec![],
            vec![],
            vec![
                ld_u64(100),
                extension(AdamantBytecode::ChargeGas(GasDimension::Computation)),
                ret(),
            ],
        );
        run(&m).expect("ChargeGas pops u64");
    }

    /// `ChargeGas` rejects non-u64 operand.
    #[test]
    fn charge_gas_with_non_u64_rejected() {
        let m = module_with_function(
            vec![],
            vec![],
            vec![],
            vec![
                ld_true(),
                extension(AdamantBytecode::ChargeGas(GasDimension::Computation)),
                ret(),
            ],
        );
        match run(&m) {
            Err(AdamantValidationError::TypeMismatch {
                reason: TypeMismatchReason::OperandTypeMismatch,
                ..
            }) => {}
            other => panic!("expected OperandTypeMismatch, got {other:?}"),
        }
    }

    /// `RemainingGas` happy path: pushes u64.
    #[test]
    fn remaining_gas_happy_path() {
        let m = module_with_function(
            vec![],
            vec![],
            vec![],
            vec![
                extension(AdamantBytecode::RemainingGas(GasDimension::Computation)),
                pop(),
                ret(),
            ],
        );
        run(&m).expect("RemainingGas pushes u64");
    }

    /// `OutOfGas` happy path: no stack effect.
    #[test]
    fn out_of_gas_happy_path() {
        let m = module_with_function(
            vec![],
            vec![],
            vec![],
            vec![extension(AdamantBytecode::OutOfGas), ret()],
        );
        run(&m).expect("OutOfGas has no stack effect");
    }

    // --- Cat B parametric-FH (2) ---

    /// `InvokeShielded` happy path: same shape as `Call`.
    #[test]
    fn invoke_shielded_happy_path() {
        let mut m = module_with_function(vec![], vec![], vec![], vec![ret()]);
        let h = add_function_handle(&mut m, vec![SignatureToken::U64], vec![]);
        m.function_defs[0].code = Some(AdamantCodeUnit {
            locals: SignatureIndex(1),
            code: vec![
                ld_u64(42),
                extension(AdamantBytecode::InvokeShielded(h)),
                ret(),
            ],
            jump_tables: vec![],
        });
        run(&m).expect("InvokeShielded with matching arg type OK");
    }

    /// `InvokeTransparent` happy path: same shape as `Call`.
    #[test]
    fn invoke_transparent_happy_path() {
        let mut m = module_with_function(vec![], vec![], vec![], vec![ret()]);
        let h = add_function_handle(&mut m, vec![SignatureToken::U64], vec![]);
        m.function_defs[0].code = Some(AdamantCodeUnit {
            locals: SignatureIndex(1),
            code: vec![
                ld_u64(42),
                extension(AdamantBytecode::InvokeTransparent(h)),
                ret(),
            ],
            jump_tables: vec![],
        });
        run(&m).expect("InvokeTransparent with matching arg type OK");
    }

    /// `InvokeShielded` with mismatched arg fires
    /// `WrongFunctionSignature` (same code path as `Call`).
    #[test]
    fn invoke_shielded_with_wrong_arg_type_rejected() {
        let mut m = module_with_function(vec![], vec![], vec![], vec![ret()]);
        let h = add_function_handle(&mut m, vec![SignatureToken::U64], vec![]);
        m.function_defs[0].code = Some(AdamantCodeUnit {
            locals: SignatureIndex(1),
            code: vec![
                ld_true(),
                extension(AdamantBytecode::InvokeShielded(h)),
                ret(),
            ],
            jump_tables: vec![],
        });
        match run(&m) {
            Err(AdamantValidationError::TypeMismatch {
                reason: TypeMismatchReason::WrongFunctionSignature,
                ..
            }) => {}
            other => panic!("expected WrongFunctionSignature, got {other:?}"),
        }
    }

    // --- Cat C/D fail-open (3) ---

    /// `GenerateProof` fails open: any stack state accepted at
    /// type layer (D-3 fails open at count layer too; runtime
    /// carries the binding).
    #[test]
    fn generate_proof_fails_open() {
        let m = module_with_function(
            vec![],
            vec![],
            vec![],
            vec![
                extension(AdamantBytecode::GenerateProof(CircuitId(0))),
                ret(),
            ],
        );
        run(&m).expect("GenerateProof fails open at the type layer");
    }

    /// `VerifyProof` fails open.
    #[test]
    fn verify_proof_fails_open() {
        let m = module_with_function(
            vec![],
            vec![],
            vec![],
            vec![extension(AdamantBytecode::VerifyProof(CircuitId(0))), ret()],
        );
        run(&m).expect("VerifyProof fails open at the type layer");
    }

    /// `RecursiveVerify` fails open.
    #[test]
    fn recursive_verify_fails_open() {
        let m = module_with_function(
            vec![],
            vec![],
            vec![],
            vec![extension(AdamantBytecode::RecursiveVerify), ret()],
        );
        run(&m).expect("RecursiveVerify fails open at the type layer");
    }

    // ===========================================================
    // Eager-error semantics
    // ===========================================================

    /// Per-instruction first-failure-wins: when two type-safety
    /// errors are present in the same block, the earlier
    /// instruction's reason fires.
    #[test]
    fn eager_error_first_failure_wins() {
        // params[0] = u64; locals[0] = u64.
        // Body: ld_true (Bool), st_loc(0)  <-- first error: LocalTypeMismatch
        //       cast_u8                    <-- if reached, would be CastTargetTypeInvalid
        //       ret
        let m = module_with_function(
            vec![],
            vec![SignatureToken::U64],
            vec![],
            vec![ld_true(), st_loc(0), ld_true(), cast_u8(), pop(), ret()],
        );
        match run(&m) {
            Err(AdamantValidationError::TypeMismatch {
                reason: TypeMismatchReason::LocalTypeMismatch,
                ..
            }) => {}
            other => panic!("expected LocalTypeMismatch (first failure wins), got {other:?}"),
        }
    }

    // ===========================================================
    // Additional happy-path pinning
    // ===========================================================

    /// Pack with matching field type pushes the struct value.
    #[test]
    fn pack_happy_path() {
        let mut m = module_with_function(vec![], vec![], vec![], vec![ret()]);
        let (_s_token, def_idx, _fh_idx) = add_simple_struct(&mut m);
        m.function_defs[0].code = Some(AdamantCodeUnit {
            locals: SignatureIndex(1),
            code: vec![
                ld_u64(42),
                BytecodeInstruction::Inherited(Bytecode::Pack(def_idx)),
                pop(),
                ret(),
            ],
            jump_tables: vec![],
        });
        run(&m).expect("Pack with matching field type OK");
    }

    /// Unpack with matching struct value pushes one value per
    /// field.
    #[test]
    fn unpack_happy_path() {
        let mut m = module_with_function(vec![], vec![], vec![], vec![ret()]);
        let (_s_token, def_idx, _fh_idx) = add_simple_struct(&mut m);
        m.function_defs[0].code = Some(AdamantCodeUnit {
            locals: SignatureIndex(1),
            code: vec![
                ld_u64(42),
                BytecodeInstruction::Inherited(Bytecode::Pack(def_idx)),
                BytecodeInstruction::Inherited(Bytecode::Unpack(def_idx)),
                pop(), // pop the u64 field
                ret(),
            ],
            jump_tables: vec![],
        });
        run(&m).expect("Unpack pushes one operand per field");
    }

    /// `Call` happy path: matching arg type, no return.
    #[test]
    fn call_happy_path() {
        let mut m = module_with_function(vec![], vec![], vec![], vec![ret()]);
        let h = add_function_handle(&mut m, vec![SignatureToken::U64], vec![]);
        m.function_defs[0].code = Some(AdamantCodeUnit {
            locals: SignatureIndex(1),
            code: vec![
                ld_u64(42),
                BytecodeInstruction::Inherited(Bytecode::Call(h)),
                ret(),
            ],
            jump_tables: vec![],
        });
        run(&m).expect("Call with matching arg type OK");
    }

    /// `ImmBorrowLoc` + `ReadRef` round-trip succeeds.
    #[test]
    fn imm_borrow_loc_and_read_ref_happy_path() {
        let m = module_with_function(
            vec![SignatureToken::U64],
            vec![],
            vec![],
            vec![
                BytecodeInstruction::Inherited(Bytecode::ImmBorrowLoc(0)),
                BytecodeInstruction::Inherited(Bytecode::ReadRef),
                pop(),
                ret(),
            ],
        );
        run(&m).expect("ImmBorrowLoc + ReadRef u64 OK");
    }

    // Suppress "unused import" — these aliases exist so future
    // tests can use them without re-listing every import.
    #[allow(dead_code)]
    fn _silence_unused_imports() {
        let _ = (
            ConstantPoolIndex(0),
            FieldInstantiationIndex(0),
            FieldInstantiation {
                handle: FieldHandleIndex(0),
                type_parameters: SignatureIndex(0),
            },
            FunctionInstantiationIndex(0),
            FunctionInstantiation {
                handle: FunctionHandleIndex(0),
                type_parameters: SignatureIndex(0),
            },
            StructDefInstantiationIndex(0),
            StructDefInstantiation {
                def: StructDefinitionIndex(0),
                type_parameters: SignatureIndex(0),
            },
            VariantHandleIndex(0),
            VariantHandle {
                enum_def: EnumDefinitionIndex(0),
                variant: 0,
            },
            VariantInstantiationHandleIndex(0),
            VariantInstantiationHandle {
                enum_def: adamant_bytecode_format::EnumDefInstantiationIndex(0),
                variant: 0,
            },
        );
    }

    // ----- Phase 5/5c F-2: Layer B parity backfill -----
    //
    // Sui's `type_safety::verify` is `pub(crate)` — only the
    // composite per-function entry `code_unit_verifier::verify_module`
    // is reachable from our test code. Composite-pipeline parity
    // is the right shape per the Sui-public-API-shape-constrains-
    // parity-helper sub-pattern (D-7b registration; 3rd instance
    // at F-2). Each fixture is curated to isolate type_safety's
    // behaviour: well-formed at every other pass; triggers the
    // type rule under test on both sides. Pipeline-position note:
    // Adamant runs type_safety at position 4 (control_flow →
    // stack_usage → locals_safety → type_safety →
    // reference_safety) while Sui runs type_safety at position 3
    // (control_flow → stack_usage → type_safety → locals_safety
    // → reference_safety). For type-violation fixtures the
    // ordering difference doesn't change the rejection set —
    // type-mismatched fixtures reject at type_safety on both
    // sides; locals-violation fixtures (per E-6 backfill) are
    // type-correct by construction.

    use super::super::test_helpers::{
        assert_function_pass_parity_vm, run_adamant_pipeline, run_sui_code_unit_verifier,
        sui_config_from, to_sui,
    };
    use crate::validator::config::AdamantStructuralLimits;
    use adamant_types::Address as AccountAddress;

    fn add_self_address_typesafe(m: &mut AdamantCompiledModule) {
        if m.address_identifiers.is_empty() {
            m.address_identifiers
                .push(AccountAddress::from_bytes([0u8; 32]));
        }
    }

    /// Cross-validate `type_safety` pipeline parity. Mirror of
    /// D-7a's `locals_safety` / `stack_usage` helper shape.
    fn cross_validate_type_safety_pipeline(m: &AdamantCompiledModule) {
        let mut m = m.clone();
        add_self_address_typesafe(&mut m);
        // Add mutability metadata so Rule 1 doesn't pre-empt
        // (defensive-fixture-isolation pattern from E-5).
        if !m.metadata.iter().any(|md| md.key == b"adamant.mutability") {
            m.metadata.push(adamant_bytecode_format::Metadata {
                key: b"adamant.mutability".to_vec(),
                value: bcs::to_bytes(&adamant_types::Mutability::Immutable).unwrap(),
            });
        }
        let limits = AdamantStructuralLimits::genesis();
        let adamant_result = run_adamant_pipeline(&m, &limits);
        let sui_module = to_sui(&m);
        let sui_config = sui_config_from(&limits);
        let sui_result = run_sui_code_unit_verifier(&sui_module, &sui_config);
        assert_function_pass_parity_vm("type_safety", adamant_result, sui_result);
    }

    #[test]
    fn cross_validation_accepts_simple_balanced_function() {
        // Body: empty params/locals/returns; just Ret. Both
        // Adamant and Sui accept.
        let m = module_with_function(vec![], vec![], vec![], vec![ret()]);
        cross_validate_type_safety_pipeline(&m);
    }

    #[test]
    fn cross_validation_rejects_cast_to_u8_on_bool() {
        let m = module_with_function(
            vec![],
            vec![],
            vec![SignatureToken::U8],
            vec![ld_true(), cast_u8(), ret()],
        );
        cross_validate_type_safety_pipeline(&m);
    }

    #[test]
    fn cross_validation_rejects_add_with_mismatched_int_widths() {
        let m = module_with_function(
            vec![],
            vec![],
            vec![SignatureToken::U64],
            vec![ld_u8(1), ld_u64(2), add(), ret()],
        );
        cross_validate_type_safety_pipeline(&m);
    }

    #[test]
    fn cross_validation_rejects_ret_with_wrong_return_type() {
        let m = module_with_function(
            vec![],
            vec![],
            vec![SignatureToken::U64],
            vec![ld_true(), ret()],
        );
        cross_validate_type_safety_pipeline(&m);
    }

    #[test]
    fn cross_validation_rejects_st_loc_wrong_value_type() {
        // Local declared as u8; body pushes u64 + StLoc 0.
        let m = module_with_function(
            vec![],
            vec![SignatureToken::U8],
            vec![],
            vec![ld_u64(1), st_loc(0), ret()],
        );
        cross_validate_type_safety_pipeline(&m);
    }

    #[test]
    fn cross_validation_rejects_br_true_on_non_bool() {
        // BrTrue expects a bool on stack; supply u64.
        let m = module_with_function(
            vec![],
            vec![],
            vec![],
            vec![
                ld_u64(1),
                BytecodeInstruction::Inherited(Bytecode::BrTrue(2)),
                ret(),
                ret(),
            ],
        );
        cross_validate_type_safety_pipeline(&m);
    }

    #[test]
    fn cross_validation_rejects_read_ref_on_non_reference() {
        // ReadRef expects &T on stack; supply u64.
        let m = module_with_function(
            vec![],
            vec![],
            vec![],
            vec![
                ld_u64(1),
                BytecodeInstruction::Inherited(Bytecode::ReadRef),
                pop(),
                ret(),
            ],
        );
        cross_validate_type_safety_pipeline(&m);
    }

    #[test]
    fn cross_validation_rejects_freeze_ref_on_imm_ref() {
        // FreezeRef expects &mut T; supply &T (immutable
        // reference). Param 0: &u64.
        let m = module_with_function(
            vec![SignatureToken::Reference(Box::new(SignatureToken::U64))],
            vec![],
            vec![],
            vec![
                BytecodeInstruction::Inherited(Bytecode::CopyLoc(0)),
                BytecodeInstruction::Inherited(Bytecode::FreezeRef),
                pop(),
                ret(),
            ],
        );
        cross_validate_type_safety_pipeline(&m);
    }
}
