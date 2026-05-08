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
//! - **D-5a.1.a (this commit).** Foundation: `TypeSafetyChecker`
//!   struct + helpers + per-instruction transfer for the first
//!   ~30-40 inherited bytecode arms (load/move/copy/store/binop/
//!   eq/cast/branch/ret/abort/pop) + structural-impossibility
//!   `unreachable!`-three-anchor consolidating 10 deprecated
//!   global-storage opcodes (sub-shape 2 instance, 3rd at D-5a.1.a
//!   closure — rule-of-three threshold met for sub-shape 2).
//!   Out-of-scope arms (refs/pack/unpack/calls/vector/variant)
//!   land at D-5a.1.b alongside the orchestration wire-in.
//!   Adamant extensions land at D-5a.1.b. Module is registered
//!   but **NOT chained into `verify_function_bodies` at D-5a.1.a**
//!   per the test-correctness adjustment surfaced at impl-gate
//!   (chaining a half-implemented type-safety pass would corrupt
//!   the abstract-stack tracking on out-of-scope arms and break
//!   existing `locals_safety` tests).
//! - **D-5a.1.b.** Remaining inherited arms + 17 Adamant
//!   extensions per §6.2.1.4 lines 408–423 (Categories A/B/C/D
//!   on record at D-3's 10th verification gate) + orchestration
//!   chain in `function_pass/mod.rs`.
//!
//! # Adamant deviations
//!
//! - **Per-pass-instance `AdamantAbilityCache` lifecycle** (Q2(a)
//!   at D-5 plan-gate; mirrors B-2.3's per-pass-instance shape;
//!   stricter than D-4's per-function-instance lifecycle which
//!   was the 6th deliberate-Adamant-decision). Cache is
//!   constructed once at the per-function batch entry and reused
//!   across all functions within the type-safety pass.
//! - **Adamant-native `AbstractStack`** (Q1(a) at D-5a plan-gate;
//!   9th deliberate-Adamant-decision instance). Consumes
//!   [`super::abstract_stack::AbstractStack`] (D-5a.0's port)
//!   rather than upstream's `move_abstract_stack::AbstractStack`.
//!   Same vendored-Sui-crates-port canonical principle as D-1a/
//!   D-1b/D-2.
//! - **Closed-enum sub-reason on `TypeMismatch`** (Q4(a) at D-5
//!   plan-gate; 7th deliberate-Adamant-decision instance via
//!   `TypeMismatchReason`). 14 sub-reasons land at D-5a.0;
//!   variant-vs-test mapping audit closes across D-5a.1.a +
//!   D-5a.1.b.
//! - **`expect()`-three-anchor on `AbsStackError`** (Q1(a) at
//!   D-5a.1 plan-gate; **NEW sub-shape 4 of structural-
//!   impossibility-checks pattern**). D-3's per-block-balance
//!   precondition makes `Underflow` structurally impossible at
//!   type-safety's pipeline position; D-3's `max_push_size` check
//!   makes `Overflow` structurally impossible; `pop_eq_n`'s
//!   `ElementNotEqual` is unreachable in this pass (no per-run
//!   pops). All `AbsStackError` paths panic via `expect()` with
//!   three-anchor stem.
//! - No metering surface (D-1a/D-1b/D-2/D-3/D-4 precedent;
//!   `TYPE_NODE_COST`, `TYPE_NODE_QUADRATIC_THRESHOLD`,
//!   `TYPE_PUSH_COST` constants not ported). Confirmed at D-5a
//!   plan-gate Q4.
//!
//! # Cross-pass-pipeline-dependency
//!
//! Four intra-pipeline preconditions:
//! - **Step 3** (`module_pass::bounds_checker`,
//!   `signature_checker`, `instruction_consistency`): handle and
//!   signature-pool indices validated; per-instruction lookups
//!   in `verify_inherited_instr` cannot panic.
//! - **Step 4 D-2** (`function_pass::control_flow`): non-empty
//!   reducible CFG; `verify_function` iterates `cfg.blocks()`.
//! - **Step 4 D-3** (`function_pass::stack_usage`): per-block
//!   stack balance; `AbstractStack` underflow / overflow are
//!   structurally impossible (Q1(a) sub-shape 4).
//! - **Step 4 D-4** (`function_pass::locals_safety`): locals
//!   availability; `CopyLoc` / `MoveLoc` lookups assume the
//!   local has a value, then this pass type-checks the value.
//!
//! Cross-pass-pipeline-dependency sub-pattern (registered at
//! C-5); D-5a.1 instantiates without surfacing new sub-pattern
//! instances.

use adamant_bytecode_format::{
    AbilitySet, Bytecode, CodeOffset, FunctionDefinitionIndex, LocalIndex, Signature,
    SignatureToken, VariantJumpTable,
};

use super::abstract_stack::AbstractStack;
use super::cfg::AdamantControlFlowGraph;
use crate::bytecode::{AdamantBytecode, BytecodeInstruction};
use crate::module::{AdamantCompiledModule, AdamantFunctionDefinition};
use crate::validator::error::{AdamantValidationError, TypeMismatchReason};
use crate::validator::module_pass::ability_cache::AdamantAbilityCache;

/// Three-anchor message stem for the `AbstractStack`
/// structural-impossibility check. Sub-shape 4 of the
/// structural-impossibility-checks pattern (NEW at D-5a.1.a).
/// `expect()` fires in BOTH debug AND release builds — the
/// invariant is consensus-binding (D-3's per-block-balance
/// precondition is what makes type-safety's stack ops
/// well-formed; a violation indicates an Adamant
/// implementation bug, not malformed input).
const STACK_INVARIANT_THREE_ANCHOR_STEM: &str =
    "AbstractStack invariant violated; should be unreachable in pipeline (D-3's per-block-balance \
     + max_push_size preconditions); if this fires from direct-unvalidated-input caller, caller \
     violates the precondition";

/// Three-anchor message stem for the deprecated global-storage
/// `unreachable!` arm. Sub-shape 2 of structural-impossibility-
/// checks (3rd instance at D-5a.1.a closure — rule-of-three
/// threshold met for sub-shape 2 specifically: B-2.4 deprecated
/// arms + D-4 acquires-list + D-5a.1.a deprecated global-storage
/// in type-safety).
const DEPRECATED_GLOBAL_STORAGE_THREE_ANCHOR_STEM: &str =
    "Rule 5 deserializer-enforcement makes deprecated global-storage opcodes (MoveTo/MoveFrom/\
     BorrowGlobal/Exists × {Deprecated, GenericDeprecated}) unreachable in valid Adamant modules; \
     should be unreachable in pipeline; if this fires from direct-unvalidated-input caller, caller \
     violates the deserializer-precondition";

/// Per-function type-safety verifier state.
///
/// Mirrors upstream's `TypeSafetyChecker` byte-faithfully:
/// constructed once per function, holds the typed `AbstractStack`
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

    /// Push a value onto the abstract typed-stack. `expect()`-
    /// three-anchor on overflow (sub-shape 4 of structural-
    /// impossibility-checks).
    fn push(&mut self, ty: SignatureToken) {
        self.stack
            .push(ty)
            .unwrap_or_else(|e| panic!("{STACK_INVARIANT_THREE_ANCHOR_STEM}. push error: {e:?}"));
    }

    /// Pop a value from the abstract typed-stack. `expect()`-
    /// three-anchor on underflow.
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
/// Constructs a `TypeSafetyChecker`, iterates every basic block
/// in the CFG, and applies `verify_instr` per instruction.
///
/// The `ability_cache` parameter implements per-pass-instance
/// memoization (Q2(a) at D-5 plan-gate): the caller (function-
/// pass orchestration in D-5a.1.b) constructs one cache shared
/// across all functions in a module; lookups for the same
/// signature token in different functions hit the cache.
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
/// `verify_instr` byte-faithfully; routes to `verify_inherited_instr`
/// for inherited Sui-Move bytecode arms and `verify_adamant_instr`
/// for Adamant extensions per §6.2.1.4.
fn verify_instr(
    verifier: &mut TypeSafetyChecker<'_, '_>,
    instr: &BytecodeInstruction,
    jump_tables: &[VariantJumpTable],
    offset: CodeOffset,
) -> Result<(), AdamantValidationError> {
    match instr {
        BytecodeInstruction::Inherited(b) => verify_inherited_instr(verifier, b, jump_tables, offset),
        BytecodeInstruction::Adamant(a) => verify_adamant_instr(verifier, a, offset),
    }
}

/// Per-instruction transfer for inherited Sui-Move bytecode.
///
/// **D-5a.1.a covers the first ~30-40 arms** (load/move/copy/
/// store/binop/eq/cast/branch/ret/abort/pop). Out-of-scope arms
/// land at D-5a.1.b. Until D-5a.1.b, `verify_function` is NOT
/// chained into `verify_function_bodies`, so out-of-scope arms
/// are not exercised in production paths.
#[allow(
    clippy::too_many_lines,
    clippy::match_same_arms,
    reason = "byte-faithful per-instruction table mirroring upstream's `verify_instr`; \
              merging same-result arms would lose the per-instruction audit anchor"
)]
fn verify_inherited_instr(
    verifier: &mut TypeSafetyChecker<'_, '_>,
    bytecode: &Bytecode,
    _jump_tables: &[VariantJumpTable],
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
            // Walk the return signature in reverse (top of
            // stack is the last return value).
            let return_tokens = verifier.return_.0.clone();
            for return_type in return_tokens.iter().rev() {
                let operand = verifier.pop();
                if &operand != return_type {
                    return Err(verifier.type_mismatch(offset, TypeMismatchReason::RetTypeMismatch));
                }
            }
        }

        Bytecode::Branch(_) | Bytecode::Nop => {}

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

        Bytecode::CastU8 => {
            let operand = verifier.pop();
            if !is_integer(&operand) {
                return Err(verifier.type_mismatch(offset, TypeMismatchReason::CastTargetTypeInvalid));
            }
            verifier.push(ST::U8);
        }
        Bytecode::CastU16 => {
            let operand = verifier.pop();
            if !is_integer(&operand) {
                return Err(verifier.type_mismatch(offset, TypeMismatchReason::CastTargetTypeInvalid));
            }
            verifier.push(ST::U16);
        }
        Bytecode::CastU32 => {
            let operand = verifier.pop();
            if !is_integer(&operand) {
                return Err(verifier.type_mismatch(offset, TypeMismatchReason::CastTargetTypeInvalid));
            }
            verifier.push(ST::U32);
        }
        Bytecode::CastU64 => {
            let operand = verifier.pop();
            if !is_integer(&operand) {
                return Err(verifier.type_mismatch(offset, TypeMismatchReason::CastTargetTypeInvalid));
            }
            verifier.push(ST::U64);
        }
        Bytecode::CastU128 => {
            let operand = verifier.pop();
            if !is_integer(&operand) {
                return Err(verifier.type_mismatch(offset, TypeMismatchReason::CastTargetTypeInvalid));
            }
            verifier.push(ST::U128);
        }
        Bytecode::CastU256 => {
            let operand = verifier.pop();
            if !is_integer(&operand) {
                return Err(verifier.type_mismatch(offset, TypeMismatchReason::CastTargetTypeInvalid));
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
                return Err(verifier.type_mismatch(offset, TypeMismatchReason::BinaryOpTypeMismatch));
            }
        }

        Bytecode::Shl | Bytecode::Shr => {
            let operand1 = verifier.pop();
            let operand2 = verifier.pop();
            if is_integer(&operand2) && operand1 == ST::U8 {
                verifier.push(operand2);
            } else {
                return Err(verifier.type_mismatch(offset, TypeMismatchReason::BinaryOpTypeMismatch));
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
                return Err(verifier.type_mismatch(offset, TypeMismatchReason::EqualityComparisonInvalid));
            }
        }

        Bytecode::Lt | Bytecode::Gt | Bytecode::Le | Bytecode::Ge => {
            let operand1 = verifier.pop();
            let operand2 = verifier.pop();
            if is_integer(&operand1) && operand1 == operand2 {
                verifier.push(ST::Bool);
            } else {
                return Err(verifier.type_mismatch(offset, TypeMismatchReason::BinaryOpTypeMismatch));
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
            unreachable!(
                "{DEPRECATED_GLOBAL_STORAGE_THREE_ANCHOR_STEM}. opcode = {bytecode:?}"
            )
        }

        // --- D-5a.1.a out-of-scope arms (refs / pack / unpack /
        // calls / vector / variant); land at D-5a.1.b. Returning
        // Ok here would corrupt the abstract-stack tracking for
        // arms that produce or consume stack values. Since
        // D-5a.1.a is NOT chained into the function-pass
        // orchestration (chain wires at D-5a.1.b alongside the
        // complete pass), this arm is unreachable in production
        // paths; tests at D-5a.1.a invoke `verify_function`
        // directly with bodies covering only the in-scope arms.
        Bytecode::FreezeRef
        | Bytecode::MutBorrowField(_)
        | Bytecode::MutBorrowFieldGeneric(_)
        | Bytecode::ImmBorrowField(_)
        | Bytecode::ImmBorrowFieldGeneric(_)
        | Bytecode::MutBorrowLoc(_)
        | Bytecode::ImmBorrowLoc(_)
        | Bytecode::Call(_)
        | Bytecode::CallGeneric(_)
        | Bytecode::Pack(_)
        | Bytecode::PackGeneric(_)
        | Bytecode::Unpack(_)
        | Bytecode::UnpackGeneric(_)
        | Bytecode::ReadRef
        | Bytecode::WriteRef
        | Bytecode::VecPack(_, _)
        | Bytecode::VecLen(_)
        | Bytecode::VecImmBorrow(_)
        | Bytecode::VecMutBorrow(_)
        | Bytecode::VecPushBack(_)
        | Bytecode::VecPopBack(_)
        | Bytecode::VecUnpack(_, _)
        | Bytecode::VecSwap(_)
        | Bytecode::PackVariant(_)
        | Bytecode::PackVariantGeneric(_)
        | Bytecode::UnpackVariant(_)
        | Bytecode::UnpackVariantImmRef(_)
        | Bytecode::UnpackVariantMutRef(_)
        | Bytecode::UnpackVariantGeneric(_)
        | Bytecode::UnpackVariantGenericImmRef(_)
        | Bytecode::UnpackVariantGenericMutRef(_)
        | Bytecode::VariantSwitch(_) => {
            unreachable!(
                "D-5a.1.a out-of-scope arm; lands at D-5a.1.b alongside Adamant extensions and \
                 orchestration wire-in. opcode = {bytecode:?}"
            )
        }
    }
    Ok(())
}

/// Per-instruction transfer for Adamant extensions. **Stub at
/// D-5a.1.a; full implementation lands at D-5a.1.b alongside
/// the orchestration wire-in.**
#[allow(
    clippy::needless_pass_by_value,
    clippy::unnecessary_wraps,
    reason = "stub at D-5a.1.a; full per-extension dispatch lands at D-5a.1.b"
)]
fn verify_adamant_instr(
    _verifier: &mut TypeSafetyChecker<'_, '_>,
    instr: &AdamantBytecode,
    _offset: CodeOffset,
) -> Result<(), AdamantValidationError> {
    unreachable!(
        "D-5a.1.a stub; Adamant-extension type rules land at D-5a.1.b. extension = {instr:?}"
    )
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

// `AbsStackError` flows through `AbstractStack`'s API and is
// mapped to panic via `expect()` / `unwrap_or_else` per Q1(a)
// at D-5a.1 plan-gate; not directly named in this module.

#[cfg(test)]
mod tests {
    //! Layer A unit tests for the type-safety pass at D-5a.1.a.
    //!
    //! Tests invoke `verify_function` directly (D-5a.1.a does not
    //! chain into `verify_function_bodies`; chain wires at
    //! D-5a.1.b alongside the complete pass).
    //!
    //! Coverage at D-5a.1.a:
    //! - First-half inherited-bytecode arms (load/move/copy/
    //!   store/binop/eq/cast/branch/ret/abort/pop)
    //! - Variant-vs-test mapping audit closure for the 6
    //!   `TypeMismatchReason` sub-reasons whose producers are
    //!   in D-5a.1.a scope (`OperandTypeMismatch` via `Pop` on
    //!   non-droppable, `EqualityComparisonInvalid`,
    //!   `CastTargetTypeInvalid`, `BinaryOpTypeMismatch`,
    //!   `RetTypeMismatch`, `LocalTypeMismatch`). Remaining 8
    //!   sub-reasons close at D-5a.1.b.
    //! - Structural-impossibility `unreachable!` for the
    //!   deprecated global-storage arm (`#[should_panic]`).

    use super::*;
    use adamant_bytecode_format::{
        AbilitySet, Ability, AddressIdentifierIndex, Constant, ConstantPoolIndex, DatatypeHandle,
        DatatypeHandleIndex, FunctionHandle, FunctionHandleIndex, Identifier, IdentifierIndex,
        ModuleHandle, ModuleHandleIndex, Signature, SignatureIndex, SignatureToken, Visibility,
    };
    use crate::bytecode::BytecodeInstruction;
    use crate::module::{AdamantCodeUnit, AdamantCompiledModule, AdamantFunctionDefinition};
    use crate::validator::module_pass::ability_cache::AdamantAbilityCache;

    // --- builders ---

    fn ld_u64(v: u64) -> BytecodeInstruction {
        BytecodeInstruction::Inherited(Bytecode::LdU64(v))
    }

    fn ld_u8(v: u8) -> BytecodeInstruction {
        BytecodeInstruction::Inherited(Bytecode::LdU8(v))
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
        let handle_idx = u16::try_from(m.datatype_handles.len())
            .expect("test fixture handle count fits u16");
        m.identifiers.push(Identifier::new("S").unwrap());
        let name_idx = u16::try_from(m.identifiers.len() - 1)
            .expect("test fixture identifier count fits u16");
        m.datatype_handles.push(DatatypeHandle {
            module: ModuleHandleIndex(0),
            name: IdentifierIndex(name_idx),
            abilities: AbilitySet::EMPTY | Ability::Key,
            type_parameters: vec![],
        });
        SignatureToken::Datatype(DatatypeHandleIndex(handle_idx))
    }

    // --- per-instruction happy paths ---

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
    fn move_loc_pushes_local_type() {
        let m = module_with_function(
            vec![SignatureToken::U64],
            vec![],
            vec![],
            vec![mv_loc(0), pop(), ret()],
        );
        run(&m).expect("MoveLoc pushes parameter's type");
    }

    #[test]
    fn copy_loc_requires_copy_ability() {
        let m = module_with_function(
            vec![SignatureToken::U64],
            vec![],
            vec![],
            vec![cp_loc(0), pop(), ret()],
        );
        run(&m).expect("CopyLoc on copy-able local OK");
    }

    #[test]
    fn st_loc_consumes_local_type() {
        let m = module_with_function(
            vec![],
            vec![SignatureToken::U64],
            vec![],
            vec![ld_u64(42), st_loc(0), mv_loc(0), pop(), ret()],
        );
        run(&m).expect("StLoc on matching type OK");
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

    // --- variant-vs-test mapping audit closure (6 of 14 sub-reasons) ---

    /// `OperandTypeMismatch` audit pin: `BrTrue` on non-bool.
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

    /// `EqualityComparisonInvalid` audit pin: Eq on non-droppable.
    #[test]
    fn eq_on_non_droppable_type_rejected() {
        let mut m = module_with_function(vec![], vec![], vec![], vec![ret()]);
        let s_token = add_non_drop_datatype(&mut m);
        m.signatures[0] = Signature(vec![s_token.clone(), s_token.clone()]); // 2 params
        m.function_defs[0].code = Some(AdamantCodeUnit {
            locals: SignatureIndex(1),
            code: vec![
                mv_loc(0),
                mv_loc(1),
                eq(),
                pop(),
                ret(),
            ],
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

    /// `CastTargetTypeInvalid` audit pin: `CastU8` on bool.
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

    /// `BinaryOpTypeMismatch` audit pin: Add on (u8, u64).
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

    /// `RetTypeMismatch` audit pin: Ret with bool when return
    /// is u64.
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

    /// `LocalTypeMismatch` audit pin: `StLoc` with bool when
    /// local is u64.
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
    // global-storage arm ---

    /// Direct-unvalidated-input invocation hits the
    /// `unreachable!` panic. Sub-shape 2 of structural-
    /// impossibility-checks (3rd instance at D-5a.1.a closure;
    /// rule-of-three threshold met for sub-shape 2 specifically).
    #[test]
    #[should_panic(expected = "Rule 5 deserializer-enforcement")]
    fn deprecated_global_storage_panics_with_three_anchor() {
        let m = module_with_function(
            vec![SignatureToken::Address],
            vec![],
            vec![],
            vec![
                mv_loc(0),
                BytecodeInstruction::Inherited(Bytecode::ExistsDeprecated(
                    adamant_bytecode_format::StructDefinitionIndex(0),
                )),
                pop(),
                ret(),
            ],
        );
        let _ = run(&m);
    }

    // --- additional pinning tests ---

    /// Pop on droppable type (u64 has drop) succeeds.
    #[test]
    fn pop_on_droppable_succeeds() {
        let m = module_with_function(
            vec![],
            vec![],
            vec![],
            vec![ld_u64(1), pop(), ret()],
        );
        run(&m).expect("Pop on droppable type OK");
    }

    /// Branch / Nop have no stack effect; sequence of branches
    /// followed by Ret with empty return signature OK.
    #[test]
    fn branch_nop_no_stack_effect() {
        let m = module_with_function(
            vec![],
            vec![],
            vec![],
            vec![
                BytecodeInstruction::Inherited(Bytecode::Nop),
                BytecodeInstruction::Inherited(Bytecode::Branch(2)),
                ret(),
                ret(),
            ],
        );
        run(&m).expect("Branch + Nop have no stack effect");
    }

    /// Cast-chain: u8 → u64 via `CastU64`.
    #[test]
    fn cast_u64_on_u8_succeeds() {
        let m = module_with_function(
            vec![],
            vec![],
            vec![SignatureToken::U64],
            vec![
                ld_u8(7),
                BytecodeInstruction::Inherited(Bytecode::CastU64),
                ret(),
            ],
        );
        run(&m).expect("cast u8 → u64 succeeds");
    }

    /// Or / And on bools push bool.
    #[test]
    fn or_and_on_bools_push_bool() {
        let m = module_with_function(
            vec![],
            vec![],
            vec![],
            vec![
                ld_true(),
                ld_true(),
                BytecodeInstruction::Inherited(Bytecode::Or),
                pop(),
                ret(),
            ],
        );
        run(&m).expect("Or on bools pushes bool, popped, ret 0");
    }
}
