//! Adamant-native reference-safety per-instruction transfer +
//! `AbstractInterpreter` consumer (whitepaper §6.2.1.6 Rule
//! "reference safety").
//!
//! Forked byte-faithfully from
//! `vendor/move-bytecode-verifier/src/reference_safety/mod.rs`
//! at Sui-Move tag `mainnet-v1.66.2` (646 LOC upstream). 2nd
//! consumer of D-1b's [`AbstractInterpreter`][AI] framework
//! (D-4 `locals_safety` was 1st).
//!
//! [AI]: super::super::absint::AbstractInterpreter
//!
//! # Adamant deviations
//!
//! - **No metering surface** (D-5a / D-5b.1 precedent).
//! - **`deprecate_global_storage_ops = true`** path only:
//!   `state.call_v2` for `Call` / `CallGeneric` / Cat B
//!   extensions; `state.call_v2` for `VecImmBorrow` /
//!   `VecMutBorrow`. The deprecated paths (`state.call`,
//!   `state.vector_element_borrow`, `state.borrow_global`,
//!   `state.move_from`, `Bytecode::*GlobalDeprecated`,
//!   `Bytecode::ExistsDeprecated`, `Bytecode::MoveFromDeprecated`,
//!   `Bytecode::MoveToDeprecated`) hit `unreachable!` —
//!   structural-impossibility per Rule 5 deserializer-
//!   enforcement. Sub-shape 2 of structural-impossibility-
//!   checks pattern (continued use; per-mechanism counting).
//! - **`name_def_map` dropped.** Upstream uses it to resolve
//!   `acquired_resources` for the legacy `state.call` path;
//!   Adamant's `call_v2` path doesn't query `acquired_resources`
//!   so the map is unnecessary. Per Rule 5 +
//!   `deprecate_global_storage_ops = true`.
//! - **17 Adamant-extension reference rules per §6.2.1.4
//!   (Categories A/B/C/D)** — see [`verify_adamant_instr`].
//!   Cat A: pop / push `NonReference` per upstream's
//!   non-reference inherited-arm pattern. Cat B: reuse [`call`]
//!   helper (cross-pass-distinct 2nd instance of spec-text-to-
//!   shared-helper canonical principle; rule-of-three pending).
//!   Cat C / Cat D: fail open at borrow-graph layer (3rd
//!   cross-pass consistency instance of shielding-vs-runtime
//!   canonical pattern; rule-of-three threshold met).
//!
//! # Cross-pass-pipeline-dependency
//!
//! Same as [`super::abstract_state`]: reference-safety runs at
//! step 4 after type-safety. D-3 (stack), D-4 (locals), and
//! D-5a.1 (type-safety) preconditions make argument
//! `verifier.stack.pop()` infallible and operand types correct.

use std::num::NonZeroU64;

use adamant_bytecode_format::{
    Bytecode, CodeOffset, FunctionDefinitionIndex, FunctionHandle, SignatureIndex, SignatureToken,
    StructDefinition, StructFieldInformation, VariantDefinition,
};

use super::super::absint::{analyze_function, AbstractInterpreter, JoinResult};
use super::super::abstract_stack::AbstractStack;
use super::super::cfg::AdamantControlFlowGraph;
use super::abstract_state::{
    AbstractState, AbstractValue, ValueKind, STACK_INVARIANT_THREE_ANCHOR_STEM,
};
use crate::bytecode::{AdamantBytecode, BytecodeInstruction};
use crate::module::{AdamantCompiledModule, AdamantFunctionDefinition};
use crate::validator::error::{AdamantValidationError, BorrowViolationReason};

/// Three-anchor stem for the Rule-5 deserializer-enforcement
/// `unreachable!` arm (deprecated global-storage opcodes).
const DEPRECATED_GLOBAL_STORAGE_THREE_ANCHOR_STEM: &str =
    "Rule 5 deserializer-enforcement makes deprecated global-storage opcodes unreachable in valid \
     Adamant modules; should be unreachable in pipeline; if this fires from direct-unvalidated-\
     input caller, caller violates the deserializer-precondition";

/// Per-function reference-safety analysis state.
struct ReferenceSafetyAnalysis<'a> {
    module: &'a AdamantCompiledModule,
    fn_def_idx: FunctionDefinitionIndex,
    return_count: usize,
    stack: AbstractStack<AbstractValue>,
}

impl<'a> ReferenceSafetyAnalysis<'a> {
    fn new(
        module: &'a AdamantCompiledModule,
        fn_def_idx: FunctionDefinitionIndex,
        return_count: usize,
    ) -> Self {
        Self {
            module,
            fn_def_idx,
            return_count,
            stack: AbstractStack::new(),
        }
    }

    fn push(&mut self, v: AbstractValue) {
        self.stack
            .push(v)
            .unwrap_or_else(|e| panic!("{STACK_INVARIANT_THREE_ANCHOR_STEM}. push error: {e:?}"));
    }

    fn push_n(&mut self, v: AbstractValue, n: u64) {
        self.stack
            .push_n(v, n)
            .unwrap_or_else(|e| panic!("{STACK_INVARIANT_THREE_ANCHOR_STEM}. push_n error: {e:?}"));
    }

    fn pop(&mut self) -> AbstractValue {
        self.stack
            .pop()
            .unwrap_or_else(|e| panic!("{STACK_INVARIANT_THREE_ANCHOR_STEM}. pop error: {e:?}"))
    }
}

/// Verify reference safety for one function body. Public entry
/// point consumed by [`super::super::verify_function_bodies`].
pub(in crate::validator::function_pass) fn verify_function(
    module: &AdamantCompiledModule,
    fn_def_idx: FunctionDefinitionIndex,
    function_definition: &AdamantFunctionDefinition,
    code: &[BytecodeInstruction],
    cfg: &AdamantControlFlowGraph,
) -> Result<(), AdamantValidationError> {
    let function_handle = resolve_function_handle(module, function_definition);
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
    let return_sig = &module.signatures[return_idx];

    let initial_state = AbstractState::new(fn_def_idx, parameters, locals);
    let mut verifier = ReferenceSafetyAnalysis::new(module, fn_def_idx, return_sig.0.len());

    analyze_function(&mut verifier, cfg, code, initial_state)?;
    Ok(())
}

fn resolve_function_handle<'a>(
    module: &'a AdamantCompiledModule,
    function_definition: &AdamantFunctionDefinition,
) -> &'a FunctionHandle {
    let handle_idx = function_definition.function.0 as usize;
    debug_assert!(handle_idx < module.function_handles.len());
    &module.function_handles[handle_idx]
}

/// Call-helper shared across `Call`, `CallGeneric`, `InvokeShielded`,
/// `InvokeTransparent`. Cross-pass-distinct 2nd instance of
/// spec-text-to-shared-helper canonical principle (per §6.2.1.4
/// line 408 verbatim: "treat reference inputs and outputs of
/// `InvokeShielded` exactly as they would for an inherited
/// `Call`").
fn call(
    verifier: &mut ReferenceSafetyAnalysis<'_>,
    state: &mut AbstractState,
    offset: CodeOffset,
    function_handle: &FunctionHandle,
) -> Result<(), AdamantValidationError> {
    let parameters_idx = function_handle.parameters.0 as usize;
    debug_assert!(parameters_idx < verifier.module.signatures.len());
    let parameters = verifier.module.signatures[parameters_idx].clone();
    let return_idx = function_handle.return_.0 as usize;
    debug_assert!(return_idx < verifier.module.signatures.len());
    let return_sig = verifier.module.signatures[return_idx].clone();

    // Pop one argument per parameter; reverse order is
    // upstream's pattern.
    let mut arguments: Vec<AbstractValue> = parameters.0.iter().map(|_| verifier.pop()).collect();
    arguments.reverse();

    // Build ValueKind list from return signature.
    let return_kinds: Vec<ValueKind> = return_sig
        .0
        .iter()
        .map(|ty| match ty {
            SignatureToken::Reference(_) => ValueKind::Reference(false),
            SignatureToken::MutableReference(_) => ValueKind::Reference(true),
            _ => ValueKind::NonReference,
        })
        .collect();

    let values = state.call_v2(
        offset,
        arguments,
        &return_kinds,
        BorrowViolationReason::CallTransfersBorrowedMutable,
    )?;
    for value in values {
        verifier.push(value);
    }
    Ok(())
}

fn num_fields(struct_def: &StructDefinition) -> usize {
    match &struct_def.field_information {
        StructFieldInformation::Native => 0,
        StructFieldInformation::Declared(fields) => fields.len(),
    }
}

fn pack_struct(verifier: &mut ReferenceSafetyAnalysis<'_>, struct_def: &StructDefinition) {
    for _ in 0..num_fields(struct_def) {
        let popped = verifier.pop();
        debug_assert!(
            popped.is_value(),
            "{STACK_INVARIANT_THREE_ANCHOR_STEM}. pack_struct popped non-value"
        );
    }
    verifier.push(AbstractValue::NonReference);
}

fn unpack_struct(verifier: &mut ReferenceSafetyAnalysis<'_>, struct_def: &StructDefinition) {
    let popped = verifier.pop();
    debug_assert!(
        popped.is_value(),
        "{STACK_INVARIANT_THREE_ANCHOR_STEM}. unpack_struct popped non-value"
    );
    let count = u64::try_from(num_fields(struct_def))
        .expect("struct field count fits u64 per binary-format limits");
    verifier.push_n(AbstractValue::NonReference, count);
}

fn pack_enum_variant(verifier: &mut ReferenceSafetyAnalysis<'_>, variant_def: &VariantDefinition) {
    for _ in 0..variant_def.fields.len() {
        let popped = verifier.pop();
        debug_assert!(
            popped.is_value(),
            "{STACK_INVARIANT_THREE_ANCHOR_STEM}. pack_enum_variant popped non-value"
        );
    }
    verifier.push(AbstractValue::NonReference);
}

fn unpack_enum_variant(
    verifier: &mut ReferenceSafetyAnalysis<'_>,
    variant_def: &VariantDefinition,
) {
    let popped = verifier.pop();
    debug_assert!(
        popped.is_value(),
        "{STACK_INVARIANT_THREE_ANCHOR_STEM}. unpack_enum_variant popped non-value"
    );
    let count = u64::try_from(variant_def.fields.len())
        .expect("variant field count fits u64 per binary-format limits");
    verifier.push_n(AbstractValue::NonReference, count);
}

fn vec_element_type(verifier: &ReferenceSafetyAnalysis<'_>, idx: SignatureIndex) -> SignatureToken {
    let sig_idx = idx.0 as usize;
    debug_assert!(sig_idx < verifier.module.signatures.len());
    verifier.module.signatures[sig_idx]
        .0
        .first()
        .cloned()
        .unwrap_or_else(|| {
            panic!(
                "{STACK_INVARIANT_THREE_ANCHOR_STEM}. vec_element_type called on empty signature; \
             signature_checker pre-condition violated"
            )
        })
}

/// Helper that pops a `ref_id()` from the abstract stack with a
/// three-anchor panic on missing-reference (type-safety
/// precondition).
fn pop_ref_id(verifier: &mut ReferenceSafetyAnalysis<'_>) -> super::borrow_graph::RefID {
    verifier.pop().ref_id().unwrap_or_else(|| {
        panic!(
            "{STACK_INVARIANT_THREE_ANCHOR_STEM}. pop_ref_id called when top-of-stack was \
             non-reference; type-safety pre-condition violated"
        )
    })
}

#[allow(
    clippy::too_many_lines,
    clippy::match_same_arms,
    reason = "byte-faithful per-instruction table mirroring upstream's `execute_inner`; \
              merging same-result arms would lose the per-instruction audit anchor"
)]
fn execute_inherited_instr(
    verifier: &mut ReferenceSafetyAnalysis<'_>,
    state: &mut AbstractState,
    bytecode: &Bytecode,
    offset: CodeOffset,
) -> Result<(), AdamantValidationError> {
    use SignatureToken as ST;
    match bytecode {
        Bytecode::Pop => state.release_value(verifier.pop()),

        Bytecode::CopyLoc(local) => {
            let value = state.copy_loc(offset, *local)?;
            verifier.push(value);
        }
        Bytecode::MoveLoc(local) => {
            let value = state.move_loc(offset, *local)?;
            verifier.push(value);
        }
        Bytecode::StLoc(local) => {
            let value = verifier.pop();
            state.st_loc(offset, *local, value)?;
        }

        Bytecode::FreezeRef => {
            let id = pop_ref_id(verifier);
            let frozen = state.freeze_ref(offset, id)?;
            verifier.push(frozen);
        }

        Bytecode::Eq | Bytecode::Neq => {
            let v1 = verifier.pop();
            let v2 = verifier.pop();
            let value = state.comparison(offset, v1, v2)?;
            verifier.push(value);
        }

        Bytecode::ReadRef => {
            let id = pop_ref_id(verifier);
            let value = state.read_ref(offset, id)?;
            verifier.push(value);
        }
        Bytecode::WriteRef => {
            let id = pop_ref_id(verifier);
            let val_operand = verifier.pop();
            debug_assert!(
                val_operand.is_value(),
                "{STACK_INVARIANT_THREE_ANCHOR_STEM}. WriteRef value operand was a reference"
            );
            state.write_ref(offset, id)?;
        }

        Bytecode::MutBorrowLoc(local) => {
            let value = state.borrow_loc(offset, true, *local)?;
            verifier.push(value);
        }
        Bytecode::ImmBorrowLoc(local) => {
            let value = state.borrow_loc(offset, false, *local)?;
            verifier.push(value);
        }

        Bytecode::MutBorrowField(field_handle_index) => {
            let id = pop_ref_id(verifier);
            let value = state.borrow_field(offset, true, id, *field_handle_index)?;
            verifier.push(value);
        }
        Bytecode::MutBorrowFieldGeneric(field_inst_index) => {
            let inst_idx = field_inst_index.0 as usize;
            debug_assert!(inst_idx < verifier.module.field_instantiations.len());
            let field_inst = verifier.module.field_instantiations[inst_idx].clone();
            let id = pop_ref_id(verifier);
            let value = state.borrow_field(offset, true, id, field_inst.handle)?;
            verifier.push(value);
        }
        Bytecode::ImmBorrowField(field_handle_index) => {
            let id = pop_ref_id(verifier);
            let value = state.borrow_field(offset, false, id, *field_handle_index)?;
            verifier.push(value);
        }
        Bytecode::ImmBorrowFieldGeneric(field_inst_index) => {
            let inst_idx = field_inst_index.0 as usize;
            debug_assert!(inst_idx < verifier.module.field_instantiations.len());
            let field_inst = verifier.module.field_instantiations[inst_idx].clone();
            let id = pop_ref_id(verifier);
            let value = state.borrow_field(offset, false, id, field_inst.handle)?;
            verifier.push(value);
        }

        Bytecode::Call(idx) => {
            let handle_idx = idx.0 as usize;
            debug_assert!(handle_idx < verifier.module.function_handles.len());
            let function_handle = verifier.module.function_handles[handle_idx].clone();
            call(verifier, state, offset, &function_handle)?;
        }
        Bytecode::CallGeneric(idx) => {
            let inst_idx = idx.0 as usize;
            debug_assert!(inst_idx < verifier.module.function_instantiations.len());
            let func_inst = verifier.module.function_instantiations[inst_idx].clone();
            let handle_idx = func_inst.handle.0 as usize;
            debug_assert!(handle_idx < verifier.module.function_handles.len());
            let function_handle = verifier.module.function_handles[handle_idx].clone();
            call(verifier, state, offset, &function_handle)?;
        }

        Bytecode::Ret => {
            let mut return_values = Vec::with_capacity(verifier.return_count);
            for _ in 0..verifier.return_count {
                return_values.push(verifier.pop());
            }
            return_values.reverse();
            state.ret(offset, return_values)?;
        }

        Bytecode::Branch(_) | Bytecode::Nop => {}

        Bytecode::CastU8
        | Bytecode::CastU16
        | Bytecode::CastU32
        | Bytecode::CastU64
        | Bytecode::CastU128
        | Bytecode::CastU256
        | Bytecode::Not => {}

        Bytecode::BrTrue(_) | Bytecode::BrFalse(_) | Bytecode::Abort => {
            let popped = verifier.pop();
            debug_assert!(
                popped.is_value(),
                "{STACK_INVARIANT_THREE_ANCHOR_STEM}. BrTrue/BrFalse/Abort operand was a reference"
            );
        }

        Bytecode::LdTrue | Bytecode::LdFalse => {
            verifier.push(state.value_for(&ST::Bool));
        }
        Bytecode::LdU8(_) => verifier.push(state.value_for(&ST::U8)),
        Bytecode::LdU16(_) => verifier.push(state.value_for(&ST::U16)),
        Bytecode::LdU32(_) => verifier.push(state.value_for(&ST::U32)),
        Bytecode::LdU64(_) => verifier.push(state.value_for(&ST::U64)),
        Bytecode::LdU128(_) => verifier.push(state.value_for(&ST::U128)),
        Bytecode::LdU256(_) => verifier.push(state.value_for(&ST::U256)),
        Bytecode::LdConst(idx) => {
            let const_idx = idx.0 as usize;
            debug_assert!(const_idx < verifier.module.constant_pool.len());
            let signature = verifier.module.constant_pool[const_idx].type_.clone();
            verifier.push(state.value_for(&signature));
        }

        Bytecode::Add
        | Bytecode::Sub
        | Bytecode::Mul
        | Bytecode::Mod
        | Bytecode::Div
        | Bytecode::BitOr
        | Bytecode::BitAnd
        | Bytecode::Xor
        | Bytecode::Shl
        | Bytecode::Shr
        | Bytecode::Or
        | Bytecode::And
        | Bytecode::Lt
        | Bytecode::Gt
        | Bytecode::Le
        | Bytecode::Ge => {
            let v1 = verifier.pop();
            let v2 = verifier.pop();
            debug_assert!(v1.is_value() && v2.is_value());
            verifier.push(AbstractValue::NonReference);
        }

        Bytecode::Pack(idx) => {
            let def_idx = idx.0 as usize;
            debug_assert!(def_idx < verifier.module.struct_defs.len());
            let struct_def = verifier.module.struct_defs[def_idx].clone();
            pack_struct(verifier, &struct_def);
        }
        Bytecode::PackGeneric(idx) => {
            let inst_idx = idx.0 as usize;
            debug_assert!(inst_idx < verifier.module.struct_def_instantiations.len());
            let struct_inst = verifier.module.struct_def_instantiations[inst_idx].clone();
            let def_idx = struct_inst.def.0 as usize;
            debug_assert!(def_idx < verifier.module.struct_defs.len());
            let struct_def = verifier.module.struct_defs[def_idx].clone();
            pack_struct(verifier, &struct_def);
        }
        Bytecode::Unpack(idx) => {
            let def_idx = idx.0 as usize;
            debug_assert!(def_idx < verifier.module.struct_defs.len());
            let struct_def = verifier.module.struct_defs[def_idx].clone();
            unpack_struct(verifier, &struct_def);
        }
        Bytecode::UnpackGeneric(idx) => {
            let inst_idx = idx.0 as usize;
            debug_assert!(inst_idx < verifier.module.struct_def_instantiations.len());
            let struct_inst = verifier.module.struct_def_instantiations[inst_idx].clone();
            let def_idx = struct_inst.def.0 as usize;
            debug_assert!(def_idx < verifier.module.struct_defs.len());
            let struct_def = verifier.module.struct_defs[def_idx].clone();
            unpack_struct(verifier, &struct_def);
        }

        Bytecode::VecPack(idx, num) => {
            if let Some(num_to_pop) = NonZeroU64::new(*num) {
                let result = verifier.stack.pop_eq_n(num_to_pop);
                let abs_value = result.unwrap_or_else(|e| {
                    panic!("{STACK_INVARIANT_THREE_ANCHOR_STEM}. VecPack pop_eq_n error: {e:?}")
                });
                debug_assert!(
                    abs_value.is_value(),
                    "{STACK_INVARIANT_THREE_ANCHOR_STEM}. VecPack popped non-value"
                );
            }
            let element_type = vec_element_type(verifier, *idx);
            verifier.push(state.value_for(&ST::Vector(Box::new(element_type))));
        }

        Bytecode::VecLen(_) => {
            let vec_ref = verifier.pop();
            state.vector_op(offset, vec_ref, false)?;
            verifier.push(state.value_for(&ST::U64));
        }

        Bytecode::VecImmBorrow(_) => {
            let popped_idx = verifier.pop();
            debug_assert!(
                popped_idx.is_value(),
                "{STACK_INVARIANT_THREE_ANCHOR_STEM}. VecImmBorrow index was a reference"
            );
            let vec_ref = verifier.pop();
            let values = state.call_v2(
                offset,
                vec![vec_ref],
                &[ValueKind::Reference(false)],
                BorrowViolationReason::VecElementHasMutableBorrow,
            )?;
            debug_assert!(values.len() == 1);
            for value in values {
                verifier.push(value);
            }
        }
        Bytecode::VecMutBorrow(_) => {
            let popped_idx = verifier.pop();
            debug_assert!(
                popped_idx.is_value(),
                "{STACK_INVARIANT_THREE_ANCHOR_STEM}. VecMutBorrow index was a reference"
            );
            let vec_ref = verifier.pop();
            let values = state.call_v2(
                offset,
                vec![vec_ref],
                &[ValueKind::Reference(true)],
                BorrowViolationReason::VecElementHasMutableBorrow,
            )?;
            debug_assert!(values.len() == 1);
            for value in values {
                verifier.push(value);
            }
        }

        Bytecode::VecPushBack(_) => {
            let popped_elem = verifier.pop();
            debug_assert!(
                popped_elem.is_value(),
                "{STACK_INVARIANT_THREE_ANCHOR_STEM}. VecPushBack elem was a reference"
            );
            let vec_ref = verifier.pop();
            state.vector_op(offset, vec_ref, true)?;
        }

        Bytecode::VecPopBack(idx) => {
            let vec_ref = verifier.pop();
            state.vector_op(offset, vec_ref, true)?;
            let element_type = vec_element_type(verifier, *idx);
            verifier.push(state.value_for(&element_type));
        }

        Bytecode::VecUnpack(idx, num) => {
            let popped = verifier.pop();
            debug_assert!(
                popped.is_value(),
                "{STACK_INVARIANT_THREE_ANCHOR_STEM}. VecUnpack popped non-value"
            );
            let element_type = vec_element_type(verifier, *idx);
            verifier.push_n(state.value_for(&element_type), *num);
        }

        Bytecode::VecSwap(_) => {
            let popped_2 = verifier.pop();
            let popped_1 = verifier.pop();
            debug_assert!(popped_1.is_value() && popped_2.is_value());
            let vec_ref = verifier.pop();
            state.vector_op(offset, vec_ref, true)?;
        }

        Bytecode::PackVariant(vidx) => {
            let h_idx = vidx.0 as usize;
            debug_assert!(h_idx < verifier.module.variant_handles.len());
            let handle = verifier.module.variant_handles[h_idx].clone();
            let enum_idx = handle.enum_def.0 as usize;
            debug_assert!(enum_idx < verifier.module.enum_defs.len());
            let enum_def = verifier.module.enum_defs[enum_idx].clone();
            let variant_def = enum_def.variants[handle.variant as usize].clone();
            pack_enum_variant(verifier, &variant_def);
        }
        Bytecode::PackVariantGeneric(vidx) => {
            let h_idx = vidx.0 as usize;
            debug_assert!(h_idx < verifier.module.variant_instantiation_handles.len());
            let handle = verifier.module.variant_instantiation_handles[h_idx].clone();
            let inst_idx = handle.enum_def.0 as usize;
            let enum_inst = verifier.module.enum_def_instantiations[inst_idx].clone();
            let enum_idx = enum_inst.def.0 as usize;
            let enum_def = verifier.module.enum_defs[enum_idx].clone();
            let variant_def = enum_def.variants[handle.variant as usize].clone();
            pack_enum_variant(verifier, &variant_def);
        }
        Bytecode::UnpackVariant(vidx) => {
            let h_idx = vidx.0 as usize;
            let handle = verifier.module.variant_handles[h_idx].clone();
            let enum_idx = handle.enum_def.0 as usize;
            let enum_def = verifier.module.enum_defs[enum_idx].clone();
            let variant_def = enum_def.variants[handle.variant as usize].clone();
            unpack_enum_variant(verifier, &variant_def);
        }
        Bytecode::UnpackVariantGeneric(vidx) => {
            let h_idx = vidx.0 as usize;
            let handle = verifier.module.variant_instantiation_handles[h_idx].clone();
            let inst_idx = handle.enum_def.0 as usize;
            let enum_inst = verifier.module.enum_def_instantiations[inst_idx].clone();
            let enum_idx = enum_inst.def.0 as usize;
            let enum_def = verifier.module.enum_defs[enum_idx].clone();
            let variant_def = enum_def.variants[handle.variant as usize].clone();
            unpack_enum_variant(verifier, &variant_def);
        }
        Bytecode::UnpackVariantImmRef(vidx) => {
            unpack_variant_ref(verifier, state, offset, *vidx, false)?;
        }
        Bytecode::UnpackVariantMutRef(vidx) => {
            unpack_variant_ref(verifier, state, offset, *vidx, true)?;
        }
        Bytecode::UnpackVariantGenericImmRef(vidx) => {
            unpack_variant_generic_ref(verifier, state, offset, *vidx, false)?;
        }
        Bytecode::UnpackVariantGenericMutRef(vidx) => {
            unpack_variant_generic_ref(verifier, state, offset, *vidx, true)?;
        }

        Bytecode::VariantSwitch(_) => {
            state.release_value(verifier.pop());
        }

        // Sub-shape 2 of structural-impossibility-checks
        // (continued use; per-mechanism counting). 10 deprecated
        // global-storage opcodes consolidated into one match arm.
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
    }
    Ok(())
}

fn unpack_variant_ref(
    verifier: &mut ReferenceSafetyAnalysis<'_>,
    state: &mut AbstractState,
    offset: CodeOffset,
    vidx: adamant_bytecode_format::VariantHandleIndex,
    mut_: bool,
) -> Result<(), AdamantValidationError> {
    let h_idx = vidx.0 as usize;
    debug_assert!(h_idx < verifier.module.variant_handles.len());
    let handle = verifier.module.variant_handles[h_idx].clone();
    let enum_idx = handle.enum_def.0 as usize;
    let enum_def = verifier.module.enum_defs[enum_idx].clone();
    let variant_def = enum_def.variants[handle.variant as usize].clone();
    let id = pop_ref_id(verifier);
    let values = state.unpack_enum_variant_ref(
        offset,
        handle.enum_def,
        handle.variant,
        &variant_def,
        mut_,
        id,
    )?;
    for value in values {
        verifier.push(value);
    }
    Ok(())
}

fn unpack_variant_generic_ref(
    verifier: &mut ReferenceSafetyAnalysis<'_>,
    state: &mut AbstractState,
    offset: CodeOffset,
    vidx: adamant_bytecode_format::VariantInstantiationHandleIndex,
    mut_: bool,
) -> Result<(), AdamantValidationError> {
    let h_idx = vidx.0 as usize;
    debug_assert!(h_idx < verifier.module.variant_instantiation_handles.len());
    let handle = verifier.module.variant_instantiation_handles[h_idx].clone();
    let inst_idx = handle.enum_def.0 as usize;
    let enum_inst = verifier.module.enum_def_instantiations[inst_idx].clone();
    let enum_idx = enum_inst.def.0 as usize;
    let enum_def = verifier.module.enum_defs[enum_idx].clone();
    let variant_def = enum_def.variants[handle.variant as usize].clone();
    let id = pop_ref_id(verifier);
    // For generic ref-unpack, the enum-def index passed to
    // `add_variant_field_borrow` is the underlying
    // `EnumDefinitionIndex`, not the instantiation index.
    let values = state.unpack_enum_variant_ref(
        offset,
        enum_inst.def,
        handle.variant,
        &variant_def,
        mut_,
        id,
    )?;
    for value in values {
        verifier.push(value);
    }
    Ok(())
}

/// Per-instruction transfer for Adamant extensions per
/// §6.2.1.4. Cat A (12) pop / push `NonReference`; Cat B (2)
/// reuse [`call`] helper; Cat C (2) and Cat D (1) fail open at
/// the borrow-graph layer.
#[allow(
    clippy::match_same_arms,
    reason = "byte-faithful per-extension table mirroring §6.2.1.4 lines 408-423; \
              merging same-result arms would lose the per-extension audit anchor"
)]
fn execute_adamant_instr(
    verifier: &mut ReferenceSafetyAnalysis<'_>,
    state: &mut AbstractState,
    instr: &AdamantBytecode,
    offset: CodeOffset,
) -> Result<(), AdamantValidationError> {
    match instr {
        // Category B: parametric in FunctionHandle (cross-pass-
        // distinct 2nd instance of spec-text-to-shared-helper
        // canonical principle).
        AdamantBytecode::InvokeShielded(idx) | AdamantBytecode::InvokeTransparent(idx) => {
            let handle_idx = idx.0 as usize;
            debug_assert!(handle_idx < verifier.module.function_handles.len());
            let function_handle = verifier.module.function_handles[handle_idx].clone();
            call(verifier, state, offset, &function_handle)?;
        }

        // Category C / Category D: fail open at borrow-graph
        // layer (3rd cross-pass consistency instance of
        // shielding-vs-runtime canonical pattern; rule-of-three
        // threshold met). No pop / no push at this layer;
        // runtime carries the binding via §7 / §8.5.
        AdamantBytecode::GenerateProof(_)
        | AdamantBytecode::VerifyProof(_)
        | AdamantBytecode::RecursiveVerify => {}

        // Category A: hashes / KZG / view-key — pop one
        // NonReference, push one NonReference.
        AdamantBytecode::Sha3_256
        | AdamantBytecode::Blake3
        | AdamantBytecode::KzgCommit
        | AdamantBytecode::ReleaseSubViewKey => {
            let popped = verifier.pop();
            debug_assert!(
                popped.is_value(),
                "{STACK_INVARIANT_THREE_ANCHOR_STEM}. Cat A hash/KZG/view-key popped non-value"
            );
            verifier.push(AbstractValue::NonReference);
        }

        // Category A: signature verifies — pop three
        // NonReference, push one NonReference.
        AdamantBytecode::KzgVerify
        | AdamantBytecode::Ed25519Verify
        | AdamantBytecode::MlDsaVerify65
        | AdamantBytecode::MlDsaVerify87
        | AdamantBytecode::BlsVerify => {
            for _ in 0..3 {
                let popped = verifier.pop();
                debug_assert!(
                    popped.is_value(),
                    "{STACK_INVARIANT_THREE_ANCHOR_STEM}. Cat A sig-verify popped non-value"
                );
            }
            verifier.push(AbstractValue::NonReference);
        }

        // Category A: ChargeGas — pop one NonReference (u64).
        AdamantBytecode::ChargeGas(_) => {
            let popped = verifier.pop();
            debug_assert!(
                popped.is_value(),
                "{STACK_INVARIANT_THREE_ANCHOR_STEM}. ChargeGas popped non-value"
            );
        }

        // Category A: RemainingGas — push one NonReference (u64).
        AdamantBytecode::RemainingGas(_) => {
            verifier.push(AbstractValue::NonReference);
        }

        // Category A: OutOfGas — no stack effect.
        AdamantBytecode::OutOfGas => {}
    }
    Ok(())
}

impl AbstractInterpreter for ReferenceSafetyAnalysis<'_> {
    type State = AbstractState;

    fn join(
        &mut self,
        pre: &mut Self::State,
        post: &Self::State,
    ) -> Result<JoinResult, AdamantValidationError> {
        Ok(pre.join_into(post))
    }

    fn execute(
        &mut self,
        _block_id: CodeOffset,
        bounds: (CodeOffset, CodeOffset),
        state: &mut Self::State,
        offset: CodeOffset,
        instr: &BytecodeInstruction,
    ) -> Result<(), AdamantValidationError> {
        match instr {
            BytecodeInstruction::Inherited(b) => {
                execute_inherited_instr(self, state, b, offset)?;
            }
            BytecodeInstruction::Adamant(a) => {
                execute_adamant_instr(self, state, a, offset)?;
            }
        }
        // At end of block: stack must be empty (mirrors
        // upstream's `safe_assert!(self.stack.is_empty())` at
        // last_index) and state canonicalises before joins.
        let (_first_index, last_index) = bounds;
        if offset == last_index {
            debug_assert!(
                self.stack.is_empty(),
                "{STACK_INVARIANT_THREE_ANCHOR_STEM}. abstract stack not empty at end-of-block"
            );
            *state = state.construct_canonical_state();
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    //! Layer A unit tests for the reference-safety pass at
    //! D-5b.2.
    //!
    //! Coverage:
    //! - 13 `BorrowViolationReason` sub-reason audit pins (one
    //!   negative test per sub-reason, exercising distinct
    //!   borrow-graph paths).
    //! - Per-instruction-arm coverage for inherited bytecode.
    //! - Adamant-extension dispatch (Cat A pop/push
    //!   `NonReference`; Cat B reuse `call`; Cat C/D fail open).
    //! - Happy paths, eager-error semantics.
    //!
    //! Tests invoke [`verify_function`] directly. The
    //! orchestration chain wire-in landing in
    //! [`super::super::verify_function_bodies`] is exercised
    //! by `function_pass::tests` smoke tests rather than here.
    #![allow(clippy::too_many_lines, reason = "test fixtures are naturally verbose")]
    #![allow(
        clippy::doc_markdown,
        reason = "test docs reference instruction names verbatim; backticks add noise without \
                  improving clarity"
    )]

    use super::*;
    use crate::bytecode::{AdamantBytecode, BytecodeInstruction, CircuitId, GasDimension};
    use crate::module::{AdamantCodeUnit, AdamantCompiledModule, AdamantFunctionDefinition};
    use adamant_bytecode_format::{
        Ability, AbilitySet, AddressIdentifierIndex, DatatypeHandle, DatatypeHandleIndex,
        FieldDefinition, FieldHandle, FieldHandleIndex, FunctionHandleIndex, Identifier,
        IdentifierIndex, ModuleHandle, ModuleHandleIndex, Signature, SignatureIndex,
        SignatureToken, StructDefinition, StructDefinitionIndex, StructFieldInformation,
        TypeSignature, Visibility,
    };

    // --- builders ---

    fn ld_u64(v: u64) -> BytecodeInstruction {
        BytecodeInstruction::Inherited(Bytecode::LdU64(v))
    }

    fn ld_true() -> BytecodeInstruction {
        BytecodeInstruction::Inherited(Bytecode::LdTrue)
    }

    fn pop_inst() -> BytecodeInstruction {
        BytecodeInstruction::Inherited(Bytecode::Pop)
    }

    fn ret_inst() -> BytecodeInstruction {
        BytecodeInstruction::Inherited(Bytecode::Ret)
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

    fn imm_borrow_loc(idx: u8) -> BytecodeInstruction {
        BytecodeInstruction::Inherited(Bytecode::ImmBorrowLoc(idx))
    }

    fn mut_borrow_loc(idx: u8) -> BytecodeInstruction {
        BytecodeInstruction::Inherited(Bytecode::MutBorrowLoc(idx))
    }

    fn read_ref() -> BytecodeInstruction {
        BytecodeInstruction::Inherited(Bytecode::ReadRef)
    }

    fn write_ref() -> BytecodeInstruction {
        BytecodeInstruction::Inherited(Bytecode::WriteRef)
    }

    fn freeze_ref() -> BytecodeInstruction {
        BytecodeInstruction::Inherited(Bytecode::FreezeRef)
    }

    fn extension(a: AdamantBytecode) -> BytecodeInstruction {
        BytecodeInstruction::Adamant(a)
    }

    /// Build a one-function module with the given param/local/
    /// return signatures and body.
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
        m.function_handles
            .push(adamant_bytecode_format::FunctionHandle {
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

    /// Add an extra function handle (caller-supplied
    /// param/return signatures). Returns its
    /// `FunctionHandleIndex`.
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
        m.function_handles
            .push(adamant_bytecode_format::FunctionHandle {
                module: ModuleHandleIndex(0),
                name: IdentifierIndex(name_id),
                parameters: SignatureIndex(p_idx),
                return_: SignatureIndex(r_idx),
                type_parameters: vec![],
            });
        FunctionHandleIndex(h_idx)
    }

    /// Add a struct with one declared u64 field.
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

    // ===========================================================
    // Happy paths
    // ===========================================================

    #[test]
    fn empty_function_returns_ok() {
        let m = module_with_function(vec![], vec![], vec![], vec![ret_inst()]);
        run(&m).expect("Ret on empty signature OK");
    }

    #[test]
    fn ld_u64_pop_ret_ok() {
        let m = module_with_function(
            vec![],
            vec![],
            vec![],
            vec![ld_u64(42), pop_inst(), ret_inst()],
        );
        run(&m).expect("LdU64 + Pop + Ret OK");
    }

    #[test]
    fn imm_borrow_loc_then_read_ref_then_pop() {
        let m = module_with_function(
            vec![SignatureToken::U64],
            vec![],
            vec![],
            vec![imm_borrow_loc(0), read_ref(), pop_inst(), ret_inst()],
        );
        run(&m).expect("ImmBorrowLoc + ReadRef + Pop OK");
    }

    #[test]
    fn mut_borrow_loc_then_write_ref() {
        let m = module_with_function(
            vec![],
            vec![SignatureToken::U64],
            vec![],
            vec![ld_u64(7), mut_borrow_loc(0), write_ref(), ret_inst()],
        );
        run(&m).expect("MutBorrowLoc + WriteRef OK");
    }

    #[test]
    fn ret_with_value_param_ok() {
        let m = module_with_function(
            vec![SignatureToken::U64],
            vec![],
            vec![SignatureToken::U64],
            vec![mv_loc(0), ret_inst()],
        );
        run(&m).expect("Ret with u64 param OK");
    }

    // ===========================================================
    // 13 BorrowViolationReason audit pins
    // ===========================================================

    /// `CopyLocBorrowed` audit pin: CopyLoc of a non-ref local
    /// while the local is mutably borrowed.
    #[test]
    fn copy_loc_while_mut_borrowed_rejected() {
        // params[0]: u64, locals: empty.
        // body: mut_borrow_loc(0) (creates &mut to local 0)
        //       cp_loc(0) (CopyLoc of local 0 — should fail)
        //       ...
        let m = module_with_function(
            vec![SignatureToken::U64],
            vec![],
            vec![],
            vec![
                mut_borrow_loc(0),
                cp_loc(0),
                pop_inst(),  // pop the copy
                write_ref(), // consume the ref to balance stack
                ret_inst(),
            ],
        );
        match run(&m) {
            Err(AdamantValidationError::BorrowViolation {
                reason: BorrowViolationReason::CopyLocBorrowed,
                ..
            }) => {}
            other => panic!("expected CopyLocBorrowed, got {other:?}"),
        }
    }

    /// `MoveLocBorrowed` audit pin.
    #[test]
    fn move_loc_while_borrowed_rejected() {
        let m = module_with_function(
            vec![SignatureToken::U64],
            vec![],
            vec![],
            vec![
                imm_borrow_loc(0),
                mv_loc(0),
                pop_inst(),
                pop_inst(),
                ret_inst(),
            ],
        );
        match run(&m) {
            Err(AdamantValidationError::BorrowViolation {
                reason: BorrowViolationReason::MoveLocBorrowed,
                ..
            }) => {}
            other => panic!("expected MoveLocBorrowed, got {other:?}"),
        }
    }

    /// `StLocDestroyBorrowed` audit pin: StLoc to a local that
    /// has an outstanding borrow.
    #[test]
    fn st_loc_while_borrowed_rejected() {
        let m = module_with_function(
            vec![],
            vec![SignatureToken::U64],
            vec![],
            vec![
                imm_borrow_loc(0),
                ld_u64(7),
                st_loc(0),
                pop_inst(),
                ret_inst(),
            ],
        );
        match run(&m) {
            Err(AdamantValidationError::BorrowViolation {
                reason: BorrowViolationReason::StLocDestroyBorrowed,
                ..
            }) => {}
            other => panic!("expected StLocDestroyBorrowed, got {other:?}"),
        }
    }

    // E-6 closes the previously-deferred audit pins for the
    // 7 sub-reasons that need aliased-mutable-reference
    // setups: WriteRefHasBorrow, FreezeRefHasMutableBorrow,
    // ReadRefHasMutableBorrow, CallTransfersBorrowedMutable,
    // VecElementHasMutableBorrow, VecUpdateHasMutableBorrow,
    // RetBorrowedMutableReference. (Empirical-scope-inventory
    // grep at E-6 plan-gate corrected the D-5b.2 framing of
    // "6 of 13 deferred" to 7 of 13 — ReadRefHasMutableBorrow
    // is also deferred; the running-total drift discipline
    // operating at sub-reason-count level catches this. See
    // PROVENANCE.md "Phase 5/5b.5 closure" methodology
    // accumulation streams for the corrigendum.) Each fixture
    // uses the cp_loc-of-mutable-reference pattern (mirrors
    // borrow_field_with_outstanding_full_borrow_rejected at
    // D-5b.2) to create aliased &mut references on the stack
    // — the outstanding-mutable-borrow precondition for
    // is_writable / is_readable / is_freezable to fail.

    /// `BorrowLocHasBorrow` audit pin: ImmBorrowLoc on a local
    /// that's mutably borrowed.
    #[test]
    fn imm_borrow_loc_while_mut_borrowed_rejected() {
        let m = module_with_function(
            vec![SignatureToken::U64],
            vec![],
            vec![],
            vec![
                mut_borrow_loc(0),
                imm_borrow_loc(0),
                pop_inst(),
                pop_inst(),
                ret_inst(),
            ],
        );
        match run(&m) {
            Err(AdamantValidationError::BorrowViolation {
                reason: BorrowViolationReason::BorrowLocHasBorrow,
                ..
            }) => {}
            other => panic!("expected BorrowLocHasBorrow, got {other:?}"),
        }
    }

    /// `BorrowFieldHasMutableBorrow` audit pin: MutBorrowField
    /// on a parent reference that has full borrows outstanding.
    /// Constructs a reference that's been fully-borrowed via
    /// imm_borrow + mut_borrow_field overlap.
    #[test]
    fn borrow_field_with_outstanding_full_borrow_rejected() {
        let mut m = module_with_function(vec![], vec![], vec![], vec![ret_inst()]);
        let (s_token, _def_idx, fh_idx) = add_simple_struct(&mut m);
        // params[0]: &mut S
        m.signatures[0] = Signature(vec![SignatureToken::MutableReference(Box::new(s_token))]);
        m.function_defs[0].code = Some(AdamantCodeUnit {
            locals: SignatureIndex(1),
            code: vec![
                cp_loc(0), // ref A
                cp_loc(0), // ref B (creates full borrow on locals)
                BytecodeInstruction::Inherited(Bytecode::MutBorrowField(fh_idx)),
                pop_inst(),
                pop_inst(),
                ret_inst(),
            ],
            jump_tables: vec![],
        });
        match run(&m) {
            Err(AdamantValidationError::BorrowViolation {
                reason: BorrowViolationReason::BorrowFieldHasMutableBorrow,
                ..
            }) => {}
            other => panic!("expected BorrowFieldHasMutableBorrow, got {other:?}"),
        }
    }

    /// `RetWithBorrowedFrame` audit pin: Ret tries to return a
    /// reference to a local; frame destruction would invalidate
    /// the returned reference. Detected when the function's
    /// return signature includes a reference and the body's
    /// only effect is to take a borrow_loc and Ret it — the
    /// release phase doesn't release the on-stack ref, the
    /// frame still has the outgoing borrow edge, and
    /// `is_frame_safe_to_destroy` returns false.
    #[test]
    fn ret_while_local_borrowed_rejected() {
        let m = module_with_function(
            vec![SignatureToken::U64],
            vec![],
            vec![SignatureToken::MutableReference(Box::new(
                SignatureToken::U64,
            ))],
            vec![mut_borrow_loc(0), ret_inst()],
        );
        match run(&m) {
            Err(AdamantValidationError::BorrowViolation {
                reason: BorrowViolationReason::RetWithBorrowedFrame,
                ..
            }) => {}
            other => panic!("expected RetWithBorrowedFrame, got {other:?}"),
        }
    }

    // ===========================================================
    // Adamant-extension dispatch tests
    // ===========================================================

    /// Cat A: `Sha3_256` — pop NonReference, push NonReference.
    #[test]
    fn sha3_256_pops_nonref_pushes_nonref() {
        let m = module_with_function(
            vec![SignatureToken::Vector(Box::new(SignatureToken::U8))],
            vec![],
            vec![],
            vec![
                mv_loc(0),
                extension(AdamantBytecode::Sha3_256),
                pop_inst(),
                ret_inst(),
            ],
        );
        run(&m).expect("Sha3_256 pop/push NonReference OK");
    }

    /// Cat A: `Ed25519Verify` — pop 3 NonReference, push 1.
    #[test]
    fn ed25519_verify_pops_three_pushes_one() {
        let m = module_with_function(
            vec![SignatureToken::Vector(Box::new(SignatureToken::U8))],
            vec![],
            vec![],
            vec![
                cp_loc(0),
                cp_loc(0),
                cp_loc(0),
                extension(AdamantBytecode::Ed25519Verify),
                pop_inst(),
                ret_inst(),
            ],
        );
        run(&m).expect("Ed25519Verify pop/push OK");
    }

    /// Cat A: `ChargeGas` — pop NonReference (u64).
    #[test]
    fn charge_gas_pops_one() {
        let m = module_with_function(
            vec![],
            vec![],
            vec![],
            vec![
                ld_u64(100),
                extension(AdamantBytecode::ChargeGas(GasDimension::Computation)),
                ret_inst(),
            ],
        );
        run(&m).expect("ChargeGas pop OK");
    }

    /// Cat A: `RemainingGas` — push NonReference (u64).
    #[test]
    fn remaining_gas_pushes_one() {
        let m = module_with_function(
            vec![],
            vec![],
            vec![],
            vec![
                extension(AdamantBytecode::RemainingGas(GasDimension::Computation)),
                pop_inst(),
                ret_inst(),
            ],
        );
        run(&m).expect("RemainingGas push OK");
    }

    /// Cat A: `OutOfGas` — no stack effect.
    #[test]
    fn out_of_gas_no_effect() {
        let m = module_with_function(
            vec![],
            vec![],
            vec![],
            vec![extension(AdamantBytecode::OutOfGas), ret_inst()],
        );
        run(&m).expect("OutOfGas no effect OK");
    }

    /// Cat B: `InvokeShielded` — same shape as Call. Spec-text-
    /// to-shared-helper canonical principle cross-pass-distinct
    /// 2nd instance.
    #[test]
    fn invoke_shielded_via_call_helper() {
        let mut m = module_with_function(vec![], vec![], vec![], vec![ret_inst()]);
        let h = add_function_handle(&mut m, vec![SignatureToken::U64], vec![]);
        m.function_defs[0].code = Some(AdamantCodeUnit {
            locals: SignatureIndex(1),
            code: vec![
                ld_u64(42),
                extension(AdamantBytecode::InvokeShielded(h)),
                ret_inst(),
            ],
            jump_tables: vec![],
        });
        run(&m).expect("InvokeShielded via call helper OK");
    }

    /// Cat B: `InvokeTransparent` — same shape as Call.
    #[test]
    fn invoke_transparent_via_call_helper() {
        let mut m = module_with_function(vec![], vec![], vec![], vec![ret_inst()]);
        let h = add_function_handle(&mut m, vec![SignatureToken::U64], vec![]);
        m.function_defs[0].code = Some(AdamantCodeUnit {
            locals: SignatureIndex(1),
            code: vec![
                ld_u64(42),
                extension(AdamantBytecode::InvokeTransparent(h)),
                ret_inst(),
            ],
            jump_tables: vec![],
        });
        run(&m).expect("InvokeTransparent via call helper OK");
    }

    /// Cat C: `GenerateProof` — fail open (no pop / no push).
    /// Shielding-vs-runtime canonical pattern 3rd cross-pass
    /// consistency instance.
    #[test]
    fn generate_proof_fails_open_at_borrow_layer() {
        let m = module_with_function(
            vec![],
            vec![],
            vec![],
            vec![
                extension(AdamantBytecode::GenerateProof(CircuitId(0))),
                ret_inst(),
            ],
        );
        run(&m).expect("GenerateProof fails open at borrow layer");
    }

    /// Cat C: `VerifyProof` — fail open.
    #[test]
    fn verify_proof_fails_open_at_borrow_layer() {
        let m = module_with_function(
            vec![],
            vec![],
            vec![],
            vec![
                extension(AdamantBytecode::VerifyProof(CircuitId(0))),
                ret_inst(),
            ],
        );
        run(&m).expect("VerifyProof fails open at borrow layer");
    }

    /// Cat D: `RecursiveVerify` — fail open.
    #[test]
    fn recursive_verify_fails_open_at_borrow_layer() {
        let m = module_with_function(
            vec![],
            vec![],
            vec![],
            vec![extension(AdamantBytecode::RecursiveVerify), ret_inst()],
        );
        run(&m).expect("RecursiveVerify fails open at borrow layer");
    }

    // ----- E-6: Open Layer B gaps closure for the 7 deferred
    // BorrowViolationReason sub-reasons. Each fixture uses
    // the cp_loc-of-mutable-reference pattern to create
    // aliased &mut references on the stack — when the
    // targeted instruction operates on one of the aliases,
    // is_writable/is_readable/is_freezable returns false and
    // the corresponding BorrowViolationReason fires. -----

    /// `FreezeRefHasMutableBorrow` audit pin: FreezeRef on a
    /// &mut whose source has an outstanding mutable borrow.
    #[test]
    fn freeze_ref_with_outstanding_mut_borrow_rejected() {
        // params[0]: &mut u64; body: cp_loc(0) twice → two
        // &mut on stack aliasing param 0; FreezeRef pops one,
        // but the other &mut is outstanding.
        let m = module_with_function(
            vec![SignatureToken::MutableReference(Box::new(SignatureToken::U64))],
            vec![],
            vec![],
            vec![
                cp_loc(0),
                cp_loc(0),
                freeze_ref(),
                pop_inst(),
                pop_inst(),
                ret_inst(),
            ],
        );
        match run(&m) {
            Err(AdamantValidationError::BorrowViolation {
                reason: BorrowViolationReason::FreezeRefHasMutableBorrow,
                ..
            }) => {}
            other => panic!("expected FreezeRefHasMutableBorrow, got {other:?}"),
        }
    }

    /// `ReadRefHasMutableBorrow` audit pin: ReadRef on a &mut
    /// whose source has an outstanding mutable borrow.
    #[test]
    fn read_ref_with_outstanding_mut_borrow_rejected() {
        let m = module_with_function(
            vec![SignatureToken::MutableReference(Box::new(SignatureToken::U64))],
            vec![],
            vec![],
            vec![
                cp_loc(0),
                cp_loc(0),
                read_ref(),
                pop_inst(),
                pop_inst(),
                ret_inst(),
            ],
        );
        match run(&m) {
            Err(AdamantValidationError::BorrowViolation {
                reason: BorrowViolationReason::ReadRefHasMutableBorrow,
                ..
            }) => {}
            other => panic!("expected ReadRefHasMutableBorrow, got {other:?}"),
        }
    }

    /// `WriteRefHasBorrow` audit pin: WriteRef on a &mut whose
    /// source has an outstanding borrow. WriteRef expects
    /// `[val, ref]` with ref on top of stack (per the existing
    /// mut_borrow_loc_then_write_ref happy-path test); the
    /// fixture orders cp_loc, ld_u64, cp_loc to leave
    /// `[&mut[A], u64, &mut[B]]` on the stack — WriteRef pops
    /// &mut[B] (top) and u64 (below); &mut[A] remains as the
    /// outstanding aliased borrow on param 0.
    #[test]
    fn write_ref_with_outstanding_mut_borrow_rejected() {
        let m = module_with_function(
            vec![SignatureToken::MutableReference(Box::new(SignatureToken::U64))],
            vec![],
            vec![],
            vec![
                cp_loc(0),
                ld_u64(7),
                cp_loc(0),
                write_ref(),
                pop_inst(),
                ret_inst(),
            ],
        );
        match run(&m) {
            Err(AdamantValidationError::BorrowViolation {
                reason: BorrowViolationReason::WriteRefHasBorrow,
                ..
            }) => {}
            other => panic!("expected WriteRefHasBorrow, got {other:?}"),
        }
    }

    /// `CallTransfersBorrowedMutable` audit pin: Call passes
    /// a &mut argument that has an outstanding mutable borrow.
    #[test]
    fn call_transfers_borrowed_mutable_rejected() {
        let mut m = module_with_function(
            vec![SignatureToken::MutableReference(Box::new(SignatureToken::U64))],
            vec![],
            vec![],
            vec![ret_inst()],
        );
        // External 'g' takes &mut u64 and returns ().
        let g_handle = add_function_handle(
            &mut m,
            vec![SignatureToken::MutableReference(Box::new(SignatureToken::U64))],
            vec![],
        );
        m.function_defs[0].code = Some(AdamantCodeUnit {
            locals: SignatureIndex(1),
            code: vec![
                cp_loc(0),
                cp_loc(0),
                BytecodeInstruction::Inherited(Bytecode::Call(g_handle)),
                pop_inst(),
                ret_inst(),
            ],
            jump_tables: vec![],
        });
        match run(&m) {
            Err(AdamantValidationError::BorrowViolation {
                reason: BorrowViolationReason::CallTransfersBorrowedMutable,
                ..
            }) => {}
            other => panic!("expected CallTransfersBorrowedMutable, got {other:?}"),
        }
    }

    /// `VecElementHasMutableBorrow` audit pin: VecMutBorrow on
    /// a &mut Vec<T> whose source has an outstanding mutable
    /// borrow.
    #[test]
    fn vec_element_borrow_with_outstanding_mut_borrow_rejected() {
        let vec_t = SignatureToken::MutableReference(Box::new(SignatureToken::Vector(
            Box::new(SignatureToken::U64),
        )));
        // Inner-element type for VecMutBorrow operand: SI(2).
        let mut m = module_with_function(vec![vec_t], vec![], vec![], vec![ret_inst()]);
        let elem_sig_idx = u16::try_from(m.signatures.len()).unwrap();
        m.signatures
            .push(Signature(vec![SignatureToken::U64]));
        m.function_defs[0].code = Some(AdamantCodeUnit {
            locals: SignatureIndex(1),
            code: vec![
                cp_loc(0),
                cp_loc(0),
                ld_u64(0),
                BytecodeInstruction::Inherited(Bytecode::VecMutBorrow(SignatureIndex(elem_sig_idx))),
                pop_inst(),
                pop_inst(),
                ret_inst(),
            ],
            jump_tables: vec![],
        });
        match run(&m) {
            Err(AdamantValidationError::BorrowViolation {
                reason: BorrowViolationReason::VecElementHasMutableBorrow,
                ..
            }) => {}
            other => panic!("expected VecElementHasMutableBorrow, got {other:?}"),
        }
    }

    /// `VecUpdateHasMutableBorrow` audit pin: VecPushBack on a
    /// &mut Vec<T> whose source has an outstanding mutable
    /// borrow.
    #[test]
    fn vec_update_with_outstanding_mut_borrow_rejected() {
        let vec_t = SignatureToken::MutableReference(Box::new(SignatureToken::Vector(
            Box::new(SignatureToken::U64),
        )));
        let mut m = module_with_function(vec![vec_t], vec![], vec![], vec![ret_inst()]);
        let elem_sig_idx = u16::try_from(m.signatures.len()).unwrap();
        m.signatures
            .push(Signature(vec![SignatureToken::U64]));
        m.function_defs[0].code = Some(AdamantCodeUnit {
            locals: SignatureIndex(1),
            code: vec![
                cp_loc(0),
                cp_loc(0),
                ld_u64(7),
                BytecodeInstruction::Inherited(Bytecode::VecPushBack(SignatureIndex(elem_sig_idx))),
                pop_inst(),
                ret_inst(),
            ],
            jump_tables: vec![],
        });
        match run(&m) {
            Err(AdamantValidationError::BorrowViolation {
                reason: BorrowViolationReason::VecUpdateHasMutableBorrow,
                ..
            }) => {}
            other => panic!("expected VecUpdateHasMutableBorrow, got {other:?}"),
        }
    }

    /// `RetBorrowedMutableReference` audit pin: function with
    /// (&mut u64, &mut u64) return signature; both ret values
    /// alias the same param. The first checked has an
    /// outstanding mutable borrow from the second.
    #[test]
    fn ret_borrowed_mutable_reference_rejected() {
        let m = module_with_function(
            vec![SignatureToken::MutableReference(Box::new(SignatureToken::U64))],
            vec![],
            vec![
                SignatureToken::MutableReference(Box::new(SignatureToken::U64)),
                SignatureToken::MutableReference(Box::new(SignatureToken::U64)),
            ],
            vec![cp_loc(0), cp_loc(0), ret_inst()],
        );
        match run(&m) {
            Err(AdamantValidationError::BorrowViolation {
                reason: BorrowViolationReason::RetBorrowedMutableReference,
                ..
            }) => {}
            other => panic!("expected RetBorrowedMutableReference, got {other:?}"),
        }
    }

    // ----- Phase 5/5c F-2: Layer B parity backfill -----
    //
    // Sui's `reference_safety::verify` is `pub(crate)` — only
    // the composite per-function entry
    // `code_unit_verifier::verify_module` is reachable from our
    // test code. Composite-pipeline parity per the Sui-public-
    // API-shape-constrains-parity-helper sub-pattern (D-7b
    // registration; 3rd instance at F-2). Each fixture is
    // curated to isolate reference_safety's behaviour: well-
    // formed at every other pass; triggers the borrow rule
    // under test on both sides.
    //
    // Layer-B-coverage-shape sub-classification: F-2 D-5b
    // demonstrates retroactive-promotion (NEW sub-shape per
    // F-2 plan-gate Q2 refinement; 1st instance). Layer A
    // coverage was established at D-5b.2 (and extended at
    // E-6 with 7 deferred BorrowViolationReason sub-reasons +
    // 1 st_loc_destroys_non_drop fixture); F-2 promotes a
    // representative subset to Layer B parity.

    use crate::validator::config::AdamantStructuralLimits;
    use crate::validator::function_pass::test_helpers::{
        assert_function_pass_parity_vm, run_adamant_pipeline, run_sui_code_unit_verifier,
        sui_config_from, to_sui,
    };
    use adamant_types::Address as AccountAddress;

    fn add_self_address_refsafe(m: &mut AdamantCompiledModule) {
        if m.address_identifiers.is_empty() {
            m.address_identifiers
                .push(AccountAddress::from_bytes([0u8; 32]));
        }
    }

    fn cross_validate_reference_safety_pipeline(m: &AdamantCompiledModule) {
        let mut m = m.clone();
        add_self_address_refsafe(&mut m);
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
        assert_function_pass_parity_vm("reference_safety", adamant_result, sui_result);
    }

    #[test]
    fn cross_validation_accepts_simple_borrow_release() {
        // Body: empty function body that just returns. Both
        // Adamant and Sui accept.
        let m = module_with_function(vec![], vec![], vec![], vec![ret_inst()]);
        cross_validate_reference_safety_pipeline(&m);
    }

    #[test]
    fn cross_validation_rejects_copy_loc_while_mut_borrowed() {
        // params[0]: u64; body: mut_borrow_loc(0); cp_loc(0);
        // pop; write_ref; ret. CopyLoc on mutably-borrowed
        // local rejects on both sides.
        let m = module_with_function(
            vec![SignatureToken::U64],
            vec![],
            vec![],
            vec![
                mut_borrow_loc(0),
                cp_loc(0),
                pop_inst(),
                write_ref(),
                ret_inst(),
            ],
        );
        cross_validate_reference_safety_pipeline(&m);
    }

    #[test]
    fn cross_validation_rejects_move_loc_while_borrowed() {
        // params[0]: u64; body: imm_borrow_loc(0); mv_loc(0);
        // pop; pop; ret.
        let m = module_with_function(
            vec![SignatureToken::U64],
            vec![],
            vec![],
            vec![imm_borrow_loc(0), mv_loc(0), pop_inst(), pop_inst(), ret_inst()],
        );
        cross_validate_reference_safety_pipeline(&m);
    }

    #[test]
    fn cross_validation_rejects_st_loc_while_borrowed() {
        // locals: [u64]; body: imm_borrow_loc(0); ld_u64(7);
        // st_loc(0); pop; ret.
        let m = module_with_function(
            vec![],
            vec![SignatureToken::U64],
            vec![],
            vec![
                imm_borrow_loc(0),
                ld_u64(7),
                st_loc(0),
                pop_inst(),
                ret_inst(),
            ],
        );
        cross_validate_reference_safety_pipeline(&m);
    }

    #[test]
    fn cross_validation_rejects_imm_borrow_loc_while_mut_borrowed() {
        // params[0]: u64; body: mut_borrow_loc(0);
        // imm_borrow_loc(0); pop; pop; ret.
        let m = module_with_function(
            vec![SignatureToken::U64],
            vec![],
            vec![],
            vec![
                mut_borrow_loc(0),
                imm_borrow_loc(0),
                pop_inst(),
                pop_inst(),
                ret_inst(),
            ],
        );
        cross_validate_reference_safety_pipeline(&m);
    }

    #[test]
    fn cross_validation_rejects_ret_while_local_borrowed() {
        // params[0]: u64; return: &mut u64; body:
        // mut_borrow_loc(0); ret. Returning a mutable
        // reference to a local destroys the frame.
        let m = module_with_function(
            vec![SignatureToken::U64],
            vec![],
            vec![SignatureToken::MutableReference(Box::new(SignatureToken::U64))],
            vec![mut_borrow_loc(0), ret_inst()],
        );
        cross_validate_reference_safety_pipeline(&m);
    }

    /// Phase 5/5c F-2 Layer-B-coverage-shape retroactive-
    /// promotion 1st instance: promotes E-6's
    /// freeze_ref_with_outstanding_mut_borrow_rejected fixture
    /// (Layer A) to Layer B parity. Uses the same cp_loc-of-
    /// mutable-reference pattern.
    #[test]
    fn cross_validation_rejects_freeze_ref_with_outstanding_mut_borrow() {
        let m = module_with_function(
            vec![SignatureToken::MutableReference(Box::new(SignatureToken::U64))],
            vec![],
            vec![],
            vec![
                cp_loc(0),
                cp_loc(0),
                freeze_ref(),
                pop_inst(),
                pop_inst(),
                ret_inst(),
            ],
        );
        cross_validate_reference_safety_pipeline(&m);
    }

    /// Retroactive-promotion of E-6's
    /// write_ref_with_outstanding_mut_borrow_rejected fixture
    /// to Layer B parity. WriteRef expects ref on TOP of stack
    /// (per the existing mut_borrow_loc_then_write_ref happy-
    /// path test; D-5b.2 + E-6 fixture analysis).
    #[test]
    fn cross_validation_rejects_write_ref_with_outstanding_mut_borrow() {
        let m = module_with_function(
            vec![SignatureToken::MutableReference(Box::new(SignatureToken::U64))],
            vec![],
            vec![],
            vec![
                cp_loc(0),
                ld_u64(7),
                cp_loc(0),
                write_ref(),
                pop_inst(),
                ret_inst(),
            ],
        );
        cross_validate_reference_safety_pipeline(&m);
    }
}
