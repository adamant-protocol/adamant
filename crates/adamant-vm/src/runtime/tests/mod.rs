//! Phase 5/6.2c.2.γ-merged per-category tests for module-access
//! handlers (struct ops + vector ops + variant ops).
//!
//! Per Phase 5/6.2c.2.γ-merged plan-gate Q-γ.6 disposition:
//! per-category test files at `runtime/tests/` host module-access
//! handler tests with verbatim-spec-quote-grounds-runtime-fixture
//! discipline applied per fixture.
//!
//! Shared test-only helpers live in this module; per-category
//! tests live in [`struct_ops`], [`vector_ops`], and [`variant_ops`].

#![allow(
    clippy::doc_markdown,
    clippy::manual_let_else,
    reason = "test fixture patterns + verbatim spec quotes; same posture as Phase 5/6.2b interpreter.rs::tests"
)]

mod adamant_extensions;
mod struct_ops;
mod variant_ops;
mod vector_ops;

use core::cell::RefCell;
use std::rc::Rc;

use adamant_bytecode_format::{
    AbilitySet, Bytecode, DatatypeHandle, DatatypeHandleIndex, EnumDefInstantiation,
    EnumDefinition, EnumDefinitionIndex, FieldDefinition, FunctionHandleIndex, IdentifierIndex,
    JumpTableInner, ModuleHandleIndex, SignatureIndex, SignatureToken, StructDefInstantiation,
    StructDefinition, StructFieldInformation, TypeSignature, VariantDefinition, VariantHandle,
    VariantHandleIndex, VariantInstantiationHandle, VariantInstantiationHandleIndex,
    VariantJumpTable, VariantTag,
};

use crate::bytecode::BytecodeInstruction;
use crate::module::{AdamantCodeUnit, AdamantCompiledModule, AdamantFunctionDefinition};
use crate::runtime::interpreter::{dispatch_instruction, DispatchOutcome};
use crate::runtime::runtime_value::{
    Container, Reference, RuntimeStructValue, RuntimeVariantValue,
};
use crate::runtime::{Frame, InterpreterState, RuntimeValue, VMError};

/// Construct a `FunctionHandleIndex` from a `u16`.
pub(super) fn fh(idx: u16) -> FunctionHandleIndex {
    FunctionHandleIndex(idx)
}

/// Construct an `AdamantCompiledModule` carrying a single struct
/// definition with `field_count` placeholder declared fields.
///
/// All fields are typed `U64` (placeholder); the runtime's
/// Pack/Unpack semantics depend on field count, not field types.
pub(super) fn module_with_struct(field_count: usize) -> AdamantCompiledModule {
    let mut m = AdamantCompiledModule::default();
    // A single placeholder DatatypeHandle so the StructDefinition
    // has somewhere to point its struct_handle.
    m.module_handles
        .push(adamant_bytecode_format::ModuleHandle {
            address: adamant_bytecode_format::AddressIdentifierIndex(0),
            name: IdentifierIndex(0),
        });
    m.identifiers
        .push(adamant_bytecode_format::Identifier::new("S").expect("identifier"));
    m.address_identifiers
        .push(adamant_types::Address::from_bytes([0u8; 32]));
    m.datatype_handles.push(DatatypeHandle {
        module: ModuleHandleIndex(0),
        name: IdentifierIndex(0),
        abilities: AbilitySet::EMPTY,
        type_parameters: Vec::new(),
    });
    let fields: Vec<FieldDefinition> = (0..field_count)
        .map(|_| FieldDefinition {
            name: IdentifierIndex(0),
            signature: TypeSignature(SignatureToken::U64),
        })
        .collect();
    m.struct_defs.push(StructDefinition {
        struct_handle: DatatypeHandleIndex(0),
        field_information: StructFieldInformation::Declared(fields),
    });
    m
}

/// Add a `StructDefInstantiation` to the module pointing at the
/// existing struct definition at index 0. Returns the index of the
/// new instantiation entry.
pub(super) fn add_struct_def_instantiation(m: &mut AdamantCompiledModule) -> u16 {
    m.signatures
        .push(adamant_bytecode_format::Signature(vec![]));
    let new_inst_idx = u16::try_from(m.struct_def_instantiations.len()).expect("fits u16");
    m.struct_def_instantiations.push(StructDefInstantiation {
        def: adamant_bytecode_format::StructDefinitionIndex(0),
        type_parameters: SignatureIndex(0),
    });
    new_inst_idx
}

/// Construct an `AdamantCompiledModule` carrying a single enum
/// definition with `variants` (each entry is the field count for
/// that variant).
pub(super) fn module_with_enum(variants: Vec<usize>) -> AdamantCompiledModule {
    let mut m = AdamantCompiledModule::default();
    m.module_handles
        .push(adamant_bytecode_format::ModuleHandle {
            address: adamant_bytecode_format::AddressIdentifierIndex(0),
            name: IdentifierIndex(0),
        });
    m.identifiers
        .push(adamant_bytecode_format::Identifier::new("E").expect("identifier"));
    m.address_identifiers
        .push(adamant_types::Address::from_bytes([0u8; 32]));
    m.datatype_handles.push(DatatypeHandle {
        module: ModuleHandleIndex(0),
        name: IdentifierIndex(0),
        abilities: AbilitySet::EMPTY,
        type_parameters: Vec::new(),
    });
    let variant_defs: Vec<VariantDefinition> = variants
        .into_iter()
        .map(|field_count| VariantDefinition {
            variant_name: IdentifierIndex(0),
            fields: (0..field_count)
                .map(|_| FieldDefinition {
                    name: IdentifierIndex(0),
                    signature: TypeSignature(SignatureToken::U64),
                })
                .collect(),
        })
        .collect();
    m.enum_defs.push(EnumDefinition {
        enum_handle: DatatypeHandleIndex(0),
        variants: variant_defs,
    });
    m
}

/// Add a `VariantHandle` to the module pointing at the existing
/// enum definition at index 0 with the given tag. Returns the
/// `VariantHandleIndex` of the new handle.
pub(super) fn add_variant_handle(
    m: &mut AdamantCompiledModule,
    tag: VariantTag,
) -> VariantHandleIndex {
    let idx = u16::try_from(m.variant_handles.len()).expect("fits u16");
    m.variant_handles.push(VariantHandle {
        enum_def: EnumDefinitionIndex(0),
        variant: tag,
    });
    VariantHandleIndex(idx)
}

/// Add an `EnumDefInstantiation` + `VariantInstantiationHandle`
/// to the module. Returns the new handle's index.
pub(super) fn add_variant_inst_handle(
    m: &mut AdamantCompiledModule,
    tag: VariantTag,
) -> VariantInstantiationHandleIndex {
    m.signatures
        .push(adamant_bytecode_format::Signature(vec![]));
    let inst_idx = u16::try_from(m.enum_def_instantiations.len()).expect("fits u16");
    m.enum_def_instantiations.push(EnumDefInstantiation {
        def: EnumDefinitionIndex(0),
        type_parameters: SignatureIndex(0),
    });
    let handle_idx = u16::try_from(m.variant_instantiation_handles.len()).expect("fits u16");
    m.variant_instantiation_handles
        .push(VariantInstantiationHandle {
            enum_def: adamant_bytecode_format::EnumDefInstantiationIndex(inst_idx),
            variant: tag,
        });
    VariantInstantiationHandleIndex(handle_idx)
}

/// Add a function definition to the module. The function's code
/// unit can carry jump tables for `VariantSwitch` testing.
pub(super) fn add_function_with_jump_table(
    m: &mut AdamantCompiledModule,
    jump_offsets: Vec<u16>,
) -> FunctionHandleIndex {
    m.signatures
        .push(adamant_bytecode_format::Signature(vec![]));
    let sig_idx = u16::try_from(m.signatures.len() - 1).expect("fits u16");
    let fh_idx = u16::try_from(m.function_handles.len()).expect("fits u16");
    m.function_handles
        .push(adamant_bytecode_format::FunctionHandle {
            module: ModuleHandleIndex(0),
            name: IdentifierIndex(0),
            parameters: SignatureIndex(sig_idx),
            return_: SignatureIndex(sig_idx),
            type_parameters: Vec::new(),
        });
    m.function_defs.push(AdamantFunctionDefinition {
        function: FunctionHandleIndex(fh_idx),
        visibility: adamant_bytecode_format::Visibility::Public,
        is_entry: false,
        acquires_global_resources: Vec::new(),
        code: Some(AdamantCodeUnit {
            locals: SignatureIndex(sig_idx),
            code: Vec::new(),
            jump_tables: vec![VariantJumpTable {
                head_enum: EnumDefinitionIndex(0),
                jump_table: JumpTableInner::Full(jump_offsets),
            }],
        }),
    });
    FunctionHandleIndex(fh_idx)
}

/// Construct a state with a single frame holding `local_count`
/// locals.
pub(super) fn state_with_frame(local_count: usize) -> InterpreterState {
    let mut state = InterpreterState::new();
    state.push_frame(Frame::new(fh(0), local_count));
    state
}

/// Construct a state with a frame whose `function_handle` matches
/// the provided handle index — used for VariantSwitch tests where
/// the dispatch helper resolves the current function's jump table.
pub(super) fn state_with_function_frame(
    handle: FunctionHandleIndex,
    local_count: usize,
) -> InterpreterState {
    let mut state = InterpreterState::new();
    state.push_frame(Frame::new(handle, local_count));
    state
}

/// Push values onto the top frame's stack in order
/// (first → bottom, last → top).
pub(super) fn push_stack(state: &mut InterpreterState, values: Vec<RuntimeValue>) {
    let frame = state.top_frame_mut().expect("frame");
    for v in values {
        frame.push_value(v);
    }
}

/// Dispatch an inherited opcode against a state with a real
/// module.
pub(super) fn dispatch_with_module(
    state: &mut InterpreterState,
    opcode: Bytecode,
    module: &AdamantCompiledModule,
) -> Result<DispatchOutcome, VMError> {
    dispatch_instruction(&BytecodeInstruction::Inherited(opcode), state, module)
}

/// Read top-of-stack on the top frame for assertions.
pub(super) fn top(state: &InterpreterState) -> RuntimeValue {
    state
        .top_frame()
        .expect("frame")
        .stack
        .last()
        .cloned()
        .expect("non-empty stack")
}

/// Read the top frame's program counter.
pub(super) fn pc(state: &InterpreterState) -> u16 {
    state.top_frame().expect("frame").pc
}

/// Read the top frame's stack length.
pub(super) fn stack_len(state: &InterpreterState) -> usize {
    state.top_frame().expect("frame").stack.len()
}

/// Construct a `RuntimeValue::Container(Vector)` from a slice of
/// runtime values.
pub(super) fn vec_value(elements: Vec<RuntimeValue>) -> RuntimeValue {
    RuntimeValue::Container(Container::Vector(Rc::new(RefCell::new(elements))))
}

/// Construct a `RuntimeValue::Container(Struct)` with the given
/// fields, using a placeholder TypeId.
pub(super) fn struct_value(fields: Vec<RuntimeValue>) -> RuntimeValue {
    let type_id = adamant_types::TypeId::from_bytes([0xAA; 32]);
    RuntimeValue::Container(Container::Struct(Rc::new(RefCell::new(
        RuntimeStructValue { type_id, fields },
    ))))
}

/// Construct a `RuntimeValue::Container(Variant)` with the given
/// tag and fields, using a placeholder TypeId.
pub(super) fn variant_value(tag: u16, fields: Vec<RuntimeValue>) -> RuntimeValue {
    let type_id = adamant_types::TypeId::from_bytes([0xBB; 32]);
    RuntimeValue::Container(Container::Variant(Rc::new(RefCell::new(
        RuntimeVariantValue {
            type_id,
            variant_tag: tag,
            fields,
        },
    ))))
}
