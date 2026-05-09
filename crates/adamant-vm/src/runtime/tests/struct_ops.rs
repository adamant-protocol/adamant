//! Struct-op handler tests — Pack, PackGeneric, Unpack,
//! UnpackGeneric. Per Phase 5/6.2c.2.γ-merged.
//!
//! Verbatim-spec-quote-grounds-runtime-fixture discipline: each
//! fixture's expected outcome is anchored to a verbatim Sui-Move
//! file_format.rs quote (test-time empirical reference for
//! inherited semantics) at the pinned commit
//! `a9a6825eaf6273cc819ee3bcf65fd4909f7624a9`.

use adamant_bytecode_format::{Bytecode, StructDefInstantiationIndex, StructDefinitionIndex};

use super::*;
use crate::runtime::runtime_value::Container;

// =====================================================================
// Bytecode::Pack
// =====================================================================

/// Sui-Move file_format.rs:1690-1701 (verbatim, applicable to the
/// inherited subset): "A Pack instruction must fully initialize an
/// instance. ... Stack transition: ..., field(1)_value,
/// field(2)_value, ..., field(n)_value -> ..., struct_value."
#[test]
fn pack_pops_n_fields_and_pushes_struct_in_declaration_order() {
    let module = module_with_struct(3);
    let mut state = state_with_frame(0);
    push_stack(
        &mut state,
        vec![
            RuntimeValue::U64(1),
            RuntimeValue::U64(2),
            RuntimeValue::U64(3),
        ],
    );
    let result = dispatch_with_module(
        &mut state,
        Bytecode::Pack(StructDefinitionIndex(0)),
        &module,
    )
    .expect("ok");
    assert!(matches!(result, DispatchOutcome::Continue));
    assert_eq!(stack_len(&state), 1);
    let struct_v = top(&state);
    let fields = match struct_v {
        RuntimeValue::Container(Container::Struct(rc)) => rc.borrow().fields.clone(),
        _ => panic!("expected struct"),
    };
    assert_eq!(
        fields,
        vec![
            RuntimeValue::U64(1),
            RuntimeValue::U64(2),
            RuntimeValue::U64(3),
        ]
    );
    assert_eq!(pc(&state), 1);
}

/// Pack with zero fields produces an empty struct value.
#[test]
fn pack_zero_fields_produces_empty_struct() {
    let module = module_with_struct(0);
    let mut state = state_with_frame(0);
    let _result = dispatch_with_module(
        &mut state,
        Bytecode::Pack(StructDefinitionIndex(0)),
        &module,
    )
    .expect("ok");
    assert_eq!(stack_len(&state), 1);
    let struct_v = top(&state);
    let fields = match struct_v {
        RuntimeValue::Container(Container::Struct(rc)) => rc.borrow().fields.clone(),
        _ => panic!("expected struct"),
    };
    assert!(fields.is_empty());
}

/// Pack on a non-existent struct definition surfaces
/// `IndexOutOfBoundsPostVerification` per the verifier-residual
/// posture.
#[test]
fn pack_oob_struct_def_idx_surfaces_invariant_violation() {
    let module = AdamantCompiledModule::default();
    let mut state = state_with_frame(0);
    let result = dispatch_with_module(
        &mut state,
        Bytecode::Pack(StructDefinitionIndex(0)),
        &module,
    );
    assert!(matches!(
        result,
        Err(VMError::InvariantViolation {
            reason: crate::runtime::InvariantViolationReason::IndexOutOfBoundsPostVerification
        })
    ));
}

/// Pack popping fewer fields than the stack carries: stack
/// underflow from the verifier-residual binding.
#[test]
fn pack_with_underfilled_stack_surfaces_stack_underflow() {
    let module = module_with_struct(3);
    let mut state = state_with_frame(0);
    push_stack(&mut state, vec![RuntimeValue::U64(1)]);
    let result = dispatch_with_module(
        &mut state,
        Bytecode::Pack(StructDefinitionIndex(0)),
        &module,
    );
    assert!(matches!(
        result,
        Err(VMError::InvariantViolation {
            reason: crate::runtime::InvariantViolationReason::StackUnderflow
        })
    ));
}

// =====================================================================
// Bytecode::Unpack
// =====================================================================

/// Sui-Move file_format.rs:1715-1726 (verbatim): "Stack transition:
/// ..., struct_value -> ..., field(1)_value, field(2)_value, ...,
/// field(n)_value." Push order matches declaration order, top of
/// stack ends as field(n).
#[test]
fn unpack_pops_struct_and_pushes_fields_in_declaration_order() {
    let module = module_with_struct(3);
    let mut state = state_with_frame(0);
    push_stack(
        &mut state,
        vec![struct_value(vec![
            RuntimeValue::U64(11),
            RuntimeValue::U64(22),
            RuntimeValue::U64(33),
        ])],
    );
    let result = dispatch_with_module(
        &mut state,
        Bytecode::Unpack(StructDefinitionIndex(0)),
        &module,
    )
    .expect("ok");
    assert!(matches!(result, DispatchOutcome::Continue));
    assert_eq!(stack_len(&state), 3);
    let f = state.top_frame().expect("frame");
    assert_eq!(f.stack[0], RuntimeValue::U64(11));
    assert_eq!(f.stack[1], RuntimeValue::U64(22));
    assert_eq!(f.stack[2], RuntimeValue::U64(33));
    assert_eq!(pc(&state), 1);
}

/// Unpack on an empty struct produces no fields.
#[test]
fn unpack_zero_fields_pushes_nothing() {
    let module = module_with_struct(0);
    let mut state = state_with_frame(0);
    push_stack(&mut state, vec![struct_value(vec![])]);
    dispatch_with_module(
        &mut state,
        Bytecode::Unpack(StructDefinitionIndex(0)),
        &module,
    )
    .expect("ok");
    assert_eq!(stack_len(&state), 0);
}

/// Unpack on a non-struct value surfaces type mismatch.
#[test]
fn unpack_on_non_struct_surfaces_type_mismatch() {
    let module = module_with_struct(3);
    let mut state = state_with_frame(0);
    push_stack(&mut state, vec![RuntimeValue::U64(7)]);
    let result = dispatch_with_module(
        &mut state,
        Bytecode::Unpack(StructDefinitionIndex(0)),
        &module,
    );
    assert!(matches!(
        result,
        Err(VMError::InvariantViolation {
            reason: crate::runtime::InvariantViolationReason::TypeMismatchOnStack
        })
    ));
}

/// Pack-then-Unpack round-trips struct field values.
#[test]
fn pack_then_unpack_round_trips_fields() {
    let module = module_with_struct(2);
    let mut state = state_with_frame(0);
    push_stack(
        &mut state,
        vec![RuntimeValue::U64(7), RuntimeValue::Bool(true)],
    );
    dispatch_with_module(
        &mut state,
        Bytecode::Pack(StructDefinitionIndex(0)),
        &module,
    )
    .expect("pack");
    dispatch_with_module(
        &mut state,
        Bytecode::Unpack(StructDefinitionIndex(0)),
        &module,
    )
    .expect("unpack");
    assert_eq!(stack_len(&state), 2);
    let f = state.top_frame().expect("frame");
    assert_eq!(f.stack[0], RuntimeValue::U64(7));
    assert_eq!(f.stack[1], RuntimeValue::Bool(true));
}

// =====================================================================
// Bytecode::PackGeneric / Bytecode::UnpackGeneric
// =====================================================================

/// `PackGeneric` resolves through `struct_def_instantiations[idx].def`
/// to the underlying struct definition, then runs the same Pack
/// semantics. Sui-Move file_format.rs:1697-1701 (verbatim, generic
/// counterpart): "PackGeneric ... must fully initialize an instance"
/// with type arguments resolved via instantiation pool.
#[test]
fn pack_generic_resolves_through_instantiation_pool() {
    let mut module = module_with_struct(2);
    let inst_idx = add_struct_def_instantiation(&mut module);
    let mut state = state_with_frame(0);
    push_stack(
        &mut state,
        vec![RuntimeValue::U64(1), RuntimeValue::Bool(false)],
    );
    dispatch_with_module(
        &mut state,
        Bytecode::PackGeneric(StructDefInstantiationIndex(inst_idx)),
        &module,
    )
    .expect("ok");
    let struct_v = top(&state);
    let fields = match struct_v {
        RuntimeValue::Container(Container::Struct(rc)) => rc.borrow().fields.clone(),
        _ => panic!("expected struct"),
    };
    assert_eq!(
        fields,
        vec![RuntimeValue::U64(1), RuntimeValue::Bool(false)]
    );
}

/// `PackGeneric` with OOB instantiation index surfaces
/// `IndexOutOfBoundsPostVerification`.
#[test]
fn pack_generic_oob_instantiation_idx_surfaces_invariant_violation() {
    let module = module_with_struct(2);
    let mut state = state_with_frame(0);
    let result = dispatch_with_module(
        &mut state,
        Bytecode::PackGeneric(StructDefInstantiationIndex(0)),
        &module,
    );
    assert!(matches!(
        result,
        Err(VMError::InvariantViolation {
            reason: crate::runtime::InvariantViolationReason::IndexOutOfBoundsPostVerification
        })
    ));
}

/// `UnpackGeneric` resolves through the instantiation pool and
/// unpacks fields in declaration order.
#[test]
fn unpack_generic_resolves_and_unpacks_fields() {
    let mut module = module_with_struct(2);
    let inst_idx = add_struct_def_instantiation(&mut module);
    let mut state = state_with_frame(0);
    push_stack(
        &mut state,
        vec![struct_value(vec![
            RuntimeValue::U64(7),
            RuntimeValue::Bool(true),
        ])],
    );
    dispatch_with_module(
        &mut state,
        Bytecode::UnpackGeneric(StructDefInstantiationIndex(inst_idx)),
        &module,
    )
    .expect("ok");
    assert_eq!(stack_len(&state), 2);
    let f = state.top_frame().expect("frame");
    assert_eq!(f.stack[0], RuntimeValue::U64(7));
    assert_eq!(f.stack[1], RuntimeValue::Bool(true));
}

/// Round-trip: PackGeneric + UnpackGeneric.
#[test]
fn pack_generic_then_unpack_generic_round_trip() {
    let mut module = module_with_struct(2);
    let inst_idx = add_struct_def_instantiation(&mut module);
    let mut state = state_with_frame(0);
    push_stack(
        &mut state,
        vec![RuntimeValue::U64(42), RuntimeValue::Bool(true)],
    );
    dispatch_with_module(
        &mut state,
        Bytecode::PackGeneric(StructDefInstantiationIndex(inst_idx)),
        &module,
    )
    .expect("pack");
    dispatch_with_module(
        &mut state,
        Bytecode::UnpackGeneric(StructDefInstantiationIndex(inst_idx)),
        &module,
    )
    .expect("unpack");
    let f = state.top_frame().expect("frame");
    assert_eq!(f.stack[0], RuntimeValue::U64(42));
    assert_eq!(f.stack[1], RuntimeValue::Bool(true));
}

// =====================================================================
// Nested struct (Pack into a Pack)
// =====================================================================

/// Nested struct via two consecutive Packs: outer Pack sees the
/// inner struct as a single field value.
#[test]
fn pack_nested_struct_treats_inner_as_field_value() {
    let mut module = module_with_struct(2); // outer with 2 fields
                                            // Add a second struct def with 1 field for inner.
    let inner_fields = vec![adamant_bytecode_format::FieldDefinition {
        name: adamant_bytecode_format::IdentifierIndex(0),
        signature: adamant_bytecode_format::TypeSignature(
            adamant_bytecode_format::SignatureToken::U64,
        ),
    }];
    module
        .struct_defs
        .push(adamant_bytecode_format::StructDefinition {
            struct_handle: adamant_bytecode_format::DatatypeHandleIndex(0),
            field_information: adamant_bytecode_format::StructFieldInformation::Declared(
                inner_fields,
            ),
        });
    let mut state = state_with_frame(0);
    // Build inner first.
    push_stack(&mut state, vec![RuntimeValue::U64(99)]);
    dispatch_with_module(
        &mut state,
        Bytecode::Pack(StructDefinitionIndex(1)),
        &module,
    )
    .expect("inner pack");
    assert_eq!(stack_len(&state), 1);
    // Push the second outer field, then pack outer (which expects 2 fields).
    push_stack(&mut state, vec![RuntimeValue::Bool(true)]);
    dispatch_with_module(
        &mut state,
        Bytecode::Pack(StructDefinitionIndex(0)),
        &module,
    )
    .expect("outer pack");
    let outer = top(&state);
    let outer_fields = match outer {
        RuntimeValue::Container(Container::Struct(rc)) => rc.borrow().fields.clone(),
        _ => panic!("expected outer struct"),
    };
    // Outer field 0 is the inner struct; outer field 1 is the bool.
    assert!(matches!(
        outer_fields[0],
        RuntimeValue::Container(Container::Struct(_))
    ));
    assert_eq!(outer_fields[1], RuntimeValue::Bool(true));
}

/// Pack increments the program counter by 1.
#[test]
fn pack_advances_pc_by_1() {
    let module = module_with_struct(0);
    let mut state = state_with_frame(0);
    let _ = dispatch_with_module(
        &mut state,
        Bytecode::Pack(StructDefinitionIndex(0)),
        &module,
    );
    assert_eq!(pc(&state), 1);
}

/// Unpack increments the program counter by 1.
#[test]
fn unpack_advances_pc_by_1() {
    let module = module_with_struct(0);
    let mut state = state_with_frame(0);
    push_stack(&mut state, vec![struct_value(vec![])]);
    let _ = dispatch_with_module(
        &mut state,
        Bytecode::Unpack(StructDefinitionIndex(0)),
        &module,
    );
    assert_eq!(pc(&state), 1);
}

/// Different struct-def indices produce different placeholder
/// TypeIds via `placeholder_type_id_for_struct`. This pins the
/// distinguishability invariant of the placeholder derivation.
#[test]
fn pack_uses_distinct_placeholder_type_ids_per_struct_def_idx() {
    use crate::runtime::module_helpers::placeholder_type_id_for_struct;
    let id0 = placeholder_type_id_for_struct(StructDefinitionIndex(0));
    let id1 = placeholder_type_id_for_struct(StructDefinitionIndex(1));
    assert_ne!(id0, id1);
}
