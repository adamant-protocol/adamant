//! Variant-op handler tests — Pack/Unpack variant family +
//! VariantSwitch. Per Phase 5/6.2c.2.γ-merged.
//!
//! Verbatim-spec-quote-grounds-runtime-fixture discipline applied
//! per fixture; Sui-Move file_format.rs:1789-1819 quotes anchor
//! variant op semantics for the inherited subset.

use core::cell::RefCell;
use std::rc::Rc;

use adamant_bytecode_format::{Bytecode, VariantJumpTableIndex};

use super::*;
use crate::runtime::runtime_value::Container;
use crate::runtime::InvariantViolationReason;

// =====================================================================
// Bytecode::PackVariant
// =====================================================================

/// Sui-Move file_format.rs:1789-1791 (verbatim): "Stack transition:
/// ..., field(1)_value, field(2)_value, ..., field(n)_value -> ...,
/// variant_value." Pops n field values for the specified variant,
/// pushes a variant container with the runtime tag.
#[test]
fn pack_variant_pops_n_fields_and_pushes_variant_with_tag() {
    let mut module = module_with_enum(vec![2, 1]); // variant 0: 2 fields; variant 1: 1 field
    let h0 = add_variant_handle(&mut module, 0);
    let mut state = state_with_frame(0);
    push_stack(
        &mut state,
        vec![RuntimeValue::U64(11), RuntimeValue::U64(22)],
    );
    dispatch_with_module(&mut state, Bytecode::PackVariant(h0), &module).expect("ok");
    let v = top(&state);
    let (tag, fields) = match v {
        RuntimeValue::Container(Container::Variant(rc)) => {
            let cell = rc.borrow();
            (cell.variant_tag, cell.fields.clone())
        }
        _ => panic!("expected variant"),
    };
    assert_eq!(tag, 0);
    assert_eq!(fields, vec![RuntimeValue::U64(11), RuntimeValue::U64(22)]);
    assert_eq!(pc(&state), 1);
}

/// PackVariant with a different tag selects a different variant
/// (different field count).
#[test]
fn pack_variant_with_alt_tag_selects_alt_variant() {
    let mut module = module_with_enum(vec![2, 1]);
    let h1 = add_variant_handle(&mut module, 1);
    let mut state = state_with_frame(0);
    push_stack(&mut state, vec![RuntimeValue::U64(99)]);
    dispatch_with_module(&mut state, Bytecode::PackVariant(h1), &module).expect("ok");
    let v = top(&state);
    let (tag, fields) = match v {
        RuntimeValue::Container(Container::Variant(rc)) => {
            let cell = rc.borrow();
            (cell.variant_tag, cell.fields.clone())
        }
        _ => panic!("expected variant"),
    };
    assert_eq!(tag, 1);
    assert_eq!(fields, vec![RuntimeValue::U64(99)]);
}

/// PackVariant with 0-field variant produces an empty variant.
#[test]
fn pack_variant_zero_fields_produces_empty_variant() {
    let mut module = module_with_enum(vec![0]);
    let h = add_variant_handle(&mut module, 0);
    let mut state = state_with_frame(0);
    dispatch_with_module(&mut state, Bytecode::PackVariant(h), &module).expect("ok");
    let v = top(&state);
    let fields = match v {
        RuntimeValue::Container(Container::Variant(rc)) => rc.borrow().fields.clone(),
        _ => panic!("expected variant"),
    };
    assert!(fields.is_empty());
}

/// PackVariant with OOB handle index surfaces invariant violation.
#[test]
fn pack_variant_oob_handle_idx_surfaces_invariant_violation() {
    let module = module_with_enum(vec![1]);
    let mut state = state_with_frame(0);
    let result = dispatch_with_module(
        &mut state,
        Bytecode::PackVariant(adamant_bytecode_format::VariantHandleIndex(99)),
        &module,
    );
    assert!(matches!(
        result,
        Err(VMError::InvariantViolation {
            reason: InvariantViolationReason::IndexOutOfBoundsPostVerification
        })
    ));
}

// =====================================================================
// Bytecode::UnpackVariant (Owned mode)
// =====================================================================

/// Sui-Move file_format.rs:1797-1807 (verbatim): "Stack transition:
/// ..., instance_value -> ..., field(1)_value, field(2)_value, ...,
/// field(n)_value." Push order matches declaration order.
#[test]
fn unpack_variant_pops_variant_and_pushes_fields() {
    let mut module = module_with_enum(vec![2]);
    let h = add_variant_handle(&mut module, 0);
    let mut state = state_with_frame(0);
    push_stack(
        &mut state,
        vec![variant_value(
            0,
            vec![RuntimeValue::U64(11), RuntimeValue::U64(22)],
        )],
    );
    dispatch_with_module(&mut state, Bytecode::UnpackVariant(h), &module).expect("ok");
    let f = state.top_frame().expect("frame");
    assert_eq!(f.stack[0], RuntimeValue::U64(11));
    assert_eq!(f.stack[1], RuntimeValue::U64(22));
    assert_eq!(pc(&state), 1);
}

/// UnpackVariant on a variant value with different runtime tag
/// surfaces `VariantTagMismatch` — the new sub-reason landed at
/// 5/6.2c.2.γ-merged.
#[test]
fn unpack_variant_tag_mismatch_surfaces_variant_tag_mismatch() {
    let mut module = module_with_enum(vec![1, 1]);
    let h_for_tag_0 = add_variant_handle(&mut module, 0);
    let mut state = state_with_frame(0);
    // Push a variant with tag = 1 (different from h_for_tag_0).
    push_stack(
        &mut state,
        vec![variant_value(1, vec![RuntimeValue::U64(7)])],
    );
    let result = dispatch_with_module(&mut state, Bytecode::UnpackVariant(h_for_tag_0), &module);
    assert!(matches!(
        result,
        Err(VMError::InvariantViolation {
            reason: InvariantViolationReason::VariantTagMismatch
        })
    ));
}

/// UnpackVariant on a non-variant value surfaces type mismatch.
#[test]
fn unpack_variant_on_non_variant_surfaces_type_mismatch() {
    let mut module = module_with_enum(vec![1]);
    let h = add_variant_handle(&mut module, 0);
    let mut state = state_with_frame(0);
    push_stack(&mut state, vec![struct_value(vec![RuntimeValue::U64(7)])]);
    let result = dispatch_with_module(&mut state, Bytecode::UnpackVariant(h), &module);
    assert!(matches!(
        result,
        Err(VMError::InvariantViolation {
            reason: InvariantViolationReason::TypeMismatchOnStack
        })
    ));
}

/// PackVariant + UnpackVariant round-trip preserves fields.
#[test]
fn pack_variant_then_unpack_variant_round_trip() {
    let mut module = module_with_enum(vec![2]);
    let h = add_variant_handle(&mut module, 0);
    let mut state = state_with_frame(0);
    push_stack(
        &mut state,
        vec![RuntimeValue::U64(7), RuntimeValue::Bool(true)],
    );
    dispatch_with_module(&mut state, Bytecode::PackVariant(h), &module).expect("pack");
    dispatch_with_module(&mut state, Bytecode::UnpackVariant(h), &module).expect("unpack");
    let f = state.top_frame().expect("frame");
    assert_eq!(f.stack[0], RuntimeValue::U64(7));
    assert_eq!(f.stack[1], RuntimeValue::Bool(true));
}

// =====================================================================
// Bytecode::UnpackVariantImmRef / Bytecode::UnpackVariantMutRef
// =====================================================================

/// UnpackVariantImmRef: pop a reference to a variant, push field
/// references for the variant's fields. The Imm/Mut distinction is
/// verifier-only at runtime per the FreezeRef no-op posture.
#[test]
fn unpack_variant_imm_ref_pushes_field_references() {
    let mut module = module_with_enum(vec![2]);
    let h = add_variant_handle(&mut module, 0);
    let mut state = state_with_frame(0);
    let rc = Rc::new(RefCell::new(RuntimeVariantValue {
        type_id: adamant_types::TypeId::from_bytes([0xBB; 32]),
        variant_tag: 0,
        fields: vec![RuntimeValue::U64(11), RuntimeValue::U64(22)],
    }));
    let r = Reference::Container(Container::Variant(Rc::clone(&rc)));
    push_stack(&mut state, vec![RuntimeValue::Reference(r)]);
    dispatch_with_module(&mut state, Bytecode::UnpackVariantImmRef(h), &module).expect("ok");
    assert_eq!(stack_len(&state), 2);
    let f = state.top_frame().expect("frame");
    // Both pushed values should be References.
    assert!(matches!(f.stack[0], RuntimeValue::Reference(_)));
    assert!(matches!(f.stack[1], RuntimeValue::Reference(_)));
}

/// UnpackVariantMutRef has the same runtime semantics as
/// UnpackVariantImmRef — the verifier-only distinction is the
/// FreezeRef no-op design (Sui-VM-aligned).
#[test]
fn unpack_variant_mut_ref_pushes_field_references() {
    let mut module = module_with_enum(vec![2]);
    let h = add_variant_handle(&mut module, 0);
    let mut state = state_with_frame(0);
    let rc = Rc::new(RefCell::new(RuntimeVariantValue {
        type_id: adamant_types::TypeId::from_bytes([0xBB; 32]),
        variant_tag: 0,
        fields: vec![RuntimeValue::U64(11), RuntimeValue::U64(22)],
    }));
    let r = Reference::Container(Container::Variant(Rc::clone(&rc)));
    push_stack(&mut state, vec![RuntimeValue::Reference(r)]);
    dispatch_with_module(&mut state, Bytecode::UnpackVariantMutRef(h), &module).expect("ok");
    assert_eq!(stack_len(&state), 2);
}

/// UnpackVariantImmRef on tag-mismatched variant surfaces
/// VariantTagMismatch.
#[test]
fn unpack_variant_imm_ref_tag_mismatch_surfaces_variant_tag_mismatch() {
    let mut module = module_with_enum(vec![1, 1]);
    let h_for_tag_0 = add_variant_handle(&mut module, 0);
    let mut state = state_with_frame(0);
    let rc = Rc::new(RefCell::new(RuntimeVariantValue {
        type_id: adamant_types::TypeId::from_bytes([0xBB; 32]),
        variant_tag: 1,
        fields: vec![RuntimeValue::U64(99)],
    }));
    let r = Reference::Container(Container::Variant(rc));
    push_stack(&mut state, vec![RuntimeValue::Reference(r)]);
    let result = dispatch_with_module(
        &mut state,
        Bytecode::UnpackVariantImmRef(h_for_tag_0),
        &module,
    );
    assert!(matches!(
        result,
        Err(VMError::InvariantViolation {
            reason: InvariantViolationReason::VariantTagMismatch
        })
    ));
}

/// Field references from UnpackVariantImmRef descend through the
/// shared `Rc<RefCell<RuntimeVariantValue>>` — writing through a
/// returned reference mutates the original variant's fields.
#[test]
fn unpack_variant_imm_ref_field_references_share_rc_with_original() {
    let mut module = module_with_enum(vec![1]);
    let h = add_variant_handle(&mut module, 0);
    let mut state = state_with_frame(0);
    let rc = Rc::new(RefCell::new(RuntimeVariantValue {
        type_id: adamant_types::TypeId::from_bytes([0xBB; 32]),
        variant_tag: 0,
        fields: vec![RuntimeValue::U64(11)],
    }));
    let r = Reference::Container(Container::Variant(Rc::clone(&rc)));
    push_stack(&mut state, vec![RuntimeValue::Reference(r)]);
    dispatch_with_module(&mut state, Bytecode::UnpackVariantImmRef(h), &module).expect("ok");
    let field_ref = match state.top_frame().expect("frame").stack[0].clone() {
        RuntimeValue::Reference(r) => r,
        _ => panic!("expected reference"),
    };
    field_ref
        .write_ref(RuntimeValue::U64(99))
        .expect("write through field ref");
    assert_eq!(rc.borrow().fields[0], RuntimeValue::U64(99));
}

// =====================================================================
// PackVariantGeneric / UnpackVariantGeneric (+ImmRef/MutRef)
// =====================================================================

/// PackVariantGeneric resolves through the variant-instantiation
/// pool to the underlying enum + tag.
#[test]
fn pack_variant_generic_resolves_through_instantiation_pool() {
    let mut module = module_with_enum(vec![1]);
    let h = add_variant_inst_handle(&mut module, 0);
    let mut state = state_with_frame(0);
    push_stack(&mut state, vec![RuntimeValue::U64(7)]);
    dispatch_with_module(&mut state, Bytecode::PackVariantGeneric(h), &module).expect("ok");
    let v = top(&state);
    let (tag, fields) = match v {
        RuntimeValue::Container(Container::Variant(rc)) => {
            let cell = rc.borrow();
            (cell.variant_tag, cell.fields.clone())
        }
        _ => panic!("expected variant"),
    };
    assert_eq!(tag, 0);
    assert_eq!(fields, vec![RuntimeValue::U64(7)]);
}

/// UnpackVariantGeneric resolves through the instantiation pool.
#[test]
fn unpack_variant_generic_resolves_and_unpacks() {
    let mut module = module_with_enum(vec![1]);
    let h = add_variant_inst_handle(&mut module, 0);
    let mut state = state_with_frame(0);
    push_stack(
        &mut state,
        vec![variant_value(0, vec![RuntimeValue::U64(7)])],
    );
    dispatch_with_module(&mut state, Bytecode::UnpackVariantGeneric(h), &module).expect("ok");
    assert_eq!(top(&state), RuntimeValue::U64(7));
}

/// UnpackVariantGenericImmRef pushes field references through the
/// instantiation-resolved enum.
#[test]
fn unpack_variant_generic_imm_ref_pushes_field_refs() {
    let mut module = module_with_enum(vec![2]);
    let h = add_variant_inst_handle(&mut module, 0);
    let mut state = state_with_frame(0);
    let rc = Rc::new(RefCell::new(RuntimeVariantValue {
        type_id: adamant_types::TypeId::from_bytes([0xBB; 32]),
        variant_tag: 0,
        fields: vec![RuntimeValue::U64(1), RuntimeValue::U64(2)],
    }));
    let r = Reference::Container(Container::Variant(rc));
    push_stack(&mut state, vec![RuntimeValue::Reference(r)]);
    dispatch_with_module(&mut state, Bytecode::UnpackVariantGenericImmRef(h), &module).expect("ok");
    assert_eq!(stack_len(&state), 2);
}

/// UnpackVariantGenericMutRef has the same runtime semantics as
/// the Imm variant.
#[test]
fn unpack_variant_generic_mut_ref_pushes_field_refs() {
    let mut module = module_with_enum(vec![1]);
    let h = add_variant_inst_handle(&mut module, 0);
    let mut state = state_with_frame(0);
    let rc = Rc::new(RefCell::new(RuntimeVariantValue {
        type_id: adamant_types::TypeId::from_bytes([0xBB; 32]),
        variant_tag: 0,
        fields: vec![RuntimeValue::U64(7)],
    }));
    let r = Reference::Container(Container::Variant(rc));
    push_stack(&mut state, vec![RuntimeValue::Reference(r)]);
    dispatch_with_module(&mut state, Bytecode::UnpackVariantGenericMutRef(h), &module).expect("ok");
    assert_eq!(stack_len(&state), 1);
}

// =====================================================================
// Bytecode::VariantSwitch
// =====================================================================

/// Sui-Move file_format.rs:1813-1819 (verbatim): "Branch on the tag
/// value of the enum value reference that is on the top of the
/// value stack, and jumps to the matching code offset for that tag
/// within the `CodeUnit`. Code offsets are relative to the start
/// of the instruction stream."
#[test]
fn variant_switch_jumps_to_target_for_tag() {
    let mut module = module_with_enum(vec![1, 1, 1]);
    let fh_idx = add_function_with_jump_table(&mut module, vec![10, 20, 30]);
    let mut state = state_with_function_frame(fh_idx, 0);
    let rc = Rc::new(RefCell::new(RuntimeVariantValue {
        type_id: adamant_types::TypeId::from_bytes([0xBB; 32]),
        variant_tag: 1,
        fields: vec![RuntimeValue::U64(7)],
    }));
    let r = Reference::Container(Container::Variant(rc));
    push_stack(&mut state, vec![RuntimeValue::Reference(r)]);
    dispatch_with_module(
        &mut state,
        Bytecode::VariantSwitch(VariantJumpTableIndex(0)),
        &module,
    )
    .expect("ok");
    // pc should be set to jump_offsets[1] = 20.
    assert_eq!(pc(&state), 20);
}

/// VariantSwitch with tag = 0 jumps to first offset.
#[test]
fn variant_switch_tag_zero_jumps_to_first_offset() {
    let mut module = module_with_enum(vec![1, 1]);
    let fh_idx = add_function_with_jump_table(&mut module, vec![5, 15]);
    let mut state = state_with_function_frame(fh_idx, 0);
    let rc = Rc::new(RefCell::new(RuntimeVariantValue {
        type_id: adamant_types::TypeId::from_bytes([0xBB; 32]),
        variant_tag: 0,
        fields: vec![RuntimeValue::U64(7)],
    }));
    let r = Reference::Container(Container::Variant(rc));
    push_stack(&mut state, vec![RuntimeValue::Reference(r)]);
    dispatch_with_module(
        &mut state,
        Bytecode::VariantSwitch(VariantJumpTableIndex(0)),
        &module,
    )
    .expect("ok");
    assert_eq!(pc(&state), 5);
}

/// VariantSwitch with runtime tag exceeding jump-table length
/// surfaces `JumpTableTagOutOfRange` — the new sub-reason landed
/// at 5/6.2c.2.γ-merged.
#[test]
fn variant_switch_tag_oob_jump_table_surfaces_jump_table_tag_out_of_range() {
    let mut module = module_with_enum(vec![1, 1]);
    let fh_idx = add_function_with_jump_table(&mut module, vec![5, 15]);
    let mut state = state_with_function_frame(fh_idx, 0);
    let rc = Rc::new(RefCell::new(RuntimeVariantValue {
        type_id: adamant_types::TypeId::from_bytes([0xBB; 32]),
        variant_tag: 99,
        fields: vec![RuntimeValue::U64(7)],
    }));
    let r = Reference::Container(Container::Variant(rc));
    push_stack(&mut state, vec![RuntimeValue::Reference(r)]);
    let result = dispatch_with_module(
        &mut state,
        Bytecode::VariantSwitch(VariantJumpTableIndex(0)),
        &module,
    );
    assert!(matches!(
        result,
        Err(VMError::InvariantViolation {
            reason: InvariantViolationReason::JumpTableTagOutOfRange
        })
    ));
}

/// VariantSwitch with OOB jump-table index surfaces invariant
/// violation (different from JumpTableTagOutOfRange — this is the
/// jump-table-index-itself OOB case).
#[test]
fn variant_switch_oob_jump_table_idx_surfaces_invariant_violation() {
    let mut module = module_with_enum(vec![1]);
    let fh_idx = add_function_with_jump_table(&mut module, vec![5]);
    let mut state = state_with_function_frame(fh_idx, 0);
    let rc = Rc::new(RefCell::new(RuntimeVariantValue {
        type_id: adamant_types::TypeId::from_bytes([0xBB; 32]),
        variant_tag: 0,
        fields: vec![RuntimeValue::U64(7)],
    }));
    let r = Reference::Container(Container::Variant(rc));
    push_stack(&mut state, vec![RuntimeValue::Reference(r)]);
    let result = dispatch_with_module(
        &mut state,
        Bytecode::VariantSwitch(VariantJumpTableIndex(99)),
        &module,
    );
    assert!(matches!(
        result,
        Err(VMError::InvariantViolation {
            reason: InvariantViolationReason::IndexOutOfBoundsPostVerification
        })
    ));
}

/// VariantSwitch on a non-variant reference surfaces type mismatch.
#[test]
fn variant_switch_on_non_variant_reference_surfaces_type_mismatch() {
    let mut module = module_with_enum(vec![1]);
    let fh_idx = add_function_with_jump_table(&mut module, vec![5]);
    let mut state = state_with_function_frame(fh_idx, 0);
    let rc = Rc::new(RefCell::new(RuntimeStructValue {
        type_id: adamant_types::TypeId::from_bytes([0xAA; 32]),
        fields: vec![RuntimeValue::U64(7)],
    }));
    let r = Reference::Container(Container::Struct(rc));
    push_stack(&mut state, vec![RuntimeValue::Reference(r)]);
    let result = dispatch_with_module(
        &mut state,
        Bytecode::VariantSwitch(VariantJumpTableIndex(0)),
        &module,
    );
    assert!(matches!(
        result,
        Err(VMError::InvariantViolation {
            reason: InvariantViolationReason::TypeMismatchOnStack
        })
    ));
}

// =====================================================================
// Cross-handler: PC advancement for non-jumping handlers
// =====================================================================

/// PackVariant advances pc by 1.
#[test]
fn pack_variant_advances_pc_by_1() {
    let mut module = module_with_enum(vec![0]);
    let h = add_variant_handle(&mut module, 0);
    let mut state = state_with_frame(0);
    let _ = dispatch_with_module(&mut state, Bytecode::PackVariant(h), &module);
    assert_eq!(pc(&state), 1);
}

/// UnpackVariant advances pc by 1.
#[test]
fn unpack_variant_advances_pc_by_1() {
    let mut module = module_with_enum(vec![0]);
    let h = add_variant_handle(&mut module, 0);
    let mut state = state_with_frame(0);
    push_stack(&mut state, vec![variant_value(0, vec![])]);
    let _ = dispatch_with_module(&mut state, Bytecode::UnpackVariant(h), &module);
    assert_eq!(pc(&state), 1);
}

/// Different enum-def indices produce different placeholder
/// TypeIds.
#[test]
fn pack_variant_uses_distinct_placeholder_type_ids_per_enum_def_idx() {
    use crate::runtime::module_helpers::placeholder_type_id_for_enum;
    let id0 = placeholder_type_id_for_enum(adamant_bytecode_format::EnumDefinitionIndex(0));
    let id1 = placeholder_type_id_for_enum(adamant_bytecode_format::EnumDefinitionIndex(1));
    assert_ne!(id0, id1);
}

/// Struct and enum placeholder TypeIds are distinct (different
/// type-tag bytes).
#[test]
fn struct_and_enum_placeholder_type_ids_are_disjoint() {
    use crate::runtime::module_helpers::{
        placeholder_type_id_for_enum, placeholder_type_id_for_struct,
    };
    let struct_id =
        placeholder_type_id_for_struct(adamant_bytecode_format::StructDefinitionIndex(0));
    let enum_id = placeholder_type_id_for_enum(adamant_bytecode_format::EnumDefinitionIndex(0));
    assert_ne!(struct_id, enum_id);
}
