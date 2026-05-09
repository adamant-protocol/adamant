//! Module-resolution helpers — whitepaper §6.2.2 step 5.
//!
//! Phase 5/6.2c.1 ships the helper signatures + happy-path
//! resolution logic. Phase 5/6.2c.2 wires the helpers into the
//! 38 module-access instruction handlers (`LdConst`, `Call`,
//! `CallGeneric`, `Pack`, `Unpack`, `MutBorrowField`, etc.).
//!
//! Helpers operate against a `&AdamantCompiledModule` parameter
//! threaded through `dispatch_instruction` per Phase 5/6.2c plan-
//! gate Q5/6.2c.2 disposition (option (a): `&'a AdamantCompiledModule`
//! borrow lifetime). The single-threaded interpreter holds the
//! module reference for the duration of the transaction's
//! execution; cross-module concerns use the separate
//! `crate::validator::cross_module::ModuleResolver` trait.
//!
//! All helpers return `Result<T, VMError>` where the error case
//! is `VMError::InvariantViolation` per the verifier-residual
//! posture. The verifier's `bounds_checker` pass at deploy time
//! statically validates that all index references in bytecode
//! land within the module's pool sizes; reaching the error case
//! at runtime indicates verifier unsoundness or post-deployment
//! bytecode modification.

#![allow(
    clippy::missing_errors_doc,
    reason = "all helpers return Result with InvariantViolation error per verifier-residual binding posture; doc prose covers each function's specific verifier-pass guarantee"
)]

use adamant_bytecode_format::{
    ConstantPoolIndex, EnumDefinitionIndex, FieldHandleIndex, FunctionHandleIndex, JumpTableInner,
    StructDefInstantiationIndex, StructDefinitionIndex, VariantHandleIndex,
    VariantInstantiationHandleIndex, VariantJumpTable, VariantJumpTableIndex, VariantTag,
};
use adamant_types::TypeId;

use crate::module::{AdamantCompiledModule, AdamantFunctionDefinition};
use crate::runtime::error::{InvariantViolationReason, VMError};

/// Resolve a [`FunctionHandleIndex`] to the corresponding
/// [`AdamantFunctionDefinition`] within the module.
///
/// Per whitepaper §6.2.2 step 5: `Bytecode::Call` and
/// `Bytecode::CallGeneric` reference functions via
/// [`FunctionHandleIndex`]; the runtime resolves the handle to
/// the function's signature, parameter count, local count, and
/// bytecode body.
///
/// At sub-arc 5/6.2c.1 this helper resolves single-module calls
/// only. Cross-module function calls (where the function handle
/// references an external module per `function_handles[idx].module`)
/// land at 5/6.2c.2 with module-resolver integration via the
/// `ModuleResolver` trait at [`crate::validator::cross_module`].
pub fn resolve_function_def(
    module: &AdamantCompiledModule,
    handle: FunctionHandleIndex,
) -> Result<&AdamantFunctionDefinition, VMError> {
    // The function definition's index within `function_defs`
    // does not match the handle index directly — handles are a
    // separate pool. We find the definition whose `function`
    // field equals the handle index.
    let handle_idx = handle.0 as usize;
    if handle_idx >= module.function_handles.len() {
        return Err(VMError::InvariantViolation {
            reason: InvariantViolationReason::IndexOutOfBoundsPostVerification,
        });
    }
    // Find the function_def whose `function` field references
    // this handle. For single-module calls, every defined
    // function has a corresponding handle; for external calls,
    // no defined function matches and the caller dispatches via
    // ModuleResolver instead.
    module
        .function_defs
        .iter()
        .find(|def| def.function.0 as usize == handle_idx)
        .ok_or(VMError::InvariantViolation {
            reason: InvariantViolationReason::IndexOutOfBoundsPostVerification,
        })
}

/// Resolve a [`StructDefinitionIndex`] to the struct's field count.
///
/// Used by `Bytecode::Pack` to determine how many values to pop
/// from the operand stack and by `Bytecode::Unpack` to determine
/// how many fields to push.
pub fn resolve_struct_field_count(
    module: &AdamantCompiledModule,
    idx: StructDefinitionIndex,
) -> Result<usize, VMError> {
    let def = module
        .struct_defs
        .get(idx.0 as usize)
        .ok_or(VMError::InvariantViolation {
            reason: InvariantViolationReason::IndexOutOfBoundsPostVerification,
        })?;
    // `fields()` returns `Option<&[FieldDefinition]>`; native
    // structs return None, regular structs return Some(slice).
    Ok(def.fields().map_or(0, <[_]>::len))
}

/// Resolve a [`FieldHandleIndex`] to the struct-relative offset
/// of the field within its containing struct's fields array.
///
/// Used by `Bytecode::MutBorrowField` and `Bytecode::ImmBorrowField`
/// to compute the field index within the struct value's fields
/// before constructing a [`crate::runtime::Reference::StructField`].
pub fn resolve_field_offset(
    module: &AdamantCompiledModule,
    handle: FieldHandleIndex,
) -> Result<usize, VMError> {
    let field_handle =
        module
            .field_handles
            .get(handle.0 as usize)
            .ok_or(VMError::InvariantViolation {
                reason: InvariantViolationReason::IndexOutOfBoundsPostVerification,
            })?;
    // FieldHandle.field is MemberCount (= u16); convert to usize
    // for use as a field index within the struct's fields array.
    Ok(field_handle.field as usize)
}

/// Resolve a [`ConstantPoolIndex`] to the constant's bytes.
///
/// Used by `Bytecode::LdConst` to push a constant from the
/// module's `constant_pool` onto the operand stack. The constant
/// carries its declared type and BCS-encoded value bytes; the
/// runtime decodes the bytes to the appropriate
/// [`crate::runtime::RuntimeValue`] variant per the constant's
/// type.
pub fn resolve_constant(
    module: &AdamantCompiledModule,
    idx: ConstantPoolIndex,
) -> Result<&adamant_bytecode_format::Constant, VMError> {
    module
        .constant_pool
        .get(idx.0 as usize)
        .ok_or(VMError::InvariantViolation {
            reason: InvariantViolationReason::IndexOutOfBoundsPostVerification,
        })
}

/// Resolve a [`VariantHandleIndex`] to (enum-definition-index,
/// variant-tag) for `Bytecode::PackVariant` / `UnpackVariant` /
/// `VariantSwitch`.
///
/// Returns the enum definition index and the variant's tag.
/// 5/6.2c.2 wires this into the variant-instruction handlers.
pub fn resolve_variant_handle(
    module: &AdamantCompiledModule,
    handle: VariantHandleIndex,
) -> Result<(EnumDefinitionIndex, VariantTag), VMError> {
    let variant_handle =
        module
            .variant_handles
            .get(handle.0 as usize)
            .ok_or(VMError::InvariantViolation {
                reason: InvariantViolationReason::IndexOutOfBoundsPostVerification,
            })?;
    Ok((variant_handle.enum_def, variant_handle.variant))
}

/// Resolve a [`StructDefInstantiationIndex`] to the underlying
/// [`StructDefinitionIndex`].
///
/// Used by `Bytecode::PackGeneric` / `Bytecode::UnpackGeneric` to
/// resolve through the instantiation pool to the underlying
/// generic struct definition.
pub fn resolve_struct_def_instantiation(
    module: &AdamantCompiledModule,
    idx: StructDefInstantiationIndex,
) -> Result<StructDefinitionIndex, VMError> {
    module
        .struct_def_instantiations
        .get(idx.0 as usize)
        .map(|inst| inst.def)
        .ok_or(VMError::InvariantViolation {
            reason: InvariantViolationReason::IndexOutOfBoundsPostVerification,
        })
}

/// Resolve a [`VariantInstantiationHandleIndex`] to the underlying
/// (enum-definition-index, variant-tag) pair.
///
/// Used by `Bytecode::PackVariantGeneric` /
/// `Bytecode::UnpackVariantGeneric` /
/// `Bytecode::UnpackVariantGenericImmRef` /
/// `Bytecode::UnpackVariantGenericMutRef`. Resolves through the
/// generic-variant-instantiation pool to the underlying enum
/// definition and variant tag.
pub fn resolve_variant_instantiation_handle(
    module: &AdamantCompiledModule,
    idx: VariantInstantiationHandleIndex,
) -> Result<(EnumDefinitionIndex, VariantTag), VMError> {
    let handle = module
        .variant_instantiation_handles
        .get(idx.0 as usize)
        .ok_or(VMError::InvariantViolation {
            reason: InvariantViolationReason::IndexOutOfBoundsPostVerification,
        })?;
    // The instantiation handle's enum_def is an
    // EnumDefInstantiationIndex; resolve through to the
    // underlying EnumDefinitionIndex.
    let enum_def_inst = module
        .enum_def_instantiations
        .get(handle.enum_def.0 as usize)
        .ok_or(VMError::InvariantViolation {
            reason: InvariantViolationReason::IndexOutOfBoundsPostVerification,
        })?;
    Ok((enum_def_inst.def, handle.variant))
}

/// Resolve an enum definition + variant tag to the variant's
/// field count.
///
/// Used by `Bytecode::PackVariant` / `UnpackVariant` to determine
/// how many fields to pop or push for a specific variant.
/// Different variants of the same enum may have different field
/// counts.
pub fn resolve_enum_variant_field_count(
    module: &AdamantCompiledModule,
    enum_def: EnumDefinitionIndex,
    tag: VariantTag,
) -> Result<usize, VMError> {
    let def = module
        .enum_defs
        .get(enum_def.0 as usize)
        .ok_or(VMError::InvariantViolation {
            reason: InvariantViolationReason::IndexOutOfBoundsPostVerification,
        })?;
    let variant = def
        .variants
        .get(tag as usize)
        .ok_or(VMError::InvariantViolation {
            reason: InvariantViolationReason::IndexOutOfBoundsPostVerification,
        })?;
    Ok(variant.fields.len())
}

/// Resolve a [`VariantJumpTableIndex`] to the jump-table inner
/// data within a function's [`crate::module::AdamantCodeUnit`].
///
/// Jump tables are per-function — they live at
/// `AdamantCodeUnit::jump_tables`. Used by
/// `Bytecode::VariantSwitch` to look up the jump-target offset
/// for a runtime variant tag.
pub fn resolve_jump_table(
    function_def: &AdamantFunctionDefinition,
    idx: VariantJumpTableIndex,
) -> Result<&JumpTableInner, VMError> {
    let code = function_def
        .code
        .as_ref()
        .ok_or(VMError::InvariantViolation {
            reason: InvariantViolationReason::IndexOutOfBoundsPostVerification,
        })?;
    code.jump_tables
        .get(idx.0 as usize)
        .map(|jt: &VariantJumpTable| &jt.jump_table)
        .ok_or(VMError::InvariantViolation {
            reason: InvariantViolationReason::IndexOutOfBoundsPostVerification,
        })
}

/// Derive a deterministic placeholder [`TypeId`] for a struct
/// definition.
///
/// Phase 5/6.2c.2.γ-merged scope: `TypeId` is informational at the
/// runtime-mechanics layer — `Pack`/`Unpack` semantics depend on
/// field count, not on `TypeId` equality. This helper produces a
/// deterministic placeholder per-struct-def-index so that
/// different struct types in the same module receive different
/// `TypeId`s for diagnostic + equality purposes, without claiming
/// to implement the full `TypeId`-derivation hashing scheme.
///
/// Carry-forward: proper `TypeId` derivation (whitepaper §5.1.2 hash
/// of module + name + type-args) lands when transaction-argument
/// + object-state representation of structs/variants is finalized.
#[must_use]
pub fn placeholder_type_id_for_struct(idx: StructDefinitionIndex) -> TypeId {
    let mut bytes = [0u8; 32];
    // Tag the placeholder as a struct-def-derived TypeId via byte
    // 0 = 0x01; the next two bytes hold the def index in little-
    // endian. Distinct from the variant placeholder shape so
    // struct-vs-variant TypeIds never collide.
    bytes[0] = 0x01;
    bytes[1..3].copy_from_slice(&idx.0.to_le_bytes());
    TypeId::from_bytes(bytes)
}

/// Derive a deterministic placeholder [`TypeId`] for an enum
/// definition.
///
/// Companion to [`placeholder_type_id_for_struct`]. Same scope and
/// carry-forward.
#[must_use]
pub fn placeholder_type_id_for_enum(idx: EnumDefinitionIndex) -> TypeId {
    let mut bytes = [0u8; 32];
    bytes[0] = 0x02;
    bytes[1..3].copy_from_slice(&idx.0.to_le_bytes());
    TypeId::from_bytes(bytes)
}

#[cfg(test)]
mod tests {
    //! Helper-resolution behavioural tests. Foundation tests at
    //! 5/6.2c.1; per-handler tests using these helpers land at
    //! 5/6.2c.2.

    // (5/6.2c.1 ships helpers as foundation; tests are deferred
    // to 5/6.2c.2 where handlers actually consume them via
    // realistic AdamantCompiledModule fixtures. Placeholder
    // module preserves the test-module shape per Adamant
    // convention.)
}
