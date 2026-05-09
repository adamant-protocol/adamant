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
    ConstantPoolIndex, FieldHandleIndex, FunctionHandleIndex, StructDefinitionIndex,
    VariantHandleIndex,
};

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
/// Returns the enum definition index and the variant's tag byte.
/// 5/6.2c.2 wires this into the variant-instruction handlers.
pub fn resolve_variant_handle(
    module: &AdamantCompiledModule,
    handle: VariantHandleIndex,
) -> Result<(usize, u16), VMError> {
    let variant_handle =
        module
            .variant_handles
            .get(handle.0 as usize)
            .ok_or(VMError::InvariantViolation {
                reason: InvariantViolationReason::IndexOutOfBoundsPostVerification,
            })?;
    // VariantHandle.variant is VariantTag (= u16).
    Ok((variant_handle.enum_def.0 as usize, variant_handle.variant))
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
