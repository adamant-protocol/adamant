//! Module-level pass: bounds checking
//! (whitepaper §6.2.1.8 step 3, position 1).
//!
//! Forked from `vendor/move-binary-format/src/check_bounds.rs`
//! at Sui-Move tag `mainnet-v1.66.2` (commit
//! `a9a6825eaf6273cc819ee3bcf65fd4909f7624a9`). Note: upstream's
//! `BoundsChecker` lives in `move-binary-format` (the
//! deserializer crate), not in `move-bytecode-verifier`. In
//! Adamant's pipeline the deserializer (Phase 5/5a) does **not**
//! pre-validate bounds; bounds checking is a step-3 module-level
//! pass per §6.2.1.8 line 524's verbatim enumeration ("Bounds
//! checking, structural-limits checking, ..."). See
//! `validator/module_pass/PROVENANCE.md` for the full deviation
//! list and per-pass methodology-pattern co-location.
//!
//! # Pass scope (section 1 of the per-pass doc-comment template)
//!
//! Validates that every index reference inside the deserialized
//! [`AdamantCompiledModule`] resolves to an in-range slot of its
//! addressed pool. Upstream `BoundsChecker::verify_module` runs
//! 17 sub-checks across the module's tables; Phase 5/5b.3 ports
//! them across four sub-checkpoints (positions taken from
//! upstream's `verify_impl` enumeration, not plan-text named
//! counts — the latter are illustrative per the C-1.1
//! calibration registration):
//!
//! - **C-1.1 (landed):** initial empty-module-handles
//!   short-circuit + `check_signatures` + `check_constants` +
//!   `check_module_handles` + `check_self_module_handle` +
//!   `check_datatype_handles`. Five sub-checks plus the
//!   precondition (positions 1–5).
//! - **C-1.2 (landed):** `check_function_handles`,
//!   `check_field_handles`, `check_friend_decls`,
//!   `check_struct_instantiations`,
//!   `check_function_instantiations`,
//!   `check_field_instantiations`. Six sub-checks (positions
//!   6–11). Plan-text initially named "five instantiation
//!   tables (struct/function/enum/field/variant)"; empirical
//!   re-baseline per upstream `verify_impl` corrected this to
//!   three instantiation tables (struct/function/field) — the
//!   enum-instantiations and variant-instantiation-handles
//!   land at C-1.3.
//! - **C-1.3 (this sub-checkpoint):** `check_struct_defs`,
//!   `check_enum_defs`, `check_enum_instantiations`,
//!   `check_variant_handles`,
//!   `check_variant_instantiation_handles`. Five sub-checks
//!   (positions 12–16). Reuses [`check_type`] (C-1.1) and
//!   [`check_type_parameter`] (C-1.2) for field-signature
//!   validation. Extracts [`check_field_def`] helper at N=2
//!   (byte-identical body in struct-def and enum-def field
//!   iterations) — second instance of the per-handle-extraction
//!   refactor pattern after C-1.2's [`check_module_handle`].
//!   The extraction is a deliberate-Adamant-decision: upstream
//!   Sui inlines the body in both `check_struct_def` and
//!   `check_enum_def`; the helper name is chosen for parallel
//!   structure with the existing per-def validators.
//! - **C-1.4:** `check_function_defs` including code-unit body
//!   checks and jump-table validation. One sub-check (position
//!   17), but the widest one — covers per-bytecode bounds
//!   across the entire instruction set.
//!
//! Error variants produced at C-1.1:
//!
//! - [`AdamantValidationError::NoModuleHandles`] — the module's
//!   `module_handles` table is empty (no self-handle to anchor
//!   on).
//! - [`AdamantValidationError::IndexOutOfBounds`] — generic out-
//!   of-range carrying `IndexKind` to discriminate the addressed
//!   pool. Used by [`check_signatures`], [`check_constants`],
//!   [`check_module_handles`], [`check_self_module_handle`],
//!   [`check_datatype_handles`], and the [`check_type`] traversal
//!   helper consumed by the first two.
//! - [`AdamantValidationError::NumberOfTypeArgumentsMismatch`] —
//!   a `Datatype(idx)` token references a handle that expects
//!   non-zero type parameters but supplies zero, or a
//!   `DatatypeInstantiation(idx, type_args)` supplies a different
//!   number than the handle declares. Both code paths fire the
//!   same variant; `expected`/`actual` discriminate the sub-case.
//!
//! C-1.2 adds **0 new error variants.** All six sub-checks reuse
//! [`AdamantValidationError::IndexOutOfBounds`] from C-1.1 with
//! `IndexKind::MemberCount` (field-offset within a struct) and
//! `IndexKind::TypeParameter` (type-parameter index inside a
//! function-handle's signature) as additional discriminators.
//! Both `IndexKind` variants are existing values from
//! `adamant-bytecode-format`. Plus the existing
//! `IndexKind::ModuleHandle`/`Identifier`/`Signature`/
//! `StructDefinition`/`FunctionHandle`/`FieldHandle` discriminators
//! cover the bulk of C-1.2's bounds checks.
//!
//! C-1.3 also adds **0 new error variants.** All five sub-checks
//! reuse [`AdamantValidationError::IndexOutOfBounds`] from C-1.1
//! with three additional `IndexKind` discriminators:
//! `IndexKind::EnumDefinition` (variant-handle and enum-instantiation
//! `def` references), `IndexKind::EnumDefInstantiation`
//! (variant-instantiation-handle's `enum_def` reference into the
//! enum-instantiations table), and `IndexKind::VariantTag` (variant
//! tag-vs-count check inside variant-handle and variant-instantiation-
//! handle). All three are existing `adamant-bytecode-format` values.
//! Plus [`AdamantValidationError::NumberOfTypeArgumentsMismatch`] from
//! C-1.1 may fire via [`check_type`] recursion on field signatures
//! within `check_struct_defs` / `check_enum_defs`.
//!
//! # No-Sui-parity-claim posture (section 2)
//!
//! Not applicable. C-1.1 makes a **full Sui-parity claim** for
//! the inherited Sui-base subset of inputs: for any module shape
//! produceable through `to_sui_module`'s BCS round-trip, the pass
//! reaches the same accept/reject decision as Sui's
//! [`move_binary_format::check_bounds::BoundsChecker::verify_module`].
//! Layer B parity tests assert the claim per category. The claim
//! is byte-identical at the boundary; the typed-error variant
//! shape differs by design (`AdamantValidationError` rather than
//! `PartialVMError`/`StatusCode`) per the resistant-proof posture.
//!
//! # Deliberate-Adamant-decision (section 3)
//!
//! Not applicable. Direct algorithmic port; preserved byte-
//! faithfully per the methodology principle. Sub-check ordering
//! mirrors upstream's [`verify_impl`] sequence; `check_type`'s
//! Datatype/DatatypeInstantiation arms preserve upstream's
//! "bounds-then-arity" pairing.
//!
//! # Eager-error first-failure-wins (section 4)
//!
//! Internal-to-pass precedence:
//!
//! - [`verify`] short-circuits on the empty-module-handles check
//!   before invoking any sub-check. A module with both an empty
//!   `module_handles` table and an out-of-range signature reports
//!   `NoModuleHandles`.
//! - Sub-check ordering after C-1.3: signatures → constants →
//!   module-handles → self-module-handle → datatype-handles →
//!   function-handles → field-handles → friend-decls →
//!   struct-instantiations → function-instantiations →
//!   field-instantiations → struct-defs → enum-defs →
//!   enum-instantiations → variant-handles →
//!   variant-instantiation-handles. First-encountered violation
//!   wins. (Upstream order; preserved byte-faithfully — see
//!   `bounds_checker_sub_check_ordering` and
//!   `c13_struct_defs_before_enum_defs` tests.)
//! - Within a sub-check, iteration is in storage order (table
//!   index ascending); the lowest-index offender is reported.
//! - Within `check_type`'s match arms: `Datatype(idx)` and
//!   `DatatypeInstantiation(idx, _)` perform a bounds check on
//!   `idx` first, then (only if bounds succeed) the type-argument
//!   arity check. Upstream is explicit about this pairing; the
//!   port preserves it.
//! - Within `check_function_handle`: bounds checks on `module`,
//!   `name`, `parameters`, `return_` fire before `check_type_parameter`
//!   recursion over the parameters/return signatures. Upstream's
//!   `?` ordering preserved byte-faithfully.
//! - Within `check_field_handle`: bounds check on `owner` fires
//!   before the field-offset-within-struct check. Native-struct
//!   semantics: `fields_count = 0`, so any field index rejects
//!   (preserved byte-faithfully — see
//!   `field_handle_field_offset_against_native_struct_*` tests).
//! - Within each instantiation sub-check: bounds check on the
//!   handle/def field fires before the bounds check on the
//!   `type_parameters` signature index.
//! - Within `check_struct_def` / `check_enum_def`: the
//!   handle bounds check on `struct_handle` / `enum_handle`
//!   fires before any field iteration. Field iteration calls
//!   the extracted [`check_field_def`] helper which performs
//!   the byte-identical sequence (name bounds → `check_type`
//!   recursion → `check_type_parameter` recursion).
//! - Within `check_variant_handle` /
//!   `check_variant_instantiation_handle`: the enum-def-table
//!   bounds check on `enum_def` fires before the variant-tag-
//!   vs-count check. The latter dereferences via the addressed
//!   `EnumDefinition`'s `variants.len()` — safe by virtue of
//!   the prior bounds check.
//!
//! # Shared-variant cross-pass precedence (section 5)
//!
//! [`AdamantValidationError::IndexOutOfBounds`] is the workhorse
//! variant for bounds-checker rejections. Cross-pass shared-
//! variant exposure lands at C-1.4 (constant-pool indices
//! referenced in code units) and at C-2/C-3 (duplication and
//! signature passes). At C-1.1 the variant is introduced but
//! used only by the bounds checker itself; precedence pinning
//! against [`super::constants`]'s
//! [`AdamantValidationError::InvalidConstantType`] /
//! [`AdamantValidationError::MalformedConstantData`] surfaces at
//! C-4 wiring time.
//!
//! Per Q4 Claim 1 of the Phase 5/5b.3 plan-gate disposition,
//! `IndexOutOfBounds` produced by the bounds checker on a
//! constant whose `type_` carries an out-of-range
//! `DatatypeHandleIndex` will win over the constants pass's
//! `InvalidConstantType` precedence under the C-4 invocation
//! order (`bounds_checker` at step-3 position 1; `constants` at
//! step-3 position 3 alphabetical-of-remainder). Two-direction
//! tests pin the claim at C-4. Third instance of the cross-pass
//! shared-variant pattern after `MalformedConstantData` and
//! `MalformedPrivacyMetadata`.
//!
//! # Dead-code allow sunset (section 6)
//!
//! The module-level `#![allow(dead_code)]` is removed at C-4
//! when [`super::super::verify_module`] wires this pass into the
//! step-3 batch. Until then the pass is callable from tests but
//! has no production caller.
//!
//! # References to PROVENANCE.md cross-pass audit anchors (section 7)
//!
//! - "What was forked" / Phase 5/5b.3 C-1.1 sub-section.
//! - "Adamant deviations" / Phase 5/5b.3 C-1.1 sub-section
//!   (typed-error fork; same shape as B-2.x sibling passes).
//! - "Byte-faithful preservation of upstream consensus-affecting
//!   decisions" / cardinality + ordering instances added at
//!   C-1.1 (sub-check sequence; bounds-then-arity pairing).
//! - "Eager-error first-failure-wins" / new internal-to-pass
//!   instance at C-1.1.
//!
//! [`AdamantCompiledModule`]: crate::module::AdamantCompiledModule
//! [`AdamantValidationError`]: crate::validator::error::AdamantValidationError
//! [`verify_impl`]: https://github.com/MystenLabs/sui/blob/mainnet-v1.66.2/external-crates/move/crates/move-binary-format/src/check_bounds.rs#L52

#![allow(
    dead_code,
    reason = "Pass not wired into verify_module until Phase 5/5b.3 C-4."
)]

use adamant_bytecode_format::{ModuleIndex, SignatureToken, TableIndex};

use crate::module::AdamantCompiledModule;

use super::super::error::AdamantValidationError;

/// Verify the deserialized module's index references against
/// §6.2.1.8 step 3 / position 1 (`module_pass::bounds_checker`).
///
/// As of C-1.3 the pass covers positions 1–16 of upstream
/// `BoundsChecker::verify_impl`'s 17 sub-checks: an
/// empty-module-handles short-circuit followed by signatures,
/// constants, module-handles, self-module-handle,
/// datatype-handles, function-handles, field-handles,
/// friend-decls, the three module-level instantiation tables
/// (struct/function/field), struct-defs, enum-defs,
/// enum-instantiations, variant-handles, and
/// variant-instantiation-handles. Sub-checkpoint C-1.4 lands the
/// remaining 1 sub-check (function-defs, the widest one — covers
/// per-bytecode bounds across the entire instruction set).
///
/// Eager-error semantics: returns the first violation encountered
/// in upstream sub-check order.
pub(in crate::validator) fn verify(
    module: &AdamantCompiledModule,
) -> Result<(), AdamantValidationError> {
    if module.module_handles.is_empty() {
        return Err(AdamantValidationError::NoModuleHandles);
    }
    check_signatures(module)?;
    check_constants(module)?;
    check_module_handles(module)?;
    check_self_module_handle(module)?;
    check_datatype_handles(module)?;
    check_function_handles(module)?;
    check_field_handles(module)?;
    check_friend_decls(module)?;
    check_struct_instantiations(module)?;
    check_function_instantiations(module)?;
    check_field_instantiations(module)?;
    check_struct_defs(module)?;
    check_enum_defs(module)?;
    check_enum_instantiations(module)?;
    check_variant_handles(module)?;
    check_variant_instantiation_handles(module)?;
    Ok(())
}

/// For each entry in the signature pool, preorder-traverse every
/// signature token and bounds-check any `Datatype` /
/// `DatatypeInstantiation` references plus their type-argument
/// arity.
fn check_signatures(module: &AdamantCompiledModule) -> Result<(), AdamantValidationError> {
    for signature in &module.signatures {
        for ty in &signature.0 {
            check_type(module, ty)?;
        }
    }
    Ok(())
}

/// For each entry in the constant pool, bounds-check the
/// declared constant type via `check_type`.
fn check_constants(module: &AdamantCompiledModule) -> Result<(), AdamantValidationError> {
    for constant in &module.constant_pool {
        check_type(module, &constant.type_)?;
    }
    Ok(())
}

/// For each module-handle entry, validate that its `address`
/// resolves into the address-identifier pool and its `name`
/// resolves into the identifier pool. Reused by
/// [`check_friend_decls`] over `module.friend_decls`, since
/// upstream models friend declarations as the same `ModuleHandle`
/// shape.
fn check_module_handles(module: &AdamantCompiledModule) -> Result<(), AdamantValidationError> {
    for module_handle in &module.module_handles {
        check_module_handle(module, module_handle)?;
    }
    Ok(())
}

/// Per-handle validator extracted at C-1.2 so [`check_friend_decls`]
/// can reuse it. Mirrors upstream's
/// `BoundsChecker::check_module_handle` byte-faithfully:
/// bounds-check `address` first, then `name`.
fn check_module_handle(
    module: &AdamantCompiledModule,
    module_handle: &adamant_bytecode_format::ModuleHandle,
) -> Result<(), AdamantValidationError> {
    check_index(module.address_identifiers.len(), module_handle.address)?;
    check_index(module.identifiers.len(), module_handle.name)?;
    Ok(())
}

/// Validate that the module's `self_module_handle_idx` resolves
/// into the module-handle table.
fn check_self_module_handle(module: &AdamantCompiledModule) -> Result<(), AdamantValidationError> {
    check_index(module.module_handles.len(), module.self_module_handle_idx)
}

/// For each datatype-handle entry, validate that its `module`
/// resolves into the module-handle pool and its `name` resolves
/// into the identifier pool.
fn check_datatype_handles(module: &AdamantCompiledModule) -> Result<(), AdamantValidationError> {
    for datatype_handle in &module.datatype_handles {
        check_index(module.module_handles.len(), datatype_handle.module)?;
        check_index(module.identifiers.len(), datatype_handle.name)?;
    }
    Ok(())
}

/// Preorder-traverse a signature token tree and bounds-check
/// every `Datatype` / `DatatypeInstantiation` reference plus its
/// type-argument arity against the addressed `DatatypeHandle`.
///
/// For `Datatype(idx)`: if the handle declares any type
/// parameters, the bare form supplies zero — reject with
/// `NumberOfTypeArgumentsMismatch { expected: N, actual: 0 }`.
///
/// For `DatatypeInstantiation(idx, type_args)`: if
/// `type_args.len() != handle.type_parameters.len()`, reject
/// with `NumberOfTypeArgumentsMismatch { expected, actual }`.
///
/// Bounds check fires first; arity check is skipped on bounds
/// failure (mirrors upstream's `?` ordering).
fn check_type(
    module: &AdamantCompiledModule,
    ty: &SignatureToken,
) -> Result<(), AdamantValidationError> {
    for visited in ty.preorder_traversal() {
        match visited {
            SignatureToken::Bool
            | SignatureToken::U8
            | SignatureToken::U16
            | SignatureToken::U32
            | SignatureToken::U64
            | SignatureToken::U128
            | SignatureToken::U256
            | SignatureToken::Address
            | SignatureToken::Signer
            | SignatureToken::TypeParameter(_)
            | SignatureToken::Reference(_)
            | SignatureToken::MutableReference(_)
            | SignatureToken::Vector(_) => {}
            SignatureToken::Datatype(idx) => {
                check_index(module.datatype_handles.len(), *idx)?;
                let sh = &module.datatype_handles[idx.into_index()];
                if !sh.type_parameters.is_empty() {
                    return Err(AdamantValidationError::NumberOfTypeArgumentsMismatch {
                        datatype_handle_idx: *idx,
                        expected: sh.type_parameters.len(),
                        actual: 0,
                    });
                }
            }
            SignatureToken::DatatypeInstantiation(inst) => {
                let (idx, type_args) = &**inst;
                check_index(module.datatype_handles.len(), *idx)?;
                let sh = &module.datatype_handles[idx.into_index()];
                if sh.type_parameters.len() != type_args.len() {
                    return Err(AdamantValidationError::NumberOfTypeArgumentsMismatch {
                        datatype_handle_idx: *idx,
                        expected: sh.type_parameters.len(),
                        actual: type_args.len(),
                    });
                }
            }
        }
    }
    Ok(())
}

/// For each function-handle entry, validate its referenced
/// indices and recurse into parameter/return signatures to
/// bounds-check any `TypeParameter(idx)` against the handle's
/// declared type-parameter count.
///
/// Upstream's `?` ordering pins bounds-then-recursion: the
/// `module`/`name`/`parameters`/`return_` bounds checks fire
/// before the `check_type_parameter` recursion. The recursion
/// is skipped automatically on bounds failure via the `?`
/// operator (the in-bounds `parameters`/`return_` lookup never
/// runs).
fn check_function_handles(module: &AdamantCompiledModule) -> Result<(), AdamantValidationError> {
    for function_handle in &module.function_handles {
        check_function_handle(module, function_handle)?;
    }
    Ok(())
}

/// Per-handle validator. See [`check_function_handles`] for the
/// pairing-order rationale.
fn check_function_handle(
    module: &AdamantCompiledModule,
    function_handle: &adamant_bytecode_format::FunctionHandle,
) -> Result<(), AdamantValidationError> {
    check_index(module.module_handles.len(), function_handle.module)?;
    check_index(module.identifiers.len(), function_handle.name)?;
    check_index(module.signatures.len(), function_handle.parameters)?;
    check_index(module.signatures.len(), function_handle.return_)?;
    let type_param_count = function_handle.type_parameters.len();
    let parameters_sig = &module.signatures[function_handle.parameters.into_index()];
    for ty in &parameters_sig.0 {
        check_type_parameter(ty, type_param_count)?;
    }
    let return_sig = &module.signatures[function_handle.return_.into_index()];
    for ty in &return_sig.0 {
        check_type_parameter(ty, type_param_count)?;
    }
    Ok(())
}

/// Preorder-traverse a signature token tree and bounds-check
/// every `TypeParameter(idx)` against `type_param_count`.
///
/// Mirrors upstream's `BoundsChecker::check_type_parameter`. The
/// non-`TypeParameter` arms are no-ops; the preorder traversal
/// already descends into containers (`Vector`, `Reference`,
/// `MutableReference`, `DatatypeInstantiation`) so each visited
/// node's match arm only handles the leaf-shape decision.
fn check_type_parameter(
    ty: &SignatureToken,
    type_param_count: usize,
) -> Result<(), AdamantValidationError> {
    for visited in ty.preorder_traversal() {
        if let SignatureToken::TypeParameter(idx) = visited {
            if (*idx as usize) >= type_param_count {
                return Err(AdamantValidationError::IndexOutOfBounds {
                    kind: adamant_bytecode_format::IndexKind::TypeParameter,
                    idx: *idx,
                    pool_len: type_param_count,
                });
            }
        }
    }
    Ok(())
}

/// For each field-handle entry, validate `owner` ∈ `struct_defs`
/// and `field` < the addressed struct's field count.
///
/// **Native-struct semantics:** `fields_count = 0` for
/// [`adamant_bytecode_format::StructFieldInformation::Native`];
/// any field index rejects (preserved byte-faithfully from
/// upstream's `match`-then-`>=` pattern). Pinned by the
/// `field_handle_field_offset_against_native_struct_*` tests.
///
/// **Inline check rather than the generic
/// [`check_index`] helper:** `MemberCount` is a `u16` typedef
/// (not a `*Index` newtype implementing
/// [`adamant_bytecode_format::ModuleIndex`]), so the generic
/// helper signature doesn't apply. The inline form keeps the
/// kind explicit at the call site and matches upstream's
/// equivalent inline `bounds_error(...)` shape.
fn check_field_handles(module: &AdamantCompiledModule) -> Result<(), AdamantValidationError> {
    for field_handle in &module.field_handles {
        check_index(module.struct_defs.len(), field_handle.owner)?;
        let struct_def = &module.struct_defs[field_handle.owner.into_index()];
        let fields_count = match &struct_def.field_information {
            adamant_bytecode_format::StructFieldInformation::Native => 0,
            adamant_bytecode_format::StructFieldInformation::Declared(fields) => fields.len(),
        };
        if (field_handle.field as usize) >= fields_count {
            return Err(AdamantValidationError::IndexOutOfBounds {
                kind: adamant_bytecode_format::IndexKind::MemberCount,
                idx: field_handle.field,
                pool_len: fields_count,
            });
        }
    }
    Ok(())
}

/// For each friend declaration, run the same per-handle
/// validation as [`check_module_handle`]. Upstream models friend
/// declarations as `ModuleHandle` values stored in a separate
/// list; the bounds-checking shape is identical.
fn check_friend_decls(module: &AdamantCompiledModule) -> Result<(), AdamantValidationError> {
    for friend in &module.friend_decls {
        check_module_handle(module, friend)?;
    }
    Ok(())
}

/// For each struct-def-instantiation entry, validate `def` ∈
/// `struct_defs` and `type_parameters` ∈ signatures.
fn check_struct_instantiations(
    module: &AdamantCompiledModule,
) -> Result<(), AdamantValidationError> {
    for struct_inst in &module.struct_def_instantiations {
        check_index(module.struct_defs.len(), struct_inst.def)?;
        check_index(module.signatures.len(), struct_inst.type_parameters)?;
    }
    Ok(())
}

/// For each function-instantiation entry, validate `handle` ∈
/// `function_handles` and `type_parameters` ∈ signatures.
fn check_function_instantiations(
    module: &AdamantCompiledModule,
) -> Result<(), AdamantValidationError> {
    for function_inst in &module.function_instantiations {
        check_index(module.function_handles.len(), function_inst.handle)?;
        check_index(module.signatures.len(), function_inst.type_parameters)?;
    }
    Ok(())
}

/// For each field-instantiation entry, validate `handle` ∈
/// `field_handles` and `type_parameters` ∈ signatures.
fn check_field_instantiations(
    module: &AdamantCompiledModule,
) -> Result<(), AdamantValidationError> {
    for field_inst in &module.field_instantiations {
        check_index(module.field_handles.len(), field_inst.handle)?;
        check_index(module.signatures.len(), field_inst.type_parameters)?;
    }
    Ok(())
}

/// For each struct definition, validate `struct_handle` ∈
/// `datatype_handles` and (for declared structs) recurse into
/// each field's name and signature via [`check_field_def`].
///
/// **Native-struct field iteration:** [`StructFieldInformation::Native`]
/// has no fields; the iteration is skipped (matching upstream's
/// `if let StructFieldInformation::Declared(...)` gate).
fn check_struct_defs(module: &AdamantCompiledModule) -> Result<(), AdamantValidationError> {
    for struct_def in &module.struct_defs {
        check_index(module.datatype_handles.len(), struct_def.struct_handle)?;
        if let adamant_bytecode_format::StructFieldInformation::Declared(fields) =
            &struct_def.field_information
        {
            // The bounds check above guarantees the handle is
            // in-range; the indexing here is structurally safe.
            let type_param_count = module.datatype_handles[struct_def.struct_handle.into_index()]
                .type_parameters
                .len();
            for field in fields {
                check_field_def(module, field, type_param_count)?;
            }
        }
    }
    Ok(())
}

/// For each enum definition, validate `enum_handle` ∈
/// `datatype_handles` and recurse into each variant's name and
/// each variant's fields via [`check_field_def`].
fn check_enum_defs(module: &AdamantCompiledModule) -> Result<(), AdamantValidationError> {
    for enum_def in &module.enum_defs {
        check_index(module.datatype_handles.len(), enum_def.enum_handle)?;
        let type_param_count = module.datatype_handles[enum_def.enum_handle.into_index()]
            .type_parameters
            .len();
        for variant in &enum_def.variants {
            check_index(module.identifiers.len(), variant.variant_name)?;
            for field in &variant.fields {
                check_field_def(module, field, type_param_count)?;
            }
        }
    }
    Ok(())
}

/// Per-field validator extracted at C-1.3 with byte-identical
/// shape to the inline body upstream Sui places inside both
/// `check_struct_def` and `check_enum_def`. Three sub-steps:
///
/// 1. The field's `name` indexes into the identifier pool.
/// 2. The field's signature is bounds-checked via
///    [`check_type`] (preorder; rejects out-of-range
///    `Datatype` / `DatatypeInstantiation` references plus
///    type-argument arity violations).
/// 3. The field's signature is bounds-checked via
///    [`check_type_parameter`] (preorder; rejects out-of-range
///    `TypeParameter` references against the addressed
///    handle's declared type-parameter count).
///
/// **Deliberate-Adamant-decision (per Phase 5/5b.3 C-1.3 plan-
/// gate Q1):** upstream Sui inlines this 3-step body in both
/// `check_struct_def` and `check_enum_def`. The Adamant fork
/// extracts the helper at N=2 with byte-identical bodies per
/// the per-handle-extraction refactor pattern (rule-of-three at
/// N=2 with byte-identical bodies). The helper name is chosen
/// for parallel structure with the existing `check_struct_def`
/// and `check_enum_def` per-def validators; alternatives
/// considered include `check_field_def_bounds` (verbose) and
/// `check_field_def_signature` (more specific to the signature
/// recursion aspect, but obscures the name-bounds check).
fn check_field_def(
    module: &AdamantCompiledModule,
    field: &adamant_bytecode_format::FieldDefinition,
    type_param_count: usize,
) -> Result<(), AdamantValidationError> {
    check_index(module.identifiers.len(), field.name)?;
    check_type(module, &field.signature.0)?;
    check_type_parameter(&field.signature.0, type_param_count)?;
    Ok(())
}

/// For each enum-def-instantiation entry, validate `def` ∈
/// `enum_defs` and `type_parameters` ∈ signatures. Sibling to
/// C-1.2's struct/function/field instantiation checks.
fn check_enum_instantiations(module: &AdamantCompiledModule) -> Result<(), AdamantValidationError> {
    for enum_inst in &module.enum_def_instantiations {
        check_index(module.enum_defs.len(), enum_inst.def)?;
        check_index(module.signatures.len(), enum_inst.type_parameters)?;
    }
    Ok(())
}

/// For each variant handle, validate `enum_def` ∈ `enum_defs`
/// and `variant` < the addressed enum's variant count.
///
/// The variant-tag check is **inline** (not via [`check_index`])
/// because [`adamant_bytecode_format::VariantTag`] is a `u16`
/// typedef rather than a `*Index` newtype implementing
/// [`adamant_bytecode_format::ModuleIndex`] — same shape as
/// C-1.2's `MemberCount` field-offset check. The error reports
/// `IndexKind::VariantTag` to discriminate the addressed pool.
fn check_variant_handles(module: &AdamantCompiledModule) -> Result<(), AdamantValidationError> {
    for variant_handle in &module.variant_handles {
        check_index(module.enum_defs.len(), variant_handle.enum_def)?;
        let enum_def = &module.enum_defs[variant_handle.enum_def.into_index()];
        let variants_count = enum_def.variants.len();
        if (variant_handle.variant as usize) >= variants_count {
            return Err(AdamantValidationError::IndexOutOfBounds {
                kind: adamant_bytecode_format::IndexKind::VariantTag,
                idx: variant_handle.variant,
                pool_len: variants_count,
            });
        }
    }
    Ok(())
}

/// For each variant-instantiation handle, validate `enum_def` ∈
/// `enum_def_instantiations` and `variant` < the resolved enum's
/// variant count.
///
/// **Intra-sub-checkpoint structural-impossibility pin (per
/// Phase 5/5b.3 C-1.3 plan-gate Q2):** dereferencing into
/// `enum_def_instantiations` then dereferencing the resolved
/// instantiation's `def` into `enum_defs` is safe because
/// [`check_enum_instantiations`] (sub-check at upstream
/// `verify_impl` position 14) ran earlier in the same `verify`
/// invocation and validated `def` ∈ `enum_defs` and
/// `type_parameters` ∈ `signatures` for every entry in
/// `enum_def_instantiations`. The `debug_assert!` calls below
/// pin this intra-sub-checkpoint guarantee.
///
/// Distinct from the cross-pass structural-impossibility
/// instances (B-2.4 deprecated-arms, B-3.1 `<SELF>`, B-3.3
/// native-function filter, B-3.2 duplicate-handle/reference-field):
/// the upstream-of-this-pass guarantee here comes from THE SAME
/// PASS at an earlier sub-check, not from a different pass.
/// Registered as a new sub-pattern of the structural-
/// impossibility-checks pattern at the C-5 closure batch.
fn check_variant_instantiation_handles(
    module: &AdamantCompiledModule,
) -> Result<(), AdamantValidationError> {
    for vih in &module.variant_instantiation_handles {
        check_index(module.enum_def_instantiations.len(), vih.enum_def)?;
        let enum_inst = &module.enum_def_instantiations[vih.enum_def.into_index()];
        debug_assert!(
            enum_inst.def.into_index() < module.enum_defs.len(),
            "intra-sub-checkpoint structural impossibility: \
             check_enum_instantiations (verify_impl position 14) validated \
             def ∈ enum_defs for every enum_def_instantiation entry before \
             check_variant_instantiation_handles (position 16) reached this \
             dereference. A fired debug_assert here indicates an intra-\
             sub-checkpoint ordering bug in verify()."
        );
        debug_assert!(
            enum_inst.type_parameters.into_index() < module.signatures.len(),
            "intra-sub-checkpoint structural impossibility: \
             check_enum_instantiations (verify_impl position 14) validated \
             type_parameters ∈ signatures for every enum_def_instantiation \
             entry before check_variant_instantiation_handles (position 16) \
             reached this point."
        );
        let enum_def = &module.enum_defs[enum_inst.def.into_index()];
        let variants_count = enum_def.variants.len();
        if (vih.variant as usize) >= variants_count {
            return Err(AdamantValidationError::IndexOutOfBounds {
                kind: adamant_bytecode_format::IndexKind::VariantTag,
                idx: vih.variant,
                pool_len: variants_count,
            });
        }
    }
    Ok(())
}

/// Generic `idx < pool_len` check returning a typed
/// [`AdamantValidationError::IndexOutOfBounds`] tagged with the
/// addressed pool's `IndexKind`.
///
/// Mirrors upstream's `check_bounds_impl<T, I: ModuleIndex>`. The
/// pool itself is not consulted — only its length — so callers
/// pass `pool.len()` directly to avoid a generic parameter for
/// the pool element type. `I::KIND` discriminates the pool in
/// the produced error.
fn check_index<I: ModuleIndex>(pool_len: usize, idx: I) -> Result<(), AdamantValidationError> {
    let i = idx.into_index();
    if i >= pool_len {
        Err(AdamantValidationError::IndexOutOfBounds {
            kind: I::KIND,
            idx: TableIndex::try_from(i).expect(
                "any index produced by ModuleIndex::into_index() fits TableIndex (u16); \
                 *Index newtypes wrap u16 underneath the binary format",
            ),
            pool_len,
        })
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use adamant_bytecode_format::{
        AbilitySet, AddressIdentifierIndex, Constant, DatatypeHandle, DatatypeHandleIndex,
        DatatypeTyParameter, EnumDefInstantiation, EnumDefInstantiationIndex, EnumDefinition,
        EnumDefinitionIndex, FieldDefinition, FieldHandle, FieldHandleIndex, FieldInstantiation,
        FunctionHandle, FunctionHandleIndex, FunctionInstantiation, Identifier, IdentifierIndex,
        IndexKind, ModuleHandle, ModuleHandleIndex, Signature, SignatureIndex, SignatureToken,
        StructDefInstantiation, StructDefinition, StructDefinitionIndex, StructFieldInformation,
        TypeSignature, VariantDefinition, VariantHandle, VariantInstantiationHandle,
    };
    use adamant_types::Address as AccountAddress;

    use crate::module::AdamantCompiledModule;

    use super::super::super::error::AdamantValidationError;
    use super::super::test_helpers::assert_pass_parity;
    use super::verify;

    /// Build a fixture module shell with the self-handle
    /// referencing identifier 0 ("M") and address 0 ([0u8; 32]).
    /// Standard "module-self-identity" wiring used across the
    /// module-pass tests; matches `friends.rs::tests::empty_module`.
    fn empty_module() -> AdamantCompiledModule {
        AdamantCompiledModule {
            self_module_handle_idx: ModuleHandleIndex(0),
            module_handles: vec![ModuleHandle {
                address: AddressIdentifierIndex(0),
                name: IdentifierIndex(0),
            }],
            identifiers: vec![Identifier::new("M").unwrap()],
            address_identifiers: vec![AccountAddress::from_bytes([0u8; 32])],
            ..AdamantCompiledModule::default()
        }
    }

    /// Construct a `DatatypeTyParameter` with the given
    /// `is_phantom` and a no-constraint `AbilitySet::EMPTY`. The
    /// type-parameter ability set is irrelevant to the bounds
    /// checker — its only consumer is the `ability_field_requirements`
    /// pass at a later pipeline position.
    fn ty_param(is_phantom: bool) -> DatatypeTyParameter {
        DatatypeTyParameter {
            constraints: AbilitySet::EMPTY,
            is_phantom,
        }
    }

    /// Build a fixture extending `empty_module()` with one
    /// declared struct definition carrying `field_count` fields
    /// of type `u64`. The struct's `struct_handle` is set to
    /// a freshly-added in-bounds [`DatatypeHandle`]; the field
    /// names are auto-generated (`f0`, `f1`, ...). Pre-condition:
    /// no other modifications to the input fixture's
    /// `datatype_handles` table; the new handle lands at index 0.
    fn module_with_one_declared_struct_def(field_count: u16) -> AdamantCompiledModule {
        let mut m = empty_module();
        m.identifiers.push(Identifier::new("S").unwrap());
        m.datatype_handles.push(DatatypeHandle {
            module: ModuleHandleIndex(0),
            name: IdentifierIndex(1),
            abilities: AbilitySet::EMPTY,
            type_parameters: vec![],
        });
        let mut fields = Vec::with_capacity(field_count as usize);
        for i in 0..field_count {
            m.identifiers
                .push(Identifier::new(format!("f{i}")).unwrap());
            // identifiers[0] = "M", [1] = "S", [2..] = field names
            fields.push(FieldDefinition {
                name: IdentifierIndex(2 + i),
                signature: TypeSignature(SignatureToken::U64),
            });
        }
        m.struct_defs.push(StructDefinition {
            struct_handle: DatatypeHandleIndex(0),
            field_information: StructFieldInformation::Declared(fields),
        });
        m
    }

    /// Build a fixture extending `empty_module()` with one
    /// **native** struct definition. The pass's per-handle
    /// validator computes `fields_count = 0` for native structs;
    /// any field index against this struct rejects.
    fn module_with_one_native_struct_def() -> AdamantCompiledModule {
        let mut m = empty_module();
        m.identifiers.push(Identifier::new("N").unwrap());
        m.datatype_handles.push(DatatypeHandle {
            module: ModuleHandleIndex(0),
            name: IdentifierIndex(1),
            abilities: AbilitySet::EMPTY,
            type_parameters: vec![],
        });
        m.struct_defs.push(StructDefinition {
            struct_handle: DatatypeHandleIndex(0),
            field_information: StructFieldInformation::Native,
        });
        m
    }

    /// Build a fixture extending `empty_module()` with one
    /// enum definition. The enum has `variant_count` variants,
    /// each carrying `fields_per_variant` `u64` fields. The
    /// variant names and field names are auto-generated
    /// (`v0`/`v1`/... for variants; `f0`/`f1`/... for fields).
    /// `enum_handle` lands at `DatatypeHandleIndex(0)`; the
    /// addressed `DatatypeHandle` declares no type parameters
    /// (callers needing type parameters mutate the handle
    /// directly afterwards).
    fn module_with_one_enum_def(
        variant_count: u16,
        fields_per_variant: u16,
    ) -> AdamantCompiledModule {
        let mut m = empty_module();
        m.identifiers.push(Identifier::new("E").unwrap());
        m.datatype_handles.push(DatatypeHandle {
            module: ModuleHandleIndex(0),
            name: IdentifierIndex(1),
            abilities: AbilitySet::EMPTY,
            type_parameters: vec![],
        });
        let mut variants = Vec::with_capacity(variant_count as usize);
        for v_idx in 0..variant_count {
            // identifiers[0]="M",[1]="E",[2..]=variant/field names.
            // Layout per call: vN at index 2 + v_idx * (1+fields_per_variant);
            // the variant's field names follow.
            let variant_name_idx = u16::try_from(m.identifiers.len())
                .expect("test fixture has < u16::MAX identifiers");
            m.identifiers
                .push(Identifier::new(format!("v{v_idx}")).unwrap());
            let mut fields = Vec::with_capacity(fields_per_variant as usize);
            for f_idx in 0..fields_per_variant {
                let field_name_idx = u16::try_from(m.identifiers.len())
                    .expect("test fixture has < u16::MAX identifiers");
                m.identifiers
                    .push(Identifier::new(format!("f{v_idx}_{f_idx}")).unwrap());
                fields.push(FieldDefinition {
                    name: IdentifierIndex(field_name_idx),
                    signature: TypeSignature(SignatureToken::U64),
                });
            }
            variants.push(VariantDefinition {
                variant_name: IdentifierIndex(variant_name_idx),
                fields,
            });
        }
        m.enum_defs.push(EnumDefinition {
            enum_handle: DatatypeHandleIndex(0),
            variants,
        });
        m
    }

    /// Build a fixture extending `empty_module()` with one
    /// enum definition (via `module_with_one_enum_def`) plus a
    /// matching `EnumDefInstantiation` pointing at it with a
    /// single `U64` type-parameter signature. Both the
    /// enum-def and the enum-instantiation table land at
    /// position 0 of their respective tables.
    fn module_with_one_enum_def_instantiation(
        variant_count: u16,
        fields_per_variant: u16,
    ) -> AdamantCompiledModule {
        let mut m = module_with_one_enum_def(variant_count, fields_per_variant);
        m.signatures.push(Signature(vec![SignatureToken::U64]));
        m.enum_def_instantiations.push(EnumDefInstantiation {
            def: EnumDefinitionIndex(0),
            type_parameters: SignatureIndex(0),
        });
        m
    }

    /// Build a fixture extending `empty_module()` with two
    /// signatures (empty parameter list at index 0, empty return
    /// list at index 1) and a single function handle pointing at
    /// them with no type parameters. Used as the C-1.2
    /// function-handle "all-valid" base; negative-case fixtures
    /// override individual indices.
    fn module_with_one_function_handle() -> AdamantCompiledModule {
        let mut m = empty_module();
        m.signatures.push(Signature(vec![])); // parameters at SignatureIndex(0)
        m.signatures.push(Signature(vec![])); // return at SignatureIndex(1)
        m.identifiers.push(Identifier::new("foo").unwrap());
        m.function_handles.push(FunctionHandle {
            module: ModuleHandleIndex(0),
            name: IdentifierIndex(1),
            parameters: SignatureIndex(0),
            return_: SignatureIndex(1),
            type_parameters: vec![],
        });
        m
    }

    // --- Layer A: positive cases ---

    #[test]
    fn empty_module_passes() {
        let m = empty_module();
        assert!(verify(&m).is_ok());
    }

    #[test]
    fn signature_pool_with_primitives_passes() {
        let mut m = empty_module();
        m.signatures.push(Signature(vec![
            SignatureToken::Bool,
            SignatureToken::U8,
            SignatureToken::U64,
            SignatureToken::U256,
            SignatureToken::Address,
            SignatureToken::Signer,
            SignatureToken::TypeParameter(0),
        ]));
        assert!(verify(&m).is_ok());
    }

    #[test]
    fn signature_pool_with_nested_vector_and_reference_passes() {
        let mut m = empty_module();
        // Vector<&u64>
        m.signatures
            .push(Signature(vec![SignatureToken::Vector(Box::new(
                SignatureToken::Reference(Box::new(SignatureToken::U64)),
            ))]));
        assert!(verify(&m).is_ok());
    }

    #[test]
    fn constant_pool_with_valid_types_passes() {
        let mut m = empty_module();
        m.constant_pool.push(Constant {
            type_: SignatureToken::U64,
            data: vec![0u8; 8],
        });
        m.constant_pool.push(Constant {
            type_: SignatureToken::Vector(Box::new(SignatureToken::U8)),
            data: vec![0],
        });
        assert!(verify(&m).is_ok());
    }

    #[test]
    fn datatype_handle_with_no_type_params_referenced_via_datatype_passes() {
        let mut m = empty_module();
        m.identifiers.push(Identifier::new("S").unwrap());
        m.datatype_handles.push(DatatypeHandle {
            module: ModuleHandleIndex(0),
            name: IdentifierIndex(1),
            abilities: AbilitySet::EMPTY,
            type_parameters: vec![],
        });
        m.signatures.push(Signature(vec![SignatureToken::Datatype(
            DatatypeHandleIndex(0),
        )]));
        assert!(verify(&m).is_ok());
    }

    #[test]
    fn datatype_handle_with_two_type_params_referenced_via_instantiation_passes() {
        let mut m = empty_module();
        m.identifiers.push(Identifier::new("S").unwrap());
        m.datatype_handles.push(DatatypeHandle {
            module: ModuleHandleIndex(0),
            name: IdentifierIndex(1),
            abilities: AbilitySet::EMPTY,
            type_parameters: vec![ty_param(false), ty_param(false)],
        });
        m.signatures
            .push(Signature(vec![SignatureToken::DatatypeInstantiation(
                Box::new((
                    DatatypeHandleIndex(0),
                    vec![SignatureToken::U64, SignatureToken::Bool],
                )),
            )]));
        assert!(verify(&m).is_ok());
    }

    // --- Layer A: negative cases ---

    #[test]
    fn rejects_empty_module_handles() {
        let m = AdamantCompiledModule::default();
        match verify(&m) {
            Err(AdamantValidationError::NoModuleHandles) => {}
            other => panic!("expected NoModuleHandles, got {other:?}"),
        }
    }

    #[test]
    fn rejects_signature_with_oob_datatype() {
        let mut m = empty_module();
        // datatype_handles is empty; reference index 5.
        m.signatures.push(Signature(vec![SignatureToken::Datatype(
            DatatypeHandleIndex(5),
        )]));
        match verify(&m) {
            Err(AdamantValidationError::IndexOutOfBounds {
                kind: IndexKind::DatatypeHandle,
                idx: 5,
                pool_len: 0,
            }) => {}
            other => panic!("expected IndexOutOfBounds(DatatypeHandle, 5, 0), got {other:?}"),
        }
    }

    #[test]
    fn rejects_constant_with_oob_datatype_in_type_field() {
        let mut m = empty_module();
        m.constant_pool.push(Constant {
            type_: SignatureToken::Datatype(DatatypeHandleIndex(7)),
            data: vec![],
        });
        match verify(&m) {
            Err(AdamantValidationError::IndexOutOfBounds {
                kind: IndexKind::DatatypeHandle,
                idx: 7,
                pool_len: 0,
            }) => {}
            other => panic!("expected IndexOutOfBounds(DatatypeHandle, 7, 0), got {other:?}"),
        }
    }

    #[test]
    fn rejects_module_handle_with_oob_address() {
        let mut m = empty_module();
        // Add a second module-handle pointing at out-of-range address index 9.
        m.module_handles.push(ModuleHandle {
            address: AddressIdentifierIndex(9),
            name: IdentifierIndex(0),
        });
        match verify(&m) {
            Err(AdamantValidationError::IndexOutOfBounds {
                kind: IndexKind::AddressIdentifier,
                idx: 9,
                pool_len: 1,
            }) => {}
            other => panic!("expected IndexOutOfBounds(AddressIdentifier, 9, 1), got {other:?}"),
        }
    }

    #[test]
    fn rejects_module_handle_with_oob_name() {
        let mut m = empty_module();
        m.module_handles.push(ModuleHandle {
            address: AddressIdentifierIndex(0),
            name: IdentifierIndex(11),
        });
        match verify(&m) {
            Err(AdamantValidationError::IndexOutOfBounds {
                kind: IndexKind::Identifier,
                idx: 11,
                pool_len: 1,
            }) => {}
            other => panic!("expected IndexOutOfBounds(Identifier, 11, 1), got {other:?}"),
        }
    }

    #[test]
    fn rejects_self_module_handle_oob() {
        let mut m = empty_module();
        m.self_module_handle_idx = ModuleHandleIndex(7);
        match verify(&m) {
            Err(AdamantValidationError::IndexOutOfBounds {
                kind: IndexKind::ModuleHandle,
                idx: 7,
                pool_len: 1,
            }) => {}
            other => panic!("expected IndexOutOfBounds(ModuleHandle, 7, 1), got {other:?}"),
        }
    }

    #[test]
    fn rejects_datatype_handle_with_oob_module() {
        let mut m = empty_module();
        m.identifiers.push(Identifier::new("S").unwrap());
        m.datatype_handles.push(DatatypeHandle {
            module: ModuleHandleIndex(4),
            name: IdentifierIndex(1),
            abilities: AbilitySet::EMPTY,
            type_parameters: vec![],
        });
        match verify(&m) {
            Err(AdamantValidationError::IndexOutOfBounds {
                kind: IndexKind::ModuleHandle,
                idx: 4,
                pool_len: 1,
            }) => {}
            other => panic!("expected IndexOutOfBounds(ModuleHandle, 4, 1), got {other:?}"),
        }
    }

    #[test]
    fn rejects_datatype_handle_with_oob_name() {
        let mut m = empty_module();
        m.datatype_handles.push(DatatypeHandle {
            module: ModuleHandleIndex(0),
            name: IdentifierIndex(8),
            abilities: AbilitySet::EMPTY,
            type_parameters: vec![],
        });
        match verify(&m) {
            Err(AdamantValidationError::IndexOutOfBounds {
                kind: IndexKind::Identifier,
                idx: 8,
                pool_len: 1,
            }) => {}
            other => panic!("expected IndexOutOfBounds(Identifier, 8, 1), got {other:?}"),
        }
    }

    #[test]
    fn rejects_datatype_with_zero_args_when_handle_expects_two() {
        let mut m = empty_module();
        m.identifiers.push(Identifier::new("S").unwrap());
        m.datatype_handles.push(DatatypeHandle {
            module: ModuleHandleIndex(0),
            name: IdentifierIndex(1),
            abilities: AbilitySet::EMPTY,
            type_parameters: vec![ty_param(false), ty_param(false)],
        });
        m.signatures.push(Signature(vec![SignatureToken::Datatype(
            DatatypeHandleIndex(0),
        )]));
        match verify(&m) {
            Err(AdamantValidationError::NumberOfTypeArgumentsMismatch {
                datatype_handle_idx: DatatypeHandleIndex(0),
                expected: 2,
                actual: 0,
            }) => {}
            other => panic!(
                "expected NumberOfTypeArgumentsMismatch(0, expected 2, actual 0), \
                 got {other:?}"
            ),
        }
    }

    #[test]
    fn rejects_datatype_instantiation_with_arity_mismatch() {
        let mut m = empty_module();
        m.identifiers.push(Identifier::new("S").unwrap());
        m.datatype_handles.push(DatatypeHandle {
            module: ModuleHandleIndex(0),
            name: IdentifierIndex(1),
            abilities: AbilitySet::EMPTY,
            type_parameters: vec![ty_param(false), ty_param(false)],
        });
        // Supplied 1 type arg vs handle's declared 2.
        m.signatures
            .push(Signature(vec![SignatureToken::DatatypeInstantiation(
                Box::new((DatatypeHandleIndex(0), vec![SignatureToken::U64])),
            )]));
        match verify(&m) {
            Err(AdamantValidationError::NumberOfTypeArgumentsMismatch {
                datatype_handle_idx: DatatypeHandleIndex(0),
                expected: 2,
                actual: 1,
            }) => {}
            other => panic!("expected NumberOfTypeArgumentsMismatch(0, 2, 1), got {other:?}"),
        }
    }

    #[test]
    fn datatype_instantiation_bounds_check_fires_before_arity_check() {
        // Reference index 5 (out of bounds; datatype_handles is
        // empty); supplied 2 type args. Bounds check is upstream
        // of the arity check; the OOB error fires first per the
        // bounds-then-arity pairing preserved at C-1.1.
        let mut m = empty_module();
        m.signatures
            .push(Signature(vec![SignatureToken::DatatypeInstantiation(
                Box::new((
                    DatatypeHandleIndex(5),
                    vec![SignatureToken::U64, SignatureToken::Bool],
                )),
            )]));
        match verify(&m) {
            Err(AdamantValidationError::IndexOutOfBounds {
                kind: IndexKind::DatatypeHandle,
                idx: 5,
                pool_len: 0,
            }) => {}
            other => panic!("expected IndexOutOfBounds (bounds wins over arity), got {other:?}"),
        }
    }

    #[test]
    fn rejects_signature_with_nested_oob_datatype_via_preorder() {
        // Vector<Datatype(99)> — the OOB lives inside the vector
        // element type. Preorder traversal visits the inner
        // Datatype node and surfaces the OOB.
        let mut m = empty_module();
        m.signatures
            .push(Signature(vec![SignatureToken::Vector(Box::new(
                SignatureToken::Datatype(DatatypeHandleIndex(99)),
            ))]));
        match verify(&m) {
            Err(AdamantValidationError::IndexOutOfBounds {
                kind: IndexKind::DatatypeHandle,
                idx: 99,
                pool_len: 0,
            }) => {}
            other => panic!("expected nested-OOB report via preorder, got {other:?}"),
        }
    }

    #[test]
    fn signatures_check_fires_before_constants_eager_error() {
        // Both pools carry an OOB Datatype reference. Sub-check
        // ordering puts signatures first; the signature OOB at
        // index 1 wins over the constant OOB at index 7.
        let mut m = empty_module();
        m.signatures.push(Signature(vec![SignatureToken::Datatype(
            DatatypeHandleIndex(1),
        )]));
        m.constant_pool.push(Constant {
            type_: SignatureToken::Datatype(DatatypeHandleIndex(7)),
            data: vec![],
        });
        match verify(&m) {
            Err(AdamantValidationError::IndexOutOfBounds {
                kind: IndexKind::DatatypeHandle,
                idx: 1,
                pool_len: 0,
            }) => {}
            other => panic!("expected signatures-pass OOB(1) to win, got {other:?}"),
        }
    }

    // --- Layer A: C-1.2 sub-checks (positions 6–11 of upstream verify_impl) ---

    // check_function_handles ---------------------------------------------------

    #[test]
    fn function_handle_with_valid_indices_passes() {
        let m = module_with_one_function_handle();
        assert!(verify(&m).is_ok());
    }

    #[test]
    fn function_handle_with_type_parameter_in_parameters_passes() {
        let mut m = module_with_one_function_handle();
        // Replace SignatureIndex(0) with a single-token signature
        // referencing TypeParameter(0); add a single type
        // parameter to the function handle so the index is in
        // range.
        m.signatures[0] = Signature(vec![SignatureToken::TypeParameter(0)]);
        m.function_handles[0].type_parameters = vec![AbilitySet::EMPTY];
        assert!(verify(&m).is_ok());
    }

    #[test]
    fn rejects_function_handle_oob_module() {
        let mut m = module_with_one_function_handle();
        m.function_handles[0].module = ModuleHandleIndex(9);
        match verify(&m) {
            Err(AdamantValidationError::IndexOutOfBounds {
                kind: IndexKind::ModuleHandle,
                idx: 9,
                pool_len: 1,
            }) => {}
            other => panic!("expected IndexOutOfBounds(ModuleHandle, 9, 1), got {other:?}"),
        }
    }

    #[test]
    fn rejects_function_handle_oob_name() {
        let mut m = module_with_one_function_handle();
        m.function_handles[0].name = IdentifierIndex(13);
        match verify(&m) {
            Err(AdamantValidationError::IndexOutOfBounds {
                kind: IndexKind::Identifier,
                idx: 13,
                pool_len: 2,
            }) => {}
            other => panic!("expected IndexOutOfBounds(Identifier, 13, 2), got {other:?}"),
        }
    }

    #[test]
    fn rejects_function_handle_oob_parameters() {
        let mut m = module_with_one_function_handle();
        m.function_handles[0].parameters = SignatureIndex(7);
        match verify(&m) {
            Err(AdamantValidationError::IndexOutOfBounds {
                kind: IndexKind::Signature,
                idx: 7,
                pool_len: 2,
            }) => {}
            other => panic!("expected IndexOutOfBounds(Signature, 7, 2), got {other:?}"),
        }
    }

    #[test]
    fn rejects_function_handle_oob_return() {
        let mut m = module_with_one_function_handle();
        m.function_handles[0].return_ = SignatureIndex(11);
        match verify(&m) {
            Err(AdamantValidationError::IndexOutOfBounds {
                kind: IndexKind::Signature,
                idx: 11,
                pool_len: 2,
            }) => {}
            other => panic!("expected IndexOutOfBounds(Signature, 11, 2), got {other:?}"),
        }
    }

    #[test]
    fn rejects_function_handle_parameter_with_oob_type_parameter() {
        let mut m = module_with_one_function_handle();
        // Parameters carry TypeParameter(5) but the function
        // handle declares zero type parameters.
        m.signatures[0] = Signature(vec![SignatureToken::TypeParameter(5)]);
        match verify(&m) {
            Err(AdamantValidationError::IndexOutOfBounds {
                kind: IndexKind::TypeParameter,
                idx: 5,
                pool_len: 0,
            }) => {}
            other => panic!("expected IndexOutOfBounds(TypeParameter, 5, 0), got {other:?}"),
        }
    }

    #[test]
    fn rejects_function_handle_return_with_oob_type_parameter() {
        let mut m = module_with_one_function_handle();
        // Return signature carries TypeParameter(2) but the
        // function handle declares zero type parameters.
        // Parameters stay empty so the recursion reaches the
        // return signature.
        m.signatures[1] = Signature(vec![SignatureToken::TypeParameter(2)]);
        match verify(&m) {
            Err(AdamantValidationError::IndexOutOfBounds {
                kind: IndexKind::TypeParameter,
                idx: 2,
                pool_len: 0,
            }) => {}
            other => panic!("expected IndexOutOfBounds(TypeParameter, 2, 0), got {other:?}"),
        }
    }

    #[test]
    fn function_handle_bounds_check_fires_before_type_parameter_recursion() {
        // Both an OOB `parameters` index (signature OOB) AND a
        // type-parameter violation in the (would-be) parameters
        // signature. The bounds check on `parameters` fires
        // first; the type-parameter recursion never runs.
        let mut m = module_with_one_function_handle();
        // OOB parameters signature index
        m.function_handles[0].parameters = SignatureIndex(7);
        // Modify SignatureIndex(0) to carry a TypeParameter(99)
        // — would trigger the recursion check if reached. With
        // OOB parameters, the recursion is gated behind the
        // bounds check and never runs.
        m.signatures[0] = Signature(vec![SignatureToken::TypeParameter(99)]);
        match verify(&m) {
            Err(AdamantValidationError::IndexOutOfBounds {
                kind: IndexKind::Signature,
                idx: 7,
                pool_len: 2,
            }) => {}
            other => panic!(
                "expected bounds-check OOB on parameters to win over recursion, got {other:?}"
            ),
        }
    }

    // check_field_handles ------------------------------------------------------

    #[test]
    fn field_handle_with_valid_owner_and_field_passes() {
        let mut m = module_with_one_declared_struct_def(2);
        m.field_handles.push(FieldHandle {
            owner: StructDefinitionIndex(0),
            field: 1, // < 2
        });
        assert!(verify(&m).is_ok());
    }

    #[test]
    fn rejects_field_handle_oob_owner() {
        let mut m = empty_module();
        m.field_handles.push(FieldHandle {
            owner: StructDefinitionIndex(3),
            field: 0,
        });
        match verify(&m) {
            Err(AdamantValidationError::IndexOutOfBounds {
                kind: IndexKind::StructDefinition,
                idx: 3,
                pool_len: 0,
            }) => {}
            other => panic!("expected IndexOutOfBounds(StructDefinition, 3, 0), got {other:?}"),
        }
    }

    #[test]
    fn field_handle_field_offset_against_native_struct_field_zero_rejects() {
        // Per implementation-gate item #3: native-struct
        // semantics → fields_count = 0 → any field index
        // rejects. Pin field=0 explicitly so future regressions
        // (e.g., "native means fields_count = u32::MAX") get
        // caught.
        let mut m = module_with_one_native_struct_def();
        m.field_handles.push(FieldHandle {
            owner: StructDefinitionIndex(0),
            field: 0,
        });
        match verify(&m) {
            Err(AdamantValidationError::IndexOutOfBounds {
                kind: IndexKind::MemberCount,
                idx: 0,
                pool_len: 0,
            }) => {}
            other => panic!(
                "expected IndexOutOfBounds(MemberCount, 0, 0) on native struct, got {other:?}"
            ),
        }
    }

    #[test]
    fn field_handle_field_offset_against_native_struct_field_five_rejects() {
        // Same pin but with field=5 to confirm the rejection
        // shape is uniform across all field indices when the
        // owning struct is native.
        let mut m = module_with_one_native_struct_def();
        m.field_handles.push(FieldHandle {
            owner: StructDefinitionIndex(0),
            field: 5,
        });
        match verify(&m) {
            Err(AdamantValidationError::IndexOutOfBounds {
                kind: IndexKind::MemberCount,
                idx: 5,
                pool_len: 0,
            }) => {}
            other => panic!(
                "expected IndexOutOfBounds(MemberCount, 5, 0) on native struct, got {other:?}"
            ),
        }
    }

    #[test]
    fn rejects_field_handle_field_at_or_above_declared_count() {
        let mut m = module_with_one_declared_struct_def(2);
        m.field_handles.push(FieldHandle {
            owner: StructDefinitionIndex(0),
            field: 2, // == fields_count, rejects
        });
        match verify(&m) {
            Err(AdamantValidationError::IndexOutOfBounds {
                kind: IndexKind::MemberCount,
                idx: 2,
                pool_len: 2,
            }) => {}
            other => panic!("expected IndexOutOfBounds(MemberCount, 2, 2), got {other:?}"),
        }
    }

    #[test]
    fn field_handle_owner_bounds_fires_before_field_offset_check() {
        // OOB owner AND a high field index (would fire on
        // fields_count if reached). Owner bounds wins.
        let mut m = empty_module();
        m.field_handles.push(FieldHandle {
            owner: StructDefinitionIndex(9),
            field: 1000,
        });
        match verify(&m) {
            Err(AdamantValidationError::IndexOutOfBounds {
                kind: IndexKind::StructDefinition,
                idx: 9,
                pool_len: 0,
            }) => {}
            other => panic!(
                "expected IndexOutOfBounds(StructDefinition, 9, 0) (owner wins), got {other:?}"
            ),
        }
    }

    // check_friend_decls -------------------------------------------------------

    #[test]
    fn friend_decl_with_valid_indices_passes() {
        let mut m = empty_module();
        m.identifiers.push(Identifier::new("F").unwrap());
        m.friend_decls.push(ModuleHandle {
            address: AddressIdentifierIndex(0),
            name: IdentifierIndex(1),
        });
        assert!(verify(&m).is_ok());
    }

    #[test]
    fn rejects_friend_decl_oob_address() {
        let mut m = empty_module();
        m.friend_decls.push(ModuleHandle {
            address: AddressIdentifierIndex(7),
            name: IdentifierIndex(0),
        });
        match verify(&m) {
            Err(AdamantValidationError::IndexOutOfBounds {
                kind: IndexKind::AddressIdentifier,
                idx: 7,
                pool_len: 1,
            }) => {}
            other => panic!("expected IndexOutOfBounds(AddressIdentifier, 7, 1), got {other:?}"),
        }
    }

    #[test]
    fn rejects_friend_decl_oob_name() {
        let mut m = empty_module();
        m.friend_decls.push(ModuleHandle {
            address: AddressIdentifierIndex(0),
            name: IdentifierIndex(13),
        });
        match verify(&m) {
            Err(AdamantValidationError::IndexOutOfBounds {
                kind: IndexKind::Identifier,
                idx: 13,
                pool_len: 1,
            }) => {}
            other => panic!("expected IndexOutOfBounds(Identifier, 13, 1), got {other:?}"),
        }
    }

    #[test]
    fn friend_decls_iterates_in_storage_order_lowest_offender_wins() {
        // Two friend decls — one OOB at index 0, one OOB at
        // index 1. Iteration order reports decl 0's OOB first.
        let mut m = empty_module();
        m.friend_decls.push(ModuleHandle {
            address: AddressIdentifierIndex(7), // OOB at decl 0
            name: IdentifierIndex(0),
        });
        m.friend_decls.push(ModuleHandle {
            address: AddressIdentifierIndex(0),
            name: IdentifierIndex(99), // OOB at decl 1
        });
        match verify(&m) {
            Err(AdamantValidationError::IndexOutOfBounds {
                kind: IndexKind::AddressIdentifier,
                idx: 7,
                pool_len: 1,
            }) => {}
            other => panic!("expected decl 0's address OOB to win, got {other:?}"),
        }
    }

    // check_struct_instantiations ----------------------------------------------

    #[test]
    fn struct_instantiation_with_valid_def_and_signature_passes() {
        let mut m = module_with_one_declared_struct_def(0);
        m.signatures.push(Signature(vec![SignatureToken::U64]));
        m.struct_def_instantiations.push(StructDefInstantiation {
            def: StructDefinitionIndex(0),
            type_parameters: SignatureIndex(0),
        });
        assert!(verify(&m).is_ok());
    }

    #[test]
    fn rejects_struct_instantiation_oob_def() {
        let mut m = empty_module();
        m.signatures.push(Signature(vec![]));
        m.struct_def_instantiations.push(StructDefInstantiation {
            def: StructDefinitionIndex(5),
            type_parameters: SignatureIndex(0),
        });
        match verify(&m) {
            Err(AdamantValidationError::IndexOutOfBounds {
                kind: IndexKind::StructDefinition,
                idx: 5,
                pool_len: 0,
            }) => {}
            other => panic!("expected IndexOutOfBounds(StructDefinition, 5, 0), got {other:?}"),
        }
    }

    #[test]
    fn rejects_struct_instantiation_oob_type_parameters() {
        let mut m = module_with_one_declared_struct_def(0);
        m.struct_def_instantiations.push(StructDefInstantiation {
            def: StructDefinitionIndex(0),
            type_parameters: SignatureIndex(7),
        });
        match verify(&m) {
            Err(AdamantValidationError::IndexOutOfBounds {
                kind: IndexKind::Signature,
                idx: 7,
                pool_len: 0,
            }) => {}
            other => panic!("expected IndexOutOfBounds(Signature, 7, 0), got {other:?}"),
        }
    }

    #[test]
    fn struct_instantiation_def_bounds_fires_before_type_parameters_bounds() {
        // OOB def + OOB type_parameters. Def wins per upstream's
        // ? ordering.
        let mut m = empty_module();
        m.struct_def_instantiations.push(StructDefInstantiation {
            def: StructDefinitionIndex(9),
            type_parameters: SignatureIndex(99),
        });
        match verify(&m) {
            Err(AdamantValidationError::IndexOutOfBounds {
                kind: IndexKind::StructDefinition,
                idx: 9,
                pool_len: 0,
            }) => {}
            other => panic!("expected def bounds to win over type_parameters, got {other:?}"),
        }
    }

    // check_function_instantiations --------------------------------------------

    #[test]
    fn function_instantiation_with_valid_handle_and_signature_passes() {
        let mut m = module_with_one_function_handle();
        m.signatures.push(Signature(vec![SignatureToken::U64]));
        m.function_instantiations.push(FunctionInstantiation {
            handle: FunctionHandleIndex(0),
            type_parameters: SignatureIndex(2),
        });
        assert!(verify(&m).is_ok());
    }

    #[test]
    fn rejects_function_instantiation_oob_handle() {
        let mut m = empty_module();
        m.signatures.push(Signature(vec![]));
        m.function_instantiations.push(FunctionInstantiation {
            handle: FunctionHandleIndex(4),
            type_parameters: SignatureIndex(0),
        });
        match verify(&m) {
            Err(AdamantValidationError::IndexOutOfBounds {
                kind: IndexKind::FunctionHandle,
                idx: 4,
                pool_len: 0,
            }) => {}
            other => panic!("expected IndexOutOfBounds(FunctionHandle, 4, 0), got {other:?}"),
        }
    }

    #[test]
    fn rejects_function_instantiation_oob_type_parameters() {
        let mut m = module_with_one_function_handle();
        m.function_instantiations.push(FunctionInstantiation {
            handle: FunctionHandleIndex(0),
            type_parameters: SignatureIndex(11),
        });
        match verify(&m) {
            Err(AdamantValidationError::IndexOutOfBounds {
                kind: IndexKind::Signature,
                idx: 11,
                pool_len: 2,
            }) => {}
            other => panic!("expected IndexOutOfBounds(Signature, 11, 2), got {other:?}"),
        }
    }

    #[test]
    fn function_instantiation_handle_bounds_fires_before_type_parameters_bounds() {
        let mut m = empty_module();
        m.function_instantiations.push(FunctionInstantiation {
            handle: FunctionHandleIndex(7),
            type_parameters: SignatureIndex(13),
        });
        match verify(&m) {
            Err(AdamantValidationError::IndexOutOfBounds {
                kind: IndexKind::FunctionHandle,
                idx: 7,
                pool_len: 0,
            }) => {}
            other => panic!("expected handle bounds to win, got {other:?}"),
        }
    }

    // check_field_instantiations -----------------------------------------------

    #[test]
    fn field_instantiation_with_valid_handle_and_signature_passes() {
        let mut m = module_with_one_declared_struct_def(2);
        m.field_handles.push(FieldHandle {
            owner: StructDefinitionIndex(0),
            field: 0,
        });
        m.signatures.push(Signature(vec![SignatureToken::U64]));
        m.field_instantiations.push(FieldInstantiation {
            handle: FieldHandleIndex(0),
            type_parameters: SignatureIndex(0),
        });
        assert!(verify(&m).is_ok());
    }

    #[test]
    fn rejects_field_instantiation_oob_handle() {
        let mut m = empty_module();
        m.signatures.push(Signature(vec![]));
        m.field_instantiations.push(FieldInstantiation {
            handle: FieldHandleIndex(3),
            type_parameters: SignatureIndex(0),
        });
        match verify(&m) {
            Err(AdamantValidationError::IndexOutOfBounds {
                kind: IndexKind::FieldHandle,
                idx: 3,
                pool_len: 0,
            }) => {}
            other => panic!("expected IndexOutOfBounds(FieldHandle, 3, 0), got {other:?}"),
        }
    }

    #[test]
    fn rejects_field_instantiation_oob_type_parameters() {
        let mut m = module_with_one_declared_struct_def(2);
        m.field_handles.push(FieldHandle {
            owner: StructDefinitionIndex(0),
            field: 0,
        });
        m.field_instantiations.push(FieldInstantiation {
            handle: FieldHandleIndex(0),
            type_parameters: SignatureIndex(8),
        });
        match verify(&m) {
            Err(AdamantValidationError::IndexOutOfBounds {
                kind: IndexKind::Signature,
                idx: 8,
                pool_len: 0,
            }) => {}
            other => panic!("expected IndexOutOfBounds(Signature, 8, 0), got {other:?}"),
        }
    }

    #[test]
    fn field_instantiation_handle_bounds_fires_before_type_parameters_bounds() {
        let mut m = empty_module();
        m.field_instantiations.push(FieldInstantiation {
            handle: FieldHandleIndex(5),
            type_parameters: SignatureIndex(7),
        });
        match verify(&m) {
            Err(AdamantValidationError::IndexOutOfBounds {
                kind: IndexKind::FieldHandle,
                idx: 5,
                pool_len: 0,
            }) => {}
            other => panic!("expected handle bounds to win, got {other:?}"),
        }
    }

    // Cross-sub-check ordering pin ---------------------------------------------

    #[test]
    fn bounds_checker_sub_check_ordering_function_handles_before_field_handles() {
        // OOB function-handle module + OOB field-handle owner.
        // function-handles is at position 6; field-handles at 7.
        // The function-handle violation wins.
        let mut m = empty_module();
        m.signatures.push(Signature(vec![]));
        m.signatures.push(Signature(vec![]));
        m.identifiers.push(Identifier::new("foo").unwrap());
        m.function_handles.push(FunctionHandle {
            module: ModuleHandleIndex(99), // OOB
            name: IdentifierIndex(1),
            parameters: SignatureIndex(0),
            return_: SignatureIndex(1),
            type_parameters: vec![],
        });
        m.field_handles.push(FieldHandle {
            owner: StructDefinitionIndex(99), // OOB
            field: 0,
        });
        match verify(&m) {
            Err(AdamantValidationError::IndexOutOfBounds {
                kind: IndexKind::ModuleHandle,
                idx: 99,
                pool_len: 1,
            }) => {}
            other => panic!(
                "expected function-handle OOB at position 6 to win over field-handle OOB \
                 at position 7, got {other:?}"
            ),
        }
    }

    // --- Layer B: cross-validation against vendored Sui ---
    //
    // For each fixture below, run Adamant's `verify` and Sui's
    // `move_binary_format::check_bounds::BoundsChecker::verify_module`
    // over the same module (after BCS round-trip via
    // to_sui_module), assert accept/reject parity via the shared
    // `assert_pass_parity` helper extracted at B-2.2.
    //
    // Sui's `verify_module` takes a `deprecate_global_storage_ops`
    // flag; pass `true` to mirror Adamant's pipeline posture per
    // `validator/config.rs` (the flag is locked-down true in
    // production).

    fn cross_validate_bounds_pass(m: &AdamantCompiledModule) {
        let adamant_result = verify(m);
        let sui_module = m
            .to_sui_module()
            .expect("test fixture has no Adamant extensions; to_sui_module must succeed");
        // `BoundsChecker::verify_module` returns `PartialVMResult`
        // (unlike sibling passes whose `verify_module` wrappers
        // call `.finish(Location::Module(self.self_id()))`
        // internally). Wrapping with `Location::Undefined` here
        // because some negative fixtures (empty `module_handles`,
        // out-of-range `self_module_handle_idx`) make `self_id()`
        // panic — those are the inputs the bounds checker is
        // supposed to reject. `Location::Undefined` is a
        // constant that doesn't consult module state; accept/
        // reject parity is unchanged by the choice of location.
        let sui_result =
            move_binary_format::check_bounds::BoundsChecker::verify_module(&sui_module, true)
                .map_err(|e| e.finish(move_binary_format::errors::Location::Undefined));
        assert_pass_parity("bounds_checker", adamant_result, sui_result);
    }

    #[test]
    fn cross_validation_accepts_empty_module() {
        let m = empty_module();
        cross_validate_bounds_pass(&m);
    }

    #[test]
    fn cross_validation_accepts_module_with_signatures_and_constants() {
        let mut m = empty_module();
        m.signatures.push(Signature(vec![
            SignatureToken::U64,
            SignatureToken::Vector(Box::new(SignatureToken::Bool)),
        ]));
        m.constant_pool.push(Constant {
            type_: SignatureToken::U64,
            data: vec![0u8; 8],
        });
        cross_validate_bounds_pass(&m);
    }

    #[test]
    fn cross_validation_accepts_module_with_datatype_handle() {
        let mut m = empty_module();
        m.identifiers.push(Identifier::new("S").unwrap());
        m.datatype_handles.push(DatatypeHandle {
            module: ModuleHandleIndex(0),
            name: IdentifierIndex(1),
            abilities: AbilitySet::EMPTY,
            type_parameters: vec![],
        });
        m.signatures.push(Signature(vec![SignatureToken::Datatype(
            DatatypeHandleIndex(0),
        )]));
        cross_validate_bounds_pass(&m);
    }

    #[test]
    fn cross_validation_rejects_signature_oob_datatype() {
        let mut m = empty_module();
        m.signatures.push(Signature(vec![SignatureToken::Datatype(
            DatatypeHandleIndex(5),
        )]));
        cross_validate_bounds_pass(&m);
    }

    #[test]
    fn cross_validation_rejects_module_handle_oob_address() {
        let mut m = empty_module();
        m.module_handles.push(ModuleHandle {
            address: AddressIdentifierIndex(9),
            name: IdentifierIndex(0),
        });
        cross_validate_bounds_pass(&m);
    }

    #[test]
    fn cross_validation_rejects_self_module_handle_oob() {
        let mut m = empty_module();
        m.self_module_handle_idx = ModuleHandleIndex(7);
        cross_validate_bounds_pass(&m);
    }

    #[test]
    fn cross_validation_rejects_datatype_handle_oob_module() {
        let mut m = empty_module();
        m.identifiers.push(Identifier::new("S").unwrap());
        m.datatype_handles.push(DatatypeHandle {
            module: ModuleHandleIndex(4),
            name: IdentifierIndex(1),
            abilities: AbilitySet::EMPTY,
            type_parameters: vec![],
        });
        cross_validate_bounds_pass(&m);
    }

    #[test]
    fn cross_validation_rejects_zero_args_when_two_expected() {
        let mut m = empty_module();
        m.identifiers.push(Identifier::new("S").unwrap());
        m.datatype_handles.push(DatatypeHandle {
            module: ModuleHandleIndex(0),
            name: IdentifierIndex(1),
            abilities: AbilitySet::EMPTY,
            type_parameters: vec![ty_param(false), ty_param(false)],
        });
        m.signatures.push(Signature(vec![SignatureToken::Datatype(
            DatatypeHandleIndex(0),
        )]));
        cross_validate_bounds_pass(&m);
    }

    #[test]
    fn cross_validation_rejects_arity_mismatch_one_vs_two() {
        let mut m = empty_module();
        m.identifiers.push(Identifier::new("S").unwrap());
        m.datatype_handles.push(DatatypeHandle {
            module: ModuleHandleIndex(0),
            name: IdentifierIndex(1),
            abilities: AbilitySet::EMPTY,
            type_parameters: vec![ty_param(false), ty_param(false)],
        });
        m.signatures
            .push(Signature(vec![SignatureToken::DatatypeInstantiation(
                Box::new((DatatypeHandleIndex(0), vec![SignatureToken::U64])),
            )]));
        cross_validate_bounds_pass(&m);
    }

    #[test]
    fn cross_validation_rejects_no_module_handles() {
        let m = AdamantCompiledModule::default();
        cross_validate_bounds_pass(&m);
    }

    // --- Layer B: C-1.2 cross-validation ---

    #[test]
    fn cross_validation_accepts_module_with_function_handle() {
        let m = module_with_one_function_handle();
        cross_validate_bounds_pass(&m);
    }

    #[test]
    fn cross_validation_rejects_function_handle_oob_module() {
        let mut m = module_with_one_function_handle();
        m.function_handles[0].module = ModuleHandleIndex(9);
        cross_validate_bounds_pass(&m);
    }

    #[test]
    fn cross_validation_accepts_module_with_field_handle() {
        let mut m = module_with_one_declared_struct_def(2);
        m.field_handles.push(FieldHandle {
            owner: StructDefinitionIndex(0),
            field: 1,
        });
        cross_validate_bounds_pass(&m);
    }

    #[test]
    fn cross_validation_rejects_field_handle_oob_owner() {
        let mut m = empty_module();
        m.field_handles.push(FieldHandle {
            owner: StructDefinitionIndex(3),
            field: 0,
        });
        cross_validate_bounds_pass(&m);
    }

    #[test]
    fn cross_validation_accepts_module_with_valid_friend_decl() {
        let mut m = empty_module();
        m.identifiers.push(Identifier::new("F").unwrap());
        m.friend_decls.push(ModuleHandle {
            address: AddressIdentifierIndex(0),
            name: IdentifierIndex(1),
        });
        cross_validate_bounds_pass(&m);
    }

    #[test]
    fn cross_validation_rejects_friend_decl_oob_address() {
        let mut m = empty_module();
        m.friend_decls.push(ModuleHandle {
            address: AddressIdentifierIndex(7),
            name: IdentifierIndex(0),
        });
        cross_validate_bounds_pass(&m);
    }

    #[test]
    fn cross_validation_accepts_module_with_struct_instantiation() {
        let mut m = module_with_one_declared_struct_def(0);
        m.signatures.push(Signature(vec![SignatureToken::U64]));
        m.struct_def_instantiations.push(StructDefInstantiation {
            def: StructDefinitionIndex(0),
            type_parameters: SignatureIndex(0),
        });
        cross_validate_bounds_pass(&m);
    }

    #[test]
    fn cross_validation_rejects_struct_instantiation_oob_def() {
        let mut m = empty_module();
        m.signatures.push(Signature(vec![]));
        m.struct_def_instantiations.push(StructDefInstantiation {
            def: StructDefinitionIndex(5),
            type_parameters: SignatureIndex(0),
        });
        cross_validate_bounds_pass(&m);
    }

    #[test]
    fn cross_validation_accepts_module_with_function_instantiation() {
        let mut m = module_with_one_function_handle();
        m.signatures.push(Signature(vec![SignatureToken::U64]));
        m.function_instantiations.push(FunctionInstantiation {
            handle: FunctionHandleIndex(0),
            type_parameters: SignatureIndex(2),
        });
        cross_validate_bounds_pass(&m);
    }

    #[test]
    fn cross_validation_rejects_function_instantiation_oob_handle() {
        let mut m = empty_module();
        m.signatures.push(Signature(vec![]));
        m.function_instantiations.push(FunctionInstantiation {
            handle: FunctionHandleIndex(4),
            type_parameters: SignatureIndex(0),
        });
        cross_validate_bounds_pass(&m);
    }

    #[test]
    fn cross_validation_accepts_module_with_field_instantiation() {
        let mut m = module_with_one_declared_struct_def(2);
        m.field_handles.push(FieldHandle {
            owner: StructDefinitionIndex(0),
            field: 0,
        });
        m.signatures.push(Signature(vec![SignatureToken::U64]));
        m.field_instantiations.push(FieldInstantiation {
            handle: FieldHandleIndex(0),
            type_parameters: SignatureIndex(0),
        });
        cross_validate_bounds_pass(&m);
    }

    #[test]
    fn cross_validation_rejects_field_instantiation_oob_handle() {
        let mut m = empty_module();
        m.signatures.push(Signature(vec![]));
        m.field_instantiations.push(FieldInstantiation {
            handle: FieldHandleIndex(3),
            type_parameters: SignatureIndex(0),
        });
        cross_validate_bounds_pass(&m);
    }

    // --- Layer A: C-1.3 sub-checks (positions 12–16 of upstream verify_impl) ---

    // check_struct_defs --------------------------------------------------------

    #[test]
    fn struct_def_with_valid_handle_and_fields_passes() {
        let m = module_with_one_declared_struct_def(2);
        assert!(verify(&m).is_ok());
    }

    #[test]
    fn rejects_struct_def_oob_struct_handle() {
        let mut m = empty_module();
        // datatype_handles is empty; reference index 7.
        m.struct_defs.push(StructDefinition {
            struct_handle: DatatypeHandleIndex(7),
            field_information: StructFieldInformation::Native,
        });
        match verify(&m) {
            Err(AdamantValidationError::IndexOutOfBounds {
                kind: IndexKind::DatatypeHandle,
                idx: 7,
                pool_len: 0,
            }) => {}
            other => panic!("expected IndexOutOfBounds(DatatypeHandle, 7, 0), got {other:?}"),
        }
    }

    #[test]
    fn rejects_struct_def_field_with_oob_name() {
        let mut m = empty_module();
        m.identifiers.push(Identifier::new("S").unwrap());
        m.datatype_handles.push(DatatypeHandle {
            module: ModuleHandleIndex(0),
            name: IdentifierIndex(1),
            abilities: AbilitySet::EMPTY,
            type_parameters: vec![],
        });
        m.struct_defs.push(StructDefinition {
            struct_handle: DatatypeHandleIndex(0),
            field_information: StructFieldInformation::Declared(vec![FieldDefinition {
                name: IdentifierIndex(99), // OOB
                signature: TypeSignature(SignatureToken::U64),
            }]),
        });
        match verify(&m) {
            Err(AdamantValidationError::IndexOutOfBounds {
                kind: IndexKind::Identifier,
                idx: 99,
                pool_len: 2,
            }) => {}
            other => panic!("expected IndexOutOfBounds(Identifier, 99, 2), got {other:?}"),
        }
    }

    #[test]
    fn rejects_struct_def_field_with_oob_datatype_in_signature() {
        let mut m = empty_module();
        m.identifiers.push(Identifier::new("S").unwrap());
        m.identifiers.push(Identifier::new("f").unwrap());
        m.datatype_handles.push(DatatypeHandle {
            module: ModuleHandleIndex(0),
            name: IdentifierIndex(1),
            abilities: AbilitySet::EMPTY,
            type_parameters: vec![],
        });
        m.struct_defs.push(StructDefinition {
            struct_handle: DatatypeHandleIndex(0),
            field_information: StructFieldInformation::Declared(vec![FieldDefinition {
                name: IdentifierIndex(2),
                // DatatypeHandleIndex(99) is OOB.
                signature: TypeSignature(SignatureToken::Datatype(DatatypeHandleIndex(99))),
            }]),
        });
        match verify(&m) {
            Err(AdamantValidationError::IndexOutOfBounds {
                kind: IndexKind::DatatypeHandle,
                idx: 99,
                pool_len: 1,
            }) => {}
            other => panic!("expected IndexOutOfBounds(DatatypeHandle, 99, 1), got {other:?}"),
        }
    }

    #[test]
    fn rejects_struct_def_field_with_oob_type_parameter() {
        let mut m = empty_module();
        m.identifiers.push(Identifier::new("S").unwrap());
        m.identifiers.push(Identifier::new("f").unwrap());
        // Handle declares zero type parameters; field references TypeParameter(2).
        m.datatype_handles.push(DatatypeHandle {
            module: ModuleHandleIndex(0),
            name: IdentifierIndex(1),
            abilities: AbilitySet::EMPTY,
            type_parameters: vec![],
        });
        m.struct_defs.push(StructDefinition {
            struct_handle: DatatypeHandleIndex(0),
            field_information: StructFieldInformation::Declared(vec![FieldDefinition {
                name: IdentifierIndex(2),
                signature: TypeSignature(SignatureToken::TypeParameter(2)),
            }]),
        });
        match verify(&m) {
            Err(AdamantValidationError::IndexOutOfBounds {
                kind: IndexKind::TypeParameter,
                idx: 2,
                pool_len: 0,
            }) => {}
            other => panic!("expected IndexOutOfBounds(TypeParameter, 2, 0), got {other:?}"),
        }
    }

    #[test]
    fn struct_def_handle_bounds_fires_before_field_iteration() {
        // OOB struct_handle plus a field with OOB name. The
        // handle bounds check fires first; the field iteration
        // never runs.
        let mut m = empty_module();
        m.struct_defs.push(StructDefinition {
            struct_handle: DatatypeHandleIndex(9),
            field_information: StructFieldInformation::Declared(vec![FieldDefinition {
                name: IdentifierIndex(99),
                signature: TypeSignature(SignatureToken::U64),
            }]),
        });
        match verify(&m) {
            Err(AdamantValidationError::IndexOutOfBounds {
                kind: IndexKind::DatatypeHandle,
                idx: 9,
                pool_len: 0,
            }) => {}
            other => panic!("expected struct_handle bounds to win, got {other:?}"),
        }
    }

    // check_enum_defs ----------------------------------------------------------

    #[test]
    fn enum_def_with_one_variant_with_fields_passes() {
        let m = module_with_one_enum_def(2, 1);
        assert!(verify(&m).is_ok());
    }

    #[test]
    fn rejects_enum_def_oob_enum_handle() {
        let mut m = empty_module();
        m.enum_defs.push(EnumDefinition {
            enum_handle: DatatypeHandleIndex(5),
            variants: vec![],
        });
        match verify(&m) {
            Err(AdamantValidationError::IndexOutOfBounds {
                kind: IndexKind::DatatypeHandle,
                idx: 5,
                pool_len: 0,
            }) => {}
            other => panic!("expected IndexOutOfBounds(DatatypeHandle, 5, 0), got {other:?}"),
        }
    }

    #[test]
    fn rejects_enum_def_variant_with_oob_variant_name() {
        let mut m = module_with_one_enum_def(0, 0);
        m.enum_defs[0].variants.push(VariantDefinition {
            variant_name: IdentifierIndex(99),
            fields: vec![],
        });
        match verify(&m) {
            Err(AdamantValidationError::IndexOutOfBounds {
                kind: IndexKind::Identifier,
                idx: 99,
                pool_len: 2,
            }) => {}
            other => panic!("expected IndexOutOfBounds(Identifier, 99, 2), got {other:?}"),
        }
    }

    #[test]
    fn rejects_enum_def_field_with_oob_name() {
        let mut m = module_with_one_enum_def(1, 0);
        // Add a field to the lone variant with an OOB name.
        let identifiers_count_at_capture = m.identifiers.len();
        m.enum_defs[0].variants[0].fields.push(FieldDefinition {
            name: IdentifierIndex(99),
            signature: TypeSignature(SignatureToken::U64),
        });
        match verify(&m) {
            Err(AdamantValidationError::IndexOutOfBounds {
                kind: IndexKind::Identifier,
                idx: 99,
                pool_len,
            }) if pool_len == identifiers_count_at_capture => {}
            other => panic!("expected IndexOutOfBounds(Identifier, 99, ...), got {other:?}"),
        }
    }

    #[test]
    fn rejects_enum_def_field_with_oob_datatype_in_signature() {
        let mut m = module_with_one_enum_def(1, 0);
        let field_name_idx =
            u16::try_from(m.identifiers.len()).expect("test fixture has < u16::MAX identifiers");
        m.identifiers.push(Identifier::new("ff").unwrap());
        m.enum_defs[0].variants[0].fields.push(FieldDefinition {
            name: IdentifierIndex(field_name_idx),
            signature: TypeSignature(SignatureToken::Datatype(DatatypeHandleIndex(99))),
        });
        match verify(&m) {
            Err(AdamantValidationError::IndexOutOfBounds {
                kind: IndexKind::DatatypeHandle,
                idx: 99,
                pool_len: 1,
            }) => {}
            other => panic!("expected IndexOutOfBounds(DatatypeHandle, 99, 1), got {other:?}"),
        }
    }

    #[test]
    fn rejects_enum_def_field_with_oob_type_parameter() {
        let mut m = module_with_one_enum_def(1, 0);
        // Handle declares zero type parameters; field references TypeParameter(7).
        let field_name_idx =
            u16::try_from(m.identifiers.len()).expect("test fixture has < u16::MAX identifiers");
        m.identifiers.push(Identifier::new("ff").unwrap());
        m.enum_defs[0].variants[0].fields.push(FieldDefinition {
            name: IdentifierIndex(field_name_idx),
            signature: TypeSignature(SignatureToken::TypeParameter(7)),
        });
        match verify(&m) {
            Err(AdamantValidationError::IndexOutOfBounds {
                kind: IndexKind::TypeParameter,
                idx: 7,
                pool_len: 0,
            }) => {}
            other => panic!("expected IndexOutOfBounds(TypeParameter, 7, 0), got {other:?}"),
        }
    }

    #[test]
    fn enum_def_handle_bounds_fires_before_variant_iteration() {
        // OOB enum_handle plus an OOB variant_name. Enum-handle
        // bounds wins; variant iteration never runs.
        let mut m = empty_module();
        m.enum_defs.push(EnumDefinition {
            enum_handle: DatatypeHandleIndex(9),
            variants: vec![VariantDefinition {
                variant_name: IdentifierIndex(99),
                fields: vec![],
            }],
        });
        match verify(&m) {
            Err(AdamantValidationError::IndexOutOfBounds {
                kind: IndexKind::DatatypeHandle,
                idx: 9,
                pool_len: 0,
            }) => {}
            other => panic!("expected enum_handle bounds to win, got {other:?}"),
        }
    }

    // check_enum_instantiations ------------------------------------------------

    #[test]
    fn enum_instantiation_with_valid_def_and_signature_passes() {
        let m = module_with_one_enum_def_instantiation(1, 0);
        assert!(verify(&m).is_ok());
    }

    #[test]
    fn rejects_enum_instantiation_oob_def() {
        let mut m = empty_module();
        m.signatures.push(Signature(vec![]));
        m.enum_def_instantiations.push(EnumDefInstantiation {
            def: EnumDefinitionIndex(5),
            type_parameters: SignatureIndex(0),
        });
        match verify(&m) {
            Err(AdamantValidationError::IndexOutOfBounds {
                kind: IndexKind::EnumDefinition,
                idx: 5,
                pool_len: 0,
            }) => {}
            other => panic!("expected IndexOutOfBounds(EnumDefinition, 5, 0), got {other:?}"),
        }
    }

    #[test]
    fn rejects_enum_instantiation_oob_type_parameters() {
        let mut m = module_with_one_enum_def(0, 0);
        m.enum_def_instantiations.push(EnumDefInstantiation {
            def: EnumDefinitionIndex(0),
            type_parameters: SignatureIndex(13),
        });
        match verify(&m) {
            Err(AdamantValidationError::IndexOutOfBounds {
                kind: IndexKind::Signature,
                idx: 13,
                pool_len: 0,
            }) => {}
            other => panic!("expected IndexOutOfBounds(Signature, 13, 0), got {other:?}"),
        }
    }

    #[test]
    fn enum_instantiation_def_bounds_fires_before_type_parameters_bounds() {
        let mut m = empty_module();
        m.enum_def_instantiations.push(EnumDefInstantiation {
            def: EnumDefinitionIndex(7),
            type_parameters: SignatureIndex(13),
        });
        match verify(&m) {
            Err(AdamantValidationError::IndexOutOfBounds {
                kind: IndexKind::EnumDefinition,
                idx: 7,
                pool_len: 0,
            }) => {}
            other => panic!("expected def bounds to win, got {other:?}"),
        }
    }

    // check_variant_handles ----------------------------------------------------

    #[test]
    fn variant_handle_with_valid_indices_passes() {
        let mut m = module_with_one_enum_def(2, 0);
        m.variant_handles.push(VariantHandle {
            enum_def: EnumDefinitionIndex(0),
            variant: 1,
        });
        assert!(verify(&m).is_ok());
    }

    #[test]
    fn rejects_variant_handle_oob_enum_def() {
        let mut m = empty_module();
        m.variant_handles.push(VariantHandle {
            enum_def: EnumDefinitionIndex(5),
            variant: 0,
        });
        match verify(&m) {
            Err(AdamantValidationError::IndexOutOfBounds {
                kind: IndexKind::EnumDefinition,
                idx: 5,
                pool_len: 0,
            }) => {}
            other => panic!("expected IndexOutOfBounds(EnumDefinition, 5, 0), got {other:?}"),
        }
    }

    #[test]
    fn rejects_variant_handle_variant_at_or_above_count() {
        let mut m = module_with_one_enum_def(2, 0);
        m.variant_handles.push(VariantHandle {
            enum_def: EnumDefinitionIndex(0),
            variant: 2, // == variants.len(), rejects
        });
        match verify(&m) {
            Err(AdamantValidationError::IndexOutOfBounds {
                kind: IndexKind::VariantTag,
                idx: 2,
                pool_len: 2,
            }) => {}
            other => panic!("expected IndexOutOfBounds(VariantTag, 2, 2), got {other:?}"),
        }
    }

    #[test]
    fn variant_handle_enum_def_bounds_fires_before_variant_tag_check() {
        // OOB enum_def + variant tag that would also be OOB.
        // enum_def bounds wins.
        let mut m = empty_module();
        m.variant_handles.push(VariantHandle {
            enum_def: EnumDefinitionIndex(9),
            variant: 99,
        });
        match verify(&m) {
            Err(AdamantValidationError::IndexOutOfBounds {
                kind: IndexKind::EnumDefinition,
                idx: 9,
                pool_len: 0,
            }) => {}
            other => panic!("expected enum_def bounds to win, got {other:?}"),
        }
    }

    // check_variant_instantiation_handles --------------------------------------

    #[test]
    fn variant_instantiation_handle_with_valid_indices_passes() {
        let mut m = module_with_one_enum_def_instantiation(2, 0);
        m.variant_instantiation_handles
            .push(VariantInstantiationHandle {
                enum_def: EnumDefInstantiationIndex(0),
                variant: 1,
            });
        assert!(verify(&m).is_ok());
    }

    #[test]
    fn rejects_variant_instantiation_handle_oob_enum_def() {
        let mut m = empty_module();
        m.variant_instantiation_handles
            .push(VariantInstantiationHandle {
                enum_def: EnumDefInstantiationIndex(5),
                variant: 0,
            });
        match verify(&m) {
            Err(AdamantValidationError::IndexOutOfBounds {
                kind: IndexKind::EnumDefInstantiation,
                idx: 5,
                pool_len: 0,
            }) => {}
            other => panic!("expected IndexOutOfBounds(EnumDefInstantiation, 5, 0), got {other:?}"),
        }
    }

    #[test]
    fn rejects_variant_instantiation_handle_variant_at_or_above_count() {
        let mut m = module_with_one_enum_def_instantiation(2, 0);
        m.variant_instantiation_handles
            .push(VariantInstantiationHandle {
                enum_def: EnumDefInstantiationIndex(0),
                variant: 2, // == variants.len(), rejects
            });
        match verify(&m) {
            Err(AdamantValidationError::IndexOutOfBounds {
                kind: IndexKind::VariantTag,
                idx: 2,
                pool_len: 2,
            }) => {}
            other => panic!("expected IndexOutOfBounds(VariantTag, 2, 2), got {other:?}"),
        }
    }

    #[test]
    fn variant_instantiation_enum_def_bounds_fires_before_variant_tag_check() {
        // OOB enum_def (into enum_def_instantiations) + variant
        // tag that would also be OOB. enum_def-instantiation
        // bounds wins.
        let mut m = empty_module();
        m.variant_instantiation_handles
            .push(VariantInstantiationHandle {
                enum_def: EnumDefInstantiationIndex(9),
                variant: 99,
            });
        match verify(&m) {
            Err(AdamantValidationError::IndexOutOfBounds {
                kind: IndexKind::EnumDefInstantiation,
                idx: 9,
                pool_len: 0,
            }) => {}
            other => panic!("expected enum_def-instantiation bounds to win, got {other:?}"),
        }
    }

    // Cross-sub-check ordering pin (C-1.3) -------------------------------------

    #[test]
    fn c13_struct_defs_before_enum_defs() {
        // OOB struct_def + OOB enum_def. struct_defs is at
        // position 12; enum_defs at 13. struct_def violation
        // wins.
        let mut m = empty_module();
        m.struct_defs.push(StructDefinition {
            struct_handle: DatatypeHandleIndex(99),
            field_information: StructFieldInformation::Native,
        });
        m.enum_defs.push(EnumDefinition {
            enum_handle: DatatypeHandleIndex(99),
            variants: vec![],
        });
        match verify(&m) {
            Err(AdamantValidationError::IndexOutOfBounds {
                kind: IndexKind::DatatypeHandle,
                idx: 99,
                pool_len: 0,
            }) => {}
            other => panic!(
                "expected struct_defs (position 12) violation to win over \
                 enum_defs (position 13), got {other:?}"
            ),
        }
    }

    // --- Layer B: C-1.3 cross-validation ---

    #[test]
    fn cross_validation_accepts_module_with_struct_def() {
        let m = module_with_one_declared_struct_def(2);
        cross_validate_bounds_pass(&m);
    }

    #[test]
    fn cross_validation_rejects_struct_def_oob_struct_handle() {
        let mut m = empty_module();
        m.struct_defs.push(StructDefinition {
            struct_handle: DatatypeHandleIndex(7),
            field_information: StructFieldInformation::Native,
        });
        cross_validate_bounds_pass(&m);
    }

    #[test]
    fn cross_validation_accepts_module_with_enum_def() {
        let m = module_with_one_enum_def(2, 1);
        cross_validate_bounds_pass(&m);
    }

    #[test]
    fn cross_validation_rejects_enum_def_oob_enum_handle() {
        let mut m = empty_module();
        m.enum_defs.push(EnumDefinition {
            enum_handle: DatatypeHandleIndex(5),
            variants: vec![],
        });
        cross_validate_bounds_pass(&m);
    }

    #[test]
    fn cross_validation_accepts_module_with_enum_instantiation() {
        let m = module_with_one_enum_def_instantiation(1, 0);
        cross_validate_bounds_pass(&m);
    }

    #[test]
    fn cross_validation_rejects_enum_instantiation_oob_def() {
        let mut m = empty_module();
        m.signatures.push(Signature(vec![]));
        m.enum_def_instantiations.push(EnumDefInstantiation {
            def: EnumDefinitionIndex(5),
            type_parameters: SignatureIndex(0),
        });
        cross_validate_bounds_pass(&m);
    }

    #[test]
    fn cross_validation_accepts_module_with_variant_handle() {
        let mut m = module_with_one_enum_def(2, 0);
        m.variant_handles.push(VariantHandle {
            enum_def: EnumDefinitionIndex(0),
            variant: 1,
        });
        cross_validate_bounds_pass(&m);
    }

    #[test]
    fn cross_validation_rejects_variant_handle_variant_at_or_above_count() {
        let mut m = module_with_one_enum_def(2, 0);
        m.variant_handles.push(VariantHandle {
            enum_def: EnumDefinitionIndex(0),
            variant: 2,
        });
        cross_validate_bounds_pass(&m);
    }

    #[test]
    fn cross_validation_accepts_module_with_variant_instantiation_handle() {
        let mut m = module_with_one_enum_def_instantiation(2, 0);
        m.variant_instantiation_handles
            .push(VariantInstantiationHandle {
                enum_def: EnumDefInstantiationIndex(0),
                variant: 1,
            });
        cross_validate_bounds_pass(&m);
    }

    #[test]
    fn cross_validation_rejects_variant_instantiation_handle_variant_at_or_above_count() {
        let mut m = module_with_one_enum_def_instantiation(2, 0);
        m.variant_instantiation_handles
            .push(VariantInstantiationHandle {
                enum_def: EnumDefInstantiationIndex(0),
                variant: 2,
            });
        cross_validate_bounds_pass(&m);
    }
}
