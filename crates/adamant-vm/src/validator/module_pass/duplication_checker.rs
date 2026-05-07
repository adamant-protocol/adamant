//! Module-level pass: handle-and-identifier duplication
//! checking (whitepaper §6.2.1.8 step 3).
//!
//! Forked from `vendor/move-bytecode-verifier/src/check_duplication.rs`
//! at Sui-Move tag `mainnet-v1.66.2` (commit
//! `a9a6825eaf6273cc819ee3bcf65fd4909f7624a9`). See
//! `validator/module_pass/PROVENANCE.md` for the full
//! deviation list and per-pass methodology-pattern co-location.
//!
//! # Pass scope (section 1 of the per-pass doc-comment template)
//!
//! Validates that pool-stored items in the deserialized
//! [`AdamantCompiledModule`] are unique by their identity-
//! defining key. Upstream's `verify_module_impl` decomposes
//! into 18 sub-checks across two layers:
//!
//! **Top-level static checks (10):** `check_identifiers`,
//! `check_address_identifiers`, `check_constants`,
//! `check_signatures`, `check_module_handles`,
//! `check_module_handles` over `friend_decls`,
//! `check_datatype_handles` (by `(module, name)`),
//! `check_function_handles` (by `(module, name)`),
//! `check_function_instantiations`, `check_variant_handles`
//! (by `(enum_def, variant)`).
//!
//! **Instance-method checks (8):** `check_field_handles`,
//! `check_field_instantiations`, `check_function_definitions`,
//! `check_struct_definitions`, `check_struct_instantiations`,
//! `check_enum_definitions`, `check_enum_instantiations`,
//! `check_datatype_handles_implemented`.
//!
//! Error variants produced at C-2:
//!
//! - [`AdamantValidationError::DuplicateElement`] — workhorse
//!   for 14+ sub-checks. Carries `IndexKind` discriminator.
//! - [`AdamantValidationError::ZeroSizedStruct`] — declared
//!   struct with zero fields.
//! - [`AdamantValidationError::ZeroSizedEnum`] — enum with
//!   zero variants.
//! - [`AdamantValidationError::InvalidModuleHandle`] —
//!   struct/enum/function definition whose handle's `module`
//!   doesn't point at `self_module_handle_idx`. Uses
//!   [`DefKind`] (`Struct | Enum | Function`) per Q2
//!   disposition at the C-2 plan-gate (3rd instance of the
//!   deliberate-Adamant-decision pattern).
//! - [`AdamantValidationError::DuplicateAcquiresAnnotation`] —
//!   function-def's `acquires_global_resources` has duplicate
//!   `StructDefinitionIndex`. Always-empty in valid Adamant
//!   per Rule 5; structurally preserved.
//! - [`AdamantValidationError::UnimplementedHandle`] — self-
//!   module datatype/function handle without matching
//!   definition.
//!
//! # No-Sui-parity-claim posture (section 2)
//!
//! Not applicable. C-2 makes a **full Sui-parity claim** for
//! the inherited Sui-base subset: for any module shape
//! produceable through `to_sui_module`'s BCS round-trip, the
//! pass reaches the same accept/reject decision as Sui's
//! [`move_bytecode_verifier::check_duplication::DuplicationChecker::verify_module`].
//! Layer B parity tests assert per category. Typed-error variant
//! shape differs by design (`AdamantValidationError` rather
//! than `PartialVMError`/`StatusCode`) per the resistant-proof
//! posture.
//!
//! # Deliberate-Adamant-decision (section 3)
//!
//! [`DefKind`] enum introduction (Q2 plan-gate disposition).
//! Upstream uses `IndexKind::StructDefinition`/
//! `IndexKind::EnumDefinition`/`IndexKind::FunctionDefinition`
//! discriminators inside its untyped error machinery; Adamant's
//! typed [`AdamantValidationError::InvalidModuleHandle`] needs
//! a closed enum at the variant boundary. [`FieldOwnerKind`]
//! (`Struct | Enum`) from B-2.3 is named for field-ownership
//! context — adding `Function` would force the name's semantic
//! to drift. New `DefKind` introduced deliberately rather than
//! overloading `FieldOwnerKind`.
//!
//! Third instance of the deliberate-Adamant-decision pattern
//! after B-4.2's byte→range→duplicate ordering and C-1.3's
//! `check_field_def` extraction. Pattern stable at 3 instances
//! per the rule-of-three threshold.
//!
//! # Eager-error first-failure-wins (section 4)
//!
//! Sub-check ordering preserved byte-faithfully from upstream's
//! `verify_module_impl`: identifiers → address-identifiers →
//! constants → signatures → module-handles → friend-decls →
//! datatype-handles → function-handles → function-
//! instantiations → variant-handles → field-handles → field-
//! instantiations → function-defs → struct-defs → struct-
//! instantiations → enum-defs → enum-instantiations →
//! datatype-handles-implemented. First-encountered violation
//! wins.
//!
//! Within a sub-check, [`first_duplicate_element`] returns the
//! lowest-index duplicate (the **second occurrence** of any
//! key — the first occurrence is canonical). Per-axis pin
//! tests assert this empirically.
//!
//! Within `check_struct_definitions`: handle-uniqueness fires
//! before zero-fields rejection before per-field-name
//! uniqueness before self-module-handle check. Within
//! `check_enum_definitions`: joint struct-and-enum handle
//! uniqueness fires before zero-variants before per-variant-
//! name uniqueness before per-field-name uniqueness within
//! variant before self-module-handle check.
//!
//! # Shared-variant cross-pass precedence (section 5)
//!
//! [`AdamantValidationError::DuplicateElement`] is C-2's
//! workhorse; cross-pass exposure with later passes (C-3
//! `signature_checker`) lands at C-4 wiring time. Plan-gate
//! flag at C-4 surfaces any shared-variant precedence claims
//! between C-2's `DuplicateElement(Signature)` and any C-3
//! sub-check that produces signature-related errors.
//!
//! # Dead-code allow sunset (section 6)
//!
//! File-level `#![allow(dead_code)]` removed at C-4 when
//! [`super::super::verify_module`] wires this pass into the
//! step-3 batch.
//!
//! # References to PROVENANCE.md cross-pass audit anchors (section 7)
//!
//! - "What was forked" / Phase 5/5b.3 C-2 sub-section.
//! - "Adamant deviations" / Phase 5/5b.3 C-2 sub-section
//!   (typed-error fork; `DefKind` introduction).
//! - "Byte-faithful preservation" / sub-check ordering +
//!   first-duplicate's lowest-index reporting.
//! - "Eager-error first-failure-wins" / 18-sub-check ordering.
//! - "Adamant-extension treatment in module-level passes" /
//!   2nd instance: `DuplicationChecker` has no per-instruction
//!   operand concern; extensions are early-arm-Ok by virtue
//!   of the pass not iterating function bodies.
//! - "Deliberate-Adamant-decision pattern" / 3rd instance:
//!   `DefKind` introduction.
//!
//! [`AdamantCompiledModule`]: crate::module::AdamantCompiledModule
//! [`AdamantValidationError`]: crate::validator::error::AdamantValidationError
//! [`DefKind`]: crate::validator::error::DefKind
//! [`FieldOwnerKind`]: crate::validator::error::FieldOwnerKind

use std::collections::HashSet;
use std::hash::Hash;

use adamant_bytecode_format::{
    DatatypeHandleIndex, FunctionHandleIndex, IndexKind, ModuleHandle, ModuleIndex,
    StructFieldInformation, TableIndex,
};

use crate::module::AdamantCompiledModule;

use super::super::error::{AdamantValidationError, DefKind, HandleKind};

/// Verify the deserialized module's pool entries against
/// §6.2.1.8 step 3 (`module_pass::duplication_checker`).
///
/// Eager-error semantics: returns the first violation
/// encountered in upstream `verify_module_impl` order.
pub(in crate::validator) fn verify(
    module: &AdamantCompiledModule,
) -> Result<(), AdamantValidationError> {
    // Top-level static checks (sub-checks 1-10).
    check_identifiers(module)?;
    check_address_identifiers(module)?;
    check_constants(module)?;
    check_signatures(module)?;
    check_module_handles_pool(module, &module.module_handles, IndexKind::ModuleHandle)?;
    check_module_handles_pool(module, &module.friend_decls, IndexKind::ModuleHandle)?;
    check_datatype_handles(module)?;
    check_function_handles(module)?;
    check_function_instantiations(module)?;
    check_variant_handles(module)?;

    // Instance-method checks (sub-checks 11-18).
    check_field_handles(module)?;
    check_field_instantiations(module)?;
    check_function_definitions(module)?;
    check_struct_definitions(module)?;
    check_struct_instantiations(module)?;
    check_enum_definitions(module)?;
    check_enum_instantiations(module)?;
    check_datatype_handles_implemented(module)?;

    Ok(())
}

// --- Top-level static checks (sub-checks 1-10) -------------------------------

fn check_identifiers(module: &AdamantCompiledModule) -> Result<(), AdamantValidationError> {
    duplicate_or_ok(&module.identifiers, IndexKind::Identifier)
}

fn check_address_identifiers(module: &AdamantCompiledModule) -> Result<(), AdamantValidationError> {
    duplicate_or_ok(&module.address_identifiers, IndexKind::AddressIdentifier)
}

fn check_constants(module: &AdamantCompiledModule) -> Result<(), AdamantValidationError> {
    duplicate_or_ok(&module.constant_pool, IndexKind::ConstantPool)
}

fn check_signatures(module: &AdamantCompiledModule) -> Result<(), AdamantValidationError> {
    duplicate_or_ok(&module.signatures, IndexKind::Signature)
}

/// Per-pool helper for module-handles AND friend-decls
/// (upstream's `check_module_handles` is invoked twice with
/// the same body; Adamant collapses via this helper). The
/// `kind` parameter is `ModuleHandle` for both call sites
/// (matching upstream's `IndexKind::ModuleHandle`
/// discriminator at both sites).
fn check_module_handles_pool(
    _module: &AdamantCompiledModule,
    pool: &[ModuleHandle],
    kind: IndexKind,
) -> Result<(), AdamantValidationError> {
    duplicate_or_ok(pool, kind)
}

/// `DatatypeHandle` uniqueness is by `(module, name)` pair —
/// the `abilities` and `type_parameters` fields don't
/// participate in identity (an identical handle with different
/// abilities would be a re-declaration of the same handle).
fn check_datatype_handles(module: &AdamantCompiledModule) -> Result<(), AdamantValidationError> {
    duplicate_iter_or_ok(
        module.datatype_handles.iter().map(|h| (h.module, h.name)),
        IndexKind::DatatypeHandle,
    )
}

/// `FunctionHandle` uniqueness is by `(module, name)` pair —
/// same shape as `check_datatype_handles`.
fn check_function_handles(module: &AdamantCompiledModule) -> Result<(), AdamantValidationError> {
    duplicate_iter_or_ok(
        module.function_handles.iter().map(|h| (h.module, h.name)),
        IndexKind::FunctionHandle,
    )
}

fn check_function_instantiations(
    module: &AdamantCompiledModule,
) -> Result<(), AdamantValidationError> {
    duplicate_or_ok(
        &module.function_instantiations,
        IndexKind::FunctionInstantiation,
    )
}

/// `VariantHandle` uniqueness is by `(enum_def, variant)`
/// pair — `(enum_def, 0)` and `(enum_def, 1)` are distinct
/// variants of the same enum, but two `VariantHandle` entries
/// with the same `(enum_def, variant)` are duplicates.
fn check_variant_handles(module: &AdamantCompiledModule) -> Result<(), AdamantValidationError> {
    duplicate_iter_or_ok(
        module
            .variant_handles
            .iter()
            .map(|h| (h.enum_def, h.variant)),
        IndexKind::VariantHandle,
    )
}

// --- Instance-method checks (sub-checks 11-18) -------------------------------

fn check_field_handles(module: &AdamantCompiledModule) -> Result<(), AdamantValidationError> {
    duplicate_or_ok(&module.field_handles, IndexKind::FieldHandle)
}

fn check_field_instantiations(
    module: &AdamantCompiledModule,
) -> Result<(), AdamantValidationError> {
    duplicate_or_ok(&module.field_instantiations, IndexKind::FieldInstantiation)
}

/// `FunctionDefinition` uniqueness by `function:
/// FunctionHandleIndex` + per-acquires-uniqueness + self-module
/// check + implemented-function-handles check.
fn check_function_definitions(
    module: &AdamantCompiledModule,
) -> Result<(), AdamantValidationError> {
    // FunctionDefinition - contained FunctionHandle defines uniqueness
    if let Some(idx) = first_duplicate_element(module.function_defs.iter().map(|fd| fd.function)) {
        return Err(AdamantValidationError::DuplicateElement {
            kind: IndexKind::FunctionDefinition,
            idx,
        });
    }
    // Acquires in function declarations contain unique struct definitions
    for (idx, function_def) in module.function_defs.iter().enumerate() {
        if first_duplicate_element(function_def.acquires_global_resources.iter().copied()).is_some()
        {
            return Err(AdamantValidationError::DuplicateAcquiresAnnotation {
                fn_def_idx: adamant_bytecode_format::FunctionDefinitionIndex(
                    TableIndex::try_from(idx).expect(
                        "function-def count fits u16; binary format precludes overflow \
                         (FUNCTION_DEFINITION_INDEX_MAX = u16::MAX)",
                    ),
                ),
            });
        }
    }
    // Each function definition must point at the self-module
    if let Some(idx) = module.function_defs.iter().position(|fd| {
        let function_handle = &module.function_handles[fd.function.into_index()];
        function_handle.module != module.self_module_handle_idx
    }) {
        return Err(AdamantValidationError::InvalidModuleHandle {
            kind: DefKind::Function,
            def_idx: TableIndex::try_from(idx)
                .expect("function-def count fits u16; binary format precludes overflow"),
        });
    }
    // Each function handle in self-module must be implemented
    let implemented: HashSet<FunctionHandleIndex> =
        module.function_defs.iter().map(|fd| fd.function).collect();
    if let Some(idx) = (0..module.function_handles.len()).position(|x| {
        let handle_idx =
            FunctionHandleIndex(TableIndex::try_from(x).expect("function-handle count fits u16"));
        module.function_handles[x].module == module.self_module_handle_idx
            && !implemented.contains(&handle_idx)
    }) {
        return Err(AdamantValidationError::UnimplementedHandle {
            kind: HandleKind::FunctionHandle,
            idx: TableIndex::try_from(idx).expect("function-handle count fits u16"),
        });
    }
    Ok(())
}

/// `StructDefinition` uniqueness by `struct_handle` + zero-
/// fields rejection + per-field-name uniqueness + self-module
/// check.
fn check_struct_definitions(module: &AdamantCompiledModule) -> Result<(), AdamantValidationError> {
    // StructDefinition - contained DatatypeHandle defines uniqueness
    if let Some(idx) = first_duplicate_element(module.struct_defs.iter().map(|sd| sd.struct_handle))
    {
        return Err(AdamantValidationError::DuplicateElement {
            kind: IndexKind::StructDefinition,
            idx,
        });
    }
    // Field names in structs must be unique; declared structs must have ≥1 field.
    for (struct_idx, struct_def) in module.struct_defs.iter().enumerate() {
        let fields = match &struct_def.field_information {
            StructFieldInformation::Native => continue,
            StructFieldInformation::Declared(fields) => fields,
        };
        let struct_def_idx = adamant_bytecode_format::StructDefinitionIndex(
            TableIndex::try_from(struct_idx)
                .expect("struct-def count fits u16; binary format precludes overflow"),
        );
        if fields.is_empty() {
            return Err(AdamantValidationError::ZeroSizedStruct {
                def_idx: struct_def_idx,
            });
        }
        if let Some(idx) = first_duplicate_element(fields.iter().map(|f| f.name)) {
            return Err(AdamantValidationError::DuplicateElement {
                kind: IndexKind::FieldDefinition,
                idx,
            });
        }
    }
    // Each struct definition must point at the self-module
    if let Some(idx) = module.struct_defs.iter().position(|sd| {
        module.datatype_handles[sd.struct_handle.into_index()].module
            != module.self_module_handle_idx
    }) {
        return Err(AdamantValidationError::InvalidModuleHandle {
            kind: DefKind::Struct,
            def_idx: TableIndex::try_from(idx)
                .expect("struct-def count fits u16; binary format precludes overflow"),
        });
    }
    Ok(())
}

fn check_struct_instantiations(
    module: &AdamantCompiledModule,
) -> Result<(), AdamantValidationError> {
    duplicate_or_ok(
        &module.struct_def_instantiations,
        IndexKind::StructDefInstantiation,
    )
}

/// `EnumDefinition` uniqueness — joint with `struct_defs` by
/// `DatatypeHandleIndex`. Upstream places this at
/// `check_enum_definitions` rather than
/// `check_struct_definitions` per Q3 disposition; preserved
/// byte-faithfully (cross-cutting check placement axis of the
/// byte-faithful preservation principle — see PROVENANCE.md
/// at C-5).
fn check_enum_definitions(module: &AdamantCompiledModule) -> Result<(), AdamantValidationError> {
    // Joint struct-and-enum uniqueness by DatatypeHandleIndex.
    // NB: We check uniqueness across BOTH struct and enum handles
    // here (upstream's placement) to make sure data definitions
    // are not duplicated across struct and enums. See Q3
    // disposition at the C-2 plan-gate.
    if let Some(idx) = first_duplicate_element(
        module
            .struct_defs
            .iter()
            .map(|sd| sd.struct_handle)
            .chain(module.enum_defs.iter().map(|ed| ed.enum_handle)),
    ) {
        return Err(AdamantValidationError::DuplicateElement {
            kind: IndexKind::EnumDefinition,
            idx,
        });
    }
    // Variant names in enums must be unique; field names in each variant must be
    // unique; non-empty enums required.
    for (enum_idx, enum_def) in module.enum_defs.iter().enumerate() {
        let enum_def_idx = adamant_bytecode_format::EnumDefinitionIndex(
            TableIndex::try_from(enum_idx)
                .expect("enum-def count fits u16; binary format precludes overflow"),
        );
        if enum_def.variants.is_empty() {
            return Err(AdamantValidationError::ZeroSizedEnum {
                def_idx: enum_def_idx,
            });
        }
        if let Some(idx) = first_duplicate_element(enum_def.variants.iter().map(|v| v.variant_name))
        {
            return Err(AdamantValidationError::DuplicateElement {
                kind: IndexKind::EnumDefinition,
                idx,
            });
        }
        // NB: zero-sized variants ARE allowed (a variant with no
        // fields is non-zero-sized because the enum tag itself
        // makes it discriminable). Per upstream comment at
        // check_duplication.rs:316-318.
        for variant in &enum_def.variants {
            if let Some(idx) = first_duplicate_element(variant.fields.iter().map(|f| f.name)) {
                return Err(AdamantValidationError::DuplicateElement {
                    kind: IndexKind::FieldDefinition,
                    idx,
                });
            }
        }
    }
    // Each enum definition must point at the self-module
    if let Some(idx) = module.enum_defs.iter().position(|ed| {
        module.datatype_handles[ed.enum_handle.into_index()].module != module.self_module_handle_idx
    }) {
        return Err(AdamantValidationError::InvalidModuleHandle {
            kind: DefKind::Enum,
            def_idx: TableIndex::try_from(idx)
                .expect("enum-def count fits u16; binary format precludes overflow"),
        });
    }
    Ok(())
}

fn check_enum_instantiations(module: &AdamantCompiledModule) -> Result<(), AdamantValidationError> {
    duplicate_or_ok(
        &module.enum_def_instantiations,
        IndexKind::EnumDefInstantiation,
    )
}

/// Every datatype handle that points at the self-module must
/// have a corresponding struct or enum definition.
fn check_datatype_handles_implemented(
    module: &AdamantCompiledModule,
) -> Result<(), AdamantValidationError> {
    let implemented: HashSet<DatatypeHandleIndex> = module
        .struct_defs
        .iter()
        .map(|sd| sd.struct_handle)
        .chain(module.enum_defs.iter().map(|ed| ed.enum_handle))
        .collect();
    if let Some(idx) = (0..module.datatype_handles.len()).position(|x| {
        let handle_idx =
            DatatypeHandleIndex(TableIndex::try_from(x).expect("datatype-handle count fits u16"));
        module.datatype_handles[x].module == module.self_module_handle_idx
            && !implemented.contains(&handle_idx)
    }) {
        return Err(AdamantValidationError::UnimplementedHandle {
            kind: HandleKind::DatatypeHandle,
            idx: TableIndex::try_from(idx).expect("datatype-handle count fits u16"),
        });
    }
    Ok(())
}

// --- Helpers ----------------------------------------------------------------

/// Slice-form duplicate check producing
/// [`AdamantValidationError::DuplicateElement`] tagged with
/// `kind`. For pools whose identity is the entry's full
/// equality.
fn duplicate_or_ok<T: Eq + Hash>(
    pool: &[T],
    kind: IndexKind,
) -> Result<(), AdamantValidationError> {
    match first_duplicate_element(pool.iter()) {
        Some(idx) => Err(AdamantValidationError::DuplicateElement { kind, idx }),
        None => Ok(()),
    }
}

/// Iterator-form duplicate check. Used where the identity
/// extracts a sub-key from each entry (e.g., `DatatypeHandle` by
/// `(module, name)`).
fn duplicate_iter_or_ok<T, I>(iter: I, kind: IndexKind) -> Result<(), AdamantValidationError>
where
    I: IntoIterator<Item = T>,
    T: Eq + Hash,
{
    match first_duplicate_element(iter) {
        Some(idx) => Err(AdamantValidationError::DuplicateElement { kind, idx }),
        None => Ok(()),
    }
}

/// Returns the index of the **second occurrence** of any
/// duplicate item (the first occurrence is canonical;
/// subsequent equal items are duplicates rejected here).
///
/// Per Q1 disposition at the C-2 plan-gate: helper stays
/// **private** at first instance. Future passes (C-3 Signature
/// Checker doesn't have duplication detection in this shape)
/// may surface a second consumer; if they do, evaluate
/// extraction at that point per the rule-of-three discipline.
fn first_duplicate_element<I>(iter: I) -> Option<TableIndex>
where
    I: IntoIterator,
    I::Item: Eq + Hash,
{
    let mut seen = HashSet::new();
    for (i, item) in iter.into_iter().enumerate() {
        if !seen.insert(item) {
            return Some(
                TableIndex::try_from(i)
                    .expect("pool count fits u16; binary format precludes overflow"),
            );
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use adamant_bytecode_format::{
        AbilitySet, AddressIdentifierIndex, Constant, DatatypeHandle, DatatypeHandleIndex,
        EnumDefinition, EnumDefinitionIndex, FieldDefinition, FieldHandle, FunctionHandle,
        FunctionHandleIndex, FunctionInstantiation, Identifier, IdentifierIndex, IndexKind,
        ModuleHandle, ModuleHandleIndex, Signature, SignatureIndex, SignatureToken,
        StructDefinition, StructDefinitionIndex, StructFieldInformation, TypeSignature,
        VariantDefinition, VariantHandle, Visibility,
    };
    use adamant_types::Address as AccountAddress;

    use crate::module::{AdamantCodeUnit, AdamantCompiledModule, AdamantFunctionDefinition};

    use super::super::super::error::{AdamantValidationError, DefKind, HandleKind};
    use super::super::test_helpers::assert_pass_parity;
    use super::verify;

    /// Minimal valid module shell. `self_handle` at index 0;
    /// `identifiers[0]` = `"M"`; `address_identifiers[0]` =
    /// zero address.
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

    // --- Layer A: positives ---

    #[test]
    fn empty_module_passes() {
        let m = empty_module();
        assert!(verify(&m).is_ok());
    }

    #[test]
    fn unique_identifiers_pass() {
        let mut m = empty_module();
        m.identifiers.push(Identifier::new("a").unwrap());
        m.identifiers.push(Identifier::new("b").unwrap());
        assert!(verify(&m).is_ok());
    }

    #[test]
    fn distinct_constants_with_same_data_different_type_pass() {
        // BCS (U64, [0]) and (Bool, [0]) are distinct constants
        // even though the data bytes overlap on `[0]` because
        // the type discriminates. Exercise the
        // full-equality-by-Eq pool check.
        let mut m = empty_module();
        m.constant_pool.push(Constant {
            type_: SignatureToken::U64,
            data: vec![0u8; 8],
        });
        m.constant_pool.push(Constant {
            type_: SignatureToken::Bool,
            data: vec![0u8; 1],
        });
        assert!(verify(&m).is_ok());
    }

    #[test]
    fn unique_struct_def_with_one_field_passes() {
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
                signature: TypeSignature(SignatureToken::U64),
            }]),
        });
        assert!(verify(&m).is_ok());
    }

    #[test]
    fn unique_enum_def_with_one_variant_passes() {
        let mut m = empty_module();
        m.identifiers.push(Identifier::new("E").unwrap());
        m.identifiers.push(Identifier::new("V").unwrap());
        m.datatype_handles.push(DatatypeHandle {
            module: ModuleHandleIndex(0),
            name: IdentifierIndex(1),
            abilities: AbilitySet::EMPTY,
            type_parameters: vec![],
        });
        m.enum_defs.push(EnumDefinition {
            enum_handle: DatatypeHandleIndex(0),
            variants: vec![VariantDefinition {
                variant_name: IdentifierIndex(2),
                fields: vec![],
            }],
        });
        assert!(verify(&m).is_ok());
    }

    #[test]
    fn function_def_implementing_self_module_handle_passes() {
        let mut m = empty_module();
        m.identifiers.push(Identifier::new("foo").unwrap());
        m.signatures.push(Signature(vec![]));
        m.function_handles.push(FunctionHandle {
            module: ModuleHandleIndex(0),
            name: IdentifierIndex(1),
            parameters: SignatureIndex(0),
            return_: SignatureIndex(0),
            type_parameters: vec![],
        });
        m.function_defs.push(AdamantFunctionDefinition {
            function: FunctionHandleIndex(0),
            visibility: Visibility::Private,
            is_entry: false,
            acquires_global_resources: vec![],
            code: Some(AdamantCodeUnit::default()),
        });
        assert!(verify(&m).is_ok());
    }

    // --- Layer A: negatives — first-duplicate per pool ---

    #[test]
    fn rejects_duplicate_identifier() {
        let mut m = empty_module();
        m.identifiers.push(Identifier::new("a").unwrap());
        m.identifiers.push(Identifier::new("a").unwrap());
        match verify(&m) {
            Err(AdamantValidationError::DuplicateElement {
                kind: IndexKind::Identifier,
                idx: 2,
            }) => {}
            other => panic!("expected DuplicateElement(Identifier, 2), got {other:?}"),
        }
    }

    #[test]
    fn rejects_duplicate_address_identifier() {
        let mut m = empty_module();
        m.address_identifiers
            .push(AccountAddress::from_bytes([0u8; 32]));
        match verify(&m) {
            Err(AdamantValidationError::DuplicateElement {
                kind: IndexKind::AddressIdentifier,
                idx: 1,
            }) => {}
            other => panic!("expected DuplicateElement(AddressIdentifier, 1), got {other:?}"),
        }
    }

    #[test]
    fn rejects_duplicate_constant() {
        let mut m = empty_module();
        m.constant_pool.push(Constant {
            type_: SignatureToken::U64,
            data: vec![0u8; 8],
        });
        m.constant_pool.push(Constant {
            type_: SignatureToken::U64,
            data: vec![0u8; 8],
        });
        match verify(&m) {
            Err(AdamantValidationError::DuplicateElement {
                kind: IndexKind::ConstantPool,
                idx: 1,
            }) => {}
            other => panic!("expected DuplicateElement(ConstantPool, 1), got {other:?}"),
        }
    }

    #[test]
    fn rejects_duplicate_signature() {
        let mut m = empty_module();
        m.signatures.push(Signature(vec![SignatureToken::U64]));
        m.signatures.push(Signature(vec![SignatureToken::U64]));
        match verify(&m) {
            Err(AdamantValidationError::DuplicateElement {
                kind: IndexKind::Signature,
                idx: 1,
            }) => {}
            other => panic!("expected DuplicateElement(Signature, 1), got {other:?}"),
        }
    }

    #[test]
    fn rejects_duplicate_module_handle() {
        let mut m = empty_module();
        // Add a duplicate of the existing self-handle.
        m.module_handles.push(ModuleHandle {
            address: AddressIdentifierIndex(0),
            name: IdentifierIndex(0),
        });
        match verify(&m) {
            Err(AdamantValidationError::DuplicateElement {
                kind: IndexKind::ModuleHandle,
                idx: 1,
            }) => {}
            other => panic!("expected DuplicateElement(ModuleHandle, 1), got {other:?}"),
        }
    }

    #[test]
    fn rejects_duplicate_friend_decl() {
        let mut m = empty_module();
        m.identifiers.push(Identifier::new("F").unwrap());
        m.friend_decls.push(ModuleHandle {
            address: AddressIdentifierIndex(0),
            name: IdentifierIndex(1),
        });
        m.friend_decls.push(ModuleHandle {
            address: AddressIdentifierIndex(0),
            name: IdentifierIndex(1),
        });
        match verify(&m) {
            Err(AdamantValidationError::DuplicateElement {
                kind: IndexKind::ModuleHandle,
                idx: 1,
            }) => {}
            other => panic!("expected DuplicateElement(ModuleHandle, 1), got {other:?}"),
        }
    }

    #[test]
    fn rejects_duplicate_datatype_handle_by_module_name_pair() {
        let mut m = empty_module();
        m.identifiers.push(Identifier::new("S").unwrap());
        // Two datatype handles with same (module, name) but different abilities.
        m.datatype_handles.push(DatatypeHandle {
            module: ModuleHandleIndex(0),
            name: IdentifierIndex(1),
            abilities: AbilitySet::EMPTY,
            type_parameters: vec![],
        });
        m.datatype_handles.push(DatatypeHandle {
            module: ModuleHandleIndex(0),
            name: IdentifierIndex(1),
            abilities: AbilitySet::EMPTY,
            type_parameters: vec![],
        });
        match verify(&m) {
            Err(AdamantValidationError::DuplicateElement {
                kind: IndexKind::DatatypeHandle,
                idx: 1,
            }) => {}
            other => panic!("expected DuplicateElement(DatatypeHandle, 1), got {other:?}"),
        }
    }

    #[test]
    fn rejects_duplicate_function_handle_by_module_name_pair() {
        let mut m = empty_module();
        m.identifiers.push(Identifier::new("foo").unwrap());
        m.signatures.push(Signature(vec![]));
        m.function_handles.push(FunctionHandle {
            module: ModuleHandleIndex(0),
            name: IdentifierIndex(1),
            parameters: SignatureIndex(0),
            return_: SignatureIndex(0),
            type_parameters: vec![],
        });
        m.function_handles.push(FunctionHandle {
            module: ModuleHandleIndex(0),
            name: IdentifierIndex(1),
            parameters: SignatureIndex(0),
            return_: SignatureIndex(0),
            type_parameters: vec![],
        });
        match verify(&m) {
            Err(AdamantValidationError::DuplicateElement {
                kind: IndexKind::FunctionHandle,
                idx: 1,
            }) => {}
            other => panic!("expected DuplicateElement(FunctionHandle, 1), got {other:?}"),
        }
    }

    #[test]
    fn rejects_duplicate_function_instantiation() {
        let mut m = empty_module();
        m.identifiers.push(Identifier::new("foo").unwrap());
        m.signatures.push(Signature(vec![]));
        m.function_handles.push(FunctionHandle {
            module: ModuleHandleIndex(0),
            name: IdentifierIndex(1),
            parameters: SignatureIndex(0),
            return_: SignatureIndex(0),
            type_parameters: vec![AbilitySet::EMPTY],
        });
        m.function_instantiations.push(FunctionInstantiation {
            handle: FunctionHandleIndex(0),
            type_parameters: SignatureIndex(0),
        });
        m.function_instantiations.push(FunctionInstantiation {
            handle: FunctionHandleIndex(0),
            type_parameters: SignatureIndex(0),
        });
        match verify(&m) {
            Err(AdamantValidationError::DuplicateElement {
                kind: IndexKind::FunctionInstantiation,
                idx: 1,
            }) => {}
            other => panic!("expected DuplicateElement(FunctionInstantiation, 1), got {other:?}"),
        }
    }

    #[test]
    fn rejects_duplicate_variant_handle_by_enum_def_variant_pair() {
        let mut m = empty_module();
        m.identifiers.push(Identifier::new("E").unwrap());
        m.identifiers.push(Identifier::new("V").unwrap());
        m.datatype_handles.push(DatatypeHandle {
            module: ModuleHandleIndex(0),
            name: IdentifierIndex(1),
            abilities: AbilitySet::EMPTY,
            type_parameters: vec![],
        });
        m.enum_defs.push(EnumDefinition {
            enum_handle: DatatypeHandleIndex(0),
            variants: vec![VariantDefinition {
                variant_name: IdentifierIndex(2),
                fields: vec![],
            }],
        });
        m.variant_handles.push(VariantHandle {
            enum_def: EnumDefinitionIndex(0),
            variant: 0,
        });
        m.variant_handles.push(VariantHandle {
            enum_def: EnumDefinitionIndex(0),
            variant: 0,
        });
        match verify(&m) {
            Err(AdamantValidationError::DuplicateElement {
                kind: IndexKind::VariantHandle,
                idx: 1,
            }) => {}
            other => panic!("expected DuplicateElement(VariantHandle, 1), got {other:?}"),
        }
    }

    // --- Layer A: negatives — instance-method checks ---

    #[test]
    fn rejects_zero_sized_struct() {
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
            field_information: StructFieldInformation::Declared(vec![]),
        });
        match verify(&m) {
            Err(AdamantValidationError::ZeroSizedStruct {
                def_idx: StructDefinitionIndex(0),
            }) => {}
            other => panic!("expected ZeroSizedStruct(0), got {other:?}"),
        }
    }

    #[test]
    fn rejects_zero_variant_enum() {
        let mut m = empty_module();
        m.identifiers.push(Identifier::new("E").unwrap());
        m.datatype_handles.push(DatatypeHandle {
            module: ModuleHandleIndex(0),
            name: IdentifierIndex(1),
            abilities: AbilitySet::EMPTY,
            type_parameters: vec![],
        });
        m.enum_defs.push(EnumDefinition {
            enum_handle: DatatypeHandleIndex(0),
            variants: vec![],
        });
        match verify(&m) {
            Err(AdamantValidationError::ZeroSizedEnum {
                def_idx: EnumDefinitionIndex(0),
            }) => {}
            other => panic!("expected ZeroSizedEnum(0), got {other:?}"),
        }
    }

    #[test]
    fn rejects_struct_def_with_duplicate_field_names() {
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
            field_information: StructFieldInformation::Declared(vec![
                FieldDefinition {
                    name: IdentifierIndex(2),
                    signature: TypeSignature(SignatureToken::U64),
                },
                FieldDefinition {
                    name: IdentifierIndex(2),
                    signature: TypeSignature(SignatureToken::Bool),
                },
            ]),
        });
        match verify(&m) {
            Err(AdamantValidationError::DuplicateElement {
                kind: IndexKind::FieldDefinition,
                idx: 1,
            }) => {}
            other => panic!("expected DuplicateElement(FieldDefinition, 1), got {other:?}"),
        }
    }

    #[test]
    fn rejects_struct_def_referencing_foreign_module() {
        let mut m = empty_module();
        m.identifiers.push(Identifier::new("F").unwrap());
        m.identifiers.push(Identifier::new("S").unwrap());
        m.identifiers.push(Identifier::new("f").unwrap());
        // module_handles[1] is a foreign module.
        m.module_handles.push(ModuleHandle {
            address: AddressIdentifierIndex(0),
            name: IdentifierIndex(1),
        });
        // datatype_handles[0] points at module_handles[1].
        m.datatype_handles.push(DatatypeHandle {
            module: ModuleHandleIndex(1),
            name: IdentifierIndex(2),
            abilities: AbilitySet::EMPTY,
            type_parameters: vec![],
        });
        m.struct_defs.push(StructDefinition {
            struct_handle: DatatypeHandleIndex(0),
            field_information: StructFieldInformation::Declared(vec![FieldDefinition {
                name: IdentifierIndex(3),
                signature: TypeSignature(SignatureToken::U64),
            }]),
        });
        match verify(&m) {
            Err(AdamantValidationError::InvalidModuleHandle {
                kind: DefKind::Struct,
                def_idx: 0,
            }) => {}
            other => panic!("expected InvalidModuleHandle(Struct, 0), got {other:?}"),
        }
    }

    #[test]
    fn rejects_struct_and_enum_sharing_datatype_handle() {
        // Joint uniqueness: a struct_def and an enum_def can't
        // share the same DatatypeHandleIndex (placement at
        // check_enum_definitions per Q3 disposition).
        let mut m = empty_module();
        m.identifiers.push(Identifier::new("S").unwrap());
        m.identifiers.push(Identifier::new("E").unwrap());
        m.identifiers.push(Identifier::new("f").unwrap());
        m.datatype_handles.push(DatatypeHandle {
            module: ModuleHandleIndex(0),
            name: IdentifierIndex(1),
            abilities: AbilitySet::EMPTY,
            type_parameters: vec![],
        });
        m.datatype_handles.push(DatatypeHandle {
            module: ModuleHandleIndex(0),
            name: IdentifierIndex(2),
            abilities: AbilitySet::EMPTY,
            type_parameters: vec![],
        });
        m.struct_defs.push(StructDefinition {
            struct_handle: DatatypeHandleIndex(0),
            field_information: StructFieldInformation::Declared(vec![FieldDefinition {
                name: IdentifierIndex(3),
                signature: TypeSignature(SignatureToken::U64),
            }]),
        });
        m.enum_defs.push(EnumDefinition {
            enum_handle: DatatypeHandleIndex(0), // SAME as struct_def[0]
            variants: vec![VariantDefinition {
                variant_name: IdentifierIndex(2),
                fields: vec![],
            }],
        });
        match verify(&m) {
            Err(AdamantValidationError::DuplicateElement {
                kind: IndexKind::EnumDefinition,
                idx: 1,
            }) => {}
            other => panic!(
                "expected DuplicateElement(EnumDefinition, 1) for joint uniqueness, got {other:?}"
            ),
        }
    }

    #[test]
    fn rejects_function_def_referencing_foreign_module() {
        let mut m = empty_module();
        m.identifiers.push(Identifier::new("F").unwrap());
        m.identifiers.push(Identifier::new("foo").unwrap());
        m.signatures.push(Signature(vec![]));
        m.module_handles.push(ModuleHandle {
            address: AddressIdentifierIndex(0),
            name: IdentifierIndex(1),
        });
        m.function_handles.push(FunctionHandle {
            module: ModuleHandleIndex(1),
            name: IdentifierIndex(2),
            parameters: SignatureIndex(0),
            return_: SignatureIndex(0),
            type_parameters: vec![],
        });
        m.function_defs.push(AdamantFunctionDefinition {
            function: FunctionHandleIndex(0),
            visibility: Visibility::Private,
            is_entry: false,
            acquires_global_resources: vec![],
            code: Some(AdamantCodeUnit::default()),
        });
        match verify(&m) {
            Err(AdamantValidationError::InvalidModuleHandle {
                kind: DefKind::Function,
                def_idx: 0,
            }) => {}
            other => panic!("expected InvalidModuleHandle(Function, 0), got {other:?}"),
        }
    }

    #[test]
    fn rejects_duplicate_acquires_annotation() {
        let mut m = empty_module();
        m.identifiers.push(Identifier::new("S").unwrap());
        m.identifiers.push(Identifier::new("foo").unwrap());
        m.identifiers.push(Identifier::new("f").unwrap());
        m.signatures.push(Signature(vec![]));
        m.datatype_handles.push(DatatypeHandle {
            module: ModuleHandleIndex(0),
            name: IdentifierIndex(1),
            abilities: AbilitySet::EMPTY,
            type_parameters: vec![],
        });
        m.struct_defs.push(StructDefinition {
            struct_handle: DatatypeHandleIndex(0),
            field_information: StructFieldInformation::Declared(vec![FieldDefinition {
                name: IdentifierIndex(3),
                signature: TypeSignature(SignatureToken::U64),
            }]),
        });
        m.function_handles.push(FunctionHandle {
            module: ModuleHandleIndex(0),
            name: IdentifierIndex(2),
            parameters: SignatureIndex(0),
            return_: SignatureIndex(0),
            type_parameters: vec![],
        });
        m.function_defs.push(AdamantFunctionDefinition {
            function: FunctionHandleIndex(0),
            visibility: Visibility::Private,
            is_entry: false,
            acquires_global_resources: vec![StructDefinitionIndex(0), StructDefinitionIndex(0)],
            code: Some(AdamantCodeUnit::default()),
        });
        match verify(&m) {
            Err(AdamantValidationError::DuplicateAcquiresAnnotation {
                fn_def_idx: adamant_bytecode_format::FunctionDefinitionIndex(0),
            }) => {}
            other => panic!("expected DuplicateAcquiresAnnotation(0), got {other:?}"),
        }
    }

    #[test]
    fn rejects_unimplemented_self_module_datatype_handle() {
        let mut m = empty_module();
        m.identifiers.push(Identifier::new("S").unwrap());
        // datatype_handles[0] points at self-module but no struct_def or enum_def references it.
        m.datatype_handles.push(DatatypeHandle {
            module: ModuleHandleIndex(0),
            name: IdentifierIndex(1),
            abilities: AbilitySet::EMPTY,
            type_parameters: vec![],
        });
        match verify(&m) {
            Err(AdamantValidationError::UnimplementedHandle {
                kind: HandleKind::DatatypeHandle,
                idx: 0,
            }) => {}
            other => panic!("expected UnimplementedHandle(DatatypeHandle, 0), got {other:?}"),
        }
    }

    #[test]
    fn rejects_unimplemented_self_module_function_handle() {
        let mut m = empty_module();
        m.identifiers.push(Identifier::new("foo").unwrap());
        m.signatures.push(Signature(vec![]));
        // function_handles[0] points at self-module but no function_def references it.
        m.function_handles.push(FunctionHandle {
            module: ModuleHandleIndex(0),
            name: IdentifierIndex(1),
            parameters: SignatureIndex(0),
            return_: SignatureIndex(0),
            type_parameters: vec![],
        });
        match verify(&m) {
            Err(AdamantValidationError::UnimplementedHandle {
                kind: HandleKind::FunctionHandle,
                idx: 0,
            }) => {}
            other => panic!("expected UnimplementedHandle(FunctionHandle, 0), got {other:?}"),
        }
    }

    #[test]
    fn rejects_duplicate_field_handle() {
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
                signature: TypeSignature(SignatureToken::U64),
            }]),
        });
        m.field_handles.push(FieldHandle {
            owner: StructDefinitionIndex(0),
            field: 0,
        });
        m.field_handles.push(FieldHandle {
            owner: StructDefinitionIndex(0),
            field: 0,
        });
        match verify(&m) {
            Err(AdamantValidationError::DuplicateElement {
                kind: IndexKind::FieldHandle,
                idx: 1,
            }) => {}
            other => panic!("expected DuplicateElement(FieldHandle, 1), got {other:?}"),
        }
    }

    // --- Byte-faithful preservation pins ---

    #[test]
    fn first_duplicate_returns_lowest_index_second_occurrence() {
        // Three identifiers all equal to "x". First-duplicate
        // returns idx 2 (the second occurrence of "x"; third
        // occurrence at idx 3 is also a duplicate but later).
        let mut m = empty_module();
        m.identifiers.push(Identifier::new("x").unwrap());
        m.identifiers.push(Identifier::new("x").unwrap());
        m.identifiers.push(Identifier::new("x").unwrap());
        match verify(&m) {
            Err(AdamantValidationError::DuplicateElement {
                kind: IndexKind::Identifier,
                idx: 2,
            }) => {}
            other => panic!(
                "expected DuplicateElement(Identifier, 2) (second occurrence), got {other:?}"
            ),
        }
    }

    #[test]
    fn identifiers_check_fires_before_address_identifiers_check() {
        // Both pools have duplicates. Identifiers fires first
        // per upstream sub-check ordering.
        let mut m = empty_module();
        m.identifiers.push(Identifier::new("a").unwrap());
        m.identifiers.push(Identifier::new("a").unwrap());
        m.address_identifiers
            .push(AccountAddress::from_bytes([0u8; 32]));
        match verify(&m) {
            Err(AdamantValidationError::DuplicateElement {
                kind: IndexKind::Identifier,
                ..
            }) => {}
            other => panic!("expected identifiers to win over address_identifiers, got {other:?}"),
        }
    }

    #[test]
    fn struct_handle_uniqueness_fires_before_zero_fields_rejection() {
        // Two struct_defs share struct_handle index 0; the
        // first has zero declared fields. Handle-uniqueness
        // fires first.
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
            field_information: StructFieldInformation::Declared(vec![]),
        });
        m.struct_defs.push(StructDefinition {
            struct_handle: DatatypeHandleIndex(0),
            field_information: StructFieldInformation::Declared(vec![]),
        });
        match verify(&m) {
            Err(AdamantValidationError::DuplicateElement {
                kind: IndexKind::StructDefinition,
                idx: 1,
            }) => {}
            other => panic!(
                "expected DuplicateElement(StructDefinition, 1) to win over ZeroSizedStruct, \
                 got {other:?}"
            ),
        }
    }

    #[test]
    fn enum_zero_variants_fires_before_invalid_module_handle() {
        // Enum has zero variants AND points at a foreign
        // module. Zero-variants check fires first because the
        // struct/enum handle-uniqueness scan in
        // check_enum_definitions runs before the per-enum
        // sub-checks but doesn't fire on the foreign-module
        // case (the joint-uniqueness check only sees handle
        // index 0 once total). Per upstream's ordering
        // pinned in the body.
        let mut m = empty_module();
        m.identifiers.push(Identifier::new("F").unwrap());
        m.identifiers.push(Identifier::new("E").unwrap());
        m.module_handles.push(ModuleHandle {
            address: AddressIdentifierIndex(0),
            name: IdentifierIndex(1),
        });
        m.datatype_handles.push(DatatypeHandle {
            module: ModuleHandleIndex(1), // foreign
            name: IdentifierIndex(2),
            abilities: AbilitySet::EMPTY,
            type_parameters: vec![],
        });
        m.enum_defs.push(EnumDefinition {
            enum_handle: DatatypeHandleIndex(0),
            variants: vec![], // zero variants
        });
        match verify(&m) {
            Err(AdamantValidationError::ZeroSizedEnum { .. }) => {}
            other => {
                panic!("expected ZeroSizedEnum to fire before InvalidModuleHandle, got {other:?}")
            }
        }
    }

    // --- Layer B: cross-validation against vendored Sui ---

    fn cross_validate_duplication_pass(m: &AdamantCompiledModule) {
        let adamant_result = verify(m);
        let sui_module = m
            .to_sui_module()
            .expect("test fixture has no Adamant extensions; to_sui_module must succeed");
        let sui_result =
            move_bytecode_verifier::check_duplication::DuplicationChecker::verify_module(
                &sui_module,
            );
        assert_pass_parity("duplication_checker", adamant_result, sui_result);
    }

    #[test]
    fn cross_validation_accepts_empty_module() {
        let m = empty_module();
        cross_validate_duplication_pass(&m);
    }

    #[test]
    fn cross_validation_accepts_unique_struct_def() {
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
                signature: TypeSignature(SignatureToken::U64),
            }]),
        });
        cross_validate_duplication_pass(&m);
    }

    #[test]
    fn cross_validation_rejects_duplicate_identifier() {
        let mut m = empty_module();
        m.identifiers.push(Identifier::new("a").unwrap());
        m.identifiers.push(Identifier::new("a").unwrap());
        cross_validate_duplication_pass(&m);
    }

    #[test]
    fn cross_validation_rejects_duplicate_signature() {
        let mut m = empty_module();
        m.signatures.push(Signature(vec![SignatureToken::U64]));
        m.signatures.push(Signature(vec![SignatureToken::U64]));
        cross_validate_duplication_pass(&m);
    }

    #[test]
    fn cross_validation_rejects_zero_sized_struct() {
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
            field_information: StructFieldInformation::Declared(vec![]),
        });
        cross_validate_duplication_pass(&m);
    }

    #[test]
    fn cross_validation_rejects_zero_variant_enum() {
        let mut m = empty_module();
        m.identifiers.push(Identifier::new("E").unwrap());
        m.datatype_handles.push(DatatypeHandle {
            module: ModuleHandleIndex(0),
            name: IdentifierIndex(1),
            abilities: AbilitySet::EMPTY,
            type_parameters: vec![],
        });
        m.enum_defs.push(EnumDefinition {
            enum_handle: DatatypeHandleIndex(0),
            variants: vec![],
        });
        cross_validate_duplication_pass(&m);
    }

    #[test]
    fn cross_validation_rejects_unimplemented_handle() {
        let mut m = empty_module();
        m.identifiers.push(Identifier::new("S").unwrap());
        m.datatype_handles.push(DatatypeHandle {
            module: ModuleHandleIndex(0),
            name: IdentifierIndex(1),
            abilities: AbilitySet::EMPTY,
            type_parameters: vec![],
        });
        cross_validate_duplication_pass(&m);
    }

    #[test]
    fn cross_validation_rejects_struct_and_enum_sharing_datatype_handle() {
        let mut m = empty_module();
        m.identifiers.push(Identifier::new("S").unwrap());
        m.identifiers.push(Identifier::new("E").unwrap());
        m.identifiers.push(Identifier::new("f").unwrap());
        m.datatype_handles.push(DatatypeHandle {
            module: ModuleHandleIndex(0),
            name: IdentifierIndex(1),
            abilities: AbilitySet::EMPTY,
            type_parameters: vec![],
        });
        m.datatype_handles.push(DatatypeHandle {
            module: ModuleHandleIndex(0),
            name: IdentifierIndex(2),
            abilities: AbilitySet::EMPTY,
            type_parameters: vec![],
        });
        m.struct_defs.push(StructDefinition {
            struct_handle: DatatypeHandleIndex(0),
            field_information: StructFieldInformation::Declared(vec![FieldDefinition {
                name: IdentifierIndex(3),
                signature: TypeSignature(SignatureToken::U64),
            }]),
        });
        m.enum_defs.push(EnumDefinition {
            enum_handle: DatatypeHandleIndex(0),
            variants: vec![VariantDefinition {
                variant_name: IdentifierIndex(2),
                fields: vec![],
            }],
        });
        cross_validate_duplication_pass(&m);
    }
}
