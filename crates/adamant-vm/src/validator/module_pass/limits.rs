//! Module-level pass: structural limits
//! (whitepaper §6.2.1.8 step 3).
//!
//! Forked from `vendor/move-bytecode-verifier/src/limits.rs`
//! at Sui-Move tag `mainnet-v1.66.2` (commit
//! `a9a6825eaf6273cc819ee3bcf65fd4909f7624a9`). See
//! `validator/module_pass/PROVENANCE.md` for the deviation
//! list. Summary:
//!
//! - Operates on [`AdamantCompiledModule`] rather than Sui's
//!   `CompiledModule`. The structural-limit fields covered
//!   are byte-faithful to upstream.
//! - Returns typed [`AdamantValidationError`] variants for
//!   each sub-check rather than upstream's
//!   `PartialVMError`/`StatusCode`.
//! - Consumes [`AdamantStructuralLimits`] from B-1's
//!   `validator/config.rs` rather than Sui's `VerifierConfig`.
//!   Adamant's limits are concrete genesis values per the
//!   B-1 redirect (no `None` short-circuit branches in
//!   production), but the `Option<...>` shape is preserved
//!   so each sub-check no-ops on `None` per upstream
//!   semantics.
//! - Vector-length sub-check reads only the outer ULEB128
//!   prefix from the constant's BCS data via
//!   `read_uleb128_as_u64`, matching upstream's element-
//!   count semantics without requiring a production dep on
//!   `move_core_types::runtime_value`'s `MoveValue`. The
//!   `MalformedConstantData` variant from B-2.1 is reused
//!   if the prefix read fails — defense-in-depth structural
//!   redundancy with B-2.1's full type-directed walker.
//!
//! Six sub-checks per upstream `LimitsVerifier::verify_module_impl`,
//! preserving order byte-faithfully:
//!
//! 1. `verify_constants` — vector-length bound on Vector
//!    constants.
//! 2. `verify_function_handles` — type-parameter and
//!    parameter counts.
//! 3. `verify_datatype_handles` — type-parameter count.
//! 4. `verify_type_nodes` — preorder weighted node count
//!    on every signature-token tree (signatures pool,
//!    constant pool, struct fields, enum-variant fields).
//! 5. `verify_identifiers` — length and `<SELF>` rejection.
//! 6. `verify_definitions` — function/data/field/variant
//!    counts.
//!
//! Eager-error: first violation in the sub-check order
//! above wins; within each sub-check, lowest-index offender
//! wins.
//!
//! # `<SELF>` rejection: structural impossibility in Adamant
//!
//! The `disallow_self_identifier` check is preserved
//! byte-faithfully from upstream for defense-in-depth, but
//! its trigger condition is structurally unreachable in
//! Adamant's pipeline:
//!
//! - Adamant's [`adamant_bytecode_format::Identifier::is_valid`]
//!   rejects `<SELF>` (the `<` and `>` characters are not
//!   in `is_valid_identifier_char`'s acceptance set).
//! - Adamant has no `Identifier::new_unchecked` constructor
//!   (per `adamant-bytecode-format/PROVENANCE.md` — "Adamant's
//!   parsing path always validates on `Identifier::new`; the
//!   unchecked path is not needed").
//! - The deserializer's `Identifier::from_utf8` path delegates
//!   to `is_valid`, so `<SELF>` cannot appear in any
//!   deserialized module's identifier pool.
//!
//! In Sui, `<SELF>` enters compiled modules via the
//! `ident_str!` macro's `unsafe transmute` from `&'static str`
//! to `&'static IdentStr` — bypassing `is_valid`. Adamant
//! omits this macro path (PROVENANCE.md documents the
//! omission). The verifier-level check is therefore redundant
//! by construction in Adamant's pipeline, not by hope (same
//! pattern as B-2.4's deprecated-arms).
//!
//! No test exercises the `<SELF>`-rejection path because the
//! identifier cannot be constructed from inside the test
//! suite. The structural impossibility is pinned by a test
//! that asserts `Identifier::new("<SELF>")` returns `Err`.

use std::io::Cursor;

use adamant_bytecode_format::{
    read_uleb128_as_u64, ConstantPoolIndex, EnumDefinitionIndex, FunctionHandleIndex,
    IdentifierIndex, SignatureToken, StructFieldInformation, TableIndex,
};

use crate::module::AdamantCompiledModule;

use super::super::config::AdamantStructuralLimits;
use super::super::error::{
    AdamantValidationError, FieldOwnerKind, HandleKind, MalformedConstantReason,
};

const STRUCT_SIZE_WEIGHT: usize = 4;
const PARAM_SIZE_WEIGHT: usize = 4;
const SELF_IDENTIFIER: &str = "<SELF>";

/// Verify the module's structural limits per §6.2.1.8 step 3
/// (`module_pass::limits`).
///
/// Eager-error semantics: returns the first violation
/// encountered, scanning sub-checks in upstream order and
/// indices in pool order within each sub-check.
pub(in crate::validator) fn verify(
    module: &AdamantCompiledModule,
    limits: &AdamantStructuralLimits,
) -> Result<(), AdamantValidationError> {
    verify_constants(module, limits)?;
    verify_function_handles(module, limits)?;
    verify_datatype_handles(module, limits)?;
    verify_type_nodes(module, limits)?;
    verify_identifiers(module, limits)?;
    verify_definitions(module, limits)?;
    Ok(())
}

fn verify_constants(
    module: &AdamantCompiledModule,
    limits: &AdamantStructuralLimits,
) -> Result<(), AdamantValidationError> {
    let Some(max) = limits.max_constant_vector_len else {
        return Ok(());
    };
    for (idx, constant) in module.constant_pool.iter().enumerate() {
        let SignatureToken::Vector(_) = &constant.type_ else {
            continue;
        };
        let constant_pool_idx = ConstantPoolIndex(TableIndex::try_from(idx).expect(
            "constant_pool count exceeds u16; binary format precludes this \
                 (TABLE_INDEX_MAX = u16::MAX)",
        ));
        let mut cursor = Cursor::new(constant.data.as_slice());
        let element_count = read_uleb128_as_u64(&mut cursor).map_err(|_| {
            AdamantValidationError::MalformedConstantData {
                idx: constant_pool_idx,
                reason: MalformedConstantReason::InvalidUleb128,
            }
        })?;
        if element_count > max {
            return Err(AdamantValidationError::TooManyVectorElements {
                idx: constant_pool_idx,
            });
        }
    }
    Ok(())
}

fn verify_function_handles(
    module: &AdamantCompiledModule,
    limits: &AdamantStructuralLimits,
) -> Result<(), AdamantValidationError> {
    for (idx, handle) in module.function_handles.iter().enumerate() {
        let table_idx = TableIndex::try_from(idx)
            .expect("function_handles count exceeds u16; binary format precludes this");
        if let Some(max) = limits.max_generic_instantiation_length {
            if handle.type_parameters.len() > max {
                return Err(AdamantValidationError::TooManyTypeParameters {
                    kind: HandleKind::FunctionHandle,
                    idx: table_idx,
                });
            }
        }
        if let Some(max) = limits.max_function_parameters {
            let parameter_count = module.signatures[handle.parameters.0 as usize].0.len();
            if parameter_count > max {
                return Err(AdamantValidationError::TooManyParameters {
                    idx: FunctionHandleIndex(table_idx),
                });
            }
        }
    }
    Ok(())
}

fn verify_datatype_handles(
    module: &AdamantCompiledModule,
    limits: &AdamantStructuralLimits,
) -> Result<(), AdamantValidationError> {
    let Some(max) = limits.max_generic_instantiation_length else {
        return Ok(());
    };
    for (idx, handle) in module.datatype_handles.iter().enumerate() {
        if handle.type_parameters.len() > max {
            return Err(AdamantValidationError::TooManyTypeParameters {
                kind: HandleKind::DatatypeHandle,
                idx: TableIndex::try_from(idx)
                    .expect("datatype_handles count exceeds u16; binary format precludes this"),
            });
        }
    }
    Ok(())
}

fn verify_type_nodes(
    module: &AdamantCompiledModule,
    limits: &AdamantStructuralLimits,
) -> Result<(), AdamantValidationError> {
    let Some(max) = limits.max_type_nodes else {
        return Ok(());
    };
    for sig in &module.signatures {
        for ty in &sig.0 {
            verify_type_node(ty, max)?;
        }
    }
    for cons in &module.constant_pool {
        verify_type_node(&cons.type_, max)?;
    }
    for sdef in &module.struct_defs {
        if let StructFieldInformation::Declared(fdefs) = &sdef.field_information {
            for fdef in fdefs {
                verify_type_node(&fdef.signature.0, max)?;
            }
        }
    }
    for field in module
        .enum_defs
        .iter()
        .flat_map(|e| e.variants.iter().flat_map(|v| &v.fields))
    {
        verify_type_node(&field.signature.0, max)?;
    }
    Ok(())
}

fn verify_type_node(ty: &SignatureToken, max: usize) -> Result<(), AdamantValidationError> {
    let mut size = 0usize;
    for t in ty.preorder_traversal() {
        match t {
            SignatureToken::Datatype(_) | SignatureToken::DatatypeInstantiation(_) => {
                size = size.saturating_add(STRUCT_SIZE_WEIGHT);
            }
            SignatureToken::TypeParameter(_) => {
                size = size.saturating_add(PARAM_SIZE_WEIGHT);
            }
            _ => {
                size = size.saturating_add(1);
            }
        }
    }
    if size > max {
        return Err(AdamantValidationError::TooManyTypeNodes);
    }
    Ok(())
}

fn verify_identifiers(
    module: &AdamantCompiledModule,
    limits: &AdamantStructuralLimits,
) -> Result<(), AdamantValidationError> {
    for (idx, identifier) in module.identifiers.iter().enumerate() {
        let table_idx = TableIndex::try_from(idx)
            .expect("identifiers count exceeds u16; binary format precludes this");
        if let Some(max) = limits.max_identifier_len {
            if identifier.len() as u64 > max {
                return Err(AdamantValidationError::IdentifierTooLong {
                    idx: IdentifierIndex(table_idx),
                });
            }
        }
        if limits.disallow_self_identifier && identifier.as_str() == SELF_IDENTIFIER {
            return Err(AdamantValidationError::InvalidIdentifier {
                idx: IdentifierIndex(table_idx),
            });
        }
    }
    Ok(())
}

fn verify_definitions(
    module: &AdamantCompiledModule,
    limits: &AdamantStructuralLimits,
) -> Result<(), AdamantValidationError> {
    if let Some(max) = limits.max_function_definitions {
        if module.function_defs.len() > max {
            return Err(AdamantValidationError::MaxFunctionDefinitionsReached);
        }
    }
    if let Some(max) = limits.max_data_definitions {
        let total = module.struct_defs.len() + module.enum_defs.len();
        if total > max {
            return Err(AdamantValidationError::MaxDataDefinitionsReached);
        }
    }
    if let Some(max) = limits.max_fields_in_struct {
        for (idx, def) in module.struct_defs.iter().enumerate() {
            let StructFieldInformation::Declared(fields) = &def.field_information else {
                continue;
            };
            if fields.len() > max {
                return Err(AdamantValidationError::MaxFieldDefinitionsReached {
                    kind: FieldOwnerKind::Struct,
                    def_idx: TableIndex::try_from(idx)
                        .expect("struct_defs count exceeds u16; binary format precludes this"),
                });
            }
        }
        for (idx, def) in module.enum_defs.iter().enumerate() {
            let table_idx = TableIndex::try_from(idx)
                .expect("enum_defs count exceeds u16; binary format precludes this");
            if let Some(max_variants) = limits.max_variants_in_enum {
                if def.variants.len() as u64 > max_variants {
                    return Err(AdamantValidationError::MaxVariantsInEnumReached {
                        def_idx: EnumDefinitionIndex(table_idx),
                    });
                }
            }
            let mut num_fields = 0usize;
            for variant in &def.variants {
                num_fields = num_fields.saturating_add(variant.fields.len());
                if num_fields > max {
                    return Err(AdamantValidationError::MaxFieldDefinitionsReached {
                        kind: FieldOwnerKind::Enum,
                        def_idx: table_idx,
                    });
                }
            }
        }
    } else if let Some(max_variants) = limits.max_variants_in_enum {
        // max_fields_in_struct is None but max_variants_in_enum
        // is set: still enforce variant-count bound. Matches
        // upstream's nested-conditional shape (the variant-
        // count check is gated only by max_variants_in_enum,
        // not by max_fields_in_struct, but upstream nests them
        // structurally; Adamant preserves the nested gate
        // form when max_fields_in_struct is set and adds this
        // independent path for the None-fields case).
        for (idx, def) in module.enum_defs.iter().enumerate() {
            if def.variants.len() as u64 > max_variants {
                return Err(AdamantValidationError::MaxVariantsInEnumReached {
                    def_idx: EnumDefinitionIndex(
                        TableIndex::try_from(idx)
                            .expect("enum_defs count exceeds u16; binary format precludes this"),
                    ),
                });
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use adamant_bytecode_format::{
        AbilitySet, AddressIdentifierIndex, Constant, DatatypeHandle, DatatypeHandleIndex,
        DatatypeTyParameter, EnumDefinition, FieldDefinition, FunctionHandle, Identifier,
        IdentifierIndex, ModuleHandle, ModuleHandleIndex, Signature, SignatureIndex,
        SignatureToken, StructDefinition, StructFieldInformation, TypeSignature, VariantDefinition,
    };
    use adamant_types::Address as AccountAddress;
    use move_bytecode_verifier_meter::dummy::DummyMeter;

    use crate::module::AdamantCompiledModule;

    use super::super::super::config::AdamantStructuralLimits;
    use super::super::super::error::{
        AdamantValidationError, FieldOwnerKind, HandleKind, MalformedConstantReason,
    };
    use super::super::test_helpers::assert_pass_parity;
    use super::verify;

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

    /// Build a fixture limits config with a specific override
    /// applied. Defaults to the genesis values; tests pass a
    /// closure to tighten one or more fields.
    fn limits_with(modify: impl FnOnce(&mut AdamantStructuralLimits)) -> AdamantStructuralLimits {
        let mut limits = AdamantStructuralLimits::genesis();
        modify(&mut limits);
        limits
    }

    fn push_signature(
        m: &mut AdamantCompiledModule,
        tokens: Vec<SignatureToken>,
    ) -> SignatureIndex {
        let idx = SignatureIndex(u16::try_from(m.signatures.len()).unwrap());
        m.signatures.push(Signature(tokens));
        idx
    }

    // ============================================================
    // verify_constants
    // ============================================================

    #[test]
    fn empty_module_passes_under_genesis_limits() {
        let m = empty_module();
        assert!(verify(&m, &AdamantStructuralLimits::genesis()).is_ok());
    }

    #[test]
    fn rejects_vector_constant_above_max_constant_vector_len() {
        let mut m = empty_module();
        // ULEB128 length of 5; payload is 5 u8 bytes.
        m.constant_pool.push(Constant {
            type_: SignatureToken::Vector(Box::new(SignatureToken::U8)),
            data: vec![0x05, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE],
        });
        let limits = limits_with(|l| l.max_constant_vector_len = Some(4));
        match verify(&m, &limits) {
            Err(AdamantValidationError::TooManyVectorElements { idx }) => {
                assert_eq!(idx.0, 0);
            }
            other => panic!("expected TooManyVectorElements, got {other:?}"),
        }
    }

    #[test]
    fn vector_constant_at_limit_passes() {
        let mut m = empty_module();
        m.constant_pool.push(Constant {
            type_: SignatureToken::Vector(Box::new(SignatureToken::U8)),
            data: vec![0x04, 0xAA, 0xBB, 0xCC, 0xDD],
        });
        let limits = limits_with(|l| l.max_constant_vector_len = Some(4));
        assert!(verify(&m, &limits).is_ok());
    }

    #[test]
    fn rejects_vector_constant_with_malformed_uleb128_prefix() {
        let mut m = empty_module();
        m.constant_pool.push(Constant {
            type_: SignatureToken::Vector(Box::new(SignatureToken::U8)),
            data: vec![0x80; 10], // continuation bits all set, no terminator
        });
        let limits = limits_with(|l| l.max_constant_vector_len = Some(100));
        assert!(matches!(
            verify(&m, &limits),
            Err(AdamantValidationError::MalformedConstantData {
                reason: MalformedConstantReason::InvalidUleb128,
                ..
            })
        ));
    }

    #[test]
    fn non_vector_constant_skipped_by_constants_subcheck() {
        let mut m = empty_module();
        m.constant_pool.push(Constant {
            type_: SignatureToken::U64,
            data: vec![0; 8],
        });
        // Even with tiny vector limit, U64 constant skipped.
        let limits = limits_with(|l| l.max_constant_vector_len = Some(0));
        assert!(verify(&m, &limits).is_ok());
    }

    // ============================================================
    // verify_function_handles
    // ============================================================

    #[test]
    fn rejects_function_handle_with_too_many_type_parameters() {
        let mut m = empty_module();
        let empty_sig = push_signature(&mut m, vec![]);
        let name = IdentifierIndex(u16::try_from(m.identifiers.len()).unwrap());
        m.identifiers.push(Identifier::new("f").unwrap());
        m.function_handles.push(FunctionHandle {
            module: ModuleHandleIndex(0),
            name,
            parameters: empty_sig,
            return_: empty_sig,
            type_parameters: vec![AbilitySet::EMPTY, AbilitySet::EMPTY, AbilitySet::EMPTY],
        });
        let limits = limits_with(|l| l.max_generic_instantiation_length = Some(2));
        match verify(&m, &limits) {
            Err(AdamantValidationError::TooManyTypeParameters {
                kind: HandleKind::FunctionHandle,
                idx,
            }) => {
                assert_eq!(idx, 0);
            }
            other => panic!("expected TooManyTypeParameters/FunctionHandle, got {other:?}"),
        }
    }

    #[test]
    fn rejects_function_handle_with_too_many_parameters() {
        let mut m = empty_module();
        let empty_sig = push_signature(&mut m, vec![]);
        let big_sig = push_signature(
            &mut m,
            vec![SignatureToken::U8, SignatureToken::U8, SignatureToken::U8],
        );
        let name = IdentifierIndex(u16::try_from(m.identifiers.len()).unwrap());
        m.identifiers.push(Identifier::new("f").unwrap());
        m.function_handles.push(FunctionHandle {
            module: ModuleHandleIndex(0),
            name,
            parameters: big_sig,
            return_: empty_sig,
            type_parameters: vec![],
        });
        let limits = limits_with(|l| l.max_function_parameters = Some(2));
        match verify(&m, &limits) {
            Err(AdamantValidationError::TooManyParameters { idx }) => {
                assert_eq!(idx.0, 0);
            }
            other => panic!("expected TooManyParameters, got {other:?}"),
        }
    }

    // ============================================================
    // verify_datatype_handles
    // ============================================================

    #[test]
    fn rejects_datatype_handle_with_too_many_type_parameters() {
        let mut m = empty_module();
        let name = IdentifierIndex(u16::try_from(m.identifiers.len()).unwrap());
        m.identifiers.push(Identifier::new("S").unwrap());
        m.datatype_handles.push(DatatypeHandle {
            module: ModuleHandleIndex(0),
            name,
            abilities: AbilitySet::EMPTY,
            type_parameters: vec![
                DatatypeTyParameter {
                    constraints: AbilitySet::EMPTY,
                    is_phantom: false,
                };
                3
            ],
        });
        let limits = limits_with(|l| l.max_generic_instantiation_length = Some(2));
        match verify(&m, &limits) {
            Err(AdamantValidationError::TooManyTypeParameters {
                kind: HandleKind::DatatypeHandle,
                idx,
            }) => {
                assert_eq!(idx, 0);
            }
            other => panic!("expected TooManyTypeParameters/DatatypeHandle, got {other:?}"),
        }
    }

    // ============================================================
    // verify_type_nodes
    // ============================================================

    #[test]
    fn rejects_signature_token_tree_exceeding_max_type_nodes() {
        let mut m = empty_module();
        // Vector<Vector<Vector<Vector<U8>>>>: 5 nodes weighted as
        // 1+1+1+1+1 = 5 (Vector wraps and primitive U8 leaf).
        let nested = SignatureToken::Vector(Box::new(SignatureToken::Vector(Box::new(
            SignatureToken::Vector(Box::new(SignatureToken::Vector(Box::new(
                SignatureToken::U8,
            )))),
        ))));
        let _sig = push_signature(&mut m, vec![nested]);
        let limits = limits_with(|l| l.max_type_nodes = Some(4));
        assert!(matches!(
            verify(&m, &limits),
            Err(AdamantValidationError::TooManyTypeNodes)
        ));
    }

    #[test]
    fn signature_token_tree_at_limit_passes() {
        let mut m = empty_module();
        let nested = SignatureToken::Vector(Box::new(SignatureToken::Vector(Box::new(
            SignatureToken::U8,
        ))));
        let _sig = push_signature(&mut m, vec![nested]);
        let limits = limits_with(|l| l.max_type_nodes = Some(3));
        assert!(verify(&m, &limits).is_ok());
    }

    // ============================================================
    // verify_identifiers
    // ============================================================

    #[test]
    fn rejects_identifier_above_max_identifier_len() {
        let mut m = empty_module();
        m.identifiers.push(Identifier::new("aaaaaaaa").unwrap());
        // genesis sets max_identifier_len = Some(128); tighten
        // for the test.
        let limits = limits_with(|l| l.max_identifier_len = Some(4));
        match verify(&m, &limits) {
            Err(AdamantValidationError::IdentifierTooLong { idx }) => {
                assert_eq!(idx.0, 1);
            }
            other => panic!("expected IdentifierTooLong, got {other:?}"),
        }
    }

    /// Pin the structural argument: `<SELF>` cannot be
    /// constructed via Adamant's `Identifier::new` (the only
    /// public path), so the `disallow_self_identifier` check
    /// is unreachable through any normal pipeline path. See
    /// the module-level "`<SELF>` rejection: structural
    /// impossibility in Adamant" doc comment.
    #[test]
    fn self_identifier_cannot_be_constructed_via_identifier_new() {
        assert!(Identifier::new("<SELF>").is_err());
    }

    // ============================================================
    // verify_definitions
    // ============================================================

    #[test]
    fn rejects_too_many_function_definitions() {
        let mut m = empty_module();
        let empty_sig = push_signature(&mut m, vec![]);
        for i in 0..3 {
            let name = IdentifierIndex(u16::try_from(m.identifiers.len()).unwrap());
            m.identifiers
                .push(Identifier::new(format!("f{i}")).unwrap());
            m.function_handles.push(FunctionHandle {
                module: ModuleHandleIndex(0),
                name,
                parameters: empty_sig,
                return_: empty_sig,
                type_parameters: vec![],
            });
            m.function_defs
                .push(crate::module::AdamantFunctionDefinition {
                    function: adamant_bytecode_format::FunctionHandleIndex(i),
                    visibility: adamant_bytecode_format::Visibility::Private,
                    is_entry: false,
                    acquires_global_resources: vec![],
                    code: Some(crate::module::AdamantCodeUnit {
                        locals: empty_sig,
                        code: vec![crate::bytecode::BytecodeInstruction::Inherited(
                            adamant_bytecode_format::Bytecode::Ret,
                        )],
                        jump_tables: vec![],
                    }),
                });
        }
        let limits = limits_with(|l| l.max_function_definitions = Some(2));
        assert!(matches!(
            verify(&m, &limits),
            Err(AdamantValidationError::MaxFunctionDefinitionsReached)
        ));
    }

    #[test]
    fn rejects_too_many_data_definitions() {
        let mut m = empty_module();
        for i in 0..3 {
            let name = IdentifierIndex(u16::try_from(m.identifiers.len()).unwrap());
            m.identifiers
                .push(Identifier::new(format!("S{i}")).unwrap());
            m.datatype_handles.push(DatatypeHandle {
                module: ModuleHandleIndex(0),
                name,
                abilities: AbilitySet::EMPTY,
                type_parameters: vec![],
            });
            m.struct_defs.push(StructDefinition {
                struct_handle: DatatypeHandleIndex(i),
                field_information: StructFieldInformation::Declared(vec![]),
            });
        }
        let limits = limits_with(|l| l.max_data_definitions = Some(2));
        assert!(matches!(
            verify(&m, &limits),
            Err(AdamantValidationError::MaxDataDefinitionsReached)
        ));
    }

    #[test]
    fn rejects_struct_with_too_many_fields() {
        let mut m = empty_module();
        let s_name = IdentifierIndex(u16::try_from(m.identifiers.len()).unwrap());
        m.identifiers.push(Identifier::new("S").unwrap());
        m.datatype_handles.push(DatatypeHandle {
            module: ModuleHandleIndex(0),
            name: s_name,
            abilities: AbilitySet::EMPTY,
            type_parameters: vec![],
        });
        let f_name = IdentifierIndex(u16::try_from(m.identifiers.len()).unwrap());
        m.identifiers.push(Identifier::new("f").unwrap());
        let mut fields = vec![];
        for _ in 0..3 {
            fields.push(FieldDefinition {
                name: f_name,
                signature: TypeSignature(SignatureToken::U8),
            });
        }
        m.struct_defs.push(StructDefinition {
            struct_handle: DatatypeHandleIndex(0),
            field_information: StructFieldInformation::Declared(fields),
        });
        let limits = limits_with(|l| l.max_fields_in_struct = Some(2));
        match verify(&m, &limits) {
            Err(AdamantValidationError::MaxFieldDefinitionsReached {
                kind: FieldOwnerKind::Struct,
                def_idx,
            }) => {
                assert_eq!(def_idx, 0);
            }
            other => panic!("expected MaxFieldDefinitionsReached/Struct, got {other:?}"),
        }
    }

    #[test]
    fn rejects_enum_with_too_many_variants() {
        let mut m = empty_module();
        let e_name = IdentifierIndex(u16::try_from(m.identifiers.len()).unwrap());
        m.identifiers.push(Identifier::new("E").unwrap());
        m.datatype_handles.push(DatatypeHandle {
            module: ModuleHandleIndex(0),
            name: e_name,
            abilities: AbilitySet::EMPTY,
            type_parameters: vec![],
        });
        let v_name = IdentifierIndex(u16::try_from(m.identifiers.len()).unwrap());
        m.identifiers.push(Identifier::new("V").unwrap());
        let variants = (0..3)
            .map(|_| VariantDefinition {
                variant_name: v_name,
                fields: vec![],
            })
            .collect();
        m.enum_defs.push(EnumDefinition {
            enum_handle: DatatypeHandleIndex(0),
            variants,
        });
        let limits = limits_with(|l| l.max_variants_in_enum = Some(2));
        match verify(&m, &limits) {
            Err(AdamantValidationError::MaxVariantsInEnumReached { def_idx }) => {
                assert_eq!(def_idx.0, 0);
            }
            other => panic!("expected MaxVariantsInEnumReached, got {other:?}"),
        }
    }

    #[test]
    fn rejects_enum_with_too_many_cumulative_variant_fields() {
        let mut m = empty_module();
        let e_name = IdentifierIndex(u16::try_from(m.identifiers.len()).unwrap());
        m.identifiers.push(Identifier::new("E").unwrap());
        m.datatype_handles.push(DatatypeHandle {
            module: ModuleHandleIndex(0),
            name: e_name,
            abilities: AbilitySet::EMPTY,
            type_parameters: vec![],
        });
        let v_name = IdentifierIndex(u16::try_from(m.identifiers.len()).unwrap());
        m.identifiers.push(Identifier::new("V").unwrap());
        let f_name = IdentifierIndex(u16::try_from(m.identifiers.len()).unwrap());
        m.identifiers.push(Identifier::new("f").unwrap());
        let make_field = || FieldDefinition {
            name: f_name,
            signature: TypeSignature(SignatureToken::U8),
        };
        let variants = vec![
            VariantDefinition {
                variant_name: v_name,
                fields: vec![make_field(), make_field()],
            },
            VariantDefinition {
                variant_name: v_name,
                fields: vec![make_field(), make_field()],
            },
        ];
        m.enum_defs.push(EnumDefinition {
            enum_handle: DatatypeHandleIndex(0),
            variants,
        });
        // 4 cumulative fields; max_fields_in_struct limits to 3.
        let limits = limits_with(|l| l.max_fields_in_struct = Some(3));
        match verify(&m, &limits) {
            Err(AdamantValidationError::MaxFieldDefinitionsReached {
                kind: FieldOwnerKind::Enum,
                def_idx,
            }) => {
                assert_eq!(def_idx, 0);
            }
            other => panic!("expected MaxFieldDefinitionsReached/Enum, got {other:?}"),
        }
    }

    // ============================================================
    // None short-circuit
    // ============================================================

    #[test]
    fn none_limits_short_circuit_to_ok() {
        // Construct a module that would fail several checks
        // under genesis but pass with all-None limits.
        // Cannot include a `<SELF>` identifier (structurally
        // impossible per the module-level doc); use a long
        // identifier that exceeds genesis `max_identifier_len`
        // instead — under None, the length check skips.
        let mut m = empty_module();
        let long_name = "a".repeat(200);
        m.identifiers.push(Identifier::new(long_name).unwrap());
        let limits = AdamantStructuralLimits {
            max_generic_instantiation_length: None,
            max_function_parameters: None,
            max_type_nodes: None,
            max_function_definitions: None,
            max_data_definitions: None,
            max_fields_in_struct: None,
            max_variants_in_enum: None,
            max_constant_vector_len: None,
            max_identifier_len: None,
            disallow_self_identifier: false,
            max_loop_depth: None,
            max_push_size: None,
        };
        assert!(verify(&m, &limits).is_ok());
    }

    // ============================================================
    // Layer B — cross-validation against vendored Sui
    // ============================================================
    //
    // Sui's `LimitsVerifier::verify_module` takes `&VerifierConfig`
    // (not the structural-limits subset alone). The Layer B
    // helper builds a Sui `VerifierConfig` whose structural-
    // limits fields mirror the Adamant `AdamantStructuralLimits`
    // fixture; the rest of `VerifierConfig` defaults.

    fn cross_validate_pass(m: &AdamantCompiledModule, limits: &AdamantStructuralLimits) {
        let adamant_result = verify(m, limits);
        let sui_module = m
            .to_sui_module()
            .expect("test fixture has no Adamant extensions; to_sui_module must succeed");
        let sui_config = move_vm_config::verifier::VerifierConfig {
            max_generic_instantiation_length: limits.max_generic_instantiation_length,
            max_function_parameters: limits.max_function_parameters,
            max_type_nodes: limits.max_type_nodes,
            max_function_definitions: limits.max_function_definitions,
            max_data_definitions: limits.max_data_definitions,
            max_fields_in_struct: limits.max_fields_in_struct,
            max_variants_in_enum: limits.max_variants_in_enum,
            max_constant_vector_len: limits.max_constant_vector_len,
            max_identifier_len: limits.max_identifier_len,
            disallow_self_identifier: limits.disallow_self_identifier,
            ..move_vm_config::verifier::VerifierConfig::default()
        };
        let _ = DummyMeter; // keep import; not used by limits but keeps the
                            // dev-dep pattern uniform across passes
        let sui_result =
            move_bytecode_verifier::limits::LimitsVerifier::verify_module(&sui_config, &sui_module);
        assert_pass_parity("limits", adamant_result, sui_result);
    }

    #[test]
    fn cross_validation_accepts_empty_module() {
        cross_validate_pass(&empty_module(), &AdamantStructuralLimits::genesis());
    }

    #[test]
    fn cross_validation_rejects_too_many_function_handle_type_parameters() {
        let mut m = empty_module();
        let empty_sig = push_signature(&mut m, vec![]);
        let name = IdentifierIndex(u16::try_from(m.identifiers.len()).unwrap());
        m.identifiers.push(Identifier::new("f").unwrap());
        m.function_handles.push(FunctionHandle {
            module: ModuleHandleIndex(0),
            name,
            parameters: empty_sig,
            return_: empty_sig,
            type_parameters: vec![AbilitySet::EMPTY; 3],
        });
        let limits = limits_with(|l| l.max_generic_instantiation_length = Some(2));
        cross_validate_pass(&m, &limits);
    }

    #[test]
    fn cross_validation_rejects_too_many_parameters() {
        let mut m = empty_module();
        let empty_sig = push_signature(&mut m, vec![]);
        let big_sig = push_signature(
            &mut m,
            vec![SignatureToken::U8, SignatureToken::U8, SignatureToken::U8],
        );
        let name = IdentifierIndex(u16::try_from(m.identifiers.len()).unwrap());
        m.identifiers.push(Identifier::new("f").unwrap());
        m.function_handles.push(FunctionHandle {
            module: ModuleHandleIndex(0),
            name,
            parameters: big_sig,
            return_: empty_sig,
            type_parameters: vec![],
        });
        let limits = limits_with(|l| l.max_function_parameters = Some(2));
        cross_validate_pass(&m, &limits);
    }

    #[test]
    fn cross_validation_rejects_too_long_identifier() {
        let mut m = empty_module();
        m.identifiers.push(Identifier::new("aaaaaaaa").unwrap());
        let limits = limits_with(|l| {
            l.max_identifier_len = Some(4);
            l.disallow_self_identifier = false;
        });
        cross_validate_pass(&m, &limits);
    }

    // `cross_validation_rejects_self_identifier` is omitted
    // by design — Adamant cannot construct an `<SELF>`
    // identifier via the public `Identifier::new` API (the
    // only path), so a parity test against Sui's same check
    // would require `Identifier::new_unchecked` which Adamant
    // intentionally does not provide. See the module-level
    // "`<SELF>` rejection: structural impossibility in
    // Adamant" doc comment.

    #[test]
    fn cross_validation_rejects_vector_constant_above_limit() {
        let mut m = empty_module();
        m.constant_pool.push(Constant {
            type_: SignatureToken::Vector(Box::new(SignatureToken::U8)),
            data: vec![0x05, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE],
        });
        let limits = limits_with(|l| l.max_constant_vector_len = Some(4));
        cross_validate_pass(&m, &limits);
    }
}
