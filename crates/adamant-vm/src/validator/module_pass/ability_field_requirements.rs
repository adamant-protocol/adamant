//! Module-level pass: struct/enum-field ability requirements
//! (whitepaper §6.2.1.8 step 3).
//!
//! Forked from
//! `vendor/move-bytecode-verifier/src/ability_field_requirements.rs`
//! at Sui-Move tag `mainnet-v1.66.2` (commit
//! `a9a6825eaf6273cc819ee3bcf65fd4909f7624a9`). See
//! `validator/module_pass/PROVENANCE.md` for the deviation
//! list. Summary:
//!
//! - Operates on [`AdamantCompiledModule`] rather than Sui's
//!   `CompiledModule`. The struct/enum-definition tables are
//!   byte-identical between the two per Phase 5/5b.1b's
//!   bytecode-format fork.
//! - Returns typed [`AdamantValidationError::FieldMissingTypeAbility`]
//!   rather than upstream's `PartialVMError`/`StatusCode`.
//! - Drops the `Meter`/`Scope` parameters that Sui plumbs
//!   through `AbilityCache::abilities`. The Adamant cache
//!   (Phase 5/5b.2 B-1) doesn't carry metering surface;
//!   gas accounting per §6.3 applies at runtime, not at
//!   deploy-time verification.
//!
//! For each owning datatype (struct or enum):
//!
//! 1. Compute the required ability set: union of
//!    [`Ability::requires`] over each ability declared on the
//!    type's [`DatatypeHandle`]. Examples: `key.requires() ==
//!    store`, `copy.requires() == copy`,
//!    `drop.requires() == drop`, `store.requires() == store`.
//!    A type with `key + copy` requires `store + copy` on
//!    every field.
//! 2. Compute per-type-parameter ability assumptions: assume
//!    [`AbilitySet::ALL`] for every type parameter (the
//!    type's effective abilities depend on what's plugged in,
//!    so we conservatively assume the strongest set; the
//!    actual abilities are then determined polymorphically at
//!    instantiation sites by `polymorphic_abilities`).
//! 3. For each field (across every variant for enums),
//!    resolve its signature token's effective ability set via
//!    [`AdamantAbilityCache::abilities`] and check that the
//!    required-ability set is a subset.
//!
//! Eager-error: first violation across the
//! `(struct → field)` ∪ `(enum → variant → field)`
//! traversal wins, in the order
//! `struct_defs[0..]` then `enum_defs[0..]`.
//!
//! # Cache-error handling
//!
//! [`AdamantAbilityCache::abilities`] can return an
//! [`AbilityCacheError`] on type-parameter-index out-of-range
//! or polymorphic-ability rejection. **Both are structurally
//! impossible at this pipeline position.** Per §6.2.1.8 step
//! 3 the bounds-checker pass (Phase 5/5b.2 B-3) runs before
//! `ability_field_requirements`; the bounds checker validates
//! that type-parameter indices fit within their handles'
//! declared counts and that generic instantiation arities
//! match. A cache error reaching this pass means the bounds
//! checker is broken or the pipeline ordering has been
//! violated — an Adamant implementation bug, not a module-
//! level rejection. The pass therefore panics via
//! [`Result::expect`] with a structural-impossibility
//! message rather than propagating a typed validation
//! variant. Consistent with CLAUDE.md's "no `unwrap()`
//! outside tests; use `expect()` with a helpful message"
//! discipline applied to structural impossibilities.
//!
//! # Dead-code allow (transient)
//!
//! Phase 5/5b.2 B-5 wires this pass into
//! [`crate::validator::verify_module`]. Until B-5 lands,
//! the pass is reachable only from inline tests and Layer B
//! cross-validation; the lib build sees the entry point as
//! dead. The module-level `dead_code` allow is removed when
//! B-5 wires the pass.

#![allow(dead_code, reason = "wired into verify_module() in Phase 5/5b.2 B-5")]

use adamant_bytecode_format::{AbilitySet, StructFieldInformation, TableIndex};

use crate::module::AdamantCompiledModule;

use super::super::error::{AdamantValidationError, FieldOwnerKind};
use super::ability_cache::AdamantAbilityCache;

/// Verify the module's struct/enum field-ability requirements
/// against §6.2.1.8 step 3
/// (`module_pass::ability_field_requirements`).
///
/// Eager-error semantics: returns the first violation
/// encountered, scanning structs in `struct_defs` order then
/// enums in `enum_defs` order.
pub(in crate::validator) fn verify(
    module: &AdamantCompiledModule,
) -> Result<(), AdamantValidationError> {
    let mut cache = AdamantAbilityCache::new(module);

    for (idx, struct_def) in module.struct_defs.iter().enumerate() {
        let datatype_handle = &module.datatype_handles[struct_def.struct_handle.0 as usize];
        let fields = match &struct_def.field_information {
            StructFieldInformation::Native => continue,
            StructFieldInformation::Declared(fields) => fields,
        };

        let required_abilities = required_abilities_of(datatype_handle.abilities);
        let type_parameter_abilities: Vec<AbilitySet> = datatype_handle
            .type_parameters
            .iter()
            .map(|_| AbilitySet::ALL)
            .collect();

        for (field_idx, field) in fields.iter().enumerate() {
            let field_abilities = cache
                .abilities(&type_parameter_abilities, &field.signature.0)
                .expect(
                    "ability cache invariant violated in \
                     ability_field_requirements: either the bounds \
                     checker pass is broken or the pipeline ordering \
                     is wrong (bounds checker must run before this \
                     pass per §6.2.1.8 step 3 ordering). This is an \
                     Adamant implementation bug, not a module-level \
                     rejection.",
                );
            if !required_abilities.is_subset(field_abilities) {
                return Err(AdamantValidationError::FieldMissingTypeAbility {
                    def_idx: TableIndex::try_from(idx).expect(
                        "struct_defs count exceeds u16; binary format precludes this \
                             (TABLE_INDEX_MAX = u16::MAX)",
                    ),
                    kind: FieldOwnerKind::Struct,
                    variant_idx: None,
                    field_idx: TableIndex::try_from(field_idx)
                        .expect("struct field count exceeds u16; FIELD_COUNT_MAX precludes this"),
                });
            }
        }
    }

    for (idx, enum_def) in module.enum_defs.iter().enumerate() {
        let datatype_handle = &module.datatype_handles[enum_def.enum_handle.0 as usize];
        let required_abilities = required_abilities_of(datatype_handle.abilities);
        let type_parameter_abilities: Vec<AbilitySet> = datatype_handle
            .type_parameters
            .iter()
            .map(|_| AbilitySet::ALL)
            .collect();

        for (variant_idx, variant) in enum_def.variants.iter().enumerate() {
            for (field_idx, field) in variant.fields.iter().enumerate() {
                let field_abilities = cache
                    .abilities(&type_parameter_abilities, &field.signature.0)
                    .expect(
                        "ability cache invariant violated in \
                         ability_field_requirements: either the bounds \
                         checker pass is broken or the pipeline ordering \
                         is wrong (bounds checker must run before this \
                         pass per §6.2.1.8 step 3 ordering). This is an \
                         Adamant implementation bug, not a module-level \
                         rejection.",
                    );
                if !required_abilities.is_subset(field_abilities) {
                    return Err(AdamantValidationError::FieldMissingTypeAbility {
                        def_idx: TableIndex::try_from(idx)
                            .expect("enum_defs count exceeds u16; binary format precludes this"),
                        kind: FieldOwnerKind::Enum,
                        variant_idx: Some(TableIndex::try_from(variant_idx).expect(
                            "enum variant count exceeds u16; VARIANT_COUNT_MAX precludes this",
                        )),
                        field_idx: TableIndex::try_from(field_idx).expect(
                            "enum-variant field count exceeds u16; FIELD_COUNT_MAX precludes this",
                        ),
                    });
                }
            }
        }
    }

    Ok(())
}

/// Compute the required ability set for a datatype with the
/// given declared abilities. Per Move's ability calculus:
///
/// - `Copy.requires() == Copy`
/// - `Drop.requires() == Drop`
/// - `Store.requires() == Store`
/// - `Key.requires() == Store`
///
/// Required abilities is the union over `requires()` of every
/// declared ability.
fn required_abilities_of(declared: AbilitySet) -> AbilitySet {
    declared
        .into_iter()
        .map(adamant_bytecode_format::Ability::requires)
        .fold(AbilitySet::EMPTY, |acc, required| acc | required)
}

#[cfg(test)]
mod tests {
    use adamant_bytecode_format::{
        Ability, AbilitySet, AddressIdentifierIndex, DatatypeHandle, DatatypeHandleIndex,
        DatatypeTyParameter, EnumDefinition, FieldDefinition, Identifier, IdentifierIndex,
        ModuleHandle, ModuleHandleIndex, SignatureToken, StructDefinition, StructFieldInformation,
        TypeSignature, VariantDefinition,
    };
    use adamant_types::Address as AccountAddress;
    use move_bytecode_verifier_meter::dummy::DummyMeter;

    use crate::module::AdamantCompiledModule;

    use super::super::super::error::{AdamantValidationError, FieldOwnerKind};
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

    /// Append an `Identifier` to the module's pool and return its index.
    fn push_identifier(m: &mut AdamantCompiledModule, name: &str) -> IdentifierIndex {
        let idx = IdentifierIndex(u16::try_from(m.identifiers.len()).unwrap());
        m.identifiers.push(Identifier::new(name).unwrap());
        idx
    }

    /// Append a `DatatypeHandle` (no type parameters) and return its index.
    fn push_datatype_handle(
        m: &mut AdamantCompiledModule,
        name: &str,
        abilities: AbilitySet,
    ) -> DatatypeHandleIndex {
        let name_idx = push_identifier(m, name);
        let idx = DatatypeHandleIndex(u16::try_from(m.datatype_handles.len()).unwrap());
        m.datatype_handles.push(DatatypeHandle {
            module: ModuleHandleIndex(0),
            name: name_idx,
            abilities,
            type_parameters: vec![],
        });
        idx
    }

    /// Append a `DatatypeHandle` with a single type parameter
    /// (non-phantom, no constraints) and return its index.
    fn push_generic_datatype_handle(
        m: &mut AdamantCompiledModule,
        name: &str,
        abilities: AbilitySet,
    ) -> DatatypeHandleIndex {
        let name_idx = push_identifier(m, name);
        let idx = DatatypeHandleIndex(u16::try_from(m.datatype_handles.len()).unwrap());
        m.datatype_handles.push(DatatypeHandle {
            module: ModuleHandleIndex(0),
            name: name_idx,
            abilities,
            type_parameters: vec![DatatypeTyParameter {
                constraints: AbilitySet::EMPTY,
                is_phantom: false,
            }],
        });
        idx
    }

    /// Construct a `Field` whose name is `field_name` and
    /// whose signature is `ty`.
    fn field(name_idx: IdentifierIndex, ty: SignatureToken) -> FieldDefinition {
        FieldDefinition {
            name: name_idx,
            signature: TypeSignature(ty),
        }
    }

    // --- Layer A: struct positives ---

    #[test]
    fn struct_with_no_abilities_and_no_fields_passes() {
        let mut m = empty_module();
        let h = push_datatype_handle(&mut m, "S", AbilitySet::EMPTY);
        m.struct_defs.push(StructDefinition {
            struct_handle: h,
            field_information: StructFieldInformation::Declared(vec![]),
        });
        assert!(verify(&m).is_ok());
    }

    #[test]
    fn struct_with_no_abilities_and_field_passes() {
        // No abilities → no requirements; any field passes.
        let mut m = empty_module();
        let h = push_datatype_handle(&mut m, "S", AbilitySet::EMPTY);
        let f = push_identifier(&mut m, "f");
        m.struct_defs.push(StructDefinition {
            struct_handle: h,
            field_information: StructFieldInformation::Declared(vec![field(
                f,
                SignatureToken::Signer,
            )]),
        });
        assert!(verify(&m).is_ok());
    }

    #[test]
    fn struct_with_copy_drop_abilities_and_primitive_fields_passes() {
        // `copy + drop` requires `copy + drop`; primitives have
        // `copy + drop + store` so they satisfy.
        let mut m = empty_module();
        let h = push_datatype_handle(
            &mut m,
            "S",
            AbilitySet::EMPTY | Ability::Copy | Ability::Drop,
        );
        let f = push_identifier(&mut m, "f");
        m.struct_defs.push(StructDefinition {
            struct_handle: h,
            field_information: StructFieldInformation::Declared(vec![field(
                f,
                SignatureToken::U64,
            )]),
        });
        assert!(verify(&m).is_ok());
    }

    #[test]
    fn struct_with_key_ability_and_store_field_passes() {
        // `key.requires() == store`; primitives have `store`, so
        // any primitive field satisfies a `key` struct's
        // requirement.
        let mut m = empty_module();
        let h = push_datatype_handle(&mut m, "S", AbilitySet::EMPTY | Ability::Key);
        let f = push_identifier(&mut m, "f");
        m.struct_defs.push(StructDefinition {
            struct_handle: h,
            field_information: StructFieldInformation::Declared(vec![field(
                f,
                SignatureToken::Address,
            )]),
        });
        assert!(verify(&m).is_ok());
    }

    #[test]
    fn native_struct_skipped() {
        // Native struct: no field check. `key` ability with no
        // declared fields is vacuously fine for this pass.
        let mut m = empty_module();
        let h = push_datatype_handle(&mut m, "S", AbilitySet::EMPTY | Ability::Key);
        m.struct_defs.push(StructDefinition {
            struct_handle: h,
            field_information: StructFieldInformation::Native,
        });
        assert!(verify(&m).is_ok());
    }

    // --- Layer A: struct negatives ---

    #[test]
    fn rejects_struct_with_copy_ability_and_signer_field() {
        // `copy.requires() == copy`; Signer has `drop` only
        // (no copy), so it fails.
        let mut m = empty_module();
        let h = push_datatype_handle(&mut m, "S", AbilitySet::EMPTY | Ability::Copy);
        let f = push_identifier(&mut m, "f");
        m.struct_defs.push(StructDefinition {
            struct_handle: h,
            field_information: StructFieldInformation::Declared(vec![field(
                f,
                SignatureToken::Signer,
            )]),
        });
        match verify(&m) {
            Err(AdamantValidationError::FieldMissingTypeAbility {
                def_idx: 0,
                kind: FieldOwnerKind::Struct,
                variant_idx: None,
                field_idx: 0,
            }) => {}
            other => {
                panic!("expected FieldMissingTypeAbility(Struct, def 0 field 0), got {other:?}")
            }
        }
    }

    #[test]
    fn rejects_struct_with_drop_ability_and_signer_field_violating_copy_implication() {
        // Edge case: Signer carries `drop` only, no `copy/store/key`.
        // `drop` requirement on a Signer field passes; but if the
        // struct has `copy`, it fails. Tests negative path.
        let mut m = empty_module();
        let h = push_datatype_handle(&mut m, "S", AbilitySet::EMPTY | Ability::Copy);
        let f = push_identifier(&mut m, "f");
        m.struct_defs.push(StructDefinition {
            struct_handle: h,
            field_information: StructFieldInformation::Declared(vec![field(
                f,
                SignatureToken::Signer,
            )]),
        });
        assert!(matches!(
            verify(&m),
            Err(AdamantValidationError::FieldMissingTypeAbility { .. })
        ));
    }

    #[test]
    fn rejects_struct_field_idx_reports_first_offender() {
        // First field passes (primitive), second fails (Signer
        // under copy requirement). field_idx == 1.
        let mut m = empty_module();
        let h = push_datatype_handle(&mut m, "S", AbilitySet::EMPTY | Ability::Copy);
        let f0 = push_identifier(&mut m, "f0");
        let f1 = push_identifier(&mut m, "f1");
        m.struct_defs.push(StructDefinition {
            struct_handle: h,
            field_information: StructFieldInformation::Declared(vec![
                field(f0, SignatureToken::U64),
                field(f1, SignatureToken::Signer),
            ]),
        });
        match verify(&m) {
            Err(AdamantValidationError::FieldMissingTypeAbility {
                def_idx: 0,
                kind: FieldOwnerKind::Struct,
                variant_idx: None,
                field_idx: 1,
            }) => {}
            other => panic!("expected field_idx 1, got {other:?}"),
        }
    }

    #[test]
    fn rejects_first_struct_when_multiple_have_violations() {
        // Two structs both fail the requirement; eager-error
        // reports struct 0.
        let mut m = empty_module();
        let h0 = push_datatype_handle(&mut m, "S0", AbilitySet::EMPTY | Ability::Copy);
        let h1 = push_datatype_handle(&mut m, "S1", AbilitySet::EMPTY | Ability::Copy);
        let f0 = push_identifier(&mut m, "f0");
        let f1 = push_identifier(&mut m, "f1");
        m.struct_defs.push(StructDefinition {
            struct_handle: h0,
            field_information: StructFieldInformation::Declared(vec![field(
                f0,
                SignatureToken::Signer,
            )]),
        });
        m.struct_defs.push(StructDefinition {
            struct_handle: h1,
            field_information: StructFieldInformation::Declared(vec![field(
                f1,
                SignatureToken::Signer,
            )]),
        });
        match verify(&m) {
            Err(AdamantValidationError::FieldMissingTypeAbility { def_idx: 0, .. }) => {}
            other => panic!("expected def_idx 0, got {other:?}"),
        }
    }

    #[test]
    fn struct_with_phantom_type_param_does_not_consult_param_for_field_ability() {
        // The pass assumes AbilitySet::ALL for every type
        // parameter (matches upstream). With AbilitySet::ALL,
        // a TypeParameter field token resolves to ALL, so even
        // a `key` struct with a `TypeParameter(0)` field
        // satisfies the requirement at this pass — phantom-ness
        // and per-instantiation validation are downstream
        // concerns. This test pins that assumption.
        let mut m = empty_module();
        let h = push_generic_datatype_handle(&mut m, "S", AbilitySet::EMPTY | Ability::Key);
        let f = push_identifier(&mut m, "f");
        m.struct_defs.push(StructDefinition {
            struct_handle: h,
            field_information: StructFieldInformation::Declared(vec![field(
                f,
                SignatureToken::TypeParameter(0),
            )]),
        });
        assert!(verify(&m).is_ok());
    }

    // --- Layer A: enum positives + negatives ---

    #[test]
    fn enum_with_no_abilities_and_empty_variants_passes() {
        let mut m = empty_module();
        let h = push_datatype_handle(&mut m, "E", AbilitySet::EMPTY);
        m.enum_defs.push(EnumDefinition {
            enum_handle: h,
            variants: vec![],
        });
        assert!(verify(&m).is_ok());
    }

    #[test]
    fn enum_with_copy_ability_and_primitive_field_passes() {
        let mut m = empty_module();
        let h = push_datatype_handle(&mut m, "E", AbilitySet::EMPTY | Ability::Copy);
        let v = push_identifier(&mut m, "V");
        let f = push_identifier(&mut m, "f");
        m.enum_defs.push(EnumDefinition {
            enum_handle: h,
            variants: vec![VariantDefinition {
                variant_name: v,
                fields: vec![field(f, SignatureToken::U64)],
            }],
        });
        assert!(verify(&m).is_ok());
    }

    #[test]
    fn rejects_enum_variant_field_with_missing_ability() {
        let mut m = empty_module();
        let h = push_datatype_handle(&mut m, "E", AbilitySet::EMPTY | Ability::Copy);
        let v = push_identifier(&mut m, "V");
        let f = push_identifier(&mut m, "f");
        m.enum_defs.push(EnumDefinition {
            enum_handle: h,
            variants: vec![VariantDefinition {
                variant_name: v,
                fields: vec![field(f, SignatureToken::Signer)],
            }],
        });
        match verify(&m) {
            Err(AdamantValidationError::FieldMissingTypeAbility {
                def_idx: 0,
                kind: FieldOwnerKind::Enum,
                variant_idx: Some(0),
                field_idx: 0,
            }) => {}
            other => {
                panic!("expected FieldMissingTypeAbility(Enum, def 0 var 0 field 0), got {other:?}")
            }
        }
    }

    #[test]
    fn rejects_second_variant_field_when_first_variant_passes() {
        // Variant 0: U64 (passes copy). Variant 1: Signer (fails).
        // Eager-error reports variant 1, field 0.
        let mut m = empty_module();
        let h = push_datatype_handle(&mut m, "E", AbilitySet::EMPTY | Ability::Copy);
        let v0 = push_identifier(&mut m, "V0");
        let v1 = push_identifier(&mut m, "V1");
        let f0 = push_identifier(&mut m, "f0");
        let f1 = push_identifier(&mut m, "f1");
        m.enum_defs.push(EnumDefinition {
            enum_handle: h,
            variants: vec![
                VariantDefinition {
                    variant_name: v0,
                    fields: vec![field(f0, SignatureToken::U64)],
                },
                VariantDefinition {
                    variant_name: v1,
                    fields: vec![field(f1, SignatureToken::Signer)],
                },
            ],
        });
        match verify(&m) {
            Err(AdamantValidationError::FieldMissingTypeAbility {
                def_idx: 0,
                kind: FieldOwnerKind::Enum,
                variant_idx: Some(1),
                field_idx: 0,
            }) => {}
            other => panic!("expected enum variant 1 field 0, got {other:?}"),
        }
    }

    // --- Layer A: eager-error precedence between structs and enums ---

    #[test]
    fn struct_violation_wins_over_enum_violation_eager_error() {
        // Both struct[0] and enum[0] have violations; the
        // pass scans structs first, so the struct violation
        // is reported.
        let mut m = empty_module();
        let h0 = push_datatype_handle(&mut m, "S", AbilitySet::EMPTY | Ability::Copy);
        let h1 = push_datatype_handle(&mut m, "E", AbilitySet::EMPTY | Ability::Copy);
        let fs = push_identifier(&mut m, "fs");
        let ve = push_identifier(&mut m, "Ve");
        let fe = push_identifier(&mut m, "fe");
        m.struct_defs.push(StructDefinition {
            struct_handle: h0,
            field_information: StructFieldInformation::Declared(vec![field(
                fs,
                SignatureToken::Signer,
            )]),
        });
        m.enum_defs.push(EnumDefinition {
            enum_handle: h1,
            variants: vec![VariantDefinition {
                variant_name: ve,
                fields: vec![field(fe, SignatureToken::Signer)],
            }],
        });
        match verify(&m) {
            Err(AdamantValidationError::FieldMissingTypeAbility {
                kind: FieldOwnerKind::Struct,
                ..
            }) => {}
            other => panic!("expected Struct violation, got {other:?}"),
        }
    }

    // --- Layer B: cross-validation against vendored Sui ---

    fn cross_validate_pass(m: &AdamantCompiledModule) {
        let adamant_result = verify(m);
        let sui_module = m
            .to_sui_module()
            .expect("test fixture has no Adamant extensions; to_sui_module must succeed");
        let mut sui_cache = move_bytecode_verifier::ability_cache::AbilityCache::new(&sui_module);
        let mut meter = DummyMeter;
        let sui_result = move_bytecode_verifier::ability_field_requirements::verify_module(
            &sui_module,
            &mut sui_cache,
            &mut meter,
        );
        assert_pass_parity("ability_field_requirements", adamant_result, sui_result);
    }

    #[test]
    fn cross_validation_accepts_struct_with_no_abilities() {
        let mut m = empty_module();
        let h = push_datatype_handle(&mut m, "S", AbilitySet::EMPTY);
        let f = push_identifier(&mut m, "f");
        m.struct_defs.push(StructDefinition {
            struct_handle: h,
            field_information: StructFieldInformation::Declared(vec![field(
                f,
                SignatureToken::Signer,
            )]),
        });
        cross_validate_pass(&m);
    }

    #[test]
    fn cross_validation_accepts_struct_with_copy_drop_and_primitive() {
        let mut m = empty_module();
        let h = push_datatype_handle(
            &mut m,
            "S",
            AbilitySet::EMPTY | Ability::Copy | Ability::Drop,
        );
        let f = push_identifier(&mut m, "f");
        m.struct_defs.push(StructDefinition {
            struct_handle: h,
            field_information: StructFieldInformation::Declared(vec![field(
                f,
                SignatureToken::U64,
            )]),
        });
        cross_validate_pass(&m);
    }

    #[test]
    fn cross_validation_accepts_struct_with_key_and_address() {
        let mut m = empty_module();
        let h = push_datatype_handle(&mut m, "S", AbilitySet::EMPTY | Ability::Key);
        let f = push_identifier(&mut m, "f");
        m.struct_defs.push(StructDefinition {
            struct_handle: h,
            field_information: StructFieldInformation::Declared(vec![field(
                f,
                SignatureToken::Address,
            )]),
        });
        cross_validate_pass(&m);
    }

    #[test]
    fn cross_validation_accepts_native_struct() {
        let mut m = empty_module();
        let h = push_datatype_handle(&mut m, "S", AbilitySet::EMPTY | Ability::Key);
        m.struct_defs.push(StructDefinition {
            struct_handle: h,
            field_information: StructFieldInformation::Native,
        });
        cross_validate_pass(&m);
    }

    #[test]
    fn cross_validation_rejects_struct_copy_with_signer_field() {
        let mut m = empty_module();
        let h = push_datatype_handle(&mut m, "S", AbilitySet::EMPTY | Ability::Copy);
        let f = push_identifier(&mut m, "f");
        m.struct_defs.push(StructDefinition {
            struct_handle: h,
            field_information: StructFieldInformation::Declared(vec![field(
                f,
                SignatureToken::Signer,
            )]),
        });
        cross_validate_pass(&m);
    }

    #[test]
    fn cross_validation_rejects_enum_copy_with_signer_variant_field() {
        let mut m = empty_module();
        let h = push_datatype_handle(&mut m, "E", AbilitySet::EMPTY | Ability::Copy);
        let v = push_identifier(&mut m, "V");
        let f = push_identifier(&mut m, "f");
        m.enum_defs.push(EnumDefinition {
            enum_handle: h,
            variants: vec![VariantDefinition {
                variant_name: v,
                fields: vec![field(f, SignatureToken::Signer)],
            }],
        });
        cross_validate_pass(&m);
    }

    #[test]
    fn cross_validation_accepts_enum_with_copy_and_primitive() {
        let mut m = empty_module();
        let h = push_datatype_handle(&mut m, "E", AbilitySet::EMPTY | Ability::Copy);
        let v = push_identifier(&mut m, "V");
        let f = push_identifier(&mut m, "f");
        m.enum_defs.push(EnumDefinition {
            enum_handle: h,
            variants: vec![VariantDefinition {
                variant_name: v,
                fields: vec![field(f, SignatureToken::U64)],
            }],
        });
        cross_validate_pass(&m);
    }
}
