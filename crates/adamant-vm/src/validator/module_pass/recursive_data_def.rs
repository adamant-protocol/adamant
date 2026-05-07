//! Module-level pass: recursive-data-definition cycle
//! detection (whitepaper §6.2.1.8 step 3).
//!
//! Forked from `vendor/move-bytecode-verifier/src/data_defs.rs`
//! at Sui-Move tag `mainnet-v1.66.2` (commit
//! `a9a6825eaf6273cc819ee3bcf65fd4909f7624a9`). See
//! `validator/module_pass/PROVENANCE.md` for the deviation
//! list. Summary:
//!
//! - Operates on [`AdamantCompiledModule`] rather than Sui's
//!   `CompiledModule`. The struct/enum-definition tables and
//!   the field-signature shapes are byte-faithful to upstream
//!   per Phase 5/5b.1b's bytecode-format fork.
//! - Returns typed [`AdamantValidationError::RecursiveDataDefinition`]
//!   rather than upstream's `PartialVMError`/`StatusCode`.
//! - Uses petgraph (`DiGraphMap` + `toposort`) byte-faithfully
//!   from upstream — Adamant's first non-Sui-vendor-derived
//!   production dep on `adamant-vm`. Promoted at B-3.2 start
//!   after MSRV verification (petgraph 0.8.3 documents
//!   `rust-version = "1.64"`; Adamant's pinned channel is
//!   `1.95.0`).
//!
//! Algorithm (byte-faithful from upstream):
//!
//! 1. Build `handle_to_def: BTreeMap<DatatypeHandleIndex, DataIndex>`
//!    mapping each struct/enum's handle to its
//!    `(struct_defs | enum_defs)` position.
//! 2. Walk each struct's fields and each enum-variant's fields,
//!    adding edges from the owning datatype to each
//!    `Datatype` / `DatatypeInstantiation` reference.
//! 3. Run `petgraph::algo::toposort`; `Err(cycle)` ⇒ reject
//!    the offending datatype with
//!    [`AdamantValidationError::RecursiveDataDefinition`].
//!
//! Eager-error: `toposort` returns the first cycle node it
//! encounters; pass reports that node's def as the offender.
//!
//! # Structural-impossibility paths
//!
//! Two upstream paths return `UNKNOWN_INVARIANT_VIOLATION_ERROR`
//! for inputs that should be unreachable in a properly-ordered
//! pipeline:
//!
//! 1. **Duplicate handle-to-def mapping.** Upstream: a struct
//!    or enum handle index maps to two different def positions.
//!    The [`module_pass::duplication_checker`][super::duplication_checker]
//!    pass (Phase 5/5b.3 C-2; `verify_impl` positions 14 and
//!    16) catches this earlier in the pipeline via
//!    `check_struct_definitions` (struct-handle uniqueness)
//!    and `check_enum_definitions` (joint struct/enum handle
//!    uniqueness).
//! 2. **Reference field in a datatype position.** Upstream:
//!    a struct or enum field's signature is a `Reference(_)`
//!    or `MutableReference(_)` token (references are not
//!    permitted as field types). The
//!    [`module_pass::signature_checker`][super::signature_checker]
//!    pass (Phase 5/5b.3 C-3; `verify_impl` positions 3-4
//!    `verify_struct_fields` / `verify_enum_fields`) catches
//!    this earlier via `check_field_signature_token`'s
//!    `RefAsFieldType` rejection.
//!
//! Both are treated as Adamant implementation bugs at this
//! pass's pipeline position — `assert!`/`unreachable!` with
//! structural-impossibility messages naming the
//! upstream-of-this-pass pass that enforces the property.
//! Per the C-4 wiring (Phase 5/5b.3), both `duplication_checker`
//! (alphabetical-before, position 4) and `signature_checker`
//! (precedence-driven, position 10) run before
//! `recursive_data_def` (position 11) in
//! [`super::super::verify_module`]. `signature_checker`'s
//! position is precedence-driven specifically because
//! `recursive_data_def`'s structural argument requires it —
//! pure alphabetical ordering would place `signature_checker`
//! after `recursive_data_def`, which would let a malformed
//! ref-in-field-type module panic `recursive_data_def`
//! instead of producing a typed `InvalidSignatureToken`
//! error. Same shape as B-2.4's deprecated-arms
//! `unreachable!` and B-3.1's `<SELF>` rejection pin —
//! third instance of the structural-impossibility-checks
//! pattern named in B-3.4 PROVENANCE.md batch.

use std::collections::{BTreeMap, BTreeSet};

use adamant_bytecode_format::{
    DatatypeHandleIndex, EnumDefinitionIndex, SignatureToken, StructDefinitionIndex, TableIndex,
};
use petgraph::{algo::toposort, graphmap::DiGraphMap};

use crate::module::AdamantCompiledModule;

use super::super::error::{AdamantValidationError, FieldOwnerKind};

/// Internal graph-node type for the data-definition cycle
/// detector. Keeps struct and enum positions distinct in the
/// graph; converts to `(FieldOwnerKind, TableIndex)` at error-
/// construction time per the B-3.2 plan's Q3 disposition.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash)]
enum DataIndex {
    Struct(TableIndex),
    Enum(TableIndex),
}

impl DataIndex {
    /// Convert this internal graph-node to the external
    /// error-variant shape.
    fn into_error_kind(self) -> (FieldOwnerKind, TableIndex) {
        match self {
            DataIndex::Struct(idx) => (FieldOwnerKind::Struct, idx),
            DataIndex::Enum(idx) => (FieldOwnerKind::Enum, idx),
        }
    }
}

/// Verify that no struct or enum definition transitively
/// references itself through field-signature edges, per
/// §6.2.1.8 step 3 (`module_pass::recursive_data_def`).
pub(in crate::validator) fn verify(
    module: &AdamantCompiledModule,
) -> Result<(), AdamantValidationError> {
    let handle_to_def = build_handle_to_def(module);
    let graph = build_graph(module, &handle_to_def);
    match toposort(&graph, None) {
        Ok(_) => Ok(()),
        Err(cycle) => {
            let (kind, idx) = cycle.node_id().into_error_kind();
            Err(AdamantValidationError::RecursiveDataDefinition { kind, idx })
        }
    }
}

/// Build the mapping from `DatatypeHandleIndex` to its
/// position in `struct_defs` / `enum_defs`. Duplicate handles
/// are a `DuplicationChecker`-pass concern (not yet ported);
/// reaching a duplicate here panics via `expect()` with a
/// structural-impossibility message.
fn build_handle_to_def(module: &AdamantCompiledModule) -> BTreeMap<DatatypeHandleIndex, DataIndex> {
    let mut handle_to_def = BTreeMap::new();
    for (idx, struct_def) in module.struct_defs.iter().enumerate() {
        let table_idx = TableIndex::try_from(idx).expect(
            "struct_defs count exceeds u16; binary format precludes this \
             (TABLE_INDEX_MAX = u16::MAX)",
        );
        let prev = handle_to_def.insert(struct_def.struct_handle, DataIndex::Struct(table_idx));
        assert!(
            prev.is_none(),
            "duplicate struct_handle in handle_to_def map: \
             check_struct_definitions in module_pass::duplication_checker \
             (Phase 5/5b.3 C-2; verify_impl position 14) guarantees \
             uniqueness via first_duplicate_element over struct_defs by \
             struct_handle. A fired assert here indicates duplication_checker \
             is broken or the cross-pass invocation order has been violated \
             — an Adamant implementation bug, not a module-level rejection."
        );
    }
    for (idx, enum_def) in module.enum_defs.iter().enumerate() {
        let table_idx = TableIndex::try_from(idx).expect(
            "enum_defs count exceeds u16; binary format precludes this \
             (TABLE_INDEX_MAX = u16::MAX)",
        );
        let prev = handle_to_def.insert(enum_def.enum_handle, DataIndex::Enum(table_idx));
        assert!(
            prev.is_none(),
            "duplicate enum_handle in handle_to_def map: \
             check_enum_definitions in module_pass::duplication_checker \
             (Phase 5/5b.3 C-2; verify_impl position 16) guarantees \
             uniqueness across struct_defs AND enum_defs jointly via \
             first_duplicate_element by DatatypeHandleIndex. A fired \
             assert here indicates duplication_checker is broken or the \
             cross-pass invocation order has been violated — an Adamant \
             implementation bug, not a module-level rejection."
        );
    }
    handle_to_def
}

/// Build the directed graph of data-definition references.
/// Edge `A → B` means "datatype A has a field whose signature
/// references datatype B".
fn build_graph(
    module: &AdamantCompiledModule,
    handle_to_def: &BTreeMap<DatatypeHandleIndex, DataIndex>,
) -> DiGraphMap<DataIndex, ()> {
    let mut neighbors: BTreeMap<DataIndex, BTreeSet<DataIndex>> = BTreeMap::new();
    for (idx, struct_def) in module.struct_defs.iter().enumerate() {
        let table_idx = TableIndex::try_from(idx)
            .expect("struct_defs count exceeds u16; binary format precludes this");
        let cur = DataIndex::Struct(table_idx);
        if let Some(fields) = struct_def.fields() {
            for field in fields {
                add_signature_token(&mut neighbors, handle_to_def, cur, &field.signature.0);
            }
        }
    }
    for (idx, enum_def) in module.enum_defs.iter().enumerate() {
        let table_idx = TableIndex::try_from(idx)
            .expect("enum_defs count exceeds u16; binary format precludes this");
        let cur = DataIndex::Enum(table_idx);
        for variant in &enum_def.variants {
            for field in &variant.fields {
                add_signature_token(&mut neighbors, handle_to_def, cur, &field.signature.0);
            }
        }
    }

    let edges = neighbors
        .into_iter()
        .flat_map(|(parent, children)| children.into_iter().map(move |child| (parent, child)));
    DiGraphMap::from_edges(edges)
}

/// Walk a [`SignatureToken`] tree, adding edges from `cur`
/// to any datatype reference encountered.
fn add_signature_token(
    neighbors: &mut BTreeMap<DataIndex, BTreeSet<DataIndex>>,
    handle_to_def: &BTreeMap<DatatypeHandleIndex, DataIndex>,
    cur: DataIndex,
    token: &SignatureToken,
) {
    match token {
        SignatureToken::Bool
        | SignatureToken::U8
        | SignatureToken::U16
        | SignatureToken::U32
        | SignatureToken::U64
        | SignatureToken::U128
        | SignatureToken::U256
        | SignatureToken::Address
        | SignatureToken::Signer
        | SignatureToken::TypeParameter(_) => (),
        SignatureToken::Reference(_) | SignatureToken::MutableReference(_) => {
            // Reference fields in datatype positions are a
            // SignatureChecker-pass concern. Per Phase 5/5b.3
            // C-3 + C-4 wiring, signature_checker runs before
            // recursive_data_def in verify_module's step-3
            // batch and rejects RefAsFieldType via
            // check_field_signature_token. Same structural-
            // impossibility pattern as B-2.4 and B-3.1 — see
            // the module-level doc comment.
            unreachable!(
                "reference field in a datatype position: \
                 module_pass::signature_checker (Phase 5/5b.3 C-3; \
                 verify_impl positions 3-4 verify_struct_fields / \
                 verify_enum_fields) rejects refs at struct/enum field \
                 positions via check_field_signature_token. A fired \
                 unreachable here indicates signature_checker is broken \
                 or the cross-pass invocation order has been violated \
                 — an Adamant implementation bug, not a module-level \
                 rejection."
            );
        }
        SignatureToken::Vector(inner) => add_signature_token(neighbors, handle_to_def, cur, inner),
        SignatureToken::Datatype(sh_idx) => {
            if let Some(data_def_idx) = handle_to_def.get(sh_idx) {
                neighbors.entry(cur).or_default().insert(*data_def_idx);
            }
        }
        SignatureToken::DatatypeInstantiation(inst) => {
            let (sh_idx, inners) = &**inst;
            if let Some(data_def_idx) = handle_to_def.get(sh_idx) {
                neighbors.entry(cur).or_default().insert(*data_def_idx);
            }
            for t in inners {
                add_signature_token(neighbors, handle_to_def, cur, t);
            }
        }
    }
}

// `StructDefinitionIndex` and `EnumDefinitionIndex` newtypes
// are not used in the pass's API surface, but the pass
// internally converts via `TableIndex` to/from these
// positions in module tables. Re-export-free; just a marker
// that the imports below are deliberate.
const _: Option<StructDefinitionIndex> = None;
const _: Option<EnumDefinitionIndex> = None;

#[cfg(test)]
mod tests {
    use adamant_bytecode_format::{
        AbilitySet, AddressIdentifierIndex, DatatypeHandle, DatatypeHandleIndex, EnumDefinition,
        FieldDefinition, Identifier, IdentifierIndex, ModuleHandle, ModuleHandleIndex,
        SignatureToken, StructDefinition, StructFieldInformation, TypeSignature, VariantDefinition,
    };
    use adamant_types::Address as AccountAddress;

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

    /// Push an identifier and return its index.
    fn push_identifier(m: &mut AdamantCompiledModule, name: &str) -> IdentifierIndex {
        let idx = IdentifierIndex(u16::try_from(m.identifiers.len()).unwrap());
        m.identifiers.push(Identifier::new(name).unwrap());
        idx
    }

    /// Push a non-generic datatype handle and return its index.
    fn push_datatype_handle(m: &mut AdamantCompiledModule, name: &str) -> DatatypeHandleIndex {
        let name_idx = push_identifier(m, name);
        let idx = DatatypeHandleIndex(u16::try_from(m.datatype_handles.len()).unwrap());
        m.datatype_handles.push(DatatypeHandle {
            module: ModuleHandleIndex(0),
            name: name_idx,
            abilities: AbilitySet::EMPTY,
            type_parameters: vec![],
        });
        idx
    }

    /// Push a struct definition with the given fields.
    fn push_struct_with_fields(
        m: &mut AdamantCompiledModule,
        struct_handle: DatatypeHandleIndex,
        field_signatures: Vec<SignatureToken>,
    ) {
        let f_name = push_identifier(m, "f");
        let fields = field_signatures
            .into_iter()
            .map(|sig| FieldDefinition {
                name: f_name,
                signature: TypeSignature(sig),
            })
            .collect();
        m.struct_defs.push(StructDefinition {
            struct_handle,
            field_information: StructFieldInformation::Declared(fields),
        });
    }

    /// Push an enum definition with one variant carrying the
    /// given fields.
    fn push_enum_with_variant_fields(
        m: &mut AdamantCompiledModule,
        enum_handle: DatatypeHandleIndex,
        variant_field_signatures: Vec<SignatureToken>,
    ) {
        let v_name = push_identifier(m, "V");
        let f_name = push_identifier(m, "f");
        let fields = variant_field_signatures
            .into_iter()
            .map(|sig| FieldDefinition {
                name: f_name,
                signature: TypeSignature(sig),
            })
            .collect();
        m.enum_defs.push(EnumDefinition {
            enum_handle,
            variants: vec![VariantDefinition {
                variant_name: v_name,
                fields,
            }],
        });
    }

    // ============================================================
    // Layer A — positives
    // ============================================================

    #[test]
    fn empty_module_passes() {
        let m = empty_module();
        assert!(verify(&m).is_ok());
    }

    #[test]
    fn non_recursive_struct_with_primitive_fields_passes() {
        let mut m = empty_module();
        let h = push_datatype_handle(&mut m, "S");
        push_struct_with_fields(
            &mut m,
            h,
            vec![SignatureToken::U64, SignatureToken::Address],
        );
        assert!(verify(&m).is_ok());
    }

    #[test]
    fn struct_referencing_other_struct_passes() {
        let mut m = empty_module();
        let h_a = push_datatype_handle(&mut m, "A");
        let h_b = push_datatype_handle(&mut m, "B");
        // A references B; B has only primitives.
        push_struct_with_fields(&mut m, h_a, vec![SignatureToken::Datatype(h_b)]);
        push_struct_with_fields(&mut m, h_b, vec![SignatureToken::U64]);
        assert!(verify(&m).is_ok());
    }

    #[test]
    fn chain_a_to_b_to_c_passes() {
        let mut m = empty_module();
        let h_a = push_datatype_handle(&mut m, "A");
        let h_b = push_datatype_handle(&mut m, "B");
        let h_c = push_datatype_handle(&mut m, "C");
        push_struct_with_fields(&mut m, h_a, vec![SignatureToken::Datatype(h_b)]);
        push_struct_with_fields(&mut m, h_b, vec![SignatureToken::Datatype(h_c)]);
        push_struct_with_fields(&mut m, h_c, vec![SignatureToken::U64]);
        assert!(verify(&m).is_ok());
    }

    #[test]
    fn parallel_disjoint_structs_pass() {
        let mut m = empty_module();
        let h_a = push_datatype_handle(&mut m, "A");
        let h_b = push_datatype_handle(&mut m, "B");
        push_struct_with_fields(&mut m, h_a, vec![SignatureToken::U64]);
        push_struct_with_fields(&mut m, h_b, vec![SignatureToken::Bool]);
        assert!(verify(&m).is_ok());
    }

    // ============================================================
    // Layer A — negatives
    // ============================================================

    #[test]
    fn rejects_self_referencing_struct_with_struct_kind() {
        // S has a field of type S — direct self-reference via
        // Datatype token. Pin: kind: Struct, idx: 0.
        let mut m = empty_module();
        let h = push_datatype_handle(&mut m, "S");
        push_struct_with_fields(&mut m, h, vec![SignatureToken::Datatype(h)]);
        match verify(&m) {
            Err(AdamantValidationError::RecursiveDataDefinition { kind, idx }) => {
                assert_eq!(kind, FieldOwnerKind::Struct);
                assert_eq!(idx, 0);
            }
            other => panic!("expected RecursiveDataDefinition/Struct, got {other:?}"),
        }
    }

    #[test]
    fn rejects_two_struct_cycle() {
        // A → B → A.
        let mut m = empty_module();
        let h_a = push_datatype_handle(&mut m, "A");
        let h_b = push_datatype_handle(&mut m, "B");
        push_struct_with_fields(&mut m, h_a, vec![SignatureToken::Datatype(h_b)]);
        push_struct_with_fields(&mut m, h_b, vec![SignatureToken::Datatype(h_a)]);
        assert!(matches!(
            verify(&m),
            Err(AdamantValidationError::RecursiveDataDefinition { .. })
        ));
    }

    #[test]
    fn rejects_three_struct_cycle() {
        // A → B → C → A.
        let mut m = empty_module();
        let h_a = push_datatype_handle(&mut m, "A");
        let h_b = push_datatype_handle(&mut m, "B");
        let h_c = push_datatype_handle(&mut m, "C");
        push_struct_with_fields(&mut m, h_a, vec![SignatureToken::Datatype(h_b)]);
        push_struct_with_fields(&mut m, h_b, vec![SignatureToken::Datatype(h_c)]);
        push_struct_with_fields(&mut m, h_c, vec![SignatureToken::Datatype(h_a)]);
        assert!(matches!(
            verify(&m),
            Err(AdamantValidationError::RecursiveDataDefinition { .. })
        ));
    }

    #[test]
    fn rejects_struct_via_vector_cycle() {
        // S has a Vec<S> field — self-reference through
        // Vector wrapper.
        let mut m = empty_module();
        let h = push_datatype_handle(&mut m, "S");
        push_struct_with_fields(
            &mut m,
            h,
            vec![SignatureToken::Vector(Box::new(SignatureToken::Datatype(
                h,
            )))],
        );
        assert!(matches!(
            verify(&m),
            Err(AdamantValidationError::RecursiveDataDefinition { .. })
        ));
    }

    #[test]
    fn rejects_self_referencing_enum_variant_with_enum_kind() {
        // E has variant V(E) — direct self-reference via
        // Datatype token. Pin: kind: Enum, idx: 0.
        let mut m = empty_module();
        let h = push_datatype_handle(&mut m, "E");
        push_enum_with_variant_fields(&mut m, h, vec![SignatureToken::Datatype(h)]);
        match verify(&m) {
            Err(AdamantValidationError::RecursiveDataDefinition { kind, idx }) => {
                assert_eq!(kind, FieldOwnerKind::Enum);
                assert_eq!(idx, 0);
            }
            other => panic!("expected RecursiveDataDefinition/Enum, got {other:?}"),
        }
    }

    #[test]
    fn rejects_struct_to_enum_to_struct_cycle() {
        // S → E → S (mixed struct/enum cycle).
        let mut m = empty_module();
        let h_s = push_datatype_handle(&mut m, "S");
        let h_e = push_datatype_handle(&mut m, "E");
        push_struct_with_fields(&mut m, h_s, vec![SignatureToken::Datatype(h_e)]);
        push_enum_with_variant_fields(&mut m, h_e, vec![SignatureToken::Datatype(h_s)]);
        assert!(matches!(
            verify(&m),
            Err(AdamantValidationError::RecursiveDataDefinition { .. })
        ));
    }

    // ============================================================
    // Layer B — cross-validation against vendored Sui
    // ============================================================

    fn cross_validate_pass(m: &AdamantCompiledModule) {
        let adamant_result = verify(m);
        let sui_module = m
            .to_sui_module()
            .expect("test fixture has no Adamant extensions; to_sui_module must succeed");
        let sui_result =
            move_bytecode_verifier::data_defs::RecursiveDataDefChecker::verify_module(&sui_module);
        assert_pass_parity("recursive_data_def", adamant_result, sui_result);
    }

    #[test]
    fn cross_validation_accepts_empty_module() {
        cross_validate_pass(&empty_module());
    }

    #[test]
    fn cross_validation_accepts_non_recursive_struct() {
        let mut m = empty_module();
        let h = push_datatype_handle(&mut m, "S");
        push_struct_with_fields(&mut m, h, vec![SignatureToken::U64]);
        cross_validate_pass(&m);
    }

    #[test]
    fn cross_validation_accepts_chain_no_cycle() {
        let mut m = empty_module();
        let h_a = push_datatype_handle(&mut m, "A");
        let h_b = push_datatype_handle(&mut m, "B");
        push_struct_with_fields(&mut m, h_a, vec![SignatureToken::Datatype(h_b)]);
        push_struct_with_fields(&mut m, h_b, vec![SignatureToken::U64]);
        cross_validate_pass(&m);
    }

    #[test]
    fn cross_validation_rejects_self_referencing_struct() {
        let mut m = empty_module();
        let h = push_datatype_handle(&mut m, "S");
        push_struct_with_fields(&mut m, h, vec![SignatureToken::Datatype(h)]);
        cross_validate_pass(&m);
    }

    #[test]
    fn cross_validation_rejects_two_struct_cycle() {
        let mut m = empty_module();
        let h_a = push_datatype_handle(&mut m, "A");
        let h_b = push_datatype_handle(&mut m, "B");
        push_struct_with_fields(&mut m, h_a, vec![SignatureToken::Datatype(h_b)]);
        push_struct_with_fields(&mut m, h_b, vec![SignatureToken::Datatype(h_a)]);
        cross_validate_pass(&m);
    }

    #[test]
    fn cross_validation_rejects_self_referencing_enum_variant() {
        let mut m = empty_module();
        let h = push_datatype_handle(&mut m, "E");
        push_enum_with_variant_fields(&mut m, h, vec![SignatureToken::Datatype(h)]);
        cross_validate_pass(&m);
    }
}
