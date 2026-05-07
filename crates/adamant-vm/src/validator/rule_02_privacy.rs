//! Validator Rule 2 (whitepaper §6.2.1.6 #2):
//! privacy annotation required on public functions.
//!
//! Every `Visibility::Public` function must appear in the
//! module's `b"adamant.privacy"` metadata entry, whose value
//! is the BCS encoding of `Vec<(FunctionDefinitionIndex, u8)>`
//! per §6.2.1.3. Modules with at least one Public function
//! but no privacy entry are rejected; modules with multiple
//! privacy entries are rejected; modules whose privacy entry
//! has malformed BCS payload are rejected; modules where any
//! Public function lacks a covering entry are rejected.
//!
//! # Walk-backs (locked at B-4 plan approval)
//!
//! ## Q3: visibility coverage is Public-only
//!
//! Per §6.2.1.3 line 387 + §6.2.1.6 Rule 2, only
//! `Visibility::Public` functions are required to have a
//! privacy annotation. `Visibility::Friend` and
//! `Visibility::Private` functions MAY appear in the table
//! (the structural pass at
//! [`super::module_pass::privacy_metadata_structure`]
//! validates byte/index/duplicate well-formedness for any
//! entry that does appear), but they are NOT required to
//! appear. The original B-2-plan-time approval that included
//! Friend was an extrapolation, not a spec claim.
//!
//! Three Layer A behavioral lock fixtures pin the Q3 meaning
//! under realistic conditions:
//!
//! - Friend functions only — no privacy entry needed
//! - Friend + Public functions; Public annotated, Friend
//!   not in table — accepts
//! - Public + Private functions; Public annotated, Private
//!   not in table — accepts
//!
//! ## Q4: cardinality option (b)
//!
//! - **Zero entries:** allowed iff no Public function exists.
//! - **One entry:** standard case; validate coverage.
//! - **Two or more entries:** rejected as
//!   `MultiplePrivacyMetadata`.
//!
//! Combined with Q3: cardinality gates on Public functions
//! only. A module with only Friend or Private can omit the
//! privacy entry entirely.
//!
//! # Two-pass split per §6.2.1.8
//!
//! This file is the step-5 Adamant-rule pass: cardinality +
//! BCS decode + Public-coverage check. The step-3 module-
//! level pass at
//! [`super::module_pass::privacy_metadata_structure`] handles
//! per-entry structural well-formedness (byte values in
//! `{0x00, 0x01}`, function indices in range, no duplicate
//! indices). [`MalformedPrivacyMetadata`] is shared between
//! the two passes per the pipeline-ordering-eager-error
//! sub-pattern of byte-faithful preservation; pipeline
//! ordering means the structural pass typically wins.
//!
//! [`MalformedPrivacyMetadata`]: super::error::AdamantValidationError::MalformedPrivacyMetadata
//!
//! # Dead-code allow (transient)
//!
//! Phase 5/5b.2 B-5 wires this rule into
//! [`crate::validator::verify_module`] in the step-5 batch
//! after Rule 1 and before Rule 4. Until B-5 lands, the
//! rule is reachable only from inline tests; the lib build
//! sees the entry point as dead. The module-level
//! `dead_code` allow is removed when B-5 wires the rule.

#![allow(dead_code, reason = "wired into verify_module() in Phase 5/5b.2 B-5")]

use adamant_bytecode_format::{FunctionDefinitionIndex, TableIndex, Visibility};

use crate::module::AdamantCompiledModule;

use super::error::AdamantValidationError;

/// Per whitepaper §6.2.1.3, the metadata key under which the
/// privacy annotation table is BCS-encoded.
const PRIVACY_METADATA_KEY: &[u8] = b"adamant.privacy";

/// Verify §6.2.1.6 Rule 2 against `module`.
pub(super) fn verify(module: &AdamantCompiledModule) -> Result<(), AdamantValidationError> {
    let entries: Vec<&adamant_bytecode_format::Metadata> = module
        .metadata
        .iter()
        .filter(|m| m.key == PRIVACY_METADATA_KEY)
        .collect();

    let public_function_indices = collect_public_function_indices(module);

    match entries.len() {
        0 => {
            // Zero entries: allowed iff no Public function.
            if public_function_indices.is_empty() {
                Ok(())
            } else {
                Err(AdamantValidationError::MissingPrivacyMetadata)
            }
        }
        1 => {
            // One entry: validate coverage.
            let payload: Vec<(FunctionDefinitionIndex, u8)> = bcs::from_bytes(&entries[0].value)
                .map_err(|e| AdamantValidationError::MalformedPrivacyMetadata {
                    bcs_error: format!("{e}"),
                })?;
            let covered: std::collections::HashSet<FunctionDefinitionIndex> =
                payload.into_iter().map(|(idx, _)| idx).collect();
            for public_idx in public_function_indices {
                if !covered.contains(&public_idx) {
                    return Err(AdamantValidationError::MissingPrivacyAnnotation {
                        function_index: public_idx,
                    });
                }
            }
            Ok(())
        }
        n => Err(AdamantValidationError::MultiplePrivacyMetadata { count: n }),
    }
}

/// Collect the [`FunctionDefinitionIndex`] of every
/// `Visibility::Public` function in `module.function_defs`.
/// Friend and Private functions are excluded per Q3 walk-back.
fn collect_public_function_indices(module: &AdamantCompiledModule) -> Vec<FunctionDefinitionIndex> {
    module
        .function_defs
        .iter()
        .enumerate()
        .filter(|(_, def)| matches!(def.visibility, Visibility::Public))
        .map(|(idx, _)| {
            FunctionDefinitionIndex(TableIndex::try_from(idx).expect(
                "function_defs count exceeds u16; binary format precludes this \
                     (TABLE_INDEX_MAX = u16::MAX)",
            ))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    //! Layer A tests for Rule 2 (privacy-metadata).
    //!
    //! No Layer B parity tests by design — Rule 2 is an
    //! Adamant-specific rule per §6.2.1.6; Sui-Move has no
    //! equivalent. Test module's "no Sui parity claim"
    //! posture mirrors the `<SELF>` pin in B-3.1's
    //! invariant #7.

    use adamant_bytecode_format::{
        AddressIdentifierIndex, FunctionHandle, FunctionHandleIndex, Identifier, IdentifierIndex,
        Metadata, ModuleHandle, ModuleHandleIndex, Signature, SignatureIndex, Visibility,
    };
    use adamant_types::Address as AccountAddress;

    use crate::module::{AdamantCodeUnit, AdamantCompiledModule, AdamantFunctionDefinition};

    use super::super::error::AdamantValidationError;
    use super::{verify, PRIVACY_METADATA_KEY};

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

    /// Append a function-with-body to the module with the
    /// given visibility. Returns the function-definition
    /// index (0-based position in `function_defs`).
    fn push_fn_with_visibility(
        m: &mut AdamantCompiledModule,
        name: &str,
        visibility: Visibility,
    ) -> u16 {
        let name_idx = IdentifierIndex(u16::try_from(m.identifiers.len()).unwrap());
        m.identifiers.push(Identifier::new(name).unwrap());
        let empty_sig = SignatureIndex(u16::try_from(m.signatures.len()).unwrap());
        m.signatures.push(Signature(vec![]));
        let handle_idx = FunctionHandleIndex(u16::try_from(m.function_handles.len()).unwrap());
        m.function_handles.push(FunctionHandle {
            module: ModuleHandleIndex(0),
            name: name_idx,
            parameters: empty_sig,
            return_: empty_sig,
            type_parameters: vec![],
        });
        let def_idx = u16::try_from(m.function_defs.len()).unwrap();
        m.function_defs.push(AdamantFunctionDefinition {
            function: handle_idx,
            visibility,
            is_entry: false,
            acquires_global_resources: vec![],
            code: Some(AdamantCodeUnit {
                locals: empty_sig,
                code: vec![crate::bytecode::BytecodeInstruction::Inherited(
                    adamant_bytecode_format::Bytecode::Ret,
                )],
                jump_tables: vec![],
            }),
        });
        def_idx
    }

    /// Build a privacy-metadata entry from a list of
    /// (function-def-index, byte) pairs.
    fn privacy_entry(pairs: &[(u16, u8)]) -> Metadata {
        let typed: Vec<(adamant_bytecode_format::FunctionDefinitionIndex, u8)> = pairs
            .iter()
            .map(|(idx, byte)| {
                (
                    adamant_bytecode_format::FunctionDefinitionIndex(*idx),
                    *byte,
                )
            })
            .collect();
        Metadata {
            key: PRIVACY_METADATA_KEY.to_vec(),
            value: bcs::to_bytes(&typed).unwrap(),
        }
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
    fn module_with_no_public_and_no_privacy_entry_passes() {
        // No Public function, no privacy entry — vacuously
        // satisfied. Cardinality option (b): zero entries
        // allowed iff no Public functions.
        let mut m = empty_module();
        push_fn_with_visibility(&mut m, "p", Visibility::Private);
        assert!(verify(&m).is_ok());
    }

    #[test]
    fn module_with_one_public_function_and_valid_annotation_passes() {
        let mut m = empty_module();
        let pub_idx = push_fn_with_visibility(&mut m, "f", Visibility::Public);
        m.metadata.push(privacy_entry(&[(pub_idx, 0x00)]));
        assert!(verify(&m).is_ok());
    }

    #[test]
    fn module_with_multiple_public_functions_all_annotated_passes() {
        let mut m = empty_module();
        let p1 = push_fn_with_visibility(&mut m, "f1", Visibility::Public);
        let p2 = push_fn_with_visibility(&mut m, "f2", Visibility::Public);
        m.metadata.push(privacy_entry(&[(p1, 0x00), (p2, 0x01)]));
        assert!(verify(&m).is_ok());
    }

    // --- Q3 walk-back behavioral lock fixtures (three) ---

    #[test]
    fn module_with_friend_only_no_privacy_entry_passes() {
        // Q3 fixture (a): Friend functions only — no privacy
        // entry needed. Cardinality option (b): zero entries
        // allowed iff no Public functions.
        let mut m = empty_module();
        push_fn_with_visibility(&mut m, "fr", Visibility::Friend);
        assert!(verify(&m).is_ok());
    }

    #[test]
    fn module_with_friend_and_public_friend_not_in_table_passes() {
        // Q3 fixture (b): Friend + Public functions; Public
        // annotated, Friend not in table — accepts. Pins that
        // Friend functions don't need to appear in the table
        // even when the table exists with Public coverage.
        let mut m = empty_module();
        push_fn_with_visibility(&mut m, "fr", Visibility::Friend); // index 0
        let pub_idx = push_fn_with_visibility(&mut m, "f", Visibility::Public); // index 1
        m.metadata.push(privacy_entry(&[(pub_idx, 0x00)]));
        assert!(verify(&m).is_ok());
    }

    #[test]
    fn module_with_public_and_private_private_not_in_table_passes() {
        // Q3 fixture (c): Public + Private functions; Public
        // annotated, Private not in table — accepts. Same
        // shape for Private; symmetric with fixture (b).
        let mut m = empty_module();
        push_fn_with_visibility(&mut m, "pr", Visibility::Private); // index 0
        let pub_idx = push_fn_with_visibility(&mut m, "f", Visibility::Public); // index 1
        m.metadata.push(privacy_entry(&[(pub_idx, 0x00)]));
        assert!(verify(&m).is_ok());
    }

    // ============================================================
    // Layer A — negatives
    // ============================================================

    #[test]
    fn rejects_module_with_public_and_no_privacy_entry() {
        let mut m = empty_module();
        push_fn_with_visibility(&mut m, "f", Visibility::Public);
        match verify(&m) {
            Err(AdamantValidationError::MissingPrivacyMetadata) => {}
            other => panic!("expected MissingPrivacyMetadata, got {other:?}"),
        }
    }

    #[test]
    fn rejects_module_with_two_privacy_entries() {
        let mut m = empty_module();
        let pub_idx = push_fn_with_visibility(&mut m, "f", Visibility::Public);
        m.metadata.push(privacy_entry(&[(pub_idx, 0x00)]));
        m.metadata.push(privacy_entry(&[(pub_idx, 0x01)]));
        match verify(&m) {
            Err(AdamantValidationError::MultiplePrivacyMetadata { count: 2 }) => {}
            other => panic!("expected MultiplePrivacyMetadata {{ count: 2 }}, got {other:?}"),
        }
    }

    #[test]
    fn rejects_module_with_three_privacy_entries() {
        let mut m = empty_module();
        let pub_idx = push_fn_with_visibility(&mut m, "f", Visibility::Public);
        m.metadata.push(privacy_entry(&[(pub_idx, 0x00)]));
        m.metadata.push(privacy_entry(&[(pub_idx, 0x01)]));
        m.metadata.push(privacy_entry(&[(pub_idx, 0x00)]));
        match verify(&m) {
            Err(AdamantValidationError::MultiplePrivacyMetadata { count: 3 }) => {}
            other => panic!("expected MultiplePrivacyMetadata {{ count: 3 }}, got {other:?}"),
        }
    }

    #[test]
    fn rejects_module_with_malformed_privacy_payload() {
        let mut m = empty_module();
        push_fn_with_visibility(&mut m, "f", Visibility::Public);
        m.metadata.push(Metadata {
            key: PRIVACY_METADATA_KEY.to_vec(),
            value: vec![0xFF, 0xFF, 0xFF],
        });
        match verify(&m) {
            Err(AdamantValidationError::MalformedPrivacyMetadata { bcs_error }) => {
                assert!(
                    !bcs_error.is_empty(),
                    "BCS error string should not be empty; carries diagnostic context"
                );
            }
            other => panic!("expected MalformedPrivacyMetadata, got {other:?}"),
        }
    }

    #[test]
    fn rejects_public_function_not_covered_by_table() {
        let mut m = empty_module();
        let _pub0 = push_fn_with_visibility(&mut m, "f0", Visibility::Public);
        let pub1 = push_fn_with_visibility(&mut m, "f1", Visibility::Public);
        // Table covers only f1; f0 is uncovered.
        m.metadata.push(privacy_entry(&[(pub1, 0x00)]));
        match verify(&m) {
            Err(AdamantValidationError::MissingPrivacyAnnotation { function_index }) => {
                assert_eq!(function_index.0, 0);
            }
            other => {
                panic!("expected MissingPrivacyAnnotation {{ function_index: 0 }}, got {other:?}")
            }
        }
    }

    #[test]
    fn multiple_entries_wins_over_malformed_eager_error() {
        // Eager-error precedence: MultiplePrivacyMetadata is
        // checked before the entry-payload BCS decode runs.
        // Two entries (one valid, one malformed) ⇒ count
        // check fires first.
        let mut m = empty_module();
        let pub_idx = push_fn_with_visibility(&mut m, "f", Visibility::Public);
        m.metadata.push(privacy_entry(&[(pub_idx, 0x00)]));
        m.metadata.push(Metadata {
            key: PRIVACY_METADATA_KEY.to_vec(),
            value: vec![0xFF, 0xFF],
        });
        match verify(&m) {
            Err(AdamantValidationError::MultiplePrivacyMetadata { count: 2 }) => {}
            other => panic!("expected MultiplePrivacyMetadata, got {other:?}"),
        }
    }

    #[test]
    fn malformed_wins_over_coverage_eager_error() {
        // Eager-error precedence: malformed payload check
        // fires before coverage check. Module has uncovered
        // Public function AND malformed payload → malformed
        // wins.
        let mut m = empty_module();
        push_fn_with_visibility(&mut m, "f", Visibility::Public);
        m.metadata.push(Metadata {
            key: PRIVACY_METADATA_KEY.to_vec(),
            value: vec![0xFF, 0xFF, 0xFF],
        });
        assert!(matches!(
            verify(&m),
            Err(AdamantValidationError::MalformedPrivacyMetadata { .. })
        ));
    }
}
