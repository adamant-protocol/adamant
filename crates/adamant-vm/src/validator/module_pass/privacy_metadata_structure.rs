//! Module-level pass: privacy-metadata structural well-
//! formedness (whitepaper §6.2.1.8 step 3).
//!
//! Adamant-specific module-level pass parallel to Rule 2
//! per the §6.2.1.8 step-3-vs-step-5 split. For each
//! `b"adamant.privacy"` metadata entry in the module,
//! validates the per-pair structural shape:
//!
//! - The entry's value BCS-decodes as
//!   `Vec<(FunctionDefinitionIndex, u8)>`.
//! - Every pair's byte is in `{0x00, 0x01}` per §6.2.1.3.
//! - Every pair's `FunctionDefinitionIndex` is `<
//!   module.function_defs.len()` (in range).
//! - No two pairs in the same entry share the same
//!   `FunctionDefinitionIndex`.
//!
//! **Cardinality is NOT checked here.** The two-pass split
//! per §6.2.1.8 means cardinality (zero/one/many entries)
//! is a Rule 2 (step 5) concern; this pass iterates all
//! entries with the privacy key and validates each one
//! structurally. Modules with multiple well-formed
//! privacy entries pass this pass; Rule 2 rejects them
//! at step 5.
//!
//! # No-Sui-parity-claim posture
//!
//! No Layer B parity tests by design. This pass is
//! Adamant-specific — there is no upstream Sui equivalent
//! for the `(FunctionDefinitionIndex, u8)` list-payload
//! shape, and `b"adamant.privacy"` is an Adamant metadata
//! key Sui's verifier doesn't know about. Pattern parallel
//! to Rule 2 (B-4.1) and B-3.1's `<SELF>` invariant #7.
//!
//! # Deliberate-Adamant-decision: per-pair check ordering
//!
//! Per-pair checks are applied in the order:
//!
//! 1. Byte validity (`0x00`/`0x01`)
//! 2. Index in range (`< function_defs.len()`)
//! 3. Duplicate within entry (`HashSet` insert)
//!
//! This ordering is a **deliberate Adamant decision**, not
//! byte-faithful preservation of an upstream Sui pass —
//! `privacy_metadata_structure` has no direct upstream
//! analog because privacy metadata is Adamant-specific.
//! The ordering follows cheapest-check-first reasoning:
//!
//! - **Byte validity** is a single comparison (`> 1`).
//! - **Range check** is a comparison plus a length
//!   lookup.
//! - **Duplicate check** is a `HashSet::insert` which
//!   allocates on first use and hashes on each call.
//!
//! Alternative orderings are defensible (e.g., range-
//! first to fail-fast on out-of-range indices that can't
//! be valid under any interpretation). The cheapest-
//! check-first ordering here is documented as the chosen
//! shape so future cross-validation gaps don't get
//! mischaracterized as porting bugs against a non-existent
//! upstream-parity claim.
//!
//! # Eager-error first-failure-wins
//!
//! - Across entries: for-loop short-circuits on the first
//!   entry that fails BCS decode or any per-pair check.
//! - Within an entry: the per-pair for-loop short-circuits
//!   on the first pair that fails.
//! - Within a pair: the per-pair check ordering above
//!   short-circuits on the first failing check.
//!
//! Phase 5/5b.2-wide methodology principle: when multiple
//! violations exist, the verifier reports the first
//! encountered in deterministic iteration order.
//! Determinism matters for cross-validation parity.
//!
//! # Shared variant: `MalformedPrivacyMetadata`
//!
//! [`MalformedPrivacyMetadata`] is shared with B-4.1's
//! Rule 2. Cross-pass eager-error precedence at B-5
//! pipeline wiring: `privacy_metadata_structure` runs in
//! the step-3 batch before Rule 2 runs in the step-5
//! batch, so this pass typically wins precedence on the
//! same input. Rule 2's BCS decode is defense-in-depth.
//! Second instance of the shared-variant-with-pipeline-
//! ordering-eager-error sub-pattern of byte-faithful
//! preservation (after B-2.1 + B-3.1's
//! `MalformedConstantData`).
//!
//! [`MalformedPrivacyMetadata`]: super::super::error::AdamantValidationError::MalformedPrivacyMetadata
//!
//! # Dead-code allow (transient)
//!
//! Phase 5/5b.2 B-5 wires this pass into
//! [`crate::validator::verify_module`] in the step-3
//! batch after the seven ported B-2/B-3 passes. Until B-5
//! lands, the pass is reachable only from inline tests;
//! the lib build sees the entry point as dead. The
//! module-level `dead_code` allow is removed when B-5
//! wires the pass.

#![allow(dead_code, reason = "wired into verify_module() in Phase 5/5b.2 B-5")]

use std::collections::HashSet;

use adamant_bytecode_format::FunctionDefinitionIndex;

use crate::module::AdamantCompiledModule;

use super::super::error::AdamantValidationError;

/// Per whitepaper §6.2.1.3, the metadata key under which
/// the privacy annotation table is BCS-encoded.
const PRIVACY_METADATA_KEY: &[u8] = b"adamant.privacy";

/// Verify the structural well-formedness of every
/// `b"adamant.privacy"` metadata entry in `module` per
/// §6.2.1.8 step 3
/// (`module_pass::privacy_metadata_structure`).
pub(in crate::validator) fn verify(
    module: &AdamantCompiledModule,
) -> Result<(), AdamantValidationError> {
    for entry in module
        .metadata
        .iter()
        .filter(|m| m.key == PRIVACY_METADATA_KEY)
    {
        verify_entry(module, &entry.value)?;
    }
    Ok(())
}

fn verify_entry(
    module: &AdamantCompiledModule,
    value: &[u8],
) -> Result<(), AdamantValidationError> {
    let payload: Vec<(FunctionDefinitionIndex, u8)> =
        bcs::from_bytes(value).map_err(|e| AdamantValidationError::MalformedPrivacyMetadata {
            bcs_error: format!("{e}"),
        })?;
    let mut seen: HashSet<FunctionDefinitionIndex> = HashSet::new();
    let function_defs_len = module.function_defs.len();
    for (function_index, byte) in payload {
        // Per-pair check ordering: byte → range → duplicate
        // (cheapest-check-first; deliberate Adamant decision —
        // see module-level doc-comment).
        if byte > 1 {
            return Err(AdamantValidationError::InvalidPrivacyAnnotationByte {
                function_index,
                byte,
            });
        }
        if (function_index.0 as usize) >= function_defs_len {
            return Err(AdamantValidationError::PrivacyEntryOutOfRange {
                function_index,
                function_defs_len,
            });
        }
        if !seen.insert(function_index) {
            return Err(AdamantValidationError::DuplicatePrivacyEntry { function_index });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    //! Layer A tests for `privacy_metadata_structure`.
    //!
    //! No Layer B parity tests by design — Adamant-specific
    //! pass; no upstream Sui equivalent. See module-level
    //! "No-Sui-parity-claim posture" doc-comment.

    use adamant_bytecode_format::{
        AddressIdentifierIndex, FunctionDefinitionIndex, FunctionHandle, FunctionHandleIndex,
        Identifier, IdentifierIndex, Metadata, ModuleHandle, ModuleHandleIndex, Signature,
        SignatureIndex, Visibility,
    };
    use adamant_types::Address as AccountAddress;

    use crate::module::{AdamantCodeUnit, AdamantCompiledModule, AdamantFunctionDefinition};

    use super::super::super::error::AdamantValidationError;
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

    /// Append a Private function-with-body to the module.
    fn push_private_fn(m: &mut AdamantCompiledModule, name: &str) {
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
        m.function_defs.push(AdamantFunctionDefinition {
            function: handle_idx,
            visibility: Visibility::Private,
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
    }

    /// Build a privacy-metadata entry from a list of
    /// (function-def-index, byte) pairs.
    fn privacy_entry(pairs: &[(u16, u8)]) -> Metadata {
        let typed: Vec<(FunctionDefinitionIndex, u8)> = pairs
            .iter()
            .map(|(idx, byte)| (FunctionDefinitionIndex(*idx), *byte))
            .collect();
        Metadata {
            key: PRIVACY_METADATA_KEY.to_vec(),
            value: bcs::to_bytes(&typed).unwrap(),
        }
    }

    /// Build a privacy-metadata entry with explicitly
    /// provided raw value bytes (used for malformed-BCS
    /// fixtures).
    fn raw_privacy_entry(value: Vec<u8>) -> Metadata {
        Metadata {
            key: PRIVACY_METADATA_KEY.to_vec(),
            value,
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
    fn entry_with_zero_pairs_passes() {
        // Empty list payload: BCS-encodes as a single
        // ULEB128 zero. Structurally well-formed.
        let mut m = empty_module();
        m.metadata.push(privacy_entry(&[]));
        assert!(verify(&m).is_ok());
    }

    #[test]
    fn entry_with_one_valid_pair_passes() {
        let mut m = empty_module();
        push_private_fn(&mut m, "f");
        m.metadata.push(privacy_entry(&[(0, 0x00)]));
        assert!(verify(&m).is_ok());
    }

    #[test]
    fn entry_with_multiple_valid_pairs_passes() {
        let mut m = empty_module();
        push_private_fn(&mut m, "f0");
        push_private_fn(&mut m, "f1");
        push_private_fn(&mut m, "f2");
        m.metadata
            .push(privacy_entry(&[(0, 0x00), (1, 0x01), (2, 0x00)]));
        assert!(verify(&m).is_ok());
    }

    #[test]
    fn multiple_well_formed_entries_passes_structural_pass_cardinality_handled_at_rule_2() {
        // Two well-formed privacy entries. Rule 2 (B-4.1)
        // would reject for cardinality, but the structural
        // pass passes — §6.2.1.8 step-3-vs-step-5 split:
        // cardinality lives at step 5, not step 3.
        let mut m = empty_module();
        push_private_fn(&mut m, "f");
        m.metadata.push(privacy_entry(&[(0, 0x00)]));
        m.metadata.push(privacy_entry(&[(0, 0x01)]));
        assert!(verify(&m).is_ok());
    }

    // ============================================================
    // Layer A — negatives (full enumeration per the user's
    // re-surface flag from the original B-4 plan)
    // ============================================================

    #[test]
    fn rejects_malformed_bcs_payload() {
        let mut m = empty_module();
        push_private_fn(&mut m, "f");
        m.metadata.push(raw_privacy_entry(vec![0xFF, 0xFF, 0xFF]));
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
    fn rejects_invalid_byte_0x02() {
        let mut m = empty_module();
        push_private_fn(&mut m, "f");
        m.metadata.push(privacy_entry(&[(0, 0x02)]));
        match verify(&m) {
            Err(AdamantValidationError::InvalidPrivacyAnnotationByte {
                function_index,
                byte: 0x02,
            }) => {
                assert_eq!(function_index.0, 0);
            }
            other => {
                panic!("expected InvalidPrivacyAnnotationByte {{ byte: 0x02 }}, got {other:?}")
            }
        }
    }

    #[test]
    fn rejects_invalid_byte_0xff() {
        // Boundary: any byte > 1 rejected; verifies the
        // bound is `<= 1` not just `<= 2`.
        let mut m = empty_module();
        push_private_fn(&mut m, "f");
        m.metadata.push(privacy_entry(&[(0, 0xFF)]));
        match verify(&m) {
            Err(AdamantValidationError::InvalidPrivacyAnnotationByte {
                function_index,
                byte: 0xFF,
            }) => {
                assert_eq!(function_index.0, 0);
            }
            other => {
                panic!("expected InvalidPrivacyAnnotationByte {{ byte: 0xFF }}, got {other:?}")
            }
        }
    }

    #[test]
    fn rejects_out_of_range_index() {
        // Module has 1 function def; entry has pair with
        // idx=5.
        let mut m = empty_module();
        push_private_fn(&mut m, "f");
        m.metadata.push(privacy_entry(&[(5, 0x00)]));
        match verify(&m) {
            Err(AdamantValidationError::PrivacyEntryOutOfRange {
                function_index,
                function_defs_len,
            }) => {
                assert_eq!(function_index.0, 5);
                assert_eq!(function_defs_len, 1);
            }
            other => panic!("expected PrivacyEntryOutOfRange, got {other:?}"),
        }
    }

    #[test]
    fn rejects_duplicate_index_within_entry() {
        let mut m = empty_module();
        push_private_fn(&mut m, "f");
        m.metadata.push(privacy_entry(&[(0, 0x00), (0, 0x01)]));
        match verify(&m) {
            Err(AdamantValidationError::DuplicatePrivacyEntry { function_index }) => {
                assert_eq!(function_index.0, 0);
            }
            other => panic!("expected DuplicatePrivacyEntry, got {other:?}"),
        }
    }

    // ============================================================
    // Layer A — eager-error precedence
    // ============================================================

    #[test]
    fn within_entry_first_invalid_pair_wins() {
        // Entry has [valid, invalid-byte, duplicate]. Pass
        // reports InvalidPrivacyAnnotationByte (the first
        // invalid pair in iteration order), not
        // DuplicatePrivacyEntry.
        let mut m = empty_module();
        push_private_fn(&mut m, "f0");
        push_private_fn(&mut m, "f1");
        m.metadata
            .push(privacy_entry(&[(0, 0x00), (1, 0x02), (1, 0x01)]));
        match verify(&m) {
            Err(AdamantValidationError::InvalidPrivacyAnnotationByte {
                function_index,
                byte: 0x02,
            }) => {
                assert_eq!(function_index.0, 1);
            }
            other => panic!("expected InvalidPrivacyAnnotationByte at idx 1, got {other:?}"),
        }
    }

    #[test]
    fn cross_entry_first_failing_entry_wins() {
        // Entry 1 valid, Entry 2 malformed BCS. Pins the
        // for-loop over entries short-circuits on the first
        // failing entry (entry 2 in this case — entry 1's
        // validation result is independent).
        let mut m = empty_module();
        push_private_fn(&mut m, "f");
        m.metadata.push(privacy_entry(&[(0, 0x00)]));
        m.metadata.push(raw_privacy_entry(vec![0xFF, 0xFF, 0xFF]));
        assert!(matches!(
            verify(&m),
            Err(AdamantValidationError::MalformedPrivacyMetadata { .. })
        ));
    }

    #[test]
    fn overlapping_failure_modes_byte_check_wins_over_range_and_duplicate() {
        // A single pair that is BOTH out-of-range AND
        // duplicated AND has invalid byte. The byte check
        // fires first per the per-pair ordering (byte →
        // range → duplicate). Pins the ordering specifically
        // — not just first-pair-fails.
        let mut m = empty_module();
        push_private_fn(&mut m, "f");
        // Pair 0: valid (idx=0, byte=0x00) — accepted
        // Pair 1: idx=99 (out-of-range), byte=0x07 (invalid),
        // duplicate of itself isn't possible in a single
        // pair, so use idx=0 to overlap range-validity AND
        // duplicate-of-pair-0:
        // Pair 1: idx=0 (duplicate of pair 0), byte=0x07
        // (invalid)
        // Byte check fires first → InvalidPrivacyAnnotationByte
        m.metadata.push(privacy_entry(&[(0, 0x00), (0, 0x07)]));
        match verify(&m) {
            Err(AdamantValidationError::InvalidPrivacyAnnotationByte {
                function_index,
                byte: 0x07,
            }) => {
                assert_eq!(function_index.0, 0);
            }
            other => panic!(
                "expected InvalidPrivacyAnnotationByte (byte check wins ordering); got {other:?}"
            ),
        }
    }

    #[test]
    fn overlapping_range_and_duplicate_range_check_wins() {
        // Pair has out-of-range index AND would-be-duplicate.
        // Byte is valid; range fires before duplicate per
        // ordering.
        let mut m = empty_module();
        push_private_fn(&mut m, "f");
        // Pair 0: valid (idx=0, byte=0x00)
        // Pair 1: idx=99 (out-of-range), byte=0x01 (valid)
        // Range check fires before any duplicate check
        // could trigger.
        m.metadata.push(privacy_entry(&[(0, 0x00), (99, 0x01)]));
        match verify(&m) {
            Err(AdamantValidationError::PrivacyEntryOutOfRange {
                function_index,
                function_defs_len: 1,
            }) => {
                assert_eq!(function_index.0, 99);
            }
            other => {
                panic!("expected PrivacyEntryOutOfRange (range before duplicate); got {other:?}")
            }
        }
    }
}
