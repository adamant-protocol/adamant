//! Validator Rule 5 (whitepaper §6.2.1.6 #5):
//! no global storage instructions.
//!
//! The Diem-Move global storage instructions (`MoveTo`,
//! `MoveFrom`, `BorrowGlobal`, `Exists`, etc.) must not appear
//! in the bytecode. Per §6.1.4, all storage access goes through
//! object references.
//!
//! # Implementation: rejection by deserializer config
//!
//! Sui-Move's deserializer rejects all 10 deprecated global-storage
//! variants at parse time when the `BinaryConfig`'s
//! `deprecate_global_storage_ops` flag is `true`:
//!
//! - `ExistsDeprecated`, `ImmBorrowGlobalDeprecated`,
//!   `MutBorrowGlobalDeprecated`, `MoveFromDeprecated`,
//!   `MoveToDeprecated`
//! - `ExistsGenericDeprecated`,
//!   `ImmBorrowGlobalGenericDeprecated`,
//!   `MutBorrowGlobalGenericDeprecated`,
//!   `MoveFromGenericDeprecated`, `MoveToGenericDeprecated`
//!
//! See `vendor/move-binary-format/src/deserializer.rs:1657` for
//! the rejection function (`check_deprecate_global_storage_ops`)
//! and lines 1860–1898 for the per-variant call sites that emit
//! [`StatusCode::DEPRECATED_BYTECODE_FORMAT`].
//!
//! [`super::AdamantVerifierConfig::new`] forces the flag to
//! `true` non-overridably in the wrapped
//! [`BinaryConfig`][`move_binary_format::binary_config::BinaryConfig`],
//! so the rule is enforced structurally at the deserialize stage
//! of [`super::verify_module`] before any later step runs. This
//! module carries no verification function — the rejection
//! happens upstream of where Adamant code would scan, so there is
//! nothing for an Adamant-side scan to add.
//!
//! Sui's `move-bytecode-verifier::BoundsChecker` carries a
//! `safe_assert!(!deprecate_global_storage_ops)` for the same
//! variants as a defense-in-depth invariant — see
//! `vendor/move-binary-format/src/check_bounds.rs:531`. In a
//! correctly-deserialized module that assertion is unreachable;
//! the verifier-config flag in `AdamantVerifierConfig` is set to
//! `true` to keep the safety net active in case any deprecated
//! variant ever reaches the verifier through a code path other
//! than the public `deserialize_with_config` entry point.
//!
//! [`StatusCode::DEPRECATED_BYTECODE_FORMAT`]: move_core_types::vm_status::StatusCode::DEPRECATED_BYTECODE_FORMAT
//!
//! # Tests
//!
//! The tests below empirically confirm the rejection: each one
//! constructs a programmatic `CompiledModule` with one of the
//! 10 deprecated variants, serialises it to bytes via Sui's
//! serializer, and asserts that [`super::verify_module`] returns
//! [`AdamantValidationError::SuiDeserializer`] when handed those
//! bytes. The tests are the observable behaviour of Rule 5 in our
//! pipeline; they exist to catch regressions if Sui's behaviour or
//! our config-locking ever drifts.
//!
//! [`AdamantValidationError::SuiDeserializer`]: super::AdamantValidationError::SuiDeserializer

// Intentionally no `pub(super) fn verify(...)` — Rule 5 is
// enforced via the deserialize step in `super::verify_module`
// with `deprecate_global_storage_ops = true` (forced by
// `AdamantVerifierConfig::new` in both wrapped configs).

#[cfg(test)]
mod tests {
    use super::super::test_fixtures::{module_with_function_body_starting, serialize_module};
    use super::super::{verify_module, AdamantValidationError, AdamantVerifierConfig};
    use move_binary_format::file_format::{
        Bytecode, StructDefInstantiationIndex, StructDefinitionIndex,
    };

    /// Assert that `verify_module` rejects the given module bytes
    /// at the Sui deserializer stage (i.e. with the
    /// `SuiDeserializer` error variant). Used by every test in
    /// this file: each one of the 10 deprecated variants must
    /// land in the deserialize-stage rejection path, since
    /// Rule 5 is structurally enforced by Sui's deserializer
    /// with `deprecate_global_storage_ops = true`.
    #[track_caller]
    fn assert_rejected_by_sui_deserializer(module_bytes: &[u8]) {
        let config = AdamantVerifierConfig::new();
        let result = verify_module(module_bytes, &config);
        match result {
            Err(AdamantValidationError::SuiDeserializer(_)) => {}
            other => panic!(
                "expected SuiDeserializer rejection (Rule 5 is enforced via Sui's \
                 deserializer when deprecate_global_storage_ops=true), got {other:?}"
            ),
        }
    }

    // --- Non-generic variants (StructDefinitionIndex operand) ---

    #[test]
    fn rejects_exists_deprecated() {
        let m = module_with_function_body_starting(Bytecode::ExistsDeprecated(
            StructDefinitionIndex(0),
        ));
        assert_rejected_by_sui_deserializer(&serialize_module(&m));
    }

    #[test]
    fn rejects_imm_borrow_global_deprecated() {
        let m = module_with_function_body_starting(Bytecode::ImmBorrowGlobalDeprecated(
            StructDefinitionIndex(0),
        ));
        assert_rejected_by_sui_deserializer(&serialize_module(&m));
    }

    #[test]
    fn rejects_mut_borrow_global_deprecated() {
        let m = module_with_function_body_starting(Bytecode::MutBorrowGlobalDeprecated(
            StructDefinitionIndex(0),
        ));
        assert_rejected_by_sui_deserializer(&serialize_module(&m));
    }

    #[test]
    fn rejects_move_from_deprecated() {
        let m = module_with_function_body_starting(Bytecode::MoveFromDeprecated(
            StructDefinitionIndex(0),
        ));
        assert_rejected_by_sui_deserializer(&serialize_module(&m));
    }

    #[test]
    fn rejects_move_to_deprecated() {
        let m = module_with_function_body_starting(Bytecode::MoveToDeprecated(
            StructDefinitionIndex(0),
        ));
        assert_rejected_by_sui_deserializer(&serialize_module(&m));
    }

    // --- Generic variants (StructDefInstantiationIndex operand) ---

    #[test]
    fn rejects_exists_generic_deprecated() {
        let m = module_with_function_body_starting(Bytecode::ExistsGenericDeprecated(
            StructDefInstantiationIndex(0),
        ));
        assert_rejected_by_sui_deserializer(&serialize_module(&m));
    }

    #[test]
    fn rejects_imm_borrow_global_generic_deprecated() {
        let m = module_with_function_body_starting(Bytecode::ImmBorrowGlobalGenericDeprecated(
            StructDefInstantiationIndex(0),
        ));
        assert_rejected_by_sui_deserializer(&serialize_module(&m));
    }

    #[test]
    fn rejects_mut_borrow_global_generic_deprecated() {
        let m = module_with_function_body_starting(Bytecode::MutBorrowGlobalGenericDeprecated(
            StructDefInstantiationIndex(0),
        ));
        assert_rejected_by_sui_deserializer(&serialize_module(&m));
    }

    #[test]
    fn rejects_move_from_generic_deprecated() {
        let m = module_with_function_body_starting(Bytecode::MoveFromGenericDeprecated(
            StructDefInstantiationIndex(0),
        ));
        assert_rejected_by_sui_deserializer(&serialize_module(&m));
    }

    #[test]
    fn rejects_move_to_generic_deprecated() {
        let m = module_with_function_body_starting(Bytecode::MoveToGenericDeprecated(
            StructDefInstantiationIndex(0),
        ));
        assert_rejected_by_sui_deserializer(&serialize_module(&m));
    }
}
