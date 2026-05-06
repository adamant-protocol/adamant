//! Adamant bytecode validator (whitepaper §6.2.1.6).
//!
//! This module implements the Adamant deploy-time bytecode
//! validator atop the Adamant-native deserializer/serializer
//! (Phase 5/5a) and Sui-Move's vendored verifier (transitional
//! bridge until Phase 5/5b–5/5c land Adamant-native verifier
//! passes). The single public entry point is [`verify_module`],
//! which takes module **bytes** and returns a parsed
//! [`AdamantCompiledModule`] on success.
//!
//! # Pipeline
//!
//! 1. **Deserialize.** Calls [`crate::adamant_deserialize`] in
//!    strict mode. Per §6.2.1.6 Rule 5, the strict-mode wire
//!    decoder rejects each of the 10 deprecated global-storage
//!    bytecode variants at parse time inside
//!    [`crate::bytecode_wire::deserialize_function_body_from_cursor`];
//!    that is the enforcement point for Rule 5 post-step-4.
//! 2. **Canonicality round-trip.** Re-serializes the parsed
//!    module via [`crate::adamant_serialize`] and byte-compares
//!    against the input. Mismatch surfaces as
//!    [`AdamantValidationError::NonCanonicalBytecode`]. Adamant
//!    requires deployed bytecode to be canonically encoded so
//!    that two deployments of "the same module" cannot produce
//!    different `ObjectId`s via trailing-byte smuggling.
//! 3. **Verify (inherited, transitional).** For modules that
//!    contain no Adamant extensions per §6.2.1.4, re-parses bytes
//!    via Sui's [`CompiledModule::deserialize_with_config`] (to
//!    obtain a [`CompiledModule`] that Sui's verifier can
//!    consume) and runs Sui-Move's `move-bytecode-verifier`
//!    passes (type safety, reference safety, linearity, stack
//!    discipline, control-flow integrity, function-call ABI,
//!    generic instantiation, friend visibility, plus Sui's
//!    `BoundsChecker` for cross-pool index validity). Modules
//!    that *do* contain Adamant extensions skip this step;
//!    Adamant-native per-instruction verification of the 17
//!    extensions lands in Phase 5/5c.
//! 4. **Verify (Adamant).** Runs the Adamant-specific rules from
//!    §6.2.1.6 in spec order against the [`AdamantCompiledModule`].
//!
//! Eager error semantics: returns the first violation encountered
//! at any pipeline stage.
//!
//! # Wave 3a + Phase 5/5a step 4 coverage
//!
//! - **Rule 1** ([`rule_01_mutability`]): every module carries
//!   exactly one `b"adamant.mutability"` metadata entry whose
//!   value BCS-decodes as [`adamant_types::Mutability`].
//! - **Rule 4** ([`rule_04_no_natives`]): no function definition
//!   has `code: None`.
//! - **Rule 5** (no global storage): rejected at parse time by
//!   [`crate::adamant_deserialize`] via
//!   [`crate::bytecode_wire::DeserializeConfig::strict`]'s
//!   deprecated-opcode rejection. The previously-separate
//!   `rule_05_no_global_storage` module was removed in Phase 5/5a
//!   step 4 — defense-in-depth at rule-module level became
//!   cargo-cult once the deserializer became the enforcement
//!   point. The end-to-end test
//!   [`tests::rejects_module_with_deprecated_global_storage_opcode`]
//!   confirms the full-pipeline rejection.
//!
//! Rules 2, 3, 6, 7, and 8 (the gas-bound no-op test) land in
//! subsequent waves.
//!
//! # Discipline reference
//!
//! Per the proposal's architectural decision, [`verify_module`] is
//! the single consensus-binding entry point for module deployment
//! validation. Callers invoke it as `validator::verify_module(...)`
//! to disambiguate from Sui's verifier functions.
//!
//! [`CompiledModule`]: move_binary_format::file_format::CompiledModule
//! [`CompiledModule::deserialize_with_config`]: move_binary_format::file_format::CompiledModule::deserialize_with_config

mod config;
mod error;
mod rule_01_mutability;
mod rule_04_no_natives;

#[cfg(test)]
mod test_fixtures;

pub use config::AdamantVerifierConfig;
pub use error::AdamantValidationError;

use move_binary_format::{errors::Location, file_format::CompiledModule};

use crate::module::AdamantCompiledModule;
use crate::module_wire::{adamant_deserialize, adamant_serialize};

/// Verify Adamant module bytes against the validator rules per
/// whitepaper §6.2.1.6.
///
/// On success, returns the parsed [`AdamantCompiledModule`] so
/// callers can use it (e.g., to read metadata, register the module
/// in chain state). On failure, returns the first
/// [`AdamantValidationError`] encountered at any pipeline stage.
///
/// # Pipeline ordering
///
/// 1. Adamant-native deserialize via [`adamant_deserialize`] —
///    strict canonical decoding; Rule 5 enforcement point at
///    parse time for deprecated global-storage opcodes.
/// 2. Canonicality round-trip ([`adamant_serialize`] +
///    byte-compare).
/// 3. Inherited Sui-Move verifier passes (transitional bridge):
///    re-deserialize via Sui to obtain a [`CompiledModule`] and
///    run `move-bytecode-verifier`. Skipped for modules
///    containing Adamant extensions; per-instruction extension
///    verification lands in Phase 5/5c.
/// 4. Adamant Rule 1 (mutability metadata required).
/// 5. Adamant Rule 4 (no native functions).
///
/// Rules 2, 3, 6, 7 land in subsequent waves and slot into this
/// ordering after Rule 4.
///
/// # Errors
///
/// - [`AdamantValidationError::AdamantDeserializer`] if
///   `module_bytes` fail to parse (malformed bytes, deprecated
///   global-storage opcodes per Rule 5, etc.).
/// - [`AdamantValidationError::NonCanonicalBytecode`] if the
///   bytes are not Adamant's canonical re-serialization of the
///   parsed module.
/// - [`AdamantValidationError::SuiVerifier`] if the parsed module
///   fails any inherited verifier pass (transitional; covers
///   Sui's `BoundsChecker` and verifier passes).
/// - Per-rule variants for Adamant-specific rule failures.
///
/// # Panics
///
/// Panics only if Adamant's serializer ever fails to re-serialize
/// an [`AdamantCompiledModule`] that Adamant's deserializer just
/// produced — an invariant violation in this crate that would
/// indicate a serialise/deserialise asymmetry. In normal operation
/// this branch is unreachable. Likewise panics if Sui's
/// deserializer rejects bytes that Adamant accepted **and** for
/// which the canonicality round-trip succeeded — that combination
/// implies a byte-format divergence between the two implementations
/// that the Phase 5/5a step 2/3 cross-validation tests assert
/// cannot occur.
pub fn verify_module(
    module_bytes: &[u8],
    config: &AdamantVerifierConfig,
) -> Result<AdamantCompiledModule, AdamantValidationError> {
    // Step 1: Adamant-native deserialize. Rule 5 is enforced
    // here — bytecode_wire's strict mode rejects the 10 deprecated
    // global-storage opcodes at parse time. Strict canonical
    // decoding also rejects trailing bytes, duplicate tables,
    // version-feature mismatches, and zero-length tables.
    let module =
        adamant_deserialize(module_bytes).map_err(AdamantValidationError::AdamantDeserializer)?;

    // Step 2: canonicality round-trip check. Re-serialize the
    // parsed module via Adamant's serializer and byte-compare
    // against the input. Catches any non-canonical encoding the
    // strict deserializer didn't already reject.
    let mut canonical_bytes = vec![];
    adamant_serialize(&module, &mut canonical_bytes).expect(
        "re-serializing a successfully-deserialized AdamantCompiledModule must succeed; \
         Adamant's serializer accepts every module shape its deserializer produces \
         (asserted by the Phase 5/5a round-trip property tests)",
    );
    if module_bytes != canonical_bytes.as_slice() {
        let byte_offset = module_bytes
            .iter()
            .zip(canonical_bytes.iter())
            .position(|(a, b)| a != b)
            .unwrap_or_else(|| module_bytes.len().min(canonical_bytes.len()));
        return Err(AdamantValidationError::NonCanonicalBytecode {
            byte_offset,
            canonical_byte: canonical_bytes.get(byte_offset).copied(),
            input_byte: module_bytes.get(byte_offset).copied(),
        });
    }

    // Step 3: inherited Sui-Move verifier passes (transitional
    // bridge until Phase 5/5b/5/5c). Modules with Adamant
    // extensions skip this step — Sui's verifier cannot consume
    // bytecode that includes the 0x80..=0x90 opcode space, and
    // Adamant-native per-instruction verification of the 17
    // extensions is in scope for Phase 5/5c.
    if !module.contains_adamant_extensions() {
        // Re-deserialize via Sui to obtain a CompiledModule. The
        // bytes are guaranteed to be Sui's canonical encoding for
        // any module that just passed steps 1-2 (asserted by the
        // Phase 5/5a step 2/3 cross-validation tests), so this
        // call succeeds for every module that reaches it. Rule 5
        // was already enforced at step 1, but we keep
        // `deprecate_global_storage_ops = true` in the wrapped
        // BinaryConfig as defense-in-depth in case a future Sui
        // upgrade changes Rule-5-equivalent enforcement behavior.
        let sui_module =
            CompiledModule::deserialize_with_config(module_bytes, config.sui_binary_config())
                .map_err(|e| AdamantValidationError::SuiVerifier(e.finish(Location::Undefined)))?;

        move_bytecode_verifier::verifier::verify_module_with_config_unmetered(
            config.sui_verifier_config(),
            &sui_module,
        )
        .map_err(AdamantValidationError::SuiVerifier)?;
    }

    // Step 4: Adamant-specific rules in spec order.
    rule_01_mutability::verify(&module)?;
    rule_04_no_natives::verify(&module)?;
    // Rule 5 is enforced by step 1; no separate pass.
    // Rules 2, 3, 6, 7 (subsequent waves) slot in here.
    // Rule 8 is a no-op at deployment per §6.2.1.6 amendment
    // 804d9db.

    Ok(module)
}

#[cfg(test)]
mod tests {
    use adamant_bytecode_format::{Bytecode, StructDefinitionIndex};

    use super::test_fixtures::{
        module_with_function_body_starting, module_without_mutability_metadata, serialize_module,
        valid_module,
    };
    use super::{verify_module, AdamantValidationError, AdamantVerifierConfig};
    use crate::bytecode_wire;
    use crate::module_wire::AdamantDeserializeError;

    #[test]
    fn valid_module_passes() {
        let m = valid_module();
        let bytes = serialize_module(&m);
        let config = AdamantVerifierConfig::new();
        let result = verify_module(&bytes, &config);
        assert!(
            result.is_ok(),
            "valid_module() must pass verification; failure indicates a fixture or wrapper bug. \
             Got: {:?}",
            result.err()
        );
    }

    #[test]
    fn config_default_matches_new() {
        // The Default impl forwards to new(), preserving the
        // structural lock-down of `deprecate_global_storage_ops`
        // in both wrapped configs. Regression coverage against
        // accidentally diverging Default and new() in the future.
        let from_new = AdamantVerifierConfig::new();
        let from_default = AdamantVerifierConfig::default();
        assert_eq!(
            from_new.sui_verifier_config().deprecate_global_storage_ops,
            from_default
                .sui_verifier_config()
                .deprecate_global_storage_ops
        );
        assert!(
            from_new.sui_verifier_config().deprecate_global_storage_ops,
            "AdamantVerifierConfig must force deprecate_global_storage_ops = true \
             in the verifier config (defense in depth)"
        );
        assert_eq!(
            from_new.sui_binary_config().deprecate_global_storage_ops,
            from_default
                .sui_binary_config()
                .deprecate_global_storage_ops
        );
        assert!(
            from_new.sui_binary_config().deprecate_global_storage_ops,
            "AdamantVerifierConfig must force deprecate_global_storage_ops = true \
             in the binary config (defense in depth post-step-4; primary enforcement \
             is now in adamant_deserialize)"
        );
    }

    #[test]
    fn first_error_wins_when_multiple_rules_violated() {
        // A module without mutability metadata has no functions
        // (Rule 4 vacuously satisfied); eager-error semantics
        // should report the Rule 1 violation.
        let m = module_without_mutability_metadata();
        let bytes = serialize_module(&m);
        let config = AdamantVerifierConfig::new();
        let result = verify_module(&bytes, &config);
        match result {
            Err(AdamantValidationError::MissingMutabilityMetadata) => {}
            other => {
                panic!("expected MissingMutabilityMetadata as the first eager error, got {other:?}")
            }
        }
    }

    // --- Canonical-encoding round-trip tests ---

    #[test]
    fn rejects_module_with_one_trailing_junk_byte() {
        // Valid canonical bytes plus a single trailing byte
        // should fail the canonicality round-trip — the
        // re-serialised form has no byte at this position, so
        // canonical_byte is None and input_byte carries the
        // junk byte's value.
        //
        // Note: post-step-4, adamant_deserialize itself rejects
        // trailing bytes with `TrailingBytes` at step 1, so the
        // canonicality-round-trip branch in step 2 never fires
        // for the trailing-bytes case. This test now asserts the
        // step-1 rejection.
        let m = valid_module();
        let canonical = serialize_module(&m);
        let mut bytes = canonical.clone();
        bytes.push(0xAB);

        let config = AdamantVerifierConfig::new();
        let result = verify_module(&bytes, &config);
        match result {
            Err(AdamantValidationError::AdamantDeserializer(
                AdamantDeserializeError::TrailingBytes,
            )) => {}
            other => {
                panic!("expected AdamantDeserializer(TrailingBytes), got {other:?}")
            }
        }
    }

    #[test]
    fn rejects_module_with_multiple_trailing_junk_bytes() {
        // Same shape as the single-trailing-byte case.
        let m = valid_module();
        let canonical = serialize_module(&m);
        let mut bytes = canonical.clone();
        bytes.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);

        let config = AdamantVerifierConfig::new();
        let result = verify_module(&bytes, &config);
        match result {
            Err(AdamantValidationError::AdamantDeserializer(
                AdamantDeserializeError::TrailingBytes,
            )) => {}
            other => {
                panic!("expected AdamantDeserializer(TrailingBytes), got {other:?}")
            }
        }
    }

    #[test]
    fn rich_canonical_module_round_trips() {
        // A non-trivial fixture (multiple metadata entries plus
        // a function and a struct) round-trips cleanly through
        // the wrapper. Guards against regressions where serialise
        // and deserialise drift on richer module shapes.
        let m = super::test_fixtures::rich_valid_module();
        let bytes = serialize_module(&m);
        let config = AdamantVerifierConfig::new();
        let result = verify_module(&bytes, &config);
        assert!(
            result.is_ok(),
            "rich_valid_module() must round-trip canonically; failure indicates serialise/\
             deserialise drift or a fixture bug. Got: {:?}",
            result.err()
        );
    }

    // --- Rule 5 enforcement-point shift verification ---
    //
    // Replaces the 10 per-opcode tests that previously lived in
    // the rule_05_no_global_storage module (removed in Phase 5/5a
    // step 4). Wave 3a's exhaustive per-opcode coverage is now
    // provided by `bytecode_wire::tests::strict_mode_rejects_each_deprecated_opcode`,
    // which tests the rejection at the wire level. This test
    // confirms the full validate-pipeline propagation: a module
    // containing one deprecated opcode in a function body returns
    // `AdamantDeserializer(Bytecode(DeprecatedGlobalStorageOpcode(_)))`
    // from `verify_module`.

    #[test]
    fn rejects_module_with_deprecated_global_storage_opcode() {
        let m = module_with_function_body_starting(Bytecode::ExistsDeprecated(
            StructDefinitionIndex(0),
        ));
        let bytes = serialize_module(&m);
        let config = AdamantVerifierConfig::new();
        let result = verify_module(&bytes, &config);
        match result {
            Err(AdamantValidationError::AdamantDeserializer(
                AdamantDeserializeError::Bytecode(
                    bytecode_wire::DeserializeError::DeprecatedGlobalStorageOpcode(_),
                ),
            )) => {}
            other => {
                panic!(
                    "expected AdamantDeserializer(Bytecode(DeprecatedGlobalStorageOpcode(_))), \
                     got {other:?}"
                )
            }
        }
    }
}
