//! Adamant bytecode validator (whitepaper §6.2.1.6).
//!
//! This module implements the Adamant deploy-time bytecode
//! validator atop Sui-Move's vendored deserializer and bytecode
//! verifier. The single public entry point is [`verify_module`],
//! which takes module **bytes** (rather than a parsed
//! [`CompiledModule`]) and returns the parsed module on success.
//! Owning the bytes-to-parsed pipeline inside the wrapper means
//! Rule 5 enforcement happens at the architecturally correct
//! pipeline stage and removes a caller-side
//! deserializer-config footgun.
//!
//! # Pipeline
//!
//! 1. **Deserialize.** Calls
//!    [`CompiledModule::deserialize_with_config`] using
//!    [`AdamantVerifierConfig`]'s wrapped
//!    [`BinaryConfig`][`move_binary_format::binary_config::BinaryConfig`],
//!    which has `deprecate_global_storage_ops = true`. Sui's
//!    deserializer rejects the 10 deprecated global-storage
//!    bytecode variants at parse time
//!    (`vendor/move-binary-format/src/deserializer.rs:1657`); this
//!    is the actual enforcement point for §6.2.1.6 Rule 5.
//! 2. **Canonicality check.** Re-serializes the parsed
//!    [`CompiledModule`] via Sui's serializer at the module's
//!    own version and byte-compares against the input. Mismatch
//!    surfaces as
//!    [`AdamantValidationError::NonCanonicalBytecode`]. This
//!    recovers the canonicality posture that
//!    `check_no_extraneous_bytes = true` in the Sui deserializer
//!    would otherwise have provided — the wrapper cannot use
//!    that flag because it also rejects the metadata table
//!    Adamant needs per §6.2.1.3, so canonicality is enforced
//!    explicitly here. The check is consistent with §6.0.6 /
//!    §6.0.7's canonical-encoding posture for transactions.
//! 3. **Verify (inherited).** Runs Sui-Move's
//!    `move-bytecode-verifier` passes (type safety, reference
//!    safety, linearity, stack discipline, control-flow integrity,
//!    function-call ABI, generic instantiation, friend visibility).
//! 4. **Verify (Adamant).** Runs the Adamant-specific rules from
//!    §6.2.1.6 in spec order.
//!
//! Eager error semantics: returns the first violation encountered
//! at any pipeline stage.
//!
//! # Wave 3a coverage
//!
//! - **Rule 1** ([`rule_01_mutability`]): every module carries
//!   exactly one `b"adamant.mutability"` metadata entry whose
//!   value BCS-decodes as [`adamant_types::Mutability`].
//! - **Rule 4** ([`rule_04_no_natives`]): no function definition
//!   has `code: None` (Sui's marker for native functions).
//! - **Rule 5** ([`rule_05_no_global_storage`]): structurally
//!   enforced at deserialize stage by Sui's deserializer with
//!   `deprecate_global_storage_ops = true`. The
//!   `rule_05_no_global_storage` module carries no `verify`
//!   function — only documentation and tests confirming the
//!   rejection at the deserialize stage with the
//!   [`AdamantValidationError::SuiDeserializer`] variant.
//!
//! Rules 2, 3, 6, 7, and 8 (the gas-bound no-op test) land in
//! subsequent waves per the implementation order approved at the
//! validator-rules deliverable proposal.
//!
//! # Discipline reference
//!
//! Per the proposal's architectural decision, [`verify_module`] is
//! the single consensus-binding entry point for module deployment
//! validation. Callers invoke it as `validator::verify_module(...)`
//! to disambiguate from Sui's verifier functions.

mod config;
mod error;
mod rule_01_mutability;
mod rule_04_no_natives;
mod rule_05_no_global_storage;

#[cfg(test)]
mod test_fixtures;

pub use config::AdamantVerifierConfig;
pub use error::AdamantValidationError;

use move_binary_format::{errors::Location, file_format::CompiledModule};

/// Verify Adamant module bytes against the validator rules per
/// whitepaper §6.2.1.6.
///
/// On success, returns the parsed [`CompiledModule`] so callers
/// can use it (e.g., to read metadata, register the module in
/// chain state). On failure, returns the first
/// [`AdamantValidationError`] encountered at any pipeline stage.
///
/// # Pipeline ordering
///
/// 1. Deserialize bytes via Sui's
///    [`CompiledModule::deserialize_with_config`] with the locked-
///    down [`AdamantVerifierConfig`]'s binary config (Rule 5's
///    enforcement point).
/// 2. Canonicality round-trip check (re-serialize and byte-compare
///    against input).
/// 3. Inherited Sui verifier passes (covers §6.2.1.6's "inherited
///    checks" list; the verifier's matching
///    `deprecate_global_storage_ops` flag is defense in depth).
/// 4. Adamant Rule 1 (mutability metadata required).
/// 5. Adamant Rule 4 (no native functions).
///
/// Rules 2, 3, 6, 7 land in subsequent waves and slot into this
/// ordering after Rule 4.
///
/// # Errors
///
/// - [`AdamantValidationError::SuiDeserializer`] if `module_bytes`
///   fail to parse (malformed bytes, deprecated global-storage
///   variants per Rule 5, etc.).
/// - [`AdamantValidationError::NonCanonicalBytecode`] if the
///   bytes are not Sui's canonical re-serialization of the
///   parsed module (trailing junk bytes, alternate encodings,
///   etc.).
/// - [`AdamantValidationError::SuiVerifier`] if the parsed module
///   fails any inherited verifier pass.
/// - Per-rule variants for Adamant-specific rule failures.
///
/// # Panics
///
/// Panics only if Sui's serializer ever fails to re-serialize a
/// `CompiledModule` that Sui's deserializer just produced — an
/// invariant violation in the vendored Sui crates that would
/// indicate a bug in upstream serialise/deserialise symmetry.
/// In normal operation this branch is unreachable.
pub fn verify_module(
    module_bytes: &[u8],
    config: &AdamantVerifierConfig,
) -> Result<CompiledModule, AdamantValidationError> {
    // Step 1: deserialize. Rule 5 is enforced here — Sui's
    // deserializer rejects the 10 deprecated global-storage
    // variants at parse time when `deprecate_global_storage_ops`
    // is `true` (which AdamantVerifierConfig::new forces).
    // PartialVMError → VMError via .finish(Location::Undefined)
    // matches Sui's own pattern (see verifier.rs:106).
    let module = CompiledModule::deserialize_with_config(module_bytes, config.sui_binary_config())
        .map_err(|e| AdamantValidationError::SuiDeserializer(e.finish(Location::Undefined)))?;

    // Step 2: canonicality round-trip check. Re-serialise the
    // parsed module via Sui's serializer at the module's own
    // version and byte-compare against the input. This recovers
    // the canonicality `check_no_extraneous_bytes = true` would
    // otherwise have provided in Sui's deserializer config (see
    // `config.rs` for why we cannot enable that flag). Catches
    // trailing junk bytes after the documented binary format
    // and any other non-canonical encoding.
    let mut canonical_bytes = vec![];
    module
        .serialize_with_version(module.version, &mut canonical_bytes)
        .expect(
            "re-serialising a successfully-deserialised CompiledModule must succeed; \
             Sui's serializer accepts every module shape its deserializer produces",
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

    // Step 3: inherited Sui-Move verifier passes.
    move_bytecode_verifier::verifier::verify_module_with_config_unmetered(
        config.sui_verifier_config(),
        &module,
    )
    .map_err(AdamantValidationError::SuiVerifier)?;

    // Step 4: Adamant-specific rules in spec order.
    rule_01_mutability::verify(&module)?;
    rule_04_no_natives::verify(&module)?;
    // Rule 5 is enforced by step 1; no separate pass.
    // Rules 2, 3, 6, 7 (subsequent waves) slot in here.
    // Rule 8 is a no-op at deployment per §6.2.1.6 amendment
    // 804d9db (gas budget at runtime carries determinism per
    // §6.2.4); a single test asserting gas-bound loops aren't
    // statically rejected lands in the final wave.

    Ok(module)
}

#[cfg(test)]
mod tests {
    use super::test_fixtures::{
        module_without_mutability_metadata, serialize_module, valid_module,
    };
    use super::{verify_module, AdamantValidationError, AdamantVerifierConfig};

    #[test]
    fn valid_module_passes() {
        let m = valid_module();
        let bytes = serialize_module(&m);
        let config = AdamantVerifierConfig::new();
        let result = verify_module(&bytes, &config);
        assert!(
            result.is_ok(),
            "valid_module() must pass verification; failure indicates a fixture or wrapper bug. Got: {:?}",
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
             in the verifier config (defense in depth for §6.2.1.6 Rule 5)"
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
             in the binary config (Rule 5's primary enforcement point at deserialize)"
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
        let m = valid_module();
        let canonical = serialize_module(&m);
        let mut bytes = canonical.clone();
        bytes.push(0xAB);

        let config = AdamantVerifierConfig::new();
        let result = verify_module(&bytes, &config);
        match result {
            Err(AdamantValidationError::NonCanonicalBytecode {
                byte_offset,
                canonical_byte,
                input_byte,
            }) => {
                assert_eq!(
                    byte_offset,
                    canonical.len(),
                    "the trailing junk byte sits at the canonical's end-of-stream position"
                );
                assert_eq!(
                    canonical_byte, None,
                    "the canonical re-serialisation has no byte at this offset"
                );
                assert_eq!(
                    input_byte,
                    Some(0xAB),
                    "the input carries the trailing junk byte at this offset"
                );
            }
            other => panic!("expected NonCanonicalBytecode, got {other:?}"),
        }
    }

    #[test]
    fn rejects_module_with_multiple_trailing_junk_bytes() {
        // Same shape as the single-trailing-byte case; the
        // first trailing byte is what the diagnostic surfaces
        // (the wrapper reports the *first* divergence offset,
        // not all of them).
        let m = valid_module();
        let canonical = serialize_module(&m);
        let mut bytes = canonical.clone();
        bytes.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);

        let config = AdamantVerifierConfig::new();
        let result = verify_module(&bytes, &config);
        match result {
            Err(AdamantValidationError::NonCanonicalBytecode {
                byte_offset,
                canonical_byte,
                input_byte,
            }) => {
                assert_eq!(byte_offset, canonical.len());
                assert_eq!(canonical_byte, None);
                assert_eq!(
                    input_byte,
                    Some(0xDE),
                    "diagnostic reports the first trailing byte, not the whole tail"
                );
            }
            other => panic!("expected NonCanonicalBytecode, got {other:?}"),
        }
    }

    #[test]
    fn rich_canonical_module_round_trips() {
        // A non-trivial fixture (multiple metadata entries plus
        // a function and a struct from basic_test_module)
        // round-trips through the canonicality check cleanly.
        // This guards against regressions where serialise and
        // deserialise drift on richer module shapes.
        let m = super::test_fixtures::rich_valid_module();
        let bytes = serialize_module(&m);
        let config = AdamantVerifierConfig::new();
        let result = verify_module(&bytes, &config);
        assert!(
            result.is_ok(),
            "rich_valid_module() must round-trip canonically; failure indicates serialise/deserialise drift or a fixture bug. Got: {:?}",
            result.err()
        );
    }
}
