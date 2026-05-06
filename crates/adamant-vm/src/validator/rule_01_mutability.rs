//! Validator Rule 1 (whitepaper §6.2.1.6 #1):
//! mutability metadata required.
//!
//! Every module must carry exactly one `b"adamant.mutability"`
//! metadata entry per §6.2.1.3, whose value is the BCS encoding
//! of [`adamant_types::Mutability`]. Modules without it, with
//! more than one, or with malformed value bytes are rejected.

use adamant_types::Mutability;

use crate::module::AdamantCompiledModule;

use super::error::AdamantValidationError;

/// Per whitepaper §6.2.1.3, the metadata key under which the
/// module's [`Mutability`] declaration is BCS-encoded.
const MUTABILITY_METADATA_KEY: &[u8] = b"adamant.mutability";

/// Verify §6.2.1.6 Rule 1 against `module`.
///
/// Returns:
/// - [`Ok`] if exactly one `b"adamant.mutability"` entry exists
///   and its value BCS-decodes as [`Mutability`].
/// - [`AdamantValidationError::MissingMutabilityMetadata`] if
///   no entry exists.
/// - [`AdamantValidationError::MultipleMutabilityMetadata`] if
///   more than one entry exists.
/// - [`AdamantValidationError::MalformedMutabilityMetadata`] if
///   the (single) entry's value is not a valid BCS encoding of
///   `Mutability`.
pub(super) fn verify(module: &AdamantCompiledModule) -> Result<(), AdamantValidationError> {
    let entries: Vec<&move_core_types::metadata::Metadata> = module
        .metadata
        .iter()
        .filter(|m| m.key == MUTABILITY_METADATA_KEY)
        .collect();

    match entries.len() {
        0 => Err(AdamantValidationError::MissingMutabilityMetadata),
        1 => {
            // Exactly one entry. Validate well-formedness by
            // attempting BCS deserialisation as Mutability;
            // discard the decoded value (we only care that it
            // decodes; the value is not consumed by the
            // validator). Future rules may stash the decoded
            // value for cross-checks (e.g., upgrade-time rules
            // needing the previous and new mutability), but
            // that's a Wave-later concern.
            bcs::from_bytes::<Mutability>(&entries[0].value).map_err(|e| {
                AdamantValidationError::MalformedMutabilityMetadata {
                    bcs_error: format!("{e}"),
                }
            })?;
            Ok(())
        }
        n => Err(AdamantValidationError::MultipleMutabilityMetadata { count: n }),
    }
}

#[cfg(test)]
mod tests {
    use super::super::test_fixtures::{
        module_with_malformed_mutability_metadata, module_with_two_mutability_entries,
        module_without_mutability_metadata, valid_module,
    };
    use super::super::AdamantValidationError;
    use super::verify;

    #[test]
    fn accepts_valid_module() {
        let m = valid_module();
        assert!(verify(&m).is_ok());
    }

    #[test]
    fn rejects_module_without_mutability_metadata() {
        let m = module_without_mutability_metadata();
        match verify(&m) {
            Err(AdamantValidationError::MissingMutabilityMetadata) => {}
            other => panic!("expected MissingMutabilityMetadata, got {other:?}"),
        }
    }

    #[test]
    fn rejects_module_with_two_mutability_entries() {
        let m = module_with_two_mutability_entries();
        match verify(&m) {
            Err(AdamantValidationError::MultipleMutabilityMetadata { count: 2 }) => {}
            other => panic!("expected MultipleMutabilityMetadata {{ count: 2 }}, got {other:?}"),
        }
    }

    #[test]
    fn rejects_module_with_malformed_mutability_value() {
        let m = module_with_malformed_mutability_metadata();
        match verify(&m) {
            Err(AdamantValidationError::MalformedMutabilityMetadata { bcs_error }) => {
                assert!(
                    !bcs_error.is_empty(),
                    "BCS error string should not be empty; \
                     it carries diagnostic context for the caller"
                );
            }
            other => panic!("expected MalformedMutabilityMetadata, got {other:?}"),
        }
    }
}
