//! Validator Rule 4 (whitepaper §6.2.1.6 #4):
//! no native functions.
//!
//! Every function definition in Adamant Move must have a
//! bytecode body. Sui-Move marks a native function with
//! `code: None` on its [`FunctionDefinition`]; Adamant rejects
//! any such marker. Per §6.1.4, performance-critical primitives
//! are exposed through Adamant-specific instructions
//! ([`crate::AdamantBytecode`] per §6.2.1.4) rather than
//! through bytecode-bypass natives.

use move_binary_format::file_format::{CompiledModule, FunctionDefinitionIndex};

use super::error::AdamantValidationError;

/// Verify §6.2.1.6 Rule 4 against `module`.
///
/// Returns [`AdamantValidationError::NativeFunctionForbidden`]
/// for the first function definition with `code: None`; returns
/// [`Ok`] if every function definition has a bytecode body.
pub(super) fn verify(module: &CompiledModule) -> Result<(), AdamantValidationError> {
    for (idx, function_def) in module.function_defs.iter().enumerate() {
        if function_def.code.is_none() {
            return Err(AdamantValidationError::NativeFunctionForbidden {
                // Sui-Move's binary format limits function
                // definitions to a u16-indexable count (the
                // `FunctionDefinitionIndex` newtype wraps `u16`
                // and the upstream serialiser uses ULEB128 with
                // the same width bound), so the cast is provably
                // bounded by the format itself. `try_from` is
                // used over `as u16` to make the bound explicit.
                function_index: FunctionDefinitionIndex(u16::try_from(idx).expect(
                    "function definition count exceeds u16; \
                         Sui-Move's binary format precludes this",
                )),
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::test_fixtures::{module_with_native_function, valid_module};
    use super::super::AdamantValidationError;
    use super::verify;

    #[test]
    fn accepts_valid_module() {
        // valid_module has zero function defs, so Rule 4 is
        // vacuously satisfied.
        let m = valid_module();
        assert!(verify(&m).is_ok());
    }

    #[test]
    fn rejects_module_with_native_function() {
        let m = module_with_native_function();
        match verify(&m) {
            Err(AdamantValidationError::NativeFunctionForbidden { function_index }) => {
                assert_eq!(
                    function_index.0, 0,
                    "the test fixture installs the native function at \
                     function definition index 0; verifier should report it"
                );
            }
            other => panic!("expected NativeFunctionForbidden, got {other:?}"),
        }
    }
}
