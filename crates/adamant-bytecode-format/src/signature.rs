//! Signature types and signature-pool aliases.
//!
//! Forked from `move-binary-format/src/file_format.rs` at Sui-Move
//! tag `mainnet-v1.66.2`. See `PROVENANCE.md`. Byte-identity with
//! upstream is asserted by `tests/cross_validation.rs`.
//!
//! A signature can describe a type (field, local) or a function
//! signature (return type and arguments). Both go into the
//! signature table; tagging is positional inside the binary
//! format.

use serde::{Deserialize, Serialize};

use crate::ability::AbilitySet;
use crate::signature_token::SignatureToken;

/// A type signature: a single [`SignatureToken`] wrapped for
/// pool storage.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct TypeSignature(pub SignatureToken);

/// A function signature: parameter types, return types, and
/// type-parameter constraints.
///
/// Upstream marks this as "deprecated, consider removed" — kept
/// here for byte-faithful parity with the binary-format version
/// pinned at §6.2.1.2.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct FunctionSignature {
    /// The list of return types.
    pub return_: Vec<SignatureToken>,
    /// The list of parameter types.
    pub parameters: Vec<SignatureToken>,
    /// Type formals (identified by their index into this vector)
    /// and their constraints.
    pub type_parameters: Vec<AbilitySet>,
}

/// A list of locals used by a function. Locals include the
/// arguments at positions `0..argc-1` and the function-local
/// variables at the higher positions.
#[derive(Clone, Debug, Default, Eq, Hash, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub struct Signature(pub Vec<SignatureToken>);

impl Signature {
    /// Number of locals in this signature.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns `true` if this signature has no locals.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// The pool of [`Signature`]s — every function definition's
/// locals and every operand-type list lives here.
pub type SignaturePool = Vec<Signature>;

/// The pool of [`TypeSignature`] instances. These are system
/// and user types and their composition (e.g., `&U64`).
pub type TypeSignaturePool = Vec<TypeSignature>;

#[cfg(test)]
mod tests {
    use super::*;

    /// Empty signature has length 0 and `is_empty()` returns
    /// true; a non-empty one returns false.
    #[test]
    fn signature_len_and_empty() {
        let empty = Signature(vec![]);
        assert_eq!(empty.len(), 0);
        assert!(empty.is_empty());

        let one = Signature(vec![SignatureToken::U64]);
        assert_eq!(one.len(), 1);
        assert!(!one.is_empty());
    }

    /// `Signature::default()` produces an empty signature.
    #[test]
    fn signature_default_is_empty() {
        let s = Signature::default();
        assert!(s.is_empty());
    }
}
