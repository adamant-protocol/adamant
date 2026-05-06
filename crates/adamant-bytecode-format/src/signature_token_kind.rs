//! `SignatureTokenKind`: the kind of a signature token.
//!
//! Forked from `move-binary-format/src/lib.rs` at Sui-Move tag
//! `mainnet-v1.66.2`. See `PROVENANCE.md`. Byte-identity with
//! upstream is asserted by `tests/cross_validation.rs`.
//!
//! This kind is consumed by [`SignatureToken::signature_token_kind`]
//! (lands alongside [`SignatureToken`] in Phase 5/5b.1b's type-body
//! fork).
//!
//! [`SignatureToken`]: super::signature_token::SignatureToken
//! [`SignatureToken::signature_token_kind`]: super::signature_token::SignatureToken::signature_token_kind

use core::fmt;

/// The kind of a [`SignatureToken`]: a value, an immutable
/// reference, or a mutable reference.
///
/// [`SignatureToken`]: super::signature_token::SignatureToken
#[derive(Copy, Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Hash)]
pub enum SignatureTokenKind {
    /// Any owned value that isn't a reference (Integer, Bool,
    /// Datatype, Vector, etc).
    Value,
    /// An immutable reference.
    Reference,
    /// A mutable reference.
    MutableReference,
}

impl fmt::Display for SignatureTokenKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let desc = match self {
            Self::Value => "value",
            Self::Reference => "reference",
            Self::MutableReference => "mutable reference",
        };
        f.write_str(desc)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// All three variants display as the spec-pinned strings.
    #[test]
    fn display_strings_pinned() {
        assert_eq!(format!("{}", SignatureTokenKind::Value), "value");
        assert_eq!(format!("{}", SignatureTokenKind::Reference), "reference");
        assert_eq!(
            format!("{}", SignatureTokenKind::MutableReference),
            "mutable reference"
        );
    }

    /// `Ord` derives match the variant declaration order:
    /// `Value < Reference < MutableReference`.
    #[test]
    fn ord_follows_declaration_order() {
        assert!(SignatureTokenKind::Value < SignatureTokenKind::Reference);
        assert!(SignatureTokenKind::Reference < SignatureTokenKind::MutableReference);
    }
}
