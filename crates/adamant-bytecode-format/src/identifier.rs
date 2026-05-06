//! `Identifier` — a name for a Move entity (module, struct,
//! function, etc.).
//!
//! Forked from `move-core-types/src/identifier.rs` at Sui-Move
//! tag `mainnet-v1.66.2`. See `PROVENANCE.md` for the upstream
//! lineage and the enumerated set of items that were and were
//! not forked.
//!
//! # Adamant deviations from upstream
//!
//! - The borrowed `IdentStr` companion type is not forked.
//!   Upstream's `IdentStr` relies on `RefCast` (an `unsafe`
//!   transmute) and the `ident_str!` macro (compile-time
//!   validated identifier construction) relies on a
//!   `transmute::<&'static str, &'static IdentStr>`. Both
//!   conflict with Adamant's workspace `#![forbid(unsafe_code)]`
//!   policy. `Identifier` carries `as_str()`, `len()`, and
//!   `is_empty()` directly so callers don't need `&IdentStr`.
//! - `Identifier::new_unchecked` (the `unsafe` constructor) is
//!   not forked; Adamant's parsing path always validates.
//! - `Identifier::abstract_size_for_gas_metering` is not forked
//!   (depends on Sui's `gas_algebra::AbstractMemorySize`, which
//!   Adamant does not use).
//! - `Identifier::new` returns `Result<Self, InvalidIdentifier>`
//!   rather than upstream's `Result<Self, anyhow::Error>`. The
//!   acceptance set is byte-identical to upstream.

use core::fmt;
use core::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Returns `true` if this character can appear in a Move
/// identifier (after the first position).
///
/// Note: there are stricter restrictions on whether a character
/// can begin a Move identifier — only alphabetic characters are
/// allowed at the leading position.
#[inline]
#[must_use]
pub const fn is_valid_identifier_char(c: char) -> bool {
    matches!(c, '_' | 'a'..='z' | 'A'..='Z' | '0'..='9')
}

/// Returns `true` if all bytes in `b` after the offset
/// `start_offset` are valid ASCII identifier characters.
const fn all_bytes_valid(b: &[u8], start_offset: usize) -> bool {
    let mut i = start_offset;
    while i < b.len() {
        if !is_valid_identifier_char(b[i] as char) {
            return false;
        }
        i += 1;
    }
    true
}

/// Returns `true` if `s` is a valid Move identifier.
///
/// A valid identifier consists of an ASCII string which satisfies
/// either:
///
/// - The first character is a letter and the remaining characters
///   are letters, digits, or underscores.
/// - The first character is an underscore, and there is at least
///   one further letter, digit, or underscore.
///
/// Allowed identifiers are restricted to ASCII; non-ASCII strings
/// are rejected.
#[must_use]
pub const fn is_valid(s: &str) -> bool {
    // Rust const fn's don't currently support slicing or indexing
    // &str's, so we operate on the underlying byte slice. This is
    // not a problem as valid identifiers are (currently)
    // ASCII-only.
    let b = s.as_bytes();
    match b {
        [b'a'..=b'z' | b'A'..=b'Z', ..] => all_bytes_valid(b, 1),
        [b'_', ..] if b.len() > 1 => all_bytes_valid(b, 1),
        _ => false,
    }
}

/// Error returned by [`Identifier::new`] and
/// [`Identifier::from_utf8`] when the input does not form a
/// valid Move identifier.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub struct InvalidIdentifier;

impl fmt::Display for InvalidIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid Move identifier")
    }
}

impl std::error::Error for InvalidIdentifier {}

/// An owned identifier.
///
/// Identifiers are validated on construction; once constructed,
/// the wrapped `Box<str>` is guaranteed to satisfy [`is_valid`].
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Identifier(Box<str>);

impl Serialize for Identifier {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for Identifier {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Self::new(s).map_err(serde::de::Error::custom)
    }
}

impl Identifier {
    /// Creates a new `Identifier`, validating that `s` is a valid
    /// Move identifier per [`is_valid`].
    ///
    /// # Errors
    ///
    /// Returns [`InvalidIdentifier`] if the input fails the
    /// validation.
    pub fn new(s: impl Into<Box<str>>) -> Result<Self, InvalidIdentifier> {
        let s = s.into();
        if Self::is_valid(&s) {
            Ok(Self(s))
        } else {
            Err(InvalidIdentifier)
        }
    }

    /// Returns `true` if `s` is a valid Move identifier.
    pub fn is_valid(s: impl AsRef<str>) -> bool {
        is_valid(s.as_ref())
    }

    /// Converts a UTF-8 byte vector to an `Identifier`. Returns
    /// [`InvalidIdentifier`] for non-UTF-8 input or for valid UTF-8
    /// that fails identifier validation.
    ///
    /// # Errors
    ///
    /// [`InvalidIdentifier`] in either failure case.
    pub fn from_utf8(vec: Vec<u8>) -> Result<Self, InvalidIdentifier> {
        let s = String::from_utf8(vec).map_err(|_| InvalidIdentifier)?;
        Self::new(s)
    }

    /// Returns the identifier as a `&str`.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns the identifier as a UTF-8 byte slice.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    /// Returns the identifier's length in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns `true` if the identifier has zero bytes. Always
    /// `false` for a valid `Identifier` (the validator rejects
    /// empty strings), but provided for API symmetry.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Converts this `Identifier` into its underlying `String`.
    ///
    /// Not implemented as `From` to discourage automatic
    /// conversions.
    #[must_use]
    pub fn into_string(self) -> String {
        self.0.into()
    }

    /// Converts this `Identifier` into its UTF-8 byte
    /// representation.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.into_string().into_bytes()
    }
}

impl FromStr for Identifier {
    type Err = InvalidIdentifier;

    fn from_str(data: &str) -> Result<Self, InvalidIdentifier> {
        Self::new(data)
    }
}

impl AsRef<str> for Identifier {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// The pool of [`Identifier`]s used by a module.
pub type IdentifierPool = Vec<Identifier>;

impl fmt::Display for Identifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", &self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_valid_identifiers() {
        for s in ["foo", "_foo", "foo_bar", "F00", "Foo123", "_x", "_0", "a"] {
            assert!(is_valid(s), "should accept {s:?}");
            assert!(
                Identifier::new(s).is_ok(),
                "Identifier::new should accept {s:?}"
            );
        }
    }

    #[test]
    fn rejects_invalid_identifiers() {
        // Empty
        assert!(!is_valid(""));
        // Bare underscore
        assert!(!is_valid("_"));
        // Leading digit
        assert!(!is_valid("1foo"));
        // Embedded space
        assert!(!is_valid("foo bar"));
        // Non-ASCII
        assert!(!is_valid("résumé"));
        // Special characters
        assert!(!is_valid("foo-bar"));
        assert!(!is_valid("foo+bar"));
        assert!(!is_valid("foo.bar"));
    }

    #[test]
    fn identifier_new_returns_invalid_identifier_on_reject() {
        assert_eq!(Identifier::new("1foo").unwrap_err(), InvalidIdentifier);
        assert_eq!(Identifier::new("").unwrap_err(), InvalidIdentifier);
    }

    #[test]
    fn from_utf8_accepts_valid() {
        let id = Identifier::from_utf8(b"foo".to_vec()).unwrap();
        assert_eq!(id.as_str(), "foo");
    }

    #[test]
    fn from_utf8_rejects_invalid_utf8() {
        // 0xFF is not valid UTF-8
        let bytes = vec![0xFFu8];
        assert_eq!(Identifier::from_utf8(bytes).unwrap_err(), InvalidIdentifier);
    }

    #[test]
    fn as_str_round_trips() {
        let id = Identifier::new("hello").unwrap();
        assert_eq!(id.as_str(), "hello");
        assert_eq!(id.as_bytes(), b"hello");
        assert_eq!(id.len(), 5);
        assert!(!id.is_empty());
    }

    #[test]
    fn into_string_consumes_identifier() {
        let id = Identifier::new("foo").unwrap();
        assert_eq!(id.into_string(), "foo");
    }

    #[test]
    fn from_str_works() {
        let id: Identifier = "Bar".parse().unwrap();
        assert_eq!(id.as_str(), "Bar");
    }

    #[test]
    fn display_writes_inner() {
        let id = Identifier::new("DisplayTest").unwrap();
        assert_eq!(format!("{id}"), "DisplayTest");
    }

    #[test]
    fn ord_compares_lexicographically() {
        let a = Identifier::new("a").unwrap();
        let b = Identifier::new("b").unwrap();
        assert!(a < b);
    }

    #[test]
    fn invalid_identifier_display_populated() {
        assert!(!format!("{InvalidIdentifier}").is_empty());
    }
}
