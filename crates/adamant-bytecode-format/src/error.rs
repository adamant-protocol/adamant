//! Error types for the bytecode-format primitives.
//!
//! [`ReaderError`] is the closed error type returned by the
//! ULEB128/LE reader functions in [`crate::format_common`]. It
//! replaces Sui-Move's `anyhow::Result` at the reader boundary —
//! see `PROVENANCE.md` for the rationale.

/// Errors from the byte-stream readers.
///
/// Closed by design: forward extension via new explicit variants
/// when needed; closed enums are easier to pattern-match against
/// and document the full failure surface at one location.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub enum ReaderError {
    /// Cursor reached end-of-stream before the expected number of
    /// bytes could be read.
    UnexpectedEof,
    /// ULEB128 byte sequence is malformed: overflow past `u64`,
    /// non-canonical encoding (trailing zero-padding past the
    /// terminator), or stream ended before the terminator byte.
    MalformedUleb128,
}

impl core::fmt::Display for ReaderError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnexpectedEof => write!(f, "unexpected end of byte stream"),
            Self::MalformedUleb128 => write!(f, "malformed ULEB128 sequence"),
        }
    }
}

impl std::error::Error for ReaderError {}
