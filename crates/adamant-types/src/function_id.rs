//! Function identifier — UTF-8 string bounded to 255 bytes per
//! whitepaper section 6.0.7.
//!
//! Per whitepaper section 6.0.7:
//!
//! > "**`FunctionId`.** A UTF-8 string, length-bounded to 255 bytes:
//! >
//! > ```text
//! > FunctionId(String)
//! > ```
//! >
//! > with the constraint that the byte length of the string's UTF-8
//! > encoding is at most 255. Functions are identified by name
//! > within their containing module, not by integer index. This
//! > decouples transaction encoding from the module's internal
//! > function table layout — a module upgrade that re-orders its
//! > functions does not invalidate pending transactions referencing
//! > those functions, because the transaction names them. The
//! > 255-byte bound is a structural constraint enforced at decode
//! > time; transactions exceeding the bound are rejected. Encoded
//! > as `Vec<u8>` containing the UTF-8 bytes (ULEB128 length prefix
//! > followed by bytes)."
//!
//! Deserialisation routes through `String` and applies the bound via
//! `#[serde(try_from = "String")]`, ensuring that a malicious peer
//! cannot produce an oversized [`FunctionId`] by submitting a
//! crafted `Vec<u8>` length prefix — `bcs::from_bytes` rejects the
//! transaction at decode time.

use serde::{Deserialize, Serialize};

/// Maximum bytes in a UTF-8-encoded function name per whitepaper
/// section 6.0.7.
///
/// The bound is on UTF-8 byte length (`String::len()`), not
/// character count. A string of 200 four-byte CJK characters has
/// 200 chars but 800 bytes and exceeds the bound.
pub const FUNCTION_ID_MAX_BYTES: usize = 255;

/// A function identifier — UTF-8 string within the 255-byte bound
/// (whitepaper section 6.0.7).
///
/// Construct via [`FunctionId::new`] (returns a `Result`) for
/// untrusted input. Deserialisation enforces the bound automatically
/// via `#[serde(try_from = "String")]`: a serialised `String` whose
/// byte length exceeds [`FUNCTION_ID_MAX_BYTES`] is rejected at
/// decode time, so transactions carrying oversized function names
/// fail validation rather than being silently truncated.
#[derive(Clone, Eq, PartialEq, Hash, Debug, Serialize, Deserialize)]
#[serde(try_from = "String")]
pub struct FunctionId(String);

/// Error returned by [`FunctionId::new`] and the
/// [`TryFrom<String>`] conversion when input violates whitepaper
/// section 6.0.7's bounds.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum FunctionIdError {
    /// UTF-8 byte length exceeds [`FUNCTION_ID_MAX_BYTES`].
    TooLong,
}

impl core::fmt::Display for FunctionIdError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::TooLong => write!(
                f,
                "FunctionId UTF-8 byte length exceeds {FUNCTION_ID_MAX_BYTES} (whitepaper §6.0.7)"
            ),
        }
    }
}

impl std::error::Error for FunctionIdError {}

impl FunctionId {
    /// Construct a [`FunctionId`] from a [`String`], validating the
    /// UTF-8 byte-length bound from whitepaper section 6.0.7.
    ///
    /// # Errors
    ///
    /// Returns [`FunctionIdError::TooLong`] when `name`'s UTF-8 byte
    /// length exceeds [`FUNCTION_ID_MAX_BYTES`].
    pub fn new(name: String) -> Result<Self, FunctionIdError> {
        if name.len() > FUNCTION_ID_MAX_BYTES {
            return Err(FunctionIdError::TooLong);
        }
        Ok(Self(name))
    }

    /// Borrow the function name as a `&str`.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for FunctionId {
    type Error = FunctionIdError;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::new(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn declared_bound_matches_whitepaper() {
        assert_eq!(FUNCTION_ID_MAX_BYTES, 255);
    }

    #[test]
    fn accepts_typical_name() {
        let id = FunctionId::new("transfer".to_string()).expect("valid");
        assert_eq!(id.as_str(), "transfer");
    }

    #[test]
    fn accepts_empty_name() {
        // The bound is an upper bound; the lower end is not constrained.
        // Whether the runtime rejects empty names is a §6.2.1 / §6.4
        // bytecode-validator concern, not encoding.
        let id = FunctionId::new(String::new()).expect("valid");
        assert_eq!(id.as_str(), "");
    }

    #[test]
    fn accepts_exactly_255_bytes() {
        let s = "a".repeat(FUNCTION_ID_MAX_BYTES);
        let id = FunctionId::new(s.clone()).expect("valid at the bound");
        assert_eq!(id.as_str(), s);
    }

    #[test]
    fn rejects_256_bytes() {
        let s = "a".repeat(FUNCTION_ID_MAX_BYTES + 1);
        let err = FunctionId::new(s).expect_err("over bound");
        assert_eq!(err, FunctionIdError::TooLong);
    }

    /// A UTF-8 string whose `chars().count()` is below the bound
    /// but whose `String::len()` (byte length) exceeds it: the bound
    /// is on bytes, not characters. 100 four-byte glyphs = 400 bytes
    /// > 255, must be rejected.
    #[test]
    fn rejects_byte_overflow_with_low_char_count() {
        // U+1F600 (😀) is 4 bytes in UTF-8.
        let s: String = "\u{1F600}".repeat(100);
        assert!(s.chars().count() < FUNCTION_ID_MAX_BYTES);
        assert!(s.len() > FUNCTION_ID_MAX_BYTES);
        let err = FunctionId::new(s).expect_err("byte length over bound");
        assert_eq!(err, FunctionIdError::TooLong);
    }

    /// BCS roundtrip: a [`FunctionId`] tuple struct serialises as
    /// the inner [`String`], which BCS encodes as ULEB128 length +
    /// UTF-8 bytes per whitepaper 5.1.8.
    #[test]
    fn bcs_round_trip() {
        let id = FunctionId::new("transfer_with_lock".to_string()).expect("valid");
        let encoded = bcs::to_bytes(&id).expect("bcs encode");
        // ULEB128 of 18 = single byte 0x12, then 18 UTF-8 bytes.
        assert_eq!(encoded[0], 18);
        assert_eq!(&encoded[1..], "transfer_with_lock".as_bytes());

        let decoded: FunctionId = bcs::from_bytes(&encoded).expect("bcs decode");
        assert_eq!(decoded, id);
    }

    /// Deserialisation enforces the bound: a BCS-encoded `String`
    /// of 256 bytes is rejected at decode time, not silently
    /// accepted as a `FunctionId`. The protection exists because the
    /// `FunctionId` byte length is a consensus-relevant constraint
    /// per whitepaper 6.0.7; a peer that sends an oversize name
    /// produces a transaction that fails validation rather than
    /// being interpreted as a truncated valid one.
    ///
    /// The assertion pins the error's *origin*: rejection must come
    /// from [`FunctionId::new`]'s bound check (which propagates
    /// [`FunctionIdError::TooLong`] through `#[serde(try_from)]` to
    /// BCS's error type), not from an unrelated BCS error path. The
    /// substring `"FunctionId UTF-8 byte length exceeds"` is unique
    /// to the [`FunctionIdError::TooLong`] [`Display`] impl; if a
    /// future refactor changes the rejection source the test fails
    /// rather than silently passing on some other `Err` value.
    #[test]
    fn deserialisation_rejects_oversize() {
        let oversize: String = "a".repeat(FUNCTION_ID_MAX_BYTES + 1);
        let encoded = bcs::to_bytes(&oversize).expect("encode oversize String");
        let result: Result<FunctionId, _> = bcs::from_bytes(&encoded);
        let err = result.expect_err("decoder must reject oversize FunctionId per §6.0.7");
        let err_msg = format!("{err}");
        assert!(
            err_msg.contains("FunctionId UTF-8 byte length exceeds"),
            "rejection must originate from the 255-byte bound check in FunctionId::new, \
             not from another error path. Got: {err_msg}"
        );
    }
}
