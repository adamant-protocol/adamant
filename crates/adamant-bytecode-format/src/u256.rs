//! `U256` — a 256-bit unsigned-integer value type.
//!
//! Forked from `move-core-types/src/u256.rs` at Sui-Move tag
//! `mainnet-v1.66.2`. See `PROVENANCE.md`.
//!
//! # Adamant deviation: thin newtype with serde + equality only
//!
//! Adamant's bytecode-format `U256` is a thin newtype around
//! `[u8; 32]` carrying serde + equality + hash + default. It
//! deliberately does **not** carry arithmetic operations (`+`,
//! `-`, `*`, `/`, `%`, shifts, comparisons), conversion to/from
//! integer widths beyond `[u8; 32]`, or numeric formatting.
//!
//! Reason: bytecode-level `U256` is a constant-pool /
//! immediate-operand value type. It is constructed during
//! deserialization (parsing `Bytecode::LdU256`'s 32 little-
//! endian operand bytes) and consumed when the AVM executor
//! pushes it onto the operand stack. Arithmetic is the
//! executor's concern, not the bytecode-format layer's.
//!
//! Arithmetic is **intentionally deferred** to the AVM runtime
//! sub-arc (whitepaper §6.3 / Phase 5/6.3). The implementation
//! choice for runtime `U256` (fork Sui's full `u256` module,
//! adopt a third-party crate such as `primitive-types` or
//! `ethnum`, or implement in-repo) will be made deliberately as
//! a first-order architectural decision in that sub-arc — not
//! as a leftover from bytecode-format work. This file's surface
//! is sufficient for parsing, serializing, equality-comparing,
//! and round-tripping `U256` values through the binary format
//! and serde, which is everything the bytecode-format layer
//! requires.
//!
//! # Wire encoding
//!
//! The 32-byte storage is little-endian, matching Sui-Move's
//! `write_u256` (and the binary-format operand encoding for
//! `LdU256` per whitepaper §6.2.1.5). Serde's default for
//! `[u8; 32]` produces a 32-byte sequence in BCS — byte-
//! identical to upstream's BCS shape.

use core::fmt;

use serde::{Deserialize, Serialize};

/// A 256-bit unsigned integer, stored as 32 little-endian bytes.
///
/// **Bytecode-format-layer only.** Arithmetic is deferred; see
/// the module-level deviation note. For computation on `U256`
/// values, the AVM runtime sub-arc will pick an implementation
/// per whitepaper §6.3.
#[derive(Clone, Copy, Default, Eq, Hash, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub struct U256(pub [u8; 32]);

impl U256 {
    /// The zero value: 32 zero bytes.
    pub const ZERO: Self = Self([0u8; 32]);

    /// The maximum value: 32 `0xFF` bytes.
    pub const MAX: Self = Self([0xFFu8; 32]);

    /// Construct from a 32-byte little-endian representation.
    #[must_use]
    pub const fn from_le_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Return the 32-byte little-endian representation.
    #[must_use]
    pub const fn to_le_bytes(self) -> [u8; 32] {
        self.0
    }
}

impl fmt::Debug for U256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Hex format mirrors Sui's debug output shape for
        // diagnostic readability. The exact hex string is not a
        // consensus surface — debug output is for humans, not
        // the wire encoding.
        write!(f, "U256(0x")?;
        // Print the bytes in big-endian order so the leading
        // hex digit is the MSB, the conventional reading of
        // a hex-encoded integer.
        for byte in self.0.iter().rev() {
            write!(f, "{byte:02x}")?;
        }
        write!(f, ")")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `ZERO` and `MAX` constants are pinned.
    #[test]
    fn constants_pinned() {
        assert_eq!(U256::ZERO.0, [0u8; 32]);
        assert_eq!(U256::MAX.0, [0xFFu8; 32]);
    }

    /// `from_le_bytes` / `to_le_bytes` round-trip.
    #[test]
    fn le_bytes_round_trip() {
        let bytes: [u8; 32] = core::array::from_fn(|i| u8::try_from(i).unwrap());
        let v = U256::from_le_bytes(bytes);
        assert_eq!(v.to_le_bytes(), bytes);
    }

    /// `Default` returns `ZERO`.
    #[test]
    fn default_is_zero() {
        assert_eq!(U256::default(), U256::ZERO);
    }

    /// Equality is byte-equality.
    #[test]
    fn equality_is_byte_equal() {
        let a = U256([1u8; 32]);
        let b = U256([1u8; 32]);
        let c = U256([2u8; 32]);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    /// `Debug` prints `U256(0x...)` with the bytes in big-endian
    /// hex (MSB first).
    #[test]
    fn debug_format() {
        let mut bytes = [0u8; 32];
        bytes[0] = 0x01; // LSB
        bytes[31] = 0xFE; // MSB
        let v = U256(bytes);
        let s = format!("{v:?}");
        assert!(s.starts_with("U256(0xfe"), "got: {s}");
        assert!(s.ends_with("01)"), "got: {s}");
    }
}
