//! `U256` — a 256-bit unsigned-integer value type.
//!
//! Forked from `move-core-types/src/u256.rs` at Sui-Move tag
//! `mainnet-v1.66.2`. See `PROVENANCE.md`.
//!
//! # Adamant arithmetic semantics — whitepaper §6.2.1.9
//!
//! `U256` carries the in-repo arithmetic, comparison, shift, and
//! cast operations specified by whitepaper §6.2.1.9
//! ("Arithmetic semantics"). The implementation is Adamant-owned
//! per the Q2.2 disposition at Phase 5/6.2 plan-gate (option (c):
//! implement in-repo rather than fork Sui's `u256` module or
//! adopt a third-party crate). Rationale: U256 arithmetic
//! semantics are consensus-binding and genesis-fixed; protocol-
//! critical arithmetic stays under Adamant's audit and
//! maintenance with no production-side dependency churn.
//!
//! Per §6.2.1.9, all checked-arithmetic methods return `None` on
//! overflow / division-by-zero; the AVM runtime layer (Phase
//! 5/6.2b instruction handlers) wraps `None` into an
//! `ArithmeticError` and aborts the transaction with state
//! revert per §6.2.2 step 7. The U256 type itself does not
//! define an error type — the bytecode-format layer detects edge
//! cases and the runtime layer decides what to do (layer-
//! separation discipline).
//!
//! Wrapping-arithmetic methods are intentionally **not provided**.
//! Per §6.2.1.9 wrapping-arithmetic clause, the inherited
//! Bytecode enum contains no wrapping opcodes; adding wrapping
//! opcodes is a hard fork. `wrapping_add` / `wrapping_sub` /
//! `wrapping_mul` / `wrapping_shl` / `wrapping_shr` would be
//! dead code at the bytecode-format layer.
//!
//! # Wire encoding
//!
//! The 32-byte storage is little-endian, matching Sui-Move's
//! `write_u256` (and the binary-format operand encoding for
//! `LdU256` per whitepaper §6.2.1.5). Serde's default for
//! `[u8; 32]` produces a 32-byte sequence in BCS — byte-
//! identical to upstream's BCS shape.
//!
//! # Comparison-ordering correctness
//!
//! The byte storage is little-endian, but unsigned-integer
//! comparison ordering per §6.2.1.9 requires MSB-first
//! comparison. Rust's default `Ord`/`PartialOrd` derive on
//! `[u8; 32]` would compare LSB-first (lexicographic byte
//! order from index 0) which gives the **wrong answer** for
//! unsigned integers — for example, the value 1 (`[0x01, 0,
//! ..., 0]`) would compare greater than the value 512 (`[0x00,
//! 0x02, 0, ..., 0]`) under derived `Ord`. The manual `Ord`
//! impl below compares bytes from index 31 down to index 0
//! (MSB-first), giving the correct unsigned-integer ordering
//! per §6.2.1.9 ("All integer comparisons interpret integer
//! operands as unsigned").

use core::cmp::Ordering;
use core::fmt;
use core::ops::{BitAnd, BitOr, BitXor, Not, Shl, Shr};

use serde::{Deserialize, Serialize};

/// A 256-bit unsigned integer, stored as 32 little-endian bytes.
///
/// Arithmetic, comparison, shift, and cast operations follow
/// whitepaper §6.2.1.9 semantics. Comparison is MSB-first
/// (unsigned-integer ordering) via the manual `Ord` impl below;
/// `Ord` and `PartialOrd` are **not** derived because the
/// derived ordering on `[u8; 32]` storage is LSB-first and
/// therefore incorrect for unsigned-integer semantics.
#[derive(Clone, Copy, Default, Eq, Hash, PartialEq, Serialize, Deserialize)]
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

    /// Whether the value is zero.
    #[must_use]
    pub fn is_zero(self) -> bool {
        self.0.iter().all(|&b| b == 0)
    }

    // ---------- internal limb helpers ----------

    /// Decompose into four 64-bit little-endian limbs. Limb 0
    /// holds the LSB; limb 3 holds the MSB.
    fn to_limbs(self) -> [u64; 4] {
        [
            u64::from_le_bytes([
                self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5], self.0[6],
                self.0[7],
            ]),
            u64::from_le_bytes([
                self.0[8], self.0[9], self.0[10], self.0[11], self.0[12], self.0[13], self.0[14],
                self.0[15],
            ]),
            u64::from_le_bytes([
                self.0[16], self.0[17], self.0[18], self.0[19], self.0[20], self.0[21], self.0[22],
                self.0[23],
            ]),
            u64::from_le_bytes([
                self.0[24], self.0[25], self.0[26], self.0[27], self.0[28], self.0[29], self.0[30],
                self.0[31],
            ]),
        ]
    }

    /// Reassemble from four 64-bit little-endian limbs.
    fn from_limbs(limbs: [u64; 4]) -> Self {
        let mut bytes = [0u8; 32];
        let l0 = limbs[0].to_le_bytes();
        let l1 = limbs[1].to_le_bytes();
        let l2 = limbs[2].to_le_bytes();
        let l3 = limbs[3].to_le_bytes();
        bytes[0..8].copy_from_slice(&l0);
        bytes[8..16].copy_from_slice(&l1);
        bytes[16..24].copy_from_slice(&l2);
        bytes[24..32].copy_from_slice(&l3);
        Self(bytes)
    }

    // ---------- arithmetic (§6.2.1.9 overflow handling) ----------

    /// `self + rhs` with overflow detection per §6.2.1.9
    /// overflow handling. Returns `None` when the mathematical
    /// sum exceeds `2^256 - 1`. The runtime layer wraps `None`
    /// into an arithmetic-error abort.
    #[must_use]
    pub fn checked_add(self, rhs: Self) -> Option<Self> {
        let a = self.to_limbs();
        let b = rhs.to_limbs();
        let mut result = [0u64; 4];
        let mut carry: u64 = 0;
        for i in 0..4 {
            let (sum1, c1) = a[i].overflowing_add(b[i]);
            let (sum2, c2) = sum1.overflowing_add(carry);
            result[i] = sum2;
            carry = u64::from(c1) + u64::from(c2);
        }
        if carry != 0 {
            return None;
        }
        Some(Self::from_limbs(result))
    }

    /// `self - rhs` with underflow detection per §6.2.1.9
    /// overflow handling. Returns `None` when `rhs > self`.
    #[must_use]
    pub fn checked_sub(self, rhs: Self) -> Option<Self> {
        let a = self.to_limbs();
        let b = rhs.to_limbs();
        let mut result = [0u64; 4];
        let mut borrow: u64 = 0;
        for i in 0..4 {
            let (diff1, b1) = a[i].overflowing_sub(b[i]);
            let (diff2, b2) = diff1.overflowing_sub(borrow);
            result[i] = diff2;
            borrow = u64::from(b1) + u64::from(b2);
        }
        if borrow != 0 {
            return None;
        }
        Some(Self::from_limbs(result))
    }

    /// `self * rhs` with overflow detection per §6.2.1.9
    /// overflow handling. Returns `None` when the mathematical
    /// product exceeds `2^256 - 1`.
    ///
    /// Implementation: schoolbook multiplication accumulating
    /// `a[i] * b[j]` into an 8-limb (512-bit) buffer; the result
    /// fits in 256 bits if and only if the upper 4 limbs are all
    /// zero.
    #[must_use]
    #[allow(
        clippy::cast_possible_truncation,
        reason = "the `as u64` casts are deliberate split of u128 product into low/high u64 halves; this is the standard schoolbook-multiplication idiom"
    )]
    pub fn checked_mul(self, rhs: Self) -> Option<Self> {
        let a = self.to_limbs();
        let b = rhs.to_limbs();
        let mut buffer = [0u64; 8];
        // Schoolbook multiplication ladder. For each row `i`,
        // compute `a[i] * b` shifted left by `i` limbs and add to
        // buffer. The u128 accumulator at each position holds
        // `a[i]*b[j] + buffer[i+j] + carry`, which never exceeds
        // `(2^64-1)^2 + 2*(2^64-1) = 2^128 - 1` and therefore
        // fits in `u128` without overflow.
        for i in 0..4 {
            let mut carry: u64 = 0;
            for j in 0..4 {
                let product = u128::from(a[i]) * u128::from(b[j])
                    + u128::from(buffer[i + j])
                    + u128::from(carry);
                buffer[i + j] = product as u64;
                carry = (product >> 64) as u64;
            }
            // After the inner loop, `carry` lands at position
            // `i + 4`. That position is touched by the inner
            // loop only at j = 3 of the next outer iteration
            // (where it is read-modified-written via the
            // accumulator). For i=0, position 4 was previously
            // zero; for i=1, position 5 was zero; etc. So the
            // assignment is safe (no prior nonzero value to
            // preserve).
            buffer[i + 4] = carry;
        }
        // Result fits in 256 bits iff upper 4 limbs are all zero.
        if buffer[4] != 0 || buffer[5] != 0 || buffer[6] != 0 || buffer[7] != 0 {
            return None;
        }
        Some(Self::from_limbs([
            buffer[0], buffer[1], buffer[2], buffer[3],
        ]))
    }

    /// `self / rhs` with abort-on-zero detection per §6.2.1.9
    /// division semantics. Returns `None` when `rhs` is zero.
    /// The result is the integer quotient (floor division for
    /// unsigned).
    #[must_use]
    pub fn checked_div(self, rhs: Self) -> Option<Self> {
        if rhs.is_zero() {
            return None;
        }
        Some(self.divmod_unchecked(rhs).0)
    }

    /// `self % rhs` with abort-on-zero detection per §6.2.1.9
    /// division semantics. Returns `None` when `rhs` is zero.
    #[must_use]
    pub fn checked_rem(self, rhs: Self) -> Option<Self> {
        if rhs.is_zero() {
            return None;
        }
        Some(self.divmod_unchecked(rhs).1)
    }

    /// Long-division helper. Caller must ensure `rhs != 0`.
    /// Returns `(quotient, remainder)`.
    fn divmod_unchecked(self, rhs: Self) -> (Self, Self) {
        // Bit-shift schoolbook long division. Iterate from the
        // most-significant bit of `self` down to the least; at
        // each step shift the remainder left by 1, OR in the
        // current bit of `self`, and subtract `rhs` from the
        // remainder if remainder >= rhs (recording a 1-bit at
        // the corresponding position in the quotient).
        let mut quotient = Self::ZERO;
        let mut remainder = Self::ZERO;
        for i in (0..256).rev() {
            // Shift remainder left by 1.
            remainder = remainder.shl(1);
            // OR in bit i of self.
            let byte_idx = i / 8;
            let bit_idx = i % 8;
            let bit = (self.0[byte_idx] >> bit_idx) & 1;
            remainder.0[0] |= bit;
            // If remainder >= rhs, subtract rhs and set bit i of quotient.
            if remainder.cmp(&rhs) != Ordering::Less {
                // checked_sub cannot return None because remainder >= rhs.
                remainder = remainder
                    .checked_sub(rhs)
                    .expect("remainder >= rhs by branch condition");
                quotient.0[byte_idx] |= 1 << bit_idx;
            }
        }
        (quotient, remainder)
    }

    // (Bitwise and shift operations live as `core::ops` trait
    // impls below the inherent-method block; see `impl BitAnd`,
    // `impl BitOr`, `impl BitXor`, `impl Not`, `impl Shl<u8>`,
    // `impl Shr<u8>` for the §6.2.1.9 semantics.)

    // ---------- widening conversions (§6.2.1.9 cast widening) ----------

    /// Construct from a `u8` per §6.2.1.9 widening cast
    /// semantics. Always succeeds (the source value is
    /// representable in `u256` by zero-extension).
    #[must_use]
    pub fn from_u8(value: u8) -> Self {
        let mut bytes = [0u8; 32];
        bytes[0] = value;
        Self(bytes)
    }

    /// Construct from a `u16` per §6.2.1.9 widening cast
    /// semantics. Always succeeds.
    #[must_use]
    pub fn from_u16(value: u16) -> Self {
        let mut bytes = [0u8; 32];
        bytes[0..2].copy_from_slice(&value.to_le_bytes());
        Self(bytes)
    }

    /// Construct from a `u32` per §6.2.1.9 widening cast
    /// semantics. Always succeeds.
    #[must_use]
    pub fn from_u32(value: u32) -> Self {
        let mut bytes = [0u8; 32];
        bytes[0..4].copy_from_slice(&value.to_le_bytes());
        Self(bytes)
    }

    /// Construct from a `u64` per §6.2.1.9 widening cast
    /// semantics. Always succeeds.
    #[must_use]
    pub fn from_u64(value: u64) -> Self {
        let mut bytes = [0u8; 32];
        bytes[0..8].copy_from_slice(&value.to_le_bytes());
        Self(bytes)
    }

    /// Construct from a `u128` per §6.2.1.9 widening cast
    /// semantics. Always succeeds.
    #[must_use]
    pub fn from_u128(value: u128) -> Self {
        let mut bytes = [0u8; 32];
        bytes[0..16].copy_from_slice(&value.to_le_bytes());
        Self(bytes)
    }

    // ---------- narrowing conversions (§6.2.1.9 cast narrowing) ----------

    /// Convert to `u8` per §6.2.1.9 narrowing cast semantics.
    /// Returns `None` when the source value exceeds `u8::MAX`.
    #[must_use]
    pub fn try_into_u8(self) -> Option<u8> {
        if self.0[1..].iter().all(|&b| b == 0) {
            Some(self.0[0])
        } else {
            None
        }
    }

    /// Convert to `u16` per §6.2.1.9 narrowing cast semantics.
    /// Returns `None` when the source value exceeds `u16::MAX`.
    #[must_use]
    pub fn try_into_u16(self) -> Option<u16> {
        if self.0[2..].iter().all(|&b| b == 0) {
            Some(u16::from_le_bytes([self.0[0], self.0[1]]))
        } else {
            None
        }
    }

    /// Convert to `u32` per §6.2.1.9 narrowing cast semantics.
    /// Returns `None` when the source value exceeds `u32::MAX`.
    #[must_use]
    pub fn try_into_u32(self) -> Option<u32> {
        if self.0[4..].iter().all(|&b| b == 0) {
            Some(u32::from_le_bytes([
                self.0[0], self.0[1], self.0[2], self.0[3],
            ]))
        } else {
            None
        }
    }

    /// Convert to `u64` per §6.2.1.9 narrowing cast semantics.
    /// Returns `None` when the source value exceeds `u64::MAX`.
    #[must_use]
    pub fn try_into_u64(self) -> Option<u64> {
        if self.0[8..].iter().all(|&b| b == 0) {
            Some(u64::from_le_bytes([
                self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5], self.0[6],
                self.0[7],
            ]))
        } else {
            None
        }
    }

    /// Convert to `u128` per §6.2.1.9 narrowing cast semantics.
    /// Returns `None` when the source value exceeds `u128::MAX`.
    #[must_use]
    pub fn try_into_u128(self) -> Option<u128> {
        if self.0[16..].iter().all(|&b| b == 0) {
            Some(u128::from_le_bytes([
                self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5], self.0[6],
                self.0[7], self.0[8], self.0[9], self.0[10], self.0[11], self.0[12], self.0[13],
                self.0[14], self.0[15],
            ]))
        } else {
            None
        }
    }
}

// ---------- comparison ordering (§6.2.1.9 unsigned-integer comparison) ----------

impl Ord for U256 {
    /// Unsigned-integer comparison per whitepaper §6.2.1.9
    /// comparison ordering. Compares bytes MSB-first (index 31
    /// down to index 0) — the storage is little-endian, so the
    /// most-significant byte lives at the highest index.
    ///
    /// The derived `Ord` on `[u8; 32]` would compare LSB-first
    /// (lexicographic byte order from index 0) and produce the
    /// wrong result for unsigned-integer ordering; this manual
    /// impl replaces it.
    fn cmp(&self, other: &Self) -> Ordering {
        for i in (0..32).rev() {
            let ord = self.0[i].cmp(&other.0[i]);
            if ord != Ordering::Equal {
                return ord;
            }
        }
        Ordering::Equal
    }
}

impl PartialOrd for U256 {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

// ---------- bitwise (§6.2.1.9: no abort conditions) ----------

impl BitAnd for U256 {
    type Output = Self;
    fn bitand(self, rhs: Self) -> Self {
        Self(core::array::from_fn(|i| self.0[i] & rhs.0[i]))
    }
}

impl BitOr for U256 {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self(core::array::from_fn(|i| self.0[i] | rhs.0[i]))
    }
}

impl BitXor for U256 {
    type Output = Self;
    fn bitxor(self, rhs: Self) -> Self {
        Self(core::array::from_fn(|i| self.0[i] ^ rhs.0[i]))
    }
}

impl Not for U256 {
    type Output = Self;
    fn not(self) -> Self {
        Self(core::array::from_fn(|i| !self.0[i]))
    }
}

// ---------- shifts (§6.2.1.9 shift amount bounds) ----------

impl Shl<u8> for U256 {
    type Output = Self;

    /// Left shift by `n_bits` per §6.2.1.9 shift amount bounds.
    /// For U256, no abort condition applies — the shift amount
    /// is necessarily less than 256 (the operand's bit width)
    /// because `n_bits` is parsed as a `u8`. The result is
    /// computed as the unsigned-integer shift `lhs << n_bits`
    /// modulo `2^256`.
    #[allow(
        clippy::needless_range_loop,
        reason = "the bit-shift carry logic indexes both `result` and `self.0` from the loop variable, with conditional access at index `i - byte_shift - 1`; iterator-based access does not simplify this"
    )]
    fn shl(self, n_bits: u8) -> Self {
        let n = n_bits as usize;
        if n == 0 {
            return self;
        }
        let byte_shift = n / 8;
        let bit_shift = n % 8;
        if byte_shift >= 32 {
            return Self::ZERO;
        }
        let mut result = [0u8; 32];
        if bit_shift == 0 {
            // Pure byte-shift.
            result[byte_shift..32].copy_from_slice(&self.0[..32 - byte_shift]);
        } else {
            for i in byte_shift..32 {
                let lo = self.0[i - byte_shift] << bit_shift;
                let hi = if i - byte_shift > 0 {
                    self.0[i - byte_shift - 1] >> (8 - bit_shift)
                } else {
                    0
                };
                result[i] = lo | hi;
            }
        }
        Self(result)
    }
}

impl Shr<u8> for U256 {
    type Output = Self;

    /// Right shift by `n_bits` per §6.2.1.9 shift amount bounds.
    /// For U256, no abort condition applies (analogous to `shl`).
    /// The result is computed as the unsigned-integer shift
    /// `lhs >> n_bits`.
    #[allow(
        clippy::needless_range_loop,
        reason = "the bit-shift carry logic indexes both `result` and `self.0` from the loop variable, with conditional access at index `i + byte_shift + 1`; iterator-based access does not simplify this"
    )]
    fn shr(self, n_bits: u8) -> Self {
        let n = n_bits as usize;
        if n == 0 {
            return self;
        }
        let byte_shift = n / 8;
        let bit_shift = n % 8;
        if byte_shift >= 32 {
            return Self::ZERO;
        }
        let mut result = [0u8; 32];
        if bit_shift == 0 {
            result[..32 - byte_shift].copy_from_slice(&self.0[byte_shift..]);
        } else {
            for i in 0..(32 - byte_shift) {
                let lo = self.0[i + byte_shift] >> bit_shift;
                let hi = if i + byte_shift + 1 < 32 {
                    self.0[i + byte_shift + 1] << (8 - bit_shift)
                } else {
                    0
                };
                result[i] = lo | hi;
            }
        }
        Self(result)
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
    //! Each test's doc-comment registers a verbatim whitepaper
    //! §6.2.1.9 quote grounding the expected outcome — 2nd
    //! instance of the verbatim-spec-quote-grounds-runtime-
    //! fixture discipline (1st instance was at Phase 5/6.1).

    use super::*;

    fn u256_from_u64_lsb(value: u64) -> U256 {
        U256::from_u64(value)
    }

    // ---------- existing constructor / round-trip / debug tests ----------

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

    /// Whitepaper §6.2.1.9 (verbatim) — equality framing under
    /// the broader semantics: "byte-identity is equivalent to
    /// value equality at the unsigned-integer ... interpretation."
    #[test]
    fn is_zero_pinned() {
        assert!(U256::ZERO.is_zero());
        assert!(!U256::MAX.is_zero());
        assert!(!U256::from_u8(1).is_zero());
    }

    // ---------- comparison ordering (§6.2.1.9 unsigned comparison) ----------

    /// Whitepaper §6.2.1.9 (verbatim): "All integer comparisons
    /// (`Lt`, `Gt`, `Le`, `Ge`) interpret integer operands as
    /// unsigned. ... `Lt(a, b)` returns `true` if and only if
    /// the unsigned-integer interpretation of `a` is strictly
    /// less than the unsigned-integer interpretation of `b`."
    ///
    /// This is the load-bearing counter-example demonstrating
    /// that the manual MSB-first `Ord` impl produces correct
    /// unsigned-integer ordering. The derived `Ord` on
    /// `[u8; 32]` (LSB-first lexicographic) would give the wrong
    /// answer here.
    #[test]
    fn ord_unsigned_counter_example_one_vs_five_hundred_twelve() {
        // Value 1 = byte 0 LSB = 0x01.
        let one = U256::from_u64(1);
        // Value 512 = 2 * 256 = byte 1 contains 0x02.
        let five_twelve = U256::from_u64(512);
        // Unsigned comparison: 1 < 512.
        assert!(one < five_twelve);
        assert!(five_twelve > one);
        assert_eq!(one.cmp(&five_twelve), Ordering::Less);
    }

    /// Whitepaper §6.2.1.9 (verbatim): "All integer comparisons
    /// interpret integer operands as unsigned."
    ///
    /// Boundary: ZERO compares less than every non-zero value;
    /// MAX compares greater than every non-MAX value.
    #[test]
    fn ord_zero_and_max_boundaries() {
        let one = U256::from_u8(1);
        let mid = U256::from_u128(u128::MAX);
        assert!(U256::ZERO < one);
        assert!(U256::ZERO < mid);
        assert!(U256::ZERO < U256::MAX);
        assert!(one < U256::MAX);
        assert!(mid < U256::MAX);
    }

    /// Whitepaper §6.2.1.9 (verbatim): equal operands compare
    /// equal under `Lt`/`Gt`/`Le`/`Ge`.
    #[test]
    fn ord_equal_values_compare_equal() {
        let a = U256::from_u64(0x1234_5678_9ABC_DEF0);
        let b = U256::from_u64(0x1234_5678_9ABC_DEF0);
        assert_eq!(a.cmp(&b), Ordering::Equal);
        assert!(a <= b);
        assert!(a >= b);
        assert!(a >= b);
        assert!(a <= b);
    }

    /// Multi-byte cross-byte comparison: differences at the MSB
    /// dominate differences at lower bytes, per unsigned-integer
    /// ordering.
    #[test]
    fn ord_msb_difference_dominates_lsb_difference() {
        let mut bytes_a = [0xFFu8; 32];
        bytes_a[31] = 0x10; // MSB = 0x10
        bytes_a[0] = 0xFF; // LSB = 0xFF (large in LSB-only view)
        let mut bytes_b = [0u8; 32];
        bytes_b[31] = 0x20; // MSB = 0x20
        bytes_b[0] = 0x00; // LSB = 0x00 (small in LSB-only view)
        let a = U256(bytes_a);
        let b = U256(bytes_b);
        // Unsigned MSB-first: a.MSB=0x10 < b.MSB=0x20 → a < b.
        assert!(a < b);
    }

    /// Whitepaper §6.2.1.9 (verbatim): comparisons are
    /// "well-defined for any pair of operands of the same
    /// integer type."
    ///
    /// Reversibility / antisymmetry: if `a < b` then `b >= a`
    /// and `a != b`.
    #[test]
    fn ord_antisymmetric() {
        let a = U256::from_u64(100);
        let b = U256::from_u64(200);
        assert!(a < b);
        assert!(b >= a);
        assert_ne!(a, b);
    }

    // ---------- arithmetic: overflow handling (§6.2.1.9) ----------

    /// Whitepaper §6.2.1.9 (verbatim): "`Add`, `Sub`, and `Mul`
    /// abort when the result of the operation would fall outside
    /// the operand type's unsigned integer range."
    #[test]
    fn checked_add_within_range_succeeds() {
        let a = U256::from_u64(100);
        let b = U256::from_u64(200);
        assert_eq!(a.checked_add(b), Some(U256::from_u64(300)));
    }

    /// Whitepaper §6.2.1.9 (verbatim): overflow on `Add` returns
    /// abort (None at U256 layer).
    #[test]
    fn checked_add_overflow_returns_none() {
        assert_eq!(U256::MAX.checked_add(U256::from_u8(1)), None);
    }

    /// Identity: `a + 0 = a` for any a.
    #[test]
    fn checked_add_zero_is_identity() {
        let a = U256::from_u64(0xDEAD_BEEF);
        assert_eq!(a.checked_add(U256::ZERO), Some(a));
    }

    /// Carry propagation across limb boundaries.
    #[test]
    fn checked_add_carries_across_limbs() {
        let a = U256::from_u64(u64::MAX);
        let b = U256::from_u64(1);
        // Sum = 2^64. Should occupy byte 8 (limb 1, position 0).
        let sum = a.checked_add(b).expect("no overflow");
        let mut expected_bytes = [0u8; 32];
        expected_bytes[8] = 1;
        assert_eq!(sum, U256(expected_bytes));
    }

    /// Whitepaper §6.2.1.9 (verbatim): `Sub` aborts on underflow.
    #[test]
    fn checked_sub_within_range_succeeds() {
        let a = U256::from_u64(300);
        let b = U256::from_u64(100);
        assert_eq!(a.checked_sub(b), Some(U256::from_u64(200)));
    }

    /// Underflow: `0 - 1` returns None.
    #[test]
    fn checked_sub_underflow_returns_none() {
        assert_eq!(U256::ZERO.checked_sub(U256::from_u8(1)), None);
    }

    /// Identity: `a - 0 = a`.
    #[test]
    fn checked_sub_zero_is_identity() {
        let a = U256::from_u64(0xDEAD_BEEF);
        assert_eq!(a.checked_sub(U256::ZERO), Some(a));
    }

    /// Borrow propagation across limb boundaries.
    #[test]
    fn checked_sub_borrows_across_limbs() {
        // 2^64 - 1.
        let mut a_bytes = [0u8; 32];
        a_bytes[8] = 1;
        let a = U256(a_bytes);
        let b = U256::from_u64(1);
        let diff = a.checked_sub(b).expect("no underflow");
        assert_eq!(diff, U256::from_u64(u64::MAX));
    }

    /// Whitepaper §6.2.1.9 (verbatim): `Mul` aborts on overflow.
    #[test]
    fn checked_mul_within_range_succeeds() {
        let a = U256::from_u64(7);
        let b = U256::from_u64(11);
        assert_eq!(a.checked_mul(b), Some(U256::from_u64(77)));
    }

    /// Multiplication identity: `a * 1 = a`.
    #[test]
    fn checked_mul_one_is_identity() {
        let a = U256::from_u64(0xDEAD_BEEF);
        assert_eq!(a.checked_mul(U256::from_u8(1)), Some(a));
    }

    /// Multiplication absorbs zero: `a * 0 = 0`.
    #[test]
    fn checked_mul_by_zero_is_zero() {
        let a = U256::from_u64(0xDEAD_BEEF);
        assert_eq!(a.checked_mul(U256::ZERO), Some(U256::ZERO));
    }

    /// Cross-limb multiplication: `(2^64) * (2^64)` should
    /// produce `2^128`, which is representable in U256.
    #[test]
    fn checked_mul_cross_limb_within_range() {
        let mut bytes_a = [0u8; 32];
        bytes_a[8] = 1; // value 2^64
        let a = U256(bytes_a);
        let product = a.checked_mul(a).expect("2^128 fits in U256");
        let mut expected = [0u8; 32];
        expected[16] = 1; // 2^128
        assert_eq!(product, U256(expected));
    }

    /// Multiplication overflow: `MAX * 2` exceeds `2^256 - 1`.
    #[test]
    fn checked_mul_overflow_returns_none() {
        assert_eq!(U256::MAX.checked_mul(U256::from_u8(2)), None);
    }

    /// `MAX * MAX` overflows by far more than 2× MAX.
    #[test]
    fn checked_mul_max_squared_overflows() {
        assert_eq!(U256::MAX.checked_mul(U256::MAX), None);
    }

    // ---------- arithmetic: division / modulo (§6.2.1.9) ----------

    /// Whitepaper §6.2.1.9 (verbatim): "`Div` and `Mod` abort
    /// when the right-hand operand (the divisor) is zero."
    #[test]
    fn checked_div_by_zero_returns_none() {
        let a = U256::from_u64(100);
        assert_eq!(a.checked_div(U256::ZERO), None);
        assert_eq!(U256::ZERO.checked_div(U256::ZERO), None);
    }

    /// Basic division: 100 / 10 = 10, 100 % 10 = 0.
    #[test]
    fn checked_div_and_rem_basic() {
        let a = U256::from_u64(100);
        let b = U256::from_u64(10);
        assert_eq!(a.checked_div(b), Some(U256::from_u64(10)));
        assert_eq!(a.checked_rem(b), Some(U256::ZERO));
    }

    /// Division with remainder: 100 / 7 = 14, 100 % 7 = 2.
    #[test]
    fn checked_div_with_remainder() {
        let a = U256::from_u64(100);
        let b = U256::from_u64(7);
        assert_eq!(a.checked_div(b), Some(U256::from_u64(14)));
        assert_eq!(a.checked_rem(b), Some(U256::from_u64(2)));
    }

    /// Division by larger divisor: 5 / 10 = 0, 5 % 10 = 5.
    #[test]
    fn checked_div_dividend_smaller_than_divisor() {
        let a = U256::from_u64(5);
        let b = U256::from_u64(10);
        assert_eq!(a.checked_div(b), Some(U256::ZERO));
        assert_eq!(a.checked_rem(b), Some(U256::from_u64(5)));
    }

    /// Division identity: `a / 1 = a`, `a % 1 = 0`.
    #[test]
    fn checked_div_by_one_is_identity() {
        let a = U256::from_u64(0xDEAD_BEEF);
        assert_eq!(a.checked_div(U256::from_u8(1)), Some(a));
        assert_eq!(a.checked_rem(U256::from_u8(1)), Some(U256::ZERO));
    }

    /// Whitepaper §6.2.1.9 (verbatim): `Mod` aborts on zero divisor.
    #[test]
    fn checked_rem_by_zero_returns_none() {
        let a = U256::from_u64(100);
        assert_eq!(a.checked_rem(U256::ZERO), None);
    }

    /// `MAX / MAX = 1`; `MAX % MAX = 0`.
    #[test]
    fn checked_div_max_by_max() {
        assert_eq!(U256::MAX.checked_div(U256::MAX), Some(U256::from_u8(1)));
        assert_eq!(U256::MAX.checked_rem(U256::MAX), Some(U256::ZERO));
    }

    // ---------- bitwise (no abort conditions) ----------

    /// Whitepaper §6.2.1.9 (verbatim): bitwise ops are part of
    /// the inherited Bytecode enum (`BitOr`, `BitAnd`, `Xor`)
    /// with no abort conditions.
    #[test]
    fn bitand_pinned() {
        let a = U256([0xFFu8; 32]);
        let b = U256([0x0Fu8; 32]);
        assert_eq!(a.bitand(b), U256([0x0Fu8; 32]));
    }

    #[test]
    fn bitor_pinned() {
        let a = U256([0xF0u8; 32]);
        let b = U256([0x0Fu8; 32]);
        assert_eq!(a.bitor(b), U256([0xFFu8; 32]));
    }

    #[test]
    fn bitxor_pinned() {
        let a = U256([0xFFu8; 32]);
        let b = U256([0x0Fu8; 32]);
        assert_eq!(a.bitxor(b), U256([0xF0u8; 32]));
    }

    #[test]
    fn not_pinned() {
        assert_eq!(U256::ZERO.not(), U256::MAX);
        assert_eq!(U256::MAX.not(), U256::ZERO);
    }

    // ---------- shifts (§6.2.1.9 shift amount bounds) ----------

    /// Whitepaper §6.2.1.9 (verbatim): "For operand type `u256`,
    /// no abort condition applies: the shift amount is
    /// necessarily less than 256 (the operand's bit width)
    /// because the shift amount is parsed as a `u8`. ... The
    /// shift result for `u256` is well-defined for every `u8`
    /// shift amount in `[0, 255]`, computed as the unsigned-
    /// integer shift `lhs << rhs` (or `lhs >> rhs`) modulo
    /// `2^256`."
    #[test]
    fn shl_by_zero_is_identity() {
        let a = U256::from_u64(0xDEAD_BEEF);
        assert_eq!(a.shl(0), a);
    }

    #[test]
    fn shl_by_one_doubles() {
        let a = U256::from_u64(0x4000_0000);
        assert_eq!(a.shl(1), U256::from_u64(0x8000_0000));
    }

    #[test]
    fn shl_across_byte_boundary() {
        let a = U256::from_u8(1);
        // Shift by 8 → byte 1 = 0x01.
        let shifted = a.shl(8);
        let mut expected = [0u8; 32];
        expected[1] = 1;
        assert_eq!(shifted, U256(expected));
    }

    /// `n_bits = 255` is the maximum representable shift amount.
    /// For U256, this produces a value with only the MSB set
    /// (or zero if the source LSB was 0).
    #[test]
    fn shl_by_max_n_bits_pinned() {
        let one = U256::from_u8(1);
        let shifted = one.shl(255);
        let mut expected = [0u8; 32];
        expected[31] = 0x80; // bit 255 = byte 31 bit 7
        assert_eq!(shifted, U256(expected));
    }

    /// Whitepaper §6.2.1.9 (verbatim): "modulo `2^256`" — bits
    /// shifted past position 255 are discarded.
    #[test]
    fn shl_overflow_drops_bits_above_255() {
        let mut bytes = [0u8; 32];
        bytes[31] = 0x80; // bit 255 set
        let a = U256(bytes);
        let shifted = a.shl(1);
        // Bit 255 shifts off; result is zero (modulo 2^256).
        assert_eq!(shifted, U256::ZERO);
    }

    #[test]
    fn shr_by_zero_is_identity() {
        let a = U256::from_u64(0xDEAD_BEEF);
        assert_eq!(a.shr(0), a);
    }

    #[test]
    fn shr_by_one_halves() {
        let a = U256::from_u64(0x8000_0000);
        assert_eq!(a.shr(1), U256::from_u64(0x4000_0000));
    }

    #[test]
    fn shr_across_byte_boundary() {
        let mut bytes = [0u8; 32];
        bytes[1] = 1; // value 256
        let a = U256(bytes);
        let shifted = a.shr(8);
        assert_eq!(shifted, U256::from_u8(1));
    }

    #[test]
    fn shr_drops_bits_below_zero() {
        let a = U256::from_u8(1);
        // Shift right by 1: low bit drops; result is zero.
        assert_eq!(a.shr(1), U256::ZERO);
    }

    /// Round-trip: `shr(shl(x, n), n)` recovers `x` when the
    /// shifted-out bits are zero.
    #[test]
    fn shl_shr_round_trip_when_no_bits_lost() {
        let a = U256::from_u64(0x1234_5678);
        let shifted = a.shl(64).shr(64);
        assert_eq!(shifted, a);
    }

    // ---------- widening conversions (§6.2.1.9 cast widening) ----------

    /// Whitepaper §6.2.1.9 (verbatim): "*Widening cast* ...
    /// always succeeds; the source value is representable in
    /// the destination type by zero-extension."
    #[test]
    fn from_u8_widening_succeeds() {
        assert_eq!(U256::from_u8(0).to_le_bytes(), [0u8; 32]);
        let one = U256::from_u8(1);
        let mut expected = [0u8; 32];
        expected[0] = 1;
        assert_eq!(one.to_le_bytes(), expected);
        assert_eq!(U256::from_u8(0xFF).to_le_bytes()[0], 0xFF);
    }

    #[test]
    fn from_u16_widening_succeeds() {
        let v = U256::from_u16(0x1234);
        assert_eq!(v.to_le_bytes()[0], 0x34);
        assert_eq!(v.to_le_bytes()[1], 0x12);
        assert!(v.to_le_bytes()[2..].iter().all(|&b| b == 0));
    }

    #[test]
    fn from_u32_widening_succeeds() {
        let v = U256::from_u32(u32::MAX);
        assert_eq!(&v.to_le_bytes()[0..4], &[0xFF, 0xFF, 0xFF, 0xFF]);
        assert!(v.to_le_bytes()[4..].iter().all(|&b| b == 0));
    }

    #[test]
    fn from_u64_widening_succeeds() {
        let v = U256::from_u64(u64::MAX);
        assert!(v.to_le_bytes()[0..8].iter().all(|&b| b == 0xFF));
        assert!(v.to_le_bytes()[8..].iter().all(|&b| b == 0));
    }

    #[test]
    fn from_u128_widening_succeeds() {
        let v = U256::from_u128(u128::MAX);
        assert!(v.to_le_bytes()[0..16].iter().all(|&b| b == 0xFF));
        assert!(v.to_le_bytes()[16..].iter().all(|&b| b == 0));
    }

    // ---------- narrowing conversions (§6.2.1.9 cast narrowing) ----------

    /// Whitepaper §6.2.1.9 (verbatim): "*Narrowing cast* ...
    /// succeeds when the source value lies within the
    /// destination type's representable range; otherwise the
    /// runtime aborts with a runtime arithmetic error."
    #[test]
    fn try_into_u8_within_range_succeeds() {
        assert_eq!(U256::from_u8(0).try_into_u8(), Some(0));
        assert_eq!(U256::from_u8(0xFF).try_into_u8(), Some(0xFF));
    }

    #[test]
    fn try_into_u8_out_of_range_returns_none() {
        let v = U256::from_u16(0x100); // 256
        assert_eq!(v.try_into_u8(), None);
        assert_eq!(U256::MAX.try_into_u8(), None);
    }

    #[test]
    fn try_into_u16_within_range_succeeds() {
        assert_eq!(U256::from_u16(0).try_into_u16(), Some(0));
        assert_eq!(U256::from_u16(u16::MAX).try_into_u16(), Some(u16::MAX));
    }

    #[test]
    fn try_into_u16_out_of_range_returns_none() {
        let v = U256::from_u32(u32::from(u16::MAX) + 1);
        assert_eq!(v.try_into_u16(), None);
    }

    #[test]
    fn try_into_u32_within_range_succeeds() {
        assert_eq!(U256::from_u32(u32::MAX).try_into_u32(), Some(u32::MAX));
    }

    #[test]
    fn try_into_u32_out_of_range_returns_none() {
        let v = U256::from_u64(u64::from(u32::MAX) + 1);
        assert_eq!(v.try_into_u32(), None);
    }

    #[test]
    fn try_into_u64_within_range_succeeds() {
        assert_eq!(U256::from_u64(u64::MAX).try_into_u64(), Some(u64::MAX));
    }

    #[test]
    fn try_into_u64_out_of_range_returns_none() {
        let v = U256::from_u128(u128::from(u64::MAX) + 1);
        assert_eq!(v.try_into_u64(), None);
    }

    #[test]
    fn try_into_u128_within_range_succeeds() {
        assert_eq!(U256::from_u128(u128::MAX).try_into_u128(), Some(u128::MAX));
    }

    #[test]
    fn try_into_u128_out_of_range_returns_none() {
        // 2^128.
        let mut bytes = [0u8; 32];
        bytes[16] = 1;
        let v = U256(bytes);
        assert_eq!(v.try_into_u128(), None);
    }

    /// Same-type cast round-trip: `from_uN(x).try_into_uN()`
    /// should always recover `x` for valid input.
    #[test]
    fn cast_same_type_round_trip() {
        // u64 round-trip
        let x: u64 = 0xDEAD_BEEF_CAFE_BABE;
        assert_eq!(u256_from_u64_lsb(x).try_into_u64(), Some(x));
        // u128 round-trip
        let y: u128 = 0x1234_5678_9ABC_DEF0_FEDC_BA98_7654_3210;
        assert_eq!(U256::from_u128(y).try_into_u128(), Some(y));
    }
}
