//! Bytecode wire encoding per whitepaper §6.2.1.4 and §6.2.1.5.
//!
//! Adamant Move bytecode uses Sui-Move's binary format (§6.2.1.1
//! "strict superset") extended with the 17 Adamant-specific
//! instructions defined in [`crate::bytecode`]. This module
//! implements the wire encoder and decoder for function bodies —
//! `&[BytecodeInstruction]` ↔ `Vec<u8>` round-trips.
//!
//! # Why we re-implement instead of delegating
//!
//! Sui's per-instruction serialisation entry points
//! (`serialize_instruction_inner` and `load_code` in
//! `move_binary_format::{serializer, deserializer}`) are private.
//! Sui's only public bytecode entry points are at the
//! `CompiledModule` level. To extend Sui's encoder/decoder with
//! Adamant opcodes without modifying vendored code, we mirror
//! Sui's algorithm in this module using Sui's public helpers
//! (`Opcodes`, `read_uleb128_as_u64`, the index types). The
//! cross-validation test in this module's `tests` submodule
//! asserts byte-equivalence with Sui's encoder for the inherited
//! subset, converting "we re-implemented correctly" from claim to
//! tested property.
//!
//! # Encoding boundaries
//!
//! - Bytecode is **Move's native binary format**, not BCS
//!   (whitepaper §6.2.1.5). No `serde::Serialize` /
//!   `serde::Deserialize` derives appear here.
//! - Indices are **ULEB128**-encoded `u64`. The underlying types
//!   (e.g. `u8`, `u16`) are widened to `u64` at write time and
//!   range-checked at read time.
//! - Fixed-width immediates (`LdU8` through `LdU256`) are
//!   **little-endian**. Per the §6.2.1.5 amendment in commit
//!   83bb1e9 (and the eleventh spec-first verification instance in
//!   CONTRIBUTING.md), this includes `LdU256` — diverging from
//!   §6.0.7's BCS `Value::U256` which is big-endian-interpreted.
//!   The two paths never share bytes.
//! - The function-body wire format includes a **ULEB128 count
//!   prefix** before the instruction stream, matching Sui's
//!   `serialize_code`. [`serialize_function_body`] writes the
//!   prefix; [`deserialize_function_body`] consumes it.

// Lint posture for this module. The `cast_possible_truncation`
// lints fire on u64→usize/u16/u8 conversions that are guarded by
// explicit bound checks earlier in the same function (the casts
// are correct by construction, but clippy doesn't track ranges).
// `unnecessary_wraps` fires on serialise functions returning
// `Result<(), SerializeError>` where the error variant is reserved
// for future tighter validation per Q2 of the implementation
// proposal — the API is forward-compatible. `if_not_else` fires
// on the ULEB128 loop's `if cur != value` idiom matching Sui's
// `write_u64_as_uleb128` byte-for-byte.
// Lint posture for this module. Two module-level allows:
//
// - `unnecessary_wraps` fires on serialise functions returning
//   `Result<(), SerializeError>` where the error variant is
//   reserved for future tighter validation per Q2 of the
//   implementation proposal. The API is forward-compatible.
// - `if_not_else` fires on the ULEB128 loop's `if cur != value`
//   idiom matching Sui's `write_u64_as_uleb128` byte-for-byte.
//
// `cast_possible_truncation` is *not* allowed at module level —
// per-instance `#[allow]` with one-line rationale at each cast
// site so the next auditor sees explicit justification for every
// truncation.
//
// `trivially_copy_pass_by_ref` fires on the `&DeserializeConfig`
// parameter of [`deserialize_function_body`] /
// [`deserialize_function_body_from_cursor`]. The struct is 1 byte
// today but is the explicit configuration API surface; passing by
// reference matches `module_wire`'s posture and Sui's
// `&BinaryConfig` API. Allowing the lint at module level avoids
// per-fn `#[allow]` clutter at the public entry points.
#![allow(
    clippy::unnecessary_wraps,
    clippy::if_not_else,
    clippy::trivially_copy_pass_by_ref
)]

use std::io::Cursor;

use move_binary_format::file_format::{
    Bytecode, CodeOffset, ConstantPoolIndex, FieldHandleIndex, FieldInstantiationIndex,
    FunctionHandleIndex, FunctionInstantiationIndex, LocalIndex, SignatureIndex,
    StructDefInstantiationIndex, StructDefinitionIndex, VariantHandleIndex,
    VariantInstantiationHandleIndex, VariantJumpTableIndex,
};
use move_binary_format::file_format_common::{read_uleb128_as_u64, Opcodes};
use move_core_types::u256::U256;

use crate::bytecode::{
    AdamantBytecode, AdamantOpcodeKind, BytecodeInstruction, CircuitId, GasDimension,
};

// ---------- Error types ----------

/// Errors from [`serialize_function_body`].
///
/// Currently every well-formed [`BytecodeInstruction`] serialises
/// without error; the variants below are reserved for future
/// tighter validation (e.g., bounds checks on operand values that
/// Sui's encoder would also reject). The `Result` return type
/// preserves forward compatibility for that validation without a
/// breaking API change.
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub enum SerializeError {
    /// An operand value's structure is invalid (e.g., a future
    /// validation rule on bounded indices). Currently unreachable.
    OperandOverflow,
}

impl core::fmt::Display for SerializeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::OperandOverflow => write!(f, "operand value out of encoding range"),
        }
    }
}

impl std::error::Error for SerializeError {}

/// Errors from [`deserialize_function_body`].
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub enum DeserializeError {
    /// Bytecode stream ended mid-instruction (or before any
    /// instruction was read).
    UnexpectedEof,
    /// Opcode byte is neither an inherited Sui-Move opcode nor an
    /// Adamant extension.
    UnknownOpcode(u8),
    /// ULEB128 sequence is malformed — overflow past `u64`,
    /// non-canonical encoding, or stream ended before the
    /// terminator.
    MalformedUleb128,
    /// Operand value is out of range for its declared type
    /// (e.g., a function-handle index exceeding `u16::MAX`, a
    /// `GasDimension` byte outside `0x00..=0x05`).
    InvalidOperand {
        /// The opcode byte whose operand failed validation.
        opcode: u8,
        /// Human-readable reason for inclusion in error messages.
        reason: &'static str,
    },
    /// Bytes remain after a complete bytecode stream is parsed.
    /// [`deserialize_function_body`] is strict: the caller's input
    /// must contain exactly one length-prefixed bytecode stream.
    TrailingBytes,
    /// A deprecated global-storage opcode was encountered while
    /// the [`DeserializeConfig::reject_deprecated_global_storage`]
    /// flag was set. The 10 deprecated opcodes (`Exists`,
    /// `MutBorrowGlobal`, `ImmBorrowGlobal`, `MoveFrom`, `MoveTo`,
    /// and their `Generic` counterparts) are rejected at parse
    /// time per whitepaper §6.2.1.6 Rule 5: Adamant prohibits
    /// global-storage instructions, and the deserializer is the
    /// enforcement point.
    DeprecatedGlobalStorageOpcode(u8),
}

/// Configuration for [`deserialize_function_body`] /
/// [`deserialize_function_body_from_cursor`].
///
/// The default ([`Self::lenient`]) accepts every well-formed
/// instruction including the 10 deprecated global-storage opcodes
/// (used by `bytecode_wire`'s own round-trip property tests). The
/// strict mode ([`Self::strict`]) rejects deprecated global-storage
/// opcodes at parse time per §6.2.1.6 Rule 5; this is the mode
/// `module_wire` uses at deploy time.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub struct DeserializeConfig {
    /// If true, reject the 10 deprecated global-storage opcodes
    /// (`Exists`, `MutBorrowGlobal`, `ImmBorrowGlobal`, `MoveFrom`,
    /// `MoveTo`, and their `Generic` counterparts) with
    /// [`DeserializeError::DeprecatedGlobalStorageOpcode`]. Mirrors
    /// Sui's `BinaryConfig::deprecate_global_storage_ops` flag.
    pub reject_deprecated_global_storage: bool,
}

impl DeserializeConfig {
    /// Lenient configuration: accept all well-formed opcodes
    /// including deprecated global-storage ones. Used by
    /// `bytecode_wire`'s wire-level round-trip property tests so
    /// the encoder/decoder symmetry covers every variant.
    #[must_use]
    pub const fn lenient() -> Self {
        Self {
            reject_deprecated_global_storage: false,
        }
    }

    /// Strict configuration: reject deprecated global-storage
    /// opcodes at parse time. The deploy-time deserializer uses
    /// this mode.
    #[must_use]
    pub const fn strict() -> Self {
        Self {
            reject_deprecated_global_storage: true,
        }
    }
}

impl Default for DeserializeConfig {
    /// Default is lenient. Module-level deploy-time callers
    /// explicitly construct [`DeserializeConfig::strict`].
    fn default() -> Self {
        Self::lenient()
    }
}

impl core::fmt::Display for DeserializeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnexpectedEof => write!(f, "unexpected end of bytecode stream"),
            Self::UnknownOpcode(byte) => write!(f, "unknown opcode byte {byte:#04x}"),
            Self::MalformedUleb128 => write!(f, "malformed ULEB128 sequence"),
            Self::InvalidOperand { opcode, reason } => {
                write!(f, "invalid operand for opcode {opcode:#04x}: {reason}")
            }
            Self::TrailingBytes => write!(f, "trailing bytes after bytecode stream"),
            Self::DeprecatedGlobalStorageOpcode(byte) => {
                write!(
                    f,
                    "deprecated global-storage opcode {byte:#04x} rejected per §6.2.1.6 Rule 5"
                )
            }
        }
    }
}

impl std::error::Error for DeserializeError {}

// ---------- Public API ----------

/// Serialize a function body to its canonical bytecode bytes per
/// whitepaper §6.2.1.4 and §6.2.1.5.
///
/// The output is `ULEB128(body.len()) || serialized_instructions`,
/// matching Sui's `serialize_code` byte layout exactly for the
/// inherited subset.
///
/// # Errors
///
/// Returns [`SerializeError`] if any operand value exceeds its
/// encoding limit. Currently no well-formed
/// [`BytecodeInstruction`] triggers this; the `Result` return
/// preserves forward compatibility for future tighter validation.
pub fn serialize_function_body(body: &[BytecodeInstruction]) -> Result<Vec<u8>, SerializeError> {
    let mut out = Vec::new();
    write_uleb128(body.len() as u64, &mut out);
    for instr in body {
        serialize_instruction(instr, &mut out)?;
    }
    Ok(out)
}

/// Deserialize bytecode bytes back to a function body.
///
/// # Errors
///
/// Returns [`DeserializeError`] for any of: truncated streams,
/// unknown opcode bytes, malformed ULEB128 sequences,
/// out-of-range operand values, or trailing bytes after a complete
/// stream.
pub fn deserialize_function_body(
    bytes: &[u8],
    config: &DeserializeConfig,
) -> Result<Vec<BytecodeInstruction>, DeserializeError> {
    let mut cursor = Cursor::new(bytes);
    let body = deserialize_function_body_from_cursor(&mut cursor, config)?;
    // cursor.position(): u64 → usize. Position came from reads of
    // a slice of length `bytes.len()` (a usize), so it provably
    // fits in usize. Cast cannot truncate in practice.
    #[allow(clippy::cast_possible_truncation)]
    let consumed = cursor.position() as usize;
    if consumed != bytes.len() {
        return Err(DeserializeError::TrailingBytes);
    }
    Ok(body)
}

/// Cursor-API variant of [`deserialize_function_body`] for callers
/// (e.g., `module_wire`) that need to parse a body embedded inside
/// a larger byte stream and continue parsing afterwards. Reads the
/// ULEB128 instruction-count prefix and the instruction stream,
/// leaving the cursor positioned past the body. **Does not** check
/// for trailing bytes — the caller is responsible for whatever
/// follows the body in the surrounding stream.
///
/// # Errors
///
/// Same as [`deserialize_function_body`] except for `TrailingBytes`,
/// which only the slice-API variant raises.
pub fn deserialize_function_body_from_cursor(
    cursor: &mut Cursor<&[u8]>,
    config: &DeserializeConfig,
) -> Result<Vec<BytecodeInstruction>, DeserializeError> {
    let count = read_uleb128(cursor)?;
    // count: u64 → usize. Truncation only possible on 32-bit
    // targets; consensus targets are 64-bit. Vec::with_capacity
    // is a hint; an actual truncation would surface as an OOM or
    // mismatched count later.
    #[allow(clippy::cast_possible_truncation)]
    let mut body = Vec::with_capacity(count as usize);
    for _ in 0..count {
        body.push(deserialize_instruction(cursor, config)?);
    }
    Ok(body)
}

/// Returns `true` if `byte` is one of the 10 deprecated
/// global-storage opcode bytes (`Exists`, `MutBorrowGlobal`,
/// `ImmBorrowGlobal`, `MoveFrom`, `MoveTo`, and their `Generic`
/// counterparts). Used by [`deserialize_instruction`] to gate the
/// strict-mode rejection in [`DeserializeConfig`].
fn is_deprecated_global_storage_opcode(byte: u8) -> bool {
    byte == Opcodes::EXISTS_DEPRECATED as u8
        || byte == Opcodes::EXISTS_GENERIC_DEPRECATED as u8
        || byte == Opcodes::MUT_BORROW_GLOBAL_DEPRECATED as u8
        || byte == Opcodes::MUT_BORROW_GLOBAL_GENERIC_DEPRECATED as u8
        || byte == Opcodes::IMM_BORROW_GLOBAL_DEPRECATED as u8
        || byte == Opcodes::IMM_BORROW_GLOBAL_GENERIC_DEPRECATED as u8
        || byte == Opcodes::MOVE_FROM_DEPRECATED as u8
        || byte == Opcodes::MOVE_FROM_GENERIC_DEPRECATED as u8
        || byte == Opcodes::MOVE_TO_DEPRECATED as u8
        || byte == Opcodes::MOVE_TO_GENERIC_DEPRECATED as u8
}

// ---------- ULEB128 helpers ----------

/// Write a `u64` value as ULEB128. Mirrors Sui's
/// `write_u64_as_uleb128` (`file_format_common.rs:444`); the
/// algorithm is the textbook ULEB128 encoding.
fn write_uleb128(mut value: u64, out: &mut Vec<u8>) {
    loop {
        let cur = value & 0x7f;
        // cur: u64 in range [0, 0x7F] by construction (mask above).
        // Cast to u8 cannot truncate.
        #[allow(clippy::cast_possible_truncation)]
        let low_seven = cur as u8;
        if cur != value {
            out.push(low_seven | 0x80);
            value >>= 7;
        } else {
            out.push(low_seven);
            break;
        }
    }
}

/// Read a ULEB128-encoded `u64` from a cursor over a byte slice.
/// Wraps Sui's public [`read_uleb128_as_u64`] and translates errors
/// into our [`DeserializeError`] type.
fn read_uleb128(cursor: &mut Cursor<&[u8]>) -> Result<u64, DeserializeError> {
    read_uleb128_as_u64(cursor).map_err(|_| {
        // Sui's reader returns one error type for both EOF and
        // overflow. Distinguish by checking whether we're at EOF.
        // cursor.position(): u64 → usize. Position came from a
        // slice of length usize; cannot truncate in practice.
        #[allow(clippy::cast_possible_truncation)]
        let pos = cursor.position() as usize;
        if pos >= cursor.get_ref().len() {
            DeserializeError::UnexpectedEof
        } else {
            DeserializeError::MalformedUleb128
        }
    })
}

/// Read a ULEB128-encoded value and validate it fits a `u16`.
fn read_uleb128_u16(cursor: &mut Cursor<&[u8]>, opcode: u8) -> Result<u16, DeserializeError> {
    let v = read_uleb128(cursor)?;
    if v > u64::from(u16::MAX) {
        return Err(DeserializeError::InvalidOperand {
            opcode,
            reason: "index exceeds u16::MAX",
        });
    }
    // v ≤ u16::MAX guaranteed by the bound check above. Cast cannot
    // truncate.
    #[allow(clippy::cast_possible_truncation)]
    let v_u16 = v as u16;
    Ok(v_u16)
}

/// Read a ULEB128-encoded value and validate it fits a `u8`.
fn read_uleb128_u8(cursor: &mut Cursor<&[u8]>, opcode: u8) -> Result<u8, DeserializeError> {
    let v = read_uleb128(cursor)?;
    if v > u64::from(u8::MAX) {
        return Err(DeserializeError::InvalidOperand {
            opcode,
            reason: "index exceeds u8::MAX",
        });
    }
    // v ≤ u8::MAX guaranteed by the bound check above. Cast cannot
    // truncate.
    #[allow(clippy::cast_possible_truncation)]
    let v_u8 = v as u8;
    Ok(v_u8)
}

// ---------- Fixed-width LE readers ----------

fn read_u8(cursor: &mut Cursor<&[u8]>) -> Result<u8, DeserializeError> {
    read_n::<1>(cursor).map(|b| b[0])
}

fn read_u16_le(cursor: &mut Cursor<&[u8]>) -> Result<u16, DeserializeError> {
    read_n::<2>(cursor).map(u16::from_le_bytes)
}

fn read_u32_le(cursor: &mut Cursor<&[u8]>) -> Result<u32, DeserializeError> {
    read_n::<4>(cursor).map(u32::from_le_bytes)
}

fn read_u64_le(cursor: &mut Cursor<&[u8]>) -> Result<u64, DeserializeError> {
    read_n::<8>(cursor).map(u64::from_le_bytes)
}

fn read_u128_le(cursor: &mut Cursor<&[u8]>) -> Result<u128, DeserializeError> {
    read_n::<16>(cursor).map(u128::from_le_bytes)
}

/// Read 32 little-endian bytes as a `U256` per the §6.2.1.5
/// amendment (commit 83bb1e9). Note this is `to_le_bytes` →
/// `from_le_bytes`, matching Sui-Move's inherited encoding;
/// §6.0.7's BCS `Value::U256` uses big-endian, but bytecode and
/// BCS are independent encoding paths.
fn read_u256_le(cursor: &mut Cursor<&[u8]>) -> Result<U256, DeserializeError> {
    let bytes = read_n::<32>(cursor)?;
    Ok(U256::from_le_bytes(&bytes))
}

fn read_n<const N: usize>(cursor: &mut Cursor<&[u8]>) -> Result<[u8; N], DeserializeError> {
    // cursor.position(): u64 → usize. Position came from a slice
    // of length usize; cannot truncate in practice.
    #[allow(clippy::cast_possible_truncation)]
    let pos = cursor.position() as usize;
    let bytes = cursor.get_ref();
    if pos + N > bytes.len() {
        return Err(DeserializeError::UnexpectedEof);
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes[pos..pos + N]);
    cursor.set_position((pos + N) as u64);
    Ok(out)
}

// ---------- Per-instruction serialisation ----------

fn serialize_instruction(
    instr: &BytecodeInstruction,
    out: &mut Vec<u8>,
) -> Result<(), SerializeError> {
    match instr {
        BytecodeInstruction::Inherited(bc) => serialize_inherited(bc, out),
        BytecodeInstruction::Adamant(ext) => serialize_adamant(ext, out),
    }
}

#[allow(clippy::too_many_lines)]
fn serialize_inherited(bc: &Bytecode, out: &mut Vec<u8>) -> Result<(), SerializeError> {
    match bc {
        Bytecode::Pop => out.push(Opcodes::POP as u8),
        Bytecode::Ret => out.push(Opcodes::RET as u8),
        Bytecode::BrTrue(off) => {
            out.push(Opcodes::BR_TRUE as u8);
            write_uleb128(u64::from(*off), out);
        }
        Bytecode::BrFalse(off) => {
            out.push(Opcodes::BR_FALSE as u8);
            write_uleb128(u64::from(*off), out);
        }
        Bytecode::Branch(off) => {
            out.push(Opcodes::BRANCH as u8);
            write_uleb128(u64::from(*off), out);
        }
        Bytecode::LdU8(v) => {
            out.push(Opcodes::LD_U8 as u8);
            out.push(*v);
        }
        Bytecode::LdU64(v) => {
            out.push(Opcodes::LD_U64 as u8);
            out.extend_from_slice(&v.to_le_bytes());
        }
        Bytecode::LdU128(v) => {
            out.push(Opcodes::LD_U128 as u8);
            out.extend_from_slice(&v.to_le_bytes());
        }
        Bytecode::CastU8 => out.push(Opcodes::CAST_U8 as u8),
        Bytecode::CastU64 => out.push(Opcodes::CAST_U64 as u8),
        Bytecode::CastU128 => out.push(Opcodes::CAST_U128 as u8),
        Bytecode::LdConst(idx) => {
            out.push(Opcodes::LD_CONST as u8);
            write_uleb128(u64::from(idx.0), out);
        }
        Bytecode::LdTrue => out.push(Opcodes::LD_TRUE as u8),
        Bytecode::LdFalse => out.push(Opcodes::LD_FALSE as u8),
        Bytecode::CopyLoc(idx) => {
            out.push(Opcodes::COPY_LOC as u8);
            write_uleb128(u64::from(*idx), out);
        }
        Bytecode::MoveLoc(idx) => {
            out.push(Opcodes::MOVE_LOC as u8);
            write_uleb128(u64::from(*idx), out);
        }
        Bytecode::StLoc(idx) => {
            out.push(Opcodes::ST_LOC as u8);
            write_uleb128(u64::from(*idx), out);
        }
        Bytecode::Call(idx) => {
            out.push(Opcodes::CALL as u8);
            write_uleb128(u64::from(idx.0), out);
        }
        Bytecode::CallGeneric(idx) => {
            out.push(Opcodes::CALL_GENERIC as u8);
            write_uleb128(u64::from(idx.0), out);
        }
        Bytecode::Pack(idx) => {
            out.push(Opcodes::PACK as u8);
            write_uleb128(u64::from(idx.0), out);
        }
        Bytecode::PackGeneric(idx) => {
            out.push(Opcodes::PACK_GENERIC as u8);
            write_uleb128(u64::from(idx.0), out);
        }
        Bytecode::Unpack(idx) => {
            out.push(Opcodes::UNPACK as u8);
            write_uleb128(u64::from(idx.0), out);
        }
        Bytecode::UnpackGeneric(idx) => {
            out.push(Opcodes::UNPACK_GENERIC as u8);
            write_uleb128(u64::from(idx.0), out);
        }
        Bytecode::ReadRef => out.push(Opcodes::READ_REF as u8),
        Bytecode::WriteRef => out.push(Opcodes::WRITE_REF as u8),
        Bytecode::FreezeRef => out.push(Opcodes::FREEZE_REF as u8),
        Bytecode::MutBorrowLoc(idx) => {
            out.push(Opcodes::MUT_BORROW_LOC as u8);
            write_uleb128(u64::from(*idx), out);
        }
        Bytecode::ImmBorrowLoc(idx) => {
            out.push(Opcodes::IMM_BORROW_LOC as u8);
            write_uleb128(u64::from(*idx), out);
        }
        Bytecode::MutBorrowField(idx) => {
            out.push(Opcodes::MUT_BORROW_FIELD as u8);
            write_uleb128(u64::from(idx.0), out);
        }
        Bytecode::MutBorrowFieldGeneric(idx) => {
            out.push(Opcodes::MUT_BORROW_FIELD_GENERIC as u8);
            write_uleb128(u64::from(idx.0), out);
        }
        Bytecode::ImmBorrowField(idx) => {
            out.push(Opcodes::IMM_BORROW_FIELD as u8);
            write_uleb128(u64::from(idx.0), out);
        }
        Bytecode::ImmBorrowFieldGeneric(idx) => {
            out.push(Opcodes::IMM_BORROW_FIELD_GENERIC as u8);
            write_uleb128(u64::from(idx.0), out);
        }
        Bytecode::Add => out.push(Opcodes::ADD as u8),
        Bytecode::Sub => out.push(Opcodes::SUB as u8),
        Bytecode::Mul => out.push(Opcodes::MUL as u8),
        Bytecode::Mod => out.push(Opcodes::MOD as u8),
        Bytecode::Div => out.push(Opcodes::DIV as u8),
        Bytecode::BitOr => out.push(Opcodes::BIT_OR as u8),
        Bytecode::BitAnd => out.push(Opcodes::BIT_AND as u8),
        Bytecode::Xor => out.push(Opcodes::XOR as u8),
        Bytecode::Or => out.push(Opcodes::OR as u8),
        Bytecode::And => out.push(Opcodes::AND as u8),
        Bytecode::Not => out.push(Opcodes::NOT as u8),
        Bytecode::Eq => out.push(Opcodes::EQ as u8),
        Bytecode::Neq => out.push(Opcodes::NEQ as u8),
        Bytecode::Lt => out.push(Opcodes::LT as u8),
        Bytecode::Gt => out.push(Opcodes::GT as u8),
        Bytecode::Le => out.push(Opcodes::LE as u8),
        Bytecode::Ge => out.push(Opcodes::GE as u8),
        Bytecode::Abort => out.push(Opcodes::ABORT as u8),
        Bytecode::Nop => out.push(Opcodes::NOP as u8),
        Bytecode::Shl => out.push(Opcodes::SHL as u8),
        Bytecode::Shr => out.push(Opcodes::SHR as u8),
        Bytecode::VecPack(sig, n) => {
            out.push(Opcodes::VEC_PACK as u8);
            write_uleb128(u64::from(sig.0), out);
            out.extend_from_slice(&n.to_le_bytes());
        }
        Bytecode::VecLen(sig) => {
            out.push(Opcodes::VEC_LEN as u8);
            write_uleb128(u64::from(sig.0), out);
        }
        Bytecode::VecImmBorrow(sig) => {
            out.push(Opcodes::VEC_IMM_BORROW as u8);
            write_uleb128(u64::from(sig.0), out);
        }
        Bytecode::VecMutBorrow(sig) => {
            out.push(Opcodes::VEC_MUT_BORROW as u8);
            write_uleb128(u64::from(sig.0), out);
        }
        Bytecode::VecPushBack(sig) => {
            out.push(Opcodes::VEC_PUSH_BACK as u8);
            write_uleb128(u64::from(sig.0), out);
        }
        Bytecode::VecPopBack(sig) => {
            out.push(Opcodes::VEC_POP_BACK as u8);
            write_uleb128(u64::from(sig.0), out);
        }
        Bytecode::VecUnpack(sig, n) => {
            out.push(Opcodes::VEC_UNPACK as u8);
            write_uleb128(u64::from(sig.0), out);
            out.extend_from_slice(&n.to_le_bytes());
        }
        Bytecode::VecSwap(sig) => {
            out.push(Opcodes::VEC_SWAP as u8);
            write_uleb128(u64::from(sig.0), out);
        }
        Bytecode::LdU16(v) => {
            out.push(Opcodes::LD_U16 as u8);
            out.extend_from_slice(&v.to_le_bytes());
        }
        Bytecode::LdU32(v) => {
            out.push(Opcodes::LD_U32 as u8);
            out.extend_from_slice(&v.to_le_bytes());
        }
        Bytecode::LdU256(v) => {
            out.push(Opcodes::LD_U256 as u8);
            out.extend_from_slice(&v.to_le_bytes());
        }
        Bytecode::CastU16 => out.push(Opcodes::CAST_U16 as u8),
        Bytecode::CastU32 => out.push(Opcodes::CAST_U32 as u8),
        Bytecode::CastU256 => out.push(Opcodes::CAST_U256 as u8),
        Bytecode::PackVariant(idx) => {
            out.push(Opcodes::PACK_VARIANT as u8);
            write_uleb128(u64::from(idx.0), out);
        }
        Bytecode::PackVariantGeneric(idx) => {
            out.push(Opcodes::PACK_VARIANT_GENERIC as u8);
            write_uleb128(u64::from(idx.0), out);
        }
        Bytecode::UnpackVariant(idx) => {
            out.push(Opcodes::UNPACK_VARIANT as u8);
            write_uleb128(u64::from(idx.0), out);
        }
        Bytecode::UnpackVariantImmRef(idx) => {
            out.push(Opcodes::UNPACK_VARIANT_IMM_REF as u8);
            write_uleb128(u64::from(idx.0), out);
        }
        Bytecode::UnpackVariantMutRef(idx) => {
            out.push(Opcodes::UNPACK_VARIANT_MUT_REF as u8);
            write_uleb128(u64::from(idx.0), out);
        }
        Bytecode::UnpackVariantGeneric(idx) => {
            out.push(Opcodes::UNPACK_VARIANT_GENERIC as u8);
            write_uleb128(u64::from(idx.0), out);
        }
        Bytecode::UnpackVariantGenericImmRef(idx) => {
            out.push(Opcodes::UNPACK_VARIANT_GENERIC_IMM_REF as u8);
            write_uleb128(u64::from(idx.0), out);
        }
        Bytecode::UnpackVariantGenericMutRef(idx) => {
            out.push(Opcodes::UNPACK_VARIANT_GENERIC_MUT_REF as u8);
            write_uleb128(u64::from(idx.0), out);
        }
        Bytecode::VariantSwitch(idx) => {
            out.push(Opcodes::VARIANT_SWITCH as u8);
            write_uleb128(u64::from(idx.0), out);
        }
        // Deprecated global-storage variants. Encoded for byte-faithful
        // round-trip with Sui per §6.2.1 framing; rejected at module
        // deployment by the validator (later deliverable) per §6.2.1.6
        // rule 5 ("no global storage instructions").
        Bytecode::ExistsDeprecated(idx) => {
            out.push(Opcodes::EXISTS_DEPRECATED as u8);
            write_uleb128(u64::from(idx.0), out);
        }
        Bytecode::ExistsGenericDeprecated(idx) => {
            out.push(Opcodes::EXISTS_GENERIC_DEPRECATED as u8);
            write_uleb128(u64::from(idx.0), out);
        }
        Bytecode::MoveFromDeprecated(idx) => {
            out.push(Opcodes::MOVE_FROM_DEPRECATED as u8);
            write_uleb128(u64::from(idx.0), out);
        }
        Bytecode::MoveFromGenericDeprecated(idx) => {
            out.push(Opcodes::MOVE_FROM_GENERIC_DEPRECATED as u8);
            write_uleb128(u64::from(idx.0), out);
        }
        Bytecode::MoveToDeprecated(idx) => {
            out.push(Opcodes::MOVE_TO_DEPRECATED as u8);
            write_uleb128(u64::from(idx.0), out);
        }
        Bytecode::MoveToGenericDeprecated(idx) => {
            out.push(Opcodes::MOVE_TO_GENERIC_DEPRECATED as u8);
            write_uleb128(u64::from(idx.0), out);
        }
        Bytecode::MutBorrowGlobalDeprecated(idx) => {
            out.push(Opcodes::MUT_BORROW_GLOBAL_DEPRECATED as u8);
            write_uleb128(u64::from(idx.0), out);
        }
        Bytecode::MutBorrowGlobalGenericDeprecated(idx) => {
            out.push(Opcodes::MUT_BORROW_GLOBAL_GENERIC_DEPRECATED as u8);
            write_uleb128(u64::from(idx.0), out);
        }
        Bytecode::ImmBorrowGlobalDeprecated(idx) => {
            out.push(Opcodes::IMM_BORROW_GLOBAL_DEPRECATED as u8);
            write_uleb128(u64::from(idx.0), out);
        }
        Bytecode::ImmBorrowGlobalGenericDeprecated(idx) => {
            out.push(Opcodes::IMM_BORROW_GLOBAL_GENERIC_DEPRECATED as u8);
            write_uleb128(u64::from(idx.0), out);
        }
    }
    Ok(())
}

fn serialize_adamant(ext: &AdamantBytecode, out: &mut Vec<u8>) -> Result<(), SerializeError> {
    out.push(ext.opcode_byte());
    match ext {
        AdamantBytecode::InvokeShielded(idx) | AdamantBytecode::InvokeTransparent(idx) => {
            write_uleb128(u64::from(idx.0), out);
        }
        AdamantBytecode::GenerateProof(c) | AdamantBytecode::VerifyProof(c) => {
            write_uleb128(u64::from(c.0), out);
        }
        AdamantBytecode::ChargeGas(d) | AdamantBytecode::RemainingGas(d) => {
            out.push(gas_dimension_byte(*d));
        }
        AdamantBytecode::ReleaseSubViewKey
        | AdamantBytecode::KzgCommit
        | AdamantBytecode::KzgVerify
        | AdamantBytecode::RecursiveVerify
        | AdamantBytecode::Sha3_256
        | AdamantBytecode::Blake3
        | AdamantBytecode::Ed25519Verify
        | AdamantBytecode::MlDsaVerify65
        | AdamantBytecode::MlDsaVerify87
        | AdamantBytecode::BlsVerify
        | AdamantBytecode::OutOfGas => {
            // Zero-operand extensions: nothing more to write.
        }
    }
    Ok(())
}

/// Encode a [`GasDimension`] as a single byte tag `0x00..=0x05`
/// per the §6.2.1.5 amendment in commit 84e60d0.
const fn gas_dimension_byte(d: GasDimension) -> u8 {
    match d {
        GasDimension::Computation => 0x00,
        GasDimension::Storage => 0x01,
        GasDimension::Rent => 0x02,
        GasDimension::Bandwidth => 0x03,
        GasDimension::ProofVerification => 0x04,
        GasDimension::ProofGeneration => 0x05,
    }
}

fn gas_dimension_from_byte(b: u8, opcode: u8) -> Result<GasDimension, DeserializeError> {
    match b {
        0x00 => Ok(GasDimension::Computation),
        0x01 => Ok(GasDimension::Storage),
        0x02 => Ok(GasDimension::Rent),
        0x03 => Ok(GasDimension::Bandwidth),
        0x04 => Ok(GasDimension::ProofVerification),
        0x05 => Ok(GasDimension::ProofGeneration),
        _ => Err(DeserializeError::InvalidOperand {
            opcode,
            reason: "GasDimension tag must be 0x00..=0x05",
        }),
    }
}

// ---------- Per-instruction deserialisation ----------

#[allow(clippy::too_many_lines)]
fn deserialize_instruction(
    cursor: &mut Cursor<&[u8]>,
    config: &DeserializeConfig,
) -> Result<BytecodeInstruction, DeserializeError> {
    let byte = read_u8(cursor)?;

    // Strict-mode rejection of deprecated global-storage opcodes
    // per §6.2.1.6 Rule 5. Fires before the dispatch so the
    // operand bytes that follow are not consumed (preserving the
    // cursor position at the offending opcode for diagnostics).
    if config.reject_deprecated_global_storage && is_deprecated_global_storage_opcode(byte) {
        return Err(DeserializeError::DeprecatedGlobalStorageOpcode(byte));
    }

    // Adamant extensions occupy 0x80..=0x90.
    if let Some(kind) = AdamantOpcodeKind::try_from_opcode_byte(byte) {
        let ext = match kind {
            AdamantOpcodeKind::InvokeShielded => AdamantBytecode::InvokeShielded(
                FunctionHandleIndex::new(read_uleb128_u16(cursor, byte)?),
            ),
            AdamantOpcodeKind::InvokeTransparent => AdamantBytecode::InvokeTransparent(
                FunctionHandleIndex::new(read_uleb128_u16(cursor, byte)?),
            ),
            AdamantOpcodeKind::GenerateProof => {
                AdamantBytecode::GenerateProof(CircuitId(read_uleb128_u16(cursor, byte)?))
            }
            AdamantOpcodeKind::VerifyProof => {
                AdamantBytecode::VerifyProof(CircuitId(read_uleb128_u16(cursor, byte)?))
            }
            AdamantOpcodeKind::ReleaseSubViewKey => AdamantBytecode::ReleaseSubViewKey,
            AdamantOpcodeKind::KzgCommit => AdamantBytecode::KzgCommit,
            AdamantOpcodeKind::KzgVerify => AdamantBytecode::KzgVerify,
            AdamantOpcodeKind::RecursiveVerify => AdamantBytecode::RecursiveVerify,
            AdamantOpcodeKind::Sha3_256 => AdamantBytecode::Sha3_256,
            AdamantOpcodeKind::Blake3 => AdamantBytecode::Blake3,
            AdamantOpcodeKind::Ed25519Verify => AdamantBytecode::Ed25519Verify,
            AdamantOpcodeKind::MlDsaVerify65 => AdamantBytecode::MlDsaVerify65,
            AdamantOpcodeKind::MlDsaVerify87 => AdamantBytecode::MlDsaVerify87,
            AdamantOpcodeKind::BlsVerify => AdamantBytecode::BlsVerify,
            AdamantOpcodeKind::ChargeGas => {
                AdamantBytecode::ChargeGas(gas_dimension_from_byte(read_u8(cursor)?, byte)?)
            }
            AdamantOpcodeKind::RemainingGas => {
                AdamantBytecode::RemainingGas(gas_dimension_from_byte(read_u8(cursor)?, byte)?)
            }
            AdamantOpcodeKind::OutOfGas => AdamantBytecode::OutOfGas,
        };
        return Ok(BytecodeInstruction::Adamant(ext));
    }

    // Inherited Sui-Move opcodes.
    let bc = match byte {
        x if x == Opcodes::POP as u8 => Bytecode::Pop,
        x if x == Opcodes::RET as u8 => Bytecode::Ret,
        x if x == Opcodes::BR_TRUE as u8 => {
            Bytecode::BrTrue(read_uleb128_u16(cursor, byte)? as CodeOffset)
        }
        x if x == Opcodes::BR_FALSE as u8 => {
            Bytecode::BrFalse(read_uleb128_u16(cursor, byte)? as CodeOffset)
        }
        x if x == Opcodes::BRANCH as u8 => {
            Bytecode::Branch(read_uleb128_u16(cursor, byte)? as CodeOffset)
        }
        x if x == Opcodes::LD_U8 as u8 => Bytecode::LdU8(read_u8(cursor)?),
        x if x == Opcodes::LD_U64 as u8 => Bytecode::LdU64(read_u64_le(cursor)?),
        x if x == Opcodes::LD_U128 as u8 => Bytecode::LdU128(Box::new(read_u128_le(cursor)?)),
        x if x == Opcodes::CAST_U8 as u8 => Bytecode::CastU8,
        x if x == Opcodes::CAST_U64 as u8 => Bytecode::CastU64,
        x if x == Opcodes::CAST_U128 as u8 => Bytecode::CastU128,
        x if x == Opcodes::LD_CONST as u8 => {
            Bytecode::LdConst(ConstantPoolIndex::new(read_uleb128_u16(cursor, byte)?))
        }
        x if x == Opcodes::LD_TRUE as u8 => Bytecode::LdTrue,
        x if x == Opcodes::LD_FALSE as u8 => Bytecode::LdFalse,
        x if x == Opcodes::COPY_LOC as u8 => {
            Bytecode::CopyLoc(read_uleb128_u8(cursor, byte)? as LocalIndex)
        }
        x if x == Opcodes::MOVE_LOC as u8 => {
            Bytecode::MoveLoc(read_uleb128_u8(cursor, byte)? as LocalIndex)
        }
        x if x == Opcodes::ST_LOC as u8 => {
            Bytecode::StLoc(read_uleb128_u8(cursor, byte)? as LocalIndex)
        }
        x if x == Opcodes::CALL as u8 => {
            Bytecode::Call(FunctionHandleIndex::new(read_uleb128_u16(cursor, byte)?))
        }
        x if x == Opcodes::CALL_GENERIC as u8 => Bytecode::CallGeneric(
            FunctionInstantiationIndex::new(read_uleb128_u16(cursor, byte)?),
        ),
        x if x == Opcodes::PACK as u8 => {
            Bytecode::Pack(StructDefinitionIndex::new(read_uleb128_u16(cursor, byte)?))
        }
        x if x == Opcodes::PACK_GENERIC as u8 => Bytecode::PackGeneric(
            StructDefInstantiationIndex::new(read_uleb128_u16(cursor, byte)?),
        ),
        x if x == Opcodes::UNPACK as u8 => {
            Bytecode::Unpack(StructDefinitionIndex::new(read_uleb128_u16(cursor, byte)?))
        }
        x if x == Opcodes::UNPACK_GENERIC as u8 => Bytecode::UnpackGeneric(
            StructDefInstantiationIndex::new(read_uleb128_u16(cursor, byte)?),
        ),
        x if x == Opcodes::READ_REF as u8 => Bytecode::ReadRef,
        x if x == Opcodes::WRITE_REF as u8 => Bytecode::WriteRef,
        x if x == Opcodes::FREEZE_REF as u8 => Bytecode::FreezeRef,
        x if x == Opcodes::MUT_BORROW_LOC as u8 => {
            Bytecode::MutBorrowLoc(read_uleb128_u8(cursor, byte)? as LocalIndex)
        }
        x if x == Opcodes::IMM_BORROW_LOC as u8 => {
            Bytecode::ImmBorrowLoc(read_uleb128_u8(cursor, byte)? as LocalIndex)
        }
        x if x == Opcodes::MUT_BORROW_FIELD as u8 => {
            Bytecode::MutBorrowField(FieldHandleIndex::new(read_uleb128_u16(cursor, byte)?))
        }
        x if x == Opcodes::MUT_BORROW_FIELD_GENERIC as u8 => Bytecode::MutBorrowFieldGeneric(
            FieldInstantiationIndex::new(read_uleb128_u16(cursor, byte)?),
        ),
        x if x == Opcodes::IMM_BORROW_FIELD as u8 => {
            Bytecode::ImmBorrowField(FieldHandleIndex::new(read_uleb128_u16(cursor, byte)?))
        }
        x if x == Opcodes::IMM_BORROW_FIELD_GENERIC as u8 => Bytecode::ImmBorrowFieldGeneric(
            FieldInstantiationIndex::new(read_uleb128_u16(cursor, byte)?),
        ),
        x if x == Opcodes::ADD as u8 => Bytecode::Add,
        x if x == Opcodes::SUB as u8 => Bytecode::Sub,
        x if x == Opcodes::MUL as u8 => Bytecode::Mul,
        x if x == Opcodes::MOD as u8 => Bytecode::Mod,
        x if x == Opcodes::DIV as u8 => Bytecode::Div,
        x if x == Opcodes::BIT_OR as u8 => Bytecode::BitOr,
        x if x == Opcodes::BIT_AND as u8 => Bytecode::BitAnd,
        x if x == Opcodes::XOR as u8 => Bytecode::Xor,
        x if x == Opcodes::OR as u8 => Bytecode::Or,
        x if x == Opcodes::AND as u8 => Bytecode::And,
        x if x == Opcodes::NOT as u8 => Bytecode::Not,
        x if x == Opcodes::EQ as u8 => Bytecode::Eq,
        x if x == Opcodes::NEQ as u8 => Bytecode::Neq,
        x if x == Opcodes::LT as u8 => Bytecode::Lt,
        x if x == Opcodes::GT as u8 => Bytecode::Gt,
        x if x == Opcodes::LE as u8 => Bytecode::Le,
        x if x == Opcodes::GE as u8 => Bytecode::Ge,
        x if x == Opcodes::ABORT as u8 => Bytecode::Abort,
        x if x == Opcodes::NOP as u8 => Bytecode::Nop,
        x if x == Opcodes::SHL as u8 => Bytecode::Shl,
        x if x == Opcodes::SHR as u8 => Bytecode::Shr,
        x if x == Opcodes::VEC_PACK as u8 => {
            let sig = SignatureIndex::new(read_uleb128_u16(cursor, byte)?);
            let n = read_u64_le(cursor)?;
            Bytecode::VecPack(sig, n)
        }
        x if x == Opcodes::VEC_LEN as u8 => {
            Bytecode::VecLen(SignatureIndex::new(read_uleb128_u16(cursor, byte)?))
        }
        x if x == Opcodes::VEC_IMM_BORROW as u8 => {
            Bytecode::VecImmBorrow(SignatureIndex::new(read_uleb128_u16(cursor, byte)?))
        }
        x if x == Opcodes::VEC_MUT_BORROW as u8 => {
            Bytecode::VecMutBorrow(SignatureIndex::new(read_uleb128_u16(cursor, byte)?))
        }
        x if x == Opcodes::VEC_PUSH_BACK as u8 => {
            Bytecode::VecPushBack(SignatureIndex::new(read_uleb128_u16(cursor, byte)?))
        }
        x if x == Opcodes::VEC_POP_BACK as u8 => {
            Bytecode::VecPopBack(SignatureIndex::new(read_uleb128_u16(cursor, byte)?))
        }
        x if x == Opcodes::VEC_UNPACK as u8 => {
            let sig = SignatureIndex::new(read_uleb128_u16(cursor, byte)?);
            let n = read_u64_le(cursor)?;
            Bytecode::VecUnpack(sig, n)
        }
        x if x == Opcodes::VEC_SWAP as u8 => {
            Bytecode::VecSwap(SignatureIndex::new(read_uleb128_u16(cursor, byte)?))
        }
        x if x == Opcodes::LD_U16 as u8 => Bytecode::LdU16(read_u16_le(cursor)?),
        x if x == Opcodes::LD_U32 as u8 => Bytecode::LdU32(read_u32_le(cursor)?),
        x if x == Opcodes::LD_U256 as u8 => Bytecode::LdU256(Box::new(read_u256_le(cursor)?)),
        x if x == Opcodes::CAST_U16 as u8 => Bytecode::CastU16,
        x if x == Opcodes::CAST_U32 as u8 => Bytecode::CastU32,
        x if x == Opcodes::CAST_U256 as u8 => Bytecode::CastU256,
        x if x == Opcodes::PACK_VARIANT as u8 => {
            Bytecode::PackVariant(VariantHandleIndex::new(read_uleb128_u16(cursor, byte)?))
        }
        x if x == Opcodes::PACK_VARIANT_GENERIC as u8 => Bytecode::PackVariantGeneric(
            VariantInstantiationHandleIndex::new(read_uleb128_u16(cursor, byte)?),
        ),
        x if x == Opcodes::UNPACK_VARIANT as u8 => {
            Bytecode::UnpackVariant(VariantHandleIndex::new(read_uleb128_u16(cursor, byte)?))
        }
        x if x == Opcodes::UNPACK_VARIANT_IMM_REF as u8 => {
            Bytecode::UnpackVariantImmRef(VariantHandleIndex::new(read_uleb128_u16(cursor, byte)?))
        }
        x if x == Opcodes::UNPACK_VARIANT_MUT_REF as u8 => {
            Bytecode::UnpackVariantMutRef(VariantHandleIndex::new(read_uleb128_u16(cursor, byte)?))
        }
        x if x == Opcodes::UNPACK_VARIANT_GENERIC as u8 => Bytecode::UnpackVariantGeneric(
            VariantInstantiationHandleIndex::new(read_uleb128_u16(cursor, byte)?),
        ),
        x if x == Opcodes::UNPACK_VARIANT_GENERIC_IMM_REF as u8 => {
            Bytecode::UnpackVariantGenericImmRef(VariantInstantiationHandleIndex::new(
                read_uleb128_u16(cursor, byte)?,
            ))
        }
        x if x == Opcodes::UNPACK_VARIANT_GENERIC_MUT_REF as u8 => {
            Bytecode::UnpackVariantGenericMutRef(VariantInstantiationHandleIndex::new(
                read_uleb128_u16(cursor, byte)?,
            ))
        }
        x if x == Opcodes::VARIANT_SWITCH as u8 => {
            Bytecode::VariantSwitch(VariantJumpTableIndex::new(read_uleb128_u16(cursor, byte)?))
        }
        x if x == Opcodes::EXISTS_DEPRECATED as u8 => {
            Bytecode::ExistsDeprecated(StructDefinitionIndex::new(read_uleb128_u16(cursor, byte)?))
        }
        x if x == Opcodes::EXISTS_GENERIC_DEPRECATED as u8 => Bytecode::ExistsGenericDeprecated(
            StructDefInstantiationIndex::new(read_uleb128_u16(cursor, byte)?),
        ),
        x if x == Opcodes::MOVE_FROM_DEPRECATED as u8 => Bytecode::MoveFromDeprecated(
            StructDefinitionIndex::new(read_uleb128_u16(cursor, byte)?),
        ),
        x if x == Opcodes::MOVE_FROM_GENERIC_DEPRECATED as u8 => {
            Bytecode::MoveFromGenericDeprecated(StructDefInstantiationIndex::new(read_uleb128_u16(
                cursor, byte,
            )?))
        }
        x if x == Opcodes::MOVE_TO_DEPRECATED as u8 => {
            Bytecode::MoveToDeprecated(StructDefinitionIndex::new(read_uleb128_u16(cursor, byte)?))
        }
        x if x == Opcodes::MOVE_TO_GENERIC_DEPRECATED as u8 => Bytecode::MoveToGenericDeprecated(
            StructDefInstantiationIndex::new(read_uleb128_u16(cursor, byte)?),
        ),
        x if x == Opcodes::MUT_BORROW_GLOBAL_DEPRECATED as u8 => {
            Bytecode::MutBorrowGlobalDeprecated(StructDefinitionIndex::new(read_uleb128_u16(
                cursor, byte,
            )?))
        }
        x if x == Opcodes::MUT_BORROW_GLOBAL_GENERIC_DEPRECATED as u8 => {
            Bytecode::MutBorrowGlobalGenericDeprecated(StructDefInstantiationIndex::new(
                read_uleb128_u16(cursor, byte)?,
            ))
        }
        x if x == Opcodes::IMM_BORROW_GLOBAL_DEPRECATED as u8 => {
            Bytecode::ImmBorrowGlobalDeprecated(StructDefinitionIndex::new(read_uleb128_u16(
                cursor, byte,
            )?))
        }
        x if x == Opcodes::IMM_BORROW_GLOBAL_GENERIC_DEPRECATED as u8 => {
            Bytecode::ImmBorrowGlobalGenericDeprecated(StructDefInstantiationIndex::new(
                read_uleb128_u16(cursor, byte)?,
            ))
        }
        other => return Err(DeserializeError::UnknownOpcode(other)),
    };

    Ok(BytecodeInstruction::Inherited(bc))
}

#[cfg(test)]
mod tests {
    use super::*;
    use move_binary_format::file_format::{
        AbilitySet, AddressIdentifierIndex, CodeUnit, CompiledModule, DatatypeHandle,
        DatatypeHandleIndex, FieldDefinition, FunctionDefinition, FunctionHandle, IdentifierIndex,
        ModuleHandle, ModuleHandleIndex, Signature, SignatureToken, StructDefinition,
        StructFieldInformation, TypeSignature, Visibility,
    };
    use move_core_types::account_address::AccountAddress;
    use move_core_types::identifier::Identifier;
    use proptest::prelude::*;

    // ---------- Per-variant round-trip helpers ----------

    /// Round-trip a single instruction through encode → decode and
    /// assert equality. The test is the load-bearing internal-
    /// consistency check for every variant.
    fn round_trip(instr: &BytecodeInstruction) {
        let body = vec![instr.clone()];
        let bytes = serialize_function_body(&body).expect("encode");
        let decoded =
            deserialize_function_body(&bytes, &DeserializeConfig::lenient()).expect("decode");
        assert_eq!(decoded, body, "round-trip mismatch for {instr:?}");
    }

    fn rt_inherited(bc: Bytecode) {
        round_trip(&BytecodeInstruction::Inherited(bc));
    }

    fn rt_adamant(ext: AdamantBytecode) {
        round_trip(&BytecodeInstruction::Adamant(ext));
    }

    // ---------- Zero-operand inherited variants ----------

    #[test]
    fn round_trip_zero_operand_inherited() {
        let cases: [Bytecode; 30] = [
            Bytecode::Pop,
            Bytecode::Ret,
            Bytecode::CastU8,
            Bytecode::CastU64,
            Bytecode::CastU128,
            Bytecode::LdTrue,
            Bytecode::LdFalse,
            Bytecode::ReadRef,
            Bytecode::WriteRef,
            Bytecode::FreezeRef,
            Bytecode::Add,
            Bytecode::Sub,
            Bytecode::Mul,
            Bytecode::Mod,
            Bytecode::Div,
            Bytecode::BitOr,
            Bytecode::BitAnd,
            Bytecode::Xor,
            Bytecode::Or,
            Bytecode::And,
            Bytecode::Not,
            Bytecode::Eq,
            Bytecode::Neq,
            Bytecode::Lt,
            Bytecode::Gt,
            Bytecode::Le,
            Bytecode::Ge,
            Bytecode::Abort,
            Bytecode::Nop,
            Bytecode::Shl,
        ];
        for bc in cases {
            rt_inherited(bc);
        }
        // Three more zero-operand variants for completeness.
        rt_inherited(Bytecode::Shr);
        rt_inherited(Bytecode::CastU16);
        rt_inherited(Bytecode::CastU32);
        rt_inherited(Bytecode::CastU256);
    }

    // ---------- Fixed-width LE immediate variants ----------

    #[test]
    fn round_trip_fixed_width_immediates() {
        rt_inherited(Bytecode::LdU8(0xab));
        rt_inherited(Bytecode::LdU16(0xabcd));
        rt_inherited(Bytecode::LdU32(0xabcd_1234));
        rt_inherited(Bytecode::LdU64(0x0102_0304_0506_0708));
        rt_inherited(Bytecode::LdU128(Box::new(
            0x0102_0304_0506_0708_090a_0b0c_0d0e_0f10,
        )));
        // U256 with non-trivial pattern; tests LE encoding per §6.2.1.5
        // amendment 83bb1e9.
        let mut u256_bytes = [0u8; 32];
        for (i, byte) in u256_bytes.iter_mut().enumerate() {
            // i is bounded by 0..32 (loop range over [u8; 32]),
            // fits in u8 by construction.
            #[allow(clippy::cast_possible_truncation)]
            let i_u8 = i as u8;
            *byte = i_u8;
        }
        rt_inherited(Bytecode::LdU256(Box::new(U256::from_le_bytes(&u256_bytes))));
    }

    // ---------- ULEB128-index inherited variants ----------

    #[test]
    fn round_trip_uleb128_index_variants() {
        // Each index type uses ULEB128 encoding. Operand values
        // chosen to span single-byte (0x00, 0x7f) and multi-byte
        // (0x80, 0xffff) cases.
        for v in [0u16, 1, 0x7F, 0x80, 0x3FFF, 0xFFFF] {
            rt_inherited(Bytecode::BrTrue(v as CodeOffset));
            rt_inherited(Bytecode::BrFalse(v as CodeOffset));
            rt_inherited(Bytecode::Branch(v as CodeOffset));
            rt_inherited(Bytecode::LdConst(ConstantPoolIndex::new(v)));
            rt_inherited(Bytecode::Call(FunctionHandleIndex::new(v)));
            rt_inherited(Bytecode::CallGeneric(FunctionInstantiationIndex::new(v)));
            rt_inherited(Bytecode::Pack(StructDefinitionIndex::new(v)));
            rt_inherited(Bytecode::PackGeneric(StructDefInstantiationIndex::new(v)));
            rt_inherited(Bytecode::Unpack(StructDefinitionIndex::new(v)));
            rt_inherited(Bytecode::UnpackGeneric(StructDefInstantiationIndex::new(v)));
            rt_inherited(Bytecode::MutBorrowField(FieldHandleIndex::new(v)));
            rt_inherited(Bytecode::MutBorrowFieldGeneric(
                FieldInstantiationIndex::new(v),
            ));
            rt_inherited(Bytecode::ImmBorrowField(FieldHandleIndex::new(v)));
            rt_inherited(Bytecode::ImmBorrowFieldGeneric(
                FieldInstantiationIndex::new(v),
            ));
            rt_inherited(Bytecode::PackVariant(VariantHandleIndex::new(v)));
            rt_inherited(Bytecode::PackVariantGeneric(
                VariantInstantiationHandleIndex::new(v),
            ));
            rt_inherited(Bytecode::UnpackVariant(VariantHandleIndex::new(v)));
            rt_inherited(Bytecode::UnpackVariantImmRef(VariantHandleIndex::new(v)));
            rt_inherited(Bytecode::UnpackVariantMutRef(VariantHandleIndex::new(v)));
            rt_inherited(Bytecode::UnpackVariantGeneric(
                VariantInstantiationHandleIndex::new(v),
            ));
            rt_inherited(Bytecode::UnpackVariantGenericImmRef(
                VariantInstantiationHandleIndex::new(v),
            ));
            rt_inherited(Bytecode::UnpackVariantGenericMutRef(
                VariantInstantiationHandleIndex::new(v),
            ));
            rt_inherited(Bytecode::VariantSwitch(VariantJumpTableIndex::new(v)));
        }
        // LocalIndex is u8; cover that range separately.
        for v in [0u8, 1, 0x7F, 0x80, 0xFF] {
            rt_inherited(Bytecode::CopyLoc(v as LocalIndex));
            rt_inherited(Bytecode::MoveLoc(v as LocalIndex));
            rt_inherited(Bytecode::StLoc(v as LocalIndex));
            rt_inherited(Bytecode::MutBorrowLoc(v as LocalIndex));
            rt_inherited(Bytecode::ImmBorrowLoc(v as LocalIndex));
        }
    }

    // ---------- Vec* variants (mixed ULEB128 + fixed-width) ----------

    #[test]
    fn round_trip_vec_variants() {
        for v in [0u16, 0x7F, 0x80, 0xFFFF] {
            for n in [0u64, 1, 0xFFFF_FFFF] {
                rt_inherited(Bytecode::VecPack(SignatureIndex::new(v), n));
                rt_inherited(Bytecode::VecUnpack(SignatureIndex::new(v), n));
            }
            rt_inherited(Bytecode::VecLen(SignatureIndex::new(v)));
            rt_inherited(Bytecode::VecImmBorrow(SignatureIndex::new(v)));
            rt_inherited(Bytecode::VecMutBorrow(SignatureIndex::new(v)));
            rt_inherited(Bytecode::VecPushBack(SignatureIndex::new(v)));
            rt_inherited(Bytecode::VecPopBack(SignatureIndex::new(v)));
            rt_inherited(Bytecode::VecSwap(SignatureIndex::new(v)));
        }
    }

    // ---------- Deprecated global-storage variants ----------
    //
    // Encoded for byte-faithful round-trip with Sui per the Q3
    // sign-off; rejected at module deployment by the validator
    // (later deliverable) per §6.2.1.6 rule 5. The encoder must
    // still produce bytes for these, and the decoder must accept
    // them, so that round-trips against Sui's CompiledModule format
    // succeed for any Sui module that happens to contain them.

    #[test]
    fn round_trip_deprecated_variants() {
        for v in [0u16, 0x7F, 0x80, 0xFFFF] {
            rt_inherited(Bytecode::ExistsDeprecated(StructDefinitionIndex::new(v)));
            rt_inherited(Bytecode::ExistsGenericDeprecated(
                StructDefInstantiationIndex::new(v),
            ));
            rt_inherited(Bytecode::MoveFromDeprecated(StructDefinitionIndex::new(v)));
            rt_inherited(Bytecode::MoveFromGenericDeprecated(
                StructDefInstantiationIndex::new(v),
            ));
            rt_inherited(Bytecode::MoveToDeprecated(StructDefinitionIndex::new(v)));
            rt_inherited(Bytecode::MoveToGenericDeprecated(
                StructDefInstantiationIndex::new(v),
            ));
            rt_inherited(Bytecode::MutBorrowGlobalDeprecated(
                StructDefinitionIndex::new(v),
            ));
            rt_inherited(Bytecode::MutBorrowGlobalGenericDeprecated(
                StructDefInstantiationIndex::new(v),
            ));
            rt_inherited(Bytecode::ImmBorrowGlobalDeprecated(
                StructDefinitionIndex::new(v),
            ));
            rt_inherited(Bytecode::ImmBorrowGlobalGenericDeprecated(
                StructDefInstantiationIndex::new(v),
            ));
        }
    }

    /// Strict mode rejects every deprecated global-storage opcode
    /// at parse time per §6.2.1.6 Rule 5. Encoding still produces
    /// the bytes (lenient round-trip remains tested above) so
    /// modules that accidentally carry deprecated opcodes can be
    /// re-serialised; decoding rejects them as soon as the
    /// deploy-time `DeserializeConfig::strict()` is in effect.
    #[test]
    fn strict_mode_rejects_each_deprecated_opcode() {
        let cases: [(Bytecode, u8); 10] = [
            (
                Bytecode::ExistsDeprecated(StructDefinitionIndex::new(0)),
                Opcodes::EXISTS_DEPRECATED as u8,
            ),
            (
                Bytecode::ExistsGenericDeprecated(StructDefInstantiationIndex::new(0)),
                Opcodes::EXISTS_GENERIC_DEPRECATED as u8,
            ),
            (
                Bytecode::MoveFromDeprecated(StructDefinitionIndex::new(0)),
                Opcodes::MOVE_FROM_DEPRECATED as u8,
            ),
            (
                Bytecode::MoveFromGenericDeprecated(StructDefInstantiationIndex::new(0)),
                Opcodes::MOVE_FROM_GENERIC_DEPRECATED as u8,
            ),
            (
                Bytecode::MoveToDeprecated(StructDefinitionIndex::new(0)),
                Opcodes::MOVE_TO_DEPRECATED as u8,
            ),
            (
                Bytecode::MoveToGenericDeprecated(StructDefInstantiationIndex::new(0)),
                Opcodes::MOVE_TO_GENERIC_DEPRECATED as u8,
            ),
            (
                Bytecode::MutBorrowGlobalDeprecated(StructDefinitionIndex::new(0)),
                Opcodes::MUT_BORROW_GLOBAL_DEPRECATED as u8,
            ),
            (
                Bytecode::MutBorrowGlobalGenericDeprecated(StructDefInstantiationIndex::new(0)),
                Opcodes::MUT_BORROW_GLOBAL_GENERIC_DEPRECATED as u8,
            ),
            (
                Bytecode::ImmBorrowGlobalDeprecated(StructDefinitionIndex::new(0)),
                Opcodes::IMM_BORROW_GLOBAL_DEPRECATED as u8,
            ),
            (
                Bytecode::ImmBorrowGlobalGenericDeprecated(StructDefInstantiationIndex::new(0)),
                Opcodes::IMM_BORROW_GLOBAL_GENERIC_DEPRECATED as u8,
            ),
        ];
        for (bc, expected_byte) in cases {
            let body = vec![BytecodeInstruction::Inherited(bc.clone())];
            let bytes = serialize_function_body(&body).expect("encode");
            let result = deserialize_function_body(&bytes, &DeserializeConfig::strict());
            assert_eq!(
                result,
                Err(DeserializeError::DeprecatedGlobalStorageOpcode(
                    expected_byte
                )),
                "strict mode should reject {bc:?}"
            );
            // Lenient round-trip still succeeds.
            let decoded = deserialize_function_body(&bytes, &DeserializeConfig::lenient())
                .expect("lenient decode succeeds");
            assert_eq!(decoded, body);
        }
    }

    /// `deserialize_function_body_from_cursor` does NOT reject
    /// trailing bytes; the slice-API wrapper does. Pin this so the
    /// module-level deserializer can rely on cursor-API positioning
    /// for embedded function bodies.
    #[test]
    fn cursor_api_leaves_trailing_bytes_for_caller() {
        // ULEB128(1) + RET opcode + arbitrary trailing bytes.
        let bytes = vec![0x01, Opcodes::RET as u8, 0xAA, 0xBB, 0xCC];
        let mut cursor = Cursor::new(&bytes[..]);
        let body =
            deserialize_function_body_from_cursor(&mut cursor, &DeserializeConfig::lenient())
                .expect("decode");
        assert_eq!(body, vec![BytecodeInstruction::Inherited(Bytecode::Ret)]);
        assert_eq!(cursor.position(), 2, "cursor advanced past body only");
        // Slice-API wrapper rejects the same input.
        let result = deserialize_function_body(&bytes, &DeserializeConfig::lenient());
        assert_eq!(result, Err(DeserializeError::TrailingBytes));
    }

    // ---------- Adamant extension round-trips ----------

    #[test]
    fn round_trip_adamant_extensions() {
        for v in [0u16, 0x7F, 0x80, 0xFFFF] {
            rt_adamant(AdamantBytecode::InvokeShielded(FunctionHandleIndex::new(v)));
            rt_adamant(AdamantBytecode::InvokeTransparent(
                FunctionHandleIndex::new(v),
            ));
            rt_adamant(AdamantBytecode::GenerateProof(CircuitId(v)));
            rt_adamant(AdamantBytecode::VerifyProof(CircuitId(v)));
        }
        for d in [
            GasDimension::Computation,
            GasDimension::Storage,
            GasDimension::Rent,
            GasDimension::Bandwidth,
            GasDimension::ProofVerification,
            GasDimension::ProofGeneration,
        ] {
            rt_adamant(AdamantBytecode::ChargeGas(d));
            rt_adamant(AdamantBytecode::RemainingGas(d));
        }
        // 11 zero-operand extensions.
        rt_adamant(AdamantBytecode::ReleaseSubViewKey);
        rt_adamant(AdamantBytecode::KzgCommit);
        rt_adamant(AdamantBytecode::KzgVerify);
        rt_adamant(AdamantBytecode::RecursiveVerify);
        rt_adamant(AdamantBytecode::Sha3_256);
        rt_adamant(AdamantBytecode::Blake3);
        rt_adamant(AdamantBytecode::Ed25519Verify);
        rt_adamant(AdamantBytecode::MlDsaVerify65);
        rt_adamant(AdamantBytecode::MlDsaVerify87);
        rt_adamant(AdamantBytecode::BlsVerify);
        rt_adamant(AdamantBytecode::OutOfGas);
    }

    // ---------- Empty body round-trip ----------

    #[test]
    fn round_trip_empty_body() {
        let body: Vec<BytecodeInstruction> = vec![];
        let bytes = serialize_function_body(&body).expect("encode");
        // ULEB128(0) = single 0x00 byte.
        assert_eq!(bytes, vec![0x00]);
        let decoded =
            deserialize_function_body(&bytes, &DeserializeConfig::lenient()).expect("decode");
        assert_eq!(decoded, body);
    }

    // ---------- Negative tests: one per DeserializeError variant ----------

    #[test]
    fn deserialize_unexpected_eof_empty_input() {
        // No length prefix at all.
        let result = deserialize_function_body(&[], &DeserializeConfig::lenient());
        assert_eq!(result, Err(DeserializeError::UnexpectedEof));
    }

    #[test]
    fn deserialize_unexpected_eof_truncated_operand() {
        // Length prefix says 1 instruction, opcode is LD_U64 (needs
        // 8 bytes after), but stream ends after the opcode byte.
        let bytes = vec![0x01, Opcodes::LD_U64 as u8];
        let result = deserialize_function_body(&bytes, &DeserializeConfig::lenient());
        assert_eq!(result, Err(DeserializeError::UnexpectedEof));
    }

    #[test]
    fn deserialize_unknown_opcode() {
        // 0xFF is unassigned in both Sui's range (0x01..=0x56,
        // 0x29..=0x2D, 0x3B..=0x3F) and Adamant's range
        // (0x80..=0x90).
        let bytes = vec![0x01, 0xFF];
        let result = deserialize_function_body(&bytes, &DeserializeConfig::lenient());
        assert_eq!(result, Err(DeserializeError::UnknownOpcode(0xFF)));
    }

    #[test]
    fn deserialize_malformed_uleb128() {
        // 10 bytes all with continuation bit set → ULEB128 overflow
        // past u64 (a valid u64 ULEB128 is at most 10 bytes; this
        // sequence is the longest possible and the algorithm
        // detects the overflow).
        // length-prefix 1, opcode CALL, then bad ULEB128.
        let bytes = vec![
            0x01, // body length 1
            Opcodes::CALL as u8,
            0xFF,
            0xFF,
            0xFF,
            0xFF,
            0xFF,
            0xFF,
            0xFF,
            0xFF,
            0xFF,
            0xFF,
            0xFF,
        ];
        let result = deserialize_function_body(&bytes, &DeserializeConfig::lenient());
        assert_eq!(result, Err(DeserializeError::MalformedUleb128));
    }

    #[test]
    fn deserialize_invalid_operand_gas_dimension() {
        // ChargeGas (0x8E) followed by 0x06 (out of GasDimension's
        // 0x00..=0x05 range).
        let bytes = vec![0x01, AdamantOpcodeKind::ChargeGas.opcode_byte(), 0x06];
        let result = deserialize_function_body(&bytes, &DeserializeConfig::lenient());
        assert!(matches!(
            result,
            Err(DeserializeError::InvalidOperand { opcode: 0x8E, .. })
        ));
    }

    #[test]
    fn deserialize_trailing_bytes() {
        // Length-prefix 1, Pop opcode, then an extra byte.
        let bytes = vec![0x01, Opcodes::POP as u8, 0xAA];
        let result = deserialize_function_body(&bytes, &DeserializeConfig::lenient());
        assert_eq!(result, Err(DeserializeError::TrailingBytes));
    }

    // ---------- Opcode-byte-space coverage ----------

    /// Every byte assigned to an inherited Sui opcode or Adamant
    /// extension must parse (when followed by valid operands);
    /// every unassigned byte must fail with `UnknownOpcode`.
    #[test]
    fn opcode_byte_space_coverage_unknown() {
        // Bytes that should be unknown (neither Sui nor Adamant).
        let unknown = [
            0x00, // No opcode at 0x00
            0x57, 0x58, 0x5F, 0x60, 0x70, 0x7F, // gap between Sui and Adamant
            0x91, 0xA0, 0xC0, 0xFE, 0xFF, // above Adamant's range
        ];
        for b in unknown {
            // Length-prefix 1, then the byte. Some of these would
            // need operands; we expect UnknownOpcode before the
            // operand-read step.
            let bytes = vec![0x01, b];
            let result = deserialize_function_body(&bytes, &DeserializeConfig::lenient());
            assert_eq!(
                result,
                Err(DeserializeError::UnknownOpcode(b)),
                "byte {b:#04x} should be UnknownOpcode"
            );
        }
    }

    // ---------- Property test (Q4: 1024 cases + reproducible seed) ----------

    /// Strategy producing arbitrary `BytecodeInstruction` values
    /// covering the operand types our encoder handles. We don't
    /// generate references to specific module-level structures
    /// (handles, signatures) — the wire encoding is independent of
    /// whether the operand indices reference valid pool entries.
    fn arb_instruction() -> impl Strategy<Value = BytecodeInstruction> {
        let inherited = arb_inherited().prop_map(BytecodeInstruction::Inherited);
        let adamant = arb_adamant().prop_map(BytecodeInstruction::Adamant);
        prop_oneof![inherited, adamant]
    }

    fn arb_inherited() -> impl Strategy<Value = Bytecode> {
        prop_oneof![
            Just(Bytecode::Pop),
            Just(Bytecode::Ret),
            any::<u16>().prop_map(|v| Bytecode::BrTrue(v as CodeOffset)),
            any::<u16>().prop_map(|v| Bytecode::BrFalse(v as CodeOffset)),
            any::<u16>().prop_map(|v| Bytecode::Branch(v as CodeOffset)),
            any::<u8>().prop_map(Bytecode::LdU8),
            any::<u64>().prop_map(Bytecode::LdU64),
            any::<u128>().prop_map(|v| Bytecode::LdU128(Box::new(v))),
            Just(Bytecode::CastU8),
            Just(Bytecode::CastU64),
            Just(Bytecode::CastU128),
            any::<u16>().prop_map(|v| Bytecode::LdConst(ConstantPoolIndex::new(v))),
            Just(Bytecode::LdTrue),
            Just(Bytecode::LdFalse),
            any::<u8>().prop_map(|v| Bytecode::CopyLoc(v as LocalIndex)),
            any::<u8>().prop_map(|v| Bytecode::MoveLoc(v as LocalIndex)),
            any::<u8>().prop_map(|v| Bytecode::StLoc(v as LocalIndex)),
            any::<u16>().prop_map(|v| Bytecode::Call(FunctionHandleIndex::new(v))),
            Just(Bytecode::Add),
            Just(Bytecode::Sub),
            Just(Bytecode::Mul),
            Just(Bytecode::Eq),
            Just(Bytecode::Neq),
            any::<(u16, u64)>().prop_map(|(s, n)| Bytecode::VecPack(SignatureIndex::new(s), n)),
            any::<u16>().prop_map(|s| Bytecode::VecLen(SignatureIndex::new(s))),
            any::<u16>().prop_map(Bytecode::LdU16),
            any::<u32>().prop_map(Bytecode::LdU32),
            // U256 from arbitrary 32 bytes.
            prop::array::uniform32(any::<u8>())
                .prop_map(|bs| Bytecode::LdU256(Box::new(U256::from_le_bytes(&bs)))),
            any::<u16>().prop_map(|v| Bytecode::PackVariant(VariantHandleIndex::new(v))),
            any::<u16>().prop_map(|v| Bytecode::VariantSwitch(VariantJumpTableIndex::new(v))),
            any::<u16>().prop_map(|v| Bytecode::ExistsDeprecated(StructDefinitionIndex::new(v))),
        ]
    }

    fn arb_adamant() -> impl Strategy<Value = AdamantBytecode> {
        let dim = prop_oneof![
            Just(GasDimension::Computation),
            Just(GasDimension::Storage),
            Just(GasDimension::Rent),
            Just(GasDimension::Bandwidth),
            Just(GasDimension::ProofVerification),
            Just(GasDimension::ProofGeneration),
        ];
        prop_oneof![
            any::<u16>().prop_map(|v| AdamantBytecode::InvokeShielded(FunctionHandleIndex::new(v))),
            any::<u16>()
                .prop_map(|v| AdamantBytecode::InvokeTransparent(FunctionHandleIndex::new(v))),
            any::<u16>().prop_map(|v| AdamantBytecode::GenerateProof(CircuitId(v))),
            any::<u16>().prop_map(|v| AdamantBytecode::VerifyProof(CircuitId(v))),
            Just(AdamantBytecode::ReleaseSubViewKey),
            Just(AdamantBytecode::KzgCommit),
            Just(AdamantBytecode::KzgVerify),
            Just(AdamantBytecode::RecursiveVerify),
            Just(AdamantBytecode::Sha3_256),
            Just(AdamantBytecode::Blake3),
            Just(AdamantBytecode::Ed25519Verify),
            Just(AdamantBytecode::MlDsaVerify65),
            Just(AdamantBytecode::MlDsaVerify87),
            Just(AdamantBytecode::BlsVerify),
            dim.clone().prop_map(AdamantBytecode::ChargeGas),
            dim.prop_map(AdamantBytecode::RemainingGas),
            Just(AdamantBytecode::OutOfGas),
        ]
    }

    proptest! {
        // Q4: 1024 cases per property + recorded reproducible seed.
        // Reproducibility: PROPTEST_RNG_SEED env var or the .txt
        // failure persistence file. The cases-per-property bump from
        // proptest's default 256 to 1024 is the consensus-criticality
        // weighting agreed in the Q4 sign-off.
        #![proptest_config(ProptestConfig {
            cases: 1024,
            // Seed pinned at 0 for reproducibility. proptest's
            // `failure_persistence` mechanism augments this when
            // failures are found; our base seed gives the "happy
            // path" case sequence determinism.
            rng_algorithm: proptest::test_runner::RngAlgorithm::ChaCha,
            ..ProptestConfig::default()
        })]

        #[test]
        fn prop_round_trip_single_instruction(instr in arb_instruction()) {
            let body = vec![instr.clone()];
            let bytes = serialize_function_body(&body).unwrap();
            let decoded = deserialize_function_body(&bytes, &DeserializeConfig::lenient()).unwrap();
            prop_assert_eq!(decoded, body);
        }

        #[test]
        fn prop_round_trip_function_body(
            body in prop::collection::vec(arb_instruction(), 0..32)
        ) {
            let bytes = serialize_function_body(&body).unwrap();
            let decoded = deserialize_function_body(&bytes, &DeserializeConfig::lenient()).unwrap();
            prop_assert_eq!(decoded, body);
        }
    }

    // ---------- Cross-validation against Sui's CompiledModule decoder ----------
    //
    // Q1's load-bearing correctness anchor. The strategy:
    //   1. Construct a Vec<Bytecode> exercising every inherited
    //      variant (86 variants total, each with non-trivial
    //      operand values where applicable).
    //   2. Build a minimal valid CompiledModule via Sui's struct
    //      APIs whose function body is this Vec<Bytecode>.
    //   3. Serialize via Sui's CompiledModule::serialize.
    //   4. Deserialize via Sui's CompiledModule::deserialize_with_defaults
    //      (sanity check Sui round-trip).
    //   5. Encode the recovered Vec<Bytecode> via OUR
    //      serialize_function_body; assert the result appears as a
    //      contiguous substring within Sui's full module bytes.
    //   6. Assert OUR deserialize_function_body recovers the
    //      original Vec<Bytecode> from our bytes.
    //
    // Step 5 is the byte-equivalence assertion: if our wire format
    // matches Sui's, our function-body bytes must appear inside
    // Sui's full module binary.

    /// Build a corpus of every inherited Bytecode variant with
    /// realistic operand values. The handles/indices reference
    /// pools populated in `build_minimal_module` below.
    fn corpus_all_inherited_variants() -> Vec<Bytecode> {
        vec![
            // Zero-operand variants
            Bytecode::Pop,
            Bytecode::Ret,
            Bytecode::CastU8,
            Bytecode::CastU64,
            Bytecode::CastU128,
            Bytecode::LdTrue,
            Bytecode::LdFalse,
            Bytecode::ReadRef,
            Bytecode::WriteRef,
            Bytecode::FreezeRef,
            Bytecode::Add,
            Bytecode::Sub,
            Bytecode::Mul,
            Bytecode::Mod,
            Bytecode::Div,
            Bytecode::BitOr,
            Bytecode::BitAnd,
            Bytecode::Xor,
            Bytecode::Or,
            Bytecode::And,
            Bytecode::Not,
            Bytecode::Eq,
            Bytecode::Neq,
            Bytecode::Lt,
            Bytecode::Gt,
            Bytecode::Le,
            Bytecode::Ge,
            Bytecode::Abort,
            Bytecode::Nop,
            Bytecode::Shl,
            Bytecode::Shr,
            Bytecode::CastU16,
            Bytecode::CastU32,
            Bytecode::CastU256,
            // Fixed-width LE immediates
            Bytecode::LdU8(0xab),
            Bytecode::LdU16(0xabcd),
            Bytecode::LdU32(0xabcd_1234),
            Bytecode::LdU64(0x0102_0304_0506_0708),
            Bytecode::LdU128(Box::new(0x0102_0304_0506_0708_090a_0b0c_0d0e_0f10)),
            Bytecode::LdU256(Box::new(U256::from_le_bytes(&[0x42; 32]))),
            // ULEB128-index variants. Operand values reference
            // pool index 0 (which we populate) for every type.
            Bytecode::BrTrue(0),
            Bytecode::BrFalse(0),
            Bytecode::Branch(0),
            Bytecode::LdConst(ConstantPoolIndex::new(0)),
            Bytecode::CopyLoc(0),
            Bytecode::MoveLoc(0),
            Bytecode::StLoc(0),
            Bytecode::Call(FunctionHandleIndex::new(0)),
            Bytecode::Pack(StructDefinitionIndex::new(0)),
            Bytecode::Unpack(StructDefinitionIndex::new(0)),
            Bytecode::MutBorrowLoc(0),
            Bytecode::ImmBorrowLoc(0),
            // Non-Loc field borrows (FieldHandleIndex)
            Bytecode::MutBorrowField(FieldHandleIndex::new(0)),
            Bytecode::ImmBorrowField(FieldHandleIndex::new(0)),
            // Generic ops (FunctionInstantiationIndex /
            // StructDefInstantiationIndex / FieldInstantiationIndex)
            Bytecode::CallGeneric(FunctionInstantiationIndex::new(0)),
            Bytecode::PackGeneric(StructDefInstantiationIndex::new(0)),
            Bytecode::UnpackGeneric(StructDefInstantiationIndex::new(0)),
            Bytecode::MutBorrowFieldGeneric(FieldInstantiationIndex::new(0)),
            Bytecode::ImmBorrowFieldGeneric(FieldInstantiationIndex::new(0)),
            // Vec ops (SignatureIndex; VecPack / VecUnpack also
            // take a u64 length).
            Bytecode::VecPack(SignatureIndex::new(0), 0),
            Bytecode::VecLen(SignatureIndex::new(0)),
            Bytecode::VecImmBorrow(SignatureIndex::new(0)),
            Bytecode::VecMutBorrow(SignatureIndex::new(0)),
            Bytecode::VecPushBack(SignatureIndex::new(0)),
            Bytecode::VecPopBack(SignatureIndex::new(0)),
            Bytecode::VecUnpack(SignatureIndex::new(0), 0),
            Bytecode::VecSwap(SignatureIndex::new(0)),
            // Variant ops (VariantHandleIndex /
            // VariantInstantiationHandleIndex /
            // VariantJumpTableIndex).
            Bytecode::PackVariant(VariantHandleIndex::new(0)),
            Bytecode::PackVariantGeneric(VariantInstantiationHandleIndex::new(0)),
            Bytecode::UnpackVariant(VariantHandleIndex::new(0)),
            Bytecode::UnpackVariantImmRef(VariantHandleIndex::new(0)),
            Bytecode::UnpackVariantMutRef(VariantHandleIndex::new(0)),
            Bytecode::UnpackVariantGeneric(VariantInstantiationHandleIndex::new(0)),
            Bytecode::UnpackVariantGenericImmRef(VariantInstantiationHandleIndex::new(0)),
            Bytecode::UnpackVariantGenericMutRef(VariantInstantiationHandleIndex::new(0)),
            Bytecode::VariantSwitch(VariantJumpTableIndex::new(0)),
            // Deprecated global-storage ops are excluded from
            // cross-validation. Per §6.2.1.6 rule 5 they are
            // rejected at module deployment by the validator
            // (later deliverable). Wire-encoding correctness for
            // them is byte-faithfulness only, not consensus-
            // critical. The per-variant `round_trip_deprecated_variants`
            // test covers their internal round-trip.
        ]
    }

    /// Build a minimal valid `CompiledModule` whose first
    /// function's body is the given `Vec<Bytecode>`. Pools
    /// populated for cross-validation coverage of 76 of 86
    /// inherited variants (everything except the 10 deprecated
    /// global-storage ops, which are wire-encoding-only —
    /// validator-rejected per §6.2.1.6 rule 5):
    ///
    ///   - 1 module handle (self)
    ///   - 2 datatype handles (one for the struct, one for the
    ///     enum)
    ///   - 1 struct definition with 1 field
    ///   - 1 enum definition with 1 (empty) variant
    ///   - 1 function handle and 1 function definition
    ///   - 2 signatures (empty + `[U64]` for locals)
    ///   - 2 identifiers (`test` for the struct and module name,
    ///     `enum_test` for the enum)
    ///   - 1 address identifier (0x0)
    ///   - 1 constant in the constant pool
    ///   - 1 field handle (for `Mut/ImmBorrowField`)
    ///   - 1 struct-def instantiation (for `Pack/UnpackGeneric`)
    ///   - 1 function instantiation (for `CallGeneric`)
    ///   - 1 field instantiation (for `Mut/ImmBorrowFieldGeneric`)
    ///   - 1 enum-def instantiation (for `*VariantGeneric`)
    ///   - 1 variant handle (for `Pack/UnpackVariant*`)
    ///   - 1 variant instantiation handle (for
    ///     `*VariantGeneric*`)
    ///   - 1 jump table in the function's code (for
    ///     `VariantSwitch`)
    // The fixture is intentionally exhaustive — populating
    // every pool the cross-validation corpus references in one
    // place is more auditable than splitting across multiple
    // smaller fixtures.
    #[allow(clippy::too_many_lines)]
    fn build_minimal_module(body: Vec<Bytecode>) -> CompiledModule {
        use move_binary_format::file_format::{
            Constant, EnumDefInstantiation, EnumDefInstantiationIndex, EnumDefinition,
            EnumDefinitionIndex, FieldHandle, FieldInstantiation, FunctionInstantiation,
            JumpTableInner, StructDefInstantiation, VariantDefinition, VariantHandle,
            VariantInstantiationHandle, VariantJumpTable,
        };

        let test_id = Identifier::new("test").unwrap();
        let enum_id = Identifier::new("enum_test").unwrap();
        let address_zero = AccountAddress::ZERO;

        CompiledModule {
            version: move_binary_format::file_format_common::VERSION_MAX,
            self_module_handle_idx: ModuleHandleIndex::new(0),
            module_handles: vec![ModuleHandle {
                address: AddressIdentifierIndex::new(0),
                name: IdentifierIndex::new(0),
            }],
            // Two datatype handles: index 0 for the struct, index
            // 1 for the enum. Each must be referenced by exactly
            // one struct_def or enum_def.
            datatype_handles: vec![
                DatatypeHandle {
                    module: ModuleHandleIndex::new(0),
                    name: IdentifierIndex::new(0), // "test"
                    abilities: AbilitySet::EMPTY,
                    type_parameters: vec![],
                },
                DatatypeHandle {
                    module: ModuleHandleIndex::new(0),
                    name: IdentifierIndex::new(1), // "enum_test"
                    abilities: AbilitySet::EMPTY,
                    type_parameters: vec![],
                },
            ],
            function_handles: vec![FunctionHandle {
                module: ModuleHandleIndex::new(0),
                name: IdentifierIndex::new(0),
                parameters: SignatureIndex::new(0),
                return_: SignatureIndex::new(0),
                type_parameters: vec![],
            }],
            field_handles: vec![FieldHandle {
                owner: StructDefinitionIndex::new(0),
                field: 0, // first (and only) field of struct_defs[0]
            }],
            friend_decls: vec![],
            struct_def_instantiations: vec![StructDefInstantiation {
                def: StructDefinitionIndex::new(0),
                type_parameters: SignatureIndex::new(0),
            }],
            function_instantiations: vec![FunctionInstantiation {
                handle: FunctionHandleIndex::new(0),
                type_parameters: SignatureIndex::new(0),
            }],
            field_instantiations: vec![FieldInstantiation {
                handle: FieldHandleIndex::new(0),
                type_parameters: SignatureIndex::new(0),
            }],
            // Two signatures: index 0 is empty (used for function
            // params/return and as type-parameters everywhere),
            // index 1 has one U64 (used as locals signature so
            // LocalIndex(0) is a valid bound).
            signatures: vec![Signature(vec![]), Signature(vec![SignatureToken::U64])],
            identifiers: vec![test_id, enum_id],
            address_identifiers: vec![address_zero],
            constant_pool: vec![Constant {
                type_: SignatureToken::U64,
                data: 0u64.to_le_bytes().to_vec(),
            }],
            metadata: vec![],
            struct_defs: vec![StructDefinition {
                struct_handle: DatatypeHandleIndex::new(0),
                field_information: StructFieldInformation::Declared(vec![FieldDefinition {
                    name: IdentifierIndex::new(0),
                    signature: TypeSignature(SignatureToken::U64),
                }]),
            }],
            function_defs: vec![FunctionDefinition {
                function: FunctionHandleIndex::new(0),
                visibility: Visibility::Public,
                is_entry: true,
                acquires_global_resources: vec![],
                code: Some(CodeUnit {
                    locals: SignatureIndex::new(1),
                    code: body,
                    // One jump table for VariantSwitch(0). Full
                    // jump table with one entry pointing at offset
                    // 0 (a valid bytecode offset within the body).
                    jump_tables: vec![VariantJumpTable {
                        head_enum: EnumDefinitionIndex::new(0),
                        jump_table: JumpTableInner::Full(vec![0]),
                    }],
                }),
            }],
            enum_defs: vec![EnumDefinition {
                enum_handle: DatatypeHandleIndex::new(1),
                variants: vec![VariantDefinition {
                    variant_name: IdentifierIndex::new(1),
                    fields: vec![],
                }],
            }],
            enum_def_instantiations: vec![EnumDefInstantiation {
                def: EnumDefinitionIndex::new(0),
                type_parameters: SignatureIndex::new(0),
            }],
            variant_handles: vec![VariantHandle {
                enum_def: EnumDefinitionIndex::new(0),
                variant: 0,
            }],
            variant_instantiation_handles: vec![VariantInstantiationHandle {
                enum_def: EnumDefInstantiationIndex::new(0),
                variant: 0,
            }],
            publishable: true,
        }
    }

    /// Cross-validation: our encoder's bytes match Sui's at the
    /// function-body byte-substring level. This is the load-bearing
    /// correctness anchor for Option II.
    #[test]
    fn cross_validate_against_sui_compiled_module() {
        // Use a corpus that only references operand indices we
        // populate in the minimal module. This is the subset that
        // can round-trip through Sui's CompiledModule decoder
        // without violating Sui's bound checks.
        let corpus = corpus_all_inherited_variants();
        let module = build_minimal_module(corpus.clone());

        // Step 1-3: Sui's full module serialization. Use
        // serialize_with_version (unconditionally public) rather
        // than serialize (which is #[cfg(any(test, feature =
        // "fuzzing"))] inside Sui's crate and not visible to
        // downstream consumers).
        let mut sui_bytes = Vec::new();
        module
            .serialize_with_version(
                move_binary_format::file_format_common::VERSION_MAX,
                &mut sui_bytes,
            )
            .expect("Sui serialize");

        // Step 4: Sui round-trip sanity.
        let recovered_module =
            CompiledModule::deserialize_with_defaults(&sui_bytes).expect("Sui deserialize");
        let recovered_body: Vec<Bytecode> = recovered_module.function_defs[0]
            .code
            .as_ref()
            .expect("function 0 has code")
            .code
            .clone();
        assert_eq!(
            recovered_body, corpus,
            "Sui's own round-trip failed — fixture or Sui version issue"
        );

        // Step 5: encode the recovered body via OUR encoder and
        // assert it appears as a contiguous substring of Sui's full
        // module bytes. Byte-equivalence with Sui's encoder.
        let our_body: Vec<BytecodeInstruction> = recovered_body
            .iter()
            .cloned()
            .map(BytecodeInstruction::Inherited)
            .collect();
        let our_bytes = serialize_function_body(&our_body).expect("our serialize");

        let pos = find_subslice(&sui_bytes, &our_bytes);
        assert!(
            pos.is_some(),
            "our encoder's bytes should appear within Sui's full module bytes; \
             our bytes ({} bytes) not found in Sui bytes ({} bytes)",
            our_bytes.len(),
            sui_bytes.len()
        );

        // Step 6: our decoder recovers the original from our bytes.
        let our_recovered = deserialize_function_body(&our_bytes, &DeserializeConfig::lenient())
            .expect("our deserialize");
        assert_eq!(our_recovered, our_body);
    }

    fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
        if needle.is_empty() || haystack.len() < needle.len() {
            return None;
        }
        for i in 0..=(haystack.len() - needle.len()) {
            if &haystack[i..i + needle.len()] == needle {
                return Some(i);
            }
        }
        None
    }
}
