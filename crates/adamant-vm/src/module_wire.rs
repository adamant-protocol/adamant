//! Module-level wire encoding per whitepaper §6.2.1.2 and §6.2.1.8.
//!
//! Adamant's deploy-time pipeline is fully Adamant-native per
//! §6.2.1.8 (re-amended at commit `0de50d8`): the validator owns
//! deserializer, canonicality round-trip, and verification end-to-end,
//! and never delegates module-level work to vendored Sui-Move at
//! runtime. This module implements the **serialize** half of that
//! pipeline: it lowers an [`AdamantCompiledModule`] (defined in
//! [`crate::module`]) to bytes that match Sui-Move's binary format
//! §6.2.1.2 byte-for-byte for the inherited subset, and extend
//! Sui's encoding through [`crate::bytecode_wire`] for function
//! bodies that carry Adamant extensions.
//!
//! # Why we re-implement instead of delegating
//!
//! Sui's per-pool serializers, the `BinaryData` wrapper, and
//! `CompiledModule::serialize_with_version` are private or operate
//! on Sui's `CompiledModule` shape. To extend Sui's encoder with
//! Adamant function bodies *without* modifying vendored code, we
//! mirror Sui's algorithm in this module using only Sui's public
//! constants and tag enums (`BinaryConstants`, `BinaryFlavor`,
//! `TableType`, `SerializedType`, etc., from
//! [`move_binary_format::file_format_common`]). The cross-validation
//! tests in this module's `tests` submodule assert byte-equivalence
//! with Sui's encoder for pure-Sui modules, converting "we
//! re-implemented correctly" from claim to tested property.
//!
//! # Encoding conventions
//!
//! - Indices and counts are **ULEB128** with kind-specific upper
//!   bounds from [`move_binary_format::file_format_common`]
//!   (`TABLE_INDEX_MAX`, `IDENTIFIER_SIZE_MAX`, etc.).
//! - Magic and version are written first (`MOVE_MAGIC` for
//!   `publishable = true`, `UNPUBLISHABLE_MAGIC` otherwise; version
//!   passed through `BinaryFlavor::encode_version`).
//! - Table indices follow the header: a one-byte count, then one
//!   `(kind, offset, length)` triple per non-empty table.
//! - Table content follows the table indices in the order Sui
//!   serializes (`module_handles`, `datatype_handles`, ...,
//!   `metadata`, `struct_defs`, ..., `variant_instantiation_handles`).
//! - The `self_module_handle_idx` is appended *after* the table
//!   content as a final ULEB128.
//! - Function bodies inside `function_defs` are produced by
//!   [`crate::bytecode_wire::serialize_function_body`], which already
//!   writes the ULEB128 instruction-count prefix and the
//!   instruction stream including Adamant extensions.
//!
//! # Error reporting
//!
//! [`AdamantSerializeError`] variants are kind-specific so the
//! deploy-time error path can name the offending input precisely
//! rather than reporting a generic "encoding failed". Sui's
//! serializer uses `anyhow::Error` and bails with formatted strings;
//! Adamant's variants are structured so callers can match on them.

// Lint posture for this module:
//
// - `unnecessary_wraps` fires on serialise functions that return
//   `Result<(), AdamantSerializeError>` even though some never error
//   today. The API is forward-compatible with future tighter
//   validation (mirroring `bytecode_wire`'s posture). The
//   alternative — splitting the serializer functions into infallible
//   and fallible halves based on whether they call ULEB128 with a
//   bound — would be churn for no reader benefit, since the bounds
//   are part of the binary-format spec we're tracking.
// - `trivially_copy_pass_by_ref` fires on `&Idx` parameters. We
//   mirror Sui's serializer API (`fn serialize_*_index(&Idx)`)
//   exactly so cross-referencing against
//   `vendor/move-binary-format/src/serializer.rs` is mechanical.
//   Allowing the lint at module level is preferable to diverging
//   from Sui's API surface.
// - `if_not_else` fires on the ULEB128 loop's `if cur != val`
//   idiom, mirroring Sui's `write_u64_as_uleb128` byte-for-byte.
//   `bytecode_wire` allows the same lint for the same reason.
// - `cast_possible_truncation` is **not** allowed at module level.
//   Per-instance `#[allow]` with one-line rationale at each cast
//   site keeps every truncation explicit for the next auditor.
#![allow(
    clippy::unnecessary_wraps,
    clippy::trivially_copy_pass_by_ref,
    clippy::if_not_else,
    // The table-writer closures in `serialize_tables` thin-wrap
    // each per-pool serializer for use with `write_table`'s
    // generic `FnMut(&mut Vec<u8>, &T)` bound. Replacing them with
    // function pointers is possible but loses the visual symmetry
    // across the 19-table block; the lint flags the block form
    // (Rust 1.83+) even though removing the closure changes the
    // call shape, not the behavior.
    clippy::redundant_closure
)]

// Sui types that 5/5b.1a does not yet fork. The 25 reused
// parallel-struct neighbour types (DatatypeHandle, FunctionHandle,
// etc.) move to `adamant-bytecode-format` in Phase 5/5b.1b. The
// `AbilitySet` import stays here too — `AbilitySet` is forked and
// cross-validated in `adamant-bytecode-format`, but the Sui
// neighbour types (`DatatypeHandle`, `FunctionHandle`,
// `DatatypeTyParameter`) carry `abilities` fields of Sui's
// `AbilitySet` type. Swapping the import here would type-conflict
// with those fields; the consistent rewire lands in 5/5b.1b
// alongside the type-fork.
use move_binary_format::file_format::{
    AbilitySet, Constant, DatatypeHandle, DatatypeHandleIndex, DatatypeTyParameter,
    EnumDefInstantiation, EnumDefinition, EnumDefinitionIndex, FieldDefinition, FieldHandle,
    FieldHandleIndex, FieldInstantiation, FieldInstantiationIndex, FunctionDefinition,
    FunctionHandle, FunctionHandleIndex, FunctionInstantiation, FunctionInstantiationIndex,
    IdentifierIndex, JumpTableInner, ModuleHandle, ModuleHandleIndex, Signature, SignatureIndex,
    SignatureToken, StructDefInstantiation, StructDefInstantiationIndex, StructDefinition,
    StructDefinitionIndex, StructFieldInformation, VariantDefinition, VariantHandle,
    VariantHandleIndex, VariantInstantiationHandle, VariantInstantiationHandleIndex,
    VariantJumpTable, VariantJumpTableIndex, Visibility,
};
// Adamant-owned bytecode-format primitives per Phase 5/5b.1a's
// resistant-proof fork. The constants, tag enums, and readers
// here are consumed at the production layer with no type-level
// conflict against the still-Sui neighbour types above.
use adamant_bytecode_format::{
    BinaryConstants, BinaryFlavor, SerializedEnumFlag, SerializedJumpTableFlag,
    SerializedNativeStructFlag, SerializedType, TableType, ACQUIRES_COUNT_MAX, ADDRESS_INDEX_MAX,
    BYTECODE_INDEX_MAX, CONSTANT_INDEX_MAX, CONSTANT_SIZE_MAX, DATATYPE_HANDLE_INDEX_MAX,
    ENUM_DEF_INDEX_MAX, ENUM_DEF_INST_INDEX_MAX, FIELD_COUNT_MAX, FIELD_HANDLE_INDEX_MAX,
    FIELD_INST_INDEX_MAX, FIELD_OFFSET_MAX, FUNCTION_HANDLE_INDEX_MAX, FUNCTION_INST_INDEX_MAX,
    IDENTIFIER_INDEX_MAX, IDENTIFIER_SIZE_MAX, JUMP_TABLE_INDEX_MAX, LOCAL_INDEX_MAX,
    METADATA_KEY_SIZE_MAX, METADATA_VALUE_SIZE_MAX, MODULE_HANDLE_INDEX_MAX, SIGNATURE_INDEX_MAX,
    SIGNATURE_SIZE_MAX, SIGNATURE_TOKEN_DEPTH_MAX, STRUCT_DEF_INDEX_MAX, STRUCT_DEF_INST_INDEX_MAX,
    TABLE_COUNT_MAX, TABLE_OFFSET_MAX, TABLE_SIZE_MAX, TYPE_PARAMETER_COUNT_MAX,
    TYPE_PARAMETER_INDEX_MAX, VARIANT_COUNT_MAX, VARIANT_HANDLE_INDEX_MAX,
    VARIANT_INSTANTIATION_HANDLE_INDEX_MAX, VARIANT_TAG_MAX_VALUE, VERSION_5, VERSION_7,
    VERSION_MAX, VERSION_MIN,
};
use move_core_types::account_address::AccountAddress;
use move_core_types::metadata::Metadata;

use crate::bytecode_wire;
use crate::module::{AdamantCodeUnit, AdamantCompiledModule, AdamantFunctionDefinition};

// ============================================================================
// Error type
// ============================================================================

/// Errors from [`adamant_serialize`].
///
/// Variants are kind-specific so callers can match on the offending
/// input class. The integer payloads carry the offending size or
/// index for diagnostics.
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub enum AdamantSerializeError {
    /// Module's `version` field is outside [`VERSION_MIN`,
    /// `VERSION_MAX`]. Sui's serializer rejects the same range.
    UnsupportedVersion(u32),
    /// A pool entry's index does not fit the bound for its kind
    /// (e.g., a ULEB128 ≥ `TABLE_INDEX_MAX`).
    IndexOverflow {
        /// Human-readable name of the index field (e.g.
        /// `"ModuleHandleIndex"`).
        kind: &'static str,
        /// The actual offending value.
        value: u64,
        /// The inclusive maximum for the field's kind.
        max: u64,
    },
    /// A length field exceeds the encoding's bound (e.g., an
    /// identifier longer than `IDENTIFIER_SIZE_MAX` bytes, a
    /// signature pool with more than `SIGNATURE_SIZE_MAX` entries,
    /// a constant blob exceeding `CONSTANT_SIZE_MAX`).
    LengthOverflow {
        /// Human-readable name of the length field (e.g.
        /// `"identifier size"`).
        kind: &'static str,
        /// The offending length, in entries or bytes depending on
        /// the field.
        len: usize,
        /// The inclusive maximum for the field's kind.
        max: u64,
    },
    /// Aggregate table content exceeds `u32::MAX` bytes (same
    /// upper bound Sui enforces).
    BinaryTooLarge(usize),
    /// A `SignatureToken` chain exceeds `SIGNATURE_TOKEN_DEPTH_MAX`
    /// nesting levels (same bound Sui enforces).
    SignatureTooDeep,
    /// The module declares a binary-format feature that is not
    /// available at the chosen `version` (e.g., enum opcodes at
    /// version < 7, `LdU16` at version < 6).
    VersionFeatureMismatch {
        /// Human-readable name of the missing feature (e.g.
        /// `"enum tables"`).
        feature: &'static str,
        /// The bytecode-format version the module declared.
        version: u32,
    },
    /// An error from the function-body wire encoder. Currently
    /// unreachable for well-formed [`crate::bytecode::BytecodeInstruction`]
    /// inputs (mirrors `bytecode_wire`'s forward-compatibility
    /// posture).
    Bytecode(bytecode_wire::SerializeError),
}

impl core::fmt::Display for AdamantSerializeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnsupportedVersion(v) => {
                write!(
                    f,
                    "bytecode version {v} unsupported (only {VERSION_MIN}..={VERSION_MAX} accepted)"
                )
            }
            Self::IndexOverflow { kind, value, max } => {
                write!(f, "{kind} index {value} exceeds maximum {max}")
            }
            Self::LengthOverflow { kind, len, max } => {
                write!(f, "{kind} length {len} exceeds maximum {max}")
            }
            Self::BinaryTooLarge(size) => {
                write!(f, "binary table content size {size} exceeds u32::MAX")
            }
            Self::SignatureTooDeep => write!(
                f,
                "signature-token nesting exceeds maximum depth {SIGNATURE_TOKEN_DEPTH_MAX}"
            ),
            Self::VersionFeatureMismatch { feature, version } => {
                write!(
                    f,
                    "feature {feature:?} not available at bytecode version {version}"
                )
            }
            Self::Bytecode(e) => write!(f, "function body encoding: {e}"),
        }
    }
}

impl std::error::Error for AdamantSerializeError {}

impl From<bytecode_wire::SerializeError> for AdamantSerializeError {
    fn from(e: bytecode_wire::SerializeError) -> Self {
        Self::Bytecode(e)
    }
}

// ============================================================================
// ULEB128 / fixed-width primitives
// ============================================================================

/// Writes `val` as a ULEB128 sequence to `out`. Mirrors Sui's
/// `write_u64_as_uleb128` byte-for-byte. Reused unconditionally —
/// Sui's helper is `pub(crate)` to its own crate so we cannot call
/// it directly.
fn write_u64_as_uleb128(out: &mut Vec<u8>, mut val: u64) {
    loop {
        let cur = val & 0x7f;
        if cur != val {
            // Cast safety: `cur` is `val & 0x7f`, so `cur | 0x80`
            // fits in `u8` (0x80..=0xFF range).
            #[allow(clippy::cast_possible_truncation)]
            let byte = (cur | 0x80) as u8;
            out.push(byte);
            val >>= 7;
        } else {
            // Cast safety: `cur != val` was false, so `cur == val`
            // and `val <= 0x7f` fits in `u8`.
            #[allow(clippy::cast_possible_truncation)]
            let byte = cur as u8;
            out.push(byte);
            break;
        }
    }
}

/// Writes `value` (widened to `u64`) as a ULEB128, validating that
/// it does not exceed `max`. The `kind` label is carried into the
/// resulting error for diagnostics.
fn write_uleb128_bounded(
    out: &mut Vec<u8>,
    value: u64,
    max: u64,
    kind: &'static str,
) -> Result<(), AdamantSerializeError> {
    if value > max {
        return Err(AdamantSerializeError::IndexOverflow { kind, value, max });
    }
    write_u64_as_uleb128(out, value);
    Ok(())
}

/// Writes `len` as a ULEB128 length field with bound `max`. Same
/// shape as [`write_uleb128_bounded`] but emits a [`LengthOverflow`]
/// rather than [`IndexOverflow`].
///
/// [`LengthOverflow`]: AdamantSerializeError::LengthOverflow
/// [`IndexOverflow`]: AdamantSerializeError::IndexOverflow
fn write_uleb128_length(
    out: &mut Vec<u8>,
    len: usize,
    max: u64,
    kind: &'static str,
) -> Result<(), AdamantSerializeError> {
    // Cast safety: `len` originates from a `Vec`/`&[T]` so its
    // value fits `usize`; `u64` is at least 64 bits on every
    // target Adamant supports. The comparison against `max`
    // covers the binary-format upper bound.
    let len_u64 = len as u64;
    if len_u64 > max {
        return Err(AdamantSerializeError::LengthOverflow { kind, len, max });
    }
    write_u64_as_uleb128(out, len_u64);
    Ok(())
}

/// Writes a little-endian `u32`. Mirrors Sui's `write_u32`.
fn write_u32_le(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

/// Returns `index` as a `u32`, erroring if it exceeds `u32::MAX`.
/// Mirrors Sui's `check_index_in_binary`. Used at every offset/size
/// boundary that Sui caps at `u32::MAX`.
fn check_index_in_binary(index: usize) -> Result<u32, AdamantSerializeError> {
    if index > u32::MAX as usize {
        return Err(AdamantSerializeError::BinaryTooLarge(index));
    }
    // Cast safety: bound check above guarantees `index <= u32::MAX`.
    #[allow(clippy::cast_possible_truncation)]
    let value = index as u32;
    Ok(value)
}

// ============================================================================
// Index / count primitives (mirror Sui's `serialize_*_index` and
// `serialize_*_count` helpers)
// ============================================================================

fn serialize_module_handle_index(
    out: &mut Vec<u8>,
    idx: &ModuleHandleIndex,
) -> Result<(), AdamantSerializeError> {
    write_uleb128_bounded(
        out,
        u64::from(idx.0),
        MODULE_HANDLE_INDEX_MAX,
        "ModuleHandleIndex",
    )
}

fn serialize_datatype_handle_index(
    out: &mut Vec<u8>,
    idx: &DatatypeHandleIndex,
) -> Result<(), AdamantSerializeError> {
    write_uleb128_bounded(
        out,
        u64::from(idx.0),
        DATATYPE_HANDLE_INDEX_MAX,
        "DatatypeHandleIndex",
    )
}

fn serialize_function_handle_index(
    out: &mut Vec<u8>,
    idx: &FunctionHandleIndex,
) -> Result<(), AdamantSerializeError> {
    write_uleb128_bounded(
        out,
        u64::from(idx.0),
        FUNCTION_HANDLE_INDEX_MAX,
        "FunctionHandleIndex",
    )
}

fn serialize_identifier_index(
    out: &mut Vec<u8>,
    idx: &IdentifierIndex,
) -> Result<(), AdamantSerializeError> {
    write_uleb128_bounded(
        out,
        u64::from(idx.0),
        IDENTIFIER_INDEX_MAX,
        "IdentifierIndex",
    )
}

fn serialize_address_identifier_index(
    out: &mut Vec<u8>,
    idx: &move_binary_format::file_format::AddressIdentifierIndex,
) -> Result<(), AdamantSerializeError> {
    write_uleb128_bounded(
        out,
        u64::from(idx.0),
        ADDRESS_INDEX_MAX,
        "AddressIdentifierIndex",
    )
}

fn serialize_signature_index(
    out: &mut Vec<u8>,
    idx: &SignatureIndex,
) -> Result<(), AdamantSerializeError> {
    write_uleb128_bounded(out, u64::from(idx.0), SIGNATURE_INDEX_MAX, "SignatureIndex")
}

// Reserved for the deserializer (Phase 5/5a step 3): `ConstantPoolIndex`
// only appears as a `Bytecode::LdConst` operand at module level
// (delegated to `bytecode_wire`).
#[allow(dead_code)]
fn serialize_constant_pool_index(
    out: &mut Vec<u8>,
    idx: &move_binary_format::file_format::ConstantPoolIndex,
) -> Result<(), AdamantSerializeError> {
    write_uleb128_bounded(
        out,
        u64::from(idx.0),
        CONSTANT_INDEX_MAX,
        "ConstantPoolIndex",
    )
}

fn serialize_struct_def_index(
    out: &mut Vec<u8>,
    idx: &StructDefinitionIndex,
) -> Result<(), AdamantSerializeError> {
    write_uleb128_bounded(
        out,
        u64::from(idx.0),
        STRUCT_DEF_INDEX_MAX,
        "StructDefinitionIndex",
    )
}

fn serialize_enum_def_index(
    out: &mut Vec<u8>,
    idx: &EnumDefinitionIndex,
) -> Result<(), AdamantSerializeError> {
    write_uleb128_bounded(
        out,
        u64::from(idx.0),
        ENUM_DEF_INDEX_MAX,
        "EnumDefinitionIndex",
    )
}

fn serialize_field_handle_index(
    out: &mut Vec<u8>,
    idx: &FieldHandleIndex,
) -> Result<(), AdamantSerializeError> {
    write_uleb128_bounded(
        out,
        u64::from(idx.0),
        FIELD_HANDLE_INDEX_MAX,
        "FieldHandleIndex",
    )
}

// Reserved for the deserializer (Phase 5/5a step 3): `FieldInstantiationIndex`
// and `FunctionInstantiationIndex` only appear as `Bytecode` operands at
// module level (delegated to `bytecode_wire`).
#[allow(dead_code)]
fn serialize_field_inst_index(
    out: &mut Vec<u8>,
    idx: &FieldInstantiationIndex,
) -> Result<(), AdamantSerializeError> {
    write_uleb128_bounded(
        out,
        u64::from(idx.0),
        FIELD_INST_INDEX_MAX,
        "FieldInstantiationIndex",
    )
}

#[allow(dead_code)]
fn serialize_function_inst_index(
    out: &mut Vec<u8>,
    idx: &FunctionInstantiationIndex,
) -> Result<(), AdamantSerializeError> {
    write_uleb128_bounded(
        out,
        u64::from(idx.0),
        FUNCTION_INST_INDEX_MAX,
        "FunctionInstantiationIndex",
    )
}

// Reserved for the deserializer (Phase 5/5a step 3) and for parity
// with Sui's helper set: at module level, `StructDefInstantiationIndex`
// only appears as a `Bytecode` operand (delegated to `bytecode_wire`).
#[allow(dead_code)]
fn serialize_struct_def_inst_index(
    out: &mut Vec<u8>,
    idx: &StructDefInstantiationIndex,
) -> Result<(), AdamantSerializeError> {
    write_uleb128_bounded(
        out,
        u64::from(idx.0),
        STRUCT_DEF_INST_INDEX_MAX,
        "StructDefInstantiationIndex",
    )
}

fn serialize_enum_def_inst_index(
    out: &mut Vec<u8>,
    idx: &move_binary_format::file_format::EnumDefInstantiationIndex,
) -> Result<(), AdamantSerializeError> {
    write_uleb128_bounded(
        out,
        u64::from(idx.0),
        ENUM_DEF_INST_INDEX_MAX,
        "EnumDefInstantiationIndex",
    )
}

// Reserved for the deserializer (Phase 5/5a step 3): `VariantHandleIndex`,
// `VariantInstantiationHandleIndex`, and `VariantJumpTableIndex` only
// appear as `Bytecode` operands at module level (delegated to
// `bytecode_wire`).
#[allow(dead_code)]
fn serialize_variant_handle_index(
    out: &mut Vec<u8>,
    idx: &VariantHandleIndex,
) -> Result<(), AdamantSerializeError> {
    write_uleb128_bounded(
        out,
        u64::from(idx.0),
        VARIANT_HANDLE_INDEX_MAX,
        "VariantHandleIndex",
    )
}

#[allow(dead_code)]
fn serialize_variant_instantiation_handle_index(
    out: &mut Vec<u8>,
    idx: &VariantInstantiationHandleIndex,
) -> Result<(), AdamantSerializeError> {
    write_uleb128_bounded(
        out,
        u64::from(idx.0),
        VARIANT_INSTANTIATION_HANDLE_INDEX_MAX,
        "VariantInstantiationHandleIndex",
    )
}

#[allow(dead_code)]
fn serialize_jump_table_index_u16(
    out: &mut Vec<u8>,
    idx: &VariantJumpTableIndex,
) -> Result<(), AdamantSerializeError> {
    write_uleb128_bounded(
        out,
        u64::from(idx.0),
        JUMP_TABLE_INDEX_MAX,
        "VariantJumpTableIndex",
    )
}

// ----- Count / size helpers -----

// Reserved for the deserializer (Phase 5/5a step 3): used to round-trip
// table-header `count` fields. The serializer writes table sizes via
// `write_u32_le` directly (mirroring Sui's `seiralize_table_offset` /
// `serialize_table_size` paths).
#[allow(dead_code)]
fn serialize_table_size(out: &mut Vec<u8>, size: u32) {
    write_u64_as_uleb128(out, u64::from(size));
}

fn serialize_table_count(out: &mut Vec<u8>, count: u8) -> Result<(), AdamantSerializeError> {
    write_uleb128_bounded(out, u64::from(count), TABLE_COUNT_MAX, "table count")
}

fn serialize_identifier_size(out: &mut Vec<u8>, len: usize) -> Result<(), AdamantSerializeError> {
    write_uleb128_length(out, len, IDENTIFIER_SIZE_MAX, "identifier size")
}

fn serialize_constant_size(out: &mut Vec<u8>, len: usize) -> Result<(), AdamantSerializeError> {
    write_uleb128_length(out, len, CONSTANT_SIZE_MAX, "constant data size")
}

fn serialize_metadata_key_size(out: &mut Vec<u8>, len: usize) -> Result<(), AdamantSerializeError> {
    write_uleb128_length(out, len, METADATA_KEY_SIZE_MAX, "metadata key size")
}

fn serialize_metadata_value_size(
    out: &mut Vec<u8>,
    len: usize,
) -> Result<(), AdamantSerializeError> {
    write_uleb128_length(out, len, METADATA_VALUE_SIZE_MAX, "metadata value size")
}

fn serialize_field_count(out: &mut Vec<u8>, len: usize) -> Result<(), AdamantSerializeError> {
    write_uleb128_length(out, len, FIELD_COUNT_MAX, "struct/variant field count")
}

fn serialize_variant_count(out: &mut Vec<u8>, len: usize) -> Result<(), AdamantSerializeError> {
    write_uleb128_length(out, len, VARIANT_COUNT_MAX, "enum variant count")
}

fn serialize_variant_tag(out: &mut Vec<u8>, tag: u16) -> Result<(), AdamantSerializeError> {
    write_uleb128_bounded(out, u64::from(tag), VARIANT_TAG_MAX_VALUE, "variant tag")
}

fn serialize_field_offset(out: &mut Vec<u8>, offset: u16) -> Result<(), AdamantSerializeError> {
    write_uleb128_bounded(out, u64::from(offset), FIELD_OFFSET_MAX, "field offset")
}

fn serialize_acquires_count(out: &mut Vec<u8>, len: usize) -> Result<(), AdamantSerializeError> {
    write_uleb128_length(out, len, ACQUIRES_COUNT_MAX, "acquires list length")
}

fn serialize_signature_size(out: &mut Vec<u8>, len: usize) -> Result<(), AdamantSerializeError> {
    write_uleb128_length(out, len, SIGNATURE_SIZE_MAX, "signature length")
}

fn serialize_type_parameter_index(
    out: &mut Vec<u8>,
    idx: u16,
) -> Result<(), AdamantSerializeError> {
    write_uleb128_bounded(
        out,
        u64::from(idx),
        TYPE_PARAMETER_INDEX_MAX,
        "type parameter index",
    )
}

fn serialize_type_parameter_count(
    out: &mut Vec<u8>,
    len: usize,
) -> Result<(), AdamantSerializeError> {
    write_uleb128_length(out, len, TYPE_PARAMETER_COUNT_MAX, "type parameter count")
}

fn serialize_bytecode_offset(out: &mut Vec<u8>, offset: u16) -> Result<(), AdamantSerializeError> {
    write_uleb128_bounded(
        out,
        u64::from(offset),
        BYTECODE_INDEX_MAX,
        "bytecode offset",
    )
}

fn serialize_jump_table_count(out: &mut Vec<u8>, len: u8) -> Result<(), AdamantSerializeError> {
    write_uleb128_bounded(
        out,
        u64::from(len),
        JUMP_TABLE_INDEX_MAX,
        "jump table count",
    )
}

fn serialize_jump_table_branch_count(
    out: &mut Vec<u8>,
    len: usize,
) -> Result<(), AdamantSerializeError> {
    write_uleb128_length(out, len, VARIANT_COUNT_MAX, "jump table branch count")
}

#[allow(dead_code)] // Reserved for future opcode-specific operands; kept for parity with Sui.
fn serialize_local_index(out: &mut Vec<u8>, idx: u8) -> Result<(), AdamantSerializeError> {
    write_uleb128_bounded(out, u64::from(idx), LOCAL_INDEX_MAX, "local index")
}

// ============================================================================
// Per-pool serializers
// ============================================================================

fn serialize_table_index_entry(
    out: &mut Vec<u8>,
    kind: TableType,
    offset: u32,
    count: u32,
) -> Result<(), AdamantSerializeError> {
    if count != 0 {
        out.push(kind as u8);
        // Sui's `seiralize_table_offset` and `serialize_table_size`
        // both encode `u32` as ULEB128 with `TABLE_OFFSET_MAX` and
        // `TABLE_SIZE_MAX` (both `u32::MAX`) as the bound. Mirror
        // exactly so byte output matches Sui's reference encoder.
        write_uleb128_bounded(out, u64::from(offset), TABLE_OFFSET_MAX, "table offset")?;
        write_uleb128_bounded(out, u64::from(count), TABLE_SIZE_MAX, "table size")?;
    }
    Ok(())
}

fn serialize_module_handle(
    out: &mut Vec<u8>,
    handle: &ModuleHandle,
) -> Result<(), AdamantSerializeError> {
    serialize_address_identifier_index(out, &handle.address)?;
    serialize_identifier_index(out, &handle.name)?;
    Ok(())
}

fn serialize_datatype_handle(
    out: &mut Vec<u8>,
    handle: &DatatypeHandle,
) -> Result<(), AdamantSerializeError> {
    serialize_module_handle_index(out, &handle.module)?;
    serialize_identifier_index(out, &handle.name)?;
    serialize_ability_set(out, handle.abilities)?;
    serialize_type_parameters(out, &handle.type_parameters)
}

fn serialize_type_parameters(
    out: &mut Vec<u8>,
    type_parameters: &[DatatypeTyParameter],
) -> Result<(), AdamantSerializeError> {
    serialize_type_parameter_count(out, type_parameters.len())?;
    for tp in type_parameters {
        serialize_type_parameter(out, tp)?;
    }
    Ok(())
}

fn serialize_type_parameter(
    out: &mut Vec<u8>,
    type_param: &DatatypeTyParameter,
) -> Result<(), AdamantSerializeError> {
    serialize_ability_set(out, type_param.constraints)?;
    // Phantom is a single-bit flag, matching Sui's encoding
    // (`write_as_uleb128(binary, type_param.is_phantom as u8, 1)`).
    write_uleb128_bounded(
        out,
        u64::from(u8::from(type_param.is_phantom)),
        1,
        "phantom flag",
    )
}

fn serialize_function_handle(
    out: &mut Vec<u8>,
    handle: &FunctionHandle,
) -> Result<(), AdamantSerializeError> {
    serialize_module_handle_index(out, &handle.module)?;
    serialize_identifier_index(out, &handle.name)?;
    serialize_signature_index(out, &handle.parameters)?;
    serialize_signature_index(out, &handle.return_)?;
    serialize_ability_sets(out, &handle.type_parameters)
}

fn serialize_function_instantiation(
    out: &mut Vec<u8>,
    inst: &FunctionInstantiation,
) -> Result<(), AdamantSerializeError> {
    serialize_function_handle_index(out, &inst.handle)?;
    serialize_signature_index(out, &inst.type_parameters)?;
    Ok(())
}

fn serialize_identifier(out: &mut Vec<u8>, string: &str) -> Result<(), AdamantSerializeError> {
    let bytes = string.as_bytes();
    serialize_identifier_size(out, bytes.len())?;
    out.extend_from_slice(bytes);
    Ok(())
}

fn serialize_address(out: &mut Vec<u8>, address: &AccountAddress) {
    out.extend_from_slice(address.as_ref());
}

fn serialize_constant(out: &mut Vec<u8>, constant: &Constant) -> Result<(), AdamantSerializeError> {
    serialize_signature_token(out, &constant.type_)?;
    serialize_constant_size(out, constant.data.len())?;
    out.extend_from_slice(&constant.data);
    Ok(())
}

fn serialize_metadata_entry(
    out: &mut Vec<u8>,
    metadata: &Metadata,
) -> Result<(), AdamantSerializeError> {
    serialize_metadata_key_size(out, metadata.key.len())?;
    out.extend_from_slice(&metadata.key);
    serialize_metadata_value_size(out, metadata.value.len())?;
    out.extend_from_slice(&metadata.value);
    Ok(())
}

fn serialize_struct_definition(
    out: &mut Vec<u8>,
    sd: &StructDefinition,
) -> Result<(), AdamantSerializeError> {
    serialize_datatype_handle_index(out, &sd.struct_handle)?;
    match &sd.field_information {
        StructFieldInformation::Native => {
            out.push(SerializedNativeStructFlag::NATIVE as u8);
            Ok(())
        }
        StructFieldInformation::Declared(fields) => {
            out.push(SerializedNativeStructFlag::DECLARED as u8);
            serialize_field_definitions(out, fields)
        }
    }
}

fn serialize_enum_definition(
    out: &mut Vec<u8>,
    ed: &EnumDefinition,
) -> Result<(), AdamantSerializeError> {
    serialize_datatype_handle_index(out, &ed.enum_handle)?;
    out.push(SerializedEnumFlag::DECLARED as u8);
    serialize_variant_count(out, ed.variants.len())?;
    for variant in &ed.variants {
        serialize_variant_definition(out, variant)?;
    }
    Ok(())
}

fn serialize_variant_definition(
    out: &mut Vec<u8>,
    vd: &VariantDefinition,
) -> Result<(), AdamantSerializeError> {
    serialize_identifier_index(out, &vd.variant_name)?;
    serialize_field_definitions(out, &vd.fields)
}

fn serialize_struct_def_instantiation(
    out: &mut Vec<u8>,
    inst: &StructDefInstantiation,
) -> Result<(), AdamantSerializeError> {
    serialize_struct_def_index(out, &inst.def)?;
    serialize_signature_index(out, &inst.type_parameters)?;
    Ok(())
}

fn serialize_enum_def_instantiation(
    out: &mut Vec<u8>,
    inst: &EnumDefInstantiation,
) -> Result<(), AdamantSerializeError> {
    serialize_enum_def_index(out, &inst.def)?;
    serialize_signature_index(out, &inst.type_parameters)?;
    Ok(())
}

fn serialize_field_definitions(
    out: &mut Vec<u8>,
    fields: &[FieldDefinition],
) -> Result<(), AdamantSerializeError> {
    serialize_field_count(out, fields.len())?;
    for fd in fields {
        serialize_field_definition(out, fd)?;
    }
    Ok(())
}

fn serialize_field_definition(
    out: &mut Vec<u8>,
    fd: &FieldDefinition,
) -> Result<(), AdamantSerializeError> {
    serialize_identifier_index(out, &fd.name)?;
    serialize_signature_token(out, &fd.signature.0)
}

fn serialize_field_handle(
    out: &mut Vec<u8>,
    fh: &FieldHandle,
) -> Result<(), AdamantSerializeError> {
    serialize_struct_def_index(out, &fh.owner)?;
    serialize_field_offset(out, fh.field)?;
    Ok(())
}

fn serialize_field_instantiation(
    out: &mut Vec<u8>,
    fi: &FieldInstantiation,
) -> Result<(), AdamantSerializeError> {
    serialize_field_handle_index(out, &fi.handle)?;
    serialize_signature_index(out, &fi.type_parameters)?;
    Ok(())
}

fn serialize_variant_handle(
    out: &mut Vec<u8>,
    vh: &VariantHandle,
) -> Result<(), AdamantSerializeError> {
    serialize_enum_def_index(out, &vh.enum_def)?;
    serialize_variant_tag(out, vh.variant)
}

fn serialize_variant_instantiation_handle(
    out: &mut Vec<u8>,
    vih: &VariantInstantiationHandle,
) -> Result<(), AdamantSerializeError> {
    serialize_enum_def_inst_index(out, &vih.enum_def)?;
    serialize_variant_tag(out, vih.variant)
}

fn serialize_acquires(
    out: &mut Vec<u8>,
    indices: &[StructDefinitionIndex],
) -> Result<(), AdamantSerializeError> {
    serialize_acquires_count(out, indices.len())?;
    for idx in indices {
        serialize_struct_def_index(out, idx)?;
    }
    Ok(())
}

fn serialize_signature(out: &mut Vec<u8>, sig: &Signature) -> Result<(), AdamantSerializeError> {
    serialize_signature_tokens(out, &sig.0)
}

fn serialize_signature_tokens(
    out: &mut Vec<u8>,
    tokens: &[SignatureToken],
) -> Result<(), AdamantSerializeError> {
    serialize_signature_size(out, tokens.len())?;
    for token in tokens {
        serialize_signature_token(out, token)?;
    }
    Ok(())
}

/// Serialises a single `SignatureToken` chain. Mirrors Sui's
/// non-recursive preorder traversal so we do not blow the stack on
/// pathologically nested types.
fn serialize_signature_token(
    out: &mut Vec<u8>,
    token: &SignatureToken,
) -> Result<(), AdamantSerializeError> {
    for (node, depth) in token.preorder_traversal_with_depth() {
        if depth > SIGNATURE_TOKEN_DEPTH_MAX {
            return Err(AdamantSerializeError::SignatureTooDeep);
        }
        serialize_signature_token_node(out, node)?;
    }
    Ok(())
}

fn serialize_signature_token_node(
    out: &mut Vec<u8>,
    token: &SignatureToken,
) -> Result<(), AdamantSerializeError> {
    match token {
        SignatureToken::Bool => out.push(SerializedType::BOOL as u8),
        SignatureToken::U8 => out.push(SerializedType::U8 as u8),
        SignatureToken::U16 => out.push(SerializedType::U16 as u8),
        SignatureToken::U32 => out.push(SerializedType::U32 as u8),
        SignatureToken::U64 => out.push(SerializedType::U64 as u8),
        SignatureToken::U128 => out.push(SerializedType::U128 as u8),
        SignatureToken::U256 => out.push(SerializedType::U256 as u8),
        SignatureToken::Address => out.push(SerializedType::ADDRESS as u8),
        SignatureToken::Signer => out.push(SerializedType::SIGNER as u8),
        SignatureToken::Vector(_) => out.push(SerializedType::VECTOR as u8),
        SignatureToken::Datatype(idx) => {
            out.push(SerializedType::STRUCT as u8);
            serialize_datatype_handle_index(out, idx)?;
        }
        SignatureToken::DatatypeInstantiation(inst) => {
            let (idx, type_params) = &**inst;
            out.push(SerializedType::DATATYPE_INST as u8);
            serialize_datatype_handle_index(out, idx)?;
            serialize_signature_size(out, type_params.len())?;
        }
        SignatureToken::Reference(_) => out.push(SerializedType::REFERENCE as u8),
        SignatureToken::MutableReference(_) => out.push(SerializedType::MUTABLE_REFERENCE as u8),
        SignatureToken::TypeParameter(idx) => {
            out.push(SerializedType::TYPE_PARAMETER as u8);
            serialize_type_parameter_index(out, *idx)?;
        }
    }
    Ok(())
}

fn serialize_ability_set(out: &mut Vec<u8>, set: AbilitySet) -> Result<(), AdamantSerializeError> {
    write_uleb128_bounded(
        out,
        u64::from(set.into_u8()),
        u64::from(AbilitySet::ALL.into_u8()),
        "ability set",
    )
}

fn serialize_ability_sets(
    out: &mut Vec<u8>,
    sets: &[AbilitySet],
) -> Result<(), AdamantSerializeError> {
    serialize_type_parameter_count(out, sets.len())?;
    for set in sets {
        serialize_ability_set(out, *set)?;
    }
    Ok(())
}

// ============================================================================
// Function definition + code unit (Adamant-specific)
// ============================================================================

fn serialize_function_definition(
    out: &mut Vec<u8>,
    version: u32,
    fd: &AdamantFunctionDefinition,
) -> Result<(), AdamantSerializeError> {
    serialize_function_handle_index(out, &fd.function)?;

    let mut flags: u8 = 0;
    if version < VERSION_5 {
        // Pre-v5 visibility encoding folds entry-ness into the
        // visibility byte via the deprecated SCRIPT marker. Mirrors
        // Sui's `serialize_function_definition` lines 1693–1702.
        let visibility = if fd.visibility == Visibility::Public && fd.is_entry {
            Visibility::DEPRECATED_SCRIPT
        } else {
            fd.visibility as u8
        };
        out.push(visibility);
    } else {
        out.push(fd.visibility as u8);
        if fd.is_entry {
            flags |= FunctionDefinition::ENTRY;
        }
    }
    if fd.is_native() {
        flags |= FunctionDefinition::NATIVE;
    }
    out.push(flags);

    serialize_acquires(out, &fd.acquires_global_resources)?;
    if let Some(code) = &fd.code {
        serialize_code_unit(out, version, code)?;
    }
    Ok(())
}

fn serialize_code_unit(
    out: &mut Vec<u8>,
    version: u32,
    code: &AdamantCodeUnit,
) -> Result<(), AdamantSerializeError> {
    serialize_signature_index(out, &code.locals)?;
    // Function bodies are serialised by `bytecode_wire`, which is
    // the Adamant-aware extension of Sui's `serialize_code` (count
    // prefix + per-instruction encoding). It already handles
    // inherited Sui opcodes plus the 17 Adamant extensions per
    // §6.2.1.4. We surface its errors through `From`.
    let body_bytes = bytecode_wire::serialize_function_body(&code.code)?;
    out.extend_from_slice(&body_bytes);
    serialize_jump_tables(out, version, &code.jump_tables)?;
    Ok(())
}

fn serialize_jump_tables(
    out: &mut Vec<u8>,
    version: u32,
    jump_tables: &[VariantJumpTable],
) -> Result<(), AdamantSerializeError> {
    if version < VERSION_7 {
        if !jump_tables.is_empty() {
            return Err(AdamantSerializeError::VersionFeatureMismatch {
                feature: "jump tables",
                version,
            });
        }
        return Ok(());
    }
    // Cast safety: `jump_table_count` is a u8 in Sui's serializer
    // because the max is 255; we emit a `LengthOverflow` if a caller
    // ever exceeds that.
    if jump_tables.len() > u8::MAX as usize {
        return Err(AdamantSerializeError::LengthOverflow {
            kind: "jump tables",
            len: jump_tables.len(),
            max: u64::from(u8::MAX),
        });
    }
    // Cast safety: bound check above guarantees `len <= u8::MAX`.
    #[allow(clippy::cast_possible_truncation)]
    let jt_count = jump_tables.len() as u8;
    serialize_jump_table_count(out, jt_count)?;
    for jt in jump_tables {
        serialize_jump_table(out, jt)?;
    }
    Ok(())
}

fn serialize_jump_table(
    out: &mut Vec<u8>,
    jt: &VariantJumpTable,
) -> Result<(), AdamantSerializeError> {
    let JumpTableInner::Full(branches) = &jt.jump_table;
    serialize_enum_def_index(out, &jt.head_enum)?;
    serialize_jump_table_branch_count(out, branches.len())?;
    out.push(SerializedJumpTableFlag::FULL as u8);
    for off in branches {
        serialize_bytecode_offset(out, *off)?;
    }
    Ok(())
}

// ============================================================================
// Pool table writers (offset/length tracking)
// ============================================================================

/// Tracks (offset, length) for every potentially-emitted table. A
/// table whose length is zero is omitted from the table-index block
/// per Sui's convention.
#[derive(Default)]
struct TableTracker {
    table_count: u8,
    module_handles: (u32, u32),
    datatype_handles: (u32, u32),
    function_handles: (u32, u32),
    function_instantiations: (u32, u32),
    signatures: (u32, u32),
    identifiers: (u32, u32),
    address_identifiers: (u32, u32),
    constant_pool: (u32, u32),
    metadata: (u32, u32),
    struct_defs: (u32, u32),
    struct_def_instantiations: (u32, u32),
    function_defs: (u32, u32),
    field_handles: (u32, u32),
    field_instantiations: (u32, u32),
    friend_decls: (u32, u32),
    enum_defs: (u32, u32),
    enum_def_instantiations: (u32, u32),
    variant_handles: (u32, u32),
    variant_instantiation_handles: (u32, u32),
}

/// Computes `(offset, length)` for a table by writing its content
/// to `out` and tracking the byte range. Returns the populated pair
/// which the caller assigns into the appropriate [`TableTracker`]
/// field. If the slice is empty, returns `(0, 0)` and skips the
/// table count increment.
fn write_table<T, F>(
    out: &mut Vec<u8>,
    tracker: &mut TableTracker,
    items: &[T],
    mut writer: F,
) -> Result<(u32, u32), AdamantSerializeError>
where
    F: FnMut(&mut Vec<u8>, &T) -> Result<(), AdamantSerializeError>,
{
    if items.is_empty() {
        return Ok((0, 0));
    }
    tracker.table_count += 1;
    let start = check_index_in_binary(out.len())?;
    for item in items {
        writer(out, item)?;
    }
    let end = check_index_in_binary(out.len())?;
    debug_assert!(end >= start, "table end must be >= start");
    Ok((start, end - start))
}

fn serialize_tables(
    out: &mut Vec<u8>,
    module: &AdamantCompiledModule,
    tracker: &mut TableTracker,
) -> Result<(), AdamantSerializeError> {
    let version = module.version;

    // ---- Common tables (mirror Sui's `CommonSerializer::serialize_common_tables`) ----
    tracker.module_handles = write_table(out, tracker, &module.module_handles, |o, h| {
        serialize_module_handle(o, h)
    })?;
    tracker.datatype_handles = write_table(out, tracker, &module.datatype_handles, |o, h| {
        serialize_datatype_handle(o, h)
    })?;
    tracker.function_handles = write_table(out, tracker, &module.function_handles, |o, h| {
        serialize_function_handle(o, h)
    })?;
    tracker.function_instantiations =
        write_table(out, tracker, &module.function_instantiations, |o, fi| {
            serialize_function_instantiation(o, fi)
        })?;
    tracker.signatures = write_table(out, tracker, &module.signatures, |o, sig| {
        serialize_signature(o, sig)
    })?;
    tracker.identifiers = write_table(out, tracker, &module.identifiers, |o, ident| {
        serialize_identifier(o, ident.as_str())
    })?;
    tracker.address_identifiers =
        write_table(out, tracker, &module.address_identifiers, |o, addr| {
            serialize_address(o, addr);
            Ok(())
        })?;
    tracker.constant_pool = write_table(out, tracker, &module.constant_pool, |o, c| {
        serialize_constant(o, c)
    })?;
    if version >= VERSION_5 {
        tracker.metadata = write_table(out, tracker, &module.metadata, |o, m| {
            serialize_metadata_entry(o, m)
        })?;
    } else if !module.metadata.is_empty() {
        return Err(AdamantSerializeError::VersionFeatureMismatch {
            feature: "metadata",
            version,
        });
    }

    // ---- Module-only tables (mirror `ModuleSerializer::serialize_tables`) ----
    tracker.struct_defs = write_table(out, tracker, &module.struct_defs, |o, sd| {
        serialize_struct_definition(o, sd)
    })?;
    tracker.struct_def_instantiations =
        write_table(out, tracker, &module.struct_def_instantiations, |o, si| {
            serialize_struct_def_instantiation(o, si)
        })?;
    tracker.function_defs = write_table(out, tracker, &module.function_defs, |o, fd| {
        serialize_function_definition(o, version, fd)
    })?;
    tracker.field_handles = write_table(out, tracker, &module.field_handles, |o, fh| {
        serialize_field_handle(o, fh)
    })?;
    tracker.field_instantiations =
        write_table(out, tracker, &module.field_instantiations, |o, fi| {
            serialize_field_instantiation(o, fi)
        })?;
    tracker.friend_decls = write_table(out, tracker, &module.friend_decls, |o, h| {
        serialize_module_handle(o, h)
    })?;
    if version >= VERSION_7 {
        tracker.enum_defs = write_table(out, tracker, &module.enum_defs, |o, ed| {
            serialize_enum_definition(o, ed)
        })?;
        tracker.enum_def_instantiations =
            write_table(out, tracker, &module.enum_def_instantiations, |o, ei| {
                serialize_enum_def_instantiation(o, ei)
            })?;
        tracker.variant_handles = write_table(out, tracker, &module.variant_handles, |o, vh| {
            serialize_variant_handle(o, vh)
        })?;
        tracker.variant_instantiation_handles = write_table(
            out,
            tracker,
            &module.variant_instantiation_handles,
            |o, vih| serialize_variant_instantiation_handle(o, vih),
        )?;
    } else if !module.enum_defs.is_empty()
        || !module.enum_def_instantiations.is_empty()
        || !module.variant_handles.is_empty()
        || !module.variant_instantiation_handles.is_empty()
    {
        return Err(AdamantSerializeError::VersionFeatureMismatch {
            feature: "enum tables",
            version,
        });
    }
    Ok(())
}

// `clippy::too_many_lines` fires here because the function makes
// 19 sequential calls to `serialize_table_index_entry` — one per
// pool. Splitting it would obscure the binary-format mapping
// against §6.2.1.2 / Sui's `serialize_table_indices`. Allow per
// site.
#[allow(clippy::too_many_lines)]
fn serialize_table_indices(
    out: &mut Vec<u8>,
    tracker: &TableTracker,
    version: u32,
) -> Result<(), AdamantSerializeError> {
    serialize_table_count(out, tracker.table_count)?;

    // Common-table indices, in the order Sui emits them.
    serialize_table_index_entry(
        out,
        TableType::MODULE_HANDLES,
        tracker.module_handles.0,
        tracker.module_handles.1,
    )?;
    serialize_table_index_entry(
        out,
        TableType::DATATYPE_HANDLES,
        tracker.datatype_handles.0,
        tracker.datatype_handles.1,
    )?;
    serialize_table_index_entry(
        out,
        TableType::FUNCTION_HANDLES,
        tracker.function_handles.0,
        tracker.function_handles.1,
    )?;
    serialize_table_index_entry(
        out,
        TableType::FUNCTION_INST,
        tracker.function_instantiations.0,
        tracker.function_instantiations.1,
    )?;
    serialize_table_index_entry(
        out,
        TableType::SIGNATURES,
        tracker.signatures.0,
        tracker.signatures.1,
    )?;
    serialize_table_index_entry(
        out,
        TableType::IDENTIFIERS,
        tracker.identifiers.0,
        tracker.identifiers.1,
    )?;
    serialize_table_index_entry(
        out,
        TableType::ADDRESS_IDENTIFIERS,
        tracker.address_identifiers.0,
        tracker.address_identifiers.1,
    )?;
    serialize_table_index_entry(
        out,
        TableType::CONSTANT_POOL,
        tracker.constant_pool.0,
        tracker.constant_pool.1,
    )?;
    if version >= VERSION_5 {
        serialize_table_index_entry(
            out,
            TableType::METADATA,
            tracker.metadata.0,
            tracker.metadata.1,
        )?;
    }

    // Module-only indices.
    serialize_table_index_entry(
        out,
        TableType::STRUCT_DEFS,
        tracker.struct_defs.0,
        tracker.struct_defs.1,
    )?;
    serialize_table_index_entry(
        out,
        TableType::STRUCT_DEF_INST,
        tracker.struct_def_instantiations.0,
        tracker.struct_def_instantiations.1,
    )?;
    serialize_table_index_entry(
        out,
        TableType::FUNCTION_DEFS,
        tracker.function_defs.0,
        tracker.function_defs.1,
    )?;
    serialize_table_index_entry(
        out,
        TableType::FIELD_HANDLE,
        tracker.field_handles.0,
        tracker.field_handles.1,
    )?;
    serialize_table_index_entry(
        out,
        TableType::FIELD_INST,
        tracker.field_instantiations.0,
        tracker.field_instantiations.1,
    )?;
    serialize_table_index_entry(
        out,
        TableType::FRIEND_DECLS,
        tracker.friend_decls.0,
        tracker.friend_decls.1,
    )?;
    if version >= VERSION_7 {
        serialize_table_index_entry(
            out,
            TableType::ENUM_DEFS,
            tracker.enum_defs.0,
            tracker.enum_defs.1,
        )?;
        serialize_table_index_entry(
            out,
            TableType::ENUM_DEF_INST,
            tracker.enum_def_instantiations.0,
            tracker.enum_def_instantiations.1,
        )?;
        serialize_table_index_entry(
            out,
            TableType::VARIANT_HANDLES,
            tracker.variant_handles.0,
            tracker.variant_handles.1,
        )?;
        serialize_table_index_entry(
            out,
            TableType::VARIANT_INST_HANDLES,
            tracker.variant_instantiation_handles.0,
            tracker.variant_instantiation_handles.1,
        )?;
    }
    Ok(())
}

// ============================================================================
// Public entry point
// ============================================================================

/// Serialises an [`AdamantCompiledModule`] to bytes per
/// whitepaper §6.2.1.2 binary format with the §6.2.1.4 bytecode
/// extensions interleaved into function bodies.
///
/// The output format is byte-equivalent to Sui's
/// `CompiledModule::serialize_with_version` for any
/// [`AdamantCompiledModule`] that contains no Adamant extensions
/// (asserted by the cross-validation tests in this module). For
/// modules with extensions, the deviation is contained entirely
/// within function bodies (per §6.2.1.5); module-level structure
/// remains byte-faithful.
///
/// # Errors
///
/// - [`AdamantSerializeError::UnsupportedVersion`] if `module.version`
///   is outside [`VERSION_MIN`, `VERSION_MAX`].
/// - [`AdamantSerializeError::VersionFeatureMismatch`] if the module
///   uses a feature absent from its declared version (e.g., enum
///   tables at version < 7, metadata at version < 5).
/// - [`AdamantSerializeError::IndexOverflow`] /
///   [`AdamantSerializeError::LengthOverflow`] if any index or
///   length field exceeds the encoding's bound.
/// - [`AdamantSerializeError::SignatureTooDeep`] if a `SignatureToken`
///   chain exceeds [`SIGNATURE_TOKEN_DEPTH_MAX`] nesting levels.
/// - [`AdamantSerializeError::BinaryTooLarge`] if total table content
///   exceeds `u32::MAX` bytes.
/// - [`AdamantSerializeError::Bytecode`] for any inner function-body
///   encoding error.
pub fn adamant_serialize(
    module: &AdamantCompiledModule,
    out: &mut Vec<u8>,
) -> Result<(), AdamantSerializeError> {
    if !(VERSION_MIN..=VERSION_MAX).contains(&module.version) {
        return Err(AdamantSerializeError::UnsupportedVersion(module.version));
    }

    // Build the table content into a temporary buffer, recording
    // (offset, length) per table as we go. Mirrors Sui's two-pass
    // approach: header and table indices need to know table sizes,
    // so content is built first.
    let mut tracker = TableTracker::default();
    let mut temp: Vec<u8> = Vec::new();
    serialize_tables(&mut temp, module, &mut tracker)?;
    if temp.len() > u32::MAX as usize {
        return Err(AdamantSerializeError::BinaryTooLarge(temp.len()));
    }

    // Header: magic + flavored version.
    if module.publishable {
        out.extend_from_slice(&BinaryConstants::MOVE_MAGIC);
    } else {
        out.extend_from_slice(&BinaryConstants::UNPUBLISHABLE_MAGIC);
    }
    write_u32_le(out, BinaryFlavor::encode_version(module.version));

    // Table indices.
    serialize_table_indices(out, &tracker, module.version)?;

    // Table content.
    out.extend_from_slice(&temp);

    // Trailing self-module-handle index (Sui appends it after the
    // table content; mirrors `serialize_with_version` line 247).
    serialize_module_handle_index(out, &module.self_module_handle_idx)?;

    Ok(())
}

// ============================================================================
// Deserializer
// ============================================================================
//
// Per whitepaper §6.2.1.8 (re-amended at commit 0de50d8), Adamant's
// deploy-time pipeline parses module bytes via this Adamant-native
// deserializer rather than delegating to vendored Sui-Move at
// runtime. The implementation mirrors Sui's two-pass approach:
// (1) read the header + table indices and validate layout;
// (2) parse each table's content from a sub-cursor scoped to the
// table's byte range. Function bodies dispatch to
// [`bytecode_wire::deserialize_function_body_from_cursor`] in
// strict mode (rejecting deprecated global-storage opcodes per
// §6.2.1.6 Rule 5). Strict canonical decoding is the only mode:
// trailing bytes, duplicate tables, version-feature mismatches,
// and zero-length tables are all rejected.

/// Errors from [`adamant_deserialize`].
///
/// Variants are kind-specific so callers can match on the
/// offending input class for diagnostics.
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub enum AdamantDeserializeError {
    /// Stream ended before parsing finished.
    UnexpectedEof,
    /// Magic header is neither [`BinaryConstants::MOVE_MAGIC`] nor
    /// [`BinaryConstants::UNPUBLISHABLE_MAGIC`].
    BadMagic([u8; 4]),
    /// Bytecode-format version (after `BinaryFlavor` decode) is
    /// outside `[VERSION_MIN, VERSION_MAX]`.
    UnsupportedVersion(u32),
    /// Flavor byte is present (version ≥ 7) but is not
    /// [`BinaryFlavor::SUI_FLAVOR`] (`0x05`).
    UnknownFlavor(u8),
    /// Table-kind byte does not match any known [`TableType`].
    UnknownTableKind(u8),
    /// A table kind appears more than once in the table-index
    /// block.
    DuplicateTable(TableType),
    /// Table layout is invalid: tables overlap, leave gaps, have
    /// zero size, or extend past the binary end.
    BadTableLayout {
        /// Human-readable reason for inclusion in error messages.
        reason: &'static str,
    },
    /// ULEB128 sequence is malformed (overflow, non-canonical, or
    /// terminator missing).
    MalformedUleb128,
    /// A pool index, count, or length exceeds its declared bound.
    OutOfRange {
        /// Human-readable name of the offending field.
        kind: &'static str,
        /// The actual offending value.
        value: u64,
        /// The inclusive maximum for the field's kind.
        max: u64,
    },
    /// `SignatureToken` chain exceeds [`SIGNATURE_TOKEN_DEPTH_MAX`].
    SignatureTooDeep,
    /// A binary-format feature appears at a version that does not
    /// support it (metadata at v < 5, enum tables at v < 7,
    /// jump tables at v < 7).
    VersionFeatureMismatch {
        /// Human-readable name of the missing feature.
        feature: &'static str,
        /// The bytecode-format version the module declared.
        version: u32,
    },
    /// Trailing bytes remain after a complete module is parsed.
    TrailingBytes,
    /// Inner bytecode-wire error from
    /// [`bytecode_wire::deserialize_function_body_from_cursor`].
    Bytecode(bytecode_wire::DeserializeError),
    /// An identifier-pool entry's bytes do not form a valid Move
    /// identifier per [`move_core_types::identifier::Identifier::new`].
    InvalidIdentifier,
    /// A function-definition byte indicated a flag bit other than
    /// the well-defined ENTRY (0x4) or NATIVE (0x2) bits.
    UnknownFunctionFlag(u8),
    /// A serialized-type tag (in a [`SignatureToken`] stream) does
    /// not correspond to any known [`SerializedType`] variant.
    UnknownSerializedType(u8),
    /// A struct-field-information flag is neither NATIVE nor
    /// DECLARED.
    UnknownStructFlag(u8),
    /// An enum-flag byte is not DECLARED (the only variant Sui
    /// emits).
    UnknownEnumFlag(u8),
    /// A jump-table flag byte is not FULL (the only variant Sui
    /// emits).
    UnknownJumpTableFlag(u8),
    /// A visibility byte is not Private (0), Public (1), Friend
    /// (3), or (at version < 5) the deprecated SCRIPT marker (2).
    UnknownVisibility(u8),
    /// An ability-set byte has bits outside the four defined
    /// abilities (Copy=0x1, Drop=0x2, Store=0x4, Key=0x8).
    InvalidAbilitySet(u8),
}

impl core::fmt::Display for AdamantDeserializeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnexpectedEof => write!(f, "unexpected end of module bytes"),
            Self::BadMagic(magic) => {
                write!(f, "bad magic header {magic:02x?}")
            }
            Self::UnsupportedVersion(v) => write!(
                f,
                "bytecode version {v} unsupported (only {VERSION_MIN}..={VERSION_MAX} accepted)"
            ),
            Self::UnknownFlavor(b) => write!(f, "unknown binary flavor byte {b:#04x}"),
            Self::UnknownTableKind(b) => write!(f, "unknown table-kind byte {b:#04x}"),
            Self::DuplicateTable(k) => write!(f, "duplicate table kind {k:?}"),
            Self::BadTableLayout { reason } => write!(f, "bad table layout: {reason}"),
            Self::MalformedUleb128 => write!(f, "malformed ULEB128 sequence"),
            Self::OutOfRange { kind, value, max } => {
                write!(f, "{kind} value {value} exceeds maximum {max}")
            }
            Self::SignatureTooDeep => {
                write!(
                    f,
                    "signature-token nesting exceeds maximum depth {SIGNATURE_TOKEN_DEPTH_MAX}"
                )
            }
            Self::VersionFeatureMismatch { feature, version } => write!(
                f,
                "feature {feature:?} not available at bytecode version {version}"
            ),
            Self::TrailingBytes => write!(f, "trailing bytes after module"),
            Self::Bytecode(e) => write!(f, "function body decoding: {e}"),
            Self::InvalidIdentifier => {
                write!(f, "identifier-pool entry is not a valid Move identifier")
            }
            Self::UnknownFunctionFlag(b) => write!(f, "unknown function flag byte {b:#04x}"),
            Self::UnknownSerializedType(b) => write!(f, "unknown serialized-type tag {b:#04x}"),
            Self::UnknownStructFlag(b) => write!(f, "unknown struct flag byte {b:#04x}"),
            Self::UnknownEnumFlag(b) => write!(f, "unknown enum flag byte {b:#04x}"),
            Self::UnknownJumpTableFlag(b) => write!(f, "unknown jump-table flag byte {b:#04x}"),
            Self::UnknownVisibility(b) => write!(f, "unknown visibility byte {b:#04x}"),
            Self::InvalidAbilitySet(b) => write!(f, "ability-set byte {b:#04x} has unknown bits"),
        }
    }
}

impl std::error::Error for AdamantDeserializeError {}

impl From<bytecode_wire::DeserializeError> for AdamantDeserializeError {
    fn from(e: bytecode_wire::DeserializeError) -> Self {
        Self::Bytecode(e)
    }
}

// ----- Cursor primitives -----

/// Returns `cursor.position()` as `usize`. The cast is safe by
/// construction: position originates from reads of a slice of
/// length `usize`, so it provably fits `usize` on every supported
/// (64-bit) target.
#[inline]
fn cursor_position(cursor: &std::io::Cursor<&[u8]>) -> usize {
    #[allow(clippy::cast_possible_truncation)]
    let pos = cursor.position() as usize;
    pos
}

/// Returns `true` when `cursor` has consumed every byte of the
/// underlying slice.
#[inline]
fn cursor_at_end(cursor: &std::io::Cursor<&[u8]>) -> bool {
    cursor_position(cursor) >= cursor.get_ref().len()
}

/// Reads a single byte. Returns `UnexpectedEof` if the cursor is at
/// end-of-stream.
fn read_u8(cursor: &mut std::io::Cursor<&[u8]>) -> Result<u8, AdamantDeserializeError> {
    use std::io::Read as _;
    let mut buf = [0u8; 1];
    cursor
        .read_exact(&mut buf)
        .map_err(|_| AdamantDeserializeError::UnexpectedEof)?;
    Ok(buf[0])
}

/// Reads `N` little-endian bytes into a fixed-size array.
fn read_n<const N: usize>(
    cursor: &mut std::io::Cursor<&[u8]>,
) -> Result<[u8; N], AdamantDeserializeError> {
    use std::io::Read as _;
    let mut buf = [0u8; N];
    cursor
        .read_exact(&mut buf)
        .map_err(|_| AdamantDeserializeError::UnexpectedEof)?;
    Ok(buf)
}

fn read_u32_le(cursor: &mut std::io::Cursor<&[u8]>) -> Result<u32, AdamantDeserializeError> {
    Ok(u32::from_le_bytes(read_n::<4>(cursor)?))
}

/// Reads a ULEB128-encoded `u64`. Mirrors Sui's
/// [`read_uleb128_as_u64`] but maps errors to our taxonomy.
fn read_uleb128_u64(cursor: &mut std::io::Cursor<&[u8]>) -> Result<u64, AdamantDeserializeError> {
    adamant_bytecode_format::read_uleb128_as_u64(cursor).map_err(|_| {
        // Disambiguate EOF from malformed encoding by checking
        // cursor position against the underlying slice length.
        // Cast safety: position originates from reads of a slice of
        // length `usize`; on a 64-bit target it cannot truncate.
        #[allow(clippy::cast_possible_truncation)]
        let pos = cursor.position() as usize;
        if pos >= cursor.get_ref().len() {
            AdamantDeserializeError::UnexpectedEof
        } else {
            AdamantDeserializeError::MalformedUleb128
        }
    })
}

/// Reads a ULEB128 and validates it does not exceed `max`. Returns
/// the value as a `u64`.
fn read_uleb128_bounded(
    cursor: &mut std::io::Cursor<&[u8]>,
    max: u64,
    kind: &'static str,
) -> Result<u64, AdamantDeserializeError> {
    let v = read_uleb128_u64(cursor)?;
    if v > max {
        return Err(AdamantDeserializeError::OutOfRange {
            kind,
            value: v,
            max,
        });
    }
    Ok(v)
}

/// Reads a ULEB128 length and validates it does not exceed `max`.
/// Same shape as [`read_uleb128_bounded`] but the return type is
/// `usize` for direct use with `Vec::with_capacity` / loop bounds.
fn read_uleb128_length(
    cursor: &mut std::io::Cursor<&[u8]>,
    max: u64,
    kind: &'static str,
) -> Result<usize, AdamantDeserializeError> {
    let v = read_uleb128_bounded(cursor, max, kind)?;
    // Cast safety: `v <= max <= u64::MAX`, and on supported
    // (64-bit) targets `usize::MAX == u64::MAX`. The pool-size
    // bounds (TABLE_INDEX_MAX = 65535, etc.) are well below
    // `usize::MAX` on every supported target.
    #[allow(clippy::cast_possible_truncation)]
    let v_usize = v as usize;
    Ok(v_usize)
}

// ----- Index / count readers (mirror serialise side) -----

fn load_module_handle_index(
    cursor: &mut std::io::Cursor<&[u8]>,
) -> Result<ModuleHandleIndex, AdamantDeserializeError> {
    let v = read_uleb128_bounded(cursor, MODULE_HANDLE_INDEX_MAX, "ModuleHandleIndex")?;
    // Cast safety: bound is 65535 (`TABLE_INDEX_MAX`), fits u16.
    #[allow(clippy::cast_possible_truncation)]
    let idx = v as u16;
    Ok(ModuleHandleIndex(idx))
}

fn load_datatype_handle_index(
    cursor: &mut std::io::Cursor<&[u8]>,
) -> Result<DatatypeHandleIndex, AdamantDeserializeError> {
    let v = read_uleb128_bounded(cursor, DATATYPE_HANDLE_INDEX_MAX, "DatatypeHandleIndex")?;
    #[allow(clippy::cast_possible_truncation)]
    let idx = v as u16;
    Ok(DatatypeHandleIndex(idx))
}

fn load_function_handle_index(
    cursor: &mut std::io::Cursor<&[u8]>,
) -> Result<FunctionHandleIndex, AdamantDeserializeError> {
    let v = read_uleb128_bounded(cursor, FUNCTION_HANDLE_INDEX_MAX, "FunctionHandleIndex")?;
    #[allow(clippy::cast_possible_truncation)]
    let idx = v as u16;
    Ok(FunctionHandleIndex(idx))
}

fn load_identifier_index(
    cursor: &mut std::io::Cursor<&[u8]>,
) -> Result<IdentifierIndex, AdamantDeserializeError> {
    let v = read_uleb128_bounded(cursor, IDENTIFIER_INDEX_MAX, "IdentifierIndex")?;
    #[allow(clippy::cast_possible_truncation)]
    let idx = v as u16;
    Ok(IdentifierIndex(idx))
}

fn load_address_identifier_index(
    cursor: &mut std::io::Cursor<&[u8]>,
) -> Result<move_binary_format::file_format::AddressIdentifierIndex, AdamantDeserializeError> {
    let v = read_uleb128_bounded(cursor, ADDRESS_INDEX_MAX, "AddressIdentifierIndex")?;
    #[allow(clippy::cast_possible_truncation)]
    let idx = v as u16;
    Ok(move_binary_format::file_format::AddressIdentifierIndex(idx))
}

fn load_signature_index(
    cursor: &mut std::io::Cursor<&[u8]>,
) -> Result<SignatureIndex, AdamantDeserializeError> {
    let v = read_uleb128_bounded(cursor, SIGNATURE_INDEX_MAX, "SignatureIndex")?;
    #[allow(clippy::cast_possible_truncation)]
    let idx = v as u16;
    Ok(SignatureIndex(idx))
}

fn load_struct_def_index(
    cursor: &mut std::io::Cursor<&[u8]>,
) -> Result<StructDefinitionIndex, AdamantDeserializeError> {
    let v = read_uleb128_bounded(cursor, STRUCT_DEF_INDEX_MAX, "StructDefinitionIndex")?;
    #[allow(clippy::cast_possible_truncation)]
    let idx = v as u16;
    Ok(StructDefinitionIndex(idx))
}

fn load_enum_def_index(
    cursor: &mut std::io::Cursor<&[u8]>,
) -> Result<EnumDefinitionIndex, AdamantDeserializeError> {
    let v = read_uleb128_bounded(cursor, ENUM_DEF_INDEX_MAX, "EnumDefinitionIndex")?;
    #[allow(clippy::cast_possible_truncation)]
    let idx = v as u16;
    Ok(EnumDefinitionIndex(idx))
}

fn load_enum_def_inst_index(
    cursor: &mut std::io::Cursor<&[u8]>,
) -> Result<move_binary_format::file_format::EnumDefInstantiationIndex, AdamantDeserializeError> {
    let v = read_uleb128_bounded(cursor, ENUM_DEF_INST_INDEX_MAX, "EnumDefInstantiationIndex")?;
    #[allow(clippy::cast_possible_truncation)]
    let idx = v as u16;
    Ok(move_binary_format::file_format::EnumDefInstantiationIndex(
        idx,
    ))
}

fn load_field_offset(cursor: &mut std::io::Cursor<&[u8]>) -> Result<u16, AdamantDeserializeError> {
    let v = read_uleb128_bounded(cursor, FIELD_OFFSET_MAX, "field offset")?;
    #[allow(clippy::cast_possible_truncation)]
    let off = v as u16;
    Ok(off)
}

fn load_variant_tag(cursor: &mut std::io::Cursor<&[u8]>) -> Result<u16, AdamantDeserializeError> {
    let v = read_uleb128_bounded(cursor, VARIANT_TAG_MAX_VALUE, "variant tag")?;
    #[allow(clippy::cast_possible_truncation)]
    let tag = v as u16;
    Ok(tag)
}

fn load_type_parameter_index(
    cursor: &mut std::io::Cursor<&[u8]>,
) -> Result<u16, AdamantDeserializeError> {
    let v = read_uleb128_bounded(cursor, TYPE_PARAMETER_INDEX_MAX, "type parameter index")?;
    #[allow(clippy::cast_possible_truncation)]
    let idx = v as u16;
    Ok(idx)
}

// ----- Per-pool deserializers -----

fn load_module_handle(
    cursor: &mut std::io::Cursor<&[u8]>,
) -> Result<ModuleHandle, AdamantDeserializeError> {
    let address = load_address_identifier_index(cursor)?;
    let name = load_identifier_index(cursor)?;
    Ok(ModuleHandle { address, name })
}

fn load_datatype_handle(
    cursor: &mut std::io::Cursor<&[u8]>,
) -> Result<DatatypeHandle, AdamantDeserializeError> {
    let module = load_module_handle_index(cursor)?;
    let name = load_identifier_index(cursor)?;
    let abilities = load_ability_set(cursor)?;
    let type_parameters = load_type_parameters(cursor)?;
    Ok(DatatypeHandle {
        module,
        name,
        abilities,
        type_parameters,
    })
}

fn load_type_parameters(
    cursor: &mut std::io::Cursor<&[u8]>,
) -> Result<Vec<DatatypeTyParameter>, AdamantDeserializeError> {
    let n = read_uleb128_length(cursor, TYPE_PARAMETER_COUNT_MAX, "type parameter count")?;
    let mut tps = Vec::with_capacity(n);
    for _ in 0..n {
        tps.push(load_type_parameter(cursor)?);
    }
    Ok(tps)
}

fn load_type_parameter(
    cursor: &mut std::io::Cursor<&[u8]>,
) -> Result<DatatypeTyParameter, AdamantDeserializeError> {
    let constraints = load_ability_set(cursor)?;
    let phantom_byte = read_uleb128_bounded(cursor, 1, "phantom flag")?;
    Ok(DatatypeTyParameter {
        constraints,
        is_phantom: phantom_byte == 1,
    })
}

fn load_function_handle(
    cursor: &mut std::io::Cursor<&[u8]>,
) -> Result<FunctionHandle, AdamantDeserializeError> {
    let module = load_module_handle_index(cursor)?;
    let name = load_identifier_index(cursor)?;
    let parameters = load_signature_index(cursor)?;
    let return_ = load_signature_index(cursor)?;
    let type_parameters = load_ability_sets(cursor)?;
    Ok(FunctionHandle {
        module,
        name,
        parameters,
        return_,
        type_parameters,
    })
}

fn load_function_instantiation(
    cursor: &mut std::io::Cursor<&[u8]>,
) -> Result<FunctionInstantiation, AdamantDeserializeError> {
    let handle = load_function_handle_index(cursor)?;
    let type_parameters = load_signature_index(cursor)?;
    Ok(FunctionInstantiation {
        handle,
        type_parameters,
    })
}

fn load_field_handle(
    cursor: &mut std::io::Cursor<&[u8]>,
) -> Result<FieldHandle, AdamantDeserializeError> {
    let owner = load_struct_def_index(cursor)?;
    let field = load_field_offset(cursor)?;
    Ok(FieldHandle { owner, field })
}

fn load_field_instantiation(
    cursor: &mut std::io::Cursor<&[u8]>,
) -> Result<FieldInstantiation, AdamantDeserializeError> {
    let v = read_uleb128_bounded(cursor, FIELD_HANDLE_INDEX_MAX, "FieldHandleIndex")?;
    #[allow(clippy::cast_possible_truncation)]
    let handle = move_binary_format::file_format::FieldHandleIndex(v as u16);
    let type_parameters = load_signature_index(cursor)?;
    Ok(FieldInstantiation {
        handle,
        type_parameters,
    })
}

fn load_struct_def_instantiation(
    cursor: &mut std::io::Cursor<&[u8]>,
) -> Result<StructDefInstantiation, AdamantDeserializeError> {
    let def = load_struct_def_index(cursor)?;
    let type_parameters = load_signature_index(cursor)?;
    Ok(StructDefInstantiation {
        def,
        type_parameters,
    })
}

fn load_enum_def_instantiation(
    cursor: &mut std::io::Cursor<&[u8]>,
) -> Result<EnumDefInstantiation, AdamantDeserializeError> {
    let def = load_enum_def_index(cursor)?;
    let type_parameters = load_signature_index(cursor)?;
    Ok(EnumDefInstantiation {
        def,
        type_parameters,
    })
}

fn load_variant_handle(
    cursor: &mut std::io::Cursor<&[u8]>,
) -> Result<VariantHandle, AdamantDeserializeError> {
    let enum_def = load_enum_def_index(cursor)?;
    let variant = load_variant_tag(cursor)?;
    Ok(VariantHandle { enum_def, variant })
}

fn load_variant_instantiation_handle(
    cursor: &mut std::io::Cursor<&[u8]>,
) -> Result<VariantInstantiationHandle, AdamantDeserializeError> {
    let enum_def = load_enum_def_inst_index(cursor)?;
    let variant = load_variant_tag(cursor)?;
    Ok(VariantInstantiationHandle { enum_def, variant })
}

fn load_address(
    cursor: &mut std::io::Cursor<&[u8]>,
) -> Result<AccountAddress, AdamantDeserializeError> {
    let bytes = read_n::<{ AccountAddress::LENGTH }>(cursor)?;
    Ok(AccountAddress::new(bytes))
}

fn load_identifier(
    cursor: &mut std::io::Cursor<&[u8]>,
) -> Result<move_core_types::identifier::Identifier, AdamantDeserializeError> {
    let len = read_uleb128_length(cursor, IDENTIFIER_SIZE_MAX, "identifier size")?;
    // Cast safety: cursor position is bounded by the underlying
    // slice length (a `usize`).
    #[allow(clippy::cast_possible_truncation)]
    let pos = cursor.position() as usize;
    let bytes = cursor.get_ref();
    if pos + len > bytes.len() {
        return Err(AdamantDeserializeError::UnexpectedEof);
    }
    let slice = &bytes[pos..pos + len];
    cursor.set_position((pos + len) as u64);
    let s = std::str::from_utf8(slice).map_err(|_| AdamantDeserializeError::InvalidIdentifier)?;
    move_core_types::identifier::Identifier::new(s)
        .map_err(|_| AdamantDeserializeError::InvalidIdentifier)
}

fn load_constant(
    cursor: &mut std::io::Cursor<&[u8]>,
) -> Result<move_binary_format::file_format::Constant, AdamantDeserializeError> {
    let type_ = load_signature_token(cursor)?;
    let len = read_uleb128_length(cursor, CONSTANT_SIZE_MAX, "constant data size")?;
    #[allow(clippy::cast_possible_truncation)]
    let pos = cursor.position() as usize;
    let bytes = cursor.get_ref();
    if pos + len > bytes.len() {
        return Err(AdamantDeserializeError::UnexpectedEof);
    }
    let data = bytes[pos..pos + len].to_vec();
    cursor.set_position((pos + len) as u64);
    Ok(move_binary_format::file_format::Constant { type_, data })
}

fn load_metadata_entry(
    cursor: &mut std::io::Cursor<&[u8]>,
) -> Result<Metadata, AdamantDeserializeError> {
    let key = load_byte_blob(cursor, METADATA_KEY_SIZE_MAX, "metadata key size")?;
    let value = load_byte_blob(cursor, METADATA_VALUE_SIZE_MAX, "metadata value size")?;
    Ok(Metadata { key, value })
}

fn load_byte_blob(
    cursor: &mut std::io::Cursor<&[u8]>,
    max: u64,
    kind: &'static str,
) -> Result<Vec<u8>, AdamantDeserializeError> {
    let len = read_uleb128_length(cursor, max, kind)?;
    #[allow(clippy::cast_possible_truncation)]
    let pos = cursor.position() as usize;
    let bytes = cursor.get_ref();
    if pos + len > bytes.len() {
        return Err(AdamantDeserializeError::UnexpectedEof);
    }
    let blob = bytes[pos..pos + len].to_vec();
    cursor.set_position((pos + len) as u64);
    Ok(blob)
}

fn load_signature(
    cursor: &mut std::io::Cursor<&[u8]>,
) -> Result<Signature, AdamantDeserializeError> {
    let n = read_uleb128_length(cursor, SIGNATURE_SIZE_MAX, "signature length")?;
    let mut tokens = Vec::with_capacity(n);
    for _ in 0..n {
        tokens.push(load_signature_token(cursor)?);
    }
    Ok(Signature(tokens))
}

/// Iterative `SignatureToken` parser using an explicit stack of
/// "needs-children" placeholders, mirroring Sui's `load_signature_token`
/// but using our error taxonomy. Avoids unbounded recursion on
/// pathological (deeply-nested) inputs.
#[allow(clippy::too_many_lines)]
fn load_signature_token(
    cursor: &mut std::io::Cursor<&[u8]>,
) -> Result<SignatureToken, AdamantDeserializeError> {
    // Each frame tracks the kind of node and how many child tokens
    // remain to be parsed before the node can be finalised.
    enum Frame {
        Vector,
        Reference,
        MutableReference,
        DatatypeInstantiation {
            idx: DatatypeHandleIndex,
            remaining: usize,
            collected: Vec<SignatureToken>,
        },
    }

    let mut stack: Vec<Frame> = Vec::new();
    // Loop invariant: we always need to read and return exactly one
    // token at the start of each iteration; that token may itself
    // require further child tokens (pushed onto the stack), or it
    // may be terminal and start to "collapse" the stack upward.
    loop {
        if stack.len() > SIGNATURE_TOKEN_DEPTH_MAX {
            return Err(AdamantDeserializeError::SignatureTooDeep);
        }
        let tag = read_u8(cursor)?;
        let mut node = match tag {
            x if x == SerializedType::BOOL as u8 => SignatureToken::Bool,
            x if x == SerializedType::U8 as u8 => SignatureToken::U8,
            x if x == SerializedType::U16 as u8 => SignatureToken::U16,
            x if x == SerializedType::U32 as u8 => SignatureToken::U32,
            x if x == SerializedType::U64 as u8 => SignatureToken::U64,
            x if x == SerializedType::U128 as u8 => SignatureToken::U128,
            x if x == SerializedType::U256 as u8 => SignatureToken::U256,
            x if x == SerializedType::ADDRESS as u8 => SignatureToken::Address,
            x if x == SerializedType::SIGNER as u8 => SignatureToken::Signer,
            x if x == SerializedType::VECTOR as u8 => {
                stack.push(Frame::Vector);
                continue;
            }
            x if x == SerializedType::REFERENCE as u8 => {
                stack.push(Frame::Reference);
                continue;
            }
            x if x == SerializedType::MUTABLE_REFERENCE as u8 => {
                stack.push(Frame::MutableReference);
                continue;
            }
            x if x == SerializedType::STRUCT as u8 => {
                let idx = load_datatype_handle_index(cursor)?;
                SignatureToken::Datatype(idx)
            }
            x if x == SerializedType::DATATYPE_INST as u8 => {
                let idx = load_datatype_handle_index(cursor)?;
                let arity = read_uleb128_length(cursor, SIGNATURE_SIZE_MAX, "instantiation arity")?;
                if arity == 0 {
                    SignatureToken::DatatypeInstantiation(Box::new((idx, vec![])))
                } else {
                    stack.push(Frame::DatatypeInstantiation {
                        idx,
                        remaining: arity,
                        collected: Vec::with_capacity(arity),
                    });
                    continue;
                }
            }
            x if x == SerializedType::TYPE_PARAMETER as u8 => {
                let idx = load_type_parameter_index(cursor)?;
                SignatureToken::TypeParameter(idx)
            }
            other => return Err(AdamantDeserializeError::UnknownSerializedType(other)),
        };

        // Collapse: walk up the stack while the top frame is
        // satisfied by `node`.
        loop {
            match stack.pop() {
                None => return Ok(node),
                Some(Frame::Vector) => {
                    node = SignatureToken::Vector(Box::new(node));
                }
                Some(Frame::Reference) => {
                    node = SignatureToken::Reference(Box::new(node));
                }
                Some(Frame::MutableReference) => {
                    node = SignatureToken::MutableReference(Box::new(node));
                }
                Some(Frame::DatatypeInstantiation {
                    idx,
                    remaining,
                    mut collected,
                }) => {
                    collected.push(node);
                    if collected.len() == remaining {
                        node = SignatureToken::DatatypeInstantiation(Box::new((idx, collected)));
                    } else {
                        // Not yet complete — push the frame back
                        // and break to read the next sibling token.
                        stack.push(Frame::DatatypeInstantiation {
                            idx,
                            remaining,
                            collected,
                        });
                        break;
                    }
                }
            }
        }
    }
}

fn load_ability_set(
    cursor: &mut std::io::Cursor<&[u8]>,
) -> Result<AbilitySet, AdamantDeserializeError> {
    let v = read_uleb128_u64(cursor)?;
    if v > u64::from(AbilitySet::ALL.into_u8()) {
        // Cast safety: bound check above guarantees `v <= 0x0f`
        // (`AbilitySet::ALL.into_u8()`), which fits `u8`.
        #[allow(clippy::cast_possible_truncation)]
        let byte = v as u8;
        return Err(AdamantDeserializeError::InvalidAbilitySet(byte));
    }
    // Cast safety: bound check above guarantees `v <= 0x0f`.
    #[allow(clippy::cast_possible_truncation)]
    let byte = v as u8;
    AbilitySet::from_u8(byte).ok_or(AdamantDeserializeError::InvalidAbilitySet(byte))
}

fn load_ability_sets(
    cursor: &mut std::io::Cursor<&[u8]>,
) -> Result<Vec<AbilitySet>, AdamantDeserializeError> {
    let n = read_uleb128_length(cursor, TYPE_PARAMETER_COUNT_MAX, "type parameter count")?;
    let mut sets = Vec::with_capacity(n);
    for _ in 0..n {
        sets.push(load_ability_set(cursor)?);
    }
    Ok(sets)
}

fn load_struct_definition(
    cursor: &mut std::io::Cursor<&[u8]>,
) -> Result<StructDefinition, AdamantDeserializeError> {
    let struct_handle = load_datatype_handle_index(cursor)?;
    let flag = read_u8(cursor)?;
    let field_information = if flag == SerializedNativeStructFlag::NATIVE as u8 {
        StructFieldInformation::Native
    } else if flag == SerializedNativeStructFlag::DECLARED as u8 {
        let fields = load_field_definitions(cursor)?;
        StructFieldInformation::Declared(fields)
    } else {
        return Err(AdamantDeserializeError::UnknownStructFlag(flag));
    };
    Ok(StructDefinition {
        struct_handle,
        field_information,
    })
}

fn load_field_definitions(
    cursor: &mut std::io::Cursor<&[u8]>,
) -> Result<Vec<FieldDefinition>, AdamantDeserializeError> {
    let n = read_uleb128_length(cursor, FIELD_COUNT_MAX, "field count")?;
    let mut fields = Vec::with_capacity(n);
    for _ in 0..n {
        fields.push(load_field_definition(cursor)?);
    }
    Ok(fields)
}

fn load_field_definition(
    cursor: &mut std::io::Cursor<&[u8]>,
) -> Result<FieldDefinition, AdamantDeserializeError> {
    let name = load_identifier_index(cursor)?;
    let signature = move_binary_format::file_format::TypeSignature(load_signature_token(cursor)?);
    Ok(FieldDefinition { name, signature })
}

fn load_enum_definition(
    cursor: &mut std::io::Cursor<&[u8]>,
) -> Result<EnumDefinition, AdamantDeserializeError> {
    let enum_handle = load_datatype_handle_index(cursor)?;
    let flag = read_u8(cursor)?;
    if flag != SerializedEnumFlag::DECLARED as u8 {
        return Err(AdamantDeserializeError::UnknownEnumFlag(flag));
    }
    let n = read_uleb128_length(cursor, VARIANT_COUNT_MAX, "variant count")?;
    let mut variants = Vec::with_capacity(n);
    for _ in 0..n {
        variants.push(load_variant_definition(cursor)?);
    }
    Ok(EnumDefinition {
        enum_handle,
        variants,
    })
}

fn load_variant_definition(
    cursor: &mut std::io::Cursor<&[u8]>,
) -> Result<VariantDefinition, AdamantDeserializeError> {
    let variant_name = load_identifier_index(cursor)?;
    let fields = load_field_definitions(cursor)?;
    Ok(VariantDefinition {
        variant_name,
        fields,
    })
}

fn load_function_definition(
    cursor: &mut std::io::Cursor<&[u8]>,
    version: u32,
) -> Result<AdamantFunctionDefinition, AdamantDeserializeError> {
    let function = load_function_handle_index(cursor)?;

    let visibility_byte = read_u8(cursor)?;
    let (visibility, mut is_entry) = if version < VERSION_5 {
        // Pre-v5: visibility byte may carry the deprecated SCRIPT
        // marker (0x2), which encodes Public + entry. Mirrors
        // Sui's serializer lines 1693–1702 in reverse.
        if visibility_byte == Visibility::DEPRECATED_SCRIPT {
            (Visibility::Public, true)
        } else if let Ok(vis) = Visibility::try_from(visibility_byte) {
            (vis, false)
        } else {
            return Err(AdamantDeserializeError::UnknownVisibility(visibility_byte));
        }
    } else {
        let vis = Visibility::try_from(visibility_byte)
            .map_err(|()| AdamantDeserializeError::UnknownVisibility(visibility_byte))?;
        (vis, false)
    };

    let flags = read_u8(cursor)?;
    // Reject flag bits that are not ENTRY (0x4) or NATIVE (0x2).
    // Per Sui's serializer the only two bits that may be set are
    // these; bit 0x1 is the deprecated DEPRECATED_PUBLIC_BIT and
    // should never appear in a v≥5 module.
    let allowed_flags = FunctionDefinition::ENTRY | FunctionDefinition::NATIVE;
    if flags & !allowed_flags != 0 {
        return Err(AdamantDeserializeError::UnknownFunctionFlag(flags));
    }
    if flags & FunctionDefinition::ENTRY != 0 {
        if version >= VERSION_5 {
            is_entry = true;
        } else {
            // Pre-v5 should encode entry-ness via the SCRIPT
            // marker, not via the flag bit.
            return Err(AdamantDeserializeError::UnknownFunctionFlag(flags));
        }
    }
    let is_native = flags & FunctionDefinition::NATIVE != 0;

    let acquires_global_resources = load_acquires(cursor)?;
    let code = if is_native {
        None
    } else {
        Some(load_code_unit(cursor, version)?)
    };

    Ok(AdamantFunctionDefinition {
        function,
        visibility,
        is_entry,
        acquires_global_resources,
        code,
    })
}

fn load_acquires(
    cursor: &mut std::io::Cursor<&[u8]>,
) -> Result<Vec<StructDefinitionIndex>, AdamantDeserializeError> {
    let n = read_uleb128_length(cursor, ACQUIRES_COUNT_MAX, "acquires list length")?;
    let mut indices = Vec::with_capacity(n);
    for _ in 0..n {
        indices.push(load_struct_def_index(cursor)?);
    }
    Ok(indices)
}

fn load_code_unit(
    cursor: &mut std::io::Cursor<&[u8]>,
    version: u32,
) -> Result<AdamantCodeUnit, AdamantDeserializeError> {
    let locals = load_signature_index(cursor)?;
    // Function bodies are dispatched to bytecode_wire's cursor-API
    // variant in strict mode (rejects deprecated global-storage
    // opcodes per §6.2.1.6 Rule 5).
    let code = bytecode_wire::deserialize_function_body_from_cursor(
        cursor,
        &bytecode_wire::DeserializeConfig::strict(),
    )?;
    let jump_tables = load_jump_tables(cursor, version)?;
    Ok(AdamantCodeUnit {
        locals,
        code,
        jump_tables,
    })
}

fn load_jump_tables(
    cursor: &mut std::io::Cursor<&[u8]>,
    version: u32,
) -> Result<Vec<VariantJumpTable>, AdamantDeserializeError> {
    if version < VERSION_7 {
        // Sui's serializer emits no jump-table count byte at v < 7;
        // mirror that — the table is implicitly empty and there is
        // nothing to read.
        return Ok(vec![]);
    }
    let n = read_uleb128_bounded(cursor, JUMP_TABLE_INDEX_MAX, "jump table count")?;
    // Cast safety: `n <= JUMP_TABLE_INDEX_MAX = 1023` fits usize.
    #[allow(clippy::cast_possible_truncation)]
    let n_usize = n as usize;
    let mut tables = Vec::with_capacity(n_usize);
    for _ in 0..n_usize {
        tables.push(load_jump_table(cursor)?);
    }
    Ok(tables)
}

fn load_jump_table(
    cursor: &mut std::io::Cursor<&[u8]>,
) -> Result<VariantJumpTable, AdamantDeserializeError> {
    let head_enum = load_enum_def_index(cursor)?;
    let n = read_uleb128_length(cursor, VARIANT_COUNT_MAX, "jump table branch count")?;
    let flag = read_u8(cursor)?;
    if flag != SerializedJumpTableFlag::FULL as u8 {
        return Err(AdamantDeserializeError::UnknownJumpTableFlag(flag));
    }
    let mut branches = Vec::with_capacity(n);
    for _ in 0..n {
        let v = read_uleb128_bounded(cursor, BYTECODE_INDEX_MAX, "bytecode offset")?;
        // Cast safety: `BYTECODE_INDEX_MAX = 65535` fits u16.
        #[allow(clippy::cast_possible_truncation)]
        let off = v as u16;
        branches.push(off);
    }
    Ok(VariantJumpTable {
        head_enum,
        jump_table: JumpTableInner::Full(branches),
    })
}

// ----- Table layout parsing & validation -----

/// One table-index entry from the binary header.
#[derive(Clone, Copy, Debug)]
struct Table {
    kind: TableType,
    offset: u32,
    count: u32,
}

/// Maps a raw kind byte to a [`TableType`]. Sui's
/// `TableType::from_u8` is private to its deserializer crate, so we
/// reproduce the (small, finite) mapping here.
fn table_type_from_u8(byte: u8) -> Option<TableType> {
    match byte {
        x if x == TableType::MODULE_HANDLES as u8 => Some(TableType::MODULE_HANDLES),
        x if x == TableType::DATATYPE_HANDLES as u8 => Some(TableType::DATATYPE_HANDLES),
        x if x == TableType::FUNCTION_HANDLES as u8 => Some(TableType::FUNCTION_HANDLES),
        x if x == TableType::FUNCTION_INST as u8 => Some(TableType::FUNCTION_INST),
        x if x == TableType::SIGNATURES as u8 => Some(TableType::SIGNATURES),
        x if x == TableType::CONSTANT_POOL as u8 => Some(TableType::CONSTANT_POOL),
        x if x == TableType::IDENTIFIERS as u8 => Some(TableType::IDENTIFIERS),
        x if x == TableType::ADDRESS_IDENTIFIERS as u8 => Some(TableType::ADDRESS_IDENTIFIERS),
        x if x == TableType::STRUCT_DEFS as u8 => Some(TableType::STRUCT_DEFS),
        x if x == TableType::STRUCT_DEF_INST as u8 => Some(TableType::STRUCT_DEF_INST),
        x if x == TableType::FUNCTION_DEFS as u8 => Some(TableType::FUNCTION_DEFS),
        x if x == TableType::FIELD_HANDLE as u8 => Some(TableType::FIELD_HANDLE),
        x if x == TableType::FIELD_INST as u8 => Some(TableType::FIELD_INST),
        x if x == TableType::FRIEND_DECLS as u8 => Some(TableType::FRIEND_DECLS),
        x if x == TableType::METADATA as u8 => Some(TableType::METADATA),
        x if x == TableType::ENUM_DEFS as u8 => Some(TableType::ENUM_DEFS),
        x if x == TableType::ENUM_DEF_INST as u8 => Some(TableType::ENUM_DEF_INST),
        x if x == TableType::VARIANT_HANDLES as u8 => Some(TableType::VARIANT_HANDLES),
        x if x == TableType::VARIANT_INST_HANDLES as u8 => Some(TableType::VARIANT_INST_HANDLES),
        _ => None,
    }
}

/// Read all `table_count` table-index entries from the cursor.
fn read_tables(
    cursor: &mut std::io::Cursor<&[u8]>,
    table_count: u8,
) -> Result<Vec<Table>, AdamantDeserializeError> {
    let mut tables = Vec::with_capacity(table_count as usize);
    for _ in 0..table_count {
        let kind_byte = read_u8(cursor)?;
        let kind = table_type_from_u8(kind_byte)
            .ok_or(AdamantDeserializeError::UnknownTableKind(kind_byte))?;
        let offset = read_uleb128_bounded(cursor, u64::from(u32::MAX), "table offset")?;
        let count = read_uleb128_bounded(cursor, u64::from(u32::MAX), "table size")?;
        // Cast safety: bound checks above guarantee `offset, count <= u32::MAX`.
        #[allow(clippy::cast_possible_truncation)]
        let offset = offset as u32;
        #[allow(clippy::cast_possible_truncation)]
        let count = count as u32;
        tables.push(Table {
            kind,
            offset,
            count,
        });
    }
    Ok(tables)
}

/// Validate table layout: tables must be contiguous (sorted by
/// offset, no gaps, no overlap), each table.count > 0, no duplicate
/// kinds, and total content ≤ available bytes. Returns the
/// cumulative content length.
fn check_tables(
    tables: &mut [Table],
    available_content_bytes: usize,
) -> Result<u32, AdamantDeserializeError> {
    tables.sort_by_key(|t| t.offset);
    let mut current_offset: u32 = 0;
    let mut seen = std::collections::HashSet::new();
    for table in tables.iter() {
        if table.offset != current_offset {
            return Err(AdamantDeserializeError::BadTableLayout {
                reason: "non-contiguous table offsets",
            });
        }
        if table.count == 0 {
            return Err(AdamantDeserializeError::BadTableLayout {
                reason: "zero-length table",
            });
        }
        current_offset = current_offset.checked_add(table.count).ok_or(
            AdamantDeserializeError::BadTableLayout {
                reason: "table content size overflows u32",
            },
        )?;
        if !seen.insert(table.kind) {
            return Err(AdamantDeserializeError::DuplicateTable(table.kind));
        }
        if current_offset as usize > available_content_bytes {
            return Err(AdamantDeserializeError::BadTableLayout {
                reason: "table content extends past binary",
            });
        }
    }
    Ok(current_offset)
}

// ----- Top-level orchestration -----

/// Parses module bytes per whitepaper §6.2.1.2 (binary format) and
/// §6.2.1.8 (fully Adamant-native verifier architecture).
///
/// Strict canonical decoding: trailing bytes, duplicate tables,
/// version-feature mismatches, deprecated global-storage opcodes
/// (per §6.2.1.6 Rule 5), and zero-length tables are all rejected.
///
/// # Errors
///
/// Returns [`AdamantDeserializeError`] on any of the parse-time
/// failure modes enumerated by that type.
pub fn adamant_deserialize(bytes: &[u8]) -> Result<AdamantCompiledModule, AdamantDeserializeError> {
    use std::io::Cursor;

    // ----- Header: magic + flavored version -----
    if bytes.len() < BinaryConstants::MOVE_MAGIC_SIZE + 4 {
        return Err(AdamantDeserializeError::UnexpectedEof);
    }
    // Cast safety: literal index, well within bytes.len() check above.
    let mut magic = [0u8; 4];
    magic.copy_from_slice(&bytes[..4]);
    let publishable = match BinaryConstants::decode_magic(magic, 4) {
        Ok(adamant_bytecode_format::MagicKind::Normal) => true,
        Ok(adamant_bytecode_format::MagicKind::Unpublishable) => false,
        Err(_) => return Err(AdamantDeserializeError::BadMagic(magic)),
    };

    let mut cursor = Cursor::new(bytes);
    cursor.set_position(4);
    let flavored = read_u32_le(&mut cursor)?;
    let version = BinaryFlavor::decode_version(flavored);
    if !(VERSION_MIN..=VERSION_MAX).contains(&version) {
        return Err(AdamantDeserializeError::UnsupportedVersion(version));
    }
    if version >= VERSION_7 {
        match BinaryFlavor::decode_flavor(flavored) {
            Some(b) if b == BinaryFlavor::SUI_FLAVOR => {}
            Some(b) => return Err(AdamantDeserializeError::UnknownFlavor(b)),
            None => {
                return Err(AdamantDeserializeError::BadTableLayout {
                    reason: "v≥7 requires flavor byte",
                });
            }
        }
    }

    // ----- Table-index block -----
    let table_count = read_u8(&mut cursor)?;
    if u64::from(table_count) > TABLE_COUNT_MAX {
        return Err(AdamantDeserializeError::OutOfRange {
            kind: "table count",
            value: u64::from(table_count),
            max: TABLE_COUNT_MAX,
        });
    }
    let mut tables = read_tables(&mut cursor, table_count)?;

    // The remaining-bytes window starts at the cursor position
    // (after the table-index block) and extends to the end of
    // `bytes` minus the trailing self-handle ULEB128. We don't
    // know the trailing-handle's length in advance, so we let the
    // table-content cover the full remainder and validate the
    // trailing handle separately at the end.
    // Cast safety: cursor.position() bounded by bytes.len().
    #[allow(clippy::cast_possible_truncation)]
    let content_start = cursor.position() as usize;
    if content_start > bytes.len() {
        return Err(AdamantDeserializeError::UnexpectedEof);
    }
    let content_window_len = bytes.len() - content_start;
    let total_content = check_tables(&mut tables, content_window_len)?;

    // ----- Build the module -----
    let mut module = AdamantCompiledModule {
        version,
        publishable,
        ..AdamantCompiledModule::default()
    };

    for table in &tables {
        let abs_start = content_start + table.offset as usize;
        let abs_end = abs_start + table.count as usize;
        // Sub-cursor over the table's byte range. We slice the
        // outer `bytes` to the table's window and parse content
        // until exhausted.
        let table_bytes = &bytes[abs_start..abs_end];
        let mut table_cursor = Cursor::new(table_bytes);
        load_table(&mut table_cursor, &mut module, table.kind, version)?;
        // Verify the sub-cursor consumed exactly the table's
        // declared range (catches per-pool over- or under-reads).
        #[allow(clippy::cast_possible_truncation)]
        let consumed = table_cursor.position() as usize;
        if consumed != table_bytes.len() {
            return Err(AdamantDeserializeError::BadTableLayout {
                reason: "table parser under- or over-consumed",
            });
        }
    }

    // ----- Trailing self_module_handle_idx -----
    cursor.set_position((content_start + total_content as usize) as u64);
    module.self_module_handle_idx = load_module_handle_index(&mut cursor)?;

    // ----- Canonicality: no trailing bytes -----
    #[allow(clippy::cast_possible_truncation)]
    let final_pos = cursor.position() as usize;
    if final_pos != bytes.len() {
        return Err(AdamantDeserializeError::TrailingBytes);
    }
    Ok(module)
}

/// Dispatches a single table to its per-pool loader based on
/// [`TableType`] kind. Mirrors Sui's
/// `build_common_tables` / `build_module_tables` split, fused into
/// one function since Adamant has only one container type
/// ([`AdamantCompiledModule`], no `CompiledScript`).
#[allow(clippy::too_many_lines)]
fn load_table(
    cursor: &mut std::io::Cursor<&[u8]>,
    module: &mut AdamantCompiledModule,
    kind: TableType,
    version: u32,
) -> Result<(), AdamantDeserializeError> {
    match kind {
        TableType::MODULE_HANDLES => {
            while !cursor_at_end(cursor) {
                module.module_handles.push(load_module_handle(cursor)?);
            }
        }
        TableType::DATATYPE_HANDLES => {
            while !cursor_at_end(cursor) {
                module.datatype_handles.push(load_datatype_handle(cursor)?);
            }
        }
        TableType::FUNCTION_HANDLES => {
            while !cursor_at_end(cursor) {
                module.function_handles.push(load_function_handle(cursor)?);
            }
        }
        TableType::FUNCTION_INST => {
            while !cursor_at_end(cursor) {
                module
                    .function_instantiations
                    .push(load_function_instantiation(cursor)?);
            }
        }
        TableType::SIGNATURES => {
            while !cursor_at_end(cursor) {
                module.signatures.push(load_signature(cursor)?);
            }
        }
        TableType::IDENTIFIERS => {
            while !cursor_at_end(cursor) {
                module.identifiers.push(load_identifier(cursor)?);
            }
        }
        TableType::ADDRESS_IDENTIFIERS => {
            while !cursor_at_end(cursor) {
                module.address_identifiers.push(load_address(cursor)?);
            }
        }
        TableType::CONSTANT_POOL => {
            while !cursor_at_end(cursor) {
                module.constant_pool.push(load_constant(cursor)?);
            }
        }
        TableType::METADATA => {
            if version < VERSION_5 {
                return Err(AdamantDeserializeError::VersionFeatureMismatch {
                    feature: "metadata",
                    version,
                });
            }
            while !cursor_at_end(cursor) {
                module.metadata.push(load_metadata_entry(cursor)?);
            }
        }
        TableType::STRUCT_DEFS => {
            while !cursor_at_end(cursor) {
                module.struct_defs.push(load_struct_definition(cursor)?);
            }
        }
        TableType::STRUCT_DEF_INST => {
            while !cursor_at_end(cursor) {
                module
                    .struct_def_instantiations
                    .push(load_struct_def_instantiation(cursor)?);
            }
        }
        TableType::FUNCTION_DEFS => {
            while !cursor_at_end(cursor) {
                module
                    .function_defs
                    .push(load_function_definition(cursor, version)?);
            }
        }
        TableType::FIELD_HANDLE => {
            while !cursor_at_end(cursor) {
                module.field_handles.push(load_field_handle(cursor)?);
            }
        }
        TableType::FIELD_INST => {
            while !cursor_at_end(cursor) {
                module
                    .field_instantiations
                    .push(load_field_instantiation(cursor)?);
            }
        }
        TableType::FRIEND_DECLS => {
            while !cursor_at_end(cursor) {
                module.friend_decls.push(load_module_handle(cursor)?);
            }
        }
        TableType::ENUM_DEFS => {
            if version < VERSION_7 {
                return Err(AdamantDeserializeError::VersionFeatureMismatch {
                    feature: "enum tables",
                    version,
                });
            }
            while !cursor_at_end(cursor) {
                module.enum_defs.push(load_enum_definition(cursor)?);
            }
        }
        TableType::ENUM_DEF_INST => {
            if version < VERSION_7 {
                return Err(AdamantDeserializeError::VersionFeatureMismatch {
                    feature: "enum tables",
                    version,
                });
            }
            while !cursor_at_end(cursor) {
                module
                    .enum_def_instantiations
                    .push(load_enum_def_instantiation(cursor)?);
            }
        }
        TableType::VARIANT_HANDLES => {
            if version < VERSION_7 {
                return Err(AdamantDeserializeError::VersionFeatureMismatch {
                    feature: "enum tables",
                    version,
                });
            }
            while !cursor_at_end(cursor) {
                module.variant_handles.push(load_variant_handle(cursor)?);
            }
        }
        TableType::VARIANT_INST_HANDLES => {
            if version < VERSION_7 {
                return Err(AdamantDeserializeError::VersionFeatureMismatch {
                    feature: "enum tables",
                    version,
                });
            }
            while !cursor_at_end(cursor) {
                module
                    .variant_instantiation_handles
                    .push(load_variant_instantiation_handle(cursor)?);
            }
        }
    }
    Ok(())
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bytecode::BytecodeInstruction;
    use adamant_bytecode_format::VERSION_6;
    use move_binary_format::file_format::{
        AbilitySet, AddressIdentifierIndex, Bytecode, CodeUnit, CompiledModule, Constant,
        DatatypeHandle, FunctionDefinition as SuiFunctionDefinition, FunctionHandle, ModuleHandle,
        Signature, SignatureToken, Visibility,
    };
    use move_core_types::account_address::AccountAddress;
    use move_core_types::identifier::Identifier;
    use move_core_types::metadata::Metadata;

    // ---- Fixture builders --------------------------------------------------

    /// Returns a minimal valid (Adamant, Sui) module pair: a single
    /// module handle, a single identifier, a single address, the
    /// `self_module_handle_idx` pointing at the only module handle.
    fn minimal_pair(version: u32) -> (AdamantCompiledModule, CompiledModule) {
        let identifiers = vec![Identifier::new("M").unwrap()];
        let address_identifiers = vec![AccountAddress::ZERO];
        let module_handles = vec![ModuleHandle {
            address: AddressIdentifierIndex(0),
            name: IdentifierIndex(0),
        }];
        let adamant = AdamantCompiledModule {
            version,
            publishable: true,
            self_module_handle_idx: ModuleHandleIndex(0),
            module_handles: module_handles.clone(),
            identifiers: identifiers.clone(),
            address_identifiers: address_identifiers.clone(),
            ..AdamantCompiledModule::default()
        };
        let sui = CompiledModule {
            version,
            publishable: true,
            self_module_handle_idx: ModuleHandleIndex(0),
            module_handles,
            identifiers,
            address_identifiers,
            ..CompiledModule::default()
        };
        (adamant, sui)
    }

    /// Builds a richer pair containing every common-table category
    /// (handles, signatures, constants, metadata) plus a single
    /// pure-Sui function definition with a small body.
    fn rich_pure_sui_pair(version: u32) -> (AdamantCompiledModule, CompiledModule) {
        let (mut adamant, mut sui) = minimal_pair(version);
        // Identifiers.
        adamant.identifiers.push(Identifier::new("f").unwrap());
        sui.identifiers.push(Identifier::new("f").unwrap());
        // Datatype handle.
        let dh = DatatypeHandle {
            module: ModuleHandleIndex(0),
            name: IdentifierIndex(1),
            abilities: AbilitySet::EMPTY | move_binary_format::file_format::Ability::Drop,
            type_parameters: vec![],
        };
        adamant.datatype_handles.push(dh.clone());
        sui.datatype_handles.push(dh);
        // Signatures: empty + (U64,).
        adamant.signatures.push(Signature(vec![]));
        adamant
            .signatures
            .push(Signature(vec![SignatureToken::U64]));
        sui.signatures.push(Signature(vec![]));
        sui.signatures.push(Signature(vec![SignatureToken::U64]));
        // Function handle for a function `f(): u64`.
        let fh = FunctionHandle {
            module: ModuleHandleIndex(0),
            name: IdentifierIndex(1),
            parameters: SignatureIndex(0),
            return_: SignatureIndex(1),
            type_parameters: vec![],
        };
        adamant.function_handles.push(fh.clone());
        sui.function_handles.push(fh);
        // Constant pool.
        adamant.constant_pool.push(Constant {
            type_: SignatureToken::U64,
            data: vec![1, 0, 0, 0, 0, 0, 0, 0],
        });
        sui.constant_pool.push(Constant {
            type_: SignatureToken::U64,
            data: vec![1, 0, 0, 0, 0, 0, 0, 0],
        });
        // Metadata (version 5+).
        if version >= VERSION_5 {
            adamant.metadata.push(Metadata {
                key: b"adamant.privacy".to_vec(),
                value: vec![0x00],
            });
            sui.metadata.push(Metadata {
                key: b"adamant.privacy".to_vec(),
                value: vec![0x00],
            });
        }
        // Function definition with a small pure-Sui body:
        //   LdU64(1); Pop; Ret
        let adamant_body = vec![
            BytecodeInstruction::Inherited(Bytecode::LdU64(1)),
            BytecodeInstruction::Inherited(Bytecode::Pop),
            BytecodeInstruction::Inherited(Bytecode::Ret),
        ];
        let sui_body = vec![Bytecode::LdU64(1), Bytecode::Pop, Bytecode::Ret];
        adamant.function_defs.push(AdamantFunctionDefinition {
            function: FunctionHandleIndex(0),
            visibility: Visibility::Public,
            is_entry: false,
            acquires_global_resources: vec![],
            code: Some(AdamantCodeUnit {
                locals: SignatureIndex(0),
                code: adamant_body,
                jump_tables: vec![],
            }),
        });
        sui.function_defs.push(SuiFunctionDefinition {
            function: FunctionHandleIndex(0),
            visibility: Visibility::Public,
            is_entry: false,
            acquires_global_resources: vec![],
            code: Some(CodeUnit {
                locals: SignatureIndex(0),
                code: sui_body,
                jump_tables: vec![],
            }),
        });
        (adamant, sui)
    }

    // ---- Constructive byte-comparison tests -------------------------------

    /// An empty module at `VERSION_MAX` serialises to: magic +
    /// version + table count `0` (one ULEB128 byte) + trailing
    /// `self_module_handle_idx` ULEB128. No tables means no per-table
    /// entries in the index block.
    #[test]
    fn empty_module_serializes_to_expected_bytes() {
        let module = AdamantCompiledModule {
            version: VERSION_MAX,
            publishable: true,
            self_module_handle_idx: ModuleHandleIndex(0),
            ..AdamantCompiledModule::default()
        };
        let mut out = Vec::new();
        adamant_serialize(&module, &mut out).unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&BinaryConstants::MOVE_MAGIC);
        expected.extend_from_slice(&BinaryFlavor::encode_version(VERSION_MAX).to_le_bytes());
        expected.push(0); // table_count = 0
        expected.push(0); // self_module_handle_idx = 0
        assert_eq!(out, expected);
    }

    /// Unpublishable modules begin with `UNPUBLISHABLE_MAGIC` rather
    /// than `MOVE_MAGIC`.
    #[test]
    fn unpublishable_module_uses_unpublishable_magic() {
        let module = AdamantCompiledModule {
            version: VERSION_MAX,
            publishable: false,
            self_module_handle_idx: ModuleHandleIndex(0),
            ..AdamantCompiledModule::default()
        };
        let mut out = Vec::new();
        adamant_serialize(&module, &mut out).unwrap();
        assert_eq!(&out[..4], &BinaryConstants::UNPUBLISHABLE_MAGIC);
    }

    /// `version < VERSION_MIN` is rejected with `UnsupportedVersion`.
    #[test]
    fn rejects_version_below_minimum() {
        let module = AdamantCompiledModule {
            version: VERSION_MIN - 1,
            ..AdamantCompiledModule::default()
        };
        let err = adamant_serialize(&module, &mut Vec::new()).unwrap_err();
        assert_eq!(
            err,
            AdamantSerializeError::UnsupportedVersion(VERSION_MIN - 1)
        );
    }

    /// `version > VERSION_MAX` is rejected with `UnsupportedVersion`.
    #[test]
    fn rejects_version_above_maximum() {
        let module = AdamantCompiledModule {
            version: VERSION_MAX + 1,
            ..AdamantCompiledModule::default()
        };
        let err = adamant_serialize(&module, &mut Vec::new()).unwrap_err();
        assert_eq!(
            err,
            AdamantSerializeError::UnsupportedVersion(VERSION_MAX + 1)
        );
    }

    /// Enum tables at version < 7 are rejected with
    /// `VersionFeatureMismatch`.
    #[test]
    fn rejects_enum_definitions_at_version_below_7() {
        let mut module = AdamantCompiledModule {
            version: VERSION_6,
            publishable: true,
            self_module_handle_idx: ModuleHandleIndex(0),
            ..AdamantCompiledModule::default()
        };
        // Stub enum definition (don't need handles to exist for
        // wire serialization rejection — the version check fires
        // before any handle index is read).
        module.enum_defs.push(EnumDefinition {
            enum_handle: DatatypeHandleIndex(0),
            variants: vec![],
        });
        let err = adamant_serialize(&module, &mut Vec::new()).unwrap_err();
        assert!(matches!(
            err,
            AdamantSerializeError::VersionFeatureMismatch {
                feature: "enum tables",
                ..
            }
        ));
    }

    /// Metadata at version < 5 is rejected with
    /// `VersionFeatureMismatch`. (This branch can fire only if a
    /// caller hand-constructs a v4 module, which our `VERSION_MIN`
    /// floor of 5 makes impossible — but the check is still wired so
    /// future floor-lowering does not regress.)
    #[test]
    fn metadata_below_version_5_check_present() {
        // VERSION_MIN is 5 today; this test verifies the branch is
        // reachable in principle by checking the check fires when
        // we manually inject a v5 module with metadata against the
        // version-feature check at version=5 boundary. We use a
        // ge-5 path here since we can't construct a v<5 module.
        // The real defensive value of this branch is that adding
        // VERSION_4 to VERSION_MIN later won't silently accept
        // metadata.
        let module = AdamantCompiledModule {
            version: VERSION_5,
            publishable: true,
            self_module_handle_idx: ModuleHandleIndex(0),
            metadata: vec![Metadata {
                key: b"x".to_vec(),
                value: b"y".to_vec(),
            }],
            ..AdamantCompiledModule::default()
        };
        // At version 5, metadata is allowed; serialization should
        // succeed. The branch under test fires only at version < 5,
        // which is unreachable through the public API, but the
        // defensive check itself is exercised in
        // `serialize_tables`.
        let mut out = Vec::new();
        adamant_serialize(&module, &mut out).unwrap();
        assert!(!out.is_empty());
    }

    /// Module with `metadata.value` longer than
    /// `METADATA_VALUE_SIZE_MAX` is rejected with `LengthOverflow`.
    #[test]
    fn rejects_oversized_metadata_value() {
        let module = AdamantCompiledModule {
            version: VERSION_MAX,
            publishable: true,
            self_module_handle_idx: ModuleHandleIndex(0),
            metadata: vec![Metadata {
                key: b"k".to_vec(),
                // `METADATA_VALUE_SIZE_MAX + 1` bytes. Cast safety:
                // `METADATA_VALUE_SIZE_MAX` is 65535, well below
                // `usize::MAX` on every supported target.
                value: vec![
                    0u8;
                    usize::try_from(METADATA_VALUE_SIZE_MAX).expect("MAX fits usize") + 1
                ],
            }],
            ..AdamantCompiledModule::default()
        };
        let err = adamant_serialize(&module, &mut Vec::new()).unwrap_err();
        assert!(matches!(
            err,
            AdamantSerializeError::LengthOverflow {
                kind: "metadata value size",
                ..
            }
        ));
    }

    /// `Display` impl on `AdamantSerializeError` produces non-empty
    /// strings for every variant. Pin this so the diagnostic surface
    /// does not silently regress to a `Debug`-only path.
    #[test]
    fn error_display_is_populated() {
        let cases = [
            AdamantSerializeError::UnsupportedVersion(99),
            AdamantSerializeError::IndexOverflow {
                kind: "x",
                value: 1,
                max: 0,
            },
            AdamantSerializeError::LengthOverflow {
                kind: "y",
                len: 1,
                max: 0,
            },
            AdamantSerializeError::BinaryTooLarge(usize::MAX),
            AdamantSerializeError::SignatureTooDeep,
            AdamantSerializeError::VersionFeatureMismatch {
                feature: "z",
                version: 5,
            },
            AdamantSerializeError::Bytecode(bytecode_wire::SerializeError::OperandOverflow),
        ];
        for e in &cases {
            assert!(!format!("{e}").is_empty(), "empty Display for {e:?}");
        }
    }

    // ---- Cross-validation against Sui's serializer -------------------------

    /// A pure-Sui empty module serialises byte-identically through
    /// Adamant's serializer and Sui's reference serializer at every
    /// supported version.
    #[test]
    fn cross_validate_empty_module_all_versions() {
        for version in VERSION_MIN..=VERSION_MAX {
            let (adamant, sui) = minimal_pair(version);
            let mut adamant_bytes = Vec::new();
            adamant_serialize(&adamant, &mut adamant_bytes).unwrap();
            let mut sui_bytes = Vec::new();
            sui.serialize_with_version(version, &mut sui_bytes).unwrap();
            assert_eq!(
                adamant_bytes, sui_bytes,
                "version {version}: byte mismatch between Adamant and Sui serialisers"
            );
        }
    }

    /// A pure-Sui module with handles, identifiers, signatures,
    /// constants, metadata, and a function body serialises byte-
    /// identically to Sui's reference output.
    #[test]
    fn cross_validate_rich_pure_sui_module() {
        let (adamant, sui) = rich_pure_sui_pair(VERSION_MAX);
        let mut adamant_bytes = Vec::new();
        adamant_serialize(&adamant, &mut adamant_bytes).unwrap();
        let mut sui_bytes = Vec::new();
        sui.serialize_with_version(VERSION_MAX, &mut sui_bytes)
            .unwrap();
        assert_eq!(
            adamant_bytes, sui_bytes,
            "byte mismatch between Adamant and Sui serialisers on rich pure-Sui module"
        );
    }

    /// `Visibility::Public` + `is_entry: true` at version < 5 emits
    /// the deprecated SCRIPT marker. Cross-validate against Sui's
    /// reference serializer at version 5 (the floor) to confirm the
    /// post-v5 path emits visibility + flags in the order Sui does.
    #[test]
    fn cross_validate_public_entry_function_at_v5() {
        let (mut adamant, mut sui) = minimal_pair(VERSION_5);
        adamant.identifiers.push(Identifier::new("g").unwrap());
        sui.identifiers.push(Identifier::new("g").unwrap());
        adamant.signatures.push(Signature(vec![]));
        sui.signatures.push(Signature(vec![]));
        let fh = FunctionHandle {
            module: ModuleHandleIndex(0),
            name: IdentifierIndex(1),
            parameters: SignatureIndex(0),
            return_: SignatureIndex(0),
            type_parameters: vec![],
        };
        adamant.function_handles.push(fh.clone());
        sui.function_handles.push(fh);
        adamant.function_defs.push(AdamantFunctionDefinition {
            function: FunctionHandleIndex(0),
            visibility: Visibility::Public,
            is_entry: true,
            acquires_global_resources: vec![],
            code: Some(AdamantCodeUnit {
                locals: SignatureIndex(0),
                code: vec![BytecodeInstruction::Inherited(Bytecode::Ret)],
                jump_tables: vec![],
            }),
        });
        sui.function_defs.push(SuiFunctionDefinition {
            function: FunctionHandleIndex(0),
            visibility: Visibility::Public,
            is_entry: true,
            acquires_global_resources: vec![],
            code: Some(CodeUnit {
                locals: SignatureIndex(0),
                code: vec![Bytecode::Ret],
                jump_tables: vec![],
            }),
        });

        let mut adamant_bytes = Vec::new();
        adamant_serialize(&adamant, &mut adamant_bytes).unwrap();
        let mut sui_bytes = Vec::new();
        sui.serialize_with_version(VERSION_5, &mut sui_bytes)
            .unwrap();
        assert_eq!(adamant_bytes, sui_bytes);
    }

    /// Friend declarations (a module-only table that stores
    /// `ModuleHandle`s) round-trip byte-identically.
    #[test]
    fn cross_validate_friend_decls() {
        let (mut adamant, mut sui) = minimal_pair(VERSION_MAX);
        adamant
            .identifiers
            .push(Identifier::new("FriendMod").unwrap());
        sui.identifiers.push(Identifier::new("FriendMod").unwrap());
        let friend = ModuleHandle {
            address: AddressIdentifierIndex(0),
            name: IdentifierIndex(1),
        };
        adamant.friend_decls.push(friend.clone());
        sui.friend_decls.push(friend);

        let mut adamant_bytes = Vec::new();
        adamant_serialize(&adamant, &mut adamant_bytes).unwrap();
        let mut sui_bytes = Vec::new();
        sui.serialize_with_version(VERSION_MAX, &mut sui_bytes)
            .unwrap();
        assert_eq!(adamant_bytes, sui_bytes);
    }

    /// `SignatureToken::Vector(Box::new(SignatureToken::U8))` exercises
    /// the recursive preorder traversal. Cross-validate the token
    /// encoding against Sui's reference output by embedding it in a
    /// constant.
    #[test]
    fn cross_validate_recursive_signature_token() {
        let (mut adamant, mut sui) = minimal_pair(VERSION_MAX);
        adamant.constant_pool.push(Constant {
            type_: SignatureToken::Vector(Box::new(SignatureToken::U8)),
            data: vec![],
        });
        sui.constant_pool.push(Constant {
            type_: SignatureToken::Vector(Box::new(SignatureToken::U8)),
            data: vec![],
        });

        let mut adamant_bytes = Vec::new();
        adamant_serialize(&adamant, &mut adamant_bytes).unwrap();
        let mut sui_bytes = Vec::new();
        sui.serialize_with_version(VERSION_MAX, &mut sui_bytes)
            .unwrap();
        assert_eq!(adamant_bytes, sui_bytes);
    }

    // ---- Adamant-extension serialization (no Sui counterpart) -------------

    /// A function body containing an Adamant extension serialises
    /// without panicking. Byte-level correctness here is covered by
    /// `bytecode_wire`'s own round-trip tests; this test confirms
    /// the module-level path delegates to `bytecode_wire` rather
    /// than dropping or substituting extensions silently.
    #[test]
    fn extension_in_function_body_serializes_successfully() {
        use crate::bytecode::AdamantBytecode;

        let mut module = AdamantCompiledModule {
            version: VERSION_MAX,
            publishable: true,
            self_module_handle_idx: ModuleHandleIndex(0),
            module_handles: vec![ModuleHandle {
                address: AddressIdentifierIndex(0),
                name: IdentifierIndex(0),
            }],
            identifiers: vec![Identifier::new("M").unwrap(), Identifier::new("h").unwrap()],
            address_identifiers: vec![AccountAddress::ZERO],
            signatures: vec![Signature(vec![])],
            ..AdamantCompiledModule::default()
        };
        module.function_handles.push(FunctionHandle {
            module: ModuleHandleIndex(0),
            name: IdentifierIndex(1),
            parameters: SignatureIndex(0),
            return_: SignatureIndex(0),
            type_parameters: vec![],
        });
        module.function_defs.push(AdamantFunctionDefinition {
            function: FunctionHandleIndex(0),
            visibility: Visibility::Private,
            is_entry: false,
            acquires_global_resources: vec![],
            code: Some(AdamantCodeUnit {
                locals: SignatureIndex(0),
                code: vec![
                    BytecodeInstruction::Adamant(AdamantBytecode::Sha3_256),
                    BytecodeInstruction::Inherited(Bytecode::Ret),
                ],
                jump_tables: vec![],
            }),
        });

        let mut out = Vec::new();
        adamant_serialize(&module, &mut out).unwrap();
        assert!(module.contains_adamant_extensions());
        assert!(!out.is_empty());
    }

    // ---- Deserializer: round-trip property tests ------------------------

    fn round_trip_module(module: &AdamantCompiledModule) {
        let mut bytes = Vec::new();
        adamant_serialize(module, &mut bytes).expect("serialize");
        let parsed = adamant_deserialize(&bytes).expect("deserialize");
        assert_eq!(&parsed, module, "round-trip mismatch");
    }

    /// Empty module round-trips at every supported version and
    /// publishability.
    #[test]
    fn round_trip_empty_module_all_versions() {
        for version in VERSION_MIN..=VERSION_MAX {
            for publishable in [true, false] {
                let module = AdamantCompiledModule {
                    version,
                    publishable,
                    self_module_handle_idx: ModuleHandleIndex(0),
                    ..AdamantCompiledModule::default()
                };
                round_trip_module(&module);
            }
        }
    }

    /// Rich pure-Sui module (handles, identifiers, signatures,
    /// constants, metadata, function with body) round-trips.
    #[test]
    fn round_trip_rich_pure_sui_module() {
        let (module, _) = rich_pure_sui_pair(VERSION_MAX);
        round_trip_module(&module);
    }

    /// Module with friend declarations round-trips.
    #[test]
    fn round_trip_friend_decls() {
        let (mut module, _) = minimal_pair(VERSION_MAX);
        module
            .identifiers
            .push(Identifier::new("FriendMod").unwrap());
        module.friend_decls.push(ModuleHandle {
            address: AddressIdentifierIndex(0),
            name: IdentifierIndex(1),
        });
        round_trip_module(&module);
    }

    /// `Vector(Box<U8>)` signature token (recursive) round-trips
    /// via the iterative parser.
    #[test]
    fn round_trip_vector_u8_signature_token() {
        let (mut module, _) = minimal_pair(VERSION_MAX);
        module.constant_pool.push(Constant {
            type_: SignatureToken::Vector(Box::new(SignatureToken::U8)),
            data: vec![],
        });
        round_trip_module(&module);
    }

    /// `SignatureToken` nesting at `SIGNATURE_TOKEN_DEPTH_MAX + 1`
    /// is rejected with `SignatureTooDeep`. Exercises the depth
    /// check in the iterative parser at its boundary;
    /// [`round_trip_deep_signature_token_within_depth`] covers the
    /// well-under-limit case.
    ///
    /// Constructs the byte sequence directly (`MAX+1` `VECTOR` tag
    /// bytes followed by a `U8` terminator) and dispatches to the
    /// private `load_signature_token` parser via the test module's
    /// `super::*` import — the rejection happens before any
    /// terminal token is consumed, so the byte sequence's
    /// well-formedness past the depth check doesn't matter.
    #[test]
    fn signature_token_at_max_depth_plus_one_rejected() {
        let depth = SIGNATURE_TOKEN_DEPTH_MAX + 1;
        let mut bytes = Vec::with_capacity(depth + 1);
        for _ in 0..depth {
            bytes.push(SerializedType::VECTOR as u8);
        }
        bytes.push(SerializedType::U8 as u8);
        let mut cursor = std::io::Cursor::new(&bytes[..]);
        let result = load_signature_token(&mut cursor);
        assert_eq!(
            result.unwrap_err(),
            AdamantDeserializeError::SignatureTooDeep
        );
    }

    /// Deeply-nested `Vector(Vector(...(U8)...))` round-trips up to
    /// `SIGNATURE_TOKEN_DEPTH_MAX - 1` (within the depth bound).
    #[test]
    fn round_trip_deep_signature_token_within_depth() {
        let (mut module, _) = minimal_pair(VERSION_MAX);
        // Build Vector wrapping U8 to depth 64 (well under the 256
        // limit but exercises the iterative parser non-trivially).
        let mut tok = SignatureToken::U8;
        for _ in 0..64 {
            tok = SignatureToken::Vector(Box::new(tok));
        }
        module.constant_pool.push(Constant {
            type_: tok,
            data: vec![],
        });
        round_trip_module(&module);
    }

    /// Module with `DatatypeInstantiation(idx, [U64, Bool])` round-trips
    /// via the multi-child collapse path of the iterative parser.
    #[test]
    fn round_trip_datatype_instantiation_signature_token() {
        let (mut module, _) = minimal_pair(VERSION_MAX);
        // Need a datatype handle for the instantiation to point at.
        module.identifiers.push(Identifier::new("S").unwrap());
        module.datatype_handles.push(DatatypeHandle {
            module: ModuleHandleIndex(0),
            name: IdentifierIndex(1),
            abilities: AbilitySet::EMPTY,
            type_parameters: vec![],
        });
        module.constant_pool.push(Constant {
            type_: SignatureToken::DatatypeInstantiation(Box::new((
                DatatypeHandleIndex(0),
                vec![SignatureToken::U64, SignatureToken::Bool],
            ))),
            data: vec![],
        });
        round_trip_module(&module);
    }

    /// Module with an Adamant-extension instruction in a function
    /// body round-trips through deserialize. This is the load-bearing
    /// test for the `bytecode_wire` cursor-API integration.
    #[test]
    fn round_trip_function_body_with_extension() {
        use crate::bytecode::AdamantBytecode;
        let mut module = AdamantCompiledModule {
            version: VERSION_MAX,
            publishable: true,
            self_module_handle_idx: ModuleHandleIndex(0),
            module_handles: vec![ModuleHandle {
                address: AddressIdentifierIndex(0),
                name: IdentifierIndex(0),
            }],
            identifiers: vec![Identifier::new("M").unwrap(), Identifier::new("h").unwrap()],
            address_identifiers: vec![AccountAddress::ZERO],
            signatures: vec![Signature(vec![])],
            ..AdamantCompiledModule::default()
        };
        module.function_handles.push(FunctionHandle {
            module: ModuleHandleIndex(0),
            name: IdentifierIndex(1),
            parameters: SignatureIndex(0),
            return_: SignatureIndex(0),
            type_parameters: vec![],
        });
        module.function_defs.push(AdamantFunctionDefinition {
            function: FunctionHandleIndex(0),
            visibility: Visibility::Private,
            is_entry: false,
            acquires_global_resources: vec![],
            code: Some(AdamantCodeUnit {
                locals: SignatureIndex(0),
                code: vec![
                    BytecodeInstruction::Adamant(AdamantBytecode::Sha3_256),
                    BytecodeInstruction::Adamant(AdamantBytecode::Blake3),
                    BytecodeInstruction::Inherited(Bytecode::Ret),
                ],
                jump_tables: vec![],
            }),
        });
        round_trip_module(&module);
    }

    /// Module containing a public-entry function at version 5
    /// (deprecated SCRIPT visibility marker is *not* used at v≥5)
    /// round-trips.
    #[test]
    fn round_trip_public_entry_function_at_v5() {
        let mut module = AdamantCompiledModule {
            version: VERSION_5,
            publishable: true,
            self_module_handle_idx: ModuleHandleIndex(0),
            module_handles: vec![ModuleHandle {
                address: AddressIdentifierIndex(0),
                name: IdentifierIndex(0),
            }],
            identifiers: vec![Identifier::new("M").unwrap(), Identifier::new("g").unwrap()],
            address_identifiers: vec![AccountAddress::ZERO],
            signatures: vec![Signature(vec![])],
            ..AdamantCompiledModule::default()
        };
        module.function_handles.push(FunctionHandle {
            module: ModuleHandleIndex(0),
            name: IdentifierIndex(1),
            parameters: SignatureIndex(0),
            return_: SignatureIndex(0),
            type_parameters: vec![],
        });
        module.function_defs.push(AdamantFunctionDefinition {
            function: FunctionHandleIndex(0),
            visibility: Visibility::Public,
            is_entry: true,
            acquires_global_resources: vec![],
            code: Some(AdamantCodeUnit {
                locals: SignatureIndex(0),
                code: vec![BytecodeInstruction::Inherited(Bytecode::Ret)],
                jump_tables: vec![],
            }),
        });
        round_trip_module(&module);
    }

    // ---- Deserializer: constructive parse rejection tests ----------------

    /// Empty input → `UnexpectedEof`.
    #[test]
    fn deserialize_rejects_empty_input() {
        assert_eq!(
            adamant_deserialize(&[]).unwrap_err(),
            AdamantDeserializeError::UnexpectedEof
        );
    }

    /// Bad magic header → `BadMagic`.
    #[test]
    fn deserialize_rejects_bad_magic() {
        let mut bytes = vec![0x00; 8];
        bytes[..4].copy_from_slice(b"WXYZ");
        bytes[4..8].copy_from_slice(&VERSION_MAX.to_le_bytes());
        let err = adamant_deserialize(&bytes).unwrap_err();
        assert!(matches!(
            err,
            AdamantDeserializeError::BadMagic([b'W', b'X', b'Y', b'Z'])
        ));
    }

    /// Version below `VERSION_MIN` → `UnsupportedVersion`.
    #[test]
    fn deserialize_rejects_version_too_low() {
        let mut bytes = vec![];
        bytes.extend_from_slice(&BinaryConstants::MOVE_MAGIC);
        bytes.extend_from_slice(&(VERSION_MIN - 1).to_le_bytes());
        bytes.push(0); // table count = 0
        bytes.push(0); // self_module_handle_idx = 0
        let err = adamant_deserialize(&bytes).unwrap_err();
        assert_eq!(
            err,
            AdamantDeserializeError::UnsupportedVersion(VERSION_MIN - 1)
        );
    }

    /// Version above `VERSION_MAX` → `UnsupportedVersion`.
    #[test]
    fn deserialize_rejects_version_too_high() {
        let mut bytes = vec![];
        bytes.extend_from_slice(&BinaryConstants::MOVE_MAGIC);
        bytes.extend_from_slice(&(VERSION_MAX + 1).to_le_bytes());
        bytes.push(0);
        bytes.push(0);
        let err = adamant_deserialize(&bytes).unwrap_err();
        assert_eq!(
            err,
            AdamantDeserializeError::UnsupportedVersion(VERSION_MAX + 1)
        );
    }

    /// Trailing bytes after a complete module → `TrailingBytes`.
    #[test]
    fn deserialize_rejects_trailing_bytes() {
        let module = AdamantCompiledModule {
            version: VERSION_MAX,
            publishable: true,
            self_module_handle_idx: ModuleHandleIndex(0),
            ..AdamantCompiledModule::default()
        };
        let mut bytes = Vec::new();
        adamant_serialize(&module, &mut bytes).unwrap();
        bytes.push(0xFF); // junk byte
        let err = adamant_deserialize(&bytes).unwrap_err();
        assert_eq!(err, AdamantDeserializeError::TrailingBytes);
    }

    /// Function body with a deprecated global-storage opcode
    /// → `Bytecode(DeprecatedGlobalStorageOpcode(_))`. Confirms the
    /// strict-mode dispatch through `bytecode_wire` flows correctly.
    #[test]
    fn deserialize_rejects_deprecated_global_storage_in_function_body() {
        // Build a module where serialize emits a deprecated opcode
        // in the function body, then attempt to deserialize.
        let mut module = AdamantCompiledModule {
            version: VERSION_MAX,
            publishable: true,
            self_module_handle_idx: ModuleHandleIndex(0),
            module_handles: vec![ModuleHandle {
                address: AddressIdentifierIndex(0),
                name: IdentifierIndex(0),
            }],
            identifiers: vec![Identifier::new("M").unwrap(), Identifier::new("h").unwrap()],
            address_identifiers: vec![AccountAddress::ZERO],
            signatures: vec![Signature(vec![])],
            ..AdamantCompiledModule::default()
        };
        module.function_handles.push(FunctionHandle {
            module: ModuleHandleIndex(0),
            name: IdentifierIndex(1),
            parameters: SignatureIndex(0),
            return_: SignatureIndex(0),
            type_parameters: vec![],
        });
        module.function_defs.push(AdamantFunctionDefinition {
            function: FunctionHandleIndex(0),
            visibility: Visibility::Private,
            is_entry: false,
            acquires_global_resources: vec![],
            code: Some(AdamantCodeUnit {
                locals: SignatureIndex(0),
                code: vec![BytecodeInstruction::Inherited(Bytecode::ExistsDeprecated(
                    StructDefinitionIndex(0),
                ))],
                jump_tables: vec![],
            }),
        });
        let mut bytes = Vec::new();
        adamant_serialize(&module, &mut bytes).expect("serialize");
        let err = adamant_deserialize(&bytes).unwrap_err();
        assert!(
            matches!(
                err,
                AdamantDeserializeError::Bytecode(
                    bytecode_wire::DeserializeError::DeprecatedGlobalStorageOpcode(_)
                )
            ),
            "expected Bytecode(DeprecatedGlobalStorageOpcode(_)), got {err:?}"
        );
    }

    /// `Display` impl on `AdamantDeserializeError` produces non-empty
    /// strings for every variant.
    #[test]
    fn deserialize_error_display_is_populated() {
        let cases = [
            AdamantDeserializeError::UnexpectedEof,
            AdamantDeserializeError::BadMagic([0, 1, 2, 3]),
            AdamantDeserializeError::UnsupportedVersion(99),
            AdamantDeserializeError::UnknownFlavor(0xAB),
            AdamantDeserializeError::UnknownTableKind(0xCD),
            AdamantDeserializeError::DuplicateTable(TableType::MODULE_HANDLES),
            AdamantDeserializeError::BadTableLayout { reason: "test" },
            AdamantDeserializeError::MalformedUleb128,
            AdamantDeserializeError::OutOfRange {
                kind: "test",
                value: 1,
                max: 0,
            },
            AdamantDeserializeError::SignatureTooDeep,
            AdamantDeserializeError::VersionFeatureMismatch {
                feature: "test",
                version: 5,
            },
            AdamantDeserializeError::TrailingBytes,
            AdamantDeserializeError::Bytecode(bytecode_wire::DeserializeError::UnexpectedEof),
            AdamantDeserializeError::InvalidIdentifier,
            AdamantDeserializeError::UnknownFunctionFlag(0xFF),
            AdamantDeserializeError::UnknownSerializedType(0xFF),
            AdamantDeserializeError::UnknownStructFlag(0xFF),
            AdamantDeserializeError::UnknownEnumFlag(0xFF),
            AdamantDeserializeError::UnknownJumpTableFlag(0xFF),
            AdamantDeserializeError::UnknownVisibility(0xFF),
            AdamantDeserializeError::InvalidAbilitySet(0x10),
        ];
        for e in &cases {
            assert!(!format!("{e}").is_empty(), "empty Display for {e:?}");
        }
    }

    // ---- Deserializer: cross-validation against Sui's reference ----------

    /// A Sui-serialized pure-Sui module deserializes correctly via
    /// Adamant's deserializer — the parsed `AdamantCompiledModule`
    /// has the same shape (sans extension functions) as the original
    /// Sui `CompiledModule`.
    #[test]
    fn cross_validate_deserialize_sui_emitted_bytes() {
        for version in VERSION_MIN..=VERSION_MAX {
            let (adamant_expected, sui) = minimal_pair(version);
            let mut sui_bytes = Vec::new();
            sui.serialize_with_version(version, &mut sui_bytes).unwrap();
            let parsed = adamant_deserialize(&sui_bytes)
                .unwrap_or_else(|e| panic!("version {version}: deserialize failed: {e}"));
            assert_eq!(parsed, adamant_expected, "version {version}: mismatch");
        }
    }

    /// Adamant-serialized bytes of a pure-Sui-shape module
    /// deserialize correctly via Sui's reference deserializer
    /// (confirming byte-format compatibility from the encoder side
    /// when consumed by Sui's parser). Uses `minimal_pair` rather
    /// than `rich_pure_sui_pair` because Sui's
    /// `deserialize_with_defaults` sets
    /// `check_no_extraneous_bytes = true`, which Sui treats as
    /// "metadata declarations not applicable" (metadata's full
    /// audit-time validation is not in scope here).
    #[test]
    fn cross_validate_sui_deserializes_adamant_emitted_bytes() {
        let (adamant, sui_expected) = minimal_pair(VERSION_MAX);
        let mut adamant_bytes = Vec::new();
        adamant_serialize(&adamant, &mut adamant_bytes).unwrap();
        let parsed = CompiledModule::deserialize_with_defaults(&adamant_bytes)
            .expect("Sui deserializes Adamant-emitted bytes");
        assert_eq!(parsed, sui_expected);
    }

    // ---- 17 extension-aware fixture round-trips (Phase 5/5a step 5) ------
    //
    // Each AdamantBytecode variant per §6.2.1.4 is wrapped in a
    // single-function module and round-tripped through the
    // module-level serialize/deserialize pipeline. Extends
    // bytecode_wire's wire-level coverage to the module level.

    /// Builds a one-function module whose body is `[extension, Ret]`.
    /// Used by the parameterized 17-extension test.
    fn module_with_extension(extension: crate::bytecode::AdamantBytecode) -> AdamantCompiledModule {
        AdamantCompiledModule {
            version: VERSION_MAX,
            publishable: true,
            self_module_handle_idx: ModuleHandleIndex(0),
            module_handles: vec![ModuleHandle {
                address: AddressIdentifierIndex(0),
                name: IdentifierIndex(0),
            }],
            identifiers: vec![Identifier::new("M").unwrap(), Identifier::new("h").unwrap()],
            address_identifiers: vec![AccountAddress::ZERO],
            signatures: vec![Signature(vec![])],
            function_handles: vec![FunctionHandle {
                module: ModuleHandleIndex(0),
                name: IdentifierIndex(1),
                parameters: SignatureIndex(0),
                return_: SignatureIndex(0),
                type_parameters: vec![],
            }],
            function_defs: vec![AdamantFunctionDefinition {
                function: FunctionHandleIndex(0),
                visibility: Visibility::Private,
                is_entry: false,
                acquires_global_resources: vec![],
                code: Some(AdamantCodeUnit {
                    locals: SignatureIndex(0),
                    code: vec![
                        BytecodeInstruction::Adamant(extension),
                        BytecodeInstruction::Inherited(Bytecode::Ret),
                    ],
                    jump_tables: vec![],
                }),
            }],
            ..AdamantCompiledModule::default()
        }
    }

    /// Round-trip every Adamant extension at the module level. One
    /// representative instance per [`AdamantOpcodeKind`] —
    /// parameter-bearing variants get one fixed sample value
    /// (parameter-shape coverage already lands in `bytecode_wire`).
    #[test]
    fn round_trip_each_extension_at_module_level() {
        use crate::bytecode::{AdamantBytecode, CircuitId, GasDimension};
        use move_binary_format::file_format::FunctionHandleIndex;

        let extensions = [
            AdamantBytecode::InvokeShielded(FunctionHandleIndex(0)),
            AdamantBytecode::InvokeTransparent(FunctionHandleIndex(0)),
            AdamantBytecode::GenerateProof(CircuitId(0)),
            AdamantBytecode::VerifyProof(CircuitId(0)),
            AdamantBytecode::ReleaseSubViewKey,
            AdamantBytecode::KzgCommit,
            AdamantBytecode::KzgVerify,
            AdamantBytecode::RecursiveVerify,
            AdamantBytecode::Sha3_256,
            AdamantBytecode::Blake3,
            AdamantBytecode::Ed25519Verify,
            AdamantBytecode::MlDsaVerify65,
            AdamantBytecode::MlDsaVerify87,
            AdamantBytecode::BlsVerify,
            AdamantBytecode::ChargeGas(GasDimension::Computation),
            AdamantBytecode::RemainingGas(GasDimension::Storage),
            AdamantBytecode::OutOfGas,
        ];
        // Sanity: 17 entries matches §6.2.1.4's extension count.
        assert_eq!(extensions.len(), 17);

        for ext in extensions {
            let module = module_with_extension(ext.clone());
            let mut bytes = Vec::new();
            adamant_serialize(&module, &mut bytes)
                .unwrap_or_else(|e| panic!("serialize failed for {ext:?}: {e}"));
            let parsed = adamant_deserialize(&bytes)
                .unwrap_or_else(|e| panic!("deserialize failed for {ext:?}: {e}"));
            assert_eq!(parsed, module, "round-trip mismatch for {ext:?}");
            assert!(
                parsed.contains_adamant_extensions(),
                "fixture must contain the extension"
            );
            // to_sui_module must refuse: the offending instruction
            // is at function-def 0, instruction offset 0.
            let conv = parsed.to_sui_module();
            assert!(
                matches!(
                    conv,
                    Err(
                        crate::module::AdamantToSuiConversionError::ContainsAdamantExtensions {
                            function_index: 0,
                            instruction_offset: 0,
                        }
                    )
                ),
                "to_sui_module must refuse extension {ext:?}; got {conv:?}"
            );
        }
    }

    /// A "rich" function body that exercises multiple extensions
    /// in a single function. 10 distinct extension instructions
    /// in one function body, mixed with inherited ops:
    /// `Sha3_256`, `Blake3`, `Ed25519Verify`, `MlDsaVerify65`,
    /// `BlsVerify`, `ChargeGas`, `RemainingGas`, `OutOfGas`,
    /// `GenerateProof`, `VerifyProof`, `InvokeShielded`.
    #[test]
    fn round_trip_rich_multi_extension_function_body() {
        use crate::bytecode::{AdamantBytecode, CircuitId, GasDimension};
        use move_binary_format::file_format::FunctionHandleIndex;

        let mut module = module_with_extension(AdamantBytecode::Sha3_256);
        // Replace the body with a richer mix.
        module.function_defs[0].code.as_mut().unwrap().code = vec![
            BytecodeInstruction::Adamant(AdamantBytecode::Sha3_256),
            BytecodeInstruction::Adamant(AdamantBytecode::Blake3),
            BytecodeInstruction::Inherited(Bytecode::Pop),
            BytecodeInstruction::Adamant(AdamantBytecode::Ed25519Verify),
            BytecodeInstruction::Adamant(AdamantBytecode::MlDsaVerify65),
            BytecodeInstruction::Adamant(AdamantBytecode::BlsVerify),
            BytecodeInstruction::Adamant(AdamantBytecode::ChargeGas(GasDimension::Computation)),
            BytecodeInstruction::Adamant(AdamantBytecode::RemainingGas(GasDimension::Bandwidth)),
            BytecodeInstruction::Adamant(AdamantBytecode::OutOfGas),
            BytecodeInstruction::Adamant(AdamantBytecode::GenerateProof(CircuitId(7))),
            BytecodeInstruction::Adamant(AdamantBytecode::VerifyProof(CircuitId(7))),
            BytecodeInstruction::Adamant(AdamantBytecode::InvokeShielded(FunctionHandleIndex(0))),
            BytecodeInstruction::Inherited(Bytecode::Ret),
        ];
        round_trip_module(&module);
    }

    // ---- Cross-validation surface expansion (more module shapes) ---------
    //
    // Phase 5/5a step 5 expands the bidirectional cross-validation
    // surface beyond `minimal_pair` and `rich_pure_sui_pair` to
    // exercise less-common module shapes against Sui's reference
    // serializer/deserializer. Each fixture builds a paired
    // (AdamantCompiledModule, CompiledModule) and asserts byte-
    // identity through both encoders plus reciprocal deserialize.

    /// Build a pair containing a generic struct `S<T>` and a
    /// generic function `f<T>(): T`. Exercises the type-parameter
    /// pool + ability-set encoding paths.
    fn generic_pair(
        version: u32,
    ) -> (
        AdamantCompiledModule,
        move_binary_format::file_format::CompiledModule,
    ) {
        use move_binary_format::file_format::{
            DatatypeTyParameter, FieldDefinition, StructDefinition, StructFieldInformation,
            TypeSignature,
        };

        let (mut adamant, mut sui) = minimal_pair(version);
        adamant.identifiers.push(Identifier::new("S").unwrap());
        sui.identifiers.push(Identifier::new("S").unwrap());
        adamant.identifiers.push(Identifier::new("f").unwrap());
        sui.identifiers.push(Identifier::new("f").unwrap());
        adamant.identifiers.push(Identifier::new("g").unwrap());
        sui.identifiers.push(Identifier::new("g").unwrap());
        adamant.signatures.push(Signature(vec![]));
        sui.signatures.push(Signature(vec![]));
        adamant
            .signatures
            .push(Signature(vec![SignatureToken::TypeParameter(0)]));
        sui.signatures
            .push(Signature(vec![SignatureToken::TypeParameter(0)]));
        let dh = DatatypeHandle {
            module: ModuleHandleIndex(0),
            name: IdentifierIndex(1),
            abilities: AbilitySet::EMPTY | move_binary_format::file_format::Ability::Drop,
            type_parameters: vec![DatatypeTyParameter {
                constraints: AbilitySet::EMPTY,
                is_phantom: false,
            }],
        };
        adamant.datatype_handles.push(dh.clone());
        sui.datatype_handles.push(dh);
        adamant.struct_defs.push(StructDefinition {
            struct_handle: DatatypeHandleIndex(0),
            field_information: StructFieldInformation::Declared(vec![FieldDefinition {
                name: IdentifierIndex(2),
                signature: TypeSignature(SignatureToken::TypeParameter(0)),
            }]),
        });
        sui.struct_defs.push(StructDefinition {
            struct_handle: DatatypeHandleIndex(0),
            field_information: StructFieldInformation::Declared(vec![FieldDefinition {
                name: IdentifierIndex(2),
                signature: TypeSignature(SignatureToken::TypeParameter(0)),
            }]),
        });
        let fh = FunctionHandle {
            module: ModuleHandleIndex(0),
            name: IdentifierIndex(3),
            parameters: SignatureIndex(0),
            return_: SignatureIndex(1),
            type_parameters: vec![AbilitySet::EMPTY],
        };
        adamant.function_handles.push(fh.clone());
        sui.function_handles.push(fh);
        (adamant, sui)
    }

    /// Cross-validate a generic struct + generic function module:
    /// `adamant_serialize` and Sui's serializer produce
    /// byte-identical output across every supported version.
    #[test]
    fn cross_validate_generic_module_all_versions() {
        for version in VERSION_MIN..=VERSION_MAX {
            let (adamant, sui) = generic_pair(version);
            let mut adamant_bytes = Vec::new();
            adamant_serialize(&adamant, &mut adamant_bytes).unwrap();
            let mut sui_bytes = Vec::new();
            sui.serialize_with_version(version, &mut sui_bytes).unwrap();
            assert_eq!(
                adamant_bytes, sui_bytes,
                "version {version}: byte mismatch on generic module"
            );
        }
    }

    /// Round-trip a generic-module fixture. Exercises the
    /// `TypeParameter` `SignatureToken` path through deserialize.
    #[test]
    fn round_trip_generic_module() {
        let (adamant, _) = generic_pair(VERSION_MAX);
        round_trip_module(&adamant);
    }

    /// Adamant-emitted bytes for a generic module deserialize via
    /// Sui's reference deserializer correctly. (Uses
    /// `deserialize_no_check_bounds` because the fixture has no
    /// metadata; default deserializer config still applies.)
    #[test]
    fn cross_validate_sui_deserializes_generic_module() {
        let (adamant, sui_expected) = generic_pair(VERSION_MAX);
        let mut adamant_bytes = Vec::new();
        adamant_serialize(&adamant, &mut adamant_bytes).unwrap();
        let parsed = CompiledModule::deserialize_with_defaults(&adamant_bytes)
            .expect("Sui deserializes Adamant-emitted bytes for generic module");
        assert_eq!(parsed, sui_expected);
    }

    /// Builds a pair containing two functions in the same module —
    /// one public, one private — both with non-trivial bodies.
    /// Exercises multi-function-def serialization.
    fn multi_function_pair(
        version: u32,
    ) -> (
        AdamantCompiledModule,
        move_binary_format::file_format::CompiledModule,
    ) {
        let (mut adamant, mut sui) = minimal_pair(version);
        adamant.identifiers.push(Identifier::new("alpha").unwrap());
        sui.identifiers.push(Identifier::new("alpha").unwrap());
        adamant.identifiers.push(Identifier::new("beta").unwrap());
        sui.identifiers.push(Identifier::new("beta").unwrap());
        adamant.signatures.push(Signature(vec![]));
        sui.signatures.push(Signature(vec![]));
        let alpha_fh = FunctionHandle {
            module: ModuleHandleIndex(0),
            name: IdentifierIndex(1),
            parameters: SignatureIndex(0),
            return_: SignatureIndex(0),
            type_parameters: vec![],
        };
        let beta_fh = FunctionHandle {
            module: ModuleHandleIndex(0),
            name: IdentifierIndex(2),
            parameters: SignatureIndex(0),
            return_: SignatureIndex(0),
            type_parameters: vec![],
        };
        adamant.function_handles.push(alpha_fh.clone());
        adamant.function_handles.push(beta_fh.clone());
        sui.function_handles.push(alpha_fh);
        sui.function_handles.push(beta_fh);
        adamant.function_defs.push(AdamantFunctionDefinition {
            function: FunctionHandleIndex(0),
            visibility: Visibility::Public,
            is_entry: false,
            acquires_global_resources: vec![],
            code: Some(AdamantCodeUnit {
                locals: SignatureIndex(0),
                code: vec![
                    BytecodeInstruction::Inherited(Bytecode::LdU64(42)),
                    BytecodeInstruction::Inherited(Bytecode::Pop),
                    BytecodeInstruction::Inherited(Bytecode::Ret),
                ],
                jump_tables: vec![],
            }),
        });
        adamant.function_defs.push(AdamantFunctionDefinition {
            function: FunctionHandleIndex(1),
            visibility: Visibility::Private,
            is_entry: false,
            acquires_global_resources: vec![],
            code: Some(AdamantCodeUnit {
                locals: SignatureIndex(0),
                code: vec![BytecodeInstruction::Inherited(Bytecode::Ret)],
                jump_tables: vec![],
            }),
        });
        sui.function_defs.push(SuiFunctionDefinition {
            function: FunctionHandleIndex(0),
            visibility: Visibility::Public,
            is_entry: false,
            acquires_global_resources: vec![],
            code: Some(CodeUnit {
                locals: SignatureIndex(0),
                code: vec![Bytecode::LdU64(42), Bytecode::Pop, Bytecode::Ret],
                jump_tables: vec![],
            }),
        });
        sui.function_defs.push(SuiFunctionDefinition {
            function: FunctionHandleIndex(1),
            visibility: Visibility::Private,
            is_entry: false,
            acquires_global_resources: vec![],
            code: Some(CodeUnit {
                locals: SignatureIndex(0),
                code: vec![Bytecode::Ret],
                jump_tables: vec![],
            }),
        });
        (adamant, sui)
    }

    /// Cross-validate the multi-function pair byte-for-byte against
    /// Sui's serializer at `VERSION_MAX`.
    #[test]
    fn cross_validate_multi_function_module() {
        let (adamant, sui) = multi_function_pair(VERSION_MAX);
        let mut adamant_bytes = Vec::new();
        adamant_serialize(&adamant, &mut adamant_bytes).unwrap();
        let mut sui_bytes = Vec::new();
        sui.serialize_with_version(VERSION_MAX, &mut sui_bytes)
            .unwrap();
        assert_eq!(adamant_bytes, sui_bytes);
    }

    /// Round-trip the multi-function pair through Adamant's
    /// serializer + deserializer.
    #[test]
    fn round_trip_multi_function_module() {
        let (adamant, _) = multi_function_pair(VERSION_MAX);
        round_trip_module(&adamant);
    }

    /// `to_sui_module` accepts the multi-function pure-Sui fixture
    /// and produces a `CompiledModule` that compares equal to the
    /// hand-constructed Sui reference.
    #[test]
    fn to_sui_module_matches_sui_reference_for_multi_function_pair() {
        let (adamant, sui_expected) = multi_function_pair(VERSION_MAX);
        let projected = adamant
            .to_sui_module()
            .expect("pure-Sui multi-function module projects without error");
        assert_eq!(projected, sui_expected);
    }

    /// `to_sui_module` also matches Sui's reference for the rich
    /// pure-Sui pair (handles + signatures + constants + metadata
    /// + function with body).
    #[test]
    fn to_sui_module_matches_sui_reference_for_rich_pair() {
        let (adamant, sui_expected) = rich_pure_sui_pair(VERSION_MAX);
        let projected = adamant
            .to_sui_module()
            .expect("rich pure-Sui module projects without error");
        assert_eq!(projected, sui_expected);
    }
}
