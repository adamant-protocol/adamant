//! Constants, tag enums, and byte-stream readers for the Move
//! bytecode binary format.
//!
//! Forked from `move-binary-format/src/file_format_common.rs` at
//! Sui-Move tag `mainnet-v1.66.2`. See `PROVENANCE.md` for the
//! upstream lineage and the enumerated set of items that were and
//! were not forked. Byte-identity with upstream is asserted by
//! `tests/cross_validation.rs`.
//!
//! Adamant deviations from upstream:
//!
//! - Reader functions ([`read_u8`], [`read_u32`],
//!   [`read_uleb128_as_u64`]) return [`Result<T, ReaderError>`]
//!   instead of `anyhow::Result<T>`.
//! - The `BinaryData` struct and the `pub(crate)` `write_*`
//!   helpers from upstream are not forked (Adamant's serializer
//!   uses `Vec<u8>` directly).
//! - `instruction_opcode` and `instruction_key` are deferred to
//!   Phase 5/5b.1b alongside the `Bytecode` enum they operate
//!   over.

use std::io::{Cursor, Read};

use crate::error::ReaderError;

// =============================================================================
// Binary flavor (version-encoding metadata for v >= 7)
// =============================================================================

/// Encoding of the flavor into the version of the binary format
/// for versions >= 7. Forked verbatim from upstream.
pub struct BinaryFlavor;

impl BinaryFlavor {
    /// Mask for the flavor bits in the flavored version.
    pub const FLAVOR_MASK: u32 = 0xFF00_0000;
    /// Mask for the version bits in the flavored version.
    pub const VERSION_MASK: u32 = 0x00FF_FFFF;
    /// Adamant inherits the Sui flavor (`0x05`) per whitepaper
    /// §6.2.1.2's "binary format inherits Sui's" framing.
    pub const SUI_FLAVOR: u8 = 0x05;
    const SHIFT_AMOUNT: u8 = 24;

    /// Encode an unflavored version (1..=6) or a flavored version
    /// (7+) into a `u32`. For versions <= 6, the encoding is the
    /// version itself; for v >= 7, the [`Self::SUI_FLAVOR`] byte
    /// is shifted into the high byte.
    #[must_use]
    pub fn encode_version(unflavored_version: u32) -> u32 {
        if unflavored_version <= VERSION_6 {
            return unflavored_version;
        }

        debug_assert!(unflavored_version & Self::VERSION_MASK == unflavored_version);
        Self::shift_and_flavor(unflavored_version)
    }

    /// Decode the unflavored version (low 24 bits for v >= 7;
    /// the value itself for v <= 6).
    #[must_use]
    pub fn decode_version(flavored_version: u32) -> u32 {
        if flavored_version <= VERSION_6 {
            return flavored_version;
        }
        flavored_version & Self::VERSION_MASK
    }

    /// Decode the flavor byte for v >= 7; returns `None` for v <= 6
    /// (no flavor byte was emitted at those versions).
    #[must_use]
    pub fn decode_flavor(flavored_version: u32) -> Option<u8> {
        if flavored_version <= VERSION_6 {
            return None;
        }
        Some(Self::mask_and_shift_to_unflavor(flavored_version))
    }

    const fn mask_and_shift_to_unflavor(flavored: u32) -> u8 {
        // Cast safety: `(flavored & FLAVOR_MASK) >> SHIFT_AMOUNT`
        // produces a value in `0..=255`, fits `u8`.
        #[allow(clippy::cast_possible_truncation)]
        let byte = ((flavored & Self::FLAVOR_MASK) >> Self::SHIFT_AMOUNT) as u8;
        byte
    }

    const fn shift_and_flavor(unflavored: u32) -> u32 {
        ((Self::SUI_FLAVOR as u32) << Self::SHIFT_AMOUNT) | unflavored
    }
}

// Static assertions about the encoding of the flavor into the
// version of the binary format. Forked from upstream.
const _: () = {
    let x = BinaryFlavor::shift_and_flavor(0u32);
    // Make sure that the flavoring is added in the correct
    // position in the u32. It should always be `0x05XX_XXXX`
    // where `XX_XXXX` is the version digits.
    assert!(x == 0x0500_0000u32);
    // Make sure that the flavoring is extracted correctly.
    assert!(BinaryFlavor::mask_and_shift_to_unflavor(x) == BinaryFlavor::SUI_FLAVOR);
};

// =============================================================================
// Magic header constants
// =============================================================================

/// Constant values for the binary format header.
///
/// The binary header is magic + version info + table count.
pub enum BinaryConstants {}
impl BinaryConstants {
    /// Length in bytes of the magic prefix.
    pub const MOVE_MAGIC_SIZE: usize = 4;
    /// Magic bytes that begin a publishable Move module.
    pub const MOVE_MAGIC: [u8; BinaryConstants::MOVE_MAGIC_SIZE] = [0xA1, 0x1C, 0xEB, 0x0B];
    /// Magic bytes that begin a non-publishable (test/debug) Move
    /// module. Used by Sui's test harnesses to mark modules that
    /// must not flow through the deploy path.
    pub const UNPUBLISHABLE_MAGIC: [u8; BinaryConstants::MOVE_MAGIC_SIZE] =
        [0xDE, 0xAD, 0xC0, 0xDE];
    /// Total header size (magic + 4 bytes flavored version + 1
    /// byte table count).
    pub const HEADER_SIZE: usize = BinaryConstants::MOVE_MAGIC_SIZE + 5;
    /// Size of one ([`TableType`], offset, count) triple in the
    /// table-index block: 1 byte tag + 4 bytes offset + 4 bytes
    /// count.
    // Cast safety: `size_of::<u32>() == 4` is far below `u8::MAX`;
    // `4 * 2 + 1 = 9` fits trivially.
    #[allow(clippy::cast_possible_truncation)]
    pub const TABLE_HEADER_SIZE: u8 = size_of::<u32>() as u8 * 2 + 1;

    /// Decode a candidate magic header into a [`MagicKind`] or a
    /// [`MagicError`] indicating which decoding step failed.
    ///
    /// # Errors
    ///
    /// - [`MagicError::BadSize`] if `count` is not
    ///   [`Self::MOVE_MAGIC_SIZE`].
    /// - [`MagicError::BadNumber`] if the bytes match neither
    ///   [`Self::MOVE_MAGIC`] nor [`Self::UNPUBLISHABLE_MAGIC`].
    pub fn decode_magic(magic: [u8; 4], count: usize) -> Result<MagicKind, MagicError> {
        if count != BinaryConstants::MOVE_MAGIC_SIZE {
            return Err(MagicError::BadSize);
        }
        match magic {
            BinaryConstants::MOVE_MAGIC => Ok(MagicKind::Normal),
            BinaryConstants::UNPUBLISHABLE_MAGIC => Ok(MagicKind::Unpublishable),
            _ => Err(MagicError::BadNumber),
        }
    }
}

/// Outcome of a successful magic-header decode.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub enum MagicKind {
    /// Module begins with [`BinaryConstants::MOVE_MAGIC`].
    Normal,
    /// Module begins with [`BinaryConstants::UNPUBLISHABLE_MAGIC`].
    Unpublishable,
}

/// Outcome of a failed magic-header decode.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub enum MagicError {
    /// The byte count passed to [`BinaryConstants::decode_magic`]
    /// is not [`BinaryConstants::MOVE_MAGIC_SIZE`].
    BadSize,
    /// The 4-byte sequence matches neither
    /// [`BinaryConstants::MOVE_MAGIC`] nor
    /// [`BinaryConstants::UNPUBLISHABLE_MAGIC`].
    BadNumber,
}

// =============================================================================
// Pool/index/size limit constants
// =============================================================================

/// Maximum number of distinct table kinds in a module's
/// table-index block. The limit is 255 because the count is
/// emitted as a single byte.
pub const TABLE_COUNT_MAX: u64 = 255;

/// Upper bound on a table's byte offset within the module bytes.
pub const TABLE_OFFSET_MAX: u64 = 0xffff_ffff;
/// Upper bound on a table's byte length within the module bytes.
pub const TABLE_SIZE_MAX: u64 = 0xffff_ffff;
/// Upper bound on aggregate table content size.
pub const TABLE_CONTENT_SIZE_MAX: u64 = 0xffff_ffff;

/// Generic upper bound on any pool index (handles, signatures,
/// identifiers, addresses, etc.). All `*_INDEX_MAX` constants
/// below alias this value, which means the index is encoded as a
/// 16-bit ULEB128.
pub const TABLE_INDEX_MAX: u64 = 65535;
/// Upper bound on `SignatureIndex`.
pub const SIGNATURE_INDEX_MAX: u64 = TABLE_INDEX_MAX;
/// Upper bound on `AddressIdentifierIndex`.
pub const ADDRESS_INDEX_MAX: u64 = TABLE_INDEX_MAX;
/// Upper bound on `IdentifierIndex`.
pub const IDENTIFIER_INDEX_MAX: u64 = TABLE_INDEX_MAX;
/// Upper bound on `ModuleHandleIndex`.
pub const MODULE_HANDLE_INDEX_MAX: u64 = TABLE_INDEX_MAX;
/// Upper bound on `DatatypeHandleIndex`.
pub const DATATYPE_HANDLE_INDEX_MAX: u64 = TABLE_INDEX_MAX;
/// Upper bound on `StructDefinitionIndex`.
pub const STRUCT_DEF_INDEX_MAX: u64 = TABLE_INDEX_MAX;
/// Upper bound on `EnumDefinitionIndex`.
pub const ENUM_DEF_INDEX_MAX: u64 = TABLE_INDEX_MAX;
/// Upper bound on `FunctionHandleIndex`.
pub const FUNCTION_HANDLE_INDEX_MAX: u64 = TABLE_INDEX_MAX;
/// Upper bound on `FunctionInstantiationIndex`.
pub const FUNCTION_INST_INDEX_MAX: u64 = TABLE_INDEX_MAX;
/// Upper bound on `FieldHandleIndex`.
pub const FIELD_HANDLE_INDEX_MAX: u64 = TABLE_INDEX_MAX;
/// Upper bound on `FieldInstantiationIndex`.
pub const FIELD_INST_INDEX_MAX: u64 = TABLE_INDEX_MAX;
/// Upper bound on `StructDefInstantiationIndex`.
pub const STRUCT_DEF_INST_INDEX_MAX: u64 = TABLE_INDEX_MAX;
/// Upper bound on `EnumDefInstantiationIndex`.
pub const ENUM_DEF_INST_INDEX_MAX: u64 = TABLE_INDEX_MAX;
/// Upper bound on `ConstantPoolIndex`.
pub const CONSTANT_INDEX_MAX: u64 = TABLE_INDEX_MAX;

/// Upper bound on the per-function bytecode-instruction count.
pub const BYTECODE_COUNT_MAX: u64 = 65535;
/// Upper bound on a positional offset within a function body.
pub const BYTECODE_INDEX_MAX: u64 = 65535;

/// Upper bound on a function's local-variable index (1 byte).
pub const LOCAL_INDEX_MAX: u64 = 255;

/// Upper bound on an identifier's byte length.
pub const IDENTIFIER_SIZE_MAX: u64 = 65535;

/// Upper bound on a constant's data byte length.
pub const CONSTANT_SIZE_MAX: u64 = 65535;

/// Upper bound on a metadata key's byte length.
pub const METADATA_KEY_SIZE_MAX: u64 = 1023;
/// Upper bound on a metadata value's byte length.
pub const METADATA_VALUE_SIZE_MAX: u64 = 65535;

/// Upper bound on a signature's token count.
pub const SIGNATURE_SIZE_MAX: u64 = 255;

/// Upper bound on a function's `acquires` list length.
pub const ACQUIRES_COUNT_MAX: u64 = 255;

/// Upper bound on a struct's field count.
pub const FIELD_COUNT_MAX: u64 = 255;
/// Upper bound on a field's positional offset within its struct.
pub const FIELD_OFFSET_MAX: u64 = 255;

// Variant count is shared with `move_core_types::VARIANT_COUNT_MAX`;
// upstream forwards the value via a const-block assertion. Adamant
// pins the value directly here (matching upstream's value at
// `mainnet-v1.66.2`); the cross-validation tests assert agreement.
/// Upper bound on an enum's variant count. Pinned at 127.
pub const VARIANT_COUNT_MAX: u64 = 127;

/// Upper bound on a variant tag value (one less than
/// [`VARIANT_COUNT_MAX`]).
pub const VARIANT_TAG_MAX_VALUE: u64 = VARIANT_COUNT_MAX - 1;

/// Upper bound on a variant jump-table index. Pinned at the same
/// value as [`VARIANT_COUNT_MAX`] (127).
pub const JUMP_TABLE_INDEX_MAX: u64 = VARIANT_COUNT_MAX;

/// Upper bound on `VariantInstantiationHandleIndex`.
pub const VARIANT_INSTANTIATION_HANDLE_INDEX_MAX: u64 = 1024;
/// Upper bound on `VariantHandleIndex`.
pub const VARIANT_HANDLE_INDEX_MAX: u64 = 1024;

/// Upper bound on a generic's type-parameter count.
pub const TYPE_PARAMETER_COUNT_MAX: u64 = 255;
/// Upper bound on a `TypeParameter` signature-token operand.
pub const TYPE_PARAMETER_INDEX_MAX: u64 = 65536;

/// Upper bound on the nesting depth of a `SignatureToken` chain.
/// The verifier's iterative-stack parser uses this as the
/// stack-depth ceiling.
pub const SIGNATURE_TOKEN_DEPTH_MAX: usize = 256;

/// Upper limit on the binary size.
pub const BINARY_SIZE_LIMIT: usize = usize::MAX;

// =============================================================================
// Tag enums (1-byte discriminants)
// =============================================================================

/// Constants for table types in the binary.
///
/// The binary contains a subset of those tables. A table
/// specification is a tuple `(table type, start offset, byte
/// count)` for a given table.
#[rustfmt::skip]
#[allow(non_camel_case_types)]
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum TableType {
    #[allow(missing_docs)] MODULE_HANDLES        = 0x1,
    #[allow(missing_docs)] DATATYPE_HANDLES      = 0x2,
    #[allow(missing_docs)] FUNCTION_HANDLES      = 0x3,
    #[allow(missing_docs)] FUNCTION_INST         = 0x4,
    #[allow(missing_docs)] SIGNATURES            = 0x5,
    #[allow(missing_docs)] CONSTANT_POOL         = 0x6,
    #[allow(missing_docs)] IDENTIFIERS           = 0x7,
    #[allow(missing_docs)] ADDRESS_IDENTIFIERS   = 0x8,
    #[allow(missing_docs)] STRUCT_DEFS           = 0xA,
    #[allow(missing_docs)] STRUCT_DEF_INST       = 0xB,
    #[allow(missing_docs)] FUNCTION_DEFS         = 0xC,
    #[allow(missing_docs)] FIELD_HANDLE          = 0xD,
    #[allow(missing_docs)] FIELD_INST            = 0xE,
    #[allow(missing_docs)] FRIEND_DECLS          = 0xF,
    #[allow(missing_docs)] METADATA              = 0x10,
    #[allow(missing_docs)] ENUM_DEFS             = 0x11,
    #[allow(missing_docs)] ENUM_DEF_INST         = 0x12,
    #[allow(missing_docs)] VARIANT_HANDLES       = 0x13,
    #[allow(missing_docs)] VARIANT_INST_HANDLES  = 0x14,
}

/// Constants for signature blob values (the byte tag prefixed to
/// each `SignatureToken` in the on-wire form).
#[rustfmt::skip]
#[allow(non_camel_case_types)]
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SerializedType {
    #[allow(missing_docs)] BOOL                    = 0x1,
    #[allow(missing_docs)] U8                      = 0x2,
    #[allow(missing_docs)] U64                     = 0x3,
    #[allow(missing_docs)] U128                    = 0x4,
    #[allow(missing_docs)] ADDRESS                 = 0x5,
    #[allow(missing_docs)] REFERENCE               = 0x6,
    #[allow(missing_docs)] MUTABLE_REFERENCE       = 0x7,
    #[allow(missing_docs)] STRUCT                  = 0x8,
    #[allow(missing_docs)] TYPE_PARAMETER          = 0x9,
    #[allow(missing_docs)] VECTOR                  = 0xA,
    #[allow(missing_docs)] DATATYPE_INST           = 0xB,
    #[allow(missing_docs)] SIGNER                  = 0xC,
    #[allow(missing_docs)] U16                     = 0xD,
    #[allow(missing_docs)] U32                     = 0xE,
    #[allow(missing_docs)] U256                    = 0xF,
}

/// Flag byte distinguishing native struct definitions from
/// declared (field-bearing) ones.
#[rustfmt::skip]
#[allow(non_camel_case_types)]
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SerializedNativeStructFlag {
    #[allow(missing_docs)] NATIVE   = 0x1,
    #[allow(missing_docs)] DECLARED = 0x2,
}

/// Flag byte for enum definitions. Only `DECLARED` is currently
/// emitted; `0x1` is reserved for a future native variant.
#[rustfmt::skip]
#[allow(non_camel_case_types)]
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SerializedEnumFlag {
    #[allow(missing_docs)] DECLARED = 0x2,
}

/// Flag byte for variant jump tables. Only `FULL` is currently
/// emitted (full table; one offset per variant tag).
#[rustfmt::skip]
#[allow(non_camel_case_types)]
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SerializedJumpTableFlag {
    #[allow(missing_docs)] FULL = 0x1,
}

/// List of opcode constants for the inherited Sui-Move
/// instruction set. Adamant's extension opcodes occupy the
/// `0x80..=0x90` range and are defined in `adamant-vm`'s
/// `bytecode` module per whitepaper §6.2.1.4.
#[rustfmt::skip]
#[allow(non_camel_case_types, missing_docs)]
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Opcodes {
    POP                            = 0x01,
    RET                            = 0x02,
    BR_TRUE                        = 0x03,
    BR_FALSE                       = 0x04,
    BRANCH                         = 0x05,
    LD_U64                         = 0x06,
    LD_CONST                       = 0x07,
    LD_TRUE                        = 0x08,
    LD_FALSE                       = 0x09,
    COPY_LOC                       = 0x0A,
    MOVE_LOC                       = 0x0B,
    ST_LOC                         = 0x0C,
    MUT_BORROW_LOC                 = 0x0D,
    IMM_BORROW_LOC                 = 0x0E,
    MUT_BORROW_FIELD               = 0x0F,
    IMM_BORROW_FIELD               = 0x10,
    CALL                           = 0x11,
    PACK                           = 0x12,
    UNPACK                         = 0x13,
    READ_REF                       = 0x14,
    WRITE_REF                      = 0x15,
    ADD                            = 0x16,
    SUB                            = 0x17,
    MUL                            = 0x18,
    MOD                            = 0x19,
    DIV                            = 0x1A,
    BIT_OR                         = 0x1B,
    BIT_AND                        = 0x1C,
    XOR                            = 0x1D,
    OR                             = 0x1E,
    AND                            = 0x1F,
    NOT                            = 0x20,
    EQ                             = 0x21,
    NEQ                            = 0x22,
    LT                             = 0x23,
    GT                             = 0x24,
    LE                             = 0x25,
    GE                             = 0x26,
    ABORT                          = 0x27,
    NOP                            = 0x28,
    // gap for deprecated bytecodes, see bottom of enum
    FREEZE_REF                     = 0x2E,
    SHL                            = 0x2F,
    SHR                            = 0x30,
    LD_U8                          = 0x31,
    LD_U128                        = 0x32,
    CAST_U8                        = 0x33,
    CAST_U64                       = 0x34,
    CAST_U128                      = 0x35,
    MUT_BORROW_FIELD_GENERIC       = 0x36,
    IMM_BORROW_FIELD_GENERIC       = 0x37,
    CALL_GENERIC                   = 0x38,
    PACK_GENERIC                   = 0x39,
    UNPACK_GENERIC                 = 0x3A,
    VEC_PACK                       = 0x40,
    VEC_LEN                        = 0x41,
    VEC_IMM_BORROW                 = 0x42,
    VEC_MUT_BORROW                 = 0x43,
    VEC_PUSH_BACK                  = 0x44,
    VEC_POP_BACK                   = 0x45,
    VEC_UNPACK                     = 0x46,
    VEC_SWAP                       = 0x47,
    LD_U16                         = 0x48,
    LD_U32                         = 0x49,
    LD_U256                        = 0x4A,
    CAST_U16                       = 0x4B,
    CAST_U32                       = 0x4C,
    CAST_U256                      = 0x4D,
    PACK_VARIANT                   = 0x4E,
    PACK_VARIANT_GENERIC           = 0x4F,
    UNPACK_VARIANT                 = 0x50,
    UNPACK_VARIANT_IMM_REF         = 0x51,
    UNPACK_VARIANT_MUT_REF         = 0x52,
    UNPACK_VARIANT_GENERIC         = 0x53,
    UNPACK_VARIANT_GENERIC_IMM_REF = 0x54,
    UNPACK_VARIANT_GENERIC_MUT_REF = 0x55,
    VARIANT_SWITCH                 = 0x56,

    // ******** DEPRECATED BYTECODES ********
    // global storage opcodes are unused and deprecated; rejected
    // at parse time per whitepaper §6.2.1.6 Rule 5.
    EXISTS_DEPRECATED                       = 0x29,
    MUT_BORROW_GLOBAL_DEPRECATED            = 0x2A,
    IMM_BORROW_GLOBAL_DEPRECATED            = 0x2B,
    MOVE_FROM_DEPRECATED                    = 0x2C,
    MOVE_TO_DEPRECATED                      = 0x2D,
    EXISTS_GENERIC_DEPRECATED               = 0x3B,
    MUT_BORROW_GLOBAL_GENERIC_DEPRECATED    = 0x3C,
    IMM_BORROW_GLOBAL_GENERIC_DEPRECATED    = 0x3D,
    MOVE_FROM_GENERIC_DEPRECATED            = 0x3E,
    MOVE_TO_GENERIC_DEPRECATED              = 0x3F,
}

// =============================================================================
// Byte-stream readers
// =============================================================================

/// Read a single byte from `cursor`. Returns
/// [`ReaderError::UnexpectedEof`] if the cursor is at end-of-stream.
///
/// # Errors
///
/// [`ReaderError::UnexpectedEof`] if `cursor` is exhausted.
pub fn read_u8(cursor: &mut Cursor<&[u8]>) -> Result<u8, ReaderError> {
    let mut buf = [0; 1];
    cursor
        .read_exact(&mut buf)
        .map_err(|_| ReaderError::UnexpectedEof)?;
    Ok(buf[0])
}

/// Read a 4-byte little-endian `u32` from `cursor`.
///
/// # Errors
///
/// [`ReaderError::UnexpectedEof`] if fewer than 4 bytes remain.
pub fn read_u32(cursor: &mut Cursor<&[u8]>) -> Result<u32, ReaderError> {
    let mut buf = [0; 4];
    cursor
        .read_exact(&mut buf)
        .map_err(|_| ReaderError::UnexpectedEof)?;
    Ok(u32::from_le_bytes(buf))
}

/// Read a ULEB128-encoded value from `cursor` and return it as a
/// `u64`. Mirrors upstream's accept/reject set; differs from
/// upstream only in the typed error classification (upstream's
/// `anyhow::Error` lumps EOF and malformed together).
///
/// # Errors
///
/// [`ReaderError::UnexpectedEof`] if `cursor` is empty (no bytes
/// consumed before EOF). [`ReaderError::MalformedUleb128`] for
/// every other failure: truncated mid-sequence, overflow past
/// `u64`, or non-canonical zero-padding past the terminator.
pub fn read_uleb128_as_u64(cursor: &mut Cursor<&[u8]>) -> Result<u64, ReaderError> {
    let mut value: u64 = 0;
    let mut shift = 0u32;
    let mut consumed_any = false;
    while let Ok(byte) = read_u8(cursor) {
        consumed_any = true;
        let cur = u64::from(byte & 0x7f);
        if (cur << shift) >> shift != cur {
            return Err(ReaderError::MalformedUleb128);
        }
        value |= cur << shift;

        if (byte & 0x80) == 0 {
            if shift > 0 && cur == 0 {
                return Err(ReaderError::MalformedUleb128);
            }
            return Ok(value);
        }

        shift += 7;
        if shift > u64::BITS {
            break;
        }
    }
    if consumed_any {
        Err(ReaderError::MalformedUleb128)
    } else {
        Err(ReaderError::UnexpectedEof)
    }
}

// =============================================================================
// Bytecode-format version constants
// =============================================================================

/// Version 1: the initial version.
pub const VERSION_1: u32 = 1;

/// Version 2: changes compared with version 1
///  + function visibility stored in separate byte before the flags byte
///  + the flags byte now contains only the `is_native` information (at bit 0x2)
///  + new visibility modifiers for "friend" and "script" functions
///  + friend list for modules
pub const VERSION_2: u32 = 2;

/// Version 3: changes compared with version 2
///  + phantom type parameters
pub const VERSION_3: u32 = 3;

/// Version 4: changes compared with version 3
///  + bytecode for vector operations
pub const VERSION_4: u32 = 4;

/// Version 5: changes compared with version 4
///  +/- script and public(script) verification is now adapter specific
///  + metadata
pub const VERSION_5: u32 = 5;

/// Version 6: changes compared with version 5
///  + u16, u32, u256 integers and corresponding Ld, Cast bytecodes
pub const VERSION_6: u32 = 6;

/// Version 7: changes compared with version 6
///  + enums
pub const VERSION_7: u32 = 7;

/// The latest supported bytecode-format version (currently 7).
pub const VERSION_MAX: u32 = VERSION_7;

/// The oldest supported bytecode-format version (currently 5).
pub const VERSION_MIN: u32 = VERSION_5;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn magic_bytes_match_spec() {
        assert_eq!(BinaryConstants::MOVE_MAGIC, [0xA1, 0x1C, 0xEB, 0x0B]);
        assert_eq!(
            BinaryConstants::UNPUBLISHABLE_MAGIC,
            [0xDE, 0xAD, 0xC0, 0xDE]
        );
    }

    #[test]
    fn binary_flavor_round_trips_versions() {
        for v in [VERSION_1, VERSION_2, VERSION_5, VERSION_6, VERSION_7] {
            let encoded = BinaryFlavor::encode_version(v);
            let decoded = BinaryFlavor::decode_version(encoded);
            assert_eq!(decoded, v);
        }
    }

    #[test]
    fn binary_flavor_decode_flavor_returns_none_for_pre_v7() {
        assert_eq!(BinaryFlavor::decode_flavor(VERSION_5), None);
        assert_eq!(BinaryFlavor::decode_flavor(VERSION_6), None);
    }

    #[test]
    fn binary_flavor_decode_flavor_returns_sui_for_v7_plus() {
        let encoded = BinaryFlavor::encode_version(VERSION_7);
        assert_eq!(
            BinaryFlavor::decode_flavor(encoded),
            Some(BinaryFlavor::SUI_FLAVOR)
        );
    }

    #[test]
    fn decode_magic_recognises_move_magic() {
        assert_eq!(
            BinaryConstants::decode_magic(BinaryConstants::MOVE_MAGIC, 4),
            Ok(MagicKind::Normal)
        );
    }

    #[test]
    fn decode_magic_recognises_unpublishable_magic() {
        assert_eq!(
            BinaryConstants::decode_magic(BinaryConstants::UNPUBLISHABLE_MAGIC, 4),
            Ok(MagicKind::Unpublishable)
        );
    }

    #[test]
    fn decode_magic_rejects_wrong_size() {
        assert_eq!(
            BinaryConstants::decode_magic([0; 4], 3),
            Err(MagicError::BadSize)
        );
    }

    #[test]
    fn decode_magic_rejects_unknown_bytes() {
        assert_eq!(
            BinaryConstants::decode_magic([0xFF, 0xFF, 0xFF, 0xFF], 4),
            Err(MagicError::BadNumber)
        );
    }

    #[test]
    fn pool_index_constants_pin_table_index_max() {
        assert_eq!(TABLE_INDEX_MAX, 65535);
        assert_eq!(SIGNATURE_INDEX_MAX, TABLE_INDEX_MAX);
        assert_eq!(MODULE_HANDLE_INDEX_MAX, TABLE_INDEX_MAX);
        assert_eq!(DATATYPE_HANDLE_INDEX_MAX, TABLE_INDEX_MAX);
        assert_eq!(STRUCT_DEF_INDEX_MAX, TABLE_INDEX_MAX);
        assert_eq!(ENUM_DEF_INDEX_MAX, TABLE_INDEX_MAX);
        assert_eq!(FUNCTION_HANDLE_INDEX_MAX, TABLE_INDEX_MAX);
    }

    #[test]
    fn version_bounds_pinned() {
        assert_eq!(VERSION_MIN, 5);
        assert_eq!(VERSION_MAX, 7);
    }

    #[test]
    fn signature_token_depth_max_pinned_at_256() {
        assert_eq!(SIGNATURE_TOKEN_DEPTH_MAX, 256);
    }

    #[test]
    fn variant_count_max_pinned_at_127() {
        assert_eq!(VARIANT_COUNT_MAX, 127);
        assert_eq!(VARIANT_TAG_MAX_VALUE, 126);
        assert_eq!(JUMP_TABLE_INDEX_MAX, 127);
    }

    #[test]
    fn table_type_discriminants_pinned() {
        assert_eq!(TableType::MODULE_HANDLES as u8, 0x1);
        assert_eq!(TableType::DATATYPE_HANDLES as u8, 0x2);
        assert_eq!(TableType::FUNCTION_HANDLES as u8, 0x3);
        assert_eq!(TableType::FUNCTION_INST as u8, 0x4);
        assert_eq!(TableType::SIGNATURES as u8, 0x5);
        assert_eq!(TableType::CONSTANT_POOL as u8, 0x6);
        assert_eq!(TableType::IDENTIFIERS as u8, 0x7);
        assert_eq!(TableType::ADDRESS_IDENTIFIERS as u8, 0x8);
        assert_eq!(TableType::STRUCT_DEFS as u8, 0xA);
        assert_eq!(TableType::FUNCTION_DEFS as u8, 0xC);
        assert_eq!(TableType::METADATA as u8, 0x10);
        assert_eq!(TableType::ENUM_DEFS as u8, 0x11);
        assert_eq!(TableType::VARIANT_INST_HANDLES as u8, 0x14);
    }

    #[test]
    fn serialized_type_discriminants_pinned() {
        assert_eq!(SerializedType::BOOL as u8, 0x1);
        assert_eq!(SerializedType::U8 as u8, 0x2);
        assert_eq!(SerializedType::U64 as u8, 0x3);
        assert_eq!(SerializedType::U256 as u8, 0xF);
    }

    #[test]
    fn opcode_discriminants_pinned() {
        assert_eq!(Opcodes::POP as u8, 0x01);
        assert_eq!(Opcodes::RET as u8, 0x02);
        assert_eq!(Opcodes::NOP as u8, 0x28);
        assert_eq!(Opcodes::EXISTS_DEPRECATED as u8, 0x29);
        assert_eq!(Opcodes::VARIANT_SWITCH as u8, 0x56);
    }

    #[test]
    fn read_u8_returns_byte() {
        let bytes = [0x42u8];
        let mut c = Cursor::new(&bytes[..]);
        assert_eq!(read_u8(&mut c), Ok(0x42));
    }

    #[test]
    fn read_u8_eof() {
        let bytes: [u8; 0] = [];
        let mut c = Cursor::new(&bytes[..]);
        assert_eq!(read_u8(&mut c), Err(ReaderError::UnexpectedEof));
    }

    #[test]
    fn read_u32_returns_le() {
        let bytes = 0x1234_5678u32.to_le_bytes();
        let mut c = Cursor::new(&bytes[..]);
        assert_eq!(read_u32(&mut c), Ok(0x1234_5678));
    }

    #[test]
    fn read_u32_eof() {
        let bytes = [0u8; 3];
        let mut c = Cursor::new(&bytes[..]);
        assert_eq!(read_u32(&mut c), Err(ReaderError::UnexpectedEof));
    }

    #[test]
    fn read_uleb128_zero() {
        let bytes = [0x00u8];
        let mut c = Cursor::new(&bytes[..]);
        assert_eq!(read_uleb128_as_u64(&mut c), Ok(0));
    }

    #[test]
    fn read_uleb128_small_values() {
        for v in [0u64, 1, 0x7F] {
            // Encode by hand: single-byte ULEB128 for values < 128.
            // Cast safety: v < 128 fits u8.
            #[allow(clippy::cast_possible_truncation)]
            let bytes = [v as u8];
            let mut c = Cursor::new(&bytes[..]);
            assert_eq!(read_uleb128_as_u64(&mut c), Ok(v));
        }
    }

    #[test]
    fn read_uleb128_two_byte_value() {
        // ULEB128(0x80) = [0x80, 0x01]
        let bytes = [0x80, 0x01u8];
        let mut c = Cursor::new(&bytes[..]);
        assert_eq!(read_uleb128_as_u64(&mut c), Ok(0x80));
    }

    #[test]
    fn read_uleb128_max_u64() {
        // u64::MAX as ULEB128: ten bytes
        let bytes = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01];
        let mut c = Cursor::new(&bytes[..]);
        assert_eq!(read_uleb128_as_u64(&mut c), Ok(u64::MAX));
    }

    #[test]
    fn read_uleb128_eof_mid_sequence() {
        // Continuation bit set, but stream ends
        let bytes = [0x80u8];
        let mut c = Cursor::new(&bytes[..]);
        assert_eq!(
            read_uleb128_as_u64(&mut c),
            Err(ReaderError::MalformedUleb128)
        );
    }

    #[test]
    fn read_uleb128_overflow() {
        // 11 bytes of 0xFF — overflow past u64
        let bytes = [0xFFu8; 11];
        let mut c = Cursor::new(&bytes[..]);
        assert_eq!(
            read_uleb128_as_u64(&mut c),
            Err(ReaderError::MalformedUleb128)
        );
    }

    #[test]
    fn read_uleb128_non_canonical_zero_padding() {
        // [0x80, 0x00] would decode to 0 but is non-canonical
        // (canonical encoding of 0 is the single byte 0x00).
        let bytes = [0x80u8, 0x00];
        let mut c = Cursor::new(&bytes[..]);
        assert_eq!(
            read_uleb128_as_u64(&mut c),
            Err(ReaderError::MalformedUleb128)
        );
    }
}
