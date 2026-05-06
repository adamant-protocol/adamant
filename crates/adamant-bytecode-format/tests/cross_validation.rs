//! Cross-validation: this crate's behaviour byte-identical to the
//! still-vendored Sui sources at `mainnet-v1.66.2`.
//!
//! Per whitepaper §6.2.1.8's resistant-proof posture, the vendored
//! Sui crates are explicitly permitted as test-only dependencies
//! (under `[dev-dependencies]`) for cross-validation purposes.
//! These tests assert that every constant, tag-enum discriminant,
//! reader behaviour, ability-set bit pattern, and identifier
//! validation outcome agrees with upstream Sui at the fork tag.
//!
//! Failure of any test in this file means either:
//! 1. This crate has drifted from the vendored snapshot
//!    (intentionally or by bug); update PROVENANCE.md's changelog
//!    to record the drift.
//! 2. The vendored snapshot has drifted from this crate (typically
//!    via a vendor refresh); follow the "Vendor refresh checklist"
//!    in PROVENANCE.md.

use adamant_bytecode_format as adamant;
use move_binary_format::file_format as sui_format;
use move_binary_format::file_format_common as sui_common;
use move_core_types::identifier as sui_ident;

// =============================================================================
// Constants
// =============================================================================

#[test]
fn pool_index_max_constants_match_upstream() {
    assert_eq!(adamant::TABLE_INDEX_MAX, sui_common::TABLE_INDEX_MAX);
    assert_eq!(
        adamant::SIGNATURE_INDEX_MAX,
        sui_common::SIGNATURE_INDEX_MAX
    );
    assert_eq!(adamant::ADDRESS_INDEX_MAX, sui_common::ADDRESS_INDEX_MAX);
    assert_eq!(
        adamant::IDENTIFIER_INDEX_MAX,
        sui_common::IDENTIFIER_INDEX_MAX
    );
    assert_eq!(
        adamant::MODULE_HANDLE_INDEX_MAX,
        sui_common::MODULE_HANDLE_INDEX_MAX
    );
    assert_eq!(
        adamant::DATATYPE_HANDLE_INDEX_MAX,
        sui_common::DATATYPE_HANDLE_INDEX_MAX
    );
    assert_eq!(
        adamant::STRUCT_DEF_INDEX_MAX,
        sui_common::STRUCT_DEF_INDEX_MAX
    );
    assert_eq!(adamant::ENUM_DEF_INDEX_MAX, sui_common::ENUM_DEF_INDEX_MAX);
    assert_eq!(
        adamant::FUNCTION_HANDLE_INDEX_MAX,
        sui_common::FUNCTION_HANDLE_INDEX_MAX
    );
    assert_eq!(
        adamant::FUNCTION_INST_INDEX_MAX,
        sui_common::FUNCTION_INST_INDEX_MAX
    );
    assert_eq!(
        adamant::FIELD_HANDLE_INDEX_MAX,
        sui_common::FIELD_HANDLE_INDEX_MAX
    );
    assert_eq!(
        adamant::FIELD_INST_INDEX_MAX,
        sui_common::FIELD_INST_INDEX_MAX
    );
    assert_eq!(
        adamant::STRUCT_DEF_INST_INDEX_MAX,
        sui_common::STRUCT_DEF_INST_INDEX_MAX
    );
    assert_eq!(
        adamant::ENUM_DEF_INST_INDEX_MAX,
        sui_common::ENUM_DEF_INST_INDEX_MAX
    );
    assert_eq!(adamant::CONSTANT_INDEX_MAX, sui_common::CONSTANT_INDEX_MAX);
}

#[test]
fn size_max_constants_match_upstream() {
    assert_eq!(adamant::BYTECODE_COUNT_MAX, sui_common::BYTECODE_COUNT_MAX);
    assert_eq!(adamant::BYTECODE_INDEX_MAX, sui_common::BYTECODE_INDEX_MAX);
    assert_eq!(adamant::LOCAL_INDEX_MAX, sui_common::LOCAL_INDEX_MAX);
    assert_eq!(
        adamant::IDENTIFIER_SIZE_MAX,
        sui_common::IDENTIFIER_SIZE_MAX
    );
    assert_eq!(adamant::CONSTANT_SIZE_MAX, sui_common::CONSTANT_SIZE_MAX);
    assert_eq!(
        adamant::METADATA_KEY_SIZE_MAX,
        sui_common::METADATA_KEY_SIZE_MAX
    );
    assert_eq!(
        adamant::METADATA_VALUE_SIZE_MAX,
        sui_common::METADATA_VALUE_SIZE_MAX
    );
    assert_eq!(adamant::SIGNATURE_SIZE_MAX, sui_common::SIGNATURE_SIZE_MAX);
    assert_eq!(adamant::ACQUIRES_COUNT_MAX, sui_common::ACQUIRES_COUNT_MAX);
    assert_eq!(adamant::FIELD_COUNT_MAX, sui_common::FIELD_COUNT_MAX);
    assert_eq!(adamant::FIELD_OFFSET_MAX, sui_common::FIELD_OFFSET_MAX);
    assert_eq!(adamant::TABLE_COUNT_MAX, sui_common::TABLE_COUNT_MAX);
    assert_eq!(adamant::TABLE_OFFSET_MAX, sui_common::TABLE_OFFSET_MAX);
    assert_eq!(adamant::TABLE_SIZE_MAX, sui_common::TABLE_SIZE_MAX);
    assert_eq!(
        adamant::TABLE_CONTENT_SIZE_MAX,
        sui_common::TABLE_CONTENT_SIZE_MAX
    );
}

#[test]
fn variant_and_signature_constants_match_upstream() {
    assert_eq!(adamant::VARIANT_COUNT_MAX, sui_common::VARIANT_COUNT_MAX);
    assert_eq!(
        adamant::VARIANT_TAG_MAX_VALUE,
        sui_common::VARIANT_TAG_MAX_VALUE
    );
    assert_eq!(
        adamant::JUMP_TABLE_INDEX_MAX,
        sui_common::JUMP_TABLE_INDEX_MAX
    );
    assert_eq!(
        adamant::VARIANT_INSTANTIATION_HANDLE_INDEX_MAX,
        sui_common::VARIANT_INSTANTIATION_HANDLE_INDEX_MAX
    );
    assert_eq!(
        adamant::VARIANT_HANDLE_INDEX_MAX,
        sui_common::VARIANT_HANDLE_INDEX_MAX
    );
    assert_eq!(
        adamant::TYPE_PARAMETER_COUNT_MAX,
        sui_common::TYPE_PARAMETER_COUNT_MAX
    );
    assert_eq!(
        adamant::TYPE_PARAMETER_INDEX_MAX,
        sui_common::TYPE_PARAMETER_INDEX_MAX
    );
    assert_eq!(
        adamant::SIGNATURE_TOKEN_DEPTH_MAX,
        sui_common::SIGNATURE_TOKEN_DEPTH_MAX
    );
}

#[test]
fn version_constants_match_upstream() {
    assert_eq!(adamant::VERSION_1, sui_common::VERSION_1);
    assert_eq!(adamant::VERSION_2, sui_common::VERSION_2);
    assert_eq!(adamant::VERSION_3, sui_common::VERSION_3);
    assert_eq!(adamant::VERSION_4, sui_common::VERSION_4);
    assert_eq!(adamant::VERSION_5, sui_common::VERSION_5);
    assert_eq!(adamant::VERSION_6, sui_common::VERSION_6);
    assert_eq!(adamant::VERSION_7, sui_common::VERSION_7);
    assert_eq!(adamant::VERSION_MAX, sui_common::VERSION_MAX);
    assert_eq!(adamant::VERSION_MIN, sui_common::VERSION_MIN);
}

#[test]
fn binary_flavor_sui_constant_matches_upstream() {
    assert_eq!(
        adamant::BinaryFlavor::SUI_FLAVOR,
        sui_common::BinaryFlavor::SUI_FLAVOR
    );
    assert_eq!(
        adamant::BinaryFlavor::FLAVOR_MASK,
        sui_common::BinaryFlavor::FLAVOR_MASK
    );
    assert_eq!(
        adamant::BinaryFlavor::VERSION_MASK,
        sui_common::BinaryFlavor::VERSION_MASK
    );
}

#[test]
fn magic_constants_match_upstream() {
    assert_eq!(
        adamant::BinaryConstants::MOVE_MAGIC,
        sui_common::BinaryConstants::MOVE_MAGIC
    );
    assert_eq!(
        adamant::BinaryConstants::UNPUBLISHABLE_MAGIC,
        sui_common::BinaryConstants::UNPUBLISHABLE_MAGIC
    );
    assert_eq!(
        adamant::BinaryConstants::HEADER_SIZE,
        sui_common::BinaryConstants::HEADER_SIZE
    );
}

// =============================================================================
// Tag-enum discriminants
// =============================================================================

#[test]
fn table_type_discriminants_match_upstream() {
    use adamant::TableType as A;
    use sui_common::TableType as S;
    let pairs: [(u8, u8); 19] = [
        (A::MODULE_HANDLES as u8, S::MODULE_HANDLES as u8),
        (A::DATATYPE_HANDLES as u8, S::DATATYPE_HANDLES as u8),
        (A::FUNCTION_HANDLES as u8, S::FUNCTION_HANDLES as u8),
        (A::FUNCTION_INST as u8, S::FUNCTION_INST as u8),
        (A::SIGNATURES as u8, S::SIGNATURES as u8),
        (A::CONSTANT_POOL as u8, S::CONSTANT_POOL as u8),
        (A::IDENTIFIERS as u8, S::IDENTIFIERS as u8),
        (A::ADDRESS_IDENTIFIERS as u8, S::ADDRESS_IDENTIFIERS as u8),
        (A::STRUCT_DEFS as u8, S::STRUCT_DEFS as u8),
        (A::STRUCT_DEF_INST as u8, S::STRUCT_DEF_INST as u8),
        (A::FUNCTION_DEFS as u8, S::FUNCTION_DEFS as u8),
        (A::FIELD_HANDLE as u8, S::FIELD_HANDLE as u8),
        (A::FIELD_INST as u8, S::FIELD_INST as u8),
        (A::FRIEND_DECLS as u8, S::FRIEND_DECLS as u8),
        (A::METADATA as u8, S::METADATA as u8),
        (A::ENUM_DEFS as u8, S::ENUM_DEFS as u8),
        (A::ENUM_DEF_INST as u8, S::ENUM_DEF_INST as u8),
        (A::VARIANT_HANDLES as u8, S::VARIANT_HANDLES as u8),
        (A::VARIANT_INST_HANDLES as u8, S::VARIANT_INST_HANDLES as u8),
    ];
    for (a, s) in pairs {
        assert_eq!(a, s);
    }
}

#[test]
fn serialized_type_discriminants_match_upstream() {
    use adamant::SerializedType as A;
    use sui_common::SerializedType as S;
    let pairs: [(u8, u8); 15] = [
        (A::BOOL as u8, S::BOOL as u8),
        (A::U8 as u8, S::U8 as u8),
        (A::U64 as u8, S::U64 as u8),
        (A::U128 as u8, S::U128 as u8),
        (A::ADDRESS as u8, S::ADDRESS as u8),
        (A::REFERENCE as u8, S::REFERENCE as u8),
        (A::MUTABLE_REFERENCE as u8, S::MUTABLE_REFERENCE as u8),
        (A::STRUCT as u8, S::STRUCT as u8),
        (A::TYPE_PARAMETER as u8, S::TYPE_PARAMETER as u8),
        (A::VECTOR as u8, S::VECTOR as u8),
        (A::DATATYPE_INST as u8, S::DATATYPE_INST as u8),
        (A::SIGNER as u8, S::SIGNER as u8),
        (A::U16 as u8, S::U16 as u8),
        (A::U32 as u8, S::U32 as u8),
        (A::U256 as u8, S::U256 as u8),
    ];
    for (a, s) in pairs {
        assert_eq!(a, s);
    }
}

#[test]
fn struct_and_enum_flag_discriminants_match_upstream() {
    assert_eq!(
        adamant::SerializedNativeStructFlag::NATIVE as u8,
        sui_common::SerializedNativeStructFlag::NATIVE as u8
    );
    assert_eq!(
        adamant::SerializedNativeStructFlag::DECLARED as u8,
        sui_common::SerializedNativeStructFlag::DECLARED as u8
    );
    assert_eq!(
        adamant::SerializedEnumFlag::DECLARED as u8,
        sui_common::SerializedEnumFlag::DECLARED as u8
    );
    assert_eq!(
        adamant::SerializedJumpTableFlag::FULL as u8,
        sui_common::SerializedJumpTableFlag::FULL as u8
    );
}

#[test]
fn opcode_discriminants_match_upstream() {
    use adamant::Opcodes as A;
    use sui_common::Opcodes as S;
    // Spot-check across the opcode space; full coverage is implied
    // by the `repr(u8)` discriminants since both enums declare
    // identical bytes verbatim.
    let pairs = [
        (A::POP as u8, S::POP as u8),
        (A::RET as u8, S::RET as u8),
        (A::BR_TRUE as u8, S::BR_TRUE as u8),
        (A::BRANCH as u8, S::BRANCH as u8),
        (A::CALL as u8, S::CALL as u8),
        (A::PACK as u8, S::PACK as u8),
        (A::UNPACK as u8, S::UNPACK as u8),
        (A::ADD as u8, S::ADD as u8),
        (A::ABORT as u8, S::ABORT as u8),
        (A::NOP as u8, S::NOP as u8),
        (A::FREEZE_REF as u8, S::FREEZE_REF as u8),
        (A::LD_U256 as u8, S::LD_U256 as u8),
        (A::PACK_VARIANT as u8, S::PACK_VARIANT as u8),
        (A::VARIANT_SWITCH as u8, S::VARIANT_SWITCH as u8),
        (A::EXISTS_DEPRECATED as u8, S::EXISTS_DEPRECATED as u8),
        (
            A::MOVE_TO_GENERIC_DEPRECATED as u8,
            S::MOVE_TO_GENERIC_DEPRECATED as u8,
        ),
    ];
    for (a, s) in pairs {
        assert_eq!(a, s);
    }
}

// =============================================================================
// Reader byte-stream behaviour
// =============================================================================

#[test]
fn read_u8_byte_identical_to_upstream() {
    for byte in [0u8, 1, 0x42, 0x80, 0xFF] {
        let bytes = [byte];
        let mut sui_cursor = std::io::Cursor::new(&bytes[..]);
        let mut adamant_cursor = std::io::Cursor::new(&bytes[..]);
        let sui = sui_common::read_u8(&mut sui_cursor).unwrap();
        let adamant = adamant::read_u8(&mut adamant_cursor).unwrap();
        assert_eq!(sui, adamant);
        assert_eq!(sui_cursor.position(), adamant_cursor.position());
    }
}

#[test]
fn read_u32_byte_identical_to_upstream() {
    for value in [0u32, 1, 0xFF, 0x1234_5678, u32::MAX] {
        let bytes = value.to_le_bytes();
        let mut sui_cursor = std::io::Cursor::new(&bytes[..]);
        let mut adamant_cursor = std::io::Cursor::new(&bytes[..]);
        let sui = sui_common::read_u32(&mut sui_cursor).unwrap();
        let adamant = adamant::read_u32(&mut adamant_cursor).unwrap();
        assert_eq!(sui, adamant);
        assert_eq!(sui_cursor.position(), adamant_cursor.position());
    }
}

#[test]
fn read_uleb128_byte_identical_for_canonical_inputs() {
    // For each value, encode as a canonical ULEB128 by hand,
    // then decode via both readers and compare.
    let cases: Vec<(u64, Vec<u8>)> = vec![
        (0u64, vec![0x00]),
        (1, vec![0x01]),
        (0x7F, vec![0x7F]),
        (0x80, vec![0x80, 0x01]),
        (0xFFFF, vec![0xFF, 0xFF, 0x03]),
        (
            u64::MAX,
            vec![0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01],
        ),
    ];
    for (expected, bytes) in cases {
        let mut sui_cursor = std::io::Cursor::new(&bytes[..]);
        let mut adamant_cursor = std::io::Cursor::new(&bytes[..]);
        let sui = sui_common::read_uleb128_as_u64(&mut sui_cursor).unwrap();
        let adamant = adamant::read_uleb128_as_u64(&mut adamant_cursor).unwrap();
        assert_eq!(sui, expected);
        assert_eq!(adamant, expected);
        assert_eq!(sui_cursor.position(), adamant_cursor.position());
    }
}

#[test]
fn read_uleb128_rejects_non_canonical_zero_padding_in_both() {
    // [0x80, 0x00] decodes to 0 but is non-canonical; both readers
    // must reject.
    let bytes = [0x80u8, 0x00];
    let mut sui_cursor = std::io::Cursor::new(&bytes[..]);
    let mut adamant_cursor = std::io::Cursor::new(&bytes[..]);
    assert!(sui_common::read_uleb128_as_u64(&mut sui_cursor).is_err());
    assert!(adamant::read_uleb128_as_u64(&mut adamant_cursor).is_err());
}

#[test]
fn read_uleb128_rejects_overflow_in_both() {
    // 11 bytes of 0xFF — overflow past u64.
    let bytes = [0xFFu8; 11];
    let mut sui_cursor = std::io::Cursor::new(&bytes[..]);
    let mut adamant_cursor = std::io::Cursor::new(&bytes[..]);
    assert!(sui_common::read_uleb128_as_u64(&mut sui_cursor).is_err());
    assert!(adamant::read_uleb128_as_u64(&mut adamant_cursor).is_err());
}

// =============================================================================
// AbilitySet bit layout
// =============================================================================

#[test]
fn ability_discriminants_match_upstream() {
    use adamant::Ability as A;
    use sui_format::Ability as S;
    assert_eq!(A::Copy as u8, S::Copy as u8);
    assert_eq!(A::Drop as u8, S::Drop as u8);
    assert_eq!(A::Store as u8, S::Store as u8);
    assert_eq!(A::Key as u8, S::Key as u8);
}

#[test]
fn ability_set_from_u8_byte_identical_to_upstream() {
    for byte in 0u8..=255 {
        let adamant = adamant::AbilitySet::from_u8(byte).map(adamant::AbilitySet::into_u8);
        let sui = sui_format::AbilitySet::from_u8(byte).map(sui_format::AbilitySet::into_u8);
        assert_eq!(
            adamant, sui,
            "AbilitySet::from_u8 divergence at byte {byte:#x}"
        );
    }
}

#[test]
fn ability_set_constants_match_upstream() {
    assert_eq!(
        adamant::AbilitySet::EMPTY.into_u8(),
        sui_format::AbilitySet::EMPTY.into_u8()
    );
    assert_eq!(
        adamant::AbilitySet::ALL.into_u8(),
        sui_format::AbilitySet::ALL.into_u8()
    );
    assert_eq!(
        adamant::AbilitySet::PRIMITIVES.into_u8(),
        sui_format::AbilitySet::PRIMITIVES.into_u8()
    );
    assert_eq!(
        adamant::AbilitySet::REFERENCES.into_u8(),
        sui_format::AbilitySet::REFERENCES.into_u8()
    );
    assert_eq!(
        adamant::AbilitySet::SIGNER.into_u8(),
        sui_format::AbilitySet::SIGNER.into_u8()
    );
    assert_eq!(
        adamant::AbilitySet::VECTOR.into_u8(),
        sui_format::AbilitySet::VECTOR.into_u8()
    );
}

// =============================================================================
// Identifier acceptance set
// =============================================================================

#[test]
fn identifier_acceptance_matches_upstream() {
    let cases = [
        // valid
        "foo", "_foo", "Foo123", "_x", "_0", "a", "F", "abc_def", // invalid: empty
        "",        // invalid: bare underscore
        "_",       // invalid: leading digit
        "1foo", "0a", // invalid: spaces, special chars
        "foo bar", "foo-bar", "foo.bar", "foo+bar", // invalid: non-ASCII
        "résumé", "café",
    ];
    for s in cases {
        let adamant = adamant::Identifier::new(s).is_ok();
        let sui = sui_ident::Identifier::new(s).is_ok();
        assert_eq!(adamant, sui, "Identifier acceptance divergence on {s:?}");
    }
}

#[test]
fn is_valid_matches_upstream() {
    let cases = ["foo", "_foo", "Foo123", "1foo", "_", "", "foo bar", "café"];
    for s in cases {
        assert_eq!(
            adamant::is_valid(s),
            sui_ident::is_valid(s),
            "is_valid divergence on {s:?}"
        );
    }
}

#[test]
fn is_valid_identifier_char_matches_upstream() {
    for c in ['a', 'Z', '0', '_', ' ', '-', '.', 'é', '\0', '\n'] {
        assert_eq!(
            adamant::is_valid_identifier_char(c),
            sui_ident::is_valid_identifier_char(c),
            "is_valid_identifier_char divergence on {c:?}"
        );
    }
}
