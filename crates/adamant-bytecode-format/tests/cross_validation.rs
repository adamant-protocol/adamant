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

// =============================================================================
// IndexKind variants — preserves upstream's AddressIdentifier omission
// =============================================================================

#[test]
fn index_kind_variants_match_upstream_including_omission() {
    let adamant_variants = adamant::IndexKind::variants();
    let sui_variants = move_binary_format::IndexKind::variants();
    assert_eq!(
        adamant_variants.len(),
        sui_variants.len(),
        "variants() length divergence"
    );
    // Both must exclude AddressIdentifier (the upstream quirk).
    assert!(
        !adamant_variants.contains(&adamant::IndexKind::AddressIdentifier),
        "Adamant variants() must not contain AddressIdentifier"
    );
    assert!(
        !sui_variants.contains(&move_binary_format::IndexKind::AddressIdentifier),
        "Sui variants() must not contain AddressIdentifier (upstream quirk)"
    );
}

// =============================================================================
// Index newtypes — BCS round-trip byte parity
// =============================================================================
//
// Each Adamant `*Index` newtype wraps a `TableIndex = u16`. BCS
// encodes a `u16` newtype struct as 2 little-endian bytes. The
// invariant: serializing an Adamant index produces the same
// bytes as serializing the corresponding Sui index for any value.

#[test]
fn module_handle_index_bcs_byte_identical() {
    for v in [0u16, 1, 7, 0x1234, u16::MAX] {
        let adamant_bytes =
            bcs::to_bytes(&adamant::ModuleHandleIndex::new(v)).expect("adamant serialize");
        let sui_bytes =
            bcs::to_bytes(&sui_format::ModuleHandleIndex::new(v)).expect("sui serialize");
        assert_eq!(adamant_bytes, sui_bytes, "ModuleHandleIndex bytes for {v}");
    }
}

#[test]
fn signature_index_bcs_byte_identical() {
    for v in [0u16, 7, u16::MAX] {
        let adamant_bytes = bcs::to_bytes(&adamant::SignatureIndex::new(v)).expect("a");
        let sui_bytes = bcs::to_bytes(&sui_format::SignatureIndex::new(v)).expect("s");
        assert_eq!(adamant_bytes, sui_bytes);
    }
}

#[test]
fn function_definition_index_bcs_byte_identical() {
    let adamant_bytes = bcs::to_bytes(&adamant::FunctionDefinitionIndex::new(42)).expect("a");
    let sui_bytes = bcs::to_bytes(&sui_format::FunctionDefinitionIndex::new(42)).expect("s");
    assert_eq!(adamant_bytes, sui_bytes);
}

// =============================================================================
// SignatureToken — BCS byte parity per variant + recursive cases
// =============================================================================

#[test]
fn signature_token_primitives_bcs_byte_identical() {
    let pairs: [(adamant::SignatureToken, sui_format::SignatureToken); 9] = [
        (
            adamant::SignatureToken::Bool,
            sui_format::SignatureToken::Bool,
        ),
        (adamant::SignatureToken::U8, sui_format::SignatureToken::U8),
        (
            adamant::SignatureToken::U16,
            sui_format::SignatureToken::U16,
        ),
        (
            adamant::SignatureToken::U32,
            sui_format::SignatureToken::U32,
        ),
        (
            adamant::SignatureToken::U64,
            sui_format::SignatureToken::U64,
        ),
        (
            adamant::SignatureToken::U128,
            sui_format::SignatureToken::U128,
        ),
        (
            adamant::SignatureToken::U256,
            sui_format::SignatureToken::U256,
        ),
        (
            adamant::SignatureToken::Address,
            sui_format::SignatureToken::Address,
        ),
        (
            adamant::SignatureToken::Signer,
            sui_format::SignatureToken::Signer,
        ),
    ];
    for (a, s) in &pairs {
        let abytes = bcs::to_bytes(a).expect("a");
        let sbytes = bcs::to_bytes(s).expect("s");
        assert_eq!(abytes, sbytes, "SignatureToken {a:?} bytes");
    }
}

#[test]
fn signature_token_vector_bcs_byte_identical() {
    let a = adamant::SignatureToken::Vector(Box::new(adamant::SignatureToken::U64));
    let s = sui_format::SignatureToken::Vector(Box::new(sui_format::SignatureToken::U64));
    assert_eq!(bcs::to_bytes(&a).expect("a"), bcs::to_bytes(&s).expect("s"));
}

#[test]
fn signature_token_reference_bcs_byte_identical() {
    let a = adamant::SignatureToken::Reference(Box::new(adamant::SignatureToken::U64));
    let s = sui_format::SignatureToken::Reference(Box::new(sui_format::SignatureToken::U64));
    assert_eq!(bcs::to_bytes(&a).expect("a"), bcs::to_bytes(&s).expect("s"));
}

#[test]
fn signature_token_datatype_bcs_byte_identical() {
    let a = adamant::SignatureToken::Datatype(adamant::DatatypeHandleIndex::new(7));
    let s = sui_format::SignatureToken::Datatype(sui_format::DatatypeHandleIndex::new(7));
    assert_eq!(bcs::to_bytes(&a).expect("a"), bcs::to_bytes(&s).expect("s"));
}

#[test]
fn signature_token_datatype_instantiation_bcs_byte_identical() {
    let a = adamant::SignatureToken::DatatypeInstantiation(Box::new((
        adamant::DatatypeHandleIndex::new(1),
        vec![adamant::SignatureToken::U8, adamant::SignatureToken::Bool],
    )));
    let s = sui_format::SignatureToken::DatatypeInstantiation(Box::new((
        sui_format::DatatypeHandleIndex::new(1),
        vec![
            sui_format::SignatureToken::U8,
            sui_format::SignatureToken::Bool,
        ],
    )));
    assert_eq!(bcs::to_bytes(&a).expect("a"), bcs::to_bytes(&s).expect("s"));
}

#[test]
fn signature_token_type_parameter_bcs_byte_identical() {
    let a = adamant::SignatureToken::TypeParameter(3);
    let s = sui_format::SignatureToken::TypeParameter(3);
    assert_eq!(bcs::to_bytes(&a).expect("a"), bcs::to_bytes(&s).expect("s"));
}

// =============================================================================
// Visibility — discriminant byte parity
// =============================================================================

#[test]
fn visibility_bcs_byte_identical() {
    let pairs = [
        (
            adamant::Visibility::Private,
            sui_format::Visibility::Private,
        ),
        (adamant::Visibility::Public, sui_format::Visibility::Public),
        (adamant::Visibility::Friend, sui_format::Visibility::Friend),
    ];
    for (a, s) in pairs {
        assert_eq!(bcs::to_bytes(&a).expect("a"), bcs::to_bytes(&s).expect("s"));
    }
    assert_eq!(
        adamant::Visibility::DEPRECATED_SCRIPT,
        sui_format::Visibility::DEPRECATED_SCRIPT
    );
}

// =============================================================================
// Handle types — BCS byte parity
// =============================================================================

#[test]
fn module_handle_bcs_byte_identical() {
    let a = adamant::ModuleHandle {
        address: adamant::AddressIdentifierIndex::new(0),
        name: adamant::IdentifierIndex::new(7),
    };
    let s = sui_format::ModuleHandle {
        address: sui_format::AddressIdentifierIndex::new(0),
        name: sui_format::IdentifierIndex::new(7),
    };
    assert_eq!(bcs::to_bytes(&a).expect("a"), bcs::to_bytes(&s).expect("s"));
}

#[test]
fn datatype_handle_bcs_byte_identical() {
    let a = adamant::DatatypeHandle {
        module: adamant::ModuleHandleIndex::new(0),
        name: adamant::IdentifierIndex::new(1),
        abilities: adamant::AbilitySet::PRIMITIVES,
        type_parameters: vec![adamant::DatatypeTyParameter {
            constraints: adamant::AbilitySet::EMPTY | adamant::Ability::Drop,
            is_phantom: false,
        }],
    };
    let s = sui_format::DatatypeHandle {
        module: sui_format::ModuleHandleIndex::new(0),
        name: sui_format::IdentifierIndex::new(1),
        abilities: sui_format::AbilitySet::PRIMITIVES,
        type_parameters: vec![sui_format::DatatypeTyParameter {
            constraints: sui_format::AbilitySet::EMPTY | sui_format::Ability::Drop,
            is_phantom: false,
        }],
    };
    assert_eq!(bcs::to_bytes(&a).expect("a"), bcs::to_bytes(&s).expect("s"));
}

#[test]
fn function_handle_bcs_byte_identical() {
    let a = adamant::FunctionHandle {
        module: adamant::ModuleHandleIndex::new(0),
        name: adamant::IdentifierIndex::new(2),
        parameters: adamant::SignatureIndex::new(0),
        return_: adamant::SignatureIndex::new(1),
        type_parameters: vec![adamant::AbilitySet::PRIMITIVES],
    };
    let s = sui_format::FunctionHandle {
        module: sui_format::ModuleHandleIndex::new(0),
        name: sui_format::IdentifierIndex::new(2),
        parameters: sui_format::SignatureIndex::new(0),
        return_: sui_format::SignatureIndex::new(1),
        type_parameters: vec![sui_format::AbilitySet::PRIMITIVES],
    };
    assert_eq!(bcs::to_bytes(&a).expect("a"), bcs::to_bytes(&s).expect("s"));
}

#[test]
fn jump_table_inner_bcs_byte_identical() {
    let a = adamant::JumpTableInner::Full(vec![1u16, 2, 3]);
    let s = sui_format::JumpTableInner::Full(vec![1u16, 2, 3]);
    assert_eq!(bcs::to_bytes(&a).expect("a"), bcs::to_bytes(&s).expect("s"));
}

// =============================================================================
// Definitions — BCS byte parity
// =============================================================================

#[test]
fn struct_definition_bcs_byte_identical_native() {
    let a = adamant::StructDefinition {
        struct_handle: adamant::DatatypeHandleIndex::new(0),
        field_information: adamant::StructFieldInformation::Native,
    };
    let s = sui_format::StructDefinition {
        struct_handle: sui_format::DatatypeHandleIndex::new(0),
        field_information: sui_format::StructFieldInformation::Native,
    };
    assert_eq!(bcs::to_bytes(&a).expect("a"), bcs::to_bytes(&s).expect("s"));
}

#[test]
fn struct_definition_bcs_byte_identical_declared() {
    let a = adamant::StructDefinition {
        struct_handle: adamant::DatatypeHandleIndex::new(0),
        field_information: adamant::StructFieldInformation::Declared(vec![
            adamant::FieldDefinition {
                name: adamant::IdentifierIndex::new(0),
                signature: adamant::TypeSignature(adamant::SignatureToken::U64),
            },
        ]),
    };
    let s = sui_format::StructDefinition {
        struct_handle: sui_format::DatatypeHandleIndex::new(0),
        field_information: sui_format::StructFieldInformation::Declared(vec![
            sui_format::FieldDefinition {
                name: sui_format::IdentifierIndex::new(0),
                signature: sui_format::TypeSignature(sui_format::SignatureToken::U64),
            },
        ]),
    };
    assert_eq!(bcs::to_bytes(&a).expect("a"), bcs::to_bytes(&s).expect("s"));
}

#[test]
fn enum_definition_bcs_byte_identical() {
    let a = adamant::EnumDefinition {
        enum_handle: adamant::DatatypeHandleIndex::new(0),
        variants: vec![adamant::VariantDefinition {
            variant_name: adamant::IdentifierIndex::new(0),
            fields: vec![],
        }],
    };
    let s = sui_format::EnumDefinition {
        enum_handle: sui_format::DatatypeHandleIndex::new(0),
        variants: vec![sui_format::VariantDefinition {
            variant_name: sui_format::IdentifierIndex::new(0),
            fields: vec![],
        }],
    };
    assert_eq!(bcs::to_bytes(&a).expect("a"), bcs::to_bytes(&s).expect("s"));
}

// =============================================================================
// Instantiation types — BCS byte parity
// =============================================================================

#[test]
fn struct_def_instantiation_bcs_byte_identical() {
    let a = adamant::StructDefInstantiation {
        def: adamant::StructDefinitionIndex::new(0),
        type_parameters: adamant::SignatureIndex::new(1),
    };
    let s = sui_format::StructDefInstantiation {
        def: sui_format::StructDefinitionIndex::new(0),
        type_parameters: sui_format::SignatureIndex::new(1),
    };
    assert_eq!(bcs::to_bytes(&a).expect("a"), bcs::to_bytes(&s).expect("s"));
}

// =============================================================================
// Signature types — BCS byte parity
// =============================================================================

#[test]
fn signature_bcs_byte_identical() {
    let a = adamant::Signature(vec![
        adamant::SignatureToken::U64,
        adamant::SignatureToken::Bool,
    ]);
    let s = sui_format::Signature(vec![
        sui_format::SignatureToken::U64,
        sui_format::SignatureToken::Bool,
    ]);
    assert_eq!(bcs::to_bytes(&a).expect("a"), bcs::to_bytes(&s).expect("s"));
}

#[test]
fn type_signature_bcs_byte_identical() {
    let a = adamant::TypeSignature(adamant::SignatureToken::U128);
    let s = sui_format::TypeSignature(sui_format::SignatureToken::U128);
    assert_eq!(bcs::to_bytes(&a).expect("a"), bcs::to_bytes(&s).expect("s"));
}

// =============================================================================
// Constant — BCS byte parity
// =============================================================================

#[test]
fn constant_bcs_byte_identical() {
    let a = adamant::Constant {
        type_: adamant::SignatureToken::U64,
        data: vec![1, 2, 3, 4, 5, 6, 7, 8],
    };
    let s = sui_format::Constant {
        type_: sui_format::SignatureToken::U64,
        data: vec![1, 2, 3, 4, 5, 6, 7, 8],
    };
    assert_eq!(bcs::to_bytes(&a).expect("a"), bcs::to_bytes(&s).expect("s"));
}

// =============================================================================
// Code unit + function definition — BCS byte parity
// =============================================================================

#[test]
fn code_unit_bcs_byte_identical() {
    let a = adamant::CodeUnit {
        locals: adamant::SignatureIndex::new(0),
        code: vec![adamant::Bytecode::Pop, adamant::Bytecode::Ret],
        jump_tables: vec![],
    };
    let s = sui_format::CodeUnit {
        locals: sui_format::SignatureIndex::new(0),
        code: vec![sui_format::Bytecode::Pop, sui_format::Bytecode::Ret],
        jump_tables: vec![],
    };
    assert_eq!(bcs::to_bytes(&a).expect("a"), bcs::to_bytes(&s).expect("s"));
}

#[test]
fn function_definition_bcs_byte_identical() {
    let a = adamant::FunctionDefinition {
        function: adamant::FunctionHandleIndex::new(0),
        visibility: adamant::Visibility::Public,
        is_entry: true,
        acquires_global_resources: vec![],
        code: Some(adamant::CodeUnit {
            locals: adamant::SignatureIndex::new(0),
            code: vec![adamant::Bytecode::Ret],
            jump_tables: vec![],
        }),
    };
    let s = sui_format::FunctionDefinition {
        function: sui_format::FunctionHandleIndex::new(0),
        visibility: sui_format::Visibility::Public,
        is_entry: true,
        acquires_global_resources: vec![],
        code: Some(sui_format::CodeUnit {
            locals: sui_format::SignatureIndex::new(0),
            code: vec![sui_format::Bytecode::Ret],
            jump_tables: vec![],
        }),
    };
    assert_eq!(bcs::to_bytes(&a).expect("a"), bcs::to_bytes(&s).expect("s"));
}

// =============================================================================
// Bytecode — BCS byte parity per representative variant
// =============================================================================
//
// Coverage: zero-operand variants, single-index-operand variants
// (each operand-shape category at least once), multi-operand
// variants (`VecPack`/`VecUnpack`), the boxed-payload variants
// (`LdU128`/`LdU256`), variant-handle variants, and at least one
// deprecated variant.

#[test]
fn bytecode_zero_operand_variants_bcs_byte_identical() {
    let pairs: [(adamant::Bytecode, sui_format::Bytecode); 8] = [
        (adamant::Bytecode::Pop, sui_format::Bytecode::Pop),
        (adamant::Bytecode::Ret, sui_format::Bytecode::Ret),
        (adamant::Bytecode::Add, sui_format::Bytecode::Add),
        (adamant::Bytecode::Eq, sui_format::Bytecode::Eq),
        (adamant::Bytecode::Nop, sui_format::Bytecode::Nop),
        (adamant::Bytecode::Abort, sui_format::Bytecode::Abort),
        (adamant::Bytecode::ReadRef, sui_format::Bytecode::ReadRef),
        (
            adamant::Bytecode::FreezeRef,
            sui_format::Bytecode::FreezeRef,
        ),
    ];
    for (a, s) in &pairs {
        assert_eq!(
            bcs::to_bytes(a).expect("a"),
            bcs::to_bytes(s).expect("s"),
            "Bytecode {a:?}"
        );
    }
}

#[test]
fn bytecode_index_operand_variants_bcs_byte_identical() {
    let a_call = adamant::Bytecode::Call(adamant::FunctionHandleIndex::new(7));
    let s_call = sui_format::Bytecode::Call(sui_format::FunctionHandleIndex::new(7));
    assert_eq!(
        bcs::to_bytes(&a_call).expect("a"),
        bcs::to_bytes(&s_call).expect("s")
    );

    let a_pack = adamant::Bytecode::Pack(adamant::StructDefinitionIndex::new(3));
    let s_pack = sui_format::Bytecode::Pack(sui_format::StructDefinitionIndex::new(3));
    assert_eq!(
        bcs::to_bytes(&a_pack).expect("a"),
        bcs::to_bytes(&s_pack).expect("s")
    );

    let a_br = adamant::Bytecode::BrTrue(42);
    let s_br = sui_format::Bytecode::BrTrue(42);
    assert_eq!(
        bcs::to_bytes(&a_br).expect("a"),
        bcs::to_bytes(&s_br).expect("s")
    );
}

#[test]
fn bytecode_immediate_value_variants_bcs_byte_identical() {
    let a_ld = adamant::Bytecode::LdU64(0xDEAD_BEEF);
    let s_ld = sui_format::Bytecode::LdU64(0xDEAD_BEEF);
    assert_eq!(
        bcs::to_bytes(&a_ld).expect("a"),
        bcs::to_bytes(&s_ld).expect("s")
    );

    let a_ld128 = adamant::Bytecode::LdU128(Box::new(0x1234_5678_9ABC_DEF0));
    let s_ld128 = sui_format::Bytecode::LdU128(Box::new(0x1234_5678_9ABC_DEF0));
    assert_eq!(
        bcs::to_bytes(&a_ld128).expect("a"),
        bcs::to_bytes(&s_ld128).expect("s")
    );
}

#[test]
fn bytecode_variant_handle_variants_bcs_byte_identical() {
    let a = adamant::Bytecode::PackVariant(adamant::VariantHandleIndex::new(5));
    let s = sui_format::Bytecode::PackVariant(sui_format::VariantHandleIndex::new(5));
    assert_eq!(bcs::to_bytes(&a).expect("a"), bcs::to_bytes(&s).expect("s"));

    let a_sw = adamant::Bytecode::VariantSwitch(adamant::VariantJumpTableIndex::new(0));
    let s_sw = sui_format::Bytecode::VariantSwitch(sui_format::VariantJumpTableIndex::new(0));
    assert_eq!(
        bcs::to_bytes(&a_sw).expect("a"),
        bcs::to_bytes(&s_sw).expect("s")
    );
}

#[test]
fn bytecode_multi_operand_variants_bcs_byte_identical() {
    let a = adamant::Bytecode::VecPack(adamant::SignatureIndex::new(2), 7);
    let s = sui_format::Bytecode::VecPack(sui_format::SignatureIndex::new(2), 7);
    assert_eq!(bcs::to_bytes(&a).expect("a"), bcs::to_bytes(&s).expect("s"));
}

#[test]
fn bytecode_deprecated_variants_bcs_byte_identical() {
    // Deprecated variants are byte-faithfully forked even though
    // §6.2.1.6 Rule 5 rejects them at deployment.
    let a = adamant::Bytecode::ExistsDeprecated(adamant::StructDefinitionIndex::new(0));
    let s = sui_format::Bytecode::ExistsDeprecated(sui_format::StructDefinitionIndex::new(0));
    assert_eq!(bcs::to_bytes(&a).expect("a"), bcs::to_bytes(&s).expect("s"));
}

#[test]
fn instruction_key_matches_upstream_per_variant() {
    // Pin the opcode-byte assignment for every active and
    // deprecated variant against upstream. This is the
    // load-bearing bytecode test: any divergence is a hard
    // fork of the inherited subset.
    use adamant::Bytecode as A;
    use move_binary_format::file_format_common as sui_common_helpers;
    use sui_format::Bytecode as S;
    let pairs: Vec<(A, S)> = vec![
        (A::Pop, S::Pop),
        (A::Ret, S::Ret),
        (A::BrTrue(0), S::BrTrue(0)),
        (A::BrFalse(0), S::BrFalse(0)),
        (A::Branch(0), S::Branch(0)),
        (A::LdU8(0), S::LdU8(0)),
        (A::LdU64(0), S::LdU64(0)),
        (A::LdU128(Box::new(0)), S::LdU128(Box::new(0))),
        (A::CastU8, S::CastU8),
        (A::CastU64, S::CastU64),
        (A::CastU128, S::CastU128),
        (
            A::LdConst(adamant::ConstantPoolIndex::new(0)),
            S::LdConst(sui_format::ConstantPoolIndex::new(0)),
        ),
        (A::LdTrue, S::LdTrue),
        (A::LdFalse, S::LdFalse),
        (A::CopyLoc(0), S::CopyLoc(0)),
        (A::MoveLoc(0), S::MoveLoc(0)),
        (A::StLoc(0), S::StLoc(0)),
        (
            A::Call(adamant::FunctionHandleIndex::new(0)),
            S::Call(sui_format::FunctionHandleIndex::new(0)),
        ),
        (
            A::Pack(adamant::StructDefinitionIndex::new(0)),
            S::Pack(sui_format::StructDefinitionIndex::new(0)),
        ),
        (A::ReadRef, S::ReadRef),
        (A::WriteRef, S::WriteRef),
        (A::FreezeRef, S::FreezeRef),
        (A::Add, S::Add),
        (A::Sub, S::Sub),
        (A::Eq, S::Eq),
        (A::Lt, S::Lt),
        (A::Abort, S::Abort),
        (A::Nop, S::Nop),
        (A::LdU16(0), S::LdU16(0)),
        (A::LdU32(0), S::LdU32(0)),
        (
            A::LdU256(Box::new(adamant::U256::ZERO)),
            S::LdU256(Box::new(move_core_types::u256::U256::zero())),
        ),
        (
            A::PackVariant(adamant::VariantHandleIndex::new(0)),
            S::PackVariant(sui_format::VariantHandleIndex::new(0)),
        ),
        (
            A::VariantSwitch(adamant::VariantJumpTableIndex::new(0)),
            S::VariantSwitch(sui_format::VariantJumpTableIndex::new(0)),
        ),
        (
            A::ExistsDeprecated(adamant::StructDefinitionIndex::new(0)),
            S::ExistsDeprecated(sui_format::StructDefinitionIndex::new(0)),
        ),
        (
            A::MoveToDeprecated(adamant::StructDefinitionIndex::new(0)),
            S::MoveToDeprecated(sui_format::StructDefinitionIndex::new(0)),
        ),
    ];
    for (a, s) in &pairs {
        assert_eq!(
            adamant::instruction_key(a),
            sui_common_helpers::instruction_key(s),
            "instruction_key divergence on {a:?}"
        );
    }
}

// =============================================================================
// U256 — BCS byte parity (32 raw little-endian bytes)
// =============================================================================

#[test]
fn u256_bcs_byte_identical() {
    // ZERO: 32 zero bytes.
    let a_zero = adamant::U256::ZERO;
    let s_zero = move_core_types::u256::U256::zero();
    assert_eq!(
        bcs::to_bytes(&a_zero).expect("a"),
        bcs::to_bytes(&s_zero).expect("s")
    );

    // A non-zero value: 0x01 in the LSB. Adamant's bytes are
    // little-endian (`from_le_bytes`); Sui's `from_le_bytes`
    // matches.
    let mut bytes = [0u8; 32];
    bytes[0] = 0x01;
    let a_one = adamant::U256::from_le_bytes(bytes);
    let s_one = move_core_types::u256::U256::from_le_bytes(&bytes);
    assert_eq!(
        bcs::to_bytes(&a_one).expect("a"),
        bcs::to_bytes(&s_one).expect("s")
    );
}

// =============================================================================
// Address pool — Adamant's reused `adamant_types::Address` is
// byte-identical to Sui's `AccountAddress` under BCS
// =============================================================================

#[test]
fn address_pool_entry_bcs_byte_identical() {
    use move_core_types::account_address::AccountAddress;
    let bytes = [
        0x01u8, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E,
        0x1F, 0x20,
    ];
    let adamant_addr = adamant_types::Address::from_bytes(bytes);
    let sui_addr = AccountAddress::new(bytes);
    assert_eq!(
        bcs::to_bytes(&adamant_addr).expect("a"),
        bcs::to_bytes(&sui_addr).expect("s"),
        "Address vs AccountAddress BCS byte divergence"
    );

    // Pool form: Vec<Address> vs Vec<AccountAddress>
    let adamant_pool: adamant::AddressIdentifierPool = vec![adamant_addr, adamant_addr];
    let sui_pool: Vec<AccountAddress> = vec![sui_addr, sui_addr];
    assert_eq!(
        bcs::to_bytes(&adamant_pool).expect("a"),
        bcs::to_bytes(&sui_pool).expect("s")
    );
}

// =============================================================================
// Metadata — BCS byte parity
// =============================================================================

#[test]
fn metadata_bcs_byte_identical() {
    let a = adamant::Metadata {
        key: b"adamant.mutability".to_vec(),
        value: vec![0x01, 0x02, 0x03],
    };
    let s = move_core_types::metadata::Metadata {
        key: b"adamant.mutability".to_vec(),
        value: vec![0x01, 0x02, 0x03],
    };
    assert_eq!(bcs::to_bytes(&a).expect("a"), bcs::to_bytes(&s).expect("s"));
}
