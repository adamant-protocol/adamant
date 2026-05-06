//! Adamant-owned bytecode-format primitives.
//!
//! This crate is the resistant-proof foundation for the Adamant
//! verifier per whitepaper §6.2.1.8. It contains constants, byte-
//! stream readers, the `Ability`/`AbilitySet` types, and the
//! `Identifier` type — the bytecode-format primitives that
//! `adamant-vm` depends on at deploy-time and runtime. None of
//! these primitives may pull `move-*` crates into the production
//! dependency graph.
//!
//! See `PROVENANCE.md` for the upstream lineage. The crate is
//! forked from Sui-Move at tag `mainnet-v1.66.2`. Cross-validation
//! tests under `tests/cross_validation.rs` assert byte-identity
//! against the still-vendored Sui crates (under `[dev-dependencies]`),
//! exercising the resistant-proof carve-out for test-only
//! dependencies.
//!
//! # Module map
//!
//! | Module                  | Surface                                                |
//! |-------------------------|--------------------------------------------------------|
//! | [`error`]               | [`ReaderError`]                                        |
//! | [`format_common`]       | [`BinaryFlavor`], [`BinaryConstants`], [`MagicKind`], [`MagicError`], all `*_MAX` constants, [`TableType`], [`SerializedType`], [`SerializedNativeStructFlag`], [`SerializedEnumFlag`], [`SerializedJumpTableFlag`], [`Opcodes`], [`read_u8`], [`read_u32`], [`read_uleb128_as_u64`], all `VERSION_*` constants |
//! | [`ability`]             | [`Ability`], [`AbilitySet`], [`AbilitySetIterator`], [`AbilityError`] |
//! | [`identifier`]          | [`Identifier`], [`InvalidIdentifier`], [`is_valid`], [`is_valid_identifier_char`] |
//! | [`index`]               | [`IndexKind`], [`ModuleIndex`], 18 `*Index` newtypes, [`TableIndex`], [`LocalIndex`], [`MemberCount`], [`CodeOffset`], [`VariantTag`], [`TypeParameterIndex`] |
//! | [`signature_token_kind`]| [`SignatureTokenKind`]                                 |

#![forbid(unsafe_code)]

pub mod ability;
pub mod address_pool;
pub mod bytecode;
pub mod code_unit;
pub mod constant;
pub mod definition;
pub mod error;
pub mod format_common;
pub mod handle;
pub mod identifier;
pub mod index;
pub mod instantiation;
pub mod metadata;
pub mod signature;
pub mod signature_token;
pub mod signature_token_kind;
pub mod u256;

// Top-level re-exports. Match the import-shape `adamant-vm`
// previously used (`use move_binary_format::file_format_common::{...};`)
// so the rewiring touch is mechanical.
pub use ability::{Ability, AbilityError, AbilitySet, AbilitySetIterator};
pub use address_pool::AddressIdentifierPool;
pub use bytecode::{instruction_key, instruction_opcode, Bytecode};
pub use code_unit::{CodeUnit, FunctionDefinition};
pub use constant::{Constant, ConstantPool};
pub use definition::{
    EnumDefinition, FieldDefinition, NativeStructError, StructDefinition, StructFieldInformation,
    VariantDefinition, Visibility,
};
pub use error::ReaderError;
pub use format_common::{
    read_u32, read_u8, read_uleb128_as_u64, BinaryConstants, BinaryFlavor, MagicError, MagicKind,
    Opcodes, SerializedEnumFlag, SerializedJumpTableFlag, SerializedNativeStructFlag,
    SerializedType, TableType, ACQUIRES_COUNT_MAX, ADDRESS_INDEX_MAX, BINARY_SIZE_LIMIT,
    BYTECODE_COUNT_MAX, BYTECODE_INDEX_MAX, CONSTANT_INDEX_MAX, CONSTANT_SIZE_MAX,
    DATATYPE_HANDLE_INDEX_MAX, ENUM_DEF_INDEX_MAX, ENUM_DEF_INST_INDEX_MAX, FIELD_COUNT_MAX,
    FIELD_HANDLE_INDEX_MAX, FIELD_INST_INDEX_MAX, FIELD_OFFSET_MAX, FUNCTION_HANDLE_INDEX_MAX,
    FUNCTION_INST_INDEX_MAX, IDENTIFIER_INDEX_MAX, IDENTIFIER_SIZE_MAX, JUMP_TABLE_INDEX_MAX,
    LOCAL_INDEX_MAX, METADATA_KEY_SIZE_MAX, METADATA_VALUE_SIZE_MAX, MODULE_HANDLE_INDEX_MAX,
    SIGNATURE_INDEX_MAX, SIGNATURE_SIZE_MAX, SIGNATURE_TOKEN_DEPTH_MAX, STRUCT_DEF_INDEX_MAX,
    STRUCT_DEF_INST_INDEX_MAX, TABLE_CONTENT_SIZE_MAX, TABLE_COUNT_MAX, TABLE_INDEX_MAX,
    TABLE_OFFSET_MAX, TABLE_SIZE_MAX, TYPE_PARAMETER_COUNT_MAX, TYPE_PARAMETER_INDEX_MAX,
    VARIANT_COUNT_MAX, VARIANT_HANDLE_INDEX_MAX, VARIANT_INSTANTIATION_HANDLE_INDEX_MAX,
    VARIANT_TAG_MAX_VALUE, VERSION_1, VERSION_2, VERSION_3, VERSION_4, VERSION_5, VERSION_6,
    VERSION_7, VERSION_MAX, VERSION_MIN,
};
pub use handle::{
    DatatypeHandle, DatatypeTyParameter, FieldHandle, FunctionHandle, JumpTableInner, ModuleHandle,
    VariantHandle, VariantInstantiationHandle, VariantJumpTable,
};
pub use identifier::{
    is_valid, is_valid_identifier_char, Identifier, IdentifierPool, InvalidIdentifier,
};
pub use index::{
    AddressIdentifierIndex, CodeOffset, ConstantPoolIndex, DatatypeHandleIndex,
    EnumDefInstantiationIndex, EnumDefinitionIndex, FieldHandleIndex, FieldInstantiationIndex,
    FunctionDefinitionIndex, FunctionHandleIndex, FunctionInstantiationIndex, IdentifierIndex,
    IndexKind, LocalIndex, MemberCount, ModuleHandleIndex, ModuleIndex, SignatureIndex,
    StructDefInstantiationIndex, StructDefinitionIndex, TableIndex, TypeParameterIndex,
    VariantHandleIndex, VariantInstantiationHandleIndex, VariantJumpTableIndex, VariantTag,
};
pub use instantiation::{
    EnumDefInstantiation, FieldInstantiation, FunctionInstantiation, StructDefInstantiation,
};
pub use metadata::Metadata;
pub use signature::{
    FunctionSignature, Signature, SignaturePool, TypeSignature, TypeSignaturePool,
};
pub use signature_token::{
    SignatureToken, SignatureTokenPreorderTraversalIter,
    SignatureTokenPreorderTraversalIterWithDepth,
};
pub use signature_token_kind::SignatureTokenKind;
pub use u256::U256;
