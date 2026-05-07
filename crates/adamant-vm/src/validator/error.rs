//! Adamant validator error type.
//!
//! [`AdamantValidationError`] is the single error type returned
//! by [`super::verify_module`]. The
//! [`AdamantValidationError::SuiVerifier`] variant wraps Sui's
//! [`VMError`] for inherited verifier failures (transitional
//! bridge — see the wrapper docs); per-rule variants carry
//! rule-specific diagnostic data for the Adamant-specific rules.
//!
//! Eager semantics: callers receive the first violation
//! encountered.

use adamant_bytecode_format::{ConstantPoolIndex, FunctionDefinitionIndex, TableIndex};
use adamant_types::Address;
use move_binary_format::errors::VMError;

use crate::module_wire::AdamantDeserializeError;

/// Errors returned by the Adamant validator
/// ([`super::verify_module`]).
///
/// Wave 3a covered Rules 1, 4, 5; Phase 5/5a step 4 swapped the
/// deserializer to Adamant-native and removed `rule_05`'s separate
/// module (Rule 5 enforcement now lives at parse time inside
/// [`AdamantDeserializeError::Bytecode`]'s
/// `DeprecatedGlobalStorageOpcode` variant). Variants for Rules 2,
/// 3, 6, 7 land in subsequent waves; `#[non_exhaustive]` is
/// intentionally not applied yet because no downstream consumer
/// matches on this enum yet — the variant set is still settling.
#[derive(Debug)]
pub enum AdamantValidationError {
    /// Adamant's deserializer rejected the module bytes per
    /// whitepaper §6.2.1.2 / §6.2.1.8.
    ///
    /// This variant covers parse-stage rejection, including
    /// whitepaper §6.2.1.6 Rule 5's no-global-storage enforcement:
    /// [`bytecode_wire::deserialize_function_body_from_cursor`]
    /// runs in [`bytecode_wire::DeserializeConfig::strict`] mode
    /// at deploy time and rejects each of the 10 deprecated
    /// global-storage bytecode variants with
    /// [`bytecode_wire::DeserializeError::DeprecatedGlobalStorageOpcode`].
    /// Distinguishing deserialize-stage failures from later-stage
    /// failures lets callers tell "the bytes are malformed or
    /// contain forbidden opcodes" apart from "the bytecode parses
    /// but violates type/borrow/etc. rules."
    ///
    /// [`bytecode_wire::deserialize_function_body_from_cursor`]: crate::bytecode_wire::deserialize_function_body_from_cursor
    /// [`bytecode_wire::DeserializeConfig::strict`]: crate::bytecode_wire::DeserializeConfig::strict
    /// [`bytecode_wire::DeserializeError::DeprecatedGlobalStorageOpcode`]: crate::bytecode_wire::DeserializeError::DeprecatedGlobalStorageOpcode
    AdamantDeserializer(AdamantDeserializeError),

    /// The input module bytes are not the canonical encoding of
    /// the parsed [`AdamantCompiledModule`].
    ///
    /// Sits between [`Self::AdamantDeserializer`] and
    /// [`Self::SuiVerifier`] in the pipeline: after Adamant's
    /// deserializer accepts the bytes, the wrapper re-serializes
    /// the parsed module via [`crate::adamant_serialize`] and
    /// byte-compares the output against the input. A mismatch
    /// indicates non-canonical content (trailing bytes after the
    /// documented binary format, or any other deviation from
    /// what Adamant's serializer would produce for this module).
    ///
    /// Adamant requires deployed bytecode to be canonically
    /// encoded so that two deployments of "the same module"
    /// cannot produce different `ObjectId`s via trailing-byte
    /// smuggling.
    ///
    /// The diagnostic fields locate the first byte where the
    /// input diverges from the canonical re-serialization, with
    /// `Option<u8>` carrying both bytes (`None` indicates one
    /// side is shorter, e.g. the common trailing-bytes case
    /// where `canonical_byte` is `None` and `input_byte` is
    /// `Some(...)`).
    ///
    /// [`AdamantCompiledModule`]: crate::AdamantCompiledModule
    NonCanonicalBytecode {
        /// First byte position where the input diverges from
        /// the canonical re-serialization.
        byte_offset: usize,
        /// What the canonical re-serialization has at
        /// `byte_offset`. `None` if the canonical re-serialization
        /// is shorter than the input — the "trailing bytes" case,
        /// the most common non-canonicality.
        canonical_byte: Option<u8>,
        /// What the input has at `byte_offset`. `None` if the
        /// input is shorter than the canonical re-serialization.
        input_byte: Option<u8>,
    },

    /// Sui-Move's inherited verifier rejected the parsed module.
    ///
    /// Transitional bridge: the wrapper re-parses bytes via
    /// Sui's deserializer (for modules without Adamant
    /// extensions) to obtain a [`CompiledModule`] and runs Sui's
    /// `move-bytecode-verifier` passes against it. This covers
    /// the inherited checks listed in §6.2.1.6 (type safety,
    /// reference safety, linearity, stack discipline, control-
    /// flow integrity, function-call ABI, generic instantiation,
    /// friend visibility) plus Sui's bounds checking. Phase 5/5b
    /// (module-level passes) and Phase 5/5c (per-function passes)
    /// will replace this transitional bridge with Adamant-native
    /// equivalents.
    ///
    /// For modules that contain Adamant extensions per §6.2.1.4,
    /// Sui's verifier cannot run (the extension opcodes 0x80..=0x90
    /// are outside Sui's opcode space); the wrapper skips this
    /// step and per-instruction extension verification lands in
    /// Phase 5/5c.
    ///
    /// The wrapped [`VMError`] carries Sui's diagnostic context.
    ///
    /// [`CompiledModule`]: move_binary_format::file_format::CompiledModule
    SuiVerifier(VMError),

    /// Module has no `b"adamant.mutability"` metadata entry per
    /// §6.2.1.3 / §6.2.1.6 Rule 1.
    MissingMutabilityMetadata,

    /// Module has more than one `b"adamant.mutability"` metadata
    /// entry. §6.2.1.6 Rule 1 requires exactly one.
    MultipleMutabilityMetadata {
        /// Number of entries with key `b"adamant.mutability"`
        /// the validator found. Always `>= 2` (the rule fires
        /// only on more-than-one).
        count: usize,
    },

    /// The `b"adamant.mutability"` metadata entry's value is not
    /// a valid BCS encoding of [`adamant_types::Mutability`]. The
    /// wrapped string is the BCS error's `Display` output.
    MalformedMutabilityMetadata {
        /// The BCS deserialiser's error rendered via `Display`.
        /// Carried as `String` (rather than the typed
        /// `bcs::Error`) so callers don't depend on the BCS
        /// crate's error-enum surface; downstream consumers
        /// pattern-matching on specific BCS failure modes
        /// would need a structured representation, which is a
        /// future-extension consideration flagged at the
        /// validator-rules deliverable proposal.
        bcs_error: String,
    },

    /// A function definition has `code: None` (Sui's marker for
    /// a native function). §6.2.1.6 Rule 4 forbids native
    /// functions; per §6.1.4, every function in Adamant Move is
    /// implemented in bytecode.
    NativeFunctionForbidden {
        /// Index into the module's `function_defs` of the
        /// offending function. The first such function (lowest
        /// index) is reported per the eager error semantics.
        function_index: FunctionDefinitionIndex,
    },

    /// A constant in the module's constant pool has a type that
    /// is not valid for constants per
    /// [`adamant_bytecode_format::SignatureToken::is_valid_for_constant`].
    /// Constant types must be primitives (`Bool`, `U8`–`U256`),
    /// `Address`, or `Vector<...>` recursively over those;
    /// `Datatype`, `DatatypeInstantiation`, references,
    /// `Signer`, and `TypeParameter` are rejected.
    ///
    /// Phase 5/5b.2 B-2.1 (`module_pass::constants`).
    InvalidConstantType {
        /// Index into the module's `constant_pool` of the
        /// offending entry.
        idx: ConstantPoolIndex,
    },

    /// A constant in the module's constant pool has a byte
    /// payload that is not a well-formed BCS encoding of a
    /// value of its declared type. Catches truncated payloads,
    /// invalid `Bool` byte values (any byte > 1), malformed
    /// ULEB128 length prefixes on vector payloads, and
    /// trailing bytes after a complete value.
    ///
    /// Phase 5/5b.2 B-2.1 (`module_pass::constants`).
    MalformedConstantData {
        /// Index into the module's `constant_pool` of the
        /// offending entry.
        idx: ConstantPoolIndex,
        /// Structured reason for the rejection. See
        /// [`MalformedConstantReason`].
        reason: MalformedConstantReason,
    },

    /// The module declares itself as a friend. A module's own
    /// `self_handle` may not appear in `friend_decls`. Per
    /// upstream Sui's friends pass, friend visibility is a
    /// directed relation: a module declaring itself as its own
    /// friend is structurally meaningless and is rejected at
    /// deployment.
    ///
    /// Phase 5/5b.2 B-2.2 (`module_pass::friends`).
    SelfFriendDeclaration,

    /// The module declares a friend whose address differs from
    /// the module's own self-address. Adamant inherits Sui's
    /// policy that friend declarations may not cross account
    /// boundaries; the rule lives under Adamant's audit per the
    /// resistant-proof posture (whitepaper §6.2.1.8). Future
    /// relaxation requires a deliberate Adamant-side decision
    /// rather than tracking a Sui upstream change.
    ///
    /// Phase 5/5b.2 B-2.2 (`module_pass::friends`).
    CrossAccountFriendDeclaration {
        /// Index into `friend_decls` of the offending entry.
        idx: TableIndex,
        /// The foreign account address the friend points at.
        /// Carried for diagnostics; reuses
        /// [`adamant_types::Address`] per the Phase 5/5b.1b
        /// address-pool reuse decision.
        foreign_address: Address,
    },

    /// A struct or enum-variant field has a type whose
    /// abilities do not satisfy the abilities required by the
    /// owning datatype.
    ///
    /// For each owning datatype (struct or enum), the required
    /// ability set is the union of `Ability::requires()` over
    /// each ability in the type's declared abilities (e.g., a
    /// struct with the `key` ability requires `store` on each
    /// field, since `key.requires() == store`). Every field
    /// (across every variant for enums) must carry at least the
    /// required abilities.
    ///
    /// Phase 5/5b.2 B-2.3 (`module_pass::ability_field_requirements`).
    FieldMissingTypeAbility {
        /// Index into `struct_defs` (when `kind = Struct`) or
        /// `enum_defs` (when `kind = Enum`) of the offending
        /// owning datatype.
        def_idx: TableIndex,
        /// Whether the offending field belongs to a struct
        /// definition or an enum-variant definition.
        kind: FieldOwnerKind,
        /// Variant index within the enum (`None` for structs;
        /// `Some` for enum variants — the variant tag whose
        /// fields the violation was found in).
        variant_idx: Option<TableIndex>,
        /// Index of the offending field within the owning
        /// struct (or within the enum variant identified by
        /// `variant_idx`).
        field_idx: TableIndex,
    },
    // Rule 5 (no global storage instructions) is enforced at
    // parse time inside `AdamantDeserializer`; no separate
    // variant. Variants for Rules 2, 3, 6, 7 land in subsequent
    // waves.
}

/// Whether the owning datatype on an
/// [`AdamantValidationError::FieldMissingTypeAbility`] is a
/// struct or an enum.
///
/// Phase 5/5b.2 B-2.3 (`module_pass::ability_field_requirements`).
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum FieldOwnerKind {
    /// The offending field belongs to a struct definition;
    /// `def_idx` indexes `struct_defs`.
    Struct,
    /// The offending field belongs to an enum-variant
    /// definition; `def_idx` indexes `enum_defs` and
    /// `variant_idx` is `Some(...)`.
    Enum,
}

impl core::fmt::Display for FieldOwnerKind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Struct => write!(f, "struct"),
            Self::Enum => write!(f, "enum"),
        }
    }
}

/// Structured reason for an
/// [`AdamantValidationError::MalformedConstantData`] rejection.
///
/// Phase 5/5b.2 B-2.1 (`module_pass::constants`).
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum MalformedConstantReason {
    /// The byte stream ended before a value of the declared
    /// type could be decoded. Sub-cases: a fixed-width primitive
    /// (`U16`, `U32`, ...) ran out mid-byte, a `Vector` ran out
    /// before reaching the declared element count, or the stream
    /// ended on a length-prefix read for a nested vector.
    UnexpectedEof,
    /// A `Bool` was decoded with a byte value other than `0x00`
    /// or `0x01`. BCS-canonical bool encoding admits only those
    /// two values.
    InvalidBool {
        /// The offending byte.
        byte: u8,
    },
    /// A ULEB128 length prefix on a `Vector<...>` was malformed
    /// (overlong encoding, no terminator, or otherwise not
    /// canonical).
    InvalidUleb128,
    /// The byte stream contained additional bytes after a
    /// complete value of the declared type was decoded.
    /// BCS-canonical encoding requires exact byte consumption.
    TrailingBytes {
        /// Number of bytes remaining in the stream after the
        /// complete value.
        remaining: usize,
    },
}

impl core::fmt::Display for MalformedConstantReason {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnexpectedEof => write!(f, "unexpected end of byte stream"),
            Self::InvalidBool { byte } => {
                write!(f, "invalid bool byte 0x{byte:02X} (expected 0x00 or 0x01)")
            }
            Self::InvalidUleb128 => write!(f, "malformed ULEB128 length prefix"),
            Self::TrailingBytes { remaining } => {
                write!(f, "{remaining} trailing byte(s) after complete value")
            }
        }
    }
}

impl core::fmt::Display for AdamantValidationError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::AdamantDeserializer(e) => {
                write!(f, "Adamant deserializer rejected the module bytes: {e}")
            }
            Self::NonCanonicalBytecode {
                byte_offset,
                canonical_byte,
                input_byte,
            } => write!(
                f,
                "module bytes are not the canonical encoding of the parsed module \
                 (first divergence at byte offset {byte_offset}: \
                 canonical = {canonical_byte:?}, input = {input_byte:?})"
            ),
            Self::SuiVerifier(e) => {
                write!(f, "Sui-Move verifier rejected the parsed module: {e}")
            }
            Self::MissingMutabilityMetadata => write!(
                f,
                "missing `adamant.mutability` metadata entry \
                 (whitepaper §6.2.1.6 Rule 1)"
            ),
            Self::MultipleMutabilityMetadata { count } => write!(
                f,
                "expected exactly one `adamant.mutability` metadata entry, \
                 found {count} (whitepaper §6.2.1.6 Rule 1)"
            ),
            Self::MalformedMutabilityMetadata { bcs_error } => write!(
                f,
                "`adamant.mutability` metadata value is not a valid \
                 BCS-encoded Mutability: {bcs_error} \
                 (whitepaper §6.2.1.6 Rule 1)"
            ),
            Self::NativeFunctionForbidden { function_index } => write!(
                f,
                "native function (function definition index {}) is forbidden \
                 (whitepaper §6.2.1.6 Rule 4)",
                function_index.0
            ),
            Self::InvalidConstantType { idx } => write!(
                f,
                "constant pool entry {} has a type not valid for constants \
                 (whitepaper §6.2.1.8 step 3, `module_pass::constants`)",
                idx.0
            ),
            Self::MalformedConstantData { idx, reason } => write!(
                f,
                "constant pool entry {} has malformed data: {reason} \
                 (whitepaper §6.2.1.8 step 3, `module_pass::constants`)",
                idx.0
            ),
            Self::SelfFriendDeclaration => write!(
                f,
                "module declares itself as a friend \
                 (whitepaper §6.2.1.8 step 3, `module_pass::friends`)"
            ),
            Self::CrossAccountFriendDeclaration {
                idx,
                foreign_address,
            } => write!(
                f,
                "friend declaration {idx} has foreign address {foreign_address:?} \
                 (whitepaper §6.2.1.8 step 3, `module_pass::friends`)"
            ),
            Self::FieldMissingTypeAbility {
                def_idx,
                kind,
                variant_idx,
                field_idx,
            } => match variant_idx {
                Some(v) => write!(
                    f,
                    "field {field_idx} in {kind} definition {def_idx} variant {v} \
                     is missing a required type ability \
                     (whitepaper §6.2.1.8 step 3, `module_pass::ability_field_requirements`)"
                ),
                None => write!(
                    f,
                    "field {field_idx} in {kind} definition {def_idx} is missing a \
                     required type ability \
                     (whitepaper §6.2.1.8 step 3, `module_pass::ability_field_requirements`)"
                ),
            },
        }
    }
}

impl std::error::Error for AdamantValidationError {}
