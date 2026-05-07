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

use adamant_bytecode_format::{
    CodeOffset, ConstantPoolIndex, DatatypeHandleIndex, EnumDefinitionIndex,
    FunctionDefinitionIndex, FunctionHandleIndex, IdentifierIndex, IndexKind, TableIndex,
};
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

    /// A bytecode instruction's generic-vs-non-generic flavor
    /// does not match its target's declared type-parameter
    /// count. Examples: `Pack` referencing a struct with
    /// declared type parameters; `PackGeneric` referencing a
    /// struct with no type parameters; `Call` on a generic
    /// function; `CallGeneric` on a non-generic function. The
    /// pairing applies symmetrically across the field-borrow,
    /// function-call, struct-pack/unpack, and enum-variant-
    /// pack/unpack instruction families.
    ///
    /// Phase 5/5b.2 B-2.4 (`module_pass::instruction_consistency`).
    GenericMemberOpcodeMismatch {
        /// Function definition containing the offending
        /// instruction.
        fn_def_idx: FunctionDefinitionIndex,
        /// Offset of the offending instruction within the
        /// function body.
        code_offset: CodeOffset,
    },

    /// A `VecPack` or `VecUnpack` instruction's element-count
    /// operand exceeds `u16::MAX`. The element count operand
    /// is encoded as a `u64` in the binary format, but the
    /// runtime stack-effect calculation consumes/produces a
    /// number of values equal to the count, and the count
    /// must fit `u16::MAX` to bound the stack-effect cost
    /// statically.
    ///
    /// Phase 5/5b.2 B-2.4 (`module_pass::instruction_consistency`).
    VecPackUnpackArgOutOfRange {
        /// Function definition containing the offending
        /// instruction.
        fn_def_idx: FunctionDefinitionIndex,
        /// Offset of the offending instruction within the
        /// function body.
        code_offset: CodeOffset,
        /// The offending element-count operand.
        num: u64,
    },

    /// A `Vector<T>` constant's element count exceeds
    /// `AdamantStructuralLimits::max_constant_vector_len`.
    /// The element count is decoded from the outer ULEB128
    /// length prefix of the constant's BCS-encoded data.
    ///
    /// Phase 5/5b.2 B-3.1 (`module_pass::limits`).
    TooManyVectorElements {
        /// Index into `constant_pool` of the offending entry.
        idx: ConstantPoolIndex,
    },

    /// A handle's declared type-parameter count exceeds
    /// `AdamantStructuralLimits::max_generic_instantiation_length`.
    /// Applies to both [`HandleKind::DatatypeHandle`] and
    /// [`HandleKind::FunctionHandle`].
    ///
    /// Phase 5/5b.2 B-3.1 (`module_pass::limits`).
    TooManyTypeParameters {
        /// Whether the offending handle is a datatype handle
        /// or a function handle.
        kind: HandleKind,
        /// Index into the corresponding handle table.
        idx: TableIndex,
    },

    /// A function handle's parameter signature exceeds
    /// `AdamantStructuralLimits::max_function_parameters`.
    ///
    /// Phase 5/5b.2 B-3.1 (`module_pass::limits`).
    TooManyParameters {
        /// Index into `function_handles` of the offending
        /// handle.
        idx: FunctionHandleIndex,
    },

    /// A signature-token tree's weighted node count exceeds
    /// `AdamantStructuralLimits::max_type_nodes`. Sui's per-
    /// node weighting (preserved byte-faithfully): `Datatype`
    /// and `DatatypeInstantiation` nodes count as 4,
    /// `TypeParameter` as 4, primitives as 1.
    ///
    /// Phase 5/5b.2 B-3.1 (`module_pass::limits`).
    TooManyTypeNodes,

    /// An identifier in the module's identifier pool exceeds
    /// `AdamantStructuralLimits::max_identifier_len` bytes.
    ///
    /// Phase 5/5b.2 B-3.1 (`module_pass::limits`).
    IdentifierTooLong {
        /// Index into `identifiers` of the offending entry.
        idx: IdentifierIndex,
    },

    /// An identifier in the module's identifier pool is the
    /// literal `<SELF>` while
    /// `AdamantStructuralLimits::disallow_self_identifier`
    /// is `true`. `<SELF>` is a Move-internal sentinel that
    /// should never appear in deployed bytecode; Adamant's
    /// genesis config flips this from Sui's `false` to `true`
    /// per the B-1 redirect.
    ///
    /// Phase 5/5b.2 B-3.1 (`module_pass::limits`).
    InvalidIdentifier {
        /// Index into `identifiers` of the offending entry.
        idx: IdentifierIndex,
    },

    /// The module's `function_defs` count exceeds
    /// `AdamantStructuralLimits::max_function_definitions`.
    ///
    /// Phase 5/5b.2 B-3.1 (`module_pass::limits`).
    MaxFunctionDefinitionsReached,

    /// The combined count of `struct_defs` and `enum_defs`
    /// exceeds `AdamantStructuralLimits::max_data_definitions`.
    ///
    /// Phase 5/5b.2 B-3.1 (`module_pass::limits`).
    MaxDataDefinitionsReached,

    /// A struct's declared-fields count exceeds
    /// `AdamantStructuralLimits::max_fields_in_struct`, OR an
    /// enum's cumulative fields-across-variants count exceeds
    /// the same limit. The `kind` field discriminates.
    ///
    /// Phase 5/5b.2 B-3.1 (`module_pass::limits`).
    MaxFieldDefinitionsReached {
        /// Whether the offending datatype is a struct or an
        /// enum.
        kind: FieldOwnerKind,
        /// Index into `struct_defs` (when `kind = Struct`) or
        /// `enum_defs` (when `kind = Enum`).
        def_idx: TableIndex,
    },

    /// An enum's variant count exceeds
    /// `AdamantStructuralLimits::max_variants_in_enum`.
    ///
    /// Phase 5/5b.2 B-3.1 (`module_pass::limits`).
    MaxVariantsInEnumReached {
        /// Index into `enum_defs` of the offending entry.
        def_idx: EnumDefinitionIndex,
    },

    /// A struct or enum definition is recursive (its own type
    /// transitively references itself through field-signature
    /// edges). The module-dependency graph is acyclic by
    /// construction at the inter-module level; this pass
    /// rejects intra-module recursion.
    ///
    /// Phase 5/5b.2 B-3.2 (`module_pass::recursive_data_def`).
    RecursiveDataDefinition {
        /// Whether the offending datatype is in `struct_defs`
        /// or `enum_defs`.
        kind: FieldOwnerKind,
        /// Index into the corresponding def table.
        idx: TableIndex,
    },

    /// The module's generic-instantiation graph contains a
    /// non-trivial strongly-connected component with at least
    /// one type-constructor-applied edge — a monomorphization-
    /// explosive loop. Cycles formed by identity edges alone
    /// (`f<T>` calls `f<T>`) are allowed since they don't grow
    /// types; cycles containing any `TyConApp` edge would
    /// require unbounded specializations and are rejected.
    ///
    /// Phase 5/5b.2 B-3.3 (`module_pass::instantiation_loops`).
    LoopInInstantiationGraph {
        /// Diagnostic summary of the offending SCC's nodes
        /// and `TyConApp` edges. Format matches upstream's
        /// `"edges with constructors: [{}], nodes: [{}]"`
        /// shape byte-faithfully (Layer B parity test pins
        /// the format). Not consensus-binding — the rejection
        /// is, but the formatting of the cycle's contents
        /// isn't.
        component_summary: String,
    },

    /// Module has no `b"adamant.privacy"` metadata entry but
    /// contains at least one `Visibility::Public` function.
    /// Per §6.2.1.6 Rule 2, every public function must carry a
    /// privacy annotation; the table is required when public
    /// functions are present.
    ///
    /// Cardinality contract per Q4 walk-back option (b):
    /// modules with only `Visibility::Friend` or
    /// `Visibility::Private` functions may omit the entry
    /// entirely. Visibility coverage is Public-only per Q3
    /// walk-back.
    ///
    /// Phase 5/5b.2 B-4.1 (`validator::rule_02_privacy`).
    MissingPrivacyMetadata,

    /// Module has more than one `b"adamant.privacy"` metadata
    /// entry. §6.2.1.6 Rule 2 + cardinality contract per Q4
    /// walk-back: at most one entry. The spec saying nothing
    /// about cardinality doesn't license contradictory privacy
    /// declarations.
    ///
    /// Phase 5/5b.2 B-4.1 (`validator::rule_02_privacy`).
    MultiplePrivacyMetadata {
        /// Number of entries with key `b"adamant.privacy"`
        /// the validator found. Always `>= 2`.
        count: usize,
    },

    /// The (single) `b"adamant.privacy"` metadata entry's value
    /// is not a valid BCS encoding of
    /// `Vec<(FunctionDefinitionIndex, u8)>`. Shared between
    /// [`super::rule_02_privacy`] (Rule 2 BCS-decode flow) and
    /// [`super::module_pass::privacy_metadata_structure`]
    /// (structural pass); per pipeline ordering the structural
    /// pass typically wins eager-error precedence.
    ///
    /// Phase 5/5b.2 B-4.1 + B-4.2 (shared variant per
    /// pipeline-ordering-eager-error sub-pattern).
    MalformedPrivacyMetadata {
        /// The BCS deserialiser's error rendered via `Display`.
        /// Carried as `String` (matching `MalformedMutabilityMetadata`
        /// from Wave 3a) so callers don't depend on the BCS
        /// crate's error-enum surface.
        bcs_error: String,
    },

    /// A `Visibility::Public` function definition is not
    /// covered by any entry in the privacy metadata table.
    /// Per Q3 walk-back, only Public functions are required
    /// to appear; Friend and Private functions need not.
    ///
    /// Phase 5/5b.2 B-4.1 (`validator::rule_02_privacy`).
    MissingPrivacyAnnotation {
        /// Index into the module's `function_defs` of the
        /// offending Public function.
        function_index: FunctionDefinitionIndex,
    },

    /// A `(FunctionDefinitionIndex, u8)` pair in a
    /// `b"adamant.privacy"` entry's payload has a byte
    /// outside the valid range `{0x00, 0x01}`. Per
    /// §6.2.1.3, the privacy byte values are `0x00`
    /// (transparent) and `0x01` (shielded); any other byte
    /// is rejected.
    ///
    /// Phase 5/5b.2 B-4.2
    /// (`module_pass::privacy_metadata_structure`).
    InvalidPrivacyAnnotationByte {
        /// The pair's `FunctionDefinitionIndex` (carried for
        /// diagnostics; the pass doesn't validate the index
        /// is in range here — the range check is a separate
        /// path. The error refers to the byte, not the
        /// index).
        function_index: FunctionDefinitionIndex,
        /// The offending byte value (anything outside
        /// `{0x00, 0x01}`).
        byte: u8,
    },

    /// A `(FunctionDefinitionIndex, u8)` pair in a
    /// `b"adamant.privacy"` entry's payload has a function
    /// index that is `>= function_defs.len()` — out of range
    /// for the module's function-definition table.
    ///
    /// Phase 5/5b.2 B-4.2
    /// (`module_pass::privacy_metadata_structure`).
    PrivacyEntryOutOfRange {
        /// The offending out-of-range index.
        function_index: FunctionDefinitionIndex,
        /// The current `function_defs.len()` for diagnostic
        /// context.
        function_defs_len: usize,
    },

    /// Two pairs in the same `b"adamant.privacy"` entry's
    /// payload share the same `FunctionDefinitionIndex`. A
    /// privacy table cannot carry contradictory annotations
    /// for the same function.
    ///
    /// Phase 5/5b.2 B-4.2
    /// (`module_pass::privacy_metadata_structure`).
    DuplicatePrivacyEntry {
        /// The duplicated index. The first pair was
        /// accepted; the duplicate triggers the rejection.
        function_index: FunctionDefinitionIndex,
    },

    /// The module's `module_handles` table is empty. A module
    /// must carry at least its own self-handle; an empty table
    /// has no anchor for any other handle reference.
    ///
    /// Mirrors upstream's `BoundsChecker::verify_module`
    /// short-circuit (`StatusCode::NO_MODULE_HANDLES`).
    ///
    /// Phase 5/5b.3 C-1.1
    /// (`module_pass::bounds_checker`).
    NoModuleHandles,

    /// An index into one of the module's pools is out of range.
    /// `kind` discriminates which pool overflowed (see
    /// [`adamant_bytecode_format::IndexKind`]); `idx` is the
    /// reported index value; `pool_len` is the addressed
    /// pool's length at the time of the check.
    ///
    /// Mirrors upstream's `bounds_error(StatusCode::INDEX_OUT_OF_BOUNDS,
    /// kind, idx, len)`. Used by the bounds-checker pass
    /// across every sub-check that resolves a `*Index`
    /// reference into a pool slot. The variant is generic
    /// across all `IndexKind` values; downstream passes that
    /// also surface index-out-of-range errors (e.g.,
    /// duplication-checker on field handles, signature-checker
    /// on signature tokens) reuse this variant in subsequent
    /// sub-arcs (C-2 and C-3).
    ///
    /// Phase 5/5b.3 C-1.1
    /// (`module_pass::bounds_checker`).
    IndexOutOfBounds {
        /// Which pool the offending index addressed. Reported
        /// as the index newtype's `ModuleIndex::KIND` constant
        /// at the call site; downstream consumers can pattern-
        /// match against [`adamant_bytecode_format::IndexKind`]
        /// variants.
        kind: IndexKind,
        /// The offending index value, narrowed to `TableIndex`
        /// (`u16`). All `*Index` newtypes wrap a `TableIndex`
        /// underneath the binary format, so the narrowing is
        /// always lossless.
        idx: TableIndex,
        /// The addressed pool's length at the time of the
        /// check. `idx >= pool_len` was the rejection condition.
        pool_len: usize,
    },

    /// A `Datatype` or `DatatypeInstantiation` signature token
    /// supplies a different number of type arguments than its
    /// addressed `DatatypeHandle` declares. For the bare
    /// `Datatype(idx)` form, `actual` is always `0`; for the
    /// `DatatypeInstantiation(idx, type_args)` form, `actual`
    /// is `type_args.len()`. Both code paths fire the same
    /// variant.
    ///
    /// Mirrors upstream's
    /// `StatusCode::NUMBER_OF_TYPE_ARGUMENTS_MISMATCH` error in
    /// `BoundsChecker::check_type`.
    ///
    /// Phase 5/5b.3 C-1.1
    /// (`module_pass::bounds_checker`).
    NumberOfTypeArgumentsMismatch {
        /// Index of the addressed `DatatypeHandle` whose
        /// type-parameter count was checked.
        datatype_handle_idx: DatatypeHandleIndex,
        /// Type-parameter count declared by the handle.
        expected: usize,
        /// Type-argument count supplied by the signature
        /// token. `0` for the bare `Datatype(_)` form; the
        /// `Vec::len()` for the `DatatypeInstantiation` form.
        actual: usize,
    },

    /// A function definition declares more locals than the
    /// binary format's per-function local-pool can address.
    /// Locals count is the sum of the locals signature length
    /// and the function's parameter count (per upstream's
    /// `locals.len().saturating_add(parameters.len())`); the
    /// bound is `LocalIndex::MAX` (`u8::MAX = 255`) per the
    /// `LocalIndex` type alias in `adamant-bytecode-format`.
    ///
    /// Mirrors upstream's `StatusCode::TOO_MANY_LOCALS` error
    /// in `BoundsChecker::check_code`.
    ///
    /// Phase 5/5b.3 C-1.4a
    /// (`module_pass::bounds_checker::check_function_def`,
    /// sub-step 4).
    TooManyLocals {
        /// Index of the offending function definition. Lowest-
        /// index offender is reported per the eager-error
        /// semantics.
        fn_def_idx: FunctionDefinitionIndex,
        /// Computed locals count
        /// (`locals.len() + parameters.len()`, saturating).
        count: usize,
        /// The maximum allowed locals count. Equal to
        /// `LocalIndex::MAX as usize` (255 at the binary-format
        /// version pinned by §6.2.1.2).
        max: usize,
    },
    // Rule 5 (no global storage instructions) is enforced at
    // parse time inside `AdamantDeserializer`; no separate
    // variant. Variants for Rules 3, 6, 7 land in subsequent
    // waves.
}

/// Whether a handle is a datatype handle or a function
/// handle. Used by
/// [`AdamantValidationError::TooManyTypeParameters`] to
/// discriminate which handle table the index applies to.
///
/// Phase 5/5b.2 B-3.1 (`module_pass::limits`).
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum HandleKind {
    /// Index references `module.datatype_handles`.
    DatatypeHandle,
    /// Index references `module.function_handles`.
    FunctionHandle,
}

impl core::fmt::Display for HandleKind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::DatatypeHandle => write!(f, "datatype handle"),
            Self::FunctionHandle => write!(f, "function handle"),
        }
    }
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
    // Naturally long: one match arm per `AdamantValidationError`
    // variant. Splitting obscures the diagnostic-message
    // dispatch shape — the long arm-list IS the table.
    #[allow(
        clippy::too_many_lines,
        reason = "dispatch over AdamantValidationError variants; the long match IS the table"
    )]
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
            Self::GenericMemberOpcodeMismatch {
                fn_def_idx,
                code_offset,
            } => write!(
                f,
                "function {} offset {code_offset}: generic vs non-generic \
                 instruction flavor does not match target's type-parameter \
                 count (whitepaper §6.2.1.8 step 3, \
                 `module_pass::instruction_consistency`)",
                fn_def_idx.0
            ),
            Self::VecPackUnpackArgOutOfRange {
                fn_def_idx,
                code_offset,
                num,
            } => write!(
                f,
                "function {} offset {code_offset}: VecPack/VecUnpack element count \
                 {num} exceeds u16::MAX (whitepaper §6.2.1.8 step 3, \
                 `module_pass::instruction_consistency`)",
                fn_def_idx.0
            ),
            Self::TooManyVectorElements { idx } => write!(
                f,
                "constant pool entry {} vector length exceeds \
                 max_constant_vector_len (whitepaper §6.2.1.8 step 3, \
                 `module_pass::limits`)",
                idx.0
            ),
            Self::TooManyTypeParameters { kind, idx } => write!(
                f,
                "{kind} {idx}: type-parameter count exceeds \
                 max_generic_instantiation_length (whitepaper §6.2.1.8 \
                 step 3, `module_pass::limits`)"
            ),
            Self::TooManyParameters { idx } => write!(
                f,
                "function handle {}: parameter count exceeds \
                 max_function_parameters (whitepaper §6.2.1.8 step 3, \
                 `module_pass::limits`)",
                idx.0
            ),
            Self::TooManyTypeNodes => write!(
                f,
                "signature-token tree exceeds max_type_nodes (whitepaper \
                 §6.2.1.8 step 3, `module_pass::limits`)"
            ),
            Self::IdentifierTooLong { idx } => write!(
                f,
                "identifier {} exceeds max_identifier_len (whitepaper \
                 §6.2.1.8 step 3, `module_pass::limits`)",
                idx.0
            ),
            Self::InvalidIdentifier { idx } => write!(
                f,
                "identifier {} is the disallowed `<SELF>` literal \
                 (whitepaper §6.2.1.8 step 3, `module_pass::limits`)",
                idx.0
            ),
            Self::MaxFunctionDefinitionsReached => write!(
                f,
                "function-definition count exceeds max_function_definitions \
                 (whitepaper §6.2.1.8 step 3, `module_pass::limits`)"
            ),
            Self::MaxDataDefinitionsReached => write!(
                f,
                "combined struct-and-enum-definition count exceeds \
                 max_data_definitions (whitepaper §6.2.1.8 step 3, \
                 `module_pass::limits`)"
            ),
            Self::MaxFieldDefinitionsReached { kind, def_idx } => write!(
                f,
                "{kind} definition {def_idx}: field count exceeds \
                 max_fields_in_struct (whitepaper §6.2.1.8 step 3, \
                 `module_pass::limits`)"
            ),
            Self::MaxVariantsInEnumReached { def_idx } => write!(
                f,
                "enum definition {}: variant count exceeds \
                 max_variants_in_enum (whitepaper §6.2.1.8 step 3, \
                 `module_pass::limits`)",
                def_idx.0
            ),
            Self::RecursiveDataDefinition { kind, idx } => write!(
                f,
                "{kind} definition {idx} is recursive (transitively \
                 references itself through field-signature edges) \
                 (whitepaper §6.2.1.8 step 3, \
                 `module_pass::recursive_data_def`)"
            ),
            Self::LoopInInstantiationGraph { component_summary } => write!(
                f,
                "monomorphization-explosive loop in generic-instantiation \
                 graph: {component_summary} (whitepaper §6.2.1.8 step 3, \
                 `module_pass::instantiation_loops`)"
            ),
            Self::MissingPrivacyMetadata => write!(
                f,
                "module has at least one Public function but no \
                 `adamant.privacy` metadata entry \
                 (whitepaper §6.2.1.6 Rule 2)"
            ),
            Self::MultiplePrivacyMetadata { count } => write!(
                f,
                "expected at most one `adamant.privacy` metadata entry, \
                 found {count} (whitepaper §6.2.1.6 Rule 2)"
            ),
            Self::MalformedPrivacyMetadata { bcs_error } => write!(
                f,
                "`adamant.privacy` metadata value is not a valid BCS \
                 encoding of Vec<(FunctionDefinitionIndex, u8)>: \
                 {bcs_error} (whitepaper §6.2.1.6 Rule 2)"
            ),
            Self::MissingPrivacyAnnotation { function_index } => write!(
                f,
                "Public function {} has no entry in the `adamant.privacy` \
                 metadata table (whitepaper §6.2.1.6 Rule 2)",
                function_index.0
            ),
            Self::InvalidPrivacyAnnotationByte {
                function_index,
                byte,
            } => write!(
                f,
                "privacy entry for function {} has invalid byte 0x{byte:02X} \
                 (expected 0x00 or 0x01) (whitepaper §6.2.1.3, \
                 `module_pass::privacy_metadata_structure`)",
                function_index.0
            ),
            Self::PrivacyEntryOutOfRange {
                function_index,
                function_defs_len,
            } => write!(
                f,
                "privacy entry function index {} out of range (function_defs \
                 has {function_defs_len} entries) (whitepaper §6.2.1.3, \
                 `module_pass::privacy_metadata_structure`)",
                function_index.0
            ),
            Self::DuplicatePrivacyEntry { function_index } => write!(
                f,
                "privacy entry for function {} appears more than once \
                 (whitepaper §6.2.1.3, \
                 `module_pass::privacy_metadata_structure`)",
                function_index.0
            ),
            Self::NoModuleHandles => write!(
                f,
                "module has no module_handles entries; a module must carry at least \
                 its own self-handle (whitepaper §6.2.1.8 step 3, \
                 `module_pass::bounds_checker`)"
            ),
            Self::IndexOutOfBounds {
                kind,
                idx,
                pool_len,
            } => write!(
                f,
                "{kind} index {idx} out of range for pool of length {pool_len} \
                 (whitepaper §6.2.1.8 step 3, `module_pass::bounds_checker`)"
            ),
            Self::NumberOfTypeArgumentsMismatch {
                datatype_handle_idx,
                expected,
                actual,
            } => write!(
                f,
                "datatype handle {} expects {expected} type argument(s), got {actual} \
                 (whitepaper §6.2.1.8 step 3, `module_pass::bounds_checker`)",
                datatype_handle_idx.0
            ),
            Self::TooManyLocals {
                fn_def_idx,
                count,
                max,
            } => write!(
                f,
                "function definition {}: locals count {count} exceeds maximum {max} \
                 (whitepaper §6.2.1.8 step 3, \
                 `module_pass::bounds_checker::check_function_def`)",
                fn_def_idx.0
            ),
        }
    }
}

impl std::error::Error for AdamantValidationError {}
