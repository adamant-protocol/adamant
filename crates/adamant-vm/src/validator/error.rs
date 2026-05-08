//! Adamant validator error type.
//!
//! [`AdamantValidationError`] is the single error type returned
//! by [`super::verify_module`]. Per-rule variants carry rule-
//! specific diagnostic data for the Adamant-specific rules; per-
//! pass variants carry pass-specific diagnostic data for the
//! Adamant-native module-level and per-function passes.
//!
//! Eager semantics: callers receive the first violation
//! encountered.
//!
//! Phase 5/5b.5 E-1a removed the transitional `SuiVerifier`
//! variant when the Sui-verifier bridge tore out; per-pass
//! Adamant-native coverage is now the only verification path.

use adamant_bytecode_format::{
    CodeOffset, ConstantPoolIndex, DatatypeHandleIndex, EnumDefinitionIndex,
    FunctionDefinitionIndex, FunctionHandleIndex, IdentifierIndex, IndexKind,
    StructDefinitionIndex, TableIndex,
};
use adamant_types::Address;

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
    /// Sits between [`Self::AdamantDeserializer`] and the step-3
    /// module-level passes in the pipeline: after Adamant's
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

    /// A bytecode operand index is out of range for its
    /// addressed pool. Carries the offending function-def
    /// index, the bytecode offset within that function's body,
    /// the addressed pool's `IndexKind`, the offending index
    /// value, and the pool's length.
    ///
    /// Distinct from [`Self::IndexOutOfBounds`] (which lacks
    /// code-unit context). Mirrors upstream's
    /// `offset_out_of_bounds_error` shape and parallels B-2.4's
    /// [`Self::GenericMemberOpcodeMismatch`] in carrying
    /// `fn_def_idx` + `code_offset` for code-unit-context
    /// errors.
    ///
    /// Used by the bounds-checker pass at sub-steps 5 (per-
    /// bytecode wide match), 6 (jump-table validation), and 7
    /// (Adamant-extension per-instruction semantics) of
    /// `check_function_def`.
    ///
    /// Phase 5/5b.3 C-1.4b
    /// (`module_pass::bounds_checker`).
    CodeIndexOutOfBounds {
        /// Index of the offending function definition.
        fn_def_idx: FunctionDefinitionIndex,
        /// Bytecode offset within the function's body where
        /// the OOB operand lives. For jump-table errors,
        /// `code_offset` is the bytecode offset of the
        /// `VariantSwitch` instruction whose jump table is
        /// being validated.
        code_offset: CodeOffset,
        /// Which pool the offending index addressed. See
        /// [`adamant_bytecode_format::IndexKind`].
        kind: IndexKind,
        /// The offending index value, narrowed to `TableIndex`
        /// (`u16`).
        idx: TableIndex,
        /// The addressed pool's length at the time of the
        /// check. `idx >= pool_len` was the rejection condition.
        pool_len: usize,
    },

    /// A jump table for a `VariantSwitch` instruction has a
    /// length that doesn't match the addressed enum's variant
    /// count.
    ///
    /// Mirrors upstream's `StatusCode::INVALID_ENUM_SWITCH`
    /// error in `BoundsChecker::check_code`'s jump-table
    /// validation. The check enforces that every enum variant
    /// has exactly one branch destination — distinguishing
    /// "valid `VariantSwitch` over a complete enum" from
    /// "structurally-malformed jump table that doesn't cover
    /// every variant."
    ///
    /// Phase 5/5b.3 C-1.4b
    /// (`module_pass::bounds_checker`, jump-table validation).
    InvalidEnumSwitch {
        /// Index of the offending function definition.
        fn_def_idx: FunctionDefinitionIndex,
        /// Index into `code_unit.jump_tables` of the offending
        /// jump table.
        jump_table_idx: TableIndex,
        /// Length of the offending jump table.
        jump_table_len: usize,
        /// Variant count of the addressed enum (the value the
        /// jump table's length should equal).
        expected_variants_count: usize,
    },

    /// A pool entry duplicates another entry with the same
    /// identity-defining key. The `kind` field discriminates
    /// which pool is offending; the `idx` field is the index
    /// of the **second occurrence** (the one rejected — the
    /// first occurrence is accepted as the canonical entry).
    ///
    /// Mirrors upstream's `StatusCode::DUPLICATE_ELEMENT`
    /// carrying `IndexKind` discriminator. Used by 14+ sub-
    /// checks of [`module_pass::duplication_checker`]:
    /// identifiers, address-identifiers, constants, signatures,
    /// module-handles, friend-declarations, datatype-handles
    /// (by `(module, name)`), function-handles (by `(module,
    /// name)`), function-instantiations, variant-handles (by
    /// `(enum_def, variant)`), field-handles, struct-
    /// instantiations, enum-instantiations, field-
    /// instantiations, struct-defs (by `struct_handle`),
    /// joint struct-and-enum-defs (by `DatatypeHandleIndex`),
    /// per-field-name within a struct/enum-variant, and
    /// function-defs (by `function`).
    ///
    /// Phase 5/5b.3 C-2
    /// (`module_pass::duplication_checker`).
    ///
    /// [`module_pass::duplication_checker`]: super::module_pass::duplication_checker
    DuplicateElement {
        /// Which pool the duplication was detected in.
        kind: IndexKind,
        /// Index of the second occurrence (the one rejected —
        /// the first occurrence is the canonical entry).
        idx: TableIndex,
    },

    /// A struct definition has a `Declared` field-information
    /// variant with zero fields. Adamant follows upstream's
    /// stance that a zero-field struct is structurally
    /// meaningless: the bytecode format reserves zero fields
    /// for native structs, and a declared struct must declare
    /// at least one field.
    ///
    /// Mirrors upstream's `StatusCode::ZERO_SIZED_STRUCT`.
    ///
    /// Phase 5/5b.3 C-2
    /// (`module_pass::duplication_checker::check_struct_definitions`).
    ZeroSizedStruct {
        /// Index of the offending struct definition.
        def_idx: StructDefinitionIndex,
    },

    /// An enum definition has zero variants. Adamant follows
    /// upstream's stance that a zero-variant enum is
    /// structurally meaningless: the variant-tag domain would
    /// be empty, and no `VariantSwitch` could ever produce a
    /// valid match.
    ///
    /// Mirrors upstream's `StatusCode::ZERO_SIZED_ENUM`.
    ///
    /// Phase 5/5b.3 C-2
    /// (`module_pass::duplication_checker::check_enum_definitions`).
    ZeroSizedEnum {
        /// Index of the offending enum definition.
        def_idx: EnumDefinitionIndex,
    },

    /// A struct/enum/function definition references a
    /// `DatatypeHandle` or `FunctionHandle` whose `module`
    /// field doesn't point at the module's own
    /// `self_module_handle_idx`. A definition must always be
    /// owned by the module it's defined in; cross-module
    /// definitions are not representable in the bytecode
    /// format. This rejection catches malformed inputs that
    /// passed bounds checking but place a definition's handle
    /// in another module's slot.
    ///
    /// Mirrors upstream's `StatusCode::INVALID_MODULE_HANDLE`.
    ///
    /// Phase 5/5b.3 C-2
    /// (`module_pass::duplication_checker`).
    InvalidModuleHandle {
        /// Whether the offending definition is a struct, enum,
        /// or function. See [`DefKind`].
        kind: DefKind,
        /// Index of the offending definition.
        def_idx: TableIndex,
    },

    /// A function definition's `acquires_global_resources`
    /// list contains the same `StructDefinitionIndex` more
    /// than once. The list is structurally always-empty in
    /// valid Adamant modules per §6.2.1.6 Rule 5 (no global
    /// storage instructions); the duplication check is
    /// preserved structurally for byte-faithful upstream
    /// parity.
    ///
    /// Mirrors upstream's
    /// `StatusCode::DUPLICATE_ACQUIRES_ANNOTATION`.
    ///
    /// Phase 5/5b.3 C-2
    /// (`module_pass::duplication_checker::check_function_definitions`).
    DuplicateAcquiresAnnotation {
        /// Index of the offending function definition.
        fn_def_idx: FunctionDefinitionIndex,
    },

    /// A `DatatypeHandle` or `FunctionHandle` whose `module`
    /// field references the module's `self_module_handle_idx`
    /// has no corresponding definition in `struct_defs` /
    /// `enum_defs` / `function_defs`. Self-module handles
    /// must be implemented by a definition; foreign-module
    /// handles are imports and need no implementation.
    ///
    /// Mirrors upstream's `StatusCode::UNIMPLEMENTED_HANDLE`.
    ///
    /// Phase 5/5b.3 C-2
    /// (`module_pass::duplication_checker::check_datatype_handles_implemented`
    /// and the analogous function-handle path inside
    /// `check_function_definitions`).
    UnimplementedHandle {
        /// Whether the offending handle is a datatype handle
        /// or a function handle.
        kind: HandleKind,
        /// Index of the offending handle.
        idx: TableIndex,
    },

    /// A reference (`&T` or `&mut T`) appears in a signature
    /// position where references are not allowed. The
    /// `reason` field discriminates the rejection context:
    /// `RefInsideContainer` for refs nested inside vector or
    /// datatype-instantiation tokens; `RefAsFieldType` for
    /// refs at the top level of a struct/enum field signature.
    ///
    /// Mirrors upstream's `StatusCode::INVALID_SIGNATURE_TOKEN`
    /// produced by `SignatureChecker::check_signature_token`'s
    /// reference-rejection arm.
    ///
    /// Phase 5/5b.3 C-3
    /// (`module_pass::signature_checker`).
    InvalidSignatureToken {
        /// Discriminator for the rejection context. See
        /// [`InvalidSignatureReason`].
        reason: InvalidSignatureReason,
    },

    /// A generic-instance type-argument list has a different
    /// number of arguments than the addressed handle's
    /// declared type-parameter count. Distinct from
    /// [`Self::NumberOfTypeArgumentsMismatch`] (which fires at
    /// the bounds-check layer for `Datatype` /
    /// `DatatypeInstantiation` signature-token references);
    /// this variant fires at generic-call-site mismatches in
    /// the signature-checker layer (`CallGeneric`,
    /// `PackGeneric`, `PackVariantGeneric`, etc.).
    ///
    /// Mirrors upstream's
    /// `StatusCode::NUMBER_OF_TYPE_ARGUMENTS_MISMATCH` from
    /// `SignatureChecker::check_generic_instance`.
    ///
    /// Phase 5/5b.3 C-3
    /// (`module_pass::signature_checker`).
    TypeArgumentsArityMismatch {
        /// Type-parameter count declared by the addressed
        /// handle.
        expected: usize,
        /// Type-argument count supplied by the call site.
        actual: usize,
    },

    /// A generic-instance type argument's effective ability
    /// set doesn't contain the constraint declared by the
    /// addressed handle's type parameter. The
    /// `type_param_idx` field identifies which type parameter
    /// the violation belongs to.
    ///
    /// Mirrors upstream's `StatusCode::CONSTRAINT_NOT_SATISFIED`
    /// from `SignatureChecker::check_generic_instance`.
    ///
    /// Phase 5/5b.3 C-3
    /// (`module_pass::signature_checker`).
    ConstraintNotSatisfied {
        /// Index (within the constraints list) of the
        /// type parameter whose constraint wasn't satisfied.
        type_param_idx: u16,
    },

    /// A phantom type parameter is used in a non-phantom
    /// position. Phantom parameters can only appear at
    /// positions whose enclosing instantiation flags them as
    /// phantom; using one in a non-phantom slot is rejected.
    ///
    /// Mirrors upstream's
    /// `StatusCode::INVALID_PHANTOM_TYPE_PARAM_POSITION` from
    /// `SignatureChecker::check_phantom_params`.
    ///
    /// Phase 5/5b.3 C-3
    /// (`module_pass::signature_checker`).
    InvalidPhantomTypeParamPosition,

    /// A vec-op instruction (`VecPack`, `VecLen`, `VecImmBorrow`,
    /// `VecMutBorrow`, `VecPushBack`, `VecPopBack`, `VecUnpack`,
    /// `VecSwap`) carries a type-argument signature whose
    /// length is not exactly 1. Vec ops require exactly one
    /// type argument (the element type).
    ///
    /// Mirrors upstream's "expected 1 type token for vector
    /// operations" rejection from
    /// `SignatureChecker::verify_code`.
    ///
    /// Phase 5/5b.3 C-3
    /// (`module_pass::signature_checker`).
    VecOpExpectedSingleTypeArgument {
        /// Actual type-argument count supplied by the vec-op
        /// instruction's signature.
        actual: usize,
    },
    /// Function body is empty (zero instructions).
    ///
    /// Whitepaper §6.2.1.8 step 4 (per-function passes:
    /// control-flow validation). Phase 5/5b.4 D-2.
    EmptyFunctionBody {
        /// Function-definition index whose body is empty.
        fn_def_idx: FunctionDefinitionIndex,
    },
    /// Function body's last instruction is not an unconditional
    /// terminator (`Ret`, `Abort`, `Branch`, `VariantSwitch`).
    /// Without an unconditional terminator the function would
    /// fall off the end of its body.
    ///
    /// Adamant extensions are non-branching by construction
    /// ([`BytecodeInstruction::is_unconditional_branch`][branch]
    /// always returns `false` for any `Adamant(_)` arm); a
    /// function ending in an Adamant extension is therefore
    /// rejected here as missing a terminator.
    ///
    /// Whitepaper §6.2.1.8 step 4 (per-function passes:
    /// control-flow validation). Phase 5/5b.4 D-2.
    ///
    /// [branch]: crate::bytecode::BytecodeInstruction::is_unconditional_branch
    MissingFallthroughTerminator {
        /// Function-definition index whose body falls through.
        fn_def_idx: FunctionDefinitionIndex,
        /// Bytecode offset of the last instruction in the body.
        code_offset: CodeOffset,
    },
    /// Function body's control-flow graph is irreducible per
    /// Tarjan 1974, or its loop-nesting depth exceeds
    /// [`AdamantStructuralLimits::max_loop_depth`][max].
    ///
    /// Irreducible CFGs cannot be decomposed into nested loops,
    /// which makes the verifier's downstream
    /// abstract-interpretation passes (Phase 5/5b.4 D-3.. /
    /// 5/5b.5) potentially run for pathologically long.
    ///
    /// Whitepaper §6.2.1.8 step 4 (per-function passes:
    /// control-flow validation). Phase 5/5b.4 D-2.
    ///
    /// [max]: super::config::AdamantStructuralLimits
    IrreducibleControlFlow {
        /// Function-definition index whose CFG was rejected.
        fn_def_idx: FunctionDefinitionIndex,
        /// Block-entry offset where the irreducibility was
        /// detected. For [`IrreducibleReason::InvalidLoopSplit`],
        /// the offending non-dominated pred's block. For
        /// [`IrreducibleReason::LoopMaxDepthReached`], the
        /// loop head whose nesting exceeds the limit.
        code_offset: CodeOffset,
        /// Sub-reason discriminator.
        reason: IrreducibleReason,
    },
    /// A basic block's accumulated push count exceeded
    /// [`AdamantStructuralLimits::max_push_size`][max].
    /// Bounds runaway-growth at deploy time.
    ///
    /// Whitepaper §6.2.1.8 step 4 (per-function passes:
    /// operand-stack discipline). Phase 5/5b.4 D-3.
    ///
    /// [max]: super::config::AdamantStructuralLimits
    StackPushOverflow {
        /// Function-definition index whose body overflowed.
        fn_def_idx: FunctionDefinitionIndex,
        /// Block-entry offset where the overflow was detected
        /// (mirrors upstream's `at_code_offset(_, block_start)`
        /// placement).
        code_offset: CodeOffset,
    },
    /// An instruction within a basic block would pop more
    /// values than the block's running stack delta supports —
    /// the abstract operand stack would go negative.
    ///
    /// Whitepaper §6.2.1.8 step 4. Phase 5/5b.4 D-3.
    StackUnderflow {
        /// Function-definition index whose body underflowed.
        fn_def_idx: FunctionDefinitionIndex,
        /// Block-entry offset of the offending block (mirrors
        /// upstream's at-block-start placement).
        code_offset: CodeOffset,
    },
    /// A basic block ends with a non-zero stack delta. For
    /// non-`Ret`-terminated blocks, the delta must be zero. For
    /// `Ret`-terminated blocks, the pre-`Ret` depth must equal
    /// the function's return arity (`Ret` pops the return
    /// values, leaving a net delta of zero); a mismatch here
    /// also surfaces as this variant.
    ///
    /// Whitepaper §6.2.1.8 step 4. Phase 5/5b.4 D-3.
    UnbalancedStackAtBlockEnd {
        /// Function-definition index whose body has an
        /// unbalanced block.
        fn_def_idx: FunctionDefinitionIndex,
        /// Block-entry offset of the offending block.
        code_offset: CodeOffset,
    },
    /// `StLoc(idx)` would destroy a value at `idx` whose type
    /// lacks the `drop` ability. Local was `Available` or
    /// `MaybeAvailable` and the `StLoc` would overwrite the
    /// prior value.
    ///
    /// Whitepaper §6.2.1.8 step 4 (per-function passes:
    /// locals safety). Phase 5/5b.4 D-4.
    StLocDestroysNonDrop {
        /// Function-definition index whose body fired the
        /// rejection.
        fn_def_idx: FunctionDefinitionIndex,
        /// Bytecode offset of the offending `StLoc`.
        code_offset: CodeOffset,
    },
    /// `MoveLoc(idx)` was applied to a local that may not be
    /// available on every CFG path reaching this offset.
    /// Locals safety rejects to preserve the move-once
    /// linearity invariant.
    ///
    /// Whitepaper §6.2.1.8 step 4. Phase 5/5b.4 D-4.
    MoveLocUnavailable {
        /// Function-definition index whose body fired the
        /// rejection.
        fn_def_idx: FunctionDefinitionIndex,
        /// Bytecode offset of the offending `MoveLoc`.
        code_offset: CodeOffset,
    },
    /// `CopyLoc(idx)` was applied to a local that may not be
    /// available on every CFG path. Even though copy doesn't
    /// transfer ownership, an `Unavailable` local has no
    /// value to copy.
    ///
    /// Whitepaper §6.2.1.8 step 4. Phase 5/5b.4 D-4.
    CopyLocUnavailable {
        /// Function-definition index whose body fired the
        /// rejection.
        fn_def_idx: FunctionDefinitionIndex,
        /// Bytecode offset of the offending `CopyLoc`.
        code_offset: CodeOffset,
    },
    /// `MutBorrowLoc(idx)` or `ImmBorrowLoc(idx)` was applied
    /// to a local that may not be available. Borrowing
    /// requires the referent to exist.
    ///
    /// Whitepaper §6.2.1.8 step 4. Phase 5/5b.4 D-4.
    BorrowLocUnavailable {
        /// Function-definition index whose body fired the
        /// rejection.
        fn_def_idx: FunctionDefinitionIndex,
        /// Bytecode offset of the offending borrow
        /// instruction.
        code_offset: CodeOffset,
    },
    /// `Ret` was reached with at least one local still
    /// `Available` or `MaybeAvailable` whose type lacks the
    /// `drop` ability. Implicit destruction of non-drop
    /// values is rejected.
    ///
    /// Whitepaper §6.2.1.8 step 4. Phase 5/5b.4 D-4.
    RetWithUndroppedLocals {
        /// Function-definition index whose body fired the
        /// rejection.
        fn_def_idx: FunctionDefinitionIndex,
        /// Bytecode offset of the offending `Ret`.
        code_offset: CodeOffset,
    },
    /// Per-instruction type-safety check rejected an
    /// operand-type mismatch. Carries a [`TypeMismatchReason`]
    /// closed-enum sub-reason for diagnostic precision while
    /// keeping the top-level variant count bounded.
    ///
    /// Whitepaper §6.2.1.8 step 4 (per-function passes:
    /// type safety). Phase 5/5b.4 D-5a.
    TypeMismatch {
        /// Function-definition index whose body fired the
        /// rejection.
        fn_def_idx: FunctionDefinitionIndex,
        /// Bytecode offset of the offending instruction.
        code_offset: CodeOffset,
        /// Sub-reason discriminator.
        reason: TypeMismatchReason,
    },
    /// Per-instruction reference-safety check rejected a
    /// borrow-graph violation (dangling reference, mutable-
    /// reference aliasing, etc.). Carries a
    /// [`BorrowViolationReason`] closed-enum sub-reason for
    /// diagnostic precision while keeping the top-level variant
    /// count bounded.
    ///
    /// Whitepaper §6.2.1.8 step 4 (per-function passes:
    /// reference safety; whitepaper §6.2.1.6 Rule "reference
    /// safety"). Phase 5/5b.4 D-5b.
    BorrowViolation {
        /// Function-definition index whose body fired the
        /// rejection.
        fn_def_idx: FunctionDefinitionIndex,
        /// Bytecode offset of the offending instruction.
        code_offset: CodeOffset,
        /// Sub-reason discriminator.
        reason: BorrowViolationReason,
    },
    /// Rule 3 (privacy consistency) call-graph walker found
    /// an `Invoke*` instruction in a function reachable from
    /// a public function whose declared privacy mode is the
    /// opposite of the instruction's mode. Carries a
    /// [`PrivacyConsistencyViolationReason`] closed-enum sub-
    /// reason discriminator. Single-module scope: the call
    /// graph is bounded to the deploying module's own
    /// function bodies.
    ///
    /// Whitepaper §6.2.1.6 Rule 3. Phase 5/5b.4 D-5c (single-
    /// module). The cross-module variant
    /// [`Self::CrossModulePrivacyConsistencyViolation`] covers
    /// call edges across module boundaries per §6.2.1.6 line
    /// 477's "Cross-module call graphs are statically checked
    /// at deploy time against the annotations of dependency
    /// modules visible on chain at that moment".
    PrivacyConsistencyViolation {
        /// Public function (entry point of the call graph)
        /// whose declared privacy mode is being violated.
        calling_public_index: FunctionDefinitionIndex,
        /// Function (possibly the public function itself, or
        /// a transitively-called private function) containing
        /// the offending `Invoke*` instruction.
        violating_function_index: FunctionDefinitionIndex,
        /// Bytecode offset of the offending `Invoke*`.
        code_offset: CodeOffset,
        /// Sub-reason discriminator.
        reason: PrivacyConsistencyViolationReason,
    },
    /// Rule 3 (privacy consistency) cross-module call-graph
    /// walker found a privacy-mismatched call edge across a
    /// module boundary. The deploying module's call graph
    /// reaches a function in a dependency module whose
    /// declared privacy annotation conflicts with the
    /// reachable-from public function's mode.
    ///
    /// Reuses [`PrivacyConsistencyViolationReason`] sub-reason
    /// closed enum with single-module
    /// [`Self::PrivacyConsistencyViolation`] (same-rule-
    /// different-scope-shares-sub-reason-enum methodology
    /// pattern; canonical at Phase 5/5b.5 E-2). The
    /// `target_module` + `target_function_handle_idx` fields
    /// localize the cross-module call site within the
    /// dependency module; `target_module_id` carries the
    /// dependency module's `(address, name)` identity so
    /// auditors can trace the call across modules.
    ///
    /// Whitepaper §6.2.1.6 Rule 3 + line 477. Phase 5/5b.5
    /// E-2 (cross-module).
    CrossModulePrivacyConsistencyViolation {
        /// Public function in the deploying module (entry
        /// point of the cross-module call graph) whose
        /// declared privacy mode is being violated.
        calling_public_index: FunctionDefinitionIndex,
        /// Function in the deploying module (possibly the
        /// public function itself, or a transitively-called
        /// private function) containing the call instruction
        /// that crosses the module boundary.
        calling_function_index: FunctionDefinitionIndex,
        /// Bytecode offset of the cross-module call
        /// (`Call`/`CallGeneric`) within the calling
        /// function's body.
        code_offset: CodeOffset,
        /// `(address, name)` identity of the dependency
        /// module the call resolves to.
        target_module_id: super::cross_module::ModuleId,
        /// `FunctionHandleIndex` value within the deploying
        /// module's `function_handles[]` table that the call
        /// instruction references. The handle's
        /// `(module, name)` resolves to the cross-module
        /// target; the handle's name resolves through the
        /// dependency module's own `function_defs[]` to
        /// surface the target function's privacy annotation.
        calling_function_handle_idx: FunctionHandleIndex,
        /// Sub-reason discriminator. Reuses single-module
        /// [`PrivacyConsistencyViolationReason`] per the
        /// same-rule-different-scope-shares-sub-reason-enum
        /// pattern.
        reason: PrivacyConsistencyViolationReason,
    },
    // Rule 5 (no global storage instructions) is enforced at
    // parse time inside `AdamantDeserializer`; no separate
    // variant.
    /// Rule 6 (no dynamic dispatch) found a `Call` /
    /// `CallGeneric` whose target resolves to a Sui-Move
    /// dynamic-field module (address `0x2`, module name
    /// `dynamic_field` or `dynamic_object_field`) without the
    /// deploying module carrying a `b"adamant.allows_dynamic"`
    /// metadata entry whose value is `true`.
    ///
    /// Whitepaper §6.2.1.6 Rule 6 + line 485
    /// (forbidden-module enumeration). Phase 5/5b.5 E-3.
    ///
    /// The `calling_function_index` + `code_offset` localize
    /// the offending call instruction within the deploying
    /// module; `calling_function_handle_idx` carries the raw
    /// `FunctionHandleIndex` referenced by the
    /// `Call`/`CallGeneric` so auditors can resolve the
    /// `(target_module, target_function_name)` pair via the
    /// module's handle tables. `reason` discriminates which
    /// dynamic-field family triggered the rejection.
    DynamicDispatchViolation {
        /// Function in the deploying module containing the
        /// offending `Call`/`CallGeneric`.
        calling_function_index: FunctionDefinitionIndex,
        /// Bytecode offset of the offending instruction.
        code_offset: CodeOffset,
        /// `FunctionHandleIndex` referenced by the
        /// `Call`/`CallGeneric` instruction.
        calling_function_handle_idx: FunctionHandleIndex,
        /// Sub-reason discriminator.
        reason: DynamicDispatchViolationReason,
    },
    /// Rule 7 (privacy-circuit instructions in shielded
    /// context only) found one of `GenerateProof`,
    /// `VerifyProof`, `RecursiveVerify`, or `ReleaseSubViewKey`
    /// in a function reachable from a `#[transparent]` public
    /// function (or its transitively-called callees). Per
    /// §6.2.1.6 Rule 7: these instructions may appear only in
    /// the body of `#[shielded]` functions or their internal
    /// callees; calling them from a transparent context is
    /// rejected at verification time.
    ///
    /// Whitepaper §6.2.1.6 Rule 7. Phase 5/5b.5 E-4.
    ///
    /// Cross-module Rule 7 enforcement is NOT a separate
    /// walker: cross-module privacy-mode boundary crossings
    /// are caught by Rule 3 (single-module at D-5c +
    /// cross-module at E-2b's
    /// `cross_module::rule_03_privacy_consistency`); within
    /// each module, this walker catches privacy-circuit
    /// instructions in transparent-reachable code. The
    /// composition (Rule 3 cross-module + Rule 7 per-module)
    /// covers transparent → shielded boundary → privacy-
    /// circuit-instruction transitively. 1st instance of
    /// rule-composition-for-cross-module-coverage methodology
    /// pattern; registered at E-4 plan-gate Q6.
    PrivacyCircuitContextViolation {
        /// `#[transparent]` public function (entry point of
        /// the call graph) whose declared mode is being
        /// violated.
        calling_public_index: FunctionDefinitionIndex,
        /// Function (possibly the public function itself, or
        /// a transitively-called private function) containing
        /// the offending privacy-circuit instruction.
        violating_function_index: FunctionDefinitionIndex,
        /// Bytecode offset of the offending privacy-circuit
        /// instruction.
        code_offset: CodeOffset,
        /// Sub-reason discriminator (which privacy-circuit
        /// instruction triggered the rejection).
        reason: PrivacyCircuitContextViolationReason,
    },
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

/// Whether the offending definition on an
/// [`AdamantValidationError::InvalidModuleHandle`] is a struct,
/// enum, or function definition. Distinct from
/// [`FieldOwnerKind`] (`Struct | Enum`) — function definitions
/// don't have field-ownership semantics, so a third variant
/// would force `FieldOwnerKind`'s name to drift.
///
/// Per the deliberate-Adamant-decision pattern (third instance
/// after B-4.2's byte→range→duplicate ordering and C-1.3's
/// `check_field_def` extraction): introduce `DefKind` deliberately
/// rather than overloading `FieldOwnerKind`. Q2 disposition at
/// the C-2 plan-gate.
///
/// Phase 5/5b.3 C-2
/// (`module_pass::duplication_checker`).
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum DefKind {
    /// The offending definition is a struct definition;
    /// `def_idx` indexes `struct_defs`.
    Struct,
    /// The offending definition is an enum definition;
    /// `def_idx` indexes `enum_defs`.
    Enum,
    /// The offending definition is a function definition;
    /// `def_idx` indexes `function_defs`.
    Function,
}

impl core::fmt::Display for DefKind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Struct => write!(f, "struct"),
            Self::Enum => write!(f, "enum"),
            Self::Function => write!(f, "function"),
        }
    }
}

/// Discriminator for [`AdamantValidationError::InvalidSignatureToken`]
/// rejection contexts.
///
/// Per Q3 disposition at the C-3 plan-gate: start with 2
/// variants (`RefInsideContainer` for refs nested inside
/// vector/datatype-instantiation; `RefAsFieldType` for refs at
/// the top level of struct/enum-variant field signatures);
/// evaluate adding `RefInVecOpTypeArg` if structurally distinct
/// at implementation. Resolved at implementation: vec-op
/// type-argument context shares the `check_signature_tokens`
/// shape with field-context (both reject all references at
/// the same recursion entry), so a third variant didn't
/// surface. Plan-gate's plan-incremental-disposition-resolved-
/// empirically pattern applied (5th plan-gate resolution
/// shape).
///
/// Phase 5/5b.3 C-3
/// (`module_pass::signature_checker`).
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum InvalidSignatureReason {
    /// A reference appears nested inside a `Vector(_)` or
    /// `DatatypeInstantiation(_)` token. References are
    /// allowed at the top level of a function-signature token
    /// only; nested positions reject.
    RefInsideContainer,
    /// A reference appears at the top level of a struct or
    /// enum-variant field signature. Field signatures reject
    /// references entirely (no top-level allowance).
    RefAsFieldType,
}

impl core::fmt::Display for InvalidSignatureReason {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::RefInsideContainer => {
                write!(
                    f,
                    "reference nested inside container token (vector or datatype instantiation)"
                )
            }
            Self::RefAsFieldType => {
                write!(
                    f,
                    "reference appearing as a struct or enum-variant field type"
                )
            }
        }
    }
}

/// Sub-reason discriminator for an
/// [`AdamantValidationError::IrreducibleControlFlow`] rejection.
///
/// Mirrors upstream `move-bytecode-verifier`'s two distinct
/// reducibility status codes (`INVALID_LOOP_SPLIT` and
/// `LOOP_MAX_DEPTH_REACHED`) as a closed-enum sub-reason rather
/// than two flat top-level variants. Same shape as
/// [`InvalidSignatureReason`] (C-3) and [`MalformedConstantReason`]
/// (B-2.1) — the closed-enum sub-reason pattern lets a single
/// validator-error variant carry an upstream-status-code-style
/// distinction without inflating
/// [`AdamantValidationError`]'s top-level variant count.
///
/// 5th instance of the deliberate-Adamant-decision pattern (see
/// `module_pass/PROVENANCE.md`); 6th public closed enum at the
/// validator surface.
///
/// Phase 5/5b.4 D-2 (`function_pass::control_flow`).
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum IrreducibleReason {
    /// A node in a loop's body is not dominated by the loop
    /// head — Tarjan property 1 violated. The CFG is not
    /// reducible.
    InvalidLoopSplit,
    /// Loop nesting depth exceeded
    /// [`AdamantStructuralLimits::max_loop_depth`][max]. The CFG
    /// is reducible but pathologically nested.
    ///
    /// [max]: super::config::AdamantStructuralLimits
    LoopMaxDepthReached,
}

impl core::fmt::Display for IrreducibleReason {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidLoopSplit => {
                write!(
                    f,
                    "control-flow graph is not reducible (loop body not dominated by head)"
                )
            }
            Self::LoopMaxDepthReached => {
                write!(f, "loop nesting depth exceeded the configured maximum")
            }
        }
    }
}

/// Sub-reason discriminator for an
/// [`AdamantValidationError::TypeMismatch`] rejection.
///
/// Mirrors upstream `move-bytecode-verifier::type_safety`'s
/// distinct `StatusCode` values for type-mismatch shapes as a
/// closed-enum sub-reason rather than flat top-level variants.
/// Same shape pattern as [`InvalidSignatureReason`] (C-3),
/// [`MalformedConstantReason`] (B-2.1), [`IrreducibleReason`]
/// (D-2). 7th public closed enum at the validator surface
/// (7th deliberate-Adamant-decision instance).
///
/// Phase 5/5b.4 D-5a (`function_pass::type_safety`).
///
/// Per Q2(b) at D-5a plan-gate, 8 sub-reasons land at this
/// commit; additional 4–6 surface empirically at impl-gate
/// (deliberate-deferral-with-impl-gate-expansion sub-pattern;
/// 1st instance at D-5a closure).
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum TypeMismatchReason {
    /// Operand on the abstract typed-stack does not match the
    /// type the consuming instruction expects (e.g., `Add`
    /// requires two integers; `ReadRef` requires a reference).
    OperandTypeMismatch,
    /// `Call` / `CallGeneric` argument types do not match the
    /// addressed `FunctionHandle`'s parameter signature.
    WrongFunctionSignature,
    /// `Pack` / `Unpack` argument types do not match the
    /// addressed struct definition's field types.
    WrongPackUnpackType,
    /// `Eq` / `Neq` comparison applied to types lacking the
    /// `drop` ability (equality requires copyable + droppable
    /// operands per Move's ability calculus).
    EqualityComparisonInvalid,
    /// `ReadRef` / `WriteRef` reference type does not match
    /// the expected referent type.
    ReferenceTypeNotMatched,
    /// `MutBorrowField` / `ImmBorrowField` reference operand
    /// type does not match the field's owning struct type.
    BorrowFieldTypeMismatch,
    /// `CastUN` source operand is not a smaller integer type
    /// (per Move's cast semantics: u8 → u16/u32/.../u256;
    /// u16 → u32/...; etc.).
    CastTargetTypeInvalid,
    /// Binary operation (`Add`, `Sub`, `Mul`, etc.) applied
    /// to operands of different integer types or non-integer
    /// types.
    BinaryOpTypeMismatch,
    /// Vector operation (`VecPack`, `VecUnpack`, `VecLen`,
    /// `VecImmBorrow`, `VecMutBorrow`, `VecPushBack`,
    /// `VecPopBack`, `VecSwap`) operand type does not match
    /// the declared element type.
    VecOpTypeMismatch,
    /// `FreezeRef` requires a mutable reference; immutable
    /// reference operand is invalid.
    FreezeRefRequiresMutableReference,
    /// `WriteRef` target reference is immutable; only mutable
    /// references support writes.
    WriteRefRequiresMutableReference,
    /// `VariantSwitch` operand is not an immutable reference,
    /// or its inner type does not match the jump table's
    /// declared head enum.
    VariantSwitchTypeMismatch,
    /// `Ret` operand-stack contents do not match the
    /// function's declared return signature.
    RetTypeMismatch,
    /// `StLoc` / `MoveLoc` / `CopyLoc` value type does not
    /// match the local's declared type at the same index.
    LocalTypeMismatch,
}

impl core::fmt::Display for TypeMismatchReason {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::OperandTypeMismatch => write!(f, "operand type does not match instruction's expectation"),
            Self::WrongFunctionSignature => write!(f, "Call/CallGeneric arguments do not match function-handle signature"),
            Self::WrongPackUnpackType => write!(f, "Pack/Unpack field types do not match struct definition"),
            Self::EqualityComparisonInvalid => write!(f, "Eq/Neq applied to types without drop ability"),
            Self::ReferenceTypeNotMatched => write!(f, "ReadRef/WriteRef reference type does not match expected referent"),
            Self::BorrowFieldTypeMismatch => write!(f, "MutBorrowField/ImmBorrowField reference does not point to the field's owning struct"),
            Self::CastTargetTypeInvalid => write!(f, "cast source operand is not a valid integer type"),
            Self::BinaryOpTypeMismatch => write!(f, "binary operation on operands of mismatched types"),
            Self::VecOpTypeMismatch => write!(f, "vector operation operand type does not match element type"),
            Self::FreezeRefRequiresMutableReference => write!(f, "FreezeRef requires a mutable reference"),
            Self::WriteRefRequiresMutableReference => write!(f, "WriteRef target reference is immutable"),
            Self::VariantSwitchTypeMismatch => write!(f, "VariantSwitch operand is not an immutable reference to the expected enum"),
            Self::RetTypeMismatch => write!(f, "Ret operand types do not match function's declared return signature"),
            Self::LocalTypeMismatch => write!(f, "local-variable operation type does not match the local's declared type"),
        }
    }
}

/// Structured reason for an
/// [`AdamantValidationError::BorrowViolation`] rejection. Each
/// variant maps to a specific borrow-graph invariant a
/// per-instruction transfer function may rule out.
///
/// Phase 5/5b.4 D-5b.2 (`function_pass::reference_safety`).
/// Closed-enum shape mirrors `TypeMismatchReason` (D-5a.0
/// precedent); declared lazily alongside producer per Q5 at
/// D-5b plan-gate (Rust error-type lifecycle).
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum BorrowViolationReason {
    /// `CopyLoc` of a non-reference local that has an
    /// outstanding mutable borrow. Maps to Sui's
    /// `COPYLOC_EXISTS_BORROW_ERROR`.
    CopyLocBorrowed,
    /// `MoveLoc` of a non-reference local that has an
    /// outstanding borrow. Maps to Sui's
    /// `MOVELOC_EXISTS_BORROW_ERROR`.
    MoveLocBorrowed,
    /// `StLoc` to a non-reference local that has an
    /// outstanding borrow (so the destruction of the existing
    /// value is unsafe). Maps to Sui's
    /// `STLOC_UNSAFE_TO_DESTROY_ERROR`.
    StLocDestroyBorrowed,
    /// `FreezeRef` on a mutable reference whose target has an
    /// outstanding mutable borrow. Maps to Sui's
    /// `FREEZEREF_EXISTS_MUTABLE_BORROW_ERROR`.
    FreezeRefHasMutableBorrow,
    /// `ReadRef` (or `Eq` / `Neq` comparison) on a reference
    /// whose target has an outstanding mutable borrow. Maps
    /// to Sui's `READREF_EXISTS_MUTABLE_BORROW_ERROR`.
    ReadRefHasMutableBorrow,
    /// `WriteRef` to a mutable reference whose target has any
    /// outstanding borrow. Maps to Sui's
    /// `WRITEREF_EXISTS_BORROW_ERROR`.
    WriteRefHasBorrow,
    /// `ImmBorrowLoc` / `MutBorrowLoc` of a local whose
    /// borrow-graph state precludes the requested borrow shape.
    /// Maps to Sui's `BORROWLOC_EXISTS_BORROW_ERROR`.
    BorrowLocHasBorrow,
    /// `MutBorrowField` / `ImmBorrowField` (and ref-unpack of
    /// enum variants) where the parent reference has an
    /// outstanding incompatible borrow. Maps to Sui's
    /// `FIELD_EXISTS_MUTABLE_BORROW_ERROR`.
    BorrowFieldHasMutableBorrow,
    /// `Call` / `CallGeneric` / `InvokeShielded` /
    /// `InvokeTransparent` argument is a mutable reference
    /// that cannot be transferred (the reference has an
    /// outstanding borrow). Maps to Sui's
    /// `CALL_BORROWED_MUTABLE_REFERENCE_ERROR`.
    CallTransfersBorrowedMutable,
    /// `VecImmBorrow` / `VecMutBorrow` on a vector reference
    /// whose state precludes the requested element borrow.
    /// Maps to Sui's
    /// `VEC_BORROW_ELEMENT_EXISTS_MUTABLE_BORROW_ERROR`.
    VecElementHasMutableBorrow,
    /// `VecPushBack` / `VecPopBack` / `VecSwap` on a mutable
    /// vector reference whose state precludes the update
    /// (some other mutable borrow is outstanding). Maps to
    /// Sui's `VEC_UPDATE_EXISTS_MUTABLE_BORROW_ERROR`.
    VecUpdateHasMutableBorrow,
    /// `Ret` from a frame where some local or resource is
    /// still borrowed. Maps to Sui's
    /// `UNSAFE_RET_LOCAL_OR_RESOURCE_STILL_BORROWED`.
    RetWithBorrowedFrame,
    /// `Ret` returning a mutable reference that cannot be
    /// transferred (the reference has an outstanding borrow).
    /// Maps to Sui's `RET_BORROWED_MUTABLE_REFERENCE_ERROR`.
    RetBorrowedMutableReference,
}

/// Structured reason for an
/// [`AdamantValidationError::PrivacyConsistencyViolation`]
/// rejection. Each variant identifies the direction of the
/// privacy-mode mismatch caught by the call-graph walker.
///
/// Phase 5/5b.4 D-5c (`rule_03_privacy_consistency`).
/// Closed-enum shape mirrors `TypeMismatchReason` (D-5a.0
/// precedent) and `BorrowViolationReason` (D-5b.2 precedent);
/// declared with producer per Q5 at D-5c plan-gate.
///
/// Forward-extensibility: cross-module Rule 3 enforcement at
/// Phase 5/5b.5 may surface additional sub-reasons (e.g.,
/// `ShieldedReachesUnannotatedExternal`).
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum PrivacyConsistencyViolationReason {
    /// A `#[shielded]` public function reaches (directly or
    /// transitively) an `InvokeTransparent` instruction. Per
    /// §6.2.1.6 Rule 3: "A `#[shielded]` function may not
    /// contain any `InvokeTransparent` instruction."
    ShieldedReachesInvokeTransparent,
    /// A `#[transparent]` public function reaches (directly
    /// or transitively) an `InvokeShielded` instruction. Per
    /// §6.2.1.6 Rule 3: "A `#[transparent]` function may not
    /// contain any `InvokeShielded` instruction."
    TransparentReachesInvokeShielded,
}

impl core::fmt::Display for PrivacyConsistencyViolationReason {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::ShieldedReachesInvokeTransparent => write!(
                f,
                "shielded public function reaches InvokeTransparent (directly or transitively)"
            ),
            Self::TransparentReachesInvokeShielded => write!(
                f,
                "transparent public function reaches InvokeShielded (directly or transitively)"
            ),
        }
    }
}

/// Sub-reason for [`AdamantValidationError::DynamicDispatchViolation`].
///
/// Whitepaper §6.2.1.6 Rule 6 + line 485 enumerates two
/// forbidden module names at address `0x2`: `dynamic_field`
/// and `dynamic_object_field`. Closed-enum sub-reason
/// distinguishes which family triggered the rejection so the
/// diagnostic surface for module authors points at the precise
/// API they invoked.
///
/// Closed-enum shape mirrors `TypeMismatchReason` /
/// `BorrowViolationReason` / `PrivacyConsistencyViolationReason`
/// per the established closed-enum-sub-reason pattern. Phase
/// 5/5b.5 E-3 (10th public closed enum).
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum DynamicDispatchViolationReason {
    /// `Call`/`CallGeneric` targets `0x2::dynamic_field::*`
    /// without `b"adamant.allows_dynamic" = true` opt-in.
    DynamicFieldNotOptedIn,
    /// `Call`/`CallGeneric` targets `0x2::dynamic_object_field::*`
    /// without `b"adamant.allows_dynamic" = true` opt-in.
    DynamicObjectFieldNotOptedIn,
}

impl core::fmt::Display for DynamicDispatchViolationReason {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::DynamicFieldNotOptedIn => write!(
                f,
                "module calls 0x2::dynamic_field::* without `adamant.allows_dynamic = true` opt-in"
            ),
            Self::DynamicObjectFieldNotOptedIn => write!(
                f,
                "module calls 0x2::dynamic_object_field::* without `adamant.allows_dynamic = true` opt-in"
            ),
        }
    }
}

/// Sub-reason for [`AdamantValidationError::PrivacyCircuitContextViolation`].
///
/// Per whitepaper §6.2.1.6 Rule 7, four Adamant-extension
/// instructions are restricted to `#[shielded]` contexts:
/// `GenerateProof`, `VerifyProof`, `RecursiveVerify`,
/// `ReleaseSubViewKey`. Closed-enum sub-reason discriminates
/// which instruction triggered the rejection so the diagnostic
/// surface points at the precise opcode the module author
/// invoked.
///
/// Closed-enum shape mirrors `TypeMismatchReason` /
/// `BorrowViolationReason` / `PrivacyConsistencyViolationReason`
/// / `DynamicDispatchViolationReason` per the established
/// closed-enum-sub-reason pattern. Phase 5/5b.5 E-4 (11th
/// public closed enum).
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum PrivacyCircuitContextViolationReason {
    /// `GenerateProof(CircuitId)` reached from a transparent
    /// public function.
    GenerateProofInTransparentContext,
    /// `VerifyProof(CircuitId)` reached from a transparent
    /// public function.
    VerifyProofInTransparentContext,
    /// `RecursiveVerify` reached from a transparent public
    /// function.
    RecursiveVerifyInTransparentContext,
    /// `ReleaseSubViewKey` reached from a transparent public
    /// function.
    ReleaseSubViewKeyInTransparentContext,
}

impl core::fmt::Display for PrivacyCircuitContextViolationReason {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::GenerateProofInTransparentContext => write!(
                f,
                "GenerateProof reachable from a transparent public function"
            ),
            Self::VerifyProofInTransparentContext => write!(
                f,
                "VerifyProof reachable from a transparent public function"
            ),
            Self::RecursiveVerifyInTransparentContext => write!(
                f,
                "RecursiveVerify reachable from a transparent public function"
            ),
            Self::ReleaseSubViewKeyInTransparentContext => write!(
                f,
                "ReleaseSubViewKey reachable from a transparent public function"
            ),
        }
    }
}

impl core::fmt::Display for BorrowViolationReason {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::CopyLocBorrowed => write!(f, "CopyLoc of a non-reference local with an outstanding mutable borrow"),
            Self::MoveLocBorrowed => write!(f, "MoveLoc of a non-reference local with an outstanding borrow"),
            Self::StLocDestroyBorrowed => write!(f, "StLoc would destroy a non-reference local with an outstanding borrow"),
            Self::FreezeRefHasMutableBorrow => write!(f, "FreezeRef on a mutable reference with an outstanding mutable borrow"),
            Self::ReadRefHasMutableBorrow => write!(f, "ReadRef / Eq / Neq on a reference with an outstanding mutable borrow"),
            Self::WriteRefHasBorrow => write!(f, "WriteRef on a mutable reference with an outstanding borrow"),
            Self::BorrowLocHasBorrow => write!(f, "ImmBorrowLoc / MutBorrowLoc precluded by an outstanding borrow on the local or frame"),
            Self::BorrowFieldHasMutableBorrow => write!(f, "MutBorrowField / ImmBorrowField (or ref-unpack) precluded by an outstanding borrow on the parent reference"),
            Self::CallTransfersBorrowedMutable => write!(f, "Call argument is a mutable reference that cannot be transferred"),
            Self::VecElementHasMutableBorrow => write!(f, "VecImmBorrow / VecMutBorrow precluded by an outstanding borrow on the vector reference"),
            Self::VecUpdateHasMutableBorrow => write!(f, "VecPushBack / VecPopBack / VecSwap on a mutable vector reference with an outstanding mutable borrow"),
            Self::RetWithBorrowedFrame => write!(f, "Ret from a frame with locals still borrowed"),
            Self::RetBorrowedMutableReference => write!(f, "Ret returning a mutable reference that cannot be transferred"),
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
            Self::CodeIndexOutOfBounds {
                fn_def_idx,
                code_offset,
                kind,
                idx,
                pool_len,
            } => write!(
                f,
                "function definition {} offset {code_offset}: {kind} index {idx} \
                 out of range for pool of length {pool_len} (whitepaper §6.2.1.8 \
                 step 3, `module_pass::bounds_checker::check_function_def`)",
                fn_def_idx.0
            ),
            Self::InvalidEnumSwitch {
                fn_def_idx,
                jump_table_idx,
                jump_table_len,
                expected_variants_count,
            } => write!(
                f,
                "function definition {} jump table {jump_table_idx}: length \
                 {jump_table_len} does not match addressed enum's variant count \
                 {expected_variants_count} (whitepaper §6.2.1.8 step 3, \
                 `module_pass::bounds_checker::check_function_def`)",
                fn_def_idx.0
            ),
            Self::DuplicateElement { kind, idx } => write!(
                f,
                "duplicate {kind} entry at index {idx} \
                 (whitepaper §6.2.1.8 step 3, `module_pass::duplication_checker`)"
            ),
            Self::ZeroSizedStruct { def_idx } => write!(
                f,
                "struct definition {} has zero declared fields \
                 (whitepaper §6.2.1.8 step 3, \
                 `module_pass::duplication_checker::check_struct_definitions`)",
                def_idx.0
            ),
            Self::ZeroSizedEnum { def_idx } => write!(
                f,
                "enum definition {} has zero variants \
                 (whitepaper §6.2.1.8 step 3, \
                 `module_pass::duplication_checker::check_enum_definitions`)",
                def_idx.0
            ),
            Self::InvalidModuleHandle { kind, def_idx } => write!(
                f,
                "{kind} definition {def_idx} references a module handle that is not the \
                 module's own self-handle (whitepaper §6.2.1.8 step 3, \
                 `module_pass::duplication_checker`)"
            ),
            Self::DuplicateAcquiresAnnotation { fn_def_idx } => write!(
                f,
                "function definition {} has duplicate entries in its \
                 acquires_global_resources list (whitepaper §6.2.1.8 step 3, \
                 `module_pass::duplication_checker::check_function_definitions`)",
                fn_def_idx.0
            ),
            Self::UnimplementedHandle { kind, idx } => write!(
                f,
                "{kind} {idx} references the module's self-handle but has no \
                 corresponding definition (whitepaper §6.2.1.8 step 3, \
                 `module_pass::duplication_checker`)"
            ),
            Self::InvalidSignatureToken { reason } => write!(
                f,
                "invalid signature token: {reason} \
                 (whitepaper §6.2.1.8 step 3, `module_pass::signature_checker`)"
            ),
            Self::TypeArgumentsArityMismatch { expected, actual } => write!(
                f,
                "generic instance expects {expected} type argument(s), got {actual} \
                 (whitepaper §6.2.1.8 step 3, `module_pass::signature_checker`)"
            ),
            Self::ConstraintNotSatisfied { type_param_idx } => write!(
                f,
                "type argument at type-parameter index {type_param_idx} does not satisfy \
                 the addressed handle's declared ability constraint \
                 (whitepaper §6.2.1.8 step 3, `module_pass::signature_checker`)"
            ),
            Self::InvalidPhantomTypeParamPosition => write!(
                f,
                "phantom type parameter used in non-phantom position \
                 (whitepaper §6.2.1.8 step 3, `module_pass::signature_checker`)"
            ),
            Self::VecOpExpectedSingleTypeArgument { actual } => write!(
                f,
                "vec op expects 1 type argument, got {actual} \
                 (whitepaper §6.2.1.8 step 3, `module_pass::signature_checker`)"
            ),
            Self::EmptyFunctionBody { fn_def_idx } => write!(
                f,
                "function definition {} has an empty body (whitepaper §6.2.1.8 \
                 step 4, `function_pass::control_flow`)",
                fn_def_idx.0
            ),
            Self::MissingFallthroughTerminator {
                fn_def_idx,
                code_offset,
            } => write!(
                f,
                "function definition {} offset {code_offset}: last instruction \
                 is not an unconditional terminator (Ret, Abort, Branch, or \
                 VariantSwitch) (whitepaper §6.2.1.8 step 4, \
                 `function_pass::control_flow`)",
                fn_def_idx.0
            ),
            Self::IrreducibleControlFlow {
                fn_def_idx,
                code_offset,
                reason,
            } => write!(
                f,
                "function definition {} offset {code_offset}: {reason} \
                 (whitepaper §6.2.1.8 step 4, `function_pass::control_flow`)",
                fn_def_idx.0
            ),
            Self::StackPushOverflow {
                fn_def_idx,
                code_offset,
            } => write!(
                f,
                "function definition {} offset {code_offset}: basic-block push count \
                 exceeds max_push_size (whitepaper §6.2.1.8 step 4, \
                 `function_pass::stack_usage`)",
                fn_def_idx.0
            ),
            Self::StackUnderflow {
                fn_def_idx,
                code_offset,
            } => write!(
                f,
                "function definition {} offset {code_offset}: instruction would \
                 underflow the operand stack within a basic block (whitepaper \
                 §6.2.1.8 step 4, `function_pass::stack_usage`)",
                fn_def_idx.0
            ),
            Self::UnbalancedStackAtBlockEnd {
                fn_def_idx,
                code_offset,
            } => write!(
                f,
                "function definition {} offset {code_offset}: basic block ends with \
                 non-zero stack delta (or Ret-terminated block does not match return \
                 arity) (whitepaper §6.2.1.8 step 4, `function_pass::stack_usage`)",
                fn_def_idx.0
            ),
            Self::StLocDestroysNonDrop {
                fn_def_idx,
                code_offset,
            } => write!(
                f,
                "function definition {} offset {code_offset}: StLoc would destroy a \
                 value whose type lacks the `drop` ability (whitepaper §6.2.1.8 \
                 step 4, `function_pass::locals_safety`)",
                fn_def_idx.0
            ),
            Self::MoveLocUnavailable {
                fn_def_idx,
                code_offset,
            } => write!(
                f,
                "function definition {} offset {code_offset}: MoveLoc on a local \
                 that may not be available on every CFG path (whitepaper §6.2.1.8 \
                 step 4, `function_pass::locals_safety`)",
                fn_def_idx.0
            ),
            Self::CopyLocUnavailable {
                fn_def_idx,
                code_offset,
            } => write!(
                f,
                "function definition {} offset {code_offset}: CopyLoc on a local \
                 that may not be available on every CFG path (whitepaper §6.2.1.8 \
                 step 4, `function_pass::locals_safety`)",
                fn_def_idx.0
            ),
            Self::BorrowLocUnavailable {
                fn_def_idx,
                code_offset,
            } => write!(
                f,
                "function definition {} offset {code_offset}: MutBorrowLoc or \
                 ImmBorrowLoc on a local that may not be available on every CFG \
                 path (whitepaper §6.2.1.8 step 4, `function_pass::locals_safety`)",
                fn_def_idx.0
            ),
            Self::RetWithUndroppedLocals {
                fn_def_idx,
                code_offset,
            } => write!(
                f,
                "function definition {} offset {code_offset}: Ret with at least one \
                 local still available whose type lacks the `drop` ability \
                 (whitepaper §6.2.1.8 step 4, `function_pass::locals_safety`)",
                fn_def_idx.0
            ),
            Self::TypeMismatch {
                fn_def_idx,
                code_offset,
                reason,
            } => write!(
                f,
                "function definition {} offset {code_offset}: {reason} \
                 (whitepaper §6.2.1.8 step 4, `function_pass::type_safety`)",
                fn_def_idx.0
            ),
            Self::BorrowViolation {
                fn_def_idx,
                code_offset,
                reason,
            } => write!(
                f,
                "function definition {} offset {code_offset}: {reason} \
                 (whitepaper §6.2.1.8 step 4, `function_pass::reference_safety`)",
                fn_def_idx.0
            ),
            Self::PrivacyConsistencyViolation {
                calling_public_index,
                violating_function_index,
                code_offset,
                reason,
            } => write!(
                f,
                "privacy-consistency violation reachable from public function {} \
                 (offending instruction in function {} at offset {code_offset}): {reason} \
                 (whitepaper §6.2.1.6 Rule 3)",
                calling_public_index.0, violating_function_index.0
            ),
            Self::CrossModulePrivacyConsistencyViolation {
                calling_public_index,
                calling_function_index,
                code_offset,
                target_module_id,
                calling_function_handle_idx,
                reason,
            } => write!(
                f,
                "cross-module privacy-consistency violation reachable from public function {} \
                 (cross-module call in function {} at offset {code_offset}; \
                 target module {:?}::{} via FunctionHandleIndex {}): {reason} \
                 (whitepaper §6.2.1.6 Rule 3 + line 477)",
                calling_public_index.0,
                calling_function_index.0,
                target_module_id.address,
                target_module_id.name,
                calling_function_handle_idx.0,
            ),
            Self::DynamicDispatchViolation {
                calling_function_index,
                code_offset,
                calling_function_handle_idx,
                reason,
            } => write!(
                f,
                "dynamic-dispatch violation in function {} at offset {code_offset} \
                 (FunctionHandleIndex {}): {reason} \
                 (whitepaper §6.2.1.6 Rule 6)",
                calling_function_index.0, calling_function_handle_idx.0,
            ),
            Self::PrivacyCircuitContextViolation {
                calling_public_index,
                violating_function_index,
                code_offset,
                reason,
            } => write!(
                f,
                "privacy-circuit-context violation reachable from transparent public function {} \
                 (offending instruction in function {} at offset {code_offset}): {reason} \
                 (whitepaper §6.2.1.6 Rule 7)",
                calling_public_index.0, violating_function_index.0
            ),
        }
    }
}

impl std::error::Error for AdamantValidationError {}
