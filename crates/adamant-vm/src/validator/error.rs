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

use adamant_bytecode_format::FunctionDefinitionIndex;
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
    // Rule 5 (no global storage instructions) is enforced at
    // parse time inside `AdamantDeserializer`; no separate
    // variant. Variants for Rules 2, 3, 6, 7 land in subsequent
    // waves.
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
        }
    }
}

impl std::error::Error for AdamantValidationError {}
