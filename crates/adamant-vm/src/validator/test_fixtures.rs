//! Test fixtures for the Adamant validator.
//!
//! Builds [`CompiledModule`] values programmatically using
//! Sui-Move's [`empty_module`] and [`basic_test_module`] as
//! starting points (both already vendored at
//! `vendor/move-binary-format/src/file_format.rs`). Each fixture
//! adds the Adamant-specific deviations a test needs.
//!
//! Conventions:
//!
//! - All fixture functions are `pub(super)` — visible only to
//!   sibling modules under `validator/`. The fixtures are not
//!   part of the public API.
//! - Each fixture is named for the property it constructs
//!   (e.g., `module_with_native_function`), not for the test
//!   that consumes it.
//! - All fixtures pass the bounds checker by construction
//!   (built atop Sui's `empty_module` / `basic_test_module`);
//!   any verifier rejection is therefore caused by the
//!   Adamant-specific deviation the fixture intends to test.
//!
//! A future cross-validation corpus of real-Sui-compiler-output
//! modules may join this file once the validator's surface is
//! fully built out (registered in the Wave 3a discussion);
//! synthetic fixtures can drift from real-world bytecode
//! patterns, and that's worth catching before the validator
//! reaches production. Deferred until the rules-implementation
//! arc completes.

use adamant_types::Mutability;
use move_binary_format::file_format::{
    basic_test_module, empty_module, CompiledModule, FunctionDefinition, FunctionHandle,
    FunctionHandleIndex, IdentifierIndex, ModuleHandleIndex, SignatureIndex, Visibility,
};
use move_binary_format::file_format_common::VERSION_MAX;
use move_core_types::{identifier::Identifier, metadata::Metadata};

const MUTABILITY_KEY: &[u8] = b"adamant.mutability";

/// BCS-encode `Mutability::Immutable` for use as a metadata
/// value. `Immutable` is chosen as the simplest variant — it has
/// no fields, so the BCS encoding is a single variant tag byte.
fn immutable_mutability_bytes() -> Vec<u8> {
    bcs::to_bytes(&Mutability::Immutable)
        .expect("Mutability::Immutable BCS-encodes deterministically")
}

/// Serialize a programmatically-constructed [`CompiledModule`]
/// to the bytes form that [`super::verify_module`] expects.
///
/// Used by tests that exercise the full bytes → deserialize →
/// verify pipeline (in particular, Rule 5 tests, where the
/// deserializer is the rejection point for the 10 deprecated
/// global-storage variants). Tests that only exercise a single
/// per-rule `verify(&CompiledModule)` function don't need to
/// serialize.
///
/// Uses [`CompiledModule::serialize_with_version`] at
/// [`VERSION_MAX`] rather than the simpler `serialize` method
/// because the latter is `#[cfg(any(test, feature = "fuzzing"))]`-
/// gated upstream — only available within `move-binary-format`'s
/// own test build, not in cross-crate test builds.
pub(super) fn serialize_module(module: &CompiledModule) -> Vec<u8> {
    let mut bytes = vec![];
    module
        .serialize_with_version(VERSION_MAX, &mut bytes)
        .expect("serializing a fixture-constructed CompiledModule must succeed");
    bytes
}

/// A minimal valid module: passes Sui-Move's verifier, has the
/// required `b"adamant.mutability"` metadata entry, no functions
/// (so Rules 4 and 7 are vacuously satisfied), no global storage
/// instructions (so Rule 5 is vacuously satisfied).
///
/// This is the baseline fixture: tests that need a passing
/// module use this; tests that exercise specific failure modes
/// modify a clone of this (or build atop `basic_test_module`
/// for fixtures that need a function body to manipulate).
pub(super) fn valid_module() -> CompiledModule {
    let mut m = empty_module();
    m.metadata.push(Metadata {
        key: MUTABILITY_KEY.to_vec(),
        value: immutable_mutability_bytes(),
    });
    m
}

/// A module with no `b"adamant.mutability"` metadata entry.
/// Triggers Rule 1's `MissingMutabilityMetadata`.
pub(super) fn module_without_mutability_metadata() -> CompiledModule {
    empty_module()
}

/// A module with two `b"adamant.mutability"` metadata entries.
/// Triggers Rule 1's `MultipleMutabilityMetadata { count: 2 }`.
pub(super) fn module_with_two_mutability_entries() -> CompiledModule {
    let mut m = valid_module();
    m.metadata.push(Metadata {
        key: MUTABILITY_KEY.to_vec(),
        value: immutable_mutability_bytes(),
    });
    m
}

/// A module whose `b"adamant.mutability"` metadata entry has a
/// value that is not a valid BCS encoding of [`Mutability`].
/// Triggers Rule 1's `MalformedMutabilityMetadata`.
///
/// The value `0xFF, 0xFF, 0xFF, 0xFF` decodes as a variant tag
/// of 255 (using BCS's ULEB128 variant encoding for a single
/// byte), which is far beyond [`Mutability`]'s variant count
/// (six variants). BCS-deserialisation as `Mutability` returns
/// an error.
pub(super) fn module_with_malformed_mutability_metadata() -> CompiledModule {
    let mut m = empty_module();
    m.metadata.push(Metadata {
        key: MUTABILITY_KEY.to_vec(),
        value: vec![0xFF, 0xFF, 0xFF, 0xFF],
    });
    m
}

/// A module with a single native function (Sui-Move marks
/// natives via `code: None`). Triggers Rule 4's
/// `NativeFunctionForbidden { function_index: 0 }`.
///
/// Built atop [`valid_module`] (which has the required
/// mutability metadata) so that the only verifier deviation is
/// the native-function marker.
pub(super) fn module_with_native_function() -> CompiledModule {
    let mut m = valid_module();
    let name_idx = u16::try_from(m.identifiers.len())
        .expect("identifier pool count fits in u16; Sui's binary format precludes overflow");
    m.function_handles.push(FunctionHandle {
        module: ModuleHandleIndex(0),
        name: IdentifierIndex(name_idx),
        parameters: SignatureIndex(0),
        return_: SignatureIndex(0),
        type_parameters: vec![],
    });
    m.identifiers
        .push(Identifier::new("native_fn").expect("identifier name is well-formed UTF-8"));
    m.function_defs.push(FunctionDefinition {
        function: FunctionHandleIndex(0),
        visibility: Visibility::Private,
        is_entry: false,
        acquires_global_resources: vec![],
        // The native marker per `FunctionDefinition::is_native`
        // (vendor/move-binary-format/src/file_format.rs:557).
        code: None,
    });
    m
}

/// A non-trivial valid module: built atop [`basic_test_module`]
/// (which provides one function `foo()` with body `[Ret]` and one
/// struct `Bar { x: u64 }`), with a `b"adamant.mutability"` entry
/// plus a second metadata entry under a different key
/// (`b"adamant.dummy"`). Used by the canonicality round-trip
/// test that exercises the wrapper against richer module
/// structure (multiple metadata entries, a function, a struct).
///
/// The `b"adamant.dummy"` key is intentionally distinct from
/// the validator's reserved keys (`b"adamant.mutability"`,
/// `b"adamant.privacy"`, `b"adamant.allows_dynamic"`); it
/// stands in for any future or third-party metadata key that
/// modules may carry without violating Rule 1's "exactly one
/// `adamant.mutability` entry" requirement.
pub(super) fn rich_valid_module() -> CompiledModule {
    let mut m = basic_test_module();
    m.metadata.push(Metadata {
        key: MUTABILITY_KEY.to_vec(),
        value: immutable_mutability_bytes(),
    });
    m.metadata.push(Metadata {
        key: b"adamant.dummy".to_vec(),
        value: vec![0xCA, 0xFE, 0xBA, 0xBE],
    });
    m
}

/// A module containing one function whose body is `[instr,
/// Ret]`. Built atop [`basic_test_module`] (which provides one
/// struct definition at index 0 and one function with a body
/// of `[Ret]`); the function's body is then overwritten with
/// `[instr, Ret]`. The required `b"adamant.mutability"`
/// metadata entry is added so Rule 1 passes.
///
/// Used by Rule 5 tests: each of the 10 deprecated global-storage
/// bytecode variants is fed in via this fixture; Sui's
/// `BoundsChecker` (with `deprecate_global_storage_ops = true`)
/// rejects on encounter, before the bounds check on the operand
/// index is reached. The operand index passed by the caller
/// therefore does not need to be valid for the fixture to
/// exercise the rejection — but using `0` keeps the fixture
/// consistent with `basic_test_module`'s shape (one `struct_def`
/// at index 0).
pub(super) fn module_with_function_body_starting(
    instr: move_binary_format::file_format::Bytecode,
) -> CompiledModule {
    let mut m = basic_test_module();
    m.metadata.push(Metadata {
        key: MUTABILITY_KEY.to_vec(),
        value: immutable_mutability_bytes(),
    });
    let function_def = m
        .function_defs
        .first_mut()
        .expect("basic_test_module installs exactly one function definition");
    let code_unit = function_def
        .code
        .as_mut()
        .expect("basic_test_module's function has a non-native body");
    code_unit.code = vec![instr, move_binary_format::file_format::Bytecode::Ret];
    m
}
