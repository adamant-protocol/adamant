//! Test fixtures for the Adamant validator.
//!
//! Builds [`AdamantCompiledModule`] values programmatically per
//! whitepaper §6.2.1.8. Each fixture adds the Adamant-specific
//! deviations a test needs.
//!
//! Conventions:
//!
//! - All fixture functions are `pub(super)` — visible only to
//!   sibling modules under `validator/`. The fixtures are not
//!   part of the public API.
//! - Each fixture is named for the property it constructs
//!   (e.g., `module_with_native_function`), not for the test
//!   that consumes it.
//! - All fixtures construct minimal-shape modules directly via
//!   [`AdamantCompiledModule`] field literals so the byte layout
//!   they produce is predictable and self-contained (no
//!   dependence on Sui-helper sentinels like `empty_module`).
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
    AbilitySet, AddressIdentifierIndex, Bytecode, DatatypeHandle, DatatypeHandleIndex,
    FieldDefinition, FunctionHandle, FunctionHandleIndex, IdentifierIndex, ModuleHandle,
    ModuleHandleIndex, Signature, SignatureIndex, SignatureToken, StructDefinition,
    StructFieldInformation, TypeSignature, Visibility,
};
use move_binary_format::file_format_common::VERSION_MAX;
use move_core_types::{
    account_address::AccountAddress, identifier::Identifier, metadata::Metadata,
};

use crate::bytecode::BytecodeInstruction;
use crate::module::{AdamantCodeUnit, AdamantCompiledModule, AdamantFunctionDefinition};
use crate::module_wire::adamant_serialize;

const MUTABILITY_KEY: &[u8] = b"adamant.mutability";

/// BCS-encode `Mutability::Immutable` for use as a metadata
/// value. `Immutable` is chosen as the simplest variant — it has
/// no fields, so the BCS encoding is a single variant tag byte.
fn immutable_mutability_bytes() -> Vec<u8> {
    bcs::to_bytes(&Mutability::Immutable)
        .expect("Mutability::Immutable BCS-encodes deterministically")
}

/// Serialize a programmatically-constructed [`AdamantCompiledModule`]
/// to the bytes form that [`super::verify_module`] expects, using
/// [`adamant_serialize`].
pub(super) fn serialize_module(module: &AdamantCompiledModule) -> Vec<u8> {
    let mut bytes = vec![];
    adamant_serialize(module, &mut bytes)
        .expect("serializing a fixture-constructed AdamantCompiledModule must succeed");
    bytes
}

/// Returns a minimal module shell with one module handle, one
/// identifier ("M"), and the zero address. Used as the base for
/// fixtures that add specific Adamant deviations.
fn module_shell() -> AdamantCompiledModule {
    AdamantCompiledModule {
        version: VERSION_MAX,
        publishable: true,
        self_module_handle_idx: ModuleHandleIndex(0),
        module_handles: vec![ModuleHandle {
            address: AddressIdentifierIndex(0),
            name: IdentifierIndex(0),
        }],
        identifiers: vec![Identifier::new("M").unwrap()],
        address_identifiers: vec![AccountAddress::ZERO],
        ..AdamantCompiledModule::default()
    }
}

/// A minimal valid module: has the required `b"adamant.mutability"`
/// metadata entry, no functions (so Rules 4 and 7 are vacuously
/// satisfied), no global storage instructions (Rule 5 is
/// vacuously satisfied).
pub(super) fn valid_module() -> AdamantCompiledModule {
    let mut m = module_shell();
    m.metadata.push(Metadata {
        key: MUTABILITY_KEY.to_vec(),
        value: immutable_mutability_bytes(),
    });
    m
}

/// A module with no `b"adamant.mutability"` metadata entry.
/// Triggers Rule 1's `MissingMutabilityMetadata`.
pub(super) fn module_without_mutability_metadata() -> AdamantCompiledModule {
    module_shell()
}

/// A module with two `b"adamant.mutability"` metadata entries.
/// Triggers Rule 1's `MultipleMutabilityMetadata { count: 2 }`.
pub(super) fn module_with_two_mutability_entries() -> AdamantCompiledModule {
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
pub(super) fn module_with_malformed_mutability_metadata() -> AdamantCompiledModule {
    let mut m = module_shell();
    m.metadata.push(Metadata {
        key: MUTABILITY_KEY.to_vec(),
        value: vec![0xFF, 0xFF, 0xFF, 0xFF],
    });
    m
}

/// A module with a single native function (`code: None`).
/// Triggers Rule 4's `NativeFunctionForbidden { function_index: 0 }`.
pub(super) fn module_with_native_function() -> AdamantCompiledModule {
    let mut m = valid_module();
    m.identifiers.push(Identifier::new("native_fn").unwrap());
    m.signatures.push(Signature(vec![]));
    m.function_handles.push(FunctionHandle {
        module: ModuleHandleIndex(0),
        name: IdentifierIndex(1),
        parameters: SignatureIndex(0),
        return_: SignatureIndex(0),
        type_parameters: vec![],
    });
    m.function_defs.push(AdamantFunctionDefinition {
        function: FunctionHandleIndex(0),
        visibility: Visibility::Private,
        is_entry: false,
        acquires_global_resources: vec![],
        // The native marker per Rule 4: `code: None` is Sui's
        // convention for native functions; Adamant rejects it.
        code: None,
    });
    m
}

/// A non-trivial valid module: one struct, one function with a
/// trivial body, plus mutability metadata and a stand-in second
/// metadata entry (`b"adamant.dummy"`). Used by the canonicality
/// round-trip test that exercises the wrapper against richer
/// module structure.
pub(super) fn rich_valid_module() -> AdamantCompiledModule {
    let mut m = valid_module();
    m.metadata.push(Metadata {
        key: b"adamant.dummy".to_vec(),
        value: vec![0xCA, 0xFE, 0xBA, 0xBE],
    });
    // Add a single struct `S { f: u64 }` and a single function
    // `foo()` with body `[Ret]`.
    m.identifiers.push(Identifier::new("S").unwrap());
    m.identifiers.push(Identifier::new("f").unwrap());
    m.identifiers.push(Identifier::new("foo").unwrap());
    m.signatures.push(Signature(vec![]));
    m.datatype_handles.push(DatatypeHandle {
        module: ModuleHandleIndex(0),
        name: IdentifierIndex(1),
        abilities: AbilitySet::EMPTY,
        type_parameters: vec![],
    });
    m.struct_defs.push(StructDefinition {
        struct_handle: DatatypeHandleIndex(0),
        field_information: StructFieldInformation::Declared(vec![FieldDefinition {
            name: IdentifierIndex(2),
            signature: TypeSignature(SignatureToken::U64),
        }]),
    });
    m.function_handles.push(FunctionHandle {
        module: ModuleHandleIndex(0),
        name: IdentifierIndex(3),
        parameters: SignatureIndex(0),
        return_: SignatureIndex(0),
        type_parameters: vec![],
    });
    m.function_defs.push(AdamantFunctionDefinition {
        function: FunctionHandleIndex(0),
        visibility: Visibility::Public,
        is_entry: false,
        acquires_global_resources: vec![],
        code: Some(AdamantCodeUnit {
            locals: SignatureIndex(0),
            code: vec![BytecodeInstruction::Inherited(Bytecode::Ret)],
            jump_tables: vec![],
        }),
    });
    m
}

/// A module containing one function whose body starts with `instr`
/// followed by `Ret`. Used by the Rule-5-via-deserializer pipeline
/// test in [`super::tests`]: the validator's deserialize stage
/// rejects deprecated global-storage instructions in strict mode
/// per §6.2.1.6 Rule 5 (enforcement-point shift in step 4 from
/// `rule_05`'s separate scan to parse-time rejection).
pub(super) fn module_with_function_body_starting(instr: Bytecode) -> AdamantCompiledModule {
    let mut m = valid_module();
    m.identifiers.push(Identifier::new("f").unwrap());
    m.signatures.push(Signature(vec![]));
    m.function_handles.push(FunctionHandle {
        module: ModuleHandleIndex(0),
        name: IdentifierIndex(1),
        parameters: SignatureIndex(0),
        return_: SignatureIndex(0),
        type_parameters: vec![],
    });
    m.function_defs.push(AdamantFunctionDefinition {
        function: FunctionHandleIndex(0),
        visibility: Visibility::Private,
        is_entry: false,
        acquires_global_resources: vec![],
        code: Some(AdamantCodeUnit {
            locals: SignatureIndex(0),
            code: vec![
                BytecodeInstruction::Inherited(instr),
                BytecodeInstruction::Inherited(Bytecode::Ret),
            ],
            jump_tables: vec![],
        }),
    });
    m
}
