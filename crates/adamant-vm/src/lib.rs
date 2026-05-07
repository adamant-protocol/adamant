//! Adamant Move virtual machine.
//!
//! This crate implements whitepaper section 6 — the smart-contract
//! language, the virtual machine, parallel execution, and resource
//! accounting. Phase 5's first deliverable was the canonical
//! transaction format (whitepaper sections 6.0 and 6.0.7) and the
//! `TxHash` derivation (whitepaper section 6.0.4); the second
//! deliverable adds the bytecode-instruction types (section 6.2.1.4)
//! atop the inherited Sui-Move bytecode (section 6.2.1.1).
//!
//! # Phase 5 surface so far
//!
//! - [`Transaction`] and its sub-types ([`TxBody`], [`AuthEvidence`],
//!   [`AccountRef`], [`CreatedObject`], [`GasBudget`], [`CallParams`],
//!   [`Witness`]) — whitepaper sections 6.0.1, 6.0.2, 6.0.3.
//! - [`Value`] and [`StructValue`] — Adamant Move value taxonomy
//!   per whitepaper section 6.0.7.
//! - [`derive_tx_hash`] — whitepaper section 6.0.4
//!   (`TxHash = sha3_256_tagged(TX_HASH, BCS(body))`).
//! - [`AdamantBytecode`], [`AdamantOpcodeKind`],
//!   [`BytecodeInstruction`], [`CircuitId`], [`GasDimension`] —
//!   whitepaper section 6.2.1.4. Sui-Move's inherited
//!   [`Bytecode`] enum and [`FunctionHandleIndex`] operand type
//!   are re-exported from this crate so consumers don't reach
//!   into the vendored Sui crate names directly.
//! - [`validator::verify_module`], [`AdamantVerifierConfig`],
//!   [`AdamantValidationError`] — whitepaper section 6.2.1.6.
//!   The wrapper takes module bytes and returns a parsed
//!   [`Bytecode`]-bearing `CompiledModule` on success, owning
//!   the deserialize → verify → Adamant-rules pipeline as a
//!   single deploy-time decision. Wave 3a coverage: Rules 1, 4,
//!   5 (Rule 5 is enforced at the deserialize stage, where
//!   Sui's deserializer rejects the 10 deprecated global-storage
//!   bytecode variants when the locked-down config flag is set);
//!   Rules 2, 3, 6, 7 land in subsequent waves.
//!
//! Subsequent commits in Phase 5 will add the bytecode wire
//! encoding (extending Sui's serializer/deserializer to interleave
//! Adamant extensions), the AVM runtime (section 6.2), the
//! bytecode validator (section 6.2.1.6), multi-dimensional gas
//! accounting (section 6.3), module deployment (section 6.4), and
//! the parallel execution scheduler (section 6.2.3).
//!
//! # Module map
//!
//! | Module           | Whitepaper section  | Surface                                                                                                                     |
//! |------------------|---------------------|-----------------------------------------------------------------------------------------------------------------------------|
//! | [`transaction`]  | 6.0.1, 6.0.2, 6.0.3 | [`Transaction`], [`TxBody`], [`AuthEvidence`], [`AccountRef`], [`CreatedObject`], [`GasBudget`], [`CallParams`], [`Witness`] |
//! | [`value`]        | 6.0.7               | [`Value`], [`StructValue`]                                                                                                  |
//! | [`tx_hash`]      | 6.0.4               | [`derive_tx_hash`]                                                                                                          |
//! | [`bytecode`]     | 6.2.1.4             | [`AdamantBytecode`], [`AdamantOpcodeKind`], [`BytecodeInstruction`], [`CircuitId`], [`GasDimension`]                        |
//! | [`module`]       | 6.2.1.8             | [`AdamantCompiledModule`], [`AdamantFunctionDefinition`], [`AdamantCodeUnit`] (Phase 5/5a: types)                           |
//! | [`module_wire`]  | 6.2.1.2, 6.2.1.8    | [`adamant_serialize`], [`AdamantSerializeError`] (Phase 5/5a step 2: serializer)                                            |
//! | [`validator`]    | 6.2.1.6             | [`validator::verify_module`], [`AdamantVerifierConfig`], [`AdamantValidationError`] (Wave 3a: Rules 1, 4, 5)                |
//!
//! # Discipline reference
//!
//! See CONTRIBUTING.md "Derivation discipline" for the four
//! invariants every protocol-level identifier derivation must
//! satisfy (registered tag, BCS canonical input, tagged-SHA3
//! composition, KAT regression vector). [`derive_tx_hash`] follows
//! the same pattern as `adamant-account::derive_address`
//! (whitepaper section 4.2) and `adamant-state::derive_object_id`
//! (whitepaper section 5.1.1) with a different domain tag
//! ([`adamant_crypto::domain::TX_HASH`]) and a different input
//! shape ([`TxBody`]).

pub mod bytecode;
pub mod bytecode_wire;
pub mod module;
pub mod module_wire;
pub mod transaction;
pub mod tx_hash;
pub mod validator;
pub mod value;

// Re-export the inherited bytecode types from
// `adamant-bytecode-format` so consumers of `adamant-vm` see the
// Adamant-owned versions per whitepaper §6.2.1.8's resistant-
// proof posture. Per whitepaper §6.2.1.4: the AVM's instruction
// set is Sui-Move's (now Adamant-owned) plus Adamant-specific
// extensions; both ends surface through this crate's public API.
pub use adamant_bytecode_format::{Bytecode, FunctionHandleIndex};

pub use bytecode::{
    AdamantBytecode, AdamantOpcodeKind, BytecodeInstruction, CircuitId, GasDimension,
};
pub use bytecode_wire::{
    deserialize_function_body, deserialize_function_body_from_cursor, serialize_function_body,
    DeserializeConfig, DeserializeError, SerializeError,
};
pub use module::{
    AdamantCodeUnit, AdamantCompiledModule, AdamantFunctionDefinition, AdamantToSuiConversionError,
};
pub use module_wire::{
    adamant_deserialize, adamant_serialize, AdamantDeserializeError, AdamantSerializeError,
};
pub use transaction::{
    AccountRef, AuthEvidence, CallParams, CreatedObject, GasBudget, Transaction, TxBody, Witness,
};
pub use tx_hash::derive_tx_hash;
// Validator (whitepaper §6.2.1.6). The verify_module entry point
// is intentionally *not* re-exported at the crate root: callers
// invoke it as `adamant_vm::validator::verify_module(...)` to
// disambiguate from Sui's `move-bytecode-verifier` functions
// (per the architectural-pattern decision at the validator-rules
// deliverable proposal). The error and config types are
// re-exported because they are unambiguously named.
pub use validator::{AdamantValidationError, AdamantVerifierConfig, MalformedConstantReason};
pub use value::{StructValue, Value, U256_BYTES};
