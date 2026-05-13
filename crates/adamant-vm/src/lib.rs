//! Adamant Move virtual machine.
//!
//! Implements whitepaper §6 — the smart-contract language, the
//! virtual machine, parallel execution, and resource accounting.
//! Phase 5 is **closed end-to-end** as of the Phase 5/5 cumulative
//! closure: Adamant-native bytecode-format types (Phase 5/5b.1a/b
//! fork in `adamant-bytecode-format`), Adamant-native verifier
//! (Phase 5/5b — 11 module-level + 5 per-function passes + 7
//! Adamant rules), Adamant-native AVM runtime + multi-dimensional
//! gas accounting (Phase 5/6), and cross-validation infrastructure
//! formalisation (Phase 5/5c) all shipped. The production
//! dependency graph contains zero `move-*` crates per the §6.2.1.8
//! resistant-proof posture, mechanically enforced by
//! `crates/adamant-vm/tests/no_sui_in_production_deps.rs`.
//!
//! # Public surface
//!
//! - [`Transaction`] and its sub-types ([`TxBody`], [`AuthEvidence`],
//!   [`AccountRef`], [`CreatedObject`], [`GasBudget`], [`CallParams`],
//!   [`Witness`]) — whitepaper §6.0.1, §6.0.2, §6.0.3.
//! - [`Value`] and [`StructValue`] — Adamant Move value taxonomy
//!   per whitepaper §6.0.7.
//! - [`derive_tx_hash`] — whitepaper §6.0.4
//!   (`TxHash = sha3_256_tagged(TX_HASH, BCS(body))`).
//! - [`AdamantBytecode`], [`AdamantOpcodeKind`],
//!   [`BytecodeInstruction`], [`CircuitId`], [`GasDimension`] —
//!   whitepaper §6.2.1.4. The Adamant-owned [`Bytecode`] enum
//!   and [`FunctionHandleIndex`] (sourced from
//!   `adamant-bytecode-format`) are re-exported from this crate's
//!   public API so downstream consumers never reach into the
//!   bytecode-format crate directly.
//! - [`validator::verify_module`], [`AdamantVerifierConfig`],
//!   [`AdamantValidationError`] — whitepaper §6.2.1.6. The single
//!   public entry point takes module bytes and returns a parsed
//!   [`AdamantCompiledModule`] on success, owning the
//!   deserialize → canonicality round-trip → 11 module-level
//!   passes → 5 per-function passes → 6 Adamant rules pipeline as
//!   the consensus-binding deploy-time decision per §6.2.1.8.
//! - [`runtime`] — AVM execution surface per §6.3.
//!
//! # Module map
//!
//! | Module           | Whitepaper section  | Surface                                                                                                                     |
//! |------------------|---------------------|-----------------------------------------------------------------------------------------------------------------------------|
//! | [`transaction`]  | 6.0.1, 6.0.2, 6.0.3 | [`Transaction`], [`TxBody`], [`AuthEvidence`], [`AccountRef`], [`CreatedObject`], [`GasBudget`], [`CallParams`], [`Witness`] |
//! | [`value`]        | 6.0.7               | [`Value`], [`StructValue`]                                                                                                  |
//! | [`tx_hash`]      | 6.0.4               | [`derive_tx_hash`]                                                                                                          |
//! | [`bytecode`]     | 6.2.1.4             | [`AdamantBytecode`], [`AdamantOpcodeKind`], [`BytecodeInstruction`], [`CircuitId`], [`GasDimension`]                        |
//! | [`module`]       | 6.2.1.8             | [`AdamantCompiledModule`], [`AdamantFunctionDefinition`], [`AdamantCodeUnit`]                                               |
//! | [`module_wire`]  | 6.2.1.2, 6.2.1.8    | [`adamant_serialize`], [`adamant_deserialize`] + their typed errors                                                         |
//! | [`bytecode_wire`]| 6.2.1.5             | per-instruction serialize/deserialize (Adamant + inherited)                                                                 |
//! | [`validator`]    | 6.2.1.6, 6.2.1.8    | [`validator::verify_module`], [`AdamantVerifierConfig`], [`AdamantValidationError`] (full pipeline; all 6 active rules)     |
//! | [`runtime`]      | 6.3                 | AVM interpreter + multi-dimensional gas accounting + module deployment                                                      |
//!
//! # Resistant-proof posture (§6.2.1.8)
//!
//! Per whitepaper §6.2.1 + §6.2.1.8: Adamant runs fully
//! independently of Sui-Move's codebase at deploy-time and
//! runtime. Vendored Sui-Move crates appear exclusively as
//! `[dev-dependencies]` for cross-validation parity testing on
//! the inherited Sui-base subset; the production binary's
//! dependency graph contains zero `move-*` crates. The
//! mechanical guardrail is the resistant-proof guard at
//! `tests/no_sui_in_production_deps.rs`, which walks
//! `cargo metadata`'s resolve tree and fails CI if any
//! `move-*` crate appears in the normal-kind dep graph.
//!
//! # Discipline reference
//!
//! See CONTRIBUTING.md "Derivation discipline" for the four
//! invariants every protocol-level identifier derivation must
//! satisfy (registered tag, BCS canonical input, tagged-SHA3
//! composition, KAT regression vector). [`derive_tx_hash`] follows
//! the same pattern as `adamant-account::derive_address`
//! (whitepaper §4.2) and `adamant-state::derive_object_id`
//! (whitepaper §5.1.1) with a different domain tag
//! ([`adamant_crypto::domain::TX_HASH`]) and a different input
//! shape ([`TxBody`]).

#![forbid(unsafe_code)]

pub mod bytecode;
pub mod bytecode_wire;
pub mod module;
pub mod module_wire;
pub mod runtime;
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
#[cfg(test)]
pub use module::AdamantToSuiConversionError;
pub use module::{AdamantCodeUnit, AdamantCompiledModule, AdamantFunctionDefinition};
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
pub use validator::{
    AdamantValidationError, AdamantVerifierConfig, FieldOwnerKind, HandleKind,
    MalformedConstantReason,
};
pub use value::{StructValue, Value, U256_BYTES};
