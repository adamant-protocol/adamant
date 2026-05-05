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
pub mod transaction;
pub mod tx_hash;
pub mod value;

// Re-export inherited Sui-Move types so consumers of adamant-vm
// don't reach into the vendored move-binary-format crate name
// directly. Per whitepaper §6.2.1.4: the AVM's instruction set is
// Sui-Move's plus Adamant-specific extensions; both ends surface
// through this crate's public API.
pub use move_binary_format::file_format::{Bytecode, FunctionHandleIndex};

pub use bytecode::{
    AdamantBytecode, AdamantOpcodeKind, BytecodeInstruction, CircuitId, GasDimension,
};
pub use transaction::{
    AccountRef, AuthEvidence, CallParams, CreatedObject, GasBudget, Transaction, TxBody, Witness,
};
pub use tx_hash::derive_tx_hash;
pub use value::{StructValue, Value, U256_BYTES};
