//! Adamant core data types.
//!
//! This crate is the protocol's data-types foundation. It implements
//! the types defined in whitepaper sections 4 (identity & accounts)
//! and 5 (object model & state), with the canonical BCS serialisation
//! pinned in whitepaper 5.1.8. Types only; no behaviour yet — creation
//! logic, validation logic, and state-transition logic live in later
//! crates (`adamant-account`, `adamant-state`, `adamant-vm`).
//!
//! # Discipline
//!
//! - No `unsafe`. The crate inherits the workspace `unsafe_code = "forbid"`
//!   lint.
//! - Every type that flows through consensus must derive
//!   [`serde::Serialize`] and [`serde::Deserialize`] for BCS canonical
//!   encoding. Every type the crate exposes has a BCS roundtrip test.
//! - No type in this crate may use a representation BCS cannot encode
//!   canonically (per whitepaper 5.1.8): no `HashMap` with
//!   non-deterministic iteration, no floating-point values, no
//!   self-referential structures. The clippy lint surface catches
//!   floats automatically; `HashMap` and self-references are caught
//!   by review and the BCS roundtrip tests.
//!
//! # Module map
//!
//! | Module                | Whitepaper section | Types                                  |
//! |-----------------------|--------------------|----------------------------------------|
//! | [`address`]           | 4.1, 4.2           | [`Address`] (32-byte account identifier) |
//! | [`tx_hash`]           | 4.2, 6.0.4         | [`TxHash`] (32-byte transaction hash) |
//! | [`object_id`]         | 5.1.1              | [`ObjectId`] (32-byte object identifier) |
//! | [`type_id`]           | 5.1.2              | [`TypeId`] (32-byte content-addressed hash of a type definition) |
//! | [`ownership`]         | 5.1.3              | [`Ownership`] enum                     |
//! | [`mutability`]        | 5.1.4              | [`Mutability`] enum, [`BasisPoints`]   |
//! | [`object`]            | 5.1, 5.1.5, 5.1.6  | [`Object`] struct, [`Contents`]        |
//! | [`metadata`]          | 5.1.7              | [`ObjectMetadata`], [`ProofCommitment`] |
//! | [`lifecycle`]         | 5.4                | [`Lifecycle`] enum                     |
//! | [`version`]           | 5.1.6, 6.0.7       | [`Version`] alias                      |
//! | [`signature`]         | 6.0.7              | [`Signature`] enum                     |
//! | [`stealth_commitment`]| 6.0.7, 7           | [`StealthCommitment`] (32-byte)        |
//! | [`module_ref`]        | 6.0.7, 6.4.1       | [`ModuleRef`] newtype over [`ObjectId`] |
//! | [`function_id`]       | 6.0.7              | [`FunctionId`] bounded UTF-8 string    |
//!
//! [`TxHash`]'s derivation logic lives in `adamant-vm`'s
//! `derive_tx_hash` per whitepaper section 6.0.4; this crate carries
//! the type. The byte newtypes ([`StealthCommitment`],
//! [`ModuleRef`]) and the discriminated unions ([`Signature`]) are
//! peers of [`Address`] / [`ObjectId`] / [`TxHash`] / [`TypeId`] —
//! protocol-level wire-format types whose canonical encodings are
//! consensus-critical and pinned by whitepaper sections 6.0.7 and
//! related. The transaction-format types proper (`Transaction`,
//! `TxBody`, `AuthEvidence`, `AccountRef`, `CreatedObject`,
//! `GasBudget`, `CallParams`, `Witness`, `Value`, `StructValue`)
//! live in `adamant-vm` because they are VM-specific and depend on
//! types declared here.

#![forbid(unsafe_code)]

pub mod address;
pub mod function_id;
pub mod lifecycle;
pub mod metadata;
pub mod module_ref;
pub mod mutability;
pub mod object;
pub mod object_id;
pub mod ownership;
pub mod signature;
pub mod stealth_commitment;
pub mod tx_hash;
pub mod type_id;
pub mod version;

pub use address::Address;
pub use function_id::{FunctionId, FunctionIdError, FUNCTION_ID_MAX_BYTES};
pub use lifecycle::Lifecycle;
pub use metadata::{ObjectMetadata, ProofCommitment};
pub use module_ref::ModuleRef;
pub use mutability::{BasisPoints, Mutability};
pub use object::{Contents, Object, MAX_CONTENTS_BYTES};
pub use object_id::ObjectId;
pub use ownership::Ownership;
pub use signature::{
    Signature, ED25519_SIGNATURE_BYTES, ML_DSA_65_SIGNATURE_BYTES, ML_DSA_87_SIGNATURE_BYTES,
};
pub use stealth_commitment::{StealthCommitment, STEALTH_COMMITMENT_BYTES};
pub use tx_hash::TxHash;
pub use type_id::TypeId;
pub use version::Version;
