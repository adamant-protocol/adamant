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
//! | Module             | Whitepaper section | Types                                  |
//! |--------------------|--------------------|----------------------------------------|
//! | [`address`]        | 4.1, 4.2           | [`Address`] (32-byte account identifier) |
//! | [`object_id`]      | 5.1.1              | [`ObjectId`] (32-byte object identifier) |
//! | [`type_id`]        | 5.1.2              | [`TypeId`] (32-byte content-addressed hash of a type definition) |
//! | [`ownership`]      | 5.1.3              | [`Ownership`] enum                     |
//! | [`mutability`]     | 5.1.4              | [`Mutability`] enum, [`BasisPoints`]   |
//! | [`object`]         | 5.1, 5.1.5, 5.1.6  | [`Object`] struct, [`Contents`]        |
//! | [`metadata`]       | 5.1.7              | [`ObjectMetadata`], [`ProofCommitment`] |
//! | [`lifecycle`]      | 5.4                | [`Lifecycle`] enum                     |
//!
//! `Transaction` is deliberately absent — its concrete fields are
//! specified in whitepaper section 6 alongside the VM, and the type
//! lands in `adamant-vm` (Phase 5 of the implementation plan, not
//! this crate). Defining it earlier means inventing fields the spec
//! does not pin.

pub mod address;
pub mod lifecycle;
pub mod metadata;
pub mod mutability;
pub mod object;
pub mod object_id;
pub mod ownership;
pub mod type_id;

pub use address::Address;
pub use lifecycle::Lifecycle;
pub use metadata::{ObjectMetadata, ProofCommitment};
pub use mutability::{BasisPoints, Mutability};
pub use object::{Contents, Object, MAX_CONTENTS_BYTES};
pub use object_id::ObjectId;
pub use ownership::Ownership;
pub use type_id::TypeId;
