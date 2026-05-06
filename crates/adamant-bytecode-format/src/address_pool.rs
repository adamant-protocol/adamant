//! `AddressIdentifierPool` — the bytecode-format module's
//! address-identifier pool.
//!
//! # Choice of address type
//!
//! Phase 5/5b.1b's verify-then-pick (Q6) confirmed that
//! [`adamant_types::Address`] has a byte-identical layout to
//! Sui's `move_core_types::account_address::AccountAddress`:
//!
//! - Both are `pub struct Foo([u8; 32])` (32-byte tuple structs).
//! - Both serialize, under BCS, as 32 raw bytes in order with
//!   no length prefix. Sui's `serialize_newtype_struct` and
//!   Adamant's `BigArray`-routed derive both reduce to that
//!   shape under non-human-readable serializers.
//! - The wire encoding used by `adamant-vm::module_wire`
//!   reads/writes 32 raw bytes directly — not through serde —
//!   so the address pool's on-chain bytes are byte-identical
//!   regardless of which serde shape the pool is constructed
//!   with at runtime.
//!
//! Reusing `adamant_types::Address` (Q6 option (b)) rather
//! than forking a parallel type:
//!
//! - Avoids duplicating address-byte-layout maintenance across
//!   two crates.
//! - Lets the bytecode-format pool flow into the canonical
//!   `Address` type used by the rest of the protocol.
//! - Does not introduce a circular workspace dependency:
//!   `adamant-types` depends only on `serde`,
//!   `serde-big-array`, and `bcs` (not on
//!   `adamant-bytecode-format`).

/// The pool of addresses used in module handles. Each entry is
/// a 32-byte [`adamant_types::Address`] per whitepaper §4.1.
pub type AddressIdentifierPool = Vec<adamant_types::Address>;
