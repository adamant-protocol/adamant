//! Module-level metadata entries.
//!
//! Forked from `move-core-types/src/metadata.rs` at Sui-Move tag
//! `mainnet-v1.66.2`. See `PROVENANCE.md`. Byte-identity with
//! upstream is asserted by `tests/cross_validation.rs`.
//!
//! Adamant's validator (whitepaper §6.2.1.6) reads three keys
//! from this metadata pool:
//!
//! - `b"adamant.mutability"` — BCS-encoded `adamant_types::Mutability`
//!   (Rule 1).
//! - `b"adamant.privacy"` — BCS-encoded
//!   `Vec<(FunctionDefinitionIndex, u8)>` (Rule 2).
//! - `b"adamant.allows_dynamic"` — BCS-encoded `bool` (Rule 6).
//!
//! All other keys are inherited Sui metadata and are passed
//! through without semantic interpretation.

use serde::{Deserialize, Serialize};

/// A module-level metadata entry: an opaque key and its
/// opaque value.
#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct Metadata {
    /// The key identifying the type of metadata.
    pub key: Vec<u8>,
    /// The value of the metadata.
    pub value: Vec<u8>,
}
