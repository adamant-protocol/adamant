//! Module-level constants and the constant pool.
//!
//! Forked from `move-binary-format/src/file_format.rs` at Sui-Move
//! tag `mainnet-v1.66.2`. See `PROVENANCE.md`. Byte-identity with
//! upstream is asserted by `tests/cross_validation.rs`.
//!
//! A [`Constant`] is a serialized value with its type. The type
//! determines how the data bytes are deserialized at the
//! `LdConst` instruction's evaluation site.

use serde::{Deserialize, Serialize};

use crate::signature_token::SignatureToken;

/// A serialized constant value with its type.
///
/// The `type_` field constrains which signature tokens are valid:
/// see [`SignatureToken::is_valid_for_constant`]. The `data`
/// field is the canonical byte encoding of the value's contents
/// per the binary-format conventions.
#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct Constant {
    /// The type of this constant.
    pub type_: SignatureToken,
    /// The serialized bytes of the constant's value.
    pub data: Vec<u8>,
}

/// The pool of [`Constant`]s used by a module.
pub type ConstantPool = Vec<Constant>;
