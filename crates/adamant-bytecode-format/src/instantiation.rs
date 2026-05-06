//! Instantiation tables for the Move binary format.
//!
//! Forked from `move-binary-format/src/file_format.rs` at Sui-Move
//! tag `mainnet-v1.66.2`. See `PROVENANCE.md`. Byte-identity with
//! upstream is asserted by `tests/cross_validation.rs`.
//!
//! Instantiations point to a generic handle and the type
//! arguments to instantiate it with. The instantiation can be
//! partial: e.g. for `S<T, W>`, both `S<u8, bool>` and `S<T, u8>`
//! are valid `StructInstantiation`s.

use serde::{Deserialize, Serialize};

use crate::index::{
    EnumDefinitionIndex, FieldHandleIndex, FunctionHandleIndex, SignatureIndex,
    StructDefinitionIndex,
};

/// A complete or partial instantiation of a generic struct.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct StructDefInstantiation {
    /// The generic struct definition being instantiated.
    pub def: StructDefinitionIndex,
    /// The instantiation's type arguments, indexed into the
    /// signature pool.
    pub type_parameters: SignatureIndex,
}

/// A complete or partial instantiation of a generic function.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct FunctionInstantiation {
    /// The generic function handle being instantiated.
    pub handle: FunctionHandleIndex,
    /// The instantiation's type arguments, indexed into the
    /// signature pool.
    pub type_parameters: SignatureIndex,
}

/// A complete or partial instantiation of a field (or the type
/// of one).
///
/// Points to a generic `FieldHandle` and the instantiation of
/// its owner type. E.g., for `S<u8, bool>.f` where `f` is any
/// type, `type_parameters` would point to a signature `[u8, bool]`.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct FieldInstantiation {
    /// The generic field handle being instantiated.
    pub handle: FieldHandleIndex,
    /// The owner type's instantiation, indexed into the
    /// signature pool.
    pub type_parameters: SignatureIndex,
}

/// A complete or partial instantiation of a generic enum.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct EnumDefInstantiation {
    /// The generic enum definition being instantiated.
    pub def: EnumDefinitionIndex,
    /// The instantiation's type arguments, indexed into the
    /// signature pool.
    pub type_parameters: SignatureIndex,
}
