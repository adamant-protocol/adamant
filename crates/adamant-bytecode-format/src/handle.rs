//! Handle types for the Move binary format.
//!
//! Forked from `move-binary-format/src/file_format.rs` at Sui-Move
//! tag `mainnet-v1.66.2`. See `PROVENANCE.md`. Byte-identity with
//! upstream is asserted by `tests/cross_validation.rs`.
//!
//! Handles are structs that accompany opcodes that need
//! references: a type reference, a function reference, a field
//! reference, or a variant reference. Handles refer to both
//! internal and external entities and are embedded as indices in
//! the instruction stream.

use serde::{Deserialize, Serialize};

use crate::ability::AbilitySet;
use crate::index::{
    AddressIdentifierIndex, CodeOffset, EnumDefInstantiationIndex, EnumDefinitionIndex,
    IdentifierIndex, MemberCount, ModuleHandleIndex, SignatureIndex, StructDefinitionIndex,
    VariantTag,
};

/// A reference to a Move module, composed of an `address` and a
/// `name`.
///
/// A `ModuleHandle` uniquely identifies a code entity on chain.
/// The `address` is the account that holds the code; the `name`
/// is the module's name within that account's code namespace.
#[derive(Clone, Debug, Eq, Hash, PartialEq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ModuleHandle {
    /// Index into the `AddressIdentifier` pool. Identifies the
    /// module-holding account's address.
    pub address: AddressIdentifierIndex,
    /// Index into the `Identifier` pool. The module's name
    /// within the account's code namespace.
    pub name: IdentifierIndex,
}

/// A reference to a user-defined type, composed of a
/// `ModuleHandle` and the name of the type within that module.
///
/// `DatatypeHandle` is polymorphic: it carries ability constraints
/// for each type parameter (empty list for non-generic types) and
/// the abilities of the type itself, so the verifier can check
/// ability semantics without loading the referenced type.
#[derive(Clone, Debug, Eq, Hash, PartialEq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct DatatypeHandle {
    /// The module that defines the type.
    pub module: ModuleHandleIndex,
    /// The name of the type.
    pub name: IdentifierIndex,
    /// The abilities of this type. For an instantiation of this
    /// type, these abilities are predicated on the corresponding
    /// constraints holding for all type parameters.
    pub abilities: AbilitySet,
    /// The type formals (identified by their index into this
    /// vector) and their constraints.
    pub type_parameters: Vec<DatatypeTyParameter>,
}

impl DatatypeHandle {
    /// Returns an iterator over the ability constraints declared
    /// on this datatype's type parameters.
    #[must_use]
    pub fn type_param_constraints(&self) -> impl ExactSizeIterator<Item = AbilitySet> + '_ {
        self.type_parameters.iter().map(|param| param.constraints)
    }
}

/// A type parameter declared on a datatype. Carries the
/// constraint set and the phantom marker.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct DatatypeTyParameter {
    /// The constraints required of any type argument bound to
    /// this parameter.
    pub constraints: AbilitySet,
    /// Whether this parameter is declared `phantom`.
    pub is_phantom: bool,
}

/// A reference to a function, composed of a `ModuleHandle` and
/// the name and signature of the function within that module.
///
/// A function within a module is uniquely identified by its name;
/// no overloading is allowed and the verifier enforces that. The
/// signature is used at link time to ensure the reference is
/// valid and at type-check time to verify call sites.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct FunctionHandle {
    /// The module that defines the function.
    pub module: ModuleHandleIndex,
    /// The name of the function.
    pub name: IdentifierIndex,
    /// The list of parameter types.
    pub parameters: SignatureIndex,
    /// The list of return types.
    pub return_: SignatureIndex,
    /// The type formals (identified by their index into this
    /// vector) and their constraints.
    pub type_parameters: Vec<AbilitySet>,
}

/// A field-access info: owner type and offset.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct FieldHandle {
    /// The struct definition that owns this field.
    pub owner: StructDefinitionIndex,
    /// The field offset within the owner.
    pub field: MemberCount,
}

/// A reference to an enum variant: the enum definition and the
/// variant tag.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct VariantHandle {
    /// The `EnumDefinition` this `VariantHandle` belongs to.
    pub enum_def: EnumDefinitionIndex,
    /// The tag of this variant — equal to the variant's index
    /// in the `EnumDefinition`'s `variants` field.
    pub variant: VariantTag,
}

/// A reference to a generic-instantiated enum variant: the enum
/// instantiation and the variant tag.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct VariantInstantiationHandle {
    /// The `EnumDefInstantiation` this handle belongs to.
    pub enum_def: EnumDefInstantiationIndex,
    /// The tag of this variant — equal to the variant's index
    /// in the underlying `EnumDefinition`'s `variants` field.
    pub variant: VariantTag,
}

/// A jump table for a `VariantSwitch` instruction, indexed by
/// variant tag.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct VariantJumpTable {
    /// The enum definition this jump table is switching on.
    pub head_enum: EnumDefinitionIndex,
    /// The jump table itself.
    pub jump_table: JumpTableInner,
}

/// The inner shape of a [`VariantJumpTable`].
#[derive(Clone, Debug, Eq, Hash, PartialEq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum JumpTableInner {
    /// Full / "complete" jump table: every tag in the enum being
    /// switched on is present. The `CodeOffset` to jump to for a
    /// given variant tag `t` is at index `t` in this vector of
    /// code offsets.
    Full(Vec<CodeOffset>),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ability::Ability;

    /// `DatatypeHandle::type_param_constraints` returns the
    /// constraint set of each type parameter in declaration
    /// order.
    #[test]
    fn datatype_handle_type_param_constraints_in_order() {
        let h = DatatypeHandle {
            module: ModuleHandleIndex::new(0),
            name: IdentifierIndex::new(0),
            abilities: AbilitySet::EMPTY,
            type_parameters: vec![
                DatatypeTyParameter {
                    constraints: AbilitySet::PRIMITIVES,
                    is_phantom: false,
                },
                DatatypeTyParameter {
                    constraints: AbilitySet::EMPTY | Ability::Drop,
                    is_phantom: true,
                },
            ],
        };
        let constraints: Vec<AbilitySet> = h.type_param_constraints().collect();
        assert_eq!(constraints.len(), 2);
        assert_eq!(constraints[0], AbilitySet::PRIMITIVES);
        assert_eq!(constraints[1], AbilitySet::EMPTY | Ability::Drop);
    }

    /// `JumpTableInner::Full` round-trips through equality.
    #[test]
    fn jump_table_inner_full_equality() {
        let a = JumpTableInner::Full(vec![0, 1, 2]);
        let b = JumpTableInner::Full(vec![0, 1, 2]);
        let c = JumpTableInner::Full(vec![0, 2, 1]);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }
}
