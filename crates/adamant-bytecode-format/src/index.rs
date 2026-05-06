//! Index machinery for the Move binary format.
//!
//! Forked from `move-binary-format/src/{lib,internals,file_format}.rs`
//! at Sui-Move tag `mainnet-v1.66.2`. See `PROVENANCE.md`. Byte-
//! identity with upstream is asserted by `tests/cross_validation.rs`.
//!
//! This module collects all index-related items in one place:
//!
//! - [`IndexKind`]: a tag enum used for diagnostic messages and as
//!   the `KIND` associated constant on each index newtype.
//! - [`ModuleIndex`]: the trait every index newtype implements,
//!   exposing `into_index() -> usize` for pool indexing.
//! - The `define_index!` macro (private to this module) generates
//!   each newtype with a uniform set of derives + impls.
//! - Eighteen `*Index` newtypes (one per `IndexKind` variant that
//!   names a concrete pool index).
//! - Six simple type aliases consumed across the binary format:
//!   [`TableIndex`], [`LocalIndex`], [`MemberCount`], [`CodeOffset`],
//!   [`VariantTag`], [`TypeParameterIndex`].
//!
//! # Adamant deviation: serde always-on
//!
//! Upstream Sui gates `Serialize`/`Deserialize` on the `wasm`
//! cargo feature for these newtypes. Adamant adds them
//! unconditionally because production-side Adamant code (e.g.,
//! BCS-decoding the privacy metadata payload
//! `Vec<(FunctionDefinitionIndex, u8)>` per whitepaper §6.2.1.6
//! Rule 2) needs serde on the wire. Byte layout of the encoded
//! form is the underlying `TableIndex` (a `u16`), matching what
//! upstream produces under `wasm`.

use core::fmt;

use serde::{Deserialize, Serialize};

// ============================================================================
// IndexKind
// ============================================================================

/// A kind of index — one tag per pool that an index can address.
///
/// Used for diagnostic messages (via [`fmt::Display`]) and as the
/// `KIND` associated constant on each index newtype's
/// [`ModuleIndex`] impl.
///
/// # Upstream quirk preserved
///
/// Sui's upstream `IndexKind::variants()` omits the
/// `AddressIdentifier` variant from the returned list (the enum
/// itself includes it, and [`fmt::Display`] handles it). This
/// looks like an upstream bug, but Adamant preserves the omission
/// byte-for-byte: `variants().len() == 24` rather than 25, and
/// `AddressIdentifier` is the only enum variant missing. Pinned
/// by a cross-validation test against the still-vendored Sui
/// reference.
#[derive(Copy, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum IndexKind {
    /// `ModuleHandle` table.
    ModuleHandle,
    /// `DatatypeHandle` table.
    DatatypeHandle,
    /// `FunctionHandle` table.
    FunctionHandle,
    /// `FieldHandle` table.
    FieldHandle,
    /// Friend-declaration list.
    FriendDeclaration,
    /// `FunctionInstantiation` table.
    FunctionInstantiation,
    /// `FieldInstantiation` table.
    FieldInstantiation,
    /// `StructDefinition` table.
    StructDefinition,
    /// `StructDefInstantiation` table.
    StructDefInstantiation,
    /// `FunctionDefinition` table.
    FunctionDefinition,
    /// `FieldDefinition` slot inside a `StructDefinition` /
    /// `VariantDefinition`.
    FieldDefinition,
    /// `Signature` pool.
    Signature,
    /// `Identifier` pool.
    Identifier,
    /// `AddressIdentifier` pool. Note: this variant is omitted
    /// from [`IndexKind::variants`] per upstream Sui's quirk; see
    /// the type-level note.
    AddressIdentifier,
    /// `Constant` pool.
    ConstantPool,
    /// Local-variable pool inside a function (locals signature).
    LocalPool,
    /// Function body / code-definition table.
    CodeDefinition,
    /// Type-parameter slot inside a generic handle.
    TypeParameter,
    /// Member-count slot (a field offset within a struct or
    /// variant).
    MemberCount,
    /// `EnumDefinition` table.
    EnumDefinition,
    /// `EnumDefInstantiation` table.
    EnumDefInstantiation,
    /// `VariantHandle` table.
    VariantHandle,
    /// `VariantInstantiationHandle` table.
    VariantInstantiationHandle,
    /// `VariantJumpTable` slot inside a function body.
    VariantJumpTable,
    /// Variant-tag slot inside an enum value.
    VariantTag,
}

impl IndexKind {
    /// Returns the list of variants used by the binary format
    /// machinery. Note: `AddressIdentifier` is intentionally
    /// omitted to match upstream Sui (see the type-level note).
    #[must_use]
    pub fn variants() -> &'static [IndexKind] {
        use IndexKind::{
            CodeDefinition, ConstantPool, DatatypeHandle, EnumDefInstantiation, EnumDefinition,
            FieldDefinition, FieldHandle, FieldInstantiation, FriendDeclaration,
            FunctionDefinition, FunctionHandle, FunctionInstantiation, Identifier, LocalPool,
            MemberCount, ModuleHandle, Signature, StructDefInstantiation, StructDefinition,
            TypeParameter, VariantHandle, VariantInstantiationHandle, VariantJumpTable, VariantTag,
        };
        &[
            ModuleHandle,
            DatatypeHandle,
            FunctionHandle,
            FieldHandle,
            FriendDeclaration,
            StructDefInstantiation,
            FunctionInstantiation,
            FieldInstantiation,
            StructDefinition,
            FunctionDefinition,
            FieldDefinition,
            Signature,
            Identifier,
            ConstantPool,
            LocalPool,
            CodeDefinition,
            TypeParameter,
            MemberCount,
            EnumDefinition,
            EnumDefInstantiation,
            VariantHandle,
            VariantInstantiationHandle,
            VariantJumpTable,
            VariantTag,
        ]
    }
}

impl fmt::Display for IndexKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let desc = match self {
            Self::ModuleHandle => "module handle",
            Self::DatatypeHandle => "datatype handle",
            Self::FunctionHandle => "function handle",
            Self::FieldHandle => "field handle",
            Self::FriendDeclaration => "friend declaration",
            Self::StructDefInstantiation => "struct instantiation",
            Self::FunctionInstantiation => "function instantiation",
            Self::FieldInstantiation => "field instantiation",
            Self::StructDefinition => "struct definition",
            Self::FunctionDefinition => "function definition",
            Self::FieldDefinition => "field definition",
            Self::Signature => "signature",
            Self::Identifier => "identifier",
            Self::AddressIdentifier => "address identifier",
            Self::ConstantPool => "constant pool",
            Self::LocalPool => "local pool",
            Self::CodeDefinition => "code definition pool",
            Self::TypeParameter => "type parameter",
            Self::MemberCount => "field offset",
            Self::EnumDefinition => "enum definition",
            Self::EnumDefInstantiation => "enum instantiation",
            Self::VariantHandle => "variant handle",
            Self::VariantInstantiationHandle => "variant instantiation handle",
            Self::VariantJumpTable => "jump table",
            Self::VariantTag => "variant tag",
        };
        f.write_str(desc)
    }
}

// ============================================================================
// ModuleIndex trait
// ============================================================================

/// Every `*Index` newtype implements this trait. The associated
/// constant [`Self::KIND`] tags the addressed pool; the
/// [`Self::into_index`] method projects the newtype to a `usize`
/// for slicing into the pool.
pub trait ModuleIndex {
    /// The pool kind this index addresses.
    const KIND: IndexKind;
    /// Project to a `usize` index suitable for slicing the
    /// addressed pool.
    fn into_index(self) -> usize;
}

// ============================================================================
// Type aliases
// ============================================================================

/// Generic table index. All `*Index` newtypes wrap a value of this
/// type. The width is `u16`, matching the `TableIndex` pool size
/// upper bound `TABLE_INDEX_MAX = u16::MAX`.
pub type TableIndex = u16;

/// Index of a local variable in a function. Bytecodes that
/// operate on locals carry indices to the locals of a function.
pub type LocalIndex = u8;

/// Max number of fields in a `StructDefinition`.
pub type MemberCount = u16;

/// Index into the code stream for a jump. The offset is relative
/// to the beginning of the instruction stream.
pub type CodeOffset = u16;

/// Tag representing the variant of an enum.
pub type VariantTag = MemberCount;

/// Type parameters are encoded as indices. This index is also
/// used to look up the kind of a type parameter in the
/// `FunctionHandle` and `DatatypeHandle`.
pub type TypeParameterIndex = u16;

// ============================================================================
// define_index! macro
// ============================================================================

/// Generates a `*Index` newtype with the standard set of impls.
///
/// Two forms:
///
/// ```text
/// define_index! { name: Foo, kind: Foo, doc: "..." }
/// define_index! { name: Foo, kind: Foo, doc: "...", bounds: "0u16..1024u16" }
/// ```
///
/// The `bounds:` form is currently unused by Adamant (the
/// proptest-strategy attribute it would emit requires
/// `proptest_derive`, which is not in this crate's dev-deps; the
/// bounds-bearing variant is preserved for byte-faithful parity
/// with upstream so the macro forms match cross-references).
macro_rules! define_index {
    {
        name: $name:ident,
        kind: $kind:ident,
        doc: $comment:literal $(,)?
    } => {
        define_index!(@internal $name, $kind, $comment);
    };
    {
        name: $name:ident,
        kind: $kind:ident,
        doc: $comment:literal,
        bounds: $bounds:literal $(,)?
    } => {
        define_index!(@internal $name, $kind, $comment);
    };

    (@internal $name:ident, $kind:ident, $comment:literal) => {
        #[doc = $comment]
        #[derive(
            Clone, Copy, Default, Eq, Hash, Ord, PartialEq, PartialOrd,
            Serialize, Deserialize,
        )]
        pub struct $name(pub TableIndex);

        impl $name {
            /// Construct an index from a `TableIndex` value.
            #[must_use]
            pub fn new(idx: TableIndex) -> Self {
                Self(idx)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", self.0)
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({})", stringify!($name), self.0)
            }
        }

        impl ModuleIndex for $name {
            const KIND: IndexKind = IndexKind::$kind;

            #[inline]
            fn into_index(self) -> usize {
                self.0 as usize
            }
        }
    };
}

// ============================================================================
// Eighteen index newtypes
// ============================================================================

define_index! {
    name: ModuleHandleIndex,
    kind: ModuleHandle,
    doc: "Index into the `ModuleHandle` table.",
}
define_index! {
    name: DatatypeHandleIndex,
    kind: DatatypeHandle,
    doc: "Index into the `DatatypeHandle` table.",
}
define_index! {
    name: FunctionHandleIndex,
    kind: FunctionHandle,
    doc: "Index into the `FunctionHandle` table.",
}
define_index! {
    name: FieldHandleIndex,
    kind: FieldHandle,
    doc: "Index into the `FieldHandle` table.",
}
define_index! {
    name: StructDefInstantiationIndex,
    kind: StructDefInstantiation,
    doc: "Index into the `StructDefInstantiation` table.",
}
define_index! {
    name: FunctionInstantiationIndex,
    kind: FunctionInstantiation,
    doc: "Index into the `FunctionInstantiation` table.",
}
define_index! {
    name: FieldInstantiationIndex,
    kind: FieldInstantiation,
    doc: "Index into the `FieldInstantiation` table.",
}
define_index! {
    name: IdentifierIndex,
    kind: Identifier,
    doc: "Index into the `Identifier` table.",
}
define_index! {
    name: AddressIdentifierIndex,
    kind: AddressIdentifier,
    doc: "Index into the `AddressIdentifier` table.",
}
define_index! {
    name: ConstantPoolIndex,
    kind: ConstantPool,
    doc: "Index into the `ConstantPool` table.",
}
define_index! {
    name: SignatureIndex,
    kind: Signature,
    doc: "Index into the `Signature` table.",
}
define_index! {
    name: StructDefinitionIndex,
    kind: StructDefinition,
    doc: "Index into the `StructDefinition` table.",
}
define_index! {
    name: FunctionDefinitionIndex,
    kind: FunctionDefinition,
    doc: "Index into the `FunctionDefinition` table.",
}
define_index! {
    name: EnumDefinitionIndex,
    kind: EnumDefinition,
    doc: "Index into the `EnumDefinition` table.",
}
define_index! {
    name: EnumDefInstantiationIndex,
    kind: EnumDefInstantiation,
    doc: "Index into the `EnumDefInstantiation` table.",
}
define_index! {
    name: VariantJumpTableIndex,
    kind: VariantJumpTable,
    doc: "Index into the `VariantJumpTable` table.",
    bounds: "0u16..128u16",
}
define_index! {
    name: VariantHandleIndex,
    kind: VariantHandle,
    doc: "Index into the `VariantHandle` table.",
    bounds: "0u16..1024u16",
}
define_index! {
    name: VariantInstantiationHandleIndex,
    kind: VariantInstantiationHandle,
    doc: "Index into the `VariantInstantiationHandle` table.",
    bounds: "0u16..1024u16",
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// `IndexKind::variants()` preserves upstream's quirk of
    /// omitting `AddressIdentifier`. The list has 24 entries (not
    /// 25) and does not contain `AddressIdentifier`. This is an
    /// **Adamant deviation pin**: if the variants list is ever
    /// "fixed" without a deliberate spec amendment, this test
    /// fails.
    #[test]
    fn variants_preserves_upstream_address_identifier_omission() {
        let v = IndexKind::variants();
        assert_eq!(v.len(), 24, "upstream omits AddressIdentifier");
        assert!(
            !v.contains(&IndexKind::AddressIdentifier),
            "AddressIdentifier must NOT appear in variants() per upstream"
        );
        assert!(v.contains(&IndexKind::Identifier));
    }

    /// `IndexKind`'s `Display` impl preserves the `address
    /// identifier` string for the omitted-from-`variants()`
    /// variant — confirms the omission is in `variants()` only,
    /// not in the type or its `Display`.
    #[test]
    fn address_identifier_displays_correctly() {
        assert_eq!(
            format!("{}", IndexKind::AddressIdentifier),
            "address identifier"
        );
    }

    /// Smoke-test the macro: `ModuleHandleIndex::KIND ==
    /// IndexKind::ModuleHandle`, `into_index` projects the inner
    /// value, and `new` round-trips.
    #[test]
    fn module_index_trait_works() {
        let idx = ModuleHandleIndex::new(42);
        assert_eq!(idx.0, 42);
        assert_eq!(idx.into_index(), 42usize);
        assert_eq!(ModuleHandleIndex::KIND, IndexKind::ModuleHandle);
    }

    /// All 18 index types have distinct `KIND`s. Pins the
    /// macro's `kind:` argument across the 18 invocations.
    #[test]
    fn all_index_kinds_distinct() {
        let kinds = [
            ModuleHandleIndex::KIND,
            DatatypeHandleIndex::KIND,
            FunctionHandleIndex::KIND,
            FieldHandleIndex::KIND,
            StructDefInstantiationIndex::KIND,
            FunctionInstantiationIndex::KIND,
            FieldInstantiationIndex::KIND,
            IdentifierIndex::KIND,
            AddressIdentifierIndex::KIND,
            ConstantPoolIndex::KIND,
            SignatureIndex::KIND,
            StructDefinitionIndex::KIND,
            FunctionDefinitionIndex::KIND,
            EnumDefinitionIndex::KIND,
            EnumDefInstantiationIndex::KIND,
            VariantJumpTableIndex::KIND,
            VariantHandleIndex::KIND,
            VariantInstantiationHandleIndex::KIND,
        ];
        let mut sorted = kinds.to_vec();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), 18, "all 18 KINDs must be distinct");
    }

    /// `Default` produces an index of zero for any `*Index` type.
    #[test]
    fn default_is_zero() {
        assert_eq!(ModuleHandleIndex::default().0, 0);
        assert_eq!(SignatureIndex::default().0, 0);
        assert_eq!(VariantJumpTableIndex::default().0, 0);
    }

    /// `Debug` formatting matches upstream's `Foo(N)` shape.
    #[test]
    fn debug_format_matches_upstream() {
        assert_eq!(
            format!("{:?}", ModuleHandleIndex::new(7)),
            "ModuleHandleIndex(7)"
        );
        assert_eq!(format!("{:?}", SignatureIndex::new(0)), "SignatureIndex(0)");
    }

    /// `Display` formatting prints the inner value alone.
    #[test]
    fn display_format_matches_upstream() {
        assert_eq!(format!("{}", ModuleHandleIndex::new(7)), "7");
    }

    /// Type aliases pin to expected widths.
    #[test]
    fn type_alias_widths_pinned() {
        assert_eq!(core::mem::size_of::<TableIndex>(), 2);
        assert_eq!(core::mem::size_of::<LocalIndex>(), 1);
        assert_eq!(core::mem::size_of::<MemberCount>(), 2);
        assert_eq!(core::mem::size_of::<CodeOffset>(), 2);
        assert_eq!(core::mem::size_of::<VariantTag>(), 2);
        assert_eq!(core::mem::size_of::<TypeParameterIndex>(), 2);
    }
}
