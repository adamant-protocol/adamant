//! Definition types for the Move binary format.
//!
//! Forked from `move-binary-format/src/file_format.rs` at Sui-Move
//! tag `mainnet-v1.66.2`. See `PROVENANCE.md`. Byte-identity with
//! upstream is asserted by `tests/cross_validation.rs`.
//!
//! Definitions are the module's own types and functions, in
//! contrast to handles (which reference internal-or-external
//! entities). This file collects struct definitions, enum
//! definitions, field definitions, variant definitions, and
//! function visibility.
//!
//! `FunctionDefinition` lives in a separate module
//! (`super::function_definition`) because it depends on
//! `super::code_unit::CodeUnit`, which depends on
//! `super::bytecode::Bytecode` — both arrive in later sub-arcs
//! (Phase 5/5b.1b's B-3 and B-4 internal phases).
//!
//! # Adamant deviation: `StructDefinition::declared_field_count` error type
//!
//! Upstream returns `PartialVMResult<MemberCount>` (an
//! `anyhow`-style error wrapping `StatusCode`). Adamant returns
//! `Result<MemberCount, NativeStructError>` where
//! `NativeStructError` is a closed unit enum. Same accept set;
//! same diagnostic content. Reasons:
//! (i) avoids pulling Sui's full error machinery into the
//! production graph,
//! (ii) typed pattern-match access at call sites,
//! (iii) callers in `adamant-vm` already adapt to typed errors.

use core::fmt;

use serde::{Deserialize, Serialize};

use crate::index::{DatatypeHandleIndex, IdentifierIndex, MemberCount};
use crate::signature::TypeSignature;

// ============================================================================
// Visibility
// ============================================================================

/// `Visibility` restricts who may call into a function.
#[repr(u8)]
#[derive(
    Clone, Copy, Debug, Default, Eq, PartialEq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
pub enum Visibility {
    /// Accessible only within the defining module.
    #[default]
    Private = 0x0,
    /// Accessible by any module or script outside the defining
    /// module.
    Public = 0x1,
    // The discriminant `0x2` is reserved by upstream for a
    // deprecated `Script` visibility; do not reuse. See
    // [`Self::DEPRECATED_SCRIPT`].
    /// Accessible by the defining module and any module declared
    /// in the friend list.
    Friend = 0x3,
}

impl Visibility {
    /// Discriminant byte (`0x2`) reserved by upstream for the
    /// deprecated `Script` visibility. Preserved here for
    /// byte-faithful parity with the binary-format version
    /// pinned at §6.2.1.2; do not reuse.
    pub const DEPRECATED_SCRIPT: u8 = 0x2;
}

impl TryFrom<u8> for Visibility {
    type Error = ();

    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            x if x == Self::Private as u8 => Ok(Self::Private),
            x if x == Self::Public as u8 => Ok(Self::Public),
            x if x == Self::Friend as u8 => Ok(Self::Friend),
            _ => Err(()),
        }
    }
}

// ============================================================================
// FieldDefinition + StructDefinition + StructFieldInformation
// ============================================================================

/// The definition of a field: its name and type.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FieldDefinition {
    /// The field's name.
    pub name: IdentifierIndex,
    /// The field's type.
    pub signature: TypeSignature,
}

/// Indicates whether a struct is native (has no accessible
/// fields) or has user-declared fields.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum StructFieldInformation {
    /// Native struct: opaque from user code, no fields.
    Native,
    /// Declared struct: carries the field definitions.
    Declared(Vec<FieldDefinition>),
}

/// A struct type definition.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct StructDefinition {
    /// The `DatatypeHandle` for this struct. Carries the name
    /// and the abilities for the type.
    pub struct_handle: DatatypeHandleIndex,
    /// Either:
    /// - [`StructFieldInformation::Native`] if the struct is
    ///   native and has no accessible fields, or
    /// - [`StructFieldInformation::Declared`] with the
    ///   declared field definitions.
    pub field_information: StructFieldInformation,
}

/// Errors from operations on a [`StructDefinition`] that vary
/// based on the [`StructFieldInformation`] variant.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub enum NativeStructError {
    /// The operation requires a struct with declared fields, but
    /// the struct is `Native`. Mirrors upstream's `LINKER_ERROR`
    /// classification of the same condition.
    StructIsNative,
}

impl fmt::Display for NativeStructError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StructIsNative => write!(f, "looking for field in native structure"),
        }
    }
}

impl std::error::Error for NativeStructError {}

impl StructDefinition {
    /// Returns the number of declared fields, or
    /// [`NativeStructError::StructIsNative`] if the struct is
    /// native.
    ///
    /// # Errors
    ///
    /// Returns [`NativeStructError::StructIsNative`] when
    /// `field_information` is [`StructFieldInformation::Native`].
    ///
    /// # Panics
    ///
    /// Panics if `fields.len()` exceeds `MemberCount::MAX`
    /// (`u16::MAX`). The binary-format structural-limit pass
    /// rejects modules with more than `FIELD_COUNT_MAX` fields,
    /// so this branch is unreachable for inputs the deploy-time
    /// pipeline produces.
    pub fn declared_field_count(&self) -> Result<MemberCount, NativeStructError> {
        match &self.field_information {
            StructFieldInformation::Native => Err(NativeStructError::StructIsNative),
            StructFieldInformation::Declared(fields) => {
                // Cast safety: a declared-fields list is bounded
                // by `FIELD_COUNT_MAX = u16::MAX` per the binary-
                // format structural-limit pass; modules accepted
                // at deploy time honour this bound. `try_from`
                // makes the bound explicit (vs upstream's silent
                // `as u16` truncation).
                Ok(MemberCount::try_from(fields.len())
                    .expect("declared field count fits MemberCount per FIELD_COUNT_MAX"))
            }
        }
    }

    /// Returns the field definition at `offset`, or `None` if the
    /// struct is native or the offset is out of range.
    #[must_use]
    pub fn field(&self, offset: usize) -> Option<&FieldDefinition> {
        match &self.field_information {
            StructFieldInformation::Native => None,
            StructFieldInformation::Declared(fields) => fields.get(offset),
        }
    }

    /// Returns a slice over the declared fields, or `None` if
    /// the struct is native.
    #[must_use]
    pub fn fields(&self) -> Option<&[FieldDefinition]> {
        match &self.field_information {
            StructFieldInformation::Native => None,
            StructFieldInformation::Declared(fields) => Some(fields),
        }
    }
}

// ============================================================================
// EnumDefinition + VariantDefinition
// ============================================================================

/// An enum type definition.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EnumDefinition {
    /// The `DatatypeHandle` for this enum. Carries the name and
    /// the abilities for the type.
    pub enum_handle: DatatypeHandleIndex,
    /// The variants of this enum. The variant tag equals the
    /// index of the variant in this vector.
    pub variants: Vec<VariantDefinition>,
}

/// A single variant of an enum.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct VariantDefinition {
    /// The variant's name.
    pub variant_name: IdentifierIndex,
    /// The fields of this variant.
    pub fields: Vec<FieldDefinition>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signature_token::SignatureToken;

    /// `Visibility::default()` is `Private`.
    #[test]
    fn visibility_default_is_private() {
        assert_eq!(Visibility::default(), Visibility::Private);
    }

    /// `Visibility::try_from(u8)` accepts the three valid
    /// discriminants and rejects the deprecated `Script` (`0x2`)
    /// and any other byte.
    #[test]
    fn visibility_try_from_accepts_valid_rejects_others() {
        assert_eq!(Visibility::try_from(0x0), Ok(Visibility::Private));
        assert_eq!(Visibility::try_from(0x1), Ok(Visibility::Public));
        assert_eq!(Visibility::try_from(0x3), Ok(Visibility::Friend));
        assert_eq!(Visibility::try_from(Visibility::DEPRECATED_SCRIPT), Err(()));
        assert_eq!(Visibility::try_from(0x4), Err(()));
        assert_eq!(Visibility::try_from(0xFF), Err(()));
    }

    /// `Visibility` discriminants are byte-pinned: `Private =
    /// 0x0`, `Public = 0x1`, `Friend = 0x3`. Reordering or
    /// renumbering is a hard fork.
    #[test]
    fn visibility_discriminants_pinned() {
        assert_eq!(Visibility::Private as u8, 0x0);
        assert_eq!(Visibility::Public as u8, 0x1);
        assert_eq!(Visibility::Friend as u8, 0x3);
        assert_eq!(Visibility::DEPRECATED_SCRIPT, 0x2);
    }

    /// `declared_field_count` on a native struct returns the
    /// typed error.
    #[test]
    fn declared_field_count_native_struct_errors() {
        let s = StructDefinition {
            struct_handle: DatatypeHandleIndex::new(0),
            field_information: StructFieldInformation::Native,
        };
        assert_eq!(
            s.declared_field_count(),
            Err(NativeStructError::StructIsNative)
        );
        assert!(s.fields().is_none());
        assert!(s.field(0).is_none());
    }

    /// `declared_field_count` on a struct with declared fields
    /// returns the count.
    #[test]
    fn declared_field_count_declared_struct_returns_count() {
        let f = FieldDefinition {
            name: IdentifierIndex::new(0),
            signature: TypeSignature(SignatureToken::U64),
        };
        let s = StructDefinition {
            struct_handle: DatatypeHandleIndex::new(0),
            field_information: StructFieldInformation::Declared(vec![f.clone(), f.clone(), f]),
        };
        assert_eq!(s.declared_field_count(), Ok(3));
        assert_eq!(s.fields().unwrap().len(), 3);
        assert!(s.field(0).is_some());
        assert!(s.field(2).is_some());
        assert!(s.field(3).is_none());
    }

    /// `NativeStructError`'s `Display` is the upstream-matching
    /// "looking for field in native structure" string.
    #[test]
    fn native_struct_error_display() {
        let err = NativeStructError::StructIsNative;
        assert_eq!(format!("{err}"), "looking for field in native structure");
    }
}
