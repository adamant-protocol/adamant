//! `SignatureToken` and its preorder traversal iterators.
//!
//! Forked from `move-binary-format/src/file_format.rs` at Sui-Move
//! tag `mainnet-v1.66.2`. See `PROVENANCE.md`. Byte-identity with
//! upstream is asserted by `tests/cross_validation.rs`.
//!
//! A [`SignatureToken`] is a type declaration for a location.
//! Every location (field, local, parameter, return) has a
//! signature token. Tokens compose recursively via `Vector`,
//! `Reference`, `MutableReference`, and `DatatypeInstantiation`.
//!
//! # Adamant deviation: serde always-on
//!
//! Upstream gates `Serialize`/`Deserialize` on the `wasm` cargo
//! feature. Adamant adds them unconditionally for parity with the
//! rest of `adamant-bytecode-format`'s production-side serde
//! exposure (see `index.rs`'s deviation note). The derived
//! encoding is the standard serde-enum tag-with-payload form;
//! the wire encoding used in module bytecode (variable-length,
//! tag byte + recursive payload bytes per
//! `move-binary-format::serializer`) is the binding consensus
//! encoding and is implemented in `adamant-vm::module_wire` —
//! independent of serde.

use core::fmt;

use serde::{Deserialize, Serialize};

use crate::index::{DatatypeHandleIndex, TypeParameterIndex};
use crate::signature_token_kind::SignatureTokenKind;

/// A type declaration for a location.
///
/// Any location in the system has a `TypeSignature`. A
/// `TypeSignature` is also used in composed signatures (see
/// `super::signature::Signature`).
///
/// A `SignatureToken` can express more types than the VM can
/// handle safely; correctness is enforced by the verifier.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub enum SignatureToken {
    /// Boolean, `true` or `false`.
    Bool,
    /// Unsigned integer, 8 bits length.
    U8,
    /// Unsigned integer, 64 bits length.
    U64,
    /// Unsigned integer, 128 bits length.
    U128,
    /// Address, a 32-byte immutable type.
    Address,
    /// Signer, a 32-byte immutable type representing the
    /// capability to publish at an address.
    Signer,
    /// Vector of an inner type.
    Vector(Box<SignatureToken>),
    /// User-defined type, referenced by index into the
    /// `DatatypeHandle` table.
    Datatype(DatatypeHandleIndex),
    /// Generic-instantiation of a user-defined type.
    DatatypeInstantiation(Box<(DatatypeHandleIndex, Vec<SignatureToken>)>),
    /// Reference to a type.
    Reference(Box<SignatureToken>),
    /// Mutable reference to a type.
    MutableReference(Box<SignatureToken>),
    /// Type-parameter slot, identified by its index in the
    /// containing handle's type-parameter list.
    TypeParameter(TypeParameterIndex),
    /// Unsigned integer, 16 bits length.
    U16,
    /// Unsigned integer, 32 bits length.
    U32,
    /// Unsigned integer, 256 bits length.
    U256,
}

/// Preorder traversal iterator for [`SignatureToken`]. Avoids
/// stack overflow on deeply-nested tokens by carrying state on a
/// heap stack.
///
/// Traversal order: root → left → right.
pub struct SignatureTokenPreorderTraversalIter<'a> {
    stack: Vec<&'a SignatureToken>,
}

impl<'a> Iterator for SignatureTokenPreorderTraversalIter<'a> {
    type Item = &'a SignatureToken;

    fn next(&mut self) -> Option<Self::Item> {
        use SignatureToken::{
            Address, Bool, Datatype, DatatypeInstantiation, MutableReference, Reference, Signer,
            TypeParameter, Vector, U128, U16, U256, U32, U64, U8,
        };
        match self.stack.pop() {
            Some(tok) => {
                match tok {
                    Reference(inner) | MutableReference(inner) | Vector(inner) => {
                        self.stack.push(inner);
                    }
                    DatatypeInstantiation(inst) => {
                        let (_, inner_toks) = &**inst;
                        self.stack.extend(inner_toks.iter().rev());
                    }
                    Signer | Bool | Address | U8 | U16 | U32 | U64 | U128 | U256 | Datatype(_)
                    | TypeParameter(_) => (),
                }
                Some(tok)
            }
            None => None,
        }
    }
}

/// Like [`SignatureTokenPreorderTraversalIter`] but yields the
/// depth of each visited token alongside the token reference.
pub struct SignatureTokenPreorderTraversalIterWithDepth<'a> {
    stack: Vec<(&'a SignatureToken, usize)>,
}

impl<'a> Iterator for SignatureTokenPreorderTraversalIterWithDepth<'a> {
    type Item = (&'a SignatureToken, usize);

    fn next(&mut self) -> Option<Self::Item> {
        use SignatureToken::{
            Address, Bool, Datatype, DatatypeInstantiation, MutableReference, Reference, Signer,
            TypeParameter, Vector, U128, U16, U256, U32, U64, U8,
        };
        match self.stack.pop() {
            Some((tok, depth)) => {
                match tok {
                    Reference(inner) | MutableReference(inner) | Vector(inner) => {
                        self.stack.push((inner, depth + 1));
                    }
                    DatatypeInstantiation(inst) => {
                        let (_, inner_toks) = &**inst;
                        self.stack
                            .extend(inner_toks.iter().map(|t| (t, depth + 1)).rev());
                    }
                    Signer | Bool | Address | U8 | U16 | U32 | U64 | U128 | U256 | Datatype(_)
                    | TypeParameter(_) => (),
                }
                Some((tok, depth))
            }
            None => None,
        }
    }
}

impl fmt::Debug for SignatureToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bool => write!(f, "Bool"),
            Self::U8 => write!(f, "U8"),
            Self::U16 => write!(f, "U16"),
            Self::U32 => write!(f, "U32"),
            Self::U64 => write!(f, "U64"),
            Self::U128 => write!(f, "U128"),
            Self::U256 => write!(f, "U256"),
            Self::Address => write!(f, "Address"),
            Self::Signer => write!(f, "Signer"),
            Self::Vector(inner) => write!(f, "Vector({inner:?})"),
            Self::Datatype(idx) => write!(f, "Struct({idx:?})"),
            Self::DatatypeInstantiation(inst) => {
                let (idx, types) = &**inst;
                write!(f, "StructInstantiation({idx:?}, {types:?})")
            }
            Self::Reference(inner) => write!(f, "Reference({inner:?})"),
            Self::MutableReference(inner) => write!(f, "MutableReference({inner:?})"),
            Self::TypeParameter(idx) => write!(f, "TypeParameter({idx:?})"),
        }
    }
}

impl SignatureToken {
    /// Returns the [`SignatureTokenKind`] of this token. Note:
    /// upstream's `SignatureTokenKind` is described in source as
    /// "out-dated" — preserved here byte-faithfully so the
    /// `signature_token_kind()` accept set matches upstream.
    #[must_use]
    pub fn signature_token_kind(&self) -> SignatureTokenKind {
        match self {
            Self::Reference(_) => SignatureTokenKind::Reference,
            Self::MutableReference(_) => SignatureTokenKind::MutableReference,
            // Per upstream comment: TypeParameter currently maps to
            // Value as a temporary hack; see Sui's
            // file_format.rs:1207-1209.
            Self::Bool
            | Self::U8
            | Self::U16
            | Self::U32
            | Self::U64
            | Self::U128
            | Self::U256
            | Self::Address
            | Self::Signer
            | Self::Datatype(_)
            | Self::DatatypeInstantiation(_)
            | Self::Vector(_)
            | Self::TypeParameter(_) => SignatureTokenKind::Value,
        }
    }

    /// Returns `true` if this is one of `U8`, `U16`, `U32`, `U64`,
    /// `U128`, or `U256`.
    #[must_use]
    pub fn is_integer(&self) -> bool {
        matches!(
            self,
            Self::U8 | Self::U16 | Self::U32 | Self::U64 | Self::U128 | Self::U256
        )
    }

    /// Returns `true` if this is a reference (mutable or
    /// immutable).
    #[must_use]
    pub fn is_reference(&self) -> bool {
        matches!(self, Self::Reference(_) | Self::MutableReference(_))
    }

    /// Returns `true` if this is a mutable reference.
    #[must_use]
    pub fn is_mutable_reference(&self) -> bool {
        matches!(self, Self::MutableReference(_))
    }

    /// Returns `true` if this is `Signer`.
    #[must_use]
    pub fn is_signer(&self) -> bool {
        matches!(self, Self::Signer)
    }

    /// Returns `true` if this token can represent a constant (a
    /// value representable in the constants table).
    #[must_use]
    pub fn is_valid_for_constant(&self) -> bool {
        match self {
            Self::Bool
            | Self::U8
            | Self::U16
            | Self::U32
            | Self::U64
            | Self::U128
            | Self::U256
            | Self::Address => true,
            Self::Vector(inner) => inner.is_valid_for_constant(),
            Self::Signer
            | Self::Datatype(_)
            | Self::DatatypeInstantiation(_)
            | Self::Reference(_)
            | Self::MutableReference(_)
            | Self::TypeParameter(_) => false,
        }
    }

    /// Set the datatype-handle index in this token. Useful for
    /// random testing (proptest fixture rewriting).
    ///
    /// # Panics
    ///
    /// Panics if this token does not contain a datatype handle —
    /// i.e., the token is not `Datatype`, `DatatypeInstantiation`,
    /// `Reference`, or `MutableReference` reaching one of those.
    pub fn debug_set_sh_idx(&mut self, sh_idx: DatatypeHandleIndex) {
        match self {
            Self::Datatype(wrapped) => *wrapped = sh_idx,
            Self::DatatypeInstantiation(inst) => Box::as_mut(inst).0 = sh_idx,
            Self::Reference(token) | Self::MutableReference(token) => {
                token.debug_set_sh_idx(sh_idx);
            }
            other => panic!("debug_set_sh_idx (to {sh_idx}) called for non-struct token {other:?}"),
        }
    }

    /// Returns a preorder traversal iterator over this token and
    /// its descendants.
    #[must_use]
    pub fn preorder_traversal(&self) -> SignatureTokenPreorderTraversalIter<'_> {
        SignatureTokenPreorderTraversalIter { stack: vec![self] }
    }

    /// Returns a preorder traversal iterator that also yields the
    /// depth of each visited token.
    #[must_use]
    pub fn preorder_traversal_with_depth(
        &self,
    ) -> SignatureTokenPreorderTraversalIterWithDepth<'_> {
        SignatureTokenPreorderTraversalIterWithDepth {
            stack: vec![(self, 1)],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `signature_token_kind` returns `Value` for primitives,
    /// datatypes, vectors, signer, and type-parameter (the
    /// upstream "temporary hack"); `Reference` for references;
    /// `MutableReference` for mutable references.
    #[test]
    fn signature_token_kind_classification() {
        assert_eq!(
            SignatureToken::U64.signature_token_kind(),
            SignatureTokenKind::Value
        );
        assert_eq!(
            SignatureToken::Reference(Box::new(SignatureToken::U64)).signature_token_kind(),
            SignatureTokenKind::Reference
        );
        assert_eq!(
            SignatureToken::MutableReference(Box::new(SignatureToken::U64)).signature_token_kind(),
            SignatureTokenKind::MutableReference
        );
        assert_eq!(
            SignatureToken::TypeParameter(0).signature_token_kind(),
            SignatureTokenKind::Value
        );
    }

    /// `is_integer` is the union of `U8`/`U16`/`U32`/`U64`/`U128`/
    /// `U256`. Pins the integer-set membership against accidental
    /// drift.
    #[test]
    fn is_integer_classifies_all_integer_widths() {
        for tok in [
            SignatureToken::U8,
            SignatureToken::U16,
            SignatureToken::U32,
            SignatureToken::U64,
            SignatureToken::U128,
            SignatureToken::U256,
        ] {
            assert!(tok.is_integer(), "{tok:?} should be integer");
        }
        for tok in [
            SignatureToken::Bool,
            SignatureToken::Address,
            SignatureToken::Signer,
            SignatureToken::Vector(Box::new(SignatureToken::U64)),
        ] {
            assert!(!tok.is_integer(), "{tok:?} should NOT be integer");
        }
    }

    /// `is_valid_for_constant` accepts primitives + Address +
    /// Vector-of-valid; rejects references, datatypes,
    /// type-parameters, signer.
    #[test]
    fn is_valid_for_constant_recursion() {
        assert!(SignatureToken::U64.is_valid_for_constant());
        assert!(SignatureToken::Address.is_valid_for_constant());
        // Vector of primitive: valid
        assert!(SignatureToken::Vector(Box::new(SignatureToken::U64)).is_valid_for_constant());
        // Vector of vector of primitive: valid (recursion)
        assert!(
            SignatureToken::Vector(Box::new(SignatureToken::Vector(Box::new(
                SignatureToken::U8
            ))))
            .is_valid_for_constant()
        );
        // Vector of reference: invalid (recursion)
        assert!(
            !SignatureToken::Vector(Box::new(SignatureToken::Reference(Box::new(
                SignatureToken::U64
            ))))
            .is_valid_for_constant()
        );
        // Signer / Datatype / TypeParameter: invalid
        assert!(!SignatureToken::Signer.is_valid_for_constant());
        assert!(!SignatureToken::Datatype(DatatypeHandleIndex::new(0)).is_valid_for_constant());
        assert!(!SignatureToken::TypeParameter(0).is_valid_for_constant());
    }

    /// Preorder traversal visits the root first, then descends
    /// into each child in order. For `Vector(Reference(U64))`,
    /// the visit order is the outer Vector, then Reference, then
    /// U64 — three nodes total.
    #[test]
    fn preorder_traversal_visits_three_nodes_for_vec_ref_u64() {
        let tok = SignatureToken::Vector(Box::new(SignatureToken::Reference(Box::new(
            SignatureToken::U64,
        ))));
        let visits: Vec<&SignatureToken> = tok.preorder_traversal().collect();
        assert_eq!(visits.len(), 3);
        assert!(matches!(visits[0], SignatureToken::Vector(_)));
        assert!(matches!(visits[1], SignatureToken::Reference(_)));
        assert_eq!(visits[2], &SignatureToken::U64);
    }

    /// Preorder-with-depth pins the depth values for a known
    /// shape: outer Vector at depth 1, its child Reference at
    /// depth 2, leaf U64 at depth 3.
    #[test]
    fn preorder_traversal_with_depth_yields_correct_depths() {
        let tok = SignatureToken::Vector(Box::new(SignatureToken::Reference(Box::new(
            SignatureToken::U64,
        ))));
        let visits: Vec<(&SignatureToken, usize)> = tok.preorder_traversal_with_depth().collect();
        assert_eq!(visits.len(), 3);
        assert_eq!(visits[0].1, 1);
        assert_eq!(visits[1].1, 2);
        assert_eq!(visits[2].1, 3);
    }

    /// `DatatypeInstantiation` traversal visits the wrapper then
    /// its inner type arguments in declaration order.
    #[test]
    fn preorder_traversal_datatype_instantiation_args_in_order() {
        let tok = SignatureToken::DatatypeInstantiation(Box::new((
            DatatypeHandleIndex::new(0),
            vec![
                SignatureToken::U8,
                SignatureToken::U64,
                SignatureToken::Bool,
            ],
        )));
        let visits: Vec<&SignatureToken> = tok.preorder_traversal().collect();
        assert_eq!(visits.len(), 4);
        assert!(matches!(
            visits[0],
            SignatureToken::DatatypeInstantiation(_)
        ));
        assert_eq!(visits[1], &SignatureToken::U8);
        assert_eq!(visits[2], &SignatureToken::U64);
        assert_eq!(visits[3], &SignatureToken::Bool);
    }

    /// `Debug` impl for `SignatureToken::Datatype` prints
    /// `Struct(...)` (matching upstream's choice of name for the
    /// renamed-but-still-displayed-as-Struct case).
    #[test]
    fn debug_datatype_prints_as_struct() {
        let tok = SignatureToken::Datatype(DatatypeHandleIndex::new(7));
        let s = format!("{tok:?}");
        assert!(s.starts_with("Struct("), "got: {s}");
    }

    /// `debug_set_sh_idx` rewrites the inner index for a
    /// `Datatype` token.
    #[test]
    fn debug_set_sh_idx_rewrites_datatype() {
        let mut tok = SignatureToken::Datatype(DatatypeHandleIndex::new(0));
        tok.debug_set_sh_idx(DatatypeHandleIndex::new(99));
        assert_eq!(tok, SignatureToken::Datatype(DatatypeHandleIndex::new(99)));
    }
}
