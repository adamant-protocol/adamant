//! `Ability` and `AbilitySet` for Move types.
//!
//! Forked from `move-binary-format/src/file_format.rs` at Sui-Move
//! tag `mainnet-v1.66.2`. See `PROVENANCE.md`. Byte-identity with
//! upstream is asserted by `tests/cross_validation.rs`.
//!
//! Adamant deviation from upstream: `polymorphic_abilities` returns
//! `Result<Self, AbilityError>` rather than upstream's
//! `PartialVMResult<Self>`. The `AbilityError` carries only the
//! arity-mismatch diagnostic the function actually produces; the
//! semantic computation is byte-identical.

use core::fmt;
use core::ops::BitOr;

use serde::{Deserialize, Serialize};

/// An `Ability` classifies what operations are permitted for a
/// given type.
#[repr(u8)]
#[derive(Debug, Clone, Eq, Copy, Hash, Ord, PartialEq, PartialOrd)]
pub enum Ability {
    /// Allows values of types with this ability to be copied, via
    /// `CopyLoc` or `ReadRef`.
    Copy = 0x1,
    /// Allows values of types with this ability to be dropped, via
    /// `Pop`, `WriteRef`, `StLoc`, `Eq`, `Neq`, or if left in a
    /// local when `Ret` is invoked. Technically also needed for
    /// numeric operations (`Add`, `BitAnd`, `Shift`, etc), but all
    /// of the types that can be used with those operations have
    /// `Drop`.
    Drop = 0x2,
    /// Allows values of types with this ability to exist inside a
    /// struct in global storage.
    Store = 0x4,
    /// Allows the type to serve as a key for global storage
    /// operations: `MoveTo`, `MoveFrom`, etc.
    Key = 0x8,
}

impl Ability {
    /// Decode a single-byte representation back into an `Ability`.
    /// Returns `None` if `u` is not one of the four defined ability
    /// bits.
    #[must_use]
    pub fn from_u8(u: u8) -> Option<Self> {
        match u {
            0x1 => Some(Self::Copy),
            0x2 => Some(Self::Drop),
            0x4 => Some(Self::Store),
            0x8 => Some(Self::Key),
            _ => None,
        }
    }

    /// For a struct with ability `a`, each field needs to have the
    /// ability `a.requires()`. Consider a generic type
    /// `Foo<t1, ..., tn>`: for `Foo<t1, ..., tn>` to have ability
    /// `a`, `Foo` must have been declared with `a` and each type
    /// argument `ti` must have the ability `a.requires()`.
    #[must_use]
    pub fn requires(self) -> Self {
        // The mapping is: Copy → Copy, Drop → Drop, Store → Store,
        // Key → Store. The Store and Key arms collapse to the same
        // body; clippy flags `match-same-arms` but separating each
        // arm keeps the mapping table readable for auditors
        // cross-referencing whitepaper §6.2.1.6 + Sui's upstream.
        #[allow(clippy::match_same_arms)]
        match self {
            Self::Copy => Self::Copy,
            Self::Drop => Self::Drop,
            Self::Store => Self::Store,
            Self::Key => Self::Store,
        }
    }

    /// An inverse of [`Self::requires`]: `x` is in `a.required_by()`
    /// iff `x.requires() == a`.
    #[must_use]
    pub fn required_by(self) -> AbilitySet {
        match self {
            Self::Copy => AbilitySet::EMPTY | Self::Copy,
            Self::Drop => AbilitySet::EMPTY | Self::Drop,
            Self::Store => AbilitySet::EMPTY | Self::Store | Self::Key,
            Self::Key => AbilitySet::EMPTY,
        }
    }
}

impl fmt::Display for Ability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Copy => write!(f, "copy"),
            Self::Drop => write!(f, "drop"),
            Self::Store => write!(f, "store"),
            Self::Key => write!(f, "key"),
        }
    }
}

/// A set of [`Ability`]s, encoded as a 1-byte bitmask.
#[derive(Clone, Eq, Copy, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct AbilitySet(u8);

impl AbilitySet {
    /// The empty ability set.
    pub const EMPTY: Self = Self(0);
    /// Abilities for `Bool`, `U8`, `U16`, `U32`, `U64`, `U128`,
    /// `U256`, and `Address`.
    pub const PRIMITIVES: AbilitySet =
        Self((Ability::Copy as u8) | (Ability::Drop as u8) | (Ability::Store as u8));
    /// Abilities for `Reference` and `MutableReference`.
    pub const REFERENCES: AbilitySet = Self((Ability::Copy as u8) | (Ability::Drop as u8));
    /// Abilities for `Signer`.
    pub const SIGNER: AbilitySet = Self(Ability::Drop as u8);
    /// Abilities for `Vector`. Note: vector abilities are
    /// predicated on the type argument; this constant is the
    /// declared set, not the polymorphic-resolved set.
    pub const VECTOR: AbilitySet =
        Self((Ability::Copy as u8) | (Ability::Drop as u8) | (Ability::Store as u8));

    /// Ability set containing all abilities.
    pub const ALL: Self = Self(
        // Cannot use AbilitySet bitor because it is not const.
        (Ability::Copy as u8)
            | (Ability::Drop as u8)
            | (Ability::Store as u8)
            | (Ability::Key as u8),
    );

    /// Singleton: an ability set containing exactly `ability`.
    #[must_use]
    pub const fn singleton(ability: Ability) -> Self {
        Self(ability as u8)
    }

    /// Returns `true` iff `self` contains `ability`.
    #[must_use]
    pub const fn has_ability(self, ability: Ability) -> bool {
        let a = ability as u8;
        (a & self.0) == a
    }

    /// Convenience: `self.has_ability(Ability::Copy)`.
    #[must_use]
    pub const fn has_copy(self) -> bool {
        self.has_ability(Ability::Copy)
    }

    /// Convenience: `self.has_ability(Ability::Drop)`.
    #[must_use]
    pub const fn has_drop(self) -> bool {
        self.has_ability(Ability::Drop)
    }

    /// Convenience: `self.has_ability(Ability::Store)`.
    #[must_use]
    pub const fn has_store(self) -> bool {
        self.has_ability(Ability::Store)
    }

    /// Convenience: `self.has_ability(Ability::Key)`.
    #[must_use]
    pub const fn has_key(self) -> bool {
        self.has_ability(Ability::Key)
    }

    /// Set difference: `self` minus a single ability.
    #[must_use]
    pub const fn remove(self, ability: Ability) -> Self {
        self.difference(Self::singleton(ability))
    }

    /// Set intersection.
    #[must_use]
    pub const fn intersect(self, other: Self) -> Self {
        Self(self.0 & other.0)
    }

    /// Set union.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Set difference.
    #[must_use]
    pub const fn difference(self, other: Self) -> Self {
        Self(self.0 & !other.0)
    }

    #[inline]
    const fn is_subset_bits(sub: u8, sup: u8) -> bool {
        (sub & sup) == sub
    }

    /// Returns `true` iff `self` is a subset of `other`.
    #[must_use]
    pub const fn is_subset(self, other: Self) -> bool {
        Self::is_subset_bits(self.0, other.0)
    }

    /// For a polymorphic type, its actual abilities correspond to
    /// its declared abilities but predicated on its non-phantom
    /// type arguments having that ability. For `Key`, instead of
    /// needing the same ability, the type arguments need `Store`.
    ///
    /// # Errors
    ///
    /// Returns [`AbilityError::ArityMismatch`] if the iterators
    /// over `declared_phantom_parameters` and `type_arguments`
    /// differ in length. Mirrors upstream's
    /// `VERIFIER_INVARIANT_VIOLATION` rejection.
    pub fn polymorphic_abilities<I1, I2>(
        declared_abilities: Self,
        declared_phantom_parameters: I1,
        type_arguments: I2,
    ) -> Result<Self, AbilityError>
    where
        I1: IntoIterator<Item = bool>,
        I2: IntoIterator<Item = Self>,
        I1::IntoIter: ExactSizeIterator,
        I2::IntoIter: ExactSizeIterator,
    {
        let declared_phantom_parameters = declared_phantom_parameters.into_iter();
        let type_arguments = type_arguments.into_iter();

        if declared_phantom_parameters.len() != type_arguments.len() {
            return Err(AbilityError::ArityMismatch);
        }

        // Conceptually this is performing the following operation:
        // For any ability 'a' in `declared_abilities`,
        // 'a' is in the result only if
        //   for all (abi_i, is_phantom_i) in `type_arguments`
        //   s.t. !is_phantom then a.required() is a subset of abi_i
        //
        // So to do this efficiently, we determine the required_by
        // set for each ti and intersect them together along with
        // the declared abilities. This only works because for any
        // ability y, |y.requires()| == 1.
        let abs = type_arguments
            .zip(declared_phantom_parameters)
            .filter(|(_, is_phantom)| !is_phantom)
            .map(|(ty_arg_abilities, _)| {
                ty_arg_abilities
                    .into_iter()
                    .map(Ability::required_by)
                    .fold(AbilitySet::EMPTY, AbilitySet::union)
            })
            .fold(declared_abilities, |acc, ty_arg_abilities| {
                acc.intersect(ty_arg_abilities)
            });
        Ok(abs)
    }

    /// Decode a single-byte representation back into an
    /// `AbilitySet`. Returns `None` if `byte` has bits set outside
    /// `ALL` (i.e., bits other than the four defined ability bits).
    #[must_use]
    pub const fn from_u8(byte: u8) -> Option<Self> {
        // If there is a bit set in the read `byte`, that bit must
        // be set in the `AbilitySet` containing all `Ability`s.
        // This corresponds to the byte being a bit-set subset of
        // ALL. The byte is a subset of ALL iff the intersection of
        // the two is the original byte.
        if Self::is_subset_bits(byte, Self::ALL.0) {
            Some(Self(byte))
        } else {
            None
        }
    }

    /// Encode `self` as a single byte.
    #[must_use]
    pub const fn into_u8(self) -> u8 {
        self.0
    }
}

impl BitOr<Ability> for AbilitySet {
    type Output = Self;
    fn bitor(self, rhs: Ability) -> Self {
        AbilitySet(self.0 | (rhs as u8))
    }
}

impl BitOr<AbilitySet> for AbilitySet {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        AbilitySet(self.0 | rhs.0)
    }
}

/// Iterator over the [`Ability`]s in an [`AbilitySet`], in
/// ascending bit order: Copy, Drop, Store, Key.
pub struct AbilitySetIterator {
    set: AbilitySet,
    idx: u8,
}

impl Iterator for AbilitySetIterator {
    type Item = Ability;

    fn next(&mut self) -> Option<Self::Item> {
        while self.idx <= 0x8 {
            let next = Ability::from_u8(self.set.0 & self.idx);
            self.idx <<= 1;
            if next.is_some() {
                return next;
            }
        }
        None
    }
}

impl IntoIterator for AbilitySet {
    type Item = Ability;
    type IntoIter = AbilitySetIterator;
    fn into_iter(self) -> Self::IntoIter {
        AbilitySetIterator {
            idx: 0x1,
            set: self,
        }
    }
}

impl fmt::Debug for AbilitySet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "[")?;
        for ability in *self {
            write!(f, "{ability:?}, ")?;
        }
        write!(f, "]")
    }
}

/// Errors from [`AbilitySet::polymorphic_abilities`].
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub enum AbilityError {
    /// `declared_phantom_parameters` and `type_arguments` differ
    /// in length. Mirrors upstream's
    /// `VERIFIER_INVARIANT_VIOLATION` rejection.
    ArityMismatch,
}

impl fmt::Display for AbilityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ArityMismatch => write!(
                f,
                "polymorphic_abilities: phantom-parameter count != type-argument count"
            ),
        }
    }
}

impl std::error::Error for AbilityError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ability_discriminants_pinned() {
        assert_eq!(Ability::Copy as u8, 0x1);
        assert_eq!(Ability::Drop as u8, 0x2);
        assert_eq!(Ability::Store as u8, 0x4);
        assert_eq!(Ability::Key as u8, 0x8);
    }

    #[test]
    fn ability_from_u8_round_trips() {
        for v in [0x1u8, 0x2, 0x4, 0x8] {
            let a = Ability::from_u8(v).unwrap();
            assert_eq!(a as u8, v);
        }
    }

    #[test]
    fn ability_from_u8_rejects_invalid() {
        for v in [0x0u8, 0x3, 0x5, 0x6, 0x7, 0x9, 0xFF] {
            assert_eq!(Ability::from_u8(v), None);
        }
    }

    #[test]
    fn ability_set_constants_pinned() {
        assert_eq!(AbilitySet::EMPTY.into_u8(), 0x0);
        assert_eq!(AbilitySet::ALL.into_u8(), 0xF);
        assert_eq!(AbilitySet::PRIMITIVES.into_u8(), 0x7);
        assert_eq!(AbilitySet::REFERENCES.into_u8(), 0x3);
        assert_eq!(AbilitySet::SIGNER.into_u8(), 0x2);
        assert_eq!(AbilitySet::VECTOR.into_u8(), 0x7);
    }

    #[test]
    fn ability_set_from_u8_accepts_all_subsets_of_all() {
        for byte in 0u8..=15 {
            let set = AbilitySet::from_u8(byte).expect("0..=15 are subsets of ALL");
            assert_eq!(set.into_u8(), byte);
        }
    }

    #[test]
    fn ability_set_from_u8_rejects_high_bits() {
        for byte in [0x10u8, 0x20, 0x80, 0xFF] {
            assert_eq!(AbilitySet::from_u8(byte), None);
        }
    }

    #[test]
    fn ability_set_iterator_yields_in_bit_order() {
        let set = AbilitySet::ALL;
        let abilities: Vec<Ability> = set.into_iter().collect();
        assert_eq!(
            abilities,
            vec![Ability::Copy, Ability::Drop, Ability::Store, Ability::Key]
        );
    }

    #[test]
    fn ability_set_subset_works() {
        assert!(AbilitySet::EMPTY.is_subset(AbilitySet::ALL));
        assert!(AbilitySet::PRIMITIVES.is_subset(AbilitySet::ALL));
        assert!(!AbilitySet::ALL.is_subset(AbilitySet::PRIMITIVES));
    }

    #[test]
    fn ability_set_union_intersect() {
        let a = AbilitySet::EMPTY | Ability::Copy;
        let b = AbilitySet::EMPTY | Ability::Drop;
        let u = a.union(b);
        let i = a.intersect(b);
        assert!(u.has_copy() && u.has_drop());
        assert_eq!(i, AbilitySet::EMPTY);
    }

    #[test]
    fn polymorphic_abilities_arity_mismatch() {
        let declared = AbilitySet::ALL;
        // 1 phantom parameter, 2 type arguments
        let err = AbilitySet::polymorphic_abilities(
            declared,
            [false],
            [AbilitySet::ALL, AbilitySet::ALL],
        )
        .unwrap_err();
        assert_eq!(err, AbilityError::ArityMismatch);
    }

    #[test]
    fn polymorphic_abilities_filters_phantom() {
        // Declared has Copy. Single non-phantom type argument also
        // has Copy → result has Copy.
        let result = AbilitySet::polymorphic_abilities(
            AbilitySet::EMPTY | Ability::Copy,
            [false],
            [AbilitySet::EMPTY | Ability::Copy],
        )
        .unwrap();
        assert!(result.has_copy());
    }
}
