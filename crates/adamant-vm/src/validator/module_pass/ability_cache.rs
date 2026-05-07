//! Memoized ability resolution for the
//! `ability_field_requirements` module-level pass
//! (whitepaper §6.2.1.8 step 3).
//!
//! Forked from `vendor/move-bytecode-verifier/src/ability_cache.rs`
//! at Sui tag `mainnet-v1.66.2` (commit
//! `a9a6825eaf6273cc819ee3bcf65fd4909f7624a9`). See
//! `validator/module_pass/PROVENANCE.md` for the full deviation
//! list. Summary:
//!
//! - Operates on [`AdamantCompiledModule`] rather than Sui's
//!   `CompiledModule`. Type-byte-identity per Phase 5/5b.1b
//!   means the algorithm carries over byte-faithfully; the
//!   wrapper differences are limited to the ability-set type
//!   path, which `adamant_bytecode_format::AbilitySet` already
//!   covers byte-for-byte.
//! - Drops `Meter`/`Scope` parameters. Adamant's deploy-time
//!   verification does not run gas accounting (gas applies at
//!   transaction-execution time per §6.3, not at module-
//!   deployment time); the upstream metering surface is dead
//!   weight in Adamant's posture.
//! - Returns [`Result<AbilitySet, AbilityCacheError>`] with a
//!   typed closed-enum error rather than upstream's
//!   `PartialVMResult<AbilitySet>` (which carries Sui's full
//!   `PartialVMError`/`StatusCode` machinery). Same diagnostic
//!   coverage; smaller error surface; no production dependence
//!   on Sui types.
//! - The single error variant
//!   [`AbilityCacheError::TypeParameterIndexOutOfRange`]
//!   replaces upstream's `safe_unwrap!` panic-on-`None`. The
//!   condition is structurally impossible after the bounds-
//!   checker pass (Phase 5/5b.3) runs, but defense-in-depth
//!   means callers receive a typed error rather than a panic
//!   if it ever surfaces.
//!
use std::collections::{btree_map::Entry, BTreeMap};

use adamant_bytecode_format::{
    AbilityError, AbilitySet, DatatypeHandleIndex, SignatureToken, TypeParameterIndex,
};

use crate::module::AdamantCompiledModule;

/// Errors returned by [`AdamantAbilityCache::abilities`].
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(super) enum AbilityCacheError {
    /// The type parameter index referenced by a
    /// [`SignatureToken::TypeParameter`] is out of range for the
    /// ambient `type_parameter_abilities` slice. Structurally
    /// impossible after Phase 5/5b.3's bounds-checker pass; this
    /// variant is the typed defense-in-depth replacement for
    /// upstream's `safe_unwrap!` panic path.
    TypeParameterIndexOutOfRange {
        /// The out-of-range index seen in the signature token.
        index: TypeParameterIndex,
        /// The slice length the index was looked up against.
        type_parameter_abilities_len: usize,
    },
    /// `AbilitySet::polymorphic_abilities` rejected its inputs
    /// per [`adamant_bytecode_format::AbilityError`].
    /// Structurally impossible after the bounds checker confirms
    /// type-parameter counts agree; defense-in-depth.
    PolymorphicAbilities(AbilityError),
}

/// Memoized resolver for the ability set of a
/// [`SignatureToken`].
///
/// Two-level cache: vector results keyed by inner ability set,
/// and datatype-instantiation results keyed by handle index +
/// per-type-arg ability set sequence. Mirrors upstream's two-
/// table layout; the algorithm reduces N type-arg evaluations
/// for the same shape from O(N) repeated work to O(1) lookup
/// after the first computation.
pub(super) struct AdamantAbilityCache<'env> {
    module: &'env AdamantCompiledModule,
    vector_results: BTreeMap<AbilitySet, AbilitySet>,
    datatype_results: BTreeMap<DatatypeHandleIndex, BTreeMap<Vec<AbilitySet>, AbilitySet>>,
}

impl<'env> AdamantAbilityCache<'env> {
    /// Build a fresh cache bound to `module`.
    pub(super) fn new(module: &'env AdamantCompiledModule) -> Self {
        Self {
            module,
            vector_results: BTreeMap::new(),
            datatype_results: BTreeMap::new(),
        }
    }

    /// Resolve the [`AbilitySet`] of `ty` under the caller's
    /// ambient type-parameter abilities.
    ///
    /// `type_parameter_abilities[i]` is the ability set bound to
    /// type parameter `i` in the enclosing context (struct,
    /// enum, or function generic header).
    pub(super) fn abilities(
        &mut self,
        type_parameter_abilities: &[AbilitySet],
        ty: &SignatureToken,
    ) -> Result<AbilitySet, AbilityCacheError> {
        use SignatureToken as S;

        Ok(match ty {
            S::Bool | S::U8 | S::U16 | S::U32 | S::U64 | S::U128 | S::U256 | S::Address => {
                AbilitySet::PRIMITIVES
            }
            S::Reference(_) | S::MutableReference(_) => AbilitySet::REFERENCES,
            S::Signer => AbilitySet::SIGNER,
            S::TypeParameter(idx) => {
                let i = *idx as usize;
                *type_parameter_abilities.get(i).ok_or(
                    AbilityCacheError::TypeParameterIndexOutOfRange {
                        index: *idx,
                        type_parameter_abilities_len: type_parameter_abilities.len(),
                    },
                )?
            }
            S::Datatype(idx) => self.module.datatype_handles[idx.0 as usize].abilities,
            S::Vector(inner) => {
                let inner_abilities = self.abilities(type_parameter_abilities, inner)?;
                match self.vector_results.entry(inner_abilities) {
                    Entry::Occupied(entry) => *entry.get(),
                    Entry::Vacant(entry) => {
                        let abilities = AbilitySet::polymorphic_abilities(
                            AbilitySet::VECTOR,
                            vec![false],
                            vec![inner_abilities],
                        )
                        .map_err(AbilityCacheError::PolymorphicAbilities)?;
                        entry.insert(abilities);
                        abilities
                    }
                }
            }
            S::DatatypeInstantiation(inst) => {
                let (idx, type_args) = &**inst;
                let type_arg_abilities = type_args
                    .iter()
                    .map(|arg| self.abilities(type_parameter_abilities, arg))
                    .collect::<Result<Vec<_>, _>>()?;
                match self
                    .datatype_results
                    .entry(*idx)
                    .or_default()
                    .entry(type_arg_abilities.clone())
                {
                    Entry::Occupied(entry) => *entry.get(),
                    Entry::Vacant(entry) => {
                        let datatype_handle = &self.module.datatype_handles[idx.0 as usize];
                        let abilities = AbilitySet::polymorphic_abilities(
                            datatype_handle.abilities,
                            datatype_handle.type_parameters.iter().map(|p| p.is_phantom),
                            type_arg_abilities,
                        )
                        .map_err(AbilityCacheError::PolymorphicAbilities)?;
                        entry.insert(abilities);
                        abilities
                    }
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use adamant_bytecode_format::{
        AbilitySet, AddressIdentifierIndex, DatatypeHandle, DatatypeHandleIndex,
        DatatypeTyParameter, Identifier, IdentifierIndex, ModuleHandle, ModuleHandleIndex,
        SignatureToken,
    };
    use adamant_types::Address as AccountAddress;

    use crate::module::AdamantCompiledModule;

    use super::{AbilityCacheError, AdamantAbilityCache};

    fn shell() -> AdamantCompiledModule {
        AdamantCompiledModule {
            self_module_handle_idx: ModuleHandleIndex(0),
            module_handles: vec![ModuleHandle {
                address: AddressIdentifierIndex(0),
                name: IdentifierIndex(0),
            }],
            identifiers: vec![Identifier::new("M").unwrap()],
            address_identifiers: vec![AccountAddress::from_bytes([0u8; 32])],
            ..AdamantCompiledModule::default()
        }
    }

    #[test]
    fn primitive_returns_primitives() {
        let m = shell();
        let mut cache = AdamantAbilityCache::new(&m);
        assert_eq!(
            cache.abilities(&[], &SignatureToken::U64).unwrap(),
            AbilitySet::PRIMITIVES
        );
    }

    #[test]
    fn reference_returns_references() {
        let m = shell();
        let mut cache = AdamantAbilityCache::new(&m);
        assert_eq!(
            cache
                .abilities(
                    &[],
                    &SignatureToken::Reference(Box::new(SignatureToken::U64))
                )
                .unwrap(),
            AbilitySet::REFERENCES
        );
    }

    #[test]
    fn signer_returns_signer() {
        let m = shell();
        let mut cache = AdamantAbilityCache::new(&m);
        assert_eq!(
            cache.abilities(&[], &SignatureToken::Signer).unwrap(),
            AbilitySet::SIGNER
        );
    }

    #[test]
    fn type_parameter_resolves_against_ambient_slice() {
        let m = shell();
        let mut cache = AdamantAbilityCache::new(&m);
        let abilities = AbilitySet::EMPTY | adamant_bytecode_format::Ability::Drop;
        assert_eq!(
            cache
                .abilities(&[abilities], &SignatureToken::TypeParameter(0))
                .unwrap(),
            abilities
        );
    }

    #[test]
    fn type_parameter_out_of_range_returns_typed_error() {
        let m = shell();
        let mut cache = AdamantAbilityCache::new(&m);
        match cache.abilities(&[], &SignatureToken::TypeParameter(0)) {
            Err(AbilityCacheError::TypeParameterIndexOutOfRange {
                index,
                type_parameter_abilities_len,
            }) => {
                assert_eq!(index, 0);
                assert_eq!(type_parameter_abilities_len, 0);
            }
            other => panic!("expected TypeParameterIndexOutOfRange, got {other:?}"),
        }
    }

    #[test]
    fn datatype_returns_handle_abilities() {
        let mut m = shell();
        m.identifiers.push(Identifier::new("S").unwrap());
        let abilities = AbilitySet::EMPTY
            | adamant_bytecode_format::Ability::Copy
            | adamant_bytecode_format::Ability::Drop;
        m.datatype_handles.push(DatatypeHandle {
            module: ModuleHandleIndex(0),
            name: IdentifierIndex(1),
            abilities,
            type_parameters: vec![],
        });
        let mut cache = AdamantAbilityCache::new(&m);
        assert_eq!(
            cache
                .abilities(&[], &SignatureToken::Datatype(DatatypeHandleIndex(0)))
                .unwrap(),
            abilities
        );
    }

    #[test]
    fn vector_memoizes_inner_lookup() {
        let m = shell();
        let mut cache = AdamantAbilityCache::new(&m);
        let v_u64 = SignatureToken::Vector(Box::new(SignatureToken::U64));
        let first = cache.abilities(&[], &v_u64).unwrap();
        let second = cache.abilities(&[], &v_u64).unwrap();
        assert_eq!(first, second);
        // Vector<u64> retains the abilities a vector inherits
        // from its primitive element type.
        assert!(first.has_ability(adamant_bytecode_format::Ability::Copy));
        assert!(first.has_ability(adamant_bytecode_format::Ability::Drop));
        assert!(first.has_ability(adamant_bytecode_format::Ability::Store));
    }

    #[test]
    fn datatype_instantiation_memoizes_per_type_arg_shape() {
        let mut m = shell();
        m.identifiers.push(Identifier::new("Box").unwrap());
        m.datatype_handles.push(DatatypeHandle {
            module: ModuleHandleIndex(0),
            name: IdentifierIndex(1),
            abilities: AbilitySet::EMPTY
                | adamant_bytecode_format::Ability::Copy
                | adamant_bytecode_format::Ability::Drop,
            type_parameters: vec![DatatypeTyParameter {
                constraints: AbilitySet::EMPTY,
                is_phantom: false,
            }],
        });
        let mut cache = AdamantAbilityCache::new(&m);
        let inst = SignatureToken::DatatypeInstantiation(Box::new((
            DatatypeHandleIndex(0),
            vec![SignatureToken::U64],
        )));
        let first = cache.abilities(&[], &inst).unwrap();
        let second = cache.abilities(&[], &inst).unwrap();
        assert_eq!(first, second);
    }
}
