//! Shared test helpers for cross-module verifier passes.
//!
//! Phase 5/5b.5 E-2a extracts [`InMemoryModuleResolver`] at
//! N=1 (sub-shape γ of helper-extraction discipline; extract-
//! at-N=1-anticipating-multiple-consumers). The resolver is
//! consumed by E-2a's trait/API correctness tests and E-2b's
//! cross-module Rule 3 walker tests; the cross-module subtree
//! has multiple Layer A test sites from inception, motivating
//! anticipated extraction at first use rather than the
//! reuse-triggered extraction sub-shapes α (`module_pass` at
//! B-2.2; N=2) and β (`function_pass` at D-7a; N=3).

use std::collections::HashMap;
#[cfg(test)]
use std::collections::HashSet;

use crate::module::AdamantCompiledModule;

use super::{ModuleId, ModuleResolver};

/// In-memory [`ModuleResolver`] backed by a [`HashMap`].
/// Test-only: no production caller constructs this; the
/// production caller (eventually the AVM runtime stdlib's
/// `adamant::module::deploy` function in Phase 5/6) implements
/// [`ModuleResolver`] over chain-state object storage.
///
/// Construct via [`Self::new`] (empty map) or
/// [`Self::from_modules`] (initial set).
pub(in crate::validator) struct InMemoryModuleResolver {
    modules: HashMap<ModuleId, AdamantCompiledModule>,
}

impl InMemoryModuleResolver {
    /// Construct an empty resolver. Modules are inserted via
    /// [`Self::insert`].
    pub(in crate::validator) fn new() -> Self {
        Self {
            modules: HashMap::new(),
        }
    }

    /// Insert a module into the resolver under its self-id
    /// (resolved via [`ModuleId::from_module`]).
    ///
    /// # Panics
    ///
    /// Panics if `module`'s self-handle indices are out of
    /// bounds, i.e., [`ModuleId::from_module`] returns `None`.
    /// Test fixtures must have valid self-handle wiring; this
    /// assertion catches fixture bugs eagerly rather than
    /// silently dropping the module from the resolver.
    pub(in crate::validator) fn insert(&mut self, module: AdamantCompiledModule) {
        let id = ModuleId::from_module(&module).expect(
            "InMemoryModuleResolver requires modules with valid self-handle wiring; \
             test fixtures must satisfy bounds_checker preconditions",
        );
        self.modules.insert(id, module);
    }
}

impl ModuleResolver for InMemoryModuleResolver {
    fn resolve(&self, id: &ModuleId) -> Option<&AdamantCompiledModule> {
        self.modules.get(id)
    }
}

#[cfg(test)]
mod tests {
    //! Layer A unit tests for the [`InMemoryModuleResolver`]
    //! helper itself. Trait/API correctness — the resolver
    //! returns inserted modules under their self-id and `None`
    //! for unknown ids.

    use super::*;
    use adamant_bytecode_format::{
        AddressIdentifierIndex, Identifier, IdentifierIndex, ModuleHandle, ModuleHandleIndex,
    };
    use adamant_types::Address;

    /// Build a minimal-shape module with the `self`-handle
    /// wiring (`self_module_handle_idx` plus `module_handles[0]`,
    /// `identifiers[0]`, and `address_identifiers[0]`) so
    /// [`ModuleId::from_module`] resolves cleanly.
    fn make_module(address_byte: u8, name: &str) -> AdamantCompiledModule {
        let mut m = AdamantCompiledModule::default();
        m.module_handles.push(ModuleHandle {
            address: AddressIdentifierIndex(0),
            name: IdentifierIndex(0),
        });
        m.identifiers.push(Identifier::new(name).unwrap());
        m.address_identifiers
            .push(Address::from_bytes([address_byte; 32]));
        m
    }

    #[test]
    fn empty_resolver_returns_none_for_any_lookup() {
        let resolver = InMemoryModuleResolver::new();
        let id = ModuleId::new(
            Address::from_bytes([0u8; 32]),
            Identifier::new("foo").unwrap(),
        );
        assert!(resolver.resolve(&id).is_none());
    }

    #[test]
    fn inserted_module_resolves_under_self_id() {
        let mut resolver = InMemoryModuleResolver::new();
        let m = make_module(0xab, "bar");
        let id = ModuleId::from_module(&m).expect("self-handle wired");
        resolver.insert(m);
        assert!(resolver.resolve(&id).is_some());
    }

    #[test]
    fn lookup_with_wrong_address_returns_none() {
        let mut resolver = InMemoryModuleResolver::new();
        resolver.insert(make_module(0x01, "shared_name"));
        let wrong = ModuleId::new(
            Address::from_bytes([0x02; 32]),
            Identifier::new("shared_name").unwrap(),
        );
        assert!(resolver.resolve(&wrong).is_none());
    }

    #[test]
    fn lookup_with_wrong_name_returns_none() {
        let mut resolver = InMemoryModuleResolver::new();
        resolver.insert(make_module(0xab, "actual_name"));
        let wrong = ModuleId::new(
            Address::from_bytes([0xab; 32]),
            Identifier::new("other_name").unwrap(),
        );
        assert!(resolver.resolve(&wrong).is_none());
    }

    #[test]
    fn two_modules_at_different_addresses_resolve_independently() {
        let mut resolver = InMemoryModuleResolver::new();
        let a = make_module(0x01, "shared");
        let b = make_module(0x02, "shared");
        let a_id = ModuleId::from_module(&a).unwrap();
        let b_id = ModuleId::from_module(&b).unwrap();
        resolver.insert(a);
        resolver.insert(b);
        assert!(resolver.resolve(&a_id).is_some());
        assert!(resolver.resolve(&b_id).is_some());
        assert_ne!(a_id, b_id);
    }

    #[test]
    fn module_id_from_module_returns_none_on_oob_self_handle() {
        // module_handles empty; default self_module_handle_idx 0
        // is therefore out of bounds.
        let m = AdamantCompiledModule {
            self_module_handle_idx: ModuleHandleIndex(0),
            ..AdamantCompiledModule::default()
        };
        assert!(ModuleId::from_module(&m).is_none());
    }

    #[test]
    fn module_id_eq_and_hash_consistent() {
        let id_a = ModuleId::new(
            Address::from_bytes([0xff; 32]),
            Identifier::new("eq_test").unwrap(),
        );
        let id_b = ModuleId::new(
            Address::from_bytes([0xff; 32]),
            Identifier::new("eq_test").unwrap(),
        );
        assert_eq!(id_a, id_b);

        // Equal ids must hash identically (HashSet correctness
        // depends on this).
        let mut set: HashSet<ModuleId> = HashSet::new();
        set.insert(id_a.clone());
        assert!(set.contains(&id_b));
    }
}
