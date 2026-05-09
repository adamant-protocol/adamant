//! Runtime-side [`ModuleResolver`] adapter — whitepaper §6.4.1
//! deployment + §6.2.1.6 line 477 cross-module Rule 3.
//!
//! Phase 5/6.7.B bridges the runtime's transaction-local module
//! load (Phase 5/6.6 [`crate::runtime::load_read_set`]) into a
//! [`ModuleResolver`] view consumable by
//! [`crate::validator::deploy_validate`].
//!
//! # Resolution model
//!
//! Module dependencies that a deploying transaction relies on for
//! cross-module Rule 3 verification must appear in the transaction's
//! `read_set` per whitepaper §6.0.2 (every object the transaction
//! reads is version-pinned in `read_set`). The runtime caller:
//!
//! 1. Loads the read-set objects via
//!    [`crate::runtime::load_read_set`].
//! 2. Filters to `Module`-typed objects (per the genesis-fixed
//!    `adamant::module::Module` `TypeId`; runtime caller carries
//!    that knowledge).
//! 3. Deserializes each Module object's `contents` bytes into an
//!    [`AdamantCompiledModule`] via
//!    [`crate::module_wire::adamant_deserialize`].
//! 4. Passes the resulting modules to
//!    [`LoadedModulesResolver::from_modules`].
//! 5. Passes `&loaded_resolver` as a `&dyn ModuleResolver` to
//!    [`crate::validator::deploy_validate`].
//!
//! # Self-id derivation
//!
//! Each module is keyed by its self-id, computed via
//! [`ModuleId::from_module`] (reads `self_module_handle_idx →
//! module_handles[idx] → (address_identifiers[idx],
//! identifiers[idx])`). For modules that have already passed deploy
//! validation, the self-handle wiring is structurally guaranteed to
//! be in-bounds by the validator's `bounds_checker` pass — so
//! [`ModuleId::from_module`] should always return `Some` on a
//! chain-loaded module. [`LoadedModulesResolver::from_modules`]
//! treats a `None` return as [`MalformedSelfHandle`] and surfaces it
//! to the caller; the runtime caller handles it as an invariant
//! violation (either chain-state corruption or a deploy-time
//! validator bug allowing a module with malformed self-handle wiring
//! through).
//!
//! # Why not lazy `StateView` lookup
//!
//! An alternate design wraps a `&dyn StateView` and looks up modules
//! lazily by `ModuleId` on each `resolve` call. That requires a
//! separate chain-state index from `(address, name) → ObjectId`,
//! which §5.x does not currently pin. Phase 5/6.7.B uses the
//! pre-loaded read-set model — every cross-module dependency is
//! version-pinned at the transaction layer, matching §6.0.2's
//! read-set discipline. A lazy `StateView` resolver may be added at
//! pre-mainnet hardening if/when the chain-state indexing layer
//! ships an authoritative `(address, name) → ObjectId` map.

use std::collections::HashMap;

use crate::module::AdamantCompiledModule;
use crate::validator::{ModuleId, ModuleResolver};

/// Resolver backed by an in-memory map of pre-loaded modules.
///
/// The runtime caller constructs this from the transaction's
/// loaded read-set after filtering to `Module`-typed objects and
/// deserializing each Module's `contents` bytes into an
/// [`AdamantCompiledModule`]. The resolver is consumed by
/// [`crate::validator::deploy_validate`] for cross-module Rule 3
/// verification.
///
/// # Construction
///
/// - [`LoadedModulesResolver::new`] — empty.
/// - [`LoadedModulesResolver::from_modules`] — bulk-insert from an
///   iterator. Returns [`MalformedSelfHandle`] if any module's
///   self-handle wiring is out of bounds.
/// - [`LoadedModulesResolver::insert`] — append a single module.
///   Returns [`MalformedSelfHandle`] on out-of-bounds self-handle.
///
/// All construction paths key by [`ModuleId::from_module`]; later
/// `insert` calls with a colliding self-id replace the earlier
/// binding (mirroring `HashMap::insert` semantics).
#[derive(Debug, Default)]
pub struct LoadedModulesResolver {
    modules: HashMap<ModuleId, AdamantCompiledModule>,
}

/// Returned by [`LoadedModulesResolver::from_modules`] /
/// [`LoadedModulesResolver::insert`] when a module's self-handle
/// wiring is out of bounds (i.e., [`ModuleId::from_module`] returns
/// `None`).
///
/// In practice this should never trip on a chain-loaded module —
/// already-deployed modules passed `bounds_checker` at their own
/// deploy time. A trip indicates either chain-state corruption or a
/// validator bug; the runtime caller treats it as an invariant
/// violation.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct MalformedSelfHandle;

impl core::fmt::Display for MalformedSelfHandle {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "module's self-handle wiring is out of bounds; module cannot be \
             keyed by ModuleId — chain-state corruption or validator bug"
        )
    }
}

impl std::error::Error for MalformedSelfHandle {}

impl LoadedModulesResolver {
    /// Construct an empty resolver. Modules are inserted via
    /// [`Self::insert`] or bulk-loaded via [`Self::from_modules`].
    #[must_use]
    pub fn new() -> Self {
        Self {
            modules: HashMap::new(),
        }
    }

    /// Construct with capacity hint.
    #[must_use]
    pub fn with_capacity(n: usize) -> Self {
        Self {
            modules: HashMap::with_capacity(n),
        }
    }

    /// Bulk-insert from an iterator. Each module is keyed by its
    /// self-id per [`ModuleId::from_module`].
    ///
    /// # Errors
    ///
    /// Returns [`MalformedSelfHandle`] on the first module whose
    /// self-handle wiring is out of bounds. Modules already
    /// inserted before the failure remain in the resolver; the
    /// caller treats the partial state as undefined and rebuilds
    /// from a fresh resolver.
    pub fn from_modules<I>(modules: I) -> Result<Self, MalformedSelfHandle>
    where
        I: IntoIterator<Item = AdamantCompiledModule>,
    {
        let iter = modules.into_iter();
        let (lower, _) = iter.size_hint();
        let mut resolver = Self::with_capacity(lower);
        for module in iter {
            resolver.insert(module)?;
        }
        Ok(resolver)
    }

    /// Insert a single module under its self-id. Returns the
    /// previous binding under the same self-id (if any).
    ///
    /// # Errors
    ///
    /// Returns [`MalformedSelfHandle`] if `module.self_module_handle_idx`
    /// is out of bounds (i.e., [`ModuleId::from_module`] returns
    /// `None`).
    pub fn insert(
        &mut self,
        module: AdamantCompiledModule,
    ) -> Result<Option<AdamantCompiledModule>, MalformedSelfHandle> {
        let id = ModuleId::from_module(&module).ok_or(MalformedSelfHandle)?;
        Ok(self.modules.insert(id, module))
    }

    /// Number of modules currently held by the resolver.
    #[must_use]
    pub fn len(&self) -> usize {
        self.modules.len()
    }

    /// Whether the resolver is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.modules.is_empty()
    }
}

impl ModuleResolver for LoadedModulesResolver {
    fn resolve(&self, id: &ModuleId) -> Option<&AdamantCompiledModule> {
        self.modules.get(id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use adamant_bytecode_format::{
        AddressIdentifierIndex, Identifier, IdentifierIndex, ModuleHandle, ModuleHandleIndex,
    };
    use adamant_types::Address;

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
    fn empty_resolver_returns_none() {
        let resolver = LoadedModulesResolver::new();
        let id = ModuleId::new(
            Address::from_bytes([0u8; 32]),
            Identifier::new("foo").unwrap(),
        );
        assert!(resolver.resolve(&id).is_none());
        assert_eq!(resolver.len(), 0);
        assert!(resolver.is_empty());
    }

    #[test]
    fn inserted_module_resolves_under_self_id() {
        let mut resolver = LoadedModulesResolver::new();
        let m = make_module(0xab, "bar");
        let id = ModuleId::from_module(&m).unwrap();
        resolver.insert(m).expect("self-handle wired");
        assert!(resolver.resolve(&id).is_some());
        assert_eq!(resolver.len(), 1);
    }

    #[test]
    fn from_modules_loads_all_supplied() {
        let m_a = make_module(0x01, "alpha");
        let m_b = make_module(0x02, "beta");
        let id_a = ModuleId::from_module(&m_a).unwrap();
        let id_b = ModuleId::from_module(&m_b).unwrap();
        let resolver = LoadedModulesResolver::from_modules([m_a, m_b]).expect("ok");
        assert!(resolver.resolve(&id_a).is_some());
        assert!(resolver.resolve(&id_b).is_some());
        assert_eq!(resolver.len(), 2);
    }

    #[test]
    fn insert_with_oob_self_handle_returns_malformed_error() {
        let mut resolver = LoadedModulesResolver::new();
        let m = AdamantCompiledModule {
            self_module_handle_idx: ModuleHandleIndex(0),
            ..AdamantCompiledModule::default()
        };
        let result = resolver.insert(m);
        assert_eq!(result, Err(MalformedSelfHandle));
    }

    #[test]
    fn from_modules_propagates_malformed_self_handle() {
        let bad = AdamantCompiledModule {
            self_module_handle_idx: ModuleHandleIndex(0),
            ..AdamantCompiledModule::default()
        };
        let result = LoadedModulesResolver::from_modules([bad]);
        assert_eq!(result.err(), Some(MalformedSelfHandle));
    }

    #[test]
    fn re_insert_under_same_self_id_returns_previous() {
        let mut resolver = LoadedModulesResolver::new();
        let first = make_module(0xab, "shared_name");
        let id = ModuleId::from_module(&first).unwrap();
        resolver.insert(first).expect("ok");
        let second = make_module(0xab, "shared_name");
        let prev = resolver.insert(second).expect("ok");
        assert!(prev.is_some());
        assert!(resolver.resolve(&id).is_some());
        assert_eq!(resolver.len(), 1);
    }

    /// Integration-shape: build a resolver from a few modules and
    /// hand it to `deploy_validate` as `&dyn ModuleResolver`.
    /// Confirms the trait coercion is clean and the dynamic
    /// dispatch resolves the same modules.
    #[test]
    fn resolver_passes_as_dyn_module_resolver() {
        let m_a = make_module(0x01, "a");
        let id_a = ModuleId::from_module(&m_a).unwrap();
        let resolver = LoadedModulesResolver::from_modules([m_a]).expect("ok");
        let dyn_ref: &dyn ModuleResolver = &resolver;
        assert!(dyn_ref.resolve(&id_a).is_some());
    }
}
