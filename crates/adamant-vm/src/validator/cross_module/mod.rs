//! Cross-module verifier passes per whitepaper §6.2.1.6.
//!
//! Single-module verifier passes (per-module checks bounded to
//! the deploying module) live at [`super::module_pass`] and
//! [`super::function_pass`] under the existing five-step
//! pipeline. Cross-module passes consume the deploying module
//! AND a [`ModuleResolver`] view into already-deployed
//! dependency modules; they enforce rules that cannot be checked
//! within a single module's own bytecode.
//!
//! Phase 5/5b.5 E-2 introduces this module subtree to host
//! cross-module Rule 3 (privacy-consistency call-graph walker
//! across module boundaries). Future cross-module rules
//! (potentially Rules 6, 7 at cross-module scope if the spec
//! amendments warrant) inherit the [`ModuleResolver`] trait
//! abstraction.
//!
//! # Architectural placement
//!
//! Per whitepaper §6.5 line 97 ("Module deployment is not a
//! special transaction variant. To deploy a new module, a
//! transaction calls the standard-library function
//! `adamant::module::deploy`...") and §6.2.1.6 line 477
//! ("Cross-module call graphs are statically checked at deploy
//! time against the annotations of dependency modules visible
//! on chain at that moment"), cross-module verification is a
//! transaction-time operation invoked by the AVM runtime
//! stdlib's `adamant::module::deploy` function (Phase 5/6).
//! The cross-module walker logic itself lives here in
//! `adamant-vm`; the caller (eventually the runtime stdlib)
//! provides the [`ModuleResolver`] implementation backed by
//! chain-state object lookup. Tests provide
//! [`test_helpers::InMemoryModuleResolver`] backed by a
//! `HashMap`.
//!
//! # Phase 5/5b.5 E-2a closure scope
//!
//! E-2a lands the foundation: [`ModuleId`] type +
//! [`ModuleResolver`] trait + the `cross_module` module
//! scaffold + [`super::error::AdamantValidationError::CrossModulePrivacyConsistencyViolation`]
//! variant + trait/API correctness tests. E-2b lands the
//! cross-module Rule 3 walker (`rule_03_privacy_consistency`)
//! and its happy-path / negative-path walker tests.

use adamant_bytecode_format::Identifier;
use adamant_types::Address;

use crate::module::AdamantCompiledModule;

#[cfg(test)]
pub(in crate::validator::cross_module) mod test_helpers;

/// Unique on-chain identity of a deployed Adamant module.
///
/// Mirrors Sui-Move's `move_core_types::language_storage::ModuleId`
/// shape — `(account address, module name)` — without the
/// production-side dependency on `move_core_types` per
/// whitepaper §6.2.1.8's resistant-proof posture.
/// [`Address`] is Adamant-native (`adamant_types::Address`,
/// byte-identical to Sui's `AccountAddress` per Phase 5/5b.1b
/// Q6); [`Identifier`] is Adamant-native
/// (`adamant_bytecode_format::Identifier`, forked at Phase
/// 5/5b.1a).
///
/// Two modules deployed at different addresses can share the
/// same name; two modules at the same address cannot share a
/// name (the address-keyed namespace is per-account). The
/// `(address, name)` tuple is therefore globally unique across
/// the on-chain module set.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ModuleId {
    /// On-chain account address that deployed the module.
    pub address: Address,
    /// Module name (validated identifier per
    /// [`Identifier::is_valid`][adamant_bytecode_format::Identifier::is_valid]).
    pub name: Identifier,
}

impl ModuleId {
    /// Construct a [`ModuleId`] from its address and name parts.
    #[must_use]
    pub fn new(address: Address, name: Identifier) -> Self {
        Self { address, name }
    }

    /// Resolve a module's self-identity from its parsed
    /// representation. Reads `self_module_handle_idx` →
    /// `module_handles[idx]` → `(address_identifiers[idx],
    /// identifiers[idx])` per whitepaper §6.2.1.3.
    ///
    /// Returns `None` if the module's self-handle indices are
    /// out of bounds — a structural impossibility for any
    /// module that passed [`super::super::verify_module`]'s
    /// step-3 `bounds_checker` pass per the cross-pass-
    /// pipeline-dependency at this layer.
    #[must_use]
    pub fn from_module(module: &AdamantCompiledModule) -> Option<Self> {
        let handle = module
            .module_handles
            .get(module.self_module_handle_idx.0 as usize)?;
        let address = *module.address_identifiers.get(handle.address.0 as usize)?;
        let name = module.identifiers.get(handle.name.0 as usize)?.clone();
        Some(Self { address, name })
    }
}

/// Resolves [`ModuleId`]s to already-deployed
/// [`AdamantCompiledModule`]s.
///
/// Implemented by the deployment-validator caller (eventually
/// the AVM runtime stdlib's `adamant::module::deploy` function
/// in Phase 5/6) backed by chain-state object lookup. Tests
/// implement via [`test_helpers::InMemoryModuleResolver`]
/// backed by a `HashMap`.
///
/// The resolver returns `None` for unknown modules (i.e.,
/// dependencies the caller did not load). The cross-module
/// walker treats `None` as an unresolvable dependency; the
/// disposition for unresolvable dependencies is defined by the
/// per-rule walker (e.g., cross-module Rule 3's E-2b walker
/// rejects on missing dependencies, since a public-shielded
/// function reaching an unresolvable cross-module call cannot
/// be statically proven privacy-consistent).
///
/// # Errors
///
/// Resolver-level errors (chain-state lookup failures, network
/// IO, etc.) are the caller's concern and are not surfaced
/// through this trait. Callers handle errors before invoking
/// the cross-module walker. The walker itself surfaces
/// "dependency not provided" as
/// [`super::error::AdamantValidationError::CrossModulePrivacyConsistencyViolation`]
/// when it cannot prove call-graph privacy consistency due to
/// missing dependencies.
pub trait ModuleResolver {
    /// Look up the already-deployed module identified by `id`.
    /// Returns `None` if the module is not loaded by this
    /// resolver instance.
    fn resolve(&self, id: &ModuleId) -> Option<&AdamantCompiledModule>;
}

// E-2b lands `rule_03_privacy_consistency` here — the cross-
// module call-graph walker that consumes the trait above.
