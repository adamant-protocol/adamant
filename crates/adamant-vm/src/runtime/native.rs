//! Native-handler dispatch infrastructure — whitepaper §6.5.
//!
//! Phase 5/6.7.C lands the foundation: [`NativeKey`] /
//! [`NativeRegistry`] / [`NativeFunction`] / [`NativeContext`].
//! The dispatch-loop hook + per-stdlib-module handler set
//! ([`adamant::module::deploy`], [`adamant::tx_context::*`],
//! [`adamant::hash::*`], [`adamant::signature::*`],
//! [`adamant::object::*`], [`adamant::address::*`]) lands at
//! Phase 5/6.8 sub-arcs, parallel to the D-1a foundation /
//! D-1b producer arc shape used throughout Phase 5/5b.
//!
//! # Spec basis
//!
//! Whitepaper §6.5 (post-amendment): "The `adamant::module`,
//! `adamant::tx_context`, `adamant::object`, `adamant::hash`,
//! `adamant::signature`, and `adamant::privacy` modules expose
//! protocol-level operations that require runtime-side execution
//! beyond what ordinary Adamant Move bytecode can express ...
//! Function calls to these modules' functions are dispatched by the
//! runtime to native Rust handlers per the AVM's execution model
//! (section 6.2.2). The dispatch is byte-identical from the caller's
//! perspective to a normal `Call` instruction; the difference is
//! internal to the runtime and consensus-binding via the genesis-
//! fixed mapping from `(module_id, function_id)` to native handler.
//! Adding or removing a native-dispatched stdlib function is a hard
//! fork."
//!
//! # Resolution path
//!
//! At dispatch time, the runtime resolves `Bytecode::Call(handle)`
//! to a [`NativeKey`] by reading:
//!
//! - `module.function_handles[handle].module` →
//!   `module.module_handles[idx]` →
//!   `(module.address_identifiers[idx], module.identifiers[idx])`
//!   (the target module's address and name)
//! - `module.function_handles[handle].name` →
//!   `module.identifiers[idx]` (the target function's name)
//!
//! The runtime then queries [`NativeRegistry::lookup`] with the
//! resulting [`NativeKey`]. A `Some` return means dispatch goes
//! to the registered [`NativeFunction`] in place of pushing a
//! new bytecode frame; a `None` return means the call falls
//! through to ordinary bytecode interpretation.
//!
//! # Interaction with Rule 4 (no natives)
//!
//! Rule 4 (whitepaper §6.2.1.6) forbids `code: None` in deployed
//! modules — every function definition ships with a bytecode body.
//! Stdlib modules deployed at genesis with native-dispatched
//! functions ship with **stub bodies** that satisfy Rule 4 (typically
//! a single `Abort` instruction or a defined-error path) but are
//! never executed when the runtime intercepts the `Call` via the
//! native registry. The genesis-fixed `(module_id, function_id) →
//! native_handler` mapping is the consensus-binding override.

use std::collections::HashMap;

use adamant_bytecode_format::Identifier;
use adamant_types::Address;

use crate::module::AdamantCompiledModule;
use crate::runtime::error::VMError;
use crate::runtime::interpreter::InterpreterState;
use crate::runtime::runtime_value::RuntimeValue;

/// Genesis-fixed identity of a native-dispatched stdlib function.
///
/// Three components matching the Move-conventional `(address,
/// module, function)` triple. The `(address, module)` pair is
/// equivalent to a [`crate::validator::ModuleId`]; the function
/// identifier disambiguates the specific entry-point within that
/// module.
///
/// Two [`NativeKey`]s are equal iff all three components are
/// byte-identical. Hash is consistent with equality.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct NativeKey {
    /// Stdlib address. Genesis-fixed at `0x1` for the
    /// `adamant::*` namespace per whitepaper §6.4.1 amendment.
    pub address: Address,
    /// Module name (e.g., `"module"`, `"hash"`, `"signature"`).
    pub module: Identifier,
    /// Function name within the module (e.g., `"deploy"`,
    /// `"sha3_256"`).
    pub function: Identifier,
}

impl NativeKey {
    /// Construct from raw address + module + function components.
    #[must_use]
    pub fn new(address: Address, module: Identifier, function: Identifier) -> Self {
        Self {
            address,
            module,
            function,
        }
    }
}

/// Per-call context handed to a [`NativeFunction`] handler.
///
/// Bundles the runtime state the handler is allowed to mutate
/// (`state` for stack/locals/gas access, `args` already popped
/// from the caller's stack, `return_values` for the handler to
/// populate before pushing them back to the caller's stack) plus
/// the immutable references the handler may read (`module` for
/// type/handle resolution).
///
/// Phase 5/6.7.C ships the minimum-viable shape. Phase 5/6.8 sub-
/// arcs extend with additional immutable references as specific
/// handlers need them (e.g., `&dyn StateView` for
/// `adamant::tx_context::sender`, `&mut TransactionStateBuffer`
/// for `adamant::module::deploy` to stage the new Module object,
/// `&TxHash` and `deploy_index` for `ObjectId` derivation, `&dyn
/// ModuleResolver` for `adamant::module::deploy`'s cross-module
/// Rule 3 walker invocation).
///
/// The Phase 5/6.7.C foundation pins the handler signature shape;
/// extending the context is a 5/6.8 sub-arc concern that lands
/// alongside the handlers that need it.
pub struct NativeContext<'a> {
    /// Mutable interpreter state — gas tracker, frame stack.
    pub state: &'a mut InterpreterState,
    /// The caller's currently-executing module. Used for type /
    /// handle resolution at dispatch time.
    pub module: &'a AdamantCompiledModule,
    /// Arguments popped from the caller's stack before the
    /// native-handler invocation. Order is `args[0]` is the first
    /// parameter, matching [`crate::runtime::Frame`] parameter
    /// layout. Sized to the function's declared parameter
    /// signature.
    pub args: Vec<RuntimeValue>,
    /// Return values the handler populates. Pushed onto the
    /// caller's stack after the handler returns successfully.
    /// Order is `return_values[0]` is the first return, matching
    /// the function's declared return signature.
    pub return_values: Vec<RuntimeValue>,
}

impl<'a> NativeContext<'a> {
    /// Construct a fresh [`NativeContext`].
    pub fn new(
        state: &'a mut InterpreterState,
        module: &'a AdamantCompiledModule,
        args: Vec<RuntimeValue>,
    ) -> Self {
        Self {
            state,
            module,
            args,
            return_values: Vec::new(),
        }
    }
}

/// Function pointer signature for a native-dispatched handler.
///
/// The handler reads/writes via the [`NativeContext`] handed to
/// it and returns `Ok(())` on success or a [`VMError`] on
/// failure (which propagates as a transaction abort).
///
/// Function-pointer (not closure / trait object) by design: the
/// genesis-fixed registry of native handlers is a static set
/// known at runtime initialisation; dynamic-dispatch overhead is
/// avoided. Per whitepaper §6.5 amendment, "Adding or removing a
/// native-dispatched stdlib function is a hard fork" — the set
/// is not extensible at runtime.
pub type NativeFunction = fn(&mut NativeContext<'_>) -> Result<(), VMError>;

/// Genesis-fixed registry of native-dispatched stdlib handlers.
///
/// Built once at runtime initialisation by registering every
/// stdlib native via [`Self::register`]; thereafter consulted
/// on every `Bytecode::Call` dispatch via [`Self::lookup`].
///
/// # Construction
///
/// Phase 5/6.7.C ships the empty registry shape. Phase 5/6.8
/// sub-arcs ship a `genesis_native_registry()` constructor that
/// pre-registers every stdlib native per the genesis-fixed
/// mapping (whitepaper §6.5).
#[derive(Debug, Default)]
pub struct NativeRegistry {
    handlers: HashMap<NativeKey, NativeFunction>,
}

impl NativeRegistry {
    /// Construct an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            handlers: HashMap::new(),
        }
    }

    /// Register a [`NativeFunction`] under `key`. Returns the
    /// previous handler if one was registered under the same key.
    ///
    /// At genesis-registry construction time, returning `Some`
    /// from this function indicates a duplicate-registration bug
    /// (the genesis mapping is fixed and unique). Caller asserts
    /// `None` was returned.
    pub fn register(&mut self, key: NativeKey, handler: NativeFunction) -> Option<NativeFunction> {
        self.handlers.insert(key, handler)
    }

    /// Look up the handler for `key`. Returns `None` for
    /// non-native targets (ordinary user-deployed function
    /// bodies); the dispatch loop falls through to bytecode
    /// interpretation in that case.
    #[must_use]
    pub fn lookup(&self, key: &NativeKey) -> Option<NativeFunction> {
        self.handlers.get(key).copied()
    }

    /// Number of registered handlers.
    #[must_use]
    pub fn len(&self) -> usize {
        self.handlers.len()
    }

    /// Whether the registry has zero registered handlers.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.handlers.is_empty()
    }
}

/// Resolve a [`adamant_bytecode_format::FunctionHandleIndex`] in
/// `module` to its [`NativeKey`] for native-registry lookup.
///
/// Reads the function handle's `module` + `name` references,
/// dereferences through `module_handles` / `address_identifiers`
/// / `identifiers` to produce the `(address, module_name,
/// function_name)` triple.
///
/// Returns `None` if any of the index dereferences are out of
/// bounds — a structural impossibility for any module that
/// passed the validator's `bounds_checker` pass per the
/// cross-pass-pipeline-dependency documented at
/// [`crate::validator::module_pass`].
///
/// Used by the Phase 5/6.8 dispatch-loop hook to decide between
/// native dispatch and bytecode interpretation. Phase 5/6.7.C
/// ships the helper for unit-testing the foundation; the
/// production caller wires at 5/6.8.
#[must_use]
pub fn native_key_from_handle(
    module: &AdamantCompiledModule,
    handle: adamant_bytecode_format::FunctionHandleIndex,
) -> Option<NativeKey> {
    let func_handle = module.function_handles.get(handle.0 as usize)?;
    let module_handle = module.module_handles.get(func_handle.module.0 as usize)?;
    let address = *module
        .address_identifiers
        .get(module_handle.address.0 as usize)?;
    let module_name = module
        .identifiers
        .get(module_handle.name.0 as usize)?
        .clone();
    let function_name = module.identifiers.get(func_handle.name.0 as usize)?.clone();
    Some(NativeKey::new(address, module_name, function_name))
}

/// The genesis-fixed Adamant standard-library address per
/// whitepaper §6.4.1 amendment.
///
/// "`0x1` is the protocol-reserved address of the `adamant::*`
/// standard library, parallel to Sui-Move's `0x1`/`0x2` system-
/// address convention adapted for Adamant." Genesis-fixed; changing
/// it is a hard fork.
pub const STDLIB_ADDRESS: Address = {
    let mut bytes = [0u8; 32];
    bytes[31] = 0x01;
    Address::from_bytes(bytes)
};

#[cfg(test)]
mod tests {
    use super::*;
    use adamant_bytecode_format::{
        AddressIdentifierIndex, FunctionHandle, FunctionHandleIndex, Identifier, IdentifierIndex,
        ModuleHandle, ModuleHandleIndex, Signature, SignatureIndex,
    };

    fn ident(s: &str) -> Identifier {
        Identifier::new(s).unwrap()
    }

    // The handlers below match the [`NativeFunction`] type
    // pointer signature exactly; they always return Ok(()) at this
    // foundation sub-arc. Returning Result<(), VMError> from a
    // function that never errors is the type-correct way to
    // satisfy the fn pointer; #[allow] silences the
    // unnecessary_wraps lint that fires on test helpers.
    #[allow(clippy::unnecessary_wraps, reason = "match NativeFunction signature")]
    fn no_op_handler(_ctx: &mut NativeContext<'_>) -> Result<(), VMError> {
        Ok(())
    }

    #[allow(clippy::unnecessary_wraps, reason = "match NativeFunction signature")]
    fn pushes_one_handler(ctx: &mut NativeContext<'_>) -> Result<(), VMError> {
        ctx.return_values.push(RuntimeValue::U64(1));
        Ok(())
    }

    #[test]
    fn empty_registry_returns_none_for_any_lookup() {
        let registry = NativeRegistry::new();
        let key = NativeKey::new(STDLIB_ADDRESS, ident("foo"), ident("bar"));
        assert!(registry.lookup(&key).is_none());
        assert_eq!(registry.len(), 0);
        assert!(registry.is_empty());
    }

    #[test]
    fn register_and_lookup_resolves_handler() {
        let mut registry = NativeRegistry::new();
        let key = NativeKey::new(STDLIB_ADDRESS, ident("module"), ident("deploy"));
        let prev = registry.register(key.clone(), no_op_handler);
        assert!(prev.is_none(), "first registration must return None");
        assert_eq!(registry.len(), 1);
        let resolved = registry.lookup(&key);
        assert!(resolved.is_some());
    }

    #[test]
    fn re_register_returns_previous_handler() {
        let mut registry = NativeRegistry::new();
        let key = NativeKey::new(STDLIB_ADDRESS, ident("hash"), ident("sha3_256"));
        registry.register(key.clone(), no_op_handler);
        let prev = registry.register(key.clone(), pushes_one_handler);
        assert!(
            prev.is_some(),
            "re-registration must return the previous handler"
        );
        assert_eq!(registry.len(), 1, "re-registration replaces, not appends");
    }

    #[test]
    fn different_keys_resolve_independently() {
        let mut registry = NativeRegistry::new();
        let k_deploy = NativeKey::new(STDLIB_ADDRESS, ident("module"), ident("deploy"));
        let k_sha3 = NativeKey::new(STDLIB_ADDRESS, ident("hash"), ident("sha3_256"));
        registry.register(k_deploy.clone(), no_op_handler);
        registry.register(k_sha3.clone(), pushes_one_handler);
        assert_eq!(registry.len(), 2);
        assert!(registry.lookup(&k_deploy).is_some());
        assert!(registry.lookup(&k_sha3).is_some());
    }

    #[test]
    fn key_equality_requires_all_three_components() {
        let key_a = NativeKey::new(STDLIB_ADDRESS, ident("module"), ident("deploy"));
        let key_b = NativeKey::new(STDLIB_ADDRESS, ident("module"), ident("deploy"));
        assert_eq!(key_a, key_b);

        let key_other_addr = NativeKey::new(
            Address::from_bytes([0xff; 32]),
            ident("module"),
            ident("deploy"),
        );
        assert_ne!(
            key_a, key_other_addr,
            "different address means distinct key"
        );

        let key_other_module = NativeKey::new(STDLIB_ADDRESS, ident("hash"), ident("deploy"));
        assert_ne!(
            key_a, key_other_module,
            "different module means distinct key"
        );

        let key_other_fn = NativeKey::new(STDLIB_ADDRESS, ident("module"), ident("upgrade"));
        assert_ne!(key_a, key_other_fn, "different function means distinct key");
    }

    #[test]
    fn handler_can_populate_return_values() {
        let mut state = InterpreterState::new();
        let module = AdamantCompiledModule::default();
        let mut ctx = NativeContext::new(&mut state, &module, vec![]);
        pushes_one_handler(&mut ctx).expect("handler ok");
        assert_eq!(ctx.return_values.len(), 1);
        assert!(matches!(ctx.return_values[0], RuntimeValue::U64(1)));
    }

    #[test]
    fn stdlib_address_is_one_in_lsb() {
        let bytes = STDLIB_ADDRESS.to_bytes();
        assert_eq!(bytes[31], 0x01);
        for &b in &bytes[..31] {
            assert_eq!(b, 0x00);
        }
    }

    #[test]
    fn native_key_from_handle_resolves_self_module_call() {
        let mut module = AdamantCompiledModule::default();
        // self module handle at index 0
        module.module_handles.push(ModuleHandle {
            address: AddressIdentifierIndex(0),
            name: IdentifierIndex(0),
        });
        module.address_identifiers.push(STDLIB_ADDRESS);
        module.identifiers.push(ident("module"));
        // function name at identifier index 1
        module.identifiers.push(ident("deploy"));
        // empty parameter signature
        module.signatures.push(Signature(vec![]));
        // function handle: refers to module 0, name 1
        module.function_handles.push(FunctionHandle {
            module: ModuleHandleIndex(0),
            name: IdentifierIndex(1),
            parameters: SignatureIndex(0),
            return_: SignatureIndex(0),
            type_parameters: vec![],
        });
        let key = native_key_from_handle(&module, FunctionHandleIndex(0)).expect("resolved");
        assert_eq!(key.address, STDLIB_ADDRESS);
        assert_eq!(key.module, ident("module"));
        assert_eq!(key.function, ident("deploy"));
    }

    #[test]
    fn native_key_from_handle_returns_none_on_oob() {
        let module = AdamantCompiledModule::default();
        // FunctionHandleIndex(0) is out of bounds for an empty module.
        assert!(native_key_from_handle(&module, FunctionHandleIndex(0)).is_none());
    }
}
