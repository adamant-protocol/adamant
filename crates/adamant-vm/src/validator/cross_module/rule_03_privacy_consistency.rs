//! Cross-module Rule 3 (privacy consistency) call-graph walker
//! per whitepaper §6.2.1.6 line 477.
//!
//! Single-module Rule 3 (D-5c) walks the call graph within the
//! deploying module; this walker extends the call graph across
//! module boundaries via the [`super::ModuleResolver`] trait.
//! For each public function (caller) in the deploying module,
//! the walker traverses internal callees (D-5c's logic) and,
//! when a call instruction targets a function in a dependency
//! module, looks up the dependency's privacy annotation and
//! verifies it is mode-consistent with the caller's declared
//! mode.
//!
//! # Spec text (§6.2.1.6 line 477; verbatim re-paste from
//! E-2 plan-gate verification gate)
//!
//! "Cross-module call graphs are statically checked at deploy
//! time against the annotations of dependency modules visible
//! on chain at that moment; combined with the upgrade-
//! immutability constraint on privacy annotations (section
//! 6.4.3), this deploy-time guarantee is durable across the
//! lifetime of the deployed module. The runtime check carries
//! the residual binding for any case the static analysis
//! cannot fully verify."
//!
//! # Spec-text-DIRECTS-shared-helper canonical principle
//!
//! Single-module Rule 3 and cross-module Rule 3 share the same
//! call-walker shape per §6.2.1.4 line 408 ("treat reference
//! inputs and outputs of `InvokeShielded` exactly as they
//! would for an inherited `Call`"). The
//! [`super::super::rule_03_privacy_consistency::call_target_handle`]
//! helper is reused here — promoted to
//! `pub(in crate::validator)` at E-2b for the cross-scope
//! reuse. 4th instance of the spec-text-DIRECTS-shared-helper
//! canonical principle (rule-of-three already met at D-5c).
//!
//! # Cross-module-error-variant-shape pattern (1st instance)
//!
//! Cross-module Rule 3 uses [`super::super::error::AdamantValidationError::CrossModulePrivacyConsistencyViolation`],
//! distinct from single-module Rule 3's
//! [`super::super::error::AdamantValidationError::PrivacyConsistencyViolation`].
//! The two variants share
//! [`super::super::error::PrivacyConsistencyViolationReason`]
//! per the same-rule-different-scope-shares-sub-reason-enum
//! pattern (1st instance, registered at E-2a).
//!
//! # Missing-dependency disposition
//!
//! When the caller-supplied [`super::ModuleResolver`] returns
//! `None` for a cross-module target, the walker rejects with
//! `CrossModulePrivacyConsistencyViolation`. Per the trait
//! doc-comment in `super::mod.rs`, `None` is "unresolvable
//! dependency"; for Rule 3 specifically, a public-shielded
//! function reaching a cross-module call to an unresolvable
//! target cannot be statically proven privacy-consistent.
//! Runtime defense-in-depth (per §6.2.1.6 line 477's "runtime
//! check carries the residual binding") is not a substitute
//! for static rejection — modules with unresolvable cross-
//! module call targets cannot deploy.

use std::collections::BTreeSet;

use adamant_bytecode_format::{FunctionDefinitionIndex, FunctionHandleIndex, Visibility};

use crate::bytecode::BytecodeInstruction;
use crate::module::AdamantCompiledModule;

use super::super::error::{AdamantValidationError, PrivacyConsistencyViolationReason};
use super::super::rule_03_privacy_consistency::call_target_handle;
use super::{ModuleId, ModuleResolver};

/// Per whitepaper §6.2.1.3, the metadata key under which the
/// privacy annotation table is BCS-encoded. Duplicated from
/// [`super::super::rule_03_privacy_consistency`] (which keeps
/// the constant private to its own module-internal walker).
const PRIVACY_METADATA_KEY: &[u8] = b"adamant.privacy";

/// Privacy-mode byte for transparent functions per §6.2.1.3.
const PRIVACY_TRANSPARENT_BYTE: u8 = 0x00;
/// Privacy-mode byte for shielded functions per §6.2.1.3.
const PRIVACY_SHIELDED_BYTE: u8 = 0x01;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
enum PrivacyMode {
    Transparent,
    Shielded,
}

impl PrivacyMode {
    fn from_byte(b: u8) -> Option<Self> {
        match b {
            PRIVACY_TRANSPARENT_BYTE => Some(Self::Transparent),
            PRIVACY_SHIELDED_BYTE => Some(Self::Shielded),
            _ => None,
        }
    }
}

/// Verify cross-module §6.2.1.6 Rule 3 against `module` using
/// `resolver` for dependency-module lookups.
///
/// Returns the first
/// [`AdamantValidationError::CrossModulePrivacyConsistencyViolation`]
/// found; returns [`Ok`] if every public function's call graph
/// is privacy-mode consistent across module boundaries.
///
/// Single-module Rule 3 (D-5c
/// [`super::super::rule_03_privacy_consistency::verify`])
/// covers internal call edges. This walker extends to external
/// call edges; both are run sequentially at the deployment-
/// validator wiring layer (E-2b lands the walker; the wiring
/// layer that calls both single-module and cross-module Rule 3
/// is the AVM runtime stdlib's `adamant::module::deploy`
/// function in Phase 5/6).
pub(in crate::validator) fn verify(
    module: &AdamantCompiledModule,
    resolver: &dyn ModuleResolver,
) -> Result<(), AdamantValidationError> {
    let public_modes = collect_public_privacy_modes(module);

    for (calling_public_idx, mode) in public_modes {
        let mut visited: BTreeSet<FunctionDefinitionIndex> = BTreeSet::new();
        verify_function_call_graph(
            module,
            resolver,
            calling_public_idx,
            calling_public_idx,
            mode,
            &mut visited,
        )?;
    }

    Ok(())
}

/// Collect `(function_definition_index, privacy_mode)` for
/// every Public function annotated in the module's privacy
/// metadata entry. Same shape as D-5c's internal helper.
fn collect_public_privacy_modes(
    module: &AdamantCompiledModule,
) -> Vec<(FunctionDefinitionIndex, PrivacyMode)> {
    let Some(entry) = module
        .metadata
        .iter()
        .find(|m| m.key == PRIVACY_METADATA_KEY)
    else {
        return Vec::new();
    };

    let payload: Vec<(FunctionDefinitionIndex, u8)> = bcs::from_bytes(&entry.value).expect(
        "privacy metadata BCS payload is structurally-validated at step 3 by \
         `module_pass::privacy_metadata_structure`",
    );

    let mut public_modes = Vec::new();
    for (def_idx, mode_byte) in payload {
        let def_idx_usize = def_idx.0 as usize;
        debug_assert!(
            def_idx_usize < module.function_defs.len(),
            "privacy_metadata_structure validates function-definition indices in range at step 3"
        );
        let function_def = &module.function_defs[def_idx_usize];
        if !matches!(function_def.visibility, Visibility::Public) {
            continue;
        }
        let mode = PrivacyMode::from_byte(mode_byte).expect(
            "privacy mode byte validated at step 3 by `module_pass::privacy_metadata_structure`",
        );
        public_modes.push((def_idx, mode));
    }
    public_modes
}

/// Recursively walk the call graph from `current_function_idx`
/// within the deploying module. For internal call targets,
/// recurse internally (matches D-5c). For external (cross-
/// module) call targets, look up the dependency's annotation
/// via [`ModuleResolver`] and verify mode-consistency with
/// `mode`.
fn verify_function_call_graph(
    module: &AdamantCompiledModule,
    resolver: &dyn ModuleResolver,
    calling_public_idx: FunctionDefinitionIndex,
    current_function_idx: FunctionDefinitionIndex,
    mode: PrivacyMode,
    visited: &mut BTreeSet<FunctionDefinitionIndex>,
) -> Result<(), AdamantValidationError> {
    if !visited.insert(current_function_idx) {
        return Ok(());
    }

    let function_def = &module.function_defs[current_function_idx.0 as usize];
    let Some(code_unit) = function_def.code.as_ref() else {
        return Ok(());
    };

    for (offset_usize, instr) in code_unit.code.iter().enumerate() {
        let offset =
            u16::try_from(offset_usize).expect("code offset fits u16 per binary-format limits");

        // Single-module InvokeShielded/InvokeTransparent
        // mismatches are caught by D-5c's walker at step 5
        // before this cross-module walker runs at the
        // deployment-validator layer; this walker focuses on
        // the cross-module call edges.
        if let Some(target_handle_idx) = call_target_handle(module, instr) {
            let handle_idx_usize = target_handle_idx.0 as usize;
            debug_assert!(
                handle_idx_usize < module.function_handles.len(),
                "function-handle index validated at step 3 by `module_pass::bounds_checker`"
            );
            let target_handle = &module.function_handles[handle_idx_usize];

            if target_handle.module == module.self_module_handle_idx {
                // Internal call: resolve to the deploying
                // module's function-def and recurse.
                if let Some(target_def_idx) =
                    resolve_internal_function_def(module, target_handle_idx)
                {
                    verify_function_call_graph(
                        module,
                        resolver,
                        calling_public_idx,
                        target_def_idx,
                        mode,
                        visited,
                    )?;
                }
            } else {
                // External call: look up the dependency
                // module's annotation via the resolver and
                // verify mode-consistency.
                check_cross_module_call(
                    module,
                    resolver,
                    calling_public_idx,
                    current_function_idx,
                    target_handle_idx,
                    offset,
                    mode,
                    instr,
                )?;
            }
        }
    }

    Ok(())
}

/// Cross-module mode-consistency check: resolve the dependency
/// module + the target function's privacy annotation, compare
/// against the caller's mode.
#[allow(
    clippy::too_many_arguments,
    reason = "diagnostic carries multi-field locus"
)]
fn check_cross_module_call(
    module: &AdamantCompiledModule,
    resolver: &dyn ModuleResolver,
    calling_public_idx: FunctionDefinitionIndex,
    calling_function_idx: FunctionDefinitionIndex,
    target_handle_idx: FunctionHandleIndex,
    code_offset: u16,
    caller_mode: PrivacyMode,
    instr: &BytecodeInstruction,
) -> Result<(), AdamantValidationError> {
    let target_handle = &module.function_handles[target_handle_idx.0 as usize];
    let target_module_handle = &module.module_handles[target_handle.module.0 as usize];
    let target_address = module.address_identifiers[target_module_handle.address.0 as usize];
    let target_module_name = module.identifiers[target_module_handle.name.0 as usize].clone();
    let target_module_id = ModuleId::new(target_address, target_module_name);

    let target_function_name = &module.identifiers[target_handle.name.0 as usize];

    // Single-module D-5c already covered the case where the
    // INSTRUCTION itself is InvokeShielded/InvokeTransparent
    // with mismatched caller mode (those don't escape this
    // module). The cross-module concern is whether the dep
    // function's declared mode is compatible — we check that
    // unconditionally for external targets.

    let Some(dep_module) = resolver.resolve(&target_module_id) else {
        // Unresolvable dependency: the walker cannot prove
        // privacy consistency. Reject per the missing-
        // dependency disposition documented at this module's
        // preamble.
        return Err(
            AdamantValidationError::CrossModulePrivacyConsistencyViolation {
                calling_public_index: calling_public_idx,
                calling_function_index: calling_function_idx,
                code_offset,
                target_module_id,
                calling_function_handle_idx: target_handle_idx,
                reason: missing_dep_reason_for(caller_mode, instr),
            },
        );
    };

    // Find the dep function-def whose handle name matches the
    // call's target name. The dep was already validated at its
    // own deploy time (Rule 3 single-module + Rule 2 + privacy_
    // metadata_structure), so the lookup is structurally safe.
    let Some(dep_target_def_idx) = find_dep_function_def_by_name(dep_module, target_function_name)
    else {
        // Target function not found in dep module — this is a
        // Rule 4-style non-existence (unimplemented handle on
        // dep side). The dep's own validation should have
        // caught it via UnimplementedHandle (C-2 duplication
        // checker, more specifically — though that's deploy-
        // time of the dep, not this caller). For static-
        // analysis robustness in this walker, reject.
        return Err(
            AdamantValidationError::CrossModulePrivacyConsistencyViolation {
                calling_public_index: calling_public_idx,
                calling_function_index: calling_function_idx,
                code_offset,
                target_module_id,
                calling_function_handle_idx: target_handle_idx,
                reason: missing_dep_reason_for(caller_mode, instr),
            },
        );
    };

    let dep_target_mode = lookup_privacy_mode(dep_module, dep_target_def_idx);

    // Mode-consistency check: if the dep target has a declared
    // privacy mode that differs from the caller's mode, the
    // call graph reachable from the caller transitively
    // includes a privacy-mismatched scope. Reject.
    if let Some(dep_mode) = dep_target_mode {
        if dep_mode != caller_mode {
            let reason = match (caller_mode, dep_mode) {
                (PrivacyMode::Shielded, PrivacyMode::Transparent) => {
                    PrivacyConsistencyViolationReason::ShieldedReachesInvokeTransparent
                }
                (PrivacyMode::Transparent, PrivacyMode::Shielded) => {
                    PrivacyConsistencyViolationReason::TransparentReachesInvokeShielded
                }
                _ => unreachable!(
                    "modes already filtered by the != comparison; non-Shielded/Transparent \
                     PrivacyMode values are unreachable per the from_byte filter"
                ),
            };
            return Err(
                AdamantValidationError::CrossModulePrivacyConsistencyViolation {
                    calling_public_index: calling_public_idx,
                    calling_function_index: calling_function_idx,
                    code_offset,
                    target_module_id,
                    calling_function_handle_idx: target_handle_idx,
                    reason,
                },
            );
        }
    }
    // If `dep_target_mode` is `None`: the dep target is
    // non-public (no privacy annotation per Rule 2). Move's
    // visibility rules permit calling friend functions
    // directly across modules (and inherited Sui-base private
    // functions are not callable cross-module by construction).
    // Friend cross-module calls fall back on runtime defense-
    // in-depth per §6.2.1.6 line 477's residual binding;
    // static analysis can't conclude one way or another.

    Ok(())
}

/// Pick the [`PrivacyConsistencyViolationReason`] for a
/// missing-dependency rejection. The walker doesn't know the
/// dep target's actual mode (resolver returned `None`), so
/// the violation reason is determined by the caller's mode
/// alone: a shielded caller's missing dep is treated as a
/// potential reach-into-transparent (worst case for static
/// analysis); a transparent caller's missing dep is treated
/// as a potential reach-into-shielded.
fn missing_dep_reason_for(
    caller_mode: PrivacyMode,
    _instr: &BytecodeInstruction,
) -> PrivacyConsistencyViolationReason {
    match caller_mode {
        PrivacyMode::Shielded => {
            PrivacyConsistencyViolationReason::ShieldedReachesInvokeTransparent
        }
        PrivacyMode::Transparent => {
            PrivacyConsistencyViolationReason::TransparentReachesInvokeShielded
        }
    }
}

/// Find the dep module's function-def whose handle's name
/// matches `target_name`. Returns the dep-side
/// [`FunctionDefinitionIndex`] or `None` if no match.
///
/// # Cross-pass-pipeline-dependency
///
/// The dep module was already deploy-validated when it landed on
/// chain. `module_pass::duplication_checker` enforces that every
/// `function_def.function` handle's `module` field equals the
/// dep's `self_module_handle_idx` (i.e., function-defs reference
/// only handles that point back at their own module — re-export-
/// style handles are rejected as `UnimplementedHandle`). Audit
/// pass F-5: defense-in-depth `debug_assert!` confirms this
/// invariant at lookup time. If a dep module ever slipped through
/// with a re-export shape (e.g., from an older verifier with a
/// duplication-checker bug), the assert catches it in debug
/// builds. Release builds trust the invariant, matching the
/// existing cross-pass-pipeline-dependency posture.
fn find_dep_function_def_by_name(
    dep_module: &AdamantCompiledModule,
    target_name: &adamant_bytecode_format::Identifier,
) -> Option<FunctionDefinitionIndex> {
    for (def_idx_usize, function_def) in dep_module.function_defs.iter().enumerate() {
        let handle_idx_usize = function_def.function.0 as usize;
        if handle_idx_usize >= dep_module.function_handles.len() {
            continue;
        }
        let handle = &dep_module.function_handles[handle_idx_usize];
        debug_assert!(
            handle.module == dep_module.self_module_handle_idx,
            "dep function_def at index {def_idx_usize} references a function handle whose \
             module field is not the dep's self_module_handle_idx — structural invariant from \
             the dep's deploy-time duplication_checker / UnimplementedHandle pass"
        );
        let name_idx_usize = handle.name.0 as usize;
        if name_idx_usize >= dep_module.identifiers.len() {
            continue;
        }
        if dep_module.identifiers[name_idx_usize] == *target_name {
            return Some(FunctionDefinitionIndex(
                u16::try_from(def_idx_usize)
                    .expect("function-def count fits u16 per binary-format limits"),
            ));
        }
    }
    None
}

/// Look up the dep module's privacy annotation for the dep
/// function-def at `dep_def_idx`. Returns the annotation's
/// privacy mode if the dep function carries one, `None` if it
/// doesn't (non-public function).
fn lookup_privacy_mode(
    dep_module: &AdamantCompiledModule,
    dep_def_idx: FunctionDefinitionIndex,
) -> Option<PrivacyMode> {
    let entry = dep_module
        .metadata
        .iter()
        .find(|m| m.key == PRIVACY_METADATA_KEY)?;
    let payload: Vec<(FunctionDefinitionIndex, u8)> = bcs::from_bytes(&entry.value).ok()?;
    for (idx, byte) in payload {
        if idx == dep_def_idx {
            return PrivacyMode::from_byte(byte);
        }
    }
    None
}

/// Resolve a [`FunctionHandleIndex`] to a
/// [`FunctionDefinitionIndex`] within the same module.
/// Duplicates the helper from D-5c's `rule_03_privacy_consistency`;
/// kept private to this module to avoid promoting D-5c's helper
/// visibility (D-5c already exposes [`call_target_handle`]; this
/// helper's logic is small and the duplication is preferable to
/// a wider-visibility surface).
fn resolve_internal_function_def(
    module: &AdamantCompiledModule,
    handle_idx: FunctionHandleIndex,
) -> Option<FunctionDefinitionIndex> {
    let handle_idx_usize = handle_idx.0 as usize;
    debug_assert!(
        handle_idx_usize < module.function_handles.len(),
        "function-handle index validated at step 3 by `module_pass::bounds_checker`"
    );
    let handle = &module.function_handles[handle_idx_usize];
    if handle.module != module.self_module_handle_idx {
        return None;
    }
    for (def_idx_usize, function_def) in module.function_defs.iter().enumerate() {
        if function_def.function == handle_idx {
            return Some(FunctionDefinitionIndex(
                u16::try_from(def_idx_usize)
                    .expect("function-def count fits u16 per binary-format limits"),
            ));
        }
    }
    None
}

#[cfg(test)]
#[allow(
    clippy::doc_markdown,
    reason = "test docs reference instruction names verbatim; backticks add noise without \
              improving clarity"
)]
mod tests {
    //! Layer A tests for cross-module Rule 3 walker.
    //!
    //! No Layer B parity tests by design — Rule 3 is an
    //! Adamant-specific rule per §6.2.1.6; Sui-Move has no
    //! equivalent.

    use super::super::test_helpers::InMemoryModuleResolver;
    use super::*;
    use adamant_bytecode_format::{
        AddressIdentifierIndex, Bytecode, FunctionDefinitionIndex, FunctionHandle,
        FunctionHandleIndex, Identifier, IdentifierIndex, Metadata, ModuleHandle,
        ModuleHandleIndex, Signature, SignatureIndex, Visibility,
    };
    use adamant_types::Address;

    use crate::module::{AdamantCodeUnit, AdamantCompiledModule, AdamantFunctionDefinition};

    /// Build a module rooted at (`address_byte`-filled address,
    /// `module_name`). The module has:
    /// - `self_module_handle_idx = 0` pointing to the local
    ///   module handle
    /// - `module_handles[0]` for the self module
    /// - `identifiers[0] = module_name`, additional identifiers
    ///   appended as needed
    /// - `address_identifiers[0]` for the self address
    /// - `signatures[0]` empty (used for empty params/returns)
    fn skeleton_module(address_byte: u8, module_name: &str) -> AdamantCompiledModule {
        let mut m = AdamantCompiledModule::default();
        m.module_handles.push(ModuleHandle {
            address: AddressIdentifierIndex(0),
            name: IdentifierIndex(0),
        });
        m.identifiers.push(Identifier::new(module_name).unwrap());
        m.address_identifiers
            .push(Address::from_bytes([address_byte; 32]));
        m.signatures.push(Signature(vec![]));
        m
    }

    /// Append a function-def with the given name and visibility.
    /// The function's handle resolves to the local module
    /// (module_handles[0]). Body is the given bytecode.
    fn add_function(
        m: &mut AdamantCompiledModule,
        name: &str,
        visibility: Visibility,
        body: Vec<BytecodeInstruction>,
    ) -> FunctionDefinitionIndex {
        let name_idx = IdentifierIndex(u16::try_from(m.identifiers.len()).unwrap());
        m.identifiers.push(Identifier::new(name).unwrap());
        let handle_idx = FunctionHandleIndex(u16::try_from(m.function_handles.len()).unwrap());
        m.function_handles.push(FunctionHandle {
            module: ModuleHandleIndex(0),
            name: name_idx,
            parameters: SignatureIndex(0),
            return_: SignatureIndex(0),
            type_parameters: vec![],
        });
        let def_idx = FunctionDefinitionIndex(u16::try_from(m.function_defs.len()).unwrap());
        m.function_defs.push(AdamantFunctionDefinition {
            function: handle_idx,
            visibility,
            is_entry: false,
            acquires_global_resources: vec![],
            code: Some(AdamantCodeUnit {
                locals: SignatureIndex(0),
                code: body,
                jump_tables: vec![],
            }),
        });
        def_idx
    }

    /// Append an external function-handle pointing to the named
    /// function in the dependency module identified by
    /// `(dep_address_byte, dep_module_name)`. Returns the
    /// `FunctionHandleIndex` in the deploying module's handles
    /// table. Adds the dep module's handle + address-identifier
    /// + name-identifier as needed.
    fn add_external_handle(
        m: &mut AdamantCompiledModule,
        dep_address_byte: u8,
        dep_module_name: &str,
        dep_function_name: &str,
    ) -> FunctionHandleIndex {
        let dep_address_idx =
            AddressIdentifierIndex(u16::try_from(m.address_identifiers.len()).unwrap());
        m.address_identifiers
            .push(Address::from_bytes([dep_address_byte; 32]));
        let dep_module_name_idx = IdentifierIndex(u16::try_from(m.identifiers.len()).unwrap());
        m.identifiers
            .push(Identifier::new(dep_module_name).unwrap());
        let dep_module_handle_idx =
            ModuleHandleIndex(u16::try_from(m.module_handles.len()).unwrap());
        m.module_handles.push(ModuleHandle {
            address: dep_address_idx,
            name: dep_module_name_idx,
        });
        let dep_function_name_idx = IdentifierIndex(u16::try_from(m.identifiers.len()).unwrap());
        m.identifiers
            .push(Identifier::new(dep_function_name).unwrap());
        let handle_idx = FunctionHandleIndex(u16::try_from(m.function_handles.len()).unwrap());
        m.function_handles.push(FunctionHandle {
            module: dep_module_handle_idx,
            name: dep_function_name_idx,
            parameters: SignatureIndex(0),
            return_: SignatureIndex(0),
            type_parameters: vec![],
        });
        handle_idx
    }

    /// Add a privacy-metadata entry for the given
    /// (def_idx, mode_byte) pairs.
    fn set_privacy_metadata(m: &mut AdamantCompiledModule, entries: &[(u16, u8)]) {
        let payload: Vec<(FunctionDefinitionIndex, u8)> = entries
            .iter()
            .map(|(idx, b)| (FunctionDefinitionIndex(*idx), *b))
            .collect();
        m.metadata.push(Metadata {
            key: PRIVACY_METADATA_KEY.to_vec(),
            value: bcs::to_bytes(&payload).unwrap(),
        });
    }

    fn ret() -> BytecodeInstruction {
        BytecodeInstruction::Inherited(Bytecode::Ret)
    }

    fn call(handle_idx: FunctionHandleIndex) -> BytecodeInstruction {
        BytecodeInstruction::Inherited(Bytecode::Call(handle_idx))
    }

    // ---------- happy paths ----------

    #[test]
    fn no_public_functions_accepts() {
        let m = skeleton_module(0x01, "deploying");
        let resolver = InMemoryModuleResolver::new();
        verify(&m, &resolver).expect("no public functions => trivially OK");
    }

    #[test]
    fn no_cross_module_calls_accepts() {
        let mut m = skeleton_module(0x01, "deploying");
        let pub_idx = add_function(&mut m, "p", Visibility::Public, vec![ret()]);
        set_privacy_metadata(&mut m, &[(pub_idx.0, PRIVACY_TRANSPARENT_BYTE)]);
        let resolver = InMemoryModuleResolver::new();
        verify(&m, &resolver).expect("no cross-module calls => no cross-module rule fires");
    }

    #[test]
    fn shielded_calls_shielded_dep_accepts() {
        // Dep module: a public shielded function "f".
        let mut dep = skeleton_module(0x02, "dep");
        let dep_pub = add_function(&mut dep, "f", Visibility::Public, vec![ret()]);
        set_privacy_metadata(&mut dep, &[(dep_pub.0, PRIVACY_SHIELDED_BYTE)]);
        // Deploying module: shielded public "p" calls dep::f.
        let mut m = skeleton_module(0x01, "deploying");
        let ext_handle = add_external_handle(&mut m, 0x02, "dep", "f");
        let pub_idx = add_function(
            &mut m,
            "p",
            Visibility::Public,
            vec![call(ext_handle), ret()],
        );
        set_privacy_metadata(&mut m, &[(pub_idx.0, PRIVACY_SHIELDED_BYTE)]);
        let mut resolver = InMemoryModuleResolver::new();
        resolver.insert(dep);
        verify(&m, &resolver).expect("shielded → shielded cross-module call OK");
    }

    #[test]
    fn transparent_calls_transparent_dep_accepts() {
        let mut dep = skeleton_module(0x02, "dep");
        let dep_pub = add_function(&mut dep, "f", Visibility::Public, vec![ret()]);
        set_privacy_metadata(&mut dep, &[(dep_pub.0, PRIVACY_TRANSPARENT_BYTE)]);
        let mut m = skeleton_module(0x01, "deploying");
        let ext_handle = add_external_handle(&mut m, 0x02, "dep", "f");
        let pub_idx = add_function(
            &mut m,
            "p",
            Visibility::Public,
            vec![call(ext_handle), ret()],
        );
        set_privacy_metadata(&mut m, &[(pub_idx.0, PRIVACY_TRANSPARENT_BYTE)]);
        let mut resolver = InMemoryModuleResolver::new();
        resolver.insert(dep);
        verify(&m, &resolver).expect("transparent → transparent cross-module call OK");
    }

    #[test]
    fn private_function_calls_dep_not_walked_from() {
        // Private functions don't have privacy annotations and
        // are not entry points for cross-module Rule 3 — even
        // a privacy-mismatched call from a private function is
        // not flagged by this walker (the walker enters from
        // public functions only).
        let mut dep = skeleton_module(0x02, "dep");
        let dep_pub = add_function(&mut dep, "f", Visibility::Public, vec![ret()]);
        set_privacy_metadata(&mut dep, &[(dep_pub.0, PRIVACY_TRANSPARENT_BYTE)]);
        let mut m = skeleton_module(0x01, "deploying");
        let ext_handle = add_external_handle(&mut m, 0x02, "dep", "f");
        // Private function calls dep — but no public function
        // reaches it.
        add_function(
            &mut m,
            "priv",
            Visibility::Private,
            vec![call(ext_handle), ret()],
        );
        let mut resolver = InMemoryModuleResolver::new();
        resolver.insert(dep);
        verify(&m, &resolver).expect(
            "no public function reaches the private callsite; cross-module rule doesn't fire",
        );
    }

    // ---------- rejections ----------

    #[test]
    fn shielded_reaches_transparent_dep_rejected() {
        let mut dep = skeleton_module(0x02, "dep");
        let dep_pub = add_function(&mut dep, "f", Visibility::Public, vec![ret()]);
        set_privacy_metadata(&mut dep, &[(dep_pub.0, PRIVACY_TRANSPARENT_BYTE)]);
        let mut m = skeleton_module(0x01, "deploying");
        let ext_handle = add_external_handle(&mut m, 0x02, "dep", "f");
        let pub_idx = add_function(
            &mut m,
            "p",
            Visibility::Public,
            vec![call(ext_handle), ret()],
        );
        set_privacy_metadata(&mut m, &[(pub_idx.0, PRIVACY_SHIELDED_BYTE)]);
        let mut resolver = InMemoryModuleResolver::new();
        resolver.insert(dep);
        match verify(&m, &resolver) {
            Err(AdamantValidationError::CrossModulePrivacyConsistencyViolation {
                reason: PrivacyConsistencyViolationReason::ShieldedReachesInvokeTransparent,
                target_module_id,
                ..
            }) => {
                assert_eq!(target_module_id.address, Address::from_bytes([0x02; 32]));
                assert_eq!(target_module_id.name.as_str(), "dep");
            }
            other => {
                panic!("expected ShieldedReachesInvokeTransparent cross-module, got {other:?}")
            }
        }
    }

    #[test]
    fn transparent_reaches_shielded_dep_rejected() {
        let mut dep = skeleton_module(0x02, "dep");
        let dep_pub = add_function(&mut dep, "f", Visibility::Public, vec![ret()]);
        set_privacy_metadata(&mut dep, &[(dep_pub.0, PRIVACY_SHIELDED_BYTE)]);
        let mut m = skeleton_module(0x01, "deploying");
        let ext_handle = add_external_handle(&mut m, 0x02, "dep", "f");
        let pub_idx = add_function(
            &mut m,
            "p",
            Visibility::Public,
            vec![call(ext_handle), ret()],
        );
        set_privacy_metadata(&mut m, &[(pub_idx.0, PRIVACY_TRANSPARENT_BYTE)]);
        let mut resolver = InMemoryModuleResolver::new();
        resolver.insert(dep);
        match verify(&m, &resolver) {
            Err(AdamantValidationError::CrossModulePrivacyConsistencyViolation {
                reason: PrivacyConsistencyViolationReason::TransparentReachesInvokeShielded,
                ..
            }) => {}
            other => {
                panic!("expected TransparentReachesInvokeShielded cross-module, got {other:?}")
            }
        }
    }

    #[test]
    fn missing_dep_rejected_from_shielded_caller() {
        // Dep module not loaded into resolver → resolver
        // returns None → walker rejects with shielded-side
        // reason.
        let mut m = skeleton_module(0x01, "deploying");
        let ext_handle = add_external_handle(&mut m, 0x02, "dep", "f");
        let pub_idx = add_function(
            &mut m,
            "p",
            Visibility::Public,
            vec![call(ext_handle), ret()],
        );
        set_privacy_metadata(&mut m, &[(pub_idx.0, PRIVACY_SHIELDED_BYTE)]);
        let resolver = InMemoryModuleResolver::new(); // empty
        match verify(&m, &resolver) {
            Err(AdamantValidationError::CrossModulePrivacyConsistencyViolation {
                reason: PrivacyConsistencyViolationReason::ShieldedReachesInvokeTransparent,
                target_module_id,
                ..
            }) => {
                assert_eq!(target_module_id.name.as_str(), "dep");
            }
            other => panic!("expected missing-dep rejection, got {other:?}"),
        }
    }

    #[test]
    fn missing_dep_target_function_in_loaded_module_rejected() {
        // Dep module IS loaded but doesn't contain a function
        // matching the called name. Reject (the dep's own
        // validation should have caught this; we reject for
        // walker robustness).
        let dep = skeleton_module(0x02, "dep"); // no functions
        let mut m = skeleton_module(0x01, "deploying");
        let ext_handle = add_external_handle(&mut m, 0x02, "dep", "missing_fn");
        let pub_idx = add_function(
            &mut m,
            "p",
            Visibility::Public,
            vec![call(ext_handle), ret()],
        );
        set_privacy_metadata(&mut m, &[(pub_idx.0, PRIVACY_TRANSPARENT_BYTE)]);
        let mut resolver = InMemoryModuleResolver::new();
        resolver.insert(dep);
        match verify(&m, &resolver) {
            Err(AdamantValidationError::CrossModulePrivacyConsistencyViolation { .. }) => {}
            other => panic!("expected missing-target-function rejection, got {other:?}"),
        }
    }

    #[test]
    fn shielded_reaches_transparent_dep_via_internal_callee_rejected() {
        // Shielded public 'p' calls internal private 'helper'
        // which calls dep::f (transparent). Cross-module rule
        // fires through transitive call.
        let mut dep = skeleton_module(0x02, "dep");
        let dep_pub = add_function(&mut dep, "f", Visibility::Public, vec![ret()]);
        set_privacy_metadata(&mut dep, &[(dep_pub.0, PRIVACY_TRANSPARENT_BYTE)]);

        let mut m = skeleton_module(0x01, "deploying");
        let ext_handle = add_external_handle(&mut m, 0x02, "dep", "f");
        let helper_idx = add_function(
            &mut m,
            "helper",
            Visibility::Private,
            vec![call(ext_handle), ret()],
        );
        let helper_handle = m.function_defs[helper_idx.0 as usize].function;
        let pub_idx = add_function(
            &mut m,
            "p",
            Visibility::Public,
            vec![call(helper_handle), ret()],
        );
        set_privacy_metadata(&mut m, &[(pub_idx.0, PRIVACY_SHIELDED_BYTE)]);

        let mut resolver = InMemoryModuleResolver::new();
        resolver.insert(dep);
        match verify(&m, &resolver) {
            Err(AdamantValidationError::CrossModulePrivacyConsistencyViolation {
                reason: PrivacyConsistencyViolationReason::ShieldedReachesInvokeTransparent,
                calling_function_index,
                ..
            }) => {
                // The cross-module call site is in helper, not
                // in the public p.
                assert_eq!(calling_function_index, helper_idx);
            }
            other => panic!("expected transitive cross-module rejection, got {other:?}"),
        }
    }

    #[test]
    fn cycle_in_internal_call_graph_terminates() {
        // p → helper → p (cycle through internal calls); no
        // cross-module call. The walker must terminate (visited
        // set deduplicates).
        let mut m = skeleton_module(0x01, "deploying");
        // First add p with a Ret-only body, then patch it to
        // call helper after both are placed.
        let p_idx = add_function(&mut m, "p", Visibility::Public, vec![ret()]);
        let p_handle = m.function_defs[p_idx.0 as usize].function;
        let helper_idx = add_function(
            &mut m,
            "helper",
            Visibility::Private,
            vec![call(p_handle), ret()],
        );
        let helper_handle = m.function_defs[helper_idx.0 as usize].function;
        m.function_defs[p_idx.0 as usize]
            .code
            .as_mut()
            .unwrap()
            .code = vec![call(helper_handle), ret()];
        set_privacy_metadata(&mut m, &[(p_idx.0, PRIVACY_TRANSPARENT_BYTE)]);
        let resolver = InMemoryModuleResolver::new();
        verify(&m, &resolver).expect("internal call cycle terminates and accepts");
    }
}
