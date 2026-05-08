//! Validator Rule 3 (whitepaper §6.2.1.6 #3): privacy
//! consistency.
//!
//! A `#[shielded]` function may not contain any
//! `InvokeTransparent` instruction; a `#[transparent]`
//! function may not contain any `InvokeShielded` instruction.
//! The verifier statically checks the entire call graph
//! reachable from each public function and rejects modules
//! where the privacy mode would be violated.
//!
//! # Defense-in-depth posture
//!
//! Per §6.2.1.6 line 477: privacy consistency is enforced
//! through defense in depth. The AVM enforces privacy at
//! runtime as the consensus-binding mechanism (a
//! `#[shielded]` function structurally requires shielded
//! execution context); the deploy-time static check is the
//! deployer-feedback and gas-trap-prevention layer. The
//! runtime check carries the residual binding for any case
//! the static analysis cannot fully verify.
//!
//! # Cross-module deferral (Q2(a) at D-5c plan-gate)
//!
//! Per §6.2.1.6 line 477: "Cross-module call graphs are
//! statically checked at deploy time against the annotations
//! of dependency modules visible on chain at that moment."
//! Adamant's deploy-time pipeline does not yet have
//! dependency-module loading wired; cross-module enforcement
//! is deferred to Phase 5/5b.5 (deployment-validator wiring)
//! per Q2(a) at D-5c plan-gate. At D-5c, external `Call` /
//! `CallGeneric` / `InvokeShielded` / `InvokeTransparent`
//! targets are treated as "external — assume conforming";
//! the runtime defense-in-depth carries the residual
//! binding.
//!
//! 2nd instance of deferred-implementation-with-explicit-
//! spec-anchor pattern (after D-5b move-regex-borrow-graph
//! out-of-scope determination); rule-of-three pending.
//!
//! # Two-pass split per §6.2.1.8
//!
//! This file is the step-5 Adamant-rule pass: walk the call
//! graph from each public function with declared privacy
//! mode and verify the body of every reachable function for
//! mode-consistent `Invoke*` instructions. Cross-pass-
//! pipeline-dependency on:
//!
//! - Step 3 (`module_pass::privacy_metadata_structure`): the
//!   `b"adamant.privacy"` metadata entry is well-formed —
//!   per-pair byte values in `{0x00, 0x01}`, function indices
//!   in range, no duplicate indices.
//! - Step 5 Rule 2 (`rule_02_privacy`): cardinality is one
//!   entry (or zero with no Public functions); every Public
//!   function is covered by the entry.
//! - Step 5 Rule 4 (`rule_04_no_natives`): no `code: None`
//!   function definitions. Defensively skip natives.
//! - Step 3 (`module_pass::bounds_checker`): function-handle
//!   indices, function-instantiation indices in range.

use std::collections::BTreeSet;

use adamant_bytecode_format::{Bytecode, FunctionDefinitionIndex, FunctionHandleIndex, Visibility};

use crate::bytecode::{AdamantBytecode, BytecodeInstruction};
use crate::module::AdamantCompiledModule;

use super::error::{AdamantValidationError, PrivacyConsistencyViolationReason};

/// Per whitepaper §6.2.1.3, the metadata key under which the
/// privacy annotation table is BCS-encoded.
const PRIVACY_METADATA_KEY: &[u8] = b"adamant.privacy";

/// Privacy-mode byte for transparent functions per §6.2.1.3.
const PRIVACY_TRANSPARENT_BYTE: u8 = 0x00;
/// Privacy-mode byte for shielded functions per §6.2.1.3.
const PRIVACY_SHIELDED_BYTE: u8 = 0x01;

/// Adamant-internal representation of the `PrivacyAnnotation`
/// byte from §6.2.1.3. Private to this module; the public-
/// facing byte values are the spec-canonical encoding.
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

/// Verify §6.2.1.6 Rule 3 against `module`.
///
/// Returns [`AdamantValidationError::PrivacyConsistencyViolation`]
/// for the first violation found in any public function's call
/// graph; returns [`Ok`] if every public function's call graph
/// is privacy-mode consistent.
pub(super) fn verify(module: &AdamantCompiledModule) -> Result<(), AdamantValidationError> {
    let public_modes = collect_public_privacy_modes(module);

    for (calling_public_idx, mode) in public_modes {
        let mut visited: BTreeSet<FunctionDefinitionIndex> = BTreeSet::new();
        verify_function_call_graph(
            module,
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
/// metadata entry. Friends and Privates in the entry are
/// skipped (per Q3 walk-back at Rule 2: only Public functions
/// are required to have a privacy annotation; non-Public
/// entries don't get walked from at Rule 3).
fn collect_public_privacy_modes(
    module: &AdamantCompiledModule,
) -> Vec<(FunctionDefinitionIndex, PrivacyMode)> {
    let Some(entry) = module
        .metadata
        .iter()
        .find(|m| m.key == PRIVACY_METADATA_KEY)
    else {
        // No privacy entry — Rule 2 already accepted the
        // module under "zero entries iff no Public function".
        return Vec::new();
    };

    // BCS decode is structurally-impossible at this point:
    // module_pass::privacy_metadata_structure (step 3)
    // already validated the payload. `expect()` here would
    // fire only on a direct-unvalidated-input caller violating
    // the cross-pass-pipeline-dependency precondition.
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
            // Friend / Private entries in the privacy table
            // are permitted by Rule 2 Q3 walk-back but not
            // walked from at Rule 3.
            continue;
        }
        let mode = PrivacyMode::from_byte(mode_byte).expect(
            "privacy mode byte validated at step 3 by `module_pass::privacy_metadata_structure`",
        );
        public_modes.push((def_idx, mode));
    }
    public_modes
}

/// Recursively walk the call graph from `current_function_idx`,
/// verifying each visited function's body against `mode`.
/// `visited` deduplicates per (function, mode) pair —
/// equivalently per function within a single root walk, since
/// a single root has a single mode.
fn verify_function_call_graph(
    module: &AdamantCompiledModule,
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
        // Native function — Rule 4 will reject this at step 5.
        // Defensively skip.
        return Ok(());
    };

    for (offset_usize, instr) in code_unit.code.iter().enumerate() {
        let offset =
            u16::try_from(offset_usize).expect("code offset fits u16 per binary-format limits");

        // Mode-consistency check per §6.2.1.6 Rule 3.
        match instr {
            BytecodeInstruction::Adamant(AdamantBytecode::InvokeShielded(_))
                if mode == PrivacyMode::Transparent =>
            {
                return Err(AdamantValidationError::PrivacyConsistencyViolation {
                    calling_public_index: calling_public_idx,
                    violating_function_index: current_function_idx,
                    code_offset: offset,
                    reason: PrivacyConsistencyViolationReason::TransparentReachesInvokeShielded,
                });
            }
            BytecodeInstruction::Adamant(AdamantBytecode::InvokeTransparent(_))
                if mode == PrivacyMode::Shielded =>
            {
                return Err(AdamantValidationError::PrivacyConsistencyViolation {
                    calling_public_index: calling_public_idx,
                    violating_function_index: current_function_idx,
                    code_offset: offset,
                    reason: PrivacyConsistencyViolationReason::ShieldedReachesInvokeTransparent,
                });
            }
            _ => {}
        }

        // Recurse into call targets. Spec-text-DIRECTS-shared-
        // helper canonical principle 3rd instance (rule-of-
        // three threshold met): per §6.2.1.4 line 408 verbatim
        // ("treat reference inputs and outputs of
        // `InvokeShielded` exactly as they would for an
        // inherited `Call`"), the four call kinds are walked
        // uniformly via [`call_target_handle`]. Cross-pass-
        // distinct sub-classification confirmed:
        // - 1st: D-5a.1.b `call_signature` in TYPE-SAFETY pass
        // - 2nd: D-5b.2 `call` helper in BORROW-GRAPH pass
        // - 3rd (this site): `call_target_handle` in CALL-GRAPH
        //   pass (Rule 3).
        if let Some(target_handle_idx) = call_target_handle(module, instr) {
            if let Some(target_def_idx) = resolve_internal_function_def(module, target_handle_idx) {
                verify_function_call_graph(
                    module,
                    calling_public_idx,
                    target_def_idx,
                    mode,
                    visited,
                )?;
            }
            // External target: treated as conforming per Q2(a)
            // at D-5c plan-gate. Cross-module enforcement
            // deferred to Phase 5/5b.5.
        }
    }

    Ok(())
}

/// Spec-text-DIRECTS-shared-helper canonical principle 3rd
/// instance. Per §6.2.1.4 line 408 verbatim: "the verifier...
/// treat reference inputs and outputs of `InvokeShielded`
/// exactly as they would for an inherited `Call`". Returns
/// the target [`FunctionHandleIndex`] for any of the four
/// call kinds: `Call`, `CallGeneric`, `InvokeShielded`,
/// `InvokeTransparent`. Returns `None` for non-call
/// instructions.
///
/// Visibility promoted to `pub(in crate::validator)` at
/// Phase 5/5b.5 E-2b alongside the cross-module Rule 3
/// walker landing — both single-module Rule 3 (this file)
/// and cross-module Rule 3
/// (`validator/cross_module/rule_03_privacy_consistency.rs`)
/// consume the same helper. Methodology-positive: spec-
/// text-DIRECTS-shared-helper canonical principle continues
/// operating across module-boundary rule scopes.
#[allow(
    clippy::match_same_arms,
    reason = "byte-faithful per-call-kind table preserving the §6.2.1.4 line 408 audit anchor; \
              merging same-result arms (Call + InvokeShielded + InvokeTransparent) would lose \
              the spec-text-DIRECTS-shared-helper canonical principle's per-kind enumeration"
)]
pub(in crate::validator) fn call_target_handle(
    module: &AdamantCompiledModule,
    instr: &BytecodeInstruction,
) -> Option<FunctionHandleIndex> {
    match instr {
        BytecodeInstruction::Inherited(Bytecode::Call(handle_idx)) => Some(*handle_idx),
        BytecodeInstruction::Inherited(Bytecode::CallGeneric(inst_idx)) => {
            let inst_idx_usize = inst_idx.0 as usize;
            debug_assert!(
                inst_idx_usize < module.function_instantiations.len(),
                "function-instantiation index validated at step 3 by `module_pass::bounds_checker`"
            );
            Some(module.function_instantiations[inst_idx_usize].handle)
        }
        BytecodeInstruction::Adamant(
            AdamantBytecode::InvokeShielded(handle_idx)
            | AdamantBytecode::InvokeTransparent(handle_idx),
        ) => Some(*handle_idx),
        _ => None,
    }
}

/// Resolve a [`FunctionHandleIndex`] to a
/// [`FunctionDefinitionIndex`] IF the handle refers to a
/// function defined in this module; returns `None` for
/// external handles. Per Q2(a) at D-5c plan-gate: cross-
/// module Rule 3 enforcement is deferred.
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
    //! Layer A tests for Rule 3 (privacy-consistency call-
    //! graph walker).
    //!
    //! No Layer B parity tests by design — Rule 3 is an
    //! Adamant-specific rule per §6.2.1.6; Sui-Move has no
    //! equivalent.
    //!
    //! Coverage:
    //! - 2 audit pins for [`PrivacyConsistencyViolationReason`]
    //!   sub-reasons (direct + transitive each).
    //! - Happy paths for shielded-only, transparent-only,
    //!   private-reachable-from-both, no-public-functions,
    //!   self-recursive, cycle-detection, external-call-skip.

    use adamant_bytecode_format::{
        AddressIdentifierIndex, FunctionHandle, FunctionHandleIndex, FunctionInstantiation,
        FunctionInstantiationIndex, Identifier, IdentifierIndex, Metadata, ModuleHandle,
        ModuleHandleIndex, Signature, SignatureIndex, Visibility,
    };
    use adamant_types::Address as AccountAddress;

    use crate::bytecode::{AdamantBytecode, BytecodeInstruction};
    use crate::module::{AdamantCodeUnit, AdamantCompiledModule, AdamantFunctionDefinition};

    use super::super::error::{AdamantValidationError, PrivacyConsistencyViolationReason};
    use super::{verify, PRIVACY_METADATA_KEY, PRIVACY_SHIELDED_BYTE, PRIVACY_TRANSPARENT_BYTE};

    fn empty_module() -> AdamantCompiledModule {
        let mut m = AdamantCompiledModule::default();
        m.module_handles.push(ModuleHandle {
            address: AddressIdentifierIndex(0),
            name: IdentifierIndex(0),
        });
        m.identifiers.push(Identifier::new("M").unwrap());
        m.address_identifiers
            .push(AccountAddress::from_bytes([0u8; 32]));
        m
    }

    /// Append a function to the module with the given
    /// visibility and body. Returns the function-definition
    /// index.
    fn push_fn(
        m: &mut AdamantCompiledModule,
        name: &str,
        visibility: Visibility,
        body: Vec<BytecodeInstruction>,
    ) -> u16 {
        let name_idx = IdentifierIndex(u16::try_from(m.identifiers.len()).unwrap());
        m.identifiers.push(Identifier::new(name).unwrap());
        let empty_sig = SignatureIndex(u16::try_from(m.signatures.len()).unwrap());
        m.signatures.push(Signature(vec![]));
        let handle_idx = FunctionHandleIndex(u16::try_from(m.function_handles.len()).unwrap());
        m.function_handles.push(FunctionHandle {
            module: ModuleHandleIndex(0),
            name: name_idx,
            parameters: empty_sig,
            return_: empty_sig,
            type_parameters: vec![],
        });
        let def_idx = u16::try_from(m.function_defs.len()).unwrap();
        m.function_defs.push(AdamantFunctionDefinition {
            function: handle_idx,
            visibility,
            is_entry: false,
            acquires_global_resources: vec![],
            code: Some(AdamantCodeUnit {
                locals: empty_sig,
                code: body,
                jump_tables: vec![],
            }),
        });
        def_idx
    }

    /// Append an EXTERNAL function handle (target module is a
    /// different module-handle). Returns the function-handle
    /// index. No function-def is created since the function
    /// is external.
    fn push_external_fn_handle(m: &mut AdamantCompiledModule, name: &str) -> FunctionHandleIndex {
        // External module-handle: any module-handle index
        // != self_module_handle_idx. We push a second module-
        // handle and use it.
        let external_module_handle_idx = if m.module_handles.len() == 1 {
            m.identifiers.push(Identifier::new("ext_mod").unwrap());
            m.module_handles.push(ModuleHandle {
                address: AddressIdentifierIndex(0),
                name: IdentifierIndex(u16::try_from(m.identifiers.len() - 1).unwrap()),
            });
            ModuleHandleIndex(u16::try_from(m.module_handles.len() - 1).unwrap())
        } else {
            ModuleHandleIndex(1)
        };
        let name_idx = IdentifierIndex(u16::try_from(m.identifiers.len()).unwrap());
        m.identifiers.push(Identifier::new(name).unwrap());
        let empty_sig = SignatureIndex(u16::try_from(m.signatures.len()).unwrap());
        m.signatures.push(Signature(vec![]));
        let handle_idx = FunctionHandleIndex(u16::try_from(m.function_handles.len()).unwrap());
        m.function_handles.push(FunctionHandle {
            module: external_module_handle_idx,
            name: name_idx,
            parameters: empty_sig,
            return_: empty_sig,
            type_parameters: vec![],
        });
        handle_idx
    }

    /// Add a privacy-metadata entry covering `pairs`.
    fn add_privacy_entry(m: &mut AdamantCompiledModule, pairs: &[(u16, u8)]) {
        use adamant_bytecode_format::FunctionDefinitionIndex;
        let payload: Vec<(FunctionDefinitionIndex, u8)> = pairs
            .iter()
            .map(|(idx, b)| (FunctionDefinitionIndex(*idx), *b))
            .collect();
        m.metadata.push(Metadata {
            key: PRIVACY_METADATA_KEY.to_vec(),
            value: bcs::to_bytes(&payload).unwrap(),
        });
    }

    fn ret() -> BytecodeInstruction {
        BytecodeInstruction::Inherited(adamant_bytecode_format::Bytecode::Ret)
    }

    fn invoke_shielded(handle_idx: FunctionHandleIndex) -> BytecodeInstruction {
        BytecodeInstruction::Adamant(AdamantBytecode::InvokeShielded(handle_idx))
    }

    fn invoke_transparent(handle_idx: FunctionHandleIndex) -> BytecodeInstruction {
        BytecodeInstruction::Adamant(AdamantBytecode::InvokeTransparent(handle_idx))
    }

    fn call_inst(handle_idx: FunctionHandleIndex) -> BytecodeInstruction {
        BytecodeInstruction::Inherited(adamant_bytecode_format::Bytecode::Call(handle_idx))
    }

    // ---------- happy paths ----------

    /// Module with no public functions accepts (Rule 2 already
    /// accepted with "zero entries iff no Public function").
    #[test]
    fn no_public_functions_accepts() {
        let mut m = empty_module();
        push_fn(&mut m, "p", Visibility::Private, vec![ret()]);
        verify(&m).expect("Rule 3 vacuously accepts module with no public functions");
    }

    /// Shielded public function whose body has no Invoke*
    /// accepts.
    #[test]
    fn shielded_public_with_empty_body_accepts() {
        let mut m = empty_module();
        let pub_idx = push_fn(&mut m, "f", Visibility::Public, vec![ret()]);
        add_privacy_entry(&mut m, &[(pub_idx, PRIVACY_SHIELDED_BYTE)]);
        verify(&m).expect("Rule 3 accepts shielded public with no Invoke*");
    }

    /// Transparent public function whose body has no Invoke*
    /// accepts.
    #[test]
    fn transparent_public_with_empty_body_accepts() {
        let mut m = empty_module();
        let pub_idx = push_fn(&mut m, "f", Visibility::Public, vec![ret()]);
        add_privacy_entry(&mut m, &[(pub_idx, PRIVACY_TRANSPARENT_BYTE)]);
        verify(&m).expect("Rule 3 accepts transparent public with no Invoke*");
    }

    /// Shielded public function calling shielded private
    /// (via InvokeShielded) accepts.
    #[test]
    fn shielded_calls_shielded_private_accepts() {
        let mut m = empty_module();
        // Private function 1 with empty body.
        let _priv_idx = push_fn(&mut m, "p", Visibility::Private, vec![ret()]);
        let priv_handle = m.function_defs[0].function;
        // Public function 0 invokes private 1.
        let pub_idx = push_fn(
            &mut m,
            "f",
            Visibility::Public,
            vec![invoke_shielded(priv_handle), ret()],
        );
        add_privacy_entry(&mut m, &[(pub_idx, PRIVACY_SHIELDED_BYTE)]);
        verify(&m).expect("Rule 3 accepts shielded calling shielded private");
    }

    /// Public function with no Invoke* but a Call to a
    /// private function whose body is also empty accepts.
    #[test]
    fn public_with_call_to_internal_private_accepts() {
        let mut m = empty_module();
        let _priv_def_idx = push_fn(&mut m, "p", Visibility::Private, vec![ret()]);
        let priv_handle = m.function_defs[0].function;
        let pub_idx = push_fn(
            &mut m,
            "f",
            Visibility::Public,
            vec![call_inst(priv_handle), ret()],
        );
        add_privacy_entry(&mut m, &[(pub_idx, PRIVACY_SHIELDED_BYTE)]);
        verify(&m).expect("Rule 3 accepts shielded public calling private with empty body");
    }

    /// Self-recursive shielded public function with no
    /// inconsistent Invoke* accepts (cycle detection).
    #[test]
    fn self_recursive_shielded_accepts() {
        let mut m = empty_module();
        // Pre-allocate the function-handle by pushing the
        // function first with a placeholder, then patching
        // the body to call its own handle.
        let pub_idx = push_fn(&mut m, "f", Visibility::Public, vec![ret()]);
        let pub_handle = m.function_defs[pub_idx as usize].function;
        m.function_defs[pub_idx as usize]
            .code
            .as_mut()
            .unwrap()
            .code = vec![call_inst(pub_handle), ret()];
        add_privacy_entry(&mut m, &[(pub_idx, PRIVACY_SHIELDED_BYTE)]);
        verify(&m).expect("Rule 3 accepts self-recursive shielded public");
    }

    /// External Call (target module != self_module_handle)
    /// is treated as conforming per Q2(a). No internal
    /// function-def for the external handle; recursion skips.
    #[test]
    fn external_call_treated_as_conforming() {
        let mut m = empty_module();
        let pub_idx = push_fn(&mut m, "f", Visibility::Public, vec![ret()]);
        // Add external handle and patch the body.
        let ext_handle = push_external_fn_handle(&mut m, "ext_fn");
        m.function_defs[pub_idx as usize]
            .code
            .as_mut()
            .unwrap()
            .code = vec![call_inst(ext_handle), ret()];
        add_privacy_entry(&mut m, &[(pub_idx, PRIVACY_SHIELDED_BYTE)]);
        verify(&m).expect("Rule 3 accepts external Call per Q2(a) at D-5c plan-gate");
    }

    /// Two public functions of different modes; their call
    /// graphs are disjoint. Both accept.
    #[test]
    fn two_public_disjoint_call_graphs_accept() {
        let mut m = empty_module();
        // Private 1 (called by shielded).
        let _p1_idx = push_fn(&mut m, "p1", Visibility::Private, vec![ret()]);
        let p1_handle = m.function_defs[0].function;
        // Private 2 (called by transparent).
        let _p2_idx = push_fn(&mut m, "p2", Visibility::Private, vec![ret()]);
        let p2_handle = m.function_defs[1].function;
        // Public shielded (calls p1).
        let s_idx = push_fn(
            &mut m,
            "s",
            Visibility::Public,
            vec![call_inst(p1_handle), ret()],
        );
        // Public transparent (calls p2).
        let t_idx = push_fn(
            &mut m,
            "t",
            Visibility::Public,
            vec![call_inst(p2_handle), ret()],
        );
        add_privacy_entry(
            &mut m,
            &[
                (s_idx, PRIVACY_SHIELDED_BYTE),
                (t_idx, PRIVACY_TRANSPARENT_BYTE),
            ],
        );
        verify(&m).expect("Rule 3 accepts disjoint shielded and transparent call graphs");
    }

    // ---------- 2 audit pins for sub-reasons ----------

    /// Audit pin 1 (direct):
    /// `ShieldedReachesInvokeTransparent` — shielded public
    /// function's body directly contains InvokeTransparent.
    #[test]
    fn shielded_directly_invokes_transparent_rejected() {
        let mut m = empty_module();
        // Pre-allocate the shielded public function handle
        // via push_fn, then add an external transparent
        // handle and patch the body.
        let pub_idx = push_fn(&mut m, "shielded_fn", Visibility::Public, vec![ret()]);
        let ext_handle = push_external_fn_handle(&mut m, "transparent_callee");
        m.function_defs[pub_idx as usize]
            .code
            .as_mut()
            .unwrap()
            .code = vec![invoke_transparent(ext_handle), ret()];
        add_privacy_entry(&mut m, &[(pub_idx, PRIVACY_SHIELDED_BYTE)]);
        match verify(&m) {
            Err(AdamantValidationError::PrivacyConsistencyViolation {
                reason: PrivacyConsistencyViolationReason::ShieldedReachesInvokeTransparent,
                calling_public_index,
                violating_function_index,
                ..
            }) => {
                assert_eq!(calling_public_index.0, pub_idx);
                assert_eq!(violating_function_index.0, pub_idx);
            }
            other => panic!("expected ShieldedReachesInvokeTransparent, got {other:?}"),
        }
    }

    /// Audit pin 1 (transitive): shielded public function
    /// calls a private function whose body contains
    /// InvokeTransparent.
    #[test]
    fn shielded_transitively_invokes_transparent_rejected() {
        let mut m = empty_module();
        // Private function 0 with InvokeTransparent (will be
        // patched to point at an external transparent target).
        let priv_idx = push_fn(&mut m, "p", Visibility::Private, vec![ret()]);
        let priv_handle = m.function_defs[priv_idx as usize].function;
        // Public shielded function 1 calls private function.
        let pub_idx = push_fn(
            &mut m,
            "f",
            Visibility::Public,
            vec![call_inst(priv_handle), ret()],
        );
        // External transparent handle for the private body.
        let ext_handle = push_external_fn_handle(&mut m, "transparent_callee");
        m.function_defs[priv_idx as usize]
            .code
            .as_mut()
            .unwrap()
            .code = vec![invoke_transparent(ext_handle), ret()];
        add_privacy_entry(&mut m, &[(pub_idx, PRIVACY_SHIELDED_BYTE)]);
        match verify(&m) {
            Err(AdamantValidationError::PrivacyConsistencyViolation {
                reason: PrivacyConsistencyViolationReason::ShieldedReachesInvokeTransparent,
                calling_public_index,
                violating_function_index,
                ..
            }) => {
                assert_eq!(calling_public_index.0, pub_idx);
                assert_eq!(violating_function_index.0, priv_idx);
            }
            other => panic!("expected ShieldedReachesInvokeTransparent transitive, got {other:?}"),
        }
    }

    /// Audit pin 2 (direct):
    /// `TransparentReachesInvokeShielded` — transparent
    /// public function directly contains InvokeShielded.
    #[test]
    fn transparent_directly_invokes_shielded_rejected() {
        let mut m = empty_module();
        let pub_idx = push_fn(&mut m, "transparent_fn", Visibility::Public, vec![ret()]);
        let ext_handle = push_external_fn_handle(&mut m, "shielded_callee");
        m.function_defs[pub_idx as usize]
            .code
            .as_mut()
            .unwrap()
            .code = vec![invoke_shielded(ext_handle), ret()];
        add_privacy_entry(&mut m, &[(pub_idx, PRIVACY_TRANSPARENT_BYTE)]);
        match verify(&m) {
            Err(AdamantValidationError::PrivacyConsistencyViolation {
                reason: PrivacyConsistencyViolationReason::TransparentReachesInvokeShielded,
                calling_public_index,
                violating_function_index,
                ..
            }) => {
                assert_eq!(calling_public_index.0, pub_idx);
                assert_eq!(violating_function_index.0, pub_idx);
            }
            other => panic!("expected TransparentReachesInvokeShielded, got {other:?}"),
        }
    }

    /// Audit pin 2 (transitive): transparent public function
    /// calls a private function whose body contains
    /// InvokeShielded.
    #[test]
    fn transparent_transitively_invokes_shielded_rejected() {
        let mut m = empty_module();
        let priv_idx = push_fn(&mut m, "p", Visibility::Private, vec![ret()]);
        let priv_handle = m.function_defs[priv_idx as usize].function;
        let pub_idx = push_fn(
            &mut m,
            "f",
            Visibility::Public,
            vec![call_inst(priv_handle), ret()],
        );
        let ext_handle = push_external_fn_handle(&mut m, "shielded_callee");
        m.function_defs[priv_idx as usize]
            .code
            .as_mut()
            .unwrap()
            .code = vec![invoke_shielded(ext_handle), ret()];
        add_privacy_entry(&mut m, &[(pub_idx, PRIVACY_TRANSPARENT_BYTE)]);
        match verify(&m) {
            Err(AdamantValidationError::PrivacyConsistencyViolation {
                reason: PrivacyConsistencyViolationReason::TransparentReachesInvokeShielded,
                calling_public_index,
                violating_function_index,
                ..
            }) => {
                assert_eq!(calling_public_index.0, pub_idx);
                assert_eq!(violating_function_index.0, priv_idx);
            }
            other => panic!("expected TransparentReachesInvokeShielded transitive, got {other:?}"),
        }
    }

    // ---------- additional coverage ----------

    /// CallGeneric resolves through function_instantiations
    /// to the underlying function-handle. Test that recursion
    /// follows.
    #[test]
    fn call_generic_resolves_through_instantiation() {
        let mut m = empty_module();
        let priv_idx = push_fn(&mut m, "p", Visibility::Private, vec![ret()]);
        let priv_handle = m.function_defs[priv_idx as usize].function;
        // Add a function_instantiation pointing at priv_handle
        // with empty type-parameters signature.
        let empty_sig = SignatureIndex(u16::try_from(m.signatures.len()).unwrap());
        m.signatures.push(Signature(vec![]));
        let inst_idx = u16::try_from(m.function_instantiations.len()).unwrap();
        m.function_instantiations.push(FunctionInstantiation {
            handle: priv_handle,
            type_parameters: empty_sig,
        });
        // Public shielded function calls private via CallGeneric.
        let pub_idx = push_fn(
            &mut m,
            "f",
            Visibility::Public,
            vec![
                BytecodeInstruction::Inherited(adamant_bytecode_format::Bytecode::CallGeneric(
                    FunctionInstantiationIndex(inst_idx),
                )),
                ret(),
            ],
        );
        // Patch private body to InvokeTransparent (inconsistent
        // with shielded mode).
        let ext_handle = push_external_fn_handle(&mut m, "transparent_callee");
        m.function_defs[priv_idx as usize]
            .code
            .as_mut()
            .unwrap()
            .code = vec![invoke_transparent(ext_handle), ret()];
        add_privacy_entry(&mut m, &[(pub_idx, PRIVACY_SHIELDED_BYTE)]);
        match verify(&m) {
            Err(AdamantValidationError::PrivacyConsistencyViolation {
                reason: PrivacyConsistencyViolationReason::ShieldedReachesInvokeTransparent,
                ..
            }) => {}
            other => {
                panic!("expected ShieldedReachesInvokeTransparent via CallGeneric, got {other:?}")
            }
        }
    }

    /// Multiple public functions both reach the same private
    /// function with different modes; the private function
    /// has no Invoke* — accepts.
    #[test]
    fn shared_private_with_no_invoke_accepts_for_both_modes() {
        let mut m = empty_module();
        let priv_idx = push_fn(&mut m, "p", Visibility::Private, vec![ret()]);
        let priv_handle = m.function_defs[priv_idx as usize].function;
        let s_idx = push_fn(
            &mut m,
            "s",
            Visibility::Public,
            vec![call_inst(priv_handle), ret()],
        );
        let t_idx = push_fn(
            &mut m,
            "t",
            Visibility::Public,
            vec![call_inst(priv_handle), ret()],
        );
        add_privacy_entry(
            &mut m,
            &[
                (s_idx, PRIVACY_SHIELDED_BYTE),
                (t_idx, PRIVACY_TRANSPARENT_BYTE),
            ],
        );
        verify(&m).expect(
            "Rule 3 accepts shared private reachable from both modes when private body is clean",
        );
    }

    /// Friend / Private functions in the privacy entry are
    /// skipped (Rule 2 Q3 walk-back) — they don't get walked
    /// from. Even if a Friend function in the privacy entry
    /// has an inconsistent Invoke*, Rule 3 doesn't walk from
    /// it.
    #[test]
    fn friend_in_privacy_entry_not_walked() {
        let mut m = empty_module();
        let friend_idx = push_fn(&mut m, "f", Visibility::Friend, vec![ret()]);
        let ext_handle = push_external_fn_handle(&mut m, "transparent_callee");
        m.function_defs[friend_idx as usize]
            .code
            .as_mut()
            .unwrap()
            .code = vec![invoke_transparent(ext_handle), ret()];
        add_privacy_entry(&mut m, &[(friend_idx, PRIVACY_SHIELDED_BYTE)]);
        verify(&m).expect("Rule 3 doesn't walk from non-Public functions in privacy entry");
    }
}
