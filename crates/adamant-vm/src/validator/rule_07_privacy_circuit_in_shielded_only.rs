//! Validator Rule 7 (whitepaper §6.2.1.6 #7): privacy-circuit
//! instructions in shielded context only.
//!
//! `GenerateProof`, `VerifyProof`, `RecursiveVerify`, and
//! `ReleaseSubViewKey` may appear only in the body of
//! `#[shielded]` functions or their internal callees. Calling
//! these from a transparent context is rejected at
//! verification time.
//!
//! # Spec text (§6.2.1.6 Rule 7; verbatim re-paste from E-4
//! plan-gate verification gate)
//!
//! "Privacy-circuit instructions in shielded context only.
//! `GenerateProof`, `VerifyProof`, `RecursiveVerify`, and
//! `ReleaseSubViewKey` may appear only in the body of
//! `#[shielded]` functions or their internal callees. Calling
//! these from a transparent context is rejected at
//! verification time."
//!
//! # Rule 7 / Rule 3 composition for cross-module coverage
//!
//! 1st instance of rule-composition-for-cross-module-coverage
//! methodology pattern (registered at E-4 plan-gate Q6).
//!
//! Rule 7 is **single-module only** at this layer. Cross-
//! module privacy-circuit-context violations are caught by
//! the composition of (a) cross-module Rule 3
//! (`validator/cross_module/rule_03_privacy_consistency`)
//! catching transparent → shielded boundary crossings at the
//! call edge, and (b) Rule 7 single-module per-module
//! enforcement catching privacy-circuit instructions in
//! transparent-reachable code within each module.
//!
//! - Transparent caller (deploying module) calls a shielded
//!   function in a dep module: cross-module Rule 3 (E-2b)
//!   rejects at the call edge.
//! - Transparent caller calls a transparent function in a
//!   dep module: the dep was validated at its own deploy
//!   time to not contain privacy-circuit instructions in
//!   transparent-reachable code (Rule 7 single-module on
//!   the dep). The composition is closed.
//!
//! Future readers note: a missing cross-module Rule 7
//! walker is intentional, not an oversight. The transitive-
//! coverage argument is the canonical reason.
//!
//! # Walker shape
//!
//! Mirrors D-5c's `rule_03_privacy_consistency` per the
//! call-graph-walker pattern's per-walk-state-determines-
//! reject sub-classification (Rule 3 carries `caller_mode`
//! state) vs walk-set-filter-at-entry sub-classification
//! (Rule 7 filters walk-set to `#[transparent]` public
//! functions only; no per-walk state needed). Helper
//! `call_target_handle` reused from D-5c via the
//! `pub(in crate::validator)` visibility promotion at E-2b.
//! 5th instance of spec-text-DIRECTS-shared-helper canonical
//! principle (cross-scope-reuse sub-shape 2nd instance;
//! rule-of-three pending across cross-scope-reuse).

use std::collections::BTreeSet;

use adamant_bytecode_format::{FunctionDefinitionIndex, FunctionHandleIndex, Visibility};

use crate::bytecode::{AdamantBytecode, BytecodeInstruction};
use crate::module::AdamantCompiledModule;

use super::error::{AdamantValidationError, PrivacyCircuitContextViolationReason};
use super::rule_03_privacy_consistency::call_target_handle;

/// Per whitepaper §6.2.1.3, the metadata key under which the
/// privacy annotation table is BCS-encoded.
const PRIVACY_METADATA_KEY: &[u8] = b"adamant.privacy";

/// Privacy-mode byte for transparent functions per §6.2.1.3.
const PRIVACY_TRANSPARENT_BYTE: u8 = 0x00;

/// Verify §6.2.1.6 Rule 7 against `module`.
///
/// For each `#[transparent]` public function, walk the
/// internal call graph and reject if any reachable function
/// body contains `GenerateProof` / `VerifyProof` /
/// `RecursiveVerify` / `ReleaseSubViewKey`.
pub(super) fn verify(module: &AdamantCompiledModule) -> Result<(), AdamantValidationError> {
    let transparent_publics = collect_transparent_public_indices(module);

    for calling_public_idx in transparent_publics {
        let mut visited: BTreeSet<FunctionDefinitionIndex> = BTreeSet::new();
        verify_function_call_graph(module, calling_public_idx, calling_public_idx, &mut visited)?;
    }

    Ok(())
}

/// Collect function-definition indices for every Public
/// function annotated `#[transparent]` (mode byte `0x00`).
/// Public functions annotated `#[shielded]` (mode byte
/// `0x01`) are intentionally excluded from the walk-set per
/// the walk-set-filter-at-entry sub-classification — they're
/// allowed to reach privacy-circuit instructions.
fn collect_transparent_public_indices(
    module: &AdamantCompiledModule,
) -> Vec<FunctionDefinitionIndex> {
    let Some(entry) = module
        .metadata
        .iter()
        .find(|m| m.key == PRIVACY_METADATA_KEY)
    else {
        // No privacy entry — Rule 2 already accepted the
        // module under "zero entries iff no Public function".
        return Vec::new();
    };

    let payload: Vec<(FunctionDefinitionIndex, u8)> = bcs::from_bytes(&entry.value).expect(
        "privacy metadata BCS payload is structurally-validated at step 3 by \
         `module_pass::privacy_metadata_structure`",
    );

    let mut transparent_publics = Vec::new();
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
        if mode_byte != PRIVACY_TRANSPARENT_BYTE {
            // Shielded public functions are permitted to
            // reach privacy-circuit instructions — skip.
            continue;
        }
        transparent_publics.push(def_idx);
    }
    transparent_publics
}

/// Walk the internal call graph from `current_function_idx`,
/// rejecting if any reachable function body contains a
/// privacy-circuit instruction.
fn verify_function_call_graph(
    module: &AdamantCompiledModule,
    calling_public_idx: FunctionDefinitionIndex,
    current_function_idx: FunctionDefinitionIndex,
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

        if let Some(reason) = privacy_circuit_reason(instr) {
            return Err(AdamantValidationError::PrivacyCircuitContextViolation {
                calling_public_index: calling_public_idx,
                violating_function_index: current_function_idx,
                code_offset: offset,
                reason,
            });
        }

        // Recurse into internal call targets only. Cross-
        // module calls are handled by cross-module Rule 3
        // (E-2b) via the rule-composition-for-cross-module-
        // coverage pattern — see this file's preamble.
        if let Some(target_handle_idx) = call_target_handle(module, instr) {
            if let Some(target_def_idx) = resolve_internal_function_def(module, target_handle_idx) {
                verify_function_call_graph(module, calling_public_idx, target_def_idx, visited)?;
            }
        }
    }

    Ok(())
}

/// Map a privacy-circuit instruction to its sub-reason. Returns
/// `None` for any other instruction.
fn privacy_circuit_reason(
    instr: &BytecodeInstruction,
) -> Option<PrivacyCircuitContextViolationReason> {
    match instr {
        BytecodeInstruction::Adamant(AdamantBytecode::GenerateProof(_)) => {
            Some(PrivacyCircuitContextViolationReason::GenerateProofInTransparentContext)
        }
        BytecodeInstruction::Adamant(AdamantBytecode::VerifyProof(_)) => {
            Some(PrivacyCircuitContextViolationReason::VerifyProofInTransparentContext)
        }
        BytecodeInstruction::Adamant(AdamantBytecode::RecursiveVerify) => {
            Some(PrivacyCircuitContextViolationReason::RecursiveVerifyInTransparentContext)
        }
        BytecodeInstruction::Adamant(AdamantBytecode::ReleaseSubViewKey) => {
            Some(PrivacyCircuitContextViolationReason::ReleaseSubViewKeyInTransparentContext)
        }
        _ => None,
    }
}

/// Resolve a [`FunctionHandleIndex`] to a
/// [`FunctionDefinitionIndex`] within the same module.
/// Mirrors D-5c's helper; kept private (cross-module call
/// resolution is out of scope per the rule-composition-for-
/// cross-module-coverage pattern).
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
    //! Layer A tests for Rule 7.
    //!
    //! No Layer B parity tests by design — Rule 7 is an
    //! Adamant-specific rule per §6.2.1.6; Sui-Move has no
    //! equivalent.

    use super::*;
    use adamant_bytecode_format::{
        AddressIdentifierIndex, Bytecode, FunctionHandle, Identifier, IdentifierIndex, Metadata,
        ModuleHandle, ModuleHandleIndex, Signature, SignatureIndex,
    };
    use adamant_types::Address;

    use crate::bytecode::CircuitId;
    use crate::module::{AdamantCodeUnit, AdamantCompiledModule, AdamantFunctionDefinition};

    const PRIVACY_SHIELDED_BYTE: u8 = 0x01;

    fn ret() -> BytecodeInstruction {
        BytecodeInstruction::Inherited(Bytecode::Ret)
    }

    fn pop() -> BytecodeInstruction {
        BytecodeInstruction::Inherited(Bytecode::Pop)
    }

    fn ld_u64() -> BytecodeInstruction {
        BytecodeInstruction::Inherited(Bytecode::LdU64(0))
    }

    fn call(idx: FunctionHandleIndex) -> BytecodeInstruction {
        BytecodeInstruction::Inherited(Bytecode::Call(idx))
    }

    fn generate_proof() -> BytecodeInstruction {
        BytecodeInstruction::Adamant(AdamantBytecode::GenerateProof(CircuitId(0)))
    }

    fn verify_proof() -> BytecodeInstruction {
        BytecodeInstruction::Adamant(AdamantBytecode::VerifyProof(CircuitId(0)))
    }

    fn recursive_verify() -> BytecodeInstruction {
        BytecodeInstruction::Adamant(AdamantBytecode::RecursiveVerify)
    }

    fn release_sub_view_key() -> BytecodeInstruction {
        BytecodeInstruction::Adamant(AdamantBytecode::ReleaseSubViewKey)
    }

    /// Build a minimal-shape deploying module with one self
    /// module handle. The caller appends function-defs.
    fn skeleton_module() -> AdamantCompiledModule {
        let mut m = AdamantCompiledModule::default();
        m.module_handles.push(ModuleHandle {
            address: AddressIdentifierIndex(0),
            name: IdentifierIndex(0),
        });
        m.identifiers.push(Identifier::new("deploying").unwrap());
        m.address_identifiers.push(Address::from_bytes([0xab; 32]));
        m.signatures.push(Signature(vec![]));
        m
    }

    /// Add a function with the given name + visibility +
    /// body. Returns the new FunctionDefinitionIndex (and
    /// implicitly the matching FunctionHandleIndex).
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

    // ---------- happy paths ----------

    #[test]
    fn no_public_functions_accepts() {
        let m = skeleton_module();
        verify(&m).expect("no public functions => trivially OK");
    }

    #[test]
    fn shielded_public_with_generate_proof_accepts() {
        let mut m = skeleton_module();
        let pub_idx = add_function(
            &mut m,
            "p",
            Visibility::Public,
            vec![generate_proof(), pop(), ret()],
        );
        set_privacy_metadata(&mut m, &[(pub_idx.0, PRIVACY_SHIELDED_BYTE)]);
        verify(&m).expect("shielded public may contain GenerateProof");
    }

    #[test]
    fn shielded_public_with_recursive_verify_accepts() {
        let mut m = skeleton_module();
        let pub_idx = add_function(
            &mut m,
            "p",
            Visibility::Public,
            vec![recursive_verify(), ret()],
        );
        set_privacy_metadata(&mut m, &[(pub_idx.0, PRIVACY_SHIELDED_BYTE)]);
        verify(&m).expect("shielded public may contain RecursiveVerify");
    }

    #[test]
    fn transparent_public_without_circuit_instructions_accepts() {
        let mut m = skeleton_module();
        let pub_idx = add_function(
            &mut m,
            "p",
            Visibility::Public,
            vec![ld_u64(), pop(), ret()],
        );
        set_privacy_metadata(&mut m, &[(pub_idx.0, PRIVACY_TRANSPARENT_BYTE)]);
        verify(&m).expect("transparent without circuit instructions OK");
    }

    #[test]
    fn private_function_with_circuit_instruction_not_walked_from() {
        // Private function contains GenerateProof but no
        // public function reaches it. Rule 7 enters from
        // public functions only — the violation is not
        // surfaced.
        let mut m = skeleton_module();
        add_function(
            &mut m,
            "priv",
            Visibility::Private,
            vec![generate_proof(), pop(), ret()],
        );
        // No privacy metadata at all — vacuously no
        // transparent publics.
        verify(&m).expect("private functions are not walk-set entry points");
    }

    // ---------- rejections ----------

    #[test]
    fn transparent_public_with_generate_proof_rejected() {
        let mut m = skeleton_module();
        let pub_idx = add_function(
            &mut m,
            "p",
            Visibility::Public,
            vec![generate_proof(), pop(), ret()],
        );
        set_privacy_metadata(&mut m, &[(pub_idx.0, PRIVACY_TRANSPARENT_BYTE)]);
        match verify(&m) {
            Err(AdamantValidationError::PrivacyCircuitContextViolation {
                reason: PrivacyCircuitContextViolationReason::GenerateProofInTransparentContext,
                violating_function_index,
                ..
            }) => {
                assert_eq!(violating_function_index, pub_idx);
            }
            other => panic!("expected GenerateProofInTransparentContext, got {other:?}"),
        }
    }

    #[test]
    fn transparent_public_with_verify_proof_rejected() {
        let mut m = skeleton_module();
        let pub_idx = add_function(
            &mut m,
            "p",
            Visibility::Public,
            vec![verify_proof(), pop(), ret()],
        );
        set_privacy_metadata(&mut m, &[(pub_idx.0, PRIVACY_TRANSPARENT_BYTE)]);
        match verify(&m) {
            Err(AdamantValidationError::PrivacyCircuitContextViolation {
                reason: PrivacyCircuitContextViolationReason::VerifyProofInTransparentContext,
                ..
            }) => {}
            other => panic!("expected VerifyProofInTransparentContext, got {other:?}"),
        }
    }

    #[test]
    fn transparent_public_with_recursive_verify_rejected() {
        let mut m = skeleton_module();
        let pub_idx = add_function(
            &mut m,
            "p",
            Visibility::Public,
            vec![recursive_verify(), ret()],
        );
        set_privacy_metadata(&mut m, &[(pub_idx.0, PRIVACY_TRANSPARENT_BYTE)]);
        match verify(&m) {
            Err(AdamantValidationError::PrivacyCircuitContextViolation {
                reason: PrivacyCircuitContextViolationReason::RecursiveVerifyInTransparentContext,
                ..
            }) => {}
            other => panic!("expected RecursiveVerifyInTransparentContext, got {other:?}"),
        }
    }

    #[test]
    fn transparent_public_with_release_sub_view_key_rejected() {
        let mut m = skeleton_module();
        let pub_idx = add_function(
            &mut m,
            "p",
            Visibility::Public,
            vec![release_sub_view_key(), ret()],
        );
        set_privacy_metadata(&mut m, &[(pub_idx.0, PRIVACY_TRANSPARENT_BYTE)]);
        match verify(&m) {
            Err(AdamantValidationError::PrivacyCircuitContextViolation {
                reason: PrivacyCircuitContextViolationReason::ReleaseSubViewKeyInTransparentContext,
                ..
            }) => {}
            other => panic!("expected ReleaseSubViewKeyInTransparentContext, got {other:?}"),
        }
    }

    #[test]
    fn transparent_public_reaches_circuit_through_private_callee_rejected() {
        // Transparent public 'p' calls private 'helper' which
        // contains GenerateProof. Walker recurses into helper
        // and rejects.
        let mut m = skeleton_module();
        let helper_idx = add_function(
            &mut m,
            "helper",
            Visibility::Private,
            vec![generate_proof(), pop(), ret()],
        );
        let helper_handle = m.function_defs[helper_idx.0 as usize].function;
        let pub_idx = add_function(
            &mut m,
            "p",
            Visibility::Public,
            vec![call(helper_handle), ret()],
        );
        set_privacy_metadata(&mut m, &[(pub_idx.0, PRIVACY_TRANSPARENT_BYTE)]);
        match verify(&m) {
            Err(AdamantValidationError::PrivacyCircuitContextViolation {
                reason: PrivacyCircuitContextViolationReason::GenerateProofInTransparentContext,
                violating_function_index,
                ..
            }) => {
                // Violation is in helper, not in p itself.
                assert_eq!(violating_function_index, helper_idx);
            }
            other => panic!("expected transitive GenerateProof rejection, got {other:?}"),
        }
    }

    #[test]
    fn cycle_in_internal_call_graph_terminates() {
        // p → helper → p cycle without privacy-circuit
        // instructions. Walker must terminate via visited
        // dedup.
        let mut m = skeleton_module();
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
        verify(&m).expect("cycle terminates and accepts");
    }

    #[test]
    fn shielded_public_reaches_private_with_circuit_accepts() {
        // Shielded public 'p' calls private 'helper' which
        // contains GenerateProof — this is the canonical
        // valid use of privacy-circuit instructions.
        let mut m = skeleton_module();
        let helper_idx = add_function(
            &mut m,
            "helper",
            Visibility::Private,
            vec![generate_proof(), pop(), ret()],
        );
        let helper_handle = m.function_defs[helper_idx.0 as usize].function;
        let pub_idx = add_function(
            &mut m,
            "p",
            Visibility::Public,
            vec![call(helper_handle), ret()],
        );
        set_privacy_metadata(&mut m, &[(pub_idx.0, PRIVACY_SHIELDED_BYTE)]);
        verify(&m).expect("shielded public reaching private circuit instruction is the valid use");
    }

    #[test]
    fn mixed_modes_only_transparent_walked() {
        // Both shielded 'ps' and transparent 'pt' public
        // functions exist. 'ps' calls helper-with-circuit;
        // 'pt' doesn't reach the circuit. Rule 7 must walk
        // only from 'pt' (which is clean) and skip 'ps'.
        let mut m = skeleton_module();
        let helper_idx = add_function(
            &mut m,
            "helper",
            Visibility::Private,
            vec![generate_proof(), pop(), ret()],
        );
        let helper_handle = m.function_defs[helper_idx.0 as usize].function;
        let transparent_idx = add_function(
            &mut m,
            "pt",
            Visibility::Public,
            vec![ld_u64(), pop(), ret()],
        );
        let shielded_idx = add_function(
            &mut m,
            "ps",
            Visibility::Public,
            vec![call(helper_handle), ret()],
        );
        set_privacy_metadata(
            &mut m,
            &[
                (transparent_idx.0, PRIVACY_TRANSPARENT_BYTE),
                (shielded_idx.0, PRIVACY_SHIELDED_BYTE),
            ],
        );
        verify(&m).expect(
            "mixed-modes module: only transparent walked; transparent doesn't reach circuit",
        );
    }
}
