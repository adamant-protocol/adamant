//! Validator Rule 6 (whitepaper §6.2.1.6 #6): no dynamic
//! dispatch.
//!
//! Sui-Move's dynamic-field operations are restricted: a
//! function may use them only if its module carries a
//! metadata entry `b"adamant.allows_dynamic"` whose value is
//! `true`. The default is to disallow them per section 6.1.4.
//!
//! # Spec text (§6.2.1.6 Rule 6 + line 485; verbatim re-paste
//! from E-3 plan-gate verification gate)
//!
//! "Sui-Move's dynamic-field operations are restricted: a
//! function may use them only if its module carries a metadata
//! entry `b"adamant.allows_dynamic"` whose value is `true`.
//! The default is to disallow them per section 6.1.4. Most
//! Sui-Move modules don't use dynamic fields; those that do
//! typically rely on them for collection types that have
//! first-class object equivalents in Adamant."
//!
//! "'Dynamic-field operations' are specifically calls to
//! functions whose target module is at address `0x2` and whose
//! module name is either `dynamic_field` or
//! `dynamic_object_field`. This pins the rule's scope at the
//! module level (rather than enumerating individual function
//! names) so that future additions to those Sui standard
//! library modules are automatically captured by the rule
//! without spec amendment. The verifier identifies these calls
//! by inspecting `Call` and `CallGeneric` instructions and
//! resolving their `FunctionHandle` to the target module's
//! `(address, name)` pair via the module's handle tables."
//!
//! # Adamant-spec-text-pinned constants
//!
//! The forbidden address (`0x2`) and module names
//! (`dynamic_field`, `dynamic_object_field`) are spec-pinned
//! by §6.2.1.6 line 485. Adamant duplicates them as native
//! constants per the §6.2.1.8 resistant-proof posture; the
//! `adamant_native_constants_match_spec_text` test below
//! pins parity to the spec text.
//!
//! 1st instance of spec-text-pinned-constant-with-Adamant-
//! native-ownership pattern (registered at E-3 plan-gate Q2
//! refinement). Distinct from E-1b's
//! upstream-constant-duplication-with-test-time-parity-pin
//! pattern (which pins to Sui upstream); this pattern pins to
//! whitepaper spec text. Both share the Adamant-native
//! ownership discipline; differ in pinning authority.
//!
//! # Cross-pass-pipeline-dependency
//!
//! - Step 3 (`module_pass::bounds_checker`): function-handle
//!   indices and function-instantiation indices are validated
//!   in range.

use adamant_bytecode_format::{
    Bytecode, FunctionDefinitionIndex, FunctionHandleIndex, ModuleHandleIndex,
};
use adamant_types::Address;

use crate::bytecode::BytecodeInstruction;
use crate::module::AdamantCompiledModule;

use super::error::{AdamantValidationError, DynamicDispatchViolationReason};

/// Per whitepaper §6.2.1.6 Rule 6 + line 485, the metadata
/// key under which a module declares its dynamic-dispatch
/// opt-in.
const DYNAMIC_OPTIN_METADATA_KEY: &[u8] = b"adamant.allows_dynamic";

/// Per whitepaper §6.2.1.6 line 485, the address at which
/// Sui-Move's dynamic-field standard library lives. Encoded
/// as a 32-byte big-endian value with byte 31 = 0x02.
const FORBIDDEN_ADDRESS: Address = {
    let mut bytes = [0u8; 32];
    bytes[31] = 0x02;
    Address::from_bytes(bytes)
};

/// Per whitepaper §6.2.1.6 line 485, the two forbidden module
/// names at [`FORBIDDEN_ADDRESS`].
const FORBIDDEN_DYNAMIC_FIELD: &str = "dynamic_field";
const FORBIDDEN_DYNAMIC_OBJECT_FIELD: &str = "dynamic_object_field";

/// Verify §6.2.1.6 Rule 6 against `module`.
///
/// If the module's metadata carries
/// `b"adamant.allows_dynamic"` whose BCS-decoded value is
/// `true`, all dynamic-field calls are allowed and the pass
/// returns [`Ok`] without inspecting the bytecode. Otherwise,
/// every `Call`/`CallGeneric` is inspected; if any targets a
/// function in `0x2::dynamic_field` or
/// `0x2::dynamic_object_field`, the pass returns
/// [`AdamantValidationError::DynamicDispatchViolation`].
pub(super) fn verify(module: &AdamantCompiledModule) -> Result<(), AdamantValidationError> {
    if has_dynamic_optin(module) {
        return Ok(());
    }

    for (def_idx_usize, function_def) in module.function_defs.iter().enumerate() {
        let Some(code_unit) = function_def.code.as_ref() else {
            continue;
        };
        let calling_function_index = FunctionDefinitionIndex(
            u16::try_from(def_idx_usize).expect("function-def count fits u16"),
        );

        for (offset_usize, instr) in code_unit.code.iter().enumerate() {
            let code_offset =
                u16::try_from(offset_usize).expect("code offset fits u16 per binary-format limits");

            let Some(target_handle_idx) = call_handle_for_dispatch_check(module, instr) else {
                continue;
            };

            if let Some(reason) =
                forbidden_dynamic_target(module, target_handle_idx)
            {
                return Err(AdamantValidationError::DynamicDispatchViolation {
                    calling_function_index,
                    code_offset,
                    calling_function_handle_idx: target_handle_idx,
                    reason,
                });
            }
        }
    }

    Ok(())
}

/// Check whether the module's metadata carries
/// `b"adamant.allows_dynamic"` whose BCS-decoded value is
/// `true`. Returns `false` for missing entry, `false`-valued
/// entry, or malformed payload (the deserializer + step-3
/// `privacy_metadata_structure` only validate the privacy
/// entry; the dynamic-opt-in entry has no separate structural
/// pass, so a malformed payload here defaults to disallow per
/// the Rule 6 default).
fn has_dynamic_optin(module: &AdamantCompiledModule) -> bool {
    let Some(entry) = module
        .metadata
        .iter()
        .find(|m| m.key == DYNAMIC_OPTIN_METADATA_KEY)
    else {
        return false;
    };
    bcs::from_bytes::<bool>(&entry.value).unwrap_or(false)
}

/// Identify call instructions Rule 6 inspects: per §6.2.1.6
/// line 485, only `Call` and `CallGeneric` (not
/// `InvokeShielded`/`InvokeTransparent`, which target Adamant-
/// native callees by construction and never resolve to Sui-
/// Move's dynamic-field modules).
fn call_handle_for_dispatch_check(
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
        _ => None,
    }
}

/// Resolve the call's target module and check whether it
/// matches one of the forbidden `(address, name)` pairs.
/// Returns the matching [`DynamicDispatchViolationReason`] or
/// `None` if the target is not a forbidden dynamic-field
/// module.
fn forbidden_dynamic_target(
    module: &AdamantCompiledModule,
    target_handle_idx: FunctionHandleIndex,
) -> Option<DynamicDispatchViolationReason> {
    let handle = &module.function_handles[target_handle_idx.0 as usize];
    let target_address = resolve_module_address(module, handle.module)?;
    if target_address != FORBIDDEN_ADDRESS {
        return None;
    }
    let target_module_name = resolve_module_name(module, handle.module)?;
    match target_module_name {
        FORBIDDEN_DYNAMIC_FIELD => Some(DynamicDispatchViolationReason::DynamicFieldNotOptedIn),
        FORBIDDEN_DYNAMIC_OBJECT_FIELD => {
            Some(DynamicDispatchViolationReason::DynamicObjectFieldNotOptedIn)
        }
        _ => None,
    }
}

fn resolve_module_address(
    module: &AdamantCompiledModule,
    module_handle_idx: ModuleHandleIndex,
) -> Option<Address> {
    let module_handle = module.module_handles.get(module_handle_idx.0 as usize)?;
    module
        .address_identifiers
        .get(module_handle.address.0 as usize)
        .copied()
}

fn resolve_module_name(
    module: &AdamantCompiledModule,
    module_handle_idx: ModuleHandleIndex,
) -> Option<&str> {
    let module_handle = module.module_handles.get(module_handle_idx.0 as usize)?;
    Some(
        module
            .identifiers
            .get(module_handle.name.0 as usize)?
            .as_str(),
    )
}

#[cfg(test)]
mod tests {
    //! Layer A tests for Rule 6 (no dynamic dispatch).
    //!
    //! No Layer B parity tests by design — Rule 6 is an
    //! Adamant-specific rule per §6.2.1.6; Sui-Move has no
    //! equivalent.
    //!
    //! Coverage:
    //! - Adamant-spec-text-parity test for `FORBIDDEN_ADDRESS`
    //!   and `FORBIDDEN_*` module-name constants
    //! - Happy paths: no dynamic calls; opt-in present (true);
    //!   call to a non-dynamic-field module at `0x2`; call to
    //!   `dynamic_field` at a different address
    //! - Rejections: `Call` to `dynamic_field` without opt-in;
    //!   `CallGeneric` to `dynamic_object_field` without
    //!   opt-in; opt-in present but value=false; opt-in
    //!   present but malformed payload

    use super::*;
    use adamant_bytecode_format::{
        AddressIdentifierIndex, FunctionHandle, FunctionInstantiation, FunctionInstantiationIndex,
        Identifier, IdentifierIndex, Metadata, ModuleHandle, Signature, SignatureIndex, Visibility,
    };

    use crate::module::{AdamantCodeUnit, AdamantCompiledModule, AdamantFunctionDefinition};

    fn ret() -> BytecodeInstruction {
        BytecodeInstruction::Inherited(Bytecode::Ret)
    }

    fn call(idx: FunctionHandleIndex) -> BytecodeInstruction {
        BytecodeInstruction::Inherited(Bytecode::Call(idx))
    }

    fn call_generic(idx: FunctionInstantiationIndex) -> BytecodeInstruction {
        BytecodeInstruction::Inherited(Bytecode::CallGeneric(idx))
    }

    /// Build a minimal-shape deploying module rooted at
    /// `(deploy_address_byte, deploy_module_name)` with one
    /// function-def whose body is `body`.
    fn deploying_module(
        deploy_address_byte: u8,
        deploy_module_name: &str,
        body: Vec<BytecodeInstruction>,
    ) -> AdamantCompiledModule {
        let mut m = AdamantCompiledModule::default();
        m.module_handles.push(ModuleHandle {
            address: AddressIdentifierIndex(0),
            name: IdentifierIndex(0),
        });
        m.identifiers
            .push(Identifier::new(deploy_module_name).unwrap());
        m.address_identifiers
            .push(Address::from_bytes([deploy_address_byte; 32]));
        m.signatures.push(Signature(vec![]));
        // Self function-handle (so the deploying module has at
        // least one handle to define from).
        let self_fn_name_idx = IdentifierIndex(u16::try_from(m.identifiers.len()).unwrap());
        m.identifiers.push(Identifier::new("f").unwrap());
        let self_handle_idx = FunctionHandleIndex(u16::try_from(m.function_handles.len()).unwrap());
        m.function_handles.push(FunctionHandle {
            module: ModuleHandleIndex(0),
            name: self_fn_name_idx,
            parameters: SignatureIndex(0),
            return_: SignatureIndex(0),
            type_parameters: vec![],
        });
        m.function_defs.push(AdamantFunctionDefinition {
            function: self_handle_idx,
            visibility: Visibility::Private,
            is_entry: false,
            acquires_global_resources: vec![],
            code: Some(AdamantCodeUnit {
                locals: SignatureIndex(0),
                code: body,
                jump_tables: vec![],
            }),
        });
        m
    }

    /// Append an external function-handle pointing to
    /// `dep_address::dep_module_name::dep_function_name`,
    /// returning the new `FunctionHandleIndex`.
    fn add_external_handle(
        m: &mut AdamantCompiledModule,
        dep_address: Address,
        dep_module_name: &str,
        dep_function_name: &str,
    ) -> FunctionHandleIndex {
        let dep_address_idx =
            AddressIdentifierIndex(u16::try_from(m.address_identifiers.len()).unwrap());
        m.address_identifiers.push(dep_address);
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

    fn set_dynamic_optin(m: &mut AdamantCompiledModule, opt_in: bool) {
        m.metadata.push(Metadata {
            key: DYNAMIC_OPTIN_METADATA_KEY.to_vec(),
            value: bcs::to_bytes(&opt_in).unwrap(),
        });
    }

    fn set_malformed_optin(m: &mut AdamantCompiledModule) {
        // Truncated BCS: a bool needs exactly 1 byte; empty
        // payload won't decode.
        m.metadata.push(Metadata {
            key: DYNAMIC_OPTIN_METADATA_KEY.to_vec(),
            value: vec![],
        });
    }

    // ---------- Adamant-spec-text-parity ----------

    #[test]
    fn adamant_native_constants_match_spec_text() {
        // §6.2.1.6 line 485 pins address 0x2 + module names
        // `dynamic_field` / `dynamic_object_field`. Pin
        // Adamant's duplicated constants against the spec
        // text empirically.
        let mut expected_address = [0u8; 32];
        expected_address[31] = 0x02;
        assert_eq!(
            FORBIDDEN_ADDRESS,
            Address::from_bytes(expected_address),
            "FORBIDDEN_ADDRESS must encode the Sui-Move \
             standard-library address 0x2 per §6.2.1.6 line 485"
        );
        assert_eq!(FORBIDDEN_DYNAMIC_FIELD, "dynamic_field");
        assert_eq!(FORBIDDEN_DYNAMIC_OBJECT_FIELD, "dynamic_object_field");
        assert_eq!(DYNAMIC_OPTIN_METADATA_KEY, b"adamant.allows_dynamic");
    }

    // ---------- happy paths ----------

    #[test]
    fn no_calls_at_all_accepts() {
        let m = deploying_module(0xab, "deploying", vec![ret()]);
        verify(&m).expect("module without any calls trivially passes Rule 6");
    }

    #[test]
    fn call_to_non_dynamic_module_accepts() {
        let mut m = deploying_module(0xab, "deploying", vec![ret()]);
        let ext = add_external_handle(
            &mut m,
            Address::from_bytes([0x01; 32]),
            "regular_module",
            "regular_fn",
        );
        m.function_defs[0].code.as_mut().unwrap().code = vec![call(ext), ret()];
        verify(&m).expect("call to non-dynamic-field module accepts");
    }

    #[test]
    fn call_to_dynamic_field_with_optin_true_accepts() {
        let mut m = deploying_module(0xab, "deploying", vec![ret()]);
        let ext = add_external_handle(&mut m, FORBIDDEN_ADDRESS, FORBIDDEN_DYNAMIC_FIELD, "borrow");
        m.function_defs[0].code.as_mut().unwrap().code = vec![call(ext), ret()];
        set_dynamic_optin(&mut m, true);
        verify(&m).expect("opt-in true allows dynamic_field calls");
    }

    #[test]
    fn call_to_dynamic_field_at_wrong_address_accepts() {
        // Module named `dynamic_field` but at a non-0x2
        // address is not a forbidden target.
        let mut m = deploying_module(0xab, "deploying", vec![ret()]);
        let ext = add_external_handle(
            &mut m,
            Address::from_bytes([0x99; 32]),
            FORBIDDEN_DYNAMIC_FIELD,
            "borrow",
        );
        m.function_defs[0].code.as_mut().unwrap().code = vec![call(ext), ret()];
        verify(&m).expect("dynamic_field name at non-0x2 address is not forbidden");
    }

    #[test]
    fn call_to_other_module_at_0x2_accepts() {
        // Sui's 0x2 address hosts many modules; only
        // dynamic_field and dynamic_object_field are
        // forbidden.
        let mut m = deploying_module(0xab, "deploying", vec![ret()]);
        let ext =
            add_external_handle(&mut m, FORBIDDEN_ADDRESS, "transfer", "transfer_to_recipient");
        m.function_defs[0].code.as_mut().unwrap().code = vec![call(ext), ret()];
        verify(&m).expect("non-dynamic-field module at 0x2 not forbidden");
    }

    // ---------- rejections ----------

    #[test]
    fn call_to_dynamic_field_without_optin_rejected() {
        let mut m = deploying_module(0xab, "deploying", vec![ret()]);
        let ext = add_external_handle(&mut m, FORBIDDEN_ADDRESS, FORBIDDEN_DYNAMIC_FIELD, "borrow");
        m.function_defs[0].code.as_mut().unwrap().code = vec![call(ext), ret()];
        match verify(&m) {
            Err(AdamantValidationError::DynamicDispatchViolation {
                reason: DynamicDispatchViolationReason::DynamicFieldNotOptedIn,
                code_offset: 0,
                ..
            }) => {}
            other => panic!("expected DynamicFieldNotOptedIn, got {other:?}"),
        }
    }

    #[test]
    fn call_to_dynamic_object_field_without_optin_rejected() {
        let mut m = deploying_module(0xab, "deploying", vec![ret()]);
        let ext = add_external_handle(
            &mut m,
            FORBIDDEN_ADDRESS,
            FORBIDDEN_DYNAMIC_OBJECT_FIELD,
            "borrow",
        );
        m.function_defs[0].code.as_mut().unwrap().code = vec![call(ext), ret()];
        match verify(&m) {
            Err(AdamantValidationError::DynamicDispatchViolation {
                reason: DynamicDispatchViolationReason::DynamicObjectFieldNotOptedIn,
                ..
            }) => {}
            other => panic!("expected DynamicObjectFieldNotOptedIn, got {other:?}"),
        }
    }

    #[test]
    fn call_generic_to_dynamic_field_without_optin_rejected() {
        let mut m = deploying_module(0xab, "deploying", vec![ret()]);
        let ext = add_external_handle(&mut m, FORBIDDEN_ADDRESS, FORBIDDEN_DYNAMIC_FIELD, "borrow");
        // Build a function-instantiation pointing at the
        // external dynamic_field handle.
        let fi_idx = FunctionInstantiationIndex(
            u16::try_from(m.function_instantiations.len()).unwrap(),
        );
        m.function_instantiations.push(FunctionInstantiation {
            handle: ext,
            type_parameters: SignatureIndex(0),
        });
        m.function_defs[0].code.as_mut().unwrap().code = vec![call_generic(fi_idx), ret()];
        match verify(&m) {
            Err(AdamantValidationError::DynamicDispatchViolation {
                reason: DynamicDispatchViolationReason::DynamicFieldNotOptedIn,
                ..
            }) => {}
            other => panic!("expected CallGeneric → DynamicFieldNotOptedIn, got {other:?}"),
        }
    }

    #[test]
    fn optin_false_value_rejected_as_no_optin() {
        let mut m = deploying_module(0xab, "deploying", vec![ret()]);
        let ext = add_external_handle(&mut m, FORBIDDEN_ADDRESS, FORBIDDEN_DYNAMIC_FIELD, "borrow");
        m.function_defs[0].code.as_mut().unwrap().code = vec![call(ext), ret()];
        set_dynamic_optin(&mut m, false);
        match verify(&m) {
            Err(AdamantValidationError::DynamicDispatchViolation {
                reason: DynamicDispatchViolationReason::DynamicFieldNotOptedIn,
                ..
            }) => {}
            other => panic!("opt-in `false` must be treated as no opt-in; got {other:?}"),
        }
    }

    #[test]
    fn optin_malformed_payload_rejected_as_no_optin() {
        let mut m = deploying_module(0xab, "deploying", vec![ret()]);
        let ext = add_external_handle(&mut m, FORBIDDEN_ADDRESS, FORBIDDEN_DYNAMIC_FIELD, "borrow");
        m.function_defs[0].code.as_mut().unwrap().code = vec![call(ext), ret()];
        set_malformed_optin(&mut m);
        match verify(&m) {
            Err(AdamantValidationError::DynamicDispatchViolation {
                reason: DynamicDispatchViolationReason::DynamicFieldNotOptedIn,
                ..
            }) => {}
            other => panic!("malformed opt-in payload must default to disallow; got {other:?}"),
        }
    }
}
