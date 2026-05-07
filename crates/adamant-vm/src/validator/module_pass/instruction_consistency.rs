//! Module-level pass: per-instruction generic/non-generic
//! consistency (whitepaper §6.2.1.8 step 3).
//!
//! Forked from
//! `vendor/move-bytecode-verifier/src/instruction_consistency.rs`
//! at Sui-Move tag `mainnet-v1.66.2` (commit
//! `a9a6825eaf6273cc819ee3bcf65fd4909f7624a9`). See
//! `validator/module_pass/PROVENANCE.md` for the deviation
//! list. Summary:
//!
//! - Operates on [`AdamantCompiledModule`] rather than Sui's
//!   `CompiledModule`. The instruction set covered by the pass
//!   matches Sui's byte-faithfully per Phase 5/5b.1b's
//!   bytecode-format fork.
//! - Returns typed [`AdamantValidationError`] variants
//!   (`GenericMemberOpcodeMismatch`, `VecPackUnpackArgOutOfRange`)
//!   rather than upstream's `PartialVMError`/`StatusCode`.
//! - **Drops upstream's per-deprecated-arm
//!   `safe_assert!(!config.deprecate_global_storage_ops)`
//!   pattern.** Adamant's pipeline rejects the 10 deprecated
//!   global-storage opcodes at deserialize-time per §6.2.1.6
//!   Rule 5 (Phase 5/5a `adamant_deserialize` strict mode);
//!   by the time a module reaches this pass, deprecated
//!   opcodes are structurally impossible. Sui's verifier-
//!   level safe-assert is defense-in-depth at the *verifier*
//!   layer because Sui's deserializer is permissive; Adamant's
//!   deserializer is strict, which moves the enforcement
//!   point upstream and makes the verifier-level assertion
//!   redundant by construction. The deprecated arms remain
//!   in the match for **exhaustiveness preservation** —
//!   Rust's compiler flags any new `Bytecode` variant in a
//!   future Sui upstream tag as a non-exhaustive-match error,
//!   which is the audit-trail signal the resistant-proof
//!   posture wants. The arm bodies are `unreachable!` rather
//!   than no-op so that programmer error (deserializer
//!   bypassed, strict-mode check disabled) surfaces as a
//!   panic with a structural-impossibility message rather
//!   than silently passing through the pass.
//!
//! Three checks per function body:
//!
//! 1. **Generic/non-generic flavor pairing.** For each paired-
//!    flavor instruction (`Pack`/`PackGeneric`,
//!    `Unpack`/`UnpackGeneric`, `Call`/`CallGeneric`, the
//!    field-borrow family, the variant-pack/unpack family),
//!    the non-generic form must reference a target whose
//!    declared `type_parameters` are empty, and the generic
//!    form must reference a target whose declared
//!    `type_parameters` are non-empty. Mismatch ⇒
//!    [`AdamantValidationError::GenericMemberOpcodeMismatch`].
//! 2. **`VecPack`/`VecUnpack` count bound.** The element-count
//!    operand must fit `u16::MAX`. Larger ⇒
//!    [`AdamantValidationError::VecPackUnpackArgOutOfRange`].
//! 3. **Adamant extensions** (per §6.2.1.4) traverse without
//!    flagging — none of the 17 extensions have generic-vs-
//!    non-generic flavor pairs (Q6 from the B-2 plan).
//!
//! Eager-error: first violation in `(function_defs[0..]) ×
//! (code[0..])` order wins.
//!
//! # Dead-code allow (transient)
//!
//! Phase 5/5b.2 B-5 wires this pass into
//! [`crate::validator::verify_module`]. Until B-5 lands, the
//! pass is reachable only from inline tests and Layer B
//! cross-validation; the lib build sees the entry point as
//! dead. The module-level `dead_code` allow is removed when
//! B-5 wires the pass.

#![allow(dead_code, reason = "wired into verify_module() in Phase 5/5b.2 B-5")]

use adamant_bytecode_format::{
    Bytecode, CodeOffset, DatatypeHandleIndex, EnumDefinitionIndex, FieldHandleIndex,
    FunctionDefinitionIndex, FunctionHandleIndex, StructDefinitionIndex, TableIndex,
};

use crate::bytecode::BytecodeInstruction;
use crate::module::AdamantCompiledModule;

use super::super::error::AdamantValidationError;

/// Verify per-instruction generic/non-generic consistency
/// across every function body in the module per §6.2.1.8 step
/// 3 (`module_pass::instruction_consistency`).
pub(in crate::validator) fn verify(
    module: &AdamantCompiledModule,
) -> Result<(), AdamantValidationError> {
    for (def_idx, function_def) in module.function_defs.iter().enumerate() {
        let Some(code) = &function_def.code else {
            continue;
        };
        let fn_def_idx = FunctionDefinitionIndex(TableIndex::try_from(def_idx).expect(
            "function_defs count exceeds u16; binary format precludes this \
                 (TABLE_INDEX_MAX = u16::MAX)",
        ));
        for (offset, instr) in code.code.iter().enumerate() {
            let code_offset = CodeOffset::try_from(offset)
                .expect("function body code length exceeds u16; CODE_OFFSET_MAX precludes this");
            check_instruction(module, fn_def_idx, code_offset, instr)?;
        }
    }
    Ok(())
}

fn check_instruction(
    module: &AdamantCompiledModule,
    fn_def_idx: FunctionDefinitionIndex,
    code_offset: CodeOffset,
    instr: &BytecodeInstruction,
) -> Result<(), AdamantValidationError> {
    use Bytecode::{
        Abort, Add, And, BitAnd, BitOr, BrFalse, BrTrue, Branch, Call, CallGeneric, CastU128,
        CastU16, CastU256, CastU32, CastU64, CastU8, CopyLoc, Div, Eq, ExistsDeprecated,
        ExistsGenericDeprecated, FreezeRef, Ge, Gt, ImmBorrowField, ImmBorrowFieldGeneric,
        ImmBorrowGlobalDeprecated, ImmBorrowGlobalGenericDeprecated, ImmBorrowLoc, LdConst,
        LdFalse, LdTrue, LdU128, LdU16, LdU256, LdU32, LdU64, LdU8, Le, Lt, Mod,
        MoveFromDeprecated, MoveFromGenericDeprecated, MoveLoc, MoveToDeprecated,
        MoveToGenericDeprecated, Mul, MutBorrowField, MutBorrowFieldGeneric,
        MutBorrowGlobalDeprecated, MutBorrowGlobalGenericDeprecated, MutBorrowLoc, Neq, Nop, Not,
        Or, Pack, PackGeneric, PackVariant, PackVariantGeneric, Pop, ReadRef, Ret, Shl, Shr, StLoc,
        Sub, Unpack, UnpackGeneric, UnpackVariant, UnpackVariantGeneric,
        UnpackVariantGenericImmRef, UnpackVariantGenericMutRef, UnpackVariantImmRef,
        UnpackVariantMutRef, VariantSwitch, VecImmBorrow, VecLen, VecMutBorrow, VecPack,
        VecPopBack, VecPushBack, VecSwap, VecUnpack, WriteRef, Xor,
    };

    let bc = match instr {
        BytecodeInstruction::Inherited(bc) => bc,
        // Adamant extensions per §6.2.1.4: none have generic
        // vs non-generic flavor pairs (Q6 confirmed at B-2
        // plan approval). No consistency check applies.
        BytecodeInstruction::Adamant(_) => return Ok(()),
    };

    match bc {
        // --- Field paired-flavor instructions ---
        MutBorrowField(field_handle_idx) | ImmBorrowField(field_handle_idx) => {
            check_field_op(module, fn_def_idx, code_offset, *field_handle_idx, false)?;
        }
        MutBorrowFieldGeneric(field_inst_idx) | ImmBorrowFieldGeneric(field_inst_idx) => {
            let field_inst = &module.field_instantiations[field_inst_idx.0 as usize];
            check_field_op(module, fn_def_idx, code_offset, field_inst.handle, true)?;
        }

        // --- Function-call paired-flavor instructions ---
        Call(handle) => {
            check_function_op(module, fn_def_idx, code_offset, *handle, false)?;
        }
        CallGeneric(inst) => {
            let func_inst = &module.function_instantiations[inst.0 as usize];
            check_function_op(module, fn_def_idx, code_offset, func_inst.handle, true)?;
        }

        // --- Struct paired-flavor instructions ---
        Pack(idx) | Unpack(idx) => {
            check_struct_type_op(module, fn_def_idx, code_offset, *idx, false)?;
        }
        PackGeneric(idx) | UnpackGeneric(idx) => {
            let struct_inst = &module.struct_def_instantiations[idx.0 as usize];
            check_struct_type_op(module, fn_def_idx, code_offset, struct_inst.def, true)?;
        }

        // --- Variant paired-flavor instructions ---
        PackVariant(v_handle)
        | UnpackVariant(v_handle)
        | UnpackVariantImmRef(v_handle)
        | UnpackVariantMutRef(v_handle) => {
            let handle = &module.variant_handles[v_handle.0 as usize];
            check_enum_type_op(module, fn_def_idx, code_offset, handle.enum_def, false)?;
        }
        PackVariantGeneric(vi_handle)
        | UnpackVariantGeneric(vi_handle)
        | UnpackVariantGenericImmRef(vi_handle)
        | UnpackVariantGenericMutRef(vi_handle) => {
            let handle = &module.variant_instantiation_handles[vi_handle.0 as usize];
            let enum_inst = &module.enum_def_instantiations[handle.enum_def.0 as usize];
            check_enum_type_op(module, fn_def_idx, code_offset, enum_inst.def, true)?;
        }

        // --- VecPack / VecUnpack count bound ---
        VecPack(_, num) | VecUnpack(_, num) => {
            if *num > u64::from(u16::MAX) {
                return Err(AdamantValidationError::VecPackUnpackArgOutOfRange {
                    fn_def_idx,
                    code_offset,
                    num: *num,
                });
            }
        }

        // --- Deprecated global-storage opcodes ---
        // These are structurally unreachable in Adamant's
        // pipeline. The arms exist for exhaustiveness
        // preservation: Rust's compiler flags any new
        // `Bytecode` variant added in a future Sui upstream
        // tag as a non-exhaustive-match error, which is the
        // audit-trail signal the resistant-proof posture
        // wants. See module-level doc.
        ExistsDeprecated(_)
        | ExistsGenericDeprecated(_)
        | MoveFromDeprecated(_)
        | MoveFromGenericDeprecated(_)
        | MoveToDeprecated(_)
        | MoveToGenericDeprecated(_)
        | MutBorrowGlobalDeprecated(_)
        | MutBorrowGlobalGenericDeprecated(_)
        | ImmBorrowGlobalDeprecated(_)
        | ImmBorrowGlobalGenericDeprecated(_) => unreachable!(
            "deprecated global-storage opcode reached \
             instruction_consistency: Adamant's deserializer \
             rejects all 10 deprecated opcodes at parse time \
             per §6.2.1.6 Rule 5 (Phase 5/5a adamant_deserialize \
             strict mode; tests bytecode_wire.rs:1242 \
             strict_mode_rejects_each_deprecated_opcode + \
             validator/mod.rs::tests::rejects_module_with_\
             deprecated_global_storage_opcode). If this fires, \
             either the deserializer is broken or the strict-mode \
             check was bypassed. This is an Adamant implementation \
             bug, not a module-level rejection."
        ),

        // --- All other inherited instructions: no-op ---
        FreezeRef | Pop | Ret | Branch(_) | BrTrue(_) | BrFalse(_) | LdU8(_) | LdU16(_)
        | LdU32(_) | LdU64(_) | LdU128(_) | LdU256(_) | LdConst(_) | CastU8 | CastU16 | CastU32
        | CastU64 | CastU128 | CastU256 | LdTrue | LdFalse | ReadRef | WriteRef | Add | Sub
        | Mul | Mod | Div | BitOr | BitAnd | Xor | Shl | Shr | Or | And | Not | Eq | Neq | Lt
        | Gt | Le | Ge | CopyLoc(_) | MoveLoc(_) | StLoc(_) | MutBorrowLoc(_) | ImmBorrowLoc(_)
        | VecLen(_) | VecImmBorrow(_) | VecMutBorrow(_) | VecPushBack(_) | VecPopBack(_)
        | VecSwap(_) | Abort | Nop | VariantSwitch(_) => (),
    }
    Ok(())
}

fn check_struct_type_op(
    module: &AdamantCompiledModule,
    fn_def_idx: FunctionDefinitionIndex,
    code_offset: CodeOffset,
    struct_def_idx: StructDefinitionIndex,
    generic: bool,
) -> Result<(), AdamantValidationError> {
    let struct_def = &module.struct_defs[struct_def_idx.0 as usize];
    check_type_op(
        module,
        fn_def_idx,
        code_offset,
        struct_def.struct_handle,
        generic,
    )
}

fn check_enum_type_op(
    module: &AdamantCompiledModule,
    fn_def_idx: FunctionDefinitionIndex,
    code_offset: CodeOffset,
    enum_def_idx: EnumDefinitionIndex,
    generic: bool,
) -> Result<(), AdamantValidationError> {
    let enum_def = &module.enum_defs[enum_def_idx.0 as usize];
    check_type_op(
        module,
        fn_def_idx,
        code_offset,
        enum_def.enum_handle,
        generic,
    )
}

fn check_type_op(
    module: &AdamantCompiledModule,
    fn_def_idx: FunctionDefinitionIndex,
    code_offset: CodeOffset,
    datatype_handle_idx: DatatypeHandleIndex,
    generic: bool,
) -> Result<(), AdamantValidationError> {
    let datatype_handle = &module.datatype_handles[datatype_handle_idx.0 as usize];
    if datatype_handle.type_parameters.is_empty() == generic {
        return Err(AdamantValidationError::GenericMemberOpcodeMismatch {
            fn_def_idx,
            code_offset,
        });
    }
    Ok(())
}

fn check_field_op(
    module: &AdamantCompiledModule,
    fn_def_idx: FunctionDefinitionIndex,
    code_offset: CodeOffset,
    field_handle_idx: FieldHandleIndex,
    generic: bool,
) -> Result<(), AdamantValidationError> {
    let field_handle = &module.field_handles[field_handle_idx.0 as usize];
    check_struct_type_op(module, fn_def_idx, code_offset, field_handle.owner, generic)
}

fn check_function_op(
    module: &AdamantCompiledModule,
    fn_def_idx: FunctionDefinitionIndex,
    code_offset: CodeOffset,
    func_handle_idx: FunctionHandleIndex,
    generic: bool,
) -> Result<(), AdamantValidationError> {
    let function_handle = &module.function_handles[func_handle_idx.0 as usize];
    if function_handle.type_parameters.is_empty() == generic {
        return Err(AdamantValidationError::GenericMemberOpcodeMismatch {
            fn_def_idx,
            code_offset,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    //! Layer A + Layer B tests for the
    //! `instruction_consistency` pass.
    //!
    //! All Layer B fixtures use **only non-deprecated
    //! opcodes**. Deprecated-opcode rejection is upstream's
    //! concern (Phase 5/5a deserializer tests at
    //! `bytecode_wire.rs:1242 strict_mode_rejects_each_deprecated_opcode`
    //! and `validator/mod.rs::tests::rejects_module_with_deprecated_global_storage_opcode`),
    //! not this pass's concern. By the time a module reaches
    //! `instruction_consistency`, deprecated opcodes are
    //! structurally impossible — see the module-level doc-
    //! comment on the `unreachable!` arms.

    use adamant_bytecode_format::{
        AbilitySet, AddressIdentifierIndex, Bytecode, DatatypeHandle, DatatypeHandleIndex,
        DatatypeTyParameter, EnumDefinition, FieldHandle, FieldHandleIndex, FieldInstantiation,
        FieldInstantiationIndex, FunctionHandle, FunctionHandleIndex, FunctionInstantiation,
        FunctionInstantiationIndex, Identifier, IdentifierIndex, ModuleHandle, ModuleHandleIndex,
        Signature, SignatureIndex, SignatureToken, StructDefInstantiation,
        StructDefInstantiationIndex, StructDefinition, StructDefinitionIndex,
        StructFieldInformation, VariantDefinition, VariantHandle, VariantHandleIndex,
        VariantInstantiationHandle, VariantInstantiationHandleIndex,
    };
    use adamant_types::Address as AccountAddress;

    use crate::bytecode::BytecodeInstruction;
    use crate::module::{AdamantCodeUnit, AdamantCompiledModule, AdamantFunctionDefinition};

    use super::super::super::error::AdamantValidationError;
    use super::super::test_helpers::assert_pass_parity;
    use super::verify;

    // ===================================================================
    // Fixture builders
    // ===================================================================

    fn empty_module() -> AdamantCompiledModule {
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

    fn push_identifier(m: &mut AdamantCompiledModule, name: &str) -> IdentifierIndex {
        let idx = IdentifierIndex(u16::try_from(m.identifiers.len()).unwrap());
        m.identifiers.push(Identifier::new(name).unwrap());
        idx
    }

    fn push_signature(
        m: &mut AdamantCompiledModule,
        tokens: Vec<SignatureToken>,
    ) -> SignatureIndex {
        let idx = SignatureIndex(u16::try_from(m.signatures.len()).unwrap());
        m.signatures.push(Signature(tokens));
        idx
    }

    /// Push a datatype handle. If `generic`, attach one
    /// non-phantom type parameter; else none.
    fn push_datatype_handle(
        m: &mut AdamantCompiledModule,
        name: &str,
        generic: bool,
    ) -> DatatypeHandleIndex {
        let name_idx = push_identifier(m, name);
        let idx = DatatypeHandleIndex(u16::try_from(m.datatype_handles.len()).unwrap());
        let type_parameters = if generic {
            vec![DatatypeTyParameter {
                constraints: AbilitySet::EMPTY,
                is_phantom: false,
            }]
        } else {
            vec![]
        };
        m.datatype_handles.push(DatatypeHandle {
            module: ModuleHandleIndex(0),
            name: name_idx,
            abilities: AbilitySet::EMPTY,
            type_parameters,
        });
        idx
    }

    /// Push a struct definition with no fields.
    fn push_struct_def(
        m: &mut AdamantCompiledModule,
        struct_handle: DatatypeHandleIndex,
    ) -> StructDefinitionIndex {
        let idx = StructDefinitionIndex(u16::try_from(m.struct_defs.len()).unwrap());
        m.struct_defs.push(StructDefinition {
            struct_handle,
            field_information: StructFieldInformation::Declared(vec![]),
        });
        idx
    }

    fn push_struct_def_inst(
        m: &mut AdamantCompiledModule,
        def: StructDefinitionIndex,
    ) -> StructDefInstantiationIndex {
        let type_args = push_signature(m, vec![SignatureToken::U64]);
        let idx =
            StructDefInstantiationIndex(u16::try_from(m.struct_def_instantiations.len()).unwrap());
        m.struct_def_instantiations.push(StructDefInstantiation {
            def,
            type_parameters: type_args,
        });
        idx
    }

    fn push_enum_def(
        m: &mut AdamantCompiledModule,
        enum_handle: DatatypeHandleIndex,
    ) -> adamant_bytecode_format::EnumDefinitionIndex {
        let v_name = push_identifier(m, "V");
        let idx =
            adamant_bytecode_format::EnumDefinitionIndex(u16::try_from(m.enum_defs.len()).unwrap());
        m.enum_defs.push(EnumDefinition {
            enum_handle,
            variants: vec![VariantDefinition {
                variant_name: v_name,
                fields: vec![],
            }],
        });
        idx
    }

    fn push_enum_def_inst(
        m: &mut AdamantCompiledModule,
        def: adamant_bytecode_format::EnumDefinitionIndex,
    ) -> adamant_bytecode_format::EnumDefInstantiationIndex {
        let type_args = push_signature(m, vec![SignatureToken::U64]);
        let idx = adamant_bytecode_format::EnumDefInstantiationIndex(
            u16::try_from(m.enum_def_instantiations.len()).unwrap(),
        );
        m.enum_def_instantiations
            .push(adamant_bytecode_format::EnumDefInstantiation {
                def,
                type_parameters: type_args,
            });
        idx
    }

    fn push_variant_handle(
        m: &mut AdamantCompiledModule,
        enum_def: adamant_bytecode_format::EnumDefinitionIndex,
    ) -> VariantHandleIndex {
        let idx = VariantHandleIndex(u16::try_from(m.variant_handles.len()).unwrap());
        m.variant_handles.push(VariantHandle {
            enum_def,
            variant: 0,
        });
        idx
    }

    fn push_variant_inst_handle(
        m: &mut AdamantCompiledModule,
        enum_def: adamant_bytecode_format::EnumDefInstantiationIndex,
    ) -> VariantInstantiationHandleIndex {
        let idx = VariantInstantiationHandleIndex(
            u16::try_from(m.variant_instantiation_handles.len()).unwrap(),
        );
        m.variant_instantiation_handles
            .push(VariantInstantiationHandle {
                enum_def,
                variant: 0,
            });
        idx
    }

    /// Push a function handle. If `generic`, attach one
    /// type parameter; else none. Empty parameters and return.
    fn push_function_handle(
        m: &mut AdamantCompiledModule,
        name: &str,
        generic: bool,
    ) -> FunctionHandleIndex {
        let name_idx = push_identifier(m, name);
        let empty_sig = push_signature(m, vec![]);
        let idx = FunctionHandleIndex(u16::try_from(m.function_handles.len()).unwrap());
        let type_parameters = if generic {
            vec![AbilitySet::EMPTY]
        } else {
            vec![]
        };
        m.function_handles.push(FunctionHandle {
            module: ModuleHandleIndex(0),
            name: name_idx,
            parameters: empty_sig,
            return_: empty_sig,
            type_parameters,
        });
        idx
    }

    fn push_function_inst(
        m: &mut AdamantCompiledModule,
        handle: FunctionHandleIndex,
    ) -> FunctionInstantiationIndex {
        let type_args = push_signature(m, vec![SignatureToken::U64]);
        let idx =
            FunctionInstantiationIndex(u16::try_from(m.function_instantiations.len()).unwrap());
        m.function_instantiations.push(FunctionInstantiation {
            handle,
            type_parameters: type_args,
        });
        idx
    }

    fn push_field_handle(
        m: &mut AdamantCompiledModule,
        owner: StructDefinitionIndex,
    ) -> FieldHandleIndex {
        let idx = FieldHandleIndex(u16::try_from(m.field_handles.len()).unwrap());
        m.field_handles.push(FieldHandle { owner, field: 0 });
        idx
    }

    fn push_field_inst(
        m: &mut AdamantCompiledModule,
        handle: FieldHandleIndex,
    ) -> FieldInstantiationIndex {
        let type_args = push_signature(m, vec![SignatureToken::U64]);
        let idx = FieldInstantiationIndex(u16::try_from(m.field_instantiations.len()).unwrap());
        m.field_instantiations.push(FieldInstantiation {
            handle,
            type_parameters: type_args,
        });
        idx
    }

    /// Push a function definition with the given body. Uses
    /// the function-handle named `f_main` (created here).
    fn push_main_function(m: &mut AdamantCompiledModule, body: Vec<BytecodeInstruction>) {
        let handle = push_function_handle(m, "f_main", false);
        let empty_sig = SignatureIndex(0);
        m.function_defs.push(AdamantFunctionDefinition {
            function: handle,
            visibility: adamant_bytecode_format::Visibility::Private,
            is_entry: false,
            acquires_global_resources: vec![],
            code: Some(AdamantCodeUnit {
                locals: empty_sig,
                code: body,
                jump_tables: vec![],
            }),
        });
    }

    /// Wrap an inherited Bytecode in a `BytecodeInstruction`.
    fn inh(bc: Bytecode) -> BytecodeInstruction {
        BytecodeInstruction::Inherited(bc)
    }

    // ===================================================================
    // Layer A — positives
    // ===================================================================

    #[test]
    fn empty_module_passes() {
        let m = empty_module();
        assert!(verify(&m).is_ok());
    }

    #[test]
    fn pack_on_non_generic_struct_passes() {
        let mut m = empty_module();
        let h = push_datatype_handle(&mut m, "S", false);
        let s = push_struct_def(&mut m, h);
        // Push f_main last so the function-handle naming doesn't
        // collide with the struct-handle creation order.
        push_main_function(&mut m, vec![inh(Bytecode::Pack(s)), inh(Bytecode::Ret)]);
        assert!(verify(&m).is_ok());
    }

    #[test]
    fn pack_generic_on_generic_struct_passes() {
        let mut m = empty_module();
        let h = push_datatype_handle(&mut m, "S", true);
        let s = push_struct_def(&mut m, h);
        let inst = push_struct_def_inst(&mut m, s);
        push_main_function(
            &mut m,
            vec![inh(Bytecode::PackGeneric(inst)), inh(Bytecode::Ret)],
        );
        assert!(verify(&m).is_ok());
    }

    #[test]
    fn call_on_non_generic_function_passes() {
        let mut m = empty_module();
        let target = push_function_handle(&mut m, "g", false);
        push_main_function(
            &mut m,
            vec![inh(Bytecode::Call(target)), inh(Bytecode::Ret)],
        );
        assert!(verify(&m).is_ok());
    }

    #[test]
    fn call_generic_on_generic_function_passes() {
        let mut m = empty_module();
        let target = push_function_handle(&mut m, "g", true);
        let inst = push_function_inst(&mut m, target);
        push_main_function(
            &mut m,
            vec![inh(Bytecode::CallGeneric(inst)), inh(Bytecode::Ret)],
        );
        assert!(verify(&m).is_ok());
    }

    #[test]
    fn pack_variant_on_non_generic_enum_passes() {
        let mut m = empty_module();
        let h = push_datatype_handle(&mut m, "E", false);
        let e = push_enum_def(&mut m, h);
        let v = push_variant_handle(&mut m, e);
        push_main_function(
            &mut m,
            vec![inh(Bytecode::PackVariant(v)), inh(Bytecode::Ret)],
        );
        assert!(verify(&m).is_ok());
    }

    #[test]
    fn pack_variant_generic_on_generic_enum_passes() {
        let mut m = empty_module();
        let h = push_datatype_handle(&mut m, "E", true);
        let e = push_enum_def(&mut m, h);
        let einst = push_enum_def_inst(&mut m, e);
        let vi = push_variant_inst_handle(&mut m, einst);
        push_main_function(
            &mut m,
            vec![inh(Bytecode::PackVariantGeneric(vi)), inh(Bytecode::Ret)],
        );
        assert!(verify(&m).is_ok());
    }

    #[test]
    fn vec_pack_within_bound_passes() {
        let mut m = empty_module();
        let sig = push_signature(&mut m, vec![SignatureToken::U64]);
        push_main_function(
            &mut m,
            vec![inh(Bytecode::VecPack(sig, 100)), inh(Bytecode::Ret)],
        );
        assert!(verify(&m).is_ok());
    }

    #[test]
    fn function_with_no_body_skipped() {
        // `code: None` is a native function; the pass skips
        // it (matches upstream). The Rule 4 pass would reject
        // it, but this pass does not.
        let mut m = empty_module();
        let handle = push_function_handle(&mut m, "n", false);
        m.function_defs.push(AdamantFunctionDefinition {
            function: handle,
            visibility: adamant_bytecode_format::Visibility::Private,
            is_entry: false,
            acquires_global_resources: vec![],
            code: None,
        });
        assert!(verify(&m).is_ok());
    }

    // ===================================================================
    // Layer A — negatives
    // ===================================================================

    fn assert_mismatch_at(m: &AdamantCompiledModule, expected_fn_def: u16, expected_offset: u16) {
        match verify(m) {
            Err(AdamantValidationError::GenericMemberOpcodeMismatch {
                fn_def_idx,
                code_offset,
            }) => {
                assert_eq!(fn_def_idx.0, expected_fn_def);
                assert_eq!(code_offset, expected_offset);
            }
            other => panic!(
                "expected GenericMemberOpcodeMismatch at fn={expected_fn_def} \
                 offset={expected_offset}, got {other:?}"
            ),
        }
    }

    #[test]
    fn rejects_pack_on_generic_struct() {
        let mut m = empty_module();
        let h = push_datatype_handle(&mut m, "S", true);
        let s = push_struct_def(&mut m, h);
        push_main_function(&mut m, vec![inh(Bytecode::Pack(s)), inh(Bytecode::Ret)]);
        assert_mismatch_at(&m, 0, 0);
    }

    #[test]
    fn rejects_pack_generic_on_non_generic_struct() {
        let mut m = empty_module();
        let h = push_datatype_handle(&mut m, "S", false);
        let s = push_struct_def(&mut m, h);
        let inst = push_struct_def_inst(&mut m, s);
        push_main_function(
            &mut m,
            vec![inh(Bytecode::PackGeneric(inst)), inh(Bytecode::Ret)],
        );
        assert_mismatch_at(&m, 0, 0);
    }

    #[test]
    fn rejects_call_on_generic_function() {
        let mut m = empty_module();
        let target = push_function_handle(&mut m, "g", true);
        push_main_function(
            &mut m,
            vec![inh(Bytecode::Call(target)), inh(Bytecode::Ret)],
        );
        assert_mismatch_at(&m, 0, 0);
    }

    #[test]
    fn rejects_call_generic_on_non_generic_function() {
        let mut m = empty_module();
        let target = push_function_handle(&mut m, "g", false);
        let inst = push_function_inst(&mut m, target);
        push_main_function(
            &mut m,
            vec![inh(Bytecode::CallGeneric(inst)), inh(Bytecode::Ret)],
        );
        assert_mismatch_at(&m, 0, 0);
    }

    #[test]
    fn rejects_mut_borrow_field_on_generic_struct() {
        let mut m = empty_module();
        let h = push_datatype_handle(&mut m, "S", true);
        let s = push_struct_def(&mut m, h);
        let fh = push_field_handle(&mut m, s);
        push_main_function(
            &mut m,
            vec![inh(Bytecode::MutBorrowField(fh)), inh(Bytecode::Ret)],
        );
        assert_mismatch_at(&m, 0, 0);
    }

    #[test]
    fn rejects_mut_borrow_field_generic_on_non_generic_struct() {
        let mut m = empty_module();
        let h = push_datatype_handle(&mut m, "S", false);
        let s = push_struct_def(&mut m, h);
        let fh = push_field_handle(&mut m, s);
        let fhi = push_field_inst(&mut m, fh);
        push_main_function(
            &mut m,
            vec![
                inh(Bytecode::MutBorrowFieldGeneric(fhi)),
                inh(Bytecode::Ret),
            ],
        );
        assert_mismatch_at(&m, 0, 0);
    }

    #[test]
    fn rejects_pack_variant_on_generic_enum() {
        let mut m = empty_module();
        let h = push_datatype_handle(&mut m, "E", true);
        let e = push_enum_def(&mut m, h);
        let v = push_variant_handle(&mut m, e);
        push_main_function(
            &mut m,
            vec![inh(Bytecode::PackVariant(v)), inh(Bytecode::Ret)],
        );
        assert_mismatch_at(&m, 0, 0);
    }

    #[test]
    fn rejects_pack_variant_generic_on_non_generic_enum() {
        let mut m = empty_module();
        let h = push_datatype_handle(&mut m, "E", false);
        let e = push_enum_def(&mut m, h);
        let einst = push_enum_def_inst(&mut m, e);
        let vi = push_variant_inst_handle(&mut m, einst);
        push_main_function(
            &mut m,
            vec![inh(Bytecode::PackVariantGeneric(vi)), inh(Bytecode::Ret)],
        );
        assert_mismatch_at(&m, 0, 0);
    }

    #[test]
    fn rejects_vec_pack_above_u16_max() {
        let mut m = empty_module();
        let sig = push_signature(&mut m, vec![SignatureToken::U64]);
        let n = u64::from(u16::MAX) + 1;
        push_main_function(
            &mut m,
            vec![inh(Bytecode::VecPack(sig, n)), inh(Bytecode::Ret)],
        );
        match verify(&m) {
            Err(AdamantValidationError::VecPackUnpackArgOutOfRange {
                fn_def_idx,
                code_offset,
                num,
            }) => {
                assert_eq!(fn_def_idx.0, 0);
                assert_eq!(code_offset, 0);
                assert_eq!(num, n);
            }
            other => panic!("expected VecPackUnpackArgOutOfRange, got {other:?}"),
        }
    }

    #[test]
    fn rejects_vec_unpack_above_u16_max() {
        let mut m = empty_module();
        let sig = push_signature(&mut m, vec![SignatureToken::U64]);
        let n = u64::from(u16::MAX) + 1;
        push_main_function(
            &mut m,
            vec![inh(Bytecode::VecUnpack(sig, n)), inh(Bytecode::Ret)],
        );
        assert!(matches!(
            verify(&m),
            Err(AdamantValidationError::VecPackUnpackArgOutOfRange { num, .. }) if num == n
        ));
    }

    #[test]
    fn vec_pack_at_u16_max_passes() {
        // Boundary: u16::MAX itself is allowed; only counts
        // strictly greater than u16::MAX are rejected.
        let mut m = empty_module();
        let sig = push_signature(&mut m, vec![SignatureToken::U64]);
        push_main_function(
            &mut m,
            vec![
                inh(Bytecode::VecPack(sig, u64::from(u16::MAX))),
                inh(Bytecode::Ret),
            ],
        );
        assert!(verify(&m).is_ok());
    }

    // ===================================================================
    // Layer A — eager-error precedence + extension passthrough
    // ===================================================================

    #[test]
    fn first_function_offset_wins_eager_error() {
        // Function 0: passes. Function 1: violates at offset 1.
        // Eager-error reports function 1, offset 1.
        let mut m = empty_module();
        let h_target = push_function_handle(&mut m, "g_ok", false);
        // Function 0: just calls the OK target.
        push_main_function(
            &mut m,
            vec![inh(Bytecode::Call(h_target)), inh(Bytecode::Ret)],
        );
        // Function 1: a Pop then a bad Pack.
        let h_generic = push_datatype_handle(&mut m, "S", true);
        let s_generic = push_struct_def(&mut m, h_generic);
        let h_main_2 = push_function_handle(&mut m, "f_main2", false);
        let empty_sig = SignatureIndex(0);
        m.function_defs.push(AdamantFunctionDefinition {
            function: h_main_2,
            visibility: adamant_bytecode_format::Visibility::Private,
            is_entry: false,
            acquires_global_resources: vec![],
            code: Some(AdamantCodeUnit {
                locals: empty_sig,
                code: vec![
                    inh(Bytecode::Nop),
                    inh(Bytecode::Pack(s_generic)),
                    inh(Bytecode::Ret),
                ],
                jump_tables: vec![],
            }),
        });
        assert_mismatch_at(&m, 1, 1);
    }

    #[test]
    fn adamant_extension_traverses_without_flagging() {
        // Sha3_256 is an Adamant extension per §6.2.1.4 (no
        // operand, no flavor pair). The pass should pass over
        // it without flagging.
        let mut m = empty_module();
        push_main_function(
            &mut m,
            vec![
                BytecodeInstruction::Adamant(crate::bytecode::AdamantBytecode::Sha3_256),
                inh(Bytecode::Ret),
            ],
        );
        assert!(verify(&m).is_ok());
    }

    // ===================================================================
    // Layer B — cross-validation against vendored Sui
    // ===================================================================

    fn cross_validate_pass(m: &AdamantCompiledModule) {
        let adamant_result = verify(m);
        let sui_module = m
            .to_sui_module()
            .expect("test fixture has no Adamant extensions; to_sui_module must succeed");
        let sui_config = move_vm_config::verifier::VerifierConfig::default();
        let sui_result =
            move_bytecode_verifier::instruction_consistency::InstructionConsistency::verify_module(
                &sui_config,
                &sui_module,
            );
        assert_pass_parity("instruction_consistency", adamant_result, sui_result);
    }

    #[test]
    fn cross_validation_accepts_pack_on_non_generic_struct() {
        let mut m = empty_module();
        let h = push_datatype_handle(&mut m, "S", false);
        let s = push_struct_def(&mut m, h);
        push_main_function(&mut m, vec![inh(Bytecode::Pack(s)), inh(Bytecode::Ret)]);
        cross_validate_pass(&m);
    }

    #[test]
    fn cross_validation_accepts_pack_generic_on_generic_struct() {
        let mut m = empty_module();
        let h = push_datatype_handle(&mut m, "S", true);
        let s = push_struct_def(&mut m, h);
        let inst = push_struct_def_inst(&mut m, s);
        push_main_function(
            &mut m,
            vec![inh(Bytecode::PackGeneric(inst)), inh(Bytecode::Ret)],
        );
        cross_validate_pass(&m);
    }

    #[test]
    fn cross_validation_rejects_pack_on_generic_struct() {
        let mut m = empty_module();
        let h = push_datatype_handle(&mut m, "S", true);
        let s = push_struct_def(&mut m, h);
        push_main_function(&mut m, vec![inh(Bytecode::Pack(s)), inh(Bytecode::Ret)]);
        cross_validate_pass(&m);
    }

    #[test]
    fn cross_validation_rejects_pack_generic_on_non_generic_struct() {
        let mut m = empty_module();
        let h = push_datatype_handle(&mut m, "S", false);
        let s = push_struct_def(&mut m, h);
        let inst = push_struct_def_inst(&mut m, s);
        push_main_function(
            &mut m,
            vec![inh(Bytecode::PackGeneric(inst)), inh(Bytecode::Ret)],
        );
        cross_validate_pass(&m);
    }

    #[test]
    fn cross_validation_accepts_call_on_non_generic_function() {
        let mut m = empty_module();
        let target = push_function_handle(&mut m, "g", false);
        push_main_function(
            &mut m,
            vec![inh(Bytecode::Call(target)), inh(Bytecode::Ret)],
        );
        cross_validate_pass(&m);
    }

    #[test]
    fn cross_validation_rejects_call_on_generic_function() {
        let mut m = empty_module();
        let target = push_function_handle(&mut m, "g", true);
        push_main_function(
            &mut m,
            vec![inh(Bytecode::Call(target)), inh(Bytecode::Ret)],
        );
        cross_validate_pass(&m);
    }

    #[test]
    fn cross_validation_rejects_vec_pack_above_u16_max() {
        let mut m = empty_module();
        let sig = push_signature(&mut m, vec![SignatureToken::U64]);
        let n = u64::from(u16::MAX) + 1;
        push_main_function(
            &mut m,
            vec![inh(Bytecode::VecPack(sig, n)), inh(Bytecode::Ret)],
        );
        cross_validate_pass(&m);
    }

    #[test]
    fn cross_validation_accepts_vec_pack_within_bound() {
        let mut m = empty_module();
        let sig = push_signature(&mut m, vec![SignatureToken::U64]);
        push_main_function(
            &mut m,
            vec![inh(Bytecode::VecPack(sig, 100)), inh(Bytecode::Ret)],
        );
        cross_validate_pass(&m);
    }
}
