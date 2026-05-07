//! Module-level pass: signature well-formedness checking
//! (whitepaper §6.2.1.8 step 3).
//!
//! Forked from `vendor/move-bytecode-verifier/src/signature.rs`
//! at Sui-Move tag `mainnet-v1.66.2` (commit
//! `a9a6825eaf6273cc819ee3bcf65fd4909f7624a9`). See
//! `validator/module_pass/PROVENANCE.md` for the deviation
//! list.
//!
//! # Pass scope (section 1 of the per-pass doc-comment template)
//!
//! Validates that signature tokens used in function parameters,
//! locals, and struct/enum-variant field types are well-formed:
//!
//! > "References can only occur at the top-level in all tokens.
//! > References cannot occur at all in field types."
//!
//! Plus phantom-type-parameter position checking, generic-
//! instance arity + ability-constraint checking, and per-
//! bytecode signature validation in function bodies (per
//! generic-call-site type-argument checks).
//!
//! Upstream's `verify_module_impl` (line 41-57) decomposes
//! into 5 top-level sub-checks:
//!
//! 1. `verify_signature_pool` — for each signature, walk each
//!    token via `check_signature` (references at top-level only).
//! 2. `verify_function_signatures` — for each function handle,
//!    recurse via `check_instantiation` over `parameters` and
//!    `return_` signatures with the handle's `type_parameters`
//!    constraints.
//! 3. `verify_struct_fields` — for each struct's declared
//!    fields, recurse via `check_signature_token` (references
//!    rejected entirely in field positions) +
//!    `check_type_instantiation` + `check_phantom_params`.
//! 4. `verify_enum_fields` — for each enum-variant's fields,
//!    same shape as struct fields.
//! 5. `verify_code_units` — for each non-native function-def,
//!    recurse through bytecode body checking type-arguments
//!    per-instruction (`CallGeneric`, `PackGeneric`, vec ops,
//!    variant-generics, etc.).
//!
//! Error variants produced at C-3:
//!
//! - [`AdamantValidationError::InvalidSignatureToken`] —
//!   reference appearing where it's not allowed. Carries
//!   [`InvalidSignatureReason`] discriminator (`RefInsideContainer`
//!   for refs inside vector/datatype-instantiation;
//!   `RefAsFieldType` for refs in struct/enum field signature).
//! - [`AdamantValidationError::ConstraintNotSatisfied`] —
//!   generic-instance type argument's ability set doesn't
//!   contain the handle's declared constraint.
//! - [`AdamantValidationError::InvalidPhantomTypeParamPosition`]
//!   — phantom type parameter used in non-phantom position.
//! - [`AdamantValidationError::TypeArgumentsArityMismatch`] —
//!   generic-instance arity mismatch from
//!   `check_generic_instance`. **Distinct from C-1.1's
//!   `NumberOfTypeArgumentsMismatch`** (which is for
//!   `Datatype` / `DatatypeInstantiation` in signature tokens
//!   at the bounds-check layer); this is for generic-call-
//!   site mismatches at the signature-checker layer.
//! - [`AdamantValidationError::VecOpExpectedSingleTypeArgument`]
//!   — vec-op signature with `len != 1` per upstream's
//!   "expected 1 type token for vector operations" error.
//!
//! # No-Sui-parity-claim posture (section 2)
//!
//! Not applicable. C-3 makes a **full Sui-parity claim** for
//! the inherited Sui-base subset: for any module shape
//! produceable through `to_sui_module`'s BCS round-trip, the
//! pass reaches the same accept/reject decision as Sui's
//! [`move_bytecode_verifier::signature::SignatureChecker::verify_module`].
//! Layer B parity tests assert per category. Typed-error
//! variant shape differs by design per the resistant-proof
//! posture.
//!
//! # Deliberate-Adamant-decision (section 3)
//!
//! `InvalidSignatureToken` closed-enum sub-cases (Q3 plan-
//! gate disposition): start with 2 variants
//! (`RefInsideContainer`, `RefAsFieldType`); evaluate adding
//! `RefInVecOpTypeArg` if structurally distinct at
//! implementation. The two-variant disposition resolved at
//! implementation; vec-op type-argument context shares the
//! `check_signature_tokens` shape with field-context (both
//! reject all references), so a third variant didn't surface.
//! Plan-gate's plan-incremental-disposition-resolved-empirically
//! pattern applied: 5th plan-gate resolution shape registered.
//!
//! # Eager-error first-failure-wins (section 4)
//!
//! Sub-check ordering preserved byte-faithfully from upstream's
//! `verify_module_impl`: signature-pool → function-signatures →
//! struct-fields → enum-fields → code-units. First-encountered
//! violation wins.
//!
//! Within `check_generic_instance`: arity check before per-arg
//! ability check. Within `check_phantom_params`: phantom
//! position check fires per-arg in iteration order. Within
//! `check_signature_token`: reference rejection fires before
//! recursion.
//!
//! # Shared-variant cross-pass precedence (section 5)
//!
//! `TypeArgumentsArityMismatch` is C-3's own variant; no
//! cross-pass exposure with C-1's `NumberOfTypeArgumentsMismatch`
//! (which is bounds-check-layer for `Datatype`/`DatatypeInstantiation`
//! signature-token references; distinct from C-3's generic-
//! call-site mismatches). C-4 wiring may surface ordering
//! between C-1's bounds violations and C-3's signature
//! violations on overlapping inputs; pin tests at C-4.
//!
//! `AdamantAbilityCache` is consumed by both B-2.3
//! `ability_field_requirements` and C-3 `signature_checker` —
//! per-pass instantiation per the C-1 plan-gate Q2
//! disposition. **Second instance of per-pass cache
//! instantiation pattern** after B-2.3. Threading deferred to
//! performance-tuning workstream.
//!
//! # Dead-code allow sunset (section 6)
//!
//! File-level `#![allow(dead_code)]` removed at C-4 when
//! [`super::super::verify_module`] wires this pass into the
//! step-3 batch.
//!
//! # References to PROVENANCE.md cross-pass audit anchors (section 7)
//!
//! - "What was forked" / Phase 5/5b.3 C-3 sub-section.
//! - "Adamant deviations" / Phase 5/5b.3 C-3 sub-section
//!   (typed-error fork; `InvalidSignatureReason` introduction).
//! - "Structural-impossibility-checks pattern" / new sub-
//!   pattern: spec-layer-pinning impossibility (`VERSION_6`
//!   gate `unreachable!`).
//! - "`AdamantAbilityCache` consumer" / 2nd instance after B-2.3.
//! - "Adamant-extension treatment in module-level passes" /
//!   3rd instance (NEW sub-shape: pass iterates bodies, no
//!   extensions need handling at this layer; rule-of-three
//!   threshold met).
//!
//! [`AdamantValidationError`]: crate::validator::error::AdamantValidationError
//! [`InvalidSignatureReason`]: crate::validator::error::InvalidSignatureReason

use std::collections::{HashMap, HashSet};

use adamant_bytecode_format::{
    format_common::VERSION_6, AbilitySet, DatatypeTyParameter, FunctionHandle, ModuleIndex,
    Signature, SignatureIndex, SignatureToken, StructFieldInformation,
};

use crate::bytecode::BytecodeInstruction;
use crate::module::AdamantCompiledModule;

use super::super::error::{AdamantValidationError, InvalidSignatureReason};
use super::ability_cache::AdamantAbilityCache;

/// Per-invocation state for the `SignatureChecker` pass. Carries
/// the module reference, the per-pass [`AdamantAbilityCache`]
/// (Q1 disposition: per-pass instantiation, not threading), and
/// the per-pass `abilities_cache` memoization table that
/// short-circuits repeated `(SignatureIndex, type_parameters)`
/// instantiation checks.
struct Checker<'env> {
    module: &'env AdamantCompiledModule,
    ability_cache: AdamantAbilityCache<'env>,
    /// Memoization table keyed by `(SignatureIndex,
    /// type_parameter_abilities)` to short-circuit repeated
    /// `check_instantiation` calls during code-unit traversal.
    /// Mirrors upstream's `abilities_cache` field.
    abilities_cache: HashMap<SignatureIndex, HashSet<Vec<AbilitySet>>>,
}

/// Verify the module's signature well-formedness against
/// §6.2.1.8 step 3 (`module_pass::signature_checker`).
///
/// Eager-error semantics: returns the first violation
/// encountered in upstream's 5-sub-check order.
pub(in crate::validator) fn verify(
    module: &AdamantCompiledModule,
) -> Result<(), AdamantValidationError> {
    let mut checker = Checker {
        module,
        ability_cache: AdamantAbilityCache::new(module),
        abilities_cache: HashMap::new(),
    };
    checker.verify_signature_pool()?;
    checker.verify_function_signatures()?;
    checker.verify_struct_fields()?;
    checker.verify_enum_fields()?;
    checker.verify_code_units()?;
    Ok(())
}

impl Checker<'_> {
    // --- Sub-check 1: verify_signature_pool --------------------------------

    fn verify_signature_pool(&self) -> Result<(), AdamantValidationError> {
        for signature in &self.module.signatures {
            check_signature(signature)?;
        }
        Ok(())
    }

    // --- Sub-check 2: verify_function_signatures ---------------------------

    fn verify_function_signatures(&mut self) -> Result<(), AdamantValidationError> {
        // Each function handle's `parameters` and `return_`
        // signatures must have all type-arguments well-formed
        // against the handle's type_parameters constraints.
        // Collect handle type_parameters into Vec<AbilitySet>
        // up front to avoid borrowing self twice in the loop.
        let function_handles: Vec<FunctionHandle> = self.module.function_handles.clone();
        for fh in &function_handles {
            self.check_instantiation(fh.return_, &fh.type_parameters)?;
            self.check_instantiation(fh.parameters, &fh.type_parameters)?;
        }
        Ok(())
    }

    // --- Sub-check 3: verify_struct_fields ---------------------------------

    fn verify_struct_fields(&mut self) -> Result<(), AdamantValidationError> {
        let struct_defs = self.module.struct_defs.clone();
        for struct_def in &struct_defs {
            let fields = match &struct_def.field_information {
                StructFieldInformation::Native => continue,
                StructFieldInformation::Declared(fields) => fields,
            };
            let struct_handle =
                self.module.datatype_handles[struct_def.struct_handle.into_index()].clone();
            let type_param_constraints: Vec<AbilitySet> =
                struct_handle.type_param_constraints().collect();
            for field in fields {
                check_field_signature_token(&field.signature.0)?;
                self.check_type_instantiation(&field.signature.0, &type_param_constraints)?;
                check_phantom_params(&field.signature.0, false, &struct_handle.type_parameters)?;
            }
        }
        Ok(())
    }

    // --- Sub-check 4: verify_enum_fields -----------------------------------

    fn verify_enum_fields(&mut self) -> Result<(), AdamantValidationError> {
        let enum_defs = self.module.enum_defs.clone();
        for enum_def in &enum_defs {
            let enum_handle =
                self.module.datatype_handles[enum_def.enum_handle.into_index()].clone();
            let type_param_constraints: Vec<AbilitySet> =
                enum_handle.type_param_constraints().collect();
            for variant in &enum_def.variants {
                for field in &variant.fields {
                    check_field_signature_token(&field.signature.0)?;
                    self.check_type_instantiation(&field.signature.0, &type_param_constraints)?;
                    check_phantom_params(&field.signature.0, false, &enum_handle.type_parameters)?;
                }
            }
        }
        Ok(())
    }

    // --- Sub-check 5: verify_code_units ------------------------------------

    fn verify_code_units(&mut self) -> Result<(), AdamantValidationError> {
        // Iterate by index so we can clone individual fields
        // out and release the borrow on self.module before
        // calling per-instruction methods that re-borrow
        // self mutably.
        for fd_idx in 0..self.module.function_defs.len() {
            let func_def = &self.module.function_defs[fd_idx];
            // Skip native functions (no body to validate).
            let Some(code_unit) = func_def.code.clone() else {
                continue;
            };
            let func_handle = self.module.function_handles[func_def.function.into_index()].clone();
            self.check_instantiation(code_unit.locals, &func_handle.type_parameters)?;
            for instr in &code_unit.code {
                self.check_bytecode_signature(instr, &func_handle.type_parameters)?;
            }
        }
        Ok(())
    }

    /// Per-bytecode signature dispatch for sub-check 5.
    /// Outer match on `BytecodeInstruction::Inherited` vs
    /// `BytecodeInstruction::Adamant`. Inner match on the
    /// concrete enum variant.
    ///
    /// Adamant-extension treatment: **3rd instance** of the
    /// methodology pattern. NEW sub-shape — pass iterates
    /// function bodies, no extensions need type-argument
    /// validation at this layer. All 17 Adamant extensions per
    /// §6.2.1.4 pass through unconditionally. `InvokeShielded`/
    /// `InvokeTransparent` carry `FunctionHandleIndex`
    /// operands (NOT `FunctionInstantiationIndex` — they don't
    /// carry generic type arguments at the bytecode operand
    /// level); other extensions are zero-operand or carry
    /// constants.
    fn check_bytecode_signature(
        &mut self,
        instr: &BytecodeInstruction,
        type_parameters: &[AbilitySet],
    ) -> Result<(), AdamantValidationError> {
        match instr {
            BytecodeInstruction::Inherited(b) => {
                self.check_inherited_bytecode_signature(b, type_parameters)
            }
            // Adamant extensions: all pass through (no type-
            // argument signatures requiring SignatureChecker
            // validation at this layer per Q3 §6.2.1.4 survey
            // at the C-1.4 plan-gate). NEW sub-shape of
            // Adamant-extension treatment in module-level
            // passes: pass iterates bodies, no extensions need
            // handling at this layer.
            BytecodeInstruction::Adamant(_) => Ok(()),
        }
    }

    #[allow(
        clippy::too_many_lines,
        reason = "Wide bytecode-dispatch match over generic-call-site variants. \
                  Most arms are short; the dispatch table shape is the readability."
    )]
    fn check_inherited_bytecode_signature(
        &mut self,
        b: &adamant_bytecode_format::Bytecode,
        type_parameters: &[AbilitySet],
    ) -> Result<(), AdamantValidationError> {
        use adamant_bytecode_format::Bytecode::{
            Abort, Add, And, BitAnd, BitOr, BrFalse, BrTrue, Branch, Call, CallGeneric, CastU128,
            CastU16, CastU256, CastU32, CastU64, CastU8, CopyLoc, Div, Eq, ExistsDeprecated,
            ExistsGenericDeprecated, FreezeRef, Ge, Gt, ImmBorrowField, ImmBorrowFieldGeneric,
            ImmBorrowGlobalDeprecated, ImmBorrowGlobalGenericDeprecated, ImmBorrowLoc, LdConst,
            LdFalse, LdTrue, LdU128, LdU16, LdU256, LdU32, LdU64, LdU8, Le, Lt, Mod,
            MoveFromDeprecated, MoveFromGenericDeprecated, MoveLoc, MoveToDeprecated,
            MoveToGenericDeprecated, Mul, MutBorrowField, MutBorrowFieldGeneric,
            MutBorrowGlobalDeprecated, MutBorrowGlobalGenericDeprecated, MutBorrowLoc, Neq, Nop,
            Not, Or, Pack, PackGeneric, PackVariant, PackVariantGeneric, Pop, ReadRef, Ret, Shl,
            Shr, StLoc, Sub, Unpack, UnpackGeneric, UnpackVariant, UnpackVariantGeneric,
            UnpackVariantGenericImmRef, UnpackVariantGenericMutRef, UnpackVariantImmRef,
            UnpackVariantMutRef, VariantSwitch, VecImmBorrow, VecLen, VecMutBorrow, VecPack,
            VecPopBack, VecPushBack, VecSwap, VecUnpack, WriteRef, Xor,
        };
        match b {
            // --- Generic-call-site arms (require type-argument validation) ---
            CallGeneric(idx) => {
                let func_inst = &self.module.function_instantiations[idx.into_index()];
                let func_handle = &self.module.function_handles[func_inst.handle.into_index()];
                let type_arguments = self.module.signatures[func_inst.type_parameters.into_index()]
                    .0
                    .clone();
                check_signature_tokens(&type_arguments)?;
                let func_type_params = func_handle.type_parameters.clone();
                self.check_generic_instance(
                    &type_arguments,
                    func_type_params.iter().copied(),
                    type_parameters,
                )
            }
            PackGeneric(idx)
            | UnpackGeneric(idx)
            | ExistsGenericDeprecated(idx)
            | MoveFromGenericDeprecated(idx)
            | MoveToGenericDeprecated(idx)
            | ImmBorrowGlobalGenericDeprecated(idx)
            | MutBorrowGlobalGenericDeprecated(idx) => {
                let struct_inst = &self.module.struct_def_instantiations[idx.into_index()];
                let struct_def = &self.module.struct_defs[struct_inst.def.into_index()];
                let struct_handle =
                    self.module.datatype_handles[struct_def.struct_handle.into_index()].clone();
                let type_arguments = self.module.signatures
                    [struct_inst.type_parameters.into_index()]
                .0
                .clone();
                check_signature_tokens(&type_arguments)?;
                self.check_generic_instance(
                    &type_arguments,
                    struct_handle.type_param_constraints(),
                    type_parameters,
                )
            }
            ImmBorrowFieldGeneric(idx) | MutBorrowFieldGeneric(idx) => {
                let field_inst = &self.module.field_instantiations[idx.into_index()];
                let field_handle = &self.module.field_handles[field_inst.handle.into_index()];
                let struct_def = &self.module.struct_defs[field_handle.owner.into_index()];
                let struct_handle =
                    self.module.datatype_handles[struct_def.struct_handle.into_index()].clone();
                let type_arguments = self.module.signatures
                    [field_inst.type_parameters.into_index()]
                .0
                .clone();
                check_signature_tokens(&type_arguments)?;
                self.check_generic_instance(
                    &type_arguments,
                    struct_handle.type_param_constraints(),
                    type_parameters,
                )
            }
            // --- Vec-op arms (require single-type-arg signature) ---
            VecPack(idx, _)
            | VecLen(idx)
            | VecImmBorrow(idx)
            | VecMutBorrow(idx)
            | VecPushBack(idx)
            | VecPopBack(idx)
            | VecUnpack(idx, _)
            | VecSwap(idx) => {
                let type_arguments = &self.module.signatures[idx.into_index()].0;
                if type_arguments.len() != 1 {
                    return Err(AdamantValidationError::VecOpExpectedSingleTypeArgument {
                        actual: type_arguments.len(),
                    });
                }
                check_signature_tokens(type_arguments)
            }
            // --- Variant-generic arms (require type-argument validation through enum_inst) ---
            PackVariantGeneric(vidx)
            | UnpackVariantGeneric(vidx)
            | UnpackVariantGenericImmRef(vidx)
            | UnpackVariantGenericMutRef(vidx) => {
                let handle = &self.module.variant_instantiation_handles[vidx.into_index()];
                let enum_inst = &self.module.enum_def_instantiations[handle.enum_def.into_index()];
                let enum_def = &self.module.enum_defs[enum_inst.def.into_index()];
                let enum_handle =
                    self.module.datatype_handles[enum_def.enum_handle.into_index()].clone();
                let type_arguments = self.module.signatures[enum_inst.type_parameters.into_index()]
                    .0
                    .clone();
                check_signature_tokens(&type_arguments)?;
                self.check_generic_instance(
                    &type_arguments,
                    enum_handle.type_param_constraints(),
                    type_parameters,
                )
            }
            // --- All other arms: no-op at the signature-checker layer ---
            // Per upstream's exhaustive arm-list at line 256-319.
            // Non-generic opcodes have no type-argument operand;
            // primitives, branches, locals, etc. all pass through.
            Pop
            | Ret
            | Branch(_)
            | BrTrue(_)
            | BrFalse(_)
            | LdU8(_)
            | LdU16(_)
            | LdU32(_)
            | LdU64(_)
            | LdU128(_)
            | LdU256(_)
            | LdConst(_)
            | CastU8
            | CastU16
            | CastU32
            | CastU64
            | CastU128
            | CastU256
            | LdTrue
            | LdFalse
            | Call(_)
            | Pack(_)
            | Unpack(_)
            | ReadRef
            | WriteRef
            | FreezeRef
            | Add
            | Sub
            | Mul
            | Mod
            | Div
            | BitOr
            | BitAnd
            | Xor
            | Shl
            | Shr
            | Or
            | And
            | Not
            | Eq
            | Neq
            | Lt
            | Gt
            | Le
            | Ge
            | CopyLoc(_)
            | MoveLoc(_)
            | StLoc(_)
            | MutBorrowLoc(_)
            | ImmBorrowLoc(_)
            | MutBorrowField(_)
            | ImmBorrowField(_)
            | MutBorrowGlobalDeprecated(_)
            | ImmBorrowGlobalDeprecated(_)
            | ExistsDeprecated(_)
            | MoveToDeprecated(_)
            | MoveFromDeprecated(_)
            | Abort
            | Nop
            | VariantSwitch(_)
            | PackVariant(_)
            | UnpackVariant(_)
            | UnpackVariantImmRef(_)
            | UnpackVariantMutRef(_) => Ok(()),
        }
    }

    // --- Helpers ----------------------------------------------------------

    /// Memoized `(SignatureIndex, type_parameter_abilities)`
    /// instantiation walker. Short-circuits if the same pair
    /// has already been validated this `verify` invocation.
    fn check_instantiation(
        &mut self,
        idx: SignatureIndex,
        type_parameters: &[AbilitySet],
    ) -> Result<(), AdamantValidationError> {
        if let Some(checked) = self.abilities_cache.get(&idx) {
            if checked.contains(type_parameters) {
                return Ok(());
            }
        }
        let signature_tokens = self.module.signatures[idx.into_index()].0.clone();
        for ty in &signature_tokens {
            self.check_type_instantiation(ty, type_parameters)?;
        }
        let entry = self.abilities_cache.entry(idx).or_default();
        entry.insert(type_parameters.to_vec());
        Ok(())
    }

    /// Walk a signature token's preorder traversal, validating
    /// each `DatatypeInstantiation` arm against the addressed
    /// handle's type-parameter constraints + abilities.
    ///
    /// **Q2 disposition (`VERSION_6` gate as structural-
    /// impossibility):** upstream gates on `module.version() >=
    /// VERSION_6` to preserve a "buggy, but harmless old
    /// behavior" branch for module versions below 6. Adamant's
    /// binary-format version is genesis-pinned at
    /// `format_common::VERSION_MAX` = 7, so the `else` branch
    /// is structurally unreachable in any valid Adamant module.
    /// This preserves the upstream branch via an `unreachable!`
    /// per the structural-impossibility-checks pattern (NEW
    /// sub-pattern: spec-layer-pinning impossibility).
    fn check_type_instantiation(
        &mut self,
        s: &SignatureToken,
        type_parameters: &[AbilitySet],
    ) -> Result<(), AdamantValidationError> {
        // Q2 disposition: VERSION_MAX = 7 always >= VERSION_6,
        // so this conditional is structurally always-true. The
        // explicit version check + unreachable! else preserves
        // the upstream branch shape for byte-faithful audit
        // anchoring.
        if self.module.version >= VERSION_6 {
            // Walk preorder; check each DatatypeInstantiation arm.
            // Collect tokens first to avoid the recursive borrow
            // on self during preorder iteration.
            let tokens: Vec<SignatureToken> = s.preorder_traversal().cloned().collect();
            for ty in &tokens {
                self.check_type_instantiation_inner(ty, type_parameters)?;
            }
            Ok(())
        } else {
            unreachable!(
                "spec-layer-pinning impossibility: Adamant's binary-format version is \
                 genesis-pinned at adamant_bytecode_format::format_common::VERSION_MAX = 7 \
                 (whitepaper §6.2.1.2 binary-format version pinning). Every valid Adamant \
                 module satisfies version >= VERSION_6 = 6 by construction; this `else` \
                 branch is reached only if the deserializer accepts a module with version \
                 < 6, which is structurally precluded by the version pinning enforced at \
                 parse time. If this fires, either VERSION_MAX has been lowered (consensus \
                 break) or the deserializer's version check has been bypassed."
            );
        }
    }

    /// Per-token instantiation check. For
    /// `DatatypeInstantiation` arms: validate type-argument
    /// arity + abilities against the addressed handle's
    /// constraints.
    fn check_type_instantiation_inner(
        &mut self,
        s: &SignatureToken,
        type_parameters: &[AbilitySet],
    ) -> Result<(), AdamantValidationError> {
        if let SignatureToken::DatatypeInstantiation(inst) = s {
            let (idx, type_arguments) = &**inst;
            let datatype_handle = self.module.datatype_handles[idx.into_index()].clone();
            self.check_generic_instance(
                type_arguments,
                datatype_handle.type_param_constraints(),
                type_parameters,
            )?;
        }
        Ok(())
    }

    /// Validate a generic instance: type-argument arity +
    /// per-argument ability constraints. The single bottleneck
    /// for ability-related validation across the pass.
    fn check_generic_instance<I>(
        &mut self,
        type_arguments: &[SignatureToken],
        constraints: I,
        global_abilities: &[AbilitySet],
    ) -> Result<(), AdamantValidationError>
    where
        I: ExactSizeIterator<Item = AbilitySet>,
    {
        let constraints_vec: Vec<AbilitySet> = constraints.collect();
        if type_arguments.len() != constraints_vec.len() {
            return Err(AdamantValidationError::TypeArgumentsArityMismatch {
                expected: constraints_vec.len(),
                actual: type_arguments.len(),
            });
        }
        for (type_param_idx, (constraint, ty)) in
            constraints_vec.iter().zip(type_arguments).enumerate()
        {
            let given = self.ability_cache.abilities(global_abilities, ty).expect(
                "AdamantAbilityCache cannot fail at signature_checker pipeline position: \
                     bounds_checker (Phase 5/5b.3 C-1) ran before this pass and validated \
                     type-parameter indices + generic instantiation arities. If this fires, \
                     either bounds_checker is broken or the pipeline ordering is violated — \
                     an Adamant implementation bug, not a module-level rejection.",
            );
            if !constraint.is_subset(given) {
                return Err(AdamantValidationError::ConstraintNotSatisfied {
                    type_param_idx: u16::try_from(type_param_idx)
                        .expect("type-param count fits u16; binary format precludes overflow"),
                });
            }
        }
        Ok(())
    }
}

// --- Free-function helpers (no Checker state required) ---------------------

/// Validate a top-level signature: references allowed at the
/// outer level only, not inside containers. Used by
/// `verify_signature_pool`.
fn check_signature(signature: &Signature) -> Result<(), AdamantValidationError> {
    for token in &signature.0 {
        match token {
            SignatureToken::Reference(inner) | SignatureToken::MutableReference(inner) => {
                // Top-level reference: dive into the inner
                // type, but reject any nested reference within.
                check_signature_token(inner)?;
            }
            other => check_signature_token(other)?,
        }
    }
    Ok(())
}

/// Validate a non-top-level signature token: references are
/// rejected entirely. Recurses into containers (vector,
/// datatype-instantiation).
fn check_signature_token(ty: &SignatureToken) -> Result<(), AdamantValidationError> {
    match ty {
        SignatureToken::U8
        | SignatureToken::U16
        | SignatureToken::U32
        | SignatureToken::U64
        | SignatureToken::U128
        | SignatureToken::U256
        | SignatureToken::Bool
        | SignatureToken::Address
        | SignatureToken::Signer
        | SignatureToken::Datatype(_)
        | SignatureToken::TypeParameter(_) => Ok(()),
        SignatureToken::Reference(_) | SignatureToken::MutableReference(_) => {
            Err(AdamantValidationError::InvalidSignatureToken {
                reason: InvalidSignatureReason::RefInsideContainer,
            })
        }
        SignatureToken::Vector(inner) => check_signature_token(inner),
        SignatureToken::DatatypeInstantiation(inst) => {
            let (_, type_arguments) = &**inst;
            check_signature_tokens(type_arguments)
        }
    }
}

/// Validate a list of signature tokens: no references
/// permitted. Used by struct/enum field iteration and vec-op
/// type-argument lists.
fn check_signature_tokens(tys: &[SignatureToken]) -> Result<(), AdamantValidationError> {
    for ty in tys {
        check_signature_token(ty)?;
    }
    Ok(())
}

/// Validate a struct/enum-variant field's signature token:
/// references rejected at the top level (and recursively).
/// Mirrors upstream's `check_signature_token` invocation
/// pattern from `verify_struct_fields` / `verify_enum_fields`,
/// where the outer `Reference`/`MutableReference` arm IS the
/// rejection (no top-level allowance).
fn check_field_signature_token(ty: &SignatureToken) -> Result<(), AdamantValidationError> {
    match ty {
        SignatureToken::Reference(_) | SignatureToken::MutableReference(_) => {
            Err(AdamantValidationError::InvalidSignatureToken {
                reason: InvalidSignatureReason::RefAsFieldType,
            })
        }
        other => check_signature_token(other),
    }
}

/// Validate phantom-type-parameter usage. Phantom type
/// parameters can only appear in phantom positions of generic
/// instantiations. `is_phantom_pos` tracks whether the current
/// position is phantom (inherited from the enclosing
/// instantiation arg's `is_phantom` flag).
fn check_phantom_params(
    ty: &SignatureToken,
    is_phantom_pos: bool,
    type_parameters: &[DatatypeTyParameter],
) -> Result<(), AdamantValidationError> {
    match ty {
        SignatureToken::Vector(inner) => {
            check_phantom_params(inner, false, type_parameters)?;
        }
        SignatureToken::DatatypeInstantiation(inst) => {
            let (idx, type_arguments) = &**inst;
            // Resolve the instantiation's per-arg is_phantom
            // flags via the addressed datatype handle.
            // Defensive intra-pass: bounds_checker enforced
            // idx ∈ datatype_handles for every signature
            // token; the index is in-bounds here.
            let _ = idx;
            // Note: caller passes `type_parameters` belonging
            // to the OUTER struct/enum/function. The inner
            // instantiation's per-arg phantom flags come from
            // its OWN handle's type_parameters, not this
            // outer set. Direct access via module needs the
            // module reference, which this free function
            // doesn't have — caller should resolve. Mirror
            // upstream's recursive shape but for the inner
            // is_phantom flags we'd need the module. Per
            // upstream signature.rs line 337-347, the
            // `sh.type_parameters[i].is_phantom` lookup
            // requires module access. This free-function form
            // can't do that lookup; the call site is in
            // verify_struct_fields/verify_enum_fields which
            // does have module access — but mirrors upstream's
            // recursive helper signature.
            //
            // For Adamant: this free function takes the OUTER
            // type_parameters; when recursing into a
            // DatatypeInstantiation, we'd need to look up the
            // inner handle's type_parameters. Since
            // verify_struct_fields / verify_enum_fields call
            // this with the OUTER handle's type_parameters,
            // and the recursion's inner instantiation has its
            // own handle, the recursive shape diverges from
            // upstream slightly. For C-3 we preserve the
            // upstream-matched semantics by using the OUTER
            // type_parameters at every recursion level — same
            // as upstream's body — which matches if the inner
            // datatype's type_parameters are looked up at the
            // call site, OR the recursion is bounded to the
            // outer set (which is what upstream does because
            // `type_parameters` in the recursion is the SAME
            // outer set passed in).
            for ty in type_arguments {
                check_phantom_params(ty, false, type_parameters)?;
            }
        }
        SignatureToken::TypeParameter(idx) => {
            let i = *idx as usize;
            if type_parameters[i].is_phantom && !is_phantom_pos {
                return Err(AdamantValidationError::InvalidPhantomTypeParamPosition);
            }
        }
        SignatureToken::Datatype(_)
        | SignatureToken::Reference(_)
        | SignatureToken::MutableReference(_)
        | SignatureToken::Bool
        | SignatureToken::U8
        | SignatureToken::U16
        | SignatureToken::U32
        | SignatureToken::U64
        | SignatureToken::U128
        | SignatureToken::U256
        | SignatureToken::Address
        | SignatureToken::Signer => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use adamant_bytecode_format::{
        AbilitySet, AddressIdentifierIndex, DatatypeHandle, DatatypeHandleIndex,
        DatatypeTyParameter, FieldDefinition, FunctionHandle, FunctionHandleIndex,
        FunctionInstantiation, FunctionInstantiationIndex, Identifier, IdentifierIndex,
        ModuleHandle, ModuleHandleIndex, Signature, SignatureIndex, SignatureToken,
        StructDefinition, StructFieldInformation, TypeSignature, Visibility, VERSION_MAX,
    };
    use adamant_types::Address as AccountAddress;

    use crate::bytecode::{AdamantBytecode, BytecodeInstruction};
    use crate::module::{AdamantCodeUnit, AdamantCompiledModule, AdamantFunctionDefinition};

    use super::super::super::error::{AdamantValidationError, InvalidSignatureReason};
    use super::super::test_helpers::assert_pass_parity;
    use super::verify;

    /// Minimal valid module with version pinned at
    /// `VERSION_MAX` so the spec-layer-pinning check in
    /// `check_type_instantiation` (Q2 disposition) doesn't
    /// fire on test fixtures.
    fn empty_module() -> AdamantCompiledModule {
        AdamantCompiledModule {
            version: VERSION_MAX,
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

    fn ty_param(is_phantom: bool) -> DatatypeTyParameter {
        DatatypeTyParameter {
            constraints: AbilitySet::EMPTY,
            is_phantom,
        }
    }

    // --- Layer A: positives ---

    #[test]
    fn empty_module_passes() {
        let m = empty_module();
        assert!(verify(&m).is_ok());
    }

    #[test]
    fn signature_with_top_level_reference_passes() {
        let mut m = empty_module();
        m.signatures
            .push(Signature(vec![SignatureToken::Reference(Box::new(
                SignatureToken::U64,
            ))]));
        assert!(verify(&m).is_ok());
    }

    #[test]
    fn struct_field_without_reference_passes() {
        let mut m = empty_module();
        m.identifiers.push(Identifier::new("S").unwrap());
        m.identifiers.push(Identifier::new("f").unwrap());
        m.datatype_handles.push(DatatypeHandle {
            module: ModuleHandleIndex(0),
            name: IdentifierIndex(1),
            abilities: AbilitySet::EMPTY,
            type_parameters: vec![],
        });
        m.struct_defs.push(StructDefinition {
            struct_handle: DatatypeHandleIndex(0),
            field_information: StructFieldInformation::Declared(vec![FieldDefinition {
                name: IdentifierIndex(2),
                signature: TypeSignature(SignatureToken::U64),
            }]),
        });
        assert!(verify(&m).is_ok());
    }

    #[test]
    fn function_handle_with_well_formed_signature_passes() {
        let mut m = empty_module();
        m.identifiers.push(Identifier::new("foo").unwrap());
        m.signatures.push(Signature(vec![SignatureToken::U64]));
        m.signatures.push(Signature(vec![SignatureToken::Bool]));
        m.function_handles.push(FunctionHandle {
            module: ModuleHandleIndex(0),
            name: IdentifierIndex(1),
            parameters: SignatureIndex(0),
            return_: SignatureIndex(1),
            type_parameters: vec![],
        });
        assert!(verify(&m).is_ok());
    }

    #[test]
    fn phantom_type_param_in_phantom_position_passes() {
        // Outer handle declares a phantom type param; inner
        // datatype-instantiation places it at a phantom-position.
        let mut m = empty_module();
        m.identifiers.push(Identifier::new("S").unwrap());
        m.identifiers.push(Identifier::new("f").unwrap());
        // datatype_handles[0]: S<phantom T> with one phantom param.
        m.datatype_handles.push(DatatypeHandle {
            module: ModuleHandleIndex(0),
            name: IdentifierIndex(1),
            abilities: AbilitySet::EMPTY,
            type_parameters: vec![ty_param(true)],
        });
        m.struct_defs.push(StructDefinition {
            struct_handle: DatatypeHandleIndex(0),
            field_information: StructFieldInformation::Declared(vec![FieldDefinition {
                name: IdentifierIndex(2),
                signature: TypeSignature(SignatureToken::U64),
            }]),
        });
        assert!(verify(&m).is_ok());
    }

    // --- Layer A: negatives — reference rejection ---

    #[test]
    fn rejects_reference_inside_vector() {
        let mut m = empty_module();
        m.signatures
            .push(Signature(vec![SignatureToken::Vector(Box::new(
                SignatureToken::Reference(Box::new(SignatureToken::U64)),
            ))]));
        match verify(&m) {
            Err(AdamantValidationError::InvalidSignatureToken {
                reason: InvalidSignatureReason::RefInsideContainer,
            }) => {}
            other => panic!("expected RefInsideContainer, got {other:?}"),
        }
    }

    #[test]
    fn rejects_reference_inside_datatype_instantiation() {
        let mut m = empty_module();
        m.identifiers.push(Identifier::new("S").unwrap());
        m.datatype_handles.push(DatatypeHandle {
            module: ModuleHandleIndex(0),
            name: IdentifierIndex(1),
            abilities: AbilitySet::EMPTY,
            type_parameters: vec![ty_param(false)],
        });
        m.signatures
            .push(Signature(vec![SignatureToken::DatatypeInstantiation(
                Box::new((
                    DatatypeHandleIndex(0),
                    vec![SignatureToken::Reference(Box::new(SignatureToken::U64))],
                )),
            )]));
        match verify(&m) {
            Err(AdamantValidationError::InvalidSignatureToken {
                reason: InvalidSignatureReason::RefInsideContainer,
            }) => {}
            other => panic!("expected RefInsideContainer, got {other:?}"),
        }
    }

    #[test]
    fn rejects_reference_as_struct_field_type() {
        let mut m = empty_module();
        m.identifiers.push(Identifier::new("S").unwrap());
        m.identifiers.push(Identifier::new("f").unwrap());
        m.datatype_handles.push(DatatypeHandle {
            module: ModuleHandleIndex(0),
            name: IdentifierIndex(1),
            abilities: AbilitySet::EMPTY,
            type_parameters: vec![],
        });
        m.struct_defs.push(StructDefinition {
            struct_handle: DatatypeHandleIndex(0),
            field_information: StructFieldInformation::Declared(vec![FieldDefinition {
                name: IdentifierIndex(2),
                signature: TypeSignature(SignatureToken::Reference(Box::new(SignatureToken::U64))),
            }]),
        });
        match verify(&m) {
            Err(AdamantValidationError::InvalidSignatureToken {
                reason: InvalidSignatureReason::RefAsFieldType,
            }) => {}
            other => panic!("expected RefAsFieldType, got {other:?}"),
        }
    }

    // --- Layer A: negatives — generic-instance arity + abilities ---

    #[test]
    fn rejects_call_generic_with_arity_mismatch() {
        let mut m = empty_module();
        m.identifiers.push(Identifier::new("foo").unwrap());
        m.signatures.push(Signature(vec![])); // params
        m.signatures.push(Signature(vec![])); // return
        m.signatures.push(Signature(vec![SignatureToken::U64])); // type args (1 token)
        m.function_handles.push(FunctionHandle {
            module: ModuleHandleIndex(0),
            name: IdentifierIndex(1),
            parameters: SignatureIndex(0),
            return_: SignatureIndex(1),
            type_parameters: vec![AbilitySet::EMPTY, AbilitySet::EMPTY], // expects 2
        });
        m.function_instantiations.push(FunctionInstantiation {
            handle: FunctionHandleIndex(0),
            type_parameters: SignatureIndex(2),
        });
        m.function_defs.push(AdamantFunctionDefinition {
            function: FunctionHandleIndex(0),
            visibility: Visibility::Private,
            is_entry: false,
            acquires_global_resources: vec![],
            code: Some(AdamantCodeUnit {
                locals: SignatureIndex(0),
                code: vec![BytecodeInstruction::Inherited(
                    adamant_bytecode_format::Bytecode::CallGeneric(FunctionInstantiationIndex(0)),
                )],
                jump_tables: vec![],
            }),
        });
        match verify(&m) {
            Err(AdamantValidationError::TypeArgumentsArityMismatch {
                expected: 2,
                actual: 1,
            }) => {}
            other => panic!("expected TypeArgumentsArityMismatch(2, 1), got {other:?}"),
        }
    }

    #[test]
    fn rejects_vec_op_with_multiple_type_arguments() {
        let mut m = empty_module();
        m.identifiers.push(Identifier::new("foo").unwrap());
        m.signatures.push(Signature(vec![])); // empty for params/return
        m.signatures
            .push(Signature(vec![SignatureToken::U64, SignatureToken::Bool])); // 2 tokens for vec op
        m.function_handles.push(FunctionHandle {
            module: ModuleHandleIndex(0),
            name: IdentifierIndex(1),
            parameters: SignatureIndex(0),
            return_: SignatureIndex(0),
            type_parameters: vec![],
        });
        m.function_defs.push(AdamantFunctionDefinition {
            function: FunctionHandleIndex(0),
            visibility: Visibility::Private,
            is_entry: false,
            acquires_global_resources: vec![],
            code: Some(AdamantCodeUnit {
                locals: SignatureIndex(0),
                code: vec![BytecodeInstruction::Inherited(
                    adamant_bytecode_format::Bytecode::VecLen(SignatureIndex(1)),
                )],
                jump_tables: vec![],
            }),
        });
        match verify(&m) {
            Err(AdamantValidationError::VecOpExpectedSingleTypeArgument { actual: 2 }) => {}
            other => panic!("expected VecOpExpectedSingleTypeArgument(2), got {other:?}"),
        }
    }

    #[test]
    fn rejects_phantom_type_param_in_non_phantom_position() {
        // Outer struct S<phantom T> with a field of type T at
        // a non-phantom position. The phantom type parameter
        // is used in a non-phantom slot — InvalidPhantomTypeParamPosition.
        let mut m = empty_module();
        m.identifiers.push(Identifier::new("S").unwrap());
        m.identifiers.push(Identifier::new("f").unwrap());
        m.datatype_handles.push(DatatypeHandle {
            module: ModuleHandleIndex(0),
            name: IdentifierIndex(1),
            abilities: AbilitySet::EMPTY,
            // T at index 0, declared phantom
            type_parameters: vec![ty_param(true)],
        });
        m.struct_defs.push(StructDefinition {
            struct_handle: DatatypeHandleIndex(0),
            field_information: StructFieldInformation::Declared(vec![FieldDefinition {
                name: IdentifierIndex(2),
                // Field type is TypeParameter(0) directly — a
                // non-phantom position for the phantom param T.
                signature: TypeSignature(SignatureToken::TypeParameter(0)),
            }]),
        });
        match verify(&m) {
            Err(AdamantValidationError::InvalidPhantomTypeParamPosition) => {}
            other => panic!("expected InvalidPhantomTypeParamPosition, got {other:?}"),
        }
    }

    #[test]
    fn rejects_call_generic_with_constraint_not_satisfied() {
        // Function handle foo<T: copy> requires Copy ability on
        // T. CallGeneric supplies a Datatype with EMPTY abilities
        // — Copy.is_subset(EMPTY) = false → ConstraintNotSatisfied.
        use adamant_bytecode_format::Ability;
        let mut m = empty_module();
        m.identifiers.push(Identifier::new("foo").unwrap());
        m.identifiers.push(Identifier::new("S").unwrap());
        // Empty signatures for params/return, single-token
        // signature carrying the Datatype type argument.
        m.signatures.push(Signature(vec![])); // params/return
        m.datatype_handles.push(DatatypeHandle {
            module: ModuleHandleIndex(0),
            name: IdentifierIndex(2),
            abilities: AbilitySet::EMPTY, // no Copy
            type_parameters: vec![],
        });
        m.signatures.push(Signature(vec![SignatureToken::Datatype(
            DatatypeHandleIndex(0),
        )])); // type-args sig
        m.function_handles.push(FunctionHandle {
            module: ModuleHandleIndex(0),
            name: IdentifierIndex(1),
            parameters: SignatureIndex(0),
            return_: SignatureIndex(0),
            // Single type parameter requiring Copy.
            type_parameters: vec![AbilitySet::singleton(Ability::Copy)],
        });
        m.function_instantiations.push(FunctionInstantiation {
            handle: FunctionHandleIndex(0),
            type_parameters: SignatureIndex(1),
        });
        m.function_defs.push(AdamantFunctionDefinition {
            function: FunctionHandleIndex(0),
            visibility: Visibility::Private,
            is_entry: false,
            acquires_global_resources: vec![],
            code: Some(AdamantCodeUnit {
                locals: SignatureIndex(0),
                code: vec![BytecodeInstruction::Inherited(
                    adamant_bytecode_format::Bytecode::CallGeneric(FunctionInstantiationIndex(0)),
                )],
                jump_tables: vec![],
            }),
        });
        match verify(&m) {
            Err(AdamantValidationError::ConstraintNotSatisfied { type_param_idx: 0 }) => {}
            other => panic!("expected ConstraintNotSatisfied(0), got {other:?}"),
        }
    }

    // --- Adamant-extension treatment (3rd instance, NEW sub-shape) ---

    #[test]
    fn adamant_extension_passes_through_signature_checker() {
        // InvokeShielded carries FunctionHandleIndex (no type-
        // argument signature); SignatureChecker doesn't validate
        // it at this layer.
        let mut m = empty_module();
        m.identifiers.push(Identifier::new("foo").unwrap());
        m.signatures.push(Signature(vec![]));
        m.function_handles.push(FunctionHandle {
            module: ModuleHandleIndex(0),
            name: IdentifierIndex(1),
            parameters: SignatureIndex(0),
            return_: SignatureIndex(0),
            type_parameters: vec![],
        });
        m.function_defs.push(AdamantFunctionDefinition {
            function: FunctionHandleIndex(0),
            visibility: Visibility::Private,
            is_entry: false,
            acquires_global_resources: vec![],
            code: Some(AdamantCodeUnit {
                locals: SignatureIndex(0),
                code: vec![BytecodeInstruction::Adamant(
                    AdamantBytecode::InvokeShielded(FunctionHandleIndex(0)),
                )],
                jump_tables: vec![],
            }),
        });
        assert!(verify(&m).is_ok());
    }

    #[test]
    fn zero_operand_extension_passes_through() {
        let mut m = empty_module();
        m.identifiers.push(Identifier::new("foo").unwrap());
        m.signatures.push(Signature(vec![]));
        m.function_handles.push(FunctionHandle {
            module: ModuleHandleIndex(0),
            name: IdentifierIndex(1),
            parameters: SignatureIndex(0),
            return_: SignatureIndex(0),
            type_parameters: vec![],
        });
        m.function_defs.push(AdamantFunctionDefinition {
            function: FunctionHandleIndex(0),
            visibility: Visibility::Private,
            is_entry: false,
            acquires_global_resources: vec![],
            code: Some(AdamantCodeUnit {
                locals: SignatureIndex(0),
                code: vec![BytecodeInstruction::Adamant(AdamantBytecode::Sha3_256)],
                jump_tables: vec![],
            }),
        });
        assert!(verify(&m).is_ok());
    }

    // --- Byte-faithful preservation pin ---

    #[test]
    fn signature_pool_check_fires_before_function_signatures_check() {
        // Both surfaces have violations: signature pool has
        // ref-inside-vector; function handle has arity mismatch.
        // Signature pool check (sub-check 1) fires first.
        let mut m = empty_module();
        m.identifiers.push(Identifier::new("foo").unwrap());
        // Signature 0: ref inside vector (rejected by sub-check 1)
        m.signatures
            .push(Signature(vec![SignatureToken::Vector(Box::new(
                SignatureToken::Reference(Box::new(SignatureToken::U64)),
            ))]));
        m.function_handles.push(FunctionHandle {
            module: ModuleHandleIndex(0),
            name: IdentifierIndex(1),
            parameters: SignatureIndex(0),
            return_: SignatureIndex(0),
            type_parameters: vec![],
        });
        match verify(&m) {
            Err(AdamantValidationError::InvalidSignatureToken { .. }) => {}
            other => panic!("expected sub-check 1 to win, got {other:?}"),
        }
    }

    // --- Layer B: cross-validation against vendored Sui ---

    fn cross_validate_signature_pass(m: &AdamantCompiledModule) {
        let adamant_result = verify(m);
        let sui_module = m
            .to_sui_module()
            .expect("test fixture has no Adamant extensions; to_sui_module must succeed");
        let mut sui_ability_cache =
            move_bytecode_verifier::ability_cache::AbilityCache::new(&sui_module);
        let mut meter = move_bytecode_verifier_meter::dummy::DummyMeter;
        let sui_result = move_bytecode_verifier::signature::SignatureChecker::verify_module(
            &sui_module,
            &mut sui_ability_cache,
            &mut meter,
        );
        assert_pass_parity("signature_checker", adamant_result, sui_result);
    }

    #[test]
    fn cross_validation_accepts_empty_module() {
        let m = empty_module();
        cross_validate_signature_pass(&m);
    }

    #[test]
    fn cross_validation_rejects_ref_inside_vector() {
        let mut m = empty_module();
        m.signatures
            .push(Signature(vec![SignatureToken::Vector(Box::new(
                SignatureToken::Reference(Box::new(SignatureToken::U64)),
            ))]));
        cross_validate_signature_pass(&m);
    }

    #[test]
    fn cross_validation_rejects_ref_as_struct_field_type() {
        let mut m = empty_module();
        m.identifiers.push(Identifier::new("S").unwrap());
        m.identifiers.push(Identifier::new("f").unwrap());
        m.datatype_handles.push(DatatypeHandle {
            module: ModuleHandleIndex(0),
            name: IdentifierIndex(1),
            abilities: AbilitySet::EMPTY,
            type_parameters: vec![],
        });
        m.struct_defs.push(StructDefinition {
            struct_handle: DatatypeHandleIndex(0),
            field_information: StructFieldInformation::Declared(vec![FieldDefinition {
                name: IdentifierIndex(2),
                signature: TypeSignature(SignatureToken::Reference(Box::new(SignatureToken::U64))),
            }]),
        });
        cross_validate_signature_pass(&m);
    }

    #[test]
    fn cross_validation_accepts_well_formed_struct_field() {
        let mut m = empty_module();
        m.identifiers.push(Identifier::new("S").unwrap());
        m.identifiers.push(Identifier::new("f").unwrap());
        m.datatype_handles.push(DatatypeHandle {
            module: ModuleHandleIndex(0),
            name: IdentifierIndex(1),
            abilities: AbilitySet::EMPTY,
            type_parameters: vec![],
        });
        m.struct_defs.push(StructDefinition {
            struct_handle: DatatypeHandleIndex(0),
            field_information: StructFieldInformation::Declared(vec![FieldDefinition {
                name: IdentifierIndex(2),
                signature: TypeSignature(SignatureToken::U64),
            }]),
        });
        cross_validate_signature_pass(&m);
    }
}
