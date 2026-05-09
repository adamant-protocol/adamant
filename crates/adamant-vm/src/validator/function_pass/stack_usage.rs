//! Adamant-native operand-stack discipline pass (whitepaper
//! §6.2.1.8 step 4).
//!
//! Forked byte-faithfully from
//! `vendor/move-bytecode-verifier/src/stack_usage_verifier.rs`
//! at Sui-Move tag `mainnet-v1.66.2` (319 LOC upstream).
//! Verifies three properties per basic block in every function
//! body:
//!
//! 1. *Per-block balance.* Each block ends with the same stack
//!    depth as it started, with one Ret-terminated exception:
//!    a Ret-terminated block's pre-Ret depth must equal the
//!    function's return arity (Ret pops the return values,
//!    leaving net delta zero).
//! 2. *No mid-block underflow.* The running stack delta within
//!    a block must never go negative.
//! 3. *Per-block max push.* The accumulated push count within
//!    any single block must not exceed
//!    [`AdamantStructuralLimits::max_push_size`][max] (D-3
//!    ships `Some(10000)` as Bucket A — see
//!    `module_pass/PROVENANCE.md`).
//!
//! [max]: super::super::config::AdamantStructuralLimits
//!
//! # Per-extension stack-effect categorization
//!
//! Whitepaper §6.2.1.4 lines 408–423 specify the 17 Adamant
//! extensions' stack effects. The verbatim survey at the D-3
//! plan-gate (10th verification gate, fired in corrective mode)
//! partitioned them into four categories:
//!
//! - **Category A (static `(pop, push)` constants — 11):**
//!   `ReleaseSubViewKey` (1,1), `KzgCommit` (1,1), `KzgVerify`
//!   (3,1), `Sha3_256` (1,1), `Blake3` (1,1), `Ed25519Verify`
//!   (3,1), `MlDsaVerify65` (3,1), `BlsVerify` (3,1),
//!   `ChargeGas` (1,0), `RemainingGas` (0,1), `OutOfGas` (0,0).
//!   Hard-coded match arms verbatim from §6.2.1.4. (`OutOfGas`
//!   aborts the transaction at runtime per spec line 423;
//!   verifier-treatment is `(0, 0)`
//!   while runtime carries the abort binding.)
//! - **Category B (parametric in `FunctionHandle` — 2):**
//!   `InvokeShielded(FH)`, `InvokeTransparent(FH)`. Resolves
//!   `(param_count, return_count)` from
//!   `module.function_handles[idx]` — same shape as Sui's
//!   `Call`. Per §6.2.1.4 line 408: "Stack effect matches
//!   `Call`."
//! - **Category C (parametric, deferred to §7 — 2):**
//!   `GenerateProof(CircuitId)`, `VerifyProof(CircuitId)`.
//!   Per §6.2.1.4 lines 410–411: "the resolution and the
//!   input-type list are specified by section 7."
//!   **Verifier fails open with `(0, 0)`; runtime carries the
//!   stack-balance binding** — same shielding-vs-runtime
//!   pattern documented at CLAUDE.md "Open properties to
//!   track" item 2. Methodology footnote: deferred-to-§7
//!   (2nd instance, per-mechanism counting after C-1.4b).
//! - **Category D (parametric, deferred to §8.5 — 1):**
//!   `RecursiveVerify`. Per §6.2.1.4 line 415: "the recursive
//!   circuit's public-input arity is determined by the circuit
//!   signature specified in section 8.5." **Verifier fails
//!   open with `(0, 0)`; runtime carries the binding.**
//!   Methodology footnote: deferred-to-§8 (NEW 1st instance;
//!   distinct from deferred-to-§7 because §8.5 is structurally
//!   unrelated to §7's circuit-reference pool).
//!
//! # Adamant deviations
//!
//! - Operates on [`AdamantCompiledModule`] +
//!   [`AdamantControlFlowGraph`] (D-1a) directly rather than
//!   upstream's `FunctionContext` aggregator. Same shape
//!   rationale as D-1a / D-2.
//! - No metering surface (D-1a/D-1b/D-2 precedent).
//! - `max_value_stack_size` (per-instruction operand-stack
//!   bound) is **not** enforced here — it's a runtime concern
//!   per `module_pass/PROVENANCE.md` "Out-of-scope fields"
//!   carve-out, lives in the AVM runtime config in the Phase
//!   5/6.3 sub-arc per whitepaper §6.3.
//! - **Debug-only defensive guards on module-access lookups.**
//!   `instruction_effect`'s lookups into `module.function_handles`,
//!   `module.struct_defs`, and friends are guarded by
//!   `debug_assert!`s with three-anchor messages (per refinement
//!   1 at D-3 implementation-gate). Release builds elide the
//!   asserts at zero cost; debug builds catch direct-
//!   unvalidated-input callers that violate the cross-pass-
//!   pipeline-dependency precondition. 3rd sub-shape of
//!   structural-impossibility-checks pattern alongside
//!   [`super::cfg::AdamantControlFlowGraph::new`]'s
//!   `assert!`-with-three-anchor-message (D-1a) and
//!   `module_wire`'s `unreachable!` for deserializer-rejected
//!   deprecated arms (B-2.4).
//!
//! # Cross-pass-pipeline-dependency
//!
//! This pass relies on:
//!
//! - **Step 3** (`module_pass::bounds_checker`,
//!   `module_pass::signature_checker`,
//!   `module_pass::instruction_consistency`): function-handle
//!   indices, signature-pool indices, struct-def / variant-
//!   handle indices, and generic-vs-non-generic flavor
//!   agreement are validated. Per-instruction lookups in
//!   [`StackUsageVerifier::instruction_effect`] cannot panic
//!   in the validator's pipeline.
//! - **Step 4 D-2** (`function_pass::control_flow`): every
//!   function body has a non-empty CFG with reducible
//!   structure. D-3 iterates `cfg.blocks()` in the order D-2's
//!   CFG construction provides.
//!
//! Cross-pass-pipeline-dependency sub-pattern (registered at
//! C-5); D-3 instantiates without surfacing new sub-pattern
//! instances.

use adamant_bytecode_format::{
    Bytecode, CodeOffset, FunctionDefinitionIndex, FunctionHandleIndex, SignatureIndex,
    StructDefinitionIndex, StructFieldInformation, VariantHandle, VariantHandleIndex,
    VariantInstantiationHandleIndex,
};

use super::cfg::AdamantControlFlowGraph;
use crate::bytecode::{AdamantBytecode, BytecodeInstruction};
use crate::module::AdamantCompiledModule;
use crate::validator::config::AdamantStructuralLimits;
use crate::validator::error::AdamantValidationError;

/// Three-anchor message stem used by every `debug_assert!` on
/// module-access lookups. Inlined in each call site (not
/// extracted) so the panic location remains the actual lookup
/// site, not a helper.
const THREE_ANCHOR_STEM: &str = "bounds_checker invariant violated; should be unreachable in \
                                 pipeline; if this fires from direct-unvalidated-input caller, \
                                 caller violates the precondition";

/// Per-function operand-stack discipline verifier.
///
/// Mirrors upstream's `StackUsageVerifier` byte-faithfully:
/// constructed once per function body, caches the function's
/// return arity at construction so `Ret`'s instruction-effect
/// computation is constant-time.
pub(super) struct StackUsageVerifier<'a> {
    module: &'a AdamantCompiledModule,
    fn_def_idx: FunctionDefinitionIndex,
    code: &'a [BytecodeInstruction],
    /// Function's return arity, resolved once at construction
    /// from the function definition's `function` handle's
    /// `return_` signature.
    return_count: u64,
}

impl<'a> StackUsageVerifier<'a> {
    /// Verify operand-stack discipline for one function body.
    ///
    /// Resolves the function's return arity from its handle's
    /// `return_` signature, then iterates every basic block in
    /// the CFG and applies [`Self::verify_block`].
    pub(super) fn verify(
        config: &AdamantStructuralLimits,
        module: &'a AdamantCompiledModule,
        fn_def_idx: FunctionDefinitionIndex,
        code: &'a [BytecodeInstruction],
        cfg: &AdamantControlFlowGraph,
    ) -> Result<(), AdamantValidationError> {
        debug_assert!(
            (fn_def_idx.0 as usize) < module.function_defs.len(),
            "{THREE_ANCHOR_STEM}. fn_def_idx {} >= function_defs.len() {}",
            fn_def_idx.0,
            module.function_defs.len(),
        );
        let function_handle_idx = module.function_defs[fn_def_idx.0 as usize].function;
        let return_count =
            signature_len(module, return_signature_index(module, function_handle_idx));

        let verifier = Self {
            module,
            fn_def_idx,
            code,
            return_count,
        };

        for block_id in cfg.blocks() {
            verifier.verify_block(config, block_id, cfg)?;
        }
        Ok(())
    }

    /// Verify operand-stack discipline within a single basic
    /// block. Mirrors upstream's `verify_block` byte-faithfully.
    fn verify_block(
        &self,
        config: &AdamantStructuralLimits,
        block_id: CodeOffset,
        cfg: &AdamantControlFlowGraph,
    ) -> Result<(), AdamantValidationError> {
        let mut stack_size_increment: u64 = 0;
        let block_start = cfg.block_start(block_id);
        let mut overall_push: u64 = 0;
        let block_end = cfg.block_end(block_id);

        for i in block_start..=block_end {
            let (num_pops, num_pushes) = self.instruction_effect(&self.code[i as usize]);

            if let Some(new_pushes) = overall_push.checked_add(num_pushes) {
                overall_push = new_pushes;
            }
            if let Some(max_push_size) = config.max_push_size {
                if overall_push > max_push_size {
                    return Err(AdamantValidationError::StackPushOverflow {
                        fn_def_idx: self.fn_def_idx,
                        code_offset: block_start,
                    });
                }
            }

            if stack_size_increment < num_pops {
                return Err(AdamantValidationError::StackUnderflow {
                    fn_def_idx: self.fn_def_idx,
                    code_offset: block_start,
                });
            }
            stack_size_increment = stack_size_increment
                .checked_sub(num_pops)
                .expect("stack_size_increment >= num_pops checked above");
            stack_size_increment = stack_size_increment.checked_add(num_pushes).ok_or(
                AdamantValidationError::UnbalancedStackAtBlockEnd {
                    fn_def_idx: self.fn_def_idx,
                    code_offset: block_start,
                },
            )?;
        }

        if stack_size_increment == 0 {
            Ok(())
        } else {
            Err(AdamantValidationError::UnbalancedStackAtBlockEnd {
                fn_def_idx: self.fn_def_idx,
                code_offset: block_start,
            })
        }
    }

    /// Pop / push counts for a single instruction.
    ///
    /// Categories C + D (parametric, deferred to §7 / §8.5)
    /// fail open with `(0, 0)` per the Q1(a) plan-gate
    /// disposition. Module-access lookups for inherited Pack /
    /// Unpack / Call / etc. and Adamant Category B
    /// `InvokeShielded` / `InvokeTransparent` are guarded by
    /// `debug_assert!`s with the three-anchor message;
    /// release builds elide the asserts.
    fn instruction_effect(&self, instruction: &BytecodeInstruction) -> (u64, u64) {
        match instruction {
            BytecodeInstruction::Inherited(b) => self.inherited_instruction_effect(b),
            BytecodeInstruction::Adamant(a) => self.adamant_instruction_effect(a),
        }
    }

    // Naturally long: one match arm per `Bytecode` variant.
    // Splitting obscures the per-instruction audit anchor —
    // the long arm-list IS the spec-fidelity table for §6.2.1.4
    // (inherited subset). Same shape allowance as
    // `error.rs::Display`'s match.
    #[allow(
        clippy::too_many_lines,
        clippy::match_same_arms,
        reason = "byte-faithful per-instruction table mirroring upstream's \
                  `instruction_effect`; merging same-result arms would lose the \
                  per-instruction audit anchor against §6.2.1.4 / Sui's spec"
    )]
    fn inherited_instruction_effect(&self, instruction: &Bytecode) -> (u64, u64) {
        match instruction {
            // Pop, no push.
            Bytecode::Pop
            | Bytecode::BrTrue(_)
            | Bytecode::BrFalse(_)
            | Bytecode::StLoc(_)
            | Bytecode::Abort
            | Bytecode::VariantSwitch(_) => (1, 0),

            // Push, no pop.
            Bytecode::LdU8(_)
            | Bytecode::LdU16(_)
            | Bytecode::LdU32(_)
            | Bytecode::LdU64(_)
            | Bytecode::LdU128(_)
            | Bytecode::LdU256(_)
            | Bytecode::LdTrue
            | Bytecode::LdFalse
            | Bytecode::LdConst(_)
            | Bytecode::CopyLoc(_)
            | Bytecode::MoveLoc(_)
            | Bytecode::MutBorrowLoc(_)
            | Bytecode::ImmBorrowLoc(_) => (0, 1),

            // Pop and push once.
            Bytecode::Not
            | Bytecode::FreezeRef
            | Bytecode::ReadRef
            | Bytecode::ExistsDeprecated(_)
            | Bytecode::ExistsGenericDeprecated(_)
            | Bytecode::MutBorrowGlobalDeprecated(_)
            | Bytecode::MutBorrowGlobalGenericDeprecated(_)
            | Bytecode::ImmBorrowGlobalDeprecated(_)
            | Bytecode::ImmBorrowGlobalGenericDeprecated(_)
            | Bytecode::MutBorrowField(_)
            | Bytecode::MutBorrowFieldGeneric(_)
            | Bytecode::ImmBorrowField(_)
            | Bytecode::ImmBorrowFieldGeneric(_)
            | Bytecode::MoveFromDeprecated(_)
            | Bytecode::MoveFromGenericDeprecated(_)
            | Bytecode::CastU8
            | Bytecode::CastU16
            | Bytecode::CastU32
            | Bytecode::CastU64
            | Bytecode::CastU128
            | Bytecode::CastU256
            | Bytecode::VecLen(_)
            | Bytecode::VecPopBack(_) => (1, 1),

            // Binary operations: pop twice, push once.
            Bytecode::Add
            | Bytecode::Sub
            | Bytecode::Mul
            | Bytecode::Mod
            | Bytecode::Div
            | Bytecode::BitOr
            | Bytecode::BitAnd
            | Bytecode::Xor
            | Bytecode::Shl
            | Bytecode::Shr
            | Bytecode::Or
            | Bytecode::And
            | Bytecode::Eq
            | Bytecode::Neq
            | Bytecode::Lt
            | Bytecode::Gt
            | Bytecode::Le
            | Bytecode::Ge => (2, 1),

            // Vector pack / unpack: parametric in immediate.
            Bytecode::VecPack(_, num) => (*num, 1),
            Bytecode::VecUnpack(_, num) => (1, *num),

            // Vector indexing: pop twice, push once.
            Bytecode::VecImmBorrow(_) | Bytecode::VecMutBorrow(_) => (2, 1),

            // MoveTo / WriteRef / VecPushBack: pop twice, no push.
            Bytecode::MoveToDeprecated(_)
            | Bytecode::MoveToGenericDeprecated(_)
            | Bytecode::WriteRef
            | Bytecode::VecPushBack(_) => (2, 0),

            // VecSwap: pop three, no push.
            Bytecode::VecSwap(_) => (3, 0),

            // Branch / Nop: no stack effect.
            Bytecode::Branch(_) | Bytecode::Nop => (0, 0),

            // Ret pops `return_count` values.
            Bytecode::Ret => (self.return_count, 0),

            // Call / CallGeneric: parametric in FunctionHandle.
            Bytecode::Call(idx) => self.call_effect(*idx),
            Bytecode::CallGeneric(idx) => {
                debug_assert!(
                    (idx.0 as usize) < self.module.function_instantiations.len(),
                    "{THREE_ANCHOR_STEM}. FunctionInstantiationIndex {} >= function_instantiations.len() {}",
                    idx.0,
                    self.module.function_instantiations.len(),
                );
                let inst = &self.module.function_instantiations[idx.0 as usize];
                self.call_effect(inst.handle)
            }

            // Pack / Unpack: parametric in StructDefinition's
            // field count.
            Bytecode::Pack(idx) => (self.struct_field_count(*idx), 1),
            Bytecode::PackGeneric(idx) => {
                debug_assert!(
                    (idx.0 as usize) < self.module.struct_def_instantiations.len(),
                    "{THREE_ANCHOR_STEM}. StructDefInstantiationIndex {} >= struct_def_instantiations.len() {}",
                    idx.0,
                    self.module.struct_def_instantiations.len(),
                );
                let inst = &self.module.struct_def_instantiations[idx.0 as usize];
                (self.struct_field_count(inst.def), 1)
            }
            Bytecode::Unpack(idx) => (1, self.struct_field_count(*idx)),
            Bytecode::UnpackGeneric(idx) => {
                debug_assert!(
                    (idx.0 as usize) < self.module.struct_def_instantiations.len(),
                    "{THREE_ANCHOR_STEM}. StructDefInstantiationIndex {} >= struct_def_instantiations.len() {}",
                    idx.0,
                    self.module.struct_def_instantiations.len(),
                );
                let inst = &self.module.struct_def_instantiations[idx.0 as usize];
                (1, self.struct_field_count(inst.def))
            }

            // Variant pack: parametric in variant's field count.
            Bytecode::PackVariant(vidx) => (self.variant_field_count(*vidx), 1),
            Bytecode::PackVariantGeneric(vidx) => (self.variant_inst_field_count(*vidx), 1),

            // Variant unpack (and ref variants): one pop,
            // parametric pushes.
            Bytecode::UnpackVariant(vidx)
            | Bytecode::UnpackVariantImmRef(vidx)
            | Bytecode::UnpackVariantMutRef(vidx) => (1, self.variant_field_count(*vidx)),
            Bytecode::UnpackVariantGeneric(vidx)
            | Bytecode::UnpackVariantGenericImmRef(vidx)
            | Bytecode::UnpackVariantGenericMutRef(vidx) => {
                (1, self.variant_inst_field_count(*vidx))
            }
        }
    }

    // One arm per `AdamantBytecode` variant — the per-extension
    // spec-fidelity table for §6.2.1.4 lines 408-423. Same
    // byte-faithful audit-anchor allowance as
    // `inherited_instruction_effect`.
    #[allow(
        clippy::match_same_arms,
        reason = "byte-faithful per-extension table mirroring §6.2.1.4 lines 408-423; \
                  merging same-result arms would lose the per-extension audit anchor"
    )]
    fn adamant_instruction_effect(&self, instruction: &AdamantBytecode) -> (u64, u64) {
        match instruction {
            // Category B: parametric in FunctionHandle (same
            // shape as Call per §6.2.1.4 line 408).
            AdamantBytecode::InvokeShielded(idx) | AdamantBytecode::InvokeTransparent(idx) => {
                self.call_effect(*idx)
            }

            // Category C: parametric, deferred to §7. Verifier
            // fails open with (0, 0); runtime carries the
            // stack-balance binding.
            AdamantBytecode::GenerateProof(_) | AdamantBytecode::VerifyProof(_) => (0, 0),

            // Category D: parametric, deferred to §8.5.
            // Verifier fails open with (0, 0); runtime carries
            // the binding.
            AdamantBytecode::RecursiveVerify => (0, 0),

            // Category A static (pop, push) constants per
            // §6.2.1.4 verbatim.
            AdamantBytecode::ReleaseSubViewKey => (1, 1),
            AdamantBytecode::KzgCommit => (1, 1),
            AdamantBytecode::KzgVerify => (3, 1),
            AdamantBytecode::Sha3_256 => (1, 1),
            AdamantBytecode::Blake3 => (1, 1),
            AdamantBytecode::Ed25519Verify => (3, 1),
            AdamantBytecode::MlDsaVerify65 => (3, 1),
            AdamantBytecode::BlsVerify => (3, 1),
            AdamantBytecode::ChargeGas(_) => (1, 0),
            AdamantBytecode::RemainingGas(_) => (0, 1),
            // OutOfGas aborts at runtime per spec line 423;
            // verifier-treatment is (0, 0). Runtime carries
            // the abort binding (verifier sees an instruction
            // with no stack effect; runtime aborts before
            // execution falls through).
            AdamantBytecode::OutOfGas => (0, 0),
        }
    }

    /// Stack effect for a `Call` / `CallGeneric` /
    /// `InvokeShielded` / `InvokeTransparent`: pops one value
    /// per parameter, pushes one per return.
    fn call_effect(&self, idx: FunctionHandleIndex) -> (u64, u64) {
        debug_assert!(
            (idx.0 as usize) < self.module.function_handles.len(),
            "{THREE_ANCHOR_STEM}. FunctionHandleIndex {} >= function_handles.len() {}",
            idx.0,
            self.module.function_handles.len(),
        );
        let handle = &self.module.function_handles[idx.0 as usize];
        let arg_count = signature_len(self.module, handle.parameters);
        let return_count = signature_len(self.module, handle.return_);
        (arg_count, return_count)
    }

    fn struct_field_count(&self, idx: StructDefinitionIndex) -> u64 {
        debug_assert!(
            (idx.0 as usize) < self.module.struct_defs.len(),
            "{THREE_ANCHOR_STEM}. StructDefinitionIndex {} >= struct_defs.len() {}",
            idx.0,
            self.module.struct_defs.len(),
        );
        let struct_def = &self.module.struct_defs[idx.0 as usize];
        match &struct_def.field_information {
            // 'Native' is a Move-internal marker that should
            // never appear on a deployed Adamant struct (§6.2.1.6
            // Rule 4 forbids natives at the function level;
            // Adamant's struct-field-information layer treats
            // Native as an upstream-format vestige). Mirror
            // upstream's treatment (count = 0); the actual
            // rejection happens elsewhere in the verifier.
            StructFieldInformation::Native => 0,
            StructFieldInformation::Declared(fields) => fields.len() as u64,
        }
    }

    fn variant_field_count(&self, vidx: VariantHandleIndex) -> u64 {
        debug_assert!(
            (vidx.0 as usize) < self.module.variant_handles.len(),
            "{THREE_ANCHOR_STEM}. VariantHandleIndex {} >= variant_handles.len() {}",
            vidx.0,
            self.module.variant_handles.len(),
        );
        let handle: &VariantHandle = &self.module.variant_handles[vidx.0 as usize];
        debug_assert!(
            (handle.enum_def.0 as usize) < self.module.enum_defs.len(),
            "{THREE_ANCHOR_STEM}. EnumDefinitionIndex {} >= enum_defs.len() {}",
            handle.enum_def.0,
            self.module.enum_defs.len(),
        );
        let enum_def = &self.module.enum_defs[handle.enum_def.0 as usize];
        debug_assert!(
            (handle.variant as usize) < enum_def.variants.len(),
            "{THREE_ANCHOR_STEM}. variant tag {} >= enum's variant count {}",
            handle.variant,
            enum_def.variants.len(),
        );
        enum_def.variants[handle.variant as usize].fields.len() as u64
    }

    fn variant_inst_field_count(&self, vidx: VariantInstantiationHandleIndex) -> u64 {
        debug_assert!(
            (vidx.0 as usize) < self.module.variant_instantiation_handles.len(),
            "{THREE_ANCHOR_STEM}. VariantInstantiationHandleIndex {} >= variant_instantiation_handles.len() {}",
            vidx.0,
            self.module.variant_instantiation_handles.len(),
        );
        let handle = &self.module.variant_instantiation_handles[vidx.0 as usize];
        debug_assert!(
            (handle.enum_def.0 as usize) < self.module.enum_def_instantiations.len(),
            "{THREE_ANCHOR_STEM}. EnumDefInstantiationIndex {} >= enum_def_instantiations.len() {}",
            handle.enum_def.0,
            self.module.enum_def_instantiations.len(),
        );
        let inst = &self.module.enum_def_instantiations[handle.enum_def.0 as usize];
        debug_assert!(
            (inst.def.0 as usize) < self.module.enum_defs.len(),
            "{THREE_ANCHOR_STEM}. EnumDefinitionIndex {} >= enum_defs.len() {}",
            inst.def.0,
            self.module.enum_defs.len(),
        );
        let enum_def = &self.module.enum_defs[inst.def.0 as usize];
        debug_assert!(
            (handle.variant as usize) < enum_def.variants.len(),
            "{THREE_ANCHOR_STEM}. variant tag {} >= enum's variant count {}",
            handle.variant,
            enum_def.variants.len(),
        );
        enum_def.variants[handle.variant as usize].fields.len() as u64
    }
}

fn signature_len(module: &AdamantCompiledModule, idx: SignatureIndex) -> u64 {
    debug_assert!(
        (idx.0 as usize) < module.signatures.len(),
        "{THREE_ANCHOR_STEM}. SignatureIndex {} >= signatures.len() {}",
        idx.0,
        module.signatures.len(),
    );
    module.signatures[idx.0 as usize].len() as u64
}

fn return_signature_index(
    module: &AdamantCompiledModule,
    handle_idx: FunctionHandleIndex,
) -> SignatureIndex {
    debug_assert!(
        (handle_idx.0 as usize) < module.function_handles.len(),
        "{THREE_ANCHOR_STEM}. FunctionHandleIndex {} >= function_handles.len() {}",
        handle_idx.0,
        module.function_handles.len(),
    );
    module.function_handles[handle_idx.0 as usize].return_
}

#[cfg(test)]
mod tests {
    //! Layer A unit tests for the operand-stack discipline pass.
    //! Covers per-extension static effects (Category A — 12),
    //! parametric-FH effects (Category B — 2), deferred-to-§7/§8
    //! fail-open (Categories C + D — 3), per-block-balance
    //! happy paths and rejections, `max_push_size` gating,
    //! inherited-bytecode shape pins, and eager-error semantics.

    use super::*;
    use crate::bytecode::{AdamantBytecode, BytecodeInstruction, GasDimension};
    use crate::module::{AdamantCodeUnit, AdamantCompiledModule, AdamantFunctionDefinition};
    use adamant_bytecode_format::{
        Bytecode, FunctionHandle, IdentifierIndex, ModuleHandleIndex, Signature, Visibility,
    };

    // --- builders ---

    fn ld_true() -> BytecodeInstruction {
        BytecodeInstruction::Inherited(Bytecode::LdTrue)
    }

    fn ld_u64(v: u64) -> BytecodeInstruction {
        BytecodeInstruction::Inherited(Bytecode::LdU64(v))
    }

    fn pop() -> BytecodeInstruction {
        BytecodeInstruction::Inherited(Bytecode::Pop)
    }

    fn ret() -> BytecodeInstruction {
        BytecodeInstruction::Inherited(Bytecode::Ret)
    }

    fn nop() -> BytecodeInstruction {
        BytecodeInstruction::Inherited(Bytecode::Nop)
    }

    fn add() -> BytecodeInstruction {
        BytecodeInstruction::Inherited(Bytecode::Add)
    }

    /// A module shape with a single function definition whose
    /// signature has the given parameter / return arities and
    /// whose body is `body`. Pushes a parameter signature, a
    /// return signature, the function handle, and the function
    /// definition.
    fn module_with_body(
        param_count: usize,
        return_count: usize,
        body: Vec<BytecodeInstruction>,
    ) -> AdamantCompiledModule {
        use adamant_bytecode_format::{
            AddressIdentifierIndex, Identifier, ModuleHandle, SignatureToken,
        };
        let mut m = AdamantCompiledModule::default();
        // self-handle so module_handles[0] is valid.
        m.module_handles.push(ModuleHandle {
            address: AddressIdentifierIndex(0),
            name: IdentifierIndex(0),
        });
        // empty + parameter + return signatures.
        m.signatures.push(Signature(vec![])); // SignatureIndex(0): empty (locals)
        m.signatures
            .push(Signature(vec![SignatureToken::U64; param_count])); // 1: params
        m.signatures
            .push(Signature(vec![SignatureToken::U64; return_count])); // 2: returns
        m.function_handles.push(FunctionHandle {
            module: ModuleHandleIndex(0),
            name: IdentifierIndex(0),
            parameters: SignatureIndex(1),
            return_: SignatureIndex(2),
            type_parameters: vec![],
        });
        m.function_defs.push(AdamantFunctionDefinition {
            function: FunctionHandleIndex(0),
            visibility: Visibility::default(),
            is_entry: false,
            acquires_global_resources: vec![],
            code: Some(AdamantCodeUnit {
                locals: SignatureIndex(0),
                code: body,
                jump_tables: vec![],
            }),
        });
        m.identifiers.push(Identifier::new("f").unwrap());
        m
    }

    fn run(
        m: &AdamantCompiledModule,
        config: &AdamantStructuralLimits,
    ) -> Result<(), AdamantValidationError> {
        let function_definition = &m.function_defs[0];
        let code_unit = function_definition
            .code
            .as_ref()
            .expect("test fixture has body");
        let cfg = AdamantControlFlowGraph::new(&code_unit.code, &code_unit.jump_tables);
        StackUsageVerifier::verify(
            config,
            m,
            FunctionDefinitionIndex::new(0),
            &code_unit.code,
            &cfg,
        )
    }

    fn limits_with_max_push_size(s: Option<u64>) -> AdamantStructuralLimits {
        let mut l = AdamantStructuralLimits::genesis();
        l.max_push_size = s;
        l
    }

    fn extension(b: AdamantBytecode) -> BytecodeInstruction {
        BytecodeInstruction::Adamant(b)
    }

    // --- Category A static (per-extension pin) ---

    /// `ReleaseSubViewKey` pops one (parent view key) and pushes
    /// one (derived sub-key). Verbatim from §6.2.1.4 line 412.
    #[test]
    fn release_sub_view_key_pops_one_pushes_one() {
        // body: LdU64 + ReleaseSubViewKey (1 pop, 1 push) + Pop +
        // Ret with return arity 0. Net delta in block: 0.
        let m = module_with_body(
            0,
            0,
            vec![
                ld_u64(0),
                extension(AdamantBytecode::ReleaseSubViewKey),
                pop(),
                ret(),
            ],
        );
        run(&m, &AdamantStructuralLimits::genesis()).expect("balance OK");
    }

    #[test]
    fn kzg_commit_pops_one_pushes_one() {
        let m = module_with_body(
            0,
            0,
            vec![
                ld_u64(0),
                extension(AdamantBytecode::KzgCommit),
                pop(),
                ret(),
            ],
        );
        run(&m, &AdamantStructuralLimits::genesis()).expect("balance OK");
    }

    #[test]
    fn kzg_verify_pops_three_pushes_one() {
        let m = module_with_body(
            0,
            0,
            vec![
                ld_u64(0),
                ld_u64(0),
                ld_u64(0),
                extension(AdamantBytecode::KzgVerify),
                pop(),
                ret(),
            ],
        );
        run(&m, &AdamantStructuralLimits::genesis()).expect("balance OK");
    }

    #[test]
    fn sha3_256_pops_one_pushes_one() {
        let m = module_with_body(
            0,
            0,
            vec![
                ld_u64(0),
                extension(AdamantBytecode::Sha3_256),
                pop(),
                ret(),
            ],
        );
        run(&m, &AdamantStructuralLimits::genesis()).expect("balance OK");
    }

    #[test]
    fn blake3_pops_one_pushes_one() {
        let m = module_with_body(
            0,
            0,
            vec![ld_u64(0), extension(AdamantBytecode::Blake3), pop(), ret()],
        );
        run(&m, &AdamantStructuralLimits::genesis()).expect("balance OK");
    }

    #[test]
    fn ed25519_verify_pops_three_pushes_one() {
        let m = module_with_body(
            0,
            0,
            vec![
                ld_u64(0),
                ld_u64(0),
                ld_u64(0),
                extension(AdamantBytecode::Ed25519Verify),
                pop(),
                ret(),
            ],
        );
        run(&m, &AdamantStructuralLimits::genesis()).expect("balance OK");
    }

    #[test]
    fn ml_dsa_verify_65_pops_three_pushes_one() {
        let m = module_with_body(
            0,
            0,
            vec![
                ld_u64(0),
                ld_u64(0),
                ld_u64(0),
                extension(AdamantBytecode::MlDsaVerify65),
                pop(),
                ret(),
            ],
        );
        run(&m, &AdamantStructuralLimits::genesis()).expect("balance OK");
    }

    #[test]
    fn bls_verify_pops_three_pushes_one() {
        let m = module_with_body(
            0,
            0,
            vec![
                ld_u64(0),
                ld_u64(0),
                ld_u64(0),
                extension(AdamantBytecode::BlsVerify),
                pop(),
                ret(),
            ],
        );
        run(&m, &AdamantStructuralLimits::genesis()).expect("balance OK");
    }

    #[test]
    fn charge_gas_pops_one_pushes_zero() {
        let m = module_with_body(
            0,
            0,
            vec![
                ld_u64(100),
                extension(AdamantBytecode::ChargeGas(GasDimension::Computation)),
                ret(),
            ],
        );
        run(&m, &AdamantStructuralLimits::genesis()).expect("balance OK");
    }

    #[test]
    fn remaining_gas_pops_zero_pushes_one() {
        let m = module_with_body(
            0,
            0,
            vec![
                extension(AdamantBytecode::RemainingGas(GasDimension::Computation)),
                pop(),
                ret(),
            ],
        );
        run(&m, &AdamantStructuralLimits::genesis()).expect("balance OK");
    }

    /// `OutOfGas` aborts the transaction at runtime per
    /// §6.2.1.4 line 423: "abort the transaction with the
    /// out-of-gas error." Spec text does not mention pop or
    /// push. Verifier-treatment is `(0, 0)` per the D-3
    /// plan-gate disposition; runtime carries the abort
    /// binding (the instruction has no stack effect at the
    /// verifier layer; runtime aborts before execution falls
    /// through). Same shielding-vs-runtime canonical pattern
    /// as Categories C/D's deferred-to-§N footnotes — verifier
    /// accepts silently; semantic binding lives at runtime.
    /// NEW pattern sub-shape (abort-semantics-at-verifier vs
    /// abort-semantics-at-runtime); rule-of-three pending;
    /// canonical registration at D-7.
    #[test]
    fn out_of_gas_pops_zero_pushes_zero() {
        let m = module_with_body(0, 0, vec![extension(AdamantBytecode::OutOfGas), ret()]);
        run(&m, &AdamantStructuralLimits::genesis()).expect("verifier-treatment is (0, 0)");
    }

    // --- Category B parametric-FH ---

    /// `InvokeShielded` resolves param/return counts from the
    /// addressed function handle. Body pushes 2 values (matches
    /// param count), invokes the handle (pops 2, pushes 1 — its
    /// return), pops the return, Rets with arity 0.
    #[test]
    fn invoke_shielded_resolves_function_handle() {
        // We need a 2nd function handle (with 2 params, 1 return)
        // for the invoke target. The fixture's existing handle
        // is at index 0 with the test function's signature; add
        // a target handle at index 1.
        use adamant_bytecode_format::SignatureToken;
        let mut m = module_with_body(
            0,
            0,
            vec![
                ld_u64(0),
                ld_u64(0),
                extension(AdamantBytecode::InvokeShielded(FunctionHandleIndex(1))),
                pop(),
                ret(),
            ],
        );
        // Add target handle: 2 params, 1 return.
        m.signatures
            .push(Signature(vec![SignatureToken::U64, SignatureToken::U64])); // 3
        m.signatures.push(Signature(vec![SignatureToken::U64])); // 4
        m.function_handles.push(FunctionHandle {
            module: ModuleHandleIndex(0),
            name: IdentifierIndex(0),
            parameters: SignatureIndex(3),
            return_: SignatureIndex(4),
            type_parameters: vec![],
        });
        run(&m, &AdamantStructuralLimits::genesis()).expect("balance OK");
    }

    #[test]
    fn invoke_transparent_resolves_function_handle() {
        use adamant_bytecode_format::SignatureToken;
        let mut m = module_with_body(
            0,
            0,
            vec![
                ld_u64(0),
                ld_u64(0),
                extension(AdamantBytecode::InvokeTransparent(FunctionHandleIndex(1))),
                pop(),
                ret(),
            ],
        );
        m.signatures
            .push(Signature(vec![SignatureToken::U64, SignatureToken::U64]));
        m.signatures.push(Signature(vec![SignatureToken::U64]));
        m.function_handles.push(FunctionHandle {
            module: ModuleHandleIndex(0),
            name: IdentifierIndex(0),
            parameters: SignatureIndex(3),
            return_: SignatureIndex(4),
            type_parameters: vec![],
        });
        run(&m, &AdamantStructuralLimits::genesis()).expect("balance OK");
    }

    /// Zero-arity invoke: 0 params, 0 returns — pop=0, push=0.
    #[test]
    fn invoke_shielded_resolves_zero_arity() {
        let mut m = module_with_body(
            0,
            0,
            vec![
                extension(AdamantBytecode::InvokeShielded(FunctionHandleIndex(1))),
                ret(),
            ],
        );
        m.signatures.push(Signature(vec![])); // 3
        m.signatures.push(Signature(vec![])); // 4
        m.function_handles.push(FunctionHandle {
            module: ModuleHandleIndex(0),
            name: IdentifierIndex(0),
            parameters: SignatureIndex(3),
            return_: SignatureIndex(4),
            type_parameters: vec![],
        });
        run(&m, &AdamantStructuralLimits::genesis()).expect("balance OK");
    }

    // --- Categories C + D fail-open deferral ---

    /// `GenerateProof` fails open with `(0, 0)` at the verifier
    /// per Q1(a) — runtime carries the stack-balance binding
    /// per §6.2.1.4 line 410's deferral to §7.
    #[test]
    fn generate_proof_fails_open_at_verifier() {
        use crate::bytecode::CircuitId;
        let m = module_with_body(
            0,
            0,
            vec![
                extension(AdamantBytecode::GenerateProof(CircuitId(0))),
                ret(),
            ],
        );
        run(&m, &AdamantStructuralLimits::genesis()).expect("Category C fails open with (0, 0)");
    }

    #[test]
    fn verify_proof_fails_open_at_verifier() {
        use crate::bytecode::CircuitId;
        let m = module_with_body(
            0,
            0,
            vec![extension(AdamantBytecode::VerifyProof(CircuitId(0))), ret()],
        );
        run(&m, &AdamantStructuralLimits::genesis()).expect("Category C fails open with (0, 0)");
    }

    #[test]
    fn recursive_verify_fails_open_at_verifier() {
        let m = module_with_body(
            0,
            0,
            vec![extension(AdamantBytecode::RecursiveVerify), ret()],
        );
        run(&m, &AdamantStructuralLimits::genesis()).expect("Category D fails open with (0, 0)");
    }

    // --- per-block balance — happy ---

    #[test]
    fn single_ret_zero_return_balanced() {
        let m = module_with_body(0, 0, vec![ret()]);
        run(&m, &AdamantStructuralLimits::genesis()).expect("Ret with arity 0 OK");
    }

    #[test]
    fn ld_const_then_ret_one_return_balanced() {
        let m = module_with_body(0, 1, vec![ld_u64(42), ret()]);
        run(&m, &AdamantStructuralLimits::genesis()).expect("push 1, ret pops 1, balance OK");
    }

    #[test]
    fn binop_then_ret_balanced() {
        let m = module_with_body(0, 1, vec![ld_u64(1), ld_u64(2), add(), ret()]);
        run(&m, &AdamantStructuralLimits::genesis())
            .expect("push 2, add (2,1), ret pops 1, balance OK");
    }

    /// Conditional branch with per-block balance: each block
    /// ends at delta 0. The conditional pops its boolean, the
    /// fall-through is a no-op, and the join block Rets with
    /// arity 0 — no cross-block value flow. (If-else diamonds
    /// that flow values across arms must use locals via
    /// StLoc/MoveLoc per upstream's strict per-block-balance
    /// posture; that pattern is not exercised here.)
    #[test]
    fn conditional_branch_balanced() {
        // 0: LdTrue        push 1
        // 1: BrTrue 3      pop 1 → block 0 balanced
        // 2: Nop           fall-through arm, 0 → 0
        // 3: Ret           join, return arity 0
        let m = module_with_body(
            0,
            0,
            vec![
                ld_true(),
                BytecodeInstruction::Inherited(Bytecode::BrTrue(3)),
                nop(),
                ret(),
            ],
        );
        run(&m, &AdamantStructuralLimits::genesis()).expect("each block balances");
    }

    // --- per-block balance — rejections ---

    /// Function declares return arity 1 but body Rets without
    /// pushing — pre-Ret depth is 0 but Ret expects 1.
    #[test]
    fn ret_with_wrong_arity_rejected_unbalanced() {
        let m = module_with_body(0, 1, vec![ret()]);
        match run(&m, &AdamantStructuralLimits::genesis()) {
            Err(AdamantValidationError::StackUnderflow { .. }) => {}
            other => {
                panic!("expected StackUnderflow (Ret pops more than block has), got {other:?}")
            }
        }
    }

    #[test]
    fn block_ends_with_extra_push_rejected() {
        let m = module_with_body(0, 0, vec![ld_u64(1), ret()]);
        match run(&m, &AdamantStructuralLimits::genesis()) {
            Err(AdamantValidationError::UnbalancedStackAtBlockEnd { .. }) => {}
            other => panic!("expected UnbalancedStackAtBlockEnd, got {other:?}"),
        }
    }

    #[test]
    fn pop_with_empty_stack_rejected_underflow() {
        let m = module_with_body(0, 0, vec![pop(), ret()]);
        match run(&m, &AdamantStructuralLimits::genesis()) {
            Err(AdamantValidationError::StackUnderflow { .. }) => {}
            other => panic!("expected StackUnderflow, got {other:?}"),
        }
    }

    #[test]
    fn binop_with_one_operand_rejected_underflow() {
        let m = module_with_body(0, 1, vec![ld_u64(1), add(), ret()]);
        match run(&m, &AdamantStructuralLimits::genesis()) {
            Err(AdamantValidationError::StackUnderflow { .. }) => {}
            other => panic!("expected StackUnderflow, got {other:?}"),
        }
    }

    /// Block starting at branch target inherits zero entry
    /// depth (per upstream's per-block-balance posture); a
    /// branch-target block that pops an "incoming" value
    /// triggers underflow.
    #[test]
    fn unbalanced_at_branch_target_rejected() {
        // 0: LdTrue
        // 1: BrTrue 3
        // 2: Branch 3
        // 3: Pop          <- branch target; expects empty stack on entry
        // 4: Ret
        let m = module_with_body(
            0,
            0,
            vec![
                ld_true(),
                BytecodeInstruction::Inherited(Bytecode::BrTrue(3)),
                BytecodeInstruction::Inherited(Bytecode::Branch(3)),
                pop(),
                ret(),
            ],
        );
        match run(&m, &AdamantStructuralLimits::genesis()) {
            Err(AdamantValidationError::StackUnderflow { .. }) => {}
            other => panic!("expected StackUnderflow at branch-target block, got {other:?}"),
        }
    }

    // --- max_push_size gating ---

    #[test]
    fn max_push_size_at_limit_accepted() {
        // 3 pushes (LdU64 × 3), each 1 push; cleanup with Pops; max_push_size=3.
        let m = module_with_body(
            0,
            0,
            vec![ld_u64(1), ld_u64(2), ld_u64(3), pop(), pop(), pop(), ret()],
        );
        let limits = limits_with_max_push_size(Some(3));
        run(&m, &limits).expect("3 pushes at limit 3 accepts");
    }

    #[test]
    fn max_push_size_above_limit_rejected() {
        let m = module_with_body(
            0,
            0,
            vec![
                ld_u64(1),
                ld_u64(2),
                ld_u64(3),
                ld_u64(4),
                pop(),
                pop(),
                pop(),
                pop(),
                ret(),
            ],
        );
        let limits = limits_with_max_push_size(Some(3));
        match run(&m, &limits) {
            Err(AdamantValidationError::StackPushOverflow { .. }) => {}
            other => panic!("expected StackPushOverflow at 4th push, got {other:?}"),
        }
    }

    #[test]
    fn max_push_size_disabled_no_check() {
        let m = module_with_body(
            0,
            0,
            vec![
                ld_u64(1),
                ld_u64(2),
                ld_u64(3),
                ld_u64(4),
                ld_u64(5),
                pop(),
                pop(),
                pop(),
                pop(),
                pop(),
                ret(),
            ],
        );
        let limits = limits_with_max_push_size(None);
        run(&m, &limits).expect("None disables push-size check");
    }

    // --- inherited Bytecode shape pins ---

    #[test]
    fn pack_resolves_struct_field_count() {
        use adamant_bytecode_format::SignatureToken;
        use adamant_bytecode_format::{AbilitySet, DatatypeHandle};
        use adamant_bytecode_format::{FieldDefinition, StructDefinition};
        let mut m = module_with_body(
            0,
            0,
            vec![
                ld_u64(1),
                ld_u64(2),
                ld_u64(3),
                BytecodeInstruction::Inherited(Bytecode::Pack(StructDefinitionIndex(0))),
                pop(),
                ret(),
            ],
        );
        m.identifiers
            .push(adamant_bytecode_format::Identifier::new("S").unwrap());
        m.datatype_handles.push(DatatypeHandle {
            module: ModuleHandleIndex(0),
            name: IdentifierIndex(1),
            abilities: AbilitySet::EMPTY,
            type_parameters: vec![],
        });
        m.struct_defs.push(StructDefinition {
            struct_handle: adamant_bytecode_format::DatatypeHandleIndex(0),
            field_information: StructFieldInformation::Declared(vec![
                FieldDefinition {
                    name: IdentifierIndex(0),
                    signature: adamant_bytecode_format::TypeSignature(SignatureToken::U64),
                },
                FieldDefinition {
                    name: IdentifierIndex(0),
                    signature: adamant_bytecode_format::TypeSignature(SignatureToken::U64),
                },
                FieldDefinition {
                    name: IdentifierIndex(0),
                    signature: adamant_bytecode_format::TypeSignature(SignatureToken::U64),
                },
            ]),
        });
        run(&m, &AdamantStructuralLimits::genesis())
            .expect("Pack pops 3 fields and pushes 1 struct, balanced with cleanup");
    }

    #[test]
    fn unpack_resolves_struct_field_count() {
        use adamant_bytecode_format::SignatureToken;
        use adamant_bytecode_format::{AbilitySet, DatatypeHandle};
        use adamant_bytecode_format::{FieldDefinition, StructDefinition};
        let mut m = module_with_body(
            0,
            0,
            vec![
                ld_u64(1),
                ld_u64(2),
                BytecodeInstruction::Inherited(Bytecode::Pack(StructDefinitionIndex(0))),
                BytecodeInstruction::Inherited(Bytecode::Unpack(StructDefinitionIndex(0))),
                pop(),
                pop(),
                ret(),
            ],
        );
        m.identifiers
            .push(adamant_bytecode_format::Identifier::new("S").unwrap());
        m.datatype_handles.push(DatatypeHandle {
            module: ModuleHandleIndex(0),
            name: IdentifierIndex(1),
            abilities: AbilitySet::EMPTY,
            type_parameters: vec![],
        });
        m.struct_defs.push(StructDefinition {
            struct_handle: adamant_bytecode_format::DatatypeHandleIndex(0),
            field_information: StructFieldInformation::Declared(vec![
                FieldDefinition {
                    name: IdentifierIndex(0),
                    signature: adamant_bytecode_format::TypeSignature(SignatureToken::U64),
                },
                FieldDefinition {
                    name: IdentifierIndex(0),
                    signature: adamant_bytecode_format::TypeSignature(SignatureToken::U64),
                },
            ]),
        });
        run(&m, &AdamantStructuralLimits::genesis())
            .expect("Pack 2 + Unpack 2 + Pops + Ret balanced");
    }

    #[test]
    fn vec_pack_consumes_immediate_arity() {
        use adamant_bytecode_format::SignatureIndex as SI;
        // VecPack(_, num) pops `num` and pushes 1.
        let m = module_with_body(
            0,
            0,
            vec![
                ld_u64(1),
                ld_u64(2),
                ld_u64(3),
                BytecodeInstruction::Inherited(Bytecode::VecPack(SI(0), 3)),
                pop(),
                ret(),
            ],
        );
        // Need a non-empty signature pool entry for the vec
        // element type. Genesis-default signatures vec already
        // has SignatureIndex(0) as the locals signature; the
        // VecPack's SI(0) refers there. Bounds-checker would
        // accept this in real pipeline.
        run(&m, &AdamantStructuralLimits::genesis())
            .expect("VecPack with num=3 pops 3 and pushes 1");
    }

    #[test]
    fn call_resolves_function_handle() {
        use adamant_bytecode_format::SignatureToken;
        let mut m = module_with_body(
            0,
            0,
            vec![
                ld_u64(1),
                ld_u64(2),
                BytecodeInstruction::Inherited(Bytecode::Call(FunctionHandleIndex(1))),
                pop(),
                ret(),
            ],
        );
        m.signatures
            .push(Signature(vec![SignatureToken::U64, SignatureToken::U64]));
        m.signatures.push(Signature(vec![SignatureToken::U64]));
        m.function_handles.push(FunctionHandle {
            module: ModuleHandleIndex(0),
            name: IdentifierIndex(0),
            parameters: SignatureIndex(3),
            return_: SignatureIndex(4),
            type_parameters: vec![],
        });
        run(&m, &AdamantStructuralLimits::genesis())
            .expect("Call resolves params=2 returns=1 from FunctionHandle");
    }

    #[test]
    fn call_generic_resolves_function_instantiation() {
        use adamant_bytecode_format::FunctionInstantiation;
        use adamant_bytecode_format::FunctionInstantiationIndex;
        use adamant_bytecode_format::SignatureToken;
        let mut m = module_with_body(
            0,
            0,
            vec![
                ld_u64(1),
                ld_u64(2),
                BytecodeInstruction::Inherited(Bytecode::CallGeneric(FunctionInstantiationIndex(
                    0,
                ))),
                pop(),
                ret(),
            ],
        );
        m.signatures
            .push(Signature(vec![SignatureToken::U64, SignatureToken::U64]));
        m.signatures.push(Signature(vec![SignatureToken::U64]));
        m.function_handles.push(FunctionHandle {
            module: ModuleHandleIndex(0),
            name: IdentifierIndex(0),
            parameters: SignatureIndex(3),
            return_: SignatureIndex(4),
            type_parameters: vec![],
        });
        m.function_instantiations.push(FunctionInstantiation {
            handle: FunctionHandleIndex(1),
            type_parameters: SignatureIndex(0),
        });
        run(&m, &AdamantStructuralLimits::genesis())
            .expect("CallGeneric resolves through FunctionInstantiation -> FunctionHandle");
    }

    // --- eager-error semantics ---

    /// First failing instruction within the first block aborts
    /// the function-pass; later instructions don't mask earlier
    /// failures.
    #[test]
    fn first_block_failure_aborts_function_pass() {
        let m = module_with_body(0, 0, vec![pop(), ld_u64(1), pop(), ret()]);
        match run(&m, &AdamantStructuralLimits::genesis()) {
            Err(AdamantValidationError::StackUnderflow { .. }) => {}
            other => panic!("expected StackUnderflow on first Pop, got {other:?}"),
        }
    }

    // --- Layer B: cross-validation against vendored Sui ---
    //
    // Sui's per-pass entries (`StackUsageVerifier::verify`,
    // `locals_safety::verify`, `type_safety::verify`) are
    // `pub(crate)` — only the composite per-function entry
    // `code_unit_verifier::verify_module` is reachable from our
    // test code. Composite-pipeline parity is the right shape:
    // each fixture is curated to isolate stack_usage's behaviour
    // (well-formed at every other pass; triggers the rule under
    // test on both sides). Both pipelines run control_flow first
    // and stack_usage second; pure-stack-usage rejections fire
    // at stack_usage on both sides. Composite-level accept/
    // reject parity follows.
    //
    // Adamant extensions are excluded from Layer B by design (no
    // upstream counterpart); per-extension stack effects are
    // covered at Layer A by the Category A / B / C / D tests
    // above.

    use super::super::test_helpers::{
        assert_function_pass_parity_vm, run_adamant_pipeline, run_sui_code_unit_verifier,
        sui_config_from, to_sui,
    };
    use adamant_types::Address as AccountAddress;

    /// Add the minimal address-identifier the Sui-side
    /// `module.self_id()` needs (the Layer A `module_with_body`
    /// fixture omits `address_identifiers` because Adamant's
    /// `stack_usage` pass never consults them; Sui's
    /// `code_unit_verifier::verify_module` → `module.self_id()`
    /// dereferences `module_handles[0].address`).
    fn add_self_address(m: &mut AdamantCompiledModule) {
        m.address_identifiers
            .push(AccountAddress::from_bytes([0u8; 32]));
    }

    fn cross_validate_stack_usage_pipeline(m: &AdamantCompiledModule) {
        let mut m = m.clone();
        add_self_address(&mut m);
        let limits = AdamantStructuralLimits::genesis();
        let adamant_result = run_adamant_pipeline(&m, &limits);
        let sui_module = to_sui(&m);
        let sui_config = sui_config_from(&limits);
        let sui_result = run_sui_code_unit_verifier(&sui_module, &sui_config);
        assert_function_pass_parity_vm("stack_usage", adamant_result, sui_result);
    }

    #[test]
    fn cross_validation_accepts_empty_function_body_via_arity_zero() {
        // Function with no params, no returns, body = `Ret`. The
        // simplest balanced body that passes every per-function
        // pass on both sides.
        let m = module_with_body(0, 0, vec![ret()]);
        cross_validate_stack_usage_pipeline(&m);
    }

    #[test]
    fn cross_validation_accepts_push_pop_balanced() {
        // Body: LdU64 0; Pop; Ret. Stack delta = 0 at block end.
        let m = module_with_body(0, 0, vec![ld_u64(0), pop(), ret()]);
        cross_validate_stack_usage_pipeline(&m);
    }

    #[test]
    fn cross_validation_rejects_pop_with_empty_stack() {
        // Body: Pop; Ret. Pop at block start underflows.
        let m = module_with_body(0, 0, vec![pop(), ret()]);
        cross_validate_stack_usage_pipeline(&m);
    }

    #[test]
    fn cross_validation_rejects_block_ends_with_extra_push() {
        // Body: LdU64 0; Ret. Function declares 0 returns but
        // block ends with non-zero stack.
        let m = module_with_body(0, 0, vec![ld_u64(1), ret()]);
        cross_validate_stack_usage_pipeline(&m);
    }

    #[test]
    fn cross_validation_rejects_ret_with_wrong_arity() {
        // Function declares 1 return; body Rets without pushing.
        let m = module_with_body(0, 1, vec![ret()]);
        cross_validate_stack_usage_pipeline(&m);
    }

    #[test]
    fn cross_validation_rejects_binop_with_one_operand() {
        // Add pops 2; body provides only 1.
        let m = module_with_body(0, 1, vec![ld_u64(1), add(), ret()]);
        cross_validate_stack_usage_pipeline(&m);
    }

    #[test]
    fn cross_validation_rejects_unbalanced_at_branch_target() {
        // 0: LdTrue
        // 1: BrTrue 3
        // 2: Branch 3
        // 3: Pop          <- branch-target block expects empty entry
        // 4: Ret
        let m = module_with_body(
            0,
            0,
            vec![
                ld_true(),
                BytecodeInstruction::Inherited(Bytecode::BrTrue(3)),
                BytecodeInstruction::Inherited(Bytecode::Branch(3)),
                pop(),
                ret(),
            ],
        );
        cross_validate_stack_usage_pipeline(&m);
    }

    #[test]
    fn cross_validation_accepts_balanced_loop_via_branch() {
        // 0: Branch 0 — self-loop with empty body. Stack delta
        // per iteration = 0; CFG is reducible (self-loop).
        let m = module_with_body(
            0,
            0,
            vec![BytecodeInstruction::Inherited(Bytecode::Branch(0))],
        );
        cross_validate_stack_usage_pipeline(&m);
    }
}
