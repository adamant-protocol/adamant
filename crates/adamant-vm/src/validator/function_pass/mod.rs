//! Adamant-native per-function verifier passes (whitepaper
//! §6.2.1.8 step 4).
//!
//! Phase 5/5b.4 + 5/5b.5 ports the per-function verifier passes
//! from Sui-Move's `move-bytecode-verifier` into Adamant-owned
//! implementations:
//!
//! - control-flow validation (fall-through + reducibility)
//! - operand-stack discipline
//! - type safety
//! - locals safety
//! - reference safety
//! - acquires-list checking (structural pin only — Rule 5
//!   forbids global storage instructions, so the
//!   `acquires_global_resources` list is always empty in valid
//!   modules per §6.2.1.6 Rule 5)
//!
//! The per-function batch consumes the [`cfg::AdamantControlFlowGraph`]
//! built once per function in D-1a and propagated through D-2…D-5;
//! D-6 wires the batch into [`super::verify_module`] alongside the
//! existing module-level passes (and tears out the transitional
//! Sui-verifier bridge in 5/5b.5).
//!
//! # Phase 5/5b.4 sub-arc
//!
//! - **D-1a.** CFG construction module ([`cfg`]) +
//!   per-function dispatch stub ([`verify_function_bodies`]).
//!   Strictly mechanical — no typed-error variants ship at
//!   D-1a; D-2's control-flow validation pass declares
//!   variants alongside their producers + tests in one focused
//!   commit (Rust error-type lifecycle). `#![allow(dead_code)]`
//!   is module-scoped pending the D-6 wire-in.
//! - **D-1b.** Abstract-interpretation framework
//!   ([`absint`]): single consolidated [`absint::AbstractInterpreter`]
//!   trait (mirrors upstream's three-piece-as-one shape) +
//!   [`absint::analyze_function`] fixpoint engine + visitor
//!   callbacks + RPO traversal + branch-state propagation.
//!   Strictly mechanical — no typed-error variants ship at
//!   D-1b; first consumer is D-3 (operand-stack discipline).
//!   Hard-wires [`AdamantValidationError`][AVE] as the
//!   framework's error type per Q2 plan-gate disposition (4th
//!   deliberate-Adamant-decision instance).
//! - **D-2.** Control-flow validation pass
//!   ([`control_flow`] + [`loop_summary`]); first consumer of
//!   [`cfg::AdamantControlFlowGraph`]. Declares + produces +
//!   tests three CFG-related typed-error variants together
//!   ([`AVE::EmptyFunctionBody`][AVE-empty],
//!   [`AVE::MissingFallthroughTerminator`][AVE-fall],
//!   [`AVE::IrreducibleControlFlow`][AVE-irr]) plus the
//!   [`IrreducibleReason`][IR] closed enum (5th
//!   deliberate-Adamant-decision instance). Adds
//!   `max_loop_depth: Some(64)` to
//!   [`AdamantStructuralLimits`][limits] (Bucket C
//!   provisional). Extension treatment sub-shape 3 confirmed —
//!   Adamant extensions are non-branching, so a function
//!   ending in any `Adamant(_)` arm is rejected as missing a
//!   terminator (which is correct).
//! - **D-3.** Operand-stack discipline pass
//!   ([`stack_usage`]); second consumer of
//!   [`cfg::AdamantControlFlowGraph`] (does NOT consume
//!   [`absint::AbstractInterpreter`] — D-4 locals safety is
//!   the first AI consumer). Declares + produces + tests
//!   three stack-discipline variants
//!   ([`AVE::StackPushOverflow`][AVE-push],
//!   [`AVE::StackUnderflow`][AVE-under],
//!   [`AVE::UnbalancedStackAtBlockEnd`][AVE-unbal]). Adds
//!   `max_push_size: Some(10000)` to
//!   [`AdamantStructuralLimits`][limits] (Bucket A — adopt
//!   Sui's commented alternative). Confirms Adamant-extension
//!   treatment sub-shape 2 (per-extension stack-effect
//!   needed); the 10th verification gate fired in corrective
//!   mode at D-3 plan-gate, partitioning the 17 extensions
//!   into 4 categories (Category A static / B parametric-FH /
//!   C deferred-to-§7 / D deferred-to-§8.5).
//! - **D-4 (this commit).** Locals safety pass
//!   ([`locals_safety`]) + acquires-list structural-
//!   impossibility check; **first consumer of
//!   [`absint::AbstractInterpreter`]**. Declares + produces +
//!   tests five locals-safety variants
//!   ([`AVE::StLocDestroysNonDrop`][AVE-stloc],
//!   [`AVE::MoveLocUnavailable`][AVE-mv],
//!   [`AVE::CopyLocUnavailable`][AVE-cp],
//!   [`AVE::BorrowLocUnavailable`][AVE-borrow],
//!   [`AVE::RetWithUndroppedLocals`][AVE-ret]). Confirms
//!   Adamant-extension treatment sub-shape 3 — extensions
//!   don't read/write/borrow locals; rule-of-three for sub-
//!   shape 3 specifically met at D-4 closure (D-1a/D-2/D-4).
//!   Acquires structural-impossibility (`unreachable!`-three-
//!   anchor) is the 2nd instance of structural-impossibility-
//!   checks sub-shape 2 (1st was B-2.4 deprecated arms).
//!   `AdamantAbilityCache` visibility promoted from
//!   `pub(super)` to `pub(in crate::validator)` for inline
//!   per-function ability resolution per Q3(a) (6th
//!   deliberate-Adamant-decision instance).
//! - D-5. Type safety + reference safety + Rule 3 (call-graph) + Rules 4, 5 reaffirmation per the D-1 plan-gate Q1 disposition. Fires the 11th verification gate via §6.2.1.6 spec binding.
//! - D-6. Pipeline integration into [`super::verify_module`]
//!   step 4; bridge tear-out lands with 5/5b.5.
//! - D-7. Closure batch + CLAUDE.md state-bump.
//!
//! [AVE]: super::AdamantValidationError
//! [AVE-empty]: super::AdamantValidationError::EmptyFunctionBody
//! [AVE-fall]: super::AdamantValidationError::MissingFallthroughTerminator
//! [AVE-irr]: super::AdamantValidationError::IrreducibleControlFlow
//! [AVE-push]: super::AdamantValidationError::StackPushOverflow
//! [AVE-under]: super::AdamantValidationError::StackUnderflow
//! [AVE-unbal]: super::AdamantValidationError::UnbalancedStackAtBlockEnd
//! [AVE-stloc]: super::AdamantValidationError::StLocDestroysNonDrop
//! [AVE-mv]: super::AdamantValidationError::MoveLocUnavailable
//! [AVE-cp]: super::AdamantValidationError::CopyLocUnavailable
//! [AVE-borrow]: super::AdamantValidationError::BorrowLocUnavailable
//! [AVE-ret]: super::AdamantValidationError::RetWithUndroppedLocals
//! [IR]: super::AdamantValidationError
//! [limits]: super::config::AdamantStructuralLimits

#![allow(dead_code)] // D-1..D-2 foundation; entry point wires in at D-6.

pub(super) mod abstract_stack;
pub(super) mod absint;
pub(super) mod cfg;
pub(super) mod control_flow;
pub(super) mod locals_safety;
pub(super) mod loop_summary;
pub(super) mod stack_usage;

use adamant_bytecode_format::FunctionDefinitionIndex;

use crate::module::AdamantCompiledModule;

use super::config::AdamantStructuralLimits;
use super::error::AdamantValidationError;

/// Run the Adamant-native per-function verifier passes against
/// every function definition in `module`.
///
/// **D-2.** Wires the control-flow validation pass into the
/// per-function entry point. Native functions (those with
/// `code: None`) are skipped here — whitepaper §6.2.1.6 Rule 4
/// (no native functions) is enforced separately at D-5 per the
/// D-1 plan-gate Q1 disposition.
///
/// `_cfg` is intentionally discarded at D-2: D-3..D-5 will
/// replace the discard with consumers (operand-stack discipline,
/// type safety, locals safety, reference safety) operating on
/// the CFG without rebuilding. D-6 wires this entry point into
/// [`super::verify_module`] step 4.
pub(super) fn verify_function_bodies(
    module: &AdamantCompiledModule,
    config: &AdamantStructuralLimits,
) -> Result<(), AdamantValidationError> {
    for (idx, function_definition) in module.function_defs.iter().enumerate() {
        let fn_def_idx = FunctionDefinitionIndex::new(
            u16::try_from(idx).expect(
                "function-def count fits u16; binary format precludes overflow \
                 (TABLE_INDEX_MAX = u16::MAX)",
            ),
        );
        let Some(code_unit) = function_definition.code.as_ref() else {
            // Native function — no body to verify. Sui-base
            // subset permits native function declarations at
            // the binary-format level; whitepaper §6.2.1.6 Rule
            // 4 (no native functions) lands at D-5 per the D-1
            // plan-gate Q1 disposition.
            continue;
        };
        let cfg = control_flow::verify_function(
            config,
            fn_def_idx,
            &code_unit.code,
            &code_unit.jump_tables,
        )?;
        stack_usage::StackUsageVerifier::verify(
            config,
            module,
            fn_def_idx,
            &code_unit.code,
            &cfg,
        )?;
        locals_safety::verify_function(
            module,
            fn_def_idx,
            function_definition,
            &code_unit.code,
            &cfg,
        )?;
        // D-5 consumes `cfg` here for type + reference safety;
        // orchestration wired at D-6.
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    //! Layer A unit tests for the per-function dispatcher.
    //! Smoke tests for the iteration shape: empty modules,
    //! native-only modules, single-function happy path, and
    //! first-failure-wins eager semantics.

    use super::*;
    use crate::module::{
        AdamantCodeUnit, AdamantCompiledModule, AdamantFunctionDefinition,
    };
    use crate::bytecode::BytecodeInstruction;
    use adamant_bytecode_format::{
        Bytecode, FunctionHandle, IdentifierIndex, ModuleHandleIndex, Signature, SignatureIndex,
    };

    fn ret_inst() -> BytecodeInstruction {
        BytecodeInstruction::Inherited(Bytecode::Ret)
    }

    fn pop_inst() -> BytecodeInstruction {
        BytecodeInstruction::Inherited(Bytecode::Pop)
    }

    /// Builds a module with a 0-param / 0-return signature pool
    /// entry shared by every function-handle, plus one
    /// function-handle and function-def per body. D-3's
    /// `stack_usage` pass needs the handle's signature
    /// resolution, so the test helper builds a complete enough
    /// module shape to exercise both D-2 and D-3 in
    /// `verify_function_bodies`.
    fn module_with_function_bodies(bodies: Vec<Vec<BytecodeInstruction>>) -> AdamantCompiledModule {
        let mut m = AdamantCompiledModule::default();
        // Signature pool: SignatureIndex(0) is empty, used for
        // both parameters and returns of every test function.
        m.signatures.push(Signature(vec![]));
        for (idx, body) in bodies.into_iter().enumerate() {
            m.function_handles.push(FunctionHandle {
                module: ModuleHandleIndex(0),
                name: IdentifierIndex(0),
                parameters: SignatureIndex(0),
                return_: SignatureIndex(0),
                type_parameters: vec![],
            });
            let code_unit = AdamantCodeUnit {
                code: body,
                ..AdamantCodeUnit::default()
            };
            m.function_defs.push(AdamantFunctionDefinition {
                function: adamant_bytecode_format::FunctionHandleIndex(
                    u16::try_from(idx).expect("test fixture function count fits u16"),
                ),
                code: Some(code_unit),
                ..AdamantFunctionDefinition::default()
            });
        }
        m
    }

    fn module_with_native_function() -> AdamantCompiledModule {
        let mut m = AdamantCompiledModule::default();
        m.function_defs.push(AdamantFunctionDefinition {
            code: None,
            ..AdamantFunctionDefinition::default()
        });
        m
    }

    #[test]
    fn verify_function_bodies_empty_module_ok() {
        let m = AdamantCompiledModule::default();
        let limits = AdamantStructuralLimits::genesis();
        verify_function_bodies(&m, &limits).expect("empty module accepts");
    }

    #[test]
    fn verify_function_bodies_single_function_ok() {
        let m = module_with_function_bodies(vec![vec![ret_inst()]]);
        let limits = AdamantStructuralLimits::genesis();
        verify_function_bodies(&m, &limits).expect("single Ret-only function accepts");
    }

    #[test]
    fn verify_function_bodies_native_only_ok() {
        // Native functions are skipped — Rule 4 enforcement
        // lives elsewhere (D-5).
        let m = module_with_native_function();
        let limits = AdamantStructuralLimits::genesis();
        verify_function_bodies(&m, &limits).expect("native-only module skips per-function passes");
    }

    /// Eager semantics: the first failing function aborts the
    /// pass. Second function being well-formed doesn't mask the
    /// first's failure.
    #[test]
    fn verify_function_bodies_first_failure_wins() {
        let m = module_with_function_bodies(vec![
            vec![pop_inst()],   // function 0: falls off end
            vec![ret_inst()],   // function 1: well-formed
        ]);
        let limits = AdamantStructuralLimits::genesis();
        match verify_function_bodies(&m, &limits) {
            Err(AdamantValidationError::MissingFallthroughTerminator { fn_def_idx, .. }) => {
                assert_eq!(fn_def_idx.0, 0, "first function's failure must surface");
            }
            other => panic!("expected MissingFallthroughTerminator on fn 0, got {other:?}"),
        }
    }
}
