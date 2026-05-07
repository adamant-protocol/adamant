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
//! - **D-1b (this commit).** Abstract-interpretation framework
//!   ([`absint`]): single consolidated [`absint::AbstractInterpreter`]
//!   trait (mirrors upstream's three-piece-as-one shape) +
//!   [`absint::analyze_function`] fixpoint engine + visitor
//!   callbacks + RPO traversal + branch-state propagation.
//!   Strictly mechanical — no typed-error variants ship at
//!   D-1b; first consumer is D-3 (locals safety). Hard-wires
//!   [`AdamantValidationError`][AVE] as the framework's error
//!   type per Q2 plan-gate disposition (4th deliberate-Adamant-
//!   decision instance).
//! - D-2. Control-flow validation pass (fall-through +
//!   reducibility); first consumer of [`cfg::AdamantControlFlowGraph`].
//!   Declares + produces + tests all four CFG-related typed-
//!   error variants together (`EmptyFunctionBody`,
//!   `MissingFallthroughTerminator`, `InvalidBranchTarget`,
//!   `IrreducibleControlFlow`).
//! - D-3, D-4, D-5. Stack/type/locals/reference-safety + Rule 3
//!   (call-graph) + Rules 4, 5 reaffirmation per Q1 disposition.
//!   D-3 is first consumer of [`absint::AbstractInterpreter`].
//! - D-6. Pipeline integration into [`super::verify_module`]
//!   step 4; bridge tear-out lands with 5/5b.5.
//! - D-7. Closure batch + CLAUDE.md state-bump.
//!
//! [AVE]: super::AdamantValidationError

#![allow(dead_code)] // D-1a/D-1b foundation; entry point wires in at D-6.

pub(super) mod absint;
pub(super) mod cfg;

use crate::module::AdamantCompiledModule;

use super::error::AdamantValidationError;

/// Run the Adamant-native per-function verifier passes against
/// every function definition in `module`.
///
/// **D-1a stub.** This entry point exists so D-2 / D-3 / D-4 /
/// D-5 can populate per-pass call sites incrementally; the body
/// is empty pending D-6's pipeline integration. The function
/// signature matches the shape the call site at
/// [`super::verify_module`] step 4 will eventually invoke.
///
/// Adding the empty stub now establishes the module-entry shape
/// (single-pass-of-the-module that orchestrates per-function
/// passes; mirrors `move-bytecode-verifier`'s `code_unit_verifier`
/// orchestration shape) and lets D-1a's [`cfg`] construction be
/// exercised by Layer A unit tests without exposing internal
/// CFG state to the rest of the crate.
///
/// The `Result<(), AdamantValidationError>` return shape is
/// retained at D-1a even though the body is `Ok(())` only —
/// D-2 wires the control-flow validation pass at the same
/// site and will declare + produce CFG-related typed-error
/// variants there. Changing the return shape now would force
/// a churn at D-2; the `clippy::unnecessary_wraps` warning is
/// acknowledged and suppressed as deliberate forward-shape.
#[allow(clippy::unnecessary_wraps)]
pub(super) fn verify_function_bodies(
    _module: &AdamantCompiledModule,
) -> Result<(), AdamantValidationError> {
    // D-1a stub. D-2 wires the control-flow validation pass;
    // D-3..D-5 wire the stack/type/locals/reference-safety
    // passes; D-6 wires this entry point into
    // `super::verify_module`'s step 4.
    Ok(())
}
