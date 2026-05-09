//! Gas-accounting handler tests — ChargeGas, RemainingGas,
//! OutOfGas. Per Phase 5/6.5.
//!
//! Verbatim-spec-quote-grounds-runtime-fixture discipline applied
//! per fixture; whitepaper §6.2.1.4 lines 423-425 + §6.3.1 quotes
//! anchor each handler's semantics.

use adamant_bytecode_format::FunctionHandleIndex;

use super::*;
use crate::bytecode::{AdamantBytecode, BytecodeInstruction, GasDimension};
use crate::runtime::interpreter::dispatch_instruction;
use crate::runtime::{AbortReason, GasTracker};
use crate::transaction::GasBudget;

fn fh_zero() -> FunctionHandleIndex {
    FunctionHandleIndex(0)
}

fn empty_module() -> AdamantCompiledModule {
    AdamantCompiledModule::default()
}

fn budget(
    computation: u64,
    storage: u64,
    rent: u64,
    bandwidth: u64,
    proof_verification: u64,
    proof_generation: u64,
) -> GasBudget {
    GasBudget {
        computation,
        storage,
        rent,
        bandwidth,
        proof_verification,
        proof_generation,
    }
}

fn state_with_budget(b: GasBudget) -> InterpreterState {
    let mut state = InterpreterState::new();
    state.push_frame(Frame::new(fh_zero(), 0));
    state.set_gas_budget(&b);
    state
}

fn dispatch_adamant_for_gas(
    state: &mut InterpreterState,
    opcode: AdamantBytecode,
    module: &AdamantCompiledModule,
) -> Result<DispatchOutcome, VMError> {
    dispatch_instruction(&BytecodeInstruction::Adamant(opcode), state, module)
}

// =====================================================================
// ChargeGas
// =====================================================================

/// Whitepaper §6.2.1.4 line 423 (verbatim): "Charge a specified
/// amount across one of the six gas dimensions (per section
/// 6.0.7's `GasBudget` and section 6.3.1). Pops the amount as
/// `u64`."
#[test]
fn charge_gas_deducts_amount_from_named_dimension() {
    let module = empty_module();
    let mut state = state_with_budget(budget(1000, 0, 0, 0, 0, 0));
    push_stack(&mut state, vec![RuntimeValue::U64(250)]);
    dispatch_adamant_for_gas(
        &mut state,
        AdamantBytecode::ChargeGas(GasDimension::Computation),
        &module,
    )
    .expect("ok");
    assert_eq!(state.remaining_gas(GasDimension::Computation), 750);
    assert_eq!(pc(&state), 1);
    assert_eq!(stack_len(&state), 0);
}

/// Whitepaper §6.3.1 (verbatim): "The transaction aborts on the
/// first dimension exhausted; the user cannot trade unused budget
/// in one dimension for additional consumption in another."
#[test]
fn charge_gas_exhaustion_surfaces_out_of_gas_abort() {
    let module = empty_module();
    let mut state = state_with_budget(budget(10, 0, 0, 0, 0, 0));
    push_stack(&mut state, vec![RuntimeValue::U64(100)]);
    let result = dispatch_adamant_for_gas(
        &mut state,
        AdamantBytecode::ChargeGas(GasDimension::Computation),
        &module,
    );
    assert!(matches!(
        result,
        Err(VMError::AbortError {
            reason: AbortReason::OutOfGas {
                dimension: GasDimension::Computation
            }
        })
    ));
    // Remaining unchanged after a failed charge.
    assert_eq!(state.remaining_gas(GasDimension::Computation), 10);
}

/// ChargeGas across all six dimensions independently.
#[test]
fn charge_gas_across_all_six_dimensions() {
    let module = empty_module();
    let dims = [
        GasDimension::Computation,
        GasDimension::Storage,
        GasDimension::Rent,
        GasDimension::Bandwidth,
        GasDimension::ProofVerification,
        GasDimension::ProofGeneration,
    ];
    for dim in dims {
        let mut state = state_with_budget(budget(100, 100, 100, 100, 100, 100));
        push_stack(&mut state, vec![RuntimeValue::U64(40)]);
        dispatch_adamant_for_gas(&mut state, AdamantBytecode::ChargeGas(dim), &module).expect("ok");
        assert_eq!(state.remaining_gas(dim), 60);
    }
}

/// Charging zero is a no-op.
#[test]
fn charge_gas_zero_is_no_op() {
    let module = empty_module();
    let mut state = state_with_budget(budget(0, 0, 0, 0, 0, 0));
    push_stack(&mut state, vec![RuntimeValue::U64(0)]);
    dispatch_adamant_for_gas(
        &mut state,
        AdamantBytecode::ChargeGas(GasDimension::Computation),
        &module,
    )
    .expect("ok");
    assert_eq!(state.remaining_gas(GasDimension::Computation), 0);
}

// =====================================================================
// RemainingGas
// =====================================================================

/// Whitepaper §6.2.1.4 line 424 (verbatim): "Push the remaining
/// budget for a specified dimension as `u64`."
#[test]
fn remaining_gas_pushes_current_remaining() {
    let module = empty_module();
    let mut state = state_with_budget(budget(0, 0, 0, 500, 0, 0));
    dispatch_adamant_for_gas(
        &mut state,
        AdamantBytecode::RemainingGas(GasDimension::Bandwidth),
        &module,
    )
    .expect("ok");
    assert_eq!(top(&state), RuntimeValue::U64(500));
    assert_eq!(pc(&state), 1);
}

/// RemainingGas reads independently per dimension.
#[test]
fn remaining_gas_reads_independently_per_dimension() {
    let module = empty_module();
    let state = state_with_budget(budget(11, 22, 33, 44, 55, 66));
    let dims_and_expected = [
        (GasDimension::Computation, 11),
        (GasDimension::Storage, 22),
        (GasDimension::Rent, 33),
        (GasDimension::Bandwidth, 44),
        (GasDimension::ProofVerification, 55),
        (GasDimension::ProofGeneration, 66),
    ];
    for (dim, expected) in dims_and_expected {
        let mut s = state.clone();
        dispatch_adamant_for_gas(&mut s, AdamantBytecode::RemainingGas(dim), &module).expect("ok");
        assert_eq!(top(&s), RuntimeValue::U64(expected));
    }
    let _ = state; // silence unused warning post-clone
}

/// RemainingGas reflects prior charges.
#[test]
fn remaining_gas_after_charge_reflects_deduction() {
    let module = empty_module();
    let mut state = state_with_budget(budget(1000, 0, 0, 0, 0, 0));
    push_stack(&mut state, vec![RuntimeValue::U64(300)]);
    dispatch_adamant_for_gas(
        &mut state,
        AdamantBytecode::ChargeGas(GasDimension::Computation),
        &module,
    )
    .expect("charge");
    dispatch_adamant_for_gas(
        &mut state,
        AdamantBytecode::RemainingGas(GasDimension::Computation),
        &module,
    )
    .expect("read");
    assert_eq!(top(&state), RuntimeValue::U64(700));
}

// =====================================================================
// OutOfGas
// =====================================================================

/// Whitepaper §6.2.1.4 line 425 (verbatim): "Abort the transaction
/// with the out-of-gas error. Used by stdlib functions that detect
/// dimension exhaustion."
#[test]
fn out_of_gas_handler_aborts_unconditionally() {
    let module = empty_module();
    let mut state = state_with_budget(budget(10000, 10000, 10000, 10000, 10000, 10000));
    let result = dispatch_adamant_for_gas(&mut state, AdamantBytecode::OutOfGas, &module);
    assert!(matches!(
        result,
        Err(VMError::AbortError {
            reason: AbortReason::OutOfGas { .. }
        })
    ));
}

// =====================================================================
// AbortReason variant coverage (variant-vs-test mapping audit)
// =====================================================================

/// `AbortReason::UserAbort` surfaces from `Bytecode::Abort` per
/// Phase 5/6.5 refinement (see also runtime/interpreter.rs::tests::
/// abort_returns_error).
#[test]
fn abort_reason_user_abort_carries_code() {
    let r = AbortReason::UserAbort { code: 0xDEAD };
    assert!(matches!(r, AbortReason::UserAbort { code: 0xDEAD }));
}

/// `AbortReason::AssertionFailure` carries an assertion code (used
/// by stdlib `assert!` macro wrapping per Q5/6.5.3).
#[test]
fn abort_reason_assertion_failure_carries_code() {
    let r = AbortReason::AssertionFailure { code: 0x42 };
    assert!(matches!(r, AbortReason::AssertionFailure { code: 0x42 }));
}

/// `AbortReason::DivisionByZero` is variant-only (no payload);
/// cross-references `ArithmeticErrorReason::DivisionByZero` per
/// Q5/6.5.3 framing.
#[test]
fn abort_reason_division_by_zero_is_variant_only() {
    let r = AbortReason::DivisionByZero;
    assert!(matches!(r, AbortReason::DivisionByZero));
}

/// `AbortReason::OutOfGas { dimension }` carries the failed
/// dimension as payload.
#[test]
fn abort_reason_out_of_gas_carries_dimension() {
    for dim in [
        GasDimension::Computation,
        GasDimension::Storage,
        GasDimension::Rent,
        GasDimension::Bandwidth,
        GasDimension::ProofVerification,
        GasDimension::ProofGeneration,
    ] {
        let r = AbortReason::OutOfGas { dimension: dim };
        assert!(matches!(r, AbortReason::OutOfGas { dimension: d } if d == dim));
    }
}

// =====================================================================
// GasTracker integration with InterpreterState
// =====================================================================

/// `InterpreterState::set_gas_budget` initialises the tracker
/// from a `GasBudget`.
#[test]
fn interpreter_state_set_gas_budget_initialises_tracker() {
    let b = budget(1, 2, 3, 4, 5, 6);
    let mut state = InterpreterState::new();
    state.set_gas_budget(&b);
    assert_eq!(state.remaining_gas(GasDimension::Computation), 1);
    assert_eq!(state.remaining_gas(GasDimension::Storage), 2);
    assert_eq!(state.remaining_gas(GasDimension::Rent), 3);
    assert_eq!(state.remaining_gas(GasDimension::Bandwidth), 4);
    assert_eq!(state.remaining_gas(GasDimension::ProofVerification), 5);
    assert_eq!(state.remaining_gas(GasDimension::ProofGeneration), 6);
}

/// `InterpreterState::charge_gas` convenience wrapper deducts +
/// surfaces `AbortError` on exhaustion.
#[test]
fn interpreter_state_charge_gas_convenience_wrapper() {
    let mut state = InterpreterState::new();
    state.set_gas_budget(&budget(100, 0, 0, 0, 0, 0));
    state.charge_gas(GasDimension::Computation, 25).expect("ok");
    assert_eq!(state.remaining_gas(GasDimension::Computation), 75);
    let result = state.charge_gas(GasDimension::Computation, 1000);
    assert!(matches!(
        result,
        Err(VMError::AbortError {
            reason: AbortReason::OutOfGas {
                dimension: GasDimension::Computation
            }
        })
    ));
}

/// Default `InterpreterState::new()` has all-zero gas remaining.
#[test]
fn default_interpreter_state_has_empty_gas() {
    let state = InterpreterState::new();
    for dim in [
        GasDimension::Computation,
        GasDimension::Storage,
        GasDimension::Rent,
        GasDimension::Bandwidth,
        GasDimension::ProofVerification,
        GasDimension::ProofGeneration,
    ] {
        assert_eq!(state.remaining_gas(dim), 0);
    }
}

/// `GasTracker` is exposed via `InterpreterState::gas_tracker()`.
#[test]
fn interpreter_state_gas_tracker_accessor() {
    let mut state = InterpreterState::new();
    state.set_gas_budget(&budget(7, 0, 0, 0, 0, 0));
    let tracker: &GasTracker = state.gas_tracker();
    assert_eq!(tracker.computation, 7);
}
