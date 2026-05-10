//! Direct-interpreter dispatch loop scaffold — whitepaper §6.2.2 step 5.

#![allow(
    clippy::missing_errors_doc,
    reason = "the dispatch helpers all return Result<DispatchOutcome, VMError>; each method's doc prose documents the error conditions per the verifier-residual binding posture and the §6.2.1.9 abort semantics"
)]
//!
//! Phase 5/6 plan-gate Q1 disposition: direct interpreter (one
//! Rust function per `Bytecode` / `AdamantBytecode` variant;
//! `match` on opcode in fetch-decode-execute loop). Quality-over-
//! speed posture; correctness first, optimization later.
//!
//! At sub-arc 5/6.1 this module ships the dispatch-loop scaffold
//! only — no instruction handlers. Every dispatch attempt returns
//! [`crate::runtime::VMError::InvalidInstruction`]. Instruction
//! handlers land at:
//!
//! - **5/6.2** — inherited Sui-base instructions (~150 instructions)
//! - **5/6.3** — Adamant-extension non-privacy instructions
//!   (13 of 17 extensions)
//! - **5/6.4** — privacy-circuit instruction scaffold
//!   (`GenerateProof`, `VerifyProof`, `RecursiveVerify`,
//!   `ReleaseSubViewKey`); full implementation deferred to
//!   Phase 6 (privacy layer §7) per Phase 5/6 plan-gate Q4
//!   disposition

use std::sync::Arc;

use adamant_bytecode_format::{Bytecode, FunctionHandleIndex, U256 as FormatU256};
use adamant_crypto::kzg::KzgSetup;

use crate::bytecode::{BytecodeInstruction, GasDimension};
use crate::module::AdamantCompiledModule;
use crate::runtime::error::{
    AbortReason, ArithmeticErrorReason, InvariantViolationReason, VMError,
};
use crate::runtime::frame::Frame;
use crate::runtime::gas::GasTracker;
use crate::runtime::runtime_value::RuntimeValue;
use crate::transaction::GasBudget;

/// Multi-frame interpreter state.
///
/// Holds the call stack — a stack of [`Frame`] entries, with the
/// top entry being the currently-executing function. Function
/// invocation pushes a new frame; function return pops the top
/// frame. Per whitepaper §6.2.2 step 5, execution runs "to
/// completion" — i.e., until the call stack is empty — "or until
/// gas is exhausted."
///
/// Phase 5/6.5 adds the [`GasTracker`] field for multi-dimensional
/// gas accounting per §6.3.1. The tracker is set once at
/// transaction frame entry from the transaction's [`GasBudget`]
/// and never topped up mid-execution.
#[derive(Debug, Clone, Default)]
pub struct InterpreterState {
    frames: Vec<Frame>,
    /// Multi-dimensional gas tracker per §6.3.1. Initialised at
    /// transaction frame entry via
    /// [`InterpreterState::set_gas_budget`]; per-instruction
    /// charges deduct via [`InterpreterState::charge_gas`];
    /// remaining-per-dimension reads via
    /// [`InterpreterState::remaining_gas`]. Default is empty (all
    /// dimensions at zero); an empty tracker aborts on any
    /// positive charge per [`GasTracker::charge`] semantics.
    gas_tracker: GasTracker,
    /// Genesis-fixed KZG trusted-setup parameters per whitepaper
    /// §3.9.2 / §11. `None` until the runtime caller invokes
    /// [`InterpreterState::set_kzg_setup`]; in production
    /// validators load the setup at startup before accepting any
    /// transaction. `KzgCommit` / `KzgVerify` instructions abort
    /// with [`InvariantViolationReason::KzgSetupNotLoaded`] when
    /// this field is `None`.
    ///
    /// `Arc`-wrapped for cheap sharing across multiple interpreter
    /// instances per Phase 7+ consensus integration; a single
    /// validator-process loads the setup once and shares it
    /// across many transaction-execution states.
    kzg_setup: Option<Arc<KzgSetup>>,
}

impl InterpreterState {
    /// Construct an empty interpreter state with no active frames.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether the call stack is empty.
    ///
    /// Per whitepaper §6.2.2 step 5, an empty call stack at
    /// dispatch time means execution has run to completion.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.frames.is_empty()
    }

    /// Number of frames currently on the call stack.
    #[must_use]
    pub fn frame_depth(&self) -> usize {
        self.frames.len()
    }

    /// Push a new frame onto the call stack.
    ///
    /// Invoked by the `Call` / `CallGeneric` / `InvokeShielded` /
    /// `InvokeTransparent` instruction handlers (5/6.2 and 5/6.3).
    /// At sub-arc 5/6.1 this method is callable from tests but
    /// not from the dispatch loop (no instruction handlers yet).
    pub fn push_frame(&mut self, frame: Frame) {
        self.frames.push(frame);
    }

    /// Pop the top frame from the call stack.
    ///
    /// Invoked by the `Ret` instruction handler (5/6.2). Returns
    /// `None` when the call stack is already empty.
    pub fn pop_frame(&mut self) -> Option<Frame> {
        self.frames.pop()
    }

    /// Borrow the top frame mutably for instruction-handler use.
    ///
    /// Returns `None` if the call stack is empty (dispatch should
    /// not be invoked on an empty interpreter state per the
    /// dispatch-loop's own check).
    pub fn top_frame_mut(&mut self) -> Option<&mut Frame> {
        self.frames.last_mut()
    }

    /// Borrow the top frame for read-only access.
    #[must_use]
    pub fn top_frame(&self) -> Option<&Frame> {
        self.frames.last()
    }

    /// Set the gas tracker from a transaction's [`GasBudget`].
    /// Invoked at transaction-execution start to initialise
    /// per-dimension remaining budget per §6.3.1.
    pub fn set_gas_budget(&mut self, budget: &GasBudget) {
        self.gas_tracker = GasTracker::from_budget(budget);
    }

    /// Read the current gas tracker. Used by tests and by
    /// transaction-execution-end hooks that report consumed gas.
    #[must_use]
    pub fn gas_tracker(&self) -> &GasTracker {
        &self.gas_tracker
    }

    /// Install the KZG trusted-setup parameters per whitepaper
    /// §3.9.2 / §11. Must be invoked at validator startup before
    /// any transaction that may execute `KzgCommit` / `KzgVerify`
    /// is admitted to the dispatch loop.
    ///
    /// `Arc`-wrapped so a single validator-process can share one
    /// genesis-fixed setup across many interpreter states (Phase
    /// 7+ consensus integration). `Arc::clone` is a refcount bump
    /// on the calling side.
    pub fn set_kzg_setup(&mut self, setup: Arc<KzgSetup>) {
        self.kzg_setup = Some(setup);
    }

    /// Borrow the installed KZG trusted-setup parameters, if any.
    /// Returns `None` until [`InterpreterState::set_kzg_setup`]
    /// has been called.
    #[must_use]
    pub fn kzg_setup(&self) -> Option<&KzgSetup> {
        self.kzg_setup.as_deref()
    }

    /// Charge `amount` units against `dimension`'s remaining
    /// budget. Convenience wrapper over
    /// [`GasTracker::charge`]; surfaces
    /// [`VMError::AbortError`] with
    /// [`crate::runtime::AbortReason::OutOfGas`] on exhaustion.
    pub fn charge_gas(&mut self, dimension: GasDimension, amount: u64) -> Result<(), VMError> {
        self.gas_tracker.charge(dimension, amount)
    }

    /// Read the remaining budget for `dimension`.
    #[must_use]
    pub fn remaining_gas(&self, dimension: GasDimension) -> u64 {
        self.gas_tracker.remaining(dimension)
    }
}

/// Outcome of dispatching a single instruction.
///
/// Returned by [`dispatch_instruction`]. The dispatch loop's
/// outer driver consumes outcomes and either continues to the
/// next instruction (`Continue`), terminates execution
/// (`Halt`), or surfaces a runtime error (which propagates as
/// `Err(VMError)` from the dispatch function rather than as an
/// outcome variant).
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub enum DispatchOutcome {
    /// Continue to the next instruction in the dispatch loop.
    /// The instruction handler advanced the program counter
    /// (or transferred control via branch/call/return) as
    /// appropriate.
    Continue,
    /// Execution has run to completion per whitepaper §6.2.2
    /// step 5. The call stack is empty; the dispatch loop's
    /// outer driver returns success.
    Halt,
    /// `Bytecode::Call` was dispatched. The outer driver
    /// resolves the function definition, pops arguments from
    /// the caller's stack, creates a new frame, and pushes it
    /// onto the call stack per Phase 5/6.2c.2.α frame-creation
    /// design (Sui-VM-aligned `ExitCode::Call` pattern).
    Call(adamant_bytecode_format::FunctionHandleIndex),
    /// `Bytecode::CallGeneric` was dispatched. Analogous to
    /// [`Self::Call`] but resolves the function via
    /// `function_instantiations` pool.
    CallGeneric(adamant_bytecode_format::FunctionInstantiationIndex),
    /// `Bytecode::Adamant(InvokeShielded(_))` was dispatched.
    /// Same shape as [`Self::Call`] but the outer driver checks
    /// the caller's privacy mode is [`PrivacyMode::Shielded`]
    /// (residual binding for §6.2.1.6 Rule 7) and creates the
    /// new frame with [`PrivacyMode::Shielded`] per whitepaper
    /// §6.1.2.
    InvokeShielded(adamant_bytecode_format::FunctionHandleIndex),
    /// `Bytecode::Adamant(InvokeTransparent(_))` was dispatched.
    /// Same shape as [`Self::InvokeShielded`] but with
    /// [`PrivacyMode::Transparent`] for both the residual check
    /// and the new frame's mode.
    InvokeTransparent(adamant_bytecode_format::FunctionHandleIndex),
}

/// Dispatch a single instruction against the interpreter state.
///
/// At sub-arc 5/6.1 this is a scaffold: every instruction returns
/// [`VMError::InvalidInstruction`]. Instruction handlers land at
/// 5/6.2 / 5/6.3 / 5/6.4 as documented at the module level.
///
/// # Contract
///
/// The caller must ensure the interpreter state has at least one
/// frame on the call stack. The dispatch driver [`run`] enforces
/// this via [`InterpreterState::is_empty`] before invoking. The
/// scaffold uses [`Option::expect`] rather than returning an
/// error variant: empty-call-stack at dispatch time would be a
/// caller-contract violation, not a runtime error condition.
///
/// # Errors
///
/// Returns [`VMError::InvalidInstruction`] for every input at
/// sub-arc 5/6.1.
///
/// # Panics
///
/// Panics if the interpreter state's call stack is empty when
/// this function is invoked. The dispatch driver [`run`] checks
/// [`InterpreterState::is_empty`] before calling and never
/// triggers the panic; direct callers must uphold the same
/// contract.
///
/// # Defensive shape
///
/// The function takes the instruction by reference rather than
/// by value because the eventual instruction handlers (5/6.2+)
/// will need to read operand-bytes encoded inline in the
/// instruction without copying. The scaffold preserves that
/// signature shape so 5/6.2 doesn't have to refactor.
pub fn dispatch_instruction(
    instruction: &BytecodeInstruction,
    state: &mut InterpreterState,
    module: &AdamantCompiledModule,
) -> Result<DispatchOutcome, VMError> {
    // Per Phase 5/6.2c.2.α: module-access handlers (LdConst, Call,
    // CallGeneric) consume the module reference. The 38 self-
    // contained handlers from 5/6.2b ignore it.
    match instruction {
        BytecodeInstruction::Inherited(opcode) => dispatch_inherited(opcode, state, module),
        BytecodeInstruction::Adamant(opcode) => dispatch_adamant(opcode, state),
    }
}

/// Dispatch an Adamant-extension opcode per whitepaper §6.1.2 +
/// §6.2.1.4 extension surface.
///
/// Phase 5/6.3 wires 7 of the 17 Adamant-extension handlers under
/// the scope-bounded-by-infrastructure-availability principle:
///
/// - 2 frame-creation: `InvokeShielded`, `InvokeTransparent`
///   (privacy-mode residual check + frame creation)
/// - 2 hash: `Sha3_256` (§3.3.1), `Blake3` (§3.3.2)
/// - 3 signature: `Ed25519Verify` (§3.4.1), `MlDsaVerify65`
///   (§3.4.2), `BlsVerify` (§3.4.3)
///
/// Deferred to alongside their respective adamant-crypto extensions:
/// - `KzgCommit`, `KzgVerify` — pending adamant-crypto KZG impl
///
/// Note: `MlDsaVerify87` was removed from `AdamantBytecode` by
/// whitepaper §6.2 amendment (commits 80ccd46 + 22b5a8a + 63cbf5c)
/// restricting the post-quantum signature scheme to ML-DSA-65 per
/// §3.4.2's "Level 3 is the appropriate balance" commitment.
///
/// Deferred to Phase 6 `adamant-privacy` workstream (per Phase
/// 5/6.4 plan-gate Option A — `adamant-crypto/src/zk.rs` is an
/// 8-line stub at the time of this commit; full Halo 2 surface
/// lands in Phase 6):
/// - `GenerateProof(CircuitId)` (§6.2.1.4 line 410; §7.3.2
///   validity circuit) — depends on Halo 2 prover
/// - `VerifyProof(CircuitId)` (§6.2.1.4 line 411; §7.3.4
///   verification cost) — depends on Halo 2 verifier
/// - `RecursiveVerify` (§6.2.1.4 line 415; §8.5 recursive circuit
///   signature) — depends on Halo 2 recursion + §8.5 substantive
///   circuit-signature pinning
/// - `ReleaseSubViewKey` (§6.2.1.4 line 412; §7.4.2 derivation)
///   — depends on §7.4.2 `G_aux` pinning (spec-first verification
///   25th instance candidate) + adamant-crypto-blst-extra public-
///   API expansion (hash-to-scalar helper)
///
/// `CircuitId` pool placement is itself a §7 carry-forward per
/// §6.2.1.4 amendment 0d3a957 footnote ("the resolution from
/// index to circuit definition is the privacy layer's concern").
///
/// Deferred to 5/6.5 (gas accounting):
/// - `ChargeGas`, `RemainingGas`, `OutOfGas`
///
/// Deferred handlers surface `InvalidInstruction` (verifier-residual
/// posture: the verifier admits these but the runtime backing isn't
/// ready). Modules using deferred extensions cannot be deployed
/// until the corresponding sub-arc lands the handler.
#[allow(
    clippy::too_many_lines,
    reason = "single match on AdamantBytecode covers the full extension instruction set; per-handler arms are small but the count of branches is structurally large"
)]
fn dispatch_adamant(
    opcode: &crate::bytecode::AdamantBytecode,
    state: &mut InterpreterState,
) -> Result<DispatchOutcome, VMError> {
    use crate::bytecode::AdamantBytecode as AB;
    match opcode {
        // ---------- Frame-creation handlers (Phase 5/6.3) ----------
        AB::InvokeShielded(handle) => {
            let frame = top_frame_mut(state)?;
            advance_pc(frame);
            Ok(DispatchOutcome::InvokeShielded(*handle))
        }
        AB::InvokeTransparent(handle) => {
            let frame = top_frame_mut(state)?;
            advance_pc(frame);
            Ok(DispatchOutcome::InvokeTransparent(*handle))
        }

        // ---------- Hash handlers (Phase 5/6.3) ----------
        AB::Sha3_256 => dispatch_sha3_256(state),
        AB::Blake3 => dispatch_blake3(state),

        // ---------- Signature handlers (Phase 5/6.3) ----------
        AB::Ed25519Verify => dispatch_ed25519_verify(state),
        AB::MlDsaVerify65 => dispatch_ml_dsa_verify_65(state),
        AB::BlsVerify => dispatch_bls_verify(state),

        // ---------- Gas handlers (Phase 5/6.5) ----------
        AB::ChargeGas(dim) => dispatch_charge_gas(state, *dim),
        AB::RemainingGas(dim) => dispatch_remaining_gas(state, *dim),
        AB::OutOfGas => dispatch_out_of_gas(state),

        // ---------- Sub-view-key derivation (Phase 5/6.4.b) ----------
        AB::ReleaseSubViewKey => dispatch_release_sub_view_key(state),

        // ---------- KZG handlers (Phase 5/6.7) ----------
        AB::KzgCommit => dispatch_kzg_commit(state),
        AB::KzgVerify => dispatch_kzg_verify(state),

        // ---------- Deferred handlers ----------
        // GenerateProof / VerifyProof / RecursiveVerify defer to
        // Phase 6.8b.4f / 6.9b alongside §7's `CircuitId`
        // resolution and §8.5.2's recursive verifier circuit.
        // MlKemEncapsulate / MlKemDecapsulate defer to Phase 6
        // alongside §7's privacy-circuit deterministic-randomness
        // sourcing — encapsulation requires randomness whose
        // source is §7-specified per §6.2.4 determinism.
        AB::GenerateProof(_)
        | AB::VerifyProof(_)
        | AB::RecursiveVerify
        | AB::MlKemEncapsulate
        | AB::MlKemDecapsulate => {
            let frame = state
                .top_frame()
                .expect("dispatch_adamant caller-contract: call stack non-empty");
            Err(VMError::InvalidInstruction {
                function_handle: frame.function_handle,
                pc: frame.pc,
            })
        }
    }
}

/// Dispatch an inherited Sui-Move opcode. Per Phase 5/6.2b plan-
/// gate, the 38 self-contained handlers (no module access required)
/// land at this sub-arc; the remaining 38 module-access handlers
/// land at 5/6.2c. Self-contained handlers operate purely on the
/// frame's operand stack, locals, and pc.
///
/// Deprecated global-storage opcodes (10 variants per
/// `Bytecode::*Deprecated`) surface as
/// `InvariantViolation { DeprecatedOpcodePostVerification }` per
/// the verifier-residual posture: parse-time deserializer rejects
/// these per Rule 5; reaching runtime indicates parser unsoundness
/// or post-deployment bytecode modification.
#[allow(
    clippy::too_many_lines,
    reason = "single match on Bytecode covers 76 variants per Phase 5/6.2b dispatch design; per-handler branches are small and self-contained, but the count of branches is structurally large"
)]
fn dispatch_inherited(
    opcode: &Bytecode,
    state: &mut InterpreterState,
    module: &AdamantCompiledModule,
) -> Result<DispatchOutcome, VMError> {
    match opcode {
        // ---------- Stack / control flow ----------
        Bytecode::Pop => {
            let frame = top_frame_mut(state)?;
            frame.pop_value()?;
            advance_pc(frame);
            Ok(DispatchOutcome::Continue)
        }
        Bytecode::Ret => {
            // Per whitepaper §6.2.2 step 5 ("Bytecode runs to
            // completion") + §6.2.1.4 stack-based architecture:
            // Ret pops the current frame from the call stack.
            // When the call stack becomes empty after this pop,
            // execution has run to completion.
            state
                .pop_frame()
                .expect("dispatch_inherited caller-contract: call stack must be non-empty");
            if state.is_empty() {
                Ok(DispatchOutcome::Halt)
            } else {
                // Returning to caller frame; continue dispatch.
                // Frame's pc was previously advanced past the
                // Call instruction by 5/6.2c's Call handler
                // before the new frame was pushed (5/6.2c
                // forward).
                Ok(DispatchOutcome::Continue)
            }
        }
        Bytecode::Branch(target) => {
            let frame = top_frame_mut(state)?;
            frame.pc = *target;
            Ok(DispatchOutcome::Continue)
        }
        Bytecode::BrTrue(target) => {
            let frame = top_frame_mut(state)?;
            let cond = frame.pop_bool()?;
            if cond {
                frame.pc = *target;
            } else {
                advance_pc(frame);
            }
            Ok(DispatchOutcome::Continue)
        }
        Bytecode::BrFalse(target) => {
            let frame = top_frame_mut(state)?;
            let cond = frame.pop_bool()?;
            if cond {
                advance_pc(frame);
            } else {
                frame.pc = *target;
            }
            Ok(DispatchOutcome::Continue)
        }

        // ---------- Literal load (immediates only; LdConst defers to 5/6.2c) ----------
        Bytecode::LdU8(v) => push_and_continue(state, RuntimeValue::U8(*v)),
        Bytecode::LdU16(v) => push_and_continue(state, RuntimeValue::U16(*v)),
        Bytecode::LdU32(v) => push_and_continue(state, RuntimeValue::U32(*v)),
        Bytecode::LdU64(v) => push_and_continue(state, RuntimeValue::U64(*v)),
        Bytecode::LdU128(v) => push_and_continue(state, RuntimeValue::U128(**v)),
        Bytecode::LdU256(v) => push_and_continue(state, RuntimeValue::U256(v.to_le_bytes())),
        Bytecode::LdTrue => push_and_continue(state, RuntimeValue::Bool(true)),
        Bytecode::LdFalse => push_and_continue(state, RuntimeValue::Bool(false)),

        // ---------- Cast (§6.2.1.9 cast semantics) ----------
        Bytecode::CastU8 => dispatch_cast_u8(state),
        Bytecode::CastU16 => dispatch_cast_u16(state),
        Bytecode::CastU32 => dispatch_cast_u32(state),
        Bytecode::CastU64 => dispatch_cast_u64(state),
        Bytecode::CastU128 => dispatch_cast_u128(state),
        Bytecode::CastU256 => dispatch_cast_u256(state),

        // ---------- Locals access ----------
        Bytecode::CopyLoc(idx) => {
            let frame = top_frame_mut(state)?;
            let value = frame.copy_loc(*idx)?;
            frame.push_value(value);
            advance_pc(frame);
            Ok(DispatchOutcome::Continue)
        }
        Bytecode::MoveLoc(idx) => {
            let frame = top_frame_mut(state)?;
            let value = frame.move_loc(*idx)?;
            frame.push_value(value);
            advance_pc(frame);
            Ok(DispatchOutcome::Continue)
        }
        Bytecode::StLoc(idx) => {
            let frame = top_frame_mut(state)?;
            let value = frame.pop_value()?;
            frame.st_loc(*idx, value)?;
            advance_pc(frame);
            Ok(DispatchOutcome::Continue)
        }

        // ---------- Arithmetic (§6.2.1.9 overflow handling) ----------
        Bytecode::Add => dispatch_arith(state, ArithOp::Add),
        Bytecode::Sub => dispatch_arith(state, ArithOp::Sub),
        Bytecode::Mul => dispatch_arith(state, ArithOp::Mul),
        Bytecode::Div => dispatch_arith(state, ArithOp::Div),
        Bytecode::Mod => dispatch_arith(state, ArithOp::Mod),

        // ---------- Bitwise ----------
        Bytecode::BitAnd => dispatch_bitop(state, BitOp::And),
        Bytecode::BitOr => dispatch_bitop(state, BitOp::Or),
        Bytecode::Xor => dispatch_bitop(state, BitOp::Xor),

        // ---------- Logic ----------
        Bytecode::And => {
            let frame = top_frame_mut(state)?;
            let rhs = frame.pop_bool()?;
            let lhs = frame.pop_bool()?;
            frame.push_value(RuntimeValue::Bool(lhs && rhs));
            advance_pc(frame);
            Ok(DispatchOutcome::Continue)
        }
        Bytecode::Or => {
            let frame = top_frame_mut(state)?;
            let rhs = frame.pop_bool()?;
            let lhs = frame.pop_bool()?;
            frame.push_value(RuntimeValue::Bool(lhs || rhs));
            advance_pc(frame);
            Ok(DispatchOutcome::Continue)
        }
        Bytecode::Not => {
            let frame = top_frame_mut(state)?;
            let v = frame.pop_bool()?;
            frame.push_value(RuntimeValue::Bool(!v));
            advance_pc(frame);
            Ok(DispatchOutcome::Continue)
        }

        // ---------- Comparison (§6.2.1.9 unsigned comparison) ----------
        Bytecode::Eq => dispatch_eq(state, false),
        Bytecode::Neq => dispatch_eq(state, true),
        Bytecode::Lt => dispatch_cmp(state, CmpOp::Lt),
        Bytecode::Gt => dispatch_cmp(state, CmpOp::Gt),
        Bytecode::Le => dispatch_cmp(state, CmpOp::Le),
        Bytecode::Ge => dispatch_cmp(state, CmpOp::Ge),

        // ---------- Shifts (§6.2.1.9 shift bounds) ----------
        Bytecode::Shl => dispatch_shift(state, ShiftDir::Left),
        Bytecode::Shr => dispatch_shift(state, ShiftDir::Right),

        // ---------- Misc ----------
        Bytecode::Abort => {
            // Abort consumes its u64 abort code per §6.2.1.4
            // ("Abort with an error code"). Phase 5/6.5 refines
            // the prior placeholder into VMError::AbortError with
            // AbortReason::UserAbort { code } per Q5/6.5.3
            // disposition. The abort code is the user-provided
            // value from the bytecode's preceding LdU64 / LdConst
            // (already public per Move semantics; no privacy
            // leak).
            let frame = top_frame_mut(state)?;
            let code = frame.pop_u64()?;
            Err(VMError::AbortError {
                reason: AbortReason::UserAbort { code },
            })
        }
        Bytecode::Nop => {
            let frame = top_frame_mut(state)?;
            advance_pc(frame);
            Ok(DispatchOutcome::Continue)
        }

        // ---------- Deprecated global-storage opcodes (Rule 5) ----------
        Bytecode::ExistsDeprecated(_)
        | Bytecode::ExistsGenericDeprecated(_)
        | Bytecode::MoveFromDeprecated(_)
        | Bytecode::MoveFromGenericDeprecated(_)
        | Bytecode::MoveToDeprecated(_)
        | Bytecode::MoveToGenericDeprecated(_)
        | Bytecode::MutBorrowGlobalDeprecated(_)
        | Bytecode::MutBorrowGlobalGenericDeprecated(_)
        | Bytecode::ImmBorrowGlobalDeprecated(_)
        | Bytecode::ImmBorrowGlobalGenericDeprecated(_) => Err(VMError::InvariantViolation {
            reason: InvariantViolationReason::DeprecatedOpcodePostVerification,
        }),

        // ---------- Module-access handlers (Phase 5/6.2c.2.α) ----------
        Bytecode::LdConst(idx) => dispatch_ld_const(state, module, *idx),
        Bytecode::Call(idx) => {
            // Per Q5/6.2c.2.2 frame-creation outer-driver pattern:
            // dispatch advances pc past Call before signaling
            // frame-creation to the outer driver. When the callee
            // Returns, control resumes at caller's next instruction.
            let frame = top_frame_mut(state)?;
            advance_pc(frame);
            Ok(DispatchOutcome::Call(*idx))
        }
        Bytecode::CallGeneric(idx) => {
            let frame = top_frame_mut(state)?;
            advance_pc(frame);
            Ok(DispatchOutcome::CallGeneric(*idx))
        }

        // ---------- Reference-machinery handlers (Phase 5/6.2c.2.β) ----------
        Bytecode::ImmBorrowLoc(idx) | Bytecode::MutBorrowLoc(idx) => {
            // Per whitepaper §6.2.1.4: "Load a [mutable|immutable]
            // reference to a local." FreezeRef is a runtime no-op
            // (verifier-validated mut/immut distinction); the
            // handler shape is identical for both opcodes.
            let frame = top_frame_mut(state)?;
            let reference = frame.borrow_loc(*idx)?;
            frame.push_value(RuntimeValue::Reference(reference));
            advance_pc(frame);
            Ok(DispatchOutcome::Continue)
        }
        Bytecode::ImmBorrowField(handle_idx) | Bytecode::MutBorrowField(handle_idx) => {
            let field_offset =
                crate::runtime::module_helpers::resolve_field_offset(module, *handle_idx)?;
            let frame = top_frame_mut(state)?;
            let parent_ref = frame.pop_reference()?;
            let field_ref = parent_ref.borrow_field(field_offset)?;
            frame.push_value(RuntimeValue::Reference(field_ref));
            advance_pc(frame);
            Ok(DispatchOutcome::Continue)
        }
        Bytecode::ImmBorrowFieldGeneric(inst_idx) | Bytecode::MutBorrowFieldGeneric(inst_idx) => {
            // Resolve through field_instantiations to the underlying
            // FieldHandleIndex, then use the same path.
            let inst = module.field_instantiations.get(inst_idx.0 as usize).ok_or(
                VMError::InvariantViolation {
                    reason: InvariantViolationReason::IndexOutOfBoundsPostVerification,
                },
            )?;
            let field_offset =
                crate::runtime::module_helpers::resolve_field_offset(module, inst.handle)?;
            let frame = top_frame_mut(state)?;
            let parent_ref = frame.pop_reference()?;
            let field_ref = parent_ref.borrow_field(field_offset)?;
            frame.push_value(RuntimeValue::Reference(field_ref));
            advance_pc(frame);
            Ok(DispatchOutcome::Continue)
        }
        Bytecode::ReadRef => {
            let frame = top_frame_mut(state)?;
            let reference = frame.pop_reference()?;
            let value = reference.read_ref()?;
            frame.push_value(value);
            advance_pc(frame);
            Ok(DispatchOutcome::Continue)
        }
        Bytecode::WriteRef => {
            // Per Sui-VM stack order: WriteRef pops the reference
            // (top), then the value (next). Validated against
            // 5/6.2a F-2 retroactive-promotion fixture shape.
            let frame = top_frame_mut(state)?;
            let reference = frame.pop_reference()?;
            let value = frame.pop_value()?;
            reference.write_ref(value)?;
            advance_pc(frame);
            Ok(DispatchOutcome::Continue)
        }
        Bytecode::FreezeRef => {
            // FreezeRef is a runtime no-op per the Sui-VM source
            // quote at commit a9a6825eaf6273cc819ee3bcf65fd4909f7624a9
            // ("FreezeRef should just be a null op as we don't
            // distinguish between mut and immut ref at runtime").
            // The verifier statically validates mut/immut
            // distinctions; the runtime carries no per-reference
            // mutability tag. Just advance pc.
            let frame = top_frame_mut(state)?;
            advance_pc(frame);
            Ok(DispatchOutcome::Continue)
        }
        Bytecode::VecImmBorrow(_sig_idx) | Bytecode::VecMutBorrow(_sig_idx) => {
            // VecImmBorrow / VecMutBorrow per whitepaper §6.2.1.4:
            // "Immutable borrow of a vector element" / "Mutable
            // borrow of a vector element." Pops the index (u64)
            // and the vector reference; pushes an element
            // reference. Imm/Mut distinction is verifier-only.
            let frame = top_frame_mut(state)?;
            let idx = frame.pop_u64()?;
            let vec_ref = frame.pop_reference()?;
            // Convert u64 idx to usize for indexing. On 64-bit
            // targets the cast is lossless; on 32-bit targets
            // verifier-validated index bounds keep idx within
            // u32 range for concrete vectors. Defensive: if
            // truncation surfaces a wrong index, the borrow_element
            // bounds check returns IndexOutOfBoundsPostVerification.
            let idx_usize = usize::try_from(idx).map_err(|_| VMError::InvariantViolation {
                reason: InvariantViolationReason::IndexOutOfBoundsPostVerification,
            })?;
            let elem_ref = vec_ref.borrow_element(idx_usize)?;
            frame.push_value(RuntimeValue::Reference(elem_ref));
            advance_pc(frame);
            Ok(DispatchOutcome::Continue)
        }

        // ---------- Struct ops (Phase 5/6.2c.2.γ-merged) ----------
        Bytecode::Pack(struct_def_idx) => dispatch_pack(state, module, *struct_def_idx),
        Bytecode::PackGeneric(inst_idx) => {
            let struct_def_idx = crate::runtime::module_helpers::resolve_struct_def_instantiation(
                module, *inst_idx,
            )?;
            dispatch_pack(state, module, struct_def_idx)
        }
        Bytecode::Unpack(struct_def_idx) => dispatch_unpack(state, module, *struct_def_idx),
        Bytecode::UnpackGeneric(inst_idx) => {
            let struct_def_idx = crate::runtime::module_helpers::resolve_struct_def_instantiation(
                module, *inst_idx,
            )?;
            dispatch_unpack(state, module, struct_def_idx)
        }

        // ---------- Vector ops (Phase 5/6.2c.2.γ-merged) ----------
        Bytecode::VecPack(_sig_idx, n) => dispatch_vec_pack(state, *n),
        Bytecode::VecLen(_sig_idx) => dispatch_vec_len(state),
        Bytecode::VecPushBack(_sig_idx) => dispatch_vec_push_back(state),
        Bytecode::VecPopBack(_sig_idx) => dispatch_vec_pop_back(state),
        Bytecode::VecUnpack(_sig_idx, n) => dispatch_vec_unpack(state, *n),
        Bytecode::VecSwap(_sig_idx) => dispatch_vec_swap(state),

        // ---------- Variant ops (Phase 5/6.2c.2.γ-merged) ----------
        Bytecode::PackVariant(handle_idx) => dispatch_pack_variant(state, module, *handle_idx),
        Bytecode::PackVariantGeneric(inst_idx) => {
            let (enum_def_idx, tag) =
                crate::runtime::module_helpers::resolve_variant_instantiation_handle(
                    module, *inst_idx,
                )?;
            dispatch_pack_variant_inner(state, module, enum_def_idx, tag)
        }
        Bytecode::UnpackVariant(handle_idx) => {
            dispatch_unpack_variant(state, module, *handle_idx, UnpackVariantMode::Owned)
        }
        Bytecode::UnpackVariantImmRef(handle_idx) | Bytecode::UnpackVariantMutRef(handle_idx) => {
            dispatch_unpack_variant(state, module, *handle_idx, UnpackVariantMode::ByRef)
        }
        Bytecode::UnpackVariantGeneric(inst_idx) => {
            let (enum_def_idx, tag) =
                crate::runtime::module_helpers::resolve_variant_instantiation_handle(
                    module, *inst_idx,
                )?;
            dispatch_unpack_variant_inner(state, enum_def_idx, tag, UnpackVariantMode::Owned)
        }
        Bytecode::UnpackVariantGenericImmRef(inst_idx)
        | Bytecode::UnpackVariantGenericMutRef(inst_idx) => {
            let (enum_def_idx, tag) =
                crate::runtime::module_helpers::resolve_variant_instantiation_handle(
                    module, *inst_idx,
                )?;
            dispatch_unpack_variant_inner(state, enum_def_idx, tag, UnpackVariantMode::ByRef)
        }
        Bytecode::VariantSwitch(jt_idx) => dispatch_variant_switch(state, module, *jt_idx),
    }
}

// ---------- helper functions ----------

/// Borrow the top frame mutably, surfacing
/// `InvariantViolation::StackUnderflow` if the call stack is empty
/// (this case is structurally unreachable when called from
/// [`dispatch_instruction`] which itself requires a non-empty
/// stack via the run loop's check; the helper preserves the
/// invariant defensively).
fn top_frame_mut(state: &mut InterpreterState) -> Result<&mut Frame, VMError> {
    state.top_frame_mut().ok_or(VMError::InvariantViolation {
        reason: InvariantViolationReason::StackUnderflow,
    })
}

/// Advance the program counter by 1 (the default for non-branch,
/// non-return instructions).
fn advance_pc(frame: &mut Frame) {
    frame.pc = frame.pc.wrapping_add(1);
}

/// Push a value and advance pc. Used by the literal-load handlers
/// which all share the same shape: push immediate, advance pc.
fn push_and_continue(
    state: &mut InterpreterState,
    value: RuntimeValue,
) -> Result<DispatchOutcome, VMError> {
    let frame = top_frame_mut(state)?;
    frame.push_value(value);
    advance_pc(frame);
    Ok(DispatchOutcome::Continue)
}

#[derive(Clone, Copy)]
enum ArithOp {
    Add,
    Sub,
    Mul,
    Div,
    Mod,
}

#[derive(Clone, Copy)]
enum BitOp {
    And,
    Or,
    Xor,
}

#[derive(Clone, Copy)]
enum CmpOp {
    Lt,
    Gt,
    Le,
    Ge,
}

#[derive(Clone, Copy)]
enum ShiftDir {
    Left,
    Right,
}

/// Dispatch arithmetic operations across the 6 unsigned integer
/// widths per §6.2.1.9 overflow handling.
fn dispatch_arith(state: &mut InterpreterState, op: ArithOp) -> Result<DispatchOutcome, VMError> {
    let frame = top_frame_mut(state)?;
    let rhs = frame.pop_value()?;
    let lhs = frame.pop_value()?;
    let result = match (lhs, rhs) {
        (RuntimeValue::U8(a), RuntimeValue::U8(b)) => RuntimeValue::U8(arith_u8(a, b, op)?),
        (RuntimeValue::U16(a), RuntimeValue::U16(b)) => RuntimeValue::U16(arith_u16(a, b, op)?),
        (RuntimeValue::U32(a), RuntimeValue::U32(b)) => RuntimeValue::U32(arith_u32(a, b, op)?),
        (RuntimeValue::U64(a), RuntimeValue::U64(b)) => RuntimeValue::U64(arith_u64(a, b, op)?),
        (RuntimeValue::U128(a), RuntimeValue::U128(b)) => RuntimeValue::U128(arith_u128(a, b, op)?),
        (RuntimeValue::U256(a), RuntimeValue::U256(b)) => RuntimeValue::U256(arith_u256(a, b, op)?),
        _ => {
            return Err(VMError::InvariantViolation {
                reason: InvariantViolationReason::TypeMismatchOnStack,
            });
        }
    };
    frame.push_value(result);
    advance_pc(frame);
    Ok(DispatchOutcome::Continue)
}

fn arith_u8(a: u8, b: u8, op: ArithOp) -> Result<u8, VMError> {
    match op {
        ArithOp::Add => a.checked_add(b).ok_or(VMError::ArithmeticError {
            reason: ArithmeticErrorReason::Overflow,
        }),
        ArithOp::Sub => a.checked_sub(b).ok_or(VMError::ArithmeticError {
            reason: ArithmeticErrorReason::Underflow,
        }),
        ArithOp::Mul => a.checked_mul(b).ok_or(VMError::ArithmeticError {
            reason: ArithmeticErrorReason::Overflow,
        }),
        ArithOp::Div => a.checked_div(b).ok_or(VMError::ArithmeticError {
            reason: ArithmeticErrorReason::DivisionByZero,
        }),
        ArithOp::Mod => a.checked_rem(b).ok_or(VMError::ArithmeticError {
            reason: ArithmeticErrorReason::DivisionByZero,
        }),
    }
}

fn arith_u16(a: u16, b: u16, op: ArithOp) -> Result<u16, VMError> {
    match op {
        ArithOp::Add => a.checked_add(b).ok_or(VMError::ArithmeticError {
            reason: ArithmeticErrorReason::Overflow,
        }),
        ArithOp::Sub => a.checked_sub(b).ok_or(VMError::ArithmeticError {
            reason: ArithmeticErrorReason::Underflow,
        }),
        ArithOp::Mul => a.checked_mul(b).ok_or(VMError::ArithmeticError {
            reason: ArithmeticErrorReason::Overflow,
        }),
        ArithOp::Div => a.checked_div(b).ok_or(VMError::ArithmeticError {
            reason: ArithmeticErrorReason::DivisionByZero,
        }),
        ArithOp::Mod => a.checked_rem(b).ok_or(VMError::ArithmeticError {
            reason: ArithmeticErrorReason::DivisionByZero,
        }),
    }
}

fn arith_u32(a: u32, b: u32, op: ArithOp) -> Result<u32, VMError> {
    match op {
        ArithOp::Add => a.checked_add(b).ok_or(VMError::ArithmeticError {
            reason: ArithmeticErrorReason::Overflow,
        }),
        ArithOp::Sub => a.checked_sub(b).ok_or(VMError::ArithmeticError {
            reason: ArithmeticErrorReason::Underflow,
        }),
        ArithOp::Mul => a.checked_mul(b).ok_or(VMError::ArithmeticError {
            reason: ArithmeticErrorReason::Overflow,
        }),
        ArithOp::Div => a.checked_div(b).ok_or(VMError::ArithmeticError {
            reason: ArithmeticErrorReason::DivisionByZero,
        }),
        ArithOp::Mod => a.checked_rem(b).ok_or(VMError::ArithmeticError {
            reason: ArithmeticErrorReason::DivisionByZero,
        }),
    }
}

fn arith_u64(a: u64, b: u64, op: ArithOp) -> Result<u64, VMError> {
    match op {
        ArithOp::Add => a.checked_add(b).ok_or(VMError::ArithmeticError {
            reason: ArithmeticErrorReason::Overflow,
        }),
        ArithOp::Sub => a.checked_sub(b).ok_or(VMError::ArithmeticError {
            reason: ArithmeticErrorReason::Underflow,
        }),
        ArithOp::Mul => a.checked_mul(b).ok_or(VMError::ArithmeticError {
            reason: ArithmeticErrorReason::Overflow,
        }),
        ArithOp::Div => a.checked_div(b).ok_or(VMError::ArithmeticError {
            reason: ArithmeticErrorReason::DivisionByZero,
        }),
        ArithOp::Mod => a.checked_rem(b).ok_or(VMError::ArithmeticError {
            reason: ArithmeticErrorReason::DivisionByZero,
        }),
    }
}

fn arith_u128(a: u128, b: u128, op: ArithOp) -> Result<u128, VMError> {
    match op {
        ArithOp::Add => a.checked_add(b).ok_or(VMError::ArithmeticError {
            reason: ArithmeticErrorReason::Overflow,
        }),
        ArithOp::Sub => a.checked_sub(b).ok_or(VMError::ArithmeticError {
            reason: ArithmeticErrorReason::Underflow,
        }),
        ArithOp::Mul => a.checked_mul(b).ok_or(VMError::ArithmeticError {
            reason: ArithmeticErrorReason::Overflow,
        }),
        ArithOp::Div => a.checked_div(b).ok_or(VMError::ArithmeticError {
            reason: ArithmeticErrorReason::DivisionByZero,
        }),
        ArithOp::Mod => a.checked_rem(b).ok_or(VMError::ArithmeticError {
            reason: ArithmeticErrorReason::DivisionByZero,
        }),
    }
}

/// `u256` arithmetic delegates to `adamant_bytecode_format::U256`
/// per Phase 5/6.2a's in-repo implementation. The runtime converts
/// `[u8; 32]` ↔ `FormatU256` at the operand boundary.
fn arith_u256(a: [u8; 32], b: [u8; 32], op: ArithOp) -> Result<[u8; 32], VMError> {
    let a = FormatU256::from_le_bytes(a);
    let b = FormatU256::from_le_bytes(b);
    let result = match op {
        ArithOp::Add => a.checked_add(b).ok_or(VMError::ArithmeticError {
            reason: ArithmeticErrorReason::Overflow,
        })?,
        ArithOp::Sub => a.checked_sub(b).ok_or(VMError::ArithmeticError {
            reason: ArithmeticErrorReason::Underflow,
        })?,
        ArithOp::Mul => a.checked_mul(b).ok_or(VMError::ArithmeticError {
            reason: ArithmeticErrorReason::Overflow,
        })?,
        ArithOp::Div => a.checked_div(b).ok_or(VMError::ArithmeticError {
            reason: ArithmeticErrorReason::DivisionByZero,
        })?,
        ArithOp::Mod => a.checked_rem(b).ok_or(VMError::ArithmeticError {
            reason: ArithmeticErrorReason::DivisionByZero,
        })?,
    };
    Ok(result.to_le_bytes())
}

/// Bitwise ops dispatch across integer widths. No abort
/// conditions per §6.2.1.9.
fn dispatch_bitop(state: &mut InterpreterState, op: BitOp) -> Result<DispatchOutcome, VMError> {
    let frame = top_frame_mut(state)?;
    let rhs = frame.pop_value()?;
    let lhs = frame.pop_value()?;
    let result = match (lhs, rhs) {
        (RuntimeValue::U8(a), RuntimeValue::U8(b)) => RuntimeValue::U8(bitop_u8(a, b, op)),
        (RuntimeValue::U16(a), RuntimeValue::U16(b)) => RuntimeValue::U16(bitop_u16(a, b, op)),
        (RuntimeValue::U32(a), RuntimeValue::U32(b)) => RuntimeValue::U32(bitop_u32(a, b, op)),
        (RuntimeValue::U64(a), RuntimeValue::U64(b)) => RuntimeValue::U64(bitop_u64(a, b, op)),
        (RuntimeValue::U128(a), RuntimeValue::U128(b)) => RuntimeValue::U128(bitop_u128(a, b, op)),
        (RuntimeValue::U256(a), RuntimeValue::U256(b)) => {
            let a = FormatU256::from_le_bytes(a);
            let b = FormatU256::from_le_bytes(b);
            let r = match op {
                BitOp::And => a & b,
                BitOp::Or => a | b,
                BitOp::Xor => a ^ b,
            };
            RuntimeValue::U256(r.to_le_bytes())
        }
        _ => {
            return Err(VMError::InvariantViolation {
                reason: InvariantViolationReason::TypeMismatchOnStack,
            });
        }
    };
    frame.push_value(result);
    advance_pc(frame);
    Ok(DispatchOutcome::Continue)
}

fn bitop_u8(a: u8, b: u8, op: BitOp) -> u8 {
    match op {
        BitOp::And => a & b,
        BitOp::Or => a | b,
        BitOp::Xor => a ^ b,
    }
}
fn bitop_u16(a: u16, b: u16, op: BitOp) -> u16 {
    match op {
        BitOp::And => a & b,
        BitOp::Or => a | b,
        BitOp::Xor => a ^ b,
    }
}
fn bitop_u32(a: u32, b: u32, op: BitOp) -> u32 {
    match op {
        BitOp::And => a & b,
        BitOp::Or => a | b,
        BitOp::Xor => a ^ b,
    }
}
fn bitop_u64(a: u64, b: u64, op: BitOp) -> u64 {
    match op {
        BitOp::And => a & b,
        BitOp::Or => a | b,
        BitOp::Xor => a ^ b,
    }
}
fn bitop_u128(a: u128, b: u128, op: BitOp) -> u128 {
    match op {
        BitOp::And => a & b,
        BitOp::Or => a | b,
        BitOp::Xor => a ^ b,
    }
}

/// Equality dispatch per §6.2.1.9 equality semantics. `Eq` and
/// `Neq` compare any two values of the same type via byte-
/// identity at the runtime representation level (recursing into
/// struct fields and vector elements). The verifier's
/// `type_safety` pass ensures both operands have the same type
/// (with the `Eq` ability for struct types).
fn dispatch_eq(state: &mut InterpreterState, negate: bool) -> Result<DispatchOutcome, VMError> {
    let frame = top_frame_mut(state)?;
    let rhs = frame.pop_value()?;
    let lhs = frame.pop_value()?;
    // Value implements PartialEq via #[derive(PartialEq)] on the
    // enum, which recurses into fields per Rust's structural-eq
    // rules. This matches whitepaper §6.2.1.9: "byte-identity is
    // computed field-wise and recurses into nested structs."
    let equal = lhs == rhs;
    let result = if negate { !equal } else { equal };
    frame.push_value(RuntimeValue::Bool(result));
    advance_pc(frame);
    Ok(DispatchOutcome::Continue)
}

/// Comparison dispatch per §6.2.1.9 unsigned comparison ordering.
/// `Lt` / `Gt` / `Le` / `Ge` operate only on integer widths;
/// `Bool` / `Struct` / etc. land as `TypeMismatchOnStack`
/// (verifier-residual; `type_safety` pass should pre-empt).
fn dispatch_cmp(state: &mut InterpreterState, op: CmpOp) -> Result<DispatchOutcome, VMError> {
    let frame = top_frame_mut(state)?;
    let rhs = frame.pop_value()?;
    let lhs = frame.pop_value()?;
    let result = match (lhs, rhs) {
        (RuntimeValue::U8(a), RuntimeValue::U8(b)) => cmp_apply(a.cmp(&b), op),
        (RuntimeValue::U16(a), RuntimeValue::U16(b)) => cmp_apply(a.cmp(&b), op),
        (RuntimeValue::U32(a), RuntimeValue::U32(b)) => cmp_apply(a.cmp(&b), op),
        (RuntimeValue::U64(a), RuntimeValue::U64(b)) => cmp_apply(a.cmp(&b), op),
        (RuntimeValue::U128(a), RuntimeValue::U128(b)) => cmp_apply(a.cmp(&b), op),
        (RuntimeValue::U256(a), RuntimeValue::U256(b)) => {
            // U256 comparison via the manual MSB-first impl on
            // adamant_bytecode_format::U256 (Phase 5/6.2a). Per
            // §6.2.1.9 unsigned comparison ordering.
            let a = FormatU256::from_le_bytes(a);
            let b = FormatU256::from_le_bytes(b);
            cmp_apply(a.cmp(&b), op)
        }
        _ => {
            return Err(VMError::InvariantViolation {
                reason: InvariantViolationReason::TypeMismatchOnStack,
            });
        }
    };
    frame.push_value(RuntimeValue::Bool(result));
    advance_pc(frame);
    Ok(DispatchOutcome::Continue)
}

fn cmp_apply(ord: core::cmp::Ordering, op: CmpOp) -> bool {
    use core::cmp::Ordering::{Equal, Greater, Less};
    matches!(
        (op, ord),
        (CmpOp::Lt, Less)
            | (CmpOp::Gt, Greater)
            | (CmpOp::Le, Less | Equal)
            | (CmpOp::Ge, Greater | Equal)
    )
}

/// Shift dispatch per §6.2.1.9 shift amount bounds. For U8-U128,
/// shift amount >= bit width aborts with `ShiftAmountTooLarge`.
/// For `u256`, the abort is structurally unreachable (`n_bits`
/// is `u8` in `[0, 255]`, always less than `256 = bit_width`).
fn dispatch_shift(state: &mut InterpreterState, dir: ShiftDir) -> Result<DispatchOutcome, VMError> {
    let frame = top_frame_mut(state)?;
    let n_bits = frame.pop_u8()?;
    let lhs = frame.pop_value()?;
    let result = match lhs {
        RuntimeValue::U8(a) => {
            if n_bits >= 8 {
                return Err(VMError::ArithmeticError {
                    reason: ArithmeticErrorReason::ShiftAmountTooLarge,
                });
            }
            RuntimeValue::U8(match dir {
                ShiftDir::Left => a << n_bits,
                ShiftDir::Right => a >> n_bits,
            })
        }
        RuntimeValue::U16(a) => {
            if n_bits >= 16 {
                return Err(VMError::ArithmeticError {
                    reason: ArithmeticErrorReason::ShiftAmountTooLarge,
                });
            }
            RuntimeValue::U16(match dir {
                ShiftDir::Left => a << n_bits,
                ShiftDir::Right => a >> n_bits,
            })
        }
        RuntimeValue::U32(a) => {
            if n_bits >= 32 {
                return Err(VMError::ArithmeticError {
                    reason: ArithmeticErrorReason::ShiftAmountTooLarge,
                });
            }
            RuntimeValue::U32(match dir {
                ShiftDir::Left => a << n_bits,
                ShiftDir::Right => a >> n_bits,
            })
        }
        RuntimeValue::U64(a) => {
            if n_bits >= 64 {
                return Err(VMError::ArithmeticError {
                    reason: ArithmeticErrorReason::ShiftAmountTooLarge,
                });
            }
            RuntimeValue::U64(match dir {
                ShiftDir::Left => a << n_bits,
                ShiftDir::Right => a >> n_bits,
            })
        }
        RuntimeValue::U128(a) => {
            if n_bits >= 128 {
                return Err(VMError::ArithmeticError {
                    reason: ArithmeticErrorReason::ShiftAmountTooLarge,
                });
            }
            RuntimeValue::U128(match dir {
                ShiftDir::Left => a << n_bits,
                ShiftDir::Right => a >> n_bits,
            })
        }
        RuntimeValue::U256(a) => {
            // u256 shift: no abort condition. n_bits is u8; max
            // 255 < 256 = bit_width. The abort check is structurally
            // unreachable per §6.2.1.9.
            let a = FormatU256::from_le_bytes(a);
            let r = match dir {
                ShiftDir::Left => a << n_bits,
                ShiftDir::Right => a >> n_bits,
            };
            RuntimeValue::U256(r.to_le_bytes())
        }
        _ => {
            return Err(VMError::InvariantViolation {
                reason: InvariantViolationReason::TypeMismatchOnStack,
            });
        }
    };
    frame.push_value(result);
    advance_pc(frame);
    Ok(DispatchOutcome::Continue)
}

// ---------- Cast handlers (§6.2.1.9 cast semantics) ----------
//
// Each CastUN handler narrows or widens the top-of-stack value to
// the named integer type per §6.2.1.9:
// - Same-type cast: succeeds (identity)
// - Widening cast: succeeds (zero-extension)
// - Narrowing cast: succeeds when source value fits in destination
//   range; aborts CastNotRepresentable otherwise.

fn dispatch_cast_u8(state: &mut InterpreterState) -> Result<DispatchOutcome, VMError> {
    let frame = top_frame_mut(state)?;
    let v = frame.pop_value()?;
    let result = match v {
        RuntimeValue::U8(a) => a,
        RuntimeValue::U16(a) => narrow_or_abort(u8::try_from(a))?,
        RuntimeValue::U32(a) => narrow_or_abort(u8::try_from(a))?,
        RuntimeValue::U64(a) => narrow_or_abort(u8::try_from(a))?,
        RuntimeValue::U128(a) => narrow_or_abort(u8::try_from(a))?,
        RuntimeValue::U256(a) => {
            FormatU256::from_le_bytes(a)
                .try_into_u8()
                .ok_or(VMError::ArithmeticError {
                    reason: ArithmeticErrorReason::CastNotRepresentable,
                })?
        }
        _ => {
            return Err(VMError::InvariantViolation {
                reason: InvariantViolationReason::TypeMismatchOnStack,
            });
        }
    };
    frame.push_value(RuntimeValue::U8(result));
    advance_pc(frame);
    Ok(DispatchOutcome::Continue)
}

fn dispatch_cast_u16(state: &mut InterpreterState) -> Result<DispatchOutcome, VMError> {
    let frame = top_frame_mut(state)?;
    let v = frame.pop_value()?;
    let result = match v {
        RuntimeValue::U8(a) => u16::from(a),
        RuntimeValue::U16(a) => a,
        RuntimeValue::U32(a) => narrow_or_abort(u16::try_from(a))?,
        RuntimeValue::U64(a) => narrow_or_abort(u16::try_from(a))?,
        RuntimeValue::U128(a) => narrow_or_abort(u16::try_from(a))?,
        RuntimeValue::U256(a) => {
            FormatU256::from_le_bytes(a)
                .try_into_u16()
                .ok_or(VMError::ArithmeticError {
                    reason: ArithmeticErrorReason::CastNotRepresentable,
                })?
        }
        _ => {
            return Err(VMError::InvariantViolation {
                reason: InvariantViolationReason::TypeMismatchOnStack,
            });
        }
    };
    frame.push_value(RuntimeValue::U16(result));
    advance_pc(frame);
    Ok(DispatchOutcome::Continue)
}

fn dispatch_cast_u32(state: &mut InterpreterState) -> Result<DispatchOutcome, VMError> {
    let frame = top_frame_mut(state)?;
    let v = frame.pop_value()?;
    let result = match v {
        RuntimeValue::U8(a) => u32::from(a),
        RuntimeValue::U16(a) => u32::from(a),
        RuntimeValue::U32(a) => a,
        RuntimeValue::U64(a) => narrow_or_abort(u32::try_from(a))?,
        RuntimeValue::U128(a) => narrow_or_abort(u32::try_from(a))?,
        RuntimeValue::U256(a) => {
            FormatU256::from_le_bytes(a)
                .try_into_u32()
                .ok_or(VMError::ArithmeticError {
                    reason: ArithmeticErrorReason::CastNotRepresentable,
                })?
        }
        _ => {
            return Err(VMError::InvariantViolation {
                reason: InvariantViolationReason::TypeMismatchOnStack,
            });
        }
    };
    frame.push_value(RuntimeValue::U32(result));
    advance_pc(frame);
    Ok(DispatchOutcome::Continue)
}

fn dispatch_cast_u64(state: &mut InterpreterState) -> Result<DispatchOutcome, VMError> {
    let frame = top_frame_mut(state)?;
    let v = frame.pop_value()?;
    let result = match v {
        RuntimeValue::U8(a) => u64::from(a),
        RuntimeValue::U16(a) => u64::from(a),
        RuntimeValue::U32(a) => u64::from(a),
        RuntimeValue::U64(a) => a,
        RuntimeValue::U128(a) => narrow_or_abort(u64::try_from(a))?,
        RuntimeValue::U256(a) => {
            FormatU256::from_le_bytes(a)
                .try_into_u64()
                .ok_or(VMError::ArithmeticError {
                    reason: ArithmeticErrorReason::CastNotRepresentable,
                })?
        }
        _ => {
            return Err(VMError::InvariantViolation {
                reason: InvariantViolationReason::TypeMismatchOnStack,
            });
        }
    };
    frame.push_value(RuntimeValue::U64(result));
    advance_pc(frame);
    Ok(DispatchOutcome::Continue)
}

fn dispatch_cast_u128(state: &mut InterpreterState) -> Result<DispatchOutcome, VMError> {
    let frame = top_frame_mut(state)?;
    let v = frame.pop_value()?;
    let result = match v {
        RuntimeValue::U8(a) => u128::from(a),
        RuntimeValue::U16(a) => u128::from(a),
        RuntimeValue::U32(a) => u128::from(a),
        RuntimeValue::U64(a) => u128::from(a),
        RuntimeValue::U128(a) => a,
        RuntimeValue::U256(a) => {
            FormatU256::from_le_bytes(a)
                .try_into_u128()
                .ok_or(VMError::ArithmeticError {
                    reason: ArithmeticErrorReason::CastNotRepresentable,
                })?
        }
        _ => {
            return Err(VMError::InvariantViolation {
                reason: InvariantViolationReason::TypeMismatchOnStack,
            });
        }
    };
    frame.push_value(RuntimeValue::U128(result));
    advance_pc(frame);
    Ok(DispatchOutcome::Continue)
}

fn dispatch_cast_u256(state: &mut InterpreterState) -> Result<DispatchOutcome, VMError> {
    let frame = top_frame_mut(state)?;
    let v = frame.pop_value()?;
    // All widening casts to U256 succeed (zero-extension).
    let result = match v {
        RuntimeValue::U8(a) => FormatU256::from_u8(a),
        RuntimeValue::U16(a) => FormatU256::from_u16(a),
        RuntimeValue::U32(a) => FormatU256::from_u32(a),
        RuntimeValue::U64(a) => FormatU256::from_u64(a),
        RuntimeValue::U128(a) => FormatU256::from_u128(a),
        RuntimeValue::U256(a) => FormatU256::from_le_bytes(a),
        _ => {
            return Err(VMError::InvariantViolation {
                reason: InvariantViolationReason::TypeMismatchOnStack,
            });
        }
    };
    frame.push_value(RuntimeValue::U256(result.to_le_bytes()));
    advance_pc(frame);
    Ok(DispatchOutcome::Continue)
}

/// Map a `Result<T, _>` from `try_from` into our `VMError` shape:
/// success returns the value; failure surfaces as
/// `ArithmeticError { CastNotRepresentable }`.
fn narrow_or_abort<T, E>(r: Result<T, E>) -> Result<T, VMError> {
    r.map_err(|_| VMError::ArithmeticError {
        reason: ArithmeticErrorReason::CastNotRepresentable,
    })
}

/// Drive the dispatch loop until the interpreter state halts or
/// an instruction returns an error.
///
/// At sub-arc 5/6.1 this driver returns immediately on the first
/// dispatch attempt because the scaffold dispatcher returns
/// [`VMError::InvalidInstruction`] for every input. The driver's
/// shape is preserved so 5/6.2 doesn't have to refactor.
///
/// # Errors
///
/// Propagates the first [`VMError`] returned by [`dispatch_instruction`].
///
/// # Panics
///
/// The internal [`InterpreterState::top_frame`] expectation
/// cannot fail in practice — the loop checks
/// [`InterpreterState::is_empty`] before reaching the frame
/// access. The expect carries a contract assertion message.
///
/// # Spec basis
///
/// Whitepaper §6.2.2 step 5: "Bytecode runs to completion or
/// until gas is exhausted." Sub-arc 5/6.1 enforces only the
/// "to completion" half (gas exhaustion is 5/6.5 scope).
///
/// # Native-handler dispatch (Phase 5/6.8.A)
///
/// `natives` is an optional reference to a native-handler
/// [`crate::runtime::NativeRegistry`] per whitepaper §6.5
/// amendment. When `Some`, the dispatch loop checks the registry
/// before pushing a new bytecode frame for `Bytecode::Call`,
/// `Bytecode::CallGeneric`, `BytecodeInstruction::InvokeShielded`,
/// and `BytecodeInstruction::InvokeTransparent`. A registry hit
/// dispatches to the native handler in place of the new-frame
/// push; a miss falls through to ordinary bytecode interpretation.
/// `None` is equivalent to passing an empty registry — every call
/// falls through to bytecode interpretation. Tests that don't
/// exercise native dispatch pass `None` for clarity.
pub fn run(
    state: &mut InterpreterState,
    module: &AdamantCompiledModule,
    fetch_instruction: impl Fn(FunctionHandleIndex, u16) -> Option<BytecodeInstruction>,
    natives: Option<&crate::runtime::NativeRegistry>,
) -> Result<(), VMError> {
    loop {
        if state.is_empty() {
            return Ok(());
        }
        let (function_handle, pc) = {
            let frame = state.top_frame().expect("call stack non-empty");
            (frame.function_handle, frame.pc)
        };
        let instruction =
            fetch_instruction(function_handle, pc).ok_or(VMError::InvalidInstruction {
                function_handle,
                pc,
            })?;
        match dispatch_instruction(&instruction, state, module)? {
            DispatchOutcome::Continue => {}
            DispatchOutcome::Halt => return Ok(()),
            DispatchOutcome::Call(handle) => do_call_or_native(state, module, handle, natives)?,
            DispatchOutcome::CallGeneric(idx) => do_call_generic(state, module, idx)?,
            DispatchOutcome::InvokeShielded(handle) => {
                do_call_or_native_with_privacy(
                    state,
                    module,
                    handle,
                    crate::runtime::PrivacyMode::Shielded,
                    natives,
                )?;
            }
            DispatchOutcome::InvokeTransparent(handle) => {
                do_call_or_native_with_privacy(
                    state,
                    module,
                    handle,
                    crate::runtime::PrivacyMode::Transparent,
                    natives,
                )?;
            }
        }
    }
}

/// Native-aware Call dispatch. If `natives` resolves the call to
/// a registered handler, invoke it via [`do_native_call`]; else
/// fall through to ordinary [`do_call`].
fn do_call_or_native(
    state: &mut InterpreterState,
    module: &AdamantCompiledModule,
    handle: adamant_bytecode_format::FunctionHandleIndex,
    natives: Option<&crate::runtime::NativeRegistry>,
) -> Result<(), VMError> {
    if let Some(registry) = natives {
        if let Some(key) = crate::runtime::native::native_key_from_handle(module, handle) {
            if let Some(handler) = registry.lookup(&key) {
                return do_native_call(state, module, handle, handler);
            }
        }
    }
    do_call(state, module, handle)
}

/// Native-aware Call dispatch with privacy-mode pinning. Same
/// shape as [`do_call_or_native`] for the ordinary `Call` path
/// but pins the new frame's privacy mode for `InvokeShielded` /
/// `InvokeTransparent` per Phase 5/6.3 + Rule 7.
///
/// For native dispatch, the privacy-mode invariant is checked at
/// the caller-frame level (residual binding for §6.2.1.6 Rule 7
/// per `do_call_with_privacy` shape); the native handler runs
/// without a new frame, so the caller's mode persists.
fn do_call_or_native_with_privacy(
    state: &mut InterpreterState,
    module: &AdamantCompiledModule,
    handle: adamant_bytecode_format::FunctionHandleIndex,
    expected_mode: crate::runtime::PrivacyMode,
    natives: Option<&crate::runtime::NativeRegistry>,
) -> Result<(), VMError> {
    if let Some(registry) = natives {
        if let Some(key) = crate::runtime::native::native_key_from_handle(module, handle) {
            if let Some(handler) = registry.lookup(&key) {
                // Residual Rule 7 caller-frame mode pin.
                let caller_mode = state
                    .top_frame()
                    .ok_or(VMError::InvariantViolation {
                        reason: InvariantViolationReason::StackUnderflow,
                    })?
                    .privacy_mode;
                if caller_mode != expected_mode {
                    return Err(VMError::InvariantViolation {
                        reason: InvariantViolationReason::PrivacyModeMismatchPostVerification,
                    });
                }
                return do_native_call(state, module, handle, handler);
            }
        }
    }
    do_call_with_privacy(state, module, handle, expected_mode)
}

/// Invoke a native handler in place of pushing a new bytecode
/// frame.
///
/// Pops the function's declared parameter count from the caller
/// frame, builds a [`crate::runtime::NativeContext`], invokes
/// the handler, then pushes the handler's `return_values` back
/// to the caller frame. The caller frame's `pc` was already
/// advanced by the dispatch arm before the [`DispatchOutcome::Call`]
/// signal — execution resumes at the caller's next instruction
/// when the handler returns.
fn do_native_call(
    state: &mut InterpreterState,
    module: &AdamantCompiledModule,
    handle: adamant_bytecode_format::FunctionHandleIndex,
    handler: crate::runtime::NativeFunction,
) -> Result<(), VMError> {
    // 1. Resolve parameter and return signatures for arity checks.
    let func_handle =
        module
            .function_handles
            .get(handle.0 as usize)
            .ok_or(VMError::InvariantViolation {
                reason: InvariantViolationReason::IndexOutOfBoundsPostVerification,
            })?;
    let params_sig = module
        .signatures
        .get(func_handle.parameters.0 as usize)
        .ok_or(VMError::InvariantViolation {
            reason: InvariantViolationReason::IndexOutOfBoundsPostVerification,
        })?;
    let return_sig = module
        .signatures
        .get(func_handle.return_.0 as usize)
        .ok_or(VMError::InvariantViolation {
            reason: InvariantViolationReason::IndexOutOfBoundsPostVerification,
        })?;
    let arg_count = params_sig.0.len();
    let expected_return_count = return_sig.0.len();

    // 2. Pop arguments from caller frame.
    let caller_frame = state.top_frame_mut().ok_or(VMError::InvariantViolation {
        reason: InvariantViolationReason::StackUnderflow,
    })?;
    let mut args: Vec<RuntimeValue> = Vec::with_capacity(arg_count);
    for _ in 0..arg_count {
        args.push(caller_frame.pop_value()?);
    }
    args.reverse();

    // 3. Capture pre-invocation frame depth for the post-handler
    //    invariant check (audit-pass F-1: handlers must not mutate
    //    the call-frame stack).
    let frame_depth_before = state.frame_depth();

    // 4. Invoke the handler with the constructed context, then
    //    extract the return values into an owned vec so we can
    //    drop the NativeContext (and the &mut state borrow it
    //    holds) before performing the post-invocation invariant
    //    checks against state.
    let return_values = {
        let mut ctx = crate::runtime::NativeContext::new(state, module, args);
        handler(&mut ctx)?;
        std::mem::take(&mut ctx.return_values)
    };

    // 5. Audit-pass F-1: confirm the handler did not push or pop
    //    frames. The native-dispatch contract is that handlers
    //    communicate with the caller via `args` + `return_values`
    //    only; direct frame-stack mutation breaks the dispatch
    //    loop's pc-already-advanced invariant.
    if state.frame_depth() != frame_depth_before {
        return Err(VMError::InvariantViolation {
            reason: InvariantViolationReason::NativeHandlerMutatedFrameStack,
        });
    }

    // 6. Audit-pass F-3: confirm the handler produced the declared
    //    number of return values. The genesis-fixed
    //    (module_id, function_id) → native_handler mapping pins
    //    handler return-arity against stub-bytecode declared
    //    return signature; reaching the mismatch case indicates
    //    drift between handler and stub.
    if return_values.len() != expected_return_count {
        return Err(VMError::InvariantViolation {
            reason: InvariantViolationReason::ReturnArityMismatchPostNativeHandler,
        });
    }

    // 7. Push handler's return values back to the caller frame.
    let caller_frame = state.top_frame_mut().ok_or(VMError::InvariantViolation {
        reason: InvariantViolationReason::StackUnderflow,
    })?;
    for value in return_values {
        caller_frame.push_value(value);
    }
    Ok(())
}

// ---------- Module-access handler helpers (Phase 5/6.2c.2.α) ----------

/// Handle `Bytecode::LdConst` per whitepaper §6.2.1.4: "Push a
/// `Constant` from the constant pool onto the stack." The
/// constant's BCS-encoded `data` bytes are decoded per its
/// declared `type_` (a `SignatureToken`) into a `RuntimeValue`.
///
/// Phase 5/6.2c.2.α handles the primitive-type constants
/// (U8/U16/U32/U64/U128/U256, Bool, Address, plus
/// `Vector<U8>` for byte-array constants). Generic / nested-
/// container constants surface as `InvariantViolation`
/// per `verifier-residual` until later sub-arcs extend the
/// decoder.
fn dispatch_ld_const(
    state: &mut InterpreterState,
    module: &AdamantCompiledModule,
    idx: adamant_bytecode_format::ConstantPoolIndex,
) -> Result<DispatchOutcome, VMError> {
    let constant = crate::runtime::module_helpers::resolve_constant(module, idx)?;
    let value = decode_constant(&constant.type_, &constant.data)?;
    let frame = top_frame_mut(state)?;
    frame.push_value(value);
    advance_pc(frame);
    Ok(DispatchOutcome::Continue)
}

/// Decode a constant's BCS-encoded byte data per its declared
/// [`SignatureToken`] type into a [`RuntimeValue`].
///
/// Phase 5/6.2c.2.α primitive-type coverage:
/// `Bool`, `U8`, `U16`, `U32`, `U64`, `U128`, `U256`, `Address`,
/// `Vector<U8>`. Other `Vector<T>` element types and nested
/// containers surface as `InvariantViolation::TypeMismatchOnStack`
/// until handler-level decoding extends the surface.
fn decode_constant(
    token: &adamant_bytecode_format::SignatureToken,
    data: &[u8],
) -> Result<RuntimeValue, VMError> {
    use adamant_bytecode_format::SignatureToken as T;
    match token {
        T::Bool => {
            let v: bool = bcs::from_bytes(data).map_err(|_| VMError::InvariantViolation {
                reason: InvariantViolationReason::TypeMismatchOnStack,
            })?;
            Ok(RuntimeValue::Bool(v))
        }
        T::U8 => {
            let v: u8 = bcs::from_bytes(data).map_err(|_| VMError::InvariantViolation {
                reason: InvariantViolationReason::TypeMismatchOnStack,
            })?;
            Ok(RuntimeValue::U8(v))
        }
        T::U16 => {
            let v: u16 = bcs::from_bytes(data).map_err(|_| VMError::InvariantViolation {
                reason: InvariantViolationReason::TypeMismatchOnStack,
            })?;
            Ok(RuntimeValue::U16(v))
        }
        T::U32 => {
            let v: u32 = bcs::from_bytes(data).map_err(|_| VMError::InvariantViolation {
                reason: InvariantViolationReason::TypeMismatchOnStack,
            })?;
            Ok(RuntimeValue::U32(v))
        }
        T::U64 => {
            let v: u64 = bcs::from_bytes(data).map_err(|_| VMError::InvariantViolation {
                reason: InvariantViolationReason::TypeMismatchOnStack,
            })?;
            Ok(RuntimeValue::U64(v))
        }
        T::U128 => {
            let v: u128 = bcs::from_bytes(data).map_err(|_| VMError::InvariantViolation {
                reason: InvariantViolationReason::TypeMismatchOnStack,
            })?;
            Ok(RuntimeValue::U128(v))
        }
        T::U256 => {
            let v: [u8; 32] = bcs::from_bytes(data).map_err(|_| VMError::InvariantViolation {
                reason: InvariantViolationReason::TypeMismatchOnStack,
            })?;
            Ok(RuntimeValue::U256(v))
        }
        T::Address => {
            let v: adamant_types::Address =
                bcs::from_bytes(data).map_err(|_| VMError::InvariantViolation {
                    reason: InvariantViolationReason::TypeMismatchOnStack,
                })?;
            Ok(RuntimeValue::Address(v))
        }
        T::Vector(inner) if matches!(**inner, T::U8) => {
            // Special-case: Vector<U8> is the most common constant
            // shape (byte arrays); decode as Vec<u8> and lift to
            // RuntimeValue::Container(Vector(...)) of U8 elements.
            let bytes: Vec<u8> =
                bcs::from_bytes(data).map_err(|_| VMError::InvariantViolation {
                    reason: InvariantViolationReason::TypeMismatchOnStack,
                })?;
            let elements: Vec<RuntimeValue> = bytes.into_iter().map(RuntimeValue::U8).collect();
            Ok(RuntimeValue::Container(
                crate::runtime::runtime_value::Container::Vector(std::rc::Rc::new(
                    core::cell::RefCell::new(elements),
                )),
            ))
        }
        _ => {
            // Other SignatureToken variants (Vector<non-U8>,
            // Datatype, references, etc.) surface as type mismatch.
            // Extension lands at later sub-arcs if needed; the
            // verifier's `constants` pass restricts constant types
            // to a primitive-friendly subset.
            Err(VMError::InvariantViolation {
                reason: InvariantViolationReason::TypeMismatchOnStack,
            })
        }
    }
}

// ============================================================================
// Phase 5/6.2c.2.γ-merged: struct ops + vector ops + variant ops
// ============================================================================

/// `Bytecode::Pack` handler.
///
/// Per Sui-Move file_format.rs:1690-1701 (verbatim, applicable to
/// the inherited subset): pop n field values in declaration order
/// (top-of-stack is field(n)), build a struct value, push it.
fn dispatch_pack(
    state: &mut InterpreterState,
    module: &AdamantCompiledModule,
    struct_def_idx: adamant_bytecode_format::StructDefinitionIndex,
) -> Result<DispatchOutcome, VMError> {
    let n = crate::runtime::module_helpers::resolve_struct_field_count(module, struct_def_idx)?;
    let frame = top_frame_mut(state)?;
    let mut fields = Vec::with_capacity(n);
    for _ in 0..n {
        fields.push(frame.pop_value()?);
    }
    fields.reverse();
    let type_id = crate::runtime::module_helpers::placeholder_type_id_for_struct(struct_def_idx);
    let container = crate::runtime::runtime_value::Container::from_struct(type_id, fields);
    frame.push_value(RuntimeValue::Container(container));
    advance_pc(frame);
    Ok(DispatchOutcome::Continue)
}

/// `Bytecode::Unpack` handler.
///
/// Per Sui-Move file_format.rs:1715-1726 (verbatim, applicable to
/// the inherited subset): pop a struct value, push its fields in
/// declaration order (top-of-stack ends up being the last field).
fn dispatch_unpack(
    state: &mut InterpreterState,
    module: &AdamantCompiledModule,
    struct_def_idx: adamant_bytecode_format::StructDefinitionIndex,
) -> Result<DispatchOutcome, VMError> {
    // Field count is informational here — verifier guarantees the
    // struct's fields vector matches. We resolve it to fail-fast
    // if the index is OOB, matching the eager-error posture.
    let _expected_n =
        crate::runtime::module_helpers::resolve_struct_field_count(module, struct_def_idx)?;
    let frame = top_frame_mut(state)?;
    let rc = frame.pop_struct()?;
    // Take ownership where possible; otherwise clone interior.
    let runtime_struct = std::rc::Rc::try_unwrap(rc)
        .map_or_else(|rc| rc.borrow().clone(), core::cell::RefCell::into_inner);
    for field in runtime_struct.fields {
        frame.push_value(field);
    }
    advance_pc(frame);
    Ok(DispatchOutcome::Continue)
}

/// `Bytecode::VecPack(_, n)` handler.
///
/// Per whitepaper §6.2.1.4: "Pack a vector of `n` elements at the
/// given signature." Pops n elements from the operand stack and
/// constructs a vector container.
fn dispatch_vec_pack(state: &mut InterpreterState, n: u64) -> Result<DispatchOutcome, VMError> {
    let n_usize = usize::try_from(n).map_err(|_| VMError::InvariantViolation {
        reason: InvariantViolationReason::IndexOutOfBoundsPostVerification,
    })?;
    let frame = top_frame_mut(state)?;
    let mut elements = Vec::with_capacity(n_usize);
    for _ in 0..n_usize {
        elements.push(frame.pop_value()?);
    }
    elements.reverse();
    let container = crate::runtime::runtime_value::Container::from_vec(elements);
    frame.push_value(RuntimeValue::Container(container));
    advance_pc(frame);
    Ok(DispatchOutcome::Continue)
}

/// `Bytecode::VecLen` handler.
///
/// Per whitepaper §6.2.1.4: "Vector length." Pops a reference to a
/// vector, pushes its length as `u64`.
fn dispatch_vec_len(state: &mut InterpreterState) -> Result<DispatchOutcome, VMError> {
    let frame = top_frame_mut(state)?;
    let vec_ref = frame.pop_reference()?;
    let len = vec_ref.vector_len()?;
    let len_u64 = u64::try_from(len).map_err(|_| VMError::InvariantViolation {
        reason: InvariantViolationReason::IndexOutOfBoundsPostVerification,
    })?;
    frame.push_value(RuntimeValue::U64(len_u64));
    advance_pc(frame);
    Ok(DispatchOutcome::Continue)
}

/// `Bytecode::VecPushBack` handler.
///
/// Per whitepaper §6.2.1.4: "Push to the back of a vector." Pops a
/// value and a reference; pushes the value to the back of the
/// referenced vector.
///
/// Stack order: top is the value, then the reference (Sui
/// convention; see `move-vm-runtime` semantics for `vector::push_back`).
fn dispatch_vec_push_back(state: &mut InterpreterState) -> Result<DispatchOutcome, VMError> {
    let frame = top_frame_mut(state)?;
    let value = frame.pop_value()?;
    let vec_ref = frame.pop_reference()?;
    vec_ref.vector_push_back(value)?;
    advance_pc(frame);
    Ok(DispatchOutcome::Continue)
}

/// `Bytecode::VecPopBack` handler.
///
/// Per whitepaper §6.2.1.4: "Pop from the back of a vector." Pops
/// a reference to a vector, pops its last element, pushes the
/// element onto the operand stack. Aborts if the vector is empty.
fn dispatch_vec_pop_back(state: &mut InterpreterState) -> Result<DispatchOutcome, VMError> {
    let frame = top_frame_mut(state)?;
    let vec_ref = frame.pop_reference()?;
    let elem = vec_ref.vector_pop_back()?;
    frame.push_value(elem);
    advance_pc(frame);
    Ok(DispatchOutcome::Continue)
}

/// `Bytecode::VecUnpack(_, n)` handler.
///
/// Per whitepaper §6.2.1.4: "Unpack a vector of `n` elements onto
/// the stack." Pops a vector container, pushes its elements.
fn dispatch_vec_unpack(state: &mut InterpreterState, n: u64) -> Result<DispatchOutcome, VMError> {
    let n_usize = usize::try_from(n).map_err(|_| VMError::InvariantViolation {
        reason: InvariantViolationReason::IndexOutOfBoundsPostVerification,
    })?;
    let frame = top_frame_mut(state)?;
    let rc = frame.pop_vector()?;
    let elements = std::rc::Rc::try_unwrap(rc)
        .map_or_else(|rc| rc.borrow().clone(), core::cell::RefCell::into_inner);
    if elements.len() != n_usize {
        // Verifier's type_safety pass should have ensured the
        // declared n matches the vector's actual length;
        // residual binding surfaces here.
        return Err(VMError::InvariantViolation {
            reason: InvariantViolationReason::IndexOutOfBoundsPostVerification,
        });
    }
    for e in elements {
        frame.push_value(e);
    }
    advance_pc(frame);
    Ok(DispatchOutcome::Continue)
}

/// `Bytecode::VecSwap` handler.
///
/// Per whitepaper §6.2.1.4: "Swap two elements in a vector." Pops
/// two u64 indices and a reference; swaps elements at the indices.
///
/// Stack order: top is index j, then index i, then the reference.
fn dispatch_vec_swap(state: &mut InterpreterState) -> Result<DispatchOutcome, VMError> {
    let frame = top_frame_mut(state)?;
    let j = frame.pop_u64()?;
    let i = frame.pop_u64()?;
    let vec_ref = frame.pop_reference()?;
    let i_usize = usize::try_from(i).map_err(|_| VMError::InvariantViolation {
        reason: InvariantViolationReason::IndexOutOfBoundsPostVerification,
    })?;
    let j_usize = usize::try_from(j).map_err(|_| VMError::InvariantViolation {
        reason: InvariantViolationReason::IndexOutOfBoundsPostVerification,
    })?;
    vec_ref.vector_swap(i_usize, j_usize)?;
    advance_pc(frame);
    Ok(DispatchOutcome::Continue)
}

/// `Bytecode::PackVariant` handler.
///
/// Per Sui-Move `file_format.rs:1789-1791`: "Stack transition: ...,
/// field(1)_value, field(2)_value, ..., field(n)_value -> ...,
/// `variant_value`." Pops n field values for the specified variant
/// of the specified enum, builds a variant container, pushes it.
fn dispatch_pack_variant(
    state: &mut InterpreterState,
    module: &AdamantCompiledModule,
    handle_idx: adamant_bytecode_format::VariantHandleIndex,
) -> Result<DispatchOutcome, VMError> {
    let (enum_def_idx, tag) =
        crate::runtime::module_helpers::resolve_variant_handle(module, handle_idx)?;
    dispatch_pack_variant_inner(state, module, enum_def_idx, tag)
}

/// Inner `PackVariant` logic shared between non-generic and
/// generic dispatch paths.
fn dispatch_pack_variant_inner(
    state: &mut InterpreterState,
    module: &AdamantCompiledModule,
    enum_def_idx: adamant_bytecode_format::EnumDefinitionIndex,
    tag: adamant_bytecode_format::VariantTag,
) -> Result<DispatchOutcome, VMError> {
    let n = crate::runtime::module_helpers::resolve_enum_variant_field_count(
        module,
        enum_def_idx,
        tag,
    )?;
    let frame = top_frame_mut(state)?;
    let mut fields = Vec::with_capacity(n);
    for _ in 0..n {
        fields.push(frame.pop_value()?);
    }
    fields.reverse();
    let type_id = crate::runtime::module_helpers::placeholder_type_id_for_enum(enum_def_idx);
    let container = crate::runtime::runtime_value::Container::from_variant(type_id, tag, fields);
    frame.push_value(RuntimeValue::Container(container));
    advance_pc(frame);
    Ok(DispatchOutcome::Continue)
}

/// Mode discriminator for the `UnpackVariant` family.
#[derive(Debug, Clone, Copy)]
enum UnpackVariantMode {
    /// `UnpackVariant` / `UnpackVariantGeneric`: pop an owned
    /// variant value, push its fields by value.
    Owned,
    /// `UnpackVariantImmRef` / `UnpackVariantMutRef` (and generic
    /// counterparts): pop a reference to a variant, push field
    /// references (Imm/Mut distinction is verifier-only at runtime
    /// per the `FreezeRef` no-op posture).
    ByRef,
}

/// `Bytecode::UnpackVariant` and friends — non-generic path.
fn dispatch_unpack_variant(
    state: &mut InterpreterState,
    module: &AdamantCompiledModule,
    handle_idx: adamant_bytecode_format::VariantHandleIndex,
    mode: UnpackVariantMode,
) -> Result<DispatchOutcome, VMError> {
    let (enum_def_idx, tag) =
        crate::runtime::module_helpers::resolve_variant_handle(module, handle_idx)?;
    dispatch_unpack_variant_inner(state, enum_def_idx, tag, mode)
}

/// Inner `UnpackVariant` logic shared across non-generic, generic,
/// owned, and by-ref paths.
fn dispatch_unpack_variant_inner(
    state: &mut InterpreterState,
    _enum_def_idx: adamant_bytecode_format::EnumDefinitionIndex,
    expected_tag: adamant_bytecode_format::VariantTag,
    mode: UnpackVariantMode,
) -> Result<DispatchOutcome, VMError> {
    let frame = top_frame_mut(state)?;
    match mode {
        UnpackVariantMode::Owned => {
            // Pop an owned variant container.
            let value = frame.pop_value()?;
            let RuntimeValue::Container(crate::runtime::runtime_value::Container::Variant(rc)) =
                value
            else {
                return Err(VMError::InvariantViolation {
                    reason: InvariantViolationReason::TypeMismatchOnStack,
                });
            };
            let runtime_variant = std::rc::Rc::try_unwrap(rc)
                .map_or_else(|rc| rc.borrow().clone(), core::cell::RefCell::into_inner);
            if runtime_variant.variant_tag != expected_tag {
                return Err(VMError::InvariantViolation {
                    reason: InvariantViolationReason::VariantTagMismatch,
                });
            }
            for f in runtime_variant.fields {
                frame.push_value(f);
            }
        }
        UnpackVariantMode::ByRef => {
            // Pop a reference to a variant.
            let variant_ref = frame.pop_reference()?;
            let rc = variant_ref.resolve_variant_container()?;
            let runtime_variant = rc.borrow();
            if runtime_variant.variant_tag != expected_tag {
                return Err(VMError::InvariantViolation {
                    reason: InvariantViolationReason::VariantTagMismatch,
                });
            }
            // Push a field reference per field. The reference
            // points into the variant container at the field
            // index; if a field is itself a container, return
            // Reference::Container so callers can compose further
            // borrows.
            let n = runtime_variant.fields.len();
            drop(runtime_variant);
            for i in 0..n {
                let field_ref = match rc.borrow().fields.get(i) {
                    Some(RuntimeValue::Container(c)) => {
                        crate::runtime::runtime_value::Reference::Container(c.clone())
                    }
                    Some(_) => crate::runtime::runtime_value::Reference::Indexed {
                        container: crate::runtime::runtime_value::Container::Variant(
                            std::rc::Rc::clone(&rc),
                        ),
                        idx: i,
                    },
                    None => {
                        return Err(VMError::InvariantViolation {
                            reason: InvariantViolationReason::IndexOutOfBoundsPostVerification,
                        })
                    }
                };
                frame.push_value(RuntimeValue::Reference(field_ref));
            }
        }
    }
    advance_pc(frame);
    Ok(DispatchOutcome::Continue)
}

/// `Bytecode::VariantSwitch` handler.
///
/// Per Sui-Move file_format.rs:1813-1819: "Branch on the tag value
/// of the enum value reference that is on the top of the value
/// stack, and jumps to the matching code offset for that tag
/// within the `CodeUnit`." Pops a reference to a variant, looks
/// up the variant's tag in the function's jump table, and jumps
/// to the corresponding code offset.
fn dispatch_variant_switch(
    state: &mut InterpreterState,
    module: &AdamantCompiledModule,
    jt_idx: adamant_bytecode_format::VariantJumpTableIndex,
) -> Result<DispatchOutcome, VMError> {
    // Resolve the current frame's function definition, then the
    // jump table within its code unit. Hold the resolved
    // jump-table data across the operations (the function_def's
    // borrow is module-rooted; the frame mutation reborrow shape
    // is correct under the existing borrow discipline).
    let function_handle_idx = state
        .top_frame()
        .ok_or(VMError::InvariantViolation {
            reason: InvariantViolationReason::StackUnderflow,
        })?
        .function_handle;
    let function_def =
        crate::runtime::module_helpers::resolve_function_def(module, function_handle_idx)?;
    let jt_offsets: Vec<adamant_bytecode_format::CodeOffset> = {
        let inner = crate::runtime::module_helpers::resolve_jump_table(function_def, jt_idx)?;
        match inner {
            adamant_bytecode_format::JumpTableInner::Full(offsets) => offsets.clone(),
        }
    };
    let frame = top_frame_mut(state)?;
    let variant_ref = frame.pop_reference()?;
    let rc = variant_ref.resolve_variant_container()?;
    let tag = rc.borrow().variant_tag;
    let target = *jt_offsets
        .get(tag as usize)
        .ok_or(VMError::InvariantViolation {
            reason: InvariantViolationReason::JumpTableTagOutOfRange,
        })?;
    frame.pc = target;
    Ok(DispatchOutcome::Continue)
}

// ============================================================================
// Phase 5/6.3: Adamant-extension crypto dispatch helpers
// ============================================================================

/// Push a 32-byte hash digest onto the operand stack as a vector
/// of `U8`s. Helper used by [`dispatch_sha3_256`] and
/// [`dispatch_blake3`].
fn push_hash_digest(frame: &mut Frame, digest: [u8; 32]) {
    let elements: Vec<RuntimeValue> = digest.into_iter().map(RuntimeValue::U8).collect();
    let container = crate::runtime::runtime_value::Container::from_vec(elements);
    frame.push_value(RuntimeValue::Container(container));
}

/// `Bytecode::Adamant(Sha3_256)` handler.
///
/// Per whitepaper §3.3.1 (verbatim): "SHA3-256 (FIPS 202)
/// produces a 256-bit (32-byte) hash output." Pops a `vector<u8>`
/// from the operand stack, computes SHA3-256, pushes the digest as
/// a 32-byte `vector<u8>`.
fn dispatch_sha3_256(state: &mut InterpreterState) -> Result<DispatchOutcome, VMError> {
    let frame = top_frame_mut(state)?;
    let input = frame.pop_vec_u8()?;
    let digest = adamant_crypto::hash::sha3_256_plain(&input);
    push_hash_digest(frame, digest);
    advance_pc(frame);
    Ok(DispatchOutcome::Continue)
}

/// `Bytecode::Adamant(Blake3)` handler.
///
/// Per whitepaper §3.3.2: BLAKE3 auxiliary hash. Same shape as
/// `Sha3_256` — pops `vector<u8>`, pushes 32-byte digest.
fn dispatch_blake3(state: &mut InterpreterState) -> Result<DispatchOutcome, VMError> {
    let frame = top_frame_mut(state)?;
    let input = frame.pop_vec_u8()?;
    let digest = adamant_crypto::hash::blake3(&input);
    push_hash_digest(frame, digest);
    advance_pc(frame);
    Ok(DispatchOutcome::Continue)
}

/// `Bytecode::Adamant(Ed25519Verify)` handler.
///
/// Per whitepaper §3.4.1: Ed25519 classical signature verification.
/// Stack: `..., pk: vector<u8>(32), msg: vector<u8>, sig: vector<u8>(64) -> ..., bool`.
/// Pop order: signature (top), message, public key.
///
/// Returns `Bool(false)` for any verification failure (parse error
/// or signature mismatch) per the constant-time discipline:
/// distinguishing failure modes leaks information per §3.9.
fn dispatch_ed25519_verify(state: &mut InterpreterState) -> Result<DispatchOutcome, VMError> {
    let frame = top_frame_mut(state)?;
    let sig_bytes = frame.pop_vec_u8()?;
    let msg = frame.pop_vec_u8()?;
    let pk_bytes = frame.pop_vec_u8()?;
    let result = ed25519_verify_plain(&pk_bytes, &msg, &sig_bytes);
    frame.push_value(RuntimeValue::Bool(result));
    advance_pc(frame);
    Ok(DispatchOutcome::Continue)
}

/// Helper: parse-and-verify Ed25519 returning `bool`.
fn ed25519_verify_plain(pk_bytes: &[u8], msg: &[u8], sig_bytes: &[u8]) -> bool {
    let Ok(pk_arr) = <[u8; 32]>::try_from(pk_bytes) else {
        return false;
    };
    let Ok(sig_arr) = <[u8; 64]>::try_from(sig_bytes) else {
        return false;
    };
    let Ok(pk) = adamant_crypto::sig_classical::VerifyingKey::from_bytes(&pk_arr) else {
        return false;
    };
    let sig = adamant_crypto::sig_classical::Signature::from_bytes(&sig_arr);
    pk.verify(msg, &sig).is_ok()
}

/// `Bytecode::Adamant(MlDsaVerify65)` handler.
///
/// Per whitepaper §3.4.2: ML-DSA-65 (FIPS 204 security level 3)
/// post-quantum signature verification. Stack:
/// `..., pk: vector<u8>(1952), msg: vector<u8>, sig: vector<u8>(3309) -> ..., bool`.
fn dispatch_ml_dsa_verify_65(state: &mut InterpreterState) -> Result<DispatchOutcome, VMError> {
    let frame = top_frame_mut(state)?;
    let sig_bytes = frame.pop_vec_u8()?;
    let msg = frame.pop_vec_u8()?;
    let pk_bytes = frame.pop_vec_u8()?;
    let result = ml_dsa_65_verify_plain(&pk_bytes, &msg, &sig_bytes);
    frame.push_value(RuntimeValue::Bool(result));
    advance_pc(frame);
    Ok(DispatchOutcome::Continue)
}

/// Helper: parse-and-verify ML-DSA-65 returning `bool`.
fn ml_dsa_65_verify_plain(pk_bytes: &[u8], msg: &[u8], sig_bytes: &[u8]) -> bool {
    use adamant_crypto::sig_pq::{PUBLIC_KEY_BYTES, SIGNATURE_BYTES};
    let Ok(pk_arr) = <[u8; PUBLIC_KEY_BYTES]>::try_from(pk_bytes) else {
        return false;
    };
    let Ok(sig_arr) = <[u8; SIGNATURE_BYTES]>::try_from(sig_bytes) else {
        return false;
    };
    let pk = adamant_crypto::sig_pq::VerifyingKey::from_bytes(&pk_arr);
    let Ok(sig) = adamant_crypto::sig_pq::Signature::from_bytes(&sig_arr) else {
        return false;
    };
    pk.verify(msg, &sig).is_ok()
}

/// `Bytecode::Adamant(BlsVerify)` handler.
///
/// Per whitepaper §3.4.3: BLS12-381 signature verification. Stack:
/// `..., pk: vector<u8>(96), msg: vector<u8>, sig: vector<u8>(48) -> ..., bool`.
fn dispatch_bls_verify(state: &mut InterpreterState) -> Result<DispatchOutcome, VMError> {
    let frame = top_frame_mut(state)?;
    let sig_bytes = frame.pop_vec_u8()?;
    let msg = frame.pop_vec_u8()?;
    let pk_bytes = frame.pop_vec_u8()?;
    let result = bls_verify_plain(&pk_bytes, &msg, &sig_bytes);
    frame.push_value(RuntimeValue::Bool(result));
    advance_pc(frame);
    Ok(DispatchOutcome::Continue)
}

// ============================================================================
// Phase 5/6.5: Gas handlers
// ============================================================================

/// `Bytecode::Adamant(ChargeGas(dim))` handler.
///
/// Per whitepaper §6.2.1.4 line 423: "Charge a specified amount
/// across one of the six gas dimensions (per section 6.0.7's
/// `GasBudget` and section 6.3.1). Pops the amount as `u64`."
///
/// Pops `u64` amount; calls [`GasTracker::charge`]. On exhaustion,
/// surfaces [`VMError::AbortError`] with [`AbortReason::OutOfGas`].
fn dispatch_charge_gas(
    state: &mut InterpreterState,
    dim: GasDimension,
) -> Result<DispatchOutcome, VMError> {
    let amount = top_frame_mut(state)?.pop_u64()?;
    state.gas_tracker.charge(dim, amount)?;
    let frame = top_frame_mut(state)?;
    advance_pc(frame);
    Ok(DispatchOutcome::Continue)
}

/// `Bytecode::Adamant(RemainingGas(dim))` handler.
///
/// Per whitepaper §6.2.1.4 line 424: "Push the remaining budget
/// for a specified dimension as `u64`. Used by stdlib functions
/// that adapt behaviour based on remaining budget."
fn dispatch_remaining_gas(
    state: &mut InterpreterState,
    dim: GasDimension,
) -> Result<DispatchOutcome, VMError> {
    let remaining = state.gas_tracker.remaining(dim);
    let frame = top_frame_mut(state)?;
    frame.push_value(RuntimeValue::U64(remaining));
    advance_pc(frame);
    Ok(DispatchOutcome::Continue)
}

/// `Bytecode::Adamant(ReleaseSubViewKey)` handler — Phase 5/6.4.b.
///
/// Per whitepaper §7.4.2 (instance 26 Path 1 amendment): derives a
/// 64-byte ML-KEM-768 sub-view-key seed from the parent viewing-
/// keypair seed via HKDF-SHA3:
///
/// ```text
/// sub_seed_S = HKDF-SHA3(
///     salt = b"ADAMANT-v1-subview-derive",
///     ikm  = sk_v_kem_seed,
///     info = BCS(S),
///     L    = 64
/// )
/// ```
///
/// Stack input: pops `vector<u8>` parent seed (64 bytes) followed
/// by `vector<u8>` BCS-encoded scope descriptor `S`. Top of stack
/// is the scope descriptor; bottom is the parent seed.
///
/// Stack output: pushes `vector<u8>` derived sub-view-key seed
/// (64 bytes).
///
/// Per §7.4.2 Path 1 amendment: "the runtime does not need to
/// materialise the keypair; only the seed is exposed via
/// `ReleaseSubViewKey`." `ML-KEM-768.KeyGen` from the derived seed
/// is performed by the wallet outside shielded execution.
fn dispatch_release_sub_view_key(state: &mut InterpreterState) -> Result<DispatchOutcome, VMError> {
    const DOMAIN_TAG_SUBVIEW: &[u8] = b"ADAMANT-v1-subview-derive";
    const PARENT_SEED_LEN: usize = 64;
    const DERIVED_SEED_LEN: usize = 64;

    let frame = top_frame_mut(state)?;
    let scope_bcs = frame.pop_vec_u8()?;
    let parent_seed = frame.pop_vec_u8()?;

    if parent_seed.len() != PARENT_SEED_LEN {
        return Err(VMError::InvariantViolation {
            reason: InvariantViolationReason::TypeMismatchOnStack,
        });
    }

    let derived = adamant_crypto::hash::hkdf_sha3_256(
        DOMAIN_TAG_SUBVIEW,
        &parent_seed,
        &scope_bcs,
        DERIVED_SEED_LEN,
    )
    .ok_or(VMError::InvariantViolation {
        reason: InvariantViolationReason::TypeMismatchOnStack,
    })?;

    let elements: Vec<RuntimeValue> = derived.into_iter().map(RuntimeValue::U8).collect();
    let container = crate::runtime::runtime_value::Container::from_vec(elements);
    frame.push_value(RuntimeValue::Container(container));
    advance_pc(frame);
    Ok(DispatchOutcome::Continue)
}

/// `Bytecode::Adamant(KzgCommit)` handler — Phase 5/6.7.
///
/// Per whitepaper §6.2.1.4 line 412: "Pops the vector; pushes a
/// 48-byte commitment." The popped `vector<u8>` encodes the
/// polynomial coefficients in coefficient-form: a sequence of
/// 32-byte big-endian scalar field elements concatenated.
/// Length must be a multiple of 32 (otherwise the bytes do not
/// decode as a scalar vector).
///
/// Output: a 48-byte `vector<u8>` containing the canonical
/// compressed G₁ encoding of the commitment per
/// `adamant_crypto_blst_extra::G1Point::to_compressed`.
///
/// # Errors
///
/// - [`InvariantViolationReason::KzgSetupNotLoaded`] if no
///   trusted setup has been installed via
///   [`InterpreterState::set_kzg_setup`].
/// - [`InvariantViolationReason::TypeMismatchOnStack`] if the
///   popped `vector<u8>` length is not a multiple of 32 (the
///   bytes do not decode as a scalar-vector).
/// - Reuses [`InvariantViolationReason::TypeMismatchOnStack`]
///   if any 32-byte chunk does not encode a canonical scalar
///   field element (per `Scalar::from_bytes_be` failure).
/// - [`KzgError::DegreeExceedsSetup`] (lifted to
///   [`InvariantViolationReason::TypeMismatchOnStack`]) if the
///   polynomial has more coefficients than the setup's
///   `g1_powers`. Production validators should structurally
///   bound polynomial size at the contract layer; this variant
///   surfaces caller misuse.
fn dispatch_kzg_commit(state: &mut InterpreterState) -> Result<DispatchOutcome, VMError> {
    let setup = state
        .kzg_setup
        .as_ref()
        .ok_or(VMError::InvariantViolation {
            reason: InvariantViolationReason::KzgSetupNotLoaded,
        })?
        .clone();
    let frame = top_frame_mut(state)?;
    let bytes = frame.pop_vec_u8()?;
    let polynomial = decode_polynomial(&bytes)?;
    let commitment = adamant_crypto::kzg::commit(&setup, &polynomial).map_err(|_| {
        VMError::InvariantViolation {
            reason: InvariantViolationReason::TypeMismatchOnStack,
        }
    })?;
    let bytes_out = commitment.0.to_compressed();
    push_byte_vec(frame, &bytes_out);
    advance_pc(frame);
    Ok(DispatchOutcome::Continue)
}

/// `Bytecode::Adamant(KzgVerify)` handler — Phase 5/6.7.
///
/// Per whitepaper §6.2.1.4 line 413: "Pops the commitment, the
/// opening, and the claimed value; pushes a `bool`." Stack
/// layout (top-of-stack last):
///
/// ```text
/// ..., commitment: vector<u8>(48),
///      opening: vector<u8>(48),
///      claimed_value: vector<u8>(64)   // z (32 BE) || y (32 BE)
///      -> ..., bool
/// ```
///
/// `claimed_value` is the concatenation of evaluation point `z`
/// (32 big-endian bytes) followed by claimed evaluation `y` (32
/// big-endian bytes). Both interpreted as canonical scalar
/// field elements per `Scalar::from_bytes_be`.
///
/// Returns `Bool(false)` for any parse failure or verification
/// mismatch (constant-time discipline matches the
/// [`dispatch_ed25519_verify`] / [`dispatch_bls_verify_plain`]
/// pattern: distinguishing failure modes leaks timing
/// information per §3.9).
///
/// # Errors
///
/// - [`InvariantViolationReason::KzgSetupNotLoaded`] if no
///   trusted setup has been installed.
fn dispatch_kzg_verify(state: &mut InterpreterState) -> Result<DispatchOutcome, VMError> {
    let setup = state
        .kzg_setup
        .as_ref()
        .ok_or(VMError::InvariantViolation {
            reason: InvariantViolationReason::KzgSetupNotLoaded,
        })?
        .clone();
    let frame = top_frame_mut(state)?;
    // Pop order: top-of-stack is `claimed_value`; pushed-last per
    // §6.2.1.4 stack convention.
    let claimed_value_bytes = frame.pop_vec_u8()?;
    let opening_bytes = frame.pop_vec_u8()?;
    let commitment_bytes = frame.pop_vec_u8()?;

    let result = kzg_verify_plain(
        &setup,
        &commitment_bytes,
        &opening_bytes,
        &claimed_value_bytes,
    );
    frame.push_value(RuntimeValue::Bool(result));
    advance_pc(frame);
    Ok(DispatchOutcome::Continue)
}

/// Decode a `vector<u8>` byte buffer as a [`adamant_crypto::kzg::Polynomial`].
///
/// Length must be a multiple of 32; each 32-byte chunk is a
/// canonical big-endian scalar field element.
fn decode_polynomial(bytes: &[u8]) -> Result<adamant_crypto::kzg::Polynomial, VMError> {
    if !bytes.len().is_multiple_of(32) {
        return Err(VMError::InvariantViolation {
            reason: InvariantViolationReason::TypeMismatchOnStack,
        });
    }
    let coeff_count = bytes.len() / 32;
    let mut coefficients = Vec::with_capacity(coeff_count);
    for chunk in bytes.chunks_exact(32) {
        let arr: [u8; 32] = chunk
            .try_into()
            .expect("chunks_exact(32) yields 32-byte slices");
        let scalar = adamant_crypto_blst_extra::Scalar::from_bytes_be(&arr).map_err(|_| {
            VMError::InvariantViolation {
                reason: InvariantViolationReason::TypeMismatchOnStack,
            }
        })?;
        coefficients.push(scalar);
    }
    Ok(adamant_crypto::kzg::Polynomial::new(coefficients))
}

/// Verify a KZG opening with input bytes as supplied by the AVM
/// stack. Returns `false` on any parse error or verification
/// mismatch (constant-time discipline).
fn kzg_verify_plain(
    setup: &KzgSetup,
    commitment_bytes: &[u8],
    opening_bytes: &[u8],
    claimed_value_bytes: &[u8],
) -> bool {
    use adamant_crypto::kzg::{verify, Commitment, Proof};
    use adamant_crypto_blst_extra::{G1Point, Scalar};

    // Parse commitment: 48-byte compressed G₁ point.
    let Ok(commitment_arr) = <[u8; 48]>::try_from(commitment_bytes) else {
        return false;
    };
    let Ok(commitment_point) = G1Point::from_compressed(&commitment_arr) else {
        return false;
    };

    // Parse opening proof: 48-byte compressed G₁ point.
    let Ok(opening_arr) = <[u8; 48]>::try_from(opening_bytes) else {
        return false;
    };
    let Ok(opening_point) = G1Point::from_compressed(&opening_arr) else {
        return false;
    };

    // Parse claimed-value: 64 bytes, z (32 BE) || y (32 BE).
    let Ok(claimed_arr) = <[u8; 64]>::try_from(claimed_value_bytes) else {
        return false;
    };
    let mut z_bytes = [0u8; 32];
    z_bytes.copy_from_slice(&claimed_arr[..32]);
    let mut y_bytes = [0u8; 32];
    y_bytes.copy_from_slice(&claimed_arr[32..]);
    let Ok(z) = Scalar::from_bytes_be(&z_bytes) else {
        return false;
    };
    let Ok(y) = Scalar::from_bytes_be(&y_bytes) else {
        return false;
    };

    verify(
        setup,
        &Commitment(commitment_point),
        &z,
        &y,
        &Proof(opening_point),
    )
}

/// Push an arbitrary byte sequence as a `vector<u8>` onto the
/// operand stack. Generalisation of [`push_hash_digest`] for
/// non-32-byte outputs (e.g., 48-byte KZG commitments).
fn push_byte_vec(frame: &mut Frame, bytes: &[u8]) {
    let elements: Vec<RuntimeValue> = bytes.iter().copied().map(RuntimeValue::U8).collect();
    let container = crate::runtime::runtime_value::Container::from_vec(elements);
    frame.push_value(RuntimeValue::Container(container));
}

/// `Bytecode::Adamant(OutOfGas)` handler.
///
/// Per whitepaper §6.2.1.4 line 425: "Abort the transaction with
/// the out-of-gas error. Used by stdlib functions that detect
/// dimension exhaustion."
///
/// Surfaces [`VMError::AbortError`] with
/// [`AbortReason::OutOfGas { dimension: ProofGeneration }`] —
/// the proof-generation dimension is the canonical "stdlib-
/// detected exhaustion" dimension per §6.3.1.
fn dispatch_out_of_gas(_state: &mut InterpreterState) -> Result<DispatchOutcome, VMError> {
    Err(VMError::AbortError {
        reason: AbortReason::OutOfGas {
            dimension: GasDimension::ProofGeneration,
        },
    })
}

/// Helper: parse-and-verify BLS12-381 returning `bool`.
fn bls_verify_plain(pk_bytes: &[u8], msg: &[u8], sig_bytes: &[u8]) -> bool {
    use adamant_crypto::bls::{PUBLIC_KEY_BYTES, SIGNATURE_BYTES};
    let Ok(pk_arr) = <[u8; PUBLIC_KEY_BYTES]>::try_from(pk_bytes) else {
        return false;
    };
    let Ok(sig_arr) = <[u8; SIGNATURE_BYTES]>::try_from(sig_bytes) else {
        return false;
    };
    let Ok(pk) = adamant_crypto::bls::PublicKey::from_bytes(&pk_arr) else {
        return false;
    };
    let Ok(sig) = adamant_crypto::bls::Signature::from_bytes(&sig_arr) else {
        return false;
    };
    pk.verify(msg, &sig).is_ok()
}

/// Handle a `Bytecode::Call` outer-driver dispatch: resolve the
/// function definition, pop arguments from the caller's stack,
/// create a new [`Frame`] with arguments populated in locals
/// slots `[0..arg_count]`, and push the frame onto the call
/// stack.
///
/// Per whitepaper §6.2.1.4 + §6.2.2: "the abstract machine state
/// per function frame is `(stack, locals, pc)`. ... function
/// arguments are passed via the operand stack (popped one per
/// parameter in declaration order, top-of-stack last)."
fn do_call(
    state: &mut InterpreterState,
    module: &AdamantCompiledModule,
    handle: adamant_bytecode_format::FunctionHandleIndex,
) -> Result<(), VMError> {
    // 1. Resolve the function handle to its parameter signature.
    let func_handle =
        module
            .function_handles
            .get(handle.0 as usize)
            .ok_or(VMError::InvariantViolation {
                reason: InvariantViolationReason::IndexOutOfBoundsPostVerification,
            })?;
    let params_sig = module
        .signatures
        .get(func_handle.parameters.0 as usize)
        .ok_or(VMError::InvariantViolation {
            reason: InvariantViolationReason::IndexOutOfBoundsPostVerification,
        })?;
    let arg_count = params_sig.0.len();

    // 2. Resolve the function definition (single-module case).
    let func_def = crate::runtime::module_helpers::resolve_function_def(module, handle)?;
    // 3. Native functions are forbidden by whitepaper §6.2.1.6
    //    Rule 4. The validator should pre-empt; defensive case.
    let code = func_def.code.as_ref().ok_or(VMError::InvariantViolation {
        reason: InvariantViolationReason::DeprecatedOpcodePostVerification,
    })?;
    // 4. Total locals = parameters + body locals.
    let body_locals_sig =
        module
            .signatures
            .get(code.locals.0 as usize)
            .ok_or(VMError::InvariantViolation {
                reason: InvariantViolationReason::IndexOutOfBoundsPostVerification,
            })?;
    let total_locals = arg_count + body_locals_sig.0.len();

    // 5. Pop arguments from caller frame (top-of-stack is last arg).
    //    Capture caller's privacy mode for inheritance (Bytecode::Call
    //    does not transition modes — that's InvokeShielded /
    //    InvokeTransparent's job).
    let caller_frame = state.top_frame_mut().ok_or(VMError::InvariantViolation {
        reason: InvariantViolationReason::StackUnderflow,
    })?;
    let caller_mode = caller_frame.privacy_mode;
    let mut args: Vec<RuntimeValue> = Vec::with_capacity(arg_count);
    for _ in 0..arg_count {
        args.push(caller_frame.pop_value()?);
    }
    // Reverse so args[0] is the first parameter (was bottom of pop).
    args.reverse();

    // 6. Create the new frame inheriting caller's privacy mode and
    //    populate parameter locals.
    let new_frame = Frame::new_with_privacy(handle, total_locals, caller_mode);
    for (i, arg) in args.into_iter().enumerate() {
        let mut cell = new_frame.locals.borrow_mut();
        cell[i] = Some(arg);
    }

    // 7. Push the new frame onto the call stack.
    state.push_frame(new_frame);
    Ok(())
}

/// Frame-creation outer-driver helper for `InvokeShielded` /
/// `InvokeTransparent`.
///
/// Same shape as [`do_call`] but verifies the caller's privacy mode
/// matches `expected_mode` (residual binding for whitepaper
/// §6.2.1.6 Rule 7) and creates the new frame with `expected_mode`.
fn do_call_with_privacy(
    state: &mut InterpreterState,
    module: &AdamantCompiledModule,
    handle: adamant_bytecode_format::FunctionHandleIndex,
    expected_mode: crate::runtime::PrivacyMode,
) -> Result<(), VMError> {
    // Residual check: the verifier (§6.2.1.6 Rule 7) statically
    // validates privacy consistency at deploy time. Reaching this
    // case at runtime indicates either verifier unsoundness or
    // post-deployment bytecode modification.
    let caller_mode = state
        .top_frame()
        .ok_or(VMError::InvariantViolation {
            reason: InvariantViolationReason::StackUnderflow,
        })?
        .privacy_mode;
    if caller_mode != expected_mode {
        return Err(VMError::InvariantViolation {
            reason: InvariantViolationReason::PrivacyModeMismatchPostVerification,
        });
    }
    // Resolve handle → arg_count + total_locals (same as do_call).
    let func_handle =
        module
            .function_handles
            .get(handle.0 as usize)
            .ok_or(VMError::InvariantViolation {
                reason: InvariantViolationReason::IndexOutOfBoundsPostVerification,
            })?;
    let params_sig = module
        .signatures
        .get(func_handle.parameters.0 as usize)
        .ok_or(VMError::InvariantViolation {
            reason: InvariantViolationReason::IndexOutOfBoundsPostVerification,
        })?;
    let arg_count = params_sig.0.len();
    let func_def = crate::runtime::module_helpers::resolve_function_def(module, handle)?;
    let code = func_def.code.as_ref().ok_or(VMError::InvariantViolation {
        reason: InvariantViolationReason::DeprecatedOpcodePostVerification,
    })?;
    let body_locals_sig =
        module
            .signatures
            .get(code.locals.0 as usize)
            .ok_or(VMError::InvariantViolation {
                reason: InvariantViolationReason::IndexOutOfBoundsPostVerification,
            })?;
    let total_locals = arg_count + body_locals_sig.0.len();

    // Pop arguments + build new frame with the explicit privacy
    // mode. Same shape as do_call's tail.
    let caller_frame = state.top_frame_mut().ok_or(VMError::InvariantViolation {
        reason: InvariantViolationReason::StackUnderflow,
    })?;
    let mut args: Vec<RuntimeValue> = Vec::with_capacity(arg_count);
    for _ in 0..arg_count {
        args.push(caller_frame.pop_value()?);
    }
    args.reverse();

    let new_frame = Frame::new_with_privacy(handle, total_locals, expected_mode);
    for (i, arg) in args.into_iter().enumerate() {
        let mut cell = new_frame.locals.borrow_mut();
        cell[i] = Some(arg);
    }

    state.push_frame(new_frame);
    Ok(())
}

/// Handle a `Bytecode::CallGeneric` outer-driver dispatch.
///
/// Phase 5/6.2c.2.α resolves generic instantiations through
/// `function_instantiations` to obtain the underlying handle;
/// type-argument substitution is handled at execution time
/// (operand-stack values are already type-resolved per the
/// verifier's `type_safety` pass; runtime carries no per-
/// instantiation type tag).
fn do_call_generic(
    state: &mut InterpreterState,
    module: &AdamantCompiledModule,
    idx: adamant_bytecode_format::FunctionInstantiationIndex,
) -> Result<(), VMError> {
    // Resolve the instantiation to its underlying function handle.
    let instantiation =
        module
            .function_instantiations
            .get(idx.0 as usize)
            .ok_or(VMError::InvariantViolation {
                reason: InvariantViolationReason::IndexOutOfBoundsPostVerification,
            })?;
    // Delegate to do_call with the underlying handle.
    do_call(state, module, instantiation.handle)
}

#[cfg(test)]
#[allow(
    clippy::doc_markdown,
    reason = "test doc-comments quote whitepaper §6.2.1.4 / §6.2.1.9 / §6.2.2 verbatim per the verbatim-spec-quote-grounds-runtime-fixture discipline; verbatim quotes mention instruction names as plain text and adding backticks would deviate from the verbatim quote source"
)]
mod tests {
    //! Verbatim-spec-quote-grounds-runtime-fixture discipline 3rd
    //! instance — rule-of-three threshold MET at Phase 5/6.2b.
    //!
    //! Every test fixture's expected outcome anchors to a verbatim
    //! whitepaper §6.2.1.4 / §6.2.1.9 / §6.2.2 quote registered in
    //! the test's doc-comment per category. The discipline is the
    //! primary runtime correctness anchor; without spec-quote
    //! grounding, fixtures encode interpretation rather than spec.

    use super::*;
    use crate::bytecode::BytecodeInstruction;
    use crate::value::{StructValue, Value};
    use adamant_bytecode_format::{Bytecode, ConstantPoolIndex};

    // ---------- shared helpers ----------

    fn fh(idx: u16) -> FunctionHandleIndex {
        FunctionHandleIndex(idx)
    }

    /// Probe handler used by `run_invokes_native_handler_when_registered`.
    /// Pushes the sentinel `0xCAFE` value onto the caller's stack
    /// via the [`NativeContext`] return-values channel.
    #[allow(clippy::unnecessary_wraps, reason = "match NativeFunction signature")]
    fn native_probe_handler(ctx: &mut crate::runtime::NativeContext<'_>) -> Result<(), VMError> {
        ctx.return_values.push(RuntimeValue::U64(0xCAFE));
        Ok(())
    }

    /// Construct an empty placeholder module for tests that don't
    /// exercise module-access handlers. 5/6.2c.1 foundation tests
    /// pass an empty module since the 38 self-contained handlers
    /// don't dereference it; 5/6.2c.2 will replace this with
    /// realistic fixtures for module-access handler tests.
    fn empty_module() -> AdamantCompiledModule {
        AdamantCompiledModule::default()
    }

    /// Construct a state with one frame holding `local_count`
    /// locals slots.
    fn state_with_frame(local_count: usize) -> InterpreterState {
        let mut state = InterpreterState::new();
        state.push_frame(Frame::new(fh(0), local_count));
        state
    }

    /// Push values onto the frame's stack in order (first → bottom,
    /// last → top).
    fn push_stack(state: &mut InterpreterState, values: Vec<RuntimeValue>) {
        let frame = state.top_frame_mut().expect("frame");
        for v in values {
            frame.push_value(v);
        }
    }

    /// Dispatch an inherited opcode against the state.
    fn dispatch(
        state: &mut InterpreterState,
        opcode: Bytecode,
    ) -> Result<DispatchOutcome, VMError> {
        let module = empty_module();
        dispatch_instruction(&BytecodeInstruction::Inherited(opcode), state, &module)
    }

    /// Read top-of-stack on the top frame for assertions.
    fn top(state: &InterpreterState) -> RuntimeValue {
        state
            .top_frame()
            .expect("frame")
            .stack
            .last()
            .cloned()
            .expect("non-empty stack")
    }

    fn pc(state: &InterpreterState) -> u16 {
        state.top_frame().expect("frame").pc
    }

    fn stack_len(state: &InterpreterState) -> usize {
        state.top_frame().expect("frame").stack.len()
    }

    // ============================================================
    // Existing 5/6.1 tests (some refreshed for 5/6.2b semantics)
    // ============================================================

    /// Whitepaper §6.2.2 step 5 (verbatim): "Bytecode runs to
    /// completion or until gas is exhausted."
    #[test]
    fn run_on_empty_interpreter_state_returns_ok() {
        let mut state = InterpreterState::new();
        let module = empty_module();
        let result = run(
            &mut state,
            &module,
            |_h, _pc| panic!("fetch_instruction should not be called on empty state"),
            None,
        );
        assert!(result.is_ok());
    }

    /// Whitepaper §6.2.1.4 (verbatim): "the abstract machine
    /// state per function frame is `(stack, locals, pc)`."
    #[test]
    fn push_frame_extends_call_stack() {
        let mut state = InterpreterState::new();
        assert_eq!(state.frame_depth(), 0);
        state.push_frame(Frame::new(fh(0), 0));
        assert_eq!(state.frame_depth(), 1);
        state.push_frame(Frame::new(fh(1), 0));
        assert_eq!(state.frame_depth(), 2);
    }

    #[test]
    fn pop_frame_returns_none_on_empty_stack() {
        let mut state = InterpreterState::new();
        assert!(state.pop_frame().is_none());
    }

    /// Whitepaper §6.2.2 step 5: fetch returning None signals
    /// pc-out-of-bounds; verifier should pre-empt at deploy time.
    #[test]
    fn run_returns_invalid_instruction_when_fetch_returns_none() {
        let mut state = state_with_frame(0);
        let module = empty_module();
        let result = run(&mut state, &module, |_h, _pc| None, None);
        assert!(matches!(result, Err(VMError::InvalidInstruction { .. })));
    }

    // ============================================================
    // Stack / control flow handlers (5)
    // ============================================================

    /// Whitepaper §6.2.1.4 (verbatim): "Pop the value at the top of
    /// the stack."
    #[test]
    fn pop_removes_top_of_stack_and_advances_pc() {
        let mut state = state_with_frame(0);
        push_stack(&mut state, vec![RuntimeValue::U64(42)]);
        dispatch(&mut state, Bytecode::Pop).expect("ok");
        assert_eq!(stack_len(&state), 0);
        assert_eq!(pc(&state), 1);
    }

    /// Verifier-residual binding: stack_usage pass should pre-empt
    /// pop-on-empty-stack. Runtime surfaces InvariantViolation.
    #[test]
    fn pop_on_empty_stack_invariant_violation() {
        let mut state = state_with_frame(0);
        let err = dispatch(&mut state, Bytecode::Pop).expect_err("err");
        assert!(matches!(
            err,
            VMError::InvariantViolation {
                reason: InvariantViolationReason::StackUnderflow,
            }
        ));
    }

    /// Whitepaper §6.2.1.4 (verbatim): "Return from the function."
    /// Whitepaper §6.2.2 step 5: returning from the last frame
    /// halts execution.
    #[test]
    fn ret_pops_last_frame_and_halts() {
        let mut state = state_with_frame(0);
        let outcome = dispatch(&mut state, Bytecode::Ret).expect("ok");
        assert_eq!(outcome, DispatchOutcome::Halt);
        assert!(state.is_empty());
    }

    /// Whitepaper §6.2.1.4 (verbatim): "Unconditional branch to
    /// `CodeOffset`."
    #[test]
    fn branch_sets_pc_to_target() {
        let mut state = state_with_frame(0);
        dispatch(&mut state, Bytecode::Branch(42)).expect("ok");
        assert_eq!(pc(&state), 42);
    }

    /// Whitepaper §6.2.1.4 (verbatim): "Branch to `CodeOffset` if
    /// the top-of-stack value is `true`."
    #[test]
    fn br_true_branches_when_true() {
        let mut state = state_with_frame(0);
        push_stack(&mut state, vec![RuntimeValue::Bool(true)]);
        dispatch(&mut state, Bytecode::BrTrue(42)).expect("ok");
        assert_eq!(pc(&state), 42);
    }

    #[test]
    fn br_true_advances_pc_when_false() {
        let mut state = state_with_frame(0);
        push_stack(&mut state, vec![RuntimeValue::Bool(false)]);
        dispatch(&mut state, Bytecode::BrTrue(42)).expect("ok");
        assert_eq!(pc(&state), 1);
    }

    /// Whitepaper §6.2.1.4 (verbatim): "Branch to `CodeOffset` if
    /// the top-of-stack value is `false`."
    #[test]
    fn br_false_branches_when_false() {
        let mut state = state_with_frame(0);
        push_stack(&mut state, vec![RuntimeValue::Bool(false)]);
        dispatch(&mut state, Bytecode::BrFalse(42)).expect("ok");
        assert_eq!(pc(&state), 42);
    }

    #[test]
    fn br_false_advances_pc_when_true() {
        let mut state = state_with_frame(0);
        push_stack(&mut state, vec![RuntimeValue::Bool(true)]);
        dispatch(&mut state, Bytecode::BrFalse(42)).expect("ok");
        assert_eq!(pc(&state), 1);
    }

    /// Verifier-residual: BrTrue popping non-bool surfaces
    /// TypeMismatchOnStack.
    #[test]
    fn br_true_on_non_bool_invariant_violation() {
        let mut state = state_with_frame(0);
        push_stack(&mut state, vec![RuntimeValue::U64(1)]);
        let err = dispatch(&mut state, Bytecode::BrTrue(42)).expect_err("err");
        assert!(matches!(
            err,
            VMError::InvariantViolation {
                reason: InvariantViolationReason::TypeMismatchOnStack,
            }
        ));
    }

    // ============================================================
    // Literal load handlers (8 in 5/6.2b; LdConst defers to 5/6.2c)
    // ============================================================

    /// Whitepaper §6.2.1.4 (verbatim): "Push a `u8` constant onto
    /// the stack."
    #[test]
    fn ld_u8_pushes_immediate() {
        let mut state = state_with_frame(0);
        dispatch(&mut state, Bytecode::LdU8(0xAB)).expect("ok");
        assert_eq!(top(&state), RuntimeValue::U8(0xAB));
        assert_eq!(pc(&state), 1);
    }

    #[test]
    fn ld_u16_pushes_immediate() {
        let mut state = state_with_frame(0);
        dispatch(&mut state, Bytecode::LdU16(0xABCD)).expect("ok");
        assert_eq!(top(&state), RuntimeValue::U16(0xABCD));
    }

    #[test]
    fn ld_u32_pushes_immediate() {
        let mut state = state_with_frame(0);
        dispatch(&mut state, Bytecode::LdU32(0xABCD_1234)).expect("ok");
        assert_eq!(top(&state), RuntimeValue::U32(0xABCD_1234));
    }

    #[test]
    fn ld_u64_pushes_immediate() {
        let mut state = state_with_frame(0);
        dispatch(&mut state, Bytecode::LdU64(0xDEAD_BEEF_CAFE_BABE)).expect("ok");
        assert_eq!(top(&state), RuntimeValue::U64(0xDEAD_BEEF_CAFE_BABE));
    }

    #[test]
    fn ld_u128_pushes_immediate() {
        let mut state = state_with_frame(0);
        let v = 0x1234_5678_9ABC_DEF0_FEDC_BA98_7654_3210u128;
        dispatch(&mut state, Bytecode::LdU128(Box::new(v))).expect("ok");
        assert_eq!(top(&state), RuntimeValue::U128(v));
    }

    /// Whitepaper §6.2.1.4 (verbatim): "Push a `U256` constant."
    /// 5/6.2a U256 type round-trips through Value::U256 storage.
    #[test]
    fn ld_u256_pushes_immediate() {
        let mut state = state_with_frame(0);
        let mut bytes = [0u8; 32];
        bytes[0] = 0x42;
        let u = FormatU256::from_le_bytes(bytes);
        dispatch(&mut state, Bytecode::LdU256(Box::new(u))).expect("ok");
        assert_eq!(top(&state), RuntimeValue::U256(bytes));
    }

    /// Whitepaper §6.2.1.4 (verbatim): "Push `true` onto the stack."
    #[test]
    fn ld_true_pushes_bool() {
        let mut state = state_with_frame(0);
        dispatch(&mut state, Bytecode::LdTrue).expect("ok");
        assert_eq!(top(&state), RuntimeValue::Bool(true));
    }

    /// Whitepaper §6.2.1.4 (verbatim): "Push `false` onto the stack."
    #[test]
    fn ld_false_pushes_bool() {
        let mut state = state_with_frame(0);
        dispatch(&mut state, Bytecode::LdFalse).expect("ok");
        assert_eq!(top(&state), RuntimeValue::Bool(false));
    }

    /// LdConst on empty constant pool surfaces
    /// IndexOutOfBoundsPostVerification per verifier-residual.
    #[test]
    fn ld_const_on_empty_pool_surfaces_index_out_of_bounds() {
        let mut state = state_with_frame(0);
        let err =
            dispatch(&mut state, Bytecode::LdConst(ConstantPoolIndex::new(0))).expect_err("err");
        assert!(matches!(
            err,
            VMError::InvariantViolation {
                reason: InvariantViolationReason::IndexOutOfBoundsPostVerification,
            }
        ));
    }

    /// Whitepaper §6.2.1.4 (verbatim): "Push a `Constant` from
    /// the constant pool onto the stack."
    #[test]
    fn ld_const_decodes_u64_constant() {
        use adamant_bytecode_format::{Constant, SignatureToken};
        let mut state = state_with_frame(0);
        let mut module = empty_module();
        let value: u64 = 0x1234_5678;
        module.constant_pool.push(Constant {
            type_: SignatureToken::U64,
            data: bcs::to_bytes(&value).expect("bcs encode"),
        });
        dispatch_instruction(
            &BytecodeInstruction::Inherited(Bytecode::LdConst(ConstantPoolIndex::new(0))),
            &mut state,
            &module,
        )
        .expect("ok");
        assert_eq!(top(&state), RuntimeValue::U64(value));
    }

    #[test]
    fn ld_const_decodes_bool_constant() {
        use adamant_bytecode_format::{Constant, SignatureToken};
        let mut state = state_with_frame(0);
        let mut module = empty_module();
        module.constant_pool.push(Constant {
            type_: SignatureToken::Bool,
            data: bcs::to_bytes(&true).expect("bcs encode"),
        });
        dispatch_instruction(
            &BytecodeInstruction::Inherited(Bytecode::LdConst(ConstantPoolIndex::new(0))),
            &mut state,
            &module,
        )
        .expect("ok");
        assert_eq!(top(&state), RuntimeValue::Bool(true));
    }

    #[test]
    fn ld_const_decodes_address_constant() {
        use adamant_bytecode_format::{Constant, SignatureToken};
        use adamant_types::Address;
        let mut state = state_with_frame(0);
        let mut module = empty_module();
        let addr = Address::from_bytes([0x42; 32]);
        module.constant_pool.push(Constant {
            type_: SignatureToken::Address,
            data: bcs::to_bytes(&addr).expect("bcs encode"),
        });
        dispatch_instruction(
            &BytecodeInstruction::Inherited(Bytecode::LdConst(ConstantPoolIndex::new(0))),
            &mut state,
            &module,
        )
        .expect("ok");
        assert_eq!(top(&state), RuntimeValue::Address(addr));
    }

    /// LdConst with `Vector<U8>` decodes a byte-array constant
    /// into a Vector container of U8 elements.
    #[test]
    fn ld_const_decodes_vector_u8_constant() {
        use adamant_bytecode_format::{Constant, SignatureToken};
        let mut state = state_with_frame(0);
        let mut module = empty_module();
        let bytes: Vec<u8> = vec![0x01, 0x02, 0x03];
        module.constant_pool.push(Constant {
            type_: SignatureToken::Vector(Box::new(SignatureToken::U8)),
            data: bcs::to_bytes(&bytes).expect("bcs encode"),
        });
        dispatch_instruction(
            &BytecodeInstruction::Inherited(Bytecode::LdConst(ConstantPoolIndex::new(0))),
            &mut state,
            &module,
        )
        .expect("ok");
        if let RuntimeValue::Container(crate::runtime::runtime_value::Container::Vector(rc)) =
            top(&state)
        {
            let elements = rc.borrow();
            assert_eq!(elements.len(), 3);
            assert_eq!(elements[0], RuntimeValue::U8(0x01));
            assert_eq!(elements[1], RuntimeValue::U8(0x02));
            assert_eq!(elements[2], RuntimeValue::U8(0x03));
        } else {
            panic!("expected Vector container");
        }
    }

    // ============================================================
    // Cast handlers (6) — §6.2.1.9 cast semantics
    // ============================================================

    /// Whitepaper §6.2.1.9 (verbatim): "*Same-type cast* ... always
    /// succeeds; the result is the source value unchanged."
    #[test]
    fn cast_u8_same_type_succeeds() {
        let mut state = state_with_frame(0);
        push_stack(&mut state, vec![RuntimeValue::U8(42)]);
        dispatch(&mut state, Bytecode::CastU8).expect("ok");
        assert_eq!(top(&state), RuntimeValue::U8(42));
    }

    /// Whitepaper §6.2.1.9 (verbatim): "*Widening cast* ... always
    /// succeeds; the source value is representable in the
    /// destination type by zero-extension."
    #[test]
    fn cast_u64_widening_from_u8_succeeds() {
        let mut state = state_with_frame(0);
        push_stack(&mut state, vec![RuntimeValue::U8(42)]);
        dispatch(&mut state, Bytecode::CastU64).expect("ok");
        assert_eq!(top(&state), RuntimeValue::U64(42));
    }

    /// Whitepaper §6.2.1.9 (verbatim): "*Narrowing cast* ...
    /// succeeds when the source value lies within the destination
    /// type's representable range."
    #[test]
    fn cast_u8_narrowing_in_range_succeeds() {
        let mut state = state_with_frame(0);
        push_stack(&mut state, vec![RuntimeValue::U64(255)]);
        dispatch(&mut state, Bytecode::CastU8).expect("ok");
        assert_eq!(top(&state), RuntimeValue::U8(255));
    }

    /// Whitepaper §6.2.1.9 (verbatim): "[Narrowing cast] otherwise
    /// the runtime aborts with a runtime arithmetic error."
    #[test]
    fn cast_u8_narrowing_out_of_range_aborts() {
        let mut state = state_with_frame(0);
        push_stack(&mut state, vec![RuntimeValue::U64(256)]);
        let err = dispatch(&mut state, Bytecode::CastU8).expect_err("aborts");
        assert!(matches!(
            err,
            VMError::ArithmeticError {
                reason: ArithmeticErrorReason::CastNotRepresentable,
            }
        ));
    }

    #[test]
    fn cast_u256_widening_from_u128_succeeds() {
        let mut state = state_with_frame(0);
        push_stack(&mut state, vec![RuntimeValue::U128(u128::MAX)]);
        dispatch(&mut state, Bytecode::CastU256).expect("ok");
        let u = FormatU256::from_u128(u128::MAX);
        assert_eq!(top(&state), RuntimeValue::U256(u.to_le_bytes()));
    }

    #[test]
    fn cast_u128_narrowing_from_u256_in_range() {
        let mut state = state_with_frame(0);
        let u = FormatU256::from_u128(u128::MAX);
        push_stack(&mut state, vec![RuntimeValue::U256(u.to_le_bytes())]);
        dispatch(&mut state, Bytecode::CastU128).expect("ok");
        assert_eq!(top(&state), RuntimeValue::U128(u128::MAX));
    }

    #[test]
    fn cast_u128_narrowing_from_u256_out_of_range_aborts() {
        let mut state = state_with_frame(0);
        let mut bytes = [0u8; 32];
        bytes[16] = 1; // value 2^128
        push_stack(&mut state, vec![RuntimeValue::U256(bytes)]);
        let err = dispatch(&mut state, Bytecode::CastU128).expect_err("aborts");
        assert!(matches!(
            err,
            VMError::ArithmeticError {
                reason: ArithmeticErrorReason::CastNotRepresentable,
            }
        ));
    }

    #[test]
    fn cast_u16_pinned() {
        let mut state = state_with_frame(0);
        push_stack(&mut state, vec![RuntimeValue::U8(42)]);
        dispatch(&mut state, Bytecode::CastU16).expect("ok");
        assert_eq!(top(&state), RuntimeValue::U16(42));
    }

    #[test]
    fn cast_u32_pinned() {
        let mut state = state_with_frame(0);
        push_stack(&mut state, vec![RuntimeValue::U64(0xFFFF)]);
        dispatch(&mut state, Bytecode::CastU32).expect("ok");
        assert_eq!(top(&state), RuntimeValue::U32(0xFFFF));
    }

    // ============================================================
    // Locals access handlers (3)
    // ============================================================

    /// Whitepaper §6.2.1.4 (verbatim): "Copy the local at
    /// `LocalIndex` and push onto the stack."
    #[test]
    fn copy_loc_clones_local_to_stack() {
        let mut state = state_with_frame(2);
        state
            .top_frame_mut()
            .expect("frame")
            .st_loc(0, RuntimeValue::U64(7))
            .expect("ok");
        dispatch(&mut state, Bytecode::CopyLoc(0)).expect("ok");
        assert_eq!(top(&state), RuntimeValue::U64(7));
        // Local still occupied (CopyLoc clones, not moves).
        assert!(state.top_frame().expect("frame").locals.borrow()[0].is_some());
    }

    /// Whitepaper §6.2.1.4 (verbatim): "Move the local at
    /// `LocalIndex` and push onto the stack."
    #[test]
    fn move_loc_takes_local_to_stack() {
        let mut state = state_with_frame(2);
        state
            .top_frame_mut()
            .expect("frame")
            .st_loc(0, RuntimeValue::U64(7))
            .expect("ok");
        dispatch(&mut state, Bytecode::MoveLoc(0)).expect("ok");
        assert_eq!(top(&state), RuntimeValue::U64(7));
        // Local now empty (MoveLoc takes).
        assert!(state.top_frame().expect("frame").locals.borrow()[0].is_none());
    }

    /// Whitepaper §6.2.1.4 (verbatim): "Pop the stack top and
    /// store into the local at `LocalIndex`."
    #[test]
    fn st_loc_stores_stack_top_to_local() {
        let mut state = state_with_frame(2);
        push_stack(&mut state, vec![RuntimeValue::U64(99)]);
        dispatch(&mut state, Bytecode::StLoc(0)).expect("ok");
        assert_eq!(stack_len(&state), 0);
        assert_eq!(
            state.top_frame().expect("frame").locals.borrow()[0],
            Some(RuntimeValue::U64(99))
        );
    }

    /// Verifier-residual: locals_safety pass pre-empts
    /// CopyLoc-on-uninitialized.
    #[test]
    fn copy_loc_uninitialized_invariant_violation() {
        let mut state = state_with_frame(2);
        let err = dispatch(&mut state, Bytecode::CopyLoc(0)).expect_err("err");
        assert!(matches!(
            err,
            VMError::InvariantViolation {
                reason: InvariantViolationReason::LocalNotInitialized,
            }
        ));
    }

    /// Verifier-residual: bounds_checker pass pre-empts
    /// LocalIndex-out-of-bounds.
    #[test]
    fn copy_loc_out_of_bounds_invariant_violation() {
        let mut state = state_with_frame(2);
        let err = dispatch(&mut state, Bytecode::CopyLoc(99)).expect_err("err");
        assert!(matches!(
            err,
            VMError::InvariantViolation {
                reason: InvariantViolationReason::IndexOutOfBoundsPostVerification,
            }
        ));
    }

    // ============================================================
    // Arithmetic handlers (5) — §6.2.1.9 overflow handling
    // ============================================================

    /// Whitepaper §6.2.1.9 (verbatim): "`Add`, `Sub`, and `Mul`
    /// abort when the result of the operation would fall outside
    /// the operand type's unsigned integer range."
    #[test]
    fn add_u64_within_range() {
        let mut state = state_with_frame(0);
        push_stack(
            &mut state,
            vec![RuntimeValue::U64(7), RuntimeValue::U64(11)],
        );
        dispatch(&mut state, Bytecode::Add).expect("ok");
        assert_eq!(top(&state), RuntimeValue::U64(18));
    }

    #[test]
    fn add_u64_overflow_aborts() {
        let mut state = state_with_frame(0);
        push_stack(
            &mut state,
            vec![RuntimeValue::U64(u64::MAX), RuntimeValue::U64(1)],
        );
        let err = dispatch(&mut state, Bytecode::Add).expect_err("aborts");
        assert!(matches!(
            err,
            VMError::ArithmeticError {
                reason: ArithmeticErrorReason::Overflow,
            }
        ));
    }

    #[test]
    fn sub_u64_underflow_aborts() {
        let mut state = state_with_frame(0);
        push_stack(&mut state, vec![RuntimeValue::U64(0), RuntimeValue::U64(1)]);
        let err = dispatch(&mut state, Bytecode::Sub).expect_err("aborts");
        assert!(matches!(
            err,
            VMError::ArithmeticError {
                reason: ArithmeticErrorReason::Underflow,
            }
        ));
    }

    #[test]
    fn mul_u8_overflow_aborts() {
        let mut state = state_with_frame(0);
        push_stack(&mut state, vec![RuntimeValue::U8(255), RuntimeValue::U8(2)]);
        let err = dispatch(&mut state, Bytecode::Mul).expect_err("aborts");
        assert!(matches!(
            err,
            VMError::ArithmeticError {
                reason: ArithmeticErrorReason::Overflow,
            }
        ));
    }

    /// Whitepaper §6.2.1.9 (verbatim): "`Div` and `Mod` abort when
    /// the right-hand operand (the divisor) is zero."
    #[test]
    fn div_by_zero_aborts() {
        let mut state = state_with_frame(0);
        push_stack(
            &mut state,
            vec![RuntimeValue::U64(100), RuntimeValue::U64(0)],
        );
        let err = dispatch(&mut state, Bytecode::Div).expect_err("aborts");
        assert!(matches!(
            err,
            VMError::ArithmeticError {
                reason: ArithmeticErrorReason::DivisionByZero,
            }
        ));
    }

    #[test]
    fn rem_by_zero_aborts() {
        let mut state = state_with_frame(0);
        push_stack(
            &mut state,
            vec![RuntimeValue::U64(100), RuntimeValue::U64(0)],
        );
        let err = dispatch(&mut state, Bytecode::Mod).expect_err("aborts");
        assert!(matches!(
            err,
            VMError::ArithmeticError {
                reason: ArithmeticErrorReason::DivisionByZero,
            }
        ));
    }

    #[test]
    fn div_normal() {
        let mut state = state_with_frame(0);
        push_stack(
            &mut state,
            vec![RuntimeValue::U64(100), RuntimeValue::U64(7)],
        );
        dispatch(&mut state, Bytecode::Div).expect("ok");
        assert_eq!(top(&state), RuntimeValue::U64(14));
    }

    #[test]
    fn mod_normal() {
        let mut state = state_with_frame(0);
        push_stack(
            &mut state,
            vec![RuntimeValue::U64(100), RuntimeValue::U64(7)],
        );
        dispatch(&mut state, Bytecode::Mod).expect("ok");
        assert_eq!(top(&state), RuntimeValue::U64(2));
    }

    /// U256 arithmetic via adamant_bytecode_format::U256
    /// (Phase 5/6.2a). Layer-crossing conversion.
    #[test]
    fn add_u256_within_range() {
        let mut state = state_with_frame(0);
        let a = FormatU256::from_u64(7);
        let b = FormatU256::from_u64(11);
        push_stack(
            &mut state,
            vec![
                RuntimeValue::U256(a.to_le_bytes()),
                RuntimeValue::U256(b.to_le_bytes()),
            ],
        );
        dispatch(&mut state, Bytecode::Add).expect("ok");
        let expected = FormatU256::from_u64(18);
        assert_eq!(top(&state), RuntimeValue::U256(expected.to_le_bytes()));
    }

    #[test]
    fn add_u256_overflow_aborts() {
        let mut state = state_with_frame(0);
        let max = FormatU256::MAX;
        let one = FormatU256::from_u8(1);
        push_stack(
            &mut state,
            vec![
                RuntimeValue::U256(max.to_le_bytes()),
                RuntimeValue::U256(one.to_le_bytes()),
            ],
        );
        let err = dispatch(&mut state, Bytecode::Add).expect_err("aborts");
        assert!(matches!(
            err,
            VMError::ArithmeticError {
                reason: ArithmeticErrorReason::Overflow,
            }
        ));
    }

    /// Verifier-residual: type_safety pass pre-empts mixed-width
    /// arithmetic.
    #[test]
    fn add_mixed_width_invariant_violation() {
        let mut state = state_with_frame(0);
        push_stack(&mut state, vec![RuntimeValue::U64(1), RuntimeValue::U32(1)]);
        let err = dispatch(&mut state, Bytecode::Add).expect_err("err");
        assert!(matches!(
            err,
            VMError::InvariantViolation {
                reason: InvariantViolationReason::TypeMismatchOnStack,
            }
        ));
    }

    // ============================================================
    // Bitwise + logic handlers (6)
    // ============================================================

    #[test]
    fn bitand_u64() {
        let mut state = state_with_frame(0);
        push_stack(
            &mut state,
            vec![RuntimeValue::U64(0xFF), RuntimeValue::U64(0x0F)],
        );
        dispatch(&mut state, Bytecode::BitAnd).expect("ok");
        assert_eq!(top(&state), RuntimeValue::U64(0x0F));
    }

    #[test]
    fn bitor_u64() {
        let mut state = state_with_frame(0);
        push_stack(
            &mut state,
            vec![RuntimeValue::U64(0xF0), RuntimeValue::U64(0x0F)],
        );
        dispatch(&mut state, Bytecode::BitOr).expect("ok");
        assert_eq!(top(&state), RuntimeValue::U64(0xFF));
    }

    #[test]
    fn xor_u64() {
        let mut state = state_with_frame(0);
        push_stack(
            &mut state,
            vec![RuntimeValue::U64(0xFF), RuntimeValue::U64(0x0F)],
        );
        dispatch(&mut state, Bytecode::Xor).expect("ok");
        assert_eq!(top(&state), RuntimeValue::U64(0xF0));
    }

    /// Whitepaper §6.2.1.4 (verbatim): "Logical OR / AND / NOT."
    #[test]
    fn and_bool() {
        let mut state = state_with_frame(0);
        push_stack(
            &mut state,
            vec![RuntimeValue::Bool(true), RuntimeValue::Bool(false)],
        );
        dispatch(&mut state, Bytecode::And).expect("ok");
        assert_eq!(top(&state), RuntimeValue::Bool(false));
    }

    #[test]
    fn or_bool() {
        let mut state = state_with_frame(0);
        push_stack(
            &mut state,
            vec![RuntimeValue::Bool(true), RuntimeValue::Bool(false)],
        );
        dispatch(&mut state, Bytecode::Or).expect("ok");
        assert_eq!(top(&state), RuntimeValue::Bool(true));
    }

    #[test]
    fn not_bool() {
        let mut state = state_with_frame(0);
        push_stack(&mut state, vec![RuntimeValue::Bool(true)]);
        dispatch(&mut state, Bytecode::Not).expect("ok");
        assert_eq!(top(&state), RuntimeValue::Bool(false));
    }

    // ============================================================
    // Comparison handlers (6) — §6.2.1.9 unsigned ordering
    // ============================================================

    /// Whitepaper §6.2.1.9 (verbatim): "All integer comparisons
    /// (`Lt`, `Gt`, `Le`, `Ge`) interpret integer operands as
    /// unsigned."
    #[test]
    fn lt_u64() {
        let mut state = state_with_frame(0);
        push_stack(&mut state, vec![RuntimeValue::U64(1), RuntimeValue::U64(2)]);
        dispatch(&mut state, Bytecode::Lt).expect("ok");
        assert_eq!(top(&state), RuntimeValue::Bool(true));
    }

    #[test]
    fn gt_u64() {
        let mut state = state_with_frame(0);
        push_stack(&mut state, vec![RuntimeValue::U64(2), RuntimeValue::U64(1)]);
        dispatch(&mut state, Bytecode::Gt).expect("ok");
        assert_eq!(top(&state), RuntimeValue::Bool(true));
    }

    #[test]
    fn le_u64_equal() {
        let mut state = state_with_frame(0);
        push_stack(&mut state, vec![RuntimeValue::U64(5), RuntimeValue::U64(5)]);
        dispatch(&mut state, Bytecode::Le).expect("ok");
        assert_eq!(top(&state), RuntimeValue::Bool(true));
    }

    #[test]
    fn ge_u64_equal() {
        let mut state = state_with_frame(0);
        push_stack(&mut state, vec![RuntimeValue::U64(5), RuntimeValue::U64(5)]);
        dispatch(&mut state, Bytecode::Ge).expect("ok");
        assert_eq!(top(&state), RuntimeValue::Bool(true));
    }

    /// Whitepaper §6.2.1.9 (verbatim): "comparison is well-defined
    /// for any pair of operands of the same integer type" — this
    /// is the load-bearing U256 unsigned-comparison test
    /// (5/6.2a's manual MSB-first Ord impl is the source of truth).
    #[test]
    fn lt_u256_unsigned_counter_example() {
        let mut state = state_with_frame(0);
        // value 1 (LSB-first) vs value 512
        let one = FormatU256::from_u64(1);
        let five_twelve = FormatU256::from_u64(512);
        push_stack(
            &mut state,
            vec![
                RuntimeValue::U256(one.to_le_bytes()),
                RuntimeValue::U256(five_twelve.to_le_bytes()),
            ],
        );
        dispatch(&mut state, Bytecode::Lt).expect("ok");
        // 1 < 512 under unsigned ordering.
        assert_eq!(top(&state), RuntimeValue::Bool(true));
    }

    /// Whitepaper §6.2.1.9 (verbatim): "byte-identity is computed
    /// field-wise and recurses into nested structs ... `Eq`
    /// returns `true` when the two values are byte-identical."
    #[test]
    fn eq_u64_equal() {
        let mut state = state_with_frame(0);
        push_stack(&mut state, vec![RuntimeValue::U64(7), RuntimeValue::U64(7)]);
        dispatch(&mut state, Bytecode::Eq).expect("ok");
        assert_eq!(top(&state), RuntimeValue::Bool(true));
    }

    #[test]
    fn eq_u64_unequal() {
        let mut state = state_with_frame(0);
        push_stack(&mut state, vec![RuntimeValue::U64(7), RuntimeValue::U64(8)]);
        dispatch(&mut state, Bytecode::Eq).expect("ok");
        assert_eq!(top(&state), RuntimeValue::Bool(false));
    }

    #[test]
    fn neq_u64_unequal() {
        let mut state = state_with_frame(0);
        push_stack(&mut state, vec![RuntimeValue::U64(7), RuntimeValue::U64(8)]);
        dispatch(&mut state, Bytecode::Neq).expect("ok");
        assert_eq!(top(&state), RuntimeValue::Bool(true));
    }

    #[test]
    fn eq_bool() {
        let mut state = state_with_frame(0);
        push_stack(
            &mut state,
            vec![RuntimeValue::Bool(true), RuntimeValue::Bool(true)],
        );
        dispatch(&mut state, Bytecode::Eq).expect("ok");
        assert_eq!(top(&state), RuntimeValue::Bool(true));
    }

    /// Verifier-residual: comparison on mismatched types surfaces
    /// TypeMismatchOnStack.
    #[test]
    fn lt_mixed_width_invariant_violation() {
        let mut state = state_with_frame(0);
        push_stack(&mut state, vec![RuntimeValue::U64(1), RuntimeValue::U32(1)]);
        let err = dispatch(&mut state, Bytecode::Lt).expect_err("err");
        assert!(matches!(
            err,
            VMError::InvariantViolation {
                reason: InvariantViolationReason::TypeMismatchOnStack,
            }
        ));
    }

    // ============================================================
    // Shift handlers (2) — §6.2.1.9 shift bounds
    // ============================================================

    /// Whitepaper §6.2.1.9 (verbatim): "For operand types `u8`,
    /// `u16`, `u32`, `u64`, and `u128`, the runtime aborts when
    /// the shift amount is greater than or equal to the operand's
    /// bit width."
    #[test]
    fn shl_u8_at_bit_width_aborts() {
        let mut state = state_with_frame(0);
        push_stack(&mut state, vec![RuntimeValue::U8(1), RuntimeValue::U8(8)]);
        let err = dispatch(&mut state, Bytecode::Shl).expect_err("aborts");
        assert!(matches!(
            err,
            VMError::ArithmeticError {
                reason: ArithmeticErrorReason::ShiftAmountTooLarge,
            }
        ));
    }

    #[test]
    fn shl_u64_at_bit_width_aborts() {
        let mut state = state_with_frame(0);
        push_stack(&mut state, vec![RuntimeValue::U64(1), RuntimeValue::U8(64)]);
        let err = dispatch(&mut state, Bytecode::Shl).expect_err("aborts");
        assert!(matches!(
            err,
            VMError::ArithmeticError {
                reason: ArithmeticErrorReason::ShiftAmountTooLarge,
            }
        ));
    }

    #[test]
    fn shl_u128_at_bit_width_aborts() {
        let mut state = state_with_frame(0);
        push_stack(
            &mut state,
            vec![RuntimeValue::U128(1), RuntimeValue::U8(128)],
        );
        let err = dispatch(&mut state, Bytecode::Shl).expect_err("aborts");
        assert!(matches!(
            err,
            VMError::ArithmeticError {
                reason: ArithmeticErrorReason::ShiftAmountTooLarge,
            }
        ));
    }

    #[test]
    fn shl_u64_normal() {
        let mut state = state_with_frame(0);
        push_stack(&mut state, vec![RuntimeValue::U64(1), RuntimeValue::U8(8)]);
        dispatch(&mut state, Bytecode::Shl).expect("ok");
        assert_eq!(top(&state), RuntimeValue::U64(256));
    }

    #[test]
    fn shr_u64_normal() {
        let mut state = state_with_frame(0);
        push_stack(
            &mut state,
            vec![RuntimeValue::U64(256), RuntimeValue::U8(8)],
        );
        dispatch(&mut state, Bytecode::Shr).expect("ok");
        assert_eq!(top(&state), RuntimeValue::U64(1));
    }

    /// Whitepaper §6.2.1.9 (verbatim): "For operand type `u256`,
    /// no abort condition applies." The shift amount is u8 max
    /// 255 < 256 = bit_width.
    #[test]
    fn shl_u256_no_abort_at_max_n_bits() {
        let mut state = state_with_frame(0);
        let one = FormatU256::from_u8(1);
        push_stack(
            &mut state,
            vec![RuntimeValue::U256(one.to_le_bytes()), RuntimeValue::U8(255)],
        );
        dispatch(&mut state, Bytecode::Shl).expect("ok");
        // Result: bit 255 set.
        let mut expected_bytes = [0u8; 32];
        expected_bytes[31] = 0x80;
        assert_eq!(top(&state), RuntimeValue::U256(expected_bytes));
    }

    // ============================================================
    // Misc + deprecated handlers
    // ============================================================

    /// Whitepaper §6.2.1.4 (verbatim): "No operation."
    #[test]
    fn nop_advances_pc_only() {
        let mut state = state_with_frame(0);
        dispatch(&mut state, Bytecode::Nop).expect("ok");
        assert_eq!(pc(&state), 1);
        assert_eq!(stack_len(&state), 0);
    }

    /// Whitepaper §6.2.1.4 (verbatim): "Abort with an error code."
    /// Phase 5/6.5 refines the prior placeholder into
    /// VMError::AbortError with AbortReason::UserAbort { code }.
    #[test]
    fn abort_returns_error() {
        use crate::runtime::AbortReason;
        let mut state = state_with_frame(0);
        push_stack(&mut state, vec![RuntimeValue::U64(42)]);
        let err = dispatch(&mut state, Bytecode::Abort).expect_err("aborts");
        assert!(matches!(
            err,
            VMError::AbortError {
                reason: AbortReason::UserAbort { code: 42 }
            }
        ));
    }

    /// Whitepaper §6.2.1.6 Rule 5: "No global storage instructions."
    /// The 10 deprecated opcodes are rejected at parse time per
    /// Rule 5; if one reaches runtime, it indicates parser
    /// unsoundness or post-deployment modification.
    #[test]
    fn deprecated_opcode_invariant_violation() {
        use adamant_bytecode_format::StructDefinitionIndex;
        let mut state = state_with_frame(0);
        let err = dispatch(
            &mut state,
            Bytecode::ExistsDeprecated(StructDefinitionIndex::new(0)),
        )
        .expect_err("err");
        assert!(matches!(
            err,
            VMError::InvariantViolation {
                reason: InvariantViolationReason::DeprecatedOpcodePostVerification,
            }
        ));
    }

    // ============================================================
    // Module-access handlers defer to 5/6.2c
    // ============================================================

    /// Whitepaper §6.2.1.4 (verbatim): "Call the function at
    /// `FunctionHandleIndex`."
    ///
    /// Phase 5/6.2c.2.α: dispatch returns DispatchOutcome::Call;
    /// outer driver (run) creates the new frame.
    #[test]
    fn call_returns_dispatch_outcome_call() {
        let mut state = state_with_frame(0);
        let outcome = dispatch(&mut state, Bytecode::Call(fh(0))).expect("ok");
        assert!(matches!(outcome, DispatchOutcome::Call(_)));
        // pc was advanced past Call.
        assert_eq!(pc(&state), 1);
    }

    /// ReadRef on empty stack surfaces StackUnderflow per
    /// verifier-residual posture (Phase 5/6.2c.2.β implementation).
    #[test]
    fn read_ref_on_empty_stack_invariant_violation() {
        let mut state = state_with_frame(0);
        let err = dispatch(&mut state, Bytecode::ReadRef).expect_err("err");
        assert!(matches!(
            err,
            VMError::InvariantViolation {
                reason: InvariantViolationReason::StackUnderflow,
            }
        ));
    }

    // ============================================================
    // Reference-machinery handler tests (5/6.2c.2.β)
    // ============================================================

    /// Whitepaper §6.2.1.4 (verbatim): "Load an immutable
    /// reference to a local."
    #[test]
    fn imm_borrow_loc_pushes_local_reference() {
        let mut state = state_with_frame(2);
        state
            .top_frame_mut()
            .expect("frame")
            .st_loc(0, RuntimeValue::U64(42))
            .expect("ok");
        dispatch(&mut state, Bytecode::ImmBorrowLoc(0)).expect("ok");
        if let RuntimeValue::Reference(r) = top(&state) {
            assert_eq!(r.read_ref().expect("ok"), RuntimeValue::U64(42));
        } else {
            panic!("expected Reference on stack");
        }
    }

    /// Whitepaper §6.2.1.4 (verbatim): "Load a mutable reference
    /// to a local."
    #[test]
    fn mut_borrow_loc_pushes_local_reference() {
        let mut state = state_with_frame(2);
        state
            .top_frame_mut()
            .expect("frame")
            .st_loc(0, RuntimeValue::U64(42))
            .expect("ok");
        dispatch(&mut state, Bytecode::MutBorrowLoc(0)).expect("ok");
        // Verify the reference can be written through.
        if let RuntimeValue::Reference(r) = top(&state) {
            r.write_ref(RuntimeValue::U64(99)).expect("ok");
            assert_eq!(
                state.top_frame().expect("frame").locals.borrow()[0],
                Some(RuntimeValue::U64(99))
            );
        } else {
            panic!("expected Reference on stack");
        }
    }

    /// Whitepaper §6.2.1.4 (verbatim): "Read through a reference.
    /// The value's type must have `Copy`."
    #[test]
    fn read_ref_pops_reference_pushes_value() {
        let mut state = state_with_frame(1);
        state
            .top_frame_mut()
            .expect("frame")
            .st_loc(0, RuntimeValue::U64(7))
            .expect("ok");
        // Push a Local reference and ReadRef.
        dispatch(&mut state, Bytecode::ImmBorrowLoc(0)).expect("ok");
        dispatch(&mut state, Bytecode::ReadRef).expect("ok");
        assert_eq!(top(&state), RuntimeValue::U64(7));
    }

    /// Whitepaper §6.2.1.4 (verbatim): "Write through a reference.
    /// The previous value's type must have `Drop`."
    ///
    /// WriteRef pop order: reference (top), value (next).
    #[test]
    fn write_ref_writes_through_reference() {
        let mut state = state_with_frame(1);
        state
            .top_frame_mut()
            .expect("frame")
            .st_loc(0, RuntimeValue::U64(7))
            .expect("ok");
        // Push value (will be below ref on stack).
        push_stack(&mut state, vec![RuntimeValue::U64(99)]);
        // Push reference (top of stack).
        dispatch(&mut state, Bytecode::MutBorrowLoc(0)).expect("ok");
        // WriteRef pops both.
        dispatch(&mut state, Bytecode::WriteRef).expect("ok");
        assert_eq!(stack_len(&state), 0);
        assert_eq!(
            state.top_frame().expect("frame").locals.borrow()[0],
            Some(RuntimeValue::U64(99))
        );
    }

    /// FreezeRef is a runtime no-op per Sui-VM source quote at
    /// commit a9a6825eaf6273cc819ee3bcf65fd4909f7624a9. Verifier
    /// validates mut/immut distinctions; runtime preserves the
    /// reference unchanged.
    #[test]
    fn freeze_ref_is_runtime_no_op() {
        let mut state = state_with_frame(1);
        state
            .top_frame_mut()
            .expect("frame")
            .st_loc(0, RuntimeValue::U64(42))
            .expect("ok");
        dispatch(&mut state, Bytecode::MutBorrowLoc(0)).expect("ok");
        let pre_pc = pc(&state);
        dispatch(&mut state, Bytecode::FreezeRef).expect("ok");
        // pc advances; reference is preserved on stack.
        assert_eq!(pc(&state), pre_pc + 1);
        assert!(matches!(top(&state), RuntimeValue::Reference(_)));
    }

    /// Whitepaper §6.2.1.4 (verbatim): "Load a mutable reference
    /// to a struct field."
    ///
    /// Composed-borrow exercise: borrow_field through the
    /// 5/6.2c.1.b composed-borrow correction.
    #[test]
    fn mut_borrow_field_descends_through_composed_borrow() {
        use adamant_bytecode_format::FieldHandle;
        use adamant_types::TypeId;

        // Construct outer struct with one field at offset 0 = U64.
        let outer = Value::Struct(StructValue {
            type_id: TypeId::from_bytes([0x01; 32]),
            fields: vec![Value::U64(7)],
        });
        let runtime_outer = RuntimeValue::from_value(outer);
        let mut state = state_with_frame(1);
        state
            .top_frame_mut()
            .expect("frame")
            .st_loc(0, runtime_outer)
            .expect("ok");

        // Module needs a FieldHandle at index 0 referencing field 0.
        let mut module = empty_module();
        module.field_handles.push(FieldHandle {
            owner: adamant_bytecode_format::StructDefinitionIndex(0),
            field: 0, // MemberCount = u16
        });

        // BorrowLoc(0): pushes Reference::Local pointing at the outer struct.
        dispatch_instruction(
            &BytecodeInstruction::Inherited(Bytecode::ImmBorrowLoc(0)),
            &mut state,
            &module,
        )
        .expect("ok");
        // BorrowField(handle 0): pops the Local ref, pushes a field reference.
        dispatch_instruction(
            &BytecodeInstruction::Inherited(Bytecode::MutBorrowField(
                adamant_bytecode_format::FieldHandleIndex::new(0),
            )),
            &mut state,
            &module,
        )
        .expect("ok");
        // ReadRef: pops the field ref, pushes the U64 value.
        dispatch_instruction(
            &BytecodeInstruction::Inherited(Bytecode::ReadRef),
            &mut state,
            &module,
        )
        .expect("ok");
        assert_eq!(top(&state), RuntimeValue::U64(7));
    }

    /// VecImmBorrow / VecMutBorrow construct an element reference.
    #[test]
    fn vec_imm_borrow_pushes_element_reference() {
        use adamant_bytecode_format::{Signature, SignatureIndex, SignatureToken};
        let runtime_vec = RuntimeValue::from_value(Value::Vector(vec![
            Value::U64(10),
            Value::U64(20),
            Value::U64(30),
        ]));
        let mut state = state_with_frame(1);
        state
            .top_frame_mut()
            .expect("frame")
            .st_loc(0, runtime_vec)
            .expect("ok");

        let mut module = empty_module();
        module.signatures.push(Signature(vec![SignatureToken::U64]));

        // BorrowLoc(0) -> reference to local
        dispatch_instruction(
            &BytecodeInstruction::Inherited(Bytecode::ImmBorrowLoc(0)),
            &mut state,
            &module,
        )
        .expect("ok");
        // Push index (1).
        push_stack(&mut state, vec![RuntimeValue::U64(1)]);
        // Wait — VecImmBorrow expects (vec_ref, idx) on stack with idx on top.
        // Above I have (ref, idx) — ref is below, idx on top. ✓ shape matches.
        // But VecImmBorrow takes a SignatureIndex operand for element type.
        dispatch_instruction(
            &BytecodeInstruction::Inherited(Bytecode::VecImmBorrow(SignatureIndex(0))),
            &mut state,
            &module,
        )
        .expect("ok");
        // Top of stack is element reference; ReadRef gets the element.
        dispatch_instruction(
            &BytecodeInstruction::Inherited(Bytecode::ReadRef),
            &mut state,
            &module,
        )
        .expect("ok");
        assert_eq!(top(&state), RuntimeValue::U64(20));
    }

    /// MutBorrowField on out-of-bounds field handle surfaces
    /// IndexOutOfBoundsPostVerification.
    #[test]
    fn mut_borrow_field_handle_out_of_bounds_invariant_violation() {
        let module = empty_module();
        let mut state = state_with_frame(1);
        // Push a Reference::Local first (otherwise StackUnderflow).
        state
            .top_frame_mut()
            .expect("frame")
            .st_loc(
                0,
                RuntimeValue::from_value(Value::Struct(StructValue {
                    type_id: adamant_types::TypeId::from_bytes([0x01; 32]),
                    fields: vec![Value::U64(7)],
                })),
            )
            .expect("ok");
        dispatch_instruction(
            &BytecodeInstruction::Inherited(Bytecode::ImmBorrowLoc(0)),
            &mut state,
            &module,
        )
        .expect("ok");
        // Now try to borrow a field via an out-of-bounds handle.
        let err = dispatch_instruction(
            &BytecodeInstruction::Inherited(Bytecode::MutBorrowField(
                adamant_bytecode_format::FieldHandleIndex::new(99),
            )),
            &mut state,
            &module,
        )
        .expect_err("err");
        assert!(matches!(
            err,
            VMError::InvariantViolation {
                reason: InvariantViolationReason::IndexOutOfBoundsPostVerification,
            }
        ));
    }

    // ============================================================
    // do_call frame-creation outer-driver tests (5/6.2c.2.α)
    // ============================================================

    /// Whitepaper §6.2.1.4 (verbatim): "function arguments are
    /// passed via the operand stack (popped one per parameter in
    /// declaration order, top-of-stack last)."
    ///
    /// do_call resolves a single-module function call: pops
    /// arguments, creates new frame with locals populated.
    #[test]
    fn do_call_pops_args_and_creates_frame() {
        use adamant_bytecode_format::{
            FunctionHandle, IdentifierIndex, ModuleHandleIndex, Signature, SignatureIndex,
            SignatureToken,
        };

        let mut module = empty_module();
        // Add a single FunctionHandle: 2 u64 parameters, no return,
        // no type parameters.
        module
            .signatures
            .push(Signature(vec![SignatureToken::U64, SignatureToken::U64])); // index 0 — parameters
        module.signatures.push(Signature(vec![])); // index 1 — return
        module.signatures.push(Signature(vec![])); // index 2 — body locals (empty)
        module.function_handles.push(FunctionHandle {
            module: ModuleHandleIndex(0),
            name: IdentifierIndex(0),
            parameters: SignatureIndex(0),
            return_: SignatureIndex(1),
            type_parameters: vec![],
        });
        // Add a function definition referencing handle 0 with empty
        // body locals signature.
        module
            .function_defs
            .push(crate::module::AdamantFunctionDefinition {
                function: fh(0),
                visibility: adamant_bytecode_format::Visibility::Private,
                is_entry: false,
                acquires_global_resources: vec![],
                code: Some(crate::module::AdamantCodeUnit {
                    locals: SignatureIndex(2),
                    code: vec![],
                    jump_tables: vec![],
                }),
            });

        let mut state = state_with_frame(0);
        // Push 2 arguments: 0x100 (first), 0x200 (second).
        push_stack(
            &mut state,
            vec![RuntimeValue::U64(0x100), RuntimeValue::U64(0x200)],
        );
        // Dispatch Call — returns DispatchOutcome::Call.
        let outcome = dispatch_instruction(
            &BytecodeInstruction::Inherited(Bytecode::Call(fh(0))),
            &mut state,
            &module,
        )
        .expect("ok");
        match outcome {
            DispatchOutcome::Call(handle) => {
                // Outer-driver dispatch.
                do_call(&mut state, &module, handle).expect("ok");
            }
            other => panic!("expected Call outcome, got {other:?}"),
        }
        // Verify a new frame was pushed.
        assert_eq!(state.frame_depth(), 2);
        let new_frame = state.top_frame().expect("frame");
        assert_eq!(new_frame.function_handle.0, 0);
        // Parameters populated in locals[0..2].
        let cell = new_frame.locals.borrow();
        assert_eq!(cell[0], Some(RuntimeValue::U64(0x100)));
        assert_eq!(cell[1], Some(RuntimeValue::U64(0x200)));
    }

    /// Native function (code = None) surfaces InvariantViolation
    /// per Rule 4 verifier-residual.
    #[test]
    fn do_call_native_function_invariant_violation() {
        use adamant_bytecode_format::{
            FunctionHandle, IdentifierIndex, ModuleHandleIndex, Signature, SignatureIndex,
        };
        let mut module = empty_module();
        module.signatures.push(Signature(vec![]));
        module.signatures.push(Signature(vec![]));
        module.function_handles.push(FunctionHandle {
            module: ModuleHandleIndex(0),
            name: IdentifierIndex(0),
            parameters: SignatureIndex(0),
            return_: SignatureIndex(1),
            type_parameters: vec![],
        });
        module
            .function_defs
            .push(crate::module::AdamantFunctionDefinition {
                function: fh(0),
                visibility: adamant_bytecode_format::Visibility::Private,
                is_entry: false,
                acquires_global_resources: vec![],
                code: None, // native
            });

        let mut state = state_with_frame(0);
        let err = do_call(&mut state, &module, fh(0)).expect_err("err");
        assert!(matches!(
            err,
            VMError::InvariantViolation {
                reason: InvariantViolationReason::DeprecatedOpcodePostVerification,
            }
        ));
    }

    /// do_call with FunctionHandleIndex out of bounds surfaces
    /// IndexOutOfBoundsPostVerification.
    #[test]
    fn do_call_handle_out_of_bounds_invariant_violation() {
        let module = empty_module();
        let mut state = state_with_frame(0);
        let err = do_call(&mut state, &module, fh(99)).expect_err("err");
        assert!(matches!(
            err,
            VMError::InvariantViolation {
                reason: InvariantViolationReason::IndexOutOfBoundsPostVerification,
            }
        ));
    }

    /// CallGeneric returns DispatchOutcome::CallGeneric.
    #[test]
    fn call_generic_returns_dispatch_outcome_call_generic() {
        use adamant_bytecode_format::FunctionInstantiationIndex;
        let mut state = state_with_frame(0);
        let outcome = dispatch(
            &mut state,
            Bytecode::CallGeneric(FunctionInstantiationIndex::new(0)),
        )
        .expect("ok");
        assert!(matches!(outcome, DispatchOutcome::CallGeneric(_)));
    }

    // ============================================================
    // run() integration
    // ============================================================

    /// Whitepaper §6.2.2 step 5 (verbatim): "Bytecode runs to
    /// completion." A trivial program that just calls Ret
    /// completes cleanly.
    #[test]
    fn run_trivial_ret_completes() {
        let mut state = state_with_frame(0);
        let module = empty_module();
        let result = run(
            &mut state,
            &module,
            |_h, _pc| Some(BytecodeInstruction::Inherited(Bytecode::Ret)),
            None,
        );
        assert!(result.is_ok());
        assert!(state.is_empty());
    }

    /// Phase 5/6.8.A — native dispatch hook: when the registry
    /// resolves a `Bytecode::Call` target, the native handler
    /// runs instead of pushing a new frame. The handler's
    /// return values appear on the caller frame's stack.
    #[test]
    fn run_invokes_native_handler_when_registered() {
        use crate::runtime::{NativeFunction, NativeKey, NativeRegistry, STDLIB_ADDRESS};
        use adamant_bytecode_format::{
            AddressIdentifierIndex, FunctionHandle, IdentifierIndex, ModuleHandle,
            ModuleHandleIndex, Signature, SignatureIndex, SignatureToken,
        };

        let mut module = empty_module();
        // Wire a stdlib function handle for `0x1::probe::native`.
        module.module_handles.push(ModuleHandle {
            address: AddressIdentifierIndex(0),
            name: IdentifierIndex(0),
        });
        module.address_identifiers.push(STDLIB_ADDRESS);
        module
            .identifiers
            .push(adamant_bytecode_format::Identifier::new("probe").unwrap());
        module
            .identifiers
            .push(adamant_bytecode_format::Identifier::new("native").unwrap());
        // signatures[0]: empty (parameters)
        module.signatures.push(Signature(vec![]));
        // signatures[1]: one U64 (return) — matches the handler's
        // return-value count post-audit-pass F-3 arity check.
        module.signatures.push(Signature(vec![SignatureToken::U64]));
        module.function_handles.push(FunctionHandle {
            module: ModuleHandleIndex(0),
            name: IdentifierIndex(1),
            parameters: SignatureIndex(0),
            return_: SignatureIndex(1),
            type_parameters: vec![],
        });

        // Native handler pushes a sentinel value.
        let handler_fn: NativeFunction = native_probe_handler;

        let mut registry = NativeRegistry::new();
        registry.register(
            NativeKey::new(
                STDLIB_ADDRESS,
                adamant_bytecode_format::Identifier::new("probe").unwrap(),
                adamant_bytecode_format::Identifier::new("native").unwrap(),
            ),
            handler_fn,
        );

        let mut state = state_with_frame(0);
        let target_handle = adamant_bytecode_format::FunctionHandleIndex(0);
        let fired = std::cell::Cell::new(false);
        let result = run(
            &mut state,
            &module,
            |_h, _pc| {
                if fired.get() {
                    None
                } else {
                    fired.set(true);
                    Some(BytecodeInstruction::Inherited(Bytecode::Call(
                        target_handle,
                    )))
                }
            },
            Some(&registry),
        );
        // After the native fires, the next fetch returns None →
        // InvalidInstruction. Reaching that error confirms the
        // native ran without pushing a new frame (no frame push
        // would have happened for a missing-fetch on a callee
        // bytecode body).
        assert!(matches!(result, Err(VMError::InvalidInstruction { .. })));
        // The native's return value made it to the caller's stack.
        let frame = state.top_frame().expect("caller frame still present");
        assert_eq!(frame.stack.len(), 1);
        assert!(matches!(frame.stack[0], RuntimeValue::U64(0xCAFE)));
    }

    /// Audit-pass F-3: a handler that returns more values than
    /// the function's declared `return_` signature surfaces as
    /// [`InvariantViolationReason::ReturnArityMismatchPostNativeHandler`].
    #[test]
    fn run_native_handler_arity_mismatch_surfaces_invariant_violation() {
        use crate::runtime::{NativeFunction, NativeKey, NativeRegistry, STDLIB_ADDRESS};
        use adamant_bytecode_format::{
            AddressIdentifierIndex, FunctionHandle, IdentifierIndex, ModuleHandle,
            ModuleHandleIndex, Signature, SignatureIndex,
        };

        let mut module = empty_module();
        module.module_handles.push(ModuleHandle {
            address: AddressIdentifierIndex(0),
            name: IdentifierIndex(0),
        });
        module.address_identifiers.push(STDLIB_ADDRESS);
        module
            .identifiers
            .push(adamant_bytecode_format::Identifier::new("probe").unwrap());
        module
            .identifiers
            .push(adamant_bytecode_format::Identifier::new("rogue").unwrap());
        // Empty params + empty return signature.
        module.signatures.push(Signature(vec![]));
        module.function_handles.push(FunctionHandle {
            module: ModuleHandleIndex(0),
            name: IdentifierIndex(1),
            parameters: SignatureIndex(0),
            return_: SignatureIndex(0),
            type_parameters: vec![],
        });

        // Handler pushes 1 return value but stub declares 0.
        let handler_fn: NativeFunction = native_probe_handler;
        let mut registry = NativeRegistry::new();
        registry.register(
            NativeKey::new(
                STDLIB_ADDRESS,
                adamant_bytecode_format::Identifier::new("probe").unwrap(),
                adamant_bytecode_format::Identifier::new("rogue").unwrap(),
            ),
            handler_fn,
        );

        let mut state = state_with_frame(0);
        let target_handle = adamant_bytecode_format::FunctionHandleIndex(0);
        let fired = std::cell::Cell::new(false);
        let result = run(
            &mut state,
            &module,
            |_h, _pc| {
                if fired.get() {
                    None
                } else {
                    fired.set(true);
                    Some(BytecodeInstruction::Inherited(Bytecode::Call(
                        target_handle,
                    )))
                }
            },
            Some(&registry),
        );
        assert!(matches!(
            result,
            Err(VMError::InvariantViolation {
                reason: InvariantViolationReason::ReturnArityMismatchPostNativeHandler,
            })
        ));
    }

    /// Audit-pass F-1: a handler that mutates the call-frame stack
    /// (pushing a frame) violates the native-dispatch contract;
    /// the post-handler frame-depth check surfaces this as
    /// [`InvariantViolationReason::NativeHandlerMutatedFrameStack`].
    #[test]
    fn run_native_handler_frame_mutation_surfaces_invariant_violation() {
        use crate::runtime::{NativeFunction, NativeKey, NativeRegistry, STDLIB_ADDRESS};
        use adamant_bytecode_format::{
            AddressIdentifierIndex, FunctionHandle, IdentifierIndex, ModuleHandle,
            ModuleHandleIndex, Signature, SignatureIndex,
        };

        // A handler that pushes a fresh frame onto the call stack.
        // The dispatch loop's contract forbids this.
        #[allow(clippy::unnecessary_wraps, reason = "match NativeFunction signature")]
        fn frame_pushing_handler(
            ctx: &mut crate::runtime::NativeContext<'_>,
        ) -> Result<(), VMError> {
            ctx.state.push_frame(Frame::new(
                adamant_bytecode_format::FunctionHandleIndex(0),
                0,
            ));
            Ok(())
        }

        let mut module = empty_module();
        module.module_handles.push(ModuleHandle {
            address: AddressIdentifierIndex(0),
            name: IdentifierIndex(0),
        });
        module.address_identifiers.push(STDLIB_ADDRESS);
        module
            .identifiers
            .push(adamant_bytecode_format::Identifier::new("probe").unwrap());
        module
            .identifiers
            .push(adamant_bytecode_format::Identifier::new("misbehaved").unwrap());
        module.signatures.push(Signature(vec![]));
        module.function_handles.push(FunctionHandle {
            module: ModuleHandleIndex(0),
            name: IdentifierIndex(1),
            parameters: SignatureIndex(0),
            return_: SignatureIndex(0),
            type_parameters: vec![],
        });

        let handler_fn: NativeFunction = frame_pushing_handler;
        let mut registry = NativeRegistry::new();
        registry.register(
            NativeKey::new(
                STDLIB_ADDRESS,
                adamant_bytecode_format::Identifier::new("probe").unwrap(),
                adamant_bytecode_format::Identifier::new("misbehaved").unwrap(),
            ),
            handler_fn,
        );

        let mut state = state_with_frame(0);
        let target_handle = adamant_bytecode_format::FunctionHandleIndex(0);
        let fired = std::cell::Cell::new(false);
        let result = run(
            &mut state,
            &module,
            |_h, _pc| {
                if fired.get() {
                    None
                } else {
                    fired.set(true);
                    Some(BytecodeInstruction::Inherited(Bytecode::Call(
                        target_handle,
                    )))
                }
            },
            Some(&registry),
        );
        assert!(matches!(
            result,
            Err(VMError::InvariantViolation {
                reason: InvariantViolationReason::NativeHandlerMutatedFrameStack,
            })
        ));
    }

    /// Phase 5/6.8.A — native dispatch passthrough: when the
    /// registry has no entry for the call target, dispatch falls
    /// through to ordinary `do_call` (i.e., a new frame is
    /// pushed). The behaviour is byte-identical to the
    /// `natives = None` path.
    #[test]
    fn run_falls_through_to_bytecode_when_target_not_registered() {
        use crate::runtime::NativeRegistry;
        let registry = NativeRegistry::new(); // empty
        let mut state = state_with_frame(0);
        let module = empty_module();
        let result = run(
            &mut state,
            &module,
            |_h, _pc| Some(BytecodeInstruction::Inherited(Bytecode::Ret)),
            Some(&registry),
        );
        assert!(result.is_ok());
        assert!(state.is_empty());
    }

    /// Push 7, push 11, add, ret: yields 18 on operand stack at
    /// halt boundary (frame is popped at Ret; this test holds the
    /// intermediate state via `dispatch` calls instead of `run`).
    #[test]
    fn dispatch_sequence_push_push_add() {
        let mut state = state_with_frame(0);
        dispatch(&mut state, Bytecode::LdU64(7)).expect("ok");
        dispatch(&mut state, Bytecode::LdU64(11)).expect("ok");
        dispatch(&mut state, Bytecode::Add).expect("ok");
        assert_eq!(top(&state), RuntimeValue::U64(18));
    }

    // ============================================================
    // Variant-vs-test mapping audit (12 new variants)
    // ============================================================
    //
    // Each new variant gets at least one explicit negative test.

    /// VMError::ArithmeticError + ArithmeticErrorReason::Overflow.
    #[test]
    fn variant_audit_arithmetic_error_overflow() {
        let mut state = state_with_frame(0);
        push_stack(
            &mut state,
            vec![RuntimeValue::U64(u64::MAX), RuntimeValue::U64(1)],
        );
        let err = dispatch(&mut state, Bytecode::Add).expect_err("err");
        assert!(matches!(
            err,
            VMError::ArithmeticError {
                reason: ArithmeticErrorReason::Overflow,
            }
        ));
    }

    /// ArithmeticErrorReason::Underflow.
    #[test]
    fn variant_audit_arithmetic_error_underflow() {
        let mut state = state_with_frame(0);
        push_stack(&mut state, vec![RuntimeValue::U64(0), RuntimeValue::U64(1)]);
        let err = dispatch(&mut state, Bytecode::Sub).expect_err("err");
        assert!(matches!(
            err,
            VMError::ArithmeticError {
                reason: ArithmeticErrorReason::Underflow,
            }
        ));
    }

    /// ArithmeticErrorReason::DivisionByZero.
    #[test]
    fn variant_audit_arithmetic_error_division_by_zero() {
        let mut state = state_with_frame(0);
        push_stack(&mut state, vec![RuntimeValue::U64(1), RuntimeValue::U64(0)]);
        let err = dispatch(&mut state, Bytecode::Div).expect_err("err");
        assert!(matches!(
            err,
            VMError::ArithmeticError {
                reason: ArithmeticErrorReason::DivisionByZero,
            }
        ));
    }

    /// ArithmeticErrorReason::ShiftAmountTooLarge.
    #[test]
    fn variant_audit_arithmetic_error_shift_amount_too_large() {
        let mut state = state_with_frame(0);
        push_stack(&mut state, vec![RuntimeValue::U8(1), RuntimeValue::U8(8)]);
        let err = dispatch(&mut state, Bytecode::Shl).expect_err("err");
        assert!(matches!(
            err,
            VMError::ArithmeticError {
                reason: ArithmeticErrorReason::ShiftAmountTooLarge,
            }
        ));
    }

    /// ArithmeticErrorReason::CastNotRepresentable.
    #[test]
    fn variant_audit_arithmetic_error_cast_not_representable() {
        let mut state = state_with_frame(0);
        push_stack(&mut state, vec![RuntimeValue::U64(256)]);
        let err = dispatch(&mut state, Bytecode::CastU8).expect_err("err");
        assert!(matches!(
            err,
            VMError::ArithmeticError {
                reason: ArithmeticErrorReason::CastNotRepresentable,
            }
        ));
    }

    /// InvariantViolationReason::DeprecatedOpcodePostVerification.
    #[test]
    fn variant_audit_invariant_deprecated_opcode() {
        use adamant_bytecode_format::StructDefinitionIndex;
        let mut state = state_with_frame(0);
        let err = dispatch(
            &mut state,
            Bytecode::MoveToDeprecated(StructDefinitionIndex::new(0)),
        )
        .expect_err("err");
        assert!(matches!(
            err,
            VMError::InvariantViolation {
                reason: InvariantViolationReason::DeprecatedOpcodePostVerification,
            }
        ));
    }

    /// InvariantViolationReason::StackUnderflow.
    #[test]
    fn variant_audit_invariant_stack_underflow() {
        let mut state = state_with_frame(0);
        let err = dispatch(&mut state, Bytecode::Pop).expect_err("err");
        assert!(matches!(
            err,
            VMError::InvariantViolation {
                reason: InvariantViolationReason::StackUnderflow,
            }
        ));
    }

    /// InvariantViolationReason::TypeMismatchOnStack.
    #[test]
    fn variant_audit_invariant_type_mismatch_on_stack() {
        let mut state = state_with_frame(0);
        push_stack(&mut state, vec![RuntimeValue::U64(1)]);
        let err = dispatch(&mut state, Bytecode::BrTrue(0)).expect_err("err");
        assert!(matches!(
            err,
            VMError::InvariantViolation {
                reason: InvariantViolationReason::TypeMismatchOnStack,
            }
        ));
    }

    /// InvariantViolationReason::IndexOutOfBoundsPostVerification.
    #[test]
    fn variant_audit_invariant_local_index_out_of_bounds() {
        let mut state = state_with_frame(2);
        let err = dispatch(&mut state, Bytecode::CopyLoc(99)).expect_err("err");
        assert!(matches!(
            err,
            VMError::InvariantViolation {
                reason: InvariantViolationReason::IndexOutOfBoundsPostVerification,
            }
        ));
    }

    /// InvariantViolationReason::LocalNotInitialized.
    #[test]
    fn variant_audit_invariant_local_not_initialized() {
        let mut state = state_with_frame(2);
        let err = dispatch(&mut state, Bytecode::CopyLoc(0)).expect_err("err");
        assert!(matches!(
            err,
            VMError::InvariantViolation {
                reason: InvariantViolationReason::LocalNotInitialized,
            }
        ));
    }

    /// InvariantViolationReason::BranchTargetOutOfBounds — defers
    /// to 5/6.2c since branch-target bounds-check needs the
    /// function's bytecode body length (currently surfaces via
    /// `fetch_instruction` returning None at run-loop level,
    /// which maps to InvalidInstruction). The
    /// BranchTargetOutOfBounds variant is registered for future
    /// use when the run loop gains explicit bounds-check logic.
    #[test]
    fn variant_audit_invariant_branch_target_out_of_bounds_registered() {
        // This test documents that the variant exists and is
        // intentionally not yet exercised by a runtime path at
        // 5/6.2b. Future sub-arcs (5/6.2c module-access dispatch)
        // wire the explicit bounds check.
        let _ = InvariantViolationReason::BranchTargetOutOfBounds;
    }
}
