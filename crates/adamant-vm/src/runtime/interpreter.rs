//! Direct-interpreter dispatch loop scaffold — whitepaper §6.2.2 step 5.
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

use adamant_bytecode_format::FunctionHandleIndex;

use crate::bytecode::BytecodeInstruction;
use crate::runtime::error::VMError;
use crate::runtime::frame::Frame;

/// Multi-frame interpreter state.
///
/// Holds the call stack — a stack of [`Frame`] entries, with the
/// top entry being the currently-executing function. Function
/// invocation pushes a new frame; function return pops the top
/// frame. Per whitepaper §6.2.2 step 5, execution runs "to
/// completion" — i.e., until the call stack is empty — "or until
/// gas is exhausted."
#[derive(Debug, Clone, Default)]
pub struct InterpreterState {
    frames: Vec<Frame>,
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
    _instruction: &BytecodeInstruction,
    state: &mut InterpreterState,
) -> Result<DispatchOutcome, VMError> {
    let frame = state
        .top_frame()
        .expect("dispatch_instruction caller-contract: call stack must be non-empty");
    // Sub-arc 5/6.1 scaffold: every dispatch is unimplemented.
    // The diagnostic locus is the function handle and the program
    // counter at dispatch time. Subsequent sub-arcs replace this
    // with per-opcode handlers.
    Err(VMError::InvalidInstruction {
        function_handle: frame.function_handle,
        pc: frame.pc,
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
pub fn run(
    state: &mut InterpreterState,
    fetch_instruction: impl Fn(FunctionHandleIndex, u16) -> Option<BytecodeInstruction>,
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
        match dispatch_instruction(&instruction, state)? {
            DispatchOutcome::Continue => {}
            DispatchOutcome::Halt => return Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    //! Verbatim-spec-quote-grounds-runtime-fixture discipline.

    use super::*;
    use crate::bytecode::BytecodeInstruction;
    use crate::runtime::error::VMError;

    use adamant_bytecode_format::Bytecode;

    fn function_handle(idx: u16) -> FunctionHandleIndex {
        FunctionHandleIndex(idx)
    }

    /// Whitepaper §6.2.2 step 5 (verbatim): "Bytecode runs to
    /// completion or until gas is exhausted."
    ///
    /// An empty interpreter state is already at "completion": the
    /// dispatch driver returns `Ok(())` immediately without
    /// calling `dispatch_instruction`.
    #[test]
    fn run_on_empty_interpreter_state_returns_ok() {
        let mut state = InterpreterState::new();
        let result = run(&mut state, |_h, _pc| {
            panic!("fetch_instruction should not be called on empty state")
        });
        assert!(result.is_ok());
    }

    /// Whitepaper §6.2.1.4 (verbatim): "the abstract machine
    /// state per function frame is `(stack, locals, pc)`."
    ///
    /// `push_frame` extends the call stack; `frame_depth` reports
    /// the current depth.
    #[test]
    fn push_frame_extends_call_stack() {
        let mut state = InterpreterState::new();
        assert_eq!(state.frame_depth(), 0);
        state.push_frame(Frame::new(function_handle(0), 0));
        assert_eq!(state.frame_depth(), 1);
        state.push_frame(Frame::new(function_handle(1), 0));
        assert_eq!(state.frame_depth(), 2);
    }

    #[test]
    fn pop_frame_returns_none_on_empty_stack() {
        let mut state = InterpreterState::new();
        assert!(state.pop_frame().is_none());
    }

    /// Sub-arc 5/6.1 scaffold pin: `dispatch_instruction` returns
    /// [`VMError::InvalidInstruction`] for every input. Subsequent
    /// sub-arcs (5/6.2 / 5/6.3 / 5/6.4) replace the scaffold with
    /// per-opcode handlers.
    ///
    /// Whitepaper §6.2.1.6 framing: the verifier (deploy-time)
    /// is expected to pre-empt all `InvalidInstruction` cases.
    /// At sub-arc 5/6.1, this defensive variant is the only path
    /// any dispatch reaches.
    #[test]
    fn dispatch_instruction_returns_invalid_instruction_at_5_6_1_scaffold() {
        let mut state = InterpreterState::new();
        state.push_frame(Frame::new(function_handle(3), 0));
        // The Pop instruction is a Sui-base inherited opcode per
        // §6.2.1.4; the scaffold dispatcher rejects it because no
        // handlers ship at 5/6.1.
        let instruction = BytecodeInstruction::Inherited(Bytecode::Pop);
        let err = dispatch_instruction(&instruction, &mut state).expect_err("scaffold rejects");
        match err {
            VMError::InvalidInstruction {
                function_handle,
                pc,
            } => {
                assert_eq!(function_handle.0, 3);
                assert_eq!(pc, 0);
            }
            other => panic!("expected InvalidInstruction, got {other:?}"),
        }
    }

    /// Whitepaper §6.2.2 step 5 (verbatim): "Bytecode runs to
    /// completion or until gas is exhausted."
    ///
    /// At sub-arc 5/6.1 the scaffold dispatcher rejects every
    /// instruction, so `run` propagates the first
    /// `VMError::InvalidInstruction` from the scaffold.
    #[test]
    fn run_propagates_invalid_instruction_from_scaffold_dispatch() {
        let mut state = InterpreterState::new();
        state.push_frame(Frame::new(function_handle(0), 0));
        let result = run(&mut state, |_h, _pc| {
            Some(BytecodeInstruction::Inherited(Bytecode::Pop))
        });
        assert!(matches!(result, Err(VMError::InvalidInstruction { .. })));
    }

    /// Whitepaper §6.2.2 step 5 (verbatim): "Bytecode runs to
    /// completion." The fetch-instruction callback returning
    /// `None` indicates the program counter exceeds the function
    /// body's bytecode — a bounds violation that the verifier
    /// (§6.2.1.6 step 4 control-flow pass) should pre-empt.
    /// At runtime, the scaffold surfaces it as
    /// `VMError::InvalidInstruction`.
    #[test]
    fn run_returns_invalid_instruction_when_fetch_returns_none() {
        let mut state = InterpreterState::new();
        state.push_frame(Frame::new(function_handle(0), 0));
        let result = run(&mut state, |_h, _pc| None);
        assert!(matches!(result, Err(VMError::InvalidInstruction { .. })));
    }
}
