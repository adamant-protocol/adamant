//! Per-function execution frame — whitepaper §6.2.1.4 + §6.2.2.
//!
//! # Whitepaper §6.2.1.4 (verbatim)
//!
//! > "The architecture is **stack-based** — operands are pushed
//! > onto an operand stack, instructions consume and produce
//! > stack values, and the abstract machine state per function
//! > frame is `(stack, locals, pc)`."
//!
//! [`Frame`] is the runtime's representation of `(stack, locals, pc)`
//! plus the `FunctionHandleIndex` identifying which function the
//! frame is executing. A multi-frame call stack lives at
//! [`crate::runtime::InterpreterState`].

use crate::value::Value;
use adamant_bytecode_format::FunctionHandleIndex;

/// Per-function execution frame.
///
/// Carries the abstract machine state per whitepaper §6.2.1.4's
/// `(stack, locals, pc)` framing plus the function-handle locus
/// for diagnostic purposes.
///
/// At sub-arc 5/6.1 the `locals` field is a `Vec<Option<Value>>`
/// where each slot is either occupied (the local has been written
/// or is a parameter) or unoccupied (the local has been moved out
/// or has not been written yet). Whitepaper §6.2.1.6's locals-
/// safety pass at deploy time guarantees that the runtime's
/// availability tracking does not need to reject reads from
/// unoccupied slots — the verifier ensures every `CopyLoc` /
/// `MoveLoc` / `BorrowLoc` reads only from a slot the static
/// analysis proved available. The `Option` shape preserves the
/// invariant defensively.
#[derive(Debug, Clone)]
pub struct Frame {
    /// The function this frame is executing. Diagnostic locus
    /// for [`crate::runtime::VMError::InvalidInstruction`].
    pub function_handle: FunctionHandleIndex,
    /// Operand stack per §6.2.1.4. Top of stack is the last
    /// element of the `Vec`.
    pub stack: Vec<Value>,
    /// Local-variable slots per §6.2.1.4. Indexed by the local-
    /// variable index encoded in `CopyLoc` / `MoveLoc` / `StLoc`
    /// / `BorrowLoc` / `MutBorrowLoc` operands.
    pub locals: Vec<Option<Value>>,
    /// Program counter — offset into the function body's bytecode
    /// instruction sequence per §6.2.1.5. Advances one instruction
    /// at a time except on branch instructions.
    pub pc: u16,
}

impl Frame {
    /// Construct a new frame for `function_handle` with `arg_count`
    /// parameters initialised in the locals slots and `local_count`
    /// total local slots.
    ///
    /// Per whitepaper §6.2.1.4, function arguments are passed via
    /// the operand stack (popped one per parameter in declaration
    /// order, top-of-stack last). The runtime's `Call` instruction
    /// handler pops the arguments and stores them into the new
    /// frame's first `arg_count` local slots before transferring
    /// control. At sub-arc 5/6.1 there is no `Call` handler yet;
    /// this constructor sets up the locals shape that subsequent
    /// instruction handlers will populate.
    #[must_use]
    pub fn new(function_handle: FunctionHandleIndex, local_count: usize) -> Self {
        Self {
            function_handle,
            stack: Vec::new(),
            locals: vec![None; local_count],
            pc: 0,
        }
    }

    /// Whether the operand stack is empty.
    #[must_use]
    pub fn stack_is_empty(&self) -> bool {
        self.stack.is_empty()
    }
}

#[cfg(test)]
mod tests {
    //! Verbatim-spec-quote-grounds-runtime-fixture discipline.

    use super::*;

    fn function_handle(idx: u16) -> FunctionHandleIndex {
        FunctionHandleIndex(idx)
    }

    /// Whitepaper §6.2.1.4 (verbatim): "the abstract machine
    /// state per function frame is `(stack, locals, pc)`."
    ///
    /// A new frame has empty stack, all locals unoccupied, and
    /// `pc = 0`.
    #[test]
    fn new_frame_has_empty_stack_unoccupied_locals_and_pc_zero() {
        let frame = Frame::new(function_handle(7), 4);
        assert_eq!(frame.function_handle, function_handle(7));
        assert!(frame.stack.is_empty());
        assert_eq!(frame.locals.len(), 4);
        assert!(frame.locals.iter().all(Option::is_none));
        assert_eq!(frame.pc, 0);
    }

    #[test]
    fn frame_stack_is_empty_helper() {
        let frame = Frame::new(function_handle(0), 0);
        assert!(frame.stack_is_empty());
    }
}
