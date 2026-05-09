//! Per-function execution frame — whitepaper §6.2.1.4 + §6.2.2.

#![allow(
    clippy::missing_errors_doc,
    reason = "the pop_* and locals helpers all share the same error semantics (StackUnderflow + TypeMismatchOnStack for pop_*; LocalIndexOutOfBounds + LocalNotInitialized for locals); each method's doc prose already documents the error condition in the verifier-residual binding posture"
)]
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

use adamant_bytecode_format::{FunctionHandleIndex, LocalIndex};
use adamant_types::Address;

use crate::runtime::error::{InvariantViolationReason, VMError};
use crate::value::{StructValue, Value};

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

    // ---------- operand stack push/pop helpers ----------
    //
    // Per Phase 5/6.2b plan-gate Q5/6.2b.2: inherent methods on
    // Frame for value-stack ops. Each `pop_*` typed method
    // verifies that the popped value's variant matches the
    // expected type per the verifier-residual posture; mismatch
    // surfaces as `VMError::InvariantViolation { reason: ... }`
    // because the verifier's stack_usage + type_safety passes
    // should have pre-empted such cases at deploy time.

    /// Push a value onto the operand stack.
    pub fn push_value(&mut self, value: Value) {
        self.stack.push(value);
    }

    /// Pop the top value from the operand stack regardless of its
    /// variant. Returns `InvariantViolation { StackUnderflow }`
    /// when the stack is empty (verifier-residual binding per
    /// `stack_usage` pass).
    pub fn pop_value(&mut self) -> Result<Value, VMError> {
        self.stack.pop().ok_or(VMError::InvariantViolation {
            reason: InvariantViolationReason::StackUnderflow,
        })
    }

    /// Pop a `u8` from the operand stack. Returns
    /// `InvariantViolation { TypeMismatchOnStack }` when the top
    /// value is not [`Value::U8`].
    pub fn pop_u8(&mut self) -> Result<u8, VMError> {
        match self.pop_value()? {
            Value::U8(v) => Ok(v),
            _ => Err(VMError::InvariantViolation {
                reason: InvariantViolationReason::TypeMismatchOnStack,
            }),
        }
    }

    /// Pop a `u16` from the operand stack.
    pub fn pop_u16(&mut self) -> Result<u16, VMError> {
        match self.pop_value()? {
            Value::U16(v) => Ok(v),
            _ => Err(VMError::InvariantViolation {
                reason: InvariantViolationReason::TypeMismatchOnStack,
            }),
        }
    }

    /// Pop a `u32` from the operand stack.
    pub fn pop_u32(&mut self) -> Result<u32, VMError> {
        match self.pop_value()? {
            Value::U32(v) => Ok(v),
            _ => Err(VMError::InvariantViolation {
                reason: InvariantViolationReason::TypeMismatchOnStack,
            }),
        }
    }

    /// Pop a `u64` from the operand stack.
    pub fn pop_u64(&mut self) -> Result<u64, VMError> {
        match self.pop_value()? {
            Value::U64(v) => Ok(v),
            _ => Err(VMError::InvariantViolation {
                reason: InvariantViolationReason::TypeMismatchOnStack,
            }),
        }
    }

    /// Pop a `u128` from the operand stack.
    pub fn pop_u128(&mut self) -> Result<u128, VMError> {
        match self.pop_value()? {
            Value::U128(v) => Ok(v),
            _ => Err(VMError::InvariantViolation {
                reason: InvariantViolationReason::TypeMismatchOnStack,
            }),
        }
    }

    /// Pop a `u256` from the operand stack as its 32-byte little-
    /// endian representation. Callers convert to
    /// [`adamant_bytecode_format::U256`] via `from_le_bytes` for
    /// arithmetic operations.
    pub fn pop_u256(&mut self) -> Result<[u8; 32], VMError> {
        match self.pop_value()? {
            Value::U256(bytes) => Ok(bytes),
            _ => Err(VMError::InvariantViolation {
                reason: InvariantViolationReason::TypeMismatchOnStack,
            }),
        }
    }

    /// Pop a `bool` from the operand stack.
    pub fn pop_bool(&mut self) -> Result<bool, VMError> {
        match self.pop_value()? {
            Value::Bool(v) => Ok(v),
            _ => Err(VMError::InvariantViolation {
                reason: InvariantViolationReason::TypeMismatchOnStack,
            }),
        }
    }

    /// Pop an `Address` from the operand stack.
    pub fn pop_address(&mut self) -> Result<Address, VMError> {
        match self.pop_value()? {
            Value::Address(v) => Ok(v),
            _ => Err(VMError::InvariantViolation {
                reason: InvariantViolationReason::TypeMismatchOnStack,
            }),
        }
    }

    /// Pop a struct value from the operand stack.
    pub fn pop_struct(&mut self) -> Result<StructValue, VMError> {
        match self.pop_value()? {
            Value::Struct(v) => Ok(v),
            _ => Err(VMError::InvariantViolation {
                reason: InvariantViolationReason::TypeMismatchOnStack,
            }),
        }
    }

    /// Pop a vector value from the operand stack.
    pub fn pop_vector(&mut self) -> Result<Vec<Value>, VMError> {
        match self.pop_value()? {
            Value::Vector(v) => Ok(v),
            _ => Err(VMError::InvariantViolation {
                reason: InvariantViolationReason::TypeMismatchOnStack,
            }),
        }
    }

    // ---------- locals access helpers ----------

    /// Read the local at `idx` and return a clone (for `CopyLoc`).
    /// Returns `LocalIndexOutOfBounds` when `idx` exceeds the
    /// frame's locals capacity; `LocalNotInitialized` when the
    /// slot is unoccupied (moved out or never written via
    /// [`Self::move_loc`]).
    pub fn copy_loc(&self, idx: LocalIndex) -> Result<Value, VMError> {
        let slot = self
            .locals
            .get(idx as usize)
            .ok_or(VMError::InvariantViolation {
                reason: InvariantViolationReason::LocalIndexOutOfBounds,
            })?;
        slot.clone().ok_or(VMError::InvariantViolation {
            reason: InvariantViolationReason::LocalNotInitialized,
        })
    }

    /// Move the local at `idx`, leaving the slot unoccupied (for
    /// `MoveLoc`). Same error conditions as [`Self::copy_loc`].
    pub fn move_loc(&mut self, idx: LocalIndex) -> Result<Value, VMError> {
        let slot = self
            .locals
            .get_mut(idx as usize)
            .ok_or(VMError::InvariantViolation {
                reason: InvariantViolationReason::LocalIndexOutOfBounds,
            })?;
        slot.take().ok_or(VMError::InvariantViolation {
            reason: InvariantViolationReason::LocalNotInitialized,
        })
    }

    /// Store `value` into the local at `idx` (for `StLoc`).
    /// Overwrites any existing value in the slot. Returns
    /// `LocalIndexOutOfBounds` when `idx` exceeds capacity.
    ///
    /// Per Move semantics + verifier's `locals_safety` pass, the
    /// caller is guaranteed that overwriting any existing value
    /// is safe (the slot is empty or contains a Drop-able value).
    /// The runtime simply overwrites without checking — this is
    /// the verifier-residual-binding posture.
    pub fn st_loc(&mut self, idx: LocalIndex, value: Value) -> Result<(), VMError> {
        let slot = self
            .locals
            .get_mut(idx as usize)
            .ok_or(VMError::InvariantViolation {
                reason: InvariantViolationReason::LocalIndexOutOfBounds,
            })?;
        *slot = Some(value);
        Ok(())
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
