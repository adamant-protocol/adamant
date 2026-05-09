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

use core::cell::RefCell;
use std::rc::Rc;

use adamant_bytecode_format::{FunctionHandleIndex, LocalIndex};
use adamant_types::Address;

use crate::runtime::error::{InvariantViolationReason, VMError};
use crate::runtime::runtime_value::{Container, RuntimeValue};

/// Shared, mutably-borrowable storage for a frame's locals.
/// References into the frame's locals (per the
/// [`crate::runtime::Reference::Local`] variant) clone this `Rc`
/// to remain valid for as long as the verifier's `reference_safety`
/// pass proved the borrow lives.
pub type LocalsCell = Rc<RefCell<Vec<Option<RuntimeValue>>>>;

/// Per-function execution frame.
///
/// Carries the abstract machine state per whitepaper §6.2.1.4's
/// `(stack, locals, pc)` framing plus the function-handle locus
/// for diagnostic purposes.
///
/// At sub-arc 5/6.2c.1 the `locals` field changes shape from
/// `Vec<Option<Value>>` (5/6.1 / 5/6.2b) to
/// `Rc<RefCell<Vec<Option<RuntimeValue>>>>`: shared mutable
/// ownership so [`crate::runtime::Reference::Local`] variants
/// can hold `Rc::clone` of the locals storage and read/write
/// through `RefCell::borrow` / `borrow_mut` per the Sui-VM-
/// aligned reference design (Option δ at Phase 5/6.2c plan-
/// gate Q5/6.2c.1). Whitepaper §6.2.1.6's `locals_safety` +
/// `reference_safety` passes guarantee the runtime can rely on
/// `RefCell::borrow` / `borrow_mut` succeeding without runtime
/// aliasing checks; if a `RefCell::borrow_mut` panic fires, the
/// verifier was unsound for the inherited subset.
///
/// The operand stack `stack` becomes `Vec<RuntimeValue>` —
/// runtime values include both BCS-encoded primitives and
/// runtime-only references.
#[derive(Debug, Clone)]
pub struct Frame {
    /// The function this frame is executing. Diagnostic locus
    /// for [`crate::runtime::VMError::InvalidInstruction`].
    pub function_handle: FunctionHandleIndex,
    /// Operand stack per §6.2.1.4. Top of stack is the last
    /// element of the `Vec`. Holds [`RuntimeValue`] which can be
    /// either a BCS-encodable value or a runtime-only reference.
    pub stack: Vec<RuntimeValue>,
    /// Local-variable slots per §6.2.1.4. Indexed by the local-
    /// variable index encoded in `CopyLoc` / `MoveLoc` / `StLoc`
    /// / `BorrowLoc` / `MutBorrowLoc` operands. Wrapped in
    /// `Rc<RefCell<...>>` for shared mutable ownership across
    /// references into the frame.
    pub locals: LocalsCell,
    /// Program counter — offset into the function body's bytecode
    /// instruction sequence per §6.2.1.5. Advances one instruction
    /// at a time except on branch instructions.
    pub pc: u16,
}

impl Frame {
    /// Construct a new frame for `function_handle` with `local_count`
    /// total local slots, all initially unoccupied.
    ///
    /// Per whitepaper §6.2.1.4, function arguments are passed via
    /// the operand stack (popped one per parameter in declaration
    /// order, top-of-stack last). The runtime's `Call` /
    /// `CallGeneric` outer-driver logic (5/6.2c.2) pops arguments
    /// from the caller frame's stack and populates the new
    /// frame's first N local slots via [`Self::st_loc`] before
    /// transferring control.
    #[must_use]
    pub fn new(function_handle: FunctionHandleIndex, local_count: usize) -> Self {
        Self {
            function_handle,
            stack: Vec::new(),
            locals: Rc::new(RefCell::new(vec![None; local_count])),
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

    /// Push a [`RuntimeValue`] onto the operand stack.
    pub fn push_value(&mut self, value: RuntimeValue) {
        self.stack.push(value);
    }

    /// Pop the top [`RuntimeValue`] from the operand stack
    /// regardless of its variant. Returns
    /// `InvariantViolation { StackUnderflow }` when the stack is
    /// empty (verifier-residual binding per `stack_usage` pass).
    pub fn pop_value(&mut self) -> Result<RuntimeValue, VMError> {
        self.stack.pop().ok_or(VMError::InvariantViolation {
            reason: InvariantViolationReason::StackUnderflow,
        })
    }

    /// Pop a `u8` from the operand stack. Returns
    /// `InvariantViolation { TypeMismatchOnStack }` when the top
    /// value is not [`RuntimeValue::U8`].
    pub fn pop_u8(&mut self) -> Result<u8, VMError> {
        match self.pop_value()? {
            RuntimeValue::U8(v) => Ok(v),
            _ => Err(VMError::InvariantViolation {
                reason: InvariantViolationReason::TypeMismatchOnStack,
            }),
        }
    }

    /// Pop a `u16` from the operand stack.
    pub fn pop_u16(&mut self) -> Result<u16, VMError> {
        match self.pop_value()? {
            RuntimeValue::U16(v) => Ok(v),
            _ => Err(VMError::InvariantViolation {
                reason: InvariantViolationReason::TypeMismatchOnStack,
            }),
        }
    }

    /// Pop a `u32` from the operand stack.
    pub fn pop_u32(&mut self) -> Result<u32, VMError> {
        match self.pop_value()? {
            RuntimeValue::U32(v) => Ok(v),
            _ => Err(VMError::InvariantViolation {
                reason: InvariantViolationReason::TypeMismatchOnStack,
            }),
        }
    }

    /// Pop a `u64` from the operand stack.
    pub fn pop_u64(&mut self) -> Result<u64, VMError> {
        match self.pop_value()? {
            RuntimeValue::U64(v) => Ok(v),
            _ => Err(VMError::InvariantViolation {
                reason: InvariantViolationReason::TypeMismatchOnStack,
            }),
        }
    }

    /// Pop a `u128` from the operand stack.
    pub fn pop_u128(&mut self) -> Result<u128, VMError> {
        match self.pop_value()? {
            RuntimeValue::U128(v) => Ok(v),
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
            RuntimeValue::U256(bytes) => Ok(bytes),
            _ => Err(VMError::InvariantViolation {
                reason: InvariantViolationReason::TypeMismatchOnStack,
            }),
        }
    }

    /// Pop a `bool` from the operand stack.
    pub fn pop_bool(&mut self) -> Result<bool, VMError> {
        match self.pop_value()? {
            RuntimeValue::Bool(v) => Ok(v),
            _ => Err(VMError::InvariantViolation {
                reason: InvariantViolationReason::TypeMismatchOnStack,
            }),
        }
    }

    /// Pop an `Address` from the operand stack.
    pub fn pop_address(&mut self) -> Result<Address, VMError> {
        match self.pop_value()? {
            RuntimeValue::Address(v) => Ok(v),
            _ => Err(VMError::InvariantViolation {
                reason: InvariantViolationReason::TypeMismatchOnStack,
            }),
        }
    }

    /// Pop a struct container from the operand stack. Returns
    /// the `Rc<RefCell<RuntimeStructValue>>` shared interior;
    /// callers can `borrow` / `borrow_mut` for read/write access.
    ///
    /// Helper present for 5/6.2c.2 handler integration. 5/6.2c.1
    /// foundation work does not consume this method.
    pub fn pop_struct(
        &mut self,
    ) -> Result<Rc<RefCell<crate::runtime::runtime_value::RuntimeStructValue>>, VMError> {
        match self.pop_value()? {
            RuntimeValue::Container(Container::Struct(rc)) => Ok(rc),
            _ => Err(VMError::InvariantViolation {
                reason: InvariantViolationReason::TypeMismatchOnStack,
            }),
        }
    }

    /// Pop a vector container from the operand stack.
    ///
    /// Helper present for 5/6.2c.2 handler integration.
    pub fn pop_vector(&mut self) -> Result<Rc<RefCell<Vec<RuntimeValue>>>, VMError> {
        match self.pop_value()? {
            RuntimeValue::Container(Container::Vector(rc)) => Ok(rc),
            _ => Err(VMError::InvariantViolation {
                reason: InvariantViolationReason::TypeMismatchOnStack,
            }),
        }
    }

    /// Pop a [`crate::runtime::Reference`] from the operand stack.
    ///
    /// Used by `ReadRef` / `WriteRef` / `FreezeRef` and the
    /// `BorrowField` family at 5/6.2c.2. References are pushed by
    /// `BorrowLoc` / `BorrowField` / vector-element borrows.
    pub fn pop_reference(&mut self) -> Result<crate::runtime::Reference, VMError> {
        match self.pop_value()? {
            RuntimeValue::Reference(r) => Ok(r),
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
    pub fn copy_loc(&self, idx: LocalIndex) -> Result<RuntimeValue, VMError> {
        let cell = self.locals.borrow();
        let slot = cell.get(idx as usize).ok_or(VMError::InvariantViolation {
            reason: InvariantViolationReason::IndexOutOfBoundsPostVerification,
        })?;
        slot.clone().ok_or(VMError::InvariantViolation {
            reason: InvariantViolationReason::LocalNotInitialized,
        })
    }

    /// Move the local at `idx`, leaving the slot unoccupied (for
    /// `MoveLoc`). Same error conditions as [`Self::copy_loc`].
    pub fn move_loc(&mut self, idx: LocalIndex) -> Result<RuntimeValue, VMError> {
        let mut cell = self.locals.borrow_mut();
        let slot = cell
            .get_mut(idx as usize)
            .ok_or(VMError::InvariantViolation {
                reason: InvariantViolationReason::IndexOutOfBoundsPostVerification,
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
    pub fn st_loc(&mut self, idx: LocalIndex, value: RuntimeValue) -> Result<(), VMError> {
        let mut cell = self.locals.borrow_mut();
        let slot = cell
            .get_mut(idx as usize)
            .ok_or(VMError::InvariantViolation {
                reason: InvariantViolationReason::IndexOutOfBoundsPostVerification,
            })?;
        *slot = Some(value);
        Ok(())
    }

    /// Construct a [`crate::runtime::Reference::Local`] reference
    /// to the local at `idx`. Used by `ImmBorrowLoc` /
    /// `MutBorrowLoc` handlers at 5/6.2c.2.
    ///
    /// Per the Sui-VM-aligned reference design (whitepaper
    /// §6.2.1.4 + Phase 5/6.2c.1 Q5/6.2c.1 disposition), the
    /// returned reference holds an `Rc::clone` of the frame's
    /// locals storage so it remains valid across the borrow
    /// lifetime as proved by the verifier's `reference_safety`
    /// pass. Mut/immut distinction is verifier-validated; the
    /// runtime carries no per-reference mutability tag (matching
    /// the `FreezeRef` no-op posture).
    pub fn borrow_loc(&self, idx: LocalIndex) -> Result<crate::runtime::Reference, VMError> {
        let cell = self.locals.borrow();
        if (idx as usize) >= cell.len() {
            return Err(VMError::InvariantViolation {
                reason: InvariantViolationReason::IndexOutOfBoundsPostVerification,
            });
        }
        Ok(crate::runtime::Reference::Local {
            locals: Rc::clone(&self.locals),
            idx: idx as usize,
        })
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
        let cell = frame.locals.borrow();
        assert_eq!(cell.len(), 4);
        assert!(cell.iter().all(Option::is_none));
        assert_eq!(frame.pc, 0);
    }

    #[test]
    fn frame_stack_is_empty_helper() {
        let frame = Frame::new(function_handle(0), 0);
        assert!(frame.stack_is_empty());
    }
}
