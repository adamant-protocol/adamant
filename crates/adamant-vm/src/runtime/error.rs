//! Runtime error type for the Adamant VM (whitepaper §6.2.2).
//!
//! [`VMError`] is the single error type returned by runtime entry
//! points. The variant set follows the Phase 5/5 closed-enum-sub-
//! reason discipline: each top-level variant carries either
//! structured diagnostic data or a closed sub-reason enum.
//!
//! # Variant taxonomy (locked at Phase 5/6.1 plan-gate Q1.3)
//!
//! Top-level variants partition the runtime error surface into
//! categories distinguished by **what the failure means** for the
//! transaction:
//!
//! - [`VMError::Load`] — state-view object load failure (§6.2.2
//!   step 2). The transaction is rejected before execution; gas
//!   is not charged because no execution occurred.
//! - [`VMError::Commit`] — state-mutator commit failure (§6.2.2
//!   step 7). The transaction's accumulated state changes could
//!   not be applied atomically; the transaction is treated as
//!   failed.
//! - [`VMError::ReadSetViolation`] / [`VMError::WriteSetViolation`]
//!   — the transaction attempted to load or modify an object
//!   outside its declared read or write set per §6.2.2 step 2.
//!   The transaction is rejected before execution.
//! - [`VMError::GasExhausted`] — the transaction's gas budget for
//!   one of the six dimensions per §6.3.1 was exhausted during
//!   execution. Execution aborts at the first dimension exhausted.
//! - [`VMError::InvalidInstruction`] — defensive: the bytecode
//!   contains an instruction the runtime cannot dispatch. The
//!   verifier (§6.2.1.6) should pre-empt all such cases at deploy
//!   time; this variant fires only if the verifier was unsound or
//!   if the bytecode was modified post-deployment.
//! - [`VMError::ArithmeticError`] — runtime arithmetic abort per
//!   whitepaper §6.2.1.9. Expected runtime error condition (not
//!   defensive): overflow on Add/Sub/Mul, divide-by-zero on
//!   Div/Mod, shift-amount-too-large on Shl/Shr (U8-U128), or
//!   narrowing-cast-not-representable. Carries an
//!   [`ArithmeticErrorReason`] sub-reason per the closed-enum-
//!   sub-reason discipline.
//! - [`VMError::InvariantViolation`] — defensive: the runtime
//!   encountered a state that should be unreachable under correct
//!   operation. Carries a [`InvariantViolationReason`] sub-reason
//!   per the closed-enum-sub-reason discipline.
//!
//! Per Phase 5/5 verifier-error discipline, `Internal(String)` is
//! intentionally **not** a variant. Every defensive failure mode
//! lands as a typed [`InvariantViolationReason`] sub-reason rather
//! than as a free-form string.

use crate::runtime::state_mutator::CommitError;
use crate::runtime::state_view::LoadError;

use adamant_types::ObjectId;

/// Runtime error type returned by VM entry points (whitepaper §6.2).
///
/// The variant set partitions the runtime error surface into six
/// top-level categories per the Phase 5/6.1 plan-gate disposition.
/// See the module-level documentation for the variant taxonomy.
///
/// `#[non_exhaustive]` is intentionally not applied yet because
/// downstream consumers do not match on this enum at sub-arc
/// 5/6.1; the variant set is still settling. Subsequent sub-arcs
/// (5/6.2 instruction handlers, 5/6.5 gas accounting) may extend
/// the variant set.
#[derive(Debug)]
pub enum VMError {
    /// State-view object load failure per whitepaper §6.2.2 step 2
    /// ("All objects referenced by the transaction are loaded from
    /// chain state").
    ///
    /// Wraps a [`LoadError`] from the [`crate::runtime::StateView`]
    /// trait. The transaction is rejected before execution begins;
    /// no gas is charged because no execution occurred.
    Load(LoadError),

    /// State-mutator commit failure per whitepaper §6.2.2 step 7
    /// ("If execution succeeded ... state changes are committed").
    ///
    /// Wraps a [`CommitError`] from the [`crate::runtime::StateMutator`]
    /// trait. The transaction's accumulated state changes could
    /// not be applied atomically; the transaction is treated as
    /// failed and gas charged per §6.3.3.
    Commit(CommitError),

    /// The transaction attempted to load an object outside its
    /// declared `read_set` per whitepaper §6.2.2 step 2 ("the
    /// loader validates that the transaction touches no objects
    /// outside its declared sets").
    ///
    /// The transaction is rejected before execution.
    ReadSetViolation {
        /// The `ObjectId` the transaction attempted to load.
        attempted: ObjectId,
    },

    /// The transaction attempted to modify an object outside its
    /// declared `write_set` per whitepaper §6.2.2 step 2.
    ///
    /// The `write_set` is a subset of the `read_set`'s `ObjectId`s
    /// per whitepaper §6.0.2 ("Modification requires the object
    /// to be in the read set as well"). An object that is in the
    /// `read_set` but not the `write_set` may be loaded but not
    /// mutated.
    WriteSetViolation {
        /// The `ObjectId` the transaction attempted to modify.
        attempted: ObjectId,
    },

    /// Gas-budget dimension exhausted during execution per
    /// whitepaper §6.2.2 step 5 ("Bytecode runs to completion or
    /// until gas is exhausted") and §6.3.1.
    ///
    /// The runtime aborts at the first dimension exhausted; the
    /// user cannot trade unused budget in one dimension for
    /// additional consumption in another per whitepaper §6.0.2's
    /// `GasBudget` semantics.
    ///
    /// 5/6.5 (gas accounting sub-arc) refines this variant with
    /// per-dimension diagnostic data; the 5/6.1 surface is
    /// minimal.
    GasExhausted {
        /// Which of the six dimensions was exhausted per
        /// [`crate::bytecode::GasDimension`].
        dimension: crate::bytecode::GasDimension,
    },

    /// Defensive: the bytecode contains an instruction the runtime
    /// cannot dispatch.
    ///
    /// The verifier (whitepaper §6.2.1.6) is expected to pre-empt
    /// all such cases at deploy time. This variant fires only if
    /// (a) the verifier was unsound for the inherited subset, (b)
    /// the bytecode was modified after deployment outside the
    /// upgrade-compatibility surface (§6.4.3), or (c) the runtime
    /// encountered a defensive case the verifier could not
    /// statically rule out.
    ///
    /// At sub-arc 5/6.1 the dispatch loop is a scaffold that
    /// returns this variant for every opcode; instruction handlers
    /// land at 5/6.2 (inherited Sui-base) and 5/6.3 (Adamant
    /// extensions).
    InvalidInstruction {
        /// Diagnostic locus: which function and program-counter
        /// offset triggered the dispatch failure.
        function_handle: adamant_bytecode_format::FunctionHandleIndex,
        /// Program counter offset within the function body.
        pc: u16,
    },

    /// Runtime arithmetic abort per whitepaper §6.2.1.9 abort
    /// semantics.
    ///
    /// Distinct from [`Self::InvariantViolation`]: arithmetic
    /// errors are **expected runtime conditions** under §6.2.1.9
    /// (overflow on Add/Sub/Mul, divide-by-zero on Div/Mod,
    /// shift-amount-too-large on Shl/Shr for U8-U128, narrowing-
    /// cast-not-representable on Cast). Contract authors can
    /// trigger these via well-typed bytecode that the verifier
    /// admits; the runtime's binding is to abort the transaction
    /// with state revert per §6.2.2 step 7 and charge gas per
    /// §6.3.3.
    ///
    /// Carries an [`ArithmeticErrorReason`] closed sub-reason
    /// per the closed-enum-sub-reason discipline.
    ArithmeticError {
        /// The specific arithmetic-abort condition.
        reason: ArithmeticErrorReason,
    },

    /// Defensive: the runtime encountered a state that should be
    /// unreachable under correct operation.
    ///
    /// Carries a [`InvariantViolationReason`] closed sub-reason
    /// per the Phase 5/5 closed-enum-sub-reason discipline. New
    /// invariant cases are added as sub-arc work surfaces them;
    /// the closed enum makes the audit surface auditable.
    InvariantViolation {
        /// The specific invariant that was violated.
        reason: InvariantViolationReason,
    },
}

impl From<LoadError> for VMError {
    fn from(err: LoadError) -> Self {
        Self::Load(err)
    }
}

impl From<CommitError> for VMError {
    fn from(err: CommitError) -> Self {
        Self::Commit(err)
    }
}

/// Closed sub-reason enum for [`VMError::ArithmeticError`].
///
/// Per whitepaper §6.2.1.9 arithmetic semantics, the AVM runtime
/// aborts the transaction in five distinct arithmetic conditions.
/// Each is a separate sub-reason for diagnostic clarity.
///
/// Closed-enum-sub-reason discipline (canonical at Phase 5/5b.4
/// D-5a.0): every typed-error variant added at a sub-checkpoint
/// has at least one explicit negative test asserting on the
/// variant shape per the variant-vs-test mapping audit principle.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub enum ArithmeticErrorReason {
    /// `Add` or `Mul` result exceeds the operand type's unsigned
    /// integer range per whitepaper §6.2.1.9 overflow handling.
    Overflow,
    /// `Sub` result would be less than zero (unsigned underflow).
    /// Whitepaper §6.2.1.9 frames Sub abort under "overflow
    /// handling" because Sub on unsigned integers produces
    /// underflow when `rhs > self`.
    Underflow,
    /// `Div` or `Mod` divisor is zero per whitepaper §6.2.1.9
    /// division semantics.
    DivisionByZero,
    /// `Shl` or `Shr` shift amount is greater than or equal to
    /// the operand's bit width for `u8` / `u16` / `u32` / `u64`
    /// / `u128` per whitepaper §6.2.1.9 shift bounds. (For
    /// `u256`, the abort condition is structurally unreachable
    /// because the shift amount is parsed as a `u8` — see
    /// §6.2.1.9.)
    ShiftAmountTooLarge,
    /// `Cast` narrowing where the source value lies outside the
    /// destination type's representable range per whitepaper
    /// §6.2.1.9 cast narrowing semantics.
    CastNotRepresentable,
}

/// Closed sub-reason enum for [`VMError::InvariantViolation`].
///
/// Per the Phase 5/5 closed-enum-sub-reason discipline (registered
/// at Phase 5/5b.4 D-5a.0 with [`crate::validator::error::TypeMismatchReason`]
/// and 10 subsequent canonical sub-reason enums), every defensive
/// runtime failure mode lands as a typed sub-reason rather than as
/// a free-form string.
///
/// Each sub-reason documents a specific verifier-guarantee residual
/// binding per whitepaper §6.2.1.6 line 477 ("The runtime check
/// carries the residual binding for any case the static analysis
/// cannot fully verify"). The runtime-residual-binding-per-
/// verifier-guarantee discipline (registered at Phase 5/6.2b)
/// pairs each sub-reason with the verifier pass that should have
/// pre-empted the case at deploy time.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub enum InvariantViolationReason {
    /// A `#[shielded]` callee was invoked from a `#[transparent]`
    /// caller (or vice-versa) at runtime.
    ///
    /// Whitepaper §6.2.1.6 Rule 7 enforces privacy consistency at
    /// deploy time via the verifier; whitepaper §6.2.1.6 line 477
    /// frames the runtime check as the residual binding. If the
    /// verifier was sound and the bytecode was not modified post-
    /// deployment, this variant should never fire at runtime.
    PrivacyModeMismatchPostVerification,

    /// Bytecode contains a deprecated global-storage opcode
    /// (`MoveFrom`, `MoveTo`, `BorrowGlobal`, `Exists`, etc.).
    ///
    /// Whitepaper §6.2.1.6 Rule 5 + Adamant's parse-time
    /// deserializer reject these opcodes before deployment. If
    /// the runtime encounters one, either the parser was unsound
    /// or the bytecode was modified post-deployment.
    DeprecatedOpcodePostVerification,

    /// Operand stack underflow at instruction handler dispatch —
    /// the handler popped from an empty stack or with too few
    /// values to satisfy the instruction's stack effect.
    ///
    /// The verifier's `stack_usage` pass (§6.2.1.6 inherited
    /// "Stack discipline") should pre-empt this case.
    StackUnderflow,

    /// Stack-top value type does not match the handler's expected
    /// type. For example, an arithmetic instruction popped a
    /// `Bool` instead of an integer, or `BrTrue` popped a non-
    /// boolean value.
    ///
    /// The verifier's `type_safety` pass (§6.2.1.6 inherited
    /// "Type safety") should pre-empt this case.
    TypeMismatchOnStack,

    /// Index out of bounds for a verifier-validated index access.
    ///
    /// Covers all index-shape verifier residuals: local-variable
    /// index, function-handle index, struct-definition index,
    /// field-handle index, constant-pool index, variant-handle
    /// index, struct-field index within a struct's fields array,
    /// vector-element index within a vector's elements. The
    /// verifier's `bounds_checker` pass (§6.2.1.6 inherited
    /// "bounds checking") + per-pool index validation should
    /// pre-empt all such cases at deploy time.
    ///
    /// Renamed at Phase 5/6.2c.1.b from `LocalIndexOutOfBounds`
    /// to generalize across all index-shape residuals — module-
    /// access handlers (5/6.2c.2) reuse this variant for handle/
    /// pool indices alongside locals/field/element indices.
    /// Variant-naming-generalization-as-refactor discipline 1st
    /// instance.
    IndexOutOfBoundsPostVerification,

    /// Local-variable slot is unoccupied (the local has been
    /// moved out via `MoveLoc` or has not been written yet) when
    /// `CopyLoc` / `MoveLoc` / `BorrowLoc` reads from it.
    ///
    /// The verifier's `locals_safety` pass (§6.2.1.6 inherited
    /// "locals safety") should pre-empt this case.
    LocalNotInitialized,

    /// Branch target offset is out of bounds for the executing
    /// function's bytecode body.
    ///
    /// The verifier's `control_flow` pass (§6.2.1.6 inherited
    /// "control-flow integrity") should pre-empt this case.
    BranchTargetOutOfBounds,
}

#[cfg(test)]
mod tests {
    //! Verbatim-spec-quote-grounds-runtime-fixture discipline.

    use super::*;
    use crate::runtime::state_mutator::CommitError;
    use crate::runtime::state_view::LoadError;

    use adamant_types::ObjectId;

    /// `From<LoadError> for VMError` lifts a state-view load
    /// failure into the runtime error surface per the
    /// `VMError::Load` variant.
    #[test]
    fn from_load_error_lifts_into_vmerror_load() {
        let id = ObjectId::from_bytes([0x01; 32]);
        let load_err = LoadError::ObjectNotFound { id };
        let vm_err: VMError = load_err.into();
        assert!(matches!(
            vm_err,
            VMError::Load(LoadError::ObjectNotFound { .. })
        ));
    }

    /// `From<CommitError> for VMError` lifts a state-mutator
    /// commit failure into the runtime error surface per the
    /// `VMError::Commit` variant.
    #[test]
    fn from_commit_error_lifts_into_vmerror_commit() {
        let id = ObjectId::from_bytes([0x02; 32]);
        let commit_err = CommitError::ObjectIdCollision { id };
        let vm_err: VMError = commit_err.into();
        assert!(matches!(
            vm_err,
            VMError::Commit(CommitError::ObjectIdCollision { .. })
        ));
    }

    /// Whitepaper §6.2.1.6 line 477 (verbatim): "The runtime
    /// check carries the residual binding for any case the static
    /// analysis cannot fully verify."
    ///
    /// `InvariantViolationReason::PrivacyModeMismatchPostVerification`
    /// pins the residual-binding rationale per the closed-enum-
    /// sub-reason discipline.
    #[test]
    fn invariant_violation_carries_typed_reason() {
        let err = VMError::InvariantViolation {
            reason: InvariantViolationReason::PrivacyModeMismatchPostVerification,
        };
        assert!(matches!(
            err,
            VMError::InvariantViolation {
                reason: InvariantViolationReason::PrivacyModeMismatchPostVerification,
            }
        ));
    }
}
