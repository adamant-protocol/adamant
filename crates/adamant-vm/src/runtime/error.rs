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

/// Closed sub-reason enum for [`VMError::InvariantViolation`].
///
/// Per the Phase 5/5 closed-enum-sub-reason discipline (registered
/// at Phase 5/5b.4 D-5a.0 with [`crate::validator::error::TypeMismatchReason`]
/// and 10 subsequent canonical sub-reason enums), every defensive
/// runtime failure mode lands as a typed sub-reason rather than as
/// a free-form string.
///
/// At sub-arc 5/6.1 the initial sub-reason set is small (one
/// variant per the Q1.3 refinement at the plan-gate). Subsequent
/// sub-arcs add sub-reasons as runtime work surfaces invariants;
/// each addition lands per the variant-vs-test mapping audit
/// principle (canonical at Phase 5/5b.3 C-3) — every new sub-reason
/// gets at least one explicit negative-test asserting on the
/// variant shape.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub enum InvariantViolationReason {
    /// A `#[shielded]` callee was invoked from a `#[transparent]`
    /// caller (or vice-versa) at runtime.
    ///
    /// Whitepaper §6.2.1.6 Rule 7 enforces privacy consistency at
    /// deploy time via the verifier; whitepaper §6.2.1.6 line 477
    /// frames the runtime check as the residual binding ("The
    /// runtime check carries the residual binding for any case
    /// the static analysis cannot fully verify"). If the verifier
    /// was sound and the bytecode was not modified post-deployment,
    /// this variant should never fire at runtime.
    ///
    /// Documenting this as an `InvariantViolation` rather than as
    /// a top-level [`VMError`] variant matches the methodology
    /// posture: it is **not** an expected runtime error condition;
    /// it is a defensive assertion that surfaces verifier
    /// soundness bugs or post-deployment bytecode modification.
    /// Same posture as the verifier's defensive Sui-base handlers
    /// at deploy-time.
    PrivacyModeMismatchPostVerification,
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
