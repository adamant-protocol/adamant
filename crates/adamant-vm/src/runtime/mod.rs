//! Adamant Move virtual machine runtime — whitepaper §6.2.
//!
//! Phase 5/6 deliverable: the AVM runtime that executes Adamant
//! Move bytecode per §6.2.2 ("Execution model"). Sub-arc 5/6.1
//! lands the runtime foundation — error types, state-view +
//! state-mutator trait abstractions, the transaction-local state
//! buffer, the per-function execution frame, the multi-frame
//! interpreter state, and the direct-interpreter dispatch-loop
//! scaffold. Subsequent sub-arcs land instruction handlers (5/6.2
//! inherited Sui-base; 5/6.3 Adamant extensions; 5/6.4 privacy-
//! circuit scaffold), gas accounting (5/6.5), object loader
//! integration (5/6.6), `adamant::module::deploy` stdlib + cross-
//! module Rule 3 wiring (5/6.7), and other stdlib modules (5/6.8).
//!
//! # Architectural posture
//!
//! Per whitepaper §6.2.1.8's resistant-proof commitment, the
//! runtime is **fully Adamant-native from initial implementation**.
//! Unlike the verifier (Phase 5/5) which had vendored Sui-Move's
//! `move-bytecode-verifier` available as a test-time cross-
//! validation reference, Sui-Move's `move-vm-runtime` is **not
//! vendored** and is **not** a cross-validation reference for
//! Adamant's runtime. Runtime correctness is anchored to whitepaper
//! §6.2 spec text plus Adamant's own test fixtures; the methodology
//! discipline that compensates for the absent oracle is the
//! **verbatim-spec-quote-grounds-runtime-fixture** pattern
//! introduced at sub-arc 5/6.1.
//!
//! # Verbatim-spec-quote-grounds-runtime-fixture discipline
//!
//! Without a Sui-VM cross-validation oracle, runtime correctness
//! depends entirely on whether the implementation matches whitepaper
//! §6.2 semantics. To make this auditable, every runtime test
//! fixture's expected outcome must be derivable from a verbatim
//! whitepaper quote registered in the test's doc-comment. A fixture
//! whose expected-outcome rationale is not anchored to a verbatim
//! spec quote pins **interpretation**; a fixture whose rationale
//! is anchored to a verbatim quote pins **spec**.
//!
//! This is the primary correctness anchor for runtime work, not a
//! secondary check. The discipline operates as a sibling to the
//! `spec-text-DIRECTS-shared-helper` canonical principle that
//! emerged at Phase 5/5b.4 D-5a.1.b — both invoke spec text as
//! the load-bearing authority, but at different mechanical scopes
//! (helper extraction versus test-fixture grounding).
//!
//! # Module map
//!
//! | Module           | Whitepaper section | Surface |
//! |------------------|--------------------|---------|
//! | [`error`]        | §6.2 / §6.2.2      | [`VMError`], [`InvariantViolationReason`] |
//! | [`state_view`]   | §6.2.2 step 2      | [`StateView`], [`LoadError`] |
//! | [`state_mutator`]| §6.2.2 step 7      | [`StateMutator`], [`CommitError`], [`TransactionStateChanges`] |
//! | [`state_buffer`] | §6.2.2 step 5      | [`TransactionStateBuffer`] |
//! | [`frame`]        | §6.2.2 step 5      | [`Frame`] |
//! | [`interpreter`]  | §6.2.2 step 5      | [`InterpreterState`], [`DispatchOutcome`] |
//! | `test_helpers`   | (test-only)        | `InMemoryStateView`, `InMemoryStateMutator` |
//!
//! # State trait abstractions (Q8 disposition at Phase 5/6 plan-gate)
//!
//! The runtime operates against [`StateView`] and [`StateMutator`]
//! trait abstractions rather than against a concrete chain-state
//! backend. Same posture as the [`crate::validator::cross_module::ModuleResolver`]
//! trait abstraction at Phase 5/5b.5 E-2a: the trait surface ships
//! at the runtime sub-arc; production-side concrete implementations
//! (RocksDB-backed [`StateView`] + [`StateMutator`] with per-object
//! KZG commitments + rent accounting + archival/restoration) land
//! at the Phase 4 object-storage backfill workstream (parallel to
//! Phase 5/6; not a Phase 5/6 prerequisite).
//!
//! In-memory [`HashMap`]-backed test implementations live at
//! `runtime::test_helpers::InMemoryStateView` and `runtime::test_helpers::InMemoryStateMutator`,
//! mirroring [`crate::validator::cross_module::test_helpers::InMemoryModuleResolver`]
//! at Phase 5/5b.5 E-2a.
//!
//! [`HashMap`]: std::collections::HashMap

pub mod error;
pub mod frame;
pub mod gas;
pub mod interpreter;
pub mod module_helpers;
pub mod runtime_value;
pub mod state_buffer;
pub mod state_mutator;
pub mod state_view;

#[cfg(test)]
pub(in crate::runtime) mod test_helpers;

#[cfg(test)]
mod tests;

pub use error::{AbortReason, ArithmeticErrorReason, InvariantViolationReason, VMError};
pub use frame::{Frame, PrivacyMode};
pub use gas::GasTracker;
pub use interpreter::{DispatchOutcome, InterpreterState};
pub use runtime_value::{
    compare_unsigned, Container, Reference, RuntimeStructValue, RuntimeValue, RuntimeVariantValue,
};
pub use state_buffer::TransactionStateBuffer;
pub use state_mutator::{CommitError, StateMutator, TransactionStateChanges};
pub use state_view::{LoadError, StateView};
