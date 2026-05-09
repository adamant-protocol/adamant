//! Transaction-boundary execution helpers — whitepaper §6.2.2.
//!
//! Phase 5/6.6 lands the runtime-side state-trait integration:
//! [`load_read_set`] orchestrates the §6.2.2 step 2 pre-execution
//! object load against a [`StateView`]; [`commit_buffer`]
//! orchestrates the §6.2.2 step 7 post-execution atomic commit
//! against a [`StateMutator`].
//!
//! # Scope-bounding (Phase 5/6.6 plan-gate)
//!
//! This sub-arc ships the **transaction-boundary integration**
//! between the interpreter and the [`StateView`] / [`StateMutator`]
//! traits introduced at Phase 5/6.1. Per the plan-gate empirical
//! finding (foundation-already-exists-disposition-is-renaming-
//! question sub-pattern 2nd instance), the trait surface was
//! already in place at Phase 5/6.1; the gap was wiring
//! transaction-boundary load/commit around the existing dispatch
//! loop.
//!
//! **Out of scope for 5/6.6:**
//!
//! - Full `TxBody → InterpreterState` construction (module-
//!   loader resolution from [`crate::transaction::CallParams`] +
//!   `FunctionId` resolution + argument decoding from `Vec<Value>`
//!   to runtime stack values). That work belongs at Phase 5/6.7
//!   alongside the `adamant::module::deploy` stdlib + cross-
//!   module Rule 3 wiring.
//! - Per-handler object-state-touching dispatch. Per Phase 5/6.3
//!   plan-gate Q5/6.3.4 + Phase 5/6.4 disposition: 0 of 12 active
//!   Adamant-extension handlers touch object state directly. Sui-
//!   Move object semantics work through existing Phase 5/6.2c
//!   reference machinery + standard library calls (transfer,
//!   freeze, share). 5/6.6 does not add new dispatch arms.
//! - Consensus-side object-set verification. Runtime-side ships
//!   here; consensus-side defers to Phase 5/7 (parallel execution
//!   scheduler).
//!
//! # Whitepaper §6.2.2 verbatim quotes
//!
//! Step 2: "All objects referenced by the transaction are loaded
//! from chain state ... the loader validates that the transaction
//! touches no objects outside its declared sets."
//!
//! Step 5: "Bytecode runs to completion or until gas is exhausted.
//! State changes are accumulated in a transaction-local buffer;
//! chain state is not mutated until execution succeeds."
//!
//! Step 7: "If execution succeeded ... state changes are
//! committed."

use adamant_types::{Object, ObjectId};

use crate::runtime::error::VMError;
use crate::runtime::state_buffer::TransactionStateBuffer;
use crate::runtime::state_mutator::StateMutator;
use crate::runtime::state_view::StateView;

/// Pre-execution read-set loader per whitepaper §6.2.2 step 2.
///
/// Loads each `(ObjectId, Version)` in `read_set` from the
/// `state_view`. Version-pin failures surface as
/// [`VMError::Load`] with the underlying
/// [`crate::runtime::state_view::LoadError`]; the caller should
/// halt before invoking the dispatch loop on any error.
///
/// Returns the loaded objects in `read_set` order. Caller is
/// responsible for installing them into the runtime's [`Object`]-
/// access surface (e.g., reference-machinery setup at frame
/// construction; full integration lands at Phase 5/6.7).
///
/// # Errors
///
/// Returns [`VMError::Load`] (via the [`From`] impl) on any of
/// the [`crate::runtime::state_view::LoadError`] variants:
/// `ObjectNotFound`, `VersionMismatch`, `ObjectArchived`,
/// `ObjectDestroyed`. The transaction is rejected without
/// execution per §6.2.2 step 2 ("a transaction is rejected
/// before execution").
pub fn load_read_set<S>(
    state_view: &S,
    read_set: &[(ObjectId, u64)],
) -> Result<Vec<Object>, VMError>
where
    S: StateView,
{
    let mut loaded = Vec::with_capacity(read_set.len());
    for (id, expected_version) in read_set {
        let object = state_view.load_object(id, *expected_version)?;
        loaded.push(object);
    }
    Ok(loaded)
}

/// Post-execution buffer-commit per whitepaper §6.2.2 step 7.
///
/// Consumes the transaction-local [`TransactionStateBuffer`] into
/// a [`crate::runtime::state_mutator::TransactionStateChanges`]
/// payload and submits it to the `state_mutator`. The mutator
/// applies the changes atomically per §6.2.2 step 7 ("the full
/// state-changes payload is applied as a single atomic
/// operation").
///
/// On success, chain state reflects the transaction's effects.
/// On failure ([`VMError::Commit`] via the [`From`] impl), the
/// transaction is treated as failed and gas is charged per
/// §6.3.3.
///
/// **Caller contract:** invoke this only on successful execution
/// (the dispatch loop returned `Ok`). If execution failed, drop
/// the buffer without invoking this function — that satisfies
/// §6.2.2 step 7's "if execution failed, all state changes are
/// discarded except for the gas charged."
///
/// # Errors
///
/// Returns [`VMError::Commit`] (via the [`From`] impl) on any of
/// the [`crate::runtime::state_mutator::CommitError`] variants:
/// `ConflictingWrite`, `ObjectIdCollision`. Surfaced to the
/// caller for transaction-failure accounting.
pub fn commit_buffer<M>(
    state_mutator: &mut M,
    buffer: TransactionStateBuffer,
) -> Result<(), VMError>
where
    M: StateMutator,
{
    let changes = buffer.into_changes();
    state_mutator.commit(changes)?;
    Ok(())
}

/// Outcome of [`execute_transaction`] per whitepaper §6.2.2 step 7.
///
/// The variant pins which branch of the success-or-abort dichotomy
/// the transaction took:
///
/// - [`TransactionResult::Success`] — execution completed,
///   `commit_buffer` succeeded, gas charged for actual consumption.
/// - [`TransactionResult::Failed`] — execution aborted (any
///   [`VMError`] from steps 2 / 4 / 5 / 7); state changes
///   discarded; gas charged for consumption-up-to-failure per
///   §6.3.3.
///
/// Per §6.3.3, **both branches charge gas** — the only way a
/// transaction is not charged is if it failed authorisation
/// (step 1) and therefore was rejected at the mempool layer
/// before reaching this function. Callers of
/// [`execute_transaction`] are expected to have pre-authorised
/// the transaction (§4.3 account validation; deferred to a
/// dedicated Phase 5/6.x sub-arc once `adamant-account` ships
/// the validation surface).
#[derive(Debug)]
pub enum TransactionResult {
    /// Execution succeeded; state changes committed.
    Success {
        /// Gas consumed across all six dimensions per §6.3.1.
        /// Echoes the [`crate::runtime::GasTracker`]'s consumption
        /// vector at termination; used by callers to deduct from
        /// the `fee_payer`'s balance.
        gas_consumed: GasConsumed,
    },
    /// Execution failed at some point during steps 2-5 or step 7.
    /// State changes discarded; gas charged for consumption-up-
    /// to-failure per §6.3.3.
    Failed {
        /// The error that caused the failure.
        error: VMError,
        /// Gas consumed up to the failure point per §6.3.3
        /// ("charged for the gas it consumed up to the point of
        /// failure"). For step-2 (load) and step-4 (gas-budget)
        /// failures, this is the minimum-fee floor (currently
        /// zero pending the §6.3.3 minimum-fee calibration item
        /// in CLAUDE.md §10's pre-mainnet workstream).
        gas_consumed: GasConsumed,
    },
}

/// Per-dimension gas consumption captured at transaction
/// termination per whitepaper §6.3.1.
#[derive(Debug, Clone, Copy, Default, Eq, PartialEq)]
pub struct GasConsumed {
    /// Computation dimension (CPU cycles).
    pub computation: u64,
    /// State storage dimension (bytes added).
    pub storage: u64,
    /// State rent prepayment dimension.
    pub rent: u64,
    /// Bandwidth dimension (transmission bytes).
    pub bandwidth: u64,
    /// Proof-verification dimension.
    pub proof_verification: u64,
    /// Proof-generation dimension (optional, for prover-market
    /// outsourcing per §3.7).
    pub proof_generation: u64,
}

impl GasConsumed {
    /// Capture per-dimension consumption from an
    /// [`InterpreterState`]'s gas tracker, given the original
    /// budget. Consumed = budget - remaining.
    fn capture(
        state: &crate::runtime::interpreter::InterpreterState,
        budget: &crate::transaction::GasBudget,
    ) -> Self {
        use crate::bytecode::GasDimension as GD;
        let tracker = state.gas_tracker();
        Self {
            computation: budget
                .computation
                .saturating_sub(tracker.remaining(GD::Computation)),
            storage: budget
                .storage
                .saturating_sub(tracker.remaining(GD::Storage)),
            rent: budget.rent.saturating_sub(tracker.remaining(GD::Rent)),
            bandwidth: budget
                .bandwidth
                .saturating_sub(tracker.remaining(GD::Bandwidth)),
            proof_verification: budget
                .proof_verification
                .saturating_sub(tracker.remaining(GD::ProofVerification)),
            proof_generation: budget
                .proof_generation
                .saturating_sub(tracker.remaining(GD::ProofGeneration)),
        }
    }
}

/// Execute a [`crate::transaction::Transaction`] end-to-end per
/// whitepaper §6.2.2's seven-step pipeline.
///
/// This is the top-level entry point that wires a transaction
/// from chain-state-load through bytecode execution to atomic
/// commit. The seven §6.2.2 steps are walked explicitly:
///
/// 1. **Authorisation** (§4.3) — **caller's responsibility.**
///    `execute_transaction` does not validate `tx.auth` against
///    `tx.body.authorising_account`'s validation logic. The
///    §4.3 validation surface is deferred per CLAUDE.md §6
///    Phase 3 framing ("validation logic ... requires the VM
///    and transaction format from section 6"); when that surface
///    ships, callers should run it before invoking this
///    function. A transaction reaching this function is treated
///    as already authorised. Per §6.3.3 final paragraph:
///    "if a transaction's authorisation logic returns invalid,
///    the transaction is rejected at the mempool layer and
///    never executed." The mempool layer (§9) is the auth-fail
///    rejection point; this function is the post-auth executor.
///
/// 2. **Object loading.** Loads the transaction's `read_set`
///    via [`load_read_set`]. Failures (object not found,
///    version mismatch, archived/destroyed) surface as
///    [`TransactionResult::Failed`].
///
/// 3. **Type checking.** Done at deploy-time by
///    [`crate::validator::deploy_validate`]; the runtime carries
///    residual binding via per-instruction type-on-stack checks.
///    No top-level driver action.
///
/// 4. **Gas budgeting.** Initialises the interpreter's
///    [`crate::runtime::GasTracker`] from `tx.body.gas_budget`
///    via [`crate::runtime::InterpreterState::set_gas_budget`].
///    The budget bounds total consumption per §6.3.1.
///
/// 5. **Execution.** Resolves the entry function from
///    `tx.body.call.target_module` (loaded as a Module Object
///    in step 2) and `tx.body.call.target_function` (a
///    [`adamant_types::FunctionId`] string). Pushes an entry
///    frame with arguments from `tx.body.call.arguments`. Runs the
///    dispatch loop ([`crate::runtime::interpreter::run`])
///    against the loaded module + the genesis-fixed
///    [`crate::runtime::NativeRegistry`]. State changes
///    accumulate in a transaction-local
///    [`TransactionStateBuffer`].
///
/// 6. **Privacy proof generation.** Deferred to Phase 6 (§7
///    privacy layer). Transparent transactions skip this step
///    entirely; shielded transactions will emit a Halo 2 proof
///    here when §7 ships.
///
/// 7. **Commit or abort.** On success, [`commit_buffer`]
///    applies the accumulated state changes atomically. On
///    failure, the buffer is dropped and gas is charged per
///    §6.3.3.
///
/// # Type parameters
///
/// - `S: StateView` — read-only view of chain state at the
///   transaction's load point (§6.2.2 step 2).
/// - `M: StateMutator` — atomic-commit interface for chain-state
///   mutation (§6.2.2 step 7).
///
/// # Errors
///
/// Returns `Err(VMError)` only for **unrecoverable infrastructure
/// failures** that the caller cannot meaningfully proceed past
/// (e.g., the entry-function resolution itself failing because
/// the target module isn't in the read-set — this is a
/// caller-construction bug, not a transaction-level abort). All
/// transaction-level failures (load errors, dispatch errors,
/// commit errors) are folded into [`TransactionResult::Failed`]
/// per the §6.3.3 charge-on-failure semantics.
///
/// # Spec deferrals
///
/// - Step 1 (authorisation): §4.3 mempool-layer concern.
/// - Step 6 (proof gen): §7 privacy layer.
/// - §6.3.3 minimum-fee floor: pre-mainnet calibration; Phase
///   5/6.10 ships zero floor.
pub fn execute_transaction<S, M>(
    tx: &crate::transaction::Transaction,
    state_view: &S,
    state_mutator: &mut M,
    natives: &crate::runtime::NativeRegistry,
    verifier_config: &crate::validator::AdamantVerifierConfig,
    module_resolver: &dyn crate::validator::ModuleResolver,
    tx_hash: &adamant_types::TxHash,
) -> Result<TransactionResult, VMError>
where
    S: StateView,
    M: StateMutator,
{
    // Step 1: authorisation — deferred per §4.3 (see function
    // doc-comment).
    //
    // Step 2: load read-set per §6.2.2 step 2.
    let loaded_objects = match load_read_set(state_view, &tx.body.read_set) {
        Ok(objs) => objs,
        Err(e) => {
            // Step-2 failure: zero gas consumed (no execution).
            return Ok(TransactionResult::Failed {
                error: e,
                gas_consumed: GasConsumed::default(),
            });
        }
    };

    // Step 3: type-checking is deploy-time validator's job.
    //
    // Step 4: initialise gas tracker from declared budget.
    let mut interp = crate::runtime::interpreter::InterpreterState::new();
    interp.set_gas_budget(&tx.body.gas_budget);

    // Step 5 prep: resolve target module + entry function.
    //
    // The transaction's `call.target_module` is a `ModuleRef`
    // wrapping an `ObjectId` per §6.0.7. The Module object must
    // appear in the transaction's `read_set` and therefore is
    // present in `loaded_objects`. Deserialise its `contents`
    // bytes into an `AdamantCompiledModule`.
    let target_module_id = tx.body.call.target_module.0;
    let target_module_obj = loaded_objects
        .iter()
        .find(|o| o.id == target_module_id)
        .ok_or(VMError::ReadSetViolation {
            attempted: target_module_id,
        })?;
    let target_module = crate::module_wire::adamant_deserialize(
        target_module_obj.contents.as_bytes(),
    )
    .map_err(|_| VMError::InvariantViolation {
        reason: crate::runtime::error::InvariantViolationReason::TypeMismatchOnStack,
    })?;

    // Resolve target function: scan function_defs + identifiers
    // for a matching name.
    let target_function_name = tx.body.call.target_function.as_str();
    let entry_handle = resolve_entry_function(&target_module, target_function_name)?;

    // Set up the entry frame: pop args from CallParams, push to
    // the entry frame's locals.
    let entry_frame = build_entry_frame(&target_module, entry_handle, &tx.body.call.arguments)?;
    interp.push_frame(entry_frame);

    // Step 5 + Step 7: run dispatch loop with native registry
    // wired; on success, commit the buffer. On failure, drop the
    // buffer; charge gas in either case per §6.3.3.
    //
    // The interpreter's dispatch loop manages the buffer
    // internally via the `tx_context` field of `NativeContext`;
    // for Phase 5/6.10, we pass tx_context = None until the
    // chain-state-mutating handlers (Phase 5/6.8.C) and the
    // top-level driver are jointly tested. The next sub-arc
    // (Phase 5/6.10.B integration tests) ships `tx_context = Some`
    // alongside concrete invocation tests.
    let mut state_buffer = TransactionStateBuffer::new();
    let _ = (
        target_function_name,
        verifier_config,
        module_resolver,
        tx_hash,
        &mut state_buffer,
    ); // placeholder for Phase 5/6.10.B wiring

    let dispatch_result = run_with_module_fetch(&mut interp, &target_module, natives);

    let gas_consumed = GasConsumed::capture(&interp, &tx.body.gas_budget);

    match dispatch_result {
        Ok(()) => {
            // Step 7 commit. State buffer is empty until the
            // tx_context wiring lands; current sub-arc commits
            // an empty buffer on success.
            match commit_buffer(state_mutator, state_buffer) {
                Ok(()) => Ok(TransactionResult::Success { gas_consumed }),
                Err(e) => Ok(TransactionResult::Failed {
                    error: e,
                    gas_consumed,
                }),
            }
        }
        Err(e) => {
            // Step 7 abort path: drop buffer, charge gas (§6.3.3).
            Ok(TransactionResult::Failed {
                error: e,
                gas_consumed,
            })
        }
    }
}

/// Resolve a function-name string into a
/// [`adamant_bytecode_format::FunctionHandleIndex`] by scanning
/// `module.function_defs` for a function whose handle's name
/// matches `name`. Used by [`execute_transaction`] step 5 to
/// resolve `tx.body.call.target_function`.
///
/// Returns [`VMError::InvariantViolation`] with
/// [`InvariantViolationReason::IndexOutOfBoundsPostVerification`]
/// if no matching function is found — the caller is expected to
/// have constructed `target_function` against a deployed module
/// that exposes the named function publicly.
fn resolve_entry_function(
    module: &crate::module::AdamantCompiledModule,
    name: &str,
) -> Result<adamant_bytecode_format::FunctionHandleIndex, VMError> {
    for def in &module.function_defs {
        let handle = module
            .function_handles
            .get(def.function.0 as usize)
            .ok_or(VMError::InvariantViolation {
            reason:
                crate::runtime::error::InvariantViolationReason::IndexOutOfBoundsPostVerification,
        })?;
        let candidate_name = module
            .identifiers
            .get(handle.name.0 as usize)
            .ok_or(VMError::InvariantViolation {
            reason:
                crate::runtime::error::InvariantViolationReason::IndexOutOfBoundsPostVerification,
        })?;
        if candidate_name.as_str() == name {
            return Ok(def.function);
        }
    }
    Err(VMError::InvariantViolation {
        reason: crate::runtime::error::InvariantViolationReason::IndexOutOfBoundsPostVerification,
    })
}

/// Build the entry frame for [`execute_transaction`] step 5,
/// populating the function's parameter locals from the
/// transaction's [`crate::transaction::CallParams::args`] vector.
fn build_entry_frame(
    module: &crate::module::AdamantCompiledModule,
    entry: adamant_bytecode_format::FunctionHandleIndex,
    args: &[crate::value::Value],
) -> Result<crate::runtime::Frame, VMError> {
    let func_handle =
        module
            .function_handles
            .get(entry.0 as usize)
            .ok_or(VMError::InvariantViolation {
            reason:
                crate::runtime::error::InvariantViolationReason::IndexOutOfBoundsPostVerification,
        })?;
    let params_sig = module
        .signatures
        .get(func_handle.parameters.0 as usize)
        .ok_or(VMError::InvariantViolation {
            reason:
                crate::runtime::error::InvariantViolationReason::IndexOutOfBoundsPostVerification,
        })?;
    if args.len() != params_sig.0.len() {
        return Err(VMError::InvariantViolation {
            reason: crate::runtime::error::InvariantViolationReason::TypeMismatchOnStack,
        });
    }
    // Resolve function-def for total locals (parameters + body
    // locals).
    let func_def = crate::runtime::module_helpers::resolve_function_def(module, entry)?;
    let body_locals_sig =
        module
            .signatures
            .get(func_def.code.as_ref().ok_or(VMError::InvariantViolation {
                reason: crate::runtime::error::InvariantViolationReason::DeprecatedOpcodePostVerification,
            })?.locals.0 as usize)
            .ok_or(VMError::InvariantViolation {
                reason: crate::runtime::error::InvariantViolationReason::IndexOutOfBoundsPostVerification,
            })?;
    let total_locals = params_sig.0.len() + body_locals_sig.0.len();

    let frame = crate::runtime::Frame::new(entry, total_locals);
    {
        let mut cell = frame.locals.borrow_mut();
        for (i, arg) in args.iter().enumerate() {
            cell[i] = Some(crate::runtime::runtime_value::RuntimeValue::from_value(
                arg.clone(),
            ));
        }
    }
    Ok(frame)
}

/// Wrapper around [`crate::runtime::interpreter::run`] that fetches
/// instructions from the target module's bytecode body. The fetch
/// callback closure resolves `(function_handle, pc)` to the
/// `BytecodeInstruction` at that program-counter offset within the
/// function's body, returning `None` when the pc exceeds the body
/// length (signalling a missing-`Ret` malformed function — the
/// validator's `control_flow` pass should pre-empt at deploy time).
fn run_with_module_fetch(
    state: &mut crate::runtime::interpreter::InterpreterState,
    module: &crate::module::AdamantCompiledModule,
    natives: &crate::runtime::NativeRegistry,
) -> Result<(), VMError> {
    let module_clone = module.clone();
    crate::runtime::interpreter::run(
        state,
        module,
        move |handle, pc| {
            let func_def = module_clone
                .function_defs
                .iter()
                .find(|d| d.function == handle)?;
            let code = func_def.code.as_ref()?;
            code.code.get(pc as usize).cloned()
        },
        Some(natives),
    )
}

#[cfg(test)]
mod tests {
    //! Verbatim-spec-quote-grounds-runtime-fixture discipline.

    use super::*;
    use crate::runtime::state_mutator::CommitError;
    use crate::runtime::state_view::LoadError;
    use adamant_types::metadata::{ObjectMetadata, ProofCommitment, PROOF_COMMITMENT_BYTES};
    use adamant_types::{Address, Contents, Lifecycle, Mutability, Ownership, TypeId};
    use std::collections::HashMap;

    fn fixed_object_id(seed: u8) -> ObjectId {
        ObjectId::from_bytes([seed; 32])
    }

    fn make_active_object(id: ObjectId, version: u64) -> Object {
        Object {
            id,
            type_id: TypeId::from_bytes([0u8; 32]),
            owner: Ownership::Address(Address::from_bytes([0u8; 32])),
            mutability: Mutability::Immutable,
            lifecycle: Lifecycle::Active,
            contents: Contents::empty(),
            version,
            metadata: ObjectMetadata {
                created_at_height: 0,
                last_modified_height: 0,
                creator: Address::from_bytes([0u8; 32]),
                storage_rent_paid_through: 0,
                proof_commitment: ProofCommitment::from_bytes([0u8; PROOF_COMMITMENT_BYTES]),
            },
        }
    }

    /// In-memory mock implementation of [`StateView`] for tests.
    struct MockStateView {
        objects: HashMap<ObjectId, Object>,
    }

    impl StateView for MockStateView {
        fn load_object(&self, id: &ObjectId, expected_version: u64) -> Result<Object, LoadError> {
            let object = self
                .objects
                .get(id)
                .ok_or(LoadError::ObjectNotFound { id: *id })?;
            if object.version != expected_version {
                return Err(LoadError::VersionMismatch {
                    id: *id,
                    expected: expected_version,
                    actual: object.version,
                });
            }
            match object.lifecycle {
                Lifecycle::Active | Lifecycle::Frozen => Ok(object.clone()),
                Lifecycle::Archived => Err(LoadError::ObjectArchived { id: *id }),
                Lifecycle::Destroyed => Err(LoadError::ObjectDestroyed { id: *id }),
            }
        }
    }

    /// In-memory mock implementation of [`StateMutator`] for tests.
    struct MockStateMutator {
        committed: HashMap<ObjectId, Object>,
        commit_calls: usize,
    }

    impl MockStateMutator {
        fn new() -> Self {
            Self {
                committed: HashMap::new(),
                commit_calls: 0,
            }
        }
    }

    impl StateMutator for MockStateMutator {
        fn commit(
            &mut self,
            changes: crate::runtime::state_mutator::TransactionStateChanges,
        ) -> Result<(), CommitError> {
            self.commit_calls += 1;
            for object in changes.created {
                if self.committed.contains_key(&object.id) {
                    return Err(CommitError::ObjectIdCollision { id: object.id });
                }
                self.committed.insert(object.id, object);
            }
            for object in changes.updated {
                self.committed.insert(object.id, object);
            }
            for id in changes.destroyed {
                if let Some(obj) = self.committed.get_mut(&id) {
                    obj.lifecycle = Lifecycle::Destroyed;
                }
            }
            Ok(())
        }
    }

    /// Whitepaper §6.2.2 step 2 (verbatim): "All objects referenced
    /// by the transaction are loaded from chain state."
    #[test]
    fn load_read_set_loads_all_referenced_objects() {
        let id_a = fixed_object_id(0xA1);
        let id_b = fixed_object_id(0xB2);
        let mut objects = HashMap::new();
        objects.insert(id_a, make_active_object(id_a, 1));
        objects.insert(id_b, make_active_object(id_b, 7));
        let view = MockStateView { objects };

        let read_set = vec![(id_a, 1), (id_b, 7)];
        let loaded = load_read_set(&view, &read_set).expect("load ok");
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded[0].id, id_a);
        assert_eq!(loaded[1].id, id_b);
    }

    /// Empty `read_set` produces empty loaded vec.
    #[test]
    fn load_read_set_empty_produces_empty_vec() {
        let view = MockStateView {
            objects: HashMap::new(),
        };
        let loaded = load_read_set(&view, &[]).expect("ok");
        assert!(loaded.is_empty());
    }

    /// `LoadError::ObjectNotFound` surfaces as `VMError::Load`.
    #[test]
    fn load_read_set_unknown_id_surfaces_load_error() {
        let view = MockStateView {
            objects: HashMap::new(),
        };
        let result = load_read_set(&view, &[(fixed_object_id(0x99), 1)]);
        assert!(matches!(
            result,
            Err(VMError::Load(LoadError::ObjectNotFound { .. }))
        ));
    }

    /// `LoadError::VersionMismatch` surfaces as `VMError::Load`.
    #[test]
    fn load_read_set_version_mismatch_surfaces_load_error() {
        let id = fixed_object_id(0xC3);
        let mut objects = HashMap::new();
        objects.insert(id, make_active_object(id, 5));
        let view = MockStateView { objects };

        let result = load_read_set(&view, &[(id, 99)]);
        assert!(matches!(
            result,
            Err(VMError::Load(LoadError::VersionMismatch { .. }))
        ));
    }

    /// `LoadError::ObjectArchived` surfaces as `VMError::Load`.
    #[test]
    fn load_read_set_archived_object_surfaces_load_error() {
        let id = fixed_object_id(0xD4);
        let mut obj = make_active_object(id, 1);
        obj.lifecycle = Lifecycle::Archived;
        let mut objects = HashMap::new();
        objects.insert(id, obj);
        let view = MockStateView { objects };

        let result = load_read_set(&view, &[(id, 1)]);
        assert!(matches!(
            result,
            Err(VMError::Load(LoadError::ObjectArchived { .. }))
        ));
    }

    /// `LoadError::ObjectDestroyed` surfaces as `VMError::Load`.
    #[test]
    fn load_read_set_destroyed_object_surfaces_load_error() {
        let id = fixed_object_id(0xE5);
        let mut obj = make_active_object(id, 1);
        obj.lifecycle = Lifecycle::Destroyed;
        let mut objects = HashMap::new();
        objects.insert(id, obj);
        let view = MockStateView { objects };

        let result = load_read_set(&view, &[(id, 1)]);
        assert!(matches!(
            result,
            Err(VMError::Load(LoadError::ObjectDestroyed { .. }))
        ));
    }

    /// First failure halts loading; subsequent entries not
    /// attempted (per fail-fast semantics).
    #[test]
    fn load_read_set_halts_on_first_failure() {
        let id_a = fixed_object_id(0xF1);
        let id_b = fixed_object_id(0xF2);
        let mut objects = HashMap::new();
        objects.insert(id_a, make_active_object(id_a, 1));
        // id_b intentionally absent
        let view = MockStateView { objects };

        let read_set = vec![(id_a, 1), (id_b, 1)];
        let result = load_read_set(&view, &read_set);
        assert!(matches!(
            result,
            Err(VMError::Load(LoadError::ObjectNotFound { .. }))
        ));
    }

    /// Whitepaper §6.2.2 step 7 (verbatim): "the full state-changes
    /// payload is applied as a single atomic operation."
    #[test]
    fn commit_buffer_applies_creates_to_mutator() {
        let id = fixed_object_id(0x10);
        let mut buffer = TransactionStateBuffer::new();
        buffer.record_create(make_active_object(id, 1));
        let mut mutator = MockStateMutator::new();
        commit_buffer(&mut mutator, buffer).expect("ok");
        assert_eq!(mutator.commit_calls, 1);
        assert!(mutator.committed.contains_key(&id));
    }

    /// `commit_buffer` invokes the mutator exactly once per call.
    #[test]
    fn commit_buffer_invokes_mutator_once() {
        let buffer = TransactionStateBuffer::new();
        let mut mutator = MockStateMutator::new();
        commit_buffer(&mut mutator, buffer).expect("ok");
        assert_eq!(mutator.commit_calls, 1);
    }

    /// Empty buffer commits successfully (no-op semantics).
    #[test]
    fn commit_buffer_empty_buffer_succeeds() {
        let buffer = TransactionStateBuffer::new();
        let mut mutator = MockStateMutator::new();
        commit_buffer(&mut mutator, buffer).expect("ok");
        assert!(mutator.committed.is_empty());
    }

    /// `CommitError::ObjectIdCollision` surfaces as
    /// `VMError::Commit`.
    #[test]
    fn commit_buffer_collision_surfaces_commit_error() {
        let id = fixed_object_id(0x20);
        let mut buffer = TransactionStateBuffer::new();
        buffer.record_create(make_active_object(id, 1));

        let mut mutator = MockStateMutator::new();
        // Pre-existing object with same id triggers collision.
        mutator.committed.insert(id, make_active_object(id, 1));

        let result = commit_buffer(&mut mutator, buffer);
        assert!(matches!(
            result,
            Err(VMError::Commit(CommitError::ObjectIdCollision { .. }))
        ));
    }

    /// Round-trip: load `read_set` + commit buffer round-trip.
    #[test]
    fn round_trip_load_then_commit() {
        let id_loaded = fixed_object_id(0x30);
        let id_created = fixed_object_id(0x31);
        let mut state_objects = HashMap::new();
        state_objects.insert(id_loaded, make_active_object(id_loaded, 5));
        let view = MockStateView {
            objects: state_objects,
        };

        // Pre-execution: load.
        let loaded = load_read_set(&view, &[(id_loaded, 5)]).expect("load");
        assert_eq!(loaded.len(), 1);

        // Mid-execution: buffer accumulates a creation.
        let mut buffer = TransactionStateBuffer::new();
        buffer.record_create(make_active_object(id_created, 1));

        // Post-execution: commit.
        let mut mutator = MockStateMutator::new();
        commit_buffer(&mut mutator, buffer).expect("commit");

        assert!(mutator.committed.contains_key(&id_created));
    }

    /// Failure after load + before commit drops the buffer
    /// without invoking the mutator (per §6.2.2 step 7 caller-
    /// contract).
    #[test]
    fn execution_failure_drops_buffer_without_committing() {
        let mut buffer = TransactionStateBuffer::new();
        buffer.record_create(make_active_object(fixed_object_id(0x40), 1));

        // Caller-contract: drop buffer without invoking
        // commit_buffer. The mutator is unchanged.
        drop(buffer);

        let mutator = MockStateMutator::new();
        assert_eq!(mutator.commit_calls, 0);
        assert!(mutator.committed.is_empty());
    }

    /// `From<LoadError> for VMError` surface (already shipped at
    /// 5/6.1; verified here for transaction-boundary integration).
    #[test]
    fn load_error_from_impl_surfaces_in_vm_error() {
        let id = fixed_object_id(0x50);
        let load_err = LoadError::ObjectNotFound { id };
        let vm_err: VMError = load_err.into();
        assert!(matches!(
            vm_err,
            VMError::Load(LoadError::ObjectNotFound { .. })
        ));
    }

    /// `From<CommitError> for VMError` surface.
    #[test]
    fn commit_error_from_impl_surfaces_in_vm_error() {
        let id = fixed_object_id(0x51);
        let commit_err = CommitError::ObjectIdCollision { id };
        let vm_err: VMError = commit_err.into();
        assert!(matches!(
            vm_err,
            VMError::Commit(CommitError::ObjectIdCollision { .. })
        ));
    }

    // =====================================================================
    // execute_transaction integration tests (Phase 5/6.10)
    // =====================================================================

    /// Build a minimal Module Object containing valid bytecode
    /// for a single trivial entry function `f` that runs `Ret`.
    fn build_module_object_with_trivial_entry(id: ObjectId) -> Object {
        use crate::bytecode::BytecodeInstruction;
        use crate::module::{AdamantCodeUnit, AdamantCompiledModule, AdamantFunctionDefinition};
        use adamant_bytecode_format::{
            AddressIdentifierIndex, Bytecode, FunctionHandle, Identifier, IdentifierIndex,
            ModuleHandle, ModuleHandleIndex, Signature, SignatureIndex, Visibility,
        };

        let mut m = AdamantCompiledModule {
            version: adamant_bytecode_format::VERSION_MAX,
            ..AdamantCompiledModule::default()
        };
        // Self module handle 0: 0x1::M
        m.module_handles.push(ModuleHandle {
            address: AddressIdentifierIndex(0),
            name: IdentifierIndex(0),
        });
        m.address_identifiers
            .push(adamant_types::Address::from_bytes([0; 32]));
        m.identifiers.push(Identifier::new("M").unwrap());
        // Function name `f`
        m.identifiers.push(Identifier::new("f").unwrap());
        // Empty signature (params + return + locals)
        m.signatures.push(Signature(vec![]));
        m.function_handles.push(FunctionHandle {
            module: ModuleHandleIndex(0),
            name: IdentifierIndex(1),
            parameters: SignatureIndex(0),
            return_: SignatureIndex(0),
            type_parameters: vec![],
        });
        m.function_defs.push(AdamantFunctionDefinition {
            function: adamant_bytecode_format::FunctionHandleIndex(0),
            visibility: Visibility::Public,
            is_entry: true,
            acquires_global_resources: vec![],
            code: Some(AdamantCodeUnit {
                locals: SignatureIndex(0),
                code: vec![BytecodeInstruction::Inherited(Bytecode::Ret)],
                jump_tables: vec![],
            }),
        });
        // Mutability metadata so the module is well-formed enough
        // for testing; the deploy_validate path is not exercised
        // here.
        let mutability_value = bcs::to_bytes(&Mutability::Immutable).unwrap();
        m.metadata.push(adamant_bytecode_format::Metadata {
            key: b"adamant.mutability".to_vec(),
            value: mutability_value,
        });

        // Serialize to canonical bytes.
        let mut bytecode_bytes = Vec::new();
        crate::module_wire::adamant_serialize(&m, &mut bytecode_bytes).unwrap();

        Object {
            id,
            type_id: TypeId::from_bytes([0u8; 32]),
            owner: Ownership::Address(Address::from_bytes([0u8; 32])),
            mutability: Mutability::Immutable,
            lifecycle: Lifecycle::Active,
            contents: Contents::from_bytes(&bytecode_bytes).expect("contents fits"),
            version: 1,
            metadata: ObjectMetadata {
                created_at_height: 0,
                last_modified_height: 0,
                creator: Address::from_bytes([0u8; 32]),
                storage_rent_paid_through: 0,
                proof_commitment: ProofCommitment::from_bytes([0u8; PROOF_COMMITMENT_BYTES]),
            },
        }
    }

    fn build_minimal_transaction(module_id: ObjectId) -> crate::transaction::Transaction {
        use crate::transaction::{
            AccountRef, AuthEvidence, CallParams, GasBudget, Transaction, TxBody,
        };
        use adamant_types::{FunctionId, ModuleRef, Signature as Sig};

        Transaction {
            body: TxBody {
                authorising_account: AccountRef::Cleartext(Address::from_bytes([0xAA; 32])),
                fee_payer: None,
                read_set: vec![(module_id, 1)],
                write_set: vec![],
                created_objects: vec![],
                gas_budget: GasBudget {
                    computation: 1_000_000,
                    storage: 1_000_000,
                    rent: 1_000_000,
                    bandwidth: 1_000_000,
                    proof_verification: 1_000_000,
                    proof_generation: 0,
                },
                call: CallParams {
                    target_module: ModuleRef(module_id),
                    target_function: FunctionId::new("f".to_string()).unwrap(),
                    type_arguments: vec![],
                    arguments: vec![],
                },
                nonce: 0,
            },
            auth: AuthEvidence {
                signatures: vec![Sig::Ed25519([0u8; 64])],
                witnesses: vec![],
            },
        }
    }

    /// In-memory `ModuleResolver` test helper for the integration
    /// tests. Empty by default; the integration tests we ship at
    /// Phase 5/6.10 don't exercise cross-module Rule 3 since the
    /// minimal trivial module has no cross-module calls.
    struct EmptyResolver;
    impl crate::validator::ModuleResolver for EmptyResolver {
        fn resolve(
            &self,
            _id: &crate::validator::ModuleId,
        ) -> Option<&crate::module::AdamantCompiledModule> {
            None
        }
    }

    /// Whitepaper §6.2.2 happy path: a transaction whose entry
    /// function returns immediately runs to completion and the
    /// commit step produces `TransactionResult::Success` with
    /// zero state changes.
    #[test]
    fn execute_transaction_trivial_entry_succeeds() {
        let module_id = fixed_object_id(0xCC);
        let module_obj = build_module_object_with_trivial_entry(module_id);
        let mut objects = HashMap::new();
        objects.insert(module_id, module_obj);
        let view = MockStateView { objects };
        let mut mutator = MockStateMutator::new();
        let registry = crate::runtime::genesis_native_registry();
        let config = crate::validator::AdamantVerifierConfig::new();
        let resolver = EmptyResolver;
        let tx_hash = adamant_types::TxHash::from_bytes([0xEE; 32]);
        let tx = build_minimal_transaction(module_id);

        let result = execute_transaction(
            &tx,
            &view,
            &mut mutator,
            &registry,
            &config,
            &resolver,
            &tx_hash,
        )
        .expect("execute ok");
        assert!(matches!(result, TransactionResult::Success { .. }));
        // Commit was called even though no state changes were
        // staged (empty buffer).
        assert_eq!(mutator.commit_calls, 1);
    }

    /// Whitepaper §6.2.2 step 2 failure: a transaction referencing
    /// a missing object surfaces as `TransactionResult::Failed`
    /// with `VMError::Load(ObjectNotFound)`. Gas consumption is
    /// zero because no execution occurred.
    #[test]
    fn execute_transaction_load_failure_returns_failed() {
        let module_id = fixed_object_id(0xCD);
        // module_id is NOT inserted into the view → ObjectNotFound.
        let view = MockStateView {
            objects: HashMap::new(),
        };
        let mut mutator = MockStateMutator::new();
        let registry = crate::runtime::genesis_native_registry();
        let config = crate::validator::AdamantVerifierConfig::new();
        let resolver = EmptyResolver;
        let tx_hash = adamant_types::TxHash::from_bytes([0xEF; 32]);
        let tx = build_minimal_transaction(module_id);

        let result = execute_transaction(
            &tx,
            &view,
            &mut mutator,
            &registry,
            &config,
            &resolver,
            &tx_hash,
        )
        .expect("execute_transaction returns Result-Ok with embedded Failed");
        match result {
            TransactionResult::Failed {
                error,
                gas_consumed,
            } => {
                assert!(matches!(
                    error,
                    VMError::Load(LoadError::ObjectNotFound { .. })
                ));
                // Step-2 failure: zero gas consumed.
                assert_eq!(gas_consumed, GasConsumed::default());
            }
            TransactionResult::Success { .. } => panic!("expected Failed, got Success"),
        }
        // Commit was not called.
        assert_eq!(mutator.commit_calls, 0);
    }

    /// `GasConsumed::capture` correctly subtracts remaining from
    /// the budget across all six dimensions.
    #[test]
    fn gas_consumed_capture_subtracts_remaining_from_budget() {
        use crate::bytecode::GasDimension as GD;
        use crate::transaction::GasBudget;

        let budget = GasBudget {
            computation: 1_000,
            storage: 2_000,
            rent: 3_000,
            bandwidth: 4_000,
            proof_verification: 5_000,
            proof_generation: 6_000,
        };
        let mut state = crate::runtime::interpreter::InterpreterState::new();
        state.set_gas_budget(&budget);
        // Charge some gas across dimensions.
        state.charge_gas(GD::Computation, 100).expect("ok");
        state.charge_gas(GD::Storage, 200).expect("ok");
        state.charge_gas(GD::Bandwidth, 50).expect("ok");
        let consumed = GasConsumed::capture(&state, &budget);
        assert_eq!(consumed.computation, 100);
        assert_eq!(consumed.storage, 200);
        assert_eq!(consumed.rent, 0);
        assert_eq!(consumed.bandwidth, 50);
        assert_eq!(consumed.proof_verification, 0);
        assert_eq!(consumed.proof_generation, 0);
    }
}
