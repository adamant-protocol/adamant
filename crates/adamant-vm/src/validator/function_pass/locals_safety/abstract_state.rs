//! Abstract state for the locals-safety analysis (whitepaper
//! §6.2.1.8 step 4).
//!
//! Forked byte-faithfully from
//! `vendor/move-bytecode-verifier/src/locals_safety/abstract_state.rs`
//! at Sui-Move tag `mainnet-v1.66.2` (168 LOC upstream). The
//! analysis tracks, for each local in a function body, whether
//! that local has a value at every CFG offset.
//!
//! # Adamant deviations
//!
//! - **Inline per-function ability resolution** (Q3(a) at D-4
//!   plan-gate; 6th deliberate-Adamant-decision instance).
//!   [`LocalsAbstractState::new`] constructs an
//!   [`AdamantAbilityCache`] internally and discards it after
//!   per-local ability resolution; cross-function memoization
//!   is intentionally not threaded through. Rationale: locals
//!   signatures are bounded by `max_function_parameters`
//!   (genesis: 128) plus `max_locals` (binary-format-bound to
//!   `u8::MAX`), so per-function cache lifetime suffices for
//!   the work involved. Threading `&mut cache` through the
//!   per-function pipeline at D-4 would couple D-4's surface
//!   to a future D-5 (type/reference safety) decision that
//!   hasn't been made yet — D-5's plan-gate will surface
//!   whether cross-function memoization earns its keep at the
//!   heavier-resolution passes.
//!
//!   This is **stricter** than B-2.3's per-pass-instance cache
//!   lifecycle (cache reused across struct/enum traversals
//!   within one `ability_field_requirements` invocation); D-4
//!   establishes per-function-instance lifecycle (cache
//!   discarded after each `LocalsAbstractState::new` call).
//!   The B-2.3 disposition stays as it was; D-4 is a NEW
//!   posture decision, not inherited.
//! - Hard-wired [`AdamantValidationError`] as the join-result
//!   error type (inherits D-1b's `AbstractInterpreter`-trait
//!   shape; same shielding-vs-runtime canonical pattern).
//! - No metering surface (D-1a/D-1b/D-2/D-3 precedent).

use adamant_bytecode_format::{AbilitySet, FunctionDefinitionIndex, LocalIndex, SignatureIndex};

use crate::module::AdamantCompiledModule;
use crate::validator::error::AdamantValidationError;
use crate::validator::module_pass::ability_cache::AdamantAbilityCache;

/// `LocalState` represents the assignment state of a local at a
/// single CFG offset.
///
/// Mirrors upstream's `LocalState`. Three-way lattice with
/// `Unavailable < MaybeAvailable < Available` partial order;
/// the meet operator at branch-target join points produces the
/// least-permissive state across incoming paths.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum LocalState {
    /// The local has no value (never assigned, or moved out
    /// since last assignment).
    Unavailable,
    /// The local was assigned a non-drop value in at least
    /// one CFG path reaching this offset, but was
    /// `Unavailable` in at least one other path. Reads,
    /// borrows, and moves all reject; only writes (`StLoc`)
    /// are permitted (and only when the type has `drop`,
    /// since the prior path's value would be destroyed).
    MaybeAvailable,
    /// The local has a value on every CFG path reaching this
    /// offset.
    Available,
}

/// Per-function locals-safety abstract state.
///
/// Mirrors upstream's `AbstractState` byte-faithfully. The
/// `all_local_abilities` field caches each local's ability set
/// at construction time; subsequent transitions consult it
/// without re-resolving signatures.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct LocalsAbstractState {
    fn_def_idx: FunctionDefinitionIndex,
    /// Ability set per local position. Length =
    /// `parameters.len() + locals.len()`. Indexed by `LocalIndex`.
    all_local_abilities: Vec<AbilitySet>,
    /// Per-local availability state at the current CFG offset.
    /// Length matches `all_local_abilities`.
    local_states: Vec<LocalState>,
}

impl LocalsAbstractState {
    /// Build the entry-block initial state.
    ///
    /// Parameters are `Available` (caller-provided values);
    /// locals are `Unavailable` (no value yet). Constructs an
    /// internal [`AdamantAbilityCache`] for per-token ability
    /// resolution, then discards it (per-function lifecycle —
    /// see module-doc).
    ///
    /// Returns `Result<Self, AdamantValidationError>` for
    /// forward-compatibility with D-5+ ability-resolution
    /// failure modes (the current implementation panics via
    /// `expect` on cache resolution because `bounds_checker`
    /// makes the failure paths structurally impossible at
    /// step 3; D-5's type/reference-safety may surface
    /// failure modes that legitimately propagate).
    #[allow(
        clippy::unnecessary_wraps,
        reason = "forward-shape preservation for D-5+ ability-resolution failure paths"
    )]
    pub(super) fn new(
        module: &AdamantCompiledModule,
        fn_def_idx: FunctionDefinitionIndex,
        parameters: SignatureIndex,
        locals: SignatureIndex,
        type_parameter_abilities: &[AbilitySet],
    ) -> Result<Self, AdamantValidationError> {
        let parameters_idx = parameters.0 as usize;
        let locals_idx = locals.0 as usize;
        debug_assert!(
            parameters_idx < module.signatures.len(),
            "bounds_checker invariant violated; should be unreachable in pipeline; \
             if this fires from direct-unvalidated-input caller, caller violates \
             the precondition. SignatureIndex {} (parameters) >= signatures.len() {}",
            parameters_idx,
            module.signatures.len(),
        );
        debug_assert!(
            locals_idx < module.signatures.len(),
            "bounds_checker invariant violated; should be unreachable in pipeline; \
             if this fires from direct-unvalidated-input caller, caller violates \
             the precondition. SignatureIndex {} (locals) >= signatures.len() {}",
            locals_idx,
            module.signatures.len(),
        );

        let parameter_tokens = &module.signatures[parameters_idx].0;
        let local_tokens = &module.signatures[locals_idx].0;
        let num_args = parameter_tokens.len();
        let num_locals = num_args + local_tokens.len();

        let mut cache = AdamantAbilityCache::new(module);
        let mut all_local_abilities = Vec::with_capacity(num_locals);
        for tok in parameter_tokens.iter().chain(local_tokens.iter()) {
            let abilities = cache.abilities(type_parameter_abilities, tok).expect(
                "AdamantAbilityCache resolution is structurally infallible after \
                     bounds_checker; type-parameter and datatype indices are validated \
                     at step 3",
            );
            all_local_abilities.push(abilities);
        }

        let local_states = (0..num_locals)
            .map(|i| {
                if i < num_args {
                    LocalState::Available
                } else {
                    LocalState::Unavailable
                }
            })
            .collect();

        Ok(Self {
            fn_def_idx,
            all_local_abilities,
            local_states,
        })
    }

    pub(super) fn fn_def_idx(&self) -> FunctionDefinitionIndex {
        self.fn_def_idx
    }

    pub(super) fn local_state(&self, idx: LocalIndex) -> LocalState {
        self.local_states[idx as usize]
    }

    pub(super) fn local_abilities(&self, idx: LocalIndex) -> AbilitySet {
        self.all_local_abilities[idx as usize]
    }

    pub(super) fn local_states(&self) -> &[LocalState] {
        &self.local_states
    }

    pub(super) fn all_local_abilities(&self) -> &[AbilitySet] {
        &self.all_local_abilities
    }

    pub(super) fn set_available(&mut self, idx: LocalIndex) {
        self.local_states[idx as usize] = LocalState::Available;
    }

    pub(super) fn set_unavailable(&mut self, idx: LocalIndex) {
        debug_assert_eq!(
            self.local_states[idx as usize],
            LocalState::Available,
            "set_unavailable invariant violated; should be unreachable in pipeline; \
             if this fires from direct-unvalidated-input caller, caller violates \
             the precondition. local idx {idx} state was not Available"
        );
        self.local_states[idx as usize] = LocalState::Unavailable;
    }

    /// Lattice meet operator. Returns `(joined_state,
    /// changed_flag)` where `changed_flag` is true iff
    /// `joined_state.local_states != self.local_states`.
    ///
    /// Mirrors upstream's `join_` byte-faithfully:
    /// `Available + Available -> Available`,
    /// `Unavailable + Unavailable -> Unavailable`,
    /// any other pair -> `MaybeAvailable`.
    pub(super) fn join_internal(&self, other: &Self) -> (Self, bool) {
        debug_assert_eq!(self.fn_def_idx, other.fn_def_idx);
        debug_assert_eq!(
            self.all_local_abilities.len(),
            other.all_local_abilities.len()
        );
        debug_assert_eq!(self.local_states.len(), other.local_states.len());

        let local_states: Vec<LocalState> = self
            .local_states
            .iter()
            .zip(&other.local_states)
            .map(|(s, o)| match (s, o) {
                (LocalState::Unavailable, LocalState::Unavailable) => LocalState::Unavailable,
                (LocalState::Available, LocalState::Available) => LocalState::Available,
                _ => LocalState::MaybeAvailable,
            })
            .collect();

        let changed = self
            .local_states
            .iter()
            .zip(&local_states)
            .any(|(s, j)| s != j);

        (
            Self {
                fn_def_idx: self.fn_def_idx,
                all_local_abilities: self.all_local_abilities.clone(),
                local_states,
            },
            changed,
        )
    }
}
