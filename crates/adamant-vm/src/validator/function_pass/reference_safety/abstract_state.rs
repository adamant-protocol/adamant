//! Adamant-native reference-safety abstract state (whitepaper
//! §6.2.1.6 Rule "reference safety" backing data structure).
//!
//! Forked byte-faithfully from
//! `vendor/move-bytecode-verifier/src/reference_safety/abstract_state.rs`
//! at Sui-Move tag `mainnet-v1.66.2` (1022 LOC upstream).
//!
//! # Adamant deviations
//!
//! - **No metering surface.** Upstream's metering constants
//!   (`STEP_BASE_COST`, `JOIN_BASE_COST`, `PER_GRAPH_ITEM_COST`,
//!   `RELEASE_ITEM_COST`, `RELEASE_ITEM_QUADRATIC_THRESHOLD`,
//!   `JOIN_ITEM_COST`, `JOIN_ITEM_QUADRATIC_THRESHOLD`,
//!   `ADD_BORROW_COST`) and the `charge_*` helpers are dropped.
//!   `meter` parameters dropped from every method signature.
//!   Consistent with D-1a / D-1b / D-2 / D-3 / D-4 / D-5a.0 /
//!   D-5a.1.a / D-5a.1.b precedent.
//! - **`AdamantValidationError::BorrowViolation` typed errors.**
//!   Upstream's `PartialVMError::new(StatusCode::*)` becomes
//!   `AdamantValidationError::BorrowViolation { fn_def_idx,
//!   code_offset, reason: BorrowViolationReason::* }`. Closed
//!   enum [`BorrowViolationReason`][bvr] declared at D-5b.2
//!   alongside producer per Q5 (Rust error-type lifecycle); 8th
//!   deliberate-Adamant-decision instance subject to Q-B Q7
//!   recount.
//! - **`additional_borrow_checks` hardcoded `true`.** Upstream's
//!   `VerifierConfig::default()` sets `true`; Adamant adopts the
//!   conservative-default verbatim and drops the runtime config
//!   flag entirely. The flag enables a soundness improvement
//!   that rejects borrows of locals when the frame root has
//!   outstanding full borrows. Adamant's resistant-proof posture
//!   prefers hardcoded behavior over configurable surface.
//! - **`deprecate_global_storage_ops` hardcoded `true`** (Rule 5
//!   posture). Upstream's `state.call`,
//!   `state.vector_element_borrow`, `state.borrow_global`,
//!   `state.move_from`, `state.is_global_borrowed`,
//!   `state.is_global_mutably_borrowed`, and `add_resource_borrow`
//!   are all gated by `!deprecate_global_storage_ops` or are
//!   reachable only through deprecated global-storage opcodes.
//!   These methods are dropped entirely; only `state.call_v2`
//!   (the modern path) and `state.vector_op` are kept.
//! - **`Label::Global` variant dropped.** Only consumed by
//!   `add_resource_borrow` and `is_global_*_borrowed` (all
//!   dropped). Adamant `Label` is `Local | StructField |
//!   VariantField` (3 variants vs upstream's 4).
//! - **`current_function: FunctionDefinitionIndex`** (non-
//!   `Option`). Upstream's `Option<FunctionDefinitionIndex>`
//!   accommodates scripts; Adamant has no scripts and constructs
//!   `AbstractState` only from a real function definition.
//! - **`safe_unwrap!` / `safe_unwrap_err!` / `safe_assert!`
//!   replaced by `expect()` / `unwrap_or_else(|e| panic!(...))` /
//!   `debug_assert!`** with three-anchor stems where
//!   structural-impossibility applies. Sub-shape 4 of
//!   structural-impossibility-checks pattern (continued use;
//!   per-mechanism counting discipline).
//!
//! # Cross-pass-pipeline-dependency preconditions
//!
//! - **Step 3** (`bounds_checker`, `signature_checker`,
//!   `instruction_consistency`): handle and signature-pool
//!   indices validated.
//! - **Step 4 D-2** (`control_flow`): non-empty reducible CFG.
//! - **Step 4 D-3** (`stack_usage`): per-block stack balance;
//!   `verifier.stack` pop/push are balanced.
//! - **Step 4 D-4** (`locals_safety`): locals availability;
//!   reference-safety's local accesses presume the local has a
//!   value or a tracked reference.
//! - **Step 4 D-5a.1** (`type_safety`): operand types match
//!   instruction expectations; reference-safety's
//!   `safe_unwrap!(value.ref_id())` paths assume type-safe
//!   reference operands.
//!
//! [bvr]: super::super::super::error::BorrowViolationReason

use std::cmp::max;
use std::collections::{BTreeMap, BTreeSet};

use adamant_bytecode_format::{
    CodeOffset, EnumDefinitionIndex, FieldHandleIndex, FunctionDefinitionIndex, LocalIndex,
    MemberCount, Signature, SignatureToken, VariantDefinition, VariantTag,
};

use super::super::absint::JoinResult;
use super::borrow_graph::{BorrowGraph, RefID};
use crate::validator::error::{AdamantValidationError, BorrowViolationReason};

/// Three-anchor message stem for the abstract-stack
/// structural-impossibility check on single-pop/push paths.
/// Sub-shape 4 of structural-impossibility-checks (continued
/// use through D-5b.2 per per-mechanism counting discipline).
pub(super) const STACK_INVARIANT_THREE_ANCHOR_STEM: &str =
    "AbstractStack invariant violated; should be unreachable in pipeline (D-3's per-block-balance \
     + max_push_size + D-5a type-safety preconditions); if this fires from direct-unvalidated-\
     input caller, caller violates the precondition";

/// `additional_borrow_checks` is hardcoded `true` per Adamant
/// deviation noted in module preamble.
const ADDITIONAL_BORROW_CHECKS: bool = true;

/// `AbstractValue` represents a reference or a non-reference
/// value, both on the stack and stored in a local.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum AbstractValue {
    Reference(RefID),
    NonReference,
}

impl AbstractValue {
    /// Checks if `self` is a reference.
    pub(super) fn is_reference(&self) -> bool {
        matches!(self, AbstractValue::Reference(_))
    }

    /// Checks if `self` is a value (non-reference).
    pub(super) fn is_value(&self) -> bool {
        !self.is_reference()
    }

    /// Possibly extracts id from `self`.
    pub(super) fn ref_id(&self) -> Option<RefID> {
        match self {
            AbstractValue::Reference(id) => Some(*id),
            AbstractValue::NonReference => None,
        }
    }
}

/// `ValueKind` is used for specifying the type of value
/// expected to be returned from a function call.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ValueKind {
    Reference(/* is_mut */ bool),
    NonReference,
}

/// `Label` is an element of a label on an edge in the borrow
/// graph. Adamant deviates from upstream's 4-variant
/// `Local | Global | StructField | VariantField` shape — Adamant
/// drops `Global` because Rule 5 makes deprecated global-storage
/// opcodes unreachable. Adamant `Label` is 3 variants.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(super) enum Label {
    Local(LocalIndex),
    StructField(FieldHandleIndex),
    VariantField(EnumDefinitionIndex, VariantTag, MemberCount),
}

impl std::fmt::Display for Label {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Label::Local(i) => write!(f, "local#{i}"),
            Label::StructField(i) => write!(f, "struct_field#{i}", i = i.0),
            Label::VariantField(eidx, tag, field_idx) => {
                write!(f, "variant_field#{}#{tag}#{field_idx}", eidx.0)
            }
        }
    }
}

/// `AbstractState` is the analysis state over which abstract
/// interpretation is performed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct AbstractState {
    current_function: FunctionDefinitionIndex,
    locals: Vec<AbstractValue>,
    borrow_graph: BorrowGraph<(), Label>,
    next_id: usize,
}

impl AbstractState {
    /// Construct the initial abstract state for a function:
    /// reference parameters get fresh `RefID`s in the borrow
    /// graph; non-reference parameters and locals are
    /// `NonReference`. The frame root is added with id
    /// `parameters.len() + locals.len()`.
    pub(super) fn new(
        fn_def_idx: FunctionDefinitionIndex,
        parameters: &Signature,
        locals: &Signature,
    ) -> Self {
        let num_locals = parameters.0.len() + locals.0.len();
        // ids in [0, num_locals) are reserved for constructing
        // canonical state; id at num_locals is reserved for the
        // frame root.
        let next_id = num_locals + 1;
        let mut state = AbstractState {
            current_function: fn_def_idx,
            locals: vec![AbstractValue::NonReference; num_locals],
            borrow_graph: BorrowGraph::new(),
            next_id,
        };

        for (param_idx, param_ty) in parameters.0.iter().enumerate() {
            if param_ty.is_reference() {
                let id = RefID::new(param_idx);
                state
                    .borrow_graph
                    .new_ref(id, param_ty.is_mutable_reference());
                state.locals[param_idx] = AbstractValue::Reference(id);
            }
        }
        state.borrow_graph.new_ref(state.frame_root(), true);

        debug_assert!(state.is_canonical());
        state
    }

    pub(super) fn graph_size(&self) -> usize {
        self.borrow_graph.graph_size()
    }

    /// Returns the frame root id.
    fn frame_root(&self) -> RefID {
        RefID::new(self.locals.len())
    }

    /// Build a typed [`AdamantValidationError::BorrowViolation`].
    fn error(
        &self,
        code_offset: CodeOffset,
        reason: BorrowViolationReason,
    ) -> AdamantValidationError {
        AdamantValidationError::BorrowViolation {
            fn_def_idx: self.current_function,
            code_offset,
            reason,
        }
    }

    // ----- Core API -----

    pub(super) fn value_for(&mut self, s: &SignatureToken) -> AbstractValue {
        match s {
            SignatureToken::Reference(_) => AbstractValue::Reference(self.new_ref(false)),
            SignatureToken::MutableReference(_) => AbstractValue::Reference(self.new_ref(true)),
            _ => AbstractValue::NonReference,
        }
    }

    /// Adds and returns a new id to the borrow graph.
    fn new_ref(&mut self, mut_: bool) -> RefID {
        let id = RefID::new(self.next_id);
        self.borrow_graph.new_ref(id, mut_);
        self.next_id += 1;
        id
    }

    fn add_copy(&mut self, parent: RefID, child: RefID) {
        self.borrow_graph.add_strong_borrow((), parent, child);
    }

    fn add_borrow(&mut self, parent: RefID, child: RefID) {
        self.borrow_graph.add_weak_borrow((), parent, child);
    }

    fn add_field_borrow(&mut self, parent: RefID, field: FieldHandleIndex, child: RefID) {
        self.borrow_graph
            .add_strong_field_borrow((), parent, Label::StructField(field), child);
    }

    fn add_local_borrow(&mut self, local: LocalIndex, id: RefID) {
        let frame_root = self.frame_root();
        self.borrow_graph
            .add_strong_field_borrow((), frame_root, Label::Local(local), id);
    }

    fn add_variant_field_borrow(
        &mut self,
        parent: RefID,
        enum_def_idx: EnumDefinitionIndex,
        variant_tag: VariantTag,
        field_index: MemberCount,
        child_id: RefID,
    ) {
        self.borrow_graph.add_strong_field_borrow(
            (),
            parent,
            Label::VariantField(enum_def_idx, variant_tag, field_index),
            child_id,
        );
    }

    /// Removes `id` from the borrow graph. Returns the count of
    /// edges spliced through during release (no consumer of this
    /// count in Adamant after the meter drop; preserved for
    /// byte-faithful audit anchor).
    fn release(&mut self, id: RefID) -> usize {
        self.borrow_graph.release(id)
    }

    // ----- Core Predicates -----

    /// Checks if `id` has any full (non-field) borrows.
    fn has_full_borrows(&self, id: RefID) -> bool {
        let (full_borrows, _field_borrows) = self.borrow_graph.borrowed_by(id);
        !full_borrows.is_empty()
    }

    /// Checks if `id` is borrowed:
    /// - All full / epsilon borrows are considered.
    /// - Only field borrows for the specified label (or all if
    ///   none specified) are considered.
    fn has_consistent_borrows(&self, id: RefID, label_opt: Option<Label>) -> bool {
        let (full_borrows, field_borrows) = self.borrow_graph.borrowed_by(id);
        !full_borrows.is_empty()
            || match label_opt {
                None => field_borrows.values().any(|borrows| !borrows.is_empty()),
                Some(label) => field_borrows
                    .get(&label)
                    .is_some_and(|borrows| !borrows.is_empty()),
            }
    }

    /// Checks if `id` is mutably borrowed.
    fn has_consistent_mutable_borrows(&self, id: RefID, label_opt: Option<Label>) -> bool {
        let (full_borrows, field_borrows) = self.borrow_graph.borrowed_by(id);
        !self.all_immutable(&full_borrows)
            || match label_opt {
                None => field_borrows
                    .values()
                    .any(|borrows| !self.all_immutable(borrows)),
                Some(label) => field_borrows
                    .get(&label)
                    .is_some_and(|borrows| !self.all_immutable(borrows)),
            }
    }

    /// Checks if `id` is writable.
    fn is_writable(&self, id: RefID) -> bool {
        debug_assert!(self.borrow_graph.is_mutable(id));
        !self.has_consistent_borrows(id, None)
    }

    /// Checks if `id` is freezable.
    fn is_freezable(&self, id: RefID, at_field_opt: Option<FieldHandleIndex>) -> bool {
        debug_assert!(self.borrow_graph.is_mutable(id));
        !self.has_consistent_mutable_borrows(id, at_field_opt.map(Label::StructField))
    }

    /// Checks if `id` is readable.
    fn is_readable(&self, id: RefID, at_field_opt: Option<FieldHandleIndex>) -> bool {
        let is_mutable = self.borrow_graph.is_mutable(id);
        !is_mutable || self.is_freezable(id, at_field_opt)
    }

    /// Checks if `local@idx` is borrowed.
    fn is_local_borrowed(&self, idx: LocalIndex) -> bool {
        self.has_consistent_borrows(self.frame_root(), Some(Label::Local(idx)))
    }

    /// Checks if `local@idx` is mutably borrowed.
    /// Adamant hardcodes `additional_borrow_checks = true` per
    /// the deviation in module preamble — if the frame root has
    /// any full borrows, the local is conservatively reported
    /// as mutably borrowed.
    fn is_local_mutably_borrowed(&self, idx: LocalIndex) -> bool {
        if ADDITIONAL_BORROW_CHECKS && self.has_full_borrows(self.frame_root()) {
            return true;
        }
        self.has_consistent_mutable_borrows(self.frame_root(), Some(Label::Local(idx)))
    }

    /// Checks if the stack frame can be safely destroyed.
    fn is_frame_safe_to_destroy(&self) -> bool {
        !self.has_consistent_borrows(self.frame_root(), None)
    }

    // ----- Instruction Entry Points -----

    /// Destroys an abstract value (releases its reference id if
    /// it was a reference).
    pub(super) fn release_value(&mut self, value: AbstractValue) {
        if let AbstractValue::Reference(id) = value {
            self.release(id);
        }
    }

    pub(super) fn copy_loc(
        &mut self,
        offset: CodeOffset,
        local: LocalIndex,
    ) -> Result<AbstractValue, AdamantValidationError> {
        let local_value = self.locals.get(local as usize).copied().unwrap_or_else(|| {
            panic!(
                "{STACK_INVARIANT_THREE_ANCHOR_STEM}. local index {local} out of range; \
                 D-3 / D-4 preconditions violated"
            )
        });
        match local_value {
            AbstractValue::Reference(id) => {
                let new_id = self.new_ref(self.borrow_graph.is_mutable(id));
                self.add_copy(id, new_id);
                Ok(AbstractValue::Reference(new_id))
            }
            AbstractValue::NonReference if self.is_local_mutably_borrowed(local) => {
                Err(self.error(offset, BorrowViolationReason::CopyLocBorrowed))
            }
            AbstractValue::NonReference => Ok(AbstractValue::NonReference),
        }
    }

    pub(super) fn move_loc(
        &mut self,
        offset: CodeOffset,
        local: LocalIndex,
    ) -> Result<AbstractValue, AdamantValidationError> {
        let slot = self.locals.get_mut(local as usize).unwrap_or_else(|| {
            panic!("{STACK_INVARIANT_THREE_ANCHOR_STEM}. local index {local} out of range")
        });
        let old_value = std::mem::replace(slot, AbstractValue::NonReference);
        match old_value {
            AbstractValue::Reference(id) => Ok(AbstractValue::Reference(id)),
            AbstractValue::NonReference if self.is_local_borrowed(local) => {
                Err(self.error(offset, BorrowViolationReason::MoveLocBorrowed))
            }
            AbstractValue::NonReference => Ok(AbstractValue::NonReference),
        }
    }

    pub(super) fn st_loc(
        &mut self,
        offset: CodeOffset,
        local: LocalIndex,
        new_value: AbstractValue,
    ) -> Result<(), AdamantValidationError> {
        let slot = self.locals.get_mut(local as usize).unwrap_or_else(|| {
            panic!("{STACK_INVARIANT_THREE_ANCHOR_STEM}. local index {local} out of range")
        });
        let old_value = std::mem::replace(slot, new_value);
        match old_value {
            AbstractValue::Reference(id) => {
                self.release(id);
                Ok(())
            }
            AbstractValue::NonReference if self.is_local_borrowed(local) => {
                Err(self.error(offset, BorrowViolationReason::StLocDestroyBorrowed))
            }
            AbstractValue::NonReference => Ok(()),
        }
    }

    pub(super) fn freeze_ref(
        &mut self,
        offset: CodeOffset,
        id: RefID,
    ) -> Result<AbstractValue, AdamantValidationError> {
        if !self.is_freezable(id, None) {
            return Err(self.error(offset, BorrowViolationReason::FreezeRefHasMutableBorrow));
        }
        let frozen_id = self.new_ref(false);
        self.add_copy(id, frozen_id);
        self.release(id);
        Ok(AbstractValue::Reference(frozen_id))
    }

    pub(super) fn comparison(
        &mut self,
        offset: CodeOffset,
        v1: AbstractValue,
        v2: AbstractValue,
    ) -> Result<AbstractValue, AdamantValidationError> {
        match (v1, v2) {
            (AbstractValue::Reference(id1), AbstractValue::Reference(id2))
                if !self.is_readable(id1, None) || !self.is_readable(id2, None) =>
            {
                Err(self.error(offset, BorrowViolationReason::ReadRefHasMutableBorrow))
            }
            (AbstractValue::Reference(id1), AbstractValue::Reference(id2)) => {
                self.release(id1);
                self.release(id2);
                Ok(AbstractValue::NonReference)
            }
            (v1, v2) => {
                debug_assert!(v1.is_value() && v2.is_value());
                Ok(AbstractValue::NonReference)
            }
        }
    }

    pub(super) fn read_ref(
        &mut self,
        offset: CodeOffset,
        id: RefID,
    ) -> Result<AbstractValue, AdamantValidationError> {
        if !self.is_readable(id, None) {
            return Err(self.error(offset, BorrowViolationReason::ReadRefHasMutableBorrow));
        }
        self.release(id);
        Ok(AbstractValue::NonReference)
    }

    pub(super) fn write_ref(
        &mut self,
        offset: CodeOffset,
        id: RefID,
    ) -> Result<(), AdamantValidationError> {
        if !self.is_writable(id) {
            return Err(self.error(offset, BorrowViolationReason::WriteRefHasBorrow));
        }
        self.release(id);
        Ok(())
    }

    pub(super) fn borrow_loc(
        &mut self,
        offset: CodeOffset,
        mut_: bool,
        local: LocalIndex,
    ) -> Result<AbstractValue, AdamantValidationError> {
        // Nothing to check in case borrow is mutable since the
        // frame cannot have a full borrow / epsilon outgoing
        // edge.
        if !mut_ && self.is_local_mutably_borrowed(local) {
            return Err(self.error(offset, BorrowViolationReason::BorrowLocHasBorrow));
        }

        if ADDITIONAL_BORROW_CHECKS && mut_ && self.has_full_borrows(self.frame_root()) {
            return Err(self.error(offset, BorrowViolationReason::BorrowLocHasBorrow));
        }

        let new_id = self.new_ref(mut_);
        self.add_local_borrow(local, new_id);
        Ok(AbstractValue::Reference(new_id))
    }

    pub(super) fn borrow_field(
        &mut self,
        offset: CodeOffset,
        mut_: bool,
        id: RefID,
        field: FieldHandleIndex,
    ) -> Result<AbstractValue, AdamantValidationError> {
        // Any field borrows will be factored out, so don't check
        // in the mutable case.
        let is_mut_borrow_with_full_borrows = mut_ && self.has_full_borrows(id);
        // For new immutable borrow, the reference must be
        // readable at that field.
        let is_imm_borrow_with_mut_borrows = !mut_ && !self.is_readable(id, Some(field));
        if is_mut_borrow_with_full_borrows || is_imm_borrow_with_mut_borrows {
            return Err(self.error(offset, BorrowViolationReason::BorrowFieldHasMutableBorrow));
        }

        let field_borrow_id = self.new_ref(mut_);
        self.add_field_borrow(id, field, field_borrow_id);
        self.release(id);
        Ok(AbstractValue::Reference(field_borrow_id))
    }

    pub(super) fn unpack_enum_variant_ref(
        &mut self,
        offset: CodeOffset,
        enum_def_idx: EnumDefinitionIndex,
        variant_tag: VariantTag,
        variant_def: &VariantDefinition,
        mut_: bool,
        id: RefID,
    ) -> Result<Vec<AbstractValue>, AdamantValidationError> {
        let is_mut_borrow_with_full_borrows = mut_ && self.has_full_borrows(id);
        let is_imm_borrow_with_mut_borrows = !mut_ && !self.is_readable(id, None);
        if is_mut_borrow_with_full_borrows || is_imm_borrow_with_mut_borrows {
            return Err(self.error(offset, BorrowViolationReason::BorrowFieldHasMutableBorrow));
        }

        let mut field_borrows = Vec::with_capacity(variant_def.fields.len());
        for (i, _) in variant_def.fields.iter().enumerate() {
            let field_borrow_id = self.new_ref(mut_);
            let field_idx = u16::try_from(i)
                .expect("variant field count fits MemberCount per binary-format limits");
            self.add_variant_field_borrow(
                id,
                enum_def_idx,
                variant_tag,
                field_idx,
                field_borrow_id,
            );
            field_borrows.push(AbstractValue::Reference(field_borrow_id));
        }

        self.release(id);
        Ok(field_borrows)
    }

    pub(super) fn vector_op(
        &mut self,
        offset: CodeOffset,
        vector: AbstractValue,
        mut_: bool,
    ) -> Result<(), AdamantValidationError> {
        let id = vector.ref_id().unwrap_or_else(|| {
            panic!("{STACK_INVARIANT_THREE_ANCHOR_STEM}. vector_op called on non-reference operand")
        });
        if mut_ && !self.is_writable(id) {
            return Err(self.error(offset, BorrowViolationReason::VecUpdateHasMutableBorrow));
        }
        self.release(id);
        Ok(())
    }

    /// Modern call helper (Adamant uses this exclusively per
    /// `deprecate_global_storage_ops = true` posture). Pops
    /// argument references, validates mutable transferability,
    /// adds borrow relationships from inputs to returns, and
    /// releases the inputs.
    ///
    /// `reason_on_violation` is the [`BorrowViolationReason`]
    /// emitted when an argument's mutable reference cannot be
    /// transferred — varies across call sites:
    /// - `CallTransfersBorrowedMutable` for `Call` /
    ///   `CallGeneric` / `InvokeShielded` / `InvokeTransparent`
    ///   (cross-pass-distinct 2nd instance of spec-text-to-
    ///   shared-helper canonical principle per Q3 Cat B).
    /// - `VecElementHasMutableBorrow` for `VecImmBorrow` /
    ///   `VecMutBorrow`.
    #[allow(
        clippy::needless_pass_by_value,
        reason = "byte-faithful upstream signature `Vec<AbstractValue>` per \
                  `vendor/move-bytecode-verifier/src/reference_safety/abstract_state.rs:779`; \
                  preserving the audit anchor"
    )]
    pub(super) fn call_v2(
        &mut self,
        offset: CodeOffset,
        arguments: Vec<AbstractValue>,
        return_kinds: &[ValueKind],
        reason_on_violation: BorrowViolationReason,
    ) -> Result<Vec<AbstractValue>, AdamantValidationError> {
        let mut all_references_to_borrow_from = BTreeSet::new();
        let mut mutable_references_to_borrow_from = BTreeSet::new();
        for id in arguments.iter().filter_map(AbstractValue::ref_id) {
            if self.borrow_graph.is_mutable(id) {
                if !self.is_writable(id) {
                    return Err(self.error(offset, reason_on_violation));
                }
                mutable_references_to_borrow_from.insert(id);
            }
            all_references_to_borrow_from.insert(id);
        }

        let return_values: Vec<AbstractValue> = return_kinds
            .iter()
            .map(|value_kind| match value_kind {
                ValueKind::Reference(true) => {
                    let id = self.new_ref(true);
                    for parent in &mutable_references_to_borrow_from {
                        self.add_borrow(*parent, id);
                    }
                    AbstractValue::Reference(id)
                }
                ValueKind::Reference(false) => {
                    let id = self.new_ref(false);
                    for parent in &all_references_to_borrow_from {
                        self.add_borrow(*parent, id);
                    }
                    AbstractValue::Reference(id)
                }
                ValueKind::NonReference => AbstractValue::NonReference,
            })
            .collect();

        for id in all_references_to_borrow_from {
            self.release(id);
        }
        Ok(return_values)
    }

    pub(super) fn ret(
        &mut self,
        offset: CodeOffset,
        values: Vec<AbstractValue>,
    ) -> Result<(), AdamantValidationError> {
        // Release all local-stored references.
        let mut released = BTreeSet::new();
        for stored_value in &self.locals {
            if let AbstractValue::Reference(id) = stored_value {
                released.insert(*id);
            }
        }
        for id in released {
            self.release(id);
        }

        // Check that no local is borrowed.
        if !self.is_frame_safe_to_destroy() {
            return Err(self.error(offset, BorrowViolationReason::RetWithBorrowedFrame));
        }

        // Check that mutable references in return values can be
        // transferred.
        for id in values.into_iter().filter_map(|v| v.ref_id()) {
            if self.borrow_graph.is_mutable(id) && !self.is_writable(id) {
                return Err(self.error(offset, BorrowViolationReason::RetBorrowedMutableReference));
            }
        }
        Ok(())
    }

    // ----- Abstract Interpreter Entry Points -----

    /// Returns the canonical representation of `self` — locals
    /// renumbered to `[0, locals.len())` and the frame-root id
    /// preserved.
    pub(super) fn construct_canonical_state(&self) -> Self {
        let mut id_map = BTreeMap::new();
        id_map.insert(self.frame_root(), self.frame_root());
        let locals: Vec<AbstractValue> = self
            .locals
            .iter()
            .enumerate()
            .map(|(local, value)| match value {
                AbstractValue::Reference(old_id) => {
                    let new_id = RefID::new(local);
                    id_map.insert(*old_id, new_id);
                    AbstractValue::Reference(new_id)
                }
                AbstractValue::NonReference => AbstractValue::NonReference,
            })
            .collect();
        debug_assert!(self.locals.len() == locals.len());
        let mut borrow_graph = self.borrow_graph.clone();
        borrow_graph.remap_refs(&id_map);
        let canonical_state = AbstractState {
            locals,
            borrow_graph,
            current_function: self.current_function,
            next_id: self.locals.len() + 1,
        };
        debug_assert!(canonical_state.is_canonical());
        canonical_state
    }

    #[allow(
        clippy::zero_sized_map_values,
        reason = "byte-faithful upstream signature `BTreeMap<RefID, Loc>` with `Loc = ()` per \
                  `vendor/move-borrow-graph/src/graph.rs:60`; the borrow_graph public API \
                  `borrowed_by` returns this shape and Adamant uses `Loc = ()` since location \
                  metadata is consensus-irrelevant"
    )]
    fn all_immutable(&self, borrows: &BTreeMap<RefID, ()>) -> bool {
        !borrows.keys().any(|x| self.borrow_graph.is_mutable(*x))
    }

    fn is_canonical(&self) -> bool {
        self.locals.len() + 1 == self.next_id
            && self
                .locals
                .iter()
                .enumerate()
                .all(|(local, value)| value.ref_id().is_none_or(|id| RefID::new(local) == id))
    }

    /// Joins `other` into `self`, returning `(joined, released_count)`.
    /// `released_count` counts edges spliced through during joins-
    /// induced releases (no consumer in Adamant after meter drop;
    /// preserved for byte-faithful audit anchor).
    fn join_(&self, other: &Self) -> (Self, usize) {
        debug_assert!(self.current_function == other.current_function);
        debug_assert!(self.is_canonical() && other.is_canonical());
        debug_assert!(self.next_id == other.next_id);
        debug_assert!(self.locals.len() == other.locals.len());
        let mut self_graph = self.borrow_graph.clone();
        let mut other_graph = other.borrow_graph.clone();
        let mut released = 0;
        let locals: Vec<AbstractValue> = self
            .locals
            .iter()
            .zip(&other.locals)
            .map(
                |(self_value, other_value)| match (self_value, other_value) {
                    (AbstractValue::Reference(id), AbstractValue::NonReference) => {
                        released += self_graph.release(*id);
                        AbstractValue::NonReference
                    }
                    (AbstractValue::NonReference, AbstractValue::Reference(id)) => {
                        released += other_graph.release(*id);
                        AbstractValue::NonReference
                    }
                    (v1, v2) => {
                        debug_assert!(v1 == v2);
                        *v1
                    }
                },
            )
            .collect();

        let borrow_graph = self_graph.join(&other_graph);
        let joined = Self {
            current_function: self.current_function,
            locals,
            borrow_graph,
            next_id: self.next_id,
        };
        (joined, released)
    }

    /// `AbstractInterpreter` framework join hook. Returns
    /// [`JoinResult::Changed`] if `pre` was actually mutated
    /// (forces successor reanalysis) or [`JoinResult::Unchanged`]
    /// if `pre` remains equivalent.
    pub(super) fn join_into(&mut self, post: &Self) -> JoinResult {
        let self_size = self.graph_size();
        let post_size = post.graph_size();
        let (joined, _released) = AbstractState::join_(self, post);
        debug_assert!(joined.is_canonical());
        debug_assert!(self.locals.len() == joined.locals.len());
        let _max_size = max(max(self_size, post_size), joined.graph_size());
        let locals_unchanged = self
            .locals
            .iter()
            .zip(&joined.locals)
            .all(|(self_value, joined_value)| self_value == joined_value);
        if locals_unchanged && self.borrow_graph.leq(&joined.borrow_graph) {
            JoinResult::Unchanged
        } else {
            *self = joined;
            JoinResult::Changed
        }
    }
}

#[cfg(test)]
#[allow(
    dead_code,
    reason = "exercised by D-5b.2 pass tests; placeholder for direct unit tests"
)]
mod tests {
    use super::*;
    use adamant_bytecode_format::Signature;

    fn fn_idx(i: u16) -> FunctionDefinitionIndex {
        FunctionDefinitionIndex(i)
    }

    /// Empty function (no params, no locals): canonical
    /// initial state has only the frame-root reference.
    #[test]
    fn new_empty_function_is_canonical() {
        let state = AbstractState::new(fn_idx(0), &Signature(vec![]), &Signature(vec![]));
        assert!(state.is_canonical());
        assert_eq!(state.graph_size(), 1); // frame root only
    }

    /// Function with a reference parameter: param 0 gets
    /// `RefID(0)` in the borrow graph, frame root gets
    /// `RefID(1)`.
    #[test]
    fn new_with_reference_param_creates_ref_in_graph() {
        let params = Signature(vec![SignatureToken::Reference(Box::new(
            SignatureToken::U64,
        ))]);
        let locals = Signature(vec![]);
        let state = AbstractState::new(fn_idx(0), &params, &locals);
        assert!(state.is_canonical());
        assert!(matches!(state.locals[0], AbstractValue::Reference(_)));
    }

    /// Function with a non-reference parameter: locals[0] is
    /// `NonReference`, no borrow-graph entry beyond frame root.
    #[test]
    fn new_with_value_param_does_not_create_ref() {
        let params = Signature(vec![SignatureToken::U64]);
        let locals = Signature(vec![]);
        let state = AbstractState::new(fn_idx(0), &params, &locals);
        assert_eq!(state.locals[0], AbstractValue::NonReference);
        assert_eq!(state.graph_size(), 1); // frame root only
    }

    /// `is_value` and `is_reference` are inverses.
    #[test]
    fn abstract_value_is_value_and_is_reference_are_inverses() {
        let v = AbstractValue::NonReference;
        let r = AbstractValue::Reference(RefID::new(0));
        assert!(v.is_value());
        assert!(!v.is_reference());
        assert!(r.is_reference());
        assert!(!r.is_value());
    }

    /// `ref_id` extracts id from `Reference`, returns `None` for
    /// `NonReference`.
    #[test]
    fn abstract_value_ref_id_round_trips() {
        let id = RefID::new(7);
        assert_eq!(AbstractValue::Reference(id).ref_id(), Some(id));
        assert_eq!(AbstractValue::NonReference.ref_id(), None);
    }
}
