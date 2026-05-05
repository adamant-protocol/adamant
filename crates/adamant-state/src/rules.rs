//! Protocol-level structural rules for object state transitions
//! (whitepaper sections 5.3, 5.4, and 5.4.1).
//!
//! These functions answer the consensus-layer question "is this
//! operation structurally permitted given the object's current
//! state?" — separately from authorisation (signatures, votes,
//! validator objects, all higher-layer concerns) and economics
//! (rent, fees, also higher-layer).
//!
//! Unlike the cryptographic primitives in `adamant-crypto` and the
//! data types in `adamant-types`, this module begins to implement
//! protocol semantics — the rules a transaction must satisfy to be
//! applied. The structural rules are necessary but not sufficient;
//! the VM (Phase 5) and consensus (Phase 8) layer authorisation
//! and economic checks on top.
//!
//! # Spec sources
//!
//! - Whitepaper 5.1.4 specifies the [`Mutability`] enum and its
//!   variants' upgrade rules.
//! - Whitepaper 5.3 specifies that mutability is enforced *at the
//!   consensus layer*, not by smart-contract code: "The validator
//!   does not invoke any smart contract to determine whether the
//!   upgrade is permitted; the permission is a structural property
//!   of the object."
//! - Whitepaper 5.4 specifies the [`Lifecycle`] states and their
//!   high-level meanings.
//! - Whitepaper 5.4.1 ("The transition graph") pins the legal
//!   transitions between non-`Creation` lifecycle states and the
//!   seven properties governing them (freeze one-way; restoration
//!   preserves pre-archival lifecycle; `Archived → Destroyed`
//!   forbidden; restoration not version-incrementing; `Destroyed`
//!   terminal; etc.).
//!
//! # Surface
//!
//! Two groups of validators, by what they gate:
//!
//! Section 5.3 / 5.1.4 — operations within a lifecycle state:
//!
//! - [`can_modify_contents`] — can the object's [`Contents`] be
//!   updated by a state transition?
//! - [`can_upgrade_rules`] — can the object's mutability declaration
//!   or validation logic be replaced?
//! - [`can_freeze`] — can the freeze operation be invoked,
//!   transitioning [`Lifecycle::Active`] → [`Lifecycle::Frozen`]
//!   for an [`Mutability::UpgradeableUntilFrozen`] object?
//!
//! Section 5.4.1 — lifecycle transitions:
//!
//! - [`can_archive`] — can the archive operation be invoked,
//!   transitioning [`Lifecycle::Active`] / [`Lifecycle::Frozen`]
//!   to [`Lifecycle::Archived`] (rent depletion)?
//! - [`can_destroy`] — can the destroy operation be invoked,
//!   transitioning [`Lifecycle::Active`] / [`Lifecycle::Frozen`]
//!   to [`Lifecycle::Destroyed`] via type-logic?
//! - [`can_restore`] — can the restore operation be invoked,
//!   transitioning [`Lifecycle::Archived`] back to its
//!   pre-archival lifecycle?
//!
//! Each function returns `Result<(), RuleViolation>` so the caller
//! gets a structured reason on rejection rather than a bare bool.
//! The rule violations are not security-sensitive — both the rules
//! and the object's state are public, so leaking the specific
//! reason is fine and useful for tooling and consensus error
//! reporting.

use adamant_types::{Lifecycle, Mutability, Object};

/// A structural-rule violation explaining why a proposed operation
/// is rejected. Used by all six validators in this module
/// (`can_modify_contents`, `can_upgrade_rules`, `can_freeze`,
/// `can_archive`, `can_destroy`, `can_restore`). Each variant's
/// doc comment specifies which validators can return it.
///
/// Variants are grouped by category, applied in priority order
/// when multiple rules would block within a single validator:
///
/// - lifecycle-unreachable: `ObjectArchived`, `ObjectDestroyed`
/// - mutability-fixed: `Immutable`
/// - deferred-mechanism: `ForkedDeferred`
/// - state-dependent: `Frozen`, `NotFreezable`, `AlreadyFrozen`,
///   `AlreadyArchived`, `NotArchived`
///
/// The variants are not security-sensitive; the rules they describe
/// are public, the object's state is public, and the reason for
/// rejection is fully determined by public state.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub enum RuleViolation {
    /// The object is in [`Lifecycle::Archived`]; its contents are
    /// pruned from validator working storage and cannot be
    /// referenced until the object is restored per whitepaper
    /// section 5.6.2. Returned by [`can_modify_contents`],
    /// [`can_upgrade_rules`], [`can_freeze`], and [`can_destroy`]
    /// (the last by section 5.4.1's "Archived → Destroyed
    /// forbidden" rule). Not returned by [`can_archive`] (which
    /// uses [`RuleViolation::AlreadyArchived`] for the
    /// already-archived case) or [`can_restore`] (for which
    /// `Archived` is the legal source state).
    ObjectArchived,
    /// The object is in [`Lifecycle::Destroyed`]; the [`ObjectId`]
    /// cannot be reused per whitepaper section 5.4 step 5, and
    /// `Destroyed` is terminal per section 5.4.1 — no transitions
    /// occur from this state. Returned by every validator in this
    /// module.
    ///
    /// [`ObjectId`]: adamant_types::ObjectId
    ObjectDestroyed,
    /// The object's [`Mutability`] is [`Mutability::Immutable`];
    /// the object's rules are permanently fixed at creation per
    /// whitepaper section 5.1.4. Returned by [`can_upgrade_rules`].
    Immutable,
    /// The object's [`Mutability`] is [`Mutability::Forked`].
    /// Forked objects are blocked from all upgrades and freezes
    /// pending the chain-fork mechanism specification in whitepaper
    /// section 11. Two interpretations are possible: Forked objects
    /// could be immutable post-fork (historical record only), in
    /// which case blocking is correct; or Forked objects could
    /// inherit their original's mutability rules, in which case
    /// dispatching through the original is required. Phase 11 will
    /// pick one; this Phase 4 implementation is correct under
    /// interpretation (a) and conservatively safe under
    /// interpretation (b). Returned by [`can_upgrade_rules`] and
    /// [`can_freeze`]. The lifecycle-transition validators
    /// ([`can_archive`], [`can_destroy`], [`can_restore`]) do not
    /// return this variant: per whitepaper section 5.4.1, the
    /// transition graph does not gate by `Mutability`.
    ForkedDeferred,
    /// Returned by [`can_upgrade_rules`] when an object in
    /// [`Lifecycle::Frozen`] would otherwise be upgradeable. The
    /// semantically intended case is
    /// [`Mutability::UpgradeableUntilFrozen`] + [`Lifecycle::Frozen`]
    /// (per whitepaper §5.4 step 3 and §5.1.4: "Cannot un-freeze.
    /// The freeze operation is one-way"). For
    /// non-`UpgradeableUntilFrozen` mutabilities in
    /// [`Lifecycle::Frozen`] — protocol-unreachable states that
    /// shouldn't occur in practice but might appear in adversarial
    /// test inputs — this variant is also returned as the
    /// conservative-block default.
    Frozen,
    /// The freeze operation was attempted on an object whose
    /// [`Mutability`] is not
    /// [`Mutability::UpgradeableUntilFrozen`]. Per whitepaper
    /// section 5.4 step 3, freeze applies only to that variant.
    /// Returned by [`can_freeze`].
    NotFreezable,
    /// The freeze operation was attempted on an
    /// [`Mutability::UpgradeableUntilFrozen`] object whose
    /// [`Lifecycle`] is [`Lifecycle::Frozen`] (already frozen).
    /// Freeze is one-way per whitepaper section 5.1.4 — it cannot
    /// be re-invoked. Returned by [`can_freeze`].
    AlreadyFrozen,
    /// The archive operation was invoked on an object already in
    /// [`Lifecycle::Archived`]. Archival is rent-depletion-driven
    /// (whitepaper section 5.4 step 4) and not idempotent at the
    /// validator layer; the validator rejects re-archival as a
    /// structural error rather than a silent no-op. Returned by
    /// [`can_archive`].
    AlreadyArchived,
    /// The restore operation was invoked on an object not in
    /// [`Lifecycle::Archived`]. Restoration applies only to
    /// archived objects per whitepaper section 5.6.2; no other
    /// lifecycle state has valid restore semantics. Returned by
    /// [`can_restore`].
    NotArchived,
}

/// Whether an object's [`Contents`] may be modified by a state
/// transition, on protocol-structural grounds alone.
///
/// Per whitepaper section 5.4: contents are mutable in the
/// [`Lifecycle::Active`] state and remain mutable in
/// [`Lifecycle::Frozen`] — freeze blocks rule upgrades, not the
/// type-specific in-rules state transitions that update
/// contents. Archived and Destroyed objects are unreachable; their
/// contents cannot be modified until restoration (whitepaper
/// section 5.6.2) or never, respectively.
///
/// Mutability does not affect whether contents are modifiable —
/// even an [`Mutability::Immutable`] object can have its contents
/// updated by valid in-rules transitions (e.g., a token-balance
/// object whose rules are immutable but whose balance changes on
/// every transfer). Mutability gates whether the *rules themselves*
/// can change, which is the concern of [`can_upgrade_rules`].
///
/// # Errors
///
/// Returns [`RuleViolation::ObjectArchived`] or
/// [`RuleViolation::ObjectDestroyed`] for objects in those
/// lifecycles. Returns `Ok(())` for [`Lifecycle::Active`] and
/// [`Lifecycle::Frozen`].
///
/// [`Contents`]: adamant_types::Contents
pub fn can_modify_contents(object: &Object) -> Result<(), RuleViolation> {
    match object.lifecycle {
        Lifecycle::Active | Lifecycle::Frozen => Ok(()),
        Lifecycle::Archived => Err(RuleViolation::ObjectArchived),
        Lifecycle::Destroyed => Err(RuleViolation::ObjectDestroyed),
    }
}

/// Whether an object's rules (mutability declaration and validation
/// logic) may be upgraded by a state transition, on
/// protocol-structural grounds alone.
///
/// Authorisation (signatures for [`Mutability::OwnerUpgradeable`],
/// vote outcome for [`Mutability::VoteUpgradeable`], validator
/// invocation for [`Mutability::Custom`]) is a higher-layer
/// concern; this function says only whether the structural rules
/// permit an upgrade in principle.
///
/// # Priority
///
/// Failures are returned in order:
/// 1. [`Lifecycle::Archived`] / [`Lifecycle::Destroyed`] —
///    object unreachable.
/// 2. [`Mutability::Immutable`] — rules permanently fixed.
/// 3. [`Mutability::Forked`] — deferred to Phase 11.
/// 4. [`Lifecycle::Frozen`] — upgrades blocked from this point.
/// 5. Otherwise `Ok(())` (subject to higher-layer authorisation).
///
/// This priority means an [`Mutability::Immutable`] object in
/// [`Lifecycle::Frozen`] returns [`RuleViolation::Immutable`]
/// (the more specific reason) rather than [`RuleViolation::Frozen`].
///
/// # Errors
///
/// Returns one of [`RuleViolation::ObjectArchived`],
/// [`RuleViolation::ObjectDestroyed`], [`RuleViolation::Immutable`],
/// [`RuleViolation::ForkedDeferred`], or [`RuleViolation::Frozen`]
/// per the priority above.
pub fn can_upgrade_rules(object: &Object) -> Result<(), RuleViolation> {
    // Priority 1: lifecycle-unreachable failures.
    match object.lifecycle {
        Lifecycle::Archived => return Err(RuleViolation::ObjectArchived),
        Lifecycle::Destroyed => return Err(RuleViolation::ObjectDestroyed),
        Lifecycle::Active | Lifecycle::Frozen => {}
    }
    // Priority 2: mutability-fixed.
    if matches!(object.mutability, Mutability::Immutable) {
        return Err(RuleViolation::Immutable);
    }
    // Priority 3: Forked-deferred.
    if matches!(object.mutability, Mutability::Forked { .. }) {
        return Err(RuleViolation::ForkedDeferred);
    }
    // Priority 4: state-dependent (Frozen blocks upgrades for the
    // remaining mutability variants).
    if object.lifecycle == Lifecycle::Frozen {
        return Err(RuleViolation::Frozen);
    }
    Ok(())
}

/// Whether the freeze operation may be invoked on the object,
/// transitioning [`Lifecycle::Active`] → [`Lifecycle::Frozen`].
///
/// Per whitepaper section 5.4 step 3, freeze applies only to
/// [`Mutability::UpgradeableUntilFrozen`] objects; per section
/// 5.1.4, freeze is one-way and cannot be re-invoked once an
/// object is already frozen.
///
/// # Priority
///
/// Failures are returned in order:
/// 1. [`Lifecycle::Archived`] / [`Lifecycle::Destroyed`] —
///    object unreachable.
/// 2. [`Mutability::Forked`] — deferred to Phase 11.
/// 3. Mutability is not [`Mutability::UpgradeableUntilFrozen`] —
///    freeze is not the right operation for this object.
/// 4. [`Lifecycle::Frozen`] — already frozen; freeze is one-way.
/// 5. [`Mutability::UpgradeableUntilFrozen`] +
///    [`Lifecycle::Active`] → `Ok(())`.
///
/// # Errors
///
/// Returns one of [`RuleViolation::ObjectArchived`],
/// [`RuleViolation::ObjectDestroyed`],
/// [`RuleViolation::ForkedDeferred`],
/// [`RuleViolation::NotFreezable`], or
/// [`RuleViolation::AlreadyFrozen`] per the priority above.
pub fn can_freeze(object: &Object) -> Result<(), RuleViolation> {
    // Priority 1: lifecycle-unreachable failures.
    match object.lifecycle {
        Lifecycle::Archived => return Err(RuleViolation::ObjectArchived),
        Lifecycle::Destroyed => return Err(RuleViolation::ObjectDestroyed),
        Lifecycle::Active | Lifecycle::Frozen => {}
    }
    // Priority 2: Forked-deferred.
    if matches!(object.mutability, Mutability::Forked { .. }) {
        return Err(RuleViolation::ForkedDeferred);
    }
    // Priority 3: only UpgradeableUntilFrozen supports freeze.
    if !matches!(object.mutability, Mutability::UpgradeableUntilFrozen { .. }) {
        return Err(RuleViolation::NotFreezable);
    }
    // Priority 4: already frozen.
    if object.lifecycle == Lifecycle::Frozen {
        return Err(RuleViolation::AlreadyFrozen);
    }
    // UpgradeableUntilFrozen + Active.
    Ok(())
}

/// Whether the archive operation may be invoked on the object,
/// transitioning [`Lifecycle::Active`] or [`Lifecycle::Frozen`]
/// to [`Lifecycle::Archived`].
///
/// Per whitepaper section 5.4 step 4, archival is invoked on
/// rent depletion and applies regardless of the object's
/// [`Mutability`] field — both `Active` and `Frozen` objects
/// archive on the same path. The validator does not see rent
/// state; it only confirms the source-lifecycle structural
/// precondition.
///
/// # Priority
///
/// 1. [`Lifecycle::Destroyed`] →
///    [`RuleViolation::ObjectDestroyed`] (Destroyed is terminal
///    per section 5.4.1).
/// 2. [`Lifecycle::Archived`] →
///    [`RuleViolation::AlreadyArchived`] (re-archival is a
///    structural error rather than a silent no-op).
/// 3. [`Lifecycle::Active`] / [`Lifecycle::Frozen`] → `Ok(())`.
///
/// # Errors
///
/// Returns [`RuleViolation::ObjectDestroyed`] or
/// [`RuleViolation::AlreadyArchived`] per the priority above.
pub fn can_archive(object: &Object) -> Result<(), RuleViolation> {
    match object.lifecycle {
        Lifecycle::Destroyed => Err(RuleViolation::ObjectDestroyed),
        Lifecycle::Archived => Err(RuleViolation::AlreadyArchived),
        Lifecycle::Active | Lifecycle::Frozen => Ok(()),
    }
}

/// Whether the destroy operation may be invoked on the object,
/// transitioning [`Lifecycle::Active`] or [`Lifecycle::Frozen`]
/// to [`Lifecycle::Destroyed`].
///
/// Per whitepaper section 5.4 step 5, destruction is invoked
/// through the type's pre-existing destroy-logic. Per section
/// 5.4.1, `Frozen → Destroyed` is permitted: the freeze
/// operation locks rule changes, not the object's existence,
/// so a frozen escrow that becomes ready to settle is
/// destroyable through the same type-logic that would destroy
/// an active escrow. `Archived → Destroyed` is forbidden (must
/// restore first; the type-logic cannot operate on an archived
/// object whose contents are pruned). The validator does not
/// invoke the type-logic itself — that is a higher-layer
/// concern; it only confirms the source-lifecycle structural
/// precondition.
///
/// # Priority
///
/// 1. [`Lifecycle::Destroyed`] →
///    [`RuleViolation::ObjectDestroyed`].
/// 2. [`Lifecycle::Archived`] →
///    [`RuleViolation::ObjectArchived`] (must restore first per
///    section 5.4.1).
/// 3. [`Lifecycle::Active`] / [`Lifecycle::Frozen`] → `Ok(())`.
///
/// # Errors
///
/// Returns [`RuleViolation::ObjectDestroyed`] or
/// [`RuleViolation::ObjectArchived`] per the priority above.
pub fn can_destroy(object: &Object) -> Result<(), RuleViolation> {
    match object.lifecycle {
        Lifecycle::Destroyed => Err(RuleViolation::ObjectDestroyed),
        Lifecycle::Archived => Err(RuleViolation::ObjectArchived),
        Lifecycle::Active | Lifecycle::Frozen => Ok(()),
    }
}

/// Whether the restore operation may be invoked on the object,
/// transitioning [`Lifecycle::Archived`] back to its
/// pre-archival lifecycle (`Active` or `Frozen`).
///
/// Per whitepaper section 5.4.1 and section 5.6.2, restoration
/// preserves the pre-archival lifecycle (an object archived from
/// `Frozen` returns to `Frozen`, preserving section 5.1.4's
/// freeze-is-one-way invariant) and the pre-archival version
/// (causal ordering per section 5.2.1 requires version
/// continuity across archival round-trips). The validator does
/// not see the contents-proof or the rent payment; those are
/// section 5.6.2 concerns at a higher layer. It only confirms
/// the source-lifecycle structural precondition.
///
/// # Priority
///
/// 1. [`Lifecycle::Destroyed`] →
///    [`RuleViolation::ObjectDestroyed`].
/// 2. [`Lifecycle::Active`] / [`Lifecycle::Frozen`] →
///    [`RuleViolation::NotArchived`] (restoration applies only
///    to archived objects).
/// 3. [`Lifecycle::Archived`] → `Ok(())`.
///
/// # Errors
///
/// Returns [`RuleViolation::ObjectDestroyed`] or
/// [`RuleViolation::NotArchived`] per the priority above.
pub fn can_restore(object: &Object) -> Result<(), RuleViolation> {
    match object.lifecycle {
        Lifecycle::Destroyed => Err(RuleViolation::ObjectDestroyed),
        Lifecycle::Active | Lifecycle::Frozen => Err(RuleViolation::NotArchived),
        Lifecycle::Archived => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use adamant_types::{
        Address, BasisPoints, Contents, ObjectId, ObjectMetadata, Ownership, ProofCommitment,
        TypeId,
    };

    // ---------- test fixtures ----------

    fn fixed_address() -> Address {
        Address::from_bytes([0x11; 32])
    }

    fn fixed_type_id() -> TypeId {
        TypeId::from_bytes([0x22; 32])
    }

    fn fixed_object_id() -> ObjectId {
        ObjectId::from_bytes([0x33; 32])
    }

    fn fixed_metadata() -> ObjectMetadata {
        ObjectMetadata {
            created_at_height: 0,
            last_modified_height: 0,
            creator: fixed_address(),
            storage_rent_paid_through: 0,
            proof_commitment: ProofCommitment::from_bytes([0; 48]),
        }
    }

    /// Construct an [`Object`] for rule-checking tests. Only
    /// `mutability` and `lifecycle` matter to the rules functions;
    /// the other fields are filled with deterministic dummy values.
    fn make_object(mutability: Mutability, lifecycle: Lifecycle) -> Object {
        Object {
            id: ObjectId::from_bytes([0; 32]),
            type_id: fixed_type_id(),
            owner: Ownership::Shared,
            mutability,
            lifecycle,
            contents: Contents::empty(),
            version: 1,
            metadata: fixed_metadata(),
        }
    }

    // ---------- one fixed sample of each Mutability variant ----------
    //
    // Mutability has structured payloads that aren't const-creatable;
    // these helpers produce a canonical sample of each variant for
    // use in the table below.

    fn mut_immutable() -> Mutability {
        Mutability::Immutable
    }
    fn mut_owner_upgradeable() -> Mutability {
        Mutability::OwnerUpgradeable {
            owner: fixed_address(),
        }
    }
    fn mut_vote_upgradeable() -> Mutability {
        Mutability::VoteUpgradeable {
            token_type: fixed_type_id(),
            approval_threshold: BasisPoints::new(6700).expect("valid"),
            quorum_threshold: BasisPoints::new(3000).expect("valid"),
            voting_period_secs: 7 * 24 * 3600,
            execution_delay_secs: 7 * 24 * 3600,
        }
    }
    fn mut_upgradeable_until_frozen() -> Mutability {
        Mutability::UpgradeableUntilFrozen {
            owner: fixed_address(),
        }
    }
    fn mut_custom() -> Mutability {
        Mutability::Custom {
            upgrade_validator: fixed_type_id(),
            validator_id: fixed_object_id(),
        }
    }
    fn mut_forked() -> Mutability {
        Mutability::Forked {
            original: fixed_object_id(),
            fork_height: 100,
        }
    }

    // ---------- the rules matrix ----------
    //
    // The 24 (mutability × lifecycle) cells with each function's
    // expected outcome. This table is the human-readable
    // specification of the rules module: a reader scans
    // left-to-right and sees what every cell should produce.
    //
    // Column meanings:
    //   - mutability_label: the [`Mutability`] variant under test
    //   - lifecycle: the [`Lifecycle`] state under test
    //   - expect_modify: expected output of [`can_modify_contents`]
    //   - expect_upgrade: expected output of [`can_upgrade_rules`]
    //   - expect_freeze: expected output of [`can_freeze`]
    //
    // Reordering rows or changing expected values is a structural
    // protocol-rule change requiring a corresponding update to
    // whitepaper sections 5.1.4 / 5.3 / 5.4 — not a refactor.

    type Outcome = Result<(), RuleViolation>;

    // NOTE: Some cells in this matrix correspond to
    // protocol-unreachable states. For example, `Immutable + Frozen`
    // cannot be produced through valid protocol operations because
    // the freeze transition only applies to `UpgradeableUntilFrozen`
    // (whitepaper §5.4 step 3). Such cells are tested anyway to pin
    // defensive behaviour: if an incoherent state somehow occurred
    // (a bug elsewhere in the protocol, an adversarially-constructed
    // test input), the rules functions still produce a coherent
    // answer rather than panicking. The asserted outcomes for
    // unreachable cells are conservative-block defaults.
    struct RuleCase {
        mutability_label: &'static str,
        mutability: Mutability,
        lifecycle: Lifecycle,
        expect_modify: Outcome,
        expect_upgrade: Outcome,
        expect_freeze: Outcome,
    }

    // The matrix is deliberately verbose: each row is one cell of
    // the human-readable specification and is independently
    // readable. Compressing the function would hide the structure
    // the test exists to make explicit.
    #[allow(clippy::too_many_lines)]
    fn rules_matrix() -> Vec<RuleCase> {
        use Lifecycle::{Active, Archived, Destroyed, Frozen};
        use RuleViolation as RV;

        let archived_row = |label: &'static str, m: Mutability| -> RuleCase {
            RuleCase {
                mutability_label: label,
                mutability: m,
                lifecycle: Archived,
                expect_modify: Err(RV::ObjectArchived),
                expect_upgrade: Err(RV::ObjectArchived),
                expect_freeze: Err(RV::ObjectArchived),
            }
        };
        let destroyed_row = |label: &'static str, m: Mutability| -> RuleCase {
            RuleCase {
                mutability_label: label,
                mutability: m,
                lifecycle: Destroyed,
                expect_modify: Err(RV::ObjectDestroyed),
                expect_upgrade: Err(RV::ObjectDestroyed),
                expect_freeze: Err(RV::ObjectDestroyed),
            }
        };

        vec![
            // --- Immutable ---
            RuleCase {
                mutability_label: "Immutable",
                mutability: mut_immutable(),
                lifecycle: Active,
                expect_modify: Ok(()),
                expect_upgrade: Err(RV::Immutable),
                expect_freeze: Err(RV::NotFreezable),
            },
            RuleCase {
                mutability_label: "Immutable",
                mutability: mut_immutable(),
                lifecycle: Frozen,
                expect_modify: Ok(()),
                expect_upgrade: Err(RV::Immutable),
                expect_freeze: Err(RV::NotFreezable),
            },
            archived_row("Immutable", mut_immutable()),
            destroyed_row("Immutable", mut_immutable()),
            // --- OwnerUpgradeable ---
            RuleCase {
                mutability_label: "OwnerUpgradeable",
                mutability: mut_owner_upgradeable(),
                lifecycle: Active,
                expect_modify: Ok(()),
                expect_upgrade: Ok(()),
                expect_freeze: Err(RV::NotFreezable),
            },
            RuleCase {
                mutability_label: "OwnerUpgradeable",
                mutability: mut_owner_upgradeable(),
                lifecycle: Frozen,
                expect_modify: Ok(()),
                expect_upgrade: Err(RV::Frozen),
                expect_freeze: Err(RV::NotFreezable),
            },
            archived_row("OwnerUpgradeable", mut_owner_upgradeable()),
            destroyed_row("OwnerUpgradeable", mut_owner_upgradeable()),
            // --- VoteUpgradeable ---
            RuleCase {
                mutability_label: "VoteUpgradeable",
                mutability: mut_vote_upgradeable(),
                lifecycle: Active,
                expect_modify: Ok(()),
                expect_upgrade: Ok(()),
                expect_freeze: Err(RV::NotFreezable),
            },
            RuleCase {
                mutability_label: "VoteUpgradeable",
                mutability: mut_vote_upgradeable(),
                lifecycle: Frozen,
                expect_modify: Ok(()),
                expect_upgrade: Err(RV::Frozen),
                expect_freeze: Err(RV::NotFreezable),
            },
            archived_row("VoteUpgradeable", mut_vote_upgradeable()),
            destroyed_row("VoteUpgradeable", mut_vote_upgradeable()),
            // --- UpgradeableUntilFrozen ---
            RuleCase {
                mutability_label: "UpgradeableUntilFrozen",
                mutability: mut_upgradeable_until_frozen(),
                lifecycle: Active,
                expect_modify: Ok(()),
                expect_upgrade: Ok(()),
                expect_freeze: Ok(()),
            },
            RuleCase {
                mutability_label: "UpgradeableUntilFrozen",
                mutability: mut_upgradeable_until_frozen(),
                lifecycle: Frozen,
                expect_modify: Ok(()),
                expect_upgrade: Err(RV::Frozen),
                expect_freeze: Err(RV::AlreadyFrozen),
            },
            archived_row("UpgradeableUntilFrozen", mut_upgradeable_until_frozen()),
            destroyed_row("UpgradeableUntilFrozen", mut_upgradeable_until_frozen()),
            // --- Custom ---
            RuleCase {
                mutability_label: "Custom",
                mutability: mut_custom(),
                lifecycle: Active,
                expect_modify: Ok(()),
                expect_upgrade: Ok(()),
                expect_freeze: Err(RV::NotFreezable),
            },
            RuleCase {
                mutability_label: "Custom",
                mutability: mut_custom(),
                lifecycle: Frozen,
                expect_modify: Ok(()),
                expect_upgrade: Err(RV::Frozen),
                expect_freeze: Err(RV::NotFreezable),
            },
            archived_row("Custom", mut_custom()),
            destroyed_row("Custom", mut_custom()),
            // --- Forked ---
            RuleCase {
                mutability_label: "Forked",
                mutability: mut_forked(),
                lifecycle: Active,
                expect_modify: Ok(()),
                expect_upgrade: Err(RV::ForkedDeferred),
                expect_freeze: Err(RV::ForkedDeferred),
            },
            RuleCase {
                mutability_label: "Forked",
                mutability: mut_forked(),
                lifecycle: Frozen,
                expect_modify: Ok(()),
                expect_upgrade: Err(RV::ForkedDeferred),
                expect_freeze: Err(RV::ForkedDeferred),
            },
            archived_row("Forked", mut_forked()),
            destroyed_row("Forked", mut_forked()),
        ]
    }

    // ---------- exhaustive matrix test ----------

    /// Exhaustive enumeration of every (Mutability variant ×
    /// Lifecycle state) cell, asserting the expected outcome of
    /// each rule function. A failure here means the rules diverged
    /// from the matrix above; the matrix IS the spec, and changing
    /// it is a protocol-rule change.
    #[test]
    fn rules_matrix_exhaustive() {
        let cases = rules_matrix();
        assert_eq!(
            cases.len(),
            6 * 4,
            "matrix must have exactly 6 mutabilities × 4 lifecycles = 24 rows"
        );

        for case in &cases {
            let object = make_object(case.mutability.clone(), case.lifecycle);
            let label = format!("{} + {:?}", case.mutability_label, case.lifecycle);
            assert_eq!(
                can_modify_contents(&object),
                case.expect_modify,
                "can_modify_contents mismatch for {label}"
            );
            assert_eq!(
                can_upgrade_rules(&object),
                case.expect_upgrade,
                "can_upgrade_rules mismatch for {label}"
            );
            assert_eq!(
                can_freeze(&object),
                case.expect_freeze,
                "can_freeze mismatch for {label}"
            );
        }
    }

    // ---------- priority invariants ----------

    /// Lifecycle-unreachable failures take priority over
    /// mutability-fixed failures: an Archived Immutable object
    /// returns `ObjectArchived` (the lifecycle reason), not Immutable.
    /// Establishes that a future refactor can't silently swap the
    /// priority order.
    #[test]
    fn lifecycle_priority_over_mutability_immutable() {
        let object = make_object(mut_immutable(), Lifecycle::Archived);
        assert_eq!(
            can_upgrade_rules(&object),
            Err(RuleViolation::ObjectArchived)
        );
    }

    /// Lifecycle-unreachable failures take priority over Forked
    /// deferral: an Archived Forked object returns `ObjectArchived`,
    /// not `ForkedDeferred`.
    #[test]
    fn lifecycle_priority_over_mutability_forked() {
        let object = make_object(mut_forked(), Lifecycle::Archived);
        assert_eq!(
            can_upgrade_rules(&object),
            Err(RuleViolation::ObjectArchived)
        );
        assert_eq!(can_freeze(&object), Err(RuleViolation::ObjectArchived));
    }

    /// Immutable takes priority over Frozen for `can_upgrade_rules`:
    /// an Immutable+Frozen object returns Immutable (the
    /// more-specific reason), not Frozen.
    #[test]
    fn immutable_priority_over_frozen() {
        let object = make_object(mut_immutable(), Lifecycle::Frozen);
        assert_eq!(can_upgrade_rules(&object), Err(RuleViolation::Immutable));
    }

    /// Forked takes priority over Frozen for `can_upgrade_rules`:
    /// a Forked+Frozen object returns `ForkedDeferred`, not Frozen.
    #[test]
    fn forked_priority_over_frozen() {
        let object = make_object(mut_forked(), Lifecycle::Frozen);
        assert_eq!(
            can_upgrade_rules(&object),
            Err(RuleViolation::ForkedDeferred)
        );
    }

    /// For `can_freeze`, `NotFreezable` (mutability-doesn't-support)
    /// takes priority over `AlreadyFrozen` (lifecycle-state). This
    /// matters for Immutable + Frozen, where the more-actionable
    /// reason is "this mutability can't be frozen at all" rather
    /// than "it's already frozen" (which would be misleading
    /// because Immutable can't reach Frozen via the normal freeze
    /// transition).
    #[test]
    fn non_upgradeable_until_frozen_in_frozen_returns_not_freezable() {
        let object = make_object(mut_immutable(), Lifecycle::Frozen);
        assert_eq!(can_freeze(&object), Err(RuleViolation::NotFreezable));
    }

    // ---------- the legitimate freeze case ----------

    /// The single (Mutability, Lifecycle) combination where
    /// `can_freeze` returns Ok: `UpgradeableUntilFrozen` + Active.
    /// Pinned as its own test as a positive-case readability anchor.
    #[test]
    fn freeze_succeeds_only_for_upgradeable_until_frozen_active() {
        let object = make_object(mut_upgradeable_until_frozen(), Lifecycle::Active);
        assert_eq!(can_freeze(&object), Ok(()));
    }

    // ---------- lifecycle-transition matrix ----------
    //
    // The 12 (lifecycle × validator) cells for the lifecycle-
    // transition validators introduced per whitepaper §5.4.1.
    // `Mutability` does not enter these validators (per §5.4 step 4:
    // archival is mutability-independent; per §5.4.1: the transition
    // graph does not gate by Mutability variant). The matrix is a
    // 4×3 table — one row per `Lifecycle` state, one column per
    // validator; mutability-invariance is pinned by a separate
    // `lifecycle_validators_ignore_mutability` test below.
    //
    // Reordering rows or changing expected values is a structural
    // protocol-rule change requiring a corresponding update to
    // whitepaper §5.4.1 — not a refactor.

    struct LifecycleCase {
        lifecycle: Lifecycle,
        expect_archive: Outcome,
        expect_destroy: Outcome,
        expect_restore: Outcome,
    }

    fn lifecycle_matrix() -> Vec<LifecycleCase> {
        use Lifecycle::{Active, Archived, Destroyed, Frozen};
        use RuleViolation as RV;

        vec![
            LifecycleCase {
                lifecycle: Active,
                expect_archive: Ok(()),
                expect_destroy: Ok(()),
                expect_restore: Err(RV::NotArchived),
            },
            LifecycleCase {
                lifecycle: Frozen,
                expect_archive: Ok(()),
                expect_destroy: Ok(()),
                expect_restore: Err(RV::NotArchived),
            },
            LifecycleCase {
                lifecycle: Archived,
                expect_archive: Err(RV::AlreadyArchived),
                expect_destroy: Err(RV::ObjectArchived),
                expect_restore: Ok(()),
            },
            LifecycleCase {
                lifecycle: Destroyed,
                expect_archive: Err(RV::ObjectDestroyed),
                expect_destroy: Err(RV::ObjectDestroyed),
                expect_restore: Err(RV::ObjectDestroyed),
            },
        ]
    }

    /// Exhaustive enumeration of every (Lifecycle × validator) cell
    /// for the lifecycle-transition validators ([`can_archive`],
    /// [`can_destroy`], [`can_restore`]). Failure here means a
    /// validator diverged from §5.4.1's transition graph.
    ///
    /// Mutability is held at `Mutability::Immutable` arbitrarily;
    /// `lifecycle_validators_ignore_mutability` pins the spec
    /// requirement that all six `Mutability` variants produce the
    /// same outcome.
    #[test]
    fn lifecycle_transition_matrix_exhaustive() {
        let cases = lifecycle_matrix();
        assert_eq!(cases.len(), 4, "matrix must have exactly 4 lifecycles");

        for case in &cases {
            let object = make_object(mut_immutable(), case.lifecycle);
            let label = format!("{:?}", case.lifecycle);
            assert_eq!(
                can_archive(&object),
                case.expect_archive,
                "can_archive mismatch for {label}"
            );
            assert_eq!(
                can_destroy(&object),
                case.expect_destroy,
                "can_destroy mismatch for {label}"
            );
            assert_eq!(
                can_restore(&object),
                case.expect_restore,
                "can_restore mismatch for {label}"
            );
        }
    }

    // ---------- lifecycle-transition positive anchors ----------

    /// `can_archive` returns `Ok(())` for both `Active` and `Frozen`
    /// sources. Per §5.4 step 4: archival applies regardless of
    /// whether the source is `Active` or `Frozen` — both share the
    /// rent-depletion path. Pinned as a positive-case readability
    /// anchor.
    #[test]
    fn archive_succeeds_for_active_and_frozen() {
        let active = make_object(mut_immutable(), Lifecycle::Active);
        let frozen = make_object(mut_upgradeable_until_frozen(), Lifecycle::Frozen);
        assert_eq!(can_archive(&active), Ok(()));
        assert_eq!(can_archive(&frozen), Ok(()));
    }

    /// `can_destroy` returns `Ok(())` for both `Active` and `Frozen`
    /// sources. Per §5.4.1: `Frozen → Destroyed` is permitted via
    /// the type's pre-existing destroy-logic (freeze locks rule
    /// changes, not the object's existence). Pinned as a positive-
    /// case readability anchor.
    #[test]
    fn destroy_succeeds_for_active_and_frozen() {
        let active = make_object(mut_immutable(), Lifecycle::Active);
        let frozen = make_object(mut_upgradeable_until_frozen(), Lifecycle::Frozen);
        assert_eq!(can_destroy(&active), Ok(()));
        assert_eq!(can_destroy(&frozen), Ok(()));
    }

    /// `can_restore` returns `Ok(())` only for `Archived` sources.
    /// Pinned as the positive-case readability anchor for the
    /// restoration validator.
    #[test]
    fn restore_succeeds_for_archived() {
        let archived = make_object(mut_immutable(), Lifecycle::Archived);
        assert_eq!(can_restore(&archived), Ok(()));
    }

    /// The lifecycle-transition validators ([`can_archive`],
    /// [`can_destroy`], [`can_restore`]) ignore the `Mutability`
    /// field per §5.4 step 4 ("Archival applies regardless of the
    /// object's `Mutability` field") and §5.4.1 (the transition
    /// graph does not gate by `Mutability` variant). Spot-check by
    /// varying `Mutability` across all six variants for the
    /// positive-case lifecycle of each validator (`Active` for
    /// archive/destroy; `Archived` for restore); the result must
    /// be invariant.
    ///
    /// Catches a future refactor that accidentally adds a
    /// mutability-gate (e.g., a "no archival of `Custom`-mutability
    /// objects" rule that would contradict §5.4 step 4).
    #[test]
    fn lifecycle_validators_ignore_mutability() {
        let mutabilities = [
            mut_immutable(),
            mut_owner_upgradeable(),
            mut_vote_upgradeable(),
            mut_upgradeable_until_frozen(),
            mut_custom(),
            mut_forked(),
        ];

        for m in &mutabilities {
            let active = make_object(m.clone(), Lifecycle::Active);
            assert_eq!(
                can_archive(&active),
                Ok(()),
                "can_archive must accept Active regardless of mutability"
            );
            assert_eq!(
                can_destroy(&active),
                Ok(()),
                "can_destroy must accept Active regardless of mutability"
            );

            let archived = make_object(m.clone(), Lifecycle::Archived);
            assert_eq!(
                can_restore(&archived),
                Ok(()),
                "can_restore must accept Archived regardless of mutability"
            );
        }
    }

    // ---------- RuleViolation distinctness ----------

    /// All nine [`RuleViolation`] variants are distinguishable.
    /// A future contributor adding a variant won't accidentally
    /// collapse two existing ones into the same value.
    #[test]
    fn rule_violation_variants_are_distinct() {
        let variants = [
            RuleViolation::ObjectArchived,
            RuleViolation::ObjectDestroyed,
            RuleViolation::Immutable,
            RuleViolation::ForkedDeferred,
            RuleViolation::Frozen,
            RuleViolation::NotFreezable,
            RuleViolation::AlreadyFrozen,
            RuleViolation::AlreadyArchived,
            RuleViolation::NotArchived,
        ];
        for (i, a) in variants.iter().enumerate() {
            for (j, b) in variants.iter().enumerate() {
                if i == j {
                    assert_eq!(a, b);
                } else {
                    assert_ne!(a, b, "variants at indices {i} and {j} must differ");
                }
            }
        }
    }
}
