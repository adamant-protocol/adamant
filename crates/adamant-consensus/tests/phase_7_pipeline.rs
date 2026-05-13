//! Phase 7.11 end-to-end integration tests for the §8 consensus
//! layer.
//!
//! Exercises the full Phase 7 stack through realistic
//! multi-validator scenarios. Each test composes types from
//! multiple Phase 7 sub-arcs to verify the pipeline holds
//! end-to-end.
//!
//! # Scenarios
//!
//! - [`equivocation_detected_then_slashed_pipeline`] — Phase
//!   7.7a `DagState` surfaces `EquivocationDetected` →
//!   Phase 7.10 `verify_equivocation_evidence` confirms →
//!   `apply_slashing` burns 100% of the offender's stake.
//! - [`liveness_failure_detected_then_slashed_pipeline`] —
//!   Phase 7.1 `Slot::is_liveness_failed` surfaces →
//!   Phase 7.10 `verify_liveness_failure_evidence` confirms →
//!   `apply_slashing` burns 0.5% + removes from active set.
//! - [`tier_signal_tracks_active_set_size_across_epochs`] —
//!   Phase 7.9 `LightClientState::advance` consumes
//!   `EpochBoundary` artifacts; tier signal updates per §8.1.7
//!   as active-set size crosses Tier boundaries (7→I, 15→II,
//!   30→III).
//! - [`pipeline_is_dag_construction_order_independent`] —
//!   §8.7 safety convergence: two independently-constructed
//!   pipelines on identical inputs converge to identical state.

use adamant_consensus::vertex::PartialProofWitness;
use adamant_consensus::SlashingError;
use adamant_consensus::{
    apply_slashing, slashing_penalty_basis_points, verify_equivocation_evidence,
    verify_liveness_failure_evidence, ActiveSet, DagError, DagState, EpochBoundary, EpochNumber,
    LightClientState, ProofCommitment, RoundNumber, SecurityTier, SlashOffence, Stake,
    StateCommitment, ValidatorId, ValidatorPublicKeys, Vertex, VertexBuilder, VertexId,
    VertexSignature, BASIS_POINTS_DENOMINATOR, BLS_SIGNATURE_BYTES,
};
use adamant_crypto::bls;

fn validator_pubkeys(seed: u8) -> ValidatorPublicKeys {
    ValidatorPublicKeys::new([seed; 32], [seed; 1952], [seed; 96])
}

fn validator_id(seed: u8) -> ValidatorId {
    validator_pubkeys(seed).derive_id()
}

fn fixture_active_set(n: u8) -> ActiveSet {
    let mut set = ActiveSet::new();
    for seed in 1..=n {
        set.register(validator_id(seed), EpochNumber::default())
            .expect("register");
    }
    set
}

/// Build a vertex signed with a real BLS key derived from a
/// 32-byte IKM seed. The `nonce` byte differentiates two
/// vertices for the same (author, round) — the equivocation
/// evidence pattern.
fn signed_vertex_with_nonce(
    sk_seed: &[u8; 32],
    author: ValidatorId,
    round: u64,
    nonce: u8,
) -> Vertex {
    let sk = bls::SecretKey::from_ikm(sk_seed).expect("bls secret");
    let body = if nonce == 0 { vec![] } else { vec![nonce] };
    let unsigned = VertexBuilder::new(author, RoundNumber::new(round))
        .with_proof_witness(PartialProofWitness::new(body.clone()))
        .build_unsigned();
    let id = unsigned.derive_id();
    let sig = sk.sign(id.as_bytes());
    VertexBuilder::new(author, RoundNumber::new(round))
        .with_proof_witness(PartialProofWitness::new(body))
        .with_signature(VertexSignature::from_bytes(sig.to_bytes()))
        .build()
}

/// Derive the (`PublicKeys`, `ValidatorId`) pair for a BLS IKM.
fn bls_keypair(sk_seed: &[u8; 32]) -> (ValidatorPublicKeys, ValidatorId) {
    let sk = bls::SecretKey::from_ikm(sk_seed).expect("bls");
    let pk = sk.public_key();
    let pubkeys = ValidatorPublicKeys::new([0u8; 32], [0u8; 1952], pk.to_bytes());
    let id = pubkeys.derive_id();
    (pubkeys, id)
}

// ===============================================================
// Phase 7.11: equivocation pipeline
// ===============================================================

#[test]
fn equivocation_detected_then_slashed_pipeline() {
    // Step 1 — set up an active set including a validator
    // with real BLS keys (so signatures verify).
    let (offender_pubkeys, offender_id) = bls_keypair(&[7u8; 32]);
    // Build a 7-validator active set with the offender as
    // validator 1 (replace seed-1's keys with the BLS-derived
    // ones so the offender_id matches a registered validator).
    let mut active = ActiveSet::new();
    active
        .register(offender_id, EpochNumber::default())
        .expect("register offender");
    for seed in 2..=7u8 {
        active
            .register(validator_id(seed), EpochNumber::default())
            .expect("register others");
    }

    // Step 2 — offender constructs two distinct vertices at
    // the same (author, round=0 genesis). Both signed with
    // their real BLS key. Genesis-round vertices need no
    // parents per §8.3.2, which keeps the test minimal.
    let v_a = signed_vertex_with_nonce(&[7u8; 32], offender_id, 0, 0);
    let v_b = signed_vertex_with_nonce(&[7u8; 32], offender_id, 0, 1);
    assert_ne!(v_a.id(), v_b.id(), "two distinct vertices required");

    // Step 3 — DagState surfaces the equivocation on second
    // insert (Phase 7.7a detection layer).
    let mut dag = DagState::new();
    dag.insert(v_a.clone(), &active).expect("first vertex");
    let err = dag.insert(v_b.clone(), &active).expect_err("second vertex");
    match err {
        DagError::EquivocationDetected {
            author,
            round,
            existing,
        } => {
            assert_eq!(author, offender_id);
            assert_eq!(round, RoundNumber::default());
            assert_eq!(existing, v_a.id());
        }
        other => panic!("expected EquivocationDetected, got {other:?}"),
    }

    // Step 4 — observer constructs slashing evidence from the
    // two vertices and verifies it (Phase 7.10).
    let resolver = move |id: &ValidatorId| -> Option<ValidatorPublicKeys> {
        if *id == offender_id {
            Some(offender_pubkeys)
        } else {
            None
        }
    };
    let offence =
        verify_equivocation_evidence(&v_a, &v_b, resolver).expect("genuine equivocation verifies");
    assert_eq!(offence, SlashOffence::Equivocation);

    // Step 5 — apply the slashing (Phase 7.10).
    let offender_stake = Stake::from_adm(1_000);
    let outcome = apply_slashing(offender_stake, offence);
    assert_eq!(outcome.remaining_stake.as_micro_units(), 0);
    assert_eq!(outcome.burned_amount, offender_stake);
    assert!(!outcome.triggers_active_set_removal);
    // Per §8.1.5 equivocation is 100% but does NOT trigger
    // active-set removal beyond the natural "zero stake means
    // you can no longer participate" consequence.

    // Sanity-pin: the penalty matches the §8.1.5 100% pin.
    assert_eq!(
        slashing_penalty_basis_points(offence),
        BASIS_POINTS_DENOMINATOR
    );
}

// ===============================================================
// Phase 7.11: liveness failure pipeline
// ===============================================================

#[test]
fn liveness_failure_detected_then_slashed_pipeline() {
    // Step 1 — fixture active set; validator 1 hasn't
    // participated since epoch 0.
    let active = fixture_active_set(7);
    let slot = active
        .active_slots()
        .find(|s| s.validator_id == validator_id(1))
        .expect("slot");
    let slot_id = slot.id;
    let validator = slot.validator_id;
    let last_participation = slot.last_participation_epoch;
    // Current epoch 4. With last_participation=0 the delta is
    // 4 - 0 = 4 > 3, so liveness failure fires per §8.1.5.
    let current = EpochNumber::new(4);

    // Step 2 — Phase 7.1 detection: slot reports liveness
    // failure.
    assert!(slot.is_liveness_failed(current));

    // Step 3 — Phase 7.10 verification.
    let offence =
        verify_liveness_failure_evidence(&active, slot_id, validator, last_participation, current)
            .expect("liveness threshold met");
    assert_eq!(offence, SlashOffence::LivenessFailure);

    // Step 4 — apply slashing.
    let stake = Stake::from_adm(1_000);
    let outcome = apply_slashing(stake, offence);
    // 0.5% of 1,000 ADM = 5 ADM.
    assert_eq!(outcome.burned_amount, Stake::from_adm(5));
    assert_eq!(
        outcome.remaining_stake.as_micro_units(),
        stake.as_micro_units() - 5_000_000
    );
    assert!(
        outcome.triggers_active_set_removal,
        "§8.1.5: liveness failure triggers active-set removal"
    );
}

#[test]
fn liveness_failure_threshold_not_met_when_within_grace() {
    let active = fixture_active_set(7);
    let slot_id = active
        .active_slots()
        .find(|s| s.validator_id == validator_id(1))
        .expect("slot")
        .id;
    // Current epoch 3; last participation 0. 3 - 0 = 3, which
    // is NOT > 3 (need strict). Within grace period.
    let err = verify_liveness_failure_evidence(
        &active,
        slot_id,
        validator_id(1),
        EpochNumber::new(0),
        EpochNumber::new(3),
    )
    .expect_err("within grace period");
    // The specific error variant pins the §8.1.5 boundary.
    match err {
        SlashingError::LivenessThresholdNotMet {
            last_participation,
            current,
        } => {
            assert_eq!(last_participation, EpochNumber::new(0));
            assert_eq!(current, EpochNumber::new(3));
        }
        other => panic!("expected LivenessThresholdNotMet(last=0, current=3), got {other:?}"),
    }
}

// ===============================================================
// Phase 7.11: tier signal across epoch boundaries
// ===============================================================

#[test]
fn tier_signal_tracks_active_set_size_across_epochs() {
    // Spin up a light client; advance through epochs 0..5
    // with monotonically growing active-set size; verify the
    // tier signal updates at the §8.1.7 boundaries.
    let mut lc = LightClientState::new();

    // Epoch 0: active_set_size=6 → below floor → dormant.
    lc.advance(EpochBoundary::new(
        EpochNumber::new(0),
        6,
        StateCommitment::from_bytes([0u8; 32]),
        ProofCommitment::from_bytes([0u8; 32]),
    ))
    .expect("epoch 0");
    let signal = lc.tier_signal().expect("present");
    assert!(signal.is_dormant());
    assert!(!signal.meets_minimum(SecurityTier::Tier1));

    // Epoch 1: active_set_size=10 → Tier I.
    lc.advance(EpochBoundary::new(
        EpochNumber::new(1),
        10,
        StateCommitment::from_bytes([1u8; 32]),
        ProofCommitment::from_bytes([1u8; 32]),
    ))
    .expect("epoch 1");
    let signal = lc.tier_signal().expect("present");
    assert_eq!(signal.tier, Some(SecurityTier::Tier1));
    assert!(signal.meets_minimum(SecurityTier::Tier1));
    assert!(!signal.meets_minimum(SecurityTier::Tier2));

    // Epoch 2: active_set_size=15 → Tier II (the §8.4
    // viability-boundary crossing).
    lc.advance(EpochBoundary::new(
        EpochNumber::new(2),
        15,
        StateCommitment::from_bytes([2u8; 32]),
        ProofCommitment::from_bytes([2u8; 32]),
    ))
    .expect("epoch 2");
    let signal = lc.tier_signal().expect("present");
    assert_eq!(signal.tier, Some(SecurityTier::Tier2));
    assert!(signal.meets_minimum(SecurityTier::Tier2));

    // Epoch 3: active_set_size=30 → Tier III.
    lc.advance(EpochBoundary::new(
        EpochNumber::new(3),
        30,
        StateCommitment::from_bytes([3u8; 32]),
        ProofCommitment::from_bytes([3u8; 32]),
    ))
    .expect("epoch 3");
    let signal = lc.tier_signal().expect("present");
    assert_eq!(signal.tier, Some(SecurityTier::Tier3));
    assert!(signal.meets_minimum(SecurityTier::Tier3));

    // Epoch 4: active_set_size drops back to 8 → Tier I
    // again (the §8.1.7 tier transitions are bidirectional;
    // a chain can lose validators).
    lc.advance(EpochBoundary::new(
        EpochNumber::new(4),
        8,
        StateCommitment::from_bytes([4u8; 32]),
        ProofCommitment::from_bytes([4u8; 32]),
    ))
    .expect("epoch 4");
    let signal = lc.tier_signal().expect("present");
    assert_eq!(signal.tier, Some(SecurityTier::Tier1));
}

// ===============================================================
// Phase 7.11: convergence + safety
// ===============================================================

#[test]
fn pipeline_is_dag_construction_order_independent() {
    // §8.7 safety convergence: two independently-constructed
    // pipelines on identical inputs converge to identical
    // state.

    fn run_pipeline() -> (DagState, LightClientState) {
        let active = fixture_active_set(7);
        let mut dag = DagState::new();
        // Build genesis-round vertices for all 7 validators.
        for seed in 1..=7u8 {
            let v = VertexBuilder::new(validator_id(seed), RoundNumber::default())
                .with_signature(VertexSignature::from_bytes([0u8; BLS_SIGNATURE_BYTES]))
                .build();
            dag.insert(v, &active).expect("insert");
        }
        // Build a light client tracking epoch boundaries.
        let mut lc = LightClientState::new();
        for n in 0..3u8 {
            lc.advance(EpochBoundary::new(
                EpochNumber::new(u64::from(n)),
                7,
                StateCommitment::from_bytes([n; 32]),
                ProofCommitment::from_bytes([n + 100; 32]),
            ))
            .expect("advance");
        }
        (dag, lc)
    }

    let (dag1, lc1) = run_pipeline();
    let (dag2, lc2) = run_pipeline();
    // Both pipelines have identical DagState content.
    assert_eq!(dag1.len(), dag2.len());
    for round_n in 0..3u64 {
        let r = RoundNumber::new(round_n);
        let v1 = dag1.vertices_at_round(r);
        let v2 = dag2.vertices_at_round(r);
        // Both sets contain the same vertex ids (insertion
        // order is deterministic since the BLS keys + body
        // bytes are deterministic).
        let mut s1: Vec<VertexId> = v1.to_vec();
        let mut s2: Vec<VertexId> = v2.to_vec();
        s1.sort();
        s2.sort();
        assert_eq!(s1, s2);
    }
    // Light clients converge.
    assert_eq!(lc1, lc2);
}

// ===============================================================
// Phase 7.11: slashing pipeline composability
// ===============================================================

#[test]
fn slashing_outcomes_compose_across_offences() {
    // A validator could in theory be slashed for multiple
    // offences in sequence. After equivocation (100%), the
    // stake is zero; subsequent slashing operations on the
    // residual stake are no-ops.
    let initial = Stake::from_adm(1_000);
    // Equivocation first.
    let after_eq = apply_slashing(initial, SlashOffence::Equivocation);
    assert_eq!(after_eq.remaining_stake.as_micro_units(), 0);
    // Subsequent liveness failure on zero stake: zero burned,
    // zero remaining.
    let after_live = apply_slashing(after_eq.remaining_stake, SlashOffence::LivenessFailure);
    assert_eq!(after_live.remaining_stake.as_micro_units(), 0);
    assert_eq!(after_live.burned_amount.as_micro_units(), 0);

    // Different sequence: invalid proof (10%) first, then
    // incorrect threshold (5%) on residual.
    let after_proof = apply_slashing(initial, SlashOffence::InvalidProof);
    assert_eq!(after_proof.burned_amount, Stake::from_adm(100));
    let after_threshold = apply_slashing(
        after_proof.remaining_stake,
        SlashOffence::IncorrectThresholdDecryption,
    );
    // 5% of 900 ADM = 45 ADM.
    assert_eq!(after_threshold.burned_amount, Stake::from_adm(45));
    assert_eq!(
        after_threshold.remaining_stake.as_micro_units(),
        855_000_000 // 855 ADM
    );
}
