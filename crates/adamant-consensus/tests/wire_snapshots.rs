#![allow(
    clippy::doc_markdown,
    clippy::wildcard_imports,
    reason = "Test file: doc comments embed BCS/wire shorthand and \
              wildcards keep the fixture surface concise."
)]

//! Snapshot tests pinning the BCS wire-format byte layout of
//! consensus-binding types per whitepaper §5.1.8 + §8.3.1.
//!
//! Each consensus-observable type's BCS encoding under a
//! fixture input is captured as a hex string and pinned via
//! `insta::assert_snapshot!`. Any drift in field order,
//! variant tag, BCS canonicality, or struct shape surfaces as
//! a snapshot mismatch — auditors review the diff before
//! accepting (or reject as a consensus-breaking change).
//!
//! These complement the existing manual byte-layout pins in
//! per-type unit tests (e.g., `vertex_id_bcs_round_trip`,
//! `network_transaction_field_order_pin`) by giving us a
//! file-level visual diff anchor for byte sequences that would
//! otherwise be opaque assertion values.
//!
//! # Updating snapshots
//!
//! Snapshot changes are consensus-binding by construction. To
//! intentionally update a snapshot:
//!
//! 1. Confirm the wire-format change is intentional and
//!    spec-author-ratified.
//! 2. Run `INSTA_UPDATE=always cargo test --test wire_snapshots`
//!    to regenerate the snapshot file.
//! 3. Review the diff in `tests/snapshots/`.
//! 4. Commit both the code change and the snapshot update
//!    atomically; the commit message must justify the wire
//!    change.
//!
//! Per the resistant-proof posture (§13 + §14), insta is a
//! test-time-only dependency; the production binary's
//! dependency graph contains no `insta` crate.

use adamant_consensus::{
    EpochBoundary, EpochNumber, MempoolEnvelope, ProofCommitment, RegimeState, Slot, SlotStatus,
    SlotTransfer, StateCommitment, ThresholdMempoolEnvelope, ValidatorId, ValidatorPublicKeys,
    VertexId,
};
use adamant_crypto::vdf::TimeLockEnvelope;

// ---------------------------------------------------------------
// Fixture builders
// ---------------------------------------------------------------

/// Fixed-pattern ValidatorPublicKeys for reproducible snapshots.
/// Each byte field is a single repeated value so the snapshot
/// hex is easy to inspect by eye.
fn fixture_validator_keys() -> ValidatorPublicKeys {
    ValidatorPublicKeys::new([0x11; 32], [0x22; 1952], [0x33; 96])
}

fn fixture_validator_id() -> ValidatorId {
    ValidatorId::from_bytes([0x44; 32])
}

// ---------------------------------------------------------------
// Snapshot tests
// ---------------------------------------------------------------

/// ValidatorId BCS encoding pin (32 bytes — no length prefix,
/// no variant tag).
#[test]
fn snapshot_validator_id_bcs() {
    let id = fixture_validator_id();
    let bytes = bcs::to_bytes(&id).expect("encode");
    insta::assert_snapshot!("validator_id_bcs", hex::encode(&bytes));
}

/// ValidatorPublicKeys BCS encoding pin (32 + 1952 + 96 = 2080
/// bytes). The snapshot file captures the canonical wire shape
/// across the three constituent key types.
#[test]
fn snapshot_validator_public_keys_bcs() {
    let keys = fixture_validator_keys();
    let bytes = bcs::to_bytes(&keys).expect("encode");
    insta::assert_snapshot!("validator_public_keys_bcs_len", bytes.len().to_string());
    // The full 2080-byte snapshot would be unwieldy in review;
    // hash the bytes and pin the digest for compact regression
    // anchoring while still catching any byte-level drift.
    let digest =
        adamant_crypto::hash::sha3_256_tagged(&adamant_crypto::domain::VALIDATOR_ID, &bytes);
    insta::assert_snapshot!("validator_public_keys_bcs_digest", hex::encode(digest));
}

/// VertexId BCS encoding pin (32 bytes).
#[test]
fn snapshot_vertex_id_bcs() {
    let id = VertexId::from_bytes([0x55; 32]);
    let bytes = bcs::to_bytes(&id).expect("encode");
    insta::assert_snapshot!("vertex_id_bcs", hex::encode(&bytes));
}

/// StateCommitment BCS encoding pin (32 bytes).
#[test]
fn snapshot_state_commitment_bcs() {
    let c = StateCommitment::from_bytes([0xAA; 32]);
    let bytes = bcs::to_bytes(&c).expect("encode");
    insta::assert_snapshot!("state_commitment_bcs", hex::encode(&bytes));
}

/// ProofCommitment BCS encoding pin (32 bytes).
#[test]
fn snapshot_proof_commitment_bcs() {
    let c = ProofCommitment::from_bytes([0xBB; 32]);
    let bytes = bcs::to_bytes(&c).expect("encode");
    insta::assert_snapshot!("proof_commitment_bcs", hex::encode(&bytes));
}

/// EpochBoundary BCS encoding pin. Field order: epoch || active_set_size || state || proof.
/// active_set_size is u32 (4 bytes LE) per the pre-Phase-10 portability fix.
#[test]
fn snapshot_epoch_boundary_bcs() {
    let b = EpochBoundary::new(
        EpochNumber::new(0x0807_0605_0403_0201),
        0xCAFE_BABE,
        StateCommitment::from_bytes([0xAA; 32]),
        ProofCommitment::from_bytes([0xBB; 32]),
    );
    let bytes = bcs::to_bytes(&b).expect("encode");
    insta::assert_snapshot!("epoch_boundary_bcs", hex::encode(&bytes));
}

/// Slot BCS encoding pin (51 bytes per Phase 7.1 documentation).
#[test]
fn snapshot_slot_bcs() {
    let s = Slot::new(
        adamant_consensus::SlotId::new(0x0123),
        fixture_validator_id(),
        EpochNumber::new(0x0102_0304_0506_0708),
        SlotStatus::Active,
    );
    let bytes = bcs::to_bytes(&s).expect("encode");
    insta::assert_snapshot!("slot_active_bcs", hex::encode(&bytes));
}

/// SlotTransfer BCS encoding pin (74 bytes per Phase 7.1 documentation).
#[test]
fn snapshot_slot_transfer_bcs() {
    let t = SlotTransfer {
        slot_id: adamant_consensus::SlotId::new(0xABCD),
        seller_validator_id: ValidatorId::from_bytes([0x55; 32]),
        buyer_validator_id: ValidatorId::from_bytes([0xAA; 32]),
        initiated_at_epoch: EpochNumber::new(0x1234_5678_9ABC_DEF0),
    };
    let bytes = bcs::to_bytes(&t).expect("encode");
    insta::assert_snapshot!("slot_transfer_bcs", hex::encode(&bytes));
}

/// SlotStatus variant tag pin. The Phase 7.1 spec pins
/// Active = 0x00, Standby = 0x01, Inactive = 0x02. Reordering
/// is a hard fork.
#[test]
fn snapshot_slot_status_variant_tags_bcs() {
    let active = bcs::to_bytes(&SlotStatus::Active).expect("encode");
    let standby = bcs::to_bytes(&SlotStatus::Standby).expect("encode");
    let inactive = bcs::to_bytes(&SlotStatus::Inactive).expect("encode");
    insta::assert_snapshot!("slot_status_variant_active", hex::encode(active));
    insta::assert_snapshot!("slot_status_variant_standby", hex::encode(standby));
    insta::assert_snapshot!("slot_status_variant_inactive", hex::encode(inactive));
}

/// RegimeState BCS encoding pin. The Phase 7.6 spec pins
/// Regime::TimeLock = 0x00, Regime::Threshold = 0x01.
#[test]
fn snapshot_regime_state_bcs() {
    let tl = bcs::to_bytes(&RegimeState::at_activation()).expect("encode");
    insta::assert_snapshot!("regime_state_time_lock", hex::encode(tl));
}

/// MempoolEnvelope variant-tag pin. Phase 7.6: TimeLock = 0x00,
/// Threshold = 0x01.
#[test]
fn snapshot_mempool_envelope_variant_tags_bcs() {
    let timelock_env = MempoolEnvelope::TimeLock(TimeLockEnvelope {
        puzzle: adamant_crypto::vdf::ClassGroupElement::from_bytes(vec![0xCD; 8]),
        ciphertext: vec![0xFE; 16],
        well_formedness_proof: adamant_crypto::vdf::WesolowskiProof {
            pi: adamant_crypto::vdf::ClassGroupElement::from_bytes(vec![0xAB; 8]),
        },
    });
    let threshold_env = MempoolEnvelope::Threshold(ThresholdMempoolEnvelope {
        identity: vec![0x77; 8],
        ciphertext_header: [0x88; 96],
        ciphertext: vec![0x99; 16],
    });
    insta::assert_snapshot!(
        "mempool_envelope_time_lock_prefix_4",
        hex::encode(&bcs::to_bytes(&timelock_env).expect("encode")[..4])
    );
    insta::assert_snapshot!(
        "mempool_envelope_threshold_prefix_4",
        hex::encode(&bcs::to_bytes(&threshold_env).expect("encode")[..4])
    );
}
