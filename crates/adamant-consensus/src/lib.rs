//! Adamant consensus layer per whitepaper §8.
//!
//! Phase 7 deliverable. The consensus layer is the largest single
//! workstream of the protocol implementation: validator
//! management, DAG-BFT vertex production, the consensus VRF, the
//! threshold-encrypted mempool, recursive proof submission,
//! slashing, and the §8.7 safety/liveness invariants.
//!
//! # Sub-arc map
//!
//! | Sub-arc | Whitepaper | Surface |
//! |---------|------------|---------|
//! | 7.0     | §8.1.1–8.1.9 | validator identity + types (THIS SUB-ARC) |
//! | 7.1     | §8.1.3, §8.1.5, §8.1.8 | active set + slot mgmt + slashing types |
//! | 7.2     | §8.2, §8.3.2 | epoch / round semantics |
//! | 7.3     | §8.3.1     | DAG vertex structure |
//! | 7.4     | §8.6       | consensus VRF |
//! | 7.5     | §3.8, §8.4.4 | time-lock VDF |
//! | 7.6     | §3.6, §8.4 | threshold mempool + two-regime hysteresis |
//! | 7.7     | §8.3, §8.7 | DAG-BFT consensus core |
//! | 7.8     | §9         | networking + transaction propagation |
//! | 7.9     | §8.1.7, §8.9 | light client + tier signal |
//! | 7.10    | §8.1.5, §10 | slashing wiring + economics |
//! | 7.11    | all        | end-to-end integration |
//!
//! # Phase 7.0 scope
//!
//! Phase 7.0 ships the validator-identity foundation:
//!
//! - [`ValidatorPublicKeys`] — the canonical (Ed25519, ML-DSA-65,
//!   BLS12-381) public-key bundle that defines a validator's
//!   on-chain identity per §8.1.1.
//! - [`ValidatorId`] — a 32-byte content-derived identifier per
//!   §8.1.2, computed via tagged-hash over BCS-encoded
//!   `ValidatorPublicKeys`.
//! - [`Stake`] — bonded stake amount in ADM micro-units.
//! - [`Validator`] — the on-chain validator object per §8.1.2.
//! - [`SecurityTier`] — Tier I / II / III per §8.1.7.
//! - [`GenesisCohortMarker`] — the non-transferable §8.1.9
//!   marker attached to the first 75 validator addresses.
//! - [`EpochNumber`] / [`RoundNumber`] — sequence-number newtypes
//!   per §8.2.
//! - [`SlashOffence`] / [`SlashingPenalty`] — the four §8.1.5
//!   slashing categories and their per-offence stake-fraction
//!   penalties.
//!
//! Subsequent sub-arcs build on these types: 7.1 wires the active
//! set; 7.3 carries `ValidatorId` into vertex parent-set proofs;
//! 7.4's VRF binds to `ValidatorPublicKeys.bls`; etc.
//!
//! # Adamant-native posture
//!
//! Per CLAUDE.md §14, this crate's external dependencies are
//! limited to the locked bounded ecosystem: `adamant-crypto`
//! (the §3 cryptographic-primitive layer), `adamant-types` (the
//! §4–§5 type foundation), `serde` + `bcs` (canonical
//! serialisation per §5.1.8), `serde-big-array` (large fixed-size
//! arrays). No external networking / consensus / crypto crates
//! are pulled in here; integration with `libp2p` lands in Phase
//! 7.8 via a separate dependency-vetting step.

#![forbid(unsafe_code)]
#![allow(
    clippy::doc_markdown,
    reason = "doc comments freely reference field names + spec section markers (\
             `registered_at_epoch`, `§8.1.5`, etc.) without backticks where the \
             prose context makes the identifier unambiguous"
)]

pub mod active_set;
pub mod commit_sequencer;
pub mod commit_wave;
pub mod dag;
pub mod epoch;
pub mod genesis;
pub mod identity;
pub mod mempool;
pub mod mempool_decryption;
pub mod schedule;
pub mod slashing;
pub mod slot;
pub mod tier;
pub mod validator;
pub mod vertex;
pub mod vrf;

pub use active_set::{ActiveSet, ActiveSetError, ACTIVE_SET_FLOOR, ACTIVE_SET_LAUNCH_CEILING};
pub use commit_sequencer::{
    is_chain_at_floor, is_chain_dormant, CommitSequencer, SequencerError, WaveOutcome,
};
pub use commit_wave::{
    commit_order, direct_commit_decision, elect_anchor, CommitDecision,
    DIRECT_COMMIT_DECISION_OFFSET,
};
pub use dag::{DagError, DagState};
pub use epoch::{EpochNumber, RoundNumber};
pub use genesis::{GenesisCohortMarker, GENESIS_COHORT_MARKER_BYTES, GENESIS_COHORT_SIZE};
pub use identity::{
    ValidatorId, ValidatorPublicKeys, BLS_PUBLIC_KEY_BYTES, ED25519_PUBLIC_KEY_BYTES,
    ML_DSA_PUBLIC_KEY_BYTES, VALIDATOR_ID_BYTES, VALIDATOR_PUBLIC_KEYS_BYTES,
};
pub use mempool::{
    MempoolEnvelope, Regime, RegimeState, ThresholdMempoolEnvelope, THRESHOLD_ACTIVATION_FLOOR,
    THRESHOLD_CIPHERTEXT_HEADER_BYTES, THRESHOLD_DEACTIVATION_FLOOR,
};
pub use mempool_decryption::{
    decrypt_time_lock, extract_envelopes, DecryptedTransaction, MempoolDecryptionError,
    ThresholdShareAccumulator, ValidatorDecryptionShare,
};
pub use schedule::{
    quorum_threshold, CommitWaveSchedule, EpochSchedule, WaveIndex, COMMIT_WAVE_PERIOD_ROUNDS,
    EPOCH_DURATION_TARGET_MS, QUORUM_DENOMINATOR, QUORUM_NUMERATOR, ROUNDS_PER_EPOCH,
    ROUND_DURATION_TARGET_MS,
};
pub use slashing::{slashing_penalty_basis_points, SlashOffence, BASIS_POINTS_DENOMINATOR};
pub use slot::{Slot, SlotId, SlotStatus, SlotTransfer};
pub use tier::SecurityTier;
pub use validator::{Stake, Validator, MIN_VALIDATOR_STAKE_LAUNCH};
pub use vertex::{
    DecryptionShare, PartialProofWitness, TransactionEnvelope, UnsignedVertex, Vertex,
    VertexBuilder, VertexId, VertexSignature, BLS_SIGNATURE_BYTES, VERTEX_ID_BYTES,
};
pub use vrf::{
    aggregate_public_keys, aggregate_shares, output_randomness, select_index, verify_output,
    VrfError, VrfInput, VrfOutput, VrfShare, VRF_RANDOMNESS_BYTES,
};
