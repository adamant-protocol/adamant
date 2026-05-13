//! Adamant networking layer per whitepaper §9.
//!
//! Phase 7.8 deliverable. The networking layer carries the
//! protocol's peer-to-peer messages: vertex propagation
//! (§8.3 DAG-BFT), transaction submission (§9.3, threshold-
//! encrypted or transparent), threshold-decryption-share
//! propagation (§8.4.3), and time-lock-decryption publication
//! (§8.4.4). Per the spec, libp2p is the substrate (§9.2);
//! Adamant pins the QUIC + Noise + Yamux + Kademlia + gossipsub
//! configuration (§9.2.2).
//!
//! # Sub-arc map
//!
//! | Sub-arc | Whitepaper | Surface |
//! |---------|------------|---------|
//! | 7.8.0   | §9.3.1 | wire-format types (THIS SUB-ARC) |
//! | 7.8.1   | §9.2, §9.3 | libp2p integration + gossipsub propagation |
//! | 7.8.2   | §9.5 | anti-DoS + submission proofs + fee floors |
//! | 7.8.3   | §9.6 | discovery + bootstrap nodes |
//! | 7.8.4   | §9.7 | mempool design + synchronisation |
//!
//! # Phase 7.8.0 scope
//!
//! Phase 7.8.0 ships the **networking-substrate-agnostic wire-
//! format foundation** — the types that flow over the libp2p
//! gossipsub topics once Phase 7.8.1 lands. Mirrors the wire-
//! foundation pattern at Phase 7.5.0 (time-lock VDF), Phase 7.3
//! (DAG vertex), and Phase 7.6 (mempool envelopes): pin the
//! consensus-binding wire shapes first; layer the actual
//! transport on top in a follow-on sub-arc.
//!
//! - [`NetworkTransaction`] — the §9.3.1 wire shape for
//!   transaction submission. `version` + `encryption_mode` +
//!   `payload` + `fee_tip` + `expiration_round` +
//!   `submission_proof`.
//! - [`EncryptionMode`] — closed enum (`Transparent = 0x00`,
//!   `Encrypted = 0x01`) per §9.3.1.
//! - [`SubmissionProof`] — opaque-bytes wrapper for the
//!   §9.5.1 anti-DoS submission-proof payload. The inner
//!   structure pins at Phase 7.8.2.
//! - [`GossipsubTopic`] — closed enum identifying which
//!   gossipsub topic a message belongs to. Two topics at
//!   Phase 7.8.0: `Vertices` and `Mempool`. Additional topics
//!   (e.g., a dedicated share-propagation topic) may land at
//!   Phase 7.8.1+ as the spec details solidify.
//! - [`NetworkMessage`] — wire envelope enum dispatching
//!   between vertex propagation (`Vertex` from
//!   `adamant-consensus`) and transaction propagation
//!   (`NetworkTransaction`).
//! - [`NETWORK_PROTOCOL_VERSION`] — the network protocol's
//!   wire version, distinct from per-transaction versions.
//!
//! # Posture per CLAUDE.md §14.4 Decision 4 (RESOLVED)
//!
//! libp2p is admitted to Category E networking-infrastructure
//! tier per the §9.2.1 Principle-VI invocation. The
//! `adamant-network` crate is the production-side wrapper
//! around libp2p's API; libp2p is not forked. Network-layer
//! correctness is delivery, not state-transition correctness,
//! so the resistant-proof rationale driving the Halo 2 +
//! Sui-Move forks does not apply with the same force here —
//! two nodes running different libp2p versions still agree on
//! the chain because consensus is BLS-signed and the DAG is
//! content-addressed.
//!
//! Phase 7.8.0 does NOT yet pull in libp2p as a runtime dep —
//! the wire-format types are pure-Rust serde structures
//! consumable by any transport. The libp2p dep pins at Phase
//! 7.8.1 with the §9.2.2 feature gates.

#![forbid(unsafe_code)]
#![allow(
    clippy::multiple_crate_versions,
    reason = "libp2p's transitive dep tree contains multiple-\
              version duplicates for several common Rust \
              ecosystem crates (hashlink, socket2, thiserror, \
              unsigned-varint, yamux). These are entirely \
              inside libp2p's networking-infrastructure \
              subtree, none touch Adamant's cryptographic or \
              consensus surface, and resolving them would \
              require forking specific libp2p sub-crates \
              (rejected per §14.4 Decision 4 Option A). Scope \
              this allow narrowly to the networking crate; the \
              workspace-wide multiple_crate_versions = \"warn\" \
              discipline remains in force everywhere else."
)]

use serde::{Deserialize, Serialize};

use adamant_consensus::{RoundNumber, Vertex};

pub mod anti_dos;
pub mod mempool;
pub mod node;

pub use anti_dos::{
    compute_submission_proof, duration_to_micros, validate_submission, AntiDosError, FeeFloor,
    RateLimitConfig, RateLimitDecision, RateLimiter, MAX_DIFFICULTY_BITS,
};
pub use mempool::{InsertOutcome, Mempool, MempoolError, DEFAULT_MEMPOOL_CAPACITY};
pub use node::{AdamantBehaviour, NetworkConfig, NetworkError, NetworkEvent, NetworkNode};

/// Re-exports of the libp2p types Adamant consumers most
/// commonly need at the boundary (peer ids, multiaddrs,
/// keypair). Consumers MAY import these via
/// `adamant_network::libp2p::*` to avoid pulling libp2p as a
/// direct dep.
pub mod libp2p_re {
    pub use libp2p::identity::Keypair;
    pub use libp2p::{Multiaddr, PeerId};
}

/// Adamant network protocol version. Distinct from a
/// transaction's per-version field (the
/// [`NetworkTransaction::version`] byte): this is the wire-
/// envelope version that governs the [`NetworkMessage`] /
/// [`GossipsubTopic`] surface itself, not the transaction
/// format.
///
/// Consensus-binding — a node running protocol version `N`
/// cannot decode messages tagged at version `M ≠ N`, so a
/// bump here is a hard-fork-aware deliberate change. Mirrors
/// the consensus-binding constant discipline in
/// `adamant-consensus`.
pub const NETWORK_PROTOCOL_VERSION: u8 = 1;

/// Transaction encryption mode per whitepaper §9.3.1.
///
/// Pinned BCS variant tags — reordering is a hard-fork-aware
/// deliberate change.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum EncryptionMode {
    /// Transparent transaction: `payload` is the BCS-encoded
    /// AVM `Transaction` directly. No §8.4 mempool-encryption
    /// protection; the transaction's contents are visible to
    /// every node during ordering. Forfeits MEV protection per
    /// §8.4.5.
    Transparent = 0x00,

    /// Encrypted transaction: `payload` is a BCS-encoded
    /// `adamant_consensus::MempoolEnvelope` (`TimeLock` or
    /// `Threshold` regime per §8.4.2 hysteresis). The encrypted
    /// transaction decrypts at the §8.3.3 step-4 commit-wave
    /// boundary via Phase 7.7d's `decrypt_time_lock` /
    /// `ThresholdShareAccumulator` flows.
    Encrypted = 0x01,
}

/// Anti-DoS submission proof per whitepaper §9.5.1.
///
/// Hashcash-style proof-of-work: the submitter grinds nonces
/// until the SHA3-256 tagged hash of
/// `BCS(tx with submission_proof=None) || nonce_le_bytes`
/// (tagged under [`adamant_crypto::domain::SUBMISSION_PROOF`])
/// has at least `difficulty_bits` leading zero bits.
///
/// Per §9.5.1 the target difficulty is calibrated to a 50-
/// 100ms grind on consumer hardware — barely noticeable for
/// honest users, materially expensive for spam-flooders.
/// Difficulty is per-node dynamic; heavily-loaded receivers
/// raise their minimum-accepted threshold without protocol-
/// level coordination.
///
/// See [`crate::anti_dos::SubmissionProofExt`] for the
/// verify + compute API.
///
/// # Wire layout
///
/// BCS-canonical: `nonce: u64` (8 bytes LE) + `difficulty_bits:
/// u8` (1 byte) = 9 bytes flat. Field order is consensus-
/// binding; reordering is a hard-fork-aware deliberate change.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct SubmissionProof {
    /// Nonce the submitter found via grinding. Combined with
    /// the transaction body (minus this proof field) via
    /// [`adamant_crypto::domain::SUBMISSION_PROOF`] and
    /// SHA3-256-tagged into the `PoW` hash.
    pub nonce: u64,

    /// Target difficulty (leading-zero-bit count of the hash)
    /// the submitter claims to have met. Receivers verify the
    /// hash actually meets this difficulty AND accept the
    /// proof only if `difficulty_bits >= receiver's minimum
    /// threshold`.
    pub difficulty_bits: u8,
}

impl SubmissionProof {
    /// Construct a submission proof from raw nonce + difficulty
    /// fields. The receiver must call
    /// [`crate::anti_dos::verify_submission_proof`] to confirm
    /// the proof actually meets its claimed difficulty.
    #[must_use]
    pub const fn new(nonce: u64, difficulty_bits: u8) -> Self {
        Self {
            nonce,
            difficulty_bits,
        }
    }
}

/// Wire-shaped transaction submission per whitepaper §9.3.1.
///
/// This is the message a wallet constructs and pushes onto the
/// `Mempool` gossipsub topic. Validators receive it,
/// optionally decrypt (per the §8.4 regime), and include the
/// resulting transaction in a future vertex per the §8.3.1
/// vertex production flow.
///
/// # BCS-canonical encoding
///
/// Field order is consensus-binding. Reordering or
/// re-typing is a hard-fork-aware deliberate change. The
/// `submission_proof` is `Option`-wrapped because anti-DoS is
/// an additive layer the protocol may enable / disable at
/// fee-policy granularity (per §9.5; final shape pinned at
/// Phase 7.8.2).
#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct NetworkTransaction {
    /// Transaction-format version. Distinct from
    /// [`NETWORK_PROTOCOL_VERSION`] (the network-envelope
    /// version): this is the per-transaction format version
    /// the §6 execution layer reads.
    pub version: u8,

    /// Encryption regime per §9.3.1.
    pub encryption_mode: EncryptionMode,

    /// The transaction payload. Shape depends on
    /// `encryption_mode`:
    /// [`EncryptionMode::Transparent`] carries a BCS-encoded
    /// AVM `Transaction` directly; [`EncryptionMode::Encrypted`]
    /// carries a BCS-encoded
    /// [`adamant_consensus::MempoolEnvelope`].
    pub payload: Vec<u8>,

    /// ADM micro-units the submitter is willing to pay above
    /// the §10 base fee. Higher tips signal higher inclusion
    /// priority per §9.7 mempool ranking.
    pub fee_tip: u64,

    /// Round after which the transaction is no longer valid.
    /// Past this round, mempool implementations drop the
    /// transaction per §9.7's TTL behaviour.
    pub expiration_round: RoundNumber,

    /// Optional anti-DoS submission proof per §9.5.1.
    /// Required when the chain's per-peer rate limiter
    /// signals saturation; optional otherwise. Phase 7.8.2
    /// pins the exact policy.
    pub submission_proof: Option<SubmissionProof>,
}

impl NetworkTransaction {
    /// Construct a transparent (unencrypted) transaction
    /// submission. The payload must be a BCS-encoded AVM
    /// `Transaction` — callers that pass arbitrary bytes
    /// will see decode failures downstream at the execution
    /// layer.
    #[must_use]
    pub const fn transparent(
        version: u8,
        payload: Vec<u8>,
        fee_tip: u64,
        expiration_round: RoundNumber,
    ) -> Self {
        Self {
            version,
            encryption_mode: EncryptionMode::Transparent,
            payload,
            fee_tip,
            expiration_round,
            submission_proof: None,
        }
    }

    /// Construct an encrypted transaction submission. The
    /// payload must be a BCS-encoded
    /// [`adamant_consensus::MempoolEnvelope`].
    #[must_use]
    pub const fn encrypted(
        version: u8,
        envelope_bytes: Vec<u8>,
        fee_tip: u64,
        expiration_round: RoundNumber,
    ) -> Self {
        Self {
            version,
            encryption_mode: EncryptionMode::Encrypted,
            payload: envelope_bytes,
            fee_tip,
            expiration_round,
            submission_proof: None,
        }
    }

    /// Attach a §9.5.1 anti-DoS submission proof. Returns a
    /// new value with the proof set; the original is
    /// consumed.
    #[must_use]
    pub fn with_submission_proof(mut self, proof: SubmissionProof) -> Self {
        self.submission_proof = Some(proof);
        self
    }
}

/// Gossipsub topic identifier per whitepaper §9.2.2.
///
/// Two topics at Phase 7.8.0:
/// - [`GossipsubTopic::Vertices`] — vertex propagation
///   (§8.3.1 vertices flow here from proposers to the rest
///   of the active set).
/// - [`GossipsubTopic::Mempool`] — transaction submission
///   (§9.3 wallets push [`NetworkTransaction`]s here for
///   validator pickup).
///
/// Additional topics (dedicated share-propagation channel,
/// peer-info gossip, block-sync) may land at Phase 7.8.1+ as
/// the spec details solidify. The closed-enum shape is
/// consensus-binding; adding a variant is a hard-fork-aware
/// deliberate change.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum GossipsubTopic {
    /// `Vertex` propagation per §8.3.1. Subscribers: every
    /// active-set validator + every observer node.
    Vertices = 0x00,

    /// [`NetworkTransaction`] propagation per §9.3.
    /// Subscribers: every active-set validator. Submitters:
    /// wallets + service nodes.
    Mempool = 0x01,
}

impl GossipsubTopic {
    /// Canonical libp2p gossipsub topic string. The
    /// `ADAMANT/v1/` prefix matches [`NETWORK_PROTOCOL_VERSION`]
    /// and is what subscribers register with the libp2p
    /// `gossipsub` behaviour at Phase 7.8.1.
    ///
    /// Two topics' strings are pinned now to lock the wire-
    /// observable topic-name discipline before Phase 7.8.1
    /// integration; changing them would require a hard fork.
    #[must_use]
    pub const fn topic_name(self) -> &'static str {
        match self {
            Self::Vertices => "ADAMANT/v1/vertices",
            Self::Mempool => "ADAMANT/v1/mempool",
        }
    }
}

/// Network message wire envelope.
///
/// Dispatches between the two §9.2.2 gossipsub topics: vertex
/// propagation (carrying a Phase 7.3 [`Vertex`]) and
/// transaction submission (carrying a [`NetworkTransaction`]).
///
/// Wire layout: BCS-encoded `NetworkMessage` enum. The variant
/// tag (1 byte) names the topic; the body is the
/// topic-appropriate payload. Pinned BCS variant tags — adding
/// a variant is a hard-fork-aware deliberate change.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum NetworkMessage {
    /// Vertex propagation per §8.3.1. Carried on the
    /// [`GossipsubTopic::Vertices`] topic.
    Vertex(Vertex),

    /// Transaction submission per §9.3.1. Carried on the
    /// [`GossipsubTopic::Mempool`] topic.
    Transaction(NetworkTransaction),
}

impl NetworkMessage {
    /// The gossipsub topic this message belongs on. Caller-side
    /// helper for routing messages to the correct topic at
    /// publish time.
    #[must_use]
    pub const fn topic(&self) -> GossipsubTopic {
        match self {
            Self::Vertex(_) => GossipsubTopic::Vertices,
            Self::Transaction(_) => GossipsubTopic::Mempool,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use adamant_consensus::{ValidatorId, ValidatorPublicKeys};
    use adamant_consensus::{VertexBuilder, VertexSignature, BLS_SIGNATURE_BYTES};

    fn fixture_validator_id() -> ValidatorId {
        ValidatorPublicKeys::new([1u8; 32], [1u8; 1952], [1u8; 96], [1u8; 48]).derive_id()
    }

    fn fixture_vertex() -> Vertex {
        VertexBuilder::new(fixture_validator_id(), RoundNumber::default())
            .with_signature(VertexSignature::from_bytes([0u8; BLS_SIGNATURE_BYTES]))
            .build()
    }

    // ---- Constants ----

    #[test]
    fn protocol_version_pinned_at_one() {
        assert_eq!(NETWORK_PROTOCOL_VERSION, 1);
    }

    // ---- EncryptionMode ----

    #[test]
    fn encryption_mode_variant_tags_pinned() {
        let transparent = bcs::to_bytes(&EncryptionMode::Transparent).expect("encode");
        let encrypted = bcs::to_bytes(&EncryptionMode::Encrypted).expect("encode");
        assert_eq!(transparent, vec![0x00]);
        assert_eq!(encrypted, vec![0x01]);
    }

    #[test]
    fn encryption_mode_bcs_round_trip() {
        for mode in [EncryptionMode::Transparent, EncryptionMode::Encrypted] {
            let bytes = bcs::to_bytes(&mode).expect("encode");
            let decoded: EncryptionMode = bcs::from_bytes(&bytes).expect("decode");
            assert_eq!(mode, decoded);
        }
    }

    // ---- SubmissionProof ----

    #[test]
    fn submission_proof_new_sets_fields() {
        let p = SubmissionProof::new(0xDEAD_BEEFu64, 16);
        assert_eq!(p.nonce, 0xDEAD_BEEFu64);
        assert_eq!(p.difficulty_bits, 16);
    }

    #[test]
    fn submission_proof_bcs_round_trip() {
        let p = SubmissionProof::new(0x1234_5678_9ABC_DEF0, 20);
        let bytes = bcs::to_bytes(&p).expect("encode");
        let decoded: SubmissionProof = bcs::from_bytes(&bytes).expect("decode");
        assert_eq!(p, decoded);
    }

    #[test]
    fn submission_proof_bcs_layout_pin() {
        // BCS encoding: nonce (u64 LE, 8 bytes) +
        // difficulty_bits (u8, 1 byte) = 9 bytes flat.
        // Consensus-binding; field order changes are hard
        // forks.
        let p = SubmissionProof::new(1u64, 0x10);
        let bytes = bcs::to_bytes(&p).expect("encode");
        assert_eq!(bytes.len(), 9);
        assert_eq!(bytes[0], 1); // nonce LSB
        for b in &bytes[1..8] {
            assert_eq!(*b, 0); // remainder of nonce LE
        }
        assert_eq!(bytes[8], 0x10); // difficulty_bits
    }

    // ---- NetworkTransaction ----

    #[test]
    fn network_transaction_transparent_constructor() {
        let tx = NetworkTransaction::transparent(
            1,
            vec![0xDE, 0xAD, 0xBE, 0xEF],
            100,
            RoundNumber::new(42),
        );
        assert_eq!(tx.version, 1);
        assert_eq!(tx.encryption_mode, EncryptionMode::Transparent);
        assert_eq!(tx.payload, vec![0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(tx.fee_tip, 100);
        assert_eq!(tx.expiration_round, RoundNumber::new(42));
        assert!(tx.submission_proof.is_none());
    }

    #[test]
    fn network_transaction_encrypted_constructor() {
        let tx = NetworkTransaction::encrypted(1, vec![0xCAu8; 96], 50, RoundNumber::new(100));
        assert_eq!(tx.encryption_mode, EncryptionMode::Encrypted);
        assert_eq!(tx.payload.len(), 96);
    }

    #[test]
    fn network_transaction_with_submission_proof() {
        let proof = SubmissionProof::new(42, 16);
        let tx = NetworkTransaction::transparent(1, vec![1, 2], 0, RoundNumber::new(10))
            .with_submission_proof(proof);
        assert_eq!(tx.submission_proof, Some(proof));
    }

    #[test]
    fn network_transaction_bcs_round_trip() {
        let tx =
            NetworkTransaction::transparent(1, vec![0x01, 0x02, 0x03], 999, RoundNumber::new(1234))
                .with_submission_proof(SubmissionProof::new(0xAA_AA_AA_AAu64, 12));
        let bytes = bcs::to_bytes(&tx).expect("encode");
        let decoded: NetworkTransaction = bcs::from_bytes(&bytes).expect("decode");
        assert_eq!(tx, decoded);
    }

    #[test]
    fn network_transaction_field_order_pin() {
        // BCS encodes fields in declaration order. This test
        // pins the canonical order: version | encryption_mode |
        // payload | fee_tip | expiration_round |
        // submission_proof. A reordering would surface as a
        // failing test before it became a consensus-breaking
        // wire change.
        let tx = NetworkTransaction::transparent(0xAB, vec![0xCD], 0, RoundNumber::new(0));
        let bytes = bcs::to_bytes(&tx).expect("encode");
        // version (1) + encryption_mode (1) + payload-len-prefix (1) +
        // payload (1) + fee_tip (8 LE) + expiration_round (8 LE) +
        // option-tag (1) = 21 bytes.
        assert_eq!(bytes.len(), 21);
        assert_eq!(bytes[0], 0xAB); // version
        assert_eq!(bytes[1], 0x00); // EncryptionMode::Transparent
        assert_eq!(bytes[2], 1); // ULEB128 length-prefix for payload
        assert_eq!(bytes[3], 0xCD); // payload byte
                                    // fee_tip (8 zero bytes) + expiration_round (8 zero bytes)
        for b in &bytes[4..20] {
            assert_eq!(*b, 0);
        }
        // Option None tag at the tail.
        assert_eq!(bytes[20], 0x00);
    }

    // ---- GossipsubTopic ----

    #[test]
    fn gossipsub_topic_variant_tags_pinned() {
        let v = bcs::to_bytes(&GossipsubTopic::Vertices).expect("encode");
        let m = bcs::to_bytes(&GossipsubTopic::Mempool).expect("encode");
        assert_eq!(v, vec![0x00]);
        assert_eq!(m, vec![0x01]);
    }

    #[test]
    fn gossipsub_topic_names_pinned() {
        assert_eq!(GossipsubTopic::Vertices.topic_name(), "ADAMANT/v1/vertices");
        assert_eq!(GossipsubTopic::Mempool.topic_name(), "ADAMANT/v1/mempool");
    }

    #[test]
    fn gossipsub_topic_names_are_distinct() {
        assert_ne!(
            GossipsubTopic::Vertices.topic_name(),
            GossipsubTopic::Mempool.topic_name()
        );
    }

    #[test]
    fn gossipsub_topic_bcs_round_trip() {
        for topic in [GossipsubTopic::Vertices, GossipsubTopic::Mempool] {
            let bytes = bcs::to_bytes(&topic).expect("encode");
            let decoded: GossipsubTopic = bcs::from_bytes(&bytes).expect("decode");
            assert_eq!(topic, decoded);
        }
    }

    // ---- NetworkMessage ----

    #[test]
    fn network_message_topic_dispatch() {
        let v_msg = NetworkMessage::Vertex(fixture_vertex());
        assert_eq!(v_msg.topic(), GossipsubTopic::Vertices);
        let tx_msg = NetworkMessage::Transaction(NetworkTransaction::transparent(
            1,
            vec![],
            0,
            RoundNumber::default(),
        ));
        assert_eq!(tx_msg.topic(), GossipsubTopic::Mempool);
    }

    #[test]
    fn network_message_bcs_round_trip_vertex() {
        let msg = NetworkMessage::Vertex(fixture_vertex());
        let bytes = bcs::to_bytes(&msg).expect("encode");
        let decoded: NetworkMessage = bcs::from_bytes(&bytes).expect("decode");
        assert_eq!(msg, decoded);
    }

    #[test]
    fn network_message_bcs_round_trip_transaction() {
        let msg = NetworkMessage::Transaction(NetworkTransaction::encrypted(
            1,
            vec![0xCA, 0xFE, 0xBA, 0xBE],
            42,
            RoundNumber::new(123),
        ));
        let bytes = bcs::to_bytes(&msg).expect("encode");
        let decoded: NetworkMessage = bcs::from_bytes(&bytes).expect("decode");
        assert_eq!(msg, decoded);
    }

    #[test]
    fn network_message_variant_tags_pinned() {
        // Vertex variant = 0x00 (first in declaration order).
        // Transaction variant = 0x01.
        let v_msg = NetworkMessage::Vertex(fixture_vertex());
        let v_bytes = bcs::to_bytes(&v_msg).expect("encode");
        assert_eq!(v_bytes[0], 0x00, "Vertex variant tag is 0x00");
        let tx_msg = NetworkMessage::Transaction(NetworkTransaction::transparent(
            1,
            vec![],
            0,
            RoundNumber::default(),
        ));
        let tx_bytes = bcs::to_bytes(&tx_msg).expect("encode");
        assert_eq!(tx_bytes[0], 0x01, "Transaction variant tag is 0x01");
    }

    #[test]
    fn distinct_messages_have_distinct_bcs_encodings() {
        let a = NetworkMessage::Transaction(NetworkTransaction::transparent(
            1,
            vec![1, 2, 3],
            10,
            RoundNumber::new(5),
        ));
        let b = NetworkMessage::Transaction(NetworkTransaction::transparent(
            1,
            vec![4, 5, 6],
            10,
            RoundNumber::new(5),
        ));
        assert_ne!(
            bcs::to_bytes(&a).expect("encode"),
            bcs::to_bytes(&b).expect("encode")
        );
    }
}
