//! Adamant light client library.
//!
//! Phase 9.2 deliverable — the phone-verifiable light client
//! per whitepaper §8.9. Tracks epoch boundaries via the Phase
//! 7.9 [`LightClientState`]; surfaces tier signal + state
//! commitment for consumer-side queries (wallets + explorers
//! + service nodes).
//!
//! Per §8.9: "Light clients receive the recursive proof at
//! each epoch boundary and verify it; this is sufficient to
//! know the current state commitment without trusting any
//! validator." Per Principle III: "Wallets `SHOULD` operate as
//! light clients by default, syncing only the recursive proof
//! and Merkle paths for the user's own state."
//!
//! # Phase 9.2 / 9.3 scope
//!
//! - [`LightNodeConfig`] — caller-supplied configuration:
//!   networking keypair + bootstrap peers + initial
//!   `LightClientState`.
//! - [`LightNodeRuntime`] — the running light-client process.
//!   Owns the network handle + the light-client state; surfaces
//!   advance APIs that consume new [`EpochBoundary`] artifacts.
//! - [`LightNodeError`] — typed errors across the surface.
//! - **Recursive-proof verification** at each epoch boundary
//!   (Phase 9.3 cross-layer wiring via
//!   [`LightNodeRuntime::verify_and_advance`]).
//! - **§8.9 claim verification** (Phase 9.3.1) —
//!   [`LightNodeRuntime::verify_state_membership_claim`] and
//!   [`LightNodeRuntime::verify_state_non_membership_claim`]
//!   verify an account-balance / object-existence /
//!   non-existence claim against the latest state commitment
//!   using a Phase 4 [`adamant_state::MerkleProof`].
//!
//! # What this scope does NOT yet wire
//!
//! - **`EpochBoundary` ingestion from the network** — the
//!   light node has the `LightClientState` but lacks the
//!   gossipsub-topic listener that consumes `EpochBoundary`
//!   artifacts from peers. Lands at a later sub-arc when the
//!   cross-layer ingestion driver is wired.
//! - **Concrete object-tree binding**: the Merkle-proof
//!   verification primitives operate on raw 32-byte
//!   `StateKey` + value-bytes pairs. The mapping from
//!   `ObjectId` → `StateKey` and from `Object` → value-bytes
//!   serialisation is fixed by Phase 4's tree shape; the
//!   binding between the AVM-runtime's
//!   `commit_buffer`-produced state and this tree is the
//!   pre-mainnet object-tree binding sub-arc.
//!
//! [`LightClientState`]: adamant_consensus::LightClientState
//! [`EpochBoundary`]: adamant_consensus::EpochBoundary

#![forbid(unsafe_code)]
#![allow(
    clippy::multiple_crate_versions,
    reason = "adamant-light transitively depends on libp2p via \
              adamant-network; same dup-version posture as the \
              other binary crates (adamant-node, adamant-cli)."
)]

use adamant_consensus::{
    EpochBoundary, LightClientError, LightClientState, ProofCommitment, StateCommitment, TierSignal,
};
use adamant_network::libp2p_re::{Keypair as NetworkKeypair, Multiaddr, PeerId};
use adamant_network::{NetworkConfig, NetworkError, NetworkNode};
use adamant_privacy::epoch_recursion::{verify_envelope, EpochRecursionError};
use adamant_privacy::recursive_proof::RecursiveProofEnvelope;
use adamant_state::{verify_membership, verify_non_membership, MerkleProof, StateKey};

/// Re-exports of the recursive-proof types light-client
/// consumers most commonly need at the boundary.
pub mod recursion_re {
    pub use adamant_privacy::epoch_recursion::{verify_envelope, EpochRecursionError};
    pub use adamant_privacy::recursive_proof::{
        ProofCadence, RecursiveProof, RecursiveProofEnvelope, RecursiveProofPublicInputs,
    };
}

/// Re-exports of the state-tree types light-client consumers
/// most commonly need for §8.9 claim verification.
pub mod state_re {
    pub use adamant_state::{
        empty_leaf_hash, empty_subtree_hashes, leaf_hash, node_hash, value_hash, verify_membership,
        verify_non_membership, Hash, MerkleProof, SparseMerkleTree, StateKey, STATE_KEY_BYTES,
        STATE_TREE_DEPTH,
    };
}

/// Light-client node configuration.
///
/// Caller-supplied at startup. [`LightNodeRuntime::launch`]
/// consumes a `LightNodeConfig` and produces a running light
/// node.
pub struct LightNodeConfig {
    /// libp2p networking keypair. The light node connects to
    /// the network passively — it does not produce vertices
    /// or participate in consensus.
    pub network_keypair: NetworkKeypair,

    /// libp2p multiaddrs the light node listens on. May be
    /// empty for pure-outbound clients (e.g., phone wallets
    /// behind NAT that only initiate connections).
    pub listen_addresses: Vec<Multiaddr>,

    /// Bootstrap-peer addresses. Light clients typically dial
    /// 1-3 bootstrap peers to begin observing the gossipsub
    /// stream; more peers improves censorship resistance per
    /// §9.6.2.
    pub bootstrap_peers: Vec<(PeerId, Multiaddr)>,

    /// Initial [`LightClientState`]. Use
    /// [`LightClientState::new`] for a fresh light client; use
    /// [`LightClientState::from_genesis`] when bootstrapping
    /// from a known-good genesis checkpoint.
    pub initial_state: LightClientState,
}

impl LightNodeConfig {
    /// New config with the supplied network keypair and
    /// initial state. Listen addresses + bootstrap peers
    /// default to empty.
    #[must_use]
    pub fn new(network_keypair: NetworkKeypair, initial_state: LightClientState) -> Self {
        Self {
            network_keypair,
            listen_addresses: Vec::new(),
            bootstrap_peers: Vec::new(),
            initial_state,
        }
    }

    /// Append a listen address (chainable builder).
    #[must_use]
    pub fn with_listen_address(mut self, addr: Multiaddr) -> Self {
        self.listen_addresses.push(addr);
        self
    }

    /// Append a bootstrap peer (chainable builder).
    #[must_use]
    pub fn with_bootstrap_peer(mut self, peer_id: PeerId, addr: Multiaddr) -> Self {
        self.bootstrap_peers.push((peer_id, addr));
        self
    }
}

/// Typed errors across the [`LightNodeRuntime`] surface.
#[derive(Debug)]
pub enum LightNodeError {
    /// The networking layer rejected the supplied
    /// [`LightNodeConfig`].
    Network(NetworkError),

    /// The light client rejected an advance attempt (monotonicity
    /// or gap violation per §8.9).
    LightClient(LightClientError),

    /// The §8.5 recursive proof attached to an epoch
    /// boundary failed verification. Phase 9.3 wiring: the
    /// `adamant-privacy::epoch_recursion::verify_envelope`
    /// primitive checks the accumulator identity; a failure
    /// here means the supplied proof does not attest to a
    /// valid epoch transition and the boundary MUST be
    /// rejected.
    RecursiveProof(EpochRecursionError),
}

impl core::fmt::Display for LightNodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Network(e) => write!(f, "light node network error: {e}"),
            Self::LightClient(e) => write!(f, "light node state error: {e}"),
            Self::RecursiveProof(e) => {
                write!(f, "light node recursive-proof verification failed: {e}")
            }
        }
    }
}

impl From<EpochRecursionError> for LightNodeError {
    fn from(e: EpochRecursionError) -> Self {
        Self::RecursiveProof(e)
    }
}

impl std::error::Error for LightNodeError {}

impl From<NetworkError> for LightNodeError {
    fn from(e: NetworkError) -> Self {
        Self::Network(e)
    }
}

impl From<LightClientError> for LightNodeError {
    fn from(e: LightClientError) -> Self {
        Self::LightClient(e)
    }
}

/// Light-client runtime.
///
/// Owns the networking handle + the running
/// [`LightClientState`]. Long-lived; consumers query the tier
/// signal + state commitment for wallet UI; push
/// [`EpochBoundary`] artifacts (received via the network) into
/// [`Self::advance`] to keep the state current.
pub struct LightNodeRuntime {
    network: NetworkNode,
    state: LightClientState,
    local_peer_id: PeerId,
}

impl LightNodeRuntime {
    /// Construct + launch the light node from a
    /// [`LightNodeConfig`].
    ///
    /// # Errors
    ///
    /// Returns [`LightNodeError::Network`] if the network
    /// layer fails to launch.
    pub fn launch(config: LightNodeConfig) -> Result<Self, LightNodeError> {
        let mut network_config = NetworkConfig::new(config.network_keypair);
        for addr in config.listen_addresses {
            network_config = network_config.with_listen_address(addr);
        }
        for (peer, addr) in config.bootstrap_peers {
            network_config = network_config.with_bootstrap_peer(peer, addr);
        }
        let network = NetworkNode::launch(&network_config)?;
        let local_peer_id = *network.local_peer_id();
        Ok(Self {
            network,
            state: config.initial_state,
            local_peer_id,
        })
    }

    /// The light node's network peer ID.
    #[must_use]
    pub const fn network_peer_id(&self) -> &PeerId {
        &self.local_peer_id
    }

    /// The current tier signal per §8.1.7, or `None` if no
    /// epoch boundary has been observed yet.
    #[must_use]
    pub fn tier_signal(&self) -> Option<TierSignal> {
        self.state.tier_signal()
    }

    /// The latest observed state commitment, or `None` if no
    /// epoch boundary has been observed yet.
    #[must_use]
    pub fn state_commitment(&self) -> Option<&StateCommitment> {
        self.state.state_commitment()
    }

    /// The latest observed proof commitment, or `None` if no
    /// epoch boundary has been observed yet.
    #[must_use]
    pub fn proof_commitment(&self) -> Option<&ProofCommitment> {
        self.state.proof_commitment()
    }

    /// Borrow the underlying [`LightClientState`] for
    /// inspection.
    #[must_use]
    pub const fn state(&self) -> &LightClientState {
        &self.state
    }

    /// Mutable handle to the underlying network node. Used by
    /// drivers that loop on [`NetworkNode::next_event`].
    pub fn network_mut(&mut self) -> &mut NetworkNode {
        &mut self.network
    }

    /// Advance the light client by one epoch boundary
    /// **without** recursive-proof verification.
    ///
    /// Trusts the boundary's claimed commitments without
    /// validating the §8.5 recursive proof. Suitable for
    /// trusted-checkpoint advances (e.g., wallet bootstrap
    /// from a known-good genesis pin) and tests; production
    /// wallet code SHOULD use [`Self::verify_and_advance`]
    /// to require cryptographic proof of validity per §8.9.
    ///
    /// # Errors
    ///
    /// Returns [`LightNodeError::LightClient`] for monotonicity
    /// or gap violations per §8.9.
    pub fn advance(&mut self, boundary: EpochBoundary) -> Result<(), LightNodeError> {
        self.state.advance(boundary)?;
        Ok(())
    }

    /// Advance the light client by one epoch boundary
    /// **with** recursive-proof verification per §8.9.
    ///
    /// Phase 9.3 cross-layer wiring: invokes
    /// [`adamant_privacy::epoch_recursion::verify_envelope`]
    /// to cryptographically validate the supplied recursive-
    /// proof envelope before advancing the light client
    /// state. This is the §8.9 light-client-grade advance —
    /// no trust in the boundary's claimed commitments; the
    /// proof attests directly to the chain-state transition.
    ///
    /// Per §8.5.5 the verification is fast (~50–200ms on a
    /// modern smartphone); this is what makes light clients
    /// "phone-verifiable" per Principle III.
    ///
    /// # Errors
    ///
    /// - [`LightNodeError::RecursiveProof`] if the recursive
    ///   proof fails verification.
    /// - [`LightNodeError::LightClient`] if the epoch boundary
    ///   itself fails monotonicity / no-gap checks.
    pub fn verify_and_advance(
        &mut self,
        boundary: EpochBoundary,
        proof: &RecursiveProofEnvelope,
    ) -> Result<(), LightNodeError> {
        // Verify the recursive proof first; reject the
        // advance if it fails.
        verify_envelope(proof)?;
        // Recursive proof checks out; advance state.
        self.state.advance(boundary)?;
        Ok(())
    }

    /// Verify a §8.9 state-membership claim against the
    /// latest observed state commitment.
    ///
    /// Phase 9.3.1 cross-layer wiring: invokes
    /// [`adamant_state::verify_membership`] against the latest
    /// state commitment tracked by this light client. Returns
    /// `true` iff the supplied (key, value) pair is a member
    /// of the sparse Merkle tree committed to by the latest
    /// epoch boundary.
    ///
    /// Per §8.9 + Principle III: a wallet running this light
    /// client receives a Merkle proof from a service node (or
    /// untrusted source) and checks it against the
    /// recursive-proof-attested state commitment. The wallet
    /// does not need to trust the service node — the proof is
    /// cryptographically self-validating against the
    /// commitment.
    ///
    /// Returns `false` if:
    /// - No epoch boundary has been observed yet (no state
    ///   commitment to verify against).
    /// - The proof's sibling chain has the wrong length
    ///   (must be exactly `STATE_TREE_DEPTH = 256`).
    /// - The reconstructed root does not match the latest
    ///   state commitment.
    ///
    /// # Use cases per §8.9
    ///
    /// - **Account balance**: `key` = the account's state-tree
    ///   key; `value` = the BCS-encoded account record
    ///   carrying the balance field.
    /// - **Object existence**: `key` = the object's state-tree
    ///   key derived from its `ObjectId`; `value` = the
    ///   BCS-encoded object state.
    /// - **Transaction inclusion**: when the protocol's
    ///   transaction-inclusion tree (Phase 4 follow-on) is
    ///   wired into the same state commitment, the same
    ///   verification primitive applies to transaction-hash
    ///   keys.
    #[must_use]
    pub fn verify_state_membership_claim(
        &self,
        key: &StateKey,
        value: &[u8],
        proof: &MerkleProof,
    ) -> bool {
        self.state
            .state_commitment()
            .is_some_and(|root| verify_membership(key, value, proof, root.as_bytes()))
    }

    /// Verify a §8.9 state-non-membership claim against the
    /// latest observed state commitment.
    ///
    /// Phase 9.3.1 cross-layer wiring: invokes
    /// [`adamant_state::verify_non_membership`] against the
    /// latest state commitment tracked by this light client.
    /// Returns `true` iff the supplied key is NOT a member of
    /// the sparse Merkle tree committed to by the latest
    /// epoch boundary.
    ///
    /// Non-membership proofs let a wallet verify negative
    /// claims: "this address has no on-chain account" /
    /// "this `ObjectId` does not exist on chain." Useful for
    /// rejecting nonce-replay attempts and for service-node
    /// audits.
    ///
    /// Returns `false` if:
    /// - No epoch boundary has been observed yet.
    /// - The proof's sibling chain has the wrong length.
    /// - The reconstructed empty-leaf-rooted hash does not
    ///   match the latest state commitment.
    #[must_use]
    pub fn verify_state_non_membership_claim(&self, key: &StateKey, proof: &MerkleProof) -> bool {
        self.state
            .state_commitment()
            .is_some_and(|root| verify_non_membership(key, proof, root.as_bytes()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use adamant_consensus::{EpochNumber, SecurityTier};
    use adamant_network::libp2p_re::Keypair;

    fn fixture_boundary(epoch_n: u64, active_size: u32) -> EpochBoundary {
        EpochBoundary::new(
            EpochNumber::new(epoch_n),
            active_size,
            StateCommitment::from_bytes([0xAAu8; 32]),
            ProofCommitment::from_bytes([0xBBu8; 32]),
        )
    }

    #[test]
    fn light_node_config_new_defaults() {
        let cfg = LightNodeConfig::new(Keypair::generate_ed25519(), LightClientState::new());
        assert!(cfg.listen_addresses.is_empty());
        assert!(cfg.bootstrap_peers.is_empty());
    }

    #[test]
    fn light_node_config_builder_chains() {
        let addr: Multiaddr = "/ip4/0.0.0.0/tcp/0".parse().expect("multiaddr");
        let peer = PeerId::random();
        let cfg = LightNodeConfig::new(Keypair::generate_ed25519(), LightClientState::new())
            .with_listen_address(addr.clone())
            .with_bootstrap_peer(peer, addr);
        assert_eq!(cfg.listen_addresses.len(), 1);
        assert_eq!(cfg.bootstrap_peers.len(), 1);
    }

    #[test]
    fn light_node_error_display() {
        let e1 = LightNodeError::Network(NetworkError::GossipsubSetupFailed("x".into()));
        let e2 = LightNodeError::LightClient(LightClientError::EpochGap {
            latest: EpochNumber::new(0),
            supplied: EpochNumber::new(2),
        });
        assert!(e1.to_string().contains("network error"));
        assert!(e2.to_string().contains("state error"));
        assert_ne!(e1.to_string(), e2.to_string());
    }

    #[test]
    fn light_node_error_implements_std_error() {
        fn assert_err<E: std::error::Error>() {}
        assert_err::<LightNodeError>();
    }

    #[test]
    fn light_node_error_recursive_proof_variant() {
        let err = LightNodeError::RecursiveProof(EpochRecursionError::AccumulatorRejected);
        assert!(err.to_string().contains("recursive-proof"));
    }

    /// Smoke test: a light node can launch with no listen
    /// addresses + no bootstrap peers + empty state.
    #[tokio::test]
    async fn light_node_launch_smoke_test() {
        let cfg = LightNodeConfig::new(Keypair::generate_ed25519(), LightClientState::new());
        let node = LightNodeRuntime::launch(cfg).expect("launch");
        assert!(node.tier_signal().is_none());
        assert!(node.state_commitment().is_none());
    }

    /// Advance accepts monotonic boundaries; tier signal
    /// updates correctly.
    #[tokio::test]
    async fn light_node_advance_updates_tier_signal() {
        let cfg = LightNodeConfig::new(Keypair::generate_ed25519(), LightClientState::new());
        let mut node = LightNodeRuntime::launch(cfg).expect("launch");
        // Genesis boundary at active-set-size 15 → Tier II.
        node.advance(fixture_boundary(0, 15)).expect("advance");
        let signal = node.tier_signal().expect("present");
        assert_eq!(signal.tier, Some(SecurityTier::Tier2));
        // Next boundary at active-set-size 30 → Tier III.
        node.advance(fixture_boundary(1, 30)).expect("advance");
        assert_eq!(
            node.tier_signal().expect("present").tier,
            Some(SecurityTier::Tier3)
        );
    }

    /// Advance rejects gaps per §8.9 "light clients observe
    /// EVERY epoch boundary".
    #[tokio::test]
    async fn light_node_advance_rejects_gap() {
        let cfg = LightNodeConfig::new(Keypair::generate_ed25519(), LightClientState::new());
        let mut node = LightNodeRuntime::launch(cfg).expect("launch");
        node.advance(fixture_boundary(0, 15)).expect("advance");
        // Skip epoch 1.
        let err = node.advance(fixture_boundary(2, 15)).expect_err("gap");
        match err {
            LightNodeError::LightClient(LightClientError::EpochGap { .. }) => {}
            other => panic!("expected EpochGap, got {other:?}"),
        }
    }

    // ---------- §8.9 claim verification ----------

    /// Build a small sparse Merkle tree, populate it with three
    /// (key, value) pairs, and return the tree alongside its root
    /// (for advancing the light client) and a single key/value
    /// pair the test will prove against.
    fn fixture_state_tree() -> (
        state_re::SparseMerkleTree,
        [u8; 32],
        state_re::StateKey,
        Vec<u8>,
    ) {
        let mut tree = state_re::SparseMerkleTree::new();
        let key_a: state_re::StateKey = [0x11; 32];
        let key_b: state_re::StateKey = [0x22; 32];
        let key_c: state_re::StateKey = [0x33; 32];
        let val_a = b"account-balance-100".to_vec();
        let val_b = b"object-record-foo".to_vec();
        let val_c = b"tx-inclusion-bar".to_vec();
        tree.insert(key_a, &val_a);
        tree.insert(key_b, &val_b);
        tree.insert(key_c, &val_c);
        let root = tree.root();
        (tree, root, key_a, val_a)
    }

    fn boundary_with_root(epoch_n: u64, active_size: u32, root: [u8; 32]) -> EpochBoundary {
        EpochBoundary::new(
            EpochNumber::new(epoch_n),
            active_size,
            StateCommitment::from_bytes(root),
            ProofCommitment::from_bytes([0xBBu8; 32]),
        )
    }

    /// `verify_state_membership_claim` returns `false` before
    /// any epoch boundary has been observed.
    #[tokio::test]
    async fn verify_membership_returns_false_without_state_commitment() {
        let cfg = LightNodeConfig::new(Keypair::generate_ed25519(), LightClientState::new());
        let node = LightNodeRuntime::launch(cfg).expect("launch");
        let (tree, _root, key, value) = fixture_state_tree();
        let proof = tree.prove(&key);
        assert!(!node.verify_state_membership_claim(&key, &value, &proof));
    }

    /// `verify_state_membership_claim` returns `true` for an
    /// honest (key, value) pair against a populated tree.
    #[tokio::test]
    async fn verify_membership_accepts_honest_claim() {
        let cfg = LightNodeConfig::new(Keypair::generate_ed25519(), LightClientState::new());
        let mut node = LightNodeRuntime::launch(cfg).expect("launch");
        let (tree, root, key, value) = fixture_state_tree();
        node.advance(boundary_with_root(0, 15, root))
            .expect("advance");
        let proof = tree.prove(&key);
        assert!(node.verify_state_membership_claim(&key, &value, &proof));
    }

    /// Tampered value bytes are rejected — the reconstructed
    /// leaf hash diverges from the committed root.
    #[tokio::test]
    async fn verify_membership_rejects_tampered_value() {
        let cfg = LightNodeConfig::new(Keypair::generate_ed25519(), LightClientState::new());
        let mut node = LightNodeRuntime::launch(cfg).expect("launch");
        let (tree, root, key, _value) = fixture_state_tree();
        node.advance(boundary_with_root(0, 15, root))
            .expect("advance");
        let proof = tree.prove(&key);
        let tampered = b"account-balance-999".to_vec();
        assert!(!node.verify_state_membership_claim(&key, &tampered, &proof));
    }

    /// Wrong key (same proof, different key) is rejected.
    #[tokio::test]
    async fn verify_membership_rejects_wrong_key() {
        let cfg = LightNodeConfig::new(Keypair::generate_ed25519(), LightClientState::new());
        let mut node = LightNodeRuntime::launch(cfg).expect("launch");
        let (tree, root, key, value) = fixture_state_tree();
        node.advance(boundary_with_root(0, 15, root))
            .expect("advance");
        let proof = tree.prove(&key);
        let wrong_key: state_re::StateKey = [0x44; 32];
        assert!(!node.verify_state_membership_claim(&wrong_key, &value, &proof));
    }

    /// `verify_state_non_membership_claim` accepts a key the
    /// tree does not contain.
    #[tokio::test]
    async fn verify_non_membership_accepts_absent_key() {
        let cfg = LightNodeConfig::new(Keypair::generate_ed25519(), LightClientState::new());
        let mut node = LightNodeRuntime::launch(cfg).expect("launch");
        let (tree, root, _key, _value) = fixture_state_tree();
        node.advance(boundary_with_root(0, 15, root))
            .expect("advance");
        // 0x44 was not inserted in `fixture_state_tree`.
        let absent_key: state_re::StateKey = [0x44; 32];
        let proof = tree.prove(&absent_key);
        assert!(node.verify_state_non_membership_claim(&absent_key, &proof));
    }

    /// `verify_state_non_membership_claim` rejects a key that
    /// IS present in the tree (the leaf is populated, so the
    /// empty-leaf reconstruction diverges from the root).
    #[tokio::test]
    async fn verify_non_membership_rejects_present_key() {
        let cfg = LightNodeConfig::new(Keypair::generate_ed25519(), LightClientState::new());
        let mut node = LightNodeRuntime::launch(cfg).expect("launch");
        let (tree, root, key, _value) = fixture_state_tree();
        node.advance(boundary_with_root(0, 15, root))
            .expect("advance");
        let proof = tree.prove(&key);
        assert!(!node.verify_state_non_membership_claim(&key, &proof));
    }

    /// Proofs with wrong sibling-chain length (not 256) are
    /// rejected. Guards against malformed-proof injection.
    #[tokio::test]
    async fn verify_membership_rejects_malformed_proof() {
        let cfg = LightNodeConfig::new(Keypair::generate_ed25519(), LightClientState::new());
        let mut node = LightNodeRuntime::launch(cfg).expect("launch");
        let (_tree, root, key, value) = fixture_state_tree();
        node.advance(boundary_with_root(0, 15, root))
            .expect("advance");
        // Build a proof with too few siblings.
        let short_proof = state_re::MerkleProof::new(vec![[0u8; 32]; 10]);
        assert!(!node.verify_state_membership_claim(&key, &value, &short_proof));
    }

    /// Sibling-perturbation rejection — flipping any single
    /// proof byte must reject the claim.
    #[tokio::test]
    async fn verify_membership_rejects_tampered_proof() {
        let cfg = LightNodeConfig::new(Keypair::generate_ed25519(), LightClientState::new());
        let mut node = LightNodeRuntime::launch(cfg).expect("launch");
        let (tree, root, key, value) = fixture_state_tree();
        node.advance(boundary_with_root(0, 15, root))
            .expect("advance");
        let mut proof = tree.prove(&key);
        // Perturb the first sibling.
        proof.siblings[0][0] ^= 0x01;
        assert!(!node.verify_state_membership_claim(&key, &value, &proof));
    }

    /// Wrong root (advance with a different commitment) rejects
    /// honest proofs — pins the §8.9 trust-anchor binding.
    #[tokio::test]
    async fn verify_membership_rejects_under_wrong_commitment() {
        let cfg = LightNodeConfig::new(Keypair::generate_ed25519(), LightClientState::new());
        let mut node = LightNodeRuntime::launch(cfg).expect("launch");
        let (tree, _real_root, key, value) = fixture_state_tree();
        // Advance under a different commitment.
        node.advance(boundary_with_root(0, 15, [0u8; 32]))
            .expect("advance");
        let proof = tree.prove(&key);
        assert!(!node.verify_state_membership_claim(&key, &value, &proof));
    }
}
