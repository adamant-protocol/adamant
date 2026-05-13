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
//! # Phase 9.2 scope
//!
//! - [`LightNodeConfig`] — caller-supplied configuration:
//!   networking keypair + bootstrap peers + initial
//!   `LightClientState`.
//! - [`LightNodeRuntime`] — the running light-client process.
//!   Owns the network handle + the light-client state; surfaces
//!   advance APIs that consume new [`EpochBoundary`] artifacts.
//! - [`LightNodeError`] — typed errors across the surface.
//!
//! # What Phase 9.2 does NOT yet wire
//!
//! - **Recursive-proof verification** at each epoch boundary
//!   (the Phase 7.9 deferred surface). The verification
//!   primitive lives in `adamant-privacy::epoch_recursion`;
//!   wiring it through would couple `adamant-light` to the
//!   privacy crate. Lands at Phase 9.3 or later.
//! - **§8.9 claim verification** (account balance via Merkle
//!   path, transaction inclusion, object existence). Depends
//!   on the Phase 4 state-commitment Merkle tree which is
//!   skeleton.
//! - **`EpochBoundary` ingestion from the network** — Phase
//!   9.2's light node has the `LightClientState` but lacks
//!   the gossipsub-topic listener that consumes
//!   `EpochBoundary` artifacts from peers. Lands at Phase
//!   9.3 when the cross-layer ingestion driver is wired.
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

/// Re-exports of the recursive-proof types light-client
/// consumers most commonly need at the boundary.
pub mod recursion_re {
    pub use adamant_privacy::epoch_recursion::{verify_envelope, EpochRecursionError};
    pub use adamant_privacy::recursive_proof::{
        ProofCadence, RecursiveProof, RecursiveProofEnvelope, RecursiveProofPublicInputs,
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
}

#[cfg(test)]
mod tests {
    use super::*;

    use adamant_consensus::{EpochNumber, SecurityTier};
    use adamant_network::libp2p_re::Keypair;

    fn fixture_boundary(epoch_n: u64, active_size: usize) -> EpochBoundary {
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
}
