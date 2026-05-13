//! Adamant validator node library.
//!
//! Phase 9 deliverable — the long-running daemon that wires
//! the §8 consensus core ([`adamant_consensus`]) + §9
//! networking layer ([`adamant_network`]) into a single
//! validator process. The library surface is consumable by
//! tests + simulators; the [`adamant-node` binary] wraps this
//! library as the production daemon entry point.
//!
//! [`adamant-node` binary]: ../adamant_node/index.html
//!
//! # Phase 9 scope
//!
//! Phase 9.0 (this commit) ships the **scaffolding wiring**:
//!
//! - [`NodeConfig`] — caller-supplied node configuration:
//!   networking keypair + listen addresses + bootstrap peers,
//!   plus the validator-identity bundle the node operates as.
//! - [`NodeRuntime`] — the running state machine. Owns the
//!   `adamant-network` `NetworkNode` + the
//!   `adamant-consensus` `DagState` + the `CommitSequencer` +
//!   the local mempool. Surfaces a tokio task that drives the
//!   network event loop.
//! - [`NodeError`] — typed errors across the surface.
//!
//! # What Phase 9 does NOT yet wire
//!
//! - The §6 execution layer (`adamant-vm`) for transaction
//!   execution. Crosses Phase 5/6 boundary; lands at Phase 9.1
//!   when the AVM runtime is feature-complete.
//! - The §4 state layer ([`adamant-state`]) for object storage
//!   + state-commitment Merkle tree. Crosses Phase 4 backfill.
//! - The §3.6 DKG for threshold-encryption key shares.
//!   Crosses Phase 7.7d → §8.4.3.
//! - Persistent storage (`RocksDB` integration). Crosses Phase 4
//!   backfill + spec-author Decision 2 in §14.4.
//! - The full validator transaction-production loop. Requires
//!   AVM + state-layer integration.
//!
//! Phase 9.0 ships the **integration scaffold** — a binary that
//! launches, connects to the network, and runs the consensus
//! event loop without crashing. Full validator behaviour
//! requires the above cross-layer wiring.
//!
//! # Architectural shape
//!
//! ```text
//! NodeRuntime
//!   ├── network: NetworkNode      (adamant-network)
//!   ├── dag: DagState             (adamant-consensus)
//!   ├── sequencer: CommitSequencer (adamant-consensus)
//!   ├── mempool: Mempool          (adamant-network)
//!   └── identity: ValidatorPublicKeys + bls::SecretKey
//! ```

#![forbid(unsafe_code)]
#![allow(
    clippy::multiple_crate_versions,
    reason = "adamant-node transitively depends on libp2p via \
              adamant-network, inheriting the same dup-version \
              tree (hashlink, socket2, thiserror, unsigned-varint, \
              yamux). Scoped narrowly to the binary-integration \
              crate; workspace-wide multiple_crate_versions = \
              \"warn\" stays in force elsewhere."
)]

use std::time::Duration;

use adamant_consensus::{
    ActiveSet, CommitSequencer, CommitWaveSchedule, DagState, EpochNumber, ValidatorId,
    ValidatorPublicKeys,
};
use adamant_network::libp2p_re::{Keypair as NetworkKeypair, Multiaddr, PeerId};
use adamant_network::{Mempool, NetworkConfig, NetworkError, NetworkNode};

/// Adamant validator node configuration.
///
/// Caller-supplied at startup. [`NodeRuntime::launch`]
/// consumes a `NodeConfig` and produces a running node.
pub struct NodeConfig {
    /// libp2p networking keypair. Distinct from the validator's
    /// consensus signing keys (which are in `validator_identity`):
    /// networking identity is per-node, consensus identity is
    /// per-validator. The same operator may rotate networking
    /// keys without changing their consensus role.
    pub network_keypair: NetworkKeypair,

    /// libp2p multiaddrs the node listens on. Typical entries:
    /// `/ip4/0.0.0.0/udp/<port>/quic-v1` + `/ip4/0.0.0.0/tcp/<port>`.
    pub listen_addresses: Vec<Multiaddr>,

    /// Bootstrap-peer addresses to dial at startup. Seeded
    /// from the §11 genesis specification's published
    /// bootstrap-node list per §9.6.1.
    pub bootstrap_peers: Vec<(PeerId, Multiaddr)>,

    /// Validator consensus-identity bundle (Ed25519 + ML-DSA +
    /// BLS keys per §8.1.1). The validator signs vertices with
    /// the BLS key; the ML-DSA key is post-quantum signature
    /// material for §4 account-bound operations.
    pub validator_identity: ValidatorPublicKeys,

    /// Initial active-set snapshot. In production this is
    /// recovered from chain state on startup; in tests +
    /// simulator runs the caller supplies the desired
    /// initial state directly.
    pub initial_active_set: ActiveSet,

    /// Initial epoch. In production this is recovered from
    /// chain state on startup; defaults to genesis for tests.
    pub initial_epoch: EpochNumber,

    /// Commit-wave schedule per §8.3.3. Defaults to
    /// [`CommitWaveSchedule::launch`] (4-round wave period).
    pub wave_schedule: CommitWaveSchedule,

    /// Mempool capacity per §9.7.1. Defaults to
    /// [`adamant_network::DEFAULT_MEMPOOL_CAPACITY`].
    pub mempool_capacity: usize,

    /// gossipsub heartbeat interval. Forwarded to
    /// `NetworkNode::launch`.
    pub heartbeat_interval: Duration,

    /// Maximum gossipsub message size in bytes. Forwarded to
    /// `NetworkNode::launch`.
    pub max_message_size: usize,
}

impl NodeConfig {
    /// New config with reasonable defaults for the supplied
    /// network keypair + validator identity + initial active
    /// set. Listen addresses + bootstrap peers default to
    /// empty; the caller fills them via the [`Self::with_*`]
    /// builders.
    #[must_use]
    pub fn new(
        network_keypair: NetworkKeypair,
        validator_identity: ValidatorPublicKeys,
        initial_active_set: ActiveSet,
    ) -> Self {
        Self {
            network_keypair,
            listen_addresses: Vec::new(),
            bootstrap_peers: Vec::new(),
            validator_identity,
            initial_active_set,
            initial_epoch: EpochNumber::default(),
            wave_schedule: CommitWaveSchedule::launch(),
            mempool_capacity: adamant_network::DEFAULT_MEMPOOL_CAPACITY,
            heartbeat_interval: Duration::from_millis(200),
            max_message_size: 1024 * 1024,
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

    /// Override the default initial epoch.
    #[must_use]
    pub const fn with_initial_epoch(mut self, epoch: EpochNumber) -> Self {
        self.initial_epoch = epoch;
        self
    }
}

/// Typed errors across the [`NodeRuntime`] surface.
#[derive(Debug)]
pub enum NodeError {
    /// The networking layer rejected the supplied
    /// [`NodeConfig`]. Wraps the underlying [`NetworkError`].
    Network(NetworkError),
}

impl core::fmt::Display for NodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Network(e) => write!(f, "node network error: {e}"),
        }
    }
}

impl std::error::Error for NodeError {}

impl From<NetworkError> for NodeError {
    fn from(e: NetworkError) -> Self {
        Self::Network(e)
    }
}

/// Adamant validator node runtime.
///
/// Owns the network handle + the consensus state machines +
/// the local mempool. Long-lived; consumers spawn a tokio task
/// that drives [`NetworkNode::next_event`] in a loop and
/// dispatches into the consensus + mempool layers.
///
/// # Phase 9.0 scope
///
/// The runtime exposes the **integration touchpoints**: the
/// network can be polled for events, the DAG can be queried,
/// the mempool can be queried. Phase 9.0 does NOT yet wire
/// the full consume-network-events → update-DAG →
/// run-commit-wave → dispatch-to-execution loop; that lands at
/// Phase 9.1 once AVM integration is feature-complete.
pub struct NodeRuntime {
    /// libp2p networking handle.
    network: NetworkNode,

    /// Consensus DAG state.
    dag: DagState,

    /// Commit-wave sequencer state.
    sequencer: CommitSequencer,

    /// Local active set (current snapshot).
    active_set: ActiveSet,

    /// Current epoch.
    epoch: EpochNumber,

    /// Local mempool.
    mempool: Mempool,

    /// This validator's consensus identity bundle.
    identity: ValidatorPublicKeys,
}

impl NodeRuntime {
    /// Construct + launch the node from a [`NodeConfig`].
    ///
    /// Steps:
    /// 1. Build the [`NetworkNode`] via Phase 7.8 wiring.
    /// 2. Initialise [`DagState`] (empty at startup).
    /// 3. Initialise [`CommitSequencer`] with the supplied
    ///    wave schedule.
    /// 4. Initialise [`Mempool`] with the supplied capacity.
    ///
    /// # Errors
    ///
    /// Returns [`NodeError::Network`] if the networking layer
    /// fails to launch (bad listen address, bad bootstrap
    /// peer, etc.).
    pub fn launch(config: NodeConfig) -> Result<Self, NodeError> {
        let network_config = NetworkConfig::new(config.network_keypair)
            .with_max_message_size(config.max_message_size)
            .with_heartbeat_interval(config.heartbeat_interval);
        let network_config = config
            .listen_addresses
            .into_iter()
            .fold(network_config, NetworkConfig::with_listen_address);
        let network_config = config
            .bootstrap_peers
            .into_iter()
            .fold(network_config, |c, (peer, addr)| {
                c.with_bootstrap_peer(peer, addr)
            });
        let network = NetworkNode::launch(&network_config)?;
        Ok(Self {
            network,
            dag: DagState::new(),
            sequencer: CommitSequencer::new(config.wave_schedule),
            active_set: config.initial_active_set,
            epoch: config.initial_epoch,
            mempool: Mempool::with_capacity(config.mempool_capacity),
            identity: config.validator_identity,
        })
    }

    /// The node's networking peer ID (derived from the
    /// network keypair). Distinct from the validator's
    /// consensus identity (`validator_id`).
    #[must_use]
    pub fn network_peer_id(&self) -> &PeerId {
        self.network.local_peer_id()
    }

    /// The node's consensus identity per §8.1.2.
    #[must_use]
    pub fn validator_id(&self) -> ValidatorId {
        self.identity.derive_id()
    }

    /// The node's current epoch.
    #[must_use]
    pub const fn epoch(&self) -> EpochNumber {
        self.epoch
    }

    /// Borrow the DAG state for inspection.
    #[must_use]
    pub const fn dag(&self) -> &DagState {
        &self.dag
    }

    /// Borrow the active set for inspection.
    #[must_use]
    pub const fn active_set(&self) -> &ActiveSet {
        &self.active_set
    }

    /// Borrow the mempool for inspection.
    #[must_use]
    pub const fn mempool(&self) -> &Mempool {
        &self.mempool
    }

    /// Borrow the sequencer for inspection.
    #[must_use]
    pub const fn sequencer(&self) -> &CommitSequencer {
        &self.sequencer
    }

    /// Mutable handle to the underlying network node. Used by
    /// drivers that loop on [`NetworkNode::next_event`] and
    /// dispatch into the consensus + mempool layers.
    pub fn network_mut(&mut self) -> &mut NetworkNode {
        &mut self.network
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use adamant_consensus::EpochNumber;
    // NetworkKeypair already imported from adamant_network at the module level.

    fn fixture_validator_identity() -> ValidatorPublicKeys {
        ValidatorPublicKeys::new([1u8; 32], [1u8; 1952], [1u8; 96])
    }

    fn fixture_active_set() -> ActiveSet {
        let mut s = ActiveSet::new();
        for seed in 1..=7u8 {
            let id = ValidatorPublicKeys::new([seed; 32], [seed; 1952], [seed; 96]).derive_id();
            s.register(id, EpochNumber::default()).expect("register");
        }
        s
    }

    #[test]
    fn node_config_new_defaults() {
        let cfg = NodeConfig::new(
            NetworkKeypair::generate_ed25519(),
            fixture_validator_identity(),
            fixture_active_set(),
        );
        assert!(cfg.listen_addresses.is_empty());
        assert!(cfg.bootstrap_peers.is_empty());
        assert_eq!(cfg.initial_epoch, EpochNumber::default());
        assert_eq!(
            cfg.mempool_capacity,
            adamant_network::DEFAULT_MEMPOOL_CAPACITY
        );
    }

    #[test]
    fn node_config_builder_chains() {
        let addr: Multiaddr = "/ip4/0.0.0.0/tcp/0".parse().expect("multiaddr");
        let peer = PeerId::random();
        let cfg = NodeConfig::new(
            NetworkKeypair::generate_ed25519(),
            fixture_validator_identity(),
            fixture_active_set(),
        )
        .with_listen_address(addr.clone())
        .with_bootstrap_peer(peer, addr)
        .with_initial_epoch(EpochNumber::new(42));
        assert_eq!(cfg.listen_addresses.len(), 1);
        assert_eq!(cfg.bootstrap_peers.len(), 1);
        assert_eq!(cfg.initial_epoch, EpochNumber::new(42));
    }

    #[test]
    fn node_error_display_includes_inner_message() {
        let err = NodeError::Network(NetworkError::GossipsubSetupFailed("test".into()));
        let msg = err.to_string();
        assert!(msg.contains("node network error"));
        assert!(msg.contains("gossipsub"));
    }

    #[test]
    fn node_error_implements_std_error() {
        fn assert_err<E: std::error::Error>() {}
        assert_err::<NodeError>();
    }

    /// Smoke test: a node can be launched with empty listen
    /// addresses + empty bootstrap peers. Verifies the
    /// network + consensus + mempool wiring.
    #[tokio::test]
    async fn node_launch_smoke_test() {
        let cfg = NodeConfig::new(
            NetworkKeypair::generate_ed25519(),
            fixture_validator_identity(),
            fixture_active_set(),
        );
        let expected_validator_id = fixture_validator_identity().derive_id();
        let node = NodeRuntime::launch(cfg).expect("launch");
        assert_eq!(node.validator_id(), expected_validator_id);
        assert_eq!(node.epoch(), EpochNumber::default());
        assert!(node.dag().is_empty());
        assert!(node.mempool().is_empty());
        assert_eq!(node.active_set().active_size(), 7);
    }

    /// Two independent nodes can launch concurrently with
    /// distinct network identities.
    #[tokio::test]
    async fn two_nodes_have_distinct_network_identities() {
        let cfg_a = NodeConfig::new(
            NetworkKeypair::generate_ed25519(),
            fixture_validator_identity(),
            fixture_active_set(),
        );
        let cfg_b = NodeConfig::new(
            NetworkKeypair::generate_ed25519(),
            fixture_validator_identity(),
            fixture_active_set(),
        );
        let node_a = NodeRuntime::launch(cfg_a).expect("a");
        let node_b = NodeRuntime::launch(cfg_b).expect("b");
        assert_ne!(node_a.network_peer_id(), node_b.network_peer_id());
    }
}
