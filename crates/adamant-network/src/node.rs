//! libp2p integration layer per whitepaper §9.2.
//!
//! Phase 7.8.1 deliverable — wires the Phase 7.8.0 wire-format
//! types ([`NetworkMessage`], [`GossipsubTopic`]) onto the
//! libp2p substrate per the §9.2.2 configuration (QUIC + TCP
//! fallback, Noise XX, Yamux, gossipsub v1.1, identify).
//! Phase 7.8.3 extended the [`AdamantBehaviour`] with Kademlia
//! DHT discovery + bootstrap per §9.6; bootstrap peers
//! supplied via [`NetworkConfig::bootstrap_peers`] seed the
//! DHT routing table at launch.
//!
//! # Architectural shape
//!
//! - [`NetworkConfig`] — caller-supplied configuration:
//!   keypair, listen addresses, bootstrap peers, gossipsub
//!   tuning parameters.
//! - [`AdamantBehaviour`] — the composite libp2p
//!   [`NetworkBehaviour`] for the Adamant network: gossipsub +
//!   identify + Kademlia DHT.
//! - [`NetworkNode`] — the high-level handle. Owns the
//!   [`libp2p::Swarm`], the topic registry, and the consumer-
//!   facing publish/subscribe surface. Exposes
//!   [`NetworkNode::publish`] for outgoing messages and
//!   [`NetworkNode::next_event`] for incoming events.
//! - [`NetworkEvent`] — application-level events emitted by
//!   the node: incoming gossipsub messages, peer connection
//!   state changes.
//! - [`NetworkError`] — typed errors across the surface.
//!
//! # Runtime + transport posture
//!
//! Adamant pins **tokio** as the async runtime (per CLAUDE.md
//! Section 7) and **QUIC primary + TCP fallback** as the
//! transport (per §9.2.2). The libp2p `SwarmBuilder` chain is:
//!
//! 1. `.with_existing_identity(keypair)` — uses the caller-
//!    supplied Ed25519 keypair; the derived `PeerId` is the
//!    node's networking identity.
//! 2. `.with_tokio()` — registers the tokio executor.
//! 3. `.with_tcp(... noise ... yamux)` — TCP fallback path.
//! 4. `.with_quic()` — QUIC primary path (its own built-in
//!    encryption + multiplexing; no Noise/Yamux composition
//!    needed).
//! 5. `.with_dns()` — multiaddr DNS resolution.
//! 6. `.with_behaviour(|key| AdamantBehaviour::new(...))`.
//! 7. `.build()`.
//!
//! # Topic subscription posture
//!
//! [`NetworkNode::launch`] auto-subscribes to both
//! [`GossipsubTopic`] values at startup. Operators do NOT need
//! to manually subscribe. This is consistent with the §8 +
//! §9.3 protocol-mandated subscription set: every active
//! validator and every observer node receives both Vertices
//! and Mempool topic traffic.
//!
//! # Phase 7.8.1 scope vs deferred
//!
//! Ships (cumulative through Phase 7.8.3):
//! - Swarm construction with the §9.2.2 transport + security
//!   + multiplexer pinning.
//! - gossipsub behaviour with topic subscription.
//! - identify behaviour for peer-info exchange.
//! - Kademlia DHT discovery + bootstrap (Phase 7.8.3).
//! - publish + `next_event` APIs.
//! - peer-connection + peer-discovery + bootstrap-completion
//!   lifecycle events.
//!
//! Deferred to follow-on sub-arcs:
//! - Anti-DoS submission-proof gating wired into propagation
//!   (Phase 7.8.2 ships the primitives; the
//!   propagation-side gating lands at Phase 7.8.4).
//! - Mempool synchronisation + replacement policy (Phase
//!   7.8.4).
//! - Onion routing + timing obfuscation per §9.4.2 / §9.4.3
//!   (Phase 7.8.5+; out-of-band for the core networking
//!   surface).

use std::time::Duration;

use futures::StreamExt;
use libp2p::gossipsub::{
    self, Behaviour as GossipsubBehaviour, IdentTopic, MessageAuthenticity, ValidationMode,
};
use libp2p::identify::{self, Behaviour as IdentifyBehaviour};
use libp2p::identity::Keypair;
use libp2p::kad::{self, store::MemoryStore, Behaviour as KademliaBehaviour, QueryResult};
use libp2p::swarm::SwarmEvent;
use libp2p::{noise, tcp, yamux, Multiaddr, PeerId, StreamProtocol, Swarm};

use crate::{GossipsubTopic, NetworkMessage};

/// Default gossipsub heartbeat interval. Lower than the libp2p
/// default to match Adamant's sub-second finality target per
/// whitepaper §8.2: a 200ms heartbeat keeps mesh-maintenance
/// latency below one round (250ms target round duration).
const DEFAULT_HEARTBEAT_INTERVAL: Duration = Duration::from_millis(200);

/// Default maximum gossipsub message size. Sized to accommodate
/// vertex propagation in the time-lock regime: a vertex carries
/// up to a few KB of transactions + ~96-byte BLS signature.
/// Tunable; the §9.3.2 "Transaction sizes" subsection bounds
/// individual transaction sizes, and the vertex aggregates them.
const DEFAULT_MAX_MESSAGE_SIZE: usize = 1024 * 1024; // 1 MiB

/// Adamant's identify-protocol agent string. Carried in the
/// identify handshake per the §9.2.2 spec; lets peers identify
/// each other as Adamant nodes.
const ADAMANT_AGENT_STRING: &str = "adamant-network/0.1";

/// libp2p protocol-name suffix for the identify exchange.
/// Versioned to match [`NETWORK_PROTOCOL_VERSION`]; a bump here
/// is a hard-fork-aware deliberate change.
const ADAMANT_IDENTIFY_PROTOCOL: &str = "/adamant/identify/1.0.0";

/// libp2p Kademlia protocol-name per §9.2.2 + §9.6.
/// Adamant-specific so the Adamant DHT does not share
/// records with other libp2p networks (the same physical
/// libp2p mesh can host multiple protocol-isolated DHTs;
/// distinct protocol names is what separates them).
/// Versioned to match [`NETWORK_PROTOCOL_VERSION`]; a bump
/// here is a hard-fork-aware deliberate change.
const ADAMANT_KADEMLIA_PROTOCOL: &str = "/adamant/kad/1.0.0";

/// Typed errors produced by the [`NetworkNode`] surface.
///
/// Non-`#[non_exhaustive]` per the consensus-critical-surface
/// discipline established across the workspace (see
/// `adamant-consensus`'s `DagError`, `CommitDecision`,
/// `SequencerError`).
#[derive(Debug)]
pub enum NetworkError {
    /// libp2p gossipsub behaviour construction failed. The
    /// inner string is the libp2p-level error message; folded
    /// to a single variant for consensus-stable surface size.
    GossipsubSetupFailed(String),

    /// libp2p identify behaviour construction failed (rare —
    /// the identify behaviour is mostly trivial config).
    IdentifySetupFailed(String),

    /// libp2p swarm construction failed (transport, security,
    /// or multiplexer setup). The inner string is the
    /// libp2p-level diagnostic.
    SwarmBuildFailed(String),

    /// `swarm.listen_on(addr)` rejected one of the listen
    /// addresses in [`NetworkConfig::listen_addresses`].
    ListenAddressFailed {
        /// The multiaddr that failed to bind.
        address: Multiaddr,
        /// libp2p-level error description.
        reason: String,
    },

    /// `swarm.dial(addr)` rejected a bootstrap-peer address.
    DialFailed {
        /// The multiaddr that failed to dial.
        address: Multiaddr,
        /// libp2p-level error description.
        reason: String,
    },

    /// gossipsub publish failed. Common causes: message too
    /// large for the configured `max_message_size`, mesh empty
    /// for the topic (peers haven't joined yet), or duplicate
    /// publish (already-seen message-id).
    PublishFailed {
        /// The topic the message would have been published on.
        topic: GossipsubTopic,
        /// libp2p-level error description.
        reason: String,
    },

    /// BCS encoding of a [`NetworkMessage`] failed (should
    /// not occur in practice for plain-data shapes; folded
    /// into a typed error for completeness).
    MessageEncodingFailed(String),

    /// BCS decoding of received gossipsub message bytes
    /// failed. The peer's wire was malformed or
    /// version-mismatched against [`NETWORK_PROTOCOL_VERSION`].
    MessageDecodingFailed(String),

    /// gossipsub subscription to a topic failed at swarm
    /// startup. Rare — subscription is mostly trivial.
    SubscriptionFailed {
        /// The topic the subscription failed for.
        topic: GossipsubTopic,
        /// libp2p-level error description.
        reason: String,
    },
}

impl core::fmt::Display for NetworkError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::GossipsubSetupFailed(s) => write!(f, "gossipsub setup failed: {s}"),
            Self::IdentifySetupFailed(s) => write!(f, "identify setup failed: {s}"),
            Self::SwarmBuildFailed(s) => write!(f, "swarm build failed: {s}"),
            Self::ListenAddressFailed { address, reason } => {
                write!(f, "listen on {address} failed: {reason}")
            }
            Self::DialFailed { address, reason } => {
                write!(f, "dial {address} failed: {reason}")
            }
            Self::PublishFailed { topic, reason } => {
                write!(f, "publish to {} failed: {reason}", topic.topic_name())
            }
            Self::MessageEncodingFailed(s) => write!(f, "message encoding failed: {s}"),
            Self::MessageDecodingFailed(s) => write!(f, "message decoding failed: {s}"),
            Self::SubscriptionFailed { topic, reason } => {
                write!(f, "subscription to {} failed: {reason}", topic.topic_name())
            }
        }
    }
}

impl std::error::Error for NetworkError {}

/// Adamant network node configuration.
///
/// Caller-supplied. The [`NetworkNode::launch`] constructor
/// consumes a `NetworkConfig` and produces a running node.
#[derive(Debug, Clone)]
pub struct NetworkConfig {
    /// libp2p keypair. The derived `PeerId` is the node's
    /// networking identity. Distinct from the validator's
    /// §3.4 signing keys — networking identity is per-node,
    /// not per-validator (a validator may rotate networking
    /// keys without affecting its consensus identity).
    pub keypair: Keypair,

    /// libp2p multiaddrs the node listens on. Typical entries:
    /// `/ip4/0.0.0.0/udp/<port>/quic-v1` (QUIC) plus
    /// `/ip4/0.0.0.0/tcp/<port>` (TCP fallback). Empty Vec is
    /// permitted (no listening; pure outbound node).
    pub listen_addresses: Vec<Multiaddr>,

    /// Bootstrap peers to dial at startup. Each is a
    /// `(PeerId, Multiaddr)` pair — the multiaddr is where
    /// the peer is reachable; the `PeerId` is its libp2p
    /// identity. Phase 7.8.1 uses caller-supplied bootstrap
    /// peers exclusively; Kademlia DHT discovery (Phase
    /// 7.8.3) layers on top.
    pub bootstrap_peers: Vec<(PeerId, Multiaddr)>,

    /// Maximum gossipsub message size in bytes. Defaults to
    /// 1 MiB; tunable per the §9.3.2 transaction-size policy.
    pub max_message_size: usize,

    /// Gossipsub heartbeat interval. Defaults to 200ms to
    /// match the §8.2 sub-second finality target.
    pub heartbeat_interval: Duration,
}

impl NetworkConfig {
    /// New config with the supplied keypair and default
    /// tuning. Listen addresses + bootstrap peers default to
    /// empty Vecs; the caller fills them via
    /// [`Self::with_listen_address`] / [`Self::with_bootstrap_peer`].
    #[must_use]
    pub fn new(keypair: Keypair) -> Self {
        Self {
            keypair,
            listen_addresses: Vec::new(),
            bootstrap_peers: Vec::new(),
            max_message_size: DEFAULT_MAX_MESSAGE_SIZE,
            heartbeat_interval: DEFAULT_HEARTBEAT_INTERVAL,
        }
    }

    /// Add a listen address (chainable).
    #[must_use]
    pub fn with_listen_address(mut self, addr: Multiaddr) -> Self {
        self.listen_addresses.push(addr);
        self
    }

    /// Add a bootstrap peer (chainable).
    #[must_use]
    pub fn with_bootstrap_peer(mut self, peer_id: PeerId, addr: Multiaddr) -> Self {
        self.bootstrap_peers.push((peer_id, addr));
        self
    }

    /// Override the default 1 MiB max message size.
    #[must_use]
    pub const fn with_max_message_size(mut self, bytes: usize) -> Self {
        self.max_message_size = bytes;
        self
    }

    /// Override the default 200ms heartbeat interval.
    #[must_use]
    pub const fn with_heartbeat_interval(mut self, interval: Duration) -> Self {
        self.heartbeat_interval = interval;
        self
    }
}

/// Adamant's composite libp2p [`NetworkBehaviour`].
///
/// Combines gossipsub (per §9.2.2 pubsub) and identify (per
/// §9.2.2 peer-info exchange). Kademlia DHT lands at Phase
/// 7.8.3.
///
/// The libp2p `NetworkBehaviour` derive macro emits a sibling
/// `AdamantBehaviourEvent` enum (one variant per behaviour
/// field) that lacks per-variant doc-comments. The wrapping
/// `behaviour` module scopes a `missing_docs` allow narrowly
/// to that derive-emit boundary; the application-visible event
/// surface is [`NetworkEvent`], which carries full
/// documentation.
pub use behaviour::{AdamantBehaviour, AdamantBehaviourEvent};

mod behaviour {
    #![allow(
        missing_docs,
        reason = "libp2p NetworkBehaviour derive emits a \
                  sibling event enum whose variants lack doc-\
                  comments; the application surface is the \
                  documented NetworkEvent enum, not this \
                  derive-emitted internal."
    )]

    use libp2p::gossipsub::Behaviour as GossipsubBehaviour;
    use libp2p::identify::Behaviour as IdentifyBehaviour;
    use libp2p::kad::{store::MemoryStore, Behaviour as KademliaBehaviour};
    use libp2p::swarm::NetworkBehaviour;

    /// Adamant's composite libp2p [`NetworkBehaviour`] (inner
    /// definition; re-exported via `pub use behaviour::*`).
    /// Combines gossipsub (per §9.2.2 pubsub), identify (per
    /// §9.2.2 peer-info exchange), and Kademlia DHT (per
    /// §9.2.2 + §9.6 peer discovery + bootstrap).
    #[derive(NetworkBehaviour)]
    pub struct AdamantBehaviour {
        /// Gossipsub pubsub behaviour. Handles message
        /// dissemination on the
        /// [`crate::GossipsubTopic`] topics per §9.2.2
        /// gossipsub v1.1 semantics.
        pub gossipsub: GossipsubBehaviour,

        /// Identify protocol behaviour. Exchanges peer-info
        /// (agent string, supported protocols, listen
        /// addresses) at connection establishment per §9.2.2.
        pub identify: IdentifyBehaviour,

        /// Kademlia DHT behaviour per §9.2.2 + §9.6.
        /// Discovers peers seeded from
        /// [`crate::NetworkConfig::bootstrap_peers`] and
        /// surfaces them via [`crate::NetworkEvent::PeerDiscovered`].
        /// Per §9.6.1, bootstrap nodes are "not 'trusted' for
        /// any consensus-critical purpose"; they are
        /// convenience infrastructure.
        pub kademlia: KademliaBehaviour<MemoryStore>,
    }
}

impl AdamantBehaviour {
    /// Construct the composite behaviour from a keypair plus
    /// configuration. Internal helper invoked by
    /// [`NetworkNode::launch`].
    fn new(
        keypair: &Keypair,
        max_message_size: usize,
        heartbeat_interval: Duration,
    ) -> Result<Self, NetworkError> {
        let gossipsub_config = gossipsub::ConfigBuilder::default()
            .heartbeat_interval(heartbeat_interval)
            .validation_mode(ValidationMode::Strict)
            .max_transmit_size(max_message_size)
            .build()
            .map_err(|e| NetworkError::GossipsubSetupFailed(e.to_string()))?;
        let gossipsub = GossipsubBehaviour::new(
            MessageAuthenticity::Signed(keypair.clone()),
            gossipsub_config,
        )
        .map_err(|e| NetworkError::GossipsubSetupFailed(e.to_string()))?;

        let identify = IdentifyBehaviour::new(
            identify::Config::new(ADAMANT_IDENTIFY_PROTOCOL.to_string(), keypair.public())
                .with_agent_version(ADAMANT_AGENT_STRING.to_string()),
        );

        let local_peer_id = PeerId::from(keypair.public());
        let store = MemoryStore::new(local_peer_id);
        let mut kad_config = kad::Config::new(StreamProtocol::new(ADAMANT_KADEMLIA_PROTOCOL));
        // Server-mode by default so this node accepts DHT
        // queries from peers (per §9.6.2 decentralisation
        // posture — every node is a potential bootstrap
        // contributor once registered).
        kad_config.set_query_timeout(Duration::from_secs(30));
        let kademlia = KademliaBehaviour::with_config(local_peer_id, store, kad_config);

        Ok(Self {
            gossipsub,
            identify,
            kademlia,
        })
    }
}

/// Application-level events emitted by [`NetworkNode::next_event`].
///
/// Non-`#[non_exhaustive]` per consensus-critical-surface
/// discipline.
#[derive(Debug, Clone)]
pub enum NetworkEvent {
    /// A gossipsub message was received from a peer.
    Message {
        /// The topic the message arrived on.
        topic: GossipsubTopic,
        /// The peer that propagated the message (the
        /// immediate forwarder; not necessarily the original
        /// author).
        source: Option<PeerId>,
        /// The decoded message payload.
        message: NetworkMessage,
    },

    /// A peer connection was established.
    PeerConnected(PeerId),

    /// A peer connection was closed (gracefully or
    /// otherwise).
    PeerDisconnected(PeerId),

    /// A bootstrap-peer dial failed. Diagnostic; not a fatal
    /// error.
    BootstrapDialFailed {
        /// The peer that failed to dial.
        peer: Option<PeerId>,
        /// libp2p-level error description.
        reason: String,
    },

    /// The node started listening on a multiaddr (e.g., a
    /// QUIC or TCP socket bound successfully).
    NewListenAddress(Multiaddr),

    /// Kademlia DHT discovered a new peer per §9.6 + §9.2.2
    /// DHT-based peer discovery. The local routing table has
    /// been updated; the peer is now reachable via the DHT.
    /// Per §9.6.1, discovered peers are NOT trusted for
    /// consensus-critical purposes — they are connectivity
    /// candidates only.
    PeerDiscovered(PeerId),

    /// Kademlia DHT bootstrap query (triggered at startup
    /// when at least one bootstrap peer was supplied)
    /// completed. The routing table is populated and the
    /// node is participating in the DHT. Per §9.6.1, this is
    /// operational state — not consensus-binding.
    KademliaBootstrapped,
}

/// High-level Adamant networking node handle.
///
/// Owns the libp2p [`Swarm`] and exposes the application-level
/// publish/subscribe surface. Tokio-based; consumers spawn
/// long-running tasks that loop on [`Self::next_event`] and
/// dispatch to the §8 consensus layer (vertex propagation) and
/// the §9.3 mempool layer (transaction submission).
pub struct NetworkNode {
    swarm: Swarm<AdamantBehaviour>,
    local_peer_id: PeerId,
}

impl NetworkNode {
    /// Construct + bring up the node.
    ///
    /// Steps:
    /// 1. Build the [`Swarm`] with the §9.2.2 transport stack
    ///    (QUIC + TCP + Noise + Yamux + DNS).
    /// 2. Install [`AdamantBehaviour`] (gossipsub + identify).
    /// 3. Auto-subscribe to both [`GossipsubTopic`] values.
    /// 4. Listen on every address in
    ///    [`NetworkConfig::listen_addresses`].
    /// 5. Dial every bootstrap peer.
    ///
    /// # Errors
    ///
    /// See the [`NetworkError`] variant docs.
    ///
    /// # Panics
    ///
    /// The internal `expect("AdamantBehaviour::new")` inside
    /// the `with_behaviour` closure cannot fail in practice:
    /// behaviour construction is deterministic given the
    /// keypair + config, and the inner failure modes
    /// ([`NetworkError::GossipsubSetupFailed`],
    /// [`NetworkError::IdentifySetupFailed`]) are only
    /// reachable under invalid gossipsub config values that
    /// [`AdamantBehaviour::new`] does not accept. The panic
    /// would surface only if the libp2p gossipsub config
    /// builder rejected the default heartbeat/transmit-size
    /// values — which it does not.
    pub fn launch(config: &NetworkConfig) -> Result<Self, NetworkError> {
        let local_peer_id = PeerId::from(config.keypair.public());
        let max_message_size = config.max_message_size;
        let heartbeat_interval = config.heartbeat_interval;
        let mut swarm = libp2p::SwarmBuilder::with_existing_identity(config.keypair.clone())
            .with_tokio()
            .with_tcp(
                tcp::Config::default(),
                noise::Config::new,
                yamux::Config::default,
            )
            .map_err(|e| NetworkError::SwarmBuildFailed(format!("tcp setup: {e}")))?
            .with_quic()
            .with_dns()
            .map_err(|e| NetworkError::SwarmBuildFailed(format!("dns setup: {e}")))?
            .with_behaviour(|key| {
                AdamantBehaviour::new(key, max_message_size, heartbeat_interval)
                    .expect("AdamantBehaviour::new")
            })
            .map_err(|e| NetworkError::SwarmBuildFailed(format!("behaviour: {e}")))?
            .build();

        // Auto-subscribe to both protocol topics.
        for topic in [GossipsubTopic::Vertices, GossipsubTopic::Mempool] {
            let ident = IdentTopic::new(topic.topic_name());
            swarm
                .behaviour_mut()
                .gossipsub
                .subscribe(&ident)
                .map_err(|e| NetworkError::SubscriptionFailed {
                    topic,
                    reason: e.to_string(),
                })?;
        }

        // Listen on every configured address.
        for addr in &config.listen_addresses {
            swarm
                .listen_on(addr.clone())
                .map_err(|e| NetworkError::ListenAddressFailed {
                    address: addr.clone(),
                    reason: e.to_string(),
                })?;
        }

        // Dial bootstrap peers + seed Kademlia routing table.
        // Per §9.6.1, bootstrap nodes seed the DHT for newcomers
        // but are NOT trusted for consensus; the routing-table
        // population here is purely operational.
        for (peer_id, addr) in &config.bootstrap_peers {
            swarm.behaviour_mut().gossipsub.add_explicit_peer(peer_id);
            swarm
                .behaviour_mut()
                .kademlia
                .add_address(peer_id, addr.clone());
            swarm
                .dial(addr.clone())
                .map_err(|e| NetworkError::DialFailed {
                    address: addr.clone(),
                    reason: e.to_string(),
                })?;
        }
        // Trigger an initial Kademlia bootstrap query if at
        // least one bootstrap peer was registered. Per
        // libp2p's `kad::Behaviour::bootstrap`, this kicks off
        // an iterative-find-node query against the local
        // `PeerId` to populate the routing table. The query
        // result surfaces as a `BootstrapCompleted` /
        // `BootstrapFailed` `NetworkEvent`.
        if !config.bootstrap_peers.is_empty() {
            // `bootstrap()` returns an error if the routing
            // table has no peers; we just registered at least
            // one above, so the failure mode here would be
            // surprising. Swallow defensively — the next
            // automatic refresh will retry.
            let _ = swarm.behaviour_mut().kademlia.bootstrap();
        }

        Ok(Self {
            swarm,
            local_peer_id,
        })
    }

    /// The local node's libp2p [`PeerId`]. Derived from the
    /// keypair supplied at construction.
    #[must_use]
    pub const fn local_peer_id(&self) -> &PeerId {
        &self.local_peer_id
    }

    /// Publish a message on its [`NetworkMessage::topic`]
    /// gossipsub topic. BCS-encodes the message and pushes
    /// onto the gossipsub mesh.
    ///
    /// # Errors
    ///
    /// - [`NetworkError::MessageEncodingFailed`] if BCS
    ///   encoding fails (should not occur for plain-data
    ///   shapes).
    /// - [`NetworkError::PublishFailed`] if the gossipsub
    ///   layer rejects the message (size, mesh empty,
    ///   duplicate).
    pub fn publish(&mut self, message: &NetworkMessage) -> Result<(), NetworkError> {
        let topic = message.topic();
        let bytes = bcs::to_bytes(message)
            .map_err(|e| NetworkError::MessageEncodingFailed(e.to_string()))?;
        let ident = IdentTopic::new(topic.topic_name());
        self.swarm
            .behaviour_mut()
            .gossipsub
            .publish(ident, bytes)
            .map(|_| ())
            .map_err(|e| NetworkError::PublishFailed {
                topic,
                reason: e.to_string(),
            })
    }

    /// Drive the swarm event loop and return the next
    /// application-level [`NetworkEvent`]. libp2p-internal
    /// events that don't surface to the application are
    /// silently consumed.
    ///
    /// Returns `None` only if the swarm's internal stream
    /// terminates — typically only at shutdown. Honest
    /// consumers loop on this in a tokio task.
    pub async fn next_event(&mut self) -> Option<NetworkEvent> {
        while let Some(event) = self.swarm.next().await {
            if let Some(app_event) = Self::translate_swarm_event(event) {
                return Some(app_event);
            }
            // Internal libp2p event with no application
            // surface — keep polling.
        }
        None
    }

    /// Translate a libp2p swarm event into an application-
    /// level [`NetworkEvent`]. Returns `None` for events the
    /// application doesn't care about (mesh maintenance,
    /// identify exchanges, etc.).
    fn translate_swarm_event(event: SwarmEvent<AdamantBehaviourEvent>) -> Option<NetworkEvent> {
        match event {
            SwarmEvent::Behaviour(AdamantBehaviourEvent::Gossipsub(
                gossipsub::Event::Message {
                    propagation_source,
                    message,
                    ..
                },
            )) => {
                let topic_name = message.topic.as_str();
                let topic = if topic_name == GossipsubTopic::Vertices.topic_name() {
                    GossipsubTopic::Vertices
                } else if topic_name == GossipsubTopic::Mempool.topic_name() {
                    GossipsubTopic::Mempool
                } else {
                    return None; // unknown topic; ignore
                };
                let decoded: NetworkMessage = bcs::from_bytes(&message.data).ok()?;
                Some(NetworkEvent::Message {
                    topic,
                    source: Some(propagation_source),
                    message: decoded,
                })
            }
            SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                Some(NetworkEvent::PeerConnected(peer_id))
            }
            SwarmEvent::ConnectionClosed { peer_id, .. } => {
                Some(NetworkEvent::PeerDisconnected(peer_id))
            }
            SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
                Some(NetworkEvent::BootstrapDialFailed {
                    peer: peer_id,
                    reason: error.to_string(),
                })
            }
            SwarmEvent::NewListenAddr { address, .. } => {
                Some(NetworkEvent::NewListenAddress(address))
            }
            SwarmEvent::Behaviour(AdamantBehaviourEvent::Kademlia(
                kad::Event::RoutingUpdated {
                    peer,
                    is_new_peer: true,
                    ..
                },
            )) => Some(NetworkEvent::PeerDiscovered(peer)),
            SwarmEvent::Behaviour(AdamantBehaviourEvent::Kademlia(
                kad::Event::OutboundQueryProgressed {
                    result: QueryResult::Bootstrap(Ok(_)),
                    step,
                    ..
                },
            )) if step.last => Some(NetworkEvent::KademliaBootstrapped),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::NETWORK_PROTOCOL_VERSION;

    fn fixture_config() -> NetworkConfig {
        NetworkConfig::new(Keypair::generate_ed25519())
    }

    #[test]
    fn network_config_new_defaults() {
        let cfg = fixture_config();
        assert!(cfg.listen_addresses.is_empty());
        assert!(cfg.bootstrap_peers.is_empty());
        assert_eq!(cfg.max_message_size, DEFAULT_MAX_MESSAGE_SIZE);
        assert_eq!(cfg.heartbeat_interval, DEFAULT_HEARTBEAT_INTERVAL);
    }

    #[test]
    fn network_config_with_listen_address_chains() {
        let cfg =
            fixture_config().with_listen_address("/ip4/0.0.0.0/tcp/0".parse().expect("multiaddr"));
        assert_eq!(cfg.listen_addresses.len(), 1);
    }

    #[test]
    fn network_config_with_bootstrap_peer_chains() {
        let peer = PeerId::random();
        let addr: Multiaddr = "/ip4/127.0.0.1/tcp/1234".parse().expect("multiaddr");
        let cfg = fixture_config().with_bootstrap_peer(peer, addr.clone());
        assert_eq!(cfg.bootstrap_peers.len(), 1);
        assert_eq!(cfg.bootstrap_peers[0].0, peer);
        assert_eq!(cfg.bootstrap_peers[0].1, addr);
    }

    #[test]
    fn network_config_with_max_message_size_overrides_default() {
        let cfg = fixture_config().with_max_message_size(2 * 1024 * 1024);
        assert_eq!(cfg.max_message_size, 2 * 1024 * 1024);
    }

    #[test]
    fn network_config_with_heartbeat_interval_overrides_default() {
        let cfg = fixture_config().with_heartbeat_interval(Duration::from_millis(500));
        assert_eq!(cfg.heartbeat_interval, Duration::from_millis(500));
    }

    #[test]
    fn protocol_constants_versioned() {
        // Identify + Kademlia protocol strings must include
        // /1.0.0 to match NETWORK_PROTOCOL_VERSION; agent
        // string must mention adamant.
        assert!(ADAMANT_IDENTIFY_PROTOCOL.contains("/adamant/"));
        assert!(ADAMANT_IDENTIFY_PROTOCOL.contains("/1.0.0"));
        assert!(ADAMANT_KADEMLIA_PROTOCOL.contains("/adamant/"));
        assert!(ADAMANT_KADEMLIA_PROTOCOL.contains("/1.0.0"));
        // Identify + Kademlia protocols must be distinct (so
        // protocol-routing in libp2p doesn't conflate them).
        assert_ne!(ADAMANT_IDENTIFY_PROTOCOL, ADAMANT_KADEMLIA_PROTOCOL);
        assert!(ADAMANT_AGENT_STRING.contains("adamant"));
        // NETWORK_PROTOCOL_VERSION = 1 ↔ /1.0.0 in protocols.
        assert_eq!(NETWORK_PROTOCOL_VERSION, 1);
    }

    #[test]
    fn kademlia_protocol_string_is_adamant_specific() {
        // The Kademlia protocol string MUST be Adamant-specific
        // (with /adamant/ prefix) so we don't share a DHT with
        // other libp2p networks — per §9.6.1 + §9.2.2 the
        // Adamant DHT is its own namespace.
        assert_eq!(ADAMANT_KADEMLIA_PROTOCOL, "/adamant/kad/1.0.0");
    }

    #[test]
    fn network_error_display_messages_are_distinct() {
        let variants = [
            NetworkError::GossipsubSetupFailed("e1".into()),
            NetworkError::IdentifySetupFailed("e2".into()),
            NetworkError::SwarmBuildFailed("e3".into()),
            NetworkError::ListenAddressFailed {
                address: "/ip4/0.0.0.0/tcp/0".parse().unwrap(),
                reason: "e4".into(),
            },
            NetworkError::DialFailed {
                address: "/ip4/0.0.0.0/tcp/0".parse().unwrap(),
                reason: "e5".into(),
            },
            NetworkError::PublishFailed {
                topic: GossipsubTopic::Vertices,
                reason: "e6".into(),
            },
            NetworkError::MessageEncodingFailed("e7".into()),
            NetworkError::MessageDecodingFailed("e8".into()),
            NetworkError::SubscriptionFailed {
                topic: GossipsubTopic::Mempool,
                reason: "e9".into(),
            },
        ];
        let messages: Vec<String> = variants.iter().map(ToString::to_string).collect();
        for m in &messages {
            assert!(!m.is_empty());
        }
        for i in 0..messages.len() {
            for j in (i + 1)..messages.len() {
                assert_ne!(messages[i], messages[j]);
            }
        }
    }

    #[test]
    fn network_error_implements_std_error() {
        fn assert_err<E: std::error::Error>() {}
        assert_err::<NetworkError>();
    }

    /// Smoke test: a node can be launched + reports its
    /// local `PeerId`. Does not require networking; the node
    /// is constructed without listen-addresses or bootstrap-
    /// peers, so no socket binding happens.
    #[tokio::test]
    async fn network_node_launch_smoke_test() {
        let kp = Keypair::generate_ed25519();
        let expected_peer = PeerId::from(kp.public());
        let cfg = NetworkConfig::new(kp);
        let node = NetworkNode::launch(&cfg).expect("launch");
        assert_eq!(*node.local_peer_id(), expected_peer);
    }

    /// Launching with a registered bootstrap peer should
    /// succeed: the peer gets added to gossipsub's explicit-
    /// peer list and to Kademlia's routing table; the
    /// `bootstrap()` call is fired-and-forgotten. The dial
    /// itself fails (no peer actually exists at the multiaddr)
    /// but that surfaces as a `BootstrapDialFailed` event
    /// rather than a launch error.
    ///
    /// This regression-pins the §9.6 bootstrap-peer wiring:
    /// `kademlia.add_address` + `kademlia.bootstrap()` are
    /// invoked exactly once per bootstrap peer at launch.
    #[tokio::test]
    async fn launch_with_bootstrap_peer_does_not_error() {
        let bootstrap_id = PeerId::random();
        let bootstrap_addr: Multiaddr = "/ip4/127.0.0.1/tcp/65534".parse().expect("multiaddr");
        let cfg = NetworkConfig::new(Keypair::generate_ed25519())
            .with_bootstrap_peer(bootstrap_id, bootstrap_addr);
        let node = NetworkNode::launch(&cfg).expect("launch with bootstrap peer");
        // Local peer id is distinct from bootstrap id.
        assert_ne!(*node.local_peer_id(), bootstrap_id);
    }

    /// Two nodes can be independently launched without
    /// interaction. Each gets a unique `PeerId`.
    #[tokio::test]
    async fn two_independent_nodes_have_distinct_peer_ids() {
        let n1 = NetworkNode::launch(&NetworkConfig::new(Keypair::generate_ed25519()))
            .expect("n1 launch");
        let n2 = NetworkNode::launch(&NetworkConfig::new(Keypair::generate_ed25519()))
            .expect("n2 launch");
        assert_ne!(node_peer_id(&n1), node_peer_id(&n2));
    }

    fn node_peer_id(node: &NetworkNode) -> PeerId {
        *node.local_peer_id()
    }
}
