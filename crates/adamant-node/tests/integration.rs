//! Phase 9.4 end-to-end node integration tests.
//!
//! Exercises the cross-crate boundaries of the validator-node
//! library at the binary-integration tier. Each test wires
//! together at least three crates (adamant-node →
//! adamant-network → adamant-consensus) and exercises a
//! realistic validator-side query / mempool / DAG flow.
//!
//! Phase 9.4 scope: library-tier integration only. Cross-
//! process / cross-node networking tests (two `NodeRuntime`
//! instances gossiping vertices to each other) would require
//! port-binding fixtures and TCP/QUIC liveness, which is
//! flaky in CI. Those land at Phase 10's testnet workstream.

use adamant_consensus::{ActiveSet, EpochNumber, ValidatorPublicKeys, MIN_VALIDATOR_STAKE_LAUNCH};
use adamant_network::libp2p_re::Keypair;
use adamant_node::{NodeConfig, NodeRuntime};

fn fixture_validator_keys(seed: u8) -> ValidatorPublicKeys {
    ValidatorPublicKeys::new([seed; 32], [seed; 1952], [seed; 96])
}

/// Build an active set with `n` validators at the launch
/// minimum stake.
fn fixture_active_set(n: u8) -> ActiveSet {
    let mut s = ActiveSet::new();
    for seed in 1..=n {
        let id = fixture_validator_keys(seed).derive_id();
        s.register(id, EpochNumber::default()).expect("register");
    }
    s
}

/// Headline integration: launch a node, query its identity +
/// initial state, confirm the expected shape end-to-end. This
/// pins the full Phase 9.0 wiring path.
#[tokio::test]
async fn node_launches_with_correct_identity_and_initial_state() {
    let cfg = NodeConfig::new(
        Keypair::generate_ed25519(),
        fixture_validator_keys(1),
        fixture_active_set(7),
    );
    let expected_validator_id = fixture_validator_keys(1).derive_id();

    let node = NodeRuntime::launch(cfg).expect("launch");

    assert_eq!(node.validator_id(), expected_validator_id);
    assert_eq!(node.epoch(), EpochNumber::default());
    assert!(node.dag().is_empty(), "DAG starts empty at launch");
    assert!(node.mempool().is_empty(), "mempool starts empty at launch");
    assert_eq!(node.active_set().active_size(), 7);
}

/// Three independent nodes coexist with distinct network
/// identities + distinct validator identities. Pins the
/// per-node-per-validator distinctness property at the
/// integration tier.
#[tokio::test]
async fn multiple_nodes_have_distinct_identities() {
    let mut runtimes = Vec::new();
    for seed in 1..=3u8 {
        let cfg = NodeConfig::new(
            Keypair::generate_ed25519(),
            fixture_validator_keys(seed),
            fixture_active_set(7),
        );
        runtimes.push(NodeRuntime::launch(cfg).expect("launch"));
    }
    // Pairwise-distinct network peer IDs.
    for i in 0..runtimes.len() {
        for j in (i + 1)..runtimes.len() {
            assert_ne!(
                runtimes[i].network_peer_id(),
                runtimes[j].network_peer_id(),
                "pairwise-distinct peer IDs"
            );
            assert_ne!(
                runtimes[i].validator_id(),
                runtimes[j].validator_id(),
                "pairwise-distinct validator IDs"
            );
        }
    }
}

/// Active-set tier signal is observable through the node API.
/// Pins the §8.1.7 boundary at the integration tier — the
/// node's exposed `active_set()` accessor returns a value
/// whose `tier()` method matches expected.
#[tokio::test]
async fn active_set_tier_observable_through_node() {
    use adamant_consensus::SecurityTier;

    // Tier I at floor (n=7).
    let cfg_tier1 = NodeConfig::new(
        Keypair::generate_ed25519(),
        fixture_validator_keys(1),
        fixture_active_set(7),
    );
    let node_tier1 = NodeRuntime::launch(cfg_tier1).expect("launch tier1");
    assert_eq!(node_tier1.active_set().tier(), Some(SecurityTier::Tier1));

    // Tier II at n=15.
    let cfg_tier2 = NodeConfig::new(
        Keypair::generate_ed25519(),
        fixture_validator_keys(1),
        fixture_active_set(15),
    );
    let node_tier2 = NodeRuntime::launch(cfg_tier2).expect("launch tier2");
    assert_eq!(node_tier2.active_set().tier(), Some(SecurityTier::Tier2));

    // Tier III at n=30.
    let cfg_tier3 = NodeConfig::new(
        Keypair::generate_ed25519(),
        fixture_validator_keys(1),
        fixture_active_set(30),
    );
    let node_tier3 = NodeRuntime::launch(cfg_tier3).expect("launch tier3");
    assert_eq!(node_tier3.active_set().tier(), Some(SecurityTier::Tier3));
}

/// `MIN_VALIDATOR_STAKE_LAUNCH` is observable at the integration
/// boundary. Pins the constitutional constant per §8.1.6 +
/// §11.5.4.
#[tokio::test]
async fn min_validator_stake_constant_accessible() {
    // 1000 ADM = 1_000_000_000 micro-units per §8.1.6.
    assert_eq!(MIN_VALIDATOR_STAKE_LAUNCH.as_micro_units(), 1_000_000_000);
}

/// Launching a node with empty config (no listen addresses,
/// no bootstrap peers) succeeds. This is the smoke-test for
/// the §9.6.1 "bootstrap peers are not required for correctness"
/// posture: a node CAN start in isolation and observe the
/// gossipsub when peers connect later.
#[tokio::test]
async fn node_launches_in_isolation_without_bootstrap_peers() {
    let cfg = NodeConfig::new(
        Keypair::generate_ed25519(),
        fixture_validator_keys(1),
        fixture_active_set(7),
    );
    assert!(cfg.bootstrap_peers.is_empty());
    assert!(cfg.listen_addresses.is_empty());

    let node = NodeRuntime::launch(cfg).expect("isolation launch");
    // Validator identity + DAG state still wired correctly.
    assert_eq!(node.validator_id(), fixture_validator_keys(1).derive_id());
    assert!(node.dag().is_empty());
}
