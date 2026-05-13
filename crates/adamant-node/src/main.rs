#![allow(
    clippy::multiple_crate_versions,
    reason = "adamant-node binary transitively depends on libp2p via \
              adamant-network; same dup-version posture as the lib."
)]

//! `adamant-node` binary entry point.
//!
//! Phase 9.0 scaffold: launches a [`NodeRuntime`] with
//! sensible defaults + a fresh networking keypair + an empty
//! active-set fixture. Suitable for smoke-testing the binary
//! launch path; production deployment requires:
//!
//! - Networking keypair loaded from operator-managed key
//!   storage (filesystem / HSM / KMS).
//! - Validator-identity bundle (ML-DSA / Ed25519 / BLS keys)
//!   loaded from operator-managed key storage.
//! - Active-set snapshot recovered from chain state at
//!   startup.
//! - Bootstrap peers from the §11 genesis specification.
//! - CLI argument parsing (port, data-dir, log-level).
//!
//! Production CLI ergonomics + key-loading land at Phase 9.1
//! alongside the `adamant-cli` crate.

use std::time::Duration;

use adamant_consensus::{ActiveSet, EpochNumber, ValidatorPublicKeys};
use adamant_network::libp2p_re::{Keypair, Multiaddr};
use adamant_node::{NodeConfig, NodeRuntime};

#[tokio::main]
async fn main() {
    // Sensible-default startup: fresh keypair, fresh
    // identity, empty active-set. The binary launches,
    // confirms the network + consensus wiring, and waits for
    // shutdown.
    //
    // Production deployment will swap these placeholders for
    // operator-managed keys + chain-state-recovered active
    // set + genesis-spec bootstrap peers.
    let network_keypair = Keypair::generate_ed25519();
    let validator_identity = ValidatorPublicKeys::new([0u8; 32], [0u8; 1952], [0u8; 96], [0u8; 48]);
    let mut active_set = ActiveSet::new();
    active_set
        .register(validator_identity.derive_id(), EpochNumber::default())
        .expect("register self");

    let listen_addr: Multiaddr = "/ip4/0.0.0.0/udp/0/quic-v1".parse().expect("multiaddr");
    let config = NodeConfig::new(network_keypair, validator_identity, active_set)
        .with_listen_address(listen_addr);

    let node = match NodeRuntime::launch(config) {
        Ok(n) => n,
        Err(e) => {
            eprintln!("adamant-node: launch failed: {e}");
            std::process::exit(1);
        }
    };

    println!(
        "adamant-node: launched. network peer id = {}, validator id = {:?}",
        node.network_peer_id(),
        node.validator_id()
    );
    println!("adamant-node: Phase 9.0 scaffold — no event-loop driver yet.");
    println!("adamant-node: idling for 5 seconds then exiting.");
    tokio::time::sleep(Duration::from_secs(5)).await;
    println!("adamant-node: exit.");
}
