//! `adamant-light` binary entry point. Phase 9.2 scaffold:
//! launches a light-client runtime that joins the network,
//! reports its tier signal, and idles. Production deployment
//! requires the §8.9 recursive-proof verification wiring at
//! Phase 9.3+.

#![forbid(unsafe_code)]
#![allow(
    clippy::multiple_crate_versions,
    reason = "adamant-light binary transitively depends on libp2p \
              via adamant-network; same dup-version posture as the \
              other binary crates."
)]

use std::time::Duration;

use adamant_consensus::LightClientState;
use adamant_light::{LightNodeConfig, LightNodeRuntime};
use adamant_network::libp2p_re::{Keypair, Multiaddr};

#[tokio::main]
async fn main() {
    let keypair = Keypair::generate_ed25519();
    let initial_state = LightClientState::new();
    let listen_addr: Multiaddr = "/ip4/0.0.0.0/udp/0/quic-v1".parse().expect("multiaddr");
    let config = LightNodeConfig::new(keypair, initial_state).with_listen_address(listen_addr);

    let node = match LightNodeRuntime::launch(config) {
        Ok(n) => n,
        Err(e) => {
            eprintln!("adamant-light: launch failed: {e}");
            std::process::exit(1);
        }
    };
    println!(
        "adamant-light: launched. peer id = {}, tier = {:?}",
        node.network_peer_id(),
        node.tier_signal().map(|s| s.tier)
    );
    println!("adamant-light: Phase 9.2 scaffold — no boundary-ingestion driver yet.");
    println!("adamant-light: idling for 5 seconds then exiting.");
    tokio::time::sleep(Duration::from_secs(5)).await;
    println!("adamant-light: exit.");
}
