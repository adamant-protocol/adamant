//! Phase 9.4 end-to-end light-client integration tests.
//!
//! Exercises the cross-crate boundaries of the light client at
//! the binary-integration tier per whitepaper §8.9 + Principle
//! III. Each test wires together at least three crates
//! (adamant-light → adamant-consensus → adamant-state →
//! adamant-crypto → adamant-privacy when applicable) and
//! exercises a realistic light-client query flow.
//!
//! These tests complement the per-crate unit tests by pinning
//! the **integration shape**: the full path from a wallet
//! receiving an `EpochBoundary` artifact off the gossipsub
//! topic, advancing the `LightClientState`, then verifying a
//! `MerkleProof` against the latest commitment.

use adamant_consensus::{
    EpochBoundary, EpochNumber, LightClientState, ProofCommitment, SecurityTier, StateCommitment,
};
use adamant_light::state_re::{MerkleProof, SparseMerkleTree, StateKey};
use adamant_light::{LightNodeConfig, LightNodeRuntime};
use adamant_network::libp2p_re::Keypair;

/// Type alias for the `build_realistic_tree` return shape:
/// the tree, its root, and the (key, value) pairs that were
/// inserted.
type TreeBuildOutput = (SparseMerkleTree, [u8; 32], Vec<(StateKey, Vec<u8>)>);

/// Build a realistic state tree with multiple (key, value)
/// pairs spanning the 32-byte key space. Returns the tree, the
/// root, and a sample membership pair the tests will exercise.
fn build_realistic_tree() -> TreeBuildOutput {
    let mut tree = SparseMerkleTree::new();
    let pairs: Vec<(StateKey, Vec<u8>)> = vec![
        // Three accounts with different balance values.
        ([0x01; 32], b"account-alice-balance-1000".to_vec()),
        ([0x02; 32], b"account-bob-balance-500".to_vec()),
        ([0x03; 32], b"account-carol-balance-2500".to_vec()),
        // Two objects with distinct payloads.
        ([0xA0; 32], b"object-nft-token-id-42".to_vec()),
        ([0xB0; 32], b"object-shared-resource-config".to_vec()),
        // Two transaction-inclusion hashes.
        ([0xC0; 32], b"tx-included-2024-01-01".to_vec()),
        ([0xD0; 32], b"tx-included-2024-01-02".to_vec()),
    ];
    for (k, v) in &pairs {
        tree.insert(*k, v);
    }
    let root = tree.root();
    (tree, root, pairs)
}

fn boundary(epoch_n: u64, active_size: u32, root: [u8; 32]) -> EpochBoundary {
    EpochBoundary::new(
        EpochNumber::new(epoch_n),
        active_size,
        StateCommitment::from_bytes(root),
        ProofCommitment::from_bytes([0xBB; 32]),
    )
}

/// Headline integration: launch a light client, advance it
/// through a realistic state-tree epoch boundary, verify ALL
/// the published (key, value) claims hold, and verify a
/// non-membership claim for an absent key holds. This is the
/// canonical wallet-side §8.9 verification flow end-to-end.
#[tokio::test]
async fn wallet_side_verification_flow_end_to_end() {
    let cfg = LightNodeConfig::new(Keypair::generate_ed25519(), LightClientState::new());
    let mut node = LightNodeRuntime::launch(cfg).expect("launch");

    let (tree, root, pairs) = build_realistic_tree();
    node.advance(boundary(0, 15, root)).expect("advance");

    // Tier signal correctly derived from active-set size 15
    // per §8.1.7.
    let signal = node.tier_signal().expect("present");
    assert_eq!(signal.tier, Some(SecurityTier::Tier2));

    // Every published pair verifies as a member.
    for (key, value) in &pairs {
        let proof = tree.prove(key);
        assert!(
            node.verify_state_membership_claim(key, value, &proof),
            "expected membership for key {key:?}"
        );
    }

    // Two absent keys verify as non-members.
    for absent in [[0xEE; 32], [0xFF; 32]] {
        let proof = tree.prove(&absent);
        assert!(
            node.verify_state_non_membership_claim(&absent, &proof),
            "expected non-membership for key {absent:?}"
        );
    }
}

/// Multi-epoch advance: the light client tracks state through
/// successive epoch boundaries, and claim verification works
/// against whichever commitment is current. This pins the
/// "always against latest commitment" property.
#[tokio::test]
async fn claim_verification_uses_latest_commitment_across_epochs() {
    let cfg = LightNodeConfig::new(Keypair::generate_ed25519(), LightClientState::new());
    let mut node = LightNodeRuntime::launch(cfg).expect("launch");

    // Epoch 0: tree A.
    let mut tree_a = SparseMerkleTree::new();
    tree_a.insert([0x11; 32], b"epoch-0-value".as_ref());
    let root_a = tree_a.root();
    node.advance(boundary(0, 15, root_a)).expect("advance a");

    // Claim against tree A verifies under epoch-0 commitment.
    let proof_a = tree_a.prove(&[0x11; 32]);
    assert!(node.verify_state_membership_claim(&[0x11; 32], b"epoch-0-value", &proof_a));

    // Epoch 1: tree B (different content).
    let mut tree_b = SparseMerkleTree::new();
    tree_b.insert([0x11; 32], b"epoch-1-value".as_ref());
    let root_b = tree_b.root();
    node.advance(boundary(1, 15, root_b)).expect("advance b");

    // The previously-valid epoch-0 proof + value now FAIL
    // under the epoch-1 commitment. The light client always
    // verifies against the latest commitment per §8.9.
    assert!(!node.verify_state_membership_claim(&[0x11; 32], b"epoch-0-value", &proof_a));

    // The new tree-B proof + value succeed under epoch-1.
    let proof_b = tree_b.prove(&[0x11; 32]);
    assert!(node.verify_state_membership_claim(&[0x11; 32], b"epoch-1-value", &proof_b));
}

/// Adversary scenario: a service node returns a Merkle proof
/// against a structurally different tree than the honest
/// chain. The light client rejects the fabricated claim,
/// defending against a malicious service node.
#[tokio::test]
async fn adversarial_service_node_proof_rejected() {
    let cfg = LightNodeConfig::new(Keypair::generate_ed25519(), LightClientState::new());
    let mut node = LightNodeRuntime::launch(cfg).expect("launch");

    // The honest chain commits to a tree with TWO entries.
    let mut honest_tree = SparseMerkleTree::new();
    honest_tree.insert([0x11; 32], b"honest-value".as_ref());
    honest_tree.insert([0x22; 32], b"another-honest-entry".as_ref());
    let honest_root = honest_tree.root();
    node.advance(boundary(0, 15, honest_root)).expect("advance");

    // An adversarial service node constructs an alternate
    // tree with a fabricated value at the same key, but the
    // alternate tree differs structurally (different second
    // entry → different sibling chain → different root).
    let mut adversary_tree = SparseMerkleTree::new();
    adversary_tree.insert([0x11; 32], b"fabricated-value".as_ref());
    adversary_tree.insert([0x22; 32], b"adversary-injected-entry".as_ref());
    let adversary_proof = adversary_tree.prove(&[0x11; 32]);

    // Adversary's fabricated value with adversary's proof —
    // reconstructs the adversary's root, which does NOT match
    // the honest chain's commitment.
    assert!(
        !node.verify_state_membership_claim(&[0x11; 32], b"fabricated-value", &adversary_proof),
        "adversary's full claim should be rejected"
    );

    // The honest value with the adversary's proof also fails
    // — the sibling chain doesn't match the honest commitment.
    assert!(
        !node.verify_state_membership_claim(&[0x11; 32], b"honest-value", &adversary_proof),
        "honest value with adversary's proof should be rejected"
    );

    // Sanity: the honest proof against the honest value
    // succeeds. The chain's own claim verifies.
    let honest_proof = honest_tree.prove(&[0x11; 32]);
    assert!(
        node.verify_state_membership_claim(&[0x11; 32], b"honest-value", &honest_proof),
        "honest proof + honest value must verify"
    );
}

/// Tier-signal observability across the full §8.1.7 ladder.
/// Validators publish active-set size in the `EpochBoundary`;
/// wallets surface the tier signal so users can decide whether
/// to wait for finality. This test pins the §8.1.7 mapping
/// end-to-end through the light client.
#[tokio::test]
async fn tier_signal_tracks_active_set_changes() {
    let cfg = LightNodeConfig::new(Keypair::generate_ed25519(), LightClientState::new());
    let mut node = LightNodeRuntime::launch(cfg).expect("launch");

    let dummy_root = [0u8; 32];

    // n=7 → Tier I (just-above floor).
    node.advance(boundary(0, 7, dummy_root)).expect("0");
    assert_eq!(
        node.tier_signal().expect("a").tier,
        Some(SecurityTier::Tier1)
    );

    // n=15 → Tier II.
    node.advance(boundary(1, 15, dummy_root)).expect("1");
    assert_eq!(
        node.tier_signal().expect("b").tier,
        Some(SecurityTier::Tier2)
    );

    // n=30 → Tier III.
    node.advance(boundary(2, 30, dummy_root)).expect("2");
    assert_eq!(
        node.tier_signal().expect("c").tier,
        Some(SecurityTier::Tier3)
    );

    // n=75 → still Tier III (saturates at the top).
    node.advance(boundary(3, 75, dummy_root)).expect("3");
    assert_eq!(
        node.tier_signal().expect("d").tier,
        Some(SecurityTier::Tier3)
    );
}

/// Two independent light clients observing the same chain
/// converge on the same state-commitment view. This is the
/// §8.9 + §8.7 safety convergence property at the light-
/// client tier: same inputs → same state, regardless of
/// network topology or observation order.
#[tokio::test]
async fn parallel_light_clients_converge_to_same_state() {
    let cfg_a = LightNodeConfig::new(Keypair::generate_ed25519(), LightClientState::new());
    let cfg_b = LightNodeConfig::new(Keypair::generate_ed25519(), LightClientState::new());
    let mut node_a = LightNodeRuntime::launch(cfg_a).expect("a");
    let mut node_b = LightNodeRuntime::launch(cfg_b).expect("b");

    let (_tree, root, _pairs) = build_realistic_tree();

    for epoch_n in 0..5u64 {
        let b = boundary(epoch_n, 15, root);
        node_a.advance(b.clone()).expect("a advance");
        node_b.advance(b).expect("b advance");
    }

    // Independent observers, identical state.
    assert_eq!(node_a.state_commitment(), node_b.state_commitment());
    assert_eq!(node_a.proof_commitment(), node_b.proof_commitment());
    assert_eq!(
        node_a.tier_signal().map(|t| t.tier),
        node_b.tier_signal().map(|t| t.tier)
    );

    // The peer IDs differ (independent network identities) but
    // the chain-state views agree.
    assert_ne!(node_a.network_peer_id(), node_b.network_peer_id());
}

/// Malformed-proof defense at the integration tier. A proof
/// with wrong sibling-chain length is rejected without
/// panicking, even when the commitment is present.
#[tokio::test]
async fn malformed_proof_rejected_safely() {
    let cfg = LightNodeConfig::new(Keypair::generate_ed25519(), LightClientState::new());
    let mut node = LightNodeRuntime::launch(cfg).expect("launch");

    let (_tree, root, pairs) = build_realistic_tree();
    node.advance(boundary(0, 15, root)).expect("advance");

    let (key, value) = pairs.first().expect("first");

    // Proofs with all common malformed shapes.
    for bad_len in [0usize, 1, 10, 100, 255, 257, 1000] {
        let proof = MerkleProof::new(vec![[0xFFu8; 32]; bad_len]);
        assert!(
            !node.verify_state_membership_claim(key, value, &proof),
            "malformed proof of length {bad_len} should reject"
        );
    }
}
