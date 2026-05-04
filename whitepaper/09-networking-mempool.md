# 9. Networking & Mempool

This section specifies the network layer of Adamant: how nodes find each other, how transactions reach validators, how messages are propagated, and how network-level metadata is protected. It complements section 8 (Consensus) by specifying the infrastructure on which consensus operates.

The networking layer follows Principle II (privacy by default) and Principle VII (permissionless participation): the network is open, the protocols are public, and the metadata is protected to the extent practical.

## 9.1 Architectural overview

The network comprises four classes of node:

1. **Validators.** Participate in consensus (section 8), maintain full state, generate proofs.
2. **Full nodes.** Maintain full state and verify all transactions but do not participate in consensus. Operated by exchanges, indexers, archive services, and security-conscious individual users.
3. **Light clients.** Maintain only the recursive proof and Merkle paths to specific state of interest. Wallets typically operate as light clients.
4. **Archive nodes.** Maintain historical state beyond what active state requires (section 5.6.2). Voluntary participants.

All four classes communicate over the same peer-to-peer network. There is no separate "validator network" or "user network"; a single permissionless overlay connects everyone.

## 9.2 The libp2p substrate

The protocol's network layer uses **libp2p**, the modular peer-to-peer networking framework originally developed for IPFS and now the de facto standard for blockchain peer-to-peer networks.

### 9.2.1 Why libp2p

The protocol does not roll its own peer-to-peer stack. libp2p is used by Ethereum (consensus and execution clients), Polkadot, Filecoin, Cosmos chains, and many others. It provides:

- **Pluggable transports.** TCP, QUIC, WebSockets, WebTransport — all interchangeable.
- **Pluggable security.** Noise protocol, TLS 1.3 — both supported with strong security properties.
- **Multiplexing.** Multiple logical streams over a single connection.
- **Peer discovery.** Kademlia DHT, mDNS, bootstrap nodes — all standard.
- **Pubsub.** Gossip-based message dissemination.
- **NAT traversal.** Hole punching, AutoRelay — for nodes behind firewalls.

Implementing each of these from scratch would consume engineering effort with no marginal benefit. libp2p is a known-good choice (Principle VI: standard primitives, novel synthesis).

### 9.2.2 Specific libp2p configuration

The protocol uses:

- **Transport:** QUIC primary, TCP fallback. QUIC's built-in encryption, multiplexing, and connection migration are well-suited to a high-throughput chain.
- **Security:** Noise protocol with the `Noise_XX` handshake pattern, providing forward secrecy and mutual authentication.
- **Multiplexing:** Yamux for stream multiplexing within QUIC connections.
- **Discovery:** Kademlia DHT for peer discovery, with bootstrap nodes published in the genesis specification (section 11). The bootstrap nodes are not "trusted"; they are simply the initial seeds for DHT participation. Once the DHT is populated, bootstrap nodes are not specially privileged.
- **Pubsub:** `gossipsub` v1.1 for message dissemination, with Adamant-specific topic configuration.

### 9.2.3 No central servers

The protocol's networking design has no central servers, no required relays, and no participants whose role is to mediate the network. Bootstrap nodes are convenient seeds for new clients to find peers; the network functions identically without them once peers know each other.

This is consistent with Principle I (credible neutrality): there is no infrastructure component whose operator can selectively block or surveil network participation.

## 9.3 Transaction propagation

When a user submits a transaction, the following sequence occurs:

1. **Wallet construction.** The wallet constructs the transaction, signs it under the account's validation logic, and (for shielded transactions) generates the Halo 2 proof.
2. **Encryption (optional).** For mempool privacy, the wallet encrypts the transaction to the upcoming epoch's threshold key (section 8.4.2). The encrypted envelope contains the transaction and the proof.
3. **Submission.** The wallet submits the (possibly encrypted) transaction to one or more nodes, typically via a `gossipsub` topic dedicated to mempool messages.
4. **Gossip propagation.** Nodes propagate the transaction to their peers using `gossipsub`'s mesh-based dissemination. Within seconds, the transaction is known to all validators.
5. **Mempool inclusion.** Validators add the transaction to their local mempool, ranked by fee (section 10).
6. **Consensus inclusion.** Validators include high-priority mempool transactions in their next vertex (section 8.3.1).

This is the standard pattern for blockchain transaction propagation. The Adamant-specific elements are the encryption (step 2) and the multi-dimensional fee ranking (step 5).

### 9.3.1 Transaction format

A transaction submitted to the network has the following structure:

```
NetworkTransaction {
    version:           u8,          // protocol version
    encryption_mode:   u8,          // 0 = transparent, 1 = encrypted
    payload:           Bytes,       // the transaction or its encrypted envelope
    fee_tip:           u64,         // ADM the user is willing to pay above base fee
    expiration_round:  u64,         // round after which this tx is invalid
    submission_proof:  Option<...>, // anti-DoS rate-limiting proof
}
```

The `expiration_round` prevents indefinite mempool retention: a transaction not included by its expiration round is dropped. This bounds mempool memory and prevents stale transactions from being included long after the user assumed they had failed.

The `submission_proof` is a small computational proof attached to mempool submissions to prevent denial-of-service attacks (subsection 9.5).

### 9.3.2 Transaction sizes

Typical transaction sizes:

- **Simple transparent transfer:** ~200-400 bytes
- **Shielded transfer (single input, two outputs):** ~2-4 KB (dominated by the Halo 2 proof)
- **Complex shielded contract execution:** ~4-10 KB
- **Account creation (with dual-signature setup):** ~5 KB

The chain's bandwidth requirement at 200,000 TPS with mostly-shielded transactions is approximately 600 MB/sec aggregate across all validators. Per-validator bandwidth is approximately 3-6 MB/sec, well within consumer-grade home-internet capabilities.

### 9.3.3 Mempool replacement

Users may replace a previously-submitted transaction by submitting a new transaction with the same nonce and a higher fee. This is the standard "RBF" (replace-by-fee) pattern from Bitcoin and other chains, adapted to Adamant's transaction model.

Replacement is constrained: the replacing transaction must offer a fee at least 10% higher than the original, and replacement is permitted only before the original is included in a vertex. Once a transaction enters consensus, it cannot be replaced; users must wait for it to either commit or expire.

## 9.4 Network-layer privacy

The chain's cryptographic privacy (section 7) protects the contents of transactions. The networking layer's privacy protects the *metadata* — who is sending what, to whom, when, from where.

### 9.4.1 Default transport encryption

All node-to-node communication is encrypted via libp2p's Noise transport (subsection 9.2.2). Network observers see only encrypted traffic between peers; they cannot read transaction contents in flight, peer messages, or consensus communications.

This is the baseline. Network observers without privileged position learn:

- Which IP addresses participate as nodes (visible to anyone running their own libp2p node)
- Approximate traffic volumes between peers (visible to observers with traffic-analysis capability)
- Approximate transaction submission times (visible to observers near the user's IP)

These observations leak metadata. The protocol provides additional defences for users who require stronger privacy.

### 9.4.2 Onion routing

The protocol supports onion-routed transaction submission for users requiring strong network-level privacy. Onion routing follows the Tor and I2P models:

- The user's wallet selects a chain of relay nodes (typically 3) from the network.
- The transaction is encrypted in layers, one per relay.
- Each relay decrypts one layer, learning only the next hop (not the original source or the final destination).
- The final relay submits the transaction to the mempool.

The protocol does not specify the relay-selection mechanism; this is a wallet-level concern. Relays are not privileged validators; they are ordinary network participants who opt in to relaying. Relay operation is not rewarded by the protocol (it is a community-provided service); the protocol provides the cryptographic tools to support it.

### 9.4.3 Timing obfuscation

Sophisticated network observers can correlate transaction submissions to specific users through timing analysis: a user's transaction appears in the mempool seconds after they performed a related off-chain action. The protocol's defences:

- **Random submission delay.** Wallets `SHOULD` introduce small random delays (uniform in [0, 5] seconds) between user actions and transaction submission. This breaks tight timing correlations.
- **Submission batching.** Wallets `MAY` batch multiple user transactions and submit them together at predictable intervals (e.g. once per minute). This is a stronger obfuscation but introduces user-visible latency.

These defences are wallet-level, not protocol-level. The protocol allows them; the protocol does not enforce them.

### 9.4.4 What network-level privacy does not provide

Network-level privacy is a useful complement to cryptographic privacy but does not replace it:

- Onion routing protects the IP-level source of submissions but does not hide the existence of the submission itself. An observer monitoring all relays could still observe that *some* transaction was submitted at a given time.
- Timing obfuscation reduces correlation power but does not eliminate it. Determined adversaries with broad surveillance capabilities can still construct probabilistic associations.
- A user whose identity is exposed off-chain (by interacting with services that know their identity) cannot be made anonymous by network-level protections alone.

Users requiring strong end-to-end privacy combine: (a) cryptographic privacy at the transaction layer, (b) network-level privacy via onion routing, (c) careful operational security including separate identities for sensitive activities. The protocol provides the first two; the third is the user's responsibility.

## 9.5 Anti-denial-of-service

A permissionless network is susceptible to denial-of-service attacks: adversaries flooding the network with low-value transactions to consume validator resources. The protocol's defences operate at multiple layers:

### 9.5.1 Submission proofs

Mempool submissions include a small computational proof (typically a 50-100ms PoW puzzle, parameterised based on current network load). This is not a "mining" mechanism; it is a rate-limiter. Honest users barely notice it; spam-flooders find their submission rate capped.

The proof difficulty is adjusted dynamically per-node: heavily-loaded nodes increase difficulty; lightly-loaded nodes decrease it. This adapts to current attack pressure without requiring intervention.

### 9.5.2 Fee floors

Every transaction must pay at least a per-byte minimum fee to be relayed by the network. Validators discard transactions below this floor without propagating them. The floor is set high enough to make spam economically expensive while remaining negligible for real use (section 10).

### 9.5.3 Per-peer rate limiting

Each node imposes per-peer rate limits on incoming messages. Peers that exceed their limits are temporarily throttled or disconnected. Limits are conservative by default and adjust based on the peer's history (well-behaved peers earn higher limits).

### 9.5.4 Cryptographic verification before propagation

Before propagating a transaction, each node verifies its signature, its proofs, and its fee compliance. Invalid transactions are discarded immediately; they are not propagated. This prevents adversaries from amplifying attacks by submitting transactions whose validation cost is high but rejection is certain.

## 9.6 Discovery and bootstrapping

A new node joining the network needs to discover existing peers. The protocol's discovery mechanism uses libp2p's Kademlia DHT, seeded from a list of bootstrap nodes published in the genesis specification.

### 9.6.1 Bootstrap nodes

The genesis specification (section 11) includes a list of bootstrap node addresses. These are nodes operated by parties willing to maintain stable network presence for newcomers. They are not validators in any privileged sense; they are simply known endpoints.

A new node connects to one or more bootstrap nodes, queries the DHT for active peers, and joins the network. After this initial connection, the node maintains its peer list independently; bootstrap nodes are only needed for the initial join.

The protocol does not "trust" bootstrap nodes for any consensus-critical purpose. They cannot censor connections, lie about chain state (the new node will verify state independently), or otherwise compromise the protocol. They are convenience infrastructure.

### 9.6.2 Decentralisation of bootstrap

Multiple parties operate bootstrap nodes. The genesis specification lists at least 20 such nodes operated by independent parties at launch. Anyone may operate a bootstrap node by registering with the DHT; the genesis list is a starting point, not an exhaustive list.

If all genesis bootstrap nodes are simultaneously unavailable (a coordinated denial-of-service or coercive shutdown), new nodes can still discover peers through:

- mDNS for nodes on the same local network
- Manually-specified peer addresses
- Out-of-band peer lists shared via web, social media, or mesh networks

The chain remains operable even if every bootstrap node is taken down, though new-node onboarding becomes manual until alternative peer-discovery mechanisms repopulate.

## 9.7 Mempool design

Each validator maintains a local mempool of pending transactions. The mempool is a priority queue ranked by:

1. **Fee tip.** Transactions offering higher tips above the base fee are preferred.
2. **Submission time.** Among equally-tipped transactions, earlier submissions are preferred.
3. **Encrypted vs transparent.** Encrypted transactions are propagated identically to transparent ones; encryption does not affect mempool priority. (This is a deliberate choice: privileging one form over the other would create observable distinctions.)

### 9.7.1 Mempool size

Each validator maintains up to ~100,000 pending transactions in their mempool. When the mempool is full, the lowest-priority transactions are evicted to make room for higher-priority arrivals.

### 9.7.2 Mempool synchronisation

Validators do not maintain identical mempools. Each validator independently observes the gossipsub stream of transactions and decides which to retain. Different validators may have slightly different mempool contents at any given moment.

This is acceptable: consensus does not require validators to agree on mempool contents, only on which transactions are included in vertices. A validator who happens to have a transaction in their mempool may include it; another validator who does not have it cannot include it but does not stall consensus by its absence.

## 9.8 Network observability

The protocol's networking is designed to be observable for operational purposes (network health monitoring, abuse detection) without compromising user privacy.

What is observable:

- The set of active nodes (their IP addresses, libp2p peer IDs, and approximate liveness)
- Aggregate network traffic patterns
- Public consensus messages (vertices, signatures, recursive proof commitments)

What is not observable (without breaking transport encryption):

- The contents of specific transactions
- Specific peer-to-peer message contents
- Validator-internal computations

This observability supports the operation of a healthy decentralised network: anyone can monitor the network's health, identify misbehaving nodes, and contribute to community-level abuse mitigation. The same observability is bounded by the encryption protections that prevent it from becoming a surveillance vector.
