# 1. Introduction & Motivation

## 1.1 The state of the art (2026)

Public blockchains have matured along several distinct axes since the Bitcoin whitepaper was published in 2008. Each axis has produced exemplary systems, and each has produced trade-offs that the broader ecosystem has implicitly accepted as inherent. This section reviews the current frontier on each axis and identifies the gap that Adamant is designed to fill.

### 1.1.1 Throughput and finality

The throughput frontier has moved from Bitcoin's 7 transactions per second to current production systems handling hundreds of thousands of transactions per second with sub-second finality. The Mysticeti consensus protocol, peer-reviewed at NDSS 2025 and deployed in the Sui blockchain, demonstrates a wide-area-network commit latency of approximately 500 milliseconds at sustained throughput exceeding 200,000 transactions per second on a single shard. Solana, through proof-of-history and parallel execution, has demonstrated similar throughput with different latency characteristics. Monad, Aptos, and Sei have shown that optimistic concurrency control via Block-STM-style algorithms can deliver order-of-magnitude improvements over the Ethereum Virtual Machine's strictly-sequential execution model.

These throughput gains do not come for free. Higher throughput typically requires higher hardware requirements for validators, which centralises participation; tighter coupling between consensus and execution, which reduces architectural flexibility; and in some cases optimistic models that require complex re-execution logic when transactions conflict.

### 1.1.2 Privacy

Privacy on public blockchains has progressed from Bitcoin's pseudonymous transparency to chains where transaction privacy is the default. Monero's ring signatures and stealth addresses, deployed since 2014, offer privacy for simple value transfers but limited programmability. Zcash's zero-knowledge proofs offer optional shielded transactions with strong cryptographic guarantees but a transparent default and limited smart-contract support. Aleo extends this model to private programmability with the Leo programming language but operates at modest throughput on the order of single-digit transactions per second.

The most significant recent development is Aztec Network, which entered mainnet on November 20, 2025 as the first Ethereum Layer 2 with general programmable privacy through the Noir domain-specific language. Aztec demonstrates that complex private smart contracts — including private DeFi primitives — are viable. As an Ethereum Layer 2, Aztec inherits Ethereum's settlement guarantees but is constrained by its proving costs (multi-second client-side proof generation for typical operations) and its dependence on Ethereum's evolving rollup framework.

No production Layer 1 blockchain combines high-throughput consensus with privacy by default. This is a structural gap, not an incidental one: privacy chains have been built without contemporary consensus, and high-throughput chains have been built without privacy.

### 1.1.3 Maximal extractable value (MEV) and censorship resistance

The transparency of public mempools has produced an industry of value extraction estimated at over $1.8 billion on Ethereum alone since 2020, primarily through front-running and sandwich attacks against decentralized exchange users. Mitigation efforts have followed two paths: out-of-protocol services such as MEV Blocker and Flashbots, which depend on trusted relays; and in-protocol cryptographic solutions such as the Shutter Network's threshold-encrypted mempool, deployed on Gnosis Chain.

Threshold encryption is a promising approach: transactions are encrypted by users and decryptable only by a quorum of "keypers" after ordering is committed, eliminating the visibility on which extraction depends. However, current deployments add significant latency. Shutter transactions on Gnosis Chain average approximately three minutes to inclusion due to keyper coordination overhead — acceptable for some use cases, prohibitive for most.

Censorship resistance suffers from a related class of problems. Where validators or sequencers can observe transaction contents before ordering, they can selectively exclude transactions based on origin, destination, or content. Most chains delegate this resistance to validator-set decentralisation rather than addressing it cryptographically.

### 1.1.4 Stateless verification and accessibility

The Ethereum Foundation's "Verge" roadmap targets a chain that can be verified by stateless clients carrying only cryptographic witnesses, enabled by Verkle trees and EIP-4444-style history expiry. As of July 2025, partial history expiry has begun rolling out across Ethereum execution clients. Mina Protocol, by contrast, has demonstrated since 2021 that recursive zero-knowledge proofs can compress the entire chain history into a constant-size proof verifiable on consumer devices, including smartphones.

The trade-off has been throughput: Mina prioritises succinctness over transaction volume. The combination of recursive verification *and* high throughput has not been demonstrated in a production system.

### 1.1.5 Account abstraction

Native account abstraction — where every account is a smart contract with programmable validation logic — is an established pattern on newer Layer 1 and Layer 2 chains including zkSync Era, StarkNet, and Aptos. Ethereum's ERC-4337, deployed in March 2023, achieves similar functionality through an out-of-protocol bundler architecture, with Ethereum's EIP-7702 (Pectra upgrade, May 2025) providing a hybrid path. Native implementations are simpler, more efficient, and treat all transactions uniformly, but require account abstraction to be designed into the chain at genesis rather than added later.

### 1.1.6 Post-quantum cryptography

The National Institute of Standards and Technology finalised post-quantum signature standards in August 2024: ML-DSA (FIPS 204, formerly CRYSTALS-Dilithium), SLH-DSA (FIPS 205, formerly SPHINCS+), and the forthcoming FN-DSA (FIPS 206, formerly Falcon). Recent benchmarks demonstrate that ML-DSA verification at security level 5 takes approximately 0.14 milliseconds on ARM-based laptops, compared to 0.88 milliseconds for ECDSA — meaning post-quantum signatures are not merely *acceptable* in performance terms but *superior* at the security levels relevant to long-term consensus security.

Despite this, no major chain has launched with post-quantum signatures as a default option. Polkadot has published a migration roadmap; Solana has run a Dilithium testnet with Project Eleven as of December 2025; both will require eventual hard forks to migrate user account keys. The cost of retrofitting post-quantum cryptography onto a deployed chain is significant; the cost of including it from genesis is negligible.

### 1.1.7 Credible neutrality

Bitcoin and Monero stand alone as programmable-money systems with credibly neutral governance. Both have no foundation that controls protocol direction, no on-chain governance mechanism that can be captured, and no admin keys. Protocol changes require social consensus expressed through node operators voluntarily upgrading client software. This property — that no party, including the original creators, can unilaterally modify the protocol — is what allows users to commit large amounts of value to these systems with confidence that the rules will not change adversarially.

Every chain that has launched with a foundation, treasury, or on-chain governance system has, by construction, sacrificed this property. Even chains with strong technical merits (Ethereum, Solana, Sui, Aptos) have foundations that, while behaving responsibly to date, retain the *capability* to coordinate protocol changes that users may not want. This capability is permanent once established. Once a chain has a foundation, it cannot be removed — the chain's history is bound to the foundation's existence.

A chain that wishes to be credibly neutral must commit to it at genesis. There is no path from "centrally-stewarded" to "credibly neutral" once the chain is running.

## 1.2 The gap

Each property described above is, in isolation, well understood and demonstrated in production:

| Property | Best demonstrated by | Year |
|----------|----------------------|------|
| 200k+ TPS, sub-second finality | Mysticeti / Sui | 2024 |
| Programmable privacy | Aztec | 2025 |
| Encrypted mempool (in production) | Shutter / Gnosis | 2024 |
| Phone-verifiable chain | Mina | 2021 |
| Native account abstraction | zkSync Era, StarkNet, Aptos | 2022–2024 |
| Post-quantum signatures | NIST standardisation | 2024 |
| Credible neutrality | Bitcoin, Monero | 2009, 2014 |

Adamant's throughput floor is 50,000+ TPS at design-target validator count rather than the 200,000+ TPS demonstrated by the Mysticeti / Sui line. This is a deliberate choice: a 200,000 TPS target on a DAG-BFT mechanism (where communication cost grows quadratically in validator count) implies an active set of approximately 200 validators, which in turn implies VPS-grade hardware at every validator. That hardware floor excludes the residential-fibre operators the protocol is designed to include. A 50,000 TPS floor tolerates an active-set ceiling of 75, which is feasible on consumer-desktop hardware on residential fibre. The 50,000 figure is a floor rather than a cap: actual throughput depends on the active set's aggregate hardware and network conditions, and routinely exceeds the floor when validators run better-than-baseline hardware. The reduction in headline throughput relative to the prior-art line is the engineering cost of preserving low-coordination launch and broad participation; 50,000 TPS remains substantially above the sustained throughput of any production L1 in 2026 and is an order of magnitude above the requirements of any consumer payment workload. The figure is subject to empirical validation on residential-fibre hardware before genesis.

The protocol's participation model is multi-tiered. Validators run consensus and threshold/time-lock mempool decryption on residential-fiber hardware. Provers (subsection 8.5.3) generate recursive proofs in a permissionless market, with validators retaining a fallback role at degraded cadence (subsection 8.5.4) to preserve phone-verifiability when the prover market is insufficient. Witnesses (subsection 8.7.2) perform attestation, data availability sampling, recursive proof verification, and fraud detection on phone-class hardware. Service nodes (subsection 9.10) provide light-client infrastructure. Each tier has bounded power; no single tier alone controls the chain.

The active validator set is dynamic. The constitutional floor is 7 validators — the smallest size at which Byzantine fault tolerance retains non-zero margin against correlated failures (at N=7 the chain tolerates f=2 Byzantine validators, so one Byzantine validator combined with one offline validator still leaves the chain inside its safety bound). The soft ceiling is 75 validators, set by the throughput-floor sizing argument above. Selection follows a first-come-first-served-with-persistent-membership rule: validators are admitted in registration order, and once admitted retain their slot continuously until they fail liveness duties or voluntarily unbond. This rewards commitment and continuity rather than hardware budget or stake size — a small home-fibre validator who registered early and stays online cannot be displaced by a wealthier latecomer with more stake or by a faster competitor with better hardware. The chain self-activates at the floor: block production begins the moment 7 validators are simultaneously registered, stake-eligible, and online, with no coordination event and no human-in-the-loop activation. Below the floor, the chain halts on disagreement rather than forking, preserving safety at the cost of liveness during periods of severe validator unavailability.

Adamant's post-quantum security posture is hybrid by deliberate design (Principle VIII, subsection 2.8). The identity layer — addresses, validator registrations, contract deployments, and any operation producing persistent on-chain identity binding — uses ML-DSA (FIPS 204) signatures and is post-quantum-secure. The privacy layer's key-agreement surface — stealth address derivation, encrypted memo delivery — uses ML-KEM (FIPS 203) post-quantum key encapsulation, ensuring historical privacy survives future quantum cryptanalysis. Ordinary user transactions and validator consensus messages use Ed25519 signatures by default for performance reasons (Ed25519 signatures are 64 bytes; ML-DSA-65 signatures are ~3.3KB; at 50,000 TPS the bandwidth difference is structural for residential-fiber validator participation). The trade-off is that historical ordinary transaction signatures are quantum-forgeable: a future adversary capable of breaking Ed25519 could forge historical signatures for audit, dispute, or forensics purposes. The chain's structural integrity, account control, and historical privacy remain post-quantum-secure regardless. Users requiring full post-quantum protection of their transaction history can opt into ML-DSA per-transaction; wallets default to ML-DSA above a user-configurable value threshold. This trade-off is acknowledged honestly rather than hidden.

The protocol's integrated design also enables a permissionless service-node infrastructure market (subsection 9.10) and a validator-funded infrastructure mechanism (subsection 10.5.5). These are not constitutional core properties — the chain functions correctly without them — but they are downstream consequences of the architecture: a chain that is permissionless at the participation layer, with standardised lightweight verification, naturally supports a market for the infrastructure that serves its lightweight clients. Whether this market develops at scale is determined by ecosystem dynamics rather than protocol mechanism, but the standardisation that makes it possible is part of the protocol's design.

No single chain in the present landscape combines more than three of these properties. The chains that combine *credible neutrality* with anything else (Bitcoin, Monero) lack programmability and high throughput. The chains that combine *programmable privacy* with anything else (Aztec, Aleo) lack the throughput tier and the credibly neutral governance. The high-throughput chains (Sui, Solana, Aptos, Monad) have neither default privacy nor credibly neutral governance.

This is the gap Adamant is designed to fill. The protocol's contribution is not the invention of new cryptographic primitives — those are taken from peer-reviewed literature unchanged — but the systems-level synthesis of these properties into a single coherent architecture, with credible neutrality enforced at genesis and the technical architecture chosen to be compatible with that neutrality.

## 1.3 The thesis

Adamant exists for users and applications that require properties no other chain currently provides. The design assumption is that such users and applications exist and that their number is growing. They include:

- **Individuals in jurisdictions with restrictive financial controls.** Privacy-by-default with selective disclosure allows compliance with legitimate legal requirements (tax filing, audit cooperation) without the wholesale exposure of financial history that transparent chains require.

- **Decentralised exchange users facing systematic value extraction.** Threshold-encrypted mempools eliminate the structural conditions that enable front-running and sandwich attacks, returning to users the value currently extracted by sophisticated arbitrageurs.

- **Long-lived contractual arrangements.** Wills, trusts, escrows, and inheritance arrangements that must outlive their creators by decades require a chain whose rules cannot be modified by future political pressure on a foundation.

- **Sovereign-grade applications.** Voting systems, identity registries, and public-record applications where the absence of an off switch is the central security property.

- **Treasury-grade asset custody.** Institutions and individuals holding significant assets on-chain face a class of risks specific to chains with foundations: foundation capture, foundation insolvency, foundation legal action, and foundation-coordinated upgrades that change asset behavior. Adamant eliminates these risks by construction.

- **Stablecoin payments at consumer scale.** The combination of sub-second finality, sub-cent fees, and default privacy enables stablecoin payments to behave like contemporary digital payment networks while preserving the properties that make them useful — global accessibility, censorship resistance, and self-custody.

This is not a "world computer" pitch. Adamant does not aim to host every application, displace every blockchain, or serve every user. The design optimises for users who need credible neutrality, privacy, speed, and verifiability *together*; users who do not need all of these are well served by existing chains and need not migrate.

## 1.4 What this whitepaper is and is not

This document specifies the Adamant protocol in detail sufficient to implement it. It is a technical reference, not a marketing document; claims that cannot be substantiated technically have been removed from this draft and will not be added in subsequent revisions.

It does not include:

- Token price predictions or projections
- Roadmap commitments beyond the protocol specification itself
- Comparisons to specific competing chains beyond the analytical context required to motivate design decisions
- Endorsements of specific applications, validator services, wallets, or third-party software

It does include:

- Normative protocol requirements (sections 3–11)
- Justifications for non-obvious design decisions
- Identification of open problems and known limitations
- The genesis state and constitutional commitments that define the chain's permanent properties (section 11)

Subsequent sections assume familiarity with elementary blockchain concepts (transactions, validators, consensus, state). Specialist concepts (DAG consensus, zero-knowledge proofs, threshold encryption, post-quantum signatures) are introduced when first used.

The protocol specified here is intended to be implemented exactly once: at genesis. After genesis, the specification is frozen. Section 11 makes this commitment formally.
