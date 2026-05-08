# 0. Abstract

Adamant is a Layer 1 blockchain protocol designed to serve users who require properties that no existing programmable chain delivers in combination: privacy by default, high transaction throughput, sub-second finality, post-quantum cryptographic security, phone-verifiable correctness, and credibly neutral governance with no foundation, no premine, no admin keys, and no upgrade authority after genesis.

The protocol combines a directed-acyclic-graph (DAG) consensus mechanism, an object-based parallel execution model, encrypted transaction propagation (threshold-encrypted at design-target validator count, time-lock-encrypted during the low-N period using a publicly-verifiable VDF), recursive zero-knowledge proofs of state validity, and a fixed constitutional rule set established at genesis. Every transaction is shielded by default, with users retaining the ability to selectively disclose specific information through cryptographically verifiable view keys. Smart contracts declare their mutability rules — `IMMUTABLE`, `OWNER_UPGRADEABLE`, `VOTE_UPGRADEABLE`, `UPGRADEABLE_UNTIL_FROZEN`, or a custom rule — at deployment, and these declarations are themselves immutable and visible to users before interaction.

The chain rejects on-chain governance by design. The protocol's consensus rules, virtual machine, token issuance schedule, and validity logic are fixed at genesis and cannot be modified by any party, including the original implementers. Changes require socially-coordinated forks in which every node operator individually opts into new client software — the same model that has kept Bitcoin's protocol stable for over fifteen years, here applied to a programmable execution environment.

Adamant targets a sustained throughput of at least 50,000 transactions per second on a single shard at design-target validator count, a finality latency of approximately 500 milliseconds for transactions not requiring consensus on shared state, and a per-transaction fee floor on the order of $0.0001 USD-equivalent at design throughput. The 50,000 TPS figure is a *floor*, not a cap — actual throughput depends on the active set's aggregate hardware capability and current network conditions, and routinely exceeds the floor when validators run better-than-baseline hardware. The throughput floor is subject to empirical validation on residential-fibre hardware before genesis; if validation indicates the floor is not deliverable on commodity hardware at the target validator count, the floor will be re-calibrated rather than the hardware tier raised. Fee accounting is multi-dimensional, separating the costs of state storage, computation, and proof verification rather than collapsing them into a single gas number. Fees are paid in the native token (working name ADM) and burned via an EIP-1559-style mechanism, producing deflationary token economics under network usage.

The active validator set is dynamic, with a constitutional floor of 7 validators (the minimum size at which Byzantine fault tolerance retains non-zero margin against correlated failures) and a soft ceiling of 75 validators (the upper bound at which DAG-BFT communication cost remains tractable on residential-fibre hardware at the throughput floor). Selection follows a first-come-first-served-with-persistent-membership rule: validators are admitted to the active set in registration order, and once admitted retain their slot continuously until they fail liveness duties or voluntarily unbond. This rewards commitment and continuity rather than hardware budget or stake size — early committed validators cannot be displaced by wealthier latecomers or by faster competitors. The chain self-activates the moment 7 validators are simultaneously registered, stake-eligible, and online; there is no coordination event, no recruited genesis cohort, no foundation. Below the floor, the chain halts rather than forks, preserving safety at the cost of liveness during periods of severe validator unavailability. The chain commits an on-chain security-tier signal (Tier I at 7–14 validators, Tier II at 15–29, Tier III at 30+) so that wallets and applications can adapt to the chain's current security posture rather than assume the design-target posture from launch onward.

Participation is structured across four tiers with bounded power. Validators do consensus and mempool decryption. Provers do steady-state recursive-proof generation in a permissionless market, paid per-proof from transaction fees; validators do proof generation as a fallback at degraded cadence to preserve phone-verifiability regardless of prover-market health. Witnesses perform attestation, data availability sampling, recursive proof verification, and fraud detection on phone-class hardware. Service nodes provide light-client infrastructure. The role split keeps validator hardware on residential-fiber commodity desktops by moving GPU-class proof generation off-tier; phone-class participation is meaningful via witnesses; no single tier alone controls the chain.

The protocol uses standard, peer-reviewed cryptographic primitives — Ed25519 and ML-DSA (CRYSTALS-Dilithium, FIPS 204) for signatures in a hybrid configuration (Ed25519 for ordinary transactions and validator messages; ML-DSA for identity-binding operations and high-value opt-in), ML-KEM-768 (FIPS 203) for post-quantum key agreement underlying stealth addresses and encrypted memos, BLS12-381 for signature aggregation, SHA-3 for hashing, the Halo 2 proving system for zero-knowledge proofs, and a Wesolowski Verifiable Delay Function over class groups for time-lock encryption during the low-N period. No novel cryptography is introduced. The protocol's contribution is the systems-level synthesis of these primitives into a coherent architecture meeting the property set described above.

This document specifies the Adamant protocol in full. Section 1 motivates the design through gap analysis of the existing landscape. Section 2 establishes the design principles that constrain all subsequent decisions. Sections 3 through 9 specify the technical architecture from cryptographic primitives through networking. Section 10 specifies the economic and incentive model. Section 11 specifies the genesis state and constitutional commitments. Section 12 discusses open problems and the scope of future work.

The reference implementation is being developed in Rust and is available under the Apache 2.0 license at [github.com/adamant-protocol](https://github.com/adamant-protocol). This whitepaper and the implementation evolve together; specification changes are tracked in this document's version history and reflected in the corresponding code releases.
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
# 2. Design Principles

This section establishes the principles that constrain every subsequent design decision in this document. These principles are not aspirational; they are normative. Where a technical choice in later sections must be made between alternatives, the alternative more consistent with the principles below `MUST` be chosen, even at the cost of performance, convenience, or developer experience.

These principles are also the basis on which proposed changes to this specification will be evaluated. A proposal that improves throughput at the cost of credible neutrality will be rejected. A proposal that improves developer ergonomics at the cost of privacy by default will be rejected. The principles take precedence over their consequences.

There are seven principles. They are listed in priority order: where two principles conflict, the higher principle prevails.

## 2.1 Principle I: Credible neutrality

**The protocol `MUST NOT` admit any party with the unilateral capability to alter its operation.**

Concretely, this principle requires:

1. **No on-chain governance.** The protocol `MUST NOT` include any mechanism by which any quorum of token holders, validators, or other participants can alter consensus rules, the virtual machine, the issuance schedule, the validity logic, or any other consensus-critical parameter.

2. **No foundation, treasury, or admin keys.** No key, multisig, or signing authority `MAY` exist with the capability to modify protocol behavior, freeze state, censor transactions, or unilaterally upgrade clients.

3. **No premine or founder allocation.** The genesis state `MUST NOT` allocate the native token to the original implementers, contributors, advisors, investors, or any party associated with the protocol's creation. Token issuance begins at genesis through mechanisms specified in section 10.

4. **Forks require individual opt-in.** Changes to consensus rules require the publication of new client software which node operators `MUST` individually choose to run. There is no mechanism by which a node automatically upgrades, no upgrade key controlled by any party, and no on-chain coordination of upgrades.

5. **No protected contracts or precompiles favouring the implementers.** All contracts, addresses, and accounts on the chain are subject to identical rules. The protocol `MUST NOT` include precompiled contracts, system contracts, or built-in addresses that grant special privileges to any party.

The intent of this principle is the property colloquially expressed as "the chain has no master." Its precise meaning is: any participant in the protocol can verify, at any time, that no other participant possesses asymmetric capability to alter the protocol's operation.

This principle is the most important in this document. It is the property that distinguishes Adamant from the chains it shares technical features with. Every other principle is subordinate to it.

### 2.1.1 Discussion

This principle is uncomfortable. It commits the protocol to permanent rules that cannot be changed if circumstances reveal them to be suboptimal. It eliminates the safety net that on-chain governance provides for emergency response. It places the entire burden of "getting it right" on the genesis specification.

These are real costs. The protocol accepts them because the alternative — retaining the *capability* to change protocol rules — is itself the property that this principle exists to prevent. A capability cannot be conditionally exercised; it can only be present or absent. A foundation that promises never to use its emergency powers is, with respect to the credible-neutrality property, indistinguishable from a foundation that uses them every week. Users protecting against worst-case adversaries must assume the capability will be exercised.

The historical evidence supports this principle. Bitcoin's protocol has remained substantively unchanged for over fifteen years, and the changes that have occurred (SegWit, Taproot) have required years of social consensus expressed through individual node-operator opt-in. This stability has been the foundation of Bitcoin's role as a settlement layer. The chains that have permitted easy protocol modification (most of them) have produced histories of contested upgrades, foundation-driven changes that some users opposed, and ongoing governance overhead. The trade-off is clear and Adamant chooses Bitcoin's side of it.

## 2.2 Principle II: Privacy by default

**Transactions on the protocol `MUST` be private by default. Users `MUST` retain the ability to selectively disclose specific information to specific parties through cryptographically verifiable means.**

Concretely:

1. **Default shielded execution.** The default transaction format on the protocol `MUST` conceal the sender, the recipient, the amount, and the contract execution details from observers other than the parties to the transaction.

2. **Selective disclosure.** Users `MUST` be able to generate verifiable proofs that disclose specific facts about their transactions or balances (for example, "I sent at least X to address Y between dates D1 and D2") without disclosing other facts.

3. **No backdoor decryption.** The protocol `MUST NOT` include any mechanism by which any party — including governments, the original implementers, or quorums of validators — can decrypt private transaction data without the cooperation of the transacting parties.

4. **Optional transparency.** Users `MAY` opt their transactions into transparent execution where the use case requires it (for example, public charitable donations, public bounties, or transparency-required regulatory contexts). Transparency is a per-transaction choice, not a chain-wide default.

5. **View keys.** The account model `MUST` support delegated view keys allowing third parties (auditors, accountants, regulators with legitimate authority) to observe a user's transaction history without granting spending authority.

6. **MEV protection is structural at design-target validator count.** At design-target N, threshold encryption (subsection 8.4) ensures no validator sees plaintext transaction contents before ordering is committed; this is the structural mechanism preventing front-running, sandwich attacks, and other MEV extraction. During the low-N period (prior to the chain reaching the threshold-encryption viability boundary specified in subsection 8.4), MEV protection operates via time-lock encryption with deterministic anchor rotation; this provides similar protection against external observers and against most validator-side extraction, but admits a bounded residual surface for anchor-internal transaction reordering. The chain's MEV protection is therefore qualitatively similar across both regimes but quantitatively weaker during the low-N period. This trade-off is acknowledged honestly rather than hidden.

### 2.2.1 Discussion

Privacy by default is the principle most likely to attract regulatory hostility, and the protocol does not attempt to disguise this. The justification is that the alternative — transparent-by-default with optional privacy — produces a worse outcome for both legitimate privacy and legitimate regulation. When privacy is opt-in, using the privacy feature itself becomes evidence of suspicious behavior; legitimate users avoid it for reputational reasons; the only users left in the privacy pool are those for whom privacy is essential, which makes that pool a prime target for regulatory pressure. When privacy is the default, no such inference can be drawn from the use of privacy features, and the cryptographic anonymity set comprises the entire chain rather than a self-selected subset.

The selective disclosure mechanism is the protocol's answer to the regulatory question. Users can prove compliance with specific obligations (income reporting, sanctions screening, anti-money-laundering due diligence) without exposing unrelated transaction history. This is a stronger compliance posture than transparent chains offer, which expose all transaction history to all observers indefinitely.

The MEV-protection clause of this principle is necessarily honest about the difference between the two regimes that operate during the chain's lifetime. Threshold encryption requires a coordinated active validator set running DKG (distributed key generation) every epoch — a mechanism that cannot operate at very low N. Time-lock encryption operates at any N including N=1, but its security model differs: a single validator (the round anchor) finishes the VDF computation and decrypts the round's transactions before publishing. Mitigations specified in subsection 8.4 (deterministic anchor rotation, decryption-publication binding via equivocation slashing) bound the resulting MEV surface significantly, but cannot eliminate it. The chain therefore commits to "MEV protection at the same structural quality as the design-target chain at design-target N, with bounded weaker protection during the low-N period that is honestly disclosed via the security tier mechanism in subsection 8.7."

## 2.3 Principle III: Verifiability without trust

**Any participant `MUST` be able to verify the correctness of the protocol's operation using only consumer-grade hardware, without trusting any third party.**

Concretely:

1. **Phone-verifiable verification.** A modern smartphone `MUST` be capable of verifying the entire chain history's validity in time bounded by a small constant, regardless of the chain's age or transaction count.

2. **No light-client trust assumptions.** Verification `MUST NOT` require trusting a node, a committee, or a federation. Verification is cryptographic, not statistical.

3. **Recursive proofs.** The protocol `MUST` produce a recursive zero-knowledge proof attesting to the validity of all transactions and state transitions from genesis to the current head. This proof is the canonical verification artifact.

4. **Open verification.** Verification software `MUST` be free, open-source, and runnable without permission. Users do not need to register, identify themselves, or pay to verify the chain.

5. **Proof production cadence.** Recursive proofs `MUST` be produced continuously by the protocol. The protocol commits to producing proofs at a steady-state cadence at design-target operation (driven by a permissionless prover market, subsection 8.5) and to a fallback cadence when the prover market is insufficient (driven by validators on their own hardware at degraded but bounded freshness windows). Phone-verifiability never depends on a market materialising; it depends only on proofs being produced, and the protocol's fallback mechanism guarantees this.

### 2.3.1 Discussion

This principle exists because the value of credible neutrality is realised only when individual users can verify it. A chain that is technically neutral but practically requires trusting a hosted node is, from the user's perspective, a chain that requires trust in the node operator. The combination of credible neutrality (Principle I) and unverifiable operation in practice (the historical norm) has been one of the central usability failures of the blockchain ecosystem.

Recursive zero-knowledge proofs, demonstrated in production by Mina Protocol since 2021, make this principle achievable in 2026 in a way that was not possible at Bitcoin's launch. The protocol takes advantage of this technological maturity to make verifiability a first-class property rather than an aspiration.

The fallback clause of this principle is necessary because the protocol splits proof generation into a separate participation tier (provers, subsection 8.5). Splitting roles cleanly is good engineering — it separates cryptographic message-passing (validator work) from intensive computation (prover work) — but it makes phone-verifiability nominally dependent on the prover tier existing. The fallback specification removes that dependency: even if no provers are present, validators produce proofs at degraded cadence (every several blocks rather than every block), preserving the verifiability commitment at a longer freshness window. The constitutional commitment is "phone-verifiable proofs are produced," not "phone-verifiable proofs are produced every 500ms."

## 2.4 Principle IV: Performance sufficient for use

**The protocol `MUST` provide throughput, latency, and cost properties consistent with practical use as a payment network and smart-contract platform.**

Concretely:

1. **Throughput floor.** The protocol `MUST` sustain at least 50,000 transactions per second on a single shard at the design-target validator count (specified in section 8), subject to empirical validation on residential-fibre hardware before genesis. The 50,000 TPS figure is a *minimum commitment*, not a cap: actual throughput depends on the active set's aggregate hardware capability and current network conditions, and routinely exceeds the floor when validators run better-than-baseline hardware. The protocol commits to delivering at least the floor; reality often delivers more.

2. **Finality target.** The protocol `MUST` provide finality for transactions that do not require shared-state consensus (simple transfers, owned-object operations) within approximately 500 milliseconds at design throughput. During the low-N launch period when the chain operates with time-lock encryption fallback (subsection 8.4), end-to-end inclusion latency is 10-30 seconds; this is an acknowledged consequence of operating without coordinated DKG and is bounded to the period before the active set crosses the threshold-encryption viability boundary.

3. **Cost target.** The base fee for a simple transfer at design throughput `MUST` be on the order of $0.0001 USD-equivalent or less, computed at the fee model specified in section 10.

4. **Phone-friendly proving.** Where users generate zero-knowledge proofs locally, proof generation `MUST` complete in time tolerable for interactive use on consumer mobile hardware (target: 10 seconds or less for typical operations).

### 2.4.1 Discussion

This principle is fourth in priority because it is subordinate to neutrality, privacy, and verifiability. The protocol declines performance gains that would require concessions on those properties. However, performance is not an aesthetic preference; it is the difference between a protocol used in production and a protocol used in research papers. The targets above are calibrated to the threshold below which usability suffers materially.

The 50,000 TPS floor is calibrated to the throughput at which DAG-BFT communication cost (O(N²) in the active set size) is operationally feasible on residential-fibre validator hardware at the design-target active-set ceiling of 75 validators. Earlier drafts of this whitepaper specified a 200,000 TPS target derived from the demonstrated throughput of Mysticeti consensus on VPS-grade validator hardware; that target was incompatible with Adamant's commitment to residential-fibre validator participation and has been reduced. 50,000 TPS is roughly 30x Visa's average global throughput, matches or exceeds the sustained throughput of contemporary high-performance L1s, and is genuinely state-of-the-art for a privacy-default chain. The empirical validation caveat is necessary because the sizing argument from 200k @ 200 validators to 50k @ 75 validators is provisional; section 8 specifies the calculation and the validation requirement.

Framing throughput as a *floor* rather than a *target* is deliberate. A target invites the framing "the chain runs at exactly this number, that's all it does." A floor invites the framing "the chain commits to at least this number; more is delivered when conditions allow." The latter is closer to how the protocol actually behaves: a chain with all validators running well-provisioned hardware on uncongested links delivers higher throughput than the floor; a chain with marginal validators or congested networking delivers the floor. The protocol's commitment is to the floor; the network often does better.

The 500ms finality target derives from Mysticeti's wide-area-network commit latency at design throughput. The $0.0001 cost target derives from the observation that fees significantly above this level discourage routine micropayments and limit the protocol's usefulness for payment applications.

The protocol does not commit to higher targets (millions of TPS, single-millisecond finality, zero fees). These targets either require unproven engineering, centralised operation, or both. The protocol's performance commitments are intended to be deliverable rather than aspirational.

## 2.5 Principle V: Mutability is a property of objects, not the chain

**The chain's consensus rules `MUST` be immutable. Objects living on the chain `MAY` declare their own mutability rules at creation, and those declarations `MUST` themselves be immutable and visible to users before interaction.**

Concretely:

1. **Chain-level immutability.** Consensus rules, the virtual machine, validity logic, and the issuance schedule `MUST NOT` be modifiable by any on-chain mechanism after genesis.

2. **Object-level mutability declarations.** Smart contracts and other on-chain objects `MUST` declare a mutability policy at creation. The policy is itself immutable: a contract created with `IMMUTABLE` mutability `MUST NOT` ever become mutable, and a contract created with a particular upgrade mechanism `MUST NOT` ever change to a different upgrade mechanism.

3. **Standard mutability policies.** The protocol `MUST` provide and document standard mutability policies including at minimum:
   - `IMMUTABLE` — the contract is permanently fixed
   - `OWNER_UPGRADEABLE` — a designated owner key may upgrade
   - `VOTE_UPGRADEABLE` — token holders of a specified token may vote on upgrades subject to specified thresholds
   - `UPGRADEABLE_UNTIL_FROZEN` — the contract is upgradeable until the owner calls a freeze operation, after which it is permanently `IMMUTABLE`
   - `CUSTOM` — the contract specifies its own upgrade logic at deployment

4. **User-visible declarations.** The mutability policy of any contract `MUST` be queryable by any user before interaction. Wallets and clients `SHOULD` display the mutability policy prominently.

5. **No proxy-pattern hiding.** The protocol `MUST NOT` permit upgradeability mechanisms that conceal themselves from users. A contract whose code can be replaced through any mechanism `MUST` be tagged as upgradeable in the user-visible declaration.

### 2.5.1 Discussion

This principle resolves the apparent tension between the immutability of credible neutrality and the practical need for some application-level evolution. The chain itself does not change; what lives on the chain may, but only on terms its creator declared and its users accepted at the time of interaction.

The status quo on existing smart-contract chains is a footgun. Proxy patterns allow contract code to be replaced under the user's feet without explicit warning, and the practice has produced repeated incidents in which users believed they were interacting with immutable code that was, in fact, controlled by an upgrade key. Adamant's mutability declarations make this property explicit and visible, allowing users to make informed decisions about which contracts they trust and on what terms.

## 2.6 Principle VI: Standard primitives, novel synthesis

**The protocol `MUST` use standard, peer-reviewed cryptographic primitives. The protocol `MUST NOT` introduce novel cryptographic constructions.**

Concretely:

1. **Standard primitives only.** Hash functions, signature schemes, encryption schemes, zero-knowledge proof systems, and other cryptographic building blocks `MUST` be drawn from peer-reviewed literature with substantial implementation history.

2. **Specific primitives.** The protocol uses Ed25519 and ML-DSA (FIPS 204) for signatures, ML-KEM (FIPS 203) for post-quantum key encapsulation underlying privacy primitives, BLS12-381 for signature aggregation, SHA-3 for hashing, Halo 2 for zero-knowledge proofs, and standard threshold encryption constructions for the encrypted mempool. These are specified in detail in section 3.

3. **No "rolled" cryptography.** The protocol's reference implementation `MUST NOT` include hand-rolled implementations of cryptographic primitives. It uses well-maintained, audited libraries (`dalek` ecosystem, `arkworks`, `blst`, `ml_dsa`) and contributes upstream where improvements are required.

4. **Innovation at the systems layer.** The protocol's contribution is the synthesis of these primitives into a coherent architecture. New properties emerge from the combination, not from new primitives.

### 2.6.1 Discussion

This principle is intended to forestall a common failure mode. The history of cryptocurrency includes a substantial subset of projects whose authors, persuaded that their problem domain required novel cryptography, produced novel cryptography that turned out to be insecure. Where the protocol's value depends on cryptographic correctness — and Adamant's value depends on it absolutely — the appropriate posture is conservative.

This does not constrain the protocol's ambition. The properties Adamant aims to deliver are achievable with existing primitives; what has been missing is the engineering effort to combine them. That engineering is the protocol's contribution.

## 2.7 Principle VII: Permissionless participation

**Participation in the protocol `MUST NOT` require permission from any party.**

Concretely:

1. **Permissionless validation.** Anyone meeting the published technical requirements `MUST` be able to operate a validator without obtaining permission from any existing participant.

2. **Permissionless transaction submission.** Anyone `MUST` be able to submit transactions without registering, identifying themselves, or obtaining permission.

3. **Permissionless development.** Anyone `MUST` be able to deploy contracts and applications without obtaining permission. Contracts are not subject to whitelisting, audit-gating, or other permission gates at the protocol level. (Higher-layer applications may impose their own access controls.)

4. **Permissionless verification.** Anyone `MUST` be able to verify the chain's operation without obtaining permission. Verification software is open-source and runnable without registration.

5. **No identity requirements.** The protocol `MUST NOT` require, store, or rely on real-world identity information for any of its operations. Compliance with identity-related regulation is the responsibility of higher-layer applications.

### 2.7.1 Discussion

Permissionless participation is the operational complement to credible neutrality (Principle I). A chain whose protocol cannot be modified but whose validator set is permissioned is not credibly neutral; the permission-grantor retains effective control. This principle ensures that the absence of an on-chain governance mechanism (Principle I) is not undermined by an off-chain permission gate.

## 2.8 Principle VIII: Post-quantum security at identity and privacy layers

**The protocol `MUST` be post-quantum secure at the identity layer (addresses, validator registrations, contract deployments) and at the privacy layer's key-agreement surface (stealth addresses, encrypted memos). Ordinary transaction signatures `MAY` use classical cryptography for performance reasons; users `MUST` retain the ability to opt into post-quantum signatures per-transaction.**

Concretely:

1. **Post-quantum identity.** Account addresses, validator registrations, contract deployments, and any operation producing persistent on-chain identity binding `MUST` be authorised under ML-DSA (FIPS 204) or another peer-reviewed post-quantum signature scheme. A future quantum adversary `MUST NOT` be able to take control of accounts, forge validator registrations, or rewrite chain structural state.

2. **Post-quantum privacy.** Key agreement underlying stealth address derivation, encrypted memo delivery, and any other privacy-relevant key-exchange surface `MUST` use ML-KEM (FIPS 203) or another peer-reviewed post-quantum KEM. A future quantum adversary `MUST NOT` be able to retroactively deanonymise historical privacy-shielded transactions through key-agreement attacks.

3. **Hybrid signature posture for ordinary transactions.** Ordinary user transactions and validator consensus messages `MAY` use Ed25519 for performance reasons (smaller signatures, faster verification). The trade-off: a future quantum adversary capable of breaking Ed25519 could retroactively forge historical ordinary transactions, breaking transaction-history forensics, audit, and dispute resolution. The chain's structural integrity and historical privacy remain post-quantum-secure regardless. Users requiring full post-quantum protection of their transaction history `MUST` be able to opt into ML-DSA signatures per-transaction; wallets `SHOULD` default to ML-DSA for transactions above a user-configurable value threshold.

4. **No automatic transition.** The hybrid posture is permanent. There is no protocol-level mechanism by which the chain transitions from hybrid to pure post-quantum signing; users migrate via opt-in as their threat model evolves. This avoids introducing governance (Principle I).

### 2.8.1 Discussion

The hybrid signature model is the protocol's response to the bandwidth and storage cost of large post-quantum signatures (ML-DSA-65 is ~3.3KB versus Ed25519's 64 bytes). At 50,000 TPS, all-ML-DSA signatures consume approximately 165 MB/sec of validator bandwidth versus 3.2 MB/sec for all-Ed25519; this difference is structural for residential-fiber validator participation. The hybrid model, with ~95% Ed25519 and ~5% ML-DSA in expected operation, reduces signature bandwidth to approximately 11 MB/sec while preserving post-quantum security at the surfaces where it matters most.

The honest trade-off is that historical ordinary transaction signatures are quantum-forgeable. Once Ed25519 is broken (estimated 2030-2040 in the consensus cryptanalysis literature), an adversary with quantum capability can produce signatures that verify correctly against historical Ed25519 public keys for any chosen message. This affects audit, legal disputes, regulatory compliance, and any retrospective analysis that relies on signature non-forgeability. It does not affect: the chain's continued operation post-quantum (because ongoing validation uses post-quantum primitives at the identity layer); historical privacy (because key agreement is post-quantum via ML-KEM); the integrity of contract deployments and validator registrations (post-quantum via ML-DSA).

The protocol commits to the trade-off honestly rather than hiding it. Users are explicitly told that ordinary transaction signing is not post-quantum; they are given the tools to opt up where their threat model requires it; and wallets are expected to surface the choice clearly.

## 2.9 The principles in conflict

These principles will, at points, conflict. When they do, they resolve in priority order:

1. Credible neutrality (Principle I) takes precedence over all others.
2. Privacy by default (Principle II) takes precedence over Principles III–VIII.
3. Verifiability (Principle III) takes precedence over Principles IV–VIII.
4. Performance (Principle IV) takes precedence over Principles V–VIII.
5. Mutability-as-property (Principle V) takes precedence over Principles VI–VIII.
6. Standard primitives (Principle VI) takes precedence over Principles VII and VIII.
7. Permissionless participation (Principle VII) takes precedence over Principle VIII.

In practice, the principles harmonise in the design that follows. This priority order is provided to resolve cases where reasonable people might disagree, including future cases that this document's authors have not anticipated.

## 2.10 What these principles exclude

For clarity, these principles exclude the following from the protocol:

- Any form of on-chain governance, including parameter governance for "non-critical" values
- Any treasury, foundation account, or community fund existing at the protocol level
- Any "ecosystem support" allocation in the genesis state
- Any kill-switch, circuit breaker, or pause mechanism, regardless of which party would operate it
- Any ability for the original implementers to claim rewards beyond their participation in genesis distribution mechanisms specified in section 10
- Any KYC, AML, or identity-verification requirements at the protocol layer
- Any precompiles, system contracts, or built-in addresses that grant privileged behavior to specific parties

These exclusions are normative. A future revision of this whitepaper that proposes to add any of the above features would, by definition, be specifying a different protocol — not a revised Adamant.

The remainder of this document specifies how a protocol meeting these principles is constructed.
# 3. Cryptographic Foundation

This section specifies every cryptographic primitive used by the Adamant protocol. It is the foundation on which all other sections depend: the consensus mechanism, the privacy layer, the encrypted mempool, the identity system, and the recursive verification all rest on the primitives specified here.

The protocol's guiding principle for cryptography is stated in Principle VI of section 2: standard primitives, novel synthesis. This section operationalises that principle. Every primitive is drawn from peer-reviewed literature with substantial implementation history. No primitive is novel to Adamant. Where multiple peer-reviewed alternatives exist, the rationale for the chosen primitive is explicit and the alternatives are documented.

This section is normative. The reference implementation `MUST` use the primitives, parameters, and libraries specified here. Substitution requires a formal specification revision under the procedure described in section 12.

## 3.1 Threat model

The protocol's cryptographic design assumes the following adversary capabilities:

1. **Classical computational adversary.** An adversary with computational resources up to but not exceeding those plausibly available to a well-resourced nation-state through approximately 2040, on classical computing hardware. The protocol targets at least 128-bit classical security across all primitives.

2. **Network adversary.** An adversary that can observe, modify, delay, drop, and inject network traffic at any point in the public internet. The protocol assumes no confidentiality or integrity from the underlying network and provides both at the cryptographic layer.

3. **Quantum adversary (long-term).** An adversary with a sufficiently large fault-tolerant quantum computer to execute Shor's algorithm against elliptic-curve and integer-factorisation problems. The protocol assumes such an adversary may exist at some point during the operational lifetime of the chain (potentially within 10–25 years of genesis) and provides a migration path to post-quantum primitives that does not require a hard fork.

4. **Compromised validators (Byzantine).** Up to one-third of validators by stake may be Byzantine — actively malicious, colluding, or compromised — without violating safety guarantees. This is the standard assumption for Byzantine-fault-tolerant consensus and is enforced at the consensus layer (section 8); cryptographic primitives are required to remain secure under arbitrary validator behaviour.

5. **Compromised user devices.** The protocol assumes that user devices may be compromised. Primitives that protect users (signing, encryption) `SHOULD` be amenable to use within hardware security modules, secure enclaves, and hardware wallets where available, but the protocol does not depend on hardware security for its core safety properties.

The protocol does **not** defend against:

- An adversary with sufficient quantum computing resources to break ML-DSA, ML-KEM, or other lattice-based primitives at the parameters specified in this section. Such an adversary would constitute a fundamental break of post-quantum cryptography, the consequences of which would extend beyond any individual blockchain.
- An adversary capable of compromising more than one-third of validators by stake. Adamant's safety guarantees are conditioned on this threshold; an adversary above this threshold can violate safety regardless of cryptographic correctness.
- An adversary with physical access to a user's device and unencrypted secret material. The protocol assumes users protect their secret keys; key management is the user's responsibility.

## 3.2 Cryptographic primitives summary

The protocol uses five categories of cryptographic primitives, summarised here and specified in detail in subsequent subsections.

| Category | Primitive | Standard / source | Use |
|----------|-----------|-------------------|-----|
| Hash function | SHA3-256, SHAKE-256 | FIPS 202 | All chain hashing, transaction identifiers, Merkle trees |
| Hash to curve | BLAKE3 (auxiliary), Poseidon (zk circuits) | BLAKE3 spec; Grassi et al. 2020 | Auxiliary hashing, zk-friendly hashing inside circuits |
| Classical signature | Ed25519 | RFC 8032 | Ordinary user transactions, validator consensus messages |
| Post-quantum signature | ML-DSA (CRYSTALS-Dilithium) | FIPS 204 | Identity-binding operations (validator registration, contract deployment, address derivation, opt-in high-value transactions) |
| Post-quantum KEM | ML-KEM-768 (CRYSTALS-Kyber) | FIPS 203 | Stealth address derivation, encrypted memo delivery, post-quantum key agreement |
| Aggregate signature | BLS12-381 (BLS signatures) | IRTF CFRG draft, BLS12-381 curve | Validator vote aggregation |
| Symmetric encryption | ChaCha20-Poly1305 | RFC 8439 | Transport encryption, mempool envelope |
| Threshold encryption | Boneh-Lynn-Shacham threshold scheme on BLS12-381 | Boneh, Boyen, Shacham 2004; subsequent work | Encrypted mempool (threshold regime, N≥15) |
| Time-lock encryption (VDF) | Wesolowski VDF on RSA / class groups | Wesolowski 2019 | Encrypted mempool (time-lock regime, N<15) |
| Zero-knowledge proofs | Halo 2 (PLONKish, no trusted setup) | Bowe, Grigg, Hopwood 2019 | Shielded execution, recursive verification |
| Vector commitments | KZG commitments on BLS12-381 | Kate, Zaverucha, Goldberg 2010 | State commitments, proof aggregation |

Each primitive is justified and parameterised below.

## 3.3 Hash functions

### 3.3.1 Primary hash: SHA3-256 and SHAKE-256

The protocol's primary hash function is SHA3-256 for fixed-output hashing and SHAKE-256 for extensible-output hashing, both as standardised in FIPS 202.

**Rationale.** SHA3 is a Keccak-derived hash function selected by NIST through an open competition (2007–2012) and standardised in 2015. It has a fundamentally different internal construction from the SHA-2 family (sponge construction vs. Merkle–Damgård), providing diversity against the unlikely event of a structural attack on SHA-2. It has no known attacks reducing security below the 128-bit collision-resistance level at the SHA3-256 parameter. Hardware acceleration is increasingly available (ARM v8.4-A includes SHA3 instructions; x86-64 implementations via SSE/AVX achieve >1 GB/s throughput on modern processors).

**Parameters.** SHA3-256 produces 256-bit output, providing 128-bit collision resistance and 256-bit preimage resistance. SHAKE-256 produces output of arbitrary length with the same security level.

**Domain separation.** All uses of SHA3-256 and SHAKE-256 within the protocol `MUST` use domain separation. The protocol uses the **BIP-340 tagged-hash construction** (Bitcoin Improvement Proposal 340, deployed in Bitcoin Taproot, November 2021), adapted to SHA3:

```
tagged_hash_sha3(tag, input)   = SHA3-256( SHA3-256(tag) || SHA3-256(tag) || input )
tagged_shake(tag, input, len)  = SHAKE-256( SHA3-256(tag) || SHA3-256(tag) || input, len )
```

where `tag` is a domain identifier of the form `b"ADAMANT-v1-<context>"` and `input` is the data being hashed. The tag prefix is **always** `SHA3-256(tag)`, regardless of whether the body uses SHA3-256 or SHAKE-256. This uniformity means each registered tag has exactly one canonical 32-byte prefix, computed once and cached, usable across both hash variants.

Naive concatenation (`tag || input`) is insufficient because it admits prefix collisions: with variable-length tags, a tag like `ADAMANT-v1-block` followed by input `_hash` || X produces the same byte string as tag `ADAMANT-v1-block_hash` followed by input X, causing the hash function to produce identical outputs for what should be domain-separated operations. The BIP-340 construction eliminates this by binding the tag through a fixed-size hash commitment.

The construction has the following properties:

- **Collision-resistant across tags.** Finding two distinct tags `t1 ≠ t2` and inputs `i1`, `i2` such that `tagged_hash_sha3(t1, i1) == tagged_hash_sha3(t2, i2)` requires finding a SHA3-256 collision. The protocol's domain separation inherits the security of SHA3-256 directly.
- **Length-agnostic for tags.** Tags may be any byte string; no length cap is imposed and no length field is encoded.
- **Production-validated.** The doubled-tag-prefix construction has been deployed at production scale in Bitcoin since 2021 and is the de facto standard for hash-based domain separation in modern cryptographic protocols.
- **Negligible runtime cost.** The cached `SHA3-256(tag)` is computed once per registered tag and reused. Each domain-separated hash costs one additional 64-byte absorb relative to a tag-less hash — invisible at any throughput the protocol targets.

All tags are specified in the centralised registry maintained by the reference implementation (`crates/adamant-crypto/src/domain.rs`). Tags have the format `b"ADAMANT-v1-<context>"` where `<context>` identifies the specific use. Adding, removing, or renaming a tag is a consensus rule change and follows the procedure in section 3.12.

**Worked example:**

```
tag    = b"ADAMANT-v1-object-id"
input  = creation_tx_hash || creator_address || creation_index

prefix = SHA3-256(tag)       // 32 bytes; fixed for this tag, computed once

tagged_hash_sha3(tag, input)
  = SHA3-256( prefix || prefix || creation_tx_hash || creator_address || creation_index )
```

This construction is `MUST`-required for any SHA3-256 or SHAKE-256 use that is consensus-critical. Non-consensus-critical hashing (for example, peer-to-peer message integrity checks where collisions across contexts are not security-relevant) `MAY` use plain SHA3 or SHAKE without the tagged-hash wrapper, though the centralised registry pattern is `RECOMMENDED` even there for consistency.

**Library.** The reference implementation uses the `sha3` crate from RustCrypto, which provides constant-time implementations and is widely audited.

### 3.3.2 Auxiliary hash: BLAKE3

BLAKE3 is used as an auxiliary hash function for performance-sensitive paths where collision-resistance security at 128 bits suffices and where SHA3 would be a measurable bottleneck.

**Rationale.** BLAKE3, published in 2020, is built on the Bao tree-hashing construction over a Merkle-tree-friendly internal compression function. It is significantly faster than SHA3 in software (typically 5–10x on commodity hardware) and is naturally parallelisable. Specific uses include: peer-to-peer message integrity checks where the message is large and the security context permits a faster primitive; streaming hashes during block propagation; and content-addressed storage of historical chain data.

**Parameters.** BLAKE3 produces 256-bit output by default, with extensible-output mode for arbitrary lengths. The protocol uses 256-bit output throughout.

**Constraint.** BLAKE3 `MUST NOT` be used for any of the following: transaction identifiers, state commitments, signature inputs, consensus-critical hashes. These uses require SHA3-256 to maintain protocol-wide hash-function uniformity. BLAKE3 is exclusively for non-consensus-critical performance paths.

**Library.** The reference implementation uses the `blake3` crate.

### 3.3.3 zk-friendly hash: Poseidon

Inside zero-knowledge circuits, the protocol uses the Poseidon hash function. Poseidon is designed for efficient evaluation in arithmetic circuits over large prime fields, where SHA3 and BLAKE3 are prohibitively expensive (a single SHA3 invocation requires hundreds of thousands of constraints in a SNARK circuit; a single Poseidon invocation requires hundreds).

**Rationale.** Poseidon was designed by Grassi, Khovratovich, Rechberger, Roy, and Schofnegger (2020) specifically for zk-friendly hashing. It has been adopted by Filecoin, Mina, and Aztec, providing extensive deployment evidence. Cryptanalytic effort against Poseidon has been substantial, with no attacks reducing security below the 128-bit level at the parameters used.

**Parameters.** The protocol uses Poseidon with the following parameters: prime field of order equal to the BLS12-381 scalar field (255 bits), state width of 3 field elements (rate 2, capacity 1), 8 full rounds and 57 partial rounds. These parameters provide approximately 128-bit security against differential and algebraic attacks.

**Constraint.** Poseidon is used only inside zk circuits. It `MUST NOT` be used for general protocol hashing outside circuits. Hashes that cross the circuit/non-circuit boundary use both Poseidon (inside the circuit) and SHA3-256 (outside), with the circuit proving consistency between the two representations.

**Library.** The reference implementation uses the Poseidon implementation from `halo2_gadgets` (zcash variant).

## 3.4 Signature schemes

The protocol supports two signature schemes for user and validator signatures: Ed25519 (classical) and ML-DSA (post-quantum). Both are first-class. Accounts may use either or both, as specified in section 4.

### 3.4.1 Classical signatures: Ed25519

Ed25519 is the protocol's classical signature scheme. It is specified in RFC 8032 and is the most widely deployed elliptic-curve signature scheme in modern cryptographic systems.

**Rationale.** Ed25519 provides 128-bit classical security, has no patent encumbrance, supports deterministic signing (eliminating the catastrophic key-recovery vulnerability that affects ECDSA when the per-signature randomness is reused or biased), and is implementable in fully constant time. Every major modern operating system, secure element, and HSM supports it. Performance is excellent: signing and verification both take well under one millisecond on commodity hardware.

**Parameters.** As specified in RFC 8032: the Edwards curve `edwards25519`, hash function SHA-512 internally (a deliberate choice in the original Ed25519 design that is independent of the protocol's preference for SHA3 elsewhere), 256-bit private keys, 32-byte public keys, 64-byte signatures.

**Note on hash choice.** Ed25519 internally uses SHA-512 as part of its specification; this is a fixed property of the scheme and not a protocol choice. The protocol does not modify Ed25519's internal hash. Protocol-level hashing of Ed25519 keys and signatures (for example, computing a hash commitment to a public key) uses SHA3-256.

**Library.** The reference implementation uses `ed25519-dalek` from the `dalek-cryptography` ecosystem, which provides constant-time, audited, no-`unsafe` implementations.

### 3.4.2 Post-quantum signatures: ML-DSA

ML-DSA (Module-Lattice-Based Digital Signature Algorithm) is the protocol's post-quantum signature scheme. It is standardised in FIPS 204, finalised in August 2024 by NIST. It is the lattice-based scheme formerly known as CRYSTALS-Dilithium.

**Rationale.** ML-DSA is one of three post-quantum signature schemes selected by NIST through a multi-year open competition (2017–2022). It provides security under standard lattice problem assumptions (Module Learning With Errors, Module Short Integer Solution) and has been the subject of extensive cryptanalysis without significant security degradation. Recent benchmarks (October 2025, arXiv 2510.09271) demonstrate that ML-DSA verification at security level 5 is approximately 0.14 milliseconds on ARM-based laptops — faster than ECDSA at 0.88 milliseconds. ML-DSA is therefore not a performance compromise; at the security levels relevant to long-term consensus, it is a performance improvement.

**Parameters.** The protocol uses **ML-DSA-65** (security level 3, equivalent to AES-192 or SHA-384 collision resistance), providing 192-bit classical security and approximately 128-bit security against quantum attack. Public keys are 1952 bytes; signatures are 3309 bytes. This is significantly larger than Ed25519 but acceptable for the protocol's per-transaction and per-vote cost budget.

The signature size reflects FIPS 204 (final, August 2024). The CRYSTALS-Dilithium round 3 NIST PQC submission specified 3293-byte signatures for the equivalent parameter set; the standardisation process expanded the encoding by 16 bytes for the final standard. References to the round-3 size (3293 bytes) in pre-2024 literature are obsolete; the protocol uses the FIPS 204 final size throughout.

**Why level 3 and not level 2 or level 5.** Level 2 (ML-DSA-44) provides 128-bit classical security, marginal in long-lived systems. Level 5 (ML-DSA-87) provides 256-bit classical security at significantly higher signature size (4627 bytes per FIPS 204 final) and computational cost. Level 3 is the appropriate balance for a chain whose lifetime is intended to be measured in decades.

**Account flexibility.** Section 4 specifies an account model in which an individual account may declare itself to use Ed25519 only, ML-DSA only, or both (with both required for transactions, providing belt-and-braces security). Validators `MUST` support all three account types from genesis.

**Library.** The reference implementation uses the `ml_dsa` crate from the RustCrypto project, which is the FIPS-204-compliant ML-DSA implementation. As ML-DSA implementations mature, the protocol may revise its choice of library; the algorithm choice (ML-DSA-65) is fixed.

### 3.4.3 Aggregate signatures: BLS on BLS12-381

The protocol uses BLS signatures on the BLS12-381 elliptic curve for validator vote aggregation in the consensus mechanism. BLS signatures support efficient aggregation: the signatures of N validators on the same message can be combined into a single signature whose verification cost is approximately constant in N.

**Rationale.** BLS aggregate signatures are essential for efficient DAG-based consensus at high validator counts. Without aggregation, each consensus vertex would carry hundreds of individual signatures, exhausting block bandwidth before useful payload. BLS allows a single aggregate signature to attest to validator votes at minimal marginal cost.

**Parameters.** BLS12-381 is the Barreto-Lynn-Scott curve at the 12-degree-extension construction with the specific embedding `x = -0xd201000000010000`, providing approximately 128-bit security in the optimal-Ate pairing. This curve is the de facto standard for BLS-based blockchain applications, used by Ethereum (consensus signatures), Filecoin, Zcash (Sapling), and others. Public keys are 48 bytes (G1) or 96 bytes (G2); signatures are 96 bytes (G2) or 48 bytes (G1).

The protocol uses the **G1 signature, G2 public key** variant. Signatures are smaller (48 bytes), which matters at consensus scale; public keys are larger but registered once per validator.

**Domain separation.** BLS signatures use the standardised hash-to-curve operation specified in IRTF draft `draft-irtf-cfrg-hash-to-curve` with domain tag `BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_ADAMANT_v1`. Domain separation prevents signature replay across protocols and across versions of the protocol.

**Quantum vulnerability.** BLS signatures, like all elliptic-curve schemes, are vulnerable to a future quantum adversary running Shor's algorithm. The protocol mitigates this by reserving BLS aggregation strictly for short-lived consensus messages: validator votes are valid only within a single epoch (specified in section 8) and are pruned after the epoch closes. A quantum adversary that breaks BLS in 2040 cannot retroactively forge consensus votes from 2030, because no one is verifying those votes any more — they have been finalised by recursive zk proofs (section 7) that do not depend on the original BLS signatures. Long-term security is provided by the ML-DSA layer; BLS provides efficiency for short-term consensus messaging.

**Library.** The reference implementation uses the `blst` library from Supranational, which is the highest-performance audited BLS12-381 implementation in current use. The Rust binding is `blst-rs`.

## 3.5 Symmetric encryption

The protocol uses ChaCha20-Poly1305 (RFC 8439) for all symmetric authenticated encryption, including transport encryption between nodes, encrypted-mempool transaction envelopes (in conjunction with threshold key derivation, section 3.6), and encrypted user data within accounts (section 4).

**Rationale.** ChaCha20-Poly1305 is an authenticated encryption with associated data (AEAD) scheme combining the ChaCha20 stream cipher (Bernstein, 2008) with the Poly1305 message authentication code (Bernstein, 2005). It is constant-time by construction (no S-box lookups, no timing-variable branches), software-efficient on platforms without AES-NI hardware acceleration (which includes most ARM mobile devices and many embedded systems), and has been deployed at internet scale through TLS 1.3, WireGuard, and SSH.

The alternative, AES-256-GCM, is faster on platforms with hardware AES acceleration but slower on those without; it is also more difficult to implement in constant time without hardware support. The protocol prioritises portable performance and constant-time guarantees over peak performance on the fastest server CPUs.

**Parameters.** ChaCha20-Poly1305 with 256-bit keys, 96-bit nonces, 128-bit authentication tags. Nonce-uniqueness is enforced by deriving nonces deterministically from a counter that `MUST NOT` be reused with the same key. Implementation details for nonce derivation are specified per-use in subsequent sections.

**Library.** The reference implementation uses the `chacha20poly1305` crate from RustCrypto.

## 3.6 Threshold encryption

The encrypted mempool (section 9) uses threshold encryption built on BLS12-381. Transactions are encrypted by users such that decryption requires cooperation of a threshold of validators serving as keypers. The construction is a hashed-ElGamal threshold key encapsulation mechanism (KEM) on BLS12-381, in the Boneh-Franklin / Baek-Zheng lineage, combined with Shamir secret sharing of the master secret. The same construction is deployed in production by Shutter Network on Gnosis Chain.

**High-level operation.** The validator set holds a shared master secret distributed via a distributed key generation (DKG) protocol at the start of each epoch. A user encrypts a transaction with respect to a public identifier (specifically, the consensus epoch number plus a salt). To decrypt, a threshold of validators contribute decryption shares; the shares are combined to recover a symmetric key, which is then used to decrypt the transaction's AEAD-encrypted payload. No single validator, no minority of validators, and no observer can decrypt before the threshold is reached.

**Parameters.** The threshold is set at two-thirds of validators by stake, matching the consensus safety threshold. Decryption is integrated into consensus: the act of committing a consensus vertex containing an encrypted transaction simultaneously triggers the decryption-share contribution. This integration is what allows Adamant's encrypted mempool to operate at sub-second latency, in contrast to externally-coordinated systems such as Shutter Network on Gnosis Chain (current latency approximately three minutes).

### 3.6.1 Cryptographic construction

The protocol uses a **hashed-ElGamal threshold KEM** on BLS12-381 with the following structure.

**Group orientation.** Master public key in G₂ (96 bytes compressed); decryption shares in G₁ (48 bytes compressed). This matches the BLS signature orientation in section 3.4.3 (G₁ signatures, G₂ public keys) and reuses the same hash-to-curve operation on G₁.

**Domain separation.** Threshold encryption uses its own hash-to-curve domain tag, distinct from BLS signatures:

```
BLS_TE_BLS12381G1_XMD:SHA-256_SSWU_RO_ADAMANT_v1
```

This domain separation is essential to the security of the construction. A decryption share is computationally identical to a BLS signature on the same identity under the same key share — the structural identity is what makes the construction efficient and verifiable. Without domain separation, a signature produced under a validator's signing key could be used as a decryption share, opening cross-protocol forgery attacks. The TE-specific DST cryptographically separates the two operations: a value valid as a signature under the BLS DST is computationally unrelated to a value valid as a decryption share under the TE DST.

**Algorithm specification.**

Let `r` denote the BLS12-381 scalar field order, `g₁`, `g₂` the canonical generators of G₁ and G₂, `e: G₁ × G₂ → G_T` the optimal-Ate pairing, and `H_TE: {0,1}* → G₁` the hash-to-curve operation with the TE domain tag above.

**Setup** (output of DKG specified in section 8; for testing the cryptographic primitive in isolation, a trusted-dealer Shamir secret sharing produces the same outputs).

- Master secret `s ∈ Z_r` (held collectively, never reconstructed)
- Master public key `MPK = g₂^s ∈ G₂`
- Validator shares `s_i ∈ Z_r` via Shamir secret sharing over `Z_r`, threshold `t`
- Public share verification keys `PK_i = g₂^{s_i} ∈ G₂` (published; allow verification of decryption shares)

**Encapsulate(MPK, identity, randomness) → (header, key)**:

1. `Q = H_TE(identity) ∈ G₁`
2. Sample `ρ ← Z_r` from the supplied randomness
3. `U = g₂^ρ ∈ G₂`  (the ciphertext header, transmitted alongside the AEAD ciphertext)
4. `K = KDF(e(Q, MPK)^ρ, U, identity)` — 32-byte symmetric key
5. Return `(U, K)`

**DecryptionShare(s_i, identity) → D_i ∈ G₁**:

`D_i = s_i · H_TE(identity)`

This is structurally identical to a BLS signature under the TE DST. Validators compute and broadcast `D_i` as part of consensus.

**VerifyDecryptionShare(PK_i, identity, D_i) → bool**:

`e(D_i, g₂) ≟ e(H_TE(identity), PK_i)`

Validators discard malformed shares before combination. This check is consensus-critical: a single malformed share fed into Lagrange interpolation produces an incorrect combined value that decrypts to garbage.

**Combine({(i, D_i) : i ∈ S}) → D ∈ G₁**, where `|S| ≥ t`:

`D = Σ_{i ∈ S} λ_i(0) · D_i ∈ G₁`

where `λ_i(0)` is the Lagrange coefficient at `x=0` for index `i` over the set `S`, computed in `Z_r`. The result satisfies `D = s · H_TE(identity)` by the algebraic property of Shamir reconstruction in the exponent.

**Decapsulate(D, header U, identity) → key**:

`K = KDF(e(D, U), U, identity)`

Correctness follows from bilinearity: `e(D, U) = e(s·Q, g₂^ρ) = e(Q, g₂)^{s·ρ} = e(Q, g₂^s)^ρ = e(Q, MPK)^ρ`, matching the value the encapsulator computed.

**Key derivation function (KDF).** The KDF uses tagged-SHAKE-256 per the BIP-340 tagged-hash construction in section 3.3.1, with a dedicated registry tag:

```
ADAMANT-v1-threshold-kdf
```

Input absorbed: `serialise(GT_value) || serialise(U) || identity`. Output squeezed: 32 bytes. The 32-byte output is used directly as a ChaCha20-Poly1305 key (section 3.5) to encrypt and authenticate the transaction payload.

The choice of GT-value serialisation follows the standard compressed encoding for BLS12-381 GT elements (576 bytes). The choice of U serialisation is the compressed G₂ encoding (96 bytes). Identity is the consensus epoch number (8 bytes, big-endian) concatenated with a per-transaction salt (32 bytes).

### 3.6.2 Distributed key generation

At each epoch boundary, validators run a Pedersen-style DKG to establish the new master public key and individual key shares. The DKG protocol itself is specified in section 8 alongside consensus. The specification of DKG primitives (commitment, verification) is built on KZG commitments (section 3.9.2) over BLS12-381. Phase 1 of the reference implementation provides a trusted-dealer Shamir splitter for testing the cryptographic primitive in isolation; this splitter is explicitly marked as test-only and is replaced by the production DKG when consensus is implemented.

### 3.6.3 Quantum vulnerability

Threshold encryption based on BLS12-381 is vulnerable to a quantum adversary, in the same way as BLS signatures. The protocol accepts this for the same reason: encrypted mempool envelopes are short-lived. A transaction is encrypted, ordered, and decrypted within a single epoch. After the epoch closes, the transaction is in the chain (in either shielded or transparent form) and the ephemeral encryption is no longer security-relevant. A quantum adversary in 2040 cannot retroactively decrypt transactions from 2030 in any meaningful sense — those transactions are already public knowledge or already finalised in zero-knowledge proofs that do not depend on the original encryption.

### 3.6.4 Long-term threshold encryption

If, at some future point, post-quantum threshold encryption schemes mature into production-ready form, they may be adopted via specification revision under the procedure in section 12. The protocol does not attempt to anticipate which scheme that will be.

## 3.7 Post-quantum key encapsulation: ML-KEM

The protocol uses **ML-KEM-768** (FIPS 203, the standardisation of CRYSTALS-Kyber) as the post-quantum key encapsulation mechanism (KEM). ML-KEM provides the protocol's post-quantum-secure key-agreement primitive — used wherever the protocol needs a sender to establish a shared secret with a recipient without prior communication, in a way that remains secure against future quantum adversaries.

### 3.7.1 Why a KEM, not a signature scheme

Earlier drafts of this whitepaper specified ML-DSA for the privacy layer's key-agreement surface (stealth address derivation, encrypted memo delivery). This was a primitive misidentification: ML-DSA is a signature scheme and does not support key agreement. Signature schemes prove message authorship; KEMs establish shared secrets. The post-quantum analog of the elliptic-curve Diffie-Hellman key agreement that backed earlier privacy designs is not ML-DSA but ML-KEM. Both are 2024 NIST-standardised lattice-based primitives, both have substantial implementation history, and using both is consistent with Principle VI (standard primitives, novel synthesis).

### 3.7.2 Construction

ML-KEM-768 is parameterised at NIST security level 3 (~AES-192 equivalent), matching the security level of ML-DSA-65 used for the protocol's post-quantum signatures. The KEM operations are:

- **Key generation.** Produces a public key (1184 bytes) and secret key (2400 bytes).
- **Encapsulation.** Given a public key, produces a ciphertext (1088 bytes) and a 32-byte shared secret. The ciphertext is sent to the recipient; the shared secret is used by the sender to derive symmetric keys.
- **Decapsulation.** Given a secret key and a ciphertext, recovers the shared secret. The recipient performs decapsulation using their private key.

The shared secret derived through encapsulation is computationally indistinguishable from random against any adversary not holding the secret key, including quantum adversaries operating against historical chain state.

### 3.7.3 Use sites

ML-KEM is used in the following protocol surfaces:

- **Stealth address derivation (subsection 7.2).** The recipient publishes an ML-KEM public key; senders encapsulate to it to derive the per-note shared secret used to compute the stealth address.
- **Encrypted memo delivery (subsection 7.6).** The same KEM construction encrypts memo content from sender to recipient.
- **Any future key-exchange surface.** Post-genesis privacy-relevant key exchange mechanisms must use ML-KEM or another peer-reviewed post-quantum KEM to satisfy Principle VIII.

The KEM does **not** replace ML-DSA. ML-DSA remains the protocol's identity-binding signature scheme (subsection 3.4.2). ML-KEM is added alongside it; together they cover the post-quantum-secure surfaces required by Principle VIII.

### 3.7.4 Bandwidth cost

ML-KEM ciphertexts are ~1.1KB per encapsulation. Stealth-address-derivation ciphertexts are stored on-chain as part of the note-publishing transaction. At the protocol's design-target throughput, this is per-note overhead, not per-transaction overhead — most transactions involve few notes. The total bandwidth and storage cost is tractable (subsection 7.2's analysis quantifies it). The per-note ciphertext size is the engineering cost of post-quantum-secure historical privacy; the protocol accepts this cost for the permanence of the privacy guarantee.

### 3.7.5 Implementation

The reference implementation uses the `ml-kem` crate from the `RustCrypto` project (or equivalent audited library) at the FIPS 203 parameter set. Constant-time implementation is required; the library's published timing characteristics are reviewed during cryptographic audit (subsection 3.11).

### 3.7.6 Quantum vulnerability

ML-KEM's security rests on the Module Learning With Errors (MLWE) problem, conjectured to be hard against both classical and quantum adversaries. No quantum algorithm is known that solves MLWE substantially faster than classical algorithms; the conjecture is the basis of NIST's selection of CRYSTALS-Kyber as the standardised KEM. The protocol therefore treats ML-KEM as plausibly post-quantum-secure for the operational lifetime of the chain. As with ML-DSA, future cryptanalysis may erode the security margin; specification revision under section 3.12 addresses this if needed.

## 3.8 Time-lock encryption (Wesolowski VDF)

Threshold encryption (subsection 3.6) requires a coordinated active set running distributed key generation. At the constitutional active-set floor of 7 (subsection 8.1.3) and during periods between activation and the threshold-encryption viability boundary (N=15), the chain cannot run threshold encryption with parameters that provide meaningful protection — at N=4 the threshold scheme is trivially breakable by 2-validator collusion; at N=7 it offers limited margin. To preserve mempool encryption (Principle II) during the low-N period, the protocol uses **time-lock encryption** based on a **publicly-verifiable Verifiable Delay Function (VDF)**.

A VDF is a function whose evaluation requires a specified amount of sequential computation (and cannot be parallelised) but whose output can be verified cheaply. Time-lock encryption uses a VDF to create a ciphertext that decrypts only after a specified delay, regardless of who attempts decryption. This works at any active-set size, including N=1 — there is no DKG, no threshold, no key-agreement step among validators.

### 3.8.1 The Wesolowski construction

The protocol uses the Wesolowski VDF (Wesolowski 2019) over class groups of imaginary quadratic order (or, optionally, over RSA groups; the choice is implementation-defined and does not affect protocol correctness). Class groups are preferred because they require no trusted setup — there is no group element whose secret factorisation could compromise the construction.

The construction is summarised:

- **Setup.** A class group of unknown order is fixed at protocol initialisation. The group's parameters are derived deterministically from the genesis state (subsection 11.2.8) using a hash-to-class-group construction. There is no secret involved.
- **Encryption.** A user encrypts a transaction by sampling a random group element `g` and computing `h = g^(2^T)` for the time-lock parameter T. The transaction's symmetric encryption key is derived from `h`. The user publishes `g`, the symmetric ciphertext, and a Wesolowski proof of knowledge of `h` (this last is required only to prevent malformed envelopes, not for security against time-locked decryption).
- **Decryption.** A validator (specifically, the round anchor for the round in which the transaction is included; subsection 8.4.4) computes `h = g^(2^T)` by performing T sequential squarings, then derives the symmetric key and decrypts. The computation is by construction sequential — no parallel speedup exists.
- **Verification.** Any party can verify that the published `h` is correct given `g` and T by checking the Wesolowski proof. The proof is a single class-group element and verifies in constant time.

### 3.8.2 Parameter selection

The time-lock parameter T determines the decryption delay. T is calibrated so that a single squaring takes approximately the targeted per-transaction delay divided by the wall-clock decryption budget. For the protocol's design target of 10–15 seconds of decryption delay on consensus-grade hardware (sufficient to prevent immediate decryption by external observers but short enough that user inclusion latency remains tolerable):

- A modern consensus-grade desktop performs approximately 200,000–500,000 class-group squarings per second
- T = 2,000,000–7,500,000 produces 10–15 seconds of decryption time
- The exact value is calibrated empirically before genesis and committed as a chain-state parameter at activation

The class-group discriminant size is selected to provide approximately 128 bits of security against the best-known classical attacks. Class groups of discriminant size 2048 bits are sufficient. Larger discriminants slow squaring proportionally and may be preferred for higher security levels at the cost of slower decryption.

### 3.8.3 Public verifiability requirement

The protocol specifies a **publicly-verifiable** VDF (Wesolowski's construction satisfies this; Pietrzak's construction, also publicly-verifiable, would be an acceptable alternative; black-box VDFs that produce only the output without a verification proof are explicitly excluded). Public verifiability is required because subsection 8.4.4's anchor-rotation and decryption-publication-binding mitigations depend on observers being able to verify that the round anchor finished the VDF computation at the correct time and published the correct result. Without public verifiability, those mitigations cannot detect anchors that publish forged decryption claims, and the time-lock regime's MEV protection collapses.

### 3.8.4 Quantum vulnerability

Wesolowski's VDF security depends on the unknown-order assumption in class groups, which is conjectured to hold against quantum adversaries (Shor's algorithm does not directly apply because class groups are not cyclic of known order). The construction is therefore *plausibly* post-quantum but not formally proven to be. For the mempool-encryption use case this is acceptable because mempool envelopes are short-lived (decrypted within the same epoch they are submitted); a quantum adversary in 2040 cannot retroactively decrypt mempool transactions from 2030 in any meaningful sense, since those transactions are already finalised in chain state.

### 3.8.5 Transition to threshold encryption

When the active set crosses the viability boundary N≥15 (subsection 8.4.2), the chain transitions from time-lock encryption to threshold encryption automatically. The transition is one-way per epoch: the chain operates one regime per epoch, never both simultaneously, with hysteresis (switch to threshold at N≥15; switch back at N<10) preventing flapping at the boundary. Pending time-lock-encrypted transactions submitted before the transition complete decryption normally; new transactions submitted after the transition use the threshold key.

## 3.9 Zero-knowledge proofs

The protocol's privacy layer (section 7) and recursive verification (section 8) use zero-knowledge succinct non-interactive arguments of knowledge (zk-SNARKs). Two specific systems are used: **Halo 2** for general-purpose proving with no trusted setup, and **KZG commitments** as a building block for vector commitments and for state commitments inside the consensus layer.

### 3.9.1 General-purpose proving: Halo 2

Halo 2 is a zk-SNARK proving system using the PLONK arithmetisation (Plonkish) over the Pasta curves (Pallas and Vesta), with a polynomial commitment scheme based on the inner product argument (IPA). It does not require a trusted setup ceremony.

**Rationale.** Trusted setups are a structural compromise: they introduce a step in the protocol's lifecycle during which a particular set of participants holds toxic waste whose disclosure would compromise the system. Halo 2's transparent setup eliminates this. The cost is somewhat larger proof sizes and longer verification times than equivalent KZG-based systems with trusted setup. The protocol accepts this cost in exchange for the elimination of the trusted-setup compromise, which is consistent with Principle I (credible neutrality): a trusted setup is a residual centralising assumption.

**Parameters.** Halo 2 is parameterised by the underlying curve and the circuit's row/column structure. The protocol uses the Pasta curves (Pallas as the primary curve, Vesta for recursion) at standard parameters. Specific circuit dimensions are specified per-use throughout the privacy and verification sections.

**Recursive proof composition.** Halo 2's design supports efficient recursive proof composition through the Pasta cycle: a Pallas-curve proof can be verified in a Vesta-curve circuit and vice versa. This is the foundation of Adamant's phone-verifiable property: the entire chain history is compressed into a single recursive proof verifiable on consumer hardware.

**Library.** The reference implementation uses the Halo 2 implementation maintained by the Zcash project (not the original Electric Coin Company implementation, which was deprecated; the maintained fork lives under `halo2`). This implementation is in production in Zcash's Orchard pool and is the most heavily-deployed Halo 2 implementation in existence.

### 3.9.2 Vector and polynomial commitments: KZG

KZG commitments (Kate, Zaverucha, Goldberg 2010) are used inside the consensus layer for state commitments and for certain operations within the encrypted mempool. KZG commitments require a trusted setup: a set of values `[g, g^τ, g^{τ^2}, …, g^{τ^n}]` for a secret `τ` that must be irrecoverably destroyed.

**Justification of trusted setup.** This is the only place in the protocol where a trusted setup is used, and the use case is narrow: KZG commitments are used for fixed-size vector commitments where Halo 2's transparent commitment scheme would be unacceptably large. The trusted setup is exposed only to the size of vectors used inside consensus operations (specifically, validator-set-size vectors), not to general-purpose proving.

**Mitigation: Powers of Tau.** The protocol uses the Ethereum KZG Powers of Tau ceremony output, which had over 140,000 participants between January and July 2023. The security of this setup requires that at least one participant honestly destroyed their contribution; the very large number of participants means that the assumption is violated only if every single participant was simultaneously colluding, which is implausible. The protocol's reuse of this existing ceremony output, rather than running a new one, is deliberate: it transfers all of the cryptographic confidence accumulated by Ethereum's ceremony to Adamant at no marginal cost.

**Parameters.** The protocol uses KZG commitments on BLS12-381, with a trusted setup of size 2^16 (sufficient for validator sets up to approximately 65,000, well above any plausible operational set size). The specific Powers of Tau output used is documented in section 11 (genesis specification).

**Library.** The reference implementation uses the KZG implementation from the `arkworks` ecosystem.

## 3.10 Randomness

The protocol requires randomness in several contexts, each with different properties.

**Per-signature randomness.** Ed25519 is deterministic (signatures derive their randomness from the message and key, eliminating the per-signature randomness requirement). ML-DSA is also deterministic in its standard mode. The protocol uses deterministic signing throughout, eliminating any dependency on the quality of per-signature randomness sources.

**Cryptographic key generation.** Users generating new keys `MUST` use a cryptographically secure random number generator (CSPRNG). The protocol does not specify the user's CSPRNG; this is a property of the user's operating system and wallet software. Reference wallet implementations use `getrandom` on Unix and `BCryptGenRandom` on Windows.

**Consensus randomness.** The consensus protocol (section 8) requires randomness for sequencer selection and for deterministic transaction ordering within DAG vertices. This randomness is derived from a verifiable random function (VRF) bound to validator BLS keys, with output committed in each consensus vertex and verifiable by all participants. The VRF construction is specified in section 8.

**Threshold-encrypted nonces.** The encrypted mempool requires per-transaction nonces that are unpredictable to adversaries. These are derived deterministically from the user's signing key and a transaction-specific identifier, ensuring that each nonce is unique without requiring access to a runtime randomness source.

## 3.11 Library and implementation discipline

The reference implementation `MUST` adhere to the following discipline regarding cryptographic libraries:

1. **No hand-rolled cryptography.** The reference implementation `MUST NOT` include hand-rolled implementations of any cryptographic primitive specified in this section. Where a Rust library is named in a subsection above, that library or an equivalent audited library is the only acceptable implementation source.

2. **Constant-time implementation required.** All cryptographic operations on secret material `MUST` be implemented in constant time. The named libraries (`ed25519-dalek`, `ml_dsa`, `blst`, `chacha20poly1305`) are constant-time by design. New library choices `MUST` preserve this property.

3. **No `unsafe` in cryptographic code.** Rust's `unsafe` keyword permits the bypass of memory-safety guarantees. Cryptographic libraries used by the reference implementation `SHOULD` minimise their use of `unsafe` and `MUST` document and justify any uses. The named libraries either avoid `unsafe` entirely or restrict it to well-audited, performance-critical sections.

4. **Audit history required.** Cryptographic libraries `MUST` have a documented audit history before adoption. New libraries proposed for inclusion `MUST` undergo audit prior to deployment in genesis.

5. **Upstream contribution.** Where the reference implementation requires improvements to upstream cryptographic libraries (performance, additional functionality, bug fixes), contributions `MUST` be offered upstream rather than maintained as forks.

## 3.12 Migration and revision

The cryptographic primitives specified in this section are part of the protocol's consensus rules. Their modification falls under Principle I (credible neutrality): no on-chain mechanism can alter them. Migration to new primitives requires the publication of a new client implementation that node operators individually adopt, in the same manner as any other consensus rule change.

**Anticipated migrations.** The protocol anticipates two categories of cryptographic migration during its operational lifetime:

1. **Algorithmic improvements.** New zero-knowledge proving systems (post-Halo 2), new lattice-based signature schemes (post-ML-DSA), and new threshold encryption schemes are likely to mature into production-ready form during the chain's lifetime. These migrations, if they occur, will be additive: new primitives are introduced alongside existing ones, accounts and applications can elect to use them, and existing primitives are deprecated only after extensive transition periods.

2. **Quantum-induced migrations.** If a quantum adversary materialises before the protocol's BLS-based consensus signatures have been deprecated in favour of post-quantum alternatives, the protocol's safety would be at risk. The protocol's response is the migration path described in section 11: validator signing material can be rotated to ML-DSA-only at the validator's discretion, and consensus signatures can be migrated to a post-quantum aggregation scheme when one matures. The exact mechanism is specified in section 8.

The protocol does not attempt to specify in advance the exact form these migrations will take. The principle is that migrations occur via the same mechanism as any consensus change: through the ordinary process of client release and individual operator opt-in, on a timescale long enough that no party can force a migration on the rest of the network.

## 3.13 What this section does not specify

For clarity, the following are deliberately not specified in this section and are deferred to later sections:

- The exact use of each primitive in transaction structure: deferred to section 5 (Object Model & State).
- The construction of zero-knowledge circuits for shielded execution: deferred to section 7 (Privacy Layer).
- The integration of threshold encryption into the mempool and consensus: deferred to sections 8 (Consensus) and 9 (Networking & Mempool).
- The recursive proof structure attesting to chain validity: deferred to section 8 (Consensus).
- The genesis state, including the specific Powers of Tau parameters: deferred to section 11 (Genesis & Constitution).

This section establishes the primitives. Subsequent sections specify how they are composed.
# 4. Identity & Accounts

This section specifies how identity is represented on Adamant: how accounts are constructed, how keys authorise transactions, how users delegate visibility through view keys, and how recovery from key loss is handled. The design follows directly from the principles in section 2: privacy by default (II), permissionless participation (VII), and the cryptographic primitives in section 3.

The protocol's account model is uncompromisingly modern: **every account is a smart account from genesis**. There is no distinction between "externally-owned accounts" and "contract accounts" as found in Ethereum. There is no special category of account with privileged validation logic. There is no account type that requires migration to access account-abstraction features. Account abstraction is not a feature layered on top of the base protocol; it is the only model the base protocol supports.

This is the model used by zkSync Era, StarkNet, and Aptos, and it is the only sensible model for a chain designed in 2026. ERC-4337-style add-on architectures exist on Ethereum because Ethereum's account model was fixed in 2015 and cannot be changed without breaking compatibility. Adamant has no such constraint and uses the cleaner design.

## 4.1 What an account is

An Adamant account is an on-chain object (objects are specified in section 5) with the following minimum properties:

1. **An address.** A 32-byte identifier derived deterministically from the account's initial public key material at creation time. Addresses are stable: an account's address never changes, even if its keys are rotated.

2. **Authentication state.** The set of cryptographic public keys, validation rules, and other authentication parameters the account uses to determine whether a given transaction is authorised.

3. **Validation logic.** The function that, given a candidate transaction and the account's authentication state, returns either *valid* or *invalid*. This logic is expressed in the protocol's smart-contract language (section 6) and is invoked for every transaction submitted under this account's authority.

4. **Mutability declaration.** The account's mutability policy, declared at creation, governing whether and how the validation logic and authentication state may change. Mutability is one of the standard policies described in section 2.5 (`IMMUTABLE`, `OWNER_UPGRADEABLE`, etc.).

5. **State.** Any account-specific data the account needs to maintain. By default this includes a transaction nonce counter (to prevent replay) and a sequence of any objects the account holds. Accounts may declare additional state at creation.

6. **View key set (optional).** A set of view keys that allow specified third parties to observe the account's transaction history without granting transaction-authorisation power. Specified in detail in section 4.4.

This list is the minimum. Accounts may declare additional fields at creation, subject to the validation rules of the smart-contract language.

## 4.2 Account creation

Accounts are created on Adamant by submitting an account-creation transaction. The transaction specifies:

- The initial authentication state (public key(s), validation rules)
- The validation logic (the smart-contract code that determines authorisation)
- The mutability declaration
- Any initial state values
- An optional human-readable label (no on-chain semantics; for wallet display only)

The address of the new account is computed as `SHA3-256(domain_tag || creation_tx_hash || creator_address || index)` where `index` is a per-creator counter ensuring uniqueness. Accounts are not created at "well-known" addresses; there is no equivalent of Ethereum's `CREATE2` predictable address mechanism, because the protocol's privacy model makes pre-funding of unfunded addresses unnecessary.

**No account creation gating.** Account creation is permissionless. The cost of creating an account is paid in the standard fee mechanism (section 10). There is no minimum balance, no whitelist, and no creator-specific privileges.

**No precompiled accounts.** The protocol contains no built-in accounts with privileged behaviour. There is no equivalent of Ethereum's precompiled contracts (`0x1` through `0x9`) or system contracts. Every account on the chain is created through the same mechanism described above. This is required by Principle I.

## 4.3 Authentication

When a transaction is submitted under an account's authority, the protocol invokes the account's validation logic with the transaction's contents as input. The validation logic returns *valid* or *invalid*. *Valid* causes the transaction to be admitted to the mempool and processed; *invalid* causes it to be rejected before any state change.

The validation logic is arbitrary smart-contract code, subject only to the resource limits described in section 6. This is the substance of "smart accounts": validation is *programmable*. Standard validation patterns supported by reference implementations include:

### 4.3.1 Single-signature validation

The simplest pattern: the account holds a single public key — Ed25519 or ML-DSA — and a transaction is valid if and only if it carries a signature from the corresponding secret key over the transaction's canonical encoding.

This pattern is the default for new user accounts created by reference wallets. Per Principle VIII (subsection 2.8), Ed25519 is the wallet default for ordinary transaction signing because of its substantially smaller signature size (64 bytes vs ~3.3KB for ML-DSA-65), with wallets opting users up to ML-DSA per-transaction above a configurable value threshold and offering ML-DSA-only single-signature accounts for users whose threat model warrants it. The chain accepts any single-signature account regardless of which scheme the user chose. It approximates the user experience of legacy externally-owned accounts on other chains while remaining smart-account-native.

### 4.3.2 Dual-signature validation (classical + post-quantum)

The protocol's recommended pattern for accounts intending to hold significant value over long timescales: the account holds both an Ed25519 key and an ML-DSA key, and a transaction is valid only if it carries valid signatures from both.

This pattern provides defence in depth. An adversary capable of compromising Ed25519 (for example, a future quantum adversary) cannot forge transactions because they would also need to compromise ML-DSA. An adversary capable of compromising ML-DSA (for example, an unforeseen lattice attack) cannot forge transactions because they would also need to compromise Ed25519. The account is secure unless *both* schemes are simultaneously broken.

The cost is that signing requires both keys to be available, and the signature itself is larger (Ed25519 is 64 bytes, ML-DSA-65 is 3293 bytes). For long-term storage of value, this is an acceptable trade-off.

### 4.3.3 Threshold-signature validation

The account holds N public keys and a threshold k. A transaction is valid if at least k of the N keys have signed it. This is the standard multi-signature pattern, expressed natively in the smart-account model rather than requiring a separate multisig contract.

Common configurations: 2-of-3 (a typical personal multi-device setup), 3-of-5 (a typical institutional setup), m-of-n where the keys are held by a board of trustees.

### 4.3.4 Time-locked validation

The account's validation logic may incorporate time-based constraints. Examples:

- **Spending limits.** A transaction transferring more than X tokens within a Y-second window requires additional signatures.
- **Cooling periods.** Certain operations require a delay between submission and execution, during which they may be cancelled.
- **Beneficiary access.** Specific keys gain transaction authority only after the account has been inactive for a specified period (a dead-man's-switch pattern, useful for inheritance arrangements).

### 4.3.5 Session keys

A session key is a secondary key authorised to submit a restricted class of transactions on behalf of the account, typically time-bounded and scope-restricted. Example: an account's primary key (held offline) authorises a session key to make transactions of value less than X with a specific application contract for the next 24 hours. The application can then operate without prompting the user for signatures every transaction, while the user retains protection against runaway authority.

Session keys are a natural use of the smart-account model: the validation logic specifies that signatures from the session key are accepted only when the transaction matches the session key's restrictions. This is the same pattern used by StarkNet's session keys (deployed in production for game applications such as Cartridge's Flippy Flop, October 2024) and by various account-abstraction systems on Ethereum.

### 4.3.6 Custom validation

The above patterns are illustrative, not exhaustive. The validation logic can implement any logic expressible in the smart-contract language: passkey signatures (WebAuthn), threshold-encrypted shares, social-recovery rules, biometric-gated transactions (via attested device signatures), and arbitrary combinations thereof. The protocol does not prescribe what validation looks like; it provides the framework within which any validation policy can be expressed.

## 4.4 View keys and selective disclosure

Adamant transactions are private by default (Principle II). The account holder, by default, is the only party who can observe their account's transaction history in clear form. This is the protocol's security baseline.

But many legitimate use cases require selective disclosure: a user proving their tax obligations to a government, a business proving its solvency to an auditor, an exchange proving its reserve composition to its customers. The view-key mechanism enables these use cases without compromising default privacy.

### 4.4.1 What a view key is

A view key is a cryptographic key that grants the holder the ability to *observe* an account's transactions in clear form, but not to *authorise* new transactions. It is a one-way trapdoor: a user can derive view-key access from their full account access, but a view-key holder cannot derive transaction-authorisation access from a view key.

Concretely: a user account holds a master seed. The master seed deterministically generates two distinct keypairs: the *spending key*, which is used in transaction validation, and the *viewing key*, which is used to decrypt the user's own transactions on the chain. The spending key cannot be derived from the viewing key. The user can disclose the viewing key (or sub-keys derived from it) to any third party without granting them spending power.

This construction follows the design used in Zcash since Sapling (2018) and refined in subsequent shielded-pool protocols. It is a well-understood pattern with substantial deployment evidence.

### 4.4.2 Sub-view-keys for granular disclosure

The viewing key is hierarchically structured. A user can derive sub-keys that grant visibility into restricted subsets of their transactions. Examples:

- **Time-bounded view key.** Visibility into transactions occurring between dates D1 and D2 only, useful for annual tax filings without exposing other periods.
- **Counterparty-bounded view key.** Visibility into transactions involving a specific counterparty only, useful for proving a specific commercial relationship without exposing unrelated activity.
- **Amount-bounded view key.** Visibility into transactions exceeding a specified amount only, useful for high-value-transaction reporting requirements.

Sub-view-key derivation is specified cryptographically by section 7 (Privacy Layer); from the user's perspective, wallets expose this as "create an audit key for [specific use]" with the relevant parameters.

### 4.4.3 View keys are not surveillance

The protocol's view-key mechanism is fundamentally different from surveillance-friendly architectures (such as backdoor decryption, key escrow, or "lawful access" mechanisms). The differences:

1. **User-controlled disclosure.** Only the account holder can issue a view key. The protocol contains no mechanism by which any other party — not validators, not the original implementers, not governments — can compel decryption against the user's will.

2. **Granular and revocable.** The user controls the scope of disclosure (which transactions, over which period) and can stop deriving new sub-keys at any time. Already-issued sub-keys reveal only the data they were authorised to reveal; they cannot be retroactively expanded.

3. **No technical means of compulsion.** The protocol does not include any mechanism for a third party to demand a view key cryptographically. A user who refuses to disclose simply does not disclose; the protocol provides no means of override.

The view-key mechanism is therefore a tool for the user, available when the user chooses to use it, not an infrastructure for compelled disclosure.

## 4.5 Key rotation

A user `MUST` be able to rotate the keys associated with their account without changing the account's address or losing access to their state.

**Mechanism.** Key rotation is performed by submitting a transaction signed under the account's *current* validation logic that updates the authentication state to a new set of keys. The transaction has the same structure as any other transaction; the only difference is its target (the account's own authentication state) and its effect (replacing keys).

**Constraints by mutability declaration.** Whether key rotation is permitted at all, and under what conditions, depends on the account's mutability declaration (section 2.5):

- `IMMUTABLE` accounts: rotation is forbidden. The account's keys are fixed at creation.
- `OWNER_UPGRADEABLE` accounts: rotation requires a signature from the designated owner key.
- `VOTE_UPGRADEABLE` accounts: rotation requires a vote from the designated token holders meeting the specified threshold.
- `UPGRADEABLE_UNTIL_FROZEN` accounts: rotation is permitted until the account is frozen, then forbidden.
- `CUSTOM` accounts: rotation follows the rules declared at account creation.

**Rotation is not migration.** Rotating keys is distinct from migrating to a different account. Rotation preserves the account's address, state, holdings, view keys, and transaction history. The account is the same account; only the keys that authorise it have changed.

**Why rotation matters.** Long-lived accounts will need to rotate keys for many reasons: routine key hygiene, response to suspected compromise, transition to post-quantum keys as cryptographic best practice evolves, transition between hardware-wallet generations, and changes in the user's threat model. The protocol makes this a first-class operation rather than requiring users to migrate to a new account.

## 4.6 Recovery

Key loss — losing the ability to sign transactions because the secret key has been lost, destroyed, or rendered inaccessible — is the single most common failure mode in cryptocurrency. The protocol does not solve this problem at the cryptographic layer; it provides building blocks that allow users to construct recovery solutions appropriate to their threat model.

### 4.6.1 The protocol provides no built-in recovery

There is no protocol-level mechanism by which a lost key can be replaced without authority from the existing account. There is no foundation that can issue replacement keys. There are no validators with the authority to override an account. The protocol's commitment to credible neutrality (Principle I) precludes any such mechanism.

A user who creates an `IMMUTABLE` single-signature account and loses the key has lost the account. The protocol does not provide a fallback. This is a property of the security model, not an oversight.

### 4.6.2 What the protocol enables

The smart-account model enables users to construct recovery mechanisms appropriate to their needs. The most common patterns:

**Social recovery.** The account is configured such that a quorum of designated "guardians" — friends, family members, multiple devices — can collectively rotate the account's keys, even without the original key. Each guardian holds a key that, in isolation, has no power; only when k of n guardians cooperate can a new authorisation key be installed. This is the model used by Argent (deployed since 2018) and the Ethereum Foundation has explicitly endorsed it as the recommended recovery pattern. The protocol supports this natively through the smart-account validation model.

**Time-locked recovery.** The account is configured such that a recovery key gains the ability to rotate the account's keys, but only after a delay (e.g. seven days) during which the account holder can cancel the recovery using their primary key. An adversary who steals the recovery key cannot use it immediately; the legitimate holder has a window to detect and abort. This is a useful pattern when the recovery key is held by an institution (a law firm, a digital-estate service) whose attack surface is non-zero.

**Multi-device redundancy.** The account is configured as a 2-of-3 threshold with keys held on three distinct devices (phone, laptop, hardware wallet). Loss of any one device does not compromise the account; loss of two simultaneously is required.

**Inheritance arrangements.** The account is configured such that, after a specified period of inactivity (no signed transactions for, say, twelve months), beneficiary keys gain transaction authority. The account holder can defeat this by signing any transaction during the inactivity period. This is a dead-man's-switch pattern useful for digital inheritance.

**Hardware-secured recovery.** Recovery keys are held in hardware security modules, secure elements, or third-party custodial services. The protocol does not specify the hardware; it specifies that the validation logic can incorporate signatures from hardware-attested keys.

The protocol's role is to provide the framework. The user's role is to choose a configuration appropriate to their needs and to communicate with their guardians, beneficiaries, or service providers about the implications.

### 4.6.3 Wallet defaults

Reference wallets `SHOULD` strongly default new user accounts to a recovery-enabled configuration. The exact default is wallet-specific, but the principle is that a user creating their first account `SHOULD NOT` be defaulted to an `IMMUTABLE` single-signature configuration without explicit informed consent. The risk of catastrophic loss to inexperienced users is too high to justify defaults that leave them no recovery path.

A recommended default for new user accounts is: `OWNER_UPGRADEABLE` with social recovery, requiring 2-of-3 guardians (one of which may be the user's own backup device, two of which are external). This default provides reasonable protection against routine key loss while preserving full user control.

## 4.7 Privacy of accounts

By default, account addresses are not directly observable from transaction data. The transaction format (specified in section 5) does not include cleartext sender or recipient addresses; instead, it references shielded notes whose ownership is verifiable only by the parties holding the relevant view keys.

This means that account-level analysis ("how many transactions has this address sent?") is not possible from the chain alone, by design. An observer can see *that* transactions occurred (the encrypted envelope and the proof that it is well-formed) but not *which addresses* were involved.

**Optional transparency.** A user may submit a transaction in transparent form, exposing sender, recipient, and amount in cleartext. This is useful for specific applications: public charitable donations, public bounty payments, transparent governance votes (when those occur off-protocol, as Adamant has no on-chain governance), and similar contexts. Transparency is a per-transaction choice, not a chain-wide default, and not a property of the account itself.

**Account discoverability.** Because addresses are not exposed by default, accounts are *not* easily discoverable from chain data. This is the inverse of the assumption built into chains where every transaction exposes its participants. The implication for user-experience: an account "exists" as soon as it is created, but it is not visible to third parties unless the holder discloses its address (typically via off-chain channels: paste an address into a chat, scan a QR code, share via a payment-request URI).

Reference wallets handle address sharing through the standard mechanisms used by privacy chains: stealth addresses, shareable payment requests, or QR-encoded one-time identifiers. Section 7 specifies the cryptographic basis for stealth addresses; section 4 establishes only that account addresses are not assumed to be public.

## 4.8 Worked example: a typical user account

To make the foregoing concrete, here is the configuration of a typical personal account created by a reference wallet for a new user:

- **Mutability:** `OWNER_UPGRADEABLE`
- **Authentication:** dual-signature (Ed25519 + ML-DSA), with the keys derived from the user's recovery seed phrase
- **Recovery:** social recovery configured with three guardians, requiring two to authorise a key rotation
- **View keys:** generated and stored locally; not yet shared with any third party
- **Session keys:** none initially; added per-application as the user grants permissions
- **Spending limits:** $10,000 USD-equivalent per 24-hour period without additional signatures (configurable)
- **Transaction privacy:** shielded by default; transparency available per-transaction

This configuration trades some complexity (the user needs three guardians) for a substantial improvement in security relative to a legacy single-key account. It supports key rotation without migration, recovery from key loss without protocol-level intervention, and audit cooperation through view-key derivation as needed. It is post-quantum-secure (via the ML-DSA component) and compatible with the encrypted-mempool architecture.

Reference wallets `SHOULD` make this configuration achievable in approximately the same number of user actions as creating a legacy single-key account elsewhere. The complexity is the wallet's responsibility, not the user's.

## 4.9 Account-level fees and gas

This section briefly anticipates section 10 (Economics & Incentives). Account-related operations — creation, key rotation, validation logic invocation — are subject to the protocol's fee mechanism. The fee for account creation is paid by the creator. Validation logic invocation (which occurs for every transaction the account submits) is paid by whichever party the validation logic specifies as fee-payer; this enables sponsored transactions, where an application or paymaster pays fees on behalf of the user.

Section 10 specifies fee structure in detail. The note here is that the smart-account model permits fee abstraction natively: the question of "who pays" is part of the validation logic, not a separate concept.
# 5. Object Model & State

This section specifies how Adamant represents data on the chain. It is the longest technical section in the whitepaper because the object model touches every other component: it determines what transactions can do, what the virtual machine operates on, what the consensus mechanism orders, what the privacy layer shields, and what the recursive verification proves.

The protocol's data model is **object-based**. The chain's state is a collection of independent objects, each owned by an account or shared between accounts according to declared rules, each carrying its own validation logic and mutability declaration. This is the model used by Sui (Move objects), with significant divergences specific to Adamant's privacy and credible-neutrality requirements.

The object model deliberately rejects three alternatives:

1. **The account-balance model** (Ethereum, Solana, Cosmos). State is a flat key-value mapping from account addresses to balances and contract storage. Every transaction touches global mutable state. This model is the easiest to reason about but the hardest to parallelise, and it requires every validator to process every transaction to know any state.

2. **The pure UTXO model** (Bitcoin, Cardano). State is a set of unspent transaction outputs; transactions consume some and produce others. Highly parallelisable but limited in expressiveness; smart-contract programmability requires substantial workarounds.

3. **The actor model** (TON, Internet Computer). State is partitioned into independent actors that communicate by asynchronous message-passing. Highly parallelisable but introduces a difficult programming model and requires reasoning about message ordering across actors.

The object model preserves the parallelism of UTXOs, the expressiveness of accounts, and the modularity of actors. It is the modern consensus among new Layer 1 designs (Sui, Aptos with Move, the various Move-derivative chains) for good reason: it is what works.

## 5.1 What an object is

An Adamant object is a typed, addressed, ownership-tracked piece of state. Every object has the following fields:

```
Object {
    id:            ObjectId,        // 32-byte unique identifier
    type_id:       TypeId,          // identifier of the object's type definition
    owner:         Ownership,       // who can mutate this object
    mutability:    Mutability,      // how the object's code/rules can change
    contents:      Bytes,           // type-specific serialized data
    version:       u64,             // monotonic version counter
    metadata:      ObjectMetadata,  // protocol-managed bookkeeping
}
```

Each field is specified below.

### 5.1.1 ObjectId

The object's unique identifier on the chain. 32 bytes, computed as `SHA3-256(domain_tag || creation_tx_hash || creator_address || creation_index)`. Once assigned, an `ObjectId` never changes. Object identifiers are stable across the object's lifetime: an object that exists at version 1 has the same `ObjectId` at version 1,000,000.

The `creation_tx_hash` is the `TxHash` of the transaction that created this object, computed per section 6.0.4. The `creator_address` and `creation_index` are declared in the transaction's `created_objects` list per section 6.0.2.

This is in contrast to UTXO models, where each "version" of a piece of state has a distinct identifier. Stable identifiers make programs easier to write (a contract holds a reference to a specific object across many transactions) and make the privacy model simpler (one anonymity set per long-lived object, rather than a fresh anonymity set per output).

### 5.1.2 TypeId

The identifier of the object's type. Object types are themselves on-chain objects (specifically, instances of the `Type` meta-type, registered through the type-registration mechanism in section 6). The `TypeId` references the type definition that specifies:

- The schema of the object's `contents` field (what fields it has, what their layouts are)
- The set of operations valid on objects of this type (the object's "methods" in object-oriented terminology)
- Invariants the protocol enforces on every state transition involving objects of this type
- Default mutability rules for objects of this type at creation (which the creator may override per-object)

A `TypeId` is itself a 32-byte hash of the type's canonical definition. Two distinct type definitions with identical canonical encodings produce the same `TypeId`; this is intentional and supports content-addressed type registration.

### 5.1.3 Ownership

The protocol supports four ownership modes:

- **`Address(addr)`**: the object is owned by a single account. Only transactions authorised under that account's validation logic may mutate the object. This is the default for user-held assets such as token balances, NFT-like unique items, and personal data.

- **`Shared`**: the object has no single owner; any transaction may mutate it, subject to the object's own validation rules. Shared objects are the basis for all multi-party applications: decentralised exchanges, lending pools, governance contracts, registries. Mutations of shared objects require consensus (section 8) because two transactions touching the same shared object may conflict.

- **`Immutable`**: the object can never be mutated after creation. Useful for published documents, code modules, type definitions, and other objects intended to be permanent reference material. Immutable ownership is distinct from `IMMUTABLE` mutability declarations (section 5.3): an immutable-owned object cannot be mutated by anyone, while an `IMMUTABLE`-mutability object cannot have its *rules* changed but can still have its `contents` mutated according to those rules.

- **`Group(g)`**: the object is owned by a *group object*, which is itself an object on the chain. The group's validation logic determines whether a given transaction is authorised to mutate the group-owned object. This is the mechanism for multi-signature ownership, organisational ownership, and complex shared-control patterns. The group is itself owned by some entity (an address, another group, or `Shared`), giving rise to nested ownership trees.

Ownership is a property of the object, not of the account. An account holds a set of objects; transferring an object to another account is a state transition that updates the object's `owner` field, leaving the object's identity and contents otherwise unchanged.

**Ownership transitions.** An object's ownership may be transferred subject to the rules of its current ownership mode and the object's mutability declaration. Specifically: an `Address`-owned object may be transferred by the owning account; a `Shared` object may not be made `Address`-owned without explicit consent in the protocol's transition logic; an `Immutable` object's ownership cannot change (it remains permanently un-owned); a `Group`-owned object's ownership transitions follow the group's rules.

### 5.1.4 Mutability

This is the field that operationalises Principle V (mutability as a property of objects, not the chain). Every object declares its mutability at creation, and the declaration is itself immutable: an object created `IMMUTABLE` cannot become `OWNER_UPGRADEABLE`; an object created `OWNER_UPGRADEABLE` cannot become `IMMUTABLE` except via the `UPGRADEABLE_UNTIL_FROZEN` mechanism, which itself was declared at creation.

The protocol defines six mutability variants:

```
enum Mutability {
    Immutable,
    OwnerUpgradeable {
        owner: AccountId,
    },
    VoteUpgradeable {
        token_type: TypeId,
        approval_threshold: u32,    // basis points: 10000 = 100%
        quorum_threshold: u32,      // basis points
        voting_period_secs: u64,
        execution_delay_secs: u64,
    },
    UpgradeableUntilFrozen {
        owner: AccountId,
        // The Mutability field itself does not change after `freeze`;
        // the object's Lifecycle field transitions to Frozen, and the
        // (UpgradeableUntilFrozen, Frozen) combination is what blocks
        // upgrades at the consensus layer. See section 5.4.1.
    },
    Custom {
        upgrade_validator: TypeId,  // type of validator object that authorises upgrades
        validator_id: ObjectId,
    },
    Forked {
        // for objects created by forking another object;
        // inherits original's mutability with restrictions, see section 5.5
        original: ObjectId,
        fork_height: u64,
    },
}
```

Each variant is detailed below.

#### `Immutable`

The object's code, rules, and validation logic are permanently fixed at creation. The object's `contents` field may still change according to the rules of the object's type, but the rules themselves never change.

This is the strongest mutability declaration. A user interacting with an `Immutable` object knows, with cryptographic certainty, that the rules of engagement cannot be altered after the fact.

Use cases: financial primitives (token contracts, escrow contracts, lending markets) where users commit substantial value and require certainty that the rules cannot be retroactively changed; digital monuments (commemorative records, public-record archives); standard libraries and well-known reference implementations.

#### `OwnerUpgradeable { owner }`

The object's code and rules may be changed by transactions authorised under the specified owner account. This is the most permissive standard mutability mode.

Use cases: rapidly-iterating early-stage applications; contracts whose authors retain full operational control; private internal tools; applications where the user is also the owner.

**Trust model.** Users interacting with `OwnerUpgradeable` objects must trust the owner not to make changes that disadvantage them. The protocol does not constrain the owner; it only ensures that the user is *aware* of the owner's authority. Wallets `MUST` display the owner's account when surfacing an `OwnerUpgradeable` object's mutability, so users can make informed decisions about whether to interact.

#### `VoteUpgradeable { token_type, approval_threshold, quorum_threshold, voting_period_secs, execution_delay_secs }`

The object's code and rules may be changed by a vote of token holders, where:

- `token_type`: the `TypeId` of the token whose holders are eligible to vote
- `approval_threshold`: minimum percentage of cast votes that `MUST` approve the change (in basis points; 5000 = 50.00%, 6700 = 67.00%)
- `quorum_threshold`: minimum percentage of total token supply that `MUST` participate for the vote to be valid
- `voting_period_secs`: duration of the voting window
- `execution_delay_secs`: delay between vote success and upgrade application, allowing token holders who object to exit before the change takes effect

This mode supports decentralised governance of contracts. A typical configuration for a community-governed application: 67% approval threshold, 30% quorum, 7-day voting period, 7-day execution delay.

**Important note on credible neutrality.** This mutability mode applies to *individual objects*, not to the protocol itself. The protocol's own consensus rules, virtual machine, and validity logic are `Immutable` by construction (Principle I, section 11). `VoteUpgradeable` is a tool that *applications* can use, not a backdoor through which the protocol itself can be governed.

#### `UpgradeableUntilFrozen { owner }`

A common pattern: the object is `OwnerUpgradeable` for a period (during which the owner iterates on the implementation), and at some later point, the owner calls a `freeze` operation that converts the object's mutability permanently to `Immutable`. After freeze, the object behaves identically to one declared `Immutable` at creation.

This mode is the recommended pattern for many production applications. The owner can fix bugs and deploy improvements during the early operational period; once the application has matured, the owner relinquishes that power and commits to the current implementation forever. Users who interact with the object before freeze trust the owner; users who interact after freeze trust no one.

**Cannot un-freeze.** The freeze operation is one-way. Once frozen, an object cannot be unfrozen, even by the original owner, even by a future fork, even by the protocol itself. This is enforced at the protocol layer, not by convention.

**Wallet display.** Wallets `MUST` distinguish between "frozen" and "still upgradeable" states for `UpgradeableUntilFrozen` objects, so users can see clearly which trust model they are operating under at the time of interaction.

#### `Custom { upgrade_validator, validator_id }`

The object's upgrade rules are specified by a separate validator object (itself a regular Adamant object, with its own type and rules). When an upgrade is proposed, the protocol invokes the validator's `validate_upgrade` method with the proposed change as input; the validator returns *valid* or *invalid*.

This is the protocol's escape hatch for upgrade logic that doesn't fit the standard patterns. Examples:

- **Multi-stage approval.** An upgrade requires approval from a board of trustees AND a community vote AND a 30-day waiting period.
- **Time-restricted upgradeability.** The object is upgradeable only during specified maintenance windows.
- **Conditional upgrades.** Upgrades are permitted only if the object's current state meets specified preconditions.
- **Cross-object dependencies.** Upgrades require the simultaneous upgrade of related objects.

The cost of `Custom` is complexity: users wishing to understand the trust model must inspect the validator object. Wallets `SHOULD` provide tooling that surfaces well-known validator patterns by name (e.g. "this object uses the standard 3-stage governance validator") rather than presenting raw validator code.

#### `Forked { original, fork_height }`

Reserved for objects produced by the chain-fork mechanism specified in section 11. A `Forked` object inherits its predecessor's rules but with restrictions designed to ensure that forks do not produce ambiguous claims of authority. End users do not encounter `Forked` mutability in normal operation.

### 5.1.5 Contents

A type-specific serialized payload. The schema is specified by the object's type (section 5.1.2). The protocol does not interpret `contents` directly; it is the virtual machine's responsibility (section 6) to deserialize, manipulate, and re-serialize this field according to the type definition.

`contents` size is bounded per object. The current bound is 1 MiB; objects requiring more state are expected to split themselves into multiple linked objects. This bound exists to ensure that any single object can be loaded into memory by a validator with reasonable hardware.

### 5.1.6 Version

A monotonically-increasing 64-bit counter, incremented on every state transition that mutates the object. The version field is essential to the consensus mechanism (section 8): two transactions both attempting to mutate the same object at the same version conflict, and only one can be ordered first; the second fails with a version conflict.

The version field is also the basis of the protocol's *causal ordering* property (anticipated in section 1, fully specified in section 8). Two transactions touching disjoint sets of object versions are causally independent and can be processed in any order, in parallel. Two transactions touching the same object version are causally dependent and require consensus to determine which executes first.

### 5.1.7 Metadata

Protocol-managed bookkeeping fields, not under the user's control:

- `created_at_height`: the consensus height (section 8) at which the object was created
- `last_modified_height`: the consensus height of the most recent state transition
- `creator`: the account that created the object
- `storage_rent_paid_through`: the consensus height through which storage rent has been paid (section 5.6)
- `proof_commitment`: cryptographic commitment to the object's history, used by the privacy layer (section 7) and recursive verification (section 8). The commitment is a KZG commitment on BLS12-381 (section 3.9.2), serialised as a compressed G₁ element (48 bytes).

Users do not write to metadata fields directly; they are updated by the protocol as a side-effect of valid state transitions.

### 5.1.8 Canonical serialisation

Every object, every component of an object, and every value that flows through consensus has a single canonical byte representation. Canonical serialisation is consensus-critical: every conforming Adamant implementation must produce byte-identical encodings of the same logical value, or hashes diverge and consensus breaks.

The protocol uses **BCS (Binary Canonical Serialization)** as its canonical encoding, the same format deployed by Sui, Aptos, and the broader Move ecosystem. BCS was designed specifically for blockchain consensus contexts: it produces a unique encoding for each value (no ambiguity in field ordering, no optional padding, no variable-length integer encodings without canonical resolution), it is compact, and it has a stable specification with mature implementations.

BCS encoding rules used by the protocol:

- Integers: little-endian fixed-width for `u8` through `u128`; ULEB128 for collection lengths.
- Booleans: single byte, `0x00` for false, `0x01` for true.
- Sequences (`Vec<T>`): ULEB128 length prefix followed by elements in order.
- Structs: fields serialised in source-declaration order with no separators.
- Enums: ULEB128 variant tag followed by the variant's payload.
- Fixed-size arrays: elements in order with no length prefix.

This is the standard BCS specification; the protocol does not deviate from it. Any value that hashes into consensus — `ObjectId` derivation (section 5.1.1), `TypeId` derivation (section 5.1.2), `Address` derivation (section 4.2), state commitments, transaction hashes — first canonically serialises to BCS bytes, then hashes those bytes with SHA3-256 under an appropriate domain tag (section 3.3.1).

Implementations `MUST` use a BCS-conformant encoder and `MUST NOT` introduce protocol-level fields that BCS cannot represent canonically (for instance: `HashMap` with non-deterministic iteration order, floating-point values, or self-referential structures).

## 5.2 State as a graph of objects

The chain's global state at any moment is the set of all live objects. State transitions are caused by transactions, which take a set of input objects, perform computation, and produce a set of output objects. An object's "history" is the sequence of versions it has passed through, each version produced by a specific transaction.

This is fundamentally different from the global-mutable-state model of account-based chains. Adamant has no global state vector that all validators must agree on at every instant; it has a graph of object histories that validators agree on independently per-object.

### 5.2.1 Causal ordering

Two transactions are *causally dependent* if and only if they read or write at least one common object version. Two transactions that touch disjoint object versions are *causally independent*.

The consensus mechanism (section 8) imposes total ordering only on causally dependent transactions. Causally independent transactions are not ordered relative to each other at the protocol layer; they can be processed in parallel by any validator, in any order, with deterministic results.

This is the core property that makes Adamant's throughput target (200,000+ TPS) achievable. In real-world workloads, the vast majority of transactions are causally independent: Alice paying Bob does not depend on Carol paying Dan. Consensus needs to order them only when they collide, which for typical workloads is a small fraction of total transactions.

The chain's history can therefore be visualised as a directed acyclic graph: nodes are object versions, edges are transactions that read or write objects, and the graph's "shape" reflects the actual causal structure of the chain's activity. Validators agree on the shape of this graph; they do not agree on a single sequential history because no such history exists for causally independent activities.

### 5.2.2 No global state root, but per-object commitments

Account-based chains compute a single global state root after every block — a Merkle (or Verkle) hash of the entire state. This is convenient for light-client verification but expensive to maintain at high throughput, because every transaction touches the global root.

Adamant takes a different approach. Each object maintains its own commitment in its `metadata.proof_commitment` field. The chain's "state root" at any point is the aggregated commitment over all live objects, computable from the per-object commitments without re-hashing the entire state.

This change has two consequences:

- **State updates are local.** A transaction touching N objects updates N commitments, not the entire global state. Throughput scales with object-level parallelism.
- **Recursive proofs are compositional.** Section 8's recursive verification works by aggregating per-object validity proofs, rather than proving validity of monolithic state transitions. This is what enables phone-verifiable verification.

The per-object commitment is computed using KZG vector commitments over BLS12-381 (specified in section 3.9.2). The aggregation across objects uses Halo 2 recursive proofs (section 3.9.1).

## 5.3 The mutability declaration is enforced by consensus

This subsection makes explicit a property that has been implied throughout: **mutability declarations are not enforced by convention or by smart-contract code; they are enforced by the protocol's consensus rules.**

Concretely, when a validator processes a transaction that proposes to upgrade an object's code or rules, the validator checks the target object's `mutability` field directly. If the field is `Immutable`, the upgrade transaction is invalid and rejected at the consensus layer, regardless of what the rest of the transaction says. The validator does not invoke any smart contract to determine whether the upgrade is permitted; the permission is a structural property of the object.

This is in deliberate contrast to Ethereum's proxy patterns, where upgradeability is implemented in user-level smart-contract code and where bugs or unexpected interactions in that code can produce upgradeability behaviours the user did not anticipate. Adamant's mutability is a first-class protocol concept, with the same status as ownership, with no possibility of user-level code violating its constraints.

**This is the property that makes mutability-as-declaration trustworthy.** A user inspecting an `Immutable` object knows that no path in any contract can render it mutable. A user inspecting an `UpgradeableUntilFrozen` object knows that the freeze operation will, in fact, transition the object to permanent immutability at the protocol layer. The mutability declaration is a constitutional fact, not a programming convention.

## 5.4 Object lifecycle

An object passes through a defined lifecycle:

1. **Creation.** A transaction explicitly creates the object, specifying its type, owner, mutability, initial contents, and any other type-specific parameters. The object is assigned an `ObjectId`, set to version 1, and added to the chain state.

2. **Active.** The object exists and is subject to mutation per its rules. State transitions produced by valid transactions update its `contents`, `owner`, or other fields, increment its version, and update its commitments and metadata.

3. **Frozen** (only for `UpgradeableUntilFrozen`). The owner has called the `freeze` operation. The object's `Mutability` field remains `UpgradeableUntilFrozen`; the object's `Lifecycle` field changes to `Frozen`. The combination — `UpgradeableUntilFrozen` + `Frozen` — is what blocks further upgrades at the consensus layer; the `Mutability` field itself is never mutated post-creation. State transitions per the existing rules continue to be valid: contents may be updated through the type's existing logic, the object may be archived if rent is not maintained (lifecycle step 4), and the object may be destroyed through the type's existing destroy-logic (lifecycle step 5). What freeze prohibits is rule upgrades, not contents-evolution or termination through pre-existing rules.

4. **Archived.** If the object's storage rent (section 5.6) is not maintained, the object enters an archived state. Archival applies regardless of the object's `Mutability` field and regardless of whether the object is `Active` or `Frozen` at the time of rent depletion: rent is mutability-independent and freeze-independent. Archived objects' contents are pruned from validator working storage; only their commitment hash is retained. Archived objects cannot be referenced by new transactions until restored. Restoration requires paying the accumulated rent and submitting a proof (provided by archival nodes) of the object's most recent active contents.

5. **Destroyed.** Some objects are explicitly destroyed by their type's logic — for example, a redeemed coupon, a fulfilled escrow, a settled bet. Destruction is a state transition that removes the object from the active state set. Destroyed objects are pruned from working storage but their existence is permanently recorded in the chain's history; their `ObjectId` cannot be reused. Destroyed is terminal: no further lifecycle transitions occur from this state, and any subsequent reference to the `ObjectId` is invalid at the consensus layer.

The lifecycle is enforced by the protocol; type-specific logic determines which transitions occur, but cannot violate the lifecycle's structural properties.

### 5.4.1 The transition graph

The legal transitions between non-`Creation` lifecycle states are:

| From → To       | Active                           | Frozen                          | Archived                         | Destroyed                        |
|-----------------|----------------------------------|---------------------------------|----------------------------------|----------------------------------|
| **Active**      | Self (in-rules contents update)  | `freeze` op; only `UpgradeableUntilFrozen` | Rent depletion        | Type-logic destruction           |
| **Frozen**      | **Forbidden** (freeze is one-way per §5.1.4) | Self (in-rules contents update; freeze is one-way) | Rent depletion        | Type-logic destruction           |
| **Archived**    | Restoration (preserves pre-archival lifecycle — see below) | n/a (cannot be referenced while archived) | Self                  | **Forbidden** (must restore first) |
| **Destroyed**   | n/a (terminal)                   | n/a (terminal)                  | n/a (terminal)                   | Self                             |

Several properties of this graph deserve explicit statement:

- **`Active → Frozen` occurs exclusively through the freeze operation.** No other path produces lifecycle-`Frozen` state. The freeze operation is invoked only on objects with `Mutability::UpgradeableUntilFrozen`; objects with any other mutability cannot reach `Lifecycle::Frozen` through valid protocol operations.

- **`Frozen → Active` is forbidden.** Per section 5.1.4, freeze is one-way "even by a future fork, even by the protocol itself." No protocol operation un-freezes an object.

- **`Frozen → Destroyed` is permitted via the type's pre-existing destroy-logic.** The freeze operation locks rule changes, not the object's existence. A frozen escrow that becomes ready to settle, for example, is destroyed through the same logic that would destroy an active escrow; freeze does not strand the object.

- **Restoration preserves the pre-archival lifecycle.** When an object is archived from `Active`, restoration returns it to `Active`. When an object is archived from `Frozen`, restoration returns it to `Frozen`. This is required by section 5.1.4's freeze-is-one-way invariant: any restoration semantics that landed Frozen objects in `Active` would constitute a backdoor un-freeze through the archival round-trip, contradicting the freeze guarantee.

- **`Archived → Destroyed` is forbidden.** Type-logic operates on an object's contents; archived objects have no contents in working storage; therefore type-logic-driven destruction cannot execute on an archived object. To destroy an archived object, an actor must first restore it (paying accumulated rent and providing the contents proof per section 5.6.2), at which point the object becomes destructible through normal type-logic. This preserves the property that destruction is always an explicit, content-driven decision rather than a side effect of rent depletion.

- **Restoration is not a version-incrementing transition.** A restored object resumes at the version it held at archival time. Causal ordering (section 5.2.1) requires version continuity across the archival round-trip; treating restoration as a version increment would invalidate every reference held by other objects to the pre-archival object.

- **Destroyed is terminal.** No transition out of `Destroyed` exists. Any transaction referencing a destroyed `ObjectId` is invalid at the consensus layer.

## 5.5 Object derivation: forks, copies, and references

Object identity is unique. Two objects with the same `ObjectId` are the same object. The protocol does not support arbitrary cloning of objects; what it supports are several specific derivation operations:

- **Reference.** Many objects can hold references to a single shared object. A reference is a 32-byte `ObjectId` field that the holding object's logic can use to dispatch operations to the referenced object. References are cheap and create no new state.

- **Copy of contents.** A new object is created whose `contents` are derived from another object's `contents` (typically by transforming or summarising it). The new object has a fresh `ObjectId` and an independent existence; modifications to either object do not affect the other. Copying is a normal `create` operation; the protocol does not distinguish copies from any other newly-created object.

- **Fork.** A reserved operation specified in section 11. Forking applies in the context of a chain fork — a divergence where part of the validator set has migrated to a new client implementation with different consensus rules. Forked objects inherit their predecessor's content and rules but carry the `Forked` mutability variant, signalling that they exist on a forked timeline. End users do not encounter forked objects in normal operation.

- **Snapshot.** A reserved operation that creates a content-addressed read-only handle to an object's state at a specific version. Snapshots support certain advanced patterns (proof-of-historical-state, audit trails) without violating the unique-identity property, because snapshots are themselves identified by `(ObjectId, version)` pairs rather than fresh `ObjectId`s.

## 5.6 Storage and rent

The chain's state grows monotonically as objects are created. Without a counterbalance, validators would eventually be unable to store the full state on commodity hardware, centralising the network. The protocol prevents this through a state-rent mechanism.

### 5.6.1 The rent model

Every object is associated with a *storage rent rate*: a per-byte-per-second cost charged to the object's "rent account." The rent account is funded by the object's owner (or by anyone, for shared objects) through normal token transfers. When the rent account is depleted, the object enters the *archived* lifecycle state.

**Rent rates.** The rent rate is a chain-wide parameter set at genesis and not modifiable post-genesis. The exact value is specified in section 10 (Economics & Incentives); for context, the design target is that one year's storage of one kilobyte of object content costs approximately the same as one normal transaction's fee.

**Pre-payment.** Object creation includes pre-payment of rent for some initial period (default: one year). Owners may top up the rent account at any time.

### 5.6.2 Archival is not deletion

When an object is archived, its `contents` are pruned from validator working storage, but its `ObjectId` and commitment remain in chain state. The object is *unreferenceable* in new transactions but not *forgotten*. Specifically:

- The object's `proof_commitment` remains in the chain's recursive proof.
- The object's `ObjectId` cannot be reassigned to a new object.
- The object's contents are retained by *archival nodes* — voluntary participants who store full historical state for cryptographic or social reasons. Archival nodes are not part of consensus and are not required by the protocol; they are a community resource.
- The object can be *restored* by paying accumulated rent plus a restoration fee, and submitting a proof (provided by an archival node) that the object's pre-archival contents are unchanged. Restoration returns the object to its pre-archival lifecycle state — `Active` if it was `Active` at archival time, `Frozen` if it was `Frozen` at archival time. The restored object resumes at its pre-archival `version`; restoration is not a version-incrementing transition. (See section 5.4.1 for the lifecycle-transition graph these properties are part of.)

This model ensures that state size is bounded by *active* state, not total state ever created. Inactive state is preserved for historical and forensic purposes but does not impose ongoing cost on consensus participants.

### 5.6.3 Rent-exempt objects

Some objects, by their nature, cannot be archived without violating the chain's invariants. Examples:

- **Type definitions.** If a type definition were archived, every object of that type would become uninterpretable. Type definitions pay one-time rent at creation that grants permanent active status.
- **Active validator records.** A validator's record is essential to consensus; it cannot be archived while the validator is participating.
- **Recently-created objects.** Objects in their first 30 days are rent-exempt to prevent denial-of-service attacks where an adversary creates objects faster than rent payments can be collected.

The exempt categories are specified in section 11 (Genesis & Constitution) and cannot be expanded after genesis.

## 5.7 Privacy and the object model

This section has described objects as if they were universally visible. They are not. Section 7 (Privacy Layer) specifies how the object model interacts with the protocol's privacy properties, but the high-level relationship is:

- **Object existence is public.** The set of `ObjectId`s in active state is observable by all participants. The total state size is observable. The number of objects created and destroyed per consensus epoch is observable.

- **Object contents may be shielded.** An object's `contents` may be encrypted such that only specified parties (the owner, holders of view keys, parties to a multi-party object) can decrypt them. Shielded `contents` are accompanied by zero-knowledge proofs that state transitions involving the object are valid, computable without decrypting the contents.

- **Ownership may be hidden.** An object's `owner` field may itself be shielded, such that the chain records only that the object is owned by *some* account, without recording which account. Stealth-address mechanisms (section 7) support this.

- **Mutability declarations are public.** The `mutability` field is always in clear text. This is required by Principle V's user-visibility requirement: users `MUST` be able to query an object's mutability before interacting, even if they cannot read its contents.

The privacy model is therefore selective: structural properties of objects (existence, type, mutability, version-counter advancement) are public; semantic properties (contents, ownership in detail, the meaning of state transitions) may be shielded. Section 7 specifies the cryptographic constructions in detail.

## 5.8 Worked example: a token

To make the foregoing concrete, here is the structure of a typical fungible-token object on Adamant:

**Type definition** (a `Type` object, registered once):

- `name`: "ExampleToken"
- `symbol`: "EXM"
- `decimals`: 6
- `total_supply_logic`: defines how supply changes (mint/burn rules)
- `transfer_logic`: defines how token balances move between accounts
- `default_mutability`: `Immutable` (recommended for production tokens)

**Token-supply object** (a single `Shared` object representing the global token supply):

- `id`: derived from creation
- `type_id`: the ExampleToken type
- `owner`: `Shared`
- `mutability`: `Immutable`
- `contents`: encodes total supply, supply schedule, mint/burn authority
- `version`: increments on every supply change

**User-balance objects** (one per holder, `Address`-owned):

- `id`: derived per-balance
- `type_id`: the ExampleToken-balance type
- `owner`: `Address(holder_account)`
- `mutability`: `Immutable`
- `contents`: encrypted; encodes the holder's balance
- `version`: increments on every transfer

A transfer transaction reads the sender's balance object, the recipient's balance object, and (potentially) the supply object; produces updated versions of the sender's and recipient's balance objects; and emits a zero-knowledge proof that the transfer is valid (sender's balance decreases by amount X, recipient's balance increases by amount X, no funds created or destroyed). The supply object is not modified, only read.

This pattern — global supply object plus per-holder balance objects — is the canonical fungible-token implementation on Adamant. It supports parallel processing (transfers between disjoint pairs of accounts do not conflict), it supports privacy (balances are shielded; transfers use stealth addresses; observers see only that *some* account transferred to *some other* account), and it is verifiable by recursive proofs (the chain's recursive proof attests that all balance changes are well-formed across all token types).

Section 6 (the virtual machine) specifies how this pattern is expressed in the protocol's smart-contract language. Section 7 specifies the privacy mechanisms that shield the contents.
# 6. Execution & Virtual Machine

This section specifies how transactions are executed on Adamant: the smart-contract language, the virtual machine, the parallel execution model, and the resource accounting (gas) framework. It builds directly on the object model of section 5 and is the layer at which user-defined logic interacts with chain state.

The protocol's execution model is governed by three requirements:

1. **Resource safety.** The language must make value-related bugs (double-spend, accidental destruction, reentrancy) structurally impossible, not merely conventionally avoidable. This is non-negotiable for a chain whose users hold significant value in shielded form, where the auditability of contracts is reduced and the cost of a single class of bugs can be catastrophic.

2. **Parallel execution.** The VM must support deterministic parallel execution at scale, exploiting the causal-independence property of the object model (section 5.2.1). Sequential execution as in Ethereum's EVM is incompatible with the throughput targets in Principle IV.

3. **Privacy compatibility.** The language must integrate cleanly with the privacy layer (section 7). Shielded execution — running a contract while keeping its inputs, intermediate state, and outputs encrypted — must be a first-class concept, not an afterthought.

## 6.0 Transactions: the input to execution

This subsection specifies the canonical `Transaction` data type — the input the rest of section 6 operates on. Every other subsection (the language, the runtime, gas, deployment) consumes Transactions; pinning the type's fields, encoding, and derived `TxHash` here is therefore prerequisite to specifying any of them precisely.

A `Transaction` is the protocol's unit of state-change request. It is created off-chain (typically by a wallet), signed off-chain by the authorising account, submitted to the network, and either executed (advancing chain state) or rejected (with no effect on chain state). Transactions are the only mechanism by which users cause state to change.

### 6.0.1 The body / evidence split

A `Transaction` has two parts:

```
Transaction {
    body: TxBody,
    auth: AuthEvidence,
}
```

The **body** carries the operation payload — what the transaction is asking to do. The **authorisation evidence** carries the signatures, witnesses, and other non-body data that authorise the body's execution. The split exists to solve the signature-signs-itself problem: signatures cover `BCS(body)` and live in `auth`, so the body's canonical encoding does not depend on the signatures it produces.

The `TxHash` (section 6.0.4) is computed over the body alone, not the full Transaction. This means two Transactions with identical bodies but different auth evidence produce the same `TxHash`. That property is intentional: it ensures the `TxHash` identifies the *operation* a user committed to, not the particular signature instance carrying that commitment. Replay protection is the body's responsibility (via nonces or version-pinned read sets), not the hash's.

### 6.0.2 The body

```
TxBody {
    authorising_account: AccountRef,
    fee_payer: Option<AccountRef>,
    read_set: Vec<(ObjectId, Version)>,
    write_set: Vec<ObjectId>,
    created_objects: Vec<CreatedObject>,
    gas_budget: GasBudget,
    call: CallParams,
    nonce: u64,
}
```

**`authorising_account`.** The account whose validation logic (per section 4.3) is invoked at execution-pipeline step 1. For transparent transactions, `AccountRef::Cleartext(Address)` names the account directly. For shielded transactions, `AccountRef::Shielded(StealthCommitment)` names it via a stealth-address commitment (section 4.7), preserving privacy of the authorising account while still enabling validation-logic dispatch.

**`fee_payer`.** Optional. When `None`, the fee payer is the `authorising_account`. When `Some(account)`, the fee payer is a different account whose own authorisation must also appear in `AuthEvidence` (per the sponsored-transaction model in section 6.3.4). The same shielded/cleartext options apply.

**`read_set`.** The objects this transaction reads, declared as `(ObjectId, Version)` pairs. The version pin protects against read-write conflicts: if any read object's version has advanced beyond the declared version at execution time, the transaction is rejected without execution. Wildcards are forbidden — the read set must be a statically declared list, both for the parallel scheduler (section 6.2.3) and for the privacy layer (section 7) which requires the read set to be circuit-encoded for shielded transactions.

**`write_set`.** The pre-existing objects this transaction modifies, declared as `ObjectId`s. Modification requires the object to be in the read set as well (read-then-write); the write set is therefore a subset of the read set's `ObjectId`s. Objects whose contents are read but not modified appear only in the read set.

**`created_objects`.** Objects to be created within this transaction, declared explicitly so their ObjectIds are derivable per section 5.1.1. Each `CreatedObject` carries:

```
CreatedObject {
    creator: Address,
    creation_index: u64,
    type_id: TypeId,
    initial_owner: Ownership,
    initial_mutability: Mutability,
}
```

The `(creator, creation_index)` pair, combined with this transaction's `TxHash` (computed over the body, which contains this declaration), produces the new `ObjectId` per the section 5.1.1 formula. This is well-defined despite the apparent circularity: the `TxHash` is computed over the body bytes, and the body's bytes are fixed before hashing — the body declares its created objects by `(creator, creation_index)` only, and the `ObjectId` is derived from the resulting `TxHash` afterward. No object's `ObjectId` appears in the body's declaration of itself.

**`gas_budget`.** A six-dimension cap matching section 6.3.1's gas dimensions:

```
GasBudget {
    computation: u64,
    storage: u64,
    rent: u64,
    bandwidth: u64,
    proof_verification: u64,
    proof_generation: u64,
}
```

The transaction aborts on the first dimension exhausted; the user cannot trade unused budget in one dimension for additional consumption in another. This preserves section 6.3.1's motivation for multi-dimensional pricing: dimensions correspond to distinct validator resources, and a single combined cap would obscure which resource a transaction actually stresses.

**`call`.** The operation payload — which function to invoke, on which target, with which arguments:

```
CallParams {
    target_module: ModuleRef,
    target_function: FunctionId,
    type_arguments: Vec<TypeId>,
    arguments: Vec<Value>,
}
```

Module deployment is not a special transaction variant. To deploy a new module, a transaction calls the standard-library function `adamant::module::deploy` (section 6.5) with the module's bytecode as an argument. This keeps `TxBody` shape uniform — every transaction is a function call — and matches the standard-library pattern where protocol-level operations are exposed as system-function calls rather than as kernel discriminators.

**`nonce`.** A monotonic counter scoped to the `authorising_account`, ensuring distinct transactions from the same account have distinct bodies (and therefore distinct `TxHash`es) even when their other fields match. The nonce also defends against replay across forks of the chain. The protocol-enforced rule is that a transaction's `nonce` must equal one greater than the highest nonce previously executed for `authorising_account`; gaps are not permitted.

### 6.0.3 The auth evidence

```
AuthEvidence {
    signatures: Vec<Signature>,
    witnesses: Vec<Witness>,
}
```

The evidence is a flat list of signatures and witnesses. The structure is deliberately simple: validation logic in the authorising account interprets them according to the account's declared scheme (single-sig, dual-sig, threshold-sig, etc., per section 4.3). The protocol does not impose a fixed signature scheme on transactions — the account's validation logic does.

For sponsored transactions (section 6.3.4) where `fee_payer` is set, the fee payer's authorisation must also appear in `signatures`. The fee payer's account validation logic runs alongside the authorising account's during the execution pipeline.

For shielded transactions, the authorising account's signature is replaced (or accompanied) by zero-knowledge witnesses proving authority without revealing the account. Section 7 specifies the construction.

The auth evidence is excluded from the `TxHash`. Modifying signatures or witnesses does not change the `TxHash`; only modifying the body does. This property simplifies the signature-signs-itself problem and matches standard practice across the field.

### 6.0.4 TxHash derivation

The transaction hash is computed over the canonical BCS encoding of the body alone:

```
TxHash = sha3_256_tagged(TX_HASH, BCS(body))
```

where `TX_HASH` is the registered domain tag `b"ADAMANT-v1-tx-hash"` per section 3.3.1, and `BCS(body)` is the canonical encoding per section 5.1.8. The `TxHash` is the protocol-level identifier of a transaction's *operation*; two transactions with byte-identical bodies have the same `TxHash` regardless of how they were authorised.

This `TxHash` value is what flows into `ObjectId` derivation per section 5.1.1, into chain-history records, into the read/write conflict detector, and into recursive proof aggregation per section 8.

### 6.0.5 Privacy mode is implicit

A transaction's privacy mode (transparent or shielded) is determined by the annotation on its target function (`#[transparent]` or `#[shielded]` per section 6.1.2), not by an explicit field on the `Transaction` itself. A transaction whose `call.target_function` is a `#[shielded]` function is a shielded transaction; one targeting a `#[transparent]` function is a transparent transaction. The bytecode validator (section 6.2.2 step 3) rejects transactions whose target function's annotation conflicts with the validator's static analysis of read/write set contents — for example, a transparent function attempting to read a shielded object.

A single transaction targets a single function; a transaction cannot mix transparent and shielded annotations within itself. Composite operations that span multiple functions are achieved by decomposition into multiple transactions, not by mixed-annotation calls.

### 6.0.6 Canonical encoding and consensus

Like every consensus-critical type, the `Transaction` and its sub-types are BCS-encoded canonically per section 5.1.8. Field ordering in this subsection's struct definitions is the canonical encoding order; reordering fields is a hard fork. Adding fields is also a hard fork — the transaction format is genesis-fixed in the same sense as the gas table (section 6.3.2) and the bytecode format (section 6.2.1). Validators reject transactions whose BCS encoding contains unknown fields or non-canonical ordering.

### 6.0.7 Inner-type canonical encodings

Several types referenced in sections 6.0.1 / 6.0.2 / 6.0.3 are themselves consensus-critical in their canonical encoding (because they appear inside `BCS(body)` bytes that flow into the `TxHash`) but their *semantic* or *cryptographic* construction is specified elsewhere or in later sections. This subsection pins the canonical encoding of each — what bytes each type produces under BCS — without specifying the construction of the underlying value. The two concerns are separable: the encoding boundary is what consensus validators depend on, while the construction of the underlying value is the concern of the section that defines the cryptographic or semantic role.

**`Version`.** Type alias for `u64`, matching the `version` field on `Object` per section 5.1.6. Encoded as a little-endian 8-byte integer.

**`Signature`.** A discriminated union over the protocol's signature schemes (sections 3.4.1 / 3.4.2):

```
Signature {
    Ed25519([u8; 64]),       // BCS variant tag 0x00
    MlDsa65([u8; 3309]),     // BCS variant tag 0x01
    MlDsa87([u8; 4627]),     // BCS variant tag 0x02
}
```

The variant set is fixed at genesis. Adding a new signature scheme is a hard fork. The fixed sizes match the signature outputs of the schemes specified in section 3.4. Validators decode signatures by reading the variant tag, then the appropriate fixed-size byte array.

**`StealthCommitment`.** A 32-byte fixed-size value used in `AccountRef::Shielded(StealthCommitment)` per section 6.0.2. The cryptographic construction — what the bytes mean as a stealth-address commitment — is specified in section 7 (privacy layer). Section 6.0.7 pins only the encoding: `[u8; 32]`. Validators that hash a `TxBody` containing `AccountRef::Shielded(_)` produce a `TxHash` over those 32 bytes; the interpretation of the bytes (as a curve point, as a Pedersen commitment, etc.) is section 7's concern but does not affect the encoding.

**`Witness`.** A length-prefixed byte vector used in `AuthEvidence.witnesses` per section 6.0.3. Encoded as `Vec<u8>` (ULEB128 length prefix followed by raw bytes). The contents — a zero-knowledge proof, a signature witness, an authentication tag, etc. — are specified in section 7. Section 6.0.7 pins only that the encoding is a BCS-canonical byte vector; the contents are opaque to the encoding layer.

Implementation note: because `Witness` is part of `AuthEvidence` (excluded from the `TxHash` per section 6.0.4), changing the contents-level interpretation of `Witness` bytes in a future revision does not alter `TxHash` values for transactions whose witnesses are byte-identical. This decoupling is a deliberate consequence of the body/evidence split.

**`ModuleRef`.** A newtype wrapping `ObjectId`:

```
ModuleRef(ObjectId)
```

per section 6.4.1's framing of modules as first-class objects. Encoded as the wrapped `ObjectId` (32 bytes, no additional discriminator).

**`FunctionId`.** A UTF-8 string, length-bounded to 255 bytes:

```
FunctionId(String)
```

with the constraint that the byte length of the string's UTF-8 encoding is at most 255. Functions are identified by name within their containing module, not by integer index. This decouples transaction encoding from the module's internal function table layout — a module upgrade that re-orders its functions does not invalidate pending transactions referencing those functions, because the transaction names them. The 255-byte bound is a structural constraint enforced at decode time; transactions exceeding the bound are rejected. Encoded as `Vec<u8>` containing the UTF-8 bytes (ULEB128 length prefix followed by bytes).

**`Value`.** A discriminated union covering Adamant Move's value taxonomy:

```
Value {
    U8(u8),                      // BCS variant tag 0x00
    U16(u16),                    // BCS variant tag 0x01
    U32(u32),                    // BCS variant tag 0x02
    U64(u64),                    // BCS variant tag 0x03
    U128(u128),                  // BCS variant tag 0x04
    U256([u8; 32]),              // BCS variant tag 0x05, big-endian
    Bool(bool),                  // BCS variant tag 0x06
    Address(Address),            // BCS variant tag 0x07
    Vector(Vec<Value>),          // BCS variant tag 0x08
    Struct(StructValue),         // BCS variant tag 0x09
}

StructValue {
    type_id: TypeId,
    fields: Vec<Value>,
}
```

The `Value` enum's variant set covers Adamant Move's primitive types, addresses, the polymorphic `vector<T>` constructor (encoded recursively as `Vector(Vec<Value>)`), and user-defined structs. The variant tags are fixed at genesis. Adding a new primitive type is a hard fork.

For `Struct(StructValue)`, the `type_id` identifies the struct type per section 5.1.2, and `fields` carries the struct's field values in the canonical order specified by the type's definition. The mapping from `fields` ordering to the struct's named fields is a property of the type definition (section 6.2.1), not the `Value` encoding. Two struct values with the same `type_id` and byte-identical `fields` BCS encoding are equal by definition; their semantic interpretation (which field is which) requires the type definition.

**Summary.** This subsection's encodings are genesis-fixed and consensus-critical. The cryptographic construction of `StealthCommitment` (section 7), the contents of `Witness` (section 7), the structural layout of any specific user-defined struct value (section 6.2.1), and the semantic interpretation of any field at the application layer are all out of scope here. The encoding pinned here is what `BCS(body)` and `BCS(witnesses)` produce when validators flow these types through canonical serialisation.

## 6.1 The Adamant Move language

The protocol's smart-contract language is **Adamant Move**, a derivative of the Move language originally developed by Facebook (Diem project, 2018–2022) and now maintained as an open standard by the Move community, with significant production deployment in Sui and Aptos.

### 6.1.1 Why Move

Move was designed from first principles around the problem of representing digital assets safely. Its core innovation is a *linear type system* in which values denoting assets cannot be copied, accidentally discarded, or implicitly destroyed. Operations on assets must explicitly account for their movement: a function that takes a `Coin` as input must explicitly transfer it, store it, or destroy it; the compiler refuses to compile code that does anything else.

This property is enforced at the type level, not by runtime checks. A contract that incorrectly handles assets does not compile; it cannot be deployed; it cannot run. This makes whole classes of bugs that have plagued Solidity contracts (double-spends due to integer underflow, lost funds due to forgotten transfers, reentrancy attacks due to ordering bugs) structurally impossible in Move.

The protocol adopts Move because:

1. **Linear types are the right primitive for value-bearing systems.** Every other language requires programmer discipline; Move enforces correctness at the compiler.

2. **Move's object model aligns with Adamant's object model.** Move's "resources" map cleanly to Adamant's `Address`-owned objects; Move's "shared objects" (in Sui's variant) map cleanly to Adamant's `Shared` objects. The languages are designed for the same world.

3. **Production track record.** Sui mainnet (May 2023) and Aptos mainnet (October 2022) have processed over $30B in cumulative volume across hundreds of millions of transactions on Move. The language is not experimental.

4. **Existing tooling.** Compilers, formal verifiers (the Move Prover), debuggers, and IDE support exist. Adamant inherits this ecosystem rather than rebuilding it.

5. **Active research community.** Mysten Labs, Aptos Labs, and academic researchers continue to publish on Move's foundations. Adamant participates in this community rather than diverging from it.

### 6.1.2 What "Adamant Move" extends

Adamant Move is Move with three protocol-specific extensions. Where standard Move and Adamant Move agree, programs written in standard Move work without modification on Adamant; where they differ, the differences are documented here.

**Extension 1: Mutability declarations as first-class syntax.**

Standard Move does not have native syntax for object mutability declarations as defined in section 5.3. Adamant Move adds the following construct to module declarations:

```move
module 0xCOFFEE::example_token {
    use adamant::object;
    use adamant::mutability;

    // The mutability declaration is part of the type definition,
    // visible to readers, enforced by the protocol.
    #[mutability(immutable)]
    public struct ExampleToken has key {
        id: object::ObjectId,
        balance: u64,
    }

    // ...
}
```

Available declarations: `#[mutability(immutable)]`, `#[mutability(owner_upgradeable(addr))]`, `#[mutability(vote_upgradeable(token_type, thresholds))]`, `#[mutability(upgradeable_until_frozen(addr))]`, `#[mutability(custom(validator_id))]`. The compiler refuses to compile a module that lacks an explicit mutability annotation; defaults are not provided, because defaulting to anything other than the strictest option silently weakens the user's expectations.

**Extension 2: Shielded and transparent execution annotations.**

Functions in Adamant Move are annotated with their privacy requirement:

```move
// Operates entirely on shielded inputs and shielded state.
// Produces a zk-SNARK proof of correct execution without
// revealing inputs or state to validators.
#[shielded]
public fun private_transfer(
    sender: &mut Coin,
    recipient: address,
    amount: u64,
) { /* ... */ }

// Operates on transparent (cleartext) inputs and state.
// Validators see all inputs and outputs.
#[transparent]
public fun public_donation(
    coin: Coin,
    pool: &mut DonationPool,
) { /* ... */ }

// Default: contract author has not specified.
// Compiler error - explicit choice required.
public fun unspecified() { /* ... */ }
```

The compiler refuses to compile functions without an explicit privacy annotation. This forces contract authors to make a deliberate choice about each function's privacy properties, rather than producing transparent contracts by default.

The protocol enforces these annotations at execution time. A `#[shielded]` function invoked in a transparent transaction is an error; a `#[transparent]` function invoked under a shielded execution context is an error. Section 7 specifies the cryptographic mechanisms by which shielded execution operates.

**Extension 3: Privacy primitives.**

Adamant Move provides built-in primitives for the privacy operations specified in section 7. Contract authors do not implement these from scratch; they call protocol-provided functions:

- `adamant::privacy::shielded_balance` — type representing an encrypted balance
- `adamant::privacy::stealth_address` — derive a one-time recipient address
- `adamant::privacy::view_key_release` — produce a sub-view-key for selective disclosure
- `adamant::privacy::range_proof` — prove a value lies in a range without revealing it
- `adamant::privacy::membership_proof` — prove an element belongs to a set without revealing which

These primitives compile to circuit operations in the protocol's Halo 2 circuit library (section 7), invisibly to the contract author. The contract author thinks of them as ordinary function calls; the compiler emits the corresponding circuit witnesses.

### 6.1.3 What Adamant Move does not change

Adamant Move preserves Move's core semantics unchanged. Specifically:

- The linear type system, including the `key` and `store` ability constraints
- Module structure, function visibility, and abilities
- Generic types and phantom type parameters
- Bytecode format. Adamant Move bytecode is a strict superset of Sui-Move bytecode, with the additional protocol-specific instructions and metadata documented in subsection 6.2.1. The Sui-Move dialect is the substrate; the protocol-specific extensions are additive.
- The Move Prover specification language for formal verification
- Standard library types (vectors, options, strings, etc.)

A developer fluent in Move learns Adamant Move in days. The differences are additive, not breaking.

### 6.1.4 What Adamant Move excludes

Adamant Move excludes the following constructs that exist in some Move dialects:

- **Dynamic dispatch via runtime type discovery.** Move's type system is statically resolved; dynamic dispatch in some dialects is implemented through trait-like patterns. Adamant Move declines these patterns to preserve verifiability properties.

- **Native functions (NFTs in the language sense, not in the asset sense).** Standard Move permits "native functions" implemented by the runtime in C++ for performance. Adamant Move does not: every function is implemented in Move bytecode and verifiable. Performance-critical primitives are provided through the Halo 2 circuit interface (section 7) rather than through bytecode-bypass mechanisms.

- **Direct global storage access.** Some Move dialects permit modules to read and write global storage by address. Adamant Move requires all storage access to be mediated through object references, consistent with section 5's object model.

These exclusions tighten the language's verifiability and parallelism properties at modest cost to expressiveness.

## 6.2 The Adamant Virtual Machine (AVM)

The Adamant Virtual Machine (AVM) is the runtime that executes Adamant Move bytecode. It is implemented in Rust (Principle VI: standard tooling) and operates as one component of the validator node.

### 6.2.1 Bytecode format

The AVM executes **Adamant Move bytecode**, a strict superset of Sui-Move bytecode with protocol-specific extensions for privacy operations, recursive proof primitives, and Adamant's gas-accounting model. This subsection specifies the bytecode at the level of detail required for an independent implementation: the dialect choice and its rationale, the module file format, the privacy and mutability annotations at bytecode level, the instruction set, operand encoding, the validation rules, and the per-instruction gas costs.

#### 6.2.1.1 Dialect choice: Sui-Move

Three Move dialects exist in production with meaningful differences:

- **Diem-Move** (the original, maintained at github.com/move-language/move). Has no native object model; objects are represented through global storage primitives (`move_to`, `move_from`, `borrow_global`).
- **Sui-Move** (Mysten Labs' fork, maintained at github.com/MystenLabs/sui). Replaces Diem's global storage with a first-class object model where objects have unique IDs, ownership types (`Address`-owned, `Shared`, `Immutable`), and are passed by reference between transactions.
- **Aptos-Move** (Aptos Labs' fork, maintained at github.com/aptos-labs/aptos-core). Retains Diem's global storage model and adds resource accounts and table abstractions.

The protocol selects **Sui-Move as the bytecode substrate**. The reasoning is structural: section 5's object model is itself Sui-derived, and Sui-Move bytecode integrates with that object model at the bytecode level — instructions for object packing, transfer, and freezing operate directly on object references rather than through global storage. Building Adamant on Diem-Move would require us to extend Diem-Move with object-model integration that already exists in Sui-Move; building on Aptos-Move would inherit Aptos's global storage model that conflicts with section 5's "all state is an object" position.

The dialect choice is genesis-fixed. Migrating to a different Move dialect post-genesis would be a hard fork affecting every deployed module.

**What "strict superset" means.** Every valid Sui-Move module that respects Adamant's tightened verifier rules (section 6.2.1.6) is a valid Adamant Move module: same instruction set, same module file format, same type system, same verifier rules. Adamant adds:

- New instruction opcodes for privacy operations, recursive proof primitives, and protocol-specific cryptographic operations (specified in section 6.2.1.4).
- Module-level metadata fields encoding mutability declarations per section 5.1.4 and section 6.1.2 (specified in section 6.2.1.3).
- Function-level metadata fields encoding privacy annotations per section 6.1.2 (specified in section 6.2.1.3).
- Tightened verifier rules excluding the constructs listed in section 6.1.4 (specified in section 6.2.1.6).

A program that uses none of Adamant's extensions, carries the required metadata, and respects Adamant's tighter verifier rules is bytecode-identical to its Sui-Move equivalent.

**Implementation note.** This subsection treats Sui-Move's `move-binary-format` and `move-bytecode-verifier` crates as a test-time cross-validation reference for the inherited substrate's semantics. A conforming Adamant implementation may vendor those crates and exercise them at test time to confirm that Adamant's own deserializer and verifier reach the same accept/reject decision as Sui's on pure-Sui modules. The protocol's behaviour on the inherited subset is defined by sections 6.2.1.1 through 6.2.1.8 of this specification; Sui's reference implementation is consulted at test time to confirm semantic parity, not as the binding source of truth. The vendored crates do not appear in the production binary's dependency graph — section 6.2.1.8 specifies the Adamant-native deserializer and verifier that own the deploy-time pipeline and runtime, with the vendored Sui crates serving as test-only cross-validation reference.

The strict-superset property is at the *language* level: every valid Sui-Move module that respects Adamant's tightened verifier rules is a valid Adamant Move module, and an Adamant module that uses no extensions is bytecode-identical to its Sui-Move equivalent. The vendored Sui crates, by contrast, recognise only the Sui-base subset — Sui's `move-binary-format` deserializer rejects any opcode byte outside Sui's instruction set with `UNKNOWN_OPCODE`, and Sui's `move-bytecode-verifier` operates on Sui's `Bytecode` enum which has no representation for Adamant extensions. The Adamant-native deserializer and verifier specified in section 6.2.1.8 handle the full Adamant superset directly; cross-validation against the vendored Sui crates on pure-Sui modules confirms semantic parity for the inherited subset.

#### 6.2.1.2 Module file format

A deployed module is stored in `Object.contents` (per section 5.1.5 and section 6.4.1) as a byte string whose interior structure is the **CompiledModule** format defined by Sui-Move (`move-binary-format` crate). The format is itself a stable subset of the Move bytecode binary format originally specified by Diem.

The module structure consists of a four-byte magic number `0xA1, 0x1C, 0xEB, 0x0B` (the Move file format magic, inherited unchanged across Diem, Sui, and Aptos), a `u32` version number, and pools of definitions and references. The pools are, in canonical order: `module_handles` (modules this module imports), `struct_handles` and `field_handles` (struct types and their fields), `function_handles` (function signatures), `friend_decls` (friend module declarations), generic instantiation tables (`struct_def_instantiations`, `function_instantiations`, `field_instantiations`), `signatures` (parameter and return type lists; this is Move's bytecode-format-internal type-list type, distinct from the cryptographic `Signature` of section 6.0.7), `identifiers` (string pool for names), `address_identifiers` (address pool), `constant_pool` (typed constants), `metadata` (Sui-Move metadata entries plus Adamant extensions per section 6.2.1.3), `struct_defs` (struct definitions), and `function_defs` (function definitions, including bytecode bodies).

The structure inside each entry follows Sui-Move's binary format exactly. Genesis modules use the Sui-Move binary format version current at the time of Adamant genesis; future format revisions are hard forks.

**What's stored per function.** Each `FunctionDefinition` carries: a reference to the function's signature in the module's signature pool, the function's bytecode body as a list of instructions (the `Bytecode` enum specified in section 6.2.1.4), local-variable type information, an acquires-list for global resources (always empty in Adamant, since global storage is excluded per section 6.2.1.6), and visibility (`public`, `private`, or `friend`). Adamant-specific privacy annotations are not stored in `FunctionDefinition` itself — they live in a module-level metadata entry (per section 6.2.1.3) so that `FunctionDefinition` remains byte-identical to Sui-Move's layout. The validator (section 6.2.1.6) consults the metadata entry to resolve privacy annotations during verification.

**Encoding boundary.** The CompiledModule bytes themselves are opaque to BCS — they are stored inside the `contents` field of a Module object, and the `contents` field's BCS encoding is a length-prefixed byte vector per section 5.1.5. The bytecode's internal structure is not BCS; it is Sui-Move's binary format extended with Adamant's instruction-set additions per section 6.2.1.4. This is consistent with the encoding/construction split established in section 6.0.7: the protocol's BCS-canonical envelope carries the module bytes, and the bytes' internal interpretation is the bytecode format's concern. Parsing those bytes into an in-memory module representation is specified in section 6.2.1.8.

#### 6.2.1.3 Annotations at bytecode level

Adamant Move's source-level annotations (per section 6.1.2) round-trip into bytecode through metadata entries.

**Mutability declarations** are module-level metadata. The compiler emits a `Metadata` entry on each module with the key `b"adamant.mutability"` and value being the BCS encoding of the `Mutability` enum (per section 5.1.4). The validator (section 6.2.1.6) requires every Adamant module to carry exactly one such metadata entry; modules without it are rejected at deployment.

**Privacy annotations** are module-level metadata. The compiler emits a `Metadata` entry on each module with the key `b"adamant.privacy"` and value being the BCS encoding of `Vec<(FunctionDefinitionIndex, u8)>` — a list of (function index, privacy byte) pairs. The privacy byte values are:

```
PrivacyAnnotation: u8
    0x00 = #[transparent]
    0x01 = #[shielded]
```

The metadata-entry storage location (rather than appending the byte to `FunctionDefinition` directly) preserves byte-faithfulness with Sui-Move's bytecode format per section 6.2.1.1's strict-superset commitment. `FunctionDefinition` is inherited unchanged from Sui-Move; Adamant-specific function metadata lives in module-level metadata entries that the validator (section 6.2.1.6) consults.

Public functions without an entry in this metadata table are rejected by the verifier (matching the source-level requirement in section 6.1.2 that compilers reject unannotated public functions). Private (internal) functions may omit the entry; they inherit the privacy mode of the calling context, and the AVM rejects mixed-mode call chains per section 6.0.5 and the verifier rule in section 6.2.1.6.

**Backward compatibility with Sui-Move.** A standard Sui-Move module without these annotations cannot be deployed on Adamant — the validator rejects it for missing the mutability metadata. This is intentional: Adamant requires explicit mutability and privacy choices on every module, and a Sui module that hasn't made those choices is not yet an Adamant module. Porting a Sui module to Adamant is a one-line change at the module level (adding the mutability declaration) plus per-public-function privacy annotations.

#### 6.2.1.4 Instruction set

The AVM's instruction set is **Sui-Move's bytecode instruction set** (the `Bytecode` enum defined in `move-binary-format::file_format`) plus Adamant-specific extensions. The architecture is **stack-based** — operands are pushed onto an operand stack, instructions consume and produce stack values, and the abstract machine state per function frame is `(stack, locals, pc)`. (Pre-revision drafts of this section described the AVM as register-based; that was a drafting error inconsistent with section 6.1.3's "strict superset of Sui-Move bytecode" claim. Move's bytecode has been stack-based across all three lineages — Diem, Sui, Aptos — and Adamant inherits this architecture.)

**Inherited instruction set.** The protocol inherits the full Sui-Move instruction set as of the binary-format version specified in section 6.2.1.2. The categories below are illustrative for orientation; the authoritative enumeration with opcodes, operand formats, and stack effects is the `Bytecode` enum in Sui's `move-binary-format` crate.

- *Stack and locals:* `Pop`, `Ret`, `BrTrue`, `BrFalse`, `Branch`, `LdU8` through `LdU256`, `CastU8` through `CastU256`, `LdConst`, `LdTrue`, `LdFalse`, `CopyLoc`, `MoveLoc`, `StLoc`.
- *References:* `MutBorrowLoc`, `ImmBorrowLoc`, `MutBorrowField`, `ImmBorrowField`, `ReadRef`, `WriteRef`, `FreezeRef`.
- *Function calls:* `Call`, `CallGeneric`.
- *Struct operations:* `Pack`, `Unpack`, `PackGeneric`, `UnpackGeneric`.
- *Arithmetic and logic:* `Add`, `Sub`, `Mul`, `Mod`, `Div`, `BitOr`, `BitAnd`, `Xor`, `Or`, `And`, `Not`, `Eq`, `Neq`, `Lt`, `Gt`, `Le`, `Ge`, `Shl`, `Shr`.
- *Vector operations:* `VecPack`, `VecLen`, `VecImmBorrow`, `VecMutBorrow`, `VecPushBack`, `VecPopBack`, `VecUnpack`, `VecSwap`.
- *Object operations (Sui-derived):* packing and unpacking of types with the `key` ability, transfer through Sui's object-transfer instructions.
- *Abort:* `Abort`.

**Adamant-specific extensions.** Adamant adds the following instructions in a reserved opcode range above Sui-Move's last opcode, allowing future Sui-Move additions without collision:

- `InvokeShielded(FunctionHandleIndex)` — invoke a `#[shielded]` function. The runtime asserts the caller's privacy context is shielded; if not, the transaction aborts. Stack effect matches `Call`: the operand stack pops one value per function parameter (in declaration order, top-of-stack last) and pushes one value per return value. When the target function's signature contains reference parameters or returns, the borrow-graph effect is identical to Sui-Move's `Call` for the same signature shape — the verifier (section 6.2.1.6) and AVM runtime treat reference inputs and outputs of `InvokeShielded` exactly as they would for an inherited `Call`.
- `InvokeTransparent(FunctionHandleIndex)` — invoke a `#[transparent]` function. The runtime asserts the caller's privacy context is transparent; if not, aborts. Stack effect and reference-safety semantics match `InvokeShielded` (and `Call`) above; the only difference is the runtime privacy-mode assertion.
- `GenerateProof(CircuitId)` — emit a Halo 2 proof witness for the current shielded execution context. Operand is an index into the module's circuit-reference pool. Pops the circuit's input arity (one stack value per declared circuit input, in declaration order) from the stack; pushes a single `Witness` value (per section 6.0.7). The circuit's input arity and per-input types are determined by the circuit signature resolved through the operand's `CircuitId`; the resolution and the input-type list are specified by section 7. At the bytecode layer, the stack effect is parametric in the circuit's signature, similar to how `Call`'s stack effect is parametric in its `FunctionHandle`'s signature.
- `VerifyProof(CircuitId)` — verify a Halo 2 proof. Pops a `Witness` value followed by the circuit's public-input arity (one stack value per declared public input, in declaration order, top-of-stack last); pushes a `bool`. As with `GenerateProof`, the public-input arity and types are determined by the circuit signature resolved through the operand's `CircuitId` per section 7.
- `ReleaseSubViewKey` — produce a sub-view-key per section 4.4 and section 7. Pops the parent view key; pushes the derived sub-key.
- `KzgCommit` — produce a KZG commitment over a vector of field elements per section 3.9.2. Pops the vector; pushes a 48-byte commitment.
- `KzgVerify` — verify a KZG opening proof. Pops the commitment, the opening, and the claimed value; pushes a `bool`.
- `RecursiveVerify` — verify a recursive Halo 2 proof per section 8's recursive verification. Pops the proof value followed by the recursive circuit's public-input arity (one stack value per declared public input, in declaration order, top-of-stack last); pushes a `bool`. The recursive circuit's public-input arity is determined by the circuit signature specified in section 8.5; the stack effect is parametric in that signature in the same shape as `VerifyProof`.
- `Sha3_256` — SHA3-256 hash of a byte vector (per section 3.3.1). Pops a `vector<u8>`; pushes `[u8; 32]`.
- `Blake3` — BLAKE3 hash of a byte vector (per section 3.3.2). Pops a `vector<u8>`; pushes `[u8; 32]`.
- `Ed25519Verify` — verify an Ed25519 signature (per section 3.4.1). Pops public key, message, signature; pushes `bool`.
- `MlDsaVerify65` and `MlDsaVerify87` — verify ML-DSA signatures (per section 3.4.2).
- `MlKemEncapsulate` — perform ML-KEM-768 encapsulation (per section 3.7). Pops an ML-KEM public key (1184 bytes); pushes a `(ciphertext, shared_secret)` tuple as `[u8; 1088]` followed by `[u8; 32]`. Used by privacy-layer circuits (section 7) for stealth address derivation and encrypted memo construction.
- `MlKemDecapsulate` — perform ML-KEM-768 decapsulation (per section 3.7). Pops an ML-KEM secret key and a 1088-byte ciphertext; pushes the recovered 32-byte shared secret. Used by recipient-side privacy circuits.
- `BlsVerify` — verify a BLS12-381 signature (per section 3.4.3).
- `ChargeGas(GasDimension)` — charge a specified amount across one of the six gas dimensions (per section 6.0.7's `GasBudget` and section 6.3.1). Pops the amount as `u64`.
- `RemainingGas(GasDimension)` — push the remaining budget for a specified dimension as `u64`. Used by stdlib functions that adapt behaviour based on remaining budget.
- `OutOfGas` — abort the transaction with the out-of-gas error. Used by stdlib functions that detect dimension exhaustion.

The Adamant-specific extensions are documented as a separate enum (`AdamantBytecode`) that the bytecode format includes alongside the Sui-Move base set; the bytecode body of a function is a sequence of instructions where each instruction is either an inherited Sui-Move opcode or an Adamant extension, distinguished by opcode value.

The complete instruction set — inherited and extension — is genesis-fixed. Adding new instructions (whether by Sui-Move upstream additions we choose to incorporate or by Adamant-specific additions) is a hard fork.

**CircuitId resolution.** Section 6.2.1.4 references "an index into the module's circuit-reference pool" as the operand of `GenerateProof` and `VerifyProof`. The pool is not part of section 6.2.1.2's `CompiledModule` layout (which inherits Sui-Move's pool list unchanged). The pool's location and structure — chain-wide circuit registry, per-module pool extending Sui's `metadata`, or a separate per-module pool field — is deferred to section 7 (the privacy layer), where the cryptographic role of Halo 2 circuits is specified. At the bytecode layer, `CircuitId` is an opaque `u16` index; the resolution from index to circuit definition is the privacy layer's concern, applied at runtime when shielded execution invokes `GenerateProof` or `VerifyProof`. This is the encoding/construction split established in section 6.0.7 (canonical encoding pinned now; semantic construction deferred to the section that defines the role) applied to bytecode operands.

#### 6.2.1.5 Operand encoding

Sui-Move's bytecode uses variable-length operand encoding: the opcode byte is followed by zero or more operand bytes whose layout depends on the opcode. Most operands are indices (into the local-variable table, function-handle table, struct-handle table, signature pool, constant pool, etc.) encoded as ULEB128; immediate values are encoded as little-endian fixed-width integers (`LdU64` is followed by 8 little-endian bytes; `LdU128` is followed by 16 little-endian bytes; `LdU256` is followed by 32 little-endian bytes, matching Sui-Move's inherited `write_u256` encoding).

The bytecode-operand encoding for `U256` differs from section 6.0.7's `Value::U256` BCS encoding, where the 32-byte array is interpreted big-endian as a 256-bit integer. The two paths are independent: bytecode operand encoding inherits from Sui-Move per section 6.2.1.1, while transaction-argument encoding follows BCS canonicality per section 5.1.8. The endianness divergence has no observable consequence at the byte level because the two encoding paths never share bytes — bytecode operands appear inside Move binary modules, while BCS-encoded values appear in transaction arguments and on-chain typed values. Auditors verifying `U256` encoding must check the encoding path against the byte's location in the protocol's data flow.

Adamant inherits this encoding unchanged for the Sui-Move base set. Adamant-specific instructions follow the same encoding rules: opcode byte followed by ULEB128 indices or fixed-width immediates as appropriate.

The bytecode stream itself is not BCS-encoded — it is Move's native binary format, opaque to BCS at the protocol layer. BCS canonicality (section 5.1.8) applies to the protocol's consensus types (Transaction, Object, etc.); the bytecode stored inside a Module object is consensus-critical only insofar as the *bytes* are stored and hashed faithfully, not insofar as those bytes follow BCS rules.

**Per-extension operand encodings.** The 19 Adamant-specific extensions per section 6.2.1.4 use the following operand layouts within the framing above:

- `InvokeShielded(FunctionHandleIndex)` and `InvokeTransparent(FunctionHandleIndex)` — operand encoded as ULEB128, matching Sui-Move's `FunctionHandleIndex` encoding for inherited `Call` and `CallGeneric`.
- `GenerateProof(CircuitId)` and `VerifyProof(CircuitId)` — operand encoded as ULEB128. `CircuitId` is treated as an index per section 6.2.1.4's "an index into the module's circuit-reference pool" framing, matching Sui-Move's encoding pattern for other indices (function-handle, constant-pool, struct-handle, etc.).
- `ChargeGas(GasDimension)` and `RemainingGas(GasDimension)` — operand encoded as a single byte variant tag in declaration order: `Computation = 0x00`, `Storage = 0x01`, `Rent = 0x02`, `Bandwidth = 0x03`, `ProofVerification = 0x04`, `ProofGeneration = 0x05`. This matches the variant-tag pattern established in section 6.0.7's `Value` enum encoding.
- The 13 zero-operand extensions (`ReleaseSubViewKey`, `KzgCommit`, `KzgVerify`, `RecursiveVerify`, `Sha3_256`, `Blake3`, `Ed25519Verify`, `MlDsaVerify65`, `MlDsaVerify87`, `MlKemEncapsulate`, `MlKemDecapsulate`, `BlsVerify`, `OutOfGas`) carry no operand bytes after the opcode byte.

These encodings are genesis-fixed; changing any of them is a hard fork.

#### 6.2.1.6 Validator (bytecode verification)

Before a module is deployed, its bytecode must pass validation. The validator is a static analyser that runs over the module and rejects modules that violate any required property. Deployment is denied for invalid modules; a module that is accepted is guaranteed by the consensus layer to have the validated properties.

The validator runs the **inherited Sui-Move bytecode verifier** (the `move-bytecode-verifier` crate) plus **Adamant-specific additional checks**.

**Inherited checks (from Sui-Move's verifier).** These pass through unchanged:

- *Type safety:* every operand on the stack matches the type expected by the consuming instruction.
- *Reference safety:* borrowed references do not outlive the values they reference; mutable references are not aliased.
- *Linearity:* values without the `copy` ability are never duplicated; values without the `drop` ability are never implicitly discarded.
- *Stack discipline:* stack depth is statically bounded; no stack underflow or runaway growth.
- *Control-flow integrity:* every `Branch` target is a valid instruction within the function; no jumps into the middle of multi-byte instructions.
- *Function-call ABI:* arguments and return values match the function's declared signature.
- *Generic instantiation:* type arguments satisfy the abilities required by the generic parameters (`copy`, `drop`, `key`, `store`).
- *Friend visibility:* friend calls only reach declared friends.

**Adamant-specific additional checks.**

1. **Mutability metadata required.** Every module must carry exactly one `b"adamant.mutability"` metadata entry per section 6.2.1.3. Modules without it are rejected.

2. **Privacy annotation required on public functions.** Every public function must carry a `PrivacyAnnotation` byte (`0x00` for transparent, `0x01` for shielded). Public functions without it are rejected. Private functions may omit the annotation.

3. **Privacy consistency.** A `#[shielded]` function may not contain any `InvokeTransparent` instruction; a `#[transparent]` function may not contain any `InvokeShielded` instruction. The verifier statically checks the entire call graph reachable from each public function and rejects modules where the privacy mode would be violated.

   Privacy consistency is enforced through **defense in depth**: the AVM enforces privacy at runtime as the consensus-binding mechanism (a `#[shielded]` function structurally requires shielded execution context — proof generation infrastructure, encrypted operand stack — and the AVM aborts privacy-mismatched calls at the call boundary regardless of whether deploy-time verification caught the mismatch). The deploy-time static check is the deployer-feedback and gas-trap-prevention layer: it rejects modules whose call graph contains known privacy violations within the limits of what static analysis can prove given the dependencies visible at deploy time. Cross-module call graphs are statically checked at deploy time against the annotations of dependency modules visible on chain at that moment; combined with the upgrade-immutability constraint on privacy annotations (section 6.4.3), this deploy-time guarantee is durable across the lifetime of the deployed module. The runtime check carries the residual binding for any case the static analysis cannot fully verify.

4. **No native functions.** The native-function flag on a function definition (Sui-Move marks runtime-implemented natives this way) must not be set on any function. Per section 6.1.4, every function in Adamant Move is implemented in bytecode. Performance-critical primitives are exposed through Adamant-specific instructions (section 6.2.1.4), not through bytecode-bypass natives.

5. **No global storage instructions.** The Diem-Move global storage instructions (`MoveTo`, `MoveFrom`, `BorrowGlobal`, `Exists`, etc.) must not appear in the bytecode. Per section 6.1.4, all storage access goes through object references. Sui-Move itself phases out these instructions in favour of objects; this rule formalises that policy and rejects any module attempting the legacy patterns.

6. **No dynamic dispatch.** Sui-Move's dynamic-field operations are restricted: a function may use them only if its module carries a metadata entry `b"adamant.allows_dynamic"` whose value is `true`. The default is to disallow them per section 6.1.4. Most Sui-Move modules don't use dynamic fields; those that do typically rely on them for collection types that have first-class object equivalents in Adamant.

   "Dynamic-field operations" are specifically calls to functions whose target module is at address `0x2` and whose module name is either `dynamic_field` or `dynamic_object_field`. This pins the rule's scope at the module level (rather than enumerating individual function names) so that future additions to those Sui standard library modules are automatically captured by the rule without spec amendment. The verifier identifies these calls by inspecting `Call` and `CallGeneric` instructions and resolving their `FunctionHandle` to the target module's `(address, name)` pair via the module's handle tables.

7. **Privacy-circuit instructions in shielded context only.** `GenerateProof`, `VerifyProof`, `RecursiveVerify`, and `ReleaseSubViewKey` may appear only in the body of `#[shielded]` functions or their internal callees. Calling these from a transparent context is rejected at verification time.

8. **Bounded loops.** Loops in the bytecode are bounded at runtime by the gas mechanism per section 6.2.4 ("All loops must have statically-bounded iteration counts or run within a gas budget that bounds them dynamically"). Static loop-bound verification is not required at deployment time; the gas-budget bound at runtime carries the determinism guarantee.

   (Pre-revision drafts of this rule referenced "Sui-Move's existing loop-bound analysis as a starting point." That was a drafting error: Sui-Move's `move-bytecode-verifier::loop_summary` module performs CFG structural analysis — back-edge identification via Tarjan's loop reducibility — rather than iteration-bound analysis. There is no upstream loop-bound analysis to extend. Determinism is established at runtime via section 6.2.4's gas-budget bound; the verifier-level check is a no-op.)

A module that passes all inherited and Adamant-specific checks is **valid** and may be deployed. A module that fails any check is rejected with an error indicating which check failed; the deployment transaction aborts and no rent is consumed for the module that would not have been accepted.

#### 6.2.1.7 Per-instruction gas costs

Per section 6.3.2, gas costs are fixed at genesis and not modifiable post-genesis. Every bytecode instruction has a fixed cost across the six dimensions of the `GasBudget` (per section 6.0.7 and section 6.3.1). Most instructions consume only the `computation` dimension and zero in the others; cryptographic and proof-related instructions consume `computation` plus one or more other dimensions reflecting their resource profile.

The complete cost table is large (≥ 200 instructions × 6 dimensions, mostly zero in five of six dimensions for any given instruction); the table is published as a separate normative appendix to this whitepaper. Reference values across cost categories, illustrative only:

- *Pure stack operations* (`Pop`, `CopyLoc`, `MoveLoc`, `StLoc`): 1–10 computation units; zero in all other dimensions.
- *Arithmetic and logic* (`Add`, `Mul`, `Lt`, `Eq`): width-proportional in computation (u8 cheaper than u256); zero elsewhere.
- *References and field access* (`MutBorrowField`, `ReadRef`, `WriteRef`): computation plus `bandwidth` for references that cross object boundaries.
- *Function calls* (`Call`, `CallGeneric`): computation plus a per-call frame-setup overhead.
- *Object operations* (`Pack` of `key`-bearing types, transfer instructions): computation plus `storage` for any new object created and `rent` for the object's rent prepayment.
- *Cryptographic primitives* (`Sha3_256`, `Ed25519Verify`, `BlsVerify`): computation, proportional to input size and primitive cost. SHA3-256 over n bytes is roughly `100 + 0.5 · n` computation units; Ed25519 verification is roughly 50,000 units; BLS verification is roughly 100,000 units.
- *Privacy operations* (`GenerateProof`, `VerifyProof`, `RecursiveVerify`): consume `proof_generation` and `proof_verification` heavily. A single Halo 2 proof generation is on the order of 10⁹ proof_generation units; verification is on the order of 10⁵ proof_verification units, reflecting the asymmetric cost profile of zero-knowledge proofs.
- *Resource operations* (`ChargeGas`, `RemainingGas`, `OutOfGas`): a flat 1 computation unit; their purpose is to manipulate the gas budget rather than to perform work.

The reference values above are illustrative; the genesis-fixed table in the appendix supplies the exact values. Implementations must match those values exactly. Deviation produces consensus disagreement: validators on different cost tables would diverge on which transactions exhaust their budgets.

The total instruction set is finite and frozen at genesis. New instructions cannot be added without a hard fork (section 11).

#### 6.2.1.8 Module deserializer and verifier architecture

Sections 6.2.1.1 through 6.2.1.7 describe the bytecode language. This subsection describes how a conforming Adamant implementation parses bytecode bytes into an in-memory module representation and runs verification over that representation. The architecture is **fully Adamant-native at deploy-time and runtime**: a conforming Adamant implementation runs entirely independently of Sui-Move's codebase in production builds, with the vendored Sui-Move crates serving as test-only cross-validation reference. A conforming implementation provides its own deserializer, serializer, type definitions, constants, helper utilities, and verifier passes covering both the inherited Sui-Move subset and the Adamant extensions; the vendored Sui-Move crates do not appear in the production binary's dependency graph. This posture makes Adamant **resistant-proof** against upstream Sui changes, shutdowns, vulnerabilities, or governance shifts: once a vendored snapshot is exercised at test time, no future Sui-Move change can affect Adamant's deploy-time accept/reject decisions or runtime behaviour. Two implementations that disagree on whether a given module-bytes input is valid for deployment are not both conforming, regardless of whether either consults Sui-Move. No implementation that depends on Sui-Move's logic at deploy-time or runtime is conforming; test-only, build-tooling-only, and CI-only dependencies on vendored Sui-Move are explicitly permitted, but Sui-Move logic must not execute during deploy-time module verification or runtime VM execution.

(Pre-revision drafts of this subsection described a "Sui-projection" mechanism that fed Adamant modules through Sui-Move's vendored verifier with extension instructions substituted by Sui's `Nop` instruction. Empirical investigation surfaced that 3 of Sui-Move's 4 per-instruction verifier passes — `StackUsageVerifier`, `type_safety`, and `reference_safety` — reject the `Nop` projection for any Adamant extension with nonzero stack, type, or reference effect, which is 16 of 17 extensions. The projection mechanism is therefore not viable: Sui's passes would reject perfectly valid Adamant modules at deployment. The Adamant-native verifier architecture below replaces it. The drafting error is acknowledged here rather than silently revised, in keeping with the audit-trail-honesty pattern established at section 6.2.1.4.)

**The Adamant-native deserializer.** A conforming Adamant implementation provides a deserializer that parses module bytes into an Adamant module representation containing the full Adamant instruction set. The representation extends Sui-Move's `CompiledModule` shape — same module-level pools, same handle tables, same per-function metadata — with one structural change: function bodies are sequences over the Adamant instruction set (Sui-base instructions plus Adamant extensions per section 6.2.1.4) rather than over Sui-Move's `Bytecode` enum alone. The wire encoding for function bodies is specified in section 6.2.1.5; the deserializer parses module-level structure (handle tables, signature pool, identifiers, addresses, constants, metadata, struct definitions, function definition headers) using the binary format defined in section 6.2.1.2, and parses function bodies via the wire-encoding layer.

The deserializer enforces canonical encoding: the deserialized module representation must re-serialize byte-identically to the input. Non-canonical inputs (trailing junk bytes, redundant encodings, or any divergence between input and re-serialization) are rejected. This recovers the canonical-encoding posture that section 6.0.6 establishes for transactions and applies it to module bytecode at the deployment boundary.

**The Adamant-native verifier.** A conforming implementation provides a verifier that operates directly on the Adamant module representation, with full coverage of both the Sui-base subset and the Adamant extensions. The verifier comprises module-level passes (validating structure that does not iterate function bodies) and per-function passes (validating function bodies one at a time):

*Module-level passes.* Bounds checking, structural-limits checking, handle-and-identifier duplication checking, signature well-formedness, instruction-consistency checking (generic versus non-generic variant agreement), constant-pool validation, friend-declaration validation, ability-field-requirements checking on struct fields, recursive-data-definition cycle detection, and instantiation-loop detection. These passes mirror Sui-Move's module-level checks for the inherited subset and are extended where necessary to cover the Adamant-specific module-level metadata (the `b"adamant.mutability"` and `b"adamant.privacy"` entries per section 6.2.1.3, and the `b"adamant.allows_dynamic"` entry per section 6.2.1.6).

*Per-function passes.* Control-flow validation (CFG construction, branch-target validity, fall-through requirement on the last instruction, reducibility), operand-stack discipline (per-block stack-balance with full per-extension stack-effect knowledge from section 6.2.1.4), type safety (abstract interpretation of typed operand stack and locals across the CFG, with type-effect rules for each Adamant extension per section 6.2.1.4), locals safety (control-flow-sensitive availability tracking for local variables), reference safety (abstract borrow-graph tracking with reference-effect rules for `InvokeShielded` and `InvokeTransparent` per section 6.2.1.4 and for any extension whose signature includes references), and acquires-list checking (always trivial in Adamant since global storage is excluded per section 6.2.1.6 rule 5).

The verifier then runs the Adamant-specific rules per section 6.2.1.6.

**What the verifier proves.** A module that is accepted by the Adamant-native verifier satisfies, over the entire module body (Sui-base subset and Adamant extensions alike):

- *Type safety:* every operand on the stack at the consumption point of any instruction has the type that instruction expects.
- *Reference safety:* borrowed references do not outlive the values they reference; mutable references are not aliased; the borrow graph is consistent across the CFG.
- *Linearity:* values without the `copy` ability are not duplicated; values without the `drop` ability are not implicitly discarded.
- *Stack discipline:* the operand stack depth at every basic-block boundary is statically bounded; no instruction underflows the stack or causes runaway growth.
- *Control-flow integrity:* every branch target is a valid instruction within the function; the CFG is reducible.
- *Generic instantiation:* type arguments to generic instructions satisfy the abilities required by the generic parameters.
- *Friend visibility:* friend calls only reach declared friends.
- *Adamant-specific rules per section 6.2.1.6:* mutability metadata required, privacy annotation required on public functions, privacy consistency, no native functions, no global storage instructions, no dynamic dispatch (except with opt-in), privacy-circuit instructions in shielded context only, and bounded loops (per the §6.2.1.6 amendment, this is a runtime gas-budget property rather than a static check).

These guarantees apply uniformly to functions whether or not they contain Adamant extensions. There is no per-function dispatch to different verifier subsets; every function is checked by the full verifier in a single pass.

**Cross-validation against vendored Sui-Move.** The vendored Sui-Move `move-binary-format` and `move-bytecode-verifier` crates serve as a test-only cross-validation reference for the inherited Sui-base subset's semantics. A conforming Adamant implementation exercises Sui's verifier against pure-Sui modules (Adamant modules containing no extension instructions) at test time and confirms that Adamant's verifier reaches the same accept/reject decision — for any such module, the two implementations agree. This cross-validation is strictly a test-time property: it is not run at deployment, and the vendored crates do not appear in the production binary's dependency graph. The cross-validation is exercised by the implementation's test suite to confirm semantic parity with Sui for the inherited subset, surfacing any divergence at development time as a bug in either implementation.

The vendored Sui crates are pinned to the binary-format version specified in section 6.2.1.2 and may be refreshed independently of the Adamant verifier (subject to genesis-fixed binary-format compatibility). If a future Sui upstream change diverges from Adamant's behaviour for the inherited subset, the divergence is contained: Adamant's verifier is the binding implementation, and the vendored crates serve as a reference whose agreement is verified at test time. A vendor refresh that surfaces divergence is a development-time signal — it is not a consensus event, since the production-build pipeline never loads the vendored crates.

**Why fully Adamant-native rather than projection-based.** The architectural decision to verify the full Adamant superset directly, rather than projecting Adamant modules into a Sui-only form for Sui's verifier to check, follows from three considerations:

- *Empirical infeasibility of projection.* As noted in the parenthetical above, the `Nop` projection mechanism originally drafted does not work; 3 of Sui's 4 per-instruction passes reject the projection for non-trivial extension usage. Alternative projections (instruction stripping, per-extension multi-instruction substitution) reintroduce consensus-critical risk surfaces (offset rewriting on branch targets) that were ruled out in earlier investigation. There is no projection mechanism that simultaneously preserves Sui's per-instruction guarantees and avoids breaking branch targets.
- *Genesis-fixed posture.* Adamant's bytecode language and verifier rules are genesis-fixed (sections 6.2.1.4 and 6.2.1.6); once mainnet launches, the verifier's accept/reject decisions are part of consensus and cannot drift. A verifier that depends on Sui's vendored implementation in the deploy-time hot path inherits Sui's evolution as a potential consensus-drift surface — bumping the Sui vendor tag could in principle change which modules are accepted. An Adamant-native verifier removes this surface: Adamant's verifier is the binding implementation, and the vendored Sui crates serve as a reference for development and cross-validation only.
- *Audit surface.* Adamant's verifier is fully under Adamant's audit and maintenance, with consistent treatment of inherited-subset semantics and extension semantics. The "what does Sui's verifier do here" question never arises in the hot path; the verifier is one codebase under one set of eyes.

**Pipeline ordering.** A conforming Adamant deployment validator processes module bytes in the following order:

1. *Deserialize.* Parse the bytes into the Adamant module representation. Reject malformed bytes, unknown opcodes (including bytes outside both the Sui-base and Adamant-extension opcode ranges), or any structural violation of the binary format.
2. *Canonical-encoding round-trip.* Re-serialize the deserialized module and byte-compare against the input. Reject on any divergence.
3. *Module-level passes.* Run the Adamant-native module-level passes (bounds checking, signature well-formedness, etc.) on the deserialized module. Reject on any failure.
4. *Per-function passes.* For each function definition, run the Adamant-native per-function passes (control-flow, stack-usage, type-safety, locals-safety, reference-safety, acquires-list checking). Reject on any failure.
5. *Adamant-specific rules per section 6.2.1.6.* Run the eight rules enumerated in section 6.2.1.6 against the unmodified Adamant module representation. Reject on any failure.

A module is valid for deployment if and only if all five steps succeed. The order is fixed: each step's preconditions are established by the prior step's success, and the canonical-encoding check (step 2) precedes any verification work to ensure that the bytes the verifier examines are the canonical bytes the deployer submitted.

**Implementation note.** The Adamant-native deserializer, serializer, type definitions, helpers, and verifier passes are protocol-level concerns: a conforming implementation must reach the same accept/reject decision on every module-bytes input as the spec's pipeline, and the production-build dependency posture is fixed (no vendored Sui-Move crates in the production dependency graph; test-only, build-tooling-only, and CI-only dependencies are explicitly permitted). Internal representations, data-structure choices, and pass-orchestration details are implementation-discretionary, but both the externally observable accept/reject behaviour and the production-dependency posture are fixed. Two implementations that disagree on whether a given module-bytes input is valid for deployment are not both conforming, regardless of internal choices. The vendored Sui-Move crates are a cross-validation reference for the inherited subset and are exercised at test time; they are not part of the protocol-level specification and cannot appear in conforming production builds.

### 6.2.2 Execution model

When a transaction is executed by the AVM, the following sequence occurs:

1. **Authorisation.** The transaction's authorisation logic is run (section 4). If invalid, execution aborts.

2. **Object loading.** All objects referenced by the transaction are loaded from chain state. The transaction declares its read-set and write-set in advance; the loader validates that the transaction touches no objects outside its declared sets.

3. **Type checking.** The bytecode is verified against the declared types of loaded objects.

4. **Gas budgeting.** The transaction's gas budget (specified by the user, paid in advance) is checked against the protocol's minimum requirements.

5. **Execution.** Bytecode runs to completion or until gas is exhausted. State changes are accumulated in a transaction-local buffer; chain state is not mutated until execution succeeds.

6. **Privacy proof generation.** For shielded transactions, a Halo 2 proof is generated attesting to the correctness of the execution without revealing the shielded inputs or state. For transparent transactions, no proof is required.

7. **Commit or abort.** If execution succeeded and (for shielded transactions) the proof verifies, state changes are committed: object versions increment, ownership transfers apply, new objects are created, destroyed objects are removed. If execution failed, all state changes are discarded except for the gas charged.

This model is per-transaction. Parallel execution across transactions is the next subsection.

### 6.2.3 Parallel execution

The protocol exploits the causal-independence property of the object model (section 5.2.1) to execute many transactions in parallel. The mechanism is **deterministic, declared parallelism**: each transaction declares its read-set and write-set; the scheduler partitions transactions into groups whose declared sets do not overlap; each group runs in parallel.

**Scheduler algorithm (high level).** Given a batch of transactions to execute:

1. Compute the conflict graph: nodes are transactions; edges connect transactions whose read/write sets overlap.
2. Compute a graph colouring: transactions of the same colour have no edges, hence no conflicts.
3. Execute all transactions of the same colour in parallel on available cores.
4. Once a colour completes, proceed to the next colour.
5. Across colours, ordering follows the consensus order from section 8.

This is a deterministic version of the Block-STM algorithm used by Aptos and Sui, with the optimisation that conflicts are detected statically (from declared sets) rather than discovered optimistically at runtime. Static detection is possible because Adamant Move requires explicit declaration of read/write sets; this is a deliberate language design choice that pays off at execution.

**Throughput properties.** For typical workloads, in which the vast majority of transactions touch disjoint object sets, the conflict graph has very few edges and most transactions run in the first colour. Empirically (extrapolating from published Sui and Aptos benchmarks), this translates to per-validator throughput of 100,000+ transactions per second per CPU core, scaling roughly linearly to the number of cores used. The 50,000 TPS floor in Principle IV is comfortably achievable on a 4–8 core validator at realistic conflict rates, with substantial headroom for delivery above the floor under favourable conditions.

**Conflict handling.** When two transactions conflict, the consensus order (section 8) determines which executes first. The losing transaction is re-executed against the post-state of the winner; if the re-execution succeeds, both commit; if it fails (for example, the winner consumed a resource that the loser also needed), the loser aborts with a clear error and its gas is charged against the user's account.

### 6.2.4 Determinism

The AVM is deterministic: two executions of the same transaction against the same state produce identical results. This is essential for consensus: validators must agree on the outcome of every transaction without communicating.

Sources of nondeterminism that Adamant Move and the AVM eliminate:

- **No floating-point arithmetic.** All numeric operations are over fixed-precision integers.
- **No system time access.** Functions cannot query wall-clock time. The chain provides a "consensus time" derived from the consensus mechanism (section 8) which is deterministic across all validators.
- **No randomness from runtime sources.** When randomness is needed, it comes from the consensus VRF (section 8), which is deterministic given the chain state.
- **No I/O.** The AVM cannot make network requests, read files, or interact with anything outside the chain state.
- **Bounded loops only.** All loops must have statically-bounded iteration counts or run within a gas budget that bounds them dynamically.
- **No undefined behaviour.** All operations have specified behaviour for all inputs; there is no equivalent of C's "undefined behaviour" that compilers may exploit.

These constraints are familiar from other smart-contract VMs and are necessary for the correctness of the consensus mechanism. The cost is that some classes of computation cannot be expressed in Adamant Move; this is acceptable.

## 6.3 Resource accounting (gas)

Computation on Adamant is metered. Every operation has a gas cost; transactions specify a gas budget; the budget is charged regardless of whether the transaction succeeds. This prevents denial-of-service attacks and allocates a finite computational resource fairly.

### 6.3.1 Multi-dimensional gas

Adamant uses multi-dimensional gas accounting, separating distinct resources rather than collapsing them into a single number. The dimensions are:

1. **Computation.** CPU cycles consumed by bytecode execution. Charged per instruction class, with weights calibrated to actual hardware costs.

2. **State storage.** Bytes added to active state. Charged per byte at object creation and at object growth.

3. **State rent prepayment.** When an object is created, an amount of rent (section 5.6) must be prepaid. This is a separate dimension from storage to allow per-byte storage and per-byte-second rent to be priced independently.

4. **Bandwidth.** Bytes transmitted by validators when propagating the transaction. Charged per byte at submission.

5. **Proof verification.** CPU cost of verifying zero-knowledge proofs attached to shielded transactions. Charged per proof.

6. **Proof generation (optional).** CPU cost of generating zero-knowledge proofs, if outsourced to a prover market (section 7). Charged per proof when used.

Each dimension has its own price (in ADM) set per epoch by the EIP-1559-style mechanism specified in section 10. A transaction's total fee is the sum of its consumption across dimensions, each multiplied by the relevant price.

**Why multi-dimensional.** The cost of a simple transfer is dominated by computation and bandwidth; the cost of creating a large data object is dominated by storage; the cost of a complex shielded operation is dominated by proof verification. Pricing these as a single "gas" number, as Ethereum does, mis-allocates resources: simple transfers subsidise heavy contracts, and the chain's bottleneck shifts unpredictably between resources. Multi-dimensional accounting prices each resource at its actual marginal cost.

### 6.3.2 Gas costs are fixed at genesis

The gas costs of individual instructions are part of the consensus rules and are fixed at genesis. They cannot be modified by any on-chain mechanism. Changes require a hard fork (section 11).

This is consistent with Principle I (credible neutrality) but represents a real constraint. If, post-genesis, an instruction is found to be under-priced (allowing denial-of-service attacks) or over-priced (deterring legitimate use), the protocol cannot be patched without coordinating a hard fork. The genesis gas table must therefore be calibrated carefully against published benchmarks before launch.

The exception is the *prices* — the multipliers from gas units to ADM. Prices are determined per-epoch by the EIP-1559-style mechanism in section 10, which targets a specific block-fullness. This is not governance; it is a feedback loop with parameters fixed at genesis.

### 6.3.3 Failed transactions are charged

A transaction that fails partway through execution is charged for the gas it consumed up to the point of failure, plus a small minimum fee. This prevents adversaries from submitting failing transactions for free.

The exception is authorisation failure: if a transaction's authorisation logic (section 4) returns invalid, the transaction is rejected at the mempool layer and never executed. No gas is charged because no execution occurred.

### 6.3.4 Sponsored transactions

The smart-account model (section 4) allows validation logic to specify that fees are paid by an account other than the transaction submitter. This enables:

- **Application-sponsored transactions.** A dapp pays the gas for its users' interactions, removing a key onboarding friction.
- **Paymaster contracts.** A specialised contract pays gas for specified categories of transactions, charging users in another currency or off-chain.
- **Free-tier sponsorship.** A protocol-deployed contract pays gas for users below a usage threshold, funded by some other mechanism (advertisement-free model, philanthropic funding, etc.).

Sponsored transactions are not a special case in the protocol; they are a natural consequence of validation logic being arbitrary code. The "fee payer" of a transaction is whichever account the validation logic specifies — typically, but not necessarily, the transaction submitter.

## 6.4 Module deployment and upgrades

Smart contracts on Adamant are organised into *modules*, the same unit of code organisation as in standard Move. A module contains type definitions and function definitions; modules are deployed to the chain as Adamant Move bytecode.

### 6.4.1 Deployment

Module deployment is a transaction whose effect is to create a new `Module` object on the chain. The `Module` object's `mutability` field is the module's declared mutability (from the `#[mutability(...)]` annotation, section 6.1.2). The module's bytecode is stored in the `contents` field.

After deployment, contracts and other modules can reference the deployed module by its `ObjectId`, invoke its public functions, and read its public types.

### 6.4.2 Upgrade

A module upgrade is a transaction that submits new bytecode to replace the existing bytecode of a module. Whether the upgrade succeeds depends on the module's mutability:

- `Immutable` modules cannot be upgraded. Upgrade transactions targeting them are rejected by consensus.
- `OwnerUpgradeable` modules can be upgraded by a transaction signed by the owner.
- `VoteUpgradeable` modules can be upgraded after a successful vote, with the upgrade applied after the execution delay.
- `UpgradeableUntilFrozen` modules can be upgraded by the owner until the freeze operation is called, after which they behave as `Immutable`.
- `Custom` modules can be upgraded subject to the validator object's rules.

### 6.4.3 Compatibility constraints on upgrades

A module upgrade is required to be *compatible* with the previous version, in a specific technical sense: types defined by the module that are referenced by other modules cannot be removed or have their layout changed. Adding new types, new functions, or extending existing functions in backward-compatible ways is permitted.

**Privacy annotations are part of the public API contract.** The privacy annotation on a public function (per section 6.2.1.3) is upgrade-immutable: an upgrade may not change a public function's annotation from `#[transparent]` to `#[shielded]` or vice versa. This is enforced at upgrade time alongside the existing compatibility checks; an upgrade attempting to change a public function's privacy annotation is rejected.

This constraint exists because dependent modules may have been deployed against the original privacy annotation — a `#[shielded]` caller in another module that linked against an upgraded function expecting it to remain `#[shielded]` should not silently find itself calling a `#[transparent]` implementation after the upgrade. Privacy mode is a fundamental property of how a function interacts with the rest of the chain, and changing it across upgrades would invalidate the static deploy-time guarantees that dependent modules rely on (per section 6.2.1.6 rule 3). Internal (non-public) functions may change privacy mode across upgrades freely; only public functions are constrained, since only public functions are part of the cross-module API surface.

This constraint exists to prevent silent breakage of dependent contracts. If module A defines type `T` and module B holds a value of type `T`, an upgrade to module A that removes `T` would render module B's value un-interpretable. The compiler and the chain enforce this constraint at upgrade time.

For cases where breaking changes are desired, the standard pattern is to deploy a new module (with a new `ObjectId`) and migrate users explicitly.

## 6.5 Standard library

The protocol provides a standard library of modules, deployed at genesis with `Immutable` mutability. The standard library includes:

- `adamant::primitives` — basic types (vectors, options, strings, etc.) and operations
- `adamant::object` — object manipulation primitives
- `adamant::address` — address arithmetic and validation
- `adamant::hash` — SHA-3 and BLAKE3 wrappers
- `adamant::signature` — Ed25519 and ML-DSA verification
- `adamant::privacy` — shielded execution primitives
- `adamant::token` — fungible token reference implementation
- `adamant::nft` — non-fungible token reference implementation
- `adamant::governance` — vote-based mutability helpers
- `adamant::recovery` — social-recovery helpers for accounts

Modules in the standard library are accessible from any contract without separate deployment. They are `Immutable` and cannot be modified post-genesis. A future hard fork may extend the standard library; existing standard-library modules are permanent.

The standard library is deliberately conservative. It provides the primitives applications need without prescribing application architectures. Higher-level patterns (decentralised exchange logic, lending protocols, identity systems, etc.) are expected to be implemented as user-deployed modules, not bundled into the standard library.

## 6.6 Verification and the Move Prover

The Move language was designed alongside the **Move Prover**, a static verification tool that checks contracts against formal specifications. Adamant Move inherits the Move Prover; specifications written in the Move Prover specification language are checked against contracts at compile time.

The Move Prover's contribution is the ability to prove non-trivial properties of contracts: "this contract never allows the total token supply to exceed X", "this lending protocol never allows under-collateralised positions", "this voting contract never allows double-voting". These are exactly the properties that have, on other chains, been violated by deployed contracts with catastrophic consequences.

The protocol does not require contracts to be Prover-verified; it does, however, strongly recommend it for any contract holding significant value. Reference wallets `SHOULD` surface verification status to users when displaying contracts: "this contract has been formally verified for the property [X]" is a meaningfully different trust signal than "this contract compiled without errors".

## 6.7 Worked example: continuing the token

Continuing the worked example from section 5.8, here is the structure of a fungible-token module in Adamant Move:

```move
#[mutability(immutable)]
module 0xCOFFEE::example_token {
    use adamant::object;
    use adamant::token;

    public struct ExampleToken has key, store {
        id: object::ObjectId,
        balance: u64,
    }

    public struct TokenSupply has key {
        id: object::ObjectId,
        total: u64,
        max_supply: u64,
    }

    #[shielded]
    public fun transfer(
        from: &mut ExampleToken,
        to: &mut ExampleToken,
        amount: u64,
    ) {
        // Linear types ensure 'amount' is accounted for exactly:
        // it leaves 'from' and arrives at 'to'.
        from.balance = from.balance - amount;
        to.balance = to.balance + amount;
        // The compiler emits range-proof and balance-conservation
        // circuit witnesses automatically, because the function is
        // marked #[shielded].
    }

    #[transparent]
    public fun supply(supply: &TokenSupply): u64 {
        supply.total
    }

    // ... mint, burn, etc.
}
```

A few features worth observing:

- The mutability is declared `Immutable` at the module level. The module's code cannot be changed after deployment. Users interacting with the token can rely on its current rules forever.
- The `transfer` function is `#[shielded]`. The compiler automatically generates the zero-knowledge circuit witness; the developer writes ordinary code.
- The linear type system ensures `amount` is correctly accounted for. Code that "forgets" to update `to.balance` after subtracting from `from.balance` does not compile.
- The function body is short because the protocol provides the cryptographic machinery. The contract author writes business logic; the protocol handles cryptography.

This worked example will be revisited in section 7 (Privacy Layer), which specifies the cryptographic mechanisms underlying `#[shielded]` functions.
# 7. Privacy Layer

This section specifies how Adamant achieves privacy by default. It is the longest and most cryptographically dense section in this whitepaper, because privacy that is genuinely usable — private by default, programmable, auditable when the user chooses, and resistant to deanonymisation through chain analysis — requires substantial cryptographic machinery.

The section builds on section 3 (cryptographic primitives), section 4 (account model and view keys), section 5 (object model), and section 6 (Adamant Move's `#[shielded]` annotation). It specifies:

1. The note model: how value is represented privately on the chain
2. Stealth addresses: how recipient identities are hidden
3. Shielded execution circuits: how Halo 2 proofs attest to correct shielded computation
4. View keys and selective disclosure: the cryptographic basis of section 4.4
5. The shielded pool: the global anonymity set
6. Encrypted memos: how parties communicate transaction context privately
7. Prover markets: the optional outsourcing of proof generation
8. Compliance considerations and threat boundaries

The design follows from Principle II (privacy by default), and it is designed to interact cleanly with Principle I (credible neutrality) and Principle IV (performance). Where these come into tension, the priority order in section 2.8 governs.

## 7.1 The note model

The fundamental unit of shielded value on Adamant is the **note**: a cryptographic commitment to a value held by a specified recipient under specified conditions. Notes are conceptually similar to Zcash Sapling/Orchard notes and to Aztec's notes, with adaptations for Adamant's object model.

A note is a tuple:

```
Note {
    value:        u64,           // the amount, in the smallest unit
    asset_type:   TypeId,        // identifies the type of asset (e.g. ADM, a token type)
    recipient:    StealthAddress, // see section 7.2
    randomness:   [u8; 32],      // sampled per note; ensures uncorrelatable commitments
    metadata:     NoteMetadata,  // application-specific data
}
```

A note never appears on the chain in cleartext. What appears on the chain is the note's **commitment**, computed as:

```
commitment = Poseidon(value || asset_type || recipient || randomness || metadata_hash)
```

The commitment is 256 bits and reveals nothing about its inputs. Two notes with the same `value`, `asset_type`, and `recipient` but different `randomness` values produce uncorrelated commitments.

### 7.1.1 Note states

Notes have three possible states:

1. **Created** — the commitment exists in the global note commitment tree, but the note has not been spent.
2. **Spent** — the note's nullifier has been published, indicating that the note has been consumed by some transaction. The note's commitment remains in the tree (commitments are append-only) but the nullifier prevents double-spending.
3. **Discoverable** — the note's owner has access to it via their view key but has not yet spent it. This is a property of view-key holders, not a global state.

### 7.1.2 Nullifiers

A **nullifier** is a 256-bit value uniquely derived from a note and its owner's secret key. It is published to the chain when the note is spent, and the chain rejects any future transaction that publishes the same nullifier.

Nullifier construction:

```
nullifier = Poseidon(domain_tag || nullifier_key || note_commitment || position_in_tree)
```

Where:
- `nullifier_key` is a key derived from the owner's spending key (specifically: `nullifier_key = Poseidon(domain || spending_key)`)
- `position_in_tree` is the note's leaf index in the global commitment tree

This construction has critical properties:

- **Unlinkability.** A nullifier reveals nothing about the note it nullifies — neither value, recipient, nor commitment. To an observer, a published nullifier is a random 256-bit value.
- **Uniqueness.** Each note has exactly one valid nullifier. An attacker who tries to spend the same note twice must produce the same nullifier; the chain rejects the duplicate.
- **Unforgeability.** Producing the correct nullifier requires the spending key. Without it, computing the nullifier is intractable.

### 7.1.3 The note commitment tree

All note commitments ever created on Adamant live in a single append-only Merkle tree, the **global note commitment tree** (GNCT). The tree has a fixed depth of 64, allowing 2^64 notes — sufficient for the chain's projected lifetime.

Tree properties:

- **Append-only.** Once a commitment is added, it cannot be removed or modified. This is essential to the privacy model: removing commitments would create deanonymisation opportunities.
- **Per-shielded-transaction Merkle proof.** A transaction spending a note proves, via a Merkle path, that the note's commitment is in the tree. The proof reveals only the path's hash chain, not which specific commitment is referenced. This is the basis of the protocol's anonymity set.
- **Anonymity set = entire tree.** Every shielded spend is indistinguishable from spending any other note in the tree, because the Merkle proof reveals only that *some* commitment in the tree is being spent. The anonymity set grows with the chain's history.
- **Recent-roots window.** Validators retain Merkle roots of the GNCT for the most recent 100 epochs (approximately 1 hour at 36-second epochs). Spends prove against any of these roots, allowing wallets to spend notes without re-syncing the latest tree state on every transaction.

The tree is implemented using the Pedersen-hashed Merkle construction with Poseidon hashing for in-circuit efficiency.

### 7.1.4 Comparison with Zcash and Aztec

Adamant's note model is closest to Zcash Orchard (the current generation of Zcash shielded notes), with two adaptations:

1. **Asset diversity.** Adamant notes carry an `asset_type` field, allowing many distinct assets (tokens, NFT-like objects, etc.) to share the global anonymity set. Zcash's Orchard pool is single-asset (ZEC only); Adamant's design follows Aztec's multi-asset approach.

2. **Programmable metadata.** Adamant notes carry application-specific metadata, allowing contracts to attach arbitrary data to notes (e.g. a vesting schedule, an unlock condition, an attached message hash). The metadata is committed in the note commitment but visible only to view-key holders.

These adaptations preserve Zcash's strong privacy properties while extending the model to support programmable shielded contracts.

## 7.2 Stealth addresses

A **stealth address** is a one-time-use address derived from a recipient's long-term identity such that observers cannot link multiple notes destined for the same recipient.

### 7.2.1 The problem stealth addresses solve

Without stealth addresses, every transfer to a particular recipient would publish the recipient's address (or a fixed hash of it) on the chain. Even if the value and sender are hidden, repeated transfers to the same recipient would be observable: "the same recipient received 50 transactions over the past week" is a powerful starting point for deanonymisation, even without knowing who the recipient is.

Stealth addresses solve this by deriving a fresh, unlinkable address for every transfer. A recipient publishes a single long-term *viewing key* and *spending public key*, and senders derive one-time addresses from these such that the recipient can recognise transfers to themselves but no observer can correlate multiple transfers.

### 7.2.2 Construction

The protocol uses an **ML-KEM-based stealth address scheme**, providing post-quantum-secure key agreement (Principle VIII, section 2.8). Earlier drafts of this whitepaper specified a Diffie-Hellman scheme on BLS12-381 (analogous to Zcash Sapling/Orchard); that scheme is replaced here because Diffie-Hellman key agreement on BLS12-381 is not post-quantum-secure, and historical privacy is a permanent property that must survive future quantum cryptanalysis.

A recipient's long-term identity comprises:

- **Spending key** `sk_s`: scalar in the BLS12-381 scalar field (used for nullifier derivation and spending authorization, classical layer; see section 7.2.5 for hybrid-mode considerations)
- **Viewing keypair** `(sk_v_kem, pk_v_kem)`: an ML-KEM-768 keypair (public key 1184 bytes, secret key 2400 bytes)
- **Spending public key** `pk_s = sk_s · G` where G is the BLS12-381 curve generator

The recipient's "address" published off-chain (in payment URIs, QR codes, etc.) is `(pk_s, pk_v_kem)`. ML-KEM public keys are larger than ECDH public keys, so addresses are larger; address-encoding formats accommodate this (Bech32m at appropriate length, QR codes scaled correspondingly).

To send a note to this recipient, a sender:

1. Performs ML-KEM-768 encapsulation against `pk_v_kem`, producing `(ct, ss)` where `ct` is a 1088-byte ciphertext and `ss` is a 32-byte shared secret
2. Stores `ct` as part of the note's on-chain data (analogous to the `R` element in classical schemes)
3. Computes the shared scalar: `s = HashToScalar(ss || domain_tag)` where `HashToScalar` produces a BLS12-381 scalar field element
4. Computes the one-time stealth address: `P = pk_s + s · G`
5. Constructs the note with `recipient = P`

The recipient's wallet, upon scanning the chain, performs for each note:

1. ML-KEM-768 decapsulation: `ss' = Decap(sk_v_kem, ct)`
2. `s' = HashToScalar(ss' || domain_tag)`
3. `P' = pk_s + s' · G`
4. If `P' == note.recipient`, the note is for this recipient

If the note is theirs, the recipient derives the corresponding spending key as `sk' = sk_s + s'` and uses it to construct the nullifier when spending.

**Why ML-KEM and not BLS12-381 ECDH.** ECDH on BLS12-381 (or any elliptic curve over a finite field) is broken by Shor's algorithm; a future quantum adversary observing historical chain state can recover `r · pk_v` from `(r · G, pk_v)` by computing the discrete logarithm. ML-KEM is lattice-based and presumed post-quantum-secure; encapsulation outputs cannot be retroactively broken by quantum attack. The cost of this protection is the per-note ciphertext size (1088 bytes vs ~32 bytes for ECDH); this is amortised across the note's lifetime and is acceptable given the permanence of the privacy guarantee.

**Bytecode-level construction.** Section 6.2.1.4's `MlKemEncapsulate` and `MlKemDecapsulate` instructions perform the ML-KEM operations inside Adamant Move shielded circuits. The compiler emits these instructions automatically when `#[shielded]` functions construct or process notes; contract authors do not invoke them directly.

### 7.2.3 Properties

- **Unlinkability.** Two stealth addresses for the same recipient look entirely uncorrelated to anyone without the viewing keypair. Computing the link requires either `sk_v_kem` or breaking ML-KEM, which is presumed hard against both classical and quantum adversaries.
- **No interaction.** The sender does not communicate with the recipient; the stealth address is derived purely from public information.
- **Selective disclosure compatible.** Disclosing the viewing keypair reveals all notes for the recipient but does not reveal the spending key, so view-key holders can audit but not spend.
- **Post-quantum secure.** Future quantum cryptanalysis cannot retroactively deanonymise transactions that used ML-KEM-derived stealth addresses. This is the substantive improvement over the classical scheme this construction replaces.

### 7.2.4 View tag optimisation

A naive scan of the chain requires the recipient to compute `s'` and `P'` for every note ever created — an operation that becomes prohibitive as the chain grows. The protocol addresses this with a **view tag**: an 8-bit value attached to each note, computed from the shared secret. A wallet scanning notes can quickly reject notes whose view tag does not match the expected value, computing the full check only for the ~1/256 notes that pass the tag filter.

The view tag is computed as `view_tag = SHA3_256(ss || tag_domain)[0]` where `ss` is the ML-KEM shared secret. Wallets first compute the view tag from the candidate decapsulation, compare it to the on-chain tag, and proceed to the full address derivation only on match.

This optimisation is borrowed from Monero's view tag design (introduced 2022), adapted to the ML-KEM construction. It reduces wallet scan cost by roughly 256× at the cost of a minor reduction in privacy: an attacker observing the view tags of a known recipient can identify roughly 1/256 of notes as candidates for that recipient. This is a substantially weaker signal than full address linkage and is widely accepted as a reasonable trade-off.

### 7.2.5 Spending key in hybrid signature mode

The spending key `sk_s` controls authorisation to spend notes received at stealth addresses. Per Principle VIII (hybrid signatures), users may configure spending authorization via either Ed25519 (default for routine spending) or ML-DSA (opt-in for elevated threat models). The wallet derives both from the same master seed via HKDF-SHA3 with distinct domain separators.

The protocol's nullifier derivation (section 7.1.2) is independent of the spending signature scheme: nullifiers commit to the note position and the spending key, not to the signature. A user who later opts up from Ed25519 to ML-DSA spending does not invalidate previously-derived nullifiers; the spending key material is the same, only the signature scheme over the spend transaction changes.

## 7.3 Shielded execution circuits

A shielded transaction's correctness is attested by a Halo 2 zero-knowledge proof. The proof asserts that the transaction is valid — every input note exists, every nullifier is correctly derived, every output note is well-formed, every value-conservation rule is respected — without revealing the inputs, the values, or the recipients.

### 7.3.1 Anatomy of a shielded transaction

A shielded transaction comprises:

```
ShieldedTransaction {
    nullifiers:        Vec<Nullifier>,        // notes being spent
    output_commitments: Vec<NoteCommitment>,  // notes being created
    encrypted_outputs:  Vec<EncryptedNote>,   // for recipient delivery
    public_inputs:     PublicInputs,          // explicit transaction parameters
    proof:             Halo2Proof,            // attests to validity
    binding_signature: Signature,             // ties the proof to the transaction
}
```

Public inputs include the nullifiers, the output commitments, the GNCT root being spent against, the asset types involved (which may be partially disclosed for compliance), and any explicit fees. Everything else is hidden.

### 7.3.2 The validity circuit

The Halo 2 circuit that proves validity asserts the following statements:

1. **Input note existence.** For each nullifier, there exists a note commitment in the GNCT (proven via a Merkle path) and the nullifier is correctly derived from the note's contents.

2. **Nullifier uniqueness.** Each published nullifier has not previously appeared on the chain. (This check is partly in-circuit, partly enforced by the consensus layer's nullifier set.)

3. **Output note well-formedness.** Each output commitment is correctly computed from valid inputs (a recipient stealth address, a value, an asset type, randomness).

4. **Value conservation.** The sum of input values equals the sum of output values plus the explicit fees, *per asset type*. This is the property that prevents inflation: a shielded transaction cannot create value from nothing or destroy value silently.

5. **Range proofs.** Every value in the transaction lies in `[0, 2^64)`. Without this, an attacker could create notes with negative values that nominally satisfy value conservation while creating value.

6. **Authority.** For each input note, the prover knows the spending key corresponding to the note's recipient. This is the analog of "the spender authorised the spend."

7. **Smart-contract execution.** For shielded executions of `#[shielded]` Adamant Move functions, the circuit additionally proves that the function executed correctly given the shielded inputs and produced the shielded outputs.

The circuit is large — typical proofs cover tens of thousands of constraints. Halo 2's PLONKish arithmetisation is well suited to this scale; proof size is approximately 1–4 KB depending on the complexity of the shielded computation.

### 7.3.3 Proof generation cost

Generating a Halo 2 proof for a typical shielded transaction takes:

- **Simple transfer (1 input, 2 outputs):** approximately 2–5 seconds on consumer laptop hardware (M2-class CPU), 4–10 seconds on a modern smartphone.
- **Complex shielded contract execution:** can range from 10 seconds to several minutes depending on circuit complexity.

These figures derive from published Halo 2 benchmarks and Aztec's measured proving times for analogous operations (Aztec mainnet, November 2025 onwards). They are improving over time as proving systems mature.

### 7.3.4 Proof verification cost

Verifying a Halo 2 proof is fast: approximately 5–10 milliseconds per proof on commodity hardware, regardless of the proof's circuit size. Validators verify proofs as part of consensus; the verification cost is bounded and predictable.

## 7.4 View keys and selective disclosure

Section 4.4 introduced view keys conceptually. This subsection specifies the cryptographic mechanisms.

### 7.4.1 View key hierarchy

A user's master seed deterministically generates a hierarchical key tree:

```
master_seed
   ├── spending_key (sk_s)
   ├── viewing_key (sk_v) ── full account visibility
   │      ├── time_window_view_key   ── visibility into [t1, t2] only
   │      ├── counterparty_view_key  ── visibility into transactions with X only
   │      ├── amount_threshold_view_key ── visibility into amounts > Y only
   │      └── compliance_view_key    ── visibility into transactions matching rules R
   └── nullifier_key (sk_n) ── deterministic from sk_s
```

The viewing key has full visibility. Sub-view-keys are derived deterministically from the viewing key with parameters specifying their scope. The derivation is one-way: a sub-view-key holder cannot derive the parent viewing key.

### 7.4.2 Sub-view-key construction

A sub-view-key for scope `S` is constructed as:

```
sub_view_key_S = (sk_v + Hash(domain || S || sk_v) · G_aux)
```

Where `G_aux` is a fixed auxiliary curve point and `S` is a structured description of the sub-key's scope (e.g. `{"start": t1, "end": t2}` for a time-windowed key).

The sub-view-key allows the holder to compute the shared secret `s'` for notes that fall within scope `S`, but is cryptographically constructed so that notes outside scope `S` produce nonsense decryption results.

The implementation of "in scope" is enforced by the recipient's wallet, not by the chain: the wallet decides which sub-view-keys to derive and to whom. The chain has no view-key-related logic; it does not know which sub-view-keys exist.

### 7.4.3 Provable disclosure

A user can produce cryptographic proofs of specific facts about their transactions without revealing other facts. Examples:

- "I received at least X ADM from address Y between dates D1 and D2." Prover constructs a Halo 2 proof that some subset of their notes meet these criteria, without revealing which specific notes or what other notes they hold.
- "My current shielded balance is at least Z." Useful for proof-of-solvency to a counterparty.
- "I have not received any notes from sanctioned address X." Useful for compliance assertions where the user wants to prove the negative.

The protocol provides circuit primitives for constructing such proofs (`adamant::privacy::prove_assertion(...)` in the standard library, section 6.5). Wallets expose them as user-friendly operations: "generate audit proof for tax filing", "generate solvency proof for counterparty", etc.

### 7.4.4 Compliance considerations

The view-key mechanism provides users with a strong compliance posture: they can prove facts about their financial activity to legitimate authorities (auditors, tax authorities, regulators with demonstrated legal standing) without exposing unrelated transaction history.

This is a significantly *stronger* compliance posture than transparent chains offer. On a transparent chain, a user complying with a regulatory request must expose their entire transaction history forever, to all observers. On Adamant, the user controls precisely what is disclosed and to whom.

The protocol does **not** include any mechanism for compelled disclosure. There is no key escrow, no master decryption key held by any party, no protocol-level mechanism by which a third party can demand a view key. A user who refuses to disclose simply does not disclose; the protocol does not provide override.

This is not a regulatory loophole; it is a deliberate design choice consistent with Principle I and Principle II. The protocol's view is that compliance is an obligation of the user, not a property the protocol enforces. Users in jurisdictions with disclosure requirements can comply; users facing illegitimate demands have the cryptographic option to refuse.

## 7.5 The shielded pool and anonymity set

The "shielded pool" is the collective set of all unspent shielded notes on the chain. The pool's size is the protocol's anonymity set: every shielded spend is, in principle, indistinguishable from spending any note in the pool.

### 7.5.1 Anonymity set growth

The anonymity set grows monotonically over time, in two senses:

1. **More notes.** As transactions create more notes, the pool grows. A spend's anonymity set is the entire pool at the time of spending.
2. **More age.** The age distribution of notes in the pool widens over time, making timing-correlation attacks harder.

There is no equivalent on Adamant of Monero's "ring size" or Zcash's "selected anonymity set". Every spend is anonymised against the full pool, because the Merkle proof of inclusion reveals only that *some* commitment is being spent.

### 7.5.2 Anonymity set hygiene

Several practices preserve the strength of the anonymity set:

- **Default-shielded transactions.** Because Adamant transactions are shielded by default (Principle II), the anonymity set comprises the entire population of users, not the subset who opted into privacy. This is the most important property: the anonymity set is the chain's user base, not its privacy-conscious subset.

- **Decoy transactions are unnecessary.** Some privacy chains generate decoy traffic to obscure timing patterns. Adamant does not, because the volume of organic shielded traffic at the throughput target is sufficient.

- **No pool segmentation.** All shielded transactions, regardless of asset type or amount, draw from the same anonymity set. There is no "small-value pool" vs "large-value pool"; segmentation would weaken privacy by partitioning users.

### 7.5.3 Known limitations

The anonymity set is a powerful but not unconditional defence:

- **Off-chain context.** If a user known to receive a payment from another known user transfers funds shortly afterward, an observer with off-chain knowledge can draw inferences. The chain's privacy does not protect against off-chain correlation.

- **Statistical attacks at edges.** Users who interact only rarely with the chain present a smaller "behavioural" anonymity set to a sophisticated observer with access to broad metadata (network surveillance, exchange records, etc.). The chain's cryptographic privacy is unconditional, but the *practical* privacy of an individual user depends on their broader operational security.

- **Zero-day cryptographic breaks.** The privacy guarantees rest on Halo 2's soundness, the discrete-log assumption on BLS12-381, and the random-oracle assumption on Poseidon. A break in any of these would compromise privacy. The protocol uses well-studied primitives to minimise this risk but cannot eliminate it.

These limitations are documented because they are real. The protocol does not promise privacy that it cannot deliver.

## 7.6 Encrypted memos

Senders frequently need to communicate context to recipients — invoice numbers, references, free-text notes. The protocol supports this via **encrypted memos** attached to notes.

### 7.6.1 Memo construction

A memo is up to 512 bytes of arbitrary data, encrypted to the recipient's stealth address. The memo is included in the note's encrypted output (the data structure that allows the recipient to decrypt the note's contents) and is invisible to all other parties.

Encryption uses ChaCha20-Poly1305 (section 3.5) with the key derived from the stealth shared secret:

```
memo_key = HashToKey(s || domain_tag_memo)
encrypted_memo = ChaCha20Poly1305(memo_key, nonce, memo_plaintext)
```

The recipient decrypts using their derived shared secret.

### 7.6.2 Memo policies

Applications may define structured memo formats: standard fields for invoices, payment references, etc. The protocol does not prescribe a format; common formats may emerge by convention.

Wallets `SHOULD` warn users that memos are visible to the recipient and to anyone the recipient shares their viewing key with. A "private memo" between sender and recipient is genuinely private only if both parties' operational security is intact.

## 7.7 Prover markets

Generating Halo 2 proofs is computationally significant — seconds on a laptop, longer on a phone for complex contracts. Some users will prefer to outsource proof generation to specialised hardware. The protocol supports this through **prover markets**.

### 7.7.1 Mechanism

A user constructing a shielded transaction can:

1. **Prove locally.** Generate the Halo 2 proof on their own device. The proof reveals nothing to anyone; the user pays only standard transaction fees.

2. **Outsource to a prover.** Encrypt the witness data (the inputs the prover needs) to a chosen prover's public key, submit the witness with a fee offer to the prover market, and receive the completed proof. The prover sees the witness contents (so the user must trust the prover with this data); the chain sees only the final proof.

3. **Outsource via a privacy-preserving prover.** Some prover protocols (using secure enclaves, multi-party computation, or trusted hardware) allow proving without revealing the witness to the prover. These are emerging technologies; the protocol supports them where available but does not require them.

### 7.7.2 The trust model

Outsourcing proof generation is a trust trade-off: the user trades computational convenience for the prover's ability to see (and potentially log) their witness data. For low-value transactions where the witness contents are uninteresting, this is fine. For high-value transactions, users `SHOULD` prove locally or use privacy-preserving proving.

The chain does not enforce this trade-off; it is the user's choice. Wallets `SHOULD` surface the choice clearly.

### 7.7.3 Provers as a market

Multiple provers compete in the market. Provers advertise their fee rates, their hardware, and (where applicable) their privacy-preservation properties. Users select provers based on these criteria.

Provers earn fees in ADM. The protocol does not specify the prover protocol in detail beyond ensuring that the on-chain submission mechanism (a transaction containing a prover-generated proof) works identically to a self-generated proof. The market itself is permissionless: anyone can become a prover.

## 7.8 Privacy and the object model

Section 5.7 anticipated this subsection: how does the privacy layer interact with the object model?

### 7.8.1 Shielded vs transparent objects

An object is either **shielded** or **transparent**, declared at creation:

- **Shielded objects.** The `contents` field is encrypted. State transitions are accompanied by Halo 2 proofs attesting to correctness. The object's existence is public; its contents and ownership details are not.

- **Transparent objects.** The `contents` field is in clear text. State transitions are visible to all observers. Ownership is visible. Useful for public-record applications, public bounties, transparent governance, and any case where the application's purpose requires transparency.

This is a per-object choice, not a per-transaction choice. An object created shielded remains shielded for its lifetime; an object created transparent remains transparent for its lifetime. (A shielded object can produce transparent outputs by explicitly burning to a transparent destination, and vice versa, but the object itself does not switch modes.)

### 7.8.2 Mixed transactions

A single transaction may touch both shielded and transparent objects. The transaction's structure reflects this: shielded portions carry Halo 2 proofs; transparent portions are visible. The mix is common: a user spends shielded notes to pay a transparent contract, or a transparent contract emits shielded notes to a recipient.

The Adamant Move compiler handles the proof generation for the shielded portions automatically when functions are annotated `#[shielded]` (section 6.1.2).

### 7.8.3 Privacy of mutability declarations

Object mutability declarations are *always* in clear text, regardless of whether the object is otherwise shielded. This is mandated by Principle V (mutability must be visible to users before interaction). A user inspecting a contract `MUST` be able to determine its mutability without trust in any party.

## 7.9 Threat model and limitations

This subsection documents what the privacy layer protects against and what it does not.

### 7.9.1 Protected against

- **On-chain analysis.** An adversary observing only the chain learns the existence and structural properties of shielded transactions but not their contents, values, or participants beyond what is publicly disclosed.

- **Validator surveillance.** Validators see the same data as any other on-chain observer; their privileged role in consensus does not give them privileged access to shielded data.

- **Network surveillance of shielded transaction contents.** Encryption between user wallets and the network protects shielded transaction data in transit.

- **Compelled decryption.** No party — including the protocol's original implementers, validators acting in concert, or governments — can decrypt shielded data without the user's cooperation.

### 7.9.2 Not protected against

- **Off-chain correlation.** If the user identifies themselves to a third party (an exchange, a vendor, a service provider) and that party correlates on-chain activity to their off-chain identity, the chain's cryptographic privacy is undefeated but the practical anonymity is reduced.

- **Compromised user devices.** A malware-infected wallet leaks the user's keys and renders cryptographic privacy moot.

- **Operational security failures.** A user reusing the same payment addresses, leaking metadata through transaction timing, or interacting predictably with services that expose their identity reduces their practical anonymity.

- **Quantum cryptanalysis (long-term).** The Halo 2 proving system is not post-quantum: it relies on discrete-log assumptions that Shor's algorithm breaks. A future quantum adversary could retroactively break the soundness of historical Halo 2 proofs, which means a quantum adversary could in principle produce false witnesses for historical state transitions — but they cannot retroactively *change* committed history because the commitments themselves are SHA-3-based and post-quantum-secure. The implications and limits are addressed in subsection 7.9.3.

  Stealth address derivation and encrypted memo delivery use ML-KEM-768 (section 3.7) and are post-quantum-secure. This is a substantive change from earlier drafts of this whitepaper, which specified BLS12-381 ECDH for these surfaces; that scheme would not have survived quantum cryptanalysis. With the ML-KEM construction, historical privacy of shielded transactions is preserved against future quantum adversaries.

  The chain's signature layer is hybrid post-quantum (Principle VIII): identity layer (addresses, validator registrations, contract deployments) is post-quantum-secure via ML-DSA; ordinary transaction signatures use Ed25519 by default with ML-DSA available per-transaction.

- **Side-channel attacks on prover hardware.** When proofs are generated on devices vulnerable to side channels (timing attacks, power analysis, electromagnetic leakage), an adversary with physical access could potentially extract witness data. This is a hardware concern, not a protocol concern.

### 7.9.3 Quantum vulnerability of historical proof soundness

The protocol acknowledges that a future sufficiently large quantum computer could retroactively break Halo 2's discrete-log-based soundness assumptions. A quantum adversary could in principle produce a Halo 2 proof that verifies for a false statement, which would compromise the soundness of historical shielded-transaction proofs.

Importantly, this is a different concern from the quantum vulnerability addressed by ML-KEM (section 3.7). Two surfaces should be distinguished:

1. **Key agreement** (stealth addresses, encrypted memos) is post-quantum-secure via ML-KEM. Historical privacy — who sent what to whom — survives the quantum threshold because the encapsulation cannot be retroactively broken.

2. **Proof soundness** (Halo 2 attestations of correct state transition) is not post-quantum. A quantum adversary could in principle produce false proofs for historical transactions; combined with control of a sufficient validator set, this could be used to retroactively claim that invalid state transitions had been validly proven.

The chain's responses to the proof-soundness concern:

1. **Forward-only impact.** Quantum forgery of historical proofs requires also rewriting the chain's recursive proof history forward from the point of forgery. The recursive proof's commitments (via SHA-3 and KZG) are post-quantum-binding; an adversary cannot insert a forged proof into committed history without breaking the cryptographic anchors that bind history to the genesis state.

2. **Forward security of nullifiers.** Even if historical proof soundness is compromised, nullifiers prevent any reanalysis from triggering double-spends or other consensus violations on the running chain. The chain's integrity going forward is not at risk; only retrospective claims about historical statement validity.

3. **Migration to post-quantum proving.** When post-quantum zk proving systems mature into production-ready form (likely some years after the chain's launch), the protocol can be migrated. New shielded transactions would use the new system. Section 11 specifies the migration mechanism.

The honest assessment: a user requiring privacy *and* dispute-resolution-grade proof soundness that survives the next 25–50 years against nation-state-level adversaries with future quantum computers should not rely on Adamant's privacy layer alone. They should also use operational security measures (separate identities, careful counterparty selection, geographically diverse infrastructure) and consider the eventual post-quantum migration.

For the typical use cases — privacy of financial activity against contemporary adversaries, including most regulatory and commercial threat actors — the protocol's privacy is sound and substantial. Historical privacy (who-sent-to-whom) is post-quantum-secure via ML-KEM; only proof-soundness retrospective attack remains as a limitation, and even that is bounded by the post-quantum-binding commitments that anchor chain history.

## 7.10 Summary

The privacy layer is constructed from peer-reviewed primitives composed in well-understood patterns:

- **Notes and nullifiers** following Zcash Orchard's design, extended for multi-asset support
- **Stealth addresses** using ML-KEM-768 (FIPS 203) post-quantum key encapsulation, replacing the classical BLS12-381 ECDH that earlier drafts of this whitepaper specified — historical privacy is now post-quantum-secure
- **Halo 2 proofs** for shielded execution validity, leveraging Zcash's production implementation
- **View keys and sub-view-keys** for selective disclosure, structured for granular user control
- **Encrypted memos** using ML-KEM-768 for sender-to-recipient context, post-quantum-secure
- **Prover markets** for optional outsourcing of proof generation

The contribution is the integration: a system where these primitives compose cleanly with the object model, the smart-contract language, and the consensus mechanism (specified in section 8 next), to deliver a chain that is genuinely private by default, post-quantum-secure at the privacy-relevant key-agreement surfaces, and genuinely usable.
# 8. Consensus

This section specifies how Adamant's validators agree on the order of transactions, the state of the chain, and the validity of each state transition. It is the longest technical section in this whitepaper because consensus is where the protocol's correctness, performance, and credible-neutrality properties are simultaneously realised.

The protocol uses a **DAG-based Byzantine fault-tolerant consensus mechanism** with the following properties:

1. **Causal ordering, not total ordering.** Transactions that do not conflict are not ordered relative to each other. This is the property that makes 200,000+ TPS achievable.
2. **Sub-second finality.** Transactions touching only owned objects (no shared state) finalise in approximately 500 milliseconds. Transactions touching shared state finalise in approximately 1.5 seconds.
3. **Encrypted mempool integration.** Threshold decryption is performed by the same validator set that produces consensus, eliminating the latency of externally-coordinated decryption.
4. **Recursive proof of validity.** Every consensus epoch produces a recursive Halo 2 proof attesting to the validity of all included transactions. The chain's entire history is compressed into a constant-size proof verifiable on consumer hardware.
5. **No leader.** The consensus mechanism is leaderless; no single validator's failure can stall progress.
6. **Permissionless validation.** Anyone meeting the published technical and stake requirements can become a validator without permission from any party.

The mechanism draws on the Mysticeti protocol family (peer-reviewed at NDSS 2025), with modifications specific to Adamant's encrypted mempool, recursive verification, and credible-neutrality requirements. The Mysticeti reference is structural, not literal: Adamant's implementation is original code, written from scratch, informed by the published Mysticeti paper but adapted to our requirements.

## 8.1 Validators and stake

### 8.1.1 What a validator is

An Adamant validator is a node operator who participates in consensus by:

1. Receiving transactions from the network's mempool
2. Constructing and broadcasting consensus messages
3. Verifying other validators' messages
4. Contributing to threshold decryption of mempool transactions
5. Generating partial recursive proofs of epoch validity
6. Committing finalised transactions to chain state

Validators receive rewards (specified in section 10) for these contributions and face slashing penalties for provable misbehaviour.

### 8.1.2 Becoming a validator

A user becomes a validator by:

1. **Registering a validator object.** A transaction creates an on-chain `Validator` object containing the validator's identity (public keys) and operational parameters.
2. **Posting bonded stake.** The validator's `Validator` object is associated with a bonded stake — ADM tokens locked in a stake account. Stake serves as the validator's "skin in the game" and is at risk of slashing for misbehaviour.
3. **Joining an active set.** Once registered with sufficient stake, the validator is eligible to be selected for the active set in the next epoch boundary.

There is no minimum stake floor at the protocol level. Practically, very small validators are unprofitable because operational costs exceed their proportional rewards; the natural floor emerges from operational economics, not from a protocol-imposed barrier. This is consistent with Principle VII: validation is permissionless.

### 8.1.3 Active set

In any epoch, a subset of registered validators forms the **active set** — the validators currently responsible for consensus. The active set is dynamic, with a constitutional floor and a soft ceiling, and membership is **persistent**: once a validator is in the active set, they stay in until they fail liveness duties or voluntarily unbond.

**Floor: 7 validators.** This is the smallest active-set size at which Byzantine fault tolerance retains non-zero margin against correlated failures. At N=7, the BFT threshold tolerates f=2 Byzantine validators; one Byzantine validator combined with one offline validator still leaves the chain inside its safety bound. At N=4 (the absolute BFT minimum, tolerating f=1) any single Byzantine event combined with any single offline event would put the chain outside its safety bound, and real-world failures correlate (ISP outages, cloud-region failures, time zones, software bugs in shared dependencies, coordinated denial-of-service). The floor of 7 is the smallest size at which a single correlated event cannot push the chain past its safety threshold. This is a constitutional minimum: below 7 simultaneously-online validators, the chain halts on disagreement (subsection 8.7) rather than producing blocks under reduced safety.

**Soft ceiling: 75 validators.** This number is set by the throughput-target sizing argument. DAG-BFT communication cost grows quadratically in active-set size; per-validator bandwidth load grows linearly. At the 50,000 TPS minimum-throughput floor on residential-fibre hardware (commodity desktop, 1 Gbps fibre, ~100 ms typical wide-area latency), 75 active validators is the upper bound at which the per-validator bandwidth and verification cost remain tractable without exceeding the residential-fibre profile. Above 75, the chain either fails to deliver the throughput floor or forces the hardware tier up to VPS-grade, which excludes the residential-fibre operators the protocol is designed to include. The exact number is subject to empirical validation prior to mainnet (subsection 8.10).

**Selection: first-come-first-served with persistent membership.** When the count of registered, stake-eligible, currently-online validators is at or below the ceiling, every such validator is in the active set. When the count exceeds the ceiling, validators are admitted in **registration order**: the first 75 to register and meet the eligibility criteria fill the active set, and subsequent registrants enter a standby queue. A validator's active-set slot is held continuously as long as the validator continues to participate; the slot is released only when the validator is removed for liveness failure (subsection 8.1.5: failure to participate for more than 2 consecutive epochs while in the active set) or voluntarily unbonds. When a slot opens, the next standby validator in queue order is admitted to the active set automatically at the next epoch boundary. There is no forced rotation: a validator who registered early and continues to show up indefinitely retains their slot indefinitely.

**Why first-come-first-served.** This selection mechanism rewards *commitment and continuity* rather than hardware budget or stake size. A small home-fibre validator who registered on day 3 of the chain and has stayed online consistently for two years cannot be displaced by a wealthier latecomer with more stake or by a faster competitor with better hardware. The mechanism aligns with the chain's home-runnable-validator commitment: validators compete on showing up, not on raw performance. Stake-weighted-lottery and performance-tier selection mechanisms — both standard elsewhere — would, given enough time, push the active set toward whichever validators have the deepest hardware budgets, eroding the home-runnable property through selection pressure. First-come-first-served avoids that drift by structurally protecting incumbents who continue to participate.

**Re-entry after removal.** A validator removed for liveness failure may re-register immediately. Re-registration places the validator at the back of the standby queue; they re-enter the active set when their queue position is reached and a slot is open. There is no additional cooldown beyond the existing 28-day stake-unbonding period (which only applies to validators who actively unbond stake, not to those merely removed from the active set with stake intact).

**Sizing rationale.** The relationship between active-set size N, throughput, and hardware tier is roughly:

| N | Throughput floor | Hardware tier |
|---|-----------------|---------------|
| 200 | 200,000 TPS | VPS-grade ($300+/month) |
| 100 | 100,000 TPS | high-end consumer / low-end VPS |
| 75 | 50,000 TPS | residential-fibre commodity desktop |
| 30 | 25,000 TPS | residential-fibre commodity desktop with margin |
| 7–15 | low (limited by validator count, not bandwidth) | any commodity hardware |

The 75 ceiling at 50,000 TPS reflects the design choice to keep validators on residential-fibre hardware. Were Adamant to target VPS-grade validators, the ceiling could rise to 200 and the throughput floor could rise correspondingly; the protocol explicitly rejects that path because it sacrifices the participation profile the chain is designed to support.

**Throughput as a floor, not a target.** The 50,000 TPS figure is the chain's *minimum commitment* at design-target validator count, not a cap. Actual throughput in operation depends on the active set's aggregate hardware capability and current network conditions, and routinely exceeds the floor when validators run better-than-baseline hardware or when network conditions are favourable. The chain commits to delivering at least 50,000 TPS at N=75 on baseline residential fibre; the reality often delivers more. The figure is subject to empirical validation prior to mainnet.

**Future revision.** The ceiling of 75 is a soft ceiling set by current residential hardware and current consensus implementation maturity. As residential connectivity improves and consensus implementations are optimised, the ceiling may be raised in a future hard fork without violating constitutional commitments. The floor of 7 is a constitutional minimum and not subject to revision unless the BFT mathematics that justify it changes.

### 8.1.4 Stake delegation

Token holders who do not wish to operate validator hardware may delegate their stake to validators. Delegation is implemented at the protocol layer:

- A holder calls `delegate(validator_id, amount)`. Their tokens become part of the validator's bonded stake; the holder receives a proportional share of that validator's rewards (less the validator's commission).
- The holder may undelegate at any time, subject to a 28-day unbonding period during which the stake is still slashable but no longer earning rewards.
- The validator may not spend or claim the delegated stake; it remains the holder's property, locked under the consensus contract.

Delegation has two purposes: it allows non-operators to earn yield by sharing in validator rewards, and it allows validators to economically pass through delegated commitment to the chain. Note that under first-come-first-served selection (subsection 8.1.3), delegation does *not* affect a validator's probability of being in the active set — that is determined by registration order and continuity of online presence, not by total bonded stake. Delegation affects validator economics (more delegated stake → larger share of validator rewards) but not validator selection. This is a deliberate decoupling: the selection mechanism rewards commitment and continuity, while the economic mechanism rewards stake distribution.

### 8.1.5 Slashing

Validators who violate consensus rules face automatic slashing of their bonded stake. The protocol slashes for the following provable offences:

- **Equivocation:** signing two distinct consensus messages for the same DAG round. Slashing: 100% of stake.
- **Incorrect threshold decryption:** publishing a decryption share that does not correctly correspond to the validator's threshold key. Slashing: 5% of stake.
- **Liveness failure:** failing to participate in consensus for more than 2 consecutive epochs while in the active set. Slashing: 0.5% of stake plus removal from the active set.
- **Invalid proof:** producing a partial recursive proof that does not verify. Slashing: 10% of stake.

Slashed stake is burned (not redistributed). This ensures slashing is a pure cost, not a transfer to other validators that might be incentivised to provoke offences.

Slashing is automatic and on-chain: any party can submit evidence of equivocation (two signed messages) or invalid proof (the failing proof itself), and the protocol slashes the offending validator without requiring a vote. There is no governance review of slashing; the rules are mechanical.

### 8.1.6 Genesis activation gate

The chain self-activates the first time the active-set floor is met. Specifically, block 1 is produced the moment 7 validators are simultaneously registered, stake-eligible, and online; before that condition is met, the chain is dormant and produces no blocks. After that condition is first met, the chain produces blocks normally.

There is no human-in-the-loop activation. There is no recruited genesis cohort. There is no coordination event. The protocol activates itself the moment the floor is met, and the genesis-anchor validator (whichever validator's vertex deterministically anchors the first round, per the consensus VRF in subsection 8.6) initiates block production.

**Per-validator stake floor.** Each registered validator must post a minimum bonded stake (specified in section 10.7) to be eligible. There is no aggregate stake threshold for activation; the per-validator minimum prevents trivial-stake spam, and the activation gate is purely a count of simultaneously-online stake-eligible validators. This shape supports low-coordination launch: a founder plus a small group of independent early operators can bring the chain online without recruiting a 50-validator genesis cohort and without coordinating a DKG ceremony at genesis.

**Bootstrap mechanism.** During the period between protocol publication and the first time the floor is met, the chain has no blocks and no state. Validators who register during this period observe each other through the peer-discovery layer (section 9) but do not produce vertices. The first round begins automatically when the seventh validator's online presence is observed by the network.

**Honest framing.** The chain was designed and built by Ryan Geldart. The activation period is expected to include the designer and a small number of independent early operators who chose to run the binary. No party retains protocol-level powers post-genesis: no admin keys, no foundation treasury, no governance role for any pre-genesis party. The activation gate does not bind the future shape of the active set, which is determined dynamically by registration and on-line status (subsection 8.1.3).

### 8.1.7 Security tier disclosure

The chain commits a verifiable on-chain property indicating the current active-set size and the resulting security tier. Three tiers are defined:

- **Tier I (low).** Active set size N=7–14. The chain is operational and Byzantine-fault-tolerant within its size. Suitable for ordinary transfers, validator registrations, low-value transactions. Not suitable for high-value contracts, large-stake DeFi, mission-critical applications.
- **Tier II (medium).** N=15–29. The chain has crossed the threshold-encryption viability boundary (subsection 8.4). Suitable for most user transactions and moderate-value contracts. Not suitable for mission-critical applications.
- **Tier III (full).** N=30+. Full design-target security. Any application.

The tier is computed deterministically from the active-set size committed each epoch and is queryable as a constant-time chain-state property accessible to light clients. Tier transitions are automatic: as N crosses a tier boundary, the next epoch's tier signal updates.

**Use.** Wallets read the tier signal and adjust user-facing warnings and confirmation requirements accordingly. Applications can choose to gate features by minimum tier (a high-value DeFi contract may refuse to execute below Tier II, for example). The tier is advisory at the protocol level (the chain will execute valid transactions regardless of tier) but binding at the application level wherever applications opt to enforce it.

The Tier I → Tier II boundary at N=15 aligns with the threshold-encryption viability boundary in subsection 8.4: the chain transitions from time-lock encryption to threshold-encrypted mempool at the same point that the security tier moves from I to II. The Tier II → Tier III boundary at N=30 reflects the point at which the active set is large enough that BFT collusion attacks (requiring f+1 = 11+ Byzantine validators) are commercially infeasible.

**Honest framing.** The tier signal exists because the chain operates at variable scale and users deserve to know the current scale rather than assume the design-target scale from launch onward. The chain is honest about being weak when it is weak. This is a feature of credibly neutral launch, not a workaround.

## 8.2 Epochs and rounds

Consensus operates in two timescales:

- **Rounds:** the basic unit of DAG progression. Each round adds one layer to the DAG. Target round duration: 250 milliseconds.
- **Epochs:** a fixed number of rounds (144, approximately 36 seconds). Active set selection, threshold key generation, recursive proof aggregation, and reward distribution all occur on epoch boundaries.

The 250ms round target is chosen for sub-second finality: shared-state transactions finalise after 4–6 rounds (approximately 1–1.5 seconds), well below the target in Principle IV.

The 36-second epoch is chosen to balance:

- **Threshold key churn.** Shorter epochs mean more frequent DKG (distributed key generation) for threshold encryption, which is cryptographically expensive.
- **Active set responsiveness.** Longer epochs mean validators leaving the active set face longer delays before their changes take effect.
- **Reward distribution granularity.** Validators and delegators see rewards at epoch boundaries; users prefer finer granularity.

36 seconds is in the range used by Sui (24 hours per epoch with shorter checkpoint intervals), Cosmos chains (typically 6-12 hours), and other DAG protocols (1-60 seconds). The choice is calibrated to Adamant's specific cryptographic requirements.

## 8.3 The DAG structure

The protocol's consensus mechanism is structured around a **directed acyclic graph (DAG)** of validator messages. Each message references multiple parent messages from the previous round; the resulting graph encodes both the temporal progression of consensus and the pattern of validator agreement.

### 8.3.1 Vertices

A **vertex** is the unit of validator participation per round. Each validator in the active set produces one vertex per round. A vertex contains:

```
Vertex {
    author:           ValidatorId,
    round:            u64,
    parents:          Vec<VertexId>,    // references to previous-round vertices
    transactions:     Vec<Transaction>, // mempool batch
    threshold_shares: Vec<DecryptionShare>, // for previously-encrypted txs
    proof_witness:    PartialProofWitness,  // contribution to recursive proof
    signature:        BLSSignature,
}
```

Each vertex must reference at least 2/3+1 vertices from the previous round. This is the "quorum requirement" inherited from Mysticeti: validators must have seen and agreed with a supermajority of the previous round's vertices before proceeding.

### 8.3.2 The DAG grows by rounds

At round 1, validators broadcast vertices referencing the genesis state. At round R+1, each validator broadcasts a vertex referencing 2/3+1 of the round-R vertices. The graph grows in layers, with each round adding one layer.

Two vertices can be **causally compared**: vertex A is a *causal ancestor* of vertex B if there is a path from B back to A through parent edges. Two vertices that are neither's ancestor are *causally concurrent*.

This causal structure is what enables Adamant's parallel execution model (section 6.2.3): transactions in causally concurrent vertices can be executed in parallel; transactions in causally ordered vertices must be executed in their causal order.

### 8.3.3 Commit waves

Periodically (every 4 rounds, by default), the DAG enters a **commit wave**: a process by which a specific vertex is selected as the "anchor" for that wave, and the anchor's causal history is committed to the chain.

The commit wave proceeds as follows:

1. **Anchor election.** Using the consensus VRF, one vertex from a specific round is elected as the wave's anchor.
2. **Commit decision.** Validators determine, based on the DAG's structure, whether the anchor is "committed" (sufficient validators have built on top of it) or skipped.
3. **Causal commit.** If the anchor commits, all of its causal ancestors that are not already committed are committed in causal order.
4. **Transaction extraction.** The protocol extracts all transactions from the committed vertices, applies them in causal order, and updates chain state.

This is a simplified description of the Mysticeti commit rule. The full rule handles edge cases (multiple consecutive anchor failures, network partitions) with care; the published Mysticeti paper specifies it formally.

### 8.3.4 Why DAG instead of chain

A traditional blockchain proceeds linearly: each block extends a single chain. A DAG proceeds in parallel: many vertices per round, many parents per vertex.

The advantage is *throughput*. At any given moment, all validators in the active set are simultaneously producing vertices and broadcasting them. The chain's effective throughput is the *aggregate* of all validators' contributions, not the throughput of a single leader. With 75 validators each contributing transactions per round and 4 rounds per second, the protocol delivers the throughput floor of 50,000 TPS at design-target validator count under baseline residential-fibre conditions, with actual throughput exceeding the floor when validators run better-than-baseline hardware or under favourable network conditions.

The disadvantage is *complexity*. DAG protocols are harder to reason about than linear chains, harder to implement correctly, and historically have suffered from subtle correctness bugs. Mysticeti's contribution is a formally analyzed DAG protocol with proven safety and liveness properties; Adamant inherits this analysis.

## 8.4 Encrypted mempool: two-regime construction

Section 9 (Networking & Mempool) specifies the mempool layer in detail. This subsection specifies the consensus-level integration of the encrypted mempool. The protocol uses two distinct cryptographic constructions for mempool encryption — threshold encryption at design-target validator counts and time-lock encryption at low validator counts — with an automatic transition between them as the active set crosses a viability boundary.

### 8.4.1 Why two regimes are needed

Threshold encryption requires a coordinated active set running distributed key generation (DKG). The threshold parameters (t-of-N for some honest threshold t) need N≥15 to provide meaningful security: at N=4 a 2-validator collusion trivially breaks the scheme; at N=7 the margin is narrow and the cryptographic protocol is dominated by failure modes that don't exist at larger N. The chain therefore cannot rely on threshold encryption during the low-N period that follows low-coordination launch (subsection 8.1.6) and persists until enough validators register to cross the viability boundary.

Time-lock encryption (subsection 3.8) does not require coordination. A single validator can decrypt by performing sequential VDF computation. This works at N=1, N=4, N=7, and at any active-set size. It introduces 10–15 seconds of decryption delay (the cost of the sequential VDF) but does not require DKG, threshold key shares, or any inter-validator key agreement.

The chain uses time-lock encryption when N is low and threshold encryption when N is high. The transition is automatic; the boundary is observable from on-chain state; both regimes preserve mempool confidentiality from external observers, and both regimes provide MEV protection (with quantitative differences specified below).

### 8.4.2 Two regimes with hysteresis

The chain operates in one of two regimes per epoch:

- **Time-lock regime.** Active when the active-set size N satisfies N < 15 (the threshold-encryption viability boundary, aligned with the security tier I/II boundary in subsection 8.1.7). User transactions are encrypted to a Wesolowski VDF puzzle (subsection 3.8); the round anchor for each round (selected deterministically per subsection 8.6) computes the decryption and publishes the cleartext atomically with their vertex.
- **Threshold regime.** Active when N ≥ 15. User transactions are encrypted to the active validator set's threshold public key for the upcoming epoch (subsection 8.4.3). At the epoch boundary, validators publish decryption shares; transactions decrypt and execute when 2/3+1 shares are collected.

**Hysteresis.** To prevent the chain from flapping between regimes if N oscillates near the boundary, the transitions are hysteretic: the chain switches from time-lock to threshold at N ≥ 15; the chain switches from threshold to time-lock at N < 10. Between 10 and 14 (when the chain has previously been in threshold regime), the threshold regime continues; between 10 and 14 (when the chain has previously been in time-lock regime), the time-lock regime continues until N reaches 15.

**Transition mechanics.** When the chain is about to transition from time-lock to threshold regime, validators run DKG during the epoch boundary preceding the transition; the new threshold key is published with the start of the transition epoch; pending time-lock-encrypted transactions complete decryption normally; new transactions submitted during and after the transition use the threshold key. When the chain transitions from threshold back to time-lock regime (validators leaving), the previous epoch's pending threshold-decryption completes normally; new transactions use time-lock encryption.

### 8.4.3 The threshold regime

When N ≥ 15, the chain operates as the encrypted mempool integration originally designed:

**DKG at every epoch boundary.** The active validator set runs a Pedersen-style DKG over BLS12-381 to establish the new threshold key. The DKG produces:

- A **master public key** for the next epoch (used by users to encrypt their transactions)
- **Per-validator secret shares** (each validator holds a share of the master secret)
- **Verification keys** (allowing any party to verify decryption shares)

The DKG uses verifiable secret sharing with KZG commitments (section 3.9.2) to validate participants' contributions. DKG completion is a precondition for entering the new epoch: if the DKG fails (insufficient participation), the previous epoch is extended by one until it succeeds. This is rare in practice and the protocol handles it gracefully.

**Encryption for the next epoch.** Users encrypt transactions to the upcoming epoch's threshold key. Round R is in epoch E. Transactions submitted during epoch E are encrypted to the threshold key of epoch E+1; they are propagated, included in vertices, and ordered during epoch E. At the epoch E → E+1 transition, validators publish decryption shares; transactions decrypt at the start of epoch E+1. This adds approximately one epoch (36 seconds) of latency to encrypted transactions relative to transparent transactions; for use cases requiring lower latency, transactions may be submitted in transparent form (forfeiting encrypted-mempool protection).

**Decryption share generation.** When a vertex includes encrypted transactions, the proposing validator also includes their decryption shares for transactions ordered in the previous epoch. Once 2/3+1 valid shares are collected for a transaction, the protocol decrypts it and proceeds with execution. Share generation happens automatically as part of vertex production; the cryptographic cost is small (roughly one BLS pairing per transaction).

**MEV protection.** Threshold decryption is structurally MEV-resistant: no validator sees plaintext transaction contents during ordering, because decryption is gated on 2/3+1 share aggregation that happens after ordering is committed. Front-running and sandwiching are structurally impossible at this regime.

### 8.4.4 The time-lock regime

When N < 15, the chain operates with time-lock encryption based on the Wesolowski VDF (subsection 3.8). The construction includes two MEV mitigations that bound (but do not eliminate) the residual MEV surface relative to threshold decryption.

**Encryption.** Users encrypt transactions to the protocol's time-lock VDF puzzle. The puzzle's parameters (group, generator, time-lock parameter T) are committed at activation as chain-state constants (subsection 3.8.2). Encryption is local to the user; no key-agreement step is required.

**Decryption — round anchor only.** Time-lock VDF computation for a given round is bound to a single validator: the **round anchor**, selected deterministically by the consensus VRF (subsection 8.6) from the currently-online active set. Only the round anchor's decryption is accepted by the chain for that round. The anchor selection is unpredictable until the previous round commits (because the VRF input includes the previous round's aggregate output) and rotates uniformly across active validators over time.

**Mitigation A — Deterministic anchor rotation.** Because anchor selection is per-round and unpredictable until the previous round commits, no validator can self-select for front-running opportunities. Any individual validator gets the front-running opportunity only on rounds where they are the rotated anchor — roughly 1/N of rounds. At N=7 an individual validator's front-running opportunity is approximately 14% of rounds; at N=14, approximately 7%. This eliminates the "race-to-decrypt-first" dynamic that would exist if every validator could compete to publish decryption.

**Mitigation B — Decryption-publication binding.** The round anchor's decryption is published *atomically* with the transaction-ordering commitment in their vertex. The vertex is consensus-bound; it cannot be modified after publication. The anchor cannot include a self-favouring transaction in a *different* vertex that finalises before the decrypted transactions are visible, because the decryption itself is what makes the transactions visible — the publication is the moment of visibility. Equivocation (publishing two different vertices for the same round) is slashable per subsection 8.1.5 at 100% of the validator's stake. This eliminates the "include my own transaction in a competing vertex" MEV pattern.

**The honest residual.** Mitigations A and B do not eliminate all MEV opportunity. Specifically, the round anchor *can* choose the internal order of decrypted transactions within the vertex they publish. They cannot front-run cross-vertex, they cannot self-select for the opportunity, but they can reorder the transactions whose decryption they publish. This is a residual MEV surface that the threshold regime does not have.

**Bounded scope of the residual.** Three considerations bound the practical impact:

1. The opportunity is per-anchor-rotation (1/N of rounds), not per-transaction.
2. The opportunity is limited to ordering choices within a single vertex's transactions, not cross-vertex front-running.
3. Reordering attempts are detectable by external observers — the witness tier (subsection 8.7.2) flags suspicious anchor reordering; while the chain has no cryptographic slashing for this surface (because "natural ordering" is not cryptographically defined), reputational pressure is real.

**Honest constitutional posture.** The time-lock regime provides quantitatively weaker MEV protection than the threshold regime. Both regimes preserve transaction confidentiality from external observers; they differ in the residual surface available to the round anchor. Principle II is honestly framed (subsection 2.2) as MEV-protection that is structural at design-target N and bounded-but-non-zero at low N. The chain does not pretend the two regimes are equivalent in MEV protection; they are not.

### 8.4.5 Censorship resistance

The encrypted mempool's central property is *censorship resistance*: validators cannot selectively exclude transactions based on their content, because they cannot read the content until after ordering is committed. This holds in both regimes:

- **In the threshold regime,** validators see only encrypted blobs during ordering; selective exclusion based on content requires breaking threshold encryption.
- **In the time-lock regime,** the round anchor is the only validator who decrypts (and only after the VDF computation completes); other validators see only encrypted envelopes during ordering and cannot censor based on content.

This eliminates the structural conditions that enable:

- **Front-running.** A validator who could see transaction contents could insert their own transaction ahead. With encryption (either regime), validators see only ciphertext during ordering. The time-lock regime admits the bounded round-anchor reordering surface specified in subsection 8.4.4; the threshold regime does not.
- **Sandwich attacks.** Same mechanism as front-running.
- **Selective censorship.** A validator who could see transaction contents could exclude transactions to/from specific addresses. With encryption, validators see only encrypted blobs during ordering.

Censorship resistance is not absolute: a validator can refuse to include any transactions at all (a denial-of-service attack), and a colluding majority can refuse to include transactions from specific encrypted senders if they can identify the sender by other means (such as network metadata). The protocol mitigates these via:

- **Liveness slashing.** Validators who fail to include transactions face slashing (subsection 8.1.5).
- **Network-layer privacy.** The networking layer (section 9) uses onion routing and timing obfuscation to prevent network-metadata-based identification.

These are not perfect defences, but they substantially raise the cost of censorship.

## 8.5 Recursive proof generation

Adamant produces a **recursive proof of validity** for the entire chain at every epoch boundary. This is the cryptographic basis of phone-verifiable verification (Principle III).

### 8.5.1 What the proof attests to

The recursive proof, at any given epoch boundary, attests:

- The genesis state is a specific commitment (anchored at the protocol's genesis block).
- Every transaction in the committed DAG history was authorised, well-formed, and correctly executed.
- Every shielded transaction's Halo 2 proof verified.
- The chain state at the end of the current epoch is a specific commitment.

A verifier checking this proof learns: "the chain state at epoch N is X, derived correctly from the genesis state via valid transactions, and I do not need to trust any party to know this."

### 8.5.2 How recursion works

Halo 2 supports recursive proof composition: a proof of statement P1 can be verified inside a circuit, and the verification result becomes part of the witness for a new proof. Iterating this allows arbitrarily long histories to be compressed into a single proof of constant size.

The protocol's recursive proof at epoch N:
- Verifies the recursive proof from epoch N-1 (constant size, ~5-10 KB)
- Verifies all per-transaction proofs in epoch N (typically thousands)
- Outputs a new constant-size proof for epoch N

The total proof at any point in time is a single artifact, ~5-10 KB, attesting to the validity of the entire chain history.

### 8.5.3 The permissionless prover market

Generating the recursive proof is computationally expensive — much more expensive than verifying it. The protocol's earlier design conflated proof generation with consensus participation, requiring every validator to run GPU-class hardware capable of producing proofs at sub-second cadence. This forced validator hardware to a tier (datacenter-hosted GPU) inconsistent with the residential-fiber profile the chain commits to (subsection 8.1.3).

The protocol therefore separates proof generation into a **permissionless prover tier** distinct from validators. Validators do consensus, threshold/time-lock mempool decryption, and fallback proof generation (subsection 8.5.4). Provers do steady-state proof generation at the design-target cadence, in a competitive market.

**Operation.**

- Validators broadcast "proof needed for state X" requests as part of normal consensus operation.
- Provers race to produce valid Halo 2 proofs and submit them to validators.
- The first valid proof submission for a given state wins the per-proof bounty; losing proofs are discarded with no compensation.
- Validators verify submitted proofs cheaply (recursive SNARK verification is fast — subsection 8.5.5) and accept the first valid one.
- Verified proofs become part of chain state; the prover claims their bounty (subsection 10.4).

**Permissionless registration.** Provers register an on-chain identity (public key) and are eligible to submit proofs immediately. No stake required; no application; no approval; no Sybil resistance gate. Invalid proofs are simply rejected at validator verification, costing the prover their work-time but not the chain anything. The market self-disciplines through bounty competition.

**Bounded prover power.** Provers cannot:

- Censor transactions (they don't see plaintext mempool contents — they prove validator-produced state)
- Reorder transactions (validators determine ordering; provers prove the result)
- Halt the chain (if no prover submits, validators continue producing blocks; subsection 8.5.4's fallback handles proof gaps)
- Substitute for validators in consensus (provers cannot vote, cannot produce vertices, cannot affect block production)

Provers can:

- Refuse to produce proofs (other provers compete; fallback covers gaps)
- Compete on speed and cost (this is the intended dynamic)
- Operate anywhere geographically (no consensus-binding latency requirement)

This bounded-power posture is what makes permissionless proving safe.

**Hardware target.** Provers run GPU-class hardware (consumer RTX 4090 minimum; A100/H100 for serious operators) optimised for Halo 2 proof generation. There is no protocol-imposed minimum hardware spec — provers who can produce valid proofs faster or cheaper than competitors win bounties; provers whose hardware is insufficient simply don't win. Geographic location is unconstrained; provers can operate from anywhere with adequate compute and network.

**Compensation.** Per-proof bounty paid from the transaction-fee pool plus an optional small slice of issuance (specified in subsection 10.4). The bounty is calibrated to cover prover operating cost (GPU power, hardware amortisation) plus competitive margin. If proofs are consistently produced quickly, the bounty decreases (provers competing for under-priced work); if proofs lag and validator-fallback engages frequently, the bounty increases. The adjustment algorithm mirrors the EIP-1559 base-fee shape and is specified in subsection 10.4.

### 8.5.4 Validator-fallback for phone-verifiability

Principle III (phone-verifiable, subsection 2.3) commits the chain to producing recursive proofs at a cadence that makes light-client verification practical. Splitting proof generation off to a prover market makes this commitment dependent on a market that may not always be sufficient. The protocol therefore specifies a fallback: **if no prover submits a valid proof for a target state within a timeout window, the active validators take over proof generation themselves at a degraded cadence.**

**Cadence.**

- **Steady-state cadence (prover market healthy):** approximately one proof per block, sub-second cadence, produced by external provers on GPU-class hardware.
- **Fallback cadence (no prover bid within timeout):** approximately one proof per N blocks (N calibrated empirically; suggested starting value N=10, producing ~5-second cadence), produced by validators on their own consumer-desktop hardware.
- **Transition is automatic.** If the prover market becomes responsive again, the chain returns to steady-state cadence on the next successful prover submission. There is no governance involvement; the cadence is observable from on-chain state.

The fallback cadence is intentionally degraded — proofs every several seconds rather than every sub-second. This is what allows validators to do the work on the same residential-fiber consumer-desktop hardware they use for consensus, rather than requiring them to maintain GPU-class hardware as a backup. Phone-verifiability is preserved (proofs still exist, still verifiable on phones) but with longer freshness windows during fallback periods.

**Constitutional commitment.** The protocol commits to "phone-verifiable proofs are produced," not "phone-verifiable proofs are produced every sub-second." Steady-state cadence is the design target; fallback cadence is the floor below which the chain refuses to fall. This is what makes Principle III honest — phone-verifiability never depends on a market materialising; it depends only on proofs being produced, and the fallback mechanism guarantees this even if the prover market collapses entirely.

**Compensation alignment.** When validators generate fallback proofs, they receive the same per-proof bounty an external prover would have received. This avoids creating an incentive imbalance where validators would prefer the prover market to remain broken. The bounty calibration is the same in both cases, paid from the same fee pool, settled the same way (subsection 10.4).

**Fallback timeout.** The timeout before validators engage fallback is short — suggested 2–5 seconds — so that prover-market gaps are quickly absorbed by validator fallback rather than letting proof gaps accumulate. The exact value is calibrated empirically and committed as a chain-state parameter at activation.

**The market as optimisation, not requirement.** The prover market is an optimisation on top of the chain's baseline guarantees, not a requirement for them. The chain functions correctly without an external prover market — it operates at fallback cadence with proofs absorbed by validators. The market provides:

- Faster proof cadence (sub-second vs ~5-second)
- Lower proof costs at scale (specialised GPU operators produce proofs more cheaply per unit than validators using fallback hardware)
- Market discipline on proof costs (competition keeps bounty calibration honest)

Without the market, the chain operates at fallback cadence indefinitely. Light-client verification still works; UX is somewhat worse (longer freshness windows); the chain is not broken.

### 8.5.5 Verifier requirements

A verifier — anyone wishing to confirm the chain's validity without trusting validators or provers — needs:

- The chain's genesis commitment (in the protocol's genesis specification, section 11)
- The current recursive proof (publishable from any validator, prover, witness, or archive node)
- A Halo 2 verifier (open-source, runnable on any modern hardware)

Verification time is approximately 50–200 milliseconds on a modern smartphone, regardless of how many epochs of history exist or whether the proofs were produced by external provers or by validator-fallback. This is the property that makes the protocol genuinely "phone-verifiable."

## 8.6 The consensus VRF

Several consensus operations require deterministic randomness: active set selection, anchor election, leader rotation. The protocol provides this through a **consensus VRF** (Verifiable Random Function).

### 8.6.1 Construction

The VRF is constructed from BLS signatures: each validator's BLS signature over a specific input is deterministic (a property of BLS) and unpredictable to anyone without the validator's secret key (the random-oracle assumption). Aggregating BLS signatures from a quorum of validators produces a value that is unpredictable to anyone who cannot compromise a majority of validators.

VRF inputs:

- For active set selection at epoch boundaries: the previous epoch's recursive proof commitment.
- For anchor election within an epoch: the previous round's aggregate VRF output, plus the round number.

VRF outputs are publicly verifiable: anyone can check that the published output is correct given the input and the validators' public keys.

### 8.6.2 Why this matters

Randomness manipulation is a known attack vector in proof-of-stake systems. An adversary who can predict or influence randomness can game leader election (becoming leader more often than their stake warrants), select favourable transaction orderings, or exclude themselves from validator slashing.

The BLS-based aggregate VRF makes manipulation expensive: an adversary must compromise a supermajority of validators to influence a single output, and even then the manipulation is detectable (the output would not match the published BLS signatures' aggregate). This raises the cost of manipulation to approximately the cost of compromising the chain itself.

## 8.7 Consensus safety, liveness, and the witness tier

The consensus mechanism's correctness is established by the following theorems, derived from the Mysticeti analysis with adaptations specific to Adamant's modifications:

**Theorem 1 (Safety).** If fewer than 1/3 of validators by stake are Byzantine, the chain never commits two conflicting transactions. (No double-spends, no fork ambiguity.)

**Theorem 2 (Liveness).** If fewer than 1/3 of validators by stake are Byzantine and network partitions are eventually resolved, the chain commits transactions at a rate determined by network conditions, with expected delay bounded above by a constant — *except during periods when the active set is below the constitutional floor of 7, in which case the chain halts rather than fork (subsection 8.7.1).*

**Theorem 3 (MEV protection).** No validator can extract MEV-style value at the level threshold encryption prevents, except for the bounded intra-anchor reordering surface during the time-lock regime (subsection 8.4.4). Specifically: in the threshold regime (N ≥ 15), validators cannot observe transaction contents during ordering and front-running/sandwiching is structurally impossible. In the time-lock regime (N < 15), the round anchor for a given round can choose the internal order of decrypted transactions within their vertex, but cannot front-run cross-vertex (Mitigation B) or be self-selected (Mitigation A); intra-anchor reordering is detectable by witnesses and disincentivised by reputational pressure.

These theorems rely on:

- BLS signature soundness (subsection 3.4.3)
- Halo 2 soundness (subsection 3.9.1)
- KZG commitment binding (subsection 3.9.2)
- ML-KEM security (subsection 3.7) for key agreement
- Threshold encryption security (subsection 3.6) for the threshold regime
- Wesolowski VDF correctness (subsection 3.8) for the time-lock regime
- The honest-majority assumption (≥2/3 of stake non-Byzantine in the active set)

The proofs are not reproduced here; they appear in the Mysticeti paper (NDSS 2025) and in the supplementary cryptographic literature for the modified components. Adamant's deviations from Mysticeti are localised; their effect on the original proofs is marginal and the proofs are reconstructed in supplementary material to the reference implementation.

### 8.7.1 Halt-on-disagreement at low N

When the active set is at or near the constitutional floor (N=7–14), the chain halts on disagreement rather than forking. If quorum cannot be reached for a round (validators offline, network partition, conflicting proposals), the chain pauses until quorum is restored. Safety is preserved (no double-spends, no forks). Liveness is weak at low N — this is an honest cost, not a hidden one.

**Liveness math.** At N=7 with independent 99% per-validator uptime, the probability that at least 5 validators (the 2/3+1 quorum threshold) are simultaneously online is approximately 99.97%. At a 250ms round target this implies expected halt frequency of approximately one halt per several days lasting a few rounds. Real-world correlation (ISP outages, time-zone-correlated downtime, software bugs in shared dependencies, coordinated DDoS) will increase actual halt frequency above what independence assumes; the chain should expect occasional halts of several rounds in its first months at low N.

This shape is structurally similar to Bitcoin's early months: occasional gaps, slow growth, weak guarantees. The chain is honest about being weak when it is weak.

**Pending transactions during halt.** Transactions in the encrypted mempool when a halt begins remain in the mempool until quorum is restored. Time-lock-encrypted transactions whose VDF computation completes during the halt have their decryption deferred until consensus resumes; threshold-encrypted transactions whose ordering is in flight remain ordered after quorum returns. No transaction loss occurs during halts.

**Halt detection and recovery.** The chain's halt state is observable in on-chain state — the security tier disclosure (subsection 8.1.7) and the round timing parameters make halts visible. Light clients seeing extended gaps in proof production should consult tier disclosure; wallets should display halt state to users transparently. Recovery is automatic: when quorum returns, consensus resumes from where it paused.

### 8.7.2 The witness tier

The protocol specifies a third participation tier alongside validators and provers: **witnesses**. Together with service nodes (subsection 9.10), witnesses complete the protocol's four-tier participation model. Witnesses run on phones and basic laptops, performing four roles:

- **Role A — Cryptographic attestation.** Witnesses produce signed attestations for valid vertices, valid proofs, and valid state transitions. Attestations are used for light-client verification, cross-chain bridge integrity, and dispute resolution.
- **Role B — Data availability sampling.** Witnesses sample chain data (random vertex requests, random transaction requests) and verify availability. Failed samples flag potential data-availability attacks.
- **Role C — Recursive proof verification.** Witnesses verify the recursive proofs produced by the prover market or by validator-fallback proof generation (subsection 8.5.4). Verification is cheap; redundant verification across many witnesses provides defence-in-depth against malicious provers and against validator-fallback errors.
- **Role D — Fraud and reordering detection.** Witnesses watch for invalid state transitions, double-spending attempts, validator misbehaviour, and suspicious anchor reordering during the time-lock regime (subsection 8.4.4). Detected fraud triggers slashing claims; suspicious reordering triggers reputational signals.

**Hardware target.** Witnesses run on modern smartphones (Role B at low duty cycle; Roles A and C tractable), basic laptops (full role suite tractable), or residential desktops (over-provisioned). Witnesses do not require GPU acceleration, datacenter-class network, or high availability.

**Registration.** Witnesses register an on-chain identity (public key) and a small Sybil-resistance stake (suggested 100 ADM; specific amount TBD by economic specification). The stake is forfeit only on slashable offences (false attestations corroborated by other witnesses); routine non-participation simply forgoes compensation. Witness registration is permissionless; no application, approval, or capability gate.

**Compensation.** Witnesses receive compensation per role (Role A and Role C scale with proof/attestation volume; Role B is rate-paid; Role D bonuses are conditional on corroborated flags). Specific calibration is in section 10. Compensation is sufficient to incentivise participation but small enough to not displace validator economics; per-witness compensation decreases as witness population grows, distributing fixed reward pool across more participants.

**Cross-tier dependencies (honest framing).** Witness utility depends on tiers witnesses verify: Role C depends on proofs being produced (the validator-fallback per subsection 8.5.4 ensures Role C operates at the cadence proofs are produced — fast during steady state, slower during fallback, but never absent); Role D operates reputationally rather than via cryptographic slashing for the intra-anchor reordering surface. The chain is honest about this: witnesses provide defence-in-depth and broaden participation, but their effectiveness is co-determined with the integrity of the tiers they verify, not independent of them.

## 8.8 Failure modes

The consensus mechanism handles a range of partial failures gracefully. The following are documented because they are the operational realities validators encounter:

- **Single-validator crash.** Other validators continue without interruption. The crashed validator's contributions for the affected rounds are missing but the DAG progresses normally if 2/3+1 validators remain.
- **Network partition.** If the network splits into pieces each containing fewer than 2/3 of stake, no piece can commit. Once the partition heals, both sides reconcile by adopting the higher-stake side's history.
- **Active set turnover during DKG.** If the DKG fails partway through (e.g. validators dropping out during the protocol), the previous epoch is extended and the DKG retries. Repeated failures indicate a serious operational problem and trigger an alert, but do not violate safety.
- **Mass coordinated failure.** If more than 1/3 of stake fails simultaneously (e.g. due to a software bug affecting one client implementation), liveness is lost until validators recover. Safety is preserved: no incorrect state is committed.

Recovery procedures are specified in the operational documentation that accompanies the reference implementation, not in this section.

## 8.9 Light clients and verification

Anyone may run a **light client** that follows the chain without storing full state. Light clients receive the recursive proof at each epoch boundary and verify it; this is sufficient to know the current state commitment without trusting any validator.

Light clients can also verify *specific* claims:

- "Account X has a balance of at least Y." Verified via Merkle path into the state commitment, plus the recursive proof.
- "Transaction T was included in epoch E." Verified via the epoch's transaction commitment.
- "Object O exists with current state S." Verified via the state commitment.

The protocol's commitment to phone-verifiable verification (Principle III) means light client verification is a first-class operational mode, not an afterthought. Wallets `SHOULD` operate as light clients by default, syncing only the recursive proof and Merkle paths for the user's own state.

## 8.10 Comparison to alternatives

For context, here is how Adamant's consensus compares to the alternatives that were considered:

- **Single-leader BFT (Tendermint, HotStuff, Sui's pre-Mysticeti protocol).** Simpler but throughput is bounded by the leader's resources. Adamant rejects this for performance reasons.

- **Proof-of-Work (Bitcoin, Ethereum pre-Merge).** Strong simplicity but unsuited to sub-second finality and incompatible with Adamant's encrypted mempool design.

- **Other DAG protocols (Narwhal/Bullshark, Aleph).** Adjacent to Mysticeti, with similar performance characteristics. Mysticeti was chosen as the closest fit because of its fast-path single-vote commit (in optimistic conditions, transactions can finalise in 250ms via the fast path).

- **Asynchronous BFT (HoneyBadgerBFT, Dumbo).** Provably safe under arbitrary network conditions but with higher communication overhead. Adamant prefers Mysticeti's partial-synchrony assumption (which requires the network to eventually deliver messages) because it is realistic for internet conditions and enables better performance.

The choice of Mysticeti-derived consensus reflects Adamant's prioritisation of the throughput-finality-decentralisation triangle at production scale.
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

The chain's bandwidth requirement at 50,000 TPS with mostly-shielded transactions is approximately 150 MB/sec aggregate across all validators. Per-validator bandwidth is approximately 2-4 MB/sec, well within consumer-grade home-internet capabilities.

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

## 9.10 Service-node infrastructure market

The protocol's networking design enables a permissionless market for light-client infrastructure: nodes that serve recursive proofs, Merkle paths, and state queries to wallets that prefer not to maintain full state themselves. This subsection specifies the protocol-level standardisation that makes the market liquid; the economics of the market are between participants, not protocol-funded.

### 9.10.1 Motivation

Per subsection 9.1, light clients maintain only the recursive proof and Merkle paths to specific state of interest. This is the cryptographically lightest mode of participation in the chain — verification time is approximately 50-200 milliseconds on a modern smartphone (subsection 8.5.5), and storage requirements are minimal.

A light client must, however, obtain its data from somewhere. Two paths exist:

1. The wallet operates as a full node itself, maintaining the data it queries. This works but requires significant storage and bandwidth for what is otherwise a lightweight client.
2. The wallet queries another node that maintains the data and serves it on request. This is the common pattern; it is how Ethereum wallets typically interact with Infura, Alchemy, or QuickNode.

The second path's risk is centralisation: if all wallets query the same handful of providers, those providers become a privileged infrastructure layer that can observe user activity, censor specific queries, or fail in ways that affect the entire ecosystem.

The protocol's response is to standardise the query format and registration mechanism such that *any* node can serve light-client queries, allowing many small operators (including phone-based operators) to participate alongside any large infrastructure providers that emerge. The market itself is permissionless and competitive.

### 9.10.2 Service node role

A **service node** is a node that:

- Maintains the chain state required to answer light-client queries (recursive proofs, Merkle paths, transaction inclusion proofs)
- Exposes a standardised query/response interface over libp2p
- Optionally registers its availability and pricing in a discovery topic
- Earns fees from the parties that pay for its services (specified in subsection 9.10.5)

Service nodes are not validators, provers, or witnesses. They do not participate in consensus, do not generate recursive proofs (provers do that, subsection 8.5.3), do not produce attestations or perform fraud detection (witnesses do that, subsection 8.7.2), do not have stake at risk, and do not earn from issuance. Their role is purely informational: serving public, cryptographically-verifiable data to clients that prefer not to maintain the data themselves. The protocol's full participation model has four bounded-power tiers — validators, provers, witnesses, service nodes — each with a distinct role profile and compensation pattern; service nodes are the lightest tier in operational terms (no stake, no slashing, no protocol-level compensation flow), serving infrastructure rather than security.

A node may simultaneously occupy multiple roles; the roles are independent and operate on independent infrastructure. The most common combinations are likely to be validator+service-node (a validator that also serves light-client queries) and witness+service-node (a phone-class operator providing both attestation and infrastructure). Prover hardware (GPU-class) is typically distinct from service-node hardware (state-storage-class) and the roles are unlikely to combine economically. Phone-based service nodes are the design's primary intended audience for the service-node tier, though the role is open to any hardware capable of maintaining the required state.

### 9.10.3 Standardised query format

Service-node queries use a libp2p protocol identifier `/adamant/service-query/v1` with a defined message schema. The schema covers:

- **State queries.** Given an account address or object ID, return the current value plus a Merkle path to the state commitment.
- **Inclusion queries.** Given a transaction identifier, return the transaction plus a Merkle path to its containing epoch's transaction commitment.
- **Recursive proof queries.** Return the recursive proof for a specified epoch.
- **Range queries.** Given a stealth-address scan range and time window, return all matching note commitments (subject to per-node policy on data volume).
- **Subscription queries.** Establish a streaming subscription for events matching a specified filter, paid per-event.

Each query type has a defined request schema, response schema, and error format. The full schema is specified in the reference implementation; this subsection documents the categories rather than the specific bytes.

### 9.10.4 Service-node registration

A service node may register its availability via a libp2p gossipsub topic `/adamant/service-nodes/v1`. The registration message contains:

- The node's libp2p endpoint
- Its supported query types
- Its fee schedule per query type
- Optional metadata (geographic region for latency-sensitive selection, supported query subset, archive node status)
- A cryptographic signature binding the registration to the node's identity

Registration is permissionless. Any node may register. Wallets crawl the topic to build their service-node list and select providers based on advertised criteria (latency, fee, supported queries, geographic preference).

The protocol does not maintain a central registry, does not vet service nodes, and does not provide a "trusted" service-node list. The market is open and competitive.

### 9.10.5 Payment

Service-node payments occur through one of three patterns. The protocol enables all three; nodes and clients select the pattern that suits their relationship.

#### Pattern A: Direct wallet-to-node payment

A wallet pays a service node directly via the protocol's payment-channel infrastructure. The wallet opens a channel with a small ADM deposit, queries are paid as off-chain channel updates, and the channel settles on-chain when closed. This pattern is appropriate when wallets have ADM available and want direct relationships with service nodes.

#### Pattern B: Validator-funded service

A validator funds service-node operation as part of providing infrastructure to their delegator base. The validator pays service nodes (per query, per period, or per uptime, by mutual agreement) from their own commission revenue; delegators of that validator receive service-node access bundled with their delegation, paying nothing additional. This pattern is appropriate for validators competing for delegators on the basis of delegator experience quality (subsection 10.5.5).

#### Pattern C: Application-paid service

An application or wallet developer pays service nodes on behalf of their users — analogous to the sponsored-fee pattern in subsection 10.4.5. This pattern is appropriate for consumer applications that want to abstract infrastructure costs away from end users.

The protocol provides standard smart-contract patterns implementing each payment mode in the standard library (subsection 6.5). Service nodes and clients choose patterns by mutual agreement; the protocol does not privilege one over another.

### 9.10.6 Reputation and verification

Service nodes serve cryptographically-verifiable data. A service node cannot lie about chain state without producing a Merkle path or recursive proof that fails verification — the client detects invalid responses immediately and refuses payment.

The protocol provides a **delivery receipt** primitive: a signed acknowledgement from the client to the service node confirming that a query was served correctly. Service nodes accumulate delivery receipts as evidence of reliable operation. Third parties may build reputation systems on top of these receipts; the protocol does not specify or operate a reputation system itself.

A service node may operate in two modes, advertised in their registration:

- **Verifying mode:** The service node verifies recursive proofs and Merkle paths before serving them. This adds a small marginal cost per query but provides an additional check against malformed data propagating through the network.
- **Relay mode:** The service node forwards data without independent verification. This is cheaper to operate but offers no observability beyond the wallet's own verification.

Wallets select between modes based on their trust posture; verifying nodes typically charge slightly higher fees.

### 9.10.7 Relationship to onion-routing relays

Subsection 9.4.2 specifies that onion-routing relays support transaction privacy but are not protocol-rewarded. The same service-market mechanism extends naturally to relays: a wallet (or a relay-using application) may pay relays via the same payment patterns described above. The protocol's standardisation extends to relay registration and payment formats; the economics are between participants.

### 9.10.8 What this market does and does not provide

**It does provide:**

- A pathway for phone-based operators to contribute to the network's infrastructure and earn fees from real demand
- Standardisation that makes the market liquid (any wallet can query any service node; any validator can fund any service node)
- An alternative to centralised RPC providers without compromising the lightweight-client model
- Natural amplification of the slashing-evidence-submission mechanism (subsection 8.1.5): service nodes operating in verifying mode are positioned to detect protocol violations as a side effect of their service work

**It does not provide:**

- A guarantee that service nodes will earn meaningfully — that depends on demand materialising
- A new economic recipient at the protocol layer — service nodes are paid by other participants, not by the protocol
- Consensus participation — service nodes do not vote, propose, or sign consensus messages
- Privileged access to private data — service nodes see only the public, cryptographically-verifiable data the chain commits to
- Censorship resistance for queries — a wallet whose chosen service node refuses to serve them must select another service node; multiple competing nodes are the protection

The market is an enhancement, not a constitutional core property. The chain functions correctly whether or not the service-node market materialises. If no service nodes exist, wallets fall back to running their own full nodes or using whatever centralised RPC providers exist; the protocol works either way. The market's value is in providing an alternative pathway for participation and a check on centralisation pressure.

### 9.10.9 Scope and operational dependencies

The reference implementation includes service-node software as a deployment target distinct from validator software. The service-node software is intentionally lightweight, with hardware requirements compatible with consumer-grade phones and laptops. Specific hardware and storage requirements are documented in the reference implementation's operational guidance, not in this specification.

Service-node operation is voluntary and unincentivised at the protocol layer. Whether a healthy service-node ecosystem develops depends on:

- Wallets choosing to use service nodes rather than running full nodes or using centralised RPC providers
- Validators choosing to fund service nodes as part of competing for delegators
- Operators finding the work economically worthwhile at prevailing fee levels
- Service-node software being usable enough that operators can run it without specialised expertise

The protocol provides the substrate; the ecosystem develops the infrastructure on top.
# 10. Economics & Incentives

This section specifies the protocol's economic model: the native token, the genesis pool and launch mechanics, the post-launch issuance schedule, the fee mechanism, and the staking and reward economy. These specifications are part of the consensus rules; they cannot be modified by any on-chain mechanism (Principle I).

The economic model has three goals:

1. **Sustainable security.** Validator rewards must be sufficient to attract honest participation in perpetuity, even at modest network usage.
2. **Real value accrual.** The native token's value must be tied to actual network usage, not to speculation. Fee burn under usage achieves this.
3. **Credibly fair distribution.** No premine, no founder allocation, no privileged early holders. Distribution begins at genesis through mechanisms anyone can participate in.

## 10.1 The native token

The protocol's native token is provisionally named **ADM**. The name is provisional because community input is appropriate before final selection; the name is not consensus-critical and a final name will be selected before genesis through a public process. For specification purposes, ADM is used throughout.

### 10.1.1 Properties

ADM is:

- **Divisible.** The smallest unit is `1 base unit = 10^-9 ADM` (i.e., 9 decimal places). This is finer granularity than fiat currencies and supports micropayments at the protocol's intended cost level.
- **Fungible.** All ADM units are interchangeable. The protocol does not distinguish ADM by origin, age, or transaction history.
- **Used for fees.** All transaction fees are paid in ADM.
- **Used for staking.** All validator stake is denominated in ADM.
- **Native, not contract-defined.** ADM exists at the protocol layer, not as a smart contract. This makes ADM unforgeable, unstoppable, and free of contract-level risks (no rug pulls, no contract upgrades, no admin functions).

### 10.1.2 Total supply

ADM has **no fixed total supply**. The total supply is determined by the launch-phase genesis pool (subsection 10.2), the post-launch issuance schedule (subsection 10.3), net of fee burn (subsection 10.4). Under typical post-launch usage, the supply is approximately stable or slowly deflating; under heavy usage, it deflates measurably.

This is a deliberate choice. Fixed-supply tokens (Bitcoin's 21M cap) provide a strong narrative anchor but eventually face the question of how to reward validators when the issuance schedule terminates. Adamant's continuous-issuance-with-burn model resolves this: validator rewards are sustainable indefinitely, while burn ties supply to usage.

During the launch phase, the protocol distributes a fixed genesis pool of 100,000,000 ADM via the mechanisms specified in subsection 10.2. The launch phase ends when the pool is fully claimed or, at latest, five years from genesis. After the launch phase, post-launch issuance per subsection 10.3 takes effect. The launch phase is a one-time event; the post-launch regime is perpetual.

The expected long-term equilibrium: in steady state (post-launch), fees burned approximately equal new issuance, producing rough supply stability with mild deflationary pressure under above-average usage.

## 10.2 Launch mechanics

The protocol's launch is structured around a **genesis pool**: a fixed quantity of 100,000,000 ADM that exists at protocol launch and drains via two acquisition paths over a launch phase that ends when the pool is exhausted or, at latest, five years from genesis. The launch phase is followed by an operational phase governed by the issuance schedule (subsection 10.3) and fee mechanisms (subsection 10.4) that operate in perpetuity thereafter.

This architecture differs from a pure burn-launch (the original design considered for Adamant) and from mechanisms used by other proof-of-stake chains. The reasoning for this choice is given in subsection 10.2.5.

### 10.2.1 What does not happen at genesis

At genesis, no party — including the protocol's original implementers, contributors, advisors, hypothetical investors, validators, or any external entity — receives any token allocation, holds any privileged claim on the genesis pool, or possesses any mechanism to extract value from the launch phase outside the public acquisition paths defined in subsection 10.2.3.

Specifically, the genesis state contains:

- The genesis recursive proof anchor
- The initial protocol parameters (gas costs, validator set size, etc.)
- The list of bootstrap node addresses
- The Powers of Tau ceremony reference
- The genesis pool counter, initialised to 100,000,000 ADM, accessible only via the protocol-defined acquisition paths
- Zero ADM allocations to any account, address, contract, or party

There is no:

- Founder allocation
- Foundation treasury
- Pre-mine for development funding
- Early-investor allocation
- Validator set "starter pack"
- Ecosystem fund
- Marketing fund
- Custodian holding the genesis pool
- Multisig or governance mechanism controlling the pool's release
- Privileged address with any access to the pool other than via the public acquisition paths

The genesis pool is a **protocol-level construct**, not an allocation. It does not belong to any party. No party can transfer it, hold it, earn returns from it, or extract value from it outside the public claim mechanisms specified in subsection 10.2.3. It is mechanically equivalent to a counter that decrements as participants claim tokens through the defined paths, and that the protocol cannot otherwise reduce, increase, or redirect.

Anyone holding ADM at any point after genesis acquired it through one of the mechanisms specified below.

### 10.2.2 The genesis pool

The genesis pool is a fixed quantity of 100,000,000 ADM that the protocol may issue during the launch phase via the acquisition paths in subsection 10.2.3. The pool is partitioned in policy into two sub-counters:

- **Burn-allocated:** 70,000,000 ADM, drained exclusively via burn-to-mint claims (path A in subsection 10.2.3).
- **Validator-allocated:** 30,000,000 ADM, drained exclusively via validator block rewards (path B in subsection 10.2.3).

Each sub-counter decrements monotonically as claims occur through its respective path. Neither sub-counter can be incremented, transferred between, or accessed through any other mechanism. The pool is exhausted when both sub-counters reach zero.

The 70/30 partition prevents a failure mode where validator rewards alone could exhaust the pool with minimal burn participation, producing extreme concentration in the validator set. The reference allocation is calibrated so that, under expected validator-set sizes and target launch durations, the validator-allocated portion drains over a similar time horizon to the burn-allocated portion under reasonable burn participation. The specific partition is subject to calibration prior to mainnet.

The pool size of 100,000,000 ADM is chosen to:

- Be drainable within a reasonable launch period (years, not decades) at expected participation rates
- Be large enough that no single participant can dominate, given the per-address claim cap (subsection 10.2.3)
- Sit within familiar token-supply orders of magnitude (Bitcoin's eventual cap is 21M; Ethereum's circulating supply is approximately 120M)

The specific size, like the partition ratio, is subject to calibration prior to mainnet based on simulation analysis of participation distributions and drain rates.

### 10.2.3 Acquisition paths

Two paths drain the genesis pool. Both run concurrently from genesis day one. Both are open to any participant without permission, registration, or identity verification.

#### Path A — Burn-to-mint

A participant burns external crypto at a verifiably unspendable address on the source chain. The protocol observes the confirmed burn via light-client verification of source-chain block headers (the verification mechanism is specified in section 11) and mints the corresponding quantity of ADM to the participant's claim address from the burn-allocated sub-counter.

The burned external crypto is permanently destroyed. No party — including the protocol — receives, custodies, or holds any claim on the burned assets.

Supported source chains at launch:

- Bitcoin (BTC), via burn to a verifiably unspendable address derived from a known public construction
- Ethereum (ETH), via burn to the Ethereum null address or a verifiably unspendable contract
- Additional source chains may be supported per the protocol's specification at launch

The conversion rate is constant throughout the launch phase. Reference rates (subject to calibration prior to mainnet):

- 1 BTC burned → X ADM (X to be calibrated)
- 1 ETH burned → Y ADM (Y to be calibrated)

Conversion rates across source chains are defined in USD-equivalent terms at protocol design time, not at burn time. This avoids gaming based on currency-fluctuation arbitrage during the launch window.

**Per-address claim cap.** A single claim address cannot accumulate more than a defined fraction of the burn-allocated sub-counter via path A. The cap grows over time:

- Months 0–1 from genesis: 1% of the burn-allocated sub-counter
- Months 1–3: 2%
- Months 3–6: 4%
- Months 6–12: 8%
- Month 12+: no cap

The cap applies to total cumulative claims by a single address across the launch phase. The cap is per-address rather than per-identity; the protocol cannot enforce identity. A determined adversary can fragment claims across many addresses to circumvent the cap, but doing so requires managing many wallets, signing many separate claim transactions, and incurring per-claim friction. The cap raises the cost of opportunistic concentration without claiming complete sybil resistance.

**Full-or-nothing burn semantics.** A burn-to-mint claim either fully succeeds or fully reverts. If a claim would drain the burn-allocated sub-counter past zero, the claim reverts and the burner's external crypto is not destroyed (the source-chain transaction also reverts, or, if the burn is irreversible on the source chain, the claim is rejected and the source-chain assets are stranded — implementation detail per source-chain integration). If a claim would exceed the per-address cap, the same revert applies.

#### Path B — Validator block rewards

Validators that participate in consensus receive block rewards minted from the validator-allocated sub-counter. Each block proposed by a validator generates a reward; the reward is calibrated such that the validator-allocated 30,000,000 ADM drains over the target launch duration under expected validator-set sizes.

Reference reward sizing (subject to calibration prior to mainnet):

- Target launch duration: approximately two to three years
- At 8-second blocks and an active set near the ceiling (75 validators), this implies a per-block reward in the order of single-digit ADM

The validator path serves the audience that wishes to participate by securing the network rather than by burning external value, and solves the proof-of-stake bootstrap problem: early validators can earn stake by validating, not exclusively by burning external assets.

The validator-allocated sub-counter is not subject to the per-address cap of path A. Validator concentration concerns are addressed by the partition itself (the validator-allocated portion is bounded at 30% of the pool) and by the consensus mechanism's stake-weighting and slashing rules (section 8).

#### Acquisition outside paths A and B

Once tokens exist in circulation, holders can transfer them freely. Centralised exchanges, decentralised exchanges, OTC desks, and peer-to-peer transfers will emerge organically and are not specified by the protocol.

Anyone wishing to acquire ADM may do so through these secondary markets in the same manner as for any other cryptocurrency. The protocol does not provide a "buy from the protocol" mechanism. Market-based acquisition is the standard pattern in functional cryptocurrencies and Adamant follows it.

### 10.2.4 Phase transition

The chain operates in **launch phase** until the genesis pool is exhausted or the time cap is reached, then transitions to **operational phase** automatically.

#### Trigger conditions

Phase transition occurs when either of the following is true:

- **Pool exhaustion:** Both sub-counters (burn-allocated and validator-allocated) reach zero.
- **Time cap:** Five years have elapsed since genesis.

Whichever condition is met first triggers the transition.

#### Behaviour at transition

When the transition triggers, the following changes take effect on the next block:

- Path A (burn-to-mint) closes. Subsequent burn-to-mint transactions revert.
- Path B (validator block rewards from pool) closes. Validator rewards switch to the post-launch issuance schedule (subsection 10.3), drawn from new minting against total supply rather than from the genesis pool.
- All other mechanisms (EIP-1559 base fee, fee burn, gas markets, multi-dimensional fees) operate as previously specified — unchanged across the transition.

The transition is **automatic and irreversible**. No governance vote, no protocol upgrade, no foundation decision triggers it. The protocol's state machine observes the trigger conditions and transitions on the next block. No party can extend the launch phase. No party can re-open it once closed.

#### Time-cap forced exhaustion

If the time cap is reached with one or both sub-counters non-zero (the pool was not fully claimed during the launch phase), the protocol forces phase transition. Any unclaimed ADM in either sub-counter is **destroyed** — not redistributed, not allocated to any party, not reserved for future use. The unclaimed portion of the pool ceases to exist; total ADM in circulation at the moment of transition is whatever was claimed during the launch phase.

Forced exhaustion via destruction (rather than redistribution) preserves the no-insider-allocation property. Unclaimed tokens at the time cap simply do not exist; no party gains from the chain's failure to fully drain the pool.

#### Asymmetric exhaustion

Because the pool is partitioned into two sub-counters that drain at independent rates, one sub-counter may exhaust before the other. The behaviour:

- If the **burn-allocated** sub-counter exhausts first, path A closes immediately. Path B continues until the validator-allocated sub-counter exhausts (or the time cap is reached). Phase transition occurs when both are exhausted.
- If the **validator-allocated** sub-counter exhausts first, validator rewards immediately switch to the post-launch issuance schedule (subsection 10.3). Path A continues to drain the burn-allocated sub-counter until it exhausts (or the time cap is reached). Phase transition occurs when both are exhausted.

This produces a clean state machine: each path closes when its sub-counter reaches zero, and full phase transition occurs only when both are closed (or the time cap is reached).

#### Total supply trajectory

The launch phase produces a deterministic supply trajectory:

- **Block 0:** Total claimed ADM = 0; pool counter = 100,000,000.
- **Block 0 to phase transition:** Claimed ADM grows monotonically as paths drain the pool. At all times, claimed ADM + remaining pool ≤ 100,000,000.
- **Phase transition:** Pool counter reaches zero (or is forced to zero by the time cap). Claimed ADM at transition is at most 100,000,000.
- **Post-transition:** Claimed ADM grows via the post-launch issuance schedule (subsection 10.3). Total supply trajectory is governed by the issuance schedule net of fee burn (subsection 10.4).

The genesis pool effectively acts as a one-time supply seeding event with a hard upper bound. After it exhausts, supply dynamics are entirely governed by the post-launch operational regime.

### 10.2.5 Why this approach

The protocol's launch model was the subject of substantial design deliberation. The original specification (the version of this whitepaper at v0.1) used a pure burn-launch in 180 daily windows, distributing a fixed quantity of ADM each day to that day's burners proportional to their burn value. The genesis pool model replaces it. This subsection explains the reasoning.

#### What was rejected, and why

**Pre-mine to founders.** Violates Principle I. Founders with substantial ADM holdings have ongoing power over the chain. Rejected, regardless of launch mechanism.

**VC fundraising.** Same reason. Investors with allocations expect influence over the chain's direction. Rejected, regardless of launch mechanism.

**Airdrop to existing crypto users.** Easier launch path but creates an "incumbent class" of large early holders who benefit from arbitrary inclusion criteria. Rejected, regardless of launch mechanism.

**Pure proof-of-work mining (Bitcoin's model).** Excellent fairness but environmentally expensive and produces hardware-arms-race dynamics that do not align with Adamant's principles. Rejected.

**Liquidity bootstrapping pools.** Used by some projects but has the same insider-advantage problems as VC rounds, with the additional disadvantage of being more complex. Rejected.

**The original burn-launch with daily windows.** Considered carefully and ultimately revised. The reasoning is given below.

#### Why the original burn-launch was revised

The original burn-launch model had the property that supply scales perfectly with participation — if X is burned, Y tokens are issued, with X and Y proportional. This is appealing as a fairness statement: no token exists that didn't have a corresponding burn behind it.

However, the model has a failure mode that became clear under examination: **at low participation, the chain launches with such limited absolute supply and such concentrated distribution that subsequent adoption becomes structurally difficult.** A chain that launches with 50 burners holding the entire supply between them has not failed mechanically — the protocol works, transactions happen, validators run — but it lacks the distributional and supply properties needed to attract additional users, validators, application developers, or exchange listings.

This is the cold-start problem. Most successful cryptocurrencies took years to develop usable distributions. Bitcoin spent its first 18 months at near-zero economic value. Ethereum's launch was small by today's standards. The original burn-launch model offered no protection against a similar trajectory for Adamant — and arguably worsened it, because the fixed six-month window meant the chain could not gain participation through gradual outreach over the years it would actually take to build awareness.

The genesis pool model addresses this by extending the launch phase beyond a fixed calendar window. The launch phase ends when participation is sufficient to drain the pool (or, at latest, five years out). A chain with low early participation has years to attract additional burners and validators before its launch phase forcibly ends. A chain with high early participation transitions quickly to its operational phase.

The model also adds a second acquisition path (validator block rewards) that does not require burning external assets. This serves participants who wish to contribute to network security but lack the existing crypto holdings that the burn-launch model implicitly required.

#### Why this is not a violation of fair launch

A skeptical reader may object that 100,000,000 ADM existing at genesis is itself a violation of the no-allocation principle — that the protocol has effectively allocated tokens to itself. The objection deserves a direct answer.

The genesis pool is **not held by any party**. There is no foundation that controls it. No multisig that signs releases. No address with privileged access. No governance mechanism that decides how it drains. The pool is a counter in the protocol's state, decrementing only through the public acquisition paths defined in subsection 10.2.3.

The claim "the protocol has allocated tokens to itself" treats "the protocol" as a party. It is not. The protocol is the rule-set that all validators execute. No one *is* the protocol. The pool's existence does not benefit any party beyond what the public acquisition paths grant equally to all participants.

The pool is mechanically equivalent to a protocol-level construct that defines launch-phase boundary conditions, similar to:

- Bitcoin's block reward halving schedule, which defines how new BTC enters circulation over time without anyone "owning" the future issuance.
- Ethereum's pre-Merge issuance, which minted ETH to validators each block without any party holding the future-mintable ETH.
- Any cryptocurrency's perpetual issuance schedule, which represents a future supply commitment without an allocation to a specific party.

The 100,000,000 ADM in the genesis pool is, structurally, future issuance with a defined upper bound and defined distribution mechanisms. It is no more an "allocation" than Bitcoin's not-yet-mined 21 million BTC was an allocation to Satoshi at genesis.

What would violate the fair-launch principle: a foundation holding the pool, a privileged address controlling drain rates, a discretionary mechanism for allocation decisions, or any party (including the implementers) receiving tokens outside the public acquisition paths. The genesis pool model contains none of these.

#### Why this is structurally better than alternatives

Beyond addressing the cold-start problem, the genesis pool model has properties that make it stronger than the original burn-launch:

- **The launch phase has a defined end.** Pool exhaustion (or the time cap) triggers operational phase. This produces a clean transition point that the original model lacked — the original simply ended after 180 days regardless of participation.

- **Two acquisition paths serve different audiences.** Burning external assets is appropriate for participants with existing crypto holdings; validating is appropriate for participants who want to contribute infrastructure. Neither audience is privileged over the other.

- **The per-address cap shapes distribution.** The original model's daily-windows mechanism partly addressed concentration but had the side effect that latecomers within a day faced reduced rates relative to early-day burners. The cap-based mechanism applies a clean per-address constraint without timing artifacts within each acquisition window.

- **Forced exhaustion via destruction handles low-participation outcomes cleanly.** The five-year time cap with token destruction means the chain cannot remain in launch phase indefinitely. The original model had no equivalent mechanism for chains that failed to reach reasonable participation.

- **The operational phase is unchanged.** The post-launch issuance schedule, fee mechanisms, staking economy, and consensus rules are identical to the original specification. The genesis pool is a launch-phase preamble; the operational regime that governs the chain in perpetuity is unchanged.

The model is more complex than the original. The complexity buys real properties: a defined-end launch phase, two acquisition paths, distributional shaping, low-participation resilience, and clean integration with the unchanged operational regime. Each of these complexities exists for a reason and addresses a specific failure mode of the simpler model.

### 10.2.6 Validator set at genesis

At genesis, no party holds ADM, and therefore no party holds the stake necessary to be a validator. The active set is empty.

The protocol's solution: the active set populates organically during the launch phase as participants accumulate ADM and choose to stake it. Two pathways exist:

- **Via path A (burn-to-mint):** A participant burns external crypto, receives ADM, and stakes it to register as a validator.
- **Via path B (validator block rewards):** Once the chain has any active validators, those validators earn block rewards from the validator-allocated sub-counter, and may use accumulated rewards as additional stake or invite delegations.

The bootstrap mechanism: the consensus mechanism's standard validator-onboarding rules (subsection 8.1.2) apply from genesis. There is no special bootstrap period during which different rules apply. However, the consensus mechanism cannot produce blocks until at least 50 validators are registered with stake totalling at least 1,000,000 ADM. During the period between genesis and this threshold, the chain is in pre-consensus state — the protocol exists, burn claims via path A are processable in principle, but no blocks are produced.

Resolution of pre-consensus state requires path A to bootstrap initial validators. The first burners receive ADM via path A; they register as validators; once the threshold is met, consensus activates and path B begins producing blocks (and block rewards). From that point, both acquisition paths run concurrently per subsection 10.2.3.

This bootstrap is naturally self-resolving. The chain cannot launch without participation, and participation begins with path A. Once path A produces sufficient stake distribution, the chain transitions to its full launch-phase operation.

## 10.3 Issuance schedule

After the launch phase (subsection 10.2) terminates — whether by pool exhaustion or by the time cap — the protocol issues new ADM continuously to validators as block rewards. The issuance rate is fixed at genesis and cannot be modified without a hard fork. During the launch phase, validator block rewards are drawn from the genesis pool's validator-allocated sub-counter (subsection 10.2.3 path B); after the launch phase, this schedule takes effect.

### 10.3.1 Schedule

The issuance schedule is:

- **Year 1-5:** Validator rewards equal to 4% of current total supply per year, paid in proportion to validator stake.
- **Year 6-10:** 3% per year.
- **Year 11-20:** 2% per year.
- **Year 21+:** 1% per year, in perpetuity.

This produces a slowly-decreasing inflation rate that asymptotes at 1% indefinitely. At long-term equilibrium, the 1% issuance balances against fee burn under typical usage levels, producing approximately stable supply.

The schedule is designed to provide substantial early validator rewards (the 4% level supports many validators with reasonable hardware investments) while reducing inflation as the chain matures.

### 10.3.2 Where issuance goes

Newly-issued ADM is distributed primarily to validators (and their delegators) as rewards for consensus participation, with a small slice directed to the witness compensation pool (subsection 10.6.1). No portion goes to a foundation, a development fund, or any other recipient. Provers (subsection 8.5.3) and service nodes (subsection 9.10) receive no issuance allocation; their compensation is entirely fee-funded or ecosystem-funded.

Specifically, each epoch:

- The protocol calculates the epoch's issuance based on the schedule above.
- A configured percentage of issuance (calibrated prior to mainnet, suggested order of magnitude: ~5%) is directed to the witness compensation pool for distribution per subsection 10.6.2.
- The remaining issuance (the substantial majority) is distributed across the active validator set in proportion to each validator's bonded stake (including delegated stake).
- Each validator's share is further split between the validator and their delegators per the validator's commission rate.

Validators set their own commission rates (typically 5-15%); the rest passes through to delegators. Delegators receive their share automatically each epoch; it accrues to their stake account and can be withdrawn or restaked.

The witness slice is small enough not to displace validator economics meaningfully, while sufficient to underwrite witness participation during low-throughput periods when fee-based compensation alone would be insufficient.

### 10.3.3 Why not "burn the issuance and let fees do the work"

Some chains (notably Ethereum post-Merge) attempt to make issuance nearly zero, paying validators primarily from fees. This is sustainable only if fees are reliably high.

Adamant rejects this approach because:

- It produces volatile validator economics: in periods of low network usage, validators are under-rewarded and the active set thins, weakening security.
- It creates pressure to increase fees, which conflicts with our cost target ($0.0001 per transfer, Principle IV).
- It makes validator participation uneconomic for smaller validators with less efficient operations, centralising the active set.

The issuance-plus-fee-burn model provides a stable validator income floor (issuance) while still tying token value to usage (burn).

## 10.4 Fee mechanism

### 10.4.1 Multi-dimensional fees

As specified in section 6.3, fees are computed across multiple dimensions:

1. **Computation:** per gas unit consumed by execution
2. **State storage:** per byte added to active state
3. **State rent prepayment:** per byte-second of object lifetime
4. **Bandwidth:** per byte transmitted
5. **Proof verification:** per Halo 2 proof verified
6. **Proof generation:** per Halo 2 proof produced by the prover market (subsection 8.5.3) or by validator-fallback (subsection 8.5.4); paid as a per-proof bounty to the producer rather than to validators

Each dimension has its own price. The user's transaction fee is the sum across dimensions.

### 10.4.2 EIP-1559-style price discovery

The price for each dimension is determined per-epoch by an EIP-1559-style mechanism:

- Each dimension has a target consumption per epoch (a "block fullness" target).
- If the previous epoch consumed more than the target, the price increases (up to 12.5% per epoch).
- If the previous epoch consumed less than the target, the price decreases (down to 12.5% per epoch).
- The base price for each dimension is consumed by burn (not paid to validators).
- A small "tip" above the base price is paid to validators as a priority signal.

This produces:

- Predictable congestion pricing: heavy usage periods see higher prices, but the increase is bounded per-epoch.
- Efficient resource allocation: each dimension is priced independently; demand for one does not crowd out demand for another.
- Token value capture from usage: base fees are burned, reducing supply in proportion to usage.

### 10.4.3 Cost target

The protocol's design target is that simple transparent transfers cost approximately $0.0001 USD-equivalent at typical usage. This is achievable with the multi-dimensional fee model: a simple transfer's resource consumption is small in every dimension.

Shielded transfers cost more, primarily due to proof verification cost: typically $0.001-$0.01 USD-equivalent. This is more expensive than transparent transfers but still within consumer payment-network territory and far below Ethereum's typical $1-50 fee range.

Heavy contract executions cost more still, scaling with their actual resource consumption. The protocol's contribution is that you pay for what you use, not a flat rate that mis-allocates costs.

### 10.4.4 Fee burn

Base fees are burned. Tips go to validators. The burn mechanism:

- Each transaction's base fee (the price-per-dimension multiplied by consumption-per-dimension, summed across dimensions) is destroyed at execution time.
- The burn is recorded in the chain state but the burned ADM is no longer counted in total supply.
- Tips are paid to the validator who included the transaction in a vertex.

Under typical usage, fee burn approximately equals issuance, producing roughly stable supply. Under heavy usage, burn exceeds issuance, producing net deflation. Under light usage, issuance exceeds burn, producing modest inflation.

### 10.4.5 Sponsored fees

The smart-account model (section 4) allows validation logic to designate a fee payer other than the transaction submitter. This enables:

- **Application-paid fees.** Apps pay for their users' transactions.
- **Paymaster contracts.** Services pay user fees and recoup costs in another currency.
- **Free-tier sponsorship.** Protocol or community-funded contracts pay for users below thresholds.

The protocol does not specify these patterns; it makes them possible. Whether they are widely used depends on application-level economics.

### 10.4.6 Prover bounty mechanism

The proof-generation fee dimension (§10.4.1 dimension 6) flows to a separate compensation pool from the burn-or-validator-tip flow that governs the other dimensions. Specifically:

- **Bounty pool source.** Each transaction's proof-generation fee accumulates in a per-block bounty pool. The pool is paid out at proof acceptance: the prover (or validator-fallback producer) whose proof for the relevant state is first accepted by validators receives the entire bounty for that proof's covered block range.
- **Bounty amount.** The bounty is set by the dimension's price under the EIP-1559-style adjustment (subsection 10.4.2), with the dimension's "block fullness" target calibrated to the proof-production cadence rather than to gas consumption. The target is set such that consistent steady-state production at the design-target cadence produces a stable bounty; persistent prover-market shortfall (validator-fallback engaging frequently) raises the bounty until external prover supply returns; persistent oversupply (proofs produced faster than the cadence target requires) lowers it.
- **Prover-side claim.** Provers register on-chain identities (subsection 8.5.3); bounties paid to a prover's address are immediately spendable on confirmation.
- **Validator-fallback alignment.** When a validator generates a fallback proof (subsection 8.5.4), the bounty flows to the validator's address using the same mechanism. Validators do not face an incentive to keep the prover market broken — the per-proof compensation is identical regardless of who produces the proof.
- **No issuance subsidy at launch.** The bounty is funded entirely from transaction fees; the protocol does not allocate a slice of issuance to provers at launch. If empirical data shows persistent prover undersupply at low TPS (insufficient transaction-fee volume to fund GPU operating costs), a small issuance subsidy may be considered as a future hard-fork revision (subsection 11.5). At launch, fee-funded compensation is sufficient at design-target throughput.

**Constitutional posture.** The bounty mechanism is implementation-detail rather than constitutional. The constitutional commitment is that proof generation is a separate compensated tier (validators do not capture proof-generation revenue beyond the fallback case), not the specific bounty-calibration algorithm. Future hard forks can adjust the bounty mechanism without violating the role split.

## 10.5 Staking economy

### 10.5.1 Validator rewards

A validator's epoch reward is:

```
reward = (validator_stake / total_staked) * epoch_issuance + tips_collected
```

The validator's commission is taken from this reward; the remainder is distributed to delegators.

A validator's effective annual yield is approximately the issuance rate (4% in early years, declining per the schedule) minus their operational costs and any slashing they incur. After slashing risk and operational overhead, the typical net yield to delegators is in the range of 3.5% in early years.

### 10.5.2 Slashing risk

Validators (and their delegators) face slashing risk for the offences in subsection 8.1.5. Honest validators with well-operated infrastructure rarely incur slashing; the risk is primarily a defence against malicious or grossly negligent operators.

Delegators bear slashing in proportion to their delegation: if a validator is slashed 5%, all delegators' stakes decrease by 5%. This aligns delegator incentives with validator selection: delegators are economically motivated to delegate to high-quality validators.

### 10.5.3 Liquid staking

The protocol does not provide liquid staking at the protocol layer. Liquid staking — receiving a tradeable token representing one's staked position — can be implemented as a smart contract using the standard primitives. The protocol declines to provide this as a primitive because it would centralise on a single liquid-staking provider; allowing the market to provide multiple competing options is healthier.

### 10.5.4 Compounding

Validator rewards accrue automatically. Delegators may compound (restake their rewards) by submitting a restake transaction; rewards do not auto-compound by default. This is a deliberate choice: auto-compounding requires defining a compounding interval that may not match every delegator's preferred cadence; manual restaking puts the choice in delegators' hands.

### 10.5.5 Validator-funded infrastructure

Validators may, at their discretion, allocate a portion of their commission revenue to fund infrastructure providers — including but not limited to service nodes (subsection 9.10), onion-routing relays (subsection 9.4.2), and other ecosystem participants whose work supports the validator's delegator base. This is a market mechanism enabled by the protocol but not specified by it.

The economic logic is that validators compete for delegations. Beyond commission rates, validators may compete on the quality of services available to their delegators. A validator who funds well-distributed service-node infrastructure can offer their delegators better wallet experiences (faster queries, lower-latency state lookups) than a validator who relies on centralised RPC providers or who provides no infrastructure at all. This competition is healthy: it creates an economic flow from validator rewards to infrastructure providers, broadening the population of participants who earn from the network's operation.

The protocol does not:

- Require validators to fund infrastructure
- Specify what infrastructure validators must fund
- Set rates or terms for validator-to-infrastructure-provider payments
- Maintain a registry of validators that fund infrastructure
- Privilege validators that fund infrastructure over those that do not

Validators that fund infrastructure do so out of their own commission revenue (already received per subsection 10.3.2), via voluntary on-chain or off-chain payment. The protocol provides standard smart-contract patterns supporting these payments (subsection 9.10.5), but the existence of such patterns does not constitute a protocol-level allocation: every ADM paid to an infrastructure provider was first earned by a validator, and the validator chose to spend it on infrastructure rather than retain it as commission profit or distribute it to delegators.

This mechanism preserves the constitutional property that issuance goes entirely to validators (subsection 10.3.2) while enabling a downstream market in which validators voluntarily share their earnings with parties whose work supports the validator's competitive position. It also preserves credible neutrality (Principle I): the protocol does not pick infrastructure winners or operate any allocation mechanism beyond enabling the market to function.

The honest expectation: this market may or may not materialise at scale. Its success depends on validators finding it worthwhile to compete on infrastructure quality, on infrastructure providers finding the work economically viable, and on delegators valuing the resulting service quality enough to influence their delegation choices. The protocol enables; the ecosystem develops.

## 10.6 Witness compensation

The witness tier (subsection 8.7.2) performs four roles — cryptographic attestation, data availability sampling, recursive proof verification, and fraud/reordering detection — on phone-class hardware. Witness participation is permissionless; sustaining it economically requires a compensation flow distinct from validator rewards and prover bounties.

### 10.6.1 Sources of witness compensation

Witness compensation is sourced from two pools:

- **A small slice of transaction fees** (specifically, a percentage of the verification dimension fee — section 10.4.1 dimension 5 — calibrated so that witness compensation tracks chain activity). The percentage is set such that aggregate witness compensation at design-target throughput covers the operational cost of running a witness on phone-class hardware (approximately negligible — a few cents of energy per month) plus a small reward.
- **A small slice of issuance** (a percentage of the post-launch-phase issuance — subsection 10.3.1 — directed to the witness pool). The percentage is set such that witnesses receive meaningful compensation even at low transaction volume; this avoids witness participation collapsing during low-activity periods.

The combined witness pool is structurally analogous to the prover bounty pool (subsection 10.4.6) but funded from different sources and distributed across many witnesses rather than one prover per proof.

### 10.6.2 Per-witness allocation

Per-witness compensation is calibrated to the four roles witnesses perform:

- **Role A (attestation):** paid per attestation produced and accepted by the chain. Per-attestation amount decreases as the witness pool grows (more witnesses sharing the fixed per-attestation reward).
- **Role B (DA sampling):** paid per successful sampling round at a fixed rate. Witnesses submit signed sample evidence; the chain verifies and pays.
- **Role C (proof verification):** paid per recursive proof verified, with the per-proof amount scaled to the cadence at which proofs are produced. During fallback periods (subsection 8.5.4), Role C compensation per witness scales down with the slower proof cadence — witnesses earn less per unit time when proofs are produced less frequently, which is correct because there is less work to do.
- **Role D (fraud and reordering detection):** paid as a small base rate plus bonuses on corroborated flags. False flags (evidence that does not support an actual fraud or reordering claim) cost the witness a portion of their Role D base compensation as a deterrent against spurious flagging.

A witness may choose to perform all four roles or any subset; compensation scales accordingly. A phone-only witness performing just Role B can participate meaningfully with minimal hardware investment.

### 10.6.3 Slashing for false attestations

A witness's Sybil-resistance stake (suggested 100 ADM, subsection 8.7.2) is slashable for **false attestations corroborated by other witnesses**: when N witnesses produce attestations agreeing on a chain state and a small minority of witnesses produce contradicting attestations, the contradicting witnesses' attestations are treated as evidence of malicious or careless behaviour and their stake is slashed at a rate calibrated to the offence severity. Routine non-participation (failing to submit attestations) does not trigger slashing — it simply forfeits compensation.

Slashing for false attestations is automatic and on-chain, similar to validator slashing (subsection 8.1.5): any party can submit corroborating evidence, and the protocol slashes the offending witness without governance review. Slashed stake is burned, not redistributed.

### 10.6.4 Honest framing

Witness compensation is calibrated for participation, not for profit. The economic value of running a single witness is small — comparable to running a Bitcoin full node a decade ago. The point is to enable a large, distributed, phone-runnable participation surface that broadens chain security beyond the validator-class operators. Aggregate witness participation, distributed across a large population, provides defence-in-depth that any individual witness's contribution does not.

The protocol does not promise that witness participation is profitable; it promises that the compensation flow exists, that the slashing model is mechanical, and that participation is permissionless. Whether a substantial witness population emerges in practice is determined by ecosystem dynamics (wallet adoption of witness-mode features, phone-class operating cost trends, user willingness to dedicate phone resources to chain participation) rather than protocol mechanism.

## 10.7 Genesis economic parameters

The following parameters are set at genesis and cannot be modified:

- Genesis pool size: 100,000,000 ADM (subject to calibration prior to mainnet)
- Pool partition: 70% burn-allocated / 30% validator-allocated (subject to calibration)
- Per-address claim cap schedule: 1% / 2% / 4% / 8% / unlimited at months 0–1 / 1–3 / 3–6 / 6–12 / 12+ (subject to calibration)
- Time cap: 5 years from genesis (subject to calibration)
- Conversion rates per source chain: defined in USD-equivalent at protocol design time, subject to calibration
- Validator block reward during launch phase: calibrated to drain the validator-allocated sub-counter over the target launch duration
- Minimum per-validator stake: TBD (suggested order of magnitude: 1,000 ADM; specific value calibrated prior to mainnet to balance entry accessibility against trivial-stake spam)
- Witness Sybil-resistance stake: TBD (suggested order of magnitude: 100 ADM; calibrated prior to mainnet)
- Genesis activation gate: 7 simultaneously-online stake-eligible validators (constitutional floor; subsection 8.1.6)
- Active set: dynamic with constitutional floor of 7 validators and soft ceiling of 75 validators (subsection 8.1.3); ceiling subject to empirical validation prior to mainnet
- Active set selection: first-come-first-served with persistent membership — validators admitted in registration order; slots held continuously until liveness failure or voluntary unbonding; no forced rotation; standby queue admits new validators when slots open
- Security tier boundaries: Tier I at N=7–14, Tier II at N=15–29, Tier III at N=30+ (subsection 8.1.7)
- Encryption regime transition thresholds: switch to threshold encryption at N≥15, switch back to time-lock encryption at N<10 (hysteresis preventing flapping; subsection 8.4.2)
- Time-lock parameter T for VDF: calibrated to 10–15 seconds of decryption delay on consensus-grade hardware; specific value set prior to mainnet
- Validator commission ceiling: 100% (no protocol cap; market discipline applies)
- Unbonding period: 28 days
- Witness unbonding period: 7 days (lighter than validator unbonding because of bounded power)
- Issuance schedule (post-launch-phase): as specified in subsection 10.3.1
- Slashing rates: as specified in section 8.1.5 (validator) and subsection 10.6.3 (witness)
- Fee dimensions: 6, as specified in section 6.3
- Base price adjustment: ±12.5% per epoch
- Block fullness targets: per-dimension, calibrated at genesis
- Witness compensation pool sourcing: percentage of verification-dimension fees + percentage of issuance, both calibrated prior to mainnet
- Prover bounty pool sourcing: 100% of proof-generation-dimension fees (subsection 10.4.6); no issuance subsidy at launch

These parameters are stored in the genesis specification (section 11) and are subject to the same constitutional immutability as consensus rules. Changes require the social-coordination mechanism for hard forks specified in section 11.

Parameters listed as "subject to calibration prior to mainnet" reflect the genesis pool mechanism's reference values. Specific values will be finalised based on simulation analysis of participation distributions, drain rates, and stress-tested scenarios. The calibrated values become consensus-critical at the moment of genesis; the calibration process happens before that moment. After genesis, all values are immutable per the constitutional commitment of section 11.

## 10.8 What this section deliberately omits

This section does not contain:

- Predictions of token price
- Projections of network fee revenue
- Projections of validator adoption rates
- Investment-related language of any kind

The protocol is a piece of infrastructure. Its economic model is specified in mechanical terms — issuance schedules, fee formulas, burn rates — and the consequences of those mechanics in terms of token supply and validator economics are derivable from the specifications. Predicting market outcomes is outside the scope of a technical specification and is intentionally absent.
# 11. Genesis & Constitution

This section is the protocol's constitutional commitment. It specifies what is fixed forever at genesis, what cannot be changed by any party including the protocol's original implementers, and the precise mechanism by which the protocol may change despite this — through socially-coordinated hard forks in which every node operator individually chooses whether to adopt new client software.

This section is the operational realisation of Principle I (credible neutrality). Every other section of this whitepaper specifies *what* the protocol does; this section specifies *what cannot change about that, and how*.

## 11.1 The constitutional commitment

At genesis, the protocol's specification — every section of this whitepaper, the parameters defined within it, and the reference implementation that realises it — is fixed. The fixing is enforced not by a foundation, not by a multisig, not by an on-chain governance mechanism, but by the structural absence of any mechanism to modify the protocol.

After genesis, the protocol exists as:

- A **specification document** (this whitepaper, version-frozen at v1.0)
- A **reference implementation** (the Rust code in this repository, version-tagged at v1.0.0)
- A **running network** (the validators executing the reference implementation)

There is no party with the authority to:

- Add a new validity rule
- Change a gas cost
- Modify the issuance schedule
- Add a new system contract
- Freeze any account or transaction
- Censor any participant
- Pause the chain
- Issue an emergency fix
- Coordinate an automatic upgrade
- Change the active set size, the round duration, the epoch length, the slashing rates, or any other consensus parameter

Each of these operations is technically *possible* — anyone can write a modified Rust implementation that does any of them. What is *impossible* is for any party to make such modifications take effect on the running network without the explicit cooperation of the validators running the existing implementation.

This is the meaning of "constitutional immutability": not that the protocol cannot change, but that change requires a process that cannot be controlled by any party.

## 11.2 What is fixed at genesis

The following are set at genesis and constitute the protocol's permanent character:

### 11.2.1 The eight design principles

The principles in section 2, in priority order:

1. Credible neutrality
2. Privacy by default
3. Verifiability without trust
4. Performance sufficient for use
5. Mutability as a property of objects
6. Standard primitives, novel synthesis
7. Permissionless participation
8. Post-quantum security at identity and privacy layers

These principles are the protocol's identity. A future version of this protocol that violated any of these principles would, by definition, be a different protocol — not a revised Adamant.

### 11.2.2 Cryptographic primitives

The cryptographic primitives specified in section 3, including:

- SHA3-256 and SHAKE-256 as primary hash functions
- BLAKE3 as auxiliary hash
- Poseidon as zk-friendly hash
- Ed25519 and ML-DSA-65 as signature schemes (hybrid posture per Principle VIII: Ed25519 for ordinary transactions and validator consensus messages; ML-DSA for identity-binding operations including validator registrations, contract deployments, and address derivation)
- ML-KEM-768 (FIPS 203) as the post-quantum key encapsulation mechanism for stealth address derivation, encrypted memo delivery, and any other privacy-relevant key-agreement surface
- BLS12-381 with G1 signatures and G2 public keys for aggregation
- ChaCha20-Poly1305 for symmetric encryption
- BLS-based threshold encryption for the encrypted mempool (operative at N≥15)
- Wesolowski VDF on class groups for time-lock encryption (operative at N<15)
- Halo 2 (Pasta curves) for general-purpose proving
- KZG commitments on BLS12-381 for vector commitments

These choices are part of the consensus rules. Migration to alternatives requires hard fork.

### 11.2.3 Object model and mutability

The object model specified in section 5, including:

- The six mutability variants (`Immutable`, `OwnerUpgradeable`, `VoteUpgradeable`, `UpgradeableUntilFrozen`, `Custom`, `Forked`)
- The four ownership modes (`Address`, `Shared`, `Immutable`, `Group`)
- The protocol-enforced mutability semantics (validators reject upgrades inconsistent with the declared mutability)
- The 1 MiB per-object size cap
- The state rent mechanism

### 11.2.4 Adamant Move language

The smart-contract language specified in section 6:

- The bytecode instruction set
- The mutability and privacy annotations
- The standard library (the modules in `adamant::*`)
- The gas cost table

The standard library modules are deployed at genesis with `Immutable` mutability; they cannot be modified post-genesis.

### 11.2.5 Privacy layer

The privacy layer specified in section 7:

- The note model
- The stealth address construction
- The view key hierarchy
- The Halo 2 circuit specifications for shielded execution

### 11.2.6 Consensus mechanism

The consensus mechanism specified in section 8:

- DAG structure with 250ms target round duration
- 36-second epochs (144 rounds per epoch)
- Dynamic active set: constitutional floor of 7 validators, soft ceiling of 75 validators (calibrated to the throughput floor on residential-fibre hardware)
- First-come-first-served selection with persistent membership: validators admitted in registration order, slots held continuously until liveness failure or voluntary unbonding; no forced rotation; no stake-weighted lottery; commitment and continuity rewarded over hardware budget or stake size
- 2/3+1 quorum threshold within the active set
- Genesis activation gate: chain self-activates when 7 validators are simultaneously registered, stake-eligible, and online; no coordination event, no recruited cohort, no human-in-the-loop activation
- Halt-on-disagreement: at the floor, the chain pauses rather than forks if quorum cannot be reached; safety is preserved at the cost of liveness during severe-unavailability periods
- On-chain security tier disclosure: Tier I (N=7–14), Tier II (N=15–29), Tier III (N=30+), queryable as constant-time chain-state property
- The slashing rates and offences
- Two-regime mempool encryption: time-lock encryption (Wesolowski VDF, subsection 3.8) operative at N<15; threshold encryption with DKG operative at N≥15; automatic transition with hysteresis (switch to threshold at N≥15, switch back at N<10); both regimes preserve transaction confidentiality, with quantitative MEV-protection difference acknowledged in subsection 8.4.4
- Round-anchor rotation and decryption-publication binding as the load-bearing mitigations for the time-lock regime's MEV surface
- Role split between consensus and proof generation: validators do consensus, mempool decryption, and fallback proof generation; provers (subsection 8.5.3) do steady-state proof generation in a permissionless market; the role split is constitutional, the bounty calibration is implementation-detail
- Validator-fallback proof generation at degraded cadence (subsection 8.5.4) preserving Principle III (phone-verifiability) regardless of prover-market health
- Witness tier (subsection 8.7.2) providing phone-runnable participation across four roles (cryptographic attestation, data availability sampling, recursive proof verification, fraud and reordering detection); permissionless registration with small Sybil-resistance stake; honest constitutional acknowledgment that witness utility is co-determined with the integrity of the tiers witnesses verify
- Four-tier participation model with bounded power across all tiers (validators, provers, witnesses, service nodes); no single tier alone controls the chain

### 11.2.7 Economic model

The economic model specified in section 10:

- The genesis pool mechanism (100,000,000 ADM, 70% burn-allocated / 30% validator-allocated)
- The two acquisition paths (burn-to-mint and validator block rewards)
- The per-address claim cap schedule for the burn path
- The phase-transition rules (pool exhaustion or 5-year time cap; unclaimed tokens destroyed)
- The post-launch issuance schedule (4% Y1-5, 3% Y6-10, 2% Y11-20, 1% perpetual), with issuance distributed across validators (primary recipient) and witnesses (small slice, subsection 10.6); no issuance to provers or service nodes (their compensation is fee-funded or ecosystem-funded)
- The EIP-1559-style base fee mechanism
- The fee burn mechanism for base fees on most dimensions
- The proof-generation fee dimension funding the prover bounty pool (subsection 10.4.6) rather than burning or being paid to validators
- The verification fee dimension partially funding the witness compensation pool (subsection 10.6.1)
- The 28-day validator unbonding period; the 7-day witness unbonding period
- Witness slashing for false attestations (subsection 10.6.3) is automatic and on-chain, mirroring validator slashing in mechanical character

The launch phase is a one-time event ending in pool exhaustion or the 5-year time cap; the post-launch operational regime governs the chain in perpetuity thereafter.

The protocol additionally enables, but does not fund from a dedicated issuance allocation, a permissionless service-node infrastructure market (subsection 9.10) and a validator-funded infrastructure mechanism (subsection 10.5.5). The protocol-level commitments fixed at genesis include the standardised query format, the registration mechanism, the smart-contract patterns supporting payment, and the structure of issuance flow (validators and witnesses receive slices; provers and service nodes are fee/ecosystem-funded). The downstream service-node market — its participants, fee schedules, reputation systems, and operational shape — is not constitutionally fixed and may evolve organically without requiring hard-fork coordination. Validators choosing to fund infrastructure do so from their own commission revenue, not from any protocol allocation; the protocol's role is enablement, not allocation.

### 11.2.8 Genesis state

The specific state at the moment of genesis, including:

- The protocol's null genesis state (no balances, no objects beyond standard library)
- The bootstrap node addresses for initial network discovery
- The Powers of Tau ceremony parameters (using Ethereum's ceremony output, July 2023)
- The reference implementation hash (committed at v1.0.0 release)

The genesis state is published as a distinct artifact (`genesis.json` in the repository) and is itself version-controlled. Once the chain launches, this artifact becomes immutable: every node's local genesis state must match the published artifact, or the node is on a different chain.

## 11.3 What is not fixed at genesis

The following are explicitly *not* fixed and are subject to natural variation:

- The set of validators (changes per epoch)
- The set of active applications (changes continuously as developers deploy contracts)
- The token's market price (determined externally)
- Wallet implementations (any client may exist)
- Network gateways, RPC providers, and indexer services (any party may operate these)
- Off-protocol coordination mechanisms (forums, social media, communications channels)

These are the natural ecosystem around the protocol. Their evolution is healthy and expected.

## 11.4 The fork mechanism

Despite all the above, the protocol *can* change. The mechanism is:

1. **Specification revision.** Someone proposes a change. They draft the change as a revised whitepaper section, a new reference implementation, or both.

2. **Public discussion.** The proposal is discussed in public forums (the protocol's GitHub repository, public mailing lists, etc.). The discussion is open; anyone may participate.

3. **Implementation.** A reference implementation of the change is published. Anyone may write or audit the implementation.

4. **Validator opt-in.** Validators choose whether to upgrade their software. Each validator's decision is independent.

5. **Activation.** When a sufficient supermajority of validators (at least 2/3+1 by stake) have upgraded, the new rules become effective on the network they form. Validators who did not upgrade either:
   - Find themselves on a "minority chain" with the same history but different rules going forward
   - Upgrade voluntarily to remain on the chain with the supermajority

There is no point at which any party — including the proposers, the implementers, or any subset of validators — can force the upgrade onto unwilling participants. The minority chain remains operational as long as it has any validators willing to maintain it.

### 11.4.1 What this looks like in practice

In practice, hard forks are infrequent and contentious in proportion to their scope:

- **Routine upgrades** (bug fixes, performance improvements that don't change semantics): typically uncontroversial, supermajority adoption within weeks.
- **Substantive upgrades** (new features, parameter changes): contested, take months to gather supermajority adoption, may produce minority chains.
- **Fundamental upgrades** (changes to core principles): produce permanent splits. The protocol's history may include such splits; both sides continue with their preferred ruleset.

This is the same mechanism Bitcoin uses. Bitcoin has had multiple hard forks (Bitcoin Cash, Bitcoin SV, etc.), each producing a separate chain whose adherents preferred the alternative ruleset. Both chains continue operating; users choose which to use; the market resolves which receives more value over time.

Adamant accepts that some changes will produce splits, and considers this preferable to a centralised mechanism that prevents splits at the cost of forcing changes on dissenters.

### 11.4.2 What the original implementers commit to

The original implementers — those of us drafting this specification and writing the reference implementation — commit to the following:

1. We will not retain admin keys, hardcoded backdoors, or other privileged access mechanisms in the reference implementation. The implementation, once released, has no special accommodations for our continued involvement.

2. We will not pre-mine, allocate to ourselves, or otherwise position ourselves to receive ADM beyond what we acquire through public participation in the launch-phase acquisition paths (subsection 10.2.3) alongside everyone else, and through normal market acquisition after the launch phase.

3. We will not maintain "official" forks or channels in a way that confers privilege. If we propose changes, we propose them through the same mechanism anyone else does. Our proposals receive no special weight.

4. We will not claim ownership of the protocol's name, logo, or other markers in a way that creates leverage. If forks adopt different names, that is a healthy outcome of the fork mechanism.

5. We will publish the specification, reference implementation, and supporting materials under permissive licenses (Apache 2.0) such that anyone may modify and redistribute.

These commitments are voluntary. They are not enforced by the protocol; they are enforced by the same mechanism that enforces credible neutrality — the absence of any mechanism by which we *could* violate them while the chain remains running.

### 11.4.3 Why this is credible

A skeptical reader may ask: "The original implementers say they will not pre-mine, but how can users verify this?"

The answer is that the genesis state is verifiable. The genesis specification contains every account that exists at genesis (none), every object that exists at genesis (only the standard library modules and consensus parameters), and every parameter that governs subsequent issuance. Anyone may verify that the implementers do not appear in this state. Anyone may follow the chain's subsequent history and verify that no privileged distribution occurred.

If the implementers wished to sneak a pre-mine into the protocol, they would have to do so visibly, in the published genesis specification, where it could be detected before launch. They cannot insert it post-launch because there is no mechanism to do so.

The credibility comes from the protocol's design making misbehaviour infeasible, not from the implementers' promises.

## 11.5 Anticipated future revisions

For honest engagement with the future, this section anticipates several categories of change that may eventually justify hard forks:

### 11.5.1 Post-quantum migration

The protocol's privacy primitives (BLS12-381, Halo 2) are not post-quantum (section 7.9.3). When production-ready post-quantum proving systems mature — likely in the 2030s — a migration to post-quantum primitives may become appropriate. The migration would be additive: new shielded transactions use post-quantum primitives; existing notes can be spent under the old primitives until users choose to migrate.

This is anticipated but not specified in detail because the specific post-quantum primitives that will be appropriate are not yet known.

### 11.5.2 Throughput improvements

The protocol's single-shard throughput floor (50,000 TPS) may eventually be insufficient. Sharding extensions, parallel consensus instances, or other techniques may be proposed. These extensions require hard forks; they are not anticipated to occur before year 5 of the chain's operation, by which point empirical data on usage patterns will inform the design.

### 11.5.3 Cryptographic algorithm improvements

New zero-knowledge proving systems, new signature schemes, and new threshold encryption schemes are likely to mature during the chain's lifetime. Migration to these — when they are clearly superior, peer-reviewed, and production-tested — will be proposed via the same hard-fork mechanism.

### 11.5.4 Bug fixes

Despite extensive review and testing, some bugs in the reference implementation may be discovered post-launch. Bug fixes that do not change protocol semantics (e.g. fixing a memory leak in the validator) can be deployed by validators choosing to run patched software without coordinating with anyone. Bug fixes that *do* change protocol semantics (e.g. fixing an underflow in fee calculation) require the same hard-fork mechanism as any other change.

### 11.5.5 What is not anticipated

The protocol does not anticipate:

- Adding on-chain governance (this would violate Principle I)
- Adding admin keys (same)
- Adding a foundation or treasury (same)
- Removing privacy by default (this would violate Principle II)
- Removing permissionless participation (this would violate Principle VII)

These changes, if proposed, would not be revisions of Adamant but proposals for a different protocol. The fork mechanism would still apply, but the resulting chain would not be considered Adamant by anyone who values the original principles.

## 11.6 The constitutional commitment, restated

The protocol's constitutional commitment, in the simplest possible terms:

- The rules at genesis are the rules forever, except by the explicit individual choice of every node operator to run different software.
- No party — including the protocol's original implementers, validators acting in concert, governments, or any other actor — has the authority to modify the protocol.
- The mechanism for change is social coordination: discussion, proposal, implementation, voluntary adoption.
- The mechanism's slowness is its strength: it ensures that any change has been examined, debated, and accepted by a supermajority of those whose participation makes the chain function.
- A protocol with this property cannot be captured. It can only be replaced by an alternative that participants prefer.

This is what is meant by "the chain you use when you don't trust anyone." The chain itself is what you trust, and it is constructed such that the trust is mechanical, not personal.
# 12. Conclusion & Open Problems

This section closes the whitepaper. It is shorter than the technical sections by design: it does not specify new protocol behaviour but reflects on what has been specified, identifies the open problems that remain, and outlines the path from this document to a running chain.

## 12.1 What this document has specified

This whitepaper specifies, in detail sufficient to implement, a Layer 1 blockchain protocol with the following properties:

- **Credible neutrality.** No foundation, no admin keys, no on-chain governance, no premine, no upgrade authority. The chain has no master. Low-coordination launch via genesis activation gate (7 validators simultaneously online); the chain self-activates with no recruited cohort and no human-in-the-loop activation.

- **Privacy by default.** All transactions are shielded by default through Halo 2 zero-knowledge proofs. Users retain selective disclosure via view keys. Stealth address derivation and encrypted memo delivery use ML-KEM-768, making historical privacy post-quantum-secure.

- **High throughput.** DAG-based consensus targeting 50,000+ transactions per second at design-target validator count on residential-fiber hardware (subject to empirical validation before genesis), with sub-second finality at design-target N.

- **Phone-verifiable.** Recursive zero-knowledge proofs compress chain history into a constant-size proof verifiable on consumer hardware. Proofs are produced by a permissionless prover market at steady state, with validators retaining a fallback role at degraded cadence to preserve phone-verifiability regardless of prover-market health.

- **Two-regime encrypted mempool.** Threshold encryption integrated into consensus at design-target validator count; time-lock encryption (Wesolowski VDF) operative during the low-N period before threshold-encryption viability. Both regimes preserve transaction confidentiality from external observers; MEV protection is structural in the threshold regime and bounded-but-non-zero in the time-lock regime via deterministic anchor rotation and decryption-publication binding.

- **Hybrid post-quantum signatures.** ML-DSA (FIPS 204) for identity-binding operations; Ed25519 for ordinary transactions and validator messages by default; per-transaction opt-in to ML-DSA. ML-KEM-768 (FIPS 203) for post-quantum-secure key agreement underlying privacy primitives. Trade-off honestly disclosed: ordinary transaction signatures are quantum-forgeable; identity, structural state, and historical privacy are not.

- **Dynamic active validator set.** Constitutional floor of 7 validators; soft ceiling of 75; first-come-first-served selection with persistent membership (slots held continuously until liveness failure or voluntary unbonding); on-chain security tier disclosure (Tier I / II / III) so wallets and applications can adapt to current chain scale.

- **Four-tier participation model.** Validators (consensus + decryption + fallback proofs); provers (steady-state recursive proof generation in a permissionless market); witnesses (attestation, data availability sampling, proof verification, fraud detection on phone-class hardware); service nodes (light-client infrastructure). Each tier has bounded power.

- **Mutability as a first-class property.** Every contract declares its mutability rules at creation; declarations are protocol-enforced and visible to users before interaction.

- **Native account abstraction.** Every account is a smart account from genesis. No retrofit, no special cases.

- **Service-node infrastructure market.** Permissionless, standardised market for light-client infrastructure (subsection 9.10), with validator-funded service mechanisms (subsection 10.5.5). The protocol enables the market without funding it from issuance.

- **Adamant Move smart contracts.** Linear-typed, resource-safe, formally verifiable smart-contract language.

- **Multi-dimensional gas.** Six independent fee dimensions including a separate proof-generation dimension funding the prover bounty pool, EIP-1559-style price discovery, fee burn.

- **Fair launch.** Six-month proof-of-burn distribution mechanism. No premine, no investor allocation, no founder allocation.

- **Constitutional immutability.** Protocol rules fixed at genesis; changes require socially-coordinated hard forks with individual node-operator opt-in.

The protocol's contribution is the integration: each component above exists in some form in some existing chain or research paper, but no chain combines all of them coherently. Adamant is the engineering effort to do so.

## 12.2 What remains to be done

This whitepaper is a specification. Substantial work remains before genesis:

### 12.2.1 Reference implementation

The Rust reference implementation is, as of this draft, not begun. The estimated scope is 150,000-250,000 lines of Rust across a workspace of 20-30 crates, implementing every component described in this whitepaper.

The implementation will proceed in phases:

1. **Cryptographic foundations** — the primitives in section 3, packaged as standalone crates with property tests.
2. **Object model and VM** — a minimal Adamant Move implementation with object storage but no privacy or consensus.
3. **Privacy layer** — Halo 2 circuits, note construction, stealth addresses, view keys.
4. **Consensus and networking** — the DAG protocol, libp2p integration, encrypted mempool.
5. **Recursive proofs** — the recursive proof construction, distributed generation, light client verification.
6. **Genesis tooling** — the fair-launch mining mechanism, the genesis state generation.
7. **Audit, hardening, and testnet** — extensive testing, security audits, public testnets.
8. **Genesis launch** — the moment the network goes live.

A realistic timeline for one or two engineers working full-time is 24-36 months. With a small team (3-5 core engineers plus auditors and reviewers), the timeline can be compressed to 18-24 months.

### 12.2.2 Open problems

Several problems are acknowledged as open and will be addressed during implementation:

**Optimal gas calibration.** The gas costs of individual instructions must be calibrated against actual hardware benchmarks before being committed at genesis. The numbers in this whitepaper are placeholders; final values require empirical measurement on the reference implementation.

**Prover market dynamics and bounty calibration.** Section 8.5.3 specifies a permissionless prover market with per-proof bounties and an automatic adjustment algorithm modelled on EIP-1559. The exact bounty calibration, the timing of validator-fallback engagement, and the conditions under which the market may underperform need implementation experience to refine. Section 8.5.4's fallback ensures phone-verifiability is preserved regardless, but the market's behaviour at scale is empirical territory.

**DKG protocol details.** Section 8.4.3 specifies that validators run a Pedersen-style DKG at each epoch boundary. Concrete protocol details (specific message formats, timeout handling, late-joining rules) are deferred to the implementation.

**Fee dimension calibration.** Section 6.3 and section 10.4 specify multi-dimensional gas with EIP-1559-style price discovery, but the specific block-fullness targets per dimension require empirical calibration.

**Stealth address scanning performance.** Section 7.2.4 specifies view tags as an optimisation for wallet scanning. As the chain grows, even with view tags, scan time may become a UX issue. Future optimisations (probabilistic data structures, server-assisted scanning with privacy guarantees) may be needed but are not part of v1.0.

**Bridging.** The protocol does not specify a bridge to other chains. Bridges are a frequent source of catastrophic failures in blockchain history (over $2B in bridge hacks since 2022), and the protocol takes no position on bridge design at genesis. Bridges, if they emerge, will be deployed as smart contracts subject to the standard rules; the protocol provides no special infrastructure for them.

**MEV in cross-vertex composition.** Section 8.4 specifies that the encrypted mempool eliminates MEV at the protocol layer. However, when shielded transactions interact with shared transparent state, some forms of MEV may persist (e.g. an attacker observing the *order* of shielded transactions affecting a transparent DEX). Further analysis and possible mitigations are an open research area.

**Long-term storage costs.** Section 5.6 specifies state rent and archival, but the long-term economics of the archival ecosystem (how many archive nodes are needed, who pays for them) are uncertain. The protocol provides the mechanism; the ecosystem must develop in practice.

**Operational tooling.** Wallets, indexers, block explorers, RPC providers, monitoring tooling — these are not part of the protocol but are essential for users. The protocol's launch must be accompanied by reasonable tooling, and the early ecosystem requires bootstrapping.

**Service-node market materialisation.** Subsection 9.10 specifies the standardised infrastructure for a service-node market. Whether such a market develops at meaningful scale depends on multiple factors that are open at the time of this draft: whether wallets prefer service nodes over centralised RPC providers, whether validators choose to fund infrastructure as part of competing for delegators (subsection 10.5.5), whether payment-channel UX is good enough for routine wallet usage, and whether the population of operators is large enough to resist centralisation pressure. The protocol provides the substrate; the ecosystem must develop the market. The chain's correct operation does not depend on the market materialising.

**Service-node payment channel UX.** Subsection 9.10.5 specifies three payment patterns for service-node fees. Pattern A (direct wallet-to-node payment via channels) inherits the well-documented UX challenges of payment-channel networks — channel management, liquidity considerations, force-close handling. The reference implementation aims to make these flows automatic and invisible to users, but achieving that level of polish is non-trivial. Pattern B (validator-funded) and Pattern C (application-paid) avoid these UX issues for end users by absorbing them into validator or application infrastructure.

**Reputation system development.** Subsection 9.10.6 specifies a delivery-receipt primitive but does not specify a reputation system. Practical service-node reputation requires third-party tooling: aggregators of delivery receipts, signed performance attestations, perhaps decentralised reputation networks. The protocol provides the cryptographic primitives; the reputation systems are ecosystem work.

### 12.2.3 Limitations acknowledged

Some limitations are not "open problems" but acknowledged constraints:

- The protocol's post-quantum security is partial rather than universal. The identity layer (addresses, validator registrations, contract deployments) is post-quantum-secure via ML-DSA. The privacy layer's key-agreement surface (stealth addresses, encrypted memos) is post-quantum-secure via ML-KEM-768 — historical privacy of who-sent-to-whom survives the quantum threshold. However, the proof system underlying shielded execution (Halo 2 over the Pasta curves) is not post-quantum-secure: a future quantum adversary could in principle forge proofs that should not have verified, retrospectively undermining proof soundness for historical transactions (subsection 7.9.3). Ordinary user-transaction signatures use Ed25519 by default for performance reasons; these are quantum-forgeable, affecting transaction-history forensics but not chain integrity or privacy. Migration to a fully post-quantum proof system is anticipated but cannot be specified in advance — no production-ready post-quantum SNARK with comparable performance characteristics exists at the time of this draft.

- The chain has no governance mechanism for emergency intervention. A bug discovered post-launch cannot be patched without a hard fork. This is a deliberate consequence of credible neutrality (Principle I) and is accepted as a cost.

- Single-shard throughput is bounded by the consensus mechanism. The protocol's design target is 50,000 TPS at the design-target validator count on residential-fiber hardware (subsection 1.2). Beyond this target, scaling requires sharding or other techniques not specified in v1.0. The protocol accepts that it will not, in v1.0, displace high-frequency-trading-grade infrastructure.

- The chain does not natively support complex compliance frameworks (KYC, AML enforcement). These are deliberately excluded by Principle II and Principle VII. Users and applications requiring such frameworks must implement them at the application layer or use other chains.

- The fair-launch mechanism (section 10.2.2) requires bridging from other chains for genesis distribution. The bridge mechanism for genesis is specified (cryptographic proofs of inclusion in source chains) but is itself a potential failure point requiring careful implementation.

These are honest constraints, documented to set accurate expectations.

## 12.3 The path from here

The path from this whitepaper to a running chain is approximately:

**Phase 0 (now → 6 months).** Specification refinement. Public review of this whitepaper. Iteration based on feedback from cryptographers, blockchain engineers, and the broader research community. Finalisation of v1.0 specification.

**Phase 1 (6 → 18 months).** Reference implementation development. The crates, the test suites, the formal specifications. Public development with monthly releases. Engagement with the Move community, Halo 2 maintainers, libp2p maintainers, and other upstream projects.

**Phase 2 (18 → 24 months).** Audits, testnets, hardening. Multiple security audits by reputable firms. Public testnets with progressively realistic conditions. Bug bounties.

**Phase 3 (24+ months).** Genesis preparation and launch. Bootstrap node operator recruitment. Fair-launch mining infrastructure. Final genesis specification publication. Genesis transaction. Network activation.

These phases are estimates, not commitments. Software development is hard to schedule, and a project of this scope is more uncertain than most. The protocol's value is in being right at genesis, not in being early; if delays are needed to ensure correctness, they will be taken.

## 12.4 Closing

The blockchain ecosystem in 2026 is a maze of compromises. Most chains compromise neutrality for governance flexibility; many compromise privacy for compliance friendliness; some compromise verifiability for performance. Each compromise produces real users who chose that chain because the compromise suited them.

Adamant is for the users who are not served by these compromises. It is for the users whose threat model includes their own government, their own foundation, their own validators. It is for the users for whom "the chain has a foundation" is a security flaw, not a feature. It is for the users who want to commit value to a system whose rules they can verify with cryptographic finality.

This whitepaper specifies how to build that chain. The next document — and the next several years of work — is how it gets built.

---

*This whitepaper is a draft. It is subject to revision based on public review and implementation experience. The v1.0 release will be tagged in the repository when the specification is considered complete and frozen for the genesis implementation.*

*The reference implementation is being developed at [github.com/adamant-protocol/adamant](https://github.com/adamant-protocol/adamant) under the Apache 2.0 license. Issues, pull requests, and substantive review are welcome.*
