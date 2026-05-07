# 12. Conclusion & Open Problems

This section closes the whitepaper. It is shorter than the technical sections by design: it does not specify new protocol behaviour but reflects on what has been specified, identifies the open problems that remain, and outlines the path from this document to a running chain.

## 12.1 What this document has specified

This whitepaper specifies, in detail sufficient to implement, a Layer 1 blockchain protocol with the following properties:

- **Credible neutrality.** No foundation, no admin keys, no on-chain governance, no premine, no upgrade authority. The chain has no master.

- **Privacy by default.** All transactions are shielded by default through Halo 2 zero-knowledge proofs. Users retain selective disclosure via view keys.

- **High throughput.** DAG-based consensus targeting 200,000+ transactions per second on a single shard, with sub-second finality.

- **Phone-verifiable.** Recursive zero-knowledge proofs compress chain history into a constant-size proof verifiable on consumer hardware.

- **Encrypted mempool.** Threshold encryption integrated into consensus, eliminating the structural conditions that enable front-running and validator-level censorship.

- **Post-quantum signatures from genesis.** ML-DSA-65 alongside Ed25519, configurable per account.

- **Mutability as a first-class property.** Every contract declares its mutability rules at creation; declarations are protocol-enforced and visible to users before interaction.

- **Native account abstraction.** Every account is a smart account from genesis. No retrofit, no special cases.

- **Service-node infrastructure market.** Permissionless, standardised market for light-client infrastructure (subsection 9.10), with validator-funded service mechanisms (subsection 10.5.5). The protocol enables the market without funding it from issuance.

- **Adamant Move smart contracts.** Linear-typed, resource-safe, formally verifiable smart-contract language.

- **Multi-dimensional gas.** Six independent fee dimensions, EIP-1559-style price discovery, fee burn.

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

**Distributed proof generation pragmatics.** Section 8.5.3 specifies that recursive proof generation is distributed across validators. The exact protocol — how validators coordinate, how partial proofs aggregate, how failures are handled — needs implementation experience to refine.

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

- The privacy primitives are not post-quantum. Long-term private transactions are vulnerable to retrospective decryption by future quantum adversaries (section 7.9.3). The signature layer is post-quantum; the privacy layer's eventual migration is anticipated but cannot be specified in advance.

- The chain has no governance mechanism for emergency intervention. A bug discovered post-launch cannot be patched without a hard fork. This is a deliberate consequence of credible neutrality (Principle I) and is accepted as a cost.

- Single-shard throughput is bounded by the consensus mechanism. Beyond the 200,000 TPS target, scaling requires sharding or other techniques not specified in v1.0. The protocol accepts that it will not, in v1.0, displace high-frequency-trading-grade infrastructure.

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
