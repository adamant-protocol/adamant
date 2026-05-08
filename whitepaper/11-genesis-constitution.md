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
- Dynamic active set: constitutional floor of 7 validators, soft ceiling of 75 validators at launch (calibrated to the residential-fibre hardware profile of the launch period; subject to revision via hard fork as the chain's hardware composition evolves, subsection 8.1.10)
- First-come-first-served selection with transferable membership: validators admitted in registration order, slots held continuously through participation, slots transferable to other addresses by mutual consent (subsection 8.1.8); no forced rotation; no stake-weighted lottery
- Slot transfer: validators may transfer their active-set slot to another address by mutual consent at any time; the protocol is neutral on the economic terms of the transfer; the chain accepts that slot transferability produces hardware-tier evolution over time as a deliberate design choice
- Genesis cohort: the first 75 validator addresses to take active-set slots receive a permanent, non-transferable on-chain marker recording their position, activation epoch, and chain-state commitment; in addition, a tradeable Genesis NFT is minted to each genesis cohort address as a cultural artefact with no protocol-level function (subsection 8.1.9)
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

### 11.5.4 Stake-parameter re-evaluation

The protocol specifies absolute ADM amounts for participation thresholds: 1,000 ADM minimum for Node Runners (validators) and 100 ADM minimum for Node Watchers (witnesses). These values are calibrated for the expected token-value range during the chain's first five years. They are denominated in ADM rather than in any external unit (USD-equivalent, fractional supply, fee-equivalent, or oracle-priced) because every external denomination introduces a centralisation vector incompatible with Principle I.

To prevent these thresholds from becoming exclusionary if ADM appreciates substantially over time, the protocol commits to **scheduled re-evaluation of stake parameters at five-year intervals post-genesis**. At each five-year checkpoint, the network may draft a hard fork proposing recalibrated stake floors based on the chain's then-current market conditions and participation patterns. The mechanism is the same as for any other parameter change: social coordination, no governance entity, no automatic adjustment.

This is not a binding commitment to *change* the parameters at each checkpoint — only to *consider* whether they should change. If the absolute amounts remain accessible (because ADM has not appreciated dramatically), no fork is needed. If they have become exclusionary, the network coordinates a fork. The five-year cadence is structural rather than reactive: by committing in advance to revisit the parameters periodically, the chain avoids the ossification dynamic that produced Bitcoin's block-size conflict.

### 11.5.5 Bug fixes

Despite extensive review and testing, some bugs in the reference implementation may be discovered post-launch. Bug fixes that do not change protocol semantics (e.g. fixing a memory leak in the validator) can be deployed by validators choosing to run patched software without coordinating with anyone. Bug fixes that *do* change protocol semantics (e.g. fixing an underflow in fee calculation) require the same hard-fork mechanism as any other change.

### 11.5.6 What is not anticipated

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
