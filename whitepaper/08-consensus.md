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
