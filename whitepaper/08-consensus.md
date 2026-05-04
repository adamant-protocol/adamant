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

In any epoch, a subset of registered validators forms the **active set** — the validators currently responsible for consensus. The active set is selected by stake-weighted lottery using the consensus VRF (subsection 8.6) at each epoch boundary.

The active set has a target size of 200 validators. This number is chosen to balance:

- **Decentralisation.** Larger sets spread power more widely.
- **Performance.** Smaller sets reduce communication overhead.
- **Robustness.** The set must be large enough to tolerate up to one-third Byzantine without halting.

200 is in the range of validator counts used by Aptos (~150), Sui (~110), and other production DAG-based chains. It supports ~67 validators of fault tolerance with reasonable communication costs.

The active set size is fixed at 200 at genesis. Changing it post-genesis requires a hard fork (Principle I).

### 8.1.4 Stake delegation

Token holders who do not wish to operate validator hardware may delegate their stake to validators. Delegation is implemented at the protocol layer:

- A holder calls `delegate(validator_id, amount)`. Their tokens become part of the validator's bonded stake; the holder receives a proportional share of that validator's rewards (less the validator's commission).
- The holder may undelegate at any time, subject to a 28-day unbonding period during which the stake is still slashable but no longer earning rewards.
- The validator may not spend or claim the delegated stake; it remains the holder's property, locked under the consensus contract.

Delegation has two purposes: it allows non-operators to earn yield from stake, and it allows the active set to be selected by stake-weighted lottery without requiring stake to be self-bonded. Both Aptos and Cosmos use similar designs.

### 8.1.5 Slashing

Validators who violate consensus rules face automatic slashing of their bonded stake. The protocol slashes for the following provable offences:

- **Equivocation:** signing two distinct consensus messages for the same DAG round. Slashing: 100% of stake.
- **Incorrect threshold decryption:** publishing a decryption share that does not correctly correspond to the validator's threshold key. Slashing: 5% of stake.
- **Liveness failure:** failing to participate in consensus for more than 2 consecutive epochs while in the active set. Slashing: 0.5% of stake plus removal from the active set.
- **Invalid proof:** producing a partial recursive proof that does not verify. Slashing: 10% of stake.

Slashed stake is burned (not redistributed). This ensures slashing is a pure cost, not a transfer to other validators that might be incentivised to provoke offences.

Slashing is automatic and on-chain: any party can submit evidence of equivocation (two signed messages) or invalid proof (the failing proof itself), and the protocol slashes the offending validator without requiring a vote. There is no governance review of slashing; the rules are mechanical.

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

The advantage is *throughput*. At any given moment, all validators in the active set are simultaneously producing vertices and broadcasting them. The chain's effective throughput is the *aggregate* of all validators' contributions, not the throughput of a single leader. With 200 validators each contributing ~1,000 transactions per round and 4 rounds per second, the protocol can process ~800,000 transactions per second under optimal conditions, well above the 200,000 TPS target.

The disadvantage is *complexity*. DAG protocols are harder to reason about than linear chains, harder to implement correctly, and historically have suffered from subtle correctness bugs. Mysticeti's contribution is a formally analyzed DAG protocol with proven safety and liveness properties; Adamant inherits this analysis.

## 8.4 Encrypted mempool integration

Section 9 (Networking & Mempool) specifies the mempool layer in detail. This subsection specifies the consensus-level integration of the encrypted mempool.

### 8.4.1 Why integration matters

A naive encrypted mempool runs in two phases: (1) validators commit to transaction order without seeing contents, then (2) validators decrypt and execute. The two phases are sequential, and the gap between them imposes latency.

Shutter Network on Gnosis Chain demonstrates this: their encrypted mempool adds approximately 3 minutes to transaction inclusion because the decryption phase happens out-of-band, with separate keypers running their own coordination protocol.

Adamant's design eliminates this gap by making validators their own keypers. The threshold decryption happens *during consensus*, by the same set of validators producing the DAG. There is no second protocol; there is no separate keyper set; the decryption is a side-effect of consensus.

### 8.4.2 Encryption for the next epoch

Users encrypt their transactions to the active validator set's threshold public key for the *upcoming* epoch:

- Round R is in epoch E.
- Transactions submitted during epoch E are encrypted to the threshold key of epoch E+1.
- They are propagated, included in vertices, and ordered during epoch E.
- At the epoch E → E+1 transition, the threshold key for E becomes "expired" and validators publish their decryption shares for the included transactions.
- The transactions are decrypted and executed at the start of epoch E+1.

This means encrypted transactions have approximately one epoch (36 seconds) of latency added relative to transparent transactions. For most use cases this is acceptable; for use cases requiring lower latency, transactions may be submitted in transparent form (forfeiting the encrypted-mempool protection).

### 8.4.3 The DKG

At every epoch boundary, the active validator set runs a **distributed key generation (DKG)** protocol to establish the new threshold key. The DKG is a constant-round protocol producing:

- A **master public key** for the next epoch (used by users to encrypt their transactions)
- **Per-validator secret shares** (each validator holds a share of the master secret)
- **Verification keys** (allowing any party to verify decryption shares)

The DKG uses Pedersen-style verifiable secret sharing over BLS12-381, with KZG commitments (section 3.7.2) to validate participants' contributions.

DKG completion is a precondition for entering the new epoch: if the DKG fails (insufficient participation), the previous epoch is extended by one until it succeeds. This is rare in practice (validators have strong incentives to participate) but the protocol handles it gracefully.

### 8.4.4 Decryption share generation

When a vertex includes encrypted transactions, the proposing validator also includes their decryption shares for transactions ordered in the *previous* epoch. Once 2/3+1 valid shares are collected for a transaction, the protocol decrypts it and proceeds with execution.

This share generation happens automatically as part of vertex production; validators do not need to participate in a separate decryption protocol. The cryptographic cost is small (roughly one BLS pairing per transaction) and is included in the validator's per-round work.

### 8.4.5 Censorship resistance

The encrypted mempool's central property is *censorship resistance*: validators cannot selectively exclude transactions based on their content, because they cannot read the content until after ordering is committed.

This eliminates the structural conditions that enable:

- **Front-running.** A validator who could see transaction contents could insert their own transaction ahead. With encryption, no validator sees contents during ordering.
- **Sandwich attacks.** Same mechanism as front-running.
- **Selective censorship.** A validator who could see transaction contents could exclude transactions to/from specific addresses. With encryption, validators see only encrypted blobs.

Censorship resistance is not absolute: a validator can refuse to include any transactions at all (a denial-of-service attack), and a colluding majority can refuse to include transactions from specific encrypted senders (if they can identify the sender by other means, such as network metadata). The protocol mitigates these via:

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

### 8.5.3 Distributed proof generation

Generating the recursive proof is computationally expensive — much more expensive than verifying it. To prevent this from becoming a centralisation bottleneck, the protocol distributes the work across validators:

- Each validator generates a partial proof for their own contributions during the epoch.
- At the epoch boundary, partial proofs are aggregated into the epoch's recursive proof.
- The aggregation itself is performed by a rotating subset of validators, with the result published as part of the epoch transition.

This distribution means no single validator is solely responsible for proof generation. If the proof-generating subset fails, the next subset takes over. Slashing (subsection 8.1.5) penalises invalid proofs.

### 8.5.4 Verifier requirements

A verifier — anyone wishing to confirm the chain's validity without trusting validators — needs:

- The chain's genesis commitment (in the protocol's genesis specification, section 11)
- The current epoch's recursive proof (publishable from any validator or archive node)
- A Halo 2 verifier (open-source, runnable on any modern hardware)

Verification time is approximately 50-200 milliseconds on a modern smartphone, regardless of how many epochs of history exist. This is the property that makes the protocol genuinely "phone-verifiable."

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

## 8.7 Consensus safety and liveness

The consensus mechanism's correctness is established by the following theorems, derived from the Mysticeti analysis with adaptations specific to Adamant's modifications:

**Theorem 1 (Safety).** If fewer than 1/3 of validators by stake are Byzantine, the chain never commits two conflicting transactions. (No double-spends, no fork ambiguity.)

**Theorem 2 (Liveness).** If fewer than 1/3 of validators by stake are Byzantine and network partitions are eventually resolved, the chain commits transactions at a rate determined by network conditions, with expected delay bounded above by a constant.

**Theorem 3 (Fairness).** No validator can extract more than their proportional share of MEV-style value, because the encrypted mempool prevents validators from observing transaction contents during ordering.

These theorems rely on:
- BLS signature soundness (subsection 3.4.3)
- Halo 2 soundness (subsection 3.7.1)
- KZG commitment binding (subsection 3.7.2)
- Threshold encryption security (subsection 3.6)
- The honest-majority assumption (≥2/3 of stake non-Byzantine)

The proofs are not reproduced here; they appear in the Mysticeti paper (NDSS 2025) and in the supplementary cryptographic literature for the modified components. Adamant's deviations from Mysticeti are localised; their effect on the original proofs is marginal and the proofs are reconstructed in supplementary material to the reference implementation.

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
