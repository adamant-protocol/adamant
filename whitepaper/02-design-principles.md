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

### 2.2.1 Discussion

Privacy by default is the principle most likely to attract regulatory hostility, and the protocol does not attempt to disguise this. The justification is that the alternative — transparent-by-default with optional privacy — produces a worse outcome for both legitimate privacy and legitimate regulation. When privacy is opt-in, using the privacy feature itself becomes evidence of suspicious behavior; legitimate users avoid it for reputational reasons; the only users left in the privacy pool are those for whom privacy is essential, which makes that pool a prime target for regulatory pressure. When privacy is the default, no such inference can be drawn from the use of privacy features, and the cryptographic anonymity set comprises the entire chain rather than a self-selected subset.

The selective disclosure mechanism is the protocol's answer to the regulatory question. Users can prove compliance with specific obligations (income reporting, sanctions screening, anti-money-laundering due diligence) without exposing unrelated transaction history. This is a stronger compliance posture than transparent chains offer, which expose all transaction history to all observers indefinitely.

## 2.3 Principle III: Verifiability without trust

**Any participant `MUST` be able to verify the correctness of the protocol's operation using only consumer-grade hardware, without trusting any third party.**

Concretely:

1. **Phone-verifiable verification.** A modern smartphone `MUST` be capable of verifying the entire chain history's validity in time bounded by a small constant, regardless of the chain's age or transaction count.

2. **No light-client trust assumptions.** Verification `MUST NOT` require trusting a node, a committee, or a federation. Verification is cryptographic, not statistical.

3. **Recursive proofs.** The protocol `MUST` produce a recursive zero-knowledge proof attesting to the validity of all transactions and state transitions from genesis to the current head. This proof is the canonical verification artifact.

4. **Open verification.** Verification software `MUST` be free, open-source, and runnable without permission. Users do not need to register, identify themselves, or pay to verify the chain.

### 2.3.1 Discussion

This principle exists because the value of credible neutrality is realised only when individual users can verify it. A chain that is technically neutral but practically requires trusting a hosted node is, from the user's perspective, a chain that requires trust in the node operator. The combination of credible neutrality (Principle I) and unverifiable operation in practice (the historical norm) has been one of the central usability failures of the blockchain ecosystem.

Recursive zero-knowledge proofs, demonstrated in production by Mina Protocol since 2021, make this principle achievable in 2026 in a way that was not possible at Bitcoin's launch. The protocol takes advantage of this technological maturity to make verifiability a first-class property rather than an aspiration.

## 2.4 Principle IV: Performance sufficient for use

**The protocol `MUST` provide throughput, latency, and cost properties consistent with practical use as a payment network and smart-contract platform.**

Concretely:

1. **Throughput target.** The protocol `MUST` sustain at least 200,000 transactions per second on a single shard at the design target hardware specification (specified in section 8).

2. **Finality target.** The protocol `MUST` provide finality for transactions that do not require shared-state consensus (simple transfers, owned-object operations) within approximately 500 milliseconds at design throughput.

3. **Cost target.** The base fee for a simple transfer at design throughput `MUST` be on the order of $0.0001 USD-equivalent or less, computed at the fee model specified in section 10.

4. **Phone-friendly proving.** Where users generate zero-knowledge proofs locally, proof generation `MUST` complete in time tolerable for interactive use on consumer mobile hardware (target: 10 seconds or less for typical operations).

### 2.4.1 Discussion

This principle is fourth in priority because it is subordinate to neutrality, privacy, and verifiability. The protocol declines performance gains that would require concessions on those properties. However, performance is not an aesthetic preference; it is the difference between a protocol used in production and a protocol used in research papers. The targets above are calibrated to the threshold below which usability suffers materially.

The 200,000 TPS target derives from the demonstrated throughput of Mysticeti consensus in production. The 500ms finality target derives from the same source. The $0.0001 cost target derives from the observation that fees significantly above this level discourage routine micropayments and limit the protocol's usefulness for payment applications.

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

2. **Specific primitives.** The protocol uses Ed25519 and ML-DSA (FIPS 204) for signatures, BLS12-381 for signature aggregation, SHA-3 for hashing, Halo 2 for zero-knowledge proofs, and standard threshold encryption constructions for the encrypted mempool. These are specified in detail in section 3.

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

## 2.8 The principles in conflict

These principles will, at points, conflict. When they do, they resolve in priority order:

1. Credible neutrality (Principle I) takes precedence over all others.
2. Privacy by default (Principle II) takes precedence over Principles III–VII.
3. Verifiability (Principle III) takes precedence over Principles IV–VII.
4. Performance (Principle IV) takes precedence over Principles V–VII.
5. Mutability-as-property (Principle V) takes precedence over Principles VI–VII.
6. Standard primitives (Principle VI) takes precedence over Principle VII.

In practice, the principles harmonise in the design that follows. This priority order is provided to resolve cases where reasonable people might disagree, including future cases that this document's authors have not anticipated.

## 2.9 What these principles exclude

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
