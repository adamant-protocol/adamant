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
- At 8-second blocks and an active set of 200 validators, this implies a per-block reward in the order of single-digit ADM

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

Newly-issued ADM goes entirely to validators (and their delegators) as rewards for consensus participation. No portion goes to a foundation, a development fund, or any other recipient.

Specifically, each epoch:

- The protocol calculates the epoch's issuance based on the schedule above.
- The issuance is distributed across the active set in proportion to each validator's bonded stake (including delegated stake).
- Each validator's share is further split between the validator and their delegators per the validator's commission rate.

Validators set their own commission rates (typically 5-15%); the rest passes through to delegators. Delegators receive their share automatically each epoch; it accrues to their stake account and can be withdrawn or restaked.

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
6. **Proof generation (optional):** per Halo 2 proof generated by paid prover

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

## 10.6 Genesis economic parameters

The following parameters are set at genesis and cannot be modified:

- Genesis pool size: 100,000,000 ADM (subject to calibration prior to mainnet)
- Pool partition: 70% burn-allocated / 30% validator-allocated (subject to calibration)
- Per-address claim cap schedule: 1% / 2% / 4% / 8% / unlimited at months 0–1 / 1–3 / 3–6 / 6–12 / 12+ (subject to calibration)
- Time cap: 5 years from genesis (subject to calibration)
- Conversion rates per source chain: defined in USD-equivalent at protocol design time, subject to calibration
- Validator block reward during launch phase: calibrated to drain the validator-allocated sub-counter over the target launch duration
- Minimum validator stake: 1 ADM (no floor at protocol level; market floor emerges from operational economics)
- Active set size: 200
- Active set selection: stake-weighted lottery via consensus VRF
- Validator commission ceiling: 100% (no protocol cap; market discipline applies)
- Unbonding period: 28 days
- Issuance schedule (post-launch-phase): as specified in subsection 10.3.1
- Slashing rates: as specified in section 8.1.5
- Fee dimensions: 6, as specified in section 6.3
- Base price adjustment: ±12.5% per epoch
- Block fullness targets: per-dimension, calibrated at genesis

These parameters are stored in the genesis specification (section 11) and are subject to the same constitutional immutability as consensus rules. Changes require the social-coordination mechanism for hard forks specified in section 11.

Parameters listed as "subject to calibration prior to mainnet" reflect the genesis pool mechanism's reference values. Specific values will be finalised based on simulation analysis of participation distributions, drain rates, and stress-tested scenarios. The calibrated values become consensus-critical at the moment of genesis; the calibration process happens before that moment. After genesis, all values are immutable per the constitutional commitment of section 11.

## 10.7 What this section deliberately omits

This section does not contain:

- Predictions of token price
- Projections of network fee revenue
- Projections of validator adoption rates
- Investment-related language of any kind

The protocol is a piece of infrastructure. Its economic model is specified in mechanical terms — issuance schedules, fee formulas, burn rates — and the consequences of those mechanics in terms of token supply and validator economics are derivable from the specifications. Predicting market outcomes is outside the scope of a technical specification and is intentionally absent.
