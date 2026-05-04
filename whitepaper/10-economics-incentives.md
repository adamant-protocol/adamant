# 10. Economics & Incentives

This section specifies the protocol's economic model: the native token, its issuance schedule, the fee mechanism, the staking and reward economy, and the fair-launch mechanics. These specifications are part of the consensus rules; they cannot be modified by any on-chain mechanism (Principle I).

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

ADM has **no fixed total supply**. The total supply is determined by the issuance schedule (subsection 10.3) net of fee burn (subsection 10.4). Under typical usage, the supply is approximately stable or slowly deflating; under heavy usage, it deflates measurably.

This is a deliberate choice. Fixed-supply tokens (Bitcoin's 21M cap) provide a strong narrative anchor but eventually face the question of how to reward validators when the issuance schedule terminates. Adamant's continuous-issuance-with-burn model resolves this: validator rewards are sustainable indefinitely, while burn ties supply to usage.

The expected long-term equilibrium: in steady state, fees burned approximately equal new issuance, producing rough supply stability with mild deflationary pressure under above-average usage.

## 10.2 Fair launch mechanics

The protocol's launch follows a strict no-premine, no-allocation rule. Specifically:

### 10.2.1 What does not happen at genesis

At genesis, no party — including the protocol's original implementers, contributors, advisors, hypothetical investors, validators, or the protocol itself (as a foundation or treasury) — receives any token allocation.

The genesis state contains:

- The genesis recursive proof anchor
- The initial protocol parameters (gas costs, validator set size, etc.)
- The list of bootstrap node addresses
- The Powers of Tau ceremony reference
- Zero ADM allocations to any account

There is no:
- Founder allocation
- Foundation treasury
- Pre-mine for development funding
- Early-investor allocation
- Validator set "starter pack"
- Ecosystem fund
- Marketing fund

Anyone holding ADM at any point after genesis acquired it through one of the mechanisms specified below.

### 10.2.2 Genesis distribution mechanism

At genesis, the protocol begins issuance through a single mechanism: **fair-launch mining**, structured as proof-of-burn.

For the first 12 epochs (approximately 7.2 minutes of chain time, but calibrated such that the actual genesis distribution period is 6 months in calendar terms — see "Genesis launch parameters" in section 11), the protocol issues tokens via a sealed-bid mechanism. Participants commit funds (in BTC, ETH, or other widely-traded assets, via cryptographic bridge attestations specified in section 11) to a one-way burn address; the protocol distributes ADM proportionally to participants based on their committed value.

The mechanics:

- Anyone may participate by burning supported assets to the protocol's well-known burn address.
- Burn transactions are observed via cryptographic proofs of inclusion in their source chains.
- Each daily window distributes a fixed quantity of ADM to that day's participants, proportional to their burn value.
- The genesis distribution period totals 6 months. After it ends, no further fair-launch mining occurs.

This mechanism has the following properties:

- **No party with insider advantage.** The implementers do not hold ADM going into the launch; they must participate in fair-launch mining like everyone else if they wish to hold ADM.
- **Anti-whale by design.** Daily windows mean that a single very large burn does not capture a disproportionate share; the burner is competing against everyone else burning that day.
- **Provably fair.** Anyone can verify the mechanism's outputs against the on-chain burn evidence and the protocol's distribution formula.
- **No legal complexity.** The mechanism is not a sale; participants receive ADM proportional to their voluntary burns, with no commercial relationship to any party. This is the same legal structure as Bitcoin's launch.

### 10.2.3 Why this approach

Alternative launch mechanisms considered and rejected:

- **Pre-mine to founders.** Violates Principle I. Founders with substantial ADM holdings have ongoing power over the chain. Rejected.
- **VC fundraising.** Same reason. Investors with allocations expect influence over the chain's direction. Rejected.
- **Airdrop to existing crypto users.** Easier launch path but creates an "incumbent class" of large early holders who benefit from arbitrary inclusion criteria. Rejected.
- **Pure proof-of-work mining (Bitcoin's model).** Excellent fairness but environmentally expensive and produces hardware-arms-race dynamics that we do not want. Rejected.
- **Liquidity bootstrapping pools.** Used by some projects but has the same insider-advantage problems as VC rounds, with the additional disadvantage of being more complex. Rejected.

Fair-launch mining via proof-of-burn is the cleanest path that satisfies the principles. The 6-month period is long enough that participation is not artificially constrained by short windows of time-zone availability.

### 10.2.4 Validator set at genesis

At genesis, no party holds ADM, and therefore no party holds the stake necessary to be a validator. The active set is empty.

The protocol's solution: the active set populates organically as fair-launch participants accumulate ADM and choose to stake it. The first 12 epochs are a "bootstrap" period during which:

- The protocol's consensus mechanism is paused.
- Fair-launch mining proceeds.
- Participants accumulate ADM and may register as validators.
- Once at least 50 validators have registered with stake totalling at least 1 million ADM, the consensus mechanism activates.

This is a one-time bootstrap; once the chain is active, the standard validator-onboarding mechanism (subsection 8.1.2) applies.

## 10.3 Issuance schedule

After the genesis distribution period, the protocol issues new ADM continuously to validators as block rewards. The issuance rate is fixed at genesis and cannot be modified without a hard fork.

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

## 10.6 Genesis economic parameters

The following parameters are set at genesis and cannot be modified:

- Genesis distribution period: 6 months
- Daily distribution windows during genesis: 180
- Minimum validator stake: 1 ADM (no floor at protocol level; market floor emerges from operational economics)
- Active set size: 200
- Active set selection: stake-weighted lottery via consensus VRF
- Validator commission ceiling: 100% (no protocol cap; market discipline applies)
- Unbonding period: 28 days
- Issuance schedule: as specified in subsection 10.3.1
- Slashing rates: as specified in section 8.1.5
- Fee dimensions: 6, as specified in section 6.3
- Base price adjustment: ±12.5% per epoch
- Block fullness targets: per-dimension, calibrated at genesis

These parameters are stored in the genesis specification (section 11) and are subject to the same constitutional immutability as consensus rules. Changes require the social-coordination mechanism for hard forks specified in section 11.

## 10.7 What this section deliberately omits

This section does not contain:

- Predictions of token price
- Projections of network fee revenue
- Projections of validator adoption rates
- Investment-related language of any kind

The protocol is a piece of infrastructure. Its economic model is specified in mechanical terms — issuance schedules, fee formulas, burn rates — and the consequences of those mechanics in terms of token supply and validator economics are derivable from the specifications. Predicting market outcomes is outside the scope of a technical specification and is intentionally absent.
