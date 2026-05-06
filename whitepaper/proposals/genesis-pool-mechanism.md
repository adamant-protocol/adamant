# Proposal: Genesis pool mechanism for Adamant launch

**Status:** Draft proposal — not yet committed to the whitepaper.
**Authors:** Ryan Geldart (with Claude collaboration).
**Date:** May 2026.
**Target whitepaper sections:** §10 (Economics & Incentives) and §11 (Genesis & Constitution).

## Purpose of this document

This proposal sketches a launch mechanism for Adamant that differs from a pure burn-launch (the model originally described in §11). It is **not yet a whitepaper amendment**. It is a design document capturing the proposed mechanism, the rationale, the open calibration questions, and the work that needs to happen before this design can be committed to the whitepaper.

The decision to record this as a proposal rather than a direct whitepaper amendment reflects the seriousness of launch economics. Adamant launches once. The launch model is permanently visible and shapes the chain's distribution forever. Specific parameters (pool size, conversion rate, cap schedules, transition thresholds) require simulation work before they're spec-ready. The proposal captures the *mechanism* — the structural shape of the launch — so that calibration work can proceed against a stable target.

When the calibration work is complete and the design has been pressure-tested, this proposal becomes the source for the §10/§11 amendment.

## The problem we're solving

The original burn-launch model (§11 v0.1) specifies: at genesis, anyone can burn external crypto (BTC, ETH, etc.) and receive Adamant tokens at a defined conversion rate. The burn period lasts six months. After the burn period closes, no further genesis distribution occurs; supply continues via continuous validator issuance per §10.

This model has the property that **supply scales perfectly with participation**. If 10 people burn, the chain launches with whatever total they collectively burned. If a million people burn, the chain launches at scale.

But this property has a failure mode that's worth taking seriously: at low participation, the chain launches with such concentrated supply (a few large burners holding most of the tokens) and such limited absolute supply that subsequent adoption becomes structurally difficult. The chain technically exists but lacks the distribution and supply properties needed to become useful.

The proposal addresses this by introducing a **genesis pool** — a fixed token supply that exists at genesis and drains via multiple acquisition paths over a launch period that can span years rather than a fixed six-month window. The chain transitions from "launch phase" to "operational phase" when the pool exhausts, regardless of how long that takes.

The core insight: **the genesis allocation is a launch threshold that must be exhausted before the chain reaches its mature economic phase**. The chain's ability to attract enough collective participation to drain the pool is itself a credibility test, and the launch period extends until that test is met.

## Locked design (pieces 1-3)

The following design choices were worked through and locked in collaborative discussion. They are stable and will form the basis of the whitepaper amendment.

### Piece 1 — Pool size

A genesis pool of **100,000,000 Adamant tokens** is created at protocol launch. This is the reference value, subject to calibration revision before mainnet based on simulation analysis.

The pool's size is chosen to:
- Be drainable within a reasonable launch period (years, not decades) at expected participation rates
- Be large enough that no single participant can dominate (with reasonable per-address constraints, even the largest claimant captures a small percentage of the pool)
- Sit within familiar token-supply orders of magnitude (Bitcoin's eventual cap is 21M; Ethereum's circulating supply is ~120M; 100M places Adamant in a recognisable range)

The specific number is a starting anchor. Final calibration depends on simulation work that models participation distributions and drain rates.

### Piece 2 — Drain paths

Two paths drain the pool:

**Path A — Burn-to-mint.** A participant burns external crypto (initially BTC, ETH; expandable to others by protocol design) at a verifiable burn address on the source chain. The protocol observes the confirmed burn and mints the corresponding Adamant tokens to the participant's claim address. The burned external crypto is permanently destroyed; no party receives it.

**Path B — Validator rewards.** Validators run nodes that secure the network. Each block they propose, they receive a reward minted from the pool. This serves the audience that wants to participate by securing the network rather than by burning external value, and solves the proof-of-stake bootstrap problem (early validators can earn stake by validating, not exclusively by burning).

Both paths run concurrently from genesis day one. Both pull from the same shared pool counter (with policy constraints described in piece 4).

**Acquisition outside paths A and B is via secondary market.** Once tokens exist in circulation, holders can transfer them freely. Centralised exchanges, decentralised exchanges, OTC desks, and peer-to-peer transfers will emerge organically and are not specified by the protocol. Anyone wishing to acquire Adamant tokens may do so through these secondary markets in the same manner as for any other cryptocurrency. The protocol does not provide a "buy from the protocol" mechanism; market-based acquisition is the standard pattern in functional cryptocurrencies and Adamant follows it.

### Piece 3 — Conversion rate function (path A)

The burn-to-mint conversion rate is **constant** throughout the launch phase. It does not vary with time, pool state, drain velocity, or any other dynamic input.

**Reference values (subject to calibration):**
- 1 BTC burned → X Adamant tokens (X to be calibrated)
- 1 ETH burned → Y Adamant tokens (Y to be calibrated)
- Other accepted assets at protocol-defined rates

Conversion rates across source chains are defined in USD-equivalent terms at protocol design time, *not* at burn time. This avoids gaming based on currency-fluctuation arbitrage during the launch window.

**Per-address claim cap (the distributional shaping mechanism).** While the conversion rate is constant, a per-address cap on cumulative claims grows over time:

| Period | Cap (% of pool) |
|--------|-----------------|
| Months 0–1 | 1% |
| Months 1–3 | 2% |
| Months 3–6 | 4% |
| Months 6–12 | 8% |
| Month 12+ | No cap |

A single address (across the entire launch phase) cannot claim more than the prevailing cap percentage of the original 100M pool. After month 12, caps lift entirely. The cap applies to total cumulative claims via path A by an address (path B validator rewards are not subject to the cap; see piece 4).

The cap is per-address rather than per-identity. Sybil resistance is partial — a determined attacker can split claims across many addresses — but the cost of doing so (managing many wallets, each with separate claim transactions, each subject to gas costs) raises the friction enough that opportunistic concentration is meaningfully suppressed.

The cap schedule is calibratable; the values above are reference figures.

**Why constant rate plus growing cap, rather than a dynamic algorithm.** Earlier discussion considered hill-curve rates (bad-good-best across the launch period) and activity-responsive algorithms (rate adjusts to drain velocity). Both were rejected after careful analysis:

- Hill curves create incentives to wait for late-phase generous rates, which can produce a mid-period dead zone followed by a late-phase rush.
- Activity-responsive algorithms are gameable (participants coordinate to wait for high rates, then rush when rates spike), produce oscillations on bursty inputs, are hard to reason about as a participant, and harder to audit.
- Static designs trade off "algorithmic intelligence" for predictability. In launch economics, where the launch happens once and gaming or surprise are highly costly, predictability is the right side of the tradeoff.

The constant-rate-plus-cap design achieves distributional shaping via the cap (which directly limits concentration) while keeping the rate predictable for participants.

## Proposed design (pieces 4-8) — for review

The following pieces have not yet been worked through with the same depth as 1-3. They are drafted here for review. Pushback expected; revision likely.

### Piece 4 — Phase transition and pool partition

The chain operates in **launch phase** until the pool exhausts, then transitions to **operational phase** automatically.

**Trigger.** The pool counter starts at 100M. Every burn-to-mint claim and every validator block reward decrements the counter. When the counter reaches zero, the next block triggers the operational-phase regime: paths A and B close; validator rewards switch to the post-launch issuance schedule defined in §10 (4% annual, declining to 1% asymptotically); EIP-1559 burn continues as already specified.

**The transition is automatic and irreversible.** No governance vote, no protocol upgrade, no foundation decision. The protocol's state machine observes `pool_counter == 0` and transitions on the next block. No human can extend launch phase. No party can re-open it.

**Pool partition (policy constraint).** The pool is partitioned in policy: a fraction reserved for path A (burn-to-mint), a fraction available to path B (validator rewards). The partition prevents a failure mode where validator rewards alone could exhaust the pool with minimal burn participation, producing extreme concentration in the validator set.

Reference partition: **70% burn-allocated / 30% validator-allocated.**

Mechanically, the pool counter is split into two sub-counters (`burn_remaining`, `validator_remaining`), each initialised to its allocated fraction of the 100M total. Burn claims decrement `burn_remaining`; validator rewards decrement `validator_remaining`. The phase transitions when both sub-counters reach zero.

**What happens if one sub-counter exhausts before the other.** Two cases:

- *Burn-allocated exhausts first:* Path A closes. Validator rewards continue from the validator-allocated remainder until that exhausts. Once both are zero, operational phase begins. This case is unlikely but possible if burn participation is unexpectedly high relative to calibration.
- *Validator-allocated exhausts first:* Path B switches to its post-launch schedule (issuance from new minting per §10) immediately, while the burn-allocated remainder continues to drain via path A. Once the burn-allocated remainder reaches zero, the chain has fully transitioned. This case is more likely if burn participation is sustained at moderate levels while validator rewards drain steadily over time.

**Burn transactions are full-or-nothing.** If a burn would drain the burn-allocated counter past zero, the burn transaction reverts and the burner's external crypto is *not* destroyed. This requires the burn mechanism to be transactional — atomic commit, with the ability to revert. Mechanically achievable; adds protocol complexity at the burn-claim entry point.

**Validator reward sizing.** During launch phase, validator block rewards are calibrated to drain the validator-allocated portion (30% of pool = 30M tokens) over a target duration. If the target launch duration is two years and blocks are 8 seconds apart, that's roughly 7.9 million blocks; reward per block ≈ 3.8 tokens. Specific values calibrated.

After the validator-allocated portion exhausts, validator rewards switch to the §10 post-launch schedule, which is an inflation-based issuance rather than a pool-drain.

### Piece 5 — Time cap

What if the pool never drains?

A real possibility. If participation is low (10 people burn at genesis, modest validator set), the pool drain might be so slow that the launch phase extends indefinitely. The chain remains stuck in launch phase, unable to enter its mature economic regime.

**Mitigation: hard time cap of 5 years from genesis.** If five years pass and the pool is not exhausted, the protocol forces transition: any remaining tokens in either sub-counter are *destroyed* (not redistributed), and the chain enters operational phase on whatever supply has been claimed.

Forced exhaustion via destruction (rather than redistribution to a foundation, treasury, or existing holders) preserves the no-insider-allocation property. Unclaimed tokens at the time cap simply cease to exist.

**Why 5 years.** Long enough that low-but-real participation has years to drain the pool gradually. Short enough that the launch phase doesn't persist beyond a horizon where the chain's identity is settled. Calibratable.

**An alternative considered.** Could the time cap accelerate burn-rate generosity in its final months — "if we're approaching the cap and the pool isn't drained, the conversion rate temporarily improves to encourage final participation"? This was considered and rejected: it introduces a dynamic-rate element after we explicitly chose constant rates in piece 3, and it incentivises gaming (participants wait for the final months knowing rates will improve). The hard time cap with destruction is cleaner.

### Piece 6 — Anti-gaming mitigations

Several gaming risks need mitigation:

**Whale capture via path A.** Addressed by the per-address cap schedule in piece 3. Even an adversary with a billion dollars of BTC cannot dominate the early launch — the cap forces them to spread participation across either time or addresses.

**Sybil fragmentation of the cap.** An adversary splits a billion dollars across 10,000 addresses, each claiming up to its individual cap. The protocol cannot enforce identity. Mitigation is *partial*: managing 10,000 addresses with separate claim transactions imposes friction (gas costs, key management, transaction signing). It raises the cost of the attack but doesn't prevent it for a sufficiently determined attacker.

The honest position: **the per-address cap reduces opportunistic concentration but does not prevent maximally-funded adversarial concentration.** A nation-state actor or large fund could acquire a meaningful share of the pool by splitting across many addresses. We accept this; complete sybil resistance would require identity infrastructure that conflicts with the chain's privacy-default posture.

**Timing arbitrage on the cap schedule.** The cap rises at fixed times (1%, 2%, 4%, 8%, no cap). A participant could time their claims to maximise allocation under each tier. This is not really gaming — it's the system working as intended (early caps tight, later caps loose). No mitigation needed.

**Wash burning across addresses.** An attacker burns from one address, receives tokens to another, transfers tokens back, burns again. Doesn't actually accomplish anything in this model — the attacker has destroyed real BTC and gained nothing in exchange (their second "burn" still requires real BTC; the first burn's tokens transferred between their addresses gives them no advantage). Not a real attack.

**Validator collusion to inflate rewards.** Validators cannot inflate their per-block reward — it's protocol-defined. They could collude to censor non-collusive validators' blocks, capturing more block rewards. This is a general PoS attack covered by the consensus design in §8, not specific to launch economics.

**Coordinated burn-rush during favourable cap windows.** When a cap tier opens, many participants might burn simultaneously to claim under the new tier. This is the system working as intended — cap tiers are advertised, participants plan accordingly, no harm done. Network can handle the load (block space accommodates many burns per block).

### Piece 7 — Burned-asset disposition

**External assets burned via path A are permanently destroyed.** No party receives them. This is the core credibility mechanism — the cost of acquiring Adamant is paid to the universe, not to a foundation, treasury, or existing holders.

**Mechanism per source chain:**

- **Bitcoin:** burns sent to a verifiably unspendable address derived from a deterministic public construction (e.g., a P2SH address with no possible redeem script that could spend funds). The Bitcoin protocol confirms the burn; the funds are unspendable forever; no key exists to recover them.
- **Ethereum:** burns sent to the Ethereum null address (0x000...000) or a verifiably unspendable contract. Standard pattern; widely understood by the Ethereum ecosystem.
- **Other source chains:** chain-specific verifiable burn mechanisms.

The verifiability of the burn (cryptographic certainty that the destroyed funds cannot be recovered) is what makes the credibility argument work. If the protocol custodied burned funds (e.g., in a multisig held by a foundation), the credibility collapses. **No party — including the protocol itself — has any claim on burned external crypto.**

The protocol observes burns via *light-client verification of source-chain block headers*. A relay submits a proof that a burn transaction was confirmed on the source chain. The protocol verifies the proof against the source chain's consensus mechanism. If verified, Adamant tokens mint to the claim address (subject to the per-address cap and the burn-allocated sub-counter remaining).

This is a non-trivial cryptographic design. Light-client verification across multiple source chains requires careful integration. Specific protocol designs for each source chain are calibration work prior to mainnet.

### Piece 8 — Integration with existing §10

The genesis pool mechanism modifies §10's existing economic model. The modifications are additive — §10's operational-phase mechanics are preserved unchanged, with the genesis pool serving as a launch-phase preamble.

**During launch phase:**
- Validator rewards drain from the validator-allocated sub-counter (instead of being minted as inflation against total supply)
- Burn-to-mint claims drain from the burn-allocated sub-counter
- EIP-1559 base-fee burn operates as specified in §10 (gas paid by transactors; base fee burned)
- Priority tips to validators operate as specified in §10
- All other §10 mechanisms (gas markets, multi-dimensional gas accounting, etc.) operate as specified

**At phase transition (pool exhaustion or time cap):**
- Burn-to-mint path closes (no further burn claims possible)
- Validator reward source switches from pool to inflation-based issuance per §10's existing schedule (4% annual declining to 1%)
- All other mechanisms continue unchanged

**Total supply trajectory:**
- Block 0: 0 circulating, 100M in pool
- Block 0 to phase transition: circulating grows as pool drains; total = circulating + remaining pool ≤ 100M
- Phase transition: pool = 0; circulating ≤ 100M (less than 100M if time cap forced destruction of unclaimed)
- Post-transition: circulating grows via §10 issuance; EIP-1559 burn applies; long-run trajectory governed by §10's existing dynamics

**The genesis pool effectively acts as a one-time supply seeding event.** After it exhausts, supply dynamics are entirely determined by §10's operational regime, which remains unchanged from the existing whitepaper.

## Open calibration questions

The mechanism is structurally complete. Specific parameters require calibration work:

1. **Pool size (100M reference).** Sensitivity analysis under various participation distributions. Does 100M produce reasonable outcomes at 100, 1k, 10k, 100k, 1M participants? Where does it break?

2. **Conversion rates.** What rate of BTC → Adamant produces meaningful participation without absurdly cheap acquisition? Reference market caps and circulation patterns of existing privacy-focused chains as comparison.

3. **Cap schedule.** Are 1%/2%/4%/8%/no-cap the right thresholds? At what milestones do caps lift? Should caps be measured in token amount or fractional pool?

4. **Pool partition (70/30 burn/validator).** Is this the right split? At 80/20, validators struggle to bootstrap. At 60/40, validators get too much of the pool. Simulation needed.

5. **Validator reward calibration.** What block reward produces the validator-allocated drain over the target launch duration? Sensitive to assumed validator-set size.

6. **Time cap (5 years reference).** Too short and viable launches get cut off. Too long and the chain remains in launch phase indefinitely.

7. **Source chain integration details.** Burn address derivation, light-client proof formats, source-chain consensus assumptions, finality wait times.

## Failure modes considered

This mechanism could fail in several ways:

**Failure mode 1: Catastrophically low participation.** Pool barely drains in 5 years; time cap forces transition with most of the pool destroyed. Chain launches with tiny circulating supply. Operational phase begins but the chain is so small in absolute terms that it lacks the economic mass to attract validators or applications.

This is essentially the original burn-launch's low-participation failure mode preserved by the new design. The genesis pool doesn't *solve* low participation — it just gives it 5 years instead of 6 months. Mitigation is via marketing, narrative, and pre-launch credibility-building, not via mechanism design.

**Failure mode 2: Validator concentration.** Despite the 70/30 partition, the validator-allocated 30% concentrates in a small validator set if total validator count is low. Mitigation: minimum-stake-low bootstrap window (early validators with low stake requirements) plus active outreach to encourage diverse validator participation.

**Failure mode 3: Sybil fragmentation defeats the cap.** A determined adversary captures meaningful pool share via 10,000+ addresses. Result: the chain launches with a hidden whale. Mitigation is not mechanism-based — sybil resistance with privacy is a hard problem and we accept the residual risk.

**Failure mode 4: Calibration error produces broken dynamics.** Rates set wrong, partition set wrong, cap schedule misaligned with realistic participation. Result: the launch underperforms or overshoots in ways the design didn't anticipate. Mitigation: simulation-based calibration before mainnet; willingness to iterate on the calibration in the months before launch.

**Failure mode 5: Light-client verification compromise.** The cross-chain burn verification has a bug; an adversary mints Adamant tokens without actually burning external crypto. This would be catastrophic. Mitigation: extensive cryptographic review of the verification mechanism before mainnet; conservative finality wait times on source chains; formal verification of the verification logic.

## Path from this proposal to whitepaper amendment

Steps to take this from proposal to whitepaper-ready:

1. **Review and revise this document** with Ryan. Pieces 4-8 need critical engagement; the locked pieces 1-3 need to be confirmed as still acceptable in light of the full picture.

2. **Build a simulator.** A program that takes the mechanism's parameters and simulates participation distributions, drain patterns, and outcomes under various scenarios. This is real engineering work — likely 2-3 weeks. The simulator outputs lets us calibrate parameters with evidence rather than guesswork.

3. **Run scenario analysis.** Use the simulator to stress-test the design under low/medium/high participation, adversarial scenarios (whales, sybils, time-cap edge cases), and pathological inputs (oscillations, coordinated rushes, burn timing attacks). Identify failure modes the simulator surfaces that we didn't anticipate.

4. **Cryptoeconomics review.** Engage external reviewers — academic mechanism designers, experienced cryptoeconomic analysts, ideally people who have studied other launch mechanisms. They will find issues we won't.

5. **Legal review.** UK crypto-aware lawyer (already on Ryan's standing items list) — particularly important for the burn mechanism's regulatory characterisation, the cross-chain burn verification's relationship to securities law, and any jurisdiction-specific issues with the structure.

6. **Calibrate parameters to specific values** based on simulation evidence and reviewer feedback.

7. **Draft §10/§11 whitepaper amendment** incorporating the calibrated mechanism. Surface the amendment for review using the established whitepaper-amendment workflow. Land the amendment as a whitepaper commit. Update CONTRIBUTING.md if the design surfaces additional spec-first verification instances.

This is real work. Probably 2-4 months of effort distributed across simulation, review, calibration, and drafting. The launch is years away regardless; this work fits comfortably in the timeline.

## Why this proposal is recorded now rather than after the work is done

Capturing the design as a versioned proposal in the repo serves three purposes:

- **It records the thinking.** The reasoning behind why the constant-rate-plus-cap design was chosen (rather than dynamic algorithms), why pool partition was added (after surfacing the validator-concentration failure mode), why specific parameters are reference values rather than committed numbers — this reasoning is captured here, not lost to a chat conversation.

- **It creates a target for the calibration work.** The simulator and reviewers have a specific design to evaluate. Without this document, "what are we calibrating?" is itself ambiguous.

- **It establishes public commitment to the direction.** Anyone reading the Adamant repo sees this proposal and understands the launch model the project is working toward. This is stronger than a private design doc — it's an in-public commitment that allows external scrutiny.

The proposal is *not* a whitepaper amendment. The whitepaper is the chain's settled spec. This is a design document for what we're building toward. The two are different artifacts with different purposes.

## Status note

This document represents pieces 1-3 as locked design and pieces 4-8 as proposed design pending review. It does *not* yet represent settled design. The path forward is review, simulation, external evaluation, and calibration before any of this lands in the whitepaper.

The expected next action is Ryan reviewing pieces 4-8 with fresh attention and either approving them as drafted, requesting revisions, or rejecting specific pieces. After that review, the proposal stabilises and the calibration work begins.
