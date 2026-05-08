# Proposal: Low-Coordination Launch Architecture

**Status:** Draft for proposal-track deliberation (rev. 2)
**Affects:** §1.2, §1.4, §4 (Principle IV), §8.1.3, §8.7, §11
**Author:** Ryan Geldart
**Date:** 2026-05-08
**Prerequisites:** None
**Constitutional impact:** Substantial — affects Principle IV throughput target, §11 launch mechanism, §8.1 active set design

---

## Executive summary

Adamant's current whitepaper specifies a 200k TPS target requiring ~200 validators, with constitutional activation requiring 50 validators with 1M ADM staked at genesis. This shape requires a coordination event — discord countdown, recruited genesis cohort, cross-validator DKG ceremony — which is incompatible with Satoshi-style solo launch.

This proposal restructures the launch architecture to support genuine low-coordination launch by a single founder plus a small group of independent early operators, with the chain growing organically as community members discover and adopt it. The architecture shifts from "fixed-large-N from genesis" to "dynamic-N with low floor, growing toward design ceiling as adoption emerges."

Five linked changes, presented as a coherent shift:

1. Drop TPS target 200k → 50k (with empirical-validation caveat before genesis)
2. Dynamic active set (floor=7, ceiling 60-80) replacing fixed-200
3. Activation gate based on validator presence rather than coordination event
4. Halt-on-disagreement preserving safety at low N
5. On-chain security tier disclosure so wallets/applications can adapt

The seven core properties (no foundation, privacy by default, high throughput, sub-second finality, encrypted mempool, phone-verifiable, post-quantum) all remain, with sub-second finality and encrypted mempool requiring Proposal 4 (time-lock encryption fallback) to operate honestly during the low-N period.

---

## Problem statement

The current whitepaper assumes a coordinated genesis cohort:

- §1.2 lists "200,000+ TPS" as throughput target
- §8.1.3 specifies fixed active set of 200 validators
- §11.x specifies activation requires 50 validators with 1M ADM staked simultaneously
- §8.5 requires DKG ceremony among the active set, repeating every 36 seconds

Each of these assumes ~50-200 validators come online together at genesis, coordinate cryptographic ceremonies, and produce blocks from minute one. This is the architectural assumption of every modern PoS chain launch — Sui, Aptos, Sei, Celestia all launched with pre-recruited validator cohorts of 50-200 nodes.

Adamant's stated commitment to credibly-neutral solo-or-small-group launch is incompatible with this assumption. A single founder cannot be 50 validators. Even with family + early-adopter helpers, the chain is unlikely to have more than ~4-15 validators in its first weeks.

The current architecture also imposes hardware barriers that exclude the kind of participants Adamant exists to include:

- 200 validators each running consensus + threshold decryption + recursive proof generation requires VPS-grade hardware (~$300/month)
- This excludes residential-fiber operators, hobby validators, and most non-corporate participants
- The chain would launch with a corporate-validator profile, contradicting the credibly-neutral framing

---

## Proposed changes

### Change 1 — Throughput target revision: 200k TPS → 50k TPS

**Current §1.2:** "200,000+ transactions per second"

**Proposed §1.2:** "50,000+ transactions per second under design-target validator count, subject to empirical validation on residential-fiber hardware before genesis"

**Rationale:**

50k TPS is the throughput at which DAG-BFT communication cost (O(N²)) for an active set of 60-80 validators is operationally feasible on residential-fiber hardware. The 200k TPS target forced ~200 validators in the active set, which forced VPS-grade hardware for everyone.

**Sizing math (provisional, requires empirical validation):**

The validator-count documentation in earlier proposal-track work established that 200 validators at 200k TPS sit near the practical ceiling on 2025-era VPS-grade hardware. The communication cost is O(N²) and per-validator load scales linearly with N for sends and verifications, so a linear scaling argument suggests:

- 200k TPS @ N=200 (VPS): aggregate load reference point
- 50k TPS @ N=100 (VPS): same aggregate load, lower transaction throughput per validator
- 50k TPS @ N=50-80 (residential fiber): same aggregate load, fewer validators absorbing the per-validator-bandwidth saving

The proposed ceiling of 60-80 has slack on this math but is tight. **The 50k figure and the 60-80 ceiling are both subject to empirical validation on residential-fiber hardware before genesis.** If empirical results show 50k @ 60-80 is not deliverable on residential fiber, the choice is to either lower the TPS target further (e.g., to 25k) or raise the active-set ceiling (which raises the hardware floor). The proposal commits to the *shape* (residential-fiber-compatible, dynamic active set, low floor) and leaves the specific numbers calibratable before genesis.

**Competitive context:**

- Solana sustained throughput is ~3,000-4,000 TPS; theoretical peak ~50,000 TPS
- Sui sustained throughput is ~2,000-5,000 TPS; theoretical design ~120,000 TPS
- Aptos sustained throughput is ~2,000-4,000 TPS
- Visa average global throughput is ~1,700 TPS; peak ~24,000 TPS

50k TPS on a privacy-default L1 with sub-second finality and post-quantum signatures is genuinely state-of-the-art. The 200k headline was forcing architectural choices that compromised other goals.

**Trade-off acknowledged:**

The "fastest L1" marketing position is lost. Adamant becomes "fast enough for any realistic application, with privacy and post-quantum properties no other fast L1 has." This is arguably a more defensible market position than "fastest, slightly faster than Solana" — the differentiation is qualitative (privacy + PQ + credible neutrality) rather than quantitative.

### Change 2 — Dynamic active set with low floor

**Current §8.1.3:** Fixed active set of 200 validators.

**Proposed §8.1.3:**

- **Floor:** 7 validators (BFT minimum to tolerate 2 Byzantine validators with non-zero margin)
- **Ceiling:** 60-80 validators (set by 50k TPS calculation, subject to empirical validation per Change 1)
- **Current size:** all registered, online, and stake-eligible validators, capped at ceiling

If fewer than 7 validators are simultaneously online, the chain halts (see Change 4). If more than the ceiling are registered, a stake-weighted lottery selects the active set per epoch.

**Why floor=7, not floor=4:**

A floor of 4 was considered. At N=4 the BFT tolerance bound is f=1 (one Byzantine validator). This is the minimum to be Byzantine-fault-tolerant *at all*. The problem is zero margin: one Byzantine validator + one offline validator = safety bound violated. Real-world failures correlate (ISP outages, cloud regions, time zones, software bugs in shared dependencies, coordinated DDoS). At N=4 a single correlated event can take you from "fine" to "below safety threshold," and the chain has no margin to absorb it.

At N=7 the bound is f=2 (two Byzantine validators tolerated). One Byzantine + one offline simultaneously still leaves the chain within its safety bound. This gives genuine resilience margin against the kinds of failures that actually happen in practice.

The cost of floor=7 vs floor=4: solo launch requires 7 independent operators instead of 4. This is still small enough to be Satoshi-shaped (Bitcoin's first months had a comparable handful of independent participants), but it does require the founder to coordinate a slightly larger pre-launch group. In practice this is family + a few early-adopter friends + perhaps a couple of strangers from a public announcement — achievable without a foundation, a Discord countdown, or a recruited cohort.

The chain's safety properties are too important to ship with zero margin. Floor=7 is the responsible choice.

**Open Q-decisions:**

- **Q-1.** How does active set respond to validators going offline mid-epoch?
  - Recommendation: track registered-and-stake-eligible separately from currently-online; consensus quorum is computed on currently-online; offline validators don't lose stake immediately but face liveness slashing if extended outage causes consensus halts (per §8.1.5).
- **Q-2.** What is the lottery mechanism when registered validators exceed ceiling?
  - Recommendation: stake-weighted lottery per epoch via consensus VRF (§8.6) with high uptime weighting; epoch duration TBD by §8.4 work.
- **Q-3.** Does the floor lift as the chain matures?
  - Recommendation: floor stays at 7 indefinitely as constitutional minimum; in practice the active set will stabilize well above floor once network adoption reaches critical mass.

### Change 3 — Activation gate

**Current §11.x:** Chain activates when 50 validators with 1M ADM total stake are simultaneously registered.

**Proposed §11.x:**

The chain produces no blocks until 7 validators are simultaneously registered, stake-eligible, and online. Block 1 is produced via deterministic anchor election the moment that condition is met. There is no human-in-the-loop activation; the protocol activates itself.

**Rationale:**

- Removes coordination event entirely
- Removes human discretion from genesis (no "we hereby launch the chain" moment)
- Low-coordination launch becomes mechanically possible: founder registers validator 1 + family/friends register validators 2-N; chain remains dormant until 7 independent validators are simultaneously online; the chain self-activates
- Same shape as Bitcoin's small-group launch — no foundation, no countdown, no recruited cohort beyond the people who chose to run the binary

**Stake threshold question:**

The current "1M ADM staked" threshold prevents trivial-stake activation. In a small-group-launch model, three options exist:

- **(a)** No minimum stake threshold for activation. Chain activates at N=7 regardless of total stake. Stake discipline emerges via slashing economics.
- **(b)** Minimum per-validator stake (e.g., 1000 ADM minimum) to register; no aggregate threshold.
- **(c)** Aggregate minimum (e.g., 7000 ADM total) — low enough to be founder-feasible but non-trivial.

Recommendation: (b). Per-validator minimum prevents zero-stake spam; no aggregate threshold preserves low-coordination feasibility. Specific minimum amount TBD by economic analysis.

**Honest framing for §11:**

Suggested §11 amendment text:

> "Adamant was designed and built by Ryan Geldart. The chain activates when 7 validators are simultaneously registered, stake-eligible, and online; this is expected to include the designer and early independent operators who discover Adamant during the activation period. No party retains protocol-level powers post-genesis: no admin keys, no foundation treasury, no governance role for any pre-genesis party."

This is accurate without inviting capture-by-association concerns. It matches the actual launch shape.

### Change 4 — Halt-on-disagreement at low N

**Current §8.7 (consensus safety and liveness):** Standard BFT liveness assumed; safety preserved under f<N/3 Byzantine.

**Proposed §8.7 amendment:**

When the active set is at or near the floor (N=7-15), the chain halts on disagreement rather than forking. If quorum cannot be reached (validators offline, partition, conflicting proposals), the chain pauses until quorum is restored. Safety is preserved (no double-spends, no forks). Liveness is weak at low N — this is an honest cost, not a hidden one.

**Liveness math (provisional):**

At N=7 with independent 99% per-validator uptime, the probability that at least 5 validators (the 2/3+1 quorum threshold) are simultaneously online is roughly 99.97%. At 36s epochs, this implies ~1 halt per several days at the floor — not trivial but not deal-breaking. Real-world correlation will make actual halt frequency higher than independence suggests; the chain should expect occasional halts of a few epochs in its first months.

This is the same shape Bitcoin had in its early months: occasional halts, slow growth, weak guarantees. The chain is honest about being weak when it is weak.

**Open Q-decisions:**

- **Q-4.** What is the timeout before chain marks a validator as "offline" for quorum purposes?
  - Recommendation: short timeout (e.g., 60 seconds) to preserve liveness; longer timeout for liveness-slashing decisions.
- **Q-5.** What happens to halted-chain user transactions?
  - Recommendation: pending transactions remain in encrypted mempool until quorum is restored; no transaction loss.

### Change 5 — On-chain security tier disclosure

Wallets, applications, and users need to evaluate the chain's current security level. This requires standardized on-chain disclosure.

**Proposed §8.x new section:**

The chain commits a verifiable on-chain property indicating current active-set size and resulting security tier:

- **Tier I (low):** N=7-14 validators. Suitable for: simple transfers, validator registrations, low-value transactions. Not suitable for: high-value contracts, large-stake DeFi, critical applications.
- **Tier II (medium):** N=15-29 validators. Suitable for: most user transactions, moderate-value contracts. Not suitable for: critical-mission applications.
- **Tier III (full):** N=30+ validators. Full design-target security. Any application.

Wallets read this property and adjust UX accordingly. Applications can choose to gate features by tier (e.g., "this contract requires Tier II minimum").

The Tier I → Tier II boundary at N=15 aligns with Proposal 4's recommended threshold for switching from time-lock to threshold-encrypted mempool, so the security tier and the encryption mechanism transition at the same point.

**Rationale:**

- Honest disclosure is the load-bearing property that makes Tiers I and II acceptable
- Wallets/applications get a standardized signal, not ad-hoc validator-counting logic
- Users get explicit transparency about what the chain currently supports
- "The chain doesn't pretend to be strong when it isn't"

**Open Q-decisions:**

- **Q-6.** Are tier boundaries hard or advisory?
  - Recommendation: advisory at protocol level; binding at application level via opt-in. Wallets should warn but not block; applications can enforce minimum tier for their own use.
- **Q-7.** Is tier publicly readable without full-node sync?
  - Recommendation: yes; tier is a constant-time queryable chain state property accessible to light clients.

---

## Constitutional implications

**Principle IV (high throughput):** Restated from "200,000+ TPS" to "50,000+ TPS at design-target validator count, subject to empirical validation before genesis." Substantive constitutional change requiring §1.2 amendment.

**Principle II (privacy by default):** Affected during low-N period if Proposal 4 is approved (time-lock fallback has weakened MEV protection at very low N — see Proposal 4's Change 4 acknowledgment). Unchanged at design-target N.

**Principle V (sub-second finality):** Affected during low-N period via Proposal 4's time-lock fallback. Unchanged at design-target N.

**Credible neutrality (Principle I):** Strengthened. Low-coordination launch with organic adoption is more credibly neutral than coordinated 50-validator genesis. §11 amendments preserve "no foundation, no admin keys, no governance" while being honest about launch shape.

---

## Implementation impact

**Phase 5 (verifier work):** Unaffected. Verifier validates bytecode regardless of consensus shape.

**Phase 6+ (consensus implementation):** Affected. Active set logic, activation gate, halt-on-disagreement, security tier disclosure all become Phase 8 (consensus) work. DKG ceremony specification needs revision; epoch logic needs revision.

**Empirical validation work (pre-genesis):** New requirement. Before genesis, the reference implementation must demonstrate 50k TPS at N=60-80 on residential-fiber hardware in a representative network topology. If empirical results fall short, the proposal's TPS target or active-set ceiling must be re-calibrated. This is gating work for §1.2's claim.

**Whitepaper sections affected:**

- §1.2 (throughput target with empirical-validation caveat)
- §1.4 (no-team framing — minor adjustment to match honest launch shape)
- §4 Principle IV (throughput target restated)
- §8.1.2 (validator becoming process)
- §8.1.3 (active set)
- §8.5 (DKG ceremony — interacts with Proposal 4)
- §8.7 (safety and liveness)
- §11 (genesis activation, launch framing)

---

## Dependencies on other proposals

This proposal interacts with the others in the set:

- **Proposal 4 (time-lock encryption fallback)** is required to make the low-N period work honestly. Without it, the encrypted mempool either (a) doesn't run at low N (Principle II violated during launch) or (b) runs with fake/weak threshold encryption (dishonest disclosure). Proposal 4 fills this gap.
- **Proposal 1 (hybrid signatures)** reduces validator bandwidth, which makes the residential-fiber assumption more comfortable at the low end of the active-set ceiling.
- **Proposal 3 (prover market)** reduces validator hardware requirements further by removing the GPU-class workload from validators, which makes residential-fiber participation more accessible.
- **Proposal 5 (witnesses)** broadens the participation surface beyond the active set, providing a tier of phone-runnable security work that complements the validator tier.

This proposal can technically be approved alone, but the launch shape it specifies is operationally weak unless Proposal 4 is also approved. The set is most coherent approved together.

---

## Recommendation

Approve. The five linked changes form a coherent architectural shift that aligns Adamant's launch shape with its stated values (low-coordination founder launch, credibly neutral, accessible to non-corporate participants).

The trade-offs are real (50k TPS not 200k; weak liveness at low N; tier-based security disclosure; floor=7 requires 7 independent launch-day operators) but each trade-off is structurally honest and matches the chain's actual properties.

Pending: Q-1 through Q-7 sub-decisions during proposal-track deliberation. Empirical TPS validation is gating work before §1.2 lands at v1.0.

---

## Cross-references

- Witness-tier proposal (parallel proposal-track work)
- Stake-cap mechanism proposal (parallel proposal-track work)
- Validator-count documentation amendment (parallel proposal-track work)
- Proposal: Permissionless prover market (linked; reduces validator hardware further)
- Proposal: Watcher tier integration (linked; broadens participation beyond active set)
- Proposal: Time-lock encryption fallback (linked; required dependency for low-N encrypted mempool)
- Proposal: Hybrid signature model (linked; addresses signature size at high TPS)
