# Proposal: Permissionless Prover Market

**Status:** Draft for proposal-track deliberation (rev. 2)
**Affects:** §1.2 (Principle III), §8.5, §9.10, §10, §11
**Author:** Ryan Geldart
**Date:** 2026-05-08
**Prerequisites:** None (independently approvable)
**Constitutional impact:** Moderate — adds new participation tier, modifies validator role boundary, requires honest framing of phone-verifiability dependency

---

## Executive summary

The current whitepaper conflates three distinct roles into the validator tier: consensus participation, threshold mempool decryption, and recursive proof generation. This bundling forces validator hardware to the highest common denominator (GPU-class for proof generation), excluding residential-fiber operators.

This proposal splits recursive proof generation into a permissionless prover market separate from the validator tier. Validators do consensus + threshold decryption only. Anyone with a GPU runs as a prover, paid per proof in fees. Provers cannot censor or reorder transactions; their power is bounded to "produce proofs faster and cheaper than competitors."

Result: validator hardware drops to consumer-desktop tier; proof generation gets a competitive market; prover compensation is a new revenue source for GPU operators.

**One important honesty pass:** Principle III (phone-verifiable, §1.2) depends on recursive proofs being produced. If the prover market doesn't materialize at sufficient scale, phone-verifiability degrades for that period. The proposal addresses this with a validator-fallback mechanism (Change 5) that ensures proofs are always produced, with prover-market efficiency as the optimization rather than a load-bearing dependency.

---

## Problem statement

The current §8.5 specifies that validators generate recursive proofs of consensus state every block. The proof is computationally expensive — Halo 2 / Plonky2 / similar recursive SNARK systems require GPU acceleration to produce proofs at the cadence Adamant requires (sub-second finality means proofs every ~500ms).

This forces every validator to run GPU-class hardware. Three consequences:

1. **Hardware barrier.** GPU-class hardware (consumer RTX 4090 minimum, often A100/H100 for serious operators) costs $2,000-$30,000 capex plus ongoing power. This excludes most residential-fiber operators.

2. **Geographic concentration.** GPU-class hardware tends to live in datacenters, not homes. Validator network shifts toward datacenter-hosted, undermining Adamant's stated decentralization goals.

3. **Role conflation.** Consensus participation (cryptographic message exchange, state agreement) is fundamentally different work from proof generation (intensive computation). Making the same node do both forces sub-optimal hardware allocation in both directions.

The current architecture reflects an engineering shortcut from the design phase, not a principled decision. Splitting roles is the cleaner architecture.

---

## Proposed changes

### Change 1 — Role split

**Validators:**

- Run consensus (DAG message exchange, vote production)
- Run threshold mempool decryption (or time-lock decryption per Proposal 4 at low N)
- Maintain chain state
- Generate proofs as fallback when external prover supply is insufficient (see Change 5)
- Hardware: consumer desktop on residential fiber (~$1,500-$2,500 capex). Validators must have *some* proof-generation capability for fallback duty, but not at the cadence required for the steady-state market — a desktop CPU + integrated GPU is sufficient for fallback at degraded cadence.

**Provers:**

- Generate recursive proofs of consensus state at the steady-state cadence (every block at design-target throughput)
- Submit proofs to validators
- Hardware: GPU class (RTX 4090, A100, H100, similar)
- Permissionless: anyone can register as a prover; no stake required to run; no Sybil resistance needed (see Q-1 below)

### Change 2 — Prover registration and operation

**Permissionless registration:** Provers register an on-chain identity (public key) and are eligible to submit proofs immediately. No stake, no application, no approval.

**Proof submission:** Validators broadcast "proof needed for state X" requests; provers race to produce proofs and submit. First valid proof submission wins the bounty; losing proofs are discarded (no compensation for losers).

**Proof verification:** Validators verify submitted proofs cheaply (recursive SNARK verification is fast; only generation is expensive). Verified proofs become part of chain state.

**Compensation:** Per-proof bounty paid from transaction fees + small slice of issuance. Bounty amount calibrated to cover GPU operating cost + competitive margin.

### Change 3 — Bounded prover power

Provers cannot:

- Censor transactions (they don't see plaintext mempool; they prove validator-produced state)
- Reorder transactions (validator consensus determines ordering; provers prove the result)
- Halt the chain (if no prover submits a proof, validators continue producing blocks; validator-fallback per Change 5 takes over for proofs)
- Validator-substitute (provers cannot vote in consensus or affect block production)

Provers can:

- Refuse to produce proofs (other provers compete; validator-fallback covers gaps)
- Compete on speed/cost (this is the intended dynamic)
- Operate anywhere geographically (no consensus-binding latency requirement)

This bounded-power posture is what makes permissionless proving safe.

### Change 4 — Compensation flow

**Per-proof bounty:** A fixed slice of the transaction-fee pool from the proof's covered block range. Specific percentage TBD by economic analysis. Suggested starting point: 10% of fees.

**Issuance slice:** Optional small inflationary subsidy if fee-based compensation alone is insufficient at low TPS. Suggested starting point: 0% (fee-based only); revisit if empirical data shows prover undersupply.

**Claim mechanism:** Prover submits proof along with claim instruction; validator verification of proof releases bounty to prover's address.

**Validator-fallback compensation:** When a validator generates a fallback proof per Change 5, the validator receives the same bounty the prover would have received. This avoids creating an incentive imbalance where validators would prefer the market to stay broken.

### Change 5 — Validator-fallback for phone-verifiability

**The honest dependency:**

Principle III (phone-verifiable, §1.2 / §2.3) commits the chain to producing recursive proofs that any phone can verify. Splitting proof generation off to a prover market makes this commitment dependent on the market's existence. If no provers register, or all registered provers go offline, the chain still produces blocks (per Change 3) — but it stops producing recursive proofs, which means light clients cannot continue verifying without trusting full nodes. Principle III breaks during such a period.

**The fallback mechanism:**

The protocol specifies a fallback: if no prover submits a valid proof for a target state within a timeout window, the active validators take over proof generation themselves at a degraded cadence. Specifically:

- **Steady-state cadence (prover-market healthy):** one proof per block, ~500ms cadence, produced by external provers
- **Fallback cadence (no prover bid within timeout):** one proof per N blocks (e.g., one proof per 10 blocks, ~5s cadence), produced by validators on their own hardware
- **Transition is automatic:** if the prover market becomes responsive again, the chain returns to steady-state cadence on the next successful prover submission

The fallback cadence is intentionally degraded — proofs every 5 seconds rather than every 500ms. This is what allows validators to do the work on consumer-desktop hardware rather than GPU-class. Phone-verifiability is preserved (proofs still exist, still verifiable) but with longer freshness windows during fallback periods.

**The constitutional commitment:**

The protocol commits to "phone-verifiable proofs are produced," not "phone-verifiable proofs are produced every 500ms." Steady-state cadence is the design target; fallback cadence is the floor below which the chain refuses to fall.

This means Principle III is constitutionally honest: the chain *always* produces phone-verifiable proofs, with the prover market providing the steady-state efficiency rather than the underlying capability. If the market collapses entirely, the chain operates at fallback cadence indefinitely until the market recovers — slower but still phone-verifiable.

### Change 6 — Honest framing of prover market

The prover market is an *optimization*, not a *requirement*. The chain works without it (at fallback cadence). The market provides:

- Faster proof cadence (500ms vs 5s)
- Lower proof costs at scale (specialized GPU operators can produce proofs more cheaply per unit than validators using fallback hardware)
- Market discipline on proof costs (competition keeps bounty calibration honest)

Without the market, the chain operates at fallback cadence with proofs absorbed by validators. Light-client verification still works; UX is somewhat worse (longer freshness windows); the chain is not broken.

This framing is structurally similar to how §9.10 already frames the service-node market: "the chain functions correctly whether or not the service-node market materialises." The prover market gets the same posture.

---

## Open Q-decisions

**Q-1.** Should provers post stake or post bond?

Recommendation: no. Permissionless registration is the design intent. Provers cannot harm the chain (bounded power per Change 3); slashing would only deter participation without security benefit. Invalid proofs are simply rejected at verification, costing the prover their work-time but not the chain anything.

**Q-2.** What happens if no prover produces a proof for an extended period?

**RESOLVED via Change 5:** Validators generate fallback proofs at degraded cadence. Phone-verifiability preserved. The market's absence is a UX cost (longer freshness windows), not a constitutional failure.

**Q-3.** Can a validator also be a prover?

Recommendation: yes, but probably not optimal. Operationally distinct hardware profiles favor specialization. A validator running residential desktop hardware shouldn't routinely run GPU work as a prover; a prover with GPU hardware shouldn't waste it on consensus message-passing. However, validators *must* be capable of fallback proof generation (Change 5), so the boundary is "validators run proof generation as fallback duty; specialization happens via the prover market on top of that."

**Q-4.** How is bounty amount calibrated?

Recommendation: dynamic adjustment based on prover supply. If proofs consistently produced quickly, bounty decreases (provers competing for under-priced work). If proofs lag (and validator fallback is engaged frequently), bounty increases. Specific algorithm TBD; can mirror EIP-1559 base-fee adjustment shape.

**Q-5.** Are proofs publicly verifiable, or only by validators?

Recommendation: publicly verifiable. Recursive SNARK verification is cheap; any node (full or light) can verify proofs. This is what makes the proof system useful for light-client work and for Proposal 5's witness tier.

**Q-6.** Are provers anonymous, or do they need to register identity?

Recommendation: pseudonymous. Provers register a public key; that's their identity for compensation purposes. No real-world identity binding required.

**Q-7.** Is the prover market constitutional or implementation-detail?

Recommendation: the *role split* (validators vs provers) is constitutional. The *market mechanism* (bounty, registration, competition) is implementation-detail. The *fallback mechanism* (Change 5) is constitutional. §11 commits to: "consensus and proof generation are separate roles; proof generation is permissionless and market-supplied at steady state; validators provide fallback proof generation at degraded cadence to preserve Principle III when the market is insufficient."

**Q-8.** What is the fallback timeout?

Recommendation: short — perhaps 2-5 seconds — so that prover-market gaps are quickly absorbed by validator fallback rather than letting proof gaps accumulate. Specific value TBD by empirical analysis during Phase 8 implementation.

**Q-9.** Does the fallback cadence (proofs per N blocks) decrease as N (active set size) grows?

Recommendation: no. Fallback cadence is determined by per-validator hardware capability, not by N. Validators can parallelize fallback proof work across the active set, but the per-proof cost is constant — what changes with N is reliability (more validators means lower probability that all fail simultaneously), not throughput.

---

## Constitutional implications

**Principle I (no foundation):** Strengthened. Permissionless prover market means no party controls steady-state proof generation; no foundation can capture this work.

**Principle II (privacy by default):** Unchanged. Provers prove validator-produced state; they don't see decrypted mempool content.

**Principle III (phone-verifiable):** PRESERVED via Change 5 fallback. Without the fallback, this proposal would weaken Principle III; with it, the constitutional commitment holds at degraded cadence even when the market collapses.

**Principle V (sub-second finality):** Unchanged at steady state. During fallback periods, proof freshness windows extend (5s rather than 500ms), but transaction finality (which is a consensus property, not a proof property) is unaffected.

**§9.10 service-node tier:** Clean alignment. Adamant has multi-tier participation framing (validators, witnesses if Proposal 5 approved, service nodes per §9.10). Provers extend this naturally, each tier with bounded power.

---

## Implementation impact

**Phase 6+ (AVM runtime):** Minor — provers consume same on-chain APIs as any node.

**Phase 7 (privacy layer):** Minor — privacy circuits unchanged; provers prove the recursive verification of those circuits.

**Phase 8 (consensus):** Substantial — proof generation logic moves from validator code path to prover-network protocol. Validator code retains fallback proof generation (degraded cadence) per Change 5. New prover protocol (proof bounty, submission, verification, claim, fallback transition).

**Phase 9 (networking):** Substantial — prover network protocol; proof distribution; bounty payment flow.

**Phase 10 (economics):** Substantial — bounty pool, dynamic adjustment, compensation flow, validator-vs-prover revenue split, fallback compensation.

**Whitepaper sections affected:**

- §1.2 (Principle III phrasing — clarify "phone-verifiable" includes both steady-state and fallback cadences)
- §8.5 (recursive proof generation — major rewrite covering market + fallback)
- §9.10 (service-node tier — extend framing to cover prover sub-tier)
- §10 (economics — add prover compensation flow; fallback compensation)
- §11 (genesis — commit to role split + fallback mechanism as constitutional)

---

## Dependencies on other proposals

- **Proposal 2 (low-coordination launch)**: this proposal lowers validator hardware further (no GPU requirement at steady state), enabling the residential-fiber assumption at the low end of the active-set ceiling. Particularly important during the low-N period when fallback proof generation may be engaged more often.
- **Proposal 5 (witnesses)**: witnesses verify prover output. This proposal's existence is part of the foundation for that one. Both work together: provers produce, witnesses verify, validators consume.

This proposal can be approved alone, but Proposals 2, 4, and 5 form a more coherent architectural set together.

---

## Recommendation

Approve. The role split is good engineering on its own terms — it would be the right architecture even without solo-launch concerns. The fact that it also dramatically lowers validator hardware barriers (consumer desktop vs GPU class) is a significant secondary benefit.

The Change 5 fallback mechanism is what makes this proposal constitutionally honest. Without it, Principle III becomes dependent on a market that may or may not materialize. With it, the chain is honest about what depends on what.

The "validators do consensus + decryption + fallback proofs; provers do steady-state proofs at higher cadence" boundary is structurally clean and matches the natural hardware/work profile of each role.

Pending: Q-1, Q-3, Q-4, Q-5, Q-6, Q-7, Q-8, Q-9 sub-decisions during proposal-track deliberation. Q-2 is resolved via Change 5.

---

## Cross-references

- Proposal: Low-coordination launch architecture (linked; this proposal lowers validator hardware further)
- Proposal: Watcher/witness tier (linked; witnesses verify prover output as defense-in-depth)
- §1.2 / §2.3 (Principle III — phone-verifiable; framing clarified by this proposal)
- §8.5 (recursive proof generation — major rewrite by this proposal)
- §9.10 service-node infrastructure (parent framework; provers are a sub-tier)
