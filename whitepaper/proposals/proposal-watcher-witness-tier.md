# Proposal: Watcher Tier Integration (Witness Tier Naming Resolution)

**Status:** Draft for proposal-track deliberation (rev. 2)
**Affects:** §1.4, §9, §11
**Author:** Ryan Geldart
**Date:** 2026-05-08
**Prerequisites:** None for tier specification; cross-tier dependencies acknowledged in §"Dependencies" below
**Constitutional impact:** Moderate — adds participation tier per existing witness-tier proposal

---

## Executive summary

The "nine solutions" framing surfaced a "watcher tier" for phones and basic laptops doing data availability sampling, recursive proof verification, and fraud detection. This is the same design space as the witness-tier proposal already drafted in proposal-track work. This proposal resolves the naming question and integrates the watcher framing's emphases (phone-first participation, fraud detection role) into the existing witness-tier proposal.

Result: one tier, multiple roles (verification attestation + watcher functions), one name.

The proposal also tightens its honest framing about cross-tier dependencies, particularly with the prover market (Proposal 3): witnesses verify prover output, so the witness tier's utility depends on a tier (provers) that witnesses don't control. The constitutional commitment acknowledges this dependency chain.

---

## Problem statement

Two parallel proposals describe the same design space:

- **Witness-tier proposal:** Cryptographic-attestation tier; witnesses attest to vertex/proof validity; binds to Adamant's privacy-first design via attestation discipline.
- **Watcher functionality** (from nine-solutions framing): Phone-runnable tier doing data availability sampling, recursive proof verification, fraud detection.

These are not two tiers — they're two angles on the same tier. The chain needs *one* sub-validator participation tier, with multiple roles, one name, one constitutional framing.

The naming question:

- **"Witness"** — cryptographic precedent (zk witness). Risk: confusion with "witness" in cryptographic-circuit sense.
- **"Watcher"** — plain-language clear. Risk: perhaps too informal for constitutional framing.

---

## Proposed changes

### Change 1 — Single tier, multiple roles

The tier (whichever name) provides:

**Role A — Cryptographic attestation:** Witnesses produce signed attestations for valid vertices, valid proofs, valid state transitions. Used for light-client verification, cross-chain bridge integrity, dispute resolution.

**Role B — Data availability sampling:** Witnesses sample chain data (random vertex requests, random transaction requests) and verify availability. Failed samples flag potential availability attacks.

**Role C — Recursive proof verification:** Witnesses verify the recursive proofs produced by the prover market (Proposal 3) or by validator-fallback proof generation (Proposal 3 Change 5). Verification is cheap; redundant verification across many witnesses provides defense-in-depth.

**Role D — Fraud and reordering detection:** Witnesses watch for invalid state transitions, double-spending attempts, validator misbehavior, and suspicious anchor reordering during the time-lock period (Proposal 4 Change 4 / Q-8). Detected fraud triggers slashing claims; suspicious reordering triggers reputational signals on anchors.

All four roles run on the same tier, on the same hardware (phones, laptops, residential desktops). No specialization required.

### Change 2 — Naming resolution

Three options:

- **(a)** Use "witness" throughout. Cryptographic precedent; fits Adamant's privacy-circuit context. Witnesses do attestation + sampling + verification + detection.
- **(b)** Use "watcher" throughout. Plain-language clear; less overloaded. Watchers do attestation + sampling + verification + detection.
- **(c)** Use "witness" for Role A specifically; use "watcher" for Roles B-D. Two terms, two scopes.

**Recommendation: (a) "witness" throughout.** Three reasons:

1. **Cryptographic precedent.** Adamant is a privacy-default chain with extensive ZK circuit work. "Witness" is the standard term in that domain. Users coming from cryptographic background will recognize it.

2. **Constitutional gravitas.** "Witness" reads like a constitutional role; "watcher" reads like an operational role. For §11 framing, witness has the right register.

3. **Consolidation simplicity.** One term, one tier, one constitutional commitment. Two-term framing creates confusion about whether they're the same tier or different tiers.

The "watcher" framing's emphases (phone-runnable, broad participation, fraud detection) are absorbed into the witness tier's role specification rather than carved out into a separate tier.

### Change 3 — Hardware target

Witnesses run on:

- Modern smartphones (data availability sampling on a phone is feasible at low duty cycle)
- Basic laptops (full role suite tractable)
- Residential desktops (over-provisioned but fine)

Witnesses do not need:

- GPU acceleration (proof verification is cheap; that's the whole point of recursive proofs)
- Datacenter-class network (intermittent connectivity acceptable)
- High availability (witnesses can be online when convenient; system tolerates churn)

This is the design intent: massive expansion of the participation pool beyond validators.

### Change 4 — Compensation

Per existing witness-tier proposal: small fee slice from transaction fees + small slice of issuance.

Specific calibration TBD by economic analysis. Witness compensation should be:

- Sufficient to incentivize participation (covers operating costs + small reward)
- Small enough to not displace validator economics
- Calibrated against expected witness count (compensation per witness decreases as witness population grows)

### Change 5 — Sybil resistance

Witnesses face less stringent Sybil resistance than validators because witness power is more bounded:

- A validator can affect consensus; Sybil-controlled validators can attack the chain
- A witness produces attestations; Sybil-controlled witnesses can produce false attestations but other witnesses' counter-attestations expose the fraud
- A witness samples for data availability; Sybil-controlled witnesses can claim availability falsely but other witnesses' real samples expose the fraud

Recommended Sybil resistance mechanism: small stake requirement per witness (e.g., 100 ADM) + rate-limiting on attestation production. Specific parameters TBD by existing witness-tier proposal deliberation.

### Change 6 — Honest framing of cross-tier dependencies

The witness tier's utility depends on tiers that witnesses don't directly control. The constitutional commitment must acknowledge this honestly rather than pretend the witness tier is self-sufficient.

**Specific dependencies:**

1. **Witness Role C (recursive proof verification) depends on proofs being produced.** This depends on the prover market (Proposal 3) being healthy, or — when the market is insufficient — on validator-fallback proof generation (Proposal 3 Change 5). If neither produces proofs, witnesses have nothing to verify in Role C; the role goes idle. This is bounded: Roles A, B, and D continue to operate.

2. **Witness Role D (reordering detection during time-lock period) is reputational, not cryptographic.** During the time-lock encryption period (Proposal 4), witnesses observe anchor decryption-and-publication patterns. They can flag suspicious reordering, but the chain has no cryptographic slashing for this surface — anchors who reorder face reputational pressure rather than stake destruction. Witness Role D is materially weaker than the cryptographic slashing that backs witness fraud-detection of validator equivocation.

3. **The four-tier multi-tier participation framework** (validators / provers / witnesses / service nodes) is interdependent. Each tier's effectiveness depends on the others functioning. The chain is honest about this rather than pretending each tier is independent.

**Constitutional framing for §11:**

Suggested §11 amendment text:

> "The witness tier provides phone-runnable participation in chain security via attestation, data availability sampling, recursive proof verification, and fraud/reordering detection. Witness utility depends on the integrity of tiers witnesses verify (validators, provers); when those tiers function, witnesses provide defense-in-depth and broaden the participation surface; when those tiers fail in ways witnesses cannot detect cryptographically, witness attestations are reputational rather than enforceable. This is an honest cost of the multi-tier architecture, not a hidden one."

---

## Open Q-decisions

**Q-1.** Final name resolution: witness, watcher, or split-naming?

Recommendation: "witness" throughout. See Change 2 rationale.

**Q-2.** Are all four roles mandatory, or can witnesses opt into a subset?

Recommendation: all roles available; witnesses can choose participation level. A phone-witness might do only data availability sampling; a laptop-witness might do full role suite. Compensation scales with role coverage.

**Q-3.** Constitutional commitment level?

Recommendation: tier exists in §11 as constitutional; specific role parameters (compensation %, sample rate, etc.) live in implementation detail and can be calibrated.

**Q-4.** Coordination with existing witness-tier proposal?

This proposal supersedes / consolidates the existing witness-tier proposal. Existing proposal stays as design rationale source; this one is the implementation-track resolution.

**Q-5.** What happens to witnesses during periods when prover market is in fallback (Proposal 3 Change 5)?

Recommendation: Role C continues — witnesses verify validator-fallback proofs at the same cadence the validators produce them (every N blocks rather than every block). Compensation in Role C scales with proof count, so witnesses earn less per unit time during fallback periods, which is correct (less work to do means less to pay for).

**Q-6.** Is Role D (reordering detection) compensated?

Recommendation: yes, but lightly. Role D is reputational rather than cryptographically enforceable, so its compensation is capped relative to Roles A-C. Witnesses who flag legitimate suspicious reordering and whose flags are corroborated by other witnesses earn small bonuses; false flags cost the witness reputation but no stake (since the surface is reputational on both sides).

---

## Constitutional implications

**Principle I (no foundation):** Strengthened. Witness tier broadens chain participation beyond validator-class operators, reducing power concentration.

**Principle II (privacy by default):** Unchanged. Witnesses operate on chain state, not on user privacy state.

**Phone-verifiability (current §1.4 commitment):** Materially strengthened. Witnesses are *the* mechanism by which phones meaningfully participate in chain security beyond passive verification. This commitment is contingent on Role C, which is contingent on proof production (Proposal 3), per the dependency framing in Change 6.

**Multi-tier participation framework:** Tier count grows to four:

- **Tier 1 — Validators:** consensus + threshold/time-lock decryption + fallback proof generation (Proposals 2, 3, 4 scope)
- **Tier 2 — Provers:** steady-state recursive proof generation (Proposal 3 scope)
- **Tier 3 — Witnesses:** attestation + sampling + verification + fraud/reordering detection (this proposal)
- **Tier 4 — Service nodes:** §9.10 infrastructure (existing)

Each tier has bounded power; no tier alone controls the chain. Each tier's effectiveness depends on the others; this interdependence is acknowledged constitutionally rather than hidden.

---

## Implementation impact

**Phase 6+ (AVM runtime):** Minor.

**Phase 8 (consensus):** Moderate — witness attestations may interact with consensus state commitments.

**Phase 9 (networking):** Substantial — witness gossip protocol, attestation distribution, sample request/response, fraud claim submission, reordering-flag submission.

**Phase 10 (economics):** Moderate — witness compensation flow, including fallback-period scaling per Q-5 and reputational bonuses per Q-6.

**Whitepaper sections affected:**

- §1.4 (multi-tier participation framing)
- §9 (witness tier specification — new sub-section)
- §10 (witness compensation)
- §11 (constitutional commitment to four-tier shape with honest dependency framing per Change 6)

---

## Dependencies on other proposals

This proposal interacts with the others in the set:

- **Proposal 3 (prover market)**: witnesses verify prover output (Role C) and validator-fallback proof output. Without Proposal 3's Change 5 fallback, Role C would have load-bearing dependency on a market that may not materialize. With it, Role C operates at the cadence proofs are produced — fast during steady state, slower during fallback, but never absent.
- **Proposal 4 (time-lock encryption)**: witnesses provide the reputational layer for anchor-reordering detection (Role D). Without Proposal 4, Role D is unnecessary; with it, Role D fills the gap left by the lack of cryptographic slashing for the reordering surface.
- **Proposal 2 (low-coordination launch)**: witnesses broaden the participation surface during the low-N period when the active validator set is small. This is the period when the multi-tier framework provides the most value.
- **Proposal 1 (hybrid signatures)**: witnesses verify Ed25519 and ML-DSA signatures as part of Roles A and C. The hybrid model adds complexity but does not change the witness role substantively.

The "independently approvable" framing in earlier drafts of this proposal understated these dependencies. This revision tightens that framing: the witness tier specification can be approved alone, but its operational utility is co-determined with Proposals 2, 3, and 4.

---

## Recommendation

Approve. The watcher framing's emphasis on phone-runnable participation strengthens the witness-tier design rather than displacing it. One tier, multiple roles, one name resolves the apparent overlap.

The four-tier participation framework (validators / provers / witnesses / service nodes) creates a participation gradient from high-stake-high-power (validators) to low-stake-broad-participation (witnesses), aligning with Adamant's stated value of accessible decentralization.

The honest dependency framing (Change 6) is what makes this constitutionally rigorous. Earlier drafts implied the witness tier was self-sufficient; this revision acknowledges that witness utility depends on the integrity of tiers witnesses verify, and frames this honestly rather than hiding it.

Pending: Q-1 through Q-6 sub-decisions during proposal-track deliberation.

---

## Cross-references

- Witness-tier proposal (existing; this proposal supersedes/consolidates)
- Proposal: Low-coordination launch architecture (linked; witnesses provide phone-verifiable security broader than validator-only)
- Proposal: Permissionless prover market (linked; witnesses verify prover output as defense-in-depth; Role C cadence depends on Proposal 3 Change 5 fallback)
- Proposal: Time-lock encryption fallback (linked; witnesses provide Role D reordering detection during low-N period)
- §9.10 service-node tier (parent framework)
