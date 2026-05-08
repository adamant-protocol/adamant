# Proposal: Time-Lock Encryption Fallback at Low N

**Status:** Draft for proposal-track deliberation (rev. 2)
**Affects:** §1.2, §2.2 (Principle II), §4 (Principle V), §8.4, §8.5, §11
**Author:** Ryan Geldart
**Date:** 2026-05-08
**Prerequisites:** Proposal: Low-coordination launch architecture (this proposal addresses the encrypted-mempool gap that proposal creates)
**Constitutional impact:** SUBSTANTIAL — modifies Principle V (sub-second finality) and qualifies Principle II (privacy/MEV protection) during early-chain period

---

## Executive summary

Threshold-encrypted mempool requires DKG (distributed key generation) ceremony among the active validator set. DKG cannot run with N=1 or N=2; it requires a coordinated active set. This is incompatible with low-coordination-launch architecture.

This proposal adds time-lock encryption as a low-N fallback. Time-lock encryption decrypts via sequential VDF computation rather than threshold cryptography; it works at N=1. The chain switches from time-lock to threshold encryption automatically when active set crosses a transition threshold (suggested N≥15).

**Two substantive trade-offs:**

1. **Sub-second finality (Principle V) is broken during the time-lock period.** Time-lock decryption introduces 10-30 seconds of latency between transaction submission and execution.

2. **MEV protection (Principle II) is quantitatively weaker during the time-lock period.** The validator who finishes the VDF computation first sees decrypted transactions before publishing them. At N=4-7 they are 1-of-N, with non-trivial opportunity to front-run by including their own transaction in the same vertex they decrypt. This is structurally weaker than threshold encryption, where decryption requires t-of-N agreement and no single validator gets a peek. Earlier drafts of this proposal claimed "privacy outcome is similar" between the two mechanisms; that claim was not quite accurate, and this revision corrects it.

Both trade-offs are addressable but neither is fully eliminable while staying compatible with low-coordination launch. The proposal addresses the MEV gap with mitigations (Change 4) and updates the constitutional framing to be honest about what each mechanism delivers.

This is the proposal that requires the most careful constitutional deliberation in the set.

---

## Problem statement

The current §8.4 specifies threshold-encrypted mempool. Validators run DKG ceremony to produce a threshold encryption key; users encrypt transactions to that key; transactions are decrypted only when threshold of validators agree to decrypt them. This protects against MEV and transaction frontrunning.

DKG ceremony requires:

- Coordinated active set (all participants known and online)
- Multi-round message exchange (typically 3+ rounds)
- Repetition every epoch (e.g., 36 seconds in current §8.5)

DKG cannot run with N=1 or N=2:

- N=1: no threshold to distribute
- N=2: trivial collusion (single validator can recover everyone's transactions)

Threshold encryption needs at minimum N=4-7 honest validators to provide meaningful protection. Below that, threshold encryption is either impossible (N≤2) or weak (N=3-4 trivially breakable by 2-validator collusion).

Low-coordination launch architecture (Proposal 2) means the chain may operate at N=7-15 for an extended period. During this period, threshold encryption is structurally insufficient for the t-of-N parameters that give meaningful protection.

The choices:

- **(a)** Skip encrypted mempool until N≥design-target. Chain has plaintext mempool from launch through community-adoption period (potentially months). MEV/frontrunning fully exposed.
- **(b)** Use weak threshold encryption at low N. Pretend security is meaningful when it isn't. Misleading users.
- **(c)** Time-lock encryption fallback. Different cryptographic mechanism that works at N=1 but introduces decryption latency *and* has its own MEV-protection limitations at low N.

This proposal recommends (c) with explicit constitutional acknowledgment of both trade-offs (latency and MEV-quality) and mitigations for the MEV gap.

---

## Proposed changes

### Change 1 — Time-lock encryption mechanism

**At low N (N < transition threshold):**

Users encrypt transactions to a time-lock cryptographic puzzle. The puzzle decrypts only after sequential VDF computation reaches a target. Specifically:

- Transaction is encrypted to puzzle: requires T sequential squarings of an RSA element (or equivalent VDF) to decrypt
- T is calibrated such that decryption takes 10-30 seconds on consensus-grade hardware
- Validators run the VDF computation; the round-anchor validator (per Change 4) is responsible for publishing decrypted transactions
- Other validators verify decryption (verification is fast; only computation is slow)

This works at N=1: the single validator runs the VDF, decrypts, and includes transactions. No DKG needed.

**Choice of VDF:** the proposal specifies a **publicly-verifiable VDF** (Wesolowski 2019, or Pietrzak 2018 with public verification) rather than a black-box VDF. Public verifiability is required for Change 4's mitigations to work — without it, validators cannot prove they finished the computation at the right time, and observers cannot detect early-decryption misbehavior.

### Change 2 — Threshold encryption at higher N

**At N ≥ transition threshold (suggested N=15):**

Standard threshold-encrypted mempool per current §8.4 design. DKG runs; threshold key produced; transactions encrypted to threshold key; decryption requires validator threshold agreement.

### Change 3 — Automatic transition

When the active validator set first crosses the transition threshold, the chain switches from time-lock to threshold encryption:

- Next epoch boundary triggers DKG ceremony
- Successful DKG produces threshold key
- Subsequent transactions encrypt to threshold key rather than time-lock puzzle
- Pending time-lock transactions complete decryption normally

If N drops back below threshold (validators leaving), chain reverts to time-lock fallback. This is structurally tolerable but operationally undesirable; the transition threshold has hysteresis (switch to threshold at N≥15; switch back at N<10).

### Change 4 — MEV gap mitigations during time-lock period

The MEV gap: whichever validator finishes the VDF computation first sees decrypted transaction contents before they are committed to chain state. At N=4-7, this validator has a meaningful window to front-run by including their own transaction in the same vertex that publishes the decryption. This is structurally weaker than threshold decryption, where t-of-N agreement is required and no single validator decrypts in advance.

Two mitigations together substantially reduce this gap:

**Mitigation A — Deterministic round-anchor rotation.**

Time-lock VDF computation is bound to a single validator per round, selected deterministically by the consensus VRF (§8.6). The selected validator is the *round anchor*; only the round anchor's decryption is accepted by the chain for that round. The selection is unpredictable until the round begins (because the VRF is unpredictable until the previous round commits) and rotates uniformly across validators over time.

This means any individual validator gets the front-running opportunity only on rounds where they are the anchor — roughly 1/N of rounds. At N=7, an individual validator's front-running opportunity is ~14% of rounds; at N=15, ~7%. The deterministic rotation eliminates the "race to decrypt first" dynamic; whoever rotates in is the only validator who could exploit the gap, and they are economically disincentivized by uptime-slashing if they refuse the duty.

**Mitigation B — Decryption-publication binding.**

The round anchor's decryption is published *atomically* with the transaction-ordering commitment. Specifically:

- The round anchor must include the decrypted transactions in their vertex
- The vertex is consensus-bound; it cannot be modified after publication
- The anchor cannot include their own front-running transaction in a *different* vertex that finalises before the decrypted transactions are visible, because the decryption itself is what makes the transactions visible
- Equivocation (publishing two different vertices for the same round) is slashable per §8.1.5 at 100% of stake

This eliminates the "include my own transaction first" front-running pattern. The anchor sees the transactions in advance, but their inclusion order is fixed by the vertex they publish, and they cannot publish a competing vertex without losing 100% of stake.

What remains: the anchor can choose the *internal order* of decrypted transactions within their own vertex. This is a residual MEV surface that threshold encryption does not have. It is bounded — the anchor is one validator, the opportunity is per-anchor-rotation rather than per-transaction, and the threat is detectable (anchors who reorder suspiciously can be flagged by witnesses per Proposal 5). But it is not zero.

**The honest constitutional posture:**

Even with Mitigations A and B, time-lock encryption provides quantitatively weaker MEV protection than threshold encryption. This is acknowledged. Principle II is honestly framed as "MEV protection is structural via threshold encryption at design-target N; during low-N period, MEV protection is qualitatively similar but quantitatively weaker, with residual reordering surface bounded to one anchor per round."

### Change 5 — Sub-second finality posture during low-N period

**Principle V (sub-second finality) cannot hold during time-lock period.** Time-lock decryption introduces 10-30 seconds latency between transaction submission and inclusion. This is unavoidable given the cryptographic mechanism.

Honest framing options:

**(a) Honest constitutional framing (recommended):**

Amend Principle V to read: "Sub-second finality at design-target validator count. During launch period when active set is below threshold-encryption viability, the chain operates with time-lock encryption fallback introducing 10-30 second mempool inclusion latency. This is an honest cost of low-coordination launch, not a hidden compromise."

**(b) Phased rollout framing:**

Principle V applies to "fully-bootstrapped chain." During launch period, finality is a different property. Two separate latencies but users care about end-to-end.

Recommendation: (a). Honest framing matches Adamant's overall posture. Hiding the trade-off in technicality undermines credible disclosure.

### Change 6 — Principle II posture

Principle II (privacy by default) is qualified for the time-lock period:

> "Transactions are private by default. Selective disclosure is supported. MEV protection is structural at design-target validator count via threshold encryption. During low-N launch period, MEV protection operates via time-lock encryption with deterministic anchor rotation; this provides similar protection against external observers but admits a bounded residual surface for anchor-internal reordering. Both regimes preserve transaction confidentiality from non-validator observers."

This is a substantive amendment to Principle II's framing. Earlier drafts of this proposal claimed "privacy outcome is similar" between the two mechanisms; that was not accurate enough to survive cryptographic review. The corrected framing acknowledges the difference while remaining accurate about what each mechanism delivers.

---

## Open Q-decisions

**Q-1.** What is the transition threshold from time-lock to threshold encryption?

Recommendation: 15 validators. Provides reasonable security margin (5+ honest validators required for threshold collusion to break encryption). Specific number TBD by cryptographic analysis.

**Q-2.** What is the time-lock parameter T?

Recommendation: 10-15 seconds at consensus-grade hardware. Long enough to prevent immediate decryption (preserving privacy from external observers) but short enough that user transaction inclusion isn't intolerably delayed.

**Q-3.** Hysteresis for transition?

Recommendation: switch to threshold at N≥15; switch back at N<10. Hysteresis prevents flapping if validator count oscillates near threshold.

**Q-4.** Are time-lock-encrypted and threshold-encrypted transactions structurally distinguishable on-chain?

Recommendation: yes; transaction encoding includes encryption type. This allows wallets/applications to know which mechanism applies and adjust UX accordingly. Same shape as security tier disclosure (Proposal 2, Change 5).

**Q-5.** Can users opt out of time-lock to plaintext during low-N period (accepting MEV exposure for faster finality)?

Recommendation: yes, with explicit user acknowledgment. Some applications (high-frequency, low-value) may prefer plaintext + speed over time-lock + privacy. Wallet UX warns clearly. Default is time-lock (privacy-default principle).

**Q-6.** Does the time-lock mechanism use Wesolowski VDF, Pietrzak VDF, or alternative?

Recommendation: Wesolowski. Public verifiability is short and clean (one group element vs Pietrzak's logarithmic proof). Both are well-studied; both are RSA-based; both are compatible with the public-verifiability requirement of Change 4. Specific choice TBD by cryptographic analysis but constrained to publicly-verifiable VDFs.

**Q-7.** Is the transition automatic, or does it require validator vote?

Recommendation: automatic. Validator vote introduces governance (Principle I violation). Transition triggers on observable chain state (active set count crossing threshold).

**Q-8.** What slashing applies to anchors who exploit the residual MEV surface (Change 4)?

Recommendation: equivocation slashing already covers the worst case (100% of stake for publishing two different vertices). For more subtle reordering (e.g., the anchor reorders decrypted transactions within their vertex to favor a private transaction), slashing requires evidence of reordering against a "natural" ordering, which is hard to define cryptographically. Suggested approach: rely on Proposal 5 witnesses to flag suspicious anchor behavior; reputational pressure rather than cryptographic slashing for this surface. This is admittedly weaker than threshold encryption's structural prevention.

---

## Constitutional implications

**Principle V (sub-second finality):** SUBSTANTIVELY MODIFIED. Sub-second finality applies only at design-target validator count. During launch period, mempool inclusion latency is 10-30 seconds.

**Principle II (privacy by default):** SUBSTANTIVELY MODIFIED in MEV-protection framing. Both time-lock and threshold encryption protect transaction confidentiality from external observers. MEV protection differs in kind: threshold encryption is structural (no validator sees plaintext until commit); time-lock encryption with Mitigations A and B is mostly structural but admits a bounded residual surface for one anchor per round. Privacy outcome is *similar but not identical*; the framing must acknowledge this.

**Principle I (no foundation, no governance):** PRESERVED. Automatic transition (Q-7 recommendation) avoids governance.

**Honest disclosure:** Both Principle V's modified framing and Principle II's modified MEV-protection framing require explicit acknowledgment in §11 and §1.2. Cannot be hidden in §8.4 / §8.5 technical detail.

---

## Implementation impact

**Phase 6+ (AVM runtime):** Minor.

**Phase 7 (privacy layer):** Moderate — wallet/application code needs to handle both encryption mechanisms.

**Phase 8 (consensus):** Substantial — time-lock VDF integration; transition logic; transaction encoding; anchor rotation logic; decryption-publication binding via existing equivocation slashing.

**Phase 9 (networking):** Minor — VDF computation is local to validator.

**Whitepaper sections affected:**

- §1.2 (Principle V row — substantive modification; Principle II row — modified MEV-protection framing)
- §2.2 (Principle II definition — modified MEV-protection framing)
- §4 (Principle V definition — substantive modification)
- §8.4 (mempool encryption — major rewrite covering both mechanisms; anchor rotation; equivocation binding)
- §8.5 (DKG ceremony — qualified to apply at N≥threshold)
- §11 (constitutional acknowledgment of both trade-offs)

---

## Alternatives considered

**Alternative 1 — Skip encrypted mempool at low N (plaintext mempool until N≥15).**

Pros: simpler; no time-lock complexity; no MEV-quality trade-off to acknowledge.
Cons: MEV/frontrunning fully exposed during launch period. Sets precedent that early-chain is unprotected. Plaintext mempool is observable by all node operators, not just anchors — much weaker than time-lock + Mitigations A/B.
Verdict: rejected. Adamant's value proposition is privacy-default; abandoning that during launch period sends wrong signal. Time-lock + Mitigations is materially better than plaintext.

**Alternative 2 — Skip user transactions until N≥15 (chain operates only validator-registration + stake operations until threshold encryption viable).**

Pros: cleanest constitutional posture; chain doesn't ship a feature it can't deliver.
Cons: no user activity = no economic incentive for validators to participate = chicken-and-egg adoption problem.
Verdict: rejected. Practical adoption requires user transactions from launch.

**Alternative 3 — Centralized decryption authority during launch period (founder runs decryption oracle).**

Pros: technically simpler.
Cons: introduces trusted authority; violates Principle I.
Verdict: rejected outright. Constitutional violation.

**Alternative 4 — Time-lock without anchor rotation (any validator can decrypt; first to publish wins).**

Pros: simpler implementation.
Cons: MEV surface is N times larger because every validator races to decrypt and any can include their own front-running transaction. The "race-to-decrypt" dynamic is precisely what Mitigations A and B exist to eliminate.
Verdict: rejected. Anchor rotation (Change 4 Mitigation A) is what makes time-lock survivable.

**Alternative 5 — Time-lock with multi-anchor decryption (k-of-N anchors must agree).**

Pros: even stronger MEV protection (closer to threshold encryption).
Cons: requires coordinated computation among multiple anchors per round; reintroduces some of the coordination complexity that time-lock was meant to avoid; performance cost is high.
Verdict: defer. Single-anchor rotation (Change 4 Mitigation A) is the simpler design; multi-anchor could be a future hard-fork enhancement if the residual surface proves problematic in practice.

---

## Recommendation

**APPROVE WITH SUBSTANTIVE TRADE-OFF ACKNOWLEDGMENT.**

The proposal preserves Adamant's privacy commitment during the launch period at the cost of finality during that period and at the cost of quantitatively (not qualitatively) weaker MEV protection during that period. Both trade-offs are real, not hidden. Honest disclosure (Principles V and II modified framing) is what makes this acceptable.

Without this proposal, the chain's choices are:

- Centralized launch (violates Principle I)
- Plaintext launch (violates Principle II during launch period)
- Postponed launch until N=design-target (impossible without coordination event)
- Time-lock fallback (this proposal's recommendation)

Time-lock fallback with Mitigations A and B is the only path that preserves Principle I (no foundation) and substantially preserves Principle II (privacy default with bounded residual MEV surface) during low-N launch period, at the explicit cost of Principle V (sub-second finality) during that period.

This is the proposal where the founders' constitutional discipline is most tested. Recommendation is to approve with explicit trade-off acknowledgment in §1.2, §2.2, §4, §8.4, §11. Do not hide the trade-offs.

Pending: Q-1 through Q-8 sub-decisions during proposal-track deliberation.

---

## Cross-references

- Proposal: Low-coordination launch architecture (parent; this proposal addresses the encrypted-mempool gap)
- Proposal: Watcher/witness tier (linked; witnesses provide the reputational layer that backs anchor-reordering detection per Q-8)
- §8.4 (mempool encryption — current threshold-only design)
- Principle II (privacy by default — modified by this proposal's MEV-protection framing)
- Principle V (sub-second finality — modified by this proposal)
