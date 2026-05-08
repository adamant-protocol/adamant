# Proposal: Hybrid Signature Model (Ed25519 + ML-DSA + ML-KEM)

**Status:** Draft for proposal-track deliberation (rev. 2)
**Affects:** §1.2, §3, §4 (Principle VII), §6, §7, §8, §11
**Author:** Ryan Geldart
**Date:** 2026-05-08
**Prerequisites:** None for hybrid signature scope; key-agreement fix below adds ML-KEM to §3
**Constitutional impact:** SUBSTANTIAL — modifies Principle VII (post-quantum security) posture

---

## Executive summary

Adamant currently specifies ML-DSA-65/87 for all signatures (transactions, validator messages, contract deployments). ML-DSA signatures are ~3.3KB for ML-DSA-65 and ~4.6KB for ML-DSA-87. At 50k TPS, this is significant bandwidth (3.3KB × 50k = 165MB/sec just for signatures).

This proposal adopts a hybrid model:

- **Ed25519** for ordinary transactions and validator consensus messages (small, fast)
- **ML-DSA** for constitutional-binding signatures (validator registrations, contract deployments, optional high-value transactions)
- **ML-KEM** (Kyber, FIPS 203) for post-quantum key agreement underlying stealth addresses and any other key-exchange surface

The ML-KEM addition resolves a primitive-identification issue in earlier drafts of this proposal. Stealth address derivation uses key *agreement* (ECDH-style), not signature. ML-DSA is signature-only and cannot do key agreement; ML-KEM is the NIST-standardized post-quantum KEM and is the correct primitive for this surface. Both are 2024 NIST standards and both are lattice-based, so the security framing is consistent.

**The substantive trade-off:** if quantum computing becomes practical for breaking Ed25519 (estimated 2030-2040 range based on current cryptanalysis trajectory), all historical Ed25519-signed transactions become forgeable. This affects transaction history forensics, audit, dispute resolution.

This is one of two proposals in the set with substantial constitutional implications (the other being Proposal 4, time-lock encryption fallback). Careful deliberation required.

---

## Problem statement

ML-DSA signature size is significant:

- ML-DSA-44: 2,420 bytes (security level ~AES-128)
- ML-DSA-65: 3,309 bytes (security level ~AES-192)
- ML-DSA-87: 4,627 bytes (security level ~AES-256)

Adamant currently uses ML-DSA-65 for ordinary signatures and ML-DSA-87 for high-value/constitutional signatures.

At 50k TPS with one signature per transaction:

- ML-DSA-65 only: 165 MB/sec signature bandwidth
- Ed25519 only: 3.2 MB/sec signature bandwidth
- Hybrid (95% Ed25519 + 5% ML-DSA): ~11 MB/sec signature bandwidth

The 50x bandwidth difference is meaningful at high TPS. Beyond bandwidth:

- Transaction storage: ~3KB × billions of transactions = TBs of storage cost
- Light-client sync: phones download proportionally less data with smaller signatures
- Cross-chain bridges: bridge proofs include signatures; smaller is meaningfully cheaper
- Block size pressure: at high TPS, signature size is the dominant block size factor

A separate problem surfaced during earlier review of this proposal: stealth address derivation (§7) requires post-quantum key agreement, not signature. Specifying ML-DSA for this surface (as earlier drafts did) is a primitive misidentification — ML-DSA does not support key agreement. The correct primitive is ML-KEM.

---

## Proposed changes

### Change 1 — Hybrid signature classification

**Ed25519 (classical, 64-byte signatures):**

- Ordinary transactions (transfers, contract calls, vote transactions)
- Validator consensus messages (votes, vertex broadcasts)
- Mempool transactions (pre-decryption)

**ML-DSA (post-quantum, 3-5KB signatures):**

- Validator registrations
- Validator key rotations
- Contract deployments (initial deploy and upgrades)
- High-value user transactions (user opt-in; threshold TBD)
- Stake delegations above threshold
- Any operation that produces persistent on-chain identity binding

The split is "ephemeral operations get Ed25519; persistent operations get ML-DSA."

### Change 2 — ML-KEM for post-quantum key agreement

The protocol adds **ML-KEM-768** (FIPS 203) as the post-quantum key encapsulation mechanism. ML-KEM is used wherever the protocol needs post-quantum-secure key agreement, specifically:

- Stealth address derivation (§7.2): the recipient's published key is an ML-KEM public key; senders encapsulate to it to derive the per-note shared secret
- Encrypted memo delivery (§7.6): same KEM construction for sender-to-recipient encrypted memos
- Any other key-exchange surface introduced post-genesis

Why ML-KEM and not ML-DSA: signatures and KEMs solve different problems. A signature scheme proves message authorship; a KEM establishes a shared secret between two parties. ECDH (which Ed25519's stealth addresses currently rely on) is a key-agreement primitive, not a signature primitive. The post-quantum analog is ML-KEM, not ML-DSA. Both ML-DSA and ML-KEM are NIST-standardized in 2024 and both are lattice-based; using both is consistent with Principle VI (standard primitives, novel synthesis) and adds one primitive to the protocol's cryptographic surface (ML-KEM-768) alongside the signature primitives already specified in §3.

### Change 3 — Address derivation

Addresses are derived from ML-DSA public keys (post-quantum identity), but transactions sign with Ed25519 keys derived from the same seed.

- Address remains post-quantum (an attacker who breaks Ed25519 can't recover the address's private control)
- Transaction signatures can be Ed25519 (saving bandwidth)
- The Ed25519 key is one-way derived from the master seed; quantum adversary breaking Ed25519 reveals only that signing key, not the master key

Specific derivation function: HKDF-SHA3 expansion of the master seed with domain separators distinguishing the ML-DSA, Ed25519, and ML-KEM key material. The exact construction is consensus-critical and will be specified in §3 (cryptographic foundation) before genesis.

### Change 4 — Quantum-resistance posture acknowledgment

**The honest trade-off:**

Ordinary transactions signed with Ed25519 are vulnerable to retroactive quantum forgery. This means:

1. **Transaction history forensics breaks post-quantum.** Once Ed25519 is broken, any historical Ed25519-signed transaction can be forged. Proving "Alice did or didn't pay Bob in 2027" becomes impossible. Affects audit, legal disputes, regulatory compliance.

2. **Stealth address recovery is preserved post-quantum.** Because stealth addresses derive from ML-KEM (Change 2), historical stealth address derivation is post-quantum-secure. This is a positive consequence of the corrected primitive choice — earlier drafts of this proposal would have left this surface vulnerable.

3. **Validator vote integrity post-quantum.** Validator votes use Ed25519 (per Change 1). Post-quantum adversary can in principle forge historical votes. However, chain state is anchored by ML-DSA-signed validator registrations, contract deployments, and epoch state commitments; consensus state cannot be rewritten without breaking ML-DSA, which remains post-quantum-secure. Historical vote forgery is an audit/forensics concern, not a chain-rewrite concern.

4. **Identity persistence preserved.** Addresses remain quantum-resistant; an attacker breaking Ed25519 cannot take control of accounts, only forge specific historical transaction claims.

### Change 5 — Constitutional framing

**Principle VII (post-quantum security) framing options:**

**(a) Honest hybrid framing (recommended):**

> "Adamant's identity layer (addresses, validator registrations, contract deployments) is post-quantum-secure via ML-DSA. Key agreement underlying privacy primitives (stealth addresses, encrypted memos) is post-quantum-secure via ML-KEM. Ordinary transaction signatures use Ed25519 for performance reasons; this means transaction history is vulnerable to retroactive quantum forgery. The chain's structural integrity and the privacy of historical transactions are not. Users requiring full post-quantum protection of transaction history can opt into ML-DSA signatures per-transaction."

**(b) Phased framing:**

"Adamant ships with hybrid signatures at launch. As quantum threat materializes (estimated 2030-2040), the chain transitions to ML-DSA-only via [governance/automatic mechanism TBD]."

**(c) Pure framing (rejected by this proposal):**

"All signatures ML-DSA. No quantum vulnerability anywhere."

Recommendation: (a). Honest framing that acknowledges the trade-off rather than hiding it. (b) introduces governance which violates Principle I; (c) is the current spec but at material bandwidth/storage cost.

---

## Open Q-decisions

**Q-1.** Should ordinary transactions allow ML-DSA opt-in?

Recommendation: yes. Privacy-conscious users or high-value transactions can opt into ML-DSA signing. Wallet UX exposes the choice with explanation of trade-off.

**Q-2.** What's the threshold above which ordinary transactions automatically get ML-DSA signatures?

Recommendation: configurable per-wallet; default to ML-DSA for transactions above some user-set threshold (e.g., $1,000 USD-equivalent). Specific UX TBD by wallet design.

**Q-3.** Are stealth addresses derived using Ed25519 ECDH or ML-KEM?

**RESOLVED: ML-KEM.** Earlier drafts named ML-DSA for this surface, which was a primitive misidentification (ML-DSA cannot do key agreement). ML-KEM is the correct post-quantum primitive for stealth address derivation. Privacy is a permanent property; stealth address privacy must survive quantum threat. Bandwidth cost of ML-KEM ciphertexts (~1.1KB) is per-note, not per-transaction; tractable.

**Q-4.** When (if ever) does the chain transition to ML-DSA-only?

Recommendation: never automatically. The hybrid posture is permanent; users choose per-transaction. If/when quantum threat materializes, users naturally migrate to ML-DSA via opt-in. No protocol-level transition; no governance.

**Q-5.** How are Ed25519/ML-DSA signatures distinguished in transaction encoding?

Recommendation: explicit signature-type flag in transaction envelope (the existing `Signature` discriminated union in §6.0.7 already supports this; Ed25519 = 0x00, ML-DSA-65 = 0x01, ML-DSA-87 = 0x02). Verifiers know which algorithm to use. No protocol-level inference.

**Q-6.** Are validator consensus messages always Ed25519, or can validators opt up to ML-DSA?

Recommendation: always Ed25519 for performance. Consensus messages are ephemeral (not persistent state); their forgeability post-quantum doesn't affect chain integrity (chain state is anchored by ML-DSA validator registrations and ML-DSA-signed epoch commits).

**Q-7.** What happens if a user's Ed25519 key is compromised post-quantum, but the ML-DSA address is not?

Recommendation: user signs an ML-DSA-authorized "rotate Ed25519 key" transaction. New Ed25519 key derived from same seed; old Ed25519 key invalidated. Operationally clean and reuses the §4.5 key-rotation mechanism.

**Q-8.** Which ML-KEM parameter set?

Recommendation: ML-KEM-768. Provides ~AES-192 security level, matching ML-DSA-65's security target. Ciphertexts are ~1.1KB; public keys are ~1.2KB. Acceptable for stealth address derivation given that stealth address material is per-recipient, not per-transaction. ML-KEM-1024 (~AES-256) is also defensible if the privacy-layer designer wants security parity with ML-DSA-87.

---

## Constitutional implications

**Principle VII (post-quantum security):** SUBSTANTIVELY MODIFIED. Modified framing per Change 5 option (a). Honest acknowledgment of hybrid trade-off. Privacy-relevant key agreement is post-quantum-secure via ML-KEM.

**Principle II (privacy by default):** PRESERVED. The ML-KEM primitive choice ensures historical privacy survives the quantum threshold. This was at risk under earlier drafts that specified ML-DSA for this surface.

**Principle I (no foundation):** PRESERVED. No governance; user choice per transaction.

**Principle V (sub-second finality):** STRENGTHENED. Smaller signatures = faster validator vote propagation = better latency.

**Principle VI (standard primitives):** PRESERVED. Ed25519, ML-DSA, ML-KEM are all peer-reviewed and either RFC- or NIST-standardized. No novel cryptography.

---

## Implementation impact

**Phase 3 (cryptographic foundations):** Substantial — adds ML-KEM-768 to the primitives crate. Requires audited Rust implementation (`ml-kem` crate from `RustCrypto`, or equivalent) and integration into the chain's HKDF-derived key hierarchy.

**Phase 5 (verifier work):** Minor — verifier accepts both signature types per envelope flag.

**Phase 6 (AVM runtime):** Minor — runtime accepts both signature types; new bytecode instruction `MlKemEncapsulate` / `MlKemDecapsulate` for stealth address derivation circuits.

**Phase 7 (privacy layer):** Substantial — stealth address derivation rewritten to use ML-KEM. Encrypted memo construction rewritten to use ML-KEM. Halo 2 circuits for note construction must verify ML-KEM derivation; circuit performance impact requires empirical measurement.

**Phase 8 (consensus):** Moderate — validator messages standardize on Ed25519 per Q-6; signature-type handling.

**Phase 9 (networking):** Minor — bandwidth optimization significantly improves at hybrid.

**Phase 10 (economics):** Minor.

**Whitepaper sections affected:**

- §1.2 (Principle VII row — substantive modification)
- §3 (cryptographic foundation — adds ML-KEM-768 to primitives table; key-derivation hierarchy)
- §4 (Principle VII definition — substantive modification)
- §6 (transaction encoding — signature-type flag; ML-KEM bytecode instructions)
- §7 (privacy circuits — stealth address derivation specifies ML-KEM; encrypted memo specifies ML-KEM)
- §8 (consensus — validator messages specify Ed25519)
- §11 (constitutional acknowledgment of hybrid posture)

---

## Alternatives considered

**Alternative 1 — Pure ML-DSA (current spec).**

Pros: simplest constitutional framing; full post-quantum security throughout.
Cons: 50x signature bandwidth at high TPS; significant storage cost; slower consensus message propagation. Also fails to address the key-agreement primitive question — the current spec has not yet specified the post-quantum primitive for stealth address derivation, and would need to add ML-KEM regardless.
Verdict: defensible but expensive.

**Alternative 2 — Pure Ed25519 (no post-quantum).**

Pros: smallest signatures; fastest consensus.
Cons: violates Principle VII entirely.
Verdict: rejected outright.

**Alternative 3 — Hybrid as proposed (this proposal).**

Pros: balance of bandwidth and post-quantum security; identity layer protected by ML-DSA; privacy layer protected by ML-KEM; transaction signing fast via Ed25519.
Cons: substantive trade-off requiring honest constitutional acknowledgment; adds one primitive (ML-KEM) to the protocol.
Verdict: recommended.

**Alternative 4 — Hybrid with automatic transition to pure ML-DSA when quantum threat materializes.**

Pros: hybrid bandwidth benefits short-term; pure post-quantum long-term.
Cons: who decides when quantum threat is real? Introduces governance (Principle I violation) or relies on protocol-level threat detection (technically uncertain).
Verdict: rejected. Q-4 recommendation (never automatic transition; user opt-in) avoids governance.

**Alternative 5 — Falcon (FN-DSA) or SLH-DSA instead of ML-DSA.**

Pros: SLH-DSA has hash-based security (different assumption). FN-DSA (FIPS 206, finalising) has smaller signatures (~0.7KB) than ML-DSA.
Cons: SLH-DSA signatures are even larger than ML-DSA. FN-DSA finalization is recent and implementation maturity is lower.
Verdict: defer to cryptographic analysis. Specific PQ algorithm not constitutional; what's constitutional is "post-quantum signature exists for identity-binding operations."

---

## Recommendation

**APPROVE WITH SUBSTANTIVE TRADE-OFF ACKNOWLEDGMENT.**

The hybrid model is good engineering. The bandwidth/storage savings are material at design-target TPS. The trade-off (retroactive quantum vulnerability for ordinary transaction history) is real but bounded — chain identity, structural integrity, and privacy properties (with the ML-KEM correction) survive quantum threat.

The honest constitutional framing per Change 5 option (a) is what makes this acceptable. Hiding the trade-off in implementation detail would undermine credible disclosure.

Without this proposal, the chain's choice is:

- Pure ML-DSA (current spec; expensive at high TPS; still needs to add ML-KEM for key agreement)
- Pure Ed25519 (violates Principle VII)
- Hybrid (this proposal; substantive trade-off; correct primitive coverage)

Hybrid with ML-KEM is the engineering-best path with explicit constitutional acknowledgment.

Pending: Q-1, Q-2, Q-4, Q-5, Q-6, Q-7, Q-8 sub-decisions during proposal-track deliberation. Q-3 is resolved (ML-KEM).

---

## Cross-references

- §1.2 (Principle VII — modified by this proposal)
- §3 (cryptographic foundation — adds ML-KEM-768)
- §4 (Principle VII definition — modified by this proposal)
- §7 (privacy circuits — stealth address and encrypted memo derivation specify ML-KEM)
- Proposal: Low-coordination launch architecture (parallel; this proposal's bandwidth savings enable that proposal's residential-fiber assumption)
- Proposal: Time-lock encryption fallback (parallel; both proposals require honest constitutional disclosure)
