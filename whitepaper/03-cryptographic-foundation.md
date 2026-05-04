# 3. Cryptographic Foundation

This section specifies every cryptographic primitive used by the Adamant protocol. It is the foundation on which all other sections depend: the consensus mechanism, the privacy layer, the encrypted mempool, the identity system, and the recursive verification all rest on the primitives specified here.

The protocol's guiding principle for cryptography is stated in Principle VI of section 2: standard primitives, novel synthesis. This section operationalises that principle. Every primitive is drawn from peer-reviewed literature with substantial implementation history. No primitive is novel to Adamant. Where multiple peer-reviewed alternatives exist, the rationale for the chosen primitive is explicit and the alternatives are documented.

This section is normative. The reference implementation `MUST` use the primitives, parameters, and libraries specified here. Substitution requires a formal specification revision under the procedure described in section 12.

## 3.1 Threat model

The protocol's cryptographic design assumes the following adversary capabilities:

1. **Classical computational adversary.** An adversary with computational resources up to but not exceeding those plausibly available to a well-resourced nation-state through approximately 2040, on classical computing hardware. The protocol targets at least 128-bit classical security across all primitives.

2. **Network adversary.** An adversary that can observe, modify, delay, drop, and inject network traffic at any point in the public internet. The protocol assumes no confidentiality or integrity from the underlying network and provides both at the cryptographic layer.

3. **Quantum adversary (long-term).** An adversary with a sufficiently large fault-tolerant quantum computer to execute Shor's algorithm against elliptic-curve and integer-factorisation problems. The protocol assumes such an adversary may exist at some point during the operational lifetime of the chain (potentially within 10–25 years of genesis) and provides a migration path to post-quantum primitives that does not require a hard fork.

4. **Compromised validators (Byzantine).** Up to one-third of validators by stake may be Byzantine — actively malicious, colluding, or compromised — without violating safety guarantees. This is the standard assumption for Byzantine-fault-tolerant consensus and is enforced at the consensus layer (section 8); cryptographic primitives are required to remain secure under arbitrary validator behaviour.

5. **Compromised user devices.** The protocol assumes that user devices may be compromised. Primitives that protect users (signing, encryption) `SHOULD` be amenable to use within hardware security modules, secure enclaves, and hardware wallets where available, but the protocol does not depend on hardware security for its core safety properties.

The protocol does **not** defend against:

- An adversary with sufficient quantum computing resources to break ML-DSA, ML-KEM, or other lattice-based primitives at the parameters specified in this section. Such an adversary would constitute a fundamental break of post-quantum cryptography, the consequences of which would extend beyond any individual blockchain.
- An adversary capable of compromising more than one-third of validators by stake. Adamant's safety guarantees are conditioned on this threshold; an adversary above this threshold can violate safety regardless of cryptographic correctness.
- An adversary with physical access to a user's device and unencrypted secret material. The protocol assumes users protect their secret keys; key management is the user's responsibility.

## 3.2 Cryptographic primitives summary

The protocol uses five categories of cryptographic primitives, summarised here and specified in detail in subsequent subsections.

| Category | Primitive | Standard / source | Use |
|----------|-----------|-------------------|-----|
| Hash function | SHA3-256, SHAKE-256 | FIPS 202 | All chain hashing, transaction identifiers, Merkle trees |
| Hash to curve | BLAKE3 (auxiliary), Poseidon (zk circuits) | BLAKE3 spec; Grassi et al. 2020 | Auxiliary hashing, zk-friendly hashing inside circuits |
| Classical signature | Ed25519 | RFC 8032 | User signatures, validator signatures (classical layer) |
| Post-quantum signature | ML-DSA (CRYSTALS-Dilithium) | FIPS 204 | User signatures, validator signatures (PQ layer) |
| Aggregate signature | BLS12-381 (BLS signatures) | IRTF CFRG draft, BLS12-381 curve | Validator vote aggregation |
| Symmetric encryption | ChaCha20-Poly1305 | RFC 8439 | Transport encryption, mempool envelope |
| Threshold encryption | Boneh-Lynn-Shacham threshold scheme on BLS12-381 | Boneh, Boyen, Shacham 2004; subsequent work | Encrypted mempool |
| Zero-knowledge proofs | Halo 2 (PLONKish, no trusted setup) | Bowe, Grigg, Hopwood 2019 | Shielded execution, recursive verification |
| Vector commitments | KZG commitments on BLS12-381 | Kate, Zaverucha, Goldberg 2010 | State commitments, proof aggregation |

Each primitive is justified and parameterised below.

## 3.3 Hash functions

### 3.3.1 Primary hash: SHA3-256 and SHAKE-256

The protocol's primary hash function is SHA3-256 for fixed-output hashing and SHAKE-256 for extensible-output hashing, both as standardised in FIPS 202.

**Rationale.** SHA3 is a Keccak-derived hash function selected by NIST through an open competition (2007–2012) and standardised in 2015. It has a fundamentally different internal construction from the SHA-2 family (sponge construction vs. Merkle–Damgård), providing diversity against the unlikely event of a structural attack on SHA-2. It has no known attacks reducing security below the 128-bit collision-resistance level at the SHA3-256 parameter. Hardware acceleration is increasingly available (ARM v8.4-A includes SHA3 instructions; x86-64 implementations via SSE/AVX achieve >1 GB/s throughput on modern processors).

**Parameters.** SHA3-256 produces 256-bit output, providing 128-bit collision resistance and 256-bit preimage resistance. SHAKE-256 produces output of arbitrary length with the same security level.

**Domain separation.** All uses of SHA3-256 within the protocol `MUST` use domain separation. The protocol prepends a fixed-length domain tag to every hash input. Domain tags are specified per-use throughout this document. This prevents an attacker from constructing a value that hashes identically in two different contexts. Domain tags use the format `b"ADAMANT-v1-<context>"` where `<context>` identifies the specific use.

**Library.** The reference implementation uses the `sha3` crate from RustCrypto, which provides constant-time implementations and is widely audited.

### 3.3.2 Auxiliary hash: BLAKE3

BLAKE3 is used as an auxiliary hash function for performance-sensitive paths where collision-resistance security at 128 bits suffices and where SHA3 would be a measurable bottleneck.

**Rationale.** BLAKE3, published in 2020, is built on the Bao tree-hashing construction over a Merkle-tree-friendly internal compression function. It is significantly faster than SHA3 in software (typically 5–10x on commodity hardware) and is naturally parallelisable. Specific uses include: peer-to-peer message integrity checks where the message is large and the security context permits a faster primitive; streaming hashes during block propagation; and content-addressed storage of historical chain data.

**Parameters.** BLAKE3 produces 256-bit output by default, with extensible-output mode for arbitrary lengths. The protocol uses 256-bit output throughout.

**Constraint.** BLAKE3 `MUST NOT` be used for any of the following: transaction identifiers, state commitments, signature inputs, consensus-critical hashes. These uses require SHA3-256 to maintain protocol-wide hash-function uniformity. BLAKE3 is exclusively for non-consensus-critical performance paths.

**Library.** The reference implementation uses the `blake3` crate.

### 3.3.3 zk-friendly hash: Poseidon

Inside zero-knowledge circuits, the protocol uses the Poseidon hash function. Poseidon is designed for efficient evaluation in arithmetic circuits over large prime fields, where SHA3 and BLAKE3 are prohibitively expensive (a single SHA3 invocation requires hundreds of thousands of constraints in a SNARK circuit; a single Poseidon invocation requires hundreds).

**Rationale.** Poseidon was designed by Grassi, Khovratovich, Rechberger, Roy, and Schofnegger (2020) specifically for zk-friendly hashing. It has been adopted by Filecoin, Mina, and Aztec, providing extensive deployment evidence. Cryptanalytic effort against Poseidon has been substantial, with no attacks reducing security below the 128-bit level at the parameters used.

**Parameters.** The protocol uses Poseidon with the following parameters: prime field of order equal to the BLS12-381 scalar field (255 bits), state width of 3 field elements (rate 2, capacity 1), 8 full rounds and 57 partial rounds. These parameters provide approximately 128-bit security against differential and algebraic attacks.

**Constraint.** Poseidon is used only inside zk circuits. It `MUST NOT` be used for general protocol hashing outside circuits. Hashes that cross the circuit/non-circuit boundary use both Poseidon (inside the circuit) and SHA3-256 (outside), with the circuit proving consistency between the two representations.

**Library.** The reference implementation uses the Poseidon implementation from `halo2_gadgets` (zcash variant).

## 3.4 Signature schemes

The protocol supports two signature schemes for user and validator signatures: Ed25519 (classical) and ML-DSA (post-quantum). Both are first-class. Accounts may use either or both, as specified in section 4.

### 3.4.1 Classical signatures: Ed25519

Ed25519 is the protocol's classical signature scheme. It is specified in RFC 8032 and is the most widely deployed elliptic-curve signature scheme in modern cryptographic systems.

**Rationale.** Ed25519 provides 128-bit classical security, has no patent encumbrance, supports deterministic signing (eliminating the catastrophic key-recovery vulnerability that affects ECDSA when the per-signature randomness is reused or biased), and is implementable in fully constant time. Every major modern operating system, secure element, and HSM supports it. Performance is excellent: signing and verification both take well under one millisecond on commodity hardware.

**Parameters.** As specified in RFC 8032: the Edwards curve `edwards25519`, hash function SHA-512 internally (a deliberate choice in the original Ed25519 design that is independent of the protocol's preference for SHA3 elsewhere), 256-bit private keys, 32-byte public keys, 64-byte signatures.

**Note on hash choice.** Ed25519 internally uses SHA-512 as part of its specification; this is a fixed property of the scheme and not a protocol choice. The protocol does not modify Ed25519's internal hash. Protocol-level hashing of Ed25519 keys and signatures (for example, computing a hash commitment to a public key) uses SHA3-256.

**Library.** The reference implementation uses `ed25519-dalek` from the `dalek-cryptography` ecosystem, which provides constant-time, audited, no-`unsafe` implementations.

### 3.4.2 Post-quantum signatures: ML-DSA

ML-DSA (Module-Lattice-Based Digital Signature Algorithm) is the protocol's post-quantum signature scheme. It is standardised in FIPS 204, finalised in August 2024 by NIST. It is the lattice-based scheme formerly known as CRYSTALS-Dilithium.

**Rationale.** ML-DSA is one of three post-quantum signature schemes selected by NIST through a multi-year open competition (2017–2022). It provides security under standard lattice problem assumptions (Module Learning With Errors, Module Short Integer Solution) and has been the subject of extensive cryptanalysis without significant security degradation. Recent benchmarks (October 2025, arXiv 2510.09271) demonstrate that ML-DSA verification at security level 5 is approximately 0.14 milliseconds on ARM-based laptops — faster than ECDSA at 0.88 milliseconds. ML-DSA is therefore not a performance compromise; at the security levels relevant to long-term consensus, it is a performance improvement.

**Parameters.** The protocol uses **ML-DSA-65** (security level 3, equivalent to AES-192 or SHA-384 collision resistance), providing 192-bit classical security and approximately 128-bit security against quantum attack. Public keys are 1952 bytes; signatures are 3293 bytes. This is significantly larger than Ed25519 but acceptable for the protocol's per-transaction and per-vote cost budget.

**Why level 3 and not level 2 or level 5.** Level 2 (ML-DSA-44) provides 128-bit classical security, marginal in long-lived systems. Level 5 (ML-DSA-87) provides 256-bit classical security at significantly higher signature size (4595 bytes) and computational cost. Level 3 is the appropriate balance for a chain whose lifetime is intended to be measured in decades.

**Account flexibility.** Section 4 specifies an account model in which an individual account may declare itself to use Ed25519 only, ML-DSA only, or both (with both required for transactions, providing belt-and-braces security). Validators `MUST` support all three account types from genesis.

**Library.** The reference implementation uses the `ml_dsa` crate from the RustCrypto project, which is the FIPS-204-compliant ML-DSA implementation. As ML-DSA implementations mature, the protocol may revise its choice of library; the algorithm choice (ML-DSA-65) is fixed.

### 3.4.3 Aggregate signatures: BLS on BLS12-381

The protocol uses BLS signatures on the BLS12-381 elliptic curve for validator vote aggregation in the consensus mechanism. BLS signatures support efficient aggregation: the signatures of N validators on the same message can be combined into a single signature whose verification cost is approximately constant in N.

**Rationale.** BLS aggregate signatures are essential for efficient DAG-based consensus at high validator counts. Without aggregation, each consensus vertex would carry hundreds of individual signatures, exhausting block bandwidth before useful payload. BLS allows a single aggregate signature to attest to validator votes at minimal marginal cost.

**Parameters.** BLS12-381 is the Barreto-Lynn-Scott curve at the 12-degree-extension construction with the specific embedding `x = -0xd201000000010000`, providing approximately 128-bit security in the optimal-Ate pairing. This curve is the de facto standard for BLS-based blockchain applications, used by Ethereum (consensus signatures), Filecoin, Zcash (Sapling), and others. Public keys are 48 bytes (G1) or 96 bytes (G2); signatures are 96 bytes (G2) or 48 bytes (G1).

The protocol uses the **G1 signature, G2 public key** variant. Signatures are smaller (48 bytes), which matters at consensus scale; public keys are larger but registered once per validator.

**Domain separation.** BLS signatures use the standardised hash-to-curve operation specified in IRTF draft `draft-irtf-cfrg-hash-to-curve` with domain tag `BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_ADAMANT_v1`. Domain separation prevents signature replay across protocols and across versions of the protocol.

**Quantum vulnerability.** BLS signatures, like all elliptic-curve schemes, are vulnerable to a future quantum adversary running Shor's algorithm. The protocol mitigates this by reserving BLS aggregation strictly for short-lived consensus messages: validator votes are valid only within a single epoch (specified in section 8) and are pruned after the epoch closes. A quantum adversary that breaks BLS in 2040 cannot retroactively forge consensus votes from 2030, because no one is verifying those votes any more — they have been finalised by recursive zk proofs (section 7) that do not depend on the original BLS signatures. Long-term security is provided by the ML-DSA layer; BLS provides efficiency for short-term consensus messaging.

**Library.** The reference implementation uses the `blst` library from Supranational, which is the highest-performance audited BLS12-381 implementation in current use. The Rust binding is `blst-rs`.

## 3.5 Symmetric encryption

The protocol uses ChaCha20-Poly1305 (RFC 8439) for all symmetric authenticated encryption, including transport encryption between nodes, encrypted-mempool transaction envelopes (in conjunction with threshold key derivation, section 3.6), and encrypted user data within accounts (section 4).

**Rationale.** ChaCha20-Poly1305 is an authenticated encryption with associated data (AEAD) scheme combining the ChaCha20 stream cipher (Bernstein, 2008) with the Poly1305 message authentication code (Bernstein, 2005). It is constant-time by construction (no S-box lookups, no timing-variable branches), software-efficient on platforms without AES-NI hardware acceleration (which includes most ARM mobile devices and many embedded systems), and has been deployed at internet scale through TLS 1.3, WireGuard, and SSH.

The alternative, AES-256-GCM, is faster on platforms with hardware AES acceleration but slower on those without; it is also more difficult to implement in constant time without hardware support. The protocol prioritises portable performance and constant-time guarantees over peak performance on the fastest server CPUs.

**Parameters.** ChaCha20-Poly1305 with 256-bit keys, 96-bit nonces, 128-bit authentication tags. Nonce-uniqueness is enforced by deriving nonces deterministically from a counter that `MUST NOT` be reused with the same key. Implementation details for nonce derivation are specified per-use in subsequent sections.

**Library.** The reference implementation uses the `chacha20poly1305` crate from RustCrypto.

## 3.6 Threshold encryption

The encrypted mempool (section 9) uses threshold encryption built on BLS12-381. Transactions are encrypted by users such that decryption requires cooperation of a threshold of validators serving as keypers. The construction is the standard Boneh-Lynn-Shacham identity-based encryption combined with Shamir secret sharing of the master secret.

**High-level construction.** The validator set holds a shared master secret distributed via a distributed key generation (DKG) protocol at the start of each epoch. A user encrypts a transaction with respect to a public identifier (specifically, the consensus epoch number plus a salt). To decrypt, a threshold of validators contribute decryption shares; the shares are combined to recover the message. No single validator, no minority of validators, and no observer can decrypt before the threshold is reached.

**Parameters.** The threshold is set at two-thirds of validators by stake, matching the consensus safety threshold. Decryption is integrated into consensus: the act of committing a consensus vertex containing an encrypted transaction simultaneously triggers the decryption-share contribution. This integration is what allows Adamant's encrypted mempool to operate at sub-second latency, in contrast to externally-coordinated systems such as Shutter Network on Gnosis Chain (current latency approximately three minutes).

**Distributed key generation.** At each epoch boundary, validators run a Pedersen-style DKG to establish the new master public key and individual key shares. The DKG protocol itself is specified in section 8 alongside consensus. The specification of DKG primitives (commitment, verification) is built on KZG commitments (section 3.7) over BLS12-381.

**Quantum vulnerability.** Threshold encryption based on BLS12-381 is vulnerable to a quantum adversary, in the same way as BLS signatures. The protocol accepts this for the same reason: encrypted mempool envelopes are short-lived. A transaction is encrypted, ordered, and decrypted within a single epoch. After the epoch closes, the transaction is in the chain (in either shielded or transparent form) and the ephemeral encryption is no longer security-relevant. A quantum adversary in 2040 cannot retroactively decrypt transactions from 2030 in any meaningful sense — those transactions are already public knowledge or already finalised in zero-knowledge proofs that do not depend on the original encryption.

**Long-term threshold encryption.** If, at some future point, post-quantum threshold encryption schemes mature into production-ready form, they may be adopted via specification revision under the procedure in section 12. The protocol does not attempt to anticipate which scheme that will be.

## 3.7 Zero-knowledge proofs

The protocol's privacy layer (section 7) and recursive verification (section 8) use zero-knowledge succinct non-interactive arguments of knowledge (zk-SNARKs). Two specific systems are used: **Halo 2** for general-purpose proving with no trusted setup, and **KZG commitments** as a building block for vector commitments and for state commitments inside the consensus layer.

### 3.7.1 General-purpose proving: Halo 2

Halo 2 is a zk-SNARK proving system using the PLONK arithmetisation (Plonkish) over the Pasta curves (Pallas and Vesta), with a polynomial commitment scheme based on the inner product argument (IPA). It does not require a trusted setup ceremony.

**Rationale.** Trusted setups are a structural compromise: they introduce a step in the protocol's lifecycle during which a particular set of participants holds toxic waste whose disclosure would compromise the system. Halo 2's transparent setup eliminates this. The cost is somewhat larger proof sizes and longer verification times than equivalent KZG-based systems with trusted setup. The protocol accepts this cost in exchange for the elimination of the trusted-setup compromise, which is consistent with Principle I (credible neutrality): a trusted setup is a residual centralising assumption.

**Parameters.** Halo 2 is parameterised by the underlying curve and the circuit's row/column structure. The protocol uses the Pasta curves (Pallas as the primary curve, Vesta for recursion) at standard parameters. Specific circuit dimensions are specified per-use throughout the privacy and verification sections.

**Recursive proof composition.** Halo 2's design supports efficient recursive proof composition through the Pasta cycle: a Pallas-curve proof can be verified in a Vesta-curve circuit and vice versa. This is the foundation of Adamant's phone-verifiable property: the entire chain history is compressed into a single recursive proof verifiable on consumer hardware.

**Library.** The reference implementation uses the Halo 2 implementation maintained by the Zcash project (not the original Electric Coin Company implementation, which was deprecated; the maintained fork lives under `halo2`). This implementation is in production in Zcash's Orchard pool and is the most heavily-deployed Halo 2 implementation in existence.

### 3.7.2 Vector and polynomial commitments: KZG

KZG commitments (Kate, Zaverucha, Goldberg 2010) are used inside the consensus layer for state commitments and for certain operations within the encrypted mempool. KZG commitments require a trusted setup: a set of values `[g, g^τ, g^{τ^2}, …, g^{τ^n}]` for a secret `τ` that must be irrecoverably destroyed.

**Justification of trusted setup.** This is the only place in the protocol where a trusted setup is used, and the use case is narrow: KZG commitments are used for fixed-size vector commitments where Halo 2's transparent commitment scheme would be unacceptably large. The trusted setup is exposed only to the size of vectors used inside consensus operations (specifically, validator-set-size vectors), not to general-purpose proving.

**Mitigation: Powers of Tau.** The protocol uses the Ethereum KZG Powers of Tau ceremony output, which had over 140,000 participants between January and July 2023. The security of this setup requires that at least one participant honestly destroyed their contribution; the very large number of participants means that the assumption is violated only if every single participant was simultaneously colluding, which is implausible. The protocol's reuse of this existing ceremony output, rather than running a new one, is deliberate: it transfers all of the cryptographic confidence accumulated by Ethereum's ceremony to Adamant at no marginal cost.

**Parameters.** The protocol uses KZG commitments on BLS12-381, with a trusted setup of size 2^16 (sufficient for validator sets up to approximately 65,000, well above any plausible operational set size). The specific Powers of Tau output used is documented in section 11 (genesis specification).

**Library.** The reference implementation uses the KZG implementation from the `arkworks` ecosystem.

## 3.8 Randomness

The protocol requires randomness in several contexts, each with different properties.

**Per-signature randomness.** Ed25519 is deterministic (signatures derive their randomness from the message and key, eliminating the per-signature randomness requirement). ML-DSA is also deterministic in its standard mode. The protocol uses deterministic signing throughout, eliminating any dependency on the quality of per-signature randomness sources.

**Cryptographic key generation.** Users generating new keys `MUST` use a cryptographically secure random number generator (CSPRNG). The protocol does not specify the user's CSPRNG; this is a property of the user's operating system and wallet software. Reference wallet implementations use `getrandom` on Unix and `BCryptGenRandom` on Windows.

**Consensus randomness.** The consensus protocol (section 8) requires randomness for sequencer selection and for deterministic transaction ordering within DAG vertices. This randomness is derived from a verifiable random function (VRF) bound to validator BLS keys, with output committed in each consensus vertex and verifiable by all participants. The VRF construction is specified in section 8.

**Threshold-encrypted nonces.** The encrypted mempool requires per-transaction nonces that are unpredictable to adversaries. These are derived deterministically from the user's signing key and a transaction-specific identifier, ensuring that each nonce is unique without requiring access to a runtime randomness source.

## 3.9 Library and implementation discipline

The reference implementation `MUST` adhere to the following discipline regarding cryptographic libraries:

1. **No hand-rolled cryptography.** The reference implementation `MUST NOT` include hand-rolled implementations of any cryptographic primitive specified in this section. Where a Rust library is named in a subsection above, that library or an equivalent audited library is the only acceptable implementation source.

2. **Constant-time implementation required.** All cryptographic operations on secret material `MUST` be implemented in constant time. The named libraries (`ed25519-dalek`, `ml_dsa`, `blst`, `chacha20poly1305`) are constant-time by design. New library choices `MUST` preserve this property.

3. **No `unsafe` in cryptographic code.** Rust's `unsafe` keyword permits the bypass of memory-safety guarantees. Cryptographic libraries used by the reference implementation `SHOULD` minimise their use of `unsafe` and `MUST` document and justify any uses. The named libraries either avoid `unsafe` entirely or restrict it to well-audited, performance-critical sections.

4. **Audit history required.** Cryptographic libraries `MUST` have a documented audit history before adoption. New libraries proposed for inclusion `MUST` undergo audit prior to deployment in genesis.

5. **Upstream contribution.** Where the reference implementation requires improvements to upstream cryptographic libraries (performance, additional functionality, bug fixes), contributions `MUST` be offered upstream rather than maintained as forks.

## 3.10 Migration and revision

The cryptographic primitives specified in this section are part of the protocol's consensus rules. Their modification falls under Principle I (credible neutrality): no on-chain mechanism can alter them. Migration to new primitives requires the publication of a new client implementation that node operators individually adopt, in the same manner as any other consensus rule change.

**Anticipated migrations.** The protocol anticipates two categories of cryptographic migration during its operational lifetime:

1. **Algorithmic improvements.** New zero-knowledge proving systems (post-Halo 2), new lattice-based signature schemes (post-ML-DSA), and new threshold encryption schemes are likely to mature into production-ready form during the chain's lifetime. These migrations, if they occur, will be additive: new primitives are introduced alongside existing ones, accounts and applications can elect to use them, and existing primitives are deprecated only after extensive transition periods.

2. **Quantum-induced migrations.** If a quantum adversary materialises before the protocol's BLS-based consensus signatures have been deprecated in favour of post-quantum alternatives, the protocol's safety would be at risk. The protocol's response is the migration path described in section 11: validator signing material can be rotated to ML-DSA-only at the validator's discretion, and consensus signatures can be migrated to a post-quantum aggregation scheme when one matures. The exact mechanism is specified in section 8.

The protocol does not attempt to specify in advance the exact form these migrations will take. The principle is that migrations occur via the same mechanism as any consensus change: through the ordinary process of client release and individual operator opt-in, on a timescale long enough that no party can force a migration on the rest of the network.

## 3.11 What this section does not specify

For clarity, the following are deliberately not specified in this section and are deferred to later sections:

- The exact use of each primitive in transaction structure: deferred to section 5 (Object Model & State).
- The construction of zero-knowledge circuits for shielded execution: deferred to section 7 (Privacy Layer).
- The integration of threshold encryption into the mempool and consensus: deferred to sections 8 (Consensus) and 9 (Networking & Mempool).
- The recursive proof structure attesting to chain validity: deferred to section 8 (Consensus).
- The genesis state, including the specific Powers of Tau parameters: deferred to section 11 (Genesis & Constitution).

This section establishes the primitives. Subsequent sections specify how they are composed.
