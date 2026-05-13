# CLAUDE.md — Project briefing for Claude Code

This file is read automatically at the start of every Claude Code session in this repository. It is the load-bearing context document for the project. **Read it in full before doing anything in this repository.**

---

## TL;DR

You are working on **Adamant**, a Layer 1 blockchain protocol. The user is **Ryan Geldart**. The whitepaper is complete and lives in `/whitepaper`. Implementation is **just beginning**. We are in Phase 1 (reference implementation), writing Rust from scratch, working through the whitepaper crate by crate. **The whitepaper is the spec; the code implements it.** Standard cryptographic primitives only. Apache 2.0. No tokens, no fundraising, no marketing language ever.

---

## Section 1: What Adamant is

Adamant is a Layer 1 blockchain protocol designed around a single thesis:

> **The chain you use when you don't trust anyone.**

The protocol delivers properties that no existing programmable chain delivers in combination:

- **Credible neutrality.** No foundation, no admin keys, no on-chain governance, no upgrade authority, no premine.
- **Privacy by default.** Programmable shielded execution via zero-knowledge proofs. Selective disclosure via view keys.
- **High throughput.** DAG-based consensus targeting 200,000+ TPS on a single shard, sub-second finality.
- **Phone-verifiable.** Recursive zk proofs compress chain history into a constant-size proof verifiable on consumer hardware.
- **Encrypted mempool.** Threshold encryption integrated into consensus, eliminating MEV and validator-level censorship at the protocol layer.
- **Post-quantum from genesis.** ML-DSA alongside Ed25519.
- **Mutability as a declared property.** Every contract declares its mutability rules at creation; declarations are protocol-enforced.
- **Fair distribution at launch.** Zero premine, zero founder allocation, zero VC round. The 100,000,000 ADM genesis pool is a protocol-level construct, not held by any party; it drains via two public acquisition paths (burn-to-mint and validator block rewards) per §10.2.3.

The contribution is the synthesis. Each property exists somewhere in production. **No chain combines them.** That gap is the project's reason to exist.

---

## Section 2: Where to read first (in priority order)

Before touching any code or making any substantive suggestion, read these files in this order. They are mandatory context.

1. **`/whitepaper/02-design-principles.md`** — The seven principles in priority order. The most important file in the repo. **Proposals contradicting any principle are rejected on principle, not re-litigated.** If a request to Claude Code conflicts with a principle, push back on the request rather than silently compromising.

2. **`/whitepaper/11-genesis-constitution.md`** — The constitutional commitment. What's fixed forever, what's not, the explicit promises by the original implementers (no admin keys, no premine, etc.). This is the document that defines what we promised the world.

3. **`/whitepaper/01-introduction.md`** — Gap analysis of the existing chain landscape. The case for why Adamant needs to exist.

4. **`/whitepaper/00-abstract.md`** — One-page distillation.

5. **`/whitepaper/README.md`** — Section-by-section table of contents.

The other whitepaper sections (3-10, 12) are detailed technical specifications for individual subsystems. Read the relevant section before working on the corresponding code:

- Working on cryptography? → Read `/whitepaper/03-cryptographic-foundation.md` first.
- Working on accounts? → Read `/whitepaper/04-identity-accounts.md` first.
- Working on the object model? → Read `/whitepaper/05-object-model-state.md` first.
- Working on the VM? → Read `/whitepaper/06-execution-vm.md` first.
- Working on the privacy layer? → Read `/whitepaper/07-privacy-layer.md` first.
- Working on consensus? → Read `/whitepaper/08-consensus.md` first.
- Working on networking? → Read `/whitepaper/09-networking-mempool.md` first.
- Working on economics/fees? → Read `/whitepaper/10-economics-incentives.md` first.

**Do not skip these reads.** The whitepaper contains specific decisions (parameters, primitive choices, structural commitments) that you will not derive correctly from general blockchain knowledge.

---

## Section 3: The seven design principles, summarised

These are constitutional. In priority order:

1. **Credible neutrality.** No party has unilateral capability to alter the protocol. No on-chain governance. No foundation. No premine. No admin keys. Forks require individual node-operator opt-in.

2. **Privacy by default.** Transactions are shielded by default. Users retain selective disclosure via view keys. No backdoor decryption.

3. **Verifiability without trust.** Anyone can verify the chain on consumer hardware (smartphone-class) without trusting any third party.

4. **Performance sufficient for use.** 200,000+ TPS, ~500ms finality for owned-object transactions, ~$0.0001 floor for simple transfers.

5. **Mutability as a property of objects.** Chain rules are immutable; objects declare their own mutability rules at creation; declarations are themselves immutable and visible to users before interaction.

6. **Standard primitives, novel synthesis.** Use peer-reviewed cryptography. Never roll our own. Innovation is at the systems layer.

7. **Permissionless participation.** No registration, no whitelisting, no permission gates at the protocol level.

When two principles conflict, the higher-numbered one yields. The full text and justification is in `/whitepaper/02-design-principles.md`.

---

## Section 4: How we work

### Spec drives code, always

The whitepaper is canonical. If implementation reveals a problem with the spec, we update the spec first (in conversation with Ryan in the main Claude chat), then implement. Never the other way around. **Code that conflicts with the whitepaper is buggy code, not a revised spec.**

If you discover a genuine spec problem during implementation:
1. Stop coding.
2. Document the problem clearly (what the spec says, what doesn't work, why).
3. Tell Ryan. Suggest he raise it with Claude in the main chat for a spec revision.
4. Resume implementation only after the spec is updated.

### Quality over speed

Every line ships at production quality. No "we'll fix it later" placeholders. No copy-pasted boilerplate without understanding what it does. The protocol cannot be patched after genesis (Principle I), so we cannot afford to ship sloppy code. We move at the speed of *quality*, not the speed of typing.

This means:
- Every public function has a doc comment explaining what it does and why.
- Every non-obvious decision in the code has an inline comment citing the whitepaper section it implements.
- Every error path is handled. No `unwrap()` outside tests. No silent failures.
- Every module has tests before it has callers.
- Every cryptographic operation has property-based tests.

### Standard cryptographic primitives only

We do not roll our own cryptography. The whitepaper specifies exact libraries:

- **Hashing:** `sha3` (SHA3-256, SHAKE-256), `blake3` (auxiliary), Poseidon via `halo2_gadgets`
- **Classical signatures:** `ed25519-dalek`
- **Post-quantum signatures:** `ml_dsa` (RustCrypto)
- **BLS signatures and pairing:** `blst` via `blst-rs`
- **Symmetric encryption:** `chacha20poly1305`
- **Zero-knowledge proofs:** `halo2` (zcash variant), `halo2_gadgets`
- **Vector commitments:** KZG via `arkworks`

If a task seems to require a primitive not in this list, **stop and check with Ryan**. Do not improvise. Do not write your own implementation of an existing primitive. Do not pull in an unaudited library.

### Public from day one

This repo is public. Anything committed is permanent and visible. Treat every commit message and code comment as a public statement. No private jokes, no internal references, no "TODO: figure out what this does."

### No tokens, no fundraising, no marketing

This project does not have a token until genesis. There is no presale, no airdrop, no investor allocation. Anyone soliciting investment in "Adamant tokens" before genesis is a scammer.

The repo and any communications about the project must never include:
- Investment-solicitation language
- Token price predictions
- Roadmap commitments beyond what's in the whitepaper
- Marketing-style claims ("revolutionary", "next-generation", "world-changing")
- Endorsements of specific applications, wallets, or third-party software

The whitepaper sets the tone. Match it.

---

## Section 5: Repository structure (current and planned)

### Current

```
adamant/
├── README.md           Top-level project introduction
├── LICENSE             Apache 2.0
├── .gitignore          Rust-flavoured
├── CLAUDE.md           This file
└── whitepaper/         Complete v0.1 specification
    ├── README.md       Section index
    ├── 00-abstract.md
    ├── 01-introduction.md
    ├── 02-design-principles.md
    ├── 03-cryptographic-foundation.md
    ├── 04-identity-accounts.md
    ├── 05-object-model-state.md
    ├── 06-execution-vm.md
    ├── 07-privacy-layer.md
    ├── 08-consensus.md
    ├── 09-networking-mempool.md
    ├── 10-economics-incentives.md
    ├── 11-genesis-constitution.md
    ├── 12-conclusion.md
    └── adamant-whitepaper-v0.1-draft.md  (merged single-file)
```

### Planned (to be built incrementally)

```
adamant/
├── (existing files)
├── Cargo.toml          Workspace root
├── rust-toolchain.toml Pinned Rust version
├── crates/             Reference implementation crates
│   ├── adamant-crypto/         Standard primitive wrappers (Section 3)
│   ├── adamant-types/          Core data types from sections 4 & 5 (Object, Address, etc.; Transaction lives in adamant-vm)
│   ├── adamant-account/        Account and identity logic (Section 4)
│   ├── adamant-state/          Object model and state management (Section 5)
│   ├── adamant-vm/             Adamant Move VM (Section 6)
│   ├── adamant-privacy/        Privacy layer, Halo 2 circuits (Section 7)
│   ├── adamant-consensus/      DAG consensus, recursive proofs (Section 8)
│   ├── adamant-network/        libp2p integration, mempool (Section 9)
│   ├── adamant-economics/      Fees, issuance, staking (Section 10)
│   ├── adamant-genesis/        Genesis state and bootstrap (Section 11)
│   ├── adamant-node/           Validator/full node binary
│   ├── adamant-light/          Light client binary
│   └── adamant-cli/            Command-line tooling
├── specs/              Formal specifications, test vectors
├── docs/               Developer-facing documentation
├── tools/              Build and dev tooling
└── tests/              Integration and end-to-end tests
```

Crates are added in implementation order, not all at once.

---

## Section 6: Implementation order

We build in this order. Each phase produces a working artifact before the next begins. **Do not skip ahead.**

1. **Phase 1: `adamant-crypto`** — Wrappers around the standard primitive libraries. Establish the cryptographic foundations cleanly before anything else depends on them.

2. **Phase 2: `adamant-types`** — Core data types from whitepaper sections 4 (identity & accounts) and 5 (object model & state): `Address`, `ObjectId`, `TypeId`, `Object`, `Mutability`, `Ownership`, `Lifecycle`, etc. No behaviour yet, just types and canonical serialisation (BCS per whitepaper 5.1.8). The `Transaction` type is deferred to Phase 5 (`adamant-vm`) where the VM and transaction format are specified together; defining it earlier means inventing fields the spec does not pin.

3. **Phase 3: `adamant-account`** — Account creation, validation logic, key rotation, view keys.

4. **Phase 4: `adamant-state`** — Object storage, state transitions, version tracking, the GNCT (global note commitment tree) skeleton.

5. **Phase 5: `adamant-vm`** — Adamant Move VM. This is large; expect it to take many sessions.

6. **Phase 6: `adamant-privacy`** — The Halo 2 circuits for shielded execution, stealth addresses, view keys.

7. **Phase 7: `adamant-network`** — libp2p integration, gossipsub, mempool.

8. **Phase 8: `adamant-consensus`** — DAG protocol, threshold encryption integration, recursive proofs.

9. **Phase 9: integration and binaries** — `adamant-node`, `adamant-light`, end-to-end tests.

10. **Phase 10: testnets and audits** — Public testnets, security audits, hardening.

This order is deliberate. Cryptography first because everything depends on it. Types second because nothing meaningful can be written without them. Each phase establishes foundations the next phases need.

---

## Section 7: Tech stack and tooling

### Required

- **Rust:** edition 2021 minimum. Use the latest stable Rust unless we have a specific reason for a fixed version (we'll pin it in `rust-toolchain.toml` when the workspace is created).
- **Cargo workspace.** All crates under one workspace. Shared lints, shared dependencies.
- **Async runtime:** `tokio`.
- **Networking:** `libp2p` (rust-libp2p).
- **Storage:** `RocksDB` via `rocksdb` crate.
- **Serialisation:** `serde` for general serialisation, `bincode` or canonical Move serialisation where determinism matters.
- **Testing:** built-in `cargo test`, `proptest` for property-based testing, `criterion` for benchmarks.

### Linting

- `clippy` with warnings as errors.
- `rustfmt` enforced. The default config is fine; if we ever customise, document it in a top-level `rustfmt.toml`.
- `#![forbid(unsafe_code)]` on all crates by default. Crates that need unsafe (almost none should) must justify it explicitly.

### CI

- GitHub Actions. Three required checks on every PR: `cargo build --workspace`, `cargo test --workspace`, `cargo clippy --workspace -- -D warnings`.
- CI must pass before merging to `main`.

### Versioning

- Semantic versioning across the workspace.
- Until v1.0, breaking changes are expected. After v1.0 (the genesis-ready version), breaking changes require hard fork (Principle I).

---

## Section 8: What you should and shouldn't do

### Should

- Read the relevant whitepaper section before writing code for that subsystem.
- Cite the whitepaper section that backs every non-trivial design decision (e.g. `// Per Section 5.1.4: mutability is enforced at consensus, not user code`).
- Push back when a request looks wrong. Disagree when there's a reason.
- Write tests before or alongside code, not after.
- Suggest improvements to the workspace structure, CI, dev tooling.
- Catch contradictions between the whitepaper and proposed code. Surface them clearly.
- Run `cargo fmt`, `cargo clippy`, and `cargo test` before declaring work done.
- Show diffs before committing. Commit with clear messages tied to the whitepaper section being implemented.
- build everything in adamant native focus

### Should not

- Modify the whitepaper without explicit user approval. The spec is constitutional. If the user asks you to update the spec, suggest they do it in the main Claude chat where the spec is being maintained — Claude Code is for implementation.
- **Never modify `/whitepaper/02-design-principles.md` or `/whitepaper/11-genesis-constitution.md`.** These are the load-bearing constitutional sections. Any change requires deliberate process, not a Claude Code session.
- Roll your own cryptography. Use vetted libraries.
- Add token-related language, marketing copy, price/value content, or anything resembling investment solicitation.
- Make decisions that conflict with credible neutrality (no admin keys, no foundation accounts, no governance, no premine) without flagging the conflict explicitly.
- Use `unsafe` Rust in new code unless absolutely required and justified inline.
- Pull in dependencies not vetted against the whitepaper's primitive list. If you need a new dependency, justify it.
- Commit without showing the user the diff first.
- Use `unwrap()` outside tests. Use `expect()` with a helpful message, or proper error handling, or `?`.
- Skip writing tests because the code "obviously works."
- use any other networks or projects work - causing major problems implement adamant native propertys only

---

## Section 9: Communication style

- Be direct. Push back when something looks wrong. Disagree when there's a reason.
- Cite the whitepaper section that backs a recommendation, not just the recommendation.
- When unsure, say so. Don't invent.
- Treat Ryan as a serious technical collaborator, not someone who needs hand-holding. Skip preambles, confirmations, and excessive politeness — just do the work and explain what was done.
- Match the whitepaper's tone in commit messages and code comments: precise, honest, no marketing.

---

## Section 10: Current status

**Phase**: 6 — privacy layer (whitepaper §7). Phase 5/5 closed at commit `5e1bb0d` per the §6.2.1 spec architecture. Phase 5/6 (AVM runtime) ~93% complete on its own track; the privacy-layer workstream runs in parallel. Phase 6 sub-arcs through 6.8b.5 (proving-key infrastructure) closed at this state-bump:

- **Phase 6.0–6.7** (Poseidon out-of-circuit primitives, encrypted-note format, ML-KEM-768 stealth addresses, GNCT skeleton, view keys, encrypted memos): closed.
- **Phase 6.8a** (`ShieldedTransaction` wire types) + **Phase 6.9a** (`RecursiveProofEnvelope` wire types): closed.
- **Phase 6.8b.0–6.8b.3** (Halo 2 fork into `adamant-halo2` per CLAUDE.md §14.4 Decision 1 / Path C2 — Poseidon Pow5Chip, ECC chips for Pallas, utilities, dev/MockProver surface): closed.
- **Phase 6.8b.4a–6.8b.4e-3** (validity-circuit gadgets per §7.3.2: note-commitment, nullifier, GNCT Merkle membership, range checks, value commitments, full `ValidityCircuit` composition at fixed N=1, M=1, DEPTH=4): closed at commit `17153c7` with hardcoded fixed-base Lagrange tables for the §7.3.1.2 R generator (1,223 LOC generated by `tools/gen-fixed-base-tables` outside the production-binary dep graph).
- **Phase 6.8b.5** (this state-bump) — **CLOSED**. Two commits on origin: `54cc680` (const-generic `N_INPUTS`/`N_OUTPUTS` over `ValidityCircuit` + `ProductionValidityCircuit<N, M>` type alias at DEPTH=64 per §7.2 + `expensive-tests` feature gate) and `c52ec18` (new `adamant-privacy::proving` module wrapping `adamant-halo2`'s PLONK keygen / prove / verify in Adamant-shape APIs: `ValidityKeySet<DEPTH, N, M>`, `prove`, `verify`, `ProvingError`). Workspace tests 2338 → 2345 (+7); adamant-privacy lib 269 → 276 (+7). Pasta-cycle pin: circuit over `pallas::Base` commits on Vesta (`vesta::Affine`); Blake2b transcript inherited from the `adamant-halo2` fork per Path C2 — changing it would change proof bytes and is hard-fork-only. VK serialization deferred to a follow-up sub-arc; current posture is verifiers re-derive the VK from the genesis-fixed circuit shape (deterministic re-derivation, reproducible).

**Phase 6 remaining sub-arcs** (deferred to subsequent sessions):

- **Phase 6.8b.4f** (statement 7 — shielded contract execution): blocked on Phase 7+ AVM. Rolls forward as Phase 7+ work alongside the AVM integration.
- **Phase 6.9b** (recursive proving per §8.5.2): the recursive verifier circuit composing proof-of-validity with proof-of-prior-recursion via accumulators (IVC). Genuinely large sub-arc — order of magnitude similar to all of 6.8b.4 combined; needs spec-author plan-gate.
- **Phase 6.10** (selective disclosure per §7.4): view-key + sub-view-key derivation circuits + `ReleaseSubViewKey` handler. May turn out to be partly out-of-circuit (key-schedule + AEAD on memo); spec-author plan-gate at sub-arc start.

**Phase 6 deferred-hygiene work logged** at this state-bump:

- 2×2 MockProver positive test for `ValidityCircuit` (requires ~150 LOC of real 16-leaf Merkle tree construction; the synthesize loop body is straight-line code with no cross-iteration state beyond row-index arithmetic, independently pinned by `public_input_count_pinned` and `production_circuit_type_constructs` tests).
- VK wire serialization (proving keys are deterministic from circuit shape + Params, so they don't ship over the wire; the VK ships only if validators want to skip per-startup re-derivation, which is a startup-time optimization rather than a correctness requirement).

**Phase 6 foundation update (commit `ebe09bd`)** — three remaining sub-arcs (6.10, 6.9b, 6.8b.4f) now have type-level foundations in place. Workspace tests 2345 → 2365 (+20).

- **6.10a** — typed `ViewKeyScope` enum (TimeWindow / Counterparty / AmountThreshold / Compliance) added to `view_key.rs` with canonical BCS encoding pinned. `derive_sub_view_key_typed` convenience wrapper composes scope encoding with the existing raw-bytes derivation path. The view-key hierarchy + sub-view-key derivation + AVM `ReleaseSubViewKey` runtime handler were already in place from prior phases.
- **6.10b** — new `assertion` module with `AssertionCircuit` trait (extends `Circuit<pallas::Base>` + `PublicInputs` associated type + `K` const) and `RangeAssertionCircuit` worked-example proving `value ≥ threshold`. Uses dual 64-bit range checks (`value` and `delta = value - threshold`) plus a custom sum gate constraining `value - threshold_pub - delta == 0` with the threshold copy-constrained from the public-input instance column. K=9. 9 tests covering positive (above + equality), negative (threshold mismatch, malformed value bits, malformed delta bits), arity, panic-on-bad-construct, keygen compile.
- **6.9b foundation audit** — recorded in `recursive_proof.rs` module docs. Out-of-circuit IPA primitives (`Guard`, `Accumulator`, `MSM`, `verify_proof` returning `Guard`) are present and mature in `adamant-halo2`; in-circuit recursive verifier gadgets (in-circuit MSM, in-circuit transcript replay, in-circuit IPA opening) are NOT yet in the fork and need to be added at 6.9b proper. Two open spec-author plan-gate questions documented inline: Pasta-cycle posture (homogeneous pure-Pallas accumulators vs heterogeneous Pallas-Vesta cross-cycle) and recursion granularity (per-epoch confirmed-or-open).
- **6.8b.4f foundation** — new `shielded_contract` module resolving §6.2.1.4's "deferred to section 7" question for circuit-reference pool location: **per-module pool field** (rationale in module docs — smallest scope at which a shielded function lives, clean upgrade semantics, smallest update-risk surface). Ships `ShieldedSlotType` closed enum (BaseField / ScalarField / AffinePoint / Bool / U64) with pinned BCS variant tags, `CircuitSignature { inputs, public_inputs }` with `public_input_rows()` helper, `CircuitReference { signature, vk_digest, k }` per-entry type, `CircuitReferencePool { references }` per-module pool with add/resolve API + BCS round-trip + u16-cap full-error, and `ShieldedContractCircuit` trait as the target the Adamant Move → Halo 2 compiler will produce concrete implementors for. 6 tests covering pool lifecycle, BCS round-trip, slot-type variant tag pin, signature row computation, full-pool error.

**Phase 6 spec-author plan-gate questions still open** (both deferred to user-author deliberation, neither blocking the foundation work):

- **6.9b plan-gate**: Pasta-cycle posture (homogeneous vs heterogeneous) and recursion granularity. Phase 6.9b implementation work waits for these.
- **6.8b.4f plan-gate**: §7.3.2 statement-7 verification mechanism (in-circuit recursive verification depending on 6.9b vs public-input commitment with separate validator verification — both readings consume the same foundation in this state-bump). Plus Adamant Move → Halo 2 compiler scope as a separate Phase-planning question.

After the plan-gates resolve, the implementation sub-arcs build on the foundations shipped here.

**Phase 5 + Phase 6 closure state-bump (commit `e693361`)** — three substantive sub-arcs landed atop the foundation work, closing the gap between Phase 5 and Phase 7. Workspace tests 2365 → 2388 (+23).

- **Phase 5/6.7** — KZG bytecode dispatch wired. `dispatch_kzg_commit` and `dispatch_kzg_verify` replace the prior `InvalidInstruction` stubs in `runtime/interpreter.rs`. New `InvariantViolationReason::KzgSetupNotLoaded` runtime-misconfiguration variant. New `InterpreterState::kzg_setup` field (Arc-wrapped for cheap cross-state sharing). Constant-time discipline matched: malformed inputs return `Bool(false)` for verify, structured invariant for commit. End-to-end commit→open→verify round-trip exercises real BLS12-381 pairing equations. 7 dispatch tests passing (including round-trip + tampered-evaluation rejection + malformed-commitment rejection). adamant-vm gains direct dep on `adamant-crypto-blst-extra`.
- **Phase 5/6.8** — `module_deploy` computes the §5.1.7 KZG `proof_commitment` to the bytecode polynomial when the setup is loaded (production path); falls back to zero-bytes placeholder when unset (test path). Encoding: 31-byte bytecode chunks padded to 32-byte BE scalars with leading zero (always < BLS12-381 field modulus). New `bytecode_to_proof_commitment` helper in `stdlib.rs`. `TransactionContext` gains `kzg_setup: Option<&KzgSetup>` field. **Phase 5/6 substantively closed** — only spec-author calibration items remain (gas-cost calibration, structural-limits values, EthPoT genesis ingestion mechanism), all pre-mainnet hardening.
- **Phase 6.9b** — pure-Pallas accumulator-folding recursive proving. **CLOSED.** Plan-gate resolutions per delegation: pure-Pallas accumulator-deferral (homogeneous; smallest fork scope; standard Halo-paper construction), per-epoch granularity (matches §8.5.2 verbatim), §8.5.2 "constant-size proof" interpreted as the accumulator point itself (32 bytes — even smaller than the spec's "5-10 KB" upper bound; in-circuit verifier extension is a future perf optimization producing succinct SNARK-of-SNARK proofs at identical identity-check semantics). New `adamant-halo2::recursion` module with `RecursiveAccumulator<C>` + `fold_proofs` + bytes round-trip (6 tests). New `MSM::eval_to_curve_point` method (returns the multiexp result rather than the bool identity check). New `adamant-privacy::epoch_recursion` module wiring through the validity-circuit prove pipeline: `EpochAccumulator` = `RecursiveAccumulator<vesta::Affine>`, `fold_epoch` + `envelope_from_accumulator` + `verify_envelope` + `verify_chain_link` (10 tests including the canonical end-to-end soundness pin: two real validity proofs fold to identity, tampered proofs are rejected at fold-time or produce non-identity accumulator).

**Phase 6 cumulative state at this closure**:

- **Phase 6.0–6.7**: closed (Poseidon, encrypted-note format, ML-KEM-768 stealth addresses, GNCT skeleton, view keys, encrypted memos).
- **Phase 6.8a + 6.9a**: wire types closed.
- **Phase 6.8b.0–6.8b.3**: Halo 2 fork closed.
- **Phase 6.8b.4a–6.8b.4e-3**: validity-circuit gadgets closed (6 of 7 §7.3.2 statements in-circuit + value-commitments + DEPTH=64 production type alias).
- **Phase 6.8b.5**: const-generic ValidityCircuit + prove/verify infrastructure closed.
- **Phase 6.10a + 6.10b**: typed view-key scopes + AssertionCircuit framework + RangeAssertionCircuit closed.
- **Phase 6.9b**: recursive accumulator-folding closed (this state-bump).

**Phase 6 remaining sub-arcs** (deferred per the user's explicit decision on October 2026 sessions):

- **Phase 6.8b.4f** — shielded contract execution (§7.3.2 statement 7). Foundation laid (CircuitReferencePool + ShieldedContractCircuit trait + ShieldedSlotType enum). Two open spec-author plan-gate questions: §7.3.2 statement-7 verification mechanism (in-circuit recursive vs public-input commitment) + Adamant Move → Halo 2 compiler scope. Deferred to post-Phase-7 — shielded transfers (the validity circuit) work without it; only programmable shielded contracts need it.
- **Phase 6.10b extensions** — additional concrete assertion circuits (proof-of-solvency, received-from-X-between-D1-and-D2, not-received-from-X). Wallet-side; not protocol-blocking. Deferred to when wallets need them.
- **Phase 6.9b extension** — in-circuit Halo 2 verifier (succinct SNARK-of-SNARK proofs). Perf optimization; soft fork. Pre-mainnet or post-genesis venue.

**Phase 7 unblocked**: with 6.9b's recursive accumulator-folding shipped + KZG dispatch wired + AVM stdlib `module_deploy` complete, the consensus layer (DAG-BFT, threshold-encrypted mempool, time-lock VDF, libp2p networking, validator-set management, recursive-proof submission market) has all the cryptographic primitives + execution surfaces it needs to start being built.

**Phase 1-6 audit closure (commit `de382a2`)** — comprehensive pre-Phase-7 audit landed. Three parallel research agents (structural, cleanliness, cryptographic+dependency) inventoried the workspace; findings synthesized into a prioritized fix list and shipped. Strict-mode workspace audit passes.

Posture findings (good news):

- **Resistant-proof guards** both pass: Sui-Move (`tests/no_sui_in_production_deps.rs`) + upstream halo2_* (`tests/no_upstream_halo2_in_production_deps.rs`).
- **Constant-time discipline** exemplary across `adamant-crypto` + `adamant-privacy`. All secret-material types impl `subtle::ConstantTimeEq`.
- **Unsafe code** properly isolated to `adamant-crypto-blst-extra` (BLS12-381 FFI); 20/20 unsafe blocks carry SAFETY comments.
- **RNG discipline** correct: production parameterizes via `RngCore` + `CryptoRng` trait; tests use `OsRng`.
- **Module-level docs**: 148/148 `*.rs` files (100%).
- **Test-name discipline**: every sampled test name behavioral; zero `test_1` / `it_works`.
- **Cargo features**: minimal and documented (`expensive-tests`, `multicore`, `vendored-test-suite`, `test-dependencies`).

Fixes shipped at audit closure:

- **Explicit `#![forbid(unsafe_code)]`** added to 5 crates that previously inherited it implicitly from the workspace lint: adamant-account, adamant-crypto, adamant-state, adamant-types, adamant-vm. Defense-in-depth + audit-clarity. adamant-crypto-blst-extra remains the sole exception per its FFI nature.
- **Doc coverage now 100% across all 8 Adamant-authored crates** (952 pub items, 0 undocumented). Two genuine gaps fixed: `adamant-bytecode-format::u256::checked_mul` and `adamant-types::signature::Signature`. Two earlier "gaps" reported by audit agents turned out to be false positives from multi-line `#[derive]` attribute parsing.
- **New audit tool** at `tools/workspace-audit/audit.py` (Python 3, stdlib-only) for ongoing health monitoring. Checks: doc coverage, forbid declarations, module docs, TODO census, unwrap heuristic, LOC. Strict-mode (`--strict`) exits 1 on any failure for CI integration.

Final state at audit closure:

| crate | LOC | pub items | doc cov | forbid |
|---|---|---|---|---|
| adamant-account | 111 | 1 | 100.0% | yes |
| adamant-bytecode-format | 3,351 | 209 | 100.0% | yes |
| adamant-crypto | 3,183 | 166 | 100.0% | yes |
| adamant-crypto-blst-extra | 571 | 37 | 100.0% | (FFI) |
| adamant-privacy | 8,009 | 271 | 100.0% | yes |
| adamant-state | 606 | 8 | 100.0% | yes |
| adamant-types | 1,239 | 61 | 100.0% | yes |
| adamant-vm | 39,890 | 199 | 100.0% | yes |
| **TOTAL** | **56,960** | **952** | **100.0%** | |

Workspace tests: 2,388 passing, 0 failed, 1 ignored. Clippy `-D warnings`: clean. `cargo fmt --check`: clean. Resistant-proof guards: pass. **Phase 1–6 audit ratified.**

**Phase 7.0 closure (commit `d091bae`)** — Phase 7 begins. The 12-sub-arc consensus workstream's foundation lands: new `adamant-consensus` crate (Adamant-authored crate #9) carrying the validator-identity types per whitepaper §8.1.1–8.1.9. Workspace tests 2,388 → 2,440 (+52); workspace LOC 56,960 → 57,748 (+788).

**Phase 7 sub-arc map**:

| Sub-arc | Spec | Surface | Status |
|---|---|---|---|
| **7.0** | §8.1.1–8.1.9 | validator identity + types | **CLOSED** |
| **7.1** | §8.1.3, 8.1.5, 8.1.8 | active set + slot mgmt + slot transfer + liveness detection | **CLOSED** |
| **7.2** | §8.2, 8.3.2, 8.3.3 | epoch/round scheduling + commit-wave indexing + quorum threshold | **CLOSED** |
| **7.3** | §8.3.1 | DAG vertex structure (Vertex, VertexId, BCS-encoded body, BLS sig) | **CLOSED** |
| **7.4** | §8.6 | consensus VRF (BLS-aggregate share/output/verify/randomness) | **CLOSED** |
| **7.5.0** | §3.8, 8.4.4 | time-lock VDF foundation — wire types + domain tags (`adamant-crypto::vdf`) | **CLOSED** |
| **7.5.1a** | §3.8.1 | binary quadratic form arithmetic (type, reduce, normalize, identity, inverse, predicates) | **CLOSED** |
| **7.5.1b** | §3.8.1 | class-group composition (Gauss / Cohen 5.4.7) | **CLOSED** |
| **7.5.1c** | §3.8.1 | fast squaring (Cohen 5.4.8) | **CLOSED** |
| **7.5.1d** | §3.8.1 | `ClassGroupElement ↔ BinaryQuadraticForm` byte-encoding wiring | **CLOSED** |
| **7.5.2a** | §3.8.6 (new) | deterministic class-group discriminant derivation + spec amendment | **CLOSED** |
| **7.5.2b** | §3.8.6 | hash-to-element (Miller-Rabin + Jacobi + Tonelli-Shanks) | **CLOSED** |
| **7.5.3** | §3.8.7 (new) | Wesolowski VDF evaluate / prove / verify | **CLOSED** |
| **7.5.4** | §3.8.8 (new) | time-lock envelope encryption (encrypt / decrypt / verify_decryption) | **CLOSED** |
| **7.5** | §3.8 | time-lock VDF workstream | **CLOSED end-to-end** |
| **7.6** | §3.6, §8.4, §3.8.5 | threshold-mempool regime hysteresis + wire types | **CLOSED** |
| **7.7a** | §8.3.1, §8.3.2, §8.1.5 | DAG state storage + insertion validation | **CLOSED** |
| **7.7b** | §8.3.3, §8.6 | commit-wave logic (anchor election + direct commit + total ordering) | **CLOSED** |
| **7.7c** | §8.3.3, §8.7 | indirect commit + halt detection + §8.7 invariants | **CLOSED** |
| **7.7d** | §3.6, §3.8, §8.4 | mempool decryption (threshold/time-lock flows) | **CLOSED** |
| **7.7e** | §8.3, §8.7 | end-to-end integration tests | **CLOSED** |
| **7.7** | §8.3, §8.7 | **DAG-BFT consensus core — feature-complete end-to-end** | **CLOSED** |
| 7.8 | §9 | networking + transaction propagation | pending |
| **7.9** | §8.1.7, §8.9 | light-client observation layer (tier signal + epoch boundary) | **CLOSED** |
| **7.10** | §8.1.5, §10 | slashing wiring (evidence + verification + apply) | **CLOSED** |
| 7.11 | all | end-to-end integration | pending |

Phase 7.0 surface (per §8.1.1–8.1.9):

- `identity::ValidatorPublicKeys` — bundle of (Ed25519 32B + ML-DSA-65 1952B + BLS12-381 96B) public keys. BCS-canonical encoding 2080 bytes per validator.
- `identity::ValidatorId` — content-derived 32-byte identifier via `sha3_256_tagged(VALIDATOR_ID, BCS(public_keys))`. Mirrors §4.2 account-address derivation pattern.
- `validator::Stake` — newtype around `u64` ADM micro-units (1 ADM = 1e6 micro-units). Saturating + checked arithmetic.
- `validator::Validator` — on-chain validator record per §8.1.2 with `id` + `public_keys` + `operator` + `stake` + `registered_at_epoch`. BCS-canonical encoding 2160 bytes.
- `validator::MIN_VALIDATOR_STAKE_LAUNCH = 1000 ADM` per §8.1.6 / §11.5.4 (subject to pre-mainnet calibration per §11.5.4).
- `tier::SecurityTier` — Tier I / II / III enum with `from_active_set_size` per §8.1.7 boundaries (7→I, 14→I, 15→II, 29→II, 30→III) + `meets_minimum` for application gating.
- `genesis::GenesisCohortMarker` — non-transferable §8.1.9 marker {position 1..=75, activated_at_epoch, chain_state_commitment 32B}. Position-1 = chain anchor per §8.1.6 + §8.6.
- `genesis::GENESIS_COHORT_SIZE = 75` (constitutional per §8.1.9).
- `epoch::EpochNumber` / `epoch::RoundNumber` — `u64` newtypes per §8.2 / §8.3.2 with saturating + checked successor.
- `slashing::SlashOffence` — closed enum {Equivocation, IncorrectThresholdDecryption, LivenessFailure, InvalidProof} per §8.1.5.
- `slashing::slashing_penalty_basis_points` — pinned per-offence values: Equivocation=10000bp(100%), InvalidProof=1000bp(10%), IncorrectThresholdDecryption=500bp(5%), LivenessFailure=50bp(0.5%). LivenessFailure additionally triggers active-set removal.

New domain tag in adamant-crypto: `domain::VALIDATOR_ID = b"ADAMANT-v1-validator-id"`. Used for ValidatorId derivation per §8.1.2.

52 unit tests in adamant-consensus covering BCS round-trips, byte-size pins, variant-tag pins, boundary conditions for SecurityTier transitions (especially the 14→15 threshold-encryption-viability boundary aligning with §8.4 + §8.1.7), slashing-penalty values, genesis-cohort position bounds (rejects 0 and >75), and a known-answer test for ValidatorId derivation that re-derives the formula from scratch.

**Audit-script extension**: `tools/workspace-audit/audit.py` updated to include `adamant-consensus` in the crate roster. Workspace doc coverage stays at 100.0% across all 9 Adamant-authored crates (1,001 pub items, 0 undocumented).

**Phase 7.1 closure (commit `731265d`)** — active set + slot management + slot transfer + liveness detection per whitepaper §8.1.3 + §8.1.5 + §8.1.8. Workspace tests 2,440 → 2,479 (+39); adamant-consensus LOC 787 → 1,466 (+679); pub items 48 → 82 (+34).

Phase 7.1 surface:

- `slot::SlotId` — `u16` newtype per §8.1.3.
- `slot::SlotStatus` — closed enum {Active, Standby, Inactive} with pinned BCS variant tags (0x00 / 0x01 / 0x02). Reordering is a hard fork.
- `slot::Slot` — per-slot record {id, validator_id, bound_at_epoch, last_participation_epoch, status}. BCS-canonical 51 bytes. Lifecycle: Standby → Active → Inactive.
- `slot::Slot::is_liveness_failed(current_epoch)` — §8.1.5 detector. "More than 2 consecutive missed epochs" ⇔ `current - last_participation > 3`. Pin: 2 missed = OK, 3 missed = FAILED. Only active slots can fail liveness per §8.1.3.
- `slot::SlotTransfer` — §8.1.8 atomic transfer record {slot_id, seller_validator_id, buyer_validator_id, initiated_at_epoch}. `effective_at_epoch = initiated + 1` (transfer takes effect at next epoch boundary per §8.1.8 step 3). BCS-canonical 74 bytes.
- `active_set::ACTIVE_SET_FLOOR = 7` (constitutional per §8.1.3; below this the chain is dormant per §8.1.6 / §8.7.1).
- `active_set::ACTIVE_SET_LAUNCH_CEILING = 75` (soft, per §8.1.3; matches `GENESIS_COHORT_SIZE` exactly).
- `active_set::ActiveSet` — in-memory data structure {active: Vec<Slot>, standby: VecDeque<Slot>, ceiling, next_slot_id}. BCS-serialisable for chain-state commitments at Phase 7.7.
- `active_set::ActiveSetError` — typed errors {AlreadyRegistered, NotRegistered, UnknownSlot, BuyerNotRegistered}.
- `ActiveSet::register` — FCFS admission per §8.1.3: if `active.len() < ceiling` validator enters active; else standby queue (FIFO).
- `ActiveSet::remove_active` — frees a slot (liveness failure / equivocation / unbonding).
- `ActiveSet::advance_standby` — promotes front-of-queue standby validator at epoch boundary.
- `ActiveSet::record_participation` — updates active validator's `last_participation_epoch`.
- `ActiveSet::liveness_failed_at` — scan for §8.1.5 liveness-failure violators.
- `ActiveSet::apply_transfer` — §8.1.8 atomic slot transfer: buyer (from standby) takes seller's active slot; slot id + ordering preserved; seller removed; buyer's previous standby entry removed.
- `ActiveSet::tier` — §8.1.7 SecurityTier signal computed from `active_size`.
- `ActiveSet::is_dormant` — `active_size < ACTIVE_SET_FLOOR` per §8.1.6 / §8.7.1.

39 new tests in adamant-consensus covering: BCS round-trips + byte-size pins for Slot and SlotTransfer, SlotStatus variant tags, slot participation-clock monotonicity, liveness-failure boundary at "more than 2 missed" (2 OK, 3 FAILED), standby-slot exemption from liveness failure, ActiveSet floor / ceiling constant pins (7 and 75 matching `GENESIS_COHORT_SIZE`), empty/dormant set has tier=None, at-floor activation produces Tier I, FCFS registration overflow into standby, double-registration rejection, slot-id monotonicity + stability across remove+re-add, liveness-failed-at scanner, remove_active + advance_standby pairing, FIFO standby advancement, apply_transfer slot-id preservation per §8.1.8 step 3, unknown-slot rejection, unregistered-buyer rejection, seller-id-mismatch rejection, ActiveSet BCS round-trip, tier transitions across §8.1.7 boundaries (7→14 Tier I, 15→29 Tier II, 30+ Tier III).

Phase 7 progression: **7.0 + 7.1 closed**; 10 sub-arcs remaining (7.2 epoch/round semantics, 7.3 DAG vertex, 7.4 VRF, 7.5 VDF, 7.6 threshold mempool, 7.7 DAG-BFT core, 7.8 networking, 7.9 light client, 7.10 slashing wiring, 7.11 integration). Workspace LOC 57,748 → 58,427 (+679). Doc coverage stays at 100.0% across 9 Adamant-authored crates (1,001 → 1,035 pub items).

**Phase 7.2 closure (commit `a68d59b`)** — epoch/round scheduling + commit-wave indexing + quorum threshold per whitepaper §8.2 + §8.3.2 + §8.3.3. Pure arithmetic layer; no consensus state, no DAG, no vertex production (those consume the helpers here). Workspace tests 2,479 → 2,508 (+29); adamant-consensus LOC 1,466 → 1,867 (+401); pub items 82 → 109 (+27).

Phase 7.2 surface:

Timing constants per §8.2 verbatim:
- `ROUND_DURATION_TARGET_MS = 250` (sub-second finality target — 4-6 rounds = ~1-1.5s shared-state finality).
- `ROUNDS_PER_EPOCH = 144` (~36 seconds per epoch, calibrated per §8.2 trade-off between DKG cost, active-set responsiveness, and reward-distribution granularity).
- `EPOCH_DURATION_TARGET_MS = 36_000` (derived).
- `COMMIT_WAVE_PERIOD_ROUNDS = 4` per §8.3.3 default.
- `QUORUM_NUMERATOR = 2`, `QUORUM_DENOMINATOR = 3` for the "2/3+1" supermajority.

Quorum threshold per §8.3.1:
- `quorum_threshold(n) -> floor(2n/3) + 1`. Canonical-size pins: `n=7→5`, `n=15→11`, `n=30→21`, `n=75→51`, `n=100→67`. Alignment-with-§8.4 test confirms `n=15` yields quorum=11 (matching threshold-encryption viability boundary "t-of-N for some honest threshold t" calibrated for N≥15).

`EpochSchedule { genesis_round, rounds_per_epoch }`:
- `launch()` (144 rounds, genesis round 0); `new()` for hard-fork-style re-anchoring.
- `epoch_of(round)`, `first_round_of(epoch)`, `last_round_of(epoch)`, `is_epoch_boundary(round)`, `round_within_epoch(round)`.
- BCS-serialisable.

`WaveIndex(u64)` + `CommitWaveSchedule { genesis_round, period_rounds }`:
- `launch()` (4-round period); `new()` for parameterised tests.
- `wave_of(round)`, `first_round_of(wave)`, `anchor_round_of(wave)` (last round of wave — where the §8.6 VRF-elected anchor vertex lives per §8.3.3 step 1), `is_anchor_round(round)`, `round_within_wave(round)`.
- BCS-serialisable.

29 new tests covering: timing-constant pins, quorum-threshold canonical sizes, §8.4 threshold-encryption alignment, EpochSchedule launch defaults, epoch-boundary detection at rounds 0/144/288/14_400, first/last-round arithmetic, round-within-epoch cycling, custom-genesis re-anchoring, EpochSchedule BCS round-trip, zero-rounds-per-epoch panic, wave indexing at canonical rounds (0..3 wave 0, 4..7 wave 1), anchor-round invariant (`anchor_round - first_round + 1 == COMMIT_WAVE_PERIOD_ROUNDS` across waves 0..10), CommitWaveSchedule + WaveIndex BCS round-trips, epoch-and-wave alignment pin (wave 35 anchor = epoch 0's last round 143; wave 36 first = epoch 1's first round 144).

Phase 7 progression: **7.0 + 7.1 + 7.2 closed**; 9 sub-arcs remaining (7.3 DAG vertex, 7.4 VRF, 7.5 VDF, 7.6 threshold mempool, 7.7 DAG-BFT core, 7.8 networking, 7.9 light client, 7.10 slashing wiring, 7.11 integration). Workspace LOC 58,427 → 58,828 (+401). Doc coverage stays at 100.0% across 9 Adamant-authored crates (1,035 → 1,062 pub items).

**Phase 7.3 closure (commit `d87e383`)** — DAG vertex structure per whitepaper §8.3.1. Ships the consensus message format that DAG-BFT operates on. Workspace tests 2,508 → 2,533 (+25); adamant-consensus LOC 1,867 → 2,691 (+824); pub items 109 → 142 (+33).

Phase 7.3 surface:

- `vertex::VertexId` — 32-byte content-derived identifier per §8.3.1. Derived via `sha3_256_tagged(VERTEX_ID, BCS(UnsignedVertex))`. The id is over the *unsigned* body so it's stable before signing; signing happens over the id.
- `vertex::UnsignedVertex { author, round, parents, transactions, threshold_shares, proof_witness }` — the §8.3.1 body verbatim. Field order is consensus-binding.
- `vertex::Vertex { body, signature }` — complete signed vertex.
- `vertex::VertexSignature` — 48-byte BLS12-381 G1-compressed signature per §3.4.3.
- `vertex::TransactionEnvelope`, `vertex::DecryptionShare`, `vertex::PartialProofWitness` — opaque-bytes payload wrappers. Phase 7.3 doesn't introspect inner content; transactions stay BCS-encoded `Transaction` (or §8.4 ciphertext) bytes; decryption shares get their full BLS structure at Phase 7.6; proof witnesses get their `RecursiveAccumulator` partial-state structure at Phase 7.7. **This opacity keeps adamant-consensus free of adamant-vm / adamant-privacy dependencies** per the layered-architecture posture in CLAUDE.md §14.
- `UnsignedVertex::derive_id()` — content-derived VertexId via tagged-hash.
- `UnsignedVertex::has_quorum(active_set_size)` — §8.3.1 quorum predicate using `quorum_threshold` from Phase 7.2. Genesis-round (round=0) vertices exempt per §8.3.2.
- `UnsignedVertex::parents_are_distinct()` — set-semantics validation.
- `VertexBuilder` — ergonomic chainable construction (`add_parent` / `add_transaction` / `add_threshold_share` / `with_proof_witness` / `with_signature` / `build_unsigned` / `build`).

New domain tag in adamant-crypto: `domain::VERTEX_ID = "ADAMANT-v1-vertex-id"` for vertex content-addressing per §8.3.1.

25 new tests covering: byte-width pins (VertexId=32, BLS sig=48), VertexId BCS round-trip + hex Debug, `derive_id` determinism + per-field sensitivity (changing any byte of author/round/parents/transactions flips the id), `VERTEX_ID` domain-tag separation from `VALIDATOR_ID`, `has_quorum` at canonical active-set sizes (n=7→5, n=15→11, n=75→51), genesis-round (round=0) exemption from quorum requirement, `parents_are_distinct` empty / unique / duplicate cases, BCS round-trips for all vertex types + envelopes, VertexBuilder happy path + missing-signature panic, equivocation-relevant invariant (same `(author, round)` but different bodies produce distinct VertexIds — foundation for §8.1.5 equivocation detection), content-addressing invariant (identical bodies → identical ids).

Phase 7 progression: **7.0 + 7.1 + 7.2 + 7.3 closed**; 8 sub-arcs remaining (7.4 VRF, 7.5 VDF, 7.6 threshold mempool, 7.7 DAG-BFT core, 7.8 networking, 7.9 light client, 7.10 slashing wiring, 7.11 integration). Workspace LOC 58,828 → 59,652 (+824). Doc coverage stays at 100.0% across 9 Adamant-authored crates (1,062 → 1,095 pub items).

**Phase 7.4 closure (commit `77b33fc`)** — BLS-aggregate consensus VRF per whitepaper §8.6. Real cryptographic implementation through `adamant_crypto::bls` (not stubs): each validator BLS-signs the canonical input; a quorum's signatures aggregate; the aggregate is publicly verifiable via `fast_aggregate_verify`; randomness extracted via tagged-hash. Workspace tests 2,533 → 2,556 (+23); adamant-consensus LOC 2,691 → 3,550 (+859); pub items 142 → 169 (+27).

Phase 7.4 surface:

- `vrf::VrfInput` — typed enum {`EpochBoundary{epoch, previous_epoch_proof}`, `RoundAnchor{round, previous_round_vrf}`} per §8.6.1 inputs verbatim. BCS variant tags pinned (0x00 / 0x01) — reordering is a hard fork.
- `vrf::VrfInput::canonical_message() -> [u8; 32]` — `sha3_256_tagged(VRF_INPUT, BCS(self))`. Defence-in-depth domain separation: inner `VRF_INPUT` tag separates from other BLS-signed messages; BLS's own `BLS_SIG_HASH_TO_CURVE` DST separates the BLS layer.
- `vrf::VrfShare { validator_id, signature_bytes: [u8; 48] }` — one validator's BLS-G1 signature on the canonical input message. BCS encoding: 32 + 48 = 80 bytes.
- `vrf::VrfShare::compute(id, sk, input)` — sign with the validator's BLS secret key.
- `vrf::VrfShare::verify(input, pk) -> bool` — constant-time discipline matches Ed25519/BLS verify pattern (returns bool, no error detail).
- `vrf::VrfOutput { aggregate_signature_bytes, contributors }` — aggregate BLS signature + deterministically-sorted contributor list. Contributors sorted lexicographically by `ValidatorId` (which now derives `Ord + PartialOrd`).
- `vrf::aggregate_shares(shares) -> Result<VrfOutput>` — BLS-G1 aggregation. Rejects empty / duplicate / malformed.
- `vrf::verify_output(input, output, public_keys) -> Result` — `fast_aggregate_verify` against `output.contributors`-aligned public keys.
- `vrf::output_randomness(output) -> [u8; 32]` — `sha3_256_tagged(VRF_OUTPUT, aggregate_sig)`. Canonical uniform-random extraction for downstream consumers.
- `vrf::select_index(randomness, n) -> usize` — deterministic 0..n selection for anchor election. Acceptable bias `< 4e-16` at n ≤ 75.
- `vrf::VrfError` — typed errors {EmptyShareSet, DuplicateContributor, MalformedShareSignature, AggregationFailure, PublicKeyArityMismatch, MalformedPublicKey, InvalidAggregate}.
- `vrf::VRF_RANDOMNESS_BYTES = 32`.

New domain tags in adamant-crypto:
- `domain::VRF_INPUT = "ADAMANT-v1-vrf-input"` for VRF input-message commitment.
- `domain::VRF_OUTPUT = "ADAMANT-v1-vrf-output"` for VRF output-randomness extraction.

Identity refinement: `ValidatorId` now derives `Ord + PartialOrd` for the deterministic-contributor-sort path in `aggregate_shares`. Backwards-compatible (additive derive).

23 new tests covering: variant-tag pins, BCS round-trips, canonical-message determinism + domain-tag separation, distinct-variant message distinctness, real BLS share compute+verify round-trip, share verification rejects wrong input + wrong pubkey, aggregate rejects empty / duplicate / malformed, deterministic contributor ordering regardless of input order, aggregate verify succeeds for valid quorum + fails on wrong input + fails on arity mismatch, **VRF determinism pin** (same shares → same output → same randomness — §8.6 random-oracle property), randomness uses VRF_OUTPUT tag, distinct inputs produce distinct randomness, `select_index` range / determinism / non-zero panic.

Phase 7 progression: **7.0 + 7.1 + 7.2 + 7.3 + 7.4 closed**; 7 sub-arcs remaining (7.5 VDF, 7.6 threshold mempool, 7.7 DAG-BFT core, 7.8 networking, 7.9 light client, 7.10 slashing wiring, 7.11 integration). Workspace LOC 59,652 → 60,511 (+859). Doc coverage stays at 100.0% across 9 Adamant-authored crates (1,095 → 1,122 pub items).

**Phase 7.5.0 closure** — Wesolowski time-lock VDF foundation per whitepaper §3.8 + §8.4.4. Phase 7.5 is genuinely large (the Wesolowski VDF over class groups of imaginary quadratic order involves binary-quadratic-form arithmetic, NUDPL squaring, hash-to-class-group deterministic setup, Fiat-Shamir prime-challenge derivation, and a full evaluate/prove/verify operation set — thousands of LOC of Adamant-native cryptography per CLAUDE.md §14 and Principle VI). Sub-arc 7.5.0 ships the **consensus-stable wire foundation only** (same pattern as Phase 6.8a / 7.3): wire types, domain tags, BCS-pinned encoding, comprehensive type-level tests. Class-group arithmetic and the operations layered on top land at sub-arcs 7.5.1–7.5.6 in subsequent sessions.

Phase 7.5.0 surface (in `adamant-crypto::vdf`):

- `TimeLockParameters { discriminant: Vec<u8>, time_parameter_t: u64 }` — the genesis-fixed parameter bundle per §3.8.1 "Setup" + §3.8.2. `discriminant` is the class-group discriminant `D` in big-endian two's-complement (256 bytes for the §3.8.2 ≥2048-bit canonical width). `time_parameter_t` per §3.8.2 (`T ∈ [2_000_000, 7_500_000]`, calibrated empirically before genesis per CLAUDE.md Section 10 "Calibration work pending").
- `TimeLockParameters::parameter_commitment()` — re-derives the 32-byte chain-state commitment over the parameter set via `sha3_256_tagged(TIME_LOCK_PARAMETERS, BCS(self))`. Every node re-derives at startup and compares against the genesis-published commitment; drift surfaces as a parameter-commitment mismatch.
- `ClassGroupElement { encoded: Vec<u8> }` — opaque length-prefixed encoding of a single class-group element (canonical reduced binary quadratic form `(a, b)` per §3.8.1; internal layout pinned at Phase 7.5.1 when the arithmetic implementation lands). Derives `Hash` for mempool deduplication; equality is byte-equality (Phase 7.5.1's reduction invariant makes byte-equality and group-equality equivalent — the property §8.1.5 equivocation detection relies on).
- `WesolowskiProof { pi: ClassGroupElement }` — single class-group element `π = g^q` where `q = ⌊2^T / ℓ⌋` for the Fiat-Shamir prime challenge `ℓ`. Verification (Phase 7.5.5) checks `π^ℓ · g^r ≡ h`.
- `TimeLockEnvelope { puzzle, ciphertext, well_formedness_proof }` — user-submitted encryption per §3.8.1 step 2 + §8.4.4 ("Encryption"). `puzzle = g`, `ciphertext` is the ChaCha20-Poly1305 ciphertext under the §3.5 AEAD with key derived from `h`, `well_formedness_proof` rejects malformed envelopes per §3.8.1 ("required only to prevent malformed envelopes, not for security against time-locked decryption").
- `TimeLockDecryption { solution, evaluation_proof }` — anchor-published decryption per §3.8.1 step 3 + §8.4.4 Mitigation B ("Decryption-publication binding"). `solution = h`, `evaluation_proof` allows public verification per §3.8.3 ("publicly verifiable"). Per §8.4.4 the decryption is bound atomically to the anchor's vertex; equivocation is slashable at 100% per §8.1.5 `SlashOffence::Equivocation` (Phase 7.10 wiring).
- `VdfError` — typed errors {`MalformedEncoding`, `ParameterMismatch`, `ProofVerificationFailed`, `DecryptionFailed`}. Variants pin here; Phase 7.5.1+ adds operation sites that produce them. Implements `Display` + `std::error::Error`. Variants are non-`#[non_exhaustive]` per consensus-critical surface discipline.

New domain tags in `adamant-crypto::domain`:

- `TIME_LOCK_PARAMETERS = b"ADAMANT-v1-time-lock-parameters"` — for the genesis-state parameter commitment per §11.2.8.
- `WESOLOWSKI_CHALLENGE = b"ADAMANT-v1-wesolowski-challenge"` — for the Fiat-Shamir prime-challenge derivation `ℓ = HashToPrime(tagged_shake_256(WESOLOWSKI_CHALLENGE, BCS((g, h, T))))` per Wesolowski 2019 §3. Tag registers now; prime-search procedure pins at Phase 7.5.4.
- `TIME_LOCK_SYMMETRIC_KEY = b"ADAMANT-v1-time-lock-symmetric-key"` — for `key = shake_256_tagged(TIME_LOCK_SYMMETRIC_KEY, BCS(h), 32)` symmetric-key derivation from the VDF solution. Distinct from `THRESHOLD_KDF` (§3.6.1) so time-lock-derived and threshold-derived keys from numerically related inputs cannot collide.

17 unit tests covering: `TimeLockParameters` BCS round-trip + BCS layout pin (length-prefixed Vec<u8> + LE u64), `ClassGroupElement` BCS round-trip + byte-preserving `from_bytes` + byte-equality + `Hash` for set-membership, `WesolowskiProof` BCS round-trip, `TimeLockEnvelope` BCS round-trip + field-order pin (`puzzle | ciphertext | well_formedness_proof` in that order — reordering would be a consensus-breaking change and surfaces as a failing test), `TimeLockDecryption` BCS round-trip, `parameter_commitment` uses the `TIME_LOCK_PARAMETERS` tag + is deterministic + distinguishes distinct parameters (different T, different discriminant bytes) + is domain-separated from plain SHA3, `VdfError` produces distinct meaningful display messages across all four variants + implements `std::error::Error`, fixture-T falls in the §3.8.2 calibration range.

`adamant-crypto` gains a production dep on `bcs` + `serde` (workspace pins) for the BCS round-trip path; both are already in the bounded ecosystem per CLAUDE.md §14.1 Category B / E (canonical serialisation per §5.1.8). No new cryptography crate added.

Per Adamant's "never ship stub crypto functions" discipline (CLAUDE.md Section 4: "no `unwrap()` outside tests... no silent failures"), `vdf` exposes **no `evaluate` / `prove` / `verify` functions** at 7.5.0. Phase 7.5.1+ adds them as honest, tested implementations against these consensus-stable wire types. Adamant-native posture (CLAUDE.md §14 Decision pending for Phase 7.5.1 plan-gate): class-group arithmetic in Rust requires only big-integer arithmetic and the protocol's existing SHA3 / SHAKE primitives; the implementation will be Adamant-native, not pulled from an external `class_group` / `rsa-vdf` crate (same shape as KZG per §3.9.2 amendment instance 30). Whether the BigInt layer is `num-bigint` (Cat E workspace-utility) or Adamant-native is a spec-author plan-gate question at sub-arc 7.5.1 start.

Phase 7 progression: **7.0 + 7.1 + 7.2 + 7.3 + 7.4 closed; 7.5.0 closed**. 7 sub-arcs remaining (7.5.1+ VDF math, 7.6 threshold mempool, 7.7 DAG-BFT core, 7.8 networking, 7.9 light client, 7.10 slashing wiring, 7.11 integration).

Phase 7.5.0 metrics: adamant-crypto LOC 3,183 → 3,463 (+280; +3 new domain tags + new vdf module + module wiring); adamant-crypto pub items 166 → 182 (+16 — 4 new types + 1 helper method + 4 VdfError variants exposed + 3 new domain tags via re-export visibility + lib.rs module). Workspace tests 2,556 → 2,573 (+17 vdf tests). Doc coverage stays at 100.0% across 9 Adamant-authored crates. Resistant-proof guards (`no_sui_in_production_deps`, `no_upstream_halo2_in_production_deps`): both pass.

**Pre-mainnet workstream items registered at Phase 7.5.0:** (a) §3.8.2 time-parameter `T` calibration — the exact `T ∈ [2_000_000, 7_500_000]` value is calibrated empirically against consensus-grade hardware before genesis; (b) §11.2.8 hash-to-class-group construction — the deterministic derivation from genesis state is pinned at sub-arc 7.5.2 (spec-author plan-gate; may require a §11.2.8 amendment to enumerate the exact derivation algorithm parallel to the §6.2.1.7 structural-limits pattern); (c) class-group arithmetic BigInt-layer choice — spec-author plan-gate at sub-arc 7.5.1 start (Adamant-native vs `num-bigint` Cat E workspace-utility).

**Phase 7.5.1a closure (commit `49d523e`)** — binary quadratic form arithmetic foundation per whitepaper §3.8.1. Phase 7.5.1 (class-group arithmetic for the Wesolowski VDF) is split into 4 sub-sub-arcs: **7.5.1a** ships the form type + reduction (Cohen 5.4.2) + form-level predicates and identity / inverse (this closure); **7.5.1b** adds composition (NUDPL — Shanks composition over imaginary quadratic order); **7.5.1c** adds fast squaring (NUDPL special case); **7.5.1d** wires the `ClassGroupElement ↔ BinaryQuadraticForm` byte encoding (canonical `(a, b)`-only encoding with `c` recoverable from `c = (b² − D) / (4a)` given the chain-fixed discriminant).

Phase 7.5.1a surface (in `adamant-crypto::vdf::bqf`):

- `BinaryQuadraticForm { a: BigInt, b: BigInt, c: BigInt }` — `ax² + bxy + cy²` over arbitrary-precision integers. `Clone + Debug + PartialEq + Eq + Hash + Serialize + Deserialize` via `num-bigint`'s `serde` feature.
- `BqfError { ZeroLeadingCoefficient, NonNegativeDiscriminant, InvalidDiscriminantResidue }` — typed construction-error surface; `Display` + `std::error::Error`. Variants pin here; subsequent sub-sub-arcs add operation-error variants as needed.
- `BinaryQuadraticForm::new(a, b, c) -> Result<Self, BqfError>` — validating constructor (rejects `a = 0`; reduction / positive-definiteness validated separately).
- `BinaryQuadraticForm::discriminant() -> BigInt` — `D = b² − 4ac`; preserved by every form operation.
- `BinaryQuadraticForm::identity(D) -> Result<Self, BqfError>` — principal form: `(1, 0, −D/4)` if `D ≡ 0 (mod 4)`, `(1, 1, (1−D)/4)` if `D ≡ 1 (mod 4)`; rejects `D ≥ 0` and `D ≡ 2, 3 (mod 4)`.
- `BinaryQuadraticForm::inverse() -> Self` — `(a, b, c) ↦ (a, −b, c)`; class-group inverse.
- `BinaryQuadraticForm::is_positive_definite() -> bool` — `a > 0 ∧ c > 0 ∧ D < 0`.
- `BinaryQuadraticForm::is_normal() -> bool` — `−a < b ≤ a`.
- `BinaryQuadraticForm::is_reduced() -> bool` — Cohen 5.4.2 canonical form: `|b| ≤ a ≤ c` with tie-breakers `b ≥ 0` at `|b| = a` and at `a = c`.
- `BinaryQuadraticForm::normalize()` — single-step bring `b` into `(−a, a]` preserving discriminant via `s = ⌊(a − b) / (2a)⌋` and `c' = c + s(b + sa)`.
- `BinaryQuadraticForm::reduce()` / `reduced()` — full Cohen 5.4.2: alternate `normalize` with swap-step `(a, b, c) ↦ (c, −b, a)` until `a ≤ c`, then edge-case fix-up at the `a = c, b < 0` boundary.

New workspace dependencies (Cat E workspace-utility per CLAUDE.md §14.1, parallel posture to `petgraph` and `ethnum`): `num-bigint = "=0.4.6"` (with `serde` feature), `num-integer = "=0.1.46"`, `num-traits = "=0.2.19"`. Exact-pinned to versions already resolved in `Cargo.lock` transitively from vendored Sui at the time of pinning, so no transitive-dep churn. The class-group math itself is Adamant-authored — `num-bigint` provides only the BigInt primitive.

37 unit tests covering: BQF construction (accept non-zero `a`, reject `a = 0`), discriminant formula matches `b² − 4ac`, identity for both residue classes mod 4 + rejection of `D ≥ 0` and `D ≡ 2, 3 (mod 4)`, positive-definiteness predicate rejecting non-positive `a` and non-negative discriminant, normalization boundary cases (`b = a` inclusive, `b = −a` exclusive, `b > a` not normal), all reduced-form predicate cases including both tie-breaker violations (`|b| = a` with `b < 0`, `a = c` with `b < 0`), normalize idempotence on already-normal forms, reduction worked example `(3, 5, 4) ↦ (2, 1, 3)` for D = −23 preserving discriminant, identity reduces to itself, `a = c, b < 0` boundary edge case, inverse properties (negates `b`, preserves discriminant, involutive, identity inverse when `b = 0`), stress test on moderate-sized coefficients, BCS serde round-trip, error-variant display + `std::error::Error`, equivalent forms reduce to the same canonical representative (the property the class-group quotient relies on; verified concretely for `(3, 5, 4)` and `(2, 1, 3)` at D = −23).

Phase 7.5.1a metrics: workspace tests `cargo test -p adamant-crypto vdf` reports 54 passing (17 Phase 7.5.0 + 37 Phase 7.5.1a). adamant-crypto LOC 3,463 → ~4,300 (+~840 — bqf module + tests). Resistant-proof guards continue to pass; workspace audit strict mode passes at 100% doc coverage across 9 Adamant-authored crates.

**Phase 7.5.1b closure (commit `efff888`)** — class-group composition `f₁ ∘ f₂` via Gauss composition per Cohen "A Course in Computational Algebraic Number Theory" (Springer 1993) Algorithm 5.4.7. Implements the class-group multiplication operation on top of the Phase 7.5.1a foundation, completing the algebraic operations the Wesolowski VDF will compose with — at 7.5.1c the fast-squaring specialisation lands as a performance optimisation, but correctness already lives here at 7.5.1b.

Phase 7.5.1b surface:

- `BinaryQuadraticForm::compose(&self, other) -> Result<Self, BqfError>` — Gauss composition with reduction. Returns the reduced product in the shared-discriminant class group. Performs the swap-to-canonical-orientation, two extended GCD steps (the `d₁ | s` branch is the common-case fast path, the `d ≠ d₁` branch covers the general case), linkage modular reduction, and final reduction.
- `BqfError::MismatchedDiscriminants` — error variant for composition across different class groups.

16 unit tests for composition: same-discriminant precondition rejection; left + right identity (`e ∘ f = f ∘ e = f`); identity self-compose (`e ∘ e = e`); generator squared (`f ∘ f = f²`); inverse property (`f ∘ f⁻¹ = e` and `f⁻¹ ∘ f = e`); generator-squared self-compose (`f² ∘ f² = f`, since class number = 3); generator cubed equals identity (`f ∘ f ∘ f = e`); discriminant preservation; result-is-reduced invariant; **full 3×3 commutativity matrix** across the D = −23 class group; **full 3×3×3 associativity matrix** (27 triples) across the D = −23 class group; swap-when-a₁<a₂ path; D = −20 class group cross-check (different class group, class number 2: `g ∘ g = e`); equivalence-class invariance (unreduced and reduced inputs produce the same reduced output).

The 3×3 commutativity + 3×3×3 associativity matrices cover the full abelian-group axiom set on the D = −23 example. The published Cohen 5.4.7 variable names (`s, n, d, u, v, x, y, l`) are preserved in code with a documented `#[allow(clippy::many_single_char_names)]` so the comment-vs-code traceability holds during security review.

Phase 7.5.1b metrics: `cargo test -p adamant-crypto vdf` reports 70 passing (17 Phase 7.5.0 + 37 Phase 7.5.1a + 16 Phase 7.5.1b). adamant-crypto LOC ~4,300 → ~4,700 (+~370 — compose method + tests). Workspace clippy + fmt + strict audit + both resistant-proof guards all pass; doc coverage stays at 100% across 9 Adamant-authored crates.

**Phase 7.5.1c closure (commit `0f2575c`)** — fast squaring via Cohen Algorithm 5.4.8 (Squaring of Forms). The Wesolowski VDF evaluation per §3.8.2 performs `T ∈ [2_000_000, 7_500_000]` sequential squarings per envelope, so a specialised `square()` that halves the extended-GCD work vs general `compose(&self, &self)` is a constant-factor win that accumulates to material decryption-time savings for the round anchor.

Phase 7.5.1c surface:

- `BinaryQuadraticForm::square(&self) -> Self` — Cohen 5.4.8 specialisation. Single extended GCD on `(b, a)` (vs two extended GCDs in general composition); modular reduction `nu = (−μ·c) mod (a/d)` for the linkage; final form `(A_new, B_new, C_new)` with `A_new = (a/d)²`, `B_new = b + 2·(a/d)·nu`, `C_new = (B_new² − D) / (4·A_new)`. Reduces the result before returning. Positive-definite precondition; panics on indefinite inputs (same posture as `reduce` and `compose`).

9 unit tests including the headline correctness identity `square(f) == compose(f, f)` pinned across both the D = −23 class group (3 classes), the D = −20 class group (2 classes), an unreduced representative, and two medium-coefficient fixtures; identity cases (`e² = e`, `f² = (2,−1,3)` for D = −23, `f⁴ = f` for class number 3, `g² = e` for D = −20 order 2); discriminant preservation; result-is-reduced; equivalence-class invariance; and the **repeated-squaring chain** test `(f.square()).square() == (f∘f) ∘ (f∘f) = f⁴` — the property the Wesolowski VDF evaluation relies on when computing `g^(2^T)` via the `T`-sequential-squarings chain.

Phase 7.5.1c metrics: `cargo test -p adamant-crypto vdf` reports 79 passing (17 Phase 7.5.0 + 37 Phase 7.5.1a + 16 Phase 7.5.1b + 9 Phase 7.5.1c). adamant-crypto LOC ~4,700 → ~5,000 (+~260 — square method + tests). Workspace clippy + fmt + strict audit + both resistant-proof guards all pass; doc coverage stays at 100% across 9 Adamant-authored crates.

The class-group arithmetic operations needed by the Wesolowski VDF evaluation are now complete: `square` (used `T` times per evaluation), `compose` (used by the Wesolowski proof construction at sub-arc 7.5.4 for the `π = g^q` exponentiation), `inverse` (used by the envelope-verification path), and the reduction / predicate / identity infrastructure. Only the encoding bridge between the type-system-level `BinaryQuadraticForm` and the consensus-stable `ClassGroupElement` wire type remains in sub-arc 7.5.1 (lands at 7.5.1d).

**Phase 7.5.1d closure (commit `51946d5`)** — `ClassGroupElement ↔ BinaryQuadraticForm` byte-encoding bridge. Pins the canonical wire encoding for class-group elements as BCS of the `(a, b)` tuple only — `c` is intentionally omitted from the wire because the discriminant is a genesis-fixed parameter shared across every class-group element per §3.8.2, so storing `c` per element would duplicate information the verifier can recover trivially via `c = (b² − D) / (4a)`. **This closes Phase 7.5.1**: the class-group arithmetic foundation for the Wesolowski VDF is now complete (form type + reduction + identity + inverse + composition + fast squaring + wire-stable encoding).

Phase 7.5.1d surface:

- `BinaryQuadraticForm::to_class_group_element(&self) -> ClassGroupElement` — BCS-encodes `(a, b)` as a `(BigInt, BigInt)` tuple, wraps in the Phase 7.5.0 wire type. Deterministic.
- `BinaryQuadraticForm::from_class_group_element(element, discriminant) -> Result<Self, BqfError>` — BCS-decodes `(a, b)`, recovers `c = (b² − D) / (4a)` against the supplied discriminant, validates exact divisibility + non-zero `a`, constructs the form.
- `BqfError::MalformedClassGroupEncoding` — new variant covering three failure modes through a single typed error: BCS-decode failure, zero `a`, and non-integer `c` under the supplied discriminant.

15 unit tests covering: round-trip through encode/decode for the full D = −23 class group (3 classes) and D = −20 class group (2 classes); BCS bytes contain only `(a, b)` (decoder verifies `c` is recovered, not stored); deterministic encoding (byte-equality property §8.1.5 equivocation detection relies on); distinct forms encode distinctly; rejection of malformed BCS, empty bytes, zero `a`, and non-integer `c` (concrete fixture: `(a=2, b=2)` decoded under D = −23 yields `c = 27/8` — must reject); supplied-discriminant validation; wrong-discriminant rejection (D' = −19 with form encoded for D = −23 produces non-integer `c`); reduced-form-byte-equality within class; unreduced inputs round-trip to themselves then reduce to canonical; `MalformedClassGroupEncoding` display message distinctness.

Phase 7.5.1d metrics: `cargo test -p adamant-crypto vdf` reports 94 passing (17 Phase 7.5.0 + 37 Phase 7.5.1a + 16 Phase 7.5.1b + 9 Phase 7.5.1c + 15 Phase 7.5.1d). adamant-crypto LOC ~5,000 → ~5,400 (+~340 — encoding methods + tests). Workspace clippy + fmt + strict audit + both resistant-proof guards all pass; doc coverage stays at 100% across 9 Adamant-authored crates.

**Phase 7.5.1 cumulative closure**: 4 sub-sub-arcs (7.5.1a/b/c/d) landed across 4 commits (`49d523e` → `efff888` → `0f2575c` → `51946d5`); class-group arithmetic foundation complete. BqfError grew from 0 → 5 typed variants (`ZeroLeadingCoefficient`, `NonNegativeDiscriminant`, `InvalidDiscriminantResidue`, `MismatchedDiscriminants`, `MalformedClassGroupEncoding`). vdf module test count 17 (Phase 7.5.0 close) → 94 (Phase 7.5.1 close; +77 across the 4 sub-sub-arcs). adamant-crypto LOC ~3,463 → ~5,400 (+~1,940 across Phase 7.5.1).

Next sub-arc — **Phase 7.5.2** (hash-to-class-group construction per §11.2.8): deterministic derivation of the class-group discriminant from genesis state, plus the hash-to-element procedure that produces a random class-group element from a byte string for the §11.2.8 + §3.8.1 setup. Has a spec-author plan-gate open: §11.2.8 doesn't enumerate the exact hash-to-class-group algorithm, so this sub-arc may require a §11.2.8 amendment proposal parallel to the §6.2.1.7 structural-limits pattern. Surface for plan-gate at sub-arc 7.5.2 start.

**Phase 7.5.2a closure (commit `8f1a625`)** — deterministic class-group discriminant derivation per a new §3.8.6 whitepaper subsection. The spec amendment lands in this commit as a new §3.8.6 subsection of §3.8 (cryptographic foundation), specifying the byte-level algorithm. §11 (genesis-constitution) is untouched per the CLAUDE.md hard "never modify" rule — the algorithm itself lives in §3.8 where the VDF math is specified, and §11.2.8 already refers to "deterministic derivation from genesis state" without enumerating the algorithm.

Whitepaper amendment shipped in lockstep with the implementation per the spec-first ratification pattern (twenty-second spec-first verification instance shape, though not formally numbered in CONTRIBUTING.md). The §3.8.6 subsection specifies:

1. `raw ← tagged_shake_256(CLASS_GROUP_DISCRIMINANT, BCS(s, k), k/8 bytes)`
2. `d ← big-endian integer of raw`
3. `d |= 1 << (k − 1)` — fix the high bit for exact width
4. `d = (d & ¬3) | 3` — ensure `d ≡ 3 (mod 4)`, so `D = −d ≡ 1 (mod 4)`
5. `D = −d`

Plus: pre-mainnet fundamental-discriminant calibration item registered (genesis seed empirically verified pre-publication; if non-fundamental, the seed is rotated). Plus: forward-declaration of the §3.8.6 hash-to-element procedure landing at Phase 7.5.2b alongside Tonelli-Shanks modular square root infrastructure.

Phase 7.5.2a surface:

- `CLASS_GROUP_DISCRIMINANT = b"ADAMANT-v1-class-group-discriminant"` — new BIP-340 tagged-hash domain tag. Per §3.3.1, adding domain tags is a hard fork; this tag pins at Phase 7.5.2a.
- `adamant-crypto::vdf::setup` — new module hosting the deterministic-setup primitives.
- `vdf::setup::derive_discriminant(seed: &[u8; 32], bit_len: u32) -> Result<BigInt, SetupError>` — deterministic transcription of the §3.8.6 algorithm. Returns the negative-`bit_len`-bit discriminant with `D ≡ 1 (mod 4)`.
- `vdf::setup::MIN_DISCRIMINANT_BITS = 2048` — pinned to the §3.8.2 minimum.
- `vdf::setup::SetupError { BitLengthBelowMinimum, BitLengthNotByteAligned }` — typed caller-side errors.

**Spec-first verification: math bug caught and fixed during implementation**. The §3.8.6 algorithm as I first wrote it specified `d ≡ 1 (mod 4)` in step 5, which gives `D = −d ≡ 3 (mod 4)` — invalid for integral binary quadratic forms (which require `D ≡ 0 or 1 (mod 4)`). The integration test `derived_discriminant_admits_identity_form` (wiring Phase 7.5.2a's `derive_discriminant` to Phase 7.5.1a's `BinaryQuadraticForm::identity`) failed, surfacing the bug. Corrected to `d ≡ 3 (mod 4)` so `D ≡ 1 (mod 4)` in lockstep across the spec text and the implementation. The discipline functioned exactly as intended — the spec is canonical, but implementation forces the math to be empirically correct.

19 unit tests covering: bit-length rejection paths (< 2048, not multiple of 8); determinism; SHAKE-256 avalanche under seed perturbation; bit-width exactness (high bit forced, magnitude exactly `bit_len` bits); residue `D ≡ 1 (mod 4)`; negative sign; algorithm byte-recipe pinning via re-derivation; domain-separation from plain SHAKE-256 (§3.3.1 property); known-answer regression vector for all-zeros seed at 2048 bits; scales to 3072 bits; error-variant Display + std::error::Error; algorithmic-cost guard (catches accidental primality-test inflation); `MIN_DISCRIMINANT_BITS` pin; and two **headline integration tests** wiring Phase 7.5.2a to Phase 7.5.1 — `derived_discriminant_admits_identity_form` (the §3.8.6 output is a valid `BinaryQuadraticForm::identity` input) and `derived_discriminant_supports_compose_and_square` (`e ∘ e = e` and `e² = e` on the derived class group's identity).

Phase 7.5.2a metrics: `cargo test -p adamant-crypto vdf` reports 113 passing (94 Phase 7.5.1 close + 19 Phase 7.5.2a). adamant-crypto LOC ~5,400 → ~5,900 (+~500). Workspace clippy + fmt + strict audit + both resistant-proof guards all pass; doc coverage stays at 100% across 9 Adamant-authored crates.

**Pre-mainnet workstream items still registered for Phase 7.5**: (a) §3.8.2 `T`-parameter calibration (unchanged); (b) §3.8.6 fundamental-discriminant calibration on the genesis seed (registered at Phase 7.5.2a — empirical check before publication; rotate seed if non-fundamental). (c) BigInt-layer choice has been resolved as `num-bigint` per Phase 7.5.1 closure.

Next sub-arc — **Phase 7.5.2b** (hash-to-element): deterministic mapping from a byte string to a class-group element. Algorithm: iterate candidate leading coefficients `a` (small primes), solve `b² ≡ D (mod 4a)` via Tonelli-Shanks modular square root, compute `c = (b² − D) / (4a)`, return the reduced form. Requires implementing Tonelli-Shanks (square root in `ℤ/p`) as a building block — a well-known classical algorithm but ~150 LOC of careful modular arithmetic. Estimated scope: ~400 LOC + ~15 tests including known-answer vectors.

**Tri-repo whitepaper reconciliation (commits `f2726c9` here + `b3b47e0` on adamant-spec + `9e85c5c` on adamant-website)** — resolves silent spec drift between this repo, `adamant-spec`, and `adamant-website`. The three repos had diverged: amendments landed in `adamant/whitepaper/` (§3.8.6, §6.2.1.9, §7.0, §7.2.2 Pallas migration, §7.3 value-commitments) over multiple sessions never propagated to `adamant-spec`; the ML-DSA-87 amendment landed in `adamant-spec` never propagated to `adamant`; and `adamant-website` lost its spec page when whitepaper was moved out (build-time glob `../../whitepaper/*.md` resolved to a non-existent directory).

Resolution:

1. **ML-DSA-87 amendment propagated INTO `adamant/whitepaper/`** at commit `f2726c9`. §3.4.2 updated to support both ML-DSA-65 (default, level 3) and ML-DSA-87 (opt-in, level 5) as first-class variants with explicit key/signature widths and default-selection rationale; §6.0 Signature enum carries variant tag 0x02 for ML-DSA-87; §6.2.1.4 instruction set ships `MlDsaVerify87`; §6.2.1.5 operand encoding counts 19/13. No code-side impact in this commit — adamant-crypto already imports `ml_dsa` which supports both parameter sets. Wiring ML-DSA-87 into ValidatorPublicKeys / account-creation / AVM stdlib is a follow-up Phase 5/6.x or 7+ sub-arc.

2. **`adamant-spec` repo synced** at its commit `b3b47e0` — copied all 14 chapter files + complete.md from `adamant/whitepaper/` to `adamant-spec/whitepaper/`. Net diff: +492 lines, −62 lines across §03 / §06 / §07 / complete.md.

3. **`adamant-website` repo wired** at its commit `9e85c5c` — added `scripts/sync-spec.mjs` that pulls whitepaper content from `adamant-spec` at build time (sibling-clone fast path with GitHub-raw fallback for CI), `package.json` `predev` / `prestart` / `prebuild` hooks invoke the sync before astro runs, and `whitepaper/` added to `.gitignore` since it's derived content. The spec page (`src/pages/spec.astro`) now resolves its `../../whitepaper/*.md` glob to synced content.

**Canonical-source policy going forward**: `adamant-spec` is the canonical published spec source. Amendments should land there first (typically via main-chat Claude per CLAUDE.md §4); `adamant/whitepaper/` is synced from `adamant-spec` as a development-time copy for the implementation repo's offline reference. The website pulls from `adamant-spec` at build time. The two scratch clones (`spec-temp/`, `website-temp/`) are local-only redundant copies and can be deleted when convenient.

**Phase 7.5.2b closure (commit `2419b2a` here + `5f657f1` on adamant-spec)** — hash-to-class-group-element procedure per the §3.8.6 amendment. Completes the deterministic class-group setup pipeline: together Phase 7.5.2a (discriminant derivation) + 7.5.2b (hash-to-element) cover the entire "Setup" step of §3.8.1, so the chain can now produce both the genesis discriminant `D` and the canonical class-group generator `g₀` from nothing but the genesis seed.

Phase 7.5.2b surface:

- **§3.8.6 spec amendment**: replaces the "pending sub-arc" forward-declaration with the full 13-step algorithm — SHAKE-256 candidate derivation with forced bit-width + odd parity, Miller-Rabin prime search, Jacobi QR test, Tonelli-Shanks square root, b-parity adjustment, c computation via `c = (b² − D) / (4a)`, and reduction. Spec text now production-pinned.
- **`CLASS_GROUP_ELEMENT_SEED` domain tag** (new): `b"ADAMANT-v1-class-group-element-seed"`. Distinct from `CLASS_GROUP_DISCRIMINANT` so hash-to-element output cannot collide with discriminant derivation under any related seed.
- **`adamant-crypto::vdf::modular` module** (new): three classical number-theoretic primitives the §3.8.6 algorithm consumes — `jacobi_symbol` (Cohen 1.4.10), `is_probable_prime` (Miller-Rabin), `tonelli_shanks_sqrt_mod_prime` (Tonelli-Shanks), plus the `next_prime` helper. All implemented Adamant-native on top of `num-bigint`; classical algorithms (Miller 1976 / Rabin 1980; Tonelli 1891 / Shanks 1972; Jacobi 1846) rather than pulled-in from external number-theory crates.
- **`adamant-crypto::vdf::setup::hash_to_element(seed, D, bit_len_a)`**: deterministic transcription of the §3.8.6 algorithm. Miller-Rabin witnesses derived from `(seed, D, bit_len_a, counter, witness_index)` via tagged-SHAKE-256, so the test is reproducible bit-for-bit across implementations. 40 rounds → `2^-80` soundness error.
- **4 new `SetupError` variants**: `InvalidDiscriminantForHashToElement`, `LeadingCoefficientBitLengthBelowMinimum`, `HashToElementBudgetExhausted` (vanishingly rare; `2^-256` probability), plus `BitLengthNotByteAligned` reused.
- **3 new constants**: `MIN_HASH_TO_ELEMENT_BITS = 32` (impl-level minimum for testability; canonical genesis uses 1024), `HASH_TO_ELEMENT_BUDGET = 256` outer-loop iterations, `MILLER_RABIN_ROUNDS = 40`.

37 new unit tests (23 modular + 14 hash_to_element) covering: jacobi panic on even/zero modulus, known small Legendre values, multiplicativity, gcd-shared-factor → 0; Miller-Rabin acceptance/rejection of small primes/composites, Carmichael-number detection (561, 1105, 1729, ...), Mersenne primes M31 + M61, `2^32-1` composite, determinism; `next_prime` correctness + panic-on-start-below-2; Tonelli-Shanks easy + general cases verified for every residue mod {7, 11, 23} (easy) and {13, 17, 41} (general), specific KATs, non-residue → None, zero → zero, `p = 2` edge case; hash_to_element discriminant + bit-length rejection paths, success on small inputs, determinism, distinct-seeds/D/bit_len → distinct elements, empty seed, 1KB seed, output composes with itself (cross-checks 7.5.1b/c), **end-to-end integration** wiring `derive_discriminant → hash_to_element` (7.5.2a + 7.5.2b + 7.5.1a-d together), known-answer determinism pin for D = −23.

Phase 7.5.2b metrics: vdf module tests 113 → 150 passing (+37). adamant-crypto LOC ~5,900 → ~7,200 (+~1,300 — modular module + setup additions + tests). Workspace clippy + fmt + strict audit + both resistant-proof guards all pass.

**Phase 7.5 progression**: 7.5.0 + 7.5.1 (a/b/c/d) + 7.5.2a + 7.5.2b closed. The deterministic class-group setup pipeline is complete end-to-end. Next: **Phase 7.5.3** — VDF evaluation (the `T`-sequential-squarings inner loop using `BinaryQuadraticForm::square`) and Wesolowski proof construction (`π = g^q` for `q = ⌊2^T / ℓ⌋`). All class-group infrastructure is in place; 7.5.3 wires the existing pieces into `evaluate(g, T)` and `prove(g, h, T)`.

**Phase 7.5.3 closure (commit `d4c7b5d` here + `d3ca3dc` on adamant-spec)** — Wesolowski VDF evaluate / prove / verify per new §3.8.7 whitepaper subsection. **Closes the §3.8 time-lock VDF construction end-to-end.** The chain can now produce its parameters from the genesis seed (Phase 7.5.2a), sample a canonical class-group generator (Phase 7.5.2b), evaluate the `T`-sequential-squarings inner loop (Phase 7.5.3 evaluate), produce a Wesolowski proof (Phase 7.5.3 prove), and verify it in constant time (Phase 7.5.3 verify).

Whitepaper amendment — §3.8.7 (new): pins the byte-level algorithms for `evaluate`, `hash_to_prime` (Fiat-Shamir prime challenge derivation), `prove`, and `verify`. `CHALLENGE_BITS = 128` genesis-fixed (Wesolowski 2019 §4 soundness: cheating probability `≤ 1/ℓ ≤ 2^-128`, comfortably above the §3.8.2 128-bit classical security target). The §3.8.3 "publicly verifiable in constant time" property realised concretely: `verify` runs in `O(log ℓ) ≈ 128` class-group operations regardless of `T`.

Phase 7.5.3 surface (in `adamant-crypto::vdf::wesolowski`):

- `evaluate(g: &BinaryQuadraticForm, T: u64) -> BinaryQuadraticForm` — `T` sequential class-group squarings producing `h = g^(2^T)`. Sequential by construction; no parallel speedup is known. Genesis target `T ∈ [2_000_000, 7_500_000]` per §3.8.2.
- `prove(g, T) -> Result<ProveResult, WesolowskiError>` — returns `{h, π}` where `π = g^q` and `q = ⌊2^T / ℓ⌋` for the Fiat-Shamir prime `ℓ = hash_to_prime(g, h, T)`. Implementation: `evaluate` then square-and-multiply on `q`. Total cost `~2T` class-group operations.
- `verify(g, h, T, π) -> Result<bool, WesolowskiError>` — recomputes `ℓ`, computes `r = 2^T mod ℓ` (fast via `BigUint::modpow`), checks `π^ℓ · g^r ≡ h` in the class group.
- `ProveResult { h, pi }` — return shape of `prove`.
- `WesolowskiError { MismatchedDiscriminants, NotPositiveDefinite, HashToPrimeBudgetExhausted }`.
- `CHALLENGE_BITS = 128` (pub const, consensus-binding).

Internal helpers (private):
- `hash_to_prime(g, h, T)` — Fiat-Shamir prime challenge derivation via `WESOLOWSKI_CHALLENGE` domain tag (registered in Phase 7.5.0). Re-uses `vdf::modular::is_probable_prime` from Phase 7.5.2b with 40 deterministically-derived Miller-Rabin witnesses.
- `pow(base, exponent)` — left-to-right square-and-multiply over `BigUint` exponents using `BinaryQuadraticForm::{square, compose}`.

33 new unit tests covering: evaluate edge cases (T=0 returns input; T=1 is square; determinism; discriminant preservation; result-is-reduced; panic on non-positive-definite); `hash_to_prime` determinism + distinct-T-distinct-ℓ + returns-actual-128-bit-prime; `pow` exponent-0/1/2/4/8 + matches-evaluate at `2^T`; **prove + verify round-trip** at T=1, 10, 50; prove rejects non-positive-definite; verify rejects tampered `h`, tampered `π`, wrong `T`, swapped `g`/`h`; mismatched-discriminant + non-positive-definite error paths; determinism; cross-seed soundness at T=200 (both verify correctly under their own generators; cross-seed proofs do NOT verify — exercises the real `q != 0` case where `π` is non-trivially `g^q`); **end-to-end integration** (`derive_discriminant → hash_to_element → prove → verify` against a 2048-bit derived discriminant, wiring all of Phase 7.5.2a + 7.5.2b + 7.5.3 together).

Phase 7.5.3 metrics: vdf module tests 150 → 183 passing (+33). adamant-crypto LOC ~7,200 → ~8,100 (+~900 — wesolowski module + tests). Workspace clippy + fmt + strict audit + both resistant-proof guards all pass.

**Phase 7.5 progression (cumulative)**: 7.5.0 + 7.5.1 (a/b/c/d) + 7.5.2a + 7.5.2b + 7.5.3 closed. **The §3.8 time-lock VDF construction is feature-complete** (parameters + setup + arithmetic + operations + proof verification). Next sub-arc: **Phase 7.5.4** — wiring `TimeLockEnvelope` to ChaCha20-Poly1305 via the `TIME_LOCK_SYMMETRIC_KEY` domain tag, plus consensus-layer round-anchor integration per §8.4.4 (the round-anchor decryption-publication binding). After that, Phase 7.6 (threshold mempool + two-regime hysteresis at the §8.4.2 viability boundary).

**Phase 7.5.4 closure (commit `664a275` here + `a8b3931` on adamant-spec)** — time-lock envelope encryption per new §3.8.8 whitepaper subsection. **Closes Phase 7.5 end-to-end: the §3.8 time-lock VDF workstream is feature-complete.** Together with the prior sub-arcs, the user-anchor-observer flow is fully operational: a user encrypts a plaintext under the chain-fixed parameters → the round anchor decrypts after `T` sequential squarings and publishes `(plaintext, decryption)` atomically with its consensus vertex per §8.4.4 Mitigation B → any observer verifies the anchor's evaluation proof in `O(log ℓ) ≈ 128` class-group operations and recovers the plaintext via the symmetric-key path.

Whitepaper amendment — §3.8.8 (new): pins the byte-level algorithm for the three envelope flows. Key derivation `key = shake_256_tagged(TIME_LOCK_SYMMETRIC_KEY, BCS(ClassGroupElement(h)), 32)`; encryption sequence `hash_to_element → prove → derive_symmetric_key → ChaCha20-Poly1305-Encrypt` with random 12-byte nonce prefixed inside the `ciphertext` field and empty AAD; decryption sequence `from_class_group_element → prove → derive_symmetric_key → ChaCha20-Poly1305-Decrypt`; public verification via `wesolowski::verify` followed by AEAD decryption. The user's `well_formedness_proof` is byte-identical to the anchor's `evaluation_proof` because `prove` is deterministic — the anchor MAY cross-check by byte comparison.

Phase 7.5.4 surface (in `adamant-crypto::vdf::envelope`):

- `derive_symmetric_key(h: &BinaryQuadraticForm) -> Key` — public; useful for the original sender to re-derive their key without re-running the VDF.
- `encrypt_with_randomness(params, plaintext, g_seed: &[u8; 32], nonce_bytes: &[u8; 12]) -> Result<(TimeLockEnvelope, h), EnvelopeError>` — deterministic; used by tests and any caller needing reproducibility.
- `encrypt<R: CryptoRng + RngCore>(params, plaintext, rng) -> Result<(TimeLockEnvelope, h), EnvelopeError>` — convenience wrapper drawing randomness from `rng`.
- `decrypt(params, envelope) -> Result<(Vec<u8>, TimeLockDecryption), EnvelopeError>` — round-anchor-side; performs `T` sequential squarings (~10-15s at genesis `T ∈ [2M, 7.5M]` per §3.8.2).
- `verify_decryption(params, envelope, decryption) -> Result<Vec<u8>, EnvelopeError>` — public observer-side fast path; sub-millisecond at any `T`.
- `EnvelopeError` enum with 6 variants (Setup + Wesolowski + Bqf wrapping + CiphertextTooShort + SymmetricDecryptionFailed + EvaluationProofInvalid) + Display + std::error::Error.

21 unit tests covering: `derive_symmetric_key` determinism + distinct-h-distinct-key + TIME_LOCK_SYMMETRIC_KEY tag pin (byte recipe); encrypt/decrypt round-trip on empty / typical / 8KB plaintexts; encrypt determinism; distinct seeds/nonces produce expected differential outputs; encrypt's returned h matches anchor's recovered h; verify_decryption accepts honest decryption + rejects tampered solution / tampered evaluation_proof / AEAD-tampered ciphertext / short ciphertext; well_formedness_proof byte-identical to evaluation_proof (optional cross-check property); convenience encrypt(OsRng) variant; **full end-to-end pipeline** (user → anchor → observer all recover the same plaintext, h consistent across actors); error-variant display + std::error::Error.

Phase 7.5.4 metrics: vdf module tests 183 → 204 passing (+21). adamant-crypto LOC ~8,100 → ~9,000 (+~900 — envelope module + tests). Workspace clippy + fmt + strict audit + both resistant-proof guards all pass.

**Phase 7.5 cumulative closure**: 4 sub-arcs (7.5.0 wire types + 7.5.1 a/b/c/d class-group arithmetic + 7.5.2 a/b deterministic setup + 7.5.3 Wesolowski operations + 7.5.4 envelope). Total vdf module 17 → 204 tests across the workstream. adamant-crypto LOC ~3,463 → ~9,000 (+~5,500 across Phase 7.5). 4 new domain tags registered (TIME_LOCK_PARAMETERS, WESOLOWSKI_CHALLENGE, TIME_LOCK_SYMMETRIC_KEY, CLASS_GROUP_DISCRIMINANT, CLASS_GROUP_ELEMENT_SEED — actually 5). 3 new whitepaper subsections (§3.8.6 + §3.8.7 + §3.8.8). 3 new Cat E workspace utilities added (num-bigint, num-integer, num-traits). All adamant-native (no external VDF / class-group / number-theory crates pulled in).

**Next sub-arc — Phase 7.6**: threshold mempool + two-regime hysteresis at the §8.4.2 viability boundary (switch to threshold at `N ≥ 15`; switch back to time-lock at `N < 10`). The §3.6 threshold-encryption primitives are already in place from prior phases; Phase 7.6 wires them into the §8.4 mempool flow alongside the time-lock regime shipped in Phase 7.5.

**Phase 7.6 closure (commit `de95aa5`)** — threshold-mempool regime hysteresis + wire types per §3.6 + §8.4 + §3.8.5. No spec amendment needed: §8.4 (Encrypted mempool) and §3.8.5 (Transition to threshold encryption) already specify both the two-regime structure and the hysteresis rule at the level this implementation pins. Phase 7.6 ships the consensus-state-binding types + state-machine arithmetic that Phase 7.7 (DAG-BFT consensus core) will consume.

Phase 7.6 surface (in `adamant-consensus::mempool`):

- `Regime` closed enum (`TimeLock = 0x00`, `Threshold = 0x01`) with consensus-binding BCS variant tags. Adding a variant is a hard fork.
- `RegimeState { current: Regime }` — consensus state carrying the regime across epoch boundaries. `at_activation()` returns `TimeLock` (per §8.1.6 the chain activates at `N = 7 < 15`).
- `RegimeState::transition(active_set_size: usize) -> Self` — pure function applying §3.8.5 hysteresis: `TimeLock` switches to `Threshold` at `N ≥ 15`; `Threshold` switches back to `TimeLock` at `N < 10`; hysteresis band `[10, 14]` keeps the prior regime.
- `ThresholdMempoolEnvelope { identity, ciphertext_header: [u8; 96], ciphertext }` — wire type for §8.4.3 threshold-encrypted envelopes. The 96-byte header matches `adamant_crypto::threshold::CIPHERTEXT_HEADER_BYTES`; `ciphertext` carries 12-byte nonce prefix + AEAD body (same layout as the Phase 7.5 `TimeLockEnvelope`).
- `MempoolEnvelope` closed enum: `TimeLock(TimeLockEnvelope) = 0x00`, `Threshold(ThresholdMempoolEnvelope) = 0x01`. Canonical envelope-on-the-wire shape the §8.3 DAG vertex's `transactions` field will carry. `.regime() -> Regime` for caller-side dispatch.
- Consensus-binding constants pinned: `THRESHOLD_ACTIVATION_FLOOR = 15` (§8.4.2 viability boundary), `THRESHOLD_DEACTIVATION_FLOOR = 10` (§3.8.5 hysteresis floor), `THRESHOLD_CIPHERTEXT_HEADER_BYTES = 96` (re-exported from crypto layer).

Two compile-time invariants enforced via const-block assertions: `THRESHOLD_DEACTIVATION_FLOOR < THRESHOLD_ACTIVATION_FLOOR` (otherwise the hysteresis band is empty), and `THRESHOLD_DEACTIVATION_FLOOR > ACTIVE_SET_FLOOR` (otherwise the deactivation falls below the §8.7.1 dormancy threshold and regime selection is moot).

25 unit tests covering: constant pins, BCS variant tags + round-trips for `Regime` / `RegimeState` / `ThresholdMempoolEnvelope` / `MempoolEnvelope`, **exhaustive hysteresis transition matrix** (every boundary value `7..15` from both starting regimes), no-flap property (walk through `N = 14 → 15 → 14 → 10 → 9` and confirm chain visits both regimes correctly), idempotence at steady state, ciphertext-header width pin, `.regime()` dispatch.

Phase 7.6 metrics: adamant-consensus 168 → 193 tests passing (+25). adamant-consensus LOC ~3,000 → ~3,600 (+~600 — mempool module + tests). No spec amendment; no new domain tags; no new workspace dependencies. Workspace clippy + fmt + strict audit + both resistant-proof guards all pass.

**Phase 7 progression (cumulative through 7.6)**: 7.0 + 7.1 + 7.2 + 7.3 + 7.4 + 7.5 (all sub-arcs) + 7.6 closed. The §8.4 encrypted-mempool foundation is complete at the type + state-machine level. **Phase 7.7** — DAG-BFT consensus core (the large sub-arc per the §8.3 + §8.7 spec) — is in progress; split into 5 sub-arcs per the roadmap in `dag.rs`. Phase 7.7 wires together everything shipped so far: vertices (7.3), VRF anchor election (7.4), time-lock + threshold envelopes (7.5 + 7.6), through Mysticeti-style commit waves with §8.7 safety / liveness invariants.

**Phase 7.7a closure (commit `93398f5`)** — DAG state storage + insertion validation per whitepaper §8.3.1 + §8.3.2 + §8.1.5. Phase 7.7 (DAG-BFT consensus core per §8.3 + §8.7) is the largest single sub-arc of the Phase 7 consensus workstream; split into 5 sub-sub-arcs for reviewability. Phase 7.7a ships the **foundation data structure** that every subsequent sub-arc consumes: the in-memory DAG, its three indices, the structural-invariant insertion validator, and the reachability helpers commit-wave logic will walk over.

Phase 7.7 sub-arc roadmap:

| Sub-arc | Surface | Status |
|---|---|---|
| **7.7a** | DAG storage + insertion validation | **CLOSED** |
| 7.7b | Commit-wave logic (anchor election + commit decision + causal-history walk) | pending |
| 7.7c | Halt-on-disagreement + safety/liveness invariants per §8.7 | pending |
| 7.7d | Mempool integration (threshold/time-lock decryption flows) | pending |
| 7.7e | End-to-end integration tests | pending |

Phase 7.7a surface (new `adamant-consensus::dag` module):

- `DagState` — in-memory vertex storage with three indices: by `VertexId` (primary storage), by `(round, author)` (equivocation-detection index per §8.1.5), by round (parent-set enumeration + anchor-election lookup at 7.7b). Atomic insertion semantics: all three indices update together on success; nothing mutates on `Err`. The `#[allow(clippy::struct_field_names, …)]` carries explicit reason text: the `by_` prefix makes the indexing dimension obvious at every call site.
- `DagError` — typed-error closed enum with 9 variants. Non-`#[non_exhaustive]` per consensus-critical-surface discipline (adding a variant is a hard-fork-aware deliberate change): `EquivocationDetected { author, round, existing }`, `DuplicateParents`, `InsufficientQuorum { parents, required }`, `UnknownParent`, `ParentRoundMismatch { parent, parent_round, expected }`, `AuthorNotInActiveSet`, `InvalidAuthorPublicKey`, `InvalidSignature`, `GenesisVertexCarriesParents`. Display impl with pairwise-distinct messages + `std::error::Error` impl.
- `DagState::insert(vertex, active_set)` — structural validation only. Steps: (1) equivocation check via `(round, author)` index lookup; (2) parent-set distinctness; (3) genesis-round (round 0) parent-emptiness check; (4) non-genesis quorum (`parents.len() ≥ quorum_threshold(active_size)` per §8.3.1); (5) parent existence at exactly `vertex.round − 1`; (6) author-in-active-set check. BLS-signature verification is intentionally NOT performed here — `insert` is the lighter path useful for tests and pipelines that BLS-check elsewhere.
- `DagState::insert_with_pubkeys<F>(vertex, active_set, resolver)` — full validation including step-7 BLS-signature verification. Resolver pattern `F: Fn(&ValidatorId) -> Option<ValidatorPublicKeys>` decouples the DAG from any specific validator-registry storage shape (chain-state lookup, in-memory map, etc.). Pre-validates the BLS step before any state mutation to preserve atomicity.
- `DagState::causal_ancestors(start) -> HashSet<VertexId>` — BFS transitive parent-closure starting from `start`'s parents (start itself is not its own ancestor). Defensive against missing parents (e.g., post-pruning partial DAGs).
- `DagState::reaches(from, target) -> bool` — terminating BFS reachability check. Special cases: `from == target` returns false; either id missing returns false.
- Read accessors: `vertex(id)`, `vertices_at_round(round)`, `vertex_by_round_author(round, author)`, `contains(id)`, `len()`, `is_empty()`. Constant-time hash lookups.

Three new accessors on `Vertex` (`parents_are_distinct`, `body`, `signature`) expose body-level + signature-level fields the DAG state needs without forcing callers to destructure.

Equivocation posture (§8.1.5 / §8.7.4): two different VertexIds at the same `(author, round)` surface as `EquivocationDetected { author, round, existing }`. The DAG **rejects the duplicate but does NOT auto-trigger slashing** — the caller (Phase 7.10 slashing wiring) holds the equivocation evidence and produces the `SlashOffence::Equivocation` transaction. **Idempotent re-insertion** of the same VertexId is a no-op (essential because network reception is duplicative). Three properties pinned in tests: (a) two distinct vertices at the same `(author, round)` produce `EquivocationDetected` with the right existing-id; (b) same vertex re-inserted is a no-op; (c) DAG state unchanged after rejected insertion.

Genesis-round (round 0) handling per §8.3.2: vertices reference genesis state directly, not other vertices. Parent-set must be empty; non-empty parents at round 0 → `GenesisVertexCarriesParents`. Quorum check + parent-existence check are skipped at round 0.

Determinism + replay: `DagState` is a pure data structure — insertion is deterministic in `(active_set_snapshot, vertices_received)`. Two nodes seeing the same vertex multiset in any order produce identical `DagState`s (the three indices are order-independent given equivocation is rejected). This is essential for §8.7 safety: every honest validator converges on the same DAG.

26 new unit tests covering: genesis-round insertion (success + non-empty-parents rejection), round-1 quorum thresholds at n=7 (threshold=5) and n=15 (threshold=11), at-exactly-threshold succeeds, below-quorum / duplicate-parents / unknown-parent / wrong-round-parent rejection paths, equivocation detection at genesis round with `EquivocationDetected` variant assertion, idempotent re-insertion of same vertex (`dag.len() == 1` after two inserts), author-not-in-active-set rejection, vertex lookup by id + (round, author) + round, `causal_ancestors` empty/direct/transitive traversal across r0→r1→r2 (transitive ancestors include both round-1 and round-0 vertices), `reaches()` correctness (parent reaches true; non-parent reaches false; self reaches false; unknown source/target reaches false), atomicity (failed insert leaves DAG state unchanged), `DagError` Display message pairwise-distinctness + `std::error::Error` impl, 75-validator design-target stress test.

Phase 7.7a metrics: `cargo test -p adamant-consensus --lib` reports 219 passing (193 Phase 7.6 close + 26 Phase 7.7a). adamant-consensus LOC ~3,600 → 3,786 (+~190 — dag module + 3 vertex accessors). adamant-consensus pub items 169 → 195 (+26). Workspace lib tests ~2,685 → 2,711 (+26). Workspace clippy + fmt + strict audit + both resistant-proof guards all pass; doc coverage stays at 100.0% across 9 Adamant-authored crates. No spec amendment; no new domain tags; no new workspace dependencies. Pre-existing `adamant-halo2` doc-test failures (vendored upstream Halo 2 doc strings referencing the upstream `halo2_proofs` module path) are inherited from the Phase 6.8b fork and out of scope for Phase 7.7a.

**Phase 7.7b closure (commit `db47d3d`)** — commit-wave logic per whitepaper §8.3.3 + §8.6. Ships steps 1–3 of the four-step §8.3.3 commit-wave shape as pure functions over the Phase 7.7a DagState. Step 4 (transaction extraction + AVM execution) crosses into the §6 execution layer and lands at Phase 7.7d/e alongside mempool integration.

Phase 7.7b surface (new `adamant-consensus::commit_wave` module):

- **`elect_anchor(dag, anchor_round, vrf_randomness) -> Option<VertexId>`** — §8.3.3 step 1. Deterministically selects one vertex from the anchor round via the §8.6 VRF randomness. Sorts the round's vertices canonically by `(author, vertex_id)` before indexing via `vrf::select_index` — the `vertices_at_round` accessor returns insertion order (network-arrival-dependent), so the canonical sort is what makes selection network-position-independent. Returns `None` on empty round (halt-at-floor scenario per §8.7.1; Phase 7.7c handles).
- **`direct_commit_decision(dag, anchor, anchor_round, active_set_size) -> CommitDecision`** — §8.3.3 step 2. Applies Mysticeti's direct commit rule at `decision_round = anchor_round + DIRECT_COMMIT_DECISION_OFFSET` (offset=2). `Committed` when supporter count ≥ §8.3.1 quorum; `Skipped` when decision round has ≥ quorum total vertices but anchor support is below quorum; `Pending` when decision round has < quorum total vertices. Phase 7.7c lands the indirect commit rule (skip-votes at `anchor_round + 3` + halt-on-disagreement at the §8.7.1 floor).
- **`commit_order(dag, anchor, already_committed) -> Vec<VertexId>`** — §8.3.3 step 3. Causal-history total-ordering walk. Computes `causal_ancestors(anchor) ∪ {anchor} − already_committed`, sorts by `(round, author, vertex_id)` to break the partial causal order into a deterministic total order. Generic over `BuildHasher` so callers can use any `HashSet` flavor for `already_committed`.
- **`CommitDecision`** — closed enum `Committed | Skipped | Pending`; non-`#[non_exhaustive]` per consensus-critical-surface discipline.
- **`DIRECT_COMMIT_DECISION_OFFSET = 2`** — consensus-binding constant pinning the Mysticeti direct-commit horizon.

All three functions are pure — same inputs always produce same outputs. The §8.6 VRF supplies the only non-DAG-derived randomness (and VRF outputs are themselves deterministic given the inputs + the validator quorum). This is essential for the §8.7 safety theorem: every honest validator independently produces the same commit-wave decision and the same totally-ordered execution sequence.

§8.3.3 self-describes as "a simplified description of the Mysticeti commit rule" — the full Mysticeti rule has both a *direct* commit (decided at `anchor_round + 2`, this sub-arc) and an *indirect* commit (decided at `anchor_round + 3` via skip-votes pulling forward to a future wave's anchor; Phase 7.7c). Phase 7.7b ships the direct commit rule. Phase 7.7c lands the indirect commit rule, halt-on-disagreement at the §8.7.1 floor, and the §8.7 safety/liveness invariant suite.

19 new unit tests covering: `DIRECT_COMMIT_DECISION_OFFSET` pin; `elect_anchor` empty-round (`None`) / single-vertex / determinism / spread under varying randomness (≥ 2 distinct anchors over 32 trials) / insertion-order-independence (forward vs reverse-seed insertion produces the same anchor); `direct_commit_decision` `Pending` (decision round empty) / `Pending` (decision round below quorum) / `Committed` (n=7, full support) / `Skipped` (anchor unreferenced, decision round at full quorum) / `Committed` at exact n=15 quorum=11; `commit_order` anchor-alone (no ancestors) / full causal closure (16 vertices through round-3) / excludes-already-committed / empty-when-anchor-already-committed / canonical-within-round (sorted by author) / deterministic-across-invocations; full elect→decide→order pipeline integration; **full pipeline DAG-construction-order independence** (forward insertion vs reverse-author insertion produces identical ids / anchor / decision / order — the property the §8.7 safety theorem relies on).

Phase 7.7b metrics: `cargo test -p adamant-consensus --lib` reports 238 passing (219 Phase 7.7a close + 19 Phase 7.7b). adamant-consensus LOC 3,786 → 4,218 (+432 — commit_wave module + tests). adamant-consensus pub items 195 → 200 (+5: `elect_anchor`, `direct_commit_decision`, `commit_order`, `CommitDecision`, `DIRECT_COMMIT_DECISION_OFFSET`). Workspace lib tests 2,711 → 2,730 (+19). Workspace clippy + fmt + strict audit + both resistant-proof guards all pass; doc coverage stays at 100.0% across 9 Adamant-authored crates. No spec amendment; no new domain tags; no new workspace dependencies.

**Phase 7.7c closure (commit `56abe86`)** — indirect commit rule + halt detection per whitepaper §8.3.3 + §8.7. Phase 7.7c layers the **stateful** commit-decision tracker on top of Phase 7.7b's pure-function direct commit rule. Three responsibilities: indirect commit propagation, chronological commit ordering across waves, and §8.7.1 halt-detection signals.

Phase 7.7c surface (new `adamant-consensus::commit_sequencer` module):

- **`WaveOutcome`** closed enum: `Committed { anchor, ordered }` | `Skipped { anchor }` | `Undecided { anchor }`. Non-`#[non_exhaustive]` per consensus-critical-surface discipline. BCS-serialisable for chain-state commitments at Phase 7.7e. The `ordered` field on Committed is the totally-ordered list of vertices this wave brings into the chain — what step 4 of §8.3.3 (transaction extraction + AVM execution) consumes.
- **`SequencerError`** closed enum: `AlreadyResolved { wave }` | `AnchorMismatch { wave, existing, supplied }`. `Display` + `std::error::Error` impl with pairwise-distinct messages.
- **`CommitSequencer`** stateful struct owning: `schedule: CommitWaveSchedule`; `decided: BTreeMap<WaveIndex, WaveOutcome>` (BTreeMap so wave-index iteration is chronological — the property the indirect-commit propagation relies on); `committed: HashSet<VertexId>` (the running committed-vertex set passed into `commit_order` for each new wave).
- **`CommitSequencer::record_decision(dag, wave, anchor, decision)`** — the indirect-commit machinery. On `CommitDecision::Pending`: marks wave Undecided. On `CommitDecision::Skipped`: marks wave Skipped (skips don't propagate to earlier undecided). On `CommitDecision::Committed`: applies the indirect commit rule — every earlier undecided wave resolves as Committed (if `dag.reaches(anchor, earlier_anchor)`) or Skipped (otherwise), chronologically; then commits this wave. Returns `Err(SequencerError)` on `AlreadyResolved` or `AnchorMismatch`.
- Accessors: `committed_set` / `committed_count` / `is_committed` / `schedule` / `outcome` / `outcomes` (chronological iterator) / `recorded_waves` / `undecided_waves`.
- **`is_chain_dormant(active_set)`** — §8.7.1 chain-fully-paused signal. Returns `active_set.is_dormant()` (`active_size < ACTIVE_SET_FLOOR`). Wallets and explorers `SHOULD` display a halt-state warning when this returns `true`.
- **`is_chain_at_floor(active_set)`** — softer §8.7.1 signal. Returns `true` when active-set tier is `SecurityTier::Tier1` (N ∈ [7, 14]). Chain operational but with weak liveness; occasional halts of several rounds expected per §8.7.1 liveness math.

**Indirect commit rule**: Mysticeti's "indirect commit at `anchor_round + 3`" generalised — any later direct-committed anchor pulls forward all earlier undecided waves. Three scenarios pinned: (A) **Pulls forward** — wave 0 Pending, wave 1 Committed AND `A_1` causally reaches `A_0` → wave 0 indirect-committed. (B) **Indirect skip** — `A_1` does NOT causally reach `A_0` → wave 0 indirect-skipped. (C) **Skip doesn't propagate** — wave 1 Skipped leaves wave 0 still Undecided. Earlier waves are resolved by a later **Committed** decision only, never by a later Skipped.

**Chronological commit ordering**: when wave W commits and resolves earlier undecided waves `W_0, W_1, …, W_{W-1}`, the sequencer emits the totally-ordered commit sequences in wave order. Each wave's `commit_order` walk excludes the running committed set; the resulting per-wave `ordered` lists are a **partition** of the §6 execution input. The chronological order property is pinned in tests via the `chronological_commit_order_preserved_under_indirect_resolution` invariant check (three waves; ordered sets are pairwise disjoint; the union matches the committed set).

**§8.7 safety invariants** pinned in tests:
- **No double-commit across waves** (Theorem 1 expression at the consensus layer): verified via the union-of-ordered-lists equals committed_set arithmetic across multiple committed waves.
- **Chronological commit order preserved under indirect resolution**: per-wave `ordered` lists are pairwise disjoint; wave 0's stuff comes before wave 1's; wave 1's before wave 2's.
- **Deterministic across invocations** (the §8.7 safety convergence property): two `CommitSequencer`s processing the same sequence of `(DAG, wave, anchor, decision)` tuples converge to identical state.

27 new unit tests covering: sequencer basics (new is empty / schedule accessor / committed_set starts empty); `record_decision` Pending (inserts Undecided / idempotent re-record / different-anchor errors); Skipped (inserts Skipped / does NOT propagate to earlier undecided); Committed (inserts Committed + extends set / already-committed errors / already-skipped errors); indirect commit (pulls forward earlier undecided / skip when later anchor doesn't reach earlier / consecutive undecided stay undecided / resolves multiple earlier waves / mixed reach resolves each appropriately); §8.7 safety invariants (no double-commit / chronological order / determinism); halt detection (dormant below floor / not dormant at/above floor / at-floor true in Tier I range / false outside); SequencerError display + `std::error::Error`; `WaveOutcome` BCS round-trip; full pipeline integration (elect → record → committed_set evolves).

Phase 7.7c metrics: `cargo test -p adamant-consensus --lib` reports 265 passing (238 Phase 7.7b close + 27 Phase 7.7c). adamant-consensus LOC 4,218 → 4,919 (+701 — commit_sequencer module + tests). adamant-consensus pub items 200 → 216 (+16: `WaveOutcome` + 3 variants, `SequencerError` + 2 variants, `CommitSequencer` + 11 methods, `is_chain_dormant`, `is_chain_at_floor`). Workspace lib tests 2,730 → 2,757 (+27). Workspace clippy + fmt + strict audit + both resistant-proof guards all pass; doc coverage stays at 100.0% across 9 Adamant-authored crates. No spec amendment; no new domain tags; no new workspace dependencies.

**Phase 7.7 progression**: 7.7a + 7.7b + 7.7c closed; 7.7d/e pending. The DAG-BFT consensus core's **decision pipeline** is feature-complete at the type + state-machine level: vertices flow into `DagState`; anchor election + direct commit + indirect commit + halt detection produce a totally-ordered, deterministic, §8.7-safe commit sequence. What remains: **Phase 7.7d** — mempool integration (threshold/time-lock decryption flows wiring the §3.6 + §3.8 encrypted-mempool envelopes through the committed-wave output); **Phase 7.7e** — end-to-end integration tests exercising the full consensus pipeline against multi-validator fixture scenarios.

**Phase 7.7d closure (commit `94b7064`)** — mempool decryption per whitepaper §3.6 + §3.8 + §8.4. Phase 7.7d ships the decryption-flow layer that converts committed-wave output (per-wave `Vec<VertexId>` from the Phase 7.7c [`CommitSequencer`]) into the cleartext-transaction sequence the §6 execution layer consumes per §8.3.3 step 4 ("Transaction extraction"). Decryption branches on regime per §8.4: threshold regime uses validator-published decryption shares with 2/3+1 aggregation; time-lock regime uses the round anchor's atomic VDF decryption per §8.4.4 Mitigation B.

Phase 7.7d surface (new `adamant-consensus::mempool_decryption` module):

- **`MempoolDecryptionError`** closed enum with 10 variants covering every rejection path: `VertexNotInDag`, `EnvelopeDecodeFailed`, `TimeLockDecryptionFailed`, `ShareDecodeFailed`, `ShareVerificationFailed`, `UnknownValidatorShareIndex`, `CombineFailed`, `DecapsulationFailed`, `AeadDecryptionFailed`, `CiphertextTooShort`. `Display` + `std::error::Error` with pairwise-distinct messages. Non-`#[non_exhaustive]` per consensus-critical-surface discipline.
- **`DecryptedTransaction { origin_vertex, origin_index, plaintext }`** — the §6 execution layer's input shape. BCS-serialisable.
- **`ValidatorDecryptionShare { identity, share_index, share_bytes }`** — the BCS-shape inside a vertex's [`crate::DecryptionShare`] (`.bytes`). Phase 7.3 left this as opaque bytes; Phase 7.7d pins the inner shape. The 48-byte `share_bytes` array uses `#[serde(with = "BigArray")]` matching the `serde-big-array` pattern in `identity.rs`.
- **`extract_envelopes(dag, ordered)`** — walks a committed wave's ordered `VertexId` list and BCS-decodes each vertex's `transactions` field into `MempoolEnvelope`s (Phase 7.6 wire type). Returns `Vec<(VertexId, usize, MempoolEnvelope)>` in committed-wave order.
- **`decrypt_time_lock(params, vertex, index, envelope, decryption)`** — observer-side fast-path wrapping §3.8.8 `vdf::envelope::verify_decryption`. Sub-millisecond at any `T`; vs the round anchor's ~10–15 seconds of VDF work per §3.8.2. Packages the recovered plaintext as a `DecryptedTransaction`.
- **`ThresholdShareAccumulator`** stateful collector: tracks per-identity ciphertexts + collected shares; `submit_envelope` / `submit_share` / `try_decrypt` / `forget` / `share_count` / `pending_count` / `threshold` accessors. Eagerly validates each share against the §3.6 pairing-check before storing (consensus-critical share-validation discipline per §3.6.1). Internal `PendingThreshold` supports both share-then-envelope and envelope-then-share arrival orders via `Option<ThresholdHeader>`.

`Cargo.toml`: adds `num-bigint` + `rand_core` (with `getrandom` feature) as **dev-dependencies** for the time-lock decryption + trusted-dealer threshold fixtures. Both are already in the workspace bounded ecosystem per CLAUDE.md §14.1. **No production-binary dep changes.**

**What Phase 7.7d does NOT ship (deferred to later sub-arcs):**

- DKG (§8.4.3): the distributed key generation that produces the threshold public-key shares. Phase 7.7d's accumulator accepts the `PublicKeyShare` registry at construction; sourcing it from chain state is a follow-on sub-arc.
- Active-set ↔ validator-share binding via on-chain `Validator` records. Phase 7.7d treats the registry as a `BTreeMap<u32, PublicKeyShare>` input.
- Anchor-decryption wire binding: where in a vertex the round anchor publishes its time-lock `TimeLockDecryption`. Phase 7.7d's `decrypt_time_lock` is a pure function taking `(envelope, decryption)` as separate inputs; the wire-binding for pairing them inside a vertex lands at Phase 7.7e integration or a Phase 7.6 wire amendment.

19 new unit tests covering: `ValidatorDecryptionShare` BCS round-trip + distinct-identities-distinct-bytes; `extract_envelopes` empty / unknown-vertex / threshold-envelopes-decoded / malformed-envelope-rejected; `decrypt_time_lock` **full round-trip** (encrypt → anchor decrypt → observer verify recovers plaintext at 2048-bit discriminant, T=10) + tampered-decryption rejection; `ThresholdShareAccumulator` empty-at-construction / **full-round-trip-at-threshold** (3-of-5, real BLS shares from `TrustedDealerShares` fixture; the full encapsulate → encrypt → 3 decryption_shares → combine → decapsulate → AEAD pipeline) / `None`-below-threshold / `None`-when-no-envelope-yet / unknown-share-index-rejection / tampered-share-bytes-rejection / malformed-BCS-rejection / `forget`-drops-pending; `MempoolDecryptionError` Display + `std::error::Error`; `DecryptedTransaction` BCS round-trip.

Phase 7.7d metrics: `cargo test -p adamant-consensus --lib` reports 284 passing (265 Phase 7.7c close + 19 Phase 7.7d). adamant-consensus LOC 4,919 → 5,702 (+783 — mempool_decryption module + tests). adamant-consensus pub items 216 → 233 (+17: `MempoolDecryptionError` + 10 variants, `DecryptedTransaction` + 3 fields, `ValidatorDecryptionShare` + 3 fields + 3 methods, `extract_envelopes`, `decrypt_time_lock`, `ThresholdShareAccumulator` + 7 methods). Workspace lib tests 2,757 → 2,776 (+19). Workspace clippy + fmt + strict audit + both resistant-proof guards all pass; doc coverage stays at 100.0% across 9 Adamant-authored crates. No spec amendment; no new domain tags; no new production-binary workspace dependencies.

**Phase 7.7e closure (commit `866d8ae`)** — end-to-end integration tests for the DAG-BFT consensus core pipeline. Phase 7.7e closes the Phase 7.7 DAG-BFT consensus core sub-arc end-to-end. New `crates/adamant-consensus/tests/dag_bft_pipeline.rs` integration-test file exercises the full pipeline (DagState insertion → elect_anchor → direct_commit_decision → CommitSequencer indirect-commit resolution → extract_envelopes → time-lock decryption verification / threshold share accumulation → DecryptedTransaction sequence) against multi-validator fixture scenarios.

6 integration tests:

- **`threshold_pipeline_end_to_end`** — n=15 threshold regime, full pipeline. Real BLS shares from `TrustedDealerShares` (t=11); plaintext encrypted via §3.6 `encapsulate` → AEAD wrap, decrypted via accumulator collecting 11 shares + combine + decapsulate + AEAD decrypt. Asserts plaintext round-trips through DagState → CommitSequencer → extract_envelopes → ThresholdShareAccumulator.
- **`time_lock_pipeline_end_to_end`** — n=7 time-lock regime, full pipeline. Real Wesolowski VDF at 2048-bit discriminant (§3.8.2 minimum), T=10 for test speed. Anchor decrypts via `envelope::decrypt`; observer verifies via `decrypt_time_lock`.
- **`indirect_commit_pipeline_pulls_forward_earlier_wave`** — wave 0 Pending, wave 1 Committed but does NOT reach wave 0 → wave 0 indirect-Skipped per the §8.7 Mysticeti rule. Only wave 1's payload appears in the `DecryptedTransaction` sequence; wave 0's anchor is in `committed_set` absence. Verifies the indirect-commit rule end-to-end through the full decryption pipeline.
- **`halt_detection_signals_chain_paused_below_floor`** — §8.7.1 halt-on-disagreement signal. N=6 returns `is_chain_dormant` true; N=7 and N=30 false.
- **`pipeline_is_deterministic_across_independent_runs`** — §8.7 safety convergence property. Two parallel pipeline runs on identical inputs produce byte-identical `DecryptedTransaction` sequences.
- **`pipeline_produces_disjoint_per_wave_ordered_sequences`** — §8.7 safety no-double-commit invariant across 3 committed waves. Per-wave `ordered` lists partition the `committed_set` (no vertex appears in two waves' ordered sequences).

Phase 7.7e metrics: `cargo test -p adamant-consensus --test dag_bft_pipeline` reports 6/6 passing in ~12.5 seconds (VDF round-trips dominate). Workspace lib tests unchanged at 2,776 (Phase 7.7e ships integration tests, not lib code; the audit's LOC counter only walks `src/`, so adamant-consensus stays at 5,702 LOC + 233 pub items + 100% doc coverage). Workspace clippy + fmt + strict audit + both resistant-proof guards all pass. No new lib types; no new spec amendment; no new production-binary dependencies.

**Phase 7.7 cumulative closure** — all 5 sub-arcs closed (7.7a + 7.7b + 7.7c + 7.7d + 7.7e). **THE DAG-BFT CONSENSUS CORE IS FEATURE-COMPLETE END-TO-END.** Cumulative metrics across Phase 7.7:

| Sub-arc | Surface | LOC delta | Pub-item delta |
|---|---|---|---|
| 7.7a | DAG storage + insertion validation | +~190 | +26 |
| 7.7b | Direct commit-wave logic | +432 | +5 |
| 7.7c | Indirect commit + halt detection | +701 | +16 |
| 7.7d | Mempool decryption | +783 | +17 |
| 7.7e | End-to-end integration tests | +684 (tests/) | 0 (no lib code) |
| **Total** | **DAG-BFT consensus core** | **+~2,100 src + ~684 tests** | **+64 pub items** |

Pipeline shape at Phase 7.7 closure: vertices flow into `DagState`; the §8.6 BLS-aggregate VRF (Phase 7.4) drives anchor election; the Mysticeti direct + indirect commit rules produce totally-ordered, deterministic, §8.7-safe wave outcomes; threshold-encrypted (§3.6 + §8.4.3) and time-lock-encrypted (§3.8 + §8.4.4) envelopes decrypt through the regime-appropriate path to produce the `DecryptedTransaction` sequence the §6 execution layer consumes.

**Phase 7 progression**: **7.0 + 7.1 + 7.2 + 7.3 + 7.4 + 7.5 (all sub-arcs) + 7.6 + 7.7 (all sub-arcs) closed.** Sub-arcs remaining:

- **7.8** — networking + transaction propagation per §9 (libp2p integration; gossipsub-based vertex + share propagation; mempool gossiping).
- **7.9** — light client + tier signal per §8.1.7 + §8.9 (recursive-proof verification interface; SecurityTier disclosure observability).
- **7.10** — slashing wiring + economics per §8.1.5 + §10 (equivocation evidence extraction from `DagError::EquivocationDetected`; slashing transactions; §10 tokenomics flow into the validator-stake state machine).
- **7.11** — end-to-end integration (all Phase 7 sub-systems wired together; multi-validator regression suite).

**Phase 7.8.0 closure (commit `d256b81`)** — networking wire-format foundation per whitepaper §9.3.1. Phase 7.8 begins; ships the networking-substrate-agnostic wire-format foundation in a new `adamant-network` crate (Adamant-authored crate #10). Mirrors the wire-foundation pattern at Phase 7.5.0 / 7.3 / 7.6: pin the consensus-binding wire shapes first; layer the libp2p transport on top at Phase 7.8.1. **Per §14.4 Decision 4 (RESOLVED at previous commit)**, libp2p is admitted to Category E networking-infrastructure tier; the `adamant-network` crate is the production-side wrapper around libp2p's API (libp2p NOT forked). Phase 7.8.0 does not yet pull in libp2p as a runtime dep — wire types are pure-Rust serde structures consumable by any transport.

Phase 7.8.0 surface (new `adamant-network` crate):

- **`NETWORK_PROTOCOL_VERSION = 1`** — wire-envelope version. Distinct from the per-transaction version field; consensus-binding (changing it is a hard fork).
- **`EncryptionMode`** closed enum (`Transparent = 0x00`, `Encrypted = 0x01`) per §9.3.1. Pinned BCS variant tags.
- **`SubmissionProof`** — opaque-bytes wrapper for the §9.5.1 anti-DoS payload. Inner structure pins at Phase 7.8.2. `new` / `as_bytes` / `len` / `is_empty` accessors.
- **`NetworkTransaction { version, encryption_mode, payload, fee_tip, expiration_round, submission_proof }`** — §9.3.1 wire shape verbatim. `transparent` / `encrypted` constructors + `with_submission_proof` builder. Field order is consensus-binding (pinned in test).
- **`GossipsubTopic`** closed enum (`Vertices = 0x00`, `Mempool = 0x01`) with canonical libp2p topic strings: `"ADAMANT/v1/vertices"` / `"ADAMANT/v1/mempool"`. The `ADAMANT/v1/` prefix matches `NETWORK_PROTOCOL_VERSION`.
- **`NetworkMessage`** enum (`Vertex(Vertex)` | `Transaction(NetworkTransaction)`) — wire envelope dispatching between the two §9.2.2 gossipsub topics. `topic()` helper for routing.

Phase 7.8 sub-arc roadmap (registered in `adamant-network::lib.rs` module docs):

| Sub-arc | Whitepaper | Surface | Status |
|---|---|---|---|
| **7.8.0** | §9.3.1 | wire-format types | **CLOSED** |
| **7.8.1** | §9.2, §9.3 | libp2p integration + gossipsub propagation | **CLOSED** |
| **7.8.2** | §9.5 | anti-DoS + submission proofs + fee floors | **CLOSED** |
| **7.8.3** | §9.6 | Kademlia DHT discovery + bootstrap | **CLOSED** |
| **7.8.4** | §9.7 | mempool design + anti-DoS gating | **CLOSED** |
| **7.8** | §9 | **networking + mempool layer — feature-complete** | **CLOSED** |

Workspace changes:
- `Cargo.toml`: add `crates/adamant-network` to workspace members.
- `tools/workspace-audit/audit.py`: add `adamant-network` to the `ADAMANT_CRATES` roster (audit now covers 10 Adamant-authored crates).

19 new unit tests covering: `NETWORK_PROTOCOL_VERSION` pin; `EncryptionMode` variant tags + BCS round-trip; `SubmissionProof` new + accessors + round-trip; `NetworkTransaction` transparent + encrypted constructors + `with_submission_proof` + BCS round-trip + **field-order pin** (asserts 21-byte canonical encoding for a specific fixture, byte-by-byte); `GossipsubTopic` variant tags + canonical topic-name strings + distinctness + BCS round-trip; `NetworkMessage` topic dispatch + BCS round-trips for both variants + variant tag pin + distinct-payloads produce distinct encodings.

Phase 7.8.0 metrics: `cargo test -p adamant-network --lib` reports 19/19 passing. New crate metrics: 301 LOC, 15 pub items, 100% doc coverage, `#![forbid(unsafe_code)]`. Workspace lib tests 2,776 → 2,795 (+19). All 10 Adamant-authored crates at 100% doc coverage. Workspace clippy + fmt + strict audit + both resistant-proof guards all pass. No spec amendment; no new domain tags; no new production-binary workspace dependencies (libp2p lands at Phase 7.8.1).

**Phase 7.8.1 closure (commit `00ff614`)** — libp2p integration per whitepaper §9.2 + §9.3. Wires the Phase 7.8.0 wire-format types (`NetworkMessage`, `GossipsubTopic`) onto the libp2p substrate per the §9.2.2 configuration. Per §14.4 Decision 4 Option A, libp2p is admitted to Category E networking-infrastructure tier; the `adamant-network` crate is the production-side wrapper around libp2p's API (libp2p NOT forked).

Workspace dependencies added (exact-pinned per CLAUDE.md §14.1 discipline):

- **`libp2p = "=0.56.0"`** with the §9.2.2 spec-pinned feature subset: `quic`, `tcp`, `noise`, `yamux`, `kad`, `gossipsub`, `identify`, `dns`, `macros`, `tokio`.
- **`tokio = "=1.52.3"`** with `rt-multi-thread`, `net`, `time`, `sync`, `macros` features. Workspace standard async runtime per CLAUDE.md Section 7; admitted here at Phase 7.8.1.
- **`futures = "=0.3.31"`** — async stream/sink combinators used by the libp2p Swarm event loop. Category E workspace utility.

Phase 7.8.1 surface (new `adamant-network::node` module):

- **`NetworkConfig`** — caller-supplied configuration: keypair, listen addresses, bootstrap peers, gossipsub tuning. Builder-style chainables (`with_listen_address` / `with_bootstrap_peer` / `with_max_message_size` / `with_heartbeat_interval`).
- **`AdamantBehaviour`** — composite libp2p `NetworkBehaviour` combining `gossipsub::Behaviour` + `identify::Behaviour`. Defined inside a scoped `behaviour` module with `#![allow(missing_docs)]` narrowly scoping the libp2p derive-macro-emitted sibling `AdamantBehaviourEvent` enum (whose variants the derive macro doesn't doc-comment).
- **`NetworkNode`** — high-level handle owning the libp2p `Swarm<AdamantBehaviour>`. `launch` / `local_peer_id` / `publish` / `next_event` API. **Auto-subscribes to both `GossipsubTopic` values at startup** per the §8 + §9.3 protocol-mandated subscription set.
- **`NetworkEvent`** enum — application-level events: `Message`, `PeerConnected`, `PeerDisconnected`, `BootstrapDialFailed`, `NewListenAddress`. Non-`#[non_exhaustive]` per consensus-critical-surface discipline.
- **`NetworkError`** — 9 typed variants covering every rejection path (`GossipsubSetupFailed`, `IdentifySetupFailed`, `SwarmBuildFailed`, `ListenAddressFailed`, `DialFailed`, `PublishFailed`, `MessageEncodingFailed`, `MessageDecodingFailed`, `SubscriptionFailed`). `Display` + `std::error::Error` with pairwise-distinct messages.

Transport stack per §9.2.2:
- QUIC primary (libp2p's built-in QUIC with encryption + multiplexing).
- TCP fallback with Noise XX security + Yamux multiplexing.
- DNS resolution for multiaddrs.
- gossipsub v1.1 with 200ms heartbeat (matching §8.2's 250ms round target) + 1 MiB max message size + strict validation.
- identify protocol with `/adamant/identify/1.0.0` + agent string `"adamant-network/0.1"`.

Deferred to follow-on sub-arcs (registered in `node.rs` module docs):
- Kademlia DHT for peer discovery → Phase 7.8.3.
- Anti-DoS submission-proof gating → Phase 7.8.2.
- Mempool synchronisation + replacement policy → Phase 7.8.4.
- Onion routing + timing obfuscation per §9.4.2 / §9.4.3 → later sub-arc (out-of-band for the core networking surface).

**Lint scope**: `adamant-network` gets a narrowly-scoped crate-level `#![allow(clippy::multiple_crate_versions)]` to accommodate libp2p's transitive dep tree (`hashlink`, `socket2`, `thiserror`, `unsigned-varint`, `yamux` duplicates). The workspace-wide `multiple_crate_versions = "warn"` discipline stays in force everywhere else. None of the duplicates touch Adamant's cryptographic or consensus surface — they're all inside libp2p's networking-infrastructure subtree.

10 new unit tests covering: `NetworkConfig::new` defaults + 4 `with_*` builder-chain helpers; `NetworkError` 9-variant Display distinctness + `std::error::Error` impl; identify-protocol + agent-string version pin (asserts `/adamant/identify/1.0.0` matches `NETWORK_PROTOCOL_VERSION = 1`); **smoke tests via `#[tokio::test]`**: `network_node_launch_smoke_test` (a node constructs without networking — no listen-addresses or bootstrap-peers); `two_independent_nodes_have_distinct_peer_ids` (two parallel-launched nodes get distinct `PeerId`s).

Phase 7.8.1 metrics: `cargo test -p adamant-network --lib` reports 29/29 passing (19 from 7.8.0 + 10 new). Crate metrics: 717 LOC (was 301), 28 pub items (was 15), 100% doc coverage, `#![forbid(unsafe_code)]`. Workspace lib tests 2,795 → 2,805 (+10). All 10 Adamant-authored crates at 100% doc coverage. Workspace clippy + fmt + strict audit + both resistant-proof guards all pass. No spec amendment; no new domain tags.

**Phase 7.8.2 closure (commit `116e274`)** — anti-DoS primitives per whitepaper §9.5. Wires the four §9.5 anti-DoS layers onto the Phase 7.8.0 wire-format types. The §9.5.1 open question from the prior closure note resolved trivially against the spec text: **§9.5.1 pins "50-100ms PoW puzzle" — Hashcash, not stake-bound**. No spec-author ratification needed; the spec settled it.

Phase 7.8.2 surface:

**Wire-type change**: `adamant-network::SubmissionProof` migrates from opaque `Vec<u8>` to typed `{ nonce: u64, difficulty_bits: u8 }` per the Phase 7.8.0 "inner shape pins at Phase 7.8.2" forward-declaration. BCS layout: 9 bytes flat (nonce LE + difficulty_bits). Consensus-binding; reordering is a hard-fork-aware change.

**New domain tag** added to `adamant-crypto::domain::SUBMISSION_PROOF = b"ADAMANT-v1-submission-proof"` — the consensus-stable namespace anchor for the Hashcash hash construction. Per §3.3.1 adding the tag at Phase 7.8.2 is a hard-fork-aware deliberate change, consistent with prior phases' tag additions (VRF_INPUT/OUTPUT at 7.4, VERTEX_ID at 7.3, TIME_LOCK_* at 7.5, CLASS_GROUP_* at 7.5.2).

**New `adamant-network::anti_dos` module** (~900 LOC + 27 tests):

- **`MAX_DIFFICULTY_BITS = 64`** — operational cap (64-bit grind is astronomically beyond the §9.5.1 50-100ms target).
- **`verify_submission_proof(tx, proof, min_difficulty) -> bool`** — two-stage check: (1) proof's claimed difficulty ≥ receiver's threshold (fast pre-filter); (2) `leading_zero_bits(sha3_256_tagged(SUBMISSION_PROOF, BCS(tx with submission_proof=None) || nonce_le_bytes)) ≥ proof.difficulty_bits` (substantive PoW check).
- **`compute_submission_proof(tx, target, max_iter) -> Option<SubmissionProof>`** — grinds nonces; returns `Some(proof)` when target met within budget.
- **`FeeFloor { micro_adm_per_byte }`** — §9.5.2 per-byte fee floor. `minimum_for(tx) = bcs_size(tx) * per_byte`; `check(tx) = tx.fee_tip ≥ minimum_for(tx)`.
- **`RateLimiter`** — §9.5.3 per-peer token-bucket. `check(peer, now_micros)` refills + charges + returns Allow/Throttle/Reject. Caller supplies monotonic time (deterministic; testable without system clock). `forget(peer)` drops state.
- **`RateLimitConfig { capacity, refill_per_second, reject_below_negative }`** + `launch_default` (20 / 5 / 20).
- **`RateLimitDecision`** closed enum: Allow / Throttle / Reject.
- **`AntiDosError`** closed enum: MissingSubmissionProof / InvalidSubmissionProof / BelowFeeFloor. Display + `std::error::Error` with pairwise-distinct messages.
- **`validate_submission(tx, fee_floor, min_difficulty)`** — orchestrator combining §9.5.1 + §9.5.2 checks. §9.5.3 rate limiting is intentionally separate (caller decides whether to short-circuit known-abusive peers before cryptographic verification).
- **`duration_to_micros`** helper for `Instant::elapsed()` bridging.

§9.5.4 (cryptographic verification of the underlying AVM transaction body) crosses into the §6 execution layer and lands at Phase 7.8.4 + 7.11 integration; Phase 7.8.2 ships the §9.5.1/2/3 primitives only.

28 new unit tests across the anti_dos module + 1 in lib.rs (`submission_proof_bcs_layout_pin`). Coverage: `MAX_DIFFICULTY_BITS` pin; `leading_zero_bits` 10 boundary cases; `compute_submission_proof` Some-at-low-difficulty + None-above-cap; `verify_submission_proof` rejects-below-min-difficulty / forged-proofs / above-cap-claims; **proof-tx-binding** (proof for tx_a doesn't verify for tx_b); `FeeFloor` new + check + zero-floor-accepts-all + BCS round-trip; `RateLimiter` 8 scenarios (first-allows / capacity-exhausts / throttle-to-reject / refill-over-time / refill-capped / per-peer-isolation / forget); `validate_submission` happy-path + 3 rejection paths; `AntiDosError` Display + `std::error::Error`; `duration_to_micros`.

Phase 7.8.2 metrics: `cargo test -p adamant-network --lib` reports 57 passing (29 from prior + 28 new). adamant-network LOC 717 → 1,203 (+486); pub items 28 → 45 (+17). adamant-crypto LOC 6,252 → 6,253 (+1; domain tag); pub items 221 → 222 (+1). Workspace lib tests 2,805 → 2,833 (+28). All 10 Adamant-authored crates at 100% doc coverage. All gates green.

**Phase 7.8.3 closure (commit `f60b8db`)** — Kademlia DHT discovery + bootstrap per whitepaper §9.6. Extends Phase 7.8.1's `AdamantBehaviour` with a third sub-behaviour (`kademlia`); seeds the DHT routing table from caller-supplied bootstrap peers at launch; surfaces discovery + bootstrap-completion events through the existing `NetworkEvent` surface. Per §9.6.1 "bootstrap nodes are not 'trusted' for any consensus-critical purpose. They are convenience infrastructure." — Phase 7.8.3 honours that posture, treating discovered peers as operational connectivity candidates only.

Phase 7.8.3 surface additions:

- **`ADAMANT_KADEMLIA_PROTOCOL = "/adamant/kad/1.0.0"`** — protocol-name pinning the Adamant DHT into its own namespace (libp2p supports protocol-isolated DHTs sharing a physical mesh; the distinct protocol name keeps Adamant's DHT separate from any other libp2p network's). Versioned to match `NETWORK_PROTOCOL_VERSION`; a bump is a hard-fork-aware deliberate change.
- **`AdamantBehaviour.kademlia: KademliaBehaviour<MemoryStore>`** — third sub-behaviour. Configured with the §9.2.2-pinned protocol name + 30s query timeout (libp2p default values for routing-table replication, query parallelism, etc. are inherited unchanged).
- **`NetworkNode::launch` seeds the DHT**: for each bootstrap peer, calls `kademlia.add_address(peer, multiaddr)`; after registering all bootstrap peers, fires `kademlia.bootstrap()` to kick off an initial routing-table fill. The bootstrap result surfaces as a `KademliaBootstrapped` event.
- **`NetworkEvent::PeerDiscovered(PeerId)`** — emitted on each new DHT routing-table entry (`kad::Event::RoutingUpdated { is_new_peer: true, .. }`).
- **`NetworkEvent::KademliaBootstrapped`** — emitted when the Kademlia bootstrap query progresses past its final step (`kad::Event::OutboundQueryProgressed { result: QueryResult::Bootstrap(Ok(_)), step.last: true, .. }`).

Tests added (2):
- `protocol_constants_versioned` extended to cover the Kademlia protocol string (asserts `/adamant/` prefix + `/1.0.0` suffix + distinct from identify protocol).
- `kademlia_protocol_string_is_adamant_specific` pins the exact string `"/adamant/kad/1.0.0"`.
- `launch_with_bootstrap_peer_does_not_error` `#[tokio::test]` smoke-tests the `kademlia.add_address` + `kademlia.bootstrap` wiring — the dial itself fails (no peer exists at the placeholder multiaddr) but that surfaces as a `BootstrapDialFailed` event rather than a launch error; the registration path must succeed.

Module-level docs updated to reflect Phase 7.8.3's cumulative scope (Kademlia now shipped, not deferred).

Phase 7.8.3 metrics: `cargo test -p adamant-network --lib` reports 59 passing (57 from prior + 2 new — `kademlia_protocol_string_is_adamant_specific` + `launch_with_bootstrap_peer_does_not_error`; the `protocol_constants_versioned` extension reuses the existing test slot). adamant-network LOC 1,203 → 1,252 (+49). adamant-network pub items unchanged at 45 (the new `NetworkEvent` variants are visible via the existing enum; new const + behaviour-field are sub-public). Workspace lib tests 2,833 → 2,835 (+2). All 10 Adamant-authored crates at 100% doc coverage. All gates green: clippy + fmt + strict audit + both resistant-proof guards. No spec amendment; no new domain tags; no new production-binary deps (libp2p::kad feature was already admitted at Phase 7.8.1).

**Phase 7.8.4 closure (commit `bd9d6de`)** — local mempool data structure + anti-DoS gating per whitepaper §9.7. Closes Phase 7.8 networking end-to-end.

Per §9.7 the mempool is a priority queue (fee_tip DESC, arrival_seq ASC) capped at ~100,000 entries with eviction (§9.7.1). Per §9.7.2 it is **per-validator local** — consensus does not require mempool agreement; two validators may have disjoint mempools at any moment. **The mempool is therefore NOT a consensus-critical structure** — its API can evolve freely without hard-fork constraints, unlike the §8.3.1 vertex format or §9.3.1 transaction wire shape.

Phase 7.8.4 surface (new `adamant-network::mempool` module):

- **`DEFAULT_MEMPOOL_CAPACITY = 100_000`** per §9.7.1.
- **`Mempool { capacity, next_seq, entries: BTreeMap<PriorityKey, MempoolEntry> }`** — `BTreeMap` iteration = priority order (head = highest priority).
- **`InsertOutcome`** closed enum: `Inserted` / `InsertedWithEviction(Box<NetworkTransaction>)` / `RejectedAsLowerPriority` / `RejectedAsExpired`.
- **`MempoolError`** enum wrapping `AntiDosError` with `From` impl.
- **`Mempool::insert`** (priority queue + TTL only; for trusted paths and tests).
- **`Mempool::validate_and_insert`** orchestrator: runs Phase 7.8.2 `validate_submission` (PoW + fee floor) before admission.
- **`pop_highest` / `peek_highest`** with lazy TTL pruning at the head.
- **`prune_expired`** bulk-cleanup helper for periodic ticks.

**Submission-time proxy**: `arrival_seq` is a per-mempool monotonic counter — approximates §9.7's "submission time" using a strictly-monotonic local proxy. Relying on submitter-supplied timestamps would create a manipulation vector (validators could backdate preferred transactions); local arrival order is the honest proxy.

**TTL semantics**: lazy pruning on `insert` / `pop_highest` / `peek_highest`. Per `NetworkTransaction::expiration_round` semantics, "round AFTER which the tx is invalid" — at `round == expiration_round` the tx is still valid (inclusive boundary).

**§9.5.4 posture**: cryptographic verification of the underlying AVM transaction signature + proofs crosses into the §6 execution layer and lands at Phase 7.11 integration. Phase 7.8.4's mempool orchestrates the §9.5.1/2 layers (submission proof + fee floor) but not the §6 signature check.

23 new unit tests covering: capacity-pin; basic insert (Inserted with room, RejectedAsExpired); priority ordering (higher fee pops first, equal-tip tie-breaks by arrival); eviction at capacity (higher priority evicts, lower rejected, equal-priority tail rejected); TTL (skip expired on pop/peek, bulk prune, inclusive-boundary at round == expiration); `validate_and_insert` anti-DoS rejection + success; **encryption-mode-does-not-affect-priority** (the §9.7 deliberate-no-op invariant); `MempoolError` Display + `std::error::Error` + `From<AntiDosError>`; zero-capacity edge case; `with_submission_proof` field preservation.

Phase 7.8.4 metrics: `cargo test -p adamant-network --lib` reports 82 passing (59 from prior + 23 new). adamant-network LOC 1,252 → 1,645 (+393); pub items 45 → 59 (+14: `Mempool` + `InsertOutcome` + 4 variants + `MempoolError` + 2 methods on Mempool + `DEFAULT_MEMPOOL_CAPACITY`). Workspace lib tests 2,835 → 2,858 (+23). All 10 Adamant-authored crates at 100% doc coverage. All gates green: clippy + fmt + strict audit + both resistant-proof guards. No spec amendment; no new domain tags; no new production-binary deps.

**Phase 7.8 cumulative closure** — all 5 sub-arcs closed (7.8.0 + 7.8.1 + 7.8.2 + 7.8.3 + 7.8.4). **THE §9 NETWORKING + MEMPOOL LAYER IS FEATURE-COMPLETE.** Cumulative metrics across Phase 7.8:

| Sub-arc | Surface | LOC delta | Pub-item delta |
|---|---|---|---|
| 7.8.0 | Wire-format types | +301 | +15 |
| 7.8.1 | libp2p integration | +416 | +13 |
| 7.8.2 | Anti-DoS + fee floors + rate limiting | +486 | +17 |
| 7.8.3 | Kademlia DHT + bootstrap | +49 | 0 |
| 7.8.4 | Mempool + propagation gating | +393 | +14 |
| **Total** | **§9 networking + mempool** | **+1,645** | **+59** |

Spec-level commitments shipped at Phase 7.8 closure:
- **§9.2.2 transport stack pinned**: QUIC primary + TCP fallback (Noise XX + Yamux) + DNS + gossipsub v1.1 + identify + Kademlia.
- **§9.3.1 wire-shape pinned**: `NetworkTransaction` with field order + 21-byte canonical encoding for a specific fixture.
- **§9.5.1 PoW submission-proofs**: Hashcash via `sha3_256_tagged(SUBMISSION_PROOF, ...)`. 1 new domain tag at Phase 7.8.2.
- **§9.5.2 per-byte fee floor** + **§9.5.3 token-bucket rate limiting** primitives.
- **§9.6 Kademlia DHT** with `/adamant/kad/1.0.0` protocol-namespace.
- **§9.7 priority-queue mempool** with eviction + TTL + anti-DoS gating.

3 new workspace dependencies (Phase 7.8.1): `libp2p =0.56.0` (with §9.2.2-pinned feature subset), `tokio =1.52.3`, `futures =0.3.31`. Per §14.4 Decision 4 Option A, all three are Category E networking-infrastructure tier — admitted to the bounded ecosystem without forking, since network-layer correctness is delivery (not state-transition correctness).

**Phase 7 progression**: **7.0 + 7.1 + 7.2 + 7.3 + 7.4 + 7.5 + 7.6 + 7.7 + 7.8 closed.** Sub-arcs remaining:

- **7.9** — light client + tier signal per §8.1.7 + §8.9 (recursive-proof verification interface; `SecurityTier` disclosure observability).
- **7.10** — slashing wiring + economics per §8.1.5 + §10 (equivocation evidence from `DagError::EquivocationDetected`; slashing transactions; §10 tokenomics flow into validator-stake state machine).
- **7.11** — end-to-end integration (all Phase 7 sub-systems wired together; multi-validator regression suite; §9.5.4 cryptographic-verification-before-propagation finally bridges §9 → §6).

**Phase 7.9 closure (commit `84863ad`)** — light-client observation layer per whitepaper §8.1.7 + §8.9. Ships the consensus-side surface a light client consumes to track chain state without holding the full state itself. Wraps existing `SecurityTier` (Phase 7.1) + `EpochNumber` (Phase 7.0) into observation-oriented APIs that wallets and explorers consume directly.

Phase 7.9 surface (new `adamant-consensus::light_client` module):

- **`STATE_COMMITMENT_BYTES` / `PROOF_COMMITMENT_BYTES = 32`** each (per §8.5.1 state commitment + §8.6 VRF input shape).
- **`StateCommitment` / `ProofCommitment`** — opaque 32-byte newtypes. Concrete derivation pinned at Phase 4 backfill / Phase 6.9b respectively.
- **`TierSignal { tier: Option<SecurityTier>, active_set_size, epoch }`** — the §8.1.7 tier disclosure wrapped with observation context. `tier` is `Option` so **dormant** (below-floor) is distinguishable from **Tier I** (weak but operational); per §8.7.1 wallets `SHOULD` display halt-state warnings on `is_dormant()`. Helper `meets_minimum(tier)` for the §8.1.7 "Use" pattern (applications gate features by minimum tier).
- **`EpochBoundary { epoch, active_set_size, state_commitment, proof_commitment }`** — the per-epoch artifact the consensus layer emits at each boundary. BCS-serialisable; observation-stable wire shape (NOT consensus-binding — the underlying recursive proof + state commitment carry the consensus weight, this wrapper is just the wire shape §9 ships them in).
- **`LightClientState`** — running state machine. `new` / `from_genesis` constructors; `advance(boundary)` consumes a new boundary with monotonic + no-gap checking; `tier_signal` / `state_commitment` / `proof_commitment` accessors expose the latest observation.
- **`LightClientError`** closed enum (`NonMonotonicEpoch` / `EpochGap`) + `Display` + `std::error::Error` + BCS round-trip.

Per §8.9 light clients observe EVERY epoch boundary; gaps are rejected (gap-boundary's recursive proof cannot be verified without intermediate proofs). Out-of-order observations are rejected. Two light clients receiving the same boundary sequence converge on identical state — the §8.9 convergence property pinned in tests.

**What Phase 7.9 does NOT ship (deferred to Phase 7.11)**:
- **Recursive-proof verification** against the previous boundary's accumulator. The verification primitive (`adamant_privacy::epoch_recursion::verify_envelope`) lives in `adamant-privacy`; wiring it through requires coupling `adamant-consensus` to the privacy crate, which crosses the §14 layering. Phase 7.11 end-to-end integration is the venue.
- **Claim verification** (account balance / transaction inclusion / object existence per §8.9). Depends on the Phase 4 state-commitment Merkle tree which is skeleton.

Phase 7.9 ships the **consumption-side data shapes** so downstream wallets + explorers + service nodes can consume the API surface now and verification wiring lands later without API churn.

28 new unit tests covering: byte-width pins; `StateCommitment` + `ProofCommitment` round-trips + BCS; `TierSignal` dormant-below-floor + Tier I at 7 + Tier II at 15 + Tier III at 30 + `meets_minimum` correctness + dormant-meets-nothing invariant + BCS; `EpochBoundary` new + `tier_signal` derivation + BCS; `LightClientState` new-is-empty + default + `from_genesis` + advance-from-empty-accepts-any + monotonic-succeeds + gap-errors + non-monotonic-errors + tier-updates-on-advance + commitments-track-latest + **determinism-convergence** (§8.9 convergence property); `LightClientError` display distinctness + `std::error::Error` + BCS.

Phase 7.9 metrics: `cargo test -p adamant-consensus --lib` reports 312 passing (284 from prior + 28 new). adamant-consensus LOC 5,702 → 6,186 (+484); pub items 233 → 260 (+27: `StateCommitment` + `ProofCommitment` + `TierSignal` + `EpochBoundary` + `LightClientState` + `LightClientError` + 2 byte-width constants + accessor methods on each). Workspace lib tests 2,858 → 2,886 (+28). All 10 Adamant-authored crates at 100% doc coverage. All gates green: clippy + fmt + strict audit + both resistant-proof guards. No spec amendment; no new domain tags; no new workspace dependencies.

**Phase 7.10 closure (commit `24ba7c7`)** — slashing wiring per whitepaper §8.1.5. Wires the on-chain slashing-evidence handlers + actual stake reduction on top of the Phase 7.0 `SlashOffence` enum + `slashing_penalty_basis_points` table. Per §8.1.5 the machinery is permissionless ("any party can submit evidence") and mechanical (no governance review).

Phase 7.10 surface (extended `adamant-consensus::slashing`):

- **`SlashingEvidence`** closed enum (4 variants matching the §8.1.5 offences): `Equivocation { vertex_a, vertex_b }`; `LivenessFailure { slot_id, validator_id, last_participation_epoch, current_epoch }`; `IncorrectThresholdDecryption`; `InvalidProof`. `offence()` + `validator_id()` accessors.
- **`SlashingError`** closed enum (7 variants) — `EquivocationAuthorMismatch` / `EquivocationRoundMismatch` / `EquivocationIdenticalVertices` / `UnknownAuthor` / `InvalidSignature` / `LivenessThresholdNotMet` / `LivenessSlotMismatch`. `Display` + `std::error::Error` + pairwise-distinct messages.
- **`verify_equivocation_evidence(vertex_a, vertex_b, pubkeys_resolver) -> Result<SlashOffence, SlashingError>`** — full cryptographic verification: same author, same round, distinct VertexIds, both BLS signatures verify under the author's pubkey.
- **`verify_liveness_failure_evidence(active_set, slot_id, validator_id, last_participation, current_epoch)`** — checks against `Slot::is_liveness_failed` (the consensus-layer ground truth).
- **`SlashingOutcome { remaining_stake, burned_amount, triggers_active_set_removal }`** — pure-function output.
- **`apply_slashing(stake, offence) -> SlashingOutcome`** — applies the §8.1.5 basis-points penalty. The `burned_amount` is **burned** (not redistributed) per §8.1.5.

**Invariant pinned in tests**: `remaining + burned == original` across all 4 offences. Plus pinned worked-examples on a 1,000 ADM bond: Equivocation → 1,000 ADM burned (100%); InvalidProof → 100 ADM (10%); IncorrectThresholdDecryption → 50 ADM (5%); LivenessFailure → 5 ADM (0.5%) + active-set removal.

**What 7.10 does NOT yet wire (deferred to Phase 7.11)**:
- The closure-based verifiers for `IncorrectThresholdDecryption` + `InvalidProof` (those cross the §14 layering into `adamant-crypto::threshold` + `adamant-privacy::epoch_recursion`).
- Production-side caller orchestration: detection (`DagError::EquivocationDetected` from Phase 7.7a surfaces equivocation; `ActiveSet::liveness_failed_at` surfaces liveness failures) → evidence construction → slashing-transaction submission → execution-layer state mutation.

21 new unit tests covering: SlashingEvidence offence dispatch + BCS round-trip; verify_equivocation genuine + 5 rejection paths (author/round/identical/unknown/forged-sig); verify_liveness threshold-met / not-met / slot-mismatch; apply_slashing per-offence worked examples + remaining-plus-burned invariant + zero-stake yields zero; SlashingOutcome BCS round-trip; SlashingError display + std::error::Error.

Phase 7.10 metrics: `cargo test -p adamant-consensus --lib` reports 333 passing (312 from prior + 21 new). adamant-consensus pub items 260 → 268 (+8: `SlashingEvidence` + `SlashingError` + `SlashingOutcome` + `verify_equivocation_evidence` + `verify_liveness_failure_evidence` + `apply_slashing`). Workspace lib tests 2,886 → 2,906 (+20). All gates green.

**Next sub-arc — Phase 7.11**: end-to-end integration. The §9 → §6 cross-layer bridge for cryptographic verification before propagation (§9.5.4); the §8.5 recursive-proof verification wiring through to light clients (Phase 7.9 deferred surface); the slashing pipeline orchestration (detection → evidence → submission → execution); multi-validator regression suite spinning up the full pipeline. Genuine multi-session sub-arc when fully scoped — Phase 7.11 below ships the integration touchpoints reachable without crossing into Phase 4 backfill / Phase 5 finish work.

**Phase 6 hygiene follow-up (commit `0cc2848`)** — `adamant-halo2` ECC chip tests gated behind `expensive-tests` feature. Four forked-upstream tests (`ecc::chip::constants::tests::lagrange_coeffs`, `zs_and_us`, `ecc::chip::mul_fixed::short::tests::invalid_magnitude_sign`, `ecc::tests::ecc_chip`) reconstruct full fixed-base Lagrange-coefficient tables and run MockProver at k=13 across the ECC chip surface; debug-mode runtime exceeds 60s each and was blocking workspace test runs at 20+ minutes after Phase 6.8b.3 vendored them in byte-faithfully. New `expensive-tests = []` feature on `adamant-halo2` (mirrors the `adamant-privacy` posture introduced at Phase 6.8b.5); each test carries `#[cfg_attr(not(feature = "expensive-tests"), ignore = "...")]`. Empirical result: `cargo test -p adamant-halo2 --lib` reports 58 passed + 4 ignored in 3.6s (down from 20+ min hang); full workspace `cargo test` completes cleanly. Tests still compile so the upstream byte-faithful posture and refactor-checking are preserved — only the runtime ignore flag flips. Test-time only; no production-binary impact. Resistant-proof guards continue to pass; workspace audit strict mode passes; doc coverage remains 100% across 9 Adamant-authored crates.

---

**Phase**: 5 — execution VM. Phases 1–4 (crypto, types, account, state structural+lifecycle) complete. Phase 5 deliverables shipped: first (Transaction format + TxHash), second (AdamantBytecode extension types), third (bytecode wire encoding, commit `0d88e8e`), fourth (Sui-Move bytecode-verifier vendoring with Batches 1+2, commit `e6ca254`), and Wave 3a of the fifth deliverable (validator scaffold + Rules 1, 4, 5 + canonical-encoding round-trip, commit `a1789cc`). Phase 5/5a (Adamant-native deserializer + serializer + validator wrapper integration + cross-validation infrastructure) closed at commit `d7fe882` across 5 sub-deliverable commits (`12b65b0`, `73b1986`, `e38e31f`, `cde5046`, `d7fe882`), ~5,500 LOC total. Phase 5/5b.1a (foundation fork of constants + readers + AbilitySet + Identifier into a new `adamant-bytecode-format` crate) closed at commit `a7a06ab`, ~2,413 LOC. Phase 5/5b.1b (25 type-definition fork + index machinery + SignatureToken + full inherited Bytecode enum + CodeUnit + FunctionDefinition + U256 + Metadata + AddressIdentifierPool reusing `adamant_types::Address`) closed at commit `874e701`, ~4,900 LOC. Phase 5/5b.2 closed at `4b03f14`. **Phase 5/5b.3 closed (BoundsChecker + DuplicationChecker + SignatureChecker forks + pipeline integration; all three large module-level passes feature-complete and wired into `verify_module` step-3 batch). Phase 5/5b sub-arcs remaining: 5/5b.4 (per-function passes infrastructure + Rule 3), 5/5b.5 (type-safety/reference-safety per-function passes + Rules 6, 7 + final integration + Sui-verifier bridge tear-out).** Phase 5/5b.3 closure: 9 commits on origin (C-1.1 at `f9050dd`; C-1.2 at `a8e975a`; C-1.3 at `3fe1582`; C-1.4a at `25dfabe`; C-1.4b at `d2a0308`; C-2 at `60d0a53`; C-3 at `34e80de`; C-4 at `fa79976`; C-5 closure commit lands with this state-bump). Workspace test count progression across Phase 5/5b.3: **1035 → 1259 (+224)**. Three large module-level passes ported Adamant-native at C-1 / C-2 / C-3; pipeline integration at C-4 expands `verify_module` step-3 batch from 8 → 11 passes total. Eleven-pass invocation order has two precedence-driven exceptions: bounds_checker first (cross-pass-precedence; `IndexOutOfBounds` reaches first against limits' count overflow); signature_checker before recursive_data_def (cross-pass-pipeline-dependency; signature_checker's `RefAsFieldType` rejection is what makes recursive_data_def's `unreachable!` for refs-in-field-types defensible). 17 new typed-error variants on `AdamantValidationError` across Phase 5/5b.3 (C-1.1: `NoModuleHandles`, `IndexOutOfBounds`, `NumberOfTypeArgumentsMismatch`; C-1.4a: `TooManyLocals`; C-1.4b: `CodeIndexOutOfBounds`, `InvalidEnumSwitch`; C-2: `DuplicateElement`, `ZeroSizedStruct`, `ZeroSizedEnum`, `InvalidModuleHandle`, `DuplicateAcquiresAnnotation`, `UnimplementedHandle`; C-3: `InvalidSignatureToken`, `TypeArgumentsArityMismatch`, `ConstraintNotSatisfied`, `InvalidPhantomTypeParamPosition`, `VecOpExpectedSingleTypeArgument`). Two new public closed enums: `DefKind` (`Struct | Enum | Function`; C-2), `InvalidSignatureReason` (`RefInsideContainer | RefAsFieldType`; C-3). Cross-pass eager-error precedence list grows 2 → 3 instances (Q2 Claim 3: duplication_checker `DuplicateElement(Signature)` wins over signature_checker `InvalidSignatureToken` on overlapping malformed-and-duplicate-signature input — first **different-variant precedence claim shape**, distinct from existing 2 shared-variant claims). Six methodology accumulation streams formalized at C-5 closure: **(1) cross-pass-pipeline-dependency sub-pattern** (NEW; 6th sub-pattern of structural-impossibility-checks); **(2) spec-layer-pinning impossibility sub-pattern** (NEW; 5th sub-pattern); **(3) Adamant-extension treatment in module-level passes** (NEW pattern; rule-of-three threshold met across C-1.4b/C-2/C-3 with 3 sub-shapes); **(4) different-variant precedence claim shape** (NEW; C-4); **(5) variant-vs-test mapping audit principle** (NEW canonical implementation-gate discipline; C-3); **(6) deferred-to-§7 methodology footnote** (NEW; C-1.4b CircuitId pass-through). Plus **(7) commit-message running-total drift discipline** registered at C-5 after the empirical-grep audit found a "20 → 37" baseline drift inherited from B-6's CLAUDE.md state-bump (corrigendum recorded in `crates/adamant-vm/src/validator/module_pass/PROVENANCE.md`). **Spec-pipeline-impossibility-pending-port sub-pattern's 2 instances retired-via-fulfillment** at C-4 when DuplicationChecker + SignatureChecker landed; sub-pattern remains documented for future pending-port deferrals. Phase 5/5 was re-scoped three times: first during the Wave 3b proposal investigation (Phase 5/5 prerequisite for Adamant-native deserializer with Sui-projection inserted ahead of Waves 3b–3d, per amendment `61cec44`); then during the Phase 5/5 implementation proposal investigation when empirical reading of Sui's per-instruction verifier passes surfaced the Nop-projection breakage (re-amendment `0de50d8` to fully-Adamant-native architecture); then during the Phase 5/5b restructured-proposal review when the architectural commitment was extended from "fully Adamant-native verifier" to "fully Adamant-native deploy-time and runtime, resistant-proof against upstream Sui changes" (amendment `19d744b`, merged regen `0651e2f`, twenty-first spec-first instance `6084c32`). Phase 5/5 collapsed from 4 sub-deliverables to 3: 5/5a (closed at `d7fe882`); 5/5b full Adamant-native verifier covering both module-level and per-function passes plus Rules 2, 3, 6, 7, split into 6 sub-arcs (5/5b.1a foundation fork — closed at `a7a06ab`; 5/5b.1b 25 type-definition fork — closed at `874e701`; **5/5b.2** small/medium module-level passes + Rule 2 + privacy_metadata_structure + pipeline integration — closed at `4b03f14`; **5/5b.3** large module-level passes + pipeline integration of all 11 step-3 passes — closed at C-5 with this state-bump; 5/5b.4 per-function passes infrastructure + Rule 3; 5/5b.5 type-safety + reference-safety per-function passes + Rules 6, 7 + final pipeline integration with Sui-verifier bridge fully removed); 5/5c cross-validation infrastructure formalization (T0+T1+T2 tier coverage; T3 real-world corpus deferred to pre-mainnet hardening). **Phase 5/5b: 4 of 6 sub-arcs done.** Phase 5/5b LOC estimate ~10,600-14,950 LOC; total Phase 5/5 ~19,000-27,000 LOC against the original ~5,500-9,000 estimate (3-4x). 5/5b.1a and 5/5b.1b combined ~7,313 LOC actual; Phase 5/5b.2 cumulative ~13,500-14,500 LOC; **Phase 5/5b.3 cumulative ~7,927 LOC actual** across the 9 commits (C-1: ~4,547 LOC across 5 sub-checkpoints; C-2: ~1,665; C-3: ~1,466; C-4: ~249; C-5: documentation-only ~600-900 LOC docs). C-1 sub-arc adapted from planned 4 sub-checkpoints to 5 at the C-1.4 plan-gate per the empirical-complexity-drives-sub-checkpoint-shape pattern; eight-instance LOC-vs-estimate calibration cycle stable at ±25-30% midpoint variance band. Five plan-gate resolution shapes empirically observed across Phase 5/5b.3: plan-was-correct (C-1.2 negatives count); plan-was-ambiguous (C-1.3 preservation pin count); plan-was-conservative (C-1.4a/C-2/C-3/C-4 lower-bound landings); plan-overshot-on-helper-signature (C-1.4b 6→3 params); plan-incremental-disposition-resolved-empirically (C-3 InvalidSignatureReason 2-variant resolution). Waves 3b–3d (Rules 3 and 7 with shared call-graph infrastructure; Rules 2 and 6; Rule 8's gas-bound no-op test) subsumed into Phase 5/5b's per-function-pass sub-arcs (Rules 3, 6, 7 land in 5/5b.4 and 5/5b.5). **Phase 5/5b.4 closed (full per-function pipeline + Rule 3; closure batch lands D-7a Layer B backfill + D-7b documentation closure).** Phase 5/5b.4 ran across **14 commits on origin** spanning 9 logical sub-arcs: D-1 (CFG + AbstractInterpreter framework — foundation-then-producer arc split into D-1a `57b886e` + D-1b `5a56603` + mid-arc state-bump `62a1987`); D-2 (control-flow validation `4bc6eaf`); D-3 (operand-stack discipline `0ceae97`); D-4 (locals safety + acquires `603edf7`); D-5a (type-safety pass — split into D-5a.0 `824d7bc` + D-5a.1.a `952ad69` + D-5a.1.b `6e34f47` per pre-arc-split sub-shape 2); D-5b (reference safety + borrow-graph — split into D-5b.1 `47e1d7a` + D-5b.2 `23788ab`); D-5c (Rule 3 privacy-consistency call-graph walker `5926c7a`); D-6 (pipeline integration `a74f4c8`); D-7 (closure — split into D-7a Layer B backfill `31a22d0` + D-7b documentation closure landing with this state-bump). Workspace test count progression empirically verified at D-7 plan-gate: **1259 → 1532 (+273)** across the phase. AdamantValidationError progression: **50 → 64 (+14)** typed variants. **Public closed enums grew 5 → 9 (+4):** `IrreducibleReason` (D-2), `TypeMismatchReason` (D-5a.0), `BorrowViolationReason` (D-5b.2), `PrivacyConsistencyViolationReason` (D-5c). Verification gate count grows 8 → 11 (9th D-1 plan-gate via §6.2.1.8 line 526; 10th D-3 plan-gate via §6.2.1.4 per-extension stack-effects; 11th D-5c plan-gate via §6.2.1.6 spec binding). 5 per-function passes ported Adamant-native + 1 Adamant-specific rule (Rule 3) + per-function-pass infrastructure (CFG + AbstractInterpreter + AbstractStack + BorrowGraph). Helper extracted at D-7a: `function_pass/test_helpers.rs` with 6 helpers (extract-at-N=3 sub-shape β of the helper-extraction discipline; module_pass extract-at-N=2 at B-2.2 is sub-shape α, chronological naming preserved per D-7b plan-gate). **Methodology streams formalized at D-7b** (full enumeration in PROVENANCE.md "Phase 5/5b.4 closure — methodology accumulation streams" section): rule-of-three thresholds met across the phase for sub-shape 2 (pre-arc-split: C-1.4/D-1/D-5a/D-5b — 4 instances; sub-shape 2 well-established), sub-shape 3 (Adamant-extension treatment pass-through: C-3/D-1a/D-2/D-4 — 4 instances), shielding-vs-runtime canonical pattern (D-3/D-5a.1.b/D-5b.2 cross-pass consistency on Categories C+D), spec-text-DIRECTS-shared-helper canonical principle (D-5a.1.b/D-5b.2/D-5c), verbatim-survey-at-plan-gate-prevents-scope-error pattern (D-3/D-5b/D-5c), Open Layer B gaps deferred to pre-mainnet hardening (C-5 SuiVerifier / D-5b.2 BorrowViolationReason 6-of-13 / D-7a st_loc_destroys_non_drop). Plus 6 new patterns at sub-rule-of-three threshold registered at D-7b for forward-tracking: Sui-public-API-shape-constrains-parity-helper sub-pattern (1st instance D-7a), helper-extraction discipline canonical with 2 sub-shapes (α=N=2 module_pass / β=N=3 function_pass), sub-shape 4 of structural-impossibility-checks (`expect()`-three-anchor; 1st instance D-5a.1.a), hoisted-enum-for-clippy-items-after-statements (1st instance D-1a `Exploration`), upstream-consolidates-undershoot calibration (1st instance D-1b AbstractInterpreter consolidation), bridge-as-soundness-test-infrastructure framing + bridge-redundancy-validation tests as Layer B alternative (1st instances D-6; bounded in time — resolve at 5/5b.5 bridge tear-out). **Cross-pass eager-error precedence list stays at 3 instances** (no new precedence claims at D-6; Q4 Claim 1 BoundsChecker-vs-limits retired-via-empirical-absence per D-6 plan-gate disposition; new sub-pattern: 4th-precedence-claim-retired-via-empirical-absence registered at D-7b). **Commit-message running-total drift discipline operating at full effectiveness — 2nd instance** caught at D-7 plan-gate (D-3-to-D-4 baseline error: D-3 didn't claim workspace count, D-4 inherited a wrong baseline 1328 vs empirical 1362, drift propagated through 8 subsequent commits with correct deltas on wrong baseline; D-7b corrigendum parallel to B-6 in `crates/adamant-vm/src/validator/module_pass/PROVENANCE.md`). **Phase 5/5b: 5 of 6 sub-arcs done.** Phase 5/5b sub-arc remaining: **5/5b.5** (Sui-verifier bridge tear-out + 13 vendored Sui-Move crate removal from production-binary deps + Rules 6, 7 implementation + Rule 8 runtime gas-bound no-op test + cross-module Rule 3 enforcement at deployment-validator wiring + `tests/no_sui_in_production_deps.rs` build-system independence check). **Phase 5/5b.5 closed at E-7; Phase 5/5b CLOSED.** Phase 5/5b.5 ran across **9 commits on origin** spanning 7 logical sub-arcs: E-1 (Sui-bridge tear-out — split into E-1a production-code refactor `0b774a3` + E-1b Cargo.toml restructure + build-system check `4fb4114`); E-2 (cross-module Rule 3 — split into E-2a foundation `8e4d814` + E-2b walker `4e5bbab`); E-3 (Rule 6 no dynamic dispatch `922d4bd`); E-4 (Rule 7 privacy circuit `f7e6189`); E-5 (Rule 8 architectural-position pin `4764be3`); E-6 (Open Layer B gaps closure `eb766b8`); E-7 (closure batch + Phase 5/5b cumulative closure landing with this state-bump). Workspace test count progression empirically verified at E-7 session-resume + impl-gate: **1532 → 1585 (+53)** across the phase. AdamantValidationError progression: **64 → 66 (+2 net; -1 SuiVerifier removed at E-1a + 3 added: CrossModulePrivacyConsistencyViolation E-2a / DynamicDispatchViolation E-3 / PrivacyCircuitContextViolation E-4)**. Public closed enums: **9 → 11 (+2):** `DynamicDispatchViolationReason` (E-3), `PrivacyCircuitContextViolationReason` (E-4). Verification gate count grows 11 → 15 (12th E-2 plan-gate via §6.2.1.6 line 477 cross-module Rule 3; 13th E-3 plan-gate via §6.2.1.6 Rule 6 + line 485; 14th E-4 plan-gate via §6.2.1.6 Rule 7; 15th E-5 plan-gate via §6.2.1.6 Rule 8 + amendment 804d9db). **Production-side Sui dependency complete elimination at E-1.** adamant-vm production-binary dependency graph contains zero `move-*` crates per the §6.2.1.8 resistant-proof posture; build-system independence check at `tests/no_sui_in_production_deps.rs` mechanically enforces the architectural commitment via `cargo metadata`'s resolve-graph walk. **Adamant-native verifier feature-completeness at Phase 5/5b closure:** 11 module-level passes wired at step 3 (Phase 5/5b.2 + 5/5b.3); 5 per-function passes wired at step 4 (Phase 5/5b.4); 6 module-level Adamant rules wired at step 5 (Rules 1, 2, 3 single-module, 4, 6, 7); Rule 5 enforced at step 1 (parse-time inside adamant_deserialize); Rule 8 architectural-position pin (no step-5 invocation; runtime carries binding); cross-module Rule 3 walker at `validator/cross_module/` (E-2; production caller awaits Phase 5/6 AVM runtime stdlib). **Methodology framework cumulative landmarks formalized at E-7** (full enumeration in PROVENANCE.md "Phase 5/5b cumulative closure" section): cross-cutting canonical principles operating beyond rule-of-three threshold (verbatim-survey-at-plan-gate-prevents-scope-error 8 instances; running-total drift discipline 4 instances after 4th instance caught at E-7 session-resume — adamant-vm lib-count drift originating at E-1b propagated through 7 subsequent commits; spec-text-DIRECTS-shared-helper canonical principle 5 instances = 3 cross-pass-distinct + 2 cross-scope-reuse; eager-error first-failure-wins 6+ instances; variant-vs-test mapping audit principle 3 sub-shapes + 2 closure shapes with 66/66 variants covered at E-7 closure and 0 outstanding audit gaps). **25 new methodology streams (sections 30-54 in PROVENANCE.md) registered at E-7 closure**, including: architectural-commitment-mechanically-guarded (E-1b 1st instance — constitutionally meaningful posture parallel to "no foundation, no admin keys" commitments); upstream-constant-duplication-with-test-time-parity-pin (E-1b 1st instance) + spec-text-pinned-constant-with-Adamant-native-ownership (E-3 1st instance) — Adamant-native-constants discipline now has two empirical sub-classifications; same-rule-different-scope-shares-sub-reason-enum (E-2 1st instance); helper-extraction discipline three sub-shapes (α=N=2 module_pass + β=N=3 function_pass + γ=N=1-anticipating cross_module); rule-composition-for-cross-module-coverage (E-4 1st instance — Rule 7 cross-module surface bound transitively through Rule 3 cross-module + Rule 7 single-module composition); architectural-position-pin-for-explicit-non-enforcement (E-5 1st instance — Rule 8 verifier-level no-op per amendment 804d9db); code-and-PROVENANCE.md registration sub-shape (2 instances at E-4 + E-5); Open Layer B gaps closure two sub-shapes (gap-source-removal at E-1a + gap-fill at E-6); variant-count discipline four sub-shapes (add / tear-out / no-op / coverage-expansion); cumulative-phase-closure-on-final-sub-arc two shapes (single-phase D-7b + cumulative-multi-phase E-7); scope-expansion-history-as-canonical-record sub-pattern (D-7 + E-7 PROVENANCE.md scope expansions); corrigendum-as-canonical-correction-shape sub-pattern (rule-of-three threshold MET at E-7 with B-6 + D-3-to-D-4 + E-1b corrigenda); pattern-cluster meta-observation (multiple methodology areas with empirical sub-classifications stable at scale); methodology framework efficiency curve across phases (cost-of-discipline decreases as discipline internalizes). **Phase 5/5b cumulative metrics empirically verified:** workspace 821 → 1585 (+764 across the entire Phase 5/5b workstream); AdamantValidationError 7 → 66 (+59 net); public closed enums 0 → 11; deliberate-Adamant-decision instances 11; verification gates 8 (pre-Phase-5/5b.4) + 7 (Phase 5/5b: 3 at 5/5b.4 + 4 at 5/5b.5) = 15. **Open Layer B gaps at Phase 5/5b closure: 0** (all gaps closed; SuiVerifier audit gap retired-via-fulfillment at E-1a; BorrowViolationReason 7-of-13 sub-reason gap and st_loc_destroys_non_drop Layer B gap filled at E-6). **Phase 5/5b CLOSED. Phase 5/5c CLOSED at F-3 commit. Phase 5/5 CLOSED at F-3 commit.** Phase 5/5c (cross-validation infrastructure formalization) ran across 3 sub-arcs: F-1 (tier framework formalization — T0+T1+T2+T3 tier discipline registered as NEW pattern category; T0 closed at F-1 with 26 of 26 passes/rules/surfaces having pos+neg coverage or architectural-position-pin shape; T1 closed at F-1 with 66 of 66 `AdamantValidationError` variants having explicit negative-test coverage; T2 framework established with implementation gaps registered for D-5a + D-5b Layer B parity backfill; T3 deferred to pre-mainnet hardening per Q5 disposition); F-2 (D-5a + D-5b Layer B parity backfill — 8 new Layer B parity tests at `function_pass/type_safety.rs::tests::cross_validation` + 8 at `function_pass/reference_safety/pass.rs::tests::cross_validation`; Sui-public-API-shape-constrains-parity-helper sub-pattern reaches 2nd per-sub-arc instance via composite-pipeline parity through `code_unit_verifier::verify_module`; Layer-B-coverage-shape sub-classifications NEW at F-2 with companion-coverage and retroactive-promotion sub-shapes); F-3 (T2 audit closure with directly-targeted + T3-deferred two-table shape per Q5 plan-gate-to-impl-gate empirical refinement — Q5's three-table shape proposal empirically refined to two-table at impl-gate when the indirect-coverage class proved largely empty; ~25 of ~46-48 in-scope Sui StatusCodes directly-targeted via 30 dedicated Adamant Layer B parity rejection tests; ~21-23 T3-deferred per pre-mainnet hardening real-world corpus venue; Phase 5/5c closure documentation; Phase 5/5 cumulative closure documentation). 16 new methodology streams registered at F-3 closure (entries 52-67 in PROVENANCE.md; the final 2 — fmt-drift discipline at entry 66 and commit-message-and-PROVENANCE.md registration sub-shape at entry 67 — register at the F-3 verification gate boundary when 108 fmt diffs across 13 Rust files are surfaced as pre-existing drift inherited from HEAD commit `62c2a76`; F-3 commits docs-only; an atomic `cargo fmt --all` mechanical-cleanup sibling commit immediately follows per refined disposition c). **8 cross-cutting canonical principles operating beyond rule-of-three threshold at Phase 5/5 closure** (up from 5 at Phase 5/5b closure; +3 across Phase 5/5c): verbatim-survey-at-plan-gate-prevents-scope-error pattern (11 instances post-F-3); running-total drift discipline (4 instances at F-3 closure with NEW clean-self-application shape at F-2 → F-3 session-resume); spec-text-DIRECTS-shared-helper canonical principle (5 instances); eager-error first-failure-wins (6+ instances); variant-vs-test mapping audit principle (66/66 variants covered with 0 outstanding gaps); documentation-batch LOC overshoot pattern (3 instances at F-1 closure; rule-of-three threshold MET); honest-scope-flagging at session-pacing level (5 invocations at F-3 closure); scope-expansion-history-as-canonical-record sub-pattern (3 instances at F-3; rule-of-three threshold MET — D-7 + E-7 + F-3 PROVENANCE.md scope expansions). 3rd canonical audit-table sub-shape lands at F-3 (per-error-mode T2 audit; per-variant + per-pass + per-error-mode = 3 sub-shapes registered). Cumulative-multi-phase closure pattern reaches 2nd instance at F-3 (1st: E-7 5/5b.5 + 5/5b cumulative across 6 sub-arcs within 1 phase; 2nd: F-3 5/5c + 5/5 cumulative across 9 sub-arcs spanning 3 sub-phases). Workspace test count progression across Phase 5/5c: **1585 → 1601 (+16; F-2 only — F-1 + F-3 are doc-only sub-arcs)**. AdamantValidationError unchanged at 66 typed variants across Phase 5/5c. Public closed enums unchanged at 11 across Phase 5/5c. Verification gates unchanged at 15 (Phase 5/5c is doc-only; no spec re-paste). **Phase 5/5 cumulative metrics empirically verified at F-3 closure:** workspace 821 (pre-Phase-5/5b) → 1601 (post-Phase-5/5; +780 across Phase 5/5b + 5/5c combined); AdamantValidationError 7 → 66 (+59 net); public closed enums 0 → 11; deliberate-Adamant-decision instances 11+; verification gates 15 total. **Major project milestone reached: Adamant has a feature-complete, production-side Sui-free, cross-validated bytecode-verifier with formalized cross-validation tier discipline.** Future workstream: Phase 5/6 (AVM runtime per whitepaper §6.3) — includes AVM runtime stdlib `adamant::module::deploy` invoking `validator::verify_module` per-module + cross-module Rule 3 walker per the ModuleResolver trait abstraction; U256 arithmetic implementation choice per Phase 5/5b.1b Q5 deferral; per-instruction gas-cost calibration; pre-mainnet hardening venue items (Adamant-native structural-limits calibration; T3 real-world corpus collection mechanism; ~21-23 T3-deferred Sui StatusCode coverage expansion).

**Specification**: complete v0.1 draft, twenty-one spec-first verification instances landed and recorded in CONTRIBUTING.md. The most recent batch (sixteenth–nineteenth) resolved the §6.2.1 deserializer / verifier-architecture gap surfaced during the Wave 3b proposal investigation (amendment `61cec44`, merged regen `1109bab`, CONTRIBUTING.md instances `fcce531`). The twentieth instance resolved the Nop-projection breakage surfaced during the Phase 5/5 implementation proposal investigation (re-amendment `0de50d8`, merged regen `2401227`, CONTRIBUTING.md instance `3b65686`). The twenty-first instance resolved the resistant-proof posture extension during the Phase 5/5b restructured-proposal review: §6.2.1.8's "fully Adamant-native verifier" commitment extended to "fully Adamant-native deploy-time and runtime"; production binary's dependency graph cannot include vendored Sui crates; vendor refresh is a development-time signal, not a consensus event (amendment `19d744b`, merged regen `0651e2f`, CONTRIBUTING.md instance `6084c32`). The §10/§11 launch model was rewritten in May 2026 to use a 100,000,000 ADM genesis pool with burn-to-mint and validator-reward acquisition paths, replacing the prior pure burn-launch mechanism. The design proposal lives at `/whitepaper/proposals/genesis-pool-mechanism.md` and records the deliberation history; the whitepaper amendment lives in §10 and §11.

**Code**: 20 workspace members at present. 7 Adamant-authored crates (`adamant-account`, `adamant-bytecode-format`, `adamant-crypto`, `adamant-crypto-blst-extra`, `adamant-state`, `adamant-types`, `adamant-vm`) plus 13 vendored Sui-Move crates at tag `mainnet-v1.66.2` — Batch 1 (`move-binary-format`, `move-core-types`, `enum-compat-util`, `move-proc-macros`, `move-abstract-interpreter`) and Batch 2 (`move-bytecode-verifier`, `move-borrow-graph`, `move-bytecode-verifier-meter`, `move-vm-config`, `move-abstract-stack`, `move-regex-borrow-graph`, `move-command-line-common`, `move-symbol-pool`). The 13 vendored Sui-Move crates are test-only dev-dependencies of the production-binary target as of Phase 5/5b.5 E-1; the build-system independence check at `tests/no_sui_in_production_deps.rs` walks the resolved dependency tree via `cargo metadata` and asserts no `move-*` crate appears in the production-target dependency graph. **1601 tests passing across the workspace at Phase 5/5 closure** (1585 at Phase 5/5b closure + 16 across Phase 5/5c F-2 D-5a + D-5b Layer B parity backfill; F-1 + F-3 are doc-only sub-arcs with 0 test delta). adamant-vm lib test count at Phase 5/5 closure: 898 (Phase 5/5b lib closure + Phase 5/5c F-2 backfill). **1532 tests passing across the workspace at Phase 5/5b.4 closure** (1259 at Phase 5/5b.3 closure + 273 across D-1a/D-1b/D-2/D-3/D-4/D-5a/D-5b/D-5c/D-6/D-7a). Workspace test count progression across Phase 5/5b.4: **1259 → 1532 (+273)** (empirically verified at D-7 plan-gate; corrects the inherited-baseline-on-wrong-baseline arithmetic from D-4 → D-6 commit messages — see "Corrigendum: D-3-to-D-4 baseline error" in `crates/adamant-vm/src/validator/module_pass/PROVENANCE.md`). Test breakdown at Phase 5/5b.4 closure: `adamant-bytecode-format` 96 lib unit tests + 55 cross-validation tests (unchanged through Phase 5/5b.4); `adamant-vm` lib test count 588 → 830 (+242) across Phase 5/5b.4. Phase 5/5b.4 per-sub-arc test additions across `validator/function_pass/`: D-1a (+18 CFG construction); D-1b (+13 AI framework with synthetic SawPop domain); D-2 (+32 control-flow); D-3 (+36 stack_usage); D-4 (+23 locals_safety); D-5a (+53 type-safety across .0/.1.a/.1.b); D-5b (+47 reference-safety + borrow-graph across .1/.2); D-5c (+15 Rule 3 privacy-consistency); D-6 (+6 integration + bridge-redundancy validation); D-7a (+26 Layer B cross-validation across control_flow / stack_usage / locals_safety). **Production-dependency posture at Phase 5/5b.4 closure:** `petgraph 0.8.x` remains the only non-Sui-vendor-derived production dep on `adamant-vm` (added at B-3.2; no new external production deps across all of Phase 5/5b.4 per the seven-criterion external-production-dep audit template). The transitional Sui-verifier bridge in `validator/mod.rs::verify_module` is retained behind `if !module.contains_adamant_extensions()` for inherited-subset modules through Phase 5/5b.4; tears out at 5/5b.5 alongside the production-target dependency-tree independence check. **Bridge serves dual roles at Phase 5/5b.4 closure:** defense-in-depth on inherited-subset modules AND soundness-test infrastructure for cross-pass-pipeline-dependency drift detection (D-6 framing); D-6 integration tests #5 + #6 assert bridge-redundancy via composite-level Layer B coverage. Per-pass Layer B coverage backfilled at D-7a for D-2/D-3/D-4 (~26 parity tests); D-5a/D-5b/D-5c had no inline parity tests per D-7a empirical-grep retrofit-need check (Sui's per-pass entries `pub(crate)`-bounded; Adamant adapts to composite-pipeline parity via `code_unit_verifier::verify_module` per the new Sui-public-API-shape-constrains-parity-helper sub-pattern registered at D-7b). **`AdamantValidationError` carries 64 typed variants at Phase 5/5b.4 closure** (empirically grep-confirmed; pre-Phase-5/5b.4 baseline was 50; Phase 5/5b.4 added 14). **9 public closed enums** at Phase 5/5b.4 closure: `MalformedConstantReason` (B-2.1), `FieldOwnerKind` (B-2.3), `HandleKind` (B-3.1), `DefKind` (C-2), `InvalidSignatureReason` (C-3), `IrreducibleReason` (D-2), `TypeMismatchReason` (D-5a.0), `BorrowViolationReason` (D-5b.2), `PrivacyConsistencyViolationReason` (D-5c) — all re-exported via `validator/mod.rs`. **6 helpers extracted at D-7a** (function_pass test_helpers): `to_sui`, `sui_config_from`, `assert_function_pass_parity` (PartialVMResult), `assert_function_pass_parity_vm` (VMResult), `run_adamant_pipeline`, `run_sui_code_unit_verifier`. **Variant-vs-test mapping audit appendix added at D-7b** for the 14 new Phase 5/5b.4 variants — all 14 have explicit negative-test coverage. Combined audit state at D-7b closure: **63 of 64 variants have explicit negative test coverage**; 1 gap is the `SuiVerifier` transitional-bridge variant (registered at C-5; deferred to natural resolution at 5/5b.5 bridge tear-out). **11 deliberate-Adamant-decision instances** at Phase 5/5b.4 closure (1 from 5/5b.2; 2 from 5/5b.3; 8 across 5/5b.4) — full enumeration in `crates/adamant-vm/src/validator/module_pass/PROVENANCE.md` "Deliberate-Adamant-decision pattern" section.

**Vendoring posture**: vendored Sui code stays byte-faithful, with documented doc-marker patches enumerated in each crate's `PROVENANCE.md`. Vendored Sui crates' role pivoted twice: first with the §6.2.1.8 re-amendment at commit `0de50d8` from "deploy-time hot path via Nop-projection" to "test-time reference implementation for the inherited subset's semantics"; then with the §6.2.1 + §6.2.1.8 resistant-proof amendment at commit `19d744b` from "test-time reference implementation" to **test-only cross-validation reference, with zero presence in the production binary's dependency graph**. The second pivot extended the architectural commitment from "Sui doesn't run on the deploy-time hot path" to "Sui doesn't run anywhere in production builds — Adamant runs entirely independently of Sui's codebase at deploy-time and runtime, with vendored Sui crates exercised exclusively at test time for cross-validation parity on the inherited Sui-base subset." Adamant provides its own deserializer, serializer, type definitions, constants, helper utilities, and verifier (module-level + per-function passes) covering the full Adamant superset. Type-definition independence (Option II fork into the new `adamant-bytecode-format` crate) landed across two commits: 5/5b.1a (foundation primitives — constants, readers, AbilitySet, Identifier) at `a7a06ab`; 5/5b.1b (the 25 reused parallel-struct neighbour types, index machinery, SignatureToken, the full inherited Bytecode enum, CodeUnit, FunctionDefinition, U256 thin newtype, Metadata, AddressIdentifierPool reusing `adamant_types::Address`) at `874e701`. After 5/5b.1b, adamant-vm's production paths consume Adamant-owned bytecode-format types end-to-end. The transitional Sui-validator wrapper bridge in `validator/mod.rs` retains a Sui-side `CompiledModule` import for cross-validation purposes; that bridge — and the remaining `move-*` production deps in adamant-vm — is removed in Phase 5/5b.5. Vendored Sui crates remain at `mainnet-v1.66.2` and are exercised by Phase 5/5c's cross-validation infrastructure to confirm Adamant's verifier produces identical accept/reject decisions to Sui's verifier on pure-Sui modules. The first pivot was driven by empirical infeasibility of the Nop-projection mechanism (3 of 4 per-function Sui passes fail on Nop-substituted Adamant modules; full enumeration in CONTRIBUTING.md's twentieth instance), genesis-fixed posture (verifier accept/reject is consensus-binding and cannot drift with Sui upstream), and audit surface. The second pivot was driven by Adamant's resistant-proof posture: the protocol must work fully independently of Sui's codebase so that upstream Sui changes, shutdowns, vulnerabilities, or governance shifts cannot affect Adamant's deploy-time accept/reject decisions or runtime behaviour. Wire encoding implementation is Option II (re-implement instruction-level serialization in `adamant-vm`) rather than Option I (patch vendored Sui to expose internals) — this preserves the byte-faithfulness audit anchor; Phase 5/5b extends the same Option II posture to the module-level and verifier layers via the `adamant-bytecode-format` fork.

**Architectural decisions on record**: (1) §6.2.1.6 Rule 5's enforcement point shifted from "Sui's verifier with `deprecate_global_storage_ops = true`" to "Sui's deserializer with `deprecate_global_storage_ops = true`" — empirical investigation surfaced that Sui's `BoundsChecker` treats deprecated variants as a `safe_assert!` invariant (panics in debug, returns error in release); the actual rejection happens at parse time. (2) The Wave 3a wrapper API takes module bytes and returns a parsed `CompiledModule` rather than taking `&CompiledModule` — this places Rule 5 enforcement at the architecturally correct pipeline stage and removes a caller-side deserializer-config footgun. (3) A canonical-encoding round-trip check landed in Wave 3a as a strengthening property: the wrapper re-serializes the parsed module via Sui's serializer at the module's own version and byte-compares against the input; non-canonicality (trailing junk bytes, alternate encodings) surfaces as `AdamantValidationError::NonCanonicalBytecode`. The check recovers the canonicality `check_no_extraneous_bytes = true` would have provided in Sui's deserializer config (which Adamant cannot use because it also rejects the metadata table Adamant needs per §6.2.1.3). (4) The §6.2.1.8 architecture pivoted from Sui-projection to fully Adamant-native after the Nop-projection mechanism was empirically demonstrated to break Sui's stack/type/reference passes for non-trivial Adamant code; vendored Sui crates moved off the deploy-time hot path to a test-time reference role. (5) The §6.2.1.8 architectural commitment extended from "fully Adamant-native verifier" to "fully Adamant-native deploy-time and runtime, with vendored Sui crates removed from the production binary's dependency graph entirely" — driven by Adamant's resistant-proof posture against upstream Sui changes, shutdowns, vulnerabilities, and governance shifts. The extension drove a Phase 5/5 restructure (4 sub-deliverables → 3, with 5/5b further split into 6 sub-arcs); a type-definition fork into a new `adamant-bytecode-format` crate (Option II in Phase 5/5b.1a + 5/5b.1b); a build-system independence check in Phase 5/5b.5; and a Cargo.toml restructure moving the 13 vendored Sui crates to test-only dev-dependencies of the production-binary target. (6) Phase 5/5b.1b Q3 (CompiledModule placement): Option X — no CompiledModule in `adamant-bytecode-format`. `AdamantCompiledModule` (in adamant-vm) is the only Adamant-owned module type; production code never constructs an inherited-subset module shape; cross-validation constructs Sui's vendored CompiledModule directly via `[dev-dependencies]`. Saves ~630 LOC, eliminates a parallel module type that would have invited "which one do I use?" auditor questions. (7) Phase 5/5b.1b Q5 (U256 disposition): thin newtype with serde + equality + hash + LE bytes only; arithmetic intentionally deferred to the AVM runtime sub-arc (whitepaper §6.3 / Phase 5/6.3) where the implementation choice (fork Sui's full `u256` module, adopt a third-party crate like `primitive-types` or `ethnum`, or implement in-repo) will be made deliberately as a first-order architectural decision. Bytecode-level U256 is a constant-pool / immediate-operand value type; arithmetic happens at runtime, not at the bytecode-format layer. (8) Phase 5/5b.1b Q6 (AccountAddress disposition): verify-then-pick confirmed that `adamant_types::Address` is byte-layout-identical to Sui's `move_core_types::AccountAddress` (both `pub struct Foo([u8; 32])`, both produce 32 raw bytes under BCS); reused (option b) rather than forked. Saves ~150 LOC and avoids parallel address types. `adamant-bytecode-format` gains a `path = "../adamant-types"` production dep; no circular dep (adamant-types depends only on serde, serde-big-array, bcs). (9) `IndexKind::variants()` upstream quirk preserved byte-faithfully in 5/5b.1b: Sui's upstream omits the `AddressIdentifier` variant from `variants()` (looks like upstream bug); Adamant preserves the omission and pins it with a cross-validation test. If upstream "fixes" this in a future tag, the cross-validation test surfaces it as a development-time signal; disposition follows the vendor-refresh checklist. (10) `to_sui_module` (Adamant→Sui conversion path used at test time only for cross-validation) reimplemented in 5/5b.1b via BCS round-trip per byte-identity invariants — each Adamant field is `bcs::to_bytes`-serialized and `bcs::from_bytes`-deserialized into its Sui counterpart. Test-time only; Phase 5/5c (cross-validation infrastructure formalization) is the natural place to revisit shape if needed. (11) Five new Adamant deviations from upstream documented in `adamant-bytecode-format/PROVENANCE.md` at 5/5b.1b: serde always-on (vs upstream's wasm-feature-gated derives — Adamant production code BCS-decodes privacy-metadata payloads at validator time); `StructDefinition::declared_field_count` typed `NativeStructError` + explicit `MemberCount::try_from`; `move_abstract_interpreter::Instruction` trait impl dropped (deferred to Adamant-native CFG in Phase 5/5b.4); U256 arithmetic deferral; AddressIdentifierPool reuse via `adamant_types::Address`. (12) `adamant-vm`'s `move-binary-format` dep gains `features = ["wasm"]` in 5/5b.1b to enable Sui's gated Serialize/Deserialize derives required for the test-time `to_sui_module` BCS round-trip path and for cross-validation tests. Production code paths never serialise Sui types. Both this dep and the wasm feature are removed in Phase 5/5b.5 along with the validator wrapper bridge.

**Open properties to track**: (1) Thin upstream verifier test surface from Batch 2 — `move-bytecode-verifier` carries 4 unit tests vs Batch 1's `move-binary-format` at 68; Sui exercises verifier behavior at the VM-integration level we did not vendor. Phase 5/5 (Adamant-native deserializer + verifier passes + cross-validation against the vendored reference) carries more correctness-establishing weight than usual — it is where the validator's behavior is genuinely exercised through real validation paths against real Move modules. The previously-deferred Adamant-side per-instruction extension verification (full stack/type/reference safety for the 17 extensions) is now in scope for Phase 5/5b.4 + 5/5b.5 (per-function passes promoted from old 5/5c into 5/5b alongside the resistant-proof restructure) — no longer deferred. Cross-validation tier coverage requirements: T0 (every pass has positive + negative fixture pair) + T1 (every Adamant error variant exercised) + T2 (every Sui error mode produces a fixture that triggers it in Adamant with same accept/reject decision) mandatory for Phase 5/5c closure; T3 (real-world corpus from compiled Sui-Move source) deferred to pre-mainnet hardening as a stretch goal. (2) `GenerateProof`, `VerifyProof`, and `RecursiveVerify` stack effects are parametric in circuit signatures resolved through the operand's `CircuitId`; circuit-signature resolution is deferred to §7 (privacy layer). The verifier's stack-balance check on these instructions cannot ship statically until §7 lands; until then, runtime stack-balance enforcement carries the binding — same shielding-vs-runtime pattern as Rule 3. (3) `to_sui_module` BCS-round-trip shape (landed in 5/5b.1b at module.rs:307-409) is test-time only and carries `expect("byte-identity invariant per Phase 5/5b.6 cross-validation")` panics relying on the byte-identity invariants asserted by `adamant-bytecode-format/tests/cross_validation.rs`. Phase 5/5c (cross-validation infrastructure formalization) is the natural place to revisit shape if a more explicit per-field `From<Adamant> for Sui` impl set is preferred over BCS round-trip. Not blocking; the current approach is honest about what it relies on. (4) `adamant-vm`'s `move-binary-format` dep gains `features = ["wasm"]` in 5/5b.1b for the test-time `to_sui_module` path. Cargo features are crate-level not call-site-level — the wasm feature flows transitively to adamant-vm's callers, and the discipline that production code never invokes serde on Sui types is a discipline rather than a compiler-enforced guarantee. The whole transitional Sui-side surface (the validator wrapper bridge in `validator/mod.rs`, the remaining `move-*` production deps, the wasm feature) is removed in Phase 5/5b.5; the issue is bounded in time. **(5) §6.2.1 spec-amendment workstream — two carry-forwards registered at Phase 5/5b.2 closure**, both pre-mainnet workstream items distinct from the genesis-pool calibration item: **(5a) §6.2.1.7 structural-limits values** (registered at Phase 5/5b.2 B-1; reaffirmed at B-3.4 and B-6) — §6.2.1.7 specifies structural limits as genesis-fixed but does not enumerate values; B-1 ships provisional values per the Bucket A/B/C disposition documented in `crates/adamant-vm/src/validator/module_pass/PROVENANCE.md`'s "Genesis structural-limits values" section; pre-mainnet workstream raises a §6.2.1.7 amendment proposal to enumerate the values in the spec parallel to the per-instruction gas-cost appendix pattern. **(5b) §6.2.1.8 cross-pass eager-error precedence** (registered at Phase 5/5b.2 B-5; carried forward to B-6) — §6.2.1.8 line 563 classifies within-step pass-orchestration as implementation-discretionary while pinning accept/reject behaviour as fixed; Phase 5/5b.2 established that cross-pass eager-error precedence is part of accept/reject behaviour (when a shared error variant can be produced by two passes for the same input, which-error-fires-first is consensus-binding). Two shared-variant precedence claims are consensus-binding from B-5 forward: `MalformedConstantData` (constants wins over limits) and `MalformedPrivacyMetadata` (privacy_metadata_structure wins over Rule 2 via step-3-before-step-5 ordering). Pre-mainnet workstream raises a §6.2.1.8 amendment proposal to capture cross-pass eager-error precedence explicitly in the spec, similar in shape to the §6.2.1.7 amendment for structural limits. **(6) Integration-test depth limitation registered at B-5** (recorded in `crates/adamant-vm/src/validator/module_pass/PROVENANCE.md`'s "Integration-test depth limitation" section): the limits-alone-fires precedence pin under genesis defaults requires a fixture exceeding `max_constant_vector_len` (1 MiB), impractical for test fixtures; integration-level pin omitted; depth coverage lives at the per-pass Layer A level (23 tests covering each limits sub-check independently); future integration-level limits-alone-fires coverage requires a test-only `AdamantVerifierConfig::with_structural_limits` builder; deferred as known follow-up rather than added speculatively. **Reaffirmed at C-4** when Q4 Claim 1 (BoundsChecker `IndexOutOfBounds` vs limits' overflow precedence pin) was deferred under the same limitation — a fixture exceeding `max_function_definitions = 1000` plus an OOB function-handle reference would exercise both passes, but constructing 1001 function_defs is impractical. Two-instance precedent for the `AdamantVerifierConfig::with_structural_limits` builder workstream; promoted to active follow-up item with two carry-forwards (B-5 limits-alone-fires; C-4 BoundsChecker-vs-limits cross-pass precedence). **(7) Variant-vs-test mapping audit canonical implementation-gate principle (registered at Phase 5/5b.3 C-3, applied retroactively at C-5)** — every typed-error variant landing in a sub-checkpoint must have at least one explicit negative test asserting on the variant shape; implementation-gate audit step enumerates typed variants added at the sub-checkpoint, maps each to its negative test(s), and flags any unmapped variant for coverage closure before commit. Recorded in `crates/adamant-vm/src/validator/module_pass/PROVENANCE.md` as canonical methodology principle. The C-5 retroactive audit covered all 50 typed `AdamantValidationError` variants; 49 had explicit negative-test coverage; 1 gap (`SuiVerifier`, transitional bridge variant) deferred to natural resolution at Phase 5/5b.5 when the bridge tears out and the variant is removed entirely. **(8) Commit-message running-total drift discipline (registered at Phase 5/5b.3 C-5; 2nd instance at D-7b)** — per-commit deltas can be empirically correct while running totals drift if the inherited baseline is wrong. Future phase closures empirically grep-confirm running totals (variant counts, LOC, test counts, etc.) against actual code rather than inheriting prior CLAUDE.md state-bumps. Origin instance: B-6's Phase 5/5b.2 closure state-bump claimed `AdamantValidationError carries 20 typed variants` (empirically 33 at the same commit); the wrong baseline propagated through 5 subsequent C-N commit messages via correct-delta-on-wrong-baseline arithmetic. C-5 corrigendum recorded in PROVENANCE.md restored empirical counts. **2nd instance caught at D-7 plan-gate**: D-3 commit didn't claim workspace test count, D-4 inherited a wrong baseline 1328 vs empirical 1362, drift propagated through 8 subsequent commit messages (D-4 → D-5a.0 → D-5a.1.a → D-5a.1.b → D-5b.1 → D-5b.2 → D-5c → D-6) with correct deltas on wrong baseline. D-7b corrigendum parallel to B-6 in PROVENANCE.md restores empirical counts (1259 → 1532 across Phase 5/5b.4, +273 added). Pattern reaches 2 instances; rule-of-three pending at next phase closure. **Future commit-message discipline**: per-sub-checkpoint commit messages must claim workspace test count explicitly (the D-3 origin gap was "no workspace claim"; future commits that don't claim workspace count let the drift propagate silently). **(9) Open Layer B gaps deferred to pre-mainnet hardening (NEW canonical sub-pattern at D-7b; rule-of-three threshold met)** — Layer B parity tests for specific Adamant rules may be deferred when the cross-validation fixture-construction overhead exceeds sub-checkpoint scope. The deferred-rule still has Layer A direct unit-test coverage; Sui-side coverage lives in upstream's own test suite. Three instances: `SuiVerifier` audit gap (C-5; deferred to 5/5b.5 bridge tear-out); BorrowViolationReason 6 of 13 sub-reasons (D-5b.2; deferred to pre-mainnet hardening); `st_loc_destroys_non_drop` rule parity (D-7a; deferred to pre-mainnet hardening). Future per-pass Layer B coverage gaps follow the same disposition shape — register with the rule under coverage, the Layer A pin, and the resolution venue. **(10) Sui-public-API-shape-constrains-parity-helper sub-pattern (NEW at D-7b; rule-of-three pending)** — Sui's per-pass entries for `stack_usage_verifier`, `locals_safety`, `type_safety` are `pub(crate)` in upstream; only `control_flow::verify_function` (per-pass) and `code_unit_verifier::verify_module` (composite) are publicly reachable from Adamant's test code. Layer B parity strategy adapts: per-pass parity when Sui's per-pass entry is `pub` (D-2 control_flow); composite-pipeline parity with type-correct fixtures when Sui's per-pass entry is `pub(crate)` (D-3 stack_usage / D-4 locals_safety). 1st instance at D-7a; rule-of-three pending at next per-pass parity attempt with similar API constraint (likely candidate: Phase 5/5b.5 reference_safety per-pass parity if Sui's `reference_safety::verify` remains `pub(crate)`). **(11) Cross-module Rule 3 enforcement at deployment-validator wiring (registered at D-5c; forward-tracking to Phase 5/5b.5)** — D-5c's Rule 3 privacy-consistency call-graph walker operates on the current module only; cross-module Rule 3 enforcement (e.g., a function in module A calling a function in module B with privacy mismatch) requires the deployment-validator's loaded-modules view. Deferred to Phase 5/5b.5 deployment-validator wiring layer.

**Mainnet**: years away. This is a long project. Pace accordingly.

**Pace**: Ryan is also building Core Buddy. Expect inconsistent session frequency. Long gaps between sessions are normal. Always re-read this file at session start to reload context.

**Calibration work pending**: the genesis pool mechanism in §10 has several parameters flagged as "subject to calibration prior to mainnet" (pool size, partition ratio, cap schedule, time cap, conversion rates, validator reward sizing). These are reference values; final calibration via simulation analysis happens before genesis. After genesis, all values are immutable per §11. The calibration is a separate workstream from the implementation work that Claude Code is doing.

---

## Section 11: A few things worth re-emphasising

- **The whitepaper is the spec.** Every design decision is in it. If you find yourself making a decision that isn't in the whitepaper, that decision belongs in the whitepaper first, not in the code.

- **Credible neutrality is everything.** It's the property that makes Adamant worth building. Anything you do that erodes it — admin keys, foundation accounts, hidden upgrade paths, "just for development" backdoors — destroys the project. There is no acceptable version of "we'll add governance later." There is no acceptable version of "the team will hold tokens for development funding." If a request implies any of these, push back and reference Principle I.

- **Standard cryptography only.** If a task seems to need exotic crypto, it almost certainly needs standard crypto used cleverly. Ask before improvising.

- **The fair launch is non-negotiable.** Zero premine, zero implementer allocation. The only way the implementers (Ryan, you helping Ryan) get ADM is by participating in the launch-phase acquisition paths (burn-to-mint or validator block rewards per §10.2.3) on the same terms as everyone else, or by acquiring ADM through normal market activity after the launch phase ends. Anything that contradicts this destroys the project.

- **Bug fixes after genesis require hard forks.** This is a real cost. Take quality seriously now, because we cannot patch later.

- **Adamant is resistant-proof against upstream dependencies.** The protocol runs fully independently of Sui-Move's codebase at deploy-time and runtime; vendored Sui crates appear only at test time for cross-validation parity, never in the production binary's dependency graph. Anything you add or change that introduces a runtime dependency on Sui's codebase — even transitively — violates this posture. The build-system independence check in `tests/no_sui_in_production_deps.rs` (lands in Phase 5/5b.5) is the mechanical guardrail; the architectural commitment is in §6.2.1 and §6.2.1.8. If a request implies adding Sui logic to the production hot path, push back and reference the resistant-proof commitment.

- **Adamant-native posture extends project-wide to all external code.** The resistant-proof posture above (originally specific to Sui-Move) is the protocol-wide commitment going forward: do not introduce dependencies on any external network, protocol, or project code beyond the bounded ecosystem already established (RustCrypto crate family — `sha3`, `blake3`, `ed25519-dalek`, `ml-dsa`, `ml-kem`, `chacha20poly1305`, `hkdf`, `hmac`, `digest`, `rand_core` and aliases, `subtle`, `zeroize`; `blst` for BLS12-381 primitives via `adamant-crypto-blst-extra`; standard workspace utility crates such as `serde`, `bcs`, `tokio`, `petgraph`). The `arkworks` ecosystem is **explicitly excluded**; KZG is implemented Adamant-native on the existing `blst` BLS12-381 layer per whitepaper §3.9.2 amendment (spec-first verification 30th instance). Future cryptographic, consensus, or protocol functionality requiring upstream code must be **forked** into an Adamant-owned crate with `PROVENANCE.md` documenting the fork (Phase 5/5b.1a/b precedent), not pulled in as a runtime dependency. External services, network calls to other chains, or runtime reliance on third-party infrastructure are forbidden in production builds. If a request implies adding any external dependency to production paths or runtime behavior beyond the bounded ecosystem, push back and reference this commitment. The discipline is not "minimize external deps" — it is "Adamant-native by default; deliberate exception only after explicit spec-author ratification."

- **Ryan is the founder.** Substantive design decisions go through Ryan, not through you alone. If something significant comes up, surface it for Ryan's decision rather than choosing silently.

---

## Section 12: When in doubt

- Re-read `/whitepaper/02-design-principles.md`.
- Cite the section number when explaining a decision.
- Ask Ryan rather than assume.
- Prefer the conservative choice. We are building infrastructure for users who do not trust anyone, including us. Caution is a feature.

---

## Section 13: Audit story / resistant-proof posture

Adamant is designed to outlive the conditions under which it was created. A privacy-default L1 with no foundation, no admin keys, no premine, and no upgrade authority after genesis must not have a runtime dependency on another protocol's codebase — independence is part of the value proposition.

The resistant-proof commitment, captured in whitepaper §6.2.1 and §6.2.1.8 (amendment commits `19d744b`, `0651e2f`):

- **Auditor reading scope is Adamant code only.** A security auditor reading Adamant does not need to read Sui-Move's codebase. Adamant's verifier, deserializer, serializer, type definitions, helpers, and runtime are all under Adamant's authorship and audit. The vendored Sui-Move crates are CI infrastructure, not a security boundary.

- **Vendored Sui-Move crates appear only at test time.** The 13 vendored crates at tag `mainnet-v1.66.2` are exercised by the cross-validation test suite to confirm Adamant's verifier produces identical accept/reject decisions to Sui's on pure-Sui modules. They do not appear in the production binary's dependency graph. The build-system independence check in `tests/no_sui_in_production_deps.rs` (Phase 5/5b.5) walks the resolved dependency tree via `cargo metadata` and fails CI if any `move-*` crate appears in the production target.

- **Threat model addressed by the posture.** (a) Upstream Sui changes that diverge from Adamant's behaviour for the inherited subset surface as development-time signals via cross-validation, never as consensus events. (b) Sui project shutdown, dormancy, or migration leaves Adamant unaffected — the vendored snapshot at `mainnet-v1.66.2` is sufficient for cross-validation in perpetuity. (c) Vulnerabilities discovered in Sui-Move's verifier or runtime affect Adamant only if Adamant's parallel implementation has the same bug; tracking Sui's patches is not a security obligation. (d) Sui's commercial, governance, or licensing decisions cannot constrain Adamant's behaviour or roadmap.

- **The carve-out for test/CI/build-tooling.** Test-only, build-tooling-only, and CI-only dependencies on vendored Sui-Move are explicitly permitted by the spec. What is precluded is Sui-Move logic executing during deploy-time module verification or runtime VM execution. The distinction is mechanical: any crate that appears in the production-binary target's dependency graph is precluded; crates that appear only in `dev-dependencies` or behind test-only feature gates are permitted.

- **Spec-level commitment, not just implementation choice.** The resistant-proof posture is a protocol-level requirement (whitepaper §6.2.1.8). Future implementations of Adamant — different language, different team — must honour it; an implementation that loads Sui-Move at deploy-time or runtime is non-conforming, regardless of whether it reaches the same accept/reject decisions on individual modules.

---

## Section 14: Adamant-native posture (project-wide)

The resistant-proof posture in §13 was originally Sui-Move-specific. As of whitepaper §3.9.2 amendment (commit `9c36c8f`, spec-first verification 30th instance), the same discipline extends **project-wide to all external code**. This section is the canonical record of the discipline; the §11 bullet is supplementary emphasis. When in doubt about a new dependency or external integration, this is the authoritative reference.

The discipline at a single sentence:

> **Adamant-native by default; deliberate exception only after explicit spec-author ratification.**

The reasoning is the same as §13's: a privacy-default L1 with no foundation, no admin keys, no premine, no upgrade authority after genesis cannot rely on external networks, protocols, or project codebases that may shut down, change governance, introduce incompatible upgrades, or be compromised. Independence is part of the value proposition, and independence has to be enforced at the dependency-graph level, not just declared.

### 14.1 The five-category framework

Every dependency or integration falls into exactly one of five categories. The category determines whether the dependency is acceptable and on what terms.

#### Category A — Adamant-native (REQUIRED; protocol-defining)

Application logic and protocol-defining code. External dependency is unacceptable. The protocol's behaviour at consensus must be defined in code Adamant authors and audits.

In scope:

- §5 Object model + state (`adamant-state` crate)
- §6 Execution + virtual machine (`adamant-vm` crate)
- §6.0 Transaction format (`adamant-types` crate)
- §6.2.1 Bytecode format (`adamant-bytecode-format` crate; Phase 5/5b.1a/b fork from Sui-Move)
- §6.3 AVM runtime (`adamant-vm/src/runtime/`)
- §7 Privacy layer (`adamant-privacy`; Phase 6)
- §8 Consensus (DAG-BFT; Phase 7+)
- §9 Networking + service nodes (Phase 7+)
- §10–11 Genesis + tokenomics (pre-mainnet)

Decision rule: **if it defines protocol behaviour, it ships as Adamant-native code.**

#### Category B — Bounded ecosystem (PRAGMATIC; locked at current state)

Cryptographic primitives where reimplementation is audit-net-negative. Standardised algorithms (FIPS, RFC, IETF specs) with battle-tested implementations from a small set of well-audited upstream maintainers. The set is **locked**; no new external integrations beyond the enumerated list are added without explicit spec-author ratification.

Locked set (workspace `Cargo.toml` `=` exact pin discipline):

- **§3.3 Hashing.** `sha3 =0.10.9` + `blake3 =1.8.5` + `hmac =0.12.1` + `hkdf =0.12.4`
- **§3.4.1 Classical signatures.** `ed25519-dalek =2.2.0`
- **§3.4.2 Post-quantum signatures.** `ml-dsa =0.1.0-rc.9`
- **§3.7 Post-quantum KEM.** `ml-kem =0.3.0` + `rand_core_0_10 =0.10.1` (alias for the rand_core 0.10 trait surface)
- **§3.4.3 + §3.6 BLS12-381.** `blst =0.3.16` (via `adamant-crypto-blst-extra` unsafe-permitting wrapper; the workspace's only `unsafe`-permitting crate)
- **§3.5 Symmetric AEAD.** `chacha20poly1305 =0.10.1`
- **§5.1.8 Canonical serialization.** `bcs =0.1.6` + `serde =1.0.228` + `serde-big-array =0.5.1`
- **Memory hygiene.** `zeroize =1.8.2` + `subtle =2.6.1`
- **RNG trait surface.** `rand_core 0.6` (workspace default for ed25519-dalek's 2.2 trait generation)

Decision rule: **if it's a standardised cryptographic primitive (FIPS / RFC / IETF spec) that's mathematically fixed, the locked bounded ecosystem is acceptable. Adding a new cryptographic primitive requires spec-author ratification + locked-set update.**

#### Category C — Adamant-native layered on Category B (REQUIRED; bridge layer)

Anything that combines primitives into protocol-specific operations. This is where external integrations would otherwise creep in — protocol-specific cryptographic constructions, threshold schemes, commitment-and-proof schemes built on standard primitives. These are Adamant-authored.

In scope:

- **§3.3.1 BIP-340 tagged-hash construction.** Adamant-native; spec-first verification 1st instance (commit `62bfe89`).
- **§3.6 Threshold encryption.** Adamant-native; in `adamant-crypto::threshold`.
- **§3.9.2 KZG.** Adamant-native on `adamant-crypto-blst-extra`'s BLS12-381 primitives; spec-first verification 30th instance (commit `9c36c8f`); implementation pending dedicated session.
- **§3.7.1 + §8.5 Halo 2 + recursive verification.** Posture resolved at §14.4 Decision 1 below as **Path C2** (fork into `adamant-halo2` crate). `halo2_gadgets 0.3` is in the workspace and consumed by Phase 6.0 Poseidon out-of-circuit (the smallest Cat C-equivalent surface area) until the C2 fork lands at Phase 6.8b.
- **§3.8 + §8.x Time-lock VDF.** Adamant-native required; Phase 7+.
- **§7 Privacy operations.** Adamant-native dispatch wrapping circuit operations; Phase 6.

Decision rule: **if it bridges Category B primitives into protocol-specific operations, it ships as Adamant-native code (Category C). Reaching for an external bridge library is the wrong move.**

#### Category D — Test-time only (already excluded from production)

Per §13's resistant-proof posture, the workspace permits test-only / dev-only / CI-only dependencies that do not appear in the production binary's dependency graph. The mechanical enforcement is `tests/no_sui_in_production_deps.rs` (Phase 5/5b.5), which walks the resolved dependency tree via `cargo metadata` and fails CI if any `move-*` crate appears in the production target. The same mechanical posture applies to any future test-only dependency.

In scope (production binary excludes):

- 13 vendored Sui-Move crates (`move-*` under `/vendor/`) for cross-validation parity testing only.
- Test infrastructure: `proptest`, `insta`, `hex`, `hex-literal`, `datatest-stable`, `arbitrary`.

Decision rule: **test-only dependencies are acceptable provided they appear only in `[dev-dependencies]` or behind test-only feature gates and never appear in the production target's dependency graph. New test-only dependencies must satisfy this mechanical check.**

#### Category E — Workspace utilities (bounded-ecosystem; infrastructure tier)

Production-side, non-consensus, ergonomic infrastructure. These are not cryptographic primitives and not protocol-defining; they are general-purpose Rust infrastructure that's mature, well-audited, and where reimplementation would be net-negative without strengthening the protocol.

Locked set:

- `petgraph 0.8.1` (graph algorithms; promoted to production at Phase 5/5b.2 for CFG / borrow-graph work).
- `ethnum 1.0.4` (U256 helper; consensus-adjacent — pre-mainnet revisit candidate).
- `getrandom 0.2.9` (RNG entropy abstraction; CSPRNG plumbing).
- `thiserror 1.0.24` (error type derivation; macro-only).

**Networking-infrastructure tier** (admitted at the Phase 7.8 plan-gate per §14.4 Decision 4):

- `libp2p` (umbrella crate; feature-gated to the §9.2.2-pinned subset: `quic`, `tcp`, `noise`, `yamux`, `kad`, `gossipsub`, `identify`, `dns`, `macros`).

Networking infrastructure is admitted to Category E under the §9.2.1 Principle-VI invocation in the whitepaper: *"Implementing each of these from scratch would consume engineering effort with no marginal benefit. libp2p is a known-good choice."* The architectural framing: network-layer correctness is **delivery**, not state-transition correctness. Two nodes running different `libp2p` versions still agree on the chain because consensus is BLS-signed and the DAG is content-addressed — the resistant-proof rationale that drove the Halo 2 fork (Decision 1, Path C2) and the Sui-Move fork (§13) does not apply with the same force here, and the spec settled the choice in advance.

Exact version pinning lands at Phase 7.8.1 (libp2p integration; Phase 7.8.0 is networking-substrate-agnostic wire-format types).

Decision rule: **infrastructure-tier crates are acceptable when they are mature, non-consensus, and where reimplementation is audit-net-negative. Consensus-adjacent crates (e.g., `ethnum` for U256) are pre-mainnet revisit candidates: confirm at hardening time whether reimplementation is warranted. Networking-infrastructure crates (`libp2p` ecosystem) are admitted per §9.2.1 Principle-VI rationale; future networking primitives require spec-author ratification.**

### 14.2 The discipline — single-rule decision tree

When evaluating any new dependency or integration, walk the following five-step test in order:

1. **Is it a standardised cryptographic primitive (FIPS / RFC / IETF spec) that's mathematically fixed?**
   → Bounded ecosystem (Category B) is acceptable, *if* it's already in the locked set or warrants spec-author ratification to add.

2. **Does it define protocol behaviour?**
   → Adamant-native required (Category A).

3. **Does it bridge Category B primitives into protocol-specific operations?**
   → Adamant-native layered on bounded ecosystem (Category C).

4. **Is it test-time only?**
   → Acceptable per current discipline (Category D), provided it never appears in the production dependency graph.

5. **None of the above?**
   → Excluded per Adamant-native posture.

The forking-over-vendoring sub-discipline applies when upstream code is required: rather than adding a runtime dependency, the upstream code is forked into an Adamant-owned crate with a `PROVENANCE.md` documenting the fork (Phase 5/5b.1a/b precedent). Forking gives Adamant the production-binary-graph control the resistant-proof posture demands while still benefiting from upstream code quality and audit history.

### 14.3 Forking-over-vendoring discipline

When functionality requires upstream code that doesn't fit cleanly into Categories B or D — typically because the upstream code defines protocol-binding behaviour or is too entangled with protocol semantics to be a pure cryptographic primitive — the discipline is to **fork**, not depend.

Precedent: Phase 5/5b.1a/b forked Sui-Move's bytecode-format types (constants, readers, AbilitySet, Identifier, the 25 reused parallel-struct neighbour types, SignatureToken, Bytecode enum, CodeUnit, FunctionDefinition, U256, Metadata, AddressIdentifierPool) into the new `adamant-bytecode-format` crate. Each fork is documented in the destination crate's `PROVENANCE.md`: source commit, scope of fork, deviations from upstream, refresh cadence (test-time only after fork).

Mechanical posture:

- Fork lands in an Adamant-owned crate under `crates/`.
- `PROVENANCE.md` documents source provenance + audit posture + refresh policy.
- Production binary depends only on the Adamant-owned fork; upstream version (if any) appears only as test-time cross-validation oracle (Category D) or not at all.
- Upstream changes affect Adamant only as development-time signals (refresh-and-review work item), never as consensus events.

### 14.4 Posture decisions

Two posture decisions remain open for spec-author deliberation; one has been resolved. All are registered here as canonical record; pending answers land at the appropriate plan-gate.

#### Decision 1 — Halo 2 / `halo2_gadgets` at Phase 6 plan-gate (RESOLVED — Path C2)

`halo2_gadgets 0.3` (Zcash / Electric Coin Company ecosystem) is in the workspace `[workspace.dependencies]` and has been consumed since Phase 6.0 for the out-of-circuit Poseidon helper (§3.3.3). The Phase 6 privacy-layer workstream (§7 + §3.7.1 + §8.5) will additionally activate the Halo 2 in-circuit surface for shielded-execution circuits (§7.3.2) and recursive proof composition (§8.5.2) at Phase 6.8b + 6.9b.

Three options were considered:

- **Path C1 — Adamant-native Halo 2 implementation.** Tens of thousands of LOC; substantial pre-mainnet investment. Maximum independence; maximum implementation cost. **Rejected:** violates Principle VI ("Use peer-reviewed cryptography. Never roll our own. Innovation is at the systems layer."). Halo 2 is a peer-reviewed (Bowe / Grigg / Hopwood 2019) production-deployed proving system (Zcash Orchard, Aztec); reimplementing it from scratch is exactly what Principle VI forbids. The audit risk of a from-scratch reimplementation exceeds the dependency risk of reusing the audited upstream.
- **Path C2 — Fork `halo2_gadgets` (and necessary subset of `halo2_proofs`) into `adamant-halo2` with `PROVENANCE.md`.** Phase 5/5b.1a/b precedent applied to the ZK proof system. Production-binary control retained; upstream code quality preserved; refresh-cadence controlled. **Selected.**
- **Path C3 — Accept as bounded-ecosystem (Category B-style).** Pragmatic; same posture as the RustCrypto + blst set. **Rejected:** Cat B (§14.1) is reserved for "Standardised algorithms (FIPS, RFC, IETF specs) with battle-tested implementations from a small set of well-audited upstream maintainers." Halo 2 is not FIPS / RFC / IETF — it is a specific Zcash design. Treating it as Cat B would be a runtime dependency on Zcash's codebase governance, refresh cadence, and shutdown risk — exactly what §13's resistant-proof posture forbids. The §14.4 Decision 3 (KZG trusted-setup) precedent applies the same logic: the spec-author chose Adamant-native KZG over arkworks integration because resistant-proof takes precedence over ecosystem ergonomics.

**Resolution**: **Path C2**. The fork-over-vendoring discipline (§14.3) applies cleanly: Adamant owns the fork in a new `adamant-halo2` crate under `crates/`; upstream is consulted at refresh time, not depended on at runtime; production binary's dependency graph contains no `halo2_*` crates from upstream. Same pattern as Phase 5/5b.1a/b (Sui-Move bytecode-format types forked into `adamant-bytecode-format`).

The fork lands at Phase 6.8b plan-gate as part of the validity-circuit + recursive-proving implementation work. Until then, Phase 6.0 Poseidon (out-of-circuit primitive surface) continues consuming `halo2_gadgets` directly via the workspace dep — bounded to the Poseidon namespace only, the smallest Cat C-equivalent surface area until C2 lands.

**Fork scope** (target list at the Phase 6.8b plan-gate, refined as implementation proceeds): the in-circuit Poseidon chip (§7.1 / §7.1.2 / §7.1.3 in-circuit), ECC chips for Pallas (§7.2.2 stealth-address arithmetic in-circuit), the validity-circuit primitives Adamant's §7.3.2 statements consume (Merkle membership, range, value-conservation), and the subset of `halo2_proofs` (PLONKish arithmetisation, polynomial commitments) those circuits link against. The IPA-vs-KZG variant choice within `halo2_proofs` is decided at the same plan-gate; the fork carries only the variant Adamant uses.

**Sub-decision (resolved by C2 landing)**: the workspace `halo2_gadgets = "0.3"` non-exact pin becomes moot once the fork lands — the production-binary dependency moves from upstream `halo2_gadgets` to `adamant-halo2`, and the upstream pin is consumed only by the development-time refresh / cross-validation path (mirror of the Sui-Move tag-pin discipline).

**Mechanical guardrail**: a `tests/no_upstream_halo2_in_production_deps.rs` build-system independence check (mirroring `tests/no_sui_in_production_deps.rs` from Phase 5/5b.5) walks the resolved dependency tree via `cargo metadata` and fails CI if any upstream `halo2_*` crate appears in the production target. Lands with the C2 fork at Phase 6.8b.

#### Decision 2 — RocksDB at Phase 4 backfill / pre-mainnet

The Phase 4 object-storage backfill workstream needs a concrete `StateView` / `StateMutator` implementation against persistent storage (in-memory mocks shipped at Phase 5/6.6 satisfy the trait surface for runtime-side wiring; production storage backend is deferred).

Three options:

- **Bounded-ecosystem (Category B-equivalent for storage).** Industry-standard storage infrastructure (RocksDB, sled, redb, etc.). Pragmatic; storage is non-consensus infrastructure.
- **Adamant-native storage layer.** Effectively building a database. Massive scope; net-negative for protocol value.
- **Forked storage layer.** Excessive for a non-consensus dependency.

**Recommendation**: bounded-ecosystem acceptable, treating storage as infrastructure tier (Category E-equivalent). The protocol-binding logic on top of storage is Adamant-native (`adamant-state`); the storage backend itself can be off-the-shelf. Spec-author call at Phase 4 backfill plan-gate.

#### Decision 3 — KZG trusted-setup procurement source

Whitepaper §3.9.2 + §11.2 currently specify Ethereum's KZG Powers of Tau ceremony output (July 2023) as the trusted-setup source. The §3.9.2 amendment at instance 30 settled the *implementation* posture (Adamant-native math); the *setup-source* question is independent.

Two options:

- **EthPoT reuse** (current spec text). Conservative-choice; transfers Ethereum's ceremony confidence at zero marginal cost. Hard-fork-to-update if needed.
- **Adamant ceremony pre-genesis.** Custom ceremony coordinated by the Adamant ecosystem. Substantial pre-mainnet coordination cost; constitutional-impact (how is the participant set determined?). Maximum protocol autonomy.

**Recommendation**: pending spec-author deliberation at pre-mainnet hardening. The §3.9.2 amendment did not change setup-source language; that's a separate constitutional-impact deliberation.

#### Decision 4 — `libp2p` at Phase 7.8 plan-gate (RESOLVED — Option A: admit to Category E)

Whitepaper §9.2 specifies `libp2p` as the network substrate verbatim, with §9.2.1 explicitly invoking Principle VI: *"Implementing each of these from scratch would consume engineering effort with no marginal benefit. libp2p is a known-good choice (Principle VI: standard primitives, novel synthesis)."* The §9.2.2 configuration is pinned: QUIC primary + TCP fallback, Noise XX, Yamux, Kademlia DHT, gossipsub v1.1.

The spec-level *use* of `libp2p` is settled. The §14.4 plan-gate question was the *dependency posture*: admit `libp2p` to the bounded ecosystem (Category B/E-style), or fork it into an Adamant-owned crate parallel to the Sui-Move (`adamant-bytecode-format`) and Halo 2 (`adamant-halo2`) precedents.

Three options were considered:

- **Option A — Admit `libp2p` to Category E locked-set.** Pragmatic; the spec already invokes Principle VI for this exact choice. Pin specific versions; treat the libp2p ecosystem as networking-infrastructure tier (parallel to how `petgraph` is treated for graph algorithms). Risk: libp2p has substantial transitive-dep surface; expands audit scope materially. **Selected.**
- **Option B — Fork `libp2p` into `adamant-network`.** Matches the Halo 2 / Sui-Move resistant-proof posture (§13, §14.3). Rejected: libp2p is much larger than `move-binary-format` or `halo2_proofs` (50-100k+ LOC); networking is not consensus-binding the way crypto is — two nodes running different libp2p versions still converge on the same chain state as long as gossip propagates, because consensus is BLS-signed and the DAG is content-addressed. The resistant-proof rationale that drove the prior forks does not apply with the same force here, and the engineering cost of the fork is disproportionate to the marginal independence gain.
- **Option C — Adamant-native networking from scratch.** Rejected: explicitly forbidden by §9.2.1 ("does not roll its own peer-to-peer stack"); violates Principle VI.

**Resolution**: **Option A**. The spec already settled the choice with the §9.2.1 Principle-VI invocation. The §14.1 Category E locked-set is extended with a **networking-infrastructure tier** admitting `libp2p` (umbrella crate, feature-gated to the §9.2.2-pinned subset). Networking-layer correctness is delivery, not state-transition correctness — the resistant-proof framework's audit-surface concerns are addressed at the consensus + crypto layers above.

**Mechanical guardrail**: networking-infrastructure crates are categorically distinct from production-consensus crates. The locked set is `libp2p` only at this Decision; expansion to additional networking primitives (e.g., a separate `quinn` direct dep, a separate DHT crate) requires fresh spec-author ratification parallel to the §14.4 plan-gate pattern.

**Exact version pinning** lands at Phase 7.8.1 (libp2p integration). Phase 7.8.0 is networking-substrate-agnostic wire-format types (the `adamant-network` crate's foundation layer) and does not yet pull in `libp2p` as a runtime dep — mirrors the Phase 7.5.0 / 7.3 / 7.6 wire-foundation pattern.

### 14.5 Phase-by-phase build map

The following map records which phases are complete, in progress, or pending, with explicit Category labels for each major deliverable. Categories are A (Adamant-native required), B (bounded ecosystem), C (Adamant-native bridge layer), D (test-time only), E (workspace utility). The map is canonical-record forward planning; spec-author may revise scope at any phase plan-gate.

**Phase 1–2: Foundation (DONE)**
- `adamant-types` + `adamant-crypto` wrappers — Cat A + B/C bridge layer.

**Phase 3: Cryptographic primitives (DONE)**
- Hashing/sig/AEAD wrappers around bounded ecosystem — Cat B.
- BIP-340 tagged-hash construction — Cat C bridge.
- Threshold encryption — Cat C bridge.
- KZG — Cat C bridge (implementation pending; spec settled at instance 30).
- ML-KEM-768 wrapper — Cat B.

**Phase 4: Transactions + lifecycle (DONE)**
- Transaction type + TxHash + lifecycle validators — Cat A.

**Phase 5: Verifier (DONE; Phase 5/5 closed at commit `5e1bb0d` with 9 architectural commitments per CONTRIBUTING.md spec-first verification instances 16–24)**
- `adamant-bytecode-format` fork — Cat A (Phase 5/5b.1a/b precedent for forking-over-vendoring).
- `adamant-vm` verifier — Cat A.
- Cross-module Rule 3 walker — Cat A.

**Phase 5/6: AVM Runtime (~93%; current phase)**
- AVM runtime + bytecode dispatch — Cat A.
- Multi-dimensional gas accounting — Cat A.
- Transaction-boundary integration (`load_read_set` + `commit_buffer`) — Cat A.
- KZG implementation pending (Cat C bridge; dedicated session).
- 5/6.7 + 5/6.8 stdlib pending.

**Phase 6: Privacy layer (NEXT MAJOR PHASE)**
- `adamant-privacy` — Cat A.
- Halo 2 ZK circuits — **Posture Decision 1 resolved as Path C2** (fork into `adamant-halo2` crate; lands at Phase 6.8b).
- Privacy-circuit handlers (`GenerateProof` / `VerifyProof` / `RecursiveVerify` / `ReleaseSubViewKey`) — Cat C bridge.
- Recursive proof generation — Cat C bridge.

**Phase 7+: Consensus + networking**
- DAG-BFT consensus — Cat A required.
- Threshold-encrypted mempool — Cat A on Cat B primitives.
- Time-lock VDF — Cat A required.
- P2P networking — **Posture Decision 4 resolved as Option A**: `libp2p` admitted to Category E networking-infrastructure tier per §14.1 + §14.4 Decision 4. Lands at Phase 7.8.1 with exact-pinned version; Phase 7.8.0 (wire-format types) is substrate-agnostic.
- Validator-set management — Cat A required.

**Pre-mainnet hardening**
- Object-storage RocksDB backend — **Posture Decision 2 pending**.
- Per-instruction gas-cost calibration — Cat A.
- Throughput-floor empirical validation — methodological work.
- Trusted-setup procurement (KZG) — **Posture Decision 3 pending**.
- AIP framework (`adamant-improvement-proposals` repo) — Cat A process design.
- `halo2_gadgets` exact-pin tightening — small mechanical hardening.

**Genesis + Mainnet (§10–11)**
- Genesis pool mechanism — Cat A.
- Burn-to-mint bridges — Cat A on the Adamant side; per-target-chain integration is bounded-ecosystem-equivalent for the target chain's interface.
- Active-set selection (FCFS + Genesis NFT per §10.2) — Cat A.
- Wallet + explorer + SDKs — Cat A (already in 14-repo allocation).

### 14.6 When the discipline is hard

Two patterns deserve explicit acknowledgement:

**Pattern 1 — "But it's just a small dependency..."**

A small dependency is still a dependency. It pulls a transitive tree, expands the audit surface, and ties the protocol's behaviour to upstream maintenance. The five-category test runs the same way regardless of dependency size. If a small crate fits Category B, D, or E, it's acceptable on those terms; otherwise the question is whether the functionality belongs in Adamant-native code (A or C) or doesn't belong in the protocol at all.

**Pattern 2 — "But this is the standard library for X..."**

Standardisation is one input to the test, not a bypass. RustCrypto's `sha3` is in the locked set because SHA3-256 is FIPS 202; that standardisation is what makes the bounded-ecosystem treatment defensible. Arkworks is the standard library for BLS12-381 + KZG in the Rust ecosystem; the spec-author still chose Adamant-native KZG over arkworks integration because the protocol's resistant-proof posture takes precedence over ecosystem ergonomics. Standardisation is a Category B argument; it doesn't override Categories A or C.

When in doubt, escalate to Ryan rather than silently expand the dependency footprint.
