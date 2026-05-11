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
| 7.2 | §8.2, 8.3.2 | epoch / round semantics | pending |
| 7.3 | §8.3.1 | DAG vertex structure | pending |
| 7.4 | §8.6 | consensus VRF | pending |
| 7.5 | §3.8, 8.4.4 | time-lock VDF | pending (large) |
| 7.6 | §3.6, 8.4 | threshold mempool + two-regime hysteresis | pending |
| 7.7 | §8.3, 8.7 | DAG-BFT consensus core | pending (large) |
| 7.8 | §9 | networking + transaction propagation | pending |
| 7.9 | §8.1.7, 8.9 | light client + tier signal | pending |
| 7.10 | §8.1.5, §10 | slashing wiring + economics | pending |
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

Decision rule: **infrastructure-tier crates are acceptable when they are mature, non-consensus, and where reimplementation is audit-net-negative. Consensus-adjacent crates (e.g., `ethnum` for U256) are pre-mainnet revisit candidates: confirm at hardening time whether reimplementation is warranted.**

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
- P2P networking — **Posture decision pending**: `libp2p` (bounded-ecosystem-equivalent for networking infrastructure) vs Adamant-native protocol stack. Decide at Phase 7 networking plan-gate.
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
