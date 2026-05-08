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

---

## Section 9: Communication style

- Be direct. Push back when something looks wrong. Disagree when there's a reason.
- Cite the whitepaper section that backs a recommendation, not just the recommendation.
- When unsure, say so. Don't invent.
- Treat Ryan as a serious technical collaborator, not someone who needs hand-holding. Skip preambles, confirmations, and excessive politeness — just do the work and explain what was done.
- Match the whitepaper's tone in commit messages and code comments: precise, honest, no marketing.

---

## Section 10: Current status

**Phase**: 5 — execution VM. Phases 1–4 (crypto, types, account, state structural+lifecycle) complete. Phase 5 deliverables shipped: first (Transaction format + TxHash), second (AdamantBytecode extension types), third (bytecode wire encoding, commit `0d88e8e`), fourth (Sui-Move bytecode-verifier vendoring with Batches 1+2, commit `e6ca254`), and Wave 3a of the fifth deliverable (validator scaffold + Rules 1, 4, 5 + canonical-encoding round-trip, commit `a1789cc`). Phase 5/5a (Adamant-native deserializer + serializer + validator wrapper integration + cross-validation infrastructure) closed at commit `d7fe882` across 5 sub-deliverable commits (`12b65b0`, `73b1986`, `e38e31f`, `cde5046`, `d7fe882`), ~5,500 LOC total. Phase 5/5b.1a (foundation fork of constants + readers + AbilitySet + Identifier into a new `adamant-bytecode-format` crate) closed at commit `a7a06ab`, ~2,413 LOC. Phase 5/5b.1b (25 type-definition fork + index machinery + SignatureToken + full inherited Bytecode enum + CodeUnit + FunctionDefinition + U256 + Metadata + AddressIdentifierPool reusing `adamant_types::Address`) closed at commit `874e701`, ~4,900 LOC. Phase 5/5b.2 closed at `4b03f14`. **Phase 5/5b.3 closed (BoundsChecker + DuplicationChecker + SignatureChecker forks + pipeline integration; all three large module-level passes feature-complete and wired into `verify_module` step-3 batch). Phase 5/5b sub-arcs remaining: 5/5b.4 (per-function passes infrastructure + Rule 3), 5/5b.5 (type-safety/reference-safety per-function passes + Rules 6, 7 + final integration + Sui-verifier bridge tear-out).** Phase 5/5b.3 closure: 9 commits on origin (C-1.1 at `f9050dd`; C-1.2 at `a8e975a`; C-1.3 at `3fe1582`; C-1.4a at `25dfabe`; C-1.4b at `d2a0308`; C-2 at `60d0a53`; C-3 at `34e80de`; C-4 at `fa79976`; C-5 closure commit lands with this state-bump). Workspace test count progression across Phase 5/5b.3: **1035 → 1259 (+224)**. Three large module-level passes ported Adamant-native at C-1 / C-2 / C-3; pipeline integration at C-4 expands `verify_module` step-3 batch from 8 → 11 passes total. Eleven-pass invocation order has two precedence-driven exceptions: bounds_checker first (cross-pass-precedence; `IndexOutOfBounds` reaches first against limits' count overflow); signature_checker before recursive_data_def (cross-pass-pipeline-dependency; signature_checker's `RefAsFieldType` rejection is what makes recursive_data_def's `unreachable!` for refs-in-field-types defensible). 17 new typed-error variants on `AdamantValidationError` across Phase 5/5b.3 (C-1.1: `NoModuleHandles`, `IndexOutOfBounds`, `NumberOfTypeArgumentsMismatch`; C-1.4a: `TooManyLocals`; C-1.4b: `CodeIndexOutOfBounds`, `InvalidEnumSwitch`; C-2: `DuplicateElement`, `ZeroSizedStruct`, `ZeroSizedEnum`, `InvalidModuleHandle`, `DuplicateAcquiresAnnotation`, `UnimplementedHandle`; C-3: `InvalidSignatureToken`, `TypeArgumentsArityMismatch`, `ConstraintNotSatisfied`, `InvalidPhantomTypeParamPosition`, `VecOpExpectedSingleTypeArgument`). Two new public closed enums: `DefKind` (`Struct | Enum | Function`; C-2), `InvalidSignatureReason` (`RefInsideContainer | RefAsFieldType`; C-3). Cross-pass eager-error precedence list grows 2 → 3 instances (Q2 Claim 3: duplication_checker `DuplicateElement(Signature)` wins over signature_checker `InvalidSignatureToken` on overlapping malformed-and-duplicate-signature input — first **different-variant precedence claim shape**, distinct from existing 2 shared-variant claims). Six methodology accumulation streams formalized at C-5 closure: **(1) cross-pass-pipeline-dependency sub-pattern** (NEW; 6th sub-pattern of structural-impossibility-checks); **(2) spec-layer-pinning impossibility sub-pattern** (NEW; 5th sub-pattern); **(3) Adamant-extension treatment in module-level passes** (NEW pattern; rule-of-three threshold met across C-1.4b/C-2/C-3 with 3 sub-shapes); **(4) different-variant precedence claim shape** (NEW; C-4); **(5) variant-vs-test mapping audit principle** (NEW canonical implementation-gate discipline; C-3); **(6) deferred-to-§7 methodology footnote** (NEW; C-1.4b CircuitId pass-through). Plus **(7) commit-message running-total drift discipline** registered at C-5 after the empirical-grep audit found a "20 → 37" baseline drift inherited from B-6's CLAUDE.md state-bump (corrigendum recorded in `crates/adamant-vm/src/validator/module_pass/PROVENANCE.md`). **Spec-pipeline-impossibility-pending-port sub-pattern's 2 instances retired-via-fulfillment** at C-4 when DuplicationChecker + SignatureChecker landed; sub-pattern remains documented for future pending-port deferrals. Phase 5/5 was re-scoped three times: first during the Wave 3b proposal investigation (Phase 5/5 prerequisite for Adamant-native deserializer with Sui-projection inserted ahead of Waves 3b–3d, per amendment `61cec44`); then during the Phase 5/5 implementation proposal investigation when empirical reading of Sui's per-instruction verifier passes surfaced the Nop-projection breakage (re-amendment `0de50d8` to fully-Adamant-native architecture); then during the Phase 5/5b restructured-proposal review when the architectural commitment was extended from "fully Adamant-native verifier" to "fully Adamant-native deploy-time and runtime, resistant-proof against upstream Sui changes" (amendment `19d744b`, merged regen `0651e2f`, twenty-first spec-first instance `6084c32`). Phase 5/5 collapsed from 4 sub-deliverables to 3: 5/5a (closed at `d7fe882`); 5/5b full Adamant-native verifier covering both module-level and per-function passes plus Rules 2, 3, 6, 7, split into 6 sub-arcs (5/5b.1a foundation fork — closed at `a7a06ab`; 5/5b.1b 25 type-definition fork — closed at `874e701`; **5/5b.2** small/medium module-level passes + Rule 2 + privacy_metadata_structure + pipeline integration — closed at `4b03f14`; **5/5b.3** large module-level passes + pipeline integration of all 11 step-3 passes — closed at C-5 with this state-bump; 5/5b.4 per-function passes infrastructure + Rule 3; 5/5b.5 type-safety + reference-safety per-function passes + Rules 6, 7 + final pipeline integration with Sui-verifier bridge fully removed); 5/5c cross-validation infrastructure formalization (T0+T1+T2 tier coverage; T3 real-world corpus deferred to pre-mainnet hardening). **Phase 5/5b: 4 of 6 sub-arcs done.** Phase 5/5b LOC estimate ~10,600-14,950 LOC; total Phase 5/5 ~19,000-27,000 LOC against the original ~5,500-9,000 estimate (3-4x). 5/5b.1a and 5/5b.1b combined ~7,313 LOC actual; Phase 5/5b.2 cumulative ~13,500-14,500 LOC; **Phase 5/5b.3 cumulative ~7,927 LOC actual** across the 9 commits (C-1: ~4,547 LOC across 5 sub-checkpoints; C-2: ~1,665; C-3: ~1,466; C-4: ~249; C-5: documentation-only ~600-900 LOC docs). C-1 sub-arc adapted from planned 4 sub-checkpoints to 5 at the C-1.4 plan-gate per the empirical-complexity-drives-sub-checkpoint-shape pattern; eight-instance LOC-vs-estimate calibration cycle stable at ±25-30% midpoint variance band. Five plan-gate resolution shapes empirically observed across Phase 5/5b.3: plan-was-correct (C-1.2 negatives count); plan-was-ambiguous (C-1.3 preservation pin count); plan-was-conservative (C-1.4a/C-2/C-3/C-4 lower-bound landings); plan-overshot-on-helper-signature (C-1.4b 6→3 params); plan-incremental-disposition-resolved-empirically (C-3 InvalidSignatureReason 2-variant resolution). Waves 3b–3d (Rules 3 and 7 with shared call-graph infrastructure; Rules 2 and 6; Rule 8's gas-bound no-op test) subsumed into Phase 5/5b's per-function-pass sub-arcs (Rules 3, 6, 7 land in 5/5b.4 and 5/5b.5). **Phase 5/5b.4 closed (full per-function pipeline + Rule 3; closure batch lands D-7a Layer B backfill + D-7b documentation closure).** Phase 5/5b.4 ran across **14 commits on origin** spanning 9 logical sub-arcs: D-1 (CFG + AbstractInterpreter framework — foundation-then-producer arc split into D-1a `57b886e` + D-1b `5a56603` + mid-arc state-bump `62a1987`); D-2 (control-flow validation `4bc6eaf`); D-3 (operand-stack discipline `0ceae97`); D-4 (locals safety + acquires `603edf7`); D-5a (type-safety pass — split into D-5a.0 `824d7bc` + D-5a.1.a `952ad69` + D-5a.1.b `6e34f47` per pre-arc-split sub-shape 2); D-5b (reference safety + borrow-graph — split into D-5b.1 `47e1d7a` + D-5b.2 `23788ab`); D-5c (Rule 3 privacy-consistency call-graph walker `5926c7a`); D-6 (pipeline integration `a74f4c8`); D-7 (closure — split into D-7a Layer B backfill `31a22d0` + D-7b documentation closure landing with this state-bump). Workspace test count progression empirically verified at D-7 plan-gate: **1259 → 1532 (+273)** across the phase. AdamantValidationError progression: **50 → 64 (+14)** typed variants. **Public closed enums grew 5 → 9 (+4):** `IrreducibleReason` (D-2), `TypeMismatchReason` (D-5a.0), `BorrowViolationReason` (D-5b.2), `PrivacyConsistencyViolationReason` (D-5c). Verification gate count grows 8 → 11 (9th D-1 plan-gate via §6.2.1.8 line 526; 10th D-3 plan-gate via §6.2.1.4 per-extension stack-effects; 11th D-5c plan-gate via §6.2.1.6 spec binding). 5 per-function passes ported Adamant-native + 1 Adamant-specific rule (Rule 3) + per-function-pass infrastructure (CFG + AbstractInterpreter + AbstractStack + BorrowGraph). Helper extracted at D-7a: `function_pass/test_helpers.rs` with 6 helpers (extract-at-N=3 sub-shape β of the helper-extraction discipline; module_pass extract-at-N=2 at B-2.2 is sub-shape α, chronological naming preserved per D-7b plan-gate). **Methodology streams formalized at D-7b** (full enumeration in PROVENANCE.md "Phase 5/5b.4 closure — methodology accumulation streams" section): rule-of-three thresholds met across the phase for sub-shape 2 (pre-arc-split: C-1.4/D-1/D-5a/D-5b — 4 instances; sub-shape 2 well-established), sub-shape 3 (Adamant-extension treatment pass-through: C-3/D-1a/D-2/D-4 — 4 instances), shielding-vs-runtime canonical pattern (D-3/D-5a.1.b/D-5b.2 cross-pass consistency on Categories C+D), spec-text-DIRECTS-shared-helper canonical principle (D-5a.1.b/D-5b.2/D-5c), verbatim-survey-at-plan-gate-prevents-scope-error pattern (D-3/D-5b/D-5c), Open Layer B gaps deferred to pre-mainnet hardening (C-5 SuiVerifier / D-5b.2 BorrowViolationReason 6-of-13 / D-7a st_loc_destroys_non_drop). Plus 6 new patterns at sub-rule-of-three threshold registered at D-7b for forward-tracking: Sui-public-API-shape-constrains-parity-helper sub-pattern (1st instance D-7a), helper-extraction discipline canonical with 2 sub-shapes (α=N=2 module_pass / β=N=3 function_pass), sub-shape 4 of structural-impossibility-checks (`expect()`-three-anchor; 1st instance D-5a.1.a), hoisted-enum-for-clippy-items-after-statements (1st instance D-1a `Exploration`), upstream-consolidates-undershoot calibration (1st instance D-1b AbstractInterpreter consolidation), bridge-as-soundness-test-infrastructure framing + bridge-redundancy-validation tests as Layer B alternative (1st instances D-6; bounded in time — resolve at 5/5b.5 bridge tear-out). **Cross-pass eager-error precedence list stays at 3 instances** (no new precedence claims at D-6; Q4 Claim 1 BoundsChecker-vs-limits retired-via-empirical-absence per D-6 plan-gate disposition; new sub-pattern: 4th-precedence-claim-retired-via-empirical-absence registered at D-7b). **Commit-message running-total drift discipline operating at full effectiveness — 2nd instance** caught at D-7 plan-gate (D-3-to-D-4 baseline error: D-3 didn't claim workspace count, D-4 inherited a wrong baseline 1328 vs empirical 1362, drift propagated through 8 subsequent commits with correct deltas on wrong baseline; D-7b corrigendum parallel to B-6 in `crates/adamant-vm/src/validator/module_pass/PROVENANCE.md`). **Phase 5/5b: 5 of 6 sub-arcs done.** Phase 5/5b sub-arc remaining: **5/5b.5** (Sui-verifier bridge tear-out + 13 vendored Sui-Move crate removal from production-binary deps + Rules 6, 7 implementation + Rule 8 runtime gas-bound no-op test + cross-module Rule 3 enforcement at deployment-validator wiring + `tests/no_sui_in_production_deps.rs` build-system independence check).

**Specification**: complete v0.1 draft, twenty-one spec-first verification instances landed and recorded in CONTRIBUTING.md. The most recent batch (sixteenth–nineteenth) resolved the §6.2.1 deserializer / verifier-architecture gap surfaced during the Wave 3b proposal investigation (amendment `61cec44`, merged regen `1109bab`, CONTRIBUTING.md instances `fcce531`). The twentieth instance resolved the Nop-projection breakage surfaced during the Phase 5/5 implementation proposal investigation (re-amendment `0de50d8`, merged regen `2401227`, CONTRIBUTING.md instance `3b65686`). The twenty-first instance resolved the resistant-proof posture extension during the Phase 5/5b restructured-proposal review: §6.2.1.8's "fully Adamant-native verifier" commitment extended to "fully Adamant-native deploy-time and runtime"; production binary's dependency graph cannot include vendored Sui crates; vendor refresh is a development-time signal, not a consensus event (amendment `19d744b`, merged regen `0651e2f`, CONTRIBUTING.md instance `6084c32`). The §10/§11 launch model was rewritten in May 2026 to use a 100,000,000 ADM genesis pool with burn-to-mint and validator-reward acquisition paths, replacing the prior pure burn-launch mechanism. The design proposal lives at `/whitepaper/proposals/genesis-pool-mechanism.md` and records the deliberation history; the whitepaper amendment lives in §10 and §11.

**Code**: 20 workspace members at present. 7 Adamant-authored crates (`adamant-account`, `adamant-bytecode-format`, `adamant-crypto`, `adamant-crypto-blst-extra`, `adamant-state`, `adamant-types`, `adamant-vm`) plus 13 vendored Sui-Move crates at tag `mainnet-v1.66.2` — Batch 1 (`move-binary-format`, `move-core-types`, `enum-compat-util`, `move-proc-macros`, `move-abstract-interpreter`) and Batch 2 (`move-bytecode-verifier`, `move-borrow-graph`, `move-bytecode-verifier-meter`, `move-vm-config`, `move-abstract-stack`, `move-regex-borrow-graph`, `move-command-line-common`, `move-symbol-pool`). Phase 5/5b.5 will move the 13 vendored Sui-Move crates from runtime dependencies to test-only dev-dependencies of the production-binary target, with a build-system independence check (`tests/no_sui_in_production_deps.rs`) walking the resolved dependency tree via `cargo metadata` and asserting no `move-*` crate appears. **1532 tests passing across the workspace at Phase 5/5b.4 closure** (1259 at Phase 5/5b.3 closure + 273 across D-1a/D-1b/D-2/D-3/D-4/D-5a/D-5b/D-5c/D-6/D-7a). Workspace test count progression across Phase 5/5b.4: **1259 → 1532 (+273)** (empirically verified at D-7 plan-gate; corrects the inherited-baseline-on-wrong-baseline arithmetic from D-4 → D-6 commit messages — see "Corrigendum: D-3-to-D-4 baseline error" in `crates/adamant-vm/src/validator/module_pass/PROVENANCE.md`). Test breakdown at Phase 5/5b.4 closure: `adamant-bytecode-format` 96 lib unit tests + 55 cross-validation tests (unchanged through Phase 5/5b.4); `adamant-vm` lib test count 588 → 830 (+242) across Phase 5/5b.4. Phase 5/5b.4 per-sub-arc test additions across `validator/function_pass/`: D-1a (+18 CFG construction); D-1b (+13 AI framework with synthetic SawPop domain); D-2 (+32 control-flow); D-3 (+36 stack_usage); D-4 (+23 locals_safety); D-5a (+53 type-safety across .0/.1.a/.1.b); D-5b (+47 reference-safety + borrow-graph across .1/.2); D-5c (+15 Rule 3 privacy-consistency); D-6 (+6 integration + bridge-redundancy validation); D-7a (+26 Layer B cross-validation across control_flow / stack_usage / locals_safety). **Production-dependency posture at Phase 5/5b.4 closure:** `petgraph 0.8.x` remains the only non-Sui-vendor-derived production dep on `adamant-vm` (added at B-3.2; no new external production deps across all of Phase 5/5b.4 per the seven-criterion external-production-dep audit template). The transitional Sui-verifier bridge in `validator/mod.rs::verify_module` is retained behind `if !module.contains_adamant_extensions()` for inherited-subset modules through Phase 5/5b.4; tears out at 5/5b.5 alongside the production-target dependency-tree independence check. **Bridge serves dual roles at Phase 5/5b.4 closure:** defense-in-depth on inherited-subset modules AND soundness-test infrastructure for cross-pass-pipeline-dependency drift detection (D-6 framing); D-6 integration tests #5 + #6 assert bridge-redundancy via composite-level Layer B coverage. Per-pass Layer B coverage backfilled at D-7a for D-2/D-3/D-4 (~26 parity tests); D-5a/D-5b/D-5c had no inline parity tests per D-7a empirical-grep retrofit-need check (Sui's per-pass entries `pub(crate)`-bounded; Adamant adapts to composite-pipeline parity via `code_unit_verifier::verify_module` per the new Sui-public-API-shape-constrains-parity-helper sub-pattern registered at D-7b). **`AdamantValidationError` carries 64 typed variants at Phase 5/5b.4 closure** (empirically grep-confirmed; pre-Phase-5/5b.4 baseline was 50; Phase 5/5b.4 added 14). **9 public closed enums** at Phase 5/5b.4 closure: `MalformedConstantReason` (B-2.1), `FieldOwnerKind` (B-2.3), `HandleKind` (B-3.1), `DefKind` (C-2), `InvalidSignatureReason` (C-3), `IrreducibleReason` (D-2), `TypeMismatchReason` (D-5a.0), `BorrowViolationReason` (D-5b.2), `PrivacyConsistencyViolationReason` (D-5c) — all re-exported via `validator/mod.rs`. **6 helpers extracted at D-7a** (function_pass test_helpers): `to_sui`, `sui_config_from`, `assert_function_pass_parity` (PartialVMResult), `assert_function_pass_parity_vm` (VMResult), `run_adamant_pipeline`, `run_sui_code_unit_verifier`. **Variant-vs-test mapping audit appendix added at D-7b** for the 14 new Phase 5/5b.4 variants — all 14 have explicit negative-test coverage. Combined audit state at D-7b closure: **63 of 64 variants have explicit negative test coverage**; 1 gap is the `SuiVerifier` transitional-bridge variant (registered at C-5; deferred to natural resolution at 5/5b.5 bridge tear-out). **11 deliberate-Adamant-decision instances** at Phase 5/5b.4 closure (1 from 5/5b.2; 2 from 5/5b.3; 8 across 5/5b.4) — full enumeration in `crates/adamant-vm/src/validator/module_pass/PROVENANCE.md` "Deliberate-Adamant-decision pattern" section.

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
