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

**Phase**: 5 — execution VM. Phases 1–4 (crypto, types, account, state structural+lifecycle) complete. Phase 5 deliverables shipped: first (Transaction format + TxHash), second (AdamantBytecode extension types), third (bytecode wire encoding, commit `0d88e8e`), fourth (Sui-Move bytecode-verifier vendoring with Batches 1+2, commit `e6ca254`), and Wave 3a of the fifth deliverable (validator scaffold + Rules 1, 4, 5 + canonical-encoding round-trip, commit `a1789cc`). The fifth deliverable's remaining work was re-scoped twice: first during the Wave 3b proposal investigation (a Phase 5/5 prerequisite for an Adamant-native deserializer with Sui-projection was inserted ahead of Waves 3b–3d, per amendment 61cec44); then during the Phase 5/5 implementation proposal investigation, when empirical reading of Sui's per-instruction verifier passes surfaced that the Nop-projection mechanism breaks on non-trivial Adamant code (3 of 4 passes fail). Phase 5/5 was re-amended to a fully-Adamant-native verifier architecture (commit `0de50d8`) and expanded into four sub-deliverables totaling ~5500-9000 LOC: 5/5a (Adamant-native deserializer + serializer), 5/5b (module-level passes), 5/5c (per-function passes), 5/5d (cross-validation infrastructure against the vendored reference). Waves 3b–3d (Rules 3 and 7 with shared call-graph infrastructure; Rules 2 and 6; Rule 8's gas-bound no-op test) push back behind Phase 5/5 completion.

**Specification**: complete v0.1 draft, twenty spec-first verification instances landed and recorded in CONTRIBUTING.md. The most recent batch (sixteenth–nineteenth) resolved the §6.2.1 deserializer / verifier-architecture gap surfaced during the Wave 3b proposal investigation (amendment 61cec44, merged regen 1109bab, CONTRIBUTING.md instances fcce531). The twentieth instance resolved the Nop-projection breakage surfaced during the Phase 5/5 implementation proposal investigation (re-amendment 0de50d8, merged regen 2401227, CONTRIBUTING.md instance 3b65686). The §10/§11 launch model was rewritten in May 2026 to use a 100,000,000 ADM genesis pool with burn-to-mint and validator-reward acquisition paths, replacing the prior pure burn-launch mechanism. The design proposal lives at `/whitepaper/proposals/genesis-pool-mechanism.md` and records the deliberation history; the whitepaper amendment lives in §10 and §11.

**Code**: 19 workspace members. 6 Adamant-authored crates (`adamant-account`, `adamant-crypto`, `adamant-crypto-blst-extra`, `adamant-state`, `adamant-types`, `adamant-vm`) plus 13 vendored Sui-Move crates at tag `mainnet-v1.66.2` — Batch 1 (`move-binary-format`, `move-core-types`, `enum-compat-util`, `move-proc-macros`, `move-abstract-interpreter`) and Batch 2 (`move-bytecode-verifier`, `move-borrow-graph`, `move-bytecode-verifier-meter`, `move-vm-config`, `move-abstract-stack`, `move-regex-borrow-graph`, `move-command-line-common`, `move-symbol-pool`). 624 unit tests passing across the workspace as of Wave 3a.

**Vendoring posture**: vendored Sui code stays byte-faithful, with documented doc-marker patches enumerated in each crate's `PROVENANCE.md`. Vendored Sui crates' role at deploy-time pivoted with the §6.2.1.8 re-amendment at commit `0de50d8`: previously framed as "Option II extends to the module-level deserialize and verifier-projection layers" (Sui crates on the deploy-time hot path via Nop-projection), now framed as **test-time reference implementation** for the inherited subset's semantics. Adamant provides its own deserializer, serializer, and verifier (module-level + per-function passes) covering the full Adamant superset; vendored Sui crates remain at `mainnet-v1.66.2` and are exercised by Phase 5/5d's cross-validation infrastructure to confirm Adamant's verifier produces identical accept/reject decisions to Sui's verifier on the inherited Sui-base subset. The pivot was driven by empirical infeasibility of the Nop-projection mechanism (3 of 4 per-function Sui passes fail on Nop-substituted Adamant modules; full enumeration in CONTRIBUTING.md's twentieth instance), genesis-fixed posture (verifier accept/reject is consensus-binding and cannot drift with Sui upstream), and audit surface (a fully-Adamant-native verifier is under Adamant's audit and maintenance with no "what does Sui do here" hot-path question for auditors). Wire encoding implementation is Option II (re-implement instruction-level serialization in `adamant-vm`) rather than Option I (patch vendored Sui to expose internals) — this preserves the byte-faithfulness audit anchor; Phase 5/5 extends the same Option II posture to the module-level and verifier layers.

**Architectural decisions on record**: (1) §6.2.1.6 Rule 5's enforcement point shifted from "Sui's verifier with `deprecate_global_storage_ops = true`" to "Sui's deserializer with `deprecate_global_storage_ops = true`" — empirical investigation surfaced that Sui's `BoundsChecker` treats deprecated variants as a `safe_assert!` invariant (panics in debug, returns error in release); the actual rejection happens at parse time. (2) The Wave 3a wrapper API takes module bytes and returns a parsed `CompiledModule` rather than taking `&CompiledModule` — this places Rule 5 enforcement at the architecturally correct pipeline stage and removes a caller-side deserializer-config footgun. (3) A canonical-encoding round-trip check landed in Wave 3a as a strengthening property: the wrapper re-serializes the parsed module via Sui's serializer at the module's own version and byte-compares against the input; non-canonicality (trailing junk bytes, alternate encodings) surfaces as `AdamantValidationError::NonCanonicalBytecode`. The check recovers the canonicality `check_no_extraneous_bytes = true` would have provided in Sui's deserializer config (which Adamant cannot use because it also rejects the metadata table Adamant needs per §6.2.1.3). (4) The §6.2.1.8 architecture pivoted from Sui-projection to fully Adamant-native after the Nop-projection mechanism was empirically demonstrated to break Sui's stack/type/reference passes for non-trivial Adamant code; vendored Sui crates moved off the deploy-time hot path to a test-time reference role.

**Open properties to track**: (1) Thin upstream verifier test surface from Batch 2 — `move-bytecode-verifier` carries 4 unit tests vs Batch 1's `move-binary-format` at 68; Sui exercises verifier behavior at the VM-integration level we did not vendor. Phase 5/5 (Adamant-native deserializer + verifier passes + cross-validation against the vendored reference) carries more correctness-establishing weight than usual — it is where the validator's behavior is genuinely exercised through real validation paths against real Move modules. The previously-deferred Adamant-side per-instruction extension verification (full stack/type/reference safety for the 17 extensions) is now in scope for Phase 5/5c (per-function passes) — no longer deferred. (2) `GenerateProof`, `VerifyProof`, and `RecursiveVerify` stack effects are parametric in circuit signatures resolved through the operand's `CircuitId`; circuit-signature resolution is deferred to §7 (privacy layer). The verifier's stack-balance check on these instructions cannot ship statically until §7 lands; until then, runtime stack-balance enforcement carries the binding — same shielding-vs-runtime pattern as Rule 3.

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

- **Ryan is the founder.** Substantive design decisions go through Ryan, not through you alone. If something significant comes up, surface it for Ryan's decision rather than choosing silently.

---

## Section 12: When in doubt

- Re-read `/whitepaper/02-design-principles.md`.
- Cite the section number when explaining a decision.
- Ask Ryan rather than assume.
- Prefer the conservative choice. We are building infrastructure for users who do not trust anyone, including us. Caution is a feature.
