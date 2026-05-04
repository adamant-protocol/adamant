# CLAUDE.md — Project briefing for Claude Code

This file is read automatically by Claude Code at the start of every session. It is the first source of truth for what Adamant is, what we are building, and how we work. **Read it in full before doing anything in this repository.**

---

## What this project is

Adamant is a Layer 1 blockchain protocol. It is being designed and built by **Ryan Geldart** in collaboration with Claude. We are currently in the **specification phase** — there is no Rust code yet. The whitepaper is the working artifact and the source of truth.

The thesis, in one line: **the chain you use when you don't trust anyone.**

The protocol combines: credible neutrality (no foundation, no admin keys, no on-chain governance, no premine), privacy by default (programmable shielded execution), high throughput (200k+ TPS, sub-second finality), phone-verifiable state (recursive zk proofs), encrypted mempool (threshold encryption integrated into consensus), post-quantum cryptography (ML-DSA from genesis), and per-object declared mutability.

No existing chain combines all of these properties. The protocol's contribution is the systems-level synthesis, not new cryptographic primitives.

## Where to read first

Before suggesting any change to anything in this repo, read in this order:

1. `whitepaper/02-design-principles.md` — **the most important file in the repo**. The seven principles in priority order. Every other decision is constrained by these. Proposals that contradict a principle are rejected on principle, not re-litigated.
2. `whitepaper/01-introduction.md` — the gap analysis and the case for the project.
3. `whitepaper/00-abstract.md` — one-page distillation.
4. `whitepaper/README.md` — section-by-section table of contents and current draft status.

If a request to Claude Code conflicts with the design principles, push back on the request. Do not silently compromise the principles to make a task easier.

## How we work

- **Spec drives code, always.** When we begin implementation, the whitepaper is canonical. If implementation reveals a problem with the spec, we update the spec first (in the main chat with Claude), then implement. Never the other way around.
- **Standard primitives only.** We do not roll our own cryptography. We use Ed25519, ML-DSA (FIPS 204), BLS12-381, SHA-3, and Halo 2 via well-maintained Rust libraries (`dalek` ecosystem, `arkworks`, `blst`, `ml_dsa`). Principle VI in the whitepaper.
- **Quality over speed.** Every line ships at production quality or doesn't ship. No "we'll fix it later" placeholders. No copy-pasted boilerplate without understanding what it does.
- **Public from day one.** This repo is public. Anything committed is permanent and visible. Treat every commit message and code comment as a public statement.
- **No tokens, no fundraising, no hype.** This project does not have a token until genesis. Anyone soliciting investment in "Adamant tokens" before genesis is a scammer. The repo and the whitepaper must never include language that resembles investment solicitation.

## Repo structure

Currently:

```
adamant/
├── README.md           Top-level project introduction
├── LICENSE             Apache 2.0
├── .gitignore          Rust-flavoured
├── CLAUDE.md           This file
└── whitepaper/         Working specification (Markdown)
    ├── README.md       Section index
    ├── 00-abstract.md
    ├── 01-introduction.md
    ├── 02-design-principles.md
    └── ... (sections 3-12 to be drafted)
```

When implementation begins, this will expand to include `crates/` (Rust workspace), `specs/` (formal specifications, test vectors), `docs/` (developer documentation), and `tools/` (build scripts and supporting utilities). Until then, the repository is whitepaper-only.

## Tech stack (anticipated, for when we begin coding)

- **Language**: Rust (edition 2021 or later). No exceptions for the node implementation.
- **Async runtime**: `tokio`
- **Networking**: `libp2p` (we do not roll our own P2P stack)
- **Cryptography libraries**: `ed25519-dalek`, `ml_dsa` (RustCrypto), `blst` (BLS12-381), `sha3`, `halo2` (zcash variant)
- **Storage**: `RocksDB` via `rocksdb` crate
- **Consensus**: our own implementation, informed by Mysticeti's published paper (NDSS 2025)
- **Build**: standard Cargo workspace
- **CI**: GitHub Actions
- **Linting**: `clippy` with warnings as errors, `rustfmt` enforced

## What Claude Code should and shouldn't do

**Should:**
- Edit the whitepaper sections to fix typos, clarify language, or update factual details — but flag substantive changes to design for review.
- When code begins, scaffold crates, write implementations, run tests, fix linter errors, write inline documentation.
- Suggest improvements to repo organization, CI configuration, build tooling.
- Catch contradictions between sections of the whitepaper as we draft new ones.

**Should not:**
- Modify the design principles (`whitepaper/02-design-principles.md`) without explicit user approval. The principles are constitutional.
- Roll its own cryptographic primitives. Use vetted libraries.
- Add token-related language, marketing copy, price/value/fundraising content, or anything that sounds like investment solicitation.
- Make decisions that conflict with credible neutrality (no admin keys, no foundation accounts, no governance, no premine) without flagging the conflict explicitly.
- Commit and push without showing the user what is being committed first.

## Communication style

- Be direct. Push back when something looks wrong. Disagree when there's a reason.
- Cite the whitepaper section that backs a recommendation, not just the recommendation.
- When unsure, say so. Don't invent.
- Treat the user as a serious technical collaborator, not someone who needs hand-holding. Skip preambles and confirmations — just do the work and explain what was done.

## Current status

**Phase**: Specification, sections 0–2 drafted.
**Next**: Section 3 (Cryptographic Foundation), Section 4 (Identity & Accounts), Section 5 (Object Model & State).
**Code**: None yet. Begins after specification is at v0.5+ (sections 3–8 minimum).
**Mainnet**: Years away. This is a long project. Pace accordingly.
