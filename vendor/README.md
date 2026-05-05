# Vendored upstream code

This directory holds external code that the Adamant protocol
depends on at consensus level, copied into the workspace from a
specific tagged release of an upstream project. Vendoring is the
protocol's standard mechanism for binding consensus-critical
infrastructure: the audit boundary is in our repo, the version is
under our control, and bumps are deliberate audited events rather
than automatic upgrades.

This is distinct from cryptographic primitive crates (which we
depend on via Cargo with exact-version pins, per the workspace
`Cargo.toml`) because consensus-critical infrastructure has a
different audit profile: the bytecode format flowing through every
module must be byte-stable across implementations, and a stale or
moved upstream tag would be a consensus rule change in disguise.

## Policy

- **What's here.** Move-language crates from the Sui ecosystem,
  per whitepaper section 6.2.1.1 ("Adamant Move bytecode is a
  strict superset of Sui-Move bytecode"). Each vendored crate
  carries a `PROVENANCE.md` documenting the upstream Sui release
  tag, the upstream commit SHA, the date of the vendoring, and
  any local modifications.

- **What's not here.** Cryptographic primitives (in
  `adamant-crypto`'s `Cargo.toml` workspace dependencies),
  developer-tooling crates (in dev-dependencies), and any code
  authored by Adamant contributors (in `crates/`).

- **Lints.** Vendored crates inherit the workspace `[lints]` table
  by default via `[lints] workspace = true`. If a vendored crate
  requires relaxation of any specific lint (typically
  `unsafe_code` for crates that carry upstream `unsafe` blocks),
  the relaxation is declared explicitly in that crate's
  `Cargo.toml` with a doc comment naming the lint and citing the
  upstream invariant the lint conflicts with. Every relaxation is
  listed in `SECURITY.md`'s "Vendored upstream surface" section.

- **Modifications.** Modifying vendored code is permitted only as
  a documented audit-trail commit. The commit message must say
  "Patch vendored <crate>: <one-line summary>" and the
  `PROVENANCE.md` must record the patch with rationale. The
  preferred path is to upstream the patch and bump our vendoring
  to the next Sui release that includes it; local patches are a
  short-term measure.

## Vendoring policy: which Sui release tag

Each vendored crate is sourced from a specific Sui mainnet release
tag. The tag chosen at vendoring time is the latest Sui mainnet
release that has been deployed for at least eight weeks. The
eight-week cushion gives Sui's mainnet time to surface any
post-release issues before Adamant inherits them.

The tag is recorded in each crate's `PROVENANCE.md`. Bumping the
vendored tag (because Sui has shipped an improvement or fix we
want to inherit) is an explicit audit-trail commit; the commit
message documents which tag we're bumping to, what changed in the
upstream diff, and what the impact is on Adamant.

## Audit posture

Vendored code is part of Adamant's audit surface. Reviewers
inspecting a vendoring or vendoring-bump commit verify:

1. The directory naming follows `vendor/<crate-name>/` (matching
   the upstream package name).
2. `PROVENANCE.md` records the tag, commit SHA, date, and any
   local modifications.
3. The vendored code matches the upstream tag byte-for-byte
   (modulo the `PROVENANCE.md` and any documented patches).
4. The crate's `Cargo.toml` declares either `[lints] workspace =
   true` or, if relaxations are required, names them explicitly
   with rationale.
5. `SECURITY.md` is updated in the same commit.

Per CONTRIBUTING.md "Whitepaper commits are Ryan's", vendoring
commits are reviewed by Ryan with the same care as
constitutional changes — the bytecode format flowing through
consensus is genesis-fixed, and a vendoring slip is a consensus
rule change.
