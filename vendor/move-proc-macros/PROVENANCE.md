# Provenance: `move-proc-macros`

This crate is vendored from the Sui ecosystem per whitepaper
section 6.2.1.2 as a transitive dependency of `move-binary-format`
and `move-core-types` (procedural-macro support for derive
attributes used in those crates).

## Upstream

- **Project:** Sui (https://github.com/MystenLabs/sui)
- **Path within upstream repo:** `external-crates/move/crates/move-proc-macros`
- **Release tag:** `mainnet-v1.66.2`
- **Commit SHA at the tagged release:** `a9a6825eaf6273cc819ee3bcf65fd4909f7624a9`
- **Date of release:** 25 February 2026
- **Date of vendoring:** 5 May 2026
- **Upstream license:** Apache-2.0
- **Tarball SHA-256:** `ff223ce3f08fb36d0e0daf0566cec917d97d987242f7709cd2a89c72826a78ba`

## Local modifications

The following files differ from upstream:

- **`Cargo.toml`** — workspace-integration only:
  - `version`: changed to `version.workspace = true`.
  - `edition`: kept as upstream's `"2024"`, per-crate.
  - `authors`, `repository`, `license`: kept as upstream.
  - `publish`: changed from upstream (absent / default `true`) to
    `false`.
  - `description`: added to point at this `PROVENANCE.md`.
  - `[lib] proc-macro = true`: kept as upstream (this is a
    proc-macro crate).
  - `[dependencies]`: kept upstream's mix of workspace inheritance
    (`quote.workspace = true`, `enum-compat-util.workspace = true`)
    and direct version pin (`syn = { version = "2", features = [...] }`
    — `syn` v2 is pinned directly here rather than via workspace
    inheritance because the rest of Sui's tree uses `syn` v1; the
    direct pin lets `move-proc-macros` use v2 syntax tooling
    independently. We accept the resulting `syn` 1.x and 2.x
    coexistence in our lockfile per the discussion in the
    third-commit proposal).
  - `[lints]`: added `workspace = true` (upstream had no
    `[lints]` section). The vendored code is unsafe-free.

No `.rs` file is modified. The `src/` content (113 LOC across
`src/lib.rs` only) is byte-identical to the upstream tag.

### Audit anchor

Byte-identical to
`external-crates/move/crates/move-proc-macros/src/` extracted from
`sui-mainnet-v1.66.2.tar.gz` (SHA-256
`ff223ce3f08fb36d0e0daf0566cec917d97d987242f7709cd2a89c72826a78ba`),
modulo the Cargo.toml workspace integration and PROVENANCE.md
addition.

## Audit posture

Reviewers verifying this crate's vendoring or bump check the same
five points listed in `move-binary-format`'s `PROVENANCE.md`.
