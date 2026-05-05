# Provenance: `move-abstract-interpreter`

This crate is vendored from the Sui ecosystem per whitepaper
section 6.2.1.2 as a transitive dependency of `move-binary-format`
(abstract-interpretation framework over Move bytecode).

## Upstream

- **Project:** Sui (https://github.com/MystenLabs/sui)
- **Path within upstream repo:** `external-crates/move/crates/move-abstract-interpreter`
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
  - `authors`, `license`: kept as upstream.
  - `repository`: added (upstream had no `repository` field;
    pointed at Sui's repo for vendored attribution).
  - `publish`: kept as upstream's `false`.
  - `description`: added to point at this `PROVENANCE.md`.
  - `[dev-dependencies]`: `itertools.workspace = true` syntax
    matches upstream verbatim.
  - `[features] default = []`: kept as upstream.
  - `[lints]`: added `workspace = true` (upstream had no
    `[lints]` section). The vendored code is unsafe-free.

No `.rs` file is modified. The `src/` content (601 LOC across
`src/lib.rs` 5 LOC, `src/absint.rs` 213 LOC, and
`src/control_flow_graph.rs` 383 LOC) is byte-identical to the
upstream tag.

### Audit anchor

Byte-identical to
`external-crates/move/crates/move-abstract-interpreter/src/`
extracted from `sui-mainnet-v1.66.2.tar.gz` (SHA-256
`ff223ce3f08fb36d0e0daf0566cec917d97d987242f7709cd2a89c72826a78ba`),
modulo the Cargo.toml workspace integration and PROVENANCE.md
addition.

## Audit posture

Reviewers verifying this crate's vendoring or bump check the same
five points listed in `move-binary-format`'s `PROVENANCE.md`. This
crate is the smallest vendored component (601 LOC, zero runtime
dependencies, only `itertools` as a dev-dep) and provides the
abstract-interpretation framework over Move bytecode that
`move-binary-format` consumes for static analysis.
