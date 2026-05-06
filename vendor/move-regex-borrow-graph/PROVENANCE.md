# Provenance: `move-regex-borrow-graph`

This crate is vendored from the Sui ecosystem per whitepaper
section 6.2.1.6 as a direct dependency of `move-bytecode-verifier`
(Batch 2 of the Sui-Move vendoring). It provides the regex-based
borrow graph used for reference safety on regex types in the
verifier's `regex_reference_safety` pass.

This crate is the source of the transitive dependency on
`move-command-line-common` and `move-symbol-pool` that brings six
of the nine new generic workspace dependencies into Batch 2. See
SECURITY.md "Transitive generic-dependency note (Batch 2)" for the
audit-trail context.

## Upstream

- **Project:** Sui (https://github.com/MystenLabs/sui)
- **Path within upstream repo:** `external-crates/move/crates/move-regex-borrow-graph`
- **Release tag:** `mainnet-v1.66.2`
- **Commit SHA at the tagged release:** `a9a6825eaf6273cc819ee3bcf65fd4909f7624a9`
- **Date of release:** 25 February 2026
- **Date of vendoring:** 6 May 2026
- **Upstream license:** Apache-2.0
- **Tarball SHA-256:** `ff223ce3f08fb36d0e0daf0566cec917d97d987242f7709cd2a89c72826a78ba`
  (same tarball as Batch 1 commit `4164e7b`, re-verified at this vendoring)

## Local modifications

The following files differ from upstream:

- **`Cargo.toml`** — workspace-integration only. Specifically:
  - `version`: changed from upstream's literal `"0.0.1"` to
    `version.workspace = true`.
  - `description`: added (upstream had no `description` field);
    points at this `PROVENANCE.md` and the whitepaper subsection.
  - `repository`: added (upstream had no `repository` field);
    set to `https://github.com/MystenLabs/sui`.
  - `authors`: kept as upstream's `["The Move Contributors"]`
    (no augmentation; matches Batch 1's `move-abstract-interpreter`
    pattern).
  - `publish`: kept as upstream's `false`.
  - `edition`: kept as upstream's `"2024"`, declared per-crate.
  - `license`: unchanged (Apache-2.0).
  - `[dependencies]` and `[dev-dependencies]`: dependency specs
    preserved verbatim from upstream (already in
    `<crate>.workspace = true` syntax).
  - `[[test]]`: `borrow_graph_tests` with `harness = false`
    retained from upstream (the integration-test harness in
    `tests/borrow_graph_tests.rs` uses `datatest-stable` rather
    than the default Rust test harness; this drives the 34
    integration tests reported below).
  - `[lints]`: added per-crate `[lints.rust]` and `[lints.clippy]`
    (upstream had no `[lints]` section). The vendored code is
    unsafe-free upstream (`#![forbid(unsafe_code)]` at the top of
    `src/lib.rs`); per-crate lint declaration mirrors that forbid
    plus `[lints.clippy] all = "allow"` per `vendor/README.md`
    "Lints" policy.

No `.rs` file is modified. The `src/` and `tests/` content is
byte-identical to the upstream tag.

### Audit anchor

Byte-identical to
`external-crates/move/crates/move-regex-borrow-graph/src/` and
`tests/` extracted from `sui-mainnet-v1.66.2.tar.gz` (SHA-256
`ff223ce3f08fb36d0e0daf0566cec917d97d987242f7709cd2a89c72826a78ba`),
modulo the Cargo.toml workspace integration and PROVENANCE.md
addition.

## Audit posture

The vendored code's invariants are inherited from the upstream
tagged release. Reviewers verifying this crate's vendoring or
bump check:

1. The vendored content (excluding this `PROVENANCE.md` and the
   `Cargo.toml` modifications listed above) matches the upstream
   tag byte-for-byte.
2. The release tag is the same as Batch 1 (`mainnet-v1.66.2`,
   25 February 2026).
3. Local modifications above are limited to workspace-integration
   concerns rather than semantic changes.
4. The `[lints]` declaration matches workspace policy on
   `unsafe_code = "forbid"`.
