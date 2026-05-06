# Provenance: `move-command-line-common`

This crate is vendored from the Sui ecosystem per whitepaper
section 6.2.1.6 as a **transitive dependency** of
`move-regex-borrow-graph` (Batch 2 of the Sui-Move vendoring),
not a crate the bytecode verifier directly requires. It provides
shared command-line and file-handling helpers used across Sui's
Move tooling.

This crate is the entry point for six of the nine new generic
workspace dependencies in Batch 2 (`colored`, `dirs-next`,
`packed_struct`, `sha2`, `vfs`, `walkdir`) plus the further
transitive vendored crate `move-symbol-pool`. None of these enter
the audit surface because the bytecode verifier directly needs
them — they enter because Sui's `move-regex-borrow-graph` declares
this crate as a dependency. See SECURITY.md "Transitive
generic-dependency note (Batch 2)" for the audit-trail context.

## Upstream

- **Project:** Sui (https://github.com/MystenLabs/sui)
- **Path within upstream repo:** `external-crates/move/crates/move-command-line-common`
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
  - `version`: changed from upstream's literal `"0.1.0"` to
    `version.workspace = true`.
  - `description`: changed from upstream's
    `"Move shared command line and file tools"` to one pointing
    at this `PROVENANCE.md` and the whitepaper subsection (also
    flagging the transitive-via-move-regex-borrow-graph status).
  - `repository`: changed from upstream's
    `https://github.com/diem/diem` to
    `https://github.com/MystenLabs/sui`.
  - `homepage`: removed from upstream's `https://diem.com`.
  - `authors`: augmented from upstream's
    `["Diem Association <opensource@diem.com>"]` to the full
    historical lineage (Diem Association, The Move Contributors,
    Mysten Labs).
  - `publish`: kept as upstream's `false`.
  - `edition`: kept as upstream's `"2024"`, declared per-crate.
  - `license`: unchanged (Apache-2.0).
  - `[dependencies]` and `[dev-dependencies]`: dependency specs
    preserved verbatim from upstream (already in
    `<crate>.workspace = true` syntax).
  - `[lints]`: added per-crate `[lints.rust]` and `[lints.clippy]`
    (upstream had no `[lints]` section). The vendored code has no
    top-level `forbid(unsafe_code)` attribute upstream but is
    unsafe-free in practice (no `unsafe` blocks or `unsafe fn`
    in `src/`); per-crate lint declaration enforces
    `unsafe_code = "forbid"` for the workspace. Clippy lints
    deferred to upstream CI per `vendor/README.md` "Lints" policy.

No `.rs` file is modified. The `src/` content is byte-identical
to the upstream tag.

### Audit anchor

Byte-identical to
`external-crates/move/crates/move-command-line-common/src/`
extracted from `sui-mainnet-v1.66.2.tar.gz` (SHA-256
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
