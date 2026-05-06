# Provenance: `move-bytecode-verifier`

This crate is vendored from the Sui ecosystem per whitepaper
section 6.2.1.6 as the **primary crate of Batch 2** of the
Sui-Move vendoring. The Adamant-specific validator additions
(eight rules layered on top of this verifier, including rejection
of deprecated global-storage instructions per §6.2.1.6 rule 5)
are a separate Phase 5 deliverable that depends on this vendoring
landing cleanly.

## Upstream

- **Project:** Sui (https://github.com/MystenLabs/sui)
- **Path within upstream repo:** `external-crates/move/crates/move-bytecode-verifier`
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
    `version.workspace = true` (resolves to the Adamant workspace
    version, currently `0.0.1`).
  - `description`: changed from upstream's `"Move bytecode verifier"`
    to one pointing at this `PROVENANCE.md` and the whitepaper
    subsection.
  - `repository`: changed from upstream's
    `https://github.com/diem/diem` to
    `https://github.com/MystenLabs/sui` (where the vendored copy
    actually comes from; same change as Batch 1).
  - `homepage`: removed from upstream's `https://diem.com` (no
    longer relevant; same change as Batch 1).
  - `authors`: augmented from upstream's
    `["Diem Association <opensource@diem.com>"]` to the full
    historical lineage (Diem Association, The Move Contributors,
    Mysten Labs); same pattern as Batch 1.
  - `publish`: kept as upstream's `false`.
  - `edition`: kept as upstream's `"2024"`, declared per-crate
    (the Adamant workspace declares `edition = "2021"` at the
    workspace level for Adamant-authored crates).
  - `license`: unchanged (Apache-2.0).
  - `[dependencies]` and `[dev-dependencies]`: dependency specs
    preserved verbatim from upstream (already in
    `<crate>.workspace = true` syntax referencing the Adamant
    workspace's `[workspace.dependencies]`, which mirrors Sui's
    pins at `mainnet-v1.66.2`).
  - `[features]`: `default = []` retained from upstream.
  - `[lints]`: added per-crate `[lints.rust]` and `[lints.clippy]`
    (upstream had no `[lints]` section). The vendored code is
    unsafe-free upstream (`#![forbid(unsafe_code)]` at the top of
    `src/lib.rs`); the per-crate lint declaration mirrors that
    forbid plus `[lints.clippy] all = "allow"` per
    `vendor/README.md` "Lints" policy (style lints deferred to
    upstream CI).

No `.rs` file is modified. The `src/` content is byte-identical
to the upstream tag.

The `README.md` from the upstream crate root is not vendored
(matching Batch 1's policy — only `src/` and `Cargo.toml` are
required for the workspace; the upstream README is not part of
the audit anchor).

### Audit anchor

Byte-identical to
`external-crates/move/crates/move-bytecode-verifier/src/`
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
   tag byte-for-byte. Verifiable by re-running the tarball
   download against the SHA-256 above and diffing.
2. The release tag is the same as Batch 1 (`mainnet-v1.66.2`,
   25 February 2026); the eight-week-cushion policy is satisfied
   by Batch 1's selection.
3. Local modifications above are limited to workspace-integration
   concerns rather than semantic changes.
4. The `[lints]` declaration relaxes only `[lints.clippy] all`
   (deferred to upstream CI), matching Batch 1's pattern; the
   workspace lint table is mirrored on `unsafe_code = "forbid"`.
