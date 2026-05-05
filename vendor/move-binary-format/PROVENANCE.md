# Provenance: `move-binary-format`

This crate is vendored from the Sui ecosystem per whitepaper
section 6.2.1.2.

## Upstream

- **Project:** Sui (https://github.com/MystenLabs/sui)
- **Path within upstream repo:** `external-crates/move/crates/move-binary-format`
- **Release tag:** `mainnet-v1.66.2`
- **Commit SHA at the tagged release:** `a9a6825eaf6273cc819ee3bcf65fd4909f7624a9`
- **Date of release:** 25 February 2026
- **Date of vendoring:** 5 May 2026
- **Upstream license:** Apache-2.0
- **Tarball SHA-256:** `ff223ce3f08fb36d0e0daf0566cec917d97d987242f7709cd2a89c72826a78ba`
  (the `github.com/MystenLabs/sui/archive/refs/tags/mainnet-v1.66.2.tar.gz`
  artefact downloaded for vendoring)

## Local modifications

The following files differ from upstream:

- **`Cargo.toml`** — workspace-integration only. Specifically:
  - `version`: changed from upstream's literal `"0.0.3"` to
    `version.workspace = true` (resolves to the Adamant workspace
    version, currently `0.0.1`).
  - `edition`: kept as upstream's `"2024"`, declared per-crate
    rather than via workspace inheritance (the Adamant workspace
    declares `edition = "2021"` at the workspace level for
    Adamant-authored crates).
  - `authors`: kept as upstream's attribution (Diem Association,
    The Move Contributors, Mysten Labs).
  - `repository`: kept as upstream Sui repo URL.
  - `license`: unchanged (Apache-2.0).
  - `publish`: changed from upstream's `["crates-io"]` to `false`
    (the Adamant workspace does not publish vendored crates).
  - `description`: changed to point at this `PROVENANCE.md` and the
    whitepaper subsection.
  - `[dependencies]` and `[dev-dependencies]`: dependency specs
    use `<crate>.workspace = true` syntax referencing the Adamant
    workspace's `[workspace.dependencies]` (which mirrors Sui's
    pins at `mainnet-v1.66.2`); the syntax matches upstream
    verbatim (Sui also uses `.workspace = true`), only the
    workspace it inherits from differs.
  - `[features]`: `wasm = ["getrandom"]` retained from upstream
    (its declaration is byte-faithful; the feature is not enabled
    by default).
  - `[lints]`: added `workspace = true` (upstream had no `[lints]`
    section). The vendored code is unsafe-free upstream
    (`#![forbid(unsafe_code)]` at the top of `src/lib.rs`); the
    Adamant workspace lint policy `unsafe_code = "forbid"` is
    consistent with this.

No `.rs` file is modified. The `src/` content is byte-identical to
the upstream tag.

### Audit anchor

Byte-identical to
`external-crates/move/crates/move-binary-format/src/` extracted
from `sui-mainnet-v1.66.2.tar.gz` (SHA-256
`ff223ce3f08fb36d0e0daf0566cec917d97d987242f7709cd2a89c72826a78ba`),
modulo the Cargo.toml workspace integration and PROVENANCE.md
addition.

## Audit posture

The vendored code's invariants are inherited from the upstream
tagged release. Reviewers verifying this crate's vendoring or bump
check:

1. The vendored content (excluding this `PROVENANCE.md` and the
   `Cargo.toml` modifications listed above) matches the upstream
   tag byte-for-byte. Verifiable by re-running the tarball
   download against the SHA-256 above and diffing.
2. The release tag is the most recent Sui mainnet release deployed
   for at least eight weeks at the time of vendoring or bumping
   (per `vendor/README.md` policy). `mainnet-v1.66.2` was released
   25 February 2026; vendoring date is 5 May 2026 (10 weeks elapsed).
3. Local modifications above are limited to workspace-integration
   concerns rather than semantic changes.
4. The `[lints]` declaration matches workspace policy
   (`unsafe_code = "forbid"` honoured at the source level by
   upstream).
