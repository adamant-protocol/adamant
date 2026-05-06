# Provenance: `move-borrow-graph`

This crate is vendored from the Sui ecosystem per whitepaper
section 6.2.1.6 as a direct dependency of `move-bytecode-verifier`
(Batch 2 of the Sui-Move vendoring). It provides the borrow-graph
data structure used by the verifier's reference-safety pass.

## Upstream

- **Project:** Sui (https://github.com/MystenLabs/sui)
- **Path within upstream repo:** `external-crates/move/crates/move-borrow-graph`
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
  - `authors`: augmented from upstream's
    `["Diem Association <opensource@diem.com>"]` to the full
    historical lineage (Diem Association, The Move Contributors,
    Mysten Labs).
  - `publish`: kept as upstream's `false`.
  - `edition`: kept as upstream's `"2024"`, declared per-crate.
  - `license`: unchanged (Apache-2.0).
  - `[dependencies]`: empty (upstream is dep-free).
  - `[lints]`: added per-crate `[lints.rust]` and `[lints.clippy]`
    (upstream had no `[lints]` section). The vendored code is
    unsafe-free upstream (`#![forbid(unsafe_code)]` at the top of
    `src/lib.rs`); the per-crate lint declaration mirrors that
    forbid plus `[lints.clippy] all = "allow"` per
    `vendor/README.md` "Lints" policy.

No `.rs` file is modified. The `src/` content is byte-identical
to the upstream tag.

### Audit anchor

Byte-identical to
`external-crates/move/crates/move-borrow-graph/src/` extracted
from `sui-mainnet-v1.66.2.tar.gz` (SHA-256
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
