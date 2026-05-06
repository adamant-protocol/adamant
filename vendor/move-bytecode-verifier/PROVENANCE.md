# Provenance: `move-bytecode-verifier`

This crate is part of Batch 2 of the Sui-Move vendoring (whitepaper
§6.2.1.6 — bytecode verifier and validator additions). At this
scaffold commit the workspace plumbing is in place; the actual
upstream source-file copy lands in the follow-up vendor commit
per `vendor/README.md`.

This is the **primary crate of Batch 2**: the Adamant-specific
validator additions in §6.2.1.6 are layered on top of this
verifier in a separate Phase 5 deliverable after the vendor commit
lands cleanly.

## Upstream

- **Project:** Sui (https://github.com/MystenLabs/sui)
- **Path within upstream repo:** `external-crates/move/crates/move-bytecode-verifier`
- **Release tag:** `mainnet-v1.66.2`
- **Commit SHA at the tagged release:** `a9a6825eaf6273cc819ee3bcf65fd4909f7624a9`
- **Date of release:** 25 February 2026
- **Date of vendoring:** *to be filled at the follow-up vendor commit*
- **Upstream license:** Apache-2.0
- **Tarball SHA-256:** `ff223ce3f08fb36d0e0daf0566cec917d97d987242f7709cd2a89c72826a78ba`
  (same tarball as Batch 1 commit `4164e7b`)

## Local modifications

*None at scaffold stage.* At the actual-vendoring commit, this
section enumerates any changes made to the upstream code (typically
limited to `Cargo.toml` adjustments for workspace integration —
`version.workspace = true`, `edition.workspace = true`, etc., and
any targeted upstream-marker patches like the `rust,no_doc` /
`rust,no_run` fixes documented in Batch 1's `move-core-types`).

## Audit posture

The vendored code's invariants are inherited from the upstream
tagged release. Reviewers verifying this crate's vendoring or
bump check:

1. The vendored content (excluding this `PROVENANCE.md` and any
   listed modifications) matches the upstream tag byte-for-byte.
   The audit anchor is the tarball SHA-256 above.
2. The release tag is the same as Batch 1 (`mainnet-v1.66.2`,
   25 February 2026); the eight-week-cushion policy is already
   satisfied by Batch 1's selection.
3. Any local modifications are documented above with rationale
   and are limited to workspace-integration concerns rather than
   semantic changes.
4. The `[lints]` declaration matches workspace policy or, if
   relaxed, the relaxation is documented in `SECURITY.md`'s
   "Vendored upstream surface — Batch 2" section.
