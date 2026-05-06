# Provenance: `move-command-line-common`

This crate is part of Batch 2 of the Sui-Move vendoring (whitepaper
§6.2.1.6) as a **transitive dependency** of `move-regex-borrow-graph`,
not a crate the bytecode verifier directly requires. It provides
shared command-line and file-handling helpers used across Sui's
Move tooling. At this scaffold commit the workspace plumbing is in
place; the actual upstream source-file copy lands in the follow-up
vendor commit per `vendor/README.md`.

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
- **Date of vendoring:** *to be filled at the follow-up vendor commit*
- **Upstream license:** Apache-2.0
- **Tarball SHA-256:** `ff223ce3f08fb36d0e0daf0566cec917d97d987242f7709cd2a89c72826a78ba`
  (same tarball as Batch 1 commit `4164e7b`)

## Local modifications

*None at scaffold stage.* At the actual-vendoring commit, this
section enumerates any changes made to the upstream code.

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
