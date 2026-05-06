# Provenance: `move-symbol-pool`

This crate is part of Batch 2 of the Sui-Move vendoring (whitepaper
§6.2.1.6) as a **transitive dependency** of `move-command-line-common`
(itself transitive via `move-regex-borrow-graph`). It provides a
static global string-interning pool used across Sui's Move
tooling. At this scaffold commit the workspace plumbing is in
place; the actual upstream source-file copy lands in the follow-up
vendor commit per `vendor/README.md`.

This crate brings the generic dependency `phf` into Batch 2's
audit surface; it is not a crate the bytecode verifier directly
requires. See SECURITY.md "Transitive generic-dependency note
(Batch 2)" for the audit-trail context.

## Upstream

- **Project:** Sui (https://github.com/MystenLabs/sui)
- **Path within upstream repo:** `external-crates/move/crates/move-symbol-pool`
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

## Inherited upstream unsafe surface (placeholder)

This crate carries upstream `unsafe` (string-interning pattern
inherited from servo/string-cache; per the upstream `src/lib.rs`
header, "symbol-pool ... uses `unsafe` Rust"). The exact unsafe
surface — specific files, line numbers, and SAFETY invariants —
is enumerated at the actual-vendoring commit when the upstream
source files are copied in.

Per-crate `[lints.rust] unsafe_code = "allow"` is declared in
this scaffold's `Cargo.toml` to anticipate the upstream surface.
The same lint posture is used for `move-core-types` (Batch 1) and
`adamant-crypto-blst-extra` (Adamant-authored containment); see
`SECURITY.md` "Vendored upstream surface" and "Adamant-authored
unsafe surface" for the full taxonomy.

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
4. The per-crate `[lints]` declaration relaxes only `unsafe_code`
   (from `forbid` to `allow`), documented in `SECURITY.md`
   "Vendored upstream surface — Batch 2".
5. The unsafe surface enumerated in the section above (filled at
   the vendor commit) matches the upstream code at the SHA above;
   the safety invariants are upstream's responsibility and are
   inherited unchanged.
