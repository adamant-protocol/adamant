# Provenance: `move-binary-format`

This crate is vendored from the Sui ecosystem per whitepaper
section 6.2.1.2. The fields below are filled in at the
actual-vendoring commit (the follow-up to this scaffold per
`vendor/README.md`).

## Upstream

- **Project:** Sui (https://github.com/MystenLabs/sui)
- **Path within upstream repo:** `external-crates/move/crates/move-binary-format`
- **Release tag:** *to be filled at vendoring time per the
  eight-week-cushion policy in `vendor/README.md`*
- **Commit SHA at the tagged release:** *to be filled at vendoring
  time*
- **Upstream license:** Apache-2.0
- **Date of vendoring:** *to be filled at vendoring time*

## Local modifications

*None at scaffold stage.* At the actual-vendoring commit, this
section enumerates any changes made to the upstream code (typically
limited to `Cargo.toml` adjustments for workspace integration —
`version.workspace = true`, `edition.workspace = true`, etc.). Each
modification is listed with its rationale.

## Audit posture

The vendored code's invariants are inherited from the upstream
tagged release. Reviewers verifying this crate's vendoring or
bump check:

1. The vendored content (excluding this `PROVENANCE.md` and any
   listed modifications) matches the upstream tag byte-for-byte.
2. The release tag is the most recent Sui mainnet release deployed
   for at least eight weeks at the time of vendoring or bumping.
3. Any local modifications are documented above with rationale and
   are limited to workspace-integration concerns rather than
   semantic changes.
4. The `[lints]` declaration matches workspace policy or, if
   relaxed, the relaxation is documented in `SECURITY.md`'s
   "Vendored upstream surface" section.
