# Provenance: `move-core-types`

This crate is vendored from the Sui ecosystem per whitepaper
section 6.2.1.2 as a transitive dependency of `move-binary-format`
(`AccountAddress`, `Identifier`, `TypeTag`, `StructTag`, etc.). The
fields below are filled in at the actual-vendoring commit (the
follow-up to this scaffold per `vendor/README.md`).

## Upstream

- **Project:** Sui (https://github.com/MystenLabs/sui)
- **Path within upstream repo:** `external-crates/move/crates/move-core-types`
- **Release tag:** *to be filled at vendoring time per the
  eight-week-cushion policy in `vendor/README.md`*
- **Commit SHA at the tagged release:** *to be filled at vendoring
  time*
- **Upstream license:** Apache-2.0
- **Date of vendoring:** *to be filled at vendoring time*

## Local modifications

*None at scaffold stage.* At the actual-vendoring commit, this
section enumerates any changes made to the upstream code (typically
limited to `Cargo.toml` adjustments for workspace integration).
Each modification is listed with its rationale.

## Audit posture

The vendored code's invariants are inherited from the upstream
tagged release. Reviewers verifying this crate's vendoring or
bump check the same five points listed in `move-binary-format`'s
`PROVENANCE.md`. The release tag for `move-core-types` matches
the tag for `move-binary-format` — the two crates are vendored as
a coherent pair from the same Sui release.
