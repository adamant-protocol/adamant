# Provenance: `move-core-types`

This crate is vendored from the Sui ecosystem per whitepaper
section 6.2.1.2 as a transitive dependency of `move-binary-format`.

## Upstream

- **Project:** Sui (https://github.com/MystenLabs/sui)
- **Path within upstream repo:** `external-crates/move/crates/move-core-types`
- **Release tag:** `mainnet-v1.66.2`
- **Commit SHA at the tagged release:** `a9a6825eaf6273cc819ee3bcf65fd4909f7624a9`
- **Date of release:** 25 February 2026
- **Date of vendoring:** 5 May 2026
- **Upstream license:** Apache-2.0
- **Tarball SHA-256:** `ff223ce3f08fb36d0e0daf0566cec917d97d987242f7709cd2a89c72826a78ba`

## Local modifications

### Cargo.toml workspace integration (no semantic changes)

- `version`: changed from upstream's literal `"0.0.4"` to
  `version.workspace = true`.
- `edition`: kept as upstream's `"2024"`, declared per-crate.
- `authors`, `repository`, `license`: kept as upstream
  attribution.
- `publish`: changed from upstream's `["crates-io"]` to `false`.
- `description`: changed to point at this `PROVENANCE.md`.
- `[dependencies]` and `[dev-dependencies]`: dependency specs
  use `<crate>.workspace = true` syntax referencing the Adamant
  workspace's `[workspace.dependencies]`; syntax matches
  upstream verbatim.
- `[lints]`: per-crate lints declared with `unsafe_code = "allow"`
  (cannot use `[lints] workspace = true` because the workspace
  forbids `unsafe_code` and this crate carries upstream
  `unsafe`); see the parallel pattern in
  `adamant-crypto-blst-extra` and CONTRIBUTING.md
  "Unsafe-containment architecture". Clippy lints deferred to
  upstream Sui's CI per `vendor/README.md`.

### Source-file modifications (upstream documentation marker fixes)

Two related upstream issues, both fixed by changing the doc-block
marker to `ignore`:

**Issue 1 — `rust,no_doc` (4 occurrences).** `no_doc` is not a
valid rustdoc marker; rustdoc treats it as a regular Rust block
and attempts to compile-and-run it, producing test failures. The
upstream intent was clearly to mark the blocks as
illustrative-only (matching the surrounding context of
trait-method documentation fragments). Patched to `rust,ignore`.

- `src/annotated_visitor.rs`: 3 occurrences (lines 18, 24, 160)
- `src/runtime_visitor.rs`: 1 occurrence (line 20)

**Issue 2 — `rust,no_run` (2 occurrences).** `no_run` is a valid
rustdoc marker meaning "compile but don't execute." However, the
specific blocks tagged with it are trait-method fragments that
aren't standalone-compilable (they reference types and methods
only available in the surrounding trait context), so rustdoc
fails to compile them. The upstream intent (per the surrounding
documentation context) was clearly the same as Issue 1:
illustrative-only. The correct marker is `ignore`, not `no_run`.
Patched to `rust,ignore`.

- `src/annotated_visitor.rs`: line 249
- `src/runtime_visitor.rs`: line 109

Both patches are upstream-fix candidates: they make rustdoc
honour what the surrounding context shows the upstream author
clearly intended. The preferred long-term path is to upstream
both fixes and bump our vendoring to the next Sui release that
includes them (per `vendor/README.md` "Modifications" policy).
Until then, both are documented local modifications.

### Inherited upstream unsafe surface

The `unsafe` surface inherited from upstream is **two** instances
in `src/identifier.rs`:

1. `pub unsafe fn new_unchecked(s: impl Into<Box<str>>) -> Self`
   — a public unsafe constructor whose caller asserts that the
   input string is a valid Move identifier. Used in
   performance-sensitive paths where validation has already
   happened upstream.
2. An `unsafe { ... }` block performing a `transmute`-equivalent
   reborrow at line 343, with a SAFETY comment immediately above
   explaining the invariant (the reborrow is equivalent to
   `IdentStr::ref_cast()` in const-fn contexts).

Both usages are inherited from upstream Sui at the vendored tag.
Reviewers verifying the vendoring confirm the unsafe surface
matches the upstream code at the SHA above; the safety invariants
are upstream's responsibility.

### Audit anchor

Byte-identical to
`external-crates/move/crates/move-core-types/src/` extracted from
`sui-mainnet-v1.66.2.tar.gz` (SHA-256
`ff223ce3f08fb36d0e0daf0566cec917d97d987242f7709cd2a89c72826a78ba`),
modulo the Cargo.toml workspace integration and PROVENANCE.md
addition, modulo the local modifications section above.

## Audit posture

The vendored code's invariants are inherited from the upstream
tagged release. Reviewers verifying this crate's vendoring or bump
check:

1. Vendored content (excluding `PROVENANCE.md` and the `Cargo.toml`
   modifications listed above) matches the upstream tag
   byte-for-byte. Verifiable by re-running the tarball download
   against the SHA-256 above and diffing.
2. The release tag is the most recent Sui mainnet release deployed
   for at least eight weeks at the time of vendoring (10 weeks
   elapsed for this vendoring).
3. Local modifications are limited to workspace-integration
   concerns; no semantic changes.
4. The per-crate `[lints]` declaration relaxes only `unsafe_code`
   (from `forbid` to `allow`) and is documented in `SECURITY.md`
   "Vendored upstream surface".
