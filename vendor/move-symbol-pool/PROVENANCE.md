# Provenance: `move-symbol-pool`

This crate is vendored from the Sui ecosystem per whitepaper
section 6.2.1.6 as a **transitive dependency** of
`move-command-line-common` (itself transitive via
`move-regex-borrow-graph`; Batch 2 of the Sui-Move vendoring),
not a crate the bytecode verifier directly requires. It provides
a static global string-interning pool used across Sui's Move
tooling.

This crate brings the generic dependency `phf` into Batch 2's
audit surface. See SECURITY.md "Transitive generic-dependency
note (Batch 2)" for the audit-trail context.

## Upstream

- **Project:** Sui (https://github.com/MystenLabs/sui)
- **Path within upstream repo:** `external-crates/move/crates/move-symbol-pool`
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
    `"A static, global string table for Move tools"` to one
    pointing at this `PROVENANCE.md` and the whitepaper subsection
    (also flagging the transitive-via-move-command-line-common
    status).
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
  - `[features]`: `default = []` retained from upstream.
  - `[lints]`: added per-crate `[lints.rust]` and `[lints.clippy]`
    (upstream had no `[lints]` section). Per-crate
    `unsafe_code = "allow"` (relaxed from the workspace
    `unsafe_code = "forbid"`) because this crate carries upstream
    `unsafe`; full enumeration in the next subsection. Same
    pattern as Batch 1's `move-core-types` and as
    `adamant-crypto-blst-extra` (Adamant-authored containment).
    Clippy lints set to `all = "allow"` per `vendor/README.md`
    "Lints" policy.

No `.rs` file is modified. The `src/` and `tests/` content is
byte-identical to the upstream tag.

### Inherited upstream unsafe surface

The `unsafe` surface inherited from upstream is **six unsafe
blocks across two files**, with no `pub unsafe fn` declarations.
Upstream `src/lib.rs` carries an explicit header documenting the
crate's intentional use of `unsafe` for the string-interning
pattern (inherited from servo/string-cache).

**`src/symbol.rs`** — five unsafe blocks:

1. Line 102 (in `Symbol::pack_static`):
   `NonZeroU64::new_unchecked((STATIC_TAG as u64) | ...)`.
   Caller-asserted invariant: the bitwise OR with `STATIC_TAG`
   (which is non-zero) guarantees the result is non-zero.
2. Line 148 (in `Symbol::deref`, `Tag::Dynamic` arm):
   `let entry = unsafe { &*ptr };`. Raw-pointer dereference of
   the dynamic-symbol entry pointer; relies on the pool's
   guarantee that pooled entries are not freed while a `Symbol`
   holding their address is live.
3. Line 154 (in `Symbol::deref`, `Tag::Inlined` arm):
   `unsafe { std::str::from_utf8_unchecked(bytes) }`. The bytes
   are known-valid UTF-8 because they were copied in via the
   `From<Cow<str>>` impl which only accepts UTF-8 input.
4. Line 218 (in `inline_symbol_slice`):
   `slice::from_raw_parts(data, 7)`. Reads the inline 7-byte
   string from a `NonZeroU64`'s memory layout (target-endian
   aware via `cfg!(target_endian)`).
5. Line 233 (in `inline_symbol_slice_mut`):
   `slice::from_raw_parts_mut(data, 7)`. Mutable variant of the
   above; called only during `From<Cow<str>>` while constructing
   a fresh inline symbol.

**`src/pool.rs`** — one unsafe block:

1. Line 66 (in `Pool::new`):
   `Box::from_raw(vec.as_ptr() as *mut [Bucket; NB_BUCKETS])`.
   Casts a heap-allocated `Vec<usize>` (wrapped in `ManuallyDrop`
   to prevent double-free) into a fixed-size `[Bucket; NB_BUCKETS]`
   array. Relies on `Bucket` being `usize`-sized and the layout
   matching.

These six usages are inherited from upstream Sui at the vendored
tag. Reviewers verifying the vendoring confirm the unsafe surface
matches the upstream code at the SHA above; the safety invariants
are upstream's responsibility, inherited unchanged.

### Audit anchor

Byte-identical to
`external-crates/move/crates/move-symbol-pool/src/` and `tests/`
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
4. The per-crate `[lints]` declaration relaxes only `unsafe_code`
   (from `forbid` to `allow`), documented in `SECURITY.md`
   "Vendored upstream surface — Batch 2".
5. The unsafe surface enumerated in the section above matches the
   upstream code at the SHA above; the safety invariants are
   upstream's responsibility and are inherited unchanged.
