# Provenance: `adamant-bytecode-format`

This crate is **forked** from Sui-Move per whitepaper §6.2.1.8's
resistant-proof posture (amendment commits `19d744b`, `0651e2f`).
Unlike the vendored `move-*` crates under `/vendor`, this crate is
Adamant-owned: the code is under Adamant's audit and maintenance,
and this `PROVENANCE.md` documents its upstream lineage rather
than declaring vendor byte-faithfulness.

## Upstream lineage

- **Source project:** Sui (https://github.com/MystenLabs/sui)
- **Source release tag at fork:** `mainnet-v1.66.2`
- **Source commit SHA:** `a9a6825eaf6273cc819ee3bcf65fd4909f7624a9`
- **Source paths within upstream repo:**
  - `external-crates/move/crates/move-binary-format/src/file_format_common.rs`
    (constants, readers, version-flavor helpers, tag enums)
  - `external-crates/move/crates/move-binary-format/src/file_format.rs`
    (lines defining `Ability`, `AbilitySet`, `AbilitySetIterator`,
    and their impls)
  - `external-crates/move/crates/move-core-types/src/identifier.rs`
    (`Identifier`, validation helpers)
- **Source license:** Apache-2.0 (preserved here)
- **Date of fork:** 6 May 2026

## What was forked

This crate contains an Adamant-owned port of:

- All public constants from `file_format_common.rs` consumed by
  `adamant-vm` (`TABLE_INDEX_MAX`, `SIGNATURE_TOKEN_DEPTH_MAX`,
  the version constants, all index/size limits)
- The `BinaryFlavor` struct + impls
  (`encode_version`, `decode_version`, `decode_flavor`,
  `SUI_FLAVOR`)
- The `BinaryConstants` empty enum + impls
  (`MOVE_MAGIC`, `UNPUBLISHABLE_MAGIC`, `decode_magic`)
- The `MagicKind` and `MagicError` enums
- The tag enums: `TableType`, `SerializedType`,
  `SerializedNativeStructFlag`, `SerializedEnumFlag`,
  `SerializedJumpTableFlag`, `Opcodes`
- The reader functions: `read_u8`, `read_u32`,
  `read_uleb128_as_u64`
- The `Ability` enum, the `AbilitySet` struct, and the
  `AbilitySetIterator` (with their impls including `from_u8`,
  `into_u8`, ability-set algebra, and `polymorphic_abilities`)
- `Identifier` with its validation helpers (`is_valid`,
  `is_valid_identifier_char`, `Identifier::new`,
  `Identifier::from_utf8`, `as_str`, `len`, etc.)

## What was NOT forked

The following items from the upstream sources are intentionally
omitted from this crate:

- `BinaryData` struct and the `pub(crate)` `write_*` helpers from
  `file_format_common.rs`. These are Sui's serializer-internal
  buffer wrapper; Adamant's `module_wire` and `bytecode_wire`
  use `Vec<u8>` directly with their own typed-error checks.
- `instruction_opcode` and `instruction_key` from
  `file_format_common.rs`. These operate on Sui's `Bytecode`
  enum, which is part of the type-fork landing in Phase 5/5b.1b.
  When `Bytecode` lands here, the Adamant equivalents of these
  helpers will land alongside it.
- `IdentStr` (the borrowed counterpart of `Identifier`).
  Sui exposes `&IdentStr` via `Identifier`'s `Deref` and provides
  the `ident_str!` macro for compile-time validated identifier
  construction. Both rely on `unsafe` (RefCast transmute and a
  `transmute::<&'static str, &'static IdentStr>`), which conflicts
  with Adamant's workspace `#![forbid(unsafe_code)]` policy
  (CLAUDE.md Section 7). `Identifier` carries `as_str()`, `len()`,
  and `is_empty()` directly so callers don't need `&IdentStr`.
  The ergonomic loss (no compile-time identifier constants) is
  acceptable; runtime `Identifier::new` covers the same surface.
- `Identifier::new_unchecked` (the `unsafe` constructor that
  bypasses validation). Adamant's parsing path always validates
  on `Identifier::new`; the unchecked path is not needed.
- `abstract_size_for_gas_metering` on `Identifier`. Depends on
  Sui's `gas_algebra::AbstractMemorySize`, which Adamant does not
  use (gas accounting per whitepaper §6.3 is multi-dimensional
  and lives in `adamant-vm` rather than at the identifier level).

## Adamant deviations

The fork makes one deliberate semantic deviation from upstream:

- **Reader error type.** Sui's reader functions return
  `anyhow::Result<T>`. This crate's readers return
  `Result<T, ReaderError>` where `ReaderError` is a closed enum
  (`UnexpectedEof | MalformedUleb128`). Reasons:
  (i) avoids pulling `anyhow` into production deps,
  (ii) gives callers structured pattern-matching access,
  (iii) `bytecode_wire.rs` and `module_wire.rs` already adapt
       Sui's `anyhow::Error` to typed errors at every call site
       — keeping the typed shape at the source removes the
       adaptation step.
  Byte-level reader behaviour (acceptance set, byte sequences
  consumed) is identical to upstream; only the error type
  differs.
- **Identifier error type.** Sui's `Identifier::new` returns
  `Result<Self, anyhow::Error>` whose error message includes the
  offending string. This crate's `Identifier::new` returns
  `Result<Self, InvalidIdentifier>` where `InvalidIdentifier` is
  a unit struct. The offending string is not carried in the
  error type; callers that need it for diagnostics retain the
  input separately. Acceptance set is byte-identical to upstream.

## Byte-identity invariants

For the resistant-proof posture to be sound, this crate's behaviour
must be byte-identical to the upstream source on:

1. The integer values of every constant (32-bit values for
   versions; 64-bit values for `*_MAX` bounds; u8 discriminants
   for tag enums).
2. The byte sequence accepted by `read_uleb128_as_u64` for any
   given input.
3. The acceptance set of `Identifier::new` (which UTF-8 strings
   are valid Move identifiers).
4. The bit layout of `AbilitySet` (1 byte; bits 0x1 Copy, 0x2
   Drop, 0x4 Store, 0x8 Key) and the result of `from_u8`,
   `into_u8`, `union`, `intersect`, `difference`, `is_subset`,
   `polymorphic_abilities`.

These invariants are asserted by the cross-validation test suite
(`tests/cross_validation.rs`) that compares this crate's outputs
against the still-vendored `move-binary-format` and
`move-core-types` (under `[dev-dependencies]`).

## Why a fork rather than a continued vendoring

The vendored Sui crates under `/vendor` are byte-faithful copies
of upstream code, intended to be replaced wholesale on each
vendor tag refresh. That posture is appropriate for code we
exercise at test time as a reference implementation but never
ship in production.

This crate is shipped in production. Per whitepaper §6.2.1.8's
resistant-proof amendment, the production binary's dependency
graph cannot include vendored Sui crates: bumping the vendor tag
must not cause divergence in deploy-time accept/reject decisions
or runtime behaviour. To honour that posture, the bytecode-format
primitives that production code depends on must be Adamant-owned
— forked once at this commit, then maintained under Adamant's
audit independently of upstream Sui.

Future divergences from Sui upstream (intentional Adamant-specific
extensions, bug fixes Sui doesn't pick up, or upstream changes
Adamant rejects) live in this crate and stay outside the vendored
copy's byte-faithfulness audit anchor.

## Future maintenance

When the vendored Sui crates are refreshed to a new tag, the
cross-validation test suite will surface any divergence between
this crate's behaviour and the new vendored snapshot. Each such
divergence requires a deliberate decision: align this crate with
new upstream, deviate intentionally, or surface as a bug for
upstream review. The decision is recorded in the changelog at
the bottom of this file.

## Vendor refresh checklist

After bumping the vendored Sui tag:

1. Run `cargo test -p adamant-bytecode-format`. Review any
   cross-validation test failures.
2. For each failure, classify: (a) align this crate with the
   new upstream snapshot; (b) deviate intentionally and document
   in this PROVENANCE.md's changelog; (c) surface to upstream
   Sui as a bug for review.
3. Update the changelog at the bottom of this file with the
   new vendor tag, the date of refresh, and the disposition of
   each cross-validation failure.

This checklist makes vendor-refresh-implies-test-run a process
commitment rather than a hope. Cross-validation tests catch
divergence; the checklist catches the drift between "tests
exist" and "tests get run."

## Changelog

- **2026-05-06 (initial fork at Phase 5/5b.1a):** Initial fork
  from `mainnet-v1.66.2` (commit
  `a9a6825eaf6273cc819ee3bcf65fd4909f7624a9`). Surface enumerated
  in "What was forked" / "What was NOT forked" sections above;
  deviations enumerated in "Adamant deviations". No upstream
  divergence at fork time — every cross-validation test passes
  byte-identical to the vendored snapshot.
