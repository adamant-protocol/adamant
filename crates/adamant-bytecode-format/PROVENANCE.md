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

**Phase 5/5b.1a (foundation primitives):**
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

**Phase 5/5b.1b (type-definition fork):**
- `IndexKind` enum and the `ModuleIndex` trait, plus the
  `define_index!` macro and the eighteen `*Index` newtypes:
  `ModuleHandleIndex`, `DatatypeHandleIndex`,
  `FunctionHandleIndex`, `FieldHandleIndex`,
  `StructDefInstantiationIndex`, `FunctionInstantiationIndex`,
  `FieldInstantiationIndex`, `IdentifierIndex`,
  `AddressIdentifierIndex`, `ConstantPoolIndex`,
  `SignatureIndex`, `StructDefinitionIndex`,
  `FunctionDefinitionIndex`, `EnumDefinitionIndex`,
  `EnumDefInstantiationIndex`, `VariantJumpTableIndex`,
  `VariantHandleIndex`, `VariantInstantiationHandleIndex`
- The six type aliases consumed across the binary format:
  `TableIndex`, `LocalIndex`, `MemberCount`, `CodeOffset`,
  `VariantTag`, `TypeParameterIndex`
- `SignatureTokenKind` (from `move-binary-format/src/lib.rs`)
- The handle types: `ModuleHandle`, `DatatypeHandle`,
  `DatatypeTyParameter`, `FunctionHandle`, `FieldHandle`,
  `VariantHandle`, `VariantInstantiationHandle`,
  `VariantJumpTable`, `JumpTableInner`
- The instantiation types: `StructDefInstantiation`,
  `FunctionInstantiation`, `FieldInstantiation`,
  `EnumDefInstantiation`
- The definition types: `Visibility` (with `TryFrom<u8>` and
  `DEPRECATED_SCRIPT`), `FieldDefinition`,
  `StructFieldInformation`, `StructDefinition` (with
  `declared_field_count`, `field`, `fields` impls),
  `EnumDefinition`, `VariantDefinition`
- The signature types: `TypeSignature`, `FunctionSignature`,
  `Signature` (with `len`, `is_empty`); plus the pool aliases
  `SignaturePool`, `TypeSignaturePool`
- `Constant` and `ConstantPool`
- `IdentifierPool` alias added to `identifier.rs`
- `SignatureToken` enum + `Debug` impl + per-token methods
  (`signature_token_kind`, `is_integer`, `is_reference`,
  `is_mutable_reference`, `is_signer`, `is_valid_for_constant`,
  `debug_set_sh_idx`, `preorder_traversal`,
  `preorder_traversal_with_depth`); plus
  `SignatureTokenPreorderTraversalIter` and
  `SignatureTokenPreorderTraversalIterWithDepth`
- The full `Bytecode` enum (95 variants — 85 active + 10
  deprecated global-storage), `Debug` impl, inherent methods
  (`is_unconditional_branch`, `is_conditional_branch`,
  `is_branch`, `offsets`, `get_successors`)
- `instruction_opcode` and `instruction_key` (deferred from
  Phase 5/5b.1a; landed alongside `Bytecode`)
- `CodeUnit` and `FunctionDefinition` (with `is_native` +
  `DEPRECATED_PUBLIC_BIT`/`NATIVE`/`ENTRY` constants)
- `U256` thin newtype with serde + equality + hash
  (deliberately without arithmetic — see deviation note)
- `Metadata` (from `move-core-types/src/metadata.rs`)
- `AddressIdentifierPool` alias (`Vec<adamant_types::Address>`,
  reusing the canonical Adamant address type — see Q6 verify-
  then-pick decision in the deviation notes)

## What was NOT forked

The following items from the upstream sources are intentionally
omitted from this crate:

- `BinaryData` struct and the `pub(crate)` `write_*` helpers from
  `file_format_common.rs`. These are Sui's serializer-internal
  buffer wrapper; Adamant's `module_wire` and `bytecode_wire`
  use `Vec<u8>` directly with their own typed-error checks.
- `CompiledModule` is intentionally not forked. Phase 5/5b.1b's
  Q3 design decision (Option X) chose a single Adamant-owned
  module type — `adamant_vm::module::AdamantCompiledModule` —
  whose fields reference Adamant-owned bytecode-format types
  throughout. There is no Adamant-owned mirror of Sui's
  `CompiledModule` shape with `Vec<Bytecode>` bodies; the only
  module type Adamant production code constructs is
  `AdamantCompiledModule` (with `Vec<BytecodeInstruction>`
  bodies). Cross-validation tests construct Sui's vendored
  `CompiledModule` directly via `[dev-dependencies]`. Avoiding
  the parallel module type saves ~630 LOC and removes a class
  of "which one do I use?" auditor questions.
- The `move_abstract_interpreter::control_flow_graph::Instruction`
  impl on `Bytecode`. The `move_abstract_interpreter` crate is
  one of the 13 vendored Sui crates that Phase 5/5b.5 will move
  to `[dev-dependencies]`. Adamant's CFG infrastructure lands
  in Phase 5/5b.4 alongside the per-function-pass verifier.
  `Bytecode`'s inherent methods (`get_successors`, `offsets`,
  `is_branch`) are forked so that downstream Adamant CFG
  infrastructure can build on them directly without depending
  on the upstream trait.
- The `Arbitrary` impl on `SignatureToken`/`CompiledModule`/etc.
  (gated under `#[cfg(any(test, feature = "fuzzing"))]` upstream).
  These rely on `proptest_derive` and a recursive
  `prop_recursive` strategy. Adamant's per-type tests exercise
  fixed cases plus Layer B cross-validation against the still-
  vendored Sui reference; the proptest-driven generator can be
  added in a future fuzzing arc if needed.
- The Sui test-fixture helpers (`empty_module`,
  `basic_test_module`, `basic_test_module_with_enum`,
  `empty_unpublishable_module`, `basic_unpublishable_test_module`).
  Adamant's `adamant-vm/src/validator/test_fixtures.rs` builds
  Adamant equivalents from scratch with the deviations the
  validator rules require; the upstream helpers carry no
  Adamant-mutability or Adamant-privacy metadata and therefore
  fail Adamant validation as-is.
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

The fork makes the following deliberate semantic deviations
from upstream:

**Phase 5/5b.1a deviations:**

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

**Phase 5/5b.1b deviations:**

- **Serde always-on.** Upstream Sui gates `Serialize` /
  `Deserialize` on the `wasm` cargo feature for `*Index`
  newtypes, struct/enum types, `SignatureToken`, `Bytecode`,
  `CodeUnit`, `FunctionDefinition`, and `CompiledModule`.
  Adamant adds them unconditionally because production-side
  Adamant code (e.g., BCS-decoding the privacy-metadata
  payload `Vec<(FunctionDefinitionIndex, u8)>` per whitepaper
  §6.2.1.6 Rule 2) needs serde on the wire. The derived
  encoding of the index newtypes' inner `TableIndex` (a `u16`)
  is byte-identical to what upstream produces under `wasm`.
- **`StructDefinition::declared_field_count` error type.**
  Upstream returns `PartialVMResult<MemberCount>` (an
  `anyhow`-style error wrapping `StatusCode`). Adamant returns
  `Result<MemberCount, NativeStructError>` where
  `NativeStructError` is a closed unit enum. Same accept set;
  same diagnostic content. Reasons mirror the
  `ReaderError`/`InvalidIdentifier` rationale: avoid pulling
  Sui's full error machinery into the production graph; typed
  pattern-match access at call sites; consistent typed-error
  shape across this crate. Additionally, upstream's `as u16`
  truncation cast is replaced with `MemberCount::try_from(...)`
  + `expect(...)` to make the bound explicit (binary-format
  structural-limit pass guarantees `fields.len() <=
  FIELD_COUNT_MAX = u16::MAX`; the `expect` panic is unreachable
  for inputs the deploy-time pipeline produces).
- **`move_abstract_interpreter::Instruction` impl dropped.**
  See the "What was NOT forked" section.
- **`U256` is a thin newtype, arithmetic deferred.** The
  bytecode-format `U256` is a `pub struct U256(pub [u8; 32])`
  carrying serde + equality + hash + default + LE bytes
  accessors only. It deliberately does **not** carry arithmetic
  operations (`+`, `-`, `*`, `/`, `%`, shifts, comparisons),
  conversion to/from integer widths beyond `[u8; 32]`, or
  numeric formatting.
  Bytecode-level `U256` is a constant-pool / immediate-operand
  value type; arithmetic is the executor's concern, not the
  bytecode-format layer's. Arithmetic is **intentionally
  deferred to the AVM runtime sub-arc** (whitepaper §6.3 /
  Phase 5/6.3) where the implementation choice (fork Sui's
  full `u256` module, adopt a third-party crate like
  `primitive-types` or `ethnum`, or implement in-repo) will be
  made deliberately as a first-order architectural decision in
  that sub-arc — not as a leftover from bytecode-format work.
  This file's surface is sufficient for parsing, serialising,
  equality-comparing, and round-tripping `U256` values through
  the binary format and serde, which is everything the
  bytecode-format layer requires.
- **`AddressIdentifierPool` reuses `adamant_types::Address`.**
  Q6's verify-then-pick (Phase 5/5b.1b design proposal)
  confirmed that `adamant_types::Address` and Sui's
  `move_core_types::AccountAddress` have byte-identical
  layouts (both `pub struct Foo([u8; 32])`; both produce 32
  raw bytes under BCS; the wire encoding in
  `adamant-vm::module_wire` reads/writes 32 raw bytes
  directly without going through serde). Reusing
  `adamant_types::Address` rather than forking a parallel
  type avoids duplicating address-byte-layout maintenance
  across two crates and lets the bytecode-format pool flow
  into the canonical `Address` type used by the rest of the
  protocol. Adds a single `adamant-types = { path =
  "../adamant-types" }` dependency (no circular dep:
  `adamant-types` depends only on `serde`, `serde-big-array`,
  and `bcs`).
- **`IndexKind::variants()` upstream quirk preserved.**
  Sui's upstream `IndexKind::variants()` omits the
  `AddressIdentifier` variant (the enum itself includes it,
  and `Display` handles it; the `variants()` list does not).
  This looks like an upstream bug, but Adamant preserves the
  omission byte-for-byte: `variants().len() == 24`, not 25,
  and `AddressIdentifier` is the only enum variant missing.
  Pinned by a cross-validation test against the still-
  vendored Sui reference. If the upstream "fixes" this in a
  future tag, the cross-validation test surfaces it as a
  development-time signal; the disposition (align with new
  upstream, deviate intentionally, or surface as a bug to
  upstream) follows the vendor-refresh checklist below.
- **Per-variant doc comments on `Bytecode` condensed.**
  Upstream carries Stack-transition prose (~5 lines per
  variant) on each `Bytecode` variant. Adamant condenses to
  Adamant's standard concise-doc style. The Stack-transition
  documentation is not consensus-binding; whitepaper §6.2.1.4
  is the binding spec for stack effects.

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
5. The BCS encoding of every `*Index` newtype (a 2-byte
   little-endian `TableIndex` value).
6. The `Visibility` discriminant bytes (`0x0` Private, `0x1`
   Public, `0x3` Friend; `0x2` reserved for the deprecated
   Script visibility).
7. The BCS encoding of every handle/definition/instantiation/
   signature type — produced bytes match Sui's BCS encoding of
   the corresponding type for any constructed value.
8. Every `SignatureToken` variant's BCS encoding, including the
   recursive cases `Vector(Box<...>)`, `Reference(Box<...>)`,
   `MutableReference(Box<...>)`, and `DatatypeInstantiation(Box<(idx, args)>)`.
9. Every `Bytecode` variant's BCS encoding, including the 10
   deprecated global-storage variants (preserved byte-faithfully
   even though §6.2.1.6 Rule 5 rejects them at deployment).
10. The `instruction_opcode` and `instruction_key` mappings —
    every variant produces the same opcode byte as upstream
    (this is consensus-binding; changing any byte is a hard
    fork per §6.2.1.4).
11. The 32-byte LE encoding of `U256` (matching Sui's
    `write_u256`/`read_u256` and bytecode-format operand
    encoding for `LdU256` per §6.2.1.5).
12. `Address` reuse from `adamant-types`: 32-byte tuple struct
    serialising to 32 raw bytes under BCS (matching Sui's
    `AccountAddress`).
13. The BCS encoding of `Metadata` (length-prefixed `key` +
    length-prefixed `value`).
14. The `IndexKind::variants()` list contents (24 entries, with
    `AddressIdentifier` intentionally omitted to match
    upstream's quirk).

These invariants are asserted by the cross-validation test suite
(`tests/cross_validation.rs`) that compares this crate's outputs
against the still-vendored `move-binary-format` and
`move-core-types` (under `[dev-dependencies]`, with the `wasm`
feature enabled on `move-binary-format` to access the upstream-
gated `Serialize`/`Deserialize` derives required for BCS
comparison).

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
- **2026-05-06 (Phase 5/5b.1b type-definition fork):** Extended
  the fork with the eighteen `*Index` newtypes + their support
  machinery (`IndexKind`, `ModuleIndex` trait, `define_index!`
  macro), six type aliases (`TableIndex`, `LocalIndex`,
  `MemberCount`, `CodeOffset`, `VariantTag`,
  `TypeParameterIndex`), `SignatureTokenKind`, the handle types
  (`ModuleHandle`, `DatatypeHandle`, `DatatypeTyParameter`,
  `FunctionHandle`, `FieldHandle`, `VariantHandle`,
  `VariantInstantiationHandle`, `VariantJumpTable`,
  `JumpTableInner`), the instantiation types
  (`StructDefInstantiation`, `FunctionInstantiation`,
  `FieldInstantiation`, `EnumDefInstantiation`), the definition
  types (`Visibility`, `FieldDefinition`, `StructFieldInformation`,
  `StructDefinition`, `EnumDefinition`, `VariantDefinition`),
  the signature types (`TypeSignature`, `FunctionSignature`,
  `Signature`) + pool aliases, `Constant` + `ConstantPool`,
  `IdentifierPool`, `SignatureToken` + traversal iterators, the
  full `Bytecode` enum (95 variants) + impls +
  `instruction_opcode`/`instruction_key`, `CodeUnit` and
  `FunctionDefinition`, `U256` thin newtype, `Metadata`, and
  `AddressIdentifierPool` reusing `adamant_types::Address`.
  Five new deviations recorded: serde always-on,
  `StructDefinition::declared_field_count` typed error,
  `move_abstract_interpreter::Instruction` impl dropped, `U256`
  arithmetic deferral, `AddressIdentifierPool` reuse.
  Eleven new byte-identity invariants (5–15) added. No upstream
  divergence at fork time — all 96 unit tests + 55 cross-
  validation tests pass byte-identical to the vendored snapshot;
  119 `adamant-vm` tests pass unchanged after the production-
  side rewiring (B-7), confirming byte-faithful behaviour
  through the full deploy-time pipeline.
