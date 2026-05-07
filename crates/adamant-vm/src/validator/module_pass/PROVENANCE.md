# Provenance: `adamant-vm/src/validator/module_pass/`

This subtree is **forked** from Sui-Move's `move-bytecode-verifier`
crate per whitepaper §6.2.1.8's resistant-proof posture
(amendment commits `19d744b`, `0651e2f`). Unlike the vendored
`move-*` crates under `/vendor`, this code is Adamant-owned: it
ships in the production binary, is under Adamant's audit and
maintenance, and this `PROVENANCE.md` documents its upstream
lineage rather than declaring vendor byte-faithfulness.

The fork is parallel to `crates/adamant-bytecode-format/PROVENANCE.md`
(which forks the bytecode-format primitives from
`move-binary-format` and `move-core-types`). This file forks the
bytecode-verifier passes from `move-bytecode-verifier`.

## Upstream lineage

- **Source project:** Sui (https://github.com/MystenLabs/sui)
- **Source release tag at fork:** `mainnet-v1.66.2`
- **Source commit SHA:** `a9a6825eaf6273cc819ee3bcf65fd4909f7624a9`
- **Source paths within upstream repo:**
  - `external-crates/move/crates/move-bytecode-verifier/src/ability_cache.rs`
    (ability resolution helper consumed by the
    `ability_field_requirements` pass)
  - `external-crates/move/crates/move-bytecode-verifier/src/constants.rs`
    (Phase 5/5b.2 B-2; constant-pool validation pass)
  - `external-crates/move/crates/move-bytecode-verifier/src/friends.rs`
    (Phase 5/5b.2 B-2; friend-declaration validation pass)
  - `external-crates/move/crates/move-bytecode-verifier/src/ability_field_requirements.rs`
    (Phase 5/5b.2 B-2; struct/enum field-ability requirements
    pass)
  - `external-crates/move/crates/move-bytecode-verifier/src/instruction_consistency.rs`
    (Phase 5/5b.2 B-2; per-instruction generic-vs-non-generic
    consistency pass)
  - `external-crates/move/crates/move-bytecode-verifier/src/limits.rs`
    (Phase 5/5b.2 B-3; structural-limits pass)
  - `external-crates/move/crates/move-bytecode-verifier/src/data_defs.rs`
    (Phase 5/5b.2 B-3; recursive-data-definition cycle detector;
    Adamant naming: `recursive_data_def`)
  - `external-crates/move/crates/move-bytecode-verifier/src/instantiation_loops.rs`
    (Phase 5/5b.2 B-3; generic-instantiation-loop detector;
    Adamant naming: `instantiation_loops`)
- **Source license:** Apache-2.0 (preserved here)
- **Date of fork:** 7 May 2026 (B-1: `ability_cache`); extended
  through 8 May 2026 (B-2.1 → B-2.4 closure).

## What was forked

### Phase 5/5b.2 B-1 (foundation):

- `AdamantAbilityCache` (port of upstream `AbilityCache`).
  Memoized resolver for the [`AbilitySet`] of a
  [`SignatureToken`], used by the `ability_field_requirements`
  pass landing in B-2.3.

### Phase 5/5b.2 B-2.1 (`constants` pass):

- `module_pass::constants::verify` — entry point validating the
  module's constant pool per upstream
  `move-bytecode-verifier::constants`. Two checks per constant:
  (a) `SignatureToken::is_valid_for_constant` returns true,
  (b) byte payload BCS-deserializes as the declared type.
- `validate_constant_data(&[u8], &SignatureToken)` — Adamant-
  native type-directed BCS validator (cursor-based walker).
  Replaces upstream's path through `MoveValue::simple_deserialize`
  (which would require a production dep on
  `move_core_types::runtime_value`). Acceptance set is byte-
  identical to upstream; verified by 16 Layer B parity tests.
  Scoped `pub(in crate::validator)` with a forward-looking note
  for potential reuse by per-instruction `LdU64`/`LdU256`/
  `LdConst` operand-bytes validation in Phase 5/5b.4 → 5/5b.5.
- New `AdamantValidationError` variants:
  - `InvalidConstantType { idx: ConstantPoolIndex }`
  - `MalformedConstantData { idx: ConstantPoolIndex, reason:
    MalformedConstantReason }`
- New public closed enum `MalformedConstantReason`
  (`UnexpectedEof`, `InvalidBool { byte: u8 }`,
  `InvalidUleb128`, `TrailingBytes { remaining: usize }`)
  re-exported via `validator/mod.rs` and `lib.rs`.

### Phase 5/5b.2 B-2.2 (`friends` pass):

- `module_pass::friends::verify` — entry point validating the
  module's friend declarations per upstream
  `move-bytecode-verifier::friends`. Two assertions: (a)
  module's own `self_handle` does not appear in `friend_decls`;
  (b) every friend's address (resolved through
  `address_identifiers`) equals the module's self-address.
- New `AdamantValidationError` variants:
  - `SelfFriendDeclaration` (no fields)
  - `CrossAccountFriendDeclaration { idx: TableIndex,
    foreign_address: Address }` (reuses
    `adamant_types::Address` per Phase 5/5b.1b's address-pool
    reuse decision)
- Shared `assert_pass_parity` test helper extracted at N=2
  (byte-identical match-body trigger) into
  `module_pass/mod.rs::test_helpers` with visibility
  `pub(in crate::validator::module_pass)`. `constants`'s Layer
  B helper refactored to consume it; `friends` and subsequent
  B-2 passes use it from inception.

### Phase 5/5b.2 B-2.3 (`ability_field_requirements` pass + `AbilityCache` consumer):

- `module_pass::ability_field_requirements::verify` — entry
  point validating struct/enum-field ability requirements per
  upstream `move-bytecode-verifier::ability_field_requirements`.
  For each owning datatype, every field's effective `AbilitySet`
  must contain the abilities required by the parent type's
  declared `AbilitySet` (where required-set is the union of
  `Ability::requires()` over each declared ability).
- First sub-checkpoint to consume `AdamantAbilityCache` from
  B-1. Cache instantiated once at pass entry and reused across
  all struct/enum traversals.
- Cache-error handling: `expect()` with structural-impossibility
  message rather than typed-error variant. At
  `ability_field_requirements`' pipeline position — after the
  bounds-checker pass per §6.2.1.8 step 3 ordering — cache
  errors are structurally impossible (bounds checker has
  already validated type-parameter indices fit handles'
  declared counts and generic-instantiation arities match). A
  fired `expect` indicates an Adamant implementation bug
  (broken bounds checker or wrong pipeline ordering), not a
  module-level rejection.
- New `AdamantValidationError` variant:
  - `FieldMissingTypeAbility { def_idx: TableIndex, kind:
    FieldOwnerKind, variant_idx: Option<TableIndex>, field_idx:
    TableIndex }`
- New public closed enum `FieldOwnerKind` (`Struct`, `Enum`)
  re-exported via `validator/mod.rs` and `lib.rs`.
- B-1's module-level `#![allow(dead_code)]` on
  `module_pass/ability_cache.rs` removed; build clean post-
  removal confirms genuine consumption.
- New `[dev-dependencies]` entry: `move-bytecode-verifier-meter`
  (Sui's `ability_field_requirements::verify_module` takes a
  `Meter` parameter; cross-validation tests pass `DummyMeter`
  from this crate). Test-only — never reaches the production
  binary's dependency graph (consistent with §6.2.1.8's
  carve-out for test-only, build-tooling-only, and CI-only
  dependencies on vendored Sui-Move).

### Phase 5/5b.2 B-2.4 (`instruction_consistency` pass):

- `module_pass::instruction_consistency::verify` — entry point
  validating per-instruction generic/non-generic flavor pairing
  across function bodies per upstream
  `move-bytecode-verifier::instruction_consistency`. Three
  checks: (a) generic vs non-generic flavor pairing across 5
  paired-instruction families (field-borrow, function-call,
  struct-pack/unpack, variant-pack/unpack-with-three-flavors,
  plus the implicit pairing on the instantiation tables);
  (b) `VecPack`/`VecUnpack` element-count operand fits
  `u16::MAX`; (c) Adamant extensions per §6.2.1.4 traverse
  without flagging (no extension has generic/non-generic
  flavor pairs).
- New `AdamantValidationError` variants:
  - `GenericMemberOpcodeMismatch { fn_def_idx:
    FunctionDefinitionIndex, code_offset: CodeOffset }`
  - `VecPackUnpackArgOutOfRange { fn_def_idx:
    FunctionDefinitionIndex, code_offset: CodeOffset, num: u64 }`
- **Deprecated-arms disposition (option (b) per redirect).**
  The 10 deprecated global-storage opcodes
  (`ExistsDeprecated`, `MoveFromDeprecated`, `MoveToDeprecated`,
  `MutBorrowGlobalDeprecated`, `ImmBorrowGlobalDeprecated`,
  plus their `*_Generic` counterparts) are handled by an
  OR-pattern `unreachable!` arm that preserves match
  exhaustiveness while pinning the structural argument:

  > Sui's `safe_assert!(!config.deprecate_global_storage_ops)`
  > is defense-in-depth at the verifier layer in Sui's
  > architecture where the deserializer is permissive.
  > Adamant's pipeline rejects the 10 deprecated global-
  > storage opcodes at deserialize-time per §6.2.1.6 Rule 5
  > (Phase 5/5a `adamant_deserialize` strict mode). By the
  > time a module reaches the verifier's module-level passes,
  > deprecated opcodes are structurally impossible. The
  > verifier-level assertion is redundant by construction in
  > Adamant's pipeline, not by hope.

  Empirical backing: `bytecode_wire.rs:1242
  strict_mode_rejects_each_deprecated_opcode` covers all 10
  deprecated opcodes exhaustively, plus pipeline-level
  coverage at `validator/mod.rs::tests::rejects_module_with_deprecated_global_storage_opcode`
  (Wave 3a). The `unreachable!` message in
  `instruction_consistency.rs` references both tests so an
  auditor reading the source can verify the structural
  argument empirically.

  Exhaustiveness preservation rationale: if upstream Sui adds
  a new `Bytecode` variant in a future tag, Rust's compiler
  flags the missing arm at Adamant compile time, surfacing
  the divergence as a development-time signal per the
  resistant-proof posture's vendor-refresh pattern.

### Pending (later sub-arcs of Phase 5/5b.2):

- **B-3:** `limits`, `recursive_data_def`, `instantiation_loops`
- **B-4:** Rule 2 (`rule_02_privacy.rs`) + privacy-metadata-
  structure parallel module-level pass; Rule 2 lands in
  `crates/adamant-vm/src/validator/`, not in this subtree
- **B-5:** Pipeline integration in
  `crates/adamant-vm/src/validator/mod.rs`; removal of the
  four pass-level `#![allow(dead_code)]` sunsets on
  `constants.rs`, `friends.rs`, `ability_field_requirements.rs`,
  `instruction_consistency.rs`
- **B-6:** Workspace test pass + final PROVENANCE.md batch +
  CLAUDE.md state-bump for Phase 5/5b.2 closure

## What was NOT forked

The following items from the upstream sources are intentionally
omitted:

- **`Meter`/`Scope` parameters on `AbilityCache::abilities`.**
  Upstream's cache plumbs gas-metering through every ability
  resolution. Adamant does not run gas accounting at deploy time
  (gas applies at transaction-execution time per whitepaper
  §6.3); the metering surface is dead weight in Adamant's
  posture and would constrain the fork to a specific upstream
  meter API. The Adamant cache returns
  `Result<AbilitySet, AbilityCacheError>` directly.

- **`safe_unwrap!` macro path.** Upstream uses
  `safe_unwrap!(type_parameter_abilities.get(*idx as usize))`
  on the type-parameter resolution path. Adamant returns a
  typed [`AbilityCacheError::TypeParameterIndexOutOfRange`]
  instead of panicking-then-returning-error. Acceptance set is
  identical; the diagnostic surface is structured for typed
  pattern matching at call sites.

- **`script_signature` pass.** Sui's verifier carries a
  `script_signature` pass for legacy Move scripts. Adamant does
  not have scripts (per whitepaper §6.2.1 the only deployable
  unit is a module); the pass has no Adamant-side analogue.

- **`code_unit_verifier` and per-function passes.** Phase
  5/5b.2 covers module-level passes only; the per-function
  passes (control-flow, stack-usage, type-safety, locals-safety,
  reference-safety, acquires-list checking) land in Phase 5/5b.4
  + 5/5b.5.

- **`BoundsChecker`, `DuplicationChecker`, `SignatureChecker`.**
  These are the three *large* module-level passes; they ship in
  Phase 5/5b.3 along with partial pipeline integration. The
  Phase 5/5b.2 line is deliberately drawn at the seven smaller
  passes.

## Adamant deviations

The fork makes the following deliberate semantic deviations
from upstream:

**Phase 5/5b.2 B-1 deviations:**

- **`AbilityCache` error type.** Upstream returns
  `PartialVMResult<AbilitySet>` from `abilities`. This crate
  returns `Result<AbilitySet, AbilityCacheError>` where
  `AbilityCacheError` is a closed unit-style enum with two
  variants (`TypeParameterIndexOutOfRange`,
  `PolymorphicAbilities`). Reasons: (i) avoids pulling Sui's
  full error machinery into the production graph; (ii) gives
  callers structured pattern-matching access; (iii) the typed
  shape is consistent with `AbilityError` / `ReaderError` /
  `InvalidIdentifier` / `NativeStructError` already established
  in `adamant-bytecode-format`. Acceptance set is identical to
  upstream — the cache accepts and rejects the same
  `(SignatureToken, type_parameter_abilities)` pairs.

- **`Meter`/`Scope` parameters dropped.** Upstream's
  `AbilityCache::abilities` takes `Scope`, `&mut impl Meter`,
  `&[AbilitySet]`, `&SignatureToken` and threads metering
  through every recursive call. Adamant drops both metering
  parameters; the surface is `&mut self`, `&[AbilitySet]`,
  `&SignatureToken` only. See "What was NOT forked" for the
  rationale. The cache's memoization tables are otherwise
  byte-faithful to upstream.

**Phase 5/5b.2 B-2.1 deviations (`constants` pass):**

- **Typed-error fork.** Upstream returns
  `PartialVMResult<()>` carrying `PartialVMError`/`StatusCode`.
  Adamant returns `Result<(), AdamantValidationError>` with
  closed variants `InvalidConstantType` and
  `MalformedConstantData { reason: MalformedConstantReason }`.
  Avoids pulling Sui's full error machinery into the
  production graph; gives callers structured pattern-matching
  access; consistent with the typed-error shape established
  in B-1's `AbilityCacheError`.
- **Type-directed BCS validator is Adamant-native.** Upstream's
  data-validity check calls `Constant::deserialize_constant`,
  which uses `MoveValue::simple_deserialize` from
  `move_core_types::runtime_value`. Adamant has no production
  dep on `move_core_types::runtime_value` per the resistant-
  proof posture (§6.2.1.8). Replacement is
  `validate_constant_data(&[u8], &SignatureToken)` — a cursor-
  based walker that consumes bytes per type primitive
  (1/2/4/8/16/32 for fixed-width primitives, 1 byte for `Bool`
  with `0/1` strict check, ULEB128 length + recursive walk
  for `Vector`). Acceptance set is byte-identical to upstream.

**Phase 5/5b.2 B-2.2 deviations (`friends` pass):**

- **Typed-error fork.** Upstream returns
  `PartialVMResult<()>`. Adamant returns
  `Result<(), AdamantValidationError>` with closed variants
  `SelfFriendDeclaration` and `CrossAccountFriendDeclaration
  { idx, foreign_address }`. Same rationale as B-2.1.
- **Direct algorithmic port.** No Adamant-native algorithm
  replacement; the structural shape of the pass carries over
  byte-faithfully. Upstream's note that the cross-account
  check is "a policy decision rather than a technical
  requirement... we may consider lifting this limitation in
  the future" applies to Adamant's port too: future relaxation
  is a deliberate Adamant-side decision rather than tracking
  a Sui upstream change.

**Phase 5/5b.2 B-2.3 deviations (`ability_field_requirements` pass):**

- **Typed-error fork.** Upstream returns
  `PartialVMResult<()>`. Adamant returns
  `Result<(), AdamantValidationError>` with closed variant
  `FieldMissingTypeAbility { def_idx, kind, variant_idx,
  field_idx }`. Same rationale as B-2.1.
- **`Meter`/`Scope` parameters dropped.** Inherits the cache-
  level deviation from B-1 — the pass's call to
  `AdamantAbilityCache::abilities` does not thread metering.
  Upstream's `verify_module` takes
  `&mut AbilityCache<'env>, &mut (impl Meter + ?Sized)`;
  Adamant's takes only `&AdamantCompiledModule` (the cache
  is constructed internally, no metering surface).
- **Cache-error handling: `expect()` with structural-
  impossibility message rather than typed-error
  propagation.** The `AdamantAbilityCache` returns typed
  `AbilityCacheError` for caller-side correctness violations.
  At `ability_field_requirements`' pipeline position — after
  the bounds-checker pass per §6.2.1.8 step 3 ordering —
  these errors are structurally impossible (bounds checker
  has already validated type-parameter indices and generic
  instantiation arities). A typed
  `AdamantValidationError::AbilityCacheFailure` variant would
  propagate as a *validation rejection*, masking the real bug
  (broken bounds checker) by treating it as a module-level
  rejection. The `expect()` form pins the structural argument:
  a fired `expect` indicates an Adamant implementation bug,
  not malformed input. Consistent with CLAUDE.md's "no
  `unwrap()` outside tests; use `expect()` with a helpful
  message" discipline applied to structural impossibilities.

**Phase 5/5b.2 B-2.4 deviations (`instruction_consistency` pass):**

- **Typed-error fork.** Upstream returns
  `PartialVMResult<()>`. Adamant returns
  `Result<(), AdamantValidationError>` with closed variants
  `GenericMemberOpcodeMismatch { fn_def_idx, code_offset }`
  and `VecPackUnpackArgOutOfRange { fn_def_idx, code_offset,
  num }`. Same rationale as B-2.1.
- **Adamant extensions handled via early-return Ok arm.**
  Upstream's match exhaustively covers Sui's `Bytecode`.
  Adamant's pass dispatches first on `BytecodeInstruction::Inherited(_) | Adamant(_)`;
  the `Adamant(_)` arm returns `Ok(())` without further
  inspection (per Q6 from the original B-2 design proposal:
  none of the 17 extensions per §6.2.1.4 have generic/non-
  generic flavor pairs).
- **Deprecated-arms disposition: `unreachable!` rather than
  `safe_assert!(!config.deprecate_global_storage_ops)`.** See
  the "What was forked" B-2.4 entry above for the verbatim
  structural argument. The 10 deprecated arms remain in the
  match (preserving exhaustiveness so future Sui upstream
  additions surface as Rust compile-time errors), with bodies
  that panic via `unreachable!` rather than no-op or
  `safe_assert`. The `unreachable!` message references the
  empirical-backing tests
  (`bytecode_wire.rs:1242 strict_mode_rejects_each_deprecated_opcode`,
  `validator/mod.rs::tests::rejects_module_with_deprecated_global_storage_opcode`)
  so an auditor reading the source can verify the structural
  argument without external context.
- **`#[allow(clippy::too_many_lines)]` on
  `AdamantValidationError`'s `Display::fmt`.** The variant
  count (now 8 with B-2.1 → B-2.4 additions) pushes `fmt`
  past clippy's 100-line threshold. The lint is correct in
  the abstract; in this case the long match IS the dispatch
  table for diagnostic messages, and splitting obscures the
  table shape. Allow with reason
  `"dispatch over AdamantValidationError variants; the long
  match IS the table"`. Same reasoning would apply to future
  variant additions; the allow stays.

## Byte-identity invariants

For the resistant-proof posture to be sound, this subtree's
behaviour must be byte-identical to the upstream source on the
**accept/reject decision** for any (module, sub-input) pair.
Specifically:

1. `AdamantAbilityCache::abilities` returns the same
   `AbilitySet` as Sui's `AbilityCache::abilities` for any
   `(SignatureToken, type_parameter_abilities)` pair where both
   accept. This is exercised by Layer B cross-validation tests
   that construct equivalent `AdamantCompiledModule` /
   `CompiledModule` pairs and compare cache outputs.
2. The cache rejects `TypeParameter(idx)` when `idx >=
   type_parameter_abilities.len()` exactly as upstream does;
   the typed-error variant differs but the acceptance set is
   unchanged.
3. **`module_pass::constants::verify`** accepts the same
   constant-pool configurations as Sui's
   `move_bytecode_verifier::constants::verify_module` for any
   module whose constant pool contains only types Sui's
   `is_valid_for_constant` accepts (i.e., primitives,
   `Address`, `Vector<...>` recursively over those). Asserted
   by 16 Layer B parity tests covering 9 primitive accept
   paths, 4 reject paths per malformed-data failure mode, and
   3 reject paths per invalid-for-constant `SignatureToken`.
4. **`module_pass::friends::verify`** accepts the same
   `friend_decls` configurations as Sui's
   `move_bytecode_verifier::friends::verify_module` for any
   module shape produceable through `to_sui_module`'s BCS
   round-trip. Asserted by 5 Layer B parity tests (3 accept
   paths covering empty, single same-account, and multi-same-
   account friends; 2 reject paths covering self-friend and
   cross-account friend).
5. **`module_pass::ability_field_requirements::verify`**
   accepts the same `(struct_defs, enum_defs)` configurations
   as Sui's
   `move_bytecode_verifier::ability_field_requirements::verify_module`
   for any module whose datatype handles satisfy the bounds
   checker's preconditions (no out-of-range type-parameter
   indices, matching generic-instantiation arities). Asserted
   by 7 Layer B parity tests covering struct/enum positives,
   the `key`/`store` ability-implication path, native-struct
   skip, and missing-ability rejections.
6. **`module_pass::instruction_consistency::verify`** accepts
   the same `(function_defs)` configurations as Sui's
   `move_bytecode_verifier::instruction_consistency::InstructionConsistency::verify_module`
   for any module whose function bodies use only non-deprecated
   opcodes (the deprecated 10 are upstream's concern via
   Phase 5/5a's `adamant_deserialize` strict mode; Layer B
   fixtures explicitly exclude them). Asserted by 8 Layer B
   parity tests covering paired-flavor accept/reject across
   the 5 paired-instruction families plus VecPack/VecUnpack
   bound checks.

Subsequent B-3 sub-arcs extend the invariants list as each
pass lands.

## Why a fork rather than a continued vendoring

The vendored Sui crates under `/vendor` are byte-faithful copies
of upstream code, intended to be replaced wholesale on each
vendor tag refresh. That posture is appropriate for code we
exercise at test time as a reference implementation but never
ship in production.

This subtree is shipped in production. Per whitepaper §6.2.1.8's
resistant-proof amendment, the production binary's dependency
graph cannot include vendored Sui crates; bumping the vendor tag
must not cause divergence in deploy-time accept/reject decisions
or runtime behaviour. To honour that posture, the bytecode-
verifier passes that production code depends on must be Adamant-
owned — forked once and then maintained under Adamant's audit
independently of upstream Sui.

Future divergences from Sui upstream (intentional Adamant-
specific extensions, bug fixes Sui doesn't pick up, or upstream
changes Adamant rejects) live in this subtree and stay outside
the vendored copy's byte-faithfulness audit anchor.

## Genesis structural-limits values

Per whitepaper §6.2.1.7, gas costs and structural limits are
**genesis-fixed**: once mainnet launches, no on-chain mechanism
can change these values; bumping requires a hard fork. The
spec does not currently enumerate concrete values for the
structural-limits subset — a gap registered in CLAUDE.md "Open
properties to track" as a §6.2.1.7 amendment workstream
distinct from the genesis-pool calibration item.

**Adamant's verifier is the consensus boundary for structural
limits.** Sui ships `VerifierConfig::default()` with `None` on
most fields because Sui's mainnet runs an additional protocol-
config layer above the verifier that imposes its own bounds —
Sui's verifier is *not* the security boundary for structural
limits in their architecture. Adamant has no such layer.
Shipping `None` would expose validators to deploy-time DoS
through unbounded module shapes (e.g., a module declaring 4
billion function definitions, blowing through validator memory,
all of which the verifier would accept). Every field below is
therefore concrete.

Three buckets per the Phase 5/5b.2 B-1 design-proposal
redirect:

### Bucket A — adopt Sui's commented alternative

Sui's `VerifierConfig::default()` carries a block of commented-
out alternatives at `vendor/move-vm-config/src/verifier.rs:70-75`
(verbatim):

```rust
// max_push_size: Some(10000),
// max_dependency_depth: Some(100),
// max_data_definitions: Some(200),
// max_fields_in_struct: Some(30),
// max_function_definitions: Some(1000),
```

These represent Sui's own thinking about reasonable verifier-
layer bounds (not activated because Sui's protocol-config layer
already imposes its own). Adamant adopts them, with one
deviation:

| Field | Sui literal | Sui commented | Adamant 5/5b.2 |
|---|---|---|---|
| `max_function_definitions` | `None` | `Some(1000)` | **`Some(1000)`** (adopt) |
| `max_data_definitions` | `None` | `Some(200)` | **`Some(200)`** (adopt) |
| `max_fields_in_struct` | `None` | `Some(30)` | **`Some(50)`** (diverged — see below) |

**Divergence: `max_fields_in_struct: Some(50)` (Adamant) vs
`Some(30)` (Sui's commented alternative).** Adamant ships a
looser bound. Reasoning: configuration structs (e.g., privacy-
circuit configuration bundles ~20 cryptographic parameters) and
extension-related witness types can plausibly hit 30 fields
when extension instructions inflate the field count modestly.
`Some(50)` gives headroom for legitimate Adamant modules using
the 17 extension instructions per §6.2.1.4 while keeping the
memory bound tight: 50 fields × ~16 B ≈ 800 B per struct, 200
structs per module = ~160 KB worst case.

### Bucket B — Sui's literal default

Sui ships a concrete value at the verifier layer; Adamant
mirrors except where defense-in-depth dictates otherwise:

| Field | Sui literal | Adamant 5/5b.2 |
|---|---|---|
| `max_variants_in_enum` | `Some(127)` | **`Some(127)`** (mirror; structurally pinned by u8 variant tag) |
| `max_constant_vector_len` | `Some(1_048_576)` | **`Some(1_048_576)`** (mirror; 1 MiB) |
| `max_identifier_len` | `Some(128)` | **`Some(128)`** (mirror) |
| `disallow_self_identifier` | `false` | **`true`** (flipped — see below) |

**Divergence: `disallow_self_identifier: true` (Adamant) vs
`false` (Sui's literal default).** The `<SELF>` literal is a
Move-internal sentinel that should never appear in deployed
bytecode. Sui's permissive default is safe in Sui's layered
architecture (their protocol-config layer bounds attack surface
above the verifier); Adamant's verifier is the security
boundary, and rejecting `<SELF>` at zero cost closes a class
of injection attempts that have no legitimate use case.

### Bucket C — spec gap (provisional values with reasoning)

Sui has neither a literal nor a commented alternative for these
fields. Adamant ships provisional values; the §6.2.1.7
amendment workstream raises whether the spec should enumerate
them:

| Field | Sui literal | Adamant 5/5b.2 |
|---|---|---|
| `max_generic_instantiation_length` | `None` | **`Some(32)`** |
| `max_function_parameters` | `None` | **`Some(128)`** |
| `max_type_nodes` | `None` | **`Some(256)`** |

**`max_generic_instantiation_length: Some(32)` reasoning.**
Bounds type-parameter count on a single function or datatype
handle. The `instantiation_loops` pass (Phase 5/5b.2 B-3)
builds a directed graph with one node per `(function
definition, type parameter index)` pair; pass cost is O(F × T)
with F = function-definition count, T = max type parameters
per handle. Bounding T independently of F prevents single-
function inflation of pass cost. Memory profile: each type
parameter is ~2 bytes; 32 type params × 200 handles = 12.8 KB
total (tight). Practical use: most generics take 1–3 type
parameters, complex collections cap at 5–6, >10 is exotic;
`Some(32)` is generous against any plausible legitimate use
including extension-related circuit witness types. Adjacent
Move-derived chains (Aptos mainnet config) use similar values;
exact values not independently verified at this commit, pre-
mainnet review may verify against current upstream configs.

**`max_function_parameters: Some(128)` reasoning.** Bounds
parameter count on a single function signature. Each parameter
is a `SignatureToken` (variable size, capped by `max_type_nodes`
below); call-frame setup cost scales linearly with parameter
count; the type-safety pass (Phase 5/5b.5) does per-parameter
typed-stack analysis. Memory profile: each parameter signature
averages ~16 B after `max_type_nodes` bound; 128 parameters ×
16 B = 2 KB per function header, 1000 functions per module = 2
MB worst case (bounded). Practical use: most functions have ≤
8 parameters; >16 starts looking like a code smell that should
be a struct argument; 128 is well above any plausible
legitimate Adamant module. Adjacent Move-derived chains (Aptos
mainnet config) use similar values; exact values not
independently verified at this commit.

**`max_type_nodes: Some(256)` reasoning.** Bounds total node
count after preorder traversal of a `SignatureToken` tree, with
Sui's per-node weighting (`Datatype` / `DatatypeInstantiation`
nodes count as 4, `TypeParameter` as 4, primitives as 1). Type-
checking cost, signature-equality cost, and the `limits` pass's
own traversal all scale with tree size; the bound guards the
inputs to the type-safety per-function pass (Phase 5/5b.5).
Symmetry: Adamant's `adamant-bytecode-format::SIGNATURE_TOKEN_DEPTH_MAX
= 256` already bounds tree *depth*; `max_type_nodes = 256`
provides the parallel bound on tree *width × depth*. Both
deepest-allowed and widest-allowed trees clear the limit;
trees that are simultaneously deep and wide are caught.
Practical use: reasonable generic types are 10–30 nodes;
complex types 50–100 nodes; 256 gives comfortable headroom.
Adjacent Move-derived chains (Aptos mainnet config) use similar
values; exact values not independently verified at this commit.

## Out-of-scope fields (registered for future sub-arcs)

`AdamantStructuralLimits` covers **module-level deploy-time
bounds**. The following Sui `VerifierConfig` fields are
deliberately not included; each lives at a different layer:

- `max_loop_depth`, `max_basic_blocks`, `max_push_size`,
  `max_back_edges_per_function`, `max_back_edges_per_module` —
  per-function-pass concerns (CFG depth, push-count bounds);
  extend `AdamantStructuralLimits` in Phase 5/5b.4 alongside
  the per-function passes that consume them.
- `max_value_stack_size` — runtime concern (operand stack
  bound during execution); lives in AVM runtime config in the
  Phase 5/6.3 sub-arc per whitepaper §6.3.
- `max_dependency_depth` — deployment-pipeline concern (depth
  of the module-dependency tree); lives in the deployment-
  validator config when that pipeline lands.
- `bytecode_version` — already bounded at parse time in Phase
  5/5a's deserializer (`AdamantCompiledModule::version` is
  validated against `VERSION_MAX`).
- `allow_receiving_object_id`,
  `reject_mutable_random_on_entry_functions`,
  `private_generics_verifier_v2`, `additional_borrow_checks`,
  `better_loader_errors`,
  `sanity_check_with_regex_reference_safety`,
  `disable_entry_point_signature_check`,
  `switch_to_regex_reference_safety` — Sui-runtime-specific
  flags governing Sui's verifier behaviour; do not apply to
  Adamant's fully Adamant-native verifier per §6.2.1.8.

### Test-time-only dependencies on vendored Sui-Move

The following `[dev-dependencies]` are required by Layer B
cross-validation tests but are explicitly permitted by
§6.2.1.8's carve-out for test-only, build-tooling-only, and
CI-only dependencies on vendored Sui-Move. They are **never
reached by the production binary's dependency graph**:

- **`move-bytecode-verifier-meter` (added at B-2.3).** Sui's
  `ability_field_requirements::verify_module` takes a
  `&mut (impl Meter + ?Sized)` parameter; Adamant's Layer B
  helper `cross_validate_pass` passes `DummyMeter` from this
  crate. Phase 5/5b.5's resistant-proof posture is "remove
  `move-*` from the production-target dependency graph", not
  "remove all `move-*` deps" — this dev-dep stays through and
  beyond Phase 5/5b.5 alongside the other test-time-only
  vendored Sui surface.
- **`move_vm_config::verifier::VerifierConfig` (already in
  scope; consumed at B-2.4 cross-validation).** Sui's
  `instruction_consistency::InstructionConsistency::verify_module`
  takes a `&VerifierConfig` parameter for its
  `safe_assert!(!config.deprecate_global_storage_ops)` check.
  Adamant's Layer B helper passes
  `VerifierConfig::default()` (which sets
  `deprecate_global_storage_ops = true`, exercising the
  fully-deprecated-opcode-rejection path Sui ships in
  production). No production-side use of `VerifierConfig` for
  this pass — the dependency is already in scope from the
  validator wrapper bridge and is removed alongside it in
  Phase 5/5b.5.

## §6.2.1.7 spec-amendment workstream

§6.2.1.7 specifies structural limits as genesis-fixed but does
not enumerate values. The Phase 5/5b.2 B-1 implementation
ships provisional values per the buckets above; pre-mainnet
workstream raises a §6.2.1.7 amendment proposal to enumerate
them in the spec, parallel to the per-instruction gas-cost
appendix pattern. Registered in CLAUDE.md "Open properties to
track" at B-6 closure, distinct from the genesis-pool
calibration item.

## Future maintenance

When the vendored Sui crates are refreshed to a new tag, Layer B
cross-validation tests in this subtree (landing across B-1 to
B-3 in the existing
`adamant-bytecode-format/tests/cross_validation.rs` pattern)
will surface any divergence between this subtree's behaviour
and the new vendored snapshot. Each such divergence requires a
deliberate decision: align this subtree with new upstream,
deviate intentionally, or surface as a bug for upstream review.
The decision is recorded in the changelog at the bottom of this
file.

## Vendor refresh checklist

After bumping the vendored Sui tag:

1. Run `cargo test -p adamant-vm validator::module_pass`. Review
   any cross-validation test failures.
2. For each failure, classify: (a) align this subtree with the
   new upstream snapshot; (b) deviate intentionally and document
   in this PROVENANCE.md's changelog; (c) surface to upstream
   Sui as a bug for review.
3. Update the changelog at the bottom of this file with the new
   vendor tag, the date of refresh, and the disposition of each
   cross-validation failure.

This checklist makes vendor-refresh-implies-test-run a process
commitment rather than a hope. Cross-validation tests catch
divergence; the checklist catches the drift between "tests
exist" and "tests get run."

## Changelog

- **2026-05-07 (Phase 5/5b.2 B-1, foundation fork):** Initial
  fork of `AbilityCache` from `mainnet-v1.66.2` (commit
  `a9a6825eaf6273cc819ee3bcf65fd4909f7624a9`) into
  `module_pass/ability_cache.rs`. Plus `AdamantStructuralLimits`
  added to `validator/config.rs` with concrete genesis values
  per the Bucket A/B/C disposition documented above (Adamant's
  verifier is the consensus boundary for structural limits;
  unlike Sui, no protocol-config layer backstops missing
  bounds, so every field is concrete rather than `None`).
  Cache deviations recorded: typed-error return,
  `Meter`/`Scope` parameters dropped. Structural-limits
  divergences recorded: `max_fields_in_struct: Some(50)` vs
  Sui's commented `Some(30)` for extension-friendly headroom;
  `disallow_self_identifier: true` vs Sui's literal `false` as
  defense-in-depth at zero cost. No upstream divergence on
  cache behaviour at fork time — cache outputs are byte-
  identical to the vendored snapshot for every input the
  inline unit tests exercise; Layer B cross-validation lands
  alongside `ability_field_requirements` in B-2.
- **2026-05-08 (Phase 5/5b.2 B-2 closure):** Four small/medium
  module-level passes landed across B-2.1 through B-2.4.
  Cumulative file LOC: ~3,065 across `constants.rs` (680),
  `friends.rs` (341), `ability_field_requirements.rs` (738),
  and `instruction_consistency.rs` (1024); plus error-variant
  additions in `validator/error.rs` (~280 LOC across the four
  sub-checkpoints). Test additions: 39 (constants) + 12
  (friends) + 22 (ability_field_requirements) + 30
  (instruction_consistency) = 103 new tests, all passing in
  the workspace gauntlet. Two new public closed enums
  (`MalformedConstantReason`, `FieldOwnerKind`) re-exported via
  `lib.rs`. Six new `AdamantValidationError` variants
  (`InvalidConstantType`, `MalformedConstantData`,
  `SelfFriendDeclaration`, `CrossAccountFriendDeclaration`,
  `FieldMissingTypeAbility`, `GenericMemberOpcodeMismatch`,
  `VecPackUnpackArgOutOfRange`). Shared `assert_pass_parity`
  test helper extracted at N=2 (B-2.2) into
  `module_pass/mod.rs::test_helpers`. New `[dev-dependencies]`
  on `move-bytecode-verifier-meter` (B-2.3). B-1's module-
  level `#![allow(dead_code)]` on `ability_cache.rs` removed
  (B-2.3). Four pass-level `#![allow(dead_code)]` sunsets
  remain pending B-5 pipeline integration. No upstream
  divergence at fork time — every Layer B cross-validation
  test passes byte-identical to the vendored snapshot for
  every fixture exercised. Workspace test count 821 → 933
  (+112 across B-1 and B-2; 9 from B-1 + 103 from B-2.1-2.4).
