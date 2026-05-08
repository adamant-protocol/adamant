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

### Phase 5/5b.2 B-3.1 (`limits` pass):

- `module_pass::limits::verify(module, limits)` — entry
  point for structural-limits validation per upstream
  `move-bytecode-verifier::limits::LimitsVerifier`. Six
  sub-checks in upstream order: `verify_constants`,
  `verify_function_handles`, `verify_datatype_handles`,
  `verify_type_nodes`, `verify_identifiers`,
  `verify_definitions`. Consumes
  [`AdamantStructuralLimits`] from B-1's
  `validator/config.rs`.
- **Signature divergence from sibling passes:**
  `verify(module, limits)` takes
  `&AdamantStructuralLimits` as a second parameter. First
  pass in Phase 5/5b.2 to consume validator config; B-2
  and B-3.2/B-3.3 passes take only `&module`. Phase
  5/5b.2 B-5 pipeline integration threads
  `config.structural_limits()` from
  `AdamantVerifierConfig` to `limits::verify`
  specifically — registered as B-5 carry-forward.
- 10 new `AdamantValidationError` variants:
  `TooManyVectorElements`, `TooManyTypeParameters`,
  `TooManyParameters`, `TooManyTypeNodes`,
  `IdentifierTooLong`, `InvalidIdentifier` (structurally
  unreachable — see structural-impossibility section
  below), `MaxFunctionDefinitionsReached`,
  `MaxDataDefinitionsReached`,
  `MaxFieldDefinitionsReached` (reuses `FieldOwnerKind`
  from B-2.3), `MaxVariantsInEnumReached`.
- New public closed enum `HandleKind` (`DatatypeHandle`,
  `FunctionHandle`) re-exported via `validator/mod.rs`
  and `lib.rs`.

### Phase 5/5b.2 B-3.2 (`recursive_data_def` pass + petgraph promotion):

- `module_pass::recursive_data_def::verify(module)` —
  cycle detection over the module's struct + enum field
  graph per upstream
  `move-bytecode-verifier::data_defs::RecursiveDataDefChecker`.
  Builds `petgraph::graphmap::DiGraphMap<DataIndex, ()>`;
  runs `petgraph::algo::toposort`; `Err(cycle)` ⇒ reject.
- **Petgraph promoted to `adamant-vm`'s production
  `[dependencies]`** at B-3.2. First non-Sui-vendor-
  derived production dep on `adamant-vm`. Audit-template
  doc-comment lives inline in `crates/adamant-vm/Cargo.toml`,
  serving as the section anchor for "External production
  dep audit template" below. MSRV verified at B-3.2 start
  (petgraph 0.8.3 documents `rust-version = "1.64"`;
  Adamant pins `rust-toolchain.toml` channel `1.95.0`;
  +31 minor-release cushion).
- Internal `DataIndex { Struct(TableIndex),
  Enum(TableIndex) }` private helper keeps struct/enum
  positions distinct in the graph (graph-internal vs
  public-error-surface separation).
  `DataIndex::into_error_kind()` is the single conversion
  point at error construction.
- New `AdamantValidationError` variant:
  `RecursiveDataDefinition { kind: FieldOwnerKind, idx:
  TableIndex }`. Reuses `FieldOwnerKind` from B-2.3 per
  the B-3 plan's Q3 disposition.

### Phase 5/5b.2 B-3.3 (`instantiation_loops` pass):

- `module_pass::instantiation_loops::verify(module)` —
  generic-instantiation-loop detection per upstream
  `move-bytecode-verifier::instantiation_loops::InstantiationLoopChecker`.
  Builds `petgraph::Graph<Node, Edge>` where
  `Node = (FunctionDefinitionIndex, TypeParameterIndex)`
  and `Edge = Identity | TyConApp(SignatureToken)`. Runs
  `petgraph::algo::tarjan_scc`; rejects the first non-
  trivial SCC containing ≥1 `TyConApp` edge.
- Internal `Checker<'a>` struct holds the graph,
  node-index map, and function-handle-to-def map. Walks
  `CallGeneric` instructions in non-native function
  bodies; `BytecodeInstruction::Adamant(_)` arm continues
  without adding edges (Q5 from B-2 plan: 17 extensions
  don't perturb the graph).
- Native-function filter via `!def.is_native()` guard at
  the start of `build_graph` — fourth instance of the
  structural-impossibility-checks pattern with the
  "implicit-filter exclusionary" sub-pattern.
- Component-summary diagnostic format byte-faithful to
  upstream's `"edges with constructors: [{}], nodes: [{}]"`
  template. Adamant's `define_index!`-generated `Display`
  and `Debug` derives produce byte-identical output.
  Empirically validated by a Layer B parity test that
  pins the format prefix, separator, suffix, and the
  presence of `f0#0` node + `--Vector(TypeParameter(0))-->`
  edge fragments.
- New `AdamantValidationError` variant:
  `LoopInInstantiationGraph { component_summary:
  String }`. Diagnostic-only `String` per Q4 from B-2
  plan; not consensus-binding (the rejection is, the
  formatting isn't); future sub-arc can promote to typed
  if downstream consumers need pattern-matching.

### Phase 5/5b.2 B-4.1 (`rule_02_privacy` Rule 2 — privacy-metadata):

- `validator::rule_02_privacy::verify(module)` — Adamant-
  specific Rule 2 per §6.2.1.6: every `Visibility::Public`
  function must appear in the module's `b"adamant.privacy"`
  metadata table. **Lands in
  `crates/adamant-vm/src/validator/`, not in this
  `module_pass/` subtree** — parallels
  `rule_01_mutability.rs`'s placement (the rule_*.rs files
  are step-5 Adamant rules per §6.2.1.8).
- Walk-backs honored verbatim from this morning's spec
  verification:
  - **Q3 (visibility coverage):** Public-only per §6.2.1.3
    line 387 + §6.2.1.6 Rule 2 (Friend not mentioned in
    spec; original Friend-coverage approval was
    extrapolation, not spec). Three Q3 behavioral lock
    fixtures (`module_with_friend_only_no_privacy_entry_passes`,
    `module_with_friend_and_public_friend_not_in_table_passes`,
    `module_with_public_and_private_private_not_in_table_passes`)
    pin Public-only coverage under realistic conditions.
  - **Q4 (cardinality):** option (b) — zero entries
    allowed iff no Public functions; one entry standard;
    multiple always rejected.
- Four new `AdamantValidationError` variants:
  `MissingPrivacyMetadata`, `MultiplePrivacyMetadata`,
  `MalformedPrivacyMetadata` (shared with B-4.2),
  `MissingPrivacyAnnotation`.
- BCS-decode of `Vec<(FunctionDefinitionIndex, u8)>`
  payload at the n=1 cardinality arm; failure produces
  `MalformedPrivacyMetadata { bcs_error: String }`. Coverage
  check via `HashSet<FunctionDefinitionIndex>` lookup;
  first-uncovered Public function reports
  `MissingPrivacyAnnotation`.

### Phase 5/5b.2 B-4.2 (`privacy_metadata_structure` module-level pass):

- `module_pass::privacy_metadata_structure::verify(module)`
  — Adamant-specific structural pass per §6.2.1.8 step 3,
  sibling to the seven B-2/B-3 step-3 passes ported above.
  For each `b"adamant.privacy"` metadata entry:
  BCS-decodes payload; validates per-pair byte-in-set
  (`{0x00, 0x01}`), index-in-range
  (`< function_defs.len()`), and no-duplicate-within-entry.
- **Cardinality is NOT checked here** — deferred to Rule 2
  (B-4.1) per the §6.2.1.8 step-3-vs-step-5 split. Modules
  with zero, one, or many entries pass this pass treats
  them all the same way (one validation pass per entry).
- Three new `AdamantValidationError` variants:
  `InvalidPrivacyAnnotationByte`, `PrivacyEntryOutOfRange`,
  `DuplicatePrivacyEntry`. Plus shared
  `MalformedPrivacyMetadata` from B-4.1.
- **Deliberate-Adamant-decision: per-pair check ordering.**
  byte → range → duplicate (cheapest-check-first
  rationale; alternative-orderings-defensible note). No
  upstream Sui analog for `(FunctionDefinitionIndex, u8)`
  list-payload validation; the ordering is a fresh Adamant
  choice with rationale documented inline so future cross-
  validation gaps don't get mischaracterized as porting
  bugs. See "Deliberate-Adamant-decision pattern" section
  below.
- **No Layer B parity tests by design** — Adamant-specific
  pass; no upstream Sui equivalent. See "No-Sui-parity-
  claim posture" section below.

### Pending (later sub-arcs of Phase 5/5b.2):

### Phase 5/5b.2 B-5 (pipeline integration):

- `validator::verify_module` wires 8 module-level passes
  at step 3 + 3 Adamant rules at step 5 per §6.2.1.8
  five-step ordering. Step 3 batch in cross-pass-
  precedence-driven invocation order (constants at
  position 1; positions 2–8 alphabetical for audit-
  friendliness). Step 5 batch in numerical rule order
  (Rule 1, Rule 2, Rule 4).
- **Cross-pass eager-error precedence** is consensus-
  binding from B-5 forward. Constants wins over limits
  on `MalformedConstantData`; privacy_metadata_structure
  wins over Rule 2 on `MalformedPrivacyMetadata` via
  step-3-before-step-5 ordering.
- **Threading `&AdamantStructuralLimits`** to
  `limits::verify` per its signature divergence (B-3.1
  carry-forward). Other step-3 passes take only
  `&module`.
- **Nine module-level `#![allow(dead_code)]` sunsets
  removed** in the same commit as the wiring:
  `constants.rs`, `friends.rs`,
  `ability_field_requirements.rs`,
  `instruction_consistency.rs`, `limits.rs`,
  `recursive_data_def.rs`, `instantiation_loops.rs`,
  `privacy_metadata_structure.rs`, `rule_02_privacy.rs`.
  Build clean post-removal confirms genuine consumption
  via `verify_module` wiring.
- **Sui-verifier-bridge transitional** retained behind
  `if !module.contains_adamant_extensions()` guard for
  inherited-subset modules. Defense-in-depth on inherited
  subset; tears out at 5/5b.5 when per-function passes
  land.
- **16 new integration + precedence-parity tests** added
  at `validator/mod.rs::tests`: 6 cross-pass eager-error
  precedence tests (3 for `MalformedConstantData`, 3 for
  `MalformedPrivacyMetadata`) + 10 full-pipeline
  integration tests covering breadth across each step-3
  pass and each step-5 rule.

### Phase 5/5b.2 B-6 (closure batch):

- Documentation-only sub-checkpoint closing Phase 5/5b.2.
- This section update + the changelog entry below + the
  CLAUDE.md state-bump together capture the Phase 5/5b.2
  outcome.

### Remaining Phase 5/5b work (post-Phase-5/5b.2):

Phase 5/5b.2 closes at B-6. Remaining Phase 5/5b sub-arcs:

- **Phase 5/5b.3:** Three large module-level passes
  deferred from Phase 5/5b.2's plan: `BoundsChecker`,
  `DuplicationChecker`, `SignatureChecker`. These are
  the upstream Sui passes with the highest LOC counts
  (873 + 412 + 524 ≈ 1809 upstream LOC). They sit at
  step 3 alongside the eight passes already ported.
  When 5/5b.3 lands, the §6.2.1.8 step-3 batch becomes
  11 passes; cross-pass precedence ordering is re-
  evaluated per any new shared-variant claims.
- **Phase 5/5b.4:** Per-function passes infrastructure
  (CFG construction; abstract-interpreter framework;
  borrow-graph framework) + Rule 3 (privacy
  consistency). Step-4 of §6.2.1.8 currently delegates
  to the transitional Sui-verifier bridge; 5/5b.4
  begins the Adamant-native port of step-4 passes.
- **Phase 5/5b.5:** Type-safety + reference-safety per-
  function passes + Rules 6, 7 + final pipeline
  integration with Sui-verifier bridge fully removed +
  build-system independence check via
  `tests/no_sui_in_production_deps.rs`. After 5/5b.5,
  the production binary's dependency graph contains
  zero `move-*` crates per the resistant-proof posture.

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

**Phase 5/5b.2 B-3.1 deviations (`limits` pass):**

- **Typed-error fork.** Upstream returns
  `PartialVMResult<()>`. Adamant returns
  `Result<(), AdamantValidationError>` with 10 closed
  variants (`TooManyVectorElements`,
  `TooManyTypeParameters`, `TooManyParameters`,
  `TooManyTypeNodes`, `IdentifierTooLong`,
  `InvalidIdentifier`, `MaxFunctionDefinitionsReached`,
  `MaxDataDefinitionsReached`,
  `MaxFieldDefinitionsReached`,
  `MaxVariantsInEnumReached`) plus reuse of
  `MalformedConstantData` from B-2.1 for the vector-length
  sub-check's ULEB128-prefix-read path. Same rationale as
  B-2.1.
- **Signature shape divergence.** `verify(module, limits)`
  takes `&AdamantStructuralLimits` as a second parameter
  — the only B-2/B-3 pass with a config parameter.
  Sibling passes take only `&module`. B-5's pipeline
  integration threads `config.structural_limits()` from
  `AdamantVerifierConfig` to `limits::verify`
  specifically.
- **Vector-length sub-check via outer ULEB128 prefix
  read.** Upstream calls `Constant::deserialize_constant`
  which uses `MoveValue::simple_deserialize` from
  `move_core_types::runtime_value` — Adamant has no
  production dep on that path per the resistant-proof
  posture. Replacement reads only the outer ULEB128
  length prefix via `read_uleb128_as_u64`; the count is
  semantically equivalent to upstream's element count for
  `Vector<T>` constants. Reuses
  `MalformedConstantData { reason:
  MalformedConstantReason::InvalidUleb128 }` from B-2.1
  if the prefix read fails — defense-in-depth structural
  redundancy with B-2.1's full type-directed walker
  (constants pass typically wins eager-error precedence
  per pipeline ordering).
- **`<SELF>` rejection structurally unreachable in
  Adamant.** The `disallow_self_identifier` config check
  at `verify_identifiers` is structurally unreachable
  because `Identifier::new("<SELF>")` returns `Err` per
  `is_valid_identifier_char`'s acceptance set
  (`'_' | 'a'..='z' | 'A'..='Z' | '0'..='9'`); ASCII `<`
  (`0x3C`) and `>` (`0x3E`) fall in the gap between `'9'`
  (`0x39`) and `'A'` (`0x41`). Verbatim verification at
  B-3.1 commit `0dc98a7`. Pinned by the
  `self_identifier_cannot_be_constructed_via_identifier_new`
  test asserting `Identifier::new("<SELF>")` returns
  `Err`. Second instance of the structural-impossibility-
  checks pattern's "explicit-macro defensive" sub-pattern
  — see "Structural-impossibility checks pattern"
  section below.
- **Six sub-check ordering preserved byte-faithfully**
  (Q5 from B-3 plan): `verify_constants` →
  `verify_function_handles` → `verify_datatype_handles`
  → `verify_type_nodes` → `verify_identifiers` →
  `verify_definitions`. Matches upstream's
  `LimitsVerifier::verify_module_impl` ordering.
- **`max_type_nodes` weighting preserved byte-faithfully**
  (Q6 from B-3 plan):
  `STRUCT_SIZE_WEIGHT: usize = 4`,
  `PARAM_SIZE_WEIGHT: usize = 4`, primitives count as 1.
  See `verify_type_node` constants.

**Phase 5/5b.2 B-3.2 deviations (`recursive_data_def` pass + petgraph promotion):**

- **Typed-error fork.** Upstream returns
  `PartialVMResult<()>`. Adamant returns
  `Result<(), AdamantValidationError>` with closed variant
  `RecursiveDataDefinition { kind: FieldOwnerKind, idx:
  TableIndex }`. Reuses `FieldOwnerKind` from B-2.3 per
  Q3 disposition (instance of byte-faithful preservation
  of upstream cardinality decisions — see "Byte-faithful
  preservation of upstream consensus-affecting decisions"
  section below).
- **Petgraph promoted to production dependency.** First
  non-Sui-vendor-derived production dep on `adamant-vm`.
  Audit-template doc-comment in `crates/adamant-vm/Cargo.toml`
  inline with the dep entry. See "External production dep
  audit template" section below.
- **Internal `DataIndex { Struct, Enum }` graph-internal
  helper vs `(FieldOwnerKind, TableIndex)` public-error
  surface.** Pattern for future graph-pass internal node
  types: graph-internal node type kept distinct from the
  public error variant's shape;
  `DataIndex::into_error_kind()` is the single
  conversion point at error construction.
- **Two structural-impossibility paths with
  spec-pipeline-impossibility-pending-port qualifier.**
  Duplicate handle-to-def mapping (`assert!`) and
  reference field in datatype position (`unreachable!`).
  Both messages include "not yet ported" qualifier
  referencing the upstream-of-this-pass guarantee
  (`DuplicationChecker` / `SignatureChecker` not yet
  ported in Phase 5/5b.2). Cleanup item: when those
  passes land in a later sub-arc, the qualifier drops.

**Phase 5/5b.2 B-3.3 deviations (`instantiation_loops` pass):**

- **Typed-error fork.** Upstream returns
  `PartialVMResult<()>`. Adamant returns
  `Result<(), AdamantValidationError>` with closed variant
  `LoopInInstantiationGraph { component_summary:
  String }`. Diagnostic-only `String` per Q4 from B-2
  plan; not consensus-binding. Future sub-arc can promote
  to typed.
- **Two-typed graph algorithm preserved byte-faithfully.**
  `Edge = Identity | TyConApp(SignatureToken)`. Edge
  cardinality preserves one-edge-per-type-parameter in
  the actual-type's preorder (Q1 from B-3.3 plan;
  instance of byte-faithful preservation of upstream
  cardinality decisions).
- **Native-function filter via implicit-filter
  exclusionary sub-pattern.** `if !def.is_native()` guard
  at the start of `build_graph` filters out structurally-
  impossible input rather than panicking. Native
  functions are rejected by Rule 4 at a different
  pipeline stage; this filter is byte-faithful defense-
  in-depth. First instance of the structural-
  impossibility-checks pattern's "implicit-filter
  exclusionary" sub-pattern.
- **Adamant extensions don't perturb the graph** (Q5
  from B-2 plan). 17 extensions per §6.2.1.4 either use
  `FunctionHandleIndex` (non-generic call shape, no
  type-arguments) or are zero-operand / non-instantiation-
  operand. Pass's instruction match adds early-return Ok
  arm for `BytecodeInstruction::Adamant(_)` per B-2.4
  pattern. Layer A test pins no-perturbation behaviour.
- **Component-summary diagnostic byte-faithful to
  upstream.** Format `"edges with constructors: [{}],
  nodes: [{}]"`; Adamant's `define_index!`-generated
  `Display` and `Debug` derives produce byte-identical
  output. Empirically validated by the
  `rejects_with_byte_faithful_component_summary` test.
  Diagnostic isn't consensus-binding, but byte-
  faithfulness is a free audit anchor.
- **`#[allow(clippy::similar_names)]` on
  `Checker::build_graph_call`.** Paired `caller_idx` /
  `callee_idx` parameter names trip the lint; semantic
  clarity outweighs the lint, and the names are upstream-
  faithful. Reason: `"caller/callee are paired upstream-
  faithful naming"`.

**Phase 5/5b.2 B-4.1 deviations (`rule_02_privacy` Rule 2):**

- **Adamant-specific rule.** No upstream Sui equivalent —
  Rule 2 is one of the eight Adamant-specific rules per
  §6.2.1.6. The "no Sui parity claim" posture applies; see
  "No-Sui-parity-claim posture" section below.
- **Q3 walk-back: visibility coverage is Public-only.** Per
  §6.2.1.3 line 387 + §6.2.1.6 Rule 2 spec text, only
  `Visibility::Public` functions are required to have a
  privacy annotation. `Visibility::Friend` and
  `Visibility::Private` functions MAY appear in the table
  (the structural pass at B-4.2 validates byte/index/
  duplicate well-formedness for any entry that does
  appear), but they are NOT required to appear. The
  original B-2-plan-time approval that included Friend
  was an extrapolation, not a spec claim. Three Q3
  behavioral lock fixtures pin the Public-only meaning
  under realistic conditions (Friend-only-no-entry;
  Friend+Public-Friend-not-in-table;
  Public+Private-Private-not-in-table).
- **Q4 walk-back: cardinality option (b).** Spec §6.2.1.3
  line 377 uses "**a** Metadata entry" (singular indefinite
  article) without the "exactly one" qualifier §6.2.1.3
  line 375 uses for mutability. Spec is silent on
  cardinality; option (b) means zero entries allowed iff
  no Public functions; one entry standard; multiple
  always rejected.
- **`MalformedPrivacyMetadata` shared with B-4.2.** Pipeline
  ordering at B-5 wiring puts B-4.2's structural pass at
  step 3 before Rule 2 at step 5; B-4.2 typically wins
  eager-error precedence on the same input. Second
  instance of the shared-variant-with-pipeline-ordering-
  eager-error sub-pattern after B-2.1 + B-3.1's
  `MalformedConstantData`. See "Eager-error first-failure-
  wins" section below.

**Rule 1 / Rule 2 structural-pass-asymmetry rationale:**

Rule 1 (mutability) does its own BCS decode within
`rule_01_mutability::verify` without a parallel structural
pass; Rule 2 has a parallel structural pass at B-4.2. The
asymmetry is **metadata-payload-shape-driven**, not
arbitrary:

- **Rule 1's payload** is a single enum value
  (`Mutability`) — one byte that BCS-decodes to a known
  variant. The structural validity check (decodability
  + variant-recognition) happens inline with the Rule 1
  semantic check (cardinality). Splitting would duplicate
  the BCS decode with no benefit.
- **Rule 2's payload** is a list of `(FunctionDefinitionIndex,
  u8)` pairs with multiple distinct structural checks
  (byte values, index ranges, duplicates within list).
  Splitting validates each pair structurally at step 3
  (granular error variants per check type) before Rule 2
  validates coverage at step 5 (list-as-set semantic
  check). The split gives finer-grained error reporting
  and matches §6.2.1.8's step-3-vs-step-5 architecture.

If a future Rule N has a list-of-pairs payload structurally
similar to Rule 2, the structural-pass split is the
established pattern. If similar to Rule 1's single-enum-
value, no split. Future readers should not see the asymmetry
as inconsistency; it is metadata-shape-driven.

**Phase 5/5b.2 B-4.2 deviations (`privacy_metadata_structure` pass):**

- **Adamant-specific pass.** No upstream Sui equivalent —
  no Sui pass validates the `b"adamant.privacy"` metadata
  key or the `(FunctionDefinitionIndex, u8)` list-payload
  shape. The "no Sui parity claim" posture applies; see
  "No-Sui-parity-claim posture" section below.
- **Deliberate-Adamant-decision: per-pair check ordering.**
  The ordering byte → range → duplicate is a fresh
  Adamant decision, not byte-faithful preservation of
  upstream. Cheapest-check-first rationale: byte (single
  comparison) before range (comparison + length lookup)
  before duplicate (`HashSet::insert` allocation +
  hashing). Alternative orderings are defensible (e.g.,
  fail-fast on most-diagnostic-useful error first); the
  ordering chosen is documented inline so future cross-
  validation gaps don't get mischaracterized as porting
  bugs. See "Deliberate-Adamant-decision pattern" section
  below for the full pattern framing.
- **`MalformedPrivacyMetadata` shared with B-4.1.** This
  pass typically wins cross-pass eager-error precedence
  over Rule 2 at B-5 wiring per §6.2.1.8 step-3-vs-step-5
  ordering. See B-4.1 deviation note above and the
  "Eager-error first-failure-wins" section below.
- **Cardinality NOT checked here** — deferred to Rule 2
  (B-4.1) per the §6.2.1.8 step-3-vs-step-5 split. The
  pass iterates all entries with the privacy key and
  validates each one independently; cardinality (zero/
  one/many) is Rule 2's concern. A module with multiple
  well-formed privacy entries passes this pass; Rule 2
  rejects them at step 5.

**Phase 5/5b.2 B-5 deviations (pipeline integration):**

- **Within-step invocation order is implementation-
  discretionary per §6.2.1.8 line 563.** Step-3 batch
  uses cross-pass-precedence-driven ordering: constants
  at position 1 (precedence-driven; before limits per
  `MalformedConstantData` shared-variant precedence);
  positions 2–8 alphabetical for audit-friendliness.
  Step-5 batch uses numerical rule order (Rule 1, 2, 4).
  See "Wiring conventions" sub-section below for the
  established pattern.
- **Cross-pass eager-error precedence becomes consensus-
  binding from B-5 forward.** Two shared variants:
  `MalformedConstantData` (constants wins over limits)
  and `MalformedPrivacyMetadata` (privacy_metadata_
  structure wins over Rule 2 via step-3-before-step-5
  ordering). The accept/reject behaviour Adamant's
  verifier exhibits is consensus-binding per §6.2.1.8
  line 563; cross-pass precedence is part of accept/
  reject-behaviour-on-malformed-input. See "Eager-error
  first-failure-wins" pattern section below.
- **Sui-verifier-bridge transitional retained.** Step-3
  Adamant-native passes run unconditionally; the Sui
  bridge runs conditionally (`if
  !module.contains_adamant_extensions()`) for inherited-
  subset modules as defense-in-depth. The bridge tears
  out at 5/5b.5 when per-function passes land. During
  the transitional period, Adamant-native passes and
  the Sui bridge produce partially-overlapping coverage
  on inherited-subset module-level checks; the
  redundancy is intentional.

### Wiring conventions

Established at Phase 5/5b.2 B-5 for module visibility
and pipeline ordering. Future pass additions follow the
same pattern.

**Module visibility:**

- Modules in `module_pass/` that are wired into
  `verify_module` use `pub(super) mod foo;` so the
  parent `validator` module can reach `module_pass::foo::verify`.
- Modules used only internally by another pass (e.g.,
  `ability_cache` consumed only by
  `ability_field_requirements`) use private `mod foo;`.
- The convention surfaced when initial B-5 wiring
  failed with private-module errors; the eight wired
  passes were promoted in the same commit as the
  wiring.

**Pipeline ordering within a §6.2.1.8 step:**

- Cross-pass eager-error precedence is the binding
  constraint: any pass whose first-error variant is
  shared with another pass must run before the other
  pass for the precedence claim to hold. See "Eager-
  error first-failure-wins" pattern section below.
- Beyond cross-pass-precedence, ordering is alphabetical
  by pass name for audit-friendliness. Future readers
  scanning `verify_module` can predict pass-position
  from pass-name without looking at the source.
- §6.2.1.8 line 563 explicitly classifies within-step
  pass-orchestration as implementation-discretionary;
  cross-pass-precedence-driven plus alphabetical-of-
  remainder is an Adamant convention, not a spec
  prescription.

### Wiring-time fixture-update methodology pattern

Established at Phase 5/5b.2 B-5 when wiring Rule 2.

When a previously-unwired rule becomes live via wiring
into `verify_module`, existing fixtures may need updates
to satisfy the now-live rule. Future wiring sub-arcs
follow the same pattern.

Pattern instances:

- **B-5 instance:** `rich_valid_module()` fixture in
  `validator/test_fixtures.rs` had a `Visibility::Public`
  function but no `b"adamant.privacy"` metadata entry.
  When Rule 2 (B-4.1) was wired at B-5, the fixture
  became invalid under the now-live coverage check;
  `rich_canonical_module_round_trips` test failed.
  Fixed by adding a privacy entry covering the Public
  function with byte `0x00` (transparent).
- **Future expected instances:** Phase 5/5b.5 Sui-
  verifier-bridge tear-out — when the bridge is
  removed, Adamant-native per-function passes become
  the only path; existing fixtures may have shapes that
  the Sui bridge accepted but Adamant-native passes
  reject (or vice versa). When pre-mainnet calibration
  changes structural-limits values from `None` to
  concrete bounds (B-1 carry-forward), existing
  fixtures may exceed new bounds and need adjustment.

The pattern's audit anchor: any sub-arc that wires
previously-unwired rules or removes transitional
passes carries a fixture-update review as part of its
implementation gate.

### Integration-test depth limitation

Established at Phase 5/5b.2 B-5 with the
`limits_alone_fires_on_input_triggering_only_limits`
fixture pivot.

The limits-alone-fires precedence pin under genesis
defaults requires a fixture that exceeds
`max_constant_vector_len` (1 MiB), impractical for test
fixtures. The integration-level pin is omitted; depth
coverage lives at the per-pass Layer A level (23 tests
covering each limits sub-check independently). If
future test work wants integration-level limits-alone-
fires coverage, the path is a test-only
`AdamantVerifierConfig::with_structural_limits`
builder; this is deferred as a known follow-up rather
than added speculatively.

The B-5 fixture
(`limits_alone_fires_on_input_triggering_only_limits`)
landed as a structural-shape pass-through under genesis
defaults (well-formed vector constant within bounds;
both passes accept) rather than the symmetric reject-
parity assertion. The 5 other precedence-parity tests
plus the per-pass Layer A coverage carry the load-
bearing precedence claim.

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

7. **`module_pass::limits::verify`** accepts the same
   module configurations as Sui's
   `move_bytecode_verifier::limits::LimitsVerifier::verify_module`
   for any `(module, limits)` pair where the structural-
   limit fields match. Asserted by 6 Layer B parity tests
   covering each sub-check (function-handle type-params,
   function parameters, identifier length, vector
   constant, plus accept-empty parity). The
   `<SELF>`-rejection path is structurally unreachable in
   Adamant — no cross-validation parity claim applies (an
   `<SELF>` identifier cannot be constructed via Adamant's
   `Identifier::new` API; see B-3.1 deviations above).
8. **`module_pass::recursive_data_def::verify`** accepts
   the same module configurations as Sui's
   `move_bytecode_verifier::data_defs::RecursiveDataDefChecker::verify_module`
   for any module shape produceable through
   `to_sui_module`'s BCS round-trip. Asserted by 6 Layer
   B parity tests covering empty, non-recursive struct,
   chain (no cycle), self-referencing struct, two-struct
   cycle, and self-referencing enum variant.
9. **`module_pass::instantiation_loops::verify`** accepts
   the same module configurations as Sui's
   `move_bytecode_verifier::instantiation_loops::InstantiationLoopChecker::verify_module`
   for any module shape produceable through
   `to_sui_module`. Asserted by 6 Layer B parity tests
   covering empty, function with no `CallGeneric`,
   identity-only self-cycle (allowed), self-edge with
   `TyConApp`, two-function `TyConApp` cycle, and linear
   `TyConApp` no-cycle. Plus 1 component-summary parity
   test pinning the byte-faithful diagnostic format
   commitment empirically.

10. **`validator::rule_02_privacy::verify` carries no Sui
    parity claim.** Rule 2 is one of the eight Adamant-
    specific rules per §6.2.1.6; there is no upstream Sui
    pass validating `b"adamant.privacy"` metadata
    coverage. The pass's behaviour is anchored to the
    walk-back-locked Q3 (Public-only visibility coverage)
    and Q4 (option (b) cardinality) contracts rather than
    a parity claim against an upstream pass. See
    "No-Sui-parity-claim posture" section below.
11. **`module_pass::privacy_metadata_structure::verify`
    carries no Sui parity claim.** The pass validates an
    Adamant-specific metadata key with an Adamant-specific
    payload shape; no upstream Sui pass exists to compare
    against. Behaviour is anchored to the deliberate-
    Adamant-decision per-pair check ordering (byte →
    range → duplicate, cheapest-check-first) documented
    inline in the pass's doc-comment. See
    "Deliberate-Adamant-decision pattern" section below.

Phase 5/5b.2 B-4 closes the invariants list at #11. B-5
(pipeline integration) and B-6 (closure) do not extend the
list further — the invariants are accept/reject parity
claims against upstream, and B-5/B-6 don't add new passes
with parity to assert.

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

### `max_loop_depth = Some(64)` (Bucket C, D-2)

Bucket C — spec gap, provisional value. Sui ships
`max_loop_depth: None` in `VerifierConfig::default()` with no
commented alternative. Adamant's verifier is the consensus
boundary; `None` would expose validators to deploy-time DoS
through pathologically nested loops, which run abstract
interpretation in time exponential in nesting depth. Provisional
value `Some(64)` chosen to:

- Comfortably exceed any plausible legitimate code (deeply
  nested for-loops in practice rarely exceed 4-5 levels;
  loop-rolled state machines may reach 8-10 levels).
- Bound abstract-interpretation cost at the per-function passes
  (D-3..D-5) at a flat constant factor.

§6.2.1.7 spec-amendment workstream item (CLAUDE.md "Open
properties" 5a) tracks the pre-mainnet calibration. If the
amendment lands a different value, that resolution is
plan-incremental-disposition-resolved-empirically at the
spec-amendment level, not a D-2 sub-checkpoint correction.
Consumed by `function_pass::control_flow::verify_reducibility`.

## Out-of-scope fields (registered for future sub-arcs)

`AdamantStructuralLimits` covers **module-level deploy-time
bounds**. The following Sui `VerifierConfig` fields are
deliberately not included; each lives at a different layer:

- `max_basic_blocks`, `max_push_size`,
  `max_back_edges_per_function`, `max_back_edges_per_module` —
  per-function-pass concerns (CFG width, push-count bounds);
  extend `AdamantStructuralLimits` in Phase 5/5b.4 alongside
  the per-function passes that consume them. (`max_loop_depth`
  was previously in this list and landed at D-2 alongside the
  control-flow validation pass — see the entry above.)
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
  scope; consumed at B-2.4 and B-3.1 cross-validation).**
  Two passes use `VerifierConfig` at test time:
  - B-2.4: Sui's
    `instruction_consistency::InstructionConsistency::verify_module`
    takes `&VerifierConfig` for its
    `safe_assert!(!config.deprecate_global_storage_ops)`
    check. Adamant's Layer B helper passes
    `VerifierConfig::default()` (sets
    `deprecate_global_storage_ops = true`, exercising the
    fully-deprecated-opcode-rejection path Sui ships in
    production).
  - B-3.1: Sui's `LimitsVerifier::verify_module` takes
    `&VerifierConfig`. Adamant's Layer B helper builds a
    `VerifierConfig` whose structural-limits fields mirror
    the Adamant `AdamantStructuralLimits` test fixture; the
    rest of `VerifierConfig` defaults. Confirms parity at
    the same configured limits.

  No production-side use of `VerifierConfig` for either
  pass — the dependency is already in scope from the
  validator wrapper bridge and is removed alongside it in
  Phase 5/5b.5.

## Spec amendment workstream

Phase 5/5b.2 surfaced two §6.2.1 spec-amendment carry-
forwards that don't block phase closure but should be
tracked together for the §6.2.1 family. Both registered in
CLAUDE.md "Open properties to track" at B-6 closure,
distinct from the genesis-pool calibration item.

### §6.2.1.7 structural-limits values

§6.2.1.7 specifies structural limits as genesis-fixed but
does not enumerate values. The Phase 5/5b.2 B-1
implementation ships provisional values per the
Bucket A/B/C disposition documented above (the "Genesis
structural-limits values" section earlier). Adamant's
verifier is the consensus boundary for structural limits;
unlike Sui, no protocol-config layer backstops missing
bounds, so every field is concrete rather than `None`.

Pre-mainnet workstream raises a §6.2.1.7 amendment
proposal to enumerate the values in the spec, parallel to
the per-instruction gas-cost appendix pattern. The
provisional values in B-1 are not arbitrary — they're
derived from Sui's commented alternatives (Bucket A),
Sui's literal defaults (Bucket B), and DoS/memory/
practical-use reasoning (Bucket C) — but the spec
amendment makes the values part of the canonical spec
text rather than implementation-discretionary defaults.

Registered at B-1; reaffirmed at B-3.4 and B-6.

### §6.2.1.8 cross-pass eager-error precedence

§6.2.1.8 line 563 classifies within-step pass-
orchestration as implementation-discretionary while
pinning accept/reject behaviour as fixed. Phase 5/5b.2
established that **cross-pass eager-error precedence is
part of accept/reject behaviour**: when a shared error
variant can be produced by two passes for the same input,
which-error-fires-first is a consensus-binding property,
not implementation-discretionary.

Two shared-variant precedence claims are consensus-binding
from B-5 forward:

- `MalformedConstantData` shared between B-2.1
  `module_pass::constants` and B-3.1 `module_pass::limits`
  vector-length sub-check. Pipeline ordering: constants
  at step-3 position 1; limits at position 6. Constants
  wins on the same malformed-ULEB128 input.
- `MalformedPrivacyMetadata` shared between B-4.2
  `module_pass::privacy_metadata_structure` and B-4.1
  `validator::rule_02_privacy`. Pipeline ordering:
  structural pass at step 3; Rule 2 at step 5.
  privacy_metadata_structure wins via spec-pinned step-3-
  before-step-5 ordering.

Pre-mainnet workstream raises a §6.2.1.8 amendment
proposal to capture cross-pass eager-error precedence
explicitly in the spec, similar in shape to the §6.2.1.7
amendment for structural limits. Currently the precedence
claims are anchored in this PROVENANCE.md ("Eager-error
first-failure-wins" pattern section below) and in the
verbatim test fixtures at `validator/mod.rs::tests` —
both are audit-trail anchors, but the spec-text amendment
makes the property normative for any future
implementation.

Registered at B-5; carried forward to B-6.

## Structural-impossibility checks pattern

Upstream Sui has defense-in-depth checks for inputs that
Adamant's pipeline rejects earlier (or is structurally
prevented from accepting). Adamant's port keeps the check
(byte-faithful match shape, defense-in-depth posture) but
documents the structural impossibility and pin-tests the
upstream-of-this-pass guarantee rather than negative-testing
the unreachable path.

Three sub-patterns are named:

### 1. Explicit-macro defensive

`assert!` / `unreachable!` / `expect()` at unreachable code
paths. Used when reaching the path would indicate a serious
bug (broken upstream pass, bypassed deserializer, programmer
error). The macro message documents the structural argument
inline so an auditor reading the source can verify the
unreachability claim without external context.

Instances:

- **B-2.4 deprecated-arms `unreachable!`** — the 10
  deprecated global-storage opcodes (`ExistsDeprecated`
  et al.) are rejected at deserialize-time per
  §6.2.1.6 Rule 5; verifier-level arm exists for match
  exhaustiveness preservation but bodies are
  `unreachable!` with structural-impossibility messages
  referencing the deserializer tests
  (`bytecode_wire.rs:1242 strict_mode_rejects_each_deprecated_opcode`
  + `validator/mod.rs::tests::rejects_module_with_deprecated_global_storage_opcode`).
- **B-3.1 `<SELF>` rejection via
  `disallow_self_identifier` config check; structurally
  unreachable because `Identifier::new("<SELF>")`
  returns `Err` per `is_valid_identifier_char`'s
  acceptance set verification at B-3.1 commit
  `0dc98a7`.** Pinned via
  `self_identifier_cannot_be_constructed_via_identifier_new`
  test asserting the API-level rejection.
- **B-3.2 duplicate handle-to-def mapping (`assert!`)
  + reference field in datatype position
  (`unreachable!`).** Both messages include "not yet
  ported" qualifier — see "Spec-pipeline-impossibility-
  pending-port" sub-pattern below.

### 2. Implicit-filter exclusionary

`if !condition` guard that filters out structurally-
impossible input rather than panicking. Used when the
upstream check is exclusionary by design (skip processing
this category of input rather than reject). The filter
itself is byte-faithful defense-in-depth; the structural
argument lives in the doc comment rather than a panic
message.

Instances:

- **B-3.3 native-function filter via
  `!def.is_native()` guard** at the start of
  `instantiation_loops::Checker::build_graph`. Native
  functions are rejected by Rule 4 at a different
  pipeline stage; the filter here matches upstream
  byte-faithfully.

### 3. Spec-pipeline-impossibility-pending-port

Sub-sub-pattern of explicit-macro defensive where the
upstream-of-this-pass guarantee isn't yet ported in
Adamant. Macro message includes a "not yet ported"
qualifier referencing the pending pass; cleanup item
pinned for the later sub-arc that lands the relevant
upstream pass. When the relevant pass lands, the
qualifier drops from the message — known cleanup item
recorded in this PROVENANCE.md.

Instances:

- **B-3.2 duplicate handle-to-def mapping** —
  `DuplicationChecker` pending; `assert!` message
  includes "not yet ported (Phase 5/5b.2 B-3 large-pass
  set)".
- **B-3.2 reference field in datatype position** —
  `SignatureChecker` pending; `unreachable!` message
  includes "not yet ported (Phase 5/5b.2 B-3 large-pass
  set)".

### Pattern scope

The pattern is about the structural argument and the
test/doc-comment shape, not the specific macro or the
exclusionary-vs-defensive choice. Implementations choose
the most natural shape for the local code:

- `assert!` for "BTreeMap insert with duplicate"
- `unreachable!` for "closed match arm reached"
- `expect()` for "API-bounded error path resolved at
  call site"
- `if !condition` for "exclusionary filter at iteration
  start"

All four shapes are valid; the structural argument is
the load-bearing property. The
"spec-pipeline-impossibility-pending-port" qualifier
applies orthogonally to the explicit-macro sub-pattern.

## External production dep audit template

Established at Phase 5/5b.2 B-3.2 (petgraph promotion).
For each non-Sui-vendor-derived production dep added to
`adamant-vm`:

1. **License check** — must be compatible with Adamant's
   Apache 2.0.
2. **Maintenance posture** — mature (no obvious abandonment
   risk), semver-stable across major versions.
3. **MSRV verification** — documented MSRV ≤ Adamant's
   `rust-toolchain.toml` channel. Verbatim verification
   gate before promotion (paste the resolved version's
   `Cargo.toml` `rust-version` field).
4. **Transitive-dep review** — default features acceptable
   (or specific features pinned with rationale); any
   `unsafe` surface noted. No transitive dep that itself
   needs auditing without prior approval.
5. **`forbid(unsafe_code)` compatibility** — Adamant's
   workspace `forbid(unsafe_code)` lint applies to first-
   party code; deps with `unsafe` are permitted but the
   surface is noted in this PROVENANCE.md and SECURITY.md.
6. **Audit-template doc-comment** — inline in
   `crates/adamant-vm/Cargo.toml` (or the relevant crate's
   Cargo.toml) alongside the dep entry, summarizing the
   above five checks plus the Phase 5/5b.x register
   reference.
7. **Why this dep rather than implementing in-house** —
   register the implement-vs-adopt rationale. For mature
   well-trodden code (graph algorithms, BCS, hashing), the
   answer is usually "in-house implementation duplicates
   well-audited code with no audit benefit"; for
   cryptographic or consensus-binding code, the answer is
   often "in-house implementation has different audit-cost
   shape and may be preferred" — the question matters and
   the rationale should be recorded.

The audit applies to the major-version line within the
SemVer-stable contract. Cargo resolves to latest patch
within the workspace pin's range; resolution drift within a
major line is acceptable. Bumping to a new major version
requires audit re-run. The pin-vs-resolved distinction is
a deliberate posture: the workspace pin (`^0.8.1`) is the
audit-anchor declaration; the resolved patch (`0.8.3` at
B-3.2) is what the build sees.

Instances:

- **petgraph 0.8.x** (B-3.2 — first instance). License
  Apache-2.0/MIT dual; mature and semver-stable; MSRV
  1.64 vs Adamant's 1.95.0; default features acceptable
  (no `rayon` opt-in needed for our graph algorithms);
  internal `unsafe` in graph indexing noted; in-house
  implementation rationale: graph algorithms are well-
  trodden code with no Adamant-specific audit benefit
  from re-implementation.

## Byte-faithful preservation of upstream consensus-affecting decisions

Methodology principle registered at Phase 5/5b.2 B-3.3.
Divergence from upstream changes rejection behavior or
eager-error semantics; preserve byte-faithfully unless
explicit redirect (with redirect documented in "Adamant
deviations").

Scope: all consensus-affecting decisions, not cardinality
alone:

- **Cardinality** — number of edges, error-variant counts,
  iteration arities.
- **Ordering** — sub-check order, table iteration order,
  pipeline-stage order.
- **Weighting** — node/edge weights in graph algorithms,
  size weights in tree-traversal cost calculations.
- **Default values** — config defaults, pre-mainnet
  calibration anchors.
- **Error precedence** — eager-error semantics, first-
  offender reporting, sub-pass ordering for cross-pass
  shared variants.

Instances:

- **Cardinality** — B-3.2 `RecursiveDataDefinition`
  reuses `FieldOwnerKind` (`Struct | Enum`) rather than
  introducing a parallel `DataDefKind` enum (Q3 from
  B-2 plan). B-3.3 `TyConApp` edge cardinality preserves
  one-edge-per-type-parameter in the actual-type's
  preorder (Q1 from B-3.3 plan).
- **Ordering** — B-3.1 `limits` six sub-checks preserve
  upstream order: `verify_constants` →
  `verify_function_handles` → `verify_datatype_handles`
  → `verify_type_nodes` → `verify_identifiers` →
  `verify_definitions` (Q5 from B-3 plan).
- **Weighting** — B-3.1 `verify_type_node`'s `STRUCT_SIZE_WEIGHT
  = 4`, `PARAM_SIZE_WEIGHT = 4`, primitives = 1 (Q6 from
  B-3 plan).
- **Error precedence** — B-3.1 + B-2.1
  `MalformedConstantData` reuse: both passes can produce
  the variant for ULEB128-malformed vector constants;
  pipeline ordering (constants pass before limits per
  §6.2.1.8 step 3) means constants pass typically wins
  eager-error precedence. Defense-in-depth structural
  redundancy.

The principle generalizes: when in doubt, preserve
upstream behaviour byte-faithfully. Divergence requires a
deliberate redirect documented in "Adamant deviations"
above. This is the methodology counterpart to the
resistant-proof posture at the code level.

## No-Sui-parity-claim posture

When no upstream Sui equivalent exists or is reachable,
Layer B is omitted by design and the test module's
doc-comment plus the Byte-identity invariants entry both
explicitly note the omission. The pattern is about explicit
acknowledgment, not silent absence: future readers see "no
Sui parity claim — Adamant-specific" or "no Sui parity
claim — structurally unreachable" rather than wondering why
Layer B is missing.

Two reason-shapes:

- **Adamant-specific** — the pass validates an Adamant-only
  concern (Adamant-specific rule per §6.2.1.6, Adamant-
  specific metadata key, Adamant-specific opcode). No
  upstream Sui pass exists to compare against.
- **Structurally unreachable** — the pass's check fires on
  inputs that Adamant's pipeline can't construct (e.g.,
  `<SELF>` identifier rejected by `Identifier::new` per
  `is_valid_identifier_char`'s acceptance set). An upstream
  Sui pass exists, but Adamant fixtures can't reach the
  rejection path through any normal API; cross-validation
  fixtures would need API-bypass machinery (`new_unchecked`,
  `unsafe transmute`) that Adamant doesn't provide.

Pattern instances:

- **B-3.1 `<SELF>` rejection** (structurally unreachable —
  see invariant #7). Sui has a `disallow_self_identifier`
  check; Adamant inherits the check but can't reach it
  through any normal path. Pinned by a structural-
  impossibility test (`self_identifier_cannot_be_constructed_via_identifier_new`)
  rather than a cross-validation parity test.
- **B-4.1 Rule 2** (Adamant-specific — see invariant #10).
  Rule 2 is one of the eight Adamant-specific rules per
  §6.2.1.6; no upstream Sui equivalent. Layer A coverage
  carries the load-bearing surface (14 tests with explicit
  Q3 behavioral lock fixtures).
- **B-4.2 `privacy_metadata_structure`** (Adamant-specific
  — see invariant #11). No upstream Sui pass validates
  `b"adamant.privacy"` metadata. Layer A coverage covers
  the structural well-formedness checks (14 tests with
  complete precedence-ordering coverage at every axis).

For each instance, both the test module's doc-comment and
the corresponding byte-identity invariant entry explicitly
note the omission with the reason-shape. The pattern is
defensive against silent-absence-as-implicit-claim: a
future reader seeing Layer A but no Layer B might assume
the pass has parity but tests are missing; the explicit
"no Sui parity claim" framing prevents that misreading.

## Eager-error first-failure-wins as Phase 5/5b.2-wide methodology principle

When multiple violations exist, the verifier reports the
first encountered in deterministic iteration order.
Determinism matters for cross-validation parity — Sui and
Adamant must agree on which error fires first for any
given input.

**Cross-validation parity is not just accept/reject — it
includes eager-error precedence.** For shared variants
where Adamant and Sui both reject the same input, both
must report the same typed-error variant first. Layer B
tests asserting accept/reject outcomes implicitly test
this when the fixture has only one violation; multi-
violation fixtures explicitly pin which-error-fires-first
parity.

Two precedence axes:

- **Internal-to-pass:** within a single pass's logic (e.g.,
  B-4.1's cardinality-before-BCS-decode-before-coverage;
  B-4.2's byte-before-range-before-duplicate within a
  pair). Pinned by precedence tests inside the pass's
  test module.
- **Cross-pass:** between two passes that can produce the
  same shared variant. Pipeline ordering at B-5 wiring
  determines which pass typically wins. Pinned implicitly
  by pipeline ordering and explicitly by the "shared-
  variant-with-pipeline-ordering-eager-error" sub-pattern
  documented inline at each shared-variant call site.

Pattern instances:

- **B-3.2:** `petgraph::algo::toposort` returns first cycle
  node it encounters; pass reports that node's def as the
  offender.
- **B-3.3:** `petgraph::algo::tarjan_scc` returns first
  non-trivial SCC; pass filters to non-trivial-with-
  TyConApp and reports the first one.
- **B-4.1 internal-to-pass:** cardinality → BCS decode →
  coverage (multiple wins over malformed; malformed wins
  over coverage). Pinned by two precedence tests
  (`multiple_entries_wins_over_malformed_eager_error`,
  `malformed_wins_over_coverage_eager_error`).
- **B-4.2 internal-to-pass:** byte → range → duplicate
  within a pair; first failing pair within an entry;
  first failing entry across entries. Pinned by four
  precedence tests covering all three transitions plus
  cross-axis (`within_entry_first_invalid_pair_wins`,
  `cross_entry_first_failing_entry_wins`,
  `overlapping_failure_modes_byte_check_wins_over_range_and_duplicate`,
  `overlapping_range_and_duplicate_range_check_wins`).
- **Cross-pass `MalformedConstantData`:** B-2.1 constants
  pass typically wins over B-3.1 limits' vector-length
  sub-check on the same malformed-ULEB128 input per
  pipeline ordering at B-5 wiring.
- **Cross-pass `MalformedPrivacyMetadata`:** B-4.2
  privacy_metadata_structure pass typically wins over
  B-4.1 Rule 2 on the same malformed-BCS input per
  pipeline ordering at B-5 wiring.

**Sub-principle: complete precedence-ordering test
coverage.** When a pass has multi-axis precedence ordering
(e.g., byte-vs-range, range-vs-duplicate, within-pair-vs-
across-pairs), pin every axis with a dedicated test.
B-4.2's three precedence tests cover all three transitions
explicitly rather than partial pinning. Future passes with
multi-axis precedence should follow the same complete-
coverage pattern rather than relying on single-violation
fixtures to implicitly cover all precedence axes.

## Deliberate-Adamant-decision pattern

When a pass has no direct upstream analog, ordering and
precedence decisions are deliberate Adamant choices, not
preservation. Document the rationale inline in the pass's
doc-comment so future cross-validation gaps don't get
mischaracterized as porting bugs against a non-existent
upstream-parity claim.

This pattern is the **complement** to the
"byte-faithful preservation of upstream consensus-affecting
decisions" pattern above. The two patterns together cover
both cases:

- **Upstream analog exists** → preserve byte-faithfully
  unless explicit redirect (with redirect documented in
  "Adamant deviations").
- **No upstream analog exists** → document the decision
  deliberately so future divergence claims have a textual
  anchor.

Pattern instance:

- **B-4.2: byte → range → duplicate per-pair check
  ordering.** Cheapest-check-first rationale (byte =
  single comparison; range = comparison + length lookup;
  duplicate = `HashSet::insert` allocation + hashing).
  Alternative orderings would be defensible (e.g., range-
  first to fail-fast on out-of-range indices that can't
  be valid under any interpretation; or
  most-diagnostic-useful-first). What matters is
  documenting the chosen ordering as a fresh Adamant
  decision rather than implying upstream parity.

Future Adamant-specific passes with non-trivial ordering
or precedence decisions follow this pattern: document the
chosen shape with rationale (cost-driven, security-driven,
diagnostic-driven, or other) inline in the pass's doc-
comment. The rationale is not consensus-binding (the
acceptance set is) but the audit-trail anchor it provides
prevents mischaracterization of future divergence.

## Per-pass doc-comment as methodology-pattern co-location

PROVENANCE.md is the cross-pass audit anchor; per-pass
doc-comments are the per-pass details. When a pass
surfaces methodology patterns (eager-error precedence,
no-Sui-parity, deliberate-decision rationale, shared-
variant cross-references), the per-pass doc-comment
carries the local instance with cross-references to
PROVENANCE.md sections. Bidirectional anchoring: future
readers can navigate from per-pass detail to cross-pass
context, or from cross-pass pattern to per-pass instance.

**Seven-section doc-comment template** (established by
B-4.2):

1. **Pass scope.** What the pass does, what error variants
   it produces, what step (3 or 5) of §6.2.1.8 it runs at.
2. **No-Sui-parity-claim posture** (where applicable).
   Whether Layer B is omitted by design, with reason-shape
   ("Adamant-specific" or "structurally unreachable").
3. **Deliberate-Adamant-decision** (where applicable).
   For Adamant-specific passes with non-trivial ordering
   or precedence decisions, the chosen shape + rationale +
   alternative-orderings-defensible note.
4. **Eager-error first-failure-wins.** The pass's internal
   precedence ordering (within-pair, within-entry, across-
   entries; or sub-check ordering for multi-sub-check
   passes).
5. **Shared-variant cross-pass precedence** (where
   applicable). For shared error variants, which pass
   typically wins eager-error precedence at B-5 wiring,
   with cross-references to the pass that consumes the
   variant from the other side.
6. **Dead-code allow sunset.** When the module-level
   `#![allow(dead_code)]` is removed (typically B-5
   pipeline integration).
7. **References to PROVENANCE.md cross-pass audit anchors.**
   Explicit forward references to the relevant
   PROVENANCE.md sections (e.g., "see 'Eager-error first-
   failure-wins' section in `module_pass/PROVENANCE.md`")
   so a reader of the per-pass doc-comment can navigate
   to the cross-pass context.

Sections 2, 3, 5 are conditional (only included if the
pass has those properties); 1, 4, 6, 7 are always present.
B-4.2's doc-comment is the template; future passes should
follow the same shape.

The pattern's reverse direction is also load-bearing:
PROVENANCE.md sections name the per-pass instances by
sub-checkpoint identifier (e.g., "B-4.2 byte → range →
duplicate ordering" in the deliberate-Adamant-decision
section). Cross-references are bidirectional: per-pass
doc-comment → PROVENANCE.md section name + section title;
PROVENANCE.md section → sub-checkpoint identifier + pass
file name.

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
- **2026-05-08 (Phase 5/5b.2 B-3 closure):** Three large
  module-level passes landed across B-3.1 through B-3.3,
  closed by B-3.4's documentation batch. Cumulative file
  LOC: ~2,399 across `limits.rs` (942), `recursive_data_def.rs`
  (569), and `instantiation_loops.rs` (888); plus
  error-variant additions in `validator/error.rs` (~240
  LOC across the three sub-checkpoints). Test additions:
  23 (limits) + 17 (recursive_data_def) + 18
  (instantiation_loops) = **58 new tests** (sub-arc
  delta), all passing in the workspace gauntlet. Workspace
  test count progression for the B-3 sub-arc:
  **933 → 991 (+58)**. One new public closed enum
  (`HandleKind`: `DatatypeHandle | FunctionHandle`)
  re-exported via `lib.rs`. Twelve new
  `AdamantValidationError` variants (10 from B-3.1, 1
  from B-3.2, 1 from B-3.3). `petgraph` promoted to
  `adamant-vm`'s production `[dependencies]` at B-3.2 —
  first non-Sui-vendor-derived production dep on
  `adamant-vm`; audit template established. Three pass-
  level `#![allow(dead_code)]` sunsets added by B-3.1 →
  B-3.3 (totalling seven across the validator/module_pass
  subtree); all pending B-5 pipeline integration. New
  PROVENANCE.md sections added: "Structural-impossibility
  checks pattern" (formalising three named sub-patterns:
  explicit-macro defensive, implicit-filter exclusionary,
  spec-pipeline-impossibility-pending-port — with four
  pattern instances now: B-2.4 deprecated-arms, B-3.1
  `<SELF>`, B-3.2 duplicate-handle + reference-field,
  B-3.3 native-function filter); "External production dep
  audit template" (seven-criterion template registered at
  B-3.2 petgraph promotion); "Byte-faithful preservation
  of upstream consensus-affecting decisions" (methodology
  principle covering cardinality, ordering, weighting,
  default values, error precedence). No upstream divergence
  on accept/reject decisions at fork time — every Layer B
  cross-validation test passes byte-identical to the
  vendored snapshot for every fixture exercised, including
  the byte-faithful component-summary parity test pinning
  upstream's diagnostic format empirically.
- **2026-05-08 (Phase 5/5b.2 B-4 closure):** Two
  Adamant-specific privacy-metadata passes landed across
  B-4.1 + B-4.2, closed by B-4.3's documentation batch.
  Cumulative file LOC: ~905 across `rule_02_privacy.rs`
  (416, in `validator/`, not in this `module_pass/`
  subtree) + `module_pass/privacy_metadata_structure.rs`
  (489); plus error-variant additions in
  `validator/error.rs` (~159 LOC across the two sub-
  checkpoints). Test additions: 14 (Rule 2) + 14
  (privacy_metadata_structure) = **28 new tests** (sub-arc
  delta), all passing in the workspace gauntlet. Workspace
  test count progression for the B-4 sub-arc:
  **991 → 1019 (+28)**. Seven new typed-error variants
  (4 from B-4.1, 3 from B-4.2). One shared variant
  (`MalformedPrivacyMetadata`) introduced at B-4.1 and
  consumed by B-4.2. No new public enums. No new
  dependencies. Two pass-level
  `#![allow(dead_code)]` sunsets added (totalling **nine
  pending B-5**). Walk-backs from this morning's spec
  verification honored verbatim in code: Q3 (Rule 2
  Public-only visibility coverage per §6.2.1.3 line 387 +
  §6.2.1.6 Rule 2) and Q4 (option (b) cardinality —
  zero entries allowed iff no Public functions).
  Three Q3 behavioral lock fixtures pin Public-only
  coverage under realistic conditions
  (Friend-only-no-entry; Friend+Public-Friend-not-in-table;
  Public+Private-Private-not-in-table). New PROVENANCE.md
  sections added: "No-Sui-parity-claim posture" (formalising
  three pattern instances: B-3.1 `<SELF>` structurally
  unreachable, B-4.1 Rule 2 Adamant-specific, B-4.2
  privacy_metadata_structure Adamant-specific);
  "Eager-error first-failure-wins as Phase 5/5b.2-wide
  methodology principle" (two precedence axes: internal-
  to-pass and cross-pass; six pattern instances; sub-
  principle for complete precedence-ordering test
  coverage); "Deliberate-Adamant-decision pattern" (one
  pattern instance: B-4.2 byte → range → duplicate
  cheapest-check-first ordering); "Per-pass doc-comment
  as methodology-pattern co-location" (seven-section
  template established by B-4.2 with bidirectional cross-
  references to PROVENANCE.md). Rule 1 / Rule 2
  structural-pass-asymmetry rationale registered under
  "Adamant deviations" — metadata-payload-shape-driven,
  not arbitrary. No upstream divergence on accept/reject
  decisions for inherited-subset modules at fork time;
  the two B-4 passes are Adamant-specific and carry no
  Sui parity claim by design.
- **2026-05-08 (Phase 5/5b.2 B-5: pipeline integration):**
  Eight module-level passes wired into
  `validator::verify_module` at step 3 + three Adamant
  rules at step 5 per §6.2.1.8 five-step ordering. Step-3
  invocation order: constants at position 1 (precedence-
  driven; before limits per `MalformedConstantData`
  shared-variant precedence); positions 2–8 alphabetical
  (`ability_field_requirements`, `friends`,
  `instantiation_loops`, `instruction_consistency`,
  `limits`, `privacy_metadata_structure`,
  `recursive_data_def`). Step-5 batch: Rule 1, Rule 2
  (B-4.1), Rule 4 in numerical order. Threading
  `&AdamantStructuralLimits` to `limits::verify` per
  B-3.1 carry-forward. Nine module-level
  `#![allow(dead_code)]` sunsets removed in same commit
  as wiring (eight `module_pass` files +
  `rule_02_privacy.rs`). Sui-verifier-bridge transitional
  retained behind `if !module.contains_adamant_extensions()`
  guard for inherited-subset modules; tears out at
  5/5b.5. 16 new tests at `validator/mod.rs::tests`: 6
  cross-pass eager-error precedence parity tests + 10
  full-pipeline integration tests. All 1019 previously
  existing tests pass unchanged. Workspace test count:
  1019 → 1035 (+16). Two transient fixes: pub(super)
  visibility on the eight wired pass modules; privacy
  entry added to `rich_valid_module()` test fixture
  (wiring-time fixture-update methodology pattern,
  registered above). Integration-test depth limitation
  registered: limits-alone-fires precedence pin under
  genesis defaults requires fixture exceeding 1 MiB
  vector length; deferred to test-only
  `AdamantVerifierConfig::with_structural_limits`
  builder rather than added speculatively. §6.2.1.8
  cross-pass eager-error precedence registered as
  spec-amendment carry-forward alongside §6.2.1.7
  structural-limits values.
- **2026-05-08 (Phase 5/5b.2 B-6 closure: Phase 5/5b.2
  closes):** Documentation-only sub-checkpoint. No
  source-code changes; tests unchanged at 1035. This
  PROVENANCE.md update batches the B-5 wiring
  documentation, the wiring conventions sub-section, the
  wiring-time fixture-update methodology pattern, the
  integration-test depth limitation, and the §6.2.1.8
  spec-amendment carry-forward into the existing
  document. CLAUDE.md state-bump for Phase 5/5b.2 closure
  lands in the same commit per the deferred-to-phase-
  closure pattern (commits 180d67f precedent for Phase
  5/5b.1a + 5/5b.1b closure).

  **Sub-arc delta (B-6 alone):** 0 source-code changes;
  documentation-only; tests unchanged at 1035; ~500–750
  LOC of net edits to PROVENANCE.md + CLAUDE.md.

  **Cumulative phase delta (Phase 5/5b.2, B-1 through
  B-6):** 14 commits on origin. Workspace test count
  progression: 821 → 1035 (+214). Nine module-level
  passes ported Adamant-native (`constants`, `friends`,
  `ability_field_requirements`, `instruction_consistency`
  from B-2; `limits`, `recursive_data_def`,
  `instantiation_loops` from B-3;
  `privacy_metadata_structure` from B-4) plus one rule
  (`rule_02_privacy` from B-4 — Rule 1 and Rule 4 were
  already wired pre-B-5, so B-5 added only Rule 2 to
  the step-5 batch). 20 new typed-error variants on
  `AdamantValidationError`. Three new public closed
  enums: `MalformedConstantReason` (B-2.1),
  `FieldOwnerKind` (B-2.3), `HandleKind` (B-3.1). One
  new production dependency: `petgraph 0.8.x` (B-3.2;
  first non-Sui-vendor-derived production dep on
  `adamant-vm`; seven-criterion external-production-dep
  audit template established). Seven named methodology
  patterns formalized in this PROVENANCE.md:
  structural-impossibility checks (3 sub-patterns + 4
  instances); external production dep audit template
  (7-criterion); byte-faithful preservation principle
  (5-axis scope); no-Sui-parity-claim posture (2
  reason-shapes + 3 instances); eager-error first-
  failure-wins as Phase 5/5b.2-wide methodology
  principle (2 axes + sub-principle for complete
  precedence-ordering test coverage + 6 instances);
  deliberate-Adamant-decision pattern (1 instance);
  per-pass doc-comment as methodology-pattern co-
  location (7-section template). Two §6.2.1 spec-
  amendment carry-forwards registered: §6.2.1.7
  structural-limits values (B-1) and §6.2.1.8 cross-
  pass eager-error precedence (B-5). Phase 5/5b.2
  closes; Phase 5/5b sub-arcs remaining: 5/5b.3
  (BoundsChecker, DuplicationChecker, SignatureChecker
  — three large module-level passes deferred from
  Phase 5/5b.2's plan), 5/5b.4 (per-function passes
  infrastructure + Rule 3), 5/5b.5 (type-safety/
  reference-safety per-function passes + Rules 6, 7 +
  final pipeline integration with Sui-verifier bridge
  fully removed + `tests/no_sui_in_production_deps.rs`
  build-system independence check).
- **2026-05-09 (Phase 5/5b.3 C-1 closure: BoundsChecker
  feature-complete):** Five sub-checkpoints (C-1.1 → C-1.4b)
  port upstream `BoundsChecker` per
  `vendor/move-binary-format/src/check_bounds.rs` to
  `module_pass/bounds_checker.rs`. **Sub-arc adapted from
  planned 4 sub-checkpoints to 5** at the C-1.4 plan-gate
  per the empirical-complexity-drives-sub-checkpoint-shape
  pattern (C-1.4 split into C-1.4a + C-1.4b at sub-step
  boundary because the full estimate of ~1,300-1,800 LOC
  exceeded the cognitive-review threshold). Cumulative
  Phase 5/5b.3 C-1 LOC: **~4,547 LOC** across the 5
  sub-checkpoints. Test additions: **162 new tests** (C-1.1:
  29; C-1.2: 44; C-1.3: 36; C-1.4a: 20; C-1.4b: 33). Six
  new typed-error variants on `AdamantValidationError`:
  `NoModuleHandles`, `IndexOutOfBounds`,
  `NumberOfTypeArgumentsMismatch` (C-1.1);
  `TooManyLocals` (C-1.4a); `CodeIndexOutOfBounds`,
  `InvalidEnumSwitch` (C-1.4b). Methodology pattern
  instances added across C-1: per-handle-extraction
  refactor pattern's 1st instance (C-1.2's
  `check_module_handle`) and 2nd instance (C-1.3's
  `check_field_def`) — pattern reaches 2 instances; rule-of-
  three trigger formalized; intra-sub-checkpoint
  structural-impossibility sub-pattern's 1st-3rd instances
  (C-1.3's `check_variant_instantiation_handles`
  `debug_assert!`; C-1.4a's two `debug_assert!` for
  function-handle and parameters re-checks) — sub-pattern
  reaches 3 instances; **NEW Adamant-extension treatment
  in module-level passes pattern's 1st instance (C-1.4b
  `check_adamant_bytecode` partial-inspection dispatch);
  NEW deferred-to-§7 methodology footnote's 1st instance
  (C-1.4b GenerateProof/VerifyProof CircuitId pass-
  through);** structural-impossibility-checks pattern's
  5th overall instance (C-1.4b deprecated-arms
  `unreachable!` cross-referencing B-2.4's parallel
  pattern). Five plan-gate resolution shapes registered
  across C-1 sub-arc: plan-was-correct (C-1.2's negatives-
  count flag); plan-was-ambiguous (C-1.3's preservation-
  pin-count flag — empirically 6); plan-was-conservative
  (C-1.4a's 20-tests at lower bound); plan-overshot-on-
  helper-signature (C-1.4b's `check_signature_type_parameters`
  6→3 params at implementation-time); plan-incremental-
  disposition-resolved-empirically registered later at C-3.
  C-1 closes: bounds checker is feature-complete at 17 of
  17 upstream `verify_impl` sub-checks.

- **2026-05-09 (Phase 5/5b.3 C-2 closure: DuplicationChecker
  feature-complete):** Single sub-checkpoint ports upstream
  `DuplicationChecker` per
  `vendor/move-bytecode-verifier/src/check_duplication.rs`
  to `module_pass/duplication_checker.rs`. ~1,665 LOC; 38
  new tests. Six new typed-error variants:
  `DuplicateElement` (workhorse for 14+ sub-checks),
  `ZeroSizedStruct`, `ZeroSizedEnum`, `InvalidModuleHandle`,
  `DuplicateAcquiresAnnotation`, `UnimplementedHandle`.
  **NEW public closed enum `DefKind` (`Struct | Enum |
  Function`)** introduced as 3rd instance of the deliberate-
  Adamant-decision pattern after B-4.2's byte→range→duplicate
  ordering and C-1.3's `check_field_def` extraction (rule-
  of-three threshold met). Adamant-extension treatment
  pattern reaches 2nd instance (DuplicationChecker has no
  per-instruction operand concern; extensions are early-arm-
  Ok by virtue of the pass not iterating function bodies).
  `first_duplicate_element` private helper kept private per
  Q1 disposition's first-instance-private discipline.
  Plan-vs-actual variant count off-by-one registered as
  calibration data (plan +5; actual +6). Plan-was-conservative
  resolution at lower bound on test count (plan 40-45,
  actual 38). Implementation-core-vs-total-LOC refinement
  consistently validated (~440 LOC implementation core well
  below 800 threshold).

- **2026-05-09 (Phase 5/5b.3 C-3 closure: SignatureChecker
  feature-complete):** Single sub-checkpoint ports upstream
  `SignatureChecker` per
  `vendor/move-bytecode-verifier/src/signature.rs` to
  `module_pass/signature_checker.rs`. ~1,466 LOC; 19 new
  tests (after the variant-vs-test mapping audit added 2
  coverage-closure tests). Five new typed-error variants:
  `InvalidSignatureToken` with new closed enum
  `InvalidSignatureReason` (`RefInsideContainer |
  RefAsFieldType`); `TypeArgumentsArityMismatch`;
  `ConstraintNotSatisfied`; `InvalidPhantomTypeParamPosition`;
  `VecOpExpectedSingleTypeArgument`. **`AdamantAbilityCache`
  consumer's 2nd instance** after B-2.3's
  `ability_field_requirements`; per-pass instantiation per
  C-1 plan-gate Q2 disposition. **NEW spec-layer-pinning
  impossibility sub-pattern** of structural-impossibility-
  checks (5th sub-pattern overall): `check_type_instantiation`'s
  VERSION_6 gate handled as `unreachable!` because Adamant's
  binary-format version is genesis-pinned at `VERSION_MAX
  = 7`; the `else` branch is structurally unreachable. Three-
  anchor `unreachable!` message references VERSION_MAX = 7,
  deserializer parse-time enforcement, and §6.2.1.2 spec.
  Adamant-extension treatment pattern's 3rd instance with
  NEW sub-shape (pass iterates bodies, no extensions need
  handling at this layer); rule-of-three threshold met
  with three sub-shapes empirically observed. **NEW
  methodology principle: Variant-vs-test mapping audit at
  implementation-gate** registered after the audit caught
  2 unmapped typed variants (`ConstraintNotSatisfied`,
  `InvalidPhantomTypeParamPosition`) without explicit
  negative tests; coverage closed before commit. Discipline
  registered for canonical implementation-gate use.

- **2026-05-09 (Phase 5/5b.3 C-4 closure: pipeline integration
  of bounds/duplication/signature checkers):** Single sub-
  checkpoint wires the three new passes into
  `validator::verify_module`'s step-3 batch. ~249 LOC; 5 new
  tests. Step-3 batch expands from 8 → **11 passes total**.
  Eleven-pass invocation order with **two precedence-driven
  exceptions** to alphabetical-of-remainder: bounds_checker
  at position 1 (precedence-driven; IndexOutOfBounds
  reaches first on overlapping inputs against limits'
  count overflow); signature_checker at position 10 before
  recursive_data_def at position 11 (precedence-driven;
  caught at implementation-gate that pure-alphabetical
  placement would have broken recursive_data_def's
  `unreachable!` structural argument for refs-in-field-
  types). Cross-pass eager-error precedence list grows
  **2 → 3 instances** at C-4 closure (Q2 Claim 3:
  duplication_checker `DuplicateElement(Signature)` wins
  over signature_checker `InvalidSignatureToken` on
  overlapping malformed-and-duplicate-signature input).
  **NEW different-variant precedence claim shape** distinct
  from existing 2 shared-variant claims (MalformedConstantData,
  MalformedPrivacyMetadata). **NEW cross-pass-pipeline-
  dependency sub-pattern** of structural-impossibility-checks
  (6th sub-pattern overall): structural guarantee comes from
  a separate pass earlier in the pipeline; consuming pass's
  `unreachable!`/`assert!` depends on prior pass having
  fired. Canonical instance: recursive_data_def's
  `unreachable!` for refs-in-field-types depends on
  signature_checker's RefAsFieldType rejection having fired
  earlier in the pipeline. **Spec-pipeline-impossibility-
  pending-port sub-pattern's 2 instances retired-via-
  fulfillment** at C-4 (B-3.2's recursive_data_def qualifiers
  about DuplicationChecker + SignatureChecker — both passes
  now landed; qualifiers replaced with explicit upstream-
  of-this-pass references). Sub-pattern remains documented
  for future pending-port deferrals; not deleted. Q4 Claim
  1 (BoundsChecker IndexOutOfBounds vs limits' overflow)
  deferred per integration-test depth limitation; cross-
  pass precedence list count stays at 3, not 4, at C-4
  closure. Q3 wiring-time fixture-update audit clean (no
  fixture changes; 446 existing validator tests passed
  unchanged after wiring).

- **2026-05-09 (Phase 5/5b.3 C-5 closure: Phase 5/5b.3
  closes):** Documentation-only sub-checkpoint. No source-
  code changes; tests unchanged at 1259. PROVENANCE.md
  updates batch C-1 → C-4 closure entries (above) plus six
  methodology accumulation streams (next sections).
  CLAUDE.md state-bump for Phase 5/5b.3 closure lands in
  the same commit per the deferred-to-phase-closure pattern
  (B-6 precedent for Phase 5/5b.2 closure).

  **Sub-arc delta (C-5 alone):** 0 source-code changes;
  documentation-only; tests unchanged at 1259; ~600-900
  LOC of net edits to PROVENANCE.md + CLAUDE.md.

  **Cumulative phase delta (Phase 5/5b.3, C-1 through
  C-5):** 5 sub-arcs (C-1, C-2, C-3, C-4, C-5); C-1 split
  into 5 sub-checkpoints; **9 commits on origin** (C-1.1
  at `f9050dd`; C-1.2 at `a8e975a`; C-1.3 at `3fe1582`;
  C-1.4a at `25dfabe`; C-1.4b at `d2a0308`; C-2 at
  `60d0a53`; C-3 at `34e80de`; C-4 at `fa79976`; C-5
  closure commit lands with this state-bump). Workspace
  test count progression: **1035 → 1259 (+224)**.
  AdamantValidationError progression: **33 → 50 (+17)**
  (corrected from prior commit-message claim of 20 → 37
  per the B-6 baseline-error corrigendum below). Three
  large module-level passes ported Adamant-native
  (`bounds_checker` from C-1; `duplication_checker` from
  C-2; `signature_checker` from C-3) plus pipeline
  integration at C-4 (8 → 11 passes wired in
  `verify_module` step-3 batch). 17 new typed-error
  variants on `AdamantValidationError`. **2 new public
  closed enums:** `DefKind` (C-2), `InvalidSignatureReason`
  (C-3) — bringing the Phase 5/5b cumulative public closed-
  enum count to **5 total** (`MalformedConstantReason`,
  `FieldOwnerKind`, `HandleKind` from Phase 5/5b.2; plus
  the two from 5/5b.3). 5 helpers extracted across Phase
  5/5b.3: `check_index` (C-1.1); `check_module_handle`
  (C-1.2); `check_field_def` (C-1.3);
  `check_signature_type_parameters` + `check_code_index`
  (C-1.4b). Six methodology accumulation streams formalized
  (sections below): **(1) cross-pass-pipeline-dependency
  sub-pattern (NEW; C-4); (2) spec-layer-pinning
  impossibility sub-pattern (NEW; C-3); (3) Adamant-
  extension treatment in module-level passes (NEW pattern;
  rule-of-three threshold met across C-1.4b/C-2/C-3); (4)
  different-variant precedence claim shape (NEW; C-4); (5)
  variant-vs-test mapping audit principle (NEW; C-3); (6)
  deferred-to-§7 methodology footnote (NEW; C-1.4b).** Plus
  C-5's own methodology data point: **commit-message
  running-total drift discipline.** Phase 5/5b.3 closes;
  Phase 5/5b sub-arcs remaining: **5/5b.4** (per-function
  passes infrastructure + Rule 3); **5/5b.5** (type-safety
  + reference-safety per-function passes + Rules 6, 7 +
  final pipeline integration with Sui-verifier bridge fully
  removed + `tests/no_sui_in_production_deps.rs` build-system
  independence check).

## Phase 5/5b.3 closure — methodology accumulation streams

The six new methodology streams formalized at C-5 closure
(plus the C-5 commit-message-drift discipline as a seventh
data point). Each below extends the canonical methodology
catalog above for future per-function-passes inheritance
(5/5b.4, 5/5b.5).

### (1) Cross-pass-pipeline-dependency sub-pattern (NEW; structural-impossibility-checks 6th sub-pattern)

Canonical instance: C-4's `recursive_data_def`'s
`unreachable!` for refs-in-field-types depends on
`signature_checker`'s `RefAsFieldType` rejection having
fired earlier in the pipeline. Distinct from existing 5
sub-patterns of structural-impossibility-checks:

1. Explicit-macro defensive (cross-pass) — guarantee from
   prior verifier pass (B-2.4, B-3.1, ability_cache.rs)
2. Implicit-filter exclusionary (cross-pass) — guarantee
   from skipped category (B-3.3 native-function filter)
3. Spec-pipeline-impossibility-pending-port (cross-pass) —
   guarantee from a not-yet-ported upstream pass (B-3.2;
   **retired-via-fulfillment at C-4**)
4. Explicit-macro defensive (intra-sub-checkpoint) —
   guarantee from earlier sub-check within same pass
   (C-1.3, C-1.4a)
5. Spec-layer-pinning impossibility (cross-pass) —
   guarantee from binary-format spec layer (C-3
   VERSION_6 gate)
6. **Cross-pass-pipeline-dependency (cross-pass; NEW at
   C-4)** — guarantee from a separate pass earlier in the
   pipeline.

Distinguishing feature: requires deliberate pipeline
ordering (not just verbose `unreachable!` messages). C-4
caught at implementation-gate that pure-alphabetical
signature_checker placement would have broken
recursive_data_def's structural argument; precedence-driven
placement preserves it. Future per-function passes (5/5b.4,
5/5b.5) may have similar cross-pass dependencies requiring
careful pipeline-ordering decisions.

**Worth flagging to future per-function-passes plan-gates:**
when adding structural-impossibility patterns, surface any
cross-pass-pipeline-dependency at the consuming-pass
docstring with explicit reference to the providing pass.

### (2) Spec-layer-pinning impossibility sub-pattern (NEW; structural-impossibility-checks 5th sub-pattern)

Canonical instance: C-3's
`check_type_instantiation`'s VERSION_6 gate. Adamant's
binary-format version is genesis-pinned at `VERSION_MAX = 7`
per `adamant-bytecode-format::format_common`; the `else`
branch (`version < VERSION_6`) is structurally unreachable.
The `unreachable!` carries a three-anchor message:

1. `VERSION_MAX = 7` in `adamant-bytecode-format`
2. Deserializer parse-time version enforcement (rejects
   versions below `VERSION_MAX`)
3. Whitepaper §6.2.1.2 binary-format version pinning

General framing: future passes encountering other genesis-
pinned spec properties (e.g., 200-validator cap, fixed
issuance schedule, fixed gas-cost table) inherit this sub-
pattern. Distinguishing feature from cross-pass sub-pattern:
the structural guarantee is at the binary-format spec
layer, not in another verifier pass; deserializer-side
enforcement closes the consensus loop.

### (3) Adamant-extension treatment in module-level passes (NEW pattern; rule-of-three threshold met)

Three sub-shapes empirically observed at C-1.4b/C-2/C-3:

- **Sub-shape 1:** Pass doesn't iterate function bodies →
  no extension dispatch arm needed (C-2 DuplicationChecker).
- **Sub-shape 2:** Pass iterates function bodies, some
  extensions need per-extension handling → partial
  inspection (C-1.4b BoundsChecker per Q3 §6.2.1.4 verbatim
  survey: 2 of 17 extensions need bounds-check arms;
  remaining 15 fall into deferred-to-§7, variant-tag-
  deserializer-enforced, or zero-operand pass-through
  categories).
- **Sub-shape 3:** Pass iterates function bodies, no
  extensions need handling at this layer → all pass
  through (C-3 SignatureChecker; per §6.2.1.4 the 17
  extensions either don't carry generic type-arguments at
  bytecode operand level or are zero-operand).

Future per-function passes (5/5b.4, 5/5b.5) inherit the
three-sub-shape framework and surface their disposition at
plan-gate. The §6.2.1.4 verbatim re-paste (per the C-1.4
plan-gate Q3) is the empirical anchor for classification.

### (4) Different-variant precedence claim shape (NEW; cross-pass eager-error precedence)

Existing 2 cross-pass precedence claims (B-5 era) are
**shared-variant precedence**: same variant from two
passes; ordering determines which fires.

- `MalformedConstantData`: `constants` (B-2.1) > `limits`
  (B-3.1)
- `MalformedPrivacyMetadata`: `privacy_metadata_structure`
  (B-4.2) > `rule_02_privacy` (B-4.1; via step-3-before-
  step-5 ordering)

NEW shape registered at C-4 (Q2 Claim 3 empirical
resolution): **different-variant precedence on overlapping
input** — different variants trigger on the same input;
ordering determines which fires first.

- `DuplicateElement(Signature)` vs `InvalidSignatureToken`:
  `duplication_checker` (C-2; position 4) > `signature_checker`
  (C-3; position 10) on a fixture with two identical
  `Vec<&u64>` signatures (both passes can fire; ordering
  determines which is reported).

Two-shape framework empirically grounded. Future plan-
gates check for **both** shapes when registering precedence
claims, not just shared-variant.

### (5) Variant-vs-test mapping audit at implementation-gate (NEW canonical methodology principle)

Every typed-error variant landing in a sub-checkpoint must
have at least one explicit negative test asserting on the
variant shape. Implementation-gate audit step:

1. Enumerate typed variants added at the sub-checkpoint
2. Map each to its negative test(s)
3. Flag any unmapped variant for coverage closure before
   commit

**First instance: C-3 implementation-gate caught 2
unmapped variants** (`ConstraintNotSatisfied`,
`InvalidPhantomTypeParamPosition`); coverage closed before
commit with 2 new tests. Audit cost: small but load-
bearing — without it, variants land unproven.

**Retroactive C-5 audit across all 50 variants:** see
section "Retroactive variant-vs-test mapping audit" below.

**Output shape (canonical; future audits inherit):** per-
variant enumeration with variant name + negative test
name(s) + sub-checkpoint where added + any flagged gaps
with explicit follow-up disposition.

### (6) Deferred-to-§7 methodology footnote (NEW)

Canonical instance: C-1.4b's `GenerateProof(CircuitId)` /
`VerifyProof(CircuitId)` operands at the bounds-checker
wide-match. Per §6.2.1.4 line 429's "CircuitId resolution"
paragraph, the circuit-reference pool's location is
deferred to §7 (privacy layer); the pool does not exist in
`AdamantCompiledModule` at the bytecode layer.

Distinct from spec-pipeline-impossibility-pending-port
sub-pattern (which is for upstream Sui passes not yet
ported in Adamant). This is **"operand pool not yet defined
by the spec at the layer the pass operates on."** Documented
inline + cross-referenced to CLAUDE.md open property #2.

Pass-through disposition at C-1.4b: bounds-check
infrastructure becomes a §7 / Phase 5/6 concern when §7
lands. The carve-out is bounded in time; not a stable
sub-pattern with multiple instances. Footnote, not pattern.

### (7) Commit-message running-total drift discipline (NEW; C-5)

Per-commit deltas can be empirically correct while running
totals drift if the inherited baseline is wrong. **Future
phase closures grep-confirm running totals against actual
code, not inherit running totals from prior CLAUDE.md
state-bumps.**

Origin instance: B-6's CLAUDE.md state-bump for Phase
5/5b.2 closure claimed `AdamantValidationError carries 20
typed variants` — empirically 33 at the same commit
(`4b03f14`). Both interpretations of "20" (total vs new
added during phase) were wrong; the actual values were 33
total + 26 new added during Phase 5/5b.2.

Drift propagated through 5 subsequent commit messages
across Phase 5/5b.3 (C-1.1 → C-3) via correct-delta-on-
wrong-baseline:

| Commit | Inherited baseline | Per-commit delta | Claimed total | Actual total |
|---|---|---|---|---|
| C-1.1 | 20 (wrong) | +3 ✓ | 23 (wrong) | 36 |
| C-1.4a | 23 (wrong) | +1 ✓ | 24 (wrong) | 37 |
| C-1.4b | 24 (wrong) | +2 ✓ | 26 (wrong) | 39 |
| C-2 | 26 (wrong) | +6 ✓ | 32 (wrong) | 45 |
| C-3 | 32 (wrong) | +5 ✓ | 37 (wrong) | 50 |

Per-sub-checkpoint deltas were empirically correct
throughout. Only the inherited baseline was wrong. C-5
implementation-gate catch surfaced the discrepancy via
empirical grep before writing the C-5 state-bump.

**Discipline going forward:** at every phase closure,
empirically count the actual variant count (and any other
running totals like LOC, test counts) via grep-on-code
rather than inheriting prior state-bump claims.

## Retroactive variant-vs-test mapping audit (50 variants; C-5 closure)

Per the canonical methodology principle (section above),
audit every typed variant of `AdamantValidationError` for
explicit negative-test coverage. Output shape: variant
name + negative test name(s) + sub-checkpoint where added
+ flagged gaps.

**Audit method:** `grep -rE "Err\(AdamantValidationError::VARIANT\b"
crates/adamant-vm/src` per variant; counts include
positive and negative occurrences in test code.

**Audit results: 49 of 50 variants have explicit negative
test coverage. 1 gap: `SuiVerifier`.**

| Variant | Sub-checkpoint | Test occurrences | Status |
|---|---|---|---|
| `AdamantDeserializer` | Phase 5/5a | 3 | ✓ covered |
| `NonCanonicalBytecode` | Phase 5/5a | 1 | ✓ covered |
| `SuiVerifier` | Wave 3a transitional | **0** | **❌ GAP** (see follow-up below) |
| `MissingMutabilityMetadata` | Wave 3a (Rule 1) | 4 | ✓ covered |
| `MultipleMutabilityMetadata` | Wave 3a (Rule 1) | 2 | ✓ covered |
| `MalformedMutabilityMetadata` | Wave 3a (Rule 1) | 1 | ✓ covered |
| `NativeFunctionForbidden` | Wave 3a (Rule 4) | 3 | ✓ covered |
| `InvalidConstantType` | B-2.1 | 6 | ✓ covered |
| `MalformedConstantData` | B-2.1 | 6 | ✓ covered |
| `SelfFriendDeclaration` | B-2.2 | 4 | ✓ covered |
| `CrossAccountFriendDeclaration` | B-2.2 | 3 | ✓ covered |
| `FieldMissingTypeAbility` | B-2.3 | 9 | ✓ covered |
| `GenericMemberOpcodeMismatch` | B-2.4 | 3 | ✓ covered |
| `VecPackUnpackArgOutOfRange` | B-2.4 | 3 | ✓ covered |
| `TooManyVectorElements` | B-3.1 | 2 | ✓ covered |
| `TooManyTypeParameters` | B-3.1 | 4 | ✓ covered |
| `TooManyParameters` | B-3.1 | 2 | ✓ covered |
| `TooManyTypeNodes` | B-3.1 | 2 | ✓ covered |
| `IdentifierTooLong` | B-3.1 | 2 | ✓ covered |
| `InvalidIdentifier` | B-3.1 | 1 | ✓ covered (structural-impossibility pin) |
| `MaxFunctionDefinitionsReached` | B-3.1 | 2 | ✓ covered |
| `MaxDataDefinitionsReached` | B-3.1 | 2 | ✓ covered |
| `MaxFieldDefinitionsReached` | B-3.1 | 4 | ✓ covered |
| `MaxVariantsInEnumReached` | B-3.1 | 3 | ✓ covered |
| `RecursiveDataDefinition` | B-3.2 | 8 | ✓ covered |
| `LoopInInstantiationGraph` | B-3.3 | 7 | ✓ covered |
| `MissingPrivacyMetadata` | B-4.1 | 2 | ✓ covered |
| `MultiplePrivacyMetadata` | B-4.1 | 4 | ✓ covered |
| `MalformedPrivacyMetadata` | B-4.1/B-4.2 | 6 | ✓ covered |
| `MissingPrivacyAnnotation` | B-4.1 | 4 | ✓ covered |
| `InvalidPrivacyAnnotationByte` | B-4.2 | 6 | ✓ covered |
| `PrivacyEntryOutOfRange` | B-4.2 | 3 | ✓ covered |
| `DuplicatePrivacyEntry` | B-4.2 | 2 | ✓ covered |
| `NoModuleHandles` | C-1.1 | 2 | ✓ covered |
| `IndexOutOfBounds` | C-1.1 | 71 | ✓ covered (workhorse; many sites) |
| `NumberOfTypeArgumentsMismatch` | C-1.1 | 4 | ✓ covered |
| `TooManyLocals` | C-1.4a | 3 | ✓ covered |
| `CodeIndexOutOfBounds` | C-1.4b | 22 | ✓ covered (workhorse; per-bytecode) |
| `InvalidEnumSwitch` | C-1.4b | 2 | ✓ covered |
| `DuplicateElement` | C-2 | 26 | ✓ covered (workhorse; 14+ sub-checks) |
| `ZeroSizedStruct` | C-2 | 2 | ✓ covered |
| `ZeroSizedEnum` | C-2 | 3 | ✓ covered |
| `InvalidModuleHandle` | C-2 | 5 | ✓ covered |
| `DuplicateAcquiresAnnotation` | C-2 | 2 | ✓ covered |
| `UnimplementedHandle` | C-2 | 4 | ✓ covered |
| `InvalidSignatureToken` | C-3 | 8 | ✓ covered |
| `TypeArgumentsArityMismatch` | C-3 | 2 | ✓ covered |
| `ConstraintNotSatisfied` | C-3 | 2 | ✓ covered (added at C-3 audit catch) |
| `InvalidPhantomTypeParamPosition` | C-3 | 2 | ✓ covered (added at C-3 audit catch) |
| `VecOpExpectedSingleTypeArgument` | C-3 | 2 | ✓ covered |

### Audit gap: `SuiVerifier` (Wave 3a transitional bridge variant)

`SuiVerifier(VMError)` wraps Sui's verifier rejections via
the transitional bridge in `validator/mod.rs::verify_module`
(post-step-3 inherited-subset check). The variant has **0
explicit negative tests** — fixtures that reach the bridge
either pass through cleanly (via the existing integration
tests) or get rejected at earlier stages (Adamant-native
deserializer; Adamant-native step-3 passes).

**Disposition: gap deferred to natural resolution at Phase
5/5b.5 Sui-verifier-bridge tear-out** per the architectural
commitment in §6.2.1.8. When the bridge is removed, the
`SuiVerifier` variant is no longer reachable from any
consensus-critical path and can be removed from
`AdamantValidationError` entirely. The transitional gap
during Phase 5/5b.4 is acceptable because:

1. The bridge runs as defense-in-depth alongside the now-
   complete Adamant-native step-3 batch (C-4 wired all 11
   passes). Any rejection that fires at the bridge would
   also have fired at the Adamant-native passes for any
   inherited-subset module (semantic parity asserted by
   Layer B cross-validation tests in each pass).
2. Constructing a fixture that ONLY triggers `SuiVerifier`
   (not any Adamant-native pass) requires a violation that
   Sui's verifier catches but Adamant doesn't — currently
   the per-function-pass concerns (control-flow, type-
   safety, locals-safety, reference-safety, acquires-list)
   land at Phase 5/5b.4 + 5/5b.5. A `SuiVerifier`-only
   fixture would need to trigger one of those, which is
   the per-function-pass work itself.
3. At 5/5b.5 tear-out, `SuiVerifier` is removed entirely;
   no follow-up coverage-closure commit needed.

If Phase 5/5b.4 work surfaces a need for explicit
`SuiVerifier` coverage (e.g., for transition-period
behaviour assertions), a small follow-up commit can add
the test before 5/5b.5 lands. **Registered as a tracked
follow-up; not blocking C-5 closure.**

## Corrigendum: B-6 baseline error in CLAUDE.md state-bump

**Source:** Phase 5/5b.2 B-6 closure commit (`4b03f14`,
2026-05-07).

**The error:** B-6's CLAUDE.md state-bump claimed
`AdamantValidationError carries 20 typed variants at Phase
5/5b.2 closure` (Code paragraph) and `20 new typed-error
variants on AdamantValidationError` (Phase paragraph).

**Empirical reality:**

- **Pre-Phase-5/5b.2 (commit `f22e54c` = B-1 foundation
  fork; pre-variant-additions):** 7 variants
- **Phase 5/5b.2 wiring closure (commit `1cc6999` = B-5):**
  33 variants
- **Phase 5/5b.2 closure (commit `4b03f14` = B-6;
  documentation-only):** 33 variants unchanged
- **Phase 5/5b.2 added: 26 new variants** (33 − 7); not 20

Both interpretations of "20" in the B-6 state-bump were
wrong (total: 33; new added: 26). Honest typo / arithmetic
error; "20" was used for both metrics without empirical
verification.

**Drift propagation:** the wrong "20" baseline was
inherited by 5 subsequent C-N commit messages across Phase
5/5b.3, with correct per-sub-checkpoint deltas applied to
the wrong baseline. See the table in section "(7) Commit-
message running-total drift discipline" above for the per-
commit progression.

**Correction at C-5:** CLAUDE.md state-bump for Phase
5/5b.3 closure uses empirically-verified counts:
- Pre-Phase-5/5b.3 baseline: **33** (= Phase 5/5b.2
  closure actual; corrects the prior "20" claim)
- Phase 5/5b.3 added: **17** (per-sub-checkpoint deltas
  3+1+2+6+5; matches commit-message claims for the
  delta only)
- Phase 5/5b.3 closure total: **50** (= 33 + 17;
  corrects the prior "37" claim)

The "20 → 37" progression baked into Phase 5/5b.3 commit
messages stays in the git log as historical record. Future
readers of those commit messages should consult this
corrigendum for the empirically-verified counts.

**Methodology consequence:** the commit-message running-
total drift discipline (registered in section (7) above)
exists to prevent this class of error at future phase
closures. Empirical grep-on-code is the canonical method;
inherited running totals are not authoritative.
