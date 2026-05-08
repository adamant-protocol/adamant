# Provenance: bytecode-verifier fork + Adamant-specific rules

This document is the **canonical audit anchor for the Adamant
bytecode-verifier fork plus the Adamant-specific rule modules
landed across Phase 5/5b**. Originally established at Phase
5/5b.2 for module-level passes; **expanded at Phase 5/5b.4 D-7
to cover per-function passes**; **re-expanded at Phase 5/5b.5
E-7 to cover cross-module verifier work + the Phase 5/5b.5
rule modules** (`rule_06_no_dynamic_dispatch` +
`rule_07_privacy_circuit_in_shielded_only` +
`rule_08_bounded_loops`). 2nd instance of scope-expansion-
history-as-canonical-record sub-pattern (registered at E-7;
1st instance at D-7).

Subtrees covered:

- `adamant-vm/src/validator/module_pass/` (module-level
  passes; B-1 through B-6 + C-1 through C-5)
- `adamant-vm/src/validator/function_pass/` (per-function
  passes + frameworks; D-1 through D-7)
- `adamant-vm/src/validator/cross_module/` (cross-module
  verifier work; E-2)
- `adamant-vm/src/validator/rule_NN_*` modules (Adamant-
  specific rules at validator/-level: Rules 1, 2, 3, 4 from
  prior phases; Rules 6, 7, 8 from Phase 5/5b.5)

The file remains physically located under `module_pass/` for
git-history continuity; the scope is bytecode-verifier-wide
plus the validator's full §6.2.1.6 rule surface.

The fork is parallel to `crates/adamant-bytecode-format/PROVENANCE.md`
(which forks the bytecode-format primitives from
`move-binary-format` and `move-core-types`). This file forks
the bytecode-verifier passes from `move-bytecode-verifier`
(module-level + per-function) plus the per-function abstract-
interpretation framework from `move-abstract-interpreter` and
the borrow-graph machinery from `move-borrow-graph`.

Both subtrees follow the resistant-proof posture per whitepaper
§6.2.1.8 (amendment commits `19d744b`, `0651e2f`). Unlike the
vendored `move-*` crates under `/vendor`, this code is Adamant-
owned: it ships in the production binary, is under Adamant's
audit and maintenance, and this `PROVENANCE.md` documents its
upstream lineage rather than declaring vendor byte-faithfulness.

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
  - `external-crates/move/crates/move-bytecode-verifier/src/check_bounds.rs`
    (Phase 5/5b.3 C-1; module-level bounds checker; lives in
    upstream's `move-binary-format` rather than
    `move-bytecode-verifier`. Adamant naming:
    `module_pass/bounds_checker.rs`)
  - `external-crates/move/crates/move-bytecode-verifier/src/check_duplication.rs`
    (Phase 5/5b.3 C-2; duplicate-handle / duplicate-element
    checker; Adamant naming: `module_pass/duplication_checker.rs`)
  - `external-crates/move/crates/move-bytecode-verifier/src/signature.rs`
    (Phase 5/5b.3 C-3; signature-token well-formedness;
    Adamant naming: `module_pass/signature_checker.rs`)
  - `external-crates/move/crates/move-abstract-interpreter/src/control_flow_graph.rs`
    (Phase 5/5b.4 D-1a; per-function CFG construction;
    Adamant naming: `function_pass/cfg.rs`)
  - `external-crates/move/crates/move-abstract-interpreter/src/absint.rs`
    (Phase 5/5b.4 D-1b; abstract-interpretation framework
    consumed by D-4 / D-5a / D-5b; Adamant naming:
    `function_pass/absint.rs`)
  - `external-crates/move/crates/move-bytecode-verifier/src/control_flow.rs`
    (Phase 5/5b.4 D-2; per-function control-flow validation;
    Adamant naming: `function_pass/control_flow.rs`)
  - `external-crates/move/crates/move-bytecode-verifier/src/loop_summary.rs`
    (Phase 5/5b.4 D-2; reducibility helper for D-2's Tarjan
    1974 algorithm; Adamant naming: `function_pass/loop_summary.rs`)
  - `external-crates/move/crates/move-bytecode-verifier/src/stack_usage_verifier.rs`
    (Phase 5/5b.4 D-3; per-function operand-stack discipline;
    Adamant naming: `function_pass/stack_usage.rs`)
  - `external-crates/move/crates/move-abstract-stack/src/lib.rs`
    (Phase 5/5b.4 D-5a.0; AbstractStack data structure
    consumed by D-5a type-safety; Adamant naming:
    `function_pass/abstract_stack.rs`)
  - `external-crates/move/crates/move-bytecode-verifier/src/locals_safety/`
    (Phase 5/5b.4 D-4; per-function locals-safety verifier
    + acquires-list checker; Adamant naming:
    `function_pass/locals_safety/`)
  - `external-crates/move/crates/move-bytecode-verifier/src/type_safety.rs`
    (Phase 5/5b.4 D-5a; per-function type-safety verifier
    + Adamant-extension type rules per §6.2.1.4; Adamant
    naming: `function_pass/type_safety.rs`)
  - `external-crates/move/crates/move-borrow-graph/src/`
    (Phase 5/5b.4 D-5b.1; borrow-graph foundation port;
    Adamant naming: `function_pass/reference_safety/borrow_graph.rs`)
  - `external-crates/move/crates/move-bytecode-verifier/src/reference_safety/`
    (Phase 5/5b.4 D-5b.2; per-function reference-safety
    verifier + Adamant-extension reference rules; Adamant
    naming: `function_pass/reference_safety/`)
- **Source license:** Apache-2.0 (preserved here)
- **Date of fork:** 7 May 2026 (B-1: `ability_cache`); extended
  through 8 May 2026 (B-2.1 → B-2.4 closure); through 9 May
  2026 (Phase 5/5b.3 C-1 → C-5 closure); through 8 May 2026
  for the Phase 5/5b.4 D-1a → D-7 closure (per-function
  passes; calendar dates run from D-1a CFG foundation through
  D-7b documentation closure).

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

### `max_push_size = Some(10000)` (Bucket A, D-3)

Bucket A — adopt Sui's commented alternative verbatim. Sui
ships `max_push_size: None` in `VerifierConfig::default()`
(`vendor/move-vm-config/src/verifier.rs:61`) with a commented
alternative `Some(10000)` at lines 70-71 ("Max size set to
10000 to restrict number of pushes in one function"). Adamant
adopts the commented value with no deviation:

- Bounds runaway-growth within any single basic block at
  deploy time. 10000 pushes per block far exceeds any
  legitimate code shape; bounds verifier-side analysis cost
  on a worst-case input.
- Distinct from `max_value_stack_size` (a runtime concern per
  this PROVENANCE.md's "Out-of-scope fields" carve-out; lives
  in the AVM runtime config in the Phase 5/6.3 sub-arc per
  whitepaper §6.3).
- Pre-mainnet calibration tracked under §6.2.1.7 spec
  amendment workstream alongside the other Bucket A/B/C
  values.

Consumed by `function_pass::stack_usage::verify_block`.

## Out-of-scope fields (registered for future sub-arcs)

`AdamantStructuralLimits` covers **module-level deploy-time
bounds**. The following Sui `VerifierConfig` fields are
deliberately not included; each lives at a different layer:

- `max_basic_blocks`, `max_back_edges_per_function`,
  `max_back_edges_per_module` — per-function-pass concerns
  (CFG width); extend `AdamantStructuralLimits` in Phase 5/5b.4
  alongside the per-function passes that consume them.
  (`max_loop_depth` was previously in this list and landed at
  D-2 alongside the control-flow validation pass; `max_push_size`
  was previously in this list and landed at D-3 alongside the
  operand-stack discipline pass — see the entries above.)
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

**Six sub-patterns are named** (3 original at Phase 5/5b.2;
2 added at Phase 5/5b.3 closure; 1 added at Phase 5/5b.4
closure — see also Phase 5/5b.4 closure stream (19) for
sub-shape 4 below):

### 1. Explicit-macro defensive

`assert!` / `unreachable!` / `expect()` at unreachable code
paths. Used when reaching the path would indicate a serious
bug (broken upstream pass, bypassed deserializer, programmer
error). The macro message documents the structural argument
inline so an auditor reading the source can verify the
unreachability claim without external context.

Instances (Phase 5/5b.2 + 5/5b.3 + 5/5b.4):

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
  ported" qualifier through Phase 5/5b.2 — retired-via-
  fulfillment at Phase 5/5b.3 C-4 when DuplicationChecker
  + SignatureChecker landed and the qualifiers were
  replaced with explicit upstream-of-this-pass references.
- **D-1a CFG construction `assert!` with three-anchor
  message** (Phase 5/5b.4) — `AdamantControlFlowGraph::new`
  preconditions (bounds-checker validates branch targets
  + jump-table indices + code-length); `assert!` carries
  three-anchor message documenting the cross-pass-
  pipeline-dependency precondition.
- **D-3 stack_usage `debug_assert!` lookups** (Phase
  5/5b.4) — module-access lookups (`module.function_handles`,
  `module.struct_defs`) guarded by `debug_assert!` with
  three-anchor messages; release builds elide the asserts
  at zero cost; debug builds catch direct-unvalidated-
  input callers that violate the cross-pass-pipeline-
  dependency precondition. **3rd sub-shape of structural-
  impossibility-checks pattern** alongside D-1a's
  `assert!` and B-2.4's `unreachable!`.
- **D-4 acquires-list `unreachable!`-three-anchor**
  (Phase 5/5b.4) — acquires-list structural-impossibility
  check with `unreachable!`-three-anchor message; **2nd
  instance of sub-shape 2 (`unreachable!`-three-anchor)
  alongside B-2.4 deprecated arms** (rule-of-three pending
  for sub-shape 2 specifically).
- **D-5a.1.a `expect()`-three-anchor on AbsStackError
  paths** (Phase 5/5b.4) — Adamant-side defensive
  programming where `expect()` carries three-anchor
  message documenting why the path can't panic in the
  validator pipeline. **Sub-shape 4 of structural-
  impossibility-checks pattern** (NEW; registered at
  Phase 5/5b.4 closure stream (19); rule-of-three pending).

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

Pattern instances (Phase 5/5b.2 + 5/5b.3 + 5/5b.4):

1. **B-4.2: byte → range → duplicate per-pair check
   ordering.** Cheapest-check-first rationale (byte =
   single comparison; range = comparison + length lookup;
   duplicate = `HashSet::insert` allocation + hashing).
   Alternative orderings would be defensible (e.g., range-
   first to fail-fast on out-of-range indices that can't
   be valid under any interpretation; or
   most-diagnostic-useful-first). What matters is
   documenting the chosen ordering as a fresh Adamant
   decision rather than implying upstream parity.
2. **C-1.3: `check_field_def` extraction.** Per-field
   reuse helper across struct + enum field iteration in
   the bounds checker; deliberate Adamant decision to
   factor the shared shape rather than duplicate.
3. **C-2: `DefKind` closed enum** (`Struct | Enum |
   Function`). Closed-enum-sub-reason on the
   `DuplicationChecker` workhorse error variant
   `DuplicateElement`, distinguishing the def-kind
   without splitting into three separate variants.
4. **D-1b: AdamantValidationError as the AI framework's
   error type.** Hard-wired at the AbstractInterpreter
   trait level rather than parameterizing over a generic
   error type. Adamant-specific decision per the
   resistant-proof posture (the AI framework lives only
   in adamant-vm and only consumes Adamant's error type).
5. **D-2: `IrreducibleReason` closed enum**
   (`InvalidLoopSplit | LoopMaxDepthReached`). Closed-
   enum-sub-reason on `IrreducibleControlFlow`; same
   pattern as C-3's `InvalidSignatureReason`.
6. **D-4: `AdamantAbilityCache` visibility promotion**
   from `pub(super)` to `pub(in crate::validator)` for
   inline per-function ability resolution per Q3a.
   Deliberate scope expansion of an existing helper to
   serve a new consumer rather than duplicating the
   cache implementation.
7. **D-5a.0: `TypeMismatchReason` closed enum** (14 sub-
   reasons declared pre-emptively at foundation). Closed-
   enum-sub-reason on `TypeMismatch`; pre-emptive
   declaration deferred audit closure across D-5a.1.a +
   D-5a.1.b producers.
8. **D-5a.1.b: per-pass-instance ability cache hoist.**
   `type_safety_cache` hoisted outside the function loop
   (Q2(a) at D-5 plan-gate); deliberate Adamant decision
   for type_safety specifically, distinct from
   locals_safety's stricter per-function-instance
   lifecycle (Q3(a) at D-4 plan-gate).
9. **D-5b.2: `BorrowViolationReason` closed enum** (13
   sub-reasons). Closed-enum-sub-reason on
   `BorrowViolation`; same pattern as `TypeMismatchReason`.
10. **D-5c: `PrivacyConsistencyViolationReason` closed
    enum.** Closed-enum-sub-reason on
    `PrivacyConsistencyViolation`; consistent shape with
    other Adamant-specific rule violations.
11. **D-7a: extract-at-N=3 (sub-shape β of helper-
    extraction discipline).** Deliberate Adamant decision
    to extract `function_pass/test_helpers.rs` helpers at
    the third backfill rather than the second (per the
    higher fixture-construction overhead in per-function
    passes vs module-level passes). Sub-shape β
    canonically registered at Phase 5/5b.4 closure stream
    (15).

11 deliberate-Adamant-decision instances at Phase 5/5b.4
closure (5/5b.2 added 1; 5/5b.3 added 2; 5/5b.4 added 8).

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

- **2026-05-08 (Phase 5/5b.4 D-1 closure: per-function-pass
  infrastructure):** Foundation-then-producer arc; D-1 split
  into D-1a + D-1b at the D-1 plan-gate per the empirical-
  complexity-drives-sub-checkpoint-shape pattern (sub-shape 2
  pre-arc-split; 2nd instance after C-1.4 split into
  C-1.4a/C-1.4b at Phase 5/5b.3). Constituent commits:
  D-1a (CFG construction foundation; commit `57b886e`),
  D-1b (abstract-interpretation framework with synthetic
  SawPop domain; commit `5a56603`), plus a mid-arc state-
  bump for D-1 closure documentation (commit `62a1987`).
  Cumulative file LOC: ~1,512 across `function_pass/cfg.rs`
  (771) + `function_pass/loop_summary.rs` (608, lands at
  D-2 but the LoopSummary type prepared at D-1a) +
  `function_pass/absint.rs` (741, partial at D-1b) +
  `function_pass/mod.rs` (preamble + scaffold). Test
  additions: 18 (D-1a CFG construction + 1 cfg.instructions
  accessor) + 13 (D-1b AI framework with synthetic SawPop
  domain) = **31 new tests**. Workspace test count
  progression: **1259 → 1290 (+31)**.
  AdamantValidationError unchanged at 50 typed variants
  (D-1a + D-1b are infrastructure-only per Q1 walk-back
  precedent; first per-function-pass variants ship at D-2
  alongside producer per Rust error-type lifecycle). New
  patterns observed across D-1: **Q1 walk-back precedent
  reaches 2 instances** (D-1a's `unnecessary_wraps` +
  `unused_self` `#[allow]`s + D-1b's `needless_pass_by_value`
  `#[allow]`; held byte-faithful preservation rather than
  introducing Adamant-side deviation without plan-gate pre-
  approval; rule-of-three confirmation pending);
  **deliberate-Adamant-decision pattern reaches 4th
  instance** (Q2 hard-wire AdamantValidationError as the AI
  framework's error type at D-1b); **plan-incremental-
  disposition-resolved-empirically reaches 2nd instance**
  (D-1a's UnreachableBlock empirical elision; first
  instance C-3's InvalidSignatureReason 2-vs-3 resolution);
  **upstream-consolidates-undershoot calibration pattern
  registered (NEW)** at D-1b — when plan-gate framing
  decomposes upstream's consolidated implementation into
  N pieces but upstream is M < N pieces, impl-core
  undershoots framing-anticipated estimates by ~30-50%;
  first instance at D-1b where plan-gate framing surfaced
  AbstractDomain + TransferFunctions + AbstractInterpreter
  as three traits but upstream consolidates into one;
  **hoisted-enum-for-clippy-items-after-statements pattern
  registered (NEW)** at D-1a — state-machine enums hoisted
  to module level to satisfy `clippy::items_after_statements`
  while preserving upstream's state-machine shape; D-1a's
  `Exploration` enum is first instance. **9th verification
  gate fired** at D-1 plan-gate via §6.2.1.8 line 526
  verbatim re-paste; cleared cleanly. Plus **forward-shape
  elaboration registered for future plan-gate framing**:
  foundation-then-producer arcs requiring forward-shape-
  variant-declaration must surface the question at plan-
  gate with explicit pre-approval, not at implementation-
  gate as discovery; default disposition remains 'declare
  variants alongside their first producer' per the C-3
  variant-vs-test mapping audit principle.

- **2026-05-08 (Phase 5/5b.4 D-2 closure: control-flow
  validation pass):** Single sub-checkpoint commit
  (`4bc6eaf`) ports upstream
  `move-bytecode-verifier::control_flow` to
  `function_pass/control_flow.rs`. ~693 LOC implementation
  + 32 unit tests (24 control_flow + 8 loop_summary
  staging). adamant-vm crate test count: 588 → 624 (+36).
  Workspace test count progression: **1290 → 1326 (+36;
  per-commit empirical observation; commit message did not
  claim workspace count).** Three new typed-error variants:
  `EmptyFunctionBody`, `MissingFallthroughTerminator`,
  `IrreducibleControlFlow` (with closed enum
  `IrreducibleReason`: `InvalidLoopSplit | LoopMaxDepthReached`
  — 5th deliberate-Adamant-decision instance per the
  closed-enum-sub-reason pattern continued from C-3's
  `InvalidSignatureReason`). AdamantValidationError variant
  count: 50 → 53 (+3). `AdamantStructuralLimits` gains
  `max_loop_depth: Option<u16>` with provisional Bucket C
  value `Some(64)`; pre-mainnet calibration tracked under
  §6.2.1.7 amendment workstream. Adamant-extension treatment
  sub-shape 3 (extensions don't have branches; pass through
  fall-through validation) — 2nd instance of sub-shape 3
  after C-3 SignatureChecker; rule-of-three pending.
  Plan-overshot-on-helper-signature pattern observed at the
  D-2 implementation-gate (LoopSummary helper required
  fewer parameters than plan-gate anticipated) — 2nd
  instance after C-1.4b's `check_signature_type_parameters`.
  Implementation-core LOC ~561 within plan-gate band [445,
  615] (eight-instance LOC-vs-estimate calibration cycle
  stable at ±25-30% midpoint variance band).

- **2026-05-08 (Phase 5/5b.4 D-3 closure: operand-stack
  discipline pass):** Single sub-checkpoint commit
  (`0ceae97`) ports upstream
  `move-bytecode-verifier::stack_usage_verifier` to
  `function_pass/stack_usage.rs`. ~1,239 LOC implementation
  + 36 unit tests covering Categories A (12 static
  per-extension pins), B (2 parametric-FH), C (2 deferred-
  to-§7), D (1 deferred-to-§8.5), per-block balance happy
  paths and rejections, max_push_size gating, inherited-
  bytecode shape pins, eager-error semantics. adamant-vm
  crate test count: 624 → 660 (+36). Workspace test count
  progression: **1326 → 1362 (+36; per-commit empirical
  observation; commit message did not claim workspace
  count — drift origin for the D-3-to-D-4 baseline error;
  see corrigendum at end of file).** Three new typed-error
  variants alongside their producer per Q1 walk-back
  precedent: `StackPushOverflow`, `StackUnderflow`,
  `UnbalancedStackAtBlockEnd`. AdamantValidationError
  variant count: 53 → 56 (+3). `AdamantStructuralLimits`
  gains `max_push_size: Option<u64>` with provisional
  Bucket A value `Some(10000)` (adopt Sui's commented
  alternative verbatim); pre-mainnet calibration tracked
  under §6.2.1.7 amendment workstream.
  `max_value_stack_size` remains a runtime concern per
  PROVENANCE.md "Out-of-scope fields" carve-out (lives in
  AVM runtime config in Phase 5/6.3). **10th verification
  gate fired** in corrective mode at D-3 plan-gate via
  §6.2.1.4 per-extension stack-effect verbatim survey,
  partitioning the 17 Adamant extensions into four
  categories. **NEW pattern registered: verbatim-survey-
  at-plan-gate-prevents-scope-error** — D-3's §6.2.1.4
  re-paste caught what would have been Category B / C / D
  miscategorization at implementation time. 1st instance;
  rule-of-three threshold met later at D-5b + D-5c (see
  Phase 5/5b.4 closure methodology accumulation streams
  below). Debug-only defensive guards on module-access
  lookups: 3rd sub-shape of structural-impossibility-checks
  pattern (debug_assert! with three-anchor messages
  alongside D-1a's assert! and B-2.4's unreachable!).
  **Shielding-vs-runtime canonical pattern 1st instance**
  at D-3: Categories C + D fail-open at deploy-time;
  runtime carries the binding. Implementation-core LOC
  ~470 within plan-gate band [365, 510].

- **2026-05-08 (Phase 5/5b.4 D-4 closure: locals safety +
  acquires-list verification):** Single sub-checkpoint
  commit (`603edf7`) ports upstream
  `move-bytecode-verifier::locals_safety` to
  `function_pass/locals_safety/`. ~1,038 LOC implementation
  (mod.rs 791 + abstract_state.rs 247) + 23 unit tests.
  adamant-vm crate test count: 660 → 683 (+23). Workspace
  test count progression: **1362 → 1351 (+23 from baseline
  1328 incorrectly inherited from D-3's missing workspace
  claim; D-4 commit message claimed 1328 → 1351 = +23
  empirically correct delta on wrong baseline).
  Empirically: actual workspace count at D-4 closure is
  1385 (= 1362 + 23). See D-3-to-D-4 corrigendum at end
  of file.** Five new typed-error variants alongside their
  producer per Q1 walk-back precedent: `StLocDestroysNonDrop`,
  `MoveLocUnavailable`, `CopyLocUnavailable`,
  `BorrowLocUnavailable`, `RetWithUndroppedLocals`.
  AdamantValidationError variant count: 56 → 61 (+5).
  Acquires-list structural-impossibility check is the 2nd
  instance of structural-impossibility-checks sub-shape 2
  (`unreachable!`-three-anchor; 1st was B-2.4 deprecated
  arms — rule-of-three pending). Adamant-extension
  treatment sub-shape 3 reaches 3rd instance at D-4
  (extensions don't read/write/borrow locals; pass through;
  alongside D-1a CFG and D-2 fall-through) — **rule-of-
  three threshold met for sub-shape 3** specifically
  across D-1a / D-2 / D-4. `AdamantAbilityCache` visibility
  promoted from `pub(super)` to `pub(in crate::validator)`
  for inline per-function ability resolution per Q3a — 6th
  deliberate-Adamant-decision instance.

- **2026-05-08 (Phase 5/5b.4 D-5a closure: type-safety
  pass):** D-5a sub-arc split into 3 sub-checkpoints at the
  D-5a plan-gate per the empirical-complexity-drives-sub-
  checkpoint-shape pattern (sub-shape 2 pre-arc-split; 3rd
  instance after C-1.4 split + D-1 split — **rule-of-three
  threshold met for sub-shape 2**). Constituent commits:
  D-5a.0 (type-safety foundation: AbstractStack port +
  TypeMismatchReason 14-sub-reason closed enum; commit
  `824d7bc`), D-5a.1.a (type-safety pass core + first half
  inherited arms — load/move/copy/store/binop/eq/cast/
  branch/ret/abort/pop; commit `952ad69`), D-5a.1.b (type-
  safety pass remaining arms + 17 Adamant-extension type
  rules per §6.2.1.4 + orchestration chain wiring; commit
  `6e34f47`). Cumulative file LOC: ~3,060 across
  `function_pass/type_safety.rs` (2,767) +
  `function_pass/abstract_stack.rs` (293). Test additions:
  D-5a.0 (9) + D-5a.1.a (17) + D-5a.1.b (27) = **53 new
  tests**. adamant-vm crate test count: 683 → 736 (+53).
  Workspace test count progression empirically grounded:
  D-5a.0 1385 → 1394; D-5a.1.a 1394 → 1411; D-5a.1.b
  1411 → 1438 (per commit-claimed deltas applied to
  empirically corrected baseline). One new typed-error
  variant: `TypeMismatch` with closed enum
  `TypeMismatchReason` (14 sub-reasons declared pre-
  emptively at D-5a.0; producer at D-5a.1.a/D-5a.1.b).
  AdamantValidationError variant count: 61 → 62 (+1).
  Public closed enums: 7 → 8 (+1; `TypeMismatchReason`).
  **NEW spec-text-DIRECTS-shared-helper canonical principle
  1st instance** at D-5a.1.b: `InvokeShielded` /
  `InvokeTransparent` reuse the `call` type-safety helper
  per §6.2.1.4 line 408 verbatim — the spec text directly
  prescribes the shared helper rather than the
  implementation choosing it independently. Per-pass-
  instance ability cache hoisted outside the function loop
  (Q2(a) at D-5 plan-gate; consumes the D-4 visibility
  promotion). Sub-shape 4 (NEW) of structural-impossibility-
  checks pattern at D-5a.1.a: `expect()`-three-anchor on
  `AbsStackError` single-pop/push paths — Adamant-side
  defensive programming where the three-anchor message
  carries the structural argument for why the path can't
  panic in the validator pipeline. **Honest-scope-flagging
  at impl-gate sub-pattern 1st instance opening phase** at
  D-5a.1.a: chained-orchestration deferral declared
  honestly at sub-checkpoint commit; **closure phase 1st
  instance** at D-5a.1.b orchestration-chain-wired-in
  commit. 6 of 14 variant-vs-test mapping audit closures
  at D-5a.1.a, remaining 8 at D-5a.1.b — per-mechanism
  counting discipline applied. **Shielding-vs-runtime
  canonical pattern 2nd instance** at D-5a.1.b: per-
  extension type rules for Categories C + D defer to
  runtime per §6.2.1.4 lines 410-411 / line 423.

- **2026-05-08 (Phase 5/5b.4 D-5b closure: reference safety
  + borrow-graph port):** D-5b sub-arc split into 2 sub-
  checkpoints at the D-5b plan-gate per the empirical-
  complexity-drives-sub-checkpoint-shape pattern (sub-shape
  2 pre-arc-split; reaches 4th instance after C-1.4 / D-1 /
  D-5a — sub-shape 2 well-established post-rule-of-three).
  Constituent commits: D-5b.1 (borrow-graph foundation
  port from `move-borrow-graph`; commit `47e1d7a`), D-5b.2
  (reference-safety pass + Adamant extensions +
  orchestration; commit `23788ab`). Cumulative file LOC:
  ~3,572 across `function_pass/reference_safety/` (mod.rs
  91 + abstract_state.rs 886 + borrow_graph.rs 1,145 +
  pass.rs 1,450). Test additions: D-5b.1 (21) + D-5b.2
  (26) = **47 new tests**. adamant-vm crate test count:
  736 → 783 (+47). One new typed-error variant:
  `BorrowViolation` with closed enum
  `BorrowViolationReason` (13 sub-reasons declared pre-
  emptively at D-5b.2 producer landing). AdamantValidationError
  variant count: 62 → 63 (+1). Public closed enums: 8 → 9
  (+1; `BorrowViolationReason`). **Verbatim-survey-at-
  plan-gate-prevents-scope-error pattern 2nd instance** at
  D-5b plan-gate via §6.2.1.6 reference-safety + regex
  verbatim re-paste. **Shielding-vs-runtime canonical
  pattern 3rd instance** at D-5b.2: Categories C + D
  reference-safety rules fail-open at deploy-time; runtime
  carries the binding. **Rule-of-three threshold met for
  shielding-vs-runtime canonical pattern** across D-3 /
  D-5a.1.b / D-5b.2 (cross-pass consistency). **Honest-
  scope-flagging at impl-gate sub-pattern closure-phase
  2nd instance** at D-5b.2 orchestration commit (1st
  closure instance was D-5a.1.b orchestration-chain-wired-
  in commit). Plan-incremental-disposition sub-pattern β
  opening 2nd instance at D-5b.2: 6 of 13
  BorrowViolationReason sub-reasons deferred — D-6
  integration tests cover end-to-end pipeline but don't
  backfill the multi-block CFG aliasing fixtures needed
  for these specific sub-reasons; deferred to pre-mainnet
  hardening. (1st opening instance: D-5a.1.a chained-
  orchestration deferral, closed at D-5a.1.b.)

- **2026-05-08 (Phase 5/5b.4 D-5c closure: Rule 3
  privacy-consistency call-graph walker):** Single sub-
  checkpoint commit (`5926c7a`) implements whitepaper
  §6.2.1.6 Rule 3 (Adamant-specific; no upstream
  counterpart). ~416 LOC `validator/rule_03_privacy_consistency.rs`
  + 15 unit tests. adamant-vm crate test count: 783 → 798
  (+15). One new typed-error variant: `PrivacyConsistencyViolation`
  with closed enum `PrivacyConsistencyViolationReason`.
  AdamantValidationError variant count: 63 → 64 (+1).
  Public closed enums: 9 (unchanged from D-5b.2's 9).
  **Verbatim-survey-at-plan-gate-prevents-scope-error
  pattern 3rd instance** at D-5c plan-gate via §6.2.1.6
  Rules 3-5 verbatim re-paste — discovered Rules 4 and 5
  already-implemented at validator/mod.rs step 5 + step 1
  respectively, scoping D-5c down to Rule 3 only. **Rule-
  of-three threshold met for verbatim-survey-at-plan-gate-
  prevents-scope-error pattern** across D-3 / D-5b /
  D-5c. **NEW spec-text-DIRECTS-shared-helper canonical
  principle 3rd instance** at D-5c: `call_target_handle`
  walker shape directly prescribed by §6.2.1.6 Rule 3
  spec text — the call-graph walk over function-call
  bytecodes is what the spec text says to do. **Rule-of-
  three threshold met for spec-text-DIRECTS-shared-helper
  canonical principle** across D-5a.1.b (call helper
  reuse) + D-5b.2 (reference-safety call shape) + D-5c
  (call-graph walk). **11th verification gate fired** at
  D-5c plan-gate via §6.2.1.6 spec binding. Cross-module
  Rule 3 enforcement (e.g., a function in module A that
  calls a function in module B with privacy mismatch)
  registered as forward-tracking carry-forward to Phase
  5/5b.5's deployment-validator wiring layer (the
  per-function pass operates on the current module only;
  cross-module enforcement requires the deployment
  layer's loaded-modules view).

- **2026-05-08 (Phase 5/5b.4 D-6 closure: pipeline
  integration of step 4):** Single sub-checkpoint commit
  (`a74f4c8`) wires `function_pass::verify_function_bodies`
  into `validator::verify_module` between step 3 (module-
  level Adamant passes) and the transitional Sui-verifier
  bridge defense-in-depth. Step 4 now runs on ALL modules
  (both inherited-subset and Adamant-extension); the
  bridge remains at its current position as transitional
  defense-in-depth on inherited-subset modules until
  5/5b.5 tear-out. ~225 LOC of test code (6 end-to-end
  integration tests at `validator/mod.rs::tests`). No new
  typed-error variants; no new closed enums.
  AdamantValidationError variant count unchanged at 64.
  adamant-vm crate test count: 798 → 804 (+6). Workspace
  test count empirically grounded post-corrigendum: D-6
  closure at 1500 (per commit-message claim 1466 → 1472
  applied to empirically corrected baseline). **Cross-
  pass eager-error precedence list count stays at 3** (no
  new precedence claims at D-6; step-4 vs step-5 are
  distinct concerns; step-4 vs bridge is intentionally
  redundant defense-in-depth, not eager-error competitor).
  **NEW bridge-as-soundness-test-infrastructure framing**
  registered at D-6: the transitional Sui-verifier bridge
  serves dual roles — defense-in-depth on inherited-
  subset modules AND soundness-test infrastructure for
  cross-pass-pipeline-dependency drift detection (if
  Adamant accepts but Sui rejects on the same module, the
  divergence indicates a drift in Adamant's pipeline).
  **NEW bridge-redundancy-validation tests as Layer B
  cross-validation alternative** registered at D-6: tests
  #5 + #6 in the integration suite assert that the bridge
  and the Adamant-native pipeline produce identical
  accept/reject outcomes on inherited-subset modules,
  serving as composite-level Layer B coverage at the
  full-pipeline boundary. **NEW 4th-precedence-claim-
  retired-via-empirical-absence sub-pattern** at D-6
  plan-gate: Q4 had anticipated a 4th precedence claim
  (BoundsChecker `IndexOutOfBounds` vs limits' overflow)
  empirically not surfacing; cross-pass precedence list
  stays at 3 instances. **NEW implementation-adjacent
  doc-cleanup pattern** registered at D-6 with 2 sub-
  shapes: adjacent (Q6(a) step-5 comment cleanup at D-6,
  inline with the wiring change) and batch (Q6(b)
  function_pass/mod.rs comment deferred to D-7 closure
  batch).

- **2026-05-08 (Phase 5/5b.4 D-7a closure: Layer B cross-
  validation backfill):** Single sub-checkpoint commit
  (`31a22d0`) backfills Layer B cross-validation tests
  for D-2 / D-3 / D-4 deferred at honest-scope-flagging
  through closure. 26 new parity tests (9 control_flow +
  8 stack_usage + 9 locals_safety) + 165 LOC helper
  module at `function_pass/test_helpers.rs`. adamant-vm
  crate test count: 804 → 830 (+26). Workspace test
  count: **1506 → 1532 (+26; empirically verified post-
  corrigendum baseline)**. No new typed-error variants;
  no new closed enums; no new production dependencies.
  Helper extracted at extract-at-N=3 (sub-shape β of
  helper-extraction discipline; module_pass's extract-
  at-N=2 at B-2.2 is sub-shape α — chronological naming
  preserved per resume-prompt α/β refinement). Empirical-
  grep retrofit-need check across function_pass/
  confirmed no inline parity tests existed in D-5a / D-5b
  / D-5c; helper foundation lands cleanly with D-2 /
  D-3 / D-4 backfill only. **NEW Sui-public-API-shape-
  constrains-parity-helper sub-pattern 1st instance** at
  D-7a: Sui's per-pass entries (`StackUsageVerifier::verify`,
  `locals_safety::verify`, `type_safety::verify`) are
  `pub(crate)` — only `control_flow::verify_function`
  (per-pass) and `code_unit_verifier::verify_module`
  (composite) are publicly reachable. Layer B parity
  strategy adapts: D-2 control_flow uses per-pass parity;
  D-3 / D-4 use composite-pipeline parity with fixtures
  curated to isolate the targeted pass via type-correct
  construction. Composite-level accept/reject parity is
  sound because both pipelines run the same passes; rule-
  of-three pending at next per-pass parity attempt with
  similar API constraint. **Open Layer B gap registered**
  for D-7b documentation: `st_loc_destroys_non_drop`
  rejection rule's Layer B parity needs a fixture with
  two non-drop value sources, which exceeds D-7a's
  fixture-construction scope. Adamant's Layer A
  `stloc_to_available_no_drop_local_rejected` covers the
  rule directly; Sui-side coverage lives in upstream's
  own test suite. Registered at D-7b under "Open Layer B
  gaps deferred to pre-mainnet hardening" framing.

- **2026-05-08 (Phase 5/5b.4 D-7b closure: Phase 5/5b.4
  closes):** Documentation-only sub-checkpoint. No
  source-code changes beyond the function_pass/mod.rs
  doc-cleanup carry-forward and the
  `#![allow(dead_code)]` reason rewrite; tests unchanged
  at 1532. PROVENANCE.md updates batch the Phase 5/5b.4
  per-sub-arc closure entries (D-1 → D-7 above) plus the
  D-7b methodology accumulation streams section (next
  major section), the D-3-to-D-4 baseline corrigendum,
  the variant-vs-test mapping audit appendix for the 14
  new variants added during Phase 5/5b.4, and updates to
  existing thematic sections (instance count refreshes).
  CLAUDE.md state-bump for Phase 5/5b.4 closure lands in
  the same commit per the deferred-to-phase-closure
  pattern (B-6 / C-5 precedents).

  **Sub-arc delta (D-7b alone):** 0 functional source-
  code changes (function_pass/mod.rs doc-cleanup is
  pure-documentation; module-level `dead_code` allow
  reason rewrite is comment-only); documentation-only;
  tests unchanged at 1532; ~1900-2800 LOC of net edits
  to PROVENANCE.md + CLAUDE.md (largest single
  documentation closure batch in the project's history).

  **Cumulative phase delta (Phase 5/5b.4, D-1a through
  D-7b):** 9 sub-arcs (D-1 split into D-1a/D-1b/mid-arc
  state-bump; D-2; D-3; D-4; D-5a split into D-5a.0/
  D-5a.1.a/D-5a.1.b; D-5b split into D-5b.1/D-5b.2;
  D-5c; D-6; D-7 split into D-7a/D-7b). **14 commits on
  origin** (D-1a `57b886e`; D-1b `5a56603`; mid-arc
  `62a1987`; D-2 `4bc6eaf`; D-3 `0ceae97`; D-4 `603edf7`;
  D-5a.0 `824d7bc`; D-5a.1.a `952ad69`; D-5a.1.b
  `6e34f47`; D-5b.1 `47e1d7a`; D-5b.2 `23788ab`; D-5c
  `5926c7a`; D-6 `a74f4c8`; D-7a `31a22d0`; D-7b
  closure commit lands with this state-bump). Workspace
  test count progression empirically verified:
  **1259 → 1532 (+273)** across the phase. (Per-sub-
  checkpoint deltas were correct in commit messages;
  only the inherited workspace baseline at D-4 was wrong
  — see D-3-to-D-4 corrigendum below for the
  reconstruction.) AdamantValidationError progression:
  **50 → 64 (+14)**. **Public closed enums: 5 → 9 (+4):**
  `IrreducibleReason` (D-2), `TypeMismatchReason`
  (D-5a.0), `BorrowViolationReason` (D-5b.2),
  `PrivacyConsistencyViolationReason` (D-5c). 5
  per-function passes ported Adamant-native + 1 Adamant-
  specific rule (Rule 3) + per-function-pass infrastructure
  (CFG + AbstractInterpreter + AbstractStack + BorrowGraph)
  + pipeline integration at D-6. **Helper extracted at
  D-7a:** `function_pass/test_helpers.rs` with 6 helpers
  (extract-at-N=3 sub-shape β of helper-extraction
  discipline). **Verification gates fired:** 9th (D-1
  plan-gate via §6.2.1.8 line 526), 10th (D-3 plan-gate
  via §6.2.1.4 per-extension stack-effects), 11th (D-5c
  plan-gate via §6.2.1.6 Rules 3-5). **Methodology
  patterns formalized at D-7b** (full enumeration in the
  Phase 5/5b.4 closure methodology accumulation streams
  section below): rule-of-three thresholds met across the
  phase for sub-shape 2 (pre-arc-split; instances
  C-1.4 / D-1 / D-5a, then D-5b 4th); sub-shape 3
  (Adamant-extension treatment pass-through; instances
  C-3 / D-1a / D-2 / D-4); shielding-vs-runtime canonical
  pattern (D-3 / D-5a.1.b / D-5b.2); spec-text-DIRECTS-
  shared-helper canonical principle (D-5a.1.b / D-5b.2 /
  D-5c); verbatim-survey-at-plan-gate-prevents-scope-
  error pattern (D-3 / D-5b / D-5c); Open Layer B gaps
  deferred to pre-mainnet hardening (C-5 SuiVerifier /
  D-5b.2 BorrowViolationReason 6 of 13 / D-7a
  st_loc_destroys_non_drop). Plus 6 new patterns at
  sub-rule-of-three threshold registered at D-7b for
  forward-tracking. Phase 5/5b.4 closes; Phase 5/5b
  sub-arc remaining: **5/5b.5** (Sui-verifier bridge
  tear-out + 13 vendored Sui-Move crate removal from
  production-binary deps + Rules 6, 7 implementation +
  Rule 8 runtime gas-bound no-op test + cross-module
  Rule 3 enforcement at deployment-validator wiring +
  `tests/no_sui_in_production_deps.rs` build-system
  independence check).

- **2026-05-09 (Phase 5/5b.5 E-1 closure: Sui-bridge tear-
  out):** Two-sub-checkpoint sub-arc per Q2(b) at E-1 plan-
  gate (production-code refactor + Cargo.toml restructure
  separated). Constituent commits: E-1a (`0b774a3`,
  production-code refactor) + E-1b (`4fb4114`, Cargo.toml
  restructure + build-system check). Cumulative E-1 LOC:
  ~544 net diff (E-1a 177 inserts / 324 deletions; E-1b
  367 inserts / 63 deletions). adamant-vm crate test count
  E-1a → E-1b: 830 → 831 (+1; upstream-parity pin in
  `validator/config.rs`). Workspace test count progression:
  1532 → 1534 (+2 across E-1; +1 from upstream-parity pin
  + +1 from build-system check). **E-1a removes the Sui-
  verifier bridge from `validator::verify_module`'s
  pipeline; E-1b moves 4 vendored Sui-Move crates
  (`move-binary-format` with wasm, `move-core-types`,
  `move-bytecode-verifier`, `move-vm-config`) from
  `[dependencies]` to `[dev-dependencies]`. The build-system
  independence check at `tests/no_sui_in_production_deps.rs`
  walks `cargo metadata`'s resolve graph and asserts no
  `move-*` crate appears in `adamant-vm`'s production
  dependency graph; sanity-check empirically confirmed the
  test fires on regression.** AdamantValidationError
  variant count: 64 → 63 (-1; SuiVerifier removed at E-1a).
  **1st instance of variant-count-via-tear-out sub-shape**
  (NEW; per Q2 refinement at E-1 plan-gate). **1st
  instance of architectural-commitment-mechanically-guarded
  pattern** (NEW; the build-system check is the mechanical
  guardrail for §6.2.1.8's resistant-proof posture
  commitment; the `move-*`-crates absence is constitutionally
  meaningful, parallel to "no foundation, no admin keys,
  no upgrade authority after genesis"). **1st instance of
  upstream-constant-duplication-with-test-time-parity-pin
  pattern** (NEW; 3 Adamant-native constants
  `DEFAULT_MAX_VARIANTS`, `DEFAULT_MAX_CONSTANT_VECTOR_LEN`,
  `DEFAULT_MAX_IDENTIFIER_LENGTH` duplicate Sui upstream
  values; test-time parity pin asserts upstream agreement).
  **1st instance of test-actually-fires-on-regression
  sanity-check methodology shape** (NEW; verified-empirically
  discipline operating at build-system-test level). **1st
  instance of gap-source-removal closure for Open Layer B
  gaps pattern** (NEW; SuiVerifier audit gap registered at
  C-5 closes via bridge removal — retired-via-fulfillment).
  **1st instance of bridge-as-soundness-test-infrastructure
  framing reaching CLOSURE PHASE** (NEW; bridge framed at
  D-6 as soundness-test infrastructure during transition;
  bridge retires at E-1a and the framing itself closes;
  D-6 bridge-redundancy-validation tests #5 + #6 refactor
  from bridge-ordering-validation to typed-error-validation).

- **2026-05-09 (Phase 5/5b.5 E-2 closure: cross-module
  Rule 3):** Two-sub-checkpoint sub-arc per Q4(b) at E-2
  plan-gate (foundation + walker separated). Constituent
  commits: E-2a (`8e4d814`, foundation: ModuleResolver
  trait + ModuleId type + new error variant + trait/API
  correctness tests) + E-2b (`4e5bbab`, cross-module Rule
  3 walker + happy-path / negative-path tests). Cumulative
  E-2 LOC: ~1,263 net inserts (E-2a 406; E-2b 857).
  adamant-vm crate test count E-1b → E-2b: 831 → 849 (+18;
  E-2a +7 trait/API tests + E-2b +11 walker tests).
  Workspace test count: 1534 → 1552 (+18). **E-2a
  introduces the `validator/cross_module/` module subtree
  housing the cross-module verifier work. New types:
  `ModuleId(Address, Identifier)` thin newtype mirroring
  Sui-Move's ModuleId shape without the production-side
  Sui dependency (Adamant-native per the §6.2.1.8
  resistant-proof posture); `ModuleResolver` trait with
  one method `resolve(&self, id: &ModuleId) ->
  Option<&AdamantCompiledModule>`; `InMemoryModuleResolver`
  test impl backed by HashMap.** New error variant:
  `CrossModulePrivacyConsistencyViolation` reusing
  `PrivacyConsistencyViolationReason` closed enum from
  D-5c. AdamantValidationError variant count: 63 → 64
  (+1). **E-2b's walker reuses D-5c's `call_target_handle`
  via the `pub(in crate::validator)` visibility promotion
  landing in this commit** — 4th instance of spec-text-
  DIRECTS-shared-helper canonical principle (cross-scope-
  reuse sub-shape 1st instance; rule-of-three pending
  across cross-scope-reuse). Cross-module walker has no
  production caller in adamant-vm; the eventual caller is
  the AVM runtime stdlib's `adamant::module::deploy`
  function (Phase 5/6) per whitepaper §6.5 line 97; module-
  level `dead_code` allow on `cross_module` documents the
  foundation-then-producer arc shape. **1st instance of
  same-rule-different-scope-shares-sub-reason-enum
  methodology pattern** (NEW; per Q3 disposition at E-2
  plan-gate; PrivacyConsistencyViolationReason shared
  between PrivacyConsistencyViolation single-module +
  CrossModulePrivacyConsistencyViolation cross-module).
  **1st instance of helper-extraction sub-shape γ
  (extract-at-N=1-anticipating)** (NEW; per Q5 disposition
  at E-2 plan-gate; InMemoryModuleResolver extracted at
  N=1 with 7 immediate consumers + anticipated reuse at
  E-2b walker tests). Helper-extraction discipline now has
  three empirical sub-shapes: α=N=2 (B-2.2); β=N=3 (D-7a);
  γ=N=1-anticipating (E-2a).

- **2026-05-09 (Phase 5/5b.5 E-3 closure: Rule 6 — no
  dynamic dispatch):** Single sub-checkpoint commit
  (`922d4bd`). ~600 net inserts; 11 new tests in
  `validator/rule_06_no_dynamic_dispatch.rs::tests`.
  adamant-vm crate test count: 849 → 860 (+11). Workspace
  test count: 1552 → 1563 (+11). New typed-error variant:
  `DynamicDispatchViolation` with `DynamicDispatchViolation
  Reason` closed enum (sub-reasons: `DynamicFieldNotOptedIn`,
  `DynamicObjectFieldNotOptedIn`). AdamantValidationError
  variant count: 64 → 65 (+1). Public closed enums: 9 → 10
  (+1; `DynamicDispatchViolationReason`). Implements
  whitepaper §6.2.1.6 Rule 6: modules calling
  `0x2::dynamic_field::*` or `0x2::dynamic_object_field::*`
  must opt in via the `b"adamant.allows_dynamic"` metadata
  entry with value `true`. Adamant-native pre-resolved
  constants: `FORBIDDEN_ADDRESS` (const Address-as-32-bytes
  with byte 31 = 0x02; Q3 empirically resolved at impl-
  gate that `Address::from_bytes` IS const-stable);
  `FORBIDDEN_DYNAMIC_FIELD` and
  `FORBIDDEN_DYNAMIC_OBJECT_FIELD` `&'static str` consts;
  `DYNAMIC_OPTIN_METADATA_KEY = b"adamant.allows_dynamic"`.
  Pass logic: short-circuit accept if metadata carries the
  opt-in entry with BCS-decoded `true`; otherwise iterate
  function bodies, for each `Call`/`CallGeneric` resolve
  target FunctionHandle's module to `(address, name)`, if
  matches a forbidden pair reject with the appropriate
  sub-reason. Missing/false/malformed opt-in payload all
  default to disallow per spec text. **1st instance of
  spec-text-pinned-constant-with-Adamant-native-ownership
  pattern** (NEW; per Q2 refinement at E-3 plan-gate).
  Distinct from E-1b's
  upstream-constant-duplication-with-test-time-parity-pin
  pattern: E-1b pins to Sui upstream; E-3 pins to
  whitepaper spec text. Both share Adamant-native ownership
  discipline; differ in pinning authority. Pattern-cluster:
  Adamant-native constants now have two empirical sub-
  classifications. **1st instance of Adamant-spec-text-
  parity-test discipline** (NEW; the
  `adamant_native_constants_match_spec_text` test pins all
  four constants against §6.2.1.6 line 485 spec text).
  **1st instance of trigger-condition-boundary defensive-
  testing sub-pattern** (NEW; two boundary tests
  `call_to_dynamic_field_at_wrong_address_accepts` and
  `call_to_other_module_at_0x2_accepts` verify the trigger
  requires BOTH address=0x2 AND module name match).

- **2026-05-09 (Phase 5/5b.5 E-4 closure: Rule 7 —
  privacy-circuit instructions in shielded context only):**
  Single sub-checkpoint commit (`f7e6189`). ~720 net
  inserts; 13 new tests in
  `validator/rule_07_privacy_circuit_in_shielded_only.rs::tests`.
  adamant-vm crate test count: 860 → 873 (+13). Workspace
  test count: 1563 → 1576 (+13). New typed-error variant:
  `PrivacyCircuitContextViolation` with
  `PrivacyCircuitContextViolationReason` closed enum (4
  sub-reasons; one per restricted Adamant extension).
  AdamantValidationError variant count: 65 → 66 (+1).
  Public closed enums: 10 → 11 (+1;
  `PrivacyCircuitContextViolationReason`; naming honored
  Q3 refinement at E-4 plan-gate to follow canonical
  `<X>Violation` + `<X>ViolationReason` shape). Implements
  whitepaper §6.2.1.6 Rule 7: `GenerateProof` /
  `VerifyProof` / `RecursiveVerify` / `ReleaseSubViewKey`
  may appear only in shielded-reachable code. Walker walks
  only `#[transparent]` public functions per Q2(b) at E-4
  plan-gate (walk-set-filter-at-entry sub-classification of
  call-graph walker pattern); `#[shielded]` publics are
  permitted to reach privacy-circuit instructions. Reuses
  D-5c's `call_target_handle` helper — **5th instance of
  spec-text-DIRECTS-shared-helper canonical principle
  (cross-scope-reuse sub-shape 2nd instance; rule-of-three
  pending)**. Resolves only internal call edges; cross-
  module call edges NOT walked per Q6 disposition (transitive
  coverage via Rule 3 cross-module + Rule 7 single-module
  composition). **1st instance of rule-composition-for-
  cross-module-coverage methodology pattern** (NEW; per Q6
  disposition at E-4 plan-gate; registered in BOTH walker
  preamble AND PROVENANCE.md per the code-and-PROVENANCE.md
  registration sub-shape). **1st instance of code-and-
  PROVENANCE.md methodology-pattern-registration sub-
  shape** (NEW; vs PROVENANCE.md-only registration used
  for most patterns). **2nd instance of trigger-condition-
  boundary defensive-testing sub-pattern**
  (`mixed_modes_only_transparent_walked` boundary test on
  walk-set filter). **Helper-extraction discipline sub-
  shape α complexity-reduction qualifier 1st instance
  registered** (NEW; per Q1 disposition at E-4 plan-gate;
  refines sub-shape α from "mechanical extract at N=2" to
  "evaluate-extraction-at-N=2"; D-5c walker ported to E-4
  walker with state-threading difference rather than
  refactored to closure-typed predicate API). **Call-graph
  walker pattern sub-classifications registered** (NEW;
  per-walk-state-determines-reject for D-5c carrying
  `caller_mode` state, vs walk-set-filter-at-entry for
  E-4 filtering walk-set to `#[transparent]` publics).

- **2026-05-09 (Phase 5/5b.5 E-5 closure: Rule 8 —
  bounded loops architectural-position pin):** Single sub-
  checkpoint commit (`4764be3`). ~195 net inserts; 1 new
  pin test in `validator/rule_08_bounded_loops.rs::tests`.
  adamant-vm crate test count: 873 → 874 (+1). Workspace
  test count: 1576 → 1577 (+1). **No new typed-error
  variants; no step-5 invocation in `verify_module`** —
  Rule 8 is verifier-level no-op per §6.2.1.6 amendment
  804d9db; runtime gas-budget per §6.2.4 carries the
  determinism binding. AdamantValidationError variant
  count: 66 (unchanged from E-4). The pin module exists
  as documentation + test surface only; the lack of a
  `verify(&module)` function call is the canonical
  implementation of "verifier-level check is a no-op".
  Pin test (`unbounded_self_loop_module_accepts_at_deploy_time`)
  constructs a module with `Branch(0)` self-loop body +
  mandatory mutability metadata + valid VERSION_MAX, and
  asserts `verify_module` returns Ok. **1st instance of
  architectural-position-pin-for-explicit-non-enforcement
  methodology pattern** (NEW; per Q5 disposition at E-5
  plan-gate; renamed from initial framing per Q5 naming
  refinement). Distinct from spec-text-DIRECTS-shared-
  helper (about reuse) and rule-composition-for-cross-
  module-coverage (about transitive coverage); this
  pattern is about explicit non-enforcement at the
  verifier layer. Three patterns now operating across
  distinct architectural-decision domains. **2nd instance
  of code-and-PROVENANCE.md methodology-pattern-
  registration sub-shape** (after E-4's rule-composition-
  for-cross-module-coverage). **1st instance of variant-
  count-via-no-op sub-shape** (NEW; per Q4 disposition at
  E-5 plan-gate). Variant-count discipline now has three
  empirical sub-shapes: variant-count-via-add (most rule
  sub-arcs); variant-count-via-tear-out (E-1a SuiVerifier
  removal); variant-count-via-no-op (E-5 architectural-
  position pin). **1st instance of architectural-position-
  confirmation testing test-shape pattern** (NEW; test
  asserts verifier accepts what spec mandates non-
  enforcement of). Distinct from trigger-condition-
  boundary defensive-testing (different mechanical shapes;
  same methodology-positive defensive-testing core
  discipline). **1st instance of defensive-fixture-
  isolation pattern** (NEW; pin test fixture includes
  mandatory mutability metadata + VERSION_MAX so other
  rules don't pre-empt Rule 8 acceptance assertion).

- **2026-05-09 (Phase 5/5b.5 E-6 closure: Open Layer B
  gaps closure):** Single sub-checkpoint commit
  (`eb766b8`). ~263 net inserts (281 inserts; 18
  deletions); 8 new tests (7 BorrowViolationReason
  negative-path tests in `validator/function_pass/reference_safety/pass.rs::tests`
  + 1 `st_loc_destroys_non_drop` Layer B parity test in
  `validator/function_pass/locals_safety/mod.rs::tests`).
  adamant-vm crate test count: 874 → 882 (+8). Workspace
  test count: 1577 → 1585 (+8). No new typed-error
  variants; no new closed enums. AdamantValidationError
  variant count: 66 (unchanged from E-5; variant-count-
  via-coverage-expansion sub-shape 1st instance). Public
  closed enums: 11 (unchanged). **Empirical-scope-
  inventory correction at E-6 impl-gate**: plan-gate
  framing said "6 of 13 BorrowViolationReason sub-reasons
  deferred" but empirical grep at impl-gate found 7 of 13
  (`ReadRefHasMutableBorrow` was also deferred — D-5b.2's
  original "6 of 13" comment was off-by-one). Closed all
  7 deferred + 1 `st_loc_destroys_non_drop` = 8 new
  tests. **3rd instance of running-total drift discipline
  (rule-of-three threshold MET at E-6).** Pattern instances:
  B-6 → C-1/C-2/C-3 propagation (variant-count baseline);
  D-3 → D-4-through-D-6 propagation (workspace-test-count
  drift); D-5b.2 → D-7b → E-6 propagation (BorrowViolationReason
  sub-reason-count off-by-one). Pattern stable across
  count types, discovery venues, and workstream contexts;
  operates as cross-cutting canonical principle alongside
  verbatim-survey-at-plan-gate-prevents-scope-error
  pattern. **1st instance of gap-fill closure sub-shape
  of Open Layer B gaps closure pattern** (NEW; per Q1
  disposition at E-6 plan-gate). Two empirical sub-shapes
  now: gap-source-removal (E-1a SuiVerifier; bridge tear-
  out retires gap by removing what needed Layer B parity)
  + gap-fill (E-6; fixture construction closes gap). Each
  fixture uses the cp_loc-of-mutable-reference pattern
  (mirrors D-5b.2's
  borrow_field_with_outstanding_full_borrow_rejected) to
  create aliased &mut references on the stack — when the
  targeted instruction operates on one alias,
  is_writable / is_readable / is_freezable returns false
  because the source has another outstanding mutable
  borrow. **Plan-incremental-disposition sub-pattern β
  closure-phase 2nd instance** (after D-5a.0 → D-5a.1.b
  TypeMismatchReason audit closure; here at D-5b.2 → E-6
  BorrowViolationReason audit closure). **1st instance of
  variant-count-via-coverage-expansion sub-shape** (NEW;
  per Q4 disposition at E-6 plan-gate). Variant-count
  discipline now has four empirical sub-shapes (add /
  tear-out / no-op / coverage-expansion). **1st instance
  of coverage-deferred-gap-closure sub-shape of variant-
  vs-test mapping audit principle** (NEW; per Q2
  disposition). Three empirical sub-shapes now: coverage-
  baseline-establishment (C-3 origin); coverage-
  retroactive-audit (C-5 + D-7b); coverage-deferred-gap-
  closure (E-6). **1st instance of test-placement public-
  API-boundary-canonical-for-audit-purposes sub-shape**
  (NEW; per Q3 disposition). **1st instance of sub-shape
  2 (pre-arc-split) empirical-substantiality qualifier**
  (NEW; per Q5 disposition; E-6 has 8 components but
  bundled because methodology shape is uniform).
  BorrowViolationReason variant-vs-test mapping audit
  closes cleanly: all 13 sub-reasons have explicit
  negative-test coverage post-E-6.

- **2026-05-09 (Phase 5/5b.5 E-7 closure: Phase 5/5b.5
  closes; Phase 5/5b cumulative closure):** Documentation-
  only sub-checkpoint. No functional source-code changes
  beyond `validator/mod.rs` preamble update for Rule 5 /
  Rule 8 venue clarifications (deferred from E-5 per Q3
  disposition); tests unchanged at 1585. PROVENANCE.md
  updates batch the Phase 5/5b.5 per-sub-arc closure
  entries (E-1 through E-6 above) plus the Phase 5/5b.5
  methodology accumulation streams section, the E-1b
  lib-count baseline corrigendum, the variant-vs-test
  mapping audit appendix for the 3 new variants since
  D-7b + 1 removed-variant closure-of-record note for
  SuiVerifier, the Phase 5/5b cumulative closure section,
  and updates to existing thematic sections. CLAUDE.md
  state-bump for Phase 5/5b.5 closure + Phase 5/5b
  cumulative closure lands in the same commit per the
  deferred-to-phase-closure pattern (B-6 / C-5 / D-7b
  precedents).

  **Sub-arc delta (E-7 alone):** 1 functional source-code
  change (`validator/mod.rs` preamble doc-cleanup);
  documentation-only otherwise; tests unchanged at 1585;
  ~2500-4500 LOC of net edits to PROVENANCE.md +
  CLAUDE.md (largest single documentation closure batch
  in the project's history).

  **Cumulative phase delta (Phase 5/5b.5, E-1a through
  E-7):** 7 sub-arcs (E-1 split into E-1a/E-1b; E-2 split
  into E-2a/E-2b; E-3, E-4, E-5, E-6, E-7 each single).
  **9 commits on origin** (E-1a `0b774a3`; E-1b `4fb4114`;
  E-2a `8e4d814`; E-2b `4e5bbab`; E-3 `922d4bd`; E-4
  `f7e6189`; E-5 `4764be3`; E-6 `eb766b8`; E-7 closure
  commit lands with this state-bump). Workspace test
  count progression: **1532 → 1585 (+53)**.
  AdamantValidationError progression: **64 → 66 (+2 net;
  -1 SuiVerifier removed at E-1a + 3 added: CrossModulePrivacyConsistencyViolation
  E-2a / DynamicDispatchViolation E-3 /
  PrivacyCircuitContextViolation E-4)**. **2 new public
  closed enums:** `DynamicDispatchViolationReason` (E-3),
  `PrivacyCircuitContextViolationReason` (E-4) — bringing
  the cumulative public closed-enum count to **11
  total** (HandleKind, DefKind, InvalidSignatureReason,
  IrreducibleReason, TypeMismatchReason, BorrowViolation
  Reason, PrivacyConsistencyViolationReason,
  DynamicDispatchViolationReason,
  PrivacyCircuitContextViolationReason, FieldOwnerKind,
  MalformedConstantReason). **3 verification gates fired**
  during Phase 5/5b.5: 12th at E-2 plan-gate (§6.2.1.6
  line 477 cross-module Rule 3); 13th at E-3 plan-gate
  (§6.2.1.6 Rule 6 + line 485); 14th at E-4 plan-gate
  (§6.2.1.6 Rule 7); 15th at E-5 plan-gate (§6.2.1.6
  Rule 8 + amendment 804d9db). Total cumulative
  verification gates 11 → 15 (+4). **Production-side Sui
  dependency complete elimination at E-1.** adamant-vm
  production-binary dependency graph contains zero
  `move-*` crates per the §6.2.1.8 resistant-proof
  posture; build-system independence check at
  `tests/no_sui_in_production_deps.rs` mechanically
  enforces the architectural commitment. **5 per-Adamant-
  rule modules** finalized at Phase 5/5b.5: Rules 1, 2,
  3 (single-module), 4 from prior phases; Rules 6, 7
  added at E-3 / E-4; Rule 8 architectural-position pin
  at E-5; Rule 5 enforced at parse-time inside
  adamant_deserialize. Plus cross-module Rule 3 at
  `validator/cross_module/` (E-2; production caller
  awaiting Phase 5/6 AVM runtime stdlib). **Methodology
  patterns formalized at E-7** (full enumeration in the
  Phase 5/5b.5 closure methodology accumulation streams
  section below): rule-of-three thresholds met across the
  phase for running-total drift discipline (3 instances
  at E-6 + 4th instance at E-7 session-resume); spec-
  text-DIRECTS-shared-helper canonical principle (5
  instances total: 3 cross-pass-distinct + 2 cross-scope-
  reuse); verbatim-survey-at-plan-gate-prevents-scope-
  error pattern (8 instances; pattern stable beyond
  threshold). Plus ~25 new patterns / sub-shapes /
  refinements registered at sub-rule-of-three threshold
  for forward-tracking. **Cross-cutting canonical
  principles operating beyond rule-of-three threshold:**
  verbatim-survey-at-plan-gate-prevents-scope-error;
  running-total drift discipline; spec-text-DIRECTS-
  shared-helper; eager-error first-failure-wins;
  variant-vs-test mapping audit principle. Phase 5/5b.5
  closes; **Phase 5/5b CLOSED** with all 6 sub-arcs done
  (5/5b.1a + 5/5b.1b + 5/5b.2 + 5/5b.3 + 5/5b.4 +
  5/5b.5).

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

## Phase 5/5b.4 closure — methodology accumulation streams

The methodology streams formalized at D-7b closure. Each
extends the canonical methodology catalog above for future
phase inheritance (5/5b.5 and beyond). Numbering continues
from the Phase 5/5b.3 closure stream count (which ended at
7) — this section opens at (8). Streams below the rule-of-
three threshold are registered with current instance count;
streams meeting the rule-of-three threshold are registered
canonically with all instances enumerated.

### (8) Empirical-complexity-drives-sub-checkpoint-shape sub-shape 2 (NEW; rule-of-three threshold met)

**Rule-of-three threshold met across the phase.** Sub-shape 2
of empirical-complexity-drives-sub-checkpoint-shape is **pre-
arc-split**: at the sub-arc-level plan-gate, the implementation
plan splits the sub-arc into N sub-checkpoints rather than
landing as a single commit. Sub-shape 1 (intra-sub-checkpoint-
split, e.g., C-1.4 → C-1.4a + C-1.4b) was registered at
Phase 5/5b.3.

Three empirical instances of sub-shape 2:

1. **C-1 split into 5 sub-checkpoints** (C-1.1 → C-1.4b) at
   the C-1 plan-gate (Phase 5/5b.3). Total impl ~4,547 LOC
   exceeded the cognitive-review threshold; pre-arc-split
   surfaced at plan-gate.
2. **D-1 split into D-1a + D-1b** (Phase 5/5b.4) at the D-1
   plan-gate. Foundation-then-producer arc; CFG construction
   foundation (D-1a) before AbstractInterpreter framework
   (D-1b) per implementation-core-vs-total-LOC discipline.
3. **D-5a split into D-5a.0 + D-5a.1.a + D-5a.1.b** (Phase
   5/5b.4) at the D-5a plan-gate. Type-safety pass split
   into foundation (AbstractStack + TypeMismatchReason),
   first half inherited arms, and remaining arms +
   extensions + orchestration — each exceeded ~600 LOC
   independently.

**Sub-shape 2 4th instance** (already past rule-of-three at
this point): D-5b split into D-5b.1 + D-5b.2 (Phase 5/5b.4)
at the D-5b plan-gate. Borrow-graph foundation port (D-5b.1)
before reference-safety pass + extensions + orchestration
(D-5b.2). Confirms sub-shape 2 as load-bearing methodology.

**Pattern scope:** sub-shape 2 fires at sub-arc-level plan-
gates when total estimated impl exceeds ~1,000-1,500 LOC AND
the sub-arc admits a foundation-then-producer or per-aspect
decomposition. Future plan-gates pre-emptively assess the
estimated total and surface the split decision at plan-gate
discovery.

### (9) Adamant-extension treatment in module-level passes — sub-shape 3 (rule-of-three threshold met)

Sub-shape 3 of the Adamant-extension treatment pattern (which
itself reached rule-of-three at Phase 5/5b.3 closure across
sub-shapes 1/2/3) is **pass iterates function bodies, no
extensions need handling at this layer — all pass through**.

Sub-shape 3 specifically reaches rule-of-three across:

1. **C-3 SignatureChecker** (Phase 5/5b.3): per §6.2.1.4 the
   17 extensions either don't carry generic type-arguments
   at bytecode operand level or are zero-operand; signature
   checker passes through.
2. **D-1a CFG construction** (Phase 5/5b.4): extensions don't
   branch (`is_unconditional_branch` returns `false` for
   `Adamant(_)`); CFG construction passes through.
3. **D-2 control-flow validation** (Phase 5/5b.4): extensions
   are non-branching, so a function ending in an Adamant
   extension is rejected by the fall-through check
   (correctly — extensions don't terminate).
4. **D-4 locals-safety** (Phase 5/5b.4): extensions don't
   read/write/borrow locals; pass through.

Sub-shape 3 is the dominant Adamant-extension treatment at
the per-function-pass layer. Future per-function passes
default to this sub-shape unless the §6.2.1.4 verbatim
survey at plan-gate surfaces an extension-specific arm.

### (10) Spec-text-DIRECTS-shared-helper canonical principle (NEW; rule-of-three threshold met)

When the §6.2.1.4 / §6.2.1.6 spec text **directly prescribes**
that a per-extension or per-rule check reuses an inherited
helper rather than introducing a new one, Adamant's
implementation reuses the helper verbatim per the spec
prescription. The principle is distinguishing because it
inverts the default: normally a new check warrants a new
helper; here the spec text is the binding driver toward
reuse.

Three empirical instances:

1. **D-5a.1.b type-safety**: `InvokeShielded` and
   `InvokeTransparent` reuse the inherited `call` type-
   safety helper per §6.2.1.4 line 408 verbatim. Spec text:
   "InvokeShielded(FH) — same shape as Call per
   FunctionHandle resolution."
2. **D-5b.2 reference-safety**: `InvokeShielded` and
   `InvokeTransparent` reuse the inherited `call` reference-
   safety shape per §6.2.1.6 lines 540-545 verbatim.
3. **D-5c privacy-consistency**: the call-graph walker over
   function-call bytecodes reuses the
   `call_target_handle` shape directly prescribed by Rule 3
   spec text (the walk over function-call bytecodes IS what
   Rule 3 says to do).

**Pattern scope:** future per-pass implementations facing
`InvokeShielded` / `InvokeTransparent` extensions, or any
extension that §6.2.1.4 / §6.2.1.6 spec-text-binds to an
inherited shape, default to spec-prescribed reuse. The §6.2.1.4
verbatim re-paste at plan-gate surfaces these prescriptions
empirically (see (12) below).

### (11) Shielding-vs-runtime canonical pattern (NEW; rule-of-three threshold met)

Adamant has a deploy-time vs runtime distinction that
upstream Sui doesn't carry: deploy-time validation may
fail-open on properties that the runtime carries the binding
for. The canonical instance shape: a per-extension rule has
its enforcement point at runtime (gas, circuit verification,
recursive proof verification), not at deploy-time. The
verifier accepts at deploy-time as a fail-open posture; the
runtime carries the consensus-binding enforcement.

Three empirical instances:

1. **D-3 stack_usage** Categories C + D fail-open: per
   §6.2.1.4 lines 410-411 + line 423,
   `GenerateProof(CircuitId)`, `VerifyProof(CircuitId)`, and
   `RecursiveVerify` are parametric-in-circuit-signatures-
   resolved-at-runtime. Verifier ships `(0, 0)` stack-effect
   pin; runtime computes the actual effect from circuit
   parameters per §7 (when §7 lands).
2. **D-5a.1.b type-safety** Categories C + D fail-open: per
   the same §6.2.1.4 references, type rules for the
   circuit-parametric extensions defer to runtime. Verifier
   ships pass-through type rules; runtime carries the
   binding.
3. **D-5b.2 reference-safety** Categories C + D fail-open:
   reference-safety rules for the circuit-parametric
   extensions defer to runtime under the same shielding-vs-
   runtime posture.

**Cross-pass consistency:** the Categories C + D treatment is
consistent across stack_usage / type_safety / reference_safety
— the same set of 3 extensions
(GenerateProof / VerifyProof / RecursiveVerify) are deferred
to runtime in identical terms by all three passes.

**Pattern scope:** future per-pass implementations facing
parametric-in-runtime-resolution extensions default to the
shielding-vs-runtime fail-open posture. The §6.2.1.4 / §6.2.1.6
verbatim re-paste at plan-gate is the empirical anchor for
the Categories C + D classification.

### (12) Verbatim-survey-at-plan-gate-prevents-scope-error pattern (NEW; rule-of-three threshold met)

The discipline of verbatim re-pasting the relevant whitepaper
section at plan-gate (rather than relying on memory or
inference) catches scope errors before they propagate into
implementation. The cost of a verbatim re-paste at plan-gate
is small (~5-10 minutes); the cost of an unsurfaced scope
error is much higher (re-implementation at impl-gate).

Three empirical instances:

1. **D-3 plan-gate** §6.2.1.4 per-extension stack-effect
   verbatim survey: partitioned the 17 Adamant extensions
   into Categories A (12 static) / B (2 parametric-FH) /
   C (2 deferred-§7) / D (1 deferred-§8.5). Without the
   verbatim survey, Category B / C / D miscategorization at
   impl time was likely.
2. **D-5b plan-gate** §6.2.1.6 reference-safety + regex
   verbatim re-paste: surfaced the borrow-graph
   reference-safety rule shape and the regex-borrow-graph
   sanity-check shape. Without the re-paste,
   `regex_reference_safety` would have been miscategorized
   as a separate pass requiring its own implementation
   rather than a sanity-check sub-mode of the main
   reference-safety pass.
3. **D-5c plan-gate** §6.2.1.6 Rules 3-5 verbatim re-paste:
   discovered that Rule 4 (no native functions) was already
   implemented at validator/mod.rs step 5 and Rule 5 (no
   global storage) was already enforced at validator/mod.rs
   step 1 via `adamant_deserialize`'s strict mode.
   D-5c's scope was reduced from "Rules 3, 4, 5" to "Rule 3
   only" at plan-gate, avoiding double-implementation.

**Pattern scope:** all future plan-gates verbatim re-paste
the relevant §6.2.1.X spec section before locking dispositions.
Verification gates fired in corrective mode (10th at D-3;
11th at D-5c) are the empirical signal that the verbatim
survey caught a scope error.

### (13) Open Layer B gaps deferred to pre-mainnet hardening (NEW; rule-of-three threshold met at D-7b)

Layer B parity tests for specific Adamant rules may be
deferred when the cross-validation fixture-construction
overhead exceeds sub-checkpoint scope. The deferred-rule
still has Layer A direct unit-test coverage; Sui-side
coverage lives in upstream's own test suite. The Layer B
parity gap is registered as a forward-tracking carry-forward
to pre-mainnet hardening (or to a natural resolution venue
like Sui-bridge tear-out at 5/5b.5).

Three empirical instances:

1. **`SuiVerifier` audit gap** (registered at C-5; deferred
   to natural resolution at 5/5b.5 Sui-verifier-bridge tear-
   out). When the bridge is removed, the `SuiVerifier`
   variant is no longer reachable from any consensus-critical
   path and can be removed from `AdamantValidationError`
   entirely. The transitional gap during Phase 5/5b.4 is
   acceptable per the C-5 disposition (defense-in-depth
   redundancy with the now-complete Adamant-native step-3
   batch).
2. **BorrowViolationReason 6 of 13 sub-reasons** (registered
   at D-5b.2; deferred to pre-mainnet hardening). D-6
   integration tests cover end-to-end pipeline but don't
   backfill the multi-block CFG aliasing fixtures needed
   for these specific sub-reasons. Pre-mainnet hardening is
   the resolution venue.
3. **`st_loc_destroys_non_drop` rule parity** (registered
   at D-7a; deferred to pre-mainnet hardening). Cross-
   validation fixture needs two non-drop value sources (one
   to populate the local, another to trigger the destroy
   attempt), exceeding D-7a's fixture-construction scope.
   Adamant's Layer A
   `stloc_to_available_no_drop_local_rejected` covers the
   rule directly.

**Pattern scope:** future per-pass Layer B coverage gaps
follow the same disposition shape — register the gap with
the rule under coverage, the Layer A pin, and the resolution
venue (pre-mainnet hardening or natural resolution). Cross-
references to plan-incremental-disposition sub-pattern β
(deliberate-deferral) in place: instances 1 / 2 / 3 above
are also opening-phase plan-incremental-disposition β
instances.

### (14) Sui-public-API-shape-constrains-parity-helper sub-pattern (NEW; 1st instance at D-7a; rule-of-three pending)

Sui's per-pass entries for `stack_usage_verifier`,
`locals_safety`, and `type_safety` are `pub(crate)` in
upstream — only `control_flow::verify_function` (per-pass)
and `code_unit_verifier::verify_module` (composite) are
publicly reachable from Adamant's test code. Layer B parity
strategy adapts to the Sui-public-API shape:

- **Per-pass parity** when Sui's per-pass entry is `pub`
  (D-2 control_flow direct via Sui's
  `control_flow::verify_function`).
- **Composite-pipeline parity** when Sui's per-pass entry is
  `pub(crate)` (D-3 stack_usage + D-4 locals_safety via
  Sui's `code_unit_verifier::verify_module` with fixtures
  curated to isolate the targeted pass).

**1st instance: D-7a Layer B helper extraction.** Resume-
prompt-staging-discipline: rule-of-three pending at next
per-pass parity attempt with similar API constraint (likely
candidate: Phase 5/5b.5 reference-safety per-pass parity if
Sui's `reference_safety::verify` remains `pub(crate)`).

**Methodology-positive empirical adaptation:** the discipline
holds that vendored Sui crates have byte-faithful preservation
discipline; visibility patches are NOT permitted. The Layer B
parity strategy adapts to the API shape rather than patching
upstream. Composite-level accept/reject parity is sound when
both pipelines run the same passes; fixtures isolate the
targeted pass via type-correct construction.

### (15) Helper-extraction discipline (NEW; rule-of-three pending; canonical pattern with two named sub-shapes)

Shared test helpers for cross-validation parity are extracted
when the per-pass test boilerplate becomes load-bearing. The
trigger-N varies by per-pass fixture-construction-overhead.

**Sub-shape α: extract-at-N=2** (low fixture overhead).
Module-level passes need to construct an `AdamantCompiledModule`
+ run Adamant's pass + run Sui's pass via direct public entry
+ compare. Boilerplate per-test is small (~5-10 lines); N=2
trigger surfaces the helper extraction without premature
abstraction. **Canonical instance: B-2.2 `friends` pass** —
extracted `assert_pass_parity` helper into
`module_pass/mod.rs::test_helpers` once the second pass
duplicated the body.

**Sub-shape β: extract-at-N=3** (high fixture overhead).
Per-function passes need additionally to construct
FunctionContext + AbilityCache + DummyMeter on Sui's side.
Boilerplate per-test is larger (~15-25 lines); the higher
overhead motivates extraction at first reuse. **Canonical
instance: D-7a function_pass test_helpers** — extracted
6 helpers (`to_sui`, `sui_config_from`,
`assert_function_pass_parity`,
`assert_function_pass_parity_vm`, `run_adamant_pipeline`,
`run_sui_code_unit_verifier`) into
`function_pass/test_helpers.rs` at the third backfill
target (D-2 / D-3 / D-4 all needed the shared shape from
inception of their Layer B backfills).

**Pattern naming preserves chronology:** sub-shape α is the
first-observed (B-2.2; module_pass), sub-shape β is the
second-observed (D-7a; function_pass). The trigger-N
varies inversely with per-test boilerplate cost — low
overhead allows extract-at-N=2; high overhead motivates
extract-at-N=3.

**Rule-of-three pending** at next per-pass-helper extraction
candidate (Phase 5/5b.5 reference-safety per-pass parity
helper extraction if it warrants its own helper, or any
new sub-shape with a different trigger-N).

### (16) Honest-scope-flagging at impl-gate sub-pattern (opening + closure phases registered)

Sub-pattern of impl-gate methodology: when an
implementation-gate audit surfaces work that exceeds the
sub-checkpoint's locked scope, the work is honestly deferred
with explicit registration rather than silently absorbed.

**Opening phase** (declaration of deferral at the
sub-checkpoint commit message):

1. **D-5a.1.a chained-orchestration deferral** (Phase
   5/5b.4): type-safety pass core landed but the
   orchestration chain wiring deferred to D-5a.1.b.
   Honestly flagged at D-5a.1.a commit; closed at D-5a.1.b.

**Closure phase** (the deferred work landing in a subsequent
sub-checkpoint commit):

1. **D-5a.1.b orchestration chain wired in** (Phase 5/5b.4):
   closes the D-5a.1.a opening-phase deferral.
2. **D-5b.2 reference-safety orchestration** (Phase 5/5b.4):
   closes a similar opening-phase pattern from D-5b.1.

**Pattern scope:** opening + closure phases registered as
canonical sub-pattern at D-7b. **Rule-of-three pending** at
opening phase with one current instance; sub-pattern β
(deliberate-deferral) at the broader plan-incremental-
disposition pattern level (see (13) above) overlaps at
opening phase with 3 instances meeting rule-of-three across
the phase.

**Session-pacing-level invocations** (broader posture, not
per-sub-pattern instances): D-2/D-3/D-4 all flagged Layer B
backfill deferral honestly at sub-checkpoint commit
messages, leading to D-7a's backfill batch — methodology-
positive operation of honest-scope-flagging at the session-
pacing level. 4 invocations total.

### (17) Plan-incremental-disposition sub-patterns (canonical with current instance counts)

**Sub-pattern α: count-resolution.** When a plan-gate
question's count or arity is left ambiguous and resolved
empirically at impl-gate. 2 current instances:

1. **C-3 InvalidSignatureReason 2-vs-3 resolution** (Phase
   5/5b.3): plan-gate left the closed-enum sub-reason count
   ambiguous; empirical impl resolved at 2 sub-reasons
   (`RefInsideContainer | RefAsFieldType`).
2. **D-1a UnreachableBlock empirical elision** (Phase
   5/5b.4): plan-gate framing left UnreachableBlock as a
   potential CFG variant; empirical impl elided it (CFG
   construction reaches all blocks declared by upstream's
   Tarjan-1974 algorithm; UnreachableBlock would be defensive
   redundancy without an empirical use case).

**Sub-pattern β: deliberate-deferral.** When a plan-gate
disposition explicitly defers a sub-component to a later
sub-checkpoint or pre-mainnet hardening. Opening phase:
3 current instances (the three Open Layer B gaps in (13)
above are also β opening instances). Closure phase: 2
current instances (D-5a.1.a → D-5a.1.b chained-
orchestration; D-5b.1 → D-5b.2 reference-safety
orchestration; tracked under (16) honest-scope-flagging
above).

**Rule-of-three pending** for sub-pattern α (2 instances).
Rule-of-three threshold met at opening phase for sub-pattern
β across the three Open Layer B gaps; closure-phase
instances overlap with (16) but represent distinct sub-
pattern phases.

### (18) Empirical-discovery-during-implementation sub-patterns

**Sub-pattern α: test-fixture.** When implementation
discovers a test fixture is needed beyond what plan-gate
anticipated. 2 current instances:

1. **D-7a `module_with_body` address_identifier extension**:
   Layer A `module_with_body` fixture didn't push
   `address_identifiers`; Sui's `module.self_id()`
   dereferences `module_handles[0].address` and panicked.
   Wrapped fixture-extension `add_self_address` resolves.
2. **C-3 SignatureChecker negative-test fixture catch**:
   variant-vs-test mapping audit at C-3 implementation-gate
   caught 2 unmapped variants; coverage closure required
   constructing 2 new test fixtures.

**Sub-pattern β: test-scope.** When implementation discovers
a test scope is needed beyond what plan-gate anticipated.
2 current instances:

1. **D-7a Sui-public-API-shape discovery**: implementation
   discovered Sui's per-pass entries are `pub(crate)`;
   parity strategy adapted from per-pass to composite-
   pipeline for D-3 / D-4.
2. **D-1b walk-back precedent**: implementation discovered
   `needless_pass_by_value` clippy guidance applied to the
   AbstractInterpreter trait surface; walk-back precedent
   held byte-faithful preservation rather than introducing
   Adamant-side deviation.

**Rule-of-three pending** for both sub-patterns.

### (19) Sub-shape 4 of structural-impossibility-checks (NEW; rule-of-three pending)

Sub-shape 4: **`expect()`-three-anchor**. Adamant-side
defensive programming where an `expect()` carries a three-
anchor message documenting why the path can't panic in the
validator pipeline. Used for paths that are structurally
impossible to reach (per cross-pass-pipeline-dependency
guarantees) but where Rust's type system can't prove it
without a runtime check.

1 current instance: **D-5a.1.a `AbsStackError` single-
pop/push paths** — `AbstractStack::pop_any` and
`push_n` return `Result` types upstream; Adamant's per-pass
consumer wraps in `expect()` with three-anchor message
(citing the bounds checker's pre-validation, the cross-pass
ordering, and the structural argument).

**Rule-of-three pending** at next defensive-`expect()`-with-
three-anchor instance.

### (20) Hoisted-enum-for-clippy-items-after-statements pattern (NEW; 1st instance at D-1a)

State-machine enums hoisted to module level to satisfy
`clippy::items_after_statements` while preserving upstream's
state-machine shape. Upstream Sui-Move declares state-machine
enums inline within functions; Rust's `clippy::items_after_statements`
prohibits item declarations following statements; Adamant
hoists the enum to module level.

1 current instance: **D-1a `Exploration` enum** in CFG
construction. Hoisted to module level; preserves upstream's
state-machine shape; satisfies clippy.

**Rule-of-three pending** at next state-machine hoist
instance.

### (21) Upstream-consolidates-undershoot calibration pattern (NEW; 1st instance at D-1b)

When plan-gate framing decomposes upstream's consolidated
implementation into N pieces but upstream is M < N pieces,
impl-core undershoots framing-anticipated estimates by ~30-
50%. Distinct from plan-was-conservative (which is about
estimate-vs-actual variance on the same-shape impl); this
pattern is about decomposition-mismatch.

1 current instance: **D-1b AbstractInterpreter framework**.
Plan-gate framing surfaced AbstractDomain + TransferFunctions
+ AbstractInterpreter as three traits; upstream consolidates
into one trait with associated types. Impl-core undershoots
plan-gate framing anticipation by ~40%.

**Rule-of-three pending** at next decomposition-mismatch
instance.

### (22) Forward-shape-variant-declaration pattern (NEW; 1st instance at D-1)

Foundation-then-producer arcs requiring forward-shape-
variant-declaration must surface the question at plan-gate
with explicit pre-approval, not at implementation-gate as
discovery. Default disposition: declare variants alongside
their first producer per the C-3 variant-vs-test mapping
audit principle.

1 current instance: **D-1 plan-gate Q1 walk-back**. Plan-gate
asked whether infrastructure variants should be declared at
foundation commit or alongside first producer. Walk-back
held the C-3 default (declare-alongside-producer); registered
the question at plan-gate for future foundation-then-
producer arcs.

**Rule-of-three pending** at next foundation-then-producer
arc with forward-shape-variant declaration question.

### (23) Bridge-as-soundness-test-infrastructure framing (NEW; 1st instance at D-6)

The transitional Sui-verifier bridge serves dual roles:
defense-in-depth on inherited-subset modules AND soundness-
test infrastructure for cross-pass-pipeline-dependency drift
detection. If Adamant accepts but Sui rejects on the same
module, the divergence indicates a drift in Adamant's
pipeline.

1 current instance: **D-6 bridge framing**. The bridge was
originally registered as defense-in-depth at B-5; D-6's
empirical observation is that the bridge also functions as a
soundness-test for the now-complete Adamant-native step-3 +
step-4 batch.

**Pattern resolution at 5/5b.5:** when the bridge tears out,
the soundness-test framing is replaced by Layer B cross-
validation tests at the per-pass level. Pattern is bounded
in time (resolves at 5/5b.5).

### (24) Bridge-redundancy-validation tests as Layer B alternative (NEW; 1st instance at D-6)

Tests #5 + #6 in the D-6 integration suite assert that the
bridge and the Adamant-native pipeline produce identical
accept/reject outcomes on inherited-subset modules. Composite-
level Layer B coverage at the full-pipeline boundary;
alternative shape to per-pass Layer B parity tests.

1 current instance: **D-6 tests #5 + #6**. Bridge-redundancy-
validation tests serve as composite-level Layer B coverage
alongside the per-pass Layer B tests added at D-7a.

**Pattern scope:** bounded in time (resolves at 5/5b.5
bridge tear-out, like (23) above).

### (25) 4th-precedence-claim-retired-via-empirical-absence sub-pattern (NEW; 1st instance at D-6)

Sub-pattern of cross-pass eager-error precedence: an
anticipated precedence claim doesn't fire empirically because
the constructable fixture exceeds practical bounds. The
claim is retired-via-empirical-absence rather than
retired-via-fulfillment.

1 current instance: **D-6 plan-gate Q4 retired**.
BoundsChecker `IndexOutOfBounds` vs limits' overflow
precedence claim deferred per integration-test depth
limitation (constructing 1001 function_defs is impractical).
The claim doesn't fire; cross-pass precedence list stays
at 3 instances rather than reaching 4.

Distinct from spec-pipeline-impossibility-pending-port
sub-pattern (retired-via-fulfillment when the upstream Sui
pass landed); this is retired-via-empirical-absence.

**Rule-of-three pending** at next anticipated-but-empirically-
absent precedence claim. **Promoted from pending follow-up
to active workstream item:** the test-only
`AdamantVerifierConfig::with_structural_limits` builder is
the natural unblocking mechanism (register from B-5 + C-4 as
two-instance precedent for the builder workstream;
fulfillment at the builder lands closes the limitation).

### (26) Implementation-adjacent doc-cleanup pattern (NEW; 1st instance at D-6 with 2 sub-shapes)

When implementation lands an architectural change, related
documentation cleanup may be applied either adjacent to the
change (inline with the same commit) or batched at a later
closure commit. Two sub-shapes:

**Sub-shape α: adjacent.** Doc-cleanup applied inline with
the architectural change. **D-6 Q6(a)**: step-5 comment
"Rules 3, 6, 7 land in subsequent sub-arcs" updated to
"Rules 6 and 7 land in subsequent sub-arcs" inline with
D-6's wiring change (Rule 3 had just landed at D-5c).

**Sub-shape β: batch.** Doc-cleanup deferred to a closure-
batch commit. **D-6 Q6(b)**: function_pass/mod.rs comment
"Rule 4 (no native functions) lands at D-5" deferred to
D-7b closure batch. (Closed at D-7b: see Phase A of D-7b
implementation; comment updated to reflect Rule 4's actual
location at validator/mod.rs:336.)

**Rule-of-three pending** at next implementation-adjacent
doc-cleanup instance with both sub-shapes.

### (27) Per-mechanism counting discipline (canonical at D-7b)

Multiple applications across Phase 5/5b.4 of a discipline:
when a sub-checkpoint adds N typed variants alongside their
producer, the variant count delta is reported per-sub-
checkpoint without inheriting prior counts. Avoids the
running-total drift that B-6 / D-3-to-D-4 instances
produced.

Applications across the phase:

- **D-3 deferred-to-§N footnotes**: Categories C + D fail-
  open per-extension classifications were registered with
  per-extension `→ §7` / `→ §8.5` deferral footnotes,
  empirically counted at the §6.2.1.4 verbatim re-paste.
- **D-5a.1.a 10-deprecated-opcodes consolidation**: the 10
  deprecated global-storage opcodes folded into one
  `unreachable!` arm with consolidated empirical count;
  the consolidated arm references B-2.4's parallel pattern
  + cross-references to the deserializer-side rejection
  per §6.2.1.6 Rule 5.
- **D-5a.1.b expect()-three-anchor continued use**:
  consistent application of sub-shape 4
  (`expect()`-three-anchor) across multiple call sites
  with per-mechanism count = 1 each (rather than batching
  into a multi-instance count).

**Pattern scope:** future sub-checkpoints apply per-mechanism
counting at variant additions, helper extractions, deferral
registrations.

### (28) Citation-precision discipline (canonical at D-7b)

Multiple levels of citation precision applied across Phase
5/5b.4:

**Level 1: running totals.** B-6 / D-3-to-D-4 corrigenda are
the canonical empirical-grep-confirmation discipline at
phase closure (registered at C-5 as section (7); reaffirmed
at D-7b as section (8) below — second instance of the
discipline operating).

**Level 2: citations.** D-4's citation of B-2.3 for the
`AdamantAbilityCache` consumer pattern; the citation pin is
explicit at the D-4 commit and verified at D-7b PROVENANCE
review.

**Level 3: canonical-principle-naming.** D-5c's
`spec-text-DIRECTS-shared-helper` registration uses uppercase
`DIRECTS` to distinguish from the broader
`spec-text-prescribes-shared-helper` shape (which is more
permissive); the precise naming distinguishes the principle
from its broader analogue.

**Pattern scope:** future canonical registrations apply
citation precision at all three levels — running totals
empirically grep-confirmed at phase closure; per-instance
citations explicit at sub-checkpoint commits; canonical-
principle naming chosen for distinguishing precision.

### (29) Commit-message running-total drift discipline (2nd instance at D-7b)

Second instance of the C-5-registered running-total drift
discipline. The D-3-to-D-4 baseline error inherited a wrong
workspace test count through 8 commits (D-4 → D-5a.0 →
D-5a.1.a → D-5a.1.b → D-5b.1 → D-5b.2 → D-5c → D-6) before
the D-7 plan-gate empirical grep caught it.

Per-commit drift trajectory and corrigendum: see "Corrigendum:
D-3-to-D-4 baseline error in commit-message running totals"
section near the end of this file.

**Pattern reaches 2 instances** at D-7b. Rule-of-three
pending at next phase closure where the empirical-grep
discipline catches another running-total drift instance.
**Methodology-positive empirical operation:** D-7 plan-gate
caught the drift before D-7b documentation inherited the
wrong baseline; second methodology-positive operation of
the C-5-registered discipline. **Pattern reaches 3
instances and rule-of-three threshold MET at E-6** when
the BorrowViolationReason sub-reason-count off-by-one was
caught at E-6 impl-gate empirical grep (D-5b.2's "6 of 13"
framing empirically corrected to "7 of 13"). **Pattern
reaches 4 instances at E-7 session-resume** when the
adamant-vm lib-count drift originating at E-1b was caught
at E-7 session-resume empirical verification (claimed lib
830 unchanged; empirical 831 — propagated through 7
subsequent commits). See "Corrigendum: E-1b lib-count
baseline drift" section near the end of this file for the
per-commit reconstruction.

## Phase 5/5b.5 closure — methodology accumulation streams

The methodology streams formalized at E-7 closure across
the 7 sub-arcs of Phase 5/5b.5 (E-1 through E-7). Each
below extends the canonical methodology catalog above for
future phase inheritance (5/5c, 5/6, future
implementation work). Numbering continues from Phase
5/5b.4 closure stream count (which ended at 29) — this
section opens at (30).

### (30) Architectural-commitment-mechanically-guarded pattern (NEW; 1st instance at E-1b)

When a constitutional / spec-level architectural commitment
exists, mechanical assertion at the build-system level
prevents architectural drift even if per-source-file
vigilance lapses. The mechanical guardrail makes the
commitment robust against future drift in a way that
documentation alone cannot.

1st instance at E-1b: `tests/no_sui_in_production_deps.rs`
walks `cargo metadata`'s resolve graph and asserts no
`move-*` crate appears in `adamant-vm`'s production
dependency graph. The build-system check is the mechanical
guardrail for §6.2.1.8's resistant-proof posture
commitment ("vendored Sui-Move crates appear only at test
time; production-binary dependency graph contains zero
move-* crates"). Constitutionally meaningful posture —
parallel shape to "no foundation, no admin keys, no
upgrade authority after genesis" commitments in the
whitepaper; mechanical guardrails make commitments robust
against future drift.

Sanity-check empirically performed at E-1b: temporarily
reintroduced `move-vm-config` to `[dependencies]`,
confirmed the test fires with the offending crate names
enumerated, then reverted. **1st instance of test-actually-
fires-on-regression sanity-check methodology shape**
registered alongside this pattern.

Rule-of-three pending. Future build-system checks at
analogous architectural-commitment boundaries (e.g., a
hypothetical genesis-state-immutability check at Phase 5/6
or Phase 5/5c) would inherit the pattern shape.

### (31) Upstream-constant-duplication-with-test-time-parity-pin pattern (NEW; 1st instance at E-1b)

Adamant-native constants duplicate Sui upstream values
(test-time parity pin asserts upstream agreement);
production code references Adamant-native constants
exclusively (no Sui dependency in production graph).
Methodology-positive shape: protects against accidental
drift while making deliberate divergence visible.

1st instance at E-1b: 3 constants duplicated from
`move_vm_config::verifier`:

- `DEFAULT_MAX_VARIANTS = 127`
- `DEFAULT_MAX_CONSTANT_VECTOR_LEN = 1024 * 1024` (1 MiB)
- `DEFAULT_MAX_IDENTIFIER_LENGTH = 128`

The `adamant_structural_limits_constants_match_sui_upstream`
test pins parity. If Adamant chooses to deviate from Sui
upstream, the parity pin fires and forces explicit
deliberate-Adamant-decision registration.

Pattern-cluster: Adamant-native constants now have two
empirical sub-classifications operating across distinct
artifact-types:

- **Sui-upstream-parity-pinned** (E-1b 1st instance;
  pinning authority is Sui upstream tag).
- **Adamant-spec-text-pinned** (E-3 1st instance — see
  stream (33) below; pinning authority is whitepaper
  spec text).

Both share Adamant-native ownership discipline; differ in
pinning authority. Rule-of-three pending across the
broader Adamant-native-constants discipline (which now has
two sub-classifications; one more would meet rule-of-three).

### (32) Same-rule-different-scope-shares-sub-reason-enum pattern (NEW; 1st instance at E-2)

When a rule applies across multiple verifier scopes (e.g.,
single-module + cross-module), Adamant uses two typed
variants but ONE shared closed sub-reason enum. The
diagnostic locus differs (single-module vs cross-module)
but the rule-violation reason discriminator is shared.

1st instance at E-2: `PrivacyConsistencyViolation` (D-5c
single-module) and `CrossModulePrivacyConsistencyViolation`
(E-2a cross-module) share `PrivacyConsistencyViolationReason`'s
2 sub-reasons (`ShieldedReachesInvokeTransparent`,
`TransparentReachesInvokeShielded`).

Distinct from cross-module-error-variant-shape pattern
(E-2 1st instance; about diagnostic-field shape). Same-
rule-different-scope-shares-sub-reason-enum is about
sub-reason enum reuse across scopes. Future shape: if
Phase 5/6 AVM runtime adds a runtime-check variant for
Rule 3 (third scope: deployment-time + runtime), the
sub-reason enum would be reused there too — 2nd instance.
Rule-of-three pending.

### (33) Spec-text-pinned-constant-with-Adamant-native-ownership pattern (NEW; 1st instance at E-3)

Adamant-native constants whose values are pinned by
whitepaper spec text (not Sui upstream). The
test-time parity pin asserts the constants match the spec
text empirically.

1st instance at E-3: 4 constants pinned by §6.2.1.6 line
485:

- `FORBIDDEN_ADDRESS = [0u8; 31, 2u8]` (Sui standard-
  library address `0x2`)
- `FORBIDDEN_DYNAMIC_FIELD = "dynamic_field"`
- `FORBIDDEN_DYNAMIC_OBJECT_FIELD = "dynamic_object_field"`
- `DYNAMIC_OPTIN_METADATA_KEY = b"adamant.allows_dynamic"`

The `adamant_native_constants_match_spec_text` test pins
all four against §6.2.1.6 line 485 spec text. **1st
instance of Adamant-spec-text-parity-test discipline
registered alongside** (analogous to E-1b's upstream-
parity-test discipline; different pinning authority).

Distinct from E-1b's
upstream-constant-duplication-with-test-time-parity-pin
pattern (which pins to Sui upstream tag). Both share
Adamant-native ownership discipline; differ in pinning
authority. Pattern-cluster: Adamant-native constants
discipline now has two empirical sub-classifications;
rule-of-three pending across the broader cluster.

### (34) Helper-extraction discipline sub-shape γ extract-at-N=1-anticipating (NEW; 1st instance at E-2a)

Sub-shape γ of helper-extraction discipline (which
already had α=N=2 at B-2.2 + β=N=3 at D-7a). Sub-shape γ
fires when extraction is anticipation-triggered rather
than reuse-triggered: the test surface anticipates
multiple consumers from inception of the work, motivating
extraction at first use.

1st instance at E-2a: `InMemoryModuleResolver` extracted
at N=1 with 7 immediate consumers in the trait/API
correctness tests + anticipated reuse at E-2b walker
tests. The cross-module subtree has multiple Layer A test
sites from inception, motivating anticipated extraction
at first use rather than the reuse-triggered extraction
sub-shapes α (`module_pass` at B-2.2; N=2) and β
(`function_pass` at D-7a; N=3).

Helper-extraction discipline now has three empirical
sub-shapes:

- **α: extract-at-N=2** (low fixture overhead; reuse-
  triggered; B-2.2 module_pass `assert_pass_parity`)
- **β: extract-at-N=3** (high fixture overhead; reuse-
  triggered; D-7a function_pass test_helpers)
- **γ: extract-at-N=1-anticipating** (anticipated reuse
  triggers extraction at first use; E-2a cross_module
  test_helpers)

Rule-of-three pending across sub-shapes (currently 3
sub-shapes, one instance each).

### (35) Helper-extraction discipline sub-shape α complexity-reduction qualifier (NEW; 1st refinement instance at E-4)

Sub-shape α (extract-at-N=2) refined at E-4 from "mechanical
extract at N=2" to "evaluate-extraction-at-N=2 — extract
ONLY when extraction reduces complexity; defer otherwise."

1st refinement instance at E-4: D-5c walker + E-4 walker
=  2 instances. Sub-shape α threshold met. But extraction
would have added closure-typed predicate API noise (state
threading differs: `caller_mode` for Rule 3 vs no per-call
state for Rule 7). Deferral was right shape; D-5c walker
ported to E-4 walker with state-threading difference
rather than refactored to closure-typed predicate API.

Methodology consequence: helper-extraction discipline
sub-shape α has a complexity-reduction qualifier.
Future plan-gate evaluations of sub-shape α extraction at
N=2 ask "does extraction reduce complexity?" before
firing.

Rule-of-three pending for the qualifier specifically.

### (36) Call-graph walker pattern sub-classifications (NEW; per-walk-state vs walk-set-filter)

Two empirical sub-classifications of call-graph walker
shape based on reject-condition shape:

- **Per-walk-state-determines-reject** (D-5c shape): walk
  every public function; per-walk mode (caller_mode in
  Rule 3) determines reject condition.
- **Walk-set-filter-at-entry** (E-4 shape): filter walk-
  set at entry (only `#[transparent]` publics for Rule
  7); reject condition is uniform within walks.

Same call-graph-walker pattern; different reject-condition
shape. Both methodology-positive; choice depends on
whether the rejection mode varies per-walk (per-walk-
state) or is uniform (walk-set-filter).

Rule-of-three pending across each sub-classification.

### (37) Rule-composition-for-cross-module-coverage pattern (NEW; 1st instance at E-4)

When a rule's cross-module surface is transitively bound
through composition with another rule's cross-module
machinery + the rule's per-module enforcement, Adamant
documents the transitive-coverage argument explicitly so
future maintainers don't assume the rule has a missing
cross-module implementation.

1st instance at E-4: Rule 7 cross-module coverage bound
through:

1. Cross-module Rule 3 (E-2b) catches transparent →
   shielded boundary crossings at the call edge.
2. Rule 7 single-module catches privacy-circuit
   instructions in transparent-reachable code within each
   module.

Composition: transparent caller (deploying module) calls
a shielded function in a dep module — cross-module Rule
3 (E-2b) rejects at the call edge. Transparent caller
calls a transparent function in a dep module — the dep
was validated at its own deploy time to not contain
privacy-circuit instructions in transparent-reachable
code (Rule 7 single-module on the dep). Composition is
closed; Rule 7 single-module + Rule 3 cross-module covers
the full constitutional surface.

Distinct from spec-text-DIRECTS-shared-helper canonical
principle (about reuse) and architectural-position-pin-
for-explicit-non-enforcement (about explicit non-
enforcement). This pattern is about constitutional
coverage via composition.

Rule-of-three pending.

### (38) Code-and-PROVENANCE.md methodology-pattern-registration sub-shape (NEW; 2 instances at E-4 + E-5)

When a methodology pattern affects implementation
decisions that future maintainers might question, the
pattern's rationale lives in BOTH code (per-module
preamble or variant doc-comment) AND PROVENANCE.md
(canonical methodology accumulation record).

vs the default sub-shape: PROVENANCE.md-only registration
(used for most patterns; canonical record is the
reference; code carries the implementation, not the
methodology rationale).

Two instances at Phase 5/5b.5:

- **E-4 rule-composition-for-cross-module-coverage**
  (walker preamble + variant doc-comment + canonical
  record). Future maintainer searching for "why no
  cross-module Rule 7 walker?" finds the transitive-
  coverage argument in code immediately.
- **E-5 architectural-position-pin-for-explicit-non-
  enforcement** (module preamble + canonical record).
  Future maintainer searching for "why no Rule 8 verify
  function?" finds the architectural position in code.

Rule-of-three pending across this sub-shape.

### (39) Architectural-position-pin-for-explicit-non-enforcement pattern (NEW; 1st instance at E-5)

When a spec amendment mandates a verifier-level no-op for
a rule whose enforcement venue is elsewhere (runtime,
parse-time, etc.), Adamant lands a canonical pin module
documenting (a) the architectural position, (b) the spec
text, (c) a test confirming the verifier accepts a fixture
that would otherwise be the rule's trigger condition. The
pin makes the absence of enforcement consensus-binding —
future maintainers searching for `rule_NN` find the
canonical record.

1st instance at E-5: `rule_08_bounded_loops` per §6.2.1.6
amendment 804d9db ("Static loop-bound verification is not
required at deployment time; the gas-budget bound at
runtime carries the determinism guarantee"). Pin module
contains doc-comment + 1 test
(`unbounded_self_loop_module_accepts_at_deploy_time`); no
`verify(&module)` function call at step 5.

Distinct from:

- Spec-text-DIRECTS-shared-helper canonical principle
  (about reuse).
- Rule-composition-for-cross-module-coverage (about
  transitive coverage).
- Architectural-position-pin-for-explicit-non-enforcement
  (this pattern; about explicit non-enforcement).

Three patterns operating across distinct architectural-
decision domains, all surfacing decisions that future
maintainers might question.

Rule-of-three pending. Future candidates: Rule 5 (no
global storage instructions) is enforced at parse time
inside `adamant_deserialize`'s strict mode — pinned at
the deserializer side rather than via a validator pin
module. If a future spec amendment lands a deploy-time-
no-op rule, the architectural-position-pin pattern's 2nd
instance fires.

### (40) Trigger-condition-boundary defensive-testing sub-pattern (NEW; 2 instances E-3 + E-4)

Tests that verify the trigger condition fires only when
ALL conditions match — boundary discrimination preserves
the trigger condition against accidental widening in
future refactors.

Two instances:

- **E-3** (Rule 6 boundary tests):
  - `call_to_dynamic_field_at_wrong_address_accepts`
    (address discrimination — name match only at non-0x2
    address: not forbidden)
  - `call_to_other_module_at_0x2_accepts` (module-name
    discrimination — 0x2 address with non-dynamic-field
    name: not forbidden)
- **E-4** (Rule 7 walk-set boundary):
  - `mixed_modes_only_transparent_walked` (transparent
    public not reaching circuit accepts; shielded public
    reaching circuit accepts; only transparent walked)

Pattern shape: when a rule's trigger condition is
multi-conditional, defensive boundary tests verify each
condition's exclusion-from-trigger. Without these,
future refactor could accidentally widen the trigger
(e.g., remove the address check; rule fires on any 0x2
module name match).

Rule-of-three pending.

### (41) Architectural-position-confirmation testing sub-pattern (NEW; 1st instance at E-5)

Test asserts the verifier ACCEPTS a fixture that would
otherwise be the rule's trigger condition — confirms
spec-mandated non-enforcement empirically. Distinct from
trigger-condition-boundary defensive-testing (which
verifies the trigger DOES fire when conditions match);
this confirms the verifier DOES NOT enforce when spec
mandates non-enforcement.

1st instance at E-5: `unbounded_self_loop_module_accepts_at_deploy_time`
asserts the verifier accepts an unbounded `Branch(0)`
self-loop module — the canonical empirical pin that
Rule 8 is not enforced at the verifier layer.

Both methodology-positive defensive-testing core
discipline; different mechanical shapes:

- Trigger-condition-boundary (E-3 + E-4): trigger fires
  only when ALL conditions match.
- Architectural-position-confirmation (E-5): verifier
  accepts what spec mandates non-enforcement of.

Rule-of-three pending.

### (42) Defensive-fixture-isolation pattern (NEW; 1st instance at E-5)

When testing one rule's behavior, ensure other rules
don't pre-empt the assertion. Fixture is curated to
satisfy all OTHER rules so the test's failure path is
exclusively the targeted rule.

1st instance at E-5: `unbounded_self_loop_module_accepts_at_deploy_time`
fixture includes mandatory mutability metadata (Rule 1)
+ `VERSION_MAX = 7` + valid module-handle wiring + valid
function-handle wiring. Without these, Rule 1 (or another
rule) would pre-empt the Rule 8 acceptance assertion.

Same posture as D-7a Layer B fixture curation
(composite-pipeline parity sound because fixtures
isolated targeted pass per the Sui-public-API-shape-
constrains-parity-helper sub-pattern).

Rule-of-three pending.

### (43) Open Layer B gaps closure two sub-shapes (NEW; gap-source-removal at E-1a + gap-fill at E-6)

Open Layer B gaps closure pattern (registered at D-7b)
now has two empirical sub-shapes:

- **Gap-source-removal closure** (E-1a 1st instance):
  the gap closes via removing what needed Layer B
  parity. SuiVerifier audit gap (registered at C-5)
  closes via the bridge tear-out at E-1a — the variant
  itself is removed; nothing left to audit.
- **Gap-fill closure** (E-6 1st instance): the gap
  closes via fixture construction filling the audit
  hole. BorrowViolationReason 7-of-13 sub-reasons +
  st_loc_destroys_non_drop close via E-6's negative-
  test fixtures.

Different mechanical shapes; same audit-gap-closure
core discipline. Rule-of-three pending across each
sub-shape.

### (44) Variant-vs-test mapping audit principle three sub-shapes (NEW; coverage trajectories)

Variant-vs-test mapping audit principle (canonical at
C-3, retroactive audit at C-5 + D-7b, deferred-gap
closure at E-6) now has three empirical sub-shapes:

- **Coverage-baseline-establishment** (C-3 origin):
  forward-looking — new variants get audit at impl-gate.
- **Coverage-retroactive-audit** (C-5 + D-7b): backward-
  looking validation of existing variants.
- **Coverage-deferred-gap-closure** (E-6): closes audit
  gaps that were honestly-scope-flagged at prior sub-
  arcs.

All three sub-shapes operate across Phase 5/5b. Rule-of-
three threshold met for the audit principle's coverage-
trajectory taxonomy.

### (45) Variant-vs-test mapping audit closure shapes (NEW; test-addition vs variant-removal)

Within the audit principle, two closure shapes:

- **Test-addition closure** (most variants): new variant
  gets audit at impl-gate; explicit negative test added
  alongside producer.
- **Variant-removal closure** (E-1a SuiVerifier): audit
  gap closes via tear-out — variant removed; nothing
  left to audit.

Structurally similar to Open Layer B gaps closure's gap-
source-removal sub-shape (E-1a) — same retire-via-
fulfillment shape applied at variant level.

Rule-of-three pending across variant-removal-closure
specifically.

### (46) Variant-count discipline four sub-shapes (NEW; comprehensive empirical taxonomy)

Variant-count discipline now has four empirical sub-
shapes:

- **Variant-count-via-add** (most rule sub-arcs): new
  rejection conditions add typed variants.
- **Variant-count-via-tear-out** (E-1a; 64 → 63):
  bridge tear-out removes SuiVerifier variant.
- **Variant-count-via-no-op** (E-5; 66 unchanged):
  architectural-position pin; no rejection condition
  at deploy time.
- **Variant-count-via-coverage-expansion** (E-6; 66
  unchanged): work expands Layer B coverage on existing
  variants without adding new ones.

Pattern of "core discipline + empirical sub-
classifications" continues stable across multiple
methodology areas (helper-extraction three sub-shapes;
Adamant-native-constants two sub-classifications;
Open Layer B gaps closure two sub-shapes; etc.).

Rule-of-three pending across each sub-shape.

### (47) Test-placement discipline sub-shapes (NEW; producer-adjacent vs public-API-boundary)

Two empirical sub-shapes of test placement:

- **Producer-adjacent placement**: each test alongside
  its producer (same source file). Granular; useful for
  unit-test coverage at a lower layer.
- **Public-API-boundary placement** (E-6 1st instance
  for variant-vs-test mapping audit purposes): all
  tests for a closed-enum variant at the end-to-end
  entry point. Stronger coverage anchored at the
  verifier's public API; canonical for variant-vs-test
  mapping audit purposes.

Rule-of-three pending across each sub-shape.

### (48) Sub-shape 2 (pre-arc-split) empirical-substantiality qualifier (NEW; 1st refinement instance at E-6)

Sub-shape 2 of empirical-complexity-drives-sub-checkpoint-
shape pattern (pre-arc-split) refined at E-6: pattern
fires when scope is empirically substantial, not
mechanically at multi-component sub-arc.

1st refinement instance at E-6: E-6 has 8 components (7
BorrowViolationReason tests + 1 st_loc_destroys_non_drop)
but bundled because methodology shape is uniform (Layer
B fixture construction). Pre-arc-split would have over-
applied; bundling honors the empirical-substantiality
principle.

Same posture as helper-extraction discipline sub-shape α
complexity-reduction qualifier (E-4 1st instance):
extract-at-N=2 fires when extraction reduces complexity,
not mechanically. Both refinements move from "mechanical
threshold trigger" to "evaluate trigger empirically with
qualifier."

Rule-of-three pending for the qualifier specifically.

### (49) Plan-incremental-disposition sub-pattern β closure-phase 2nd instance (D-5b.2 → E-6)

Sub-pattern β (deliberate-deferral) closure-phase
canonical pattern reaches 2 instances:

- 1st closure: D-5a.0 → D-5a.1.b (TypeMismatchReason 14
  sub-reason audit closure).
- 2nd closure: D-5b.2 → E-6 (BorrowViolationReason 13
  sub-reason audit closure).

Pattern stable across phase boundaries (Phase 5/5b.4 +
Phase 5/5b.5). Rule-of-three pending at next closure
instance.

### (50) Cumulative-phase-closure-on-final-sub-arc pattern two shapes (NEW; single-phase vs cumulative-multi-phase)

Phase-closure documentation has two empirical shapes:

- **Single-phase closure** (D-7b 1st instance; Phase
  5/5b.4 closure only). Per-sub-arc entries +
  methodology accumulation streams + state-bump.
- **Cumulative-multi-phase closure** (E-7 1st instance;
  Phase 5/5b.5 closure + Phase 5/5b cumulative closure
  across 6 sub-arcs). Adds cumulative-phase tally +
  cross-phase pattern accumulation.

Different methodology shape; same closure-batch core
discipline. Rule-of-three pending across cumulative-
multi-phase closure shape (would land at next phase-
cumulative closure: Phase 5/5c if applicable, or Phase
5 overall).

### (51) Scope-expansion-history-as-canonical-record sub-pattern (NEW; 2 instances D-7 + E-7)

How canonical-record files evolve in scope and document
their own evolution. Each scope expansion adds a paragraph
at the file's top documenting the expansion.

Two instances:

- **D-7** (1st instance): expanded `module_pass/PROVENANCE.md`
  to cover `function_pass/` subtree.
- **E-7** (2nd instance): re-expanded same file to cover
  `cross_module/` subtree + Phase 5/5b.5 rule modules.

Different from variant-count discipline (count tracking)
and corrigendum-pattern (correction shape). Specifically
about how canonical-record files evolve in scope and
document their own evolution.

Rule-of-three pending.

### (52) Corrigendum-as-canonical-correction-shape sub-pattern of running-total drift discipline (NEW; rule-of-three threshold MET at E-7)

Within the running-total drift discipline, the canonical
correction landing shape is a corrigendum section in
PROVENANCE.md with a per-commit progression table.

Three corrigendum instances at E-7 closure:

1. **B-6 baseline error in CLAUDE.md state-bump**
   (variant-count baseline, registered at C-5;
   corrigendum at end of file).
2. **D-3-to-D-4 baseline error in commit-message running
   totals** (workspace-test-count drift, registered at
   D-7b; corrigendum at end of file).
3. **E-1b lib-count baseline drift** (registered at E-7;
   corrigendum lands in this commit; see "Corrigendum:
   E-1b lib-count baseline drift" section below).

Rule-of-three threshold met for corrigendum-as-canonical-
correction-shape sub-pattern. Pattern stability across
phase boundaries (5/5b.2 + 5/5b.4 + 5/5b.5) confirms
corrigendum shape is the canonical landing for running-
total drift catches.

### (53) Pattern-cluster meta-observation across methodology areas (NEW; meta-pattern at E-7)

Methodology framework consistently surfaces empirical
sub-classifications at scale, not just monolithic
patterns. Multiple methodology areas have pattern-
cluster shape:

- Helper-extraction discipline (3 sub-shapes: α/β/γ)
- Spec-text-DIRECTS-shared-helper canonical principle (2
  sub-shapes: cross-pass-distinct + cross-scope-reuse)
- Adamant-native-constants discipline (2 sub-
  classifications: Sui-upstream-parity-pinned + Adamant-
  spec-text-pinned)
- Open Layer B gaps closure (2 sub-shapes: gap-source-
  removal + gap-fill)
- Bridge-as-soundness-test-infrastructure (opening +
  closure phases)
- Call-graph walker pattern (2 sub-classifications:
  per-walk-state-determines-reject + walk-set-filter-
  at-entry)
- Variant-count discipline (4 sub-shapes: add / tear-
  out / no-op / coverage-expansion)
- Variant-vs-test mapping audit principle (3 sub-shapes
  + 2 closure shapes)
- Test-placement discipline (2 sub-shapes: producer-
  adjacent + public-API-boundary)
- Cumulative-phase-closure-on-final-sub-arc (2 shapes:
  single-phase + cumulative-multi-phase)

Pattern-cluster is itself a methodology pattern. Sub-
classifications emerge through empirical iteration;
framework accommodates discovery rather than forcing
monolithic patterns.

Worth canonical methodology-meta registration: pattern-
cluster shape at scale is a stable phenomenon of the
methodology framework's operation.

### (54) Methodology framework efficiency curve across phases (NEW; meta-observation at E-7)

Empirical observation across phase boundaries: phase-
later sub-arcs surface plan-gates more cleanly than
phase-earlier sub-arcs. Framework efficiency improves
as discipline internalizes:

- Phase 5/5b.2 (B-1 through B-6): framework
  establishment phase; multi-question plan-gates with
  significant empirical-resolution cycles.
- Phase 5/5b.3 (C-1 through C-5): framework refinement;
  C-3 variant-vs-test mapping audit principle
  established; C-5 running-total drift discipline
  registered.
- Phase 5/5b.4 (D-1 through D-7): framework maturation;
  multiple cross-cutting canonical principles operating
  beyond rule-of-three threshold; D-7b 22-subsection
  methodology accumulation streams.
- Phase 5/5b.5 (E-1 through E-7): framework efficiency;
  plan-gates surface more cleanly; methodology data
  points cluster around new sub-shape registrations
  rather than novel patterns. E-7 25-subsection
  methodology accumulation streams.

Efficiency curve is methodology-positive: cost-of-
discipline decreases as discipline internalizes; framework
scales without bottlenecking implementation.

Worth canonical meta-registration: methodology framework
itself improves with phase iteration; pattern stability
across phase boundaries demonstrates framework
robustness.

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

## Variant-vs-test mapping audit appendix (14 new variants; D-7b closure)

Per the canonical methodology principle (section "(5)
Variant-vs-test mapping audit at implementation-gate" of
the Phase 5/5b.3 closure section), each new typed variant
landing in a sub-checkpoint must have at least one explicit
negative test asserting on the variant shape. Phase 5/5b.4
added 14 new variants (50 → 64). This appendix audits each
for explicit negative-test coverage; the C-5 audit table
above (50 pre-D-1 variants) stays canonical for those
variants.

**Audit method (matches C-5):** `grep -rE "Err\(AdamantValidationError::VARIANT\b"
crates/adamant-vm/src` per variant; counts include positive
and negative occurrences in test code.

**Audit results: 14 of 14 new variants have explicit
negative test coverage.** Per-D-N audit-already-applied-
at-impl-gate disposition (Q4(a) at D-7 plan-gate) — the
variant-vs-test mapping audit principle was applied at each
sub-checkpoint commit per the C-3 origin instance; D-7b's
role is grep-confirmation at phase closure.

| Variant | Sub-checkpoint | Test occurrences | Status |
|---|---|---|---|
| `EmptyFunctionBody` | D-2 | 4 | ✓ covered |
| `MissingFallthroughTerminator` | D-2 | 5 | ✓ covered |
| `IrreducibleControlFlow` | D-2 | 5 | ✓ covered |
| `StackPushOverflow` | D-3 | 2 | ✓ covered |
| `StackUnderflow` | D-3 | 6 | ✓ covered |
| `UnbalancedStackAtBlockEnd` | D-3 | 3 | ✓ covered |
| `StLocDestroysNonDrop` | D-4 | 3 | ✓ covered |
| `MoveLocUnavailable` | D-4 | 4 | ✓ covered |
| `CopyLocUnavailable` | D-4 | 3 | ✓ covered |
| `BorrowLocUnavailable` | D-4 | 3 | ✓ covered |
| `RetWithUndroppedLocals` | D-4 | 3 | ✓ covered |
| `TypeMismatch` | D-5a.0/D-5a.1.a/D-5a.1.b | 25+ | ✓ covered (workhorse; 14 sub-reasons) |
| `BorrowViolation` | D-5b.2 | 14+ | ✓ covered (workhorse; 13 sub-reasons; 6 sub-reasons have Layer B gap registered under "Open Layer B gaps deferred to pre-mainnet hardening" — see Phase 5/5b.4 closure stream (13)) |
| `PrivacyConsistencyViolation` | D-5c | 6+ | ✓ covered |

**Combined audit state at D-7b closure: 63 of 64 variants
have explicit negative test coverage.** The 1 gap is the
`SuiVerifier` transitional bridge variant (registered at
C-5; deferred to natural resolution at 5/5b.5 bridge tear-
out per the C-5 disposition; gap unchanged across Phase
5/5b.4).

The BorrowViolationReason 6-of-13 sub-reasons gap is
registered at the sub-reason level (not the variant level)
— `BorrowViolation` itself has explicit coverage; the gap
is in the comprehensiveness of sub-reason coverage. Tracked
under Phase 5/5b.4 closure stream (13) as the 2nd instance
of "Open Layer B gaps deferred to pre-mainnet hardening".

## Corrigendum: D-3-to-D-4 baseline error in commit-message running totals

**Source:** Phase 5/5b.4 D-3 closure commit (`0ceae97`,
2026-05-08) inherited a missing workspace-test-count claim;
D-4 closure commit (`603edf7`, 2026-05-08) inherited the
wrong baseline.

**The error:** D-2 commit (`4bc6eaf`) and D-3 commit
(`0ceae97`) claimed only `adamant-vm crate test count` (per-
crate delta) without `Workspace test count` claims. D-4
commit (`603edf7`) claimed `Workspace test count: 1328 →
1351 (+23)`. The "1328" baseline was wrong — empirical
workspace test count after D-3 closure was 1362 (= 1290 at
D-1b closure + 36 D-2 + 36 D-3, matching per-sub-checkpoint
adamant-vm crate deltas).

**Empirical reality (corrected at D-7 plan-gate empirical-
grep catch):**

- **D-1b closure (commit `5a56603`; baseline empirically
  verified):** 1290 workspace tests
- **D-2 closure (commit `4bc6eaf`):** 1290 + 36 = **1326**
  workspace tests (commit message: no workspace claim)
- **D-3 closure (commit `0ceae97`):** 1326 + 36 = **1362**
  workspace tests (commit message: no workspace claim;
  drift origin)
- **D-4 closure (commit `603edf7`):** 1362 + 23 = **1385**
  workspace tests (commit message claimed 1328 → 1351; +23
  delta correct, but baseline 1328 was 34 below empirical
  1362)

**Drift propagation:** the wrong "1351" terminal claim was
inherited by 7 subsequent commit messages across Phase
5/5b.4, with correct per-sub-checkpoint deltas applied to
the wrong baseline:

| Commit | Inherited baseline | Per-commit delta | Claimed total | Actual total |
|---|---|---|---|---|
| D-3 (origin) | — (no workspace claim) | +36 ✓ | — | 1362 |
| D-4 | 1328 (wrong, -34) | +23 ✓ | 1351 (wrong) | 1385 |
| D-5a.0 | 1351 (wrong, -34) | +9 ✓ | 1360 (wrong) | 1394 |
| D-5a.1.a | 1360 (wrong, -34) | +17 ✓ | 1377 (wrong) | 1411 |
| D-5a.1.b | 1377 (wrong, -34) | +27 ✓ | 1404 (wrong) | 1438 |
| D-5b.1 | 1404 (wrong, -34) | +21 ✓ | 1425 (wrong) | 1459 |
| D-5b.2 | 1425 (wrong, -34) | +26 ✓ | 1451 (wrong) | 1485 |
| D-5c | 1451 (wrong, -34) | +15 ✓ | 1466 (wrong) | 1500 |
| D-6 | 1466 (wrong, -34) | +6 ✓ | 1472 (wrong) | 1506 |

**Per-sub-checkpoint deltas were empirically correct
throughout** (each commit's claimed delta matches the
adamant-vm crate-level test additions; only the inherited
workspace baseline was wrong from D-4 forward).

**Catch at D-7 plan-gate:** D-7 plan-gate's empirical-grep
verification of the resume-prompt baseline (claimed 1472
workspace tests; empirically 1506 at HEAD `a74f4c8`) caught
the discrepancy. Per the C-5-registered commit-message
running-total drift discipline (section "(7)" of Phase
5/5b.3 closure methodology accumulation streams), D-7b's
state-bump uses empirically-grep-confirmed counts.

**Correction at D-7b:** Phase 5/5b.4 closure metrics use
empirically-verified counts:
- Pre-Phase-5/5b.4 baseline: **1259** (= D-1a entry
  baseline; = Phase 5/5b.3 closure actual at C-5)
- Phase 5/5b.4 added: **+273** (per-sub-checkpoint deltas
  18+13+36+36+23+9+17+27+21+26+15+6+26 = 273; matches
  adamant-vm crate-level totals; corrects the prior
  inherited-baseline-on-wrong-baseline arithmetic)
- Phase 5/5b.4 closure total: **1532** (= 1259 + 273; D-7a
  empirical state at HEAD `31a22d0`; corrects the
  inherited "1472" claim from D-6 commit message)

The commit messages from D-4 through D-6 stay in the git
log as historical record. Future readers of those commit
messages consult this corrigendum for the empirically-
verified counts. **Same posture as the B-6 corrigendum
above for the AdamantValidationError variant-count drift.**

**Methodology consequence:** second instance of the commit-
message running-total drift pattern operating at full
empirical-catch effectiveness. Rule-of-three pending at
next phase closure. Future per-sub-checkpoint commit
messages must claim workspace test count explicitly (the
D-3 origin gap was "no workspace claim"; future commits
that don't claim workspace count let the drift propagate
silently).

## Variant-vs-test mapping audit appendix (3 new variants + 1 removed-variant closure-of-record; E-7 closure)

Per the canonical methodology principle (registered at
C-3, applied retroactively at C-5 + D-7b), each typed-
error variant landing in a sub-checkpoint must have at
least one explicit negative test asserting on the variant
shape. Phase 5/5b.5 net variant-count delta:
**64 → 66 (+2 net; -1 SuiVerifier removed at E-1a +
3 new added across E-2a/E-3/E-4)**. This appendix
audits the 3 new variants for explicit negative-test
coverage AND records the closure-of-record for the
SuiVerifier audit gap (registered at C-5 with disposition
"deferred to natural resolution at 5/5b.5 bridge tear-
out"; resolution achieved at E-1a).

D-7b's audit table (64 variants) stays canonical for the
variants that existed at D-7b closure. This appendix adds
the 3-variant increment + 1 removed-variant closure-of-
record.

**Audit method:** `grep -rE "Err\(AdamantValidationError::VARIANT\b"
crates/adamant-vm/src` per variant; counts include
positive and negative occurrences in test code.

**Audit results (3 new variants): all 3 have explicit
negative test coverage.**

| Variant | Sub-checkpoint | Test occurrences | Status |
|---|---|---|---|
| `CrossModulePrivacyConsistencyViolation` | E-2a (variant) / E-2b (producer + tests) | 5 | ✓ covered (5 negative tests in `validator/cross_module/rule_03_privacy_consistency::tests`) |
| `DynamicDispatchViolation` | E-3 | 5 | ✓ covered (5 negative tests in `validator/rule_06_no_dynamic_dispatch::tests`) |
| `PrivacyCircuitContextViolation` | E-4 | 5 | ✓ covered (5 negative tests; one per restricted Adamant extension + 1 transitive-reach test) |

**Removed-variant closure-of-record:**

`SuiVerifier(VMError)` (registered at Wave 3a; carried
the C-5 audit gap with disposition "deferred to natural
resolution at Phase 5/5b.5 Sui-verifier-bridge tear-out
per the architectural commitment in §6.2.1.8") is
**removed at E-1a** as part of the bridge tear-out. The
audit gap is **closed via gap-source-removal**: the
variant no longer exists in the codebase, so there is
nothing to audit. 1st instance of variant-removal closure
shape of variant-vs-test mapping audit principle (NEW;
registered at E-7 closure stream (45)).

**Combined audit state at E-7 closure (Phase 5/5b.5
closes; Phase 5/5b CLOSED):** all 66 typed
`AdamantValidationError` variants have explicit negative-
test coverage. The 1 audit gap registered at C-5 (the
`SuiVerifier` transitional bridge variant) closed-of-
record at E-1a. **No outstanding audit gaps at Phase 5/5b
closure.** Pattern-cluster: the variant-vs-test mapping
audit principle's cumulative coverage trajectory
(C-5 audit at 50 variants → D-7b audit at 64 variants →
E-7 audit at 66 variants with 0 gaps) demonstrates
discipline scaling cleanly across phases.

## Corrigendum: E-1b lib-count baseline drift in commit-message running totals

**Source:** Phase 5/5b.5 E-1b closure commit (`4fb4114`,
2026-05-09).

**The error:** E-1b's commit message claimed
`adamant-vm lib: 830 tests (unchanged from E-1a closure)`.
The empirical lib count at E-1b was **831** — E-1b added
1 lib test (the `adamant_structural_limits_constants_match_sui_upstream`
upstream-parity pin in `validator/config.rs::tests`) plus
1 integration test (the
`adamant_vm_production_deps_contain_no_sui_move_crates`
build-system check in `tests/no_sui_in_production_deps.rs`,
which counts as workspace +1 but NOT lib +1). The
commit message correctly claimed workspace 1532 → 1534
(+2) but missed the lib +1 from the upstream-parity pin.

**Empirical reality (corrected at E-7 session-resume
empirical verification):**

- **E-1a closure (commit `0b774a3`):** 830 lib tests
  (baseline empirically verified)
- **E-1b closure (commit `4fb4114`):** 830 + 1 = **831**
  lib tests (commit message: "830 tests (unchanged)";
  drift origin)
- **E-2a closure (commit `8e4d814`):** 831 + 7 = **838**
  lib tests (commit message claimed 837 → 838;
  + 7 delta correct, baseline 837 was 1 below empirical
  831 + 7 = 838)
- **E-2b closure (commit `4e5bbab`):** 838 + 11 = **849**
  lib tests (commit message claimed 848 → 849;
  + 11 delta correct, baseline 848 was 1 below empirical)
- **E-3 closure (commit `922d4bd`):** 849 + 11 = **860**
  lib tests (commit message claimed 859 → 860;
  + 11 delta correct, baseline 859 was 1 below empirical)
- **E-4 closure (commit `f7e6189`):** 860 + 13 = **873**
  lib tests (commit message claimed 872 → 873;
  + 13 delta correct, baseline 872 was 1 below empirical)
- **E-5 closure (commit `4764be3`):** 873 + 1 = **874**
  lib tests (commit message claimed 873 → 874;
  + 1 delta correct, baseline 873 was 1 below empirical)
- **E-6 closure (commit `eb766b8`):** 874 + 8 = **882**
  lib tests (commit message claimed 881 → 882;
  + 8 delta correct, baseline 881 was 1 below empirical)

**Drift propagation:** the wrong "830 unchanged" baseline
inherited by 7 subsequent commits across Phase 5/5b.5,
with correct per-sub-checkpoint deltas applied to the
wrong baseline:

| Commit | Inherited baseline | Per-commit delta | Claimed total | Actual total |
|---|---|---|---|---|
| E-1b (origin) | 830 (correct from E-1a) | +1 ✗ (claimed 0) | 830 (wrong, -1) | 831 |
| E-2a | 830 (wrong, -1) | +7 ✓ | 837 (wrong, -1) | 838 |
| E-2b | 837 (wrong, -1) | +11 ✓ | 848 (wrong, -1) | 849 |
| E-3 | 848 (wrong, -1) | +11 ✓ | 859 (wrong, -1) | 860 |
| E-4 | 859 (wrong, -1) | +13 ✓ | 872 (wrong, -1) | 873 |
| E-5 | 872 (wrong, -1) | +1 ✓ | 873 (wrong, -1) | 874 |
| E-6 | 873 (wrong, -1) | +8 ✓ | 881 (wrong, -1) | 882 |

Per-sub-checkpoint deltas were empirically correct from
E-2a forward (each commit's claimed delta matches the
actual additions; only the inherited E-1b baseline was
wrong from E-1b forward). Workspace count was correct
throughout (1534 → 1541 → 1552 → 1563 → 1576 → 1577 →
1585 all match empirical).

**Catch at E-7 session-resume:** E-7 session-resume
empirical-grep verification of the resume-prompt baseline
(claimed `adamant-vm lib: 881 tests`; empirical 882 at
HEAD `eb766b8`) caught the discrepancy. Per the C-5-
registered commit-message running-total drift discipline
(operating beyond rule-of-three threshold post-E-6 with
this catch as 4th instance), E-7's state-bump uses
empirically-grep-confirmed counts.

**Correction at E-7:** Phase 5/5b.5 closure metrics use
empirically-verified counts:

- Pre-Phase-5/5b.5 baseline (= D-7b closure / Phase
  5/5b.4 closure actual): adamant-vm lib **830 tests**
  (matches commit message claim)
- Phase 5/5b.5 added: **+52 lib tests** (per-sub-
  checkpoint deltas 1+7+11+11+13+1+8 = 52; matches
  empirical reconstruction)
- Phase 5/5b.5 closure total: **882 lib tests** (= 830
  + 52; corrects the inherited "881" claim from E-6
  commit message)

The commit messages from E-1b through E-6 stay in the git
log as historical record. Future readers of those commit
messages consult this corrigendum for the empirically-
verified counts. **Same posture as the B-6 corrigendum
above for the AdamantValidationError variant-count drift
and the D-3-to-D-4 corrigendum for the workspace-test-
count drift.**

**Methodology consequence:** **3rd corrigendum instance**
of the running-total drift discipline operating at full
empirical-catch effectiveness — **rule-of-three threshold
MET for corrigendum-as-canonical-correction-shape sub-
pattern** (registered at E-7 closure stream (52)). Pattern
stability across phase boundaries (5/5b.2 + 5/5b.4 +
5/5b.5) confirms corrigendum shape is the canonical
landing for running-total drift catches. Verified-
empirically posture at session-resume boundary operating
exactly as designed: catch propagated drift before
canonical record landing.

**Discipline going forward:** at every phase closure AND
session-resume boundary, empirically grep-confirm running
totals (variant counts, lib test counts, workspace test
counts, sub-reason counts, etc.) via grep-on-code rather
than inheriting prior state-bump claims. **Session-resume
verification is now mandatory** per the running-total
drift discipline operating beyond rule-of-three threshold.

## Phase 5/5b cumulative closure

Phase 5/5b is the longest sub-arc set in the project's
history: **6 sub-arcs across ~5 weeks** of development
(2026-05-07 through 2026-05-09; calendar-tight workstream
with internalized methodology framework discipline).
**Phase 5/5b CLOSED at E-7 commit.**

### Phase 5/5b sub-arc enumeration

- **Phase 5/5b.1a** (foundation fork; commit `a7a06ab`):
  bytecode-format primitives — constants, readers,
  AbilitySet, Identifier — into the new `adamant-bytecode-
  format` crate.
- **Phase 5/5b.1b** (foundation fork continued; commit
  `874e701`): 25 reused parallel-struct neighbour types,
  index machinery, SignatureToken, full inherited
  Bytecode enum, CodeUnit, FunctionDefinition, U256 thin
  newtype, Metadata, AddressIdentifierPool reusing
  `adamant_types::Address`.
- **Phase 5/5b.2** (B-1 through B-6; closed at `4b03f14`,
  workspace 821 → 1035): module-level passes
  establishment + 9 module-level passes ported Adamant-
  native + Rule 2 + privacy_metadata_structure + 8-pass
  pipeline integration.
- **Phase 5/5b.3** (C-1 through C-5; closed at `7d90847`,
  workspace 1035 → 1259): module-level pass completion +
  3 large module-level passes (BoundsChecker /
  DuplicationChecker / SignatureChecker) + 11-pass
  pipeline integration. PROVENANCE.md establishment.
- **Phase 5/5b.4** (D-1 through D-7; closed at `4ce3d5b`,
  workspace 1259 → 1532): per-function pipeline
  establishment + 5 per-function passes + Rule 3 single-
  module + per-function-pass framework (CFG +
  AbstractInterpreter + AbstractStack + BorrowGraph) +
  step-4 pipeline integration. PROVENANCE.md scope
  expansion to cover function_pass.
- **Phase 5/5b.5** (E-1 through E-7; closed at the
  current commit, workspace 1532 → 1585): Sui-bridge
  tear-out + cross-module Rule 3 + Rules 6, 7
  implementation + Rule 8 architectural-position pin +
  Open Layer B gaps closure + cumulative closure
  documentation. PROVENANCE.md re-expansion to cover
  cross_module + Phase 5/5b.5 rule modules.

### Phase 5/5b cumulative metrics

**Workspace test count progression:** 821 → 1585 (+764
across the entire Phase 5/5b workstream).

**Per-phase cumulative deltas:**

| Phase | Sub-arcs | Closing workspace test count | Phase delta | AdamantValidationError variants |
|---|---|---|---|---|
| Phase 5/5b.1a | 1 | (foundation; tests in adamant-bytecode-format) | foundation | (no validator yet) |
| Phase 5/5b.1b | 1 | (foundation continued) | foundation | (no validator yet) |
| Phase 5/5b.2 | 6 (B-1..B-6) | 1035 | +214 | 7 → 33 (+26) |
| Phase 5/5b.3 | 5 (C-1..C-5) | 1259 | +224 | 33 → 50 (+17) |
| Phase 5/5b.4 | 12 commits / 9 sub-arcs | 1532 | +273 | 50 → 64 (+14) |
| Phase 5/5b.5 | 9 commits / 7 sub-arcs | 1585 | +53 | 64 → 66 (+2 net) |

**Cumulative AdamantValidationError variants:** 7 → 66
(+59 net).

**Cumulative public closed enums:** 0 → 11. Enumeration:
HandleKind (B-3.1), DefKind (C-2), InvalidSignatureReason
(C-3), IrreducibleReason (D-2), TypeMismatchReason
(D-5a.0), BorrowViolationReason (D-5b.2),
PrivacyConsistencyViolationReason (D-5c),
DynamicDispatchViolationReason (E-3),
PrivacyCircuitContextViolationReason (E-4), FieldOwnerKind
(B-2.3), MalformedConstantReason (B-2.1).

**Cumulative deliberate-Adamant-decision instances:** 11
(per CLAUDE.md state-bump tracking).

**Cumulative verification gates fired:** 8 (pre-Phase-
5/5b.4) + 3 (Phase 5/5b.4) + 4 (Phase 5/5b.5) = 15
total. Phase 5/5b alone fired 7 verification gates
across the §6.2.1.X spec sections.

**Production-side Sui dependency complete elimination:**
Phase 5/5b.5 E-1 milestone. adamant-vm production-binary
dependency graph contains zero `move-*` crates per the
§6.2.1.8 resistant-proof posture; build-system independence
check at `tests/no_sui_in_production_deps.rs`
mechanically enforces the architectural commitment.

**Adamant-native verifier feature-completeness at Phase
5/5b closure:**

- **Module-level passes:** 11 Adamant-native passes wired
  at step 3 of `verify_module` (bounds_checker first
  per cross-pass-precedence; 10 others alphabetical /
  cross-pass-pipeline-dependency-driven).
- **Per-function passes:** 5 Adamant-native passes wired
  at step 4 (control_flow → stack_usage → locals_safety
  → type_safety → reference_safety).
- **Adamant-specific rules:** 6 module-level rules at
  step 5 (Rules 1, 2, 3 single-module, 4, 6, 7); Rule 5
  enforced at step 1 (parse-time); Rule 8 architectural-
  position pin (no step-5 invocation; runtime carries
  binding).
- **Cross-module verification:** Rule 3 cross-module
  walker at `validator/cross_module/`; awaits Phase 5/6
  AVM runtime stdlib production caller.

### Phase 5/5b cumulative methodology landmarks

**Cross-cutting canonical principles operating beyond
rule-of-three threshold at Phase 5/5b closure:**

1. **Verbatim-survey-at-plan-gate-prevents-scope-error
   pattern.** 8 instances at E-7 closure (D-3, D-5b,
   D-5c, E-2, E-3, E-4, E-5 plan-gates + the §6.2.1.8
   pre-arc verifications across Phase 5/5b.2 + 5/5b.3).
   Stable beyond threshold.
2. **Running-total drift discipline.** 4 instances at
   E-7 closure (B-6 → C-1/C-2/C-3 propagation; D-3 →
   D-4-through-D-6 propagation; D-5b.2 → D-7b → E-6
   propagation; E-1b → E-2-through-E-6 propagation
   caught at E-7 session-resume). Cross-cutting canonical
   principle stable across count types, discovery
   venues, and workstream contexts.
3. **Spec-text-DIRECTS-shared-helper canonical principle.**
   5 instances at E-7 closure: 3 cross-pass-distinct
   (D-5a.1.b TYPE-SAFETY call_signature; D-5b.2 BORROW-
   GRAPH call; D-5c CALL-GRAPH call_target_handle) + 2
   cross-scope-reuse (E-2b cross-module Rule 3 walker
   reuses D-5c's call_target_handle; E-4 Rule 7 walker
   reuses D-5c's call_target_handle).
4. **Eager-error first-failure-wins.** 6+ pattern
   instances across Phase 5/5b.2 + 5/5b.3 + 5/5b.4
   (cross-pass-precedence, within-pass eager-error,
   step-3 vs step-5 pipeline ordering).
5. **Variant-vs-test mapping audit principle.** 66 of
   66 variants covered at E-7 closure; 3 sub-shapes
   operating (coverage-baseline-establishment + coverage-
   retroactive-audit + coverage-deferred-gap-closure) + 2
   closure shapes (test-addition + variant-removal).

**Pattern-cluster shape across methodology areas (meta-
observation registered at E-7 stream (53)):**
methodology framework consistently surfaces empirical
sub-classifications at scale — helper-extraction (3 sub-
shapes); spec-text-DIRECTS-shared-helper (2 sub-shapes);
Adamant-native-constants (2 sub-classifications); Open
Layer B gaps closure (2 sub-shapes); call-graph walker (2
sub-classifications); variant-count discipline (4 sub-
shapes); variant-vs-test mapping audit (3 sub-shapes + 2
closure shapes); test-placement (2 sub-shapes);
cumulative-phase-closure (2 shapes); bridge-as-soundness-
test-infrastructure (opening + closure phases). Pattern-
cluster shape itself is a stable phenomenon of the
framework's operation.

**Methodology framework efficiency curve across phases
(meta-observation registered at E-7 stream (54)):**
empirical observation across phase boundaries shows
phase-later sub-arcs surface plan-gates more cleanly
than phase-earlier sub-arcs. Cost-of-discipline decreases
as discipline internalizes; framework scales without
bottlenecking implementation.

### Phase 5/5b architectural decisions on record

**Constitutional commitments crystallized during Phase
5/5b:**

1. **Resistant-proof posture (§6.2.1.8).** Adamant
   protocol works fully independently of Sui's codebase
   at deploy-time and runtime. Production-binary
   dependency graph contains zero move-* crates;
   vendored Sui-Move crates exercised exclusively at
   test time for cross-validation parity. Build-system
   independence check at `tests/no_sui_in_production_deps.rs`
   mechanically enforces the architectural commitment.
2. **Genesis-fixed verifier semantics.** Verifier accept/
   reject decisions are consensus-binding and cannot
   drift with upstream Sui. After genesis, all
   structural limits + gas costs + rule semantics are
   immutable per §6.2.1.7 and §6.2.1.8.
3. **Defense-in-depth at runtime via gas-budget bound
   for loop termination.** Rule 8 architectural-position
   pin at E-5; runtime gas-budget per §6.2.4 carries the
   determinism guarantee. Verifier-level no-op per
   amendment 804d9db.
4. **Cross-module Rule 3 enforcement via deployment-
   validator wiring.** Cross-module call graphs
   statically checked at deploy time against dependency
   modules' annotations per §6.2.1.6 line 477. The
   walker lives in adamant-vm; the production caller
   awaits Phase 5/6 AVM runtime stdlib.

### Phase 5/5b cumulative outstanding items

**Open Layer B gaps at Phase 5/5b closure: 0** (all
gaps closed; SuiVerifier audit gap retired-via-
fulfillment at E-1a; BorrowViolationReason 7-of-13 sub-
reason gap and st_loc_destroys_non_drop Layer B gap
filled at E-6).

**Future workstream items (Phase 5/5c or Phase 5/6):**

1. AVM runtime stdlib `adamant::module::deploy`
   implementation (Phase 5/6) — invokes
   `validator::verify_module` per-module + cross-module
   Rule 3 walker per the ModuleResolver trait abstraction.
2. Phase 5/5c plan-gate scope to be determined
   (cross-validation infrastructure formalization;
   T0+T1+T2 tier coverage canonical; T3 real-world
   corpus pre-mainnet hardening).
3. Pre-mainnet calibration of Adamant-native structural
   limits in `validator/config.rs` (per §6.2.1.7
   amendment workstream registered at B-1 / B-3.4 / B-6
   / E-7).
4. Bytecode-format genesis-fixed parameters review (gas
   costs, structural limits) before mainnet.

Phase 5/5b CLOSED. Next phase (5/5c or 5/6) awaits
direction.

## Phase 5/5c — Tier-based cross-validation coverage discipline (NEW pattern category at F-1)

Phase 5/5c formalizes the **T0 + T1 + T2 + T3** tier
framework defined in CLAUDE.md Section 10 Open Properties
#1, registered as a NEW methodology pattern category at
F-1 plan-gate Q4 disposition. Tier-based-cross-validation-
coverage-discipline is methodologically novel — not a
refinement of prior canonical principles but a new pattern
category. Future workstreams (security tiers in Phase
5/5b.6+ if the spec amendments warrant; runtime tiers at
Phase 5/6) may benefit from analogous tier-based shapes.

### Tier framework

| Tier | Coverage criterion | Phase 5/5c disposition |
|---|---|---|
| **T0** | Every Adamant-native pass has at least 1 positive AND at least 1 negative Layer A fixture (audit-table evidence per pass) | F-1 audit closure (this section) |
| **T1** | Every typed `AdamantValidationError` variant has at least 1 explicit negative test asserting on the variant shape | F-1 audit closure (re-registers existing variant-vs-test mapping audit as canonical T1 closure) |
| **T2** | Every Sui error mode produces a fixture that triggers it in Adamant with same accept/reject decision (Layer B parity) | F-2 D-5a + D-5b Layer B parity backfill + F-3 T2 audit closure |
| **T3** | Real-world corpus of compiled Sui-Move modules exercised against Adamant's verifier as integration cross-validation | **Deferred to pre-mainnet hardening** as stretch goal |

### Tier-framework-crystallizes-existing-discipline meta-observation

Per Q4 refinement at F-1 plan-gate, the tier framework
operates as **retroactive classification of pre-existing
canonical principles** rather than introducing fresh
requirements:

- **T0 = positive+negative-fixture-pair-per-pass discipline**
  (operational since Phase 5/5b.2 B-1; implicit in every
  per-pass test surface).
- **T1 = variant-vs-test mapping audit principle**
  (canonical at Phase 5/5b.3 C-3; retroactive audits at
  C-5 + D-7b + E-7).
- **T2 = Layer B parity discipline**
  (operational since Phase 5/5b.2 B-2.2 with the
  `assert_pass_parity` helper extraction; D-7a Layer B
  backfill consolidated the function_pass shape).
- **T3 = real-world-corpus discipline**
  (deferred since CLAUDE.md Open Properties registration;
  pre-mainnet hardening venue).

Methodology consequence: tier framework operates as a
unified-classification view over four pre-existing
canonical principles. Re-registration as canonical at
Phase 5/5c surfaces the relationship between the
principles + adds the per-tier formal closure shape.

Worth canonical methodology-meta registration: tier
framework is itself a methodology pattern (NEW at F-1)
that crystallizes pre-existing discipline rather than
introducing fresh requirements. Future tier-based
disciplines (e.g., security-tier at later phases) may
inherit the retroactive-classification posture.

### T0 audit closure (F-1)

**Audit method:** for each Adamant-native pass + rule
module, empirically count test functions; confirm
presence of positive (accepting) and negative
(rejecting) fixtures.

**Audit results:** every Adamant-native pass with
rejection conditions has both positive and negative
Layer A coverage. The architectural-position pin module
(`rule_08_bounded_loops`) has only positive coverage by
design — Rule 8 has no rejection condition at the
verifier layer per amendment 804d9db; the architectural-
position-confirmation testing sub-pattern (E-5
registration) is the canonical T0 shape for explicit-
non-enforcement rules.

#### Module-level passes (step 3; 11 passes)

| Pass | Sub-checkpoint | Total Layer A tests | Has pos+neg | Status |
|---|---|---|---|---|
| `bounds_checker` | C-1 | 162 | ✓ | ✓ T0 |
| `ability_field_requirements` | B-2.3 | 22 | ✓ | ✓ T0 |
| `constants` | B-2.1 | 39 | ✓ | ✓ T0 |
| `duplication_checker` | C-2 | 38 | ✓ | ✓ T0 |
| `friends` | B-2.2 | 12 | ✓ | ✓ T0 |
| `instantiation_loops` | B-3.3 | 18 | ✓ | ✓ T0 |
| `instruction_consistency` | B-2.4 | 30 | ✓ | ✓ T0 |
| `limits` | B-3.1 | 23 | ✓ | ✓ T0 |
| `privacy_metadata_structure` | B-4.2 | 14 | ✓ | ✓ T0 |
| `recursive_data_def` | B-3.2 | 17 | ✓ | ✓ T0 |
| `signature_checker` | C-3 | 19 | ✓ | ✓ T0 |

#### Per-function passes (step 4; 5 passes)

| Pass | Sub-checkpoint | Total Layer A tests | Has pos+neg | Status |
|---|---|---|---|---|
| `control_flow` | D-2 | 33 | ✓ | ✓ T0 |
| `stack_usage` | D-3 | 44 | ✓ | ✓ T0 |
| `locals_safety` | D-4 | 33 (mod.rs) | ✓ | ✓ T0 |
| `type_safety` | D-5a | 44 | ✓ | ✓ T0 |
| `reference_safety` | D-5b | 28 (pass.rs) + 5 (abstract_state.rs) + 21 (borrow_graph.rs) | ✓ | ✓ T0 |

#### Cross-module verifier (E-2)

| Pass | Sub-checkpoint | Total Layer A tests | Has pos+neg | Status |
|---|---|---|---|---|
| `cross_module/rule_03_privacy_consistency` | E-2b | 11 (+ 7 trait/API tests at E-2a) | ✓ | ✓ T0 |

#### Adamant-specific rules at step 5 (6 rules + Rule 5 at step 1 + Rule 8 architectural-position pin)

| Rule | Sub-checkpoint | Total Layer A tests | Has pos+neg | Status |
|---|---|---|---|---|
| Rule 1 (`rule_01_mutability`) | Wave 3a | 4 | ✓ | ✓ T0 |
| Rule 2 (`rule_02_privacy`) | B-4.1 | 14 | ✓ | ✓ T0 |
| Rule 3 (`rule_03_privacy_consistency` single-module) | D-5c | 15 | ✓ | ✓ T0 |
| Rule 4 (`rule_04_no_natives`) | Wave 3a | 2 | ✓ | ✓ T0 |
| Rule 5 (parse-time inside `adamant_deserialize`) | Wave 3a | (covered at deserializer test surface) | ✓ | ✓ T0 |
| Rule 6 (`rule_06_no_dynamic_dispatch`) | E-3 | 11 | ✓ | ✓ T0 |
| Rule 7 (`rule_07_privacy_circuit_in_shielded_only`) | E-4 | 13 | ✓ | ✓ T0 |
| Rule 8 (`rule_08_bounded_loops`) | E-5 | 1 | architectural-position pin only | ✓ T0 (pin shape) |

#### Pipeline integration (validator/mod.rs)

| Surface | Sub-checkpoint | Total tests | Has pos+neg | Status |
|---|---|---|---|---|
| `validator::verify_module` end-to-end | Wave 3a + B-5 + C-4 + D-6 | 34 | ✓ | ✓ T0 |

**T0 audit verdict at F-1 closure: 26 of 26 passes /
rules / surfaces have positive + negative Layer A
coverage** (or architectural-position-pin shape for
Rule 8 explicit-non-enforcement). **T0 closed at F-1.**

### T1 audit closure (F-1)

**Audit method:** re-register the existing variant-vs-
test mapping audit (canonical at C-3, retroactive audits
at C-5 + D-7b + E-7) as the canonical T1 closure. T1's
coverage criterion is exactly the variant-vs-test
mapping audit principle: every typed
`AdamantValidationError` variant has at least 1 explicit
negative test asserting on the variant shape.

**Audit results (referenced from E-7 closure):**

- C-5 retroactive audit: 50 of 50 variants covered (1
  gap: `SuiVerifier`, deferred to natural resolution at
  Phase 5/5b.5 bridge tear-out)
- D-7b incremental audit: 14 new variants covered (cumulative
  64 of 64; 1 gap unchanged from C-5)
- E-7 incremental audit: 3 new variants covered + 1
  removed-variant closure-of-record (cumulative 66 of
  66; 0 outstanding gaps after SuiVerifier removed at
  E-1a via gap-source-removal closure)

**T1 audit verdict at F-1 closure: 66 of 66
`AdamantValidationError` variants have explicit negative-
test coverage. 0 outstanding audit gaps. T1 closed at
F-1.**

Cross-references: see "Retroactive variant-vs-test
mapping audit (50 variants; C-5 closure)" + "Variant-vs-
test mapping audit appendix (14 new variants; D-7b
closure)" + "Variant-vs-test mapping audit appendix (3
new variants + 1 removed-variant closure-of-record; E-7
closure)" sections elsewhere in this file. T1 framework
re-uses the existing audit infrastructure rather than
duplicating.

### T2 audit framework (F-1; full audit at F-3)

T2's coverage criterion: every Sui error mode produces a
fixture that triggers it in Adamant with same accept/
reject decision (Layer B parity).

**T2 framework at F-1:**

- Per-pass Layer B helpers established at Phase 5/5b
  (module_pass `assert_pass_parity` at B-2.2;
  function_pass `test_helpers.rs` at D-7a).
- Composite-pipeline parity strategy operational (D-3
  stack_usage; D-4 locals_safety; D-7a backfill) per the
  Sui-public-API-shape-constrains-parity-helper sub-
  pattern (D-7b registration).
- Per-pass parity strategy operational where Sui's per-
  pass entry is `pub` (D-2 control_flow uses
  `move_bytecode_verifier::control_flow::verify_function`
  directly).

**T2 implementation gaps registered at F-1 plan-gate:**

- D-5a `type_safety` has no Layer B parity tests.
- D-5b `reference_safety` has no Layer B parity tests.

Both have Sui counterparts (`type_safety::verify` and
`locals_safety::verify` are `pub(crate)` in upstream;
composite-pipeline parity via `code_unit_verifier::verify_module`
is the strategy per the Sui-public-API-shape-constrains-
parity-helper sub-pattern). F-2 closes these gaps with
full Layer B backfill matching D-7a's shape.

**T2 closure: F-3 (post-F-2; the full T2 audit table
covering every Sui error mode lands at F-3 alongside the
Phase 5/5c closure batch).**

### T3 disposition (F-1; deferred to pre-mainnet hardening)

T3's coverage criterion: real-world corpus from compiled
Sui-Move source exercised against Adamant's verifier as
integration cross-validation.

Per CLAUDE.md Open Properties #1 + Q5 disposition at
F-1 plan-gate: **T3 deferred to pre-mainnet hardening as
a stretch goal.** Phase 5/5c closes T0+T1+T2 cleanly; T3
stays in pre-mainnet workstream. Rationale: foundation
work (corpus collection mechanism, fixture import format)
is premature given no current Sui-Move-source compilation
pipeline exists in adamant-vm; pre-mainnet hardening is
the natural venue.

**Plan-incremental-disposition sub-pattern β (deliberate-
deferral) reaches OPENING 4th instance** at F-1 with the
T3 disposition. Pattern instances:

1. D-4 Layer B fixture overhead opening (deferred to
   D-7a backfill)
2. D-5a.0 / D-5a.1 staging (deferred to D-5a.1.b
   orchestration)
3. D-5b.2 BorrowViolationReason 7-of-13 sub-reason audit
   gap (deferred to E-6 fixture closure)
4. T3 deferral at F-1 (deferred to pre-mainnet hardening)

Pattern stable beyond rule-of-three threshold (4
instances); operating consistently across phase
boundaries.

### Audit-table-pattern multiple sub-shapes

Audit-table shape now operates at 3 levels per F-1
disposition Q3:

- **Variant-vs-test mapping audit** (per-variant rows;
  established C-5 + D-7b + E-7; 3 instances)
- **T0 audit** (per-pass positive + negative test rows;
  Phase 5/5c F-1 1st instance)
- **T2 audit** (per-Sui-error-mode rows; F-3 work)

Three audit-table sub-shapes operating across cross-
validation discipline. Worth canonical registration that
audit-table-pattern has multiple sub-shapes per audit
dimension (per-variant / per-pass / per-error-mode).

Same posture as helper-extraction discipline three sub-
shapes registration (α / β / γ) and variant-count
discipline four sub-shapes (add / tear-out / no-op /
coverage-expansion). Pattern-cluster shape stable across
methodology areas.

### Phase 5/5c F-1 closure

F-1 lands T0 audit closure + T1 audit closure + T2
framework establishment + T3 disposition. F-2 closes T2
gaps via D-5a + D-5b Layer B parity backfill. F-3 is the
T2 audit + Phase 5/5c closure batch + Phase 5/5
cumulative closure.

**Phase 5/5c F-1 sub-arc state:**

- T0 audit: closed at F-1 (26 of 26 passes/rules/surfaces
  with pos+neg coverage or architectural-position-pin
  shape)
- T1 audit: closed at F-1 (66 of 66 variants covered;
  re-registers existing audit principle as canonical T1)
- T2 framework: established at F-1; gaps registered for
  F-2 backfill (D-5a + D-5b) + F-3 closure
- T3: deferred to pre-mainnet hardening per Q5 disposition

Phase 5/5c sub-arcs remaining: F-2 (D-5a + D-5b Layer B
parity backfill); F-3 (T2 audit + Phase 5/5c closure +
Phase 5/5 cumulative closure).
