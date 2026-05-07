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
- **Date of fork:** 7 May 2026 (B-1: `ability_cache`)

## What was forked

Phase 5/5b.2 B-1 (this commit):

- `AdamantAbilityCache` (port of upstream `AbilityCache`).
  Memoized resolver for the [`AbilitySet`] of a
  [`SignatureToken`], used by the `ability_field_requirements`
  pass landing in B-2.

Subsequent B-2 / B-3 / B-4 / B-5 / B-6 sub-arcs extend the fork:

- **B-2:** `constants`, `friends`, `instruction_consistency`,
  `ability_field_requirements`
- **B-3:** `limits`, `recursive_data_def`, `instantiation_loops`
- **B-4:** Rule 2 (`rule_02_privacy.rs`); landing in
  `crates/adamant-vm/src/validator/`, not in this subtree
- **B-5:** Pipeline integration in
  `crates/adamant-vm/src/validator/mod.rs`
- **B-6:** Workspace test pass + CLAUDE.md state-bump

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

Subsequent B-2 / B-3 sub-arcs extend the invariants list as
each pass lands.

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
