# Contributing to Adamant

This file collects per-environment notes for working in this repository.
As contributor concerns surface they are recorded here. Phase 1 only
carries the operational note below; broader contribution guidelines
(coding style, PR process, review expectations, signing) come later.

For project context and design discipline, see `CLAUDE.md` and the
canonical specification under `whitepaper/`.

## Build environment

### Windows: Application Control blocks `target/` (`os error 4551`)

On Windows machines running Windows Defender Application Control (WDAC)
or a managed corporate endpoint with a comparable exec-allowlist policy,
`cargo test` may compile successfully but fail to launch the resulting
test binary with:

> An Application Control policy has blocked this file. (os error 4551)

The build artifact is unsigned and the default `target/` directory is
not on the policy's allowed-execution list.

**Workaround.** Point cargo's build artifacts at a directory the policy
permits. The repository ships `.cargo/config.toml` with a commented-out
`[build] target-dir` entry — uncomment it and fill in an absolute path
that your machine allows to execute binaries (typical choices: `%TEMP%`,
`%LOCALAPPDATA%`, or a developer-specific allowlisted folder).

The setting is per-developer; do not commit a hardcoded path. The
shipped config file documents the symptom in-place so future
contributors hitting the same error can resolve it without searching.

## Linting discipline

### Verify, don't trust

When promoting a clippy lint or group, **verify the lint is actually
firing on a constructed example**. Do not trust that "no warnings"
means "watching." Lints in groups can be allow-by-default within the
group; some lints filter dev-dependencies; some require `publish =
true`. A silently-disabled lint is worse than no lint, because it
gives false confidence.

The verification ritual:

1. Promote the lint in `[workspace.lints.clippy]` (or in the
   per-crate lint table).
2. Construct a minimal change to the workspace that **should** trip
   the lint.
3. Run `cargo clippy --workspace --all-targets` and confirm the lint
   fires with the expected message.
4. Revert the constructed change.
5. Run clippy again and confirm clean.
6. Record the verification under "Verifications on record" below if
   the lint has unobvious triggering conditions.

A reviewer reading the workspace config later should be able to trust
that every promoted lint was exercised and is observably watching the
code.

### Verifications on record

- **`clippy::multiple_crate_versions`** — promoted explicitly to
  `warn` outside the `cargo` group, where it is allow-by-default.
  Verified on clippy 0.1.95 by temporarily adding direct `rand_core =
  "0.6"` and `rand = "0.9"` deps to `adamant-crypto`, producing two
  runtime-path versions of `rand_core` (0.6.4 and 0.9.5). Lint fires:

  ```
  warning: multiple versions for dependency `rand_core`: 0.6.4, 0.9.5
  ```

  Empirical scope of the lint: it catches **runtime/runtime**
  duplicates only. Runtime/dev and dev/dev splits (e.g., the
  workspace's existing `getrandom 0.3.4` vs `0.4.2` situation under
  proptest's tree) are silent. This is the correct behaviour for our
  concern — production crypto correctness depends on runtime-path
  version uniqueness — but it means a `cargo tree --duplicates`
  finding does not necessarily imply a lint fire.

  **Known allowlist:** `cpufeatures` is allowlisted in `clippy.toml`
  because the addition of `blake3 =1.8.5` (whitepaper 3.3.2) forced a
  real runtime-path duplicate against `sha3 =0.10.9`'s transitive
  `keccak 0.1.6` chain. `cpufeatures` is a CPU-feature-detection
  helper, not a cryptographic primitive — out of scope for the
  policy-rationale of this lint. See `clippy.toml` for the full
  rationale and revisit conditions.

## Cryptographic discipline

### RNG injection: production receives, tests construct

Production crypto code that needs randomness MUST receive its RNG from
the caller, parameterised over the `rand_core::CryptoRngCore` trait.
The workspace declares `rand_core = { version = "0.6", default-features
= false }` — trait surface only, no concrete RNG implementations.

Tests that need an actual OS RNG construct `rand_core::OsRng` via the
`getrandom` feature, declared in the `[dev-dependencies]` table of the
crate that needs it:

```toml
[dev-dependencies]
rand_core = { workspace = true, features = ["getrandom"] }
```

`getrandom` has platform-specific behaviour (different syscall trees on
Linux, macOS, Windows, iOS, WASM, embedded) that we do not want baked
into the production crypto path. Callers of these crates will pick a
CSPRNG appropriate to their deployment environment; the wrapper crates
stay neutral.

The same pattern applies to every randomness-consuming primitive in
the workspace — Ed25519 today, ML-DSA next, BLS later. Lock the rule
down once; do not re-derive it per primitive.

### Spec-first verification

When implementation surfaces a question that contradicts or appears
to contradict the whitepaper, stop and verify against authoritative
sources before proceeding. Twenty-six confirmed instances during
Phases 1, 2, 4, and 5:

- **BIP-340 tagged-hash construction** (whitepaper 3.3.1) — the
  original "fixed-length domain tag" text admitted prefix collisions
  with variable-length tags; resolved by spec revision pinning the
  BIP-340 construction (commit 62bfe89).
- **ML-DSA-65 signature size** (whitepaper 3.4.2) — the original
  3293-byte figure was the CRYSTALS-Dilithium round 3 number,
  superseded by the FIPS 204 final 3309-byte figure; resolved by
  spec revision (commit 30bf5ac).
- **Threshold-encryption construction** (whitepaper 3.6) — the
  original wording named "Boneh-Lynn-Shacham IBE combined with
  Shamir secret sharing" without specifying group orientation, KEM
  vs PKE shape, hash-to-curve DST, KDF construction, or
  decryption-share verification equation; the spec was incomplete
  enough that implementing it required design decisions beyond the
  whitepaper's text. Resolved by spec revision adding §3.6.1
  ("Cryptographic construction") with full algorithm specification
  including the `BLS_TE_…` DST and the `ADAMANT-v1-threshold-kdf`
  KDF tag (commit db4341c).
- **Canonical serialisation and proof-commitment encoding**
  (whitepaper 5.1.7, 5.1.8) — Phase 2 surfaced two related gaps:
  (a) the canonical byte encoding for every value flowing through
  consensus was unspecified, and (b) the `proof_commitment` field
  in `ObjectMetadata` was named without specifying its size or
  encoding. Resolved by spec revision adding §5.1.8 pinning
  **BCS** (Binary Canonical Serialization, the format used by Sui
  and Aptos) as the canonical encoding, and clarifying §5.1.7 that
  `proof_commitment` is a 48-byte compressed-G₁ KZG commitment on
  BLS12-381 (commit 3579655).
- **Lifecycle transition graph** (whitepaper 5.4, 5.4.1) — Phase 4
  surfaced seven related gaps: §5.4 enumerated the lifecycle states
  (Active, Frozen, Archived, Destroyed) but did not pin the
  transition graph between them, leaving Frozen → Archived and
  Frozen → Destroyed legality, the target lifecycle of restoration
  (Active or Frozen?), Destroyed terminality, Active → Frozen
  exclusivity, Archived → Destroyed legality, and restoration
  version semantics all under-specified. The §5.1.4 inline comment
  on `UpgradeableUntilFrozen` further mis-suggested that the
  `Mutability` field mutates post-freeze, contradicting §5.1.4's
  own "the declaration is itself immutable" rule. Resolved by spec
  revision adding §5.4.1 ("The transition graph") with the full
  4×4 matrix plus seven explicit properties, correcting the §5.1.4
  inline comment to pin Mutability-stays / Lifecycle-changes, and
  amending §5.6.2 to specify lifecycle and version preservation
  across archival round-trips (commit 91ca61d).
- **Transaction format** (whitepaper 6.0, 5.1.1 amendment) — Phase
  5's first deliverable proposal surfaced eight related gaps: §4.3,
  §5.1.1, §6.2.2, §6.3, and §6.4 all referenced "transaction"
  informally without any section pinning the `Transaction` struct's
  fields, encoding, or derived `TxHash`. The gaps spanned the
  Transaction structure (no canonical fields), `TxHash` derivation
  (no formula or domain tag), the body / auth-evidence split (no
  pinned signature carriage), the read/write/created-objects
  declaration format, the authorising account and fee-payer naming,
  the gas budget structure (per-dimension vs combined), the
  privacy-mode declaration, and module deployment as a transaction
  kind (special variant or regular call). Resolved by spec revision
  adding §6.0 ("Transactions: the input to execution") with §6.0.1
  body/evidence split, §6.0.2 body fields including version-pinned
  read sets and explicit `created_objects`, §6.0.3 auth evidence
  shape, §6.0.4 `TxHash = sha3_256_tagged(TX_HASH, BCS(body))` with
  new domain tag `b"ADAMANT-v1-tx-hash"`, §6.0.5 implicit privacy
  from function annotation, and §6.0.6 BCS canonicality and
  hard-fork-fixedness; and amending §5.1.1 to forward-reference
  §6.0.4 and §6.0.2 explicitly (commit 869112a).
- **Inner-type canonical encodings** (whitepaper 6.0.7) — §6.0
  referenced inner types (`Signature`, `Witness`, `StealthCommitment`,
  `ModuleRef`, `FunctionId`, `Value`) by name without pinning their
  canonical encodings — six related sub-gaps surfaced during Phase
  5's re-proposal cycle. Resolved by spec revision adding §6.0.7
  ("Inner-type canonical encodings"), which pins each type's BCS
  wire format (variant tags, fixed sizes, length bounds) while
  deferring the cryptographic construction of `StealthCommitment`
  and the contents of `Witness` to §7 (privacy layer) and the
  layout of any specific user-defined struct value to §6.2.1
  (bytecode format). The encoding/construction split is deliberate:
  the wire format is consensus-critical and pinnable now; the
  construction semantics belong in the sections that define each
  type's cryptographic or runtime role (commit 41ddb41).
- **Bytecode format** (whitepaper 6.2.1, 6.1.3 correction) — §6.2.1
  was a seven-line prose paragraph naming instruction classes; the
  specification needed for an independent implementation was
  under-specified across ten related areas: dialect choice (Diem /
  Sui / Aptos / custom), module file format, instruction-set
  enumeration with opcodes, operand encoding, register/stack
  architecture (the prose said "register-based" but §6.1.3 claimed
  "strict superset of standard Move bytecode" — a contradiction,
  since all Move dialects are stack-based), object-reference
  representation in bytecode, privacy/mutability annotation
  encoding, validator rules, type-system encoding, and
  per-instruction gas costs. Resolved by spec revision expanding
  §6.2.1 into seven subsubsections: §6.2.1.1 pins Sui-Move as the
  bytecode substrate (chosen because §5's object model is itself
  Sui-derived); §6.2.1.2 inherits Sui's `CompiledModule` binary
  format (`move-binary-format`); §6.2.1.3 specifies module-level
  mutability metadata (`b"adamant.mutability"`) and a function-level
  privacy-annotation byte; §6.2.1.4 inherits Sui's instruction set
  and adds 17 Adamant-specific extensions (privacy operations,
  proof primitives, hash and signature verification, gas
  manipulation); §6.2.1.5 inherits Sui's variable-length operand
  encoding; §6.2.1.6 inherits Sui's `move-bytecode-verifier` and
  adds eight Adamant-specific validator rules; §6.2.1.7 frames
  per-instruction gas costs (full table deferred to a normative
  appendix). §6.1.3 also corrected: the forward-reference now
  points at §6.2.1, and the bytecode architecture is explicit as
  stack-based (commit 5489d09).
- **CircuitId resolution path** (whitepaper 6.2.1.4) — the Phase 5
  AdamantBytecode extension enum proposal surfaced that §6.2.1.4
  referenced "the module's circuit-reference pool" as the operand
  source for `GenerateProof` and `VerifyProof`, but §6.2.1.2's
  `CompiledModule` layout (which inherits Sui-Move's pool list
  unchanged) does not include such a pool. Without resolution,
  defining the bytecode-layer `CircuitId` would have required
  either inventing a circuit pool inside §6.2.1.2 (a leaky
  abstraction since circuits are §7-territory) or shipping
  `CircuitId` with under-specified resolution semantics that the
  privacy-layer work would later have to reconcile. Resolved by
  spec amendment adding a "CircuitId resolution" paragraph to
  §6.2.1.4 deferring the pool's location and structure to §7
  (chain-wide registry vs per-module pool to be decided in §7),
  while pinning that the bytecode-layer `CircuitId` is an opaque
  u16. This applies the encoding/construction split established
  in §6.0.7 to bytecode operands: encoding pinned now, semantic
  construction deferred to the section that defines the role
  (commit 0d3a957).
- **Per-extension operand encodings** (whitepaper 6.2.1.5) — the
  Phase 5 bytecode wire encoding deliverable proposal surfaced
  that §6.2.1.5 specified generic operand-encoding rules
  (ULEB128 indices, fixed-width little-endian immediates) for
  inherited Sui-Move bytecode but did not pin per-extension
  operand layouts for the 17 Adamant-specific instructions per
  §6.2.1.4. Three operand types appear across the extensions
  (`FunctionHandleIndex`, `CircuitId`, `GasDimension`), each
  needing an explicit encoding choice; without resolution the
  implementation would have pinned the encodings silently at
  first commit, exactly the failure mode the discipline exists
  to prevent. Resolved by spec amendment adding a "Per-extension
  operand encodings" paragraph to §6.2.1.5 pinning each:
  `FunctionHandleIndex` as ULEB128 (matching Sui-Move's
  inherited encoding); `CircuitId` as ULEB128 (matching
  Sui-Move's encoding pattern for other indices, treating
  `CircuitId` as an index per §6.2.1.4's framing); `GasDimension`
  as a single byte variant tag 0x00–0x05 in declaration order
  matching `GasBudget`'s field order from §6.0.7 (matching the
  variant-tag pattern from §6.0.7's `Value` enum); and the 11
  zero-operand extensions carrying no operand bytes. These
  encodings are genesis-fixed; changing any is a hard fork
  (commit 84e60d0).
- **`LdU256` operand endianness** (whitepaper 6.2.1.5) — the
  Phase 5 bytecode wire encoding implementation needed to commit
  the `match Bytecode::LdU256(value)` arm to a specific byte
  order. §6.2.1.5 specified "32 big-endian bytes matching section
  6.0.7's `Value::U256` encoding," but Sui-Move's inherited
  `write_u256` (at
  `vendor/move-binary-format/src/file_format_common.rs:480` and
  `vendor/move-core-types/src/u256.rs:313`) encodes
  `value.to_le_bytes()` — little-endian. The spec contradicted
  §6.2.1.1's "strict superset of Sui-Move bytecode" commitment
  and Sui's actual implementation. The same sentence specified
  `LdU64` and `LdU128` as little-endian (correct, matching
  Sui-Move) before switching to "big-endian" for `LdU256` with a
  §6.0.7 cross-reference; the cross-reference was the source of
  the editorial slip, since §6.0.7's BCS `U256` is big-endian but
  BCS and bytecode are different encoding paths. Without
  resolution, the implementation would have made a
  consensus-critical encoding choice silently — exactly the
  failure mode the discipline exists to prevent. Resolved by
  amending §6.2.1.5: `LdU256` is now specified as 32 little-endian
  bytes matching Sui-Move's inherited encoding, with an explicit
  follow-on paragraph acknowledging the divergence from §6.0.7's
  BCS encoding and noting that the two paths never share bytes
  (bytecode operands appear inside Move binary modules; BCS-encoded
  values appear in transaction arguments and on-chain typed
  values) (commit 83bb1e9).
- **Privacy byte storage location** (whitepaper 6.2.1.3) — the
  Phase 5 validator-rules deliverable proposal surfaced that
  §6.2.1.3 specified privacy annotations as "appended to
  Sui-Move's standard function definition layout," implying a
  per-function field on Sui-Move's `FunctionDefinition`. Empirical
  investigation of vendored Sui-Move (at
  `vendor/move-binary-format/src/file_format.rs:529-553`) found
  that `FunctionDefinition` has fields exactly: `function`,
  `visibility`, `is_entry`, `acquires_global_resources`, `code` —
  no extension hook. Adding a privacy-byte field would require
  patching vendored Sui-Move, contradicting §6.2.1.1's
  strict-superset commitment and the byte-faithfulness audit
  anchor established at the wire encoding deliverable. Without
  resolution, the implementation would have either patched the
  vendored binary format (regressing the audit anchor) or silently
  invented a workaround — exactly the failure mode the discipline
  exists to prevent. Resolved by amending §6.2.1.3: privacy
  annotations move to a module-level metadata entry
  `b"adamant.privacy"` whose value is the BCS encoding of
  `Vec<(FunctionDefinitionIndex, u8)>`, matching the pattern
  Rule 1 uses for `b"adamant.mutability"`. `FunctionDefinition`
  stays inherited from Sui-Move unchanged (commit 804d9db).
- **Bounded-loops algorithm undefined** (whitepaper 6.2.1.6
  Rule 8) — the same Phase 5 validator-rules deliverable proposal
  surfaced that §6.2.1.6 Rule 8 specified "the verifier uses
  Sui-Move's existing loop-bound analysis as a starting point and
  tightens it: any loop whose bound is not provable is rejected."
  Empirical investigation of vendored Sui-Move (at
  `vendor/move-bytecode-verifier/src/loop_summary.rs:29`) found
  that the named module implements Tarjan's loop reducibility —
  CFG structural analysis (back-edge identification, DFS spanning
  tree) — and does not bound iteration counts. There is no
  upstream loop-bound analysis to extend. Without resolution, the
  implementation would have either invented a bound algorithm
  silently (likely incomplete or undecidable in practice for
  adversarial bytecode) or shipped an incorrect static check.
  Resolved by amending §6.2.1.6 Rule 8: drop static loop-bound
  analysis at verification time; the gas budget at runtime
  carries the determinism guarantee already specified at §6.2.4
  ("All loops must have statically-bounded iteration counts or
  run within a gas budget that bounds them dynamically"). Rule 8
  becomes a no-op at deployment. The amendment text explicitly
  acknowledges the original drafting error rather than silently
  revising — same audit-trail honesty as the §6.2.1.4
  register-vs-stack correction (commit 804d9db).
- **Dynamic-field operations enumeration** (whitepaper 6.2.1.6
  Rule 6) — the same Phase 5 validator-rules deliverable proposal
  surfaced that §6.2.1.6 Rule 6 specified "Sui-Move's
  dynamic-field operations are restricted" without pinning which
  `(module_address, module_name, function_name)` tuples
  constitute "dynamic-field operations." Sui exposes dynamic-field
  functionality across two standard library modules —
  `0x2::dynamic_field` and `0x2::dynamic_object_field` — each
  with multiple functions (`add`, `borrow`, `borrow_mut`,
  `exists_`, `exists_with_type`, `remove`, etc.). Without an
  explicit specification, the implementation would have made a
  silent consensus-critical choice about which Sui standard
  library calls trigger the restriction — exactly the failure
  mode the discipline exists to prevent. Resolved by amending
  §6.2.1.6 Rule 6: pin the rule's scope at the module level —
  calls to functions whose target module address is `0x2` and
  whose module name is `dynamic_field` or `dynamic_object_field`.
  Pinning at the module level (rather than enumerating individual
  function names) ensures future Sui standard library additions
  to those modules are automatically captured by the rule without
  further spec amendment (commit 804d9db).
- **Cross-module privacy consistency under upgrades** (whitepaper
  6.2.1.6 Rule 3, with supporting amendment to 6.4.3) — the same
  Phase 5 validator-rules deliverable proposal surfaced that
  §6.2.1.6 Rule 3 specified "the verifier statically checks the
  entire call graph reachable from each public function" without
  addressing how cross-module calls verify against modules whose
  annotations might change post-deployment. Three related
  sub-gaps surfaced: (a) for cross-module calls the deploy-time
  verifier sees the deploying module but consults dependency
  modules from chain state, raising the question of whether
  deploy-time-only checking is sufficient; (b) once loaded,
  dependency modules might be upgraded later, invalidating the
  deploy-time check; (c) the AVM must enforce privacy at runtime
  regardless because shielded execution structurally requires
  shielded context (proof generation infrastructure, encrypted
  operand stack), so a runtime check is unavoidable. Without
  resolution, the implementation would have silently chosen one
  of (i) runtime-only enforcement (giving up the static
  deployer-feedback layer), (ii) deploy-time-only (leaving
  runtime mismatches uncovered when upgrades cause staleness), or
  (iii) restricting Rule 3 to in-module call graphs (defeating
  the purpose of static cross-module privacy verification).
  Resolved by amending §6.2.1.6 Rule 3 with explicit
  defense-in-depth framing: runtime enforcement is the
  consensus-binding mechanism (the AVM aborts privacy-mismatched
  calls at the call boundary regardless of deploy-time
  verification); deploy-time static check is the deployer-feedback
  and gas-trap-prevention layer. The deploy-time guarantee is
  made durable across upgrades by a supporting amendment to
  §6.4.3 adding privacy annotations on public functions to the
  upgrade-compatibility contract: `#[transparent]` and
  `#[shielded]` cannot change across upgrades, so dependent
  modules deployed against an upstream module's privacy
  annotations can rely on those annotations remaining stable. The
  §6.4.3 amendment is itself not a contradiction-resolution but a
  strengthening constraint that closes the gap Rule 3 would
  otherwise leave open across the deployed module's lifetime
  (commit 804d9db).
- **Module deserializer architecture** (whitepaper 6.2.1.1,
  6.2.1.2, 6.2.1.8) — the Phase 5 fifth deliverable's Wave 3b
  proposal investigation surfaced an integration gap between the
  language-level "strict superset" claim of §6.2.1.1 and the
  scope of the vendored Sui-Move crates from Phase 5/4 (commit
  e6ca254). Empirical reading of vendored Sui-Move:
  `vendor/move-binary-format/src/deserializer.rs:1717` is a
  closed-match opcode dispatch, with line 2112's `_ =>
  Err(... UNKNOWN_OPCODE)` rejecting any byte outside Sui's
  `0x01..=0x56` range. Adamant's reserved extension range
  `0x80..=0x90` (per §6.2.1.4 and the AdamantOpcodeKind type)
  falls into the UNKNOWN_OPCODE bucket — Sui's deserializer
  rejects modules containing Adamant extension opcodes outright.
  Sui's per-instruction verifier passes (StackUsageVerifier,
  type_safety, locals_safety, reference_safety, control_flow,
  InstructionConsistency) likewise use exhaustive matches over
  Sui's `Bytecode` enum, with no representation for Adamant
  extensions. Phase 5/3's wire encoding (commit 0d88e8e) was
  function-body-level only and never integrated with the
  CompiledModule deserializer. The strict-superset claim was
  correct at the language level (every Sui-Move-respecting
  Adamant module is shape-equivalent to a Sui module) but the
  vendored crates handle Sui-base only; a conforming
  implementation needs an Adamant-native deserializer and a
  projection mechanism to feed the Sui-base subset into Sui's
  verifier passes. The Wave 3a wrapper slipped past this gap
  because every Wave 3a fixture used pure-Sui bytecode. Without
  resolution, the implementation would have either patched
  vendored Sui-Move to recognise Adamant extensions (regressing
  the byte-faithfulness audit anchor established at commit
  4164e7b) or silently produced an integration that rejected
  Adamant modules at the deserialize boundary — exactly the
  failure mode the discipline exists to prevent. Resolved by
  amending §6.2.1.1 to distinguish the language-level superset
  property from the vendored-crate scope (cross-referencing the
  new §6.2.1.8); amending §6.2.1.2 to remove stale per-
  FunctionDefinition privacy-annotation-byte text (privacy
  annotations were already relocated to module-level metadata in
  commit 804d9db); and adding new §6.2.1.8 ("Module deserializer
  and verifier-projection architecture") pinning the
  Adamant-native deserializer (delegating to vendored Sui logic
  for Sui-base instructions and module-level structure; using
  §6.2.1.5 wire encoding for extensions; rejecting non-canonical
  encodings), the Sui-projection mechanism (one-for-one
  substitution of extension instructions with `Bytecode::Nop`
  per `vendor/move-binary-format/src/file_format.rs:1682` —
  opcode `0x28`, (0,0) stack effect, already idiomatic in Sui's
  own test fixtures per
  `vendor/move-binary-format/src/unit_tests/binary_tests.rs:29`),
  the rationale for Nop substitution over alternatives
  (stripping requires consensus-critical offset rewriting on
  branch targets; per-function exclusion surrenders verifier
  coverage on the highest-value functions), what Sui's verifier
  proves on the projection (over the Sui-base subset only) and
  what it does not prove (per-instruction semantics of Adamant
  extensions, deferred to §6.2.1.6 rules and the AVM runtime per
  §6.2.2), and the five-step deployment-validator pipeline
  (Adamant-native deserialize, canonical-encoding round-trip,
  Sui-projection construction, inherited Sui verifier,
  Adamant-specific rules) (commit 61cec44).
- **`GenerateProof` and `VerifyProof` operand-stack pop counts
  under-specified** (whitepaper 6.2.1.4) — the same Wave 3b
  investigation read per-extension stack effects empirically
  against §6.2.1.4 and surfaced that the spec text said "Pops
  circuit inputs from the stack; pushes a `Witness` value" for
  `GenerateProof` and "Pops `Witness` and public inputs from the
  stack; pushes a `bool`" for `VerifyProof` without enumerating
  the pop count. The count is parametric in the circuit signature
  resolved through the operand's `CircuitId`; Sui's
  `StackUsageVerifier` would need either an invented count or a
  signature-lookup mechanism the spec did not pin. Without
  resolution, the implementation would have either invented a
  count silently or deferred to a circuit-signature lookup the
  spec did not pin — exactly the failure mode the discipline
  exists to prevent. Resolved by amending §6.2.1.4: stack
  effects for these two extensions are explicitly parametric in
  the circuit signature, mirroring how Sui-Move's `Call` stack
  effect is parametric in its `FunctionHandle`'s signature. The
  circuit's input arity and per-input types (`GenerateProof`)
  and the public-input arity and types (`VerifyProof`) are
  determined by the circuit signature; circuit signature
  resolution itself stays deferred to §7 (privacy layer) per
  the encoding/construction split established in §6.0.7
  (commit 61cec44).
- **`RecursiveVerify` operand-stack pop count under-specified**
  (whitepaper 6.2.1.4) — same shape as the seventeenth instance,
  applied to the recursive circuit's public-input arity. The
  spec text said "Pops the proof and the public inputs from the
  stack; pushes a `bool`" without enumerating the public-input
  count, which is parametric in the recursive circuit's signature
  per §8.5. Without resolution, same silent-choice failure mode.
  Resolved by amending §6.2.1.4 with parametric framing parallel
  to the seventeenth instance's resolution; the recursive
  circuit's public-input arity is resolved per §8.5
  (commit 61cec44).
- **`InvokeShielded` and `InvokeTransparent` reference-safety
  semantics under-specified** (whitepaper 6.2.1.4) — the same
  Wave 3b investigation surfaced that §6.2.1.4 specified "Stack
  effect matches `Call`" for `InvokeShielded` and
  `InvokeTransparent` without addressing reference-safety
  semantics. Sui-Move's `Call` performs borrow-graph updates when
  its signature contains references (per
  `vendor/move-bytecode-verifier/src/reference_safety/mod.rs`);
  the Adamant invokes presumably need the same treatment when
  their target function's signature includes reference parameters
  or returns, but the spec did not pin this. Without resolution,
  the implementation would have silently chosen whether
  borrow-graph updates apply to these extensions, leaving a
  verifier-vs-runtime drift surface. Resolved by amending
  §6.2.1.4 to make reference-safety semantics identical to Sui's
  `Call` for the same signature shape: when the target function's
  signature contains reference parameters or returns, the
  borrow-graph effect of `InvokeShielded` and `InvokeTransparent`
  is identical to `Call`; the verifier and AVM runtime treat
  reference inputs and outputs of these instructions exactly as
  they would for an inherited `Call` (commit 61cec44).
- **Nop-projection mechanism empirically broken; resolved by
  fully-Adamant-native verifier architecture** (whitepaper
  6.2.1.8 re-amended, with cross-reference to 6.2.1.1 also
  re-amended) — the §6.2.1.8 amendment that landed at commit
  61cec44 specified a Sui-projection mechanism with
  `Bytecode::Nop` substitution: each Adamant extension
  instruction in a function body would be substituted by Sui's
  `Nop` to produce a Sui-Move `CompiledModule` that Sui's
  verifier could process, on the claim that Sui's per-instruction
  passes establish their guarantees over the Sui-base subset of
  the projection. The Phase 5/5 implementation proposal
  investigation read the four Sui per-instruction passes
  empirically against the 17 Adamant extension stack/type/
  reference effects per §6.2.1.4 and surfaced that the
  projection mechanism does not actually pass Sui's verifier on
  non-trivial Adamant code. Empirical citations:
  `vendor/move-bytecode-verifier/src/stack_usage_verifier.rs:209`
  shows `Bytecode::Nop` has `(0, 0)` stack effect, while
  per-instruction effects for the 17 extensions per §6.2.1.4 are
  nonzero for 16 of them (only `OutOfGas` is exempt as a
  terminal abort);
  `vendor/move-bytecode-verifier/src/type_safety.rs:647` shows
  `Nop` is a no-op for the abstract type stack while extensions
  change typed stack contents per §6.2.1.4 (e.g., `Sha3_256`
  pops `vector<u8>` and pushes `[u8; 32]`);
  `vendor/move-bytecode-verifier/src/locals_safety/mod.rs:97-177`
  shows `Nop` in the locals-no-op arm and confirms locals_safety
  is structurally inert to Adamant extensions (none of the 17
  touch local-variable state);
  `vendor/move-bytecode-verifier/src/reference_safety/mod.rs:346`
  shows `Nop` is a borrow-graph no-op while
  `InvokeShielded`/`InvokeTransparent` with reference signatures
  perform `Call`-shaped borrow-graph updates per the nineteenth
  instance's amendment. Concrete trace: function body
  `[LdU64(5), ChargeGas(Computation), Ret]` balances under
  Adamant semantics (`+1, -1, 0` running stack increment, ends
  at 0); projection `[LdU64(5), Nop, Ret]` fails Sui's
  `POSITIVE_STACK_SIZE_AT_BLOCK_END` check (`+1, 0, 0` running
  increment, ends at +1). Three of four per-function passes
  break on Nop projection for non-trivial extension usage:
  `StackUsageVerifier` (16/17 extensions), `type_safety` (16/17),
  `reference_safety` (`InvokeShielded`/`InvokeTransparent` with
  reference signatures); only `locals_safety` is structurally
  inert. Without resolution, the implementation would have built
  a ~1500-2000 LOC deserializer + projection mechanism only to
  discover at integration time that the projection itself fails
  Sui's verifier on virtually every Adamant module — caught
  before implementation began rather than after. Resolved by
  re-amending §6.2.1.8 to fully Adamant-native verifier
  architecture: Adamant provides its own deserializer,
  serializer, module-level passes, and per-function passes
  covering the full Adamant superset; vendored Sui-Move crates
  serve as a test-time reference implementation against which
  Adamant's verifier is cross-validated for the inherited
  subset's semantics. Three architectural considerations drove
  the resolution: empirical infeasibility of any projection
  mechanism that preserves Sui's guarantees while avoiding
  branch-target offset rewrite (alternatives to Nop substitution
  either re-introduce the offset-rewrite consensus risk that the
  original investigation ruled out, or surrender Sui's coverage
  entirely on extension-containing functions, or require
  patching vendored Sui to expose private per-pass functions —
  none clean); genesis-fixed posture (verifier accept/reject is
  consensus-binding and cannot drift with Sui upstream, so
  binding our hot path to upstream behaviour was structurally
  wrong); audit surface (a fully-Adamant-native verifier is
  under Adamant's audit and maintenance, with no
  "what does Sui do here" hot-path question for auditors).
  §6.2.1.1 also amended at the same commit: the implementation
  note moved from "authoritative reference for the inherited
  substrate" to "reference implementation for the inherited
  substrate's semantics" — vendored Sui crates no longer on the
  deploy-time hot path. Phase 5/5 deliverable scope expanded
  from ~1500-2000 LOC (deserializer + projection) to
  ~5500-9000 LOC across four sub-deliverables (5/5a deserializer
  + serializer; 5/5b module-level passes; 5/5c per-function
  passes; 5/5d cross-validation infrastructure against the
  vendored reference) (commits 0de50d8, 2401227).
- **§6.2.1 + §6.2.1.8 resistant-proof posture** (whitepaper
  6.2.1, 6.2.1.8) — Phase 5/5b restructured-proposal review
  surfaced the question of whether vendored Sui-Move crates
  should remain on the deploy-time hot path during the 5/5b →
  5/5c transitional window. Initial Claude Code proposal kept a
  transitional Sui-verifier bridge for module-level passes
  during 5/5b; review escalated the architectural commitment in
  two stages: first to "close the verification gap entirely"
  (full Adamant-native verifier coverage at the moment we drop
  the Sui bridge, with per-function passes promoted from old
  5/5c into 5/5b), then to "Adamant must work fully
  independently of Sui's codebase — resistant-proof against
  upstream changes, shutdowns, vulnerabilities, and governance
  shifts." The escalation extended the prior re-amendment's
  "fully Adamant-native verifier" commitment (instance 20) from
  a verifier-only property to a deploy-time-and-runtime
  property: vendored Sui crates do not appear in the production
  binary's dependency graph at all, with test-only,
  build-tooling-only, and CI-only dependencies explicitly carved
  out as permitted. Resolved by amending §6.2.1.8 in four
  locations: opening paragraph to introduce the resistant-proof
  posture and the carve-out language; cross-validation
  paragraphs to nail down that vendor refresh surfacing
  divergence is a development-time signal, not a consensus
  event; closing implementation note to fix the production-build
  dependency posture alongside the externally observable
  accept/reject behaviour. §6.2.1's implementation note also
  amended at the same commit: protocol behaviour on the
  inherited subset is defined by sections 6.2.1.1–6.2.1.8 of
  the specification, with Sui's reference implementation
  consulted at test time to confirm semantic parity rather than
  relied on as the binding source of truth — a semantic shift
  from "Sui defines the inherited subset's behaviour" to
  "Adamant's spec is self-contained; Sui is a cross-validation
  tool." The architectural escalation drove a Phase 5/5
  restructure: from 4 sub-deliverables (5/5a closed; 5/5b
  module-level passes; 5/5c per-function passes; 5/5d
  cross-validation) to 3 sub-deliverables (5/5a closed; 5/5b
  full Adamant-native verifier covering both module-level and
  per-function passes plus Rules 2, 3, 6, 7; 5/5c
  cross-validation infrastructure formalization) with 5/5b
  further split into 6 sub-arcs (5/5b.1a foundation fork of
  constants + readers + AbilitySet + Identifier into a new
  `adamant-bytecode-format` crate; 5/5b.1b 25 type-definition
  fork; 5/5b.2 small/medium module-level passes + Rule 2; 5/5b.3
  large module-level passes + partial pipeline integration;
  5/5b.4 per-function passes infrastructure + Rule 3; 5/5b.5
  type-safety + reference-safety per-function passes + Rules 6,
  7 + final pipeline integration with Sui-verifier bridge fully
  removed). Phase 5/5b LOC estimate revised to ~10,600-14,950
  LOC; total Phase 5/5 ~19,000-27,000 LOC against the original
  ~5,500-9,000 estimate (3-4x), reflecting the empirical cost of
  mirroring Sui's verifier for the full Adamant superset. Phase
  5/5b.5 introduces a build-system independence check
  (`tests/no_sui_in_production_deps.rs`) that walks the resolved
  dependency tree of the production-binary target via `cargo
  metadata` and asserts no `move-*` crate appears, mechanically
  enforcing the resistant-proof posture rather than relying on
  convention. Without this escalation, the implementation would
  have shipped a transitional Sui-verifier bridge that lasted
  multiple months and produced code we'd later throw away when
  5/5c landed; the escalation reframes the work to lay down full
  coverage in one architectural arc with no transitional gap
  (commits 19d744b, 0651e2f).
- **Arithmetic semantics for the inherited Sui-Move subset**
  (whitepaper 6.2.1.9) — Phase 5/6.2 (AVM runtime instruction
  handlers) plan-gate surfaced that whitepaper §6.2.1.4 enumerates
  the inherited bytecode instructions and their stack effects but
  does not pin the runtime semantics of arithmetic, comparison,
  shift, and cast operations. Eight semantic gaps spanning a
  single coherent surface: overflow handling on Add/Sub/Mul;
  division and modulo by zero; shift amount bounds for Shl/Shr
  across all six integer widths; cast semantics across same-type
  / widening / narrowing distinctions; comparison ordering
  (signed vs unsigned); cross-type comparison verifier residual
  binding; equality semantics on primitives, structs, vectors,
  and shielded values; and whether wrapping-arithmetic opcodes
  exist. Each gap is consensus-binding — divergent runtime
  semantics across validators produces consensus disagreement —
  yet none was pinned at spec level prior to this amendment.
  Resolved by spec revision adding §6.2.1.9 ("Arithmetic
  semantics") as a new subsubsection appended after §6.2.1.8,
  pinning all eight gaps. The amendment aligns Adamant's runtime
  semantics with Sui-Move's empirically-verified runtime
  semantics for the inherited subset (verbatim source quote of
  Sui's `IntegerValue::shl_checked` / `shr_checked` and the
  interpreter's Shl/Shr dispatch arms taken at the vendored
  Sui commit `a9a6825eaf6273cc819ee3bcf65fd4909f7624a9`,
  preserving the strict-superset commitment of §6.2.1.1 — pure-
  Sui modules with abort-on-overflow / abort-on-shift-too-large
  / abort-on-cast-not-representable expectations on Sui exhibit
  the same runtime behaviour on Adamant. Methodologically, this
  is the **first comprehensive-semantics-amendment instance** —
  prior spec-first verification instances (instances 1–21) each
  resolved a single semantic gap or a related cluster within one
  topic; instance 22 resolves an entire semantic surface (all
  arithmetic-class instructions) in one amendment. Pre-
  ratification empirical reads at draft submission caught three
  load-bearing issues that initial draft text didn't surface:
  (a) verifier admits cast-to-same-type as no-op (confirmed by
  reading `validator/function_pass/type_safety.rs` cast
  handlers), prompting three-case cast framing rather than two-
  case widening/narrowing framing; (b) Sui-VM Shl/Shr abort
  semantics confirmed by verbatim source quote rather than
  hearsay (initial Claude Code framing said "Sui-Move's recent
  versions reportedly abort"; user direction required empirical
  verification before locking the disposition; the verbatim
  source confirmed abort, replacing "reportedly" with a quoted
  reference). The empirical-grounding-discipline operating at
  pre-ratification gate caught the §7 carry-forward as well:
  (c) §7's shielded encryption posture is implicitly probabilistic
  via the Poseidon-with-randomness scheme in §7.1.1 and the
  ChaCha20-Poly1305-with-nonce scheme in §7.6.1, but §7.8.1
  shielded object contents reference "encrypted" without
  explicitly specifying the encryption scheme. The §6.2.1.9
  shielded-value-equality paragraph names the probabilistic
  schemes in use under §7 by their cross-references rather than
  asserting a universal "all shielded encryption is
  probabilistic" claim that §7 doesn't explicitly back. **§7
  carry-forward (load-bearing):** future §7 amendment should
  pin "all shielded encryption is probabilistic" or
  equivalently specify the encryption scheme for §7.8.1
  shielded object contents to lock the §6.2.1.9 shielded-value-
  equality privacy property at spec level rather than at
  scheme-by-scheme implicit level. Without this, future
  implementations could add deterministic shielded encryption
  for §7.8.1 object contents and create a privacy hole that
  current spec text does not forbid; the §6.2.1.9 text is
  robust to §7's posture either way (it pins ciphertext-byte-
  comparison runtime behaviour unambiguously and notes the
  privacy-leakage relationship depends on §7's scheme), but
  pinning §7's posture explicitly would strengthen the
  privacy guarantee from "depends on §7's scheme" to "ciphertext
  equality does not imply plaintext equality at protocol
  level."
- **ML-DSA-87 spec-vs-spec inconsistency: restrict to ML-DSA-65**
  (whitepaper 6.2) — Phase 5/6.3 (Adamant-extension handlers)
  implementation surfaced that whitepaper §3.4.2 explicitly fixes
  the post-quantum signature scheme to ML-DSA-65 with explicit
  Level 5 rejection ("Level 5 (ML-DSA-87) provides 256-bit
  classical security at significantly higher signature size (4627
  bytes per FIPS 204 final) and computational cost. Level 3 is
  the appropriate balance for a chain whose lifetime is intended
  to be measured in decades"; "the algorithm choice (ML-DSA-65)
  is fixed"), while §6.2 admitted both `MlDsa65` and `MlDsa87` in
  three sites: the §6.0.7 `Signature` BCS variant-tag inventory
  (variant tag 0x02 = `MlDsa87`), the §6.2.1.4 AdamantBytecode
  list (`MlDsaVerify65 and MlDsaVerify87`), and the §6.2.1.5 per-
  extension operand-encoding paragraph (count of "19 Adamant-
  specific extensions" with `MlDsaVerify87` enumerated among the
  zero-operand extensions). The contradiction was internally
  load-bearing: §3.4.2's "fixed" framing is the older substantive
  spec text with explicit threat-model justification, while §6.2's
  inclusion of ML-DSA-87 appeared to be an artifact of inheriting
  general-purpose bytecode design rather than deliberate parameter-
  set choice. Resolved by spec amendment restricting §6.2 to
  ML-DSA-65: removing `MlDsa87` from the `Signature` variant
  inventory (consensus surface change; pre-mainnet so straight-
  forward), removing `MlDsaVerify87` from the AdamantBytecode list
  and the per-extension operand-encoding paragraph, and updating
  the counts (19 → 18 Adamant-specific extensions; 13 → 12 zero-
  operand extensions). The amendment aligns §6.2 with §3.4.2's
  unambiguous commitment, reduces the consensus-binding signature-
  scheme surface (one fewer variant in the genesis-fixed `Signature`
  union), and is consistent with the conservative-choice principle
  per CLAUDE.md §12 ("Prefer the conservative choice"). Hard-fork-
  to-add-later remains available via the genesis-fixed instruction-
  set posture (§6.2.1.4 "Adding new instructions ... is a hard
  fork"). Methodologically, this instance surfaces a new sub-
  classification of spec-first verification empirical work: **spec-
  vs-spec inconsistency** (two spec sections directly contradicting
  each other; resolved by spec amendment) is distinct from **spec-
  vs-implementation inconsistency** (implementation lags spec;
  resolved by implementation work) and from **spec-vs-implementation-
  comment inconsistency** (implementation comment cites wrong spec
  section; resolved by comment fix). The 5/6.3 implementation-gate
  empirical reads surfaced all three categories simultaneously
  (ML-DSA-87 = spec-vs-spec; ML-KEM lag = spec-vs-implementation;
  KZG `§3.7.2` vs `§3.9.2` comment in `bytecode.rs` = spec-vs-
  implementation-comment), with only the spec-vs-spec category
  warranting an amendment. The unratified
  `whitepaper/proposals/proposal-hybrid-signature-model.md`
  deliberation describes the current state as "ML-DSA-65 for
  ordinary, ML-DSA-87 for high-value/constitutional" signatures
  and proposes a hybrid Ed25519+ML-DSA+ML-KEM model with
  substantial constitutional impact; this proposal remains in
  active deliberation and may, if ratified, restore ML-DSA-87 to
  §3 + §6 via subsequent amendment. The instance-23 amendment does
  not preempt that deliberation — it aligns the spec to §3.4.2's
  stated authority *as currently written*, leaving the proposal-
  track future to its own ratification path. Eliminates the
  adamant-crypto ML-DSA-87 wrapper carry-forward entirely; reduces
  the 5/6.3.b deferred-handler scope from 3 to 2 (KZG only).
  Implementation cascade: `adamant-vm/src/bytecode.rs` removes
  `MlDsaVerify87` from `AdamantBytecode` and
  `AdamantOpcodeKind::ALL` (opcode byte 0x8C frees up);
  `adamant-vm/src/runtime/interpreter.rs::dispatch_adamant`
  removes the deferred-handler arm for `MlDsaVerify87`; the test
  at `runtime/tests/adamant_extensions.rs::deferred_ml_dsa_87_*`
  removes (commits 80ccd46 + 22b5a8a + this CONTRIBUTING.md
  instance entry; implementation cascade follows in a subsequent
  commit batch).
- **§7 encryption-posture commitment** (whitepaper 7.0) —
  Phase 5/6.2 §6.2.1.9 amendment surfaced this as a load-
  bearing carry-forward (instance 22's "§7 carry-forward
  (load-bearing)" closing paragraph). §6.2.1.9's shielded-
  value-equality runtime semantics — `Bytecode::Eq` on two
  shielded values compares ciphertext bytes verbatim — only
  delivers the privacy property "ciphertext equality reveals
  nothing about plaintext equality" if the encryption
  schemes are probabilistic. The §6.2.1.9 amendment named
  the probabilistic schemes in use under §7 by their cross-
  references (Poseidon-with-randomness in §7.1; ML-KEM-768
  in §7.2; ChaCha20-Poly1305 in §7.6) but §7 itself did not
  pin "all shielded encryption is probabilistic" as a
  protocol-level commitment, leaving §7.3.1 (encrypted note
  delivery), §7.6.1 (memo nonce derivation), and §7.8.1
  (shielded object contents) admissible to deterministic
  schemes that would silently break the §6.2.1.9 privacy
  property. Resolved by spec amendment adding §7.0
  ("Encryption posture") as a new top-level subsection
  inserted immediately after §7's introduction, mirroring
  §6.0's framing-material role at the top of §6. The
  amendment pins the universal probabilistic-only posture,
  enumerates the five on-chain shielded-encryption sites
  with their per-site specification status (two fully
  specified per existing spec text, one partially specified,
  two unspecified), pre-binds the three open surfaces to a
  probabilistic shape for any subsequent specification work,
  carves out the prover-market witness-encryption surface
  as out-of-protocol, and explicitly forbids deterministic
  schemes (AES-ECB, AES-SIV with deterministic IV, Poseidon-
  as-encryption without per-input randomness) for any on-
  chain shielded-encryption surface. The posture pin is at
  the privacy-property level, not the cryptographic-strength
  level: an implementation that substitutes a deterministic-
  but-cryptographically-strong scheme is non-conforming
  regardless of strength. Methodologically, this is the 2nd
  canonical instance of spec-vs-spec-inconsistency-resolved-
  via-amendment (1st was instance 23's ML-DSA-87 restriction;
  rule-of-three pending). Three carry-forwards registered at
  this amendment for subsequent §7 substantive work: §7.3.1
  EncryptedNote scheme specification; §7.6.1 nonce derivation;
  §7.8.1 shielded-object encryption scheme. Each is bound by
  the §7.0 posture in advance.
- **§7.4.2 sub-view-key construction specification gap**
  (whitepaper 7.4.2) — Phase 5/6.4 plan-gate empirical reads
  (Option A documentation-sub-arc) surfaced this load-bearing
  gap as a carry-forward bound to the §7.0 amendment-instance-
  24's three-carry-forward enumeration. §7.4.2's existing
  formula `sub_view_key_S = (sk_v + Hash(domain || S || sk_v) ·
  G_aux)` was residual text from pre-ML-KEM design: §7.2.2 was
  rewritten to use ML-KEM-768 viewing keypairs (line 105
  explicitly references "earlier drafts of this whitepaper
  specified a Diffie-Hellman scheme on BLS12-381"), but §7.4.2
  was not updated to match. The pre-ML-KEM formula is
  structurally incompatible with §7.2.2's construction:
  §7.2.2's viewing keypair `(sk_v_kem, pk_v_kem)` is an
  ML-KEM-768 keypair (public key 1184 bytes, secret key 2400
  bytes / 64-byte seed), not a BLS12-381 scalar; the pre-
  ML-KEM formula's `sk_v + Hash(...) · G_aux` requires `sk_v`
  to be a BLS12-381 scalar, a structural mismatch with the
  ML-KEM keypair shape post-§7.2.2 rewrite. Three substantively
  different cryptographic-construction paths exist for
  reconciling §7.4.2 with §7.2.2's ML-KEM viewing keypair
  (deterministic ML-KEM derivation; ChaCha20-Poly1305 wrap;
  post-decapsulation viewing-filter), each with different
  privacy properties and threat models. Selecting among them
  is substantial cryptographic-design work warranting a
  dedicated session — same posture as KZG plan-gate. Resolved
  by spec amendment replacing §7.4.2's formula and surrounding
  prose with explicit gap-acknowledgment text: the pre-ML-KEM
  formula is registered as not-applicable; the future amendment
  is bound by three constraints (§7.0 encryption posture
  probabilistic-only, §7.4.1 one-way derivation property,
  reconciliation with §7.2.2 ML-KEM); implementations `MUST NOT`
  rely on the previously-written formula; the wallet-enforced-
  scope framing is preserved unchanged. Same gap-acknowledgment
  posture as §7.0's "scheme not specified at this amendment"
  framing for sites 4 + 5; the spec is honest about the
  incompleteness while pre-binding the eventual specification
  to known constraints. Three methodology landmarks land at
  this amendment: (1) **spec-vs-spec-inconsistency-resolved-via-
  amendment 3rd canonical instance — RULE-OF-THREE THRESHOLD
  MET** (instance 23 ML-DSA-87 restriction + instance 24 §7.0
  encryption posture + instance 25 §7.4.2 residual-
  replacement); (2) **whitepaper-section-asymmetric-rewrite-
  residual sub-pattern 1st canonical instance** — §7.2.2
  rewrite (BLS ECDH → ML-KEM) did not propagate to §7.4.2;
  residual discovered at 5/6.4 plan-gate empirical reads. New
  sub-pattern shape distinct from prior spec-vs-spec
  inconsistencies (instance 23 + 24 were within-section or
  cross-section mismatches without rewrite history). Worth
  canonical Phase 5/6 PROVENANCE.md registration when
  PROVENANCE.md formalization next happens; (3) **amendment-
  mechanical-shape 4th distinct sub-shape — in-place residual
  replacement** (existing formula removed; gap-acknowledgment
  text inserted). Different from instance 22 append + instance
  23 distributed multi-line + instance 24 prepend. Carry-
  forwards registered: §7.4.2 sub-view-key construction
  reconciliation with §7.2.2 ML-KEM viewing-keypair
  (substantial; warrants dedicated cryptographic-design
  session); ReleaseSubViewKey real implementation continues
  blocked on §7.4.2 reconciliation + adamant-crypto-blst-extra
  hash-to-scalar helper expansion; 5/6.4.b ReleaseSubViewKey
  sub-arc deferred until §7.4.2 reconciliation ratifies.
- **§7.4.2 Path 1 deterministic ML-KEM sub-view-key
  construction** (whitepaper 7.4.2) — Closes the instance-25
  gap-acknowledgment with the full Path 1 cryptographic
  construction per the locked plan-gate disposition. Three
  reconciliation paths surfaced at instance 25 (deterministic
  ML-KEM derivation; ChaCha20-Poly1305 wrap of parent seed;
  post-decapsulation viewing-filter); Path 1 chosen for: (a)
  cleanest cryptographic shape — sub-view-key is a first-
  class ML-KEM keypair with bounded scope; (b) matches §7.4.1's
  "key" framing semantically; (c) reuses HKDF-SHA3 already in
  protocol per §7.2.5; (d) scope-restriction enforced
  cryptographically (stronger than wallet-only Path 3); (e)
  smaller cryptographic surface than Path 2; (f) deterministic
  derivation — no per-derivation entropy; (g) matches Zcash/
  Penumbra precedent for hierarchical viewing keys. Construction:
  `sub_seed_S = HKDF-SHA3(salt = b"ADAMANT-v1-subview-derive",
  ikm = sk_v_kem_seed, info = BCS(S), L = 64)` then
  `(sub_sk_v_kem_S, sub_pk_v_kem_S) = ML-KEM-768.KeyGen(
  sub_seed_S)`. Properties: one-way derivation (HKDF preimage
  resistance); scope-bound decapsulation (notes outside scope
  produce FIPS 203 implicit-rejection nonsense); determinism.
  Spec-vs-spec-inconsistency-resolved-via-amendment 4th
  canonical instance (instances 23 + 24 + 25 + 26 — pattern
  operating well beyond rule-of-three threshold). Amendment-
  mechanical-shape 5th distinct sub-shape: gap-acknowledgment-
  replaced-with-full-construction (different from prior 4:
  append, distributed multi-line, prepend, in-place residual
  replacement). Carry-forward eliminated: §7.4.2 reconciliation
  closes; ReleaseSubViewKey real implementation now blocked
  only on adamant-crypto HKDF-SHA3 helper + ML-KEM KeyGen-from-
  seed exposure (5/6.4.b sub-arc).

The pattern is: the cost of pausing to verify is hours; the cost of
shipping wrong constants compounds after genesis, when the protocol
cannot be patched. Implementers who hit a question against the
whitepaper should stop, document the question, and surface it for
spec review before continuing.

### Derivation discipline

Protocol-level identifiers (`Address`, `ObjectId`, and others to come)
are derived from canonical inputs via a registered domain tag. Four
invariants hold for any new derivation:

1. **The domain tag is registered in `adamant-crypto::domain`** as
   a `pub static DomainTag` — never inlined as a string literal at
   the call site. Adding, renaming, or removing a tag is a
   consensus rule change (whitepaper 3.3.1).

2. **The input is canonically encoded** before hashing, in a way
   that is byte-identical across every conforming implementation.
   For non-circuit derivations this means BCS (whitepaper 5.1.8);
   for in-circuit derivations the encoding follows the circuit's
   constraints (whitepaper 7, when implemented). The encoding must
   not be an ad-hoc concatenation lacking a referenceable spec.

3. **The hash function follows whitepaper 3.3.1's tagged-hash
   construction** — `sha3_256_tagged(&TAG, &encoded_input)` for
   non-circuit derivations, the Poseidon equivalent inside circuits
   (whitepaper 3.3.3). Raw SHA3-256 is not used for
   consensus-critical hashes.

4. **A known-answer regression test pins the wire format.** Generate
   the expected output once with documented fixed inputs; commit
   the byte string. When the regression test fails on unchanged
   inputs, the wire format has drifted — which is a consensus rule
   change requiring whitepaper revision, not a test fix.

These four are what every conforming implementation across the
protocol's lifetime must agree on. Implementation specifics —
input struct shape, function signature, test names, error handling
for BCS encode failures — vary per derivation as the shape of the
input data dictates.

**Reference implementations:**

- `adamant-account::derive_address` (whitepaper 4.2) — input is a
  three-field tuple (`creation_tx_hash`, `creator_address`, `index`).
- `adamant-state::derive_object_id` (whitepaper 5.1.1) — same input
  shape with the `creation_index` field name and a different domain
  tag.

Future derivations with different input shapes (e.g., a
transaction-hash derivation that consumes an entire serialised
transaction rather than a small input tuple) follow the same four
invariants while taking the input shape the spec section dictates.

This discipline applies to derivations of protocol-level
identifiers. Cryptographic primitives that use registered tags for
other purposes (e.g., the threshold-encryption KDF in
`adamant-crypto::threshold`) follow the spec section that defines
them, not these rules.

### Whitepaper commits are Ryan's

Whitepaper revisions are committed exclusively by Ryan. Claude Code
never commits whitepaper changes, including when the on-disk diff
matches a spec change Ryan has approved in conversation. The audit
trail for constitutional changes is shorter when Ryan's hand is on
every commit, and the marginal cost of one round-trip is acceptable
to preserve that property.

### Unsafe-containment architecture

Adamant maintains workspace-wide `unsafe_code = "forbid"` for every
Adamant-authored crate. The single exception is
`adamant-crypto-blst-extra`, which exists specifically to wrap
`blst`'s lower-level FFI (pairings, hash-to-curve, Z_r arithmetic,
G₂ scalar multiplication on a known generator) behind a safe Rust
API. `adamant-crypto::threshold` (whitepaper 3.6) consumes that safe
API and itself contains no `unsafe`.

The shape of the rule, in priority order:

1. **Default: forbid.** New crates inherit `[workspace.lints]` via
   `[lints] workspace = true` in their `Cargo.toml`, which sets
   `unsafe_code = "forbid"`. This is the workspace's structural
   guarantee: every Adamant-authored crate is statically verified to
   contain no `unsafe` blocks, `unsafe fn`, or `unsafe impl`.
2. **Containment for FFI.** If a new crate genuinely needs to call
   into an audited cryptographic library's raw FFI for operations
   the library's safe surface does not expose, the unsafe goes into
   a single-purpose containment crate (`adamant-crypto-<lib>-extra`
   or similar) that wraps the FFI behind a safe API. The containment
   crate's `Cargo.toml` sets `[lints.rust]` directly (which means
   duplicating the rest of the workspace lint configuration; cargo
   does not permit mixing `workspace = true` with per-crate
   overrides). The containment crate's lib.rs documents the
   architecture, the SAFETY discipline, and the surface it exposes.
3. **No relaxation in consumer crates.** Crates that consume the
   containment crate keep `forbid`. They get to call a safe API; they
   never use `#[allow(unsafe_code)]` themselves.
4. **Inventory in `SECURITY.md`.** Every containment crate has an
   audit-ready entry in `SECURITY.md` "Adamant-authored `unsafe`
   surface". Adding a new containment crate without an inventory
   entry is a review blocker.
5. **Lint-table sync on workspace lint changes.** When workspace
   lints are modified (`[workspace.lints.rust]` or
   `[workspace.lints.clippy]` in the root `Cargo.toml`), every
   containment crate's per-crate lint table MUST be updated to
   mirror the change. Verify by checking that
   `cargo clippy --workspace --all-targets` produces identical lint
   output before and after. This catches the maintenance failure
   mode where a workspace lint update silently leaves a containment
   crate with stale configuration — cargo does not permit mixing
   `workspace = true` with per-crate overrides, so containment
   crates carry a duplicated copy of the rest of the workspace lint
   configuration that drifts out of sync if not maintained.

The `adamant-crypto-blst-extra` crate is the canonical example. New
containment crates (if ever needed) should follow the same shape.

Reviewers should grep the workspace for `allow(unsafe_code)` and
verify each occurrence is in a containment crate listed in
`SECURITY.md`. The grep should never return a hit in
`adamant-crypto/`, `adamant-types/`, or any other consumer crate.

## Pre-publication checks

Audits to run before publishing any crate from this workspace.
Items are added as they surface; nothing here is yet automated.

- **`clippy::cargo_common_metadata` audit.** This lint silently no-ops
  for `publish = false` workspace members (the entire workspace
  today). Before publishing any crate, temporarily flip
  `[workspace.package] publish = false` to `publish = true` on a
  branch and re-run `cargo clippy --workspace --all-targets`. Address
  every reported missing metadata field (`description`, `keywords`,
  `categories`, `license`, `readme`, `repository`, `homepage`) on the
  to-be-published crate, then revert the publish flag if other crates
  in the workspace remain unpublished. Verified on clippy 0.1.95 to
  warn for `package.readme`, `package.keywords`, and
  `package.categories` with the current scaffold under `publish =
  true`.
