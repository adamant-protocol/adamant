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
sources before proceeding. Nineteen confirmed instances during Phases
1, 2, 4, and 5:

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
