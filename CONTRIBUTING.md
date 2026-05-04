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
sources before proceeding. Two confirmed instances during Phase 1:

- **BIP-340 tagged-hash construction** (whitepaper 3.3.1) — the
  original "fixed-length domain tag" text admitted prefix collisions
  with variable-length tags; resolved by spec revision pinning the
  BIP-340 construction (commit 62bfe89).
- **ML-DSA-65 signature size** (whitepaper 3.4.2) — the original
  3293-byte figure was the CRYSTALS-Dilithium round 3 number,
  superseded by the FIPS 204 final 3309-byte figure; resolved by
  spec revision (commit 30bf5ac).

The pattern is: the cost of pausing to verify is hours; the cost of
shipping wrong constants compounds after genesis, when the protocol
cannot be patched. Implementers who hit a question against the
whitepaper should stop, document the question, and surface it for
spec review before continuing.

### Whitepaper commits are Ryan's

Whitepaper revisions are committed exclusively by Ryan. Claude Code
never commits whitepaper changes, including when the on-disk diff
matches a spec change Ryan has approved in conversation. The audit
trail for constitutional changes is shorter when Ryan's hand is on
every commit, and the marginal cost of one round-trip is acceptable
to preserve that property.

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
