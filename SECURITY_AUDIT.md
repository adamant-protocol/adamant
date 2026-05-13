# SECURITY_AUDIT.md — Pre-Phase-10 audit findings

This document records the comprehensive pre-Phase-10 security audit
conducted across four parallel attack-surface domains: network,
cryptography, VM/state/bytecode, and supply chain. Each finding is
categorized by severity and tracked by resolution status (FIXED,
DEFERRED-TO-PHASE-10, or SPEC-AUTHOR-REQUIRED).

The audit is **not a substitute** for the external auditor engagement
that begins in Phase 10. Its purpose is to catch the highest-impact
issues internally and to give external auditors a focused starting
point.

---

## Resolution legend

- **FIXED** — addressed in the audit-closure commit batch.
- **DOCUMENTED** — flagged here for auditor review; no code change.
- **DEFERRED-TO-PHASE-10** — Phase 10 hardening venue.
- **SPEC-AUTHOR-REQUIRED** — needs spec amendment before fix.

---

## Network attack surface (4 HIGH + 4 MEDIUM + 4 LOW)

### H-1 Submission-proof reuse across identical transactions  *(SPEC-AUTHOR-REQUIRED)*

**File**: `crates/adamant-network/src/anti_dos.rs:95-134` (`compute_pow_hash`).

Two transactions with identical body fields produce identical PoW
hashes, so one valid `SubmissionProof` verifies against any clone.
A sophisticated attacker can produce one PoW at moderate difficulty
and flood a peer with K identical transaction submissions, each
passing `validate_submission`.

**Fix path**: bind a per-peer or per-wallet nonce into the PoW input
construction. This is a consensus-binding change — the §9.5.1
construction is hard-fork-pinned. Spec-author amendment required
before fix lands.

### H-2 Mempool eviction enables honest-tx eviction at low-difficulty PoW  *(DEFERRED-TO-PHASE-10)*

**File**: `crates/adamant-network/src/mempool.rs:224-269`.

A `fee_tip = u64::MAX` declaration on a low-PoW-cost transaction
admits with eviction. The fee is never settled at admission because
§9.5.4 cryptographic verification of the underlying AVM signature is
deferred. The mempool trusts the network-wire `fee_tip` value.

**Fix path**: §9.5.4 wiring at Phase 7.11/Phase 10 audit prep.

### H-3 Per-peer rate-limiter state grows unboundedly  *(FIXED)*

**File**: `crates/adamant-network/src/anti_dos.rs:356-430`.

`RateLimiter::peers` is an unbounded `HashMap`. An attacker rotating
through fresh ed25519 keypairs grows it without bound.

**Fix**: added `RateLimitConfig::max_tracked_peers` (default 100,000)
and `RateLimiter::check` rejects new peers when the limiter is at
capacity. New regression test `rate_limiter_caps_tracked_peers`.
Existing tracked peers continue to be served (no eviction of in-flight
honest peers).

### H-4 Threshold-share accumulator state grows unboundedly  *(DEFERRED-TO-PHASE-10)*

**File**: `crates/adamant-consensus/src/mempool_decryption.rs:530-707`.

`ThresholdShareAccumulator::pending` accepts arbitrary
`(identity, ciphertext_header, ciphertext)` triples per gossiped
vertex with no aggregate-size cap. Attacker-controlled validators
(or forged vertices pre-§9.5.4) can grow accumulator memory
unboundedly.

**Fix path**: add `max_pending_identities` cap + per-ciphertext-size
cap at admission. Defer to Phase 10 alongside the §9.5.4
signature-verification wiring (the two fix the same threat class).

### H-5 Time-lock VDF discriminant deserialization unbounded  *(DEFERRED-TO-PHASE-10)*

**File**: `crates/adamant-crypto/src/vdf/envelope.rs:411`.

A malicious anchor publishes a `TimeLockDecryption` with
multi-megabyte `solution.encoded` and forces every observer to
spend CPU recomputing class-group arithmetic against a 2 KiB
discriminant.

**Fix path**: cap `ClassGroupElement.encoded.len()` at deserialize
boundary. Adamant-native fix; lands at Phase 10 alongside the §9.5
admission-cap wiring.

### H-6 Production-path panic on `u32::try_from(origin_index)`  *(DOCUMENTED)*

**File**: `crates/adamant-consensus/src/mempool_decryption.rs:475-477, 800-802`.

The `expect("Adamant invariant: per-vertex transaction count is
bounded ... by §9.5 mempool admission caps")` assumes upstream
enforcement that lives in `adamant-network` (different crate).

**Status**: theoretically unreachable under current §9.5
admission caps (per-vertex transaction count is bounded). Promoting
the invariant from comment-enforced to runtime-asserted is a
defense-in-depth improvement deferred to Phase 10 alongside the
DAG-insert structural-limits work.

### M-1 Light client cannot verify recursive proof chains  *(SPEC-AUTHOR-REQUIRED)*

**File**: `crates/adamant-consensus/src/light_client.rs:489-523`.

`LightClientState::advance` checks epoch monotonicity + no-gap but
does NOT verify the recursive proof. A malicious service node can
feed fabricated state commitments.

**Fix path**: bind the recursive-proof verification to the
`advance` API. This crosses the `adamant-consensus` / `adamant-privacy`
layering and is documented in CLAUDE.md as a Phase 7.11 deferred
surface. Spec-author input required on the verifier wiring shape.

### M-2 AEAD error variant taxonomy leaks decryption-failure cause  *(DOCUMENTED)*

**File**: `crates/adamant-consensus/src/mempool_decryption.rs:104-203`.

Error variants distinguish CombineFailed / AeadDecryptionFailed /
CiphertextTooShort etc. — observers can correlate which check
failed. Side-channel for crafted-input probing.

**Status**: minor; recommend folding non-length failures into a
single opaque variant in production builds. Audit-recommendation;
deferred to Phase 10 hardening.

### M-3 Token-bucket time-handling drops sub-second elapsed  *(DOCUMENTED)*

**File**: `crates/adamant-network/src/anti_dos.rs:400-410`.

`elapsed_secs` floors to 0 if a peer submits every 999ms; the peer
gets zero refill. Availability footgun for honest users at high
cadence.

**Status**: documented; mitigation is to use sub-second arithmetic
(`elapsed_micros * refill_per_sec / 1_000_000`). Deferred to Phase 10
hardening alongside the rate-limiter calibration workstream.

### M-4 Vertex BCS-decoded transactions/shares can be massive  *(DEFERRED-TO-PHASE-10)*

**File**: `crates/adamant-consensus/src/vertex.rs:170-218`.

`TransactionEnvelope { bytes: Vec<u8> }` carries no per-field cap.
At 1 MiB gossipsub cap, a single vertex can pack many small or one
large envelope — accumulator bloat (see H-4).

**Fix path**: per-payload size caps inside the wire types or
aggregate-size check at `DagState::insert`.

### L-1 to L-4: documented; low priority hardening for Phase 10.

---

## Cryptographic attack surface (3 CRITICAL + 5 HIGH + 5 MEDIUM + 3 LOW)

### C-1 Recursive proof envelope does not bind public inputs  *(SPEC-AUTHOR-REQUIRED, HIGHEST PRIORITY)*

**File**: `crates/adamant-privacy/src/epoch_recursion.rs:242-248`
(`verify_envelope`).

`verify_envelope` checks only `accumulator.verifies()` (a 32-byte
Vesta-curve identity check). The `RecursiveProofPublicInputs`
(genesis, previous_epoch, current_epoch, epoch_number) are NOT
cryptographically bound into the proof.

An attacker can take any verifying accumulator (including the
trivial `EpochAccumulator::empty()`) and attach **arbitrary**
public-inputs to forge an epoch transition that a light client
would accept.

**Impact**: breaks §8.5.1 light-client soundness. A light client
trusting `verify_envelope` accepts forged chain-state commitments
under a valid-but-unrelated accumulator.

**Fix path**: bind `RecursiveProofPublicInputs` into the recursive
proof construction itself — either by hashing the public-inputs
into the accumulator's challenge derivation, or by adding a
public-input commitment to the `RecursiveProofEnvelope` that
`verify_envelope` checks. This is a Phase 6.9b extension and
requires spec-author ratification. **Top-priority Phase 10 audit
blocker.**

### C-2 BLS aggregate verification lacks rogue-key defense  *(SPEC-AUTHOR-REQUIRED, HIGHEST PRIORITY)*

**File**: `crates/adamant-crypto/src/bls.rs:429-446, 460-478`,
`crates/adamant-consensus/src/identity.rs`.

`fast_aggregate_verify` accepts the canonical rogue-key attack:
an attacker controlling one Byzantine validator registers
`pk_attacker = pk_target_aggregate - Σ pk_honest` to produce a
single-signer forgery that verifies as if every honest validator
signed. No proof-of-possession check exists at validator
registration.

**Impact**: breaks §8.6 VRF unpredictability + every BLS-aggregate
consensus check.

**Fix path**: add a proof-of-possession requirement at validator
registration time. The PoP signs `(VALIDATOR_ID || BLS_PK)` under
the BLS secret; registration rejects bundles where the PoP
doesn't verify. Spec-author amendment required for §8.1 and §8.6.
**Top-priority Phase 10 audit blocker.**

### C-3 ChaCha20-Poly1305 nonce uniqueness is API-level discipline only  *(DOCUMENTED)*

**File**: `crates/adamant-crypto/src/symmetric.rs:175-187`.

`Key::encrypt` accepts a caller-supplied `&Nonce` with no API-level
deduplication. Documented in the docstring; relied-upon by every
caller.

**Status**: latent footgun. Adding type-level nonce-uniqueness
enforcement (e.g., a one-shot Nonce that consumes itself on use)
would require reshaping every caller. Documented here as a
discipline requirement; pre-Phase-10 audit prep should sweep every
caller verifying compliance.

### H-1 Lagrange-coefficient `den.inverse()` constant-time  *(DOCUMENTED)*

**File**: `crates/adamant-crypto/src/threshold.rs:820-842`.

Confirm `adamant-crypto-blst-extra::Scalar::inverse` is
constant-time. Validator indices are public so this is likely
benign, but worth a confirmation pass on the underlying blst
scalar arithmetic.

### H-2 Stealth-address scalar arithmetic and zeroization  *(DOCUMENTED)*

**File**: `crates/adamant-privacy/src/stealth.rs:184, 311, 191-196,
442-443`.

`pallas::Scalar::ZERO` assignment-on-drop is not volatile. Replace
with explicit volatile zeroize. Defense-in-depth.

### H-4 BindingSignature has no verify surface  *(DEFERRED-TO-PHASE-10)*

**File**: `crates/adamant-privacy/src/shielded_tx.rs:142-172`.

`BindingSignature: Vec<u8>` exists as opaque bytes; no
`verify_binding_signature` function exists in `adamant-privacy`.
The validity-proof verification wiring at Phase 7+ must call a
verify primitive that doesn't exist yet.

**Fix path**: implement `verify_binding_signature` + wire it into
the validity-proof verification pipeline. Required before Phase 10
auditors review the privacy layer.

### Other findings (H-3, H-5, M-1 through M-5, L-1 through L-3):

documented per agent report; deferred to Phase 10 hardening.

### L-1 Domain-tag uniqueness  *(FIXED)*

**File**: `crates/adamant-crypto/src/domain.rs`.

**Fix**: added `uniqueness_tests` module with two regression tests:
`all_production_tags_have_distinct_bytes` (uniqueness invariant)
and `all_production_tags_share_adamant_v1_prefix` (consistency
invariant). Both run as part of `cargo test -p adamant-crypto`.

---

## VM + state + bytecode-verifier attack surface (3 CRITICAL + 4 HIGH + 4 MEDIUM + 3 LOW)

### C-1 Unbounded call-stack depth → host stack-overflow DoS  *(DEFERRED-TO-PHASE-10)*

**File**: `crates/adamant-vm/src/runtime/interpreter.rs:2605, 2681,
4407` + `runtime/frame.rs:110`.

`InterpreterState::push_frame` has no depth limit. A self-recursive
module function exhausts the host stack → process abort.

**Fix path**: add `max_call_stack_depth` to
`AdamantStructuralLimits` (canonical Move VM default is 1024) and
enforce at `push_frame`. Trivial mechanical change; lands at
Phase 10 alongside the §6.2.1.7 structural-limits amendment.

### C-2 Unbounded value/container nesting → host stack overflow  *(DEFERRED-TO-PHASE-10)*

**File**: `crates/adamant-vm/src/runtime/runtime_value.rs:78-99`.

Crafted runtime values via `VecPushBack` chains exceed any static
verifier bound and exhaust host stack during recursive operations
(Eq, Drop, BCS-encode).

**Fix path**: add `max_value_depth` (e.g., 128) to
`AdamantStructuralLimits`; enforce at construction sites.

### C-3 `expect` on `adamant_serialize` reachable from validated module  *(DEFERRED-TO-PHASE-10)*

**File**: `crates/adamant-vm/src/validator/mod.rs:282-286`.

If a future deserializer accepts a shape the serializer cannot
reproduce, this panics. Convert to `Result` returning a typed
`SerialiserAsymmetry` variant.

### H-1 `RefCell` borrow-panic reachable on reference-safety verifier gap  *(DEFERRED-TO-PHASE-10)*

**File**: `crates/adamant-vm/src/runtime/runtime_value.rs:49-54` +
74 `borrow_mut()` sites.

Defense-in-depth: replace bare `.borrow_mut()` with
`.try_borrow_mut().map_err(...)` translating to
`InvariantViolation`.

### H-2 to H-4: documented; Phase 10 hardening venue.

### M-1 to M-4: per-site investigation in Phase 10 audit prep.

---

## Supply chain attack surface (3 HIGH + 5 MEDIUM + 6 LOW)

### H-1 No CI pipeline — resistant-proof guards honor-system enforced  *(DEFERRED-TO-PHASE-10)*

**File**: missing `.github/workflows/`.

CLAUDE.md §7 documents required CI checks; none exist on disk. PRs
adding `move-*` deps to production graphs would pass review.

**Fix path**: add `.github/workflows/ci.yml` running `cargo test`,
`cargo clippy`, `cargo fmt --check`, and explicit invocations of
`no_sui_in_production_deps` + `no_upstream_halo2_in_production_deps`.

### H-2/H-3 Caret pins on vendor-tag-derived deps  *(DOCUMENTED)*

**Files**: `Cargo.toml:243-320`,
`crates/adamant-halo2/Cargo.toml:35-67`.

23 vendor-tag-derived caret pins + 10 sub-1.0 caret pins. Allow
silent upgrade on `cargo update`.

**Status**: tightening required before mainnet. The Sui-tag-derived
deps may need to retain their pins to match upstream's pin shape;
each requires individual review.

### M-1 sha3 at two versions in production graph  *(DOCUMENTED)*

`sha3 0.10.9` (consensus-critical) + `sha3 0.11.0` (via ml-dsa
transitive). Documented in CLAUDE.md §14 "RustCrypto ecosystem
skew"; clippy reports as warning-not-deny per workspace lints.

### M-2/M-3/M-4/M-5 + L-1 to L-6: documented per agent report.

---

## What this audit closure shipped (FIXED items)

| Finding | File | Action |
|---|---|---|
| Crypto L-1 | `domain.rs` | Added 2 uniqueness-invariant regression tests |
| Network H-3 | `anti_dos.rs` | Added `max_tracked_peers` cap with regression test |
| Network H-1 (test infra) | `vrf.rs` | Bit-exact + platform-independence regression tests |
| Consensus | `vertex.rs`, `vrf.rs` | KAT regression vectors for `derive_id` + `output_randomness` |
| Crypto | `tests/proptest_roundtrips.rs` | 15 proptest round-trip properties |
| Crypto | `tests/kzg_vdf_oracles.rs` | 12 KZG + VDF oracle KATs |
| Consensus | `tests/wire_snapshots.rs` | 11 BCS wire-snapshot pins |
| Supply chain | `tests/no_sui_in_production_deps.rs` | Third-tier ecosystem guard |
| Test discipline | various | 12 strengthened `assert!(matches!)` patterns |

---

## Phase 10 audit-blocker items (top priority)

These three items are the highest-priority pre-mainnet work
identified by the audit:

1. **Crypto C-1**: bind `RecursiveProofPublicInputs` into the
   recursive proof construction. Breaks §8.5.1 light-client
   soundness without it.

2. **Crypto C-2**: BLS proof-of-possession at validator
   registration. Breaks §8.6 VRF + every BLS-aggregate check
   without it.

3. **Privacy H-4**: implement `verify_binding_signature` for
   value commitments. §7.3.2 statement 4 is unenforceable
   on-chain without it.

These items require **spec-author ratification** (whitepaper
amendments to §8.1.1–8.1.5, §8.5.1, §8.6, and §7.3.2) before fixes
can land. They are the single most important pre-Phase-10
deliverable.

---

## Architecture clean-categories (audit-confirmed)

The following audit categories returned clean (no findings):

- **Concurrency posture**: no `tokio::spawn`, no `Arc<Mutex>`, no
  `unbounded_channel` in production paths. Single-threaded
  determinism holds across all 13 Adamant production crates.

- **`unsafe` isolation**: confined to `adamant-crypto-blst-extra`
  (51 unsafe blocks, all with SAFETY comments). FFI raw pointers
  never leak across function boundaries.

- **Gas accounting**: `checked_sub`-based; cannot underflow,
  cannot overflow. First-dimension-exhausted aborts per §6.3.1.

- **Sparse Merkle tree soundness**: depth-pinned at 256,
  proof-width validated at verify time, domain-separated leaf /
  empty-leaf / node / value tags.

- **Bytecode deserializer canonicality**: layered enforcement
  via per-table over/under-consumption pins + trailing-byte
  rejection + full canonical round-trip in `verify_module`.

- **Rule 5 deprecated-global-storage**: parse-time rejection
  inside `adamant_deserialize`; impossible to embed via inner
  locations.

- **Constant-time discipline**: `subtle::ConstantTimeEq` used
  uniformly across `SigningKey` / `SecretKey` / `KeyShare` /
  `SharedSecret` boundaries.

- **No build scripts**: zero `build.rs` files in the workspace.
  Entire build-script attack class eliminated.

- **All registry sources are crates.io**: no alternate
  registries, no `[source.replace]`.

- **Vendored crates `publish = false`**: every Sui-vendored
  crate cannot be accidentally republished from this workspace.

---

## How to update this document

When a finding moves from DEFERRED to FIXED:

1. Update the resolution status in the relevant section.
2. Add the file + commit reference to the "FIXED items" table.
3. Move the finding to "Architecture clean-categories" if the
   fix retires the threat class entirely.

When a new finding is identified:

1. Add it to the appropriate severity section.
2. Tag with resolution status.
3. Update the top-priority blocker list if it's CRITICAL.

The auditor engagement in Phase 10 will produce a more
comprehensive document; this file is the pre-engagement working
state.
