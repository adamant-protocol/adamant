# Adamant — Cryptographic Dependency Security Surface

This document records the `unsafe` surface and audit signal of every
cryptographic dependency used by Adamant. It is part of the security audit
surface. Updates are deliberate, called out in commit messages, and required
before a new cryptographic dependency may be added to any `Cargo.toml`.

## Policy

- **No `unsafe` in Adamant-authored crates.** The workspace lint is
  `unsafe_code = "forbid"`. The single exception is
  `adamant-crypto-blst-extra`, which exists specifically to contain
  the `unsafe` FFI surface required to expose `blst`'s lower-level
  operations (pairings, hash-to-curve, Z_r arithmetic, G₂ scalar
  multiplication on a known generator) behind a safe Rust API. New
  crates default to `forbid` by inheriting `[workspace.lints]`;
  relaxing the lint requires the same justification (and structural
  isolation) `adamant-crypto-blst-extra` has and an entry in the
  "Adamant-authored `unsafe` surface" inventory below. See
  `CONTRIBUTING.md` "Unsafe-containment architecture" for the rule.
- **Upstream `unsafe` is permitted only in audited cryptographic libraries
  named in whitepaper section 3.** New dependencies must be entered into
  the table below before they are referenced from any `Cargo.toml`.
- **No hand-rolled cryptography.** Every primitive routes through one of
  the libraries listed in this table. Substitution requires a whitepaper
  revision, not a silent code change.
- **Upstream contribution.** Where the reference implementation needs
  improvements to a cryptographic dependency, contributions are offered
  upstream rather than maintained as forks (whitepaper 3.9).
- **Transitive cryptographic dependencies are tracked individually.** Any
  transitive dependency that contains cryptographic primitives or carries
  `unsafe` code on the consensus-critical path gets its own row in the
  table below — not just the crate named in our `Cargo.toml`. The row
  identifies the parent crate that pulls it in, the version (held stable
  by `Cargo.lock`), and the audit signal. The intent is that a future
  reader of this file can enumerate the full cryptographic-primitive and
  `unsafe`-code surface without having to trace `cargo tree` themselves.

## Cryptographic dependency surface

Each row records: crate, version pin at first-use time, `unsafe` usage,
justification, and the audit / deployment signal Adamant relies on.

| Crate | Pinned version | `unsafe` usage | Justification | Audit / deployment signal |
|-------|----------------|----------------|---------------|---------------------------|
| `sha3` (RustCrypto) | `=0.10.9` (first imported by `adamant-crypto::hash`, BIP-340 tagged-hash construction per whitepaper 3.3.1) | Pure-Rust default backend used by `adamant-crypto`; `sha3` 0.10's optional SIMD/asm backends would carry `unsafe` but are not enabled. | Hardware-accelerated SHA3 on x86-64 and ARM v8.4-A matters for consensus-critical hashing throughput; default-features = false ships pure-Rust today and we revisit SIMD enablement before mainnet. | Widely deployed across the RustCrypto ecosystem; underlying `keccak` crate audited; routine community review. |
| `keccak` (RustCrypto, transitive via `sha3`) | `0.1.6` (transitive pin held by `Cargo.lock`; floats with `sha3 =0.10.9`'s declared bound) | None on the path used here (default features, pure-Rust). The crate has optional SIMD backends behind feature flags that would introduce `unsafe`; not enabled. | Tracked separately from `sha3` because `keccak` carries the actual Keccak-f[1600] permutation underlying SHA3-256 and SHAKE-256 (whitepaper 3.3.1), while `sha3` is a thin wrapper over it. | RustCrypto project; cryptanalysis on Keccak-f itself is extensive (NIST SHA-3 competition 2007–2012, FIPS 202 standardisation 2015); routine community review. |
| `blake3` | `=1.8.5` (first imported by `adamant-crypto::hash::blake3` per whitepaper 3.3.2) | SIMD intrinsics for AVX2 / AVX-512 / SSE / NEON backends, dispatched at runtime via `cpufeatures`. | BLAKE3's design relies on SIMD parallelism; the published 5–10× speedup over SHA3 is the reason it is selected for non-consensus-critical performance paths (peer-to-peer integrity, content-addressed historical storage). | Reference implementation maintained by the BLAKE3 designers; widely deployed (Cargo, b3sum, many production systems); the algorithm itself has had no published cryptanalytic break since 2020. |
| `arrayref` (transitive via `blake3`) | `0.3.9` (transitive pin held by `Cargo.lock`) | `unsafe` slice-to-array reference casts inside the `array_ref!` / `array_mut_ref!` macros. | Used pervasively inside BLAKE3's hot loop for bounded slice-to-array conversions; on the critical path. Tracked separately because the macros expand to `unsafe` at every BLAKE3 invocation site. | BLAKE3 team's standard dependency; trivial single-purpose crate; community-reviewed. |
| `arrayvec` (transitive via `blake3`) | `0.7.6` (transitive pin held by `Cargo.lock`) | `unsafe` for unchecked-index optimisations on stack-allocated array-backed buffers. | Used by BLAKE3 for fixed-size internal state buffers; on the critical path. Not a cryptographic primitive but a data-structure crate; bounded `unsafe` is documented and audited within the crate. | Widely deployed across the Rust ecosystem; long stable history. |
| `constant_time_eq` (transitive via `blake3`) | `0.4.2` (transitive pin held by `Cargo.lock`) | None observed in default configuration; the crate's focus is constant-time semantics rather than performance via `unsafe`. | Provides timing-safe byte-equality — a cryptographic primitive (defends against timing-side-channel attacks). Tracked because of its security role even though the unsafe surface is minimal. | RustCrypto / dalek-cryptography ecosystem; widely deployed; the timing-safety property is the core audit signal. |
| `cpufeatures` (transitive via `blake3` and via `keccak`/`sha3`) | Two versions concurrently: `0.3.0` (pulled by `blake3 =1.8.5`) and `0.2.17` (pulled by `keccak 0.1.6` ← `sha3 =0.10.9`). The duplicate is allowlisted in `clippy.toml` against `clippy::multiple_crate_versions`; see CONTRIBUTING.md "Verifications on record" for the rationale. **Revisit signal:** remove this row and the `clippy.toml` allowlist entry when `sha3`'s transitive `keccak` widens its `cpufeatures` constraint to admit `^0.3` (or when bumping `sha3` brings in a `keccak` that does). | Inline assembly via `CPUID` (or equivalent on ARM) for runtime CPU-feature detection. | Drives SIMD-backend dispatch in both BLAKE3 and Keccak/SHA3. Required for the SIMD performance the whitepaper relies on. Not a cryptographic primitive itself. | RustCrypto project; trivial single-purpose crate; widely deployed. |
| `ed25519-dalek` (dalek-cryptography) | `=2.2.0` (first imported by `adamant-crypto::sig_classical` per whitepaper 3.4.1) | None in dalek itself in default configuration; the dalek ecosystem explicitly minimises and documents `unsafe`. Underlying field arithmetic via `curve25519-dalek` and `fiat-crypto` carries `unsafe` in optimised backends — tracked separately below. | Constant-time, no-`unsafe` Ed25519 wrapper. Provides deterministic signing per RFC 8032 and the `SigningKey` / `VerifyingKey` / `Signature` types we wrap. | Widely audited; deployed in Signal, Tor, and many cryptocurrency systems. |
| `curve25519-dalek` (dalek-cryptography, transitive via `ed25519-dalek`) | `4.1.3` (transitive pin held by `Cargo.lock`) | `unsafe` in SIMD backends (AVX2, AVX-512) and in interfaces to `fiat-crypto`'s C-style verified field arithmetic. Pure-Rust default backend uses `unsafe` minimally; SIMD backends use it for vectorised field operations. | The cryptographic primitive underlying Ed25519: implements the `edwards25519` group operations specified in RFC 7748 / RFC 8032. Tracked separately because `curve25519-dalek` is the actual elliptic-curve implementation; `ed25519-dalek` is a thin wrapper over it. | Widely audited; deployed in Signal, Tor, and many cryptocurrency systems alongside `ed25519-dalek`. |
| `fiat-crypto` (transitive via `curve25519-dalek`) | `0.2.9` (transitive pin held by `Cargo.lock`) | Primarily safe; some `unsafe` for SIMD/intrinsic field operations on supported targets. | Field arithmetic over the `curve25519` base field, **formally verified** by extraction from Coq proofs. The unique audit signal is mathematical correctness from machine-checked proofs rather than human review. | Generated from formally verified Coq specifications; algorithmic correctness is a theorem, not a test result. Maintained as part of the broader fiat-crypto verified-cryptography project. |
| `sha2` (RustCrypto, transitive via `ed25519-dalek`) | `0.10.9` (transitive pin held by `Cargo.lock`) | None in pure-Rust default mode; SIMD backends (SHA-NI on x86, ARMv8 SHA crypto extensions) use `unsafe`. | Implements SHA-512, which Ed25519 uses **internally** per RFC 8032. Tracked separately from `sha3` because (a) it's a different primitive and (b) the protocol's own hashing uses SHA3-256 — SHA-512 is here only because the Ed25519 specification demands it (whitepaper 3.4.1). | RustCrypto project; the SHA-512 algorithm itself is FIPS 180-4 standardised; routine community review. |
| `subtle` (dalek-cryptography, transitive via `ed25519-dalek` and used directly) | `=2.6.1` (now pinned in workspace deps) | Uses `core::hint::black_box` and volatile semantics to defeat compiler timing-leak optimisations. Bounded `unsafe` documented inline in the crate. | Provides constant-time primitives (`Choice`, `ConstantTimeEq`, `ConditionallySelectable`) used by every dalek operation and by our wrapper for `SigningKey::ct_eq`. The whole point of the crate is timing-safety; treated as a cryptographic primitive on its own. | Maintained by the dalek-cryptography project; widely deployed across Rust crypto crates. |
| `ml-dsa` (RustCrypto) | `=0.1.0-rc.9` (first imported by `adamant-crypto::sig_pq` per whitepaper 3.4.2) | None in dalek-style direct usage; transitive surface is documented under the per-transitive rows below (`ctutils`, `module-lattice`, `hybrid-array`) and under "RustCrypto ecosystem skew" for the dual-version situation with `sha3` / `keccak`. | FIPS 204 final-compliant ML-DSA implementation (algorithm choice fixed in whitepaper 3.4.2). Provides deterministic signing for ML-DSA-65 and the `SigningKey` / `VerifyingKey` / `Signature` types we wrap. | RustCrypto project; cryptanalysis on ML-DSA itself (FIPS 204) is extensive; this crate is pre-1.0 (release-candidate) — implementation audit is ongoing upstream. **Test-vector coverage note:** ML-DSA-65 has 5 NIST ACVP keyGen vectors + 1 ACVP sigVer vector verifying the production API; expanded sigVer coverage would require either an API extension to take a context parameter (deferred until a use case lands) or further ACVP vectors that fit the empty-context deterministic case (none currently available — the upstream `internalProjection.json` for sigGen contains exactly one such case for ML-DSA-65). |
| `ctutils` (transitive via `ml-dsa`) | `0.4.2` (transitive pin held by `Cargo.lock`) | None observed in default configuration; the crate's focus is constant-time semantics, not performance via `unsafe`. | Constant-time primitives (`CtEq`, `Choice`) used by `ml-dsa` for secret-material comparisons. Plays the role for ML-DSA that `subtle` plays for the dalek tree; tracked separately because they are distinct crates with distinct audit histories. | RustCrypto project; widely used by the post-0.10-generation crates; the timing-safety property is the core audit signal. |
| `module-lattice` (transitive via `ml-dsa`) | `0.2.2` (transitive pin held by `Cargo.lock`) | May use `unsafe` for performance-critical polynomial / NTT operations on supported targets. | Module-lattice algebra (Module-LWE, Module-SIS) underlying ML-DSA; the actual lattice cryptographic primitive. Tracked separately from `ml-dsa` because `ml-dsa` is the FIPS-204 spec adapter and `module-lattice` is the underlying algebra. | RustCrypto project; pre-1.0; same audit signal as `ml-dsa`. |
| `hybrid-array` (transitive via `ml-dsa` and `module-lattice`) | `0.4.11` (transitive pin held by `Cargo.lock`) | `unsafe` for typed-length array handling — analogous to `arrayvec` for the dalek tree but used by the post-0.10-generation crates. | Provides const-generic typed arrays used pervasively inside ML-DSA's polynomial vectors and signature/key encodings. Bounded `unsafe` documented inline in the crate. | RustCrypto project; the typed-array crate that replaced `generic-array` in the post-0.10 generation; routine community review. |
| `blst` (Supranational) | `=0.3.16` (first imported by `adamant-crypto::bls` per whitepaper 3.4.3) | Required: Rust binding over the C-language `blst` library, plus inline `unsafe` for FFI. blst's own internal `unsafe` covers the BLS12-381 field arithmetic, pairing, and hash-to-curve implementations — these are why we use blst in the first place (whitepaper 3.4.3 calls it "the highest-performance audited BLS12-381 implementation in current use"). The `unsafe` is canonical "audited cryptographic library" surface per the policy in this file. | Used for BLS12-381 G1-signature / G2-public-key signatures (whitepaper 3.4.3) and aggregate verification. blst is **not** part of the RustCrypto ecosystem — different lineage, different versioning, no participation in the 0.10 / post-0.10 skew documented above. **Test-vector coverage note:** the widely-circulated BLS KAT suites (Ethereum bls12-381-tests, IRTF draft examples) target the min_pk variant; Adamant uses min_sig per whitepaper 3.4.3, so those KATs are not directly applicable. Coverage rationale recorded in `crates/adamant-crypto/test-vectors/bls/README.md`; verification rests on blst's own upstream KAT testing (which exercises both variants via shared primitives) plus the wrapper's inline self-consistency tests. | Audited (NCC Group 2020 and subsequent); deployed in Ethereum consensus, Filecoin, Chia, and other BLS-using systems. Maintained by Supranational. |
| `chacha20poly1305` (RustCrypto) | `=0.10.1` (first imported by `adamant-crypto::symmetric` per whitepaper 3.5) | None in the pure-Rust default backend; opt-in SIMD backends in the underlying `chacha20` crate would carry `unsafe` but are not enabled here. | AEAD primitive used for transport encryption (whitepaper 3.5), encrypted-mempool envelopes (3.6), and account-encryption (4). The wrapper takes an explicit nonce; nonce-uniqueness is enforced by higher-level modules per whitepaper 3.5 and 3.8. | RFC 8439 standardised; widely deployed (TLS 1.3, WireGuard, SSH); constant-time by construction. Resolved on the RustCrypto 0.10 generation — transitives align with `ed25519-dalek`'s tree, no new ecosystem-skew allowlist entries required. |
| `chacha20` (RustCrypto, transitive via `chacha20poly1305`) | `0.9.1` (transitive pin held by `Cargo.lock`) | None on the pure-Rust path used here; SIMD backends behind feature flags would carry `unsafe`. | The `ChaCha20` stream cipher (Bernstein 2008), the encryption half of the AEAD construction. Tracked separately from `chacha20poly1305` because it is the actual cipher primitive while `chacha20poly1305` composes it with `Poly1305`. | RustCrypto project; widely deployed; constant-time by construction (no S-boxes, no timing-variable branches). |
| `poly1305` (RustCrypto, transitive via `chacha20poly1305`) | `0.8.0` (transitive pin held by `Cargo.lock`) | Pure-Rust default backend; SIMD-optimised paths gated behind feature flags carry `unsafe`. | The `Poly1305` one-time MAC (Bernstein 2005), the authentication half of the AEAD construction. Tracked separately from `chacha20poly1305` because it is the MAC primitive whose tag-comparison constant-time discipline is security-critical for the wrapper. | RustCrypto project; widely deployed; constant-time tag verification is the core audit signal. |
| `halo2_gadgets` (zcash) | pending first-use | May use `unsafe` for elliptic-curve and field arithmetic. | Halo 2 throughput depends on optimised EC and field operations. | Deployed in Zcash Orchard pool; primary audit signal. Full Halo 2 surface decision deferred to Phase 6. |
| `zeroize` | `=1.8.2` (first imported by `adamant-crypto::sig_classical` for `SigningKey` zero-on-drop) | Uses compiler-fence intrinsics; explicitly documents and bounds `unsafe`. | Required for sound secret-material erasure under modern compiler optimisations. The `SigningKey` wrapper manually impls `Zeroize` and `ZeroizeOnDrop` because dalek 2.2 exposes `ZeroizeOnDrop` only (the inner type lacks a `Default` for `Zeroize`); see `sig_classical.rs` for the rationale. | Maintained by the RustCrypto project; widely deployed. |
| `arkworks` (`ark-bls12-381`, `ark-poly`, …) | added when `kzg` module lands | May use `unsafe` for performance-critical field and pairing operations. | Used for KZG vector / polynomial commitments per whitepaper 3.7.2. | Widely used in zk systems; community-maintained. |

`pending first-use` means the dependency is declared in
`[workspace.dependencies]` but not yet imported by any module; the version
pin is finalised in the commit that imports it.

## Adamant-authored `unsafe` surface

Adamant maintains a single workspace-wide containment crate for any
`unsafe` operations the protocol requires. Every other Adamant-authored
crate inherits `[workspace.lints]` and therefore `unsafe_code = "forbid"`.

| Crate | Whitepaper section | Surface exposed | Justification |
|-------|--------------------|-----------------|---------------|
| `adamant-crypto-blst-extra` | 3.6 (consumer); algorithms underlying 3.4.3 and 3.6 | Safe Rust API over `blst`'s lower-level operations: G₁ hash-to-curve, G₁/G₂ compressed encoding parse/serialise with subgroup validation, G₂ scalar multiplication, pairings as `blst_fp12`, Z_r scalar arithmetic (`Scalar` type with `add`/`sub`/`mul`/`inverse`, `from_u32`/`zero`/`one`, `to_bytes_le`/`to_bytes_be`, `from_bytes_be`). Public types (`G1Point`, `G2Point`, `GtElement`, `Scalar`) are opaque newtypes; the `blst` raw types do not leak across the API boundary. | The threshold-encryption construction (whitepaper 3.6, implemented in `adamant-crypto::threshold`) requires operations that `blst`'s safe `min_sig`/`min_pk`/`Pairing`/`MultiPoint` surface does not expose — only the raw FFI bindings in `blst::*` do. Rather than drop the workspace `unsafe_code = forbid` lint to enable in-place FFI calls, the FFI is contained in this single-purpose wrapper crate. The split lets `adamant-crypto` (and every higher crate) preserve `forbid`. The hot paths in threshold encryption (decryption-share generation and per-share verification) reuse `blst::min_sig::SecretKey::sign` and `blst::min_sig::PublicKey::verify` from blst's own safe surface and never touch this crate, keeping the contained surface focused on the encapsulator and Lagrange-combination paths. |

**Discipline rules for this crate:**

- Each `unsafe` block contains exactly one FFI call (or a tightly
  coupled group, e.g. `from_affine` + `mult` + `to_affine`) and is
  preceded by a `// SAFETY:` comment naming the invariants the FFI
  relies on.
- Public types are opaque newtypes around `blst` raw types. Callers
  cannot acquire a `blst_p1_affine` etc. through this crate's API.
- The crate's lint configuration in its own `Cargo.toml` mirrors the
  workspace lint table except for `unsafe_code` (set to `allow`).
  Cargo does not permit mixing `[lints] workspace = true` with
  per-crate overrides, so the workspace lint table must be kept in
  sync manually; the `Cargo.toml` carries a comment noting this.

**Discipline rule for new crates:**

New crates default to `forbid` via `[lints] workspace = true`.
Relaxing the lint requires:

1. A justification documented in this section (single-purpose
   FFI wrapper for an audited cryptographic library, with the
   surface enumerated and bounded).
2. An audit-ready row added to the table above.
3. A discussion with project maintainers before the override lands.

Reviewers should grep the workspace for `allow(unsafe_code)` and
verify each occurrence is in `adamant-crypto-blst-extra` (or in a
crate documented in the table above).

## RustCrypto ecosystem skew

The Adamant cryptographic dependency tree currently spans two
generations of the RustCrypto ecosystem. Most RustCrypto crates exist
in two parallel lines: the older "0.10 generation" (`digest 0.10`,
`signature 2.x`, `sha3 0.10`, `keccak 0.1`, etc.) and the newer
"post-0.10 generation" (`digest 0.11`, `signature 3.0`, `sha3 0.11`,
`keccak 0.2`, etc.). The break between the two generations is at the
trait level — every crate that depends on `digest` had to choose one
side.

Adamant needs both:

- `ed25519-dalek =2.2.0` (current crates.io release) — depends on the
  0.10-generation traits.
- `ml-dsa =0.1.0-rc.9` (the FIPS-204-compliant ML-DSA implementation
  per whitepaper 3.4.2) — depends on the post-0.10 generation.

Both link into the runtime, so both generations of the trait crates
and many of their downstream impls live in the binary side by side.
The version pairs allowlisted in `clippy.toml` against
`clippy::multiple_crate_versions` with the shared rationale below
are: `block-buffer`, `const-oid`, `crypto-common`, `der`, `digest`,
`keccak`, `pkcs8`, `sha3`, `signature`, `spki`.

**Operational implications.** Two SHA3 / Keccak implementations link
into the same binary (`sha3 =0.10.9` + `keccak 0.1.6` for the Ed25519
path; `sha3 0.11.0` + `keccak 0.2.0` for the ML-DSA path). They
produce algorithmically identical outputs — both implement FIPS 202
correctly — but the audit surface is doubled: a hypothetical bug in
one version would not be caught by an audit of the other. Larger
binary size and longer compile times are the further consequences.
There is no functional difference between the two paths from a
correctness standpoint.

**Why we accepted this.** Phase 1 ships Ed25519 and ML-DSA as
first-class signature schemes (whitepaper 3.4). The alternatives
were (a) a non-RustCrypto Ed25519 implementation (sacrificing
the dalek audit posture and constant-time discipline), or (b) a
pre-FIPS-204 ML-DSA crate (sacrificing FIPS 204 compliance and the
post-quantum-from-genesis commitment in whitepaper 3.4.2). Neither
is acceptable. The skew is the cost of being early adopters of
post-quantum signatures while the underlying ecosystem mid-migrates.

**Revisit signal (single, applies to all ten allowlisted version
pairs).** Remove the relevant `clippy.toml` allowlist entries when
`ed25519-dalek` upgrades to the post-0.10 RustCrypto ecosystem
(specifically: when it depends on `signature` 3.x, `digest` 0.11.x,
etc.) OR when an alternative ML-DSA crate targeting the 0.10
ecosystem appears, whichever happens first. The `clippy.toml`
rationale block carries the same trigger condition. Revisiting is a
minor diff: drop the ten allowlist entries, run `cargo update`, and
verify clippy stays clean.

## BLS test-vector coverage

The BLS12-381 wrapper has a coverage shape distinct from every other
primitive in this workspace, and the difference is large enough to
deserve a top-level explanation rather than only a row-level
footnote. (Same pattern as "RustCrypto ecosystem skew" above:
coverage and trust properties that differ from the rest of the
codebase get clearly-labelled subsections an auditor can find on
first read.)

**What's happening.** BLS12-381 has two well-known signature
variants. **min_pk** (G1 public key 48 B, G2 signature 96 B) is what
Ethereum consensus, Filecoin, Chia, and the IRTF
`draft-irtf-cfrg-bls-signature` examples use; every widely-circulated
BLS KAT suite — `ethereum/bls12-381-tests`, the IRTF draft examples,
Filecoin and Chia's repositories — targets it. **min_sig** (G2
public key 96 B, G1 signature 48 B) is what the whitepaper §3.4.3
selects for Adamant. The variants are not byte-compatible: a 48-byte
hex string labelled "pubkey" in an Eth2 vector encodes a G1 point,
which for us is a Signature, not a PublicKey. Cross-applying the
external KATs with relabelling would not exercise our wrapper's
actual sign/verify codepaths because the message + DST framing
differs between variants.

**Why we accepted it.** The variant choice is architectural. Per
whitepaper §3.4.3, "Signatures are smaller (48 bytes), which matters
at consensus scale; public keys are larger but registered once per
validator." Signatures are exchanged on every consensus vote;
public keys are written once at validator registration. min_sig
optimises the bandwidth-critical artifact. Switching to min_pk for
testability would invert a deliberate spec choice for the sake of
KAT availability.

**What we rely on instead.** Three layers, in order of independence:

1. **Upstream `blst` is itself tested against IRTF and Ethereum
   vectors at the algorithm level.** blst implements both variants
   via shared primitives — the same group ops, pairing, and
   hash-to-curve back min_pk and min_sig. blst's IRTF/Eth2 KAT
   suite (which exercises min_pk directly) therefore validates the
   maths that backs our min_sig path. blst's audit history is
   recorded in the row above; the upstream tests are part of that
   audit signal.
2. **22 inline self-consistency tests** in `bls.rs::tests` covering
   the API surface and the four aggregation cases whitepaper §3.4.3
   names (same-message aggregate, multi-message aggregate-verify,
   tampering of one signature in an aggregate, tampering of the
   aggregate signature bytes after the fact).
3. **DST sourcing is asserted at compile time** (the DST is taken
   from the centralised `crate::domain` registry, never inlined)
   and **verified at test time** against the byte string in
   whitepaper §3.4.3 verbatim.

**Operational implication.** An auditor reviewing the BLS wrapper
should look at **blst's upstream test suite** for primitive-level
coverage, not at external min_pk KAT suites. The
`crates/adamant-crypto/test-vectors/bls/` directory is intentionally
sparse — it contains a README explaining why, not committed KAT
files. This differs from `test-vectors/sha3/`, `test-vectors/ed25519/`,
and `test-vectors/ml-dsa/`, which all carry NIST or RFC vectors
verifying our wrappers directly.

**Revisit signal.** When a min_sig BLS KAT suite appears upstream
— Filecoin and Chia occasionally ship variant-specific tests, and
the IRTF draft may grow them — drop it into
`crates/adamant-crypto/test-vectors/bls/` and update this subsection
to point at the new coverage. Re-evaluate before mainnet regardless;
absence of variant-specific KATs at mainnet would be a known
limitation worth flagging in audit prep.

## Update process

**Adding a cryptographic dependency:**

1. Verify the crate is named in whitepaper section 3. If not, surface the
   deviation to Ryan — substitution requires whitepaper revision.
2. Add a row to the table above with the pinned version, `unsafe` usage,
   justification, and audit signal.
3. Add the crate to the workspace `Cargo.toml`'s `[workspace.dependencies]`
   with the same pinned version.
4. Reference whitepaper section 3 (and this file) in the commit message.

**Upgrading an existing dependency:**

1. Confirm the new version's audit posture and `unsafe` usage have not
   regressed. Read the changelog for security-relevant changes.
2. Update the version in this table and in the workspace `Cargo.toml`.
3. Run the full test-vector suite for the affected primitive before merging.

**Reacting to an upstream advisory or audit result:**

1. Update the audit signal column with the date and finding.
2. If Adamant is affected, surface to Ryan immediately and pause any work
   that depends on the affected primitive until the path forward is clear.

## Deferred decisions

Performance flags, feature toggles, and configuration choices that have
been considered and deliberately not enabled, each recorded with a
trigger condition for revisiting. The point of this section is to keep
deferral visible: an option only stays deferred while it has a
documented reason; otherwise it drifts into a default of expediency.

Entries grow over time as decisions like this surface. Format per
entry: name, current state, trigger to revisit.

- **`ed25519-dalek`'s `fast` feature** (enables `curve25519-dalek/precomputed-tables` for a measurable Ed25519 signing speedup at a memory cost). Currently disabled. **Revisit** before mainnet as part of the protocol-wide performance-flag pass; the table-memory trade-off is the decision to evaluate then.

## Out of scope

This document tracks the cryptographic dependency surface specifically.
Build-tooling and test-only dependencies (`proptest`, `hex`, `hex-literal`,
etc.) are not tracked here unless they handle secret material.
