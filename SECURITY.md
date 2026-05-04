# Adamant — Cryptographic Dependency Security Surface

This document records the `unsafe` surface and audit signal of every
cryptographic dependency used by Adamant. It is part of the security audit
surface. Updates are deliberate, called out in commit messages, and required
before a new cryptographic dependency may be added to any `Cargo.toml`.

## Policy

- **No `unsafe` in Adamant-authored crates.** Every workspace member
  inherits `unsafe_code = "forbid"` from the workspace lints. Crates that
  need to drop the lint must justify it explicitly; none currently do.
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
| `blake3` | pending first-use | SIMD intrinsics for AVX2 / AVX-512 / SSE / NEON backends. | BLAKE3's design relies on SIMD parallelism; the published performance is the reason it is selected over SHA3 on non-consensus-critical paths. | Reference implementation maintained by the BLAKE3 designers; widely deployed. |
| `ed25519-dalek` (dalek-cryptography) | pending first-use | None in default configuration; the dalek ecosystem explicitly minimises and documents `unsafe`. | Constant-time, no-`unsafe` Ed25519 is a property the dalek ecosystem maintains as a deliberate design choice. | Widely audited; deployed in Signal, Tor, and many cryptocurrency systems. |
| `ml-dsa` (RustCrypto) | pending first-use | May use `unsafe` for performance-critical polynomial / NTT operations. | ML-DSA polynomial arithmetic benefits from constant-time SIMD where the platform supports it. | RustCrypto project; cryptanalysis on ML-DSA itself (FIPS 204) is extensive; implementation audit ongoing. |
| `blst` (Supranational) | pending first-use | Required: Rust binding over the C-language `blst` library. | `blst` is the canonical high-performance BLS12-381 implementation; no pure-Rust equivalent matches its performance or audit posture. | Audited (NCC Group 2020 and subsequent); deployed in Ethereum, Filecoin, Chia. |
| `chacha20poly1305` (RustCrypto) | pending first-use | None in pure-Rust mode; SIMD backends use `unsafe`. | AEAD throughput affects transport encryption and mempool envelope cost. | Widely deployed; constant-time by construction. |
| `halo2_gadgets` (zcash) | pending first-use | May use `unsafe` for elliptic-curve and field arithmetic. | Halo 2 throughput depends on optimised EC and field operations. | Deployed in Zcash Orchard pool; primary audit signal. Full Halo 2 surface decision deferred to Phase 6. |
| `zeroize` | pending first-use | Uses compiler-fence intrinsics; explicitly documents and bounds `unsafe`. | Required for sound secret-material erasure under modern compiler optimisations. | Maintained by the RustCrypto project; widely deployed. |
| `arkworks` (`ark-bls12-381`, `ark-poly`, …) | added when `kzg` module lands | May use `unsafe` for performance-critical field and pairing operations. | Used for KZG vector / polynomial commitments per whitepaper 3.7.2. | Widely used in zk systems; community-maintained. |

`pending first-use` means the dependency is declared in
`[workspace.dependencies]` but not yet imported by any module; the version
pin is finalised in the commit that imports it.

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

## Out of scope

This document tracks the cryptographic dependency surface specifically.
Build-tooling and test-only dependencies (`proptest`, `hex`, `hex-literal`,
etc.) are not tracked here unless they handle secret material.
