# `adamant-halo2` — fork provenance

This crate is the Adamant-owned fork of the Halo 2 ecosystem
(Zcash / Electric Coin Company variant) per CLAUDE.md §14.4
Decision 1 (resolved as Path C2). The fork-over-vendoring
discipline (CLAUDE.md §14.3) applies: production-binary
dependency graph contains zero upstream `halo2_*` crates;
upstream code is consulted only at refresh time and at test time
for cross-validation parity.

## Architectural commitment

Adamant does not run external Halo 2 libraries at deploy-time
or runtime. The protocol's resistant-proof posture (whitepaper
§13 + CLAUDE.md §14) requires that the protocol work fully
independently of the Zcash / ECC codebase so that upstream
changes, shutdowns, vulnerabilities, governance shifts, or
licensing changes cannot affect Adamant's deploy-time accept /
reject decisions or runtime behaviour.

The mechanical guardrail is `tests/no_upstream_halo2_in_production_deps.rs`
(at the workspace root, lands at Phase 6.8b.0): it walks the
resolved dependency tree via `cargo metadata` and fails CI if
any upstream `halo2_*` crate (i.e., not this `adamant-halo2`
crate) appears in the production-target dependency graph.

## Vendored sub-arcs

Each sub-arc copies a self-contained upstream surface into this
crate's `src/`. Behavioural changes from upstream are
enumerated here per sub-arc; algorithmic deviation requires a
spec-author call.

### Sub-arc 6.8b.0 — `halo2_poseidon` 0.1.0

**Source.** `halo2_poseidon` crate at version `0.1.0`, sourced
from `https://crates.io/crates/halo2_poseidon` (upstream repo
`https://github.com/zcash/halo2`, MIT OR Apache-2.0
dual-licensed).

**Vendored files.** Seven source files copied verbatim from
the upstream `src/` into `crates/adamant-halo2/src/poseidon/`:

| Upstream file        | Adamant location                          | LOC  |
|----------------------|-------------------------------------------|------|
| `src/lib.rs`         | `src/poseidon/mod.rs`                     | 490  |
| `src/p128pow5t3.rs`  | `src/poseidon/p128pow5t3.rs`              | 322  |
| `src/grain.rs`       | `src/poseidon/grain.rs`                   | 195  |
| `src/mds.rs`         | `src/poseidon/mds.rs`                     | 131  |
| `src/fp.rs`          | `src/poseidon/fp.rs`                      | 1431 |
| `src/fq.rs`          | `src/poseidon/fq.rs`                      | 1431 |
| `src/test_vectors.rs`| `src/poseidon/test_vectors.rs`            | 1263 |
|                      | **Total**                                 | 5263 |

**Behavioural changes from upstream.** Limited to mechanical
adaptations required to ship the upstream source as a
sub-module of `adamant-halo2` rather than as a free-standing
crate. No algorithmic deviation.

1. **`#![no_std]` removed** at module-root level. The crate
   root `crates/adamant-halo2/src/lib.rs` is `std` by workspace
   convention; Adamant has no `no_std` target. Upstream's
   `no_std + alloc` shape is collapsed to plain `std`.
2. **`extern crate alloc;` removed.** `String` / `Vec` resolve
   from `std`'s prelude / re-exports.
3. **`use alloc::{vec::Vec, string::String};` removed.** Same
   reason as above; replaced with comments noting the change.

The Poseidon parameter set is pinned by whitepaper §3.3.3
(post-amendment instance 31) at `P128Pow5T3` over Pallas's
base field with `ConstantLength` domain (8 full + 56 partial
rounds). Round constants in `fp.rs` / `fq.rs` and the MDS
matrix in `mds.rs` are byte-identical to upstream.

**Cross-validation.** A test under `tests/cross_validation.rs`
(lands as part of this sub-arc when adamant-privacy's import
switch is verified) compares this fork's
`P128Pow5T3 as Spec<...>` round counts against the upstream
`halo2_poseidon 0.1.0` crate's same trait. Drift surfaces as a
development-time signal; resolution follows the vendor-refresh
checklist below.

**Audit posture.** This sub-arc's audit surface is the seven
vendored files plus the three behavioural changes above.
Algorithm-level review reduces to upstream `halo2_poseidon
0.1.0`'s audit history (Zcash production deployment); fork-
specific review reduces to confirming the three behavioural
changes do not alter the algorithmic surface.

### Sub-arc 6.8b.1 — `halo2_proofs` 0.3.2

**Source.** `halo2_proofs` crate at version `0.3.2`, sourced
from `https://crates.io/crates/halo2_proofs` (upstream repo
`https://github.com/zcash/halo2`, MIT OR Apache-2.0
dual-licensed).

**Variant choice (IPA-vs-KZG).** Settled by the upstream-tag
choice itself: `halo2_proofs 0.3.2` (Zcash variant) is
**IPA-only** — the polynomial commitment scheme is Inner
Product Arguments, with no `kzg/` subdirectory anywhere in
upstream's `src/poly/`. This is consistent with whitepaper
§3.9 ("Halo 2 (PLONKish, no trusted setup)") — the no-trusted-
setup property comes from IPA. The KZG variant lives in a
separate upstream branch (PSE / privacy-scaling-explorations);
Adamant does not consume it.

**Vendored files.** 52 source files copied verbatim from the
upstream `src/` into `crates/adamant-halo2/src/proofs/`:

| Upstream tree     | Adamant location                | LOC    |
|-------------------|---------------------------------|--------|
| `src/lib.rs`      | `src/proofs/mod.rs`             | ~30    |
| `src/arithmetic.rs` + `src/multicore.rs` + `src/helpers.rs` + `src/transcript.rs` | (parallel) | ~1500 |
| `src/circuit/` + `circuit.rs` (4 files)   | `src/proofs/circuit/` + `circuit.rs` | ~3000 |
| `src/dev/` + `dev.rs` (8 files)           | `src/proofs/dev/` + `dev.rs`         | ~3500 |
| `src/plonk/` + `plonk.rs` (24 files)      | `src/proofs/plonk/` + `plonk.rs`     | ~7500 |
| `src/poly/` + `poly.rs` (8 files; IPA-only) | `src/proofs/poly/` + `poly.rs`       | ~3000 |
|                   | **Total**                       | ~18382 |

**Behavioural changes from upstream.** Limited to mechanical
adaptations required to ship the upstream source as a
sub-module of `adamant-halo2` rather than as a free-standing
crate. No algorithmic deviation.

1. **Crate-level attributes removed** at `mod.rs` level. The
   upstream `src/lib.rs` carried `#![cfg_attr(docsrs, ...)]`,
   `#![allow(clippy::*)]`, `#![deny(rustdoc::*)]`,
   `#![deny(missing_*)]`, and `#![deny(unsafe_code)]` —
   none can appear inside `mod.rs`. The parent crate's
   `Cargo.toml` already sets `unsafe_code = "forbid"` at the
   `lints.rust` level, which is stronger than upstream's
   `#![deny(unsafe_code)]`.
2. **`crate::*` paths inside the forked tree rewritten to
   `crate::proofs::*`.** Upstream code's `crate::` always
   referred to its own root (the upstream `lib.rs`); after
   forking under `crate::proofs::`, every internal reference
   shifts one level. Bulk-applied via `sed` to all `*.rs`
   files under `crates/adamant-halo2/src/proofs/`. The rewrite
   is correct everywhere because no upstream `crate::*` reference
   could refer to anything outside the upstream crate.

**Cross-validation.** A future test under `tests/cross_validation.rs`
will exercise selected proof / verify round-trips and compare
against upstream `halo2_proofs 0.3.2`'s outputs to confirm
byte-identical behaviour. Lands at the natural cross-validation
sub-arc (parallel to the Phase 5/5c discipline established for
the bytecode verifier).

**Upstream tests preserved.** All 32 of upstream's own
`#[test]` functions across `proofs::arithmetic`,
`proofs::plonk::*`, `proofs::poly::commitment`,
`proofs::poly::multiopen`, `proofs::dev::*`, etc., compile
and pass against the fork verbatim. Combined with the 7
`poseidon` tests from sub-arc 6.8b.0, `adamant-halo2`'s
test count is 39 at this sub-arc closure.

**Audit posture.** Algorithm-level review reduces to upstream
`halo2_proofs 0.3.2`'s audit history (Zcash production
deployment + Aztec usage); fork-specific review reduces to
confirming the two behavioural-change classes above
(crate-attribute removal + `crate::` → `crate::proofs::`
rewrite) do not alter the algorithmic surface.

## Refresh policy

Upstream `halo2_poseidon` (and the broader Halo 2 ecosystem)
may issue patches. The discipline is:

1. **Default = no automatic refresh.** Fork lives at the
   pinned upstream version (`halo2_poseidon 0.1.0` for sub-arc
   6.8b.0) until a deliberate refresh is initiated.
2. **Trigger = security advisory or bug fix relevant to
   Adamant's surface.** Refresh is initiated by the spec-author
   (Ryan); not by Claude Code or any subagent autonomously.
3. **Refresh procedure.**
   - Read upstream's CHANGELOG entries since the pinned
     version. Identify changes relevant to the vendored
     surface.
   - Reapply behavioural changes (§ "Behavioural changes from
     upstream" above) on top of the new upstream code.
   - Run cross-validation tests. If parity holds, ship.
   - If upstream introduces algorithmic changes, treat as a
     spec-author deliberation (potential whitepaper amendment).

## License

Upstream `halo2_poseidon` is MIT OR Apache-2.0 dual-licensed.
Adamant's `LICENSE` file (Apache-2.0) covers the fork; the
upstream MIT/Apache notice is preserved in this `PROVENANCE.md`
and in the per-file source comments where present.
