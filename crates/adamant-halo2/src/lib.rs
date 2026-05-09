//! Adamant-owned fork of the Halo 2 ecosystem (Zcash variant)
//! per CLAUDE.md §14.4 Decision 1 (resolved as Path C2).
//!
//! Phase 6.8b vehicle. Fork-over-vendoring discipline applies:
//! production-binary dependency graph contains zero upstream
//! `halo2_*` crates; upstream code is consulted only at refresh
//! time and (for a small set of cross-validation parity tests)
//! at test time.
//!
//! See `crates/adamant-halo2/PROVENANCE.md` for fork sources,
//! per-sub-arc behavioural-change records, and the refresh
//! policy.
//!
//! # Sub-arc map
//!
//! | Sub-arc       | Surface                                    | Status       |
//! |---------------|--------------------------------------------|--------------|
//! | 6.8b.0        | [`poseidon::primitives`] (out-of-circuit)  | DONE         |
//! | 6.8b.1        | [`proofs`] (PLONKish + IPA)                | DONE         |
//! | 6.8b.2        | [`poseidon::Pow5Chip`] + [`utilities`]     | DONE         |
//! | 6.8b.3        | [`ecc`] chips for Pallas + [`sinsemilla`]  | THIS SUB-ARC |
//! | 6.8b.4        | §7.3.2 validity circuit                    | pending      |
//! | 6.9b          | recursive proof composition                | pending      |
//!
//! # Resistant-proof posture
//!
//! Per CLAUDE.md §14.4 Decision 1 + §13: Adamant does not run
//! external Halo 2 libraries at deploy-time or runtime. The
//! mechanical guardrail is `tests/no_upstream_halo2_in_production_deps.rs`
//! at the workspace root — `cargo metadata` walk asserts no
//! upstream `halo2_*` crate appears in the production-target
//! dependency graph.

#![forbid(unsafe_code)]

pub mod ecc;
pub mod poseidon;
pub mod proofs;
pub mod sinsemilla;
pub mod utilities;
