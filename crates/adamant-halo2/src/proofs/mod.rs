//! # `proofs` — fork of `halo2_proofs 0.3.2` (Zcash variant)
//!
//! Forked at Phase 6.8b.1 per CLAUDE.md §14.4 Decision 1
//! (resolved as Path C2). Adamant-owned; refresh cadence and
//! audit posture documented in
//! `crates/adamant-halo2/PROVENANCE.md`.
//!
//! The upstream tag (`halo2_proofs 0.3.2`) is **IPA-only** —
//! the polynomial commitment scheme is Inner Product
//! Arguments, consistent with whitepaper §3.9 ("Halo 2
//! (PLONKish, no trusted setup)"). The KZG variant lives in a
//! separate upstream branch (PSE / privacy-scaling-explorations)
//! that Adamant does not consume. The IPA-vs-KZG question
//! flagged at the §14.4 Decision 1 plan-gate is therefore
//! settled by the upstream-tag choice itself.
//!
//! Behavioural changes from upstream are limited to mechanical
//! adaptations required to ship the upstream source as a
//! sub-module rather than a free-standing crate. See
//! `crates/adamant-halo2/PROVENANCE.md` for the per-file
//! enumeration.

pub mod arithmetic;
pub mod circuit;
pub use pasta_curves as pasta;
mod multicore;
pub mod plonk;
pub mod poly;
pub mod transcript;

pub mod dev;
mod helpers;
