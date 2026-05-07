//! Adamant-native module-level verifier passes (whitepaper
//! §6.2.1.8 step 3).
//!
//! Phase 5/5b.2 ports the seven *small/medium* upstream module-
//! level passes from Sui-Move's `move-bytecode-verifier` into
//! Adamant-owned implementations:
//!
//! - constant-pool validation (`constants`)
//! - friend-declaration validation (`friends`)
//! - ability-field-requirements (`ability_field_requirements`)
//! - structural limits (`limits`)
//! - recursive data-definition cycle detection
//!   (`recursive_data_def`)
//! - generic instantiation-loop detection (`instantiation_loops`)
//! - per-instruction generic/non-generic consistency
//!   (`instruction_consistency`)
//!
//! Phase 5/5b.3 ports the three *large* upstream module-level
//! passes (`BoundsChecker`, `DuplicationChecker`,
//! `SignatureChecker`). Phase 5/5b.4 + 5/5b.5 ports the per-
//! function passes. Phase 5/5b.5 also tears out the transitional
//! Sui-verifier bridge in [`super::verify_module`].
//!
//! # Provenance
//!
//! Each pass module documents its upstream lineage at the file
//! header. The full deviation list (typed closed-enum errors
//! over `PartialVMError`/`StatusCode`, condensed doc comments,
//! `expect()` over `as` truncation casts, no production-code
//! dependence on `move-*` crates) lives in
//! `validator/module_pass/PROVENANCE.md`, parallel to the
//! `adamant-bytecode-format/PROVENANCE.md` pattern from Phase
//! 5/5b.1a + 5/5b.1b.
//!
//! Phase 5/5b.2 sub-arc: B-1 lands the foundation
//! (`AdamantStructuralLimits`, `ability_cache`); B-2 lands the
//! four small passes (`constants`, `friends`,
//! `instruction_consistency`, `ability_field_requirements`);
//! B-3 lands the three medium passes (`limits`,
//! `recursive_data_def`, `instantiation_loops`); B-4 lands
//! Rule 2; B-5 wires step 3 into [`super::verify_module`]
//! before the transitional Sui-verifier bridge; B-6 closes
//! out with workspace test-pass + CLAUDE.md state-bump.

mod ability_cache;
mod constants;
