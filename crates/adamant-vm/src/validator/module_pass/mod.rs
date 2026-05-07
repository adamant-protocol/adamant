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
mod friends;

#[cfg(test)]
pub(in crate::validator::module_pass) mod test_helpers {
    //! Shared test helpers for the module-level passes'
    //! Layer B cross-validation tests.
    //!
    //! Each pass's `tests` module asserts accept/reject
    //! parity between Adamant's pass and Sui's same pass on
    //! the same module (after BCS round-trip through
    //! [`crate::module::AdamantCompiledModule::to_sui_module`]).
    //! The match-body that compares the two results is
    //! byte-identical across every pass — [`assert_pass_parity`]
    //! is the shared implementation.
    //!
    //! Extracted at Phase 5/5b.2 B-2.2 once the second pass
    //! (`friends`) duplicated the body. Per CLAUDE.md
    //! discipline, premature abstraction at N=1 is worse than
    //! copy-paste; the extraction trigger is N=2 with byte-
    //! identical bodies, which is what this helper sees.
    //!
    //! Future B-3 passes (`limits`, `recursive_data_def`,
    //! `instantiation_loops`) reuse the helper without
    //! changing its surface; if a future pass's parity check
    //! needs different shape (e.g., asserting on specific
    //! status-code mappings rather than just accept/reject),
    //! that pass introduces its own helper alongside this one.

    use move_binary_format::errors::VMResult;

    use crate::validator::error::AdamantValidationError;

    /// Assert accept/reject parity between Adamant's pass
    /// result and Sui's pass result.
    ///
    /// `pass_name` appears in the panic message on
    /// disagreement; pass it the bare pass name (e.g.,
    /// `"constants"`, `"friends"`).
    ///
    /// Adamant's typed-error variant and Sui's `StatusCode`
    /// shape do not match by design (the resistant-proof
    /// posture takes Adamant off Sui's error machinery); the
    /// parity check is on accept-vs-reject only. A future
    /// pass that needs status-code-mapping parity introduces
    /// its own helper rather than extending this one.
    pub(in crate::validator::module_pass) fn assert_pass_parity(
        pass_name: &str,
        adamant: Result<(), AdamantValidationError>,
        sui: VMResult<()>,
    ) {
        match (adamant, sui) {
            (Ok(()), Ok(())) | (Err(_), Err(_)) => {}
            (a, s) => panic!(
                "Adamant/Sui disagreement on {pass_name} pass: \
                 adamant = {a:?}, sui = {s:?}"
            ),
        }
    }
}
