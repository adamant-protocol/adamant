//! Shared Layer B cross-validation helpers for the per-function
//! passes.
//!
//! Each per-function pass's `tests` module asserts accept/reject
//! parity between Adamant's pass and Sui's same pass on the same
//! module (after BCS round-trip through
//! [`crate::module::AdamantCompiledModule::to_sui_module`]). The
//! match-body that compares the two results is byte-identical
//! across every pass — [`assert_function_pass_parity`] is the
//! shared implementation, parallel to
//! `module_pass/mod.rs::test_helpers::assert_pass_parity`.
//!
//! Per-function passes also need an aggregator state on the
//! Sui side. Sui's per-pass entries
//! ([`StackUsageVerifier::verify`][_susv],
//! [`locals_safety::verify`][_slsv],
//! [`type_safety::verify`][_stsv]) are `pub(crate)` — the
//! composite per-function entry [`code_unit_verifier::verify_module`]
//! is the only public surface reachable from our test code.
//! [`run_sui_code_unit_verifier`] encapsulates the
//! `AbilityCache` + `DummyMeter` lifecycle the composite entry
//! requires; [`sui_config_from`] converts Adamant's
//! [`AdamantStructuralLimits`] into the Sui-side
//! [`VerifierConfig`] fields exercised by the per-function
//! parity tests (`max_loop_depth`, `max_push_size`).
//!
//! [_susv]: move_bytecode_verifier::stack_usage_verifier::StackUsageVerifier
//! [_slsv]: move_bytecode_verifier::locals_safety
//! [_stsv]: move_bytecode_verifier::type_safety
//!
//! Extracted at Phase 5/5b.4 D-7a. The trigger is N=3 (extract-
//! at-N=3, sub-shape α of helper-extraction discipline; D-2
//! control-flow + D-3 stack-usage + D-4 locals-safety all need
//! the shared shape from inception of their Layer B backfills).
//! The module-level helper at
//! `module_pass/mod.rs::test_helpers` was extract-at-N=2 (sub-
//! shape β of the same discipline) — see
//! `module_pass/PROVENANCE.md`.

use move_binary_format::CompiledModule;
use move_binary_format::errors::{PartialVMResult, VMResult};
use move_bytecode_verifier::ability_cache::AbilityCache;
use move_bytecode_verifier::code_unit_verifier;
use move_bytecode_verifier_meter::dummy::DummyMeter;
use move_vm_config::verifier::VerifierConfig;

use crate::module::AdamantCompiledModule;
use crate::validator::config::AdamantStructuralLimits;
use crate::validator::error::AdamantValidationError;

/// Convert an Adamant module to its Sui twin for cross-validation.
///
/// Panics if the module contains Adamant extensions — Layer B
/// parity is for inherited-subset modules only (Adamant
/// extensions have no upstream counterpart by design).
pub(in crate::validator::function_pass) fn to_sui(m: &AdamantCompiledModule) -> CompiledModule {
    m.to_sui_module()
        .expect("test fixture has no Adamant extensions; to_sui_module must succeed")
}

/// Build a Sui [`VerifierConfig`] mirroring the per-function-pass
/// fields of the supplied [`AdamantStructuralLimits`].
///
/// Sui defaults `max_loop_depth` and `max_push_size` to `None`
/// (no limit) in `VerifierConfig::default()`; Adamant's genesis
/// defaults set `Some(64)` and `Some(10000)` respectively per
/// `validator/config.rs`. Mirroring those values into Sui's
/// config keeps the parity comparison apples-to-apples.
pub(in crate::validator::function_pass) fn sui_config_from(
    adamant: &AdamantStructuralLimits,
) -> VerifierConfig {
    VerifierConfig {
        max_loop_depth: adamant.max_loop_depth.map(usize::from),
        max_push_size: adamant.max_push_size.map(|p| {
            usize::try_from(p).expect(
                "max_push_size fits usize on Adamant's supported targets \
                 (64-bit pointers; D-7a Layer B helper)",
            )
        }),
        ..VerifierConfig::default()
    }
}

/// Assert accept/reject parity between Adamant's per-function
/// pass result and Sui's per-function pass result.
///
/// The parity check is on accept-vs-reject only — Adamant's
/// typed-error variants and Sui's `StatusCode` shape do not match
/// by design (the resistant-proof posture takes Adamant off Sui's
/// error machinery). `pass_name` appears in the panic message on
/// disagreement; pass it the bare pass name (e.g.,
/// `"control_flow"`, `"stack_usage"`, `"locals_safety"`).
pub(in crate::validator::function_pass) fn assert_function_pass_parity(
    pass_name: &str,
    adamant: Result<(), AdamantValidationError>,
    sui: PartialVMResult<()>,
) {
    match (adamant, sui) {
        (Ok(()), Ok(())) | (Err(_), Err(_)) => {}
        (a, s) => panic!(
            "Adamant/Sui disagreement on {pass_name} pass: \
             adamant = {a:?}, sui = {s:?}"
        ),
    }
}

/// `VMResult`-shaped variant for parity helpers comparing
/// against Sui's `code_unit_verifier::verify_module` (which
/// returns `VMResult<()>` rather than `PartialVMResult<()>` —
/// it `.finish(...)` on the way out).
pub(in crate::validator::function_pass) fn assert_function_pass_parity_vm(
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

/// Run the Adamant per-function pipeline against the supplied
/// module with the genesis structural-limits configuration.
///
/// Wrapper over [`super::verify_function_bodies`] so per-pass
/// test modules can invoke the pipeline without re-importing
/// the entry every time, and so the fixture-construction
/// boilerplate is symmetric with [`run_sui_code_unit_verifier`]
/// on the Sui side.
pub(in crate::validator::function_pass) fn run_adamant_pipeline(
    module: &AdamantCompiledModule,
    limits: &AdamantStructuralLimits,
) -> Result<(), AdamantValidationError> {
    super::verify_function_bodies(module, limits)
}

/// Run Sui's `code_unit_verifier::verify_module` against the
/// supplied Sui module with a fresh `AbilityCache` and
/// `DummyMeter`.
///
/// `code_unit_verifier::verify_module` is the public per-
/// function entry on Sui's side that runs `control_flow` →
/// `stack_usage` → `type_safety` → `locals_safety` →
/// `reference_safety` → acquires for every function in the
/// module. Sui exposes the per-pass entries (`StackUsageVerifier`,
/// `locals_safety::verify`, `type_safety::verify`) as
/// `pub(crate)`; only the composite entry is reachable from
/// our test code.
///
/// Used by D-3 `stack_usage` and D-4 `locals_safety` Layer B
/// parity tests to compare against Sui's full per-function
/// pipeline. Each fixture is curated to isolate the targeted
/// pass's behaviour: well-formed at every other pass,
/// triggers the rule under test on both sides. Composite-
/// level accept/reject parity follows.
pub(in crate::validator::function_pass) fn run_sui_code_unit_verifier(
    sui_module: &CompiledModule,
    config: &VerifierConfig,
) -> VMResult<()> {
    let mut ability_cache = AbilityCache::new(sui_module);
    code_unit_verifier::verify_module(config, sui_module, &mut ability_cache, &mut DummyMeter)
}
