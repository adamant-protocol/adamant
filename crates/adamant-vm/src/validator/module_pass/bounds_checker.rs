//! Module-level pass: bounds checking
//! (whitepaper §6.2.1.8 step 3, position 1).
//!
//! Forked from `vendor/move-binary-format/src/check_bounds.rs`
//! at Sui-Move tag `mainnet-v1.66.2` (commit
//! `a9a6825eaf6273cc819ee3bcf65fd4909f7624a9`). Note: upstream's
//! `BoundsChecker` lives in `move-binary-format` (the
//! deserializer crate), not in `move-bytecode-verifier`. In
//! Adamant's pipeline the deserializer (Phase 5/5a) does **not**
//! pre-validate bounds; bounds checking is a step-3 module-level
//! pass per §6.2.1.8 line 524's verbatim enumeration ("Bounds
//! checking, structural-limits checking, ..."). See
//! `validator/module_pass/PROVENANCE.md` for the full deviation
//! list and per-pass methodology-pattern co-location.
//!
//! # Pass scope (section 1 of the per-pass doc-comment template)
//!
//! Validates that every index reference inside the deserialized
//! [`AdamantCompiledModule`] resolves to an in-range slot of its
//! addressed pool. Upstream `BoundsChecker::verify_module` runs
//! 17 sub-checks across the module's tables; Phase 5/5b.3 ports
//! them across four sub-checkpoints:
//!
//! - **C-1.1 (this sub-checkpoint):** initial empty-module-handles
//!   short-circuit + `check_signatures` + `check_constants` +
//!   `check_module_handles` + `check_self_module_handle` +
//!   `check_datatype_handles`. Five of upstream's seventeen
//!   sub-checks plus the precondition.
//! - **C-1.2:** function-handle, field-handle, friend-decl, and
//!   the five instantiation tables (struct/function/enum/field/
//!   variant).
//! - **C-1.3:** struct/enum definitions, variant-handles, and
//!   variant-instantiation-handles.
//! - **C-1.4:** function definitions including code-unit body
//!   checks and jump-table validation.
//!
//! Error variants produced at C-1.1:
//!
//! - [`AdamantValidationError::NoModuleHandles`] — the module's
//!   `module_handles` table is empty (no self-handle to anchor
//!   on).
//! - [`AdamantValidationError::IndexOutOfBounds`] — generic out-
//!   of-range carrying `IndexKind` to discriminate the addressed
//!   pool. Used by [`check_signatures`], [`check_constants`],
//!   [`check_module_handles`], [`check_self_module_handle`],
//!   [`check_datatype_handles`], and the [`check_type`] traversal
//!   helper consumed by the first two.
//! - [`AdamantValidationError::NumberOfTypeArgumentsMismatch`] —
//!   a `Datatype(idx)` token references a handle that expects
//!   non-zero type parameters but supplies zero, or a
//!   `DatatypeInstantiation(idx, type_args)` supplies a different
//!   number than the handle declares. Both code paths fire the
//!   same variant; `expected`/`actual` discriminate the sub-case.
//!
//! # No-Sui-parity-claim posture (section 2)
//!
//! Not applicable. C-1.1 makes a **full Sui-parity claim** for
//! the inherited Sui-base subset of inputs: for any module shape
//! produceable through `to_sui_module`'s BCS round-trip, the pass
//! reaches the same accept/reject decision as Sui's
//! [`move_binary_format::check_bounds::BoundsChecker::verify_module`].
//! Layer B parity tests assert the claim per category. The claim
//! is byte-identical at the boundary; the typed-error variant
//! shape differs by design (`AdamantValidationError` rather than
//! `PartialVMError`/`StatusCode`) per the resistant-proof posture.
//!
//! # Deliberate-Adamant-decision (section 3)
//!
//! Not applicable. Direct algorithmic port; preserved byte-
//! faithfully per the methodology principle. Sub-check ordering
//! mirrors upstream's [`verify_impl`] sequence; `check_type`'s
//! Datatype/DatatypeInstantiation arms preserve upstream's
//! "bounds-then-arity" pairing.
//!
//! # Eager-error first-failure-wins (section 4)
//!
//! Internal-to-pass precedence:
//!
//! - [`verify`] short-circuits on the empty-module-handles check
//!   before invoking any sub-check. A module with both an empty
//!   `module_handles` table and an out-of-range signature reports
//!   `NoModuleHandles`.
//! - Sub-check ordering: signatures → constants → module-handles
//!   → self-module-handle → datatype-handles. First-encountered
//!   violation wins. (Upstream order; preserved byte-faithfully.)
//! - Within a sub-check, iteration is in storage order (table
//!   index ascending); the lowest-index offender is reported.
//! - Within `check_type`'s match arms: `Datatype(idx)` and
//!   `DatatypeInstantiation(idx, _)` perform a bounds check on
//!   `idx` first, then (only if bounds succeed) the type-argument
//!   arity check. Upstream is explicit about this pairing; the
//!   port preserves it.
//!
//! # Shared-variant cross-pass precedence (section 5)
//!
//! [`AdamantValidationError::IndexOutOfBounds`] is the workhorse
//! variant for bounds-checker rejections. Cross-pass shared-
//! variant exposure lands at C-1.4 (constant-pool indices
//! referenced in code units) and at C-2/C-3 (duplication and
//! signature passes). At C-1.1 the variant is introduced but
//! used only by the bounds checker itself; precedence pinning
//! against [`super::constants`]'s
//! [`AdamantValidationError::InvalidConstantType`] /
//! [`AdamantValidationError::MalformedConstantData`] surfaces at
//! C-4 wiring time.
//!
//! Per Q4 Claim 1 of the Phase 5/5b.3 plan-gate disposition,
//! `IndexOutOfBounds` produced by the bounds checker on a
//! constant whose `type_` carries an out-of-range
//! `DatatypeHandleIndex` will win over the constants pass's
//! `InvalidConstantType` precedence under the C-4 invocation
//! order (`bounds_checker` at step-3 position 1; `constants` at
//! step-3 position 3 alphabetical-of-remainder). Two-direction
//! tests pin the claim at C-4. Third instance of the cross-pass
//! shared-variant pattern after `MalformedConstantData` and
//! `MalformedPrivacyMetadata`.
//!
//! # Dead-code allow sunset (section 6)
//!
//! The module-level `#![allow(dead_code)]` is removed at C-4
//! when [`super::super::verify_module`] wires this pass into the
//! step-3 batch. Until then the pass is callable from tests but
//! has no production caller.
//!
//! # References to PROVENANCE.md cross-pass audit anchors (section 7)
//!
//! - "What was forked" / Phase 5/5b.3 C-1.1 sub-section.
//! - "Adamant deviations" / Phase 5/5b.3 C-1.1 sub-section
//!   (typed-error fork; same shape as B-2.x sibling passes).
//! - "Byte-faithful preservation of upstream consensus-affecting
//!   decisions" / cardinality + ordering instances added at
//!   C-1.1 (sub-check sequence; bounds-then-arity pairing).
//! - "Eager-error first-failure-wins" / new internal-to-pass
//!   instance at C-1.1.
//!
//! [`AdamantCompiledModule`]: crate::module::AdamantCompiledModule
//! [`AdamantValidationError`]: crate::validator::error::AdamantValidationError
//! [`verify_impl`]: https://github.com/MystenLabs/sui/blob/mainnet-v1.66.2/external-crates/move/crates/move-binary-format/src/check_bounds.rs#L52

#![allow(
    dead_code,
    reason = "Pass not wired into verify_module until Phase 5/5b.3 C-4."
)]

use adamant_bytecode_format::{ModuleIndex, SignatureToken, TableIndex};

use crate::module::AdamantCompiledModule;

use super::super::error::AdamantValidationError;

/// Verify the deserialized module's index references against
/// §6.2.1.8 step 3 / position 1 (`module_pass::bounds_checker`).
///
/// C-1.1 batch covers the initial subset of upstream
/// `BoundsChecker::verify_impl`'s 17 sub-checks: an
/// empty-module-handles short-circuit followed by signatures,
/// constants, module-handles, self-module-handle, and datatype-
/// handles. Sub-checkpoints C-1.2 / C-1.3 / C-1.4 land the
/// remainder.
///
/// Eager-error semantics: returns the first violation encountered
/// in upstream sub-check order.
pub(in crate::validator) fn verify(
    module: &AdamantCompiledModule,
) -> Result<(), AdamantValidationError> {
    if module.module_handles.is_empty() {
        return Err(AdamantValidationError::NoModuleHandles);
    }
    check_signatures(module)?;
    check_constants(module)?;
    check_module_handles(module)?;
    check_self_module_handle(module)?;
    check_datatype_handles(module)?;
    Ok(())
}

/// For each entry in the signature pool, preorder-traverse every
/// signature token and bounds-check any `Datatype` /
/// `DatatypeInstantiation` references plus their type-argument
/// arity.
fn check_signatures(module: &AdamantCompiledModule) -> Result<(), AdamantValidationError> {
    for signature in &module.signatures {
        for ty in &signature.0 {
            check_type(module, ty)?;
        }
    }
    Ok(())
}

/// For each entry in the constant pool, bounds-check the
/// declared constant type via `check_type`.
fn check_constants(module: &AdamantCompiledModule) -> Result<(), AdamantValidationError> {
    for constant in &module.constant_pool {
        check_type(module, &constant.type_)?;
    }
    Ok(())
}

/// For each module-handle entry, validate that its `address`
/// resolves into the address-identifier pool and its `name`
/// resolves into the identifier pool.
fn check_module_handles(module: &AdamantCompiledModule) -> Result<(), AdamantValidationError> {
    for module_handle in &module.module_handles {
        check_index(module.address_identifiers.len(), module_handle.address)?;
        check_index(module.identifiers.len(), module_handle.name)?;
    }
    Ok(())
}

/// Validate that the module's `self_module_handle_idx` resolves
/// into the module-handle table.
fn check_self_module_handle(module: &AdamantCompiledModule) -> Result<(), AdamantValidationError> {
    check_index(module.module_handles.len(), module.self_module_handle_idx)
}

/// For each datatype-handle entry, validate that its `module`
/// resolves into the module-handle pool and its `name` resolves
/// into the identifier pool.
fn check_datatype_handles(module: &AdamantCompiledModule) -> Result<(), AdamantValidationError> {
    for datatype_handle in &module.datatype_handles {
        check_index(module.module_handles.len(), datatype_handle.module)?;
        check_index(module.identifiers.len(), datatype_handle.name)?;
    }
    Ok(())
}

/// Preorder-traverse a signature token tree and bounds-check
/// every `Datatype` / `DatatypeInstantiation` reference plus its
/// type-argument arity against the addressed `DatatypeHandle`.
///
/// For `Datatype(idx)`: if the handle declares any type
/// parameters, the bare form supplies zero — reject with
/// `NumberOfTypeArgumentsMismatch { expected: N, actual: 0 }`.
///
/// For `DatatypeInstantiation(idx, type_args)`: if
/// `type_args.len() != handle.type_parameters.len()`, reject
/// with `NumberOfTypeArgumentsMismatch { expected, actual }`.
///
/// Bounds check fires first; arity check is skipped on bounds
/// failure (mirrors upstream's `?` ordering).
fn check_type(
    module: &AdamantCompiledModule,
    ty: &SignatureToken,
) -> Result<(), AdamantValidationError> {
    for visited in ty.preorder_traversal() {
        match visited {
            SignatureToken::Bool
            | SignatureToken::U8
            | SignatureToken::U16
            | SignatureToken::U32
            | SignatureToken::U64
            | SignatureToken::U128
            | SignatureToken::U256
            | SignatureToken::Address
            | SignatureToken::Signer
            | SignatureToken::TypeParameter(_)
            | SignatureToken::Reference(_)
            | SignatureToken::MutableReference(_)
            | SignatureToken::Vector(_) => {}
            SignatureToken::Datatype(idx) => {
                check_index(module.datatype_handles.len(), *idx)?;
                let sh = &module.datatype_handles[idx.into_index()];
                if !sh.type_parameters.is_empty() {
                    return Err(AdamantValidationError::NumberOfTypeArgumentsMismatch {
                        datatype_handle_idx: *idx,
                        expected: sh.type_parameters.len(),
                        actual: 0,
                    });
                }
            }
            SignatureToken::DatatypeInstantiation(inst) => {
                let (idx, type_args) = &**inst;
                check_index(module.datatype_handles.len(), *idx)?;
                let sh = &module.datatype_handles[idx.into_index()];
                if sh.type_parameters.len() != type_args.len() {
                    return Err(AdamantValidationError::NumberOfTypeArgumentsMismatch {
                        datatype_handle_idx: *idx,
                        expected: sh.type_parameters.len(),
                        actual: type_args.len(),
                    });
                }
            }
        }
    }
    Ok(())
}

/// Generic `idx < pool_len` check returning a typed
/// [`AdamantValidationError::IndexOutOfBounds`] tagged with the
/// addressed pool's `IndexKind`.
///
/// Mirrors upstream's `check_bounds_impl<T, I: ModuleIndex>`. The
/// pool itself is not consulted — only its length — so callers
/// pass `pool.len()` directly to avoid a generic parameter for
/// the pool element type. `I::KIND` discriminates the pool in
/// the produced error.
fn check_index<I: ModuleIndex>(pool_len: usize, idx: I) -> Result<(), AdamantValidationError> {
    let i = idx.into_index();
    if i >= pool_len {
        Err(AdamantValidationError::IndexOutOfBounds {
            kind: I::KIND,
            idx: TableIndex::try_from(i).expect(
                "any index produced by ModuleIndex::into_index() fits TableIndex (u16); \
                 *Index newtypes wrap u16 underneath the binary format",
            ),
            pool_len,
        })
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use adamant_bytecode_format::{
        AbilitySet, AddressIdentifierIndex, Constant, DatatypeHandle, DatatypeHandleIndex,
        DatatypeTyParameter, Identifier, IdentifierIndex, IndexKind, ModuleHandle,
        ModuleHandleIndex, Signature, SignatureToken,
    };
    use adamant_types::Address as AccountAddress;

    use crate::module::AdamantCompiledModule;

    use super::super::super::error::AdamantValidationError;
    use super::super::test_helpers::assert_pass_parity;
    use super::verify;

    /// Build a fixture module shell with the self-handle
    /// referencing identifier 0 ("M") and address 0 ([0u8; 32]).
    /// Standard "module-self-identity" wiring used across the
    /// module-pass tests; matches `friends.rs::tests::empty_module`.
    fn empty_module() -> AdamantCompiledModule {
        AdamantCompiledModule {
            self_module_handle_idx: ModuleHandleIndex(0),
            module_handles: vec![ModuleHandle {
                address: AddressIdentifierIndex(0),
                name: IdentifierIndex(0),
            }],
            identifiers: vec![Identifier::new("M").unwrap()],
            address_identifiers: vec![AccountAddress::from_bytes([0u8; 32])],
            ..AdamantCompiledModule::default()
        }
    }

    /// Construct a `DatatypeTyParameter` with the given
    /// `is_phantom` and a no-constraint `AbilitySet::EMPTY`. The
    /// type-parameter ability set is irrelevant to the bounds
    /// checker — its only consumer is the `ability_field_requirements`
    /// pass at a later pipeline position.
    fn ty_param(is_phantom: bool) -> DatatypeTyParameter {
        DatatypeTyParameter {
            constraints: AbilitySet::EMPTY,
            is_phantom,
        }
    }

    // --- Layer A: positive cases ---

    #[test]
    fn empty_module_passes() {
        let m = empty_module();
        assert!(verify(&m).is_ok());
    }

    #[test]
    fn signature_pool_with_primitives_passes() {
        let mut m = empty_module();
        m.signatures.push(Signature(vec![
            SignatureToken::Bool,
            SignatureToken::U8,
            SignatureToken::U64,
            SignatureToken::U256,
            SignatureToken::Address,
            SignatureToken::Signer,
            SignatureToken::TypeParameter(0),
        ]));
        assert!(verify(&m).is_ok());
    }

    #[test]
    fn signature_pool_with_nested_vector_and_reference_passes() {
        let mut m = empty_module();
        // Vector<&u64>
        m.signatures
            .push(Signature(vec![SignatureToken::Vector(Box::new(
                SignatureToken::Reference(Box::new(SignatureToken::U64)),
            ))]));
        assert!(verify(&m).is_ok());
    }

    #[test]
    fn constant_pool_with_valid_types_passes() {
        let mut m = empty_module();
        m.constant_pool.push(Constant {
            type_: SignatureToken::U64,
            data: vec![0u8; 8],
        });
        m.constant_pool.push(Constant {
            type_: SignatureToken::Vector(Box::new(SignatureToken::U8)),
            data: vec![0],
        });
        assert!(verify(&m).is_ok());
    }

    #[test]
    fn datatype_handle_with_no_type_params_referenced_via_datatype_passes() {
        let mut m = empty_module();
        m.identifiers.push(Identifier::new("S").unwrap());
        m.datatype_handles.push(DatatypeHandle {
            module: ModuleHandleIndex(0),
            name: IdentifierIndex(1),
            abilities: AbilitySet::EMPTY,
            type_parameters: vec![],
        });
        m.signatures.push(Signature(vec![SignatureToken::Datatype(
            DatatypeHandleIndex(0),
        )]));
        assert!(verify(&m).is_ok());
    }

    #[test]
    fn datatype_handle_with_two_type_params_referenced_via_instantiation_passes() {
        let mut m = empty_module();
        m.identifiers.push(Identifier::new("S").unwrap());
        m.datatype_handles.push(DatatypeHandle {
            module: ModuleHandleIndex(0),
            name: IdentifierIndex(1),
            abilities: AbilitySet::EMPTY,
            type_parameters: vec![ty_param(false), ty_param(false)],
        });
        m.signatures
            .push(Signature(vec![SignatureToken::DatatypeInstantiation(
                Box::new((
                    DatatypeHandleIndex(0),
                    vec![SignatureToken::U64, SignatureToken::Bool],
                )),
            )]));
        assert!(verify(&m).is_ok());
    }

    // --- Layer A: negative cases ---

    #[test]
    fn rejects_empty_module_handles() {
        let m = AdamantCompiledModule::default();
        match verify(&m) {
            Err(AdamantValidationError::NoModuleHandles) => {}
            other => panic!("expected NoModuleHandles, got {other:?}"),
        }
    }

    #[test]
    fn rejects_signature_with_oob_datatype() {
        let mut m = empty_module();
        // datatype_handles is empty; reference index 5.
        m.signatures.push(Signature(vec![SignatureToken::Datatype(
            DatatypeHandleIndex(5),
        )]));
        match verify(&m) {
            Err(AdamantValidationError::IndexOutOfBounds {
                kind: IndexKind::DatatypeHandle,
                idx: 5,
                pool_len: 0,
            }) => {}
            other => panic!("expected IndexOutOfBounds(DatatypeHandle, 5, 0), got {other:?}"),
        }
    }

    #[test]
    fn rejects_constant_with_oob_datatype_in_type_field() {
        let mut m = empty_module();
        m.constant_pool.push(Constant {
            type_: SignatureToken::Datatype(DatatypeHandleIndex(7)),
            data: vec![],
        });
        match verify(&m) {
            Err(AdamantValidationError::IndexOutOfBounds {
                kind: IndexKind::DatatypeHandle,
                idx: 7,
                pool_len: 0,
            }) => {}
            other => panic!("expected IndexOutOfBounds(DatatypeHandle, 7, 0), got {other:?}"),
        }
    }

    #[test]
    fn rejects_module_handle_with_oob_address() {
        let mut m = empty_module();
        // Add a second module-handle pointing at out-of-range address index 9.
        m.module_handles.push(ModuleHandle {
            address: AddressIdentifierIndex(9),
            name: IdentifierIndex(0),
        });
        match verify(&m) {
            Err(AdamantValidationError::IndexOutOfBounds {
                kind: IndexKind::AddressIdentifier,
                idx: 9,
                pool_len: 1,
            }) => {}
            other => panic!("expected IndexOutOfBounds(AddressIdentifier, 9, 1), got {other:?}"),
        }
    }

    #[test]
    fn rejects_module_handle_with_oob_name() {
        let mut m = empty_module();
        m.module_handles.push(ModuleHandle {
            address: AddressIdentifierIndex(0),
            name: IdentifierIndex(11),
        });
        match verify(&m) {
            Err(AdamantValidationError::IndexOutOfBounds {
                kind: IndexKind::Identifier,
                idx: 11,
                pool_len: 1,
            }) => {}
            other => panic!("expected IndexOutOfBounds(Identifier, 11, 1), got {other:?}"),
        }
    }

    #[test]
    fn rejects_self_module_handle_oob() {
        let mut m = empty_module();
        m.self_module_handle_idx = ModuleHandleIndex(7);
        match verify(&m) {
            Err(AdamantValidationError::IndexOutOfBounds {
                kind: IndexKind::ModuleHandle,
                idx: 7,
                pool_len: 1,
            }) => {}
            other => panic!("expected IndexOutOfBounds(ModuleHandle, 7, 1), got {other:?}"),
        }
    }

    #[test]
    fn rejects_datatype_handle_with_oob_module() {
        let mut m = empty_module();
        m.identifiers.push(Identifier::new("S").unwrap());
        m.datatype_handles.push(DatatypeHandle {
            module: ModuleHandleIndex(4),
            name: IdentifierIndex(1),
            abilities: AbilitySet::EMPTY,
            type_parameters: vec![],
        });
        match verify(&m) {
            Err(AdamantValidationError::IndexOutOfBounds {
                kind: IndexKind::ModuleHandle,
                idx: 4,
                pool_len: 1,
            }) => {}
            other => panic!("expected IndexOutOfBounds(ModuleHandle, 4, 1), got {other:?}"),
        }
    }

    #[test]
    fn rejects_datatype_handle_with_oob_name() {
        let mut m = empty_module();
        m.datatype_handles.push(DatatypeHandle {
            module: ModuleHandleIndex(0),
            name: IdentifierIndex(8),
            abilities: AbilitySet::EMPTY,
            type_parameters: vec![],
        });
        match verify(&m) {
            Err(AdamantValidationError::IndexOutOfBounds {
                kind: IndexKind::Identifier,
                idx: 8,
                pool_len: 1,
            }) => {}
            other => panic!("expected IndexOutOfBounds(Identifier, 8, 1), got {other:?}"),
        }
    }

    #[test]
    fn rejects_datatype_with_zero_args_when_handle_expects_two() {
        let mut m = empty_module();
        m.identifiers.push(Identifier::new("S").unwrap());
        m.datatype_handles.push(DatatypeHandle {
            module: ModuleHandleIndex(0),
            name: IdentifierIndex(1),
            abilities: AbilitySet::EMPTY,
            type_parameters: vec![ty_param(false), ty_param(false)],
        });
        m.signatures.push(Signature(vec![SignatureToken::Datatype(
            DatatypeHandleIndex(0),
        )]));
        match verify(&m) {
            Err(AdamantValidationError::NumberOfTypeArgumentsMismatch {
                datatype_handle_idx: DatatypeHandleIndex(0),
                expected: 2,
                actual: 0,
            }) => {}
            other => panic!(
                "expected NumberOfTypeArgumentsMismatch(0, expected 2, actual 0), \
                 got {other:?}"
            ),
        }
    }

    #[test]
    fn rejects_datatype_instantiation_with_arity_mismatch() {
        let mut m = empty_module();
        m.identifiers.push(Identifier::new("S").unwrap());
        m.datatype_handles.push(DatatypeHandle {
            module: ModuleHandleIndex(0),
            name: IdentifierIndex(1),
            abilities: AbilitySet::EMPTY,
            type_parameters: vec![ty_param(false), ty_param(false)],
        });
        // Supplied 1 type arg vs handle's declared 2.
        m.signatures
            .push(Signature(vec![SignatureToken::DatatypeInstantiation(
                Box::new((DatatypeHandleIndex(0), vec![SignatureToken::U64])),
            )]));
        match verify(&m) {
            Err(AdamantValidationError::NumberOfTypeArgumentsMismatch {
                datatype_handle_idx: DatatypeHandleIndex(0),
                expected: 2,
                actual: 1,
            }) => {}
            other => panic!("expected NumberOfTypeArgumentsMismatch(0, 2, 1), got {other:?}"),
        }
    }

    #[test]
    fn datatype_instantiation_bounds_check_fires_before_arity_check() {
        // Reference index 5 (out of bounds; datatype_handles is
        // empty); supplied 2 type args. Bounds check is upstream
        // of the arity check; the OOB error fires first per the
        // bounds-then-arity pairing preserved at C-1.1.
        let mut m = empty_module();
        m.signatures
            .push(Signature(vec![SignatureToken::DatatypeInstantiation(
                Box::new((
                    DatatypeHandleIndex(5),
                    vec![SignatureToken::U64, SignatureToken::Bool],
                )),
            )]));
        match verify(&m) {
            Err(AdamantValidationError::IndexOutOfBounds {
                kind: IndexKind::DatatypeHandle,
                idx: 5,
                pool_len: 0,
            }) => {}
            other => panic!("expected IndexOutOfBounds (bounds wins over arity), got {other:?}"),
        }
    }

    #[test]
    fn rejects_signature_with_nested_oob_datatype_via_preorder() {
        // Vector<Datatype(99)> — the OOB lives inside the vector
        // element type. Preorder traversal visits the inner
        // Datatype node and surfaces the OOB.
        let mut m = empty_module();
        m.signatures
            .push(Signature(vec![SignatureToken::Vector(Box::new(
                SignatureToken::Datatype(DatatypeHandleIndex(99)),
            ))]));
        match verify(&m) {
            Err(AdamantValidationError::IndexOutOfBounds {
                kind: IndexKind::DatatypeHandle,
                idx: 99,
                pool_len: 0,
            }) => {}
            other => panic!("expected nested-OOB report via preorder, got {other:?}"),
        }
    }

    #[test]
    fn signatures_check_fires_before_constants_eager_error() {
        // Both pools carry an OOB Datatype reference. Sub-check
        // ordering puts signatures first; the signature OOB at
        // index 1 wins over the constant OOB at index 7.
        let mut m = empty_module();
        m.signatures.push(Signature(vec![SignatureToken::Datatype(
            DatatypeHandleIndex(1),
        )]));
        m.constant_pool.push(Constant {
            type_: SignatureToken::Datatype(DatatypeHandleIndex(7)),
            data: vec![],
        });
        match verify(&m) {
            Err(AdamantValidationError::IndexOutOfBounds {
                kind: IndexKind::DatatypeHandle,
                idx: 1,
                pool_len: 0,
            }) => {}
            other => panic!("expected signatures-pass OOB(1) to win, got {other:?}"),
        }
    }

    // --- Layer B: cross-validation against vendored Sui ---
    //
    // For each fixture below, run Adamant's `verify` and Sui's
    // `move_binary_format::check_bounds::BoundsChecker::verify_module`
    // over the same module (after BCS round-trip via
    // to_sui_module), assert accept/reject parity via the shared
    // `assert_pass_parity` helper extracted at B-2.2.
    //
    // Sui's `verify_module` takes a `deprecate_global_storage_ops`
    // flag; pass `true` to mirror Adamant's pipeline posture per
    // `validator/config.rs` (the flag is locked-down true in
    // production).

    fn cross_validate_bounds_pass(m: &AdamantCompiledModule) {
        let adamant_result = verify(m);
        let sui_module = m
            .to_sui_module()
            .expect("test fixture has no Adamant extensions; to_sui_module must succeed");
        // `BoundsChecker::verify_module` returns `PartialVMResult`
        // (unlike sibling passes whose `verify_module` wrappers
        // call `.finish(Location::Module(self.self_id()))`
        // internally). Wrapping with `Location::Undefined` here
        // because some negative fixtures (empty `module_handles`,
        // out-of-range `self_module_handle_idx`) make `self_id()`
        // panic — those are the inputs the bounds checker is
        // supposed to reject. `Location::Undefined` is a
        // constant that doesn't consult module state; accept/
        // reject parity is unchanged by the choice of location.
        let sui_result =
            move_binary_format::check_bounds::BoundsChecker::verify_module(&sui_module, true)
                .map_err(|e| e.finish(move_binary_format::errors::Location::Undefined));
        assert_pass_parity("bounds_checker", adamant_result, sui_result);
    }

    #[test]
    fn cross_validation_accepts_empty_module() {
        let m = empty_module();
        cross_validate_bounds_pass(&m);
    }

    #[test]
    fn cross_validation_accepts_module_with_signatures_and_constants() {
        let mut m = empty_module();
        m.signatures.push(Signature(vec![
            SignatureToken::U64,
            SignatureToken::Vector(Box::new(SignatureToken::Bool)),
        ]));
        m.constant_pool.push(Constant {
            type_: SignatureToken::U64,
            data: vec![0u8; 8],
        });
        cross_validate_bounds_pass(&m);
    }

    #[test]
    fn cross_validation_accepts_module_with_datatype_handle() {
        let mut m = empty_module();
        m.identifiers.push(Identifier::new("S").unwrap());
        m.datatype_handles.push(DatatypeHandle {
            module: ModuleHandleIndex(0),
            name: IdentifierIndex(1),
            abilities: AbilitySet::EMPTY,
            type_parameters: vec![],
        });
        m.signatures.push(Signature(vec![SignatureToken::Datatype(
            DatatypeHandleIndex(0),
        )]));
        cross_validate_bounds_pass(&m);
    }

    #[test]
    fn cross_validation_rejects_signature_oob_datatype() {
        let mut m = empty_module();
        m.signatures.push(Signature(vec![SignatureToken::Datatype(
            DatatypeHandleIndex(5),
        )]));
        cross_validate_bounds_pass(&m);
    }

    #[test]
    fn cross_validation_rejects_module_handle_oob_address() {
        let mut m = empty_module();
        m.module_handles.push(ModuleHandle {
            address: AddressIdentifierIndex(9),
            name: IdentifierIndex(0),
        });
        cross_validate_bounds_pass(&m);
    }

    #[test]
    fn cross_validation_rejects_self_module_handle_oob() {
        let mut m = empty_module();
        m.self_module_handle_idx = ModuleHandleIndex(7);
        cross_validate_bounds_pass(&m);
    }

    #[test]
    fn cross_validation_rejects_datatype_handle_oob_module() {
        let mut m = empty_module();
        m.identifiers.push(Identifier::new("S").unwrap());
        m.datatype_handles.push(DatatypeHandle {
            module: ModuleHandleIndex(4),
            name: IdentifierIndex(1),
            abilities: AbilitySet::EMPTY,
            type_parameters: vec![],
        });
        cross_validate_bounds_pass(&m);
    }

    #[test]
    fn cross_validation_rejects_zero_args_when_two_expected() {
        let mut m = empty_module();
        m.identifiers.push(Identifier::new("S").unwrap());
        m.datatype_handles.push(DatatypeHandle {
            module: ModuleHandleIndex(0),
            name: IdentifierIndex(1),
            abilities: AbilitySet::EMPTY,
            type_parameters: vec![ty_param(false), ty_param(false)],
        });
        m.signatures.push(Signature(vec![SignatureToken::Datatype(
            DatatypeHandleIndex(0),
        )]));
        cross_validate_bounds_pass(&m);
    }

    #[test]
    fn cross_validation_rejects_arity_mismatch_one_vs_two() {
        let mut m = empty_module();
        m.identifiers.push(Identifier::new("S").unwrap());
        m.datatype_handles.push(DatatypeHandle {
            module: ModuleHandleIndex(0),
            name: IdentifierIndex(1),
            abilities: AbilitySet::EMPTY,
            type_parameters: vec![ty_param(false), ty_param(false)],
        });
        m.signatures
            .push(Signature(vec![SignatureToken::DatatypeInstantiation(
                Box::new((DatatypeHandleIndex(0), vec![SignatureToken::U64])),
            )]));
        cross_validate_bounds_pass(&m);
    }

    #[test]
    fn cross_validation_rejects_no_module_handles() {
        let m = AdamantCompiledModule::default();
        cross_validate_bounds_pass(&m);
    }
}
