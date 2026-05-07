//! Module-level pass: constant-pool validation
//! (whitepaper §6.2.1.8 step 3).
//!
//! Forked from `vendor/move-bytecode-verifier/src/constants.rs`
//! at Sui-Move tag `mainnet-v1.66.2` (commit
//! `a9a6825eaf6273cc819ee3bcf65fd4909f7624a9`). See
//! `validator/module_pass/PROVENANCE.md` for the deviation
//! list. Summary:
//!
//! - Operates on [`AdamantCompiledModule`] rather than Sui's
//!   `CompiledModule`. The constant pool itself is byte-
//!   identical between the two per Phase 5/5b.1b's
//!   bytecode-format fork.
//! - Returns typed [`AdamantValidationError`] variants
//!   (`InvalidConstantType`, `MalformedConstantData`) rather
//!   than upstream's `PartialVMError`/`StatusCode`.
//! - Type-directed BCS validator is Adamant-native, walking
//!   the [`SignatureToken`] tree directly. Upstream defers
//!   the data-validity check to `Constant::deserialize_constant`
//!   which uses `MoveValue::simple_deserialize` from
//!   `move_core_types::runtime_value` — Adamant has no
//!   production dep on `move_core_types::runtime_value` per
//!   the resistant-proof posture, so the type-directed walker
//!   replaces that path. Acceptance set is identical: same
//!   bytes accepted/rejected for the same `(SignatureToken,
//!   bytes)` pair.
//!
//! Per constant in the module's constant pool:
//!
//! 1. **Type validity.** [`SignatureToken::is_valid_for_constant`]
//!    must return `true` (rejects `Datatype`,
//!    `DatatypeInstantiation`, references, `Signer`, and
//!    `TypeParameter`).
//! 2. **Data validity.** The byte payload must be a well-formed
//!    BCS encoding of a value of the declared type — exact
//!    byte count, valid `Bool` encoding (`0x00` or `0x01`
//!    only), well-formed ULEB128 length prefixes for `Vector`
//!    payloads, and no trailing bytes.

use std::io::Cursor;

use adamant_bytecode_format::{
    read_u8, read_uleb128_as_u64, Constant, ConstantPoolIndex, ReaderError, SignatureToken,
    TableIndex,
};

use crate::module::AdamantCompiledModule;

use super::super::error::{AdamantValidationError, MalformedConstantReason};

/// Verify the module's constant pool against §6.2.1.8 step 3
/// (`module_pass::constants`).
///
/// Eager-error semantics: returns the first violation
/// encountered, scanning constants in pool order.
pub(in crate::validator) fn verify(
    module: &AdamantCompiledModule,
) -> Result<(), AdamantValidationError> {
    for (idx, constant) in module.constant_pool.iter().enumerate() {
        let constant_pool_idx = ConstantPoolIndex(TableIndex::try_from(idx).expect(
            "constant pool count exceeds u16; binary format precludes this \
                 (TABLE_INDEX_MAX = u16::MAX)",
        ));
        verify_constant(constant_pool_idx, constant)?;
    }
    Ok(())
}

fn verify_constant(
    idx: ConstantPoolIndex,
    constant: &Constant,
) -> Result<(), AdamantValidationError> {
    if !constant.type_.is_valid_for_constant() {
        return Err(AdamantValidationError::InvalidConstantType { idx });
    }
    if let Err(reason) = validate_constant_data(&constant.data, &constant.type_) {
        return Err(AdamantValidationError::MalformedConstantData { idx, reason });
    }
    Ok(())
}

/// Validate that `data` is a well-formed BCS encoding of a
/// value of type `ty`.
///
/// Caller-side precondition: `ty.is_valid_for_constant()`
/// returned `true`. Reaching a non-constant-valid token here
/// is a programming error in this module (not a user-input
/// failure) and panics via `unreachable!`.
fn validate_constant_data(data: &[u8], ty: &SignatureToken) -> Result<(), MalformedConstantReason> {
    let mut cursor = Cursor::new(data);
    walk(&mut cursor, ty)?;
    let position = usize::try_from(cursor.position())
        .expect("cursor position cannot exceed slice length, which is bounded by usize::MAX");
    if position != data.len() {
        return Err(MalformedConstantReason::TrailingBytes {
            remaining: data.len() - position,
        });
    }
    Ok(())
}

/// Recursively walk `ty`, consuming bytes from `cursor`.
fn walk(cursor: &mut Cursor<&[u8]>, ty: &SignatureToken) -> Result<(), MalformedConstantReason> {
    match ty {
        SignatureToken::Bool => {
            let b = read_u8(cursor).map_err(reader_to_reason)?;
            if b > 1 {
                return Err(MalformedConstantReason::InvalidBool { byte: b });
            }
        }
        SignatureToken::U8 => consume_n(cursor, 1)?,
        SignatureToken::U16 => consume_n(cursor, 2)?,
        SignatureToken::U32 => consume_n(cursor, 4)?,
        SignatureToken::U64 => consume_n(cursor, 8)?,
        SignatureToken::U128 => consume_n(cursor, 16)?,
        // U256 and Address both consume 32 bytes (BCS LE for
        // U256 per §6.2.1.5; raw 32 bytes for Address per the
        // `adamant_types::Address` reuse).
        SignatureToken::U256 | SignatureToken::Address => consume_n(cursor, 32)?,
        SignatureToken::Vector(inner) => {
            let len = read_uleb128_as_u64(cursor).map_err(reader_to_reason)?;
            for _ in 0..len {
                walk(cursor, inner)?;
            }
        }
        // `is_valid_for_constant()` rejected these in
        // `verify_constant` above; reaching them here is an
        // internal invariant violation, not a user error.
        SignatureToken::Signer
        | SignatureToken::Datatype(_)
        | SignatureToken::DatatypeInstantiation(_)
        | SignatureToken::Reference(_)
        | SignatureToken::MutableReference(_)
        | SignatureToken::TypeParameter(_) => {
            unreachable!(
                "type rejected by is_valid_for_constant before reaching walk(); \
                 saw: {ty:?}"
            )
        }
    }
    Ok(())
}

/// Consume `n` bytes from the cursor, returning
/// [`MalformedConstantReason::UnexpectedEof`] if the cursor
/// runs out before `n` bytes are consumed.
fn consume_n(cursor: &mut Cursor<&[u8]>, n: usize) -> Result<(), MalformedConstantReason> {
    let inner = cursor.get_ref();
    let pos =
        usize::try_from(cursor.position()).expect("cursor position cannot exceed slice length");
    if pos.saturating_add(n) > inner.len() {
        return Err(MalformedConstantReason::UnexpectedEof);
    }
    cursor.set_position(u64::try_from(pos + n).expect(
        "cursor position is bounded by slice length, which fits in u64 on supported platforms",
    ));
    Ok(())
}

/// Map `adamant_bytecode_format::ReaderError` into the
/// [`MalformedConstantReason`] surface.
fn reader_to_reason(e: ReaderError) -> MalformedConstantReason {
    match e {
        ReaderError::UnexpectedEof => MalformedConstantReason::UnexpectedEof,
        ReaderError::MalformedUleb128 => MalformedConstantReason::InvalidUleb128,
    }
}

#[cfg(test)]
mod tests {
    use adamant_bytecode_format::{
        AbilitySet, AddressIdentifierIndex, Constant, ConstantPoolIndex, DatatypeHandle,
        DatatypeHandleIndex, Identifier, IdentifierIndex, ModuleHandle, ModuleHandleIndex,
        SignatureToken,
    };
    use adamant_types::Address as AccountAddress;

    use crate::module::AdamantCompiledModule;

    use super::super::super::error::{AdamantValidationError, MalformedConstantReason};
    use super::{validate_constant_data, verify};

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

    // --- Layer A: type-directed walker positive cases ---

    #[test]
    fn validates_u8_one_byte() {
        assert!(validate_constant_data(&[0x42], &SignatureToken::U8).is_ok());
    }

    #[test]
    fn validates_u64_eight_bytes() {
        assert!(validate_constant_data(&[0; 8], &SignatureToken::U64).is_ok());
    }

    #[test]
    fn validates_u256_thirty_two_bytes() {
        assert!(validate_constant_data(&[0; 32], &SignatureToken::U256).is_ok());
    }

    #[test]
    fn validates_address_thirty_two_bytes() {
        assert!(validate_constant_data(&[0; 32], &SignatureToken::Address).is_ok());
    }

    #[test]
    fn validates_bool_true_and_false() {
        assert!(validate_constant_data(&[0x00], &SignatureToken::Bool).is_ok());
        assert!(validate_constant_data(&[0x01], &SignatureToken::Bool).is_ok());
    }

    #[test]
    fn validates_empty_vector() {
        // ULEB128 length 0, no elements.
        assert!(validate_constant_data(
            &[0x00],
            &SignatureToken::Vector(Box::new(SignatureToken::U8))
        )
        .is_ok());
    }

    #[test]
    fn validates_three_byte_vector() {
        // ULEB128 length 3, three u8 bytes.
        assert!(validate_constant_data(
            &[0x03, 0xAA, 0xBB, 0xCC],
            &SignatureToken::Vector(Box::new(SignatureToken::U8))
        )
        .is_ok());
    }

    #[test]
    fn validates_nested_vector() {
        // outer length 2, inner u8-vectors of length 1 and 0.
        assert!(validate_constant_data(
            &[0x02, 0x01, 0xAB, 0x00],
            &SignatureToken::Vector(Box::new(SignatureToken::Vector(Box::new(
                SignatureToken::U8
            ))))
        )
        .is_ok());
    }

    // --- Layer A: type-directed walker negative cases ---

    #[test]
    fn rejects_u8_with_zero_bytes() {
        match validate_constant_data(&[], &SignatureToken::U8) {
            Err(MalformedConstantReason::UnexpectedEof) => {}
            other => panic!("expected UnexpectedEof, got {other:?}"),
        }
    }

    #[test]
    fn rejects_u64_with_seven_bytes() {
        match validate_constant_data(&[0; 7], &SignatureToken::U64) {
            Err(MalformedConstantReason::UnexpectedEof) => {}
            other => panic!("expected UnexpectedEof, got {other:?}"),
        }
    }

    #[test]
    fn rejects_bool_byte_two() {
        match validate_constant_data(&[0x02], &SignatureToken::Bool) {
            Err(MalformedConstantReason::InvalidBool { byte: 0x02 }) => {}
            other => panic!("expected InvalidBool {{ byte: 0x02 }}, got {other:?}"),
        }
    }

    #[test]
    fn rejects_bool_byte_ff() {
        match validate_constant_data(&[0xFF], &SignatureToken::Bool) {
            Err(MalformedConstantReason::InvalidBool { byte: 0xFF }) => {}
            other => panic!("expected InvalidBool {{ byte: 0xFF }}, got {other:?}"),
        }
    }

    #[test]
    fn rejects_trailing_bytes_after_u8() {
        match validate_constant_data(&[0x42, 0x00], &SignatureToken::U8) {
            Err(MalformedConstantReason::TrailingBytes { remaining: 1 }) => {}
            other => panic!("expected TrailingBytes {{ remaining: 1 }}, got {other:?}"),
        }
    }

    #[test]
    fn rejects_vector_with_truncated_payload() {
        // ULEB128 length 3 declared, only 2 bytes of payload.
        match validate_constant_data(
            &[0x03, 0xAA, 0xBB],
            &SignatureToken::Vector(Box::new(SignatureToken::U8)),
        ) {
            Err(MalformedConstantReason::UnexpectedEof) => {}
            other => panic!("expected UnexpectedEof, got {other:?}"),
        }
    }

    #[test]
    fn rejects_vector_with_malformed_uleb128_length() {
        // Continuation bit set with no terminator: 0x80 0x80 0x80 0x80 0x80 0x80 0x80 0x80 0x80 0x80
        // (10 bytes; ULEB128 max for u64 is 10 bytes total but
        // the last must have continuation cleared). Adamant's
        // `read_uleb128_as_u64` rejects this as MalformedUleb128.
        // Either reason is acceptable — depends on whether the
        // ULEB128 reader recognises the malformed pattern before
        // running out of bytes or after. The test asserts only
        // that the input is rejected.
        match validate_constant_data(
            &[0x80; 10],
            &SignatureToken::Vector(Box::new(SignatureToken::U8)),
        ) {
            Err(
                MalformedConstantReason::InvalidUleb128 | MalformedConstantReason::UnexpectedEof,
            ) => {}
            other => panic!("expected InvalidUleb128 or UnexpectedEof, got {other:?}"),
        }
    }

    // --- Layer A: pass-level tests over AdamantCompiledModule ---

    #[test]
    fn empty_constant_pool_passes() {
        let m = empty_module();
        assert!(verify(&m).is_ok());
    }

    #[test]
    fn valid_u64_constant_passes() {
        let mut m = empty_module();
        m.constant_pool.push(Constant {
            type_: SignatureToken::U64,
            data: vec![0; 8],
        });
        assert!(verify(&m).is_ok());
    }

    #[test]
    fn rejects_constant_with_signer_type() {
        let mut m = empty_module();
        m.constant_pool.push(Constant {
            type_: SignatureToken::Signer,
            data: vec![],
        });
        match verify(&m) {
            Err(AdamantValidationError::InvalidConstantType { idx }) => {
                assert_eq!(idx, ConstantPoolIndex(0));
            }
            other => panic!("expected InvalidConstantType {{ idx: 0 }}, got {other:?}"),
        }
    }

    #[test]
    fn rejects_constant_with_datatype_type() {
        let mut m = empty_module();
        m.identifiers.push(Identifier::new("S").unwrap());
        m.datatype_handles.push(DatatypeHandle {
            module: ModuleHandleIndex(0),
            name: IdentifierIndex(1),
            abilities: AbilitySet::EMPTY,
            type_parameters: vec![],
        });
        m.constant_pool.push(Constant {
            type_: SignatureToken::Datatype(DatatypeHandleIndex(0)),
            data: vec![],
        });
        match verify(&m) {
            Err(AdamantValidationError::InvalidConstantType { idx }) => {
                assert_eq!(idx, ConstantPoolIndex(0));
            }
            other => panic!("expected InvalidConstantType {{ idx: 0 }}, got {other:?}"),
        }
    }

    #[test]
    fn rejects_constant_with_reference_type() {
        let mut m = empty_module();
        m.constant_pool.push(Constant {
            type_: SignatureToken::Reference(Box::new(SignatureToken::U64)),
            data: vec![0; 8],
        });
        match verify(&m) {
            Err(AdamantValidationError::InvalidConstantType { idx }) => {
                assert_eq!(idx, ConstantPoolIndex(0));
            }
            other => panic!("expected InvalidConstantType {{ idx: 0 }}, got {other:?}"),
        }
    }

    #[test]
    fn rejects_constant_with_truncated_u64_data() {
        let mut m = empty_module();
        m.constant_pool.push(Constant {
            type_: SignatureToken::U64,
            data: vec![0; 7],
        });
        match verify(&m) {
            Err(AdamantValidationError::MalformedConstantData {
                idx,
                reason: MalformedConstantReason::UnexpectedEof,
            }) => {
                assert_eq!(idx, ConstantPoolIndex(0));
            }
            other => panic!("expected MalformedConstantData/UnexpectedEof, got {other:?}"),
        }
    }

    #[test]
    fn rejects_constant_with_invalid_bool_byte() {
        let mut m = empty_module();
        m.constant_pool.push(Constant {
            type_: SignatureToken::Bool,
            data: vec![0x07],
        });
        match verify(&m) {
            Err(AdamantValidationError::MalformedConstantData {
                idx,
                reason: MalformedConstantReason::InvalidBool { byte: 0x07 },
            }) => {
                assert_eq!(idx, ConstantPoolIndex(0));
            }
            other => panic!("expected MalformedConstantData/InvalidBool, got {other:?}"),
        }
    }

    #[test]
    fn first_invalid_constant_wins_eager_error_semantics() {
        // First entry: valid; second entry: invalid type. The
        // pass should report the second entry's error and not
        // continue to subsequent entries.
        let mut m = empty_module();
        m.constant_pool.push(Constant {
            type_: SignatureToken::U64,
            data: vec![0; 8],
        });
        m.constant_pool.push(Constant {
            type_: SignatureToken::Signer,
            data: vec![],
        });
        m.constant_pool.push(Constant {
            type_: SignatureToken::Bool,
            data: vec![0xFF], // also malformed; should not be reached
        });
        match verify(&m) {
            Err(AdamantValidationError::InvalidConstantType { idx }) => {
                assert_eq!(idx, ConstantPoolIndex(1));
            }
            other => panic!("expected InvalidConstantType {{ idx: 1 }}, got {other:?}"),
        }
    }

    // --- Layer B: cross-validation against vendored Sui ---
    //
    // For each fixture below, construct an Adamant module,
    // run Adamant's pass, BCS-round-trip the module to Sui's
    // `CompiledModule` via [`AdamantCompiledModule::to_sui_module`],
    // run Sui's same pass against it, and assert accept/reject
    // parity. Adamant's typed-error variant and Sui's
    // `StatusCode` shape do not match by design (the resistant-
    // proof posture takes Adamant off Sui's error machinery);
    // the parity check is on accept-vs-reject only.
    //
    // Coverage target (per the B-2.1 design redirect):
    //   - One accept-parity test per primitive type valid for
    //     constants: U8, U16, U32, U64, U128, U256, Address,
    //     Bool, Vector. (9 tests)
    //   - One reject-parity test per failure mode in
    //     validate_constant_data: truncation, trailing bytes,
    //     invalid bool byte, malformed ULEB128. (4 tests)
    //   - One reject-parity test per invalid-for-constant
    //     SignatureToken: Signer, Datatype, Reference.
    //     (3 tests)
    //
    // Total: 16 Layer B tests covering each divergence point
    // between Adamant's type-directed walker and Sui's
    // MoveValue::simple_deserialize path.

    /// Pass-level cross-validation: run Adamant's `verify` and
    /// Sui's `move_bytecode_verifier::constants::verify_module`
    /// over the same module (after BCS round-trip), assert
    /// accept/reject parity via the shared
    /// [`assert_pass_parity`] helper extracted at B-2.2.
    fn cross_validate_constants_pass(m: &AdamantCompiledModule) {
        let adamant_result = verify(m);
        let sui_module = m
            .to_sui_module()
            .expect("test fixture has no Adamant extensions; to_sui_module must succeed");
        let sui_result = move_bytecode_verifier::constants::verify_module(&sui_module);
        super::super::test_helpers::assert_pass_parity("constants", adamant_result, sui_result);
    }

    /// Convenience helper for the common case: insert a single
    /// `constant` into an empty module's constant pool, then
    /// run `cross_validate_constants_pass`.
    fn cross_validate_constant(constant: Constant) {
        let mut m = empty_module();
        m.constant_pool.push(constant);
        cross_validate_constants_pass(&m);
    }

    // --- Layer B: accept-parity per primitive type ---

    #[test]
    fn cross_validation_accepts_valid_u8_constant() {
        cross_validate_constant(Constant {
            type_: SignatureToken::U8,
            data: vec![0x42],
        });
    }

    #[test]
    fn cross_validation_accepts_valid_u16_constant() {
        cross_validate_constant(Constant {
            type_: SignatureToken::U16,
            data: vec![0xAA, 0xBB],
        });
    }

    #[test]
    fn cross_validation_accepts_valid_u32_constant() {
        cross_validate_constant(Constant {
            type_: SignatureToken::U32,
            data: vec![0; 4],
        });
    }

    #[test]
    fn cross_validation_accepts_valid_u64_constant() {
        cross_validate_constant(Constant {
            type_: SignatureToken::U64,
            data: vec![0; 8],
        });
    }

    #[test]
    fn cross_validation_accepts_valid_u128_constant() {
        cross_validate_constant(Constant {
            type_: SignatureToken::U128,
            data: vec![0; 16],
        });
    }

    #[test]
    fn cross_validation_accepts_valid_u256_constant() {
        cross_validate_constant(Constant {
            type_: SignatureToken::U256,
            data: vec![0; 32],
        });
    }

    #[test]
    fn cross_validation_accepts_valid_address_constant() {
        cross_validate_constant(Constant {
            type_: SignatureToken::Address,
            data: vec![0xAB; 32],
        });
    }

    #[test]
    fn cross_validation_accepts_valid_bool_constant() {
        cross_validate_constant(Constant {
            type_: SignatureToken::Bool,
            data: vec![0x01],
        });
    }

    #[test]
    fn cross_validation_accepts_valid_vec_u8_constant() {
        cross_validate_constant(Constant {
            type_: SignatureToken::Vector(Box::new(SignatureToken::U8)),
            data: vec![0x03, 0x10, 0x20, 0x30],
        });
    }

    // --- Layer B: reject-parity per malformed-data failure mode ---

    #[test]
    fn cross_validation_rejects_truncated_u64_data() {
        cross_validate_constant(Constant {
            type_: SignatureToken::U64,
            data: vec![0; 7],
        });
    }

    #[test]
    fn cross_validation_rejects_trailing_bytes() {
        cross_validate_constant(Constant {
            type_: SignatureToken::U8,
            data: vec![0x42, 0x00],
        });
    }

    #[test]
    fn cross_validation_rejects_invalid_bool_byte() {
        cross_validate_constant(Constant {
            type_: SignatureToken::Bool,
            data: vec![0x07],
        });
    }

    #[test]
    fn cross_validation_rejects_malformed_uleb128_in_vector() {
        // ULEB128 with continuation bits set on every byte and
        // no terminator — Adamant's walker rejects via the
        // `read_uleb128_as_u64` reader; Sui's walker rejects
        // through its own deserializer's BCS path.
        cross_validate_constant(Constant {
            type_: SignatureToken::Vector(Box::new(SignatureToken::U8)),
            data: vec![0x80; 10],
        });
    }

    // --- Layer B: reject-parity per invalid-for-constant SignatureToken ---

    #[test]
    fn cross_validation_rejects_signer_type() {
        cross_validate_constant(Constant {
            type_: SignatureToken::Signer,
            data: vec![],
        });
    }

    #[test]
    fn cross_validation_rejects_reference_type() {
        cross_validate_constant(Constant {
            type_: SignatureToken::Reference(Box::new(SignatureToken::U64)),
            data: vec![0; 8],
        });
    }

    #[test]
    fn cross_validation_rejects_datatype_type() {
        // Datatype constants need a backing DatatypeHandle in
        // the module so `to_sui_module`'s BCS round-trip
        // produces a Sui-shape-valid CompiledModule. The
        // test inlines the module-construction rather than
        // pushing through `cross_validate_constant`.
        let mut m = empty_module();
        m.identifiers.push(Identifier::new("S").unwrap());
        m.datatype_handles.push(DatatypeHandle {
            module: ModuleHandleIndex(0),
            name: IdentifierIndex(1),
            abilities: AbilitySet::EMPTY,
            type_parameters: vec![],
        });
        m.constant_pool.push(Constant {
            type_: SignatureToken::Datatype(DatatypeHandleIndex(0)),
            data: vec![],
        });
        cross_validate_constants_pass(&m);
    }
}
