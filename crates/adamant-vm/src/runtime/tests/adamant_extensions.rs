//! Adamant-extension handler tests — Phase 5/6.3 scope:
//! 7 handlers (2 frame-creation + 2 hash + 3 signature).
//!
//! Verbatim-spec-quote-grounds-runtime-fixture discipline 5th
//! instance (operating beyond rule-of-three threshold; primary
//! anchor for Adamant-native instructions per the discipline-shift-
//! from-Sui-ecosystem-grounding-to-Adamant-spec-grounding sub-pattern
//! 1st canonical instance at Phase 5/6.3 plan-gate).
//!
//! Spec sources for fixtures:
//! - `Sha3_256` / `Blake3` — whitepaper §3.3.1, §3.3.2
//! - `Ed25519Verify` — whitepaper §3.4.1
//! - `MlDsaVerify65` — whitepaper §3.4.2
//! - `BlsVerify` — whitepaper §3.4.3
//! - `InvokeShielded` / `InvokeTransparent` — whitepaper §6.1.2 +
//!   §6.2.1.6 Rule 7

use core::cell::Cell;

use adamant_bytecode_format::{
    AbilitySet, DatatypeHandle, DatatypeHandleIndex, FunctionHandle, FunctionHandleIndex,
    Identifier, IdentifierIndex, ModuleHandle, ModuleHandleIndex, Signature, SignatureIndex,
    Visibility,
};

use super::*;
use crate::bytecode::{AdamantBytecode, BytecodeInstruction};
use crate::module::{AdamantCodeUnit, AdamantFunctionDefinition};
use crate::runtime::interpreter::{dispatch_instruction, run};
use crate::runtime::InvariantViolationReason;
use crate::runtime::PrivacyMode;

// =====================================================================
// Shared helpers (5/6.3-specific)
// =====================================================================

/// Construct a runtime `vector<u8>` from raw bytes for tests that
/// pass byte arrays through the operand stack to crypto handlers.
fn vec_u8(bytes: &[u8]) -> RuntimeValue {
    let elements: Vec<RuntimeValue> = bytes.iter().copied().map(RuntimeValue::U8).collect();
    vec_value(elements)
}

/// Extract a `Vec<u8>` from a runtime hash-digest container value.
fn extract_vec_u8(value: &RuntimeValue) -> Vec<u8> {
    let RuntimeValue::Container(Container::Vector(rc)) = value else {
        panic!("expected Container::Vector");
    };
    rc.borrow()
        .iter()
        .map(|v| match v {
            RuntimeValue::U8(b) => *b,
            _ => panic!("expected U8 element"),
        })
        .collect()
}

/// Construct a state with a single transparent frame.
fn state_with_transparent_frame(local_count: usize) -> InterpreterState {
    state_with_frame(local_count)
}

/// Construct a state with a single shielded frame.
fn state_with_shielded_frame(local_count: usize) -> InterpreterState {
    let mut state = InterpreterState::new();
    state.push_frame(Frame::new_with_privacy(
        fh(0),
        local_count,
        PrivacyMode::Shielded,
    ));
    state
}

/// Construct an empty placeholder module.
fn empty_module() -> AdamantCompiledModule {
    AdamantCompiledModule::default()
}

/// Construct a module carrying a single function handle + empty
/// definition (used by frame-creation handler tests). Returns the
/// new function-handle index.
fn add_simple_function(m: &mut AdamantCompiledModule) -> FunctionHandleIndex {
    if m.module_handles.is_empty() {
        m.module_handles.push(ModuleHandle {
            address: adamant_bytecode_format::AddressIdentifierIndex(0),
            name: IdentifierIndex(0),
        });
        m.identifiers
            .push(Identifier::new("f").expect("identifier"));
        m.address_identifiers
            .push(adamant_types::Address::from_bytes([0u8; 32]));
        m.signatures.push(Signature(vec![]));
    }
    let _ = AbilitySet::EMPTY; // import used elsewhere
    let _ = DatatypeHandle {
        module: ModuleHandleIndex(0),
        name: IdentifierIndex(0),
        abilities: AbilitySet::EMPTY,
        type_parameters: Vec::new(),
    }; // datatype handle not needed for plain function defs
    let _ = DatatypeHandleIndex(0);
    let fh_idx = u16::try_from(m.function_handles.len()).expect("fits u16");
    m.function_handles.push(FunctionHandle {
        module: ModuleHandleIndex(0),
        name: IdentifierIndex(0),
        parameters: SignatureIndex(0),
        return_: SignatureIndex(0),
        type_parameters: Vec::new(),
    });
    m.function_defs.push(AdamantFunctionDefinition {
        function: FunctionHandleIndex(fh_idx),
        visibility: Visibility::Public,
        is_entry: false,
        acquires_global_resources: Vec::new(),
        code: Some(AdamantCodeUnit {
            locals: SignatureIndex(0),
            code: Vec::new(),
            jump_tables: Vec::new(),
        }),
    });
    FunctionHandleIndex(fh_idx)
}

/// Dispatch an Adamant-extension opcode against the provided
/// state + module.
fn dispatch_adamant(
    state: &mut InterpreterState,
    opcode: AdamantBytecode,
    module: &AdamantCompiledModule,
) -> Result<DispatchOutcome, VMError> {
    dispatch_instruction(&BytecodeInstruction::Adamant(opcode), state, module)
}

// =====================================================================
// Sha3_256
// =====================================================================

/// Whitepaper §3.3.1 (verbatim): "SHA3-256 (FIPS 202) produces a
/// 256-bit (32-byte) hash output."
///
/// Pops `vector<u8>`, pushes 32-byte digest as `vector<u8>`.
#[test]
fn sha3_256_hashes_input_to_32_byte_digest() {
    let module = empty_module();
    let mut state = state_with_transparent_frame(0);
    push_stack(&mut state, vec![vec_u8(b"hello")]);
    dispatch_adamant(&mut state, AdamantBytecode::Sha3_256, &module).expect("ok");
    let digest = extract_vec_u8(&top(&state));
    assert_eq!(digest.len(), 32);
    // Match against adamant_crypto's canonical implementation.
    let expected = adamant_crypto::hash::sha3_256_plain(b"hello");
    assert_eq!(digest, expected.to_vec());
    assert_eq!(pc(&state), 1);
}

/// SHA3-256 of the empty string.
#[test]
fn sha3_256_empty_input() {
    let module = empty_module();
    let mut state = state_with_transparent_frame(0);
    push_stack(&mut state, vec![vec_u8(b"")]);
    dispatch_adamant(&mut state, AdamantBytecode::Sha3_256, &module).expect("ok");
    let digest = extract_vec_u8(&top(&state));
    let expected = adamant_crypto::hash::sha3_256_plain(b"");
    assert_eq!(digest, expected.to_vec());
}

/// SHA3-256 with non-vector input surfaces type mismatch.
#[test]
fn sha3_256_with_non_vector_input_surfaces_type_mismatch() {
    let module = empty_module();
    let mut state = state_with_transparent_frame(0);
    push_stack(&mut state, vec![RuntimeValue::U64(7)]);
    let result = dispatch_adamant(&mut state, AdamantBytecode::Sha3_256, &module);
    assert!(matches!(
        result,
        Err(VMError::InvariantViolation {
            reason: InvariantViolationReason::TypeMismatchOnStack
        })
    ));
}

/// SHA3-256 with non-U8-element vector surfaces type mismatch.
#[test]
fn sha3_256_with_non_u8_elements_surfaces_type_mismatch() {
    let module = empty_module();
    let mut state = state_with_transparent_frame(0);
    push_stack(
        &mut state,
        vec![vec_value(vec![RuntimeValue::U64(1), RuntimeValue::U64(2)])],
    );
    let result = dispatch_adamant(&mut state, AdamantBytecode::Sha3_256, &module);
    assert!(matches!(
        result,
        Err(VMError::InvariantViolation {
            reason: InvariantViolationReason::TypeMismatchOnStack
        })
    ));
}

// =====================================================================
// Blake3
// =====================================================================

/// Whitepaper §3.3.2: BLAKE3 auxiliary hash. Same shape as SHA3-256.
#[test]
fn blake3_hashes_input_to_32_byte_digest() {
    let module = empty_module();
    let mut state = state_with_transparent_frame(0);
    push_stack(&mut state, vec![vec_u8(b"adamant")]);
    dispatch_adamant(&mut state, AdamantBytecode::Blake3, &module).expect("ok");
    let digest = extract_vec_u8(&top(&state));
    assert_eq!(digest.len(), 32);
    let expected = adamant_crypto::hash::blake3(b"adamant");
    assert_eq!(digest, expected.to_vec());
}

/// SHA3-256 and BLAKE3 produce different digests for same input.
#[test]
fn sha3_and_blake3_produce_distinct_digests_for_same_input() {
    let module = empty_module();
    let mut state_sha = state_with_transparent_frame(0);
    push_stack(&mut state_sha, vec![vec_u8(b"adamant")]);
    dispatch_adamant(&mut state_sha, AdamantBytecode::Sha3_256, &module).expect("ok");
    let sha_digest = extract_vec_u8(&top(&state_sha));

    let mut state_blake = state_with_transparent_frame(0);
    push_stack(&mut state_blake, vec![vec_u8(b"adamant")]);
    dispatch_adamant(&mut state_blake, AdamantBytecode::Blake3, &module).expect("ok");
    let blake_digest = extract_vec_u8(&top(&state_blake));

    assert_ne!(sha_digest, blake_digest);
}

// =====================================================================
// Ed25519Verify
// =====================================================================

/// Whitepaper §3.4.1 (verbatim): "Ed25519 (RFC 8032) for transaction
/// authorization."
///
/// Round-trip: sign with adamant-crypto, verify via the handler.
#[test]
fn ed25519_verify_accepts_valid_signature() {
    use adamant_crypto::sig_classical::SigningKey;
    let sk = SigningKey::from_seed(&[0xAB; 32]);
    let pk = sk.verifying_key();
    let msg = b"adamant test message";
    let sig = sk.sign(msg);

    let module = empty_module();
    let mut state = state_with_transparent_frame(0);
    push_stack(
        &mut state,
        vec![vec_u8(&pk.to_bytes()), vec_u8(msg), vec_u8(&sig.to_bytes())],
    );
    dispatch_adamant(&mut state, AdamantBytecode::Ed25519Verify, &module).expect("ok");
    assert_eq!(top(&state), RuntimeValue::Bool(true));
    assert_eq!(pc(&state), 1);
}

/// Ed25519 with a tampered message returns false.
#[test]
fn ed25519_verify_rejects_tampered_message() {
    use adamant_crypto::sig_classical::SigningKey;
    let sk = SigningKey::from_seed(&[0xAB; 32]);
    let pk = sk.verifying_key();
    let msg = b"adamant test message";
    let sig = sk.sign(msg);

    let module = empty_module();
    let mut state = state_with_transparent_frame(0);
    push_stack(
        &mut state,
        vec![
            vec_u8(&pk.to_bytes()),
            vec_u8(b"different message"),
            vec_u8(&sig.to_bytes()),
        ],
    );
    dispatch_adamant(&mut state, AdamantBytecode::Ed25519Verify, &module).expect("ok");
    assert_eq!(top(&state), RuntimeValue::Bool(false));
}

/// Ed25519 with wrong-size public key returns false (parse fails).
#[test]
fn ed25519_verify_with_wrong_pk_size_returns_false() {
    let module = empty_module();
    let mut state = state_with_transparent_frame(0);
    push_stack(
        &mut state,
        vec![
            vec_u8(&[0u8; 16]), // wrong size
            vec_u8(b"msg"),
            vec_u8(&[0u8; 64]),
        ],
    );
    dispatch_adamant(&mut state, AdamantBytecode::Ed25519Verify, &module).expect("ok");
    assert_eq!(top(&state), RuntimeValue::Bool(false));
}

/// Ed25519 with wrong-size signature returns false.
#[test]
fn ed25519_verify_with_wrong_sig_size_returns_false() {
    let module = empty_module();
    let mut state = state_with_transparent_frame(0);
    push_stack(
        &mut state,
        vec![
            vec_u8(&[0u8; 32]),
            vec_u8(b"msg"),
            vec_u8(&[0u8; 32]), // wrong size (sig should be 64)
        ],
    );
    dispatch_adamant(&mut state, AdamantBytecode::Ed25519Verify, &module).expect("ok");
    assert_eq!(top(&state), RuntimeValue::Bool(false));
}

// =====================================================================
// MlDsaVerify65
// =====================================================================

/// Whitepaper §3.4.2 (verbatim): "ML-DSA-65 (FIPS 204 security
/// level 3) post-quantum signature."
#[test]
fn ml_dsa_65_verify_accepts_valid_signature() {
    use adamant_crypto::sig_pq::SigningKey;
    let sk = SigningKey::from_seed(&[0xCD; 32]);
    let pk = sk.verifying_key();
    let msg = b"adamant pq sig";
    let sig = sk.sign(msg).expect("sign");

    let module = empty_module();
    let mut state = state_with_transparent_frame(0);
    push_stack(
        &mut state,
        vec![vec_u8(&pk.to_bytes()), vec_u8(msg), vec_u8(&sig.to_bytes())],
    );
    dispatch_adamant(&mut state, AdamantBytecode::MlDsaVerify65, &module).expect("ok");
    assert_eq!(top(&state), RuntimeValue::Bool(true));
}

/// ML-DSA-65 rejects tampered message.
#[test]
fn ml_dsa_65_verify_rejects_tampered_message() {
    use adamant_crypto::sig_pq::SigningKey;
    let sk = SigningKey::from_seed(&[0xCD; 32]);
    let pk = sk.verifying_key();
    let msg = b"original";
    let sig = sk.sign(msg).expect("sign");

    let module = empty_module();
    let mut state = state_with_transparent_frame(0);
    push_stack(
        &mut state,
        vec![
            vec_u8(&pk.to_bytes()),
            vec_u8(b"tampered"),
            vec_u8(&sig.to_bytes()),
        ],
    );
    dispatch_adamant(&mut state, AdamantBytecode::MlDsaVerify65, &module).expect("ok");
    assert_eq!(top(&state), RuntimeValue::Bool(false));
}

/// ML-DSA-65 with wrong-size pk returns false.
#[test]
fn ml_dsa_65_verify_with_wrong_pk_size_returns_false() {
    let module = empty_module();
    let mut state = state_with_transparent_frame(0);
    push_stack(
        &mut state,
        vec![
            vec_u8(&[0u8; 32]), // wrong size
            vec_u8(b"msg"),
            vec_u8(&[0u8; 3309]),
        ],
    );
    dispatch_adamant(&mut state, AdamantBytecode::MlDsaVerify65, &module).expect("ok");
    assert_eq!(top(&state), RuntimeValue::Bool(false));
}

// =====================================================================
// BlsVerify
// =====================================================================

/// Whitepaper §3.4.3 (verbatim): "BLS12-381 signatures used for
/// validator-set aggregation."
#[test]
fn bls_verify_accepts_valid_signature() {
    use adamant_crypto::bls::SecretKey;
    let sk = SecretKey::from_ikm(&[0xEF; 32]).expect("ikm");
    let pk = sk.public_key();
    let msg = b"validator-set msg";
    let sig = sk.sign(msg);

    let module = empty_module();
    let mut state = state_with_transparent_frame(0);
    push_stack(
        &mut state,
        vec![vec_u8(&pk.to_bytes()), vec_u8(msg), vec_u8(&sig.to_bytes())],
    );
    dispatch_adamant(&mut state, AdamantBytecode::BlsVerify, &module).expect("ok");
    assert_eq!(top(&state), RuntimeValue::Bool(true));
}

/// BLS rejects tampered message.
#[test]
fn bls_verify_rejects_tampered_message() {
    use adamant_crypto::bls::SecretKey;
    let sk = SecretKey::from_ikm(&[0xEF; 32]).expect("ikm");
    let pk = sk.public_key();
    let msg = b"original validator msg";
    let sig = sk.sign(msg);

    let module = empty_module();
    let mut state = state_with_transparent_frame(0);
    push_stack(
        &mut state,
        vec![
            vec_u8(&pk.to_bytes()),
            vec_u8(b"tampered validator msg"),
            vec_u8(&sig.to_bytes()),
        ],
    );
    dispatch_adamant(&mut state, AdamantBytecode::BlsVerify, &module).expect("ok");
    assert_eq!(top(&state), RuntimeValue::Bool(false));
}

/// BLS with wrong-size pk returns false.
#[test]
fn bls_verify_with_wrong_pk_size_returns_false() {
    let module = empty_module();
    let mut state = state_with_transparent_frame(0);
    push_stack(
        &mut state,
        vec![
            vec_u8(&[0u8; 32]), // wrong size (BLS pk is 96)
            vec_u8(b"msg"),
            vec_u8(&[0u8; 48]),
        ],
    );
    dispatch_adamant(&mut state, AdamantBytecode::BlsVerify, &module).expect("ok");
    assert_eq!(top(&state), RuntimeValue::Bool(false));
}

// =====================================================================
// InvokeShielded
// =====================================================================

/// Whitepaper §6.1.2 + §6.2.1.6 Rule 7: privacy consistency
/// statically validated by the verifier; runtime carries the
/// residual binding via `InvokeShielded`'s mode check.
///
/// InvokeShielded from a shielded caller transitions through the
/// outer-driver into a new shielded frame.
#[test]
fn invoke_shielded_from_shielded_caller_creates_shielded_frame() {
    let mut module = empty_module();
    let target = add_simple_function(&mut module);
    let mut state = state_with_shielded_frame(0);

    // Run via the outer driver so DispatchOutcome::InvokeShielded
    // routes through do_call_with_privacy. The fetch closure fires
    // the InvokeShielded once; any subsequent fetch in the callee
    // frame surfaces None → InvalidInstruction. The Cell pattern
    // gives FnOnce-like single-shot behaviour through Fn shape.
    let invoke = AdamantBytecode::InvokeShielded(target);
    let fired = Cell::new(false);
    let result = run(&mut state, &module, |_h, _pc| {
        if fired.get() {
            None
        } else {
            fired.set(true);
            Some(BytecodeInstruction::Adamant(invoke.clone()))
        }
    });
    // After the InvokeShielded fires, do_call_with_privacy creates
    // a new shielded frame. The next fetch returns None →
    // InvalidInstruction. Reaching that error (and not
    // PrivacyModeMismatch) confirms the residual check passed and
    // the new frame was created.
    assert!(matches!(result, Err(VMError::InvalidInstruction { .. })));
}

/// InvokeShielded from a transparent caller surfaces
/// PrivacyModeMismatchPostVerification.
#[test]
fn invoke_shielded_from_transparent_caller_surfaces_privacy_mismatch() {
    let mut module = empty_module();
    let target = add_simple_function(&mut module);
    let mut state = state_with_transparent_frame(0);

    let invoke = AdamantBytecode::InvokeShielded(target);
    let fired = Cell::new(false);
    let result = run(&mut state, &module, move |_h, _pc| {
        if fired.get() {
            None
        } else {
            fired.set(true);
            Some(BytecodeInstruction::Adamant(invoke.clone()))
        }
    });
    assert!(matches!(
        result,
        Err(VMError::InvariantViolation {
            reason: InvariantViolationReason::PrivacyModeMismatchPostVerification
        })
    ));
}

/// InvokeShielded against an OOB function-handle index surfaces
/// invariant violation (residual binding for `bounds_checker`).
#[test]
fn invoke_shielded_oob_handle_surfaces_invariant_violation() {
    let module = empty_module();
    let mut state = state_with_shielded_frame(0);
    let invoke = AdamantBytecode::InvokeShielded(FunctionHandleIndex(99));
    let fired = Cell::new(false);
    let result = run(&mut state, &module, move |_h, _pc| {
        if fired.get() {
            None
        } else {
            fired.set(true);
            Some(BytecodeInstruction::Adamant(invoke.clone()))
        }
    });
    assert!(matches!(
        result,
        Err(VMError::InvariantViolation {
            reason: InvariantViolationReason::IndexOutOfBoundsPostVerification
        })
    ));
}

// =====================================================================
// InvokeTransparent
// =====================================================================

/// InvokeTransparent from a transparent caller transitions into a
/// new transparent frame.
#[test]
fn invoke_transparent_from_transparent_caller_creates_transparent_frame() {
    let mut module = empty_module();
    let target = add_simple_function(&mut module);
    let mut state = state_with_transparent_frame(0);

    let invoke = AdamantBytecode::InvokeTransparent(target);
    let fired = Cell::new(false);
    let result = run(&mut state, &module, move |_h, _pc| {
        if fired.get() {
            None
        } else {
            fired.set(true);
            Some(BytecodeInstruction::Adamant(invoke.clone()))
        }
    });
    assert!(matches!(result, Err(VMError::InvalidInstruction { .. })));
}

/// InvokeTransparent from a shielded caller surfaces privacy
/// mismatch.
#[test]
fn invoke_transparent_from_shielded_caller_surfaces_privacy_mismatch() {
    let mut module = empty_module();
    let target = add_simple_function(&mut module);
    let mut state = state_with_shielded_frame(0);

    let invoke = AdamantBytecode::InvokeTransparent(target);
    let fired = Cell::new(false);
    let result = run(&mut state, &module, move |_h, _pc| {
        if fired.get() {
            None
        } else {
            fired.set(true);
            Some(BytecodeInstruction::Adamant(invoke.clone()))
        }
    });
    assert!(matches!(
        result,
        Err(VMError::InvariantViolation {
            reason: InvariantViolationReason::PrivacyModeMismatchPostVerification
        })
    ));
}

/// Bytecode::Call inherits caller's privacy mode (no transition).
/// Compose-with-do_call: a Call from a shielded frame creates a
/// shielded callee frame.
#[test]
fn call_inherits_caller_privacy_mode() {
    use adamant_bytecode_format::Bytecode;

    let mut module = empty_module();
    let target = add_simple_function(&mut module);
    let mut state = state_with_shielded_frame(0);

    let call = Bytecode::Call(target);
    let fired = Cell::new(false);
    let result = run(&mut state, &module, move |_h, _pc| {
        if fired.get() {
            None
        } else {
            fired.set(true);
            Some(BytecodeInstruction::Inherited(call.clone()))
        }
    });
    // The fact that we reach InvalidInstruction (and not
    // PrivacyModeMismatch — which is impossible here since Call
    // doesn't check) confirms the new shielded frame was created
    // via do_call's caller-mode-inheritance path.
    assert!(matches!(result, Err(VMError::InvalidInstruction { .. })));
}

// =====================================================================
// Deferred handlers
// =====================================================================

/// Deferred handlers (3 unbacked crypto + 4 privacy circuit + 3
/// gas) surface InvalidInstruction at runtime per the verifier-
/// residual posture pending their respective foundation work.
///
/// Sample: KzgCommit deferred to alongside adamant-crypto KZG
/// implementation per Q5/6.3 impl-gate Option γ disposition.
#[test]
fn deferred_kzg_commit_surfaces_invalid_instruction() {
    let module = empty_module();
    let mut state = state_with_transparent_frame(0);
    let result = dispatch_adamant(&mut state, AdamantBytecode::KzgCommit, &module);
    assert!(matches!(result, Err(VMError::InvalidInstruction { .. })));
}

/// Privacy-circuit handler `GenerateProof` deferred to Phase 6
/// `adamant-privacy` (per Phase 5/6.4 plan-gate Option A —
/// adamant-crypto/src/zk.rs is a stub at the time of this test;
/// full Halo 2 surface lands in Phase 6).
#[test]
fn deferred_generate_proof_surfaces_invalid_instruction() {
    let module = empty_module();
    let mut state = state_with_transparent_frame(0);
    let result = dispatch_adamant(
        &mut state,
        AdamantBytecode::GenerateProof(crate::bytecode::CircuitId(0)),
        &module,
    );
    assert!(matches!(result, Err(VMError::InvalidInstruction { .. })));
}

/// Privacy-circuit handler `VerifyProof` deferred to Phase 6
/// `adamant-privacy` (Halo 2 verifier dependency).
#[test]
fn deferred_verify_proof_surfaces_invalid_instruction() {
    let module = empty_module();
    let mut state = state_with_transparent_frame(0);
    let result = dispatch_adamant(
        &mut state,
        AdamantBytecode::VerifyProof(crate::bytecode::CircuitId(0)),
        &module,
    );
    assert!(matches!(result, Err(VMError::InvalidInstruction { .. })));
}

/// Privacy-circuit handler `RecursiveVerify` deferred to Phase 6
/// `adamant-privacy` (Halo 2 recursion + §8.5 recursive-circuit-
/// signature pinning).
#[test]
fn deferred_recursive_verify_surfaces_invalid_instruction() {
    let module = empty_module();
    let mut state = state_with_transparent_frame(0);
    let result = dispatch_adamant(&mut state, AdamantBytecode::RecursiveVerify, &module);
    assert!(matches!(result, Err(VMError::InvalidInstruction { .. })));
}

// (Note: deferred_release_sub_view_key_surfaces_invalid_instruction
// was removed at Phase 5/6.4.b — ReleaseSubViewKey is now a real
// handler per instance-26 §7.4.2 Path 1 amendment ratification.
// See real handler tests below.)

// =====================================================================
// ReleaseSubViewKey (Phase 5/6.4.b — post-instance-26 amendment)
// =====================================================================

/// Whitepaper §7.4.2 (instance 26 Path 1 verbatim): "sub_seed_S =
/// HKDF-SHA3(salt = domain_tag_subview, ikm = sk_v_kem_seed,
/// info = BCS(S), L = 64)".
///
/// Round-trip determinism: same parent seed + same scope produces
/// the same derived seed.
#[test]
fn release_sub_view_key_is_deterministic() {
    let module = empty_module();
    let parent_seed: Vec<u8> = (0..64u8).collect();
    let scope: Vec<u8> = b"scope-A".to_vec();

    let mut state_a = state_with_transparent_frame(0);
    push_stack(&mut state_a, vec![vec_u8(&parent_seed), vec_u8(&scope)]);
    dispatch_adamant(&mut state_a, AdamantBytecode::ReleaseSubViewKey, &module).expect("ok");
    let derived_a = extract_vec_u8(&top(&state_a));

    let mut state_b = state_with_transparent_frame(0);
    push_stack(&mut state_b, vec![vec_u8(&parent_seed), vec_u8(&scope)]);
    dispatch_adamant(&mut state_b, AdamantBytecode::ReleaseSubViewKey, &module).expect("ok");
    let derived_b = extract_vec_u8(&top(&state_b));

    assert_eq!(derived_a, derived_b);
    assert_eq!(derived_a.len(), 64);
}

/// Different scopes produce different derived seeds.
#[test]
fn release_sub_view_key_distinct_scopes_produce_distinct_seeds() {
    let module = empty_module();
    let parent_seed: Vec<u8> = (0..64u8).collect();

    let mut state_a = state_with_transparent_frame(0);
    push_stack(&mut state_a, vec![vec_u8(&parent_seed), vec_u8(b"scope-A")]);
    dispatch_adamant(&mut state_a, AdamantBytecode::ReleaseSubViewKey, &module).expect("ok");
    let derived_a = extract_vec_u8(&top(&state_a));

    let mut state_b = state_with_transparent_frame(0);
    push_stack(&mut state_b, vec![vec_u8(&parent_seed), vec_u8(b"scope-B")]);
    dispatch_adamant(&mut state_b, AdamantBytecode::ReleaseSubViewKey, &module).expect("ok");
    let derived_b = extract_vec_u8(&top(&state_b));

    assert_ne!(derived_a, derived_b);
}

/// Different parent seeds produce different derived seeds.
#[test]
fn release_sub_view_key_distinct_parent_seeds_produce_distinct_seeds() {
    let module = empty_module();
    let scope: Vec<u8> = b"shared-scope".to_vec();

    let mut state_a = state_with_transparent_frame(0);
    push_stack(&mut state_a, vec![vec_u8(&[0xAA; 64]), vec_u8(&scope)]);
    dispatch_adamant(&mut state_a, AdamantBytecode::ReleaseSubViewKey, &module).expect("ok");
    let derived_a = extract_vec_u8(&top(&state_a));

    let mut state_b = state_with_transparent_frame(0);
    push_stack(&mut state_b, vec![vec_u8(&[0xBB; 64]), vec_u8(&scope)]);
    dispatch_adamant(&mut state_b, AdamantBytecode::ReleaseSubViewKey, &module).expect("ok");
    let derived_b = extract_vec_u8(&top(&state_b));

    assert_ne!(derived_a, derived_b);
}

/// Wrong-size parent seed surfaces type mismatch.
#[test]
fn release_sub_view_key_wrong_parent_seed_size_surfaces_type_mismatch() {
    let module = empty_module();
    let mut state = state_with_transparent_frame(0);
    push_stack(&mut state, vec![vec_u8(&[0u8; 32]), vec_u8(b"scope")]);
    let result = dispatch_adamant(&mut state, AdamantBytecode::ReleaseSubViewKey, &module);
    assert!(matches!(
        result,
        Err(VMError::InvariantViolation {
            reason: InvariantViolationReason::TypeMismatchOnStack
        })
    ));
}

/// Empty scope is admissible and produces a deterministic seed.
#[test]
fn release_sub_view_key_empty_scope_is_admissible() {
    let module = empty_module();
    let mut state = state_with_transparent_frame(0);
    push_stack(&mut state, vec![vec_u8(&[0xCC; 64]), vec_u8(b"")]);
    dispatch_adamant(&mut state, AdamantBytecode::ReleaseSubViewKey, &module).expect("ok");
    let derived = extract_vec_u8(&top(&state));
    assert_eq!(derived.len(), 64);
}

// (Note: deferred_charge_gas_surfaces_invalid_instruction was
// removed at Phase 5/6.5 — gas handlers are now real per
// Q5/6.5.4 disposition; see runtime/tests/gas_accounting.rs.)

// =====================================================================
// PC advancement on hash/signature handlers
// =====================================================================

/// All hash + signature handlers advance pc by 1 on success.
#[test]
fn hash_and_signature_handlers_advance_pc_by_one() {
    let module = empty_module();

    // Sha3_256
    let mut state = state_with_transparent_frame(0);
    push_stack(&mut state, vec![vec_u8(b"x")]);
    dispatch_adamant(&mut state, AdamantBytecode::Sha3_256, &module).expect("ok");
    assert_eq!(pc(&state), 1);

    // Blake3
    let mut state = state_with_transparent_frame(0);
    push_stack(&mut state, vec![vec_u8(b"x")]);
    dispatch_adamant(&mut state, AdamantBytecode::Blake3, &module).expect("ok");
    assert_eq!(pc(&state), 1);

    // Ed25519Verify (any input — short sigs return Bool(false) but
    // still advance pc).
    let mut state = state_with_transparent_frame(0);
    push_stack(
        &mut state,
        vec![vec_u8(&[0u8; 32]), vec_u8(b""), vec_u8(&[0u8; 64])],
    );
    dispatch_adamant(&mut state, AdamantBytecode::Ed25519Verify, &module).expect("ok");
    assert_eq!(pc(&state), 1);
}
