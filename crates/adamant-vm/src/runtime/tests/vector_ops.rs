//! Vector-op handler tests — VecPack, VecLen, VecPushBack,
//! VecPopBack, VecUnpack, VecSwap. Per Phase 5/6.2c.2.γ-merged.
//!
//! Verbatim-spec-quote-grounds-runtime-fixture discipline applied
//! per fixture; whitepaper §6.2.1.4 quotes anchor each handler's
//! semantics.

use core::cell::RefCell;
use std::rc::Rc;

use adamant_bytecode_format::{Bytecode, SignatureIndex};

use super::*;
use crate::runtime::runtime_value::Container;
use crate::runtime::InvariantViolationReason;

// =====================================================================
// Bytecode::VecPack
// =====================================================================

/// Whitepaper §6.2.1.4 (verbatim): "Pack a vector of `n` elements
/// at the given signature." Pops n elements, pushes a vector
/// container.
#[test]
fn vec_pack_pops_n_and_pushes_vector() {
    let module = module_with_struct(0);
    let mut state = state_with_frame(0);
    push_stack(
        &mut state,
        vec![
            RuntimeValue::U64(1),
            RuntimeValue::U64(2),
            RuntimeValue::U64(3),
        ],
    );
    dispatch_with_module(&mut state, Bytecode::VecPack(SignatureIndex(0), 3), &module).expect("ok");
    let v = top(&state);
    let elements = match v {
        RuntimeValue::Container(Container::Vector(rc)) => rc.borrow().clone(),
        _ => panic!("expected vector"),
    };
    assert_eq!(
        elements,
        vec![
            RuntimeValue::U64(1),
            RuntimeValue::U64(2),
            RuntimeValue::U64(3),
        ]
    );
    assert_eq!(pc(&state), 1);
}

/// Vector with 0 elements → empty vector.
#[test]
fn vec_pack_zero_elements_produces_empty_vector() {
    let module = module_with_struct(0);
    let mut state = state_with_frame(0);
    dispatch_with_module(&mut state, Bytecode::VecPack(SignatureIndex(0), 0), &module).expect("ok");
    let v = top(&state);
    let elements = match v {
        RuntimeValue::Container(Container::Vector(rc)) => rc.borrow().clone(),
        _ => panic!("expected vector"),
    };
    assert!(elements.is_empty());
}

/// VecPack with stack underflow surfaces `StackUnderflow`.
#[test]
fn vec_pack_with_underfilled_stack_surfaces_stack_underflow() {
    let module = module_with_struct(0);
    let mut state = state_with_frame(0);
    push_stack(&mut state, vec![RuntimeValue::U64(1)]);
    let result = dispatch_with_module(&mut state, Bytecode::VecPack(SignatureIndex(0), 3), &module);
    assert!(matches!(
        result,
        Err(VMError::InvariantViolation {
            reason: InvariantViolationReason::StackUnderflow
        })
    ));
}

// =====================================================================
// Bytecode::VecLen
// =====================================================================

/// Whitepaper §6.2.1.4 (verbatim): "Vector length." Pops a
/// reference to a vector, pushes its length as a u64.
#[test]
fn vec_len_reads_length_from_referenced_vector() {
    let module = module_with_struct(0);
    let mut state = state_with_frame(0);
    let rc = Rc::new(RefCell::new(vec![
        RuntimeValue::U64(1),
        RuntimeValue::U64(2),
        RuntimeValue::U64(3),
    ]));
    let r = Reference::Container(Container::Vector(Rc::clone(&rc)));
    push_stack(&mut state, vec![RuntimeValue::Reference(r)]);
    dispatch_with_module(&mut state, Bytecode::VecLen(SignatureIndex(0)), &module).expect("ok");
    assert_eq!(top(&state), RuntimeValue::U64(3));
    assert_eq!(pc(&state), 1);
}

/// VecLen on an empty vector returns 0.
#[test]
fn vec_len_on_empty_vector_returns_zero() {
    let module = module_with_struct(0);
    let mut state = state_with_frame(0);
    let rc: Rc<RefCell<Vec<RuntimeValue>>> = Rc::new(RefCell::new(vec![]));
    let r = Reference::Container(Container::Vector(Rc::clone(&rc)));
    push_stack(&mut state, vec![RuntimeValue::Reference(r)]);
    dispatch_with_module(&mut state, Bytecode::VecLen(SignatureIndex(0)), &module).expect("ok");
    assert_eq!(top(&state), RuntimeValue::U64(0));
}

/// VecLen on a non-vector reference surfaces type mismatch.
#[test]
fn vec_len_on_non_vector_reference_surfaces_type_mismatch() {
    let module = module_with_struct(0);
    let mut state = state_with_frame(0);
    let rc = Rc::new(RefCell::new(RuntimeStructValue {
        type_id: adamant_types::TypeId::from_bytes([0xAA; 32]),
        fields: vec![RuntimeValue::U64(1)],
    }));
    let r = Reference::Container(Container::Struct(Rc::clone(&rc)));
    push_stack(&mut state, vec![RuntimeValue::Reference(r)]);
    let result = dispatch_with_module(&mut state, Bytecode::VecLen(SignatureIndex(0)), &module);
    assert!(matches!(
        result,
        Err(VMError::InvariantViolation {
            reason: InvariantViolationReason::TypeMismatchOnStack
        })
    ));
}

// =====================================================================
// Bytecode::VecPushBack
// =====================================================================

/// Whitepaper §6.2.1.4 (verbatim): "Push to the back of a vector."
/// Pops value + reference; pushes value to back of referenced vector.
#[test]
fn vec_push_back_appends_to_vector_through_reference() {
    let module = module_with_struct(0);
    let mut state = state_with_frame(0);
    let rc = Rc::new(RefCell::new(vec![
        RuntimeValue::U64(1),
        RuntimeValue::U64(2),
    ]));
    let r = Reference::Container(Container::Vector(Rc::clone(&rc)));
    push_stack(
        &mut state,
        vec![RuntimeValue::Reference(r), RuntimeValue::U64(3)],
    );
    dispatch_with_module(
        &mut state,
        Bytecode::VecPushBack(SignatureIndex(0)),
        &module,
    )
    .expect("ok");
    assert_eq!(stack_len(&state), 0);
    assert_eq!(
        rc.borrow().clone(),
        vec![
            RuntimeValue::U64(1),
            RuntimeValue::U64(2),
            RuntimeValue::U64(3),
        ]
    );
    assert_eq!(pc(&state), 1);
}

/// VecPushBack on an empty vector reaches length 1.
#[test]
fn vec_push_back_on_empty_vector_reaches_length_one() {
    let module = module_with_struct(0);
    let mut state = state_with_frame(0);
    let rc: Rc<RefCell<Vec<RuntimeValue>>> = Rc::new(RefCell::new(vec![]));
    let r = Reference::Container(Container::Vector(Rc::clone(&rc)));
    push_stack(
        &mut state,
        vec![RuntimeValue::Reference(r), RuntimeValue::U64(7)],
    );
    dispatch_with_module(
        &mut state,
        Bytecode::VecPushBack(SignatureIndex(0)),
        &module,
    )
    .expect("ok");
    assert_eq!(rc.borrow().len(), 1);
    assert_eq!(rc.borrow()[0], RuntimeValue::U64(7));
}

// =====================================================================
// Bytecode::VecPopBack
// =====================================================================

/// Whitepaper §6.2.1.4 (verbatim): "Pop from the back of a vector."
/// Pops a vector reference; pops back of vector; pushes element.
#[test]
fn vec_pop_back_removes_last_and_pushes_it() {
    let module = module_with_struct(0);
    let mut state = state_with_frame(0);
    let rc = Rc::new(RefCell::new(vec![
        RuntimeValue::U64(1),
        RuntimeValue::U64(2),
        RuntimeValue::U64(3),
    ]));
    let r = Reference::Container(Container::Vector(Rc::clone(&rc)));
    push_stack(&mut state, vec![RuntimeValue::Reference(r)]);
    dispatch_with_module(&mut state, Bytecode::VecPopBack(SignatureIndex(0)), &module).expect("ok");
    assert_eq!(top(&state), RuntimeValue::U64(3));
    assert_eq!(rc.borrow().len(), 2);
}

/// VecPopBack on an empty vector aborts with
/// `IndexOutOfBoundsPostVerification` (residual binding for the
/// abort-on-empty case Sui-VM surfaces).
#[test]
fn vec_pop_back_on_empty_vector_aborts() {
    let module = module_with_struct(0);
    let mut state = state_with_frame(0);
    let rc: Rc<RefCell<Vec<RuntimeValue>>> = Rc::new(RefCell::new(vec![]));
    let r = Reference::Container(Container::Vector(Rc::clone(&rc)));
    push_stack(&mut state, vec![RuntimeValue::Reference(r)]);
    let result = dispatch_with_module(&mut state, Bytecode::VecPopBack(SignatureIndex(0)), &module);
    assert!(matches!(
        result,
        Err(VMError::InvariantViolation {
            reason: InvariantViolationReason::IndexOutOfBoundsPostVerification
        })
    ));
}

// =====================================================================
// Bytecode::VecUnpack
// =====================================================================

/// Whitepaper §6.2.1.4 (verbatim): "Unpack a vector of `n`
/// elements onto the stack." Pops a vector container, pushes its
/// elements in order.
#[test]
fn vec_unpack_pushes_elements_in_order() {
    let module = module_with_struct(0);
    let mut state = state_with_frame(0);
    push_stack(
        &mut state,
        vec![vec_value(vec![
            RuntimeValue::U64(10),
            RuntimeValue::U64(20),
            RuntimeValue::U64(30),
        ])],
    );
    dispatch_with_module(
        &mut state,
        Bytecode::VecUnpack(SignatureIndex(0), 3),
        &module,
    )
    .expect("ok");
    let f = state.top_frame().expect("frame");
    assert_eq!(f.stack[0], RuntimeValue::U64(10));
    assert_eq!(f.stack[1], RuntimeValue::U64(20));
    assert_eq!(f.stack[2], RuntimeValue::U64(30));
}

/// VecUnpack with mismatched declared n surfaces invariant.
#[test]
fn vec_unpack_with_n_mismatch_surfaces_invariant() {
    let module = module_with_struct(0);
    let mut state = state_with_frame(0);
    push_stack(&mut state, vec![vec_value(vec![RuntimeValue::U64(7)])]);
    let result = dispatch_with_module(
        &mut state,
        Bytecode::VecUnpack(SignatureIndex(0), 2),
        &module,
    );
    assert!(matches!(
        result,
        Err(VMError::InvariantViolation {
            reason: InvariantViolationReason::IndexOutOfBoundsPostVerification
        })
    ));
}

/// VecPack-then-VecUnpack round-trip preserves elements.
#[test]
fn vec_pack_then_unpack_round_trip() {
    let module = module_with_struct(0);
    let mut state = state_with_frame(0);
    push_stack(
        &mut state,
        vec![
            RuntimeValue::U64(7),
            RuntimeValue::U64(8),
            RuntimeValue::U64(9),
        ],
    );
    dispatch_with_module(&mut state, Bytecode::VecPack(SignatureIndex(0), 3), &module)
        .expect("pack");
    dispatch_with_module(
        &mut state,
        Bytecode::VecUnpack(SignatureIndex(0), 3),
        &module,
    )
    .expect("unpack");
    let f = state.top_frame().expect("frame");
    assert_eq!(f.stack[0], RuntimeValue::U64(7));
    assert_eq!(f.stack[1], RuntimeValue::U64(8));
    assert_eq!(f.stack[2], RuntimeValue::U64(9));
}

// =====================================================================
// Bytecode::VecSwap
// =====================================================================

/// Whitepaper §6.2.1.4 (verbatim): "Swap two elements in a vector."
/// Pops two indices + reference; swaps elements.
///
/// Stack order: top is index j, then index i, then reference.
#[test]
fn vec_swap_swaps_elements_at_indices() {
    let module = module_with_struct(0);
    let mut state = state_with_frame(0);
    let rc = Rc::new(RefCell::new(vec![
        RuntimeValue::U64(1),
        RuntimeValue::U64(2),
        RuntimeValue::U64(3),
    ]));
    let r = Reference::Container(Container::Vector(Rc::clone(&rc)));
    push_stack(
        &mut state,
        vec![
            RuntimeValue::Reference(r),
            RuntimeValue::U64(0),
            RuntimeValue::U64(2),
        ],
    );
    dispatch_with_module(&mut state, Bytecode::VecSwap(SignatureIndex(0)), &module).expect("ok");
    assert_eq!(stack_len(&state), 0);
    assert_eq!(
        rc.borrow().clone(),
        vec![
            RuntimeValue::U64(3),
            RuntimeValue::U64(2),
            RuntimeValue::U64(1),
        ]
    );
}

/// VecSwap with OOB index aborts.
#[test]
fn vec_swap_with_oob_index_aborts() {
    let module = module_with_struct(0);
    let mut state = state_with_frame(0);
    let rc = Rc::new(RefCell::new(vec![
        RuntimeValue::U64(1),
        RuntimeValue::U64(2),
    ]));
    let r = Reference::Container(Container::Vector(Rc::clone(&rc)));
    push_stack(
        &mut state,
        vec![
            RuntimeValue::Reference(r),
            RuntimeValue::U64(0),
            RuntimeValue::U64(99),
        ],
    );
    let result = dispatch_with_module(&mut state, Bytecode::VecSwap(SignatureIndex(0)), &module);
    assert!(matches!(
        result,
        Err(VMError::InvariantViolation {
            reason: InvariantViolationReason::IndexOutOfBoundsPostVerification
        })
    ));
}

/// VecSwap with i == j is a no-op.
#[test]
fn vec_swap_with_equal_indices_is_no_op() {
    let module = module_with_struct(0);
    let mut state = state_with_frame(0);
    let rc = Rc::new(RefCell::new(vec![
        RuntimeValue::U64(1),
        RuntimeValue::U64(2),
        RuntimeValue::U64(3),
    ]));
    let r = Reference::Container(Container::Vector(Rc::clone(&rc)));
    push_stack(
        &mut state,
        vec![
            RuntimeValue::Reference(r),
            RuntimeValue::U64(1),
            RuntimeValue::U64(1),
        ],
    );
    dispatch_with_module(&mut state, Bytecode::VecSwap(SignatureIndex(0)), &module).expect("ok");
    assert_eq!(
        rc.borrow().clone(),
        vec![
            RuntimeValue::U64(1),
            RuntimeValue::U64(2),
            RuntimeValue::U64(3),
        ]
    );
}

// =====================================================================
// PC advancement (cross-handler invariant)
// =====================================================================

/// All vector handlers advance pc by 1 on success.
#[test]
fn all_vector_handlers_advance_pc_by_one() {
    let module = module_with_struct(0);
    // Test VecPack
    let mut state = state_with_frame(0);
    dispatch_with_module(&mut state, Bytecode::VecPack(SignatureIndex(0), 0), &module).expect("ok");
    assert_eq!(pc(&state), 1);

    // Test VecLen
    let mut state = state_with_frame(0);
    let rc: Rc<RefCell<Vec<RuntimeValue>>> = Rc::new(RefCell::new(vec![]));
    let r = Reference::Container(Container::Vector(Rc::clone(&rc)));
    push_stack(&mut state, vec![RuntimeValue::Reference(r)]);
    dispatch_with_module(&mut state, Bytecode::VecLen(SignatureIndex(0)), &module).expect("ok");
    assert_eq!(pc(&state), 1);

    // Test VecUnpack
    let mut state = state_with_frame(0);
    push_stack(&mut state, vec![vec_value(vec![])]);
    dispatch_with_module(
        &mut state,
        Bytecode::VecUnpack(SignatureIndex(0), 0),
        &module,
    )
    .expect("ok");
    assert_eq!(pc(&state), 1);
}
