//! Runtime-internal value type — whitepaper §6.2.1.4 + §6.2.2.

#![allow(
    clippy::missing_errors_doc,
    reason = "Reference::read_ref / write_ref / Container helpers all return Result with InvariantViolation per verifier-residual binding posture; doc prose covers each function's specific verifier-pass guarantee"
)]
//!
//! `RuntimeValue` is the runtime-layer's tagged union of values
//! that can appear on the operand stack. It is **distinct from
//! [`crate::value::Value`]**, which is the BCS-encoded value type
//! pinned at whitepaper §6.0.7 for transaction arguments and
//! constants. `Value`'s variant set + BCS encoding is consensus-
//! binding; `RuntimeValue` is runtime-internal and never appears
//! in BCS-encoded data.
//!
//! # Why distinct from `Value`
//!
//! 1. **References.** Move's `Bytecode::ImmBorrowLoc` /
//!    `MutBorrowLoc` / `MutBorrowField` etc. push values that
//!    are references to other values. References are runtime-
//!    only; they cannot cross the BCS-encoding boundary because
//!    they carry shared mutable ownership of underlying storage.
//!
//! 2. **Shared ownership for in-place mutation.** A Move
//!    `&mut Vector<u64>` written through `WriteRef` updates the
//!    vector's storage. Multiple references can be borrowed-from
//!    the same vector (the verifier proves non-aliasing of mut
//!    refs). `RuntimeValue::Vector` and `RuntimeValue::Struct`
//!    therefore wrap their interior in `Rc<RefCell<...>>` so a
//!    reference can carry an `Rc` clone alongside an index/path
//!    and mutate the underlying storage through `RefCell::borrow_mut`.
//!
//! 3. **Layer-separation discipline** (Phase 5/6.2a + 5/6.2b
//!    canonical at 3 instances): error/value types live at the
//!    layer where the consequent action is taken. `Value` is the
//!    bytecode-format / transaction-encoding layer; `RuntimeValue`
//!    is the runtime-execution layer. Conversion happens at the
//!    boundary (transaction → execution start; execution → state
//!    commit).
//!
//! # Reference design (Option δ — Sui-VM-aligned)
//!
//! Per Phase 5/6.2c plan-gate Q5/6.2c.1 + the verbatim-source-
//! quote-from-pinned-commit discipline 2nd instance (Sui-VM
//! source at commit `a9a6825eaf6273cc819ee3bcf65fd4909f7624a9`):
//! Adamant adopts the Sui-VM-aligned reference design
//! ("Option δ"). References use `Rc<RefCell<...>>` shared
//! ownership of the referenced container; the verifier
//! (whitepaper §6.2.1.6 `reference_safety` pass) statically
//! validates non-aliasing of mut refs, so `RefCell::borrow` /
//! `borrow_mut` panics are unreachable under correct operation.
//! The strict-superset commitment of §6.2.1.1 requires Adamant's
//! reference semantics to match Sui's for the inherited subset;
//! Option δ is the alignment shape.
//!
//! # `FreezeRef` is a runtime no-op
//!
//! Per the Sui-VM source quote at the same commit:
//! `FreezeRef` "should just be a null op as we don't distinguish
//! between mut and immut ref at runtime." The verifier statically
//! validates mut/immut distinctions; the runtime carries no
//! per-reference mutability tag. Adamant adopts this design.

use core::cell::RefCell;
use core::cmp::Ordering;
use std::rc::Rc;

use adamant_types::{Address, TypeId};

use crate::runtime::error::{InvariantViolationReason, VMError};
use crate::value::{StructValue, Value};

/// Runtime-internal value type.
///
/// Variants 1–8 mirror [`Value`] (BCS-encoded primitive
/// variants). Variants 9–10 are runtime-only:
///
/// - [`RuntimeValue::Container`] wraps a heap-allocated container
///   (vector / struct) with shared mutable interior. References
///   into containers carry an `Rc` clone of the container plus an
///   index, enabling mutation through references.
/// - [`RuntimeValue::Reference`] is a borrowed reference to a
///   local, struct field, or vector element.
///
/// `RuntimeValue::Container` is necessary because references
/// must be able to mutate underlying data through `RefCell`
/// shared interior; transferring this requirement to
/// `RuntimeValue::Vector(Rc<RefCell<Vec<RuntimeValue>>>)` and
/// `RuntimeValue::Struct(Rc<RefCell<StructValue>>)` keeps
/// per-variant types simple. Container-typed values are the
/// runtime representation; conversion to/from BCS [`Value`]
/// happens at the encoding boundary.
#[derive(Debug, Clone)]
pub enum RuntimeValue {
    /// 8-bit unsigned integer.
    U8(u8),
    /// 16-bit unsigned integer.
    U16(u16),
    /// 32-bit unsigned integer.
    U32(u32),
    /// 64-bit unsigned integer.
    U64(u64),
    /// 128-bit unsigned integer.
    U128(u128),
    /// 256-bit unsigned integer (32 bytes little-endian).
    U256([u8; 32]),
    /// Boolean.
    Bool(bool),
    /// Account address.
    Address(Address),
    /// Heap-allocated container (vector or struct) with shared
    /// mutable interior.
    Container(Container),
    /// Runtime-only borrowed reference to a local, struct field,
    /// or vector element.
    Reference(Reference),
}

/// Heap-allocated runtime container with shared mutable interior.
///
/// Containers wrap their interior in `Rc<RefCell<...>>` to
/// support references-with-mutation: a [`Reference`] into a
/// container holds an `Rc::clone(&container.0)` plus an
/// index/path, and mutation through the reference invokes
/// `RefCell::borrow_mut` on the shared interior.
///
/// Two variants:
///
/// - [`Container::Vector`]: a heap-allocated vector of
///   [`RuntimeValue`]s. The polymorphic element type is encoded
///   per-position (each element is a tagged [`RuntimeValue`]).
/// - [`Container::Struct`]: a heap-allocated struct value with
///   typed fields. The struct's fields are stored as a
///   [`StructValue`] inside the cell; conversion to BCS
///   [`Value::Struct`] is a clone-out at the encoding boundary.
#[derive(Debug, Clone)]
pub enum Container {
    /// Vector container.
    Vector(Rc<RefCell<Vec<RuntimeValue>>>),
    /// Struct container with typed fields.
    Struct(Rc<RefCell<StructValue>>),
}

/// Runtime reference to a local, struct field, or vector element.
///
/// References are runtime-only values — they never appear in
/// BCS-encoded data. The [`crate::validator::function_pass::reference_safety`]
/// pass at deploy time statically validates that all references
/// satisfy Move's borrow rules (no two mut refs to the same
/// location alive simultaneously; ref does not outlive the
/// referenced value); the runtime trusts these guarantees and
/// performs no aliasing checks on its own. `RefCell::borrow` /
/// `borrow_mut` panics are therefore unreachable under correct
/// operation; if one fires, the verifier was unsound for the
/// inherited subset, indicating a verifier-residual binding case
/// per [`InvariantViolationReason`].
#[derive(Debug, Clone)]
pub enum Reference {
    /// Reference to a local in a frame's locals slot.
    ///
    /// `locals` is the frame's [`Rc<RefCell<Vec<Option<RuntimeValue>>>>`]
    /// shared with the frame; the reference holds an `Rc::clone`
    /// so it remains valid for as long as the verifier's
    /// `reference_safety` pass proved it lives.
    Local {
        /// Shared ownership of the frame's locals storage.
        locals: Rc<RefCell<Vec<Option<RuntimeValue>>>>,
        /// Index of the local within the frame's locals array.
        idx: usize,
    },
    /// Reference to a field of a struct value.
    ///
    /// The reference holds an `Rc::clone` of the struct's
    /// container so mutation through the reference (`WriteRef`
    /// after `MutBorrowField`) can apply to the underlying struct.
    StructField {
        /// Shared ownership of the struct container.
        container: Rc<RefCell<StructValue>>,
        /// Index of the field within the struct's `fields` array
        /// (canonical declaration order per [`StructValue`]).
        field_idx: usize,
    },
    /// Reference to an element of a vector.
    VectorElement {
        /// Shared ownership of the vector container.
        container: Rc<RefCell<Vec<RuntimeValue>>>,
        /// Index of the element within the vector.
        idx: usize,
    },
}

impl RuntimeValue {
    /// Construct a [`RuntimeValue`] from a BCS [`Value`].
    ///
    /// Primitive variants map directly. [`Value::Vector`] and
    /// [`Value::Struct`] wrap their interior in `Rc<RefCell<...>>`
    /// for runtime shared ownership.
    #[must_use]
    pub fn from_value(value: Value) -> Self {
        match value {
            Value::U8(v) => Self::U8(v),
            Value::U16(v) => Self::U16(v),
            Value::U32(v) => Self::U32(v),
            Value::U64(v) => Self::U64(v),
            Value::U128(v) => Self::U128(v),
            Value::U256(v) => Self::U256(v),
            Value::Bool(v) => Self::Bool(v),
            Value::Address(v) => Self::Address(v),
            Value::Vector(elements) => {
                let runtime_elements: Vec<RuntimeValue> =
                    elements.into_iter().map(RuntimeValue::from_value).collect();
                Self::Container(Container::Vector(Rc::new(RefCell::new(runtime_elements))))
            }
            Value::Struct(struct_value) => {
                // A runtime struct's fields are stored as `Value`
                // (BCS-shape) inside the cell to simplify round-
                // tripping at the encoding boundary. References
                // INTO struct fields dereference the cell and
                // clone-out the referenced field, then re-write
                // through `borrow_mut` for `WriteRef`.
                Self::Container(Container::Struct(Rc::new(RefCell::new(struct_value))))
            }
        }
    }

    /// Convert a [`RuntimeValue`] back to a BCS [`Value`] for
    /// the encoding boundary (state commit, transaction return).
    ///
    /// Returns `None` if the value is a [`RuntimeValue::Reference`]
    /// — references cannot cross the BCS-encoding boundary.
    /// Callers should only invoke this at points where the
    /// verifier's `reference_safety` pass has guaranteed no
    /// references are live.
    #[must_use]
    pub fn to_value(self) -> Option<Value> {
        match self {
            Self::U8(v) => Some(Value::U8(v)),
            Self::U16(v) => Some(Value::U16(v)),
            Self::U32(v) => Some(Value::U32(v)),
            Self::U64(v) => Some(Value::U64(v)),
            Self::U128(v) => Some(Value::U128(v)),
            Self::U256(v) => Some(Value::U256(v)),
            Self::Bool(v) => Some(Value::Bool(v)),
            Self::Address(v) => Some(Value::Address(v)),
            Self::Container(Container::Vector(rc)) => {
                let elements =
                    Rc::try_unwrap(rc).map_or_else(|rc| rc.borrow().clone(), RefCell::into_inner);
                let mut bcs_elements = Vec::with_capacity(elements.len());
                for e in elements {
                    bcs_elements.push(e.to_value()?);
                }
                Some(Value::Vector(bcs_elements))
            }
            Self::Container(Container::Struct(rc)) => {
                let struct_value =
                    Rc::try_unwrap(rc).map_or_else(|rc| rc.borrow().clone(), RefCell::into_inner);
                Some(Value::Struct(struct_value))
            }
            Self::Reference(_) => None,
        }
    }
}

impl PartialEq for RuntimeValue {
    /// Equality for [`RuntimeValue`] follows whitepaper §6.2.1.9
    /// equality semantics: byte-identity at the runtime
    /// representation level, recursing into containers.
    ///
    /// References compare by structural pointer identity for the
    /// same `Reference::Local` (same locals cell + same idx) or
    /// same StructField/VectorElement; the runtime never compares
    /// references to non-references via `Bytecode::Eq` per
    /// whitepaper §6.2.1.9 type-safety pre-conditions. The
    /// implementation is provided for completeness; the verifier's
    /// `type_safety` pass ensures `Eq` operands match types.
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::U8(a), Self::U8(b)) => a == b,
            (Self::U16(a), Self::U16(b)) => a == b,
            (Self::U32(a), Self::U32(b)) => a == b,
            (Self::U64(a), Self::U64(b)) => a == b,
            (Self::U128(a), Self::U128(b)) => a == b,
            (Self::U256(a), Self::U256(b)) => a == b,
            (Self::Bool(a), Self::Bool(b)) => a == b,
            (Self::Address(a), Self::Address(b)) => a == b,
            (Self::Container(Container::Vector(a)), Self::Container(Container::Vector(b))) => {
                *a.borrow() == *b.borrow()
            }
            (Self::Container(Container::Struct(a)), Self::Container(Container::Struct(b))) => {
                *a.borrow() == *b.borrow()
            }
            // Reference operands are not Eq-comparable per
            // whitepaper §6.2.1.9 type-safety pre-conditions; the
            // verifier's type_safety pass should pre-empt any
            // bytecode that reaches this case. Falls through to
            // the catch-all `false`.
            _ => false,
        }
    }
}

impl Eq for RuntimeValue {}

impl Reference {
    /// Read the referenced value, returning an owned clone.
    ///
    /// Per Move semantics: `ReadRef` is only legal on values
    /// whose type carries the `copy` ability (the verifier's
    /// `type_safety` pass enforces this). At runtime, the
    /// referenced value is cloned out — for primitives this is
    /// trivial; for containers (`Vector` / `Struct`), this clones
    /// the underlying storage (not the `Rc` pointer).
    pub fn read_ref(&self) -> Result<RuntimeValue, VMError> {
        match self {
            Self::Local { locals, idx } => {
                let cell = locals.borrow();
                let slot = cell.get(*idx).ok_or(VMError::InvariantViolation {
                    reason: InvariantViolationReason::LocalIndexOutOfBounds,
                })?;
                slot.clone().ok_or(VMError::InvariantViolation {
                    reason: InvariantViolationReason::LocalNotInitialized,
                })
            }
            Self::StructField {
                container,
                field_idx,
            } => {
                let cell = container.borrow();
                let field = cell
                    .fields
                    .get(*field_idx)
                    .ok_or(VMError::InvariantViolation {
                        reason: InvariantViolationReason::LocalIndexOutOfBounds,
                    })?;
                Ok(RuntimeValue::from_value(field.clone()))
            }
            Self::VectorElement { container, idx } => {
                let cell = container.borrow();
                let element = cell.get(*idx).ok_or(VMError::InvariantViolation {
                    reason: InvariantViolationReason::LocalIndexOutOfBounds,
                })?;
                Ok(element.clone())
            }
        }
    }

    /// Write `value` through the reference, replacing the
    /// referenced storage.
    ///
    /// Per Move semantics: `WriteRef` is legal when the previous
    /// value at the location has the `drop` ability (the verifier's
    /// `type_safety` pass enforces this). The runtime simply
    /// overwrites without checking — verifier-residual binding.
    pub fn write_ref(&self, value: RuntimeValue) -> Result<(), VMError> {
        match self {
            Self::Local { locals, idx } => {
                let mut cell = locals.borrow_mut();
                let slot = cell.get_mut(*idx).ok_or(VMError::InvariantViolation {
                    reason: InvariantViolationReason::LocalIndexOutOfBounds,
                })?;
                *slot = Some(value);
                Ok(())
            }
            Self::StructField {
                container,
                field_idx,
            } => {
                let mut cell = container.borrow_mut();
                let field = cell
                    .fields
                    .get_mut(*field_idx)
                    .ok_or(VMError::InvariantViolation {
                        reason: InvariantViolationReason::LocalIndexOutOfBounds,
                    })?;
                let bcs_value = value.to_value().ok_or(VMError::InvariantViolation {
                    reason: InvariantViolationReason::TypeMismatchOnStack,
                })?;
                *field = bcs_value;
                Ok(())
            }
            Self::VectorElement { container, idx } => {
                let mut cell = container.borrow_mut();
                let slot = cell.get_mut(*idx).ok_or(VMError::InvariantViolation {
                    reason: InvariantViolationReason::LocalIndexOutOfBounds,
                })?;
                *slot = value;
                Ok(())
            }
        }
    }
}

impl Container {
    /// Construct an empty struct container with the given type id.
    #[must_use]
    pub fn empty_struct(type_id: TypeId) -> Self {
        Self::Struct(Rc::new(RefCell::new(StructValue {
            type_id,
            fields: Vec::new(),
        })))
    }
}

/// Comparison ordering on [`RuntimeValue`] for `Lt` / `Gt` / `Le`
/// / `Ge` per whitepaper §6.2.1.9 unsigned-integer comparison.
///
/// Only integer variants admit comparison ordering; comparing
/// non-integer or mixed-type operands is a verifier-residual
/// case (`type_safety` pass should pre-empt). The runtime
/// returns `None` on type mismatch; callers wrap that into
/// `VMError::InvariantViolation { TypeMismatchOnStack }`.
#[must_use]
pub fn compare_unsigned(lhs: &RuntimeValue, rhs: &RuntimeValue) -> Option<Ordering> {
    use adamant_bytecode_format::U256 as FormatU256;
    match (lhs, rhs) {
        (RuntimeValue::U8(a), RuntimeValue::U8(b)) => Some(a.cmp(b)),
        (RuntimeValue::U16(a), RuntimeValue::U16(b)) => Some(a.cmp(b)),
        (RuntimeValue::U32(a), RuntimeValue::U32(b)) => Some(a.cmp(b)),
        (RuntimeValue::U64(a), RuntimeValue::U64(b)) => Some(a.cmp(b)),
        (RuntimeValue::U128(a), RuntimeValue::U128(b)) => Some(a.cmp(b)),
        (RuntimeValue::U256(a), RuntimeValue::U256(b)) => {
            Some(FormatU256::from_le_bytes(*a).cmp(&FormatU256::from_le_bytes(*b)))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    //! Verbatim-spec-quote-grounds-runtime-fixture discipline.

    use super::*;

    /// Whitepaper §6.0.7 (verbatim): "U8(u8), U16(u16), ...,
    /// Vector(Vec<Value>), Struct(StructValue)."
    ///
    /// `RuntimeValue::from_value` round-trips through `to_value`
    /// for primitive variants.
    #[test]
    fn from_value_primitive_round_trip() {
        let cases = vec![
            Value::U8(0xAB),
            Value::U16(0xABCD),
            Value::U32(0xABCD_1234),
            Value::U64(0xDEAD_BEEF_CAFE_BABE),
            Value::U128(0x1234_5678_9ABC_DEF0_FEDC_BA98_7654_3210),
            Value::U256([0x42; 32]),
            Value::Bool(true),
            Value::Address(Address::from_bytes([0xCC; 32])),
        ];
        for original in cases {
            let runtime = RuntimeValue::from_value(original.clone());
            assert_eq!(runtime.to_value(), Some(original));
        }
    }

    /// Vector round-trip through `from_value` / `to_value` —
    /// the polymorphic vector encodes element types per-position.
    #[test]
    fn from_value_vector_round_trip() {
        let original = Value::Vector(vec![Value::U64(1), Value::U64(2), Value::U64(3)]);
        let runtime = RuntimeValue::from_value(original.clone());
        assert_eq!(runtime.to_value(), Some(original));
    }

    /// Struct round-trip.
    #[test]
    fn from_value_struct_round_trip() {
        let original = Value::Struct(StructValue {
            type_id: TypeId::from_bytes([0x33; 32]),
            fields: vec![Value::Bool(true), Value::U8(7)],
        });
        let runtime = RuntimeValue::from_value(original.clone());
        assert_eq!(runtime.to_value(), Some(original));
    }

    /// `Reference` cannot cross the BCS-encoding boundary —
    /// `to_value` returns `None`.
    #[test]
    fn reference_to_value_returns_none() {
        let locals = Rc::new(RefCell::new(vec![Some(RuntimeValue::U64(7))]));
        let r = RuntimeValue::Reference(Reference::Local { locals, idx: 0 });
        assert!(r.to_value().is_none());
    }

    /// Whitepaper §6.2.1.4 (verbatim): "Read through a reference.
    /// The value's type must have `Copy`."
    ///
    /// `Reference::Local::read_ref` clones the value at the local
    /// slot.
    #[test]
    fn local_read_ref_clones_value() {
        let locals = Rc::new(RefCell::new(vec![Some(RuntimeValue::U64(42))]));
        let r = Reference::Local {
            locals: Rc::clone(&locals),
            idx: 0,
        };
        let v = r.read_ref().expect("ok");
        assert_eq!(v, RuntimeValue::U64(42));
        // Original local is unchanged.
        assert_eq!(locals.borrow()[0], Some(RuntimeValue::U64(42)));
    }

    /// Whitepaper §6.2.1.4 (verbatim): "Write through a reference.
    /// The previous value's type must have `Drop`."
    ///
    /// `Reference::Local::write_ref` overwrites the local slot.
    #[test]
    fn local_write_ref_overwrites_slot() {
        let locals = Rc::new(RefCell::new(vec![Some(RuntimeValue::U64(7))]));
        let r = Reference::Local {
            locals: Rc::clone(&locals),
            idx: 0,
        };
        r.write_ref(RuntimeValue::U64(99)).expect("ok");
        assert_eq!(locals.borrow()[0], Some(RuntimeValue::U64(99)));
    }

    /// Vector-element reference read/write round-trip.
    #[test]
    fn vector_element_ref_round_trip() {
        let container = Rc::new(RefCell::new(vec![
            RuntimeValue::U64(1),
            RuntimeValue::U64(2),
            RuntimeValue::U64(3),
        ]));
        let r = Reference::VectorElement {
            container: Rc::clone(&container),
            idx: 1,
        };
        assert_eq!(r.read_ref().expect("ok"), RuntimeValue::U64(2));
        r.write_ref(RuntimeValue::U64(99)).expect("ok");
        assert_eq!(container.borrow()[1], RuntimeValue::U64(99));
    }

    /// Struct-field reference read/write round-trip.
    #[test]
    fn struct_field_ref_round_trip() {
        let container = Rc::new(RefCell::new(StructValue {
            type_id: TypeId::from_bytes([0x33; 32]),
            fields: vec![Value::U64(7), Value::Bool(true)],
        }));
        let r = Reference::StructField {
            container: Rc::clone(&container),
            field_idx: 0,
        };
        assert_eq!(r.read_ref().expect("ok"), RuntimeValue::U64(7));
        r.write_ref(RuntimeValue::U64(99)).expect("ok");
        assert_eq!(container.borrow().fields[0], Value::U64(99));
    }

    /// Whitepaper §6.2.1.9 (verbatim): "All integer comparisons
    /// (`Lt`, `Gt`, `Le`, `Ge`) interpret integer operands as
    /// unsigned."
    ///
    /// `compare_unsigned` returns `Some(ord)` for matching integer
    /// types.
    #[test]
    fn compare_unsigned_u64() {
        assert_eq!(
            compare_unsigned(&RuntimeValue::U64(1), &RuntimeValue::U64(2)),
            Some(Ordering::Less)
        );
    }

    /// Type-mismatched comparison returns `None`.
    #[test]
    fn compare_unsigned_type_mismatch_returns_none() {
        assert_eq!(
            compare_unsigned(&RuntimeValue::U64(1), &RuntimeValue::U32(1)),
            None
        );
    }
}
