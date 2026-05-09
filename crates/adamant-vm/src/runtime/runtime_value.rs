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

/// Runtime-only struct value with [`RuntimeValue`] fields.
///
/// Distinct from BCS [`StructValue`] (which has `Vec<Value>`
/// fields). At runtime, struct fields can themselves be runtime-
/// only values like [`Container`] (nested structs / vectors with
/// their own `Rc-RefCell` wrappers, enabling composed borrows
/// per Phase 5/6.2c.1.b's foundation correction).
///
/// Conversion to/from BCS [`StructValue`] happens at the encoding
/// boundary via [`RuntimeValue::from_value`] / [`RuntimeValue::to_value`].
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct RuntimeStructValue {
    /// Identifier of the struct's type definition (whitepaper
    /// section 5.1.2).
    pub type_id: TypeId,
    /// Field values in canonical declaration order. Fields can
    /// be primitive [`RuntimeValue`] variants or
    /// [`RuntimeValue::Container`] (for nested structs / vectors).
    pub fields: Vec<RuntimeValue>,
}

/// Runtime-only enum-variant value with [`RuntimeValue`] fields
/// plus the variant tag.
///
/// Distinct from [`RuntimeStructValue`]: variants are categorically
/// distinct from structs (sum types vs product types) per the
/// information-theoretic + substructural-types argument at the
/// Phase 5/6.2c.2.γ-merged plan-gate Q-γ.3 disposition. The
/// verifier's `type_safety` pass statically distinguishes variant
/// types from struct types; the runtime preserves that
/// distinction via [`Container::Variant`] / [`Container::Struct`]
/// rather than a tagged-struct convention.
///
/// `variant_tag` is the runtime-readable variant index per
/// whitepaper §6.2.1.4 + the inherited Sui-base bytecode-format
/// commitment at file_format.rs:1813-1819 ("Branch on the tag
/// value of the enum value reference"). The static
/// [`adamant_bytecode_format::VariantHandle`] pins the expected
/// tag at deploy time; the runtime tag must equal the handle's
/// tag for `UnpackVariant` (verifier-residual:
/// [`InvariantViolationReason::VariantTagMismatch`]).
///
/// At γ-merged scope, variant values do not cross the BCS-encoding
/// boundary — `to_value` returns `None` for [`Container::Variant`]
/// values, mirroring the carry-forward shape of [`Reference`].
/// Variant-to-BCS conversion lands at a future Phase 5/6 sub-arc
/// when transaction-argument and object-state representation of
/// enum values is finalized.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct RuntimeVariantValue {
    /// Identifier of the enum's type definition (whitepaper
    /// section 5.1.2).
    pub type_id: TypeId,
    /// Variant index within the enum's `variants` vector
    /// per [`adamant_bytecode_format::VariantTag`]. Read by
    /// `VariantSwitch` at runtime; checked against the static
    /// `VariantHandle::variant` by `UnpackVariant`.
    pub variant_tag: u16,
    /// Field values for this specific variant in canonical
    /// declaration order. The field shape is variant-specific;
    /// different variants of the same enum may have different
    /// field counts and types.
    pub fields: Vec<RuntimeValue>,
}

/// Heap-allocated runtime container with shared mutable interior.
///
/// Containers wrap their interior in `Rc<RefCell<...>>` to
/// support references-with-mutation + composed borrows: a
/// [`Reference`] into a container holds an `Rc::clone` of the
/// container plus an index/path; mutation through the reference
/// invokes `RefCell::borrow_mut` on the shared interior. Nested
/// containers (a struct field that is itself a struct, or a
/// vector element that is itself a vector) have their own
/// `Rc-RefCell` wrappers, allowing composed borrows like
/// `&mut s.f1.f2` to descend through the container chain.
///
/// Three variants:
///
/// - [`Container::Vector`]: a heap-allocated vector of
///   [`RuntimeValue`]s. The polymorphic element type is encoded
///   per-position.
/// - [`Container::Struct`]: a heap-allocated struct value with
///   [`RuntimeValue`] fields (per [`RuntimeStructValue`]).
/// - [`Container::Variant`]: a heap-allocated enum-variant value
///   with a runtime-readable `variant_tag` plus
///   [`RuntimeValue`] fields (per [`RuntimeVariantValue`]).
///   Distinct from `Struct` per the sum-vs-product type-level
///   distinction (Phase 5/6.2c.2.γ-merged plan-gate Q-γ.3).
#[derive(Debug, Clone)]
pub enum Container {
    /// Vector container.
    Vector(Rc<RefCell<Vec<RuntimeValue>>>),
    /// Struct container with [`RuntimeValue`] fields.
    Struct(Rc<RefCell<RuntimeStructValue>>),
    /// Enum-variant container with a tag and [`RuntimeValue`]
    /// fields.
    Variant(Rc<RefCell<RuntimeVariantValue>>),
}

/// Runtime reference — three variants per Phase 5/6.2c.1.b's
/// composed-borrow design (Sui-VM-aligned).
///
/// References are runtime-only values — they never appear in
/// BCS-encoded data. The [`crate::validator::function_pass::reference_safety`]
/// pass at deploy time statically validates Move's borrow rules
/// (no two mut refs to the same location alive simultaneously;
/// ref does not outlive the referenced value); the runtime
/// trusts these guarantees. `RefCell::borrow` / `borrow_mut`
/// panics are unreachable under correct operation.
///
/// # Variant taxonomy
///
/// - [`Reference::Local`] — reference to a slot in a frame's
///   locals storage. `locals[idx]` is `Option<RuntimeValue>`;
///   `read_ref` clones the value (must be `Some`); `write_ref`
///   replaces the slot.
/// - [`Reference::Container`] — direct reference to a heap-
///   allocated container (struct or vector). Used when borrowing
///   a container-typed local or a container-typed field.
///   `borrow_field` / `borrow_element` descend further into the
///   container.
/// - [`Reference::Indexed`] — reference to a primitive value at
///   index `idx` within a container. `read_ref` clones the
///   primitive at the index; `write_ref` overwrites the slot.
///
/// # Composed-borrow chain shape
///
/// A composed borrow `&mut s.f1.f2` produces:
/// 1. `BorrowLoc(s)` → `Reference::Container(struct_s)`
/// 2. `BorrowField(.f1)` on container → if f1 is a container,
///    `Reference::Container(struct_f1)`; otherwise
///    `Reference::Indexed { container: struct_s, idx: f1_idx }`
/// 3. `BorrowField(.f2)` continues from there
///
/// Each container in the chain has its own `Rc-RefCell` wrapper;
/// the reference holds an `Rc::clone` so it remains valid for
/// the borrow lifetime the verifier proved.
#[derive(Debug, Clone)]
pub enum Reference {
    /// Reference to a slot in a frame's locals storage.
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
    /// Direct reference to a heap-allocated container (struct
    /// or vector). Used when the borrow target is a container-
    /// typed value; further `borrow_field` / `borrow_element`
    /// descends through the container chain.
    Container(Container),
    /// Indexed reference to a primitive value at position `idx`
    /// within a container. Used when the borrow target is a
    /// primitive-typed field or vector element.
    Indexed {
        /// Shared ownership of the container holding the
        /// primitive value.
        container: Container,
        /// Position of the primitive within the container's
        /// underlying storage (struct field index or vector
        /// element index).
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
                // Per Phase 5/6.2c.1.b composed-borrow fix:
                // recursively convert struct fields to
                // RuntimeValue. Nested struct fields become
                // RuntimeValue::Container(Container::Struct(rc))
                // — each level has its own Rc-RefCell wrapper so
                // composed borrows (`&mut s.f1.f2`) can descend
                // through the container chain.
                let runtime_fields: Vec<RuntimeValue> = struct_value
                    .fields
                    .into_iter()
                    .map(RuntimeValue::from_value)
                    .collect();
                let runtime_struct = RuntimeStructValue {
                    type_id: struct_value.type_id,
                    fields: runtime_fields,
                };
                Self::Container(Container::Struct(Rc::new(RefCell::new(runtime_struct))))
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
                let runtime_struct =
                    Rc::try_unwrap(rc).map_or_else(|rc| rc.borrow().clone(), RefCell::into_inner);
                // Recursively convert each RuntimeValue field
                // back to BCS Value. Nested-struct fields became
                // RuntimeValue::Container variants at from_value
                // time; round-trip back through to_value per
                // Phase 5/6.2c.1.b composed-borrow fix.
                let mut bcs_fields = Vec::with_capacity(runtime_struct.fields.len());
                for f in runtime_struct.fields {
                    bcs_fields.push(f.to_value()?);
                }
                Some(Value::Struct(StructValue {
                    type_id: runtime_struct.type_id,
                    fields: bcs_fields,
                }))
            }
            // Variant values do not cross the BCS-encoding boundary
            // at Phase 5/6.2c.2.γ-merged scope — the BCS [`Value`]
            // surface does not carry a Variant variant. Variant-to-
            // BCS conversion is a Phase 5/6.X carry-forward when
            // transaction-argument and object-state representation
            // of enum values is finalized. Until then, callers that
            // attempt to convert a variant value to BCS will see
            // None, the same shape as Reference.
            Self::Container(Container::Variant(_)) | Self::Reference(_) => None,
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
            (Self::Container(Container::Variant(a)), Self::Container(Container::Variant(b))) => {
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
    /// trivial; for containers, this clones the container's
    /// contents (note: the `Rc` clone semantics on `Container`
    /// actually share the `Rc` pointer; clone-by-content for
    /// `ReadRef` is currently delegated to the `Clone` impl on
    /// [`RuntimeValue`] which wraps `Container` and increments
    /// the `Rc`).
    pub fn read_ref(&self) -> Result<RuntimeValue, VMError> {
        match self {
            Self::Local { locals, idx } => {
                let cell = locals.borrow();
                let slot = cell.get(*idx).ok_or(VMError::InvariantViolation {
                    reason: InvariantViolationReason::IndexOutOfBoundsPostVerification,
                })?;
                slot.clone().ok_or(VMError::InvariantViolation {
                    reason: InvariantViolationReason::LocalNotInitialized,
                })
            }
            Self::Container(c) => {
                // ReadRef on a container reference clones the
                // RuntimeValue wrapper; the Container's `Rc` is
                // cloned by reference (shared interior). Per Move
                // semantics, types with the `copy` ability that
                // are containers structurally have value semantics
                // for ReadRef — this reflects the current Sui-VM
                // alignment posture. Deep-vs-shallow ReadRef
                // semantics for containers is a Phase 5/6.X
                // refinement carry-forward if profiling surfaces
                // it as a concern.
                Ok(RuntimeValue::Container(c.clone()))
            }
            Self::Indexed { container, idx } => match container {
                Container::Struct(rc) => {
                    let cell = rc.borrow();
                    let field = cell.fields.get(*idx).ok_or(VMError::InvariantViolation {
                        reason: InvariantViolationReason::IndexOutOfBoundsPostVerification,
                    })?;
                    Ok(field.clone())
                }
                Container::Vector(rc) => {
                    let cell = rc.borrow();
                    let element = cell.get(*idx).ok_or(VMError::InvariantViolation {
                        reason: InvariantViolationReason::IndexOutOfBoundsPostVerification,
                    })?;
                    Ok(element.clone())
                }
                Container::Variant(rc) => {
                    let cell = rc.borrow();
                    let field = cell.fields.get(*idx).ok_or(VMError::InvariantViolation {
                        reason: InvariantViolationReason::IndexOutOfBoundsPostVerification,
                    })?;
                    Ok(field.clone())
                }
            },
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
                    reason: InvariantViolationReason::IndexOutOfBoundsPostVerification,
                })?;
                *slot = Some(value);
                Ok(())
            }
            Self::Container(c) => {
                // WriteRef on a container reference replaces the
                // container's interior. For Struct: replace
                // RuntimeStructValue. For Vector: replace Vec
                // contents. The new `value` is expected to be a
                // RuntimeValue::Container of the matching kind;
                // the verifier's type_safety pass guarantees
                // this. Type-mismatch surfaces as
                // TypeMismatchOnStack per residual binding.
                match (c, value) {
                    (
                        Container::Struct(target_rc),
                        RuntimeValue::Container(Container::Struct(source_rc)),
                    ) => {
                        let new_struct = source_rc.borrow().clone();
                        *target_rc.borrow_mut() = new_struct;
                        Ok(())
                    }
                    (
                        Container::Vector(target_rc),
                        RuntimeValue::Container(Container::Vector(source_rc)),
                    ) => {
                        let new_vec = source_rc.borrow().clone();
                        *target_rc.borrow_mut() = new_vec;
                        Ok(())
                    }
                    (
                        Container::Variant(target_rc),
                        RuntimeValue::Container(Container::Variant(source_rc)),
                    ) => {
                        let new_variant = source_rc.borrow().clone();
                        *target_rc.borrow_mut() = new_variant;
                        Ok(())
                    }
                    _ => Err(VMError::InvariantViolation {
                        reason: InvariantViolationReason::TypeMismatchOnStack,
                    }),
                }
            }
            Self::Indexed { container, idx } => match container {
                Container::Struct(rc) => {
                    let mut cell = rc.borrow_mut();
                    let slot = cell
                        .fields
                        .get_mut(*idx)
                        .ok_or(VMError::InvariantViolation {
                            reason: InvariantViolationReason::IndexOutOfBoundsPostVerification,
                        })?;
                    *slot = value;
                    Ok(())
                }
                Container::Vector(rc) => {
                    let mut cell = rc.borrow_mut();
                    let slot = cell.get_mut(*idx).ok_or(VMError::InvariantViolation {
                        reason: InvariantViolationReason::IndexOutOfBoundsPostVerification,
                    })?;
                    *slot = value;
                    Ok(())
                }
                Container::Variant(rc) => {
                    let mut cell = rc.borrow_mut();
                    let slot = cell
                        .fields
                        .get_mut(*idx)
                        .ok_or(VMError::InvariantViolation {
                            reason: InvariantViolationReason::IndexOutOfBoundsPostVerification,
                        })?;
                    *slot = value;
                    Ok(())
                }
            },
        }
    }

    /// Descend into a struct field of the referenced container.
    ///
    /// Used by `MutBorrowField` / `ImmBorrowField` handlers.
    /// Per Move semantics, the operand must be a reference to a
    /// struct; the verifier's `type_safety` pass guarantees this.
    /// The returned reference points to the named field —
    /// `Reference::Container` if the field is itself a container,
    /// `Reference::Indexed` if the field is primitive.
    pub fn borrow_field(&self, field_idx: usize) -> Result<Reference, VMError> {
        // First obtain the underlying struct container, dereferencing
        // through Local references as needed.
        let struct_container_rc = self.resolve_struct_container()?;
        let cell = struct_container_rc.borrow();
        let field = cell
            .fields
            .get(field_idx)
            .ok_or(VMError::InvariantViolation {
                reason: InvariantViolationReason::IndexOutOfBoundsPostVerification,
            })?;
        match field {
            // Field is itself a container — return a Container
            // reference pointing to the inner container's
            // shared Rc, enabling further composed borrows.
            RuntimeValue::Container(inner_c) => Ok(Reference::Container(inner_c.clone())),
            // Field is primitive — return an Indexed reference
            // with the parent struct container.
            _ => Ok(Reference::Indexed {
                container: Container::Struct(Rc::clone(&struct_container_rc)),
                idx: field_idx,
            }),
        }
    }

    /// Descend into a vector element of the referenced container.
    ///
    /// Used by `VecImmBorrow` / `VecMutBorrow` handlers.
    /// Analogous to [`Self::borrow_field`] for vector elements.
    pub fn borrow_element(&self, idx: usize) -> Result<Reference, VMError> {
        let vec_container_rc = self.resolve_vector_container()?;
        let cell = vec_container_rc.borrow();
        let element = cell.get(idx).ok_or(VMError::InvariantViolation {
            reason: InvariantViolationReason::IndexOutOfBoundsPostVerification,
        })?;
        match element {
            RuntimeValue::Container(inner_c) => Ok(Reference::Container(inner_c.clone())),
            _ => Ok(Reference::Indexed {
                container: Container::Vector(Rc::clone(&vec_container_rc)),
                idx,
            }),
        }
    }

    /// Resolve a reference to the underlying struct container
    /// `Rc<RefCell<RuntimeStructValue>>`.
    ///
    /// Internal helper for [`Self::borrow_field`]. Returns the
    /// `Rc` clone of the struct container; the caller can then
    /// `borrow` / `borrow_mut` for field access.
    fn resolve_struct_container(&self) -> Result<Rc<RefCell<RuntimeStructValue>>, VMError> {
        match self {
            Self::Container(Container::Struct(rc)) => Ok(Rc::clone(rc)),
            Self::Local { locals, idx } => {
                let cell = locals.borrow();
                let slot = cell.get(*idx).ok_or(VMError::InvariantViolation {
                    reason: InvariantViolationReason::IndexOutOfBoundsPostVerification,
                })?;
                let value = slot.as_ref().ok_or(VMError::InvariantViolation {
                    reason: InvariantViolationReason::LocalNotInitialized,
                })?;
                if let RuntimeValue::Container(Container::Struct(rc)) = value {
                    Ok(Rc::clone(rc))
                } else {
                    Err(VMError::InvariantViolation {
                        reason: InvariantViolationReason::TypeMismatchOnStack,
                    })
                }
            }
            _ => Err(VMError::InvariantViolation {
                reason: InvariantViolationReason::TypeMismatchOnStack,
            }),
        }
    }

    /// Resolve a reference to the underlying vector container.
    /// Analogous to [`Self::resolve_struct_container`].
    fn resolve_vector_container(&self) -> Result<Rc<RefCell<Vec<RuntimeValue>>>, VMError> {
        match self {
            Self::Container(Container::Vector(rc)) => Ok(Rc::clone(rc)),
            Self::Local { locals, idx } => {
                let cell = locals.borrow();
                let slot = cell.get(*idx).ok_or(VMError::InvariantViolation {
                    reason: InvariantViolationReason::IndexOutOfBoundsPostVerification,
                })?;
                let value = slot.as_ref().ok_or(VMError::InvariantViolation {
                    reason: InvariantViolationReason::LocalNotInitialized,
                })?;
                if let RuntimeValue::Container(Container::Vector(rc)) = value {
                    Ok(Rc::clone(rc))
                } else {
                    Err(VMError::InvariantViolation {
                        reason: InvariantViolationReason::TypeMismatchOnStack,
                    })
                }
            }
            _ => Err(VMError::InvariantViolation {
                reason: InvariantViolationReason::TypeMismatchOnStack,
            }),
        }
    }

    /// Resolve a reference to the underlying variant container.
    /// Analogous to [`Self::resolve_struct_container`] for variants.
    /// Used by `UnpackVariantImmRef` / `UnpackVariantMutRef` to
    /// access the variant's tag and fields through a reference.
    pub fn resolve_variant_container(&self) -> Result<Rc<RefCell<RuntimeVariantValue>>, VMError> {
        match self {
            Self::Container(Container::Variant(rc)) => Ok(Rc::clone(rc)),
            Self::Local { locals, idx } => {
                let cell = locals.borrow();
                let slot = cell.get(*idx).ok_or(VMError::InvariantViolation {
                    reason: InvariantViolationReason::IndexOutOfBoundsPostVerification,
                })?;
                let value = slot.as_ref().ok_or(VMError::InvariantViolation {
                    reason: InvariantViolationReason::LocalNotInitialized,
                })?;
                if let RuntimeValue::Container(Container::Variant(rc)) = value {
                    Ok(Rc::clone(rc))
                } else {
                    Err(VMError::InvariantViolation {
                        reason: InvariantViolationReason::TypeMismatchOnStack,
                    })
                }
            }
            _ => Err(VMError::InvariantViolation {
                reason: InvariantViolationReason::TypeMismatchOnStack,
            }),
        }
    }

    /// Vector reference helper — read length of the referenced
    /// vector container.
    ///
    /// Used by `Bytecode::VecLen` (whitepaper §6.2.1.4: "Vector
    /// length"). The reference must be to a `Container::Vector`;
    /// the verifier's `type_safety` pass guarantees this.
    pub fn vector_len(&self) -> Result<usize, VMError> {
        let rc = self.resolve_vector_container()?;
        let len = rc.borrow().len();
        Ok(len)
    }

    /// Vector reference helper — push `value` to the back of the
    /// referenced vector.
    ///
    /// Used by `Bytecode::VecPushBack` (whitepaper §6.2.1.4:
    /// "Push to the back of a vector").
    pub fn vector_push_back(&self, value: RuntimeValue) -> Result<(), VMError> {
        let rc = self.resolve_vector_container()?;
        rc.borrow_mut().push(value);
        Ok(())
    }

    /// Vector reference helper — pop a value from the back of the
    /// referenced vector.
    ///
    /// Used by `Bytecode::VecPopBack` (whitepaper §6.2.1.4:
    /// "Pop from the back of a vector"). Aborts with
    /// `IndexOutOfBoundsPostVerification` if the vector is empty;
    /// the verifier admits the bytecode but does not statically
    /// validate non-emptiness — the runtime carries the residual
    /// binding consistent with Sui-VM's `PopV`/`pop_back` semantics
    /// that surface as a runtime abort on empty vectors.
    pub fn vector_pop_back(&self) -> Result<RuntimeValue, VMError> {
        let rc = self.resolve_vector_container()?;
        let popped = rc.borrow_mut().pop();
        popped.ok_or(VMError::InvariantViolation {
            reason: InvariantViolationReason::IndexOutOfBoundsPostVerification,
        })
    }

    /// Vector reference helper — swap elements at indices `i` and
    /// `j` in the referenced vector.
    ///
    /// Used by `Bytecode::VecSwap` (whitepaper §6.2.1.4: "Swap
    /// two elements in a vector"). Aborts with
    /// `IndexOutOfBoundsPostVerification` if either index is out
    /// of range. Same shape as `Vec::swap`'s panic surface,
    /// surfaced as a typed runtime error rather than a panic.
    pub fn vector_swap(&self, i: usize, j: usize) -> Result<(), VMError> {
        let rc = self.resolve_vector_container()?;
        let mut cell = rc.borrow_mut();
        if i >= cell.len() || j >= cell.len() {
            return Err(VMError::InvariantViolation {
                reason: InvariantViolationReason::IndexOutOfBoundsPostVerification,
            });
        }
        cell.swap(i, j);
        Ok(())
    }
}

impl Container {
    /// Construct an empty struct container with the given type id.
    #[must_use]
    pub fn empty_struct(type_id: TypeId) -> Self {
        Self::Struct(Rc::new(RefCell::new(RuntimeStructValue {
            type_id,
            fields: Vec::new(),
        })))
    }

    /// Construct a struct container with the given type id and
    /// fields. Used by `Bytecode::Pack` after popping field values
    /// off the operand stack.
    #[must_use]
    pub fn from_struct(type_id: TypeId, fields: Vec<RuntimeValue>) -> Self {
        Self::Struct(Rc::new(RefCell::new(RuntimeStructValue {
            type_id,
            fields,
        })))
    }

    /// Construct a variant container with the given type id, tag,
    /// and fields. Used by `Bytecode::PackVariant` after popping
    /// field values off the operand stack.
    #[must_use]
    pub fn from_variant(type_id: TypeId, variant_tag: u16, fields: Vec<RuntimeValue>) -> Self {
        Self::Variant(Rc::new(RefCell::new(RuntimeVariantValue {
            type_id,
            variant_tag,
            fields,
        })))
    }

    /// Construct a vector container from a vector of runtime values.
    /// Used by `Bytecode::VecPack`.
    #[must_use]
    pub fn from_vec(elements: Vec<RuntimeValue>) -> Self {
        Self::Vector(Rc::new(RefCell::new(elements)))
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
#[allow(
    clippy::manual_let_else,
    clippy::doc_markdown,
    reason = "test fixture patterns + verbatim spec quotes; same posture as Phase 5/6.2b interpreter.rs::tests"
)]
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

    /// Vector-element reference read/write round-trip via
    /// Reference::Indexed.
    #[test]
    fn vector_element_ref_round_trip() {
        let rc = Rc::new(RefCell::new(vec![
            RuntimeValue::U64(1),
            RuntimeValue::U64(2),
            RuntimeValue::U64(3),
        ]));
        let r = Reference::Indexed {
            container: Container::Vector(Rc::clone(&rc)),
            idx: 1,
        };
        assert_eq!(r.read_ref().expect("ok"), RuntimeValue::U64(2));
        r.write_ref(RuntimeValue::U64(99)).expect("ok");
        assert_eq!(rc.borrow()[1], RuntimeValue::U64(99));
    }

    /// Struct-field reference read/write round-trip via
    /// Reference::Indexed.
    #[test]
    fn struct_field_ref_round_trip() {
        let rc = Rc::new(RefCell::new(RuntimeStructValue {
            type_id: TypeId::from_bytes([0x33; 32]),
            fields: vec![RuntimeValue::U64(7), RuntimeValue::Bool(true)],
        }));
        let r = Reference::Indexed {
            container: Container::Struct(Rc::clone(&rc)),
            idx: 0,
        };
        assert_eq!(r.read_ref().expect("ok"), RuntimeValue::U64(7));
        r.write_ref(RuntimeValue::U64(99)).expect("ok");
        assert_eq!(rc.borrow().fields[0], RuntimeValue::U64(99));
    }

    // ---------- Composed-borrow tests (5/6.2c.1.b foundation correction) ----------

    /// Whitepaper §6.2.1.4 (verbatim): "Load a mutable reference
    /// to a struct field." Composed-borrow case: `&mut s.f1.f2`
    /// where `f1` is itself a struct field.
    ///
    /// At from_value time, nested struct fields become
    /// RuntimeValue::Container variants with their own Rc-RefCell
    /// wrappers. borrow_field on a Reference::Container struct
    /// where the field is itself a container returns
    /// Reference::Container(inner_container) — enabling
    /// composed access to deeply-nested fields.
    #[test]
    fn composed_borrow_struct_in_struct_round_trip() {
        // Construct: outer = { inner: { value: 7 } }
        let original = Value::Struct(StructValue {
            type_id: TypeId::from_bytes([0x01; 32]),
            fields: vec![Value::Struct(StructValue {
                type_id: TypeId::from_bytes([0x02; 32]),
                fields: vec![Value::U64(7)],
            })],
        });
        let runtime = RuntimeValue::from_value(original.clone());
        // Outer container.
        let outer_c = match runtime {
            RuntimeValue::Container(ref c) => c.clone(),
            _ => panic!("expected container"),
        };
        let outer_ref = Reference::Container(outer_c);
        // Borrow outer.fields[0] — that's the inner struct.
        let inner_ref = outer_ref.borrow_field(0).expect("ok");
        // Borrow inner.fields[0] — that's the U64 primitive.
        let value_ref = inner_ref.borrow_field(0).expect("ok");
        // Read the primitive.
        assert_eq!(value_ref.read_ref().expect("ok"), RuntimeValue::U64(7));
        // Write through the composed reference.
        value_ref.write_ref(RuntimeValue::U64(99)).expect("ok");
        // Round-trip back to BCS Value and verify the inner
        // primitive was updated through the composed-reference
        // chain.
        let post = runtime.to_value().expect("no refs");
        let expected_post = Value::Struct(StructValue {
            type_id: TypeId::from_bytes([0x01; 32]),
            fields: vec![Value::Struct(StructValue {
                type_id: TypeId::from_bytes([0x02; 32]),
                fields: vec![Value::U64(99)],
            })],
        });
        assert_eq!(post, expected_post);
    }

    /// Composed borrow into a vector of vectors: `&mut v[0][1]`.
    #[test]
    fn composed_borrow_vector_in_vector_round_trip() {
        let original = Value::Vector(vec![
            Value::Vector(vec![Value::U64(10), Value::U64(20), Value::U64(30)]),
            Value::Vector(vec![Value::U64(40), Value::U64(50)]),
        ]);
        let runtime = RuntimeValue::from_value(original.clone());
        let outer_c = match runtime {
            RuntimeValue::Container(ref c) => c.clone(),
            _ => panic!("expected container"),
        };
        let outer_ref = Reference::Container(outer_c);
        // Borrow outer[0] — that's the inner vector.
        let inner_ref = outer_ref.borrow_element(0).expect("ok");
        // Borrow inner[1] — that's the U64 primitive (value 20).
        let value_ref = inner_ref.borrow_element(1).expect("ok");
        assert_eq!(value_ref.read_ref().expect("ok"), RuntimeValue::U64(20));
        // Write through the composed reference.
        value_ref.write_ref(RuntimeValue::U64(99)).expect("ok");
        // Round-trip back.
        let post = runtime.to_value().expect("no refs");
        let expected_post = Value::Vector(vec![
            Value::Vector(vec![Value::U64(10), Value::U64(99), Value::U64(30)]),
            Value::Vector(vec![Value::U64(40), Value::U64(50)]),
        ]);
        assert_eq!(post, expected_post);
    }

    /// borrow_field on Reference::Container where field is
    /// itself a container returns Reference::Container.
    #[test]
    fn borrow_field_returns_container_for_container_field() {
        let original = Value::Struct(StructValue {
            type_id: TypeId::from_bytes([0x01; 32]),
            fields: vec![Value::Struct(StructValue {
                type_id: TypeId::from_bytes([0x02; 32]),
                fields: vec![Value::U64(7)],
            })],
        });
        let runtime = RuntimeValue::from_value(original);
        let outer_c = match runtime {
            RuntimeValue::Container(c) => c,
            _ => panic!("expected container"),
        };
        let outer_ref = Reference::Container(outer_c);
        let inner_ref = outer_ref.borrow_field(0).expect("ok");
        assert!(matches!(inner_ref, Reference::Container(_)));
    }

    /// borrow_field on Reference::Container where field is
    /// primitive returns Reference::Indexed.
    #[test]
    fn borrow_field_returns_indexed_for_primitive_field() {
        let original = Value::Struct(StructValue {
            type_id: TypeId::from_bytes([0x01; 32]),
            fields: vec![Value::U64(42)],
        });
        let runtime = RuntimeValue::from_value(original);
        let outer_c = match runtime {
            RuntimeValue::Container(c) => c,
            _ => panic!("expected container"),
        };
        let outer_ref = Reference::Container(outer_c);
        let field_ref = outer_ref.borrow_field(0).expect("ok");
        assert!(matches!(field_ref, Reference::Indexed { .. }));
        assert_eq!(field_ref.read_ref().expect("ok"), RuntimeValue::U64(42));
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
