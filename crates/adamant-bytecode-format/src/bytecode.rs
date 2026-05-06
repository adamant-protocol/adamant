//! `Bytecode` — the inherited Sui-Move instruction set.
//!
//! Forked from `move-binary-format/src/file_format.rs` and
//! `move-binary-format/src/file_format_common.rs` at Sui-Move
//! tag `mainnet-v1.66.2`. See `PROVENANCE.md`. Byte-identity
//! with upstream is asserted by `tests/cross_validation.rs`.
//!
//! This is the **inherited Sui-base** instruction set —
//! Adamant's `BytecodeInstruction::Inherited(Bytecode)` per
//! whitepaper §6.2.1.4. Adamant extensions live in
//! `adamant-vm::bytecode::AdamantBytecode`; the composite
//! `BytecodeInstruction` enum that flows through function
//! bodies is also in `adamant-vm`.
//!
//! # Adamant deviations
//!
//! - The upstream `impl move_abstract_interpreter::control_flow_graph::Instruction
//!   for Bytecode` impl is **not** forked. The
//!   `move_abstract_interpreter` crate is one of the 13
//!   vendored Sui crates that Phase 5/5b.5 will move to
//!   `[dev-dependencies]`. Adamant-native CFG infrastructure
//!   lands in Phase 5/5b.4 alongside the per-function-pass
//!   verifier; the inherent `Bytecode::get_successors` /
//!   `Bytecode::offsets` / `Bytecode::is_branch` methods are
//!   forked here so that downstream Adamant CFG infrastructure
//!   can build on them directly.
//! - Per-variant doc comments are condensed from upstream's
//!   prose form into Adamant's standard concise-doc style.
//!   The Stack-transition documentation upstream carries on
//!   most variants is not consensus-binding; whitepaper
//!   §6.2.1.4 is the binding spec for stack effects.

use core::fmt;

use serde::{Deserialize, Serialize};

use crate::format_common::Opcodes;
use crate::handle::VariantJumpTable;
use crate::index::{
    CodeOffset, ConstantPoolIndex, FieldHandleIndex, FieldInstantiationIndex, FunctionHandleIndex,
    FunctionInstantiationIndex, LocalIndex, SignatureIndex, StructDefInstantiationIndex,
    StructDefinitionIndex, VariantHandleIndex, VariantInstantiationHandleIndex,
    VariantJumpTableIndex,
};
use crate::u256::U256;

/// A VM instruction of variable size.
///
/// `Bytecode` operates on a stack machine. Each variant's stack
/// effect is specified by whitepaper §6.2.1.4; the inherited
/// subset's effects match Sui-Move's binary-format documentation
/// at vendor tag `mainnet-v1.66.2`.
#[derive(Clone, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub enum Bytecode {
    /// Pop the value at the top of the stack.
    Pop,
    /// Return from the function.
    Ret,
    /// Branch to `CodeOffset` if the top-of-stack value is `true`.
    BrTrue(CodeOffset),
    /// Branch to `CodeOffset` if the top-of-stack value is `false`.
    BrFalse(CodeOffset),
    /// Unconditional branch to `CodeOffset`.
    Branch(CodeOffset),
    /// Push a `u8` constant onto the stack.
    LdU8(u8),
    /// Push a `u64` constant onto the stack.
    LdU64(u64),
    /// Push a `u128` constant onto the stack.
    LdU128(Box<u128>),
    /// Convert top-of-stack to `u8`.
    CastU8,
    /// Convert top-of-stack to `u64`.
    CastU64,
    /// Convert top-of-stack to `u128`.
    CastU128,
    /// Push a `Constant` from the constant pool onto the stack.
    LdConst(ConstantPoolIndex),
    /// Push `true` onto the stack.
    LdTrue,
    /// Push `false` onto the stack.
    LdFalse,
    /// Copy the local at `LocalIndex` and push onto the stack.
    CopyLoc(LocalIndex),
    /// Move the local at `LocalIndex` and push onto the stack.
    MoveLoc(LocalIndex),
    /// Pop the stack top and store into the local at `LocalIndex`.
    StLoc(LocalIndex),
    /// Call the function at `FunctionHandleIndex`.
    Call(FunctionHandleIndex),
    /// Call the generic function at `FunctionInstantiationIndex`.
    CallGeneric(FunctionInstantiationIndex),
    /// Pack a struct value at `StructDefinitionIndex`.
    Pack(StructDefinitionIndex),
    /// Pack a generic struct at `StructDefInstantiationIndex`.
    PackGeneric(StructDefInstantiationIndex),
    /// Unpack a struct value at `StructDefinitionIndex`.
    Unpack(StructDefinitionIndex),
    /// Unpack a generic struct at `StructDefInstantiationIndex`.
    UnpackGeneric(StructDefInstantiationIndex),
    /// Read through a reference. The value's type must have
    /// `Copy`.
    ReadRef,
    /// Write through a reference. The previous value's type
    /// must have `Drop`.
    WriteRef,
    /// Convert a mutable reference to an immutable reference.
    FreezeRef,
    /// Load a mutable reference to a local.
    MutBorrowLoc(LocalIndex),
    /// Load an immutable reference to a local.
    ImmBorrowLoc(LocalIndex),
    /// Load a mutable reference to a struct field.
    MutBorrowField(FieldHandleIndex),
    /// Load a mutable reference to a generic struct's field.
    MutBorrowFieldGeneric(FieldInstantiationIndex),
    /// Load an immutable reference to a struct field.
    ImmBorrowField(FieldHandleIndex),
    /// Load an immutable reference to a generic struct's field.
    ImmBorrowFieldGeneric(FieldInstantiationIndex),
    /// Add the top two stack values.
    Add,
    /// Subtract the top two stack values.
    Sub,
    /// Multiply the top two stack values.
    Mul,
    /// Modulo the top two stack values.
    Mod,
    /// Divide the top two stack values.
    Div,
    /// Bitwise OR the top two stack values.
    BitOr,
    /// Bitwise AND the top two stack values.
    BitAnd,
    /// Bitwise XOR the top two stack values.
    Xor,
    /// Logical OR the top two stack values.
    Or,
    /// Logical AND the top two stack values.
    And,
    /// Logical NOT the top of stack.
    Not,
    /// Equality comparison.
    Eq,
    /// Inequality comparison.
    Neq,
    /// Less-than comparison.
    Lt,
    /// Greater-than comparison.
    Gt,
    /// Less-or-equal comparison.
    Le,
    /// Greater-or-equal comparison.
    Ge,
    /// Abort with an error code.
    Abort,
    /// No operation.
    Nop,
    /// Shift left.
    Shl,
    /// Shift right.
    Shr,
    /// Pack a vector of `n` elements at the given signature.
    VecPack(SignatureIndex, u64),
    /// Vector length.
    VecLen(SignatureIndex),
    /// Immutable borrow of a vector element.
    VecImmBorrow(SignatureIndex),
    /// Mutable borrow of a vector element.
    VecMutBorrow(SignatureIndex),
    /// Push to the back of a vector.
    VecPushBack(SignatureIndex),
    /// Pop from the back of a vector.
    VecPopBack(SignatureIndex),
    /// Unpack a vector of `n` elements onto the stack.
    VecUnpack(SignatureIndex, u64),
    /// Swap two elements in a vector.
    VecSwap(SignatureIndex),
    /// Push a `u16` constant.
    LdU16(u16),
    /// Push a `u32` constant.
    LdU32(u32),
    /// Push a `U256` constant.
    LdU256(Box<U256>),
    /// Convert top-of-stack to `u16`.
    CastU16,
    /// Convert top-of-stack to `u32`.
    CastU32,
    /// Convert top-of-stack to `U256`.
    CastU256,
    /// Pack an enum variant.
    PackVariant(VariantHandleIndex),
    /// Pack a generic-instantiated enum variant.
    PackVariantGeneric(VariantInstantiationHandleIndex),
    /// Unpack an enum variant onto the stack.
    UnpackVariant(VariantHandleIndex),
    /// Unpack an enum variant by immutable reference.
    UnpackVariantImmRef(VariantHandleIndex),
    /// Unpack an enum variant by mutable reference.
    UnpackVariantMutRef(VariantHandleIndex),
    /// Unpack a generic-instantiated enum variant.
    UnpackVariantGeneric(VariantInstantiationHandleIndex),
    /// Unpack a generic-instantiated variant by immutable reference.
    UnpackVariantGenericImmRef(VariantInstantiationHandleIndex),
    /// Unpack a generic-instantiated variant by mutable reference.
    UnpackVariantGenericMutRef(VariantInstantiationHandleIndex),
    /// Branch on the variant tag of an enum reference.
    VariantSwitch(VariantJumpTableIndex),
    // ******** DEPRECATED BYTECODES ********
    // Per whitepaper §6.2.1.6 Rule 5 (no global storage
    // instructions), modules whose bytecode contains any of the
    // following are rejected at deployment time. The variants
    // are forked here for byte-faithful parsing of upstream
    // binary-format inputs that may carry them.
    /// Deprecated `Exists` global-storage operation. Rejected
    /// by whitepaper §6.2.1.6 Rule 5 at deployment.
    ExistsDeprecated(StructDefinitionIndex),
    /// Deprecated generic `Exists` global-storage operation.
    ExistsGenericDeprecated(StructDefInstantiationIndex),
    /// Deprecated `MoveFrom` global-storage operation.
    MoveFromDeprecated(StructDefinitionIndex),
    /// Deprecated generic `MoveFrom`.
    MoveFromGenericDeprecated(StructDefInstantiationIndex),
    /// Deprecated `MoveTo` global-storage operation.
    MoveToDeprecated(StructDefinitionIndex),
    /// Deprecated generic `MoveTo`.
    MoveToGenericDeprecated(StructDefInstantiationIndex),
    /// Deprecated `MutBorrowGlobal` global-storage operation.
    MutBorrowGlobalDeprecated(StructDefinitionIndex),
    /// Deprecated generic `MutBorrowGlobal`.
    MutBorrowGlobalGenericDeprecated(StructDefInstantiationIndex),
    /// Deprecated `ImmBorrowGlobal` global-storage operation.
    ImmBorrowGlobalDeprecated(StructDefinitionIndex),
    /// Deprecated generic `ImmBorrowGlobal`.
    ImmBorrowGlobalGenericDeprecated(StructDefInstantiationIndex),
}

impl fmt::Debug for Bytecode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pop => write!(f, "Pop"),
            Self::Ret => write!(f, "Ret"),
            Self::BrTrue(a) => write!(f, "BrTrue({a})"),
            Self::BrFalse(a) => write!(f, "BrFalse({a})"),
            Self::Branch(a) => write!(f, "Branch({a})"),
            Self::LdU8(a) => write!(f, "LdU8({a})"),
            Self::LdU16(a) => write!(f, "LdU16({a})"),
            Self::LdU32(a) => write!(f, "LdU32({a})"),
            Self::LdU64(a) => write!(f, "LdU64({a})"),
            Self::LdU128(a) => write!(f, "LdU128({a})"),
            Self::LdU256(a) => write!(f, "LdU256({a:?})"),
            Self::CastU8 => write!(f, "CastU8"),
            Self::CastU16 => write!(f, "CastU16"),
            Self::CastU32 => write!(f, "CastU32"),
            Self::CastU64 => write!(f, "CastU64"),
            Self::CastU128 => write!(f, "CastU128"),
            Self::CastU256 => write!(f, "CastU256"),
            Self::LdConst(a) => write!(f, "LdConst({a})"),
            Self::LdTrue => write!(f, "LdTrue"),
            Self::LdFalse => write!(f, "LdFalse"),
            Self::CopyLoc(a) => write!(f, "CopyLoc({a})"),
            Self::MoveLoc(a) => write!(f, "MoveLoc({a})"),
            Self::StLoc(a) => write!(f, "StLoc({a})"),
            Self::Call(a) => write!(f, "Call({a})"),
            Self::CallGeneric(a) => write!(f, "CallGeneric({a})"),
            Self::Pack(a) => write!(f, "Pack({a})"),
            Self::PackGeneric(a) => write!(f, "PackGeneric({a})"),
            Self::Unpack(a) => write!(f, "Unpack({a})"),
            Self::UnpackGeneric(a) => write!(f, "UnpackGeneric({a})"),
            Self::ReadRef => write!(f, "ReadRef"),
            Self::WriteRef => write!(f, "WriteRef"),
            Self::FreezeRef => write!(f, "FreezeRef"),
            Self::MutBorrowLoc(a) => write!(f, "MutBorrowLoc({a})"),
            Self::ImmBorrowLoc(a) => write!(f, "ImmBorrowLoc({a})"),
            Self::MutBorrowField(a) => write!(f, "MutBorrowField({a:?})"),
            Self::MutBorrowFieldGeneric(a) => write!(f, "MutBorrowFieldGeneric({a:?})"),
            Self::ImmBorrowField(a) => write!(f, "ImmBorrowField({a:?})"),
            Self::ImmBorrowFieldGeneric(a) => write!(f, "ImmBorrowFieldGeneric({a:?})"),
            Self::MutBorrowGlobalDeprecated(a) => write!(f, "MutBorrowGlobal({a:?})"),
            Self::MutBorrowGlobalGenericDeprecated(a) => {
                write!(f, "MutBorrowGlobalGeneric({a:?})")
            }
            Self::ImmBorrowGlobalDeprecated(a) => write!(f, "ImmBorrowGlobal({a:?})"),
            Self::ImmBorrowGlobalGenericDeprecated(a) => {
                write!(f, "ImmBorrowGlobalGeneric({a:?})")
            }
            Self::Add => write!(f, "Add"),
            Self::Sub => write!(f, "Sub"),
            Self::Mul => write!(f, "Mul"),
            Self::Mod => write!(f, "Mod"),
            Self::Div => write!(f, "Div"),
            Self::BitOr => write!(f, "BitOr"),
            Self::BitAnd => write!(f, "BitAnd"),
            Self::Xor => write!(f, "Xor"),
            Self::Shl => write!(f, "Shl"),
            Self::Shr => write!(f, "Shr"),
            Self::Or => write!(f, "Or"),
            Self::And => write!(f, "And"),
            Self::Not => write!(f, "Not"),
            Self::Eq => write!(f, "Eq"),
            Self::Neq => write!(f, "Neq"),
            Self::Lt => write!(f, "Lt"),
            Self::Gt => write!(f, "Gt"),
            Self::Le => write!(f, "Le"),
            Self::Ge => write!(f, "Ge"),
            Self::Abort => write!(f, "Abort"),
            Self::Nop => write!(f, "Nop"),
            Self::ExistsDeprecated(a) => write!(f, "Exists({a:?})"),
            Self::ExistsGenericDeprecated(a) => write!(f, "ExistsGeneric({a:?})"),
            Self::MoveFromDeprecated(a) => write!(f, "MoveFrom({a:?})"),
            Self::MoveFromGenericDeprecated(a) => write!(f, "MoveFromGeneric({a:?})"),
            Self::MoveToDeprecated(a) => write!(f, "MoveTo({a:?})"),
            Self::MoveToGenericDeprecated(a) => write!(f, "MoveToGeneric({a:?})"),
            Self::VecPack(a, n) => write!(f, "VecPack({a}, {n})"),
            Self::VecLen(a) => write!(f, "VecLen({a})"),
            Self::VecImmBorrow(a) => write!(f, "VecImmBorrow({a})"),
            Self::VecMutBorrow(a) => write!(f, "VecMutBorrow({a})"),
            Self::VecPushBack(a) => write!(f, "VecPushBack({a})"),
            Self::VecPopBack(a) => write!(f, "VecPopBack({a})"),
            Self::VecUnpack(a, n) => write!(f, "VecUnpack({a}, {n})"),
            Self::VecSwap(a) => write!(f, "VecSwap({a})"),
            Self::PackVariant(handle) => write!(f, "PackVariant({handle:?})"),
            Self::PackVariantGeneric(handle) => write!(f, "PackVariantGeneric({handle:?})"),
            Self::UnpackVariant(handle) => write!(f, "UnpackVariant({handle:?})"),
            Self::UnpackVariantGeneric(handle) => write!(f, "UnpackVariantGeneric({handle:?})"),
            Self::UnpackVariantImmRef(handle) => write!(f, "UnpackVariantImmRef({handle:?})"),
            Self::UnpackVariantGenericImmRef(handle) => {
                write!(f, "UnpackVariantGenericImmRef({handle:?})")
            }
            Self::UnpackVariantMutRef(handle) => write!(f, "UnpackVariantMutRef({handle:?})"),
            Self::UnpackVariantGenericMutRef(handle) => {
                write!(f, "UnpackVariantGenericMutRef({handle:?})")
            }
            Self::VariantSwitch(jt) => write!(f, "VariantSwitch({jt:?})"),
        }
    }
}

impl Bytecode {
    /// Returns `true` if this instruction always branches.
    /// `Ret`, `Abort`, `Branch`, and `VariantSwitch` are
    /// unconditional branches; everything else returns `false`.
    /// `BrTrue`/`BrFalse` are *conditional* branches and return
    /// `false` here (use [`Self::is_conditional_branch`] for those).
    #[must_use]
    pub fn is_unconditional_branch(&self) -> bool {
        matches!(
            self,
            Self::Ret | Self::Abort | Self::Branch(_) | Self::VariantSwitch(_)
        )
    }

    /// Returns `true` if this instruction's branching depends on
    /// a runtime value: `BrTrue` and `BrFalse`. `VariantSwitch`
    /// is exhaustive and therefore unconditional, not
    /// conditional.
    #[must_use]
    pub fn is_conditional_branch(&self) -> bool {
        matches!(self, Self::BrFalse(_) | Self::BrTrue(_))
    }

    /// Returns `true` if this instruction is either a
    /// conditional or an unconditional branch.
    #[must_use]
    pub fn is_branch(&self) -> bool {
        self.is_conditional_branch() || self.is_unconditional_branch()
    }

    /// Returns the offsets this instruction can branch to. For
    /// `BrTrue`/`BrFalse`/`Branch`, returns the single explicit
    /// offset. For `VariantSwitch`, returns every offset in the
    /// referenced jump table. For `Ret`/`Abort`, returns an
    /// empty vec (they branch out of the function, not within
    /// it). For non-branching instructions, returns an empty vec.
    ///
    /// # Panics
    ///
    /// Panics if a `VariantSwitch`'s jump-table index is out of
    /// bounds. The bounds checker is expected to have run prior
    /// to calling this; bounds-checked inputs do not trigger
    /// the panic.
    #[must_use]
    pub fn offsets(&self, jump_tables: &[VariantJumpTable]) -> Vec<CodeOffset> {
        match self {
            Self::BrFalse(offset) | Self::BrTrue(offset) | Self::Branch(offset) => vec![*offset],
            Self::VariantSwitch(jt_idx) => {
                assert!(
                    (jt_idx.0 as usize) < jump_tables.len(),
                    "Jump table index out of bounds"
                );
                let crate::handle::JumpTableInner::Full(offsets) =
                    &jump_tables[jt_idx.0 as usize].jump_table;
                offsets.clone()
            }
            // Everything else (including `Ret`/`Abort`, which
            // branch out of the function, and non-branching
            // instructions) emits no in-function offsets.
            _ => vec![],
        }
    }

    /// Returns the successor PCs of this instruction in
    /// ascending order. Includes the explicit branch offsets
    /// from [`Self::offsets`] plus the fall-through PC (`pc+1`)
    /// when this instruction is not an unconditional branch
    /// and the next PC is in range.
    ///
    /// # Panics
    ///
    /// Panics if `pc` is out of bounds for `code`. Mirrors
    /// upstream's invariant.
    #[must_use]
    pub fn get_successors(
        pc: CodeOffset,
        code: &[Self],
        jump_tables: &[VariantJumpTable],
    ) -> Vec<CodeOffset> {
        assert!(
            pc < u16::MAX && (pc as usize) < code.len(),
            "Program counter out of bounds"
        );
        let bytecode = &code[pc as usize];
        let mut v = vec![];
        v.extend(bytecode.offsets(jump_tables));
        let next_pc = pc + 1;
        if (next_pc as usize) >= code.len() {
            return v;
        }
        if !bytecode.is_unconditional_branch() && !v.contains(&next_pc) {
            v.push(pc + 1);
        }
        v.sort_unstable();
        v
    }
}

// ============================================================================
// instruction_opcode + instruction_key (deferred from Phase 5/5b.1a)
// ============================================================================

/// The opcode tag for an instruction (disregards arguments).
///
/// Maps each [`Bytecode`] variant to its [`Opcodes`] tag. The
/// mapping is consensus-binding: changing any tag is a hard
/// fork (whitepaper §6.2.1.4 "the complete instruction set —
/// inherited and extension — is genesis-fixed").
#[must_use]
pub fn instruction_opcode(instruction: &Bytecode) -> Opcodes {
    match instruction {
        Bytecode::Pop => Opcodes::POP,
        Bytecode::Ret => Opcodes::RET,
        Bytecode::BrTrue(_) => Opcodes::BR_TRUE,
        Bytecode::BrFalse(_) => Opcodes::BR_FALSE,
        Bytecode::Branch(_) => Opcodes::BRANCH,
        Bytecode::LdU8(_) => Opcodes::LD_U8,
        Bytecode::LdU64(_) => Opcodes::LD_U64,
        Bytecode::LdU128(_) => Opcodes::LD_U128,
        Bytecode::CastU8 => Opcodes::CAST_U8,
        Bytecode::CastU64 => Opcodes::CAST_U64,
        Bytecode::CastU128 => Opcodes::CAST_U128,
        Bytecode::LdConst(_) => Opcodes::LD_CONST,
        Bytecode::LdTrue => Opcodes::LD_TRUE,
        Bytecode::LdFalse => Opcodes::LD_FALSE,
        Bytecode::CopyLoc(_) => Opcodes::COPY_LOC,
        Bytecode::MoveLoc(_) => Opcodes::MOVE_LOC,
        Bytecode::StLoc(_) => Opcodes::ST_LOC,
        Bytecode::Call(_) => Opcodes::CALL,
        Bytecode::CallGeneric(_) => Opcodes::CALL_GENERIC,
        Bytecode::Pack(_) => Opcodes::PACK,
        Bytecode::PackGeneric(_) => Opcodes::PACK_GENERIC,
        Bytecode::Unpack(_) => Opcodes::UNPACK,
        Bytecode::UnpackGeneric(_) => Opcodes::UNPACK_GENERIC,
        Bytecode::ReadRef => Opcodes::READ_REF,
        Bytecode::WriteRef => Opcodes::WRITE_REF,
        Bytecode::FreezeRef => Opcodes::FREEZE_REF,
        Bytecode::MutBorrowLoc(_) => Opcodes::MUT_BORROW_LOC,
        Bytecode::ImmBorrowLoc(_) => Opcodes::IMM_BORROW_LOC,
        Bytecode::MutBorrowField(_) => Opcodes::MUT_BORROW_FIELD,
        Bytecode::MutBorrowFieldGeneric(_) => Opcodes::MUT_BORROW_FIELD_GENERIC,
        Bytecode::ImmBorrowField(_) => Opcodes::IMM_BORROW_FIELD,
        Bytecode::ImmBorrowFieldGeneric(_) => Opcodes::IMM_BORROW_FIELD_GENERIC,
        Bytecode::Add => Opcodes::ADD,
        Bytecode::Sub => Opcodes::SUB,
        Bytecode::Mul => Opcodes::MUL,
        Bytecode::Mod => Opcodes::MOD,
        Bytecode::Div => Opcodes::DIV,
        Bytecode::BitOr => Opcodes::BIT_OR,
        Bytecode::BitAnd => Opcodes::BIT_AND,
        Bytecode::Xor => Opcodes::XOR,
        Bytecode::Shl => Opcodes::SHL,
        Bytecode::Shr => Opcodes::SHR,
        Bytecode::Or => Opcodes::OR,
        Bytecode::And => Opcodes::AND,
        Bytecode::Not => Opcodes::NOT,
        Bytecode::Eq => Opcodes::EQ,
        Bytecode::Neq => Opcodes::NEQ,
        Bytecode::Lt => Opcodes::LT,
        Bytecode::Gt => Opcodes::GT,
        Bytecode::Le => Opcodes::LE,
        Bytecode::Ge => Opcodes::GE,
        Bytecode::Abort => Opcodes::ABORT,
        Bytecode::Nop => Opcodes::NOP,
        Bytecode::VecPack(..) => Opcodes::VEC_PACK,
        Bytecode::VecLen(_) => Opcodes::VEC_LEN,
        Bytecode::VecImmBorrow(_) => Opcodes::VEC_IMM_BORROW,
        Bytecode::VecMutBorrow(_) => Opcodes::VEC_MUT_BORROW,
        Bytecode::VecPushBack(_) => Opcodes::VEC_PUSH_BACK,
        Bytecode::VecPopBack(_) => Opcodes::VEC_POP_BACK,
        Bytecode::VecUnpack(..) => Opcodes::VEC_UNPACK,
        Bytecode::VecSwap(_) => Opcodes::VEC_SWAP,
        Bytecode::LdU16(_) => Opcodes::LD_U16,
        Bytecode::LdU32(_) => Opcodes::LD_U32,
        Bytecode::LdU256(_) => Opcodes::LD_U256,
        Bytecode::CastU16 => Opcodes::CAST_U16,
        Bytecode::CastU32 => Opcodes::CAST_U32,
        Bytecode::CastU256 => Opcodes::CAST_U256,
        Bytecode::PackVariant(_) => Opcodes::PACK_VARIANT,
        Bytecode::PackVariantGeneric(_) => Opcodes::PACK_VARIANT_GENERIC,
        Bytecode::UnpackVariant(_) => Opcodes::UNPACK_VARIANT,
        Bytecode::UnpackVariantImmRef(_) => Opcodes::UNPACK_VARIANT_IMM_REF,
        Bytecode::UnpackVariantMutRef(_) => Opcodes::UNPACK_VARIANT_MUT_REF,
        Bytecode::UnpackVariantGeneric(_) => Opcodes::UNPACK_VARIANT_GENERIC,
        Bytecode::UnpackVariantGenericImmRef(_) => Opcodes::UNPACK_VARIANT_GENERIC_IMM_REF,
        Bytecode::UnpackVariantGenericMutRef(_) => Opcodes::UNPACK_VARIANT_GENERIC_MUT_REF,
        Bytecode::VariantSwitch(_) => Opcodes::VARIANT_SWITCH,
        // Deprecated bytecodes (retained for byte-faithful
        // parsing; rejected at deployment per §6.2.1.6 Rule 5).
        Bytecode::ExistsDeprecated(_) => Opcodes::EXISTS_DEPRECATED,
        Bytecode::ExistsGenericDeprecated(_) => Opcodes::EXISTS_GENERIC_DEPRECATED,
        Bytecode::MoveFromDeprecated(_) => Opcodes::MOVE_FROM_DEPRECATED,
        Bytecode::MoveFromGenericDeprecated(_) => Opcodes::MOVE_FROM_GENERIC_DEPRECATED,
        Bytecode::MoveToDeprecated(_) => Opcodes::MOVE_TO_DEPRECATED,
        Bytecode::MoveToGenericDeprecated(_) => Opcodes::MOVE_TO_GENERIC_DEPRECATED,
        Bytecode::MutBorrowGlobalDeprecated(_) => Opcodes::MUT_BORROW_GLOBAL_DEPRECATED,
        Bytecode::MutBorrowGlobalGenericDeprecated(_) => {
            Opcodes::MUT_BORROW_GLOBAL_GENERIC_DEPRECATED
        }
        Bytecode::ImmBorrowGlobalDeprecated(_) => Opcodes::IMM_BORROW_GLOBAL_DEPRECATED,
        Bytecode::ImmBorrowGlobalGenericDeprecated(_) => {
            Opcodes::IMM_BORROW_GLOBAL_GENERIC_DEPRECATED
        }
    }
}

/// The encoding-key byte for an instruction: the opcode discriminant.
#[must_use]
pub fn instruction_key(instruction: &Bytecode) -> u8 {
    instruction_opcode(instruction) as u8
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handle::{JumpTableInner, VariantJumpTable};
    use crate::index::EnumDefinitionIndex;

    /// `is_unconditional_branch` covers `Ret`, `Abort`,
    /// `Branch`, `VariantSwitch`. `BrTrue`/`BrFalse` are
    /// conditional and not unconditional.
    #[test]
    fn unconditional_branch_set_pinned() {
        assert!(Bytecode::Ret.is_unconditional_branch());
        assert!(Bytecode::Abort.is_unconditional_branch());
        assert!(Bytecode::Branch(0).is_unconditional_branch());
        assert!(Bytecode::VariantSwitch(VariantJumpTableIndex::new(0)).is_unconditional_branch());
        assert!(!Bytecode::BrTrue(0).is_unconditional_branch());
        assert!(!Bytecode::BrFalse(0).is_unconditional_branch());
        assert!(!Bytecode::Pop.is_unconditional_branch());
    }

    /// `is_conditional_branch` covers exactly `BrTrue` and
    /// `BrFalse`. `VariantSwitch` is exhaustive (unconditional).
    #[test]
    fn conditional_branch_set_pinned() {
        assert!(Bytecode::BrTrue(0).is_conditional_branch());
        assert!(Bytecode::BrFalse(0).is_conditional_branch());
        assert!(!Bytecode::Branch(0).is_conditional_branch());
        assert!(!Bytecode::VariantSwitch(VariantJumpTableIndex::new(0)).is_conditional_branch());
        assert!(!Bytecode::Ret.is_conditional_branch());
    }

    /// `offsets` returns the explicit offset for direct branches.
    #[test]
    fn offsets_for_direct_branches() {
        assert_eq!(Bytecode::Branch(7).offsets(&[]), vec![7]);
        assert_eq!(Bytecode::BrTrue(3).offsets(&[]), vec![3]);
        assert_eq!(Bytecode::BrFalse(5).offsets(&[]), vec![5]);
    }

    /// `offsets` for `Ret`/`Abort` is empty (out-of-function
    /// branches).
    #[test]
    fn offsets_for_ret_and_abort_are_empty() {
        assert_eq!(Bytecode::Ret.offsets(&[]), Vec::<CodeOffset>::new());
        assert_eq!(Bytecode::Abort.offsets(&[]), Vec::<CodeOffset>::new());
    }

    /// `offsets` for non-branching instructions is empty.
    #[test]
    fn offsets_for_non_branching() {
        assert_eq!(Bytecode::Pop.offsets(&[]), Vec::<CodeOffset>::new());
        assert_eq!(Bytecode::LdU64(42).offsets(&[]), Vec::<CodeOffset>::new());
    }

    /// `offsets` for `VariantSwitch` resolves the jump table.
    #[test]
    fn offsets_for_variant_switch_resolves_jump_table() {
        let jt = VariantJumpTable {
            head_enum: EnumDefinitionIndex::new(0),
            jump_table: JumpTableInner::Full(vec![10, 20, 30]),
        };
        let offsets = Bytecode::VariantSwitch(VariantJumpTableIndex::new(0)).offsets(&[jt]);
        assert_eq!(offsets, vec![10, 20, 30]);
    }

    /// `get_successors` includes fall-through plus the branch
    /// offset for `BrTrue`. Sorted ascending; deduplicated.
    #[test]
    fn get_successors_includes_fallthrough_and_branch() {
        let code = vec![Bytecode::BrTrue(2), Bytecode::Pop, Bytecode::Ret];
        let succ = Bytecode::get_successors(0, &code, &[]);
        assert_eq!(succ, vec![1, 2]);
    }

    /// `get_successors` for `Ret` returns only the explicit
    /// offsets (none) and skips fall-through.
    #[test]
    fn get_successors_for_ret_skips_fallthrough() {
        let code = vec![Bytecode::Ret, Bytecode::Pop];
        let succ = Bytecode::get_successors(0, &code, &[]);
        assert_eq!(succ, Vec::<CodeOffset>::new());
    }

    /// `instruction_key` returns the underlying opcode byte.
    #[test]
    fn instruction_key_is_opcode_byte() {
        assert_eq!(instruction_key(&Bytecode::Pop), Opcodes::POP as u8);
        assert_eq!(instruction_key(&Bytecode::Ret), Opcodes::RET as u8);
        assert_eq!(instruction_key(&Bytecode::Add), Opcodes::ADD as u8);
    }

    /// `instruction_opcode` is the same regardless of operand
    /// payload — `Pack(0)` and `Pack(99)` both map to `PACK`.
    #[test]
    fn instruction_opcode_disregards_operand() {
        let a = Bytecode::Pack(StructDefinitionIndex::new(0));
        let b = Bytecode::Pack(StructDefinitionIndex::new(99));
        assert_eq!(instruction_opcode(&a), instruction_opcode(&b));
    }

    /// `Debug` for a `Bytecode::LdU64(42)` produces the
    /// upstream-matching `LdU64(42)` shape.
    #[test]
    fn debug_format_for_ldu64() {
        assert_eq!(format!("{:?}", Bytecode::LdU64(42)), "LdU64(42)");
    }

    /// `Debug` for the deprecated variants strips the
    /// `Deprecated` suffix to match upstream's display
    /// convention (debug output is for humans, not the wire).
    #[test]
    fn debug_format_strips_deprecated_suffix() {
        let s = format!(
            "{:?}",
            Bytecode::ExistsDeprecated(StructDefinitionIndex::new(0))
        );
        assert!(s.starts_with("Exists("), "got: {s}");
        assert!(!s.contains("Deprecated"), "got: {s}");
    }
}
