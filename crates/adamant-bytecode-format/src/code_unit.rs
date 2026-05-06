//! `CodeUnit` and `FunctionDefinition`.
//!
//! Forked from `move-binary-format/src/file_format.rs` at Sui-Move
//! tag `mainnet-v1.66.2`. See `PROVENANCE.md`. Byte-identity with
//! upstream is asserted by `tests/cross_validation.rs`.
//!
//! These two types are the inherited-Sui-base shape for a
//! function body. Adamant extends them in `adamant-vm::module`
//! with [`AdamantCodeUnit`] (which holds
//! `Vec<BytecodeInstruction>` instead of `Vec<Bytecode>`) and
//! [`AdamantFunctionDefinition`] (which holds
//! `Option<AdamantCodeUnit>` instead of `Option<CodeUnit>`).
//! The pure-Sui-base shape lives here because the
//! cross-validation layer (Phase 5/5b.6) constructs it directly
//! to compare against Sui's vendored types.
//!
//! [`AdamantCodeUnit`]: https://example.invalid
//! [`AdamantFunctionDefinition`]: https://example.invalid

use serde::{Deserialize, Serialize};

use crate::bytecode::Bytecode;
use crate::definition::Visibility;
use crate::handle::VariantJumpTable;
use crate::index::{FunctionHandleIndex, SignatureIndex, StructDefinitionIndex};

/// A function body: its locals signature, instruction stream,
/// and jump tables.
///
/// Branch targets in `Branch`/`BrTrue`/`BrFalse` are positional
/// `CodeOffset`s into [`Self::code`]; `VariantSwitch` jump-table
/// entries are likewise positional.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct CodeUnit {
    /// Index into the module's signature pool of this function's
    /// local-variable type list (parameters followed by locals).
    pub locals: SignatureIndex,
    /// The instruction stream — the function body.
    pub code: Vec<Bytecode>,
    /// Jump tables for `VariantSwitch` instructions.
    pub jump_tables: Vec<VariantJumpTable>,
}

/// A function definition: prototype + visibility + body.
///
/// `code: None` indicates a native function — Sui-Move's
/// marker. Per whitepaper §6.2.1.6 Rule 4, native functions are
/// rejected at deployment for Adamant modules; the field's
/// `Option` shape exists so the validator can detect and reject
/// them, not because Adamant supports them.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct FunctionDefinition {
    /// The prototype of the function (module, name, signature).
    pub function: FunctionHandleIndex,
    /// The visibility of this function.
    pub visibility: Visibility,
    /// Whether this function is an entry point.
    pub is_entry: bool,
    /// List of locally defined types this function might
    /// `acquire` from global storage. Always empty in valid
    /// Adamant modules per whitepaper §6.2.1.6 Rule 5;
    /// preserved structurally for byte-faithful parsing.
    pub acquires_global_resources: Vec<StructDefinitionIndex>,
    /// Code for this function. `None` indicates a native
    /// function; whitepaper §6.2.1.6 Rule 4 forbids native
    /// functions in deployable Adamant modules.
    pub code: Option<CodeUnit>,
}

impl FunctionDefinition {
    /// Returns `true` if this is a native function (i.e.,
    /// [`Self::code`] is `None`). Whitepaper §6.2.1.6 Rule 4
    /// forbids `is_native() == true` in any deployable Adamant
    /// module.
    #[must_use]
    pub fn is_native(&self) -> bool {
        self.code.is_none()
    }

    /// Deprecated public-bit constant: preserved for
    /// byte-faithful parity with upstream's serializer.
    pub const DEPRECATED_PUBLIC_BIT: u8 = 0b01;

    /// Native-function flag bit: preserved for byte-faithful
    /// parity. The validator (whitepaper §6.2.1.6 Rule 4)
    /// rejects modules with any function definition carrying
    /// this bit.
    pub const NATIVE: u8 = 0b10;

    /// Entry-function flag bit.
    pub const ENTRY: u8 = 0b100;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `CodeUnit::default` yields an empty body.
    #[test]
    fn code_unit_default_is_empty() {
        let cu = CodeUnit::default();
        assert_eq!(cu.locals, SignatureIndex::new(0));
        assert!(cu.code.is_empty());
        assert!(cu.jump_tables.is_empty());
    }

    /// `is_native` is `true` iff `code.is_none()`.
    #[test]
    fn is_native_iff_code_is_none() {
        let native = FunctionDefinition {
            function: FunctionHandleIndex::new(0),
            visibility: Visibility::Private,
            is_entry: false,
            acquires_global_resources: vec![],
            code: None,
        };
        assert!(native.is_native());

        let non_native = FunctionDefinition {
            code: Some(CodeUnit {
                locals: SignatureIndex::new(0),
                code: vec![Bytecode::Ret],
                jump_tables: vec![],
            }),
            ..native.clone()
        };
        assert!(!non_native.is_native());
    }

    /// `DEPRECATED_PUBLIC_BIT`, `NATIVE`, `ENTRY` constants
    /// are byte-pinned per upstream.
    #[test]
    fn flag_bits_pinned() {
        assert_eq!(FunctionDefinition::DEPRECATED_PUBLIC_BIT, 0b01);
        assert_eq!(FunctionDefinition::NATIVE, 0b10);
        assert_eq!(FunctionDefinition::ENTRY, 0b100);
    }
}
