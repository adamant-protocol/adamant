//! Adamant module representation per whitepaper §6.2.1.8.
//!
//! [`AdamantCompiledModule`] is the in-memory representation of
//! a parsed Adamant module. It mirrors Sui-Move's
//! [`CompiledModule`][move_binary_format::file_format::CompiledModule]
//! shape — same module-level pools, same handle tables, same
//! per-function metadata — with one structural change: function
//! bodies hold the full Adamant instruction set
//! ([`BytecodeInstruction`], i.e., inherited Sui-Move opcodes
//! plus Adamant extensions per §6.2.1.4) rather than Sui-Move's
//! [`Bytecode`][move_binary_format::file_format::Bytecode] enum
//! alone.
//!
//! # Architecture
//!
//! Per the §6.2.1.8 re-amendment (commit `0de50d8`), Adamant's
//! deploy-time pipeline is fully Adamant-native: a conforming
//! implementation provides its own deserializer, serializer, and
//! verifier covering the full Adamant superset. Vendored Sui-Move
//! crates are a test-time reference implementation for the
//! inherited subset, not a deploy-time hot-path dependency.
//! [`AdamantCompiledModule`] is the type that flows through every
//! step of that pipeline.
//!
//! # Type design
//!
//! The struct uses the **parallel-struct** pattern (rather than
//! composition over Sui's `CompiledModule`): it owns its own
//! fields directly, and 25 neighbour types from
//! [`move_binary_format`] are reused unchanged because none of
//! them carry [`Bytecode`][move_binary_format::file_format::Bytecode]
//! in their definitions. Only three new types are introduced —
//! [`AdamantCompiledModule`], [`AdamantFunctionDefinition`], and
//! [`AdamantCodeUnit`] — corresponding to the only Sui types
//! whose shape carries `Bytecode`.
//!
//! Field ordering within each struct matches Sui's
//! `CompiledModule`/`FunctionDefinition`/`CodeUnit` exactly. The
//! binary format §6.2.1.2 inherits Sui's pool layout unchanged;
//! re-ordering fields here is gratuitous divergence from the
//! spec's "inherits Sui's binary format" framing and would
//! confuse readers cross-referencing against
//! `vendor/move-binary-format/src/file_format.rs`.
//!
//! # Cross-validation against Sui's `CompiledModule`
//!
//! For test-time cross-validation against vendored Sui per
//! §6.2.1.8 (the development-time and test-time reference
//! implementation), an [`AdamantCompiledModule`] containing no
//! Adamant extensions can be losslessly translated to a Sui
//! `CompiledModule`. The conversion will land later in this
//! deliverable (Phase 5/5a) alongside the deserializer, and is
//! gated on [`AdamantCompiledModule::contains_adamant_extensions`]
//! returning `false` — the converter explicitly refuses to
//! translate modules with extensions, rather than silently
//! dropping or substituting them, because doing so would produce
//! a misleading "equivalence" result for near-pure-Sui modules
//! with stray extensions.

use adamant_bytecode_format::{
    AddressIdentifierPool, ConstantPool, DatatypeHandle, EnumDefInstantiation, EnumDefinition,
    FieldHandle, FieldInstantiation, FunctionHandle, FunctionHandleIndex, FunctionInstantiation,
    IdentifierPool, Metadata, ModuleHandle, ModuleHandleIndex, SignatureIndex, SignaturePool,
    StructDefInstantiation, StructDefinition, StructDefinitionIndex, VariantHandle,
    VariantInstantiationHandle, VariantJumpTable, Visibility,
};
// Sui's `CompiledModule`/`CodeUnit`/`FunctionDefinition` are
// retained as imports so that `to_sui_module` can produce a
// vendored-Sui shape for test-time cross-validation per
// whitepaper §6.2.1.8. The conversion converts each Adamant
// field to its Sui counterpart via BCS round-trip (byte-
// identity verified by `adamant-bytecode-format`'s Phase 5/5b.6
// cross-validation suite).
use move_binary_format::file_format::{CodeUnit, CompiledModule, FunctionDefinition};

use crate::bytecode::BytecodeInstruction;

/// A parsed Adamant module per whitepaper §6.2.1.8.
///
/// Mirrors Sui-Move's
/// [`CompiledModule`][move_binary_format::file_format::CompiledModule]
/// shape with one structural change: `function_defs` is a
/// `Vec<`[`AdamantFunctionDefinition`]`>`, whose function bodies
/// carry [`BytecodeInstruction`] (Sui-base + Adamant extensions
/// per §6.2.1.4) rather than `Vec<Bytecode>`.
///
/// Field ordering matches Sui's `CompiledModule` exactly, since
/// §6.2.1.2 inherits Sui's binary format unchanged and the
/// canonical wire encoding in §6.2.1.5 follows that ordering.
///
/// # Pure-Sui-translatable subset
///
/// An `AdamantCompiledModule` whose function bodies contain no
/// `BytecodeInstruction::Adamant(_)` variants is equivalent in
/// representable content to a Sui-Move `CompiledModule`. The
/// future `to_sui_module` conversion (Phase 5/5a step 5) is
/// gated on [`Self::contains_adamant_extensions`] returning
/// `false` — the converter explicitly refuses to translate
/// modules with extensions, rather than silently dropping or
/// substituting them, because doing so would produce a
/// misleading "equivalence" result for near-pure-Sui modules
/// with stray extensions.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AdamantCompiledModule {
    /// Binary-format version. Pinned at the genesis-fixed Sui-Move
    /// binary-format version per §6.2.1.2; bumps are hard forks.
    pub version: u32,
    /// Whether this module is publishable. Sui's serializer sets
    /// `false` for modules generated under specific testing modes
    /// per `vendor/move-binary-format/src/binary_config.rs:126`;
    /// Adamant's deploy-time pipeline expects `true` for valid
    /// deploy-time inputs (rejection of `publishable = false` is
    /// a Phase 5/5b module-level pass concern, tracked there).
    pub publishable: bool,
    /// Index into [`Self::module_handles`] identifying this
    /// module's own handle.
    pub self_module_handle_idx: ModuleHandleIndex,
    /// Handles to external dependency modules and self.
    pub module_handles: Vec<ModuleHandle>,
    /// Handles to external and internal datatypes (structs and
    /// enums).
    pub datatype_handles: Vec<DatatypeHandle>,
    /// Handles to external and internal functions.
    pub function_handles: Vec<FunctionHandle>,
    /// Handles to fields.
    pub field_handles: Vec<FieldHandle>,
    /// Friend declarations.
    pub friend_decls: Vec<ModuleHandle>,
    /// Struct instantiations.
    pub struct_def_instantiations: Vec<StructDefInstantiation>,
    /// Function instantiations.
    pub function_instantiations: Vec<FunctionInstantiation>,
    /// Field instantiations.
    pub field_instantiations: Vec<FieldInstantiation>,
    /// Locals signature pool. Holds parameter and local-variable
    /// type lists referenced by function definitions.
    pub signatures: SignaturePool,
    /// All identifiers used in this module.
    pub identifiers: IdentifierPool,
    /// All address identifiers used in this module.
    pub address_identifiers: AddressIdentifierPool,
    /// Constant pool.
    pub constant_pool: ConstantPool,
    /// Module-level metadata entries. The Adamant validator
    /// reads:
    ///
    /// - `b"adamant.mutability"` per §6.2.1.6 Rule 1 / §6.2.1.3
    ///   (BCS-encoded `adamant_types::Mutability`)
    /// - `b"adamant.privacy"` per §6.2.1.6 Rule 2 / §6.2.1.3
    ///   (BCS-encoded `Vec<(FunctionDefinitionIndex, u8)>`)
    /// - `b"adamant.allows_dynamic"` per §6.2.1.6 Rule 6
    ///   (BCS-encoded `bool`)
    pub metadata: Vec<Metadata>,
    /// Struct definitions in this module.
    pub struct_defs: Vec<StructDefinition>,
    /// Function definitions in this module. Holds
    /// [`AdamantFunctionDefinition`] (rather than Sui's
    /// `FunctionDefinition`) so function bodies can carry the
    /// full Adamant instruction set per §6.2.1.4.
    pub function_defs: Vec<AdamantFunctionDefinition>,
    /// Enum definitions in this module.
    pub enum_defs: Vec<EnumDefinition>,
    /// Enum instantiations.
    pub enum_def_instantiations: Vec<EnumDefInstantiation>,
    /// Variant handles for enum constructors and matchers.
    pub variant_handles: Vec<VariantHandle>,
    /// Variant instantiation handles.
    pub variant_instantiation_handles: Vec<VariantInstantiationHandle>,
}

/// A function definition in an [`AdamantCompiledModule`] per
/// §6.2.1.8.
///
/// Mirrors Sui-Move's
/// [`FunctionDefinition`][move_binary_format::file_format::FunctionDefinition]
/// shape with one structural change: the `code` field holds an
/// [`AdamantCodeUnit`] rather than a Sui `CodeUnit`, so the
/// function body carries [`BytecodeInstruction`] (Sui-base +
/// Adamant extensions) rather than `Vec<Bytecode>`.
///
/// Field ordering matches Sui's `FunctionDefinition` exactly.
/// `code: Option<AdamantCodeUnit>` retains Sui's `Option`
/// shape: `None` indicates a native function (Sui-Move's marker
/// per `FunctionDefinition::is_native()` at
/// `vendor/move-binary-format/src/file_format.rs:557`).
/// §6.2.1.6 Rule 4 forbids `None` in any deployable Adamant
/// module — every function in Adamant Move is implemented in
/// bytecode per §6.1.4; the field's `Option` shape exists so
/// the validator can detect and reject native functions, not
/// because Adamant supports them.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AdamantFunctionDefinition {
    /// The prototype of the function (module, name, signature).
    pub function: FunctionHandleIndex,
    /// The visibility of this function.
    pub visibility: Visibility,
    /// Whether this function is an entry point.
    pub is_entry: bool,
    /// List of locally defined types this function might
    /// `acquire` from global storage. Always empty in valid
    /// Adamant modules per §6.2.1.6 Rule 5 (no global storage
    /// instructions); preserved structurally for byte-faithful
    /// parsing of the inherited binary-format field.
    pub acquires_global_resources: Vec<StructDefinitionIndex>,
    /// Code for this function. `None` indicates a native
    /// function; §6.2.1.6 Rule 4 forbids native functions in
    /// deployable modules.
    pub code: Option<AdamantCodeUnit>,
}

impl AdamantFunctionDefinition {
    /// Returns `true` if this is a native function (i.e.,
    /// [`Self::code`] is `None`). §6.2.1.6 Rule 4 forbids
    /// `is_native() == true` in any deployable Adamant module.
    /// Mirrors Sui's
    /// [`FunctionDefinition::is_native`][move_binary_format::file_format::FunctionDefinition::is_native].
    #[must_use]
    pub fn is_native(&self) -> bool {
        self.code.is_none()
    }
}

/// A code unit (function body) in an [`AdamantFunctionDefinition`]
/// per §6.2.1.8.
///
/// Mirrors Sui-Move's
/// [`CodeUnit`][move_binary_format::file_format::CodeUnit] shape
/// with one structural change: `code` is a
/// `Vec<`[`BytecodeInstruction`]`>` rather than `Vec<Bytecode>`,
/// so it can hold both inherited Sui-Move opcodes and Adamant
/// extensions per §6.2.1.4.
///
/// Field ordering matches Sui's `CodeUnit` exactly. The
/// `jump_tables` field holds [`VariantJumpTable`] entries
/// referenced by `VariantSwitch` instructions (inherited from
/// Sui-Move; jump-table targets are positional offsets into
/// [`Self::code`], same as branch targets for `Branch`/`BrTrue`/
/// `BrFalse`).
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AdamantCodeUnit {
    /// Index into the module's signature pool of this function's
    /// local-variable type list (parameters followed by locals).
    pub locals: SignatureIndex,
    /// The function body — a sequence of [`BytecodeInstruction`]
    /// per §6.2.1.4. Branch targets in `Branch`/`BrTrue`/`BrFalse`
    /// instructions are positional offsets (`u16`) into this
    /// vector; jump-table entries in [`Self::jump_tables`] are
    /// likewise positional.
    pub code: Vec<BytecodeInstruction>,
    /// Jump tables for `VariantSwitch` instructions (inherited
    /// from Sui-Move).
    pub jump_tables: Vec<VariantJumpTable>,
}

impl AdamantCompiledModule {
    /// Returns `true` if any function body in this module
    /// contains an [`Adamant`-variant][BytecodeInstruction::Adamant]
    /// instruction per §6.2.1.4.
    ///
    /// Used by [`Self::to_sui_module`] to refuse conversion when
    /// extensions are present, and by test-time cross-validation
    /// per §6.2.1.8 to gate which fixtures may be cross-validated
    /// against the vendored Sui reference implementation.
    #[must_use]
    pub fn contains_adamant_extensions(&self) -> bool {
        self.function_defs.iter().any(|fd| {
            fd.code.as_ref().is_some_and(|code_unit| {
                code_unit
                    .code
                    .iter()
                    .any(|instr| matches!(instr, BytecodeInstruction::Adamant(_)))
            })
        })
    }

    /// Convert this `AdamantCompiledModule` to Sui-Move's
    /// [`CompiledModule`] for test-time cross-validation against
    /// the vendored Sui reference implementation per §6.2.1.8.
    ///
    /// The conversion is gated on
    /// [`Self::contains_adamant_extensions`] returning `false` —
    /// modules containing Adamant extensions are explicitly
    /// refused with [`AdamantToSuiConversionError::ContainsAdamantExtensions`]
    /// rather than silently dropping or substituting the
    /// extension instructions, because that would produce a
    /// misleading "equivalence" result for near-pure-Sui modules
    /// with stray extensions.
    ///
    /// All non-`function_defs` fields are reused unchanged (they
    /// are already Sui's types per the parallel-struct pattern).
    /// The `function_defs` projection rewrites each
    /// [`AdamantFunctionDefinition`] to a Sui [`FunctionDefinition`]
    /// and each [`AdamantCodeUnit`] to a Sui [`CodeUnit`] by
    /// unwrapping every `BytecodeInstruction::Inherited(b)` to
    /// `b`.
    ///
    /// # Errors
    ///
    /// Returns [`AdamantToSuiConversionError::ContainsAdamantExtensions`]
    /// reporting the first offending function index and
    /// instruction offset (lowest function index, lowest offset
    /// within that function) if any function body contains an
    /// Adamant-variant instruction.
    ///
    /// # Panics
    ///
    /// Panics if a function-def index or body-instruction offset
    /// exceeds `u16::MAX`. Sui-Move's binary format precludes both
    /// (`FUNCTION_HANDLE_INDEX_MAX = 65535`,
    /// `BYTECODE_INDEX_MAX = 65535`); any module that came through
    /// [`crate::adamant_deserialize`] respects those bounds, so
    /// this branch is unreachable for inputs the public pipeline
    /// produces.
    pub fn to_sui_module(&self) -> Result<CompiledModule, AdamantToSuiConversionError> {
        // Per-field conversion strategy: Adamant's bytecode-
        // format types are byte-identical to Sui's vendored
        // counterparts under BCS (asserted by
        // `adamant-bytecode-format/tests/cross_validation.rs`).
        // Each Adamant field is round-tripped through BCS into
        // its Sui counterpart. The conversion is test-time only
        // — `to_sui_module` is exercised exclusively by
        // cross-validation tests per whitepaper §6.2.1.8.
        //
        // `function_defs` is the one structural exception:
        // Adamant's `Vec<AdamantFunctionDefinition>` differs
        // from Sui's `Vec<FunctionDefinition>` by carrying
        // `Vec<BytecodeInstruction>` instead of `Vec<Bytecode>`
        // in each function body. The conversion strips the
        // `BytecodeInstruction::Inherited(_)` wrapper and
        // refuses on `Adamant(_)`.
        fn cv<T: serde::Serialize, U: serde::de::DeserializeOwned>(t: &T) -> U {
            let bytes = bcs::to_bytes(t)
                .expect("byte-identity invariant per Phase 5/5b.6 cross-validation");
            bcs::from_bytes(&bytes)
                .expect("byte-identity invariant per Phase 5/5b.6 cross-validation")
        }

        let mut function_defs = Vec::with_capacity(self.function_defs.len());
        for (fd_idx, fd) in self.function_defs.iter().enumerate() {
            let code = match &fd.code {
                None => None,
                Some(code_unit) => {
                    let mut sui_code = Vec::with_capacity(code_unit.code.len());
                    for (instr_idx, instr) in code_unit.code.iter().enumerate() {
                        match instr {
                            BytecodeInstruction::Inherited(b) => sui_code.push(cv(b)),
                            BytecodeInstruction::Adamant(_) => {
                                // Cast safety: Sui's binary
                                // format bounds function-def
                                // count and body-instruction
                                // count to u16
                                // (`FUNCTION_HANDLE_INDEX_MAX =
                                // 65535`, `BYTECODE_INDEX_MAX =
                                // 65535`); this module came
                                // through the deserializer
                                // which enforces the bounds.
                                // `try_from` makes the bound
                                // explicit.
                                let function_index = u16::try_from(fd_idx).expect(
                                    "function-def count fits u16; binary format precludes \
                                     overflow",
                                );
                                let instruction_offset = u16::try_from(instr_idx).expect(
                                    "body-instruction count fits u16; binary format precludes \
                                     overflow",
                                );
                                return Err(
                                    AdamantToSuiConversionError::ContainsAdamantExtensions {
                                        function_index,
                                        instruction_offset,
                                    },
                                );
                            }
                        }
                    }
                    Some(CodeUnit {
                        locals: cv(&code_unit.locals),
                        code: sui_code,
                        jump_tables: cv(&code_unit.jump_tables),
                    })
                }
            };
            function_defs.push(FunctionDefinition {
                function: cv(&fd.function),
                visibility: cv(&fd.visibility),
                is_entry: fd.is_entry,
                acquires_global_resources: cv(&fd.acquires_global_resources),
                code,
            });
        }
        Ok(CompiledModule {
            version: self.version,
            publishable: self.publishable,
            self_module_handle_idx: cv(&self.self_module_handle_idx),
            module_handles: cv(&self.module_handles),
            datatype_handles: cv(&self.datatype_handles),
            function_handles: cv(&self.function_handles),
            field_handles: cv(&self.field_handles),
            friend_decls: cv(&self.friend_decls),
            struct_def_instantiations: cv(&self.struct_def_instantiations),
            function_instantiations: cv(&self.function_instantiations),
            field_instantiations: cv(&self.field_instantiations),
            signatures: cv(&self.signatures),
            identifiers: cv(&self.identifiers),
            address_identifiers: cv(&self.address_identifiers),
            constant_pool: cv(&self.constant_pool),
            metadata: cv(&self.metadata),
            struct_defs: cv(&self.struct_defs),
            function_defs,
            enum_defs: cv(&self.enum_defs),
            enum_def_instantiations: cv(&self.enum_def_instantiations),
            variant_handles: cv(&self.variant_handles),
            variant_instantiation_handles: cv(&self.variant_instantiation_handles),
        })
    }
}

/// Errors from [`AdamantCompiledModule::to_sui_module`].
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub enum AdamantToSuiConversionError {
    /// At least one function body contains an Adamant-variant
    /// instruction per §6.2.1.4. Reports the first offending
    /// location (lowest function index, lowest instruction offset
    /// within that function); subsequent extensions are not
    /// enumerated.
    ContainsAdamantExtensions {
        /// Function-def index where the first extension was found.
        function_index: u16,
        /// Instruction offset within that function's body.
        instruction_offset: u16,
    },
}

impl core::fmt::Display for AdamantToSuiConversionError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::ContainsAdamantExtensions {
                function_index,
                instruction_offset,
            } => write!(
                f,
                "AdamantCompiledModule cannot be projected to Sui's CompiledModule: \
                 function index {function_index} instruction offset {instruction_offset} \
                 is an Adamant extension (whitepaper §6.2.1.4)"
            ),
        }
    }
}

impl std::error::Error for AdamantToSuiConversionError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bytecode::AdamantBytecode;
    use adamant_bytecode_format::Bytecode;
    // Sui's `Bytecode` is also imported to assert against the
    // result of `to_sui_module` (which returns a Sui
    // `CompiledModule`). The two enum types are byte-identical
    // under BCS but distinct nominal types in Rust's type
    // system; the test scope needs both visible.
    use move_binary_format::file_format::Bytecode as SuiBytecode;

    /// `AdamantCompiledModule::default()` returns a module with
    /// every field empty / zero. Constructing the default and
    /// reading every field surfaces type-shape regressions if a
    /// field's type ever changes shape.
    #[test]
    fn default_constructs_empty_module() {
        let m = AdamantCompiledModule::default();
        assert_eq!(m.version, 0);
        assert!(!m.publishable);
        assert_eq!(m.self_module_handle_idx, ModuleHandleIndex(0));
        assert!(m.module_handles.is_empty());
        assert!(m.datatype_handles.is_empty());
        assert!(m.function_handles.is_empty());
        assert!(m.field_handles.is_empty());
        assert!(m.friend_decls.is_empty());
        assert!(m.struct_def_instantiations.is_empty());
        assert!(m.function_instantiations.is_empty());
        assert!(m.field_instantiations.is_empty());
        assert!(m.signatures.is_empty());
        assert!(m.identifiers.is_empty());
        assert!(m.address_identifiers.is_empty());
        assert!(m.constant_pool.is_empty());
        assert!(m.metadata.is_empty());
        assert!(m.struct_defs.is_empty());
        assert!(m.function_defs.is_empty());
        assert!(m.enum_defs.is_empty());
        assert!(m.enum_def_instantiations.is_empty());
        assert!(m.variant_handles.is_empty());
        assert!(m.variant_instantiation_handles.is_empty());
    }

    /// `Clone` produces an equal module; pins the derived
    /// `Clone` + `PartialEq` shape against accidental field
    /// shadowing (e.g., a `Cell` or non-equality-derivable
    /// field sneaking in).
    #[test]
    fn clone_round_trips_through_equality() {
        let m = AdamantCompiledModule {
            version: 7,
            publishable: true,
            ..AdamantCompiledModule::default()
        };
        assert_eq!(m, m.clone());
    }

    /// `AdamantFunctionDefinition::is_native` mirrors Sui's
    /// `FunctionDefinition::is_native`: `true` iff `code.is_none()`.
    #[test]
    fn function_definition_is_native_iff_code_is_none() {
        let native = AdamantFunctionDefinition {
            function: FunctionHandleIndex(0),
            visibility: Visibility::Private,
            is_entry: false,
            acquires_global_resources: vec![],
            code: None,
        };
        assert!(native.is_native());

        let non_native = AdamantFunctionDefinition {
            function: FunctionHandleIndex(0),
            visibility: Visibility::Private,
            is_entry: false,
            acquires_global_resources: vec![],
            code: Some(AdamantCodeUnit {
                locals: SignatureIndex(0),
                code: vec![BytecodeInstruction::Inherited(Bytecode::Ret)],
                jump_tables: vec![],
            }),
        };
        assert!(!non_native.is_native());
    }

    /// A module whose function bodies contain only
    /// `BytecodeInstruction::Inherited(_)` returns `false` from
    /// `contains_adamant_extensions`.
    #[test]
    fn contains_adamant_extensions_false_for_pure_sui_module() {
        let m = AdamantCompiledModule {
            function_defs: vec![AdamantFunctionDefinition {
                function: FunctionHandleIndex(0),
                visibility: Visibility::Private,
                is_entry: false,
                acquires_global_resources: vec![],
                code: Some(AdamantCodeUnit {
                    locals: SignatureIndex(0),
                    code: vec![
                        BytecodeInstruction::Inherited(Bytecode::LdU64(5)),
                        BytecodeInstruction::Inherited(Bytecode::Pop),
                        BytecodeInstruction::Inherited(Bytecode::Ret),
                    ],
                    jump_tables: vec![],
                }),
            }],
            ..AdamantCompiledModule::default()
        };
        assert!(!m.contains_adamant_extensions());
    }

    /// A module whose function bodies contain at least one
    /// `BytecodeInstruction::Adamant(_)` returns `true`.
    #[test]
    fn contains_adamant_extensions_true_when_extension_present() {
        let m = AdamantCompiledModule {
            function_defs: vec![AdamantFunctionDefinition {
                function: FunctionHandleIndex(0),
                visibility: Visibility::Private,
                is_entry: false,
                acquires_global_resources: vec![],
                code: Some(AdamantCodeUnit {
                    locals: SignatureIndex(0),
                    code: vec![
                        BytecodeInstruction::Inherited(Bytecode::Ret),
                        BytecodeInstruction::Adamant(AdamantBytecode::Sha3_256),
                        BytecodeInstruction::Inherited(Bytecode::Ret),
                    ],
                    jump_tables: vec![],
                }),
            }],
            ..AdamantCompiledModule::default()
        };
        assert!(m.contains_adamant_extensions());
    }

    /// Native functions (no code) don't contribute to extension
    /// detection — `code.is_none()` is treated as "no instructions",
    /// not "contains extensions". Detection is structural over
    /// the instruction sequence; a native function's missing
    /// body cannot contain anything.
    #[test]
    fn contains_adamant_extensions_false_for_native_function() {
        let m = AdamantCompiledModule {
            function_defs: vec![AdamantFunctionDefinition {
                function: FunctionHandleIndex(0),
                visibility: Visibility::Private,
                is_entry: false,
                acquires_global_resources: vec![],
                code: None,
            }],
            ..AdamantCompiledModule::default()
        };
        assert!(!m.contains_adamant_extensions());
    }

    /// `to_sui_module` round-trips a pure-Sui module through the
    /// projection: every non-`function_defs` field is preserved by
    /// reference-equal cloning, and a function with body
    /// `[Inherited(Ret)]` projects to body `[Ret]`.
    #[test]
    fn to_sui_module_round_trips_pure_sui_function() {
        let m = AdamantCompiledModule {
            function_defs: vec![AdamantFunctionDefinition {
                function: FunctionHandleIndex(0),
                visibility: Visibility::Public,
                is_entry: false,
                acquires_global_resources: vec![],
                code: Some(AdamantCodeUnit {
                    locals: SignatureIndex(0),
                    code: vec![BytecodeInstruction::Inherited(Bytecode::Ret)],
                    jump_tables: vec![],
                }),
            }],
            ..AdamantCompiledModule::default()
        };
        let sui = m.to_sui_module().unwrap();
        assert_eq!(sui.function_defs.len(), 1);
        let fd = &sui.function_defs[0];
        let body = fd.code.as_ref().unwrap().code.clone();
        assert_eq!(body, vec![SuiBytecode::Ret]);
    }

    /// `to_sui_module` refuses a module with an extension and
    /// reports the first offending function/offset (in this case
    /// function 0, offset 1 — `Sha3_256` sits between `Ret` at
    /// offset 0 and `Ret` at offset 2 — actually offset 1).
    #[test]
    fn to_sui_module_refuses_module_with_extension() {
        use crate::bytecode::AdamantBytecode;
        let m = AdamantCompiledModule {
            function_defs: vec![AdamantFunctionDefinition {
                function: FunctionHandleIndex(0),
                visibility: Visibility::Public,
                is_entry: false,
                acquires_global_resources: vec![],
                code: Some(AdamantCodeUnit {
                    locals: SignatureIndex(0),
                    code: vec![
                        BytecodeInstruction::Inherited(Bytecode::Pop),
                        BytecodeInstruction::Adamant(AdamantBytecode::Sha3_256),
                        BytecodeInstruction::Inherited(Bytecode::Ret),
                    ],
                    jump_tables: vec![],
                }),
            }],
            ..AdamantCompiledModule::default()
        };
        let err = m.to_sui_module().unwrap_err();
        assert_eq!(
            err,
            AdamantToSuiConversionError::ContainsAdamantExtensions {
                function_index: 0,
                instruction_offset: 1,
            }
        );
    }

    /// `to_sui_module` reports the LOWEST offending function-index
    /// when multiple functions contain extensions. Pin the eager-
    /// rejection ordering.
    #[test]
    fn to_sui_module_reports_first_offending_function() {
        use crate::bytecode::AdamantBytecode;
        let extension_fd = AdamantFunctionDefinition {
            function: FunctionHandleIndex(0),
            visibility: Visibility::Private,
            is_entry: false,
            acquires_global_resources: vec![],
            code: Some(AdamantCodeUnit {
                locals: SignatureIndex(0),
                code: vec![
                    BytecodeInstruction::Adamant(AdamantBytecode::Blake3),
                    BytecodeInstruction::Inherited(Bytecode::Ret),
                ],
                jump_tables: vec![],
            }),
        };
        let pure_fd = AdamantFunctionDefinition {
            function: FunctionHandleIndex(0),
            visibility: Visibility::Private,
            is_entry: false,
            acquires_global_resources: vec![],
            code: Some(AdamantCodeUnit {
                locals: SignatureIndex(0),
                code: vec![BytecodeInstruction::Inherited(Bytecode::Ret)],
                jump_tables: vec![],
            }),
        };
        // Function index 0: pure. Function index 1: extension at offset 0.
        // Function index 2: extension at offset 0. The first offending is fn 1.
        let m = AdamantCompiledModule {
            function_defs: vec![pure_fd, extension_fd.clone(), extension_fd],
            ..AdamantCompiledModule::default()
        };
        let err = m.to_sui_module().unwrap_err();
        assert_eq!(
            err,
            AdamantToSuiConversionError::ContainsAdamantExtensions {
                function_index: 1,
                instruction_offset: 0,
            }
        );
    }

    /// `to_sui_module` accepts a native function (no body) without
    /// scanning. Native functions have `code: None`, so there are
    /// no instructions to check; the projection produces a Sui
    /// `FunctionDefinition` with `code: None`.
    #[test]
    fn to_sui_module_passes_native_function_through() {
        let m = AdamantCompiledModule {
            function_defs: vec![AdamantFunctionDefinition {
                function: FunctionHandleIndex(0),
                visibility: Visibility::Private,
                is_entry: false,
                acquires_global_resources: vec![],
                code: None,
            }],
            ..AdamantCompiledModule::default()
        };
        let sui = m.to_sui_module().unwrap();
        assert!(sui.function_defs[0].code.is_none());
    }

    /// `Display` impl on `AdamantToSuiConversionError` produces a
    /// non-empty diagnostic.
    #[test]
    fn conversion_error_display_is_populated() {
        let err = AdamantToSuiConversionError::ContainsAdamantExtensions {
            function_index: 5,
            instruction_offset: 2,
        };
        let s = format!("{err}");
        assert!(!s.is_empty());
        assert!(s.contains("function index 5"));
        assert!(s.contains("instruction offset 2"));
    }

    /// A module with multiple functions correctly returns `true`
    /// when any one of them contains an extension, even if
    /// earlier functions are pure-Sui.
    #[test]
    fn contains_adamant_extensions_scans_all_functions() {
        let pure_sui_fd = AdamantFunctionDefinition {
            function: FunctionHandleIndex(0),
            visibility: Visibility::Private,
            is_entry: false,
            acquires_global_resources: vec![],
            code: Some(AdamantCodeUnit {
                locals: SignatureIndex(0),
                code: vec![BytecodeInstruction::Inherited(Bytecode::Ret)],
                jump_tables: vec![],
            }),
        };
        let extension_fd = AdamantFunctionDefinition {
            function: FunctionHandleIndex(0),
            visibility: Visibility::Private,
            is_entry: false,
            acquires_global_resources: vec![],
            code: Some(AdamantCodeUnit {
                locals: SignatureIndex(0),
                code: vec![
                    BytecodeInstruction::Adamant(AdamantBytecode::Blake3),
                    BytecodeInstruction::Inherited(Bytecode::Ret),
                ],
                jump_tables: vec![],
            }),
        };
        let m = AdamantCompiledModule {
            function_defs: vec![pure_sui_fd.clone(), extension_fd, pure_sui_fd],
            ..AdamantCompiledModule::default()
        };
        assert!(m.contains_adamant_extensions());
    }
}
