//! Validator Rule 8 (whitepaper §6.2.1.6 #8): bounded loops.
//!
//! **Verifier-level no-op canonical pin.** Rule 8 has no
//! deploy-time enforcement; the architectural position is
//! pinned here so future maintainers don't mistake the
//! absence for a missing implementation.
//!
//! # Spec text (§6.2.1.6 Rule 8 + amendment 804d9db; verbatim
//! re-paste from E-5 plan-gate verification gate)
//!
//! "Bounded loops. Loops in the bytecode are bounded at
//! runtime by the gas mechanism per section 6.2.4 ('All loops
//! must have statically-bounded iteration counts or run
//! within a gas budget that bounds them dynamically'). Static
//! loop-bound verification is not required at deployment
//! time; the gas-budget bound at runtime carries the
//! determinism guarantee."
//!
//! "(Pre-revision drafts of this rule referenced 'Sui-Move's
//! existing loop-bound analysis as a starting point.' That
//! was a drafting error: Sui-Move's
//! `move-bytecode-verifier::loop_summary` module performs CFG
//! structural analysis — back-edge identification via
//! Tarjan's loop reducibility — rather than iteration-bound
//! analysis. There is no upstream loop-bound analysis to
//! extend. Determinism is established at runtime via section
//! 6.2.4's gas-budget bound; the verifier-level check is a
//! no-op.)"
//!
//! # Architectural-position-pin-for-explicit-non-enforcement
//!
//! 1st instance of architectural-position-pin-for-explicit-
//! non-enforcement methodology pattern (registered at E-5
//! plan-gate Q5 refinement).
//!
//! Pattern shape: when a spec amendment mandates a verifier-
//! level no-op for a rule whose enforcement venue is
//! elsewhere (runtime, parse-time, etc.), Adamant lands a
//! canonical pin module documenting (a) the architectural
//! position, (b) the spec text, (c) the test confirming the
//! verifier accepts a fixture that would otherwise be the
//! rule's trigger condition. The pin makes the absence of
//! enforcement consensus-binding — future maintainers
//! searching for `rule_08` find the canonical record.
//!
//! Distinct from:
//!
//! - **Spec-text-DIRECTS-shared-helper canonical principle**
//!   (about reuse of an existing helper across rule scopes;
//!   5 instances at E-4 closure across cross-pass-distinct
//!   and cross-scope-reuse sub-shapes).
//! - **Rule-composition-for-cross-module-coverage**
//!   (about transitive coverage via composition of two
//!   rules; 1st instance at E-4 for Rule 7's cross-module
//!   surface bound through Rule 3 cross-module + Rule 7
//!   single-module).
//! - **Architectural-position-pin-for-explicit-non-enforcement**
//!   (this pattern; about explicit non-enforcement at the
//!   verifier layer).
//!
//! Three patterns operating across distinct methodology
//! domains, all surfacing architectural decisions that
//! future maintainers might question.
//!
//! Rule-of-three pending across this pattern. Future
//! candidates: Rule 5 (no global storage instructions) is
//! enforced at parse time per `adamant_deserialize`'s strict
//! mode; pinned at the deserializer side rather than via a
//! validator pin module. If a future spec amendment lands a
//! deploy-time-no-op rule, the architectural-position-pin
//! pattern's 2nd instance fires here.
//!
//! # Why no `verify(&module)` function
//!
//! No-op rules don't have a `verify` function in the
//! validator step-5 batch — that would be code-noise
//! pretending to be a pass. The absence at step 5 IS the
//! implementation per the spec text's "verifier-level check
//! is a no-op" mandate. This module's doc-comment + test
//! together document the architectural position; the lack
//! of a function call in `validator/mod.rs::verify_module`
//! is the canonical implementation.

#[cfg(test)]
mod tests {
    //! Layer A pin test for Rule 8.
    //!
    //! No Layer B parity tests by design — Rule 8 is an
    //! Adamant-specific architectural position per §6.2.1.6
    //! amendment 804d9db; Sui-Move's `loop_summary` performs
    //! structural CFG analysis (back-edge identification)
    //! not iteration-bound analysis, so there is no upstream
    //! parity surface.

    use crate::module_wire::adamant_serialize;
    use crate::module::{AdamantCodeUnit, AdamantCompiledModule, AdamantFunctionDefinition};
    use crate::validator::{verify_module, AdamantVerifierConfig};
    use adamant_bytecode_format::{
        AddressIdentifierIndex, Bytecode, FunctionHandle, FunctionHandleIndex, Identifier,
        IdentifierIndex, Metadata, ModuleHandle, ModuleHandleIndex, Signature, SignatureIndex,
        Visibility,
    };
    use adamant_types::Address;

    use crate::bytecode::BytecodeInstruction;

    /// Architectural-position-pin canonical test for Rule 8.
    ///
    /// Constructs a module containing an unbounded self-loop
    /// (`Branch(0)` as the only instruction in the function
    /// body) and asserts that the validator accepts it.
    /// Without this pin, a future refactor that accidentally
    /// added static loop-bound analysis would silently change
    /// the verifier's accept set; the test fires on that
    /// drift and forces an explicit deliberate-Adamant-decision
    /// registration.
    ///
    /// The fixture passes:
    /// - `control_flow`: `Branch(0)` is an unconditional
    ///   branch (last instruction terminator OK); CFG is
    ///   reducible (single-block self-loop has unique back
    ///   edge).
    /// - `stack_usage`: empty body has zero stack delta
    ///   per-block; balanced.
    /// - `locals_safety`: no local accesses.
    /// - `type_safety`: no type-checked instructions.
    /// - `reference_safety`: no reference operations.
    /// - Rules 1, 2, 3, 4, 6, 7: no rule-fire conditions
    ///   present.
    ///
    /// Equivalent to: a function whose body is just `loop {}`
    /// in higher-level Adamant Move source. This is the
    /// canonical "the verifier doesn't bound loops" empirical
    /// pin.
    #[test]
    fn unbounded_self_loop_module_accepts_at_deploy_time() {
        let mut m = AdamantCompiledModule {
            version: adamant_bytecode_format::format_common::VERSION_MAX,
            ..AdamantCompiledModule::default()
        };
        m.module_handles.push(ModuleHandle {
            address: AddressIdentifierIndex(0),
            name: IdentifierIndex(0),
        });
        m.identifiers.push(Identifier::new("rule_08_pin").unwrap());
        m.address_identifiers.push(Address::from_bytes([0xab; 32]));
        m.signatures.push(Signature(vec![]));
        m.identifiers.push(Identifier::new("loop_fn").unwrap());
        m.function_handles.push(FunctionHandle {
            module: ModuleHandleIndex(0),
            name: IdentifierIndex(1),
            parameters: SignatureIndex(0),
            return_: SignatureIndex(0),
            type_parameters: vec![],
        });
        m.function_defs.push(AdamantFunctionDefinition {
            function: FunctionHandleIndex(0),
            visibility: Visibility::Private,
            is_entry: false,
            acquires_global_resources: vec![],
            code: Some(AdamantCodeUnit {
                locals: SignatureIndex(0),
                code: vec![BytecodeInstruction::Inherited(Bytecode::Branch(0))],
                jump_tables: vec![],
            }),
        });
        // Add the mandatory mutability metadata (Rule 1) so
        // the module is otherwise valid; the fixture's pin
        // is specifically that Rule 8 doesn't fire on the
        // unbounded loop, not that some other rule would
        // accidentally accept the module.
        m.metadata.push(Metadata {
            key: b"adamant.mutability".to_vec(),
            value: bcs::to_bytes(&adamant_types::Mutability::Immutable).unwrap(),
        });

        let mut bytes = Vec::new();
        adamant_serialize(&m, &mut bytes).expect("module serializes");
        let config = AdamantVerifierConfig::new();

        // Rule 8's architectural position: the verifier
        // accepts modules with unbounded loops. Runtime gas-
        // budget per §6.2.4 carries the determinism binding.
        verify_module(&bytes, &config).expect(
            "Rule 8 architectural-position pin: verifier must accept unbounded self-loop \
             (gas-budget bound at runtime carries determinism per §6.2.4 + §6.2.1.6 amendment 804d9db)",
        );
    }
}
