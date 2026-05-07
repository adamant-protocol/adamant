//! Module-level pass: generic-instantiation-loop detection
//! (whitepaper §6.2.1.8 step 3).
//!
//! Forked from
//! `vendor/move-bytecode-verifier/src/instantiation_loops.rs`
//! at Sui-Move tag `mainnet-v1.66.2` (commit
//! `a9a6825eaf6273cc819ee3bcf65fd4909f7624a9`). See
//! `validator/module_pass/PROVENANCE.md` for the deviation
//! list. Summary:
//!
//! - Operates on [`AdamantCompiledModule`] rather than Sui's
//!   `CompiledModule`. The function-definition tables and
//!   `CallGeneric` instruction shape are byte-faithful to
//!   upstream per Phase 5/5b.1b's bytecode-format fork.
//! - Returns typed
//!   [`AdamantValidationError::LoopInInstantiationGraph`]
//!   rather than upstream's `PartialVMError`/`StatusCode`.
//! - Uses `petgraph::Graph` + `petgraph::algo::tarjan_scc`
//!   byte-faithfully from upstream. Petgraph promoted to
//!   production dep at B-3.2 (commit `a1c81ad`).
//! - Adamant extensions per §6.2.1.4 traverse without
//!   introducing graph edges (none are `CallGeneric`-flavored;
//!   none have type-arguments). The instruction match adds
//!   an early-return Ok arm for `BytecodeInstruction::Adamant(_)`
//!   per B-2.4's pattern.
//! - Native functions are filtered out of the graph build
//!   per upstream (`!def.is_native()` filter); fourth instance
//!   of the structural-impossibility-checks pattern with the
//!   "implicit-filter" sub-pattern (Rule 4 catches native
//!   functions earlier in the pipeline).
//!
//! Algorithm (byte-faithful from upstream):
//!
//! 1. Build a directed graph where nodes are
//!    `(FunctionDefinitionIndex, TypeParameterIndex)` pairs
//!    and edges are typed:
//!    - `Identity`: caller's type parameter `T` is passed
//!      unmodified as callee's type parameter `U`.
//!    - `TyConApp(SignatureToken)`: caller's type parameter
//!      `T` appears inside a constructor (`Vec<T>`,
//!      `Box<T>`, etc.) being passed as callee's type
//!      parameter `U`. Edge labeled with the constructor.
//! 2. Walk every `CallGeneric` instruction in every non-
//!    native function body; for each `(formal_idx,
//!    actual_type)` pair in the call's type-arguments:
//!    - If `actual_type == TypeParameter(actual_idx)`: add
//!      `Identity` edge `(caller_fn, actual_idx) →
//!      (callee_fn, formal_idx)`.
//!    - Else: extract every `TypeParameter(idx)` in
//!      `actual_type`'s preorder, and add a `TyConApp`
//!      edge from each `(caller_fn, idx)` to `(callee_fn,
//!      formal_idx)` labeled with the `actual_type`.
//! 3. Run `petgraph::algo::tarjan_scc`; filter to non-trivial
//!    SCCs containing ≥1 `TyConApp` edge. Reject the first
//!    such component.
//!
//! Identity-only cycles (e.g., `f<T>` calling `f<T>`) are
//! allowed since they don't grow types on each cycle
//! traversal. Cycles containing any `TyConApp` edge would
//! require unbounded specializations and are rejected.
//!
//! # Component-summary diagnostic
//!
//! On rejection, the pass produces a diagnostic string
//! formatted byte-faithfully to upstream:
//!
//! ```text
//! edges with constructors: [{}], nodes: [{}]
//! ```
//!
//! Where the `{}` placeholders are filled with comma-
//! separated edge / node debug-strings. Adamant's
//! `define_index!`-generated `Display` impls on
//! `FunctionDefinitionIndex` (`{}` writes `self.0`) and the
//! `Debug` derives on `SignatureToken` produce byte-identical
//! output to upstream. Layer B parity test pins the format.
//!
//! The diagnostic is **not consensus-binding** — the
//! rejection is, but the exact formatting of the cycle's
//! contents isn't. A future sub-arc can promote to typed if
//! downstream consumers need pattern-matching.
//!
//! # Dead-code allow (transient)
//!
//! Phase 5/5b.2 B-5 wires this pass into
//! [`crate::validator::verify_module`]. Until B-5 lands, the
//! pass is reachable only from inline tests and Layer B
//! cross-validation; the lib build sees the entry point as
//! dead. The module-level `dead_code` allow is removed when
//! B-5 wires the pass.

#![allow(dead_code, reason = "wired into verify_module() in Phase 5/5b.2 B-5")]

use std::collections::{hash_map, HashMap, HashSet};

use adamant_bytecode_format::{
    Bytecode, FunctionDefinitionIndex, FunctionHandleIndex, SignatureIndex, SignatureToken,
    TableIndex, TypeParameterIndex,
};
use petgraph::{
    algo::tarjan_scc,
    graph::{EdgeIndex, NodeIndex},
    visit::EdgeRef,
    Graph,
};

use crate::bytecode::BytecodeInstruction;
use crate::module::AdamantCompiledModule;

use super::super::error::AdamantValidationError;

/// Internal graph-node type: a `(function definition,
/// type parameter)` pair.
#[derive(Debug, Eq, PartialEq, Hash, Copy, Clone)]
struct Node(FunctionDefinitionIndex, TypeParameterIndex);

/// Recursive helper for [`Checker::extract_type_parameters`].
/// Walks `ty`'s preorder and inserts every `TypeParameter(idx)`
/// it encounters into `out`.
fn extract_type_parameters_rec(out: &mut HashSet<TypeParameterIndex>, ty: &SignatureToken) {
    use SignatureToken as S;
    match ty {
        S::Bool
        | S::Address
        | S::U8
        | S::U16
        | S::U32
        | S::U64
        | S::U128
        | S::U256
        | S::Signer
        | S::Datatype(_) => {}
        S::TypeParameter(idx) => {
            out.insert(*idx);
        }
        S::Vector(inner) | S::Reference(inner) | S::MutableReference(inner) => {
            extract_type_parameters_rec(out, inner);
        }
        S::DatatypeInstantiation(inst) => {
            let (_, tys) = &**inst;
            for t in tys {
                extract_type_parameters_rec(out, t);
            }
        }
    }
}

/// Internal graph-edge type. `Identity` indicates caller's
/// type parameter is passed unmodified; `TyConApp` indicates
/// it appears inside a constructor.
enum Edge<'a> {
    Identity,
    TyConApp(&'a SignatureToken),
}

/// Verify that the module's generic-instantiation graph
/// contains no monomorphization-explosive loop, per §6.2.1.8
/// step 3 (`module_pass::instantiation_loops`).
pub(in crate::validator) fn verify(
    module: &AdamantCompiledModule,
) -> Result<(), AdamantValidationError> {
    let mut checker = Checker::new(module);
    checker.build_graph();
    if let Some((nodes, edges)) = checker.find_first_non_trivial_component() {
        let component_summary = checker.format_component(nodes, edges);
        return Err(AdamantValidationError::LoopInInstantiationGraph { component_summary });
    }
    Ok(())
}

struct Checker<'a> {
    module: &'a AdamantCompiledModule,
    graph: Graph<Node, Edge<'a>>,
    node_map: HashMap<Node, NodeIndex>,
    func_handle_def_map: HashMap<FunctionHandleIndex, FunctionDefinitionIndex>,
}

impl<'a> Checker<'a> {
    fn new(module: &'a AdamantCompiledModule) -> Self {
        let func_handle_def_map: HashMap<FunctionHandleIndex, FunctionDefinitionIndex> =
            module
                .function_defs
                .iter()
                .enumerate()
                .map(|(def_idx, def)| {
                    (
                        def.function,
                        FunctionDefinitionIndex(TableIndex::try_from(def_idx).expect(
                            "function_defs count exceeds u16; binary format precludes this",
                        )),
                    )
                })
                .collect();
        Self {
            module,
            graph: Graph::new(),
            node_map: HashMap::new(),
            func_handle_def_map,
        }
    }

    fn get_or_add_node(&mut self, node: Node) -> NodeIndex {
        match self.node_map.entry(node) {
            hash_map::Entry::Occupied(entry) => *entry.get(),
            hash_map::Entry::Vacant(entry) => {
                let idx = self.graph.add_node(node);
                entry.insert(idx);
                idx
            }
        }
    }

    fn add_edge(&mut self, node_from: Node, node_to: Node, edge: Edge<'a>) {
        let node_from_idx = self.get_or_add_node(node_from);
        let node_to_idx = self.get_or_add_node(node_to);
        self.graph.add_edge(node_from_idx, node_to_idx, edge);
    }

    /// Extract every distinct `TypeParameter(idx)` from a
    /// signature token's preorder.
    fn extract_type_parameters(ty: &SignatureToken) -> HashSet<TypeParameterIndex> {
        let mut out = HashSet::new();
        extract_type_parameters_rec(&mut out, ty);
        out
    }

    // `caller_idx` / `callee_idx` are intentionally paired
    // names per upstream; semantic clarity outweighs the
    // similar-names lint here.
    #[allow(
        clippy::similar_names,
        reason = "caller/callee are paired upstream-faithful naming"
    )]
    fn build_graph_call(
        &mut self,
        caller_idx: FunctionDefinitionIndex,
        callee_idx: FunctionDefinitionIndex,
        type_actuals_idx: SignatureIndex,
    ) {
        let type_actuals = &self.module.signatures[type_actuals_idx.0 as usize].0;
        for (formal_idx, ty) in type_actuals.iter().enumerate() {
            let formal_idx = TypeParameterIndex::try_from(formal_idx)
                .expect("type-actuals count exceeds u16; binary format precludes this");
            match ty {
                SignatureToken::TypeParameter(actual_idx) => self.add_edge(
                    Node(caller_idx, *actual_idx),
                    Node(callee_idx, formal_idx),
                    Edge::Identity,
                ),
                _ => {
                    for type_param in Self::extract_type_parameters(ty) {
                        self.add_edge(
                            Node(caller_idx, type_param),
                            Node(callee_idx, formal_idx),
                            Edge::TyConApp(ty),
                        );
                    }
                }
            }
        }
    }

    fn build_graph_function_def(&mut self, caller_idx: FunctionDefinitionIndex) {
        let caller_def = &self.module.function_defs[caller_idx.0 as usize];
        let Some(code) = &caller_def.code else { return };
        for instr in &code.code {
            let bc = match instr {
                BytecodeInstruction::Inherited(bc) => bc,
                // Adamant extensions per §6.2.1.4: none are
                // CallGeneric-flavored. No edges introduced.
                BytecodeInstruction::Adamant(_) => continue,
            };
            if let Bytecode::CallGeneric(callee_inst_idx) = bc {
                let callee_si = &self.module.function_instantiations[callee_inst_idx.0 as usize];
                if let Some(callee_idx) = self.func_handle_def_map.get(&callee_si.handle) {
                    self.build_graph_call(caller_idx, *callee_idx, callee_si.type_parameters);
                }
            }
        }
    }

    fn build_graph(&mut self) {
        // Native-function filter — implicit-filter sub-pattern
        // of structural-impossibility-checks. Rule 4 rejects
        // native functions at an earlier pass; this filter is
        // defense-in-depth and matches upstream byte-faithfully.
        let caller_indices: Vec<FunctionDefinitionIndex> = self
            .module
            .function_defs
            .iter()
            .enumerate()
            .filter(|(_, def)| !def.is_native())
            .map(|(def_idx, _)| {
                FunctionDefinitionIndex(
                    TableIndex::try_from(def_idx)
                        .expect("function_defs count exceeds u16; binary format precludes this"),
                )
            })
            .collect();
        for caller_idx in caller_indices {
            self.build_graph_function_def(caller_idx);
        }
    }

    /// Find the first non-trivial SCC containing ≥1 `TyConApp`
    /// edge. "First" follows `tarjan_scc`'s discovery order.
    fn find_first_non_trivial_component(&self) -> Option<(Vec<NodeIndex>, Vec<EdgeIndex>)> {
        for nodes in tarjan_scc(&self.graph) {
            let node_set: HashSet<_> = nodes.iter().copied().collect();
            let edges: Vec<EdgeIndex> = nodes
                .iter()
                .flat_map(|node_idx| {
                    self.graph.edges(*node_idx).filter_map(|edge| {
                        if node_set.contains(&edge.target()) {
                            Some(edge.id())
                        } else {
                            None
                        }
                    })
                })
                .collect();
            if edges.iter().any(|edge_idx| {
                matches!(
                    self.graph.edge_weight(*edge_idx).unwrap(),
                    Edge::TyConApp(_)
                )
            }) {
                return Some((nodes, edges));
            }
        }
        None
    }

    fn format_node(&self, node_idx: NodeIndex) -> String {
        let Node(def_idx, param_idx) = self.graph.node_weight(node_idx).unwrap();
        format!("f{def_idx}#{param_idx}")
    }

    fn format_edge(&self, edge_idx: EdgeIndex) -> String {
        let (n1, n2) = self.graph.edge_endpoints(edge_idx).unwrap();
        let s1 = self.format_node(n1);
        let s2 = self.format_node(n2);
        match self.graph.edge_weight(edge_idx).unwrap() {
            Edge::TyConApp(ty) => format!("{s1} --{ty:?}--> {s2}"),
            Edge::Identity => format!("{s1} ----> {s2}"),
        }
    }

    fn format_component(&self, nodes: Vec<NodeIndex>, edges: Vec<EdgeIndex>) -> String {
        let msg_edges = edges
            .into_iter()
            .filter_map(|edge_idx| {
                if matches!(self.graph.edge_weight(edge_idx).unwrap(), Edge::TyConApp(_)) {
                    Some(self.format_edge(edge_idx))
                } else {
                    None
                }
            })
            .collect::<Vec<_>>()
            .join(", ");
        let msg_nodes = nodes
            .into_iter()
            .map(|node_idx| self.format_node(node_idx))
            .collect::<Vec<_>>()
            .join(", ");
        format!("edges with constructors: [{msg_edges}], nodes: [{msg_nodes}]")
    }
}

#[cfg(test)]
mod tests {
    use adamant_bytecode_format::{
        AbilitySet, AddressIdentifierIndex, Bytecode, FunctionHandle, FunctionHandleIndex,
        FunctionInstantiation, FunctionInstantiationIndex, Identifier, IdentifierIndex,
        ModuleHandle, ModuleHandleIndex, Signature, SignatureIndex, SignatureToken, Visibility,
    };
    use adamant_types::Address as AccountAddress;

    use crate::bytecode::BytecodeInstruction;
    use crate::module::{AdamantCodeUnit, AdamantCompiledModule, AdamantFunctionDefinition};

    use super::super::super::error::AdamantValidationError;
    use super::super::test_helpers::assert_pass_parity;
    use super::verify;

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

    fn push_identifier(m: &mut AdamantCompiledModule, name: &str) -> IdentifierIndex {
        let idx = IdentifierIndex(u16::try_from(m.identifiers.len()).unwrap());
        m.identifiers.push(Identifier::new(name).unwrap());
        idx
    }

    fn push_signature(
        m: &mut AdamantCompiledModule,
        tokens: Vec<SignatureToken>,
    ) -> SignatureIndex {
        let idx = SignatureIndex(u16::try_from(m.signatures.len()).unwrap());
        m.signatures.push(Signature(tokens));
        idx
    }

    /// Push a generic function handle with `n` type parameters
    /// and return its index.
    fn push_generic_fn_handle(
        m: &mut AdamantCompiledModule,
        name: &str,
        n_type_params: usize,
    ) -> FunctionHandleIndex {
        let name_idx = push_identifier(m, name);
        let empty_sig = push_signature(m, vec![]);
        let idx = FunctionHandleIndex(u16::try_from(m.function_handles.len()).unwrap());
        m.function_handles.push(FunctionHandle {
            module: ModuleHandleIndex(0),
            name: name_idx,
            parameters: empty_sig,
            return_: empty_sig,
            type_parameters: vec![AbilitySet::EMPTY; n_type_params],
        });
        idx
    }

    /// Push a function instantiation referencing the given
    /// handle with the given type-arguments signature.
    fn push_fn_inst(
        m: &mut AdamantCompiledModule,
        handle: FunctionHandleIndex,
        type_args_sig: SignatureIndex,
    ) -> FunctionInstantiationIndex {
        let idx =
            FunctionInstantiationIndex(u16::try_from(m.function_instantiations.len()).unwrap());
        m.function_instantiations.push(FunctionInstantiation {
            handle,
            type_parameters: type_args_sig,
        });
        idx
    }

    /// Push a function definition with the given handle and
    /// body, with `code: Some(...)` (non-native).
    fn push_fn_def(
        m: &mut AdamantCompiledModule,
        function: FunctionHandleIndex,
        body: Vec<BytecodeInstruction>,
    ) {
        let empty_sig = SignatureIndex(0);
        m.function_defs.push(AdamantFunctionDefinition {
            function,
            visibility: Visibility::Private,
            is_entry: false,
            acquires_global_resources: vec![],
            code: Some(AdamantCodeUnit {
                locals: empty_sig,
                code: body,
                jump_tables: vec![],
            }),
        });
    }

    fn inh(bc: Bytecode) -> BytecodeInstruction {
        BytecodeInstruction::Inherited(bc)
    }

    // ============================================================
    // Layer A — positives
    // ============================================================

    #[test]
    fn empty_module_passes() {
        let m = empty_module();
        assert!(verify(&m).is_ok());
    }

    #[test]
    fn function_with_no_call_generic_passes() {
        let mut m = empty_module();
        let h = push_generic_fn_handle(&mut m, "f", 1);
        push_fn_def(&mut m, h, vec![inh(Bytecode::Ret)]);
        assert!(verify(&m).is_ok());
    }

    #[test]
    fn identity_only_self_cycle_passes() {
        // f<T> calls f<T> — Identity edge, no type growth.
        let mut m = empty_module();
        let h = push_generic_fn_handle(&mut m, "f", 1);
        let type_args = push_signature(&mut m, vec![SignatureToken::TypeParameter(0)]);
        let inst = push_fn_inst(&mut m, h, type_args);
        push_fn_def(
            &mut m,
            h,
            vec![inh(Bytecode::CallGeneric(inst)), inh(Bytecode::Ret)],
        );
        assert!(verify(&m).is_ok());
    }

    #[test]
    fn linear_tyconapp_no_cycle_passes() {
        // f<T> calls g<Vec<T>> — TyConApp edge, but no cycle
        // since g doesn't call back.
        let mut m = empty_module();
        let h_f = push_generic_fn_handle(&mut m, "f", 1);
        let h_g = push_generic_fn_handle(&mut m, "g", 1);
        let type_args = push_signature(
            &mut m,
            vec![SignatureToken::Vector(Box::new(
                SignatureToken::TypeParameter(0),
            ))],
        );
        let inst = push_fn_inst(&mut m, h_g, type_args);
        push_fn_def(
            &mut m,
            h_f,
            vec![inh(Bytecode::CallGeneric(inst)), inh(Bytecode::Ret)],
        );
        push_fn_def(&mut m, h_g, vec![inh(Bytecode::Ret)]);
        assert!(verify(&m).is_ok());
    }

    #[test]
    fn adamant_extension_does_not_introduce_edge() {
        // f<T> body contains an Adamant extension; no
        // CallGeneric. No edges added; pass passes.
        let mut m = empty_module();
        let h = push_generic_fn_handle(&mut m, "f", 1);
        push_fn_def(
            &mut m,
            h,
            vec![
                BytecodeInstruction::Adamant(crate::bytecode::AdamantBytecode::Sha3_256),
                inh(Bytecode::Ret),
            ],
        );
        assert!(verify(&m).is_ok());
    }

    // ============================================================
    // Layer A — negatives
    // ============================================================

    #[test]
    fn rejects_self_edge_with_tyconapp() {
        // f<T> calls f<Vec<T>> — TyConApp self-edge, type
        // grows on each cycle.
        let mut m = empty_module();
        let h = push_generic_fn_handle(&mut m, "f", 1);
        let type_args = push_signature(
            &mut m,
            vec![SignatureToken::Vector(Box::new(
                SignatureToken::TypeParameter(0),
            ))],
        );
        let inst = push_fn_inst(&mut m, h, type_args);
        push_fn_def(
            &mut m,
            h,
            vec![inh(Bytecode::CallGeneric(inst)), inh(Bytecode::Ret)],
        );
        assert!(matches!(
            verify(&m),
            Err(AdamantValidationError::LoopInInstantiationGraph { .. })
        ));
    }

    #[test]
    fn rejects_two_function_tyconapp_cycle() {
        // f<T> calls g<Vec<T>>; g<U> calls f<U>.
        // g→f edge: Identity. f→g edge: TyConApp.
        // Cycle has TyConApp ⇒ reject.
        let mut m = empty_module();
        let h_f = push_generic_fn_handle(&mut m, "f", 1);
        let h_g = push_generic_fn_handle(&mut m, "g", 1);
        let f_to_g_args = push_signature(
            &mut m,
            vec![SignatureToken::Vector(Box::new(
                SignatureToken::TypeParameter(0),
            ))],
        );
        let g_to_f_args = push_signature(&mut m, vec![SignatureToken::TypeParameter(0)]);
        let inst_f_to_g = push_fn_inst(&mut m, h_g, f_to_g_args);
        let inst_g_to_f = push_fn_inst(&mut m, h_f, g_to_f_args);
        push_fn_def(
            &mut m,
            h_f,
            vec![inh(Bytecode::CallGeneric(inst_f_to_g)), inh(Bytecode::Ret)],
        );
        push_fn_def(
            &mut m,
            h_g,
            vec![inh(Bytecode::CallGeneric(inst_g_to_f)), inh(Bytecode::Ret)],
        );
        assert!(matches!(
            verify(&m),
            Err(AdamantValidationError::LoopInInstantiationGraph { .. })
        ));
    }

    #[test]
    fn rejects_three_function_tyconapp_cycle() {
        // f<T> → g<Vec<T>>, g<U> → h<U>, h<V> → f<V>.
        let mut m = empty_module();
        let h_f = push_generic_fn_handle(&mut m, "f", 1);
        let h_g = push_generic_fn_handle(&mut m, "g", 1);
        let h_h = push_generic_fn_handle(&mut m, "h", 1);
        let f_to_g_args = push_signature(
            &mut m,
            vec![SignatureToken::Vector(Box::new(
                SignatureToken::TypeParameter(0),
            ))],
        );
        let identity_args = push_signature(&mut m, vec![SignatureToken::TypeParameter(0)]);
        let inst_f_to_g = push_fn_inst(&mut m, h_g, f_to_g_args);
        let inst_g_to_h = push_fn_inst(&mut m, h_h, identity_args);
        let inst_h_to_f = push_fn_inst(&mut m, h_f, identity_args);
        push_fn_def(
            &mut m,
            h_f,
            vec![inh(Bytecode::CallGeneric(inst_f_to_g)), inh(Bytecode::Ret)],
        );
        push_fn_def(
            &mut m,
            h_g,
            vec![inh(Bytecode::CallGeneric(inst_g_to_h)), inh(Bytecode::Ret)],
        );
        push_fn_def(
            &mut m,
            h_h,
            vec![inh(Bytecode::CallGeneric(inst_h_to_f)), inh(Bytecode::Ret)],
        );
        assert!(matches!(
            verify(&m),
            Err(AdamantValidationError::LoopInInstantiationGraph { .. })
        ));
    }

    #[test]
    fn rejects_deep_tyconapp_nesting_self_cycle() {
        // f<T> calls f<Vec<Vec<T>>>.
        let mut m = empty_module();
        let h = push_generic_fn_handle(&mut m, "f", 1);
        let nested = SignatureToken::Vector(Box::new(SignatureToken::Vector(Box::new(
            SignatureToken::TypeParameter(0),
        ))));
        let type_args = push_signature(&mut m, vec![nested]);
        let inst = push_fn_inst(&mut m, h, type_args);
        push_fn_def(
            &mut m,
            h,
            vec![inh(Bytecode::CallGeneric(inst)), inh(Bytecode::Ret)],
        );
        assert!(matches!(
            verify(&m),
            Err(AdamantValidationError::LoopInInstantiationGraph { .. })
        ));
    }

    #[test]
    fn rejects_mixed_identity_and_tyconapp_cycle() {
        // f<T> calls g<T> (Identity); g<U> calls f<Vec<U>> (TyConApp).
        // SCC has both edge types; the TyConApp edge triggers rejection.
        let mut m = empty_module();
        let h_f = push_generic_fn_handle(&mut m, "f", 1);
        let h_g = push_generic_fn_handle(&mut m, "g", 1);
        let identity_args = push_signature(&mut m, vec![SignatureToken::TypeParameter(0)]);
        let tyconapp_args = push_signature(
            &mut m,
            vec![SignatureToken::Vector(Box::new(
                SignatureToken::TypeParameter(0),
            ))],
        );
        let inst_f_to_g = push_fn_inst(&mut m, h_g, identity_args);
        let inst_g_to_f = push_fn_inst(&mut m, h_f, tyconapp_args);
        push_fn_def(
            &mut m,
            h_f,
            vec![inh(Bytecode::CallGeneric(inst_f_to_g)), inh(Bytecode::Ret)],
        );
        push_fn_def(
            &mut m,
            h_g,
            vec![inh(Bytecode::CallGeneric(inst_g_to_f)), inh(Bytecode::Ret)],
        );
        assert!(matches!(
            verify(&m),
            Err(AdamantValidationError::LoopInInstantiationGraph { .. })
        ));
    }

    #[test]
    fn identity_only_two_function_cycle_passes() {
        // f<T> calls g<T>; g<U> calls f<U>. No TyConApp;
        // identity-only cycle is allowed.
        let mut m = empty_module();
        let h_f = push_generic_fn_handle(&mut m, "f", 1);
        let h_g = push_generic_fn_handle(&mut m, "g", 1);
        let identity_args = push_signature(&mut m, vec![SignatureToken::TypeParameter(0)]);
        let inst_f_to_g = push_fn_inst(&mut m, h_g, identity_args);
        let inst_g_to_f = push_fn_inst(&mut m, h_f, identity_args);
        push_fn_def(
            &mut m,
            h_f,
            vec![inh(Bytecode::CallGeneric(inst_f_to_g)), inh(Bytecode::Ret)],
        );
        push_fn_def(
            &mut m,
            h_g,
            vec![inh(Bytecode::CallGeneric(inst_g_to_f)), inh(Bytecode::Ret)],
        );
        assert!(verify(&m).is_ok());
    }

    #[test]
    fn rejects_with_byte_faithful_component_summary() {
        // Pin the component_summary format byte-faithfully
        // against the upstream template. f<T> calls f<Vec<T>>:
        // - SCC nodes: f0#0 (single node)
        // - TyConApp edge: f0#0 --Vector(TypeParameter(0))--> f0#0
        // - format: "edges with constructors: [<edge>], nodes: [<node>]"
        let mut m = empty_module();
        let h = push_generic_fn_handle(&mut m, "f", 1);
        let type_args = push_signature(
            &mut m,
            vec![SignatureToken::Vector(Box::new(
                SignatureToken::TypeParameter(0),
            ))],
        );
        let inst = push_fn_inst(&mut m, h, type_args);
        push_fn_def(
            &mut m,
            h,
            vec![inh(Bytecode::CallGeneric(inst)), inh(Bytecode::Ret)],
        );
        match verify(&m) {
            Err(AdamantValidationError::LoopInInstantiationGraph { component_summary }) => {
                // Format check: must start with "edges with
                // constructors: [" and contain a node-list
                // suffix matching upstream's template.
                assert!(
                    component_summary.starts_with("edges with constructors: ["),
                    "unexpected prefix in component_summary: {component_summary}"
                );
                assert!(
                    component_summary.contains("], nodes: ["),
                    "unexpected separator in component_summary: {component_summary}"
                );
                assert!(
                    component_summary.ends_with(']'),
                    "unexpected suffix in component_summary: {component_summary}"
                );
                // The single node is f0#0 (function 0, type
                // parameter 0).
                assert!(
                    component_summary.contains("f0#0"),
                    "missing f0#0 node in component_summary: {component_summary}"
                );
                // The TyConApp edge contains the Debug form
                // of the actual_type — verifies upstream's
                // `--{:?}-->` template byte-faithfully.
                assert!(
                    component_summary.contains("--Vector(TypeParameter(0))-->"),
                    "missing Debug-formatted edge in component_summary: {component_summary}"
                );
            }
            other => panic!("expected LoopInInstantiationGraph, got {other:?}"),
        }
    }

    // ============================================================
    // Layer B — cross-validation against vendored Sui
    // ============================================================

    fn cross_validate_pass(m: &AdamantCompiledModule) {
        let adamant_result = verify(m);
        let sui_module = m
            .to_sui_module()
            .expect("test fixture has no Adamant extensions; to_sui_module must succeed");
        let sui_result =
            move_bytecode_verifier::instantiation_loops::InstantiationLoopChecker::verify_module(
                &sui_module,
            );
        assert_pass_parity("instantiation_loops", adamant_result, sui_result);
    }

    #[test]
    fn cross_validation_accepts_empty_module() {
        cross_validate_pass(&empty_module());
    }

    #[test]
    fn cross_validation_accepts_function_with_no_call_generic() {
        let mut m = empty_module();
        let h = push_generic_fn_handle(&mut m, "f", 1);
        push_fn_def(&mut m, h, vec![inh(Bytecode::Ret)]);
        cross_validate_pass(&m);
    }

    #[test]
    fn cross_validation_accepts_identity_only_self_cycle() {
        let mut m = empty_module();
        let h = push_generic_fn_handle(&mut m, "f", 1);
        let type_args = push_signature(&mut m, vec![SignatureToken::TypeParameter(0)]);
        let inst = push_fn_inst(&mut m, h, type_args);
        push_fn_def(
            &mut m,
            h,
            vec![inh(Bytecode::CallGeneric(inst)), inh(Bytecode::Ret)],
        );
        cross_validate_pass(&m);
    }

    #[test]
    fn cross_validation_rejects_self_edge_with_tyconapp() {
        let mut m = empty_module();
        let h = push_generic_fn_handle(&mut m, "f", 1);
        let type_args = push_signature(
            &mut m,
            vec![SignatureToken::Vector(Box::new(
                SignatureToken::TypeParameter(0),
            ))],
        );
        let inst = push_fn_inst(&mut m, h, type_args);
        push_fn_def(
            &mut m,
            h,
            vec![inh(Bytecode::CallGeneric(inst)), inh(Bytecode::Ret)],
        );
        cross_validate_pass(&m);
    }

    #[test]
    fn cross_validation_rejects_two_function_tyconapp_cycle() {
        let mut m = empty_module();
        let h_f = push_generic_fn_handle(&mut m, "f", 1);
        let h_g = push_generic_fn_handle(&mut m, "g", 1);
        let f_to_g_args = push_signature(
            &mut m,
            vec![SignatureToken::Vector(Box::new(
                SignatureToken::TypeParameter(0),
            ))],
        );
        let g_to_f_args = push_signature(&mut m, vec![SignatureToken::TypeParameter(0)]);
        let inst_f_to_g = push_fn_inst(&mut m, h_g, f_to_g_args);
        let inst_g_to_f = push_fn_inst(&mut m, h_f, g_to_f_args);
        push_fn_def(
            &mut m,
            h_f,
            vec![inh(Bytecode::CallGeneric(inst_f_to_g)), inh(Bytecode::Ret)],
        );
        push_fn_def(
            &mut m,
            h_g,
            vec![inh(Bytecode::CallGeneric(inst_g_to_f)), inh(Bytecode::Ret)],
        );
        cross_validate_pass(&m);
    }

    #[test]
    fn cross_validation_accepts_linear_tyconapp_no_cycle() {
        let mut m = empty_module();
        let h_f = push_generic_fn_handle(&mut m, "f", 1);
        let h_g = push_generic_fn_handle(&mut m, "g", 1);
        let type_args = push_signature(
            &mut m,
            vec![SignatureToken::Vector(Box::new(
                SignatureToken::TypeParameter(0),
            ))],
        );
        let inst = push_fn_inst(&mut m, h_g, type_args);
        push_fn_def(
            &mut m,
            h_f,
            vec![inh(Bytecode::CallGeneric(inst)), inh(Bytecode::Ret)],
        );
        push_fn_def(&mut m, h_g, vec![inh(Bytecode::Ret)]);
        cross_validate_pass(&m);
    }
}
