//! Adamant validator configuration.
//!
//! [`AdamantVerifierConfig`] carries [`AdamantStructuralLimits`]
//! — the consensus-binding structural-limits configuration per
//! whitepaper §6.2.1.7. Phase 5/5b.5 E-1a tear-out removed the
//! previously-wrapped Sui-side `BinaryConfig` and `VerifierConfig`
//! fields when the transitional Sui-verifier bridge was removed
//! from the pipeline; Adamant's deserializer carries Rule 5
//! enforcement, and the Adamant-native module-level + per-
//! function passes carry the rest.
//!
//! Future configuration knobs (e.g., Rule 6's
//! `b"adamant.allows_dynamic"` opt-in once that rule lands)
//! extend this struct rather than re-introducing Sui's config
//! types — the resistant-proof posture per §6.2.1.8 keeps the
//! validator config Adamant-owned.

// Sui-side `BinaryConfig` / `VerifierConfig` imports removed at
// Phase 5/5b.5 E-1a alongside the bridge tear-out.

/// Adamant-native structural-limits configuration.
///
/// Consumed by the Phase 5/5b.2 module-level passes (B-3's
/// `limits` pass, plus identifier-length / variant-count checks
/// in adjacent passes). Mirrors Sui's `VerifierConfig` shape
/// for the structural-limits subset, with field names matching
/// upstream so the byte-faithfulness audit anchor is direct
/// (auditors comparing Adamant's pass against Sui's same pass
/// see the same field names on both sides).
///
/// Per whitepaper §6.2.1.7, the gas table and structural
/// limits are **genesis-fixed**; once mainnet launches, no on-
/// chain mechanism can change these values. Bumping a value
/// post-genesis requires a hard fork. The defaults below
/// mirror Sui-Move's `VerifierConfig::default()` at vendored
/// tag `mainnet-v1.66.2` *literally*: most fields are `None`
/// (no limit). Sui's posture is consensus-derived from their
/// production environment; Adamant inherits the literal values
/// at this stage and **defers a deliberate calibration pass to
/// pre-mainnet hardening**. See CLAUDE.md "Open properties to
/// track" for the calibration item.
///
/// Field shape (`Option<...>`) preserves Sui's "no limit when
/// `None`" semantics so the limits pass can short-circuit
/// per-field exactly as upstream does. The shape also lets
/// pre-mainnet calibration switch any field from `None` to
/// `Some(value)` without changing the pass logic.
#[derive(Debug, Clone)]
#[allow(
    dead_code,
    reason = "fields consumed by the `limits` module-level pass in Phase 5/5b.2 B-3"
)]
pub(super) struct AdamantStructuralLimits {
    /// Maximum number of type parameters on a single handle
    /// (function or datatype). Mirrors Sui's
    /// `max_generic_instantiation_length`.
    pub(super) max_generic_instantiation_length: Option<usize>,
    /// Maximum number of parameters on a single function
    /// signature.
    pub(super) max_function_parameters: Option<usize>,
    /// Maximum number of nodes in a single signature-token tree
    /// after preorder traversal. Sui weights `Datatype` /
    /// `DatatypeInstantiation` and `TypeParameter` nodes more
    /// heavily than primitives; Adamant preserves the same
    /// weighting.
    pub(super) max_type_nodes: Option<usize>,
    /// Maximum number of function definitions per module.
    pub(super) max_function_definitions: Option<usize>,
    /// Maximum total number of struct + enum definitions per
    /// module.
    pub(super) max_data_definitions: Option<usize>,
    /// Maximum number of fields per struct (and per enum
    /// variant, summed across variants).
    pub(super) max_fields_in_struct: Option<usize>,
    /// Maximum number of variants per enum.
    pub(super) max_variants_in_enum: Option<u64>,
    /// Maximum number of elements in a constant-pool vector
    /// value.
    pub(super) max_constant_vector_len: Option<u64>,
    /// Maximum byte length of an identifier.
    pub(super) max_identifier_len: Option<u64>,
    /// If true, reject the literal identifier `<SELF>` (a Move
    /// internal sentinel that should never appear in user code).
    pub(super) disallow_self_identifier: bool,
    /// Maximum loop nesting depth permitted in any single
    /// function body. Consumed by the per-function
    /// reducibility check at Phase 5/5b.4 D-2
    /// (`function_pass::control_flow::verify_reducibility`).
    /// `None` disables the check; `Some(N)` rejects bodies
    /// whose loop nesting collapses to depth > N.
    pub(super) max_loop_depth: Option<u16>,
    /// Maximum total push count per basic block. Consumed by
    /// the per-function operand-stack discipline check at
    /// Phase 5/5b.4 D-3
    /// (`function_pass::stack_usage::verify_block`). `None`
    /// disables the check; `Some(N)` rejects blocks whose
    /// accumulated push count exceeds N. Distinct from
    /// `max_value_stack_size` (a runtime concern; lives in the
    /// AVM runtime config in the Phase 5/6.3 sub-arc per
    /// whitepaper §6.3).
    pub(super) max_push_size: Option<u64>,
}

impl AdamantStructuralLimits {
    /// Build the consensus-genesis structural limits.
    ///
    /// Adamant's verifier is the consensus boundary for
    /// structural limits; unlike Sui (whose verifier ships
    /// `None` defaults that are overridden by Sui's higher-
    /// layer protocol-config bound), Adamant has no upstream
    /// layer to backstop missing bounds. `None` here would
    /// expose validators to deploy-time denial-of-service
    /// through unbounded module shapes. Every field is
    /// therefore concrete.
    ///
    /// Three buckets per the Phase 5/5b.2 design proposal:
    ///
    /// - **Bucket A — Sui's commented alternative.** Sui's
    ///   `VerifierConfig::default()` ships `None` for these
    ///   fields and carries commented-out alternatives Sui has
    ///   considered but not activated. Adamant adopts them
    ///   directly except where deviation reasoning is
    ///   documented. See
    ///   `vendor/move-vm-config/src/verifier.rs:70-75`.
    ///
    /// - **Bucket B — Sui's literal default.** Sui ships a
    ///   concrete value at the verifier layer; Adamant
    ///   mirrors except where defense-in-depth dictates
    ///   otherwise.
    ///
    /// - **Bucket C — spec gap.** Sui has neither a literal
    ///   nor a commented alternative; Adamant ships
    ///   provisional values with reasoning documented in
    ///   `module_pass/PROVENANCE.md`. Pre-mainnet workstream
    ///   raises a §6.2.1.7 amendment proposal to enumerate
    ///   structural limits at the spec level; provisional
    ///   values are subject to deliberate review at that
    ///   amendment.
    pub(super) fn genesis() -> Self {
        Self {
            // Bucket C (spec gap, provisional — see
            // module_pass/PROVENANCE.md for DoS/memory/
            // practical reasoning behind each value).
            max_generic_instantiation_length: Some(32),
            max_function_parameters: Some(128),
            max_type_nodes: Some(256),
            // Bucket A (adopt Sui's commented alternative
            // verbatim).
            max_function_definitions: Some(1000),
            max_data_definitions: Some(200),
            // Bucket A (diverged): Sui's commented value is
            // Some(30); Adamant ships Some(50) to give
            // headroom for legitimate configuration / circuit-
            // witness structs that can plausibly hit 30 fields
            // when extension instructions inflate the field
            // count modestly. Memory bound stays tight (50
            // fields × ~16 bytes = 800 B per struct, 200
            // structs per module = ~160 KB worst case).
            // Documented in module_pass/PROVENANCE.md.
            max_fields_in_struct: Some(50),
            // Bucket B (mirror Sui's literal default).
            max_variants_in_enum: Some(move_vm_config::verifier::DEFAULT_MAX_VARIANTS),
            max_constant_vector_len: Some(
                move_vm_config::verifier::DEFAULT_MAX_CONSTANT_VECTOR_LEN,
            ),
            max_identifier_len: Some(move_vm_config::verifier::DEFAULT_MAX_IDENTIFIER_LENGTH),
            // Bucket B (defense-in-depth flip from Sui's
            // false). The `<SELF>` literal is a Move-internal
            // sentinel that should never appear in deployed
            // bytecode; Sui's permissive default is safe
            // because of Sui's layered architecture, but
            // Adamant's verifier is the security boundary.
            // Rejecting at zero cost. Documented in
            // module_pass/PROVENANCE.md.
            disallow_self_identifier: true,
            // Bucket C (spec gap, provisional — D-2). Sui ships
            // None with no commented alternative; Adamant's
            // verifier is the consensus boundary, where None
            // would expose validators to deploy-time DoS via
            // pathologically-nested loops (abstract
            // interpretation cost is exponential in nesting
            // depth). Documented in module_pass/PROVENANCE.md
            // "Genesis structural-limits values" — D-2 entry.
            // Pre-mainnet calibration tracked under §6.2.1.7
            // amendment workstream.
            max_loop_depth: Some(64),
            // Bucket A (D-3 — adopt Sui's commented
            // alternative verbatim). Sui ships None at
            // `vendor/move-vm-config/src/verifier.rs:61` with
            // a commented `Some(10000)` at lines 70-71.
            // Adamant adopts the commented value: bounds
            // runaway-growth within any single basic block at
            // deploy time. Documented in
            // module_pass/PROVENANCE.md "Genesis structural-
            // limits values" — D-3 entry. Pre-mainnet
            // calibration tracked under §6.2.1.7 amendment
            // workstream.
            max_push_size: Some(10000),
        }
    }
}

impl Default for AdamantStructuralLimits {
    fn default() -> Self {
        Self::genesis()
    }
}

/// Configuration for the Adamant validator.
///
/// Carries [`AdamantStructuralLimits`] for the module-level and
/// per-function passes. Phase 5/5b.5 E-1a tear-out removed the
/// previously-wrapped Sui-side `BinaryConfig` and `VerifierConfig`
/// fields when the transitional Sui-verifier bridge was removed
/// from the pipeline; the Adamant-native limits are now the only
/// configuration surface, and §6.2.1.6 Rule 5 enforcement lives
/// entirely in [`crate::adamant_deserialize`]'s strict mode.
#[derive(Debug, Clone)]
pub struct AdamantVerifierConfig {
    structural_limits: AdamantStructuralLimits,
}

impl AdamantVerifierConfig {
    /// Build an Adamant validator config with the genesis
    /// structural limits.
    ///
    /// Pre-Phase-5/5b.5 this constructor also locked down
    /// `deprecate_global_storage_ops = true` on the wrapped Sui
    /// `BinaryConfig` and `VerifierConfig` fields as defense-in-
    /// depth for §6.2.1.6 Rule 5; E-1a tear-out removed those
    /// fields, leaving the Adamant deserializer's strict mode as
    /// the sole Rule 5 enforcement point.
    #[must_use]
    pub fn new() -> Self {
        Self {
            structural_limits: AdamantStructuralLimits::genesis(),
        }
    }

    /// Return a reference to the Adamant-native structural-
    /// limits configuration consumed by the module-level and
    /// per-function passes.
    ///
    /// Crate-internal: callers outside the validator module
    /// should not need to read or override these values; the
    /// genesis defaults are consensus-binding per §6.2.1.7.
    pub(super) fn structural_limits(&self) -> &AdamantStructuralLimits {
        &self.structural_limits
    }
}

impl Default for AdamantVerifierConfig {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::AdamantVerifierConfig;

    #[test]
    fn genesis_structural_limits_match_approved_values() {
        // Pin the Phase 5/5b.2 B-1 approved values per the
        // design-proposal redirect (Buckets A/B/C).
        // Changes to these values are consensus-binding per
        // §6.2.1.7 and must go through the spec-amendment
        // workstream registered in CLAUDE.md "Open properties
        // to track" (§6.2.1.7 enumeration of structural
        // limits). This test pins the values so an accidental
        // change surfaces immediately rather than at deploy
        // time.
        let cfg = AdamantVerifierConfig::new();
        let limits = cfg.structural_limits();

        // Bucket C — spec gap, provisional with reasoning in
        // module_pass/PROVENANCE.md.
        assert_eq!(limits.max_generic_instantiation_length, Some(32));
        assert_eq!(limits.max_function_parameters, Some(128));
        assert_eq!(limits.max_type_nodes, Some(256));

        // Bucket A — Sui's commented alternative.
        assert_eq!(limits.max_function_definitions, Some(1000));
        assert_eq!(limits.max_data_definitions, Some(200));
        // Diverged from Sui's commented Some(30); Adamant
        // ships Some(50) for extension-friendly headroom.
        assert_eq!(limits.max_fields_in_struct, Some(50));

        // Bucket B — Sui's literal default.
        assert_eq!(
            limits.max_constant_vector_len,
            Some(move_vm_config::verifier::DEFAULT_MAX_CONSTANT_VECTOR_LEN)
        );
        assert_eq!(
            limits.max_identifier_len,
            Some(move_vm_config::verifier::DEFAULT_MAX_IDENTIFIER_LENGTH)
        );
        assert_eq!(
            limits.max_variants_in_enum,
            Some(move_vm_config::verifier::DEFAULT_MAX_VARIANTS)
        );
        // Bucket B — defense-in-depth flip from Sui's false.
        // `<SELF>` is a Move-internal sentinel; rejecting at
        // verifier time costs nothing and closes a class of
        // injection attempts.
        assert!(limits.disallow_self_identifier);
    }
}
