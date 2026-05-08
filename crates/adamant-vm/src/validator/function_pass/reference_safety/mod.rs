//! Adamant-native reference-safety verifier pass (whitepaper
//! §6.2.1.6 Rule "reference safety": borrowed references do not
//! outlive the values they reference; mutable references are
//! not aliased).
//!
//! Forked byte-faithfully from
//! `vendor/move-bytecode-verifier/src/reference_safety/` at
//! Sui-Move tag `mainnet-v1.66.2`. Port shape:
//!
//! - **D-5b.1 (this commit).** [`borrow_graph`] foundation port:
//!   inline single-file consolidation of
//!   `vendor/move-borrow-graph/`'s 4 source files (graph.rs +
//!   references.rs + paths.rs + shared.rs; ~778 LOC upstream)
//!   into a single Adamant-native module. Sub-shape α (inline
//!   within `adamant-vm`) of the vendored-Sui-crates-port
//!   canonical principle; **5th instance** after D-1a (CFG),
//!   D-1b (`AbstractInterpreter`), D-2 (`LoopSummary`), D-5a.0
//!   (`AbstractStack`). Sub-shape β (Adamant-native crate fork)
//!   remains 0 instances; forward-tracking option if AVM runtime
//!   sub-arc later needs reusable borrow-graph mechanics. No
//!   typed-error variants ship at D-5b.1 per Rust error-type
//!   lifecycle (variants land alongside producer at D-5b.2).
//! - **D-5b.2.** Reference-safety pass: `mod.rs` + `abstract_state.rs`
//!   from `vendor/move-bytecode-verifier/src/reference_safety/`
//!   (~1668 LOC upstream); 2nd consumer of D-1b's
//!   [`AbstractInterpreter`][AI] framework; declares
//!   [`BorrowViolation`] typed variant + `BorrowViolationReason`
//!   closed enum (8th deliberate-Adamant-decision instance —
//!   subject to empirical recount per Q7 deliberate-Adamant-
//!   decision count discrepancy flag at D-5b plan-gate); 17
//!   Adamant-extension reference rules per §6.2.1.4 (Cat A fail
//!   open at borrow-graph layer; Cat B reuse `call` helper —
//!   2nd instance of spec-text-to-shared-helper canonical
//!   principle; Cat C/D fail open per §7/§8.5 deferral — 3rd
//!   cross-pass consistency instance of shielding-vs-runtime
//!   canonical pattern, rule-of-three threshold met for
//!   shielding-vs-runtime); orchestration chain wire-in.
//!
//! [AI]: super::absint::AbstractInterpreter
//! [`BorrowViolation`]: super::super::error::AdamantValidationError
//!
//! # D-5b sub-arc framing
//!
//! D-5b was split into D-5b.1 + D-5b.2 at D-5b plan-gate per
//! quality-over-speed discipline (CLAUDE.md Section 4); sub-shape 2
//! (pre-arc-split) of empirical-complexity-drives-sub-checkpoint-
//! shape pattern, **3rd instance** after D-1 (D-1a + D-1b at D-1
//! plan-gate) and D-5 (D-5a + D-5b + D-5c at D-5 plan-gate).
//! Rule-of-three threshold met for sub-shape 2 specifically;
//! PROVENANCE.md canonical at D-7.
//!
//! # Genesis-fixed structural bound carry-forward
//!
//! `MAX_EDGE_SET_SIZE = 10` (in [`borrow_graph`]) is consensus-
//! binding: when a borrow-edge set hits the cap, the set
//! becomes "lossy" and is treated as borrowing any possible edge
//! from the source reference. This affects the verifier's
//! accept/reject decision and is therefore genesis-fixed. Adds
//! to the §6.2.1.7 spec-amendment workstream carry-forward
//! (CLAUDE.md "Open properties to track" item 5a — structural-
//! limits values registered for spec amendment). Pre-mainnet
//! workstream raises a §6.2.1.7 amendment proposal to enumerate
//! `MAX_EDGE_SET_SIZE` alongside the other structural-limits
//! values (`max_constant_vector_len`, `max_push_size`,
//! `max_loop_depth`, etc.).
//!
//! # Cross-pass-pipeline-dependency
//!
//! Reference-safety lands at D-5b.2 in step 4 ordering after
//! type-safety (D-5a.1.b). Preconditions:
//!
//! - **Step 3** (`module_pass::bounds_checker`,
//!   `signature_checker`, `instruction_consistency`): handle
//!   and signature-pool indices validated.
//! - **Step 4 D-2** (`function_pass::control_flow`): non-empty
//!   reducible CFG.
//! - **Step 4 D-3** (`function_pass::stack_usage`): per-block
//!   stack balance.
//! - **Step 4 D-4** (`function_pass::locals_safety`): locals
//!   availability.
//! - **Step 4 D-5a.1** (`function_pass::type_safety`): operand
//!   types match instruction expectations; reference-safety
//!   assumes type-safe operands.

#![allow(dead_code)] // D-5b.1 foundation; first consumer (reference-safety pass) lands at D-5b.2.

pub(super) mod borrow_graph;
