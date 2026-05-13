//! Build-system independence check enforcing the resistant-proof
//! posture per CLAUDE.md §14.4 Decision 1 (resolved as Path C2):
//! upstream `halo2_*` crates must not appear in the
//! `adamant-privacy` production-binary's dependency graph.
//!
//! The test walks `cargo metadata`'s resolved dependency tree
//! starting from `adamant-privacy`'s normal (non-dev, non-build)
//! dependency edges and asserts no upstream `halo2_*` crate is
//! reachable. Adamant's own fork crate `adamant-halo2` is
//! permitted (and required); only upstream prefixes
//! (`halo2_proofs`, `halo2_gadgets`, `halo2_poseidon`, etc.) are
//! forbidden.
//!
//! Phase 6.8b.0 adds this check as the mechanical guardrail for
//! the architectural commitment in CLAUDE.md §14.4 Decision 1
//! (resolution paragraph): "The fork lands at Phase 6.8b plan-
//! gate as part of the validity-circuit + recursive-proving
//! implementation work … production-binary's dependency graph
//! [must contain] no upstream `halo2_*` crates."
//!
//! Mirrors `crates/adamant-vm/tests/no_sui_in_production_deps.rs`
//! at the file-shape level; the helper functions are copied
//! verbatim from that Phase 5/5b.5 E-1b precedent (different
//! `FORBIDDEN_PREFIX` and `TARGET_CRATE`, otherwise identical).

use std::collections::HashMap;
use std::process::Command;

/// Upstream Halo 2 ZK proving-system crates (Zcash / Electric
/// Coin Company ecosystem) the resistant-proof posture forbids
/// in the production dependency graph.
///
/// `halo2_legacy_pdqsort` is intentionally NOT in this list —
/// despite the misleading `halo2_` prefix, it is a generic
/// sorting-algorithm crate (a `pdqsort` fork that happened to be
/// created under the halo2 project umbrella) with no ZK content.
/// Phase 6.8b.1 transitively pulls it in via `proofs::poly`.
///
/// If a future upstream crate joins the Halo 2 ecosystem
/// (e.g., a new `halo2_*` proving-system surface), add it to
/// this list with a brief justification in
/// `crates/adamant-halo2/PROVENANCE.md`.
const FORBIDDEN_CRATES: &[&str] = &["halo2_proofs", "halo2_gadgets", "halo2_poseidon"];

/// Adamant-authored production crates whose dependency graphs
/// must not contain any upstream `halo2_*` crate. The fork crate
/// `adamant-halo2` is itself excluded — it IS the Adamant-owned
/// fork that replaces the upstream surface. Every other Adamant
/// production crate (including the binary scaffolds) must keep
/// upstream halo2_* out of its production graph.
const TARGET_CRATES: &[&str] = &[
    "adamant-account",
    "adamant-bytecode-format",
    "adamant-cli",
    "adamant-consensus",
    "adamant-crypto",
    "adamant-crypto-blst-extra",
    "adamant-light",
    "adamant-network",
    "adamant-node",
    "adamant-privacy",
    "adamant-state",
    "adamant-types",
    "adamant-vm",
];

/// Walk `cargo metadata`'s resolve graph starting from each
/// Adamant production crate's normal-kind dependency edges.
/// Asserts no upstream `halo2_*` crate is reachable from any.
#[test]
fn adamant_production_deps_contain_no_upstream_halo2_crates() {
    let metadata_json = run_cargo_metadata();
    let id_to_name = build_id_to_name_map(&metadata_json);
    let mut all_violations: Vec<(String, Vec<String>)> = Vec::new();

    for target in TARGET_CRATES {
        let target_id = id_to_name
            .iter()
            .find(|(_, name)| name == target)
            .map_or_else(
                || panic!("`cargo metadata` did not surface `{target}` package"),
                |(id, _)| id.clone(),
            );

        let reachable = walk_normal_deps(&metadata_json, &target_id);
        let forbidden: Vec<String> = reachable
            .iter()
            .filter_map(|id| id_to_name.get(id).cloned())
            .filter(|name| FORBIDDEN_CRATES.contains(&name.as_str()))
            .collect();
        if !forbidden.is_empty() {
            all_violations.push(((*target).to_string(), forbidden));
        }
    }

    assert!(
        all_violations.is_empty(),
        "Adamant production dependency graphs contain forbidden upstream Halo 2 crate(s) \
         (CLAUDE.md §14.4 Decision 1 resistant-proof posture violated):\n{all_violations:#?}\n\
         Upstream Halo 2 ZK proving-system crates must appear only in [dev-dependencies] or \
         [build-dependencies], never in [dependencies]. Production-side Halo 2 surface flows \
         through `adamant-halo2` (Adamant's fork). See `crates/adamant-halo2/PROVENANCE.md` \
         for the fork posture."
    );
}

/// Run `cargo metadata --format-version 1` and return the JSON
/// output as a string.
fn run_cargo_metadata() -> String {
    let output = Command::new(env!("CARGO"))
        .args(["metadata", "--format-version", "1"])
        .output()
        .expect("invoking `cargo metadata` must succeed in a workspace context");
    assert!(
        output.status.success(),
        "`cargo metadata` must succeed; stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("cargo metadata output must be valid UTF-8")
}

/// Build a map from package-id → package-name by string-scanning
/// the `packages[i]` array. Each package entry has fields
/// emitted in cargo's stable order: `"name":"X","version":"Y","id":"Z"`,
/// so we can extract the name from each `"id":` site by walking
/// backward to the enclosing object's `"name":` field.
fn build_id_to_name_map(metadata: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    let id_marker = "\"id\":\"";
    let name_marker = "\"name\":\"";
    let mut cursor = 0;
    while let Some(rel) = metadata[cursor..].find(id_marker) {
        let id_start = cursor + rel + id_marker.len();
        let id_end_rel = metadata[id_start..]
            .find('"')
            .expect("closing quote on id field");
        let id_end = id_start + id_end_rel;
        let id_str = &metadata[id_start..id_end];

        let name_search_slice = &metadata[..id_start];
        let prev_name_pos = name_search_slice.rfind(name_marker);
        if let Some(name_field_start) = prev_name_pos {
            let between = &metadata[name_field_start..id_start];
            if !between.contains('}') {
                let name_value_start = name_field_start + name_marker.len();
                let name_value_end_rel = metadata[name_value_start..]
                    .find('"')
                    .expect("closing quote on name field");
                let name_str = &metadata[name_value_start..name_value_start + name_value_end_rel];
                map.insert(id_str.to_string(), name_str.to_string());
            }
        }

        cursor = id_end;
    }
    map
}

/// Walk the resolve graph from `root_id` collecting every
/// transitively reachable package id via normal-kind edges only.
fn walk_normal_deps(metadata: &str, root_id: &str) -> Vec<String> {
    let mut visited: Vec<String> = Vec::new();
    let mut queue: Vec<String> = vec![root_id.to_string()];

    while let Some(current) = queue.pop() {
        for child_id in normal_children(metadata, &current) {
            if !visited.iter().any(|id| id == &child_id) {
                visited.push(child_id.clone());
                queue.push(child_id);
            }
        }
    }
    visited
}

/// Find the resolve node for `node_id` in the metadata JSON and
/// return the list of its normal-kind dependency package ids.
fn normal_children(metadata: &str, node_id: &str) -> Vec<String> {
    let Some(resolve_section_start) = metadata.find("\"resolve\":") else {
        return Vec::new();
    };
    let resolve_slice = &metadata[resolve_section_start..];

    let id_pattern = format!("\"id\":\"{node_id}\"");
    let Some(node_id_pos) = resolve_slice.find(&id_pattern) else {
        return Vec::new();
    };
    let node_slice = bounded_object(resolve_slice, node_id_pos);

    let Some(deps_array_start) = node_slice.find("\"deps\":[") else {
        return Vec::new();
    };
    let deps_array_slice = &node_slice[deps_array_start..];

    let mut children = Vec::new();
    let mut cursor = 0;
    while let Some(rel_pkg) = deps_array_slice[cursor..].find("\"pkg\":\"") {
        let pkg_value_start = cursor + rel_pkg + "\"pkg\":\"".len();
        let pkg_value_end_rel = deps_array_slice[pkg_value_start..]
            .find('"')
            .expect("closing quote on pkg field");
        let pkg_value_end = pkg_value_start + pkg_value_end_rel;
        let pkg_id = &deps_array_slice[pkg_value_start..pkg_value_end];

        let entry_end = find_dep_entry_end(deps_array_slice, pkg_value_end);
        let entry_slice = &deps_array_slice[pkg_value_end..entry_end];
        if entry_slice.contains("\"kind\":null") {
            children.push(pkg_id.to_string());
        }

        cursor = entry_end;
    }
    children
}

/// Find the closing `}` of a single `deps[j]` entry starting
/// from after the `pkg` value.
fn find_dep_entry_end(slice: &str, search_start: usize) -> usize {
    let bytes = slice.as_bytes();
    let mut depth: i32 = 1;
    let mut i = search_start;
    while i < bytes.len() {
        match bytes[i] {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return i;
                }
            }
            _ => {}
        }
        i += 1;
    }
    slice.len()
}

/// Slice the JSON metadata starting at the `\"id\":\"...\"`
/// marker for a resolve node and return the enclosing object's
/// content (substring from the opening `{` to the matching
/// closing `}`).
fn bounded_object(metadata: &str, id_marker_start: usize) -> &str {
    let prefix = &metadata[..id_marker_start];
    let object_start = prefix.rfind('{').unwrap_or(0);
    let mut depth: i32 = 0;
    let bytes = metadata.as_bytes();
    let mut i = object_start;
    while i < bytes.len() {
        match bytes[i] {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return &metadata[object_start..=i];
                }
            }
            _ => {}
        }
        i += 1;
    }
    &metadata[object_start..]
}
