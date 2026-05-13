//! Build-system independence check enforcing the resistant-proof
//! posture per whitepaper §6.2.1 and §6.2.1.8: vendored Sui-Move
//! crates must not appear in any Adamant-authored production-
//! binary's dependency graph.
//!
//! The test walks `cargo metadata`'s resolved dependency tree
//! starting from each Adamant production crate's normal
//! (non-dev, non-build) dependency edges and asserts no `move-*`
//! crate is reachable. Dev-dependencies and build-dependencies
//! are explicitly permitted by §6.2.1.8's carve-out for test-
//! only / build-tooling-only / CI-only dependencies; they're
//! excluded from the walk via the `dep_kinds` filter.
//!
//! Phase 5/5b.5 E-1b added this check as the mechanical guardrail
//! for the architectural commitment in §6.2.1.8: "no implementation
//! that depends on Sui-Move's logic at deploy-time or runtime is
//! conforming". Pre-Phase-10 audit extended coverage from
//! `adamant-vm` alone to ALL 13 in-scope Adamant production
//! crates (excluding `adamant-halo2` per its byte-faithful forked
//! posture). If a future change accidentally introduces a
//! production-side `move-*` dep anywhere in the workspace, this
//! test fails with the offending crate's name + the chain of
//! crates that pulled it in.
//!
//! Mechanism: invokes `cargo metadata --format-version 1` via
//! `std::process::Command`, parses the JSON output by hand (no
//! third-party `cargo_metadata` crate dependency), builds a
//! package-id → name map from the `packages` array, walks the
//! resolve graph from each target crate's `normal`-kind edges
//! via the `resolve.nodes[i].deps[j].dep_kinds` filter, and
//! asserts no reached crate's name starts with `move-`.

use std::collections::HashMap;
use std::process::Command;

/// Crate-name prefix the resistant-proof posture forbids in the
/// production dependency graph. All vendored Sui-Move crates
/// share this prefix per `vendor/README.md` + the workspace
/// member list in the root `Cargo.toml`.
const FORBIDDEN_PREFIX: &str = "move-";

/// Adamant-authored production crates whose dependency graphs
/// must not contain any `move-*` crate. `adamant-halo2` is
/// excluded — it's the forked Halo 2 crate per CLAUDE.md §14.4
/// Decision 1 Path C2 and does not transitively pull Sui.
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
/// Asserts no `move-*` crate is reachable from any of them.
#[test]
fn adamant_production_deps_contain_no_sui_move_crates() {
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
            .filter(|name| name.starts_with(FORBIDDEN_PREFIX))
            .collect();
        if !forbidden.is_empty() {
            all_violations.push(((*target).to_string(), forbidden));
        }
    }

    assert!(
        all_violations.is_empty(),
        "Adamant production dependency graphs contain forbidden Sui-Move crate(s) \
         (whitepaper §6.2.1.8 resistant-proof posture violated):\n{all_violations:#?}\n\
         Move-* crates must appear only in [dev-dependencies] or [build-dependencies], \
         never in [dependencies]. See each offending crate's Cargo.toml + vendor/README.md."
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
    // Each package object opens with `{"name":"X","version":"Y","id":"Z",...`.
    // Find every `"id":"` position, then walk backward for the
    // matching `"name":"`.
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

        // Walk backward from the id-field site to find the
        // corresponding name field within the same package
        // object. The package object's opening `{` comes right
        // before the `"name":"` field; bound the search so we
        // don't pick up a name from a previous object.
        let name_search_slice = &metadata[..id_start];
        let prev_name_pos = name_search_slice.rfind(name_marker);
        // Ensure the name field is in the SAME object as the id
        // field by checking no unbalanced `}` appears between
        // them.
        if let Some(name_field_start) = prev_name_pos {
            let between = &metadata[name_field_start..id_start];
            // Both `{` and `}` should be balanced (or there
            // should be one extra `{` indicating start of object
            // — name comes after `{` and before `id`). Simpler
            // check: ensure no `}` separates name from id (which
            // would mean we're picking up a name from a
            // different object).
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
///
/// Resolve graph shape: `metadata.resolve.nodes[i]` has `id` and
/// `deps`. Each `deps[j]` has `pkg` (target package id) and
/// `dep_kinds` (an array of objects each carrying `kind` —
/// `null` for normal, `"dev"` / `"build"` for the others). We
/// walk an edge if at least one of its `dep_kinds` entries is
/// `null`-kind.
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
    // Find the resolve node whose `id` matches `node_id`. The
    // resolve nodes appear under `"resolve":{"nodes":[...]}`,
    // distinct from `packages[i]`. A node's id is followed
    // (within the same object) by `dependencies` and `deps`.
    // Because both `packages[i]` and `resolve.nodes[i]` contain
    // `"id":"X"`, we restrict the search to the resolve section.
    let Some(resolve_section_start) = metadata.find("\"resolve\":") else {
        return Vec::new();
    };
    let resolve_slice = &metadata[resolve_section_start..];

    let id_pattern = format!("\"id\":\"{node_id}\"");
    let Some(node_id_pos) = resolve_slice.find(&id_pattern) else {
        return Vec::new();
    };
    // Bound the node object: from the enclosing `{` to the
    // matching `}`.
    let node_slice = bounded_object(resolve_slice, node_id_pos);

    // Within the node, find the `"deps":[...]` array and walk
    // each entry. Each entry has `pkg` (string) and `dep_kinds`
    // (array). We collect the `pkg` value when at least one
    // dep_kind is null.
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

        // Find this dep entry's `dep_kinds` array. The entry is
        // a single object `{...}`; bound it by walking from the
        // pkg field to the closing `}` of the dep entry.
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
/// from after the `pkg` value. The entry is one JSON object
/// among many in the `deps` array; its closing `}` is balanced
/// against opening `{`s.
fn find_dep_entry_end(slice: &str, search_start: usize) -> usize {
    let bytes = slice.as_bytes();
    let mut depth: i32 = 1; // we're inside a dep object already
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
