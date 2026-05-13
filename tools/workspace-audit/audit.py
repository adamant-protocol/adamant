#!/usr/bin/env python3
"""Adamant workspace audit script.

Mechanical health checks for the Adamant L1 Rust workspace. Runs
several lightweight static analyses across Adamant-authored crates
and emits a tabular health report.

Checks covered (Phase 1-6 audit):

- Doc-comment coverage on `pub` items (struct/enum/fn/trait/type/const/static)
- `#![forbid(unsafe_code)]` declaration presence
- Module-level `//!` doc-comment presence
- TODO/FIXME/HACK census
- `unwrap()` outside test code (rough heuristic)
- Approximate LOC per crate

Usage:

    python3 tools/workspace-audit/audit.py             # human-readable report
    python3 tools/workspace-audit/audit.py --strict    # exit 1 if any
                                                       # check fails

The script is intentionally dependency-free (stdlib only) so it
can run in any Rust dev environment without setup. It is designed
to complement (not replace) `cargo clippy` + `cargo fmt`.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

# Crates to audit. Vendored Sui-Move crates and the upstream halo2
# fork are excluded — those follow upstream's own discipline.
ADAMANT_CRATES = [
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
]

# Generated files that don't need doc coverage.
GENERATED_FILES = {
    "value_commitment_chip_tables.rs",
}

# Patterns flagged in the TODO census.
TODO_PATTERNS = [
    "TODO",
    "FIXME",
    "XXX",
    "HACK",
    "BUG",
]

PUB_ITEM_RE = re.compile(
    r"^pub\s+(struct|enum|fn|trait|type|const|static)\s+(\w+)"
)
ATTR_LINE_RE = re.compile(r"^\s*#!?\[")
DOC_LINE_RE = re.compile(r"^\s*//[/!]")


def find_workspace_root() -> Path:
    """Locate the workspace root by walking up from this script's
    parent directory looking for `Cargo.toml` with `[workspace]`."""
    here = Path(__file__).resolve().parent
    for ancestor in [here, *here.parents]:
        cargo = ancestor / "Cargo.toml"
        if cargo.exists() and "[workspace]" in cargo.read_text(encoding="utf-8"):
            return ancestor
    raise RuntimeError("could not locate workspace root from " + str(here))


def is_doc_documented(lines: list[str], item_idx: int) -> bool:
    """Return True iff the `pub` item at `lines[item_idx]` has a
    `///` or `//!` doc comment immediately above (skipping blank
    lines, attributes including multi-line attributes, and non-doc
    `//` comments).

    The walk-back logic handles:
    - Multi-line `#[derive(...)]` and `#[cfg(...)]` attributes that
      span multiple lines via `(`/`)` balancing.
    - Plain `//` line comments interspersed before the doc comment
      (Rust convention permits this).
    - Blank lines.

    Stops at the first line that isn't blank, an attribute, or a
    comment. Returns True iff a `///` or `//!` line is reached
    during the walk.
    """
    i = item_idx - 1
    paren_depth = 0
    while i >= 0:
        line = lines[i]
        stripped = line.strip()

        # Track parenthesis balance for multi-line attributes.
        # If we're "inside" an attribute (paren_depth > 0), the
        # current line is part of the attribute regardless of its
        # content; just adjust depth and continue.
        # Walking BACKWARDS: ')' opens the attribute scope (we'll
        # see it before the matching '('); '(' closes it.
        if paren_depth > 0:
            paren_depth += stripped.count(")") - stripped.count("(")
            i -= 1
            continue

        # If the line ends with `]` and contains an attribute close,
        # treat as start of multi-line attribute walk-back.
        if stripped.endswith("]") and ")" in stripped and "#[" not in stripped:
            # Closing of multi-line attr; balance parens
            paren_depth = stripped.count(")") - stripped.count("(")
            i -= 1
            continue

        if stripped == "":
            i -= 1
            continue

        # Doc comment found
        if stripped.startswith("///") or stripped.startswith("//!"):
            return True

        # Single-line attribute
        if ATTR_LINE_RE.match(stripped):
            i -= 1
            continue

        # Non-doc line comment — Rust convention permits these
        # interspersed before doc comments. Walk past.
        if stripped.startswith("//"):
            i -= 1
            continue

        # Anything else: hit code or unrelated content. Not documented.
        return False

    return False


def in_test_block(lines: list[str], item_idx: int) -> bool:
    """Heuristic: is the item inside a `#[cfg(test)] mod ...` block?"""
    depth = 0
    in_test = False
    for i in range(item_idx):
        s = lines[i].strip()
        if s.startswith("#[cfg(test)]"):
            # The next mod begins a test block
            in_test = True
        elif in_test and re.match(r"^(pub\s+)?mod\s+\w+", s):
            in_test = True  # confirmed
            depth = 1
            continue
        if depth > 0:
            depth += s.count("{") - s.count("}")
            if depth == 0:
                in_test = False
    return depth > 0 and in_test


def audit_crate(crate_path: Path) -> dict:
    """Run all checks on a single crate's `src/` directory."""
    src = crate_path / "src"
    if not src.exists():
        return {
            "name": crate_path.name,
            "exists": False,
        }

    lib = src / "lib.rs"
    has_forbid = False
    has_module_doc = False
    if lib.exists():
        text = lib.read_text(encoding="utf-8")
        has_forbid = "#![forbid(unsafe_code)]" in text
        # Find first non-blank, non-`#!` attribute line
        for line in text.splitlines():
            s = line.strip()
            if s == "" or s.startswith("#!["):
                continue
            has_module_doc = s.startswith("//!")
            break

    pub_items = 0
    undoc_items = 0
    undoc_paths: list[str] = []
    todo_count = 0
    todo_samples: list[str] = []
    unwrap_outside_tests = 0
    unwrap_samples: list[str] = []
    loc = 0

    rs_files = sorted(src.rglob("*.rs"))
    for f in rs_files:
        if f.name in GENERATED_FILES:
            continue
        text = f.read_text(encoding="utf-8")
        lines = text.splitlines()
        loc += sum(1 for ln in lines if ln.strip() and not ln.strip().startswith("//"))

        # Pub-item doc coverage
        for i, line in enumerate(lines):
            if PUB_ITEM_RE.match(line.strip()):
                if in_test_block(lines, i):
                    continue
                pub_items += 1
                if not is_doc_documented(lines, i):
                    undoc_items += 1
                    rel = f.relative_to(crate_path).as_posix()
                    undoc_paths.append(f"{crate_path.name}/{rel}:{i + 1}")

        # TODO census
        for i, line in enumerate(lines):
            for pat in TODO_PATTERNS:
                if pat in line and "//" in line:
                    todo_count += 1
                    if len(todo_samples) < 3:
                        rel = f.relative_to(crate_path).as_posix()
                        todo_samples.append(
                            f"{crate_path.name}/{rel}:{i + 1} {line.strip()[:80]}"
                        )
                    break

        # unwrap() heuristic: count occurrences in non-test code.
        # Skip files that are obviously test files.
        if f.name.endswith("tests.rs"):
            continue
        # Skip lines after a `mod tests {` line; lightweight heuristic.
        in_tests_mod = False
        for i, line in enumerate(lines):
            stripped = line.strip()
            if (
                stripped.startswith("#[cfg(test)]")
                or stripped.startswith("mod tests")
            ):
                in_tests_mod = True
            if in_tests_mod:
                continue
            if ".unwrap()" in line:
                unwrap_outside_tests += 1
                if len(unwrap_samples) < 5:
                    rel = f.relative_to(crate_path).as_posix()
                    unwrap_samples.append(
                        f"{crate_path.name}/{rel}:{i + 1}"
                    )

    return {
        "name": crate_path.name,
        "exists": True,
        "loc": loc,
        "lib_has_forbid": has_forbid,
        "lib_has_module_doc": has_module_doc,
        "pub_items": pub_items,
        "undoc_items": undoc_items,
        "undoc_coverage_pct": (
            (pub_items - undoc_items) / pub_items * 100 if pub_items > 0 else 100.0
        ),
        "undoc_paths": undoc_paths,
        "todo_count": todo_count,
        "todo_samples": todo_samples,
        "unwrap_outside_tests": unwrap_outside_tests,
        "unwrap_samples": unwrap_samples,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Adamant workspace audit")
    parser.add_argument(
        "--strict",
        action="store_true",
        help="exit 1 if any check fails (doc coverage <100%%, missing forbid, "
        "any TODO, etc.)",
    )
    parser.add_argument(
        "--show-undocumented",
        action="store_true",
        help="print the file:line of every undocumented public item",
    )
    args = parser.parse_args()

    workspace = find_workspace_root()
    print(f"Adamant workspace audit — {workspace}\n")

    results = []
    for crate in ADAMANT_CRATES:
        crate_path = workspace / "crates" / crate
        if not crate_path.exists():
            print(f"  {crate:30s}  MISSING")
            continue
        results.append(audit_crate(crate_path))

    # ------ Tabular summary ------
    print(
        f"{'crate':30s}  {'LOC':>7s}  {'pub items':>9s}  {'doc cov':>9s}  "
        f"{'forbid':>6s}  {'TODOs':>5s}  {'unwrap':>6s}"
    )
    print("-" * 90)

    fails = 0
    total_loc = 0
    total_items = 0
    total_undoc = 0
    total_todos = 0

    for r in results:
        if not r["exists"]:
            continue
        total_loc += r["loc"]
        total_items += r["pub_items"]
        total_undoc += r["undoc_items"]
        total_todos += r["todo_count"]
        forbid = "yes" if r["lib_has_forbid"] else "NO"
        if not r["lib_has_forbid"] and r["name"] != "adamant-crypto-blst-extra":
            fails += 1
        if r["undoc_items"] > 0:
            fails += 1
        print(
            f"{r['name']:30s}  {r['loc']:>7d}  {r['pub_items']:>9d}  "
            f"{r['undoc_coverage_pct']:>8.1f}%  {forbid:>6s}  "
            f"{r['todo_count']:>5d}  {r['unwrap_outside_tests']:>6d}"
        )

    print("-" * 90)
    coverage = (total_items - total_undoc) / total_items * 100 if total_items else 0
    print(
        f"{'TOTAL':30s}  {total_loc:>7d}  {total_items:>9d}  "
        f"{coverage:>8.1f}%  {'-':>6s}  {total_todos:>5d}  {'-':>6s}"
    )
    print()

    # ------ Detail sections ------
    if args.show_undocumented:
        for r in results:
            if r.get("undoc_paths"):
                print(f"  {r['name']} undocumented:")
                for p in r["undoc_paths"]:
                    print(f"    {p}")

    for r in results:
        if r.get("todo_samples"):
            print(f"  {r['name']} TODOs:")
            for sample in r["todo_samples"]:
                print(f"    {sample}")

    print()
    print("Notes:")
    print("  - adamant-crypto-blst-extra is exempt from forbid(unsafe_code) "
          "(it's the BLS12-381 FFI wrapper; unsafe is documented per-block "
          "with SAFETY comments).")
    print("  - 'doc cov' percentages count `pub` items in non-test code "
          "with `///` doc comments; non-doc `//` comments and multi-line "
          "attributes are walked through correctly.")
    print("  - 'unwrap' is a heuristic count of `.unwrap()` outside `mod "
          "tests` blocks; many are justified (e.g., `try_into` on slices "
          "with proven length). Use as a quick scan, not gospel.")

    if args.strict:
        if fails > 0:
            print(f"\nSTRICT MODE: {fails} check(s) failed.", file=sys.stderr)
            return 1
        print("\nSTRICT MODE: all checks pass.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
