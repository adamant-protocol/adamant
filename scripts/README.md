# Audit scripts

Test-block-aware Python scanners for production-path discipline checks.
Each script masks `#[cfg(test)]` / `#[test]` blocks and skips cfg(test)-gated
files (`test_fixtures.rs`, `test_helpers.rs`) before scanning.

Run from the repo root:

```bash
python3 scripts/audit_unwrap.py
python3 scripts/audit_patterns.py
```

## `audit_unwrap.py`

Reports any non-test `.unwrap()` calls across the 7 Adamant-authored crates.
CLAUDE.md §8 forbids `.unwrap()` outside tests; use `.expect("...")` with a
descriptive message, or proper error handling, or `?`.

## `audit_patterns.py`

Reports any non-test occurrences of:

- `.unwrap()`
- `println!` / `eprintln!` / `dbg!` macros
- `todo!()` / `unimplemented!()` macros
- `TODO` / `FIXME` / `XXX` / `HACK` comment markers

Production code should be clean of all four categories. The expected output
is `OK: 0 non-test ... instances` for each.

## Maintenance

Add new pattern checks by extending `audit_patterns.py::main()`'s `patterns`
dict. The test-block masker (`mask_test_blocks`) is shared across both
scripts; if its heuristics need refinement (e.g., to recognize
`#[cfg(any(test, ...))]`), update both.

## Scope

Adamant-authored crates only:
- `adamant-vm`
- `adamant-crypto`
- `adamant-crypto-blst-extra`
- `adamant-types`
- `adamant-account`
- `adamant-state`
- `adamant-bytecode-format`

Vendored Sui-Move crates under `vendor/` are intentionally excluded — they
are upstream-byte-faithful per the resistant-proof posture (whitepaper
§6.2.1.8) and ship only as test-time cross-validation references at
Phase 5/5b.5 onward.
