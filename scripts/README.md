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

Reports any non-test `.unwrap()` calls across the 13 in-scope Adamant-authored
crates (the 14th, `adamant-halo2`, is excluded — see Scope below). CLAUDE.md
§8 forbids `.unwrap()` outside tests; use `.expect("...")` with a descriptive
message, or proper error handling, or `?`.

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

Adamant-authored crates in scope (13):
- `adamant-account`
- `adamant-bytecode-format`
- `adamant-cli`
- `adamant-consensus`
- `adamant-crypto`
- `adamant-crypto-blst-extra`
- `adamant-light`
- `adamant-network`
- `adamant-node`
- `adamant-privacy`
- `adamant-state`
- `adamant-types`
- `adamant-vm`

Excluded:

- **`adamant-halo2`** — forked Zcash codebase per CLAUDE.md §14.4 Decision 1
  Path C2. Byte-faithful upstream preservation is the intentional posture;
  inherited unwraps are vendored audit history (Zcash Orchard / Electric
  Coin Co), not Adamant-authored risk. The forking-discipline audit anchor
  is `crates/adamant-halo2/PROVENANCE.md`.

- **Vendored Sui-Move crates** under `vendor/` — upstream-byte-faithful per
  the resistant-proof posture (whitepaper §6.2.1.8). Test-time cross-
  validation only since Phase 5/5b.5; never appear in the production
  binary's dependency graph (enforced by
  `crates/adamant-vm/tests/no_sui_in_production_deps.rs`).
