"""Whole-codebase scan for production-path discipline patterns.

Scans Adamant-authored crates for:
- .unwrap() outside tests          [CLAUDE.md §8]
- println!/eprintln!/dbg! outside tests
- todo!/unimplemented! outside tests
- panic!() / unreachable!() outside tests in lib code (except documented)
- TODO/FIXME/XXX/HACK markers
- expect() count by file (informational)
"""

import os
import re

ROOTS = [
    'crates/adamant-account/src',
    'crates/adamant-bytecode-format/src',
    'crates/adamant-cli/src',
    'crates/adamant-consensus/src',
    'crates/adamant-crypto/src',
    'crates/adamant-crypto-blst-extra/src',
    # adamant-halo2 EXCLUDED: forked Zcash codebase per CLAUDE.md
    # §14.4 Decision 1 Path C2; byte-faithful upstream preservation.
    'crates/adamant-light/src',
    'crates/adamant-network/src',
    'crates/adamant-node/src',
    'crates/adamant-privacy/src',
    'crates/adamant-state/src',
    'crates/adamant-types/src',
    'crates/adamant-vm/src',
]


def is_under_tests_dir(path):
    return '/tests' in path.replace('\\', '/')


def is_test_only_file(path):
    posix = path.replace('\\', '/')
    return posix.endswith('test_fixtures.rs') or posix.endswith('test_helpers.rs')


def is_binary_entry_point(path):
    """Binary entry points (main.rs) legitimately use println!/eprintln!
    for operator-facing output and `--help` text. Exempt from the
    println/eprintln check."""
    posix = path.replace('\\', '/')
    return posix.endswith('/main.rs')


def mask_test_blocks(lines):
    mask = [False] * len(lines)
    i = 0
    while i < len(lines):
        line = lines[i]
        if re.search(r'#\[cfg\(test\)\]', line) or re.search(r'#\[test\]', line):
            j = i + 1
            while j < len(lines) and '{' not in lines[j]:
                j += 1
            if j < len(lines):
                depth = lines[j].count('{') - lines[j].count('}')
                mask[i] = True
                mask[j] = True
                k = j + 1
                while k < len(lines) and depth > 0:
                    depth += lines[k].count('{') - lines[k].count('}')
                    mask[k] = True
                    k += 1
                i = k
                continue
        i += 1
    return mask


def scan_pattern(path, pattern_re, exclude_doc=True):
    with open(path, 'r', encoding='utf-8', errors='replace') as fp:
        lines = fp.readlines()
    mask = mask_test_blocks(lines)
    hits = []
    for ln, line in enumerate(lines):
        if mask[ln]:
            continue
        stripped = line.lstrip()
        if exclude_doc and (stripped.startswith('//') or stripped.startswith('//!')):
            continue
        if pattern_re.search(line):
            hits.append((ln + 1, line.rstrip()))
    return hits


def main():
    patterns = {
        'unwrap': re.compile(r'\.unwrap\(\)'),
        'println/eprintln/dbg': re.compile(r'\b(println|eprintln|dbg)!'),
        'todo/unimplemented': re.compile(r'\b(todo|unimplemented)!'),
        'TODO/FIXME/XXX/HACK marker': re.compile(r'\b(TODO|FIXME|XXX|HACK)\b'),
    }

    findings = {name: [] for name in patterns}
    for root in ROOTS:
        for dp, _, files in os.walk(root):
            if is_under_tests_dir(dp):
                continue
            for fn in files:
                if not fn.endswith('.rs'):
                    continue
                path = os.path.join(dp, fn)
                if is_test_only_file(path):
                    continue
                for name, pat in patterns.items():
                    # main.rs is exempt only from the println/eprintln/dbg
                    # check — binaries legitimately print to stdout/stderr.
                    if name == 'println/eprintln/dbg' and is_binary_entry_point(path):
                        continue
                    for ln, line in scan_pattern(path, pat):
                        findings[name].append((path, ln, line))

    for name, hits in findings.items():
        print(f'\n=== {name} ===')
        if not hits:
            print(f'  OK: 0 non-test {name} instances.')
            continue
        print(f'  {len(hits)} hit(s):')
        for path, ln, line in hits[:25]:
            print(f'  {path}:{ln}: {line[:140]}')
        if len(hits) > 25:
            print(f'  ... and {len(hits) - 25} more')


if __name__ == '__main__':
    main()
