"""Test-block-aware scan for production .unwrap() calls."""

import os
import re

ROOTS = [
    'crates/adamant-vm/src',
    'crates/adamant-crypto/src',
    'crates/adamant-account/src',
    'crates/adamant-state/src',
    'crates/adamant-types/src',
    'crates/adamant-bytecode-format/src',
    'crates/adamant-crypto-blst-extra/src',
]


def is_under_tests_dir(path):
    return '/tests' in path.replace('\\', '/')


def is_test_only_file(path):
    """Files that are entirely #[cfg(test)]-gated by their parent module."""
    posix = path.replace('\\', '/')
    suffixes = ('test_fixtures.rs', 'test_helpers.rs')
    return any(posix.endswith(s) for s in suffixes)


def scan(path):
    hits = []
    with open(path, 'r', encoding='utf-8', errors='replace') as fp:
        lines = fp.readlines()
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
    for ln, line in enumerate(lines):
        if mask[ln]:
            continue
        if '.unwrap()' in line and not line.lstrip().startswith('//'):
            hits.append(f'{path}:{ln + 1}: {line.rstrip()}')
    return hits


def main():
    all_hits = []
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
                all_hits.extend(scan(path))
    if all_hits:
        print(f'{len(all_hits)} non-test unwrap() instances:')
        for h in all_hits:
            print(f'  {h}')
    else:
        print('OK: 0 non-test unwrap() instances across all Adamant-authored crates.')


if __name__ == '__main__':
    main()
