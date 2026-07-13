#!/usr/bin/env python3
"""Small, offline source-tree/repository hygiene audit for the TLS gateway.

This deliberately does not claim to be a security audit or a substitute for
compilation, integration tests, or TLS verification.
"""

import argparse
from pathlib import Path, PurePosixPath
import subprocess
import sys

REQUIRED_FILES = (
    '.gitignore', 'Makefile', 'README.md', 'progress.md',
    'docs/architecture.md', 'config/gateway.conf.example',
    'src/main.c', 'src/epoll_tls_proxy.c', 'include/epoll_tls_proxy.h',
    'tests/run_tests.py', 'tests/http_backend.py',
    'bench/https_bench.py', 'bench/concurrency_profile.py',
    'scripts/release_check.py', 'tests/test_release_check.py',
)
IGNORE_RULES = (
    '/build/', '/build-*/', 'certs/', '*.key', '*.pem',
    '*.crt', '/gateway.conf', '/bench_results/',
)
UNSAFE_DIRS = {'certs', 'build', 'build-asan', 'build-ubsan',
               'bench_results', '__pycache__', '.pytest_cache', '.git'}
UNSAFE_SUFFIXES = {'.key', '.pem', '.crt', '.csr', '.srl', '.pdf',
                   '.o', '.pyc', '.so', '.a'}
UNSAFE_FILES = {'gateway.conf', 'tls-gateway', '.DS_Store'}


def unsafe_path(name):
    """Return a reason if a path cannot belong in a source release."""
    path = PurePosixPath(str(name).replace('\\', '/'))
    pieces = path.parts
    if path.is_absolute() or '..' in pieces:
        return 'invalid archive path'
    if any(part in UNSAFE_DIRS for part in pieces):
        return 'generated/private directory'
    if path.name in UNSAFE_FILES or path.suffix.lower() in UNSAFE_SUFFIXES:
        return 'generated/private file type'
    if path.name.startswith('.swp') or path.name.endswith('~'):
        return 'temporary editor file'
    return None


def missing_files(root):
    return [name for name in REQUIRED_FILES if not (root / name).is_file()]


def missing_ignore_rules(root):
    path = root / '.gitignore'
    if not path.is_file():
        return list(IGNORE_RULES)
    lines = {line.strip() for line in path.read_text(encoding='utf-8').splitlines()}
    return [rule for rule in IGNORE_RULES if rule not in lines]


def tracked_paths(root):
    """Return staged/tracked names, or None for a source ZIP without .git."""
    if not (root / '.git').exists():
        return None
    result = subprocess.run(
        ['git', '-C', str(root), 'ls-files', '-z', '--cached'],
        capture_output=True, check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.decode('utf-8', 'replace').strip())
    return [name.decode('utf-8', 'surrogateescape')
            for name in result.stdout.split(b'\0') if name]


def audit(root, source_export=False):
    """Return a list of errors and whether the Git index was checked."""
    errors = []
    for name in missing_files(root):
        errors.append(f'missing required file: {name}')
    for rule in missing_ignore_rules(root):
        errors.append(f'missing .gitignore pattern: {rule}')

    # In a checkout, scan exactly what `git commit` could include. Files kept
    # locally under ignored certs/ or build/ must not cause false positives.
    paths = tracked_paths(root)
    if paths is not None:
        for name in paths:
            reason = unsafe_path(name)
            if reason:
                errors.append(f'unsafe tracked path: {name} ({reason})')
    elif source_export:
        # Invoke only on a pristine, freshly extracted source ZIP, before building.
        for item in root.rglob('*'):
            if item.is_file():
                name = item.relative_to(root).as_posix()
                reason = unsafe_path(name)
                if reason:
                    errors.append(f'unsafe packaged path: {name} ({reason})')
    return errors, paths is not None


def main(argv=None):
    parser = argparse.ArgumentParser(description='Audit TLS gateway source release hygiene')
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parent.parent)
    parser.add_argument('--source-export', action='store_true',
                        help='scan a pristine exported source tree (run before make)')
    args = parser.parse_args(argv)
    root = args.root.resolve()
    if not root.is_dir():
        parser.error(f'not a directory: {root}')

    try:
        errors, has_git = audit(root, source_export=args.source_export)
    except (OSError, RuntimeError) as exc:
        print(f'FAIL: could not audit source: {exc}', file=sys.stderr)
        return 1
    if errors:
        for err in errors:
            print(f'FAIL: {err}', file=sys.stderr)
        return 1
    print('PASS: required source, docs, Makefile, and test files present')
    print('PASS: generated artifacts and private keys have ignore rules')
    if has_git:
        print('PASS: Git index contains no excluded/private file paths')
    elif args.source_export:
        print('PASS: pristine source export contains no excluded/private files')
    else:
        print('NOTE: no Git index; --source-export checks a pristine, unbuilt ZIP')
    print('PASS: release source hygiene checks (not a security audit)')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
