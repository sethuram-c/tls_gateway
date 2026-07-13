#!/usr/bin/env python3
"""Check release-audit rules without touching the user's Git index."""

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from release_check import (REQUIRED_FILES, IGNORE_RULES, audit,
                           missing_files, unsafe_path)  # noqa: E402


def main():
    unsafe = [
        'certs/server.key', 'certs/ca.crt', 'build/main.o',
        'build-asan/tls-gateway', 'bench_results/results.json',
        'notes/phase44.pdf', 'gateway.conf', '__pycache__/test.pyc',
        'build/tls-gateway',
    ]
    safe = ['src/main.c', 'include/epoll_tls_proxy.h',
            'tests/test_release_check.py', 'docs/architecture.md',
            'config/gateway.conf.example', 'scripts/release_check.py']
    for name in unsafe:
        assert unsafe_path(name), f'unsafe path not caught: {name}'
    for name in safe:
        assert unsafe_path(name) is None, f'safe path rejected: {name}'

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        assert 'README.md' in missing_files(root)
        for name in REQUIRED_FILES:
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('', encoding='utf-8')
        (root / '.gitignore').write_text('\n'.join(IGNORE_RULES) + '\n', encoding='utf-8')
        errors, has_git = audit(root, source_export=True)
        assert errors == [] and not has_git, errors
        (root / 'certs').mkdir()
        (root / 'certs' / 'ca.key').write_text('PRIVATE KEY', encoding='utf-8')
        errors, _ = audit(root, source_export=True)
        assert any('certs/ca.key' in issue for issue in errors), errors
        (root / 'certs' / 'ca.key').unlink()
        (root / 'README.md').unlink()
        errors, _ = audit(root, source_export=True)
        assert any('missing required file: README.md' in issue for issue in errors)

    print('PASS: release path rules, missing-file checks, and source-tree audit')


if __name__ == '__main__':
    main()
