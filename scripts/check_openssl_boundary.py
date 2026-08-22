#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Enforce coding-rules.md Rule 7.1: one OpenSSL subprocess boundary.

Every ``openssl`` invocation in the TLS scanner tree must go through
``src/qureddy/scanners/tls/openssl_probe/executor.py``. This AST-walks every
other ``.py`` file under ``src/qureddy/scanners/tls/`` and fails if any of them
call ``subprocess.run`` / ``subprocess.Popen`` / ``subprocess.call`` directly.
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

TLS_ROOT = Path(__file__).resolve().parents[1] / "src" / "qureddy" / "scanners" / "tls"
EXECUTOR = TLS_ROOT / "openssl_probe" / "executor.py"
FORBIDDEN_ATTRS = frozenset({"run", "Popen", "call"})


def _offending_calls(tree: ast.AST) -> list[int]:
    """Return line numbers of ``subprocess.run/Popen/call`` calls in ``tree``."""
    offenders: list[int] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if (
            isinstance(func, ast.Attribute)
            and func.attr in FORBIDDEN_ATTRS
            and isinstance(func.value, ast.Name)
            and func.value.id == "subprocess"
        ):
            offenders.append(node.lineno)
    return offenders


def violations(tls_root: Path = TLS_ROOT) -> list[str]:
    """Return one message per forbidden subprocess call outside the executor."""
    failures: list[str] = []
    repo_root = tls_root.parents[3]
    for path in sorted(tls_root.rglob("*.py")):
        if path == EXECUTOR:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        relative = path.relative_to(repo_root)
        failures.extend(
            f"{relative}:{lineno} calls subprocess.run/Popen/call directly; "
            "route OpenSSL execution through openssl_probe/executor.py"
            for lineno in _offending_calls(tree)
        )
    return failures


def main() -> int:
    """Print any boundary breach and return nonzero if the boundary is broken."""
    failures = violations()
    if failures:
        print("OpenSSL subprocess boundary violated (coding-rules.md Rule 7.1):", file=sys.stderr)
        for failure in failures:
            print(f"  {failure}", file=sys.stderr)
        return 1
    print("OpenSSL subprocess boundary: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
