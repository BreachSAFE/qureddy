#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Enforce QuReddy's Python file, function, and class size ceilings."""

from __future__ import annotations

import ast
import sys
from pathlib import Path

FILE_CEILING = 400
FUNCTION_CEILING = 50
CLASS_CEILING = 200
SOURCE_ROOT = Path(__file__).resolve().parents[1] / "src" / "qureddy"


def _docstring_range(node: ast.AST) -> range:
    body = getattr(node, "body", [])
    if (
        body
        and isinstance(body[0], ast.Expr)
        and isinstance(body[0].value, ast.Constant)
        and isinstance(body[0].value.value, str)
    ):
        return range(body[0].lineno, body[0].end_lineno + 1)
    return range(0)


def _logical_line_count(lines: list[str], node: ast.AST) -> int:
    start = getattr(node, "lineno", 1)
    end = getattr(node, "end_lineno", len(lines))
    docstring_lines = _docstring_range(node)
    return sum(
        1
        for number, line in enumerate(lines[start - 1 : end], start=start)
        if line.strip() and number not in docstring_lines
    )


def violations(source_root: Path = SOURCE_ROOT) -> list[str]:
    """Return stable descriptions of source-size ceiling breaches."""
    failures: list[str] = []
    for path in sorted(source_root.rglob("*.py")):
        source = path.read_text(encoding="utf-8")
        lines = source.splitlines()
        tree = ast.parse(source)
        line_count = _logical_line_count(lines, tree)
        relative = path.relative_to(source_root.parent.parent)
        if line_count > FILE_CEILING:
            failures.append(f"{relative}: {line_count} lines exceeds {FILE_CEILING}")
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                limit = FUNCTION_CEILING
            elif isinstance(node, ast.ClassDef):
                limit = CLASS_CEILING
            else:
                continue
            logical_lines = _logical_line_count(lines, node)
            if logical_lines > limit:
                failures.append(
                    f"{relative}:{node.lineno} {node.name}: {logical_lines} lines exceeds {limit}"
                )
    return failures


def main() -> int:
    """Print policy results and return nonzero on any hard-ceiling breach."""
    failures = violations()
    if failures:
        print("File/function/class size policy failed:", file=sys.stderr)
        for failure in failures:
            print(f"  {failure}", file=sys.stderr)
        return 1
    print("File/function/class size policy: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
