# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Regression tests for the generated data-model reference."""

from __future__ import annotations

import ast
import re
import subprocess
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_SCRIPT = _ROOT / "scripts" / "gen_data_model.py"


def _run_generator(*arguments: str) -> subprocess.CompletedProcess[str]:
    """Run the checked-in generator through the active Python interpreter."""
    return subprocess.run(  # noqa: S603 - fixed interpreter and repository script.
        [sys.executable, str(_SCRIPT), *arguments],
        cwd=_ROOT,
        capture_output=True,
        check=False,
        text=True,
        timeout=10,
    )


def test_checked_in_data_model_matches_generated_sections() -> None:
    """Require the committed reference to match the current source AST."""
    completed = _run_generator("--check")

    assert completed.returncode == 0, completed.stderr
    assert completed.stdout == ""


def test_enum_output_includes_serialized_values() -> None:
    """Distinguish Python enum members from their serialized wire values."""
    completed = _run_generator("--enums")

    assert completed.returncode == 0, completed.stderr
    assert '`QUANTUM_SAFE = "quantum_safe"`' in completed.stdout


def test_graph_declares_every_source_class() -> None:
    """Keep standalone classes visible in the complete class inventory."""
    completed = _run_generator("--graph")

    assert completed.returncode == 0, completed.stderr
    source_names = {
        node.name
        for path in (_ROOT / "src" / "qureddy").rglob("*.py")
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8")))
        if isinstance(node, ast.ClassDef)
    }
    graph_names = set(re.findall(r"^class ([A-Za-z_][A-Za-z0-9_]*)", completed.stdout, re.M))

    assert graph_names == source_names
