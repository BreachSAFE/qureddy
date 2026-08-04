# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Regression test for QuReddy's repository-local documentation contract."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType


def _load_docs_check() -> ModuleType:
    path = Path(__file__).parents[1] / "scripts" / "check_docs.py"
    spec = importlib.util.spec_from_file_location("check_docs", path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["check_docs"] = module
    spec.loader.exec_module(module)
    return module


def test_first_party_documentation_contract() -> None:
    """Every tracked first-party document has a numbered contents list and valid anchors."""
    assert _load_docs_check().main() == 0
