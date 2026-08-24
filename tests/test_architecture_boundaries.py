# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Architecture boundaries for output and common posture layers."""

from __future__ import annotations

import re
from pathlib import Path

OUTPUT_ROOT = Path(__file__).parents[1] / "src" / "qureddy" / "output"
TLS_IMPORT = re.compile(r"(?:from|import)\s+qureddy\.scanners\.tls(?:\.|\s|$)")


def test_output_does_not_import_tls_scanner_modules() -> None:
    """Output adapters depend on canonical models, not TLS collector modules."""
    violations = [
        str(path.relative_to(OUTPUT_ROOT))
        for path in OUTPUT_ROOT.rglob("*.py")
        if TLS_IMPORT.search(path.read_text(encoding="utf-8"))
    ]
    assert violations == []
