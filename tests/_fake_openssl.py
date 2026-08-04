# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Cross-platform paths for deterministic fake OpenSSL executables."""

from __future__ import annotations

import os
from pathlib import Path

FAKE_OPENSSL_DIR = Path(__file__).parent / "fixtures" / "openssl" / "fake"


def fake_openssl(name: str) -> str:
    """Return the native fake executable for a named scenario."""
    suffix = ".cmd" if os.name == "nt" else ".sh"
    return str(FAKE_OPENSSL_DIR / f"{name}{suffix}")
