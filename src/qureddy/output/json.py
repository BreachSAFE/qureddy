# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""JSON output adapter."""

from __future__ import annotations

import json
import sys
from typing import IO, TYPE_CHECKING

if TYPE_CHECKING:
    from qureddy.core.models import ScanResult


def render_json(result: ScanResult, stream: IO[str] = sys.stdout) -> None:
    """Render a ScanResult as JSON to the given stream.

    Uses Pydantic's `model_dump(mode="json")` for stable serialization.
    Top-level keys appear in the order defined by the ScanResult model
    (`schema_version`, `scan`, `target`, `dependencies`, `assets`,
    `evidence`, `findings`, `summary`).
    """
    payload = result.model_dump(mode="json")
    json.dump(payload, stream, indent=2, sort_keys=False)
    stream.write("\n")
