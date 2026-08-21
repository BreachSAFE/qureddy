# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""JSON output adapter."""

from __future__ import annotations

import json
import sys
from typing import IO, TYPE_CHECKING

if TYPE_CHECKING:
    from qureddy.core.models import ScanResult


def render_json(
    result: ScanResult, stream: IO[str] | None = None, *, compact: bool = False
) -> None:
    """Render a ScanResult as JSON to the given stream (default: current sys.stdout).

    Uses Pydantic's `model_dump(mode="json")` for stable serialization.
    Top-level keys appear in the order defined by the ScanResult model
    (`schema_version`, `scan`, `target`, `dependencies`, `assets`,
    `evidence`, `findings`, `summary`).

    When ``compact`` is set the document is minified to a single line with no
    whitespace between tokens (issue #133) — the CI/streaming default for
    `| jq` and log shippers. Pretty (indent=2) stays the default. Either way
    exactly one parseable document plus a trailing newline is written, so the
    machine-purity contract (issue #30) is unaffected.

    Issue #237: `stream: IO[str] = sys.stdout` as a default is resolved
    once at function-definition time, not per call — a caller relying on
    the default after `sys.stdout` is reassigned (`contextlib.redirect_stdout`,
    pytest capture, console wrappers) silently writes to the stale
    original object. Resolve at call time instead.
    """
    target_stream = stream if stream is not None else sys.stdout
    payload = result.model_dump(mode="json")
    # ``ensure_ascii`` is an output-boundary guarantee: machine JSON remains
    # writable even when an embedding caller supplies a legacy Windows text
    # stream instead of entering through the UTF-8-configured CLI.
    if compact:
        json.dump(payload, target_stream, separators=(",", ":"), sort_keys=False, ensure_ascii=True)
    else:
        json.dump(payload, target_stream, indent=2, sort_keys=False, ensure_ascii=True)
    target_stream.write("\n")
