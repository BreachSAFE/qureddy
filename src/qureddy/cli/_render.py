# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Output-format dispatch and output-file handling for the scan commands."""

from __future__ import annotations

import sys
from typing import IO, TYPE_CHECKING

from qureddy.cli._errors import EXIT_USAGE, _fail
from qureddy.core.models import OutputFormat, ScanResult, Severity
from qureddy.output.cbom import render_cbom
from qureddy.output.console import render_rich
from qureddy.output.json import render_json

if TYPE_CHECKING:
    from pathlib import Path


def _open_output_file(output: Path | None) -> IO[str] | None:
    """Open the ``--output`` destination for writing; return None when unset.

    A path that cannot be opened is a usage error (exit 4), reported before any
    scan work — the same failure contract as ``--log`` in ``scan.py``. The
    caller owns the returned stream and closes it.
    """
    if output is None:
        return None
    try:
        return output.open("w", encoding="utf-8")
    except OSError as exc:
        _fail(f"cannot write --output file {output}: {exc.strerror or exc}", EXIT_USAGE)


def _render(
    result: ScanResult,
    output_format: OutputFormat,
    verbose: int,
    *,
    reproducible: bool = False,
    compact: bool = False,
    min_severity: Severity | None = None,
    stream: IO[str] | None = None,
) -> None:
    """Dispatch to the JSON, CBOM, or Rich renderer.

    ``stream`` defaults to the current ``sys.stdout``; ``--output`` supplies a
    file stream instead, which keeps stdout empty (and byte-clean) for the
    machine formats. ``compact`` minifies the JSON/CBOM document; ``min_severity``
    trims the human findings table only — the machine document stays complete
    (issue #30 machine-purity contract).
    """
    target = stream if stream is not None else sys.stdout
    if output_format is OutputFormat.JSON:
        render_json(result, target, compact=compact)
    elif output_format is OutputFormat.CBOM:
        render_cbom(result, target, reproducible=reproducible, compact=compact)
    else:
        render_rich(result, target, verbosity=verbose, min_severity=min_severity)
