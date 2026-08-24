# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Output-format dispatch and output-file handling for the scan commands."""

from __future__ import annotations

import io
import sys
from pathlib import Path
from typing import IO

from qureddy.cli._errors import EXIT_USAGE, _fail
from qureddy.core.models import OutputFormat, ScanResult, Severity
from qureddy.output.cbom import render_cbom
from qureddy.output.console import render_rich
from qureddy.output.json import render_json
from qureddy.output.jsonl import render_jsonl


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


def _prepare_output_dir(output_dir: Path | None, output: Path | None) -> None:
    """Validate and create a bundle directory before scan work begins."""
    if output_dir is None:
        return
    if output is not None:
        _fail("--output and --output-dir cannot be used together", EXIT_USAGE)
    try:
        output_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        _fail(f"cannot create --output-dir {output_dir}: {exc.strerror or exc}", EXIT_USAGE)


def _render_bundle(
    result: ScanResult,
    output_dir: Path,
    *,
    reproducible: bool,
    compact: bool,
) -> None:
    """Write every currently supported projection of one scan result."""
    json_stream = io.StringIO()
    cbom_stream = io.StringIO()
    jsonl_stream = io.StringIO()
    rich_stream = io.StringIO()
    render_json(result, json_stream, compact=compact)
    render_cbom(result, cbom_stream, reproducible=reproducible, compact=compact)
    render_jsonl(result, jsonl_stream)
    render_rich(result, rich_stream)
    try:
        (output_dir / "scan.json").write_text(json_stream.getvalue(), encoding="utf-8")
        (output_dir / "scan.cdx.json").write_text(cbom_stream.getvalue(), encoding="utf-8")
        (output_dir / "scan.jsonl").write_text(jsonl_stream.getvalue(), encoding="utf-8")
        (output_dir / "scan.rich.txt").write_text(rich_stream.getvalue(), encoding="utf-8")
    except OSError as exc:
        _fail(f"cannot write scan bundle in {output_dir}: {exc.strerror or exc}", EXIT_USAGE)


def _render(
    result: ScanResult,
    output_format: OutputFormat,
    verbose: int,
    *,
    reproducible: bool = False,
    compact: bool = False,
    min_severity: Severity | None = None,
    stream: IO[str] | None = None,
    output_dir: Path | None = None,
) -> None:
    """Dispatch to the JSON, CBOM, JSONL, or Rich renderer.

    ``stream`` defaults to the current ``sys.stdout``; ``--output`` supplies a
    file stream instead, which keeps stdout empty (and byte-clean) for the
    machine formats. ``compact`` minifies the JSON/CBOM document; ``min_severity``
    trims the human findings table only — the machine document stays complete
    (issue #30 machine-purity contract).
    """
    if output_dir is not None:
        _render_bundle(result, output_dir, reproducible=reproducible, compact=compact)
        return
    target = stream if stream is not None else sys.stdout
    if output_format is OutputFormat.JSON:
        render_json(result, target, compact=compact)
    elif output_format is OutputFormat.CBOM:
        render_cbom(result, target, reproducible=reproducible, compact=compact)
    elif output_format is OutputFormat.JSONL:
        render_jsonl(result, target)
    else:
        render_rich(result, target, verbosity=verbose, min_severity=min_severity)
