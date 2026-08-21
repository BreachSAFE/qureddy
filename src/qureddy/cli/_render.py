# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Output-format dispatch for the `scan tls` command."""

from __future__ import annotations

import sys

from qureddy.core.models import OutputFormat, ScanResult
from qureddy.output.cbom import render_cbom
from qureddy.output.console import render_rich
from qureddy.output.json import render_json


def _render(
    result: ScanResult,
    output_format: OutputFormat,
    verbose: int,
    *,
    reproducible: bool = False,
) -> None:
    """Dispatch to the JSON, CBOM, or Rich renderer."""
    if output_format is OutputFormat.JSON:
        render_json(result, sys.stdout)
    elif output_format is OutputFormat.CBOM:
        render_cbom(result, sys.stdout, reproducible=reproducible)
    else:
        render_rich(result, sys.stdout, verbosity=verbose)
