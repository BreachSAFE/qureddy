# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Typer CLI package for the qureddy command (ADR 0005 split of cli.py).

Public surface: `app` (the Typer application) and `main` (the installed
`qureddy` entry point, wired in pyproject's `[project.scripts]`). The
sibling modules hold one purpose each: `_errors` (exit codes +
diagnostics), `_help` (help machinery), `_options` (option
declarations), `_render` (output dispatch), `main` (app assembly +
entry point), `scan` / `ssh` (the subcommand bodies).

The subcommand imports below are load-bearing: importing `scan` and
`ssh` registers their commands onto `scan_app`, in that order — which
fixes the `qureddy scan --help` command listing (tls before ssh),
matching the pre-split single-file definition order.
"""

from __future__ import annotations

from qureddy._branding import PROJECT_NAME, VERSION_BANNER
from qureddy.cli import scan, ssh  # noqa: F401  -- command registration (see docstring)
from qureddy.cli.main import app, main
from qureddy.core.retry import MAX_RETRIES, MAX_RETRY_DELAY_SECONDS

__all__ = [
    # Legacy compatibility: the pre-split cli.py imported these names at
    # module level and tests assert identity against their canonical homes
    # (tests/test_branding.py, tests/test_cli.py). Canonical paths remain
    # qureddy._branding and qureddy.core.retry.
    "MAX_RETRIES",
    "MAX_RETRY_DELAY_SECONDS",
    "PROJECT_NAME",
    "VERSION_BANNER",
    # Genuine public API.
    "app",
    "main",
]
