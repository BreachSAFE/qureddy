# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Canonical CLI option declarations, one `Annotated` alias per option.

Module-level Annotated aliases compress the Typer option surface so
each command body stays under the 50-line ceiling. Each `OptT` is the
single canonical declaration of one CLI option.
"""

from __future__ import annotations

from typing import Annotated

import typer

from qureddy._branding import VERSION_BANNER
from qureddy.cli._errors import EXIT_OK
from qureddy.core.models import OutputFormat
from qureddy.core.retry import MAX_RETRIES, MAX_RETRY_DELAY_SECONDS

_MAX_TIMEOUT_SECONDS = 300


def _version_callback(value: bool) -> None:
    """Eager --version callback: print banner, exit 0.

    `is_eager=True` runs this during option parsing, before any
    subcommand resolution — without it Typer would try to dispatch a
    (missing) command before the callback fires.
    """
    if value:
        typer.echo(VERSION_BANNER)
        raise typer.Exit(code=EXIT_OK)


VersionOpt = Annotated[
    bool | None,
    typer.Option(
        "--version",
        "-V",
        callback=_version_callback,
        is_eager=True,
        help="Show version and exit.",
    ),
]

TargetArg = Annotated[str, typer.Argument(help="Target host[:port], URL, or IP.")]
SniOpt = Annotated[
    str | None, typer.Option("--sni", help="SNI override (required for IP targets).")
]
OpenSSLOpt = Annotated[str | None, typer.Option("--openssl", help="Path to OpenSSL 3.5+ binary.")]
FormatOpt = Annotated[
    OutputFormat,
    # Issue #266: this string had drifted out of sync with OutputFormat
    # (which already has RICH/JSON/CBOM) — the auto-generated metavar
    # showed "--format <rich|json|cbom>" right next to a description
    # that only listed two of the three, contradicting itself in the
    # same line of --help output.
    # Issue #266 item 4: --format is single-value; passing it twice
    # silently keeps the last one (standard Click behavior for a
    # non-multiple Option) — documented here rather than left as a
    # silent footgun for a scripted second --format elsewhere in a
    # command line.
    typer.Option(
        "--format",
        help="Output format: rich | json | cbom (repeat to override; last wins).",
        case_sensitive=False,
    ),
]
TimeoutOpt = Annotated[
    int,
    typer.Option(
        "--timeout",
        help="Per-probe timeout in seconds.",
        min=1,
        max=_MAX_TIMEOUT_SECONDS,
    ),
]
RetryOnOpt = Annotated[
    str | None, typer.Option("--retry-on", help="Comma-separated retryable failure categories.")
]
RetriesOpt = Annotated[
    int,
    typer.Option("--retries", help="Additional retry attempts (max 3).", min=0, max=MAX_RETRIES),
]
RetryDelayOpt = Annotated[
    float,
    typer.Option(
        "--retry-delay",
        help="Seconds between retries (max 10).",
        min=0.0,
        max=MAX_RETRY_DELAY_SECONDS,
    ),
]
VerboseOpt = Annotated[
    int, typer.Option("-v", "--verbose", count=True, help="Verbosity (-v/-vv/-vvv).")
]
JsonLogsOpt = Annotated[bool, typer.Option("--json-logs", help="Emit JSON-formatted logs.")]
QuietOpt = Annotated[bool, typer.Option("-q", "--quiet", help="Suppress non-error logs.")]
