# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Canonical CLI option declarations, one `Annotated` alias per option.

Module-level Annotated aliases compress the Typer option surface so
each command body stays under the 50-line ceiling. Each `OptT` is the
single canonical declaration of one CLI option.
"""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer

from qureddy._branding import VERSION_BANNER
from qureddy.cli._errors import EXIT_OK
from qureddy.core.models import OutputFormat, Severity
from qureddy.core.retry import MAX_RETRIES, MAX_RETRY_DELAY_SECONDS, RETRYABLE_CATEGORY_VALUES

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
SshTargetArg = Annotated[
    str,
    typer.Argument(help="SSH endpoint: host[:port], bracketed IPv6, ssh://host, or sftp://host."),
]
SniOpt = Annotated[
    str | None,
    typer.Option("--sni", help="SNI override (recommended for name-based virtual hosts)."),
]
OpenSSLOpt = Annotated[
    str | None, typer.Option("--openssl", help="Path to an OpenSSL 3.5.x LTS binary.")
]
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
        help="Output format: rich | json | cbom | jsonl (repeat to override; last wins).",
        case_sensitive=False,
    ),
]
DeterministicOpt = Annotated[
    bool,
    typer.Option(
        "--deterministic",
        help="CBOM: omit per-run identity (serial, timestamps, scan id) for a stable digest.",
    ),
]
# Keep the old spelling parseable for one deprecation cycle without advertising it in help.  Typer
# does not expose Click's ``hidden`` option in its public Option() signature, but OptionInfo carries
# the attribute through to TyperOption, where Click honors it.
_DEPRECATED_REPRODUCIBLE_OPTION = typer.Option(
    "--reproducible",
    help="Deprecated alias for --deterministic.",
)
_DEPRECATED_REPRODUCIBLE_OPTION.hidden = True
DeprecatedReproducibleOpt = Annotated[bool, _DEPRECATED_REPRODUCIBLE_OPTION]
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
    str | None,
    typer.Option(
        "--retry-on",
        metavar="CATEGORY[,CATEGORY...]",
        help=(
            "Comma-separated retryable failure categories. Choices: "
            + ", ".join(RETRYABLE_CATEGORY_VALUES)
            + "."
        ),
    ),
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
    int,
    typer.Option(
        "-v",
        "--verbose",
        count=True,
        help=(
            "Levels: -v INFO logs; -vv DEBUG logs including subprocess boundaries; "
            "-vvv also shows exact commands in Rich output and internal-error tracebacks."
        ),
    ),
]
JsonLogsOpt = Annotated[bool, typer.Option("--json-logs", help="Emit JSON-formatted logs.")]
QuietOpt = Annotated[bool, typer.Option("-q", "--quiet", help="Suppress non-error logs.")]
LogOpt = Annotated[
    Path | None,
    typer.Option(
        "--log",
        help="Capture this run's logs to a file (INFO and above; honors --json-logs). "
        "-q only affects stderr; the file always captures INFO and above. Default: logs go "
        "to stderr.",
    ),
]
OutputOpt = Annotated[
    Path | None,
    typer.Option(
        "--output",
        "-o",
        help="Write the rendered document to a file instead of standard output "
        "(stdout stays clean; exit codes unchanged). A path that cannot be opened exits 4.",
    ),
]
OutputDirOpt = Annotated[
    Path | None,
    typer.Option(
        "--output-dir",
        help="Write every supported projection to this run directory (JSON, CBOM, JSONL, Rich).",
    ),
]
CompactOpt = Annotated[
    bool,
    typer.Option(
        "--compact",
        help="Machine formats (--format json | cbom): emit minified single-line JSON. "
        "JSONL is always one object per line. Default: indented. No effect on --format rich.",
    ),
]
MinSeverityOpt = Annotated[
    Severity | None,
    typer.Option(
        "--min-severity",
        help="Rich output only: hide findings below this severity "
        "(critical | high | medium | low | info). Machine formats (json/cbom) stay complete.",
        case_sensitive=False,
    ),
]
