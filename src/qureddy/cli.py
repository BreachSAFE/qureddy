# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Typer CLI entry point for the qureddy command.

Per skill §"Exit codes" + issue #12:
- 0: scan succeeded
- 2: target scan failed
- 3: local dependency missing or unsupported
- 4: usage / configuration error
- 70: internal qureddy error (BSD sysexits.h EX_SOFTWARE)
"""

from __future__ import annotations

import sys
from typing import Annotated

import click
import structlog
import typer

from qureddy._branding import (
    PROJECT_NAME,
    VERSION_BANNER,
)
from qureddy.core.errors import (
    LocalOpenSSLLacksGroup,
    LocalOpenSSLMissing,
    LocalOpenSSLTooOld,
    QureddyError,
    RetryConfigError,
    TargetParseError,
)
from qureddy.core.logging import configure_logging, get_logger
from qureddy.core.models import (
    FailureCategory,
    OpenSSLDependency,
    OutputFormat,
    ScanResult,
    ScanTarget,
)
from qureddy.core.retry import (
    MAX_RETRIES,
    MAX_RETRY_DELAY_SECONDS,
    parse_retry_on,
    validate_retry_args,
)
from qureddy.core.targets import parse_target
from qureddy.output.console import render_rich
from qureddy.output.json import render_json
from qureddy.scanners.tls.openssl_probe import DEFAULT_TIMEOUT_SECONDS
from qureddy.scanners.tls.scanner import (
    RetryConfig,
    TLSScanner,
    build_capability_failure_result,
)

EXIT_OK = 0
EXIT_TARGET_FAILED = 2
EXIT_LOCAL_DEPENDENCY = 3
EXIT_USAGE = 4
EXIT_INTERNAL_ERROR = 70  # BSD sysexits.h EX_SOFTWARE — distinct from EXIT_TARGET_FAILED

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


app = typer.Typer(
    name="qureddy",
    help=f"{PROJECT_NAME} -- post-quantum TLS readiness scanner.",
    no_args_is_help=True,
    add_completion=False,
)
scan_app = typer.Typer(help="Run scans.", no_args_is_help=True)
app.add_typer(scan_app, name="scan")


@app.callback()
def _root(
    version: VersionOpt = None,
) -> None:
    """BreachSAFE QuReddy -- post-quantum TLS readiness scanner.

    Root callback exists so `--version` can be wired at the app level
    (visible from `qureddy --version` without a subcommand). The body
    is empty because `_version_callback` short-circuits via
    `is_eager=True`.
    """


# Module-level Annotated aliases compress the Typer option surface so
# the @scan_app.command body stays under the 50-line ceiling. Each
# `OptT` is the single canonical declaration of one CLI option.
TargetArg = Annotated[str, typer.Argument(help="Target host[:port], URL, or IP.")]
SniOpt = Annotated[
    str | None, typer.Option("--sni", help="SNI override (required for IP targets).")
]
OpenSSLOpt = Annotated[str | None, typer.Option("--openssl", help="Path to OpenSSL 3.5+ binary.")]
FormatOpt = Annotated[
    OutputFormat,
    typer.Option("--format", help="Output format: rich | json", case_sensitive=False),
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


@scan_app.command("tls")
def scan_tls(
    target: TargetArg,
    sni: SniOpt = None,
    openssl: OpenSSLOpt = None,
    output_format: FormatOpt = OutputFormat.RICH,
    timeout: TimeoutOpt = DEFAULT_TIMEOUT_SECONDS,
    retry_on: RetryOnOpt = None,
    retries: RetriesOpt = 0,
    retry_delay: RetryDelayOpt = 1.0,
    verbose: VerboseOpt = 0,
    json_logs: JsonLogsOpt = False,
    quiet: QuietOpt = False,
) -> None:
    """Scan a TLS endpoint for post-quantum readiness."""
    configure_logging(verbosity=verbose, json_logs=json_logs, quiet=quiet)
    retry_set = _parse_retry_args(retry_on, retries, retry_delay)
    scan_target = _parse_cli_target(target, sni)
    structlog.contextvars.bind_contextvars(target=scan_target.locator)
    try:
        scanner = TLSScanner(
            openssl_path=openssl,
            retry=RetryConfig(retries=retries, retry_delay=retry_delay, retry_on=retry_set),
        )
        result, exit_code = _execute_scan(scanner, scan_target, timeout)
        _render(result, output_format, verbose)
        raise typer.Exit(code=exit_code)
    finally:
        structlog.contextvars.clear_contextvars()


def _parse_retry_args(
    retry_on: str | None,
    retries: int,
    retry_delay: float,
) -> frozenset[FailureCategory]:
    """Parse + validate retry CLI args; exit 4 on bad input."""
    try:
        retry_set = parse_retry_on(retry_on)
        validate_retry_args(retries=retries, retry_delay=retry_delay, retry_on=retry_set)
    except RetryConfigError as exc:
        typer.echo(f"qureddy: {exc}", err=True)
        raise typer.Exit(code=EXIT_USAGE) from None
    return retry_set


def _parse_cli_target(target: str, sni: str | None) -> ScanTarget:
    """Parse the positional target arg; exit 4 on a malformed target."""
    try:
        return parse_target(target, sni_override=sni)
    except TargetParseError as exc:
        typer.echo(f"qureddy: invalid target: {exc}", err=True)
        raise typer.Exit(code=EXIT_USAGE) from None


def _execute_scan(
    scanner: TLSScanner,
    scan_target: ScanTarget,
    timeout: int,
) -> tuple[ScanResult, int]:
    """Run the scan; map local-capability + scan failures to exit codes.

    Returns `(result, exit_code)`. Exit codes: 0 ok, 2 target failed,
    3 local dependency, 4 usage (handled upstream).
    """
    log = get_logger("qureddy.cli")
    try:
        result = scanner.scan(scan_target, timeout_seconds=timeout)
        exit_code = EXIT_OK
    except (LocalOpenSSLMissing, LocalOpenSSLTooOld, LocalOpenSSLLacksGroup) as exc:
        log.warning("scan.local_dependency_unusable", error=str(exc))
        # Consume exc.dependency directly. Re-probing would waste a
        # subprocess and open a TOCTOU window.
        dependency = exc.dependency or OpenSSLDependency(
            failure_category=FailureCategory.LOCAL_OPENSSL_MISSING,
        )
        result = build_capability_failure_result(scan_target, dependency)
        exit_code = EXIT_LOCAL_DEPENDENCY
    except QureddyError as exc:
        log.exception("scan.failed", error=str(exc))
        typer.echo(f"qureddy: scan failed: {exc}", err=True)
        raise typer.Exit(code=EXIT_TARGET_FAILED) from None

    if exit_code == EXIT_OK and result.summary.failure_category is not None:
        exit_code = EXIT_TARGET_FAILED
    return result, exit_code


def _render(result: ScanResult, output_format: OutputFormat, verbose: int) -> None:
    """Dispatch to the JSON or Rich renderer."""
    if output_format is OutputFormat.JSON:
        render_json(result, sys.stdout)
    else:
        render_rich(result, sys.stdout, verbosity=verbose)


def main() -> None:
    """Entry point that maps Click usage errors to project exit code 4.

    Typer/Click default to exit code 2 for invalid options (e.g. an
    unknown `--format` value or a malformed `--retries` integer). The
    project's documented exit-code surface uses 2 for *target scan
    failure*, so usage errors must surface as 4. This wrapper catches
    `click.UsageError` and `click.BadParameter` and re-exits with 4.
    """
    try:
        exit_code = app(standalone_mode=False)
    except click.exceptions.UsageError as exc:
        exc.show(file=sys.stderr)
        sys.exit(EXIT_USAGE)
    except click.exceptions.Exit as exc:
        sys.exit(exc.exit_code)
    except SystemExit:
        raise
    except Exception as exc:  # noqa: BLE001 -- last-resort top-level catch
        # Internal qureddy bugs route to EX_SOFTWARE (70), not exit 2.
        # CI scripts branching on `$? == 2` must be able to trust that
        # 2 means "target scan failed", not "qureddy itself crashed".
        sys.stderr.write(f"qureddy: unexpected error: {exc}\n")
        sys.exit(EXIT_INTERNAL_ERROR)
    sys.exit(EXIT_OK if exit_code is None else exit_code)
