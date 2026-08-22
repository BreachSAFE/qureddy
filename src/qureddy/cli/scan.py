# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""The `qureddy scan tls` command body and orchestration.

The TLS scanner has a dedicated public entry point alongside `cli/ssh.py`.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import IO, TextIO

import structlog
import typer

from qureddy._branding import PROJECT_URL
from qureddy.cli._errors import (
    EXIT_INTERNAL_ERROR,
    EXIT_LOCAL_DEPENDENCY,
    EXIT_OK,
    EXIT_TARGET_FAILED,
    EXIT_USAGE,
    _echo_operator_diagnostic,
    _fail,
)
from qureddy.cli._execute import _execute_scan
from qureddy.cli._help import (
    _NO_WRAP_CONTEXT_SETTINGS,
    _OUTPUT_HELP_SECTION,
    _colorize_help_text,
)
from qureddy.cli._options import (
    CompactOpt,
    FormatOpt,
    JsonLogsOpt,
    LogOpt,
    MinSeverityOpt,
    OpenSSLOpt,
    OutputOpt,
    QuietOpt,
    ReproducibleOpt,
    RetriesOpt,
    RetryDelayOpt,
    RetryOnOpt,
    SniOpt,
    TargetArg,
    TimeoutOpt,
    VerboseOpt,
)
from qureddy.cli._render import _open_output_file, _render
from qureddy.cli.main import scan_app
from qureddy.core.errors import RetryConfigError, TargetParseError
from qureddy.core.logging import start_run_logging
from qureddy.core.models import FailureCategory, OutputFormat, ScanTarget, Severity
from qureddy.core.retry import parse_retry_on, validate_retry_args
from qureddy.core.targets import parse_target
from qureddy.scanners.tls.openssl_probe import DEFAULT_TIMEOUT_SECONDS
from qureddy.scanners.tls.scanner import (
    RetryConfig,
    TLSScanner,
)

# Tier-2 epilog for `qureddy scan tls --help` (issue #41 / ADR 0003 patterns 3-4).
#
# Exit-code lines reference the EXIT_* constants so a contract change there
# (e.g. issue #12's exit 70) doesn't drift the help text — single source of
# truth per agent-antipatterns "Copy-paste duplication" rule.
#
# Why every paragraph starts with `\b\n`:
#   Click's text formatter collapses single `\n` into spaces within a
#   paragraph (issue #71). The `\b` marker (literal backspace, ASCII 8)
#   tells the formatter to preserve literal newlines for THAT paragraph.
#   Each paragraph (each EXAMPLES pair, each EXIT CODES table, each
#   ENVIRONMENT row) needs its own `\b\n` prefix because blank lines
#   between paragraphs end the `\b` block. Single `\b` at the top of a
#   block isn't enough — paragraphs after the first blank reflow again.
_SCAN_TLS_EPILOG = _colorize_help_text(f"""\
EXAMPLES:

\b
# Most common: scan a hostname with rich console output.
qureddy scan tls google.com

\b
# Machine-readable JSON for CI pipelines.
qureddy scan tls pq.cloudflareresearch.com --format json

\b
# Scan an IP target with an SNI override for a name-based virtual host.
qureddy scan tls 1.1.1.1:443 --sni one.one.one.one

\b
# Tolerate transient network hiccups (3 retries, 2s apart).
qureddy scan tls flaky.example.com --retry-on tls_handshake_failed --retries 3 --retry-delay 2

\b
# Compact JSON written straight to a file (stdout stays empty and clean).
qureddy scan tls example.com --format json --compact --output scan.json

\b
# Human report trimmed to medium-and-above findings (machine formats stay complete).
qureddy scan tls example.com --min-severity medium

{_OUTPUT_HELP_SECTION}

SCAN BEHAVIOR:

\b
A full scan runs separate probes for TLS 1.3 hybrid key exchange, a TLS 1.3
classical control, legacy TLS protocols, and certificate evidence. The
`--timeout` value applies to each probe, so total wall time can be several
times the timeout. Use `-vvv` to see every subprocess start and completion.

\b
For a faster diagnostic run, lower the per-probe timeout:
qureddy scan tls example.com --timeout 5 -vvv

EXIT CODES:

\b
{EXIT_OK}   scan succeeded
{EXIT_TARGET_FAILED}   target scan failed (handshake, parse, etc.)
{EXIT_LOCAL_DEPENDENCY}   local dependency missing or unsupported (requires OpenSSL 3.5.x LTS)
{EXIT_USAGE}   usage / configuration error
{EXIT_INTERNAL_ERROR}  internal qureddy error (BSD sysexits.h EX_SOFTWARE)

ENVIRONMENT:

\b
NO_COLOR         Disable ANSI color (https://no-color.org).

\b
QUREDDY_OPENSSL  Override path to an OpenSSL 3.5.x LTS binary
                 (precedence: --openssl > $QUREDDY_OPENSSL > $PATH).

Project: {PROJECT_URL}
""")


def _open_run_log(
    *, log: Path | None, machine_format: bool, verbose: int, json_logs: bool, quiet: bool
) -> TextIO | None:
    """Configure logging for one scan run; return the log-file stream (caller closes it).

    With ``--log`` set, machine-format auto-quiet does not apply and the level is floored at
    INFO so a clean run still records its story (otherwise a successful machine-format scan
    writes an empty WARNING-level log). A ``--log`` path that cannot be opened is a usage
    error (exit 4), reported before any scan work.
    """
    if log is not None:
        effective_quiet = quiet
        log_verbosity = verbose if quiet else max(verbose, 1)
    else:
        # JSON/CBOM stdout is a single machine-parsed document. The #15 fd-snapshot
        # fix only guards in-process stream rebinding (CliRunner, etc.); it cannot
        # protect real shell `2>&1` (the OS merged fd 1/2 before Python started —
        # #194), so a WARNING+ log line would corrupt that document for any real
        # `| jq` consumer. Default to quiet in these formats so the common case is
        # safe; an explicit -v/-vv/-vvv still wins (the user then accepts they must
        # keep stdout/stderr genuinely separate, not `2>&1`, to keep clean JSON).
        effective_quiet = quiet or (machine_format and verbose == 0)
        log_verbosity = verbose
    try:
        return start_run_logging(
            verbosity=log_verbosity, json_logs=json_logs, quiet=effective_quiet, log=log
        )
    except OSError as exc:
        _fail(f"cannot write --log file {log}: {exc.strerror or exc}", EXIT_USAGE)


@scan_app.command(
    "tls",
    epilog=_SCAN_TLS_EPILOG,
    # Issue #266: reuses the same _NO_WRAP_CONTEXT_SETTINGS as `app`/
    # `scan_app` instead of a separately-typed {"max_content_width": ...}
    # dict — one shared constant for "-h works + epilogs don't get
    # mangled" everywhere, so a future change can't add -h at one level
    # and silently miss another.
    context_settings=_NO_WRAP_CONTEXT_SETTINGS,
)
def scan_tls(
    target: TargetArg,
    sni: SniOpt = None,
    openssl: OpenSSLOpt = None,
    output_format: FormatOpt = OutputFormat.RICH,
    output: OutputOpt = None,
    compact: CompactOpt = False,
    min_severity: MinSeverityOpt = None,
    timeout: TimeoutOpt = DEFAULT_TIMEOUT_SECONDS,
    retry_on: RetryOnOpt = None,
    retries: RetriesOpt = 0,
    retry_delay: RetryDelayOpt = 1.0,
    verbose: VerboseOpt = 0,
    json_logs: JsonLogsOpt = False,
    quiet: QuietOpt = False,
    log: LogOpt = None,
    reproducible: ReproducibleOpt = False,
) -> None:
    """Scan a TLS endpoint for post-quantum readiness."""
    machine_format = output_format in (OutputFormat.JSON, OutputFormat.CBOM)
    log_stream = _open_run_log(
        log=log, machine_format=machine_format, verbose=verbose, json_logs=json_logs, quiet=quiet
    )
    try:
        # All scan/render work (including opening --output) lives in this try so
        # the log stream is always closed, even when arg parsing exits early
        # (an invalid --retry-on, or a bad --output path) — see #194 for why a
        # stray log line must never reach the machine document on stdout.
        exit_code = _scan_and_render(
            target=target,
            sni=sni,
            openssl=openssl,
            output_format=output_format,
            output=output,
            compact=compact,
            min_severity=min_severity,
            timeout=timeout,
            retry_on=retry_on,
            retries=retries,
            retry_delay=retry_delay,
            verbose=verbose,
            reproducible=reproducible,
            machine_format=machine_format,
        )
        raise typer.Exit(code=exit_code)
    finally:
        structlog.contextvars.clear_contextvars()
        if log_stream is not None:
            log_stream.close()


def _scan_and_render(
    *,
    target: str,
    sni: str | None,
    openssl: str | None,
    output_format: OutputFormat,
    output: Path | None,
    compact: bool,
    min_severity: Severity | None,
    timeout: int,
    retry_on: str | None,
    retries: int,
    retry_delay: float,
    verbose: int,
    reproducible: bool,
    machine_format: bool,
) -> int:
    """Open ``--output``, run one TLS scan, render, and return the exit code.

    The ``--output`` stream (when set) is owned here so it is always closed, and
    a path that cannot be opened exits 4 before any scan work — the same
    contract as ``--log``. When ``--output`` is unset the renderer writes to
    stdout as before.
    """
    output_stream: IO[str] | None = _open_output_file(output)
    try:
        retry_set = _parse_retry_args(retry_on, retries, retry_delay)
        scan_target = _parse_cli_target(target, sni)
        structlog.contextvars.bind_contextvars(target=scan_target.locator)
        scanner = TLSScanner(
            openssl_path=openssl,
            retry=RetryConfig(retries=retries, retry_delay=retry_delay, retry_on=retry_set),
        )
        result, exit_code = _execute_scan(
            scanner, scan_target, timeout, machine_format=machine_format
        )
        try:
            _render(
                result,
                output_format,
                verbose,
                reproducible=reproducible,
                compact=compact,
                min_severity=min_severity,
                stream=output_stream,
            )
        except ValueError as exc:
            # #344: a render-boundary defect (e.g. a semantic-validator ValueError) must map to
            # the exit-code contract, not escape as an internal traceback.
            _echo_operator_diagnostic(
                f"internal error rendering output: {exc}", machine_format=machine_format
            )
            return EXIT_INTERNAL_ERROR
        return exit_code
    finally:
        if output_stream is not None:
            output_stream.close()


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
        _fail(str(exc), EXIT_USAGE)
    return retry_set


def _block_internal_targets() -> bool:
    """Read the opt-in SSRF guard from the environment (Rule 5.6: env at the boundary).

    Off by default: a CLI operator deliberately chooses the target. An embedder that
    accepts an untrusted target sets QUREDDY_BLOCK_INTERNAL_TARGETS=1 (#134).
    """
    return os.environ.get("QUREDDY_BLOCK_INTERNAL_TARGETS", "").strip().lower() not in (
        "",
        "0",
        "false",
        "no",
    )


def _parse_cli_target(target: str, sni: str | None) -> ScanTarget:
    """Parse the positional target arg; exit 4 on a malformed target."""
    try:
        return parse_target(target, sni_override=sni, block_internal=_block_internal_targets())
    except TargetParseError as exc:
        _fail(f"invalid target: {exc}", EXIT_USAGE)
