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

import re
import sys
from typing import Annotated

import click
import structlog
import typer

from qureddy._branding import (
    PROJECT_NAME,
    PROJECT_URL,
    VERSION_BANNER,
)
from qureddy.core.errors import (
    LocalOpenSSLBroken,
    LocalOpenSSLIsLibreSSL,
    LocalOpenSSLLacksGroup,
    LocalOpenSSLMissing,
    LocalOpenSSLTooOld,
    LocalOpenSSLVersionUnreadable,
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
from qureddy.output.cbom import render_cbom
from qureddy.output.console import render_rich
from qureddy.output.json import render_json
from qureddy.scanners.tls.cert_probe import (
    CertificateInfo,
    fetch_certificate_pem,
    parse_certificate,
)
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
    # rich_markup_mode=None disables Typer's Rich-based formatter for help
    # output; falls back to Click's classic formatter which respects literal
    # newlines + the `\b` form-feed convention. Required for the multi-line
    # epilog blocks (EXAMPLES, EXIT CODES, ENVIRONMENT) to render one item
    # per line. See issue #71 for the full investigation.
    rich_markup_mode=None,
)
scan_app = typer.Typer(
    help="Run scans.",
    no_args_is_help=True,
    rich_markup_mode=None,
)
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
_SCAN_TLS_EPILOG = f"""\
EXAMPLES:

\b
# Most common: scan a hostname with rich console output.
qureddy scan tls google.com

\b
# Machine-readable JSON for CI pipelines.
qureddy scan tls pq.cloudflareresearch.com --format json

\b
# Scan an IP target (SNI override required).
qureddy scan tls 1.1.1.1:443 --sni one.one.one.one

\b
# Tolerate transient network hiccups (3 retries, 2s apart).
qureddy scan tls flaky.example.com --retry-on tls_handshake_failed --retries 3 --retry-delay 2

EXIT CODES:

\b
{EXIT_OK}   scan succeeded
{EXIT_TARGET_FAILED}   target scan failed (handshake, parse, etc.)
{EXIT_LOCAL_DEPENDENCY}   local dependency missing or unsupported (OpenSSL <3.5)
{EXIT_USAGE}   usage / configuration error
{EXIT_INTERNAL_ERROR}  internal qureddy error (BSD sysexits.h EX_SOFTWARE)

ENVIRONMENT:

\b
NO_COLOR         Disable ANSI color (https://no-color.org).

\b
QUREDDY_OPENSSL  Override path to the OpenSSL 3.5+ binary
                 (precedence: --openssl > $QUREDDY_OPENSSL > $PATH).

Project: {PROJECT_URL}
"""


@scan_app.command(
    "tls",
    epilog=_SCAN_TLS_EPILOG,
    # Disable Click's text-wrapping for the epilog. With wrapping on,
    # `\b` blocks still see individual `\n` chars merged within a
    # paragraph (issue #71). Setting max_content_width to a very large
    # value tells Click "don't wrap" — the epilog string's literal
    # newlines survive. Option-table column widths are unaffected
    # because they have their own column-fitting logic.
    context_settings={"max_content_width": 10000},
)
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
    # JSON/CBOM stdout is a single machine-parsed document. The #15 fd-snapshot
    # fix only protects against in-process stream rebinding (CliRunner, etc.);
    # it cannot protect real shell `2>&1` (the OS has already merged fd 1/2
    # before Python starts — see issue #194). A WARNING+ log line during the
    # scan silently corrupts that document for any real `| jq`-style consumer.
    # Default to quiet in these formats so the common case is safe by
    # default; an explicit -v/-vv/-vvv still wins, since that's the user
    # asking for diagnostics and accepting they must keep stdout/stderr
    # genuinely separate (not `2>&1`) to still get clean JSON.
    machine_format = output_format in (OutputFormat.JSON, OutputFormat.CBOM)
    effective_quiet = quiet or (machine_format and verbose == 0)
    configure_logging(verbosity=verbose, json_logs=json_logs, quiet=effective_quiet)
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
    except (
        LocalOpenSSLBroken,
        LocalOpenSSLMissing,
        LocalOpenSSLTooOld,
        LocalOpenSSLVersionUnreadable,
        LocalOpenSSLIsLibreSSL,
        LocalOpenSSLLacksGroup,
    ) as exc:
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
    """Dispatch to the JSON, CBOM, or Rich renderer."""
    if output_format is OutputFormat.JSON:
        render_json(result, sys.stdout)
    elif output_format is OutputFormat.CBOM:
        render_cbom(result, sys.stdout, certificate=_fetch_cert_for_cbom(result))
    else:
        render_rich(result, sys.stdout, verbosity=verbose)


def _fetch_cert_for_cbom(result: ScanResult) -> CertificateInfo | None:
    """Best-effort certificate fetch for CBOM output.

    Reviewer-flagged bug: this call path did not exist, so cbom.py's
    certificate-component code was dead — render_cbom was always called
    with certificate=None.

    Uses the already-resolved OpenSSL path from the scan's own dependency
    check (`result.dependencies[0].path`) rather than re-resolving —
    avoids a second capability probe and stays consistent with whatever
    binary the scan itself used. Swallows fetch/parse failures: a missing
    certificate must not turn a successful TLS scan into a CBOM-export
    failure, since the CBOM is still valid (just certificate-less) without
    one.

    Raises AssertionError (not a bare `assert`, which `python -O` strips)
    if more than one dependency is present: every `TLSScanner` call site
    (`scanner.py` lines 125, 229) constructs `dependencies=(dependency,)`
    as a single-element tuple — this is a real MVP 0.1 invariant (one
    scanner, one OpenSSL dependency), not a coincidence. Enforcing it
    here means a future second-scanner change that breaks the invariant
    fails loudly at this call site instead of this function silently
    picking `[0]` and reporting the wrong binary's certificate.
    """
    if not result.dependencies:
        return None
    if len(result.dependencies) != 1:
        msg = (
            f"expected exactly one OpenSSL dependency, got {len(result.dependencies)} "
            "— _fetch_cert_for_cbom's use of dependencies[0] assumes the MVP 0.1 "
            "single-scanner invariant"
        )
        raise AssertionError(msg)
    if not result.dependencies[0].path:
        return None
    openssl_path = result.dependencies[0].path
    try:
        pem = fetch_certificate_pem(
            openssl_path, result.target.host, result.target.port, result.target.sni
        )
        return parse_certificate(openssl_path, pem) if pem else None
    except (LocalOpenSSLMissing, ValueError):
        return None


def _is_version_misplacement(exc: Exception) -> bool:
    """Detect the `--version` / `-V` on a subcommand UsageError shape.

    Click's default error reads `No such option: --version Did you mean
    --verbose?` which is unhelpful — `--version` lives at the root and
    works fine; the user just put it in the wrong position. Catch this
    specific shape so we can replace with an actionable hint.
    """
    msg = str(getattr(exc, "message", "") or "")
    if "No such option" not in msg:
        return False
    return "--version" in msg or "'-V'" in msg or " -V " in msg


# `--v` / `--vv` / `--vvv` etc — double-dash followed by 1+ `v`s as a
# whole token. Excludes `--version` (longer match, has trailing chars).
_VERBOSITY_DASH_CONFUSION_RE = re.compile(r"--v+(?:\s|$|'|\")")


def _is_verbosity_dash_confusion(exc: Exception) -> bool:
    """Detect `--v`, `--vv`, `--vvv`, `--vvvv` and `--verbos*` typos (#74).

    Click's default error for these reads `No such option: --vvv` with
    no hint that the correct invocation is `-vvv` (single-dash, stackable
    per POSIX). This detector matches the dash-confusion error shape so
    the wrapper can substitute an actionable hint.

    Matches:
      `--v`, `--vv`, `--vvv`, `--vvvv` (any count of v's, as whole tokens)
      `--verbos`, `--verbose<typo>` (typo'd long form)

    Does NOT match:
      `--version` (handled by `_is_version_misplacement`)
      `--view`, `--variable`, etc. (legitimate words starting with v)
    """
    msg = str(getattr(exc, "message", "") or "")
    if "No such option" not in msg:
        return False
    # `--version` already handled upstream; if we somehow get here for it,
    # don't claim it's a verbosity-confusion shape.
    if "--version" in msg:
        return False
    if _VERBOSITY_DASH_CONFUSION_RE.search(msg):
        return True
    return "--verbos" in msg


def _is_usage_error(exc: BaseException) -> bool:
    """True for a Click/Typer usage error, real or vendored.

    Regardless of whether it's the real `click` package's exception or
    Typer's internally vendored fork (`typer._click.exceptions.*` as of
    Typer 0.27, issue #186).

    Both name their base class `UsageError` but are not the same class
    object, so `isinstance(exc, click.exceptions.UsageError)` silently
    stops matching across that boundary. Matching by name in the MRO
    survives either fork — and any future one, without another
    import-path chase (name-matching was preferred over importing
    `typer._click.exceptions` directly for exactly this reason: it
    doesn't need to know Typer's internal module layout, only that
    *some* class in the hierarchy is spelled `UsageError`).
    """
    return any(cls.__name__ == "UsageError" for cls in type(exc).__mro__)


def main() -> None:
    """Entry point that maps Click usage errors to project exit code 4.

    Typer/Click default to exit code 2 for invalid options (e.g. an
    unknown `--format` value or a malformed `--retries` integer). The
    project's documented exit-code surface uses 2 for *target scan
    failure*, so usage errors must surface as 4. This wrapper detects
    usage errors by shape (`_is_usage_error`, issue #186) and re-exits
    with 4.

    Special case: `--version` on a subcommand fires a Click "No such
    option" error because the flag is registered at the root callback
    only (matches git/docker/gh convention). Default Click error
    suggests `--verbose` which is wrong — replace with a hint at the
    root-level form.
    """
    try:
        exit_code = app(standalone_mode=False)
    except click.exceptions.Exit as exc:
        sys.exit(exc.exit_code)
    except SystemExit:
        raise
    except Exception as exc:  # noqa: BLE001 -- dispatch by shape (_is_usage_error), not isinstance
        if _is_usage_error(exc):
            if _is_version_misplacement(exc):
                sys.stderr.write(
                    "qureddy: --version is a top-level flag. "
                    "Try `qureddy --version` (without a subcommand).\n"
                )
                sys.exit(EXIT_USAGE)
            if _is_verbosity_dash_confusion(exc):
                sys.stderr.write(
                    "qureddy: did you mean -v / -vv / -vvv (single-dash)? "
                    "Verbosity uses single-dash short flags per POSIX; "
                    "--vvv is not a long flag. Use --verbose for the long form.\n"
                )
                sys.exit(EXIT_USAGE)
            # ClickException.show() exists on both the real click hierarchy
            # and Typer's vendored fork (issue #186) — mypy can't verify
            # this across the two unrelated class hierarchies, same
            # reasoning as _is_usage_error's name-based MRO check above.
            exc.show(file=sys.stderr)  # type: ignore[attr-defined]
            sys.exit(EXIT_USAGE)
        # Internal qureddy bugs route to EX_SOFTWARE (70), not exit 2.
        # CI scripts branching on `$? == 2` must be able to trust that
        # 2 means "target scan failed", not "qureddy itself crashed".
        sys.stderr.write(f"qureddy: unexpected error: {exc}\n")
        sys.exit(EXIT_INTERNAL_ERROR)
    sys.exit(EXIT_OK if exit_code is None else exit_code)
