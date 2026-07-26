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

import os
import re
import sys
from typing import Annotated

import click
import structlog
import typer

from qureddy._branding import (
    DESCRIPTION,
    PROJECT_NAME,
    PROJECT_URL,
    PROJECT_VERSION,
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
from qureddy.core.errors import (
    SSHProbeError as _SSHProbeError,
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
from qureddy.core.targets import parse_ssh_target, parse_target
from qureddy.output.cbom import render_cbom
from qureddy.output.console import render_rich
from qureddy.output.json import render_json
from qureddy.scanners.ssh.scanner import scan_ssh as _scan_ssh
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


# Issue #266: single source of truth for "-h works everywhere, and no help
# level's multi-line epilog gets mangled by Click's default text-wrapping"
# (see the `\b` note on _SCAN_TLS_EPILOG below) — defined once, reused by
# `app`, `scan_app`, and the `scan tls` command instead of three
# separately-typed dicts that could silently drift (e.g. one level gaining
# -h, another not).
_NO_WRAP_CONTEXT_SETTINGS = {
    "help_option_names": ["-h", "--help"],
    "max_content_width": 10000,
}

# Issue #266: `qureddy scan tls` output already colors its verdict panel,
# tables, and findings (see output/_styles.py's color discipline) — plain
# black-and-white --help text next to that was an inconsistent product.
# `rich_markup_mode="rich"` was tried and rejected (issue #71: it collapses
# the `\b`-marked multi-line EXAMPLES/EXIT CODES/ENVIRONMENT blocks into one
# wrapped line on current Typer). Instead this colors the plain epilog
# strings below by *line shape* — one pattern-matching pass instead of
# hand-placing click.style() calls three separate times (root/scan/scan-tls)
# and re-doing it on every future example line added. The palette reuses
# output/_styles.py's semantics rather than inventing a second one: green
# for "do this / success", yellow for "expected, non-fatal", red for
# "broken", dim for secondary text — plus cyan for structural labels
# (matches the tables' `header_style="bold cyan"`) and magenta as the one
# net-new color, for env var names, which have no equivalent in scan output.
_HELP_SECTION_RE = re.compile(r"^[A-Z][A-Z /]*:$")
_HELP_COMMENT_RE = re.compile(r"^(\s*)(#.*)$")
_HELP_COMMAND_RE = re.compile(r"^(\s*)(qureddy\b.*)$")
_HELP_EXIT_CODE_RE = re.compile(r"^(\d+)(\s+)(.*)$")
_HELP_ENV_VAR_RE = re.compile(r"^([A-Z][A-Z0-9_]*)(\s{2,})(.*)$")


def _exit_code_color(code: str) -> str:
    """Color an exit code by severity, matching SEVERITY_STYLE's discipline.

    0 (success) is green. 70 (internal error, BSD EX_SOFTWARE) is red —
    it means qureddy itself broke. Everything between (2/3/4: target
    failed, local dependency, usage error) is yellow: expected, routine
    outcomes a script branches on, not a crash.
    """
    if code == str(EXIT_OK):
        return "green"
    if code == str(EXIT_INTERNAL_ERROR):
        return "red"
    return "yellow"


def _colorize_help_text(text: str) -> str:
    r"""Color a plain epilog string by line shape. Honors NO_COLOR.

    Section headers ("QUICK START:", "EXIT CODES:") go bold cyan
    (matches the tables' `header_style="bold cyan"`), comment lines
    ("# ...") go dim, command lines ("qureddy ...") go bold green
    (the "type this" action, same green as a PQ-positive finding),
    leading exit-code numbers are colored by severity (see
    `_exit_code_color`), and environment variable names go bold
    magenta. Lines that are exactly the literal `\\b` Click marker
    (see the note on `_SCAN_TLS_EPILOG` below) pass through untouched:
    that byte must reach Click's HelpFormatter unmodified or the block
    loses its no-wrap treatment (issue #71).
    """
    if "NO_COLOR" in os.environ:
        return text
    styled_lines = []
    for line in text.split("\n"):
        if line == "\b":
            styled_lines.append(line)
            continue
        comment_match = _HELP_COMMENT_RE.match(line)
        command_match = _HELP_COMMAND_RE.match(line)
        exit_code_match = _HELP_EXIT_CODE_RE.match(line)
        env_var_match = _HELP_ENV_VAR_RE.match(line)
        if _HELP_SECTION_RE.match(line):
            styled_lines.append(click.style(line, fg="cyan", bold=True))
        elif comment_match:
            styled_lines.append(
                comment_match.group(1) + click.style(comment_match.group(2), dim=True)
            )
        elif command_match:
            styled_lines.append(
                command_match.group(1) + click.style(command_match.group(2), fg="green", bold=True)
            )
        elif exit_code_match:
            code, gap, rest = exit_code_match.groups()
            styled_lines.append(
                click.style(code, fg=_exit_code_color(code), bold=True) + gap + rest
            )
        elif env_var_match:
            name, gap, rest = env_var_match.groups()
            styled_lines.append(click.style(name, fg="magenta", bold=True) + gap + rest)
        else:
            styled_lines.append(line)
    return "\n".join(styled_lines)


# Issue #266: root `qureddy --help` previously said only "Commands: scan
# Run scans." — zero actionable guidance for a first-time user, who'd have
# to already know to drill into `scan` then `tls` then `--help` again to
# find the real EXAMPLES section. This gives root --help a taste of the
# real range (not just one example) and a direct pointer to the full
# reference. JSON and CBOM are repeated here even though they're also in
# `scan tls --help`'s EXAMPLES — deliberately not DRY: CBOM in particular
# is the product's own flagship differentiator ("Find what's
# quantum-vulnerable. Generate a CBOM. Move on." — CLAUDE.md's tagline),
# and a user who never drills past root --help shouldn't miss it.
_ROOT_EPILOG = _colorize_help_text(f"""\
QUICK START:

\b
# Human-readable scan.
qureddy scan tls google.com

\b
# Scan an SSH endpoint.
qureddy scan ssh github.com

\b
# Machine-readable, for CI pipelines (real PQ hybrid endpoint).
qureddy scan tls pq.cloudflareresearch.com --format json

\b
# Generate a CBOM (same real PQ hybrid endpoint).
qureddy scan tls pq.cloudflareresearch.com --format cbom

\b
# IP target (SNI override required).
qureddy scan tls 1.1.1.1:443 --sni one.one.one.one

\b
# Tolerate transient network blips (3 retries).
qureddy scan tls flaky.net --retry-on tls_handshake_failed --retries 3

\b
# Verbose diagnostics (-v/-vv/-vvv).
qureddy scan tls example.com -v

MORE HELP:

\b
qureddy scan tls --help    # full options, examples, exit codes
qureddy --version          # show version

Project: {PROJECT_URL}
""")

# Issue #266: `qureddy scan --help` previously said only "Run scans." — the
# weakest link in the help hierarchy, not even naming `tls` as the thing to
# run. `scan` is a group (not `tls` directly) because more scan types are
# planned per the roadmap (ssh, config, source-code) — this epilog says so,
# rather than leaving a user to wonder why there's an extra level at all.
_SCAN_EPILOG = _colorize_help_text("""\
qureddy scans TLS and SSH endpoints; more scan types (config, source-code)
are on the roadmap, which is why "scan" is a group rather than a single
command.

\b
qureddy scan tls <target>            # TLS endpoint (OpenSSL handshakes)
qureddy scan ssh <target>            # SSH endpoint (reads the KEXINIT offer)
qureddy scan tls --help              # full options, examples, exit codes
qureddy scan ssh --help              # SSH options and examples
""")

app = typer.Typer(
    name="qureddy",
    help=(f"{PROJECT_NAME} {PROJECT_VERSION} -- {DESCRIPTION}."),
    epilog=_ROOT_EPILOG,
    no_args_is_help=True,
    add_completion=False,
    # rich_markup_mode=None disables Typer's Rich-based formatter for help
    # output; falls back to Click's classic formatter which respects literal
    # newlines + the `\b` form-feed convention. Required for the multi-line
    # epilog blocks (EXAMPLES, EXIT CODES, ENVIRONMENT) to render one item
    # per line. See issue #71 for the full investigation.
    rich_markup_mode=None,
    context_settings=_NO_WRAP_CONTEXT_SETTINGS,
)
scan_app = typer.Typer(
    # Was "Run scans." — tautological for a scanning tool's one command
    # group, and the only line a user who doesn't read the epilog ever
    # sees on `qureddy --help`'s "Commands:" table. Now self-sufficient
    # without requiring the epilog below to explain what's being scanned.
    help="Scan a TLS or SSH endpoint for post-quantum readiness.",
    epilog=_SCAN_EPILOG,
    no_args_is_help=True,
    rich_markup_mode=None,
    context_settings=_NO_WRAP_CONTEXT_SETTINGS,
)
app.add_typer(scan_app, name="scan")


@app.callback(
    help=(f"{PROJECT_NAME} {PROJECT_VERSION} -- {DESCRIPTION}."),
)
def _root(
    version: VersionOpt = None,
) -> None:
    """Root callback exists so `--version` can be wired at the app level.

    (Visible from `qureddy --version` without a subcommand.) The body
    is empty because `_version_callback` short-circuits via
    `is_eager=True`. Explicit `help=` above (not the docstring) is what
    Typer shows for `--help`/`help`, since an f-string can't populate
    `__doc__` — the docstring here is dev-facing only.
    """


@app.command("help", context_settings=_NO_WRAP_CONTEXT_SETTINGS)
def show_help(ctx: typer.Context) -> None:
    """Show this message and exit.

    Issue #266 item 3: `qureddy help` (bare word, no dashes) is common
    muscle-memory (docker help, npm help) but previously errored with
    "No such command 'help'" — confirmed live by a user hitting this
    directly. `ctx.parent` is the root group's context since this
    command is registered on `app`; printing its help text and exiting
    0 makes `qureddy help` behave like `qureddy --help`, not an error.
    """
    if ctx.parent is not None:
        click.echo(ctx.parent.get_help())
    raise typer.Exit(code=EXIT_OK)


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
# Scan an IP target (SNI override required).
qureddy scan tls 1.1.1.1:443 --sni one.one.one.one

\b
# Tolerate transient network hiccups (3 retries, 2s apart).
qureddy scan tls flaky.example.com --retry-on tls_handshake_failed --retries 3 --retry-delay 2

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
""")


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
        _render(result, output_format, verbose, timeout)
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
        # Issue #274: machine formats default to quiet logging, which
        # suppressed the warning above — the only user-facing report of
        # this failure — leaving exit 3 with an empty stderr. The
        # actionable message (the exception text carries the fix-it
        # instructions) must reach stderr directly, exempt from the
        # quiet default, matching the exit-2/exit-4 paths.
        typer.echo(f"qureddy: {exc}", err=True)
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


def _render(
    result: ScanResult, output_format: OutputFormat, verbose: int, timeout_seconds: int
) -> None:
    """Dispatch to the JSON, CBOM, or Rich renderer."""
    if output_format is OutputFormat.JSON:
        render_json(result, sys.stdout)
    elif output_format is OutputFormat.CBOM:
        render_cbom(result, sys.stdout, certificate=_fetch_cert_for_cbom(result, timeout_seconds))
    else:
        render_rich(result, sys.stdout, verbosity=verbose)


def _fetch_cert_for_cbom(result: ScanResult, timeout_seconds: int) -> CertificateInfo | None:
    """Best-effort certificate fetch for CBOM output.

    Issue #225: this redundant fetch (see docstring below) previously
    ignored the user's --timeout entirely, hardcoding cert_probe's
    30-second default regardless of what was requested. Now threads the
    same timeout_seconds the scan itself used. Eliminating the redundant
    fetch entirely (reusing the scan's own already-fetched certificate)
    is a separate, larger design change — tracked in #252, not done here.

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
    dependency = result.dependencies[0]
    if dependency.failure_category is not None or not dependency.path:
        # Issue #274: a rejected dependency still has a `path`, so a
        # path-only guard let the CBOM cert fetch shell out to the very
        # binary the capability check refused (real case: LibreSSL —
        # which also serializes DNs differently, silently forking the
        # CBOM's certificate data shape). A binary that failed the
        # capability check must not be used for anything.
        return None
    openssl_path = dependency.path
    try:
        pem = fetch_certificate_pem(
            openssl_path,
            result.target.host,
            result.target.port,
            result.target.sni,
            timeout_seconds=timeout_seconds,
        )
        return (
            parse_certificate(openssl_path, pem, timeout_seconds=timeout_seconds) if pem else None
        )
    except (LocalOpenSSLMissing, ValueError):
        return None


_DASH_V_TOKEN_RE = re.compile(r"(?<![\w-])-V(?![\w-])")


def _is_version_misplacement(exc: Exception) -> bool:
    """Detect the `--version` / `-V` on a subcommand UsageError shape.

    Click's default error reads `No such option: --version Did you mean
    --verbose?` which is unhelpful — `--version` lives at the root and
    works fine; the user just put it in the wrong position. Catch this
    specific shape so we can replace with an actionable hint.

    Issue #227: the real Click message for the short form is exactly
    `"No such option: -V"` — no quotes, no trailing space after `-V`
    (confirmed live via CliRunner). The old `"'-V'" in msg or " -V " in
    msg` checks both required characters that aren't actually there, so
    the short form fell through to Click's generic error while the
    docstring claimed both forms were handled. Match `-V` as a token
    (not preceded/followed by a word char or hyphen) instead of
    depending on specific surrounding punctuation.
    """
    msg = str(getattr(exc, "message", "") or "")
    if "No such option" not in msg:
        return False
    return "--version" in msg or bool(_DASH_V_TOKEN_RE.search(msg))


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


# ---- SSH scanner command (issue #278) ----
_SCAN_SSH_EPILOG = _colorize_help_text(f"""\
EXAMPLES:

\b
# Check an SSH/SFTP endpoint for post-quantum readiness.
qureddy scan ssh github.com

\b
# A non-standard SFTP port.
qureddy scan ssh sftp.vendor.example.com:2222

\b
# Machine-readable JSON.
qureddy scan ssh github.com --format json

VERDICTS:

\b
transitional_hybrid   PQ hybrid KEX offered (mlkem768x25519 / sntrup761x25519)
quantum_vulnerable    classical KEX only -- harvest-now-decrypt-later exposure
classically_weak      a weak/deprecated host key (e.g. ssh-dss) is offered

WHAT IT CHECKS (two axes):

\b
Key exchange   does the server offer a post-quantum hybrid KEX group?
Host key       are the host-key signature algorithms classical or weak?

\b
No OpenSSL needed -- SSH posture is read from the cleartext KEXINIT, so the
LibreSSL/OpenSSL prerequisite that applies to `scan tls` does NOT apply here.
SFTP endpoints are usually IP-allowlisted: run this from inside your perimeter.

EXIT CODES:

\b
0   scan succeeded
2   target scan failed (unreachable, port closed, malformed response)
4   usage / configuration error

Project: {PROJECT_URL}
""")


def _clean_ssh_error(msg: str) -> str:
    """Reduce a raw SSH probe error to a clean, operator-facing message.

    Strips Python's `[Errno N]` prefix and rewrites the common OS-level
    failure shapes (DNS, refused, timeout) into actionable language, so the
    CLI never surfaces a raw `[Errno 8] nodename nor servname provided`.
    """
    cleaned = re.sub(r"\[Errno \d+\]\s*", "", msg)
    lowered = cleaned.lower()
    head = cleaned.split(" failed:")[0]
    if "nodename nor servname" in lowered or "name or service not known" in lowered:
        return f"{head} failed: host could not be resolved (DNS lookup failed)"
    if "connection refused" in lowered:
        return f"{head} failed: connection refused"
    if "timed out" in lowered:
        return f"{cleaned} — is that host:port actually an SSH endpoint?"
    return cleaned


@scan_app.command("ssh", epilog=_SCAN_SSH_EPILOG, context_settings=_NO_WRAP_CONTEXT_SETTINGS)
def scan_ssh_cmd(
    target: TargetArg,
    fmt: FormatOpt = OutputFormat.RICH,
    timeout: TimeoutOpt = 8,
    verbose: VerboseOpt = 0,
    json_logs: JsonLogsOpt = False,
    quiet: QuietOpt = False,
) -> None:
    """Scan an SSH endpoint for post-quantum readiness."""
    # Mirror scan tls: machine formats default to quiet so stdout stays a
    # clean document, but an explicit -v/-vv/-vvv still wins. Keeps the
    # verbosity/logging surface consistent across subcommands.
    machine_format = fmt is not OutputFormat.RICH
    effective_quiet = quiet or (machine_format and verbose == 0)
    configure_logging(verbosity=verbose, json_logs=json_logs, quiet=effective_quiet)
    try:
        scan_target = parse_ssh_target(target)
    except TargetParseError as exc:
        typer.echo(f"qureddy: invalid target: {exc}", err=True)
        raise typer.Exit(code=EXIT_USAGE) from None
    try:
        result = _scan_ssh(scan_target, timeout_seconds=timeout)
    except _SSHProbeError as exc:
        # Present a clean, classified message on stderr — never the raw
        # OSError/errno. Exit 2 (target scan failed), same contract as tls.
        typer.echo(f"qureddy: ssh scan failed: {_clean_ssh_error(str(exc))}", err=True)
        raise typer.Exit(code=EXIT_TARGET_FAILED) from None
    if fmt is OutputFormat.JSON:
        render_json(result, sys.stdout)
    elif fmt is OutputFormat.CBOM:
        render_cbom(result, sys.stdout, certificate=None)
    else:
        render_rich(result, sys.stdout, verbosity=verbose)
