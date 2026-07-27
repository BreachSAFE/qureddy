# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Typer app assembly and the installed `qureddy` entry point.

Glue only — no command logic. The `scan tls` / `scan ssh` command bodies
live in `scan.py` / `ssh.py` and register themselves onto `scan_app` when
the package `__init__` imports them.
"""

from __future__ import annotations

import sys

import click
import typer

from qureddy._branding import DESCRIPTION, PROJECT_NAME, PROJECT_URL, PROJECT_VERSION
from qureddy.cli._errors import (
    EXIT_INTERNAL_ERROR,
    EXIT_OK,
    EXIT_USAGE,
    _is_usage_error,
    _is_verbosity_dash_confusion,
    _is_version_misplacement,
)
from qureddy.cli._help import _NO_WRAP_CONTEXT_SETTINGS, _colorize_help_text
from qureddy.cli._options import VersionOpt

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

# Issue #266: `qureddy scan --help` names the available scanner commands and
# explains why the CLI uses a scan command group.
_SCAN_EPILOG = _colorize_help_text("""\
qureddy scans TLS and SSH endpoints. "scan" is a command group so each
scanner has its own options, output formats, and exit-code behavior.

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


def _configure_utf8_stdio() -> None:
    """Make the installed CLI's byte-stream contract UTF-8 on every OS.

    Windows otherwise inherits a locale-dependent encoding such as cp1252,
    which cannot represent all scan diagnostics and can turn a typed target
    failure into an internal encoding error.  In-process test and embedding
    streams may not expose ``reconfigure``; those already consume text and
    need no byte-level configuration.
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            reconfigure(encoding="utf-8", errors="backslashreplace")


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
    _configure_utf8_stdio()
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
            # reasoning as _is_usage_error's name-based MRO check.
            exc.show(file=sys.stderr)  # type: ignore[attr-defined]
            sys.exit(EXIT_USAGE)
        # Internal qureddy bugs route to EX_SOFTWARE (70), not exit 2.
        # CI scripts branching on `$? == 2` must be able to trust that
        # 2 means "target scan failed", not "qureddy itself crashed".
        sys.stderr.write(f"qureddy: unexpected error: {exc}\n")
        sys.exit(EXIT_INTERNAL_ERROR)
    sys.exit(EXIT_OK if exit_code is None else exit_code)
