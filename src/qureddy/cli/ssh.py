# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""The `qureddy scan ssh` command body (issue #278)."""

from __future__ import annotations

import os
import re
import sys

import typer

from qureddy._branding import PROJECT_URL
from qureddy.cli._errors import (
    EXIT_OK,
    EXIT_TARGET_FAILED,
    EXIT_USAGE,
    _echo_operator_diagnostic,
    _fail,
)
from qureddy.cli._help import _NO_WRAP_CONTEXT_SETTINGS, _colorize_help_text
from qureddy.cli._options import (
    FormatOpt,
    JsonLogsOpt,
    QuietOpt,
    ReproducibleOpt,
    SshTargetArg,
    TimeoutOpt,
    VerboseOpt,
)
from qureddy.cli.main import scan_app
from qureddy.core.errors import SSHProbeError, TargetParseError
from qureddy.core.logging import start_run_logging
from qureddy.core.models import OutputFormat
from qureddy.core.targets import parse_ssh_target
from qureddy.output.cbom import render_cbom
from qureddy.output.console import render_rich
from qureddy.output.json import render_json
from qureddy.scanners.ssh.scanner import build_ssh_failure_result, scan_ssh

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


def _block_internal_targets() -> bool:
    """Read the opt-in SSRF guard from the environment (Rule 5.6: env at the boundary).

    Off by default; an embedder accepting an untrusted target sets
    QUREDDY_BLOCK_INTERNAL_TARGETS=1 to reject internal/metadata endpoints (#134).
    """
    return os.environ.get("QUREDDY_BLOCK_INTERNAL_TARGETS", "").strip().lower() not in (
        "",
        "0",
        "false",
        "no",
    )


@scan_app.command("ssh", epilog=_SCAN_SSH_EPILOG, context_settings=_NO_WRAP_CONTEXT_SETTINGS)
def scan_ssh_cmd(
    target: SshTargetArg,
    fmt: FormatOpt = OutputFormat.RICH,
    timeout: TimeoutOpt = 8,
    verbose: VerboseOpt = 0,
    json_logs: JsonLogsOpt = False,
    quiet: QuietOpt = False,
    reproducible: ReproducibleOpt = False,
) -> None:
    """Scan an SSH endpoint for post-quantum readiness."""
    # Mirror scan tls: machine formats default to quiet so stdout stays a
    # clean document, but an explicit -v/-vv/-vvv still wins. Keeps the
    # verbosity/logging surface consistent across subcommands.
    machine_format = fmt is not OutputFormat.RICH
    effective_quiet = quiet or (machine_format and verbose == 0)
    # log=None: `scan ssh` has no --log yet; shares the helper so log-capture wiring is not duplicated.
    start_run_logging(verbosity=verbose, json_logs=json_logs, quiet=effective_quiet, log=None)
    try:
        scan_target = parse_ssh_target(target, block_internal=_block_internal_targets())
    except TargetParseError as exc:
        _fail(f"invalid target: {exc}", EXIT_USAGE)
    exit_code = EXIT_OK
    try:
        result = scan_ssh(scan_target, timeout_seconds=timeout)
    except SSHProbeError as exc:
        # Present a clean, classified message on stderr — never the raw
        # OSError/errno. Exit 2 (target scan failed), same contract as tls.
        cleaned = _clean_ssh_error(str(exc))
        _echo_operator_diagnostic(f"ssh scan failed: {cleaned}", machine_format=machine_format)
        if not machine_format:
            raise typer.Exit(code=EXIT_TARGET_FAILED) from None
        # Machine formats emit exactly one parseable document even on
        # probe failure (issue #30): the failure travels in the document
        # (summary.failure_category) plus the exit code, matching the
        # `scan tls` failure paths instead of leaving stdout empty.
        result = build_ssh_failure_result(scan_target, exc, cleaned_error=cleaned)
        exit_code = EXIT_TARGET_FAILED
    if fmt is OutputFormat.JSON:
        render_json(result, sys.stdout)
    elif fmt is OutputFormat.CBOM:
        render_cbom(result, sys.stdout, reproducible=reproducible)
    else:
        render_rich(result, sys.stdout, verbosity=verbose)
    if exit_code != EXIT_OK:
        raise typer.Exit(code=exit_code)
