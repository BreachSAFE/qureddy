# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Exit-code surface, stderr diagnostics, and Click usage-error classifiers.

Per skill §"Exit codes" + issue #12:
- 0: scan succeeded
- 2: target scan failed
- 3: local dependency missing or unsupported
- 4: usage / configuration error
- 70: internal qureddy error (BSD sysexits.h EX_SOFTWARE)
"""

from __future__ import annotations

import ctypes
import os
import re
import sys
from typing import NoReturn

import typer

EXIT_OK = 0
EXIT_TARGET_FAILED = 2
EXIT_LOCAL_DEPENDENCY = 3
EXIT_USAGE = 4
EXIT_INTERNAL_ERROR = 70  # BSD sysexits.h EX_SOFTWARE — distinct from EXIT_TARGET_FAILED


def _fail(message: str, code: int) -> NoReturn:
    """Echo `message` to stderr and exit with `code`. Used by error handlers.

    ADR 0005's consolidation of the near-identical try/except/typer.Exit
    ladders: one boundary for future cross-cutting concerns (JSON-mode
    error formatting, structured-log error events).
    """
    typer.echo(f"qureddy: {message}", err=True)
    raise typer.Exit(code=code)


def _stderr_merged_into_stdout() -> bool:
    """True when fd 2 writes into the same non-tty open file as fd 1.

    Detects genuine shell-level `2>&1` (dup2 on the real file descriptor
    table): both streams resolve to the same device/inode and neither is
    an interactive terminal. In-process stream substitutes without a
    real file descriptor (CliRunner, pytest capture objects) report
    False — there is no fd-level merge to corrupt.
    """
    try:
        stdout_fd = sys.stdout.fileno()
        stderr_fd = sys.stderr.fileno()
        # A shared interactive tty is not a machine pipeline: nothing
        # downstream parses stdout, and the operator should see the hint.
        if os.isatty(stderr_fd):
            return False
        if os.name == "nt":
            return _windows_standard_handles_match()
        stdout_stat = os.fstat(stdout_fd)
        stderr_stat = os.fstat(stderr_fd)
    except (AttributeError, OSError, ValueError):
        return False
    return (stdout_stat.st_dev, stdout_stat.st_ino) == (stderr_stat.st_dev, stderr_stat.st_ino)


def _windows_standard_handles_match() -> bool:
    """Compare Win32 stdout/stderr handles without unreliable pipe inodes."""
    kernel32 = vars(ctypes)["windll"].kernel32
    get_std_handle = kernel32.GetStdHandle
    get_std_handle.restype = ctypes.c_void_p
    stdout_handle = int(get_std_handle(-11) or 0)
    stderr_handle = int(get_std_handle(-12) or 0)
    return stdout_handle != 0 and stdout_handle == stderr_handle


def _echo_operator_diagnostic(message: str, *, machine_format: bool) -> None:
    """Echo a failure diagnostic to stderr unless it would corrupt `2>&1`.

    In `--format json`/`cbom` the stdout document plus the exit code carry
    the failure (issue #30's machine-output contract); the stderr echo is
    an operator courtesy (issue #274). Under fd-level `2>&1` that courtesy
    would land inside the machine document, so it is suppressed there —
    and only there. Rich mode always echoes.
    """
    if machine_format and _stderr_merged_into_stdout():
        return
    typer.echo(f"qureddy: {message}", err=True)


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
