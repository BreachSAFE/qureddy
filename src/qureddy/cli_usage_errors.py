# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Usage-error shape detection for cli.py's exit-code-4 remap.

Split out of cli.py per the file-size gate (coding-rules.md §2.2) —
cohesive, separable concern: detecting specific Click UsageError shapes
so main() can substitute an actionable hint instead of Click's default
message.
"""

from __future__ import annotations

import re

import click


def is_version_misplacement(exc: click.exceptions.UsageError) -> bool:
    """Detect the `--version` / `-V` on a subcommand UsageError shape.

    Click's default error reads `No such option: --version Did you mean
    --verbose?` which is unhelpful — `--version` lives at the root and
    works fine; the user just put it in the wrong position. Catch this
    specific shape so we can replace with an actionable hint.
    """
    msg = str(exc.message) if exc.message else ""
    if "No such option" not in msg:
        return False
    return "--version" in msg or "'-V'" in msg or " -V " in msg


# `--v` / `--vv` / `--vvv` etc — double-dash followed by 1+ `v`s as a
# whole token. Excludes `--version` (longer match, has trailing chars).
_VERBOSITY_DASH_CONFUSION_RE = re.compile(r"--v+(?:\s|$|'|\")")


def is_verbosity_dash_confusion(exc: click.exceptions.UsageError) -> bool:
    """Detect `--v`, `--vv`, `--vvv`, `--vvvv` and `--verbos*` typos (#74).

    Click's default error for these reads `No such option: --vvv` with
    no hint that the correct invocation is `-vvv` (single-dash, stackable
    per POSIX). This detector matches the dash-confusion error shape so
    the wrapper can substitute an actionable hint.

    Matches:
      `--v`, `--vv`, `--vvv`, `--vvvv` (any count of v's, as whole tokens)
      `--verbos`, `--verbose<typo>` (typo'd long form)

    Does NOT match:
      `--version` (handled by `is_version_misplacement`)
      `--view`, `--variable`, etc. (legitimate words starting with v)
    """
    msg = str(exc.message) if exc.message else ""
    if "No such option" not in msg:
        return False
    # `--version` already handled upstream; if we somehow get here for it,
    # don't claim it's a verbosity-confusion shape.
    if "--version" in msg:
        return False
    if _VERBOSITY_DASH_CONFUSION_RE.search(msg):
        return True
    return "--verbos" in msg
