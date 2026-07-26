# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Shared --help machinery: no-wrap context settings + epilog colorization.

The epilog *texts* live next to the commands they document (`main.py`,
`scan.py`, `ssh.py`); this module owns the machinery they share. ADR 0005's
original worked example placed the epilog blocks here too, but the #266
help rewrite grew them past what Rule E's 200-LOC per-file target allows
in one module.
"""

from __future__ import annotations

import os
import re

import click

from qureddy.cli._errors import EXIT_INTERNAL_ERROR, EXIT_OK

# Issue #266: single source of truth for "-h works everywhere, and no help
# level's multi-line epilog gets mangled by Click's default text-wrapping"
# (see the `\b` note on _SCAN_TLS_EPILOG in scan.py) — defined once, reused
# by `app`, `scan_app`, and the `scan tls` command instead of three
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
# strings by *line shape* — one pattern-matching pass instead of
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
    (see the note on `_SCAN_TLS_EPILOG` in scan.py) pass through
    untouched: that byte must reach Click's HelpFormatter unmodified or
    the block loses its no-wrap treatment (issue #71).
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
