# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Top-level render orchestration: header + section order for `qureddy scan`."""

from __future__ import annotations

import os
import sys
from typing import IO, TYPE_CHECKING

from rich.console import Console
from rich.text import Text

from qureddy._branding import HEADER
from qureddy.output._styles import BRAND_CYAN
from qureddy.output.console._commands import _commands_panel
from qureddy.output.console._errors import _errors_table
from qureddy.output.console._evidence import _SEVERITY_ORDER
from qureddy.output.console._tables import _findings_table, _run_details_table, _summary_table
from qureddy.output.console._verdict import _verdict_panel

if TYPE_CHECKING:
    from qureddy.core.models import Finding, ScanResult, Severity

# `-vvv` (verbosity == 3) is the threshold for surfacing the exact
# OpenSSL commands run. The DEBUG log channel already carries the same
# information on stderr starting at `-vv` (verbosity == 2); the console
# panel is the user-visible mirror for stdout-only consumers.
_VERBOSITY_SHOW_COMMANDS = 3


def render_rich(
    result: ScanResult,
    stream: IO[str] | None = None,
    *,
    verbosity: int = 0,
    min_severity: Severity | None = None,
) -> None:
    """Render a ScanResult to the given stream (default: current sys.stdout).

    Issue #238: `stream: IO[str] = sys.stdout` as a default is resolved
    once at function-definition time, not per call — same root cause as
    #237/#239. Resolve at call time instead.

    Layout:
      1. The QuReddy header line.
      2. A bordered verdict panel (READY / NOT READY / FAIL / UNKNOWN +
         recommendation) so the at-a-glance signal is the dominant
         visual element, not a row in the middle of a table.
      3. The summary table (raw enum values + per-probe status).
      4. The findings table (rule-by-rule).
      5. The dependencies table.
      6. (`verbosity >= 3` only) A "Commands run" panel listing the
         exact OpenSSL invocations the scanner issued, for traceability.
         Probe args are also logged at DEBUG level on stderr at -vv/-vvv,
         and are always present in JSON output regardless of verbosity.

    ``min_severity`` (issue #133) trims the findings *table* to findings at or
    above the given severity — a human-output convenience for scanning a noisy
    report. It is display-only: the verdict panel and the summary table's total
    `findings` count still reflect every finding, and the machine formats
    (json/cbom) are never filtered, so the issue #30 machine-document contract
    is untouched.

    Honors NO_COLOR per https://no-color.org.
    """
    target_stream = stream if stream is not None else sys.stdout
    console = _make_console(target_stream)
    console.print(_header_text())
    console.print()

    console.print(_verdict_panel(result))
    console.print()
    console.print(_summary_table(result))
    shown_findings = _filter_by_min_severity(result.findings, min_severity)
    if shown_findings:
        console.print()
        console.print(_findings_table(result, findings=shown_findings))
    console.print()
    console.print(_run_details_table(result))
    errors_table = _errors_table(result)
    if errors_table is not None:
        console.print()
        console.print(errors_table)
    if verbosity >= _VERBOSITY_SHOW_COMMANDS:
        commands_panel = _commands_panel(result)
        if commands_panel is not None:
            console.print()
            console.print(commands_panel)


def _filter_by_min_severity(
    findings: tuple[Finding, ...],
    min_severity: Severity | None,
) -> tuple[Finding, ...]:
    """Keep findings at or above ``min_severity`` (rich-table display only).

    ``None`` means no filter. Severity ranks come from the shared
    ``_SEVERITY_ORDER`` (critical lowest .. info highest), so "at or above medium"
    keeps critical/high/medium and drops low/info.
    """
    if min_severity is None:
        return findings
    threshold = _SEVERITY_ORDER[min_severity]
    return tuple(f for f in findings if _SEVERITY_ORDER[f.severity] <= threshold)


def _header_text() -> Text:
    """Color the top-of-output header in the brand palette.

    HEADER is `QuReddy <ver> by BreachSAFE · <url>`. The `QuReddy`
    wordmark and the site render in the brand cyan; the rest of the name
    line is green. Split on the middot so the site stays a distinct element.
    """
    name_part, sep, url_part = HEADER.partition(" · ")
    header = Text()
    # "QuReddy" in the brand cyan, the rest of the name line in green.
    word, gap, rest = name_part.partition(" ")
    header.append(word, style=f"bold {BRAND_CYAN}")
    header.append(gap + rest, style="green")
    if sep:
        header.append(sep)  # keep the " · " separator so HEADER renders verbatim
        header.append(url_part, style=BRAND_CYAN)
    return header


def _make_console(stream: IO[str]) -> Console:
    """Construct a Rich Console honoring NO_COLOR.

    Per https://no-color.org any value of the NO_COLOR env var (including
    the empty string) disables color. Otherwise Rich auto-detects whether
    the stream is a TTY and emits ANSI color when it is.

    `highlight=False` keeps Rich from auto-styling field values like IP
    addresses or numbers; we want only the styles we apply ourselves.
    """
    no_color = "NO_COLOR" in os.environ
    # Rich otherwise enables a Windows-legacy layout which changes table
    # widths by one cell.  Pin both inputs so redirected output has one
    # cross-platform textual contract.
    return Console(
        file=stream,
        no_color=no_color,
        highlight=False,
        width=80,
        legacy_windows=False,
    )
