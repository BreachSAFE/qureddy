# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""The `-vvv` Commands panel for exact local probe invocations."""

from __future__ import annotations

from typing import TYPE_CHECKING

from rich import box
from rich.panel import Panel
from rich.text import Text

if TYPE_CHECKING:
    from qureddy.core.models import ProbeResult, ScanResult


def _command_text(probe: ProbeResult) -> Text:
    """Render one probe's invocation as a `$ executable arg arg ...` line."""
    cmd_line = Text("$ ", style="dim")
    cmd_line.append(probe.command.executable, style="bold")
    for arg in probe.command.args:
        cmd_line.append(" ")
        cmd_line.append(arg)
    return cmd_line


def _meta_text(probe: ProbeResult) -> Text:
    """Render one probe's return-code / duration / attempt metadata line."""
    meta = Text("    ", style="dim")
    meta.append(
        f"return_code={probe.return_code} "
        f"duration_ms={probe.duration_ms} "
        f"attempt={probe.attempt_number}",
    )
    if probe.failure_category is not None:
        meta.append(f" failure={probe.failure_category.value}", style="red")
    return meta


def _command_lines(result: ScanResult) -> list[Text]:
    """Collect the deduplicated command + metadata lines for every probe."""
    lines: list[Text] = []
    seen: set[tuple[str, ...]] = set()
    for ev in result.evidence:
        probe = ev.probe_result
        if probe is None:
            continue
        rendered = (probe.command.executable, *probe.command.args)
        if rendered in seen:
            continue
        seen.add(rendered)
        lines.extend((_command_text(probe), _meta_text(probe)))
    return lines


def _commands_body(lines: list[Text]) -> Text:
    """Join rendered lines into one newline-separated body Text."""
    body = Text()
    for i, line in enumerate(lines):
        if i:
            body.append("\n")
        body.append_text(line)
    return body


def _commands_panel(result: ScanResult) -> Panel | None:
    """At `-vvv` only: dump the exact local probe invocations.

    Returns None when no probe was run (e.g., capability-failure path
    that exited before any subprocess), so the panel doesn't render
    a misleading empty box.
    """
    lines = _command_lines(result)
    if not lines:
        return None

    return Panel(
        _commands_body(lines),
        title="Commands run (-vvv)",
        title_align="left",
        border_style="dim",
        box=box.SIMPLE,
        padding=(0, 1),
    )
