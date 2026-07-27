# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""The `-vvv` Commands panel: the exact OpenSSL invocations the scanner issued."""

from __future__ import annotations

from typing import TYPE_CHECKING

from rich import box
from rich.panel import Panel
from rich.text import Text

if TYPE_CHECKING:
    from qureddy.core.models import ScanResult


def _commands_panel(result: ScanResult) -> Panel | None:
    """At `-vvv` only: dump the exact OpenSSL invocations.

    Returns None when no probe was run (e.g., capability-failure path
    that exited before any subprocess), so the panel doesn't render
    a misleading empty box.
    """
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
        cmd_line = Text("$ ", style="dim")
        cmd_line.append(probe.command.executable, style="bold")
        for arg in probe.command.args:
            cmd_line.append(" ")
            cmd_line.append(arg)
        lines.append(cmd_line)
        meta = Text("    ", style="dim")
        meta.append(
            f"return_code={probe.return_code} "
            f"duration_ms={probe.duration_ms} "
            f"attempt={probe.attempt_number}",
        )
        if probe.failure_category is not None:
            meta.append(f" failure={probe.failure_category.value}", style="red")
        lines.append(meta)
    if not lines:
        return None

    body = Text()
    for i, line in enumerate(lines):
        if i:
            body.append("\n")
        body.append_text(line)

    return Panel(
        body,
        title="Commands run (-vvv)",
        title_align="left",
        border_style="dim",
        box=box.SIMPLE,
        padding=(0, 1),
    )
