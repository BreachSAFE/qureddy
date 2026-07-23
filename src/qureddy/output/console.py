# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Rich console output adapter for `qureddy scan tls`.

This module owns the renderers (verdict panel, summary table, findings
table, dependencies table, commands panel). The pure style helpers and
color tables live in `qureddy.output._styles` to keep this module under
the 400-line hard ceiling per docs/contributors/coding-rules.md Rule 2.2.

Color discipline (full rationale in `_styles.py`):

- PQ-positive signals → green
- Routine quantum_vulnerable findings → yellow (NOT red — every scan
  produces one from the classical control probe; red would teach
  operators to ignore the alarm)
- classically_weak / critical / high → red
- Unknowns → dim

NO_COLOR support follows https://no-color.org. No emoji or icons.
"""

from __future__ import annotations

import os
import sys
from typing import IO, TYPE_CHECKING

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from qureddy._branding import HEADER
from qureddy.core.models import Evidence, Readiness
from qureddy.output._styles import (
    CLASSICALLY_WEAK_WITH_PQC_TEMPLATE,
    RECOMMENDATION_TEXT,
    compose_status,
    style_capability,
    style_group,
    style_path,
    style_readiness,
    style_severity,
    styled_or_dash,
    unknown_headline,
    unknown_recommendation,
    verdict_border_style,
)
from qureddy.scanners.tls._cert_findings import (
    FINDING_TYPE_CLASSICAL_SIGNATURE,
    FINDING_TYPE_PQ_SIGNATURE,
)
from qureddy.scanners.tls._legacy_findings import FINDING_TYPE_LEGACY_PROTOCOL_OFFERED

# Tests import these underscore-prefixed names from the renderer module
# (legacy convention). They're re-exported here so the test surface is
# stable across the file split. The canonical implementations live in
# `qureddy.output._styles`.
_style_group = style_group
_style_readiness = style_readiness
_style_severity = style_severity

if TYPE_CHECKING:
    from qureddy.core.models import ScanResult


_HYBRID_GROUP = "X25519MLKEM768"
_CLASSICAL_GROUP = "X25519"

# `-vvv` (verbosity == 3) is the threshold for surfacing the exact
# OpenSSL commands run. The DEBUG log channel already carries the same
# information on stderr starting at `-vv` (verbosity == 2); the console
# panel is the user-visible mirror for stdout-only consumers.
_VERBOSITY_SHOW_COMMANDS = 3


def render_rich(
    result: ScanResult,
    stream: IO[str] = sys.stdout,
    *,
    verbosity: int = 0,
) -> None:
    """Render a ScanResult to the given stream.

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

    Honors NO_COLOR per https://no-color.org.
    """
    console = _make_console(stream)
    console.print(HEADER, style="bold")
    console.print()

    console.print(_verdict_panel(result))
    console.print()
    console.print(_summary_table(result))
    if result.findings:
        console.print()
        console.print(_findings_table(result))
    console.print()
    console.print(_dependencies_table(result))
    if verbosity >= _VERBOSITY_SHOW_COMMANDS:
        commands_panel = _commands_panel(result)
        if commands_panel is not None:
            console.print()
            console.print(commands_panel)


def _make_console(stream: IO[str]) -> Console:
    """Construct a Rich Console honoring NO_COLOR.

    Per https://no-color.org any value of the NO_COLOR env var (including
    the empty string) disables color. Otherwise Rich auto-detects whether
    the stream is a TTY and emits ANSI color when it is.

    `highlight=False` keeps Rich from auto-styling field values like IP
    addresses or numbers; we want only the styles we apply ourselves.
    """
    no_color = "NO_COLOR" in os.environ
    return Console(file=stream, no_color=no_color, highlight=False)


def _verdict_panel(result: ScanResult) -> Panel:
    """Top-of-output banner: at-a-glance verdict + recommendation.

    The panel border color matches the verdict (green / yellow / red /
    dim) so the result is readable without parsing any text. The
    headline word ("READY", "NOT READY", "FAIL", "UNKNOWN") inside the
    panel is also colored so the same signal survives a screen-reader
    that ignores the border.
    """
    headline, recommendation = _summary_headline_and_recommendation(result)
    body = Text()
    body.append_text(headline)
    body.append("\n")
    body.append_text(recommendation)
    return Panel(
        body,
        title=f"QuReddy scan: {result.summary.target}",
        title_align="left",
        border_style=verdict_border_style(result.summary.readiness),
        box=box.HEAVY,
        padding=(0, 1),
    )


def _summary_table(result: ScanResult) -> Table:
    table = Table(
        title="Scan details",
        title_style="bold",
        show_header=False,
        show_lines=False,
        box=box.SIMPLE,
        pad_edge=False,
    )
    table.add_column("Field", style="bold cyan", no_wrap=True)
    table.add_column("Value")

    summary = result.summary
    scan = result.scan

    hybrid_evidence = _pick_evidence(result, group=_HYBRID_GROUP)
    classical_evidence = _pick_evidence(result, group=_CLASSICAL_GROUP)
    protocol = _first_protocol_version(result.evidence)
    cipher = _first_cipher_suite(result.evidence)

    table.add_row("schema_version", Text(result.schema_version))
    table.add_row("status", Text(scan.status))
    table.add_row("readiness", style_readiness(summary.readiness))
    table.add_row("protocol", styled_or_dash(protocol))
    table.add_row("cipher_suite", styled_or_dash(cipher))
    table.add_row("hybrid probe", _style_probe_status(hybrid_evidence))
    table.add_row("classical probe", _style_probe_status(classical_evidence))
    table.add_row("findings", Text(str(summary.finding_count)))
    table.add_row("attempts", Text(str(scan.total_attempts)))
    if summary.failure_category is not None:
        table.add_row(
            "failure_category",
            Text(summary.failure_category.value, style="red"),
        )
    return table


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


def _summary_headline_and_recommendation(result: ScanResult) -> tuple[Text, Text]:
    """Return (headline, recommendation) for the top of the summary block.

    The headline is a plain-English at-a-glance signal; the recommendation
    tells the user what to do about it. Both rows come before the raw
    enum values so a skim reader sees the verdict first.
    """
    readiness = result.summary.readiness
    failure = result.summary.failure_category
    hybrid_evidence = _pick_evidence(result, group=_HYBRID_GROUP)
    classical_evidence = _pick_evidence(result, group=_CLASSICAL_GROUP)
    hybrid_group = hybrid_evidence.negotiated_group if hybrid_evidence else None
    classical_group = classical_evidence.negotiated_group if classical_evidence else None

    if readiness is Readiness.QUANTUM_SAFE:
        headline = compose_status("READY", " — full PQ negotiated")
    elif readiness is Readiness.TRANSITIONAL_HYBRID:
        headline = compose_status("READY", " — PQ hybrid ", group=hybrid_group)
        headline.append(" negotiated")
    elif readiness is Readiness.QUANTUM_VULNERABLE:
        headline = compose_status("NOT READY", " — classical only (", group=classical_group)
        headline.append(")")
    elif readiness is Readiness.CLASSICALLY_WEAK:
        if hybrid_group is not None:
            headline = compose_status(
                "FAIL", " — weak legacy fallback (PQ hybrid ", group=hybrid_group
            )
            headline.append(" also negotiated)")
        else:
            headline = compose_status("FAIL", " — weak classical primitive")
    elif readiness is Readiness.NOT_APPLICABLE:
        headline = compose_status("UNKNOWN", " — scan not applicable")
    else:
        headline = unknown_headline(failure)

    if readiness is Readiness.TRANSITIONAL_HYBRID:
        recommendation = Text(_cert_axis_recommendation(result))
    elif readiness is Readiness.CLASSICALLY_WEAK and hybrid_group is not None:
        recommendation = Text(_classically_weak_with_pqc_recommendation(result, hybrid_group))
    elif readiness in RECOMMENDATION_TEXT:
        recommendation = Text(RECOMMENDATION_TEXT[readiness])
    else:
        recommendation = Text(unknown_recommendation(failure))
    return headline, recommendation


def _classically_weak_with_pqc_recommendation(result: ScanResult, hybrid_group: str) -> str:
    """Recommendation for a target that supports PQ hybrid AND legacy protocols.

    Confirmed live against google.com — a large-scale service can
    genuinely hold both postures simultaneously for a long time, and
    the old one-sided "PQ readiness is moot" message was factually
    wrong in that case: PQ readiness is NOT moot, it's already working,
    alongside a real legacy exposure. Both facts get said, not one
    hiding the other.
    """
    legacy_protocols = sorted(
        {
            f.protocol_version
            for f in result.findings
            if f.finding_type == FINDING_TYPE_LEGACY_PROTOCOL_OFFERED and f.protocol_version
        }
    )
    protocols = ", ".join(legacy_protocols) or "a legacy protocol"
    return CLASSICALLY_WEAK_WITH_PQC_TEMPLATE.format(hybrid_group=hybrid_group, protocols=protocols)


def _cert_axis_recommendation(result: ScanResult) -> str:
    """Recommendation text for TRANSITIONAL_HYBRID, driven by the actual finding.

    Issue #183: replaces a hardcoded "remain classical" claim that was
    false whenever a PQC cert was actually served. Three real states,
    not two: PQ cert, classical cert, or not inspected (cert fetch
    failed/timed out) — the issue's own guidance is to never assert
    "classical" in that third case.
    """
    cert_finding = next((f for f in result.findings if f.finding_type in _CERT_FINDING_TYPES), None)
    if cert_finding is None:
        return (
            "Monitor; certificate signature not yet inspected "
            "(fetch failed, timed out, or was skipped)."
        )
    if cert_finding.finding_type == FINDING_TYPE_PQ_SIGNATURE:
        return (
            f"Both axes are post-quantum: hybrid key exchange and a "
            f"{cert_finding.algorithm} certificate signature (FIPS 204)."
        )
    return (
        f"Monitor; key exchange is PQ-hybrid but the certificate signature "
        f"({cert_finding.algorithm}) remains classical."
    )


_CERT_FINDING_TYPES = frozenset({FINDING_TYPE_PQ_SIGNATURE, FINDING_TYPE_CLASSICAL_SIGNATURE})


def _findings_table(result: ScanResult) -> Table:
    table = Table(
        title="Findings",
        title_style="bold",
        show_header=True,
        header_style="bold cyan",
        box=box.SIMPLE_HEAD,
    )
    table.add_column("Rule")
    table.add_column("Severity")
    table.add_column("Readiness")
    table.add_column("Group")
    table.add_column("Protocol")

    for finding in result.findings:
        table.add_row(
            finding.rule_id,
            style_severity(finding.severity),
            style_readiness(finding.readiness),
            style_group(finding.negotiated_group),
            styled_or_dash(finding.protocol_version),
        )
    return table


def _dependencies_table(result: ScanResult) -> Table:
    table = Table(
        title="Dependencies",
        title_style="bold",
        show_header=True,
        header_style="bold cyan",
        box=box.SIMPLE_HEAD,
    )
    table.add_column("Name")
    table.add_column("Path")
    table.add_column("Version")
    table.add_column("X25519MLKEM768")

    for dep in result.dependencies:
        table.add_row(
            dep.name,
            style_path(dep),
            styled_or_dash(dep.version),
            style_capability(dep),
        )
    return table


def _pick_evidence(result: ScanResult, *, group: str) -> Evidence | None:
    """Find the evidence record produced by the latest probe attempt targeting `group`.

    Disambiguates hybrid vs classical by inspecting the probe command
    args rather than evidence IDs. (The scanner currently generates
    UUID-based evidence IDs; an `ev-classical-x25519` convention was
    proposed in an earlier draft but not adopted.)

    Issue #250: retries accumulate one Evidence per attempt in
    chronological order, so the first match is the oldest attempt, not
    the effective outcome. Picking the highest `attempt_number` mirrors
    #241's fix in `_summary.py` — a later successful retry must
    supersede an earlier failed attempt's evidence, not the reverse.
    """
    matches = [
        ev
        for ev in result.evidence
        if ev.probe_result is not None and group in ev.probe_result.command.args
    ]
    if not matches:
        return None
    return max(matches, key=lambda ev: ev.probe_result.attempt_number)  # type: ignore[union-attr]


def _first_protocol_version(evidence: tuple[Evidence, ...]) -> str | None:
    for ev in evidence:
        if ev.protocol_version:
            return ev.protocol_version
    return None


def _first_cipher_suite(evidence: tuple[Evidence, ...]) -> str | None:
    for ev in evidence:
        if ev.cipher_suite:
            return ev.cipher_suite
    return None


def _style_probe_status(evidence: Evidence | None) -> Text:
    """Compose the per-probe summary cell.

    `negotiated <GROUP>` (green word + group-styled name) when the probe
    succeeded; `failed (<category>)` in red on failure; dim `no result`
    when no evidence record exists.
    """
    if evidence is None:
        return Text("no result", style="dim")
    if evidence.failure_category is not None:
        return Text(f"failed ({evidence.failure_category.value})", style="red")
    if evidence.negotiated_group:
        out = Text("negotiated ", style="green")
        out.append(style_group(evidence.negotiated_group))
        return out
    return Text("no result", style="dim")
