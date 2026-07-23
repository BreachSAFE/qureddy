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
import re
import sys
from typing import IO, TYPE_CHECKING

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from qureddy._branding import HEADER
from qureddy.core.models import (
    Evidence,
    FailureCategory,
    Finding,
    ObservationType,
    ProbeResult,
    Readiness,
    Severity,
)
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
_SEVERITY_ORDER: dict[Severity, int] = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


def render_rich(
    result: ScanResult,
    stream: IO[str] | None = None,
    *,
    verbosity: int = 0,
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

    Honors NO_COLOR per https://no-color.org.
    """
    target_stream = stream if stream is not None else sys.stdout
    console = _make_console(target_stream)
    console.print(_header_text())
    console.print()

    console.print(_verdict_panel(result))
    console.print()
    console.print(_summary_table(result))
    if result.findings:
        console.print()
        console.print(_findings_table(result))
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


def _header_text() -> Text:
    """Color the top-of-output header: brand name green, website cyan.

    HEADER is `QuReddy <ver> by BreachSAFE OSS · <url>`. Split on the middot
    so the site reads as a distinct (cyan) element next to the green brand
    line, instead of one flat bold row.
    """
    name_part, sep, url_part = HEADER.partition(" · ")
    header = Text()
    header.append(name_part, style="bold green")
    if sep:
        header.append(sep)  # keep the " · " separator so HEADER renders verbatim
        header.append(url_part, style="cyan")
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
    return Console(file=stream, no_color=no_color, highlight=False)


_OPENSSL_ERR_RE = re.compile(r"SSL routines:[^:]*:(?P<msg>.+?):[^:]*\.c:\d+")
_ALERT_NUM_RE = re.compile(r"SSL alert number (?P<num>\d+)")


def _clean_error_line(line: str) -> str:
    """Reduce one OpenSSL stderr line to its human-meaningful message.

    OpenSSL error lines are `HEX:error:CODE:SSL routines:func:MESSAGE:file.c:NN:`
    — extract MESSAGE and append the alert number when present, so the reader
    sees `tlsv1 alert insufficient security (alert 71)` rather than the raw
    hex-prefixed record-layer noise. Non-OpenSSL lines pass through unchanged.
    """
    match = _OPENSSL_ERR_RE.search(line)
    if not match:
        return line
    msg = match.group("msg")
    alert = _ALERT_NUM_RE.search(line)
    return f"{msg} (alert {alert.group('num')})" if alert else msg


def _last_error_line(probe: ProbeResult) -> str:
    """Return the most informative single line from a failing probe's stderr.

    Prefers the actual TLS alert line (e.g. `tlsv1 alert insufficient
    security`) over trailing teardown noise like `SSL_shutdown`; falls back
    to the `[qureddy] timeout after Ns` marker, then the last non-blank
    line. Purely a presentation of already-captured evidence; no new probing.
    """
    lines = [line.strip() for line in probe.stderr_excerpt.splitlines() if line.strip()]
    if not lines:
        return "(no error output captured)"
    alert_line = next((line for line in lines if "alert" in line.lower()), None)
    if alert_line is not None:
        return _clean_error_line(alert_line)
    timeout_line = next((line for line in lines if "timeout after" in line), None)
    return _clean_error_line(timeout_line if timeout_line is not None else lines[-1])


def _errors_table(result: ScanResult) -> Table | None:
    """List each failing probe attempt with the real OpenSSL error it hit.

    Surfaces `evidence[].probe_result.stderr_excerpt` so the human reader
    sees *why* a probe failed (the specific alert or timeout) rather than
    only the bucketed `failure_category`. Returns None when nothing
    failed, so a clean scan shows no Errors section (issue #276).
    """
    rows: list[tuple[str, str, str]] = []
    for ev in result.evidence:
        probe = ev.probe_result
        if probe is None or probe.failure_category is None:
            continue
        group = next(
            (a for a in probe.command.args if "MLKEM" in a or a in {"X25519", "P-256"}),
            ev.evidence_type,
        )
        rows.append((group, str(probe.attempt_number), _last_error_line(probe)))
    if not rows:
        return None
    table = Table(
        title="Errors",
        title_style="bold",
        title_justify="left",
        show_header=True,
        header_style="bold cyan",
        show_lines=False,
        box=box.SIMPLE_HEAD,
        pad_edge=False,
    )
    table.add_column("Probe", style="bold cyan", no_wrap=True)
    table.add_column("Attempt", justify="right")
    table.add_column("Detail", style="yellow")
    for group, attempt, detail in rows:
        table.add_row(group, attempt, detail)
    return table


def _run_details_table(result: ScanResult) -> Table:
    """Render scan execution metadata in the same form as scan details."""
    duration = (result.scan.completed_at - result.scan.started_at).total_seconds()
    completed = result.scan.completed_at.isoformat(timespec="seconds").replace("+00:00", "Z")
    started = result.scan.started_at.isoformat(timespec="seconds").replace("+00:00", "Z")
    table = Table(
        title="Run details",
        title_style="bold",
        title_justify="left",
        show_header=True,
        header_style="bold cyan",
        show_lines=False,
        box=box.SIMPLE_HEAD,
        pad_edge=False,
    )
    table.add_column("Field", style="bold cyan", no_wrap=True)
    table.add_column("Value")
    table.add_row("scan_id", Text(result.scan.scan_id))
    table.add_row("scanner", Text(result.scan.scanner_name))
    table.add_row("version", Text(result.scan.scanner_version))
    table.add_row("started", Text(started))
    table.add_row("completed", Text(completed))
    table.add_row("duration", Text(f"{duration:.1f}s"))
    for dep in result.dependencies:
        table.add_row(f"{dep.name}_path", style_path(dep))
        table.add_row(f"{dep.name}_version", styled_or_dash(dep.version))
        table.add_row(f"{dep.name}_hybrid_support", style_capability(dep))
    return table


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
        border_style=_verdict_panel_border(result),
        # Issue #7: box.HEAVY + default expand=True stretched a full-width
        # rectangle around a short verdict. HORIZONTALS draws only top/bottom
        # rules (title on top, verdict color preserved, no side borders), and
        # expand=False sizes it to the content instead of the terminal.
        box=box.HORIZONTALS,
        expand=False,
        padding=(0, 0),
    )


def _summary_table(result: ScanResult) -> Table:
    table = Table(
        title="Scan details",
        title_style="bold",
        title_justify="left",
        show_header=True,
        header_style="bold cyan",
        show_lines=False,
        box=box.SIMPLE_HEAD,
        pad_edge=False,
    )
    table.add_column("Field", style="bold cyan", no_wrap=True)
    table.add_column("Value")

    summary = result.summary
    scan = result.scan

    table.add_row("schema_version", Text(result.schema_version))
    table.add_row("status", Text(scan.status))
    table.add_row("readiness", style_readiness(summary.readiness))
    if scan.scanner_name == "ssh":
        # SSH has no TLS-style forced hybrid/classical probes or cipher suite;
        # show the KEX/host-key algorithms actually observed instead.
        table.add_row("key_exchange", _style_ssh_kex(result))
        table.add_row("host_keys", _style_ssh_hostkeys(result))
    else:
        hybrid_evidence = _pick_evidence(result, group=_HYBRID_GROUP)
        classical_evidence = _pick_evidence(result, group=_CLASSICAL_GROUP)
        table.add_row("protocol", styled_or_dash(_first_protocol_version(result.evidence)))
        table.add_row("cipher_suite", styled_or_dash(_first_cipher_suite(result.evidence)))
        table.add_row("hybrid_probe", _style_probe_status(hybrid_evidence))
        table.add_row("classical_probe", _style_probe_status(classical_evidence))
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


def _style_ssh_kex(result: ScanResult) -> Text:
    """Summarize the SSH key-exchange evidence for the scan-details table."""
    for ev in result.evidence:
        if ev.evidence_type == "ssh.kex" and ev.negotiated_group:
            out = Text("PQ hybrid ", style="green")
            out.append(style_group(ev.negotiated_group))
            return out
    return Text("classical only", style="yellow")


def _style_ssh_hostkeys(result: ScanResult) -> Text:
    """Summarize SSH host-key posture (weak vs classical) for the table."""
    for ev in result.evidence:
        if ev.evidence_type == "ssh.hostkey":
            return Text("weak algorithm offered", style="bold red")
    return Text("classical", style="dim")


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
            headline = Text("PQ posture: ", style="bold")
            headline.append("ACCEPTABLE", style="bold green")
            headline.append(" — ")
            headline.append(hybrid_group, style="bold green")
            headline.append(" negotiated\n")
            headline.append("Protocol hygiene: ", style="bold")
            headline.append("ACTION NEEDED", style="bold yellow")
            headline.append(" — ")
            headline.append(_legacy_protocols(result))
        else:
            headline = compose_status("FAIL", " — weak classical primitive")
    elif readiness is Readiness.NOT_APPLICABLE:
        headline = compose_status("UNKNOWN", " — scan not applicable")
    else:
        headline = unknown_headline(failure)

    return headline, _recommendation(result, readiness, hybrid_group, failure)


_SSH_HYBRID_RECOMMENDATION = (
    "SSH key exchange is post-quantum hybrid.\n"
    "Host-key signatures remain classical.\n"
    "Note: no PQ SSH signature type exists yet."
)


def _recommendation(
    result: ScanResult,
    readiness: Readiness,
    hybrid_group: str | None,
    failure: FailureCategory | None,
) -> Text:
    """Select the recommendation line for the verdict panel."""
    if readiness is Readiness.TRANSITIONAL_HYBRID:
        if result.scan.scanner_name == "ssh":
            return Text(_SSH_HYBRID_RECOMMENDATION)
        return Text(_cert_axis_recommendation(result))
    if readiness is Readiness.CLASSICALLY_WEAK and hybrid_group is not None:
        return Text(_classically_weak_with_pqc_recommendation(result, hybrid_group))
    if readiness in RECOMMENDATION_TEXT:
        return Text(RECOMMENDATION_TEXT[readiness])
    return Text(unknown_recommendation(failure))


def _classically_weak_with_pqc_recommendation(result: ScanResult, hybrid_group: str) -> str:
    """Recommendation for a target that supports PQ hybrid AND legacy protocols.

    Confirmed live against google.com — a large-scale service can
    genuinely hold both postures simultaneously for a long time, and
    the old one-sided "PQ readiness is moot" message was factually
    wrong in that case: PQ readiness is NOT moot, it's already working,
    alongside a real legacy exposure. Both facts get said, not one
    hiding the other.
    """
    protocols = _legacy_protocols(result)
    return CLASSICALLY_WEAK_WITH_PQC_TEMPLATE.format(hybrid_group=hybrid_group, protocols=protocols)


def _legacy_protocols(result: ScanResult) -> str:
    """Return the offered legacy protocol versions in stable order."""
    protocols = sorted(
        {
            f.protocol_version
            for f in result.findings
            if f.finding_type == FINDING_TYPE_LEGACY_PROTOCOL_OFFERED and f.protocol_version
        }
    )
    return ", ".join(protocols) or "classical fallback accepted"


def _verdict_panel_border(result: ScanResult) -> str:
    """Use amber for mixed posture; red means unambiguously broken posture."""
    if (
        result.summary.readiness is Readiness.CLASSICALLY_WEAK
        and _pick_evidence(result, group=_HYBRID_GROUP) is not None
    ):
        return "yellow"
    return verdict_border_style(result.summary.readiness)


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
    """Findings table.

    Keep the human table compact while retaining the fields that distinguish
    observed crypto: severity, stable rule ID, protocol, group, and algorithm.
    The full readiness enum remains in JSON and the scan-details block.
    """
    table = Table(
        title="Findings",
        title_style="bold",
        title_justify="left",
        show_header=True,
        header_style="bold cyan",
        box=box.SIMPLE_HEAD,
        pad_edge=False,
        padding=(0, 0),
    )
    table.add_column("Severity", no_wrap=True, width=8)
    # Long rule IDs must never be ellipsized: they are the stable join key
    # between console, JSON, tests, and policy tooling.
    table.add_column("Rule", no_wrap=True, width=38)
    table.add_column("Protocol", no_wrap=True, width=8)
    table.add_column("Crypto", no_wrap=False, overflow="fold", width=20)

    for finding in sorted(result.findings, key=lambda item: _SEVERITY_ORDER[item.severity]):
        details = _finding_crypto_detail(finding)
        table.add_row(
            style_severity(finding.severity),
            finding.rule_id,
            styled_or_dash(finding.protocol_version),
            details,
        )
    return table


def _finding_crypto_detail(finding: Finding) -> Text:
    """Render the compact crypto discriminator for one finding."""
    if finding.negotiated_group:
        details = style_group(finding.negotiated_group)
        if finding.algorithm:
            details.append(f" / {finding.algorithm}")
        return details
    if finding.algorithm:
        return Text(finding.algorithm)
    if finding.finding_type == FINDING_TYPE_LEGACY_PROTOCOL_OFFERED:
        return Text("legacy protocol")
    if finding.finding_type == "tls.kex.classical_protocol":
        return Text("classical suites")
    return Text("—", style="dim")


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
        if (
            ev.observation_type is ObservationType.NEGOTIATED
            and ev.failure_category is None
            and ev.protocol_version
        ):
            return ev.protocol_version
    return None


def _first_cipher_suite(evidence: tuple[Evidence, ...]) -> str | None:
    for ev in evidence:
        if (
            ev.observation_type is ObservationType.NEGOTIATED
            and ev.failure_category is None
            and ev.cipher_suite
        ):
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
