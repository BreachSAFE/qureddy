# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""The scan-details, findings, and run-details tables."""

from __future__ import annotations

from typing import TYPE_CHECKING

from rich import box
from rich.table import Table
from rich.text import Text

from qureddy.output._styles import (
    BODY_TEXT,
    style_capability,
    style_group,
    style_path,
    style_readiness,
    style_severity,
    styled_or_dash,
)
from qureddy.output.console._evidence import (
    _CLASSICAL_GROUP,
    _HYBRID_GROUP,
    _SEVERITY_ORDER,
    _first_cipher_suite,
    _first_protocol_version,
    _pick_evidence,
    _style_probe_status,
)
from qureddy.scanners.tls._legacy_findings import FINDING_TYPE_LEGACY_PROTOCOL_OFFERED

if TYPE_CHECKING:
    from qureddy.core.models import Finding, ScanResult


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
    table.add_column("Value", style=BODY_TEXT)

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
    table.add_column("Value", style=BODY_TEXT)
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
