# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""The scan-details, findings, and run-details tables."""

from __future__ import annotations

from typing import TYPE_CHECKING

from rich import box
from rich.table import Table
from rich.text import Text

from qureddy.core.models import OpenSSLDependency, ProbeRole
from qureddy.core.pqc import is_hybrid_pq
from qureddy.output._styles import (
    BODY_TEXT,
    style_capability,
    style_group,
    style_hndl,
    style_hygiene,
    style_path,
    style_readiness,
    style_severity,
    styled_or_dash,
)
from qureddy.output.console._evidence import (
    _SEVERITY_ORDER,
    _first_cipher_suite,
    _first_protocol_version,
    _pick_evidence,
    _style_probe_status,
)
from qureddy.scanners.common.finding_types import FINDING_TYPE_LEGACY_PROTOCOL_OFFERED

if TYPE_CHECKING:
    from qureddy.core.models import Finding, ScanResult


def _field_value_table(title: str) -> Table:
    """A two-column Field/Value table shared by the scan-details and run-details blocks."""
    table = Table(
        title=title,
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
    return table


def _summary_table(result: ScanResult) -> Table:
    table = _field_value_table("Scan details")

    summary = result.summary
    scan = result.scan

    table.add_row("schema_version", Text(result.schema_version))
    table.add_row("status", Text(scan.status))
    table.add_row("readiness", style_readiness(summary.readiness))
    if summary.interpretation is not None:
        display = summary.interpretation.display
        table.add_row("overall_status", Text(display.overall_status))
        table.add_row("quantum_protection", Text(display.quantum_protection))
        table.add_row("future_quantum_risk", Text(display.future_quantum_risk))
        table.add_row("current_hygiene", Text(display.current_hygiene))
        table.add_row("technical_detail", Text(summary.interpretation.headline))
        table.add_row("recommended_action", Text(summary.interpretation.recommended_action))
        table.add_row("hndl_exposure", style_hndl(summary.interpretation.hndl_exposure))
        table.add_row("hygiene_status", style_hygiene(summary.interpretation.hygiene_status))
        axes = summary.interpretation.axes
        table.add_row("pqc_support", Text(axes.pqc_support.value))
        table.add_row("key_exchange_posture", Text(axes.key_exchange.value))
        table.add_row("downgrade_resistance", Text(axes.downgrade_resistance.value))
        table.add_row("authentication", Text(axes.authentication.value))
        table.add_row("protocol_hygiene", Text(axes.protocol_hygiene.value))
    if scan.scanner_name == "ssh":
        # SSH has no TLS-style forced hybrid/classical probes or cipher suite;
        # show the KEX/host-key algorithms actually observed instead.
        table.add_row("key_exchange", _style_ssh_kex(result))
        table.add_row("host_keys", _style_ssh_hostkeys(result))
    else:
        hybrid_evidence = _pick_evidence(result, role=ProbeRole.HYBRID_READINESS)
        classical_evidence = _pick_evidence(result, role=ProbeRole.CLASSICAL_CONTROL)
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
    table = _field_value_table("Run details")
    table.add_row("scan_id", Text(result.scan.scan_id))
    table.add_row("scanner", Text(result.scan.scanner_name))
    table.add_row("version", Text(result.scan.scanner_version))
    if result.scan.provenance is not None:
        provenance = result.scan.provenance
        table.add_row("distribution", Text(provenance.distribution))
        table.add_row("source_revision", styled_or_dash(provenance.source_revision))
        table.add_row(
            "source_dirty",
            styled_or_dash(
                None if provenance.source_dirty is None else str(provenance.source_dirty).lower()
            ),
        )
        table.add_row("container_digest", styled_or_dash(provenance.container_digest))
    table.add_row("started", Text(started))
    table.add_row("completed", Text(completed))
    table.add_row("duration", Text(f"{duration:.1f}s"))
    for dep in result.dependencies:
        table.add_row(f"{dep.name}_path", style_path(dep))
        table.add_row(f"{dep.name}_version", styled_or_dash(dep.version))
        if isinstance(dep, OpenSSLDependency):
            table.add_row(f"{dep.name}_hybrid_support", style_capability(dep))
    return table


def _style_ssh_kex(result: ScanResult) -> Text:
    """Summarize the SSH key-exchange evidence for the scan-details table."""
    for ev in result.evidence:
        if ev.evidence_type == "ssh.kex" and ev.negotiated_group:
            group = ev.negotiated_group
            if is_hybrid_pq(group):
                out = Text("PQ hybrid ", style="green")
                out.append(style_group(group))
                return out
            return style_group(group)
    return Text("classical only", style="yellow")


def _style_ssh_hostkeys(result: ScanResult) -> Text:
    """Summarize SSH host-key posture (weak vs classical) for the table.

    Every offered host key is now recorded as ssh.hostkey evidence (so the CBOM can
    inventory it), so the weak signal comes from the finding, not the evidence type.
    """
    if any(f.rule_id == "ssh.hostkey.weak" for f in result.findings):
        return Text("weak algorithm offered", style="bold red")
    return Text("classical", style="dim")


def _findings_table(result: ScanResult, *, findings: tuple[Finding, ...] | None = None) -> Table:
    """Findings table.

    Keep the human table compact while retaining the fields that distinguish
    observed crypto: severity, stable rule ID, protocol, group, and algorithm.
    The full readiness enum remains in JSON and the scan-details block.

    ``findings`` overrides which findings are rendered (used by the
    ``--min-severity`` display filter, issue #133); it defaults to every
    finding on ``result``.
    """
    rows = result.findings if findings is None else findings
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

    for finding in sorted(rows, key=lambda item: _SEVERITY_ORDER[item.severity]):
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
        if finding.algorithm and finding.algorithm != finding.negotiated_group:
            details.append(f" / {finding.algorithm}")
        return details
    if finding.algorithm:
        return Text(finding.algorithm)
    if finding.finding_type == FINDING_TYPE_LEGACY_PROTOCOL_OFFERED:
        return Text("legacy protocol")
    if finding.finding_type == "tls.kex.classical_protocol":
        return Text("classical suites")
    return Text("—", style="dim")
