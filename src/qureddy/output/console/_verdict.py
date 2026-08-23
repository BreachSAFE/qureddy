# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""The verdict panel: at-a-glance headline + recommendation at the top of output."""

from __future__ import annotations

from typing import TYPE_CHECKING

from rich import box
from rich.panel import Panel
from rich.text import Text

from qureddy.core.models import FailureCategory, Readiness
from qureddy.output._styles import (
    CLASSICALLY_WEAK_WITH_PQC_TEMPLATE,
    RECOMMENDATION_TEXT,
    compose_status,
    unknown_headline,
    unknown_recommendation,
    verdict_border_style,
)
from qureddy.output.console._evidence import _CLASSICAL_GROUP, _HYBRID_GROUP, _pick_evidence
from qureddy.scanners.tls._cert_findings import (
    FINDING_TYPE_CLASSICAL_SIGNATURE,
    FINDING_TYPE_PQ_SIGNATURE,
)
from qureddy.scanners.tls._legacy_findings import FINDING_TYPE_LEGACY_PROTOCOL_OFFERED
from qureddy.scanners.tls.cert_sig import pqc_signature_standard

if TYPE_CHECKING:
    from qureddy.core.models import ScanResult

_CERT_FINDING_TYPES = frozenset({FINDING_TYPE_PQ_SIGNATURE, FINDING_TYPE_CLASSICAL_SIGNATURE})

_SSH_HYBRID_RECOMMENDATION = (
    "SSH key exchange is post-quantum hybrid.\n"
    "Host-key signatures remain classical.\n"
    "Note: no PQ SSH signature type exists yet."
)


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


def _summary_headline_and_recommendation(result: ScanResult) -> tuple[Text, Text]:
    """Return (headline, recommendation) for the top of the summary block.

    The headline is a plain-English at-a-glance signal; the recommendation
    tells the user what to do about it. Both rows come before the raw
    enum values so a skim reader sees the verdict first.
    """
    readiness = result.summary.readiness
    failure = result.summary.failure_category
    # Derive the hybrid group from the finding, not a hardcoded TLS group name,
    # so SSH (sntrup761x25519-sha512) shows its group in the headline too. The
    # old TLS-only _HYBRID_GROUP lookup returned None for SSH, leaving
    # "PQ hybrid  negotiated" with a blank group and a double space.
    hybrid_group = next(
        (
            f.negotiated_group
            for f in result.findings
            if f.readiness is Readiness.TRANSITIONAL_HYBRID and f.negotiated_group
        ),
        None,
    )
    classical_evidence = _pick_evidence(result, group=_CLASSICAL_GROUP)
    classical_group = classical_evidence.negotiated_group if classical_evidence else None

    headline = _compose_headline(
        result, readiness, failure, hybrid_group=hybrid_group, classical_group=classical_group
    )
    return headline, _recommendation(result, readiness, hybrid_group, failure)


def _compose_headline(  # noqa: PLR0911
    result: ScanResult,
    readiness: Readiness,
    failure: FailureCategory | None,
    *,
    hybrid_group: str | None,
    classical_group: str | None,
) -> Text:
    """Build the plain-English at-a-glance headline for the given readiness verdict."""
    if readiness is Readiness.QUANTUM_SAFE:
        return compose_status("READY", " — full PQ negotiated")
    if readiness is Readiness.TRANSITIONAL_HYBRID:
        headline = compose_status("READY", " — PQ hybrid ", group=hybrid_group)
        headline.append(" negotiated")
        return headline
    if readiness is Readiness.QUANTUM_VULNERABLE:
        if any(f.rule_id == "tls.hybrid.probe_failed" for f in result.findings):
            headline = compose_status("NOT READY", " — PQ support unconfirmed; classical ")
            headline.append(classical_group or "key exchange")
            headline.append(" observed")
            return headline
        headline = compose_status("NOT READY", " — classical only (", group=classical_group)
        headline.append(")")
        return headline
    if readiness is Readiness.CLASSICALLY_WEAK:
        return _classically_weak_headline(result, hybrid_group)
    if readiness is Readiness.NOT_APPLICABLE:
        return compose_status("UNKNOWN", " — scan not applicable")
    return unknown_headline(failure)


def _classically_weak_headline(result: ScanResult, hybrid_group: str | None) -> Text:
    """Headline for a classically-weak verdict: split axes when PQ hybrid is present."""
    if hybrid_group is None:
        return compose_status("FAIL", " — weak classical primitive")
    headline = Text("PQ posture: ", style="bold")
    headline.append("ACCEPTABLE", style="bold green")
    headline.append(" — ")
    headline.append(hybrid_group, style="bold green")
    headline.append(" negotiated\n")
    headline.append("Protocol hygiene: ", style="bold")
    headline.append("ACTION NEEDED", style="bold yellow")
    headline.append(" — ")
    legacy_protocols = _legacy_protocols(result)
    headline.append(
        legacy_protocols
        or (
            "classical SSH algorithms remain offered"
            if result.scan.scanner_name == "ssh"
            else "classical fallback accepted"
        )
    )
    return headline


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
    if protocols is None and result.scan.scanner_name == "ssh":
        return (
            f"PQ hybrid {hybrid_group} works. "
            "Classical SSH algorithms remain offered; review fallback posture."
        )
    protocols = protocols or "classical fallback accepted"
    return CLASSICALLY_WEAK_WITH_PQC_TEMPLATE.format(hybrid_group=hybrid_group, protocols=protocols)


def _legacy_protocols(result: ScanResult) -> str | None:
    """Return the offered legacy protocol versions in stable order."""
    protocols = sorted(
        {
            f.protocol_version
            for f in result.findings
            if f.finding_type == FINDING_TYPE_LEGACY_PROTOCOL_OFFERED and f.protocol_version
        }
    )
    return ", ".join(protocols) or None


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
        standard = pqc_signature_standard(cert_finding.algorithm or "")
        return (
            f"Both axes are post-quantum: hybrid key exchange and a "
            f"{cert_finding.algorithm} certificate signature ({standard})."
        )
    return (
        f"Monitor; key exchange is PQ-hybrid but the certificate signature "
        f"({cert_finding.algorithm}) remains classical."
    )
