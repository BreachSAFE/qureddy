# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Shared evidence selectors and cell styling for the console renderers.

Low-level helpers with no intra-package dependencies — the other console
modules import from here, not the reverse.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from rich.text import Text

from qureddy.core.models import Evidence, ObservationType, Severity
from qureddy.output._styles import style_group

if TYPE_CHECKING:
    from qureddy.core.models import ScanResult

_HYBRID_GROUP = "X25519MLKEM768"
_CLASSICAL_GROUP = "X25519"

_SEVERITY_ORDER: dict[Severity, int] = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


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
