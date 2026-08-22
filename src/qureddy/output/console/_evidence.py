# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Shared evidence selectors and cell styling for the console renderers.

Low-level helpers with no intra-package dependencies — the other console
modules import from here, not the reverse.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from rich.text import Text

from qureddy.core.models import Evidence, ObservationType, Severity
from qureddy.output._styles import style_group
from qureddy.scanners.common.rollup import SEVERITY_ORDER
from qureddy.scanners.tls.openssl_probe._constants import CLASSICAL_GROUP, HYBRID_GROUP

if TYPE_CHECKING:
    from qureddy.core.models import ScanResult

_HYBRID_GROUP = HYBRID_GROUP
_CLASSICAL_GROUP = CLASSICAL_GROUP

# Console orders findings most-severe first, the reverse of rollup's canonical
# INFO=0..CRITICAL=4 ranking (#315). Negating that single source of truth keeps the
# ordering identical without a second hand-maintained table: CRITICAL sorts lowest, so
# an ascending sort and the `<=` severity-floor filter in render.py both keep
# critical/high/medium and drop low/info, exactly as the old inline table did.
_SEVERITY_ORDER: dict[Severity, int] = {sev: -rank for sev, rank in SEVERITY_ORDER.items()}


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
