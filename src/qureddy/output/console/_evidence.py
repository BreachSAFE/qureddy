# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Shared evidence selectors and cell styling for the console renderers.

Low-level helpers with no intra-package dependencies — the other console
modules import from here, not the reverse.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from rich.text import Text

from qureddy.core.models import Evidence, ObservationType, ProbeRole, Severity
from qureddy.core.pqc import is_hybrid_pq, is_pq_kem
from qureddy.output._styles import style_group
from qureddy.scanners.common.rollup import SEVERITY_ORDER

if TYPE_CHECKING:
    from qureddy.core.models import ScanResult

# Console orders findings most-severe first, the reverse of rollup's canonical
# INFO=0..CRITICAL=4 ranking (#315). Negating that single source of truth keeps the
# ordering identical without a second hand-maintained table: CRITICAL sorts lowest, so
# an ascending sort and the `<=` severity-floor filter in render.py both keep
# critical/high/medium and drop low/info, exactly as the old inline table did.
_SEVERITY_ORDER: dict[Severity, int] = {sev: -rank for sev, rank in SEVERITY_ORDER.items()}


def _pick_evidence(result: ScanResult, *, role: ProbeRole) -> Evidence | None:
    """Find the latest evidence record produced for a probe role.

    Probe roles are canonical evidence semantics, so output does not need to
    know TLS/OpenSSL group names. The scanner currently generates UUID-based
    evidence IDs; role is the stable selector.

    Issue #250: retries accumulate one Evidence per attempt in
    chronological order, so the first match is the oldest attempt, not
    the effective outcome. Picking the highest `attempt_number` mirrors
    #241's fix in `_summary.py` — a later successful retry must
    supersede an earlier failed attempt's evidence, not the reverse.
    """
    matches = [ev for ev in result.evidence if ev.probe_role is role]
    if not matches:
        # Archived/pre-role fixtures use the neutral group classifier as a
        # compatibility bridge; new scans always take the role path above.
        matches = [ev for ev in result.evidence if _legacy_role_match(ev, role)]
    if not matches:
        return None
    # Offered evidence is intentionally probe-free, so it has no attempt
    # number.  Treat it as the oldest record rather than crashing the rich
    # renderer while selecting a role summary.
    return max(
        matches,
        key=lambda ev: ev.probe_result.attempt_number if ev.probe_result is not None else -1,
    )


def _legacy_role_match(evidence: Evidence, role: ProbeRole) -> bool:
    """Match pre-role evidence without importing a protocol scanner."""
    group = evidence.negotiated_group
    if not group:
        return False
    if role is ProbeRole.HYBRID_READINESS:
        return is_hybrid_pq(group)
    return role is ProbeRole.CLASSICAL_CONTROL and not is_pq_kem(group)


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
