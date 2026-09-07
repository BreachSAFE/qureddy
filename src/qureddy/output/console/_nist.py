# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Rich rendering for evidence-backed NIST quantum categories."""

from __future__ import annotations

from typing import TYPE_CHECKING

from rich import box
from rich.table import Table
from rich.text import Text

from qureddy.core.models import ProbeRole
from qureddy.output._styles import BODY_TEXT
from qureddy.scanners.common.rollup import _KEX_EVIDENCE_TYPES

if TYPE_CHECKING:
    from qureddy.core.models import Evidence, ScanResult


def nist_categories_table(result: ScanResult) -> Table | None:
    """Render every evidence-backed NIST category with its observation surface."""
    rows = _category_rows(result.evidence)
    if not rows:
        return None
    return _build_table(rows)


def _category_rows(evidence: tuple[Evidence, ...]) -> list[tuple[str, str, str, str, str]]:
    """Collect displayable category rows without changing their evidence meaning."""
    return [row for record in evidence if (row := _category_row(record))]


def _build_table(rows: list[tuple[str, str, str, str, str]]) -> Table:
    """Build the category table from already classified display rows."""
    table = Table(
        title="NIST quantum categories observed",
        title_style="bold",
        title_justify="left",
        show_header=True,
        header_style="bold cyan",
        box=box.SIMPLE_HEAD,
        pad_edge=False,
    )
    table.add_column("Surface", style="bold cyan", no_wrap=True)
    table.add_column("Context", style=BODY_TEXT, no_wrap=True)
    table.add_column("Level", justify="right", no_wrap=True)
    table.add_column("Algorithm", style=BODY_TEXT, overflow="fold")
    table.add_column("Note", style="yellow")
    for surface, context, level, algorithm, note in rows:
        level_text = Text(level, style="yellow" if level == "0" else "green")
        table.add_row(surface, context, level_text, algorithm, note)
    return table


def _category_row(evidence: Evidence) -> tuple[str, str, str, str, str] | None:
    """Project one category-bearing evidence record onto the Rich table shape."""
    level = evidence.nist_quantum_security_level
    if level is None:
        return None
    if evidence.evidence_type in _KEX_EVIDENCE_TYPES:
        return _key_exchange_row(evidence, level)
    if evidence.evidence_type == "tls.cert.signature":
        return _certificate_row(evidence, level)
    return None


def _key_exchange_row(evidence: Evidence, level: int) -> tuple[str, str, str, str, str]:
    """Build one key-exchange category row."""
    context = evidence.probe_role.value if evidence.probe_role is not None else "observed"
    note = "downgrade path" if evidence.probe_role is ProbeRole.CLASSICAL_CONTROL else ""
    return (
        "key exchange",
        context,
        str(level),
        evidence.negotiated_group or evidence.algorithm or "unknown",
        note,
    )


def _certificate_row(evidence: Evidence, level: int) -> tuple[str, str, str, str, str]:
    """Build one certificate-signature category row with its subject context."""
    subject = evidence.certificate.subject if evidence.certificate is not None else "observed"
    return ("certificate", subject, str(level), evidence.algorithm or "unknown", "")
