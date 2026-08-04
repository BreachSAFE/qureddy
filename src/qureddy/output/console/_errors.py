# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""The Errors section: surface the real OpenSSL error per failing probe (#276)."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from rich import box
from rich.table import Table

if TYPE_CHECKING:
    from qureddy.core.models import ProbeResult, ScanResult

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
