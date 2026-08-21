# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Errors table (#276) and `-vvv` Commands panel rendering (issue #109).

Covers output/console/_errors.py and output/console/_commands.py -- the failing-
probe error surface and the exact-invocation dump. Both are driven through the
public `render_rich` (verbosity 3 to enable the Commands panel), rendering to an
in-memory buffer under NO_COLOR so the assertions are on plain text.

Hermetic: pure model -> string rendering; no subprocess, no network.
"""

from __future__ import annotations

import io
from datetime import UTC, datetime

import pytest

from qureddy.core.models import (
    Asset,
    Evidence,
    FailureCategory,
    ObservationType,
    ProbeCommand,
    ProbeResult,
    Readiness,
    ScanMetadata,
    ScanResult,
    ScanSummary,
    ScanTarget,
    Severity,
)
from qureddy.output.console import render_rich

_OPENSSL = "/opt/homebrew/opt/openssl@3.5/bin/openssl"
# A real OpenSSL record-layer error line: alert message + numeric alert code.
_ALERT_STDERR = (
    "40A7:error:0A000410:SSL routines:ssl3_read_bytes:"
    "tlsv1 alert insufficient security:ssl/record/rec_layer_s3.c:1605:"
    "SSL alert number 71"
)


def _probe(args: tuple[str, ...], *, failure: FailureCategory | None, stderr: str) -> ProbeResult:
    return ProbeResult(
        command=ProbeCommand(executable=_OPENSSL, args=args, timeout_seconds=30),
        return_code=1 if failure else 0,
        stdout_sha256="0" * 64,
        stderr_sha256="0" * 64,
        stderr_excerpt=stderr,
        duration_ms=90,
        failure_category=failure,
    )


def _evidence(ev_id: str, probe: ProbeResult | None) -> Evidence:
    return Evidence(
        id=ev_id,
        asset_id="asset-1",
        evidence_type="tls.negotiation",
        observation_type=ObservationType.NEGOTIATED,
        source="qureddy.scanners.tls.parse",
        probe_result=probe,
    )


def _result_with_probes(evidence: tuple[Evidence, ...]) -> ScanResult:
    target = ScanTarget(
        original_input="example.com",
        host="example.com",
        port=443,
        sni="example.com",
        locator="tls://example.com:443",
    )
    asset = Asset(
        id="asset-1",
        asset_type="tls.endpoint",
        locator=target.locator,
        display_name="example.com:443",
    )
    now = datetime(2026, 4, 26, tzinfo=UTC)
    return ScanResult(
        scan=ScanMetadata(scan_id="scan-1", started_at=now, completed_at=now, status="completed"),
        target=target,
        dependencies=(),
        assets=(asset,),
        evidence=evidence,
        findings=(),
        summary=ScanSummary(
            target=target.locator,
            finding_count=0,
            highest_severity=Severity.INFO,
            readiness=Readiness.UNKNOWN,
        ),
    )


def _render(result: ScanResult, *, verbosity: int = 0) -> str:
    buf = io.StringIO()
    render_rich(result, buf, verbosity=verbosity)
    return buf.getvalue()


@pytest.fixture(autouse=True)
def _no_color(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NO_COLOR", "1")


class TestErrorsTable:
    """_errors.py -- each failing probe's most-informative stderr line."""

    def test_alert_line_is_cleaned_to_message_and_alert_number(self) -> None:
        """An OpenSSL alert line is reduced to its human message plus the alert
        number; the MLKEM group in the args labels the probe."""
        ev = _evidence(
            "ev-1",
            _probe(
                ("s_client", "-groups", "X25519MLKEM768"),
                failure=FailureCategory.TLS_HANDSHAKE_FAILED,
                stderr=_ALERT_STDERR,
            ),
        )
        out = _render(_result_with_probes((ev,)))
        assert "Errors" in out
        assert "tlsv1 alert insufficient security (alert 71)" in out
        assert "X25519MLKEM768" in out

    def test_timeout_marker_used_when_no_alert(self) -> None:
        ev = _evidence(
            "ev-2",
            _probe(
                ("s_client", "-groups", "X25519"),
                failure=FailureCategory.TARGET_CONNECT_FAILED,
                stderr="Connecting...\n[qureddy] timeout after 30s",
            ),
        )
        out = _render(_result_with_probes((ev,)))
        assert "timeout after 30s" in out

    def test_no_stderr_shows_placeholder(self) -> None:
        ev = _evidence(
            "ev-3",
            _probe(
                ("s_client",),
                failure=FailureCategory.TLS_HANDSHAKE_FAILED,
                stderr="",
            ),
        )
        out = _render(_result_with_probes((ev,)))
        assert "(no error output captured)" in out

    def test_plain_last_line_passthrough(self) -> None:
        ev = _evidence(
            "ev-4",
            _probe(
                ("s_client",),
                failure=FailureCategory.TARGET_CONNECT_FAILED,
                stderr="connect: Connection refused",
            ),
        )
        out = _render(_result_with_probes((ev,)))
        assert "Connection refused" in out

    def test_no_errors_section_when_nothing_failed(self) -> None:
        ev = _evidence("ev-ok", _probe(("s_client",), failure=None, stderr=""))
        out = _render(_result_with_probes((ev,)))
        assert "Errors" not in out


class TestCommandsPanel:
    """_commands.py -- the `-vvv` exact-invocation dump with dedup."""

    def test_commands_panel_lists_unique_invocations_at_vvv(self) -> None:
        """Duplicate commands are de-duplicated; a probe with no result is
        skipped; a failing probe surfaces its failure category in red text."""
        dup_args = ("s_client", "-connect", "example.com:443", "-groups", "X25519MLKEM768")
        evidence = (
            _evidence("ev-a", _probe(dup_args, failure=None, stderr="")),
            _evidence("ev-b", _probe(dup_args, failure=None, stderr="")),  # duplicate
            _evidence(
                "ev-c",
                _probe(
                    ("s_client", "-connect", "example.com:443", "-groups", "X25519"),
                    failure=FailureCategory.TLS_HANDSHAKE_FAILED,
                    stderr=_ALERT_STDERR,
                ),
            ),
            _evidence("ev-none", None),  # probe_result None -> skipped
        )
        out = _render(_result_with_probes(evidence), verbosity=3)
        assert "Commands run" in out
        assert out.count("X25519MLKEM768") >= 1
        # The duplicate command line appears once in the panel body.
        assert out.count("-groups X25519MLKEM768") == 1
        assert "failure=" in out

    def test_commands_panel_absent_below_vvv(self) -> None:
        ev = _evidence("ev-a", _probe(("s_client",), failure=None, stderr=""))
        out = _render(_result_with_probes((ev,)), verbosity=2)
        assert "Commands run" not in out

    def test_commands_panel_none_when_no_probes_run(self) -> None:
        """A capability-failure scan with only result-less evidence renders no
        panel (returns None) rather than an empty box."""
        ev = _evidence("ev-none", None)
        out = _render(_result_with_probes((ev,)), verbosity=3)
        assert "Commands run" not in out
