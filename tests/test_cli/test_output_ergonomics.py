# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Output ergonomics (issue #133): --output FILE, --compact, --min-severity.

These options add peer-scanner conventions (testssl/ssh-audit/nmap) without
weakening the machine-output purity contract (issue #30): the json/cbom stdout
document stays exactly one complete, parseable document. The severity filter is
a rich-display convenience only — it never trims a machine document.
"""

from __future__ import annotations

import io
import json
import socket

import pytest
from typer.testing import CliRunner

from qureddy.cli import app
from qureddy.cli._render import _render
from qureddy.core.models import OutputFormat, ScanProvenance, Severity
from qureddy.output.cbom import render_cbom
from qureddy.output.json import render_json
from tests._fake_openssl import fake_openssl
from tests.test_output import _build_result

_HYBRID_RULE = "tls.hybrid.negotiated_pq"  # severity INFO in _build_result
_CLASSICAL_RULE = "tls.classical.negotiated_x25519"  # severity LOW in _build_result


def _refused_loopback_target() -> str:
    """A loopback host:port that refuses connections (hermetic, no network)."""
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    return f"127.0.0.1:{port}"


# --------------------------------------------------------------------------- #
# --output FILE / -o
# --------------------------------------------------------------------------- #
def test_output_writes_document_to_file_and_keeps_stdout_empty(tmp_path) -> None:
    """--output writes the machine document to a file; stdout stays byte-empty."""
    destination = tmp_path / "scan.json"
    result = CliRunner().invoke(
        app,
        [
            "scan",
            "tls",
            "example.com",
            "--openssl",
            fake_openssl("openssl_too_old"),
            "--format",
            "json",
            "--output",
            str(destination),
        ],
    )
    # Exit code is unchanged by the redirect (capability failure is still 3).
    assert result.exit_code == 3, result.output
    assert result.stdout == ""
    payload = json.loads(destination.read_text(encoding="utf-8"))
    assert payload["summary"]["failure_category"] == "local_openssl_too_old"


def test_output_short_flag_is_accepted(tmp_path) -> None:
    """-o is parity with --output."""
    destination = tmp_path / "scan.json"
    result = CliRunner().invoke(
        app,
        [
            "scan",
            "tls",
            "example.com",
            "--openssl",
            fake_openssl("openssl_too_old"),
            "--format",
            "json",
            "-o",
            str(destination),
        ],
    )
    assert result.exit_code == 3
    assert (
        json.loads(destination.read_text(encoding="utf-8"))["schema_version"] == "qureddy.scan.v1"
    )


def test_output_bad_path_is_usage_error_not_traceback(tmp_path) -> None:
    """A --output path that cannot be opened is a usage error (exit 4), like --log."""
    a_file = tmp_path / "a_file"
    a_file.write_text("x")  # a regular file used as a parent directory must fail
    result = CliRunner().invoke(
        app,
        [
            "scan",
            "tls",
            "example.com",
            "--openssl",
            fake_openssl("openssl_too_old"),
            "--format",
            "json",
            "--output",
            str(a_file / "sub.json"),
        ],
    )
    assert result.exit_code == 4, result.output
    assert "Traceback" not in result.output


# --------------------------------------------------------------------------- #
# --compact
# --------------------------------------------------------------------------- #
def test_compact_json_is_single_line_and_valid() -> None:
    """--compact JSON is minified (one line, no spaces after separators) and parseable."""
    buffer = io.StringIO()
    render_json(_build_result(), buffer, compact=True)
    text = buffer.getvalue()
    assert text.endswith("\n")
    assert text.count("\n") == 1, "compact JSON must be a single line plus a trailing newline"
    assert ", " not in text, "compact JSON must use minified separators"
    assert ": " not in text, "compact JSON must use minified separators"
    # Still a complete, parseable document with every top-level key.
    payload = json.loads(text)
    assert payload["summary"]["finding_count"] == 2


def test_pretty_json_stays_the_default() -> None:
    """Without --compact, JSON keeps the indented (multi-line) default."""
    buffer = io.StringIO()
    render_json(_build_result(), buffer)
    text = buffer.getvalue()
    assert text.count("\n") > 1
    assert "\n  " in text, "default JSON must stay indented"


def test_compact_cbom_is_single_line_and_valid() -> None:
    """--compact CBOM is minified to one line and remains a valid CycloneDX doc."""
    buffer = io.StringIO()
    render_cbom(_build_result(), buffer, compact=True)
    text = buffer.getvalue()
    assert text.count("\n") == 1
    payload = json.loads(text)
    assert payload["specVersion"] == "1.7"
    assert payload["bomFormat"] == "CycloneDX"


def test_cbom_carries_complete_build_provenance() -> None:
    """All available advisory provenance fields survive CBOM projection."""
    result = _build_result()
    result = result.model_copy(
        update={
            "scan": result.scan.model_copy(
                update={
                    "provenance": ScanProvenance(
                        distribution="container",
                        source_revision="abc123",
                        source_dirty=True,
                        container_digest="sha256:digest",
                    )
                }
            )
        }
    )
    buffer = io.StringIO()
    render_cbom(result, buffer)
    properties = {
        item["name"]: item["value"]
        for item in json.loads(buffer.getvalue())["metadata"]["properties"]
    }
    assert properties["qureddy:provenance.source_revision"] == "abc123"
    assert properties["qureddy:provenance.source_dirty"] == "true"
    assert properties["qureddy:provenance.container_digest"] == "sha256:digest"


def test_compact_flag_wired_through_cli(tmp_path) -> None:
    """`--format json --compact` end-to-end emits a minified single-line file."""
    destination = tmp_path / "scan.json"
    result = CliRunner().invoke(
        app,
        [
            "scan",
            "tls",
            "example.com",
            "--openssl",
            fake_openssl("openssl_too_old"),
            "--format",
            "json",
            "--compact",
            "--output",
            str(destination),
        ],
    )
    assert result.exit_code == 3
    text = destination.read_text(encoding="utf-8")
    assert text.count("\n") == 1
    json.loads(text)  # still parseable


# --------------------------------------------------------------------------- #
# --min-severity (rich display only; machine documents stay complete)
# --------------------------------------------------------------------------- #
def test_min_severity_hides_findings_below_threshold_in_rich() -> None:
    """--min-severity trims the rich findings table to the threshold and above."""
    unfiltered = io.StringIO()
    _render(_build_result(), OutputFormat.RICH, 0, stream=unfiltered)
    assert _HYBRID_RULE in unfiltered.getvalue()
    assert _CLASSICAL_RULE in unfiltered.getvalue()

    filtered = io.StringIO()
    _render(_build_result(), OutputFormat.RICH, 0, min_severity=Severity.HIGH, stream=filtered)
    # Both findings are INFO/LOW, i.e. below HIGH, so neither is shown.
    assert _HYBRID_RULE not in filtered.getvalue()
    assert _CLASSICAL_RULE not in filtered.getvalue()


def test_min_severity_keeps_findings_at_or_above_threshold_in_rich() -> None:
    """A LOW threshold keeps the LOW finding and drops the INFO one."""
    filtered = io.StringIO()
    _render(_build_result(), OutputFormat.RICH, 0, min_severity=Severity.LOW, stream=filtered)
    text = filtered.getvalue()
    assert _CLASSICAL_RULE in text  # LOW is at the threshold
    assert _HYBRID_RULE not in text  # INFO is below it


@pytest.mark.parametrize("output_format", [OutputFormat.JSON, OutputFormat.CBOM])
def test_min_severity_never_filters_machine_documents(output_format: OutputFormat) -> None:
    """The machine document stays complete even at the strictest --min-severity."""
    buffer = io.StringIO()
    _render(_build_result(), output_format, 0, min_severity=Severity.CRITICAL, stream=buffer)
    payload = json.loads(buffer.getvalue())
    if output_format is OutputFormat.JSON:
        assert len(payload["findings"]) == 2
        assert payload["summary"]["finding_count"] == 2
    else:
        # Findings survive as native annotations + per-component verdict properties (#287),
        # never filtered out of the machine document by --min-severity.
        assert payload.get("annotations"), "CBOM findings (annotations) must survive the filter"
        verdict_names = {
            prop["name"]
            for component in payload.get("components", [])
            for prop in component.get("properties", [])
            if prop["name"] in {"qureddy:readiness", "qureddy:severity"}
        }
        assert verdict_names, "CBOM finding verdicts must survive the severity filter"


def test_min_severity_json_via_cli_keeps_all_findings(tmp_path) -> None:
    """End-to-end: --format json --min-severity high still writes every finding."""
    destination = tmp_path / "scan.json"
    result = CliRunner().invoke(
        app,
        [
            "scan",
            "tls",
            "example.com",
            "--openssl",
            fake_openssl("openssl_too_old"),
            "--format",
            "json",
            "--min-severity",
            "high",
            "--output",
            str(destination),
        ],
    )
    assert result.exit_code == 3
    # The capability-failure document carries no findings, but the schema and
    # summary are intact — the filter must not have touched the document shape.
    payload = json.loads(destination.read_text(encoding="utf-8"))
    assert payload["schema_version"] == "qureddy.scan.v1"
    assert "findings" in payload


# --------------------------------------------------------------------------- #
# scan ssh parity
# --------------------------------------------------------------------------- #
def test_ssh_output_and_compact_write_clean_file(tmp_path) -> None:
    """scan ssh honors --output + --compact; stdout stays empty on a failure doc."""
    destination = tmp_path / "ssh.json"
    result = CliRunner().invoke(
        app,
        [
            "scan",
            "ssh",
            _refused_loopback_target(),
            "--format",
            "json",
            "--compact",
            "--output",
            str(destination),
        ],
    )
    assert result.exit_code == 2, result.output
    assert result.stdout == ""
    text = destination.read_text(encoding="utf-8")
    assert text.count("\n") == 1  # compact single line
    payload = json.loads(text)
    assert payload["summary"]["failure_category"] == "target_connect_failed"
    assert payload["scan"]["scanner_name"] == "ssh"
