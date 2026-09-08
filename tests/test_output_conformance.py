# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Regression tests for the five-format output conformance harness."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from scripts.validate_output_bundle import validate_bundle

from qureddy.cli._render import _render_bundle
from tests._cbom_fixtures import _build_result


def _write_bundle(directory: Path) -> None:
    """Emit all supported projections from the canonical test ScanResult."""
    result = _build_result()
    finding = result.findings[0].model_copy(update={"runtime": "openssl"})
    _render_bundle(
        result.model_copy(update={"findings": (finding,)}),
        directory,
        reproducible=True,
        compact=False,
    )


def test_bundle_validator_accepts_canonical_four_format_bundle(tmp_path: Path) -> None:
    """A real renderer bundle passes JSON, JSONL, Rich, and CBOM checks."""
    _write_bundle(tmp_path)

    result = validate_bundle(tmp_path, "tls", "example.com")

    assert "findings=1" in result
    assert "jsonl_records=2" in result
    assert "sarif_results=not-requested" in result


def test_bundle_validator_rejects_jsonl_finding_drift(tmp_path: Path) -> None:
    """A changed JSONL finding cannot silently diverge from canonical JSON."""
    _write_bundle(tmp_path)
    jsonl_path = tmp_path / "scan.jsonl"
    records = [json.loads(line) for line in jsonl_path.read_text().splitlines()]
    records[0]["template-id"] = "tls.fabricated.rule"
    jsonl_path.write_text(
        "".join(json.dumps(record, separators=(",", ":")) + "\n" for record in records)
    )

    with pytest.raises(ValueError, match="JSONL finding identity drift"):
        validate_bundle(tmp_path, "tls", "example.com")


def test_bundle_validator_accepts_optional_sarif_envelope(tmp_path: Path) -> None:
    """The fifth-format gate validates a supplied SARIF 2.1.0 artifact."""
    _write_bundle(tmp_path)
    (tmp_path / "scan.sarif.json").write_text(
        json.dumps(
            {
                "version": "2.1.0",
                "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
                "runs": [
                    {
                        "tool": {"driver": {"name": "QuReddy"}},
                        "results": [{"ruleId": "tls.hybrid.negotiated_pq"}],
                    }
                ],
            }
        )
    )

    result = validate_bundle(tmp_path, "tls", "example.com", tmp_path / "scan.sarif.json")

    assert "sarif_results=1" in result
