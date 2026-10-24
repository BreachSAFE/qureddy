# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Regression tests for native retrieval Markdown projections."""

from __future__ import annotations

import io

from qureddy.output.cbom import build_cbom_payload
from qureddy.output.markdown import render_cbom_markdown, render_scan_markdown
from tests._cbom_fixtures import _build_result


def test_scan_markdown_projects_every_scanresult_top_level_field() -> None:
    """The native Markdown projection does not silently drop ScanResult data."""
    result = _build_result()
    document = io.StringIO()

    render_scan_markdown(result, document)

    output = document.getvalue()
    assert "# QuReddy Scan" in output
    assert "## Run" in output
    assert "## Target" in output
    assert "## Dependencies" in output
    assert "## Assets" in output
    assert "## Findings" in output
    assert "## Evidence" in output
    assert "## Summary" in output
    assert "```" not in output
    assert "scan-test" in output
    assert "tls.hybrid.negotiated_pq" in output


def test_cbom_markdown_projects_components_and_future_fields() -> None:
    """CBOM Markdown retains component semantics without scanner-specific rules."""
    payload = build_cbom_payload(_build_result(), reproducible=True)
    payload["futureCycloneDxField"] = {"nested": [["value"]]}
    document = io.StringIO()

    render_cbom_markdown(payload, document)

    output = document.getvalue()
    assert "# QuReddy CBOM" in output
    assert "## Metadata" in output
    assert "## Components" in output
    assert "## Dependencies" in output
    assert "X25519MLKEM768" in output
    assert "## Additional fields" in output
    assert "futureCycloneDxField.nested[0][0]: value" in output
    assert "```" not in output
