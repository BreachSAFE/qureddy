# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Regression tests for native retrieval Markdown projections.

The parity tests here derive every expectation from the typed ``ScanResult``
rather than from hardcoded literals. A hardcoded assertion only proves the one
value it names: an earlier revision of this module asserted section headings
plus two string values, and every dependency, asset and evidence record could
be dropped from the renderer with the suite still green, because
``_write_records`` emits its heading before it emits any record. Deriving the
expectation from ``result`` makes the test fail for any dropped record and keeps
working as the fixture grows.
"""

from __future__ import annotations

import io
import re
from typing import TYPE_CHECKING, Any

import pytest

from qureddy.output.cbom import build_cbom_payload
from qureddy.output.markdown import render_cbom_markdown, render_scan_markdown
from tests._cbom_fixtures import _build_result

if TYPE_CHECKING:
    from qureddy.core.models import ScanResult

#: ``- some.path[0].field: value`` is the one line shape the projection emits.
_BULLET = re.compile(r"^- (?P<path>[^:]+): ?(?P<value>.*)$")

#: Every top-level ``ScanResult`` field must reach the document. Kept as a
#: literal so a field added to the model without a projection section fails
#: here instead of silently vanishing.
_SCAN_SECTIONS = (
    "Run",
    "Target",
    "Dependencies",
    "Assets",
    "Findings",
    "Evidence",
    "Summary",
)


def _render_scan(result: ScanResult) -> str:
    """Render one scan projection to text."""
    document = io.StringIO()
    render_scan_markdown(result, document)
    return document.getvalue()


def _bullet_values(document: str) -> list[str]:
    """Return every rendered bullet value, in document order."""
    return [
        match.group("value")
        for line in document.splitlines()
        if (match := _BULLET.match(line)) is not None
    ]


def _record_ids(result: ScanResult) -> dict[str, list[str]]:
    """Collect the identity of every record the projection must carry."""
    return {
        "asset": [asset.id for asset in result.assets],
        "evidence": [evidence.id for evidence in result.evidence],
        "finding": [finding.id for finding in result.findings],
        "dependency": [dependency.name for dependency in result.dependencies],
    }


def test_scan_markdown_carries_every_section_and_record() -> None:
    """Dropping any record from any section fails this test.

    The identity of every asset, evidence, finding and dependency is read from
    the typed result, so a renderer that emits a section heading without its
    records cannot pass.
    """
    result = _build_result()

    document = _render_scan(result)
    values = _bullet_values(document)

    assert document.startswith("# QuReddy Scan\n")
    for section in _SCAN_SECTIONS:
        assert f"## {section}\n" in document, f"missing section: {section}"

    for kind, identities in _record_ids(result).items():
        assert identities, f"fixture carries no {kind} records; parity is unproven"
        for identity in identities:
            assert identity in values, f"{kind} identity absent from scan.md: {identity}"


def test_scan_markdown_carries_the_schema_and_scan_identity() -> None:
    """The document identifies the same schema and scan as the typed result."""
    result = _build_result()

    document = _render_scan(result)
    values = _bullet_values(document)

    assert result.schema_version in values
    assert result.scan.scan_id in values
    assert result.scan.status in values
    assert result.target.locator in values


def test_scan_markdown_record_count_matches_the_typed_result() -> None:
    """Each section emits exactly one numbered heading per record."""
    result = _build_result()

    document = _render_scan(result)

    for label, identities in (
        ("Dependency", result.dependencies),
        ("Asset", result.assets),
        ("Finding", result.findings),
        ("Evidence", result.evidence),
    ):
        emitted = len(re.findall(rf"^### {label} \d+$", document, re.MULTILINE))
        assert emitted == len(identities), (
            f"{label}: {emitted} headings for {len(identities)} records"
        )


def test_scan_markdown_emits_no_fenced_block() -> None:
    """The projection is flattened bullets, so a fence would break chunking."""
    assert "```" not in _render_scan(_build_result())


def test_scan_markdown_keeps_every_bullet_on_one_line() -> None:
    """A multi-line value must collapse so it cannot invent Markdown structure."""
    base = _build_result()
    result = base.model_copy(
        update={
            "summary": base.summary.model_copy(
                update={"target": "line-one\n# fabricated heading\n- fabricated bullet"}
            )
        }
    )

    document = _render_scan(result)

    assert "line-one # fabricated heading - fabricated bullet" in document
    assert "\n# fabricated heading" not in document
    assert "\n- fabricated bullet" not in document


@pytest.mark.parametrize(
    ("value", "expected"),
    [(None, "null"), ((), "[]")],
)
def test_scan_markdown_marks_absent_values_explicitly(value: Any, expected: str) -> None:
    """``None`` and an empty sequence each render a marker, never a blank."""
    base = _build_result()
    result = base.model_copy(
        update={"summary": base.summary.model_copy(update={"nist_quantum_security_levels": value})}
    )

    document = _render_scan(result)

    assert f"- nist_quantum_security_levels: {expected}\n" in document


def test_scan_markdown_marks_an_empty_string_explicitly() -> None:
    """An empty string needs a marker for the same reason ``None`` does.

    Live counts per real scan at the time of writing: 12 bullets on an IKE run,
    7 on TLS, 7 on STARTTLS, 3 on wallet. One of them is
    ``interpretation.display.evaluation.hardening``, a human-readable verdict.
    """
    base = _build_result()
    result = base.model_copy(update={"summary": base.summary.model_copy(update={"target": ""})})

    document = _render_scan(result)

    assert '- target: ""\n' in document


def test_scan_markdown_preserves_model_field_order_and_header_block() -> None:
    """Keep the typed model order and group document identity fields together."""
    document = _render_scan(_build_result())

    assert document.index("- scan_id:") < document.index("- started_at:")
    assert document.index("- started_at:") < document.index("- completed_at:")
    assert (
        "- projection_version: qureddyai-scan-v2\n- schema_version: qureddy.scan.v1\n\n"
    ) in document


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


def test_cbom_markdown_carries_every_component_and_metadata_property() -> None:
    """Dropping a component or a metadata property fails this test."""
    payload = build_cbom_payload(_build_result(), reproducible=True)
    document = io.StringIO()

    render_cbom_markdown(payload, document)

    values = _bullet_values(document.getvalue())
    components = payload.get("components", [])
    assert components, "fixture carries no CBOM components; parity is unproven"
    for component in components:
        assert component["bom-ref"] in values, f"bom-ref absent: {component['bom-ref']}"

    properties = payload.get("metadata", {}).get("properties", [])
    assert properties, "fixture carries no CBOM metadata properties"
    for prop in properties:
        assert prop["name"] in values, f"metadata property absent: {prop['name']}"


def test_cbom_markdown_component_count_matches_the_payload() -> None:
    """One numbered component heading per payload component."""
    payload = build_cbom_payload(_build_result(), reproducible=True)
    document = io.StringIO()

    render_cbom_markdown(payload, document)

    emitted = len(re.findall(r"^### Component \d+$", document.getvalue(), re.MULTILINE))
    assert emitted == len(payload.get("components", []))
