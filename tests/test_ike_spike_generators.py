# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Regression tests for the retained IKE catalog generators."""

from __future__ import annotations

import hashlib
import importlib.util
from pathlib import Path
from types import ModuleType

import pytest

_ROOT = Path(__file__).resolve().parents[1]
_CATALOG_DIR = _ROOT / "docs" / "spikes" / "ike-0.10-contract" / "catalog"


def _load_module(name: str, filename: str) -> ModuleType:
    """Load a retained generator without making the docs tree a package."""
    spec = importlib.util.spec_from_file_location(name, _CATALOG_DIR / filename)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


GENERATOR = _load_module("ike_catalog_generator", "gen_catalog.py")
RFC_AXIS = _load_module("ike_rfc8247_axis", "add_rfc8247.py")


def test_catalog_parser_preserves_status_and_unique_xrefs(tmp_path: Path) -> None:
    """Parse either IANA name element without duplicating citations."""
    source = tmp_path / "registry.xml"
    source.write_text(
        '<registry id="fixture"><record><value>7</value><name>ALG_TEST</name>'
        '<status>Deprecated</status><xref type="rfc" data="rfc1"/>'
        '<xref type="rfc" data="rfc1"/></record></registry>',
        encoding="utf-8",
    )

    assert GENERATOR.parse(source, "fixture") == [
        {
            "value": "7",
            "name": "ALG_TEST",
            "status_raw": "deprecated",
            "xrefs": ["rfc:rfc1"],
        }
    ]
    assert GENERATOR.classify("ALG_TEST", "deprecated") == "deprecated"


def test_catalog_digest_validation_fails_closed(tmp_path: Path) -> None:
    """Reject a changed snapshot before parsing it."""
    source = tmp_path / "registry.xml"
    source.write_bytes(b"pinned source")
    expected = hashlib.sha256(b"pinned source").hexdigest()

    assert GENERATOR.verify_input(source, expected) == expected
    with pytest.raises(SystemExit, match="input digest mismatch"):
        GENERATOR.verify_input(source, "0" * 64)


def test_catalog_entry_builder_schedules_numeric_rows(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Build wire-keyed entries while counting non-numeric ranges separately."""
    source = tmp_path / "registry.xml"
    source.write_text(
        '<registry id="fixture"><record><value>7</value><description>ALG_TEST</description>'
        '<xref type="draft" data="draft-test"/></record>'
        "<record><value>8-9</value><description>Unassigned</description></record></registry>",
        encoding="utf-8",
    )
    monkeypatch.setattr(
        GENERATOR,
        "SPEC",
        {("2", "encryption"): ("registry.xml", "fixture", "transform_type=1")},
    )
    monkeypatch.setattr(GENERATOR, "SCHEDULED", {("2", "encryption", 7)})

    entries, skipped = GENERATOR.build_entries(
        {"registry.xml": source},
        {"registry.xml": {"updated": "2026-01-01", "sha256": "abc"}},
    )

    assert skipped == 1
    assert entries == [
        {
            "ike_version": "2",
            "role": "encryption",
            "wire_location": "transform_type=1",
            "wire_id": 7,
            "name": "ALG_TEST",
            "status": "current",
            "citations": ["draft:draft-test"],
            "registry_file": "registry.xml",
            "registry_updated": "2026-01-01",
            "registry_sha256": "abc",
            "scheduled_profile": "scheduled_0_10",
        }
    ]


def test_rfc_parser_keeps_lf_line_numbers_and_first_requirement() -> None:
    """Do not count form feeds as lines or overwrite the first RFC table row."""
    requirements = RFC_AXIS.parse_requirements(
        "page one\x0cpage two\n| ENCR_NULL | MUST NOT |\n| ENCR_NULL | MAY |"
    )

    assert requirements == {"ENCR_NULL": {"requirement": "MUST NOT", "line": 2}}


def test_rfc_digest_validation_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Reject changed RFC text before deriving requirement claims."""
    source = tmp_path / "rfc8247.txt"
    source.write_bytes(b"pinned RFC")
    expected = hashlib.sha256(b"pinned RFC").hexdigest()
    monkeypatch.setattr(RFC_AXIS, "RFC_SHA256", expected)

    RFC_AXIS.verify_rfc(source)
    monkeypatch.setattr(RFC_AXIS, "RFC_SHA256", "0" * 64)
    with pytest.raises(SystemExit, match="input digest mismatch"):
        RFC_AXIS.verify_rfc(source)


def test_rfc_axis_only_matches_ikev2_entries() -> None:
    """Keep IKEv1 out of RFC 8247 while distinguishing unmatched IKEv2 rows."""
    doc = {
        "entries": [
            {"name": "ENCR_NULL", "ike_version": "2"},
            {"name": "ENCR_NULL", "ike_version": "1"},
            {"name": "OTHER", "ike_version": "2"},
        ]
    }

    matched, unmatched = RFC_AXIS.apply_requirements(
        doc, {"ENCR_NULL": {"requirement": "MUST NOT", "line": 296}}
    )

    assert (matched, unmatched) == (1, 2)
    assert doc["entries"][0]["rfc8247_requirement"] == "MUST NOT"
    assert doc["entries"][0]["rfc8247_citation"] == "rfc8247/rfc8247.txt:296"
    assert doc["entries"][1]["rfc8247_requirement"] is None
    assert doc["entries"][2]["rfc8247_requirement"] is None
