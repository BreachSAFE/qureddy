# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Conformance matrix for pinned CycloneDX fixture bytes."""

from __future__ import annotations

import json

import pytest

from tests.conformance.harness import (
    FIXTURE_DIR,
    load_manifest,
    official_errors,
    semantic_errors,
    sha256,
    verify_schema_assets,
)


def _cases(kind: str) -> list[pytest.param]:
    fixtures = load_manifest()["fixtures"]
    return [
        pytest.param(name, details, id=name)
        for name, details in fixtures.items()
        if details["kind"] == kind
    ]


def _load(name: str, details: dict[str, object]) -> dict[str, object]:
    path = FIXTURE_DIR / str(details["kind"]) / f"{name}.cbom.json"
    assert sha256(path) == details["sha256"]
    return json.loads(path.read_text(encoding="utf-8"))


def test_vendored_schema_hashes_match_pinned_manifest() -> None:
    verify_schema_assets()


@pytest.mark.parametrize(("name", "details"), _cases("positive"))
def test_positive_fixture_passes_official_and_semantic_gates(
    name: str, details: dict[str, object]
) -> None:
    payload = _load(name, details)

    assert official_errors(payload) == []
    assert semantic_errors(payload) == []


@pytest.mark.parametrize(("name", "details"), _cases("negative"))
def test_negative_fixture_detection_matrix(name: str, details: dict[str, object]) -> None:
    payload = _load(name, details)

    assert bool(official_errors(payload)) is details["official_rejects"]
    assert bool(semantic_errors(payload)) is details["semantic_rejects"]


@pytest.mark.parametrize(("name", "details"), _cases("positive") + _cases("negative"))
def test_fixture_has_explicit_provenance(name: str, details: dict[str, object]) -> None:
    path = FIXTURE_DIR / str(details["kind"]) / f"{name}.provenance.txt"
    text = path.read_text(encoding="utf-8")

    assert f"fixture: {name}" in text
    assert f"classification: {details['classification']}" in text
    assert "sha256:" in text
