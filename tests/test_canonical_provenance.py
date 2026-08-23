# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Regression tests for the canonical QuReddy provenance gate."""

from __future__ import annotations

from pathlib import Path

import scripts.verify_canonical_provenance as provenance


def test_forbidden_references_reports_legacy_repository(monkeypatch, tmp_path: Path) -> None:
    """A legacy source reference must fail even when it appears in documentation."""
    candidate = tmp_path / "candidate.md"
    candidate.write_text("https://github.com/" + "paul007ex" + "/qureddy\n", encoding="utf-8")
    monkeypatch.setattr(provenance, "tracked_files", lambda _root: [candidate])

    assert provenance.forbidden_references(tmp_path) == ["candidate.md"]


def test_sibling_product_reference_is_not_treated_as_legacy_repository(
    monkeypatch, tmp_path: Path
) -> None:
    """The UX image name shares a prefix but is a different product/repository."""
    candidate = tmp_path / "candidate.md"
    candidate.write_text(
        "ghcr.io/paul007ex/qureddy-ux:latest\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(provenance, "tracked_files", lambda _root: [candidate])

    assert provenance.forbidden_references(tmp_path) == []


def test_main_rejects_wrong_github_actions_repository(monkeypatch) -> None:
    """Release and CI jobs cannot claim the canonical guard from another repository."""
    monkeypatch.setenv("GITHUB_REPOSITORY", "example/incorrect")

    assert provenance.main() == 1


def test_main_accepts_canonical_repository_case_insensitively(monkeypatch) -> None:
    """GITHUB_REPOSITORY preserves the org's display casing (BreachSAFE/qureddy); the
    guard must accept it, else every CI run and the release job fail on the canonical
    repo (the case bug that broke the v0.2.18 release)."""
    monkeypatch.setenv("GITHUB_REPOSITORY", "BreachSAFE/qureddy")
    monkeypatch.setattr(provenance, "tracked_files", lambda _root: [])

    assert provenance.main() == 0
