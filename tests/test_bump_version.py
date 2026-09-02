# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Self-tests for the single-source version bump tool.

Every version-bearing single-source that ``scripts/bump_version.py`` owns is
exercised here against an isolated fixture repository. General documentation
is deliberately version-agnostic; release metadata, container metadata, the
lockfile, and golden output contracts remain checked.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType

import pytest


def _load_script(name: str) -> ModuleType:
    path = Path(__file__).parents[1] / "scripts" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


bump_version = _load_script("bump_version")


def _write_repo(root: Path, version: str) -> None:
    """Materialise a fully consistent fixture repo at ``version``."""
    golden = root / "tests" / "golden"
    golden.mkdir(parents=True, exist_ok=True)

    (root / "pyproject.toml").write_text(
        f'[project]\nname = "breachsafe-qureddy"\nversion = "{version}"\n'
    )
    (root / "README.md").write_text(
        "# QuReddy\n\n"
        f"[![Version](https://img.shields.io/badge/version-{version}-blue?style=flat-square)]"
        "(CHANGELOG.md)\n"
    )
    (root / "CHANGELOG.md").write_text(
        "# Changelog\n\n"
        f"[![Version](https://img.shields.io/badge/version-{version}-blue?style=flat-square)]"
        "(CHANGELOG.md)\n\n"
        "## [Unreleased]\n\n"
        f"## [{version}] - 2026-01-02\n\n### Added\n\n- initial\n\n"
        "## Contents\n\n"
        f"1. [{version}](#{version.replace('.', '')}---2026-01-02)\n"
    )
    (root / "Dockerfile").write_text(
        f'FROM python:3.12\nARG QUREDDY_VERSION={version}\nLABEL x="y"\n'
    )
    workflows = root / ".github" / "workflows"
    workflows.mkdir(parents=True, exist_ok=True)
    (workflows / "container.yml").write_text(
        "on:\n"
        "  workflow_dispatch:\n"
        "    inputs:\n"
        "      version:\n"
        "        description: Image version to publish\n"
        "        required: true\n"
        f"        default: {version}\n"
    )
    (root / "uv.lock").write_text(
        "[[package]]\n"
        f'name = "breachsafe-qureddy"\nversion = "{version}"\nsource = {{ editable = "." }}\n'
    )
    reference = root / "docs" / "reference"
    reference.mkdir(parents=True, exist_ok=True)
    (reference / "cli.md").write_text(
        "# CLI reference\n\n"
        f"This page records the installed `qureddy {version}` command surface.\n\n"
        "```text\n"
        f"BreachSAFE QuReddy {version} -- https://www.breachsafe.io\n"
        "```\n"
    )
    (root / "docs" / "BADGE.md").write_text(
        f'| `version_unique` | Met | `pyproject.toml` `version = "{version}"`; each release bumps it. |\n'
        f"| `version_tags` | Met | Releases are tagged `vX.Y.Z` (e.g. `v{version}`). |\n"
    )
    (reference / "json-schema.md").write_text(
        "| `scanner_version` | string | Installed QuReddy version |\n\n"
        f'    "scanner_version": "{version}",\n'
    )
    (golden / "rich.golden").write_text(f"QuReddy {version} by BreachSAFE\n version  {version}\n")
    (golden / "json.golden").write_text(f'{{"scanner_version": "{version}"}}\n')
    (golden / "cbom.golden").write_text(
        f'{{"name": "qureddy", "type": "application", "version": "{version}"}}\n'
    )


@pytest.fixture
def repo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Point the module's single-source paths at an isolated fixture repo."""
    _write_repo(tmp_path, "0.0.1")
    monkeypatch.setattr(bump_version, "PYPROJECT", tmp_path / "pyproject.toml")
    monkeypatch.setattr(bump_version, "README", tmp_path / "README.md")
    monkeypatch.setattr(bump_version, "CHANGELOG", tmp_path / "CHANGELOG.md")
    monkeypatch.setattr(bump_version, "DOCKERFILE", tmp_path / "Dockerfile")
    monkeypatch.setattr(
        bump_version, "CONTAINER_WORKFLOW", tmp_path / ".github" / "workflows" / "container.yml"
    )
    monkeypatch.setattr(bump_version, "UVLOCK", tmp_path / "uv.lock")
    monkeypatch.setattr(bump_version, "GOLDEN", tmp_path / "tests" / "golden")
    # ``_simple_targets()`` is rebuilt from the path globals above on each call,
    # so patching those alone retargets the tool at this fixture repository.
    return tmp_path


def test_check_passes_when_consistent(repo: Path) -> None:
    assert bump_version.check() == 0


def test_bump_propagates_to_every_stampable_source(repo: Path) -> None:
    assert bump_version.bump("1.2.3") == 0

    assert 'version = "1.2.3"' in (repo / "pyproject.toml").read_text()
    assert "badge/version-0.0.1-blue" in (repo / "README.md").read_text()
    assert "badge/version-0.0.1-blue" in (repo / "CHANGELOG.md").read_text()
    assert "ARG QUREDDY_VERSION=1.2.3" in (repo / "Dockerfile").read_text()
    assert "default: 1.2.3" in (repo / ".github/workflows/container.yml").read_text()
    assert 'version = "1.2.3"' in (repo / "uv.lock").read_text()

    golden = repo / "tests" / "golden"
    assert "QuReddy 1.2.3 by" in (golden / "rich.golden").read_text()
    assert '"scanner_version": "1.2.3"' in (golden / "json.golden").read_text()
    assert '"version": "1.2.3"' in (golden / "cbom.golden").read_text()

    # No stale 0.0.1 left in any stampable file.
    for name in ("pyproject.toml", "Dockerfile", ".github/workflows/container.yml", "uv.lock"):
        assert "0.0.1" not in (repo / name).read_text()


def test_bump_accepts_four_segment_release(repo: Path) -> None:
    """PEP 440 four-segment releases propagate through machine-readable artifacts."""
    assert bump_version.bump("0.9.0.0") == 0
    assert 'version = "0.9.0.0"' in (repo / "pyproject.toml").read_text()
    assert "ARG QUREDDY_VERSION=0.9.0.0" in (repo / "Dockerfile").read_text()
    assert 'version = "0.9.0.0"' in (repo / "uv.lock").read_text()
    assert '"scanner_version": "0.9.0.0"' in (repo / "tests/golden/json.golden").read_text()


def test_bump_stamps_dockerfile_arg(repo: Path) -> None:
    """The Dockerfile ARG default (OCI image.version + wheel selector) is stamped."""
    original = (repo / "Dockerfile").read_text()
    assert "ARG QUREDDY_VERSION=0.0.1" in original

    bump_version.bump("2.0.0")

    updated = (repo / "Dockerfile").read_text()
    assert "ARG QUREDDY_VERSION=2.0.0" in updated
    assert "ARG QUREDDY_VERSION=0.0.1" not in updated


def test_check_detects_dockerfile_drift(repo: Path, capsys: pytest.CaptureFixture[str]) -> None:
    (repo / "Dockerfile").write_text("FROM python:3.12\nARG QUREDDY_VERSION=0.0.0\n")
    assert bump_version.check() == 1
    assert "Dockerfile" in capsys.readouterr().err


def test_check_detects_uvlock_drift(repo: Path, capsys: pytest.CaptureFixture[str]) -> None:
    (repo / "uv.lock").write_text('name = "breachsafe-qureddy"\nversion = "9.9.9"\n')
    assert bump_version.check() == 1
    assert "uv.lock" in capsys.readouterr().err


def test_check_detects_container_workflow_drift(
    repo: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    workflow = repo / ".github/workflows/container.yml"
    workflow.write_text(workflow.read_text().replace("default: 0.0.1", "default: 9.9.9"))
    assert bump_version.check() == 1
    assert "container.yml" in capsys.readouterr().err


def test_check_detects_missing_changelog_heading(
    repo: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # Bump the source of truth but leave the CHANGELOG un-authored for it.
    bump_version.bump("3.0.0")
    assert bump_version.check() == 1
    err = capsys.readouterr().err
    assert "CHANGELOG.md" in err
    assert "3.0.0" in err


def test_help_prints_usage_and_exits_zero(repo: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert bump_version.main(["bump_version.py", "--help"]) == 0
    assert "Single-source version bump" in capsys.readouterr().out


def test_rejects_non_semver(repo: Path) -> None:
    with pytest.raises(SystemExit):
        bump_version.bump("not-a-version")
