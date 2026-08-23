# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Fail-closed contracts for the repository-owned release gate."""

from __future__ import annotations

import importlib.util
import json
import re
import subprocess
import sys
import tarfile
import tomllib
import zipfile
from io import BytesIO
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


release_support = _load_script("release_support")
release_gate = _load_script("release_gate")
size_policy = _load_script("check_size_policy")
STATIC_GATES = (
    "sync",
    "ruff-lint",
    "ruff-format",
    "mypy",
    "tests",
    "file-size",
    "bandit",
    "pip-audit",
    "deptry",
    "reuse",
    "secrets",
    "runtime-export",
    "pip-audit",
)
BUILD_GATES = (
    "build",
    "twine",
    "smoke-venv",
    "smoke-install",
    "smoke-pip-check",
    "smoke-console",
    "smoke-version",
    "smoke-tls-help",
    "smoke-ssh-help",
    "smoke-usage-error",
    "smoke-tls-scan",
    "smoke-ssh-scan",
    "sdist-venv",
    "sdist-install",
    "sdist-pip-check",
    "conformance-dependencies",
    "cbom-conformance",
)
CRITICAL_GATES = (*STATIC_GATES, *BUILD_GATES)


def test_dirty_worktree_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(release_support, "git_output", lambda *args: " M pyproject.toml")
    with pytest.raises(RuntimeError, match="clean Git worktree"):
        release_support.verify_clean_source()


@pytest.mark.parametrize("gate_name", CRITICAL_GATES)
def test_each_critical_command_fails_closed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, gate_name: str
) -> None:
    completed = subprocess.CompletedProcess(["false"], 9, "", "controlled failure")
    monkeypatch.setattr(release_support.subprocess, "run", lambda *args, **kwargs: completed)
    gate = release_support.Gate(tmp_path / "evidence.json", {}, {"source": "abc"})
    with pytest.raises(RuntimeError, match="got 9"):
        gate.run(gate_name, ["false"])
    assert gate.commands[0]["exit_code"] == 9


@pytest.mark.parametrize("gate_name", CRITICAL_GATES)
def test_actual_orchestrator_fails_closed_at_each_gate(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, gate_name: str
) -> None:
    def succeed(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        expected = (
            4
            if command[-2:] == ["scan", "tls"]
            else 2
            if "scan" in command and "ssh" in command and "--format" in command
            else 0
        )
        return subprocess.CompletedProcess(command, expected, "", "")

    evidence = tmp_path / "evidence" / "manifest.json"
    evidence.parent.mkdir()
    dist = evidence.parent / "dist"
    dist.mkdir()
    (dist / "candidate.whl").touch()
    (dist / "candidate.tar.gz").touch()
    cyclonedx = tmp_path / "cyclonedx"
    cyclonedx.write_bytes(b"pinned test executable")
    monkeypatch.setattr(release_support.subprocess, "run", succeed)
    monkeypatch.setattr(release_gate, "inspect_archives", lambda _artifacts: None)
    monkeypatch.setattr(
        release_gate,
        "download_cyclonedx",
        lambda _cache: (cyclonedx, "linux-x64"),
    )
    gate = release_support.Gate(
        evidence,
        {release_support.FAILURE_INJECTION_ENV: gate_name},
        release_support.locked_versions("abc"),
    )

    def run_orchestrator() -> None:
        if gate_name in STATIC_GATES:
            release_gate._static_commands(  # noqa: SLF001
                tmp_path / "uv", tmp_path / "gitleaks", gate
            )
        else:
            release_gate._build_and_conformance(  # noqa: SLF001
                tmp_path / "uv", gate, tmp_path / "tools"
            )

    with pytest.raises(RuntimeError, match=f"{gate_name} failed: injected"):
        run_orchestrator()
    assert gate.commands[-1]["name"] == gate_name
    assert gate.commands[-1]["status"] == "fail"
    assert gate.commands[-1]["exit_code"] == 97


def test_timeout_is_recorded_and_raised(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    def time_out(*args: object, **kwargs: object) -> None:
        raise subprocess.TimeoutExpired(["slow"], 3)

    monkeypatch.setattr(release_support.subprocess, "run", time_out)
    gate = release_support.Gate(tmp_path / "evidence.json", {}, {"source": "abc"})
    with pytest.raises(RuntimeError, match="timed out"):
        gate.run("controlled", ["slow"], timeout=3)
    assert gate.commands[0]["status"] == "timeout"
    assert gate.commands[0]["duration_seconds"] >= 0


def test_failed_outcome_manifest_is_machine_readable(tmp_path: Path) -> None:
    evidence = tmp_path / "manifest.json"
    gate = release_support.Gate(evidence, {}, {"source": "abc"})
    gate.write("abc", "fail", "controlled failure")
    payload = json.loads(evidence.read_text(encoding="utf-8"))
    assert payload["outcome"] == "fail"
    assert payload["error"] == "controlled failure"
    assert payload["platform"]
    assert payload["python"]
    assert payload["ended_at"]
    assert payload["duration_seconds"] >= 0


def test_failed_manifest_retains_built_artifact_digest(tmp_path: Path) -> None:
    evidence = tmp_path / "manifest.json"
    artifact = tmp_path / "candidate.whl"
    artifact.write_bytes(b"built-once")
    gate = release_support.Gate(evidence, {}, {"source": "abc"})
    gate.artifacts = [artifact]
    gate.write("abc", "fail", "post-build conformance failed")
    payload = json.loads(evidence.read_text(encoding="utf-8"))
    assert payload["artifacts"][0]["sha256"] == release_support.sha256(artifact)


def test_archive_inspection_rejects_internal_content(tmp_path: Path) -> None:
    wheel = tmp_path / "candidate.whl"
    sdist = tmp_path / "candidate.tar.gz"
    with zipfile.ZipFile(wheel, "w") as bundle:
        bundle.writestr(".github/workflows/publish.yml", "secret")
    with tarfile.open(sdist, "w:gz"):
        pass
    with pytest.raises(RuntimeError, match="forbidden internal content"):
        release_support.inspect_archives([wheel, sdist])


def test_archive_inspection_rejects_tests_in_sdist(tmp_path: Path) -> None:
    wheel = tmp_path / "candidate.whl"
    sdist = tmp_path / "candidate.tar.gz"
    with zipfile.ZipFile(wheel, "w") as bundle:
        bundle.writestr("qureddy/__init__.py", "__version__ = '0.2.0'\n")
    with tarfile.open(sdist, "w:gz") as bundle:
        root = "breachsafe-qureddy-0.2.0"
        info = tarfile.TarInfo(f"{root}/tests/test_public.py")
        info.size = 0
        bundle.addfile(info)
    with pytest.raises(RuntimeError, match="unexpected sdist content"):
        release_support.inspect_archives([wheel, sdist])


def test_archive_inspection_rejects_incomplete_build(tmp_path: Path) -> None:
    wheel = tmp_path / "candidate.whl"
    wheel.touch()
    with pytest.raises(RuntimeError, match="exactly one wheel and one sdist"):
        release_support.inspect_archives([wheel])


def test_archive_inspection_rejects_version_mismatch(tmp_path: Path) -> None:
    wheel = tmp_path / "breachsafe_qureddy-0.2.49-py3-none-any.whl"
    sdist = tmp_path / "breachsafe-qureddy-0.2.49.tar.gz"
    with zipfile.ZipFile(wheel, "w") as bundle:
        bundle.writestr("qureddy/__init__.py", "__version__ = '0.2.49'\n")
    with tarfile.open(sdist, "w:gz") as bundle:
        root = "breachsafe-qureddy-0.2.49"
        for name in ("PKG-INFO",):
            info = tarfile.TarInfo(f"{root}/{name}")
            info.size = 0
            bundle.addfile(info)
    with pytest.raises(RuntimeError, match="artifact version mismatch"):
        release_support.inspect_archives([wheel, sdist])


def test_release_metadata_matches_source() -> None:
    version = release_support.verify_release_metadata()
    assert version == release_support.source_version()


def test_size_policy_rejects_oversized_file(tmp_path: Path) -> None:
    source = tmp_path / "src" / "qureddy"
    source.mkdir(parents=True)
    lines = ["def oversized():", *["    value = 1" for _ in range(51)], "    return value"]
    (source / "oversized.py").write_text("\n".join(lines + ["# padding"] * 350), encoding="utf-8")
    failures = size_policy.violations(source)
    assert any("lines exceeds 400" in failure for failure in failures)


def test_tool_download_rejects_checksum_mismatch(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    manifest = tmp_path / "tools.json"
    manifest.write_text(
        json.dumps(
            {
                "uv": {
                    "version": "0.11.32",
                    "assets": {"linux-x64": ["uv.tar.gz", "0" * 64]},
                }
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(release_support, "TOOLS_MANIFEST", manifest)
    monkeypatch.setattr(release_support, "platform_key", lambda: "linux-x64")
    monkeypatch.setattr(
        release_support.urllib.request, "urlopen", lambda *args, **kwargs: BytesIO(b"tampered")
    )
    with pytest.raises(RuntimeError, match="checksum mismatch"):
        release_support.download_tool("uv", tmp_path / "download")


def test_tool_cache_reextracts_verified_archive(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    cache = tmp_path / "cache"
    cache.mkdir()
    archive = cache / "uv.tar.gz"
    payload = b"verified executable"
    with tarfile.open(archive, "w:gz") as bundle:
        member = tarfile.TarInfo("uv-release/uv")
        member.size = len(payload)
        bundle.addfile(member, BytesIO(payload))
    manifest = tmp_path / "tools.json"
    manifest.write_text(
        json.dumps(
            {
                "uv": {
                    "version": "0.11.32",
                    "assets": {
                        "linux-x64": [archive.name, release_support.sha256(archive)],
                    },
                }
            }
        ),
        encoding="utf-8",
    )
    stale = cache / "uv" / "uv"
    stale.parent.mkdir()
    stale.write_bytes(b"tampered cached executable")
    monkeypatch.setattr(release_support, "TOOLS_MANIFEST", manifest)
    monkeypatch.setattr(release_support, "platform_key", lambda: "linux-x64")
    monkeypatch.setattr(release_support.platform, "system", lambda: "Linux")

    executable = release_support.download_tool("uv", cache)

    assert executable.read_bytes() == payload
    assert not (cache / ".uv-fresh").exists()


def test_gitleaks_false_positive_classification_is_exactly_scoped() -> None:
    config_path = Path(__file__).parents[1] / ".gitleaks.toml"
    config = tomllib.loads(config_path.read_text(encoding="utf-8"))
    key_label = "Key:"
    fixture_line_regex = rf"^\s*-\s*`Server Temp {key_label} X25519MLKEM768`\s*$"
    assert config["extend"] == {"useDefault": True}
    assert config["allowlists"] == [
        {
            "description": "OpenSSL X25519MLKEM768 parser fixture in an archived prompt",
            "targetRules": ["generic-api-key"],
            "condition": "AND",
            "commits": ["72f3fa4d750a393460ac40348e71f4b6c717bbce"],
            "paths": [r"^docs/mvp/MVP-0\.1-[Cc][Ll][Aa][Uu][Dd][Ee]-PROMPT\.md$"],
            "regexTarget": "line",
            "regexes": [fixture_line_regex],
        }
    ]


def test_all_github_actions_are_commit_pinned() -> None:
    github_root = Path(__file__).parents[1] / ".github"
    unpinned = []
    for workflow in sorted(github_root.rglob("*.yml")):
        for line_number, line in enumerate(workflow.read_text(encoding="utf-8").splitlines(), 1):
            if "uses:" not in line or "uses: ./" in line:
                continue
            if re.search(r"uses:\s+[^@\s]+@[0-9a-f]{40}(?:\s+#\s+\S+)?$", line) is None:
                unpinned.append(f"{workflow.name}:{line_number}: {line.strip()}")
    assert unpinned == []
