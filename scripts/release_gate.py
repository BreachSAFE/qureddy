#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Run the portable, fail-closed QuReddy release gate."""

from __future__ import annotations

import os
import platform
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from release_support import (
    ROOT,
    Gate,
    download_cyclonedx,
    download_tool,
    git_output,
    inspect_archives,
    locked_versions,
    sha256,
    verify_clean_source,
)


def _static_commands(uv: Path, gitleaks: Path, gate: Gate) -> None:
    run = [str(uv), "run", "--locked", "--python", "3.12"]
    gate.run("sync", [str(uv), "sync", "--locked", "--python", "3.12", "--extra", "dev"])
    commands = (
        ("ruff-lint", [*run, "ruff", "check", "."]),
        ("ruff-format", [*run, "ruff", "format", "--check", "."]),
        ("mypy", [*run, "mypy", "src/qureddy", "--strict"]),
        ("tests", [*run, "pytest", "--ignore=tests/live", "--cov=qureddy", "--cov-fail-under=80"]),
        ("file-size", [*run, "python", "scripts/check_size_policy.py"]),
        ("bandit", [*run, "bandit", "-r", "-ll", "src/qureddy", "scripts"]),
        ("deptry", [*run, "deptry", "."]),
        ("reuse", [*run, "reuse", "lint"]),
        (
            "secrets",
            [str(gitleaks), "git", "--no-banner", "--log-opts=HEAD", str(ROOT)],
        ),
    )
    for name, command in commands:
        gate.run(name, command)
    requirements = gate.evidence.parent / "runtime-requirements.txt"
    gate.run(
        "runtime-export",
        [str(uv), "export", "--locked", "--no-dev", "--no-emit-project", "-o", str(requirements)],
    )
    gate.run("pip-audit", [*run, "pip-audit", "-r", str(requirements)])


def _install_smokes(uv: Path, gate: Gate, artifacts: list[Path]) -> tuple[Path, Path]:
    wheel = next(path for path in artifacts if path.suffix == ".whl")
    sdist = next(path for path in artifacts if path.name.endswith(".tar.gz"))
    smoke = gate.evidence.parent / "smoke"
    gate.run("smoke-venv", [str(uv), "venv", "--python", "3.12", str(smoke)])
    python = smoke / ("Scripts/python.exe" if platform.system() == "Windows" else "bin/python")
    console = smoke / ("Scripts/qureddy.exe" if platform.system() == "Windows" else "bin/qureddy")
    gate.run("smoke-install", [str(uv), "pip", "install", "--python", str(python), str(wheel)])
    gate.run("smoke-pip-check", [str(uv), "pip", "check", "--python", str(python)])
    gate.run("smoke-console", [str(console), "--help"])
    gate.run("smoke-version", [str(console), "--version"])
    gate.run("smoke-tls-help", [str(console), "scan", "tls", "--help"])
    gate.run("smoke-ssh-help", [str(console), "scan", "ssh", "--help"])
    gate.run("smoke-usage-error", [str(console), "scan", "tls"], expected_exit=4)
    suffix = ".cmd" if platform.system() == "Windows" else ".sh"
    replay = ROOT / f"tests/conformance/shims/openssl_classical_replay{suffix}"
    gate.run(
        "smoke-tls-scan",
        [str(console), "scan", "tls", "192.0.2.10", "--openssl", str(replay), "--format", "json"],
    )
    gate.run(
        "smoke-ssh-scan",
        [str(console), "scan", "ssh", "127.0.0.1:1", "--format", "json"],
        expected_exit=2,
    )
    sdist_smoke = gate.evidence.parent / "sdist-smoke"
    gate.run("sdist-venv", [str(uv), "venv", "--python", "3.12", str(sdist_smoke)])
    sdist_python = sdist_smoke / (
        "Scripts/python.exe" if platform.system() == "Windows" else "bin/python"
    )
    gate.run(
        "sdist-install", [str(uv), "pip", "install", "--python", str(sdist_python), str(sdist)]
    )
    gate.run("sdist-pip-check", [str(uv), "pip", "check", "--python", str(sdist_python)])
    return python, console


def _build_and_conformance(uv: Path, gate: Gate, tool_cache: Path) -> None:
    run = [str(uv), "run", "--locked", "--python", "3.12"]
    dist = gate.evidence.parent / "dist"
    gate.run("build", [str(uv), "build", "--python", "3.12", "--out-dir", str(dist)])
    artifacts = sorted(
        path for path in dist.iterdir() if path.suffix == ".whl" or path.name.endswith(".tar.gz")
    )
    gate.artifacts = artifacts
    inspect_archives(artifacts)
    gate.run("twine", [*run, "twine", "check", *[str(path) for path in artifacts]])
    python, console = _install_smokes(uv, gate, artifacts)
    versions = locked_versions(gate.versions["source"])
    gate.run(
        "conformance-dependencies",
        [
            str(uv),
            "pip",
            "install",
            "--python",
            str(python),
            f"jsonschema=={versions['jsonschema'].split()[-1]}",
            f"rfc3339-validator=={versions['rfc3339-validator'].split()[-1]}",
        ],
    )
    cyclonedx, asset_key = download_cyclonedx(tool_cache)
    gate.tools.append({"name": "cyclonedx-cli", "version": "0.33.1", "sha256": sha256(cyclonedx)})
    gate.run(
        "cbom-conformance",
        [
            str(python),
            "scripts/run_cbom_conformance.py",
            "--cyclonedx-cli",
            str(cyclonedx),
            "--tool-asset-key",
            asset_key,
            "--qureddy-console",
            str(console),
        ],
    )


def main() -> int:
    """Run every blocking local release check and always write evidence."""
    if sys.version_info[:2] != (3, 12):
        print("release gate requires Python 3.12", file=sys.stderr)
        return 2
    commit = git_output("rev-parse", "HEAD")
    output = ROOT / "dist" / "release-evidence"
    if output.exists():
        shutil.rmtree(output)
    output.mkdir(parents=True)
    error: str | None = None
    with tempfile.TemporaryDirectory(prefix="qureddy-release-gate-") as temporary:
        temporary_root = Path(temporary)
        tools = ROOT / ".cache" / "release-tools"
        tools.mkdir(parents=True, exist_ok=True)
        environment = os.environ.copy()
        environment["UV_PROJECT_ENVIRONMENT"] = str(temporary_root / "project-venv")
        versions = {
            **locked_versions(commit),
            "sync": "uv 0.11.32",
            "build": "uv 0.11.32",
            "smoke-venv": "uv 0.11.32",
            "smoke-install": "uv 0.11.32",
            "runtime-export": "uv 0.11.32",
            "secrets": "gitleaks 8.30.1",
            "cbom-conformance": "cyclonedx-cli 0.33.1",
        }
        gate = Gate(output / "manifest.json", environment, versions)
        try:
            verify_clean_source()
            gate.clean_worktree = True
            uv = download_tool("uv", tools)
            gitleaks = download_tool("gitleaks", tools)
            gate.tools.extend(
                [
                    {"name": "uv", "version": "0.11.32", "sha256": sha256(uv)},
                    {"name": "gitleaks", "version": "8.30.1", "sha256": sha256(gitleaks)},
                ]
            )
            _static_commands(uv, gitleaks, gate)
            _build_and_conformance(uv, gate, tools)
        except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
            error = str(exc)
        gate.write(commit, "pass" if error is None else "fail", error)
    if error:
        print(error, file=sys.stderr)
        return 1
    print(f"release gate PASS; evidence: {gate.evidence}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
