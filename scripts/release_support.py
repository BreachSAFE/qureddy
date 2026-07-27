# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Fail-closed evidence, tool, source-policy, and archive support."""

from __future__ import annotations

import hashlib
import json
import platform
import shutil
import subprocess
import tarfile
import tomllib
import urllib.request
import zipfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]
TOOLS_MANIFEST = ROOT / "scripts" / "release-tools.json"
COMMAND_TIMEOUT = 600
DOWNLOAD_TIMEOUT = 120
EXPECTED_ARTIFACT_COUNT = 2
FAILURE_INJECTION_ENV = "QUREDDY_RELEASE_GATE_TEST_FAIL"


def sha256(path: Path) -> str:
    """Return a file's lowercase SHA-256 digest."""
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def platform_key() -> str:
    """Return the release manifest key for this supported platform."""
    systems = {"Darwin": "macos", "Linux": "linux", "Windows": "windows"}
    machines = {"x86_64": "x64", "AMD64": "x64", "arm64": "arm64", "aarch64": "arm64"}
    try:
        return f"{systems[platform.system()]}-{machines[platform.machine()]}"
    except KeyError as exc:
        raise RuntimeError(f"unsupported release-gate platform: {platform.platform()}") from exc


def _download_https(url: str, destination: Path) -> None:
    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.hostname != "github.com":
        raise RuntimeError(f"release tool URL is not approved: {url}")
    with urllib.request.urlopen(  # noqa: S310  # nosec B310 - restricted HTTPS host.
        url, timeout=DOWNLOAD_TIMEOUT
    ) as response:
        destination.write_bytes(response.read())


def download_tool(name: str, directory: Path) -> Path:
    """Download, checksum, freshly extract, and return a pinned tool.

    The archive is the cache authority because its digest is pinned in the
    repository. Never trust an executable left in the extraction directory:
    re-extract from the rehashed archive on every run, validate the shape, and
    only then replace the prior extraction.
    """
    directory.mkdir(parents=True, exist_ok=True)
    manifest = json.loads(TOOLS_MANIFEST.read_text(encoding="utf-8"))[name]
    key = platform_key()
    asset = manifest["assets"].get(key)
    if asset is None:
        raise RuntimeError(f"{name} does not support release-gate platform {key}")
    filename, expected = asset
    repository = "astral-sh/uv" if name == "uv" else "gitleaks/gitleaks"
    tag = manifest["version"] if name == "uv" else f"v{manifest['version']}"
    archive = directory / filename
    if not archive.exists():
        _download_https(
            f"https://github.com/{repository}/releases/download/{tag}/{filename}", archive
        )
    actual = sha256(archive)
    if actual != expected:
        raise RuntimeError(f"{name} checksum mismatch: expected {expected}, got {actual}")
    unpacked = directory / name
    fresh = directory / f".{name}-fresh"
    if fresh.exists():
        shutil.rmtree(fresh)
    fresh.mkdir()
    _extract_archive(name, archive, fresh)
    executable = f"{name}.exe" if platform.system() == "Windows" else name
    matches = list(fresh.rglob(executable))
    if len(matches) != 1:
        shutil.rmtree(fresh)
        raise RuntimeError(f"{name} archive did not contain exactly one executable")
    matches[0].chmod(0o755)
    relative_executable = matches[0].relative_to(fresh)
    if unpacked.exists():
        shutil.rmtree(unpacked)
    fresh.replace(unpacked)
    return unpacked / relative_executable


def _extract_archive(name: str, archive: Path, destination: Path) -> None:
    if archive.suffix == ".zip":
        with zipfile.ZipFile(archive) as bundle:
            if any(
                Path(member).is_absolute() or ".." in Path(member).parts
                for member in bundle.namelist()
            ):
                raise RuntimeError(f"{name} archive contains an unsafe path")
            for member in bundle.infolist():
                target = destination / member.filename
                if member.is_dir():
                    target.mkdir(parents=True, exist_ok=True)
                else:
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with bundle.open(member) as source, target.open("wb") as output:
                        shutil.copyfileobj(source, output)
    else:
        with tarfile.open(archive) as bundle:
            bundle.extractall(destination, filter="data")


def download_cyclonedx(directory: Path) -> tuple[Path, str]:
    """Download and checksum the platform's pinned CycloneDX CLI."""
    path = ROOT / "tests/conformance/cyclonedx-cli-v0.33.1.json"
    manifest = json.loads(path.read_text(encoding="utf-8"))
    key = platform_key().replace("macos-", "osx-")
    asset = manifest["assets"].get(key)
    if asset is None:
        raise RuntimeError(f"CycloneDX CLI does not support release-gate platform {key}")
    executable = directory / asset["filename"]
    if not executable.exists():
        directory.mkdir(parents=True, exist_ok=True)
        _download_https(asset["url"], executable)
    actual = sha256(executable)
    if actual != asset["sha256"]:
        raise RuntimeError(
            f"CycloneDX CLI checksum mismatch: expected {asset['sha256']}, got {actual}"
        )
    executable.chmod(0o755)
    return executable, key


class Gate:
    """Record commands, tools, artifacts, failures, and timeouts."""

    def __init__(
        self, evidence: Path, environment: dict[str, str], versions: dict[str, str]
    ) -> None:
        """Initialize an evidence recorder."""
        self.evidence = evidence
        self.environment = environment
        self.versions = versions
        self.commands: list[dict[str, Any]] = []
        self.artifacts: list[Path] = []
        self.tools: list[dict[str, str]] = []
        self.started_at = datetime.now(UTC)
        self.clean_worktree = False

    def run(
        self, name: str, command: list[str], timeout: int = COMMAND_TIMEOUT, expected_exit: int = 0
    ) -> None:
        """Run and record one blocking command."""
        started = datetime.now(UTC)
        if self.environment.get(FAILURE_INJECTION_ENV) == name:
            record = self._record(name, command, started, 97, "fail")
            record["stdout_sha256"] = hashlib.sha256(b"").hexdigest()
            record["stderr_sha256"] = hashlib.sha256(b"injected failure").hexdigest()
            record["duration_seconds"] = (datetime.now(UTC) - started).total_seconds()
            self.commands.append(record)
            raise RuntimeError(f"{name} failed: injected release-gate test failure")
        try:
            completed = subprocess.run(  # noqa: S603 - fixed repository gate definitions.
                command,
                cwd=ROOT,
                env=self.environment,
                check=False,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired as exc:
            record = self._record(name, command, started, None, "timeout")
            record["duration_seconds"] = (datetime.now(UTC) - started).total_seconds()
            self.commands.append(record)
            raise RuntimeError(f"{name} timed out after {timeout} seconds") from exc
        status = "pass" if completed.returncode == expected_exit else "fail"
        record = self._record(name, command, started, completed.returncode, status)
        record["stdout_sha256"] = hashlib.sha256(completed.stdout.encode()).hexdigest()
        record["stderr_sha256"] = hashlib.sha256(completed.stderr.encode()).hexdigest()
        record["duration_seconds"] = (datetime.now(UTC) - started).total_seconds()
        self.commands.append(record)
        if status == "fail":
            raise RuntimeError(
                f"{name} failed: expected exit {expected_exit}, got {completed.returncode}"
            )

    def _record(
        self, name: str, command: list[str], started: datetime, exit_code: int | None, status: str
    ) -> dict[str, Any]:
        return {
            "name": name,
            "command": command,
            "version": self.versions.get(name, self.versions["source"]),
            "started_at": started.isoformat(),
            "exit_code": exit_code,
            "status": status,
        }

    def write(self, commit: str, outcome: str, error: str | None) -> None:
        """Atomically write redacted evidence, retaining built artifact digests."""
        ended_at = datetime.now(UTC)
        payload = {
            "schema": "qureddy.release-evidence.v1",
            "source_commit": commit,
            "platform": platform.platform(),
            "python": platform.python_version(),
            "clean_worktree": self.clean_worktree,
            "started_at": self.started_at.isoformat(),
            "ended_at": ended_at.isoformat(),
            "duration_seconds": (ended_at - self.started_at).total_seconds(),
            "outcome": outcome,
            "error": error,
            "commands": self.commands,
            "tools": self.tools,
            "artifacts": [
                {"path": path.name, "sha256": sha256(path), "size": path.stat().st_size}
                for path in self.artifacts
                if path.exists()
            ],
        }
        temporary = self.evidence.with_suffix(".tmp")
        temporary.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        temporary.replace(self.evidence)


def git_output(*args: str) -> str:
    """Run a bounded Git inspection command."""
    git = shutil.which("git")
    if git is None:
        raise RuntimeError("git executable is required")
    completed = subprocess.run(  # noqa: S603 - resolved Git and fixed arguments.
        [git, *args], cwd=ROOT, check=True, capture_output=True, text=True, timeout=30
    )
    return completed.stdout.strip()


def verify_clean_source() -> str:
    """Fail unless the source worktree is clean, then return its commit."""
    if git_output("status", "--porcelain"):
        raise RuntimeError("release gate requires a clean Git worktree")
    return git_output("rev-parse", "HEAD")


def locked_versions(commit: str) -> dict[str, str]:
    """Return evidence versions for locked Python tools."""
    packages = {
        item["name"]: item["version"]
        for item in tomllib.loads((ROOT / "uv.lock").read_text(encoding="utf-8"))["package"]
    }
    mapping = {
        "ruff-lint": "ruff",
        "ruff-format": "ruff",
        "mypy": "mypy",
        "tests": "pytest",
        "bandit": "bandit",
        "pip-audit": "pip-audit",
        "deptry": "deptry",
        "reuse": "reuse",
        "jsonschema": "jsonschema",
        "rfc3339-validator": "rfc3339-validator",
        "twine": "twine",
    }
    versions = {gate: f"{package} {packages[package]}" for gate, package in mapping.items()}
    return {"source": commit, "file-size": commit, **versions}


def inspect_archives(artifacts: list[Path]) -> None:
    """Enforce an allowlist over exactly one wheel and one sdist."""
    wheels = [path for path in artifacts if path.suffix == ".whl"]
    sdists = [path for path in artifacts if path.name.endswith(".tar.gz")]
    if len(artifacts) != EXPECTED_ARTIFACT_COUNT or len(wheels) != 1 or len(sdists) != 1:
        raise RuntimeError("build must produce exactly one wheel and one sdist")
    forbidden = (".claude/", ".agents/", ".github/", "scratch/", ".git/")
    allowed_files = {
        ".gitignore",
        "CHANGELOG.md",
        "CODE_OF_CONDUCT.md",
        "CONTRIBUTING.md",
        "LICENSE",
        "README.md",
        "REUSE.toml",
        "SECURITY.md",
        "pyproject.toml",
        "PKG-INFO",
    }
    for artifact in artifacts:
        if artifact.suffix == ".whl":
            with zipfile.ZipFile(artifact) as bundle:
                names = bundle.namelist()
        else:
            with tarfile.open(artifact) as bundle:
                names = bundle.getnames()
        if any(part in name for name in names for part in forbidden):
            raise RuntimeError(f"forbidden internal content in {artifact.name}")
        if any(name.startswith("/") or ".." in name.split("/") for name in names):
            raise RuntimeError(f"unsafe archive path in {artifact.name}")
        if artifact.suffix == ".whl" and any(
            not (name.startswith("qureddy/") or ".dist-info/" in name) for name in names
        ):
            raise RuntimeError(f"unexpected wheel content in {artifact.name}")
        if artifact.name.endswith(".tar.gz"):
            inner = [name.split("/", 1)[1] for name in names if "/" in name]
            if any(
                name not in allowed_files
                and not name.startswith(("src/qureddy/", "LICENSES/"))
                for name in inner
            ):
                raise RuntimeError(f"unexpected sdist content in {artifact.name}")
