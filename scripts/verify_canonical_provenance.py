#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Reject noncanonical QuReddy provenance in tracked repository content."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

CANONICAL_REPOSITORY = "breachsafe/qureddy"
FORBIDDEN_REPOSITORY = "paul007ex" + "/qureddy"
# Match the legacy repository identity at a URL/reference boundary. Do not
# reject sibling products such as paul007ex/qureddy-ux.
FORBIDDEN_REPOSITORY_PATTERN = re.compile(re.escape(FORBIDDEN_REPOSITORY) + r"(?:[/:?#\s\"'`]|$)")


def tracked_files(repository_root: Path) -> list[Path]:
    """Return every tracked file without accidentally scanning build output."""
    git = shutil.which("git")
    if git is None:
        raise RuntimeError("git is required to verify repository provenance")
    result = subprocess.run(  # noqa: S603 -- fixed, shell-free arguments
        [git, "ls-files", "-z"],
        cwd=repository_root,
        check=True,
        capture_output=True,
    )
    return [repository_root / name for name in result.stdout.decode().split("\0") if name]


def forbidden_references(repository_root: Path) -> list[str]:
    """Return stable locations that contain the forbidden repository identity."""
    failures: list[str] = []
    for path in tracked_files(repository_root):
        try:
            content = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        if FORBIDDEN_REPOSITORY_PATTERN.search(content):
            failures.append(str(path.relative_to(repository_root)))
    return failures


def main() -> int:
    """Enforce canonical source identity locally and in GitHub Actions."""
    repository_root = Path(__file__).resolve().parents[1]
    github_repository = os.environ.get("GITHUB_REPOSITORY")
    if github_repository and github_repository.lower() != CANONICAL_REPOSITORY:
        print(
            "Canonical provenance failed: "
            f"GitHub Actions repository is {github_repository!r}, expected {CANONICAL_REPOSITORY!r}.",
            file=sys.stderr,
        )
        return 1

    failures = forbidden_references(repository_root)
    if failures:
        print(
            "Canonical provenance failed: forbidden legacy repository reference in:",
            file=sys.stderr,
        )
        for path in failures:
            print(f"  {path}", file=sys.stderr)
        return 1

    print(f"Canonical provenance: PASS ({CANONICAL_REPOSITORY})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
