# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Single-source version bump for QuReddy.

`pyproject.toml [project] version` is the ONE source of truth for the package
version. Other places that must repeat the string (currently just the README
version badge) are derived from it here, so a release touches one number instead
of hunting the value across the tree.

Docker documentation intentionally uses the floating ``:latest`` tag and is not
version-stamped, so it never needs a bump.

Usage:
    python scripts/bump_version.py 0.2.3   # set the version and propagate
    python scripts/bump_version.py --check  # verify everything already agrees (CI)
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PYPROJECT = ROOT / "pyproject.toml"
README = ROOT / "README.md"

_PYPROJECT_VERSION = re.compile(r'^version = "(?P<v>[^"]+)"', re.MULTILINE)
# shields.io badge: version-<v>-blue (dots and dashes are URL-escaped by shields, but
# a simple SemVer with dots renders fine unescaped)
_BADGE = re.compile(r"badge/version-(?P<v>[0-9][^-\s]*)-blue")

_SEMVER = re.compile(r"^\d+\.\d+\.\d+([-+][0-9A-Za-z.-]+)?$")


def _read_pyproject_version() -> str:
    m = _PYPROJECT_VERSION.search(PYPROJECT.read_text())
    if not m:
        sys.exit("bump_version: could not find [project] version in pyproject.toml")
    return m.group("v")


def _set(text: str, pattern: re.Pattern[str], new_version: str) -> tuple[str, int]:
    return pattern.subn(
        lambda m: m.group(0).replace(m.group("v"), new_version), text
    )


def check() -> int:
    """Return 0 if every derived version string matches pyproject, else 1."""
    version = _read_pyproject_version()
    badge = _BADGE.search(README.read_text())
    if not badge:
        print("bump_version: README version badge not found", file=sys.stderr)
        return 1
    if badge.group("v") != version:
        print(
            f"bump_version: README badge {badge.group('v')!r} != pyproject {version!r}",
            file=sys.stderr,
        )
        return 1
    print(f"bump_version: OK — all version strings agree ({version})")
    return 0


def bump(new_version: str) -> int:
    """Set pyproject version and propagate to the README badge."""
    if not _SEMVER.match(new_version):
        sys.exit(f"bump_version: {new_version!r} is not a SemVer string")
    PYPROJECT.write_text(
        _set(PYPROJECT.read_text(), _PYPROJECT_VERSION, new_version)[0]
    )
    readme, n = _set(README.read_text(), _BADGE, new_version)
    README.write_text(readme)
    print(f"bump_version: set version {new_version} (pyproject + {n} badge)")
    print("Next: add a CHANGELOG entry and tag the release.")
    return 0


def main(argv: list[str]) -> int:
    """CLI: `--check` verifies agreement; a version argument bumps."""
    if len(argv) != 2:
        sys.exit(__doc__)
    return check() if argv[1] == "--check" else bump(argv[1])


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
