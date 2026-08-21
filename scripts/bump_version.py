# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Single-source version bump for QuReddy.

``pyproject.toml [project] version`` is the ONE source of truth for the package
version. Every other place that must repeat the string is derived from it here,
so a release touches one number instead of hunting the value across the tree.

Covered single-sources (a bump stamps all of them; ``--check`` verifies they
already agree):

* ``pyproject.toml`` ``[project] version`` (the source of truth itself)
* the README version badge
* the CHANGELOG version badge
* the ``Dockerfile`` ``ARG QUREDDY_VERSION`` default (feeds the OCI
  ``image.version`` label and selects the wheel to install)
* the ``uv.lock`` entry for this package
* the golden output contracts (``tests/golden/*.golden``)

``--check`` additionally verifies the CHANGELOG documents the current version:
a ``## [<version>] - <date>`` heading and a matching Contents entry must exist.
The bump does not fabricate those (they need a date and human-written notes);
it prints a reminder instead.

Docker *documentation* intentionally uses the floating ``:latest`` tag and is
not version-stamped, so it never needs a bump.

Usage:
    python scripts/bump_version.py 0.2.17  # set the version and propagate
    python scripts/bump_version.py --check  # verify everything already agrees (CI)
    python scripts/bump_version.py --help   # print this message
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PYPROJECT = ROOT / "pyproject.toml"
README = ROOT / "README.md"
CHANGELOG = ROOT / "CHANGELOG.md"
DOCKERFILE = ROOT / "Dockerfile"
UVLOCK = ROOT / "uv.lock"
GOLDEN = ROOT / "tests" / "golden"

_PYPROJECT_VERSION = re.compile(r'^version = "(?P<v>[^"]+)"', re.MULTILINE)
# shields.io badge: version-<v>-blue (dots and dashes are URL-escaped by shields, but
# a simple SemVer with dots renders fine unescaped). Present in both README and CHANGELOG.
_BADGE = re.compile(r"badge/version-(?P<v>[0-9][^-\s]*)-blue")
# Dockerfile default that stamps the OCI image.version label and picks the wheel.
_DOCKER_ARG = re.compile(r"^ARG QUREDDY_VERSION=(?P<v>\d+\.\d+\.\d+[^\s]*)$", re.MULTILINE)
# The editable entry for this package in the resolved lockfile.
_UVLOCK_VERSION = re.compile(
    r'(?P<pre>name = "breachsafe-qureddy"\nversion = ")(?P<v>[^"]+)(?P<post>")'
)


def _simple_targets() -> list[tuple[Path, re.Pattern[str]]]:
    """Single-version-bearing files: (path, pattern with a "v" group).

    Built from the module path globals on each call so tests can retarget the
    tool at a fixture repository by patching those globals alone. Each file
    carries exactly one occurrence of the version through its pattern.
    """
    return [
        (README, _BADGE),
        (CHANGELOG, _BADGE),
        (DOCKERFILE, _DOCKER_ARG),
        (UVLOCK, _UVLOCK_VERSION),
    ]


# The scanner version appears verbatim in the golden output contracts. These are the
# ONLY version-bearing spots there, so a bump must update them or test_golden_output fails.
_GOLDEN_PATTERNS: dict[str, list[re.Pattern[str]]] = {
    "rich.golden": [
        re.compile(r"(?P<pre>QuReddy )(?P<v>\d+\.\d+\.\d+)(?P<post> by)"),
        re.compile(r"(?P<pre>^ version +)(?P<v>\d+\.\d+\.\d+)(?P<post>)", re.MULTILINE),
    ],
    "json.golden": [
        re.compile(r'(?P<pre>"scanner_version": ")(?P<v>\d+\.\d+\.\d+)(?P<post>")'),
    ],
    # anchor on the qureddy tool component so we don't touch OpenSSL's version etc.
    # (CBOM is emitted with sorted keys, so name → type → version order is stable).
    "cbom.golden": [
        re.compile(
            r'(?P<pre>"name": "qureddy",\s*"type": "application",\s*"version": ")'
            r'(?P<v>\d+\.\d+\.\d+)(?P<post>")'
        ),
    ],
}

_SEMVER = re.compile(r"^\d+\.\d+\.\d+([-+][0-9A-Za-z.-]+)?$")


def _read_pyproject_version() -> str:
    m = _PYPROJECT_VERSION.search(PYPROJECT.read_text())
    if not m:
        sys.exit("bump_version: could not find [project] version in pyproject.toml")
    return m.group("v")


def _set(text: str, pattern: re.Pattern[str], new_version: str) -> tuple[str, int]:
    return pattern.subn(lambda m: m.group(0).replace(m.group("v"), new_version), text)


def _golden_mismatches(version: str) -> list[str]:
    """Return a list of golden version strings that don't match ``version``."""
    bad: list[str] = []
    for name, patterns in _GOLDEN_PATTERNS.items():
        text = (GOLDEN / name).read_text()
        for pat in patterns:
            for m in pat.finditer(text):
                if m.group("v") != version:
                    bad.append(f"{name}: {m.group('v')} != {version}")
    return bad


def _simple_mismatches(version: str) -> list[str]:
    """Return mismatches for the single-version-bearing files (badges, Docker, lock)."""
    bad: list[str] = []
    for path, pattern in _simple_targets():
        name = path.name
        m = pattern.search(path.read_text())
        if not m:
            bad.append(f"{name}: version marker not found")
            continue
        if m.group("v") != version:
            bad.append(f"{name}: {m.group('v')} != {version}")
    return bad


def _changelog_release_problems(version: str) -> list[str]:
    """Return problems if the CHANGELOG doesn't document ``version``.

    A released version needs both a ``## [<version>] - <date>`` heading and a
    matching entry in the ``## Contents`` list. ``bump`` cannot author these
    (they need a date and notes), so ``--check`` is where the drift is caught.
    """
    text = CHANGELOG.read_text()
    escaped = re.escape(version)
    problems: list[str] = []
    if not re.search(rf"^## \[{escaped}\] - \d{{4}}-\d\d-\d\d", text, re.MULTILINE):
        problems.append(f"CHANGELOG.md: no '## [{version}] - <date>' release heading")
    if not re.search(rf"\[{escaped}\]\(#", text):
        problems.append(f"CHANGELOG.md: no Contents entry linking to [{version}]")
    return problems


def check() -> int:
    """Return 0 if every derived version string agrees with pyproject, else 1."""
    version = _read_pyproject_version()
    problems: list[str] = []
    problems.extend(_simple_mismatches(version))
    problems.extend(_golden_mismatches(version))
    problems.extend(_changelog_release_problems(version))
    if problems:
        for p in problems:
            print(f"bump_version: MISMATCH — {p}", file=sys.stderr)
        return 1
    print(f"bump_version: OK — all version markers agree ({version})")
    return 0


def bump(new_version: str) -> int:
    """Set pyproject version and propagate it to every stampable single-source."""
    if not _SEMVER.match(new_version):
        sys.exit(f"bump_version: {new_version!r} is not a SemVer string")
    PYPROJECT.write_text(_set(PYPROJECT.read_text(), _PYPROJECT_VERSION, new_version)[0])
    simple_updates = 0
    for path, pattern in _simple_targets():
        text, n = _set(path.read_text(), pattern, new_version)
        if n == 0:
            sys.exit(f"bump_version: version marker not found in {path.name}")
        path.write_text(text)
        simple_updates += n
    golden_updates = 0
    for name, patterns in _GOLDEN_PATTERNS.items():
        path = GOLDEN / name
        text = path.read_text()
        for pat in patterns:
            text, k = pat.subn(lambda m: f"{m.group('pre')}{new_version}{m.group('post')}", text)
            golden_updates += k
        path.write_text(text)
    print(
        f"bump_version: set version {new_version} "
        f"(pyproject + {simple_updates} markers + {golden_updates} golden)"
    )
    if _changelog_release_problems(new_version):
        print(
            f"Next: add a `## [{new_version}] - <date>` CHANGELOG heading and Contents "
            "entry, run `uv lock` (resync uv.lock), then tag the release."
        )
    else:
        print("Next: run `uv lock` (resync uv.lock) and tag the release.")
    return 0


def main(argv: list[str]) -> int:
    """CLI: ``--check`` verifies agreement; ``--help`` prints usage; a version bumps."""
    prog_and_one_arg = 2
    if len(argv) != prog_and_one_arg:
        sys.exit(__doc__)
    if argv[1] in ("-h", "--help"):
        print(__doc__)
        return 0
    return check() if argv[1] == "--check" else bump(argv[1])


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
