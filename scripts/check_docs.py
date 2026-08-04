# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Validate the first-party Markdown documentation contract.

The check is intentionally dependency-free so contributors can run it before
opening a pull request. Markdown style is checked separately with
markdownlint; this script verifies the QuReddy-specific promises that generic
linters cannot: a numbered contents list and working in-document anchors.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
from collections import Counter
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
EXCLUDED_PREFIXES = (".github/", "tests/conformance/schemas/")
ANCHOR_LINK = re.compile(r"\]\(#([^)\s]+)\)")
HEADING = re.compile(r"^(#{1,6})\s+(.+?)\s*#*\s*$")
ORDERED_ITEM = re.compile(r"^\d+\.\s+\[[^]]+\]\(#[-\w.]+\)$")


def tracked_markdown_files() -> list[Path]:
    """Return first-party Markdown files tracked by Git."""
    git = shutil.which("git")
    if git is None:
        raise RuntimeError("git is required to enumerate tracked documentation")
    result = subprocess.run(  # noqa: S603 - resolved Git executable; fixed arguments
        [git, "ls-files", "*.md"],
        cwd=REPOSITORY_ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    return [
        REPOSITORY_ROOT / filename
        for filename in result.stdout.splitlines()
        if not filename.startswith(EXCLUDED_PREFIXES)
    ]


def github_anchor(text: str) -> str:
    """Create the GitHub-compatible anchor used by this repository's headings."""
    text = re.sub(r"`([^`]+)`", r"\1", text)
    text = re.sub(r"\[([^]]+)\]\([^)]+\)", r"\1", text)
    text = text.lower().strip()
    text = re.sub(r"[^\w\s-]", "", text)
    # GitHub preserves literal hyphens and turns each whitespace character into
    # a hyphen. For example, ``[0.2.13] - 2026-08-04`` becomes
    # ``0213---2026-08-04``.
    return re.sub(r"\s", "-", text).strip("-")


def headings(lines: list[str]) -> set[str]:
    """Collect rendered anchors, ignoring Markdown inside fenced code blocks."""
    anchors: list[str] = []
    inside_fence = False
    for line in lines:
        if line.lstrip().startswith(("```", "~~~")):
            inside_fence = not inside_fence
            continue
        if inside_fence:
            continue
        match = HEADING.match(line)
        if match:
            anchors.append(github_anchor(match.group(2)))

    counts: Counter[str] = Counter()
    rendered: set[str] = set()
    for anchor in anchors:
        suffix = counts[anchor]
        rendered.add(anchor if suffix == 0 else f"{anchor}-{suffix}")
        counts[anchor] += 1
    return rendered


def validate_document(path: Path) -> list[str]:
    """Return every documentation-contract error for one Markdown document."""
    relative = path.relative_to(REPOSITORY_ROOT)
    lines = path.read_text(encoding="utf-8").splitlines()
    errors: list[str] = []

    try:
        contents_index = lines.index("## Contents")
    except ValueError:
        return [f"{relative}: missing required '## Contents' section"]

    toc_items: list[str] = []
    for line in lines[contents_index + 1 :]:
        if not line.strip():
            if toc_items:
                break
            continue
        if ORDERED_ITEM.match(line):
            toc_items.append(line)
            continue
        if toc_items:
            break

    if not toc_items:
        errors.append(f"{relative}: Contents must start with a numbered local-link list")
    elif [int(item.split(".", 1)[0]) for item in toc_items] != list(range(1, len(toc_items) + 1)):
        errors.append(f"{relative}: Contents numbering must be consecutive, starting at 1")

    rendered_anchors = headings(lines)
    for line_number, line in enumerate(lines, start=1):
        for anchor in ANCHOR_LINK.findall(line):
            if anchor not in rendered_anchors:
                errors.append(f"{relative}:{line_number}: unresolved local anchor '#{anchor}'")
    return errors


def main() -> int:
    """Run the documentation contract check."""
    errors = [error for path in tracked_markdown_files() for error in validate_document(path)]
    if errors:
        print("Documentation contract failed:", file=sys.stderr)
        print("\n".join(f"- {error}" for error in errors), file=sys.stderr)
        return 1
    print("Documentation contract passed: numbered contents and local anchors are valid.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
